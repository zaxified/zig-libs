// SPDX-License-Identifier: MIT

//! pager — page-granular I/O over `kv`'s `Storage` seam, plus the freelist
//! container. MECHANICAL: reading/writing a fixed-size page at `id*page_size`,
//! growing the file by one page, and the freelist's push/encode/decode are all
//! deterministic bookkeeping tested here. The ONE thing that is not mechanical
//! is *which* freed page may be pulled for reuse — `popReusable` routes that
//! decision through `core.reclaimGate` (the gated MVCC page-lifecycle
//! invariant), so it is only ever reached from a real `core.commit`.
//!
//! Reusing `kv.Storage` (rather than a new storage seam) is deliberate: the
//! Bitcask store already ships a production `FsStorage` and — crucially — a
//! deterministic crash/fault simulator (`SimStorage`) with torn-write,
//! out-of-order-durability and I/O-error injection. A page store is exactly an
//! offset-addressed blob store, which is what that seam already is, so the
//! whole VOPR fault machinery comes for free (see harness.zig).

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv = @import("kv");
const format = @import("format.zig");
const core = @import("core.zig");

const page_size = format.page_size;
const PageId = format.PageId;

pub const StorageError = kv.Storage.Error;

/// Byte offset of page `id`.
fn offsetOf(id: PageId) u64 {
    return @as(u64, id) * page_size;
}

pub const Pager = struct {
    store: kv.Storage,
    handle: kv.Storage.Handle,
    /// Total pages the file has been grown to; the next never-used page id.
    /// Mirrors `Meta.high_water`; `core.commit` advances it and persists it.
    high_water: u64,

    pub fn init(store: kv.Storage, handle: kv.Storage.Handle, high_water: u64) Pager {
        return .{ .store = store, .handle = handle, .high_water = high_water };
    }

    /// Read page `id` fully into `buf`. A short read (page not fully present)
    /// is corruption from the tree's point of view — the meta said it exists.
    pub fn readPage(self: *Pager, id: PageId, buf: *[page_size]u8) (StorageError || error{Corrupt})!void {
        try self.store.preadFull(self.handle, buf, offsetOf(id));
    }

    /// Write page `id` (no fsync — durability is `sync`'s job, ordered by
    /// `core.commit`). Writing at/after end-of-file extends it.
    pub fn writePage(self: *Pager, id: PageId, buf: *const [page_size]u8) StorageError!void {
        try self.store.writeAll(self.handle, buf, offsetOf(id));
    }

    pub fn sync(self: *Pager) StorageError!void {
        try self.store.sync(self.handle);
    }

    pub fn syncDir(self: *Pager) StorageError!void {
        try self.store.syncDir();
    }

    /// Grow the file logically by one page and return the fresh id. Mechanical:
    /// the reuse path (pulling from the freelist instead of growing) is
    /// `Freelist.popReusable`, gated behind `core.reclaimGate`.
    pub fn growOne(self: *Pager) PageId {
        const id: PageId = @intCast(self.high_water);
        self.high_water += 1;
        return id;
    }

    pub fn fileSizePages(self: *Pager) StorageError!u64 {
        const bytes = try self.store.size(self.handle);
        return bytes / page_size;
    }
};

// ── Freelist container ───────────────────────────────────────────────────────
//
// Pages the COW makes dead are parked here, each tagged with the txn that freed
// it. A page is reusable only once no reader can still see a version older than
// its freeing txn — the `reclaimGate` predicate. The container itself (push +
// on-disk encode/decode) is mechanical; the reuse gate is the Fable core.
//
// On-disk, the freelist is a CHAIN of pages (not a single bounded page): each
// page header is `count(u16) + next(PageId u32)`, followed by up to
// `capacity` fixed 12-byte entries. A commit that frees more pages than one
// page holds simply chains another — there is no cap on how many pages may be
// parked, only on how many fit per chain page. Chain-storage pages themselves
// are allocated via `Pager.growOne` only (never `popReusable`): that sidesteps
// the classic chicken-and-egg problem of a freelist write needing to itself
// describe the very page it is about to be written to, at the cost of never
// reusing a freed page for freelist storage (a documented simplification,
// orthogonal to the reuse-safety invariant `reclaimGate` enforces).

pub const Freelist = struct {
    ids: std.ArrayList(PageId) = .empty,
    /// Parallel to `ids`: the txn_id that freed each page (feeds reclaimGate).
    free_txns: std.ArrayList(u64) = .empty,

    pub const entry_bytes = 12; // PageId(4) + free_txn(8)
    pub const hdr_bytes = 6; // count(2) + next PageId(4)
    /// Entries that fit on ONE chain page (not the whole list — see above).
    pub const capacity = (page_size - hdr_bytes) / entry_bytes;

    pub fn deinit(self: *Freelist, gpa: Allocator) void {
        self.ids.deinit(gpa);
        self.free_txns.deinit(gpa);
    }

    pub fn len(self: *const Freelist) usize {
        return self.ids.items.len;
    }

    /// Park a page freed by `free_txn`.
    pub fn push(self: *Freelist, gpa: Allocator, id: PageId, free_txn: u64) !void {
        try self.ids.append(gpa, id);
        try self.free_txns.append(gpa, free_txn);
    }

    /// Pull a page that is safe to reuse given the oldest live reader, or null
    /// if none qualifies (caller then grows the file). FABLE-REACHED: the
    /// safety decision is `core.reclaimGate`, a gated stub — so this is only
    /// ever called from a real `core.commit`.
    pub fn popReusable(self: *Freelist, oldest_reader_txn: u64) ?PageId {
        var i: usize = self.ids.items.len;
        while (i > 0) {
            i -= 1;
            if (core.reclaimGate(self.free_txns.items[i], oldest_reader_txn)) {
                const id = self.ids.items[i];
                _ = self.ids.orderedRemove(i);
                _ = self.free_txns.orderedRemove(i);
                return id;
            }
        }
        return null;
    }

    /// Chain pages needed to persist the current entry count (0 if empty).
    pub fn pagesNeeded(self: *const Freelist) usize {
        const n = self.ids.items.len;
        if (n == 0) return 0;
        return (n + capacity - 1) / capacity;
    }

    fn encodeChunk(ids: []const PageId, txns: []const u64, next: PageId, page: *[page_size]u8) void {
        std.debug.assert(ids.len <= capacity);
        @memset(page, 0);
        std.mem.writeInt(u16, page[0..2], @intCast(ids.len), .little);
        std.mem.writeInt(u32, page[2..6], next, .little);
        for (ids, txns, 0..) |id, txn, k| {
            const base = hdr_bytes + k * entry_bytes;
            std.mem.writeInt(u32, page[base .. base + 4][0..4], id, .little);
            std.mem.writeInt(u64, page[base + 4 .. base + 12][0..8], txn, .little);
        }
    }

    /// Write the whole list as a chain of fresh pages and return the chain
    /// head (0 if empty). Storage pages come only from `pager.growOne` (see
    /// the container doc comment) — this never touches `popReusable`, so it
    /// can safely be called after this commit's own freed pages have already
    /// been pushed into `self`.
    pub fn writeChain(self: *const Freelist, pager: *Pager) StorageError!PageId {
        const n = self.ids.items.len;
        if (n == 0) return 0;
        const npages = self.pagesNeeded();
        const first_id: PageId = @intCast(pager.high_water);
        pager.high_water += npages; // reserve npages consecutive fresh ids

        var buf: [page_size]u8 = undefined;
        var start: usize = 0;
        var i: usize = 0;
        while (i < npages) : (i += 1) {
            const take = @min(capacity, n - start);
            const next: PageId = if (i + 1 < npages) first_id + @as(PageId, @intCast(i + 1)) else 0;
            encodeChunk(self.ids.items[start .. start + take], self.free_txns.items[start .. start + take], next, &buf);
            try pager.writePage(first_id + @as(PageId, @intCast(i)), &buf);
            start += take;
        }
        return first_id;
    }
};

pub const ChainReadError = StorageError || error{Corrupt} || Allocator.Error;

/// Result of reading the on-disk freelist chain: the merged entry list plus
/// the page ids that make up the chain itself (the caller must mark these
/// dead on the next COW rewrite — the chain's own pages die every commit just
/// like tree nodes do).
pub const FreelistChain = struct {
    fl: Freelist = .{},
    pages: std.ArrayList(PageId) = .empty,

    pub fn deinit(self: *FreelistChain, gpa: Allocator) void {
        self.fl.deinit(gpa);
        self.pages.deinit(gpa);
    }
};

/// Read the whole on-disk freelist chain starting at `head` (0 = empty).
/// This is the COMMIT-PATH reader over pages this module itself wrote last
/// commit — not the crash-recovery validation path (that is
/// `core.recover`'s `candidateValid`, which trusts nothing). Still guards
/// against a runaway/cyclic chain defensively: a legitimate chain can never
/// visit more pages than the file has ever grown to.
pub fn readFreelistChain(gpa: Allocator, pager: *Pager, head: PageId) ChainReadError!FreelistChain {
    var out = FreelistChain{};
    errdefer out.deinit(gpa);
    var id = head;
    var buf: [page_size]u8 = undefined;
    var visited: u64 = 0;
    while (id != 0) {
        visited += 1;
        if (visited > pager.high_water) return error.Corrupt; // cycle guard
        try out.pages.append(gpa, id);
        try pager.readPage(id, &buf);
        const n = std.mem.readInt(u16, buf[0..2], .little);
        if (n > Freelist.capacity) return error.Corrupt;
        const next = std.mem.readInt(u32, buf[2..6], .little);
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const base = Freelist.hdr_bytes + k * Freelist.entry_bytes;
            try out.fl.push(
                gpa,
                std.mem.readInt(u32, buf[base .. base + 4][0..4], .little),
                std.mem.readInt(u64, buf[base + 4 .. base + 12][0..8], .little),
            );
        }
        id = next;
    }
    return out;
}

// ── tests: the mechanical bookkeeping (no core reached) ──────────────────────

const testing = std.testing;

test "pager grows page ids monotonically from high_water" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    const h = try sim.storage().open("t.kvt", .create_truncate);
    var p = Pager.init(sim.storage(), h, format.first_data_page);
    try testing.expectEqual(@as(PageId, 2), p.growOne());
    try testing.expectEqual(@as(PageId, 3), p.growOne());
    try testing.expectEqual(@as(u64, 4), p.high_water);
}

test "pager write/read a page round-trips through kv.Storage" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    const h = try sim.storage().open("t.kvt", .create_truncate);
    var p = Pager.init(sim.storage(), h, format.first_data_page);

    var out: [page_size]u8 = undefined;
    var in: [page_size]u8 = undefined;
    format.encodeEmptyLeaf(&out);
    out[100] = 0xAB;
    try p.writePage(5, &out);
    try p.readPage(5, &in);
    try testing.expectEqualSlices(u8, &out, &in);
}

/// Fresh Pager + backing SimStorage handle, ready for freelist chain tests.
fn testPager(sim: *kv.SimStorage) !Pager {
    const h = try sim.storage().open("t.kvt", .create_truncate);
    return Pager.init(sim.storage(), h, format.first_data_page);
}

test "freelist writeChain/readFreelistChain round-trip (well below capacity)" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var p = try testPager(&sim);

    var fl = Freelist{};
    defer fl.deinit(testing.allocator);
    try fl.push(testing.allocator, 7, 3);
    try fl.push(testing.allocator, 9, 3);
    try fl.push(testing.allocator, 4, 5);
    try testing.expectEqual(@as(usize, 1), fl.pagesNeeded());

    const head = try fl.writeChain(&p);
    try testing.expect(head != 0);

    var back = try readFreelistChain(testing.allocator, &p, head);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), back.pages.items.len);
    try testing.expectEqualSlices(PageId, fl.ids.items, back.fl.ids.items);
    try testing.expectEqualSlices(u64, fl.free_txns.items, back.fl.free_txns.items);
}

test "freelist chain: empty list writes/reads as head 0, no pages" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var p = try testPager(&sim);

    var fl = Freelist{};
    defer fl.deinit(testing.allocator);
    try testing.expectEqual(@as(PageId, 0), try fl.writeChain(&p));

    var back = try readFreelistChain(testing.allocator, &p, 0);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), back.pages.items.len);
    try testing.expectEqual(@as(usize, 0), back.fl.len());
}

test "freelist chain: exactly at one page's capacity stays a single page" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var p = try testPager(&sim);

    var fl = Freelist{};
    defer fl.deinit(testing.allocator);
    var i: PageId = 0;
    while (i < Freelist.capacity) : (i += 1)
        try fl.push(testing.allocator, i + 100, 1);
    try testing.expectEqual(@as(usize, 1), fl.pagesNeeded());

    const head = try fl.writeChain(&p);
    var back = try readFreelistChain(testing.allocator, &p, head);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), back.pages.items.len);
    try testing.expectEqual(@as(usize, Freelist.capacity), back.fl.len());
    try testing.expectEqualSlices(PageId, fl.ids.items, back.fl.ids.items);
}

test "freelist chain: ONE OVER capacity forces a second chain page (the overflow boundary)" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var p = try testPager(&sim);

    var fl = Freelist{};
    defer fl.deinit(testing.allocator);
    var i: PageId = 0;
    while (i < Freelist.capacity + 1) : (i += 1)
        try fl.push(testing.allocator, i + 100, 1);
    try testing.expectEqual(@as(usize, 2), fl.pagesNeeded());

    const head = try fl.writeChain(&p);
    var back = try readFreelistChain(testing.allocator, &p, head);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), back.pages.items.len);
    // The overflow entry (the (capacity+1)-th) must NOT be silently lost —
    // this is exactly the boundary where a single bounded page used to leak.
    try testing.expectEqual(@as(usize, Freelist.capacity + 1), back.fl.len());
    try testing.expectEqualSlices(PageId, fl.ids.items, back.fl.ids.items);
    try testing.expectEqualSlices(u64, fl.free_txns.items, back.fl.free_txns.items);
}

test "readFreelistChain rejects an over-capacity per-page count" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var p = try testPager(&sim);

    var page: [page_size]u8 = @splat(0);
    std.mem.writeInt(u16, page[0..2], @intCast(Freelist.capacity + 1), .little);
    std.mem.writeInt(u32, page[2..6], 0, .little); // next = end of chain
    const id = p.growOne();
    try p.writePage(id, &page);

    try testing.expectError(error.Corrupt, readFreelistChain(testing.allocator, &p, id));
}

test "freelist chain: freeing MORE pages than one page holds survives a simulated reopen, all still known-free and reusable" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var p = try testPager(&sim);

    // Free enough pages to force a 3-page chain (2 full pages + a remainder).
    const total = Freelist.capacity * 2 + 17;
    var fl = Freelist{};
    defer fl.deinit(testing.allocator);
    var i: PageId = 0;
    while (i < total) : (i += 1)
        try fl.push(testing.allocator, i + 1000, 42); // all freed by txn 42
    try testing.expectEqual(@as(usize, 3), fl.pagesNeeded());

    const head = try fl.writeChain(&p);
    const high_water_after_write = p.high_water;

    // Simulate reopen: a fresh Pager over the SAME store/handle, as `recover`
    // would build after re-deriving high_water from the durable meta.
    var reopened = Pager.init(sim.storage(), p.handle, high_water_after_write);

    var back = try readFreelistChain(testing.allocator, &reopened, head);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), back.pages.items.len);
    try testing.expectEqual(@as(usize, total), back.fl.len());
    try testing.expectEqualSlices(PageId, fl.ids.items, back.fl.ids.items);

    // Every single one of them is still known-free and reusable (passes the
    // real reclaimGate against a reader pinned at-or-after the freeing txn).
    var reused: usize = 0;
    while (back.fl.popReusable(42)) |_| reused += 1;
    try testing.expectEqual(total, reused);
    try testing.expectEqual(@as(usize, 0), back.fl.len());
}
