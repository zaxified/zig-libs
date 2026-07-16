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
// Scaffold simplification: a single freelist page (bounded capacity). A
// production build chains freelist pages when one fills; that chaining is a
// documented backlog item (SPEC.md), orthogonal to the reuse-safety invariant.

pub const Freelist = struct {
    ids: std.ArrayList(PageId) = .empty,
    /// Parallel to `ids`: the txn_id that freed each page (feeds reclaimGate).
    free_txns: std.ArrayList(u64) = .empty,

    pub const entry_bytes = 12; // PageId(4) + free_txn(8)
    pub const capacity = (page_size - 2) / entry_bytes;

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

    /// Serialize into a single freelist page. Asserts it fits (see `capacity`).
    pub fn encode(self: *const Freelist, page: *[page_size]u8) void {
        std.debug.assert(self.ids.items.len <= capacity);
        @memset(page, 0);
        std.mem.writeInt(u16, page[0..2], @intCast(self.ids.items.len), .little);
        for (self.ids.items, self.free_txns.items, 0..) |id, txn, k| {
            const base = 2 + k * entry_bytes;
            std.mem.writeInt(u32, page[base .. base + 4][0..4], id, .little);
            std.mem.writeInt(u64, page[base + 4 .. base + 12][0..8], txn, .little);
        }
    }

    pub fn decode(gpa: Allocator, page: *const [page_size]u8) !Freelist {
        var fl = Freelist{};
        errdefer fl.deinit(gpa);
        const n = std.mem.readInt(u16, page[0..2], .little);
        if (n > capacity) return error.Corrupt;
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const base = 2 + k * entry_bytes;
            try fl.push(
                gpa,
                std.mem.readInt(u32, page[base .. base + 4][0..4], .little),
                std.mem.readInt(u64, page[base + 4 .. base + 12][0..8], .little),
            );
        }
        return fl;
    }
};

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

test "freelist push + encode/decode round-trip" {
    var fl = Freelist{};
    defer fl.deinit(testing.allocator);
    try fl.push(testing.allocator, 7, 3);
    try fl.push(testing.allocator, 9, 3);
    try fl.push(testing.allocator, 4, 5);
    try testing.expectEqual(@as(usize, 3), fl.len());

    var page: [page_size]u8 = undefined;
    fl.encode(&page);
    var back = try Freelist.decode(testing.allocator, &page);
    defer back.deinit(testing.allocator);
    try testing.expectEqualSlices(PageId, fl.ids.items, back.ids.items);
    try testing.expectEqualSlices(u64, fl.free_txns.items, back.free_txns.items);
}

test "freelist decode rejects an over-capacity count" {
    var page: [page_size]u8 = @splat(0);
    std.mem.writeInt(u16, page[0..2], @intCast(Freelist.capacity + 1), .little);
    try testing.expectError(error.Corrupt, Freelist.decode(testing.allocator, &page));
}
