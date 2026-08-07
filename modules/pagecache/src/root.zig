// SPDX-License-Identifier: MIT

//! pagecache — a bounded, transparent page cache that slots between kvtree's
//! pager and its underlying `Storage`, keeping only a fixed RAM budget of hot
//! pages resident while cold pages are refetched from the backing store on
//! demand (hot-cold tiering). It is the "load only part of the store into RAM
//! by access pattern" answer for a kvtree that is larger than you want fully
//! resident.
//!
//! **The seam.** `PageCache` wraps one inner `Storage` (production `FsStorage`
//! or deterministic `SimStorage`) and *itself implements the very same
//! `Storage` vtable* kvtree expects — so it is a drop-in: open a store with
//! `kvtree.Db.open(gpa, page_cache.storage(), path, .{})` instead of handing
//! `Db.open` the raw `FsStorage`. Every page read/write kvtree issues flows
//! through the cache; nothing else about kvtree changes.
//!
//! **Write-through, never write-back.** kvtree is a copy-on-write B-tree whose
//! crash-safety rests on *ordered* durability: it writes tree pages, then
//! `sync`s, then overwrites a meta page, then `sync`s again — a torn commit
//! leaves the previous meta as the newest valid one. A write-*back* cache
//! (buffering dirty pages in RAM and flushing later) would reorder or delay
//! those writes and silently destroy that invariant. So `PageCache` is
//! strictly **write-through**: every `writeAll` reaches the inner `Storage`
//! *before* the call returns, exactly as if the cache were not there; the
//! cache copy is only refreshed as a side effect. `sync`/`syncDir`/`truncate`
//! forward verbatim, so kvtree's commit barriers keep their exact meaning.
//! The cache bounds memory and cuts inner reads — it never changes what is
//! durable and never changes an observable result.
//!
//! **Transparency invariant.** A `kvtree.Db` opened over `PageCache(inner)`
//! behaves identically to one opened directly over `inner`: same data, same
//! ordered scans, same durability. The cache is invisible to correctness — it
//! can only make reads faster or bound RSS. The tests prove this by running an
//! identical put/get/delete/commit workload through both and asserting
//! byte-identical final scans, and by reopening a `PageCache(FsStorage)` store
//! with a *fresh* (empty) cache and confirming every committed key survives
//! (proving the write-through writes actually reached disk).
//!
//! **Eviction / budget.** The bounded set is a `ramcache.Cache` (W-TinyLFU
//! admission + segmented-LRU). Pages are keyed by (handle, page-index) and the
//! budget is a fixed number of resident pages (`max_pages`, i.e.
//! `max_pages * page_size` bytes). W-TinyLFU is a deliberate fit here: the
//! constantly re-read meta pages become "hot" and stay pinned while churning
//! leaf pages are admitted/evicted by recent frequency, and a large scan of
//! one-hit pages cannot flush the hot set — exactly the hot-cold tiering this
//! module is for. See SPEC.md for the full design and the write-back
//! rejection argument.

const std = @import("std");
const kvtree = @import("kvtree");
const ramcache = @import("ramcache");

pub const meta = .{
    .platform = .any, // all I/O forwarded to the wrapped Storage seam
    .role = .util, // a transparent adapter between kvtree's pager and Storage
    // Wraps a single-owner ramcache and a single-writer kvtree; one owner.
    .concurrency = .single_owner,
    .model_after = "buffer pool / page cache (LMDB mmap, Postgres shared_buffers) — write-through only",
    .deps = .{ "kvtree", "ramcache" },
};

/// The storage seam kvtree drives — re-exported so a caller wires a backend
/// (and this cache) without importing `kv`/`kvtree` internals directly.
pub const Storage = kvtree.Storage;

/// Default page size — matches kvtree's fixed page size, so a full page read
/// or write is exactly one cache entry.
pub const default_page_size = kvtree.page_size;

pub const Options = struct {
    /// Fixed page size in bytes. Only reads/writes that are aligned to and
    /// exactly this many bytes are cached (kvtree always issues those); any
    /// other-shaped access is passed straight through. Defaults to kvtree's
    /// page size.
    page_size: usize = default_page_size,
    /// RAM budget expressed as the maximum number of resident pages. Total
    /// resident value bytes are therefore bounded by `max_pages * page_size`.
    max_pages: usize,
};

/// Cumulative + current cache figures (a superset of `ramcache.Stats`).
pub const Stats = struct {
    /// Page-aligned reads served from RAM without touching the inner Storage.
    hits: u64,
    /// Page-aligned reads that had to fall through to the inner Storage.
    misses: u64,
    /// Currently resident pages (always `<= max_pages`).
    resident_pages: usize,
    /// Currently resident value bytes (`<= max_pages * page_size`).
    resident_bytes: usize,
    /// Lifetime pages removed by the bounded cache to stay within budget.
    evictions: u64,
};

/// A bounded, write-through page cache in front of one inner `Storage`.
/// Construct with `init`, hand `storage()` to `kvtree.Db.open`, and `deinit`
/// when the store is closed.
pub const PageCache = struct {
    inner: Storage,
    cache: ramcache.Cache,
    page_size: usize,
    hits: u64 = 0,
    misses: u64 = 0,

    /// Key layout for a cached page: the backend handle (so two files opened
    /// through the same cache never alias) followed by the page index.
    const key_len = 4 + 8;

    pub fn init(gpa: std.mem.Allocator, inner: Storage, options: Options) PageCache {
        std.debug.assert(options.page_size > 0);
        std.debug.assert(options.max_pages > 0);
        return .{
            .inner = inner,
            .cache = ramcache.Cache.init(gpa, .{
                .max_entries = options.max_pages,
                .max_bytes = options.max_pages * options.page_size,
            }),
            .page_size = options.page_size,
        };
    }

    pub fn deinit(self: *PageCache) void {
        self.cache.deinit();
        self.* = undefined;
    }

    /// The `Storage` view to hand to `kvtree.Db.open` — a drop-in replacement
    /// for the raw backend's `storage()`.
    pub fn storage(self: *PageCache) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Combined cache figures.
    pub fn stats(self: *const PageCache) Stats {
        return .{
            .hits = self.hits,
            .misses = self.misses,
            .resident_pages = self.cache.stats.entries,
            .resident_bytes = self.cache.stats.bytes,
            .evictions = self.cache.stats.evictions,
        };
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn cast(ctx: *anyopaque) *PageCache {
        return @ptrCast(@alignCast(ctx));
    }

    /// Is `off`/`len` an access of exactly one whole, aligned page?
    fn isFullPage(self: *const PageCache, off: u64, len: usize) bool {
        return len == self.page_size and off % self.page_size == 0;
    }

    fn pageKey(handle: Storage.Handle, page_index: u64) [key_len]u8 {
        var k: [key_len]u8 = undefined;
        std.mem.writeInt(u32, k[0..4], handle, .little);
        std.mem.writeInt(u64, k[4..12], page_index, .little);
        return k;
    }

    // ── Storage vtable ───────────────────────────────────────────────────────

    const vtable = Storage.VTable{
        .open = vOpen,
        .size = vSize,
        .pread = vPread,
        .writeAll = vWriteAll,
        .sync = vSync,
        .truncate = vTruncate,
        .close = vClose,
        .rename = vRename,
        .delete = vDelete,
        .syncDir = vSyncDir,
        .tryLockExclusive = vTryLockExclusive,
    };

    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        const self = cast(ctx);
        const h = try self.inner.open(path, mode);
        // A truncating open discards the file's contents; any pages we still
        // hold for a reused handle number would be stale. ramcache exposes no
        // per-key removal, so drop the whole set — correctness over precision;
        // this path is rare (kvtree opens open_or_create).
        if (mode == .create_truncate) self.cache.clear();
        return h;
    }

    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        const self = cast(ctx);
        // Size reflects durable writes; write-through keeps the inner Storage
        // authoritative, so ask it directly.
        return self.inner.size(h);
    }

    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        if (!self.isFullPage(off, buf.len)) return self.inner.pread(h, buf, off);

        const key = pageKey(h, off / self.page_size);
        if (self.cache.get(&key, 0, 0)) |cached| {
            @memcpy(buf, cached); // cached.len == page_size == buf.len
            self.hits += 1;
            return self.page_size;
        }
        self.misses += 1;
        const n = try self.inner.pread(h, buf, off);
        // Only a full, present page is a cacheable unit (a short read means the
        // page is not fully on media — never cache a partial page).
        if (n == self.page_size) self.cache.put(&key, buf, 0, 0, 0);
        return n;
    }

    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        // WRITE-THROUGH: the durable write happens first and must succeed
        // before we touch the cache. On inner failure we return the error with
        // the cache unchanged (it still holds the last correct copy).
        try self.inner.writeAll(h, bytes, off);

        if (self.isFullPage(off, bytes.len)) {
            const key = pageKey(h, off / self.page_size);
            // Replace-in-place if resident (put over an existing key always
            // succeeds and never mis-admits), else offer it to the cache.
            self.cache.put(&key, bytes, 0, 0, 0);
        } else {
            // A sub-page or unaligned write could partially overlap resident
            // pages we cannot selectively invalidate; drop everything to stay
            // correct. kvtree never issues such a write, so this is defensive.
            self.cache.clear();
        }
    }

    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        return cast(ctx).inner.sync(h);
    }

    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        try self.inner.truncate(h, len);
        // Truncation can drop pages we hold; without per-key removal, clear.
        self.cache.clear();
    }

    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        const self = cast(ctx);
        self.inner.close(h);
        // The handle number may be recycled by the backend for a different
        // file; forget its pages so a future open cannot read stale bytes.
        self.cache.clear();
    }

    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        try self.inner.rename(old_path, new_path);
        self.cache.clear(); // paths→handles is opaque here; be safe
    }

    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        try self.inner.delete(path);
        self.cache.clear();
    }

    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }

    /// Forwarded verbatim: the cross-process lock belongs to the real backing
    /// file, and a cache that answered it locally would hand out an exclusion
    /// guarantee it cannot enforce.
    fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
//
// Determinism: an injected LCG drives the workload; SimStorage is an in-memory
// fault simulator. The one FsStorage test uses std.testing.tmpDir and cleans up.

const kv = struct {
    // Local aliases to the backends kvtree re-exports, for readable tests.
    const SimStorage = kvtree.SimStorage;
    const FsStorage = kvtree.FsStorage;
};
const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

/// A tiny deterministic PRNG so the workload is reproducible.
const Lcg = struct {
    state: u64,
    fn next(self: *Lcg) u64 {
        self.state = self.state *% 6364136223846793005 +% 1442695040888963407;
        return self.state >> 17;
    }
    fn below(self: *Lcg, n: u64) u64 {
        return self.next() % n;
    }
};

/// Serialize a full ordered scan of `db` as "key=val;" — the canonical
/// observable state used to compare two stores for identity.
fn dumpScan(gpa: std.mem.Allocator, db: *kvtree.Db) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var cur = try db.cursor();
    defer cur.deinit();
    try cur.first();
    while (try cur.next()) |pair| {
        try out.appendSlice(gpa, pair.key);
        try out.append(gpa, '=');
        try out.appendSlice(gpa, pair.val);
        try out.append(gpa, ';');
    }
    return out.toOwnedSlice(gpa);
}

/// Apply one deterministic op stream to `db` (70% put, 30% delete over a fixed
/// key space) so two stores can be driven identically.
fn runWorkload(db: *kvtree.Db, seed: u64, ops: usize, key_space: u64, val_len: usize, scratch: []u8) !void {
    var rng = Lcg{ .state = seed };
    var kbuf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < ops) : (i += 1) {
        const id = rng.below(key_space);
        const key = try std.fmt.bufPrint(&kbuf, "key{d:0>5}", .{id});
        if (rng.below(10) < 7) {
            // Fill the value with id-derived bytes of the requested length.
            for (scratch[0..val_len], 0..) |*b, j| b.* = @truncate(id +% j);
            try db.put(key, scratch[0..val_len]);
        } else {
            try db.del(key);
        }
    }
}

test "transparency: kvtree over PageCache(Sim) == kvtree over raw Sim (identical final scan)" {
    const gpa = testing.allocator;

    // Raw baseline.
    var raw_sim = kv.SimStorage.init(gpa);
    defer raw_sim.deinit();
    raw_sim.allow_overwrite = true; // kvtree overwrites its meta pages in place
    var raw_db = try kvtree.Db.open(gpa, raw_sim.storage(), "t.kvt", .{});
    defer raw_db.close();

    // Same workload through a bounded page cache.
    var cached_sim = kv.SimStorage.init(gpa);
    defer cached_sim.deinit();
    cached_sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, cached_sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    var cached_db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer cached_db.close();

    const scratch = try gpa.alloc(u8, 64);
    defer gpa.free(scratch);

    try runWorkload(&raw_db, 0xA11CE, 1500, 200, 64, scratch);
    try runWorkload(&cached_db, 0xA11CE, 1500, 200, 64, scratch);

    // Whole-store identity: ordered scans must be byte-for-byte equal.
    const raw_dump = try dumpScan(gpa, &raw_db);
    defer gpa.free(raw_dump);
    const cached_dump = try dumpScan(gpa, &cached_db);
    defer gpa.free(cached_dump);
    try testing.expectEqualStrings(raw_dump, cached_dump);
    try testing.expect(raw_dump.len > 0); // the workload actually populated data

    // Point reads must also agree across the whole key space.
    var kbuf: [32]u8 = undefined;
    var id: u64 = 0;
    while (id < 200) : (id += 1) {
        const key = try std.fmt.bufPrint(&kbuf, "key{d:0>5}", .{id});
        const a = try raw_db.get(gpa, key);
        defer if (a) |v| gpa.free(v);
        const b = try cached_db.get(gpa, key);
        defer if (b) |v| gpa.free(v);
        if (a) |av| {
            try testing.expect(b != null);
            try testing.expectEqualSlices(u8, av, b.?);
        } else {
            try testing.expect(b == null);
        }
    }

    // The cache did real work (hits) yet never exceeded its budget.
    try testing.expect(pc.hits > 0);
    try testing.expect(pc.cache.stats.entries <= 8);
}

test "bounding: working set >> budget stays within the budget, evicts, and still reads correctly" {
    const gpa = testing.allocator;

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    const budget = 4;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = budget });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    // Insert enough sizeable entries to force a multi-page tree far larger
    // than the 4-page budget; COW commits grow the file every op.
    const scratch = try gpa.alloc(u8, 256);
    defer gpa.free(scratch);
    try runWorkload(&db, 0xBEEF, 800, 400, 256, scratch);

    const st = pc.stats();
    // Budget is respected at all times (ramcache enforces the cap on every
    // put); the file is far larger than the budget so eviction had to happen.
    try testing.expect(st.resident_pages <= budget);
    try testing.expect(st.resident_bytes <= budget * pc.page_size);
    try testing.expect(st.evictions > 0);
    // Cold pages were genuinely refetched: far more misses than the budget.
    try testing.expect(st.misses > budget);
    // Hot pages (the meta pages, re-read every commit) were served from RAM.
    try testing.expect(st.hits > 0);

    // Despite heavy eviction, every read is correct — cold pages refetched.
    //
    // Named lookup, not handle 0: `kvtree.Db.open` now opens the `.lock`
    // sidecar before the data file (the F2/K3 cross-process-exclusion fix),
    // so handle 0 is the lock file's tiny handle, not "t.kvt"'s — a
    // hardcoded `size(0)` silently measured the wrong file.
    const file_pages = sim.fileContent("t.kvt").?.len / pc.page_size;
    try testing.expect(file_pages > budget); // sanity: working set exceeds budget

    var kbuf: [32]u8 = undefined;
    var found: usize = 0;
    var id: u64 = 0;
    while (id < 400) : (id += 1) {
        const key = try std.fmt.bufPrint(&kbuf, "key{d:0>5}", .{id});
        const got = try db.get(gpa, key);
        defer if (got) |v| gpa.free(v);
        if (got) |v| {
            // Value must equal what the deterministic workload would store.
            var expect: [256]u8 = undefined;
            for (&expect, 0..) |*b, j| b.* = @truncate(id +% j);
            try testing.expectEqualSlices(u8, expect[0..v.len], v);
            found += 1;
        }
        try testing.expect(pc.cache.stats.entries <= budget); // invariant holds throughout
    }
    try testing.expect(found > 0); // some keys survived to be read back
}

test "durability: reopen with a FRESH cache over FsStorage recovers committed data (write-through reached disk)" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write + commit through a bounded page cache, then tear down the
    // WHOLE cache (its RAM copies are gone).
    {
        var fs = kv.FsStorage.init(testing.io, tmp.dir);
        var pc = PageCache.init(gpa, fs.storage(), .{ .max_pages = 4 });
        defer pc.deinit();
        var db = try kvtree.Db.open(gpa, pc.storage(), "real.kvt", .{});
        try db.put("alpha", "one");
        try db.put("beta", "two");
        try db.put("gamma", "three");
        try db.put("beta", "two-updated"); // overwrite exercises meta re-commit
        try db.del("gamma");
        db.close();
    }

    // Phase 2: a brand-new FsStorage AND a brand-new (empty) PageCache. If the
    // write-through had ever masked a write instead of hitting disk, the data
    // would be gone. It must all be here.
    {
        var fs = kv.FsStorage.init(testing.io, tmp.dir);
        var pc = PageCache.init(gpa, fs.storage(), .{ .max_pages = 4 });
        defer pc.deinit();
        var db = try kvtree.Db.open(gpa, pc.storage(), "real.kvt", .{});
        defer db.close();

        const a = try db.get(gpa, "alpha");
        defer if (a) |v| gpa.free(v);
        try testing.expectEqualStrings("one", a.?);
        const b = try db.get(gpa, "beta");
        defer if (b) |v| gpa.free(v);
        try testing.expectEqualStrings("two-updated", b.?);
        const g = try db.get(gpa, "gamma");
        defer if (g) |v| gpa.free(v);
        try testing.expect(g == null); // the delete was durable too

        // Every read here started as a cold miss served from disk (fresh
        // cache) — proof the write-through data is on media, not in RAM.
        try testing.expect(pc.misses > 0);
    }
}

test "in-place meta-page overwrite works through the cache (allow_overwrite path)" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true; // as kvtree's own harness does

    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    // Many commits repeatedly overwrite meta pages 0/1 at the same offset;
    // each must both reach the inner Sim AND refresh the cached meta page so
    // the next read is never stale.
    var i: usize = 0;
    var kbuf: [16]u8 = undefined;
    while (i < 50) : (i += 1) {
        const key = try std.fmt.bufPrint(&kbuf, "k{d}", .{i});
        try db.put(key, "v");
    }
    // Read the newest committed state back — a stale cached meta page would
    // point at an old root and lose recent keys.
    i = 0;
    while (i < 50) : (i += 1) {
        const key = try std.fmt.bufPrint(&kbuf, "k{d}", .{i});
        const got = try db.get(gpa, key);
        defer if (got) |v| gpa.free(v);
        try testing.expectEqualStrings("v", got.?);
    }
}

test "non-page-aligned and short reads pass straight through, uncached" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;

    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 4 });
    defer pc.deinit();
    const st = pc.storage();

    const h = try st.open("blob", .create_truncate);
    // Write two full pages so the file exists at page granularity.
    const page = try gpa.alloc(u8, pc.page_size * 2);
    defer gpa.free(page);
    for (page, 0..) |*b, i| b.* = @truncate(i);
    try st.writeAll(h, page, 0);

    // A sub-page read (8 bytes at a non-aligned offset) must bypass the cache
    // and return exactly the inner bytes.
    var small: [8]u8 = undefined;
    const n = try st.pread(h, &small, 5);
    try testing.expectEqual(@as(usize, 8), n);
    try testing.expectEqualSlices(u8, page[5..13], &small);
    // It did not register as a page hit/miss (only full-page reads do).
    try testing.expectEqual(@as(u64, 0), pc.hits);
    try testing.expectEqual(@as(u64, 0), pc.misses);

    // A full-page read is cached; the second one is a hit.
    var full: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &full, 0);
    _ = try st.pread(h, &full, 0);
    try testing.expectEqual(@as(u64, 1), pc.hits);
    try testing.expectEqual(@as(u64, 1), pc.misses);
    st.close(h);
}

test "F2: each of the six clear() invalidation guards actually empties the cache" {
    // SPEC's whole stale-hit-impossibility argument rests on these six
    // sites (vOpen/.create_truncate, sub-page vWriteAll, vTruncate, vClose,
    // vRename, vDelete) — none had a test. Fill the cache, trigger the
    // guarded operation, and confirm `resident_pages` actually drops to 0
    // (not just that the module happens to still return correct bytes for
    // some other reason).
    const gpa = testing.allocator;
    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    @memset(page, 0xAB);

    // 1) vOpen(.create_truncate): a truncating open on a path with a page
    //    still cached under a DIFFERENT, still-open handle on that same
    //    path must invalidate — otherwise the still-open handle's next
    //    full-page read returns pre-truncation bytes the file no longer has.
    {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
        defer pc.deinit();
        const st = pc.storage();

        const h0 = try st.open("a", .create_truncate);
        try st.writeAll(h0, page, 0);
        try testing.expect(pc.stats().resident_pages > 0);

        _ = try st.open("a", .create_truncate); // truncates "a" via a second handle
        try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
        // The now-empty file has nothing to read at offset 0: a stale hit
        // would instead return a full page of 0xAB.
        var buf: [default_page_size]u8 = undefined;
        const n = try st.pread(h0, &buf, 0);
        try testing.expectEqual(@as(usize, 0), n);
    }

    // 2) sub-page vWriteAll: an unaligned/partial write over a resident
    //    page must drop it — otherwise a later full-page read returns the
    //    pre-write bytes instead of the just-written change.
    {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
        defer pc.deinit();
        const st = pc.storage();

        const h = try st.open("b", .create_truncate);
        try st.writeAll(h, page, 0); // a full-page write caches too (write-through)
        try testing.expect(pc.stats().resident_pages > 0);

        try st.writeAll(h, "Z", 5); // sub-page, unaligned
        try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
        var buf: [default_page_size]u8 = undefined;
        _ = try st.pread(h, &buf, 0);
        try testing.expectEqual(@as(u8, 'Z'), buf[5]);
    }

    // 3) vTruncate: truncating away a resident page must drop it.
    {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
        defer pc.deinit();
        const st = pc.storage();

        const h = try st.open("c", .create_truncate);
        try st.writeAll(h, page, 0);
        try testing.expect(pc.stats().resident_pages > 0);

        try st.truncate(h, 0);
        try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
        var buf: [default_page_size]u8 = undefined;
        const n = try st.pread(h, &buf, 0);
        try testing.expectEqual(@as(usize, 0), n); // nothing left to read; a stale hit would return 0xAB * page_size
    }

    // 4) vClose: closing must drop resident pages, because the handle
    //    number can be recycled by an unrelated later open.
    {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
        defer pc.deinit();
        const st = pc.storage();

        const h = try st.open("d", .create_truncate);
        try st.writeAll(h, page, 0);
        try testing.expect(pc.stats().resident_pages > 0);

        st.close(h);
        try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);

        // A fresh, unrelated file reuses the just-freed handle number.
        const h2 = try st.open("e", .create_truncate);
        try testing.expectEqual(h, h2); // sanity: the slot really was reused
        var buf: [default_page_size]u8 = undefined;
        const n = try st.pread(h2, &buf, 0);
        try testing.expectEqual(@as(usize, 0), n); // "e" is empty; a stale hit would return "d"'s 0xAB page
    }

    // 5) vRename: must drop resident pages.
    {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
        defer pc.deinit();
        const st = pc.storage();

        const h = try st.open("f", .create_truncate);
        try st.writeAll(h, page, 0);
        try testing.expect(pc.stats().resident_pages > 0);

        try st.rename("f", "g");
        try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
    }

    // 6) vDelete: must drop resident pages.
    {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
        defer pc.deinit();
        const st = pc.storage();

        const h = try st.open("h", .create_truncate);
        try st.writeAll(h, page, 0);
        try testing.expect(pc.stats().resident_pages > 0);

        try st.delete("h");
        try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
    }
}

test "F4: vTryLockExclusive forwards to the inner Storage verbatim (dead in kvtree's own call path today)" {
    // `kvtree.Db.open` discards its options and never calls
    // `store.tryLockExclusive` at all, so this forwarding method has zero
    // exercise through the intended path. It is still `pub` on the
    // `Storage` vtable PageCache implements, so a direct caller must get
    // the real cross-process-lock semantics from the inner Storage, not a
    // locally-fabricated answer (the doc comment above `vTryLockExclusive`
    // explicitly warns against the cache ever answering this itself).
    // Mirrors `kv`'s own "the exclusive lock contends between handles"
    // test, one layer up through the cache.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const a = try st.open("lock-me", .open_or_create);
    const b = try st.open("lock-me", .open_or_create); // second description, same file

    try testing.expect(try st.tryLockExclusive(a));
    // The contending handle is refused — proves this reached the REAL
    // inner lock state, not a cache-local stub returning `true` for anyone.
    try testing.expect(!try st.tryLockExclusive(b));
    // Re-locking through the holder itself is still a no-op success.
    try testing.expect(try st.tryLockExclusive(a));

    st.close(a); // releases; there is no unlock op
    try testing.expect(try st.tryLockExclusive(b));
    st.close(b);
}
