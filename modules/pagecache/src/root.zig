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
//!
//! **Many handles per path.** Pages are keyed by (file id, page index). A file
//! id is assigned at `open` by path and refcounted across the handles open on
//! it, so two handles on the same path share one key space: a write through
//! one is seen by a read through the other. `rename` and `delete` re-bind the
//! path -> id table (an open handle keeps following its file, as with an
//! inode); `create_truncate` open drops that file's pages. Every
//! invalidation is per file; nothing clears the whole cache. Paths are
//! compared as byte strings: two spellings of one file ("x" and "./x") get two
//! ids, so open a file under one spelling. The last `close` of a file drops its
//! pages.
//!
//! **Read-ahead** (opt-in, `Options.read_ahead_pages`): see the option and
//! SPEC.md.
//!
//! **Fiber-reentrant on one thread.** Single-owner means one thread, not one
//! call at a time: when the inner `Storage` parks the calling fiber on its
//! I/O (qap's io_uring owner ring does), another fiber on the same thread may
//! call in meanwhile. Every inner call is made with the cache in a state a
//! second caller may see: a write reaches media before the cache is touched,
//! and a page being read into its slot is a miss for everyone else until it
//! is filled (ramcache hides unfilled reservations) -- so the second caller
//! reads it for itself and never sees the unfilled bytes. Found and pinned
//! for qap's research register H4 (2026-09-29): a kvtree reader and a commit
//! interleaved at every storage call, both directions.

const std = @import("std");
const kvtree = @import("kvtree");
const ramcache = @import("ramcache");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bounded write-through page cache between `kvtree`'s pager and its `Storage` — hot-cold tiering (W-TinyLFU via ramcache) with an RSS budget; transparent to callers",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    /// Sequential read-ahead depth, in pages. `0` (the default) is the module
    /// exactly as it was: one inner `pread` per missed page. With `k > 0`, a
    /// full-page `pread` miss on page `i` of a handle whose previous full-page
    /// access was page `i - 1` reads pages `i .. i + k` in ONE inner `pread`
    /// (clamped to the file's size and to `max_pages - 1` extra pages) and
    /// keeps the extra pages as ordinary, unpinned, evictable entries. See
    /// SPEC.md § "Read-ahead" for the safety argument.
    read_ahead_pages: u32 = 0,
};

/// One borrowed page: `bytes` points **into cache storage**, not into a
/// caller buffer, so obtaining it copied nothing. Hand it back with
/// `PageCache.releasePage` (or `Storage.releaseRef`) exactly once.
///
/// The lifetime rule is enforced by the cache, not by this doc comment: while
/// the borrow is live the underlying entry is not an eviction candidate at all
/// (`ramcache.Cache.pin` takes it out of the structures victim selection reads
/// from), and a write or invalidation that lands on the same page parks the
/// old bytes with this borrow instead of freeing them under it. So neither
/// eviction pressure nor a same-page overwrite can turn `bytes` into a
/// dangling read — the failure mode that made `ocspcache` F4 a real
/// use-after-free.
pub const Page = struct {
    bytes: []const u8,
    borrow: ramcache.Cache.Borrow,
};

/// Cumulative + current cache figures (a superset of `ramcache.Stats`).
pub const Stats = struct {
    /// Page-aligned reads served from RAM without touching the inner Storage.
    hits: u64,
    /// Page-aligned reads that had to fall through to the inner Storage.
    misses: u64,
    /// Currently resident pages: `<= max_pages + borrowed_pages` (a borrowed
    /// page is resident and unevictable; with none outstanding, `<= max_pages`).
    resident_pages: usize,
    /// Currently resident value bytes (`<= max_pages * page_size`).
    resident_bytes: usize,
    /// Lifetime pages removed by the bounded cache to stay within budget.
    evictions: u64,
    /// Pages currently lent out by `preadRef` and not yet released. They are
    /// resident and unevictable for as long as they are borrowed, so the
    /// budget can legitimately be exceeded by up to this many pages.
    borrowed_pages: usize,
    /// Page-aligned reads served as a borrow — **zero** copies, versus one
    /// `@memcpy` of a whole page for a `pread` hit.
    ref_hits: u64,
    /// `preadRef` misses filled straight into cache storage: one copy (the
    /// inner `pread`) instead of the two a `pread` miss pays.
    ref_misses: u64,
    /// Pages inserted by read-ahead (beyond the one the caller asked for).
    /// Always 0 when `Options.read_ahead_pages == 0`.
    readahead_pages: u64,
};

/// A bounded, write-through page cache in front of one inner `Storage`.
/// Construct with `init`, hand `storage()` to `kvtree.Db.open`, and `deinit`
/// when the store is closed.
pub const PageCache = struct {
    inner: Storage,
    cache: ramcache.Cache,
    page_size: usize,
    /// `log2(page_size)` when it is a power of two (kvtree's always is), so
    /// the per-access page arithmetic is a shift and a mask, not two 64-bit
    /// divisions -- measurable on a resident kvtree scan, one borrow per leaf.
    page_shift: ?std.math.Log2Int(u64),
    hits: u64 = 0,
    misses: u64 = 0,
    ref_hits: u64 = 0,
    ref_misses: u64 = 0,
    gpa: std.mem.Allocator,
    max_pages: usize,
    read_ahead_pages: u32,
    readahead_inserted: u64 = 0,
    /// Bumped on entry and exit of every operation that can change what media
    /// holds (`writeAll`, `truncate`, truncating `open`, `rename`, `delete`).
    /// A read-ahead compares it across its inner `pread`: if it moved, a
    /// second fiber may have written a page the read is about to describe with
    /// older bytes, so the prefetched pages are dropped instead of inserted.
    epoch: u64 = 0,
    /// Per-handle "last full-page index accessed", a tiny lossy table: a
    /// forgotten handle only costs one missed read-ahead, never correctness.
    seq: [seq_slots]SeqSlot = @as([seq_slots]SeqSlot, @splat(.{})),
    seq_next: usize = 0,
    /// Files with at least one open handle. Few entries (kvtree holds two), so
    /// lookups by path or id are linear scans; the table never grows with the
    /// store, only with the number of simultaneously open files.
    files: std.ArrayList(FileEntry) = .empty,
    /// Open handle -> file id. A handle absent here was not opened through
    /// this cache; its accesses go straight to the inner `Storage`.
    handle_file: std.AutoHashMapUnmanaged(Storage.Handle, FileId) = .empty,
    /// Starts at 0 on purpose: for the usual case of files opened once, in
    /// order, the file id equals the backend handle number the keys used
    /// before, so ramcache's (hash-dependent) admission behaves as it did.
    next_id: FileId = 0,
    const FileId = u32;
    /// `path == null` is an orphan: the name was deleted or renamed over, but
    /// handles keep the (inode-like) file alive and keep sharing its pages.
    const FileEntry = struct { id: FileId, path: ?[]u8, refs: u32 };
    const seq_slots = 8;
    const SeqSlot = struct { handle: Storage.Handle = 0, last: u64 = 0, valid: bool = false };
    /// Key layout for a cached page: the file id (so two files opened
    /// through the same cache never alias) followed by the page index.
    const key_len = 4 + 8;

    pub fn init(gpa: std.mem.Allocator, inner: Storage, options: Options) PageCache {
        // A named refusal, not `std.debug.assert`: `max_pages` has no default,
        // so a caller computing it (`cache_bytes / page_size` with
        // `cache_bytes < page_size`) gets 0, and in ReleaseFast the assert is
        // `unreachable` -- measured as a SIGSEGV inside `init` itself, before
        // it even returns. `page_size == 0` is the same shape one modulo away.
        if (options.page_size == 0) std.debug.panic("pagecache: page_size must be > 0", .{});
        if (options.max_pages == 0) std.debug.panic("pagecache: max_pages must be > 0", .{});
        // Checked: wrapped in ReleaseFast, the byte budget came out small and
        // the cache refused every page without a word.
        const max_bytes = std.math.mul(usize, options.max_pages, options.page_size) catch
            std.debug.panic("pagecache: max_pages * page_size overflows usize", .{});
        return .{
            .inner = inner,
            .cache = ramcache.Cache.init(gpa, .{
                .max_entries = options.max_pages,
                .max_bytes = max_bytes,
            }),
            .page_size = options.page_size,
            .page_shift = if (std.math.isPowerOfTwo(options.page_size)) std.math.log2_int(u64, options.page_size) else null,
            .gpa = gpa,
            .max_pages = options.max_pages,
            .read_ahead_pages = options.read_ahead_pages,
        };
    }

    /// Every `preadRef` borrow must be released first: a borrowed page's
    /// bytes belong to the borrower until `releasePage`.
    pub fn deinit(self: *PageCache) void {
        for (self.files.items) |f| if (f.path) |p| self.gpa.free(p);
        self.files.deinit(self.gpa);
        self.handle_file.deinit(self.gpa);
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
            .borrowed_pages = self.cache.stats.pinned,
            .ref_hits = self.ref_hits,
            .ref_misses = self.ref_misses,
            .readahead_pages = self.readahead_inserted,
        };
    }

    // ── borrow path (zero-copy reads) ───────────────────────────────────────

    /// Read exactly one whole page **without copying it**: the returned
    /// `Page.bytes` points into cache storage. A hit copies nothing at all; a
    /// miss copies once (the inner `pread` lands directly in the cache slot
    /// that will hold the page) instead of the two copies `pread` pays — once
    /// into the caller's buffer, once again when `cache.put` dupes it.
    ///
    /// Returns `null` when this access cannot be lent, and the caller must
    /// then use `pread`:
    ///   * `off`/`len` is not exactly one aligned page (never cached at all),
    ///   * the page is not fully present on media (a short read at EOF) —
    ///     a partial page is not a cacheable unit, same rule as `vPread`,
    ///   * the cache could not allocate the entry.
    /// There is deliberately no internal fall-back to a copying read: the
    /// point of this path is that a caller can tell whether it engaged.
    ///
    /// Release with `releasePage` exactly once. Holding a page across other
    /// operations on this cache is *safe* (that is what the pin is for) — a
    /// borrowed page is never evicted, and a write to the same page parks the
    /// borrowed bytes rather than overwriting them, so the borrow keeps the
    /// snapshot it was given while later readers see the new bytes.
    pub fn preadRef(self: *PageCache, h: Storage.Handle, len: usize, off: u64) Storage.Error!?Page {
        if (!self.isFullPage(off, len)) return null;
        const fid = self.fileOf(h) orelse return null;
        const page_index = self.pageIndex(off);
        const key = pageKey(fid, page_index);
        _ = self.noteAccess(h, page_index);

        if (self.cache.pin(&key, 0, 0)) |borrow| {
            self.ref_hits += 1;
            return .{ .bytes = borrow.bytes, .borrow = borrow };
        }
        // Miss: hand the inner Storage the cache's own slot to read into, so
        // the page is materialised exactly once.
        const fill = self.cache.reserve(&key, self.page_size, 0, 0, 0) orelse return null;
        const n = self.inner.pread(h, fill.bytes, off) catch |err| {
            self.cache.discard(fill);
            return err;
        };
        if (n != self.page_size) {
            // Never cache a partially-present page (same gate as `vPread`).
            self.cache.discard(fill);
            return null;
        }
        self.ref_misses += 1;
        const borrow = self.cache.commit(fill);
        return .{ .bytes = borrow.bytes, .borrow = borrow };
    }

    /// End a borrow taken with `preadRef`. The page becomes an ordinary
    /// eviction candidate again.
    pub fn releasePage(self: *PageCache, p: Page) void {
        self.cache.release(p.borrow);
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn cast(ctx: *anyopaque) *PageCache {
        return @ptrCast(@alignCast(ctx));
    }

    /// Is `off`/`len` an access of exactly one whole, aligned page?
    fn isFullPage(self: *const PageCache, off: u64, len: usize) bool {
        if (len != self.page_size) return false;
        if (self.page_shift != null) return off & (self.page_size - 1) == 0;
        return off % self.page_size == 0;
    }

    /// `off / page_size`, a shift for a power-of-two page size.
    fn pageIndex(self: *const PageCache, off: u64) u64 {
        if (self.page_shift) |sh| return off >> sh;
        return off / self.page_size;
    }

    fn pageKey(file: FileId, page_index: u64) [key_len]u8 {
        var k: [key_len]u8 = undefined;
        std.mem.writeInt(u32, k[0..4], file, .little);
        std.mem.writeInt(u64, k[4..12], page_index, .little);
        return k;
    }

    /// The key prefix every page of a file shares: `pageKey`'s id field.
    /// Whole-file invalidation sweeps this prefix over the RESIDENT set, which
    /// is bounded by `max_pages`; there is no side table of touched pages to
    /// keep, to grow, or to fail to allocate.
    fn filePrefix(file: FileId) [4]u8 {
        var k: [4]u8 = undefined;
        std.mem.writeInt(u32, &k, file, .little);
        return k;
    }

    fn fileOf(self: *const PageCache, h: Storage.Handle) ?FileId {
        return self.handle_file.get(h);
    }

    fn findById(self: *const PageCache, id: FileId) ?usize {
        for (self.files.items, 0..) |f, i| if (f.id == id) return i;
        return null;
    }

    fn findByPath(self: *const PageCache, path: []const u8) ?usize {
        for (self.files.items, 0..) |f, i| {
            if (f.path) |p| if (std.mem.eql(u8, p, path)) return i;
        }
        return null;
    }

    /// A file id no live entry uses (ids wrap after 2^32 opens; skip live ones).
    fn freshId(self: *PageCache) FileId {
        while (true) {
            const id = self.next_id;
            self.next_id +%= 1;
            if (self.findById(id) == null) return id;
        }
    }

    /// Record a full-page access of `h` at `page_index`; returns whether it
    /// continued a sequential run (the previous one was `page_index - 1`).
    fn noteAccess(self: *PageCache, h: Storage.Handle, page_index: u64) bool {
        for (&self.seq) |*sl| {
            if (sl.valid and sl.handle == h) {
                const sequential = page_index > 0 and sl.last == page_index - 1;
                sl.last = page_index;
                return sequential;
            }
        }
        self.seq[self.seq_next] = .{ .handle = h, .last = page_index, .valid = true };
        self.seq_next = (self.seq_next + 1) % seq_slots;
        return false;
    }

    fn forgetAccess(self: *PageCache, h: Storage.Handle) void {
        for (&self.seq) |*sl| {
            if (sl.valid and sl.handle == h) sl.valid = false;
        }
    }

    fn dropFile(self: *PageCache, file: FileId) void {
        const prefix = filePrefix(file);
        _ = self.cache.removeMatching(&prefix);
    }

    /// Drop the cached pages of `h` that a truncate to `len` can have changed:
    /// every page at index `>= len / page_size` (the boundary page, when `len`
    /// is not page-aligned, is partial afterwards and must go too). ramcache
    /// has no predicate removal, so this removes the candidate keys one by one
    /// when their span is small and otherwise sweeps the whole handle by
    /// prefix (a sound superset). `old_size == null` (or a failed truncate,
    /// whose media state is unknown) also means the sweep.
    fn dropFrom(self: *PageCache, file: FileId, len: u64, old_size: ?u64, known: bool) void {
        if (known) if (old_size) |os| {
            const first = len / self.page_size;
            const end = os / self.page_size + @intFromBool(os % self.page_size != 0);
            if (end <= first) return; // grew or unchanged: no resident page lies past the old end
            if (end - first <= 4 *| self.max_pages) {
                var i = first;
                while (i < end) : (i += 1) {
                    const key = pageKey(file, i);
                    _ = self.cache.remove(&key);
                }
                return;
            }
        };
        self.dropFile(file);
    }

    /// Read-ahead on a sequential full-page miss of page `off / page_size`:
    /// one inner `pread` of up to `read_ahead_pages + 1` pages into a scratch
    /// buffer. Returns the page-`i` result for the caller (already copied into
    /// `buf`) or `null` when read-ahead did not apply / did not work and the
    /// caller must take the ordinary single-page path.
    fn readAhead(self: *PageCache, h: Storage.Handle, fid: FileId, buf: []u8, off: u64) ?usize {
        const ps = self.page_size;
        const extra_cap: u64 = @min(self.read_ahead_pages, self.max_pages -| 1);
        if (extra_cap == 0) return null;
        const size = self.inner.size(h) catch return null;
        if (size <= off) return null;
        const avail_pages = (size - off) / ps; // whole pages present from `off`
        const total: usize = @intCast(@min(avail_pages, extra_cap + 1));
        if (total < 2) return null;
        const tmp = self.gpa.alloc(u8, total * ps) catch return null;
        defer self.gpa.free(tmp);
        const epoch0 = self.epoch;
        const n = self.inner.pread(h, tmp, off) catch return null;
        if (n < ps) return null; // let the ordinary path see and report it
        @memcpy(buf, tmp[0..ps]);
        const got = n / ps; // whole pages media really returned
        const index = off / ps;
        if (self.epoch == epoch0) {
            // Extra pages first, the requested page last, so at a tiny budget
            // the page the caller asked for is the one that stays.
            var j: usize = 1;
            while (j < got) : (j += 1) {
                const key = pageKey(fid, index + j);
                self.cache.put(&key, tmp[j * ps ..][0..ps], 0, 0, 0);
                self.readahead_inserted += 1;
            }
        }
        // The requested page is guarded like the extras: a write that landed
        // while the inner `pread` was parked has already put its NEWER bytes,
        // and `buf` (older) must not replace them. The caller still gets the
        // bytes media held when it read.
        if (self.epoch == epoch0) {
            const key = pageKey(fid, index);
            self.cache.put(&key, buf, 0, 0, 0);
        }
        return ps;
    }

    // ── Storage vtable ───────────────────────────────────────────────────────

    const vtable = Storage.VTable{
        .open = vOpen,
        .size = vSize,
        .pread = vPread,
        .writeAll = vWriteAll,
        .sync = vSync,
        .syncData = vSyncData,
        .truncate = vTruncate,
        .close = vClose,
        .rename = vRename,
        .delete = vDelete,
        .syncDir = vSyncDir,
        .tryLockExclusive = vTryLockExclusive,
        .tryLockShared = vTryLockShared,
        // This is the one backend in the seam that *can* lend: it is the only
        // one that holds page bytes in its own memory. `FsStorage` and
        // `SimStorage` leave these null and `Storage.canLend()` answers false
        // for them, so a caller reading through a raw backend keeps the
        // copying path and knows it.
        .preadRef = vPreadRef,
        .releaseRef = vReleaseRef,
        .list = vList,
        .allocate = vAllocate,
    };

    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        const self = cast(ctx);
        const h = try self.inner.open(path, mode);
        // A truncating open has emptied the file on media already: its pages
        // under other open handles go NOW, before anything below can fail.
        // Until 2026-10-23 they went at the end, so an allocation failure in
        // between left those handles serving pre-truncation bytes as hits.
        if (mode == .create_truncate) if (self.findByPath(path)) |i| {
            self.epoch +%= 1;
            self.dropFile(self.files.items[i].id);
        };
        // Everything below runs without yielding to another fiber, so the
        // tables cannot change between the lookup and the update.
        errdefer self.inner.close(h);
        // A backend that hands out a handle number we still map did not see a
        // close; release the stale mapping rather than leak its refcount.
        if (self.handle_file.fetchRemove(h)) |stale| self.releaseFile(stale.value);
        try self.handle_file.ensureUnusedCapacity(self.gpa, 1);
        const existing = self.findByPath(path);
        var fresh_path: ?[]u8 = null;
        if (existing == null) {
            try self.files.ensureUnusedCapacity(self.gpa, 1);
            fresh_path = try self.gpa.dupe(u8, path);
        }
        var fid: FileId = undefined;
        if (existing) |i| {
            fid = self.files.items[i].id;
            self.files.items[i].refs += 1;
        } else {
            fid = self.freshId();
            self.files.appendAssumeCapacity(.{ .id = fid, .path = fresh_path, .refs = 1 });
        }
        self.handle_file.putAssumeCapacity(h, fid);
        // (A truncating open's pages went above, before anything could fail;
        // a file new to the table has none.)
        if (mode == .create_truncate) self.forgetAccess(h);
        return h;
    }

    /// One handle of `fid` went away; the last one drops the file's pages and
    /// its table entry.
    fn releaseFile(self: *PageCache, fid: FileId) void {
        const i = self.findById(fid) orelse return;
        const e = &self.files.items[i];
        e.refs -= 1;
        if (e.refs != 0) return;
        // A read parked on this file must not insert its pages afterwards.
        self.epoch +%= 1;
        self.dropFile(fid);
        if (e.path) |pth| self.gpa.free(pth);
        _ = self.files.swapRemove(i);
    }

    /// The name of entry `i` no longer leads to its file (deleted, renamed
    /// over, or rebinding failed). Open handles keep it and its pages; no later
    /// `open` can reach it.
    fn orphan(self: *PageCache, i: usize) void {
        const e = &self.files.items[i];
        if (e.path) |pth| self.gpa.free(pth);
        e.path = null;
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
        const fid = self.fileOf(h) orelse return self.inner.pread(h, buf, off);

        const key = pageKey(fid, self.pageIndex(off));
        const sequential = self.noteAccess(h, self.pageIndex(off));
        if (self.cache.get(&key, 0, 0)) |cached| {
            @memcpy(buf, cached); // cached.len == page_size == buf.len
            self.hits += 1;
            return self.page_size;
        }
        self.misses += 1;
        if (sequential and self.read_ahead_pages > 0) {
            if (self.readAhead(h, fid, buf, off)) |n| return n;
        }
        const epoch0 = self.epoch;
        const n = try self.inner.pread(h, buf, off);
        // Only a full, present page is a cacheable unit (a short read means the
        // page is not fully on media — never cache a partial page). And only
        // bytes no mutation raced: over an inner `Storage` that parks the
        // fiber, a write through this cache can land while this read is
        // parked, and it has already put the NEWER bytes -- inserting these
        // would replace them with older ones, a stale hit served for as long
        // as the page stays resident. The caller still gets what media held
        // when it read; only the cache skips it.
        if (n == self.page_size and self.epoch == epoch0) {
            self.cache.put(&key, buf, 0, 0, 0);
        }
        return n;
    }

    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        // WRITE-THROUGH: the durable write happens first and must succeed
        // before we touch the cache.
        //
        // On inner failure the cache must not simply be left alone. "The last
        // correct copy" assumes the write was all-or-nothing, and the real
        // `FsStorage` shape is a looping `pwrite` whose second chunk can fail
        // after the first landed. The resident page is then OLDER than media,
        // and the cache MASKS the torn page from every subsequent reader in
        // the process while a raw reader sees it -- breaking the transparency
        // invariant in the direction that hides damage. After a failed write
        // the media state is unknown, so the only answer we can honestly give
        // is "absent": drop it and let the next read go to media.
        self.epoch +%= 1;
        defer self.epoch +%= 1;
        // The file id is looked up AFTER the inner write: it may park this
        // fiber, and the handle can be closed (and the file's pages dropped)
        // meanwhile. A handle no longer mapped has no pages to refresh.
        self.inner.writeAll(h, bytes, off) catch |err| {
            const fid = self.fileOf(h) orelse return err;
            if (self.isFullPage(off, bytes.len)) {
                const failed_key = pageKey(fid, self.pageIndex(off));
                _ = self.cache.remove(&failed_key);
            } else {
                // Sub-page/unaligned failed write: media state unknown for
                // this file's pages (all handles on the path share them).
                self.dropFile(fid);
            }
            return err;
        };
        const fid = self.fileOf(h) orelse return;

        if (self.isFullPage(off, bytes.len)) {
            const page_index = self.pageIndex(off);
            const key = pageKey(fid, page_index);
            // Replace-in-place if resident (put over an existing key always
            // succeeds and never mis-admits), else offer it to the cache.
            self.cache.put(&key, bytes, 0, 0, 0);
        } else {
            // A sub-page or unaligned write could partially overlap several
            // resident pages we cannot pick out cheaply; drop every page of
            // THIS file (shared by all handles open on it). kvtree never
            // issues such a write, so this is defensive.
            self.dropFile(fid);
        }
    }

    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        return cast(ctx).inner.sync(h);
    }

    /// Forwarded, so a caller's `fdatasync` reaches the backend instead of
    /// widening into `Storage.syncData`'s full-`sync` fallback (write-through:
    /// the inner backend already holds every byte this would make durable).
    fn vSyncData(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        return cast(ctx).inner.syncData(h);
    }

    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        // Only THIS file's pages can be affected (the cache key starts with
        // the file id, shared by every handle on the path), and of those only
        // the pages at or past the new length -- see `dropFrom`.
        // The old size bounds the candidate span; it is read before the
        // truncate because afterwards it is gone.
        const old_size: ?u64 = self.inner.size(h) catch null;
        self.epoch +%= 1;
        const during = self.epoch;
        const result = self.inner.truncate(h, len);
        // A write that landed while the truncate was parked may have cached a
        // page past `old_size`, which the narrow span would miss: then sweep.
        const raced = self.epoch != during;
        self.epoch +%= 1;
        // Also on failure: a failed truncate leaves the media state unknown,
        // and "absent" is the only honest answer (see `vWriteAll`).
        if (self.fileOf(h)) |fid| {
            const ok = if (result) |_| true else |_| false;
            self.dropFrom(fid, len, old_size, ok and !raced);
        }
        self.forgetAccess(h);
        return result;
    }

    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        const self = cast(ctx);
        self.inner.close(h);
        // The handle number may be recycled by the backend for a different
        // file, so the handle -> file mapping goes now. Pages belong to the
        // FILE: other handles still open on it keep sharing them, and the last
        // close drops them (sweeping the RESIDENT set by key prefix: exact,
        // allocation-free, bounded by `max_pages`).
        //
        // An earlier form kept a per-handle set of every page index the
        // handle had ever touched. Two defects, both structural: the set grew
        // with the STORE (measured at ~12 B live / ~18 B peak per distinct
        // page, so a 4-page budget over 200 000 pages held 2.4 MB -- 145x the
        // cache's own ceiling), and it was populated best-effort, so a page
        // whose tracking allocation failed survived the close and was served
        // to a DIFFERENT file through the recycled handle number.
        if (self.handle_file.fetchRemove(h)) |entry| self.releaseFile(entry.value);
        self.forgetAccess(h);
    }

    /// `old_path`'s file now answers to `new_path`: its open handles keep
    /// following it and its pages stay valid (same file, new name). Whatever
    /// file `new_path` named before is unreachable by name from now on:
    /// orphaned, its pages dropped. No other file is touched.
    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        try self.inner.rename(old_path, new_path);
        self.epoch +%= 1;
        if (std.mem.eql(u8, old_path, new_path)) return;
        if (self.findByPath(new_path)) |j| {
            self.dropFile(self.files.items[j].id);
            self.orphan(j);
        }
        if (self.findByPath(old_path)) |i| {
            if (self.gpa.dupe(u8, new_path)) |np| {
                self.gpa.free(self.files.items[i].path.?);
                self.files.items[i].path = np;
            } else |_| {
                // Cannot rebind the name: the only safe answer is to forget
                // the file's pages and stop resolving the old name to it.
                self.dropFile(self.files.items[i].id);
                self.orphan(i);
            }
        }
    }

    /// `path` stops naming its file: open handles keep it (inode semantics of
    /// the backends), but a later `open` of the name makes a new file. Only
    /// that file's pages are dropped.
    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        try self.inner.delete(path);
        self.epoch +%= 1;
        if (self.findByPath(path)) |i| {
            self.dropFile(self.files.items[i].id);
            self.orphan(i);
        }
    }

    /// Forwarded: preallocation only adds zeros past the end, and no page
    /// past the end is ever resident (a partial page is never cached), so
    /// nothing to invalidate. A backend that cannot preallocate answers false.
    fn vAllocate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!bool {
        return cast(ctx).inner.allocate(h, len);
    }

    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }

    /// Forwarded verbatim: the cache holds pages, not names. An inner
    /// backend that cannot list makes this one answer `null` too.
    fn vList(ctx: *anyopaque, gpa: std.mem.Allocator, prefix: []const u8) Storage.Error!?Storage.Listing {
        return cast(ctx).inner.list(gpa, prefix);
    }

    /// Forwarded verbatim: the cross-process lock belongs to the real backing
    /// file, and a cache that answered it locally would hand out an exclusion
    /// guarantee it cannot enforce.
    fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }

    /// Forwarded verbatim, for the same reason.
    fn vTryLockShared(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockShared(h);
    }

    fn vPreadRef(ctx: *anyopaque, h: Storage.Handle, len: usize, off: u64) Storage.Error!?Storage.Ref {
        const self = cast(ctx);
        const page = (try self.preadRef(h, len, off)) orelse return null;
        // The borrow's index node is a stable heap allocation for exactly this
        // reason: it survives the cache's hash map rehashing, so it is a legal
        // opaque token to hand across the seam and back.
        return .{ .bytes = page.bytes, .token = @ptrCast(page.borrow.node) };
    }

    fn vReleaseRef(ctx: *anyopaque, ref: Storage.Ref) void {
        const self = cast(ctx);
        self.releasePage(.{
            .bytes = ref.bytes,
            .borrow = .{ .bytes = ref.bytes, .node = @ptrCast(@alignCast(ref.token)) },
        });
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
    // CONVENTIONS §6.3: a bare import does not pull the file's tests in.
    _ = @import("bench.zig");
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
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
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
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
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
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
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
        const key = try std.mem.print(&kbuf, "k{d}", .{i});
        try db.put(key, "v");
    }
    // Read the newest committed state back — a stale cached meta page would
    // point at an old root and lose recent keys.
    i = 0;
    while (i < 50) : (i += 1) {
        const key = try std.mem.print(&kbuf, "k{d}", .{i});
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

    // 5) vRename: the renamed file's pages MOVE with it (same file, new
    //    name, so they stay valid); the replaced file's pages are dropped.
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
        try testing.expect(pc.stats().resident_pages > 0); // still resident under the new name
        var buf: [default_page_size]u8 = undefined;
        const hits0 = pc.stats().hits;
        _ = try st.pread(h, &buf, 0);
        try testing.expectEqual(hits0 + 1, pc.stats().hits);
        try testing.expectEqualSlices(u8, page, &buf);

        // A rename OVER an existing, open file drops that file's pages.
        const victim = try st.open("v", .create_truncate);
        try st.writeAll(victim, page, 0);
        try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages);
        try st.rename("g", "v");
        try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages);
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

/// Read page 0 of `h` through `st`; returns whether it was a cache hit and
/// the byte it holds (every test page is filled with one byte).
fn probePage(pc: *PageCache, st: Storage, h: Storage.Handle) !struct { hit: bool, first: u8, n: usize } {
    var buf: [default_page_size]u8 = undefined;
    const hits0 = pc.stats().hits;
    const n = try st.pread(h, &buf, 0);
    return .{ .hit = pc.stats().hits == hits0 + 1, .first = if (n > 0) buf[0] else 0, .n = n };
}

fn putPage(gpa: std.mem.Allocator, st: Storage, h: Storage.Handle, fill: u8) !void {
    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    @memset(page, fill);
    try st.writeAll(h, page, 0);
}

test "multi-handle: two handles on one path share pages; a write through either is seen by the other" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const h1 = try st.open("shared", .open_or_create);
    const h2 = try st.open("shared", .open_or_create);
    try putPage(gpa, st, h1, 1);
    const a = try probePage(&pc, st, h2); // written via h1, read via h2
    try testing.expect(a.hit);
    try testing.expectEqual(@as(u8, 1), a.first);
    try putPage(gpa, st, h2, 2); // overwritten via h2, read via h1
    const b = try probePage(&pc, st, h1);
    try testing.expect(b.hit);
    try testing.expectEqual(@as(u8, 2), b.first);
    try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages); // ONE page, not one per handle

    // Truncate through one handle is seen by the other.
    try st.truncate(h1, 0);
    const c = try probePage(&pc, st, h2);
    try testing.expectEqual(@as(usize, 0), c.n);

    // Closing one handle keeps the shared pages for the other; the last close drops them.
    try putPage(gpa, st, h1, 3);
    st.close(h1);
    const d = try probePage(&pc, st, h2);
    try testing.expect(d.hit);
    try testing.expectEqual(@as(u8, 3), d.first);
    st.close(h2);
    try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
    try testing.expectEqual(@as(usize, 0), pc.files.items.len);
    try testing.expectEqual(@as(u32, 0), pc.handle_file.count());
}

test "multi-handle: rename, delete and create_truncate touch only the affected path's pages" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const hx = try st.open("x", .open_or_create);
    const hy = try st.open("y", .open_or_create);
    const hy2 = try st.open("y", .open_or_create);
    const hz = try st.open("z", .open_or_create);
    try putPage(gpa, st, hx, 10);
    try putPage(gpa, st, hy, 20);
    try putPage(gpa, st, hz, 30);
    try testing.expectEqual(@as(usize, 3), pc.stats().resident_pages);

    // rename(x, w): x's pages move with the file, y and z stay resident.
    try st.rename("x", "w");
    try testing.expectEqual(@as(usize, 3), pc.stats().resident_pages);
    for ([_]struct { Storage.Handle, u8 }{ .{ hx, 10 }, .{ hy, 20 }, .{ hy2, 20 }, .{ hz, 30 } }) |c| {
        const r = try probePage(&pc, st, c[0]);
        try testing.expect(r.hit);
        try testing.expectEqual(c[1], r.first);
    }
    // The renamed file answers to its new name: a new handle shares its pages.
    const hw = try st.open("w", .open_or_create);
    const rw = try probePage(&pc, st, hw);
    try testing.expect(rw.hit and rw.first == 10);

    // delete(y): only y's pages go; its open handles keep reading the (now
    // nameless) file from the backend, and z / w stay resident.
    try st.delete("y");
    try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages);
    try testing.expect((try probePage(&pc, st, hz)).hit);
    try testing.expect((try probePage(&pc, st, hw)).hit);
    const old_y = try probePage(&pc, st, hy);
    try testing.expect(!old_y.hit);
    try testing.expectEqual(@as(u8, 20), old_y.first);
    // Reopening y after the delete is a NEW, empty file: no stale bytes.
    const hy_new = try st.open("y", .open_or_create);
    const fresh = try probePage(&pc, st, hy_new);
    try testing.expectEqual(@as(usize, 0), fresh.n);
    try putPage(gpa, st, hy_new, 21);
    try testing.expectEqual(@as(u8, 20), (try probePage(&pc, st, hy2)).first); // the old file is not the new one
    try testing.expectEqual(@as(u8, 21), (try probePage(&pc, st, hy_new)).first);

    // create_truncate of z through a second handle: z's pages go, others stay.
    const before = pc.stats().resident_pages;
    const hz2 = try st.open("z", .create_truncate);
    try testing.expectEqual(before - 1, pc.stats().resident_pages);
    try testing.expectEqual(@as(usize, 0), (try probePage(&pc, st, hz)).n);
    try testing.expectEqual(@as(usize, 0), (try probePage(&pc, st, hz2)).n);
    try testing.expect((try probePage(&pc, st, hw)).hit);
    try testing.expect((try probePage(&pc, st, hy_new)).hit);

    // rename OVER an existing path: the replaced file's pages are dropped,
    // the moved file's are kept, and the old name stops resolving.
    try putPage(gpa, st, hz2, 31);
    try st.rename("z", "w");
    const rw2 = try probePage(&pc, st, hz2);
    try testing.expect(rw2.hit and rw2.first == 31);
    const old_w = try probePage(&pc, st, hw); // the replaced inode, still open
    try testing.expect(!old_w.hit);
    try testing.expectEqual(@as(u8, 10), old_w.first);
    const hw_new = try st.open("w", .open_or_create);
    const rw3 = try probePage(&pc, st, hw_new);
    try testing.expect(rw3.hit and rw3.first == 31);

    for ([_]Storage.Handle{ hx, hy, hy2, hz, hw, hy_new, hz2, hw_new }) |h| st.close(h);
    try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
    try testing.expectEqual(@as(usize, 0), pc.files.items.len);
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

test "list forwards to the inner Storage, and says null when the inner one cannot list" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    st.close(try st.open("b", .create_new));
    st.close(try st.open("a", .create_new));
    const l = (try st.list(gpa, "")).?;
    defer l.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), l.names.len);
    try testing.expectEqualStrings("a", l.names[0]);
    try testing.expectEqualStrings("b", l.names[1]);

    var vt = sim.storage().vtable.*;
    vt.list = null;
    var pc2 = PageCache.init(gpa, .{ .ctx = &sim, .vtable = &vt }, .{ .max_pages = 8 });
    defer pc2.deinit();
    try testing.expect(try pc2.storage().list(gpa, "") == null);
}

/// Write `n` distinct full pages (page `i` filled with byte `i+1`) through
/// `st`, then leave the cache empty so a following read is a genuine miss.
fn seedPages(gpa: std.mem.Allocator, pc: *PageCache, st: Storage, n: usize) !Storage.Handle {
    const h = try st.open("pages", .create_truncate);
    const page = try gpa.alloc(u8, pc.page_size);
    defer gpa.free(page);
    for (0..n) |i| {
        @memset(page, @as(u8, @truncate(i + 1)));
        try st.writeAll(h, page, i * pc.page_size);
    }
    pc.cache.clear(); // start every borrow test from a cold cache
    return h;
}

test "F3: a borrowed page is unevictable — it survives pressure that discards every other page, and is evictable again once released" {
    // The borrow path's whole safety claim. Without the pin, `preadRef` would
    // be `get`'s slice with `get`'s rule ("valid until this key is replaced,
    // evicted, or the cache is cleared") — and 23 fills into a 4-page budget
    // is exactly that. Two things must hold while the borrow is live: the
    // bytes are still page 0's bytes, and page 0 is still RESIDENT (so the
    // borrow is the real entry, not a copy that got orphaned). And one thing
    // must hold after: releasing puts it back in the eviction index, or the
    // budget would leak a slot per borrow forever.
    //
    // **Why `max_pages = 1`.** The first version of this test used a 4-page
    // budget and 23 competing reads, and it passed *with the pin mechanism
    // disabled* — W-TinyLFU is scan-resistant on purpose, so a page touched
    // twice beats a stream of one-hit-wonder pages and simply was never
    // chosen as a victim. The harness could not reach the thing it was
    // testing. At a budget of 1 the eviction decision is forced and has no
    // frequency contest in it: an unpinned page 0 is the window's LRU and is
    // dropped by the very next fill, a pinned one is not in the window heap
    // at all so the incoming page is dropped instead.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;

    const budget = 1;
    const n_pages = 8;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = budget });
    defer pc.deinit();
    const st = pc.storage();
    const h = try seedPages(gpa, &pc, st, n_pages);

    // Borrow page 0 — zero copies: `bytes` IS the cache's storage.
    const borrowed = (try pc.preadRef(h, default_page_size, 0)).?;
    try testing.expectEqual(@as(u64, 1), pc.stats().ref_misses);

    // Stream every other page through the one-page cache.
    const evictions_before = pc.stats().evictions;
    var buf: [default_page_size]u8 = undefined;
    for (1..n_pages) |i| _ = try st.pread(h, &buf, i * default_page_size);
    try testing.expect(pc.stats().evictions - evictions_before >= n_pages - 1 - budget);
    // Every one of those fills competed for the single slot page 0 holds.
    try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages);

    // 1) The borrowed bytes are still page 0's bytes. Freed storage would be
    //    a use-after-free; a recycled slot would show some other page.
    for (borrowed.bytes) |b| try testing.expectEqual(@as(u8, 1), b);

    // 2) Page 0 is still resident — re-reading it costs no inner read. This
    //    is the assertion that fails if the borrow is not pinned: at a budget
    //    of 1, seven competing fills evict it and this read becomes a miss.
    const misses_before = pc.misses;
    _ = try st.pread(h, &buf, 0);
    try testing.expectEqual(misses_before, pc.misses);
    try testing.expectEqualSlices(u8, borrowed.bytes, &buf);
    try testing.expectEqual(@as(usize, 1), pc.stats().borrowed_pages);

    pc.releasePage(borrowed);
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);

    // 3) Released means evictable again: the same pressure now does drop it.
    for (1..n_pages) |i| _ = try st.pread(h, &buf, i * default_page_size);
    const misses_after = pc.misses;
    _ = try st.pread(h, &buf, 0);
    try testing.expectEqual(misses_after + 1, pc.misses); // a real miss
    for (buf) |b| try testing.expectEqual(@as(u8, 1), b); // and still correct
}

test "F3: a write to a borrowed page neither corrupts the borrow nor leaves the cache stale" {
    // The `ocspcache` F4 shape: a borrow invalidated by the next refresh. A
    // write-through cache MUST make the new bytes visible to the next reader,
    // and MUST NOT free or overwrite bytes a borrower is still reading. Doing
    // one at the cost of the other is the bug; the cache does both by parking
    // the old page with its borrower and inserting the new one fresh.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;

    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try seedPages(gpa, &pc, st, 4);

    const borrowed = (try pc.preadRef(h, default_page_size, 0)).?;
    for (borrowed.bytes) |b| try testing.expectEqual(@as(u8, 1), b);

    // Overwrite page 0 through the cache while the borrow is live.
    const fresh = try gpa.alloc(u8, default_page_size);
    defer gpa.free(fresh);
    @memset(fresh, 0xBB);
    try st.writeAll(h, fresh, 0);

    // The borrow still reads its own snapshot, not the new bytes and not
    // freed memory.
    for (borrowed.bytes) |b| try testing.expectEqual(@as(u8, 1), b);

    // And the cache is NOT stale: the next reader sees the write.
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    try testing.expectEqualSlices(u8, fresh, &buf);

    // Same for a fresh borrow of the same page.
    const reborrowed = (try pc.preadRef(h, default_page_size, 0)).?;
    try testing.expectEqualSlices(u8, fresh, reborrowed.bytes);
    try testing.expect(reborrowed.bytes.ptr != borrowed.bytes.ptr); // two live snapshots

    pc.releasePage(reborrowed);
    pc.releasePage(borrowed); // frees the parked page; a leak here fails the test
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);
}

test "F3: invalidation guards still empty the cache with a borrow outstanding (nothing findable, nothing freed under the borrower)" {
    // `clear()` is the other way a borrowed entry can die. The six guards'
    // contract (F2) is "resident_pages drops to 0" — that must stay literally
    // true even when one of those pages is lent out.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;

    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try seedPages(gpa, &pc, st, 2);

    const borrowed = (try pc.preadRef(h, default_page_size, 0)).?;
    try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages);

    try st.truncate(h, 0); // one of the six clear() guards
    try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
    // Still a valid, unchanged snapshot for the borrower.
    for (borrowed.bytes) |b| try testing.expectEqual(@as(u8, 1), b);
    // And no stale hit: the file is empty now.
    var buf: [default_page_size]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try st.pread(h, &buf, 0));

    pc.releasePage(borrowed);
}

test "F3: only a backend that really holds the bytes advertises lending; the rest say so instead of silently copying" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;

    // The raw backend cannot lend and admits it — no stub that copies behind
    // the caller's back, so `canLend` is a usable branch condition.
    try testing.expect(!sim.storage().canLend());
    const raw_h = try sim.storage().open("x", .create_truncate);
    try testing.expect(try sim.storage().preadRef(raw_h, default_page_size, 0) == null);

    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    try testing.expect(st.canLend());

    const h = try seedPages(gpa, &pc, st, 2);

    // Non-page-shaped accesses are not lendable either — same rule as the
    // copying path's "only aligned whole pages are cached".
    try testing.expect(try st.preadRef(h, 8, 5) == null);
    try testing.expect(try st.preadRef(h, default_page_size, 5) == null);
    // Nor is a page that is not fully present on media.
    try testing.expect(try st.preadRef(h, default_page_size, 9 * default_page_size) == null);

    // The whole seam round-trip: borrow through the vtable, release through it.
    const ref = (try st.preadRef(h, default_page_size, default_page_size)).?;
    for (ref.bytes) |b| try testing.expectEqual(@as(u8, 2), b);
    try testing.expectEqual(@as(usize, 1), pc.stats().borrowed_pages);
    st.releaseRef(ref);
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);

    // A borrowed read returns exactly what the copying read returns.
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    const p = (try pc.preadRef(h, default_page_size, 0)).?;
    defer pc.releasePage(p);
    try testing.expectEqualSlices(u8, &buf, p.bytes);
    try testing.expect(p.bytes.ptr != @as([*]const u8, &buf)); // not a copy of the caller's buffer
}

test "F3: kvtree's read descent really takes the borrow seam, and still reads identically to the copying one" {
    // A seam nothing calls is a seam nothing checks. `kvtree`'s `lookup`
    // descent is the one tree path that can borrow (read-only, one page live
    // at a time), so this asserts it *does* — `ref_hits` counts pages handed
    // to it without a copy — and that the answers are byte-identical to the
    // same store read through the raw backend.
    const gpa = testing.allocator;

    var raw_sim = kv.SimStorage.init(gpa);
    defer raw_sim.deinit();
    raw_sim.allow_overwrite = true;
    var raw_db = try kvtree.Db.open(gpa, raw_sim.storage(), "t.kvt", .{});
    defer raw_db.close();

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 64 });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    const scratch = try gpa.alloc(u8, 64);
    defer gpa.free(scratch);
    try runWorkload(&raw_db, 0xF00D, 600, 150, 64, scratch);
    try runWorkload(&db, 0xF00D, 600, 150, 64, scratch);

    const ref_hits_before = pc.stats().ref_hits;
    var kbuf: [32]u8 = undefined;
    var id: u64 = 0;
    while (id < 150) : (id += 1) {
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
        const a = try raw_db.get(gpa, key);
        defer if (a) |v| gpa.free(v);
        const b = try db.get(gpa, key);
        defer if (b) |v| gpa.free(v);
        if (a) |av| {
            try testing.expect(b != null);
            try testing.expectEqualSlices(u8, av, b.?);
        } else {
            try testing.expect(b == null);
        }
    }
    // The descent borrowed resident pages instead of copying them, and gave
    // every one of them back.
    try testing.expect(pc.stats().ref_hits > ref_hits_before);
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);
}

test "F3: kvtree's cursor borrows its frames, holds no more than its depth, and gives every one back" {
    // The cursor keeps a root-to-leaf stack across `next` calls, so unlike the
    // descent its borrows outlive a call: this checks the release discipline
    // (leaving a leaf, re-seeking, deinit) and that a scan in both directions
    // over a cache far smaller than the store, with a commit overwriting pages
    // mid-scan, reads exactly what the copying cursor over the raw backend does.
    const gpa = testing.allocator;

    var raw_sim = kv.SimStorage.init(gpa);
    defer raw_sim.deinit();
    raw_sim.allow_overwrite = true;
    var raw_db = try kvtree.Db.open(gpa, raw_sim.storage(), "t.kvt", .{});
    defer raw_db.close();

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 6 });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    const scratch = try gpa.alloc(u8, 64);
    defer gpa.free(scratch);
    try runWorkload(&raw_db, 0xC0B5, 1500, 400, 64, scratch);
    try runWorkload(&db, 0xC0B5, 1500, 400, 64, scratch);

    var raw_snap = try raw_db.snapshot();
    defer raw_snap.release();
    var snap = try db.snapshot();
    defer snap.release();
    var raw_cur = try raw_snap.cursor();
    defer raw_cur.deinit();
    var cur = try snap.cursor();

    const ref_hits_before = pc.stats().ref_hits;
    try raw_cur.first();
    try cur.first();
    var n: usize = 0;
    while (try raw_cur.next()) |want| : (n += 1) {
        const got = (try cur.next()).?;
        try testing.expectEqualStrings(want.key, got.key);
        try testing.expectEqualSlices(u8, want.val, got.val);
        // At most one borrow per tree level is ever outstanding.
        try testing.expect(pc.stats().borrowed_pages <= 4);
        // A commit overwriting the pages under the cursor: the snapshot's
        // cursor keeps reading the version it started on.
        if (n == 40) try runWorkload(&db, 0xBEEF, 300, 400, 64, scratch);
    }
    try testing.expect(try cur.next() == null);
    try testing.expect(n > 100);
    try testing.expect(pc.stats().ref_hits > ref_hits_before);

    // Backwards from a seek, then a re-seek drops the old stack's borrows.
    try raw_cur.seekAfter("key00300");
    try cur.seekAfter("key00300");
    while (try raw_cur.prev()) |want| {
        const got = (try cur.prev()).?;
        try testing.expectEqualStrings(want.key, got.key);
    }
    try testing.expect(try cur.prev() == null);
    try cur.seek("key00200");
    try testing.expect(pc.stats().borrowed_pages > 0);
    cur.deinit();
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);
}

/// A `Storage` that forwards everything to an inner one but can make
/// `writeAll` fail -- optionally after landing part of the bytes, which is the
/// real `FsStorage` shape (a looping `pwrite` whose second chunk can hit
/// `ENOSPC` after the first landed).
///
/// The suite had no such backend, so **no test ever made an inner write fail**
/// and `vWriteAll`'s entire error path -- the module's central safety claim --
/// was unexercised. Two guards were deletable with the suite green because of
/// it.
const FaultStorage = struct {
    inner: Storage,
    /// Fail the write whose 0-based index is this one; `null` never fails.
    fail_write_index: ?usize = null,
    /// On the failing write, first land `torn_prefix` bytes on media.
    torn_prefix: usize = 0,
    writes: usize = 0,

    fn cast(ctx: *anyopaque) *FaultStorage {
        return @ptrCast(@alignCast(ctx));
    }
    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        return cast(ctx).inner.open(path, mode);
    }
    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }
    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        return cast(ctx).inner.pread(h, buf, off);
    }
    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        const idx = self.writes;
        self.writes += 1;
        if (self.fail_write_index) |fi| {
            if (idx == fi) {
                if (self.torn_prefix > 0) try self.inner.writeAll(h, bytes[0..self.torn_prefix], off);
                return error.NoSpaceLeft;
            }
        }
        return self.inner.writeAll(h, bytes, off);
    }
    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        return cast(ctx).inner.sync(h);
    }
    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        return cast(ctx).inner.truncate(h, len);
    }
    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        cast(ctx).inner.close(h);
    }
    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        return cast(ctx).inner.rename(old_path, new_path);
    }
    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn vTryLock(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
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
        .tryLockExclusive = vTryLock,
    };
    fn storage(self: *FaultStorage) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

test "a write that FAILS never leaves the cache holding bytes media does not have" {
    // The write-through ordering guard (`inner.writeAll` before any cache
    // mutation) is the module's central claim, and inverting it left the suite
    // green: nothing ever made an inner write fail. With a backend that can,
    // the inverted order serves bytes that never reached media.
    const gpa = testing.allocator;
    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    const page2 = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page2);
    @memset(page, 0x11);
    @memset(page2, 0x22);

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var fault = FaultStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, fault.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const h = try st.open("f", .create_truncate);
    try st.writeAll(h, page, 0); // write 0: lands
    fault.fail_write_index = fault.writes; // the NEXT write fails outright
    try testing.expectError(error.NoSpaceLeft, st.writeAll(h, page2, 0));

    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    try testing.expectEqualSlices(u8, page, &buf); // media truth, not 0x22

    // And the same for a TORN write, where part of the bytes did land: the
    // resident copy would then be OLDER than media, so the cache would hide
    // the damage from every reader in the process while a raw reader saw it.
    fault.fail_write_index = fault.writes;
    fault.torn_prefix = 128;
    try testing.expectError(error.NoSpaceLeft, st.writeAll(h, page2, 0));

    _ = try st.pread(h, &buf, 0);
    var raw: [default_page_size]u8 = undefined;
    _ = try sim.storage().pread(h, &raw, 0);
    try testing.expectEqualSlices(u8, &raw, &buf); // cached == media, torn or not
    try testing.expectEqual(@as(u8, 0x22), buf[0]); // and it really is torn
    try testing.expectEqual(@as(u8, 0x11), buf[default_page_size - 1]);
}

/// An inner `Storage` whose `pread` first runs `hook` once -- what another
/// fiber on the same thread does while the reading fiber is parked on its
/// disk read (qap's `Serial` owner ring suspends exactly there). The hook
/// re-enters the SAME `PageCache`, so the test sees every cache state that a
/// read in flight leaves visible.
const YieldStorage = struct {
    inner: Storage,
    hook: ?*const fn (ctx: *anyopaque) anyerror!void = null,
    hook_ctx: *anyopaque = undefined,
    hook_err: ?anyerror = null,
    /// false: the hook runs once, on the next `pread`. true: on EVERY
    /// `pread`, `writeAll` and `sync` -- each a point where a fiber parks --
    /// except the ones the hook itself makes.
    every: bool = false,
    in_hook: bool = false,
    fired: usize = 0,

    fn cast(ctx: *anyopaque) *YieldStorage {
        return @ptrCast(@alignCast(ctx));
    }
    fn park(self: *YieldStorage) void {
        const hk = self.hook orelse return;
        if (self.in_hook) return;
        if (!self.every) self.hook = null;
        self.in_hook = true;
        defer self.in_hook = false;
        self.fired += 1;
        hk(self.hook_ctx) catch |e| {
            if (self.hook_err == null) self.hook_err = e;
        };
    }
    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        self.park();
        return self.inner.pread(h, buf, off);
    }
    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        return cast(ctx).inner.open(path, mode);
    }
    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }
    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.every) self.park();
        return self.inner.writeAll(h, bytes, off);
    }
    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self = cast(ctx);
        if (self.every) self.park();
        return self.inner.sync(h);
    }
    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        return cast(ctx).inner.truncate(h, len);
    }
    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        cast(ctx).inner.close(h);
    }
    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        return cast(ctx).inner.rename(old_path, new_path);
    }
    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn vTryLock(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
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
        .tryLockExclusive = vTryLock,
    };
    fn storage(self: *YieldStorage) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

test "fiber-reentrant: a read of a page whose fill is in flight gets the page, never the unfilled slot" {
    // qap research register H4 (2026-09-29): `preadRef`'s miss reserves the
    // cache slot and then reads into it. A reader that suspends in that read
    // (a fiber) lets a second one in; before ramcache hid unfilled entries,
    // the second one got a HIT on the uninitialized slot -- and a kvtree
    // commit reading its base tree that way writes a corrupt tree.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var ys = YieldStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, ys.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    @memset(page, 0x5C);
    const h = try st.open("f", .create_truncate);
    // Written straight to media, so the first read of it is a miss.
    try sim.storage().writeAll(h, page, 0);

    const Second = struct {
        pc: *PageCache,
        h: Storage.Handle,
        want: []const u8,
        fn run(ctx: *anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            // The zero-copy path, then the copying one, for the same page.
            const got = (try self.pc.preadRef(self.h, default_page_size, 0)) orelse return error.NotLent;
            defer self.pc.releasePage(got);
            if (!std.mem.eql(u8, got.bytes, self.want)) return error.ServedTheUnfilledSlot;
            var buf: [default_page_size]u8 = undefined;
            _ = try self.pc.storage().pread(self.h, &buf, 0);
            if (!std.mem.eql(u8, &buf, self.want)) return error.ServedTheUnfilledSlot;
        }
    };
    var second: Second = .{ .pc = &pc, .h = h, .want = page };

    // First reader: the borrow path, parked mid-fill.
    ys.hook = Second.run;
    ys.hook_ctx = &second;
    const first = (try pc.preadRef(h, default_page_size, 0)) orelse return error.NotLent;
    try testing.expect(ys.hook_err == null);
    try testing.expectEqualSlices(u8, page, first.bytes);
    pc.releasePage(first);

    // First reader on the copying path, same shape, a fresh cache state.
    pc.cache.clear();
    ys.hook = Second.run;
    ys.hook_ctx = &second;
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    try testing.expect(ys.hook_err == null);
    try testing.expectEqualSlices(u8, page, &buf);

    // What is left resident is the page, and nothing is still borrowed.
    const after = (try pc.preadRef(h, default_page_size, 0)).?;
    try testing.expectEqualSlices(u8, page, after.bytes);
    pc.releasePage(after);
    try testing.expectEqual(@as(usize, 0), pc.cache.stats.pinned);
    st.close(h);
}

test "fiber-reentrant: kvtree reads the committed version at every point a commit parks" {
    // The contract qap's `Serial` relies on to serve reads while a commit's
    // fsync is in flight (research register H4): with the Db's commit parked
    // in ANY of its storage calls -- a base-page read, a page write, either
    // fsync -- a second fiber on the same thread may read, and reads the last
    // committed version. Cold cache, so both sides fill pages as they go.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var ys = YieldStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, ys.storage(), .{ .max_pages = 16 });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    const n = 300;
    var kbuf: [32]u8 = undefined;
    var vbuf: [48]u8 = undefined;
    {
        var txn = try db.begin();
        for (0..n) |i| {
            const key = try std.mem.print(&kbuf, "key{d:0>5}", .{i});
            try txn.put(key, try std.mem.print(&vbuf, "old-{d}", .{i}));
        }
        try txn.commit();
    }

    const Reader = struct {
        db: *kvtree.Db,
        /// The committed version of the even keys; odd keys stay "old".
        even: []const u8,
        next: usize = 0,
        fn run(ctx: *anyopaque) anyerror!void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            // A few keys per park, walking the whole key space over the commit.
            for (0..3) |_| {
                const i = r.next % n;
                r.next += 37;
                var kb: [32]u8 = undefined;
                var wb: [48]u8 = undefined;
                const key = try std.mem.print(&kb, "key{d:0>5}", .{i});
                const ver = if (i % 2 == 0) r.even else "old";
                const want = try std.mem.print(&wb, "{s}-{d}", .{ ver, i });
                var got = (try r.db.getRef(key)) orelse return error.KeyMissing;
                defer got.release();
                if (!std.mem.eql(u8, got.bytes, want)) return error.SawAnUncommittedOrCorruptValue;
            }
        }
    };
    var reader: Reader = .{ .db = &db, .even = "old" };

    for (0..2) |round| {
        pc.cache.clear(); // cold: the commit and the reader both miss
        var txn = try db.begin();
        const ver = if (round == 0) "new" else "newer";
        for (0..n) |i| {
            if (i % 2 == 1) continue; // half the keys, so base pages are shared
            const key = try std.mem.print(&kbuf, "key{d:0>5}", .{i});
            try txn.put(key, try std.mem.print(&vbuf, "{s}-{d}", .{ ver, i }));
        }
        ys.hook = Reader.run;
        ys.hook_ctx = &reader;
        ys.every = true;
        ys.fired = 0;
        // What is committed while this commit runs: the previous round's.
        reader.even = if (round == 0) "old" else "new";
        try txn.commit();
        ys.hook = null;
        try testing.expect(ys.hook_err == null);
        try testing.expect(ys.fired >= 4); // base reads, writes, both fsyncs

        // And after it, the new version.
        for (0..n) |i| {
            const key = try std.mem.print(&kbuf, "key{d:0>5}", .{i});
            var got = (try db.getRef(key)).?;
            defer got.release();
            const want = if (i % 2 == 1) try std.mem.print(&vbuf, "old-{d}", .{i}) else try std.mem.print(&vbuf, "{s}-{d}", .{ ver, i });
            try testing.expectEqualSlices(u8, want, got.bytes);
        }
    }

    // The other direction, the one that corrupted: the READER parks mid-fill
    // (its first read is the root page) and a whole commit runs meanwhile,
    // reading that same root as its base. Before ramcache hid unfilled
    // entries the commit's base read was a HIT on the unfilled slot.
    const Committer = struct {
        db: *kvtree.Db,
        fn run(ctx: *anyopaque) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            var txn = try c.db.begin();
            var kb: [32]u8 = undefined;
            for (0..n) |i| {
                if (i % 3 != 0) continue;
                try txn.put(try std.mem.print(&kb, "key{d:0>5}", .{i}), "third");
            }
            try txn.commit();
        }
    };
    var committer: Committer = .{ .db = &db };
    pc.cache.clear();
    ys.every = false;
    ys.hook = Committer.run;
    ys.hook_ctx = &committer;
    {
        // key00001: odd, not a multiple of 3 -- "old" before and after.
        var got = (try db.getRef("key00001")).?;
        defer got.release();
        try testing.expectEqualStrings("old-1", got.bytes);
    }
    try testing.expect(ys.hook_err == null);
    for (0..n) |i| {
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{i});
        var got = (try db.getRef(key)).?;
        defer got.release();
        const want = if (i % 3 == 0) "third" else if (i % 2 == 1) try std.mem.print(&vbuf, "old-{d}", .{i}) else try std.mem.print(&vbuf, "newer-{d}", .{i});
        try testing.expectEqualSlices(u8, want, got.bytes);
    }
    try testing.expectEqual(@as(usize, 0), pc.cache.stats.pinned);
}

test "a page that is not fully present is never cached, however many times it is read" {
    // `vPread`'s `n == page_size` gate: mutating it to `if (true)` left the
    // suite green in both modes. What it actually prevents is a short read
    // being stored as a whole page -- the next reader then gets `page_size`
    // back with the PREVIOUS CALLER'S BUFFER as the tail, which in kvtree's
    // `lookup` is `var page: [page_size]u8 = undefined`, i.e. uninitialised
    // stack presented as a valid tree page. Reachable after a crash leaves a
    // torn last page.
    const gpa = testing.allocator;
    const full = try gpa.alloc(u8, default_page_size);
    defer gpa.free(full);
    @memset(full, 0x01);

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const h = try st.open("short", .create_truncate);
    try st.writeAll(h, full, 0); // page 0: whole
    try st.writeAll(h, full[0..100], default_page_size); // page 1: 100 bytes only

    var buf1: [default_page_size]u8 = undefined;
    @memset(&buf1, 0xDD);
    const n1 = try st.pread(h, &buf1, default_page_size);
    try testing.expectEqual(@as(usize, 100), n1);

    var buf2: [default_page_size]u8 = undefined;
    @memset(&buf2, 0xDD);
    const n2 = try st.pread(h, &buf2, default_page_size);
    // The second read must report the same truth as the first. Cached, it
    // reports a full page and hands back `0xDD` from byte 100 on.
    try testing.expectEqual(@as(usize, 100), n2);
    try testing.expectEqual(@as(u8, 0xDD), buf2[100]);
}

test "closing a handle forgets ALL of its resident pages, so a recycled handle cannot serve another file's bytes" {
    // `vClose` invalidated only the pages a best-effort side table had
    // recorded. An untracked page outlived the close, and the backend recycles
    // handle numbers, so a `pread` of an unrelated (even empty) file returned
    // another file's content as a HIT -- cross-file disclosure, not staleness.
    // The sweep is over the resident set by key prefix now, so there is no
    // side table to fail: every resident page of the handle goes.
    const gpa = testing.allocator;
    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    @memset(page, 0xAB);

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    const ha = try st.open("secret", .create_truncate);
    try st.writeAll(ha, page, 0);
    try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages);
    st.close(ha);
    try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);

    // A different, EMPTY file. If it lands on the recycled handle number, a
    // surviving page would be served for it.
    const hb = try st.open("public", .create_truncate);
    var buf: [default_page_size]u8 = undefined;
    @memset(&buf, 0);
    const n = try st.pread(hb, &buf, 0);
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expectEqual(@as(u8, 0), buf[0]);
}

test "F5: vClose forgets only the closing handle's pages, not every open file's (per-handle invalidation via ramcache.remove)" {
    // The defect: `vClose` called `self.cache.clear()` — a whole-cache wipe —
    // so closing ONE of several files sharing this PageCache discarded every
    // OTHER open file's resident pages too. Two files, two handles, one
    // shared cache: closing "alpha" must leave "beta"'s page hot.
    const gpa = testing.allocator;
    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    @memset(page, 0xCD);

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();

    // Open both handles FIRST: a `.create_truncate` open clears the whole
    // cache (unrelated to F5 — see `vOpen`), so both opens must happen
    // before either write or the second open would wipe the first's page.
    const ha = try st.open("alpha", .create_truncate);
    const hb = try st.open("beta", .create_truncate);
    try st.writeAll(ha, page, 0); // caches alpha's page 0 (write-through also caches)
    try st.writeAll(hb, page, 0); // caches beta's page 0

    try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages);

    st.close(ha); // must forget ONLY alpha's page

    // alpha's page is gone (the handle is closed and its number may be
    // recycled, so this is the correct half).
    try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages);

    // beta's page must still be resident: reading it must be a HIT, not a
    // fresh miss. Before the fix, `vClose` cleared beta's page too, so this
    // read would fall through to the inner Storage and bump `pc.misses`.
    const misses_before = pc.misses;
    const hits_before = pc.hits;
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(hb, &buf, 0);
    try testing.expectEqual(misses_before, pc.misses); // no new miss
    try testing.expectEqual(hits_before + 1, pc.hits); // served from RAM
    try testing.expectEqualSlices(u8, page, &buf);
}

test "W3: kvtree getRef lends the value in place -- same bytes as get, held stable across an overwrite" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 64 });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    // Enough keys for a tree with branches, so the descent is not one leaf.
    var kbuf: [32]u8 = undefined;
    var vbuf: [48]u8 = undefined;
    var id: u64 = 0;
    while (id < 400) : (id += 1) {
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
        const val = try std.mem.print(&vbuf, "value-{d}-{d}", .{ id, id * 7 });
        try db.put(key, val);
    }

    const hits_before = pc.stats().ref_hits;
    id = 0;
    while (id < 400) : (id += 13) {
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
        const copied = (try db.get(gpa, key)).?;
        defer gpa.free(copied);
        var lent = (try db.getRef(key)).?;
        defer lent.release();
        try testing.expectEqualSlices(u8, copied, lent.bytes);
    }
    try testing.expect(pc.stats().ref_hits > hits_before);
    try testing.expectEqual(@as(?kvtree.ValueRef, null), try db.getRef("no-such-key"));

    // Held across a commit that rewrites the key: the borrower keeps the
    // bytes it was lent; a fresh read sees the new value.
    var held = (try db.getRef("key00013")).?;
    try testing.expectEqualStrings("value-13-91", held.bytes);
    try db.put("key00013", "rewritten");
    try testing.expectEqualStrings("value-13-91", held.bytes);
    held.release();
    var fresh = (try db.getRef("key00013")).?;
    try testing.expectEqualStrings("rewritten", fresh.bytes);
    fresh.release();

    // Every borrow was handed back.
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);
}

test "W3: kvtree Txn.getRef -- buffered changes shadow the tree, tree values are lent in place" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 64 });
    defer pc.deinit();
    var db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer db.close();

    var kbuf: [32]u8 = undefined;
    var vbuf: [48]u8 = undefined;
    var id: u64 = 0;
    while (id < 400) : (id += 1) {
        const key = try std.mem.print(&kbuf, "key{d:0>5}", .{id});
        const val = try std.mem.print(&vbuf, "value-{d}-{d}", .{ id, id * 7 });
        try db.put(key, val);
    }

    var txn = try db.begin();
    try txn.put("key00013", "first");
    try txn.put("key00013", "second"); // the latest buffered change wins
    try txn.del("key00026");
    try txn.put("new-key", "fresh");

    // Each answer equals the copying `Txn.get`, whichever layer it came from.
    const probes = [_][]const u8{ "key00013", "key00026", "new-key", "key00039", "no-such-key" };
    const refs_before = pc.stats().ref_hits;
    for (probes) |key| {
        const copied = try txn.get(gpa, key);
        defer if (copied) |c| gpa.free(c);
        var lent = try txn.getRef(key);
        defer if (lent) |*l| l.release();
        if (copied) |c| try testing.expectEqualSlices(u8, c, lent.?.bytes) else try testing.expectEqual(@as(?kvtree.ValueRef, null), lent);
    }
    var latest = (try txn.getRef("key00013")).?;
    try testing.expectEqualStrings("second", latest.bytes);
    latest.release();
    // A key the batch did not touch came from the store's lent page.
    try testing.expect(pc.stats().ref_hits > refs_before);

    try txn.commit();
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);
}

// ── narrowed truncate + read-ahead tests ─────────────────────────────────────

/// Forwarding `Storage` that counts inner `pread`s, can fail the next one, and
/// can run a hook right after an inner `pread` has read its bytes (the moment a
/// second fiber could run while the first is parked on I/O).
const CountingStorage = struct {
    inner: Storage,
    preads: usize = 0,
    fail_next_pread: bool = false,
    /// The next `pread` returns at most this many bytes (a file that shrank
    /// between `size` and `pread`).
    short_next_pread: ?usize = null,
    hook: ?*const fn (*CountingStorage) void = null,
    hook_pc: ?*PageCache = null,
    /// Run once inside `truncate`, before the inner truncate.
    truncate_hook: ?*const fn (*CountingStorage) void = null,
    syncs: usize = 0,
    sync_datas: usize = 0,
    shared_locks: usize = 0,
    allocates: usize = 0,

    fn cast(ctx: *anyopaque) *CountingStorage {
        return @ptrCast(@alignCast(ctx));
    }
    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        return cast(ctx).inner.open(path, mode);
    }
    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }
    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        self.preads += 1;
        if (self.fail_next_pread) {
            self.fail_next_pread = false;
            return error.NoSpaceLeft;
        }
        const lim = if (self.short_next_pread) |m| @min(m, buf.len) else buf.len;
        self.short_next_pread = null;
        const n = try self.inner.pread(h, buf[0..lim], off);
        if (self.hook) |f| {
            self.hook = null; // once
            f(self);
        }
        return n;
    }
    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        return cast(ctx).inner.writeAll(h, bytes, off);
    }
    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        cast(ctx).syncs += 1;
        return cast(ctx).inner.sync(h);
    }
    fn vSyncData(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        cast(ctx).sync_datas += 1;
        return cast(ctx).inner.syncData(h);
    }
    fn vTryLockShared(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        cast(ctx).shared_locks += 1;
        return cast(ctx).inner.tryLockShared(h);
    }
    fn vAllocate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!bool {
        cast(ctx).allocates += 1;
        return cast(ctx).inner.allocate(h, len);
    }
    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.truncate_hook) |f| {
            self.truncate_hook = null; // once
            f(self);
        }
        return self.inner.truncate(h, len);
    }
    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        cast(ctx).inner.close(h);
    }
    fn vRename(ctx: *anyopaque, a: []const u8, b: []const u8) Storage.Error!void {
        return cast(ctx).inner.rename(a, b);
    }
    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn vTryLock(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
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
        .tryLockExclusive = vTryLock,
        .syncData = vSyncData,
        .tryLockShared = vTryLockShared,
        .allocate = vAllocate,
    };
    fn storage(self: *CountingStorage) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

/// Write `n` pages to `h`, page `i` filled with `base + i`.
fn fillFile(gpa: std.mem.Allocator, st: Storage, h: Storage.Handle, n: usize, base: u8) !void {
    const page = try gpa.alloc(u8, default_page_size);
    defer gpa.free(page);
    for (0..n) |i| {
        @memset(page, base +% @as(u8, @truncate(i)));
        try st.writeAll(h, page, i * default_page_size);
    }
}

test "narrowed truncate: another handle's pages survive; truncated handle's stale pages are gone after regrow" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16 });
    defer pc.deinit();
    const st = pc.storage();

    const a = try st.open("a", .create_truncate);
    const b = try st.open("b", .create_truncate);
    try fillFile(gpa, st, a, 4, 0x10);
    try fillFile(gpa, st, b, 3, 0x50);
    try testing.expectEqual(@as(usize, 7), pc.stats().resident_pages);

    // Truncate `a` to 1.5 pages: page 0 stays, page 1 is partial (must go),
    // pages 2..3 go. `b` is untouched.
    try st.truncate(a, default_page_size + default_page_size / 2);
    try testing.expectEqual(@as(usize, 1 + 3), pc.stats().resident_pages);

    // b's pages are still hits: no inner read.
    var buf: [default_page_size]u8 = undefined;
    const preads = cs.preads;
    for (0..3) |i| {
        _ = try st.pread(b, &buf, i * default_page_size);
        try testing.expectEqual(@as(u8, 0x50 + @as(u8, @truncate(i))), buf[0]);
    }
    _ = try st.pread(a, &buf, 0); // a's page 0 kept: hit
    try testing.expectEqual(preads, cs.preads);
    try testing.expectEqual(@as(u8, 0x10), buf[0]);

    // Regrow `a` and write NEW bytes over the old range: never the old ones.
    // (SimStorage cannot extend by truncate; regrow by writing.)
    try fillFile(gpa, st, a, 4, 0xA0);
    for (0..4) |i| {
        _ = try st.pread(a, &buf, i * default_page_size);
        try testing.expectEqual(@as(u8, 0xA0 + @as(u8, @truncate(i))), buf[0]);
    }
    // Cut again, regrow with only page 0 rewritten: page 1 must not come back
    // from the cache with its 0xA1 bytes -- the file ends after page 0.
    try st.truncate(a, default_page_size);
    try testing.expectEqual(@as(usize, 0), try st.pread(a, &buf, default_page_size));
    _ = try st.pread(a, &buf, 0); // page 0 (below the cut) keeps its bytes
    try testing.expectEqual(@as(u8, 0xA0), buf[0]);
}

test "narrowed truncate: a huge span falls back to the handle sweep and still leaves other handles alone" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 2 });
    defer pc.deinit();
    const st = pc.storage();
    const a = try st.open("a", .create_truncate);
    const b = try st.open("b", .create_truncate);
    try fillFile(gpa, st, a, 20, 1); // span 20 > 4 * max_pages: sweep path
    try fillFile(gpa, st, b, 1, 0x70);
    try st.truncate(a, 0);
    var buf: [default_page_size]u8 = undefined;
    const hits = pc.hits;
    _ = try st.pread(b, &buf, 0);
    try testing.expectEqual(hits + 1, pc.hits);
    try testing.expectEqual(@as(usize, 0), try st.pread(a, &buf, 0));
}

test "narrowed truncate: a borrow outstanding across it stays valid, other handle unaffected" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try seedPages(gpa, &pc, st, 3);
    const other = try st.open("other", .create_truncate);
    try fillFile(gpa, st, other, 1, 0x33);

    const borrowed = (try pc.preadRef(h, default_page_size, default_page_size)).?;
    try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages); // h:1 + other:0

    try st.truncate(h, default_page_size); // page 1 is now past the end
    try testing.expectEqual(@as(usize, 1), pc.stats().resident_pages); // only `other`
    for (borrowed.bytes) |x| try testing.expectEqual(@as(u8, 2), x); // snapshot intact
    var buf: [default_page_size]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try st.pread(h, &buf, default_page_size)); // no stale hit
    const hits = pc.hits;
    _ = try st.pread(other, &buf, 0);
    try testing.expectEqual(hits + 1, pc.hits);
    pc.releasePage(borrowed);
    try testing.expectEqual(@as(usize, 0), pc.stats().borrowed_pages);
}

test "narrowed sub-page write: only the written handle's pages are dropped" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const a = try st.open("a", .create_truncate);
    const b = try st.open("b", .create_truncate);
    try fillFile(gpa, st, a, 2, 1);
    try fillFile(gpa, st, b, 2, 9);
    try st.writeAll(a, "Z", 7);
    try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages); // b's two
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(a, &buf, 0);
    try testing.expectEqual(@as(u8, 'Z'), buf[7]);
}

/// Sequential scan of `n` pages through `st`, returning the concatenation.
fn scanAll(gpa: std.mem.Allocator, st: Storage, h: Storage.Handle, n: usize) ![]u8 {
    const out = try gpa.alloc(u8, n * default_page_size);
    errdefer gpa.free(out);
    for (0..n) |i| {
        const got = try st.pread(h, out[i * default_page_size ..][0..default_page_size], i * default_page_size);
        try testing.expectEqual(@as(usize, default_page_size), got);
    }
    return out;
}

test "read-ahead: a sequential scan makes fewer inner reads and returns identical bytes; off = today's behaviour" {
    const gpa = testing.allocator;
    const n = 40;
    var expect: ?[]u8 = null;
    defer if (expect) |e| gpa.free(e);
    var reads: [2]usize = undefined;
    for ([_]u32{ 0, 7 }, 0..) |k, which| {
        var sim = kv.SimStorage.init(gpa);
        defer sim.deinit();
        var cs = CountingStorage{ .inner = sim.storage() };
        var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = k });
        defer pc.deinit();
        const st = pc.storage();
        const h = try st.open("f", .create_truncate);
        try fillFile(gpa, st, h, n, 3);
        pc.cache.clear();
        cs.preads = 0;
        const got = try scanAll(gpa, st, h, n);
        defer gpa.free(got);
        reads[which] = cs.preads;
        if (k == 0) {
            expect = try gpa.dupe(u8, got);
            try testing.expectEqual(@as(usize, n), cs.preads);
            try testing.expectEqual(@as(u64, 0), pc.stats().readahead_pages);
        } else {
            try testing.expectEqualSlices(u8, expect.?, got);
            try testing.expect(pc.stats().readahead_pages > 0);
            try testing.expect(pc.stats().resident_pages <= 16);
        }
    }
    try testing.expect(reads[1] < reads[0] / 2);
}

test "read-ahead: random (non-sequential) access triggers none" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 4 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 30, 0);
    pc.cache.clear();
    cs.preads = 0;
    var buf: [default_page_size]u8 = undefined;
    for ([_]usize{ 5, 20, 2, 11, 27, 8, 14 }) |i| _ = try st.pread(h, &buf, i * default_page_size);
    try testing.expectEqual(@as(usize, 7), cs.preads);
    try testing.expectEqual(@as(u64, 0), pc.stats().readahead_pages);
}

test "read-ahead: never past end of file, partial tail page never cached" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 4, 1);
    try st.writeAll(h, "tail", 4 * default_page_size); // 4 whole pages + a 4-byte tail
    pc.cache.clear();
    cs.preads = 0;
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    _ = try st.pread(h, &buf, default_page_size); // sequential: pages 1..3 in one read
    try testing.expectEqual(@as(usize, 2), cs.preads);
    try testing.expectEqual(@as(usize, 4), pc.stats().resident_pages); // 0..3, not the tail
    for (2..4) |i| {
        _ = try st.pread(h, &buf, i * default_page_size);
        try testing.expectEqual(@as(u8, 1 + @as(u8, @truncate(i))), buf[0]);
    }
    try testing.expectEqual(@as(usize, 2), cs.preads);
    // The tail is not a full page: a short read, returned, never cached.
    try testing.expectEqual(@as(usize, 4), try st.pread(h, &buf, 4 * default_page_size));
    try testing.expectEqual(@as(usize, 4), pc.stats().resident_pages);
}

test "read-ahead: a failed inner read caches nothing false and the ordinary path answers" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 4 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 8, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    cs.fail_next_pread = true; // the read-ahead attempt fails ...
    _ = try st.pread(h, &buf, default_page_size); // ... the fallback single read succeeds
    try testing.expectEqual(@as(u8, 2), buf[0]);
    try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages); // pages 0 and 1 only
    try testing.expectEqual(@as(u64, 0), pc.stats().readahead_pages);
    // Without read-ahead the failure surfaces and nothing is cached.
    var failing = CountingStorage{ .inner = sim.storage() };
    var pc2 = PageCache.init(gpa, failing.storage(), .{ .max_pages = 4 });
    defer pc2.deinit();
    failing.fail_next_pread = true;
    try testing.expectError(error.NoSpaceLeft, pc2.storage().pread(h, &buf, 0));
    try testing.expectEqual(@as(usize, 0), pc2.stats().resident_pages);
}

fn writeDuringReadAhead(cs: *CountingStorage) void {
    // A "second fiber" writes page 3 while the first is parked in its inner
    // pread (whose bytes for page 3 are already the OLD ones).
    var fresh: [default_page_size]u8 = undefined;
    @memset(&fresh, 0xEE);
    cs.hook_pc.?.storage().writeAll(0, &fresh, 3 * default_page_size) catch unreachable;
}

test "read-ahead: a write landing during the inner read is never overwritten by older prefetched bytes" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 5 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try testing.expectEqual(@as(Storage.Handle, 0), h);
    try fillFile(gpa, st, h, 8, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    cs.hook = writeDuringReadAhead;
    cs.hook_pc = &pc;
    _ = try st.pread(h, &buf, default_page_size); // read-ahead 1..6, hook writes page 3
    _ = try st.pread(h, &buf, 3 * default_page_size);
    for (buf) |x| try testing.expectEqual(@as(u8, 0xEE), x);
}

fn writeRequestedPageDuringReadAhead(cs: *CountingStorage) void {
    // The "second fiber" rewrites page 1, the very page the parked read-ahead
    // was asked for.
    var fresh: [default_page_size]u8 = undefined;
    @memset(&fresh, 0xEE);
    cs.hook_pc.?.storage().writeAll(0, &fresh, 1 * default_page_size) catch unreachable;
}

test "read-ahead: a write to the REQUESTED page during the inner read is not overwritten by the older bytes" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 5 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try testing.expectEqual(@as(Storage.Handle, 0), h);
    try fillFile(gpa, st, h, 8, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    cs.hook = writeRequestedPageDuringReadAhead;
    cs.hook_pc = &pc;
    _ = try st.pread(h, &buf, default_page_size); // read-ahead of 1..6 parks; the hook rewrites page 1
    for (buf) |x| try testing.expectEqual(@as(u8, 2), x); // what media held when it read
    _ = try st.pread(h, &buf, default_page_size);
    for (buf) |x| try testing.expectEqual(@as(u8, 0xEE), x); // never the older bytes from the cache
}

test "a write landing during a plain miss's inner read is not overwritten by the older bytes" {
    // The same race without read-ahead: page 3 missed, its inner pread got
    // the old bytes, and a second fiber wrote page 3 before the read resumed.
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try testing.expectEqual(@as(Storage.Handle, 0), h);
    try fillFile(gpa, st, h, 8, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    cs.hook = writeDuringReadAhead;
    cs.hook_pc = &pc;
    _ = try st.pread(h, &buf, 3 * default_page_size); // parked read of page 3
    for (buf) |x| try testing.expectEqual(@as(u8, 4), x); // what media held when it read
    const reads = cs.preads;
    _ = try st.pread(h, &buf, 3 * default_page_size);
    for (buf) |x| try testing.expectEqual(@as(u8, 0xEE), x);
    try testing.expectEqual(reads, cs.preads); // and served from the cache, not re-read
}

// ── review + mutation additions (2026-10-23) ────────────────────────────────

fn truncatingOpenDuringRead(cs: *CountingStorage) void {
    // A "second fiber" truncates the file by reopening it while the first is
    // parked in its inner pread (which already holds the old bytes).
    const st = cs.hook_pc.?.storage();
    const h2 = st.open("f", .create_truncate) catch unreachable;
    st.close(h2);
}

test "a truncating open landing during a parked read is never overtaken by the older bytes" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 2, 1);
    pc.cache.clear();
    cs.hook = truncatingOpenDuringRead;
    cs.hook_pc = &pc;
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0); // parked; the file is emptied meanwhile
    try testing.expectEqual(@as(usize, 0), try st.pread(h, &buf, 0)); // EOF, not a stale hit
}

fn closeDuringRead(cs: *CountingStorage) void {
    cs.hook_pc.?.storage().close(0);
}

test "a read whose handle is closed while it is parked leaves no orphan page behind" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try testing.expectEqual(@as(Storage.Handle, 0), h);
    try fillFile(gpa, st, h, 1, 1);
    pc.cache.clear();
    cs.hook = closeDuringRead;
    cs.hook_pc = &pc;
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    // The file is gone from the table: a page put under its id now would sit
    // in the budget, unreachable, until evicted.
    try testing.expectEqual(@as(usize, 0), pc.stats().resident_pages);
}

test "truncate forgets the handle's read sequence: the next read does not read ahead" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 4 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 8, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    try st.truncate(h, 8 * default_page_size); // same length: only the sequence is reset
    _ = try st.pread(h, &buf, default_page_size);
    try testing.expectEqual(@as(u64, 0), pc.stats().readahead_pages);
}

test "read-ahead: a read shorter than one page (the file shrank meanwhile) falls back, a short tail caches nothing extra" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16, .read_ahead_pages = 4 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 8, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    cs.short_next_pread = 10; // the read-ahead's pread returns 10 bytes
    try testing.expectEqual(@as(usize, default_page_size), try st.pread(h, &buf, default_page_size));
    for (buf) |x| try testing.expectEqual(@as(u8, 2), x); // the fallback's bytes, whole
    try testing.expectEqual(@as(u64, 0), pc.stats().readahead_pages);

    // A read-ahead whose pread returns exactly one page caches no extra page.
    pc.cache.clear();
    _ = try st.pread(h, &buf, 3 * default_page_size);
    cs.short_next_pread = default_page_size;
    _ = try st.pread(h, &buf, 4 * default_page_size);
    try testing.expectEqual(@as(u64, 0), pc.stats().readahead_pages);
    try testing.expectEqual(@as(usize, 2), pc.stats().resident_pages); // pages 3 and 4
}

test "read-ahead: never more extra pages per read than the budget leaves" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 2, .read_ahead_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 12, 1);
    pc.cache.clear();
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    _ = try st.pread(h, &buf, default_page_size);
    try testing.expectEqual(@as(u64, 1), pc.stats().readahead_pages); // max_pages - 1
}

test "a failed sub-page write drops the file's pages: a torn page is never masked" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var fault = FaultStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, fault.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 2, 0x11);
    fault.fail_write_index = fault.writes;
    fault.torn_prefix = 3;
    try testing.expectError(error.NoSpaceLeft, st.writeAll(h, "ZZZZZ", 100));
    var buf: [default_page_size]u8 = undefined;
    _ = try st.pread(h, &buf, 0);
    try testing.expectEqualStrings("ZZZ", buf[100..103]); // media, torn
    try testing.expectEqual(@as(u8, 0x11), buf[103]);
}

test "a handle number the backend recycles without a close releases the stale file" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const a = try st.open("a", .create_truncate);
    sim.storage().close(a); // behind the cache's back
    const b = try st.open("b", .create_truncate);
    try testing.expectEqual(a, b); // the backend recycled the number
    try testing.expectEqual(@as(usize, 1), pc.files.items.len); // "a" released, not leaked
    st.close(b);
}

test "a fresh file id never reuses a live one (after the counter wraps)" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const a = try st.open("a", .create_truncate);
    try fillFile(gpa, st, a, 1, 0xAA);
    pc.next_id = pc.handle_file.get(a).?; // as if 2^32 opens later
    const b = try st.open("b", .create_truncate);
    try testing.expect(pc.handle_file.get(a).? != pc.handle_file.get(b).?);
    var buf: [default_page_size]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try st.pread(b, &buf, 0)); // not a's page
}

test "syncData, tryLockShared and allocate reach the inner Storage as themselves" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try st.syncData(h);
    try testing.expectEqual(@as(usize, 1), cs.sync_datas);
    try testing.expectEqual(@as(usize, 0), cs.syncs);
    _ = try st.tryLockShared(h);
    try testing.expectEqual(@as(usize, 1), cs.shared_locks);
    _ = try st.allocate(h, 4 * default_page_size);
    try testing.expectEqual(@as(usize, 1), cs.allocates);
}

test "a truncating open that fails after the backend emptied the file leaves no stale page under the other handles" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var pc = PageCache.init(failing.allocator(), sim.storage(), .{ .max_pages = 8 });
    defer pc.deinit();
    const st = pc.storage();
    const a = try st.open("f", .create_truncate);
    try fillFile(gpa, st, a, 1, 0x5A);
    // Fill the handle table to its capacity, so the next open must grow it.
    var extra: [64]Storage.Handle = undefined;
    var n: usize = 0;
    while (pc.handle_file.available != 0) : (n += 1) extra[n] = try st.open("other", .create_truncate);
    failing.fail_index = failing.alloc_index; // the growth fails
    try testing.expectError(error.OutOfMemory, st.open("f", .create_truncate));
    var buf: [default_page_size]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try st.pread(a, &buf, 0)); // emptied on media: EOF
    for (extra[0..n]) |x| st.close(x);
}

fn writePastEndDuringTruncate(cs: *CountingStorage) void {
    var page: [default_page_size]u8 = undefined;
    @memset(&page, 0xCD);
    cs.hook_pc.?.storage().writeAll(0, &page, 5 * default_page_size) catch unreachable;
}

test "a write that lands during a parked truncate past the old end is not left cached" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var cs = CountingStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, cs.storage(), .{ .max_pages = 16 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try testing.expectEqual(@as(Storage.Handle, 0), h);
    try fillFile(gpa, st, h, 2, 1); // old size: 2 pages
    cs.truncate_hook = writePastEndDuringTruncate; // page 5, then the cut to 0
    cs.hook_pc = &pc;
    try st.truncate(h, 0);
    var buf: [default_page_size]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try st.pread(h, &buf, 5 * default_page_size));
}

test "read-ahead: budget of one page still holds and reads stay correct" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 1, .read_ahead_pages = 6 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try st.open("f", .create_truncate);
    try fillFile(gpa, st, h, 10, 1);
    const got = try scanAll(gpa, st, h, 10);
    defer gpa.free(got);
    for (0..10) |i| try testing.expectEqual(@as(u8, 1 + @as(u8, @truncate(i))), got[i * default_page_size]);
    try testing.expect(pc.stats().resident_pages <= 1);
}

test "read-ahead: a borrowed page is not evicted by read-ahead" {
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var pc = PageCache.init(gpa, sim.storage(), .{ .max_pages = 4, .read_ahead_pages = 6 });
    defer pc.deinit();
    const st = pc.storage();
    const h = try seedPages(gpa, &pc, st, 12);
    const borrowed = (try pc.preadRef(h, default_page_size, 11 * default_page_size)).?;
    const got = try scanAll(gpa, st, h, 11);
    defer gpa.free(got);
    for (borrowed.bytes) |x| try testing.expectEqual(@as(u8, 12), x);
    try testing.expectEqual(@as(usize, 1), pc.stats().borrowed_pages);
    pc.releasePage(borrowed);
}

test "read-ahead: transparency, kvtree over PageCache(Sim) with read-ahead == raw Sim" {
    const gpa = testing.allocator;
    var raw_sim = kv.SimStorage.init(gpa);
    defer raw_sim.deinit();
    raw_sim.allow_overwrite = true;
    var raw_db = try kvtree.Db.open(gpa, raw_sim.storage(), "t.kvt", .{});
    defer raw_db.close();

    var cached_sim = kv.SimStorage.init(gpa);
    defer cached_sim.deinit();
    cached_sim.allow_overwrite = true;
    var pc = PageCache.init(gpa, cached_sim.storage(), .{ .max_pages = 8, .read_ahead_pages = 4 });
    defer pc.deinit();
    var cached_db = try kvtree.Db.open(gpa, pc.storage(), "t.kvt", .{});
    defer cached_db.close();

    const scratch = try gpa.alloc(u8, 64);
    defer gpa.free(scratch);
    try runWorkload(&raw_db, 0xA11CE, 1500, 200, 64, scratch);
    try runWorkload(&cached_db, 0xA11CE, 1500, 200, 64, scratch);

    const raw_dump = try dumpScan(gpa, &raw_db);
    defer gpa.free(raw_dump);
    const cached_dump = try dumpScan(gpa, &cached_db);
    defer gpa.free(cached_dump);
    try testing.expectEqualStrings(raw_dump, cached_dump);
    try testing.expect(raw_dump.len > 0);
    try testing.expect(pc.cache.stats.entries <= 8);
}

// ── model-fuzz: seeded random operation sequences vs a naive reference ───────
//
// The reference model is a flat byte array per path ("the disk"), written from
// the Storage contract alone: a write overlays bytes (zero-filling any gap), a
// truncate shrinks, a read returns the bytes that are there (short at EOF, 0
// past it). It knows nothing of pages, residency, eviction or pinning. The
// cache must be invisible: every pread / size equals the model, the inner
// media equals the model after every step (write-through, also after a failed
// or torn write), and a borrow keeps the snapshot it was handed. Eviction
// order is an implementation choice and is not modelled -- only the budget
// invariant (`resident <= max_pages + borrowed`) and the counter identities
// (`hits + misses` == full-page preads issued) are.

const MfModel = struct {
    const ps = 16; // page size under test (tiny, so edges are reached fast)
    const n_paths = 3;
    const cap = 24 * ps;
    const pool = 96; // inodes available to one case
    const paths = [n_paths][]const u8{ "p0", "p1", "p2" };

    /// Path -> file. The model is per PATH for names and per FILE (inode) for
    /// bytes, like the backend: a handle follows its file across `rename` and
    /// `delete`, and a name can lead to a different file after either.
    name: [n_paths]?usize = @splat(null),
    used: usize = 0,
    len: [pool]usize = @splat(0),
    data: [pool][cap]u8 = undefined,

    fn write(m: *MfModel, ino: usize, off: usize, bytes: []const u8) void {
        const end = off + bytes.len;
        if (end > m.len[ino]) {
            @memset(m.data[ino][m.len[ino]..end], 0);
            m.len[ino] = end;
        }
        @memcpy(m.data[ino][off..end], bytes);
    }

    fn read(m: *const MfModel, ino: usize, off: usize, out: []u8) usize {
        if (off >= m.len[ino]) return 0;
        const n = @min(out.len, m.len[ino] - off);
        @memcpy(out[0..n], m.data[ino][off..][0..n]);
        return n;
    }

    fn named(m: *const MfModel, ino: usize) bool {
        for (m.name) |n| if (n == ino) return true;
        return false;
    }
};

const MfReach = struct {
    hit: u64 = 0,
    miss: u64 = 0,
    evict: u64 = 0,
    ref_hit: u64 = 0,
    ref_miss: u64 = 0,
    ref_null: u64 = 0,
    readahead: u64 = 0,
    over_cap_by_borrow: u64 = 0,
    borrow_kept_snapshot: u64 = 0,
    short_read: u64 = 0,
    eof_read: u64 = 0,
    unaligned_write: u64 = 0,
    failed_write: u64 = 0,
    torn_write: u64 = 0,
    ro_denied: u64 = 0,
    truncate: u64 = 0,
    close_reopen: u64 = 0,
    create_truncate: u64 = 0,
    rename: u64 = 0,
    delete: u64 = 0,
    open_errors: u64 = 0,
    // several handles on one path
    second_handle: u64 = 0,
    shared_read_after_other_write: u64 = 0,
    create_truncate_shared: u64 = 0,
    rename_open: u64 = 0,
    rename_over_open: u64 = 0,
    delete_open: u64 = 0,
    orphan_io: u64 = 0,
};

const MfBorrow = struct { page: Page, ino: usize, off: usize, snap: [MfModel.ps]u8 };
const MfHandle = struct { h: Storage.Handle, ino: usize, ro: bool };

fn mfCase(gpa: std.mem.Allocator, seed: u64, reach: *MfReach) !void {
    const ps = MfModel.ps;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    const max_pages_choices = [_]usize{ 1, 1, 2, 3, 5, 8 };
    const ra_choices = [_]u32{ 0, 0, 2, 4 };
    const max_pages = max_pages_choices[rnd.uintLessThan(usize, max_pages_choices.len)];
    const ra = ra_choices[rnd.uintLessThan(usize, ra_choices.len)];

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var fault = FaultStorage{ .inner = sim.storage() };
    var pc = PageCache.init(gpa, fault.storage(), .{ .page_size = ps, .max_pages = max_pages, .read_ahead_pages = ra });
    defer pc.deinit();
    const st = pc.storage();

    var model = MfModel{};
    // Up to two handles per path (slot k), each bound to the file it opened.
    var hs: [MfModel.n_paths][2]?MfHandle = @splat(.{ null, null });
    var borrows: [6]?MfBorrow = @splat(null);
    // Which handle slot last wrote each file (for the shared-read reach class).
    var last_writer: [MfModel.pool]?Storage.Handle = @splat(null);
    var full_reads: u64 = 0;
    var ref_ok: u64 = 0;
    defer for (&borrows) |*slot| {
        if (slot.*) |b| pc.releasePage(b.page);
    };

    const steps = 80 + rnd.uintLessThan(usize, 220);
    var step: usize = 0;
    errdefer std.debug.print("pagecache model-fuzz FAILED: seed={d} step={d} max_pages={d} read_ahead={d}\n", .{ seed, step, max_pages, ra });
    while (step < steps) : (step += 1) {
        const i = rnd.uintLessThan(usize, MfModel.n_paths);
        const k = rnd.uintLessThan(usize, 2);
        var roll = rnd.uintLessThan(u32, 100);
        if (hs[i][k] == null and roll >= 12 and roll < 96) roll = 0; // a closed slot: open it first
        const hk = hs[i][k];
        const ino: usize = if (hk) |x| x.ino else 0;
        const live_pages = model.len[ino] / ps;

        if (roll < 12) { // ---- open (a second handle on an open path is the point)
            if (hk != null) continue;
            const modes = [_]Storage.OpenMode{ .open_or_create, .open_or_create, .create_truncate, .read_only, .create_new };
            const mode = modes[rnd.uintLessThan(usize, modes.len)];
            const exists = model.name[i] != null;
            if (!exists and mode != .read_only and model.used == MfModel.pool) continue;
            if (st.open(MfModel.paths[i], mode)) |h| {
                try testing.expect(!(mode == .read_only and !exists));
                try testing.expect(!(mode == .create_new and exists));
                const other_open = hs[i][1 - k] != null;
                var fino: usize = undefined;
                if (model.name[i]) |n| {
                    fino = n;
                    if (mode == .create_truncate) model.len[n] = 0;
                } else {
                    fino = model.used;
                    model.used += 1;
                    model.len[fino] = 0;
                    model.name[i] = fino;
                }
                if (mode == .create_truncate) {
                    reach.create_truncate += 1;
                    if (other_open) reach.create_truncate_shared += 1;
                }
                if (other_open) reach.second_handle += 1;
                hs[i][k] = .{ .h = h, .ino = fino, .ro = mode == .read_only };
            } else |err| {
                reach.open_errors += 1;
                if (mode == .read_only and !exists) {
                    try testing.expectEqual(error.FileNotFound, err);
                } else if (mode == .create_new and exists) {
                    try testing.expectEqual(error.PathAlreadyExists, err);
                } else return err;
            }
        } else if (roll < 18) { // ---- close (and usually reopen later)
            st.close(hk.?.h);
            hs[i][k] = null;
            reach.close_reopen += 1;
        } else if (roll < 42) { // ---- full aligned page write
            const h = hk.?.h;
            const idx = rnd.uintLessThan(usize, live_pages + 3);
            if ((idx + 1) * ps > MfModel.cap) continue;
            var page: [ps]u8 = undefined;
            if (rnd.boolean()) rnd.bytes(&page) else @memset(&page, rnd.int(u8));
            if (hk.?.ro) {
                try testing.expectError(error.AccessDenied, st.writeAll(h, &page, idx * ps));
                reach.ro_denied += 1;
            } else {
                try st.writeAll(h, &page, idx * ps);
                model.write(ino, idx * ps, &page);
                last_writer[ino] = h;
            }
        } else if (roll < 48) { // ---- unaligned / short / long write
            const h = hk.?.h;
            if (hk.?.ro) continue;
            const off = rnd.uintLessThan(usize, model.len[ino] + 2 * ps + 1);
            const n = 1 + rnd.uintLessThan(usize, 2 * ps + 3);
            if (off + n > MfModel.cap) continue;
            var buf: [2 * ps + 3]u8 = undefined;
            rnd.bytes(buf[0..n]);
            try st.writeAll(h, buf[0..n], off);
            model.write(ino, off, buf[0..n]);
            last_writer[ino] = h;
            if (!(n == ps and off % ps == 0)) reach.unaligned_write += 1;
        } else if (roll < 72) { // ---- full aligned page read
            const h = hk.?.h;
            const idx = rnd.uintLessThan(usize, live_pages + 3);
            var got: [ps]u8 = undefined;
            var want: [ps]u8 = undefined;
            const hits0 = pc.stats().hits;
            const n = try st.pread(h, &got, idx * ps);
            const wn = model.read(ino, idx * ps, &want);
            full_reads += 1;
            try testing.expectEqual(wn, n);
            try testing.expectEqualSlices(u8, want[0..wn], got[0..n]);
            if (n == 0) reach.eof_read += 1 else if (n < ps) reach.short_read += 1;
            if (!model.named(ino)) reach.orphan_io += 1;
            if (pc.stats().hits == hits0 + 1 and last_writer[ino] != null and last_writer[ino].? != h) reach.shared_read_after_other_write += 1;
        } else if (roll < 78) { // ---- arbitrary read
            const h = hk.?.h;
            const off = rnd.uintLessThan(usize, model.len[ino] + ps + 1);
            const len = 1 + rnd.uintLessThan(usize, 3 * ps);
            var got: [3 * ps]u8 = undefined;
            var want: [3 * ps]u8 = undefined;
            const n = try st.pread(h, got[0..len], off);
            const wn = model.read(ino, off, want[0..len]);
            if (len == ps and off % ps == 0) full_reads += 1;
            try testing.expectEqual(wn, n);
            try testing.expectEqualSlices(u8, want[0..wn], got[0..n]);
        } else if (roll < 86) { // ---- borrow
            const h = hk.?.h;
            const aligned = rnd.uintLessThan(u32, 8) != 0;
            const idx = rnd.uintLessThan(usize, live_pages + 2);
            const off = idx * ps + (if (aligned) 0 else 1 + rnd.uintLessThan(usize, ps - 1));
            const slot = for (&borrows) |*sl| {
                if (sl.* == null) break sl;
            } else continue;
            const full_present = off % ps == 0 and off + ps <= model.len[ino];
            const r = try pc.preadRef(h, ps, off);
            if (r) |page| {
                try testing.expect(full_present);
                var want: [ps]u8 = undefined;
                _ = model.read(ino, off, &want);
                try testing.expectEqualSlices(u8, &want, page.bytes);
                ref_ok += 1;
                slot.* = .{ .page = page, .ino = ino, .off = off, .snap = want };
            } else {
                try testing.expect(!full_present);
                reach.ref_null += 1;
            }
        } else if (roll < 91) { // ---- release a borrow
            const kb = rnd.uintLessThan(usize, borrows.len);
            if (borrows[kb]) |b| {
                try testing.expectEqualSlices(u8, &b.snap, b.page.bytes);
                pc.releasePage(b.page);
                borrows[kb] = null;
            }
        } else if (roll < 94) { // ---- truncate (shrink only: the seam's contract)
            const h = hk.?.h;
            const nl = rnd.uintLessThan(usize, model.len[ino] + 1);
            if (hk.?.ro) {
                try testing.expectError(error.AccessDenied, st.truncate(h, nl));
                reach.ro_denied += 1;
            } else {
                // No sync first: a cut through an un-synced overwrite is the
                // case that found kv SimStorage's undo-buffer invalid free
                // (fixed 2026-10-11, kv/src/sim.zig `undoBytes`).
                try st.truncate(h, nl);
                model.len[ino] = nl;
                last_writer[ino] = h;
                reach.truncate += 1;
            }
        } else if (roll < 96) { // ---- failed write, optionally torn
            const h = hk.?.h;
            if (hk.?.ro) continue;
            const idx = rnd.uintLessThan(usize, live_pages + 2);
            var page: [ps]u8 = undefined;
            rnd.bytes(&page);
            const torn = if (rnd.boolean()) rnd.uintLessThan(usize, ps) else 0;
            fault.fail_write_index = fault.writes;
            fault.torn_prefix = torn;
            try testing.expectError(error.NoSpaceLeft, st.writeAll(h, &page, idx * ps));
            fault.fail_write_index = null;
            fault.torn_prefix = 0;
            if (torn > 0) {
                model.write(ino, idx * ps, page[0..torn]); // the prefix really landed on media
                last_writer[ino] = h;
                reach.torn_write += 1;
            }
            reach.failed_write += 1;
        } else if (roll < 98) { // ---- rename (handles on either path may be open)
            const j = rnd.uintLessThan(usize, MfModel.n_paths);
            if (model.name[i] == null) {
                try testing.expectError(error.FileNotFound, st.rename(MfModel.paths[i], MfModel.paths[j]));
            } else {
                try st.rename(MfModel.paths[i], MfModel.paths[j]);
                if (i != j) {
                    if (hs[i][0] != null or hs[i][1] != null) reach.rename_open += 1;
                    if (hs[j][0] != null or hs[j][1] != null) reach.rename_over_open += 1;
                    model.name[j] = model.name[i];
                    model.name[i] = null;
                }
                reach.rename += 1;
            }
        } else { // ---- delete (handles may be open: the file lives on, nameless)
            if (model.name[i] == null) {
                try testing.expectError(error.FileNotFound, st.delete(MfModel.paths[i]));
            } else {
                if (hs[i][0] != null or hs[i][1] != null) reach.delete_open += 1;
                try st.delete(MfModel.paths[i]);
                model.name[i] = null;
                reach.delete += 1;
            }
        }

        // ---- invariants after EVERY step
        var open_handles: usize = 0;
        for (0..MfModel.n_paths) |p| {
            // Write-through: media equals the model, always.
            if (model.name[p]) |n| {
                try testing.expectEqualSlices(u8, model.data[n][0..model.len[n]], sim.fileContent(MfModel.paths[p]).?);
            } else {
                try testing.expect(sim.fileContent(MfModel.paths[p]) == null);
            }
            for (hs[p]) |maybe| if (maybe) |x| {
                open_handles += 1;
                try testing.expectEqual(@as(u64, model.len[x.ino]), try st.size(x.h));
            };
        }
        try testing.expectEqual(open_handles, pc.handle_file.count());
        try testing.expect(pc.files.items.len <= open_handles);
        var live_borrows: usize = 0;
        for (borrows) |slot| {
            const b = slot orelse continue;
            live_borrows += 1;
            // A borrow keeps the snapshot it was handed, whatever happened since.
            try testing.expectEqualSlices(u8, &b.snap, b.page.bytes);
            var cur: [ps]u8 = undefined;
            const cn = model.read(b.ino, b.off, &cur);
            // (reach) the live page moved on while the borrow still holds the old bytes
            if (cn != ps or !std.mem.eql(u8, &cur, &b.snap)) reach.borrow_kept_snapshot += 1;
        }
        const s = pc.stats();
        try testing.expect(s.resident_pages <= max_pages + s.borrowed_pages);
        try testing.expect(s.resident_bytes <= s.resident_pages * ps);
        try testing.expect(s.borrowed_pages <= live_borrows);
        try testing.expectEqual(full_reads, s.hits + s.misses);
        try testing.expectEqual(ref_ok, s.ref_hits + s.ref_misses);
        if (s.resident_pages > max_pages) reach.over_cap_by_borrow += 1;
    }

    // A last full audit through the cache, page by page, against the model
    // (every open handle, named or orphaned).
    for (0..MfModel.n_paths) |p| for (hs[p]) |maybe| {
        const x = maybe orelse continue;
        var off: usize = 0;
        while (off < model.len[x.ino]) : (off += ps) {
            var got: [ps]u8 = undefined;
            var want: [ps]u8 = undefined;
            const n = try st.pread(x.h, &got, off);
            const wn = model.read(x.ino, off, &want);
            full_reads += 1;
            try testing.expectEqual(wn, n);
            try testing.expectEqualSlices(u8, want[0..wn], got[0..n]);
        }
    };
    const fin = pc.stats();
    if (fin.hits > 0) reach.hit += 1;
    if (fin.misses > 0) reach.miss += 1;
    if (fin.evictions > 0) reach.evict += 1;
    if (fin.ref_hits > 0) reach.ref_hit += 1;
    if (fin.ref_misses > 0) reach.ref_miss += 1;
    if (fin.readahead_pages > 0) reach.readahead += 1;
}

test "model-fuzz: PageCache over SimStorage == naive per-file byte model (300 seeds)" {
    const gpa = testing.allocator;
    var reach = MfReach{};
    var seed: u64 = 0;
    while (seed < 300) : (seed += 1) try mfCase(gpa, 0x9A6E_CAC0_0000 + seed, &reach);
    errdefer std.debug.print("pagecache model-fuzz reach: {any}\n", .{reach});
    // Every outcome class must have happened, or the run proved less than it claims.
    inline for (@typeInfo(MfReach).@"struct".field_names) |name| {
        if (@field(reach, name) == 0) {
            std.debug.print("pagecache model-fuzz: reach class never hit: {s}\n", .{name});
            return error.ReachClassMissed;
        }
    }
}
