// SPDX-License-Identifier: MIT

//! kvtree — an embedded, ordered, transactional key-value store: a
//! copy-on-write B-tree (LMDB/BoltDB lineage) with MVCC snapshot isolation,
//! multi-key ACID transactions, ordered range scans, and crash-safety proven
//! the same VOPR way `kv` v0 is. It is the ordered/transactional sibling of the
//! `kv` Bitcask point-store — `kv` stays for get/put-only workloads (e.g.
//! `jobqueue`); reach for `kvtree` when you need `scan(a..b)` in key order,
//! atomic multi-key commit/rollback, or readers that see a consistent snapshot
//! without blocking the writer.
//!
//! **Architecture: copy-on-write B-tree, not B-tree + WAL.** A write
//! transaction copies every tree node on its root-to-leaf path (never mutates
//! in place), then flips a single durable pointer — the meta page — from the
//! old root to the new one. From that one design choice, three properties fall
//! out for free instead of needing a separate write-ahead-log state machine:
//! *snapshot isolation* (a reader pins an old root and reads an immutable tree
//! version), *atomic commit* (the tree becomes visible in one pointer swap, or
//! not at all), and *crash-safety* (double-buffered meta pages mean a torn
//! commit leaves the previous meta as the newest valid one). The price COW pays
//! is write amplification (a whole path rewritten per commit) and single-writer
//! serialization — both fine for the embedded, low-contention workloads this
//! serves; see SPEC.md for the full A-vs-B decision.
//!
//! **Status: core implemented.** The irreducible correctness core — `commit`'s
//! durability-ordered COW meta swap, `recover`'s crash meta-selection, and the
//! MVCC page-reuse gate — is implemented in `core.zig` and
//! `gate.fable_core_implemented` is flipped, so the property tests drive the
//! real `Db` through commit/snapshot schedules and a crash-point sweep on
//! `kv.SimStorage` (see `harness.zig`). Remaining scaffold simplifications are
//! documented in SPEC.md's backlog (overflow pages, freelist chaining — the
//! single freelist page LEAKS excess freed ids when full, never corrupts —
//! and rebalance-by-borrow).

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv = @import("kv");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Ordered transactional KV store — copy-on-write B-tree (LMDB/BoltDB lineage), MVCC snapshots, crash-safe range scans.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // all I/O via kv's Storage seam (std.Io)
    .role = .both, // embedded ordered read+write store
    // Single writer; MVCC readers take lockless immutable snapshots (the COW
    // design). Reader/writer coordination safety = the gated reclaim invariant.
    .concurrency = .single_owner,
    .model_after = "LMDB / BoltDB (COW B-tree, meta double-buffer); VOPR = TigerBeetle",
    .deps = .{"kv"},
};

const format = @import("format.zig");
const pager_mod = @import("pager.zig");
const core = @import("core.zig");
const gate = @import("gate.zig");

// ── re-exports ────────────────────────────────────────────────────────────────

pub const page_size = format.page_size;
pub const PageId = format.PageId;
pub const Pager = pager_mod.Pager;
pub const Freelist = pager_mod.Freelist;
pub const Change = core.Change;
/// True since the core landed — see `gate.zig`.
pub const fable_core_implemented = gate.fable_core_implemented;

/// Re-export `kv`'s storage seam so consumers wire a backend without importing
/// `kv` directly: production `FsStorage`, deterministic `SimStorage`.
pub const Storage = kv.Storage;
pub const FsStorage = kv.FsStorage;
pub const SimStorage = kv.SimStorage;

pub const OpenError = kv.Storage.Error || core.RecoverError || error{
    Corrupt,
    NotAKvtreeFile,
    /// Another `Db` — in another process, or in this one — currently holds
    /// the store's exclusive lock. Nothing was opened, read or written.
    Locked,
};
pub const GetError = kv.Storage.Error || error{ Corrupt, OutOfMemory };
pub const CommitError = core.CommitError;

/// A borrowed key/value pair yielded by a `Cursor`. The slices point into the
/// cursor's current leaf-page buffer and stay valid only until the next
/// `next()`/`seek()` call — copy them if you need to keep them.
pub const KV = struct { key: []const u8, val: []const u8 };

// ── Db ─────────────────────────────────────────────────────────────────────

pub const Db = struct {
    gpa: Allocator,
    pager: Pager,
    /// The current committed meta (root of the newest durable tree version).
    meta_rec: format.Meta,
    path: []u8,
    /// Owned copy of the cross-process lock sidecar's path (freed on close).
    lock_path: []u8,
    /// Handle of the held `<path>.lock` sidecar, or null with
    /// `Options.lock == .none`. Closing it releases the advisory lock.
    lock_file: ?kv.Storage.Handle,
    /// txn_id to stamp the next commit with (monotonic).
    next_txn: u64,
    /// Open read snapshots' pinned txn_ids — their minimum is the oldest reader
    /// the reclaim gate must respect. Kept sorted-insert-free; min computed on
    /// demand (open-snapshot counts are tiny in the embedded model).
    open_snapshots: std.ArrayList(u64),

    /// Open (or create) the store. A fresh/empty file is initialized
    /// mechanically (two meta pages + an empty-leaf root); an existing file is
    /// recovered via `core.recover` (the Fable crash-recovery core).
    ///
    /// Unless `options.lock == .none`, an exclusive advisory lock on a
    /// `<path>.lock` sidecar is taken FIRST, before the data file is even
    /// opened — mirroring `kv.Db.open`'s ordering (see its doc comment for
    /// why the lock lives on a sidecar rather than the data file). A second
    /// concurrent opener over the same store gets `error.Locked` with
    /// nothing touched, instead of silently racing this one's COW commits.
    pub fn open(gpa: Allocator, store: kv.Storage, path: []const u8, options: Options) OpenError!Db {
        const lock_path = try std.fmt.allocPrint(gpa, "{s}.lock", .{path});
        errdefer gpa.free(lock_path);

        var lock_file: ?kv.Storage.Handle = null;
        if (options.lock == .exclusive) {
            const lh = try store.open(lock_path, .open_or_create);
            lock_file = lh;
        }
        errdefer if (lock_file) |lh| store.close(lh);
        if (lock_file) |lh| {
            if (!try store.tryLockExclusive(lh)) return error.Locked;
        }

        const handle = try store.open(path, .open_or_create);
        errdefer store.close(handle);
        const size = try store.size(handle);

        var pager = Pager.init(store, handle, 0);
        var meta_rec: format.Meta = undefined;
        if (size < 2 * page_size) {
            // Fresh (or a torn creation): lay down the initial store. Mechanical
            // — a crash mid-init leaves < 2 meta pages, so the next open just
            // re-initializes; there is no prior committed state to protect yet.
            meta_rec = try initFresh(&pager);
        } else {
            pager.high_water = size / page_size;
            meta_rec = core.recover(gpa, &pager) catch |e| switch (e) {
                error.Unrecoverable => return error.Corrupt,
                error.Storage => return error.Corrupt,
                error.OutOfMemory => return error.OutOfMemory,
            };
            pager.high_water = meta_rec.high_water;
        }

        return .{
            .gpa = gpa,
            .pager = pager,
            .meta_rec = meta_rec,
            .path = try gpa.dupe(u8, path),
            .lock_path = lock_path,
            .lock_file = lock_file,
            .next_txn = meta_rec.txn_id + 1,
            .open_snapshots = .empty,
        };
    }

    pub fn close(self: *Db) void {
        self.pager.store.close(self.pager.handle);
        if (self.lock_file) |lh| self.pager.store.close(lh);
        self.gpa.free(self.lock_path);
        self.open_snapshots.deinit(self.gpa);
        self.gpa.free(self.path);
        self.* = undefined;
    }

    /// Mechanical fresh-store init: an empty-leaf root at page 2, both meta
    /// slots pointing at it (txn_id 0), all durable. Not the Fable core — no
    /// prior committed state exists to be atomic against.
    fn initFresh(pager: *Pager) OpenError!format.Meta {
        var page: [page_size]u8 = undefined;
        const root_id = format.first_data_page; // page 2
        format.encodeEmptyLeaf(&page);
        try pager.writePage(root_id, &page);
        const m = format.Meta{
            .txn_id = 0,
            .root = root_id,
            .free_root = 0,
            .free_count = 0,
            .high_water = root_id + 1,
        };
        m.encode(&page);
        try pager.writePage(format.meta_page_a, &page);
        try pager.writePage(format.meta_page_b, &page);
        try pager.sync();
        try pager.syncDir();
        pager.high_water = m.high_water;
        return m;
    }

    // ── point reads (mechanical: descend the committed tree) ────────────────

    /// Look up `key` in the newest committed version. Caller frees the result.
    pub fn get(self: *Db, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        return lookup(&self.pager, self.meta_rec.root, gpa, key);
    }

    /// A cursor over the newest committed version (ordered iteration / scan).
    /// Consistent for the cursor's lifetime only in the single-writer model;
    /// for a stable view across concurrent commits, take a `snapshot`.
    pub fn cursor(self: *Db) Allocator.Error!Cursor {
        return Cursor.init(self.gpa, &self.pager, self.meta_rec.root);
    }

    // ── transactions ─────────────────────────────────────────────────────────

    /// Begin a read-write transaction: buffer put/del, then `commit` (atomic,
    /// via the Fable core) or `rollback`. Single-writer — one RW txn at a time.
    pub fn begin(self: *Db) Allocator.Error!Txn {
        return .{
            .db = self,
            .base = self.meta_rec,
            .changes = .empty,
            .arena = std.heap.ArenaAllocator.init(self.gpa),
        };
    }

    /// Convenience autocommit put (a one-op transaction).
    pub fn put(self: *Db, key: []const u8, val: []const u8) (CommitError || Allocator.Error)!void {
        var txn = try self.begin();
        txn.put(key, val) catch |e| {
            txn.rollback();
            return e;
        };
        // commit() consumes the txn on both outcomes — no rollback after it.
        try txn.commit();
    }

    /// Convenience autocommit delete.
    pub fn del(self: *Db, key: []const u8) (CommitError || Allocator.Error)!void {
        var txn = try self.begin();
        txn.del(key) catch |e| {
            txn.rollback();
            return e;
        };
        try txn.commit();
    }

    // ── snapshots (MVCC readers) ─────────────────────────────────────────────

    /// Pin the current committed version for repeatable reads. The pinned root
    /// stays readable even as the writer commits newer versions — its pages are
    /// protected from reuse by the reclaim gate until the snapshot is released.
    pub fn snapshot(self: *Db) Allocator.Error!Snapshot {
        try self.open_snapshots.append(self.gpa, self.meta_rec.txn_id);
        return .{ .db = self, .root = self.meta_rec.root, .txn_id = self.meta_rec.txn_id };
    }

    /// Lowest txn any open snapshot is pinned to, or "one past current" when
    /// none is open — the `oldest_reader_txn` the reclaim gate is fed.
    fn oldestReader(self: *const Db) u64 {
        var m: u64 = self.meta_rec.txn_id + 1;
        for (self.open_snapshots.items) |t| m = @min(m, t);
        return m;
    }

    fn releaseSnapshot(self: *Db, txn_id: u64) void {
        for (self.open_snapshots.items, 0..) |t, i| {
            if (t == txn_id) {
                _ = self.open_snapshots.swapRemove(i);
                return;
            }
        }
    }
};

pub const Options = struct {
    /// Cross-process exclusion policy (default: on). See `LockPolicy`.
    lock: LockPolicy = .exclusive,
};

pub const LockPolicy = enum {
    /// Take and hold an exclusive advisory lock on `<path>.lock` for the
    /// whole lifetime of the `Db`. A second opener over the same store gets
    /// `error.Locked`. This is the default: kvtree's whole correctness case
    /// rests on being the sole writer of its COW meta pages, and two
    /// independent `Db`s over one file is not something the format survives.
    exclusive,
    /// No locking at all. For a pure in-memory `Storage`, for a caller that
    /// already has its own exclusion (e.g. a single `Store` that itself
    /// serializes access to a shard), or where the backend cannot support
    /// locking at all. Choosing this is choosing to be the sole writer by
    /// construction.
    none,
};

// ── Txn ──────────────────────────────────────────────────────────────────────

pub const Txn = struct {
    db: *Db,
    base: format.Meta,
    /// Buffered mutations (last-writer-wins per key is resolved at commit).
    changes: std.ArrayList(core.Change),
    /// Owns the buffered keys/values until commit or rollback.
    arena: std.heap.ArenaAllocator,

    pub fn put(self: *Txn, key: []const u8, val: []const u8) Allocator.Error!void {
        const a = self.arena.allocator();
        try self.changes.append(self.db.gpa, .{
            .put = .{ .key = try a.dupe(u8, key), .val = try a.dupe(u8, val) },
        });
    }

    pub fn del(self: *Txn, key: []const u8) Allocator.Error!void {
        const a = self.arena.allocator();
        try self.changes.append(self.db.gpa, .{ .del = try a.dupe(u8, key) });
    }

    /// Read within the transaction: buffered changes shadow the base tree.
    pub fn get(self: *Txn, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        // Latest buffered change for this key wins.
        var i: usize = self.changes.items.len;
        while (i > 0) {
            i -= 1;
            switch (self.changes.items[i]) {
                .put => |p| if (std.mem.eql(u8, p.key, key)) return try gpa.dupe(u8, p.val),
                .del => |k| if (std.mem.eql(u8, k, key)) return null,
            }
        }
        return lookup(&self.db.pager, self.base.root, gpa, key);
    }

    /// Commit atomically (via `core.commit`). CONSUMES the transaction on
    /// BOTH outcomes: after a failed commit the txn is already torn down —
    /// do not call `rollback` on it (the store itself is left on the last
    /// committed version either way; that is `core.commit`'s guarantee).
    pub fn commit(self: *Txn) CommitError!void {
        defer {
            self.arena.deinit();
            self.changes.deinit(self.db.gpa);
            self.* = undefined;
        }
        const new_meta = try core.commit(
            self.db.gpa,
            &self.db.pager,
            self.base,
            self.changes.items,
            self.db.oldestReader(),
        );
        self.db.meta_rec = new_meta;
        self.db.next_txn = new_meta.txn_id + 1;
    }

    pub fn rollback(self: *Txn) void {
        self.arena.deinit();
        self.changes.deinit(self.db.gpa);
        self.* = undefined;
    }
};

// ── Snapshot (read-only MVCC view) ───────────────────────────────────────────

pub const Snapshot = struct {
    db: *Db,
    root: PageId,
    txn_id: u64,

    pub fn get(self: *Snapshot, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        return lookup(&self.db.pager, self.root, gpa, key);
    }

    pub fn cursor(self: *Snapshot) Allocator.Error!Cursor {
        return Cursor.init(self.db.gpa, &self.db.pager, self.root);
    }

    pub fn release(self: *Snapshot) void {
        self.db.releaseSnapshot(self.txn_id);
        self.* = undefined;
    }
};

// ── read path: descend + ordered cursor (all mechanical) ─────────────────────

/// Descend from `root` to the leaf that would hold `key` and return a copy of
/// its value, or null. No allocation beyond the returned value.
fn lookup(pager: *Pager, root: PageId, gpa: Allocator, key: []const u8) GetError!?[]u8 {
    var page: [page_size]u8 = undefined;
    var id = root;
    while (true) {
        // The descent only ever *reads* its pages, and holds exactly one at a
        // time, so it is the one tree path that can take the store's borrow
        // seam when there is one (a `pagecache` in front of the backend): a
        // resident page then costs no copy per level instead of a whole-page
        // `@memcpy` per level. Everything else here — the copy-on-write write
        // path and the cursor's root-to-leaf frame stack — mutates or outlives
        // its pages and correctly keeps its own copies.
        const ref = try pager.readPageRef(id);
        defer if (ref) |r| pager.releasePageRef(r);
        const bytes: *const [page_size]u8 = if (ref) |r| r.bytes[0..page_size] else blk: {
            try pager.readPage(id, &page);
            break :blk &page;
        };
        switch (format.kindOf(bytes)) {
            .branch => id = format.Branch.init(bytes).childFor(key),
            .leaf => {
                const leaf = format.Leaf.init(bytes);
                const s = leaf.search(key);
                if (!s.found) return null;
                return try gpa.dupe(u8, leaf.valAt(s.index));
            },
        }
    }
}

/// In-order cursor over a B-tree version. Holds a root-to-leaf stack of page
/// copies so it can walk leaves left to right; yielded slices borrow the leaf
/// frame and are valid until the next call.
pub const Cursor = struct {
    gpa: Allocator,
    pager: *Pager,
    root: PageId,
    stack: std.ArrayList(Frame),

    const Frame = struct {
        page: [page_size]u8,
        id: PageId,
        /// For a branch: ordinal of the child we descended into. For a leaf:
        /// index of the next entry to yield.
        idx: u16,
    };

    fn init(gpa: Allocator, pager: *Pager, root: PageId) Allocator.Error!Cursor {
        return .{ .gpa = gpa, .pager = pager, .root = root, .stack = .empty };
    }

    pub fn deinit(self: *Cursor) void {
        self.stack.deinit(self.gpa);
        self.* = undefined;
    }

    /// Position at the first (smallest) key.
    pub fn first(self: *Cursor) (kv.Storage.Error || error{ Corrupt, OutOfMemory })!void {
        self.stack.clearRetainingCapacity();
        try self.descendLeftmost(self.root);
    }

    /// Position at the first key >= `key` (range-scan start).
    pub fn seek(self: *Cursor, key: []const u8) (kv.Storage.Error || error{ Corrupt, OutOfMemory })!void {
        self.stack.clearRetainingCapacity();
        var id = self.root;
        while (true) {
            var frame = Frame{ .page = undefined, .id = id, .idx = 0 };
            try self.pager.readPage(id, &frame.page);
            switch (format.kindOf(&frame.page)) {
                .branch => {
                    const br = format.Branch.init(&frame.page);
                    const ci = br.childIndexFor(key);
                    frame.idx = @intCast(ci);
                    try self.stack.append(self.gpa, frame);
                    id = br.childAtIndex(ci);
                },
                .leaf => {
                    const leaf = format.Leaf.init(&frame.page);
                    frame.idx = leaf.search(key).index; // first entry >= key
                    try self.stack.append(self.gpa, frame);
                    return;
                },
            }
        }
    }

    fn descendLeftmost(self: *Cursor, from: PageId) (kv.Storage.Error || error{ Corrupt, OutOfMemory })!void {
        var id = from;
        while (true) {
            var frame = Frame{ .page = undefined, .id = id, .idx = 0 };
            try self.pager.readPage(id, &frame.page);
            const is_leaf = format.kindOf(&frame.page) == .leaf;
            try self.stack.append(self.gpa, frame);
            if (is_leaf) return;
            id = format.Branch.init(&self.stack.items[self.stack.items.len - 1].page).childAtIndex(0);
        }
    }

    /// Yield the next entry in key order, or null at the end. Returned slices
    /// borrow the cursor's leaf buffer — valid until the next call.
    pub fn next(self: *Cursor) (kv.Storage.Error || error{ Corrupt, OutOfMemory })!?KV {
        while (self.stack.items.len > 0) {
            const top = &self.stack.items[self.stack.items.len - 1];
            const leaf = format.Leaf.init(&top.page);
            if (top.idx < leaf.count()) {
                const out = KV{ .key = leaf.keyAt(top.idx), .val = leaf.valAt(top.idx) };
                top.idx += 1;
                return out;
            }
            // Leaf exhausted → climb to the nearest ancestor with a next child.
            _ = self.stack.pop();
            while (self.stack.items.len > 0) {
                const anc = &self.stack.items[self.stack.items.len - 1];
                const br = format.Branch.init(&anc.page);
                if (anc.idx < br.count()) { // children are 0..count
                    anc.idx += 1;
                    const child = br.childAtIndex(anc.idx);
                    try self.descendLeftmost(child);
                    break; // retry the outer loop against the new leaf
                }
                _ = self.stack.pop();
            }
        }
        return null;
    }
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("format.zig");
    _ = @import("pager.zig");
    _ = @import("core.zig");
    _ = @import("prng.zig");
    _ = @import("harness.zig");
    _ = @import("gate.zig");
}

const testing = std.testing;

test "smoke: fresh store opens, is empty, and closes cleanly (mechanical init)" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{});
    defer db.close();
    try testing.expectEqual(@as(u64, 0), db.meta_rec.txn_id);
    const got = try db.get(testing.allocator, "absent");
    try testing.expect(got == null);
    // empty cursor yields nothing
    var cur = try db.cursor();
    defer cur.deinit();
    try cur.first();
    try testing.expect((try cur.next()) == null);
}

test "open takes an exclusive lock by default: a second concurrent opener over the same store is refused" {
    // WAVE-2 K3: `Db.open` used to discard `Options` entirely (`_ = options;`)
    // and never call `store.tryLockExclusive`, so two independent `Db`s could
    // race each other's COW commits over one file with no complaint at all —
    // three consumers (`tsdb` F6, `shardstore` F2, `pagecache` F4) filed the
    // same finding independently. Fixed once, here.
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();

    var db1 = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{});

    // A second opener over the SAME store, while the first is still live,
    // must be refused — not silently allowed to race the first one's commits.
    try testing.expectError(error.Locked, Db.open(testing.allocator, sim.storage(), "t.kvt", .{}));

    // Closing the first releases the lock; a subsequent opener succeeds.
    db1.close();
    var db2 = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{});
    db2.close();

    // `.lock = .none` opts back out, for a caller that already provides its
    // own exclusion (e.g. `shardstore`'s single store-wide lock).
    var db3 = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{ .lock = .none });
    defer db3.close();
    var db4 = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{ .lock = .none });
    db4.close();
}

test "read path over a hand-built two-level tree: get + ordered scan + seek" {
    // Build a real branch→leaf tree by writing pages directly (the write path
    // proper is the gated core; this exercises the MECHANICAL read path against
    // a genuine multi-level tree). Layout: root branch(sep="m") → leafL, leafR.
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{});
    defer db.close();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var page: [page_size]u8 = undefined;

    // leafL: apple, banana ; leafR: mango, zebra
    var lb = format.LeafBuilder.init(a);
    try lb.put("apple", "1");
    try lb.put("banana", "2");
    const leafL = db.pager.growOne();
    lb.encode(&page);
    try db.pager.writePage(leafL, &page);

    var rb = format.LeafBuilder.init(a);
    try rb.put("mango", "3");
    try rb.put("zebra", "4");
    const leafR = db.pager.growOne();
    rb.encode(&page);
    try db.pager.writePage(leafR, &page);

    var branch = format.BranchBuilder.init(a, leafL);
    try branch.insert("m", leafR); // keys < "m" → leafL, >= "m" → leafR
    const root = db.pager.growOne();
    branch.encode(&page);
    try db.pager.writePage(root, &page);
    try db.pager.sync();
    db.meta_rec.root = root; // point the live view at our hand-built tree

    // get across both leaves + the routing key boundary
    try expectGet(&db, "apple", "1");
    try expectGet(&db, "banana", "2");
    try expectGet(&db, "mango", "3");
    try expectGet(&db, "zebra", "4");
    try expectGet(&db, "cherry", null); // < m, absent in leafL
    try expectGet(&db, "yak", null); // >= m, absent in leafR

    // full ordered scan
    var cur = try db.cursor();
    defer cur.deinit();
    try cur.first();
    const order = [_][]const u8{ "apple", "banana", "mango", "zebra" };
    for (order) |want| {
        const e = (try cur.next()).?;
        try testing.expectEqualStrings(want, e.key);
    }
    try testing.expect((try cur.next()) == null);

    // seek into the right leaf: first key >= "n" is "zebra"
    var cur2 = try db.cursor();
    defer cur2.deinit();
    try cur2.seek("n");
    try testing.expectEqualStrings("zebra", (try cur2.next()).?.key);
    try testing.expect((try cur2.next()) == null);

    // seek at the boundary: first key >= "m" is "mango"
    var cur3 = try db.cursor();
    defer cur3.deinit();
    try cur3.seek("m");
    try testing.expectEqualStrings("mango", (try cur3.next()).?.key);
}

test "transaction buffers reads (put/del shadow the base tree) without committing" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "t.kvt", .{});
    defer db.close();

    var txn = try db.begin();
    defer txn.rollback();
    try txn.put("k", "v");
    try txn.put("k", "v2"); // later write wins
    const got = try txn.get(testing.allocator, "k");
    defer if (got) |g| testing.allocator.free(g);
    try testing.expectEqualStrings("v2", got.?);
    try txn.del("k");
    try testing.expect((try txn.get(testing.allocator, "k")) == null);
}

fn expectGet(db: *Db, key: []const u8, want: ?[]const u8) !void {
    const got = try db.get(testing.allocator, key);
    defer if (got) |g| testing.allocator.free(g);
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(w, got.?);
    } else {
        try testing.expect(got == null);
    }
}

test "smoke: module re-exports resolve; gate is readable regardless of value" {
    _ = fable_core_implemented;
    _ = Change;
    try testing.expectEqual(@as(usize, 4096), page_size);
}

test "steady state: overwriting a fixed key set stops growing the file (the freelist chain recycles)" {
    // THE REGRESSION GATE for the unbounded-growth defect. Chain-storage pages
    // used to come only from `Pager.growOne`, so every commit permanently added
    // `pagesNeeded()` entries to the freelist, which lengthened the chain, which
    // added more entries — self-amplifying. It went unnoticed because every
    // other test either commits a handful of times or checks correctness rather
    // than footprint; the cost only shows up as a store that never stops
    // growing under a steady write load. Measured downstream before the fix: a
    // modest append workload grew the file by over a gigabyte an hour.
    //
    // The workload overwrites a FIXED key set, so the tree's own size is
    // constant and any growth is pure bookkeeping leak.
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // COW page store: meta slots + page reuse
    var db = try Db.open(testing.allocator, sim.storage(), "steady.kvt", .{});
    defer db.close();

    var key_buf: [16]u8 = undefined;
    const val = "v" ** 64;
    const keys = 16;

    // Warm up: the tree reaches its shape, and the freelist reaches the state
    // where a commit's frees can satisfy the next commit's allocations.
    var i: usize = 0;
    while (i < keys * 8) : (i += 1) {
        const key = try std.fmt.bufPrint(&key_buf, "k{d:0>4}", .{i % keys});
        try db.put(key, val);
    }
    const warm = db.meta_rec.high_water;

    // Then a long run of the same thing. A leak of even ONE page per commit
    // would show as +200 here; the old code leaked at least that.
    while (i < keys * 8 + 200) : (i += 1) {
        const key = try std.fmt.bufPrint(&key_buf, "k{d:0>4}", .{i % keys});
        try db.put(key, val);
    }
    try testing.expectEqual(warm, db.meta_rec.high_water);

    // …and the data is still right, so this is a steady state and not a store
    // that quietly stopped writing.
    var k: usize = 0;
    while (k < keys) : (k += 1) {
        const key = try std.fmt.bufPrint(&key_buf, "k{d:0>4}", .{k});
        const got = try db.get(testing.allocator, key);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(val, got.?);
    }
}
