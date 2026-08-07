// SPDX-License-Identifier: MIT

//! shardstore — a key-sharding router over N independent `kvtree` stores, the
//! multi-core WRITE-parallelism answer for the data layer.
//!
//! A single `kvtree` is a copy-on-write B-tree with a **single-writer** commit
//! path: correct and crash-safe, but one durable writer at a time, so it cannot
//! absorb multi-core write throughput on its own. The classic scale-out is to
//! **shard by key** across N independent `kvtree` instances — each its own
//! single-writer domain backed by its own file — so writes to *different* shards
//! proceed fully in parallel with no lock between them. This module is that
//! router: a stable key hash picks the owning shard; `put`/`get`/`delete`
//! delegate to it. It is a *stateless* router — the shard array is immutable
//! after `init` — so it adds **no** cross-shard coordination of its own.
//!
//! ## Threading contract (exactly what this guarantees — and what it does not)
//!
//! Each shard inherits `kvtree`'s contract verbatim: **one writer at a time per
//! shard**, with lockless MVCC readers. This router does not widen that:
//!
//! - Operations on **distinct** shards are independent — two threads writing
//!   keys that hash to different shards never contend (separate `kvtree.Db`
//!   state, separate files, no shared mutable router state). This is the whole
//!   point of sharding, and the design naturally encourages partitioning work
//!   by shard.
//! - Operations on the **same** shard are bounded by `kvtree`'s single-writer
//!   rule: the caller MUST serialize concurrent writers to the same shard. This
//!   router adds no latch to do that for you — `shardFor` is exposed precisely
//!   so a caller can partition work and route a dedicated thread per shard.
//! - **…and all of that is conditional on the injected `Storage`.** The router
//!   and the `Db`s above it hold no shared mutable state, but every operation
//!   ultimately lands in the backend, and two shards' operations meet there.
//!   Cross-shard parallelism is real only over a backend that is itself safe
//!   for concurrent operations on **distinct handles**. `FsStorage` is
//!   (per-handle `pread`/`pwrite`; its `files` array is written only by
//!   `open`/`close`, which the caller does single-threaded); `SimStorage` is
//!   **not** (plain `StringHashMapUnmanaged`/`ArrayListUnmanaged` plus a
//!   non-atomic `ops_seen`). This precondition used to be unstated, and the
//!   module's own headline test violated it — see `Options.storage_concurrency`,
//!   which now makes it part of the API and enforces it.
//!
//! We do NOT claim more safety than `kvtree` provides. `kvtree` is
//! `single_owner` (one thread/loop owns a `Db`'s mutation state, lock-free); a
//! stateless key-router over N of them is therefore per-shard single-owner and
//! cross-shard parallel — no more, no less.
//!
//! ## `n_shards` is immutable for the life of the data
//!
//! Routing reduces the key hash modulo `n_shards`, so changing the shard count
//! re-routes essentially every key: the data is still on disk but the router
//! looks for it in the wrong file. That used to be silent — reopening four
//! shards' worth of data with `n_shards = 8` simply read empty for ~half the
//! keys. A tiny `"<name_prefix>.manifest"` file now records the shard count at
//! creation and a mismatched reopen fails with `error.ShardCountMismatch`.
//! Incremental resharding (Redis Cluster's 16 384 fixed hash slots, or a
//! consistent-hashing ring) is a design this module does **not** implement.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kvtree = @import("kvtree");

pub const meta = .{
    .platform = .any, // all I/O via kvtree → kv's Storage seam (std.Io)
    .role = .both, // sharded read+write store router
    // Per-shard single-owner (kvtree's contract), cross-shard parallel. The
    // router itself holds only immutable-after-init state; it adds no locking.
    // The caller serializes same-shard writers (the sharded design encourages
    // partitioning work by shard so this falls out naturally).
    .concurrency = .single_owner,
    .model_after = "consistent key-sharding over N single-writer stores (Redis Cluster / Dynamo partitioning idea)",
    .deps = .{"kvtree"},
};

// ── re-exports: the storage seam, so consumers wire a backend without also
// importing `kvtree`/`kv` directly ───────────────────────────────────────────

pub const Storage = kvtree.Storage;
pub const FsStorage = kvtree.FsStorage;
pub const SimStorage = kvtree.SimStorage;
/// The per-shard store type, exposed for advanced per-shard use (transactions,
/// snapshots, ordered cursors) via `shardAt`/`shardFor`.
pub const Db = kvtree.Db;

// ── errors ───────────────────────────────────────────────────────────────────

pub const InitError = kvtree.OpenError || Allocator.Error || error{
    /// `options.n_shards` was 0 — a store needs at least one shard.
    InvalidShardCount,
    /// The generated shard file name did not fit the format buffer (prefix +
    /// suffix too long).
    ShardNameTooLong,
    /// The store's manifest records a different `n_shards` than this `init`
    /// asked for. Routing is `hash % n_shards`, so opening with the wrong count
    /// would look for existing keys in the wrong shard files and silently read
    /// empty for most of them. Reopen with the recorded count.
    ShardCountMismatch,
    /// The manifest file exists but is not a shardstore manifest (bad magic) or
    /// is shorter than one record — a torn creation, or a name collision with
    /// some other file. Refused rather than overwritten.
    CorruptManifest,
};

/// Raised by a routed operation on a `.single_thread` store called from a
/// thread other than its owner. See `Options.storage_concurrency`.
pub const OwnerError = error{NotOwningThread};

/// Errors from a routed write (`put`/`delete`) — `kvtree`'s, plus the
/// owning-thread check.
pub const WriteError = kvtree.CommitError || Allocator.Error || OwnerError;
/// Errors from a routed read (`get`) — `kvtree`'s, plus the owning-thread
/// check.
pub const GetError = kvtree.GetError || OwnerError;

// ── Options ──────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Number of independent shards. Each becomes its own `kvtree` file and its
    /// own single-writer domain. A power of two lets routing use a cheap mask
    /// instead of a modulo, but any `n_shards >= 1` is accepted.
    n_shards: usize,
    /// Shard files are named `"<name_prefix>-<index:0>5><name_suffix>"` and
    /// resolved by the injected `Storage` (for `FsStorage`, relative to its
    /// `dir`). E.g. defaults yield `shard-00000.kvt` … `shard-0000N.kvt`.
    name_prefix: []const u8 = "shard",
    name_suffix: []const u8 = ".kvt",
    /// What the injected `Storage` guarantees about **concurrent** use. This is
    /// the module's central precondition, not a tuning knob: cross-shard write
    /// parallelism is a property of the composition, and the composition is only
    /// as parallel as the backend underneath it.
    storage_concurrency: StorageConcurrency = .single_thread,
};

/// The concurrency contract of the injected `Storage`. Defaults to the
/// conservative value: declaring `.parallel_per_handle` for a backend that is
/// not is silent undefined behaviour, while declaring `.single_thread` for one
/// that is costs only a lost opportunity.
pub const StorageConcurrency = enum {
    /// The backend is **not** safe for concurrent use — e.g. `SimStorage`,
    /// whose `files`/`log` are plain unmanaged containers and whose `ops_seen`
    /// is a non-atomic counter. The whole `Store` is then a single-thread
    /// object, and that is **enforced**: `put`/`get`/`delete` from any thread
    /// other than the owner return `error.NotOwningThread` rather than
    /// corrupting the backend. (`init` records the calling thread as the owner;
    /// `adoptOwner` hands the store to another thread explicitly.)
    single_thread,
    /// The backend is safe for concurrent operations on **distinct handles**,
    /// each shard having its own — e.g. `FsStorage`, where every operation is a
    /// positional `pread`/`pwrite` on its own `std.Io.File` and the only shared
    /// field, the handle table, is mutated solely by `open`/`close`. Routed
    /// operations then take no latch and no owner check, and threads working on
    /// distinct shards genuinely run in parallel. **The caller still serializes
    /// writers to the same shard** (`kvtree`'s single-writer rule) — partition
    /// work with `shardFor`/`shardAt`.
    parallel_per_handle,
};

// ── manifest: the shard count is part of the on-disk identity ────────────────

const manifest_magic = "SHRDSTOR";
/// magic (8) + n_shards as u64 LE (8).
const manifest_len = manifest_magic.len + 8;

/// A per-thread token that is unique to the calling thread and costs a TLS
/// address computation rather than a `gettid` syscall: the address of a
/// `threadlocal` is distinct in every thread and stable within one.
threadlocal var thread_marker: u8 = 0;

fn currentThreadToken() usize {
    return @intFromPtr(&thread_marker);
}

// ── Store ────────────────────────────────────────────────────────────────────

pub const Store = struct {
    gpa: Allocator,
    /// One independent single-writer store per shard. Immutable slice after
    /// `init` (never resized), so concurrent access to *distinct* elements is
    /// data-race-free; each element's mutation is bounded by `kvtree`'s rule.
    shards: []Db,
    n_shards: usize,
    /// `n_shards - 1` when `n_shards` is a power of two (routing masks), else
    /// null (routing uses modulo).
    mask: ?u64,
    /// The declared concurrency of the injected backend (`Options`).
    storage_concurrency: StorageConcurrency,
    /// Owning-thread token, meaningful only for `.single_thread` stores.
    owner: usize,
    /// Kept only to close `lock_file` in `deinit` — the `Storage` value
    /// itself is just a `{ctx, vtable}` pair, cheap to hold onto.
    store: Storage,
    /// Handle of the held `"<name_prefix>.lock"` sidecar — see `acquireLock`.
    lock_file: Storage.Handle,

    /// Open (or create) `options.n_shards` independent `kvtree` shards over the
    /// injected `Storage`. On any per-shard open failure, already-opened shards
    /// are closed and nothing leaks.
    ///
    /// A fresh store writes a `"<name_prefix>.manifest"` record; an existing one
    /// is checked against it and `error.ShardCountMismatch` is returned if the
    /// counts differ (see the module doc comment).
    pub fn init(gpa: Allocator, store: Storage, options: Options) InitError!Store {
        if (options.n_shards == 0) return error.InvalidShardCount;

        try checkManifest(store, options);

        // ONE exclusive lock for the whole store (not one per shard — see
        // `acquireLock`'s doc comment for why).
        const lock_file = try acquireLock(store, options);
        errdefer store.close(lock_file);

        const shards = try gpa.alloc(Db, options.n_shards);
        errdefer gpa.free(shards);

        var opened: usize = 0;
        // Close the shards opened so far if a later open fails.
        errdefer for (shards[0..opened]) |*d| d.close();

        while (opened < options.n_shards) : (opened += 1) {
            var buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(
                &buf,
                "{s}-{d:0>5}{s}",
                .{ options.name_prefix, opened, options.name_suffix },
            ) catch return error.ShardNameTooLong;
            // `.lock = .none`: exclusion is already held once, above, for the
            // whole store — see `acquireLock`.
            shards[opened] = try Db.open(gpa, store, path, .{ .lock = .none });
        }

        return .{
            .gpa = gpa,
            .shards = shards,
            .n_shards = options.n_shards,
            .mask = if (std.math.isPowerOfTwo(options.n_shards))
                @as(u64, options.n_shards - 1)
            else
                null,
            .storage_concurrency = options.storage_concurrency,
            .owner = currentThreadToken(),
            .store = store,
            .lock_file = lock_file,
        };
    }

    /// Cross-process/cross-instance exclusion for the WHOLE store — one lock
    /// covering every shard, rather than each shard taking its own via
    /// `kvtree.Db.open`'s default `Options.lock == .exclusive`. Per-shard
    /// locking would work too (it is `kvtree`'s default), but it doubles the
    /// handle count per shard (data file + lock sidecar), and `FsStorage`'s
    /// handle table is small and fixed (`max_handles == 4`, sized for one
    /// `kv`/`kvtree` store's own data+lock+compaction-temp needs) — four
    /// shards alone would then need 8 concurrently open handles over one
    /// `FsStorage` and fail with `error.Unexpected`. One lock at the `Store`
    /// level gives the identical guarantee this module's F2 finding asked
    /// for — a second `Store` over the same paths gets `error.Locked` with
    /// nothing touched — at the cost of one handle instead of N.
    fn acquireLock(store: Storage, options: Options) InitError!Storage.Handle {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}.lock", .{options.name_prefix}) catch
            return error.ShardNameTooLong;

        const h = try store.open(path, .open_or_create);
        errdefer store.close(h);
        if (!try store.tryLockExclusive(h)) return error.Locked;
        return h;
    }

    /// Create-or-verify the shard-count manifest. Runs **before** any shard is
    /// opened, so a mismatched reopen touches nothing, and the manifest handle
    /// is closed again before the shard loop — `FsStorage` has a small fixed
    /// handle table and the manifest must not spend one of its slots.
    fn checkManifest(store: Storage, options: Options) InitError!void {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}.manifest", .{options.name_prefix}) catch
            return error.ShardNameTooLong;

        const h = try store.open(path, .open_or_create);
        defer store.close(h);

        const size = try store.size(h);
        if (size == 0) {
            // Fresh store: stamp the count. (A pre-existing store created before
            // manifests were written has no manifest either, so it is adopted
            // with whatever count this call passes — documented in SPEC.md.)
            var rec: [manifest_len]u8 = undefined;
            @memcpy(rec[0..manifest_magic.len], manifest_magic);
            std.mem.writeInt(u64, rec[manifest_magic.len..][0..8], options.n_shards, .little);
            try store.writeAll(h, &rec, 0);
            try store.sync(h);
            try store.syncDir();
            return;
        }
        if (size < manifest_len) return error.CorruptManifest;

        var rec: [manifest_len]u8 = undefined;
        store.preadFull(h, &rec, 0) catch |e| switch (e) {
            error.Corrupt => return error.CorruptManifest,
            else => |other| return other,
        };
        if (!std.mem.eql(u8, rec[0..manifest_magic.len], manifest_magic)) return error.CorruptManifest;
        const recorded = std.mem.readInt(u64, rec[manifest_magic.len..][0..8], .little);
        if (recorded != options.n_shards) return error.ShardCountMismatch;
    }

    /// Transfer ownership of a `.single_thread` store to the calling thread.
    /// The previous owner must be done with it (this is a hand-off, not a lock);
    /// the point is that a store built on the main thread and then run by one
    /// worker thread is legitimate, while two threads at once is not. No-op for
    /// a `.parallel_per_handle` store, which has no single owner.
    pub fn adoptOwner(self: *Store) void {
        self.owner = currentThreadToken();
    }

    /// The owning-thread check for `.single_thread` stores. Two loads and a
    /// compare; no syscall, no atomics, and deterministic — a foreign thread is
    /// rejected whether or not it happens to overlap with the owner, which is
    /// what makes it testable at all.
    inline fn checkOwner(self: *const Store) OwnerError!void {
        if (self.storage_concurrency == .single_thread and currentThreadToken() != self.owner)
            return error.NotOwningThread;
    }

    /// Close every shard, release the store-wide lock, and free the shard
    /// array. No leaks.
    pub fn deinit(self: *Store) void {
        for (self.shards) |*d| d.close();
        self.store.close(self.lock_file);
        self.gpa.free(self.shards);
        self.* = undefined;
    }

    /// The shard index that owns `key`: a stable, dep-free `Wyhash` of the key
    /// reduced to `[0, n_shards)`. Deterministic — the same key always routes to
    /// the same shard, within a run and across `init`s with the same `n_shards`.
    pub fn shardFor(self: *const Store, key: []const u8) usize {
        const h = std.hash.Wyhash.hash(0, key);
        if (self.mask) |m| return @intCast(h & m);
        return @intCast(h % @as(u64, self.n_shards));
    }

    /// The owning shard for `key`, for advanced per-shard use — multi-key ACID
    /// transactions, MVCC snapshots and ordered cursors are all per-shard (a
    /// transaction spanning shards is NOT atomic; keep atomic groups on one
    /// shard by choosing keys that route together, or use one shard).
    pub fn shard(self: *Store, key: []const u8) *Db {
        return &self.shards[self.shardFor(key)];
    }

    /// The shard at `index` (`index < n_shards`), e.g. to drive one dedicated
    /// writer thread per shard.
    pub fn shardAt(self: *Store, index: usize) *Db {
        return &self.shards[index];
    }

    // ── routed operations ────────────────────────────────────────────────────

    /// Autocommit put, routed to the owning shard. Concurrency: safe alongside
    /// puts to *other* shards; same-shard writers must be serialized by the
    /// caller (kvtree's single-writer rule — this router adds no latch).
    pub fn put(self: *Store, key: []const u8, val: []const u8) WriteError!void {
        try self.checkOwner();
        return self.shards[self.shardFor(key)].put(key, val);
    }

    /// Look up `key` in its owning shard's newest committed version. Caller
    /// frees the returned slice with `gpa`.
    pub fn get(self: *Store, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        try self.checkOwner();
        return self.shards[self.shardFor(key)].get(gpa, key);
    }

    /// Autocommit delete, routed to the owning shard. Same concurrency contract
    /// as `put`.
    pub fn delete(self: *Store, key: []const u8) WriteError!void {
        try self.checkOwner();
        return self.shards[self.shardFor(key)].del(key);
    }
};

// ── tests ─────────────────────────────────────────────────────────────────────

test {
    std.testing.refAllDecls(@This());
}

const testing = std.testing;

test "smoke: init opens N shards, empty, closes cleanly (SimStorage)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    try testing.expectEqual(@as(usize, 4), store.n_shards);
    try testing.expect(store.mask != null); // 4 is a power of two
    const got = try store.get(testing.allocator, "absent");
    try testing.expect(got == null);
}

test "init rejects zero shards" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    try testing.expectError(error.InvalidShardCount, Store.init(testing.allocator, sim.storage(), .{ .n_shards = 0 }));
}

test "routing is deterministic and stable across store instances" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    var s1 = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 });

    // Same key → same shard, repeatedly.
    const idx = s1.shardFor("stable-key");
    try testing.expectEqual(idx, s1.shardFor("stable-key"));
    try testing.expectEqual(idx, s1.shardFor("stable-key"));

    // shardFor is a pure function of the key (no I/O), so capture s1's
    // answers before closing it — a second Store now holds an exclusive
    // store-wide lock (see `Store.acquireLock`), so a second live Store over
    // the SAME paths while the first is still open is refused, not merely
    // untested; that used to be the F2 finding (kvtree.Db.open discarded its
    // locking Options entirely). Close s1 first, exactly like any real
    // sequential reopen would.
    var buf: [32]u8 = undefined;
    var want: [200]usize = undefined;
    for (&want, 0..) |*w, n| {
        const k = try std.fmt.bufPrint(&buf, "k-{d}", .{n});
        w.* = s1.shardFor(k);
    }
    s1.deinit();

    // A second store with the same n_shards routes identically (pure hash).
    var s2 = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 });
    defer s2.deinit();
    for (want, 0..) |w, n| {
        const k = try std.fmt.bufPrint(&buf, "k-{d}", .{n});
        try testing.expectEqual(w, s2.shardFor(k));
        try testing.expect(s2.shardFor(k) < 8);
    }
}

test "keys distribute across shards (histogram sanity — hits >1 shard, all shards)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    const n_shards = 8;
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = n_shards });
    defer store.deinit();

    var hist = [_]usize{0} ** n_shards;
    var buf: [32]u8 = undefined;
    for (0..2000) |n| {
        const k = try std.fmt.bufPrint(&buf, "user:{d}", .{n});
        hist[store.shardFor(k)] += 1;
    }
    // Every shard should get a healthy share (expected ~250 each); assert none
    // is empty (spread hits every shard, definitely >1).
    var nonempty: usize = 0;
    for (hist) |c| {
        if (c > 0) nonempty += 1;
        try testing.expect(c > 50); // far from the 250 mean; catches a stuck router
    }
    try testing.expectEqual(@as(usize, n_shards), nonempty);
}

test "round-trip: put→get across shards, delete, values survive reads on other shards" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    var kbuf: [32]u8 = undefined;
    var vbuf: [32]u8 = undefined;
    // Write a spread of keys (they fan out across all 4 shards).
    for (0..400) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
        const v = try std.fmt.bufPrint(&vbuf, "val-{d}", .{n});
        try store.put(k, v);
    }
    // Read every one back through the router.
    for (0..400) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "val-{d}", .{n});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
    // Delete half; the surviving half (which spans other shards) is untouched.
    for (0..400) |n| {
        if (n % 2 == 0) {
            const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
            try store.delete(k);
        }
    }
    for (0..400) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        if (n % 2 == 0) {
            try testing.expect(got == null);
        } else {
            const want = try std.fmt.bufPrint(&vbuf, "val-{d}", .{n});
            try testing.expectEqualStrings(want, got.?);
        }
    }
}

// ── the headline claim, on a backend that can actually carry it ──────────────
//
// WAVE-2 F1. This test used to drive four threads through ONE `SimStorage`,
// whose state is plain `StringHashMapUnmanaged`/`ArrayListUnmanaged` fields plus
// a NON-ATOMIC `ops_seen`. The audit measured a lost increment (serial 33006 vs
// parallel 33005): the test certifying "no contention" was itself a data race,
// free to pass or to corrupt at the scheduler's whim, and the claim had never
// been exercised on a backend that could support it.
//
// The replacement changes three things.
//  1. It runs over `FsStorage` in a tmpDir — positional per-handle `pread`/
//     `pwrite`, and the one shared field (the handle table) is written only by
//     `open`/`close`, which happen single-threaded in `init`/`deinit`. The
//     backend is declared `.parallel_per_handle`, which is what the module now
//     requires before it will let more than one thread near a `Store`.
//  2. It does not merely check that the data is correct afterwards. Correct
//     data is exactly what a fully SERIALIZED run would also produce, so that
//     assertion alone cannot tell parallelism from its absence — which is how
//     the original claim survived unexamined. A `Storage` shim instead
//     rendezvouses the first backend write of each thread: the barrier opens
//     only when all `n_shards` threads are inside the backend AT THE SAME
//     TIME, on `n_shards` distinct shards, and every arriving thread blocks
//     until then. Put a latch back in the routed path, or any shared mutable
//     state that forces ordering, and the barrier is never met: the shim
//     gives up, sets `timed_out`, and the test fails. That is a deterministic
//     consequence of serialization, not a race we hope to catch in the act.
//     `n_shards` is 3, not 4 — `FsStorage.max_handles == 4` (kv module) plus
//     the one store-wide lock handle `Store.init` now holds for cross-process
//     exclusion (the F2 fix) leaves room for exactly 3 concurrently open
//     shards; see the test itself.
//  3. Three rounds, each re-arming the barrier and rewriting every key, with a
//     full exact-value read-back of all the keys as the correctness oracle —
//     one lost or torn write is one wrong value — under the leak-checking
//     `testing.allocator`. The suite also runs in ReleaseFast, so the same
//     assertions are made against optimized code.

/// A pass-through `Storage` that can prove N threads are simultaneously inside
/// the backend. Only `writeAll` participates; everything else delegates.
const Rendezvous = struct {
    inner: Storage,
    want: u32,
    armed: std.atomic.Value(bool) = .init(false),
    arrived: std.atomic.Value(u32) = .init(0),
    met: std.atomic.Value(bool) = .init(false),
    /// Set when a thread waited out the whole budget without the barrier
    /// opening — i.e. the writes were serialized.
    timed_out: std.atomic.Value(bool) = .init(false),

    /// Yields, so waiting is scheduler-friendly rather than a busy spin; the
    /// budget only ever elapses in the failure case.
    const spin_budget = 400_000;

    fn storage(self: *Rendezvous) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn cast(ctx: *anyopaque) *Rendezvous {
        return @ptrCast(@alignCast(ctx));
    }

    fn arm(self: *Rendezvous) void {
        self.arrived.store(0, .release);
        self.met.store(false, .release);
        self.armed.store(true, .release);
    }

    fn disarm(self: *Rendezvous) void {
        self.armed.store(false, .release);
        self.met.store(true, .release);
    }

    fn meet(self: *Rendezvous) void {
        if (!self.armed.load(.acquire)) return;
        if (self.met.load(.acquire)) return;
        // Each caller increments exactly once and then blocks, so the barrier
        // can only open when `want` DISTINCT threads are inside this function.
        if (self.arrived.fetchAdd(1, .acq_rel) + 1 >= self.want) {
            self.met.store(true, .release);
            return;
        }
        var spins: usize = 0;
        while (!self.met.load(.acquire)) : (spins += 1) {
            if (spins >= spin_budget) {
                self.timed_out.store(true, .release);
                self.met.store(true, .release); // let any peers out; the test fails
                return;
            }
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
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
        .tryLockExclusive = vTryLockExclusive,
    };

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
        self.meet();
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
    fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
};

test "multi-core write parallelism: three writers provably inside the backend at once (FsStorage)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 3, not 4: `FsStorage.max_handles == 4` (kv module) has zero headroom
    // beyond exactly `n_shards` data-file handles, and `Store.init` now also
    // holds one store-wide lock handle for the whole store's lifetime (the
    // F2 fix) — 3 shard handles + 1 lock handle == 4 fits exactly; 4 shards
    // would need 5 and fail with `error.Unexpected` from `FsStorage.vOpen`.
    const n_shards = 3;
    var fs = FsStorage.init(testing.io, tmp.dir);
    var rv = Rendezvous{ .inner = fs.storage(), .want = n_shards };

    var store = try Store.init(testing.allocator, rv.storage(), .{
        .n_shards = n_shards,
        .storage_concurrency = .parallel_per_handle,
    });
    defer store.deinit();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Bucket a pool of keys by their owning shard, so each thread's key set
    // routes only to its own shard (distinct shards ⇒ no cross-thread contention).
    var buckets: [n_shards]std.ArrayList([]const u8) = undefined;
    for (&buckets) |*b| b.* = .empty;
    // Every `put` here is a real `kvtree` COW commit ending in an `fsync`, so
    // the key count is a wall-clock budget, not a coverage knob: the barrier
    // needs one write per thread and the oracle needs every key checked.
    const total_keys = 400;
    for (0..total_keys) |n| {
        const k = try std.fmt.allocPrint(a, "item-{d}", .{n});
        try buckets[store.shardFor(k)].append(a, k);
    }
    // A thread with no keys would never reach the barrier and would time it out
    // for a reason that has nothing to do with parallelism.
    for (buckets) |b| try testing.expect(b.items.len > 0);

    const Worker = struct {
        store: *Store,
        keys: []const []const u8,
        round: usize = 0,
        err: ?anyerror = null,

        fn run(w: *@This()) void {
            var vbuf: [48]u8 = undefined;
            for (w.keys) |k| {
                const v = std.fmt.bufPrint(&vbuf, "V{d}:{s}", .{ w.round, k }) catch {
                    w.err = error.Format;
                    return;
                };
                w.store.put(k, v) catch |e| {
                    w.err = e;
                    return;
                };
            }
        }
    };

    const rounds = 3;
    for (0..rounds) |round| {
        var workers: [n_shards]Worker = undefined;
        for (&workers, 0..) |*w, i| w.* = .{ .store = &store, .keys = buckets[i].items, .round = round };

        rv.arm();
        var threads: [n_shards]std.Thread = undefined;
        for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{&workers[i]});
        for (&threads) |t| t.join();

        // No worker hit an error.
        for (workers) |w| try testing.expect(w.err == null);
        // THE CLAIM ITSELF: all `n_shards` writers were inside the backend
        // together, on `n_shards` distinct shards. This is what goes red if
        // the routed path ever serializes again.
        try testing.expect(!rv.timed_out.load(.acquire));
        try testing.expect(rv.met.load(.acquire));
    }
    rv.disarm();

    // Every write landed and reads back correctly (single-threaded verify): the
    // last round's value, for all 4000 keys, byte for byte.
    var vbuf: [48]u8 = undefined;
    for (0..total_keys) |n| {
        var kbuf: [32]u8 = undefined;
        const k = try std.fmt.bufPrint(&kbuf, "item-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "V{d}:{s}", .{ rounds - 1, k });
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
}

// The other half of F1: the shape that produced the finding — several threads
// through one `SimStorage` — is now REJECTED rather than silently undefined.
// This is the deterministic guard. A foreign thread is refused whether or not it
// happens to overlap with the owner, so unlike a concurrency test it cannot pass
// by luck; rewrite the parallelism test back onto `SimStorage` and it stops
// being UB and starts being a hard error.
test "single_thread backend: a routed call from a foreign thread is refused, not raced" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    // `.single_thread` is the DEFAULT — the unsafe combination is the one you
    // have to ask for, not the one you get by forgetting.
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    try store.put("owned", "ok"); // the owning thread is fine

    const Probe = struct {
        store: *Store,
        put_res: WriteError!void = {},
        get_res: GetError!?[]u8 = null,
        del_res: WriteError!void = {},

        fn run(p: *@This()) void {
            p.put_res = p.store.put("foreign", "x");
            p.get_res = p.store.get(testing.allocator, "owned");
            p.del_res = p.store.delete("owned");
        }
    };
    var probe = Probe{ .store = &store };
    const t = try std.Thread.spawn(.{}, Probe.run, .{&probe});
    t.join();

    try testing.expectError(error.NotOwningThread, probe.put_res);
    try testing.expectError(error.NotOwningThread, probe.get_res);
    try testing.expectError(error.NotOwningThread, probe.del_res);

    // Nothing the foreign thread attempted reached the backend.
    const gone = try store.get(testing.allocator, "foreign");
    try testing.expect(gone == null);
    const survived = try store.get(testing.allocator, "owned");
    defer if (survived) |g| testing.allocator.free(g);
    try testing.expectEqualStrings("ok", survived.?);
}

test "single_thread backend: ownership can be handed over explicitly" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 });
    defer store.deinit();

    const Runner = struct {
        store: *Store,
        err: ?anyerror = null,

        fn run(r: *@This()) void {
            r.store.adoptOwner(); // explicit hand-off: the old owner is done
            r.store.put("handed", "over") catch |e| {
                r.err = e;
            };
        }
    };
    var runner = Runner{ .store = &store };
    const t = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    t.join();
    try testing.expect(runner.err == null);

    // The main thread is no longer the owner and is now the one refused.
    try testing.expectError(error.NotOwningThread, store.put("nope", "x"));
    store.adoptOwner();
    const got = try store.get(testing.allocator, "handed");
    defer if (got) |g| testing.allocator.free(g);
    try testing.expectEqualStrings("over", got.?);
}

test "persistence: data survives reopening the shards (FsStorage over a tmp dir)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 3, not 4: see the multi-core-parallelism test above — `Store.init` now
    // holds one store-wide lock handle for the whole store's lifetime (the
    // F2 fix), and `FsStorage.max_handles == 4` (kv module) has no headroom
    // beyond exactly `n_shards` data-file handles + that one lock handle.
    {
        var fs = FsStorage.init(testing.io, tmp.dir);
        var store = try Store.init(testing.allocator, fs.storage(), .{ .n_shards = 3 });
        defer store.deinit();
        var kbuf: [32]u8 = undefined;
        var vbuf: [32]u8 = undefined;
        for (0..300) |n| {
            const k = try std.fmt.bufPrint(&kbuf, "persist-{d}", .{n});
            const v = try std.fmt.bufPrint(&vbuf, "durable-{d}", .{n});
            try store.put(k, v);
        }
    }

    // Reopen a fresh Store over the SAME dir/paths — durability delegates to
    // kvtree; the same key routes to the same shard file it was written to.
    var fs2 = FsStorage.init(testing.io, tmp.dir);
    var store2 = try Store.init(testing.allocator, fs2.storage(), .{ .n_shards = 3 });
    defer store2.deinit();
    var kbuf: [32]u8 = undefined;
    var vbuf: [32]u8 = undefined;
    for (0..300) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "persist-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "durable-{d}", .{n});
        const got = try store2.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
}

// WAVE-2 F3. Routing is `hash % n_shards`, so a reopen with a different shard
// count sends every key to the wrong file. Before the manifest this was SILENT:
// the data was still on disk, the router just looked elsewhere, and ~half the
// keys read back as absent — indistinguishable from "never written", after an
// ordinary operational mistake (an operator scaling shards in a config file).
// Fail closed instead: the count is part of the store's on-disk identity.
test "reopen with a different n_shards FAILS instead of silently reading empty" {
    // `SimStorage` deliberately, not `FsStorage`: the latter's handle table
    // holds only 4 files, so a mismatched reopen with MORE shards happens to die
    // on `error.Unexpected` — an accident of the backend that masks the real
    // defect. Growing AND shrinking the count must both be refused on their own
    // merits, and only an unbounded backend shows that.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    {
        var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
        defer store.deinit();
        var kbuf: [32]u8 = undefined;
        for (0..200) |n| {
            const k = try std.fmt.bufPrint(&kbuf, "reshard-{d}", .{n});
            try store.put(k, "v");
        }
    }

    // Without the manifest check both of these SUCCEED and then read empty for
    // most of the 200 keys (measured: 8 shards → 98/200 found, 2 shards →
    // 88/200 found) — a silent partial data loss after an ordinary
    // config-file mistake. Fail closed instead.
    try testing.expectError(
        error.ShardCountMismatch,
        Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 }),
    );
    try testing.expectError(
        error.ShardCountMismatch,
        Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 }),
    );

    // The recorded count still opens, and every key is still there.
    var ok = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer ok.deinit();
    var kbuf: [32]u8 = undefined;
    for (0..200) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "reshard-{d}", .{n});
        const got = try ok.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expectEqualStrings("v", got.?);
    }
}

test "manifest: a foreign/corrupt file under the manifest name is refused, not overwritten" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    // Something else already owns "shard.manifest": neither our magic nor our
    // length. Stamping over it would destroy a stranger's file and invent an
    // identity for data we never wrote.
    const store = sim.storage();
    const h = try store.open("shard.manifest", .open_or_create);
    try store.writeAll(h, "not a shardstore manifest at all", 0);
    store.close(h);

    try testing.expectError(
        error.CorruptManifest,
        Store.init(testing.allocator, store, .{ .n_shards = 4 }),
    );

    // A torn/short record is refused too, rather than being treated as fresh.
    const h2 = try store.open("short.manifest", .open_or_create);
    try store.writeAll(h2, "SHRD", 0);
    store.close(h2);
    try testing.expectError(
        error.CorruptManifest,
        Store.init(testing.allocator, store, .{ .n_shards = 4, .name_prefix = "short" }),
    );
}

test "non-power-of-two shard count uses modulo routing and round-trips" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 5 });
    defer store.deinit();
    try testing.expect(store.mask == null); // 5 is not a power of two → modulo

    var kbuf: [32]u8 = undefined;
    for (0..100) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "m-{d}", .{n});
        try testing.expect(store.shardFor(k) < 5);
        try store.put(k, "x");
    }
    for (0..100) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "m-{d}", .{n});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expectEqualStrings("x", got.?);
    }
}
