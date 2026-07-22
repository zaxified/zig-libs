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
//!
//! We do NOT claim more safety than `kvtree` provides. `kvtree` is
//! `single_owner` (one thread/loop owns a `Db`'s mutation state, lock-free); a
//! stateless key-router over N of them is therefore per-shard single-owner and
//! cross-shard parallel — no more, no less.

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
};

/// Errors from a routed write (`put`/`delete`) — exactly `kvtree`'s.
pub const WriteError = kvtree.CommitError || Allocator.Error;
/// Errors from a routed read (`get`) — exactly `kvtree`'s.
pub const GetError = kvtree.GetError;

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
};

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

    /// Open (or create) `options.n_shards` independent `kvtree` shards over the
    /// injected `Storage`. On any per-shard open failure, already-opened shards
    /// are closed and nothing leaks.
    pub fn init(gpa: Allocator, store: Storage, options: Options) InitError!Store {
        if (options.n_shards == 0) return error.InvalidShardCount;

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
            shards[opened] = try Db.open(gpa, store, path, .{});
        }

        return .{
            .gpa = gpa,
            .shards = shards,
            .n_shards = options.n_shards,
            .mask = if (std.math.isPowerOfTwo(options.n_shards))
                @as(u64, options.n_shards - 1)
            else
                null,
        };
    }

    /// Close every shard and free the shard array. No leaks.
    pub fn deinit(self: *Store) void {
        for (self.shards) |*d| d.close();
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
        return self.shards[self.shardFor(key)].put(key, val);
    }

    /// Look up `key` in its owning shard's newest committed version. Caller
    /// frees the returned slice with `gpa`.
    pub fn get(self: *Store, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        return self.shards[self.shardFor(key)].get(gpa, key);
    }

    /// Autocommit delete, routed to the owning shard. Same concurrency contract
    /// as `put`.
    pub fn delete(self: *Store, key: []const u8) WriteError!void {
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
    defer s1.deinit();

    // Same key → same shard, repeatedly.
    const idx = s1.shardFor("stable-key");
    try testing.expectEqual(idx, s1.shardFor("stable-key"));
    try testing.expectEqual(idx, s1.shardFor("stable-key"));

    // A second store with the same n_shards routes identically (pure hash).
    var s2 = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 });
    defer s2.deinit();
    var buf: [32]u8 = undefined;
    for (0..200) |n| {
        const k = try std.fmt.bufPrint(&buf, "k-{d}", .{n});
        try testing.expectEqual(s1.shardFor(k), s2.shardFor(k));
        try testing.expect(s1.shardFor(k) < 8);
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

// The headline test: one writer thread per shard, each writing a disjoint key
// range that routes ONLY to its own shard, concurrently. Independent shards do
// not contend; all writes must land and read back with no corruption. (Per the
// contract, same-shard access stays single-threaded — each thread owns exactly
// one shard.)
test "multi-core write parallelism: one writer thread per shard, no contention" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    const n_shards = 4;
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = n_shards });
    defer store.deinit();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Bucket a pool of keys by their owning shard, so each thread's key set
    // routes only to its own shard (distinct shards ⇒ no cross-thread contention).
    var buckets: [n_shards]std.ArrayList([]const u8) = undefined;
    for (&buckets) |*b| b.* = .empty;
    const total_keys = 4000;
    for (0..total_keys) |n| {
        const k = try std.fmt.allocPrint(a, "item-{d}", .{n});
        try buckets[store.shardFor(k)].append(a, k);
    }

    const Worker = struct {
        store: *Store,
        keys: []const []const u8,
        err: ?anyerror = null,

        fn run(w: *@This()) void {
            var vbuf: [48]u8 = undefined;
            for (w.keys) |k| {
                const v = std.fmt.bufPrint(&vbuf, "V:{s}", .{k}) catch {
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

    var workers: [n_shards]Worker = undefined;
    for (&workers, 0..) |*w, i| w.* = .{ .store = &store, .keys = buckets[i].items };

    var threads: [n_shards]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{&workers[i]});
    for (&threads) |t| t.join();

    // No worker hit an error.
    for (workers) |w| try testing.expect(w.err == null);

    // Every write landed and reads back correctly (single-threaded verify).
    var vbuf: [48]u8 = undefined;
    for (0..total_keys) |n| {
        var kbuf: [32]u8 = undefined;
        const k = try std.fmt.bufPrint(&kbuf, "item-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "V:{s}", .{k});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
}

test "persistence: data survives reopening the shards (FsStorage over a tmp dir)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var fs = FsStorage.init(testing.io, tmp.dir);
        var store = try Store.init(testing.allocator, fs.storage(), .{ .n_shards = 4 });
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
    var store2 = try Store.init(testing.allocator, fs2.storage(), .{ .n_shards = 4 });
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
