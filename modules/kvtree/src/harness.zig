// SPDX-License-Identifier: MIT

//! harness — the property/model-checker that will hold the Fable core to
//! account, plus its teeth. Mirrors `kv`'s VOPR + `df-elect`'s positive-control
//! pattern:
//!
//!   * a reference `Model` (a sorted map with independent MVCC snapshot clones)
//!     that defines the correct answer;
//!   * pure invariant checkers — sorted scans, snapshot isolation,
//!     serializability of committed transactions, and crash-recovery to a
//!     committed prefix;
//!   * a generic property engine (`runProperty`) that drives a store
//!     implementation and its reference `Model` in lockstep across randomized
//!     transaction/snapshot schedules and asserts the invariants;
//!   * a correct in-memory oracle `RefStore` the engine runs green today, and a
//!     deliberately-broken `BrokenRefStore` (snapshot reads ignore the pin —
//!     an MVCC isolation bug) the engine MUST catch. That broken control proves
//!     the checkers have teeth INDEPENDENT of whether the real B-tree core is
//!     filled in — exactly `df-elect`'s `BrokenAlwaysDf` role.
//!
//! The real `kvtree.Db` plugs into the SAME checkers via the gated
//! `dbPropertyRun` (bottom of file); because `Db.commit`/recovery route into
//! `core.zig`'s `@panic` stubs, those tests are gated behind
//! `gate.fable_core_implemented` and report SKIP until it flips.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Prng = @import("prng.zig").Prng;
const core = @import("core.zig");
const gate = @import("gate.zig");
const kv = @import("kv");
const kvtree = @import("root.zig");

/// A key/value observation (borrowed or arena-owned; never frees itself).
pub const Obs = struct { key: []const u8, val: []const u8 };

// ── the reference model: a sorted map with deep-cloneable snapshots ──────────

pub const Model = struct {
    a: Allocator, // an arena — bytes/list are never individually freed
    pairs: std.ArrayList(Obs) = .empty,

    pub fn init(a: Allocator) Model {
        return .{ .a = a };
    }

    fn find(self: *const Model, key: []const u8) struct { found: bool, index: usize } {
        var lo: usize = 0;
        var hi: usize = self.pairs.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, self.pairs.items[mid].key, key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return .{ .found = true, .index = mid },
            }
        }
        return .{ .found = false, .index = lo };
    }

    pub fn put(self: *Model, key: []const u8, val: []const u8) !void {
        const e = Obs{ .key = try self.a.dupe(u8, key), .val = try self.a.dupe(u8, val) };
        const f = self.find(key);
        if (f.found) self.pairs.items[f.index] = e else try self.pairs.insert(self.a, f.index, e);
    }

    pub fn del(self: *Model, key: []const u8) void {
        const f = self.find(key);
        if (f.found) _ = self.pairs.orderedRemove(f.index);
    }

    pub fn apply(self: *Model, changes: []const core.Change) !void {
        for (changes) |c| switch (c) {
            .put => |p| try self.put(p.key, p.val),
            .del => |k| self.del(k),
        };
    }

    /// Entries in ascending key order.
    pub fn entries(self: *const Model) []const Obs {
        return self.pairs.items;
    }

    /// Deep copy into `dst` (a fresh arena) — the basis of an MVCC snapshot.
    pub fn clone(self: *const Model, dst: Allocator) !Model {
        var m = Model.init(dst);
        for (self.pairs.items) |e| try m.put(e.key, e.val);
        return m;
    }
};

// ── invariant checkers (pure; the teeth) ─────────────────────────────────────

pub const CheckError = error{
    ScanNotSorted,
    SnapshotIsolationViolated,
    NotSerializable,
    RecoveredStateNotCommitted,
};

/// Ordered-scan invariant: keys strictly ascending, no dup.
pub fn checkSorted(obs: []const Obs) CheckError!void {
    var i: usize = 1;
    while (i < obs.len) : (i += 1) {
        if (!std.mem.lessThan(u8, obs[i - 1].key, obs[i].key)) return error.ScanNotSorted;
    }
}

fn entriesEqual(a: []const Obs, b: []const Obs) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x.key, y.key)) return false;
        if (!std.mem.eql(u8, x.val, y.val)) return false;
    }
    return true;
}

/// Snapshot-isolation invariant: a read under a pinned snapshot equals the
/// state as of the pin — it never observes a later commit or an uncommitted
/// write.
pub fn checkSnapshotIsolation(pinned: []const Obs, observed: []const Obs) CheckError!void {
    try checkSorted(observed);
    if (!entriesEqual(pinned, observed)) return error.SnapshotIsolationViolated;
}

/// Serializability invariant: applying the committed transactions in commit
/// order yields exactly the observed committed state.
pub fn checkSerializable(model: []const Obs, observed: []const Obs) CheckError!void {
    try checkSorted(observed);
    if (!entriesEqual(model, observed)) return error.NotSerializable;
}

/// Crash-recovery invariant: the recovered state equals SOME committed version
/// (the last commit, or an earlier one if the final commit was in flight at the
/// crash) — never a torn mix, never an uncommitted write.
pub fn checkRecoveredPrefix(committed: []const []const Obs, recovered: []const Obs) CheckError!void {
    try checkSorted(recovered);
    for (committed) |candidate| {
        if (entriesEqual(candidate, recovered)) return;
    }
    return error.RecoveredStateNotCommitted;
}

// ── in-memory stores: the correct oracle + the broken positive control ───────
//
// `RefStoreImpl(false)` is a correct MVCC store (snapshots are independent deep
// clones, unaffected by later commits). `RefStoreImpl(true)` plants ONE bug:
// snapshot reads return the CURRENT state, ignoring the pin — a textbook
// snapshot-isolation violation the checker must catch.

fn RefStoreImpl(comptime broken: bool) type {
    return struct {
        const Self = @This();
        gpa: Allocator,
        // Heap-allocated so its address is stable across the by-value return of
        // `init` (the Model's captured allocator points INTO this arena).
        cur_owner: *std.heap.ArenaAllocator,
        cur: Model,
        snaps: std.ArrayList(Snap) = .empty,
        next_id: u64 = 1,

        const Snap = struct { id: u64, owner: *std.heap.ArenaAllocator, model: Model };

        pub fn init(gpa: Allocator) !Self {
            const owner = try gpa.create(std.heap.ArenaAllocator);
            owner.* = std.heap.ArenaAllocator.init(gpa);
            const cur = Model.init(owner.allocator());
            return .{ .gpa = gpa, .cur_owner = owner, .cur = cur };
        }

        pub fn deinit(self: *Self) void {
            for (self.snaps.items) |s| {
                s.owner.deinit();
                self.gpa.destroy(s.owner);
            }
            self.snaps.deinit(self.gpa);
            self.cur_owner.deinit();
            self.gpa.destroy(self.cur_owner);
            self.* = undefined;
        }

        pub fn apply(self: *Self, changes: []const core.Change) !void {
            try self.cur.apply(changes);
        }

        pub fn snapshot(self: *Self) !u64 {
            const owner = try self.gpa.create(std.heap.ArenaAllocator);
            owner.* = std.heap.ArenaAllocator.init(self.gpa);
            const model = try self.cur.clone(owner.allocator());
            const id = self.next_id;
            self.next_id += 1;
            try self.snaps.append(self.gpa, .{ .id = id, .owner = owner, .model = model });
            return id;
        }

        fn snapModel(self: *Self, id: u64) *const Model {
            for (self.snaps.items) |*s| {
                if (s.id == id) return if (broken) &self.cur else &s.model; // THE BUG (broken)
            }
            unreachable;
        }

        /// Scan a pinned snapshot into `out` (arena) — caller owns nothing to
        /// free individually.
        pub fn snapshotScan(self: *Self, id: u64, out: Allocator) ![]Obs {
            return copyEntries(self.snapModel(id).entries(), out);
        }

        pub fn scanAll(self: *Self, out: Allocator) ![]Obs {
            return copyEntries(self.cur.entries(), out);
        }

        pub fn releaseSnapshot(self: *Self, id: u64) void {
            for (self.snaps.items, 0..) |s, i| {
                if (s.id == id) {
                    s.owner.deinit();
                    self.gpa.destroy(s.owner);
                    _ = self.snaps.swapRemove(i);
                    return;
                }
            }
        }
    };
}

pub const RefStore = RefStoreImpl(false);
pub const BrokenRefStore = RefStoreImpl(true);

fn copyEntries(src: []const Obs, out: Allocator) ![]Obs {
    const dst = try out.alloc(Obs, src.len);
    for (src, dst) |s, *d| d.* = .{ .key = try out.dupe(u8, s.key), .val = try out.dupe(u8, s.val) };
    return dst;
}

// ── the generic property engine ──────────────────────────────────────────────

const key_space = 16;

fn randKey(prng: *Prng, buf: *[8]u8) []const u8 {
    return std.fmt.bufPrint(buf, "k{d:0>3}", .{prng.below(key_space)}) catch unreachable;
}

/// Drive `Store` and the reference `Model` in lockstep across a randomized
/// transaction/snapshot schedule, asserting every invariant. Generic over any
/// store exposing `apply`/`snapshot`/`snapshotScan`/`scanAll`/`releaseSnapshot`.
/// Returns a `CheckError` on the first violation — the oracle never trips, the
/// broken control does.
pub fn runProperty(comptime Store: type, gpa: Allocator, seed: u64) !void {
    var prng = Prng.init(seed);
    var store = try Store.init(gpa);
    defer store.deinit();

    var ref_owner = std.heap.ArenaAllocator.init(gpa);
    defer ref_owner.deinit();
    var ref = Model.init(ref_owner.allocator());

    const OpenSnap = struct { sid: u64, owner: *std.heap.ArenaAllocator, model: Model };
    var opens: std.ArrayList(OpenSnap) = .empty;
    defer {
        for (opens.items) |o| {
            o.owner.deinit();
            gpa.destroy(o.owner);
        }
        opens.deinit(gpa);
    }

    const steps = 80;
    var step: usize = 0;
    while (step < steps) : (step += 1) {
        const roll = prng.below(100);
        if (roll < 45) {
            // Commit a small random batch atomically to store + reference.
            var scratch = std.heap.ArenaAllocator.init(gpa);
            defer scratch.deinit();
            const sa = scratch.allocator();
            const n = 1 + prng.below(4);
            var changes: std.ArrayList(core.Change) = .empty;
            var j: usize = 0;
            while (j < n) : (j += 1) {
                var kb: [8]u8 = undefined;
                const key = try sa.dupe(u8, randKey(&prng, &kb));
                if (prng.chance(3, 4)) {
                    var vb: [8]u8 = undefined;
                    const val = try sa.dupe(u8, std.fmt.bufPrint(&vb, "v{d}", .{prng.next() % 1000}) catch unreachable);
                    try changes.append(sa, .{ .put = .{ .key = key, .val = val } });
                } else {
                    try changes.append(sa, .{ .del = key });
                }
            }
            try store.apply(changes.items);
            try ref.apply(changes.items);
            const obs = try store.scanAll(sa);
            try checkSerializable(ref.entries(), obs);
        } else if (roll < 65) {
            // Open a snapshot; clone the reference as of now.
            const sid = try store.snapshot();
            const owner = try gpa.create(std.heap.ArenaAllocator);
            owner.* = std.heap.ArenaAllocator.init(gpa);
            const model = try ref.clone(owner.allocator());
            try opens.append(gpa, .{ .sid = sid, .owner = owner, .model = model });
        } else if (roll < 90 and opens.items.len > 0) {
            // Verify a random open snapshot still reads its pinned state.
            var scratch = std.heap.ArenaAllocator.init(gpa);
            defer scratch.deinit();
            const os = opens.items[prng.below(opens.items.len)];
            const obs = try store.snapshotScan(os.sid, scratch.allocator());
            try checkSnapshotIsolation(os.model.entries(), obs);
        } else if (opens.items.len > 0) {
            // Release a random snapshot.
            const os = opens.swapRemove(prng.below(opens.items.len));
            store.releaseSnapshot(os.sid);
            os.owner.deinit();
            gpa.destroy(os.owner);
        }
    }

    // Final sweep: every still-open snapshot must STILL read its pinned state,
    // after all the intervening commits — this is what gives the broken control
    // its teeth (a snapshot opened early has surely seen later commits).
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    for (opens.items) |o| {
        const obs = try store.snapshotScan(o.sid, scratch.allocator());
        try checkSnapshotIsolation(o.model.entries(), obs);
    }
}

// ── tests: checkers + oracle + positive control (all real today) ─────────────

const testing = std.testing;

test "checkSorted accepts ascending, rejects out-of-order and dups" {
    try checkSorted(&.{ .{ .key = "a", .val = "" }, .{ .key = "b", .val = "" } });
    try testing.expectError(error.ScanNotSorted, checkSorted(&.{ .{ .key = "b", .val = "" }, .{ .key = "a", .val = "" } }));
    try testing.expectError(error.ScanNotSorted, checkSorted(&.{ .{ .key = "a", .val = "" }, .{ .key = "a", .val = "" } }));
}

test "checkSnapshotIsolation / checkSerializable equality + teeth" {
    const a = [_]Obs{.{ .key = "k", .val = "1" }};
    const b = [_]Obs{.{ .key = "k", .val = "2" }};
    try checkSnapshotIsolation(&a, &a);
    try testing.expectError(error.SnapshotIsolationViolated, checkSnapshotIsolation(&a, &b));
    try checkSerializable(&a, &a);
    try testing.expectError(error.NotSerializable, checkSerializable(&a, &b));
}

test "checkRecoveredPrefix accepts a committed version, rejects a phantom" {
    const v0 = [_]Obs{};
    const v1 = [_]Obs{.{ .key = "k", .val = "1" }};
    const committed = [_][]const Obs{ &v0, &v1 };
    try checkRecoveredPrefix(&committed, &v1); // last commit
    try checkRecoveredPrefix(&committed, &v0); // earlier committed prefix
    const phantom = [_]Obs{.{ .key = "k", .val = "UNCOMMITTED" }};
    try testing.expectError(error.RecoveredStateNotCommitted, checkRecoveredPrefix(&committed, &phantom));
}

test "Model: put/del/overwrite stays sorted; clone is independent" {
    var owner = std.heap.ArenaAllocator.init(testing.allocator);
    defer owner.deinit();
    var m = Model.init(owner.allocator());
    try m.put("banana", "y");
    try m.put("apple", "r");
    try m.put("apple", "g"); // overwrite
    try checkSorted(m.entries());
    try testing.expectEqualStrings("apple", m.entries()[0].key);
    try testing.expectEqualStrings("g", m.entries()[0].val);

    var owner2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer owner2.deinit();
    var snap = try m.clone(owner2.allocator());
    try m.put("cherry", "d"); // mutate original after cloning
    try testing.expectEqual(@as(usize, 2), snap.entries().len); // clone unaffected
    try testing.expectEqual(@as(usize, 3), m.entries().len);
}

test "property: the correct RefStore oracle passes a randomized sweep" {
    var seed: u64 = 1;
    while (seed <= 200) : (seed += 1) {
        try runProperty(RefStore, testing.allocator, seed);
    }
}

test "teeth: the BrokenRefStore trips the snapshot-isolation checker across a sweep" {
    var caught: usize = 0;
    var seed: u64 = 1;
    while (seed <= 200) : (seed += 1) {
        if (runProperty(BrokenRefStore, testing.allocator, seed)) |_| {
            // A pass is only legal if no snapshot ever outlived a mutating
            // commit on that seed — rare, but not an error.
        } else |e| {
            try testing.expectEqual(error.SnapshotIsolationViolated, e);
            caught += 1;
        }
    }
    // A checker with no teeth would catch zero. The bug is provoked on the vast
    // majority of seeds.
    try testing.expect(caught >= 150);
}

// ── gated: the real Db through the same checkers (SKIP until core lands) ──────
//
// These reference the real transactional API (autocommit `put`/`del`,
// `snapshot`, crash+reopen on `kv.SimStorage`) and the same checkers above.
// They compile today — the signatures are type-checked — but every path
// transitively calls a `core.zig` `@panic` stub, so they are gated to SKIP
// until `gate.fable_core_implemented` flips. The pattern mirrors df-elect.

test "real Db: snapshot isolation + serializability under a commit schedule (gated)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var prng = Prng.init(1);
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var db = try kvtree.Db.open(gpa, sim.storage(), "prop.kvt", .{});
    defer db.close();

    var ref_owner = std.heap.ArenaAllocator.init(gpa);
    defer ref_owner.deinit();
    var ref = Model.init(ref_owner.allocator());

    var snap = try db.snapshot();
    var pin_owner = std.heap.ArenaAllocator.init(gpa);
    defer pin_owner.deinit();
    const pinned = try ref.clone(pin_owner.allocator());

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var kb: [8]u8 = undefined;
        const key = randKey(&prng, &kb);
        try db.put(key, "v");
        try ref.put(key, "v");
    }

    // The pinned snapshot must still read empty; the live view is serializable.
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const snap_obs = try scanCursor(&snap, scratch.allocator());
    try checkSnapshotIsolation(pinned.entries(), snap_obs);
    var cur = try db.cursor();
    defer cur.deinit();
    const live_obs = try drainCursor(&cur, scratch.allocator());
    try checkSerializable(ref.entries(), live_obs);
    snap.release();
}

test "real Db: crash at a commit recovers to a committed prefix (gated)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    var v0: std.ArrayList(Obs) = .empty; // committed version snapshots
    defer v0.deinit(gpa);

    {
        var db = try kvtree.Db.open(gpa, sim.storage(), "rec.kvt", .{});
        defer db.close();
        try db.put("committed", "1");
    }
    // Crash the next commit mid-fsync, then reopen and require a committed prefix.
    sim.ops_until_crash = 0;
    {
        var db = kvtree.Db.open(gpa, sim.storage(), "rec.kvt", .{}) catch return;
        defer db.close();
        _ = db.put("inflight", "2") catch {};
    }
    sim.reboot();
    var db = try kvtree.Db.open(gpa, sim.storage(), "rec.kvt", .{});
    defer db.close();
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    var cur = try db.cursor();
    defer cur.deinit();
    const recovered = try drainCursor(&cur, scratch.allocator());
    const committed_only = [_]Obs{.{ .key = "committed", .val = "1" }};
    const with_inflight = [_]Obs{ .{ .key = "committed", .val = "1" }, .{ .key = "inflight", .val = "2" } };
    const candidates = [_][]const Obs{ &committed_only, &with_inflight };
    try checkRecoveredPrefix(&candidates, recovered);
}

/// Drain a `kvtree.Cursor` (from `first`) into an arena as `[]Obs`.
fn drainCursor(cur: *kvtree.Cursor, out: Allocator) ![]Obs {
    try cur.first();
    var list: std.ArrayList(Obs) = .empty;
    while (try cur.next()) |e| {
        try list.append(out, .{ .key = try out.dupe(u8, e.key), .val = try out.dupe(u8, e.val) });
    }
    return list.items;
}

fn scanCursor(snap: *kvtree.Snapshot, out: Allocator) ![]Obs {
    var cur = try snap.cursor();
    defer cur.deinit();
    return drainCursor(&cur, out);
}
