// SPDX-License-Identifier: MIT

//! history — a linearizability check of FIFO-queue histories (test support).
//!
//! The multiset oracle in `harness.zig` proves that nothing is lost,
//! duplicated or corrupted, and its per-consumer check that one producer's
//! items stay in order. It says nothing about two producers' items relative to
//! each other, nor about an empty answer. This file records, per operation,
//! the interval it was in flight (a stamp from one shared counter taken just
//! before the call and one just after it returns, so the recorded interval
//! contains the real one) and then looks for the four patterns that make a
//! queue history with distinct values non-linearizable (Henzinger, Sezgin,
//! Vafeiadis, "Aspect-Oriented Linearizability Proofs", CONCUR 2013):
//!
//!  * `fresh`   — a dequeue returned a value no enqueue of it can precede
//!                (never enqueued, or its dequeue returned before the enqueue
//!                was invoked);
//!  * `repeat`  — a value was dequeued twice;
//!  * `order`   — enq(x) returned before enq(y) was invoked, yet y was
//!                dequeued and x was not, or y's dequeue returned before x's
//!                was invoked;
//!  * `witness` — a dequeue answered empty while some x had been enqueued
//!                (enqueue returned before the dequeue was invoked) and was
//!                dequeued only after the empty answer returned (or never):
//!                x sat in the queue throughout the call.
//!
//! Every pattern is a violation by itself, so a flagged history is a true
//! bug (stamps only widen intervals, which can hide a violation, never invent
//! one); the converse (a clean history is linearizable) is not claimed here,
//! and a `bounded.zig` ring is not run through it: a Vyukov ring answers empty
//! while a claimed-but-unpublished slot precedes a published one, which is
//! `witness` by this definition (SPEC §4b).
//!
//! `fresh` and `repeat` are in `harness.verify` already; they are here so a
//! history is judged whole.

const std = @import("std");
const atomic = @import("atomic.zig");
const ebr = @import("ebr.zig");
const mpmc = @import("mpmc.zig");
const segqueue = @import("segqueue.zig");

const testing = std.testing;

const Kind = enum { enq, deq, deq_empty };

/// One operation: its kind, the value (not for `deq_empty`) and the stamps
/// taken before the call (`inv`) and after its return (`ret`). Stamps are
/// distinct, so `a` precedes `b` in real time exactly when `a.ret < b.inv`.
const Op = struct {
    kind: Kind,
    value: u64,
    inv: u64,
    ret: u64,
};

const Violation = enum { fresh, repeat, order, witness, lost };

const never: u64 = std.math.maxInt(u64);

/// Judge `ops` (any order). `drained`: the run ended with the queue emptied,
/// so an enqueued value without a dequeue is `lost`. Enqueued values must be
/// distinct.
fn checkFifo(allocator: std.mem.Allocator, ops: []const Op, drained: bool) !?Violation {
    var enq_idx: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer enq_idx.deinit(allocator);
    var deq_idx: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer deq_idx.deinit(allocator);

    for (ops, 0..) |op, i| {
        if (op.kind != .enq) continue;
        const gop = try enq_idx.getOrPut(allocator, op.value);
        if (gop.found_existing) return error.DuplicateEnqueue;
        gop.value_ptr.* = i;
    }
    for (ops, 0..) |op, i| {
        if (op.kind != .deq) continue;
        const e = enq_idx.get(op.value) orelse return .fresh;
        if (op.ret < ops[e].inv) return .fresh;
        const gop = try deq_idx.getOrPut(allocator, op.value);
        if (gop.found_existing) return .repeat;
        gop.value_ptr.* = i;
    }

    // The enqueues with the stamps of their value's dequeue (`never` = none).
    const E = struct { enq_inv: u64, enq_ret: u64, deq_inv: u64, deq_ret: u64, dequeued: bool };
    var es: std.ArrayListUnmanaged(E) = .empty;
    defer es.deinit(allocator);
    for (ops) |op| {
        if (op.kind != .enq) continue;
        const d = deq_idx.get(op.value);
        try es.append(allocator, .{
            .enq_inv = op.inv,
            .enq_ret = op.ret,
            .deq_inv = if (d) |i| ops[i].inv else never,
            .deq_ret = if (d) |i| ops[i].ret else never,
            .dequeued = d != null,
        });
        if (d == null and drained) return .lost;
    }

    for (es.items) |x| {
        for (es.items) |y| {
            if (x.enq_ret >= y.enq_inv or !y.dequeued) continue;
            // enq(x) precedes enq(y) and y came out: x had to come out first.
            if (!x.dequeued or y.deq_ret < x.deq_inv) return .order;
        }
    }
    for (ops) |d| {
        if (d.kind != .deq_empty) continue;
        for (es.items) |x| {
            if (x.enq_ret < d.inv and (!x.dequeued or d.ret < x.deq_inv)) return .witness;
        }
    }
    return null;
}

// ── recording ────────────────────────────────────────────────────────────────

const Log = struct {
    ops: []Op,
    n: usize = 0,
    clock: *std.atomic.Value(u64),

    fn stamp(l: *const Log) u64 {
        return l.clock.fetchAdd(1, .seq_cst);
    }

    fn enq(l: *Log, adapter: anytype, ctx: anytype, v: u64) !void {
        const inv = l.stamp();
        try adapter.enqueue(ctx, v);
        l.ops[l.n] = .{ .kind = .enq, .value = v, .inv = inv, .ret = l.stamp() };
        l.n += 1;
    }

    fn deq(l: *Log, adapter: anytype, ctx: anytype) ?u64 {
        const inv = l.stamp();
        const got = adapter.dequeue(ctx);
        l.ops[l.n] = .{ .kind = if (got == null) .deq_empty else .deq, .value = got orelse 0, .inv = inv, .ret = l.stamp() };
        l.n += 1;
        return got;
    }
};

/// A run of `threads` workers, each doing `per_thread` operations: a coin
/// (xorshift, per-thread seed) picks an enqueue of the next value of its own
/// range or a dequeue, so empty answers and non-empty queues both occur. The
/// queue is then drained by the caller thread; every operation is logged.
/// `Adapter` is `harness.runStress`'s: `ThreadCtx`, `initThread`,
/// `deinitThread`, `enqueue(ctx, v)`, `dequeue(ctx)`.
fn run(comptime Adapter: type, adapter: *Adapter, threads: usize, per_thread: usize, seed: u64, allocator: std.mem.Allocator) !?Violation {
    var clock: std.atomic.Value(u64) = .init(0);
    const logs = try allocator.alloc(Log, threads);
    defer allocator.free(logs);
    var made: usize = 0;
    defer for (logs[0..made]) |l| allocator.free(l.ops);
    while (made < threads) : (made += 1) {
        logs[made] = .{ .ops = try allocator.alloc(Op, per_thread), .clock = &clock };
    }

    const Worker = struct {
        fn main(a: *Adapter, log: *Log, tid: usize, n: usize, s: u64, failed: *std.atomic.Value(bool)) void {
            const ctx = a.initThread() catch {
                failed.store(true, .release);
                return;
            };
            defer a.deinitThread(ctx);
            var x = s *% 0x9E3779B97F4A7C15 +% tid +% 1;
            var seq: u64 = 0;
            for (0..n) |_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if (x & 1 == 0) {
                    log.enq(a, ctx, (@as(u64, tid) << 40) | seq) catch {
                        failed.store(true, .release);
                        return;
                    };
                    seq += 1;
                } else {
                    _ = log.deq(a, ctx);
                }
            }
        }
    };

    var failed: std.atomic.Value(bool) = .init(false);
    const ts = try allocator.alloc(std.Thread, threads);
    defer allocator.free(ts);
    var spawned: usize = 0;
    var spawn_err: ?std.Thread.SpawnError = null;
    while (spawned < threads) : (spawned += 1) {
        ts[spawned] = std.Thread.spawn(.{}, Worker.main, .{ adapter, &logs[spawned], spawned, per_thread, seed, &failed }) catch |e| {
            spawn_err = e;
            break;
        };
    }
    for (ts[0..spawned]) |*t| t.join();
    if (spawn_err) |e| return e;
    if (failed.load(.acquire)) return error.StressThreadFailed;

    var all: std.ArrayListUnmanaged(Op) = .empty;
    defer all.deinit(allocator);
    for (logs) |l| try all.appendSlice(allocator, l.ops[0..l.n]);

    // Drain on this thread, logged like the rest.
    const ctx = try adapter.initThread();
    defer adapter.deinitThread(ctx);
    var tail: Log = .{ .ops = try allocator.alloc(Op, all.items.len + 1), .clock = &clock };
    defer allocator.free(tail.ops);
    while (tail.n + 1 < tail.ops.len) {
        if (tail.deq(adapter, ctx) == null) break;
    }
    try all.appendSlice(allocator, tail.ops[0..tail.n]);
    return checkFifo(allocator, all.items, true);
}

// ── adapters and controls ────────────────────────────────────────────────────

const harness = @import("harness.zig");

/// A queue with `enqueue(v)` / `dequeue()` and no handles.
fn PlainAdapter(comptime Q: type, comptime enq_fn: []const u8, comptime deq_fn: []const u8) type {
    return struct {
        q: *Q,
        const Self = @This();
        const ThreadCtx = void;
        fn initThread(self: *Self) !ThreadCtx {
            _ = self;
        }
        fn deinitThread(self: *Self, ctx: ThreadCtx) void {
            _ = self;
            _ = ctx;
        }
        fn enqueue(self: *Self, ctx: ThreadCtx, v: u64) !void {
            _ = ctx;
            try @field(Q, enq_fn)(self.q, v);
        }
        fn dequeue(self: *Self, ctx: ThreadCtx) ?u64 {
            _ = ctx;
            return @field(Q, deq_fn)(self.q);
        }
    };
}

const RefAdapter = PlainAdapter(harness.RefQueue, "enqueue", "dequeue");

/// A coarse-locked LIFO: no value lost, duplicated or corrupted (the multiset
/// oracle is satisfied), but the order is wrong.
const LifoStack = struct {
    const Node = struct { v: u64, next: ?*Node };
    lock: atomic.SpinLock = .{},
    top: ?*Node = null,
    allocator: std.mem.Allocator,

    fn deinit(s: *LifoStack) void {
        while (s.top) |n| {
            s.top = n.next;
            s.allocator.destroy(n);
        }
    }
    fn enqueue(s: *LifoStack, v: u64) !void {
        const n = try s.allocator.create(Node);
        s.lock.lock();
        defer s.lock.unlock();
        n.* = .{ .v = v, .next = s.top };
        s.top = n;
    }
    fn dequeue(s: *LifoStack) ?u64 {
        s.lock.lock();
        const n = s.top orelse {
            s.lock.unlock();
            return null;
        };
        s.top = n.next;
        s.lock.unlock();
        const v = n.v;
        s.allocator.destroy(n);
        return v;
    }
};

/// A correct queue that answers empty on every second dequeue call without
/// removing anything: nothing lost, nothing out of order, but an empty answer
/// with a value in the queue.
const FlakyEmpty = struct {
    inner: harness.RefQueue,
    calls: std.atomic.Value(u32) = .init(0),

    fn enqueue(s: *FlakyEmpty, v: u64) !void {
        try s.inner.enqueue(v);
    }
    fn dequeue(s: *FlakyEmpty) ?u64 {
        if (s.calls.fetchAdd(1, .monotonic) % 2 == 0) return null;
        return s.inner.dequeue();
    }
};

const MpmcAdapter = struct {
    q: *mpmc.Queue(u64),
    domain: *ebr.Domain,
    const ThreadCtx = *ebr.Participant;
    fn initThread(self: *MpmcAdapter) !ThreadCtx {
        return self.domain.register();
    }
    fn deinitThread(self: *MpmcAdapter, ctx: ThreadCtx) void {
        self.domain.unregister(ctx);
    }
    fn enqueue(self: *MpmcAdapter, ctx: ThreadCtx, v: u64) !void {
        try self.q.enqueue(ctx, v);
    }
    fn dequeue(self: *MpmcAdapter, ctx: ThreadCtx) ?u64 {
        return self.q.dequeue(ctx);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

fn mk(kind: Kind, value: u64, inv: u64, ret: u64) Op {
    return .{ .kind = kind, .value = value, .inv = inv, .ret = ret };
}

test "HISTORY CHECKER TEETH: each pattern is flagged, overlapping calls are not (deterministic)" {
    const a = testing.allocator;
    // Sequential, in order: clean.
    try testing.expectEqual(@as(?Violation, null), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1),       mk(.enq, 2, 2, 3),
        mk(.deq, 1, 4, 5),       mk(.deq, 2, 6, 7),
        mk(.deq_empty, 0, 8, 9),
    }, true));
    // Two enqueues that overlap may come out either way round.
    try testing.expectEqual(@as(?Violation, null), try checkFifo(a, &.{
        mk(.enq, 1, 0, 5), mk(.enq, 2, 1, 4),
        mk(.deq, 2, 6, 7), mk(.deq, 1, 8, 9),
    }, true));
    // An empty answer that overlaps the enqueue is fine.
    try testing.expectEqual(@as(?Violation, null), try checkFifo(a, &.{
        mk(.enq, 1, 0, 5), mk(.deq_empty, 0, 1, 2), mk(.deq, 1, 6, 7),
    }, true));
    // An empty answer that overlaps the dequeue of the only item is fine.
    try testing.expectEqual(@as(?Violation, null), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.deq, 1, 2, 9), mk(.deq_empty, 0, 3, 4),
    }, true));

    // order: 2 dequeued before 1 although enq(1) returned before enq(2) began.
    try testing.expectEqual(@as(?Violation, .order), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.enq, 2, 2, 3),
        mk(.deq, 2, 4, 5), mk(.deq, 1, 6, 7),
    }, true));
    // order, the value that overtook is out and the earlier one never was.
    try testing.expectEqual(@as(?Violation, .order), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.enq, 2, 2, 3), mk(.deq, 2, 4, 5),
    }, false));
    // order needs the dequeues to be disjoint: overlapping ones may be either way.
    try testing.expectEqual(@as(?Violation, null), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.enq, 2, 2, 3),
        mk(.deq, 2, 4, 8), mk(.deq, 1, 5, 7),
    }, true));
    // witness: empty while 1 sat in the queue the whole call.
    try testing.expectEqual(@as(?Violation, .witness), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.deq_empty, 0, 2, 3), mk(.deq, 1, 4, 5),
    }, true));
    // witness with a value nobody dequeues.
    try testing.expectEqual(@as(?Violation, .witness), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.deq_empty, 0, 2, 3),
    }, false));
    // repeat, fresh (never enqueued; dequeued before its enqueue began), lost.
    try testing.expectEqual(@as(?Violation, .repeat), try checkFifo(a, &.{
        mk(.enq, 1, 0, 1), mk(.deq, 1, 2, 3), mk(.deq, 1, 4, 5),
    }, true));
    try testing.expectEqual(@as(?Violation, .fresh), try checkFifo(a, &.{mk(.deq, 7, 0, 1)}, true));
    try testing.expectEqual(@as(?Violation, .fresh), try checkFifo(a, &.{
        mk(.deq, 1, 0, 1), mk(.enq, 1, 2, 3),
    }, true));
    try testing.expectEqual(@as(?Violation, .lost), try checkFifo(a, &.{mk(.enq, 1, 0, 1)}, true));
    try testing.expectError(error.DuplicateEnqueue, checkFifo(a, &.{ mk(.enq, 1, 0, 1), mk(.enq, 1, 2, 3) }, true));
}

test "HISTORY: the locked reference queue is clean (no false positive)" {
    var q = harness.RefQueue.init(testing.allocator);
    defer q.deinit();
    var ad: RefAdapter = .{ .q = &q };
    for (0..3) |round| {
        try testing.expectEqual(@as(?Violation, null), try run(RefAdapter, &ad, 4, 2_000, round, testing.allocator));
    }
}

test "HISTORY TEETH: a LIFO that passes the multiset check fails here, sequentially and under threads" {
    var s: LifoStack = .{ .allocator = testing.allocator };
    defer s.deinit();
    const Ad = PlainAdapter(LifoStack, "enqueue", "dequeue");
    var ad: Ad = .{ .q = &s };
    // One thread: two enqueues in order, then the dequeues swap them.
    var clock: std.atomic.Value(u64) = .init(0);
    var buf: [4]Op = undefined;
    var log: Log = .{ .ops = &buf, .clock = &clock };
    try log.enq(&ad, {}, 1);
    try log.enq(&ad, {}, 2);
    try testing.expectEqual(@as(?u64, 2), log.deq(&ad, {}));
    try testing.expectEqual(@as(?u64, 1), log.deq(&ad, {}));
    try testing.expectEqual(@as(?Violation, .order), try checkFifo(testing.allocator, log.ops[0..log.n], true));
    // Four threads: the run drains it and the driver must flag it.
    try testing.expectEqual(@as(?Violation, .order), try run(Ad, &ad, 4, 2_000, 1, testing.allocator));
}

test "HISTORY TEETH: an empty answer with an item inside is flagged" {
    var q: FlakyEmpty = .{ .inner = harness.RefQueue.init(testing.allocator) };
    defer q.inner.deinit();
    const Ad = PlainAdapter(FlakyEmpty, "enqueue", "dequeue");
    var ad: Ad = .{ .q = &q };
    var clock: std.atomic.Value(u64) = .init(0);
    var buf: [3]Op = undefined;
    var log: Log = .{ .ops = &buf, .clock = &clock };
    try log.enq(&ad, {}, 1);
    try testing.expectEqual(@as(?u64, null), log.deq(&ad, {}));
    try testing.expectEqual(@as(?u64, 1), log.deq(&ad, {}));
    try testing.expectEqual(@as(?Violation, .witness), try checkFifo(testing.allocator, log.ops[0..log.n], true));
}

test "HISTORY: MpmcQueue + EBR histories are linearizable (4 threads, mixed operations)" {
    const alloc = testing.allocator;
    var domain = try ebr.Domain.init(alloc, .{ .max_participants = 32 });
    defer domain.deinit();
    var node_pool = mpmc.Queue(u64).Pool.init(alloc);
    defer node_pool.deinit();
    var q = try mpmc.Queue(u64).init(&node_pool, &domain);
    defer q.deinit();
    var ad: MpmcAdapter = .{ .q = &q, .domain = &domain };
    for (0..4) |round| {
        try testing.expectEqual(@as(?Violation, null), try run(MpmcAdapter, &ad, 4, 3_000, round, alloc));
    }
    try node_pool.verifyQuiescent();
}

test "HISTORY: SegQueue histories are linearizable (1-, 3- and default-slot blocks)" {
    inline for (.{ 1, 3, 0 }) |slots| {
        const Q = if (slots == 0) segqueue.SegQueue(u64, .{}) else segqueue.SegQueue(u64, .{ .block_slots = slots });
        var q = try Q.init(testing.allocator);
        defer q.deinit();
        const Ad = PlainAdapter(Q, "push", "pop");
        var ad: Ad = .{ .q = &q };
        for (0..4) |round| {
            try testing.expectEqual(@as(?Violation, null), try run(Ad, &ad, 4, 3_000, round, testing.allocator));
        }
    }
}
