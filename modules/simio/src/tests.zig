// SPDX-License-Identifier: MIT

//! M1 behaviour tests: the scheduler against the `std.Io` contract, driven only
//! through the public `std.Io` API the code under test would use.

const std = @import("std");
const sched = @import("sched.zig");

const Io = std.Io;
const Sim = sched.Sim;
const testing = std.testing;

const ns_per_s = std.time.ns_per_s;

fn newSim(sim: *Sim, seed: u64) void {
    sim.init(testing.allocator, .{ .seed = seed, .stack_size = 256 * 1024 });
}

// ── a lost update the scheduler must be able to expose ─────────────────────

const Counter = struct {
    value: u32 = 0,
    mutex: Io.Mutex = .init,
};

/// Read-modify-write with an `Io` call in the middle: a yield point, as a
/// syscall would be on a real thread. Without the mutex it loses updates
/// under some interleavings.
fn bump(io: Io, c: *Counter, rounds: usize, locked: bool) !void {
    for (0..rounds) |_| {
        if (locked) try c.mutex.lock(io);
        defer if (locked) c.mutex.unlock(io);
        const seen = c.value;
        _ = Io.Timestamp.now(io, .awake);
        c.value = seen + 1;
    }
}

fn runCounter(seed: u64, locked: bool) !struct { value: u32, fingerprint: u64 } {
    var sim: Sim = undefined;
    newSim(&sim, seed);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var c: Counter = .{};
    for (0..4) |_| try h.spawn(bump, .{ h.io(), &c, 25, locked });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(usize, 0), h.failures);
    return .{ .value = c.value, .fingerprint = sim.fingerprint() };
}

test "the same seed replays the same schedule" {
    const a = try runCounter(42, false);
    const b = try runCounter(42, false);
    try testing.expectEqual(a.value, b.value);
    try testing.expectEqual(a.fingerprint, b.fingerprint);
}

test "seeds explore interleavings: a lost update is found, and the mutex prevents it" {
    var lost: usize = 0;
    var fingerprints: std.AutoArrayHashMapUnmanaged(u64, void) = .empty;
    defer fingerprints.deinit(testing.allocator);
    for (0..40) |seed| {
        const racy = try runCounter(seed, false);
        if (racy.value != 100) lost += 1;
        try fingerprints.put(testing.allocator, racy.fingerprint, {});
        const safe = try runCounter(seed, true);
        try testing.expectEqual(@as(u32, 100), safe.value);
    }
    try testing.expect(lost > 0);
    // Different seeds really are different schedules.
    try testing.expect(fingerprints.count() > 30);
}

test "fifo with no preemption never interleaves the racy section" {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 1, .schedule = .fifo, .stack_size = 256 * 1024 });
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var c: Counter = .{};
    for (0..4) |_| try h.spawn(bump, .{ h.io(), &c, 25, false });
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(u32, 100), c.value);
}

// ── virtual time ───────────────────────────────────────────────────────────

const Readings = struct { awake0: i96 = 0, awake1: i96 = 0, real1: i96 = 0 };

fn sleeper(io: Io, out: *Readings) !void {
    out.awake0 = Io.Timestamp.now(io, .awake).nanoseconds;
    try io.sleep(.fromSeconds(5), .awake);
    out.awake1 = Io.Timestamp.now(io, .awake).nanoseconds;
    out.real1 = Io.Timestamp.now(io, .real).nanoseconds;
}

test "sleep advances virtual time exactly, clocks are per host" {
    var sim: Sim = undefined;
    newSim(&sim, 3);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{ .clock_skew_ns = -2 * ns_per_s });
    var ra: Readings = .{};
    var rb: Readings = .{};
    try a.spawn(sleeper, .{ a.io(), &ra });
    try b.spawn(sleeper, .{ b.io(), &rb });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(u64, 5 * ns_per_s), r.now_ns);
    try testing.expectEqual(@as(i96, 5 * ns_per_s), ra.awake1 - ra.awake0);
    const epoch = sim.opts.epoch_ns;
    try testing.expectEqual(epoch + 5 * ns_per_s, ra.real1);
    try testing.expectEqual(epoch + 3 * ns_per_s, rb.real1);
}

fn deadlineSleeper(io: Io, woke_at: *i96) !void {
    const start = Io.Clock.Timestamp.now(io, .real);
    try start.addDuration(.{ .raw = .fromMilliseconds(1500), .clock = .real }).wait(io);
    woke_at.* = Io.Timestamp.now(io, .real).nanoseconds;
}

test "a deadline on the skewed real clock is honoured in that host's time" {
    var sim: Sim = undefined;
    newSim(&sim, 4);
    defer sim.deinit();
    const h = try sim.addHost(.{ .clock_skew_ns = 7 * ns_per_s });
    var woke: i96 = 0;
    try h.spawn(deadlineSleeper, .{ h.io(), &woke });
    const r = sim.run();
    try testing.expectEqual(@as(u64, 1500 * std.time.ns_per_ms), r.now_ns);
    try testing.expectEqual(sim.opts.epoch_ns + 7 * ns_per_s + 1500 * std.time.ns_per_ms, woke);
}

fn timedWaiter(io: Io, word: *const u32, elapsed: *i96) !void {
    const t0 = Io.Timestamp.now(io, .awake);
    try io.futexWaitTimeout(u32, word, 0, .{ .duration = .{ .raw = .fromMilliseconds(250), .clock = .awake } });
    elapsed.* = t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds;
}

test "a futex wait with a timeout returns when the timeout expires" {
    var sim: Sim = undefined;
    newSim(&sim, 5);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    const word: u32 = 0;
    var elapsed: i96 = 0;
    try h.spawn(timedWaiter, .{ h.io(), &word, &elapsed });
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(i96, 250 * std.time.ns_per_ms), elapsed);
}

// ── futures and cancelation ────────────────────────────────────────────────

fn square(io: Io, x: u64) u64 {
    io.sleep(.fromMilliseconds(10), .awake) catch {};
    return x * x;
}

fn sumOfSquares(io: Io, out: *u64) !void {
    var futures: [5]Io.Future(u64) = undefined;
    for (&futures, 0..) |*f, i| f.* = io.async(square, .{ io, i + 1 });
    var total: u64 = 0;
    for (&futures) |*f| total += f.await(io);
    out.* = total;
}

test "async tasks run concurrently and await returns their results" {
    var sim: Sim = undefined;
    newSim(&sim, 6);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var out: u64 = 0;
    try h.spawn(sumOfSquares, .{ h.io(), &out });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(u64, 55), out);
    // All five slept concurrently: 10 ms in total, not 50.
    try testing.expectEqual(@as(u64, 10 * std.time.ns_per_ms), r.now_ns);
}

const CancelLog = struct {
    first: ?anyerror = null,
    second_ok: bool = false,
};

fn sleepForever(io: Io, log: *CancelLog) error{Canceled}!void {
    Io.Timeout.sleep(.none, io) catch |err| {
        log.first = err;
        // Delivered once: the next cancelation point does not fire again.
        io.sleep(.fromSeconds(1), .awake) catch return error.Canceled;
        log.second_ok = true;
        return err;
    };
}

fn cancelAfter(io: Io, log: *CancelLog, result: *?anyerror) !void {
    var f = io.async(sleepForever, .{ io, log });
    try io.sleep(.fromSeconds(2), .awake);
    f.cancel(io) catch |err| {
        result.* = err;
    };
}

test "cancel wakes a blocked task once, and only the next cancelation point sees it" {
    var sim: Sim = undefined;
    newSim(&sim, 7);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var log: CancelLog = .{};
    var result: ?anyerror = null;
    try h.spawn(cancelAfter, .{ h.io(), &log, &result });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(?anyerror, error.Canceled), log.first);
    try testing.expect(log.second_ok);
    try testing.expectEqual(@as(?anyerror, error.Canceled), result);
    try testing.expectEqual(@as(u64, 3 * ns_per_s), r.now_ns);
}

const ProtLog = struct { slept: bool = false, check: ?anyerror = null, recheck: ?anyerror = null };

fn protectedSleep(io: Io, log: *ProtLog) void {
    const old = io.swapCancelProtection(.blocked);
    io.sleep(.fromSeconds(3), .awake) catch unreachable; // protected: no cancelation point
    log.slept = true;
    _ = io.swapCancelProtection(old);
    io.checkCancel() catch |err| {
        log.check = err;
        io.recancel();
        io.checkCancel() catch |again| {
            log.recheck = again;
        };
    };
}

fn cancelProtected(io: Io, log: *ProtLog) !void {
    var f = io.async(protectedSleep, .{ io, log });
    try io.sleep(.fromSeconds(1), .awake);
    f.cancel(io);
}

test "cancel protection defers the request; recancel re-arms it" {
    var sim: Sim = undefined;
    newSim(&sim, 8);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var log: ProtLog = .{};
    try h.spawn(cancelProtected, .{ h.io(), &log });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expect(log.slept);
    try testing.expectEqual(@as(?anyerror, error.Canceled), log.check);
    try testing.expectEqual(@as(?anyerror, error.Canceled), log.recheck);
    try testing.expectEqual(@as(u64, 3 * ns_per_s), r.now_ns);
}

// ── groups ─────────────────────────────────────────────────────────────────

fn member(io: Io, done: *u32, secs: u64) Io.Cancelable!void {
    try io.sleep(.fromSeconds(@intCast(secs)), .awake);
    done.* += 1;
}

fn groupAwaitAll(io: Io, done: *u32) !void {
    var g: Io.Group = .init;
    for (1..6) |i| g.async(io, member, .{ io, done, i });
    try g.await(io);
}

test "a group await returns after every member finished" {
    var sim: Sim = undefined;
    newSim(&sim, 9);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var done: u32 = 0;
    try h.spawn(groupAwaitAll, .{ h.io(), &done });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(u32, 5), done);
    try testing.expectEqual(@as(u64, 5 * ns_per_s), r.now_ns);
}

fn groupCancelEarly(io: Io, done: *u32) !void {
    var g: Io.Group = .init;
    for (1..6) |i| g.async(io, member, .{ io, done, i * 10 });
    try io.sleep(.fromSeconds(25), .awake);
    g.cancel(io);
}

test "group cancel stops the members still sleeping" {
    var sim: Sim = undefined;
    newSim(&sim, 10);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var done: u32 = 0;
    try h.spawn(groupCancelEarly, .{ h.io(), &done });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(u32, 2), done); // the 10 s and 20 s members
    try testing.expectEqual(@as(u64, 25 * ns_per_s), r.now_ns);
}

/// Starts a group whose members finish at once, then outlives them without
/// ever awaiting it: the group's state is then held by no task at all.
fn groupNeverAwaited(io: Io, done: *u32) !void {
    var g: Io.Group = .init;
    for (0..3) |_| g.async(io, member, .{ io, done, 0 });
    try io.sleep(.fromSeconds(3600), .awake);
    g.cancel(io);
}

test "a group left behind by a discarded task is freed by deinit and by a crash" {
    // ssh pilot finding: neither path found a group none of whose tasks were
    // still alive, and `testing.allocator` reported its state as leaked.
    for ([_]bool{ false, true }) |crash| {
        var sim: Sim = undefined;
        newSim(&sim, 31);
        defer sim.deinit();
        const h = try sim.addHost(.{});
        var done: u32 = 0;
        try h.spawn(groupNeverAwaited, .{ h.io(), &done });
        if (crash) try sim.scheduleFault(ns_per_s, .{ .crash = h.id });
        _ = sim.runFor(2 * ns_per_s);
        try testing.expectEqual(@as(u32, 3), done);
    }
}

fn awaitGroupThenReport(io: Io, done: *u32, result: *?anyerror) void {
    var g: Io.Group = .init;
    for (1..4) |i| g.async(io, member, .{ io, done, i * 10 });
    g.await(io) catch |err| {
        result.* = err;
    };
}

fn cancelTheAwaiter(io: Io, done: *u32, result: *?anyerror) !void {
    var f = io.async(awaitGroupThenReport, .{ io, done, result });
    try io.sleep(.fromSeconds(15), .awake);
    f.cancel(io);
}

test "canceling a group's awaiter propagates to the members and surfaces at the end" {
    var sim: Sim = undefined;
    newSim(&sim, 11);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var done: u32 = 0;
    var result: ?anyerror = null;
    try h.spawn(cancelTheAwaiter, .{ h.io(), &done, &result });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(u32, 1), done);
    try testing.expectEqual(@as(?anyerror, error.Canceled), result);
    try testing.expectEqual(@as(u64, 15 * ns_per_s), r.now_ns);
}

// ── condition variables over the futex ─────────────────────────────────────

const Channel = struct {
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    items: [8]u32 = undefined,
    len: usize = 0,
    closed: bool = false,
};

fn producer(io: Io, ch: *Channel) !void {
    for (0..20) |i| {
        try ch.mutex.lock(io);
        defer ch.mutex.unlock(io);
        while (ch.len == ch.items.len) try ch.cond.wait(io, &ch.mutex);
        ch.items[ch.len] = @intCast(i);
        ch.len += 1;
        ch.cond.broadcast(io);
    }
    try ch.mutex.lock(io);
    defer ch.mutex.unlock(io);
    ch.closed = true;
    ch.cond.broadcast(io);
}

fn consumer(io: Io, ch: *Channel, sum: *u32) !void {
    while (true) {
        try ch.mutex.lock(io);
        defer ch.mutex.unlock(io);
        while (ch.len == 0 and !ch.closed) try ch.cond.wait(io, &ch.mutex);
        if (ch.len == 0) return;
        ch.len -= 1;
        sum.* += ch.items[ch.len];
        ch.cond.broadcast(io);
    }
}

test "mutex and condition variable work over the simulated futex, on every seed" {
    for (0..20) |seed| {
        var sim: Sim = undefined;
        newSim(&sim, seed);
        defer sim.deinit();
        const h = try sim.addHost(.{});
        var ch: Channel = .{};
        var sum: u32 = 0;
        try h.spawn(producer, .{ h.io(), &ch });
        try h.spawn(consumer, .{ h.io(), &ch, &sum });
        try h.spawn(consumer, .{ h.io(), &ch, &sum });
        try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
        try testing.expectEqual(@as(usize, 0), h.failures);
        try testing.expectEqual(@as(u32, 190), sum);
    }
}

// ── outcomes other than quiescent ──────────────────────────────────────────

fn waitForever(io: Io, word: *const u32) !void {
    try io.futexWait(u32, word, 0);
}

test "a task nobody can wake is reported as a deadlock and released by deinit" {
    var sim: Sim = undefined;
    newSim(&sim, 12);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    const word: u32 = 0;
    try h.spawn(waitForever, .{ h.io(), &word });
    try h.spawn(waitForever, .{ h.io(), &word });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.deadlock, r.outcome);
    try testing.expectEqual(@as(usize, 2), r.blocked);
}

fn spin(io: Io) !void {
    while (true) try io.checkCancel();
}

test "a task that never blocks hits the step limit" {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 13, .max_steps = 1000, .preempt_permille = 1000, .stack_size = 256 * 1024 });
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.spawn(spin, .{h.io()});
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.step_limit, r.outcome);
    try testing.expectEqual(@as(u64, 1000), r.steps);
}

fn fails(io: Io) !void {
    try io.sleep(.fromMilliseconds(1), .awake);
    return error.Boom;
}

test "an error from a root task is recorded on its host" {
    var sim: Sim = undefined;
    newSim(&sim, 14);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.spawn(fails, .{h.io()});
    try h.spawn(fails, .{h.io()});
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(?anyerror, error.Boom), h.failure);
    try testing.expectEqual(@as(usize, 2), h.failures);
}

// ── randomness ─────────────────────────────────────────────────────────────

fn draw(io: Io, out: *[2][16]u8) !void {
    io.random(&out[0]);
    try io.randomSecure(&out[1]);
}

test "randomness is seeded per host: reproducible, and distinct between hosts" {
    var first: [2][2][16]u8 = undefined;
    for (0..2) |round| {
        var sim: Sim = undefined;
        newSim(&sim, 15);
        defer sim.deinit();
        const a = try sim.addHost(.{});
        const b = try sim.addHost(.{});
        var ra: [2][16]u8 = undefined;
        var rb: [2][16]u8 = undefined;
        try a.spawn(draw, .{ a.io(), &ra });
        try b.spawn(draw, .{ b.io(), &rb });
        _ = sim.run();
        try testing.expect(!std.mem.eql(u8, &ra[0], &rb[0]));
        try testing.expect(!std.mem.eql(u8, &ra[0], &ra[1]));
        if (round == 0) {
            first = .{ ra, rb };
        } else {
            try testing.expectEqualSlices(u8, &first[0][0], &ra[0]);
            try testing.expectEqualSlices(u8, &first[1][1], &rb[1]);
        }
    }
}

// ── contract details found by the mutation run ─────────────────────────────

fn waitStale(io: Io, word: *const u32, returned_at: *u64, sim: *Sim) !void {
    // The value is already 1: a wait expecting 0 must return at once
    // instead of blocking (a lost wakeup otherwise).
    try io.futexWait(u32, word, 0);
    returned_at.* = sim.now;
}

test "a futex wait whose expected value is already stale returns immediately" {
    var sim: Sim = undefined;
    newSim(&sim, 21);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    const word: u32 = 1;
    var at: u64 = std.math.maxInt(u64);
    try h.spawn(waitStale, .{ h.io(), &word, &at, &sim });
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(u64, 0), at);
}

fn wakeEarlyThenSleep(io: Io, word: *const u32, slept_until: *u64, sim: *Sim) !void {
    // Woken at 1 s, long before its 5 s timeout ...
    try io.futexWaitTimeout(u32, word, 0, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    // ... so that timeout must not cut this later sleep short at 5 s.
    try io.sleep(.fromSeconds(10), .awake);
    slept_until.* = sim.now;
}

fn wakeAfter(io: Io, word: *u32) !void {
    try io.sleep(.fromSeconds(1), .awake);
    word.* = 1;
    io.futexWake(u32, word, 1);
}

test "a timeout armed for an earlier wait does not end a later one" {
    var sim: Sim = undefined;
    newSim(&sim, 22);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var word: u32 = 0;
    var until: u64 = 0;
    try h.spawn(wakeEarlyThenSleep, .{ h.io(), &word, &until, &sim });
    try h.spawn(wakeAfter, .{ h.io(), &word });
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(u64, 11 * ns_per_s), until);
}

fn recordStart(order: *std.ArrayList(u8), id: u8) void {
    order.appendAssumeCapacity(id);
}

test "with preemption off, the seed alone still varies the order tasks start in" {
    var orders: std.AutoArrayHashMapUnmanaged(u32, void) = .empty;
    defer orders.deinit(testing.allocator);
    for (0..20) |seed| {
        var sim: Sim = undefined;
        sim.init(testing.allocator, .{ .seed = seed, .preempt_permille = 0, .stack_size = 256 * 1024 });
        defer sim.deinit();
        const h = try sim.addHost(.{});
        var buf: [4]u8 = undefined;
        var order: std.ArrayList(u8) = .initBuffer(&buf);
        for (0..4) |i| try h.spawn(recordStart, .{ &order, @as(u8, @intCast(i)) });
        _ = sim.run();
        try orders.put(testing.allocator, std.mem.readInt(u32, &buf, .little), {});
    }
    try testing.expect(orders.count() > 5);
}
