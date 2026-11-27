// SPDX-License-Identifier: MIT

//! Tests that kill the survivors of the 2026-11-27 whole-module mutation run.
//! Every expected value comes from the documented contract (the doc comments
//! in root.zig, README), never from running the code.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const r = @import("root.zig");

const ms = std.time.ns_per_ms;

const FakeClock = struct {
    ns: u64 = 0,
    fn clock(t: *FakeClock) r.Clock {
        return .{ .ctx = t, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const t: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return t.ns;
    }
};

// ── forked children: checked panics (a panic cannot be caught in-process) ────

const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const w = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(w) != .SUCCESS) return error.WaitFailed;
        if (w == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

/// The child dies of a panic whose header line carries `needle`.
fn expectPanic(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// Needles live in consts, never inline in the call: the child's stack trace
// prints the caller's source line.
const n_probes = "panic: resilience: half_open_probes must be >= 1";
const n_required = "panic: resilience: half_open_required_successes must be in 1..half_open_probes";
const n_threshold = "panic: resilience: failure_threshold must be >= 1";
const n_rate = "panic: resilience: failure_rate_pct must be in 1..100";
const n_slow_pct = "panic: resilience: slow_call_rate_pct must be in 1..100";
const n_slow_dur = "panic: resilience: slow_call_rate_pct needs slow_call_duration_ms";
const n_bucket = "panic: resilience: bucket_ms must be >= 1";
const n_mincalls = "panic: resilience: minimum_calls must be >= 1";
const n_bulkhead = "panic: resilience: Bulkhead max_concurrent must be >= 1";
const n_factor = "panic: resilience: Retry.factor must be finite and >= 1";
const n_jf = "panic: resilience: Retry.jitter_factor must be in [0, 1]";

const Rate4 = r.RateCircuitBreaker(4);

fn childProbes0() void {
    var p: u32 = 0;
    std.mem.doNotOptimizeAway(&p);
    _ = r.CircuitBreaker.init(.{ .half_open_probes = p });
}
fn childRequired0() void {
    var p: u32 = 2;
    var k: u32 = 0;
    std.mem.doNotOptimizeAway(&p);
    std.mem.doNotOptimizeAway(&k);
    _ = r.CircuitBreaker.init(.{ .half_open_probes = p, .half_open_required_successes = k });
}
fn childRequired3() void {
    var p: u32 = 2;
    var k: u32 = 3;
    std.mem.doNotOptimizeAway(&p);
    std.mem.doNotOptimizeAway(&k);
    _ = r.CircuitBreaker.init(.{ .half_open_probes = p, .half_open_required_successes = k });
}
fn childThreshold0() void {
    var t: u32 = 0;
    std.mem.doNotOptimizeAway(&t);
    _ = r.CircuitBreaker.init(.{ .failure_threshold = t });
}
fn childRate0() void {
    var t: u8 = 0;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .failure_rate_pct = t });
}
fn childRate101() void {
    var t: u8 = 101;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .failure_rate_pct = t });
}
fn childSlowPct0() void {
    var t: u8 = 0;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .slow_call_rate_pct = t, .slow_call_duration_ms = 10 });
}
fn childSlowPct101() void {
    var t: u8 = 101;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .slow_call_rate_pct = t, .slow_call_duration_ms = 10 });
}
fn childSlowPctNoDuration() void {
    var t: u8 = 50;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .slow_call_rate_pct = t });
}
fn childBucket0() void {
    var t: u64 = 0;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .kind = .time, .bucket_ms = t });
}
fn childMinCalls0() void {
    var t: u32 = 0;
    std.mem.doNotOptimizeAway(&t);
    _ = Rate4.init(.{ .minimum_calls = t });
}
fn childBulkhead0() void {
    var t: u32 = 0;
    std.mem.doNotOptimizeAway(&t);
    _ = r.Bulkhead.init(.{ .max_concurrent = t });
}
fn childFactorHalf() void {
    var f: f64 = 0.5;
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .factor = f, .jitter = .none };
    _ = rt.nextDelayFrom(1, null);
}
fn childFactorNegative() void {
    var f: f64 = -2.0;
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .factor = f, .jitter = .none };
    _ = rt.nextDelayFrom(1, null);
}
fn childFactorInf() void {
    var f: f64 = std.math.inf(f64);
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .factor = f, .jitter = .none };
    _ = rt.nextDelayFrom(1, null);
}
fn childFactorNan() void {
    var f: f64 = std.math.nan(f64);
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .factor = f, .jitter = .none };
    _ = rt.nextDelayFrom(1, null);
}
fn childJitterFactor2() void {
    var f: f64 = 2.0;
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .jitter = .proportional, .jitter_factor = f };
    _ = rt.nextDelayFrom(1, 7);
}
fn childJitterFactorNegative() void {
    var f: f64 = -0.25;
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .jitter = .proportional, .jitter_factor = f };
    _ = rt.nextDelayFrom(1, 7);
}
fn childJitterFactorNan() void {
    var f: f64 = std.math.nan(f64);
    std.mem.doNotOptimizeAway(&f);
    const rt: r.Retry = .{ .jitter = .proportional, .jitter_factor = f };
    _ = rt.nextDelayFrom(1, 7);
}

test "mutation 2026-11-27: invalid breaker options are checked panics in every build mode" {
    try expectPanic(childProbes0, n_probes);
    try expectPanic(childRequired0, n_required);
    try expectPanic(childRequired3, n_required);
    try expectPanic(childThreshold0, n_threshold);
    try expectPanic(childRate0, n_rate);
    try expectPanic(childRate101, n_rate);
    try expectPanic(childSlowPct0, n_slow_pct);
    try expectPanic(childSlowPct101, n_slow_pct);
    try expectPanic(childSlowPctNoDuration, n_slow_dur);
    try expectPanic(childBucket0, n_bucket);
    try expectPanic(childMinCalls0, n_mincalls);
    try expectPanic(childBulkhead0, n_bulkhead);
}

test "mutation 2026-11-27: Retry.factor outside the finite range from 1 and jitter_factor outside [0, 1] panic" {
    try expectPanic(childFactorHalf, n_factor);
    try expectPanic(childFactorNegative, n_factor);
    try expectPanic(childFactorInf, n_factor);
    try expectPanic(childFactorNan, n_factor);
    try expectPanic(childJitterFactor2, n_jf);
    try expectPanic(childJitterFactorNegative, n_jf);
    try expectPanic(childJitterFactorNan, n_jf);
}

test "mutation 2026-11-27: the edge values of every option check are valid, not panics" {
    const a: r.CircuitBreaker = .init(.{ .half_open_probes = 2, .half_open_required_successes = 2, .failure_threshold = 1 });
    const b: r.CircuitBreaker = .init(.{ .half_open_probes = 2, .half_open_required_successes = 1 });
    const c1 = Rate4.init(.{ .failure_rate_pct = 1, .slow_call_rate_pct = 1, .slow_call_duration_ms = 5 });
    const c2 = Rate4.init(.{ .failure_rate_pct = 100, .slow_call_rate_pct = 100, .slow_call_duration_ms = 5 });
    // bucket_ms = 1 is the smallest valid bucket; bucket_ms = 0 is only a time-mode error.
    const c3 = Rate4.init(.{ .kind = .time, .bucket_ms = 1, .minimum_calls = 1 });
    const c4 = Rate4.init(.{ .kind = .count, .bucket_ms = 0 });
    try testing.expectEqual(.closed, a.cur_state);
    try testing.expectEqual(.closed, b.cur_state);
    try testing.expectEqual(.closed, c1.cur_state);
    try testing.expectEqual(.closed, c2.cur_state);
    try testing.expectEqual(.closed, c3.cur_state);
    try testing.expectEqual(.closed, c4.cur_state);
    var bh = r.Bulkhead.init(.{ .max_concurrent = 1 });
    try testing.expect(bh.tryAcquire());
    // factor 1.0 and the jitter_factor ends are valid.
    const rt: r.Retry = .{ .factor = 1.0, .jitter = .proportional, .jitter_factor = 0.0 };
    try testing.expectEqual(@as(u64, 100), rt.nextDelayFrom(5, 3));
    const rt1: r.Retry = .{ .jitter = .proportional, .jitter_factor = 1.0 };
    _ = rt1.nextDelayFrom(1, 3);
}

// ── half-open probe accounting ───────────────────────────────────────────────

test "mutation 2026-11-27: BreakerHandle.timesCalls is true exactly when slow_call_duration_ms is set" {
    var a: r.CircuitBreaker = .init(.{});
    var b: r.CircuitBreaker = .init(.{ .slow_call_duration_ms = 10 });
    var c = Rate4.init(.{});
    var d = Rate4.init(.{ .slow_call_duration_ms = 10 });
    try testing.expect(!a.handle().timesCalls());
    try testing.expect(b.handle().timesCalls());
    try testing.expect(!c.handle().timesCalls());
    try testing.expect(d.handle().timesCalls());
}

/// Breaker half-open with probes = 2, required = 1, one probe admitted and
/// failed: undecided (2 - 1 failed >= 1 needed), no probe outstanding.
fn undecidedHalfOpen(fc: *FakeClock) r.CircuitBreaker {
    var cb: r.CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 1000,
        .half_open_probes = 2,
        .half_open_required_successes = 1,
        .clock = fc.clock(),
    });
    cb.onFailure();
    fc.ns += 1000 * ms;
    if (!cb.allow()) @panic("setup: the probe was refused");
    cb.onFailure();
    return cb;
}

test "mutation 2026-11-27: a result nobody is waiting for does not decide a half-open breaker" {
    var fc: FakeClock = .{};
    var cb = undecidedHalfOpen(&fc);
    try testing.expectEqual(.half_open, cb.state());
    // The only admitted probe has reported; a stray success is no verdict.
    cb.onSuccess();
    try testing.expectEqual(.half_open, cb.state());
    cb.onFailure();
    try testing.expectEqual(.half_open, cb.state());
}

test "mutation 2026-11-27: ignore with no probe outstanding releases nothing" {
    var fc: FakeClock = .{};
    var cb = undecidedHalfOpen(&fc);
    cb.record(.ignore, null);
    // One slot of the two is still free, exactly one.
    try testing.expect(cb.allow());
    try testing.expect(!cb.allow());
}

test "mutation 2026-11-27: abandonProbe is a no-op once the breaker closed, whatever probes were admitted" {
    var fc: FakeClock = .{};
    var cb: r.CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 1000,
        .half_open_probes = 3,
        .half_open_required_successes = 1,
        .clock = fc.clock(),
    });
    cb.onFailure();
    fc.ns += 1000 * ms;
    try testing.expect(cb.allow());
    try testing.expect(cb.allow());
    try testing.expect(cb.allow());
    cb.onSuccess(); // one success of the one required: closed, two probes unreported
    try testing.expectEqual(.closed, cb.state());
    try testing.expect(!cb.abandonProbe());
    try testing.expectEqual(.closed, cb.state());
}

// ── RateCircuitBreaker ───────────────────────────────────────────────────────

test "mutation 2026-11-27: count window default minimum is a full window, time window default is one call" {
    var fc: FakeClock = .{};
    var cnt = Rate4.init(.{ .clock = fc.clock() });
    cnt.onFailure();
    cnt.onFailure();
    cnt.onFailure();
    try testing.expectEqual(.closed, cnt.state()); // 3 of 4 calls: no verdict yet
    cnt.onFailure();
    try testing.expectEqual(.open, cnt.state());

    // README / the option doc name `n` as the count default only; the time
    // default is the module's own 1: a failing bucket trips at once.
    var tm = Rate4.init(.{ .kind = .time, .bucket_ms = 1000, .clock = fc.clock() });
    tm.onFailure();
    try testing.expectEqual(.open, tm.state());
}

test "mutation 2026-11-27: a clock that reads earlier than before never panics a time window" {
    // `clock.monotonicNs` returns 0 on a clock_gettime error (see
    // Bulkhead.acquire), so a clock can step back; the window just stays.
    var fc: FakeClock = .{};
    var cb = Rate4.init(.{ .kind = .time, .bucket_ms = 1000, .minimum_calls = 100, .clock = fc.clock() });
    fc.ns = 5_000 * ms;
    cb.onSuccess();
    fc.ns = 0;
    cb.onSuccess();
    const c = cb.counts();
    try testing.expectEqual(.closed, c.state);
    try testing.expect(c.window_calls >= 1);
    try testing.expectEqual(@as(u64, 2), c.successes);
}

test "mutation 2026-11-27: concurrent onSuccess from eight threads loses no count" {
    const n_threads = 8;
    const iters = 50_000;
    var cb: r.CircuitBreaker = .init(.{});
    const Worker = struct {
        fn run(b: *r.CircuitBreaker) void {
            for (0..iters) |_| b.onSuccess();
        }
    };
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{&cb});
    for (handles) |h| h.join();
    try testing.expectEqual(@as(u64, n_threads * iters), cb.counts().successes);
}

// ── Bulkhead bounded wait ────────────────────────────────────────────────────

/// A virtual delay whose sleeps advance the shared clock by `mult` times the
/// requested duration (an OS that oversleeps; 0 = a clock that never moves)
/// and frees a slot on the `release_at`-th sleep. After 1000 sleeps it jumps
/// the clock so a mutant that never ends does not hang the run.
const WaitDelay = struct {
    clk: *FakeClock,
    bh: *r.Bulkhead,
    mult: u64,
    release_at: usize = 0,
    calls: usize = 0,
    last_ns: u64 = 0,

    fn delay(t: *WaitDelay) r.Delay {
        return .{ .ctx = t, .sleepFn = sleepFn };
    }
    fn sleepFn(ctx: ?*anyopaque, ns: u64) void {
        const t: *WaitDelay = @ptrCast(@alignCast(ctx.?));
        t.calls += 1;
        t.last_ns = ns;
        t.clk.ns += ns * t.mult;
        if (t.calls == t.release_at) t.bh.release();
        if (t.calls > 1000) t.clk.ns = std.math.maxInt(u64) / 2;
    }
};

test "mutation 2026-11-27: the bounded wait ends when the clock passes the deadline, even with budget unslept" {
    var fc: FakeClock = .{};
    var bh = r.Bulkhead.init(.{ .max_concurrent = 1 });
    var wd: WaitDelay = .{ .clk = &fc, .bh = &bh, .mult = 50, .release_at = 2 };
    bh = r.Bulkhead.init(.{
        .max_concurrent = 1,
        .max_wait_ns = 1 * ms,
        .poll_ns = 100 * std.time.ns_per_us,
        .clock = fc.clock(),
        .delay = wd.delay(),
    });
    try testing.expect(bh.tryAcquire());
    // One poll oversleeps to 5 ms, past the 1 ms deadline: no second poll.
    try testing.expectError(error.BulkheadFull, bh.acquire());
    try testing.expectEqual(@as(usize, 1), wd.calls);
}

test "mutation 2026-11-27: the bounded wait ends when the clock is exactly on the deadline" {
    var fc: FakeClock = .{};
    var bh = r.Bulkhead.init(.{ .max_concurrent = 1 });
    var wd: WaitDelay = .{ .clk = &fc, .bh = &bh, .mult = 2, .release_at = 2 };
    bh = r.Bulkhead.init(.{
        .max_concurrent = 1,
        .max_wait_ns = 200 * std.time.ns_per_us,
        .poll_ns = 100 * std.time.ns_per_us,
        .clock = fc.clock(),
        .delay = wd.delay(),
    });
    try testing.expect(bh.tryAcquire());
    // The first poll sleeps 100 us and the clock moves 200 us: now == deadline.
    try testing.expectError(error.BulkheadFull, bh.acquire());
    try testing.expectEqual(@as(usize, 1), wd.calls);
}

test "mutation 2026-11-27: poll_ns = 0 still sleeps at least 1 ns per poll, so a stuck clock ends the wait" {
    var fc: FakeClock = .{};
    var bh = r.Bulkhead.init(.{ .max_concurrent = 1 });
    var wd: WaitDelay = .{ .clk = &fc, .bh = &bh, .mult = 0 };
    bh = r.Bulkhead.init(.{
        .max_concurrent = 1,
        .max_wait_ns = 50,
        .poll_ns = 0,
        .clock = fc.clock(),
        .delay = wd.delay(),
    });
    try testing.expect(bh.tryAcquire());
    try testing.expectError(error.BulkheadFull, bh.acquire());
    // 50 ns of budget in 1 ns sleeps.
    try testing.expectEqual(@as(usize, 50), wd.calls);
    try testing.expectEqual(@as(u64, 1), wd.last_ns);
}

// ── Retry schedule ───────────────────────────────────────────────────────────

test "mutation 2026-11-27: a .none schedule draws nothing from the random source" {
    var prng = std.Random.DefaultPrng.init(1234);
    var before = prng;
    const rt: r.Retry = .{ .jitter = .none, .base_delay_ms = 100 };
    try testing.expectEqual(@as(u64, 100), rt.nextDelay(1, prng.random()));
    try testing.expectEqual(@as(u64, 200), rt.nextDelay(2, prng.random()));
    try testing.expectEqual(before.random().int(u64), prng.random().int(u64));
}

test "mutation 2026-11-27: nextDelayFrom with bits and .none is the plain schedule" {
    const rt: r.Retry = .{ .jitter = .none, .base_delay_ms = 100 };
    try testing.expectEqual(@as(u64, 200), rt.nextDelayFrom(2, 0xdead_beef));
    try testing.expectEqual(@as(u64, 400), rt.nextDelayFrom(3, std.math.maxInt(u64)));
}

test "mutation 2026-11-27: full jitter spans [0, d] inclusive, equal jitter [d/2, d] with d odd" {
    const max = std.math.maxInt(u64);
    const full: r.Retry = .{ .jitter = .full, .base_delay_ms = 100 };
    try testing.expectEqual(@as(u64, 0), full.nextDelayFrom(1, 0));
    try testing.expectEqual(@as(u64, 100), full.nextDelayFrom(1, max));
    const eq: r.Retry = .{ .jitter = .equal, .base_delay_ms = 5 };
    try testing.expectEqual(@as(u64, 2), eq.nextDelayFrom(1, 0));
    try testing.expectEqual(@as(u64, 5), eq.nextDelayFrom(1, max));
}

test "mutation 2026-11-27: proportional jitter spans [d(1-f), d(1+f)]" {
    const max = std.math.maxInt(u64);
    const p: r.Retry = .{ .jitter = .proportional, .jitter_factor = 0.5, .base_delay_ms = 100 };
    try testing.expectEqual(@as(u64, 50), p.nextDelayFrom(1, 0));
    try testing.expectEqual(@as(u64, 150), p.nextDelayFrom(1, max));
}

test "mutation 2026-11-27: proportional jitter of a delay whose f64 rounds above it cannot underflow" {
    // d = 2^60 + 129 rounds to 2^60 + 256 as an f64, so with f = 1 the
    // computed spread exceeds d; the lower end d(1-f) is 0.
    const d: u64 = (1 << 60) + 129;
    const p: r.Retry = .{ .jitter = .proportional, .jitter_factor = 1.0, .base_delay_ms = d, .max_delay_ms = std.math.maxInt(u64) };
    try testing.expectEqual(@as(u64, 0), p.nextDelayFrom(1, 0));
}

test "mutation 2026-11-27: the factor-2 schedule is exact for a base above 2^53 and caps on overflow" {
    const big: u64 = (1 << 53) + 1;
    const rt: r.Retry = .{ .jitter = .none, .base_delay_ms = big, .max_delay_ms = std.math.maxInt(u64) };
    try testing.expectEqual(big, rt.nextDelayFrom(1, null));
    const three: r.Retry = .{ .jitter = .none, .base_delay_ms = 3, .max_delay_ms = std.math.maxInt(u64) };
    // 3 * 2^63 does not fit in u64: the delay is the cap.
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), three.nextDelayFrom(64, null));
    // The shift count 64 and beyond is the cap as well.
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), three.nextDelayFrom(65, null));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), three.nextDelayFrom(1000, null));
}

test "mutation 2026-11-27: a float schedule landing exactly on 2^64 is the cap" {
    // 1 * 4^32 = 2^64 = (f64) maxInt(u64): at or beyond the cap -> the cap.
    const rt: r.Retry = .{ .jitter = .none, .base_delay_ms = 1, .factor = 4.0, .max_delay_ms = std.math.maxInt(u64) };
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), rt.nextDelayFrom(33, null));
}

// ── run ──────────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: setDeadline is handed to the operation only when a timeout is set" {
    const Op = struct {
        set: u32 = 0,
        pub fn call(_: *@This()) error{Boom}!u32 {
            return 1;
        }
        pub fn setDeadline(self: *@This(), _: r.Deadline) void {
            self.set += 1;
        }
    };
    var fc: FakeClock = .{};
    var op: Op = .{};
    _ = try r.run(&op, .{ .clock = fc.clock() });
    try testing.expectEqual(@as(u32, 0), op.set);
    _ = try r.run(&op, .{ .clock = fc.clock(), .timeout_ms = 100 });
    try testing.expectEqual(@as(u32, 1), op.set);
}

test "mutation 2026-11-27: an operation's own error.Timeout is recorded once per attempt" {
    const Op = struct {
        pub fn call(_: *@This()) error{Timeout}!u32 {
            return error.Timeout;
        }
    };
    var fc: FakeClock = .{};
    var cb: r.CircuitBreaker = .init(.{ .failure_threshold = 5, .clock = fc.clock() });
    var op: Op = .{};
    try testing.expectError(error.Timeout, r.run(&op, .{ .breaker = cb.handle(), .clock = fc.clock() }));
    const c = cb.counts();
    try testing.expectEqual(@as(u64, 1), c.failures);
    try testing.expectEqual(@as(u32, 1), c.consecutive_failures);
}

fn neverRetry(_: anyerror) bool {
    return false;
}

const ResultOp = struct {
    calls: u32 = 0,
    pub fn call(self: *ResultOp) error{Boom}!u32 {
        self.calls += 1;
        return self.calls;
    }
    pub fn retryOnResult(_: *ResultOp, v: *const u32) bool {
        return v.* < 2;
    }
};

test "mutation 2026-11-27: a result the operation asks to retry is retried whatever retryable says of errors" {
    var fc: FakeClock = .{};
    var op: ResultOp = .{};
    const v = try r.run(&op, .{
        .clock = fc.clock(),
        .delay = .none,
        .retry = .{ .max_attempts = 3, .base_delay_ms = 0, .jitter = .none, .retryable = &neverRetry },
    });
    try testing.expectEqual(@as(u32, 2), v);
    try testing.expectEqual(@as(u32, 2), op.calls);
}

const FailOp = struct {
    calls: u32 = 0,
    pub fn call(self: *FailOp) error{Boom}!u32 {
        self.calls += 1;
        return error.Boom;
    }
};

test "mutation 2026-11-27: a retry whose wait ends exactly at the total budget is made" {
    var fc: FakeClock = .{};
    var op: FailOp = .{};
    try testing.expectError(error.Boom, r.run(&op, .{
        .clock = fc.clock(),
        .delay = .none,
        .retry = .{ .max_attempts = 2, .base_delay_ms = 50, .jitter = .none, .max_elapsed_ms = 50 },
    }));
    try testing.expectEqual(@as(u32, 2), op.calls);
}

const Events = struct {
    n: usize = 0,
    failure: [4]?anyerror = @splat(null),
    delay_ms: [4]u64 = @splat(99),
    fn on(ctx: ?*anyopaque, _: u32, failure: ?anyerror, delay_ms: u64) void {
        const e: *Events = @ptrCast(@alignCast(ctx.?));
        e.failure[e.n] = failure;
        e.delay_ms[e.n] = delay_ms;
        e.n += 1;
    }
};

test "mutation 2026-11-27: on_retry gets the error, or null for a retried result, and the wait" {
    var fc: FakeClock = .{};
    var ev: Events = .{};
    var fail: FailOp = .{};
    try testing.expectError(error.Boom, r.run(&fail, .{
        .clock = fc.clock(),
        .delay = .none,
        .retry = .{ .max_attempts = 2, .base_delay_ms = 7, .jitter = .none },
        .on_retry = .{ .ctx = &ev, .onRetry = Events.on },
    }));
    try testing.expectEqual(@as(usize, 1), ev.n);
    try testing.expectEqual(@as(?anyerror, error.Boom), ev.failure[0]);
    try testing.expectEqual(@as(u64, 7), ev.delay_ms[0]);

    var ev2: Events = .{};
    var res: ResultOp = .{};
    _ = try r.run(&res, .{
        .clock = fc.clock(),
        .delay = .none,
        .retry = .{ .max_attempts = 3, .base_delay_ms = 0, .jitter = .none },
        .on_retry = .{ .ctx = &ev2, .onRetry = Events.on },
    });
    try testing.expectEqual(@as(usize, 1), ev2.n);
    try testing.expectEqual(@as(?anyerror, null), ev2.failure[0]);
    try testing.expectEqual(@as(u64, 0), ev2.delay_ms[0]);
}

const CountSleep = struct {
    n: usize = 0,
    fn delay(t: *CountSleep) r.Delay {
        return .{ .ctx = t, .sleepFn = sleepFn };
    }
    fn sleepFn(ctx: ?*anyopaque, _: u64) void {
        const t: *CountSleep = @ptrCast(@alignCast(ctx.?));
        t.n += 1;
    }
};

test "mutation 2026-11-27: a zero wait between attempts does not call the Delay" {
    var fc: FakeClock = .{};
    var cs: CountSleep = .{};
    var op: FailOp = .{};
    try testing.expectError(error.Boom, r.run(&op, .{
        .clock = fc.clock(),
        .delay = cs.delay(),
        .retry = .{ .max_attempts = 3, .base_delay_ms = 0, .jitter = .none },
    }));
    try testing.expectEqual(@as(u32, 3), op.calls);
    try testing.expectEqual(@as(usize, 0), cs.n);
    // and a non-zero wait does
    var op2: FailOp = .{};
    try testing.expectError(error.Boom, r.run(&op2, .{
        .clock = fc.clock(),
        .delay = cs.delay(),
        .retry = .{ .max_attempts = 2, .base_delay_ms = 5, .jitter = .none },
    }));
    try testing.expectEqual(@as(usize, 1), cs.n);
}

// ── the blocking delay ───────────────────────────────────────────────────────

test "mutation 2026-11-27: Delay.blocking sleeps whole seconds and the remainder (about 1.03 s of real time)" {
    const want: u64 = 1_030_000_000;
    const t0 = r.Clock.monotonic.now();
    r.Delay.blocking.sleep(want);
    const dt = r.Clock.monotonic.now() - t0;
    try testing.expect(dt >= want);
    try testing.expect(dt < want + 500 * ms);
}
