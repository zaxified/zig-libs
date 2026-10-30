// SPDX-License-Identifier: MIT

//! No-panic sweep regressions (wave GO). Each test names its finding.

const std = @import("std");
const resilience = @import("root.zig");

const testing = std.testing;

const FakeClock = struct {
    ns: u64 = 0,
    fn clock(t: *FakeClock) resilience.Clock {
        return .{ .ctx = t, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const t: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return t.ns;
    }
};

test "Bulkhead.release without a matching acquire is a no-op, not a panic (sweep RS-2)" {
    var b = resilience.Bulkhead.init(.{ .max_concurrent = 2 });
    b.release();
    b.release();
    try testing.expectEqual(@as(u32, 0), b.activeCount());
    // The counter did not go negative/wrap: exactly the cap is admitted.
    try testing.expect(b.tryAcquire());
    try testing.expect(b.tryAcquire());
    try testing.expect(!b.tryAcquire());
    b.release();
    b.release();
    b.release(); // surplus again
    try testing.expectEqual(@as(u32, 0), b.activeCount());
}

test "Retry.nextDelayFrom: attempt 0 reads as attempt 1 (sweep RS-3)" {
    const r: resilience.Retry = .{ .base_delay_ms = 100, .jitter = .none };
    try testing.expectEqual(r.nextDelayFrom(1, null), r.nextDelayFrom(0, null));
    try testing.expectEqual(@as(u64, 100), r.nextDelayFrom(0, null));
    const f: resilience.Retry = .{ .base_delay_ms = 100, .factor = 3.0, .jitter = .none };
    try testing.expectEqual(@as(u64, 100), f.nextDelayFrom(0, null));
    try testing.expectEqual(@as(u64, 100), f.nextDelay(0, null));
}

test "RateCircuitBreaker time window: counters past 2^32 calls in one bucket neither overflow nor trip wrongly (sweep RS-4)" {
    var fc: FakeClock = .{};
    var cb = resilience.RateCircuitBreaker(4).init(.{
        .kind = .time,
        .bucket_ms = 1000,
        .clock = fc.clock(),
    });
    // 2^32 - 1 calls (all successes) already sit in the current bucket 0.
    const full: u64 = std.math.maxInt(u32);
    cb.trip_state.slots[0].calls = full;
    cb.trip_state.calls = full;
    cb.onSuccess(); // u32 `+= 1` overflowed here
    cb.onSuccess();
    try testing.expectEqual(resilience.BreakerState.closed, cb.state());
    // The public snapshot is u32: it saturates instead of truncating.
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), cb.counts().window_calls);
    try testing.expectEqual(@as(u64, full + 2), cb.trip_state.calls);
    // A window failing 1/4 of 2^62 calls must not trip a 50% rule; with the
    // percentage compared in u64 `failures * 100` would overflow.
    cb.trip_state.slots[0].calls = 1 << 62;
    cb.trip_state.calls = 1 << 62;
    cb.trip_state.slots[0].failures = 1 << 60;
    cb.trip_state.failures = 1 << 60;
    cb.onSuccess();
    try testing.expectEqual(resilience.BreakerState.closed, cb.state());
    // And one that really is over the rate does trip.
    cb.trip_state.slots[0].failures = 1 << 62;
    cb.trip_state.failures = 1 << 62;
    cb.onFailure();
    try testing.expectEqual(resilience.BreakerState.open, cb.state());
}

const StuckWait = struct {
    clock: FakeClock = .{},
    sleeps: u32 = 0,
    total_ns: u64 = 0,
    fn delay(w: *StuckWait) resilience.Delay {
        return .{ .ctx = w, .sleepFn = sleepFn };
    }
    fn sleepFn(ctx: ?*anyopaque, ns: u64) void {
        const w: *StuckWait = @ptrCast(@alignCast(ctx.?));
        w.sleeps += 1;
        w.total_ns += ns;
        // Safety net so that a regression fails instead of hanging: after a
        // generous number of polls let the clock finally move.
        if (w.sleeps == 100_000) w.clock.ns = std.math.maxInt(u64) / 2;
    }
};

test "Bulkhead.acquire ends on a clock that never advances (sweep REV-RS-1)" {
    var w: StuckWait = .{};
    var b = resilience.Bulkhead.init(.{
        .max_concurrent = 1,
        .max_wait_ns = 1_000_000,
        .poll_ns = 100_000,
        .clock = w.clock.clock(),
        .delay = w.delay(),
    });
    try b.acquire();
    try testing.expectError(error.BulkheadFull, b.acquire());
    // The budget was spent on requested sleeps alone: ~10 polls, not 100000.
    // Exactly the budget: 1 ms of 100 us polls, not one poll more or less.
    try testing.expectEqual(@as(u32, 10), w.sleeps);
    try testing.expectEqual(@as(u64, 1_000_000), w.total_ns);
    try testing.expectEqual(@as(u32, 1), b.activeCount());
}

test "Retry.expDelayMs with base 0 and a non-2 factor is 0 at huge attempts (sweep REV-RS-2b)" {
    const r: resilience.Retry = .{ .max_attempts = 5000, .base_delay_ms = 0, .factor = 3.0, .max_delay_ms = 30_000, .jitter = .none };
    try testing.expectEqual(@as(u64, 0), r.nextDelay(1000, null));
    try testing.expectEqual(@as(u64, 0), r.nextDelay(1, null));
}

test "time-window breaker built by struct literal with bucket_ms 0 does not divide by zero (sweep REV-RS-4)" {
    var fc: FakeClock = .{ .ns = 5_000_000_000 };
    var cb: resilience.RateCircuitBreaker(4) = .{ .options = .{
        .kind = .time,
        .bucket_ms = 0,
        .minimum_calls = 1,
        .clock = fc.clock(),
    } };
    try testing.expect(cb.allow());
    cb.onFailure();
    cb.onSuccess();
    const c = cb.counts();
    try testing.expectEqual(@as(u64, 1), c.failures);
}

test "counts() on a bucket_ms 0 literal breaker before any record does not divide by zero (sweep REV-RS-4)" {
    var fc: FakeClock = .{ .ns = 5_000_000_000 };
    var cb: resilience.RateCircuitBreaker(4) = .{ .options = .{ .kind = .time, .bucket_ms = 0, .clock = fc.clock() } };
    const c = cb.counts();
    try testing.expectEqual(@as(u32, 0), c.window_calls);
}

test "RateCircuitBreaker: slow-call rate and window counters stay exact past 2^32 (sweep audit GO-RS-1)" {
    var fc: FakeClock = .{};
    var cb = resilience.RateCircuitBreaker(4).init(.{
        .kind = .time,
        .bucket_ms = 1000,
        .failure_rate_pct = 100,
        .slow_call_rate_pct = 50,
        .slow_call_duration_ms = 100,
        .clock = fc.clock(),
    });
    // 25 % slow over 2^62 calls: `slow * 100` overflows u64.
    cb.trip_state.slots[0].calls = 1 << 62;
    cb.trip_state.calls = 1 << 62;
    cb.trip_state.slots[0].slow = 1 << 60;
    cb.trip_state.slow = 1 << 60;
    cb.trip_state.slots[0].failures = 1 << 40;
    cb.trip_state.failures = 1 << 40;
    cb.record(.success, 0);
    try testing.expectEqual(resilience.BreakerState.closed, cb.state());
    // The public snapshot saturates every field instead of truncating.
    const c = cb.counts();
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), c.window_calls);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), c.window_failures);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), c.window_slow);
    // Now over 50 % slow: trips.
    cb.trip_state.slots[0].slow = 1 << 62;
    cb.trip_state.slow = 1 << 62;
    cb.record(.success, 1_000_000_000);
    try testing.expectEqual(resilience.BreakerState.open, cb.state());
}
