// SPDX-License-Identifier: MIT

//! Model-based fuzzing for `resilience` (2026-10-16): each harness drives the
//! real implementation and a deliberately naive reference model with the
//! same script and compares every observable after every step.
//!
//! - `resilience-breaker` — `CircuitBreaker`, `RateCircuitBreaker` in count
//!   and time mode: a script of clock advances, `allow`, `record` (success /
//!   failure / ignore, with or without a duration), `abandonProbe`, `reset`,
//!   `forceOpen`, `disable`. The model keeps every call it was told about in
//!   a plain list and recounts the window from scratch at each verdict (the
//!   implementation keeps running sums in a ring of buckets), and replays the
//!   state machine from the SPEC's wording. Compared: every `allow()` answer,
//!   `state()`, `mode()`, all of `counts()`, and the listener's transition
//!   sequence.
//! - `resilience-retry` — `Retry.nextDelay`: the un-jittered schedule exactly,
//!   against a rational model (`base × num^k / den^k`, floored, capped) over
//!   factors that are exact in binary; every jitter flavour within its
//!   bounds; one seed, one sequence.
//! - `resilience-run` — `run` against an interpreter of the documented
//!   composition: a scripted operation (values, retryable and fatal errors,
//!   slow calls, results to retry, Retry-After), a scripted fake breaker
//!   behind `BreakerHandle` that logs what it is told, a bulkhead, a
//!   timeout, a total budget, `classify`, `on_retry`, a virtual clock that
//!   the operation's own duration and every wait advance. Compared: the
//!   result, the calls made, the waits, the breaker's log, the retry
//!   events, the bulkhead returned to zero.
//!
//! Driver: `RESILIENCE_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_ONLY` picks a harness by name).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const r = @import("root.zig");
const fuzz_driver = testkit.fuzz.driver;
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

/// Reach counters for one harness's labels (the same plumbing as aescbc's).
fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        fn mark(l: Label) void {
            counts[@intFromEnum(l)] += 1;
            switch (l) {
                inline else => |c| fuzz_driver.hit(@tagName(c)),
            }
        }

        fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: Rng = .{ .r = prng.random() };
                harness(Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

const VClock = struct {
    ns: u64 = 1_000_000_000,
    fn now(ctx: ?*anyopaque) u64 {
        return @as(*VClock, @ptrCast(@alignCast(ctx.?))).ns;
    }
    fn clock(c: *VClock) r.Clock {
        return .{ .ctx = c, .nowFn = now };
    }
    fn sleep(ctx: ?*anyopaque, ns: u64) void {
        @as(*VClock, @ptrCast(@alignCast(ctx.?))).ns += ns;
    }
    fn delay(c: *VClock) r.Delay {
        return .{ .ctx = c, .sleepFn = sleep };
    }
};

const ms = std.time.ns_per_ms;

// ── breaker ─────────────────────────────────────────────────────────────

const BreakerMark = Marker(enum {
    consecutive,
    rate_count,
    rate_time,
    tripped,
    probed,
    closed_again,
    reopened,
    partial_success_close,
    slow_trip,
    slow_probe_failed,
    ignored_probe,
    reclaimed,
    abandoned,
    forced_open,
    disabled,
    window_expired,
});

const Kind = enum { consecutive, count, time };

const Event = struct { at: u64, failed: bool, slow: bool };

/// The reference: a plain struct and if/else straight from the SPEC text.
const Model = struct {
    kind: Kind,
    // options
    threshold: u32,
    cooldown_ms: u64,
    probes: u32,
    required: u32,
    probe_timeout_ms: u64, // 0 = no reclaim
    slow_ms: ?u64,
    n: u32,
    bucket_ms: u64,
    min_calls: u32,
    rate_pct: u32,
    slow_pct: ?u32,
    // state
    state: r.BreakerState = .closed,
    mode: r.Mode = .normal,
    streak: u32 = 0,
    events: [256]Event = undefined,
    n_events: usize = 0,
    opened_at: u64 = 0,
    admitted: u32 = 0,
    succ: u32 = 0,
    failed: u32 = 0,
    last_admit: u64 = 0,
    totals: r.Counts = .{ .state = .closed, .mode = .normal },
    transitions: [256][2]r.BreakerState = undefined,
    n_tr: usize = 0,

    fn visible(m: *const Model) r.BreakerState {
        return switch (m.mode) {
            .normal => m.state,
            .forced_open => .open,
            .disabled => .closed,
        };
    }

    fn move(m: *Model, to: r.BreakerState) void {
        if (m.state == to) return;
        m.transitions[m.n_tr] = .{ m.state, to };
        m.n_tr += 1;
        m.totals.transitions += 1;
        m.state = to;
    }

    fn clearWindow(m: *Model) void {
        m.streak = 0;
        m.n_events = 0;
    }

    fn tripAt(m: *Model, now: u64) void {
        m.move(.open);
        m.opened_at = now;
        m.clearWindow();
    }

    /// The calls inside the window as of `now` (recounted from scratch).
    fn window(m: *const Model, now: u64) struct { calls: u32, failures: u32, slow: u32 } {
        var calls: u32 = 0;
        var failures: u32 = 0;
        var slow: u32 = 0;
        const start: usize = switch (m.kind) {
            .consecutive => m.n_events,
            .count => m.n_events -| m.n,
            .time => 0,
        };
        const cur_epoch = now / (m.bucket_ms * ms);
        for (m.events[start..m.n_events]) |e| {
            if (m.kind == .time and e.at / (m.bucket_ms * ms) + m.n <= cur_epoch) continue;
            calls += 1;
            if (e.failed) failures += 1;
            if (e.slow) slow += 1;
        }
        return .{ .calls = calls, .failures = failures, .slow = slow };
    }

    fn allow(m: *Model, now: u64) bool {
        switch (m.mode) {
            .disabled => return true,
            .forced_open => {
                m.totals.not_permitted += 1;
                return false;
            },
            .normal => {},
        }
        switch (m.state) {
            .closed => return true,
            .open => {
                if (now - m.opened_at < m.cooldown_ms * ms) {
                    m.totals.not_permitted += 1;
                    return false;
                }
                m.move(.half_open);
                m.admitted = 1;
                m.succ = 0;
                m.failed = 0;
                m.last_admit = now;
                return true;
            },
            .half_open => {
                const pending = m.admitted - m.succ - m.failed;
                if (m.probe_timeout_ms != 0 and pending > 0 and now - m.last_admit >= m.probe_timeout_ms * ms)
                    m.admitted = m.succ + m.failed;
                if (m.admitted >= m.probes) {
                    m.totals.not_permitted += 1;
                    return false;
                }
                m.admitted += 1;
                m.last_admit = now;
                return true;
            },
        }
    }

    fn record(m: *Model, now: u64, o: r.Outcome, dur: ?u64) void {
        const slow = o != .ignore and m.slow_ms != null and dur != null and dur.? > m.slow_ms.? * ms;
        switch (o) {
            .success => m.totals.successes += 1,
            .failure => m.totals.failures += 1,
            .ignore => m.totals.ignored += 1,
        }
        if (slow) m.totals.slow += 1;
        if (m.mode != .normal) return;
        switch (m.state) {
            .open => {},
            .closed => {
                if (o == .ignore) return;
                const failed = o == .failure;
                if (m.kind == .consecutive) {
                    if (!failed) {
                        m.streak = 0;
                    } else {
                        m.streak += 1;
                        if (m.streak >= m.threshold) m.tripAt(now);
                    }
                    return;
                }
                m.events[m.n_events] = .{ .at = now, .failed = failed, .slow = slow };
                m.n_events += 1;
                const w = m.window(now);
                if (w.calls < m.min_calls) return;
                const trip_fail = w.failures * 100 >= m.rate_pct * w.calls;
                const trip_slow = if (m.slow_pct) |p| w.slow * 100 >= p * w.calls else false;
                if (trip_fail or trip_slow) {
                    if (trip_slow and !trip_fail) BreakerMark.mark(.slow_trip);
                    m.tripAt(now);
                }
            },
            .half_open => {
                const pending = m.admitted - m.succ - m.failed;
                if (o == .ignore) {
                    if (pending > 0) {
                        m.admitted -= 1;
                        BreakerMark.mark(.ignored_probe);
                    }
                    return;
                }
                if (pending == 0) return;
                if (o == .success and !slow) m.succ += 1 else {
                    m.failed += 1;
                    if (o == .success) BreakerMark.mark(.slow_probe_failed);
                }
                if (m.succ >= m.required) {
                    m.move(.closed);
                    m.clearWindow();
                    if (m.failed > 0) BreakerMark.mark(.partial_success_close);
                } else if (m.probes - m.failed < m.required) {
                    m.tripAt(now);
                }
            },
        }
    }

    fn abandon(m: *Model) bool {
        if (m.mode != .normal or m.state != .half_open) return false;
        if (m.admitted - m.succ - m.failed == 0) return false;
        m.admitted -= 1;
        return true;
    }

    fn setMode(m: *Model, mode: r.Mode) void {
        const before = m.visible();
        m.mode = mode;
        m.state = .closed;
        m.clearWindow();
        m.admitted = 0;
        m.succ = 0;
        m.failed = 0;
        const after = m.visible();
        if (before != after) {
            m.transitions[m.n_tr] = .{ before, after };
            m.n_tr += 1;
            m.totals.transitions += 1;
        }
    }

    fn counts(m: *const Model, now: u64) r.Counts {
        var c = m.totals;
        c.state = m.visible();
        c.mode = m.mode;
        if (m.mode == .normal and m.state == .closed) {
            if (m.kind == .consecutive) {
                c.consecutive_failures = m.streak;
            } else {
                const w = m.window(now);
                c.window_calls = w.calls;
                c.window_failures = w.failures;
                c.window_slow = w.slow;
            }
        }
        return c;
    }
};

const Log = struct {
    tr: [256][2]r.BreakerState = undefined,
    n: usize = 0,
    fn on(ctx: ?*anyopaque, from: r.BreakerState, to: r.BreakerState) void {
        const l: *Log = @ptrCast(@alignCast(ctx.?));
        l.tr[l.n] = .{ from, to };
        l.n += 1;
    }
};

fn breakerSmith(_: void, s: *testing.Smith) !void {
    return fuzzBreaker(testing.Smith, s, testing.allocator);
}
test "fuzz: breakers agree with the reference model, step by step" {
    try testing.fuzz({}, breakerSmith, .{});
}
test "fuzz driver: RESILIENCE_FUZZ (breaker)" {
    try fuzz_driver.run(fuzzBreaker, .{ .prefix = "RESILIENCE_FUZZ", .name = "resilience-breaker" });
}
test "fuzz harness: breaker, 600 seeds, reaches every outcome" {
    try BreakerMark.reach(fuzzBreaker, "resilience-breaker", 600);
}

fn fuzzBreaker(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [512]u8 = undefined;
    const len: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..len] };
    switch (k.ranged(0, 2)) {
        0 => {
            BreakerMark.mark(.consecutive);
            try breakerCase(r.CircuitBreaker, .consecutive, &k);
        },
        1 => {
            BreakerMark.mark(.rate_count);
            try breakerCase(r.RateCircuitBreaker(6), .count, &k);
        },
        else => {
            BreakerMark.mark(.rate_time);
            try breakerCase(r.RateCircuitBreaker(4), .time, &k);
        },
    }
}

fn breakerCase(comptime B: type, comptime kind: Kind, k: *Cursor) !void {
    var vc: VClock = .{};
    var log: Log = .{};
    const probes = k.ranged(1, 3);
    const required: ?u32 = if (k.byte() & 1 == 0) null else k.ranged(1, probes);
    const probe_timeout: ?u64 = switch (k.ranged(0, 3)) {
        0 => null,
        1 => 0,
        else => k.ranged(5, 40),
    };
    const cooldown = k.ranged(1, 50);
    const slow_ms: ?u64 = if (k.byte() & 1 == 0) null else k.ranged(2, 20);
    var m: Model = .{
        .kind = kind,
        .threshold = k.ranged(1, 4),
        .cooldown_ms = cooldown,
        .probes = probes,
        .required = required orelse probes,
        .probe_timeout_ms = probe_timeout orelse cooldown,
        .slow_ms = slow_ms,
        .n = if (kind == .count) 6 else 4,
        .bucket_ms = k.ranged(3, 15),
        .min_calls = k.ranged(1, 7),
        .rate_pct = k.ranged(1, 100),
        .slow_pct = if (slow_ms != null and k.byte() & 1 == 0) k.ranged(1, 100) else null,
    };
    const listener: r.StateListener = .{ .ctx = &log, .onStateChange = Log.on };
    var b: B = if (kind == .consecutive) .init(.{
        .failure_threshold = m.threshold,
        .cooldown_ms = m.cooldown_ms,
        .half_open_probes = probes,
        .half_open_required_successes = required,
        .probe_timeout_ms = probe_timeout,
        .slow_call_duration_ms = slow_ms,
        .clock = vc.clock(),
        .listener = listener,
    }) else .init(.{
        .kind = if (kind == .count) .count else .time,
        .bucket_ms = m.bucket_ms,
        .minimum_calls = m.min_calls,
        .failure_rate_pct = @intCast(m.rate_pct),
        .slow_call_rate_pct = if (m.slow_pct) |p| @intCast(p) else null,
        .cooldown_ms = m.cooldown_ms,
        .half_open_probes = probes,
        .half_open_required_successes = required,
        .probe_timeout_ms = probe_timeout,
        .slow_call_duration_ms = slow_ms,
        .clock = vc.clock(),
        .listener = listener,
    });

    const steps = k.ranged(10, 120);
    for (0..steps) |_| {
        const before = m.visible();
        const before_tr = m.n_tr;
        switch (k.ranged(0, 15)) {
            0...2 => {
                // Edge-biased clock steps: 0, the cooldown and probe-timeout
                // edges, a bucket, a whole window.
                const dt: u64 = switch (k.ranged(0, 7)) {
                    0 => 0,
                    1 => 1,
                    2 => m.cooldown_ms * ms - 1,
                    3 => m.cooldown_ms * ms,
                    4 => m.probe_timeout_ms * ms,
                    5 => m.bucket_ms * ms,
                    6 => m.bucket_ms * ms * m.n,
                    else => @as(u64, k.ranged(0, 30)) * ms,
                };
                const old_epoch = vc.ns / (m.bucket_ms * ms);
                vc.ns += dt;
                if (kind == .time and vc.ns / (m.bucket_ms * ms) >= old_epoch + m.n and m.n_events > 0) BreakerMark.mark(.window_expired);
            },
            3...6 => {
                const want = m.allow(vc.ns);
                if (b.allow() != want) return error.AllowDiffers;
                if (want and before == .open) BreakerMark.mark(.probed);
            },
            7...11 => {
                const o: r.Outcome = switch (k.ranged(0, 5)) {
                    0, 1 => .success,
                    2, 3, 4 => .failure,
                    else => .ignore,
                };
                const dur: ?u64 = if (k.byte() & 1 == 0) null else @as(u64, k.ranged(0, 25)) * ms;
                m.record(vc.ns, o, dur);
                b.record(o, dur);
            },
            12 => {
                const pending = m.admitted - m.succ - m.failed;
                const want = m.abandon();
                if (b.abandonProbe() != want) return error.AbandonDiffers;
                if (want and pending > 0) BreakerMark.mark(.abandoned);
            },
            13 => {
                m.setMode(.normal);
                b.reset();
            },
            14 => {
                m.setMode(.forced_open);
                b.forceOpen();
                BreakerMark.mark(.forced_open);
            },
            else => {
                m.setMode(.disabled);
                b.disable();
                BreakerMark.mark(.disabled);
            },
        }
        // Reclaim is observable through the next allow(); mark when the model
        // would reclaim now.
        if (m.mode == .normal and m.state == .half_open and m.probe_timeout_ms != 0 and
            m.admitted > m.succ + m.failed and vc.ns - m.last_admit >= m.probe_timeout_ms * ms)
            BreakerMark.mark(.reclaimed);
        for (m.transitions[before_tr..m.n_tr]) |t| {
            if (t[1] == .open and t[0] == .closed and m.mode == .normal) BreakerMark.mark(.tripped);
            if (t[0] == .half_open and t[1] == .closed) BreakerMark.mark(.closed_again);
            if (t[0] == .half_open and t[1] == .open) BreakerMark.mark(.reopened);
        }

        if (b.state() != m.visible()) return error.StateDiffers;
        if (b.mode() != m.mode) return error.ModeDiffers;
        const got = b.counts();
        const want = m.counts(vc.ns);
        if (!std.meta.eql(got, want)) {
            std.debug.print("counts: got {any}\n  want {any}\n", .{ got, want });
            return error.CountsDiffer;
        }
        if (log.n != m.n_tr) return error.TransitionCountDiffers;
        for (log.tr[0..log.n], m.transitions[0..m.n_tr]) |a, e| {
            if (a[0] != e[0] or a[1] != e[1]) return error.TransitionDiffers;
        }
        if (m.n_events > 200 or m.n_tr > 200) break;
    }
}

// ── retry delays ────────────────────────────────────────────────────────

const RetryMark = Marker(enum { capped, exact, full, equal, proportional, proportional_clamped, no_random });

fn retrySmith(_: void, s: *testing.Smith) !void {
    return fuzzRetry(testing.Smith, s, testing.allocator);
}
test "fuzz: nextDelay agrees with a rational model and stays in its jitter bounds" {
    try testing.fuzz({}, retrySmith, .{});
}
test "fuzz driver: RESILIENCE_FUZZ (retry)" {
    try fuzz_driver.run(fuzzRetry, .{ .prefix = "RESILIENCE_FUZZ", .name = "resilience-retry" });
}
test "fuzz harness: retry, 300 seeds, reaches every outcome" {
    try RetryMark.reach(fuzzRetry, "resilience-retry", 300);
}

/// `base × (num/den)^k`, floored, capped — in integers. Factors 1, 1.5, 2,
/// 2.5, 3 are exact in binary; `k` stays where `num^k` fits 53 bits, so
/// the f64 `pow` the implementation uses is exact too.
fn modelDelay(base: u64, num: u64, den: u64, k: u32, cap: u64) u64 {
    var x: u128 = base;
    var d: u128 = 1;
    for (0..k) |_| {
        x *= num;
        d *= den;
        if (x / d >= cap) return cap;
    }
    return @intCast(@min(x / d, cap));
}

fn fuzzRetry(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [64]u8 = undefined;
    const len: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..len] };
    const factors = [_][2]u64{ .{ 1, 1 }, .{ 3, 2 }, .{ 2, 1 }, .{ 5, 2 }, .{ 3, 1 } };
    const f = factors[k.ranged(0, factors.len - 1)];
    const base: u64 = switch (k.ranged(0, 2)) {
        0 => 0,
        1 => k.ranged(1, 1000),
        else => @as(u64, k.word()) * 37,
    };
    const cap: u64 = switch (k.ranged(0, 2)) {
        0 => base,
        1 => @as(u64, k.word()) * 1000,
        else => 1_000_000_000,
    };
    const jitter: r.Jitter = @enumFromInt(k.ranged(0, 3));
    const jf: f64 = @as(f64, @floatFromInt(k.ranged(0, 100))) / 100;
    const policy: r.Retry = .{
        .base_delay_ms = base,
        .factor = @as(f64, @floatFromInt(f[0])) / @as(f64, @floatFromInt(f[1])),
        .max_delay_ms = cap,
        .jitter = jitter,
        .jitter_factor = jf,
    };
    const seed = k.word();
    var p1 = std.Random.DefaultPrng.init(seed);
    var p2 = std.Random.DefaultPrng.init(seed);
    const max_k: u32 = if (f[0] == 1) 40 else 30; // 3^30 < 2^53
    var attempt: u32 = 1;
    while (attempt <= max_k + 1) : (attempt += 1) {
        const d = modelDelay(base, f[0], f[1], attempt - 1, cap);
        if (policy.nextDelay(attempt, null) != d) return error.ScheduleDiffers;
        if (d == cap and attempt > 1) RetryMark.mark(.capped) else RetryMark.mark(.exact);
        RetryMark.mark(.no_random);
        const a = policy.nextDelay(attempt, p1.random());
        if (a != policy.nextDelay(attempt, p2.random())) return error.SameSeedDiffers;
        switch (jitter) {
            .none => if (a != d) return error.NoneJittered,
            .full => {
                if (a > d) return error.FullOutOfBounds;
                RetryMark.mark(.full);
            },
            .equal => {
                if (a < d / 2 or a > d) return error.EqualOutOfBounds;
                RetryMark.mark(.equal);
            },
            .proportional => {
                const spread: u64 = @intFromFloat(@as(f64, @floatFromInt(d)) * jf);
                if (a + spread < d or a > @min(cap, d + spread)) return error.ProportionalOutOfBounds;
                if (a == cap and d + spread > cap) RetryMark.mark(.proportional_clamped);
                RetryMark.mark(.proportional);
            },
        }
    }
}

// ── run ─────────────────────────────────────────────────────────────────

const RunMark = Marker(enum {
    success_first,
    success_after_retry,
    exhausted,
    fatal,
    circuit_open,
    bulkhead_full,
    timeout,
    result_retried,
    result_returned_rejected,
    retry_after,
    budget_stop,
    ignored_error,
    success_classified,
});

/// One scripted attempt.
const Step = struct {
    kind: enum { ok, soft, fatal, ignored, praised },
    value: u32,
    dur_ms: u64,
    reject: bool, // retryOnResult says retry this value
    retry_after: ?u64,
};

const ScriptOp = struct {
    steps: []const Step,
    clock: *VClock,
    calls: usize = 0,
    last: ?Step = null,

    pub fn call(self: *ScriptOp) error{ Soft, Fatal, Ignored, Praised }!u32 {
        const s = self.steps[@min(self.calls, self.steps.len - 1)];
        self.calls += 1;
        self.last = s;
        self.clock.ns += s.dur_ms * ms;
        return switch (s.kind) {
            .ok => s.value,
            .soft => error.Soft,
            .fatal => error.Fatal,
            .ignored => error.Ignored,
            .praised => error.Praised,
        };
    }
    pub fn retryOnResult(self: *ScriptOp, _: *const u32) bool {
        return self.last.?.reject;
    }
    pub fn retryAfterMs(self: *ScriptOp) ?u64 {
        return self.last.?.retry_after;
    }
};

fn classifyScript(err: anyerror) r.Outcome {
    return switch (err) {
        error.Ignored => .ignore,
        error.Praised => .success,
        else => .failure,
    };
}

fn retryableScript(err: anyerror) bool {
    return err != error.Fatal;
}

/// A breaker that answers `allow` from a script and logs every record.
const FakeBreaker = struct {
    allow_script: []const bool,
    asked: usize = 0,
    rec: [64]struct { r.Outcome, ?u64 } = undefined,
    n_rec: usize = 0,
    times: bool,

    fn allowFn(p: *anyopaque) bool {
        const f: *FakeBreaker = @ptrCast(@alignCast(p));
        defer f.asked += 1;
        return f.allow_script[@min(f.asked, f.allow_script.len - 1)];
    }
    fn recordFn(p: *anyopaque, o: r.Outcome, d: ?u64) void {
        const f: *FakeBreaker = @ptrCast(@alignCast(p));
        f.rec[f.n_rec] = .{ o, d };
        f.n_rec += 1;
    }
    fn timesFn(p: *anyopaque) bool {
        return @as(*FakeBreaker, @ptrCast(@alignCast(p))).times;
    }
    const vt: r.BreakerHandle.VTable = .{ .allow = allowFn, .record = recordFn, .timesCalls = timesFn };
    fn handle(f: *FakeBreaker) r.BreakerHandle {
        return .{ .ptr = f, .vtable = &vt };
    }
};

const RetryLog = struct {
    ev: [64]struct { u32, ?anyerror, u64 } = undefined,
    n: usize = 0,
    fn on(ctx: ?*anyopaque, attempt: u32, failure: ?anyerror, delay_ms: u64) void {
        const l: *RetryLog = @ptrCast(@alignCast(ctx.?));
        l.ev[l.n] = .{ attempt, failure, delay_ms };
        l.n += 1;
    }
};

fn runSmith(_: void, s: *testing.Smith) !void {
    return fuzzRun(testing.Smith, s, testing.allocator);
}
test "fuzz: run agrees with an interpreter of the documented composition" {
    try testing.fuzz({}, runSmith, .{});
}
test "fuzz driver: RESILIENCE_FUZZ (run)" {
    try fuzz_driver.run(fuzzRun, .{ .prefix = "RESILIENCE_FUZZ", .name = "resilience-run" });
}
test "fuzz harness: run, 600 seeds, reaches every outcome" {
    try RunMark.reach(fuzzRun, "resilience-run", 600);
}

fn fuzzRun(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [256]u8 = undefined;
    const len: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..len] };

    var steps: [8]Step = undefined;
    const n_steps = k.ranged(1, 8);
    for (steps[0..n_steps]) |*s| s.* = .{
        .kind = switch (k.ranged(0, 9)) {
            0...3 => .ok,
            4...6 => .soft,
            7 => .fatal,
            8 => .ignored,
            else => .praised,
        },
        .value = k.ranged(0, 1000),
        .dur_ms = switch (k.ranged(0, 3)) {
            0 => 0,
            1 => 5,
            else => k.ranged(0, 40),
        },
        .reject = k.ranged(0, 4) == 0,
        .retry_after = if (k.ranged(0, 3) == 0) k.ranged(0, 500) else null,
    };
    var allow_script: [8]bool = undefined;
    for (&allow_script) |*a| a.* = k.ranged(0, 7) != 0;
    const use_breaker = k.byte() & 1 == 0;
    const use_bulkhead = k.ranged(0, 3) == 0;
    const bulkhead_full = use_bulkhead and k.byte() & 1 == 0;
    const timeout_ms: u64 = if (k.byte() & 1 == 0) 0 else k.ranged(1, 30);
    const retry: ?r.Retry = if (k.ranged(0, 4) == 0) null else .{
        .max_attempts = k.ranged(0, 6),
        .base_delay_ms = k.ranged(0, 50),
        .factor = 2.0,
        .max_delay_ms = k.ranged(0, 300),
        .jitter = .none,
        .max_elapsed_ms = if (k.byte() & 1 == 0) 0 else k.ranged(1, 400),
        .retryable = retryableScript,
    };

    var vc: VClock = .{};
    var op: ScriptOp = .{ .steps = steps[0..n_steps], .clock = &vc };
    var fb: FakeBreaker = .{ .allow_script = &allow_script, .times = k.byte() & 1 == 0 };
    var bh: r.Bulkhead = .init(.{ .max_concurrent = 1 });
    if (bulkhead_full) _ = bh.tryAcquire();
    var rlog: RetryLog = .{};

    const got = r.run(&op, .{
        .breaker = if (use_breaker) fb.handle() else null,
        .bulkhead = if (use_bulkhead) &bh else null,
        .retry = retry,
        .timeout_ms = timeout_ms,
        .clock = vc.clock(),
        .delay = vc.delay(),
        .classify = classifyScript,
        .on_retry = .{ .ctx = &rlog, .onRetry = RetryLog.on },
    });

    // ── the interpreter ──
    var want_calls: usize = 0;
    var want_waits: [64]u64 = undefined;
    var n_waits: usize = 0;
    var want_rec: [64]struct { r.Outcome, ?u64 } = undefined;
    var n_rec: usize = 0;
    var asked: usize = 0;
    const want: anyerror!u32 = interp: {
        if (bulkhead_full) {
            RunMark.mark(.bulkhead_full);
            break :interp error.BulkheadFull;
        }
        const max_attempts: u32 = if (retry) |x| @max(1, x.max_attempts) else 1;
        const time_calls = timeout_ms != 0 or (use_breaker and fb.times);
        var t: u64 = 1_000_000_000;
        const start = t;
        var attempt: u32 = 1;
        while (true) : (attempt += 1) {
            if (use_breaker) {
                const a = allow_script[@min(asked, allow_script.len - 1)];
                asked += 1;
                if (!a) {
                    RunMark.mark(.circuit_open);
                    break :interp error.CircuitOpen;
                }
            }
            const s = steps[@min(want_calls, n_steps - 1)];
            want_calls += 1;
            t += s.dur_ms * ms;
            const dur: ?u64 = if (time_calls) s.dur_ms * ms else null;
            const late = timeout_ms != 0 and s.dur_ms * ms > timeout_ms * ms;
            var rejected: ?u32 = null;
            var failure: anyerror = undefined;
            if (late) {
                failure = error.Timeout;
                RunMark.mark(.timeout);
                if (use_breaker) {
                    want_rec[n_rec] = .{ .failure, dur };
                    n_rec += 1;
                }
            } else switch (s.kind) {
                .ok => {
                    if (s.reject) {
                        rejected = s.value;
                        if (use_breaker) {
                            want_rec[n_rec] = .{ .failure, dur };
                            n_rec += 1;
                        }
                    } else {
                        if (use_breaker) {
                            want_rec[n_rec] = .{ .success, dur };
                            n_rec += 1;
                        }
                        RunMark.mark(if (attempt == 1) .success_first else .success_after_retry);
                        break :interp s.value;
                    }
                },
                .ignored, .praised => {
                    if (use_breaker) {
                        want_rec[n_rec] = .{ if (s.kind == .ignored) .ignore else .success, dur };
                        n_rec += 1;
                    }
                    RunMark.mark(if (s.kind == .ignored) .ignored_error else .success_classified);
                    break :interp if (s.kind == .ignored) error.Ignored else error.Praised;
                },
                .soft, .fatal => {
                    failure = if (s.kind == .soft) error.Soft else error.Fatal;
                    if (use_breaker) {
                        want_rec[n_rec] = .{ .failure, dur };
                        n_rec += 1;
                    }
                },
            }
            const fatal = rejected == null and failure == error.Fatal;
            if (attempt < max_attempts and !fatal) {
                const x = retry.?;
                var wait = x.nextDelay(attempt, null);
                if (s.retry_after) |ra| {
                    wait = @min(ra, x.max_delay_ms);
                    RunMark.mark(.retry_after);
                }
                const over = x.max_elapsed_ms != 0 and (t - start) + wait * ms > x.max_elapsed_ms * ms;
                if (!over) {
                    if (rejected != null) RunMark.mark(.result_retried);
                    want_waits[n_waits] = wait;
                    n_waits += 1;
                    t += wait * ms;
                    continue;
                }
                RunMark.mark(.budget_stop);
            }
            if (fatal) RunMark.mark(.fatal) else RunMark.mark(.exhausted);
            if (rejected) |v| {
                RunMark.mark(.result_returned_rejected);
                break :interp v;
            }
            break :interp failure;
        }
    };

    // ── compare ──
    if (want) |wv| {
        const gv = got catch |e| {
            std.debug.print("run: got error {t}, want value {d}\n", .{ e, wv });
            return error.RunDiffers;
        };
        if (gv != wv) return error.RunValueDiffers;
    } else |we| {
        if (got) |gv| {
            std.debug.print("run: got value {d}, want error {t}\n", .{ gv, we });
            return error.RunDiffers;
        } else |ge| if (ge != we) {
            std.debug.print("run: got error {t}, want {t}\n", .{ ge, we });
            return error.RunErrorDiffers;
        }
    }
    if (op.calls != want_calls) return error.CallCountDiffers;
    if (rlog.n != n_waits) return error.RetryEventsDiffer;
    for (rlog.ev[0..rlog.n], want_waits[0..n_waits], 0..) |e, w, i| {
        if (e[0] != i + 1 or e[2] != w) return error.RetryEventDiffers;
    }
    if (fb.n_rec != n_rec) return error.BreakerLogDiffers;
    for (fb.rec[0..n_rec], want_rec[0..n_rec]) |a, b| {
        if (a[0] != b[0] or !std.meta.eql(a[1], b[1])) return error.BreakerRecordDiffers;
    }
    if (use_breaker and fb.asked != asked) return error.AllowCountDiffers;
    if (bh.activeCount() != @intFromBool(bulkhead_full)) return error.BulkheadLeak;
}
