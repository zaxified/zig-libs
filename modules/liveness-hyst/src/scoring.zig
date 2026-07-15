// SPDX-License-Identifier: MIT
//! Scoring harness: turns `trace.zig`'s netsim-driven corpus into the two
//! headline objectives this estimator design is judged against (see root.zig's
//! module doc for the problem statement):
//!
//!   1. detection latency on a genuine hard failure (bounded, target ≤ 1.5s
//!      equivalent — `DETECTION_LATENCY_TARGET`);
//!   2. spurious-failover count on a flapping-but-usable / degraded-but-usable
//!      link over a simulated week (bounded — `SPURIOUS_FAILOVER_BUDGET_PER_WEEK`).
//!
//! Unit convention for this file (and for the `trace.zig` scenarios it drives):
//! **1 tick = 1 millisecond** (see root.zig's `Time` doc) — chosen so the
//! real-world targets above are literal tick counts; the Estimator / netsim
//! underneath are tick-unit-agnostic.
//!
//! Every test here drives a `trace.Prober`, which owns an `Estimator`, which
//! calls into the `core.decide` Fable stub on every probe outcome — so every
//! test in this file panics at the stub until the Fable core lands. That is
//! EXPECTED (see root.zig / core.zig doc); the harness itself is complete and
//! correct today and needs no changes once the stub is filled in.

const std = @import("std");
const netsim = @import("netsim");
const root = @import("root.zig");
const trace = @import("trace.zig");

const Config = root.Config;
const Time = root.Time;

const testing = std.testing;

// ── unit convention ──────────────────────────────────────────────────────────

const MS: Time = 1;
const SEC: Time = 1000 * MS;
const WEEK: Time = 7 * 24 * 60 * 60 * SEC;

// ── asserted trade-off bounds ─────────────────────────────────────────────────
//
// These are the executable form of the design's headline claim. They are
// documented placeholders in the sense that the exact numbers came from this
// scaffolding pass, not a separately-published spec — but they ARE the bounds
// the Fable core in `core.zig` must satisfy; tune them here (with rationale) if
// the design settles on different numbers.

/// Detection-latency bound on a genuine, sustained hard failure.
pub const DETECTION_LATENCY_TARGET: Time = 1500 * MS; // 1.5s

/// How many times the estimator may cross into `.down` over a simulated WEEK on
/// a link that is flapping/degraded but still fundamentally usable. A naive
/// "N consecutive misses -> down" BFD timer turns every flap into a failover
/// (hundreds/week on a 30%-duty-cycle flap); this budget is the harness's teeth
/// against that failure mode.
pub const SPURIOUS_FAILOVER_BUDGET_PER_WEEK: usize = 5;

// ── mechanical objective functions (no decision logic here) ──────────────────

/// First transition into `.down` at or after `fail_at`, minus `fail_at`. `null`
/// if the estimator never declared the link down in the trace.
pub fn detectionLatency(transitions: []const trace.Transition, fail_at: Time) ?Time {
    for (transitions) |t| {
        if (t.state == .down and t.at >= fail_at) return t.at - fail_at;
    }
    return null;
}

/// Count of transitions INTO `.down` — the spurious-flap metric on a link that
/// never actually goes fully, permanently dead.
pub fn countFailovers(transitions: []const trace.Transition) usize {
    var n: usize = 0;
    for (transitions) |t| {
        if (t.state == .down) n += 1;
    }
    return n;
}

// ── corpus: clean link ────────────────────────────────────────────────────────

test "scoring: a clean link never leaves .up" {
    const gpa = testing.allocator;
    var prober = trace.Prober.init(gpa, .{}, RESPONDER, 200 * MS, 800 * MS);
    defer prober.deinit();
    const case = netsim.Case{ .seed = 1, .scenario = trace.cleanScenario, .protocol = prober.protocol(), .until = 60 * SEC };
    _ = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(@as(usize, 0), countFailovers(prober.transitions.items));
}

// ── corpus: cleanly-failing link — detection-latency bound ───────────────────

test "scoring: detection latency on a genuine hard failure is within target" {
    const gpa = testing.allocator;
    var prober = trace.Prober.init(gpa, .{}, RESPONDER, 100 * MS, 400 * MS);
    defer prober.deinit();
    const case = netsim.Case{ .seed = 2, .scenario = trace.cleanScenario, .protocol = prober.protocol(), .until = 30 * SEC };
    const fail_at: Time = 10 * SEC;
    const fault_trace = trace.hardFailureTrace(fail_at);
    _ = try netsim.replay(gpa, case, &fault_trace, null);
    const latency = detectionLatency(prober.transitions.items, fail_at) orelse return error.NeverDetected;
    try testing.expect(latency <= DETECTION_LATENCY_TARGET);
}

// ── corpus: flapping link, ~30% downtime — spurious-failover budget ──────────

test "scoring: a 30%-down flapping link stays within the spurious-failover budget" {
    const gpa = testing.allocator;
    var prober = trace.Prober.init(gpa, .{}, RESPONDER, 1 * SEC, 4 * SEC);
    defer prober.deinit();
    const case = netsim.Case{ .seed = 3, .scenario = trace.cleanScenario, .protocol = prober.protocol(), .until = WEEK };
    // 10s period, down 3s of every 10s => 30% duty-cycle downtime.
    const fault_trace = try trace.dutyCycleTrace(gpa, 7 * SEC, 3 * SEC, WEEK);
    defer gpa.free(fault_trace);
    _ = try netsim.replay(gpa, case, fault_trace, null);
    const n = countFailovers(prober.transitions.items);
    try testing.expect(n <= SPURIOUS_FAILOVER_BUDGET_PER_WEEK);
}

// ── corpus: continuously degraded-but-usable link (30% probabilistic loss) ───

test "scoring: a continuously-degraded-but-usable link stays within the spurious-failover budget" {
    const gpa = testing.allocator;
    var prober = trace.Prober.init(gpa, .{}, RESPONDER, 1 * SEC, 4 * SEC);
    defer prober.deinit();
    const case = netsim.Case{ .seed = 4, .scenario = trace.degradedScenario, .protocol = prober.protocol(), .until = WEEK };
    _ = try netsim.replay(gpa, case, &.{}, null);
    const n = countFailovers(prober.transitions.items);
    try testing.expect(n <= SPURIOUS_FAILOVER_BUDGET_PER_WEEK);
}

// ── corpus: flapping link across a duty-cycle sweep ───────────────────────────

test "scoring: the flapping corpus generator covers a duty-cycle sweep" {
    const gpa = testing.allocator;
    const period: Time = 10 * SEC;
    const down_permille = [_]u16{ 100, 300, 500, 700 }; // 10%..70% down
    var seed: u64 = 100;
    for (down_permille) |dp| {
        var prober = trace.Prober.init(gpa, .{}, RESPONDER, 1 * SEC, 4 * SEC);
        defer prober.deinit();
        const down_ticks = period * dp / 1000;
        const up_ticks = period - down_ticks;
        const case = netsim.Case{ .seed = seed, .scenario = trace.cleanScenario, .protocol = prober.protocol(), .until = WEEK };
        seed += 1;
        const fault_trace = try trace.dutyCycleTrace(gpa, up_ticks, down_ticks, WEEK);
        defer gpa.free(fault_trace);
        _ = try netsim.replay(gpa, case, fault_trace, null);
        // Exercises the corpus generator across the sweep; the precise budget is
        // asserted only for the documented 30% case above (tighten to a
        // per-duty-cycle bound once the Fable core's actual trade-off curve is
        // known — a 70%-down link plausibly SHOULD fail over more).
        _ = countFailovers(prober.transitions.items);
    }
}

const RESPONDER: netsim.NodeId = 1;
