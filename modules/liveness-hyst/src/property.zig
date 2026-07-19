// SPDX-License-Identifier: MIT
//! Property tests for the Estimator's ADJUDICATED monotonicity contract (see
//! `core.decide`'s doc for the full statement and the impossibility argument
//! that forced the split):
//!
//!   (1) FORWARDING SAFETY: `pathCost()` is pointwise monotone — a
//!       pointwise-worse probe stream (every reply as slow or slower, or
//!       degraded to a timeout; every timeout kept) never yields a LOWER cost,
//!       so a worse path is never strictly preferred for forwarding.
//!   (2) UP-BOUNDARY monotonicity: a pointwise-worse stream is never `.up`
//!       when the better stream is not.
//!   (3) Inside {`.suspect`, `.down`} the STATE is intentionally non-monotone
//!       (anti-flap damping): the audit-F1 counterexample — clean-then-dead
//!       ranks `.down` while a pointwise-WORSE degraded stream ranks
//!       `.suspect` — is pinned below as a PERMANENT regression case. If that
//!       pin ever fails, either the degraded damping was removed (re-check the
//!       spurious-failover budget in scoring.zig) or someone re-coupled
//!       ranking to state — both require re-opening the adjudication.
//!
//! Plus bounded memory (fixed state regardless of stream length). These are
//! properties of the Estimator itself, not of any particular network scenario,
//! so they drive `onProbeReply` / `onProbeTimeout` directly with synthetic
//! paired streams — no netsim needed.

const std = @import("std");
const root = @import("root.zig");
const Estimator = root.Estimator;
const LinkState = root.LinkState;
const Time = root.Time;

const testing = std.testing;

// ── monotonicity ──────────────────────────────────────────────────────────────

const ProbeEvent = union(enum) {
    reply: Time, // rtt
    timeout,
};

/// A "pointwise worse" transform of a single probe event: a reply either stays
/// a reply with an RTT that is never lower, or degrades all the way to a
/// timeout; a timeout stays a timeout. Never improves any single probe.
fn worsen(rng: std.Random, ev: ProbeEvent) ProbeEvent {
    return switch (ev) {
        .timeout => .timeout,
        .reply => |rtt| if (rng.boolean())
            .timeout
        else
            .{ .reply = rtt + rng.uintLessThan(Time, 50) },
    };
}

fn feed(est: *Estimator, now: Time, ev: ProbeEvent) void {
    switch (ev) {
        .reply => |rtt| est.onProbeReply(now, rtt),
        .timeout => est.onProbeTimeout(now),
    }
}

/// The two TRUE halves of the monotonicity contract, checked at one instant of
/// a paired run where `b`'s stream pointwise-dominates `a`'s in badness.
fn checkDominance(a: *const Estimator, b: *const Estimator) !void {
    // (1) Forwarding safety: the ordering key is pointwise monotone — the
    // worse stream's cost is never lower. The exact EWMA recurrence is
    // monotone; the 1e-12 slack only covers sub-ulp f64 rounding of near-equal
    // trajectories and is orders of magnitude below any real inversion (a
    // state-rank-derived cost violates this by O(1)).
    try testing.expect(b.pathCost() >= a.pathCost() - 1e-12);
    // (2) Up-boundary: the worse stream is never `.up` unless the better one is.
    if (b.state() == .up) try testing.expectEqual(LinkState.up, a.state());
}

test "property: pointwise-worse stream — monotone path cost + up-boundary (randomized)" {
    var prng = std.Random.DefaultPrng.init(0xA11CE);
    const rng = prng.random();

    var a = Estimator.init(.{});
    var b = Estimator.init(.{});

    const n = 500;
    var now: Time = 0;
    const interval: Time = 200;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        now += interval;
        // Baseline stream A: mostly clean replies, occasional timeout.
        const ev_a: ProbeEvent = if (rng.uintLessThan(u32, 20) == 0)
            .timeout
        else
            .{ .reply = 10 + rng.uintLessThan(Time, 40) };
        const ev_b = worsen(rng, ev_a);

        feed(&a, now, ev_a);
        feed(&b, now, ev_b);

        try checkDominance(&a, &b);
    }
}

test "property: audit-F1 adversarial pair — cost stays monotone through the pinned state inversion" {
    // The reproduced audit counterexample, kept as a permanent regression:
    //   A: 100 clean replies, then a 5-timeout burst  -> fast-down fires.
    //   B: pointwise WORSE — every other phase-1 reply degraded to a timeout
    //      (~50% loss => degraded regime), then the SAME 5-timeout burst
    //      -> the anti-flap degraded gate holds B at `.suspect`.
    // At the burst, A ranks `.down` while the worse B ranks `.suspect` — the
    // intentional, adjudicated state inversion. The contract that MUST survive
    // it: B's pathCost never drops below A's, and B is never `.up`.
    var a = Estimator.init(.{});
    var b = Estimator.init(.{});
    var now: Time = 0;
    const interval: Time = 200;

    // Phase 1: 100 probes.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        now += interval;
        a.onProbeReply(now, 20);
        if (i % 2 == 1) b.onProbeTimeout(now) else b.onProbeReply(now, 20);
        try checkDominance(&a, &b);
    }

    // Phase 2: identical 5-timeout burst on both streams.
    var saw_inversion = false;
    i = 0;
    while (i < 5) : (i += 1) {
        now += interval;
        a.onProbeTimeout(now);
        b.onProbeTimeout(now);
        try checkDominance(&a, &b);
        if (a.state() == .down and b.state() == .suspect) saw_inversion = true;
    }

    // Pin the inversion itself: A's fast-down fired inside the burst while the
    // degraded damping held B at `.suspect`. If this fails, the degraded gate
    // changed — re-run the scoring budget and re-open the adjudication in
    // `core.decide` before "fixing" this test.
    try testing.expect(saw_inversion);
    try testing.expectEqual(LinkState.down, a.state());
    try testing.expectEqual(LinkState.suspect, b.state());
    // And the forwarding key still refuses to prefer B: its cost is higher.
    try testing.expect(b.pathCost() >= a.pathCost());
}

test "property: recovery is uniform — worse stream never reaches .up first (high-smoothing, sparse probes)" {
    // Regression for the uniform recovery gate in `core.decide`: with a
    // mandatory `.down` -> `.suspect` stopover (one reply), a pointwise-worse
    // stream parked at `.suspect` by the degraded damping would pass the
    // quiet+metric recovery gate one reply-step BEFORE the cleaner stream
    // still exiting `.down` — i.e. the WORSE stream reaches `.up` first,
    // breaking up-boundary monotonicity. Realizable exactly here: high
    // `metric_smoothing` (post-reply metric of the failed stream already under
    // theta_up) + a probe gap longer than `up_threshold` (quiet holds at the
    // very first reply). The uniform gate makes both streams climb together.
    const cfg = root.Config{ .metric_smoothing = 0.8 };
    var a = Estimator.init(cfg);
    var b = Estimator.init(cfg);
    var now: Time = 0;
    const interval: Time = 200;

    // Phase 1: as in the audit-F1 pair — A clean, B ~50% degraded.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        now += interval;
        a.onProbeReply(now, 20);
        if (i % 2 == 1) b.onProbeTimeout(now) else b.onProbeReply(now, 20);
        try checkDominance(&a, &b);
    }

    // Phase 2: identical 5-timeout burst -> A `.down` (fast path), B `.suspect`
    // (degraded damping).
    i = 0;
    while (i < 5) : (i += 1) {
        now += interval;
        a.onProbeTimeout(now);
        b.onProbeTimeout(now);
        try checkDominance(&a, &b);
    }
    try testing.expectEqual(LinkState.down, a.state());
    try testing.expectEqual(LinkState.suspect, b.state());

    // Phase 3: a probe gap longer than `up_threshold`, then ONE reply on both.
    // The recovery gate (quiet AND metric <= theta_up) holds for both; the
    // uniform gate must lift A straight `.down` -> `.up` so the worse B cannot
    // be `.up` while A is not (the old stopover code fails checkDominance here:
    // B=.up, A=.suspect).
    now += 6000; // > up_threshold (5000) of silence, no probes in flight
    a.onProbeReply(now, 20);
    b.onProbeReply(now, 20);
    try checkDominance(&a, &b);
    try testing.expectEqual(LinkState.up, a.state());
    try testing.expectEqual(LinkState.up, b.state());
}

// ── bounded memory ────────────────────────────────────────────────────────────

test "property: bounded memory — Estimator holds no pointer/slice field" {
    // Structural proof: the type has no allocator and no dynamically-growing
    // collection (a raw pointer or slice field would be the tell), so its
    // footprint cannot depend on how many probes it has processed. Compares
    // against `history`, which is a fixed `[history_capacity]Probe` array (not
    // a pointer), by construction.
    comptime {
        const info = @typeInfo(Estimator).@"struct";
        for (info.fields) |f| {
            if (@typeInfo(f.type) == .pointer) {
                @compileError("Estimator must not hold a pointer/slice field (unbounded-memory risk): " ++ f.name);
            }
        }
    }
}

test "property: bounded memory — recent-probe history saturates instead of growing" {
    var est = Estimator.init(.{});
    var now: Time = 0;
    const n = root.history_capacity * 10; // far more probes than the window holds
    var i: usize = 0;
    while (i < n) : (i += 1) {
        now += 100;
        if (i % 7 == 0) est.onProbeTimeout(now) else est.onProbeReply(now, 20);
        try testing.expect(est.history_len <= root.history_capacity);
    }
    try testing.expectEqual(root.history_capacity, est.history_len);
}
