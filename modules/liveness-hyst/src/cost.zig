// SPDX-License-Identifier: MIT
//! Latency-aware path cost and hysteretic path selection.
//!
//! `Estimator.pathCost()` is the key a caller orders forwarding paths by. It
//! combines three inputs, each already smoothed by the Estimator's input filter
//! (the same `Config.metric_smoothing` EWMA that drives `core.decide`):
//!
//!   cost = loss_term(loss) + rtt_weight · rtt_penalty(srtt) + jitter_weight · jitter_penalty(jitter)
//!
//! in units of ONE NOMINAL LINK COST (a clean, fast path costs 0; adding one
//! nominal cost is what Babel calls "one more hop" on a link of that type).
//!
//! - **loss_term** is ETX − 1, i.e. `m / (1 − m)` for the smoothed probe-loss
//!   fraction `m` (`Estimator.metric()`): the expected number of EXTRA
//!   transmissions per delivered packet. This is Babel's ETX link cost
//!   (RFC 8966 Appendix A.2.2, cost = nominal · ETX), shifted so a clean link
//!   reads 0, with an echo probe's round-trip success standing in for the
//!   product of the two one-way delivery probabilities. It is unbounded as
//!   `m → 1` (saturated at `max_loss`), which is what makes large loss dominate.
//! - **rtt_penalty** is the piecewise-linear RTT penalty of the Babel
//!   delay-based metric extension (RFC 9616; babeld's `rtt-min` / `rtt-max` /
//!   `max-rtt-penalty`): 0 below `rtt_min`, linear in `srtt − rtt_min`, 1 at and
//!   above `rtt_max`. babeld's documented tunnel defaults are rtt-min 10 ms,
//!   rtt-max 120 ms, max-rtt-penalty 96 on a nominal cost (rxcost) of 96, so
//!   `rtt_weight = 96 / 96 = 1.0`: a path at or beyond `rtt_max` costs one
//!   extra nominal link. WireGuard IS a tunnel interface in babeld's sense.
//! - **jitter_penalty** is the RFC 3550 §6.4.1 interarrival jitter the
//!   `latency-stats` accumulator already keeps, scaled by `jitter_max` and
//!   clamped to [0, 1]. OFF by default (`jitter_weight = 0`): neither RFC 9616
//!   nor babeld puts jitter in the metric, and — unlike loss and RTT — jitter
//!   is not monotone in path quality (a uniformly slower stream can be
//!   smoother), so a non-zero weight voids the pointwise-monotone guarantee of
//!   `pathCost()` (property.zig's contract (1)). Opt in knowingly.
//!
//! **What the RTT smoother sees.** A reply contributes `min(rtt, rtt_max)`; an
//! unanswered probe contributes `rtt_max`. The first probe seeds the average.
//! Babel only measures RTT on received Hellos, so RFC 9616 has nothing to say
//! about losses; here a timeout MUST count as "at least as slow as anything
//! the penalty can distinguish", or a reply degraded to a timeout could LOWER
//! the smoothed RTT relative to the better stream and break forwarding safety.
//! Clamping the reply at `rtt_max` costs nothing (the penalty saturates there
//! anyway) and keeps one multi-second outlier from pinning the penalty high
//! for many probes.
//!
//! **Consequences of the defaults** (all checked by tests below):
//! - two paths with the same loss order by RTT (LTE at ~50 ms beats GEO
//!   satellite at ~600 ms by ~0.64 nominal cost — RTT saturates at `rtt_max`);
//! - loss dominates once large: any path whose smoothed loss exceeds
//!   `rtt_weight / (1 + rtt_weight)` (50% at the default weight) costs more
//!   than ANY loss-free path, whatever that path's RTT;
//! - `rtt_weight = 0` gives exactly the old loss-only ORDER (ETX − 1 is
//!   strictly increasing in the loss metric), and `cost_fn = lossOnlyCost`
//!   gives the old VALUES too.
//!
//! **Where the hysteresis is.** The cost itself carries no hold or dead-band,
//! deliberately: a held value can be stale-low on a worse path while the
//! better path's value is fresh, which breaks the monotone ordering contract
//! that `pathCost()` exists for. So, as in Babel (smoothed metric, then
//! route-selection hysteresis — babeld's `-M` 4 s selection smoothing), the
//! damping is split: (1) every input is EWMA-filtered with the same
//! `metric_smoothing` as the liveness verdict, and (2) the asymmetric
//! hysteresis lives in `Selector`: leave a `.down` path at once (fast to
//! distrust), but switch to a better-looking path only after it has been
//! better by at least `margin` for `hold` ticks continuously (slow to trust) —
//! the same shape as `Config.down_threshold` / `Config.up_threshold`.

const std = @import("std");
const root = @import("root.zig");

const Time = root.Time;
const LinkState = root.LinkState;
const Estimator = root.Estimator;

/// The smoothed inputs a path cost is computed from. All are read from an
/// `Estimator` by `Estimator.costInputs()`.
pub const CostInputs = struct {
    /// Smoothed probe-loss fraction in [0, 1] — `Estimator.metric()`.
    loss: f64,
    /// Smoothed RTT in ticks (replies clamped at `rtt_max`, timeouts counted
    /// as `rtt_max`) — `Estimator.smoothedRtt()`. 0 before the first probe.
    srtt: f64,
    /// RFC 3550 interarrival jitter of the replies, in ticks (`latency-stats`).
    jitter: f64,
    /// The damped liveness verdict, for cost functions that want it.
    state: LinkState,
};

/// A replacement cost function (`PathCostConfig.cost_fn`). Must be
/// non-decreasing in `loss` and `srtt` for `pathCost()` to keep its
/// forwarding-safety guarantee; the module cannot check that for you.
pub const CostFn = *const fn (in: CostInputs, cfg: PathCostConfig) f64;

/// How `Estimator.pathCost()` combines loss, RTT and jitter. Times are in the
/// caller's ticks; the defaults assume this module's 1 tick = 1 ms convention.
pub const PathCostConfig = struct {
    /// RTT at and below which no penalty is added (babeld `rtt-min`, 10 ms).
    rtt_min: Time = 10,
    /// RTT at and above which the penalty is maximal (babeld `rtt-max`,
    /// 120 ms). Also the value an unanswered probe feeds the RTT smoother.
    rtt_max: Time = 120,
    /// Maximum RTT penalty, in nominal link costs (babeld tunnel default
    /// `max-rtt-penalty` 96 / `rxcost` 96 = 1.0). 0 = loss-only ordering.
    rtt_weight: f64 = 1.0,
    /// Jitter at and above which the jitter penalty is maximal.
    jitter_max: Time = 30,
    /// Maximum jitter penalty, in nominal link costs. Default 0 (off) — see
    /// the module doc for why a non-zero value voids pointwise monotonicity.
    jitter_weight: f64 = 0,
    /// Upper clamp on the loss fraction fed to ETX, so a dead path's cost is
    /// large but finite (ETX − 1 saturates at 1023 with the default).
    max_loss: f64 = 1.0 - 1.0 / 1024.0,
    /// Replace the default combination entirely (e.g. `lossOnlyCost` for the
    /// pre-2026-10-06 loss-only values). `null` = `defaultCost`.
    cost_fn: ?CostFn = null,
};

/// The documented default combination — see the module doc.
pub fn defaultCost(in: CostInputs, cfg: PathCostConfig) f64 {
    const m = std.math.clamp(in.loss, 0.0, cfg.max_loss);
    const loss_term = m / (1.0 - m);
    return loss_term +
        @max(cfg.rtt_weight, 0.0) * rttPenalty(in.srtt, cfg) +
        @max(cfg.jitter_weight, 0.0) * jitterPenalty(in.jitter, cfg);
}

/// The pre-2026-10-06 `pathCost()`: the smoothed loss fraction alone.
pub fn lossOnlyCost(in: CostInputs, cfg: PathCostConfig) f64 {
    _ = cfg;
    return in.loss;
}

/// Babel delay-metric penalty in [0, 1]: 0 at or below `rtt_min`, linear up to
/// 1 at `rtt_max`. With `rtt_max <= rtt_min` it is a step at `rtt_min`.
pub fn rttPenalty(srtt: f64, cfg: PathCostConfig) f64 {
    const lo: f64 = @floatFromInt(cfg.rtt_min);
    const hi: f64 = @floatFromInt(cfg.rtt_max);
    if (srtt <= lo) return 0;
    if (hi <= lo) return 1;
    return @min((srtt - lo) / (hi - lo), 1.0);
}

/// Jitter penalty in [0, 1]: `jitter / jitter_max`, clamped.
pub fn jitterPenalty(jitter: f64, cfg: PathCostConfig) f64 {
    if (cfg.jitter_max == 0) return if (jitter > 0) 1 else 0;
    const hi: f64 = @floatFromInt(cfg.jitter_max);
    return std.math.clamp(jitter / hi, 0.0, 1.0);
}

/// Hysteresis policy for `Selector`.
pub const SelectorConfig = struct {
    /// A challenger must cost at least this much LESS than the incumbent
    /// (nominal link costs) to start counting. 0.2 ≈ 22 ms of RTT inside the
    /// default penalty band. SELF-DERIVED: about five standard deviations of
    /// the smoothed cost of a path with uniform ±20 ms RTT noise at the
    /// default `metric_smoothing` (σ_EWMA = σ·√(α/(2−α)) ≈ 4.5 ms; see the
    /// noisy-RTT test), while still separating LTE-class from 5G-class RTTs.
    margin: f64 = 0.2,
    /// …and stay that much cheaper continuously for this long before the
    /// switch happens — the "slow to trust" half, mirroring
    /// `Config.up_threshold`. Long enough that the cost spike of one lost
    /// probe on the incumbent (it decays within a few probe intervals) does
    /// not move traffic.
    hold: Time = 5000,
};

/// Picks one path out of several and keeps it until another is clearly and
/// durably better — so per-probe noise in `pathCost()` does not move traffic
/// back and forth. Holds only indices; the caller owns the estimators and must
/// pass them in the same order on every `update`.
pub const Selector = struct {
    cfg: SelectorConfig,
    /// Index of the selected path, or `null` before the first `update` with a
    /// non-empty slice.
    current: ?usize = null,
    /// The path currently accumulating `hold` time, and since when.
    challenger: ?usize = null,
    challenger_since: Time = 0,
    /// Number of times `current` changed from one path to another.
    switches: u64 = 0,

    pub fn init(cfg: SelectorConfig) Selector {
        return .{ .cfg = cfg };
    }

    /// Re-evaluate at caller-clock `now`. Returns the selected index (`null`
    /// iff `paths` is empty). Rules, in order:
    ///   1. the cheapest path that is not `.down` is the candidate (cheapest
    ///      overall if every path is `.down`); ties go to the lower index;
    ///   2. no selection yet, the selection fell out of range, or the
    ///      incumbent is `.down` while the candidate is not → take the
    ///      candidate immediately (fast failover);
    ///   3. otherwise switch only when the candidate has cost at least
    ///      `margin` less than the incumbent at every `update` for `hold`.
    pub fn update(self: *Selector, now: Time, paths: []const *const Estimator) ?usize {
        if (paths.len == 0) {
            self.current = null;
            self.challenger = null;
            return null;
        }
        var best: usize = 0;
        var best_live = paths[0].state() != .down;
        var best_cost = paths[0].pathCost();
        for (paths[1..], 1..) |p, i| {
            const live = p.state() != .down;
            const c = p.pathCost();
            if ((live and !best_live) or (live == best_live and c < best_cost)) {
                best = i;
                best_live = live;
                best_cost = c;
            }
        }

        const cur = self.current orelse return self.take(best);
        if (cur >= paths.len) return self.take(best);
        if (cur == best) {
            self.challenger = null;
            return cur;
        }
        if (paths[cur].state() == .down and best_live) return self.take(best);

        if (best_cost + self.cfg.margin <= paths[cur].pathCost()) {
            if (self.challenger != best) {
                self.challenger = best;
                self.challenger_since = now;
            }
            if (now - self.challenger_since >= self.cfg.hold) return self.take(best);
        } else {
            self.challenger = null;
        }
        return cur;
    }

    fn take(self: *Selector, idx: usize) usize {
        if (self.current) |c| {
            if (c != idx) self.switches += 1;
        }
        self.current = idx;
        self.challenger = null;
        return idx;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Babel units → this module's units: Babel cost C on a link of nominal cost
/// 96 corresponds to (C − 96) / 96 here.
fn fromBabel(c: f64) f64 {
    return (c - 96.0) / 96.0;
}

test "cost: default RTT penalty follows babeld's documented tunnel defaults" {
    // babeld(8): "The additional cost is linear in (rtt - rtt-min)", rtt-min
    // 10 ms, rtt-max 120 ms, max-rtt-penalty 96 on a tunnel, rxcost 96. The
    // expected values below are that documented formula evaluated by hand
    // (Babel units on the right), not output of babeld.
    const cfg: PathCostConfig = .{};
    const clean = CostInputs{ .loss = 0, .srtt = 0, .jitter = 0, .state = .up };
    var in = clean;
    in.srtt = 5; // below rtt-min: 96
    try testing.expectApproxEqAbs(fromBabel(96), defaultCost(in, cfg), 1e-12);
    in.srtt = 65; // 96 + 96 * 55 / 110 = 144
    try testing.expectApproxEqAbs(fromBabel(144), defaultCost(in, cfg), 1e-12);
    in.srtt = 120; // at rtt-max: 96 + 96 = 192
    try testing.expectApproxEqAbs(fromBabel(192), defaultCost(in, cfg), 1e-12);
    in.srtt = 600; // saturated
    try testing.expectApproxEqAbs(fromBabel(192), defaultCost(in, cfg), 1e-12);
    // ETX on a 50%-loss link doubles the nominal cost: 96 * 2 = 192.
    in = clean;
    in.loss = 0.5;
    try testing.expectApproxEqAbs(fromBabel(192), defaultCost(in, cfg), 1e-12);
}

fn runPath(est: *Estimator, n: usize, interval: Time, rtt: Time, lose_every: usize) void {
    var now: Time = 0;
    for (0..n) |i| {
        now += interval;
        if (lose_every != 0 and i % lose_every == lose_every - 1)
            est.onProbeTimeout(now)
        else
            est.onProbeReply(now, rtt);
    }
}

test "cost: equal loss, different RTT — LTE is preferred over GEO satellite" {
    // Same loss pattern on both (every 10th probe lost), RTT 50 vs 600.
    var lte = Estimator.init(.{});
    var sat = Estimator.init(.{});
    var now: Time = 0;
    var compared: usize = 0;
    for (0..500) |i| {
        now += 200;
        if (i % 10 == 9) {
            lte.onProbeTimeout(now);
            sat.onProbeTimeout(now);
        } else {
            lte.onProbeReply(now, 50);
            sat.onProbeReply(now, 600);
        }
        try testing.expectApproxEqAbs(lte.metric(), sat.metric(), 0);
        // The loss term is identical, so the order is the RTT's: strictly at
        // every step (the satellite's smoothed RTT is pinned at rtt_max).
        try testing.expect(lte.pathCost() < sat.pathCost());
        compared += 1;
    }
    try testing.expect(compared == 500);
    // Two clean paths: the gap is exactly the penalty difference.
    var a = Estimator.init(.{});
    var b = Estimator.init(.{});
    runPath(&a, 50, 200, 50, 0);
    runPath(&b, 50, 200, 600, 0);
    try testing.expectApproxEqAbs(@as(f64, 40.0 / 110.0), a.pathCost(), 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1.0), b.pathCost(), 1e-9);
}

test "cost: large loss dominates any RTT" {
    // A clean satellite path vs a 20 ms terrestrial path losing 3 of 4 probes.
    var sat = Estimator.init(.{});
    var lossy = Estimator.init(.{});
    runPath(&sat, 200, 200, 600, 0);
    runPath(&lossy, 200, 200, 20, 0);
    // Healthy terrestrial path first beats the satellite …
    try testing.expect(lossy.pathCost() < sat.pathCost());
    var now: Time = 200 * 200;
    for (0..200) |i| {
        now += 200;
        sat.onProbeReply(now, 600);
        if (i % 4 == 0) lossy.onProbeReply(now, 20) else lossy.onProbeTimeout(now);
        if (i >= 20) try testing.expect(lossy.pathCost() > sat.pathCost());
    }
    // … but once it loses 75% the satellite wins at every step, including
    // right after one of the lossy path's replies (its cheapest moment).
    try testing.expect(lossy.pathCost() > sat.pathCost());

    // The documented bound: smoothed loss above w / (1 + w) costs more than
    // any loss-free path, whatever its RTT (jitter weight at its default 0).
    const cfg: PathCostConfig = .{};
    const worst_clean = defaultCost(.{ .loss = 0, .srtt = 1e9, .jitter = 0, .state = .up }, cfg);
    const bound = cfg.rtt_weight / (1.0 + cfg.rtt_weight);
    try testing.expect(defaultCost(.{ .loss = bound + 1e-6, .srtt = 0, .jitter = 0, .state = .up }, cfg) > worst_clean);
    // And a dead path's cost is large and finite.
    var dead = Estimator.init(.{});
    runPath(&dead, 300, 200, 20, 1);
    try testing.expect(std.math.isFinite(dead.pathCost()));
    try testing.expect(dead.pathCost() > 1000);
}

test "cost: jitter counts only when weighted" {
    // Same mean RTT (60), same loss (none); one path alternates 30/90.
    const on: root.Config = .{ .path_cost = .{ .jitter_weight = 0.5 } };
    var steady_off = Estimator.init(.{});
    var jittery_off = Estimator.init(.{});
    var steady_on = Estimator.init(on);
    var jittery_on = Estimator.init(on);
    var now: Time = 0;
    for (0..400) |i| {
        now += 200;
        const r: Time = if (i % 2 == 0) 30 else 90;
        steady_off.onProbeReply(now, 60);
        jittery_off.onProbeReply(now, r);
        steady_on.onProbeReply(now, 60);
        jittery_on.onProbeReply(now, r);
    }
    // The RFC 3550 jitter of a 30/90 alternation converges to 60 ≥ jitter_max.
    try testing.expect(jittery_on.costInputs().jitter > 30);
    try testing.expectApproxEqAbs(@as(f64, 0), steady_on.costInputs().jitter, 1e-9);
    // Off: only the smoothed RTT differs, and it oscillates around 60, so the
    // two costs stay within the RTT noise; on: the jittery path pays +0.5.
    try testing.expect(@abs(jittery_off.pathCost() - steady_off.pathCost()) < 0.2);
    try testing.expect(jittery_on.pathCost() - steady_on.pathCost() > 0.3);
    try testing.expectApproxEqAbs(
        jittery_on.pathCost() - jittery_off.pathCost(),
        @as(f64, 0.5),
        1e-9,
    );
}

test "cost: lossOnlyCost reproduces the old pathCost values" {
    var est = Estimator.init(.{ .path_cost = .{ .cost_fn = lossOnlyCost } });
    runPath(&est, 100, 200, 600, 3);
    try testing.expectEqual(est.metric(), est.pathCost());
    // rtt_weight = 0 keeps the default ETX shape but the loss-only ORDER.
    var a = Estimator.init(.{ .path_cost = .{ .rtt_weight = 0 } });
    var b = Estimator.init(.{ .path_cost = .{ .rtt_weight = 0 } });
    runPath(&a, 100, 200, 600, 5);
    runPath(&b, 100, 200, 20, 4);
    try testing.expect((a.metric() < b.metric()) == (a.pathCost() < b.pathCost()));
}

test "cost: pathCost stays pointwise monotone across the whole RTT range, for any RTT weight" {
    // property.zig drives RTTs below rtt_max at the default config; this
    // stream crosses rtt_min and rtt_max, which is where the clamp and the
    // timeout-as-rtt_max rule matter. A heavy RTT weight is included because
    // at weight <= 1 the ETX jump of a timeout happens to outweigh any one RTT
    // step, which would hide a smoother that skipped timeouts.
    const cfgs = [_]root.Config{
        .{},
        .{ .path_cost = .{ .rtt_weight = 4 } },
        .{ .metric_smoothing = 0.8, .path_cost = .{ .rtt_weight = 10, .rtt_max = 300 } },
    };
    for (cfgs, 0..) |cfg, k| {
        var prng = std.Random.DefaultPrng.init(0x5A7E11 + k);
        const rng = prng.random();
        var a = Estimator.init(cfg);
        var b = Estimator.init(cfg);
        var now: Time = 0;
        for (0..2000) |_| {
            now += 200;
            const lost = rng.uintLessThan(u32, 8) == 0;
            const rtt = rng.uintLessThan(Time, 400);
            if (lost) a.onProbeTimeout(now) else a.onProbeReply(now, rtt);
            // b: pointwise worse — every timeout kept, each reply slower or lost.
            if (lost or rng.uintLessThan(u32, 4) == 0)
                b.onProbeTimeout(now)
            else
                b.onProbeReply(now, rtt + rng.uintLessThan(Time, 200));
            try testing.expect(b.pathCost() >= a.pathCost() - 1e-12);
        }
    }
}

test "selector: no flapping under noisy RTT around the incumbent's cost" {
    // A: steady 65 ms. B: uniform 45..85 ms (mean 65) — the two costs cross
    // constantly. Raw argmin would flip many times; the Selector must not move.
    var prng = std.Random.DefaultPrng.init(0xF1A9);
    const rng = prng.random();
    var a = Estimator.init(.{});
    var b = Estimator.init(.{});
    const paths = [_]*const Estimator{ &a, &b };
    var sel = Selector.init(.{});
    var now: Time = 0;
    var raw_flips: usize = 0;
    var raw_prev: ?bool = null;
    for (0..20) |_| { // identical warm-up: the tie goes to A (index 0)
        now += 200;
        a.onProbeReply(now, 65);
        b.onProbeReply(now, 65);
        try testing.expectEqual(@as(?usize, 0), sel.update(now, &paths));
    }
    for (0..20_000) |_| {
        now += 200;
        a.onProbeReply(now, 65);
        b.onProbeReply(now, 45 + rng.uintLessThan(Time, 41));
        _ = sel.update(now, &paths);
        const raw = b.pathCost() < a.pathCost();
        if (raw_prev) |p| {
            if (p != raw) raw_flips += 1;
        }
        raw_prev = raw;
    }
    try testing.expect(raw_flips > 1000); // vacuity: the noise really crosses
    try testing.expectEqual(@as(u64, 0), sel.switches);
    try testing.expectEqual(@as(?usize, 0), sel.current);
}

test "selector: one lost probe on the incumbent does not move traffic" {
    var a = Estimator.init(.{});
    var b = Estimator.init(.{});
    const paths = [_]*const Estimator{ &a, &b };
    var sel = Selector.init(.{});
    var now: Time = 0;
    for (0..400) |i| {
        now += 200;
        // Equal 40 ms paths; A loses one probe in every 50.
        if (i % 50 == 49) a.onProbeTimeout(now) else a.onProbeReply(now, 40);
        b.onProbeReply(now, 40);
        _ = sel.update(now, &paths);
    }
    try testing.expectEqual(@as(u64, 0), sel.switches);
    try testing.expectEqual(@as(?usize, 0), sel.current);
}

test "selector: a durable improvement switches once, after hold" {
    var a = Estimator.init(.{});
    var b = Estimator.init(.{});
    const paths = [_]*const Estimator{ &a, &b };
    var sel = Selector.init(.{});
    var now: Time = 0;
    for (0..50) |_| {
        now += 200;
        a.onProbeReply(now, 30);
        b.onProbeReply(now, 60);
        try testing.expectEqual(@as(?usize, 0), sel.update(now, &paths));
    }
    // A's RTT rises to 110 ms for good: B (60 ms) is now ~0.45 cheaper.
    var switched_at: ?Time = null;
    var first_better: ?Time = null;
    for (0..200) |_| {
        now += 200;
        a.onProbeReply(now, 110);
        b.onProbeReply(now, 60);
        if (first_better == null and b.pathCost() + sel.cfg.margin <= a.pathCost()) first_better = now;
        const s = sel.update(now, &paths);
        if (switched_at == null and s == 1) switched_at = now;
    }
    try testing.expectEqual(@as(u64, 1), sel.switches);
    try testing.expectEqual(@as(?usize, 1), sel.current);
    try testing.expectEqual(first_better.? + sel.cfg.hold, switched_at.?);
}

test "selector: a .down incumbent is left immediately" {
    var a = Estimator.init(.{});
    var b = Estimator.init(.{});
    const paths = [_]*const Estimator{ &a, &b };
    var sel = Selector.init(.{});
    var now: Time = 0;
    for (0..50) |_| {
        now += 200;
        a.onProbeReply(now, 20);
        b.onProbeReply(now, 100);
        _ = sel.update(now, &paths);
    }
    try testing.expectEqual(@as(?usize, 0), sel.current);
    // A dies: the first update that sees A `.down` moves to B, no hold.
    var t: Time = now;
    while (a.state() != .down) {
        t += 500;
        a.onProbeTimeout(t);
        b.onProbeReply(t, 100);
        if (a.state() != .down) try testing.expectEqual(@as(?usize, 0), sel.update(t, &paths));
    }
    try testing.expectEqual(@as(?usize, 1), sel.update(t, &paths));
    try testing.expectEqual(@as(u64, 1), sel.switches);
    // Edge cases: empty slice, and a selection past the end of a shorter slice.
    try testing.expectEqual(@as(?usize, 0), sel.update(t, paths[0..1]));
    try testing.expectEqual(@as(?usize, null), sel.update(t, &.{}));
}
