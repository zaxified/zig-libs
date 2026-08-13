// SPDX-License-Identifier: MIT
//! The irreducible liveness-decision algorithm: Babel-style metric smoothing used
//! as an INPUT FILTER to an up/suspect/down verdict (see root.zig's module doc for
//! the full problem statement).
//!
//! FABLE CORE — `decide` below is the implemented hysteresis kernel. Its design
//! contract (including the adjudicated monotonicity trade-off) is documented on
//! `decide` itself; `scoring.zig` (detection latency, failover budget) and
//! `property.zig` (monotone path cost, up-boundary monotonicity, the pinned
//! degraded-vs-clean state inversion) are the executable teeth.

const std = @import("std");
const root = @import("root.zig");

/// Combine the probe event JUST folded into `est.stats` / `est.history` (all
/// mechanical bookkeeping already done by the caller — see
/// `Estimator.onProbeReply` / `onProbeTimeout` in root.zig) into an updated
/// up/suspect/down verdict + smoothed link metric.
///
/// `est` is the FULL estimator state as of the instant the current probe was
/// folded in: `est.stats` (cumulative RTT/jitter/loss via `latency-stats`),
/// `est.history` / `recentProbes()` (bounded recent-probe window),
/// `est.consecutive_timeouts`, `est.cfg` (the hysteresis knobs —
/// `down_threshold` / `up_threshold` / `metric_smoothing` /
/// `degraded_loss_threshold`), and `est.verdict` (the PREVIOUS verdict, i.e. the
/// value to smooth/hold/transition FROM — this is where damping state persists
/// between calls, since the Estimator holds no other per-call scratch space).
///
/// Design contract (see `scoring.zig` for the executable form of these bounds,
/// and `property.zig` for the two structural properties):
///   - Detection latency on a hard, sustained failure must be bounded — see
///     `scoring.DETECTION_LATENCY_TARGET` (1.5s-equivalent).
///   - Spurious `.down` transitions on a flapping-but-usable or merely
///     lossy-but-usable link must stay under
///     `scoring.SPURIOUS_FAILOVER_BUDGET_PER_WEEK` — this is what the asymmetric
///     up/down thresholds + EWMA metric damping are FOR: a naive "N consecutive
///     misses -> down" timer (classic BFD) fails this bound on a 30%-loss
///     flapping link. Babel's metric-smoothing-as-input-filter idea (damp the
///     INPUT before it ever reaches a hard threshold, instead of just widening
///     the threshold) is the model to follow.
///   - Monotonicity (`property.zig`) — ADJUDICATED TRADE-OFF: strict pointwise
///     monotonicity of the 3-state verdict ("a pointwise-worse probe stream is
///     never ranked more `.up` at any corresponding point in time") is PROVABLY
///     INCOMPATIBLE with the two bounds above, for ANY estimator whose verdict
///     is a function of its own probe stream: the detection bound forces a
///     clean stream into `.down` within ~2 misses of a burst, while the
///     failover budget forbids a 30%-degraded stream — whose ROUTINE bursts
///     are locally indistinguishable from death inside the 1.5s window — from
///     doing the same on every such burst (that would be thousands of
///     failovers/week). So at a shared terminal burst the degraded,
///     pointwise-worse stream necessarily sits at `.suspect` while the clean
///     one is already `.down`. The contract is therefore split into what CAN
///     be guaranteed, and each part is enforced by `property.zig`:
///       (1) FORWARDING SAFETY (strict, monotone): path preference must order
///           by `Estimator.pathCost()` — the smoothed metric — never by state
///           rank. The metric is a fixed-weight EWMA of per-probe cost and is
///           therefore pointwise monotone (even under f64 rounding, since each
///           EWMA step is a composition of monotone rounded operations): a
///           pointwise-worse stream never gets a LOWER cost, so a worse path
///           is never strictly preferred for forwarding.
///       (2) UP-BOUNDARY monotonicity of the state (strict): a pointwise-worse
///           stream is never `.up` when the better stream is not. Guaranteed
///           for every config by the UNIFORM recovery gate below (`.down` and
///           `.suspect` climb through the identical quiet+metric test, so the
///           better stream can never lag the worse one into `.up`).
///       (3) Inside {`.suspect`, `.down`} the state is intentionally
///           NON-monotone across loss regimes — that inversion IS the
///           anti-flap damping. The state is a transition-TIMING signal for
///           reconvergence, not an ordering key; `property.zig` pins the
///           inversion as a permanent regression case so any "fix" that
///           re-couples ranking to state must re-open this adjudication.
///   - Bounded memory: do not stash any state outside `est`'s existing
///     fixed-size fields (e.g. no static/global maps keyed by probe id) —
///     `est.verdict` is the ONLY place damping/smoothing state may persist
///     between calls.
/// Consecutive unanswered probes required to declare `.down` on a link already
/// classified as lossy-but-usable (recent/cumulative loss above
/// `Config.degraded_loss_threshold`). Rationale: on such a link, isolated and
/// short timeout bursts are its NORMAL behavior, so only total, sustained
/// silence may fail it over. Even at ~50% residual probe loss (worse than the
/// 30% design point), P(streak >= 18) ≈ 0.51^17 ≈ 1e-5 per burst — about half
/// a spurious failover per simulated week of continuous probing, comfortably
/// inside `scoring.SPURIOUS_FAILOVER_BUDGET_PER_WEEK`. At the 30% design point
/// itself the expected rate is ~1e-4/week.
const degraded_consec_floor: u32 = 18;

pub fn decide(est: *const root.Estimator, now: root.Time) root.Verdict {
    const cfg = est.cfg;
    const prev = est.verdict;

    // The caller (Estimator.onProbeReply/onProbeTimeout) folds the current
    // probe into `history` BEFORE calling us, so the ring is never empty here
    // and its newest entry IS the event we are deciding on.
    std.debug.assert(est.history_len > 0);
    const cap = root.history_capacity;
    const newest = est.history[(est.history_head + cap - 1) % cap];
    const is_timeout = newest.rtt == null;

    // ── Babel-style smoothed metric: EWMA of a per-probe loss cost ──────────
    //
    // The metric is the input filter: a smoothed loss estimate in [0, 1]
    // (0 = perfectly clean, 1 = total silence). Each probe contributes cost 1
    // (timeout) or 0 (reply); `metric_smoothing` is the EWMA weight. This is
    // the ONLY state carried between calls (via `prev.metric`), and the fast
    // down-path thresholds it below — damping the input instead of widening a
    // raw miss-count threshold, per Babel's metric-smoothing idea.
    const alpha = std.math.clamp(cfg.metric_smoothing, 1e-9, 1.0);
    const cost: f64 = if (is_timeout) 1.0 else 0.0;
    const metric = prev.metric + alpha * (cost - prev.metric);

    // Thresholds derived from the smoothing weight so retuning
    // `metric_smoothing` keeps them consistent:
    //   - down: the level two consecutive timeouts reach from a clean metric
    //     (1 - (1-a)^2 = a(2-a)), with a 10% margin. An isolated miss on a
    //     flapping link peaks at ~a·(1+eps) and never gets here.
    //   - up: half of a single miss's contribution — the metric must have
    //     decayed well past the last incident before we trust the link again.
    const theta_down = 0.9 * (alpha * (2.0 - alpha));
    const theta_up = alpha / 2.0;

    // ── bounded-window facts from the history ring (newest → oldest) ────────
    var last_reply_at: ?root.Time = null;
    var last_timeout_at: ?root.Time = null;
    var window_timeouts: usize = 0;
    var i: usize = 0;
    while (i < est.history_len) : (i += 1) {
        const p = est.history[(est.history_head + cap - 1 - i) % cap];
        if (p.rtt == null) {
            window_timeouts += 1;
            if (last_timeout_at == null) last_timeout_at = p.at;
        } else if (last_reply_at == null) {
            last_reply_at = p.at;
        }
    }

    // ── loss regime: is this link merely degraded-but-usable? ───────────────
    //
    // A link whose longer-term loss already exceeds `degraded_loss_threshold`
    // must not be flushed to `.down` by the fast path — timeout bursts are its
    // steady state, not news. Regime = max(cumulative loss, recent-window
    // loss): the cumulative term is stable against lucky clean stretches on a
    // chronically lossy link; the windowed term catches a link that turned
    // lossy long after a clean start.
    const snap = est.stats.snapshot();
    const window_loss = @as(f64, @floatFromInt(window_timeouts)) /
        @as(f64, @floatFromInt(est.history_len));
    const regime_loss = @max(snap.lossPct() / 100.0, window_loss);
    const degraded = regime_loss > cfg.degraded_loss_threshold;

    // ── down decision (independent of the previous state) ───────────────────
    //
    // Fast path — a clean link going genuinely dead: at least two consecutive
    // misses AND the smoothed metric over `theta_down` AND real wall-clock
    // silence. The silence floor is 2/3 of `down_threshold` (1000 of 1500 with
    // defaults): with a serialized prober whose reply→timeout stride is
    // (gap + timeout), the second consecutive miss lands at exactly twice that
    // stride past the last reply, so any prober meeting the classic
    // 3×interval BFD sizing fires here well inside `down_threshold` — while
    // two adjacent 200 ms-spaced misses (only 400 ms of silence) stay merely
    // `.suspect`.
    //
    // Degraded path — see `degraded_consec_floor`.
    const silence_floor: root.Time = cfg.down_threshold * 2 / 3;
    const silent = if (last_reply_at) |t| now - t >= silence_floor else true;
    const fast_down = !degraded and
        est.consecutive_timeouts >= 2 and
        silent and
        metric >= theta_down;
    const down_now = fast_down or est.consecutive_timeouts >= degraded_consec_floor;

    // ── state transition (asymmetric hysteresis) ────────────────────────────
    //
    // Down is entered by evidence alone (above). Climbing back is slow and
    // UNIFORM: on a reply, `.down` and `.suspect` pass through the identical
    // recovery gate — `up_threshold` of timeout-free running AND the smoothed
    // metric decayed under `theta_up` — reaching `.up` if it holds, `.suspect`
    // otherwise. A timeout never improves the state and immediately demotes
    // `.up` to `.suspect`.
    //
    // The gate MUST be uniform (no mandatory `.down` → `.suspect` stopover):
    // with a per-state stopover, a pointwise-worse stream parked at `.suspect`
    // by the degraded damping could satisfy the gate one reply-step BEFORE the
    // cleaner stream still exiting `.down` — reaching `.up` first and breaking
    // up-boundary monotonicity (contract point (2) above; realizable at high
    // `metric_smoothing` with sparse probing — see the property.zig regression
    // "recovery is uniform"). With the uniform gate the implication is
    // config-independent: the worse stream's metric is never lower and its
    // last window-timeout is never older, so whenever the worse stream passes
    // the gate, the better one does too.
    const state: root.LinkState = if (down_now)
        .down
    else if (is_timeout)
        (if (prev.state == .down) .down else .suspect)
    else switch (prev.state) {
        .up => .up,
        .down, .suspect => blk: {
            const quiet = if (last_timeout_at) |t| now - t >= cfg.up_threshold else true;
            break :blk if (quiet and metric <= theta_up) .up else .suspect;
        },
    };

    return .{
        .state = state,
        .metric = metric,
        .since = if (state != prev.state) now else prev.since,
    };
}

test "core: `since` stamps the last TRANSITION, not the last update" {
    // The third field of `Verdict` and the only one nothing else in the module
    // reads: `state` is asserted everywhere, `metric` is the ordering key
    // `property.zig` pins, and `since` — documented as "caller-clock time of
    // the most recent state transition (dwell-time / anti-flap accounting)" —
    // had no assertion anywhere before this test. Dwell time is what a caller
    // damps ITS OWN failover with, so a `since` that restamped on every probe
    // would report a permanently new state and defeat that.
    //
    // The property is checked over a whole scripted stream rather than at one
    // point: `since` must change exactly on the steps where `state` changes,
    // and hold otherwise.
    const testing = std.testing;
    var est = root.Estimator.init(.{});

    try testing.expectEqual(root.LinkState.up, est.verdict.state);
    try testing.expectEqual(@as(root.Time, 0), est.verdict.since);

    // (reply?, time) — two clean replies, a timeout burst that demotes `.up`
    // to `.suspect` and then holds there, and a long quiet recovery back to
    // `.up`. Times are chosen so the burst stays short of the fast-down
    // silence floor (`down_threshold * 2 / 3` = 1000 with defaults).
    const script = [_]struct { reply: bool, at: root.Time }{
        .{ .reply = true, .at = 100 },
        .{ .reply = true, .at = 500 },
        .{ .reply = false, .at = 1000 },
        .{ .reply = false, .at = 1200 },
        .{ .reply = true, .at = 7000 },
        .{ .reply = true, .at = 7200 },
        .{ .reply = true, .at = 7400 },
        .{ .reply = true, .at = 7600 },
        .{ .reply = true, .at = 7800 },
        .{ .reply = true, .at = 8000 },
        .{ .reply = true, .at = 8200 },
    };

    var expected_since: root.Time = 0;
    var transitions: usize = 0;
    var holds: usize = 0;
    for (script) |step| {
        const before = est.verdict.state;
        if (step.reply) est.onProbeReply(step.at, 10) else est.onProbeTimeout(step.at);
        if (est.verdict.state != before) {
            expected_since = step.at;
            transitions += 1;
        } else {
            holds += 1;
        }
        try testing.expectEqual(expected_since, est.verdict.since);
    }

    // Vacuity guard: the stream above must actually exercise both sides of the
    // `if`, or the loop would pass against an implementation that never moves
    // `since` at all (and against one that always moves it).
    try testing.expect(transitions >= 2);
    try testing.expect(holds >= 2);
    // …and it must have gone somewhere and come back, so the transitions are
    // real state changes and not one demotion counted twice.
    try testing.expectEqual(root.LinkState.up, est.verdict.state);
    try testing.expect(est.verdict.since > 1_000);
}
