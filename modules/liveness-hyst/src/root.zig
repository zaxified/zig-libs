// SPDX-License-Identifier: MIT
//! liveness-hyst — BFD-like link-liveness estimator with hysteresis.
//!
//! Built for an encrypted L2VPN fabric over WireGuard:
//! WireGuard has no fast liveness and internet paths (LTE/satellite) flap, so a naive
//! BFD timer turns a degraded link into fabric-wide oscillation. This estimator combines
//! echo-probe timing with jitter/loss statistics (`latency-stats`) and Babel-style metric
//! smoothing as an *input filter* to the link-state metric: fast detection (bounded
//! latency) without flap-driven churn. Scored against a replayable trace corpus in
//! `netsim` for detection-latency vs spurious-failover trade-off.
//!
//! This file is the fully-built shell: the `Estimator` type (probe ingestion, cumulative
//! `latency-stats` accumulation, a fixed-capacity recent-probe ring, verdict accessors).
//! The trace corpus lives in `trace.zig`; the scoring + property harness lives in
//! `scoring.zig` and `property.zig`. The ONE irreducible piece — the hysteresis decision
//! itself (combine probe timing + jitter/loss into an up/suspect/down verdict + a smoothed
//! metric, with asymmetric thresholds/damping) — is `core.decide` (`src/core.zig`), which
//! also documents the adjudicated monotonicity contract: order paths by `pathCost()`
//! (monotone), treat `state()` as the damped transition-timing signal.

const std = @import("std");
const netsim = @import("netsim");
const latency_stats = @import("latency-stats");
const core = @import("core.zig");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "BFD (RFC 5880) liveness + Babel-style metric hysteresis",
    .deps = .{ "netsim", "latency-stats" },
};

/// Simulated time, in abstract ticks — the same unit as `netsim.Time` (the trace
/// corpus drives an `Estimator` directly off a `netsim.Sim`'s clock). The Estimator
/// never reads a wall clock; every `now` is caller-supplied. Convention adopted by
/// this module's trace corpus and scoring harness (see `trace.zig` / `scoring.zig`):
/// **1 tick = 1 millisecond**, so the ≤1.5s detection-latency target is literally
/// 1500 ticks and "a simulated week" is 604_800_000 ticks — the Estimator itself is
/// agnostic to what a tick means.
pub const Time = netsim.Time;

/// The liveness verdict. `rank()` gives the informal "up-ness" order
/// (`up` > `suspect` > `down`) for tests and display, but it is NOT monotone in
/// stream quality inside {`.suspect`, `.down`} (a degraded-but-usable link is
/// deliberately harder to fail over than a clean one — see `core.decide`'s
/// contract) and MUST NOT be used to order paths for forwarding preference —
/// use `Estimator.pathCost()` for that.
pub const LinkState = enum {
    up,
    suspect,
    down,

    /// `up` = 2 (most "up"), `down` = 0 (least "up"). Display/test ordering
    /// only — see the type doc for why this is not a forwarding-preference key.
    pub fn rank(self: LinkState) u8 {
        return switch (self) {
            .down => 0,
            .suspect => 1,
            .up => 2,
        };
    }
};

/// Hysteresis knobs. All fields here are consumed entirely by `core.decide` — this
/// struct just declares and documents the shape of the tuning surface; the semantics
/// (how a threshold is actually applied) are the Fable core's to define.
pub const Config = struct {
    /// Nominal echo-probe cadence the caller intends to drive `onProbeReply` /
    /// `onProbeTimeout` at. The Estimator does not schedule probes itself (the
    /// caller's clock drives it) — this is a hint the Fable core may use to
    /// interpret the threshold fields below in probe-count-equivalent terms.
    probe_interval: Time = 200,

    /// Target maximum time (same unit as `Time`) to declare `.down` after a
    /// genuine, sustained failure begins. Ties to this module's scoring-harness
    /// bound (`scoring.DETECTION_LATENCY_TARGET`).
    down_threshold: Time = 1500,

    /// Minimum sustained good-probe evidence required to climb back from
    /// `.suspect` / `.down` to `.up` — the "slow to trust recovery" half of the
    /// asymmetric hysteresis: a flapping link must not oscillate the verdict as
    /// fast as it oscillates itself.
    up_threshold: Time = 5000,

    /// EWMA smoothing weight in (0, 1] for the Babel-style smoothed link metric
    /// (input filter): smaller = more damping, larger = more reactive.
    metric_smoothing: f64 = 0.25,

    /// Loss fraction (0..1, as read from the internal `latency_stats.Accumulator`)
    /// above which a link should be treated as merely "degraded" rather than
    /// failed — the boundary the flap-damping logic must respect so a
    /// merely-lossy-but-usable link is not flushed to `.down`.
    degraded_loss_threshold: f64 = 0.30,
};

/// A liveness verdict at a point in time.
pub const Verdict = struct {
    state: LinkState = .up,
    /// Smoothed link metric (Babel-style input-filter output): an EWMA of
    /// per-probe loss cost in [0, 1], lower is better. Doubles as the monotone
    /// failover-ordering key — see `Estimator.pathCost`.
    metric: f64 = 0,
    /// Caller-clock time of the most recent state transition (dwell-time /
    /// anti-flap accounting, if a caller wants it).
    since: Time = 0,
};

/// One probe outcome, as stored in the Estimator's bounded recent-probe ring.
pub const Probe = struct {
    at: Time,
    /// RTT of a reply, or `null` for an unanswered probe (timeout).
    rtt: ?Time,
};

/// Fixed capacity of `Estimator.history`. Bounded by construction — the
/// Estimator's memory footprint does not grow with the length of the probe
/// stream (see `property.zig`'s bounded-memory test). 64 gives the Fable core a
/// hysteresis window of many probe intervals without needing an allocator.
pub const history_capacity: usize = 64;

/// Ingests per-probe observations on a caller-supplied clock and exposes the
/// current liveness verdict. All bookkeeping in THIS type is mechanical (stats
/// accumulation, ring-buffer history, consecutive-timeout streak); the actual
/// up/suspect/down decision + metric smoothing is delegated to `core.decide` —
/// see that function's doc for the design contract it must satisfy.
pub const Estimator = struct {
    cfg: Config,
    /// Cumulative RTT/jitter/loss statistics since `init` (see `latency-stats`);
    /// read via `snapshot()`. The Fable core may also read this directly.
    stats: latency_stats.Accumulator = latency_stats.Accumulator.init(),
    /// The current (and, between calls, the previous — see `core.decide`'s doc)
    /// verdict. This is the ONLY place damping/smoothing state may persist
    /// between probe events.
    verdict: Verdict = .{},
    /// Recent-probe ring buffer, fixed capacity — see `recentProbes`.
    history: [history_capacity]Probe = undefined,
    history_len: usize = 0,
    history_head: usize = 0,
    /// Consecutive unanswered probes since the last reply (resets to 0 on any
    /// reply) — mechanical bookkeeping the Fable core may use directly instead
    /// of re-deriving it from `history`.
    consecutive_timeouts: u32 = 0,
    /// Total probes observed (replies + timeouts).
    probes_total: u64 = 0,

    pub fn init(cfg: Config) Estimator {
        return .{ .cfg = cfg };
    }

    /// Record a reply with round-trip time `rtt` at caller-clock `now`.
    pub fn onProbeReply(self: *Estimator, now: Time, rtt: Time) void {
        self.stats.addSample(rtt);
        self.pushHistory(.{ .at = now, .rtt = rtt });
        self.consecutive_timeouts = 0;
        self.probes_total += 1;
        self.verdict = core.decide(self, now);
    }

    /// Record an unanswered probe (timeout) at caller-clock `now`.
    pub fn onProbeTimeout(self: *Estimator, now: Time) void {
        self.stats.addLoss();
        self.pushHistory(.{ .at = now, .rtt = null });
        self.consecutive_timeouts += 1;
        self.probes_total += 1;
        self.verdict = core.decide(self, now);
    }

    /// The current up/suspect/down verdict.
    pub fn state(self: *const Estimator) LinkState {
        return self.verdict.state;
    }

    /// The current smoothed link metric (EWMA loss cost in [0, 1]; lower is
    /// better — see `core.decide`).
    pub fn metric(self: *const Estimator) f64 {
        return self.verdict.metric;
    }

    /// The MONOTONE failover-ordering key: when choosing which of several
    /// paths to prefer for forwarding, order by ascending `pathCost()` (lower
    /// = better), NOT by `state().rank()`. Contract (enforced by
    /// `property.zig`): for two estimators fed paired probe streams where one
    /// stream is pointwise worse-or-equal (every reply as slow or slower, or
    /// degraded to a timeout; every timeout kept), the worse stream's
    /// `pathCost()` is never lower — so a strictly-worse path is never
    /// strictly preferred. `state()` deliberately does NOT have this property
    /// inside {`.suspect`, `.down`} (anti-flap damping — see `core.decide`'s
    /// adjudicated contract), which is exactly why forwarding preference must
    /// key off this cost instead.
    pub fn pathCost(self: *const Estimator) f64 {
        return self.verdict.metric;
    }

    /// Snapshot of the cumulative RTT/jitter/loss statistics.
    pub fn snapshot(self: *const Estimator) latency_stats.Stats {
        return self.stats.snapshot();
    }

    /// Copy up to `out.len` of the most recent probes, oldest first, into `out`.
    /// Returns the number written (`<= history_capacity`, `<= out.len`).
    pub fn recentProbes(self: *const Estimator, out: []Probe) usize {
        const n = @min(self.history_len, out.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const idx = (self.history_head + history_capacity - n + i) % history_capacity;
            out[i] = self.history[idx];
        }
        return n;
    }

    fn pushHistory(self: *Estimator, p: Probe) void {
        self.history[self.history_head] = p;
        self.history_head = (self.history_head + 1) % history_capacity;
        if (self.history_len < history_capacity) self.history_len += 1;
    }
};

// ── smoke: the shell works WITHOUT ever touching the Fable stub ─────────────

test "smoke: Estimator constructs with defaults and starts .up with no history" {
    const est = Estimator.init(.{});
    try std.testing.expectEqual(LinkState.up, est.state());
    try std.testing.expectApproxEqAbs(@as(f64, 0), est.metric(), 1e-9);
    try std.testing.expectEqual(@as(u64, 0), est.probes_total);
    var buf: [4]Probe = undefined;
    try std.testing.expectEqual(@as(usize, 0), est.recentProbes(&buf));
    const s = est.snapshot();
    try std.testing.expectEqual(@as(u64, 0), s.sent);
    try std.testing.expectEqual(@as(u64, 0), s.received);
}

test "recentProbes: returns the most recent probes, oldest-first, across a wraparound" {
    var est = Estimator.init(.{});
    // Push more than history_capacity so the ring wraps at least once, then
    // request fewer than the full window: `recentProbes` must hand back
    // exactly the LAST `out.len` probes, oldest-first, not an off-by-one
    // rotation of them.
    const total = history_capacity + 5;
    var i: Time = 0;
    while (i < total) : (i += 1) {
        est.onProbeReply(i, 20);
    }
    var buf: [10]Probe = undefined;
    const n = est.recentProbes(&buf);
    try std.testing.expectEqual(@as(usize, 10), n);
    var j: usize = 0;
    while (j < 10) : (j += 1) {
        // The most recent probe was fed at `at == total - 1`; the window of
        // the last 10 is oldest-first, so buf[j].at == total - 10 + j.
        try std.testing.expectEqual(@as(Time, total - 10 + j), buf[j].at);
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("core.zig");
    _ = @import("trace.zig");
    _ = @import("scoring.zig");
    _ = @import("property.zig");
}
