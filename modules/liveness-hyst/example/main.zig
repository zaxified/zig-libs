// SPDX-License-Identifier: MIT

//! What a fabric consumer does with `liveness-hyst`: drive an `Estimator`
//! off its own clock with a stream of echo-probe outcomes and read back the
//! liveness verdict plus the monotone failover-ordering key.
//!
//! The scenario: a link that is healthy, then degrades into a lossy-but-
//! usable state (should NOT flip straight to `.down` — that is the whole
//! point of the hysteresis), then suffers a genuine sustained outage past
//! `down_threshold` (must eventually reach `.down`).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to drive the estimator is not public, this file stops compiling.

const std = @import("std");
const liveness_hyst = @import("liveness-hyst");

pub fn main() !void {
    var est = liveness_hyst.Estimator.init(.{
        .probe_interval = 200,
        .down_threshold = 1500,
        .up_threshold = 5000,
    });

    var now: liveness_hyst.Time = 0;

    // Healthy period: steady low-RTT replies every 200 ticks.
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        est.onProbeReply(now, 15);
        now += 200;
    }
    std.debug.print("after healthy run: state={s} metric={d:.3} cost={d:.3}\n", .{
        @tagName(est.state()), est.metric(), est.pathCost(),
    });
    if (est.state() != .up) @panic("a steadily healthy link must read .up");

    // Degraded-but-usable: every third probe times out, the rest reply with
    // higher RTT. Hysteresis should keep this from immediately reading .down.
    i = 0;
    while (i < 12) : (i += 1) {
        if (i % 3 == 0) {
            est.onProbeTimeout(now);
        } else {
            est.onProbeReply(now, 80);
        }
        now += 200;
    }
    std.debug.print("after degraded run: state={s} metric={d:.3} cost={d:.3}\n", .{
        @tagName(est.state()), est.metric(), est.pathCost(),
    });
    if (est.state() == .down) @panic("a merely-lossy link must not be flushed straight to .down");

    // Genuine sustained outage: consecutive timeouts past down_threshold.
    //
    // The preceding degraded run already pushed this link's cumulative/
    // windowed loss over `degraded_loss_threshold` (30% by default), so by
    // the time this loop starts the estimator classifies it as an already-
    // lossy link, not a freshly-dying clean one. Per the module's documented
    // anti-flap design (core.zig's `decide`), a lossy-classified link is
    // deliberately NOT failed over by the fast 2-consecutive-miss path —
    // isolated timeout bursts are its normal behavior. It only reaches
    // `.down` once misses are total and sustained: `degraded_consec_floor`
    // (18) consecutive timeouts. So this loop must run well past 18 probe
    // intervals, not just past `down_threshold` in wall-clock time.
    const outage_start = now;
    while (now - outage_start < 4000) : (now += 200) {
        est.onProbeTimeout(now);
    }
    std.debug.print("after sustained outage: state={s} metric={d:.3} consecutive_timeouts={d}\n", .{
        @tagName(est.state()), est.metric(), est.consecutive_timeouts,
    });
    if (est.state() != .down) @panic("a sustained outage past down_threshold must read .down");

    // The cumulative stats accumulator (latency-stats.Stats, re-derived
    // through the estimator's own snapshot rather than imported directly).
    const snap = est.snapshot();
    std.debug.print("cumulative: sent={d} received={d}\n", .{ snap.sent, snap.received });

    // Bounded memory: the recent-probe ring never exceeds history_capacity
    // regardless of how many probes were fed.
    var recent: [liveness_hyst.history_capacity]liveness_hyst.Probe = undefined;
    const n = est.recentProbes(&recent);
    std.debug.print("recent probe window: {d} of capacity {d}, total observed={d}\n", .{
        n, liveness_hyst.history_capacity, est.probes_total,
    });

    // Ordering two live paths: an LTE uplink (~50 ms) and a GEO satellite
    // (~600 ms), both loss-free. `pathCost()` folds the smoothed RTT into the
    // cost (Babel-style RTT penalty), and a `Selector` keeps the choice from
    // flapping when the costs are close.
    var lte = liveness_hyst.Estimator.init(.{});
    var sat = liveness_hyst.Estimator.init(.{});
    const paths = [_]*const liveness_hyst.Estimator{ &sat, &lte };
    var sel = liveness_hyst.Selector.init(.{});
    var t: liveness_hyst.Time = 0;
    var chosen: ?usize = null;
    i = 0;
    while (i < 50) : (i += 1) {
        t += 200;
        lte.onProbeReply(t, 50);
        sat.onProbeReply(t, 600);
        chosen = sel.update(t, &paths);
    }
    std.debug.print("lte cost={d:.3} sat cost={d:.3} chosen={s}\n", .{
        lte.pathCost(), sat.pathCost(), if (chosen.? == 1) "lte" else "sat",
    });
    if (chosen.? != 1) @panic("with equal loss the lower-RTT path must be chosen");
}
