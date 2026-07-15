// SPDX-License-Identifier: MIT
//! Trace-corpus generators: netsim topologies + fault schedules that drive a
//! `root.Estimator` through representative link behaviors (clean, hard failure,
//! flapping, continuously degraded). `Prober` is the netsim `Protocol` that wires
//! an Estimator to netsim's clock — it owns ALL the request/reply/timeout
//! bookkeeping (probe correlation, one-in-flight serialization) so `scoring.zig`
//! only has to read back `transitions`.
//!
//! Topology convention used throughout this module: node 0 is the prober (holds
//! the Estimator under test), node 1 is a trivial echo responder. Both scenario
//! functions below build exactly that 2-node topology, differing only in the
//! link's CONTINUOUS fault profile (`netsim.LinkConfig`); anything that changes
//! OVER TIME (hard failure, flapping) is layered on top via an explicit
//! `netsim.FaultEvent` trace fed to `netsim.replay`, not baked into the scenario
//! (scenarios are plain function pointers with no closure state — see
//! `netsim.Scenario`).

const std = @import("std");
const netsim = @import("netsim");
const root = @import("root.zig");
const Estimator = root.Estimator;
const Config = root.Config;
const LinkState = root.LinkState;
const Time = root.Time;

const PROBER: netsim.NodeId = 0;
const RESPONDER: netsim.NodeId = 1;

/// Clean bidirectional link: modest fixed latency + small jitter, no loss. Used
/// as the topology for the clean-link, hard-failure, and flapping corpora (their
/// differentiation is entirely in the fault trace layered on top).
pub fn cleanScenario(sim: *netsim.Sim) anyerror!void {
    _ = try sim.addNode(.{});
    _ = try sim.addNode(.{});
    try sim.addBiLink(PROBER, RESPONDER, .{ .latency = 20, .jitter = 5 });
}

/// Continuously degraded-but-usable link: the same topology, but with 30%
/// per-message loss and heavier jitter baked into the link itself — the link
/// never goes fully down, it is just lossy and jittery for the entire run.
pub fn degradedScenario(sim: *netsim.Sim) anyerror!void {
    _ = try sim.addNode(.{});
    _ = try sim.addNode(.{});
    try sim.addBiLink(PROBER, RESPONDER, .{ .latency = 20, .jitter = 15, .loss_permille = 300 });
}

/// A single, permanent, hard failure at `fail_at`: both directions of the
/// prober<->responder link go down and never recover — the "cleanly-failing
/// link" corpus case.
pub fn hardFailureTrace(fail_at: Time) [2]netsim.FaultEvent {
    return .{
        .{ .time = fail_at, .kind = .{ .link_down = .{ .a = PROBER, .b = RESPONDER } } },
        .{ .time = fail_at, .kind = .{ .link_down = .{ .a = RESPONDER, .b = PROBER } } },
    };
}

/// A deterministic alternating up/down duty-cycle trace (both directions),
/// starting "up" (matching the scenario's default `up = true` link state): up
/// for `up_ticks`, down for `down_ticks`, repeating until `horizon`. This is the
/// "flapping link at various duty cycles" corpus generator — callers pick
/// `up_ticks` / `down_ticks` to hit any target downtime fraction (e.g.
/// `down_ticks = 3 * period / 10` for a ~30%-down duty cycle).
pub fn dutyCycleTrace(
    gpa: std.mem.Allocator,
    up_ticks: Time,
    down_ticks: Time,
    horizon: Time,
) std.mem.Allocator.Error![]netsim.FaultEvent {
    var list: std.ArrayList(netsim.FaultEvent) = .empty;
    errdefer list.deinit(gpa);
    var t: Time = up_ticks;
    while (t < horizon) {
        try list.append(gpa, .{ .time = t, .kind = .{ .link_down = .{ .a = PROBER, .b = RESPONDER } } });
        try list.append(gpa, .{ .time = t, .kind = .{ .link_down = .{ .a = RESPONDER, .b = PROBER } } });
        t += down_ticks;
        if (t >= horizon) break;
        try list.append(gpa, .{ .time = t, .kind = .{ .link_up = .{ .a = PROBER, .b = RESPONDER } } });
        try list.append(gpa, .{ .time = t, .kind = .{ .link_up = .{ .a = RESPONDER, .b = PROBER } } });
        t += up_ticks;
    }
    return list.toOwnedSlice(gpa);
}

/// One recorded state transition (the scoring harness's raw material).
pub const Transition = struct {
    at: Time,
    state: LinkState,
};

/// Sentinel timer id for "send the next probe" (distinct from any real probe id,
/// which is a u32 — see `sendProbe`).
const NEXT_PROBE_TIMER: u64 = std.math.maxInt(u64);

/// The netsim `Protocol` that drives one `Estimator` against the simulated
/// clock: strictly one probe in flight at a time (send -> await reply or timeout
/// deadline, whichever comes first -> after `probe_gap` -> repeat), feeding every
/// outcome to the Estimator and recording every state transition it produces.
/// Runs on node `PROBER`; any other node in the topology is treated as a trivial
/// echo responder (see `onMessage`) so the same `Protocol` value covers both
/// roles, matching netsim's single-ctx convention (see netsim's own
/// `Flood` / `LoopyForward` examples).
pub const Prober = struct {
    gpa: std.mem.Allocator,
    est: Estimator,
    responder: netsim.NodeId,
    /// Time to wait after a probe is RESOLVED (reply or timeout) before sending
    /// the next one. 0 = back-to-back probing.
    probe_gap: Time,
    /// Deadline for a reply before a probe counts as a timeout.
    probe_timeout: Time,
    next_probe_id: u32 = 0,
    awaiting: ?struct { id: u32, sent_at: Time } = null,
    last_state: LinkState = .up,
    transitions: std.ArrayList(Transition) = .empty,

    pub fn init(gpa: std.mem.Allocator, cfg: Config, responder: netsim.NodeId, probe_gap: Time, probe_timeout: Time) Prober {
        return .{
            .gpa = gpa,
            .est = Estimator.init(cfg),
            .responder = responder,
            .probe_gap = probe_gap,
            .probe_timeout = probe_timeout,
        };
    }

    pub fn deinit(self: *Prober) void {
        self.transitions.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn protocol(self: *Prober) netsim.Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *Prober {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        self.est = Estimator.init(self.est.cfg);
        self.next_probe_id = 0;
        self.awaiting = null;
        self.last_state = .up;
        self.transitions.clearRetainingCapacity();
    }

    fn recordIfChanged(self: *Prober, sim: *netsim.Sim) void {
        const st = self.est.state();
        if (st != self.last_state) {
            self.last_state = st;
            self.transitions.append(self.gpa, .{ .at = sim.timeNow(), .state = st }) catch {};
        }
    }

    fn sendProbe(self: *Prober, sim: *netsim.Sim) anyerror!void {
        const id = self.next_probe_id;
        self.next_probe_id +%= 1;
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, id, .little);
        self.awaiting = .{ .id = id, .sent_at = sim.timeNow() };
        try sim.send(PROBER, self.responder, &buf);
        try sim.setTimer(PROBER, self.probe_timeout, id);
    }

    fn armNext(self: *Prober, sim: *netsim.Sim) anyerror!void {
        if (self.probe_gap == 0) {
            try self.sendProbe(sim);
        } else {
            try sim.setTimer(PROBER, self.probe_gap, NEXT_PROBE_TIMER);
        }
    }

    fn onStart(ctx: *anyopaque, sim: *netsim.Sim, node: netsim.NodeId) anyerror!void {
        const self = cast(ctx);
        if (node != PROBER) return;
        try self.sendProbe(sim);
    }

    fn onTimer(ctx: *anyopaque, sim: *netsim.Sim, node: netsim.NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        _ = node;
        if (timer_id == NEXT_PROBE_TIMER) {
            try self.sendProbe(sim);
            return;
        }
        // A probe-deadline timer: only genuine if `timer_id` matches the STILL-
        // outstanding probe (an earlier reply may have already resolved it and
        // moved on — netsim has no timer-cancel API, so a stale deadline is
        // simply a no-op here).
        if (self.awaiting) |aw| {
            if (@as(u64, aw.id) == timer_id) {
                self.awaiting = null;
                self.est.onProbeTimeout(sim.timeNow());
                self.recordIfChanged(sim);
                try self.armNext(sim);
            }
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *netsim.Sim, node: netsim.NodeId, from: netsim.NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        if (node != PROBER) {
            // Echo-responder role: bounce the probe straight back.
            try sim.send(node, from, payload);
            return;
        }
        if (payload.len < 4) return;
        const id = std.mem.readInt(u32, payload[0..4], .little);
        if (self.awaiting) |aw| {
            if (aw.id == id) {
                const rtt = sim.timeNow() - aw.sent_at;
                self.awaiting = null;
                self.est.onProbeReply(sim.timeNow(), rtt);
                self.recordIfChanged(sim);
                try self.armNext(sim);
            }
            // else: a stale reply for an already-timed-out probe — ignore.
        }
    }
};

const testing = std.testing;

test "trace: dutyCycleTrace produces a well-formed alternating schedule" {
    const gpa = testing.allocator;
    const events = try dutyCycleTrace(gpa, 100, 50, 500);
    defer gpa.free(events);
    try testing.expect(events.len > 0);
    var prev: Time = 0;
    for (events) |e| {
        try testing.expect(e.time >= prev);
        prev = e.time;
        try testing.expect(e.time < 500);
    }
    // First event must be a down (link starts up per scenario default).
    try testing.expectEqual(std.meta.activeTag(events[0].kind), .link_down);
}

test "trace: hardFailureTrace severs both directions at the same instant" {
    const events = hardFailureTrace(42);
    try testing.expectEqual(@as(Time, 42), events[0].time);
    try testing.expectEqual(@as(Time, 42), events[1].time);
    try testing.expectEqual(std.meta.activeTag(events[0].kind), .link_down);
    try testing.expectEqual(std.meta.activeTag(events[1].kind), .link_down);
}
