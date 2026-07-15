// SPDX-License-Identifier: MIT

//! protocol — the `netsim.Protocol` consumer(s).
//!
//!  - `DfElect` is the real thing: link-state Hello flood (liveness) + BUM
//!    flood, calling `election.decide` (the Fable stub) to gate both DF
//!    status and per-frame split-horizon forwarding. Its property/shrink
//!    tests are gated behind `gate.fable_core_implemented` — see that file.
//!  - `BrokenAlwaysDf` is the POSITIVE CONTROL: a deliberately-wrong
//!    "everyone is DF, no split-horizon" forwarder that does NOT call
//!    `election.decide` at all, so it runs today. Its job is to prove
//!    `checks.DeliveryChecker` has teeth — it reuses that EXACT type, so a
//!    violation it trips is provably the same check the real protocol will
//!    be held to.
//!
//! Both protocols share one topology (`scenario`): a 3-node core triangle
//! plus two independent edge segments, each dual-homed to two DIFFERENT core
//! nodes, so a core-internal partition can genuinely separate a segment's own
//! two edge nodes from EACH OTHER (the actual failure mode DF-election has to
//! survive) without necessarily isolating either one from the rest of the
//! fabric.
//!
//! ```text
//!        core0 ─── core1 ─── core2
//!         │          │  ╲       │
//!        edgeA0   edgeA1 edgeB0 edgeB1     (segment A = {edgeA0,edgeA1},
//!        (id 3)   (id 4) (id 5) (id 6)      segment B = {edgeB0,edgeB1})
//! ```
//! core0─core2 also links directly (triangle), so the core alone survives a
//! single-link cut; only a partition that separates the segment's own two
//! edge nodes onto opposite sides of the cut exercises the hard case.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");
const checks = @import("checks.zig");
const election = @import("election.zig");
const gate = @import("gate.zig");

const Allocator = std.mem.Allocator;
const NodeId = netsim.NodeId;
const Time = netsim.Time;
const Sim = netsim.Sim;
const Protocol = netsim.Protocol;
const LinkConfig = netsim.LinkConfig;

const SegmentId = types.SegmentId;
const EdgeSegment = types.EdgeSegment;
const ElectConfig = types.ElectConfig;

// ── shared topology ──────────────────────────────────────────────────────

pub const NODE_N = 7;
pub const CORE0: NodeId = 0;
pub const CORE1: NodeId = 1;
pub const CORE2: NodeId = 2;
pub const NETWORK_ORIGIN: NodeId = CORE0;

pub const SEG_A = EdgeSegment{ .id = 1, .nodes = .{ 3, 4 }, .priority = .{ 10, 20 } };
pub const SEG_B = EdgeSegment{ .id = 2, .nodes = .{ 5, 6 }, .priority = .{ 15, 5 } };
pub const segments = [_]EdgeSegment{ SEG_A, SEG_B };

pub fn scenario(sim: *Sim) anyerror!void {
    var i: usize = 0;
    while (i < NODE_N) : (i += 1) _ = try sim.addNode(.{});
    const core_cfg = LinkConfig{ .latency = 5, .jitter = 2 };
    try sim.addBiLink(CORE0, CORE1, core_cfg);
    try sim.addBiLink(CORE1, CORE2, core_cfg);
    try sim.addBiLink(CORE0, CORE2, core_cfg);
    const edge_cfg = LinkConfig{ .latency = 3, .jitter = 1 };
    try sim.addBiLink(CORE0, SEG_A.nodes[0], edge_cfg); // edgeA0 → core0
    try sim.addBiLink(CORE1, SEG_A.nodes[1], edge_cfg); // edgeA1 → core1
    try sim.addBiLink(CORE1, SEG_B.nodes[0], edge_cfg); // edgeB0 → core1
    try sim.addBiLink(CORE2, SEG_B.nodes[1], edge_cfg); // edgeB1 → core2
}

fn segmentOfNode(node: NodeId) ?SegmentId {
    for (segments) |s| {
        if (s.indexOf(node) != null) return s.id;
    }
    return null;
}

fn segmentById(id: SegmentId) ?EdgeSegment {
    for (segments) |s| {
        if (s.id == id) return s;
    }
    return null;
}

// ── DfElect: the real protocol (calls the Fable stub) ───────────────────

const HELLO_TIMER: u64 = 0;
const BUM_CE_TIMER: u64 = 1;
const BUM_NET_TIMER: u64 = 2;

/// `bum_seen`/`hello_last_seq` dedup a flooded message per (node, origin)
/// with a bitmask / monotonic counter respectively — see their field docs.
/// Both assume a bounded per-origin sequence count for the run, checked by
/// `originateBum`'s assert.
pub const DfElect = struct {
    gpa: Allocator,
    node_count: usize,
    cfg: ElectConfig,

    /// hello_last_seq[node*node_count + origin] = highest Hello `seq` `node`
    /// has already accepted-and-forwarded from `origin` (monotonic-supersede
    /// flooding — see `types.Hello`'s doc). 0 = "never seen"; real sequence
    /// numbers start at 1 (see `originateHello`).
    hello_last_seq: []u32,
    /// bum_seen[node*node_count + origin], bit `seq` = "`node` has already
    /// processed BUM frame `seq` from `origin`". A bitmask (not a monotonic
    /// counter, since BUM frames are NOT supersede-flooded — every distinct
    /// frame must reach every node) — this bounds each origin to fewer than
    /// 64 originations over a run's lifetime, enforced by `originateBum`'s
    /// assert; a real deployment would use a bounded window / hash set
    /// instead, but a sim harness's known, small `until` makes the bitmask
    /// both correct and allocation-free.
    bum_seen: []u64,
    /// seg_of[node] = the one segment `node` is a member of, or `null`.
    seg_of: []?SegmentId,
    /// is_df[node] = node's own CACHED last election verdict for its segment
    /// (meaningless if `seg_of[node] == null`). Refreshed on every Hello that
    /// changes the peer-liveness view and on every Hello-timer tick
    /// (staleness reassessment needs to happen even with no NEW Hello, since
    /// a silent peer sends nothing to trigger a recompute).
    is_df: []bool,
    /// peer_last_seen[node] = sim time `node` last saw a fresh Hello from its
    /// OWN segment's peer (0 = never). Only meaningful for segment members.
    peer_last_seen: []Time,
    hello_seq: []u32,
    bum_seq: []u32,

    delivery: checks.DeliveryChecker = .{},
    transitions: std.ArrayList(checks.DfTransition) = .empty,

    pub fn init(gpa: Allocator, node_count: usize, cfg: ElectConfig) Allocator.Error!DfElect {
        const hello_last_seq = try gpa.alloc(u32, node_count * node_count);
        @memset(hello_last_seq, 0);
        const bum_seen = try gpa.alloc(u64, node_count * node_count);
        @memset(bum_seen, 0);
        const seg_of = try gpa.alloc(?SegmentId, node_count);
        for (seg_of, 0..) |*s, n| s.* = segmentOfNode(@intCast(n));
        const is_df = try gpa.alloc(bool, node_count);
        @memset(is_df, false);
        const peer_last_seen = try gpa.alloc(Time, node_count);
        @memset(peer_last_seen, 0);
        const hello_seq = try gpa.alloc(u32, node_count);
        @memset(hello_seq, 0);
        const bum_seq = try gpa.alloc(u32, node_count);
        @memset(bum_seq, 0);
        return .{
            .gpa = gpa,
            .node_count = node_count,
            .cfg = cfg,
            .hello_last_seq = hello_last_seq,
            .bum_seen = bum_seen,
            .seg_of = seg_of,
            .is_df = is_df,
            .peer_last_seen = peer_last_seen,
            .hello_seq = hello_seq,
            .bum_seq = bum_seq,
        };
    }

    pub fn deinit(self: *DfElect, gpa: Allocator) void {
        gpa.free(self.hello_last_seq);
        gpa.free(self.bum_seen);
        gpa.free(self.seg_of);
        gpa.free(self.is_df);
        gpa.free(self.peer_last_seen);
        gpa.free(self.hello_seq);
        gpa.free(self.bum_seq);
        self.delivery.deinit(gpa);
        self.transitions.deinit(gpa);
        self.* = undefined;
    }

    pub fn protocol(self: *DfElect) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *DfElect {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        @memset(self.hello_last_seq, 0);
        @memset(self.bum_seen, 0);
        @memset(self.is_df, false);
        @memset(self.peer_last_seen, 0);
        @memset(self.hello_seq, 0);
        @memset(self.bum_seq, 0);
        self.delivery.reset();
        self.transitions.clearRetainingCapacity();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        if (self.seg_of[node]) |seg_id| {
            try sim.setTimer(node, self.cfg.hello_period, HELLO_TIMER);
            const seg = segmentById(seg_id).?;
            if (seg.nodes[0] == node) { // exactly one member originates CE-side test traffic
                try sim.setTimer(node, self.cfg.bum_period, BUM_CE_TIMER);
            }
        }
        if (node == NETWORK_ORIGIN) {
            try sim.setTimer(node, self.cfg.bum_period, BUM_NET_TIMER);
        }
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        switch (timer_id) {
            HELLO_TIMER => {
                if (self.seg_of[node]) |seg_id| {
                    const seg = segmentById(seg_id).?;
                    try self.originateHello(sim, node, seg);
                    try self.refreshDf(sim, node, seg); // staleness reassessment, even absent a new Hello
                    try sim.setTimer(node, self.cfg.hello_period, HELLO_TIMER);
                }
            },
            BUM_CE_TIMER => {
                if (self.seg_of[node]) |seg_id| {
                    try self.originateBum(sim, node, seg_id);
                    try sim.setTimer(node, self.cfg.bum_period, BUM_CE_TIMER);
                }
            },
            BUM_NET_TIMER => {
                try self.originateBum(sim, node, types.no_ingress);
                try sim.setTimer(node, self.cfg.bum_period, BUM_NET_TIMER);
            },
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        switch (types.tagOf(payload)) {
            .hello => try self.handleHello(sim, node, from, payload),
            .bum => try self.handleBum(sim, node, from, payload),
        }
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        try self.delivery.check();
    }

    fn floodFrom(self: *DfElect, sim: *Sim, node: NodeId, payload: []const u8, exclude: ?NodeId) anyerror!void {
        _ = self;
        var nb: [16]NodeId = undefined;
        const n = sim.neighbors(node, &nb);
        for (nb[0..n]) |peer| {
            if (exclude) |ex| {
                if (peer == ex) continue;
            }
            try sim.send(node, peer, payload);
        }
    }

    fn originateHello(self: *DfElect, sim: *Sim, node: NodeId, seg: EdgeSegment) anyerror!void {
        self.hello_seq[node] += 1;
        var buf: [types.Hello.wire_len]u8 = undefined;
        (types.Hello{ .origin = node, .seq = self.hello_seq[node], .segment = seg.id }).encode(&buf);
        self.hello_last_seq[node * self.node_count + node] = self.hello_seq[node];
        try self.floodFrom(sim, node, &buf, null);
    }

    fn originateBum(self: *DfElect, sim: *Sim, node: NodeId, ingress_segment: SegmentId) anyerror!void {
        self.bum_seq[node] += 1;
        std.debug.assert(self.bum_seq[node] < 64); // see `bum_seen`'s doc
        var buf: [types.BumFrame.wire_len]u8 = undefined;
        (types.BumFrame{ .origin = node, .seq = self.bum_seq[node], .ingress_segment = ingress_segment }).encode(&buf);
        self.bum_seen[node * self.node_count + node] |= @as(u64, 1) << @intCast(self.bum_seq[node]);
        try self.floodFrom(sim, node, &buf, null);
    }

    fn handleHello(self: *DfElect, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const h = types.Hello.decode(payload);
        const idx = node * self.node_count + h.origin;
        if (h.seq <= self.hello_last_seq[idx]) return; // stale or duplicate — supersede semantics
        self.hello_last_seq[idx] = h.seq;

        if (self.seg_of[node]) |seg_id| {
            const seg = segmentById(seg_id).?;
            if (h.origin == seg.otherOf(node)) {
                self.peer_last_seen[node] = sim.timeNow();
                try self.refreshDf(sim, node, seg);
            }
        }
        try self.floodFrom(sim, node, payload, from);
    }

    fn handleBum(self: *DfElect, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const f = types.BumFrame.decode(payload);
        const idx = node * self.node_count + f.origin;
        const bit = @as(u64, 1) << @intCast(f.seq);
        if (self.bum_seen[idx] & bit != 0) return; // already processed this exact frame
        self.bum_seen[idx] |= bit;

        if (self.seg_of[node]) |seg_id| {
            const seg = segmentById(seg_id).?;
            const view = self.viewFor(sim, node, seg);
            const d = election.decide(view, f.ingress_segment, seg.id);
            self.setDf(sim, seg, node, d.is_df);
            // Defense in depth: gate on BOTH flags even though a correct
            // `decide` should never disagree with itself between them.
            if (d.is_df and d.allow_forward) {
                try self.delivery.recordDelivery(self.gpa, seg.id, f.id(), f.ingress_segment);
            }
        }
        try self.floodFrom(sim, node, payload, from);
    }

    fn viewFor(self: *DfElect, sim: *Sim, node: NodeId, seg: EdgeSegment) election.SegmentView {
        const peer = seg.otherOf(node);
        const alive = self.peer_last_seen[node] != 0 and
            (sim.timeNow() - self.peer_last_seen[node]) <= self.cfg.stale_after;
        return .{
            .self_id = node,
            .self_priority = seg.priorityOf(node).?,
            .peer_id = peer,
            .peer_priority = seg.priorityOf(peer).?,
            .peer_alive = alive,
        };
    }

    fn refreshDf(self: *DfElect, sim: *Sim, node: NodeId, seg: EdgeSegment) anyerror!void {
        const view = self.viewFor(sim, node, seg);
        const d = election.decide(view, null, seg.id);
        self.setDf(sim, seg, node, d.is_df);
    }

    fn setDf(self: *DfElect, sim: *Sim, seg: EdgeSegment, node: NodeId, is_df: bool) void {
        if (self.is_df[node] == is_df) return;
        self.is_df[node] = is_df;
        self.transitions.append(self.gpa, .{
            .time = sim.timeNow(),
            .segment = seg.id,
            .node = node,
            .is_df = is_df,
        }) catch {}; // best-effort log, mirrors netsim's own Log.append
    }
};

// ── BrokenAlwaysDf: the positive control ────────────────────────────────

/// Deliberately WRONG: every segment member always considers itself DF, and
/// forwards every BUM frame it sees to its segment regardless of where the
/// frame ingressed. Does NOT call `election.decide` — it exists to prove
/// `checks.DeliveryChecker` (the exact same type the real protocol will be
/// held to) actually catches both zero-tolerance invariants:
///   - a network-side frame reaches BOTH members of a segment → the SECOND
///     delivery trips `error.DuplicateDelivery`;
///   - a CE-side frame (tagged with its own segment as ingress) reaches the
///     OTHER member of that same segment → trips `error.SplitHorizonViolation`
///     on the very first delivery attempt.
pub const BrokenAlwaysDf = struct {
    gpa: Allocator,
    node_count: usize,
    cfg: ElectConfig,

    bum_seen: []u64,
    seg_of: []?SegmentId,
    bum_seq: []u32,

    delivery: checks.DeliveryChecker = .{},

    pub fn init(gpa: Allocator, node_count: usize, cfg: ElectConfig) Allocator.Error!BrokenAlwaysDf {
        const bum_seen = try gpa.alloc(u64, node_count * node_count);
        @memset(bum_seen, 0);
        const seg_of = try gpa.alloc(?SegmentId, node_count);
        for (seg_of, 0..) |*s, n| s.* = segmentOfNode(@intCast(n));
        const bum_seq = try gpa.alloc(u32, node_count);
        @memset(bum_seq, 0);
        return .{ .gpa = gpa, .node_count = node_count, .cfg = cfg, .bum_seen = bum_seen, .seg_of = seg_of, .bum_seq = bum_seq };
    }

    pub fn deinit(self: *BrokenAlwaysDf, gpa: Allocator) void {
        gpa.free(self.bum_seen);
        gpa.free(self.seg_of);
        gpa.free(self.bum_seq);
        self.delivery.deinit(gpa);
        self.* = undefined;
    }

    pub fn protocol(self: *BrokenAlwaysDf) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *BrokenAlwaysDf {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        @memset(self.bum_seen, 0);
        @memset(self.bum_seq, 0);
        self.delivery.reset();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        if (self.seg_of[node]) |seg_id| {
            const seg = segmentById(seg_id).?;
            if (seg.nodes[0] == node) try sim.setTimer(node, self.cfg.bum_period, BUM_CE_TIMER);
        }
        if (node == NETWORK_ORIGIN) try sim.setTimer(node, self.cfg.bum_period, BUM_NET_TIMER);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        switch (timer_id) {
            BUM_CE_TIMER => {
                if (self.seg_of[node]) |seg_id| {
                    try self.originateBum(sim, node, seg_id);
                    try sim.setTimer(node, self.cfg.bum_period, BUM_CE_TIMER);
                }
            },
            BUM_NET_TIMER => {
                try self.originateBum(sim, node, types.no_ingress);
                try sim.setTimer(node, self.cfg.bum_period, BUM_NET_TIMER);
            },
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        if (types.tagOf(payload) != .bum) return; // this broken protocol never sends Hellos
        const f = types.BumFrame.decode(payload);
        const idx = node * self.node_count + f.origin;
        const bit = @as(u64, 1) << @intCast(f.seq);
        if (self.bum_seen[idx] & bit != 0) return;
        self.bum_seen[idx] |= bit;

        if (self.seg_of[node]) |seg_id| {
            // THE BUG: no election, no split-horizon gate — always forward.
            try self.delivery.recordDelivery(self.gpa, seg_id, f.id(), f.ingress_segment);
        }
        try floodFrom(sim, node, payload, from);
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        try self.delivery.check();
    }

    fn originateBum(self: *BrokenAlwaysDf, sim: *Sim, node: NodeId, ingress_segment: SegmentId) anyerror!void {
        self.bum_seq[node] += 1;
        std.debug.assert(self.bum_seq[node] < 64);
        var buf: [types.BumFrame.wire_len]u8 = undefined;
        (types.BumFrame{ .origin = node, .seq = self.bum_seq[node], .ingress_segment = ingress_segment }).encode(&buf);
        self.bum_seen[node * self.node_count + node] |= @as(u64, 1) << @intCast(self.bum_seq[node]);
        try floodFrom(sim, node, &buf, null);
    }

    fn floodFrom(sim: *Sim, node: NodeId, payload: []const u8, exclude: ?NodeId) anyerror!void {
        var nb: [16]NodeId = undefined;
        const n = sim.neighbors(node, &nb);
        for (nb[0..n]) |peer| {
            if (exclude) |ex| {
                if (peer == ex) continue;
            }
            try sim.send(node, peer, payload);
        }
    }
};

// ── unguarded tests: the positive control proves the harness has teeth ──

const testing = std.testing;

const DEFAULT_CFG = ElectConfig{};
const UNTIL: Time = 1500;

test "positive control: BrokenAlwaysDf trips a zero-tolerance invariant" {
    const gpa = testing.allocator;
    var broken = try BrokenAlwaysDf.init(gpa, NODE_N, DEFAULT_CFG);
    defer broken.deinit(gpa);
    const case = netsim.Case{ .seed = 1, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL };

    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    const err = r.violation.?.err;
    try testing.expect(err == error.DuplicateDelivery or err == error.SplitHorizonViolation);
}

test "teeth: BrokenAlwaysDf trips the checker across a seed sweep, including under partition/heal fuzzing" {
    const gpa = testing.allocator;
    var broken = try BrokenAlwaysDf.init(gpa, NODE_N, DEFAULT_CFG);
    defer broken.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL };

    var caught: usize = 0;
    var seed: u64 = 1;
    while (seed <= 100) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try netsim.run(gpa, case, .{});
        defer gr.trace.deinit();
        if (gr.result.outcome == .violated) caught += 1;
    }
    // A harness/checker that could never provoke the always-broken forwarder
    // would report 0 — that would mean the invariant check itself is dead.
    try testing.expect(caught > 0);
}

test "shrink: a fuzzed failing schedule against BrokenAlwaysDf minimizes to a still-reproducing core" {
    const gpa = testing.allocator;
    var broken = try BrokenAlwaysDf.init(gpa, NODE_N, DEFAULT_CFG);
    defer broken.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL };

    var failing = (try netsim.findFailing(gpa, template, .{}, 1, 200)) orelse return error.NoFailingSeed;
    defer failing.deinit();

    var res = try netsim.shrinkTrace(gpa, &failing);
    defer res.deinit();
    try testing.expect(res.after >= 1);
    try testing.expect(res.after <= res.before);

    const r = try netsim.replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(failing.err, r.violation.?.err);
}

test "smoke: scenario topology matches the declared segment membership" {
    const gpa = testing.allocator;
    var b = try BrokenAlwaysDf.init(gpa, NODE_N, DEFAULT_CFG);
    defer b.deinit(gpa);
    const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = scenario, .protocol = b.protocol(), .until = UNTIL });
    defer gpa.free(topo.links);
    try testing.expectEqual(@as(usize, NODE_N), topo.node_count);
    try testing.expectEqual(@as(?SegmentId, SEG_A.id), segmentOfNode(SEG_A.nodes[0]));
    try testing.expectEqual(@as(?SegmentId, SEG_A.id), segmentOfNode(SEG_A.nodes[1]));
    try testing.expectEqual(@as(?SegmentId, SEG_B.id), segmentOfNode(SEG_B.nodes[0]));
    try testing.expectEqual(@as(?SegmentId, null), segmentOfNode(CORE0));
}

// ── gated tests: the real DfElect, behind the Fable stub ────────────────
//
// See `gate.zig`. These call `election.decide` transitively (any Hello or
// BUM processing at a segment member does) and so PANIC — crashing the
// whole test binary, per Zig's test runner (a `@panic` aborts the process,
// it is not a catchable per-test failure) — the moment `decide` is no
// longer a stub-only no-op. `error.SkipZigTest` keeps `zig build
// test-df-elect` green today while documenting exactly what will start
// running once `gate.fable_core_implemented` flips to `true`.

test "real: DfElect never trips a zero-tolerance invariant, across a seed sweep with partition/heal fuzzing" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };

    const failing = try netsim.findFailing(gpa, template, .{}, 1, 300);
    if (failing) |*f| {
        var mf = f.*;
        defer mf.deinit();
        std.debug.print("df-elect: real election tripped {} at seed {}\n", .{ mf.err, mf.case.seed });
        return error.HardInvariantViolated;
    }
}

test "real: bounded-badness — the worst observed DF-count window stays within the declared bound" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
    const bound = checks.maxBadDfWindow(DEFAULT_CFG);

    var seed: u64 = 1;
    while (seed <= 100) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try netsim.run(gpa, case, .{});
        defer gr.trace.deinit();
        try testing.expectEqual(netsim.RunOutcome.ok, gr.result.outcome);

        const worst = try checks.worstBadDfWindow(gpa, df.transitions.items, &segments, case.until);
        if (worst > bound) {
            std.debug.print("df-elect: seed {} worst DF window {} exceeds bound {}\n", .{ seed, worst, bound });
        }
        try testing.expect(worst <= bound);
    }
}
