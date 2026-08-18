// SPDX-License-Identifier: MIT
//! `Fabric` — the `netsim.Protocol` consumer under test: a small fixed ring
//! of nodes forwarding "frames" toward one destination through a per-node
//! FIB (`next_hop`), with FIB updates driven by topology changes and applied
//! in an order chosen by `fib.zig` (either the Fable core or the
//! `naiveBadOrder` positive control).
//!
//! ── Topology ─────────────────────────────────────────────────────────────
//! A 4-node ring `0 - 1 - 2 - 3 - 0` (see `edges` below), destination = node
//! 0, "customer" origin = node 1 (periodically sends a frame toward 0). The
//! asymmetric weight on edge `3-0` (10, vs. 1 everywhere else) is chosen so
//! that severing `1-0` forces a specific, hand-verified next-hop swap
//! (node 1: 0→2, node 2: 1→3) — see the "positive control" test in
//! `root.zig` for the full derivation of why that swap, applied in the wrong
//! order, is guaranteed to bounce a frame between nodes 1 and 2.
//!
//! ── Topology-change visibility (a deliberate scaffold simplification) ───
//! `netsim.Protocol` has no fault-observation hook (see the netsim module
//! doc): a link going up/down is only ever visible to a real IGP indirectly,
//! through hello/keepalive timeouts. Modeling that fully (flooded LSAs,
//! hold-timers) is out of scope for this scaffold and orthogonal to the
//! ordering problem it exists to test. Instead: `harness.zig` pre-generates
//! the fault schedule (via `netsim.generateFaultTrace`, so it's still
//! genuinely netsim's seeded fault fuzzer) and hands it to `Fabric` via
//! `setSchedule` BEFORE the run; node 0 (the conductor — chosen because it's
//! already special as the destination) schedules one `netsim.Sim.setTimer`
//! per `link_down`/`link_up` event in `onStart`, so every node's control
//! plane learns about a topology change at EXACTLY the tick it happens —
//! i.e. this models an instantaneous, always-consistent global LSA flood.
//! What is NOT simplified: the DATA plane. `link_down`/`link_up` are real
//! `netsim.FaultKind`s injected into the actual `Sim`, so message delivery
//! genuinely gets severed/restored by the engine, independent of anything
//! `Fabric` does — and the individual per-node FIB updates dictated by the
//! chosen ordering are applied at genuinely different simulated times
//! (`step_gap` ticks apart), which is what makes the transient-inconsistency
//! window — and therefore the loop-freedom property under test — real.
//!
//! ── Conductor / transition serialization ─────────────────────────────────
//! `computeUpdateOrder`'s loop-freedom proof holds for ONE transition applied
//! from a FIB that starts exactly at `old_tree.pred`. When a second topology
//! change arrives before the first's ordered convergence has finished (e.g.
//! seed 464's `link_down 0-1` immediately followed by `link_up 0-1`), a naive
//! conductor would schedule the second transition's updates overlapping the
//! first's still-pending ones — a stale queued update lands AFTER the second
//! transition's updates and leaves the FIB in a mixed state neither
//! transition's proof covers: a persistent loop. Real ordered-FIB
//! deployments (RFC 6976 / Francois–Bonaventure) complete or abort an
//! in-progress ordered convergence before starting the next; this conductor
//! models "complete first" by SERIALIZING: each transition's ordered window
//! starts no earlier than `last_apply_time + step_gap` (see
//! `applyTopologyChange`). Because `self.up` advances monotonically and every
//! `old_tree`/`new_tree` is a full SPF over it, a transition's `old_tree` is
//! exactly the FIB the previous transition's serialized window converges to —
//! so concatenating complete, individually prefix-safe transitions stays
//! loop-free no matter how tightly the topology events bunch up.
//!
//! ── Loop invariant (the teeth) ───────────────────────────────────────────
//! Every frame carries a `frame_id`; `Fabric` tracks, per in-flight frame,
//! the SET of nodes it has already been forwarded from and the single node
//! it was MOST RECENTLY at. A node forwarding the very same frame it is
//! already sitting at (an immediate re-delivery — what a `dup_once` fault
//! produces) is absorbed as a harmless duplicate, not a loop. A node
//! receiving a frame it visited EARLIER, after the frame has since moved on
//! to a DIFFERENT node, is a genuine forwarding loop: `checkFn` raises
//! `error.ForwardingLoop`.

const std = @import("std");
const netsim = @import("netsim");
const spf = @import("spf-ect");
const fib = @import("fib.zig");
const Allocator = std.mem.Allocator;
const NodeId = netsim.NodeId;

/// Which FIB-update-ordering strategy the conductor uses on every topology
/// change. `naive_bad` is the deliberately-wrong baseline (applies FIB
/// updates in an unordered/racy sequence); `ordered_fable` drives the real,
/// implemented `fib.computeUpdateOrder` kernel under test (see `fib.zig`).
pub const Mode = enum { naive_bad, ordered_fable };

pub const NODE_COUNT: usize = 4;
const EDGE_COUNT: usize = 4;
const MAX_FRAMES: usize = 512;
const MAX_PENDING: usize = 256;

const ORIGIN_TIMER: u64 = 0;
const CONDUCTOR_BASE: u64 = 1_000_000;
const FIB_APPLY_BASE: u64 = 2_000_000;

const EdgeDef = struct { a: NodeId, b: NodeId, weight: spf.Weight };

/// The fixed ring topology (see the module doc for why the `3-0` weight is
/// 10, not 1). `scenario` (below) builds the IDENTICAL topology in netsim —
/// keep the two in sync by hand if either ever changes.
const edges = [EDGE_COUNT]EdgeDef{
    .{ .a = 0, .b = 1, .weight = 1 },
    .{ .a = 1, .b = 2, .weight = 1 },
    .{ .a = 2, .b = 3, .weight = 1 },
    .{ .a = 3, .b = 0, .weight = 10 },
};

/// Build the same 4-node ring in netsim's own topology model. Passed
/// directly as a `netsim.Case.scenario`.
pub fn scenario(sim: *netsim.Sim) anyerror!void {
    var i: usize = 0;
    while (i < NODE_COUNT) : (i += 1) _ = try sim.addNode(.{});
    const cfg = netsim.LinkConfig{ .latency = 5 }; // uniform, no jitter: fully deterministic timing
    for (edges) |e| try sim.addBiLink(e.a, e.b, cfg);
}

const PendingUpdate = struct { node: NodeId, next_hop: ?NodeId };

pub const Fabric = struct {
    gpa: Allocator,
    mode: Mode,
    dest: NodeId = 0,
    origin: NodeId = 1,
    origin_period: netsim.Time = 20,
    /// Ticks between successively-applied FIB updates within one topology
    /// change's ordering — what turns "an ordering" into a REAL transient
    /// window a frame can be caught in.
    step_gap: netsim.Time = 50,

    /// The pre-generated schedule this run will be replayed against (see
    /// the module doc's "Topology-change visibility" section). Borrowed —
    /// must outlive the `netsim.replay`/`run` call it's set before.
    schedule: []const netsim.FaultEvent = &.{},

    /// Per-undirected-edge up/down state (control-plane view; index matches
    /// `edges`). `spf.Graph` is undirected-only, so a `link_down`/`link_up`
    /// fault on EITHER direction of a ring edge takes the whole edge down/up
    /// in this model — see the module doc.
    up: [EDGE_COUNT]bool = [_]bool{true} ** EDGE_COUNT,
    /// Currently-APPLIED next-hop per node toward `dest` (`null` = no route,
    /// drop). This is the live FIB the data plane forwards against.
    next_hop: [NODE_COUNT]?NodeId = [_]?NodeId{null} ** NODE_COUNT,

    /// Per-frame-slot bookkeeping (`frame_id % MAX_FRAMES`, reclaimed by a
    /// fresh `frame_id` claiming the slot). `slot_visited` is a per-node
    /// bitmask (NODE_COUNT <= 8, fits `u8`); `slot_last` is the most
    /// recently visited node, encoded `node + 1` (0 = none).
    slot_owner: [MAX_FRAMES]u32 = [_]u32{std.math.maxInt(u32)} ** MAX_FRAMES,
    slot_visited: [MAX_FRAMES]u8 = [_]u8{0} ** MAX_FRAMES,
    slot_last: [MAX_FRAMES]u8 = [_]u8{0} ** MAX_FRAMES,
    next_frame_id: u32 = 0,
    /// Count of frame ids that have terminated (delivered, dropped, or
    /// loop-violated — see `deliverAt`'s three terminal branches), i.e. can
    /// never again be the target of a hop. `next_frame_id - retired_frame_id`
    /// is therefore the number of frame ids genuinely still in flight; used
    /// only to bound-check a fresh claim against `MAX_FRAMES` (audit F2) —
    /// this module does not otherwise need frame lifecycle tracking.
    retired_frame_id: u32 = 0,

    /// FIFO of FIB updates scheduled but not yet applied, keyed by a
    /// globally-increasing id (`% MAX_PENDING` for storage) so overlapping
    /// topology changes never alias each other's pending updates.
    pending: [MAX_PENDING]PendingUpdate = undefined,
    next_pending_id: u64 = 0,
    /// Count of pending ids actually applied so far (`onTimer`'s
    /// `FIB_APPLY_BASE` arm). `next_pending_id - applied_pending_id` is the
    /// number of scheduled-but-not-yet-applied updates; used only to
    /// bound-check a fresh claim against `MAX_PENDING` (audit F2).
    applied_pending_id: u64 = 0,

    /// Absolute sim time at which the LAST-scheduled pending FIB update will
    /// apply — the conductor's transition-serialization watermark. A new
    /// topology change starts its ordered update window no earlier than
    /// `last_apply_time + step_gap`, so a superseded transition's ordered
    /// convergence always COMPLETES before the next one begins (RFC 6976 /
    /// Francois–Bonaventure "complete or abort the in-progress ordered
    /// convergence first"). Without this, a stale queued update from an
    /// interrupted transition can land after the next transition's updates,
    /// leaving the FIB in a mixed state neither transition's loop-freedom
    /// proof covers — a persistent forwarding loop. See the module doc's
    /// "conductor / transition-serialization" note and `../SPEC.md`.
    last_apply_time: netsim.Time = 0,

    loop_violation: bool = false,
    loop_frame: ?u32 = null,
    loop_node: ?NodeId = null,

    pub fn init(gpa: Allocator, mode: Mode) Fabric {
        return .{ .gpa = gpa, .mode = mode };
    }

    /// See the module doc's "Topology-change visibility" section. Call
    /// before every `netsim.replay`/`run`/`findFailing` this `Fabric` drives
    /// — `harness.zig` does this automatically.
    pub fn setSchedule(self: *Fabric, events: []const netsim.FaultEvent) void {
        self.schedule = events;
    }

    pub fn protocol(self: *Fabric) netsim.Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *Fabric {
        return @ptrCast(@alignCast(ctx));
    }

    fn canonicalEdgeIndex(a: NodeId, b: NodeId) ?usize {
        for (edges, 0..) |e, i| {
            if ((e.a == a and e.b == b) or (e.a == b and e.b == a)) return i;
        }
        return null;
    }

    /// Materialize the CURRENT control-plane topology (only `up` edges) as a
    /// fresh `spf.Graph`. Caller must `deinit` it; safe to do so immediately
    /// after computing a `Tree` from it (`Tree` owns its own `dist`/`pred`).
    fn buildGraph(self: *Fabric) spf.Graph.AddEdgeError!spf.Graph {
        var g = spf.Graph.init(self.gpa);
        errdefer g.deinit();
        try g.ensureNode(NODE_COUNT - 1); // keep isolated nodes in range even if all their edges are down
        for (edges, 0..) |e, i| {
            if (self.up[i]) try g.addEdge(e.a, e.b, e.weight);
        }
        return g;
    }

    fn applyInitialFib(self: *Fabric) anyerror!void {
        var g = try self.buildGraph();
        var tree = try spf.shortestPathTree(self.gpa, &g, self.dest);
        g.deinit();
        defer tree.deinit();
        var n: NodeId = 0;
        while (n < NODE_COUNT) : (n += 1) self.next_hop[n] = tree.pred[n];
    }

    /// Recompute the shortest-path tree before and after toggling one edge,
    /// hand the (old, new) pair to the configured ordering strategy, and
    /// schedule each resulting FIB update `step_gap` ticks apart.
    fn applyTopologyChange(self: *Fabric, sim: *netsim.Sim, ev: netsim.FaultEvent) anyerror!void {
        var link: netsim.Link = undefined;
        var going_up: bool = undefined;
        switch (ev.kind) {
            .link_down => |l| {
                link = l;
                going_up = false;
            },
            .link_up => |l| {
                link = l;
                going_up = true;
            },
            else => return, // not a topology-relevant fault
        }
        const idx = canonicalEdgeIndex(link.a, link.b) orelse return;
        if (self.up[idx] == going_up) return; // redundant event, no-op

        var old_graph = try self.buildGraph();
        var old_tree = try spf.shortestPathTree(self.gpa, &old_graph, self.dest);
        old_graph.deinit();
        defer old_tree.deinit();

        self.up[idx] = going_up;

        var new_graph = try self.buildGraph();
        var new_tree = try spf.shortestPathTree(self.gpa, &new_graph, self.dest);
        new_graph.deinit();
        defer new_tree.deinit();

        const order = switch (self.mode) {
            .naive_bad => try fib.naiveBadOrder(self.gpa, &old_tree, &new_tree),
            .ordered_fable => try fib.computeUpdateOrder(self.gpa, &old_tree, &new_tree),
        };
        defer self.gpa.free(order);

        // Transition serialization (the conductor fix). This transition's
        // ordered window must not start until the PREVIOUS transition's last
        // pending update has landed, or an in-flight (superseded) transition's
        // stale update would apply after ours and break the loop-freedom
        // proof, which assumes the FIB starts exactly at `old_tree.pred`
        // before this order applies. Because `self.up` is updated
        // monotonically and each `old_tree`/`new_tree` is a full SPF over it,
        // this transition's `old_tree` is EXACTLY the FIB state the prior
        // transition's serialized window converges to — so concatenating
        // complete, individually prefix-safe transitions stays loop-free.
        const now = sim.timeNow();
        var base = now;
        if (self.last_apply_time + self.step_gap > base) base = self.last_apply_time + self.step_gap;

        for (order, 0..) |n, k| {
            // Audit F2: `pending` is a fixed ring buffer with no ownership
            // tag (unlike the frame slots below) — a claim past capacity
            // would silently overwrite a still-outstanding update, and
            // `onTimer`'s FIB_APPLY_BASE arm would then apply the WRONG
            // node's next-hop with no way to detect it. Fail loud instead.
            std.debug.assert(self.next_pending_id - self.applied_pending_id < MAX_PENDING);
            // `next_pending_id` is a genuinely-unbounded `u64` sequence
            // number (it never wraps for the run's lifetime and is folded
            // into the netsim timer id below), but `% MAX_PENDING` (a
            // `usize` constant = 256) always yields a value `< 256` no
            // matter how wide the dividend is — the cast can never truncate
            // a value that reaches it, for any `next_pending_id`.
            const slot: usize = @intCast(self.next_pending_id % MAX_PENDING);
            self.pending[slot] = .{ .node = n, .next_hop = new_tree.pred[n] };
            const apply_time: netsim.Time = base + @as(netsim.Time, @intCast(k)) * self.step_gap;
            try sim.setTimer(0, apply_time - now, FIB_APPLY_BASE + self.next_pending_id);
            self.last_apply_time = apply_time; // ascending k → final iteration = max
            self.next_pending_id += 1;
        }
    }

    /// Mark `node` visited by `frame_id` and forward it to the CURRENT
    /// `next_hop[node]` — the single place both message-delivery
    /// (`onMessage`) and origination (`onTimer`'s `ORIGIN_TIMER` arm) route
    /// through, so the invariant bookkeeping only lives in one place.
    fn deliverAt(self: *Fabric, sim: *netsim.Sim, node: NodeId, frame_id: u32) anyerror!void {
        const slot = frame_id % MAX_FRAMES;
        if (self.slot_owner[slot] != frame_id) {
            self.slot_owner[slot] = frame_id;
            self.slot_visited[slot] = 0;
            self.slot_last[slot] = 0;
        }
        const last_plus_one: u8 = @as(u8, @intCast(node)) + 1;
        if (self.slot_last[slot] == last_plus_one) {
            // Immediate re-delivery to the node the frame is ALREADY at
            // (e.g. a dup_once fault duplicating the last hop) — not a new
            // hop, not a loop. Absorb it (idempotent forwarding).
            return;
        }
        const bit: u8 = @as(u8, 1) << @intCast(node);
        if (self.slot_visited[slot] & bit != 0) {
            // `node` was visited before, and this is NOT the immediately
            // prior hop (ruled out above): the frame left `node` and came
            // back — a genuine forwarding loop.
            self.loop_violation = true;
            self.loop_frame = frame_id;
            self.loop_node = node;
            self.retired_frame_id += 1; // terminal: no further hop for this frame_id
            return;
        }
        self.slot_visited[slot] |= bit;
        self.slot_last[slot] = last_plus_one;
        if (node == self.dest) {
            self.retired_frame_id += 1; // terminal: delivered
            return;
        }
        const next = self.next_hop[node] orelse {
            self.retired_frame_id += 1; // terminal: no route, dropped
            return;
        };
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, frame_id, .little);
        try sim.send(node, next, &buf);
    }

    fn onStart(ctxp: *anyopaque, sim: *netsim.Sim, node: NodeId) anyerror!void {
        const self = cast(ctxp);
        if (node == self.origin) try sim.setTimer(node, self.origin_period, ORIGIN_TIMER);
        if (node == 0) {
            // Conductor: schedule one topology-change trigger per
            // link_down/link_up in the pre-generated schedule (see the
            // module doc), and converge the initial (all-up) FIB.
            for (self.schedule, 0..) |ev, i| {
                switch (ev.kind) {
                    .link_down, .link_up => try sim.setTimer(0, ev.time, CONDUCTOR_BASE + i),
                    else => {},
                }
            }
            try self.applyInitialFib();
        }
    }

    fn onMessage(ctxp: *anyopaque, sim: *netsim.Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        _ = from;
        const self = cast(ctxp);
        if (payload.len < 4) return;
        const frame_id = std.mem.readInt(u32, payload[0..4], .little);
        try self.deliverAt(sim, node, frame_id);
    }

    fn onTimer(ctxp: *anyopaque, sim: *netsim.Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctxp);
        if (timer_id == ORIGIN_TIMER) {
            // Audit F2: bound-check before claiming a fresh frame slot —
            // `slot_owner`'s mismatch check keeps stale data from being
            // mistaken for live data, but a claim past `MAX_FRAMES`
            // in-flight frames would still stomp a genuinely live frame's
            // tracking state mid-flight (a mis-attributed loop check).
            std.debug.assert(self.next_frame_id - self.retired_frame_id < MAX_FRAMES);
            const frame_id = self.next_frame_id;
            self.next_frame_id += 1;
            try self.deliverAt(sim, node, frame_id);
            try sim.setTimer(node, self.origin_period, ORIGIN_TIMER);
        } else if (timer_id >= FIB_APPLY_BASE) {
            // Same unconditionally-in-range modulo as above.
            const slot: usize = @intCast((timer_id - FIB_APPLY_BASE) % MAX_PENDING);
            const upd = self.pending[slot];
            self.next_hop[upd.node] = upd.next_hop;
            self.applied_pending_id += 1;
        } else if (timer_id >= CONDUCTOR_BASE) {
            // Unlike the two slots above, this index is NOT taken modulo
            // anything — it is checked directly against `self.schedule.len`
            // (a real `usize` bound), so it needs an actual boundary
            // decision rather than an always-safe cast. `timer_id -
            // CONDUCTOR_BASE` is itself a `u64` sequence offset; guard the
            // comparison and the indexing on the `usize` side so a
            // wildly-out-of-range `timer_id` (which would already be a bug
            // elsewhere — this module only ever hands back ids it minted
            // itself) fails the bounds check instead of being silently
            // truncated into an in-range but WRONG index.
            const raw_idx = timer_id - CONDUCTOR_BASE;
            if (raw_idx < self.schedule.len) {
                const idx: usize = @intCast(raw_idx);
                try self.applyTopologyChange(sim, self.schedule[idx]);
            }
        }
    }

    fn check(ctxp: *anyopaque, sim: *const netsim.Sim) anyerror!void {
        _ = sim;
        const self = cast(ctxp);
        if (self.loop_violation) return error.ForwardingLoop;
    }

    fn reset(ctxp: *anyopaque) void {
        const self = cast(ctxp);
        @memset(&self.up, true);
        @memset(&self.next_hop, null);
        @memset(&self.slot_owner, std.math.maxInt(u32));
        @memset(&self.slot_visited, 0);
        @memset(&self.slot_last, 0);
        self.next_frame_id = 0;
        self.retired_frame_id = 0;
        self.next_pending_id = 0;
        self.applied_pending_id = 0;
        self.last_apply_time = 0;
        self.loop_violation = false;
        self.loop_frame = null;
        self.loop_node = null;
    }
};

const testing = std.testing;

test "buildGraph + applyInitialFib: all-up ring converges to the hand-derived next-hops" {
    const gpa = testing.allocator;
    var f = Fabric.init(gpa, .naive_bad);
    try f.applyInitialFib();
    // dest=0 direct: node1 -> 0. node2: via1 (cost2) beats via3 (cost11) -> 1.
    // node3: via2->1->0 (cost3) beats direct (cost10) -> 2.
    try testing.expectEqual(@as(?NodeId, 0), f.next_hop[1]);
    try testing.expectEqual(@as(?NodeId, 1), f.next_hop[2]);
    try testing.expectEqual(@as(?NodeId, 2), f.next_hop[3]);
}

test "applyTopologyChange (naive_bad): severing 1-0 flips node1's and node2's next-hop as derived" {
    const gpa = testing.allocator;
    var f = Fabric.init(gpa, .naive_bad);
    try f.applyInitialFib();

    // Fake sim just to receive setTimer calls; use the real engine minimally.
    var log = netsim.Log{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, f.protocol(), &log, 1000, 1000);
    defer sim.deinit();
    try scenario(&sim);

    try f.applyTopologyChange(&sim, .{ .time = 0, .kind = .{ .link_down = .{ .a = 1, .b = 0 } } });
    // Updates are only *scheduled* (via setTimer), not yet applied.
    try testing.expectEqual(@as(?NodeId, 0), f.next_hop[1]); // unchanged until its timer fires
    try testing.expect(f.next_pending_id > 0);
}

test {
    std.testing.refAllDecls(@This());
}
