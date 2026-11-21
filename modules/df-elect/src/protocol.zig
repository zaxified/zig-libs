// SPDX-License-Identifier: MIT

//! protocol — the `netsim.Protocol` consumers.
//!
//!  - `DfElect` is the real thing: a link-state Hello flood (liveness) and a
//!    BUM flood; each segment member keeps, per Ethernet tag, an
//!    `election.Role` driven by `election.designatedForwarder` over the
//!    members it currently sees, and delivers a frame to its segment only as
//!    the DF for the frame's tag and only past split-horizon.
//!  - `BrokenAlwaysDf` is the POSITIVE CONTROL: every member delivers every
//!    frame for a tag its segment carries, with no split-horizon. It reuses
//!    `checks.DeliveryChecker` verbatim, so what it trips is the same check.
//!
//! Both share one topology (`scenario`): a 3-node core triangle and two
//! multihomed segments whose members hang off DIFFERENT core nodes, so a core
//! partition can separate a segment's own members from each other.
//!
//! ```text
//!             core0 ──── core1 ──── core2      (core0─core2 also linked)
//!               │        │   │      │   │
//!              A3       A4   B6    A5   B7
//!   segment A = {3, 4, 5}, tags 10..15      segment B = {6, 7}, tags 10, 11, 20
//! ```
//!
//! Tags 10 and 11 exist on both segments, so a network-side frame on tag 10
//! is delivered twice — once per segment, both legitimate — and a CE-side
//! frame from segment B on tag 10 must reach segment A but never B again.

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
const Tag = types.Tag;
const Member = types.Member;
const EdgeSegment = types.EdgeSegment;
const ElectConfig = types.ElectConfig;

// ── shared topology ──────────────────────────────────────────────────────

pub const NODE_N = 8;
pub const CORE0: NodeId = 0;
pub const CORE1: NodeId = 1;
pub const CORE2: NodeId = 2;
pub const NETWORK_ORIGIN: NodeId = CORE0;

/// Most tags any segment here carries; sizes the per-node role table.
pub const MAX_TAGS = 8;

const members_a = [_]Member{
    .{ .node = 3, .addr = 0x0a00_0003 },
    .{ .node = 4, .addr = 0x0a00_0004 },
    .{ .node = 5, .addr = 0x0a00_0005 },
};
const members_b = [_]Member{
    .{ .node = 6, .addr = 0x0a00_0006 },
    .{ .node = 7, .addr = 0x0a00_0007 },
};

pub const SEG_A = EdgeSegment{
    .id = 1,
    .esi = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01 },
    .members = &members_a,
    .tags = &.{ 10, 11, 12, 13, 14, 15 },
};
pub const SEG_B = EdgeSegment{
    .id = 2,
    .esi = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x02 },
    .members = &members_b,
    .tags = &.{ 10, 11, 20 },
};
pub const segments = [_]EdgeSegment{ SEG_A, SEG_B };

/// Every tag some segment carries, in the order the network origin cycles
/// through them.
const all_tags = [_]Tag{ 10, 11, 12, 13, 14, 15, 20 };

pub fn scenario(sim: *Sim) anyerror!void {
    var i: usize = 0;
    while (i < NODE_N) : (i += 1) _ = try sim.addNode(.{});
    const core_cfg = LinkConfig{ .latency = 5, .jitter = 2 };
    try sim.addBiLink(CORE0, CORE1, core_cfg);
    try sim.addBiLink(CORE1, CORE2, core_cfg);
    try sim.addBiLink(CORE0, CORE2, core_cfg);
    const edge_cfg = LinkConfig{ .latency = 3, .jitter = 1 };
    try sim.addBiLink(CORE0, 3, edge_cfg);
    try sim.addBiLink(CORE1, 4, edge_cfg);
    try sim.addBiLink(CORE2, 5, edge_cfg);
    try sim.addBiLink(CORE1, 6, edge_cfg);
    try sim.addBiLink(CORE2, 7, edge_cfg);
}

fn memberMask(seg: EdgeSegment) u32 {
    return if (seg.members.len >= 32) std.math.maxInt(u32) else (@as(u32, 1) << @intCast(seg.members.len)) - 1;
}

/// The members of `seg` whose bits are set in `view`, in address order.
fn membersIn(seg: EdgeSegment, view: u32, buf: *[types.max_members]Member) []Member {
    var n: usize = 0;
    for (seg.members, 0..) |m, i| {
        if (view & (@as(u32, 1) << @intCast(i)) != 0) {
            buf[n] = m;
            n += 1;
        }
    }
    return buf[0..n];
}

fn segmentIndexOf(node: NodeId) ?usize {
    for (segments, 0..) |s, i| if (s.indexOf(node) != null) return i;
    return null;
}

/// The DF each tag should settle on when every member is up and connected.
pub fn settledDf(algorithm: types.Algorithm, seg: EdgeSegment, tag: Tag) NodeId {
    return election.designatedForwarder(algorithm, seg.esi, seg.members, tag).?;
}

// ── DfElect: the real protocol ───────────────────────────────────────────

/// Hello flag bit 1: a Don't Preempt member that has not yet frozen its
/// operational preference; peers leave it out of the candidates.
const flag_unready: u8 = 2;

const HELLO_TIMER: u64 = 0;
const BUM_CE_TIMER: u64 = 1;
const BUM_NET_TIMER: u64 = 2;
const DFW_TIMER: u64 = 3;

/// Timer ids carry the node's start epoch above the kind, so a timer armed
/// before a crash that comes due after the restart is recognised as stale
/// instead of doubling the new chain.
fn timerId(kind: u64, epoch: u32) u64 {
    return kind | (@as(u64, epoch) << 8);
}

/// The node's own clock, as the protocol would read it: global time plus the
/// node's skew/jump offset (netsim's `clock_jump` fault), clamped at 0.
/// Liveness and `df_wait` are measured on it, so a clock jump exercises the
/// DF wait exactly as a real skewed PE would.
fn localTime(sim: *const Sim, node: NodeId) Time {
    return @intCast(@max(0, sim.clock(node)));
}

/// `bum_seen`/`hello_last_seq` dedup a flooded message per (node, origin)
/// with a bitmask / monotonic counter respectively — see their field docs.
pub const DfElect = struct {
    gpa: Allocator,
    node_count: usize,
    cfg: ElectConfig,

    /// hello_last_seq[node*node_count + origin] = highest Hello `seq` `node`
    /// has accepted-and-forwarded from `origin` (supersede flooding). 0 =
    /// never; real sequence numbers start at 1.
    hello_last_seq: []u32,
    /// bum_seen[node*node_count + origin], bit `seq` = "`node` has processed
    /// BUM frame `seq` from `origin`". A bitmask, since every distinct BUM
    /// frame must reach every node; it bounds each origin to fewer than 64
    /// originations per run (asserted in `originateBum`).
    bum_seen: []u64,
    /// last_seen[node*node_count + member] = the local time until which
    /// `node` counts `member` of its own segment alive: the arrival time of
    /// its last fresh Hello plus the lifetime that Hello advertised.
    last_seen: []?Time,
    /// The preference, flag octet and AC-down mask `member` last advertised
    /// to `node`, indexed like `last_seen`.
    last_pref: []u16,
    last_flags: []u8,
    last_ac: []u8,
    /// Per node: its own AC-down mask, whether it has been alive for
    /// `df_wait` (`ready`: it has heard its peers, so its operational
    /// preference may be frozen), that frozen advert, and the global time of
    /// the pending DF-wait timer (null: none armed).
    own_ac: []u8,
    ready: []bool,
    op_pref: []u16,
    op_dp: []bool,
    start_at: []Time,
    dfw_due: []?Time,
    /// Which `cfg.ac_events` have been applied.
    ac_applied: []bool,
    /// last_view[node*node_count + member] = the `Hello.view` `member` last
    /// advertised to `node` (meaningful while `last_seen` says alive).
    last_view: []u32,
    /// last_heard[node] = the local time until which `node` counts the fabric
    /// as heard: the latest arrival plus lifetime of a fresh Hello from ANY
    /// other fabric node; `null` = never since its start.
    last_heard: []?Time,
    /// roles[node*MAX_TAGS + i] = `node`'s standing for its segment's
    /// `tags[i]`.
    roles: []election.Role,
    hello_seq: []u32,
    bum_seq: []u32,
    /// Incremented by every `onStart`; see `timerId`.
    epoch: []u32,
    tag_cursor: []u32,

    delivery: checks.DeliveryChecker = .{},
    transitions: std.ArrayList(checks.DfTransition) = .empty,
    /// Every BUM frame put on the fabric, for `checks.firstUnexplainedLoss`.
    originated: std.ArrayList(checks.Origination) = .empty,

    /// Frames dropped because they did not decode, or because `origin`/`seq`
    /// fell outside what this node's dedup state can represent. Every frame
    /// in this harness comes from our own `encode`, so it must stay 0.
    malformed_dropped: u64 = 0,

    pub const InitError = Allocator.Error || error{InvalidConfig} || EdgeSegment.Error;

    pub fn init(gpa: Allocator, node_count: usize, cfg: ElectConfig) InitError!DfElect {
        return initUnchecked(gpa, node_count, cfg, true);
    }

    /// `check_config = false` admits a `df_wait` too short to cover the
    /// first Hello round — only the negative control uses it.
    pub fn initUnchecked(gpa: Allocator, node_count: usize, cfg: ElectConfig, check_config: bool) InitError!DfElect {
        if (check_config and cfg.df_wait <= cfg.hello_period) return error.InvalidConfig;
        for (segments) |s| {
            try s.validate();
            if (s.tags.len > MAX_TAGS) return error.InvalidConfig;
        }
        const hello_last_seq = try gpa.alloc(u32, node_count * node_count);
        errdefer gpa.free(hello_last_seq);
        const bum_seen = try gpa.alloc(u64, node_count * node_count);
        errdefer gpa.free(bum_seen);
        const last_seen = try gpa.alloc(?Time, node_count * node_count);
        errdefer gpa.free(last_seen);
        const last_view = try gpa.alloc(u32, node_count * node_count);
        errdefer gpa.free(last_view);
        const last_heard = try gpa.alloc(?Time, node_count);
        errdefer gpa.free(last_heard);
        const last_pref = try gpa.alloc(u16, node_count * node_count);
        errdefer gpa.free(last_pref);
        const last_flags = try gpa.alloc(u8, node_count * node_count);
        errdefer gpa.free(last_flags);
        const last_ac = try gpa.alloc(u8, node_count * node_count);
        errdefer gpa.free(last_ac);
        const own_ac = try gpa.alloc(u8, node_count);
        errdefer gpa.free(own_ac);
        const ready = try gpa.alloc(bool, node_count);
        errdefer gpa.free(ready);
        const op_pref = try gpa.alloc(u16, node_count);
        errdefer gpa.free(op_pref);
        const op_dp = try gpa.alloc(bool, node_count);
        errdefer gpa.free(op_dp);
        const start_at = try gpa.alloc(Time, node_count);
        errdefer gpa.free(start_at);
        const dfw_due = try gpa.alloc(?Time, node_count);
        errdefer gpa.free(dfw_due);
        const ac_applied = try gpa.alloc(bool, cfg.ac_events.len);
        errdefer gpa.free(ac_applied);
        const roles = try gpa.alloc(election.Role, node_count * MAX_TAGS);
        errdefer gpa.free(roles);
        const hello_seq = try gpa.alloc(u32, node_count);
        errdefer gpa.free(hello_seq);
        const bum_seq = try gpa.alloc(u32, node_count);
        errdefer gpa.free(bum_seq);
        const epoch = try gpa.alloc(u32, node_count);
        errdefer gpa.free(epoch);
        const tag_cursor = try gpa.alloc(u32, node_count);
        var self: DfElect = .{
            .gpa = gpa,
            .node_count = node_count,
            .cfg = cfg,
            .hello_last_seq = hello_last_seq,
            .bum_seen = bum_seen,
            .last_seen = last_seen,
            .last_view = last_view,
            .last_heard = last_heard,
            .last_pref = last_pref,
            .last_flags = last_flags,
            .last_ac = last_ac,
            .own_ac = own_ac,
            .ready = ready,
            .op_pref = op_pref,
            .op_dp = op_dp,
            .start_at = start_at,
            .dfw_due = dfw_due,
            .ac_applied = ac_applied,
            .roles = roles,
            .hello_seq = hello_seq,
            .bum_seq = bum_seq,
            .epoch = epoch,
            .tag_cursor = tag_cursor,
        };
        self.clearState();
        return self;
    }

    pub fn deinit(self: *DfElect, gpa: Allocator) void {
        gpa.free(self.hello_last_seq);
        gpa.free(self.bum_seen);
        gpa.free(self.last_seen);
        gpa.free(self.last_view);
        gpa.free(self.last_heard);
        gpa.free(self.last_pref);
        gpa.free(self.last_flags);
        gpa.free(self.last_ac);
        gpa.free(self.own_ac);
        gpa.free(self.ready);
        gpa.free(self.op_pref);
        gpa.free(self.op_dp);
        gpa.free(self.start_at);
        gpa.free(self.dfw_due);
        gpa.free(self.ac_applied);
        gpa.free(self.roles);
        gpa.free(self.hello_seq);
        gpa.free(self.bum_seq);
        gpa.free(self.epoch);
        gpa.free(self.tag_cursor);
        self.delivery.deinit(gpa);
        self.transitions.deinit(gpa);
        self.originated.deinit(gpa);
        self.* = undefined;
    }

    fn clearState(self: *DfElect) void {
        @memset(self.hello_last_seq, 0);
        @memset(self.bum_seen, 0);
        @memset(self.last_seen, null);
        @memset(self.last_view, 0);
        @memset(self.last_heard, null);
        @memset(self.last_pref, 0);
        @memset(self.last_flags, 0);
        @memset(self.last_ac, 0);
        @memset(self.own_ac, 0);
        @memset(self.ready, false);
        @memset(self.op_pref, 0);
        @memset(self.op_dp, false);
        @memset(self.start_at, 0);
        @memset(self.dfw_due, null);
        @memset(self.ac_applied, false);
        @memset(self.roles, .{});
        @memset(self.hello_seq, 0);
        @memset(self.bum_seq, 0);
        @memset(self.epoch, 0);
        @memset(self.tag_cursor, 0);
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
        self.clearState();
        self.delivery.reset();
        self.transitions.clearRetainingCapacity();
        self.originated.clearRetainingCapacity();
        self.malformed_dropped = 0;
    }

    /// Start or RESTART: a restarted member comes back with an empty view and
    /// no role (RFC 7432 §8.5 step 2: a PE starts blocked and waits), so any
    /// role it held before the crash is logged as given up now. Every node,
    /// member or not, floods Hellos.
    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        self.epoch[node] += 1;
        const e = self.epoch[node];
        self.last_heard[node] = null;
        self.own_ac[node] = 0;
        self.ready[node] = false;
        self.start_at[node] = localTime(sim, node);
        self.dfw_due[node] = null;
        try sim.setTimer(node, self.cfg.hello_period, timerId(HELLO_TIMER, e));
        if (segmentIndexOf(node)) |si| {
            const seg = segments[si];
            for (seg.tags, 0..) |tag, ti| {
                const r = &self.roles[node * MAX_TAGS + ti];
                if (r.is_df) self.logTransition(sim, seg, tag, node, false);
                r.* = .{};
            }
            @memset(self.last_seen[node * self.node_count ..][0..self.node_count], null);
            @memset(self.last_view[node * self.node_count ..][0..self.node_count], 0);
            @memset(self.last_pref[node * self.node_count ..][0..self.node_count], 0);
            @memset(self.last_flags[node * self.node_count ..][0..self.node_count], 0);
            @memset(self.last_ac[node * self.node_count ..][0..self.node_count], 0);
            if (seg.members[0].node == node) try sim.setTimer(node, self.cfg.bum_period, timerId(BUM_CE_TIMER, e));
        }
        if (node == NETWORK_ORIGIN) try sim.setTimer(node, self.cfg.bum_period, timerId(BUM_NET_TIMER, e));
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const e = self.epoch[node];
        if (timer_id >> 8 != e) return; // armed before a restart
        switch (timer_id & 0xff) {
            HELLO_TIMER => {
                const si = segmentIndexOf(node);
                if (si) |i| self.tickState(sim, node, i);
                try self.originateHello(sim, node, si);
                // Staleness and isolation are only noticed on a tick.
                if (si) |i| try self.refreshRoles(sim, node, i);
                try sim.setTimer(node, self.cfg.hello_period, timerId(HELLO_TIMER, e));
            },
            DFW_TIMER => {
                self.dfw_due[node] = null;
                if (segmentIndexOf(node)) |si| try self.refreshRoles(sim, node, si);
            },
            BUM_CE_TIMER => if (segmentIndexOf(node)) |si| {
                const seg = segments[si];
                const tag = seg.tags[self.tag_cursor[node] % seg.tags.len];
                self.tag_cursor[node] += 1;
                try self.originateBum(sim, node, seg.id, tag);
                try sim.setTimer(node, self.cfg.bum_period, timerId(BUM_CE_TIMER, e));
            },
            BUM_NET_TIMER => {
                const tag = all_tags[self.tag_cursor[node] % all_tags.len];
                self.tag_cursor[node] += 1;
                try self.originateBum(sim, node, types.no_ingress, tag);
                try sim.setTimer(node, self.cfg.bum_period, timerId(BUM_NET_TIMER, e));
            },
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const tag = types.tagOf(payload) catch {
            self.malformed_dropped += 1;
            return;
        };
        switch (tag) {
            .hello => try self.handleHello(sim, node, from, payload),
            .bum => try self.handleBum(sim, node, from, payload),
        }
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        try cast(ctx).delivery.check();
    }

    fn floodFrom(sim: *Sim, node: NodeId, payload: []const u8, exclude: ?NodeId) anyerror!void {
        var nb: [16]NodeId = undefined;
        const n = try sim.neighbors(node, &nb);
        for (nb[0..n]) |peer| {
            if (exclude) |ex| if (peer == ex) continue;
            try sim.send(node, peer, payload);
        }
    }

    fn originateHello(self: *DfElect, sim: *Sim, node: NodeId, si: ?usize) anyerror!void {
        self.hello_seq[node] += 1;
        var buf: [types.Hello.wire_len]u8 = undefined;
        const segment = if (si) |i| segments[i].id else types.no_segment;
        const view = if (si) |i| self.viewOf(sim, node, i) else 0;
        const adv = self.advertOf(node);
        (types.Hello{
            .origin = node,
            .seq = self.hello_seq[node],
            .segment = segment,
            .view = view,
            .pref = adv.pref,
            .flags = (if (adv.dp) types.Hello.flag_dp else 0) | (if (self.dpMember(node) and !self.ready[node]) flag_unready else 0),
            .ac_down = self.own_ac[node],
            .lifetime = @intCast(@min(self.cfg.stale_after, std.math.maxInt(u32))),
        }).encode(&buf);
        self.hello_last_seq[node * self.node_count + node] = self.hello_seq[node];
        try floodFrom(sim, node, &buf, null);
    }

    fn originateBum(self: *DfElect, sim: *Sim, node: NodeId, ingress_segment: SegmentId, tag: Tag) anyerror!void {
        self.bum_seq[node] += 1;
        std.debug.assert(self.bum_seq[node] < 64); // see `bum_seen`
        var buf: [types.BumFrame.wire_len]u8 = undefined;
        const frame = types.BumFrame{ .origin = node, .seq = self.bum_seq[node], .ingress_segment = ingress_segment, .tag = tag };
        frame.encode(&buf);
        self.bum_seen[node * self.node_count + node] |= @as(u64, 1) << @intCast(self.bum_seq[node]);
        try self.originated.append(self.gpa, .{ .time = sim.timeNow(), .origin = node, .frame_id = frame.id(), .tag = tag, .ingress_segment = ingress_segment });
        try floodFrom(sim, node, &buf, null);
    }

    fn handleHello(self: *DfElect, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const h = types.Hello.decode(payload) catch {
            self.malformed_dropped += 1;
            return;
        };
        // `origin` indexes node_count*node_count arrays: a well-formed Hello
        // claiming origin 0xFFFFFFFF would write far out of bounds. The
        // decoder does not know the topology, so the check lives here.
        if (h.origin >= self.node_count) {
            self.malformed_dropped += 1;
            return;
        }
        const idx = node * self.node_count + h.origin;
        if (h.seq <= self.hello_last_seq[idx]) return; // stale or duplicate
        self.hello_last_seq[idx] = h.seq;
        const now = localTime(sim, node);
        if (h.origin != node) {
            const until = now +| h.lifetime;
            self.last_heard[node] = if (self.last_heard[node]) |old| @max(old, until) else until;
        }

        if (segmentIndexOf(node)) |si| {
            const seg = segments[si];
            if (h.origin != node and h.segment == seg.id and seg.indexOf(h.origin) != null) {
                // Lifetime 0 is a purge: the origin is forgotten at once.
                self.last_seen[idx] = if (h.lifetime == 0) null else now +| h.lifetime;
                // Bits past the member list mean nothing; drop them.
                self.last_view[idx] = h.view & memberMask(seg);
                self.last_pref[idx] = h.pref;
                self.last_flags[idx] = h.flags;
                self.last_ac[idx] = h.ac_down;
                try self.refreshRoles(sim, node, si);
            }
        }
        try floodFrom(sim, node, payload, from);
    }

    fn handleBum(self: *DfElect, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const f = types.BumFrame.decode(payload) catch {
            self.malformed_dropped += 1;
            return;
        };
        // Two untrusted VALUES a length check cannot catch: `origin` indexes
        // `bum_seen`, and `seq` is a shift amount into a u64.
        if (f.origin >= self.node_count or f.seq >= @bitSizeOf(u64)) {
            self.malformed_dropped += 1;
            return;
        }
        const idx = node * self.node_count + f.origin;
        const bit = @as(u64, 1) << @intCast(f.seq);
        if (self.bum_seen[idx] & bit != 0) return;
        self.bum_seen[idx] |= bit;

        if (segmentIndexOf(node)) |si| {
            const seg = segments[si];
            if (seg.tagIndex(f.tag)) |ti| {
                try self.refreshRoles(sim, node, si);
                if (self.roles[node * MAX_TAGS + ti].is_df and election.allowForward(f.ingress_segment, seg.id)) {
                    try self.delivery.recordDelivery(self.gpa, sim.timeNow(), seg.id, f.tag, f.id(), f.ingress_segment);
                }
            }
        }
        try floodFrom(sim, node, payload, from);
    }

    /// Is peer `member` (whose bit in a view is `bit`) alive in `node`'s
    /// view: a fresh Hello from it, and that Hello does not declare it
    /// isolated (its own bit set).
    fn sees(self: *const DfElect, now: Time, node: NodeId, member: NodeId, bit: u32) bool {
        const idx = node * self.node_count + member;
        const until = self.last_seen[idx] orelse return false;
        if (now > until) return false;
        return self.last_view[idx] & bit != 0;
    }

    /// Core isolation: `node` has heard no fabric node for `stale_after`
    /// (or not yet since it started). Such a member most likely receives no
    /// frame either, so it must neither hold a role nor be deferred to — the
    /// rule FRRouting applies as EVPN-MH "core isolation" (access ports go
    /// protodown once every uplink is gone).
    fn isolated(self: *const DfElect, now: Time, node: NodeId) bool {
        const until = self.last_heard[node] orelse return true;
        return now > until;
    }

    /// `node`'s current view of its segment as a member bitmask (the value
    /// its Hellos advertise): itself and the peers it `sees`, or 0 — without
    /// even its own bit — while it is `isolated`.
    fn viewOf(self: *const DfElect, sim: *const Sim, node: NodeId, si: usize) u32 {
        const now = localTime(sim, node);
        if (self.isolated(now, node)) return 0;
        var mask: u32 = 0;
        for (segments[si].members, 0..) |m, i| {
            const bit = @as(u32, 1) << @intCast(i);
            if (m.node == node or self.sees(now, node, m.node, bit)) mask |= bit;
        }
        return mask;
    }

    /// Per-tick local state: apply due scripted AC events and, once the member
    /// has been alive for `df_wait`, freeze its operational preference.
    fn tickState(self: *DfElect, sim: *const Sim, node: NodeId, si: usize) void {
        _ = si;
        const now = localTime(sim, node);
        for (self.cfg.ac_events, 0..) |ev, k| {
            if (ev.node != node or self.ac_applied[k] or now < ev.time) continue;
            self.ac_applied[k] = true;
            const bit = @as(u8, 1) << @intCast(ev.tag_index);
            if (ev.down) self.own_ac[node] |= bit else self.own_ac[node] &= ~bit;
        }
        if (!self.ready[node] and now -| self.start_at[node] >= self.cfg.df_wait) {
            const seg = segments[segmentIndexOf(node).?];
            const admin = self.adminOf(node);
            // The peers' adverts as received: members this node sees and
            // that are themselves ready.
            var peers: [types.max_members]Member = undefined;
            var n: usize = 0;
            for (seg.members) |m| {
                if (m.node == node) continue;
                const idx = node * self.node_count + m.node;
                const bit = @as(u32, 1) << @intCast(seg.indexOf(m.node).?);
                if (!self.sees(now, node, m.node, bit) or self.last_flags[idx] & flag_unready != 0) continue;
                peers[n] = .{ .node = m.node, .addr = m.addr, .pref = self.last_pref[idx], .dp = self.last_flags[idx] & types.Hello.flag_dp != 0 };
                n += 1;
            }
            const op = election.operationalPref(admin, peers[0..n]);
            self.op_pref[node] = op.pref;
            self.op_dp[node] = op.dp;
            self.ready[node] = true;
        }
    }

    /// The configured preference of `node`.
    fn adminOf(self: *const DfElect, node: NodeId) election.Advert {
        for (self.cfg.prefs) |p| if (p.node == node) return .{ .pref = p.pref, .dp = p.dp };
        const seg = segments[segmentIndexOf(node).?];
        const m = seg.members[seg.indexOf(node).?];
        return .{ .pref = m.pref, .dp = m.dp };
    }

    /// Does `node` run Don't Preempt?
    fn dpMember(self: *const DfElect, node: NodeId) bool {
        if (segmentIndexOf(node) == null) return false;
        return self.adminOf(node).dp;
    }

    /// What `node` advertises: its configured value until it is ready, the
    /// frozen operational one after. A DP member that is not yet ready also
    /// sets `flag_unready` so that peers leave it out of the candidates.
    fn advertOf(self: *const DfElect, node: NodeId) election.Advert {
        if (segmentIndexOf(node) == null) return .{ .pref = 0, .dp = false };
        if (!self.ready[node]) return self.adminOf(node);
        return .{ .pref = self.op_pref[node], .dp = self.op_dp[node] };
    }

    /// The candidate list for `tag` under the member set `view`, as `node`
    /// knows it: the members in `view`, each with the preference it last
    /// advertised, less those whose attachment circuit for the tag is down
    /// (RFC 8584 section 4) and, for DP members, those not yet ready.
    fn candidatesFor(self: *const DfElect, node: NodeId, seg: EdgeSegment, view: u32, ti: usize, buf: *[types.max_members]Member) []Member {
        var n: usize = 0;
        const tag_bit = @as(u8, 1) << @intCast(ti);
        for (seg.members, 0..) |m, i| {
            if (view & (@as(u32, 1) << @intCast(i)) == 0) continue;
            var c = m;
            if (m.node == node) {
                if (self.own_ac[node] & tag_bit != 0) continue;
                if (self.dpMember(node) and !self.ready[node]) continue;
                const adv = self.advertOf(node);
                c.pref = adv.pref;
                c.dp = adv.dp;
            } else {
                const idx = node * self.node_count + m.node;
                if (self.last_ac[idx] & tag_bit != 0) continue;
                if (self.last_flags[idx] & flag_unready != 0) continue;
                c.pref = self.last_pref[idx];
                c.dp = self.last_flags[idx] & types.Hello.flag_dp != 0;
            }
            buf[n] = c;
            n += 1;
        }
        return buf[0..n];
    }

    /// Re-run the election for every tag of `node`'s segment.
    ///
    /// `node` is NAMED for a tag when the DF function over its own view picks
    /// it AND the view each peer it sees last advertised picks it too. An
    /// isolated node's view is empty, so it is named for nothing. The
    /// second half is what makes a one-way failure safe: a member whose
    /// outbound path died still hears its peers, but they no longer see it
    /// and carve its tags among themselves; their advertised views say so,
    /// and it yields instead of delivering alongside them. (netsim's
    /// `link_down` is directional, and the fuzzer found exactly this.) EVPN
    /// gets the same property from BGP sessions being two-way.
    ///
    /// A role gain that is pending arms one DF-wait timer for the moment its
    /// wait ends, so the role is taken then and not on the next tick.
    fn refreshRoles(self: *DfElect, sim: *Sim, node: NodeId, si: usize) anyerror!void {
        const seg = segments[si];
        const now = localTime(sim, node);
        const my_view = self.viewOf(sim, node, si);
        var next_due: ?Time = null; // earliest pending end of a DF wait, local time
        for (seg.tags, 0..) |tag, ti| {
            const alg = types.algorithmFor(self.cfg, tag);
            var mine_buf: [types.max_members]Member = undefined;
            const mine = self.candidatesFor(node, seg, my_view, ti, &mine_buf);
            var named = election.designatedForwarder(alg, seg.esi, mine, tag) == node;
            if (named) for (seg.members, 0..) |peer, pi| {
                if (peer.node == node or my_view & (@as(u32, 1) << @intCast(pi)) == 0) continue;
                var theirs_buf: [types.max_members]Member = undefined;
                const theirs = self.candidatesFor(node, seg, self.last_view[node * self.node_count + peer.node], ti, &theirs_buf);
                if (election.designatedForwarder(alg, seg.esi, theirs, tag) != node) {
                    named = false;
                    break;
                }
            };
            const r = &self.roles[node * MAX_TAGS + ti];
            const next = election.stepRole(r.*, named, now, self.cfg.df_wait);
            if (next.is_df != r.is_df) self.logTransition(sim, seg, tag, node, next.is_df);
            r.* = next;
            if (next.want_since) |since| {
                const due = since +| self.cfg.df_wait;
                next_due = if (next_due) |d| @min(d, due) else due;
            }
        }
        if (next_due) |due| {
            const global_due = sim.timeNow() + @max(1, due -| now);
            const armed = self.dfw_due[node];
            if (armed == null or armed.? > global_due) {
                self.dfw_due[node] = global_due;
                try sim.setTimer(node, global_due - sim.timeNow(), timerId(DFW_TIMER, self.epoch[node]));
            }
        }
    }

    fn logTransition(self: *DfElect, sim: *Sim, seg: EdgeSegment, tag: Tag, node: NodeId, is_df: bool) void {
        self.transitions.append(self.gpa, .{
            .time = sim.timeNow(),
            .segment = seg.id,
            .tag = tag,
            .node = node,
            .is_df = is_df,
        }) catch {}; // best-effort log, mirrors netsim's own Log.append
    }

    /// Who holds the role for `<seg, tag>` according to this node table.
    pub fn holders(self: *const DfElect, seg: EdgeSegment, tag: Tag, out: []NodeId) []NodeId {
        const ti = seg.tagIndex(tag).?;
        var n: usize = 0;
        for (seg.members) |m| {
            if (self.roles[m.node * MAX_TAGS + ti].is_df) {
                out[n] = m.node;
                n += 1;
            }
        }
        return out[0..n];
    }
};

// ── BrokenAlwaysDf: the positive control ────────────────────────────────

/// Deliberately WRONG: every member delivers every frame whose tag its
/// segment carries, with no election and no split-horizon. It trips
/// `checks.DeliveryChecker` (with `duplicates_fatal`) two ways: a
/// network-side frame reaching two members of one segment is a duplicate,
/// and a CE-side frame reaching another member of its own segment is a
/// split-horizon violation.
pub const BrokenAlwaysDf = struct {
    gpa: Allocator,
    node_count: usize,
    cfg: ElectConfig,

    bum_seen: []u64,
    bum_seq: []u32,
    tag_cursor: []u32,

    delivery: checks.DeliveryChecker = .{ .duplicates_fatal = true },

    pub fn init(gpa: Allocator, node_count: usize, cfg: ElectConfig) Allocator.Error!BrokenAlwaysDf {
        const bum_seen = try gpa.alloc(u64, node_count * node_count);
        errdefer gpa.free(bum_seen);
        const bum_seq = try gpa.alloc(u32, node_count);
        errdefer gpa.free(bum_seq);
        const tag_cursor = try gpa.alloc(u32, node_count);
        @memset(bum_seen, 0);
        @memset(bum_seq, 0);
        @memset(tag_cursor, 0);
        return .{ .gpa = gpa, .node_count = node_count, .cfg = cfg, .bum_seen = bum_seen, .bum_seq = bum_seq, .tag_cursor = tag_cursor };
    }

    pub fn deinit(self: *BrokenAlwaysDf, gpa: Allocator) void {
        gpa.free(self.bum_seen);
        gpa.free(self.bum_seq);
        gpa.free(self.tag_cursor);
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
        @memset(self.tag_cursor, 0);
        self.delivery.reset();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        if (segmentIndexOf(node)) |si| {
            if (segments[si].members[0].node == node) try sim.setTimer(node, self.cfg.bum_period, BUM_CE_TIMER);
        }
        if (node == NETWORK_ORIGIN) try sim.setTimer(node, self.cfg.bum_period, BUM_NET_TIMER);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        switch (timer_id) {
            BUM_CE_TIMER => if (segmentIndexOf(node)) |si| {
                const seg = segments[si];
                const tag = seg.tags[self.tag_cursor[node] % seg.tags.len];
                self.tag_cursor[node] += 1;
                try self.originateBum(sim, node, seg.id, tag);
                try sim.setTimer(node, self.cfg.bum_period, BUM_CE_TIMER);
            },
            BUM_NET_TIMER => {
                const tag = all_tags[self.tag_cursor[node] % all_tags.len];
                self.tag_cursor[node] += 1;
                try self.originateBum(sim, node, types.no_ingress, tag);
                try sim.setTimer(node, self.cfg.bum_period, BUM_NET_TIMER);
            },
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        // Wrong about the ELECTION, not about parsing: a decode panic must
        // never masquerade as the checker firing.
        const tag = types.tagOf(payload) catch return;
        if (tag != .bum) return; // this broken protocol never sends Hellos
        const f = types.BumFrame.decode(payload) catch return;
        if (f.origin >= self.node_count or f.seq >= @bitSizeOf(u64)) return;
        const idx = node * self.node_count + f.origin;
        const bit = @as(u64, 1) << @intCast(f.seq);
        if (self.bum_seen[idx] & bit != 0) return;
        self.bum_seen[idx] |= bit;

        if (segmentIndexOf(node)) |si| {
            const seg = segments[si];
            // THE BUG: no election, no split-horizon gate.
            if (seg.tagIndex(f.tag) != null)
                try self.delivery.recordDelivery(self.gpa, sim.timeNow(), seg.id, f.tag, f.id(), f.ingress_segment);
        }
        try DfElect.floodFrom(sim, node, payload, from);
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        try cast(ctx).delivery.check();
    }

    fn originateBum(self: *BrokenAlwaysDf, sim: *Sim, node: NodeId, ingress_segment: SegmentId, tag: Tag) anyerror!void {
        self.bum_seq[node] += 1;
        std.debug.assert(self.bum_seq[node] < 64);
        var buf: [types.BumFrame.wire_len]u8 = undefined;
        (types.BumFrame{ .origin = node, .seq = self.bum_seq[node], .ingress_segment = ingress_segment, .tag = tag }).encode(&buf);
        self.bum_seen[node * self.node_count + node] |= @as(u64, 1) << @intCast(self.bum_seq[node]);
        try DfElect.floodFrom(sim, node, &buf, null);
    }
};

// ── tests: the positive control proves the checker has teeth ────────────

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
    try testing.expect(res.after <= res.before);
    // netsim audit F6: the control breaks from its own traffic alone, so the
    // true minimal reproducer is the EMPTY fault set.
    try testing.expectEqual(@as(usize, 0), res.after);

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
    try testing.expectEqual(@as(?usize, 0), segmentIndexOf(4));
    try testing.expectEqual(@as(?usize, 1), segmentIndexOf(7));
    try testing.expectEqual(@as(?usize, null), segmentIndexOf(CORE0));
    for (segments) |s| try s.validate();
}

// ── the real DfElect ──────────────────────────────────────────────────────

const algorithms = [_]types.Algorithm{ .modulo, .hrw, .preference, .preference_lowest };

/// The final role table must be the RFC assignment over all members: one
/// holder per tag, the one `settledDf` names.
fn expectSettled(df: *const DfElect, algorithm: types.Algorithm) !void {
    for (segments) |seg| for (seg.tags) |tag| {
        var buf: [types.max_members]NodeId = undefined;
        const h = df.holders(seg, tag, &buf);
        try testing.expectEqual(@as(usize, 1), h.len);
        try testing.expectEqual(settledDf(algorithm, seg, tag), h[0]);
    };
}

/// The first frame a segment should have received and did not
/// (`checks.firstUnexplainedLoss` with this module's windows).
fn firstLoss(df: *const DfElect, case: netsim.Case, links: []const netsim.Link, trace: []const netsim.FaultEvent) !?checks.Loss {
    return checks.firstUnexplainedLoss(testing.allocator, df.originated.items, &df.delivery, &segments, trace, links, NODE_N, checks.maxZeroDfWindow(df.cfg), checks.maxDuplicateWindow(df.cfg), case.until);
}

fn worstZeroDf(df: *const DfElect, case: netsim.Case, trace: []const netsim.FaultEvent) !Time {
    const topo = try netsim.snapshotTopo(testing.allocator, case);
    defer testing.allocator.free(topo.links);
    return (try checks.worstZeroDfWindow(testing.allocator, df.transitions.items, &segments, trace, topo.links, NODE_N, case.until)).len;
}

fn expectNoLoss(df: *const DfElect, case: netsim.Case, trace: []const netsim.FaultEvent) !void {
    const topo = try netsim.snapshotTopo(testing.allocator, case);
    defer testing.allocator.free(topo.links);
    if (try firstLoss(df, case, topo.links, trace)) |l| {
        std.debug.print("lost: frame {x} tag {} for segment {} sent at t={}\n", .{ l.frame_id, l.tag, l.segment, l.time });
        return error.UnexplainedLoss;
    }
}

test "real: fault-free — no duplicate at all, settles on the RFC assignment, startup zero-DF within the bound" {
    const gpa = testing.allocator;
    for (algorithms) |alg| {
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        df.delivery.duplicates_fatal = true;
        const case = netsim.Case{ .seed = 7, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        const r = try netsim.replay(gpa, case, &.{}, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
        try expectSettled(&df, alg);
        const worst = try worstZeroDf(&df, case, &.{});
        try testing.expect(worst > 0); // startup is a real window: df_wait is observed
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
        try testing.expect(df.delivery.delivered.count() > 0);
        try expectNoLoss(&df, case, &.{});
    }
}

test "real: both RFC algorithms really differ on this segment (the HRW path is not the modulo path)" {
    var differ: usize = 0;
    for (SEG_A.tags) |tag| {
        if (settledDf(.modulo, SEG_A, tag) != settledDf(.hrw, SEG_A, tag)) differ += 1;
    }
    try testing.expect(differ > 0);
}

test "negative control: df_wait = 0 duplicates at startup, with no fault to explain it" {
    const gpa = testing.allocator;
    var df = try DfElect.initUnchecked(gpa, NODE_N, .{ .df_wait = 0 }, false);
    defer df.deinit(gpa);
    const case = netsim.Case{ .seed = 7, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    // Every member's first view holds only itself, so each names itself DF
    // for every tag and, without the wait, takes the roles at once.
    try testing.expect(df.delivery.duplicates.items.len > 0);
    try testing.expect(checks.firstUnexplainedDuplicate(df.delivery.duplicates.items, &.{}, checks.maxDuplicateWindow(df.cfg)) != null);
    // The config check refuses the same setting.
    try testing.expectError(error.InvalidConfig, DfElect.init(gpa, NODE_N, .{ .df_wait = 0 }));
}

test "real: failover — the DF of a tag crashes, a survivor takes over within the bound; after restart the RFC assignment returns" {
    const gpa = testing.allocator;
    for (algorithms) |alg| {
        const victim = settledDf(alg, SEG_A, 10);
        const trace = [_]netsim.FaultEvent{
            .{ .time = 400, .kind = .{ .crash_node = .{ .node = victim } } },
            .{ .time = 1000, .kind = .{ .restart_node = .{ .node = victim } } },
        };
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        df.delivery.duplicates_fatal = true; // no heal race here: a restart starts blocked
        const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

        // A survivor held tag 10 while the victim was down.
        var took_over = false;
        for (df.transitions.items) |t| {
            if (t.segment == SEG_A.id and t.tag == 10 and t.is_df and t.node != victim and t.time > 400 and t.time < 1000) took_over = true;
        }
        try testing.expect(took_over);
        const worst = try worstZeroDf(&df, case, &trace);
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
        try expectNoLoss(&df, case, &trace);
        try expectSettled(&df, alg);
    }
}

test "real: partition and heal — each side serves its own members, duplicates only right after the heal" {
    const gpa = testing.allocator;
    // Cut {core0, A3} from the rest: segment A splits into {3} and {4, 5}.
    const cut = [_]NodeId{ CORE0, 3 };
    const trace = [_]netsim.FaultEvent{
        .{ .time = 300, .kind = .{ .partition = .{ .id = 1, .cut = &cut } } },
        .{ .time = 900, .kind = .{ .heal = .{ .id = 1 } } },
    };
    for (algorithms) |alg| {
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        const case = netsim.Case{ .seed = 5, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
        try testing.expectEqual(@as(?checks.Duplicate, null), checks.firstUnexplainedDuplicate(df.delivery.duplicates.items, &trace, checks.maxDuplicateWindow(df.cfg)));
        const worst = try worstZeroDf(&df, case, &trace);
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
        // During the partition node 3 carved every tag for itself.
        var isolated_took_all = true;
        for (SEG_A.tags) |tag| {
            var held = false;
            for (df.transitions.items) |t| {
                if (t.segment == SEG_A.id and t.tag == tag and t.node == 3 and t.is_df and t.time < 900) held = true;
            }
            if (!held) isolated_took_all = false;
        }
        try testing.expect(isolated_took_all);
        try expectNoLoss(&df, case, &trace);
        try expectSettled(&df, alg);
    }
}

test "real: a member cut off INBOUND (it hears nothing) gives its roles up and the segment keeps receiving" {
    // Found by review 2026-10-01: with only the view consensus, member 4 kept
    // every role of segment A (its view held only itself, and the peers that
    // still heard it deferred to that view) while it received no frame at all
    // — every network-side frame for segment A was lost for good, and the
    // zero-DF check, which counts role holders, saw nothing wrong.
    const gpa = testing.allocator;
    const cuts = [_]netsim.Link{ .{ .a = CORE1, .b = 4 }, .{ .a = CORE2, .b = 7 } };
    for (cuts) |cut| for (algorithms) |alg| {
        const trace = [_]netsim.FaultEvent{.{ .time = 200, .kind = .{ .link_down = cut } }};
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        const case = netsim.Case{ .seed = 5, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
        try expectNoLoss(&df, case, &trace);
        try testing.expectEqual(@as(?checks.Duplicate, null), checks.firstUnexplainedDuplicate(df.delivery.duplicates.items, &trace, checks.maxDuplicateWindow(df.cfg)));
        const worst = try worstZeroDf(&df, case, &trace);
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
        // The deaf member ends with no role.
        for (segments) |seg| if (seg.indexOf(cut.b) != null) for (seg.tags) |tag| {
            var buf: [types.max_members]NodeId = undefined;
            for (df.holders(seg, tag, &buf)) |h| try testing.expect(h != cut.b);
        };
    };
}

test "real: a member cut off OUTBOUND (nobody hears it) yields to the peers' carving, no duplicates" {
    const gpa = testing.allocator;
    const cuts = [_]netsim.Link{ .{ .a = 4, .b = CORE1 }, .{ .a = 7, .b = CORE2 } };
    for (cuts) |cut| for (algorithms) |alg| {
        const trace = [_]netsim.FaultEvent{.{ .time = 200, .kind = .{ .link_down = cut } }};
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        df.delivery.duplicates_fatal = true;
        const case = netsim.Case{ .seed = 5, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
        try expectNoLoss(&df, case, &trace);
        const worst = try worstZeroDf(&df, case, &trace);
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
    };
}

test "known limit: a one-way failure deeper in the core can still black-hole a segment" {
    // core1 stops hearing core0 and core2 but they still hear it. Member 4
    // (behind core1) hears core1, so it is not isolated; it hears no peer, so
    // it claims every tag of segment A and receives no frame from core0.
    // Members 3 and 5 still hear 4, whose view declares only itself, and the
    // consensus makes them defer to it. Telling this from the outbound case
    // (where deferring is right) needs the directed fabric graph, which a
    // Hello flood carrying segment views alone does not give (SPEC Backlog).
    // This test pins the limit; it flips the day that is built.
    const gpa = testing.allocator;
    for (algorithms) |alg| {
        const trace = [_]netsim.FaultEvent{
            .{ .time = 200, .kind = .{ .link_down = .{ .a = CORE0, .b = CORE1 } } },
            .{ .time = 200, .kind = .{ .link_down = .{ .a = CORE2, .b = CORE1 } } },
        };
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        const case = netsim.Case{ .seed = 5, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        _ = try netsim.replay(gpa, case, &trace, null);
        const topo = try netsim.snapshotTopo(gpa, case);
        defer gpa.free(topo.links);
        const lost = (try firstLoss(&df, case, topo.links, &trace)).?;
        try testing.expectEqual(SEG_A.id, lost.segment);
        try testing.expectEqual(@as(usize, 0), df.delivery.duplicates.items.len);
    }
}

/// Print the fault schedule and one `<segment, tag>`'s DF transitions — the
/// reproducer a failing sweep leaves behind.
fn dumpReproducer(trace: []const netsim.FaultEvent, transitions: []const checks.DfTransition, segment: SegmentId, tag: Tag) void {
    for (trace) |e| std.debug.print("  fault t={} {any}\n", .{ e.time, e.kind });
    for (transitions) |t| {
        if (t.segment == segment and t.tag == tag) std.debug.print("  df t={} node {} -> {}\n", .{ t.time, t.node, t.is_df });
    }
}

/// The fuzz sweep's verdict for one run, plus the worst numbers it saw.
const SweepStats = struct {
    runs: usize = 0,
    duplicates: usize = 0,
    worst_dup_delay: Time = 0,
    worst_zero: Time = 0,
};

fn dupDelay(d: checks.Duplicate, trace: []const netsim.FaultEvent) Time {
    var best: Time = std.math.maxInt(Time);
    for (trace) |e| switch (e.kind) {
        .heal, .link_up, .restart_node => if (e.time <= d.time) {
            best = @min(best, d.time - e.time);
        },
        else => {},
    };
    return best;
}

test "real: fuzzed partitions, cuts, crashes, clock jumps — split-horizon never, duplicates only in the heal window, zero-DF bounded" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const seeds: u64 = if (@import("builtin").mode == .debug) 120 else 400;
    for (algorithms) |alg| {
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
        const topo = try netsim.snapshotTopo(gpa, template);
        defer gpa.free(topo.links);
        var stats: SweepStats = .{};
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            var case = template;
            case.seed = seed;
            var gr = try netsim.run(gpa, case, .{});
            defer gr.trace.deinit();
            const trace = gr.trace.events;
            stats.runs += 1;
            if (gr.result.outcome != .ok) {
                std.debug.print("df-elect {s}: seed {} tripped {s}\n", .{ @tagName(alg), seed, if (gr.result.violation) |v| @errorName(v.err) else "a non-ok outcome" });
                return error.HardInvariantViolated;
            }
            const window = checks.maxDuplicateWindow(df.cfg);
            if (checks.firstUnexplainedDuplicate(df.delivery.duplicates.items, trace, window)) |d| {
                std.debug.print("df-elect {s}: seed {} unexplained duplicate at t={} seg {} tag {}\n", .{ @tagName(alg), seed, d.time, d.segment, d.tag });
                dumpReproducer(trace, df.transitions.items, d.segment, d.tag);
                return error.UnexplainedDuplicate;
            }
            for (df.delivery.duplicates.items) |d| stats.worst_dup_delay = @max(stats.worst_dup_delay, dupDelay(d, trace));
            stats.duplicates += df.delivery.duplicates.items.len;
            const zw = try checks.worstZeroDfWindow(gpa, df.transitions.items, &segments, trace, topo.links, NODE_N, case.until);
            stats.worst_zero = @max(stats.worst_zero, zw.len);
            if (zw.len > checks.maxZeroDfWindow(df.cfg)) {
                std.debug.print("df-elect {s}: seed {} zero-DF window {} (seg {} tag {} from t={}) > bound {}\n", .{ @tagName(alg), seed, zw.len, zw.segment, zw.tag, zw.start, checks.maxZeroDfWindow(df.cfg) });
                dumpReproducer(trace, df.transitions.items, zw.segment, zw.tag);
                return error.ZeroDfWindowExceeded;
            }
            if (try firstLoss(&df, case, topo.links, trace)) |l| {
                std.debug.print("df-elect {s}: seed {} lost frame {x} (tag {}) for segment {} sent at t={}\n", .{ @tagName(alg), seed, l.frame_id, l.tag, l.segment, l.time });
                dumpReproducer(trace, df.transitions.items, l.segment, l.tag);
                return error.UnexplainedLoss;
            }
            try testing.expectEqual(@as(u64, 0), df.malformed_dropped);
        }
        // Measured 2026-10-01 with core isolation, per algorithm: Debug (120
        // seeds) 7 duplicates, worst 44 ticks after a heal (bound 100), worst
        // zero-DF 362-363 ticks (bound 470); ReleaseSafe (400 seeds) 23-24
        // duplicates, worst 44, worst zero-DF 390-409. Not printed: the test
        // lanes treat any stderr on a passing run as a FAIL. The bounds are asserted per run above;
        // these keep the sweep honest: the heal race really happens.
        try testing.expect(stats.duplicates > 0);
        try testing.expect(stats.worst_dup_delay <= checks.maxDuplicateWindow(df.cfg));
        try testing.expect(stats.worst_zero > 0);
    }
}

// ── malformed inbound frames: dropped, counted, never fatal ─────────────────
//
// `origin` indexes a NODE_N*NODE_N array and `seq` is a shift into a u64
// bitmask, so a PERFECTLY WELL-FORMED frame carrying `origin = 0xFFFFFFFF` or
// `seq = 64` was an out-of-bounds write / a `@intCast` panic — neither of
// which a bounds-checked decoder can catch. Those checks live in the handlers.

fn feedFrames(df: *DfElect, payloads: []const []const u8) !void {
    const gpa = testing.allocator;
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, df.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scenario(&sim);
    const p = df.protocol();
    // Node 3 (a member of segment A) receiving from its core neighbour.
    for (payloads) |payload| try p.onMessageFn(p.ctx, &sim, 3, CORE0, payload);
}

test "malformed inbound frames are dropped and counted, and never crash the node" {
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);

    var wild_origin: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 0xFFFF_FFFF, .seq = 1, .segment = SEG_A.id, .view = 1 }).encode(&wild_origin);
    var wild_bum_origin: [types.BumFrame.wire_len]u8 = undefined;
    (types.BumFrame{ .origin = 0xFFFF_FFFF, .seq = 1, .ingress_segment = types.no_ingress, .tag = 10 }).encode(&wild_bum_origin);
    // seq = 64 is exactly the first shift amount a u64 bitmask cannot hold.
    var wild_seq: [types.BumFrame.wire_len]u8 = undefined;
    (types.BumFrame{ .origin = 1, .seq = 64, .ingress_segment = types.no_ingress, .tag = 10 }).encode(&wild_seq);

    const cases = [_][]const u8{
        &.{}, // empty: tagOf out of bounds
        &.{7}, // undefined tag byte: "invalid enum value"
        &.{@backingInt(types.MsgTag.hello)}, // the reported reproducer
        &.{@backingInt(types.MsgTag.bum)},
        &wild_origin,
        &wild_bum_origin,
        &wild_seq,
    };
    try feedFrames(&df, &cases);

    try testing.expectEqual(@as(u64, cases.len), df.malformed_dropped);
    for (df.hello_last_seq) |s| try testing.expectEqual(@as(u32, 0), s);
    for (df.bum_seen) |s| try testing.expectEqual(@as(u64, 0), s);
}

test "a well-formed frame is still accepted (the guard is not over-tight)" {
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);

    var buf: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 4, .seq = 9, .segment = SEG_A.id, .view = 0b111 }).encode(&buf);
    try feedFrames(&df, &.{&buf});

    try testing.expectEqual(@as(u64, 0), df.malformed_dropped);
    try testing.expectEqual(@as(u32, 9), df.hello_last_seq[3 * NODE_N + 4]);
    try testing.expect(df.last_seen[3 * NODE_N + 4] != null);
    try testing.expectEqual(@as(u32, 0b111), df.last_view[3 * NODE_N + 4]);
}

test "a Hello naming another segment does not make its origin a member" {
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    var buf: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 6, .seq = 1, .segment = SEG_B.id, .view = 0b11 }).encode(&buf);
    try feedFrames(&df, &.{&buf});
    try testing.expectEqual(@as(?Time, null), df.last_seen[3 * NODE_N + 6]);
}

// ── found by the 2026-10-01 mutation run: guards no test had pinned ─────────

test "a timer armed before a crash does not double the Hello chain after the restart" {
    // Member 3's Hello timer is due at t=150; it crashes at 120 and restarts
    // at 130 (new chain: 180, 230, …). The old timer still comes due at 150,
    // after the restart; without the start-epoch check it would run a second
    // chain beside the new one.
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    const trace = [_]netsim.FaultEvent{
        .{ .time = 120, .kind = .{ .crash_node = .{ .node = 3 } } },
        .{ .time = 130, .kind = .{ .restart_node = .{ .node = 3 } } },
    };
    const case = netsim.Case{ .seed = 1, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
    _ = try netsim.replay(gpa, case, &trace, null);
    // Two Hellos before the crash (50, 100), then one per period from 180.
    const one_chain: u32 = 2 + (UNTIL - 180) / DEFAULT_CFG.hello_period + 1;
    try testing.expectEqual(one_chain, df.hello_seq[3]);
}

test "a Hello's view bits past the member list are dropped" {
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    var buf: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 4, .seq = 1, .segment = SEG_A.id, .view = 0xFFFF_FFFF }).encode(&buf);
    try feedFrames(&df, &.{&buf});
    try testing.expectEqual(@as(u32, 0b111), df.last_view[3 * NODE_N + 4]);
}

test "a member's Hello that names another segment, or none, does not count as its peer's" {
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    var other: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 4, .seq = 1, .segment = SEG_B.id, .view = 0b111 }).encode(&other);
    var none: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 5, .seq = 1, .segment = types.no_segment, .view = 0b111 }).encode(&none);
    try feedFrames(&df, &.{ &other, &none });
    try testing.expectEqual(@as(?Time, null), df.last_seen[3 * NODE_N + 4]);
    try testing.expectEqual(@as(?Time, null), df.last_seen[3 * NODE_N + 5]);
    // Both still prove the fabric is audible.
    try testing.expect(df.last_heard[3] != null);
}

test "the config check refuses df_wait == hello_period, the edge the wait must clear" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, DfElect.init(gpa, NODE_N, .{ .hello_period = 50, .df_wait = 50 }));
    var ok = try DfElect.init(gpa, NODE_N, .{ .hello_period = 50, .df_wait = 51 });
    ok.deinit(gpa);
}

// ── RFC 8584 section 4, RFC 9785, lifetime ───────────────────────────────

fn holderOf(df: *const DfElect, seg: EdgeSegment, tag: Tag) !NodeId {
    var buf: [types.max_members]NodeId = undefined;
    const h = df.holders(seg, tag, &buf);
    try testing.expectEqual(@as(usize, 1), h.len);
    return h[0];
}

test "AC-influenced DF: a member whose AC for one tag is down drops out of that tag only, and returns when it is up" {
    const gpa = testing.allocator;
    // Preference with default values: node 3 (least address) is DF of every tag.
    // Modulo: tag 10 mod 3 = 1, node 4 is its DF; pruning 4 leaves {3, 5}, 10 mod 2 = 0.
    const cases = [_]struct { alg: types.Algorithm, victim: NodeId, expect_down: NodeId }{
        .{ .alg = .preference, .victim = 3, .expect_down = 4 },
        .{ .alg = .modulo, .victim = 4, .expect_down = 3 },
        .{ .alg = .hrw, .victim = settledDf(.hrw, SEG_A, 10), .expect_down = 0 },
    };
    for (cases) |c| {
        const events = [_]types.AcEvent{.{ .time = 400, .node = c.victim, .tag_index = 0, .down = true }};
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = c.alg, .ac_events = &events });
        defer df.deinit(gpa);
        const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = df.protocol(), .until = 1000 };
        const r = try netsim.replay(gpa, case, &.{}, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
        // Tag 10 (index 0) left the victim; tag 11 did not move.
        try testing.expect(try holderOf(&df, SEG_A, 10) != c.victim);
        if (c.expect_down != 0) try testing.expectEqual(c.expect_down, try holderOf(&df, SEG_A, 10));
        try testing.expectEqual(settledDf(c.alg, SEG_A, 11), try holderOf(&df, SEG_A, 11));
        try testing.expectEqual(@as(usize, 0), df.delivery.duplicates.items.len);
    }
    // Repair: the AC comes back and the RFC assignment returns.
    const events = [_]types.AcEvent{
        .{ .time = 400, .node = 3, .tag_index = 0, .down = true },
        .{ .time = 800, .node = 3, .tag_index = 0, .down = false },
    };
    var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = .preference, .ac_events = &events });
    defer df.deinit(gpa);
    const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = df.protocol(), .until = 1400 };
    _ = try netsim.replay(gpa, case, &.{}, null);
    try expectSettled(&df, .preference);
}

test "Don't Preempt: a returning higher-preference member does not take the role back; without DP it does" {
    const gpa = testing.allocator;
    const trace = [_]netsim.FaultEvent{
        .{ .time = 500, .kind = .{ .crash_node = .{ .node = 3 } } },
        .{ .time = 1100, .kind = .{ .restart_node = .{ .node = 3 } } },
    };
    for ([_]bool{ true, false }) |dp| {
        const prefs = [_]types.NodePref{
            .{ .node = 3, .pref = 500, .dp = dp },
            .{ .node = 4, .pref = 100, .dp = dp },
            .{ .node = 5, .pref = 50, .dp = dp },
        };
        for ([_]types.Algorithm{ .preference, .preference_lowest }) |alg| {
            var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg, .prefs = &prefs });
            defer df.deinit(gpa);
            const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = df.protocol(), .until = 2200 };
            _ = try netsim.replay(gpa, case, &trace, null);
            // Highest: 3 first, 4 while 3 is down. Lowest: 5 first (50), and
            // the crash of 3 changes nothing, so the returning 3 (500) is not
            // a better choice either way; check the highest direction only.
            if (alg == .preference) {
                try testing.expectEqual(if (dp) @as(NodeId, 4) else 3, try holderOf(&df, SEG_A, 10));
            } else {
                try testing.expectEqual(@as(NodeId, 5), try holderOf(&df, SEG_A, 10));
            }
        }
    }
}

test "tag policy: a tag range runs another algorithm than the segment default" {
    const gpa = testing.allocator;
    const policy = [_]types.TagPolicy{.{ .first = 12, .last = 13, .algorithm = .preference }};
    var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = .modulo, .tag_policy = &policy });
    defer df.deinit(gpa);
    const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
    _ = try netsim.replay(gpa, case, &.{}, null);
    for (SEG_A.tags) |tag| {
        const alg = types.algorithmFor(df.cfg, tag);
        try testing.expectEqual(settledDf(alg, SEG_A, tag), try holderOf(&df, SEG_A, tag));
    }
    // 12 mod 3 = 0 is also node 3, so pick the tags where the two differ.
    try testing.expectEqual(@as(NodeId, 3), try holderOf(&df, SEG_A, 13)); // preference: least address
    try testing.expect(settledDf(.modulo, SEG_A, 13) != 3);
}

test "lifetime: a Hello advertising lifetime 0 purges its origin at once; a longer lifetime outlives stale_after" {
    const gpa = testing.allocator;
    var df = try DfElect.init(gpa, NODE_N, DEFAULT_CFG);
    defer df.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, df.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scenario(&sim);
    const p = df.protocol();
    var buf: [types.Hello.wire_len]u8 = undefined;
    (types.Hello{ .origin = 4, .seq = 1, .segment = SEG_A.id, .view = 0b111, .lifetime = 1000 }).encode(&buf);
    try p.onMessageFn(p.ctx, &sim, 3, CORE0, &buf);
    try testing.expectEqual(@as(?Time, 1000), df.last_seen[3 * NODE_N + 4]);
    (types.Hello{ .origin = 4, .seq = 2, .segment = SEG_A.id, .view = 0b111, .lifetime = 0 }).encode(&buf);
    try p.onMessageFn(p.ctx, &sim, 3, CORE0, &buf);
    try testing.expectEqual(@as(?Time, null), df.last_seen[3 * NODE_N + 4]);
}
