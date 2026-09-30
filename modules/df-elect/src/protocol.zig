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

const HELLO_TIMER: u64 = 0;
const BUM_CE_TIMER: u64 = 1;
const BUM_NET_TIMER: u64 = 2;

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
    /// last_seen[node*node_count + member] = `node`'s local time when it last
    /// accepted a fresh Hello from `member` of its own segment.
    last_seen: []?Time,
    /// last_view[node*node_count + member] = the `Hello.view` `member` last
    /// advertised to `node` (meaningful while `last_seen` says alive).
    last_view: []u32,
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
        gpa.free(self.roles);
        gpa.free(self.hello_seq);
        gpa.free(self.bum_seq);
        gpa.free(self.epoch);
        gpa.free(self.tag_cursor);
        self.delivery.deinit(gpa);
        self.transitions.deinit(gpa);
        self.* = undefined;
    }

    fn clearState(self: *DfElect) void {
        @memset(self.hello_last_seq, 0);
        @memset(self.bum_seen, 0);
        @memset(self.last_seen, null);
        @memset(self.last_view, 0);
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
        self.malformed_dropped = 0;
    }

    /// Start or RESTART: a restarted member comes back with an empty view and
    /// no role (RFC 7432 §8.5 step 2: a PE starts blocked and waits), so any
    /// role it held before the crash is logged as given up now.
    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        self.epoch[node] += 1;
        const e = self.epoch[node];
        if (segmentIndexOf(node)) |si| {
            const seg = segments[si];
            for (seg.tags, 0..) |tag, ti| {
                const r = &self.roles[node * MAX_TAGS + ti];
                if (r.is_df) self.logTransition(sim, seg, tag, node, false);
                r.* = .{};
            }
            @memset(self.last_seen[node * self.node_count ..][0..self.node_count], null);
            @memset(self.last_view[node * self.node_count ..][0..self.node_count], 0);
            try sim.setTimer(node, self.cfg.hello_period, timerId(HELLO_TIMER, e));
            if (seg.members[0].node == node) try sim.setTimer(node, self.cfg.bum_period, timerId(BUM_CE_TIMER, e));
        }
        if (node == NETWORK_ORIGIN) try sim.setTimer(node, self.cfg.bum_period, timerId(BUM_NET_TIMER, e));
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const e = self.epoch[node];
        if (timer_id >> 8 != e) return; // armed before a restart
        switch (timer_id & 0xff) {
            HELLO_TIMER => if (segmentIndexOf(node)) |si| {
                try self.originateHello(sim, node, si);
                self.refreshRoles(sim, node, si); // staleness is only noticed on a tick
                try sim.setTimer(node, self.cfg.hello_period, timerId(HELLO_TIMER, e));
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

    fn originateHello(self: *DfElect, sim: *Sim, node: NodeId, si: usize) anyerror!void {
        const seg = segments[si];
        self.hello_seq[node] += 1;
        var buf: [types.Hello.wire_len]u8 = undefined;
        const view = self.viewOf(sim, node, si);
        (types.Hello{ .origin = node, .seq = self.hello_seq[node], .segment = seg.id, .view = view }).encode(&buf);
        self.hello_last_seq[node * self.node_count + node] = self.hello_seq[node];
        try floodFrom(sim, node, &buf, null);
    }

    fn originateBum(self: *DfElect, sim: *Sim, node: NodeId, ingress_segment: SegmentId, tag: Tag) anyerror!void {
        self.bum_seq[node] += 1;
        std.debug.assert(self.bum_seq[node] < 64); // see `bum_seen`
        var buf: [types.BumFrame.wire_len]u8 = undefined;
        (types.BumFrame{ .origin = node, .seq = self.bum_seq[node], .ingress_segment = ingress_segment, .tag = tag }).encode(&buf);
        self.bum_seen[node * self.node_count + node] |= @as(u64, 1) << @intCast(self.bum_seq[node]);
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

        if (segmentIndexOf(node)) |si| {
            const seg = segments[si];
            if (h.origin != node and h.segment == seg.id and seg.indexOf(h.origin) != null) {
                self.last_seen[idx] = localTime(sim, node);
                // Bits past the member list mean nothing; drop them.
                self.last_view[idx] = h.view & memberMask(seg);
                self.refreshRoles(sim, node, si);
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
                self.refreshRoles(sim, node, si);
                if (self.roles[node * MAX_TAGS + ti].is_df and election.allowForward(f.ingress_segment, seg.id)) {
                    try self.delivery.recordDelivery(self.gpa, sim.timeNow(), seg.id, f.tag, f.id(), f.ingress_segment);
                }
            }
        }
        try floodFrom(sim, node, payload, from);
    }

    /// Is `member` alive in `node`'s view (itself always is)?
    fn sees(self: *const DfElect, now: Time, node: NodeId, member: NodeId) bool {
        if (member == node) return true;
        const seen = self.last_seen[node * self.node_count + member] orelse return false;
        return now -| seen <= self.cfg.stale_after;
    }

    /// `node`'s current view of its segment as a member bitmask (the value
    /// its Hellos advertise).
    fn viewOf(self: *const DfElect, sim: *const Sim, node: NodeId, si: usize) u32 {
        const now = localTime(sim, node);
        var mask: u32 = 0;
        for (segments[si].members, 0..) |m, i| {
            if (self.sees(now, node, m.node)) mask |= @as(u32, 1) << @intCast(i);
        }
        return mask;
    }

    /// Re-run the election for every tag of `node`'s segment.
    ///
    /// `node` is NAMED for a tag when the DF function over its own view picks
    /// it AND the view each peer it sees last advertised picks it too. The
    /// second half is what makes a one-way failure safe: a member whose
    /// outbound path died still hears its peers, but they no longer see it
    /// and carve its tags among themselves; their advertised views say so,
    /// and it yields instead of delivering alongside them. (netsim's
    /// `link_down` is directional, and the fuzzer found exactly this.) EVPN
    /// gets the same property from BGP sessions being two-way.
    fn refreshRoles(self: *DfElect, sim: *Sim, node: NodeId, si: usize) void {
        const seg = segments[si];
        const now = localTime(sim, node);
        const my_view = self.viewOf(sim, node, si);
        var mine_buf: [types.max_members]Member = undefined;
        const mine = membersIn(seg, my_view, &mine_buf);
        for (seg.tags, 0..) |tag, ti| {
            var named = election.designatedForwarder(self.cfg.algorithm, seg.esi, mine, tag) == node;
            if (named) for (seg.members, 0..) |peer, pi| {
                if (peer.node == node or my_view & (@as(u32, 1) << @intCast(pi)) == 0) continue;
                var theirs_buf: [types.max_members]Member = undefined;
                const theirs = membersIn(seg, self.last_view[node * self.node_count + peer.node], &theirs_buf);
                if (election.designatedForwarder(self.cfg.algorithm, seg.esi, theirs, tag) != node) {
                    named = false;
                    break;
                }
            };
            const r = &self.roles[node * MAX_TAGS + ti];
            const next = election.stepRole(r.*, named, now, self.cfg.df_wait);
            if (next.is_df != r.is_df) self.logTransition(sim, seg, tag, node, next.is_df);
            r.* = next;
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

const algorithms = [_]types.Algorithm{ .modulo, .hrw, .preference };

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
        const worst = (try checks.worstZeroDfWindow(gpa, df.transitions.items, &segments, &.{}, NODE_N, UNTIL)).len;
        try testing.expect(worst > 0); // startup is a real window: df_wait is observed
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
        try testing.expect(df.delivery.delivered.count() > 0);
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
        const worst = (try checks.worstZeroDfWindow(gpa, df.transitions.items, &segments, &trace, NODE_N, UNTIL)).len;
        try testing.expect(worst <= checks.maxZeroDfWindow(df.cfg));
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
        const worst = (try checks.worstZeroDfWindow(gpa, df.transitions.items, &segments, &trace, NODE_N, UNTIL)).len;
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
        try expectSettled(&df, alg);
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
    const seeds: u64 = if (@import("builtin").mode == .Debug) 120 else 400;
    for (algorithms) |alg| {
        var df = try DfElect.init(gpa, NODE_N, .{ .algorithm = alg });
        defer df.deinit(gpa);
        const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = df.protocol(), .until = UNTIL };
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
            const zw = try checks.worstZeroDfWindow(gpa, df.transitions.items, &segments, trace, NODE_N, case.until);
            stats.worst_zero = @max(stats.worst_zero, zw.len);
            if (zw.len > checks.maxZeroDfWindow(df.cfg)) {
                std.debug.print("df-elect {s}: seed {} zero-DF window {} (seg {} tag {} from t={}) > bound {}\n", .{ @tagName(alg), seed, zw.len, zw.segment, zw.tag, zw.start, checks.maxZeroDfWindow(df.cfg) });
                dumpReproducer(trace, df.transitions.items, zw.segment, zw.tag);
                return error.ZeroDfWindowExceeded;
            }
            try testing.expectEqual(@as(u64, 0), df.malformed_dropped);
        }
        std.debug.print("MEASURED df-elect {s}: {} runs, {} duplicates, worst duplicate {} ticks after a heal (bound {}), worst zero-DF {} ticks (bound {})\n", .{
            @tagName(alg),                     stats.runs,       stats.duplicates,               stats.worst_dup_delay,
            checks.maxDuplicateWindow(df.cfg), stats.worst_zero, checks.maxZeroDfWindow(df.cfg),
        });
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
        &.{@intFromEnum(types.MsgTag.hello)}, // the reported reproducer
        &.{@intFromEnum(types.MsgTag.bum)},
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
