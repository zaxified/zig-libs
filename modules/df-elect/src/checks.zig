// SPDX-License-Identifier: MIT

//! checks — the invariants, and how each one is checked:
//!
//!  1. **Split-horizon, zero tolerance, LIVE** via netsim's
//!     `Protocol.checkFn`: a frame delivered back into the segment it
//!     ingressed from halts the run with the exact reproducer trace
//!     (`error.SplitHorizonViolation`). See `DeliveryChecker`.
//!  2. **Duplicates, bounded, POST-RUN**: the checker records every second
//!     delivery of a frame to a segment with its time. With failover a
//!     duplicate is legal only in the heal race (`election.zig` module doc),
//!     so `firstUnexplainedDuplicate` requires each one to follow a
//!     connectivity-restoring fault (heal, link up, node restart) within
//!     `maxDuplicateWindow`. The positive control and the fault-free runs use
//!     `duplicates_fatal`, which turns any duplicate into a live
//!     `error.DuplicateDelivery`.
//!  3. **Zero-DF, bounded, POST-RUN**: `worstZeroDfWindow` rebuilds, per
//!     `<segment, tag>`, how many SERVING members (up, and reachable from
//!     some other live node) hold the role over time and returns the
//!     longest stretch with none while at least one member was serving; the
//!     caller compares it with `maxZeroDfWindow`. Two DFs at once is not
//!     measured as bad: across a partition it is the design (each side
//!     serves its own component), and where it matters — one frame reaching
//!     both — it shows up as a duplicate under (2).
//!  4. **Lost frames, POST-RUN**: `firstUnexplainedLoss` checks traffic, not
//!     roles: every frame put on the fabric must reach every segment owed it,
//!     unless a fault explains the loss or no member was reachable. (3) alone
//!     once passed a run in which a deaf member held every role of its
//!     segment and the segment received nothing.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");

const NodeId = netsim.NodeId;
const Time = netsim.Time;
const Allocator = std.mem.Allocator;
const SegmentId = types.SegmentId;
const Tag = types.Tag;
const EdgeSegment = types.EdgeSegment;
const ElectConfig = types.ElectConfig;

// ── 1 + 2. DeliveryChecker ─────────────────────────────────────────────────

pub const Duplicate = struct {
    time: Time,
    segment: SegmentId,
    tag: Tag,
    frame_id: u64,
};

/// Shared verbatim by the real `protocol.DfElect` and the positive-control
/// `protocol.BrokenAlwaysDf`, so a violation either trips is provably the
/// same check.
pub const DeliveryChecker = struct {
    const Key = struct { frame_id: u64, segment: u64 };

    delivered: std.AutoHashMapUnmanaged(Key, void) = .empty,
    duplicates: std.ArrayList(Duplicate) = .empty,
    /// When set, a duplicate is a live violation like split-horizon.
    duplicates_fatal: bool = false,
    /// Sticky: set the instant a bad delivery is observed; `check()` turns it
    /// into a `netsim.Protocol.checkFn` error on that same event (netsim's
    /// own `LoopyForward` pattern: accumulate in the handler, assert in
    /// `check`).
    violation: ?anyerror = null,

    pub fn deinit(self: *DeliveryChecker, gpa: Allocator) void {
        self.delivered.deinit(gpa);
        self.duplicates.deinit(gpa);
        self.* = undefined;
    }

    pub fn reset(self: *DeliveryChecker) void {
        self.delivered.clearRetainingCapacity();
        self.duplicates.clearRetainingCapacity();
        self.violation = null;
    }

    /// Record a BUM frame's delivery to `segment` at `time`. First violation
    /// wins and stays sticky.
    pub fn recordDelivery(
        self: *DeliveryChecker,
        gpa: Allocator,
        time: Time,
        segment: SegmentId,
        tag: Tag,
        frame_id: u64,
        ingress_segment: SegmentId,
    ) Allocator.Error!void {
        if (self.violation != null) return;
        if (ingress_segment == segment) {
            self.violation = error.SplitHorizonViolation;
            return;
        }
        const gop = try self.delivered.getOrPut(gpa, .{ .frame_id = frame_id, .segment = segment });
        if (gop.found_existing) {
            try self.duplicates.append(gpa, .{ .time = time, .segment = segment, .tag = tag, .frame_id = frame_id });
            if (self.duplicates_fatal) self.violation = error.DuplicateDelivery;
        }
    }

    /// `netsim.Protocol.checkFn` body.
    pub fn check(self: *const DeliveryChecker) anyerror!void {
        if (self.violation) |e| return e;
    }
};

/// How long after connectivity is restored a duplicate may still happen: the
/// next Hello has to be sent (up to `hello_period`) and to cross the fabric,
/// then the losing member drops the role at once. The flood budget is a
/// second `hello_period`, generous for this module's topologies (a handful
/// of hops of a few ticks each); `protocol.zig` prints the measured worst.
pub fn maxDuplicateWindow(cfg: ElectConfig) Time {
    return 2 * cfg.hello_period;
}

/// Is `kind` a fault after which the heal race may produce a duplicate?
fn restoresConnectivity(kind: netsim.FaultKind) bool {
    return switch (kind) {
        .heal, .link_up, .restart_node => true,
        else => false,
    };
}

/// The first duplicate NOT within `window` after a connectivity-restoring
/// fault in `trace` (sorted by time or not), or `null` if every duplicate is
/// explained.
pub fn firstUnexplainedDuplicate(
    duplicates: []const Duplicate,
    trace: []const netsim.FaultEvent,
    window: Time,
) ?Duplicate {
    outer: for (duplicates) |d| {
        for (trace) |e| {
            if (!restoresConnectivity(e.kind)) continue;
            if (e.time <= d.time and d.time - e.time <= window) continue :outer;
        }
        return d;
    }
    return null;
}

// ── 3. zero-DF windows ─────────────────────────────────────────────────────

pub const DfTransition = struct {
    time: Time,
    segment: SegmentId,
    tag: Tag,
    node: NodeId,
    is_df: bool,
};

/// Worst ticks a `<segment, tag>` may go without a DF while a member is
/// serving. The slow path is a member that goes deaf: it notices after
/// `stale_after` (on its next Hello tick, up to one `hello_period`) and
/// declares itself isolated in that tick's Hello; every peer drops it at
/// once, but the view consensus also waits for each peer's NEXT Hello to
/// advertise the shrunk view (a second `hello_period`); then the new DF waits
/// `df_wait` and takes the role at its next evaluation (a third). A dead DF
/// is one step faster (its peers notice the silence themselves). Flood delays
/// of a few ticks per hop fit the slack: evaluation also runs on every BUM
/// frame, more often than the Hello tick. Startup fits the same bound.
pub fn maxZeroDfWindow(cfg: ElectConfig) Time {
    return cfg.stale_after + cfg.df_wait + 3 * cfg.hello_period;
}

const TagKey = struct { segment: SegmentId, tag: Tag };

const TagState = struct {
    /// Bit i = `members[i]` currently claims the role.
    holders: u32 = 0,
    zero_since: ?Time = 0,
    worst: ZeroWindow = .{},
};

/// The longest zero-DF stretch found, and where.
pub const ZeroWindow = struct {
    len: Time = 0,
    segment: SegmentId = 0,
    tag: Tag = 0,
    start: Time = 0,

    fn consider(self: *ZeroWindow, seg: SegmentId, tag: Tag, start: Time, end: Time) void {
        if (end - start > self.len) self.* = .{ .len = end - start, .segment = seg, .tag = tag, .start = start };
    }
};

/// Is `kind` a fault that can legitimately start a zero-DF stretch (or
/// extend one): anything that changes who can hear whom, who is up, or a
/// node's clock. Single-message faults (drop/dup/delay once) are not: one
/// lost Hello never flips liveness, by `stale_after`'s construction.
fn disrupts(kind: netsim.FaultKind) bool {
    return switch (kind) {
        .link_down, .link_up, .partition, .heal, .crash_node, .restart_node, .clock_jump => true,
        .drop_once, .dup_once, .delay_once => false,
    };
}

/// Rebuild, per `<segment, tag>`, the set of members holding the role over
/// `[0, until)` from `transitions` (time-ordered, as `protocol.DfElect`
/// records them) and `trace` over `links`, and return the worst stretch with
/// no holder while at least one member was SERVING — up, and reachable from
/// some other live node (a member nothing can reach receives no frame, so
/// neither its holding a role nor its lacking one says anything) — measured
/// from startup or from the LAST disruptive fault before the stretch ended,
/// whichever is later. That is the bound's meaning: the election must
/// recover within it once the fabric stops changing; a schedule that keeps
/// disrupting can keep a tag without a DF, as it can any failover protocol.
/// (A fault anywhere counts, even on a node unrelated to the segment — a
/// deliberate leniency, stated.)
pub fn worstZeroDfWindow(
    gpa: Allocator,
    transitions: []const DfTransition,
    segments: []const EdgeSegment,
    trace: []const netsim.FaultEvent,
    links: []const netsim.Link,
    node_count: usize,
    until: Time,
) Allocator.Error!ZeroWindow {
    var states: std.AutoHashMapUnmanaged(TagKey, TagState) = .empty;
    defer states.deinit(gpa);
    for (segments) |s| for (s.tags) |t| try states.put(gpa, .{ .segment = s.id, .tag = t }, .{});

    const crashed = try gpa.alloc(bool, node_count);
    defer gpa.free(crashed);
    @memset(crashed, false);
    const reach = try Reach.init(gpa, node_count);
    defer reach.deinit(gpa);
    reach.compute(trace, links, 0);

    // Events that change who is up or who reaches whom, in time order.
    var faults: std.ArrayList(netsim.FaultEvent) = .empty;
    defer faults.deinit(gpa);
    for (trace) |e| switch (e.kind) {
        .crash_node, .restart_node, .link_down, .link_up, .partition, .heal => try faults.append(gpa, e),
        else => {},
    };
    std.mem.sort(netsim.FaultEvent, faults.items, {}, struct {
        fn lt(_: void, a: netsim.FaultEvent, b: netsim.FaultEvent) bool {
            return a.time < b.time;
        }
    }.lt);

    var disruptions: std.ArrayList(Time) = .empty;
    defer disruptions.deinit(gpa);
    for (trace) |e| if (disrupts(e.kind)) try disruptions.append(gpa, e.time);
    std.mem.sort(Time, disruptions.items, {}, std.sort.asc(Time));

    var ti: usize = 0;
    var fi: usize = 0;
    while (ti < transitions.len or fi < faults.items.len) {
        // Faults first at equal times: a restart's own transitions (logged
        // from its onStart) come after it.
        const take_fault = fi < faults.items.len and
            (ti >= transitions.len or faults.items[fi].time <= transitions[ti].time);
        const now = if (take_fault) faults.items[fi].time else transitions[ti].time;
        if (take_fault) {
            const e = faults.items[fi];
            fi += 1;
            switch (e.kind) {
                .crash_node => |c| if (c.node < node_count) {
                    crashed[c.node] = true;
                },
                .restart_node => |r| if (r.node < node_count) {
                    crashed[r.node] = false;
                },
                else => {},
            }
            reach.compute(trace, links, now);
        } else {
            const t = transitions[ti];
            ti += 1;
            const seg = findSegment(segments, t.segment) orelse continue;
            const idx = seg.indexOf(t.node) orelse continue;
            const st = states.getPtr(.{ .segment = t.segment, .tag = t.tag }) orelse continue;
            const bit = @as(u32, 1) << @intCast(idx);
            if (t.is_df) st.holders |= bit else st.holders &= ~bit;
        }
        // Re-evaluate every <segment, tag> after the event.
        for (segments) |seg| {
            const any_up = anyMemberUp(seg, crashed, reach.connected);
            for (seg.tags) |tag| {
                const st = states.getPtr(.{ .segment = seg.id, .tag = tag }).?;
                const live = liveHolders(seg, st.holders, crashed, reach.connected);
                const bad = live == 0 and any_up;
                if (bad) {
                    if (st.zero_since == null) st.zero_since = now;
                } else if (st.zero_since) |since| {
                    st.worst.consider(seg.id, tag, anchor(disruptions.items, since, now), now);
                    st.zero_since = null;
                }
            }
        }
    }

    var worst: ZeroWindow = .{};
    var it = states.iterator();
    while (it.next()) |e| {
        const st = e.value_ptr;
        if (st.zero_since) |since| if (until > since) st.worst.consider(e.key_ptr.segment, e.key_ptr.tag, anchor(disruptions.items, since, until), until);
        if (st.worst.len > worst.len) worst = st.worst;
    }
    return worst;
}

/// Where a zero stretch `[start, end)` is measured from: `start`, or the last
/// disruption at or before `end` if that is later.
fn anchor(disruptions: []const Time, start: Time, end: Time) Time {
    var a = start;
    for (disruptions) |t| {
        if (t > end) break;
        a = @max(a, t);
    }
    return a;
}

// ── 4. lost frames ─────────────────────────────────────────────────────────

/// One BUM frame put on the fabric, as `protocol.DfElect` logs it.
pub const Origination = struct {
    time: Time,
    origin: NodeId,
    frame_id: u64,
    tag: Tag,
    ingress_segment: SegmentId,
};

pub const Loss = struct {
    time: Time,
    segment: SegmentId,
    tag: Tag,
    frame_id: u64,
};

/// Is `kind` a fault that can explain a lost frame shortly after it: every
/// disruption, plus a dropped message (the drop may be the frame itself or
/// the copy headed for the DF).
fn explainsLoss(kind: netsim.FaultKind) bool {
    return disrupts(kind) or kind == .drop_once;
}

/// The first frame in `originated` that a segment carrying its tag (other
/// than the one it ingressed from) never received, unless the loss is
/// explained. Explained means: the frame left within `window` after startup
/// or after a disruption or drop (`explainsLoss`), or such a fault came less
/// than `settle` after it left (it was in flight); or no live member of the
/// segment was reachable from the frame's origin over the links up at that
/// moment (`reachable`); or it left less than `settle` before `until`.
///
/// This is the check `worstZeroDfWindow` cannot make: that one counts role
/// HOLDERS, so a holder that hears nothing — and so receives no frame — looks
/// healthy to it while its segment gets no traffic at all.
pub fn firstUnexplainedLoss(
    gpa: Allocator,
    originated: []const Origination,
    delivery: *const DeliveryChecker,
    segments: []const EdgeSegment,
    trace: []const netsim.FaultEvent,
    links: []const netsim.Link,
    node_count: usize,
    window: Time,
    settle: Time,
    until: Time,
) Allocator.Error!?Loss {
    const seen = try gpa.alloc(bool, node_count);
    defer gpa.free(seen);
    const queue = try gpa.alloc(NodeId, node_count);
    defer gpa.free(queue);
    const crashed = try gpa.alloc(bool, node_count);
    defer gpa.free(crashed);

    for (originated) |o| {
        if (o.time + settle > until) continue;
        if (o.time <= window) continue; // startup
        var explained = false;
        for (trace) |e| {
            if (!explainsLoss(e.kind)) continue;
            // Before the frame left (recovery), or while it was in flight.
            if (e.time <= o.time and o.time - e.time <= window) explained = true;
            if (e.time > o.time and e.time - o.time <= settle) explained = true;
        }
        if (explained) continue;
        for (segments) |seg| {
            if (seg.id == o.ingress_segment or seg.tagIndex(o.tag) == null) continue;
            if (delivery.delivered.contains(.{ .frame_id = o.frame_id, .segment = seg.id })) continue;
            reachable(trace, links, o.origin, o.time, seen, queue, crashed);
            var any = false;
            for (seg.members) |m| {
                if (m.node < node_count and seen[m.node]) any = true;
            }
            if (any) return .{ .time = o.time, .segment = seg.id, .tag = o.tag, .frame_id = o.frame_id };
        }
    }
    return null;
}

/// Fill `seen` with the nodes a flood from `origin` reaches at `time`: over
/// links neither cut (`link_down`) nor split by an active partition, through
/// nodes that are up. Replays `trace` up to `time` from scratch.
fn reachable(
    trace: []const netsim.FaultEvent,
    links: []const netsim.Link,
    origin: NodeId,
    time: Time,
    seen: []bool,
    queue: []NodeId,
    crashed: []bool,
) void {
    @memset(seen, false);
    @memset(crashed, false);
    for (trace) |e| {
        if (e.time > time) continue;
        switch (e.kind) {
            .crash_node => |c| if (c.node < crashed.len) {
                crashed[c.node] = true;
            },
            .restart_node => |r| if (r.node < crashed.len) {
                crashed[r.node] = false;
            },
            else => {},
        }
    }
    if (origin >= seen.len or crashed[origin]) return;
    seen[origin] = true;
    queue[0] = origin;
    var head: usize = 0;
    var tail: usize = 1;
    while (head < tail) : (head += 1) {
        const a = queue[head];
        for (links) |l| {
            if (l.a != a or l.b >= seen.len or seen[l.b] or crashed[l.b]) continue;
            if (!linkUp(trace, l, time)) continue;
            seen[l.b] = true;
            queue[tail] = l.b;
            tail += 1;
        }
    }
}

/// Is the directed link `l` usable at `time`: its last `link_down`/`link_up`
/// says up, and no partition active at `time` puts exactly one end in its cut.
fn linkUp(trace: []const netsim.FaultEvent, l: netsim.Link, time: Time) bool {
    // Faults apply in trace order at equal times, as netsim applies them.
    var up = true;
    for (trace) |e| {
        if (e.time > time) continue;
        switch (e.kind) {
            .link_down => |d| if (d.a == l.a and d.b == l.b) {
                up = false;
            },
            .link_up => |d| if (d.a == l.a and d.b == l.b) {
                up = true;
            },
            else => {},
        }
    }
    if (!up) return false;
    for (trace) |e| {
        if (e.time > time) continue;
        const p = switch (e.kind) {
            .partition => |p| p,
            else => continue,
        };
        if (healedBy(trace, p.id, e.time, time)) continue;
        const a_in = std.mem.indexOfScalar(NodeId, p.cut, l.a) != null;
        const b_in = std.mem.indexOfScalar(NodeId, p.cut, l.b) != null;
        if (a_in != b_in) return false;
    }
    return true;
}

/// Was partition `id` (applied at `since`) healed by `time`?
fn healedBy(trace: []const netsim.FaultEvent, id: u32, since: Time, time: Time) bool {
    for (trace) |e| switch (e.kind) {
        .heal => |h| if (h.id == id and e.time >= since and e.time <= time) return true,
        else => {},
    };
    return false;
}

fn findSegment(segments: []const EdgeSegment, id: SegmentId) ?EdgeSegment {
    for (segments) |s| if (s.id == id) return s;
    return null;
}

/// Up and reachable from some other live node.
fn serving(node: NodeId, crashed: []const bool, connected: []const bool) bool {
    return node < crashed.len and !crashed[node] and connected[node];
}

fn anyMemberUp(seg: EdgeSegment, crashed: []const bool, connected: []const bool) bool {
    for (seg.members) |m| if (serving(m.node, crashed, connected)) return true;
    return false;
}

fn liveHolders(seg: EdgeSegment, holders: u32, crashed: []const bool, connected: []const bool) usize {
    var n: usize = 0;
    for (seg.members, 0..) |m, i| {
        if (serving(m.node, crashed, connected) and holders & (@as(u32, 1) << @intCast(i)) != 0) n += 1;
    }
    return n;
}

/// Which nodes some OTHER live node reaches at a given moment.
const Reach = struct {
    connected: []bool,
    seen: []bool,
    queue: []NodeId,
    crashed: []bool,

    fn init(gpa: Allocator, n: usize) Allocator.Error!Reach {
        const connected = try gpa.alloc(bool, n);
        errdefer gpa.free(connected);
        const seen = try gpa.alloc(bool, n);
        errdefer gpa.free(seen);
        const queue = try gpa.alloc(NodeId, n);
        errdefer gpa.free(queue);
        const crashed = try gpa.alloc(bool, n);
        return .{ .connected = connected, .seen = seen, .queue = queue, .crashed = crashed };
    }

    fn deinit(self: Reach, gpa: Allocator) void {
        gpa.free(self.connected);
        gpa.free(self.seen);
        gpa.free(self.queue);
        gpa.free(self.crashed);
    }

    fn compute(self: Reach, trace: []const netsim.FaultEvent, links: []const netsim.Link, time: Time) void {
        @memset(self.connected, false);
        for (0..self.connected.len) |src| {
            reachable(trace, links, @intCast(src), time, self.seen, self.queue, self.crashed);
            for (self.seen, 0..) |r, n| {
                if (r and n != src) self.connected[n] = true;
            }
        }
    }
};

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "DeliveryChecker: distinct frames and one frame to distinct segments are fine" {
    var dc = DeliveryChecker{ .duplicates_fatal = true };
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 1, 1, 10, 100, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 2, 2, 10, 100, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 3, 1, 10, 101, types.no_ingress);
    try dc.check();
    try testing.expectEqual(@as(usize, 0), dc.duplicates.items.len);
}

test "DeliveryChecker: a duplicate is recorded with its time, and is fatal only when asked" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 5, 1, 10, 100, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 9, 1, 10, 100, types.no_ingress);
    try dc.check();
    try testing.expectEqual(@as(usize, 1), dc.duplicates.items.len);
    try testing.expectEqual(@as(Time, 9), dc.duplicates.items[0].time);

    var fatal = DeliveryChecker{ .duplicates_fatal = true };
    defer fatal.deinit(testing.allocator);
    try fatal.recordDelivery(testing.allocator, 5, 1, 10, 100, types.no_ingress);
    try fatal.recordDelivery(testing.allocator, 9, 1, 10, 100, types.no_ingress);
    try testing.expectError(error.DuplicateDelivery, fatal.check());
}

test "DeliveryChecker: split-horizon is fatal in every mode, sticky, and cleared by reset" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 1, 5, 10, 200, 5);
    try testing.expectError(error.SplitHorizonViolation, dc.check());
    try dc.recordDelivery(testing.allocator, 2, 1, 10, 300, types.no_ingress);
    try testing.expectError(error.SplitHorizonViolation, dc.check());
    dc.reset();
    try dc.check();
    try testing.expectEqual(@as(usize, 0), dc.duplicates.items.len);
}

test "firstUnexplainedDuplicate: only a restoring fault within the window explains a duplicate" {
    const dups = [_]Duplicate{
        .{ .time = 530, .segment = 1, .tag = 10, .frame_id = 1 },
        .{ .time = 900, .segment = 1, .tag = 10, .frame_id = 2 },
    };
    const heal_500 = [_]netsim.FaultEvent{.{ .time = 500, .kind = .{ .heal = .{ .id = 1 } } }};
    // 530 is explained by the heal at 500; 900 is not.
    try testing.expectEqual(@as(Time, 900), firstUnexplainedDuplicate(&dups, &heal_500, 100).?.time);
    try testing.expectEqual(@as(?Duplicate, null), firstUnexplainedDuplicate(dups[0..1], &heal_500, 100));
    // A cut does not explain a duplicate; a fault AFTER the duplicate neither.
    const cut = [_]netsim.FaultEvent{
        .{ .time = 520, .kind = .{ .link_down = .{ .a = 0, .b = 1 } } },
        .{ .time = 531, .kind = .{ .link_up = .{ .a = 0, .b = 1 } } },
    };
    try testing.expectEqual(@as(Time, 530), firstUnexplainedDuplicate(dups[0..1], &cut, 100).?.time);
    // No trace at all: every duplicate is unexplained.
    try testing.expect(firstUnexplainedDuplicate(dups[0..1], &.{}, 100) != null);
}

test "maxZeroDfWindow / maxDuplicateWindow: functions of the config" {
    try testing.expectEqual(@as(Time, 170 + 150 + 150), maxZeroDfWindow(.{}));
    try testing.expectEqual(@as(Time, 100), maxDuplicateWindow(.{}));
    try testing.expectEqual(@as(Time, 30 + 20 + 30), maxZeroDfWindow(.{ .hello_period = 10, .stale_after = 30, .df_wait = 20 }));
}

const members_a = [_]types.Member{ .{ .node = 10, .addr = 1 }, .{ .node = 11, .addr = 2 } };
const seg_a = EdgeSegment{ .id = 1, .esi = @splat(0), .members = &members_a, .tags = &.{ 7, 8 } };
/// Both members hang off fabric node 0, so each is reachable while 0 is up.
const hub = [_]netsim.Link{ .{ .a = 0, .b = 10 }, .{ .a = 10, .b = 0 }, .{ .a = 0, .b = 11 }, .{ .a = 11, .b = 0 } };

test "worstZeroDfWindow: startup counts until the first holder, per tag" {
    const tr = [_]DfTransition{
        .{ .time = 200, .segment = 1, .tag = 7, .node = 10, .is_df = true },
        .{ .time = 250, .segment = 1, .tag = 8, .node = 11, .is_df = true },
    };
    try testing.expectEqual(@as(Time, 250), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &.{}, &hub, 12, 1000)).len);
}

test "worstZeroDfWindow: a crashed holder stops counting at the crash, and the takeover closes the window" {
    const tr = [_]DfTransition{
        .{ .time = 0, .segment = 1, .tag = 7, .node = 10, .is_df = true },
        .{ .time = 0, .segment = 1, .tag = 8, .node = 11, .is_df = true },
        // node 10 crashes at 300 (trace); its role is still logged as held.
        .{ .time = 640, .segment = 1, .tag = 7, .node = 11, .is_df = true },
    };
    const trace = [_]netsim.FaultEvent{.{ .time = 300, .kind = .{ .crash_node = .{ .node = 10 } } }};
    try testing.expectEqual(@as(Time, 340), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &trace, &hub, 12, 1000)).len);
    // Without the trace the dead holder would hide the gap entirely.
    try testing.expectEqual(@as(Time, 0), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &.{}, &hub, 12, 1000)).len);
}

test "worstZeroDfWindow: a gap with every member down is not counted; one left open at `until` is" {
    const tr = [_]DfTransition{
        .{ .time = 0, .segment = 1, .tag = 7, .node = 10, .is_df = true },
        .{ .time = 0, .segment = 1, .tag = 8, .node = 10, .is_df = true },
    };
    const both_down = [_]netsim.FaultEvent{
        .{ .time = 100, .kind = .{ .crash_node = .{ .node = 10 } } },
        .{ .time = 100, .kind = .{ .crash_node = .{ .node = 11 } } },
    };
    try testing.expectEqual(@as(Time, 0), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &both_down, &hub, 12, 1000)).len);
    const one_down = both_down[0..1];
    // node 11 is up and never takes over: open until 1000.
    try testing.expectEqual(@as(Time, 900), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, one_down, &hub, 12, 1000)).len);
}

test "worstZeroDfWindow: measured from the last disruption, not from a startup that the fault interrupted" {
    // Nobody holds tag 7 from t=0 to 450; a partition at 198 is the last
    // disruption, so the recovery is measured as 252 ticks.
    const tr = [_]DfTransition{
        .{ .time = 0, .segment = 1, .tag = 8, .node = 11, .is_df = true },
        .{ .time = 450, .segment = 1, .tag = 7, .node = 11, .is_df = true },
    };
    const cut = [_]NodeId{10};
    const trace = [_]netsim.FaultEvent{
        .{ .time = 198, .kind = .{ .partition = .{ .id = 1, .cut = &cut } } },
        .{ .time = 300, .kind = .{ .drop_once = .{ .a = 10, .b = 11 } } }, // not a disruption
        .{ .time = 900, .kind = .{ .heal = .{ .id = 1 } } }, // after the stretch: ignored
    };
    const zw = try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &trace, &hub, 12, 1000);
    try testing.expectEqual(@as(Time, 252), zw.len);
    try testing.expectEqual(@as(Time, 198), zw.start);
    try testing.expectEqual(@as(Tag, 7), zw.tag);
}

test "worstZeroDfWindow: two holders at once is not a zero window" {
    const tr = [_]DfTransition{
        .{ .time = 0, .segment = 1, .tag = 7, .node = 10, .is_df = true },
        .{ .time = 0, .segment = 1, .tag = 8, .node = 10, .is_df = true },
        .{ .time = 50, .segment = 1, .tag = 7, .node = 11, .is_df = true },
        .{ .time = 90, .segment = 1, .tag = 7, .node = 10, .is_df = false },
    };
    try testing.expectEqual(@as(Time, 0), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &.{}, &hub, 12, 1000)).len);
}

test "worstZeroDfWindow: a member nothing reaches counts neither as serving nor as a holder" {
    // Node 10 holds both tags but goes deaf at 200: from then on node 11 is
    // the only serving member and nobody serving holds anything.
    const tr = [_]DfTransition{
        .{ .time = 0, .segment = 1, .tag = 7, .node = 10, .is_df = true },
        .{ .time = 0, .segment = 1, .tag = 8, .node = 10, .is_df = true },
    };
    const deaf_10 = [_]netsim.FaultEvent{.{ .time = 200, .kind = .{ .link_down = .{ .a = 0, .b = 10 } } }};
    try testing.expectEqual(@as(Time, 800), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &deaf_10, &hub, 12, 1000)).len);
    // Both deaf: nobody serves, so nothing is owed.
    const both_deaf = [_]netsim.FaultEvent{
        .{ .time = 200, .kind = .{ .link_down = .{ .a = 0, .b = 10 } } },
        .{ .time = 200, .kind = .{ .link_down = .{ .a = 0, .b = 11 } } },
    };
    try testing.expectEqual(@as(Time, 0), (try worstZeroDfWindow(testing.allocator, &tr, &.{seg_a}, &both_deaf, &hub, 12, 1000)).len);
    // Node 11 takes both tags over at 650: the gap is 450, from the cut.
    const takeover = tr ++ [_]DfTransition{
        .{ .time = 650, .segment = 1, .tag = 7, .node = 11, .is_df = true },
        .{ .time = 650, .segment = 1, .tag = 8, .node = 11, .is_df = true },
    };
    try testing.expectEqual(@as(Time, 450), (try worstZeroDfWindow(testing.allocator, &takeover, &.{seg_a}, &deaf_10, &hub, 12, 1000)).len);
}

test "firstUnexplainedLoss: a frame a reachable member never got is a loss unless a fault explains it" {
    const gpa = testing.allocator;
    var dc = DeliveryChecker{};
    defer dc.deinit(gpa);
    const sent = [_]Origination{.{ .time = 600, .origin = 0, .frame_id = 1, .tag = 7, .ingress_segment = types.no_ingress }};
    const window: Time = 100;
    const settle: Time = 50;
    const S = struct {
        fn loss(d: *const DeliveryChecker, o: []const Origination, trace: []const netsim.FaultEvent) !?Loss {
            return firstUnexplainedLoss(testing.allocator, o, d, &.{seg_a}, trace, &hub, 12, window, settle, 1000);
        }
    };

    // Nothing explains it.
    try testing.expectEqual(@as(Time, 600), (try S.loss(&dc, &sent, &.{})).?.time);
    // A disruption too long before does not either.
    const old = [_]netsim.FaultEvent{.{ .time = 450, .kind = .{ .crash_node = .{ .node = 5 } } }};
    try testing.expect((try S.loss(&dc, &sent, &old)) != null);
    // A dup or a delay never loses a frame.
    const harmless = [_]netsim.FaultEvent{
        .{ .time = 590, .kind = .{ .dup_once = .{ .a = 0, .b = 10 } } },
        .{ .time = 595, .kind = .{ .delay_once = .{ .a = 0, .b = 10, .extra = 5 } } },
    };
    try testing.expect((try S.loss(&dc, &sent, &harmless)) != null);

    // Explained: a disruption within `window` before, a drop, a fault while in flight.
    const recent = [_]netsim.FaultEvent{.{ .time = 520, .kind = .{ .partition = .{ .id = 1, .cut = &.{10} } } }};
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &sent, &recent));
    const dropped = [_]netsim.FaultEvent{.{ .time = 580, .kind = .{ .drop_once = .{ .a = 0, .b = 10 } } }};
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &sent, &dropped));
    const in_flight = [_]netsim.FaultEvent{.{ .time = 640, .kind = .{ .crash_node = .{ .node = 0 } } }};
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &sent, &in_flight));
    const too_late = [_]netsim.FaultEvent{.{ .time = 651, .kind = .{ .crash_node = .{ .node = 0 } } }};
    try testing.expect((try S.loss(&dc, &sent, &too_late)) != null);

    // Explained: no member reachable (cut long ago, never repaired) — and one
    // reachable member is enough to make it a loss again.
    const unreachable_all = [_]netsim.FaultEvent{
        .{ .time = 100, .kind = .{ .link_down = .{ .a = 0, .b = 10 } } },
        .{ .time = 100, .kind = .{ .link_down = .{ .a = 0, .b = 11 } } },
    };
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &sent, &unreachable_all));
    try testing.expect((try S.loss(&dc, &sent, unreachable_all[0..1])) != null);
    const healed = [_]netsim.FaultEvent{
        .{ .time = 100, .kind = .{ .partition = .{ .id = 3, .cut = &.{ 10, 11 } } } },
        .{ .time = 200, .kind = .{ .heal = .{ .id = 3 } } },
    };
    try testing.expect((try S.loss(&dc, &sent, &healed)) != null);
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &sent, healed[0..1]));

    // Not owed at all: startup, too close to `until`, the ingress segment, a
    // tag the segment does not carry.
    const owed_not = [_]Origination{
        .{ .time = 100, .origin = 0, .frame_id = 2, .tag = 7, .ingress_segment = types.no_ingress },
        .{ .time = 960, .origin = 0, .frame_id = 3, .tag = 7, .ingress_segment = types.no_ingress },
        .{ .time = 600, .origin = 10, .frame_id = 4, .tag = 7, .ingress_segment = 1 },
        .{ .time = 600, .origin = 0, .frame_id = 5, .tag = 99, .ingress_segment = types.no_ingress },
    };
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &owed_not, &.{}));

    // Delivered: no loss.
    try dc.recordDelivery(gpa, 610, 1, 7, 1, types.no_ingress);
    try testing.expectEqual(@as(?Loss, null), try S.loss(&dc, &sent, &.{}));
}
