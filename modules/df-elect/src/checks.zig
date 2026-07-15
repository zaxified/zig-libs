// SPDX-License-Identifier: MIT

//! checks — the invariant proof. Two DIFFERENT kinds of invariant, checked
//! two DIFFERENT ways, on purpose:
//!
//!  1. **Zero-tolerance**, checked LIVE via netsim's `Protocol.checkFn` (so a
//!     violation halts the run and captures the exact reproducer trace).
//!     Exactly two things are NEVER allowed, not even for one tick:
//!       - `error.DuplicateDelivery` — the same BUM frame delivered twice to
//!         the same segment.
//!       - `error.SplitHorizonViolation` — a frame delivered back into the
//!         segment it ingressed from.
//!     See `DeliveryChecker`.
//!  2. **Bounded-badness**, checked POST-RUN over the full DF-status
//!     transition log: at most / at least one DF per segment, allowed to be
//!     transiently wrong ONLY within `maxBadDfWindow` ticks of a topology
//!     change (or of startup). This is a liveness property, not a safety
//!     one — flagging it as a live `checkFn` error would be WRONG, because
//!     the transient window is legal by design, not a bug. So it is measured
//!     instead of asserted inline: `worstBadDfWindow` reconstructs the
//!     per-segment DF-count-over-time step function from a transition log
//!     and returns the worst "count != 1" interval observed; the CALLER
//!     compares that measurement against the declared bound. See
//!     `worstBadDfWindow` + `maxBadDfWindow`.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");

const NodeId = netsim.NodeId;
const Time = netsim.Time;
const Allocator = std.mem.Allocator;
const SegmentId = types.SegmentId;
const EdgeSegment = types.EdgeSegment;
const ElectConfig = types.ElectConfig;

// ── 1. zero-tolerance: DeliveryChecker ──────────────────────────────────────

/// Shared verbatim by BOTH the real (stub-gated) `protocol.DfElect` and the
/// positive-control `protocol.BrokenAlwaysDf`, so a violation either one
/// trips is provably the SAME check (see `protocol.zig`'s positive-control
/// tests — the whole point of a positive control is that it exercises the
/// real proof machinery, not a copy of it).
pub const DeliveryChecker = struct {
    const Key = struct { frame_id: u64, segment: u64 };

    delivered: std.AutoHashMapUnmanaged(Key, void) = .empty,
    /// Sticky: set the instant a bad delivery is observed; `check()` turns it
    /// into a `netsim.Protocol.checkFn` error on that SAME event (mirrors
    /// `netsim`'s own `LoopyForward` pattern: accumulate in the message
    /// handler, assert in `check`).
    violation: ?anyerror = null,

    pub fn deinit(self: *DeliveryChecker, gpa: Allocator) void {
        self.delivered.deinit(gpa);
        self.* = undefined;
    }

    pub fn reset(self: *DeliveryChecker) void {
        self.delivered.clearRetainingCapacity();
        self.violation = null;
    }

    /// Record a BUM frame's delivery to `segment`. Sets `violation` (does
    /// NOT return it — `check()` is where a `Protocol.checkFn` must surface
    /// it, see the module doc) if this is a second delivery of the same
    /// frame to the same segment, or if the frame is being reflected back
    /// into the very segment it ingressed from. First violation wins and
    /// stays sticky for the rest of the run — netsim stops at the first
    /// `check()` failure anyway, but staying sticky keeps this type correct
    /// even if a caller keeps recording after the fact (e.g. in a unit test).
    pub fn recordDelivery(
        self: *DeliveryChecker,
        gpa: Allocator,
        segment: SegmentId,
        frame_id: u64,
        ingress_segment: SegmentId,
    ) Allocator.Error!void {
        if (self.violation != null) return;
        if (ingress_segment == segment) {
            self.violation = error.SplitHorizonViolation;
            return;
        }
        const key = Key{ .frame_id = frame_id, .segment = segment };
        const gop = try self.delivered.getOrPut(gpa, key);
        if (gop.found_existing) {
            self.violation = error.DuplicateDelivery;
            return;
        }
    }

    /// `netsim.Protocol.checkFn` body (wrap in the protocol's own `check`,
    /// which also has to cast `ctx`).
    pub fn check(self: *const DeliveryChecker) anyerror!void {
        if (self.violation) |e| return e;
    }
};

// ── 2. bounded-badness: DF transition log + post-run window analyzer ───────

pub const DfTransition = struct {
    time: Time,
    segment: SegmentId,
    node: NodeId,
    is_df: bool,
};

/// Worst-case ticks a segment may need to reconverge to EXACTLY one DF after
/// a topology change (partition, heal, link up/down, crash, restart) or
/// since startup. Reasoning, spelled out because it is a declared SPEC bound
/// the real election in `election.zig` must satisfy — not a law of physics:
///   - the stale side needs up to `stale_after` ticks to notice a severed
///     peer at all (by construction: a single dropped Hello must not flip
///     liveness, so staleness detection is deliberately not instant);
///   - a just-healed side needs up to one more `hello_period` for the next
///     Hello to land and re-establish liveness;
///   - a flat 2x multiplier over that sum budgets core flood-propagation
///     delay plus one full round-trip of confirmation, so a multi-hop core
///     (not just a direct edge-to-edge link) doesn't need re-derivation.
/// Retune this once the real algorithm's measured settling behavior is in —
/// this is the bound the harness enforces, not a promise about the eventual
/// implementation's true worst case.
pub fn maxBadDfWindow(cfg: ElectConfig) Time {
    return 2 * (cfg.stale_after + cfg.hello_period);
}

const SegState = struct {
    member: [2]bool = .{ false, false },
    count: u8 = 0,
    /// Ticks since which `count != 1` has been continuously true for this
    /// segment. `0` at construction: with both members starting at
    /// `is_df = false`, `count = 0 != 1` from t=0 until the first DF
    /// transition — startup counts as the first "topology change".
    bad_since: ?Time = 0,
    worst: Time = 0,
};

/// Reconstruct each segment's DF-count-over-time step function from
/// `transitions` and return the WORST observed "count != 1" window across
/// all of `segments`, closing out any window still open at `until`.
///
/// `transitions` MUST already be time-ordered (true of any log recorded by
/// `protocol.DfElect`, which appends during netsim's strictly
/// (time, seq)-ordered event processing — see `netsim`'s `EventHeap`).
/// Pure otherwise: no netsim `Sim` dependency, no allocation beyond one
/// `segments.len`-sized scratch buffer, so it is fully testable with
/// hand-written synthetic transitions (see the tests below) without ever
/// running a real `Protocol`.
pub fn worstBadDfWindow(
    gpa: Allocator,
    transitions: []const DfTransition,
    segments: []const EdgeSegment,
    until: Time,
) Allocator.Error!Time {
    const states = try gpa.alloc(SegState, segments.len);
    defer gpa.free(states);
    for (states) |*s| s.* = .{};

    for (transitions) |t| {
        const seg_idx = indexOfSegment(segments, t.segment) orelse continue;
        const seg = segments[seg_idx];
        const member_idx = seg.indexOf(t.node) orelse continue;
        const st = &states[seg_idx];

        if (st.member[member_idx] == t.is_df) continue; // not an actual flip
        const was_one = st.count == 1;
        st.member[member_idx] = t.is_df;
        st.count = @as(u8, @intFromBool(st.member[0])) + @as(u8, @intFromBool(st.member[1]));
        const is_one = st.count == 1;

        if (was_one and !is_one) {
            st.bad_since = t.time;
        } else if (!was_one and is_one) {
            if (st.bad_since) |since| {
                std.debug.assert(t.time >= since);
                st.worst = @max(st.worst, t.time - since);
                st.bad_since = null;
            }
        }
    }

    var worst: Time = 0;
    for (states) |*st| {
        if (st.bad_since) |since| {
            std.debug.assert(until >= since);
            st.worst = @max(st.worst, until - since);
        }
        worst = @max(worst, st.worst);
    }
    return worst;
}

fn indexOfSegment(segments: []const EdgeSegment, id: SegmentId) ?usize {
    for (segments, 0..) |s, i| {
        if (s.id == id) return i;
    }
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "DeliveryChecker: a clean run of distinct frames to distinct segments never violates" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 1, 100, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 2, 100, types.no_ingress); // same frame, DIFFERENT segment — legitimate
    try dc.recordDelivery(testing.allocator, 1, 101, types.no_ingress);
    try dc.check();
}

test "DeliveryChecker: a second delivery of the same frame to the same segment is a duplicate" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 1, 100, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 1, 100, types.no_ingress);
    try testing.expectError(error.DuplicateDelivery, dc.check());
}

test "DeliveryChecker: delivery back into the ingress segment is a split-horizon violation" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 5, 200, 5); // ingress_segment == segment
    try testing.expectError(error.SplitHorizonViolation, dc.check());
}

test "DeliveryChecker: sticky — the FIRST violation wins, a later one does not overwrite it" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 5, 200, 5); // split-horizon first
    try dc.recordDelivery(testing.allocator, 1, 300, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 1, 300, types.no_ingress); // would-be duplicate, second
    try testing.expectError(error.SplitHorizonViolation, dc.check());
}

test "DeliveryChecker: reset clears both the dedup table and the sticky violation" {
    var dc = DeliveryChecker{};
    defer dc.deinit(testing.allocator);
    try dc.recordDelivery(testing.allocator, 1, 100, types.no_ingress);
    try dc.recordDelivery(testing.allocator, 1, 100, types.no_ingress);
    try testing.expectError(error.DuplicateDelivery, dc.check());
    dc.reset();
    try dc.check();
    try dc.recordDelivery(testing.allocator, 1, 100, types.no_ingress); // same frame id, fresh table
    try dc.check();
}

test "maxBadDfWindow: a documented function of the hold-timer config, not a bare constant" {
    const cfg = ElectConfig{ .hello_period = 50, .stale_after = 170 };
    try testing.expectEqual(@as(Time, 440), maxBadDfWindow(cfg));
    const tighter = ElectConfig{ .hello_period = 10, .stale_after = 30 };
    try testing.expectEqual(@as(Time, 80), maxBadDfWindow(tighter));
}

const seg_a = EdgeSegment{ .id = 1, .nodes = .{ 10, 11 }, .priority = .{ 1, 2 } };

test "worstBadDfWindow: immediate convergence at t=0 measures a zero window" {
    const transitions = [_]DfTransition{
        .{ .time = 0, .segment = 1, .node = 10, .is_df = true },
    };
    const worst = try worstBadDfWindow(testing.allocator, &transitions, &.{seg_a}, 1000);
    try testing.expectEqual(@as(Time, 0), worst);
}

test "worstBadDfWindow: a bounded gap between losing and regaining a DF measures correctly" {
    const transitions = [_]DfTransition{
        .{ .time = 0, .segment = 1, .node = 10, .is_df = true }, // converges immediately
        .{ .time = 100, .segment = 1, .node = 10, .is_df = false }, // node 10 goes stale — count=0
        .{ .time = 140, .segment = 1, .node = 11, .is_df = true }, // node 11 takes over — count=1
    };
    const worst = try worstBadDfWindow(testing.allocator, &transitions, &.{seg_a}, 1000);
    try testing.expectEqual(@as(Time, 40), worst);
    try testing.expect(worst <= maxBadDfWindow(.{}));
}

test "worstBadDfWindow: teeth — a window left open past `until` is measured as still-bad, and can exceed the bound" {
    const transitions = [_]DfTransition{
        .{ .time = 0, .segment = 1, .node = 10, .is_df = true },
        .{ .time = 200, .segment = 1, .node = 10, .is_df = false }, // count=0, never repaired
    };
    const worst = try worstBadDfWindow(testing.allocator, &transitions, &.{seg_a}, 1000);
    try testing.expectEqual(@as(Time, 800), worst); // 1000 - 200
    try testing.expect(worst > maxBadDfWindow(.{})); // 800 > 440 — this WOULD fail a real property test
}

test "worstBadDfWindow: teeth — an overlong recovery gap is measured larger than the bound" {
    const transitions = [_]DfTransition{
        .{ .time = 0, .segment = 1, .node = 10, .is_df = true },
        .{ .time = 100, .segment = 1, .node = 10, .is_df = false },
        .{ .time = 900, .segment = 1, .node = 11, .is_df = true }, // took 800 ticks to recover
    };
    const worst = try worstBadDfWindow(testing.allocator, &transitions, &.{seg_a}, 1000);
    try testing.expectEqual(@as(Time, 800), worst);
    try testing.expect(worst > maxBadDfWindow(.{}));
}

test "worstBadDfWindow: dual-DF (count=2) is measured exactly like zero-DF (count=0) — both are 'count != 1'" {
    const transitions = [_]DfTransition{
        .{ .time = 0, .segment = 1, .node = 10, .is_df = true },
        .{ .time = 50, .segment = 1, .node = 11, .is_df = true }, // both now believe DF — count=2
        .{ .time = 90, .segment = 1, .node = 11, .is_df = false }, // back to exactly one — count=1
    };
    const worst = try worstBadDfWindow(testing.allocator, &transitions, &.{seg_a}, 1000);
    try testing.expectEqual(@as(Time, 40), worst); // 90 - 50
}

test "worstBadDfWindow: independent segments do not leak into each other's window" {
    const seg_b = EdgeSegment{ .id = 2, .nodes = .{ 20, 21 }, .priority = .{ 1, 2 } };
    const transitions = [_]DfTransition{
        .{ .time = 0, .segment = 1, .node = 10, .is_df = true }, // seg 1: converges immediately
        .{ .time = 0, .segment = 2, .node = 20, .is_df = true },
        .{ .time = 300, .segment = 2, .node = 20, .is_df = false }, // seg 2: goes bad late, recovers fast
        .{ .time = 330, .segment = 2, .node = 21, .is_df = true },
    };
    const worst = try worstBadDfWindow(testing.allocator, &transitions, &.{ seg_a, seg_b }, 1000);
    try testing.expectEqual(@as(Time, 30), worst); // seg 2's 30-tick gap dominates seg 1's 0
}
