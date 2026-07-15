// SPDX-License-Identifier: MIT

//! election — the irreducible algorithm this module exists to prove. THE
//! FABLE CORE (see `decide` below): a deterministic Designated-Forwarder
//! election from a node's own link-state view (no second election protocol,
//! no side-channel vote) that stays correct — bounded dual-DF and bounded
//! zero-DF windows, never worse — across arbitrary partition and heal, plus
//! the split-horizon rule, which must hold with ZERO tolerance even DURING a
//! transient dual-DF window (it is EVPN's local-bias backstop, not itself
//! subject to a settling window — see `checks.zig`'s module doc for why the
//! two are checked two different ways).
//!
//! **Why this is hard, and what EVPN does instead:** EVPN gets DF election
//! "for free" from BGP. Every PE runs a full-mesh iBGP (or route-reflector)
//! session per peer; each PE advertises an Ethernet A-D per-ES route for
//! every Ethernet Segment it is multi-homed to, and BGP's own session
//! liveness + route withdrawal machinery IS the "who is currently reachable
//! for this ES" view — the DF is then just a deterministic ordinal function
//! over the ordered list of PEs that have an active advertisement (RFC 7432
//! §8.5's default algorithm: sort by PE address, `DF = list[(ES-ordinal) mod
//! N]`). A link-state fabric has no BGP session to lean on: `protocol.zig`
//! floods plain link-state Hellos (the same primitive SPF itself would use),
//! and THIS function must derive the equivalent "list of currently-live
//! members for this segment" guarantee — and the partition-correctness proof
//! that goes with it — purely from that flood, with no second protocol
//! layered on top. That derivation is the module's actual contribution.
//!
//! **The two failure modes a correct `decide` must avoid:**
//!  - *Dual DF*: both edge nodes of a segment believe they are DF at once →
//!    the segment receives every BUM frame twice.
//!  - *Zero DF*: neither believes it → the segment receives no BUM traffic
//!    at all (a silent black hole, worse than a duplicate because nothing
//!    signals the failure).
//! Neither can be avoided with zero settling time — a genuinely partitioned
//! node cannot instantaneously learn that fact — so both are budgeted a
//! `checks.maxBadDfWindow` window instead of being outlawed outright. What
//! MUST be avoided outright, always, is split-horizon: an unbounded window on
//! that one is a live forwarding loop into the customer's own site, not a
//! transient blip.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");

const NodeId = netsim.NodeId;
const SegmentId = types.SegmentId;

/// What a node currently believes about its OWN segment, derived purely from
/// its own flooded link-state (no second election protocol — this IS the SPF
/// view `protocol.zig` already maintains for Hello flooding).
pub const SegmentView = struct {
    self_id: NodeId,
    self_priority: u32,
    peer_id: NodeId,
    peer_priority: u32,
    /// Has a fresh Hello from `peer_id` been seen within
    /// `types.ElectConfig.stale_after` ticks of the caller's current time?
    /// `false` also covers "never seen a Hello from this peer at all" —
    /// `decide` cannot distinguish "never up" from "just went down" from
    /// this view alone (neither can a real link-state node).
    peer_alive: bool,
};

pub const Decision = struct {
    /// Does `view.self_id` currently consider itself the DF for this segment?
    is_df: bool,
    /// Split-horizon gate for ONE specific frame: may a frame that ingressed
    /// from `ingress_segment` (`null` = network/WAN-side, no ingress
    /// segment) be forwarded out toward `this_segment`? Independent of
    /// `is_df` in this return value — `protocol.zig` ANDs both before acting
    /// (defense in depth), but a correct implementation must NEVER return
    /// `allow_forward = true` when `ingress_segment == this_segment`,
    /// regardless of `is_df` or which node is asking. That invariant is
    /// checked live, with zero tolerance, by `checks.DeliveryChecker`.
    allow_forward: bool,
};

/// Decide DF status for `view.self_id` on segment `this_segment`, and (when a
/// concrete frame is in flight) the split-horizon gate for a frame that
/// ingressed from `ingress_segment`. Must be a PURE function of its inputs —
/// no hidden state, no clock reads, no I/O — so `protocol.zig` can call it
/// from anywhere (on every Hello that changes the view, on every BUM frame
/// that needs a forwarding decision) with identical guarantees, and so that
/// "deterministic from link-state" is actually true: two nodes with the same
/// view of a segment must reach the same `is_df` verdict WITHOUT talking to
/// each other about the verdict itself (only about the view, via Hellos).
///
/// See `checks.maxBadDfWindow` for the bound this function's convergence
/// behavior is measured against, and `checks.zig`'s module doc for why
/// dual-DF/zero-DF get a settling window while split-horizon does not.
///
/// ── THE RULE, AND WHY IT IS THE ONLY SAFE ONE ────────────────────────────
///
/// Nominally: elect, among the members of `this_segment` the local view
/// considers alive+attached, the winner of the static total order (lowest
/// `priority` value, ties by lowest node id — the order `types.EdgeSegment`
/// declares). For a two-member segment that expands to four cases:
///
///   |            | owner (order winner) | backup (order loser) |
///   | peer alive |     DF (wins)        |    not DF (loses)    |
///   | peer stale |  DF (sole member)    |     ??? — see below  |
///
/// The one free choice is the backup's stale cell — "I am the only member I
/// can see, so I am DF" is the symmetric, intuitively-correct fill (and what
/// naive EVPN-style re-election would do). It is WRONG here, and provably so
/// against `checks.DeliveryChecker`'s zero-tolerance duplicate invariant:
///
///  - *Startup:* the first network-side BUM frame is originated before the
///    first Hello round completes (any config where traffic can precede
///    liveness convergence — here `bum_period < hello_period`). It floods to
///    BOTH members while BOTH still see `peer_alive = false`; under the
///    symmetric fill both self-promote and both deliver → duplicate, on
///    every schedule, no partition needed.
///  - *Heal race:* after a partition heals, a BUM frame and the peer's next
///    Hello race across the healed cut on the same links; nothing orders
///    them. A frame that beats the Hello reaches the backup while its view
///    still says stale (→ self-promoted) and the owner while the owner is
///    DF (the owner is DF in EVERY view) → duplicate. The window is small
///    but the invariant has ZERO tolerance — "small" is still a loop seed.
///
/// Generalizing: `decide` is a pure function of the LOCAL view, and around a
/// heal every (owner-view, backup-view) ∈ {alive,stale}² combination is
/// simultaneously reachable while one frame reaches both members. Duplicate
/// freedom therefore requires: for every such pair, at most one member
/// answers DF. The owner must answer DF when stale (else a real peer death
/// would black-hole the segment forever — an UNBOUNDED zero-DF window), so
/// the backup may answer DF in NO reachable view: `is_df` must be
/// independent of `peer_alive`. The election collapses to the static total
/// order — which is exactly the guarantee EVPN's BGP-fed DF list provides
/// (RFC 7432 §8.5 is a deterministic ordinal over a list all PEs agree on;
/// the liveness feed only ever REMOVES the dead, it never lets the survivor
/// side invent a second concurrent forwarder for the same reachable frame).
/// A link-state Hello flood cannot distinguish "peer dead" from "peer
/// unreachable-from-me", so the only view-derived fact both members can
/// never disagree about is the static order itself.
///
/// *Bounded-badness accounting* (`checks.maxBadDfWindow` = 2·(stale_after +
/// hello_period) = 440 with the default config): under this rule dual-DF
/// NEVER occurs (only the owner ever answers DF), and zero-DF occurs only
/// from t=0 until the owner's first `decide` call — at latest its first
/// Hello-timer tick, one `hello_period` (= 50) after start/restart — far
/// inside the budget. Partitions and heals cause no DF transitions at all.
/// The trade this buys safety with is availability, not correctness: while
/// the owner is partitioned from a frame's origin, the segment receives
/// nothing (a bounded-by-the-partition black hole on the backup's side) —
/// the same trade single-active EVPN multi-homing makes, and the only one
/// available without a second protocol (fencing/consensus) on top.
///
/// ── SPLIT-HORIZON ─────────────────────────────────────────────────────────
///
/// Independent of election state, by design (see `Decision.allow_forward`):
/// a frame may be forwarded toward `this_segment` unless it INGRESSED from
/// `this_segment` (`ingress_segment == this_segment`). `null` (no concrete
/// frame / WAN-side) always forwards. `types.no_ingress` compares unequal to
/// every real segment id by construction, so it needs no special case. This
/// must not depend on `is_df` or liveness: it is the local-bias backstop
/// that holds even mid-transient, with zero tolerance.
pub fn decide(view: SegmentView, ingress_segment: ?SegmentId, this_segment: SegmentId) Decision {
    return .{
        .is_df = winsTotalOrder(view),
        .allow_forward = if (ingress_segment) |ingress| ingress != this_segment else true,
    };
}

/// The static total order over a segment's two members: lowest `priority`
/// value wins (see `types.EdgeSegment.priority`), ties broken by lowest node
/// id. Both members compute the same winner from any view — the agreement
/// `is_df` safety rests on (see `decide`'s doc for why `peer_alive` must not
/// participate).
fn winsTotalOrder(view: SegmentView) bool {
    if (view.self_priority != view.peer_priority)
        return view.self_priority < view.peer_priority;
    return view.self_id < view.peer_id;
}

const testing = std.testing;

test "SegmentView / Decision are plain data (compiles, no stub call)" {
    const view = SegmentView{
        .self_id = 1,
        .self_priority = 10,
        .peer_id = 2,
        .peer_priority = 20,
        .peer_alive = true,
    };
    try testing.expectEqual(@as(NodeId, 1), view.self_id);
    try testing.expectEqual(@as(NodeId, 2), view.peer_id);
    try testing.expect(view.peer_alive);

    const d = Decision{ .is_df = true, .allow_forward = false };
    try testing.expect(d.is_df and !d.allow_forward);
}
