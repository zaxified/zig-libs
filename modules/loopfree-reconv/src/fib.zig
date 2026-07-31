// SPDX-License-Identifier: MIT
//! FIB update ordering — the ordered-FIB / RPF loop-free-reconvergence core.
//!
//! Given a destination's shortest-path tree BEFORE a topology change
//! (`old_tree`, `spf-ect`'s `Tree`, rooted at the destination so `pred[n]` is
//! `n`'s current next-hop toward it) and the tree AFTER the change
//! (`new_tree`), a naive distributed implementation just lets every node
//! apply its own new next-hop the moment it locally finishes recomputing —
//! which is exactly what real, uncoordinated IGP convergence does, and
//! exactly what creates the transient loop this module exists to prevent
//! (see `fabric.zig`'s module doc + the "ships passing" example in
//! `../SPEC.md` if written). `computeUpdateOrder` is the fix: a REORDERING of
//! those same per-node FIB updates — no protocol messages added, no extra
//! round-trip, just a smarter sequence — such that no application order of a
//! *prefix* of it can ever leave two adjacent nodes pointing at each other
//! for the same destination.
//!
//! `naiveBadOrder` is the deliberately-NOT-fixed baseline: it is fully
//! implemented (not a stub) specifically so `fabric.zig`'s harness can run
//! the "positive control" — proving the loop-invariant checker actually has
//! teeth — without waiting on the Fable core below.

const std = @import("std");
const spf = @import("spf-ect");
const Allocator = std.mem.Allocator;
const NodeId = spf.NodeId;
const Tree = spf.Tree;

pub const OrderError = Allocator.Error;

/// Every node whose next-hop differs between `old_tree` and `new_tree`,
/// ascending by node id — the raw "what changed" set both `naiveBadOrder`
/// and `computeUpdateOrder` start from. Caller owns the returned slice.
pub fn changedNodes(gpa: Allocator, old_tree: *const Tree, new_tree: *const Tree) OrderError![]NodeId {
    std.debug.assert(old_tree.pred.len == new_tree.pred.len);
    var list: std.ArrayList(NodeId) = .empty;
    errdefer list.deinit(gpa);
    var n: NodeId = 0;
    while (n < old_tree.pred.len) : (n += 1) {
        if (old_tree.pred[n] != new_tree.pred[n]) try list.append(gpa, n);
    }
    return list.toOwnedSlice(gpa);
}

/// KNOWN-LOOPY baseline ordering: "apply all FIBs instantly" — every changed
/// node updates in plain ascending node-id order, with NO regard for
/// whether its next-hop's distance increased or decreased, and no
/// coordination with any other node's update. This is the strategy a
/// real, purely-local, uncoordinated IGP implementation reduces to (each
/// node reprograms its own FIB the instant ITS OWN SPF run finishes) —
/// which is precisely the failure mode `computeUpdateOrder` below is
/// required to avoid. Used ONLY as `fabric.zig`'s positive control (see its
/// "positive control" test): a topology + timing exists (and is exercised
/// there, both by hand and via the seeded fuzzer) for which this ordering
/// provably produces a transient forwarding loop that the invariant checker
/// catches — proving the checker has teeth independently of whether the
/// Fable core below is implemented yet.
///
/// Not a stub — this is intentionally the WRONG algorithm, fully written.
pub fn naiveBadOrder(gpa: Allocator, old_tree: *const Tree, new_tree: *const Tree) OrderError![]NodeId {
    return changedNodes(gpa, old_tree, new_tree);
}

/// The Fable core. Given the shortest-path trees rooted at ONE destination
/// before and after a topology change (`old_tree.pred[n]` / `new_tree.pred[n]`
/// = node `n`'s next-hop toward that destination, `null` for the root and
/// for unreached nodes; `.dist` carries each node's path cost in both
/// trees), produce a permutation of `changedNodes(gpa, old_tree, new_tree)`
/// — the ORDER in which `fabric.zig`'s conductor should apply each node's
/// `next_hop[n] = new_tree.pred[n]` FIB update — such that at every
/// INTERMEDIATE prefix of that order (some nodes already switched to their
/// new next-hop, the rest still on their old one), routing every destination
/// through the CURRENT mixed set of next-hops can never revisit a node
/// (i.e. no transient forwarding loop can exist at any point during the
/// transition, not just at the start and end).
///
/// This is the ordered-FIB / loop-free-convergence problem (Francois,
/// Filsfils, Evans & Bonaventure, "Achieving sub-second IGP convergence in
/// large IP networks", INFOCOM 2005 / RFC-adjacent IETF work; also the
/// IS-IS/SPB "no black-holing, no looping during convergence" requirement).
/// The classic shape of a correct answer — and the actual design work a
/// Fable pass needs to do, not just transcribe:
///
///   - Split `changedNodes` into two classes by comparing `old_tree.dist[n]`
///     to `new_tree.dist[n]`: nodes whose distance to the destination
///     DECREASES ("link-up" class, e.g. a shorter path just became
///     available) and nodes whose distance INCREASES ("link-down" class,
///     e.g. their old next-hop just got a worse path itself).
///   - **Decreasing-distance nodes must apply FIRST**, ordered so a node
///     switches to its new next-hop only once that next-hop is EITHER
///     unchanged OR has itself already switched — i.e. topologically sort
///     the decreasing class by the NEW tree's parent-before-child relation
///     (apply the node closest to the root first, since `new_tree.pred[n]`
///     for a decreasing node is, by construction, a node that is at least
///     as close to the destination and therefore safe to route through
///     immediately).
///   - **Increasing-distance nodes must apply LAST**, ordered by the OLD
///     tree's parent-before-child relation in REVERSE (apply the node
///     FARTHEST from the root first among this class) — a node whose own
///     distance is about to get worse must not switch until every node that
///     used to route THROUGH it (its old-tree children) has already moved
///     off of it, or those children would transiently point at a node that
///     just pointed itself further away, exactly the "ships passing"
///     A-points-to-B / B-points-to-A pattern this module's package doc
///     describes.
///   - RPF (reverse-path-forwarding) framing is the equivalent dual: instead
///     of an explicit apply order, tag each FIB entry with the (old or new)
///     tree "epoch" it belongs to and have forwarding accept a frame only
///     from the direction the CURRENT epoch's tree expects, rejecting
///     (dropping, not looping) anything that would arrive against the
///     grain — see IS-IS/SPB literature for the RPF-acceptance variant. A
///     Fable pass may implement either shape; the ordering shape is what
///     `fabric.zig`'s conductor expects back (`[]NodeId`), so an RPF-style
///     implementation should still surface AS an ordering (e.g. derive one
///     from the epoch tags) to keep this function's return type simple.
///
/// The encap TTL fabric operators fall back to in practice is only a
/// backstop against whatever a broken ordering misses — it bounds the
/// DAMAGE of a transient loop (a frame dies after N hops instead of
/// broadcast-storming forever), it does not prevent the loop from forming.
/// This function's job is to make transient loops IMPOSSIBLE, not merely
/// short-lived; `fabric.zig`'s invariant checker (`error.ForwardingLoop`)
/// accepts nothing less — it flags the loop on the very first revisit,
/// TTL or no TTL.
pub fn computeUpdateOrder(gpa: Allocator, old_tree: *const Tree, new_tree: *const Tree) OrderError![]NodeId {
    // Implementation: the classic two-class ordered-FIB schedule, as a single
    // total order over `changedNodes`:
    //
    //   Class A ("migrate early") — nodes whose distance to the destination
    //   STRICTLY DECREASED (`new_dist < old_dist`; includes newly-REACHABLE
    //   nodes, whose old distance is `unreachable_dist`). Applied FIRST, in
    //   ASCENDING new-distance order — parent-before-child on the NEW tree,
    //   so an A-node switches only after every changed node nearer to the
    //   destination on the new tree (in particular its new next-hop, if that
    //   next-hop decreased too) has already switched.
    //
    //   Class B ("migrate late") — everything else that changed next-hop:
    //   distance increased OR stayed equal with a different next-hop (the
    //   tie-break-shift case; its old path is gone but an equal-cost one
    //   exists), including newly-UNREACHABLE nodes (`new_dist` is
    //   `unreachable_dist`; their update installs the null next-hop = drop).
    //   Applied LAST, in DESCENDING old-distance order — child-before-parent
    //   on the OLD tree, so a B-node keeps its stale route until every node
    //   that used to route THROUGH it has already migrated off of it.
    //
    //   Ties within a class break by ascending node id: deterministic, and
    //   harmless to the invariant (see below — the proof only needs the
    //   non-strict prefix inequalities, which ties satisfy either way).
    //
    // Why no prefix of this order can hold a forwarding loop. Fix any
    // intermediate state: U = the already-applied prefix; a node forwards
    // via `new_tree.pred` if it is in U, via `old_tree.pred` otherwise; a
    // node whose next-hop never changed forwards via BOTH trees' (identical)
    // edge at once. Suppose a directed cycle existed. Every edge of it is an
    // old-tree edge or a new-tree edge; a tree's pred-graph is acyclic
    // (weights >= 1 make pred chains strictly distance-decreasing), so the
    // cycle must mix: it contains at least one STRICT new edge (from a
    // changed node p in U) and one STRICT old edge (from a changed node q
    // not in U). Walk the cycle and pair the boundary runs:
    //
    //   * an OLD-run — a maximal stretch of old-tree edges — starts at some
    //     changed q not in U and ends entering some changed p in U (its next
    //     edge is strictly new). old_dist strictly decreases along it, so
    //     old_dist[p] < old_dist[q].
    //   * symmetrically a NEW-run runs from some changed p' in U into some
    //     changed q' not in U, and new_dist[q'] < new_dist[p'].
    //
    //   During phase A (U inside class A): a NEW-run's endpoint q' not in U
    //   cannot be class A — A applies ascending new_dist, so p' in U would
    //   force new_dist[p'] <= new_dist[q'], contradicting the run. So every
    //   such q' is class B, i.e. old_dist[q'] <= new_dist[q']. Now traverse
    //   the whole cycle tracking old_dist on old-runs and new_dist on
    //   new-runs: every edge strictly decreases the tracked value, every
    //   old->new switch happens at a class-A p (new_dist[p] < old_dist[p],
    //   a decrease), and every new->old switch at a class-B q'
    //   (old_dist[q'] <= new_dist[q'], no increase). One full lap would
    //   strictly decrease the value back onto itself — impossible.
    //
    //   During phase B (all of A applied, U covers A plus a prefix of B): an
    //   OLD-run's endpoint p in U cannot be class B — B applies descending
    //   old_dist, so q not in U (necessarily class B now) would force
    //   old_dist[p] >= old_dist[q], contradicting the run. So every old->new
    //   switch happens at a class-A p (a strict decrease again), and every
    //   new->old switch at a class-B q' (no increase): the same lap argument
    //   kills the cycle.
    //
    // Hence every prefix of the returned order — including the empty and
    // full ones — yields an acyclic forwarding graph; the per-class rules
    // above are exactly the Francois/Filsfils/Evans/Bonaventure ordered-FIB
    // conditions, and this argument extends them to arbitrary (old, new)
    // tree pairs, not just single-failure/single-recovery deltas.
    const order = try changedNodes(gpa, old_tree, new_tree);
    std.mem.sort(
        NodeId,
        order,
        UpdateOrderCtx{ .old_dist = old_tree.dist, .new_dist = new_tree.dist },
        UpdateOrderCtx.lessThan,
    );
    return order;
}

/// Sort context for `computeUpdateOrder` — see the ordering rules documented
/// there. Total, deterministic (final key = node id), allocation-free.
const UpdateOrderCtx = struct {
    old_dist: []const spf.Distance,
    new_dist: []const spf.Distance,

    /// Class A ("migrate early"): strictly-decreased distance to the
    /// destination, newly-reachable included (`old_dist` is the
    /// `unreachable_dist` sentinel, i.e. +inf, so any finite `new_dist`
    /// classifies as a decrease).
    fn migratesEarly(self: UpdateOrderCtx, n: NodeId) bool {
        return self.new_dist[n] < self.old_dist[n];
    }

    fn lessThan(self: UpdateOrderCtx, a: NodeId, b: NodeId) bool {
        const a_early = self.migratesEarly(a);
        const b_early = self.migratesEarly(b);
        if (a_early != b_early) return a_early; // all of class A before all of class B
        if (a_early) {
            // Within class A: ascending NEW distance (new-tree parents first).
            if (self.new_dist[a] != self.new_dist[b]) return self.new_dist[a] < self.new_dist[b];
        } else {
            // Within class B: descending OLD distance (old-tree children first).
            if (self.old_dist[a] != self.old_dist[b]) return self.old_dist[a] > self.old_dist[b];
        }
        return a < b; // deterministic tie-break
    }
};

const testing = std.testing;

test "changedNodes: identical trees report no changes" {
    const gpa = testing.allocator;
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    try g.addEdge(0, 1, 1);
    try g.addEdge(1, 2, 1);
    var t1 = try spf.shortestPathTree(gpa, &g, 0);
    defer t1.deinit();
    var t2 = try spf.shortestPathTree(gpa, &g, 0);
    defer t2.deinit();

    const changed = try changedNodes(gpa, &t1, &t2);
    defer gpa.free(changed);
    try testing.expectEqual(@as(usize, 0), changed.len);
}

/// Build a synthetic `Tree` directly from `dist`/`pred` arrays (no `Graph`/SPF
/// run involved) — the only way to construct an (old, new) tree PAIR where
/// BOTH ordering classes are populated at once. A single real topology event
/// (one edge up or down) can never do this: removing an edge cannot decrease
/// any node's shortest-path distance, and restoring one cannot increase any —
/// so every `computeUpdateOrder` call driven by `fabric.zig`'s single-edge
/// fault model sees an ALL-decrease or ALL-increase changed set, never a mix.
/// That means the class-A-before-class-B rule (the algorithm's central
/// safety property, and the whole reason `computeUpdateOrder` exists instead
/// of `naiveBadOrder`) is never exercised by the netsim-driven suite — not
/// even by the 5000-seed sweep in `root.zig`'s "teeth-at-scale" test. This
/// helper drives `computeUpdateOrder` directly so the ordering rule itself
/// has a pinned, table-driven answer independent of any simulation.
fn synthTree(gpa: std.mem.Allocator, dist: []const spf.Distance, pred: []const ?NodeId) !Tree {
    const d = try gpa.dupe(spf.Distance, dist);
    const p = try gpa.dupe(?NodeId, pred);
    return .{ .gpa = gpa, .root = 0, .dist = d, .pred = p };
}

test "computeUpdateOrder: mixed increase+decrease set — class A entirely before class B, correct intra-class direction" {
    const gpa = testing.allocator;
    // 6 nodes (0 = dest/root, unchanged). Distances chosen so every node's
    // classification and relative rank is unambiguous:
    //   node1: 10 -> 5   (class A, new_dist=5)
    //   node2: 20 -> 12  (class A, new_dist=12)
    //   node3: 30 -> 45  (class B, old_dist=30)
    //   node4: 40 -> 42  (class B, old_dist=40)
    //   node5: 50 -> 50  (class B: distance TIED but next-hop shifted, old_dist=50)
    var old_tree = try synthTree(
        gpa,
        &.{ 0, 10, 20, 30, 40, 50 },
        &.{ null, 0, 0, 0, 0, 0 },
    );
    defer old_tree.deinit();
    var new_tree = try synthTree(
        gpa,
        &.{ 0, 5, 12, 45, 42, 50 },
        &.{ null, 9, 9, 9, 9, 9 }, // all differ from old_tree's pred so every node of 1..5 is "changed"
    );
    defer new_tree.deinit();

    const order = try computeUpdateOrder(gpa, &old_tree, &new_tree);
    defer gpa.free(order);

    // Class A (ascending new_dist: 1 before 2), THEN class B (descending
    // old_dist: 5, 4, 3).
    try testing.expectEqualSlices(NodeId, &.{ 1, 2, 5, 4, 3 }, order);
}

test "naiveBadOrder: returns exactly the changed set, ascending by id (not a stub)" {
    const gpa = testing.allocator;
    // 0 -- 1 -- 2, then a cheaper direct 0--2 edge appears (simulating a
    // topology change): node 1's next-hop is unaffected, node 2's next-hop
    // flips from 1 to 0.
    var g_old = spf.Graph.init(gpa);
    defer g_old.deinit();
    try g_old.addEdge(0, 1, 1);
    try g_old.addEdge(1, 2, 1);
    var old_tree = try spf.shortestPathTree(gpa, &g_old, 0);
    defer old_tree.deinit();

    var g_new = spf.Graph.init(gpa);
    defer g_new.deinit();
    try g_new.addEdge(0, 1, 1);
    try g_new.addEdge(1, 2, 1);
    try g_new.addEdge(0, 2, 1);
    var new_tree = try spf.shortestPathTree(gpa, &g_new, 0);
    defer new_tree.deinit();

    const order = try naiveBadOrder(gpa, &old_tree, &new_tree);
    defer gpa.free(order);
    try testing.expectEqualSlices(NodeId, &.{2}, order);
}
