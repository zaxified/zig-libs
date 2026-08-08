// SPDX-License-Identifier: MIT
//! bumtree — SPB per-source loop-free BUM (broadcast/unknown-unicast/multicast)
//! distribution tree + Reverse-Path-Forwarding check, over the M0 `spf-ect`
//! shortest-path engine.
//!
//! In 802.1aq SPBM, BUM traffic for an I-SID is delivered on **per-source
//! shortest-path trees**: for a given source node `S`, the distribution tree is
//! `S`'s shortest-path tree (SPT), pruned to the branches that lead to a member
//! of the I-SID. For ONE source and ONE member set this module computes, per
//! node `N`:
//!
//!   1. **Replication next-hops** — the neighbours `N` must replicate a
//!      BUM-from-`S` frame to = `N`'s children in `S`'s SPT (nodes whose SPT
//!      predecessor is `N`), pruned to only children whose subtree contains at
//!      least one member (never flood toward a member-less branch). If `N` is
//!      itself a member it also delivers the frame locally (`is_member`).
//!   2. **RPF (Reverse-Path-Forwarding) ingress** — the ONE neighbour a
//!      BUM-from-`S` frame may legally arrive on = `N`'s SPT predecessor toward
//!      `S`. A frame from `S` arriving on any other edge is dropped. This is the
//!      loop/duplicate backstop.
//!
//! This is the control-plane loop-free BUM tree that the data-plane
//! `l2encap`/`l2forward` explicitly defer to. Two data-plane rules sit below it,
//! and neither is a substitute:
//!
//!   * `l2encap.droppedBySplitHorizon` stops **reflection only** — a frame handed
//!     back to the PE that ingress-replicated it. It cannot see a *relayed* copy,
//!     because `ingress_pe` names the originator and is preserved across
//!     `decrementTtl`, so a third PE never matches on it. (This module's doc
//!     comment used to call that rule "source-PE split-horizon", which reads as
//!     the broader guarantee it is not.)
//!   * `l2forward` closes the **steady-state core relay** — the exponential
//!     duplication a converged fabric produced when a core-received BUM frame was
//!     re-replicated to every other member — by classifying the frame's arrival,
//!     not by inspecting `ingress_pe`.
//!
//! What is left after both, and what this module is for: a **transient forwarding
//! loop** among other nodes during reconvergence, and duplicate delivery. RPF +
//! the pruned SPT are what stop those. See both those modules' SPECs ("Honest
//! scope of the loop claim").
//!
//! Loop-freedom is by construction: an SPT is a tree (acyclic), so tree-flooding
//! terminates and reaches each node once; RPF enforces a single valid ingress, so
//! even while the network is mid-reconvergence and some node holds a stale tree, a
//! frame that took a wrong path is dropped at the first node whose RPF predecessor
//! it did not arrive from — no loop, no duplicate. Congruency: `spf-ect`'s
//! deterministic ECT tie-break makes the `S`-rooted SPT identical at every node
//! that computes it from the same topology, so all nodes agree on the same tree
//! and mutually-consistent RPF checks (the SPB symmetry property).
//!
//! Scope is tight: per-source pruned SPT + replication next-hops + RPF, for ONE
//! source — the caller iterates sources. The upstream that builds the
//! `spf-ect.Graph` from a link-state database is `isis-spf`; this module takes the
//! graph directly and parses no LSDB. See `SPEC.md` for the deferred list.

const std = @import("std");
const spf = @import("spf-ect");

const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "IEEE 802.1aq per-source SPT multicast trees + RPFC (SPBM)",
    .deps = .{"spf-ect"},
};

/// Node identity — the same dense `[0, graph.nodeCount())` id `spf-ect` uses.
pub const NodeId = spf.NodeId;

/// Per-node BUM-forwarding plan for one source's tree. Indexed by `NodeId`.
pub const NodePlan = struct {
    /// The RPF ingress: the ONE neighbour a BUM-from-source frame may legally
    /// arrive on = this node's SPT predecessor toward the source. `null` for the
    /// source itself (it originates the frame, it never accepts one from the
    /// network) and for nodes unreachable from the source.
    rpf_ingress: ?NodeId,
    /// Children in the source's SPT whose subtree contains at least one member —
    /// the set this node must replicate a BUM-from-source frame to. Sorted
    /// ascending (deterministic). Empty for a leaf, a source with no
    /// member-bearing children, or (when pruning is on) any node all of whose
    /// SPT-children lead to member-less branches. Borrowed from the owning
    /// `BumTree` — valid until its `deinit`.
    replicate_to: []const NodeId,
    /// Is this node itself an I-SID member (→ deliver the frame locally)? Set for
    /// every member id in range, even one unreachable from the source (which
    /// simply never receives the frame).
    is_member: bool,
};

/// Tuning for `buildWith`. The default is the correct SPBM behaviour; the
/// non-default exists only for the permanent positive control.
pub const Options = struct {
    /// Member-pruning. When `true` (default, correct) a child is a replication
    /// target only if its SPT subtree contains a member, so BUM is never flooded
    /// down a member-less branch. When `false` EVERY SPT child is a replication
    /// target — deliberately WRONG (floods member-less branches, wasting the
    /// fabric and delivering toward non-members); kept solely to prove, in a
    /// permanent test, that pruning is load-bearing.
    prune: bool = true,

    /// Test-only instrumentation: when non-null, incremented once per visit
    /// of the member-pruning walk's `while (true)` body (i.e. once per
    /// `has_member[cur]` check in `buildWith`). Lets a test assert the walk
    /// stays `O(nodes)` regardless of member count, per the doc comment on
    /// `buildWith`'s algorithm step 2. Never read by production code.
    mark_steps: ?*usize = null,
};

/// One source's pruned per-source BUM distribution tree + RPF plan. Caller-owned;
/// free with `deinit`. `plan(n)`/`replicateTo(n)`/`rpfIngress(n)`/`rpfCheck(...)`/
/// `isMember(n)` are all bounds-safe (an out-of-range `NodeId` reads as an
/// absent/empty/false default, never a panic).
pub const BumTree = struct {
    gpa: Allocator,
    /// The source this tree is rooted at (as passed to `build`).
    source: NodeId,
    /// `graph.nodeCount()` at build time — the valid `NodeId` range is
    /// `[0, node_count)`. `0` when the source was not a node of the graph.
    node_count: u32,
    /// Per-node plans, indexed by `NodeId`; length `node_count`.
    nodes: []NodePlan,
    /// Contiguous backing store the per-node `replicate_to` slices point into.
    backing: []NodeId,

    pub fn deinit(self: *BumTree) void {
        self.gpa.free(self.backing);
        self.gpa.free(self.nodes);
        self.* = undefined;
    }

    /// This node's plan, or `null` if `node` is out of range.
    pub fn plan(self: *const BumTree, node: NodeId) ?NodePlan {
        if (node >= self.node_count) return null;
        return self.nodes[node];
    }

    /// The single valid RPF ingress neighbour for `node` (its SPT predecessor
    /// toward the source), or `null` for the source, an unreachable node, or an
    /// out-of-range id.
    pub fn rpfIngress(self: *const BumTree, node: NodeId) ?NodeId {
        if (node >= self.node_count) return null;
        return self.nodes[node].rpf_ingress;
    }

    /// The RPF gate: may a BUM-from-source frame that arrived at `node` from
    /// neighbour `ingress` be accepted? True iff `ingress` is exactly `node`'s
    /// RPF ingress. Always false at the source (it has no valid ingress — it is
    /// the origin) and for an unreachable/out-of-range `node`.
    pub fn rpfCheck(self: *const BumTree, node: NodeId, ingress: NodeId) bool {
        const rpf = self.rpfIngress(node) orelse return false;
        return rpf == ingress;
    }

    /// The (sorted, pruned) set of neighbours `node` replicates a BUM-from-source
    /// frame to. Empty for a leaf / member-less-subtree node / out-of-range id.
    pub fn replicateTo(self: *const BumTree, node: NodeId) []const NodeId {
        if (node >= self.node_count) return &.{};
        return self.nodes[node].replicate_to;
    }

    /// Is `node` an I-SID member (→ local delivery)? False for an out-of-range id.
    ///
    /// NOTE: `true` does not by itself mean `node` will ever RECEIVE a
    /// BUM-from-source frame to deliver locally -- `is_member` is set for
    /// every in-range member id, even one unreachable from `source`, which
    /// "simply never receives the frame" (see `NodePlan.is_member`'s doc
    /// comment). A caller that wants "will this node actually deliver
    /// locally" must consult `deliversLocally`, not this alone (wave-2
    /// audit finding `bumtree` F5).
    pub fn isMember(self: *const BumTree, node: NodeId) bool {
        if (node >= self.node_count) return false;
        return self.nodes[node].is_member;
    }

    /// Is `node` an I-SID member that will ACTUALLY deliver a
    /// BUM-from-source frame locally? True iff `isMember(node)` AND `node`
    /// is reachable from `source` -- either `node == source` (the source
    /// always "receives" its own originated frame) or `rpfIngress(node) !=
    /// null` (it has an SPT predecessor, i.e. it's on the tree). Closes the
    /// gap `isMember` alone leaves: an in-range member partitioned away
    /// from `source` has `isMember == true` but `deliversLocally == false`.
    pub fn deliversLocally(self: *const BumTree, node: NodeId) bool {
        if (!self.isMember(node)) return false;
        return node == self.source or self.rpfIngress(node) != null;
    }
};

/// Build the per-source pruned BUM distribution tree + RPF plan for `source` over
/// `graph`, delivering to `members`, with correct member pruning.
///
/// `members` is the I-SID's member node set (duplicates and out-of-range ids are
/// tolerated; an out-of-range id is ignored, an in-range-but-unreachable member
/// is marked `is_member` yet simply never receives the frame). See `buildWith`
/// for the degenerate cases.
pub fn build(
    gpa: Allocator,
    graph: *const spf.Graph,
    source: NodeId,
    members: []const NodeId,
) Allocator.Error!BumTree {
    return buildWith(gpa, graph, source, members, .{});
}

/// `build` with explicit `Options`.
///
/// Algorithm:
///   1. `spf-ect.shortestPathTree(graph, source)` → the SPT rooted at `source`.
///      `tree.pred[N]` is `N`'s next hop toward `source`; `N`'s children are
///      `{ C : pred[C] == N }`.
///   2. **Member pruning** — for each member, walk its predecessor chain up to
///      the source, marking every node on the way as "has a member in its
///      subtree" (short-circuiting the first already-marked ancestor, so the
///      whole pass is O(nodes)). A child `C` is a replication target of `N` iff
///      `C`'s subtree has a member.
///   3. **Replication next-hops** — iterating child ids ascending yields each
///      parent's `replicate_to` already sorted, deterministically.
///   4. **RPF** — `rpf_ingress[N] = pred[N]`.
///
/// Degenerate cases (all documented, none panic):
///   - **Source not a node of the graph** (`source >= graph.nodeCount()`) — an
///     empty tree: `node_count == 0`, every accessor returns its absent/empty/
///     false default.
///   - **No members / empty `members`** — every node's `replicate_to` is empty
///     (nothing to deliver), RPF ingresses are still populated.
///   - **Single member == source** — local delivery at the source only, no
///     replication (`is_member(source)` true, all `replicate_to` empty).
///   - **Source present but isolated** — only the source is reachable; its
///     `replicate_to` is empty and every other node is unreachable
///     (`rpf_ingress == null`).
pub fn buildWith(
    gpa: Allocator,
    graph: *const spf.Graph,
    source: NodeId,
    members: []const NodeId,
    opts: Options,
) Allocator.Error!BumTree {
    const n = graph.nodeCount();

    // Source not in the graph → defined empty result.
    if (source >= n) {
        return .{
            .gpa = gpa,
            .source = source,
            .node_count = 0,
            .nodes = try gpa.alloc(NodePlan, 0),
            .backing = try gpa.alloc(NodeId, 0),
        };
    }

    var tree = try spf.shortestPathTree(gpa, graph, source);
    defer tree.deinit();

    // ── membership + subtree marking ─────────────────────────────────────────
    const is_member = try gpa.alloc(bool, n);
    defer gpa.free(is_member);
    @memset(is_member, false);
    // has_member[N] — does N's SPT subtree (N itself or any descendant) hold a
    // member? Built by walking each reachable member up to the source.
    const has_member = try gpa.alloc(bool, n);
    defer gpa.free(has_member);
    @memset(has_member, false);

    for (members) |m| {
        if (m >= n) continue; // out-of-range member id: ignored
        is_member[m] = true;
    }
    for (members) |m| {
        if (m >= n or !tree.reachable(m)) continue;
        var cur = m;
        while (true) {
            if (opts.mark_steps) |s| s.* += 1;
            if (has_member[cur]) break; // this node (and its ancestors) already marked
            has_member[cur] = true;
            if (cur == source) break;
            cur = tree.pred[cur].?; // reachable non-source always has a predecessor
        }
    }

    // ── count replication targets per parent (for a single contiguous alloc) ──
    const counts = try gpa.alloc(usize, n);
    defer gpa.free(counts);
    @memset(counts, 0);
    {
        var c: NodeId = 0;
        while (c < n) : (c += 1) {
            if (c == source or !tree.reachable(c)) continue;
            if (included(opts, has_member, c)) counts[tree.pred[c].?] += 1;
        }
    }
    var total: usize = 0;
    for (counts) |k| total += k;

    const backing = try gpa.alloc(NodeId, total);
    errdefer gpa.free(backing);
    const nodes = try gpa.alloc(NodePlan, n);
    errdefer gpa.free(nodes);

    // Prefix-sum offsets into `backing`, one contiguous run per parent.
    const offset = try gpa.alloc(usize, n);
    defer gpa.free(offset);
    {
        var acc: usize = 0;
        for (0..n) |i| {
            offset[i] = acc;
            acc += counts[i];
        }
    }

    // Fill each parent's run in ascending child order (⇒ each run is sorted).
    {
        const fill = try gpa.alloc(usize, n);
        defer gpa.free(fill);
        @memset(fill, 0);
        var c: NodeId = 0;
        while (c < n) : (c += 1) {
            if (c == source or !tree.reachable(c)) continue;
            if (!included(opts, has_member, c)) continue;
            const parent = tree.pred[c].?;
            backing[offset[parent] + fill[parent]] = c;
            fill[parent] += 1;
        }
    }

    for (0..n) |i| {
        nodes[i] = .{
            // pred[i] is null for the source and for unreachable nodes — exactly
            // the "no valid RPF ingress" cases.
            .rpf_ingress = tree.pred[i],
            .replicate_to = backing[offset[i] .. offset[i] + counts[i]],
            .is_member = is_member[i],
        };
    }

    return .{
        .gpa = gpa,
        .source = source,
        .node_count = n,
        .nodes = nodes,
        .backing = backing,
    };
}

/// Is child `c` a replication target under `opts`? With pruning on, iff its
/// subtree holds a member; with pruning off, always (the positive control).
fn included(opts: Options, has_member: []const bool, c: NodeId) bool {
    return if (opts.prune) has_member[c] else true;
}

// ─────────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The golden fixture — a pure tree (so the SPT is unambiguous, no equal-cost
/// ties to reason about) with one deliberately member-less branch (node 6):
///
/// ```
///            0  (source)
///           / \
///          1   2
///         /|    \
///        3 6     4
///                |
///                5
/// ```
/// Members {3, 5}. Node 6 hangs off 1 but is not a member and has no member
/// below it, so it must be pruned from 1's replication set.
fn goldenGraph(gpa: Allocator) !spf.Graph {
    var g = spf.Graph.init(gpa);
    errdefer g.deinit();
    try g.addEdge(0, 1, 1);
    try g.addEdge(0, 2, 1);
    try g.addEdge(1, 3, 1);
    try g.addEdge(1, 6, 1);
    try g.addEdge(2, 4, 1);
    try g.addEdge(4, 5, 1);
    return g;
}

test "golden: exact replication next-hops, RPF ingress, is_member" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    var bt = try build(gpa, &g, 0, &.{ 3, 5 });
    defer bt.deinit();

    // Replication next-hops (children with a member in their subtree).
    try testing.expectEqualSlices(NodeId, &.{ 1, 2 }, bt.replicateTo(0));
    try testing.expectEqualSlices(NodeId, &.{3}, bt.replicateTo(1)); // 6 pruned
    try testing.expectEqualSlices(NodeId, &.{4}, bt.replicateTo(2));
    try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(3));
    try testing.expectEqualSlices(NodeId, &.{5}, bt.replicateTo(4));
    try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(5));
    try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(6));

    // RPF ingress = SPT predecessor toward the source.
    try testing.expectEqual(@as(?NodeId, null), bt.rpfIngress(0));
    try testing.expectEqual(@as(?NodeId, 0), bt.rpfIngress(1));
    try testing.expectEqual(@as(?NodeId, 0), bt.rpfIngress(2));
    try testing.expectEqual(@as(?NodeId, 1), bt.rpfIngress(3));
    try testing.expectEqual(@as(?NodeId, 2), bt.rpfIngress(4));
    try testing.expectEqual(@as(?NodeId, 4), bt.rpfIngress(5));
    try testing.expectEqual(@as(?NodeId, 1), bt.rpfIngress(6));

    // Local delivery flags.
    for ([_]NodeId{ 0, 1, 2, 4, 6 }) |x| try testing.expect(!bt.isMember(x));
    for ([_]NodeId{ 3, 5 }) |x| try testing.expect(bt.isMember(x));
}

test "plan: matches the per-field accessors and returns null out of range" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    var bt = try build(gpa, &g, 0, &.{ 3, 5 });
    defer bt.deinit();

    var node: NodeId = 0;
    while (node < bt.node_count) : (node += 1) {
        const p = bt.plan(node).?;
        try testing.expectEqual(bt.rpfIngress(node), p.rpf_ingress);
        try testing.expectEqual(bt.isMember(node), p.is_member);
        try testing.expectEqualSlices(NodeId, bt.replicateTo(node), p.replicate_to);
    }
    // Exactly at and beyond node_count: out of range, defined null.
    try testing.expectEqual(@as(?NodePlan, null), bt.plan(bt.node_count));
    try testing.expectEqual(@as(?NodePlan, null), bt.plan(bt.node_count + 50));
}

test "member pruning: a member-less branch is absent until it gains a member" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    // Without a member on the {1→6} branch, 6 is not a replication target of 1.
    {
        var bt = try build(gpa, &g, 0, &.{ 3, 5 });
        defer bt.deinit();
        try testing.expectEqualSlices(NodeId, &.{3}, bt.replicateTo(1));
    }
    // Make 6 a member → the branch appears (sorted: {3, 6}).
    {
        var bt = try build(gpa, &g, 0, &.{ 3, 5, 6 });
        defer bt.deinit();
        try testing.expectEqualSlices(NodeId, &.{ 3, 6 }, bt.replicateTo(1));
        try testing.expect(bt.isMember(6));
    }
}

test "RPF: the predecessor is accepted, every other ingress is dropped" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    var bt = try build(gpa, &g, 0, &.{ 3, 5 });
    defer bt.deinit();

    // For every reachable non-source node, exactly one neighbour (pred) passes.
    var node: NodeId = 0;
    while (node < g.nodeCount()) : (node += 1) {
        const pred = bt.rpfIngress(node) orelse continue; // source: no ingress
        for (g.neighbors(node)) |e| {
            try testing.expectEqual(e.to == pred, bt.rpfCheck(node, e.to));
        }
    }
    // Spot-checks with several ingresses at node 1 (neighbours 0, 3, 6).
    try testing.expect(bt.rpfCheck(1, 0)); // parent toward source: accept
    try testing.expect(!bt.rpfCheck(1, 3)); // a wrong-way ingress: drop
    try testing.expect(!bt.rpfCheck(1, 6));
    // The source never accepts a BUM-from-source frame from the network.
    try testing.expect(!bt.rpfCheck(0, 1));
    try testing.expect(!bt.rpfCheck(0, 2));
}

/// Flood a BUM-from-source frame down the pruned `replicate_to` tree, delivering
/// at every member, and record how many times each node is visited.
fn floodViaTree(gpa: Allocator, bt: *const BumTree) ![]u32 {
    const visits = try gpa.alloc(u32, bt.node_count);
    @memset(visits, 0);
    var stack: std.ArrayList(NodeId) = .empty;
    defer stack.deinit(gpa);
    try stack.append(gpa, bt.source);
    while (stack.pop()) |node| {
        visits[node] += 1;
        for (bt.replicateTo(node)) |child| try stack.append(gpa, child);
    }
    return visits;
}

test "loop-freedom: tree flood delivers to each member exactly once, skips member-less branches" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    var bt = try build(gpa, &g, 0, &.{ 3, 5 });
    defer bt.deinit();

    const visits = try floodViaTree(gpa, &bt);
    defer gpa.free(visits);

    // Every member receives the frame exactly once…
    try testing.expectEqual(@as(u32, 1), visits[3]);
    try testing.expectEqual(@as(u32, 1), visits[5]);
    // …no node is processed more than once (tree ⇒ no loop, no duplicate)…
    for (visits) |v| try testing.expect(v <= 1);
    // …and the member-less branch (node 6) is never reached.
    try testing.expectEqual(@as(u32, 0), visits[6]);
}

/// Worst-case reconvergence flood: every node that ACCEPTS the frame re-floods it
/// to all of its graph neighbours (modelling nodes that hold a stale tree and do
/// not prune). Each receiver applies the RPF gate when `enforce_rpf` is set. TTL-
/// bounded so the broken (no-RPF) mode still terminates. Returns the per-node
/// accept count — the payoff metric: with RPF it must be ≤ 1 everywhere.
fn floodWithRpf(gpa: Allocator, g: *const spf.Graph, bt: *const BumTree, enforce_rpf: bool) ![]u32 {
    const n = g.nodeCount();
    const accepts = try gpa.alloc(u32, n);
    @memset(accepts, 0);

    const Ev = struct { node: NodeId, ingress: ?NodeId, ttl: u32 };
    var queue: std.ArrayList(Ev) = .empty;
    defer queue.deinit(gpa);
    // Source originates the frame (no ingress); generous TTL so an unbounded
    // loop in the broken mode still halts.
    try queue.append(gpa, .{ .node = bt.source, .ingress = null, .ttl = n + 2 });

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const ev = queue.items[head];
        if (ev.node != bt.source) {
            if (enforce_rpf and !(ev.ingress != null and bt.rpfCheck(ev.node, ev.ingress.?))) {
                continue; // RPF drop
            }
        }
        accepts[ev.node] += 1;
        if (ev.ttl == 0) continue;
        for (g.neighbors(ev.node)) |e| {
            if (ev.ingress) |in| if (e.to == in) continue; // never straight back
            try queue.append(gpa, .{ .node = e.to, .ingress = ev.node, .ttl = ev.ttl - 1 });
        }
    }
    return accepts;
}

test "RPF backstop: single acceptance under a reconvergence flood; no-RPF duplicates (positive control)" {
    const gpa = testing.allocator;
    // A MESHED graph with redundant paths (cycles) — RPF only earns its keep
    // where more than one edge can carry the frame toward a node. (A pure tree
    // like the golden fixture never duplicates even without RPF, which is exactly
    // why this test needs cycles.) Triangle {0,1,2} plus node 3 dual-homed to
    // 1 and 2, all weight 1.
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    try g.addEdge(0, 1, 1);
    try g.addEdge(0, 2, 1);
    try g.addEdge(1, 2, 1);
    try g.addEdge(1, 3, 1);
    try g.addEdge(2, 3, 1);

    var bt = try build(gpa, &g, 0, &.{ 1, 2, 3 });
    defer bt.deinit();

    // With RPF: even under a flood where every node re-floods to ALL neighbours,
    // each reachable node accepts exactly once (its frame from the RPF ingress);
    // every wrong-ingress copy — including the ones arriving over the redundant
    // 1↔2 chord and the second home of 3 — is dropped ⇒ no loop, no duplicate.
    {
        const accepts = try floodWithRpf(gpa, &g, &bt, true);
        defer gpa.free(accepts);
        for (accepts) |a| try testing.expect(a <= 1);
        for ([_]NodeId{ 1, 2, 3 }) |member| try testing.expectEqual(@as(u32, 1), accepts[member]);
    }
    // Positive control: drop the RPF gate and the very same flood duplicates over
    // those redundant edges — some node is accepted more than once. This is what
    // proves RPF is load-bearing; if it ever passes, RPF has silently broken.
    {
        const accepts = try floodWithRpf(gpa, &g, &bt, false);
        defer gpa.free(accepts);
        var max: u32 = 0;
        for (accepts) |a| max = @max(max, a);
        try testing.expect(max > 1);
    }
}

test "positive control: prune=false floods the member-less branch (pruning is load-bearing)" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    // Correct (pruned): 6 absent from 1's replication set.
    {
        var bt = try buildWith(gpa, &g, 0, &.{ 3, 5 }, .{ .prune = true });
        defer bt.deinit();
        try testing.expectEqualSlices(NodeId, &.{3}, bt.replicateTo(1));
    }
    // Broken (unpruned): 6 IS a replication target although its branch has no
    // member — the tree flood would then waste the fabric delivering toward a
    // non-member. Proves the prune flag actually gates the branch.
    {
        var bt = try buildWith(gpa, &g, 0, &.{ 3, 5 }, .{ .prune = false });
        defer bt.deinit();
        try testing.expectEqualSlices(NodeId, &.{ 3, 6 }, bt.replicateTo(1));
        const visits = try floodViaTree(gpa, &bt);
        defer gpa.free(visits);
        try testing.expectEqual(@as(u32, 1), visits[6]); // member-less node reached
    }
}

test "congruency/determinism: identical result regardless of edge-insertion order" {
    const gpa = testing.allocator;

    // Same topology as the golden fixture, edges added in a scrambled order.
    var g2 = spf.Graph.init(gpa);
    defer g2.deinit();
    try g2.addEdge(4, 5, 1);
    try g2.addEdge(1, 6, 1);
    try g2.addEdge(0, 2, 1);
    try g2.addEdge(2, 4, 1);
    try g2.addEdge(1, 3, 1);
    try g2.addEdge(0, 1, 1);

    var g1 = try goldenGraph(gpa);
    defer g1.deinit();

    var a = try build(gpa, &g1, 0, &.{ 3, 5 });
    defer a.deinit();
    var b = try build(gpa, &g2, 0, &.{ 3, 5 });
    defer b.deinit();

    try testing.expectEqual(a.node_count, b.node_count);
    var node: NodeId = 0;
    while (node < a.node_count) : (node += 1) {
        try testing.expectEqual(a.rpfIngress(node), b.rpfIngress(node));
        try testing.expectEqual(a.isMember(node), b.isMember(node));
        try testing.expectEqualSlices(NodeId, a.replicateTo(node), b.replicateTo(node));
    }

    // And a plain rebuild of the same graph is byte-identical too.
    var a2 = try build(gpa, &g1, 0, &.{ 3, 5 });
    defer a2.deinit();
    node = 0;
    while (node < a.node_count) : (node += 1) {
        try testing.expectEqualSlices(NodeId, a.replicateTo(node), a2.replicateTo(node));
    }
}

test "congruency: an equal-cost diamond resolves to one deterministic source-rooted tree" {
    const gpa = testing.allocator;
    // Diamond with two equal-cost paths 0→1→3 and 0→2→3 (all weight 10). The ECT
    // tie-break in spf-ect picks exactly one parent for 3, the SAME one every
    // time — so the source-rooted BUM tree is congruent, not observer-dependent.
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    try g.addEdge(0, 1, 10);
    try g.addEdge(0, 2, 10);
    try g.addEdge(1, 3, 10);
    try g.addEdge(2, 3, 10);

    var t1 = try build(gpa, &g, 0, &.{3});
    defer t1.deinit();
    var t2 = try build(gpa, &g, 0, &.{3});
    defer t2.deinit();

    const pred3 = t1.rpfIngress(3).?;
    try testing.expect(pred3 == 1 or pred3 == 2); // one legitimate parent
    try testing.expectEqual(t1.rpfIngress(3), t2.rpfIngress(3)); // stable
    // Only the winning parent replicates to 3; the loser does not.
    const winner = pred3;
    const loser: NodeId = if (winner == 1) 2 else 1;
    try testing.expectEqualSlices(NodeId, &.{3}, t1.replicateTo(winner));
    try testing.expectEqualSlices(NodeId, &.{}, t1.replicateTo(loser));
}

test "degenerate: source not in graph, no members, single member == source, isolated source" {
    const gpa = testing.allocator;

    // Source id past the node range → defined empty tree.
    {
        var g = try goldenGraph(gpa);
        defer g.deinit();
        var bt = try build(gpa, &g, 99, &.{3});
        defer bt.deinit();
        try testing.expectEqual(@as(u32, 0), bt.node_count);
        try testing.expectEqual(@as(?NodeId, null), bt.rpfIngress(0));
        try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(0));
        try testing.expect(!bt.isMember(3));
        try testing.expect(!bt.rpfCheck(0, 1));
    }
    // No members → nothing replicated anywhere, RPF ingresses still populated.
    {
        var g = try goldenGraph(gpa);
        defer g.deinit();
        var bt = try build(gpa, &g, 0, &.{});
        defer bt.deinit();
        var node: NodeId = 0;
        while (node < bt.node_count) : (node += 1) {
            try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(node));
            try testing.expect(!bt.isMember(node));
        }
        try testing.expectEqual(@as(?NodeId, 2), bt.rpfIngress(4));
    }
    // Single member == source → local delivery only, no replication.
    {
        var g = try goldenGraph(gpa);
        defer g.deinit();
        var bt = try build(gpa, &g, 0, &.{0});
        defer bt.deinit();
        try testing.expect(bt.isMember(0));
        var node: NodeId = 0;
        while (node < bt.node_count) : (node += 1)
            try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(node));
    }
    // Source present but isolated → only the source is reachable.
    {
        var g = spf.Graph.init(gpa);
        defer g.deinit();
        try g.addEdge(1, 2, 1); // component that does not contain node 0
        try g.ensureNode(0); // node 0 exists but is isolated
        var bt = try build(gpa, &g, 0, &.{ 1, 2 });
        defer bt.deinit();
        try testing.expectEqualSlices(NodeId, &.{}, bt.replicateTo(0));
        try testing.expectEqual(@as(?NodeId, null), bt.rpfIngress(1)); // unreachable
        try testing.expectEqual(@as(?NodeId, null), bt.rpfIngress(2));
        // Members are flagged even though unreachable (they never receive).
        try testing.expect(bt.isMember(1) and bt.isMember(2));
        // F5 regression: `isMember` alone is a trap here -- both are
        // members but neither will ever actually deliver, since neither is
        // reachable from source 0. `deliversLocally` must say so.
        try testing.expect(!bt.deliversLocally(1));
        try testing.expect(!bt.deliversLocally(2));
        // The source itself always delivers locally when it's a member
        // (positive control, reusing the "single member == source" case
        // above's tree shape via a fresh build here for a self-contained
        // assertion).
        var g2 = try goldenGraph(gpa);
        defer g2.deinit();
        var bt2 = try build(gpa, &g2, 0, &.{0});
        defer bt2.deinit();
        try testing.expect(bt2.deliversLocally(0));
    }
}

test "out-of-range member id (including exactly node_count) is ignored, not a bounds violation" {
    const gpa = testing.allocator;
    var g = try goldenGraph(gpa);
    defer g.deinit();

    // node_count == 7 (ids 0..6). Mix valid members with out-of-range ones,
    // including the boundary id == node_count itself.
    var bt = try build(gpa, &g, 0, &.{ 3, 5, g.nodeCount(), 999 });
    defer bt.deinit();

    try testing.expectEqual(g.nodeCount(), bt.node_count);
    // Valid members still recognized and still drive replication normally.
    try testing.expect(bt.isMember(3));
    try testing.expect(bt.isMember(5));
    try testing.expectEqualSlices(NodeId, &.{3}, bt.replicateTo(1)); // 6 still pruned
    try testing.expectEqualSlices(NodeId, &.{5}, bt.replicateTo(4));
    // Out-of-range ids are simply ignored (bounds-safe accessors, not a crash).
    try testing.expect(!bt.isMember(g.nodeCount()));
}

test "unreachable member: flagged but never a replication target" {
    const gpa = testing.allocator;
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    try g.addEdge(0, 1, 1); // component {0,1}
    try g.addEdge(2, 3, 1); // separate component {2,3}, unreachable from 0

    var bt = try build(gpa, &g, 0, &.{ 1, 3 });
    defer bt.deinit();
    try testing.expectEqualSlices(NodeId, &.{1}, bt.replicateTo(0)); // only reachable member's branch
    try testing.expect(bt.isMember(3)); // flagged…
    try testing.expectEqual(@as(?NodeId, null), bt.rpfIngress(3)); // …but unreachable
}

test "member-pruning walk is O(nodes), not O(members x depth): the has_member short-circuit is load-bearing" {
    // A depth-9 chain 0->1->...->9, source = 0, with the far leaf (9) listed
    // as a member 40 times over. The has_member[cur] short-circuit means the
    // first walk marks all 10 nodes and every subsequent duplicate walk
    // breaks after a single step, so total steps stay bounded in the number
    // of NODES, not (members x depth). Without the short-circuit each of
    // the 40 duplicate members would re-walk the full depth-9 chain.
    const gpa = testing.allocator;
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    const chain_len = 10;
    var i: NodeId = 0;
    while (i + 1 < chain_len) : (i += 1) try g.addEdge(i, i + 1, 1);

    var members: [40]NodeId = undefined;
    for (&members) |*m| m.* = chain_len - 1; // same far leaf, duplicated

    var steps: usize = 0;
    var bt = try buildWith(gpa, &g, 0, &members, .{ .mark_steps = &steps });
    defer bt.deinit();

    // O(nodes): bounded by node_count plus one cheap short-circuit check per
    // duplicate member. A broken (non-short-circuiting) walk would instead
    // cost members.len * chain_len == 400 steps, which this bound rejects.
    try testing.expect(steps <= chain_len + members.len);
}

test "meta is well-formed" {
    try testing.expectEqual(.any, meta.platform);
    try testing.expectEqual(.util, meta.role);
    try testing.expectEqual(.single_owner, meta.concurrency);
}
