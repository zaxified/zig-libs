// SPDX-License-Identifier: MIT
//! Distributed and multi-destination forms of the ordered-FIB schedule.
//!
//! `fib.zig` returns ONE global order for one destination with one next hop
//! per node. This file adds three things on top of the same two-class rule
//! (class A first by ascending new distance, class B last by descending old
//! distance):
//!
//!  * `RankTable`: the per-node form. A node that holds both trees (every IGP
//!    node has the whole LSDB, so it can run the SPF for the old and the new
//!    topology) derives its own `Rank` without any conductor; it reprograms its
//!    FIB at `rank * max_fib` after the hold-down, as RFC 6976 section 4 does.
//!    Nodes of equal rank may update at the same time.
//!  * `Ecmp`: a next-hop SET per node instead of one predecessor. The proof in
//!    `fib.zig` only uses that every forwarding edge strictly decreases the
//!    distance of the tree it belongs to, which holds for every member of an
//!    ECMP set, so the same rule orders set changes.
//!  * `computeBatch`: several destinations at once. A FIB entry is per
//!    destination and installed independently, so the per-destination
//!    orders merge into one timeline sorted by rank: the transition takes
//!    the largest per-destination number of rounds instead of their sum, and
//!    every destination's subsequence is its own proven order.

const std = @import("std");
const spf = @import("spf-ect");
const fib = @import("fib.zig");
const Allocator = std.mem.Allocator;
const NodeId = spf.NodeId;
const Tree = spf.Tree;
const Distance = spf.Distance;

/// A node's position in the transition: nodes of rank 0 update first.
pub const Rank = u32;

/// Per-node rank table for one (old, new) pair. Built from the two distance
/// vectors and the set of nodes whose forwarding changed; see `RankTable.init`
/// and `RankTable.initEcmp`.
pub const RankTable = struct {
    gpa: Allocator,
    old_dist: []const Distance,
    new_dist: []const Distance,
    /// `rank[n]`, or `no_rank` for a node whose forwarding did not change
    /// (it never reprograms).
    rank: []Rank,
    /// Number of distinct ranks, i.e. the rounds of the transition.
    rounds: Rank,

    pub const no_rank: Rank = std.math.maxInt(Rank);

    pub fn deinit(self: *RankTable) void {
        self.gpa.free(self.rank);
        self.* = undefined;
    }

    /// The rank of `n`, or null when `n` does not reprogram. The delay of a
    /// node is `rank * max_fib` (RFC 6976 section 4: "T0 + H + (rank * MAX_FIB)").
    pub fn rankOf(self: *const RankTable, n: NodeId) ?Rank {
        const r = self.rank[n];
        return if (r == no_rank) null else r;
    }

    /// Delay of `n` after the hold-down, in the caller's time unit; null for a
    /// node that does not reprogram.
    pub fn delayOf(self: *const RankTable, n: NodeId, max_fib: u64) ?u64 {
        const r = self.rankOf(n) orelse return null;
        return @as(u64, r) * max_fib;
    }

    /// Ranks for the single-next-hop trees of `fib.computeUpdateOrder`. The
    /// trees must have the same length.
    pub fn init(gpa: Allocator, old_tree: *const Tree, new_tree: *const Tree) Allocator.Error!RankTable {
        const changed = try fib.changedNodes(gpa, old_tree, new_tree);
        defer gpa.free(changed);
        return build(gpa, old_tree.dist, new_tree.dist, changed);
    }

    /// Ranks for ECMP next-hop sets (see `Ecmp`).
    pub fn initEcmp(gpa: Allocator, old_fwd: *const Ecmp, new_fwd: *const Ecmp) Allocator.Error!RankTable {
        const changed = try changedNodesEcmp(gpa, old_fwd, new_fwd);
        defer gpa.free(changed);
        return build(gpa, old_fwd.dist, new_fwd.dist, changed);
    }

    fn build(gpa: Allocator, old_dist: []const Distance, new_dist: []const Distance, changed: []const NodeId) Allocator.Error!RankTable {
        const rank = try gpa.alloc(Rank, old_dist.len);
        errdefer gpa.free(rank);
        @memset(rank, no_rank);

        // Distinct key values per class: class A by ascending new distance,
        // class B by descending old distance (the order `fib` sorts by).
        var a_keys: std.ArrayList(Distance) = .empty;
        defer a_keys.deinit(gpa);
        var b_keys: std.ArrayList(Distance) = .empty;
        defer b_keys.deinit(gpa);
        for (changed) |n| {
            if (new_dist[n] < old_dist[n]) {
                try a_keys.append(gpa, new_dist[n]);
            } else {
                try b_keys.append(gpa, old_dist[n]);
            }
        }
        std.mem.sort(Distance, a_keys.items, {}, std.sort.asc(Distance));
        std.mem.sort(Distance, b_keys.items, {}, std.sort.desc(Distance));
        const a_levels = uniqueInPlace(a_keys.items);
        const b_levels = uniqueInPlace(b_keys.items);

        for (changed) |n| {
            if (new_dist[n] < old_dist[n]) {
                rank[n] = levelOf(a_keys.items[0..a_levels], new_dist[n], true);
            } else {
                rank[n] = @as(Rank, @intCast(a_levels)) + levelOf(b_keys.items[0..b_levels], old_dist[n], false);
            }
        }
        return .{
            .gpa = gpa,
            .old_dist = old_dist,
            .new_dist = new_dist,
            .rank = rank,
            .rounds = @intCast(a_levels + b_levels),
        };
    }
};

/// Collapse equal neighbours of a sorted slice; returns the new length.
fn uniqueInPlace(s: []Distance) usize {
    if (s.len == 0) return 0;
    var w: usize = 1;
    for (s[1..]) |v| {
        if (v != s[w - 1]) {
            s[w] = v;
            w += 1;
        }
    }
    return w;
}

/// Index of `key` in the sorted unique `levels` (ascending when `asc`, else
/// descending). `key` is always present.
fn levelOf(levels: []const Distance, key: Distance, asc: bool) Rank {
    var lo: usize = 0;
    var hi: usize = levels.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const before = if (asc) levels[mid] < key else levels[mid] > key;
        if (before) lo = mid + 1 else hi = mid;
    }
    std.debug.assert(lo < levels.len and levels[lo] == key);
    return @intCast(lo);
}

// ── ECMP ─────────────────────────────────────────────────────────────────

/// A node's complete forwarding toward one destination as an ECMP set: every
/// neighbour that lies on some shortest path. Owns its data.
pub const Ecmp = struct {
    gpa: Allocator,
    root: NodeId,
    /// Copy of the tree's distances (`unreachable_dist` for unreached nodes).
    dist: []Distance,
    /// `hops[n]`: the next hops of `n` toward `root`, ascending by id; empty
    /// for the root and for unreached nodes.
    hops: [][]NodeId,

    pub fn deinit(self: *Ecmp) void {
        for (self.hops) |h| self.gpa.free(h);
        self.gpa.free(self.hops);
        self.gpa.free(self.dist);
        self.* = undefined;
    }

    /// The ECMP sets of `tree` (built by `spf.shortestPathTree(graph, root)`):
    /// `u` is a next hop of `v` when the arc `u -> v` exists and
    /// `dist[u] + weight == dist[v]`, the same relation the tree's own
    /// predecessor is chosen from, so `tree.pred[v]` is always a member.
    pub fn fromTree(gpa: Allocator, graph: *const spf.Graph, tree: *const Tree) Allocator.Error!Ecmp {
        const n_nodes = tree.dist.len;
        const dist = try gpa.dupe(Distance, tree.dist);
        errdefer gpa.free(dist);
        const lists = try gpa.alloc(std.ArrayList(NodeId), n_nodes);
        for (lists) |*l| l.* = .empty;
        defer {
            for (lists) |*l| l.deinit(gpa);
            gpa.free(lists);
        }
        // Visit `u` ascending, so every set comes out ascending by id.
        var u: NodeId = 0;
        while (u < n_nodes) : (u += 1) {
            if (tree.dist[u] == spf.unreachable_dist) continue;
            for (graph.neighbors(u)) |e| {
                if (e.to >= n_nodes) continue;
                if (tree.dist[u] + e.weight == tree.dist[e.to]) try lists[e.to].append(gpa, u);
            }
        }
        const hops = try gpa.alloc([]NodeId, n_nodes);
        var made: usize = 0;
        errdefer {
            for (hops[0..made]) |h| gpa.free(h);
            gpa.free(hops);
        }
        while (made < n_nodes) : (made += 1) hops[made] = try gpa.dupe(NodeId, lists[made].items);
        return .{ .gpa = gpa, .root = tree.root, .dist = dist, .hops = hops };
    }
};

fn sameSet(a: []const NodeId, b: []const NodeId) bool {
    return std.mem.eql(NodeId, a, b);
}

/// Every node whose next-hop SET differs, ascending by id.
pub fn changedNodesEcmp(gpa: Allocator, old_fwd: *const Ecmp, new_fwd: *const Ecmp) Allocator.Error![]NodeId {
    std.debug.assert(old_fwd.hops.len == new_fwd.hops.len);
    var list: std.ArrayList(NodeId) = .empty;
    errdefer list.deinit(gpa);
    for (old_fwd.hops, new_fwd.hops, 0..) |o, n, i| {
        if (!sameSet(o, n)) try list.append(gpa, @intCast(i));
    }
    return list.toOwnedSlice(gpa);
}

/// `fib.computeUpdateOrder` for ECMP sets: a permutation of the nodes whose
/// set changed, such that no prefix of it leaves a forwarding cycle in the
/// union of the old sets (nodes not yet switched) and the new sets (switched).
/// The cycle argument of `fib.computeUpdateOrder` needs only that each edge
/// strictly decreases the distance of its own tree, which every ECMP member
/// does, so the classes and sort keys are unchanged.
pub fn computeUpdateOrderEcmp(gpa: Allocator, old_fwd: *const Ecmp, new_fwd: *const Ecmp) Allocator.Error![]NodeId {
    const order = try changedNodesEcmp(gpa, old_fwd, new_fwd);
    std.mem.sort(NodeId, order, fib.UpdateOrderCtx{ .old_dist = old_fwd.dist, .new_dist = new_fwd.dist }, fib.UpdateOrderCtx.lessThan);
    return order;
}

// ── multi-destination batching ───────────────────────────────────────────

/// One destination's transition: its trees before and after, both rooted at
/// the destination (`old_tree.root == new_tree.root`).
pub const TreePair = struct {
    old_tree: *const Tree,
    new_tree: *const Tree,
};

/// One FIB entry update of a batch: node `node` reprograms its entry for
/// destination `dest` in round `rank`.
pub const DestUpdate = struct {
    dest: NodeId,
    node: NodeId,
    rank: Rank,
};

pub const BatchError = Allocator.Error || error{
    /// A pair whose old and new tree have different roots.
    RootMismatch,
};

fn updateLessThan(_: void, a: DestUpdate, b: DestUpdate) bool {
    if (a.rank != b.rank) return a.rank < b.rank;
    if (a.dest != b.dest) return a.dest < b.dest;
    return a.node < b.node;
}

/// Merge the per-destination schedules of `pairs` into one timeline sorted by
/// (rank, destination, node). Caller owns the slice. The subsequence of one
/// destination is exactly `fib.computeUpdateOrder` of its pair, so each
/// destination is loop-free at every prefix of the batch; the batch needs
/// `max` rounds over the destinations, not their sum.
pub fn computeBatch(gpa: Allocator, pairs: []const TreePair) BatchError![]DestUpdate {
    var out: std.ArrayList(DestUpdate) = .empty;
    errdefer out.deinit(gpa);
    for (pairs) |p| {
        if (p.old_tree.root != p.new_tree.root) return error.RootMismatch;
        var table = try RankTable.init(gpa, p.old_tree, p.new_tree);
        defer table.deinit();
        for (table.rank, 0..) |r, n| {
            if (r == RankTable.no_rank) continue;
            try out.append(gpa, .{ .dest = p.old_tree.root, .node = @intCast(n), .rank = r });
        }
    }
    std.mem.sort(DestUpdate, out.items, {}, updateLessThan);
    return out.toOwnedSlice(gpa);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn synthTree(gpa: Allocator, dist: []const Distance, pred: []const ?NodeId) !Tree {
    return .{ .gpa = gpa, .root = 0, .dist = try gpa.dupe(Distance, dist), .pred = try gpa.dupe(?NodeId, pred) };
}

test "RankTable: ranks are dense levels, class A before class B, equal keys share a round" {
    const gpa = testing.allocator;
    // The mixed table of fib.zig: 1:10->5 and 6:10->5 (A, tied), 2:20->12 (A),
    // 3 and 7: 30->45 (B, tied), 4: 40->42 (B), 5: 3->3 (B, equal distance).
    var old_tree = try synthTree(gpa, &.{ 0, 10, 20, 30, 40, 3, 10, 30 }, &.{ null, 0, 0, 0, 0, 0, 0, 0 });
    defer old_tree.deinit();
    var new_tree = try synthTree(gpa, &.{ 0, 5, 12, 45, 42, 3, 5, 45 }, &.{ null, 9, 9, 9, 9, 9, 9, 9 });
    defer new_tree.deinit();
    var t = try RankTable.init(gpa, &old_tree, &new_tree);
    defer t.deinit();
    // A levels: new_dist 5 -> 0, 12 -> 1. B levels (old_dist descending):
    // 40 -> 2, 30 -> 3, 3 -> 4.
    try testing.expectEqual(@as(?Rank, null), t.rankOf(0));
    try testing.expectEqual(@as(?Rank, 0), t.rankOf(1));
    try testing.expectEqual(@as(?Rank, 0), t.rankOf(6));
    try testing.expectEqual(@as(?Rank, 1), t.rankOf(2));
    try testing.expectEqual(@as(?Rank, 2), t.rankOf(4));
    try testing.expectEqual(@as(?Rank, 3), t.rankOf(3));
    try testing.expectEqual(@as(?Rank, 3), t.rankOf(7));
    try testing.expectEqual(@as(?Rank, 4), t.rankOf(5));
    try testing.expectEqual(@as(Rank, 5), t.rounds);
    try testing.expectEqual(@as(?u64, 3 * 250), t.delayOf(7, 250));
    try testing.expectEqual(@as(?u64, null), t.delayOf(0, 250));

    // Sorting by (rank, id) reproduces computeUpdateOrder: the local rank is
    // the same schedule, with the ties made explicit.
    const order = try fib.computeUpdateOrder(gpa, &old_tree, &new_tree);
    defer gpa.free(order);
    var prev: Rank = 0;
    for (order) |n| {
        const r = t.rankOf(n).?;
        try testing.expect(r >= prev);
        prev = r;
    }
}

/// Reference checker: does the forwarding graph "switched nodes use the new
/// set, the rest the old set" contain a cycle?
fn hasCycle(gpa: Allocator, old_fwd: []const []const NodeId, new_fwd: []const []const NodeId, switched: []const bool) !bool {
    const n = old_fwd.len;
    const color = try gpa.alloc(u8, n);
    defer gpa.free(color);
    @memset(color, 0);
    const Frame = struct { node: NodeId, next: usize };
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(gpa);
    var s: NodeId = 0;
    while (s < n) : (s += 1) {
        if (color[s] != 0) continue;
        try stack.append(gpa, .{ .node = s, .next = 0 });
        color[s] = 1;
        while (stack.items.len > 0) {
            const top = &stack.items[stack.items.len - 1];
            const hops = if (switched[top.node]) new_fwd[top.node] else old_fwd[top.node];
            if (top.next == hops.len) {
                color[top.node] = 2;
                _ = stack.pop();
                continue;
            }
            const to = hops[top.next];
            top.next += 1;
            if (color[to] == 1) return true;
            if (color[to] == 0) {
                color[to] = 1;
                try stack.append(gpa, .{ .node = to, .next = 0 });
            }
        }
    }
    return false;
}

fn randomGraph(gpa: Allocator, rnd: std.Random, nodes: u32, max_w: u32, density: u32) !spf.Graph {
    var g = spf.Graph.init(gpa);
    errdefer g.deinit();
    try g.ensureNode(nodes - 1);
    var a: u32 = 0;
    while (a < nodes) : (a += 1) {
        var b = a + 1;
        while (b < nodes) : (b += 1) {
            if (rnd.intRangeLessThan(u32, 0, 100) < density) {
                try g.addEdge(a, b, rnd.intRangeAtMost(u32, 1, max_w));
            }
        }
    }
    return g;
}

/// Brute-force: every prefix of `order` is cycle-free, and so is every
/// prefix of every rank-respecting reshuffle (here: reversed within a rank).
fn checkOrder(
    gpa: Allocator,
    old_fwd: []const []const NodeId,
    new_fwd: []const []const NodeId,
    order: []const NodeId,
) !void {
    const switched = try gpa.alloc(bool, old_fwd.len);
    defer gpa.free(switched);
    @memset(switched, false);
    try testing.expect(!try hasCycle(gpa, old_fwd, new_fwd, switched));
    for (order) |n| {
        switched[n] = true;
        try testing.expect(!try hasCycle(gpa, old_fwd, new_fwd, switched));
    }
}

fn singleHops(gpa: Allocator, tree: *const Tree) ![][]const NodeId {
    const out = try gpa.alloc([]const NodeId, tree.pred.len);
    for (tree.pred, 0..) |p, i| {
        if (p) |x| {
            const one = try gpa.alloc(NodeId, 1);
            one[0] = x;
            out[i] = one;
        } else out[i] = &.{};
    }
    return out;
}

fn freeHops(gpa: Allocator, h: [][]const NodeId) void {
    for (h) |s| if (s.len != 0) gpa.free(s);
    gpa.free(h);
}

test "ranks and ECMP orders are loop-free at every prefix, brute-force over random graph pairs" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6976_0000_0001);
    const rnd = prng.random();
    var case: u32 = 0;
    while (case < 400) : (case += 1) {
        const nodes = rnd.intRangeAtMost(u32, 3, 12);
        // Small weights make ties (ECMP) common.
        const max_w = rnd.intRangeAtMost(u32, 1, 3);
        var g_old = try randomGraph(gpa, rnd, nodes, max_w, 45);
        defer g_old.deinit();
        // The new topology: rebuilt from a fresh draw sharing the node set, so
        // distances move up and down at once (mixed classes).
        var g_new = try randomGraph(gpa, rnd, nodes, max_w, 45);
        defer g_new.deinit();
        var t_old = try spf.shortestPathTree(gpa, &g_old, 0);
        defer t_old.deinit();
        var t_new = try spf.shortestPathTree(gpa, &g_new, 0);
        defer t_new.deinit();

        // single next hop
        const order = try fib.computeUpdateOrder(gpa, &t_old, &t_new);
        defer gpa.free(order);
        const so = try singleHops(gpa, &t_old);
        defer freeHops(gpa, so);
        const sn = try singleHops(gpa, &t_new);
        defer freeHops(gpa, sn);
        try checkOrder(gpa, so, sn, order);

        // ECMP sets
        var e_old = try Ecmp.fromTree(gpa, &g_old, &t_old);
        defer e_old.deinit();
        var e_new = try Ecmp.fromTree(gpa, &g_new, &t_new);
        defer e_new.deinit();
        for (t_old.pred, 0..) |p, i| {
            if (p) |x| try testing.expect(std.mem.indexOfScalar(NodeId, e_old.hops[i], x) != null);
        }
        const eorder = try computeUpdateOrderEcmp(gpa, &e_old, &e_new);
        defer gpa.free(eorder);
        try checkOrder(gpa, e_old.hops, e_new.hops, eorder);

        // Per-node ranks: any shuffle inside a rank is safe too, so check the
        // order reversed within each rank (ties go descending by id).
        var tab = try RankTable.initEcmp(gpa, &e_old, &e_new);
        defer tab.deinit();
        const rev = try gpa.dupe(NodeId, eorder);
        defer gpa.free(rev);
        const Ctx = struct {
            t: *const RankTable,
            fn lt(c: @This(), a: NodeId, b: NodeId) bool {
                const ra = c.t.rankOf(a).?;
                const rb = c.t.rankOf(b).?;
                if (ra != rb) return ra < rb;
                return a > b;
            }
        };
        std.mem.sort(NodeId, rev, Ctx{ .t = &tab }, Ctx.lt);
        try checkOrder(gpa, e_old.hops, e_new.hops, rev);
    }
}

test "computeBatch: per-destination subsequences are their own orders, rounds are the maximum" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6976_0000_0002);
    const rnd = prng.random();
    var case: u32 = 0;
    while (case < 60) : (case += 1) {
        const nodes = rnd.intRangeAtMost(u32, 4, 10);
        var g_old = try randomGraph(gpa, rnd, nodes, 3, 50);
        defer g_old.deinit();
        var g_new = try randomGraph(gpa, rnd, nodes, 3, 50);
        defer g_new.deinit();
        var olds: [3]Tree = undefined;
        var news: [3]Tree = undefined;
        var pairs: [3]TreePair = undefined;
        var made: usize = 0;
        defer for (0..made) |i| {
            olds[i].deinit();
            news[i].deinit();
        };
        while (made < 3) : (made += 1) {
            olds[made] = try spf.shortestPathTree(gpa, &g_old, @intCast(made));
            news[made] = try spf.shortestPathTree(gpa, &g_new, @intCast(made));
            pairs[made] = .{ .old_tree = &olds[made], .new_tree = &news[made] };
        }
        const batch = try computeBatch(gpa, &pairs);
        defer gpa.free(batch);

        var max_rounds: Rank = 0;
        for (pairs) |p| {
            var tab = try RankTable.init(gpa, p.old_tree, p.new_tree);
            defer tab.deinit();
            max_rounds = @max(max_rounds, tab.rounds);
            const want = try fib.computeUpdateOrder(gpa, p.old_tree, p.new_tree);
            defer gpa.free(want);
            var i: usize = 0;
            for (batch) |u| {
                if (u.dest != p.old_tree.root) continue;
                try testing.expect(i < want.len and want[i] == u.node);
                i += 1;
            }
            try testing.expectEqual(want.len, i);
        }
        var last_rank: Rank = 0;
        var top: Rank = 0;
        for (batch) |u| {
            try testing.expect(u.rank >= last_rank);
            last_rank = u.rank;
            top = @max(top, u.rank + 1);
        }
        try testing.expect(top <= max_rounds);
    }
}

test "computeBatch: a pair with different roots is refused" {
    const gpa = testing.allocator;
    var a = try synthTree(gpa, &.{ 0, 1 }, &.{ null, 0 });
    defer a.deinit();
    var b = try synthTree(gpa, &.{ 0, 1 }, &.{ null, 0 });
    defer b.deinit();
    b.root = 1;
    try testing.expectError(error.RootMismatch, computeBatch(gpa, &.{.{ .old_tree = &a, .new_tree = &b }}));
}

test "Ecmp.fromTree: both equal-cost next hops of a diamond are in the set" {
    const gpa = testing.allocator;
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    try g.addEdge(0, 1, 1);
    try g.addEdge(0, 2, 1);
    try g.addEdge(1, 3, 1);
    try g.addEdge(2, 3, 1);
    var t = try spf.shortestPathTree(gpa, &g, 0);
    defer t.deinit();
    var e = try Ecmp.fromTree(gpa, &g, &t);
    defer e.deinit();
    try testing.expectEqualSlices(NodeId, &.{ 1, 2 }, e.hops[3]);
    try testing.expectEqualSlices(NodeId, &.{0}, e.hops[1]);
    try testing.expectEqual(@as(usize, 0), e.hops[0].len);
}
