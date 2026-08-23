// SPDX-License-Identifier: MIT

//! What an SPBM backbone node does with `bumtree`: build a 7-node fabric by
//! hand out of `spf-ect.Graph` (a source PE, a redundant core triangle so
//! there is an actual cycle for the RPF backstop to earn its keep, and two
//! member-bearing leaves plus one deliberately member-less leaf), compute
//! the per-source BUM distribution tree, and check the property that
//! matters: every node the tree is supposed to reach is reached EXACTLY
//! ONCE (asserted by actually flooding through `replicateTo`, not by
//! trusting that `build` returned), the member-less branch is never
//! reached at all, and a naive full-neighbour flood over the topology's
//! real cycle still accepts each node at most once once RPF is applied —
//! with a positive control proving that claim is not vacuous.
//!
//! Topology (all edges weight 1), source = node 0:
//!
//! ```
//!        4          5
//!        |          |
//!   0 -- 1 -------- 2       (0-1, 0-2, 1-2: a triangle, so 3 is
//!        |\        /|        reachable two equal-cost ways — a cycle)
//!        6 \      / 3
//!            `----'
//! ```
//! Edges: 0-1, 0-2, 1-2, 1-3, 2-3, 1-4, 2-5, 1-6. Members = {3, 4, 5}. Node 6
//! is deliberately NOT a member and has no member below it, so it must be
//! pruned from node 1's replication set.
//!
//! By hand (Dijkstra from 0, all weights 1): dist(1)=dist(2)=1;
//! dist(3)=dist(4)=dist(5)=dist(6)=2. Node 3 is a genuine tie (reachable via
//! 1 OR via 2, both cost 2).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). Declared
//! deps: `spf-ect`.

const std = @import("std");
const spf = @import("spf-ect");
const bumtree = @import("bumtree");

const NodeId = bumtree.NodeId;
const source: NodeId = 0;
const members = [_]NodeId{ 3, 4, 5 };

fn buildGraph(gpa: std.mem.Allocator) !spf.Graph {
    var g = spf.Graph.init(gpa);
    errdefer g.deinit();
    try g.addEdge(0, 1, 1);
    try g.addEdge(0, 2, 1);
    try g.addEdge(1, 2, 1); // closes the triangle: a real cycle for RPF to guard
    try g.addEdge(1, 3, 1);
    try g.addEdge(2, 3, 1); // 3 is reachable two equal-cost ways
    try g.addEdge(1, 4, 1);
    try g.addEdge(2, 5, 1);
    try g.addEdge(1, 6, 1); // member-less leaf: must be pruned
    return g;
}

/// Flood a BUM-from-source frame down the pruned `replicateTo` tree,
/// counting visits per node — the direct check that the tree reaches every
/// intended node exactly once and nothing else at all.
fn floodViaTree(gpa: std.mem.Allocator, bt: *const bumtree.BumTree) ![]u32 {
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

/// Worst-case flood: every node that ACCEPTS the frame re-floods to ALL of
/// its graph neighbours (modelling a stale node that does not prune),
/// applying the RPF gate on receipt when `enforce_rpf` is set. This is the
/// scenario `replicateTo` alone cannot exercise, because it only ever walks
/// the tree's own edges — RPF earns its keep specifically on the graph's
/// redundant 1<->2<->3 cycle, which a naive flood WOULD duplicate across.
fn floodWithRpf(gpa: std.mem.Allocator, g: *const spf.Graph, bt: *const bumtree.BumTree, enforce_rpf: bool) ![]u32 {
    const n = g.nodeCount();
    const accepts = try gpa.alloc(u32, n);
    @memset(accepts, 0);
    const Ev = struct { node: NodeId, ingress: ?NodeId, ttl: u32 };
    var queue: std.ArrayList(Ev) = .empty;
    defer queue.deinit(gpa);
    try queue.append(gpa, .{ .node = bt.source, .ingress = null, .ttl = n + 2 });

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const ev = queue.items[head];
        if (ev.node != bt.source) {
            if (enforce_rpf and !(ev.ingress != null and bt.rpfCheck(ev.node, ev.ingress.?))) continue;
        }
        accepts[ev.node] += 1;
        if (ev.ttl == 0) continue;
        for (g.neighbors(ev.node)) |e| {
            if (ev.ingress) |in| if (e.to == in) continue;
            try queue.append(gpa, .{ .node = e.to, .ingress = ev.node, .ttl = ev.ttl - 1 });
        }
    }
    return accepts;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── run 1: build the tree, assert the reachability set + loop-freedom ────
    {
        var g = try buildGraph(gpa);
        defer g.deinit();

        var bt = try bumtree.build(gpa, &g, source, &members);
        defer bt.deinit();

        // Reachability: every one of the 7 nodes is on the SPT (this graph
        // is connected), including the tied node 3.
        std.debug.assert(bt.node_count == 7);
        var n: NodeId = 1;
        while (n < 7) : (n += 1) std.debug.assert(bt.rpfIngress(n) != null);
        std.debug.assert(bt.rpfIngress(0) == null); // the source has no ingress

        // Membership, independent of the tie.
        for ([_]NodeId{ 0, 1, 2, 6 }) |x| std.debug.assert(!bt.isMember(x));
        for ([_]NodeId{ 3, 4, 5 }) |x| std.debug.assert(bt.isMember(x));

        // Pruning: node 6 is a member-less leaf and must NEVER be a
        // replication target, regardless of which way node 3's tie resolved.
        for (0..7) |i| std.debug.assert(std.mem.indexOfScalar(NodeId, bt.replicateTo(@intCast(i)), 6) == null);

        // The tie: node 3's parent is 1 or 2 (both legitimate), and it is
        // stable across an independent rebuild of the same graph — not a
        // fresh coin flip per call.
        const pred3 = bt.rpfIngress(3).?;
        std.debug.assert(pred3 == 1 or pred3 == 2);
        var g2 = try buildGraph(gpa);
        defer g2.deinit();
        var bt2 = try bumtree.build(gpa, &g2, source, &members);
        defer bt2.deinit();
        std.debug.assert(bt2.rpfIngress(3).? == pred3);

        // The reachability set, checked by actually flooding, not by
        // trusting `build`'s return: every member (3, 4, 5) is visited
        // EXACTLY once, node 6 is visited ZERO times, and no node is
        // visited more than once anywhere (tree ⇒ no loop, no duplicate).
        const visits = try floodViaTree(gpa, &bt);
        defer gpa.free(visits);
        for ([_]NodeId{ 3, 4, 5 }) |m| std.debug.assert(visits[m] == 1);
        std.debug.assert(visits[6] == 0);
        for (visits) |v| std.debug.assert(v <= 1);
        std.debug.print("run 1: 7-node fabric, tie at node 3 stable, node 6 correctly pruned, every member reached exactly once\n", .{});

        // Loop-freedom under the REAL hazard: a stale-node flood over the
        // graph's actual 0-1-2(-3) cycle. With RPF enforced every reachable
        // node accepts at most once; without it (positive control), the
        // same flood duplicates over the redundant edges — proving RPF is
        // load-bearing on this exact topology, not merely asserted.
        {
            const accepts = try floodWithRpf(gpa, &g, &bt, true);
            defer gpa.free(accepts);
            for (accepts) |acc| std.debug.assert(acc <= 1);
            for ([_]NodeId{ 3, 4, 5 }) |m| std.debug.assert(accepts[m] == 1);
        }
        {
            const accepts = try floodWithRpf(gpa, &g, &bt, false);
            defer gpa.free(accepts);
            var max: u32 = 0;
            for (accepts) |acc| max = @max(max, acc);
            std.debug.assert(max > 1); // the cycle DOES duplicate without RPF
        }
        std.debug.print("RPF backstop: <=1 accept per node under a stale full-neighbour flood; without RPF the same flood duplicates\n", .{});
    }

    // ── run 2: topology/dataset change — node 6 gains a member ───────────────
    // Same graph, a different member set: the previously-pruned branch must
    // now appear. Rebuilding in the same process (fresh Graph + fresh
    // BumTree, both properly torn down above) is what would surface a leak
    // left over from run 1.
    {
        var g = try buildGraph(gpa);
        defer g.deinit();
        const members2 = [_]NodeId{ 3, 4, 5, 6 };
        var bt = try bumtree.build(gpa, &g, source, &members2);
        defer bt.deinit();

        std.debug.assert(bt.isMember(6));
        std.debug.assert(std.mem.indexOfScalar(NodeId, bt.replicateTo(1), 6) != null); // now present
        const visits = try floodViaTree(gpa, &bt);
        defer gpa.free(visits);
        std.debug.assert(visits[6] == 1); // and actually reached
        std.debug.print("run 2 (6 gains membership): the previously-pruned branch now appears and is reached\n", .{});
    }

    // ── negative: a malformed topology is rejected by NAMED error ───────────
    // A caller mistake building the graph itself — a zero-weight edge —
    // rather than a bumtree API misuse: `spf-ect.Graph` requires weight >= 1
    // (a zero-weight edge could otherwise form a predecessor 2-cycle).
    {
        var g = spf.Graph.init(gpa);
        defer g.deinit();
        try g.addEdge(0, 1, 1);
        if (g.addEdge(1, 2, 0)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.ZeroWeight => std.debug.print("zero-weight edge: ZeroWeight (expected)\n", .{}),
            else => return err,
        }
    }

    // ── a failure path that allocates and returns early, by NAMED error ─────
    // `bumtree.build` runs `spf.shortestPathTree` and then several of its
    // own allocations (membership/subtree-marking arrays, the contiguous
    // `replicate_to` backing store) before it can return a `BumTree` at
    // all — drive that under a `FailingAllocator` and confirm the error is
    // `error.OutOfMemory`, not a partially-built tree.
    {
        var g = try buildGraph(gpa);
        defer g.deinit();
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        if (bumtree.build(failing.allocator(), &g, source, &members)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("build under a FailingAllocator: OutOfMemory (expected)\n", .{}),
        }
    }
}
