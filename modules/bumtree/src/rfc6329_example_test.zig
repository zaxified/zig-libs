// SPDX-License-Identifier: MIT
//! RFC 6329 §5 (SPBM) and §6 (SPBV) worked examples driven through the real
//! `bumtree` API over `spf-ect`. External oracle: the RFC's own FDB figures.
//!
//! Figure 2 / Figure 5 (RFC 6329 pp.12, 14): seven nodes :1..:7, all links the
//! same cost, default ECT-ALGORITHM 00-80-C2-01 (lowest BridgeID on ties),
//! B-VID / base VID 100. The interface index drawn at each end of every link is
//! transcribed in `links`. Node :n is `spf-ect` NodeId n-1, so NodeId order is
//! BridgeID order (all Bridge Priorities equal, RFC p.18).
//!
//! Reproduced (asserted row for row): Figure 3 M row (node :1), Figure 4 M rows
//! (node :2, four rows), Figure 6 unicast rows (node :2, six rows), Figure 7
//! multicast rows (node :2, four rows) — IN/IF and OUT/IF set of each, and the
//! source-:1 SPT quoted on p.14.
//!
//! NOT reproduced: the DESTINATION ADDR / BVID / VID columns — the group DA is
//! `spbfib.groupDa` (asserted in `spbfib`'s own RFC test), and `bumtree` has no
//! notion of VIDs. Figure 3/4 U rows and Figure 6's wildcard DA are not
//! multicast-tree state (`spbfib` covers the U rows).

const std = @import("std");
const testing = std.testing;
const spf = @import("spf-ect");
const bum = @import("root.zig");

const Link = struct { a: u8, a_if: u8, b: u8, b_if: u8 };
/// Figure 2 / Figure 5: node `a` port `a_if` <-> node `b` port `b_if`.
const links = [_]Link{
    .{ .a = 4, .a_if = 2, .b = 5, .b_if = 1 },
    .{ .a = 4, .a_if = 1, .b = 1, .b_if = 1 },
    .{ .a = 4, .a_if = 3, .b = 2, .b_if = 4 },
    .{ .a = 5, .a_if = 3, .b = 2, .b_if = 3 },
    .{ .a = 5, .a_if = 2, .b = 3, .b_if = 2 },
    .{ .a = 1, .a_if = 2, .b = 2, .b_if = 1 },
    .{ .a = 2, .a_if = 2, .b = 3, .b_if = 1 },
    .{ .a = 1, .a_if = 3, .b = 6, .b_if = 3 },
    .{ .a = 2, .a_if = 6, .b = 6, .b_if = 2 },
    .{ .a = 2, .a_if = 5, .b = 7, .b_if = 1 },
    .{ .a = 3, .a_if = 3, .b = 7, .b_if = 2 },
    .{ .a = 6, .a_if = 1, .b = 7, .b_if = 3 },
};

/// Interface index at node :`node` toward node :`neighbour` (1-based labels).
fn ifToward(node: u8, neighbour: u8) u8 {
    for (links) |l| {
        if (l.a == node and l.b == neighbour) return l.a_if;
        if (l.b == node and l.a == neighbour) return l.b_if;
    }
    unreachable;
}

fn buildGraph(gpa: std.mem.Allocator) !spf.Graph {
    var g = spf.Graph.init(gpa);
    errdefer g.deinit();
    for (links) |l| try g.addEdge(l.a - 1, l.b - 1, 1);
    return g;
}

/// One FDB row as the RFC prints it: IN/IF (0 = "if/00", head of the tree) and
/// the OUT/IF set (ascending).
const Row = struct {
    in_if: u8,
    out: []const u8,
};

/// Derive node :`node`'s row for the tree of source :`src` with `members`
/// (1-based labels) from bumtree's plan, translating neighbours to interfaces.
fn rowFor(gpa: std.mem.Allocator, g: *const spf.Graph, src: u8, members: []const u8, node: u8, out_buf: []u8) !Row {
    var m: [7]bum.NodeId = undefined;
    for (members, 0..) |x, i| m[i] = x - 1;
    var t = try bum.build(gpa, g, src - 1, m[0..members.len]);
    defer t.deinit();
    const in_if: u8 = if (t.rpfIngress(node - 1)) |p| ifToward(node, @intCast(p + 1)) else 0;
    var n: usize = 0;
    for (t.replicateTo(node - 1)) |c| {
        out_buf[n] = ifToward(node, @intCast(c + 1));
        n += 1;
    }
    std.mem.sort(u8, out_buf[0..n], {}, std.sort.asc(u8));
    return .{ .in_if = in_if, .out = out_buf[0..n] };
}

fn expectRow(g: *const spf.Graph, src: u8, members: []const u8, node: u8, in_if: u8, out: []const u8) !void {
    var buf: [8]u8 = undefined;
    const r = try rowFor(testing.allocator, g, src, members, node, &buf);
    try testing.expectEqual(in_if, r.in_if);
    try testing.expectEqualSlices(u8, out, r.out);
}

/// I-SID 1 members of Figure 2: the nodes with a UNI port (`i1`).
const spbm_members = [_]u8{ 1, 3, 5, 7 };
/// Figure 5: :1, :5, :3, :7 advertise the multicast MAC ..:f.
const spbv_members = spbm_members;
const all_nodes = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };

test "RFC 6329 Figure 3: node :1 M row (1) — if/00 in, {if/2} out, head of its own tree" {
    var g = try buildGraph(testing.allocator);
    defer g.deinit();
    try expectRow(&g, 1, &spbm_members, 1, 0, &.{2});
}

test "RFC 6329 §5 text: node :1 is not transit for any other member's tree" {
    var g = try buildGraph(testing.allocator);
    defer g.deinit();
    // "Since node :1 is not transit for any multicast, it only has a single
    // entry" (p.13): in every other source's tree :1 is a leaf.
    for ([_]u8{ 3, 5, 7 }) |src| {
        var buf: [8]u8 = undefined;
        const r = try rowFor(testing.allocator, &g, src, &spbm_members, 1, &buf);
        try testing.expectEqual(@as(usize, 0), r.out.len);
    }
}

test "RFC 6329 Figure 4: node :2 M rows (4) — IN/IF and OUT/IF set per SPSourceID" {
    var g = try buildGraph(testing.allocator);
    defer g.deinit();
    // src :1 (7300-0100-0001): in if/01, out {if/2,if/3,if/5}
    try expectRow(&g, 1, &spbm_members, 2, 1, &.{ 2, 3, 5 });
    // src :3 (7300-0300-0001): in if/02, out {if/1}
    try expectRow(&g, 3, &spbm_members, 2, 2, &.{1});
    // src :5 (7300-0500-0001): in if/03, out {if/1,if/5}
    try expectRow(&g, 5, &spbm_members, 2, 3, &.{ 1, 5 });
    // src :7 (7300-0700-0001): in if/05, out {if/1,if/3}
    try expectRow(&g, 7, &spbm_members, 2, 5, &.{ 1, 3 });
}

test "RFC 6329 §6: node :1's SPT is {1->4, 1->6, 1->2->3, 1->2->5, 1->2->7}" {
    var g = try buildGraph(testing.allocator);
    defer g.deinit();
    var t = try bum.build(testing.allocator, &g, 0, &all_nodes_ids);
    defer t.deinit();
    // predecessor (parent) of each node in :1's tree, 1-based labels
    const parent = [_]struct { node: u8, pred: ?u8 }{
        .{ .node = 1, .pred = null },
        .{ .node = 2, .pred = 1 },
        .{ .node = 3, .pred = 2 },
        .{ .node = 4, .pred = 1 },
        .{ .node = 5, .pred = 2 },
        .{ .node = 6, .pred = 1 },
        .{ .node = 7, .pred = 2 },
    };
    for (parent) |p| {
        const want: ?bum.NodeId = if (p.pred) |x| x - 1 else null;
        try testing.expectEqual(want, t.rpfIngress(p.node - 1));
    }
}

const all_nodes_ids = [_]bum.NodeId{ 0, 1, 2, 3, 4, 5, 6 };

test "RFC 6329 Figure 6: node :2 SPBV unicast rows (6) — one SPT per SPVID" {
    var g = try buildGraph(testing.allocator);
    defer g.deinit();
    // Unicast SPBV: every node is a destination (all seven are members of its
    // own source-rooted tree). Rows keyed by the source's SPVID = 100 + node.
    // VID 0101: in if/01, {if/2,if/3,if/5}
    try expectRow(&g, 1, &all_nodes, 2, 1, &.{ 2, 3, 5 });
    // VID 0103: in if/02, {if/1,if/4,if/6}
    try expectRow(&g, 3, &all_nodes, 2, 2, &.{ 1, 4, 6 });
    // VID 0104: in if/04, {if/2,if/5}
    try expectRow(&g, 4, &all_nodes, 2, 4, &.{ 2, 5 });
    // VID 0105: in if/03, {if/1,if/5,if/6}
    try expectRow(&g, 5, &all_nodes, 2, 3, &.{ 1, 5, 6 });
    // VID 0106: in if/06, {if/2,if/3}
    try expectRow(&g, 6, &all_nodes, 2, 6, &.{ 2, 3 });
    // VID 0107: in if/05, {if/1,if/3,if/4}
    try expectRow(&g, 7, &all_nodes, 2, 5, &.{ 1, 3, 4 });
}

test "RFC 6329 Figure 7: node :2 SPBV multicast rows (4) for group ..:f" {
    var g = try buildGraph(testing.allocator);
    defer g.deinit();
    // VID 0101: in if/01, {if/2,if/3,if/5}
    try expectRow(&g, 1, &spbv_members, 2, 1, &.{ 2, 3, 5 });
    // VID 0103: in if/02, {if/1}
    try expectRow(&g, 3, &spbv_members, 2, 2, &.{1});
    // VID 0105: in if/03, {if/1,if/5}
    try expectRow(&g, 5, &spbv_members, 2, 3, &.{ 1, 5 });
    // VID 0107: in if/05, {if/1,if/3}
    try expectRow(&g, 7, &spbv_members, 2, 5, &.{ 1, 3 });
}
