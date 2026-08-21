// SPDX-License-Identifier: MIT

//! What an SPB-style fabric controller does with `spf-ect`: build the switch
//! topology as a symmetric-weighted graph, compute the shortest-path tree
//! from one root switch, read off a path to a leaf, confirm path(A→B) really
//! is the reverse of path(B→A) (the whole point of the ECT tie-break), and
//! compute a disjoint second tree for a protection path.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.

const std = @import("std");
const spf = @import("spf-ect");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A small ring-with-a-chord fabric: 0=core, 1..3=access switches.
    var g = spf.Graph.init(gpa);
    defer g.deinit();
    try g.addEdge(0, 1, 4);
    try g.addEdge(1, 2, 3);
    try g.addEdge(2, 3, 2);
    try g.addEdge(3, 0, 5);
    try g.addEdge(0, 2, 6); // chord

    // A 0-weight link is rejected by name: it would let the ECT tie-break
    // walk an unbounded predecessor cycle.
    g.addEdge(1, 3, 0) catch |err| switch (err) {
        error.ZeroWeight => std.debug.print("rejected 0-weight link 1<->3\n", .{}),
        else => return err,
    };

    var tree = try spf.shortestPathTree(gpa, &g, 0);
    defer tree.deinit();
    std.debug.print("distance 0->3: {d}\n", .{tree.distanceTo(3)});

    const forward = try spf.shortestPath(gpa, &g, 0, 3);
    defer gpa.free(forward);
    std.debug.print("path 0->3: {any}\n", .{forward});

    const reverse = try spf.shortestPath(gpa, &g, 3, 0);
    defer gpa.free(reverse);
    std.debug.print("path 3->0: {any}\n", .{reverse});

    // The ECT tie-break guarantee: reversing one path equals the other.
    const reversed_copy = try gpa.dupe(spf.NodeId, reverse);
    defer gpa.free(reversed_copy);
    std.mem.reverse(spf.NodeId, reversed_copy);
    std.debug.print("path(0,3) == reverse(path(3,0)): {}\n", .{std.mem.eql(spf.NodeId, forward, reversed_copy)});

    // An unreachable node behind an isolated island: the error is nameable,
    // not folded into a generic failure.
    try g.ensureNode(9); // node exists but has no edges
    _ = spf.shortestPath(gpa, &g, 0, 9) catch |err| switch (err) {
        error.Unreachable => std.debug.print("node 9 correctly reported unreachable\n", .{}),
        else => return err,
    };

    // A disjoint second tree from the same root, for a protection path that
    // steers off the primary tree's links wherever the graph allows it.
    var trees = try spf.disjointTrees(gpa, &g, 0);
    defer trees[0].deinit();
    defer trees[1].deinit();
    const primary_path = try spf.shortestPath(gpa, &g, 0, 3);
    defer gpa.free(primary_path);
    const secondary_path = try trees[1].pathTo(gpa, 3);
    defer gpa.free(secondary_path);
    std.debug.print("primary path to 3: {any}\n", .{primary_path});
    std.debug.print("secondary (disjoint) path to 3: {any}\n", .{secondary_path});
}
