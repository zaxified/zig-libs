// SPDX-License-Identifier: MIT

//! What a fabric conductor does with `loopfree-reconv` when a link fails:
//! compute the shortest-path trees before and after the change with
//! `spf-ect`, then ask `computeUpdateOrder` for the sequence in which each
//! node's FIB may be reprogrammed without ever creating a transient
//! forwarding loop — and contrast it with `naiveBadOrder`, the
//! known-loopy "apply instantly" baseline the module ships as its own
//! positive control.
//!
//! Topology: the 4-node ring `0-1-2-3-0` (edge `3-0` weighted 10, every
//! other edge weighted 1) that this module's own root.zig doc derives the
//! "severing 1-0 flips node 1's next-hop 0->2 and node 2's next-hop 1->3"
//! scenario from.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const reconv = @import("loopfree-reconv");
const spf = @import("spf-ect");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── before: the intact ring, destination = node 0 ───────────────────
    var before = spf.Graph.init(gpa);
    defer before.deinit();
    try before.addEdge(0, 1, 1);
    try before.addEdge(1, 2, 1);
    try before.addEdge(2, 3, 1);
    try before.addEdge(3, 0, 10);

    var old_tree = try spf.shortestPathTree(gpa, &before, 0);
    defer old_tree.deinit();

    // ── after: edge 1-0 has failed ───────────────────────────────────────
    var after = spf.Graph.init(gpa);
    defer after.deinit();
    try after.addEdge(1, 2, 1);
    try after.addEdge(2, 3, 1);
    try after.addEdge(3, 0, 10);
    try after.ensureNode(0); // node 0 still exists even though 1-0 is gone

    var new_tree = try spf.shortestPathTree(gpa, &after, 0);
    defer new_tree.deinit();

    std.debug.print("node 1 next-hop: {?d} -> {?d}\n", .{ old_tree.pred[1], new_tree.pred[1] });
    std.debug.print("node 2 next-hop: {?d} -> {?d}\n", .{ old_tree.pred[2], new_tree.pred[2] });

    const changed = try reconv.changedNodes(gpa, &old_tree, &new_tree);
    defer gpa.free(changed);
    std.debug.print("changed nodes: {any}\n", .{changed});

    // The Fable core: provably loop-free at every intermediate step.
    const safe_order = try reconv.computeUpdateOrder(gpa, &old_tree, &new_tree);
    defer gpa.free(safe_order);
    std.debug.print("loop-free update order: {any}\n", .{safe_order});

    // The deliberately-wrong baseline this module ships as its own
    // positive control — same changed-node set, no loop-freedom guarantee.
    const naive_order = try reconv.naiveBadOrder(gpa, &old_tree, &new_tree);
    defer gpa.free(naive_order);
    std.debug.print("naive (loopy) update order: {any}\n", .{naive_order});

    // A tree pair with mismatched node counts is a caller bug, not a wire
    // condition -- `changedNodes`/`computeUpdateOrder` assert it rather than
    // returning a typed error, so there is nothing to name-catch here; the
    // only error this module's ordering functions can return at all is
    // allocation failure (`OrderError = Allocator.Error`), which a failing
    // allocator demonstrates more honestly than a crafted input would.
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    if (reconv.computeUpdateOrder(failing.allocator(), &old_tree, &new_tree)) |order| {
        gpa.free(order);
        return error.ExpectedOutOfMemory;
    } else |err| switch (err) {
        error.OutOfMemory => std.debug.print("allocation failure correctly reported\n", .{}),
    }
}
