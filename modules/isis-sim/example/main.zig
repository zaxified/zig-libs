// SPDX-License-Identifier: MIT

//! What a fabric-stack integrator does with `isis-sim`: build a 4-node
//! IS-IS ring, schedule a mid-run link failure, drive the fabric to
//! convergence through `netsim`, and confirm every node's LSDB agrees and
//! that `isis-spf` still finds a route around the failed link — the
//! end-to-end proof that lsdb+flood+spf actually work together, not just
//! individually.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const isis_sim = @import("isis-sim");
const isis_spf = @import("isis-spf");
const netsim = @import("netsim");

const step_cap: netsim.Time = 100_000;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A 4-node ring: two disjoint paths between any pair of nodes, so a
    // single link failure cannot partition the fabric.
    const edges = [_]isis_sim.Edge{
        .{ .a = 0, .b = 1, .metric = 10 },
        .{ .a = 1, .b = 2, .metric = 10 },
        .{ .a = 2, .b = 3, .metric = 10 },
        .{ .a = 3, .b = 0, .metric = 10 },
    };
    var fab = try isis_sim.Fabric.init(gpa, .{ .node_count = 4, .edges = &edges }, 42);
    defer fab.deinit();

    // Sever 0<->1 partway through the run; the ring's other path (0-3-2-1)
    // must still get everyone to agreement.
    try fab.failLinkAt(0, 1, 5_000);

    const outcome = try fab.runToConvergence(step_cap);
    std.debug.print("outcome: {t}\n", .{outcome});
    switch (outcome) {
        .converged => {},
        .safety_violated => {
            std.debug.print("safety invariant tripped: {?}\n", .{fab.violation});
            return error.SafetyViolated;
        },
        .event_cap_exceeded => return error.EventCapExceeded,
        .not_quiescent => return error.NotQuiescent,
    }

    if (!fab.lsdbsAgree()) return error.LsdbsDisagree;
    std.debug.print("all 4 LSDBs agree after reconvergence\n", .{});

    // Nodes 0 and 1 both re-originated after losing their direct link —
    // their sequence numbers bumped from the initial origination.
    std.debug.print("node0 seq={d} node1 seq={d}\n", .{ fab.selfSequence(0), fab.selfSequence(1) });
    if (fab.selfSequence(0) < 2 or fab.selfSequence(1) < 2) return error.ExpectedReorigination;

    // Node 0's forwarding table must still reach node 1, now via the long
    // way around the ring (cost 30, not the severed direct link's 10).
    var table = try fab.routes(gpa, 0);
    defer table.deinit();

    const dest = isis_sim.systemIdForNode(1);
    const route = table.lookup(dest) orelse return error.ExpectedRoute;
    std.debug.print("node0 -> node1: cost={d} next_hop reroutes around the failed link\n", .{route.metric});
    if (route.metric != 30) return error.UnexpectedRerouteCost;

    // `reaches` is the convenience form: system-id of what `to` resolves to
    // through `from`'s table, without the caller building a `RouteTable`
    // itself.
    const reached = try fab.reaches(gpa, 0, 2);
    std.debug.print("node0 reaches node2: {}\n", .{reached != null});
    if (reached == null) return error.ExpectedReachability;
}
