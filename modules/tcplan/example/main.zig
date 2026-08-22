// SPDX-License-Identifier: MIT

//! What an ISP shaper deployer does with `tcplan`: describe a two-site
//! hierarchy (site -> access point -> subscriber) as a `Topology`, compile
//! it into a deterministic ordered `Plan` of `tc` operations, and check the
//! plan is internally consistent (no colliding handles, parents installed
//! before children) before ever touching netlink. A topology whose child
//! ceil exceeds its parent's is rejected by name instead of producing a
//! plan HTB would refuse at install time.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const tcplan = @import("tcplan");
const tc = @import("tc");

const subscribers = [_]tcplan.Node{
    .{
        .name = "alice",
        .rate_bps = tcplan.mbit(100),
        .ceil_bps = tcplan.mbit(500),
        .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 1 } } },
    },
    .{
        .name = "bob",
        .rate_bps = tcplan.mbit(50),
        .ceil_bps = tcplan.mbit(500),
        .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 2 } } },
    },
};

const access_points = [_]tcplan.Node{
    .{ .name = "ap1", .rate_bps = tcplan.mbit(500), .ceil_bps = tcplan.mbit(500), .children = &subscribers },
};

const sites = [_]tcplan.Node{
    .{ .name = "site1", .rate_bps = tcplan.mbit(1000), .ceil_bps = tcplan.mbit(1000), .cpu = 0, .children = &access_points },
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const ifindex: u32 = 7;
    var p = try tcplan.compile(gpa, .{ .queue_count = 1, .roots = &sites }, ifindex);
    defer p.deinit(gpa);

    // Sanity the compiler itself claims: unique handles, parents before the
    // children that reference them.
    if (p.findHandleCollision() != null) return error.HandleCollision;
    if ((try p.firstOrderingViolation(gpa)) != null) return error.OrderingViolation;

    std.debug.print("compiled {d} tc operations:\n", .{p.ops.len});
    var qdiscs: usize = 0;
    var classes: usize = 0;
    var filters: usize = 0;
    for (p.ops) |op| switch (op) {
        .qdisc => qdiscs += 1,
        .class => classes += 1,
        .filter => filters += 1,
    };
    std.debug.print("  qdiscs={d} classes={d} filters={d}\n", .{ qdiscs, classes, filters });

    // Each op builds real netlink request bytes through the sibling `tc`
    // module's own encoders — proves the plan is actually executable, not
    // just structurally plausible.
    const ps = tc.Psched.fallback;
    var total_bytes: usize = 0;
    for (p.ops) |op| {
        const bytes = try op.buildRequest(gpa, 1, .replace, ps);
        defer gpa.free(bytes);
        total_bytes += bytes.len;
    }
    std.debug.print("  {d} bytes of netlink requests\n", .{total_bytes});

    // A child ceil exceeding its parent's is rejected by name at compile
    // time — HTB itself would refuse this at install, but tcplan catches it
    // before ever touching netlink.
    const bad_subs = [_]tcplan.Node{
        .{ .name = "greedy", .rate_bps = tcplan.mbit(50), .ceil_bps = tcplan.mbit(2000) },
    };
    const bad_roots = [_]tcplan.Node{
        .{ .name = "site-bad", .rate_bps = tcplan.mbit(1000), .ceil_bps = tcplan.mbit(1000), .cpu = 0, .children = &bad_subs },
    };
    _ = tcplan.compile(gpa, .{ .queue_count = 1, .roots = &bad_roots }, ifindex) catch |err| switch (err) {
        error.CeilExceedsParent => std.debug.print("over-ceil child correctly rejected\n", .{}),
        else => return err,
    };
}
