// SPDX-License-Identifier: MIT
//! Opt-in measurement behind the "incremental SPF" decision (SPEC, *What is
//! deliberately not done*): how much of one `compute` is the shortest-path
//! tree, which is all that reusing a previous tree could save. Off by default
//! (`error.SkipZigTest`); run it with
//!
//!   ISIS_SPF_BENCH=1 hw run --slots 2 -- zig build test-isis-spf -Doptimize=ReleaseFast
//!
//! The topology is a ring of `n` systems with a chord to the system 37 steps
//! on, four two-way links per system at metric 10, one IPv4 prefix each; `n`
//! is 1000 (the LSDB holds 1000 LSPs of about 80 octets).

const std = @import("std");
const isis = @import("isis");
const lsdb = @import("isis-lsdb");
const spf = @import("spf-ect");
const root = @import("root.zig");

const n_nodes: u32 = 1000;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn sys(i: u32) root.SystemId {
    var s: root.SystemId = @splat(0);
    std.mem.writeInt(u32, s[2..6], i + 1, .big);
    return s;
}

fn fill(db: *lsdb.Lsdb, seq: u32) !void {
    var buf: [512]u8 = undefined;
    var i: u32 = 0;
    while (i < n_nodes) : (i += 1) {
        const me = sys(i);
        var b = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = me ++ [_]u8{ 0, 0 },
            .sequence_number = seq,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        const nbrs = [_]u32{ (i + 1) % n_nodes, (i + n_nodes - 1) % n_nodes, (i + 37) % n_nodes, (i + n_nodes - 37) % n_nodes };
        for (nbrs) |nb| try isis.tlvs.addExtendedIsReach(&b.tlvs, sys(nb) ++ [_]u8{0}, 10, &.{});
        try isis.tlvs.addExtIpReach(&b.tlvs, .{ .metric = 1, .prefix_len = 24, .prefix = .{ 10, @intCast(i >> 8), @intCast(i & 0xff), 0 } });
        _ = try db.insert(b.finishStamped(), null, 0);
    }
}

test "bench (opt-in via ISIS_SPF_BENCH): compute against the bare shortest-path tree" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("ISIS_SPF_BENCH") == null) return error.SkipZigTest;
    const gpa = std.heap.smp_allocator;
    var db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys(0), .interface_count = 2, .capacity = n_nodes + 8 });
    defer db.deinit();
    try fill(&db, 1);

    // The graph `compute` builds, built once, for the bare Dijkstra timing.
    var graph = spf.Graph.init(gpa);
    defer graph.deinit();
    try graph.ensureNode(n_nodes - 1);
    var i: u32 = 0;
    while (i < n_nodes) : (i += 1) {
        const nbrs = [_]u32{ (i + 1) % n_nodes, (i + n_nodes - 1) % n_nodes, (i + 37) % n_nodes, (i + n_nodes - 37) % n_nodes };
        for (nbrs) |nb| graph.addArc(i, nb, 10) catch |e| switch (e) {
            error.DuplicateEdge => {},
            else => return e,
        };
    }

    const rounds: usize = 7;
    const iters: usize = 20;
    for (0..rounds) |r| {
        var t0 = nowNs();
        for (0..iters) |_| {
            var t = try root.computeWith(gpa, &db, sys(0), 0, .{ .prefixes = false });
            std.mem.doNotOptimizeAway(t.routes.len);
            t.deinit();
        }
        const full = (nowNs() - t0) / iters;
        t0 = nowNs();
        for (0..iters) |_| {
            var t = try root.computeWith(gpa, &db, sys(0), 0, .{ .prefixes = true });
            std.mem.doNotOptimizeAway(t.prefixes.len);
            t.deinit();
        }
        const full_pfx = (nowNs() - t0) / iters;
        t0 = nowNs();
        for (0..iters) |_| {
            var tree = try spf.shortestPathTree(gpa, &graph, 0);
            std.mem.doNotOptimizeAway(tree.distanceTo(500));
            tree.deinit();
        }
        const tree_only = (nowNs() - t0) / iters;
        std.debug.print("round {d}: compute {d} us, compute+prefixes {d} us, bare tree {d} us, tree share {d}%\n", .{ r, full / 1000, full_pfx / 1000, tree_only / 1000, tree_only * 100 / full });
    }
}
