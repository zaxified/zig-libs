// SPDX-License-Identifier: MIT
//! RFC 6329 §5 worked example (Figure 2 network, Figures 3 and 4 FDBs) driven
//! through the real `spbfib` API. External oracle: the RFC's own tables.
//!
//! Figure 2 (RFC 6329 p.12): seven nodes :1..:7, B-MAC 4455-6677-00xx, all
//! links the same cost, B-VID 100, default ECT-ALGORITHM 00-80-C2-01. Each link
//! is transcribed below with the interface index drawn at each end.
//!
//! What is reproduced: every unicast (U) row of Figure 3 (node :1) and Figure 4
//! (node :2) — destination B-MAC -> egress interface — and the group DA of
//! every multicast (M) row (Figure 3: 1, Figure 4: 4).
//!
//! What is NOT reproduced (not spbfib's job): the IN/IF and OUT/IF sets of the
//! M rows (that is the per-source tree, `bumtree`, which asserts them in its
//! own `rfc6329_example_test.zig`) and the BVID column (spbfib is a single-VID
//! FIB, see SPEC "Backlog").
//!
//! Input caveat: `spbfib` consumes an `isis-spf` `RouteTable`, but `isis-lsdb`
//! is not a dependency of this module, so the route tables are built from the
//! RFC's own normative path list (p.12: the 2-hop shortest paths
//! `{1-2-3, 1-2-5, 1-2-7, 6-2-5, 4-2-7, 4-1-6, 5-2-7, 6-2-3, 4-2-3}`; every
//! other pair is a direct link). The SPF itself is anchored on the same figure
//! in `bumtree` (over `spf-ect`, which `isis-spf` runs).

const std = @import("std");
const testing = std.testing;
const spf = @import("isis-spf");
const fib_mod = @import("root.zig");

const BMac = fib_mod.BMac;

/// B-MAC of node :n — 4455-6677-00xx (RFC 6329 §5, p.12). Per §9 the SYSID of
/// an SPB node is its B-MAC, so the same 6 octets serve as the system-id.
fn bmacOf(n: u8) BMac {
    return .{ 0x44, 0x55, 0x66, 0x77, 0x00, n };
}

/// Figure 2 links: node `a` port `a_if` <-> node `b` port `b_if` (p.12).
const Link = struct { a: u8, a_if: u8, b: u8, b_if: u8 };
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

/// The RFC's normative 2-hop shortest paths (p.12), as {end, middle, end}.
const two_hop = [_][3]u8{
    .{ 1, 2, 3 }, .{ 1, 2, 5 }, .{ 1, 2, 7 },
    .{ 6, 2, 5 }, .{ 4, 2, 7 }, .{ 4, 1, 6 },
    .{ 5, 2, 7 }, .{ 6, 2, 3 }, .{ 4, 2, 3 },
};

/// Interface index at `node` of the link toward `neighbour`, or null.
fn ifToward(node: u8, neighbour: u8) ?u8 {
    for (links) |l| {
        if (l.a == node and l.b == neighbour) return l.a_if;
        if (l.b == node and l.a == neighbour) return l.b_if;
    }
    return null;
}

/// Next-hop node of `root` toward `dest` per the RFC: direct link, else the
/// middle node of the listed 2-hop path (paths are symmetric).
fn rfcNextHop(root: u8, dest: u8) u8 {
    if (ifToward(root, dest) != null) return dest;
    for (two_hop) |p| {
        if (p[0] == root and p[2] == dest) return p[1];
        if (p[2] == root and p[0] == dest) return p[1];
    }
    unreachable; // every non-adjacent pair is in the RFC's list (asserted below)
}

/// The route table `isis-spf` would hand `spbfib` at `root` — hop count as
/// metric (all links have the same cost), sorted by destination system-id.
fn routeTableFor(gpa: std.mem.Allocator, root: u8) !spf.RouteTable {
    var routes: std.ArrayList(spf.Route) = .empty;
    errdefer routes.deinit(gpa);
    var d: u8 = 1;
    while (d <= 7) : (d += 1) {
        const nh = if (d == root) root else rfcNextHop(root, d);
        const metric: u64 = if (d == root) 0 else if (nh == d) 1 else 2;
        try routes.append(gpa, .{ .dest = bmacOf(d), .next_hop = bmacOf(nh), .metric = metric });
    }
    return .{ .gpa = gpa, .routes = try routes.toOwnedSlice(gpa) };
}

fn fibFor(gpa: std.mem.Allocator, table: *const spf.RouteTable) !fib_mod.Fib {
    var map: [7]fib_mod.BmacEntry = undefined;
    for (&map, 0..) |*e, i| e.* = .{ .system_id = bmacOf(@intCast(i + 1)), .b_mac = bmacOf(@intCast(i + 1)) };
    return fib_mod.build(gpa, table, &map);
}

/// Egress interface of `root` for the FIB entry keyed by `dest`.
fn egressIf(fib: *const fib_mod.Fib, root: u8, dest: u8) !u8 {
    const e = fib.lookup(bmacOf(dest)) orelse return error.NoEntry;
    // The FIB carries the next hop's B-MAC; the interface is the link to it.
    return ifToward(root, e.next_hop_bmac[5]) orelse error.NotAdjacent;
}

test "RFC 6329 §5: the path list covers every non-adjacent pair exactly once" {
    var pairs: usize = 0;
    var a: u8 = 1;
    while (a <= 7) : (a += 1) {
        var b: u8 = a + 1;
        while (b <= 7) : (b += 1) {
            var n: usize = 0;
            for (two_hop) |p| {
                if ((p[0] == a and p[2] == b) or (p[0] == b and p[2] == a)) n += 1;
            }
            const adjacent = ifToward(a, b) != null;
            try testing.expectEqual(@as(usize, if (adjacent) 0 else 1), n);
            pairs += 1;
        }
    }
    try testing.expectEqual(@as(usize, 21), pairs); // 12 links + 9 two-hop paths
}

test "RFC 6329 Figure 3: node :1 unicast rows (6) — dest B-MAC -> if/N" {
    const gpa = testing.allocator;
    var table = try routeTableFor(gpa, 1);
    defer table.deinit();
    var fib = try fibFor(gpa, &table);
    defer fib.deinit();

    // Figure 3, U rows: (destination 4455-6677-000d, out interface).
    const rows = [_]struct { dest: u8, out: u8 }{
        .{ .dest = 2, .out = 2 },
        .{ .dest = 3, .out = 2 },
        .{ .dest = 4, .out = 1 },
        .{ .dest = 5, .out = 2 },
        .{ .dest = 6, .out = 3 },
        .{ .dest = 7, .out = 2 },
    };
    for (rows) |r| try testing.expectEqual(r.out, try egressIf(&fib, 1, r.dest));
    // The FIB also holds the local self route (Figure 3 has no row for it).
    try testing.expect(fib.lookup(bmacOf(1)).?.local);
    try testing.expectEqual(@as(usize, 7), fib.entries.len);
}

test "RFC 6329 Figure 4: node :2 unicast rows (6) — dest B-MAC -> if/N" {
    const gpa = testing.allocator;
    var table = try routeTableFor(gpa, 2);
    defer table.deinit();
    var fib = try fibFor(gpa, &table);
    defer fib.deinit();

    // Figure 4, U rows.
    const rows = [_]struct { dest: u8, out: u8 }{
        .{ .dest = 1, .out = 1 },
        .{ .dest = 3, .out = 2 },
        .{ .dest = 4, .out = 4 },
        .{ .dest = 5, .out = 3 },
        .{ .dest = 6, .out = 6 },
        .{ .dest = 7, .out = 5 },
    };
    for (rows) |r| {
        try testing.expectEqual(r.out, try egressIf(&fib, 2, r.dest));
        // :2 is the centre: "direct 1-hop paths to all other nodes" (p.13),
        // so next hop == destination.
        const e = fib.lookup(bmacOf(r.dest)).?;
        try testing.expectEqual(bmacOf(r.dest), e.next_hop_bmac);
    }
}

test "RFC 6329 §5 text: :1 routes :7, :3 and :5 via if/2, single-hop paths direct" {
    const gpa = testing.allocator;
    var table = try routeTableFor(gpa, 1);
    defer table.deinit();
    var fib = try fibFor(gpa, &table);
    defer fib.deinit();
    for ([_]u8{ 7, 3, 5 }) |d| {
        const e = fib.lookup(bmacOf(d)).?;
        try testing.expectEqual(bmacOf(2), e.next_hop_bmac); // via :2 (= if/2)
        try testing.expectEqual(@as(u64, 2), e.metric);
    }
    for ([_]u8{ 2, 4, 6 }) |d| {
        const e = fib.lookup(bmacOf(d)).?;
        try testing.expectEqual(bmacOf(d), e.next_hop_bmac); // direct
    }
}

test "RFC 6329 Figures 3/4: multicast group DA (SPSourceID = low 20 bits of B-MAC, I-SID 1)" {
    // Figure 3 M row: 7300-0100-0001. Figure 4 M rows: 7300-0100-0001 (:1),
    // 7300-0300-0001 (:3), 7300-0500-0001 (:5), 7300-0700-0001 (:7).
    const rows = [_]struct { node: u8, da: BMac }{
        .{ .node = 1, .da = .{ 0x73, 0x00, 0x01, 0x00, 0x00, 0x01 } },
        .{ .node = 3, .da = .{ 0x73, 0x00, 0x03, 0x00, 0x00, 0x01 } },
        .{ .node = 5, .da = .{ 0x73, 0x00, 0x05, 0x00, 0x00, 0x01 } },
        .{ .node = 7, .da = .{ 0x73, 0x00, 0x07, 0x00, 0x00, 0x01 } },
    };
    for (rows) |r| {
        const b = bmacOf(r.node);
        // "the last 20 bits of the B-MAC in the example" (p.12)
        const sp: u20 = (@as(u20, b[3] & 0x0F) << 16) | (@as(u20, b[4]) << 8) | b[5];
        try testing.expectEqual(@as(u20, 0x70000) | r.node, sp);
        try testing.expectEqual(r.da, fib_mod.groupDa(sp, 1));
        const back = fib_mod.parseGroupDa(r.da).?;
        try testing.expectEqual(sp, back.spsourceid);
        try testing.expectEqual(@as(u24, 1), back.isid);
    }
}
