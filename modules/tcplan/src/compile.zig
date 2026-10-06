// SPDX-License-Identifier: MIT
//! The compiler: a validated `Topology` → an ordered, executable `Plan`.
//!
//! Two passes over the tree. The **assignment** pass walks queues ascending and
//! DFS pre-order within a queue, allocating every node its handle (and each
//! leaf its CAKE major + one filter prio per classifier) from `HandleSpace`, validating the
//! invariants as it goes, and collecting a flat `Resolved` list. The **emit**
//! pass turns that list into ops in kernel-valid order:
//!
//!   1. the `mq` root qdisc;
//!   2. one HTB root qdisc per used queue (ascending);
//!   3. every HTB class (the `Resolved` order is already parents-before-children);
//!   4. every subscriber's CAKE leaf qdisc;
//!   5. every subscriber classifier's steering filter.
//!
//! Because the assignment pass is a single deterministic traversal with no
//! maps or hashing, the same topology always compiles to the same plan.

const std = @import("std");
const tc = @import("tc");

const topology = @import("topology.zig");
const handles = @import("handles.zig");
const plan_mod = @import("plan.zig");

const Topology = topology.Topology;
const Node = topology.Node;
const Match = topology.Match;
const Operation = plan_mod.Operation;
const Plan = plan_mod.Plan;

pub const Error = std.mem.Allocator.Error || handles.Error || error{
    /// `queue_count == 0` — nothing to shape onto.
    NoQueues,
    /// `queue_count >= mq_root_major` (0x7FFF): HTB majors would reach the
    /// reserved `mq` major.
    QueueCountTooLarge,
    /// A top-level node left `cpu` unset — the root cannot infer a queue.
    RootCpuUnset,
    /// A node's `cpu` is `>= queue_count`.
    CpuOutOfRange,
    /// A descendant named a different `cpu` than its ancestor — its class
    /// chain would straddle two queues.
    CpuStraddle,
    /// A child's ceil exceeds its parent's ceil (HTB requires ceil ≤ parent).
    CeilExceedsParent,
    /// A `match` was set on an interior (non-leaf) node; only leaves steer.
    ClassifierOnInterior,
    /// Two `match` entries — of one subscriber or of two — can match the
    /// same packet (same family and direction, one prefix covers the other;
    /// an exact duplicate included). The lower filter prio would win
    /// silently, so the topology is refused.
    OverlappingMatch,
    /// A `match` prefix length exceeds its family (`> 32` for IPv4, `> 128`
    /// for IPv6); `tc`'s flower encoder would clamp it silently.
    InvalidPrefix,
    /// `htb.prio > htb_max_prio` (7); the kernel would clamp it silently.
    HtbPrioOutOfRange,
    /// `rate_bps == 0` — HTB has no rate to build a class from.
    ZeroRate,
    /// Two nodes share a `name`.
    DuplicateName,
};

/// A node after handle assignment + validation, ready to emit.
const Resolved = struct {
    class_handle: tc.Handle,
    parent_handle: tc.Handle,
    rate_bps: u64,
    ceil_bps: u64,
    is_leaf: bool,
    // Leaf-only fields (meaningless when `is_leaf` is false):
    cake: tc.Cake,
    cake_handle: tc.Handle,
    match: []const Match,
    /// The prio of `match[0]`; entry `i` uses `first_prio + i` (allocated
    /// consecutively from the per-queue counter).
    first_prio: u16,
    htb: topology.HtbKnobs,
};

/// Compile `topo` for interface `ifindex`. Caller owns the returned plan
/// (`Plan.deinit`).
pub fn compile(gpa: std.mem.Allocator, topo: Topology, ifindex: u32) Error!Plan {
    if (topo.queue_count == 0) return error.NoQueues;
    if (topo.queue_count >= handles.mq_root_major) return error.QueueCountTooLarge;

    var hs = try handles.HandleSpace.init(gpa, topo.queue_count);
    defer hs.deinit(gpa);

    var resolved: std.ArrayList(Resolved) = .empty;
    defer resolved.deinit(gpa);
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);

    const used = try gpa.alloc(bool, topo.queue_count);
    defer gpa.free(used);
    @memset(used, false);

    // ── assignment pass: queues ascending, DFS pre-order within a queue ──
    var cpu: u16 = 0;
    while (cpu < topo.queue_count) : (cpu += 1) {
        for (topo.roots) |root_node| {
            const c = root_node.cpu orelse return error.RootCpuUnset;
            if (c >= topo.queue_count) return error.CpuOutOfRange;
            if (c != cpu) continue;
            used[cpu] = true;
            try assign(gpa, &hs, &resolved, &names, root_node, cpu, handles.htbRoot(cpu), null);
        }
    }

    // Global name uniqueness (small topologies ⇒ a plain O(n²) scan, which is
    // also obviously order-independent).
    for (names.items, 0..) |a, i| {
        for (names.items[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a, b)) return error.DuplicateName;
        }
    }

    // Global classifier disjointness (prefix lengths were range-checked in
    // `assign`, which `overlaps` relies on).
    try checkDisjoint(gpa, resolved.items);

    // ── emit pass ──
    var ops: std.ArrayList(Operation) = .empty;
    errdefer ops.deinit(gpa);

    // 1. the mq root.
    try ops.append(gpa, .{ .qdisc = .{
        .target = .{ .ifindex = ifindex, .handle = handles.mqRoot(), .parent = tc.Handle.root },
        .spec = .{ .mq = .{} },
    } });

    // 2. per-queue HTB roots (ascending).
    cpu = 0;
    while (cpu < topo.queue_count) : (cpu += 1) {
        if (!used[cpu]) continue;
        try ops.append(gpa, .{ .qdisc = .{
            .target = .{ .ifindex = ifindex, .handle = handles.htbRoot(cpu), .parent = handles.mqParent(cpu) },
            .spec = .{ .htb = .{ .defcls = topo.htb_defcls } },
        } });
    }

    // 3. HTB classes (Resolved order is parents-before-children).
    for (resolved.items) |r| {
        try ops.append(gpa, .{ .class = .{
            .target = .{ .ifindex = ifindex, .handle = r.class_handle, .parent = r.parent_handle },
            .spec = .{ .htb = .{
                .rate = r.rate_bps,
                .ceil = r.ceil_bps,
                .burst = r.htb.burst,
                .cburst = r.htb.cburst,
                .prio = r.htb.prio,
                .quantum = r.htb.quantum,
            } },
        } });
    }

    // 4. CAKE leaf qdiscs.
    for (resolved.items) |r| {
        if (!r.is_leaf) continue;
        try ops.append(gpa, .{ .qdisc = .{
            .target = .{ .ifindex = ifindex, .handle = r.cake_handle, .parent = r.class_handle },
            .spec = .{ .cake = r.cake },
        } });
    }

    // 5. steering filters (attach at the leaf's queue HTB root, `(c+1):0`):
    //    one per `match` entry, in slice order, all into the leaf's class.
    for (resolved.items) |r| {
        if (!r.is_leaf) continue;
        for (r.match, 0..) |m, i| {
            try ops.append(gpa, .{
                .filter = .{
                    .target = .{
                        .ifindex = ifindex,
                        .parent = r.class_handle.qdisc(), // (c+1):0
                        .prio = @intCast(r.first_prio + i),
                        .eth_type = m.ethType(),
                    },
                    .spec = .{ .flower = flowerFor(m, r.class_handle) },
                },
            });
        }
    }

    return .{ .ops = try ops.toOwnedSlice(gpa) };
}

/// Recursively assign handles + validate one subtree pinned to `cpu`.
/// `parent_handle` is the attach point of `node`'s class (the queue HTB root
/// for a top-level node, else the parent class); `parent_ceil` is the
/// effective ceil to check `node` against (null at the top level).
fn assign(
    gpa: std.mem.Allocator,
    hs: *handles.HandleSpace,
    resolved: *std.ArrayList(Resolved),
    names: *std.ArrayList([]const u8),
    node: Node,
    cpu: u16,
    parent_handle: tc.Handle,
    parent_ceil: ?u64,
) Error!void {
    // A descendant that names a different CPU than the subtree it lives in
    // would straddle two queues.
    if (node.cpu) |nc| {
        if (nc != cpu) return error.CpuStraddle;
    }
    if (node.rate_bps == 0) return error.ZeroRate;

    const eff_ceil = node.effectiveCeil();
    if (parent_ceil) |pc| {
        if (eff_ceil > pc) return error.CeilExceedsParent;
    }

    const is_leaf = node.isLeaf();
    if (!is_leaf and node.match.len != 0) return error.ClassifierOnInterior;
    for (node.match) |m| if (!m.prefixValid()) return error.InvalidPrefix;
    if (node.htb.prio > topology.htb_max_prio) return error.HtbPrioOutOfRange;

    try names.append(gpa, node.name);

    const minor = try hs.nextClassMinor(cpu);
    const class_handle = tc.Handle.init(cpuToQueue(cpu), minor);

    var r: Resolved = .{
        .class_handle = class_handle,
        .parent_handle = parent_handle,
        .rate_bps = node.rate_bps,
        .ceil_bps = node.ceil_bps,
        .is_leaf = is_leaf,
        .cake = node.cake,
        .cake_handle = undefined,
        .match = if (is_leaf) node.match else &.{},
        .first_prio = 0,
        .htb = node.htb,
    };
    if (is_leaf) {
        r.cake_handle = tc.Handle.init(try hs.nextCakeMajor(), 0);
        // One prio per entry, consecutive: nothing else draws from this
        // queue's counter between these calls.
        for (node.match, 0..) |_, i| {
            const p = try hs.nextPrio(cpu);
            if (i == 0) r.first_prio = p;
        }
    }
    try resolved.append(gpa, r);

    for (node.children) |child| {
        try assign(gpa, hs, resolved, names, child, cpu, class_handle, eff_ceil);
    }
}

fn cpuToQueue(cpu: u16) u16 {
    return @intCast(@as(u32, cpu) + 1);
}

/// A classifier reduced to a sortable interval key: within one
/// (family, direction) class, a prefix is the address range starting at its
/// masked address. Prefixes are laminar (two ranges are nested or disjoint),
/// so after sorting by (family, dir, start, length) any overlap shows up
/// between two *adjacent* keys — an O(n log n) check instead of all pairs.
const MatchKey = struct {
    fam: u8,
    dir: u8,
    start: [16]u8,
    len: u8,
    m: Match,

    fn of(m: Match) MatchKey {
        var k: MatchKey = .{ .fam = 0, .dir = 0, .start = @splat(0), .len = 0, .m = m };
        switch (m) {
            .ipv4 => |v| {
                k.fam = 4;
                k.dir = @intFromEnum(v.dir);
                k.len = v.prefix_len;
                @memcpy(k.start[0..4], &v.addr);
            },
            .ipv6 => |v| {
                k.fam = 6;
                k.dir = @intFromEnum(v.dir);
                k.len = v.prefix_len;
                k.start = v.addr;
            },
        }
        // Clear the host bits (bit `len` onward).
        for (&k.start, 0..) |*b, i| {
            const lo: usize = i * 8;
            if (k.len >= lo + 8) continue;
            if (k.len <= lo) {
                b.* = 0;
            } else {
                b.* &= @as(u8, 0xFF) << @intCast(8 - (k.len - lo));
            }
        }
        return k;
    }

    fn lessThan(_: void, a: MatchKey, b: MatchKey) bool {
        if (a.fam != b.fam) return a.fam < b.fam;
        if (a.dir != b.dir) return a.dir < b.dir;
        return switch (std.mem.order(u8, &a.start, &b.start)) {
            .lt => true,
            .gt => false,
            .eq => a.len < b.len,
        };
    }
};

/// `error.OverlappingMatch` when any two classifiers in the topology — of
/// one subscriber or of two — can match the same packet.
fn checkDisjoint(gpa: std.mem.Allocator, resolved: []const Resolved) Error!void {
    var keys: std.ArrayList(MatchKey) = .empty;
    defer keys.deinit(gpa);
    for (resolved) |r| for (r.match) |m| try keys.append(gpa, .of(m));
    std.mem.sort(MatchKey, keys.items, {}, MatchKey.lessThan);
    if (keys.items.len < 2) return;
    for (keys.items[0 .. keys.items.len - 1], keys.items[1..]) |a, b| {
        if (a.m.overlaps(b.m)) return error.OverlappingMatch;
    }
}

/// Map a subscriber `Match` onto a value-typed `flower` spec that flows the
/// matched traffic into `classid`.
fn flowerFor(m: Match, classid: tc.Handle) tc.Flower {
    return switch (m) {
        .ipv4 => |v| blk: {
            const p: tc.Prefix4 = .{ .addr = v.addr, .prefix_len = v.prefix_len };
            break :blk .{
                .eth_type = tc.ETH_P.IP,
                .ipv4_src = if (v.dir == .src) p else null,
                .ipv4_dst = if (v.dir == .dst) p else null,
                .classid = classid,
            };
        },
        .ipv6 => |v| blk: {
            const p: tc.Prefix6 = .{ .addr = v.addr, .prefix_len = v.prefix_len };
            break :blk .{
                .eth_type = tc.ETH_P.IPV6,
                .ipv6_src = if (v.dir == .src) p else null,
                .ipv6_dst = if (v.dir == .dst) p else null,
                .classid = classid,
            };
        },
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const mbit = topology.mbit;

test "empty topology compiles to just the mq root" {
    const gpa = testing.allocator;
    var plan = try compile(gpa, .{ .queue_count = 4 }, 3);
    defer plan.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), plan.ops.len);
    try testing.expect(plan.ops[0] == .qdisc);
    try testing.expectEqual(handles.mqRoot().raw, plan.ops[0].qdisc.target.handle.raw);
    try testing.expectEqual(tc.Handle.root.raw, plan.ops[0].qdisc.target.parent.raw);
}

test "invariant: zero queues / oversized queue count" {
    const gpa = testing.allocator;
    try testing.expectError(error.NoQueues, compile(gpa, .{ .queue_count = 0 }, 1));
    try testing.expectError(error.QueueCountTooLarge, compile(gpa, .{ .queue_count = 0x7FFF }, 1));
}

test "invariant: a root node must name a cpu, and it must be in range" {
    const gpa = testing.allocator;
    const no_cpu = [_]Node{.{ .name = "s", .rate_bps = 1000 }};
    try testing.expectError(error.RootCpuUnset, compile(gpa, .{ .queue_count = 2, .roots = &no_cpu }, 1));

    const bad_cpu = [_]Node{.{ .name = "s", .rate_bps = 1000, .cpu = 5 }};
    try testing.expectError(error.CpuOutOfRange, compile(gpa, .{ .queue_count = 2, .roots = &bad_cpu }, 1));
}

test "invariant: a descendant may not cross to another cpu" {
    const gpa = testing.allocator;
    const sub = [_]Node{.{ .name = "sub", .rate_bps = 1000, .cpu = 1 }}; // straddles!
    const roots = [_]Node{.{ .name = "site", .rate_bps = 2000, .cpu = 0, .children = &sub }};
    try testing.expectError(error.CpuStraddle, compile(gpa, .{ .queue_count = 2, .roots = &roots }, 1));
}

test "invariant: child ceil may not exceed parent ceil" {
    const gpa = testing.allocator;
    const sub = [_]Node{.{ .name = "sub", .rate_bps = 1000, .ceil_bps = 5000 }};
    const roots = [_]Node{.{ .name = "site", .rate_bps = 2000, .ceil_bps = 3000, .cpu = 0, .children = &sub }};
    try testing.expectError(error.CeilExceedsParent, compile(gpa, .{ .queue_count = 1, .roots = &roots }, 1));
}

test "flowerFor: dir picks src vs dst field for both ipv4 and ipv6" {
    const classid = tc.Handle.init(1, 3);

    // ipv4, default dir (.dst)
    const m4_dst: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .prefix_len = 24 } };
    const f4_dst = flowerFor(m4_dst, classid);
    try testing.expectEqual(tc.ETH_P.IP, f4_dst.eth_type);
    try testing.expect(f4_dst.ipv4_src == null);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &f4_dst.ipv4_dst.?.addr);
    try testing.expectEqual(@as(u6, 24), f4_dst.ipv4_dst.?.prefix_len);

    // ipv4, dir = .src — the branch the golden/silent-leaf tests never exercise.
    const m4_src: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 }, .dir = .src } };
    const f4_src = flowerFor(m4_src, classid);
    try testing.expect(f4_src.ipv4_dst == null);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &f4_src.ipv4_src.?.addr);

    // ipv6, default dir (.dst) — field values, not just "a filter exists".
    const m6_dst: Match = .{ .ipv6 = .{ .addr = [_]u8{0xab} ** 16, .prefix_len = 64 } };
    const f6_dst = flowerFor(m6_dst, classid);
    try testing.expectEqual(tc.ETH_P.IPV6, f6_dst.eth_type);
    try testing.expect(f6_dst.ipv6_src == null);
    try testing.expectEqualSlices(u8, &([_]u8{0xab} ** 16), &f6_dst.ipv6_dst.?.addr);
    try testing.expectEqual(@as(u8, 64), f6_dst.ipv6_dst.?.prefix_len);

    // ipv6, dir = .src.
    const m6_src: Match = .{ .ipv6 = .{ .addr = [_]u8{0xcd} ** 16, .dir = .src } };
    const f6_src = flowerFor(m6_src, classid);
    try testing.expect(f6_src.ipv6_dst == null);
    try testing.expectEqualSlices(u8, &([_]u8{0xcd} ** 16), &f6_src.ipv6_src.?.addr);
    try testing.expectEqual(classid.raw, f6_src.classid.?.raw);
}

test "invariant: classifier on an interior node, zero rate, duplicate name" {
    const gpa = testing.allocator;

    const kid = [_]Node{.{ .name = "kid", .rate_bps = 500 }};
    const interior_match = [_]Node{.{
        .name = "site",
        .rate_bps = 1000,
        .cpu = 0,
        .match = &.{.{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } }},
        .children = &kid,
    }};
    try testing.expectError(error.ClassifierOnInterior, compile(gpa, .{ .queue_count = 1, .roots = &interior_match }, 1));

    const zero = [_]Node{.{ .name = "s", .rate_bps = 0, .cpu = 0 }};
    try testing.expectError(error.ZeroRate, compile(gpa, .{ .queue_count = 1, .roots = &zero }, 1));

    const dup = [_]Node{
        .{ .name = "same", .rate_bps = 1000, .cpu = 0 },
        .{ .name = "same", .rate_bps = 1000, .cpu = 0 },
    };
    try testing.expectError(error.DuplicateName, compile(gpa, .{ .queue_count = 1, .roots = &dup }, 1));
}

test "invariant: cpu == queue_count is out of range, not silently dropped" {
    const gpa = testing.allocator;
    const edge = [_]Node{.{ .name = "s", .rate_bps = 1000, .cpu = 2 }};
    try testing.expectError(error.CpuOutOfRange, compile(gpa, .{ .queue_count = 2, .roots = &edge }, 1));
}

test "invariant: a child with ceil 0 is checked by its effective ceil (= its rate)" {
    const gpa = testing.allocator;
    const sub = [_]Node{.{ .name = "sub", .rate_bps = 4000 }}; // ceil 0 ⇒ 4000
    const roots = [_]Node{.{ .name = "site", .rate_bps = 2000, .ceil_bps = 3000, .cpu = 0, .children = &sub }};
    try testing.expectError(error.CeilExceedsParent, compile(gpa, .{ .queue_count = 1, .roots = &roots }, 1));
}

test "htb_defcls reaches every per-queue HTB root" {
    const gpa = testing.allocator;
    const roots = [_]Node{
        .{ .name = "a", .rate_bps = 1000, .cpu = 0 },
        .{ .name = "b", .rate_bps = 1000, .cpu = 1 },
    };
    var p = try compile(gpa, .{ .queue_count = 2, .htb_defcls = 0x42, .roots = &roots }, 1);
    defer p.deinit(gpa);
    var htb_roots: usize = 0;
    for (p.ops) |op| if (op == .qdisc and op.qdisc.spec == .htb) {
        try testing.expectEqual(@as(u32, 0x42), op.qdisc.spec.htb.defcls);
        htb_roots += 1;
    };
    try testing.expectEqual(@as(usize, 2), htb_roots);
}

test "a leaf without a classifier does not consume a filter prio" {
    const gpa = testing.allocator;
    const subs = [_]Node{
        .{ .name = "silent", .rate_bps = 500 },
        .{ .name = "steered", .rate_bps = 500, .match = &.{.{ .ipv4 = .{ .addr = .{ 10, 0, 0, 9 } } }} },
    };
    const roots = [_]Node{.{ .name = "site", .rate_bps = 1000, .cpu = 0, .children = &subs }};
    var p = try compile(gpa, .{ .queue_count = 1, .roots = &roots }, 1);
    defer p.deinit(gpa);
    const last = p.ops[p.ops.len - 1];
    try testing.expect(last == .filter);
    try testing.expectEqual(@as(u16, 1), last.filter.target.prio);
}

test "multi-match: one class, one filter per entry, consecutive prios in slice order" {
    const gpa = testing.allocator;
    const v6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01 } ++ [_]u8{0} ** 10;
    const subs = [_]Node{
        .{ .name = "dual", .rate_bps = 500, .match = &.{
            .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 1 } } },
            .{ .ipv6 = .{ .addr = v6, .prefix_len = 56 } },
            .{ .ipv4 = .{ .addr = .{ 192, 0, 2, 0 }, .prefix_len = 29 } },
        } },
        .{ .name = "next", .rate_bps = 500, .match = &.{.{ .ipv4 = .{ .addr = .{ 100, 64, 0, 2 } } }} },
    };
    const roots = [_]Node{.{ .name = "site", .rate_bps = 1000, .cpu = 0, .children = &subs }};
    var p = try compile(gpa, .{ .queue_count = 1, .roots = &roots }, 1);
    defer p.deinit(gpa);

    // mq + htb root + 3 classes + 2 cakes + 4 filters.
    try testing.expectEqual(@as(usize, 11), p.ops.len);
    const f = p.ops[7..];
    const want_prio = [_]u16{ 1, 2, 3, 4 };
    const want_class = [_]u32{ 0x00010002, 0x00010002, 0x00010002, 0x00010003 };
    const want_eth = [_]u16{ tc.ETH_P.IP, tc.ETH_P.IPV6, tc.ETH_P.IP, tc.ETH_P.IP };
    for (f, want_prio, want_class, want_eth) |op, prio, cls, eth| {
        try testing.expect(op == .filter);
        try testing.expectEqual(prio, op.filter.target.prio);
        try testing.expectEqual(eth, op.filter.target.eth_type);
        try testing.expectEqual(@as(u32, 0x00010000), op.filter.target.parent.raw);
        try testing.expectEqual(cls, op.filter.spec.flower.classid.?.raw);
    }
    try testing.expectEqual(@as(u8, 56), f[1].filter.spec.flower.ipv6_dst.?.prefix_len);
    try testing.expectEqual(@as(u6, 29), f[2].filter.spec.flower.ipv4_dst.?.prefix_len);
    // Still exactly one CAKE per subscriber.
    var cakes: usize = 0;
    for (p.ops) |op| if (op == .qdisc and op.qdisc.spec == .cake) {
        cakes += 1;
    };
    try testing.expectEqual(@as(usize, 2), cakes);
}

test "invariant: overlapping classifiers are refused, within and across subscribers" {
    const gpa = testing.allocator;
    // Within one subscriber: an exact duplicate.
    const dup_in = [_]Node{.{ .name = "s", .rate_bps = 1000, .cpu = 0, .match = &.{
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } },
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } },
    } }};
    try testing.expectError(error.OverlappingMatch, compile(gpa, .{ .queue_count = 1, .roots = &dup_in }, 1));

    // Across subscribers on different queues: a /24 covering another's /32.
    const across = [_]Node{
        .{ .name = "a", .rate_bps = 1000, .cpu = 0, .match = &.{.{ .ipv4 = .{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 24 } }} },
        .{ .name = "b", .rate_bps = 1000, .cpu = 1, .match = &.{.{ .ipv4 = .{ .addr = .{ 10, 0, 0, 200 } } }} },
    };
    try testing.expectError(error.OverlappingMatch, compile(gpa, .{ .queue_count = 2, .roots = &across }, 1));

    // IPv6, input order reversed against sort order: a host given first,
    // the /32 covering it given second.
    const v6a: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    const v6b: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0xff } ++ [_]u8{0} ** 11;
    const nested = [_]Node{
        .{ .name = "z", .rate_bps = 1000, .cpu = 0, .match = &.{.{ .ipv6 = .{ .addr = v6b } }} },
        .{ .name = "x", .rate_bps = 1000, .cpu = 0, .match = &.{.{ .ipv6 = .{ .addr = v6a, .prefix_len = 32 } }} },
    };
    try testing.expectError(error.OverlappingMatch, compile(gpa, .{ .queue_count = 1, .roots = &nested }, 1));

    // Not overlapping: same address in opposite directions; v4 vs v6; and
    // disjoint IPv6 prefixes either side of a sort boundary.
    const fine = [_]Node{
        .{ .name = "up", .rate_bps = 1000, .cpu = 0, .match = &.{
            .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .dir = .src } },
            .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .dir = .dst } },
            .{ .ipv6 = .{ .addr = v6a, .prefix_len = 64 } },
        } },
        .{ .name = "other", .rate_bps = 1000, .cpu = 0, .match = &.{.{ .ipv6 = .{ .addr = v6b } }} },
    };
    var p = try compile(gpa, .{ .queue_count = 1, .roots = &fine }, 1);
    p.deinit(gpa);
}

test "invariant: prefix length past the family is refused" {
    const gpa = testing.allocator;
    const v4 = [_]Node{.{ .name = "s", .rate_bps = 1000, .cpu = 0, .match = &.{.{ .ipv4 = .{ .addr = @splat(0), .prefix_len = 33 } }} }};
    try testing.expectError(error.InvalidPrefix, compile(gpa, .{ .queue_count = 1, .roots = &v4 }, 1));
    const v6 = [_]Node{.{ .name = "s", .rate_bps = 1000, .cpu = 0, .match = &.{.{ .ipv6 = .{ .addr = @splat(0), .prefix_len = 129 } }} }};
    try testing.expectError(error.InvalidPrefix, compile(gpa, .{ .queue_count = 1, .roots = &v6 }, 1));
}

test "htb knobs reach the class op; prio past 7 is refused" {
    const gpa = testing.allocator;
    const subs = [_]Node{.{ .name = "s", .rate_bps = 500, .htb = .{ .burst = 32768, .cburst = 65536, .prio = 7, .quantum = 3000 } }};
    const roots = [_]Node{.{ .name = "site", .rate_bps = 1000, .cpu = 0, .htb = .{ .prio = 1 }, .children = &subs }};
    var p = try compile(gpa, .{ .queue_count = 1, .roots = &roots }, 1);
    defer p.deinit(gpa);
    const site = p.ops[2].class.spec.htb;
    try testing.expectEqual(@as(u32, 1), site.prio);
    try testing.expectEqual(@as(u32, 0), site.burst);
    const leaf = p.ops[3].class.spec.htb;
    try testing.expectEqual(@as(u32, 32768), leaf.burst);
    try testing.expectEqual(@as(u32, 65536), leaf.cburst);
    try testing.expectEqual(@as(u32, 7), leaf.prio);
    try testing.expectEqual(@as(u32, 3000), leaf.quantum);

    const bad = [_]Node{.{ .name = "s", .rate_bps = 1000, .cpu = 0, .htb = .{ .prio = 8 } }};
    try testing.expectError(error.HtbPrioOutOfRange, compile(gpa, .{ .queue_count = 1, .roots = &bad }, 1));
}

test "multi-match: prio exhaustion on a later entry is a typed error" {
    const gpa = testing.allocator;
    var hs = try handles.HandleSpace.init(gpa, 1);
    defer hs.deinit(gpa);
    hs.prio_next[0] = 0xFFFF; // exactly one prio left
    var resolved: std.ArrayList(Resolved) = .empty;
    defer resolved.deinit(gpa);
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);
    const two: Node = .{ .name = "s", .rate_bps = 1, .match = &.{
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } },
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 } } },
    } };
    try testing.expectError(error.HandleExhausted, assign(gpa, &hs, &resolved, &names, two, 0, handles.htbRoot(0), null));
}
