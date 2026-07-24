// SPDX-License-Identifier: MIT
//! The compiler: a validated `Topology` → an ordered, executable `Plan`.
//!
//! Two passes over the tree. The **assignment** pass walks queues ascending and
//! DFS pre-order within a queue, allocating every node its handle (and each
//! leaf its CAKE major + filter prio) from `HandleSpace`, validating the
//! invariants as it goes, and collecting a flat `Resolved` list. The **emit**
//! pass turns that list into ops in kernel-valid order:
//!
//!   1. the `mq` root qdisc;
//!   2. one HTB root qdisc per used queue (ascending);
//!   3. every HTB class (the `Resolved` order is already parents-before-children);
//!   4. every subscriber's CAKE leaf qdisc;
//!   5. every subscriber's steering filter.
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
    match: ?Match,
    prio: u16,
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
            .spec = .{ .htb = .{ .rate = r.rate_bps, .ceil = r.ceil_bps } },
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

    // 5. steering filters (attach at the leaf's queue HTB root, `(c+1):0`).
    for (resolved.items) |r| {
        if (!r.is_leaf) continue;
        const m = r.match orelse continue;
        try ops.append(gpa, .{
            .filter = .{
                .target = .{
                    .ifindex = ifindex,
                    .parent = r.class_handle.qdisc(), // (c+1):0
                    .prio = r.prio,
                    .eth_type = m.ethType(),
                },
                .spec = .{ .flower = flowerFor(m, r.class_handle) },
            },
        });
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
    if (!is_leaf and node.match != null) return error.ClassifierOnInterior;

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
        .match = if (is_leaf) node.match else null,
        .prio = 0,
    };
    if (is_leaf) {
        r.cake_handle = tc.Handle.init(try hs.nextCakeMajor(), 0);
        if (node.match != null) r.prio = try hs.nextPrio(cpu);
    }
    try resolved.append(gpa, r);

    for (node.children) |child| {
        try assign(gpa, hs, resolved, names, child, cpu, class_handle, eff_ceil);
    }
}

fn cpuToQueue(cpu: u16) u16 {
    return @intCast(@as(u32, cpu) + 1);
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

test "invariant: classifier on an interior node, zero rate, duplicate name" {
    const gpa = testing.allocator;

    const kid = [_]Node{.{ .name = "kid", .rate_bps = 500 }};
    const interior_match = [_]Node{.{
        .name = "site",
        .rate_bps = 1000,
        .cpu = 0,
        .match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } },
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
