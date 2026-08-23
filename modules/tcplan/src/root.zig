// SPDX-License-Identifier: MIT
//! tcplan — compile a hierarchical traffic-shaping topology (site → AP →
//! subscriber, each with committed/ceil rates) into a deterministic, ordered
//! plan of `tc` operations (mq root → per-CPU HTB class trees → CAKE leaves +
//! steering filters), honouring the cpumap→MQ→per-CPU-HTB alignment invariant.
//!
//! This is a **pure compiler**: it builds on the sibling `tc` module's types
//! and produces a `Plan` of `(target, spec)` operations expressed in exactly
//! those types; it performs no I/O, no netlink and no privileged operation. The
//! caller executes the plan by feeding each op through tc's request builders
//! and driving a `tc.Socket`.
//!
//! ```zig
//! const sub = [_]tcplan.Node{
//!     .{ .name = "alice", .rate_bps = tcplan.mbit(100), .ceil_bps = tcplan.mbit(500),
//!        .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 1 } } } },
//! };
//! const ap = [_]tcplan.Node{
//!     .{ .name = "ap1", .rate_bps = tcplan.mbit(500), .ceil_bps = tcplan.mbit(500),
//!        .children = &sub },
//! };
//! const sites = [_]tcplan.Node{
//!     .{ .name = "site1", .rate_bps = tcplan.mbit(1000), .ceil_bps = tcplan.mbit(1000),
//!        .cpu = 0, .children = &ap },
//! };
//! var plan = try tcplan.compile(gpa, .{ .queue_count = 4, .roots = &sites }, ifindex);
//! defer plan.deinit(gpa);
//! // Execute: a reconciling shaper uses `.replace` for idempotence.
//! for (plan.ops) |op| {
//!     const bytes = try op.buildRequest(gpa, sock.nl.nextSeq(), .replace, sock.psched);
//!     defer gpa.free(bytes);
//!     // … sock.nl.requestAck(bytes, seq) …
//! }
//! ```

const std = @import("std");

pub const topology = @import("topology.zig");
pub const handles = @import("handles.zig");
pub const plan = @import("plan.zig");
const compile_mod = @import("compile.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Compiles a hierarchical shaping topology (site→AP→subscriber) into a deterministic ordered plan of `tc` ops — mq root + per-CPU HTB trees + CAKE leaves; pure, caller executes",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "linux",
    .targets = .{.linux64},
    .platform = .linux, // produces Linux tc plans (built on the `tc` module)
    .role = .util, // pure compiler: plan in, no I/O
    .concurrency = .reentrant, // no shared state; caller-supplied allocator
    .model_after = "LibreQoS cpumap→MQ→per-CPU-HTB + CAKE leaf arrangement → tc plan",
    .deps = .{"tc"},
};

// ── the input model ─────────────────────────────────────────────────────────
pub const Topology = topology.Topology;
pub const Node = topology.Node;
pub const Match = topology.Match;
pub const Dir = topology.Dir;
pub const mbit = topology.mbit;

// ── the output model ────────────────────────────────────────────────────────
pub const Plan = plan.Plan;
pub const Operation = plan.Operation;
pub const QdiscOp = plan.QdiscOp;
pub const ClassOp = plan.ClassOp;
pub const FilterOp = plan.FilterOp;

// ── handle-allocation constants ─────────────────────────────────────────────
pub const mq_root_major = handles.mq_root_major;
pub const HandleSpace = handles.HandleSpace;

// ── the compiler ────────────────────────────────────────────────────────────
pub const compile = compile_mod.compile;
pub const Error = compile_mod.Error;

// ── tests ───────────────────────────────────────────────────────────────────

const tc = @import("tc");
const testing = std.testing;

// A small-but-non-trivial golden topology: 2 CPUs/queues × 2 sites × an
// access-point tier × a few CAKE subscribers with IPv4 steering. Held at
// container scope so the nested slices have static storage (a topology built
// from function-local array literals would dangle once returned by value).
const golden_subs_a = [_]Node{
    .{ .name = "sub-a1", .rate_bps = mbit(100), .ceil_bps = mbit(200), .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 1 } } } },
    .{ .name = "sub-a2", .rate_bps = mbit(100), .ceil_bps = mbit(200), .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 2 } } } },
};
const golden_aps_a = [_]Node{.{ .name = "ap-a1", .rate_bps = mbit(1000), .ceil_bps = mbit(1000), .children = &golden_subs_a }};
const golden_subs_b = [_]Node{
    .{ .name = "sub-b1", .rate_bps = mbit(100), .ceil_bps = mbit(500), .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 3 } } } },
};
const golden_aps_b = [_]Node{.{ .name = "ap-b1", .rate_bps = mbit(500), .ceil_bps = mbit(500), .children = &golden_subs_b }};
const golden_roots = [_]Node{
    .{ .name = "site-a", .rate_bps = mbit(1000), .ceil_bps = mbit(1000), .cpu = 0, .children = &golden_aps_a },
    .{ .name = "site-b", .rate_bps = mbit(500), .ceil_bps = mbit(500), .cpu = 1, .children = &golden_aps_b },
};
const golden_topo: Topology = .{ .queue_count = 2, .roots = &golden_roots };

fn goldenTopology() Topology {
    return golden_topo;
}

fn expectQdisc(op: Operation, handle: u32, parent: u32) !void {
    try testing.expect(op == .qdisc);
    try testing.expectEqual(handle, op.qdisc.target.handle.raw);
    try testing.expectEqual(parent, op.qdisc.target.parent.raw);
}

fn expectHtbClass(op: Operation, handle: u32, parent: u32, rate: u64, ceil: u64) !void {
    try testing.expect(op == .class);
    try testing.expectEqual(handle, op.class.target.handle.raw);
    try testing.expectEqual(parent, op.class.target.parent.raw);
    try testing.expect(op.class.spec == .htb);
    try testing.expectEqual(rate, op.class.spec.htb.rate);
    try testing.expectEqual(ceil, op.class.spec.htb.ceil);
}

test "golden plan: exact handles, targets, rates, kinds and order" {
    const gpa = testing.allocator;
    var p = try compile(gpa, goldenTopology(), 7);
    defer p.deinit(gpa);

    try testing.expectEqual(@as(usize, 16), p.ops.len);

    // 1 mq root + 2 HTB roots.
    try expectQdisc(p.ops[0], 0x7FFF0000, tc.Handle.root.raw); // mq
    try testing.expect(p.ops[0].qdisc.spec == .mq);
    try expectQdisc(p.ops[1], 0x00010000, 0x7FFF0001); // htb root, cpu0 under mq child 1
    try testing.expect(p.ops[1].qdisc.spec == .htb);
    try expectQdisc(p.ops[2], 0x00020000, 0x7FFF0002); // htb root, cpu1 under mq child 2

    // HTB classes: DFS pre-order per queue, parents before children.
    try expectHtbClass(p.ops[3], 0x00010001, 0x00010000, mbit(1000), mbit(1000)); // site-a
    try expectHtbClass(p.ops[4], 0x00010002, 0x00010001, mbit(1000), mbit(1000)); // ap-a1
    try expectHtbClass(p.ops[5], 0x00010003, 0x00010002, mbit(100), mbit(200)); // sub-a1
    try expectHtbClass(p.ops[6], 0x00010004, 0x00010002, mbit(100), mbit(200)); // sub-a2
    try expectHtbClass(p.ops[7], 0x00020001, 0x00020000, mbit(500), mbit(500)); // site-b
    try expectHtbClass(p.ops[8], 0x00020002, 0x00020001, mbit(500), mbit(500)); // ap-b1
    try expectHtbClass(p.ops[9], 0x00020003, 0x00020002, mbit(100), mbit(500)); // sub-b1

    // CAKE leaves: one per subscriber, globally-unique majors 3,4,5.
    try expectQdisc(p.ops[10], 0x00030000, 0x00010003); // sub-a1 cake under 1:3
    try testing.expect(p.ops[10].qdisc.spec == .cake);
    try expectQdisc(p.ops[11], 0x00040000, 0x00010004); // sub-a2 cake under 1:4
    try expectQdisc(p.ops[12], 0x00050000, 0x00020003); // sub-b1 cake under 2:3

    // Steering filters: attach at the queue HTB root, per-queue prio, flower
    // dst-IP → leaf class.
    try testing.expect(p.ops[13] == .filter);
    try testing.expectEqual(@as(u32, 0x00010000), p.ops[13].filter.target.parent.raw); // 1:0
    try testing.expectEqual(@as(u16, 1), p.ops[13].filter.target.prio);
    try testing.expectEqual(tc.ETH_P.IP, p.ops[13].filter.target.eth_type);
    try testing.expect(p.ops[13].filter.spec == .flower);
    try testing.expectEqualSlices(u8, &.{ 100, 64, 0, 1 }, &p.ops[13].filter.spec.flower.ipv4_dst.?.addr);
    try testing.expectEqual(@as(u32, 0x00010003), p.ops[13].filter.spec.flower.classid.?.raw);

    try testing.expectEqual(@as(u16, 2), p.ops[14].filter.target.prio); // sub-a2, same queue ⇒ prio 2
    try testing.expectEqual(@as(u32, 0x00010004), p.ops[14].filter.spec.flower.classid.?.raw);

    try testing.expectEqual(@as(u32, 0x00020000), p.ops[15].filter.target.parent.raw); // 2:0
    try testing.expectEqual(@as(u16, 1), p.ops[15].filter.target.prio); // queue 2 prio resets to 1
    try testing.expectEqual(@as(u32, 0x00020003), p.ops[15].filter.spec.flower.classid.?.raw);
}

test "golden plan has unique handles and valid parent-before-child order" {
    const gpa = testing.allocator;
    var p = try compile(gpa, goldenTopology(), 7);
    defer p.deinit(gpa);
    try testing.expectEqual(@as(?tc.Handle, null), p.findHandleCollision());
    try testing.expectEqual(@as(?usize, null), try p.firstOrderingViolation(gpa));
}

test "executability: every op builds valid netlink bytes through the real tc builders" {
    const gpa = testing.allocator;
    var p = try compile(gpa, goldenTopology(), 7);
    defer p.deinit(gpa);

    const ps = tc.Psched.fallback;
    for (p.ops) |op| {
        const bytes = try op.buildRequest(gpa, 1, .replace, ps);
        defer gpa.free(bytes);
        try testing.expect(bytes.len > tc.codec.header_len);
        // The first message's type must match the op family.
        var it: tc.codec.MessageIterator = .{ .buf = bytes };
        const m = (try it.next()).?;
        const expected: u16 = switch (op) {
            .qdisc => tc.message.RTM_NEWQDISC,
            .class => tc.message.RTM_NEWTCLASS,
            .filter => tc.message.RTM_NEWTFILTER,
        };
        try testing.expectEqual(expected, m.type);
    }
}

test "determinism: the same topology compiles to a byte-identical plan twice" {
    const gpa = testing.allocator;
    var a = try compile(gpa, goldenTopology(), 7);
    defer a.deinit(gpa);
    var b = try compile(gpa, goldenTopology(), 7);
    defer b.deinit(gpa);

    try testing.expectEqual(a.ops.len, b.ops.len);
    const ps = tc.Psched.fallback;
    for (a.ops, b.ops) |oa, ob| {
        try testing.expectEqual(std.meta.activeTag(oa), std.meta.activeTag(ob));
        const ba = try oa.buildRequest(gpa, 1, .replace, ps);
        defer gpa.free(ba);
        const bb = try ob.buildRequest(gpa, 1, .replace, ps);
        defer gpa.free(bb);
        try testing.expectEqualSlices(u8, ba, bb);
    }
}

test "a leaf without a classifier gets a class + CAKE but no filter" {
    const gpa = testing.allocator;
    const subs = &[_]Node{
        .{ .name = "silent", .rate_bps = mbit(50) }, // no match
        .{ .name = "steered", .rate_bps = mbit(50), .match = .{ .ipv6 = .{ .addr = @splat(0) } } },
    };
    const roots = &[_]Node{.{ .name = "site", .rate_bps = mbit(100), .cpu = 0, .children = subs }};
    var p = try compile(gpa, .{ .queue_count = 1, .roots = roots }, 1);
    defer p.deinit(gpa);

    var filters: usize = 0;
    var cakes: usize = 0;
    for (p.ops) |op| switch (op) {
        .filter => filters += 1,
        .qdisc => |q| if (q.spec == .cake) {
            cakes += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 2), cakes); // both leaves get CAKE
    try testing.expectEqual(@as(usize, 1), filters); // only the one with a match steers
}

test {
    // dark-tests aggregator (CONVENTIONS §6.3): a bare re-export does not pull
    // a submodule's tests into the binary.
    _ = topology;
    _ = handles;
    _ = plan;
    _ = compile_mod;
}
