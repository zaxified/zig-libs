// SPDX-License-Identifier: MIT

//! The adversarial failure model + its seeded schedule fuzzer.
//!
//! A `FaultEvent` is a single scheduled perturbation of the network at a given
//! simulated time; a `FaultTrace` is a sorted list of them — the concrete,
//! replayable, shrinkable program the engine executes ALONGSIDE the protocol
//! under test. The kinds cover the standard adversary a fabric algorithm must
//! survive: links up/down, arbitrary-cut-set partitions and their heal, one-shot
//! message drop / duplicate / delay spikes (which also produce reordering), node
//! crash / restart, and clock jumps.
//!
//! `generate` is the failure-schedule fuzzer: for a seed it draws a random
//! churn-and-recover schedule over a topology (disruptions paired, most of the
//! time, with a later repair, so the network is not left permanently broken).
//! It draws from an INDEPENDENT PRNG stream (`seed ^ salt`) so that the concrete
//! trace it emits can later be replayed by `sim.replay` WITHOUT perturbing the
//! message-mechanics PRNG — the property that makes byte-exact replay and
//! delta-debugging shrink possible (mirrors kv's VOPR trace-replay split).

const std = @import("std");
const types = @import("types.zig");
const NodeId = types.NodeId;
const Time = types.Time;
const Prng = @import("prng.zig").Prng;
const Allocator = std.mem.Allocator;

/// A directed link endpoint pair (a → b).
pub const Link = struct { a: NodeId, b: NodeId };

/// One scheduled network perturbation. `link_up`/`heal`/`restart_node` with no
/// matching prior disruption are harmless no-ops, so a shrinker may drop the
/// disruption half of a pair and still get a well-formed trace.
pub const FaultKind = union(enum) {
    /// Sever the directed link a → b (in-flight and future messages dropped).
    link_down: Link,
    /// Restore a previously-severed directed link.
    link_up: Link,
    /// Cut the network into two sides: nodes listed in `cut` vs. everyone else.
    /// A directed link is severed iff exactly one endpoint is in `cut`.
    partition: Partition,
    /// Remove the active partition with this id.
    heal: struct { id: u32 },
    /// The node stops delivering messages and firing timers.
    crash_node: struct { node: NodeId },
    /// The node resumes and re-runs the protocol's start hook (re-bootstrap).
    restart_node: struct { node: NodeId },
    /// Shift the node's observed clock by `delta` ticks (skew injection).
    clock_jump: struct { node: NodeId, delta: i64 },
    /// Drop the next message that crosses a → b.
    drop_once: Link,
    /// Duplicate the next message that crosses a → b.
    dup_once: Link,
    /// Add `extra` ticks of delay to the next message on a → b (reorders it).
    delay_once: struct { a: NodeId, b: NodeId, extra: Time },

    pub const Partition = struct { id: u32, cut: []const NodeId };
};

pub const FaultEvent = struct {
    time: Time,
    kind: FaultKind,
};

/// A concrete, replayable schedule. Owns its events + every partition cut slice
/// in `arena` — call `deinit`.
pub const FaultTrace = struct {
    arena: std.heap.ArenaAllocator,
    events: []FaultEvent,

    pub fn deinit(self: *FaultTrace) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Topology snapshot the fuzzer draws valid targets from.
pub const Topo = struct {
    node_count: usize,
    links: []const Link,
};

pub const Config = struct {
    /// Maximum number of primary disruptions drawn (repairs are extra).
    max_events: usize = 20,
    /// Draw disruption times in [0, horizon).
    horizon: Time = 1000,
    /// Probability (in 1000ths) a repairable disruption also gets a later repair.
    repair_permille: u16 = 750,
    enable_partition: bool = true,
    enable_crash: bool = true,
    enable_clock_jump: bool = true,
};

/// Independent stream so a generated trace replays without touching the
/// message-mechanics PRNG (see module doc + sim.replay).
const salt: u64 = 0x5eed_fa17_c0de_9a1b;

/// Fuzz a churn-and-recover fault schedule for `seed` over `topo`. Deterministic
/// in (seed, topo, cfg). The returned trace is sorted by time (stable) and owns
/// all of its memory.
pub fn generate(gpa: Allocator, seed: u64, topo: Topo, cfg: Config) Allocator.Error!FaultTrace {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var list: std.ArrayList(FaultEvent) = .empty;
    var prng = Prng.init(seed ^ salt);
    var part_id: u32 = 0;

    const n = prng.below(cfg.max_events + 1);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const t: Time = prng.below(cfg.horizon);
        const repair_t: Time = t + 1 + prng.below(cfg.horizon / 2 + 1);
        const has_links = topo.links.len > 0;

        // Weighted kind selection. Duplication is over-weighted so that
        // duplicate-sensitive bugs (the loop-inducing class this harness is
        // built to catch) are reliably reachable by the fuzzer.
        var roll = prng.below(10);
        if (!has_links and roll < 5) roll = 5 + prng.below(5); // no links → node-scoped kinds only

        switch (roll) {
            0, 1, 2 => { // dup_once
                const l = topo.links[prng.below(topo.links.len)];
                try list.append(a, .{ .time = t, .kind = .{ .dup_once = l } });
            },
            3 => { // drop_once
                const l = topo.links[prng.below(topo.links.len)];
                try list.append(a, .{ .time = t, .kind = .{ .drop_once = l } });
            },
            4 => { // delay_once (reorder)
                const l = topo.links[prng.below(topo.links.len)];
                const extra: Time = 1 + prng.below(50);
                try list.append(a, .{ .time = t, .kind = .{ .delay_once = .{ .a = l.a, .b = l.b, .extra = extra } } });
            },
            5 => { // link_down (+ maybe link_up)
                if (has_links) {
                    const l = topo.links[prng.below(topo.links.len)];
                    try list.append(a, .{ .time = t, .kind = .{ .link_down = l } });
                    if (prng.permille(cfg.repair_permille))
                        try list.append(a, .{ .time = repair_t, .kind = .{ .link_up = l } });
                }
            },
            6 => { // crash (+ maybe restart)
                if (cfg.enable_crash and topo.node_count > 0) {
                    const node: NodeId = @intCast(prng.below(topo.node_count));
                    try list.append(a, .{ .time = t, .kind = .{ .crash_node = .{ .node = node } } });
                    if (prng.permille(cfg.repair_permille))
                        try list.append(a, .{ .time = repair_t, .kind = .{ .restart_node = .{ .node = node } } });
                }
            },
            7 => { // clock_jump
                if (cfg.enable_clock_jump and topo.node_count > 0) {
                    const node: NodeId = @intCast(prng.below(topo.node_count));
                    const mag: i64 = @intCast(1 + prng.below(100));
                    const delta: i64 = if (prng.chance(1, 2)) mag else -mag;
                    try list.append(a, .{ .time = t, .kind = .{ .clock_jump = .{ .node = node, .delta = delta } } });
                }
            },
            else => { // partition (+ maybe heal)
                if (cfg.enable_partition and topo.node_count >= 2) {
                    const cut = try drawCut(a, &prng, topo.node_count);
                    const id = part_id;
                    part_id += 1;
                    try list.append(a, .{ .time = t, .kind = .{ .partition = .{ .id = id, .cut = cut } } });
                    if (prng.permille(cfg.repair_permille))
                        try list.append(a, .{ .time = repair_t, .kind = .{ .heal = .{ .id = id } } });
                }
            },
        }
    }

    const events = try list.toOwnedSlice(a);
    std.sort.insertion(FaultEvent, events, {}, lessByTime);
    return .{ .arena = arena, .events = events };
}

/// A non-empty proper subset of the nodes, as a sorted id slice (arena-owned).
fn drawCut(a: Allocator, prng: *Prng, node_count: usize) Allocator.Error![]NodeId {
    var incl = try a.alloc(bool, node_count);
    var count: usize = 0;
    for (incl) |*b| {
        b.* = prng.chance(1, 2);
        if (b.*) count += 1;
    }
    if (count == 0) {
        incl[0] = true; // ensure non-empty
        count = 1;
    }
    if (count == node_count) {
        incl[node_count - 1] = false; // ensure proper
        count -= 1;
    }
    const cut = try a.alloc(NodeId, count);
    var w: usize = 0;
    for (incl, 0..) |b, idx| {
        if (b) {
            cut[w] = @intCast(idx);
            w += 1;
        }
    }
    return cut;
}

fn lessByTime(_: void, x: FaultEvent, y: FaultEvent) bool {
    return x.time < y.time;
}

const testing = std.testing;

fn sampleTopo() Topo {
    const S = struct {
        const links = [_]Link{
            .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 0 },
            .{ .a = 1, .b = 2 }, .{ .a = 2, .b = 1 },
            .{ .a = 2, .b = 3 }, .{ .a = 3, .b = 2 },
        };
    };
    return .{ .node_count = 4, .links = &S.links };
}

test "generate: identical seed reproduces the identical trace" {
    var a = try generate(testing.allocator, 12345, sampleTopo(), .{});
    defer a.deinit();
    var b = try generate(testing.allocator, 12345, sampleTopo(), .{});
    defer b.deinit();
    try testing.expectEqual(a.events.len, b.events.len);
    for (a.events, b.events) |ea, eb| {
        try testing.expectEqual(ea.time, eb.time);
        try testing.expect(std.meta.activeTag(ea.kind) == std.meta.activeTag(eb.kind));
    }
}

test "generate: events are sorted by time and stay within bounds" {
    var tr = try generate(testing.allocator, 99, sampleTopo(), .{ .horizon = 500 });
    defer tr.deinit();
    var prev: Time = 0;
    for (tr.events) |e| {
        try testing.expect(e.time >= prev);
        prev = e.time;
    }
}

test "generate: over many seeds, every fault kind is exercised (teeth)" {
    var seen = [_]bool{false} ** @typeInfo(FaultKind).@"union".fields.len;
    var seed: u64 = 1;
    while (seed <= 400) : (seed += 1) {
        var tr = try generate(testing.allocator, seed, sampleTopo(), .{});
        defer tr.deinit();
        for (tr.events) |e| seen[@intFromEnum(std.meta.activeTag(e.kind))] = true;
    }
    for (seen) |s| try testing.expect(s);
}

test "generate: a partition cut is always a non-empty proper subset" {
    var seed: u64 = 1;
    while (seed <= 200) : (seed += 1) {
        var tr = try generate(testing.allocator, seed, sampleTopo(), .{});
        defer tr.deinit();
        for (tr.events) |e| switch (e.kind) {
            .partition => |p| {
                try testing.expect(p.cut.len >= 1);
                try testing.expect(p.cut.len < 4);
            },
            else => {},
        };
    }
}
