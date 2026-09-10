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

pub const ConfigError = error{
    /// `Config.horizon` is 0, i.e. an empty `[0, horizon)` window to draw
    /// disruption times from. There is no schedule to generate: every event
    /// would land at t=0 and every repair at t=1, which is not a churn
    /// schedule but a rounding artefact. Rejected rather than quietly
    /// produced — this is the boundary where a zero bound enters, and
    /// `Prng.below` deliberately does not guess on the caller's behalf.
    ZeroHorizon,
};

pub const Error = Allocator.Error || ConfigError;

/// Fuzz a churn-and-recover fault schedule for `seed` over `topo`. Deterministic
/// in (seed, topo, cfg). The returned trace is sorted by time (stable) and owns
/// all of its memory.
pub fn generate(gpa: Allocator, seed: u64, topo: Topo, cfg: Config) Error!FaultTrace {
    if (cfg.horizon == 0) return error.ZeroHorizon;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var list: std.ArrayList(FaultEvent) = .empty;
    var prng = Prng.init(seed ^ salt);
    var part_id: u32 = 0;

    const n = prng.below(cfg.max_events + 1);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const t: Time = prng.belowWide(cfg.horizon);
        // audit F14: plain `+` overflows when `horizon` is close to
        // `maxInt(u64)` (Debug: `panic: integer overflow`; ReleaseFast: wraps
        // modularly, so a "repair" can land BEFORE the disruption it repairs
        // and the trace sorts into a nonsensical order, silently). Saturating
        // add instead: a `repair_t` that saturates at `maxInt(Time)` is still
        // a valid, sortable, in-the-future tick — just one that will never
        // actually occur before the run's `until` in practice, which is
        // exactly what "the repair landed effectively never" should mean.
        const repair_t: Time = t +| 1 +| prng.belowWide(cfg.horizon / 2 + 1);
        const has_links = topo.links.len > 0;
        const can_crash = cfg.enable_crash and topo.node_count > 0;
        const can_clock_jump = cfg.enable_clock_jump and topo.node_count > 0;
        const can_partition = cfg.enable_partition and topo.node_count >= 2;

        // Weighted kind selection over only the kinds this (topo, cfg) pair
        // can currently EMIT. Weights mirror the original design: duplication
        // is over-weighted (3) so duplicate-sensitive bugs (the loop-inducing
        // class this harness is built to catch) stay reliably reachable;
        // partition carries weight 2; every other kind is 1.
        //
        // audit F5: the previous version drew `roll = below(10)` over ALL ten
        // slots unconditionally, then no-op'd the branches an inapplicable
        // roll landed on (`enable_crash == false`, no links, a single node).
        // That silently deletes that roll's share of the schedule instead of
        // redistributing it — `Config.max_events` was documented as "maximum
        // number of primary disruptions drawn" but was actually only a bound
        // on the number of *draws*, of which some fraction (measured: up to
        // 40% with all three optional kinds off) produced nothing. A disabled
        // or inapplicable kind is now EXCLUDED from the draw itself, so every
        // draw in `[0, n)` emits exactly one primary disruption and the
        // config's promise holds regardless of which kinds are enabled.
        //
        // This changes the emitted schedule for any (seed, topo, cfg) where
        // a kind is disabled or a link/node precondition doesn't hold — by
        // design (user decision, DECISIONS.md §2 `netsim` F5): "the instrument
        // that generates a different schedule than its config claims is the
        // defective one; old seeds are sacrificed." For the fully-enabled,
        // has-links, multi-node case (the module's own default `Config{}`)
        // the ten weights below sum to 10 and this draw is unchanged.
        const dup_w: usize = if (has_links) 3 else 0;
        const drop_w: usize = if (has_links) 1 else 0;
        const delay_w: usize = if (has_links) 1 else 0;
        const link_down_w: usize = if (has_links) 1 else 0;
        const crash_w: usize = if (can_crash) 1 else 0;
        const clock_jump_w: usize = if (can_clock_jump) 1 else 0;
        const partition_w: usize = if (can_partition) 2 else 0;
        const total_w = dup_w + drop_w + delay_w + link_down_w + crash_w + clock_jump_w + partition_w;
        if (total_w == 0) continue; // nothing this (topo, cfg) pair can express at all

        var roll = prng.below(total_w);
        if (roll < dup_w) {
            const l = topo.links[prng.below(topo.links.len)];
            try list.append(a, .{ .time = t, .kind = .{ .dup_once = l } });
            continue;
        }
        roll -= dup_w;
        if (roll < drop_w) {
            const l = topo.links[prng.below(topo.links.len)];
            try list.append(a, .{ .time = t, .kind = .{ .drop_once = l } });
            continue;
        }
        roll -= drop_w;
        if (roll < delay_w) {
            const l = topo.links[prng.below(topo.links.len)];
            const extra: Time = 1 + prng.below(50);
            try list.append(a, .{ .time = t, .kind = .{ .delay_once = .{ .a = l.a, .b = l.b, .extra = extra } } });
            continue;
        }
        roll -= delay_w;
        if (roll < link_down_w) {
            const l = topo.links[prng.below(topo.links.len)];
            try list.append(a, .{ .time = t, .kind = .{ .link_down = l } });
            if (prng.permille(cfg.repair_permille))
                try list.append(a, .{ .time = repair_t, .kind = .{ .link_up = l } });
            continue;
        }
        roll -= link_down_w;
        if (roll < crash_w) {
            const node: NodeId = @intCast(prng.below(topo.node_count));
            try list.append(a, .{ .time = t, .kind = .{ .crash_node = .{ .node = node } } });
            if (prng.permille(cfg.repair_permille))
                try list.append(a, .{ .time = repair_t, .kind = .{ .restart_node = .{ .node = node } } });
            continue;
        }
        roll -= crash_w;
        if (roll < clock_jump_w) {
            const node: NodeId = @intCast(prng.below(topo.node_count));
            const mag: i64 = @intCast(1 + prng.below(100));
            const delta: i64 = if (prng.chance(1, 2)) mag else -mag;
            try list.append(a, .{ .time = t, .kind = .{ .clock_jump = .{ .node = node, .delta = delta } } });
            continue;
        }
        // else: partition (+ maybe heal) — the only remaining weight.
        const cut = try drawCut(a, &prng, topo.node_count);
        const id = part_id;
        part_id += 1;
        try list.append(a, .{ .time = t, .kind = .{ .partition = .{ .id = id, .cut = cut } } });
        if (prng.permille(cfg.repair_permille))
            try list.append(a, .{ .time = repair_t, .kind = .{ .heal = .{ .id = id } } });
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

test "Config: the documented defaults are pinned, not just prose (audit F4 teeth)" {
    // The audit's mutate.sh found that shrinking the `max_events` default
    // from 20 to 1 survives the pre-fix suite untouched — nothing pinned the
    // struct's own defaults against its doc comments.
    const cfg = Config{};
    try testing.expectEqual(@as(usize, 20), cfg.max_events);
    try testing.expectEqual(@as(Time, 1000), cfg.horizon);
    try testing.expectEqual(@as(u16, 750), cfg.repair_permille);
    try testing.expect(cfg.enable_partition);
    try testing.expect(cfg.enable_crash);
    try testing.expect(cfg.enable_clock_jump);
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

fn noLinksTopo() Topo {
    return .{ .node_count = 4, .links = &.{} };
}

test "generate: disabling a fault kind redistributes its weight, not drops it (audit F5)" {
    // Before the fix, `generate` drew `roll = below(10)` unconditionally over
    // ALL ten weighted slots, then no-op'd (silently dropped) any roll that
    // landed on a disabled or inapplicable kind (`enable_crash == false`, a
    // link-scoped kind with no links, `enable_partition == false`, …). So
    // `Config.max_events` — documented as "maximum number of primary
    // disruptions drawn" — actually bounded the number of *draws*, of which
    // the audit measured up to 40% silently producing nothing with every
    // optional kind off. `loopfree-reconv` turns all three off and so was
    // getting a ~40% weaker schedule than its own `max_events = 20` promised.
    //
    // This test recomputes exactly how many draws `generate` intends to make
    // (replaying the identical `seed ^ salt` PRNG stream it seeds internally)
    // and asserts every intended draw now yields exactly one primary
    // disruption, for every combination below, on a topology WITH links —
    // where under the old code only the fully-enabled config lost nothing.
    const cfgs = [_]Config{
        .{}, // baseline: everything on
        .{ .enable_partition = false },
        .{ .enable_crash = false },
        .{ .enable_clock_jump = false },
        .{ .enable_partition = false, .enable_crash = false, .enable_clock_jump = false }, // audit's -40.1% case
    };
    for (cfgs) |cfg| {
        var total_intended: usize = 0;
        var total_primary: usize = 0;
        var seed: u64 = 1;
        while (seed <= 500) : (seed += 1) {
            var p = Prng.init(seed ^ salt);
            total_intended += p.below(cfg.max_events + 1);

            var tr = try generate(testing.allocator, seed, sampleTopo(), cfg);
            defer tr.deinit();
            for (tr.events) |e| switch (e.kind) {
                .dup_once, .drop_once, .delay_once, .link_down, .crash_node, .clock_jump, .partition => total_primary += 1,
                .link_up, .heal, .restart_node => {}, // repairs, not primary draws
            };
        }
        try testing.expectEqual(total_intended, total_primary);
    }

    // Same property on a topology WITHOUT links (audit's -19.9% case): only
    // the node-scoped kinds are available, so exclude the all-optional-off
    // combination (nothing at all would be expressible there, which is
    // correctly zero, not a regression).
    const link_free_cfgs = [_]Config{
        .{},
        .{ .enable_partition = false },
        .{ .enable_crash = false },
        .{ .enable_clock_jump = false },
    };
    for (link_free_cfgs) |cfg| {
        var total_intended: usize = 0;
        var total_primary: usize = 0;
        var seed: u64 = 1;
        while (seed <= 500) : (seed += 1) {
            var p = Prng.init(seed ^ salt);
            total_intended += p.below(cfg.max_events + 1);

            var tr = try generate(testing.allocator, seed, noLinksTopo(), cfg);
            defer tr.deinit();
            for (tr.events) |e| switch (e.kind) {
                .dup_once, .drop_once, .delay_once, .link_down, .crash_node, .clock_jump, .partition => total_primary += 1,
                .link_up, .heal, .restart_node => {}, // repairs, not primary draws
            };
        }
        try testing.expectEqual(total_intended, total_primary);
    }
}

test "generate: a huge horizon does not overflow computing repair_t (audit F14)" {
    // Pre-fix, `t + 1 + belowWide(horizon/2+1)` used plain `+`, so a horizon
    // near `maxInt(u64)` panicked in Debug ("integer overflow") the first
    // time a repair-bearing kind (link_down+link_up, crash+restart,
    // partition+heal) was drawn — and wrapped modularly in ReleaseFast,
    // putting the "repair" before the disruption it repairs. `repair_permille
    // = 1000` forces a repair to be drawn every time one is eligible, and 50
    // seeds over all fault kinds is enough to exercise the computation
    // repeatedly at the overflow boundary.
    var seed: u64 = 1;
    while (seed <= 50) : (seed += 1) {
        var tr = try generate(testing.allocator, seed, sampleTopo(), .{
            .horizon = std.math.maxInt(u64),
            .max_events = 10,
            .repair_permille = 1000,
        });
        tr.deinit();
    }
}

test "config boundary: horizon 0 is rejected, not silently collapsed to t=0" {
    // The finding (netsim F3): `cfg.horizon` reaches `Prng.below` unchecked, so
    // a 0 was `assert(n > 0)` in Debug and `next() % 0` — illegal behaviour —
    // in ReleaseFast. Both halves are covered here: the config boundary now
    // says no, and `Prng.below` is total in every build (see prng.zig's test).
    try testing.expectError(
        error.ZeroHorizon,
        generate(testing.allocator, 7, sampleTopo(), .{ .horizon = 0 }),
    );
    // Nothing else about the config is second-guessed: a horizon of 1 is a
    // legal, if degenerate, window and still produces a trace.
    var tr = try generate(testing.allocator, 7, sampleTopo(), .{ .horizon = 1 });
    defer tr.deinit();
    for (tr.events) |e| try testing.expect(e.time <= 2); // t in [0,1), repair t+1+[0,1)
    // `max_events = 0` is a legal "no faults" schedule, so it must NOT be
    // rejected — the guard is about the time window, not about emptiness.
    var none = try generate(testing.allocator, 7, sampleTopo(), .{ .max_events = 0 });
    defer none.deinit();
    try testing.expectEqual(@as(usize, 0), none.events.len);
}
