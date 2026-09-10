// SPDX-License-Identifier: MIT

//! netsim — deterministic, seeded, discrete-event network simulator.
//!
//! A message-passing topology model (nodes, directed links with per-link
//! latency / jitter / loss / dup / reorder / bandwidth, per-node clock skew)
//! driven by a seeded PRNG and a single time-ordered event queue with
//! deterministic tie-breaking — so every run is a pure function of its seed and
//! replays byte-for-byte. On top sits the adversary: a seeded failure-schedule
//! fuzzer (link up/down, arbitrary-cut partitions + heal, message drop / dup /
//! delay spikes, node crash / restart, clock jumps), caller-registered invariant
//! predicates checked after every event, byte-exact replay of a concrete trace,
//! and a delta-debugging counterexample minimizer.
//!
//! This is the VOPR methodology proven in `kv`, generalized from a single store
//! to a network. It is the harness that model-checks fabric algorithms
//! (loop-free reconvergence, DF-election, liveness) and serves a fleet simulator;
//! the algorithms themselves are separate consumer modules that plug in a
//! `Protocol` (step/handler + invariant) — netsim bakes in no fabric specifics.
//!
//! API shape:
//!   - build a topology in a `Scenario` (`addNode` / `addLink` / `addBiLink`);
//!   - implement the algorithm as a `Protocol` (onStart / onMessage / onTimer /
//!     check) that acts through the `Sim` (`send` / `setTimer` / `neighbors`);
//!   - `run(case, fault_cfg)` fuzzes a schedule and returns `.ok` or `.violated`
//!     with the exact `FaultTrace` reproducer;
//!   - `replay(case, trace)` re-runs a concrete trace (deterministic oracle);
//!   - `findFailing` + `shrink` search a seed range and minimize a counterexample.
//!
//! Provenance: modeled after TigerBeetle's VOPR (design reference only; no code
//! consulted or copied — credited in the repository NOTICE). The splitmix64
//! mixer is Sebastiano Vigna's public-domain algorithm. Clean-room on top of
//! this module's own engine; borrows kv's VOPR methodology, not its code.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("types.zig");
const sim_mod = @import("sim.zig");
const fault_mod = @import("fault.zig");
const shrink_mod = @import("shrink.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Deterministic seeded discrete-event network simulator (latency/loss/partition/clock-skew, failure fuzzer, byte-exact replay) — model-checking harness for fabric algorithms",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure simulation, no OS/network I/O
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "TigerBeetle VOPR / deterministic discrete-event network simulation",
    .deps = .{}, // std only (borrows kv's VOPR methodology, not its code)
};

// ── public API ───────────────────────────────────────────────────────────────

pub const NodeId = types.NodeId;
pub const Time = types.Time;

pub const Sim = sim_mod.Sim;
pub const LinkConfig = sim_mod.LinkConfig;
pub const LinkConfigError = sim_mod.LinkConfigError;
pub const NodeConfig = sim_mod.NodeConfig;
pub const Protocol = sim_mod.Protocol;
pub const Scenario = sim_mod.Scenario;
pub const Case = sim_mod.Case;
pub const RunOutcome = sim_mod.RunOutcome;
pub const RunResult = sim_mod.RunResult;
pub const Violation = sim_mod.Violation;
pub const GenResult = sim_mod.GenResult;
pub const TopoOwned = sim_mod.TopoOwned;
pub const Log = sim_mod.Log;
pub const LogEntry = sim_mod.LogEntry;

pub const snapshotTopo = sim_mod.snapshotTopo;
pub const replay = sim_mod.replay;
pub const run = sim_mod.run;

pub const FaultKind = fault_mod.FaultKind;
pub const FaultEvent = fault_mod.FaultEvent;
pub const FaultTrace = fault_mod.FaultTrace;
pub const FaultConfig = fault_mod.Config;
pub const Topo = fault_mod.Topo;
pub const Link = fault_mod.Link;
pub const generateFaultTrace = fault_mod.generate;

pub const Failing = shrink_mod.Failing;
pub const ShrinkResult = shrink_mod.ShrinkResult;
pub const findFailing = shrink_mod.findFailing;
pub const shrinkTrace = shrink_mod.shrink;

// ── toy protocols (used by the tests below; illustrate the plug-in shape) ────
//
// These are deliberately minimal reference consumers, NOT part of the fabric:
// `Flood` is a correct duplicate-suppressing broadcast (exercises delivery,
// partitions, determinism); `LoopyForward` is a deliberately buggy forwarder
// whose next-hop logic ping-pongs once any single packet is duplicated — the
// harness's teeth witness (a real forwarding loop the invariant hook catches).

const testing = std.testing;

/// Monotonic wall-clock read for the F10 perf test only — std.time.Timer was
/// removed; this is the same `clock_gettime(.MONOTONIC)` pattern used by
/// other modules' benches (e.g. `bfv`'s `bench.zig`).
fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

const FLOOD_N = 5;

/// Correct epoch-broadcast flood with per-epoch duplicate suppression. The
/// origin re-broadcasts on a timer; each node forwards a never-seen epoch to all
/// neighbors except the sender. No invariant (it is used to probe connectivity
/// and determinism, not to fail).
const Flood = struct {
    gpa: Allocator,
    node_count: usize,
    origin: NodeId = 0,
    period: Time = 100,
    max_epoch: u32 = 60, // epoch used as a bit index into a u64 mask
    cur_epoch: u32 = 0,
    seen: []u64, // per node: bit e set once epoch e has been seen
    received: []u32, // per node: count of distinct epochs received

    fn init(gpa: Allocator, node_count: usize) Allocator.Error!Flood {
        const seen = try gpa.alloc(u64, node_count);
        @memset(seen, 0);
        const received = try gpa.alloc(u32, node_count);
        @memset(received, 0);
        return .{ .gpa = gpa, .node_count = node_count, .seen = seen, .received = received };
    }

    fn deinit(self: *Flood, gpa: Allocator) void {
        gpa.free(self.seen);
        gpa.free(self.received);
        self.* = undefined;
    }

    fn protocol(self: *Flood) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *Flood {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        @memset(self.seen, 0);
        @memset(self.received, 0);
        self.cur_epoch = 0;
    }

    fn floodFrom(self: *Flood, sim: *Sim, node: NodeId, epoch: u32, exclude: ?NodeId) anyerror!void {
        _ = self;
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, epoch, .little);
        var nb: [16]NodeId = undefined;
        const n = try sim.neighbors(node, &nb);
        for (nb[0..n]) |peer| {
            if (exclude) |ex| {
                if (peer == ex) continue;
            }
            try sim.send(node, peer, &buf);
        }
    }

    fn originate(self: *Flood, sim: *Sim, epoch: u32) anyerror!void {
        if (epoch >= self.max_epoch) return;
        self.seen[self.origin] |= (@as(u64, 1) << @intCast(epoch));
        try self.floodFrom(sim, self.origin, epoch, null);
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        if (node != self.origin) return;
        try self.originate(sim, 0);
        try sim.setTimer(node, self.period, 0);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        _ = timer_id;
        self.cur_epoch += 1;
        if (self.cur_epoch >= self.max_epoch) return;
        try self.originate(sim, self.cur_epoch);
        try sim.setTimer(node, self.period, 0);
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const epoch = std.mem.readInt(u32, payload[0..4], .little);
        if (epoch >= self.max_epoch) return;
        const bit = @as(u64, 1) << @intCast(epoch);
        if (self.seen[node] & bit != 0) return; // already forwarded this epoch
        self.seen[node] |= bit;
        self.received[node] += 1;
        try self.floodFrom(sim, node, epoch, from);
    }
};

/// A minimal 2-node ping/pong: node0 sends "ping" to node1 at t=0 (during
/// bootstrap — synchronous, so a fault armed at t=0 does NOT catch this first
/// send, same caveat as `example/main.zig`'s dup_once); node1 replies "pong"
/// FROM WITHIN the event-processing loop, which a t=0 fault on the 1->0
/// direction has already had a chance to arm. Used by the audit-F4 "teeth"
/// tests below: each checks that a specific fault kind actually changes this
/// protocol's observable behavior, not just that it appears in a trace.
const PingPong = struct {
    pings_sent: u32 = 0,
    pongs_sent: u32 = 0,
    pongs_received: u32 = 0,
    last_pong_clock: i64 = 0,
    /// If set, node0 also resends "ping" on a timer of this period — used by
    /// the restart_node test, where the first several sends are expected to
    /// be dropped (node1 still crashed) and a later one must get through.
    resend_period: ?Time = null,

    fn protocol(self: *PingPong) Protocol {
        return .{ .ctx = self, .onStartFn = onStart, .onMessageFn = onMessage, .onTimerFn = onTimer };
    }

    fn cast(ctx: *anyopaque) *PingPong {
        return @ptrCast(@alignCast(ctx));
    }

    fn sendPing(self: *PingPong, sim: *Sim) anyerror!void {
        self.pings_sent += 1;
        try sim.send(0, 1, "ping");
        if (self.resend_period) |p| try sim.setTimer(0, p, 0);
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        if (node == 0) try self.sendPing(sim);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        _ = timer_id;
        const self = cast(ctx);
        if (node == 0) try self.sendPing(sim);
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        _ = from;
        const self = cast(ctx);
        if (node == 1 and std.mem.eql(u8, payload, "ping")) {
            self.pongs_sent += 1;
            try sim.send(1, 0, "pong");
        } else if (node == 0 and std.mem.eql(u8, payload, "pong")) {
            self.pongs_received += 1;
            self.last_pong_clock = sim.clock(0);
        }
    }
};

fn pingPongScenario(sim: *Sim) anyerror!void {
    _ = try sim.addNode(.{});
    _ = try sim.addNode(.{});
    try sim.addBiLink(0, 1, .{ .latency = 5 });
}

test "F4 teeth: drop_once actually drops the message it targets, not just appears in the trace" {
    const gpa = testing.allocator;
    var pp = PingPong{};
    const case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = pp.protocol(), .until = 100 };
    const trace = [_]FaultEvent{.{ .time = 0, .kind = .{ .drop_once = .{ .a = 1, .b = 0 } } }};
    _ = try replay(gpa, case, &trace, null);
    try testing.expectEqual(@as(u32, 1), pp.pongs_sent); // node1 DID send the pong...
    try testing.expectEqual(@as(u32, 0), pp.pongs_received); // ...but it never arrived

    // Positive control: without the fault, the pong arrives.
    var clean = PingPong{};
    const clean_case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = clean.protocol(), .until = 100 };
    _ = try replay(gpa, clean_case, &.{}, null);
    try testing.expectEqual(@as(u32, 1), clean.pongs_received);
}

test "F4 teeth: link_down actually severs the direction it targets" {
    const gpa = testing.allocator;
    var pp = PingPong{};
    const case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = pp.protocol(), .until = 100 };
    const trace = [_]FaultEvent{.{ .time = 0, .kind = .{ .link_down = .{ .a = 1, .b = 0 } } }};
    _ = try replay(gpa, case, &trace, null);
    try testing.expectEqual(@as(u32, 1), pp.pongs_sent); // sent, but 1->0 is down
    try testing.expectEqual(@as(u32, 0), pp.pongs_received);
}

test "F4 teeth: crash_node actually stops the node from processing messages" {
    const gpa = testing.allocator;
    var pp = PingPong{};
    const case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = pp.protocol(), .until = 100 };
    const trace = [_]FaultEvent{.{ .time = 0, .kind = .{ .crash_node = .{ .node = 1 } } }};
    _ = try replay(gpa, case, &trace, null);
    // node1 crashed before the ping (latency 5) arrives, so it never even
    // runs onMessage — pongs_sent, not just pongs_received, must be 0.
    try testing.expectEqual(@as(u32, 0), pp.pongs_sent);
    try testing.expectEqual(@as(u32, 0), pp.pongs_received);
}

test "F4 teeth: restart_node actually revives the node (it resumes processing later messages)" {
    const gpa = testing.allocator;
    var pp = PingPong{ .resend_period = 20 };
    const case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = pp.protocol(), .until = 100 };
    const trace = [_]FaultEvent{
        .{ .time = 0, .kind = .{ .crash_node = .{ .node = 1 } } },
        .{ .time = 50, .kind = .{ .restart_node = .{ .node = 1 } } },
    };
    _ = try replay(gpa, case, &trace, null);
    // Pings at t=0,20,40 arrive (latency 5) at t=5,25,45 — all before the
    // t=50 restart, so all three are dropped while node1 is crashed. Pings
    // at t=60,80 arrive at t=65,85, after the restart: those must land.
    try testing.expect(pp.pongs_sent >= 1);
}

test "F4 teeth: delay_once actually delays the message it targets" {
    const gpa = testing.allocator;
    var pp = PingPong{};
    const case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = pp.protocol(), .until = 200 };
    const trace = [_]FaultEvent{.{ .time = 0, .kind = .{ .delay_once = .{ .a = 1, .b = 0, .extra = 50 } } }};
    _ = try replay(gpa, case, &trace, null);
    // Baseline: ping@0 -> arrives node1@5 -> pong@5 -> arrives node0@10.
    // With +50 on the 1->0 leg: pong arrives node0@60, not @10.
    try testing.expectEqual(@as(i64, 60), pp.last_pong_clock);

    var clean = PingPong{};
    const clean_case = Case{ .seed = 1, .scenario = pingPongScenario, .protocol = clean.protocol(), .until = 200 };
    _ = try replay(gpa, clean_case, &.{}, null);
    try testing.expectEqual(@as(i64, 10), clean.last_pong_clock);
}

const LOOPY_N = 4;
const LOOPY_DEST: NodeId = 3;
const LOOPY_MAX_EPOCH = 16;

/// Deliberately BUGGY line-forwarder (dest = last node). Each epoch-packet is
/// forwarded one hop toward the destination — correct on FIRST receipt. The bug:
/// on any SECOND receipt of the same (node, epoch) it forwards BACK to the
/// sender instead of dropping the duplicate, so a single duplicated packet makes
/// two adjacent nodes ping-pong forever. Invariant: no (node, epoch) is visited
/// more than `threshold` times ("no forwarding loop"). Clean runs never trip it;
/// exactly one `dup_once` fault on a forward link does.
const LoopyForward = struct {
    gpa: Allocator,
    node_count: usize,
    dest: NodeId,
    threshold: u32 = 3,
    period: Time = 40,
    cur_epoch: u32 = 0,
    /// visits[node * LOOPY_MAX_EPOCH + epoch]
    visits: []u32,

    fn init(gpa: Allocator, node_count: usize, dest: NodeId) Allocator.Error!LoopyForward {
        const visits = try gpa.alloc(u32, node_count * LOOPY_MAX_EPOCH);
        @memset(visits, 0);
        return .{ .gpa = gpa, .node_count = node_count, .dest = dest, .visits = visits };
    }

    fn deinit(self: *LoopyForward, gpa: Allocator) void {
        gpa.free(self.visits);
        self.* = undefined;
    }

    fn protocol(self: *LoopyForward) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *LoopyForward {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        @memset(self.visits, 0);
        self.cur_epoch = 0;
    }

    fn idx(self: *const LoopyForward, node: NodeId, epoch: u32) usize {
        _ = self;
        return @as(usize, node) * LOOPY_MAX_EPOCH + epoch;
    }

    fn originate(self: *LoopyForward, sim: *Sim, epoch: u32) anyerror!void {
        _ = self;
        if (epoch >= LOOPY_MAX_EPOCH) return;
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, epoch, .little);
        try sim.send(0, 1, &buf); // originate at node 0, one hop toward dest
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        if (node != 0) return;
        try self.originate(sim, 0);
        try sim.setTimer(0, self.period, 0);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        _ = node;
        _ = timer_id;
        self.cur_epoch += 1;
        if (self.cur_epoch >= LOOPY_MAX_EPOCH) return;
        try self.originate(sim, self.cur_epoch);
        try sim.setTimer(0, self.period, 0);
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const epoch = std.mem.readInt(u32, payload[0..4], .little);
        if (epoch >= LOOPY_MAX_EPOCH) return;
        const v = &self.visits[self.idx(node, epoch)];
        v.* += 1;
        if (node == self.dest) return; // consumed at the destination
        if (v.* == 1) {
            try sim.send(node, node + 1, payload); // correct: one hop toward dest
        } else {
            try sim.send(node, from, payload); // BUG: bounce the duplicate back
        }
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        for (self.visits) |v| {
            if (v > self.threshold) return error.ForwardingLoop;
        }
    }
};

// ── F9 perf: a ring big enough that topology-build cost isn't swamped by
//    the noise of a shared dev machine (unlike a 5-node scenario) ───────────
const F9_RING_N = 256;

fn f9RingScenario(sim: *Sim) anyerror!void {
    var i: usize = 0;
    while (i < F9_RING_N) : (i += 1) _ = try sim.addNode(.{});
    const cfg = LinkConfig{ .latency = 1 };
    var j: NodeId = 0;
    while (j < F9_RING_N) : (j += 1) try sim.addBiLink(j, @intCast((j + 1) % F9_RING_N), cfg);
}

const F9NoopProtocol = struct {
    fn onMessage(_: *anyopaque, _: *Sim, _: NodeId, _: NodeId, _: []const u8) anyerror!void {}
};

fn floodScenario(sim: *Sim) anyerror!void {
    var i: usize = 0;
    while (i < FLOOD_N) : (i += 1) _ = try sim.addNode(.{});
    // Jitter exercises the message PRNG (so determinism has something to prove);
    // no loss keeps the partition assertions crisp.
    const cfg = LinkConfig{ .latency = 5, .jitter = 3 };
    var j: NodeId = 0;
    while (j + 1 < FLOOD_N) : (j += 1) try sim.addBiLink(j, j + 1, cfg);
}

fn loopyScenario(sim: *Sim) anyerror!void {
    var i: usize = 0;
    while (i < LOOPY_N) : (i += 1) _ = try sim.addNode(.{});
    const cfg = LinkConfig{ .latency = 10 }; // deterministic timing
    var j: NodeId = 0;
    while (j + 1 < LOOPY_N) : (j += 1) try sim.addBiLink(j, j + 1, cfg);
}

// ── the four required integration tests ──────────────────────────────────────

test "determinism: an identical seed + trace reproduces an identical event stream" {
    const gpa = testing.allocator;
    var flood = try Flood.init(gpa, FLOOD_N);
    defer flood.deinit(gpa);
    const case = Case{ .seed = 0xC0FFEE, .scenario = floodScenario, .protocol = flood.protocol(), .until = 1000 };

    const topo = try snapshotTopo(gpa, case);
    defer gpa.free(topo.links);
    var trace = try generateFaultTrace(gpa, case.seed, .{ .node_count = topo.node_count, .links = topo.links }, .{});
    defer trace.deinit();

    var log1 = Log{};
    defer log1.deinit(gpa);
    var log2 = Log{};
    defer log2.deinit(gpa);
    const r1 = try replay(gpa, case, trace.events, &log1);
    const r2 = try replay(gpa, case, trace.events, &log2);

    try testing.expectEqual(r1.fingerprint, r2.fingerprint);
    try testing.expect(r1.fingerprint != 0);
    try testing.expect(Log.eql(&log1, &log2));
    try testing.expect(log1.entries.items.len > 10); // real traffic happened (teeth)
}

test "determinism: run() twice for one seed yields identical fuzzed schedule + result" {
    const gpa = testing.allocator;
    var flood = try Flood.init(gpa, FLOOD_N);
    defer flood.deinit(gpa);
    const case = Case{ .seed = 42, .scenario = floodScenario, .protocol = flood.protocol(), .until = 1000 };

    var g1 = try run(gpa, case, .{});
    defer g1.trace.deinit();
    var g2 = try run(gpa, case, .{});
    defer g2.trace.deinit();

    try testing.expectEqual(g1.result.fingerprint, g2.result.fingerprint);
    try testing.expectEqual(g1.result.events_processed, g2.result.events_processed);
    try testing.expectEqual(g1.trace.events.len, g2.trace.events.len);
}

test "partition severs delivery across the cut; heal restores it" {
    const gpa = testing.allocator;
    const cut = [_]NodeId{ 3, 4 }; // isolates {3,4} from {0,1,2} (origin side)

    // Never healed: the far side (node 4) receives nothing, but the near side
    // (nodes 0-2, entirely outside the cut) still floods normally among itself —
    // this pins down that severing is scoped to links CROSSING the cut, not to
    // every link touching a cut partition (a same-side-severs inversion would
    // still zero out node 4 by accident on a chain topology, since it would cut
    // the near-side relay links too; asserting the near side stays live rules
    // that out).
    var f_b = try Flood.init(gpa, FLOOD_N);
    defer f_b.deinit(gpa);
    const case_b = Case{ .seed = 7, .scenario = floodScenario, .protocol = f_b.protocol(), .until = 1000 };
    const trace_b = [_]FaultEvent{.{ .time = 0, .kind = .{ .partition = .{ .id = 1, .cut = &cut } } }};
    _ = try replay(gpa, case_b, &trace_b, null);
    try testing.expectEqual(@as(u32, 0), f_b.received[4]);
    try testing.expect(f_b.received[2] > 0);

    // Healed at t=500: the far side receives epochs originated after the heal.
    var f_a = try Flood.init(gpa, FLOOD_N);
    defer f_a.deinit(gpa);
    const case_a = Case{ .seed = 7, .scenario = floodScenario, .protocol = f_a.protocol(), .until = 1000 };
    const trace_a = [_]FaultEvent{
        .{ .time = 0, .kind = .{ .partition = .{ .id = 1, .cut = &cut } } },
        .{ .time = 500, .kind = .{ .heal = .{ .id = 1 } } },
    };
    _ = try replay(gpa, case_a, &trace_a, null);
    try testing.expect(f_a.received[4] > 0);
}

test "invariant hook catches a forwarding loop triggered by a duplicate" {
    const gpa = testing.allocator;
    var loopy = try LoopyForward.init(gpa, LOOPY_N, LOOPY_DEST);
    defer loopy.deinit(gpa);
    const case = Case{ .seed = 1, .scenario = loopyScenario, .protocol = loopy.protocol(), .until = 500 };

    // Clean: correct forward path, no loop, invariant holds.
    const clean = try replay(gpa, case, &.{}, null);
    try testing.expectEqual(RunOutcome.ok, clean.outcome);

    // One duplicate on the forward link 1→2 starts a ping-pong loop.
    const trace = [_]FaultEvent{.{ .time = 0, .kind = .{ .dup_once = .{ .a = 1, .b = 2 } } }};
    const bad = try replay(gpa, case, &trace, null);
    try testing.expectEqual(RunOutcome.violated, bad.outcome);
    try testing.expectEqual(error.ForwardingLoop, bad.violation.?.err);
}

test "shrink: a fuzzed failing schedule minimizes to a still-reproducing core" {
    const gpa = testing.allocator;
    var loopy = try LoopyForward.init(gpa, LOOPY_N, LOOPY_DEST);
    defer loopy.deinit(gpa);
    const template = Case{ .seed = 0, .scenario = loopyScenario, .protocol = loopy.protocol(), .until = 500 };

    var failing = (try findFailing(gpa, template, .{}, 1, 500)) orelse return error.NoFailingSeed;
    defer failing.deinit();
    try testing.expectEqual(error.ForwardingLoop, failing.err);

    var res = try shrinkTrace(gpa, &failing);
    defer res.deinit();
    try testing.expect(res.after >= 1);
    try testing.expect(res.after <= res.before);
    if (res.before > 1) try testing.expect(res.after < res.before); // it actually shrank

    // The minimized trace STILL reproduces the same invariant violation...
    const r = try replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(RunOutcome.violated, r.outcome);
    try testing.expectEqual(error.ForwardingLoop, r.violation.?.err);
    // ...and it retains a duplicate — the loop's root cause.
    var has_dup = false;
    for (res.trace.events) |e| {
        if (std.meta.activeTag(e.kind) == .dup_once) has_dup = true;
    }
    try testing.expect(has_dup);
}

test "perf: replay(log_out=null) is not slower than replay(log_out=non-null) (audit F10)" {
    // `replay` used to build the full event `Log` unconditionally, even when
    // `log_out == null` — as the ddmin shrink loop calls it thousands of
    // times. The audit's own A/B (ReleaseFast, ring topology, two
    // independent sessions) measured ~1.68x: 2416µs with the log vs 1441µs
    // without. This is a coarse, noise-tolerant regression guard (a strict
    // ratio would be flaky across machines/CI): the no-log path must not
    // come out slower than the with-log path, which would only happen if
    // `want_log` stopped being honored.
    const gpa = testing.allocator;
    var flood = try Flood.init(gpa, FLOOD_N);
    defer flood.deinit(gpa);
    const case = Case{ .seed = 1, .scenario = floodScenario, .protocol = flood.protocol(), .until = 5000 };
    const iters = 30;

    const start1 = nowNs();
    for (0..iters) |_| {
        var log = Log{};
        defer log.deinit(gpa);
        _ = try replay(gpa, case, &.{}, &log);
    }
    const with_log_ns = nowNs() - start1;

    const start2 = nowNs();
    for (0..iters) |_| _ = try replay(gpa, case, &.{}, null);
    const without_log_ns = nowNs() - start2;

    std.debug.print(
        "F10 perf: with_log={d}ns without_log={d}ns ({d} iters)\n",
        .{ with_log_ns, without_log_ns, iters },
    );
    try testing.expect(without_log_ns <= with_log_ns);
}

test "perf: run() builds the topology once, not twice (audit F9)" {
    // `run` used to call `snapshotTopo` (which builds a whole `Sim`, running
    // `case.scenario`, just to copy out the topology) and THEN `replay`
    // (which builds ANOTHER fresh `Sim` and runs `case.scenario` again) —
    // `case.scenario`'s own contract (deterministic, no unseeded randomness)
    // makes the second build strictly redundant. The audit's own A/B
    // (ReleaseFast, ring topology, two independent sessions) measured the
    // two builds at ~47-51% of a `run()` call across 32/256/2048 nodes. This
    // reconstructs that old two-build path explicitly (both halves are still
    // public on their own) against the new single-build `run`, on a 256-node
    // ring (a handful of nodes made the earlier draft of this test flaky —
    // the build-cost difference was too small to clear the noise of a shared
    // dev machine) and A/B-interleaved per iteration rather than run as two
    // sequential blocks, so a load spike hits both arms rather than just one
    // (`feedback_ratio_needs_one_instant`). Coarse, noise-tolerant regression
    // guard, not a strict ratio.
    const gpa = testing.allocator;
    var unused: usize = 0;
    const case = Case{
        .seed = 1,
        .scenario = f9RingScenario,
        .protocol = .{ .ctx = &unused, .onMessageFn = F9NoopProtocol.onMessage },
        .until = 2000,
    };
    const fault_cfg = fault_mod.Config{ .horizon = 1000 };
    const iters = 60;

    var two_build_ns: u64 = 0;
    var one_build_ns: u64 = 0;
    for (0..iters) |_| {
        const t0 = nowNs();
        {
            const topo = try snapshotTopo(gpa, case);
            defer gpa.free(topo.links);
            var trace = try fault_mod.generate(gpa, case.seed, .{ .node_count = topo.node_count, .links = topo.links }, fault_cfg);
            defer trace.deinit();
            _ = try replay(gpa, case, trace.events, null);
        }
        two_build_ns += nowNs() - t0;

        const t1 = nowNs();
        {
            var gr = try run(gpa, case, fault_cfg);
            gr.trace.deinit();
        }
        one_build_ns += nowNs() - t1;
    }

    std.debug.print(
        "F9 perf: two_build={d}ns one_build={d}ns ({d} iters, {d}-node ring)\n",
        .{ two_build_ns, one_build_ns, iters, F9_RING_N },
    );
    try testing.expect(one_build_ns <= two_build_ns);
}

test "replay: an out-of-range node id in an externally-supplied trace is rejected (audit F1)" {
    // `replay` is the module's one public entry point that takes a trace
    // from ANYWHERE — a saved reproducer hand-edited before replay, or a
    // shrunk trace applied to a topology smaller than the one that produced
    // it (`fault.generate` itself always bounds ids by its own topology, so
    // this case never reaches `applyFault` through the fuzzer). Before the
    // fix, `crash_node{.node=99}` panicked in Debug and, in ReleaseFast,
    // wrote past `Sim.nodes` while the run still reported `outcome = .ok`.
    const gpa = testing.allocator;
    var flood = try Flood.init(gpa, FLOOD_N); // FLOOD_N == 5, valid ids 0..4
    defer flood.deinit(gpa);
    const case = Case{ .seed = 1, .scenario = floodScenario, .protocol = flood.protocol(), .until = 200 };

    const trace = [_]FaultEvent{.{ .time = 0, .kind = .{ .crash_node = .{ .node = 99 } } }};
    try testing.expectError(error.UnknownNode, replay(gpa, case, &trace, null));
}

test "teeth: the fuzzer finds the loop bug across a seed sweep" {
    const gpa = testing.allocator;
    var loopy = try LoopyForward.init(gpa, LOOPY_N, LOOPY_DEST);
    defer loopy.deinit(gpa);
    const template = Case{ .seed = 0, .scenario = loopyScenario, .protocol = loopy.protocol(), .until = 500 };
    var caught: usize = 0;
    var seed: u64 = 1;
    while (seed <= 200) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try run(gpa, case, .{});
        defer gr.trace.deinit();
        if (gr.result.outcome == .violated) caught += 1;
    }
    // A harness that could not provoke the bug (or a bug-free protocol) yields 0.
    try testing.expect(caught > 0);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("prng.zig");
    _ = @import("types.zig");
    _ = @import("fault.zig");
    _ = @import("sim.zig");
    _ = @import("shrink.zig");
}
