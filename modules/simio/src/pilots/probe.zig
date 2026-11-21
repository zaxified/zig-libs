// SPDX-License-Identifier: MIT

//! Pilot: `probe.probeTarget` with a `LiveConnector` (`bounded`) and an
//! `IoSleeper`, unchanged, against simulated targets. The simulation knows
//! the true state of every target, so the classification is checked against
//! it: a listener is `up` with a round trip of exactly twice the link latency,
//! a host with no listener is `refused`, and a target behind a partition is
//! `timeout` at the budget. The budget is the property that matters: a probe
//! asked for 200 ms returns within a few milliseconds of it, where the
//! unbounded connector waits out the SYN retries (the broken variant, caught).
//! Repetitions are spaced by exactly the interval.

const std = @import("std");
const probe = @import("probe");
const sched = @import("../sched.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const latency_ns = 5 * ns_per_ms;
const budget_ms = 200;

fn listener(io: Io, port: u16) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer server.deinit(io);
    while (true) {
        const s = try server.accept(io);
        s.close(io);
    }
}

const Run = struct {
    result: ?probe.TargetResult = null,
    elapsed_ns: i96 = 0,

    fn deinit(r: *Run) void {
        if (r.result) |*x| x.deinit(testing.allocator);
    }
};

fn prober(io: Io, host: []const u8, port: u16, bounded: bool, count: u16, out: *Run) !void {
    var lc: probe.LiveConnector = .{ .io = io, .bounded = bounded };
    var sl: probe.IoSleeper = .{ .io = io };
    const t0 = Io.Timestamp.now(io, .awake);
    out.result = try probe.probeTarget(testing.allocator, .{ .host = host, .port = port }, .{
        .connector = lc.connector(),
        .timeout_ms = budget_ms,
        .count = count,
        .interval = .{ .ms = 100, .sleeper = sl.sleeper() },
    });
    out.elapsed_ns = Io.Timestamp.now(io, .awake).nanoseconds - t0.nanoseconds;
}

const World = struct { sim: Sim, target: *Host, prober: *Host };

fn world(w: *World, seed: u64) !void {
    w.sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
    w.target = try w.sim.addHost(.{});
    w.prober = try w.sim.addHost(.{});
    try w.sim.link(w.target, w.prober, .{ .latency_ns = latency_ns });
}

fn ipText(h: *const Host, buf: []u8) []const u8 {
    return std.mem.print(buf, "{d}.{d}.{d}.{d}", .{ h.ip4[0], h.ip4[1], h.ip4[2], h.ip4[3] }) catch unreachable;
}

test "pilot probe: a listener is up with a round trip of twice the link latency" {
    var w: World = undefined;
    try world(&w, 1);
    defer w.sim.deinit();
    var buf: [16]u8 = undefined;
    var run: Run = .{};
    defer run.deinit();
    try w.target.spawn(listener, .{ w.target.io(), 7000 });
    try w.prober.spawn(prober, .{ w.prober.io(), ipText(w.target, &buf), 7000, true, 3, &run });
    _ = w.sim.runFor(5 * ns_per_s);
    const r = run.result.?;
    try testing.expectEqual(@as(usize, 3), r.samples.len);
    for (r.samples) |s| {
        try testing.expectEqual(probe.Status.up, s.kind);
        try testing.expectEqual(@as(?u64, 2 * latency_ns), s.rtt_ns);
    }
    // Two pauses of 100 ms between three round trips.
    try testing.expectEqual(@as(i96, 3 * 2 * latency_ns + 2 * 100 * ns_per_ms), run.elapsed_ns);
}

test "pilot probe: a host with no listener is refused" {
    var w: World = undefined;
    try world(&w, 2);
    defer w.sim.deinit();
    var buf: [16]u8 = undefined;
    var run: Run = .{};
    defer run.deinit();
    try w.prober.spawn(prober, .{ w.prober.io(), ipText(w.target, &buf), 7000, true, 1, &run });
    _ = w.sim.runFor(5 * ns_per_s);
    try testing.expectEqual(probe.Status.refused, run.result.?.samples[0].kind);
}

test "pilot probe: a target behind a partition is timeout at the budget" {
    var w: World = undefined;
    try world(&w, 3);
    defer w.sim.deinit();
    var buf: [16]u8 = undefined;
    var run: Run = .{};
    defer run.deinit();
    _ = try w.sim.partition(&.{w.target});
    try w.target.spawn(listener, .{ w.target.io(), 7000 });
    try w.prober.spawn(prober, .{ w.prober.io(), ipText(w.target, &buf), 7000, true, 1, &run });
    _ = w.sim.runFor(5 * ns_per_s);
    try testing.expectEqual(probe.Status.timeout, run.result.?.samples[0].kind);
    try testing.expect(run.elapsed_ns >= budget_ms * ns_per_ms and run.elapsed_ns < (budget_ms + 20) * ns_per_ms);
}

test "pilot probe: the unbounded connector overruns the budget by minutes, and the check sees it" {
    var w: World = undefined;
    try world(&w, 4);
    defer w.sim.deinit();
    var buf: [16]u8 = undefined;
    var run: Run = .{};
    defer run.deinit();
    _ = try w.sim.partition(&.{w.target});
    try w.target.spawn(listener, .{ w.target.io(), 7000 });
    try w.prober.spawn(prober, .{ w.prober.io(), ipText(w.target, &buf), 7000, false, 1, &run });
    _ = w.sim.runFor(300 * ns_per_s);
    try testing.expectEqual(probe.Status.timeout, run.result.?.samples[0].kind);
    try testing.expect(run.elapsed_ns > 100 * ns_per_s);
}
