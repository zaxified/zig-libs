// SPDX-License-Identifier: MIT

//! Pilot: `icmp.Pinger` with `Config.io` — ping sockets from `std.Io.net`,
//! clocks and waits from the `Io` — probing simulated hosts. Before this
//! pilot the module ran on raw syscalls only and had no `std.Io` path at all.
//!
//! The properties: a reachable target is reported alive with an RTT of
//! exactly the path's round trip; an unreachable one is reported dead after
//! its retries; and under any schedule of loss, duplication, reordering and
//! partitions no reply is ever credited with an RTT shorter than the path —
//! which is what a reply correlated to the wrong probe would look like. A
//! timeout shorter than the round trip is caught reporting live hosts dead.

const std = @import("std");
const icmp = @import("icmp");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const n_targets = 3;
const latency_ns = 10 * ns_per_ms;

const State = struct {
    /// Probes per target (`.count` mode); 0 = `.alive` mode.
    count: u16 = 0,
    timeout_ns: u64 = 500 * ns_per_ms,
    /// No faults are scheduled: every target must come out alive.
    expect_alive: bool = false,
    /// Links that lose, duplicate, reorder (by up to 300 ms) and corrupt.
    rough: bool = false,
    targets: [n_targets][4]u8 = undefined,
    stats: [n_targets]icmp.Stats = @splat(.{}),
    replies: u32 = 0,
    duplicates: u32 = 0,
    /// The shortest RTT any reply was credited with.
    min_rtt_ns: u64 = std.math.maxInt(u64),
    done: bool = false,

    fn onResult(ctx: ?*anyopaque, _: icmp.TargetId, _: u16, outcome: icmp.Outcome) void {
        const st: *State = @ptrCast(@alignCast(ctx.?));
        switch (outcome) {
            .reply => |r| {
                st.replies += 1;
                st.min_rtt_ns = @min(st.min_rtt_ns, r.rtt_ns);
            },
            .duplicate => |r| {
                st.duplicates += 1;
                st.min_rtt_ns = @min(st.min_rtt_ns, r.rtt_ns);
            },
            else => {},
        }
    }
};

fn monitor(io: Io, gpa: std.mem.Allocator, st: *State) !void {
    var p = try icmp.Pinger.init(gpa, .{
        .io = io,
        .mode = if (st.count == 0) .alive else .count,
        .count = @max(st.count, 1),
        .retries = 2,
        .timeout_ns = st.timeout_ns,
        .interval_ns = 5 * ns_per_ms,
        .perhost_interval_ns = 100 * ns_per_ms,
    });
    defer p.deinit();
    p.setResultCallback(st, State.onResult);
    var ids: [n_targets]icmp.TargetId = undefined;
    for (st.targets, &ids) |ip, *id| {
        var buf: [16]u8 = undefined;
        id.* = try p.addTarget(try std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }));
    }
    try p.run();
    for (ids, &st.stats) |id, *s| s.* = p.stats(id);
    st.done = true;
}

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const m = try sim.addHost(.{}); // node 0
    for (&st.targets) |*ip| {
        const t = try sim.addHost(.{});
        try sim.link(m, t, if (st.rough) .{
            .latency_ns = latency_ns,
            .loss_permille = 100,
            .dup_permille = 300,
            .reorder_permille = 300,
            .reorder_ns = 300 * ns_per_ms,
            .corrupt_permille = 50,
        } else .{ .latency_ns = latency_ns });
        ip.* = t.ip4;
    }
    try m.spawn(monitor, .{ m.io(), m.allocator(), st });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    // Nothing answers faster than the round trip it travelled.
    if (st.min_rtt_ns < 2 * latency_ns) return error.ImpossibleRtt;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    try invariant(sim, ctx);
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (!st.done) return error.NeverFinished;
    for (st.stats) |s| {
        if (s.recv > s.sent) return error.MoreRepliesThanProbes;
        if (s.recv + s.lost() != s.sent) return error.Unaccounted;
        if (st.expect_alive and !s.alive()) return error.LiveHostReportedDead;
    }
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .count = st.count, .timeout_ns = st.timeout_ns, .expect_alive = st.expect_alive, .rough = st.rough };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 512 * 1024 },
        .setup = setup,
        .invariant = invariant,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 60 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot icmp: every reachable target is alive with exactly the path's round trip" {
    var st: State = .{ .expect_alive = true };
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    for (st.stats) |s| {
        try testing.expect(s.alive());
        try testing.expectEqual(@as(u32, 1), s.sent);
        try testing.expectEqual(2 * latency_ns, s.last_ns);
    }
}

test "pilot icmp: a cut-off target is reported dead after its retries" {
    var st: State = .{};
    // Node 2 (the second target) is unreachable for the whole run.
    const cut = [_]u32{2};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(0, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expect(st.stats[0].alive());
    try testing.expect(!st.stats[1].alive());
    try testing.expectEqual(@as(u32, 3), st.stats[1].sent); // 1 + 2 retries
    try testing.expect(st.stats[2].alive());
}

test "pilot icmp: a timeout shorter than the round trip reports live hosts dead, and the check sees it" {
    // 8, 12 and 18 ms with the 1.5x backoff: every attempt gives up before
    // the 20 ms round trip completes.
    var st: State = .{ .timeout_ns = 8 * ns_per_ms, .expect_alive = true };
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.LiveHostReportedDead), r.violation.?.err);
}

test "pilot icmp: on a rough link duplicates are counted as duplicates, not as replies" {
    var st: State = .{ .count = 20, .rough = true };
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expect(st.duplicates > 0);
    var sent: u32 = 0;
    var recv: u32 = 0;
    for (st.stats) |x| {
        sent += x.sent;
        recv += x.recv;
    }
    try testing.expectEqual(st.replies, recv);
    try testing.expect(recv < sent); // the loss is felt too
}

test "pilot icmp: no reply is credited to the wrong probe across seeds of loss, duplication and partitions" {
    var st: State = .{ .count = 20, .rough = true };
    const faults: search.FaultConfig = .{
        .schedule = .{
            .max_events = 8,
            .horizon = 3000,
            .repair_permille = 800,
            .enable_crash = false, // the monitor holds the results in memory
            .enable_clock_jump = false,
        },
    };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 30)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}
