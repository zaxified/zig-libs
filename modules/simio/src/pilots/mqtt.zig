// SPDX-License-Identifier: MIT

//! Pilot: the `mqtt` broker (`TcpServer` + `Broker`, unchanged) and its
//! client (`Client` + `TcpTransport`) under partitions, crashes and packet
//! faults. The property is QoS 1's promise: every message the publisher saw
//! acknowledged reaches every subscriber with a persistent session at least
//! once. A subscriber that reconnects with a clean session gives that up,
//! and the check must say so.

const std = @import("std");
const mqtt = @import("mqtt");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const n_messages = 20;
const topic = "sensors/temp";

fn nowMs(io: Io) u64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .awake).nanoseconds, ns_per_ms));
}

// ── the broker host ────────────────────────────────────────────────────────

fn brokerMain(io: Io, gpa: std.mem.Allocator) !void {
    var broker = mqtt.Broker.init(gpa, .{});
    defer broker.deinit();
    var srv = mqtt.TcpServer.init(io, &broker);
    defer srv.deinit();
    try srv.bind("0.0.0.0", 1883);
    try srv.serve();
}

// ── the publisher ──────────────────────────────────────────────────────────

const State = struct {
    /// Messages the broker acknowledged to the publisher.
    acked: [n_messages]bool = @splat(false),
    /// Per subscriber: messages it received (at least once).
    got: [2][n_messages]bool = @splat(@splat(false)),
    /// The broken variant: subscriber 1 comes back with a clean session.
    clean_after_restart: bool = false,
    boots: [2]u32 = .{ 0, 0 },
};

fn payloadOf(i: usize, buf: *[3]u8) []const u8 {
    buf.* = .{ 'm', '0' + @as(u8, @intCast(i / 10)), '0' + @as(u8, @intCast(i % 10)) };
    return buf;
}

fn indexOf(payload: []const u8) ?usize {
    if (payload.len != 3 or payload[0] != 'm') return null;
    return @as(usize, payload[1] - '0') * 10 + (payload[2] - '0');
}

/// Publishes one message every 100 ms; on a broken connection reconnects
/// with its persistent session and sends again what was not acknowledged.
fn publisher(io: Io, broker: net.IpAddress, st: *State) !void {
    var sent: [n_messages]?u16 = @splat(null);
    while (true) {
        var t = mqtt.TcpTransport.connect(io, broker) catch {
            try io.sleep(.fromMilliseconds(300), .awake);
            continue;
        };
        defer t.close();
        var rx: [512]u8 = undefined;
        var tx: [512]u8 = undefined;
        var c = mqtt.Client.init(t.transport(), .{ .rx = &rx, .tx = &tx });
        session(io, &t, &c, st, &sent) catch {};
        var done = true;
        for (st.acked) |a| done = done and a;
        if (done) return;
        @memset(&sent, null); // a new connection: ids start over
        try io.sleep(.fromMilliseconds(300), .awake);
    }
}

fn session(io: Io, t: *mqtt.TcpTransport, c: *mqtt.Client, st: *State, sent: *[n_messages]?u16) !void {
    try c.connect(nowMs(io), .{ .client_id = "pub", .clean_session = false });
    var reader = io.async(pubReader, .{ io, t, c, st, sent });
    defer _ = reader.cancel(io) catch {};
    var buf: [3]u8 = undefined;
    for (0..n_messages) |i| {
        if (st.acked[i]) continue;
        try io.sleep(.fromMilliseconds(100), .awake);
        if (c.state != .connected) return error.NotConnected;
        sent[i] = try c.publish(nowMs(io), topic, payloadOf(i, &buf), .{ .qos = .at_least_once });
    }
    // Wait for the outstanding acknowledgements (the reader records them).
    while (true) {
        var done = true;
        for (st.acked) |a| done = done and a;
        if (done) return;
        if (c.state != .connected) return error.NotConnected;
        try io.sleep(.fromMilliseconds(50), .awake);
    }
}

fn pubReader(io: Io, t: *mqtt.TcpTransport, c: *mqtt.Client, st: *State, sent: *[n_messages]?u16) !void {
    var buf: [512]u8 = undefined;
    while (true) {
        const n = t.readSome(&buf) catch 0;
        if (n == 0) {
            c.state = .disconnected;
            return;
        }
        try c.feed(buf[0..n]);
        while (try c.poll(nowMs(io))) |ev| switch (ev) {
            .puback => |ack| for (sent, 0..) |s, i| if (s == ack.packet_id) {
                st.acked[i] = true;
            },
            else => {},
        };
    }
}

// ── the subscribers ────────────────────────────────────────────────────────

fn subscriber(io: Io, broker: net.IpAddress, st: *State, which: u1) !void {
    st.boots[which] += 1;
    const ids = [_][]const u8{ "sub0", "sub1" };
    while (true) {
        var t = mqtt.TcpTransport.connect(io, broker) catch {
            try io.sleep(.fromMilliseconds(300), .awake);
            continue;
        };
        defer t.close();
        var rx: [1024]u8 = undefined;
        var tx: [512]u8 = undefined;
        var c = mqtt.Client.init(t.transport(), .{ .rx = &rx, .tx = &tx });
        const clean = st.clean_after_restart and which == 1 and st.boots[which] > 1;
        c.connect(nowMs(io), .{ .client_id = ids[which], .clean_session = clean }) catch continue;
        var subscribed = false;
        var buf: [1024]u8 = undefined;
        while (true) {
            const n = t.readSome(&buf) catch 0;
            if (n == 0) break;
            c.feed(buf[0..n]) catch break;
            while (c.poll(nowMs(io)) catch null) |ev| switch (ev) {
                .connack => if (!subscribed) {
                    _ = c.subscribe(nowMs(io), &.{.{ .filter = "sensors/#", .qos = .at_least_once }}) catch break;
                    subscribed = true;
                },
                .message => |m| if (indexOf(m.payload)) |i| {
                    st.got[which][i] = true;
                },
                else => {},
            };
        }
        try io.sleep(.fromMilliseconds(300), .awake);
    }
}

// ── the world ──────────────────────────────────────────────────────────────

const World = struct { broker: *Host, publisher: *Host, subs: [2]*Host };

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const b = try sim.addHost(.{}); // 10.0.0.1
    const p = try sim.addHost(.{});
    const s0 = try sim.addHost(.{});
    const s1 = try sim.addHost(.{});
    for ([_]*Host{ p, s0, s1 }) |h| try sim.link(b, h, .{ .latency_ns = 8 * ns_per_ms, .jitter_ns = 2 * ns_per_ms });
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = b.ip4, .port = 1883 } };
    try b.spawnBoot(brokerMain, .{ b.io(), b.allocator() });
    // Subscribers first: a persistent session must exist before the
    // publisher's first message, or there is nothing to deliver to.
    try s0.spawnBoot(subscriber, .{ s0.io(), addr, st, 0 });
    try s1.spawnBoot(subscriber, .{ s1.io(), addr, st, 1 });
    try p.spawn(startPublisherLate, .{ p.io(), addr, st });
}

fn startPublisherLate(io: Io, broker: net.IpAddress, st: *State) !void {
    try io.sleep(.fromMilliseconds(500), .awake);
    try publisher(io, broker, st);
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    for (st.acked, 0..) |acked, i| {
        if (!acked) continue;
        for (st.got) |got| if (!got[i]) return error.AckedButLost;
    }
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .clean_after_restart = st.clean_after_restart };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 512 * 1024 },
        .setup = setup,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 60 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot mqtt: QoS 1 reaches everyone once the network behaves" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    for (st.acked) |a| try testing.expect(a);
    for (st.got) |got| for (got) |g| try testing.expect(g);
}

test "pilot mqtt: a subscriber cut off for 5 s still gets every acknowledged message" {
    var st: State = .{};
    // Host 2 (subscriber 0) is cut off from 1 s to 6 s, mid-stream.
    const cut = [_]u32{2};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(1000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(6000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    for (st.got[0]) |g| try testing.expect(g);
}

test "pilot mqtt: a subscriber that crashes resumes its persistent session" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(1200, .{ .net = .{ .crash_node = .{ .node = 3 } } }),
        at(3000, .{ .net = .{ .restart_node = .{ .node = 3 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 2), st.boots[1]);
}

test "pilot mqtt: coming back with a clean session loses messages, and the check sees it" {
    var st: State = .{ .clean_after_restart = true };
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(1200, .{ .net = .{ .crash_node = .{ .node = 3 } } }),
        at(3000, .{ .net = .{ .restart_node = .{ .node = 3 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.AckedButLost), r.violation.?.err);
}

test "pilot mqtt: at-least-once holds across seeds of loss, duplication and partitions" {
    var st: State = .{};
    const faults: search.FaultConfig = .{
        .schedule = .{
            .max_events = 6,
            .horizon = 3000,
            .repair_permille = 1000,
            .enable_crash = false, // the broker keeps sessions in memory
            .enable_clock_jump = false,
        },
    };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 20)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}
