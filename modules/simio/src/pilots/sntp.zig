// SPDX-License-Identifier: MIT

//! Pilot: `sntp.query`, unchanged, against a simulated NTP server. The
//! simulation knows every clock exactly, so the offset and delay `sntp`
//! computes can be checked to the nanosecond: symmetric paths give the true
//! offset, an asymmetric path errs by exactly half the asymmetry (the
//! protocol's known limit), a server clock jump shows up in the next query,
//! and a server that does not echo the client's origin is refused.

const std = @import("std");
const sntp = @import("sntp");
const sched = @import("../sched.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

fn now(io: Io) sntp.Timestamp {
    return sntp.Timestamp.fromUnixNanos(Io.Timestamp.now(io, .real).nanoseconds);
}

const Server = struct { processing_ms: i64 = 1, echo_origin: bool = true };

fn ntpServer(io: Io, cfg: Server) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(sntp.ntp_port) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [128]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        const t2 = now(io);
        const req = sntp.Packet.decode(msg.data) catch continue;
        if (req.mode != .client) continue;
        try io.sleep(.fromMilliseconds(cfg.processing_ms), .awake);
        var origin = req.transmit;
        if (!cfg.echo_origin) origin.fraction +%= 1;
        const reply: sntp.Packet = .{
            .mode = .server,
            .stratum = 2,
            .reference_id = "SIMI".*,
            .reference = t2,
            .originate = origin,
            .receive = t2,
            .transmit = now(io),
        };
        try sock.send(io, &msg.from, &reply.encode());
    }
}

const Results = struct {
    first: ?anyerror!sntp.QueryResult = null,
    second: ?anyerror!sntp.QueryResult = null,
};

fn client(io: Io, server: net.IpAddress, results: *Results, gap_s: i64) !void {
    results.first = sntp.query(io, server, .{ .timeout_ms = 2000 }, null);
    if (gap_s == 0) return;
    try io.sleep(.fromSeconds(gap_s), .awake);
    results.second = sntp.query(io, server, .{ .timeout_ms = 2000 }, null);
}

const World = struct { sim: Sim, client: *Host, server: *Host };

fn build(w: *World, seed: u64, skew_ns: i64, latency_ms: u64, cfg: Server) !void {
    w.sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
    errdefer w.sim.deinit();
    w.client = try w.sim.addHost(.{ .clock_skew_ns = skew_ns });
    w.server = try w.sim.addHost(.{});
    try w.sim.link(w.client, w.server, .{ .latency_ns = latency_ms * ns_per_ms });
    try w.server.spawn(ntpServer, .{ w.server.io(), cfg });
}

fn addr(h: *const Host) net.IpAddress {
    return .{ .ip4 = .{ .bytes = h.ip4, .port = sntp.ntp_port } };
}

fn expectNear(expected: i128, actual: i128) !void {
    // NTP fractions are 2^-32 s: allow a few nanoseconds of rounding.
    if (@abs(expected - actual) > 10) {
        std.debug.print("expected {d}, got {d}\n", .{ expected, actual });
        return error.TestExpectedEqual;
    }
}

test "pilot sntp: the offset of a client 1.5 s behind is exact on a symmetric path" {
    var w: World = undefined;
    try build(&w, 1, -1500 * ns_per_ms, 20, .{ .processing_ms = 3 });
    defer w.sim.deinit();
    var results: Results = .{};
    try w.client.spawn(client, .{ w.client.io(), addr(w.server), &results, 0 });
    _ = w.sim.runFor(10 * ns_per_s);
    const r = try results.first.?;
    try expectNear(1500 * ns_per_ms, r.offset_ns);
    try expectNear(40 * ns_per_ms, r.roundtrip_ns); // server processing is excluded
}

test "pilot sntp: an asymmetric path errs by exactly half the asymmetry" {
    var w: World = undefined;
    try build(&w, 2, 0, 20, .{});
    defer w.sim.deinit();
    // The request is held back 30 ms more than the reply.
    try w.sim.scheduleFault(0, .{ .delay_once = .{ .from = w.client.id, .to = w.server.id, .extra_ns = 30 * ns_per_ms } });
    var results: Results = .{};
    try w.client.spawn(client, .{ w.client.io(), addr(w.server), &results, 0 });
    _ = w.sim.runFor(10 * ns_per_s);
    const r = try results.first.?;
    try expectNear(15 * ns_per_ms, r.offset_ns);
    try expectNear(70 * ns_per_ms, r.roundtrip_ns);
}

test "pilot sntp: a jump of the server's clock shows in the next query" {
    var w: World = undefined;
    try build(&w, 3, 0, 5, .{});
    defer w.sim.deinit();
    try w.sim.scheduleFault(5 * ns_per_s, .{ .clock_jump = .{ .host = w.server.id, .delta_ns = -10 * ns_per_s } });
    var results: Results = .{};
    try w.client.spawn(client, .{ w.client.io(), addr(w.server), &results, 10 });
    _ = w.sim.runFor(30 * ns_per_s);
    try expectNear(0, (try results.first.?).offset_ns);
    try expectNear(-10 * ns_per_s, (try results.second.?).offset_ns);
}

test "pilot sntp: a reply that does not echo the origin is refused" {
    var w: World = undefined;
    try build(&w, 4, 0, 5, .{ .echo_origin = false });
    defer w.sim.deinit();
    var results: Results = .{};
    try w.client.spawn(client, .{ w.client.io(), addr(w.server), &results, 0 });
    _ = w.sim.runFor(10 * ns_per_s);
    try testing.expectError(error.OriginateMismatch, results.first.?);
}

test "pilot sntp: a lost reply is a timeout, at the query's deadline" {
    var w: World = undefined;
    try build(&w, 5, 0, 5, .{});
    defer w.sim.deinit();
    try w.sim.scheduleFault(0, .{ .drop_once = .{ .from = w.server.id, .to = w.client.id } });
    var results: Results = .{};
    try w.client.spawn(client, .{ w.client.io(), addr(w.server), &results, 0 });
    _ = w.sim.runFor(10 * ns_per_s);
    try testing.expectError(error.Timeout, results.first.?);
}
