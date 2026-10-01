// SPDX-License-Identifier: MIT

//! Pilot: `dns.Resolver`, unchanged, against simulated name servers. It reads
//! `/etc/resolv.conf` from the client's simulated disk, retries over a lossy
//! link, falls back to TCP when the UDP answer is truncated, gives up with
//! `Timeout` on a dead server after exactly its attempt budget, and ignores
//! an answer that does not carry its transaction id.
//!
//! Found a defect on its first run: `lookupIp` turned every failed query
//! into "no addresses" (an empty slice), so a dead server looked like a name
//! without records. Fixed in `dns` the same day.

const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");
const sched = @import("../sched.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const answer_ip = [4]u8{ 10, 9, 9, 9 };

const Behaviour = struct {
    truncate_udp: bool = false,
    wrong_id: bool = false,
    served_udp: u32 = 0,
    served_tcp: u32 = 0,
};

/// The end of the question section of a query, or null.
fn questionEnd(q: []const u8) ?usize {
    var i: usize = 12;
    while (i < q.len) {
        const len = q[i];
        if (len == 0) return if (i + 5 <= q.len) i + 5 else null;
        if (len & 0xc0 != 0) return null;
        i += 1 + len;
    }
    return null;
}

/// Answers `q`: A queries with `answer_ip`, anything else with no records.
fn respond(out: []u8, q: []const u8, b: *const Behaviour, truncated: bool) ?[]const u8 {
    const qend = questionEnd(q) orelse return null;
    const qtype = std.mem.readInt(u16, q[qend - 4 ..][0..2], .big);
    var w: Io.Writer = .fixed(out);
    const id = std.mem.readInt(u16, q[0..2], .big);
    w.writeInt(u16, if (b.wrong_id) id +% 1 else id, .big) catch return null;
    w.writeInt(u16, if (truncated) 0x8380 else 0x8180, .big) catch return null;
    const answers: u16 = if (qtype == 1 and !truncated) 1 else 0;
    w.writeInt(u16, 1, .big) catch return null; // qdcount
    w.writeInt(u16, answers, .big) catch return null; // ancount
    w.writeInt(u32, 0, .big) catch return null; // nscount, arcount
    w.writeAll(q[12..qend]) catch return null;
    if (answers == 1) {
        w.writeAll("\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04") catch return null;
        w.writeAll(&answer_ip) catch return null;
    }
    return w.buffered();
}

fn udpServer(io: Io, b: *Behaviour) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(53) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [1500]u8 = undefined;
    var out: [512]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        b.served_udp += 1;
        const resp = respond(&out, msg.data, b, b.truncate_udp) orelse continue;
        try sock.send(io, &msg.from, resp);
    }
}

fn tcpServer(io: Io, b: *Behaviour) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(53) }, io, .{});
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        var rbuf: [600]u8 = undefined;
        var wbuf: [600]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        var w = stream.writer(io, &wbuf);
        const len = r.interface.takeInt(u16, .big) catch continue;
        const q = r.interface.take(len) catch continue;
        b.served_tcp += 1;
        var out: [512]u8 = undefined;
        const resp = respond(&out, q, b, false) orelse continue;
        try w.interface.writeInt(u16, @intCast(resp.len), .big);
        try w.interface.writeAll(resp);
        try w.interface.flush();
    }
}

const Lookup = struct {
    result: ?anyerror![]netaddr.Ip = null,
    took_ns: u64 = 0,
};

fn lookup(io: Io, sim: *Sim, options: dns.Resolver.Options, out: *Lookup) void {
    const t0 = sim.now;
    var r = dns.Resolver.init(io, testing.allocator, options);
    defer r.deinit();
    out.result = r.lookupIp("svc.sim.");
    out.took_ns = sim.now - t0;
}

fn expectAnswer(l: *const Lookup) !void {
    const ips = try l.result.?;
    defer testing.allocator.free(ips);
    try testing.expectEqual(@as(usize, 1), ips.len);
    try testing.expectEqualSlices(u8, &answer_ip, &ips[0].v4);
}

const World = struct { sim: Sim, client: *Host, server: *Host };

fn build(w: *World, seed: u64, link: @import("../net.zig").LinkConfig, b: *Behaviour) !void {
    w.sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
    errdefer w.sim.deinit();
    w.client = try w.sim.addHost(.{});
    w.server = try w.sim.addHost(.{});
    try w.sim.link(w.client, w.server, link);
    try w.server.spawn(udpServer, .{ w.server.io(), b });
    try w.server.spawn(tcpServer, .{ w.server.io(), b });
    // The resolver finds its server the usual way: /etc/resolv.conf.
    try w.client.putFile("/etc/resolv.conf", "nameserver 10.0.0.2\n");
}

const opts: dns.Resolver.Options = .{ .timeout_ms = 400, .attempts = 6, .use_hosts = false, .use_search = false };

test "pilot dns: lookupIp reads resolv.conf from the simulated disk and retries through loss" {
    var retried = false;
    for (0..12) |seed| {
        var b: Behaviour = .{};
        var w: World = undefined;
        try build(&w, seed, .{ .latency_ns = 15 * ns_per_ms, .loss_permille = 250 }, &b);
        defer w.sim.deinit();
        var l: Lookup = .{};
        try w.client.spawn(lookup, .{ w.client.io(), &w.sim, opts, &l });
        _ = w.sim.runFor(60 * ns_per_s);
        // A and AAAA each needed at least one answer; more means retries.
        if (b.served_udp > 2) retried = true;
        const ips = l.result.? catch |err| {
            // Six attempts can all be lost at 25% each way; then Timeout is right.
            try testing.expectEqual(error.Timeout, err);
            continue;
        };
        defer testing.allocator.free(ips);
        try testing.expectEqualSlices(u8, &answer_ip, &ips[0].v4);
    }
    try testing.expect(retried);
}

test "pilot dns: a truncated UDP answer sends the resolver to TCP" {
    var b: Behaviour = .{ .truncate_udp = true };
    var w: World = undefined;
    try build(&w, 1, .{ .latency_ns = 10 * ns_per_ms }, &b);
    defer w.sim.deinit();
    var l: Lookup = .{};
    try w.client.spawn(lookup, .{ w.client.io(), &w.sim, opts, &l });
    _ = w.sim.runFor(60 * ns_per_s);
    try expectAnswer(&l);
    try testing.expect(b.served_tcp >= 1);
}

test "pilot dns: a dead server is a Timeout after exactly the documented budget" {
    var b: Behaviour = .{};
    var w: World = undefined;
    try build(&w, 2, .{ .latency_ns = 10 * ns_per_ms }, &b);
    defer w.sim.deinit();
    w.sim.crash(w.server);
    var l: Lookup = .{};
    try w.client.spawn(lookup, .{ w.client.io(), &w.sim, opts, &l });
    _ = w.sim.runFor(120 * ns_per_s);
    // Before the dns fix this was an empty list: an outage read as "no
    // addresses".
    try testing.expectError(error.Timeout, l.result.?);
    // Two queries (A, AAAA), each `attempts` x `timeout_ms` — the budget the
    // resolver documents, to the nanosecond.
    try testing.expectEqual(2 * @as(u64, opts.attempts) * opts.timeout_ms * ns_per_ms, l.took_ns);
}

test "pilot dns: an answer with the wrong transaction id is not believed" {
    var b: Behaviour = .{ .wrong_id = true };
    var w: World = undefined;
    try build(&w, 3, .{ .latency_ns = 10 * ns_per_ms }, &b);
    defer w.sim.deinit();
    var l: Lookup = .{};
    try w.client.spawn(lookup, .{ w.client.io(), &w.sim, opts, &l });
    _ = w.sim.runFor(60 * ns_per_s);
    // The forged answers are ignored and the queries time out.
    try testing.expectError(error.Timeout, l.result.?);
    try testing.expect(b.served_udp >= 2);
}
