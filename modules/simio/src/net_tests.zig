// SPDX-License-Identifier: MIT

//! M2 behaviour tests: the simulated network, driven only through the public
//! `std.Io.net` API real code uses (`listen`/`accept`/`connect`, stream
//! `Reader`/`Writer`, `bind`/`send`/`receiveTimeout`).

const std = @import("std");
const sched = @import("sched.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

fn newSim(sim: *Sim, seed: u64) void {
    sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
}

fn addr4(h: *const Host, port: u16) net.IpAddress {
    return .{ .ip4 = .{ .bytes = h.ip4, .port = port } };
}

// ── streams ────────────────────────────────────────────────────────────────

fn echoServer(io: Io, port: u16) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    var rbuf: [700]u8 = undefined;
    var wbuf: [900]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    _ = r.interface.streamRemaining(&w.interface) catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        error.WriteFailed => return w.err.?,
    };
    try w.interface.flush();
}

const EchoResult = struct { ok: bool = false, elapsed_ns: i96 = 0 };

fn echoClient(io: Io, server: net.IpAddress, len: usize, out: *EchoResult) !void {
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, len);
    defer gpa.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% (i >> 9));
    const back = try gpa.alloc(u8, len);
    defer gpa.free(back);

    const t0 = Io.Timestamp.now(io, .awake);
    const stream = try server.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    // Write and read concurrently: the payload is larger than the window, so
    // a client that wrote everything first would deadlock against the echo.
    var writer_task = io.async(writeAllThenShutdown, .{ io, stream, payload });
    var rbuf: [333]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    r.interface.readSliceAll(back) catch return r.err orelse error.EndOfStream;
    try writer_task.await(io);
    out.ok = std.mem.eql(u8, payload, back);
    out.elapsed_ns = t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds;
}

fn writeAllThenShutdown(io: Io, stream: net.Stream, payload: []const u8) !void {
    var wbuf: [1000]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(payload) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try stream.shutdown(io, .send);
}

fn runEcho(seed: u64, link: @import("net.zig").LinkConfig, len: usize) !struct { r: EchoResult, fp: u64, now: u64 } {
    var sim: Sim = undefined;
    newSim(&sim, seed);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, link);
    var res: EchoResult = .{};
    try b.spawn(echoServer, .{ b.io(), 7 });
    try a.spawn(echoClient, .{ a.io(), addr4(b, 7), len, &res });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(usize, 0), a.failures);
    try testing.expectEqual(@as(usize, 0), b.failures);
    return .{ .r = res, .fp = sim.fingerprint(), .now = r.now_ns };
}

test "a stream echoes 600 KB intact through a lossy link, past the flow-control window" {
    for (0..4) |seed| {
        const run = try runEcho(seed, .{ .latency_ns = 5 * ns_per_ms, .jitter_ns = ns_per_ms, .loss_permille = 20 }, 600 * 1024);
        try testing.expect(run.r.ok);
        // At least the handshake and one data round trip: 2 × 10 ms.
        try testing.expect(run.r.elapsed_ns >= 20 * ns_per_ms);
    }
}

test "the network is part of the replay: same seed, same fingerprint" {
    const cfg: @import("net.zig").LinkConfig = .{ .latency_ns = 3 * ns_per_ms, .jitter_ns = 2 * ns_per_ms, .loss_permille = 50 };
    const x = try runEcho(9, cfg, 50_000);
    const y = try runEcho(9, cfg, 50_000);
    const z = try runEcho(10, cfg, 50_000);
    try testing.expectEqual(x.fp, y.fp);
    try testing.expectEqual(x.now, y.now);
    try testing.expect(x.fp != z.fp);
}

const ConnectOutcome = struct { err: ?anyerror = null, at_ns: u64 = 0 };

fn tryConnect(io: Io, sim: *Sim, to: net.IpAddress, timeout: Io.Timeout, out: *ConnectOutcome) void {
    if (net.IpAddress.connect(&to, io, .{ .mode = .stream, .timeout = timeout })) |s| {
        s.close(io);
    } else |err| out.err = err;
    out.at_ns = sim.now;
}

test "connect: refused with no listener, unreachable for an unknown address" {
    var sim: Sim = undefined;
    newSim(&sim, 1);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{ .latency_ns = 4 * ns_per_ms });
    var refused: ConnectOutcome = .{};
    var unknown: ConnectOutcome = .{};
    try a.spawn(tryConnect, .{ a.io(), &sim, addr4(b, 1234), .none, &refused });
    try a.spawn(tryConnect, .{ a.io(), &sim, .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 80 } }, .none, &unknown });
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(?anyerror, error.ConnectionRefused), refused.err);
    try testing.expectEqual(@as(u64, 8 * ns_per_ms), refused.at_ns); // one round trip
    try testing.expectEqual(@as(?anyerror, error.NetworkUnreachable), unknown.err);
}

fn listenOnly(io: Io, port: u16) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer server.deinit(io);
    const s = try server.accept(io);
    s.close(io);
}

test "connect across a partition times out: by its own timeout, or after SYN retries" {
    var sim: Sim = undefined;
    newSim(&sim, 2);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{});
    try sim.setLinkUp(a, b, false);
    var short: ConnectOutcome = .{};
    var long: ConnectOutcome = .{};
    try b.spawn(listenOnly, .{ b.io(), 80 });
    try a.spawn(tryConnect, .{ a.io(), &sim, addr4(b, 80), .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } }, &short });
    try a.spawn(tryConnect, .{ a.io(), &sim, addr4(b, 80), .none, &long });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.deadlock, r.outcome); // the listener still waits
    try testing.expectEqual(@as(?anyerror, error.Timeout), short.err);
    try testing.expectEqual(@as(u64, 3 * ns_per_s), short.at_ns);
    try testing.expectEqual(@as(?anyerror, error.Timeout), long.err);
    try testing.expect(long.at_ns >= sim.opts.net.tcp_syn_timeout_ns);
}

fn healLater(io: Io, sim: *Sim, a: *Host, b: *Host, after_s: i64) !void {
    try io.sleep(.fromSeconds(after_s), .awake);
    try sim.setLinkUp(a, b, true);
}

fn cutLater(io: Io, sim: *Sim, a: *Host, b: *Host, after_ms: i64) !void {
    try io.sleep(.fromMilliseconds(after_ms), .awake);
    try sim.setLinkUp(a, b, false);
}

test "a stream survives a partition that heals: data waits, then arrives in order" {
    var sim: Sim = undefined;
    newSim(&sim, 3);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{ .latency_ns = 2 * ns_per_ms });
    var res: EchoResult = .{};
    try b.spawn(echoServer, .{ b.io(), 7 });
    try a.spawn(echoClient, .{ a.io(), addr4(b, 7), 400_000, &res });
    try a.spawn(cutLater, .{ a.io(), &sim, a, b, 6 }); // mid-transfer: the handshake takes 4 ms
    try a.spawn(healLater, .{ a.io(), &sim, a, b, 30 });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expect(res.ok);
    try testing.expect(res.elapsed_ns >= 30 * ns_per_s);
}

fn writeForever(io: Io, to: net.IpAddress, out: *ConnectOutcome, sim: *Sim) !void {
    const stream = try to.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    const chunk: [4096]u8 = @splat(0x5a);
    while (true) {
        w.interface.writeAll(&chunk) catch {
            out.err = w.err.?;
            out.at_ns = sim.now;
            return;
        };
    }
}

fn readForever(io: Io, port: u16) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    var buf: [8192]u8 = undefined;
    var r = stream.reader(io, &buf);
    while (true) _ = r.interface.discardRemaining() catch return;
}

test "a partition outlasting the user timeout fails the writer" {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{
        .seed = 4,
        .stack_size = 512 * 1024,
        .net = .{ .tcp_user_timeout_ns = 60 * ns_per_s },
    });
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{ .latency_ns = ns_per_ms });
    var out: ConnectOutcome = .{};
    try b.spawn(readForever, .{ b.io(), 9 });
    try a.spawn(writeForever, .{ a.io(), addr4(b, 9), &out, &sim });
    try a.spawn(cutLater, .{ a.io(), &sim, a, b, 50 });
    _ = sim.runFor(10 * 60 * ns_per_s);
    try testing.expectEqual(@as(?anyerror, error.ConnectionResetByPeer), out.err);
    try testing.expect(out.at_ns >= 60 * ns_per_s);
    try testing.expect(out.at_ns < 5 * 60 * ns_per_s);
}

const CloseLog = struct { eof: bool = false, reset: bool = false };

fn closer(io: Io, port: u16, read_first: bool) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    if (read_first) {
        // Wait until the client's bytes are here, then close without reading
        // them: Linux answers that with a reset.
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    stream.close(io);
}

fn closeWatcher(io: Io, to: net.IpAddress, send_first: bool, log: *CloseLog) !void {
    const stream = try to.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    if (send_first) {
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        try w.interface.writeAll("unread");
        try w.interface.flush();
    }
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    if (r.interface.takeByte()) |_| {} else |err| switch (err) {
        error.EndOfStream => log.eof = true,
        error.ReadFailed => log.reset = r.err.? == error.ConnectionResetByPeer,
    }
}

test "a peer's close reads as end of stream; a close over unread data as a reset" {
    for ([_]bool{ false, true }) |unread| {
        var sim: Sim = undefined;
        newSim(&sim, 5);
        defer sim.deinit();
        const a = try sim.addHost(.{});
        const b = try sim.addHost(.{});
        try sim.link(a, b, .{ .latency_ns = 3 * ns_per_ms });
        var log: CloseLog = .{};
        try b.spawn(closer, .{ b.io(), 22, unread });
        try a.spawn(closeWatcher, .{ a.io(), addr4(b, 22), unread, &log });
        try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
        try testing.expectEqual(!unread, log.eof);
        try testing.expectEqual(unread, log.reset);
    }
}

fn acceptForever(io: Io, result: *?anyerror) void {
    var server = net.IpAddress.listen(&.{ .ip4 = .unspecified(80) }, io, .{}) catch |err| {
        result.* = err;
        return;
    };
    defer server.deinit(io);
    if (server.accept(io)) |s| s.close(io) else |err| result.* = err;
}

fn cancelAccept(io: Io, result: *?anyerror) !void {
    var f = io.async(acceptForever, .{ io, result });
    try io.sleep(.fromSeconds(1), .awake);
    f.cancel(io);
}

test "a task blocked in accept is canceled cleanly" {
    var sim: Sim = undefined;
    newSim(&sim, 6);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    var result: ?anyerror = null;
    try a.spawn(cancelAccept, .{ a.io(), &result });
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    try testing.expectEqual(@as(?anyerror, error.Canceled), result);
}

// ── datagrams ──────────────────────────────────────────────────────────────

fn udpEcho(io: Io, port: u16, count: usize) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(port) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [1500]u8 = undefined;
    for (0..count) |_| {
        const msg = try sock.receive(io, &buf);
        try sock.send(io, &msg.from, msg.data);
    }
}

const Query = struct { answered: bool = false, attempts: usize = 0, timeouts: usize = 0 };

/// What an sntp/dns client does: send, wait with a deadline, retry.
fn udpQuery(io: Io, server: net.IpAddress, out: *Query) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(0) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [64]u8 = undefined;
    while (out.attempts < 50) {
        out.attempts += 1;
        try sock.send(io, &server, "ping");
        const msg = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => {
                out.timeouts += 1;
                continue;
            },
            else => return err,
        };
        if (std.mem.eql(u8, msg.data, "ping")) {
            out.answered = true;
            return;
        }
    }
}

test "a datagram query with retries gets through a 40% lossy link, deterministically" {
    var answered_after_retry = false;
    for (0..8) |seed| {
        var sim: Sim = undefined;
        newSim(&sim, seed);
        defer sim.deinit();
        const a = try sim.addHost(.{});
        const b = try sim.addHost(.{});
        try sim.link(a, b, .{ .latency_ns = 10 * ns_per_ms, .loss_permille = 400 });
        var q: Query = .{};
        try b.spawn(udpEcho, .{ b.io(), 53, 50 });
        try a.spawn(udpQuery, .{ a.io(), addr4(b, 53), &q });
        _ = sim.run();
        try testing.expect(q.answered);
        try testing.expectEqual(q.attempts - 1, q.timeouts);
        if (q.timeouts > 0) answered_after_retry = true;
    }
    try testing.expect(answered_after_retry);
}

test "receiveTimeout reports Timeout when the server is cut off" {
    var sim: Sim = undefined;
    newSim(&sim, 7);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{});
    try sim.setLinkUp(a, b, false);
    var q: Query = .{};
    try b.spawn(udpEcho, .{ b.io(), 53, 1 });
    try a.spawn(udpQuery, .{ a.io(), addr4(b, 53), &q });
    const r = sim.run();
    try testing.expect(!q.answered);
    try testing.expectEqual(@as(usize, 50), q.timeouts);
    try testing.expectEqual(@as(u64, 50 * 500 * ns_per_ms), r.now_ns);
}

const Received = struct { count: usize = 0, flipped_bits: [8]u32 = @splat(0) };

fn udpSink(io: Io, port: u16, expect: []const u8, out: *Received) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(port) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [64]u8 = undefined;
    while (true) {
        const msg = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
        var bits: u32 = 0;
        for (msg.data, expect) |x, y| bits += @popCount(x ^ y);
        out.flipped_bits[@min(bits, 7)] += 1;
        out.count += 1;
    }
}

fn udpBurst(io: Io, to: net.IpAddress, data: []const u8, count: usize) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(0) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    for (0..count) |_| try sock.send(io, &to, data);
}

test "link faults on datagrams: every packet duplicated, or every packet one bit off" {
    const payload = "0123456789abcdef";
    {
        var sim: Sim = undefined;
        newSim(&sim, 8);
        defer sim.deinit();
        const a = try sim.addHost(.{});
        const b = try sim.addHost(.{});
        try sim.link(a, b, .{ .dup_permille = 1000 });
        var got: Received = .{};
        try b.spawn(udpSink, .{ b.io(), 9, payload, &got });
        try a.spawn(udpBurst, .{ a.io(), addr4(b, 9), payload, 10 });
        _ = sim.run();
        try testing.expectEqual(@as(usize, 20), got.count);
        try testing.expectEqual(@as(u32, 20), got.flipped_bits[0]);
    }
    {
        var sim: Sim = undefined;
        newSim(&sim, 8);
        defer sim.deinit();
        const a = try sim.addHost(.{});
        const b = try sim.addHost(.{});
        try sim.link(a, b, .{ .corrupt_permille = 1000 });
        var got: Received = .{};
        try b.spawn(udpSink, .{ b.io(), 9, payload, &got });
        try a.spawn(udpBurst, .{ a.io(), addr4(b, 9), payload, 10 });
        _ = sim.run();
        try testing.expectEqual(@as(usize, 10), got.count);
        try testing.expectEqual(@as(u32, 10), got.flipped_bits[1]);
    }
}

// ── ICMP echo ──────────────────────────────────────────────────────────────

const Ping = struct { replied: bool = false, rtt_ns: i96 = 0, from: ?net.IpAddress = null, reply: [16]u8 = undefined, len: usize = 0, port: u16 = 0 };

fn ping(io: Io, target: net.IpAddress, out: *Ping) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(0) }, io, .{ .mode = .dgram, .protocol = .icmp });
    defer sock.close(io);
    out.port = sock.address.getPort();
    // type 8, code 0, checksum (kernel fixes it), id (kernel rewrites), seq 7
    const req = [_]u8{ 8, 0, 0, 0, 0, 0, 0, 7, 'p', 'i', 'n', 'g' };
    const t0 = Io.Timestamp.now(io, .awake);
    try sock.send(io, &target, &req);
    var buf: [64]u8 = undefined;
    const msg = try sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromSeconds(2), .clock = .awake } });
    out.rtt_ns = t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds;
    out.replied = true;
    out.from = msg.from;
    @memcpy(out.reply[0..msg.data.len], msg.data);
    out.len = msg.data.len;
}

test "an ICMP echo request is answered by the target's simulated stack" {
    var sim: Sim = undefined;
    newSim(&sim, 11);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{ .latency_ns = 7 * ns_per_ms });
    var p: Ping = .{};
    try a.spawn(ping, .{ a.io(), addr4(b, 0), &p });
    _ = sim.run();
    try testing.expect(p.replied);
    try testing.expectEqual(@as(i96, 14 * ns_per_ms), p.rtt_ns);
    try testing.expect(p.from.?.eql(&addr4(b, 0)));
    const reply = p.reply[0..p.len];
    try testing.expectEqual(@as(u8, 0), reply[0]); // echo reply
    try testing.expectEqual(p.port, std.mem.readInt(u16, reply[4..6], .big)); // id = socket port
    try testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, reply[6..8], .big));
    try testing.expectEqualStrings("ping", reply[8..]);
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < reply.len) : (i += 2) sum += std.mem.readInt(u16, reply[i..][0..2], .big);
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    try testing.expectEqual(@as(u32, 0xffff), sum);
}

// ── routing ────────────────────────────────────────────────────────────────

fn oneWay(io: Io, to: net.IpAddress) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(0) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    try sock.send(io, &to, "x");
}

const Arrival = struct { at_ns: ?u64 = null };

fn arrive(io: Io, sim: *Sim, port: u16, out: *Arrival) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(port) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [8]u8 = undefined;
    _ = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } }) catch return;
    out.at_ns = sim.now;
}

fn routeLatency(build: *const fn (sim: *Sim, a: *Host, b: *Host, c: *Host) anyerror!void) !?u64 {
    var sim: Sim = undefined;
    newSim(&sim, 12);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    const c = try sim.addHost(.{});
    try build(&sim, a, b, c);
    var got: Arrival = .{};
    try c.spawn(arrive, .{ c.io(), &sim, 5000, &got });
    try a.spawn(oneWay, .{ a.io(), addr4(c, 5000) });
    _ = sim.run();
    return got.at_ns;
}

fn chain(sim: *Sim, a: *Host, b: *Host, c: *Host) anyerror!void {
    try sim.link(a, b, .{ .latency_ns = 10 * ns_per_ms });
    try sim.link(b, c, .{ .latency_ns = 10 * ns_per_ms });
}

fn chainCut(sim: *Sim, a: *Host, b: *Host, c: *Host) anyerror!void {
    try chain(sim, a, b, c);
    try sim.setLinkUp(b, c, false);
}

fn chainPlusSlowDirect(sim: *Sim, a: *Host, b: *Host, c: *Host) anyerror!void {
    try chainCut(sim, a, b, c);
    try sim.link(a, c, .{ .latency_ns = 50 * ns_per_ms });
}

fn chainPlusFastDirect(sim: *Sim, a: *Host, b: *Host, c: *Host) anyerror!void {
    try chain(sim, a, b, c);
    try sim.link(a, c, .{ .latency_ns = 15 * ns_per_ms });
}

test "packets take the shortest path over the links that are up" {
    try testing.expectEqual(@as(?u64, 20 * ns_per_ms), try routeLatency(chain)); // a-b-c
    try testing.expectEqual(@as(?u64, null), try routeLatency(chainCut)); // no path
    try testing.expectEqual(@as(?u64, 50 * ns_per_ms), try routeLatency(chainPlusSlowDirect));
    try testing.expectEqual(@as(?u64, 15 * ns_per_ms), try routeLatency(chainPlusFastDirect));
}
