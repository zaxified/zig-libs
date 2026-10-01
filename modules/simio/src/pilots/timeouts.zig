// SPDX-License-Identifier: MIT

//! Pilot: the request timeouts of four transports that bound a stream or
//! datagram exchange through `std.Io` alone — `modbus.TcpTransport`,
//! `whois.TcpTransport`, `stun.query`, `ocspcache`'s HTTP fetch and
//! `llmclient`'s body read — moved
//! here from wall-clock loopback windows.
//!
//! Each module keeps its loopback tests: they are the real-kernel half, and
//! they are already hardened against load (read cues instead of sleeps,
//! generous upper bounds). What a loopback test cannot say is *when* a
//! timeout fires — only that it fired somewhere inside a window of seconds.
//! Here virtual time makes it exact: a 80 ms budget ends at 80 ms, a slow
//! peer's late reply is not waited for, and an unbounded call is stopped by
//! its caller's cancel at the instant the caller chose.

const std = @import("std");
const modbus = @import("modbus");
const whois = @import("whois");
const stun = @import("stun");
const ocspcache = @import("ocspcache");
const llmclient = @import("llmclient");
const http = @import("http");
const sched = @import("../sched.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;

fn msSince(io: Io, start: Io.Timestamp) i64 {
    return @intCast(@divFloor(start.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, ns_per_ms));
}

/// A peer on `port`: reads a little of the request, waits `delay_ms` (or
/// forever when null), then answers `reply`.
const Peer = struct {
    port: u16,
    delay_ms: ?u64,
    reply: []const u8,
    head_then_silence: bool = false,
    /// After the head, one body byte every this many ms (an SSE trickle).
    drip_ms: ?u64 = null,

    fn run(io: Io, p: *const Peer) !void {
        var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(p.port) }, io, .{});
        defer listener.deinit(io);
        const s = try listener.accept(io);
        defer s.close(io);
        var rbuf: [256]u8 = undefined;
        var sr = s.reader(io, &rbuf);
        _ = sr.interface.readSliceShort(rbuf[0..1]) catch {};
        var wbuf: [256]u8 = undefined;
        var sw = s.writer(io, &wbuf);
        if (p.drip_ms) |gap| {
            // Drain the request head, so closing never resets unread input.
            while (true) {
                const line = sr.interface.takeDelimiterInclusive('\n') catch break;
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            try sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000000\r\n\r\n");
            try sw.interface.flush();
            for (0..200) |_| {
                sw.interface.writeAll("d") catch return;
                sw.interface.flush() catch return;
                try io.sleep(.fromMilliseconds(@intCast(gap)), .awake);
            }
            return;
        }
        if (p.head_then_silence) {
            try sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
            try sw.interface.flush();
            return io.sleep(.fromSeconds(3600), .awake);
        }
        const delay = p.delay_ms orelse return io.sleep(.fromSeconds(3600), .awake);
        try io.sleep(.fromMilliseconds(@intCast(delay)), .awake);
        try sw.interface.writeAll(p.reply);
        try sw.interface.flush();
    }
};

const Outcome = struct {
    err: ?anyerror = null,
    ok: bool = false,
    elapsed_ms: i64 = -1,
};

/// One client task against one peer host named "peer".
fn world(peer: *const Peer, client: anytype, args: anytype) !void {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 5, .stack_size = 1024 * 1024 });
    defer sim.deinit();
    const s = try sim.addHost(.{ .name = "peer" });
    const c = try sim.addHost(.{});
    try sim.link(s, c, .{ .latency_ns = 5 * ns_per_ms });
    try s.spawn(Peer.run, .{ s.io(), peer });
    try c.spawn(client, .{c.io()} ++ .{s.ip4} ++ args);
    _ = sim.runFor(30 * std.time.ns_per_s);
}

// ── modbus ─────────────────────────────────────────────────────────────────

fn modbusClient(io: Io, ip: [4]u8, timeout_ms: ?u32, cancel_at_ms: ?u64, out: *Outcome) !void {
    try io.sleep(.fromMilliseconds(10), .awake); // the peer is listening by now
    var t = try modbus.TcpTransport.connect(io, .{ .ip4 = .{ .bytes = ip, .port = 502 } });
    defer t.close();
    t.timeout_ms = timeout_ms;
    var buf: [modbus.tcp.max_adu_len]u8 = undefined;
    const start = Io.Timestamp.now(io, .awake);
    if (cancel_at_ms) |at| {
        var f = io.async(modbusExchange, .{ &t, &buf });
        try io.sleep(.fromMilliseconds(@intCast(at)), .awake);
        if (f.cancel(io)) |_| out.ok = true else |err| out.err = err;
    } else if (modbusExchange(&t, &buf)) |_| out.ok = true else |err| out.err = err;
    out.elapsed_ms = msSince(io, start);
}

fn modbusExchange(t: *modbus.TcpTransport, buf: []u8) modbus.TransportError![]const u8 {
    return t.transport().exchange(&.{ 0x00, 0x01 }, buf);
}

test "timeouts: modbus timeout_ms ends a silent peer's exchange at exactly 80 ms" {
    const peer: Peer = .{ .port = 502, .delay_ms = null, .reply = "" };
    var out: Outcome = .{};
    try world(&peer, modbusClient, .{ @as(?u32, 80), @as(?u64, null), &out });
    try testing.expectEqual(@as(?anyerror, error.Timeout), out.err);
    try testing.expectEqual(@as(i64, 80), out.elapsed_ms);
}

test "timeouts: modbus with no timeout waits until its caller cancels, at the caller's instant" {
    const peer: Peer = .{ .port = 502, .delay_ms = null, .reply = "" };
    var out: Outcome = .{};
    try world(&peer, modbusClient, .{ @as(?u32, null), @as(?u64, 300), &out });
    try testing.expectEqual(@as(?anyerror, error.Canceled), out.err);
    try testing.expectEqual(@as(i64, 300), out.elapsed_ms);
}

// ── whois ──────────────────────────────────────────────────────────────────

fn whoisClient(io: Io, ip: [4]u8, timeout_ms: ?u32, out: *Outcome) !void {
    _ = ip; // dialed by name: simio resolves "peer"
    try io.sleep(.fromMilliseconds(10), .awake);
    var tcp: whois.TcpTransport = .{ .io = io, .deny_special_use = false, .timeout_ms = timeout_ms };
    var buf: [256]u8 = undefined;
    const start = Io.Timestamp.now(io, .awake);
    if (tcp.transport().exchange("peer", 43, "example.com\r\n", &buf)) |reply| {
        out.ok = std.mem.eql(u8, reply, "late reply\r\n");
    } else |err| out.err = err;
    out.elapsed_ms = msSince(io, start);
}

test "timeouts: whois gives up on a slow-but-live peer at 80 ms, not at its 900 ms reply" {
    const peer: Peer = .{ .port = 43, .delay_ms = 900, .reply = "late reply\r\n" };
    var out: Outcome = .{};
    try world(&peer, whoisClient, .{ @as(?u32, 80), &out });
    try testing.expectEqual(@as(?anyerror, error.Timeout), out.err);
    try testing.expectEqual(@as(i64, 80), out.elapsed_ms);
}

test "timeouts: whois with no timeout gets the late reply when it comes" {
    const peer: Peer = .{ .port = 43, .delay_ms = 900, .reply = "late reply\r\n" };
    var out: Outcome = .{};
    try world(&peer, whoisClient, .{ @as(?u32, null), &out });
    try testing.expect(out.ok);
    // Connect (one round trip), the request's way there, 900 ms, the way back.
    try testing.expect(out.elapsed_ms >= 910 and out.elapsed_ms <= 925);
}

// ── stun ───────────────────────────────────────────────────────────────────

fn stunClient(io: Io, ip: [4]u8, timeout_ms: u32, out: *Outcome) !void {
    var buf: [512]u8 = undefined;
    const txid: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const start = Io.Timestamp.now(io, .awake);
    if (stun.query(io, .{ .ip4 = .{ .bytes = ip, .port = 3478 } }, txid, &buf, .{ .timeout_ms = timeout_ms })) |ap| {
        out.ok = ap.port == 4989;
    } else |err| out.err = err;
    out.elapsed_ms = msSince(io, start);
}

/// Answers one Binding request with a fixed mapped address, or never.
fn stunServer(io: Io, answer: bool) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(3478) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var req: [512]u8 = undefined;
    const in = try sock.receive(io, &req);
    if (!answer) return;
    const msg = try stun.decode(in.data);
    var resp: [64]u8 = undefined;
    var b = try stun.Builder.init(&resp, .success_response, .binding, msg.transaction_id);
    try b.addMappedAddress(.{ .v4 = .{ 192, 0, 2, 7 } }, 4989, true);
    try sock.send(io, &in.from, b.finish());
}

fn stunWorld(answer: bool, timeout_ms: u32, out: *Outcome) !void {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 6, .stack_size = 512 * 1024 });
    defer sim.deinit();
    const s = try sim.addHost(.{});
    const c = try sim.addHost(.{});
    try sim.link(s, c, .{ .latency_ns = 5 * ns_per_ms });
    try s.spawn(stunServer, .{ s.io(), answer });
    try c.spawn(stunClient, .{ c.io(), s.ip4, timeout_ms, out });
    _ = sim.runFor(10 * std.time.ns_per_s);
}

test "timeouts: stun.query against a dark server times out at exactly 150 ms" {
    var out: Outcome = .{};
    try stunWorld(false, 150, &out);
    try testing.expectEqual(@as(?anyerror, error.Timeout), out.err);
    try testing.expectEqual(@as(i64, 150), out.elapsed_ms);
}

test "timeouts: stun.query's answer arrives after one round trip, well inside the bound" {
    var out: Outcome = .{};
    try stunWorld(true, 150, &out);
    try testing.expect(out.ok);
    try testing.expectEqual(@as(i64, 10), out.elapsed_ms);
}

// ── ocspcache ──────────────────────────────────────────────────────────────

fn ocspClient(io: Io, ip: [4]u8, body_timeout_ms: u32, out: *Outcome) !void {
    _ = ip;
    try io.sleep(.fromMilliseconds(10), .awake);
    var client = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    const transport = ocspcache.httpTransport(&client);
    const start = Io.Timestamp.now(io, .awake);
    if (transport.fetch(testing.allocator, .{ .url = "http://peer:80/", .max_response_bytes = 1024, .body_timeout_ms = body_timeout_ms })) |res| {
        testing.allocator.free(res.body);
        out.ok = true;
    } else |err| out.err = err;
    out.elapsed_ms = msSince(io, start);
}

test "timeouts: an OCSP fetch whose responder sends a head and no body ends at body_timeout_ms" {
    const peer: Peer = .{ .port = 80, .delay_ms = null, .reply = "", .head_then_silence = true };
    var out: Outcome = .{};
    try world(&peer, ocspClient, .{ @as(u32, 200), &out });
    try testing.expectEqual(@as(?anyerror, error.Timeout), out.err);
    // Connect and request take a round trip each; the body budget then runs
    // its 200 ms from the head's arrival.
    try testing.expect(out.elapsed_ms >= 220 and out.elapsed_ms <= 222);
}

// ── llmclient ──────────────────────────────────────────────────────────────

fn llmClient(io: Io, ip: [4]u8, read_timeout_ms: u32, out: *Outcome) !void {
    _ = ip;
    try io.sleep(.fromMilliseconds(10), .awake);
    var hc = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer hc.deinit();
    var c: llmclient.Client = .init(&hc, "sk-test");
    c.base_url = "http://peer:80";
    c.read_timeout_ms = read_timeout_ms;
    const req: llmclient.MessageRequest = .{
        .max_tokens = 16,
        .messages = &.{llmclient.MessageParam.user(&.{llmclient.textBlock("hello")})},
    };
    const start = Io.Timestamp.now(io, .awake);
    if (c.create(testing.allocator, req)) |parsed| {
        var p = parsed;
        p.deinit();
        out.ok = true;
    } else |err| out.err = err;
    out.elapsed_ms = msSince(io, start);
}

test "timeouts: llmclient gives up on a body that trickles in, read_timeout_ms after the head" {
    // One byte every 50 ms never stalls a read for long; the body deadline
    // ends it anyway.
    const peer: Peer = .{ .port = 80, .delay_ms = null, .reply = "", .drip_ms = 50 };
    var out: Outcome = .{};
    try world(&peer, llmClient, .{ @as(u32, 300), &out });
    try testing.expectEqual(@as(?anyerror, error.Timeout), out.err);
    // Connect and request: a round trip each; then 300 ms of body.
    try testing.expect(out.elapsed_ms >= 320 and out.elapsed_ms <= 322);
}
