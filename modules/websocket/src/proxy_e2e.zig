// SPDX-License-Identifier: MIT

//! Loopback, end to end: this module's client against this module's server
//! running inside an `http.Server` handler (`handshake.respondUpgraded` + `conn.Conn`),
//! once directly and once behind `http.proxy` (which relays the Upgrade and
//! splices the two connections) — the deployment Go users have with gorilla
//! or coder behind `httputil.ReverseProxy`. Tests only.

const std = @import("std");
const http = @import("http");
const testkit = @import("testkit");
const handshake = @import("handshake.zig");
const conn = @import("conn.zig");

const testing = std.testing;
const net = std.Io.net;

/// The WebSocket endpoint: echo every message until the peer closes.
fn echoHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    if (!std.mem.eql(u8, req.path, "/ws")) return rw.notFound();
    const up = try handshake.respondUpgraded(req, rw, try handshake.acceptHandshake(req.head, .{ .protocols = &.{"echo"} }));
    var msg_buf: [1024]u8 = undefined;
    var c = conn.Conn.init(.server, up.reader, up.writer, &msg_buf, .{});
    while (true) {
        const m = c.readMessage() catch |err| switch (err) {
            error.Closed => return,
            else => return err,
        };
        try c.writeMessage(m.opcode, m.payload);
    }
}

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

/// Open a WebSocket to `port`, echo twice across an idle gap longer than the
/// servers' read timeout, then close cleanly.
fn session(io: std.Io, port: u16) !void {
    const addr = try net.IpAddress.parse("127.0.0.1", port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var rbuf: [2048]u8 = undefined;
    var wbuf: [512]u8 = undefined;
    var sr = s.reader(io, &rbuf);
    var sw = s.writer(io, &wbuf);

    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const key = handshake.generateKey(prng.random());
    try handshake.writeRequest(&sw.interface, .{ .host = "t", .target = "/ws", .key = &key, .protocols = &.{"echo"} });
    try sw.interface.flush();
    var head_buf: [1024]u8 = undefined;
    const head = try http.h1.ResponseHead.parse(try http.h1.readHead(&sr.interface, &head_buf));
    const verified = try handshake.verifyResponse(head, &key, &.{"echo"});
    try testing.expectEqualStrings("echo", verified.protocol.?);

    var msg_buf: [1024]u8 = undefined;
    var c = conn.Conn.init(.client, &sr.interface, &sw.interface, &msg_buf, .{ .mask_random = prng.random() });
    try c.writeMessage(.text, "hello");
    const m1 = try c.readMessage();
    try testing.expectEqualStrings("hello", m1.payload);
    // Idle for twice the read timeout: the HTTP timeouts are off the socket.
    try io.sleep(.fromMilliseconds(400), .awake);
    try c.writeMessage(.binary, "\x00\x01\x02");
    const m2 = try c.readMessage();
    try testing.expectEqual(.binary, m2.opcode);
    try testing.expectEqualStrings("\x00\x01\x02", m2.payload);
    try c.close(1000, "bye");
    try testing.expectError(error.Closed, c.readMessage());
    try testing.expectEqual(@as(?u16, 1000), c.peer_close.?.code);
}

test "e2e: client and server over loopback, directly and behind http.proxy" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ws = http.Server.init(io, testing.allocator, .{ .handler = echoHandler, .read_timeout_ms = 200 });
    defer ws.deinit();
    ws.bind() catch |err| return testkit.loopbackSkip("websocket server bind failed ({t})", .{err});
    const ws_thread = try std.Thread.spawn(.{}, serveWrap, .{&ws});
    defer ws_thread.join();
    defer ws.shutdown();

    var proxy_client = http.Client.init(io, testing.allocator, .{});
    defer proxy_client.deinit();
    var ph = http.proxy.ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = ws.boundAddress().getPort() },
    });
    var front = http.Server.init(io, testing.allocator, .{ .handler = http.proxy.ProxyHandler.handler, .context = &ph, .read_timeout_ms = 200 });
    defer front.deinit();
    front.bind() catch |err| return testkit.loopbackSkip("proxy bind failed ({t})", .{err});
    const front_thread = try std.Thread.spawn(.{}, serveWrap, .{&front});
    defer front_thread.join();
    defer front.shutdown();

    try session(io, ws.boundAddress().getPort());
    try session(io, front.boundAddress().getPort());
}
