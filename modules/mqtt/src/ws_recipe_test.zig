// SPDX-License-Identifier: MIT

//! Recipe, tested: MQTT over WebSocket (MQTT 5.0 §6, 3.1.1 §6) with this
//! collection's `websocket` module — the transport Mosquitto's
//! `protocol websockets` listener, mochi and paho's `ws://` speak.
//!
//! Neither side of the MQTT state machine changes: the `Client`'s and the
//! `Broker`'s `Transport.write` wrap each write in one binary frame (masked
//! from the client, RFC 6455 §5.3), and what arrives is unframed before
//! `feed`. The opening handshake offers and selects the subprotocol `mqtt`
//! (MQTT 5.0 §6.0: "MUST be mqtt"). Over `wss://` the same framing runs on a
//! TLS stream instead of a socket (`tlsclient` on the client side; on the
//! server side terminate TLS in front of `TcpServer` until a TLS server
//! exists in this collection).
//!
//! Test-only dependencies (`test_deps`): `websocket`, and `http` for its
//! `h1` head parser. The mqtt module itself stays std-only.

const std = @import("std");
const testing = std.testing;
const mqtt = @import("root.zig");
const websocket = @import("websocket");
const h1 = @import("http").h1;
const ws_frame = websocket.frame;
const ws_hs = websocket.handshake;

/// One direction of the WebSocket link: frames written by one end, parsed
/// by the other.
const Pipe = struct {
    buf: [64 * 1024]u8 = undefined,
    len: usize = 0,
    mask: bool,
    /// Masking keys from a fixed-seed PRNG: a client MUST use unpredictable
    /// keys (§5.3) — `std.Io.randomSecure` in real code; any key works here.
    prng: std.Random.DefaultPrng = .init(0x3e5),

    fn write(p: *Pipe, payload: []const u8) !void {
        var w: std.Io.Writer = .fixed(p.buf[p.len..]);
        var key: [4]u8 = undefined;
        p.prng.random().bytes(&key);
        try ws_frame.writeFrame(&w, .{ .opcode = .binary, .payload = payload, .mask_key = if (p.mask) key else null });
        p.len += w.buffered().len;
    }

    /// Unframe everything complete into `sink`.
    fn drain(p: *Pipe, role: ws_frame.Role, sink: anytype) !void {
        var at: usize = 0;
        while (true) switch (try ws_frame.parseFrame(p.buf[at..p.len], role, 1 << 20)) {
            .need_more => break,
            .frame => |f| {
                try testing.expectEqual(ws_frame.Opcode.binary, f.opcode);
                try sink.take(f.payload);
                at += f.consumed;
            },
        };
        std.mem.copyForwards(u8, &p.buf, p.buf[at..p.len]);
        p.len -= at;
    }
};

const ClientEnd = struct {
    out: Pipe = .{ .mask = true },
    fn transport(e: *ClientEnd) mqtt.Transport {
        return .{ .ctx = e, .writeFn = writeFn };
    }
    fn writeFn(ctx: *anyopaque, bytes: []const u8) mqtt.TransportError!void {
        const e: *ClientEnd = @ptrCast(@alignCast(ctx));
        e.out.write(bytes) catch return error.TransportFailed;
    }
};

const BrokerEnd = struct {
    out: Pipe = .{ .mask = false },
    fn transport(e: *BrokerEnd) mqtt.broker.Transport {
        return .{ .ctx = e, .writeFn = writeFn };
    }
    fn writeFn(ctx: *anyopaque, bytes: []const u8) mqtt.broker.TransportError!void {
        const e: *BrokerEnd = @ptrCast(@alignCast(ctx));
        e.out.write(bytes) catch return error.TransportFailed;
    }
};

const IntoBroker = struct {
    b: *mqtt.Broker,
    conn: *mqtt.Connection,
    fn take(s: @This(), bytes: []const u8) !void {
        try s.b.feed(s.conn, bytes);
        _ = try s.b.process(s.conn, 0);
    }
};

const IntoClient = struct {
    c: *mqtt.Client,
    fn take(s: @This(), bytes: []const u8) !void {
        try s.c.feed(bytes);
    }
};

test "recipe: MQTT 5.0 over WebSocket — handshake with subprotocol mqtt, then CONNECT/SUBSCRIBE/PUBLISH in binary frames" {
    // ── the opening handshake ──
    var prng = std.Random.DefaultPrng.init(7);
    const key = ws_hs.generateKey(prng.random());
    var req_buf: [512]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try ws_hs.writeRequest(&req_w, .{ .host = "broker.local", .target = "/mqtt", .key = &key, .protocols = &.{"mqtt"} });
    const req_bytes = req_w.buffered();
    const req_head = try h1.RequestHead.parse(req_bytes[0 .. std.mem.indexOf(u8, req_bytes, "\r\n\r\n").? + 2]);
    const accepted = try ws_hs.acceptHandshake(req_head, .{ .protocols = &.{"mqtt"}, .origins = &.{"*"} });
    try testing.expectEqualStrings("mqtt", accepted.protocol.?);
    var resp_buf: [512]u8 = undefined;
    var resp_w: std.Io.Writer = .fixed(&resp_buf);
    try ws_hs.writeResponse(&resp_w, accepted);
    const resp_bytes = resp_w.buffered();
    const resp_head = try h1.ResponseHead.parse(resp_bytes[0 .. std.mem.indexOf(u8, resp_bytes, "\r\n\r\n").? + 2]);
    const verified = try ws_hs.verifyResponse(resp_head, &key, &.{"mqtt"});
    try testing.expectEqualStrings("mqtt", verified.protocol.?);

    // ── MQTT over the frames ──
    var broker: mqtt.Broker = .init(testing.allocator, .{});
    defer broker.deinit();
    var be: BrokerEnd = .{};
    const conn = try broker.accept(be.transport());
    defer broker.remove(conn);

    var ce: ClientEnd = .{};
    var rx: [4096]u8 = undefined;
    var tx: [4096]u8 = undefined;
    var client = mqtt.Client.init(ce.transport(), .{ .rx = &rx, .tx = &tx });
    const to_broker: IntoBroker = .{ .b = &broker, .conn = conn };
    const to_client: IntoClient = .{ .c = &client };

    try client.connect(0, .{ .client_id = "ws-client", .version = .v5 });
    try ce.out.drain(.server, to_broker);
    try be.out.drain(.client, to_client);
    const connack = (try client.poll(0)).?;
    try testing.expect(connack == .connack and connack.connack.reason_code == .success);

    _ = try client.subscribe(0, &.{.{ .filter = "ws/#", .qos = .at_least_once }});
    try ce.out.drain(.server, to_broker);
    try be.out.drain(.client, to_client);
    try testing.expect((try client.poll(0)).? == .suback);

    const id = (try client.publish(0, "ws/hello", "over websocket", .{ .qos = .at_least_once })).?;
    try ce.out.drain(.server, to_broker);
    try be.out.drain(.client, to_client);
    var got_message = false;
    var got_puback = false;
    while (try client.poll(0)) |ev| switch (ev) {
        .message => |m| {
            try testing.expectEqualStrings("ws/hello", m.topic);
            try testing.expectEqualStrings("over websocket", m.payload);
            got_message = true;
        },
        .puback => |a| {
            try testing.expectEqual(id, a.packet_id);
            got_puback = true;
        },
        else => {},
    };
    // The client's PUBACK for the delivered message goes back framed too.
    try ce.out.drain(.server, to_broker);
    try testing.expect(got_message and got_puback);
}

test "recipe: an unmasked frame from the client is refused (RFC 6455 §5.1) before MQTT sees a byte" {
    var p: Pipe = .{ .mask = false };
    try p.write("\x10\x00");
    const Never = struct {
        fn take(_: @This(), _: []const u8) !void {
            return error.ShouldNotBeReached;
        }
    };
    try testing.expectError(error.UnmaskedClientFrame, p.drain(.server, Never{}));
}
