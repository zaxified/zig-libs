// SPDX-License-Identifier: MIT

//! MQTT 3.1.1 client state machine over a caller-provided transport seam.
//!
//! The client never touches sockets or clocks itself: outgoing bytes go
//! through a `Transport` (a "write these bytes" vtable), incoming bytes are
//! handed to `feed`, and every time-dependent call takes `now` (caller's
//! monotonic clock, milliseconds). That makes the whole state machine
//! offline-testable from in-memory buffers. `TcpTransport` is an optional
//! real-socket adapter over `std.Io.net`; tests never dial.
//!
//! QoS handling:
//! - QoS 0 publish: fire and forget.
//! - QoS 1 publish: PUBLISH → PUBACK; the packet id stays allocated until
//!   the PUBACK arrives (event `.puback`). `publishDup` retransmits with
//!   the DUP flag while unacknowledged (caller decides when).
//! - QoS 2 publish: PUBLISH → PUBREC → PUBREL → PUBCOMP; PUBREL is sent
//!   automatically on PUBREC, the id is released on PUBCOMP (event
//!   `.pubcomp`).
//! - QoS 1 receive: PUBACK is sent automatically, message delivered.
//! - QoS 2 receive: PUBREC sent automatically and the id remembered; a
//!   DUP re-delivery of the same id is suppressed; PUBREL is answered
//!   with PUBCOMP and the id forgotten (exactly-once delivery to the app).
//!
//! Session state is reset on `connect`; replaying unacknowledged QoS
//! messages into a resumed session (clean_session = false) is the caller's
//! job — the client does not buffer payloads.
//!
//! Provenance: clean-room from the OASIS MQTT 3.1.1 specification;
//! mosquitto/Paho referenced for behavior only, no source consulted or
//! copied.

const std = @import("std");
const packet = @import("packet.zig");
const topic_rules = @import("topic.zig");

/// Failures a `Transport` implementation may report.
pub const TransportError = error{TransportFailed};

/// Outgoing byte seam. Implementations must either take all bytes or fail;
/// the client never retries partial writes.
pub const Transport = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) TransportError!void,

    pub fn write(t: Transport, bytes: []const u8) TransportError!void {
        return t.writeFn(t.ctx, bytes);
    }
};

pub const ConnectionState = enum { idle, connecting, connected, disconnected };

/// An application message delivered by the broker. Slices point into the
/// client's receive buffer — valid only until the next `feed` / `poll`.
pub const Message = struct {
    topic: []const u8,
    payload: []const u8,
    qos: packet.QoS,
    retain: bool,
    dup: bool,
    /// 0 for QoS 0.
    packet_id: u16,
};

/// Events surfaced by `poll`. Slice fields point into the receive buffer —
/// valid only until the next `feed` / `poll` call.
pub const Event = union(enum) {
    /// CONNACK arrived; on `.accepted` the client is now `.connected`.
    connack: packet.Connack,
    /// Application message received (all QoS acks already handled).
    message: Message,
    /// QoS 1 publish acknowledged; the packet id has been released.
    puback: u16,
    /// QoS 2 publish completed the 4-packet handshake; id released.
    pubcomp: u16,
    /// Subscribe acknowledged; one code per filter (0/1/2 or 0x80 failure).
    suback: packet.Suback,
    unsuback: u16,
    pingresp,
};

/// Upper bound on simultaneously outstanding packet ids (either direction).
pub const max_in_flight = 64;

pub const Error = error{
    NotConnected,
    AlreadyConnected,
    /// The bounded packet-id pool (`max_in_flight`) is exhausted.
    TooManyInFlight,
    /// `feed` would overflow the caller-provided receive buffer.
    RxBufferFull,
    /// No PINGRESP within a full keep-alive interval after our PINGREQ.
    KeepAliveTimeout,
    InvalidTopic,
    InvalidFilter,
} || packet.DecodeError || packet.EncodeError || TransportError;

/// MQTT 3.1.1 client. Allocation-free: hand it a receive buffer (must hold
/// the largest expected incoming packet) and a transmit scratch buffer
/// (must hold the largest packet you send).
pub const Client = struct {
    transport: Transport,
    tx_buf: []u8,
    rx_buf: []u8,
    rx_len: usize = 0,
    rx_consumed: usize = 0,

    state: ConnectionState = .idle,
    keep_alive_ms: u64 = 0,
    last_tx: u64 = 0,
    awaiting_pingresp: bool = false,
    ping_sent: u64 = 0,

    next_packet_id: u16 = 1,
    pending: [max_in_flight]Pending = undefined,
    pending_len: usize = 0,
    /// QoS 2 receive-side ids between PUBREC and PUBREL (dedup window).
    inbound_qos2: [max_in_flight]u16 = undefined,
    inbound_len: usize = 0,

    const Pending = struct {
        id: u16,
        kind: Kind,

        const Kind = enum {
            publish_qos1, // awaiting PUBACK
            publish_await_pubrec,
            publish_await_pubcomp,
            subscribe, // awaiting SUBACK
            unsubscribe, // awaiting UNSUBACK
        };
    };

    pub const Buffers = struct { rx: []u8, tx: []u8 };

    pub fn init(transport: Transport, buffers: Buffers) Client {
        return .{ .transport = transport, .rx_buf = buffers.rx, .tx_buf = buffers.tx };
    }

    pub const PublishOptions = struct {
        qos: packet.QoS = .at_most_once,
        retain: bool = false,
    };

    // ── outgoing API ────────────────────────────────────────────────────────

    /// Send CONNECT and reset all session state. The broker's answer
    /// surfaces later as an `Event.connack` from `poll`.
    pub fn connect(c: *Client, now: u64, options: packet.Connect) Error!void {
        switch (c.state) {
            .connecting, .connected => return error.AlreadyConnected,
            .idle, .disconnected => {},
        }
        c.pending_len = 0;
        c.inbound_len = 0;
        c.awaiting_pingresp = false;
        c.rx_len = 0;
        c.rx_consumed = 0;
        const bytes = try packet.encodeConnect(c.tx_buf, options);
        try c.send(now, bytes);
        c.state = .connecting;
        c.keep_alive_ms = @as(u64, options.keep_alive_s) * std.time.ms_per_s;
    }

    /// Publish to `topic_name`. Returns the allocated packet id for
    /// QoS > 0 (released when `.puback` / `.pubcomp` fires), null for QoS 0.
    pub fn publish(
        c: *Client,
        now: u64,
        topic_name: []const u8,
        payload: []const u8,
        options: PublishOptions,
    ) Error!?u16 {
        if (c.state != .connected) return error.NotConnected;
        topic_rules.validateName(topic_name) catch return error.InvalidTopic;
        var id: u16 = 0;
        if (options.qos != .at_most_once) {
            id = try c.allocPacketId(switch (options.qos) {
                .at_least_once => .publish_qos1,
                .exactly_once => .publish_await_pubrec,
                .at_most_once => unreachable,
            });
        }
        errdefer if (id != 0) c.removePending(id);
        const bytes = try packet.encodePublish(c.tx_buf, .{
            .topic = topic_name,
            .payload = payload,
            .qos = options.qos,
            .retain = options.retain,
            .packet_id = id,
        });
        try c.send(now, bytes);
        return if (id == 0) null else id;
    }

    /// Retransmit an unacknowledged QoS > 0 publish with the DUP flag set,
    /// reusing its packet id (spec 3.3.1.1). The id must still be pending
    /// (QoS 1: no PUBACK yet; QoS 2: no PUBREC yet).
    pub fn publishDup(
        c: *Client,
        now: u64,
        packet_id: u16,
        topic_name: []const u8,
        payload: []const u8,
        options: PublishOptions,
    ) Error!void {
        if (c.state != .connected) return error.NotConnected;
        const kind = c.pendingKind(packet_id) orelse return error.InvalidPacketId;
        const expected: Pending.Kind = switch (options.qos) {
            .at_most_once => return error.InvalidPacketId,
            .at_least_once => .publish_qos1,
            .exactly_once => .publish_await_pubrec,
        };
        if (kind != expected) return error.InvalidPacketId;
        const bytes = try packet.encodePublish(c.tx_buf, .{
            .topic = topic_name,
            .payload = payload,
            .qos = options.qos,
            .retain = options.retain,
            .dup = true,
            .packet_id = packet_id,
        });
        try c.send(now, bytes);
    }

    /// Send SUBSCRIBE; returns the packet id the SUBACK will carry.
    pub fn subscribe(c: *Client, now: u64, filters: []const packet.Subscription) Error!u16 {
        if (c.state != .connected) return error.NotConnected;
        if (filters.len == 0) return error.EmptyTopicList;
        for (filters) |f| topic_rules.validateFilter(f.filter) catch return error.InvalidFilter;
        const id = try c.allocPacketId(.subscribe);
        errdefer c.removePending(id);
        const bytes = try packet.encodeSubscribe(c.tx_buf, id, filters);
        try c.send(now, bytes);
        return id;
    }

    /// Send UNSUBSCRIBE; returns the packet id the UNSUBACK will carry.
    pub fn unsubscribe(c: *Client, now: u64, filters: []const []const u8) Error!u16 {
        if (c.state != .connected) return error.NotConnected;
        if (filters.len == 0) return error.EmptyTopicList;
        for (filters) |f| topic_rules.validateFilter(f) catch return error.InvalidFilter;
        const id = try c.allocPacketId(.unsubscribe);
        errdefer c.removePending(id);
        const bytes = try packet.encodeUnsubscribe(c.tx_buf, id, filters);
        try c.send(now, bytes);
        return id;
    }

    /// Send a PINGREQ now (also done automatically by `tick`).
    pub fn pingreq(c: *Client, now: u64) Error!void {
        if (c.state != .connected) return error.NotConnected;
        const bytes = try packet.encodePingreq(c.tx_buf);
        try c.send(now, bytes);
        c.awaiting_pingresp = true;
        c.ping_sent = now;
    }

    /// Send DISCONNECT and enter `.disconnected`.
    pub fn disconnect(c: *Client, now: u64) Error!void {
        switch (c.state) {
            .connected, .connecting => {},
            .idle, .disconnected => return error.NotConnected,
        }
        const bytes = try packet.encodeDisconnect(c.tx_buf);
        try c.send(now, bytes);
        c.state = .disconnected;
    }

    /// Keep-alive driver — call periodically with the current monotonic
    /// time in ms. Sends PINGREQ once the link has been send-idle for a
    /// full keep-alive interval; errors with `KeepAliveTimeout` when a
    /// PINGREQ goes unanswered for another full interval.
    pub fn tick(c: *Client, now: u64) Error!void {
        if (c.state != .connected or c.keep_alive_ms == 0) return;
        if (c.awaiting_pingresp) {
            if (now >= c.ping_sent + c.keep_alive_ms) return error.KeepAliveTimeout;
            return;
        }
        if (now >= c.last_tx + c.keep_alive_ms) try c.pingreq(now);
    }

    // ── incoming API ────────────────────────────────────────────────────────

    /// Hand the client bytes read from the broker (any framing: partial
    /// packets and multiple packets per call are both fine).
    pub fn feed(c: *Client, bytes: []const u8) Error!void {
        c.compact();
        if (c.rx_len + bytes.len > c.rx_buf.len) return error.RxBufferFull;
        @memcpy(c.rx_buf[c.rx_len..][0..bytes.len], bytes);
        c.rx_len += bytes.len;
    }

    /// Decode buffered broker packets, advance the QoS state machines
    /// (sending PUBACK/PUBREC/PUBREL/PUBCOMP as needed) and return the next
    /// application-visible event, or null once no complete packet remains.
    ///
    /// Slices inside the returned event point into the receive buffer and
    /// are valid only until the next `feed` / `poll` call. A decode error
    /// leaves the buffer untouched; the connection should be torn down and
    /// re-`connect`ed.
    pub fn poll(c: *Client, now: u64) Error!?Event {
        while (true) {
            c.compact();
            const dec = (try packet.decode(c.rx_buf[0..c.rx_len])) orelse return null;
            c.rx_consumed = dec.consumed;
            if (try c.handle(now, dec.packet)) |event| return event;
        }
    }

    /// Drop all buffered, not-yet-processed broker bytes (e.g. after a
    /// decode error, before tearing the connection down).
    pub fn resetRx(c: *Client) void {
        c.rx_len = 0;
        c.rx_consumed = 0;
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn send(c: *Client, now: u64, bytes: []const u8) TransportError!void {
        try c.transport.write(bytes);
        c.last_tx = now;
    }

    fn compact(c: *Client) void {
        if (c.rx_consumed == 0) return;
        if (c.rx_consumed >= c.rx_len) {
            c.rx_len = 0;
            c.rx_consumed = 0;
            return;
        }
        const remaining = c.rx_len - c.rx_consumed;
        std.mem.copyForwards(u8, c.rx_buf[0..remaining], c.rx_buf[c.rx_consumed..c.rx_len]);
        c.rx_len = remaining;
        c.rx_consumed = 0;
    }

    fn handle(c: *Client, now: u64, p: packet.Packet) Error!?Event {
        if (p == .connack) {
            if (c.state != .connecting) return error.ProtocolViolation;
            const ca = p.connack;
            c.state = if (ca.return_code == .accepted) .connected else .disconnected;
            return .{ .connack = ca };
        }
        if (c.state != .connected) return error.ProtocolViolation;

        switch (p) {
            .connack => unreachable,
            // A 3.1.1 server never sends these to a client.
            .connect, .subscribe, .unsubscribe, .pingreq, .disconnect => {
                return error.ProtocolViolation;
            },
            .publish => |incoming| {
                const msg = Message{
                    .topic = incoming.topic,
                    .payload = incoming.payload,
                    .qos = incoming.qos,
                    .retain = incoming.retain,
                    .dup = incoming.dup,
                    .packet_id = incoming.packet_id,
                };
                switch (incoming.qos) {
                    .at_most_once => return .{ .message = msg },
                    .at_least_once => {
                        try c.send(now, try packet.encodePuback(c.tx_buf, incoming.packet_id));
                        return .{ .message = msg };
                    },
                    .exactly_once => {
                        const duplicate = c.hasInbound(incoming.packet_id);
                        if (!duplicate) try c.addInbound(incoming.packet_id);
                        try c.send(now, try packet.encodePubrec(c.tx_buf, incoming.packet_id));
                        return if (duplicate) null else .{ .message = msg };
                    },
                }
            },
            .puback => |id| {
                if (c.pendingKind(id) != .publish_qos1) return error.ProtocolViolation;
                c.removePending(id);
                return .{ .puback = id };
            },
            .pubrec => |id| {
                if (c.pendingKind(id) != .publish_await_pubrec) return error.ProtocolViolation;
                c.setPendingKind(id, .publish_await_pubcomp);
                try c.send(now, try packet.encodePubrel(c.tx_buf, id));
                return null;
            },
            .pubcomp => |id| {
                if (c.pendingKind(id) != .publish_await_pubcomp) return error.ProtocolViolation;
                c.removePending(id);
                return .{ .pubcomp = id };
            },
            .pubrel => |id| {
                // Always answer PUBREL with PUBCOMP (spec 4.3.3), even for
                // an id we no longer remember.
                c.removeInbound(id);
                try c.send(now, try packet.encodePubcomp(c.tx_buf, id));
                return null;
            },
            .suback => |sa| {
                if (c.pendingKind(sa.packet_id) != .subscribe) return error.ProtocolViolation;
                c.removePending(sa.packet_id);
                return .{ .suback = sa };
            },
            .unsuback => |id| {
                if (c.pendingKind(id) != .unsubscribe) return error.ProtocolViolation;
                c.removePending(id);
                return .{ .unsuback = id };
            },
            .pingresp => {
                c.awaiting_pingresp = false;
                return .pingresp;
            },
        }
    }

    /// Allocate the next free nonzero packet id (wraps 65535 → 1, skips
    /// ids still in flight) and record what it is waiting for.
    fn allocPacketId(c: *Client, kind: Pending.Kind) Error!u16 {
        if (c.pending_len >= max_in_flight) return error.TooManyInFlight;
        var attempts: u32 = 0;
        while (attempts < std.math.maxInt(u16)) : (attempts += 1) {
            const id = c.next_packet_id;
            c.next_packet_id = if (c.next_packet_id == std.math.maxInt(u16))
                1
            else
                c.next_packet_id + 1;
            if (c.pendingIndex(id) == null) {
                c.pending[c.pending_len] = .{ .id = id, .kind = kind };
                c.pending_len += 1;
                return id;
            }
        }
        return error.TooManyInFlight; // unreachable while max_in_flight < 65535
    }

    fn pendingIndex(c: *const Client, id: u16) ?usize {
        for (c.pending[0..c.pending_len], 0..) |entry, i| {
            if (entry.id == id) return i;
        }
        return null;
    }

    fn pendingKind(c: *const Client, id: u16) ?Pending.Kind {
        const i = c.pendingIndex(id) orelse return null;
        return c.pending[i].kind;
    }

    fn setPendingKind(c: *Client, id: u16, kind: Pending.Kind) void {
        if (c.pendingIndex(id)) |i| c.pending[i].kind = kind;
    }

    fn removePending(c: *Client, id: u16) void {
        if (c.pendingIndex(id)) |i| {
            c.pending_len -= 1;
            c.pending[i] = c.pending[c.pending_len];
        }
    }

    fn hasInbound(c: *const Client, id: u16) bool {
        return std.mem.indexOfScalar(u16, c.inbound_qos2[0..c.inbound_len], id) != null;
    }

    fn addInbound(c: *Client, id: u16) Error!void {
        if (c.inbound_len >= max_in_flight) return error.TooManyInFlight;
        c.inbound_qos2[c.inbound_len] = id;
        c.inbound_len += 1;
    }

    fn removeInbound(c: *Client, id: u16) void {
        if (std.mem.indexOfScalar(u16, c.inbound_qos2[0..c.inbound_len], id)) |i| {
            c.inbound_len -= 1;
            c.inbound_qos2[i] = c.inbound_qos2[c.inbound_len];
        }
    }
};

// ── optional real transport: MQTT over TCP via std.Io.net ──────────────────
// Demo convenience only — nothing in the codec, client, or tests needs it.

/// Blocking TCP transport over `std.Io.net`. Pump received bytes yourself:
/// `readSome` → `client.feed` → `client.poll`.
pub const TcpTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,

    /// Standard MQTT port (1883; 8883 is MQTT over TLS).
    pub const default_port = 1883;

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpTransport {
        const stream = try address.connect(io, .{ .mode = .stream });
        return .{ .io = io, .stream = stream };
    }

    pub fn close(t: *TcpTransport) void {
        t.stream.close(t.io);
    }

    pub fn transport(t: *TcpTransport) Transport {
        return .{ .ctx = t, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const t: *TcpTransport = @ptrCast(@alignCast(ctx));
        var wbuf: [512]u8 = undefined;
        var sw = t.stream.writer(t.io, &wbuf);
        sw.interface.writeAll(bytes) catch return error.TransportFailed;
        sw.interface.flush() catch return error.TransportFailed;
    }

    /// Read whatever bytes are available (blocking for at least one);
    /// hand them to `Client.feed`.
    pub fn readSome(t: *TcpTransport, buf: []u8) TransportError!usize {
        return std.posix.read(t.stream.socket.handle, buf) catch error.TransportFailed;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Scripted fake broker side of the seam: captures everything the client
/// writes so tests can byte-check or decode it.
const TestTransport = struct {
    written: [2048]u8 = undefined,
    len: usize = 0,
    fail: bool = false,

    fn transport(m: *TestTransport) Transport {
        return .{ .ctx = m, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const m: *TestTransport = @ptrCast(@alignCast(ctx));
        if (m.fail) return error.TransportFailed;
        if (m.len + bytes.len > m.written.len) return error.TransportFailed;
        @memcpy(m.written[m.len..][0..bytes.len], bytes);
        m.len += bytes.len;
    }

    fn reset(m: *TestTransport) void {
        m.len = 0;
    }

    fn sent(m: *const TestTransport) []const u8 {
        return m.written[0..m.len];
    }

    /// Decode the single packet the client wrote since the last reset.
    fn lastPacket(m: *const TestTransport) !packet.Packet {
        const dec = (try packet.decode(m.sent())).?;
        try testing.expectEqual(m.len, dec.consumed);
        return dec.packet;
    }
};

fn makeConnected(tt: *TestTransport, rx: []u8, tx: []u8) !Client {
    var c = Client.init(tt.transport(), .{ .rx = rx, .tx = tx });
    try c.connect(0, .{ .client_id = "test", .keep_alive_s = 60 });
    try testing.expectEqual(ConnectionState.connecting, c.state);
    try testing.expect((try tt.lastPacket()) == .connect);
    tt.reset();

    var buf: [4]u8 = undefined;
    const connack = try packet.encodeConnack(&buf, .{
        .session_present = false,
        .return_code = .accepted,
    });
    try c.feed(connack);
    const event = (try c.poll(0)).?;
    try testing.expect(event == .connack);
    try testing.expectEqual(packet.ConnectReturnCode.accepted, event.connack.return_code);
    try testing.expectEqual(ConnectionState.connected, c.state);
    return c;
}

test "connect → connack accepted; refused codes disconnect" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    const c = try makeConnected(&tt, &rx, &tx);
    try testing.expectEqual(@as(usize, 0), c.pending_len);

    // Refused: fresh client, CONNACK rc=5 → event + .disconnected.
    var tt2 = TestTransport{};
    var rx2: [256]u8 = undefined;
    var tx2: [256]u8 = undefined;
    var c2 = Client.init(tt2.transport(), .{ .rx = &rx2, .tx = &tx2 });
    try c2.connect(0, .{ .client_id = "x" });
    var buf: [4]u8 = undefined;
    try c2.feed(try packet.encodeConnack(&buf, .{
        .session_present = false,
        .return_code = .not_authorized,
    }));
    const event = (try c2.poll(0)).?;
    try testing.expectEqual(packet.ConnectReturnCode.not_authorized, event.connack.return_code);
    try testing.expectEqual(ConnectionState.disconnected, c2.state);
    try testing.expectError(error.NotConnected, c2.publish(0, "t", "x", .{}));
    // ... but a re-connect from .disconnected is allowed.
    try c2.connect(1, .{ .client_id = "x" });
    try testing.expectEqual(ConnectionState.connecting, c2.state);
}

test "guards: not connected / already connected / invalid topic + filter" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx });

    try testing.expectError(error.NotConnected, c.publish(0, "t", "x", .{}));
    try testing.expectError(error.NotConnected, c.subscribe(0, &.{.{ .filter = "t" }}));
    try testing.expectError(error.NotConnected, c.pingreq(0));
    try testing.expectError(error.NotConnected, c.disconnect(0));

    try c.connect(0, .{ .client_id = "x" });
    try testing.expectError(error.AlreadyConnected, c.connect(0, .{ .client_id = "x" }));

    tt.reset();
    var buf: [4]u8 = undefined;
    try c.feed(try packet.encodeConnack(&buf, .{ .session_present = false, .return_code = .accepted }));
    _ = (try c.poll(0)).?;

    try testing.expectError(error.InvalidTopic, c.publish(0, "a/+", "x", .{}));
    try testing.expectError(error.InvalidFilter, c.subscribe(0, &.{.{ .filter = "a/#/b" }}));
    try testing.expectError(error.EmptyTopicList, c.subscribe(0, &.{}));
    try testing.expectError(error.InvalidFilter, c.unsubscribe(0, &.{"a/#/b"}));
}

test "QoS 0 publish: fire and forget, no packet id" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    const id = try c.publish(1, "a/b", "hi", .{});
    try testing.expectEqual(null, id);
    try testing.expectEqual(@as(usize, 0), c.pending_len);
    const sent = (try tt.lastPacket()).publish;
    try testing.expectEqualStrings("a/b", sent.topic);
    try testing.expectEqual(packet.QoS.at_most_once, sent.qos);
}

test "QoS 1 publish: PUBLISH → PUBACK releases the id; DUP retransmit" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    const id = (try c.publish(1, "a/b", "hi", .{ .qos = .at_least_once })).?;
    try testing.expectEqual(@as(u16, 1), id);
    try testing.expectEqual(@as(usize, 1), c.pending_len);
    const sent = (try tt.lastPacket()).publish;
    try testing.expectEqual(id, sent.packet_id);
    try testing.expect(!sent.dup);

    // No ack yet → caller retransmits with DUP, same id.
    tt.reset();
    try c.publishDup(2, id, "a/b", "hi", .{ .qos = .at_least_once });
    const again = (try tt.lastPacket()).publish;
    try testing.expect(again.dup);
    try testing.expectEqual(id, again.packet_id);

    // PUBACK → event, id released.
    var buf: [4]u8 = undefined;
    try c.feed(try packet.encodePuback(&buf, id));
    const event = (try c.poll(3)).?;
    try testing.expectEqual(id, event.puback);
    try testing.expectEqual(@as(usize, 0), c.pending_len);

    // Now the id is unknown: another DUP retransmit is refused ...
    try testing.expectError(
        error.InvalidPacketId,
        c.publishDup(4, id, "a/b", "hi", .{ .qos = .at_least_once }),
    );
    // ... and a stray second PUBACK is a protocol violation, not a panic.
    try c.feed(try packet.encodePuback(&buf, id));
    try testing.expectError(error.ProtocolViolation, c.poll(5));
}

test "QoS 2 publish: full PUBLISH → PUBREC → PUBREL → PUBCOMP handshake" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    const id = (try c.publish(1, "q2/t", "pay", .{ .qos = .exactly_once })).?;
    const sent = (try tt.lastPacket()).publish;
    try testing.expectEqual(packet.QoS.exactly_once, sent.qos);
    try testing.expectEqual(id, sent.packet_id);

    // Broker: PUBREC → client emits no event but sends PUBREL (flags 0b0010).
    tt.reset();
    var buf: [4]u8 = undefined;
    try c.feed(try packet.encodePubrec(&buf, id));
    try testing.expectEqual(null, try c.poll(2));
    try testing.expectEqualSlices(u8, &.{ 0x62, 0x02, 0x00, 0x01 }, tt.sent());
    try testing.expectEqual(@as(usize, 1), c.pending_len);

    // Broker: PUBCOMP → completion event, id released.
    tt.reset();
    try c.feed(try packet.encodePubcomp(&buf, id));
    const event = (try c.poll(3)).?;
    try testing.expectEqual(id, event.pubcomp);
    try testing.expectEqual(@as(usize, 0), c.pending_len);

    // PUBCOMP without PUBREC first would have been a violation:
    const id2 = (try c.publish(4, "q2/t", "pay", .{ .qos = .exactly_once })).?;
    try c.feed(try packet.encodePubcomp(&buf, id2));
    try testing.expectError(error.ProtocolViolation, c.poll(5));
}

test "subscribe → SUBACK with mixed granted QoS incl. 0x80 → message delivery" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    const id = try c.subscribe(1, &.{
        .{ .filter = "sport/#", .qos = .at_least_once },
        .{ .filter = "a/+" },
    });
    const sent = (try tt.lastPacket()).subscribe;
    try testing.expectEqual(id, sent.packet_id);
    var it = sent.iterator();
    try testing.expectEqualStrings("sport/#", it.next().?.filter);
    try testing.expectEqualStrings("a/+", it.next().?.filter);

    var buf: [16]u8 = undefined;
    try c.feed(try packet.encodeSuback(&buf, id, &.{ 0x01, 0x80 }));
    const acked = (try c.poll(2)).?;
    try testing.expectEqual(id, acked.suback.packet_id);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x80 }, acked.suback.codes);
    try testing.expectEqual(@as(usize, 0), c.pending_len);

    // Broker delivers a QoS 0 message on the subscription.
    tt.reset();
    var pbuf: [64]u8 = undefined;
    try c.feed(try packet.encodePublish(&pbuf, .{ .topic = "sport/tennis", .payload = "3:1" }));
    const event = (try c.poll(3)).?;
    try testing.expectEqualStrings("sport/tennis", event.message.topic);
    try testing.expectEqualStrings("3:1", event.message.payload);
    try testing.expectEqual(packet.QoS.at_most_once, event.message.qos);
    try testing.expectEqual(@as(usize, 0), tt.len); // QoS 0: nothing to ack

    // Unsubscribe round-trip.
    const uid = try c.unsubscribe(4, &.{"sport/#"});
    try c.feed(try packet.encodeUnsuback(&buf, uid));
    try testing.expectEqual(uid, (try c.poll(5)).?.unsuback);
}

test "QoS 1 receive: message delivered and PUBACK sent automatically" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);
    tt.reset();

    var pbuf: [64]u8 = undefined;
    try c.feed(try packet.encodePublish(&pbuf, .{
        .topic = "a/b",
        .payload = "hi",
        .qos = .at_least_once,
        .packet_id = 7,
    }));
    const event = (try c.poll(1)).?;
    try testing.expectEqualStrings("a/b", event.message.topic);
    try testing.expectEqual(@as(u16, 7), event.message.packet_id);
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x02, 0x00, 0x07 }, tt.sent());
}

test "QoS 2 receive: exactly-once delivery with DUP suppression" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);
    tt.reset();

    var pbuf: [64]u8 = undefined;
    const original = try packet.encodePublish(&pbuf, .{
        .topic = "a",
        .payload = "x",
        .qos = .exactly_once,
        .packet_id = 9,
    });
    try c.feed(original);
    const event = (try c.poll(1)).?;
    try testing.expect(event == .message);
    try testing.expectEqualSlices(u8, &.{ 0x50, 0x02, 0x00, 0x09 }, tt.sent()); // PUBREC
    try testing.expectEqual(@as(usize, 1), c.inbound_len);

    // Broker re-sends the same id with DUP: no second delivery, PUBREC again.
    tt.reset();
    var dbuf: [64]u8 = undefined;
    try c.feed(try packet.encodePublish(&dbuf, .{
        .topic = "a",
        .payload = "x",
        .qos = .exactly_once,
        .packet_id = 9,
        .dup = true,
    }));
    try testing.expectEqual(null, try c.poll(2));
    try testing.expectEqualSlices(u8, &.{ 0x50, 0x02, 0x00, 0x09 }, tt.sent());

    // PUBREL → PUBCOMP, id forgotten.
    tt.reset();
    var buf: [4]u8 = undefined;
    try c.feed(try packet.encodePubrel(&buf, 9));
    try testing.expectEqual(null, try c.poll(3));
    try testing.expectEqualSlices(u8, &.{ 0x70, 0x02, 0x00, 0x09 }, tt.sent());
    try testing.expectEqual(@as(usize, 0), c.inbound_len);
}

test "multiple packets in one feed are polled in order" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    const id_a = (try c.publish(1, "x", "1", .{ .qos = .at_least_once })).?;
    const id_b = (try c.publish(2, "x", "2", .{ .qos = .at_least_once })).?;
    try testing.expect(id_a != id_b);

    var buf: [8]u8 = undefined;
    _ = try packet.encodePuback(buf[0..4], id_a);
    _ = try packet.encodePuback(buf[4..8], id_b);
    try c.feed(&buf);
    try testing.expectEqual(id_a, (try c.poll(3)).?.puback);
    try testing.expectEqual(id_b, (try c.poll(3)).?.puback);
    try testing.expectEqual(null, try c.poll(3));

    // Split feed: a packet arriving byte-by-byte decodes once complete.
    const id_c = (try c.publish(4, "x", "3", .{ .qos = .at_least_once })).?;
    var pb: [4]u8 = undefined;
    const ack = try packet.encodePuback(&pb, id_c);
    for (ack) |b| {
        try testing.expectEqual(null, try c.poll(5)); // still incomplete
        try c.feed(&.{b});
    }
    try testing.expectEqual(id_c, (try c.poll(5)).?.puback);
}

test "keep-alive: tick sends PINGREQ, PINGRESP clears, silence times out" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx); // keep_alive_s = 60
    tt.reset();

    // Idle less than the interval: nothing sent.
    try c.tick(59_999);
    try testing.expectEqual(@as(usize, 0), tt.len);

    // A full interval of send silence → PINGREQ.
    try c.tick(60_000);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0x00 }, tt.sent());

    // PINGRESP clears the outstanding ping.
    try c.feed(&.{ 0xD0, 0x00 });
    try testing.expect((try c.poll(60_001)).? == .pingresp);

    // Next ping goes unanswered for a full interval → timeout.
    tt.reset();
    try c.tick(120_001);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0x00 }, tt.sent());
    try c.tick(150_000); // waiting, not yet timed out
    try testing.expectError(error.KeepAliveTimeout, c.tick(180_001));

    // Publishing counts as send activity: no premature ping. Reconnect via
    // a fresh client state (disconnect + connect + connack).
    try c.disconnect(180_002);
    try testing.expectEqual(ConnectionState.disconnected, c.state);
}

test "packet id pool: wraps 65535 → 1 and skips in-flight ids" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    c.next_packet_id = std.math.maxInt(u16);
    const a = (try c.publish(1, "t", "x", .{ .qos = .at_least_once })).?;
    try testing.expectEqual(@as(u16, 65535), a);
    const b = (try c.publish(2, "t", "x", .{ .qos = .at_least_once })).?;
    try testing.expectEqual(@as(u16, 1), b); // wrapped, skipped 0

    // Wrap again while 65535 and 1 are still in flight: both are skipped.
    c.next_packet_id = std.math.maxInt(u16);
    const d = (try c.publish(3, "t", "x", .{ .qos = .at_least_once })).?;
    try testing.expectEqual(@as(u16, 2), d);
    try testing.expectEqual(@as(usize, 3), c.pending_len);
}

test "packet id pool: bounded — exhaustion is a typed error" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    for (0..max_in_flight) |_| {
        _ = (try c.publish(1, "t", "x", .{ .qos = .at_least_once })).?;
    }
    try testing.expectEqual(@as(usize, max_in_flight), c.pending_len);
    try testing.expectError(
        error.TooManyInFlight,
        c.publish(2, "t", "x", .{ .qos = .at_least_once }),
    );
    // Ack one → a slot frees up.
    var buf: [4]u8 = undefined;
    try c.feed(try packet.encodePuback(&buf, 1));
    _ = (try c.poll(3)).?;
    _ = (try c.publish(4, "t", "x", .{ .qos = .at_least_once })).?;
}

test "hostile broker bytes: typed errors, never a panic" {
    var tt = TestTransport{};
    var rx: [512]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected(&tt, &rx, &tx);

    // Reserved packet type.
    try c.feed(&.{ 0xF0, 0x00 });
    try testing.expectError(error.UnknownPacketType, c.poll(1));
    c.resetRx(); // caller tears down; drop the poisoned buffer

    // Server-to-client CONNECT / SUBSCRIBE / PINGREQ are violations.
    var buf: [64]u8 = undefined;
    try c.feed(try packet.encodeConnect(&buf, .{ .client_id = "evil" }));
    try testing.expectError(error.ProtocolViolation, c.poll(2));
    c.resetRx();
    try c.feed(&.{ 0xC0, 0x00 });
    try testing.expectError(error.ProtocolViolation, c.poll(3));
    c.resetRx();

    // Overlong remaining length.
    try c.feed(&.{ 0x30, 0x80, 0x80, 0x80, 0x80, 0x01 });
    try testing.expectError(error.MalformedRemainingLength, c.poll(4));
    c.resetRx();

    // Unknown-id acks.
    try c.feed(try packet.encodePubrec(buf[0..4], 42));
    try testing.expectError(error.ProtocolViolation, c.poll(5));
    c.resetRx();

    // Random garbage sweep through the client's own poll path.
    var prng = std.Random.DefaultPrng.init(0xB40C43);
    const random = prng.random();
    var junk: [64]u8 = undefined;
    for (0..1000) |_| {
        const len = random.uintAtMost(usize, junk.len);
        random.bytes(junk[0..len]);
        c.resetRx();
        c.feed(junk[0..len]) catch continue;
        while (c.poll(6) catch null) |_| {}
    }
}

test "rx buffer is bounded: overflow is a typed error" {
    var tt = TestTransport{};
    var rx: [8]u8 = undefined;
    var tx: [64]u8 = undefined;
    var c = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx });
    try c.feed(&.{ 0x30, 0x40, 0x00, 0x01 });
    try testing.expectError(error.RxBufferFull, c.feed(&.{ 0, 0, 0, 0, 0 }));
}

test "TcpTransport compiles (never dialed in tests)" {
    // Reference-only: forces semantic analysis of the std.Io.net adapter.
    std.testing.refAllDecls(TcpTransport);
}
