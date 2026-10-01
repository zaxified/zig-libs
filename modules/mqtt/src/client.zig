// SPDX-License-Identifier: MIT

//! MQTT 3.1.1 / 5.0 client state machine over a caller-provided transport seam.
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
//! MQTT 5.0 (`Connect.version = .v5`): every packet carries the properties
//! and reason codes of the codec (`packet`). The client keeps to what the
//! server's CONNACK allows — Maximum QoS, Retain Available, Receive Maximum
//! (the send quota of 4.9), Maximum Packet Size, Topic Alias Maximum, Server
//! Keep Alive (`serverLimits`) — and announces what it can hold itself
//! (`connect`). Inbound Topic Aliases resolve through caller-provided slots
//! (`Buffers.topic_aliases`); outbound ones are the caller's choice, per
//! publish. Extended authentication is caller-driven: AUTH packets surface
//! as `Event.auth` and go out through `auth`. A server's DISCONNECT is
//! `Event.disconnect`.
//!
//! Session state is reset on `connect`; replaying unacknowledged QoS
//! messages into a resumed session (clean_session = false) is the caller's
//! job — the client does not buffer payloads.
//!
//! Provenance: clean-room from the OASIS MQTT 3.1.1 and 5.0 specifications;
//! mosquitto/Paho referenced for behavior only, no source consulted or
//! copied.

const std = @import("std");
const packet = @import("packet.zig");
const topic_rules = @import("topic.zig");

/// Failures a `Transport` implementation may report.
pub const TransportError = error{
    TransportFailed,
    /// The blocking operation was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`). Surfaced instead of `TransportFailed` so a
    /// caller can tell a canceled wait from a real transport failure.
    Canceled,
};

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
    /// Under 5.0 a Topic Alias is already resolved into this.
    topic: []const u8,
    payload: []const u8,
    qos: packet.QoS,
    retain: bool,
    dup: bool,
    /// 0 for QoS 0.
    packet_id: u16,
    /// 5.0 PUBLISH properties — Message Expiry Interval (the time left),
    /// Response Topic, Correlation Data, User Properties, Subscription
    /// Identifiers, Content Type, Payload Format. Empty under 3.1.1.
    properties: packet.Properties = .{},
};

/// Events surfaced by `poll`. Slice fields point into the receive buffer —
/// valid only until the next `feed` / `poll` call.
pub const Event = union(enum) {
    /// CONNACK arrived; on success (3.1.1 `.accepted`, 5.0 reason 0x00) the
    /// client is now `.connected`, and under 5.0 the server's limits in its
    /// properties are applied (`serverLimits`).
    connack: packet.Connack,
    /// Application message received (all QoS acks already handled).
    message: Message,
    /// QoS 1 publish acknowledged; the packet id has been released. Under
    /// 5.0 a `reason_code` of 0x80 or above is the server refusing the
    /// message — acknowledged all the same, never to be resent (4.4.0-2).
    puback: packet.Ack,
    /// QoS 2 publish finished, the id released: its PUBCOMP, or under 5.0 a
    /// PUBREC whose `reason_code` (0x80 or above) refuses the message, which
    /// ends the handshake there.
    pubcomp: packet.Ack,
    /// Subscribe acknowledged; one code per filter (3.1.1: 0/1/2 or 0x80;
    /// 5.0: a SUBACK reason code).
    suback: packet.Suback,
    /// Unsubscribe acknowledged; 5.0 adds one reason code per filter.
    unsuback: packet.Unsuback,
    pingresp,
    /// 5.0: the server closed the connection and says why (`reason_code`,
    /// maybe a Reason String or a Server Reference). The client is now
    /// `.disconnected`.
    disconnect: packet.Disconnect,
    /// 5.0 extended authentication: the server's AUTH — a challenge while
    /// connecting (`continue_authentication`) or re-authentication. Answer
    /// with `auth`.
    auth: packet.Auth,
};

/// Upper bound on simultaneously outstanding packet ids (either direction).
pub const max_in_flight = 64;

/// Longest topic a Topic Alias slot holds (5.0). A server that aliases a
/// longer topic gets `error.TopicAliasInvalid` — the client cannot keep it.
pub const alias_topic_capacity = 256;

/// One inbound Topic Alias mapping (5.0 spec 3.3.2.3.4), in caller-provided
/// storage (`Buffers.topic_aliases`): alias N lives in slot N-1.
pub const AliasSlot = struct {
    topic: [alias_topic_capacity]u8 = undefined,
    len: usize = 0,
    set: bool = false,
};

/// What a 5.0 server's CONNACK said it supports. The defaults are the spec's
/// for an absent property — and all that 3.1.1 ever has.
pub const ServerLimits = struct {
    /// QoS 1/2 publishes the server takes unacknowledged at once (4.9).
    receive_maximum: u16 = std.math.maxInt(u16),
    maximum_qos: packet.QoS = .exactly_once,
    retain_available: bool = true,
    maximum_packet_size: u32 = std.math.maxInt(u32),
    /// Highest Topic Alias the server accepts from this client; 0 = none.
    topic_alias_maximum: u16 = 0,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
};

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
    /// 5.0: a publish above the server's Maximum QoS (3.2.2-11).
    QosNotSupported,
    /// 5.0: a retained publish to a server without Retain Available (3.2.2-14).
    RetainNotSupported,
    /// 5.0: the server's Receive Maximum of QoS 1/2 publishes are
    /// unacknowledged (3.3.4-7); retry after the next `puback` / `pubcomp`.
    ReceiveMaximumReached,
    /// 5.0: an outbound Topic Alias above the server's maximum, or an inbound
    /// one that is 0, above ours, unset, or names a topic too long to keep.
    TopicAliasInvalid,
} || packet.DecodeError || packet.EncodeError || TransportError;

/// MQTT 3.1.1 / 5.0 client. Allocation-free: hand it a receive buffer (must
/// hold the largest expected incoming packet) and a transmit scratch buffer
/// (must hold the largest packet you send). The version is the one
/// `connect` is given.
pub const Client = struct {
    transport: Transport,
    tx_buf: []u8,
    rx_buf: []u8,
    rx_len: usize = 0,
    rx_consumed: usize = 0,

    state: ConnectionState = .idle,
    version: packet.Version = .v3_1_1,
    keep_alive_ms: u64 = 0,
    last_tx: u64 = 0,
    awaiting_pingresp: bool = false,
    ping_sent: u64 = 0,

    /// What the server's CONNACK allows (5.0); defaults under 3.1.1.
    server: ServerLimits = .{},
    /// Inbound Topic Alias storage, and the maximum this connection
    /// announced (never more than `aliases.len`).
    aliases: []AliasSlot = &.{},
    alias_max: u16 = 0,

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

    pub const Buffers = struct {
        rx: []u8,
        tx: []u8,
        /// 5.0 only: room for the Topic Aliases the server may use toward
        /// this client. Empty (default) = the client accepts none.
        topic_aliases: []AliasSlot = &.{},
    };

    pub fn init(transport: Transport, buffers: Buffers) Client {
        return .{ .transport = transport, .rx_buf = buffers.rx, .tx_buf = buffers.tx, .aliases = buffers.topic_aliases };
    }

    pub const PublishOptions = struct {
        qos: packet.QoS = .at_most_once,
        retain: bool = false,
        /// 5.0 PUBLISH properties: Message Expiry Interval, Response Topic,
        /// Correlation Data, User Properties, Content Type, Payload Format,
        /// a Topic Alias (with `topic` empty to use an alias already set).
        /// No Subscription Identifier — a client must not send one.
        properties: packet.Properties = .{},
    };

    /// What the server's CONNACK allows (5.0).
    pub fn serverLimits(c: *const Client) ServerLimits {
        return c.server;
    }

    // ── outgoing API ────────────────────────────────────────────────────────

    /// Send CONNECT at `options.version` and reset all session state. The
    /// broker's answer surfaces later as an `Event.connack` from `poll`.
    ///
    /// Under 5.0 three properties are filled in when not given, so the server
    /// stays within what this client can hold: Receive Maximum =
    /// `max_in_flight` (the inbound QoS 2 window), Maximum Packet Size = the
    /// receive buffer, Topic Alias Maximum = the alias slots. A larger value
    /// than the client can honour is `error.InvalidProperty`.
    pub fn connect(c: *Client, now: u64, options: packet.Connect) Error!void {
        switch (c.state) {
            .connecting, .connected => return error.AlreadyConnected,
            .idle, .disconnected => {},
        }
        var opts = options;
        var alias_max: u16 = 0;
        if (opts.version == .v5) {
            const p = &opts.properties;
            if (p.receive_maximum) |rm| {
                if (rm > max_in_flight) return error.InvalidProperty;
            } else p.receive_maximum = max_in_flight;
            if (p.maximum_packet_size) |m| {
                if (m > c.rx_buf.len) return error.InvalidProperty;
            } else p.maximum_packet_size = @intCast(@min(c.rx_buf.len, std.math.maxInt(u32)));
            const slots: u16 = @intCast(@min(c.aliases.len, std.math.maxInt(u16)));
            if (p.topic_alias_maximum) |m| {
                if (m > slots) return error.InvalidProperty;
            } else if (slots > 0) p.topic_alias_maximum = slots;
            alias_max = p.topic_alias_maximum orelse 0;
        }
        const bytes = try packet.encodeConnect(c.tx_buf, opts);
        c.pending_len = 0;
        c.inbound_len = 0;
        c.awaiting_pingresp = false;
        c.rx_len = 0;
        c.rx_consumed = 0;
        c.server = .{};
        c.version = opts.version;
        c.alias_max = alias_max;
        for (c.aliases) |*a| a.set = false;
        try c.send(now, bytes);
        c.state = .connecting;
        c.keep_alive_ms = @as(u64, opts.keep_alive_s) * std.time.ms_per_s;
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
        try c.checkPublish(topic_name, options);
        if (options.qos != .at_most_once and c.publishesInFlight() >= c.server.receive_maximum) {
            return error.ReceiveMaximumReached;
        }
        var id: u16 = 0;
        if (options.qos != .at_most_once) {
            id = try c.allocPacketId(switch (options.qos) {
                .at_least_once => .publish_qos1,
                .exactly_once => .publish_await_pubrec,
                .at_most_once => unreachable,
            });
        }
        errdefer if (id != 0) c.removePending(id);
        try c.sendPublish(now, .{
            .topic = topic_name,
            .payload = payload,
            .qos = options.qos,
            .retain = options.retain,
            .packet_id = id,
            .properties = options.properties,
        });
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
        try c.checkPublish(topic_name, options);
        try c.sendPublish(now, .{
            .topic = topic_name,
            .payload = payload,
            .qos = options.qos,
            .retain = options.retain,
            .dup = true,
            .packet_id = packet_id,
            .properties = options.properties,
        });
    }

    /// Send SUBSCRIBE; returns the packet id the SUBACK will carry. Under 5.0
    /// each `Subscription` may also set No Local, Retain As Published and
    /// Retain Handling.
    pub fn subscribe(c: *Client, now: u64, filters: []const packet.Subscription) Error!u16 {
        return c.subscribeWith(now, filters, .{});
    }

    /// `subscribe` with 5.0 SUBSCRIBE properties: a Subscription Identifier
    /// (echoed on every message these filters deliver) and User Properties.
    pub fn subscribeWith(c: *Client, now: u64, filters: []const packet.Subscription, properties: packet.Properties) Error!u16 {
        if (c.state != .connected) return error.NotConnected;
        if (filters.len == 0) return error.EmptyTopicList;
        for (filters) |f| topic_rules.validateFilter(f.filter) catch return error.InvalidFilter;
        const id = try c.allocPacketId(.subscribe);
        errdefer c.removePending(id);
        const bytes = try packet.encodePacket(c.tx_buf, c.version, .{ .subscribe = .{ .packet_id = id, .filters = filters, .properties = properties } });
        try c.send(now, bytes);
        return id;
    }

    /// Send UNSUBSCRIBE; returns the packet id the UNSUBACK will carry.
    pub fn unsubscribe(c: *Client, now: u64, filters: []const []const u8) Error!u16 {
        return c.unsubscribeWith(now, filters, .{});
    }

    /// `unsubscribe` with 5.0 UNSUBSCRIBE properties (User Properties).
    pub fn unsubscribeWith(c: *Client, now: u64, filters: []const []const u8, properties: packet.Properties) Error!u16 {
        if (c.state != .connected) return error.NotConnected;
        if (filters.len == 0) return error.EmptyTopicList;
        for (filters) |f| topic_rules.validateFilter(f) catch return error.InvalidFilter;
        const id = try c.allocPacketId(.unsubscribe);
        errdefer c.removePending(id);
        const bytes = try packet.encodePacket(c.tx_buf, c.version, .{ .unsubscribe = .{ .packet_id = id, .filters = filters, .properties = properties } });
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
        return c.disconnectWith(now, .{});
    }

    /// DISCONNECT with a 5.0 reason code and properties — e.g.
    /// `disconnect_with_will_message` so the server publishes the Will
    /// anyway, or a Session Expiry Interval that replaces the CONNECT's.
    pub fn disconnectWith(c: *Client, now: u64, d: packet.Disconnect) Error!void {
        switch (c.state) {
            .connected, .connecting => {},
            .idle, .disconnected => return error.NotConnected,
        }
        const bytes = try packet.encodePacket(c.tx_buf, c.version, .{ .disconnect = d });
        try c.send(now, bytes);
        c.state = .disconnected;
    }

    /// Send a 5.0 AUTH: the next step of extended authentication while
    /// connecting, or re-authentication (`re_authenticate`) once connected.
    pub fn auth(c: *Client, now: u64, a: packet.Auth) Error!void {
        switch (c.state) {
            .connected, .connecting => {},
            .idle, .disconnected => return error.NotConnected,
        }
        const bytes = try packet.encodePacket(c.tx_buf, c.version, .{ .auth = a });
        try c.send(now, bytes);
    }

    /// Keep-alive driver — call periodically with the current monotonic
    /// time in ms. Sends PINGREQ once the link has been send-idle for a
    /// full keep-alive interval; errors with `KeepAliveTimeout` when a
    /// PINGREQ goes unanswered for another full interval. Under 5.0 the
    /// interval is the server's Server Keep Alive when it sent one (3.1.2-21).
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

    /// How many bytes `feed` takes now: the receive buffer's room once what
    /// `poll` consumed is compacted away. Feed at most this much, `poll`, and
    /// feed the rest. 0 with nothing left to poll means an incomplete packet
    /// as large as the buffer: it can never complete, so drop the connection.
    pub fn rxRoom(c: *const Client) usize {
        return c.rx_buf.len - (c.rx_len -| c.rx_consumed);
    }

    /// Decode buffered broker packets, advance the QoS state machines
    /// (sending PUBACK/PUBREC/PUBREL/PUBCOMP as needed) and return the next
    /// application-visible event, or null once no complete packet remains.
    ///
    /// Slices inside the returned event point into the receive buffer and
    /// are valid only until the next `feed` / `poll` call. A decode error
    /// leaves the buffer untouched; the connection should be torn down and
    /// re-`connect`ed (under 5.0 after a DISCONNECT carrying
    /// `packet.reasonForDecodeError`).
    pub fn poll(c: *Client, now: u64) Error!?Event {
        while (true) {
            c.compact();
            const dec = (try packet.decodePacket(c.rx_buf[0..c.rx_len], c.version)) orelse return null;
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

    /// Hold an outbound PUBLISH to the topic rules and, under 5.0, to what
    /// the server's CONNACK allows.
    fn checkPublish(c: *const Client, topic_name: []const u8, o: PublishOptions) Error!void {
        // 5.0: an empty topic is a Topic Alias already set (3.3.2.3.4).
        const alias_only = topic_name.len == 0 and o.properties.topic_alias != null;
        if (!alias_only) topic_rules.validateName(topic_name) catch return error.InvalidTopic;
        if (c.version != .v5) return;
        if (@intFromEnum(o.qos) > @intFromEnum(c.server.maximum_qos)) return error.QosNotSupported;
        if (o.retain and !c.server.retain_available) return error.RetainNotSupported;
        if (!o.properties.subscription_ids.isEmpty()) return error.InvalidProperty; // 3.3.4-6
        if (o.properties.topic_alias) |a| if (a > c.server.topic_alias_maximum) return error.TopicAliasInvalid;
    }

    fn sendPublish(c: *Client, now: u64, p: packet.Publish) Error!void {
        if (try packet.packetWireLen(c.version, .{ .publish = p }) > c.server.maximum_packet_size) {
            return error.PacketTooLarge; // 3.2.2-15
        }
        const bytes = try packet.encodePacket(c.tx_buf, c.version, .{ .publish = p });
        try c.send(now, bytes);
    }

    fn sendAck(c: *Client, now: u64, comptime kind: packet.PacketType, id: u16, reason: packet.ReasonCode) Error!void {
        const ack = packet.Ack{ .packet_id = id, .reason_code = reason };
        const bytes = try packet.encodePacket(c.tx_buf, c.version, @unionInit(packet.Packet, @tagName(kind), ack));
        try c.send(now, bytes);
    }

    /// QoS 1/2 publishes not yet acknowledged — the send quota of 4.9.
    fn publishesInFlight(c: *const Client) usize {
        var n: usize = 0;
        for (c.pending[0..c.pending_len]) |e| switch (e.kind) {
            .publish_qos1, .publish_await_pubrec, .publish_await_pubcomp => n += 1,
            .subscribe, .unsubscribe => {},
        };
        return n;
    }

    fn applyConnack(c: *Client, p: packet.Properties) void {
        c.server = .{
            .receive_maximum = p.receive_maximum orelse std.math.maxInt(u16),
            .maximum_qos = p.maximum_qos orelse .exactly_once,
            .retain_available = p.retain_available orelse true,
            .maximum_packet_size = p.maximum_packet_size orelse std.math.maxInt(u32),
            .topic_alias_maximum = p.topic_alias_maximum orelse 0,
            .wildcard_subscription_available = p.wildcard_subscription_available orelse true,
            .subscription_identifier_available = p.subscription_identifier_available orelse true,
            .shared_subscription_available = p.shared_subscription_available orelse true,
        };
        if (p.server_keep_alive) |ka| c.keep_alive_ms = @as(u64, ka) * std.time.ms_per_s;
    }

    /// The topic an inbound PUBLISH names: its own, after recording it under
    /// its alias, or the one its alias was set to (5.0 3.3.2.3.4).
    fn resolveAlias(c: *Client, alias: u16, topic_name: []const u8) Error![]const u8 {
        if (alias == 0 or alias > c.alias_max or alias > c.aliases.len) return error.TopicAliasInvalid;
        const slot = &c.aliases[alias - 1];
        if (topic_name.len == 0) {
            if (!slot.set) return error.TopicAliasInvalid;
            return slot.topic[0..slot.len];
        }
        if (topic_name.len > slot.topic.len) return error.TopicAliasInvalid;
        @memcpy(slot.topic[0..topic_name.len], topic_name);
        slot.len = topic_name.len;
        slot.set = true;
        return topic_name;
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
        switch (p) {
            .connack => |ca| {
                if (c.state != .connecting) return error.ProtocolViolation;
                const ok = if (c.version == .v5) ca.reason_code == .success else ca.return_code == .accepted;
                c.state = if (ok) .connected else .disconnected;
                if (ok and c.version == .v5) c.applyConnack(ca.properties);
                return .{ .connack = ca };
            },
            // AUTH comes before the CONNACK (a challenge) or after it
            // (re-authentication); the codec refuses it under 3.1.1.
            .auth => |a| {
                if (c.state != .connecting and c.state != .connected) return error.ProtocolViolation;
                return .{ .auth = a };
            },
            else => {},
        }
        if (c.state != .connected) return error.ProtocolViolation;

        switch (p) {
            .connack, .auth => unreachable,
            // A server never sends these to a client.
            .connect, .subscribe, .unsubscribe, .pingreq => return error.ProtocolViolation,
            .disconnect => |d| {
                // 3.1.1 has no server-sent DISCONNECT; 5.0 does (3.14).
                if (c.version != .v5) return error.ProtocolViolation;
                c.state = .disconnected;
                return .{ .disconnect = d };
            },
            .publish => |incoming| {
                const topic_name = if (incoming.properties.topic_alias) |a|
                    try c.resolveAlias(a, incoming.topic)
                else
                    incoming.topic;
                const msg = Message{
                    .topic = topic_name,
                    .payload = incoming.payload,
                    .qos = incoming.qos,
                    .retain = incoming.retain,
                    .dup = incoming.dup,
                    .packet_id = incoming.packet_id,
                    .properties = incoming.properties,
                };
                switch (incoming.qos) {
                    .at_most_once => return .{ .message = msg },
                    .at_least_once => {
                        try c.sendAck(now, .puback, incoming.packet_id, .success);
                        return .{ .message = msg };
                    },
                    .exactly_once => {
                        const duplicate = c.hasInbound(incoming.packet_id);
                        if (!duplicate) try c.addInbound(incoming.packet_id);
                        try c.sendAck(now, .pubrec, incoming.packet_id, .success);
                        return if (duplicate) null else .{ .message = msg };
                    },
                }
            },
            .puback => |ack| {
                if (c.pendingKind(ack.packet_id) != .publish_qos1) return error.ProtocolViolation;
                c.removePending(ack.packet_id);
                return .{ .puback = ack };
            },
            .pubrec => |ack| {
                if (c.pendingKind(ack.packet_id) != .publish_await_pubrec) return error.ProtocolViolation;
                // 5.0: a refusing PUBREC ends the handshake (4.3.3, 4.4.0-2).
                if (ack.reason_code.isError()) {
                    c.removePending(ack.packet_id);
                    return .{ .pubcomp = ack };
                }
                c.setPendingKind(ack.packet_id, .publish_await_pubcomp);
                try c.sendAck(now, .pubrel, ack.packet_id, .success);
                return null;
            },
            .pubcomp => |ack| {
                if (c.pendingKind(ack.packet_id) != .publish_await_pubcomp) return error.ProtocolViolation;
                c.removePending(ack.packet_id);
                return .{ .pubcomp = ack };
            },
            .pubrel => |ack| {
                // Always answer PUBREL with PUBCOMP (spec 4.3.3), even for
                // an id we no longer remember — under 5.0 saying so.
                const known = c.removeInbound(ack.packet_id);
                try c.sendAck(now, .pubcomp, ack.packet_id, if (known or c.version != .v5) .success else .packet_identifier_not_found);
                return null;
            },
            .suback => |sa| {
                if (c.pendingKind(sa.packet_id) != .subscribe) return error.ProtocolViolation;
                c.removePending(sa.packet_id);
                return .{ .suback = sa };
            },
            .unsuback => |ua| {
                if (c.pendingKind(ua.packet_id) != .unsubscribe) return error.ProtocolViolation;
                c.removePending(ua.packet_id);
                return .{ .unsuback = ua };
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

    fn removeInbound(c: *Client, id: u16) bool {
        const i = std.mem.indexOfScalar(u16, c.inbound_qos2[0..c.inbound_len], id) orelse return false;
        c.inbound_len -= 1;
        c.inbound_qos2[i] = c.inbound_qos2[c.inbound_len];
        return true;
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
        sw.interface.writeAll(bytes) catch return writeFailure(&sw);
        sw.interface.flush() catch return writeFailure(&sw);
    }

    /// Read whatever bytes are available (blocking for at least one);
    /// hand them to `Client.feed`.
    ///
    /// This used to be a raw `std.posix.read` on the socket handle — which
    /// is *not* a registered `std.Io` operation, so `Future.cancel` cannot
    /// reach a thread parked in it at all (worse than a raw `poll`: that at
    /// least gets a signal that restarts it; this gets nothing). Routing the
    /// read through `std.Io.net.Stream.Reader.fillMore` — one underlying
    /// read, buffered straight into the caller's own `buf` since it is used
    /// as the reader's backing storage — makes the wait a real cancellation
    /// point while keeping the "one read, partial fill is fine" contract.
    pub fn readSome(t: *TcpTransport, buf: []u8) TransportError!usize {
        var sr = t.stream.reader(t.io, buf);
        sr.interface.fillMore() catch |e| switch (e) {
            error.EndOfStream => return 0,
            error.ReadFailed => return readFailure(&sr),
        };
        return sr.interface.bufferedLen();
    }

    /// Distinguish a canceled wait from a genuine read failure. `Io.Reader`'s
    /// error set cannot carry `Canceled`; the concrete reader records it here.
    fn readFailure(sr: *std.Io.net.Stream.Reader) TransportError {
        if (sr.err) |e| if (e == error.Canceled) return error.Canceled;
        return error.TransportFailed;
    }

    /// The writer side of `readFailure`.
    fn writeFailure(sw: *std.Io.net.Stream.Writer) TransportError {
        if (sw.err) |e| if (e == error.Canceled) return error.Canceled;
        return error.TransportFailed;
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
    try testing.expectEqual(id, event.puback.packet_id);
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
    try testing.expectEqual(id, event.pubcomp.packet_id);
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
    try testing.expectEqual(uid, (try c.poll(5)).?.unsuback.packet_id);
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
    try testing.expectEqual(id_a, (try c.poll(3)).?.puback.packet_id);
    try testing.expectEqual(id_b, (try c.poll(3)).?.puback.packet_id);
    try testing.expectEqual(null, try c.poll(3));

    // Split feed: a packet arriving byte-by-byte decodes once complete.
    const id_c = (try c.publish(4, "x", "3", .{ .qos = .at_least_once })).?;
    var pb: [4]u8 = undefined;
    const ack = try packet.encodePuback(&pb, id_c);
    for (ack) |b| {
        try testing.expectEqual(null, try c.poll(5)); // still incomplete
        try c.feed(&.{b});
    }
    try testing.expectEqual(id_c, (try c.poll(5)).?.puback.packet_id);
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
    try testing.expectEqual(@as(usize, 8), c.rxRoom());
    try c.feed(&.{ 0x30, 0x40, 0x00, 0x01 });
    try testing.expectEqual(@as(usize, 4), c.rxRoom());
    try testing.expectError(error.RxBufferFull, c.feed(&.{ 0, 0, 0, 0, 0 }));
    try c.feed(&.{ 0, 0, 0, 0 });
    try testing.expectEqual(@as(usize, 0), c.rxRoom());
}

test "TcpTransport compiles (never dialed in tests)" {
    // Reference-only: forces semantic analysis of the std.Io.net adapter.
    std.testing.refAllDecls(TcpTransport);
}

// ── cancellation ─────────────────────────────────────────────────────────
//
// `Future.cancel` unblocks a thread parked in `TcpTransport.readSome`, but
// only because `readSome` now routes through `std.Io.net.Stream.Reader`
// instead of a raw `std.posix.read` (see the comment on `readSome`) — and
// even then the reason is erased on the way out unless the concrete reader's
// out-of-band `err` field is inspected first. This test runs against a
// listener that accepts and then never writes, so the read really is parked
// when the cancel arrives.

fn acceptOne(server: *std.Io.net.Server, io: std.Io) std.Io.net.Server.AcceptError!std.Io.net.Stream {
    return server.accept(io);
}

/// The blocking call under test, on its own thread so it can be canceled.
fn readSomeOnce(t: *TcpTransport, buf: []u8) TransportError!usize {
    return t.readSome(buf);
}

test "a canceled readSome surfaces Canceled, not TransportFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = addr.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("loopback listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer server.deinit(io);

    var accept_fut = try io.concurrent(acceptOne, .{ &server, io });
    var t = TcpTransport.connect(io, server.socket.address) catch |err| {
        if (accept_fut.cancel(io)) |s| s.close(io) else |_| {}
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer t.close();
    var peer = try accept_fut.await(io);
    defer peer.close(io);

    var buf: [64]u8 = undefined;
    var fut = try io.concurrent(readSomeOnce, .{ &t, &buf });
    // Long enough that the read is certainly parked in the kernel.
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

// ── MQTT 5.0 ────────────────────────────────────────────────────────────────

/// The single 5.0 packet the client wrote since the last reset.
fn lastPacket5(tt: *const TestTransport) !packet.Packet {
    const dec = (try packet.decodePacket(tt.sent(), .v5)).?;
    try testing.expectEqual(tt.len, dec.consumed);
    return dec.packet;
}

/// Feed the client one 5.0 packet from the fake server.
fn feed5(c: *Client, p: packet.Packet) !void {
    var buf: [512]u8 = undefined;
    try c.feed(try packet.encodePacket(&buf, .v5, p));
}

fn makeConnected5(tt: *TestTransport, rx: []u8, tx: []u8, aliases: []AliasSlot, server: packet.Properties) !Client {
    var c = Client.init(tt.transport(), .{ .rx = rx, .tx = tx, .topic_aliases = aliases });
    try c.connect(0, .{ .client_id = "v5", .keep_alive_s = 60, .version = .v5 });
    tt.reset();
    try feed5(&c, .{ .connack = .{ .session_present = false, .properties = server } });
    const ev = (try c.poll(0)).?;
    try testing.expectEqual(packet.ReasonCode.success, ev.connack.reason_code);
    try testing.expectEqual(ConnectionState.connected, c.state);
    return c;
}

test "v5 connect: the client announces what it can hold, and refuses to promise more" {
    var tt = TestTransport{};
    var rx: [300]u8 = undefined;
    var tx: [256]u8 = undefined;
    var slots: [3]AliasSlot = .{ .{}, .{}, .{} };
    var c = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx, .topic_aliases = &slots });
    try c.connect(0, .{ .client_id = "x", .version = .v5 });
    const p = (try lastPacket5(&tt)).connect;
    try testing.expectEqual(packet.Version.v5, p.version);
    try testing.expectEqual(@as(?u16, max_in_flight), p.properties.receive_maximum);
    try testing.expectEqual(@as(?u32, 300), p.properties.maximum_packet_size);
    try testing.expectEqual(@as(?u16, 3), p.properties.topic_alias_maximum);

    var c2 = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx });
    try testing.expectError(error.InvalidProperty, c2.connect(0, .{ .client_id = "x", .version = .v5, .properties = .{ .receive_maximum = max_in_flight + 1 } }));
    try testing.expectError(error.InvalidProperty, c2.connect(0, .{ .client_id = "x", .version = .v5, .properties = .{ .maximum_packet_size = 301 } }));
    try testing.expectError(error.InvalidProperty, c2.connect(0, .{ .client_id = "x", .version = .v5, .properties = .{ .topic_alias_maximum = 1 } }));
    try testing.expectEqual(ConnectionState.idle, c2.state); // nothing sent, nothing changed
}

test "v5 CONNACK: a refusal disconnects; the server's limits hold every later publish" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var refused = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx });
    try refused.connect(0, .{ .client_id = "x", .version = .v5 });
    try feed5(&refused, .{ .connack = .{ .session_present = false, .reason_code = .banned } });
    try testing.expectEqual(packet.ReasonCode.banned, (try refused.poll(0)).?.connack.reason_code);
    try testing.expectEqual(ConnectionState.disconnected, refused.state);

    var c = try makeConnected5(&tt, &rx, &tx, &.{}, .{
        .maximum_qos = .at_least_once,
        .retain_available = false,
        .receive_maximum = 2,
        .maximum_packet_size = 40,
        .topic_alias_maximum = 2,
        .server_keep_alive = 5,
    });
    try testing.expectEqual(@as(u16, 2), c.serverLimits().receive_maximum);
    try testing.expectEqual(@as(u64, 5000), c.keep_alive_ms); // Server Keep Alive wins (3.1.2-21)
    try testing.expectError(error.QosNotSupported, c.publish(1, "t", "x", .{ .qos = .exactly_once }));
    try testing.expectError(error.RetainNotSupported, c.publish(1, "t", "x", .{ .retain = true }));
    try testing.expectError(error.TopicAliasInvalid, c.publish(1, "t", "x", .{ .properties = .{ .topic_alias = 3 } }));
    try testing.expectError(error.InvalidProperty, c.publish(1, "t", "x", .{ .properties = .{ .subscription_ids = .{ .items = &.{1} } } }));
    try testing.expectError(error.PacketTooLarge, c.publish(1, "t", "x" ** 40, .{ .qos = .at_least_once }));
    try testing.expectEqual(@as(usize, 0), c.pending_len); // the refused publish holds no id

    // Receive Maximum 2: the third unacknowledged QoS 1 publish waits for an ack.
    const id1 = (try c.publish(1, "t", "1", .{ .qos = .at_least_once })).?;
    _ = (try c.publish(1, "t", "2", .{ .qos = .at_least_once })).?;
    try testing.expectError(error.ReceiveMaximumReached, c.publish(1, "t", "3", .{ .qos = .at_least_once }));
    _ = try c.publish(1, "t", "qos0 is not counted", .{});
    try feed5(&c, .{ .puback = .{ .packet_id = id1 } });
    try testing.expectEqual(id1, (try c.poll(2)).?.puback.packet_id);
    _ = (try c.publish(2, "t", "3", .{ .qos = .at_least_once })).?;
}

test "v5 inbound Topic Aliases: set, reused with an empty topic, and every invalid use refused" {
    var tt = TestTransport{};
    var rx: [512]u8 = undefined;
    var tx: [256]u8 = undefined;
    var slots: [2]AliasSlot = .{ .{}, .{} };
    var c = try makeConnected5(&tt, &rx, &tx, &slots, .{});
    try feed5(&c, .{ .publish = .{ .topic = "sensors/a", .payload = "1", .properties = .{ .topic_alias = 1 } } });
    try testing.expectEqualStrings("sensors/a", (try c.poll(1)).?.message.topic);
    try feed5(&c, .{ .publish = .{ .topic = "", .payload = "2", .properties = .{ .topic_alias = 1 } } });
    const m = (try c.poll(1)).?.message;
    try testing.expectEqualStrings("sensors/a", m.topic);
    try testing.expectEqualStrings("2", m.payload);

    try feed5(&c, .{ .publish = .{ .topic = "", .payload = "x", .properties = .{ .topic_alias = 2 } } }); // never set
    try testing.expectError(error.TopicAliasInvalid, c.poll(1));
    c.resetRx();
    try feed5(&c, .{ .publish = .{ .topic = "t", .payload = "x", .properties = .{ .topic_alias = 3 } } }); // above ours
    try testing.expectError(error.TopicAliasInvalid, c.poll(1));
    c.resetRx();
    try feed5(&c, .{ .publish = .{ .topic = "a/" ++ "x" ** alias_topic_capacity, .properties = .{ .topic_alias = 2 } } }); // too long to keep
    try testing.expectError(error.TopicAliasInvalid, c.poll(1));
    c.resetRx();

    // A reconnect forgets every mapping (3.3.2-7).
    try c.disconnect(2);
    try c.connect(3, .{ .client_id = "v5", .version = .v5 });
    try feed5(&c, .{ .connack = .{ .session_present = false } });
    _ = (try c.poll(3)).?;
    try feed5(&c, .{ .publish = .{ .topic = "", .payload = "x", .properties = .{ .topic_alias = 1 } } });
    try testing.expectError(error.TopicAliasInvalid, c.poll(3));
}

test "v5 inbound Topic Alias above the maximum the client announced is refused, slots or not" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var slots: [4]AliasSlot = .{ .{}, .{}, .{}, .{} };
    var c = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx, .topic_aliases = &slots });
    try c.connect(0, .{ .client_id = "x", .version = .v5, .properties = .{ .topic_alias_maximum = 2 } });
    try feed5(&c, .{ .connack = .{ .session_present = false } });
    _ = (try c.poll(0)).?;
    try feed5(&c, .{ .publish = .{ .topic = "t", .properties = .{ .topic_alias = 2 } } });
    try testing.expectEqualStrings("t", (try c.poll(1)).?.message.topic);
    try feed5(&c, .{ .publish = .{ .topic = "t", .properties = .{ .topic_alias = 3 } } }); // a slot exists, the promise does not
    try testing.expectError(error.TopicAliasInvalid, c.poll(1));
}

test "v5 messages carry their properties; acks carry reason codes" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected5(&tt, &rx, &tx, &.{}, .{});
    try feed5(&c, .{ .publish = .{ .topic = "req", .payload = "q", .properties = .{
        .response_topic = "resp/1",
        .correlation_data = "c1",
        .user_properties = .{ .items = &.{.{ .name = "k", .value = "v" }} },
        .subscription_ids = .{ .items = &.{ 4, 9 } },
    } } });
    const m = (try c.poll(1)).?.message;
    try testing.expectEqualStrings("resp/1", m.properties.response_topic.?);
    try testing.expectEqualStrings("c1", m.properties.correlation_data.?);
    try testing.expectEqual(@as(usize, 1), m.properties.user_properties.count());
    try testing.expectEqual(@as(usize, 2), m.properties.subscription_ids.count());

    // A refusing PUBACK still releases the id; a refusing PUBREC ends the
    // QoS 2 handshake with no PUBREL (4.4.0-2).
    const q1 = (try c.publish(2, "t", "x", .{ .qos = .at_least_once })).?;
    try feed5(&c, .{ .puback = .{ .packet_id = q1, .reason_code = .not_authorized } });
    try testing.expectEqual(packet.ReasonCode.not_authorized, (try c.poll(2)).?.puback.reason_code);
    const q2 = (try c.publish(3, "t", "x", .{ .qos = .exactly_once })).?;
    tt.reset();
    try feed5(&c, .{ .pubrec = .{ .packet_id = q2, .reason_code = .quota_exceeded } });
    const done = (try c.poll(3)).?.pubcomp;
    try testing.expectEqual(q2, done.packet_id);
    try testing.expectEqual(packet.ReasonCode.quota_exceeded, done.reason_code);
    try testing.expectEqual(@as(usize, 0), tt.len);
    try testing.expectEqual(@as(usize, 0), c.pending_len);

    // A PUBREL for an id the client never had: PUBCOMP saying so.
    try feed5(&c, .{ .pubrel = .{ .packet_id = 77 } });
    try testing.expectEqual(null, try c.poll(4));
    const comp = (try lastPacket5(&tt)).pubcomp;
    try testing.expectEqual(packet.ReasonCode.packet_identifier_not_found, comp.reason_code);
}

test "v5 server DISCONNECT is an event; 3.1.1 has none" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected5(&tt, &rx, &tx, &.{}, .{});
    try feed5(&c, .{ .disconnect = .{ .reason_code = .server_moved, .properties = .{ .server_reference = "b:1883" } } });
    const d = (try c.poll(1)).?.disconnect;
    try testing.expectEqual(packet.ReasonCode.server_moved, d.reason_code);
    try testing.expectEqualStrings("b:1883", d.properties.server_reference.?);
    try testing.expectEqual(ConnectionState.disconnected, c.state);

    var t3 = TestTransport{};
    var c3 = try makeConnected(&t3, &rx, &tx);
    var buf: [2]u8 = undefined;
    try c3.feed(try packet.encodeDisconnect(&buf));
    try testing.expectError(error.ProtocolViolation, c3.poll(1));
}

test "v5 extended authentication: the server's AUTH surfaces, the client answers, CONNACK follows" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx });
    try c.connect(0, .{ .client_id = "x", .version = .v5, .properties = .{ .authentication_method = "SCRAM", .authentication_data = "first" } });
    tt.reset();
    try feed5(&c, .{ .auth = .{ .reason_code = .continue_authentication, .properties = .{ .authentication_method = "SCRAM", .authentication_data = "challenge" } } });
    const challenge = (try c.poll(1)).?.auth;
    try testing.expectEqualStrings("challenge", challenge.properties.authentication_data.?);
    try c.auth(1, .{ .reason_code = .continue_authentication, .properties = .{ .authentication_method = "SCRAM", .authentication_data = "proof" } });
    try testing.expectEqualStrings("proof", (try lastPacket5(&tt)).auth.properties.authentication_data.?);
    try feed5(&c, .{ .connack = .{ .session_present = false, .properties = .{ .authentication_method = "SCRAM" } } });
    _ = (try c.poll(2)).?;
    try testing.expectEqual(ConnectionState.connected, c.state);
}

test "v5 SUBSCRIBE options, UNSUBACK codes and DISCONNECT with a reason go out as 5.0" {
    var tt = TestTransport{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var c = try makeConnected5(&tt, &rx, &tx, &.{}, .{});
    const sid = try c.subscribeWith(1, &.{.{ .filter = "a/#", .qos = .exactly_once, .no_local = true, .retain_handling = .never }}, .{ .subscription_ids = .{ .items = &.{12} } });
    const s = (try lastPacket5(&tt)).subscribe;
    try testing.expectEqual(@as(?u32, 12), s.properties.subscription_ids.first());
    var it = s.iterator();
    const f = it.next().?;
    try testing.expect(f.no_local);
    try testing.expectEqual(packet.RetainHandling.never, f.retain_handling);
    try feed5(&c, .{ .suback = .{ .packet_id = sid, .codes = &.{0x02} } });
    try testing.expectEqualSlices(u8, &.{0x02}, (try c.poll(1)).?.suback.codes);

    const uid = try c.unsubscribe(2, &.{"a/#"});
    try feed5(&c, .{ .unsuback = .{ .packet_id = uid, .codes = &.{0x11} } });
    try testing.expectEqualSlices(u8, &.{0x11}, (try c.poll(2)).?.unsuback.codes);

    tt.reset();
    try c.disconnectWith(3, .{ .reason_code = .disconnect_with_will_message, .properties = .{ .session_expiry_interval = 0 } });
    const d = (try lastPacket5(&tt)).disconnect;
    try testing.expectEqual(packet.ReasonCode.disconnect_with_will_message, d.reason_code);
    try testing.expectEqual(@as(?u32, 0), d.properties.session_expiry_interval);

    // 3.1.1 refuses what it cannot express.
    var t3 = TestTransport{};
    var c3 = try makeConnected(&t3, &rx, &tx);
    try testing.expectError(error.UnsupportedInVersion, c3.subscribe(1, &.{.{ .filter = "a", .no_local = true }}));
    try testing.expectError(error.UnsupportedInVersion, c3.publish(1, "a", "x", .{ .properties = .{ .message_expiry_interval = 1 } }));
}
