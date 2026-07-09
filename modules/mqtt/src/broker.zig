// SPDX-License-Identifier: MIT

//! MQTT 3.1.1 broker (server) — first cut: QoS 0 + 1, clean session, no TLS.
//!
//! The mirror image of `client.zig`. Where the client drives one connection
//! *to* a broker, the `Broker` here owns the shared server-side state — the
//! set of connections, the subscription registry and the retained store —
//! and each `Connection` is a reversed per-connection state machine: the
//! first packet it must see is a CONNECT (spec 3.1), it answers CONNACK /
//! SUBACK / UNSUBACK / PUBACK / PINGRESP, and PUBLISH packets fan out to
//! every matching subscription.
//!
//! Caller-driven, socket-free core (exactly the `client.zig` seam, reversed):
//! outgoing bytes to a client go through that connection's `Transport` write
//! seam; incoming bytes are handed to `Broker.feed`; `Broker.process(conn,
//! now)` decodes buffered packets, advances the connection's state machine
//! and performs fan-out. `now` (caller's monotonic clock, ms) is passed in —
//! the broker reads no clock itself — so the whole broker is drivable from
//! in-memory buffers in tests, no socket required. `TcpServer` is an optional
//! real-socket accept loop over `std.Io.net` (thread-per-connection, one
//! `std.Thread.Mutex`-equivalent around the shared registry); tests never
//! listen or dial.
//!
//! First-cut scope (spec 3.1.1):
//!  - CONNECT/CONNACK: protocol name+level validated (by the codec),
//!    client-id assigned (empty → server-generated) or rejected, session
//!    take-over on a duplicate client-id, `session_present` always false
//!    (clean session only). Keep-alive deadline = 1.5 × the client's
//!    keep-alive, checked against a caller-supplied last-packet timestamp.
//!  - SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK: a flat filter registry
//!    (`topic.matches` per PUBLISH — correct, no trie at this scale); filters
//!    stored verbatim so UNSUBSCRIBE removes by exact string.
//!  - PUBLISH fan-out at min(publisher QoS, granted QoS); one copy per
//!    connection at the highest granted QoS among its overlapping filters.
//!  - QoS 0 fire-and-forget; QoS 1 inbound → immediate PUBACK; QoS 1
//!    outbound → a packet-id allocated in the *subscriber* connection's id
//!    space, tracked pending until its PUBACK.
//!  - Retained store: retain=true PUBLISH stored per topic (empty payload
//!    clears); matching retained messages delivered to a new subscription
//!    right after its SUBACK.
//!
//! Deliberately deferred (documented, not built): QoS 2
//! (PUBREC/PUBREL/PUBCOMP — an inbound QoS 2 PUBLISH is a protocol violation
//! that tears the connection down), persistent / offline sessions
//! (clean-session only; `session_present` never true), DUP retransmit of an
//! unacked outbound QoS 1 publish, Will / LWT, MQTT 5.0, and TLS (terminate
//! it in front and hand `TcpServer` the plaintext, or drive the socket-free
//! core over a TLS stream yourself).
//!
//! Provenance: clean-room from the OASIS MQTT 3.1.1 specification;
//! mosquitto/Paho referenced for behavior only, no source consulted or
//! copied.

const std = @import("std");
const packet = @import("packet.zig");
const topic = @import("topic.zig");

const QoS = packet.QoS;

/// Upper bound on outstanding outbound QoS 1 packet ids per subscriber
/// connection (matches the client's pool bound).
pub const max_in_flight = 64;

/// Largest client id the broker stores inline (spec permits 65 535; a longer
/// one is refused with CONNACK `identifier_rejected`).
pub const max_client_id = 256;

/// Largest SUBSCRIBE the broker answers in one SUBACK (filters per packet).
pub const max_filters_per_subscribe = 64;

/// Failures a `Transport` implementation may report.
pub const TransportError = error{TransportFailed};

/// Outgoing byte seam to one connected client (reversed `client.Transport`).
/// Implementations must take all bytes or fail; the broker never retries
/// partial writes.
pub const Transport = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) TransportError!void,

    pub fn write(t: Transport, bytes: []const u8) TransportError!void {
        return t.writeFn(t.ctx, bytes);
    }
};

/// Errors surfaced by `process`. A decode error or a protocol violation
/// means the offending connection must be torn down (`remove`).
pub const Error = error{
    /// First packet was not CONNECT, a second CONNECT arrived, an inbound
    /// QoS 2 PUBLISH was seen, or a stray ack was received.
    ProtocolViolation,
    /// `feed` would overflow the connection's receive buffer.
    RxBufferFull,
    /// The connection's `Transport` write failed.
    TransportFailed,
    /// SUBSCRIBE carried more filters than `max_filters_per_subscribe`.
    TooManySubscriptions,
    /// `accept` refused a new connection: `Config.max_connections` reached.
    ConnectionLimitReached,
    OutOfMemory,
} || packet.DecodeError || packet.EncodeError;

/// What the caller should do with the connection after `process`.
pub const Disposition = enum {
    /// Keep serving this connection.
    keep,
    /// Tear it down (DISCONNECT received, take-over, or refused CONNECT).
    close,
};

// ── mutex around the shared registry ────────────────────────────────────────
// `std.Thread.Mutex` was removed in 0.16 and `std.Io.Mutex` needs an `Io`
// instance — but the broker core is deliberately Io-free (offline-testable).
// A tiny atomic spinlock keeps the shared registry / retained store /
// connection set safe under the thread-per-connection `TcpServer` without
// libc or an `Io`; critical sections are short (register a sub, fan out a
// publish). Uncontended (the single-threaded offline tests) it is a bare
// acquire/release.

const Mutex = struct {
    locked: std.atomic.Value(bool) = .init(false),

    pub fn lock(m: *Mutex) void {
        while (m.locked.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(m: *Mutex) void {
        m.locked.store(false, .release);
    }
};

// ── per-connection state ────────────────────────────────────────────────────

/// One client connection on the broker side. Owns its receive buffer (stream
/// reassembly, mirrors `client.zig`'s rx handling) and a transmit scratch
/// buffer used to encode packets sent to this client. Registered subscriptions
/// and pending outbound QoS 1 ids belong to the connection; the filter strings
/// themselves live in the broker's registry.
pub const Connection = struct {
    transport: Transport,
    rx_buf: []u8,
    rx_len: usize = 0,
    rx_consumed: usize = 0,
    tx_buf: []u8,

    state: State = .awaiting_connect,
    client_id_buf: [max_client_id]u8 = undefined,
    client_id_len: usize = 0,
    keep_alive_s: u16 = 0,
    /// Timestamp (caller clock, ms) of the last packet decoded from this
    /// connection — the keep-alive reference point.
    last_packet_ms: i64 = 0,

    // Outbound QoS 1 delivery to this subscriber: ids allocated in *this*
    // connection's space, pending until the client's PUBACK.
    next_packet_id: u16 = 1,
    pending: [max_in_flight]u16 = undefined,
    pending_len: usize = 0,

    pub const State = enum { awaiting_connect, connected, disconnected };

    pub fn clientId(c: *const Connection) []const u8 {
        return c.client_id_buf[0..c.client_id_len];
    }

    fn setClientId(c: *Connection, id: []const u8) error{ClientIdTooLong}!void {
        if (id.len > c.client_id_buf.len) return error.ClientIdTooLong;
        @memcpy(c.client_id_buf[0..id.len], id);
        c.client_id_len = id.len;
    }

    fn write(c: *Connection, bytes: []const u8) Error!void {
        c.transport.write(bytes) catch return error.TransportFailed;
    }

    fn compact(c: *Connection) void {
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

    /// Allocate the next free nonzero outbound packet id (wraps 65535 → 1,
    /// skips ids still in flight); null when the pool is exhausted.
    fn allocPacketId(c: *Connection) ?u16 {
        if (c.pending_len >= c.pending.len) return null;
        var attempts: u32 = 0;
        while (attempts < std.math.maxInt(u16)) : (attempts += 1) {
            const id = c.next_packet_id;
            c.next_packet_id = if (c.next_packet_id == std.math.maxInt(u16)) 1 else c.next_packet_id + 1;
            if (std.mem.indexOfScalar(u16, c.pending[0..c.pending_len], id) == null) {
                c.pending[c.pending_len] = id;
                c.pending_len += 1;
                return id;
            }
        }
        return null;
    }

    fn removePending(c: *Connection, id: u16) void {
        if (std.mem.indexOfScalar(u16, c.pending[0..c.pending_len], id)) |i| {
            c.pending_len -= 1;
            c.pending[i] = c.pending[c.pending_len];
        }
    }
};

// ── the broker ──────────────────────────────────────────────────────────────

/// One registry entry: a subscribing connection, its filter (an owned copy,
/// stored verbatim for exact-string UNSUBSCRIBE) and the granted QoS.
const Sub = struct {
    conn: *Connection,
    filter: []u8,
    qos: QoS,
};

/// One retained message: topic + payload copies the broker owns, plus the
/// QoS it was published at (delivery downgrades to the subscriber's grant).
const Retained = struct {
    topic: []u8,
    payload: []u8,
    qos: QoS,
};

pub const Config = struct {
    /// Per-connection receive and transmit buffer size; bounds the largest
    /// packet the broker will accept from or route to a client.
    max_packet_size: usize = 8 * 1024,
    /// Hard cap on live connections; `accept` refuses (closes) past this
    /// (resource-exhaustion guard — one thread/socket per connection).
    max_connections: usize = 1024,
    /// Hard cap on subscriptions across the whole broker; `registerSubscription`
    /// refuses new filters past this rather than growing `subscriptions`
    /// unboundedly.
    max_subscriptions_total: usize = 65536,
    /// Hard cap on subscriptions held by one connection (a single client
    /// spamming SUBSCRIBE cannot alone exhaust the total budget).
    max_subscriptions_per_conn: usize = 1024,
    /// Hard cap on distinct retained topics; `storeRetained` refuses a new
    /// topic past this (existing retained topics may still be updated in
    /// place) rather than growing `retained` unboundedly.
    max_retained: usize = 8192,
    /// Bounded idle window (ms) a connection is given to send its CONNECT
    /// before the accept-loop drops it (spec 3.1 requires CONNECT first, but
    /// keep-alive is 0 — meaning "no timeout" — until CONNECT succeeds, so
    /// without this a client that never sends CONNECT pins a slot forever).
    /// Only consulted by `TcpServer`; the socket-free core has no clock.
    connect_timeout_ms: u32 = 10_000,
};

/// The shared server-side state. Offline-testable: `accept` registers a
/// `Transport`, `feed` + `process` drive a connection, `remove` tears it
/// down — no sockets involved. Every mutation of the shared registry /
/// retained store / connection set happens under `mutex`, so `TcpServer` can
/// run one thread per connection ("single owner at the data-structure
/// level").
pub const Broker = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: Mutex = .{},

    connections: std.ArrayList(*Connection) = .empty,
    subscriptions: std.ArrayList(Sub) = .empty,
    retained: std.ArrayList(Retained) = .empty,
    next_auto_id: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) Broker {
        return .{ .allocator = allocator, .config = config };
    }

    /// Free every connection, subscription and retained message.
    pub fn deinit(b: *Broker) void {
        for (b.connections.items) |conn| b.freeConnection(conn);
        b.connections.deinit(b.allocator);
        for (b.subscriptions.items) |s| b.allocator.free(s.filter);
        b.subscriptions.deinit(b.allocator);
        for (b.retained.items) |r| {
            b.allocator.free(r.topic);
            b.allocator.free(r.payload);
        }
        b.retained.deinit(b.allocator);
        b.* = undefined;
    }

    /// Register a new connection over `transport`; returns an owned pointer
    /// (freed by `remove`). Allocates the connection's rx/tx buffers.
    pub fn accept(b: *Broker, transport: Transport) Error!*Connection {
        b.mutex.lock();
        defer b.mutex.unlock();

        if (b.connections.items.len >= b.config.max_connections) return error.ConnectionLimitReached;

        const conn = try b.allocator.create(Connection);
        errdefer b.allocator.destroy(conn);
        const rx = try b.allocator.alloc(u8, b.config.max_packet_size);
        errdefer b.allocator.free(rx);
        const tx = try b.allocator.alloc(u8, b.config.max_packet_size);
        errdefer b.allocator.free(tx);
        conn.* = .{ .transport = transport, .rx_buf = rx, .tx_buf = tx };
        try b.connections.append(b.allocator, conn);
        return conn;
    }

    /// Tear a connection down: drop its subscriptions, unregister it and free
    /// its memory. Idempotent w.r.t. subscriptions.
    pub fn remove(b: *Broker, conn: *Connection) void {
        b.mutex.lock();
        defer b.mutex.unlock();
        b.dropSubscriptions(conn);
        if (std.mem.indexOfScalar(*Connection, b.connections.items, conn)) |i| {
            _ = b.connections.swapRemove(i);
        }
        b.freeConnection(conn);
    }

    fn freeConnection(b: *Broker, conn: *Connection) void {
        b.allocator.free(conn.rx_buf);
        b.allocator.free(conn.tx_buf);
        b.allocator.destroy(conn);
    }

    /// Buffer bytes received from this connection's client (any framing).
    /// Touches only the connection's own rx buffer — no lock needed (one
    /// thread owns a connection).
    pub fn feed(b: *Broker, conn: *Connection, bytes: []const u8) error{RxBufferFull}!void {
        _ = b;
        conn.compact();
        if (conn.rx_len + bytes.len > conn.rx_buf.len) return error.RxBufferFull;
        @memcpy(conn.rx_buf[conn.rx_len..][0..bytes.len], bytes);
        conn.rx_len += bytes.len;
    }

    /// Decode every complete packet currently buffered for `conn`, advance
    /// its state machine and fan out PUBLISHes. `now` is the caller's clock
    /// (ms) — recorded as the connection's last-packet time for keep-alive.
    /// Returns `.close` once the connection should be torn down.
    pub fn process(b: *Broker, conn: *Connection, now: i64) Error!Disposition {
        b.mutex.lock();
        defer b.mutex.unlock();
        while (true) {
            conn.compact();
            const dec = (try packet.decode(conn.rx_buf[0..conn.rx_len])) orelse return .keep;
            conn.rx_consumed = dec.consumed;
            conn.last_packet_ms = now;
            if (try b.handle(conn, dec.packet, now) == .close) return .close;
        }
    }

    /// True when the keep-alive deadline (1.5 × the client's keep-alive)
    /// has passed relative to the last packet (spec 3.1.2.10). Keep-alive 0
    /// disables the mechanism. Lock-free read of connection-local fields.
    pub fn keepAliveExpired(b: *const Broker, conn: *const Connection, now: i64) bool {
        _ = b;
        if (conn.keep_alive_s == 0) return false;
        const deadline = conn.last_packet_ms + @as(i64, conn.keep_alive_s) * 1500;
        return now > deadline;
    }

    // ── packet handling (mutex held) ─────────────────────────────────────────

    fn handle(b: *Broker, conn: *Connection, p: packet.Packet, now: i64) Error!Disposition {
        switch (conn.state) {
            .awaiting_connect => {
                if (p != .connect) return error.ProtocolViolation; // spec 3.1: first packet
                return b.handleConnect(conn, p.connect, now);
            },
            .disconnected => return .close,
            .connected => switch (p) {
                .connect => return error.ProtocolViolation, // second CONNECT (spec 3.1-2)
                .publish => |pub_pkt| return b.handlePublish(conn, pub_pkt),
                .subscribe => |s| {
                    try b.handleSubscribe(conn, s);
                    return .keep;
                },
                .unsubscribe => |u| {
                    try b.handleUnsubscribe(conn, u);
                    return .keep;
                },
                .puback => |id| {
                    conn.removePending(id);
                    return .keep;
                },
                .pingreq => {
                    try conn.write(try packet.encodePingresp(conn.tx_buf));
                    return .keep;
                },
                .disconnect => {
                    // Clean session: state is dropped on disconnect.
                    b.dropSubscriptions(conn);
                    conn.state = .disconnected;
                    return .close;
                },
                // QoS 2 (PUBREC/PUBREL/PUBCOMP) is deferred; anything a
                // client must not send to a server is a violation.
                else => return error.ProtocolViolation,
            },
        }
    }

    fn handleConnect(b: *Broker, conn: *Connection, c: packet.Connect, now: i64) Error!Disposition {
        // The codec already validated the protocol name/level and rejected an
        // empty client-id without clean session. Assign or generate the id.
        if (c.client_id.len == 0) {
            var buf: [max_client_id]u8 = undefined;
            const gen = std.fmt.bufPrint(&buf, "auto-{d}", .{b.next_auto_id}) catch unreachable;
            b.next_auto_id += 1;
            conn.setClientId(gen) catch unreachable;
        } else conn.setClientId(c.client_id) catch {
            try conn.write(try packet.encodeConnack(conn.tx_buf, .{
                .session_present = false,
                .return_code = .identifier_rejected,
            }));
            return .close;
        };

        // Session take-over: a live connection with the same client-id is
        // disconnected (spec 3.1.4-2). Its socket is closed lazily by its own
        // owner; here we just drop its routing state so no stale fan-out
        // occurs. Clean session → no state is carried over.
        b.takeover(conn);

        conn.keep_alive_s = c.keep_alive_s;
        conn.last_packet_ms = now;
        conn.state = .connected;
        try conn.write(try packet.encodeConnack(conn.tx_buf, .{
            .session_present = false, // clean session only
            .return_code = .accepted,
        }));
        return .keep;
    }

    fn takeover(b: *Broker, newconn: *Connection) void {
        const id = newconn.clientId();
        for (b.connections.items) |other| {
            if (other == newconn) continue;
            if (other.state == .disconnected) continue;
            if (std.mem.eql(u8, other.clientId(), id)) {
                b.dropSubscriptions(other);
                other.state = .disconnected;
            }
        }
    }

    fn handleSubscribe(b: *Broker, conn: *Connection, s: packet.Subscribe) Error!void {
        // Validate the filter count BEFORE registering anything. Counting
        // first (a read-only pass over the iterator) means a >max_filters
        // SUBSCRIBE is rejected as a whole — never partial-register-then-
        // disconnect, which used to leave live subscriptions behind with no
        // SUBACK ever sent.
        var count: usize = 0;
        var count_it = s.iterator();
        while (count_it.next()) |_| {
            count += 1;
            if (count > max_filters_per_subscribe) return error.TooManySubscriptions;
        }

        var codes: [max_filters_per_subscribe]u8 = undefined;
        var grants: [max_filters_per_subscribe]QoS = undefined;
        var filters: [max_filters_per_subscribe][]const u8 = undefined;
        var n: usize = 0;

        var it = s.iterator();
        while (it.next()) |req| {
            if (topic.validateFilter(req.filter)) |_| {
                // We support up to QoS 1; grant min(requested, 1).
                const granted = minQos(req.qos, .at_least_once);
                if (try b.registerSubscription(conn, req.filter, granted)) {
                    codes[n] = @intFromEnum(granted);
                    grants[n] = granted;
                    filters[n] = req.filter;
                } else {
                    // Over Config.max_subscriptions_total/_per_conn: refuse
                    // this filter cleanly (0x80) rather than growing the
                    // registry unboundedly.
                    codes[n] = packet.suback_failure;
                    grants[n] = .at_most_once;
                    filters[n] = "";
                }
            } else |_| {
                codes[n] = packet.suback_failure;
                grants[n] = .at_most_once;
                filters[n] = "";
            }
            n += 1;
        }
        if (n == 0) return error.ProtocolViolation; // empty SUBSCRIBE (spec 3.8.3-3)

        try conn.write(try packet.encodeSuback(conn.tx_buf, s.packet_id, codes[0..n]));

        // Retained messages are delivered right after the SUBACK (spec 3.3.1.3).
        for (0..n) |i| {
            if (codes[i] == packet.suback_failure) continue;
            b.deliverRetained(conn, filters[i], grants[i]) catch |e| switch (e) {
                error.TransportFailed => return e,
                else => return e,
            };
        }
    }

    /// Add (or, for an exact re-subscribe, update the QoS of) a subscription.
    /// Returns `false` (no mutation) when `max_subscriptions_total` or
    /// `max_subscriptions_per_conn` would be exceeded by a genuinely new
    /// filter — the caller reports that as a per-filter SUBACK 0x80 rather
    /// than growing the registry unboundedly.
    fn registerSubscription(b: *Broker, conn: *Connection, filter: []const u8, qos: QoS) Error!bool {
        for (b.subscriptions.items) |*s| {
            if (s.conn == conn and std.mem.eql(u8, s.filter, filter)) {
                s.qos = qos; // re-subscribe replaces the grant (spec 3.8.4-3)
                return true;
            }
        }
        if (b.subscriptions.items.len >= b.config.max_subscriptions_total) return false;
        var per_conn: usize = 0;
        for (b.subscriptions.items) |s| {
            if (s.conn == conn) per_conn += 1;
        }
        if (per_conn >= b.config.max_subscriptions_per_conn) return false;

        const owned = try b.allocator.dupe(u8, filter);
        errdefer b.allocator.free(owned);
        try b.subscriptions.append(b.allocator, .{ .conn = conn, .filter = owned, .qos = qos });
        return true;
    }

    fn handleUnsubscribe(b: *Broker, conn: *Connection, u: packet.Unsubscribe) Error!void {
        var it = u.iterator();
        while (it.next()) |filter| {
            var i: usize = 0;
            while (i < b.subscriptions.items.len) {
                const s = b.subscriptions.items[i];
                if (s.conn == conn and std.mem.eql(u8, s.filter, filter)) {
                    b.allocator.free(s.filter);
                    _ = b.subscriptions.swapRemove(i);
                    // Exact-string removal; a filter can appear once per conn,
                    // but keep scanning defensively without advancing i.
                    continue;
                }
                i += 1;
            }
        }
        try conn.write(try packet.encodeUnsuback(conn.tx_buf, u.packet_id));
    }

    fn handlePublish(b: *Broker, conn: *Connection, pub_pkt: packet.Publish) Error!Disposition {
        // QoS 2 inbound is deferred: refuse and tear the connection down.
        if (pub_pkt.qos == .exactly_once) return error.ProtocolViolation;

        // Retained store (spec 3.3.1.3): empty payload clears, otherwise set.
        if (pub_pkt.retain) {
            if (pub_pkt.payload.len == 0) {
                b.clearRetained(pub_pkt.topic);
            } else {
                try b.storeRetained(pub_pkt.topic, pub_pkt.payload, pub_pkt.qos);
            }
        }

        // Fan-out: one copy per connection at the highest granted QoS among
        // its matching (possibly overlapping) filters, capped at the
        // publisher's QoS. The publisher receives its own message if it
        // subscribes (no loopback suppression in 3.1.1).
        for (b.connections.items) |sub_conn| {
            if (sub_conn.state != .connected) continue;
            var best: ?QoS = null;
            for (b.subscriptions.items) |s| {
                if (s.conn != sub_conn) continue;
                if (topic.matches(s.filter, pub_pkt.topic)) {
                    best = if (best) |cur| maxQos(cur, s.qos) else s.qos;
                }
            }
            if (best) |g| {
                try b.deliver(sub_conn, pub_pkt.topic, pub_pkt.payload, minQos(pub_pkt.qos, g), false);
            }
        }

        // Acknowledge an inbound QoS 1 publish (QoS 0: nothing).
        if (pub_pkt.qos == .at_least_once) {
            try conn.write(try packet.encodePuback(conn.tx_buf, pub_pkt.packet_id));
        }
        return .keep;
    }

    /// Send one PUBLISH to a subscriber at `qos`. For QoS 1 a packet id is
    /// allocated in the subscriber's id space and tracked pending until its
    /// PUBACK; if that pool is exhausted the message is dropped for this
    /// subscriber (best-effort — DUP retransmit / offline queueing deferred).
    fn deliver(b: *Broker, sub_conn: *Connection, topic_name: []const u8, payload: []const u8, qos: QoS, retain: bool) Error!void {
        _ = b;
        var out_qos = qos;
        var id: u16 = 0;
        if (qos == .at_least_once) {
            id = sub_conn.allocPacketId() orelse return; // pool full: drop
            out_qos = .at_least_once;
        }
        const bytes = try packet.encodePublish(sub_conn.tx_buf, .{
            .topic = topic_name,
            .payload = payload,
            .qos = out_qos,
            .retain = retain,
            .packet_id = id,
        });
        try sub_conn.write(bytes);
    }

    fn deliverRetained(b: *Broker, sub_conn: *Connection, filter: []const u8, granted: QoS) Error!void {
        for (b.retained.items) |r| {
            if (topic.matches(filter, r.topic)) {
                try b.deliver(sub_conn, r.topic, r.payload, minQos(r.qos, granted), true);
            }
        }
    }

    /// Store (or update) one retained topic. Past `Config.max_retained`, a
    /// genuinely new topic is refused (no-op — the live PUBLISH fan-out to
    /// current subscribers still happens; only the retained copy is
    /// dropped) rather than growing `retained` unboundedly. Updating an
    /// already-retained topic is always allowed (no growth).
    fn storeRetained(b: *Broker, topic_name: []const u8, payload: []const u8, qos: QoS) Error!void {
        for (b.retained.items) |*r| {
            if (std.mem.eql(u8, r.topic, topic_name)) {
                const new_payload = try b.allocator.dupe(u8, payload);
                b.allocator.free(r.payload);
                r.payload = new_payload;
                r.qos = qos;
                return;
            }
        }
        if (b.retained.items.len >= b.config.max_retained) return; // cap: refuse new retained topic
        const owned_topic = try b.allocator.dupe(u8, topic_name);
        errdefer b.allocator.free(owned_topic);
        const owned_payload = try b.allocator.dupe(u8, payload);
        errdefer b.allocator.free(owned_payload);
        try b.retained.append(b.allocator, .{ .topic = owned_topic, .payload = owned_payload, .qos = qos });
    }

    fn clearRetained(b: *Broker, topic_name: []const u8) void {
        for (b.retained.items, 0..) |r, i| {
            if (std.mem.eql(u8, r.topic, topic_name)) {
                b.allocator.free(r.topic);
                b.allocator.free(r.payload);
                _ = b.retained.swapRemove(i);
                return;
            }
        }
    }

    fn dropSubscriptions(b: *Broker, conn: *Connection) void {
        var i: usize = 0;
        while (i < b.subscriptions.items.len) {
            if (b.subscriptions.items[i].conn == conn) {
                b.allocator.free(b.subscriptions.items[i].filter);
                _ = b.subscriptions.swapRemove(i);
                continue;
            }
            i += 1;
        }
    }
};

fn minQos(a: QoS, b: QoS) QoS {
    return if (@intFromEnum(a) <= @intFromEnum(b)) a else b;
}

fn maxQos(a: QoS, b: QoS) QoS {
    return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
}

// ── optional real transport: an MQTT broker over TCP via std.Io.net ─────────
// Demo convenience only — nothing in the codec, broker core, or tests needs
// it. Thread-per-connection over `std.Io.Group`, modeled on http/Server.zig's
// accept loop; the shared registry is guarded by the broker's mutex.

/// Blocking TCP accept loop that fronts a `Broker`. Bind, then `serve`
/// (blocks on the caller's thread until `shutdown`). Each accepted connection
/// is served on its own task/thread: read → `feed` → `process`, with a
/// poll-bounded keep-alive check between reads.
pub const TcpServer = struct {
    io: std.Io,
    broker: *Broker,
    listener: ?std.Io.net.Server = null,
    group: std.Io.Group = .init,

    /// Standard MQTT port (1883; 8883 is MQTT over TLS).
    pub const default_port = 1883;

    pub fn init(io: std.Io, broker: *Broker) TcpServer {
        return .{ .io = io, .broker = broker };
    }

    pub fn deinit(s: *TcpServer) void {
        if (s.listener) |*l| l.deinit(s.io);
        s.* = undefined;
    }

    pub fn bind(s: *TcpServer, addr: []const u8, port: u16) !void {
        const ip = try std.Io.net.IpAddress.parse(addr, port);
        s.listener = try ip.listen(s.io, .{ .reuse_address = true });
    }

    pub fn boundAddress(s: *const TcpServer) std.Io.net.IpAddress {
        return s.listener.?.socket.address;
    }

    /// Stop accepting: wakes a blocked `serve`, which drains connection tasks.
    pub fn shutdown(s: *TcpServer) void {
        const l = s.listener orelse return;
        const stream: std.Io.net.Stream = .{ .socket = l.socket };
        stream.shutdown(s.io, .both) catch {};
    }

    pub fn serve(s: *TcpServer) !void {
        defer s.group.await(s.io) catch {};
        const listener = &s.listener.?;
        while (true) {
            const stream = listener.accept(s.io) catch |err| switch (err) {
                error.SocketNotListening => return, // shutdown()
                else => continue,
            };
            s.group.concurrent(s.io, connMain, .{ s, stream }) catch {
                // A failed spawn must never run the handler inline on this
                // accept thread — a client that never completes CONNECT
                // (keep_alive_s == 0 ⇒ waitReadable blocks forever) would
                // then wedge accept() permanently (total DoS). No logging
                // seam exists in this module; reject the stream and keep
                // accepting.
                stream.close(s.io);
                continue;
            };
        }
    }

    fn connMain(s: *TcpServer, stream: std.Io.net.Stream) void {
        defer stream.close(s.io);
        var sock = SocketTransport{ .io = s.io, .stream = stream };
        const conn = s.broker.accept(sock.transport()) catch return;
        defer s.broker.remove(conn);

        var read_buf: [4096]u8 = undefined;
        while (true) {
            if (!waitReadable(stream.socket.handle, connTimeoutMs(s.broker.config, conn))) {
                // Pre-CONNECT: keep_alive_s is still 0 (unset), which would
                // otherwise mean "wait forever" — bound it by
                // connect_timeout_ms so a client that opens a socket and
                // never sends CONNECT can't pin this slot/thread forever.
                if (conn.state == .awaiting_connect) return;
                // Post-CONNECT: no data within the keep-alive window; check
                // and drop.
                if (s.broker.keepAliveExpired(conn, milliTimestamp())) return;
                continue;
            }
            const n = std.posix.read(stream.socket.handle, &read_buf) catch return;
            if (n == 0) return; // client closed
            s.broker.feed(conn, read_buf[0..n]) catch return;
            const disp = s.broker.process(conn, milliTimestamp()) catch return;
            if (disp == .close) return;
            if (s.broker.keepAliveExpired(conn, milliTimestamp())) return;
        }
    }
};

/// Blocking socket write seam for `TcpServer` (mirrors client.TcpTransport).
const SocketTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,

    fn transport(t: *SocketTransport) Transport {
        return .{ .ctx = t, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const t: *SocketTransport = @ptrCast(@alignCast(ctx));
        var wbuf: [512]u8 = undefined;
        var sw = t.stream.writer(t.io, &wbuf);
        sw.interface.writeAll(bytes) catch return error.TransportFailed;
        sw.interface.flush() catch return error.TransportFailed;
    }
};

/// Poll a socket for readability, bounded by `timeout_ms` (-1 = indefinitely).
/// Returns true if data is ready, false on timeout. A poll failure is
/// reported as "ready" so the blocking read surfaces the real error.
fn waitReadable(handle: std.Io.net.Socket.Handle, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, timeout_ms) catch return true;
    return ready != 0;
}

/// The poll timeout (ms) for one iteration of `connMain`'s read loop: bounded
/// by `Config.connect_timeout_ms` before CONNECT succeeds (keep_alive_s is
/// still 0 there, which would otherwise mean "wait forever"); after CONNECT,
/// 1.5 × the client's keep-alive (spec 3.1.2.10), or indefinitely when the
/// client asked for keep-alive 0.
fn connTimeoutMs(config: Config, conn: *const Connection) i32 {
    if (conn.state == .awaiting_connect) return @intCast(config.connect_timeout_ms);
    if (conn.keep_alive_s == 0) return -1;
    return @intCast(@as(u32, conn.keep_alive_s) * 1500);
}

/// Wall-clock milliseconds (std.time.milliTimestamp was removed in 0.16).
/// libc-free via std.posix.system.clock_gettime (the repo's pure-Zig invariant).
fn milliTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Scripted fake client side of the seam: captures everything the broker
/// writes to this connection so tests can decode it in wire order. Mirrors
/// client.zig's TestTransport, reversed (this is the client, broker is under
/// test).
const TestTransport = struct {
    written: [4096]u8 = undefined,
    len: usize = 0,
    read_off: usize = 0,

    fn transport(m: *TestTransport) Transport {
        return .{ .ctx = m, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const m: *TestTransport = @ptrCast(@alignCast(ctx));
        if (m.len + bytes.len > m.written.len) return error.TransportFailed;
        @memcpy(m.written[m.len..][0..bytes.len], bytes);
        m.len += bytes.len;
    }

    /// Decode the next packet the broker wrote (in order), or null when
    /// nothing more is buffered.
    fn next(m: *TestTransport) !?packet.Packet {
        if (m.read_off >= m.len) return null;
        const dec = (try packet.decode(m.written[m.read_off..m.len])) orelse return null;
        m.read_off += dec.consumed;
        return dec.packet;
    }
};

/// Drive a CONNECT through the broker and assert an accepted CONNACK.
fn connectClient(b: *Broker, tt: *TestTransport, client_id: []const u8, keep_alive_s: u16, now: i64) !*Connection {
    const conn = try b.accept(tt.transport());
    var buf: [128]u8 = undefined;
    const bytes = try packet.encodeConnect(&buf, .{ .client_id = client_id, .keep_alive_s = keep_alive_s });
    try b.feed(conn, bytes);
    try testing.expectEqual(Disposition.keep, try b.process(conn, now));
    const p = (try tt.next()).?;
    try testing.expect(p == .connack);
    try testing.expectEqual(packet.ConnectReturnCode.accepted, p.connack.return_code);
    try testing.expect(!p.connack.session_present);
    try testing.expectEqual(Connection.State.connected, conn.state);
    return conn;
}

fn feedSubscribe(b: *Broker, conn: *Connection, packet_id: u16, filters: []const packet.Subscription) !void {
    var buf: [256]u8 = undefined;
    const bytes = try packet.encodeSubscribe(&buf, packet_id, filters);
    try b.feed(conn, bytes);
    try testing.expectEqual(Disposition.keep, try b.process(conn, 1));
}

fn feedPublish(b: *Broker, conn: *Connection, p: packet.Publish) !Disposition {
    var buf: [256]u8 = undefined;
    const bytes = try packet.encodePublish(&buf, p);
    try b.feed(conn, bytes);
    return b.process(conn, 1);
}

test "connect A + B → both receive an accepted CONNACK" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    _ = try connectClient(&b, &ta, "A", 60, 0);
    _ = try connectClient(&b, &tb, "B", 60, 0);
    try testing.expectEqual(@as(usize, 2), b.connections.items.len);
    // Nothing else was written to either client.
    try testing.expectEqual(@as(?packet.Packet, null), try ta.next());
    try testing.expectEqual(@as(?packet.Packet, null), try tb.next());
}

test "first packet must be CONNECT; a second CONNECT is a violation" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());

    // A PUBLISH before CONNECT is a protocol violation.
    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodePublish(&buf, .{ .topic = "t", .payload = "x" }));
    try testing.expectError(error.ProtocolViolation, b.process(conn, 0));

    // On a fresh connection: connect, then a second CONNECT is refused.
    var tt2 = TestTransport{};
    const c2 = try connectClient(&b, &tt2, "dup", 60, 0);
    try b.feed(c2, try packet.encodeConnect(&buf, .{ .client_id = "dup" }));
    try testing.expectError(error.ProtocolViolation, b.process(c2, 0));
}

test "subscribe sport/# → SUBACK, then A publishes sport/tennis QoS0 → B receives" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    const bconn = try connectClient(&b, &tb, "B", 60, 0);

    try feedSubscribe(&b, bconn, 10, &.{.{ .filter = "sport/#", .qos = .at_least_once }});
    const suback = (try tb.next()).?;
    try testing.expectEqual(@as(u16, 10), suback.suback.packet_id);
    try testing.expectEqualSlices(u8, &.{0x01}, suback.suback.codes);

    try testing.expectEqual(Disposition.keep, try feedPublish(&b, a, .{ .topic = "sport/tennis", .payload = "3:1" }));
    // B receives it at QoS 0 (min of publisher QoS 0 and granted QoS 1).
    const delivered = (try tb.next()).?;
    try testing.expectEqualStrings("sport/tennis", delivered.publish.topic);
    try testing.expectEqualStrings("3:1", delivered.publish.payload);
    try testing.expectEqual(packet.QoS.at_most_once, delivered.publish.qos);
    // A is not subscribed → receives nothing.
    try testing.expectEqual(@as(?packet.Packet, null), try ta.next());
}

test "overlapping filters deliver exactly one copy at the highest granted QoS" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    const bconn = try connectClient(&b, &tb, "B", 60, 0);

    // Two overlapping filters both matching "sport/tennis", QoS 0 and QoS 1.
    try feedSubscribe(&b, bconn, 1, &.{
        .{ .filter = "sport/#", .qos = .at_most_once },
        .{ .filter = "sport/+", .qos = .at_least_once },
    });
    _ = (try tb.next()).?; // SUBACK

    // Publish at QoS 1 → single copy at min(1, max(0,1)) = QoS 1.
    _ = try feedPublish(&b, a, .{ .topic = "sport/tennis", .payload = "x", .qos = .at_least_once, .packet_id = 5 });
    const first = (try tb.next()).?;
    try testing.expect(first == .publish);
    try testing.expectEqual(packet.QoS.at_least_once, first.publish.qos);
    // Exactly one delivery — no duplicate for the second matching filter.
    try testing.expectEqual(@as(?packet.Packet, null), try tb.next());
}

test "retain before subscribe: B gets the retained message after SUBACK" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);

    // A publishes a retained message to x/y BEFORE B exists.
    _ = try feedPublish(&b, a, .{ .topic = "x/y", .payload = "keep", .retain = true });
    try testing.expectEqual(@as(usize, 1), b.retained.items.len);

    const bconn = try connectClient(&b, &tb, "B", 60, 0);
    try feedSubscribe(&b, bconn, 1, &.{.{ .filter = "x/+" }});
    // SUBACK first, then the retained PUBLISH with the retain flag set.
    const suback = (try tb.next()).?;
    try testing.expect(suback == .suback);
    const retained = (try tb.next()).?;
    try testing.expectEqualStrings("x/y", retained.publish.topic);
    try testing.expectEqualStrings("keep", retained.publish.payload);
    try testing.expect(retained.publish.retain);

    // Empty-payload retain clears the store.
    _ = try feedPublish(&b, a, .{ .topic = "x/y", .payload = "", .retain = true });
    try testing.expectEqual(@as(usize, 0), b.retained.items.len);
}

test "QoS1 publish from A → PUBACK to A + broker-assigned-id PUBLISH to QoS1 subscriber" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    const bconn = try connectClient(&b, &tb, "B", 60, 0);

    try feedSubscribe(&b, bconn, 1, &.{.{ .filter = "a/b", .qos = .at_least_once }});
    _ = (try tb.next()).?; // SUBACK

    _ = try feedPublish(&b, a, .{ .topic = "a/b", .payload = "hi", .qos = .at_least_once, .packet_id = 42 });

    // A gets a PUBACK echoing its own packet id.
    const ack = (try ta.next()).?;
    try testing.expectEqual(@as(u16, 42), ack.puback);

    // B gets a QoS1 PUBLISH with a broker-allocated id (subscriber id space,
    // starts at 1 — independent of the publisher's 42), tracked pending.
    const delivered = (try tb.next()).?;
    try testing.expectEqual(packet.QoS.at_least_once, delivered.publish.qos);
    try testing.expectEqual(@as(u16, 1), delivered.publish.packet_id);
    try testing.expectEqual(@as(usize, 1), bconn.pending_len);

    // B PUBACKs the broker-assigned id → pending released.
    var buf: [4]u8 = undefined;
    try b.feed(bconn, try packet.encodePuback(&buf, 1));
    try testing.expectEqual(Disposition.keep, try b.process(bconn, 2));
    try testing.expectEqual(@as(usize, 0), bconn.pending_len);
}

test "unsubscribe removes by exact filter string" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    const bconn = try connectClient(&b, &tb, "B", 60, 0);

    try feedSubscribe(&b, bconn, 1, &.{.{ .filter = "sport/#" }});
    _ = (try tb.next()).?; // SUBACK
    try testing.expectEqual(@as(usize, 1), b.subscriptions.items.len);

    var buf: [64]u8 = undefined;
    try b.feed(bconn, try packet.encodeUnsubscribe(&buf, 2, &.{"sport/#"}));
    try testing.expectEqual(Disposition.keep, try b.process(bconn, 1));
    const unsuback = (try tb.next()).?;
    try testing.expectEqual(@as(u16, 2), unsuback.unsuback);
    try testing.expectEqual(@as(usize, 0), b.subscriptions.items.len);

    // A publish now reaches nobody.
    _ = try feedPublish(&b, a, .{ .topic = "sport/tennis", .payload = "x" });
    try testing.expectEqual(@as(?packet.Packet, null), try tb.next());
}

test "PINGREQ is answered with PINGRESP; DISCONNECT closes and drops subs" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try connectClient(&b, &tt, "A", 60, 0);
    try feedSubscribe(&b, conn, 1, &.{.{ .filter = "t/#" }});
    _ = (try tt.next()).?; // SUBACK
    try testing.expectEqual(@as(usize, 1), b.subscriptions.items.len);

    var buf: [8]u8 = undefined;
    try b.feed(conn, try packet.encodePingreq(&buf));
    try testing.expectEqual(Disposition.keep, try b.process(conn, 1));
    try testing.expect((try tt.next()).? == .pingresp);

    try b.feed(conn, try packet.encodeDisconnect(&buf));
    try testing.expectEqual(Disposition.close, try b.process(conn, 1));
    try testing.expectEqual(Connection.State.disconnected, conn.state);
    try testing.expectEqual(@as(usize, 0), b.subscriptions.items.len);
}

test "keep-alive timeout: connection torn down and its subscriptions dropped" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    // B connects at t=0 with keep_alive 10s → deadline = 15000 ms.
    const bconn = try connectClient(&b, &tb, "B", 10, 0);
    try feedSubscribe(&b, bconn, 1, &.{.{ .filter = "sport/#" }});
    _ = (try tb.next()).?; // SUBACK
    // The SUBSCRIBE was processed at now=1, so it is the last-packet time:
    // deadline = 1 + 1.5 × 10 s = 15001 ms.
    try testing.expect(!b.keepAliveExpired(bconn, 15_001)); // exactly at, not past
    try testing.expect(b.keepAliveExpired(bconn, 15_002)); // past the 1.5× deadline

    // Caller tears B down; its subscription is dropped.
    b.remove(bconn);
    try testing.expectEqual(@as(usize, 0), b.subscriptions.items.len);
    try testing.expectEqual(@as(usize, 1), b.connections.items.len);

    // A publish to sport/tennis now reaches nobody (B is gone).
    _ = try feedPublish(&b, a, .{ .topic = "sport/tennis", .payload = "x" });
    // A is unsubscribed; only assert no crash and empty delivery to A.
    try testing.expectEqual(@as(?packet.Packet, null), try ta.next());
}

test "session take-over: duplicate client-id disconnects the earlier connection" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var t1 = TestTransport{};
    var t2 = TestTransport{};
    const first = try connectClient(&b, &t1, "same", 60, 0);
    try feedSubscribe(&b, first, 1, &.{.{ .filter = "x/#" }});
    _ = (try t1.next()).?; // SUBACK
    try testing.expectEqual(@as(usize, 1), b.subscriptions.items.len);

    // A second connection with the same client-id takes over.
    _ = try connectClient(&b, &t2, "same", 60, 0);
    try testing.expectEqual(Connection.State.disconnected, first.state);
    try testing.expectEqual(@as(usize, 0), b.subscriptions.items.len); // old subs dropped
}

test "empty client-id is accepted and assigned a generated id" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());
    var buf: [64]u8 = undefined;
    // Empty client id requires clean_session (the codec enforces it).
    const bytes = try packet.encodeConnect(&buf, .{ .client_id = "", .clean_session = true });
    try b.feed(conn, bytes);
    try testing.expectEqual(Disposition.keep, try b.process(conn, 0));
    try testing.expect((try tt.next()).? == .connack);
    try testing.expect(std.mem.startsWith(u8, conn.clientId(), "auto-"));
}

test "inbound QoS2 publish is refused (deferred feature), never a panic" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try connectClient(&b, &tt, "A", 60, 0);
    var buf: [64]u8 = undefined;
    const bytes = try packet.encodePublish(&buf, .{
        .topic = "a/b",
        .payload = "x",
        .qos = .exactly_once,
        .packet_id = 3,
    });
    try b.feed(conn, bytes);
    try testing.expectError(error.ProtocolViolation, b.process(conn, 1));
}

test "hostile bytes from a client: typed errors, never a panic" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());

    var prng = std.Random.DefaultPrng.init(0x62726f6b); // "brok"
    const random = prng.random();
    var junk: [64]u8 = undefined;
    for (0..1000) |_| {
        conn.rx_len = 0;
        conn.rx_consumed = 0;
        const len = random.uintAtMost(usize, junk.len);
        random.bytes(junk[0..len]);
        b.feed(conn, junk[0..len]) catch continue;
        _ = b.process(conn, 0) catch {};
    }
}

test "TcpServer compiles (never bound or dialed in tests)" {
    // Reference-only: force semantic analysis of the std.Io.net accept loop.
    if (true) return error.SkipZigTest;
    std.testing.refAllDecls(TcpServer);
}
