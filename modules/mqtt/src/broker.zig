// SPDX-License-Identifier: MIT

//! MQTT 3.1.1 broker (server) — QoS 0 + 1, clean session, no TLS.
//!
//! The mirror image of `client.zig`. Where the client drives one connection
//! *to* a broker, the `Broker` here owns the shared server-side state — the
//! set of connections, the subscription index and the retained store — and
//! each `Connection` is a reversed per-connection state machine: the first
//! packet it must see is a CONNECT (spec 3.1), it answers CONNACK / SUBACK /
//! UNSUBACK / PUBACK / PINGRESP, and PUBLISH packets fan out to every matching
//! subscription.
//!
//! Caller-driven, socket-free core (exactly the `client.zig` seam, reversed):
//! outgoing bytes to a client go through that connection's `Transport` write
//! seam; incoming bytes are handed to `Broker.feed`; `Broker.process(conn,
//! now)` decodes buffered packets, advances the connection's state machine
//! and performs fan-out. `now` (caller's monotonic clock, ms) is passed in —
//! the broker reads no clock itself — so the whole broker is drivable from
//! in-memory buffers in tests, no socket required. `TcpServer` is an optional
//! real-socket accept loop over `std.Io.net` (thread-per-connection); tests
//! never listen or dial.
//!
//! Concurrency (production-hardened):
//!  - The shared registry (connection set, subscription index, retained store)
//!    is guarded by `Broker.mutex`, a tiny atomic spinlock (`std.Thread.Mutex`
//!    was removed in 0.16 and `std.Io.Mutex` needs an `Io` the offline core
//!    must not require). Critical sections are short and NEVER span socket
//!    I/O: `handlePublish` takes the lock only to update the retained store
//!    and snapshot the matching (conn, granted-QoS) set (via the subscription
//!    index — no O(total-subscriptions) scan), then releases it before the
//!    per-subscriber writes, so a large fan-out cannot stall `accept()` or any
//!    other client (FIX A).
//!  - Each `Connection` carries its own `tx_lock` guarding its `tx_buf`,
//!    packet-id pool and socket writes — so a subscriber can be written to
//!    concurrently by many fan-out threads plus its own owner thread without
//!    corrupting a shared buffer or interleaving bytes on the wire.
//!  - A fan-out reader takes a reference (`refs`) on each target under the
//!    global lock; `remove()` unlinks a connection under the same lock (so no
//!    new reference can be taken) then waits for outstanding references to
//!    drain before freeing — a subscriber that disconnects mid-fan-out is
//!    never written to freed memory (FIX A).
//!
//! Scope (spec 3.1.1): CONNECT/CONNACK (protocol validated by the codec,
//! client-id assigned/rejected, session take-over on a duplicate client-id —
//! which now also closes the superseded socket so its owner thread is promptly
//! reaped, FIX C; `session_present` always false / clean session only),
//! optional authentication + per-operation ACL hooks (FIX D), SUBSCRIBE/SUBACK
//! and UNSUBSCRIBE/UNSUBACK over a topic-filter trie index, PUBLISH fan-out at
//! min(publisher QoS, granted QoS) with a per-subscriber delivery failure
//! contained to that subscriber (never the publisher, FIX B), a retained store,
//! and resource caps (max_connections / max_subscriptions_total /
//! max_subscriptions_per_conn / max_retained / connect_timeout_ms).
//!
//! Deliberately deferred (documented, not built): QoS 2 (an inbound QoS 2
//! PUBLISH is a protocol violation that tears the connection down), persistent
//! / offline sessions (clean-session only), DUP retransmit of an unacked
//! outbound QoS 1 publish, Will / LWT, MQTT 5.0, and TLS (terminate it in front
//! and hand `TcpServer` the plaintext, or drive the socket-free core over a TLS
//! stream yourself).
//!
//! Provenance: clean-room from the OASIS MQTT 3.1.1 specification;
//! mosquitto/Paho referenced for behavior only, no source consulted or copied.

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

/// Largest username the broker stores inline for ACL identity (a longer one is
/// simply not retained — the ACL hook then sees a null username).
pub const max_username = 256;

/// Largest SUBSCRIBE the broker answers in one SUBACK (filters per packet).
pub const max_filters_per_subscribe = 64;

/// Headroom (bytes) added to every connection's `tx_buf` beyond
/// `max_packet_size` so a QoS 0 → QoS 1 re-encode for a subscriber (packet id
/// + a possible remaining-length varint growth) can never overflow the buffer
/// — the delivery failure that FIX B contains cannot arise from sizing at all.
pub const tx_headroom = 16;

/// Cap on the number of `/`-levels in a subscription filter. Bounds the trie
/// height (hence the fan-out match recursion depth) against a pathological
/// deeply-nested filter; a longer filter is refused with SUBACK 0x80.
pub const max_filter_levels = 128;

/// Failures a `Transport` implementation may report.
pub const TransportError = error{TransportFailed};

/// Outgoing byte seam to one connected client (reversed `client.Transport`).
/// Implementations must take all bytes or fail; the broker never retries
/// partial writes. The optional `closeFn` lets the broker signal a superseded
/// connection's read loop to exit on session take-over (FIX C).
pub const Transport = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) TransportError!void,
    /// Optional: shut the underlying socket down so a blocked read wakes and
    /// the owner thread reaps the connection. Null = no-op (offline core).
    closeFn: ?*const fn (ctx: *anyopaque) void = null,

    pub fn write(t: Transport, bytes: []const u8) TransportError!void {
        return t.writeFn(t.ctx, bytes);
    }

    pub fn close(t: Transport) void {
        if (t.closeFn) |f| f(t.ctx);
    }
};

/// Errors surfaced by `process`. A decode error or a protocol violation means
/// the offending connection must be torn down (`remove`).
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
// A tiny atomic spinlock keeps the shared registry / retained store /
// connection set safe under the thread-per-connection `TcpServer` without
// libc or an `Io`. Also reused per-connection as `tx_lock`. Uncontended (the
// single-threaded offline tests) it is a bare acquire/release.

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
/// reassembly) and a transmit scratch buffer used to encode PUBLISH packets
/// routed to this client. Its subscription filter strings are owned here (the
/// index stores only `(conn, qos)` references keyed by these strings).
pub const Connection = struct {
    transport: Transport,
    rx_buf: []u8,
    rx_len: usize = 0,
    rx_consumed: usize = 0,
    /// Sized `max_packet_size + tx_headroom` (FIX B).
    tx_buf: []u8,
    /// Guards `tx_buf`, `pending`, and serializes socket writes to this
    /// connection (owner-thread responses + concurrent fan-out deliveries).
    tx_lock: Mutex = .{},

    state: State = .awaiting_connect,
    client_id_buf: [max_client_id]u8 = undefined,
    client_id_len: usize = 0,
    username_buf: [max_username]u8 = undefined,
    username_len: usize = 0,
    has_username: bool = false,
    keep_alive_s: u16 = 0,
    /// Timestamp (caller clock, ms) of the last packet decoded from this
    /// connection — the keep-alive reference point.
    last_packet_ms: i64 = 0,

    // Outbound QoS 1 delivery to this subscriber: ids allocated in *this*
    // connection's space, pending until the client's PUBACK. Guarded by
    // `tx_lock`.
    next_packet_id: u16 = 1,
    pending: [max_in_flight]u16 = undefined,
    pending_len: usize = 0,

    /// This connection's own subscription filters (owned strings). Gives the
    /// per-connection subscription count and the list to drop on teardown;
    /// the trie index references these connections by pointer + granted QoS.
    subs: std.ArrayListUnmanaged([]u8) = .empty,

    /// Fan-out liveness (FIX A). Incremented under `Broker.mutex` by a fan-out
    /// reader that is about to write to this connection, decremented lock-free
    /// when the write completes. `remove()` unlinks the connection under the
    /// global lock (so no new reference can be taken) then spins on this until
    /// it drains before freeing — no write ever lands on freed memory.
    refs: std.atomic.Value(u32) = .init(0),

    pub const State = enum { awaiting_connect, connected, disconnected };

    pub fn clientId(c: *const Connection) []const u8 {
        return c.client_id_buf[0..c.client_id_len];
    }

    /// The authenticated username threaded onto the connection (FIX D), or
    /// null when the client sent none (or it was too long to retain).
    pub fn usernameOpt(c: *const Connection) ?[]const u8 {
        return if (c.has_username) c.username_buf[0..c.username_len] else null;
    }

    fn setClientId(c: *Connection, id: []const u8) error{ClientIdTooLong}!void {
        if (id.len > c.client_id_buf.len) return error.ClientIdTooLong;
        @memcpy(c.client_id_buf[0..id.len], id);
        c.client_id_len = id.len;
    }

    /// Raw write — assumes `tx_lock` is held (fan-out / SUBACK-retained path).
    fn write(c: *Connection, bytes: []const u8) Error!void {
        c.transport.write(bytes) catch return error.TransportFailed;
    }

    /// Take `tx_lock` for a standalone control-packet write (CONNACK / PUBACK /
    /// UNSUBACK / PINGRESP), serializing it against concurrent fan-out writes.
    fn lockedWrite(c: *Connection, bytes: []const u8) Error!void {
        c.tx_lock.lock();
        defer c.tx_lock.unlock();
        return c.write(bytes);
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
    /// skips ids still in flight); null when the pool is exhausted. Caller
    /// holds `tx_lock`.
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

// ── subscription index: a topic-filter trie (FIX A) ─────────────────────────
// Replaces the old flat O(total-subscriptions) scan per PUBLISH. Filters are
// split on '/'; a literal level is an exact child, '+' a dedicated single-level
// wildcard child, and '#' (only ever the last level, enforced by
// `topic.validateFilter`) attaches to the *current* node's `hash_subs` so it
// also matches that node's own level (spec 4.7.1-2). Matching a published topic
// visits only nodes along the topic's path (bounded by the trie height), never
// the whole subscription set. The `$`-topic exclusion (a leading-wildcard
// filter never matches a `$`-prefixed topic, spec 4.7.2-1) is honored at the
// root by skipping `plus` / `hash_subs` there — exactly `topic.matches`'s rule.

/// A subscribing connection reference stored in the trie (the filter string is
/// implicit in the path and owned by the connection).
const SubRef = struct { conn: *Connection, qos: QoS };

const Node = struct {
    children: std.StringHashMapUnmanaged(*Node) = .empty,
    plus: ?*Node = null,
    /// Filters that terminate exactly here (no trailing '#').
    subs: std.ArrayListUnmanaged(SubRef) = .empty,
    /// Filters of the form `<path-to-here>/#` (or bare `#` at the root).
    hash_subs: std.ArrayListUnmanaged(SubRef) = .empty,

    fn isEmpty(n: *const Node) bool {
        return n.children.count() == 0 and n.plus == null and
            n.subs.items.len == 0 and n.hash_subs.items.len == 0;
    }
};

const Index = struct {
    root: Node = .{},

    fn deinit(idx: *Index, alloc: std.mem.Allocator) void {
        freeNode(alloc, &idx.root, true);
    }

    fn freeNode(alloc: std.mem.Allocator, node: *Node, is_root: bool) void {
        var it = node.children.iterator();
        while (it.next()) |e| {
            freeNode(alloc, e.value_ptr.*, false);
            alloc.free(e.key_ptr.*);
        }
        node.children.deinit(alloc);
        if (node.plus) |p| freeNode(alloc, p, false);
        node.subs.deinit(alloc);
        node.hash_subs.deinit(alloc);
        if (!is_root) alloc.destroy(node);
    }

    /// Register `(conn, qos)` under `filter`. Creates trie nodes as needed.
    fn add(idx: *Index, alloc: std.mem.Allocator, filter: []const u8, conn: *Connection, qos: QoS) Error!void {
        var node = &idx.root;
        var it = std.mem.splitScalar(u8, filter, '/');
        while (it.next()) |level| {
            if (std.mem.eql(u8, level, "#")) {
                try node.hash_subs.append(alloc, .{ .conn = conn, .qos = qos });
                return;
            }
            if (std.mem.eql(u8, level, "+")) {
                if (node.plus == null) {
                    const child = try alloc.create(Node);
                    child.* = .{};
                    node.plus = child;
                }
                node = node.plus.?;
            } else if (node.children.get(level)) |child| {
                node = child;
            } else {
                const key = try alloc.dupe(u8, level);
                errdefer alloc.free(key);
                const child = try alloc.create(Node);
                errdefer alloc.destroy(child);
                child.* = .{};
                try node.children.put(alloc, key, child);
                node = child;
            }
        }
        try node.subs.append(alloc, .{ .conn = conn, .qos = qos });
    }

    /// Update the granted QoS of an existing `(conn, filter)` (re-subscribe).
    fn updateQos(idx: *Index, filter: []const u8, conn: *Connection, qos: QoS) void {
        var node = &idx.root;
        var it = std.mem.splitScalar(u8, filter, '/');
        while (it.next()) |level| {
            if (std.mem.eql(u8, level, "#")) return setQosIn(&node.hash_subs, conn, qos);
            if (std.mem.eql(u8, level, "+")) {
                node = node.plus orelse return;
            } else {
                node = node.children.get(level) orelse return;
            }
        }
        setQosIn(&node.subs, conn, qos);
    }

    fn setQosIn(list: *std.ArrayListUnmanaged(SubRef), conn: *Connection, qos: QoS) void {
        for (list.items) |*r| {
            if (r.conn == conn) {
                r.qos = qos;
                return;
            }
        }
    }

    fn removeRefFrom(list: *std.ArrayListUnmanaged(SubRef), conn: *Connection) void {
        for (list.items, 0..) |r, i| {
            if (r.conn == conn) {
                _ = list.swapRemove(i);
                return;
            }
        }
    }

    /// Remove `(conn, filter)` and prune any nodes left empty.
    fn removeFilter(idx: *Index, alloc: std.mem.Allocator, filter: []const u8, conn: *Connection) void {
        var levels: [max_filter_levels][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, filter, '/');
        while (it.next()) |level| {
            if (n >= max_filter_levels) return; // never registered (rejected at add)
            levels[n] = level;
            n += 1;
        }
        _ = removeRec(alloc, &idx.root, levels[0..n], conn);
    }

    /// Returns whether `node` became empty (and was pruned by the caller).
    fn removeRec(alloc: std.mem.Allocator, node: *Node, levels: [][]const u8, conn: *Connection) bool {
        if (levels.len == 0) {
            removeRefFrom(&node.subs, conn);
            return node.isEmpty();
        }
        const head = levels[0];
        if (std.mem.eql(u8, head, "#")) {
            removeRefFrom(&node.hash_subs, conn);
            return node.isEmpty();
        }
        if (std.mem.eql(u8, head, "+")) {
            if (node.plus) |p| {
                if (removeRec(alloc, p, levels[1..], conn)) {
                    freeNode(alloc, p, false);
                    node.plus = null;
                }
            }
            return node.isEmpty();
        }
        if (node.children.getEntry(head)) |e| {
            const child = e.value_ptr.*;
            const key = e.key_ptr.*;
            if (removeRec(alloc, child, levels[1..], conn)) {
                _ = node.children.remove(head);
                alloc.free(key);
                freeNode(alloc, child, false);
            }
        }
        return node.isEmpty();
    }

    /// Collect every `(conn, qos)` whose filter matches `topic_name` into
    /// `out`. Duplicates (a connection matching via several overlapping
    /// filters) are collapsed later by the caller.
    fn collect(idx: *Index, alloc: std.mem.Allocator, topic_name: []const u8, out: *std.ArrayListUnmanaged(SubRef)) Error!void {
        const dollar = topic_name.len > 0 and topic_name[0] == '$';
        try collectRec(alloc, &idx.root, topic_name, true, dollar, out);
    }

    fn collectRec(
        alloc: std.mem.Allocator,
        node: *Node,
        rest: ?[]const u8,
        is_root: bool,
        dollar: bool,
        out: *std.ArrayListUnmanaged(SubRef),
    ) Error!void {
        // '#' at this node matches zero-or-more remaining levels — except a
        // leading wildcard against a '$'-topic.
        if (!(is_root and dollar)) try appendAll(alloc, out, &node.hash_subs);

        const cur = rest orelse {
            // Topic fully consumed → exact terminal subs at this node match.
            try appendAll(alloc, out, &node.subs);
            return;
        };
        const slash = std.mem.indexOfScalar(u8, cur, '/');
        const head = cur[0 .. slash orelse cur.len];
        const tail: ?[]const u8 = if (slash) |s| cur[s + 1 ..] else null;

        if (node.children.get(head)) |child|
            try collectRec(alloc, child, tail, false, dollar, out);
        if (!(is_root and dollar)) {
            if (node.plus) |p| try collectRec(alloc, p, tail, false, dollar, out);
        }
    }

    fn appendAll(alloc: std.mem.Allocator, out: *std.ArrayListUnmanaged(SubRef), list: *std.ArrayListUnmanaged(SubRef)) Error!void {
        for (list.items) |r| try out.append(alloc, r);
    }
};

// ── the broker ──────────────────────────────────────────────────────────────

/// One retained message: topic + payload copies the broker owns, plus the QoS
/// it was published at (delivery downgrades to the subscriber's grant).
const Retained = struct {
    topic: []u8,
    payload: []u8,
    qos: QoS,
};

// ── authentication / ACL hooks (FIX D) ──────────────────────────────────────
// Optional, default allow-all (backward compatible). Function pointers + an
// opaque context — a clean seam, no external deps. The authenticated identity
// (client id + username) is threaded onto the connection so the ACL hook sees
// it on every PUBLISH / SUBSCRIBE.

/// Result of the authentication hook. A deny maps to the CONNACK return code
/// the client is sent before the connection is closed.
pub const AuthDecision = enum { allow, deny_not_authorized, deny_bad_credentials };

/// What the authentication hook is given at CONNECT time.
pub const AuthRequest = struct {
    client_id: []const u8,
    username: ?[]const u8,
    password: ?[]const u8,
};

/// The operation an ACL check authorizes.
pub const Operation = enum { publish, subscribe };

/// What the ACL hook is given per PUBLISH / SUBSCRIBE.
pub const AclRequest = struct {
    client_id: []const u8,
    username: ?[]const u8,
    topic: []const u8,
    operation: Operation,
};

pub const Config = struct {
    /// Per-connection receive buffer size; bounds the largest packet the
    /// broker accepts from a client. The transmit buffer is this plus
    /// `tx_headroom` (FIX B).
    max_packet_size: usize = 8 * 1024,
    /// Hard cap on live connections; `accept` refuses (closes) past this.
    max_connections: usize = 1024,
    /// Hard cap on subscriptions across the whole broker; a new filter past
    /// this is refused with SUBACK 0x80 rather than growing unboundedly.
    max_subscriptions_total: usize = 65536,
    /// Hard cap on subscriptions held by one connection.
    max_subscriptions_per_conn: usize = 1024,
    /// Hard cap on distinct retained topics; a genuinely new topic past this
    /// is refused (existing retained topics may still be updated in place).
    max_retained: usize = 8192,
    /// Bounded idle window (ms) a connection is given to send its CONNECT
    /// before the accept loop drops it. Only consulted by `TcpServer`.
    connect_timeout_ms: u32 = 10_000,

    /// Optional authentication hook (FIX D). Null = allow every CONNECT.
    /// Invoked in `handleConnect` with the client id + credentials; a deny
    /// sends the mapped CONNACK return code and closes the connection.
    authenticateFn: ?*const fn (ctx: ?*anyopaque, req: AuthRequest) AuthDecision = null,
    auth_ctx: ?*anyopaque = null,

    /// Optional per-operation ACL hook (FIX D). Null = allow every operation.
    /// A denied SUBSCRIBE yields per-filter SUBACK 0x80; a denied PUBLISH is
    /// silently dropped (not fanned out, not retained) while the publisher is
    /// still PUBACKed (QoS 1) so it stays well-behaved.
    authorizeFn: ?*const fn (ctx: ?*anyopaque, req: AclRequest) bool = null,
    acl_ctx: ?*anyopaque = null,
};

/// One retained message snapshotted (owned dups) under the global lock for
/// delivery to a fresh subscriber after its SUBACK — so the delivery writes
/// happen off the lock like every other fan-out.
const RetSnap = struct { topic: []u8, payload: []u8, qos: QoS };

/// One fan-out target: a subscribing connection and the (already merged, still
/// uncapped by the publisher's QoS) highest granted QoS among its filters.
const Target = struct { conn: *Connection, qos: QoS };

/// The shared server-side state. Offline-testable: `accept` registers a
/// `Transport`, `feed` + `process` drive a connection, `remove` tears it down —
/// no sockets involved.
pub const Broker = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: Mutex = .{},

    connections: std.ArrayList(*Connection) = .empty,
    index: Index = .{},
    subscriptions_total: usize = 0,
    retained: std.ArrayList(Retained) = .empty,
    next_auto_id: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) Broker {
        return .{ .allocator = allocator, .config = config };
    }

    /// Free every connection, subscription and retained message.
    pub fn deinit(b: *Broker) void {
        for (b.connections.items) |conn| b.freeConnection(conn);
        b.connections.deinit(b.allocator);
        b.index.deinit(b.allocator);
        for (b.retained.items) |r| {
            b.allocator.free(r.topic);
            b.allocator.free(r.payload);
        }
        b.retained.deinit(b.allocator);
        b.* = undefined;
    }

    /// Total live subscriptions across all connections (the flat count the
    /// old registry exposed as `subscriptions.items.len`).
    pub fn subscriptionCount(b: *const Broker) usize {
        return b.subscriptions_total;
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
        // FIX B: extra headroom so a QoS 0 → QoS 1 re-encode can never overflow.
        const tx = try b.allocator.alloc(u8, b.config.max_packet_size + tx_headroom);
        errdefer b.allocator.free(tx);
        conn.* = .{ .transport = transport, .rx_buf = rx, .tx_buf = tx };
        try b.connections.append(b.allocator, conn);
        return conn;
    }

    /// Tear a connection down: drop its subscriptions, unlink it, wait for any
    /// in-flight fan-out writers to release their references (FIX A), then free
    /// its memory. Idempotent w.r.t. subscriptions.
    pub fn remove(b: *Broker, conn: *Connection) void {
        {
            b.mutex.lock();
            defer b.mutex.unlock();
            b.dropSubscriptions(conn);
            if (std.mem.indexOfScalar(*Connection, b.connections.items, conn)) |i| {
                _ = b.connections.swapRemove(i);
            }
            conn.state = .disconnected;
        }
        // Unlinked under the lock above (and dropped from the index), so no new
        // fan-out reference can be taken. Drain the outstanding ones before we
        // free the connection's memory — a concurrent PUBLISH mid-write must
        // never land on freed `tx_buf` / socket ctx.
        while (conn.refs.load(.acquire) != 0) std.atomic.spinLoopHint();
        b.freeConnection(conn);
    }

    fn freeConnection(b: *Broker, conn: *Connection) void {
        for (conn.subs.items) |f| b.allocator.free(f);
        conn.subs.deinit(b.allocator);
        b.allocator.free(conn.rx_buf);
        b.allocator.free(conn.tx_buf);
        b.allocator.destroy(conn);
    }

    /// Buffer bytes received from this connection's client (any framing).
    /// Touches only the connection's own rx buffer — no lock (one thread owns
    /// a connection's read side).
    pub fn feed(b: *Broker, conn: *Connection, bytes: []const u8) error{RxBufferFull}!void {
        _ = b;
        conn.compact();
        if (conn.rx_len + bytes.len > conn.rx_buf.len) return error.RxBufferFull;
        @memcpy(conn.rx_buf[conn.rx_len..][0..bytes.len], bytes);
        conn.rx_len += bytes.len;
    }

    /// Decode every complete packet currently buffered for `conn`, advance its
    /// state machine and fan out PUBLISHes. `now` is the caller's clock (ms) —
    /// recorded as the connection's last-packet time for keep-alive. Returns
    /// `.close` once the connection should be torn down.
    ///
    /// The global registry lock is NOT held across this call: each handler
    /// takes it only for its short shared-state mutation (and never across a
    /// socket write), so a PUBLISH fan-out cannot stall `accept()` (FIX A). The
    /// rx buffer + state machine are single-owner (this thread) and need no
    /// lock.
    pub fn process(b: *Broker, conn: *Connection, now: i64) Error!Disposition {
        while (true) {
            conn.compact();
            const dec = (try packet.decode(conn.rx_buf[0..conn.rx_len])) orelse return .keep;
            conn.rx_consumed = dec.consumed;
            conn.last_packet_ms = now;
            if (try b.handle(conn, dec.packet, now) == .close) return .close;
        }
    }

    /// True when the keep-alive deadline (1.5 × the client's keep-alive) has
    /// passed relative to the last packet (spec 3.1.2.10). Keep-alive 0
    /// disables the mechanism. Lock-free read of connection-local fields.
    pub fn keepAliveExpired(b: *const Broker, conn: *const Connection, now: i64) bool {
        _ = b;
        if (conn.keep_alive_s == 0) return false;
        const deadline = conn.last_packet_ms + @as(i64, conn.keep_alive_s) * 1500;
        return now > deadline;
    }

    // ── packet handling ──────────────────────────────────────────────────────

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
                    conn.tx_lock.lock();
                    conn.removePending(id);
                    conn.tx_lock.unlock();
                    return .keep;
                },
                .pingreq => {
                    var buf: [2]u8 = undefined;
                    try conn.lockedWrite(try packet.encodePingresp(&buf));
                    return .keep;
                },
                .disconnect => {
                    // Clean session: routing state is dropped on disconnect.
                    b.mutex.lock();
                    b.dropSubscriptions(conn);
                    conn.state = .disconnected;
                    b.mutex.unlock();
                    return .close;
                },
                // QoS 2 (PUBREC/PUBREL/PUBCOMP) is deferred; anything a client
                // must not send to a server is a violation.
                else => return error.ProtocolViolation,
            },
        }
    }

    fn handleConnect(b: *Broker, conn: *Connection, c: packet.Connect, now: i64) Error!Disposition {
        // The codec already validated the protocol name/level and rejected an
        // empty client-id without clean session. Assign or generate the id.
        if (c.client_id.len == 0) {
            var idbuf: [max_client_id]u8 = undefined;
            b.mutex.lock();
            const gen = std.fmt.bufPrint(&idbuf, "auto-{d}", .{b.next_auto_id}) catch unreachable;
            b.next_auto_id += 1;
            b.mutex.unlock();
            conn.setClientId(gen) catch unreachable;
        } else conn.setClientId(c.client_id) catch {
            var cbuf: [4]u8 = undefined;
            try conn.lockedWrite(try packet.encodeConnack(&cbuf, .{
                .session_present = false,
                .return_code = .identifier_rejected,
            }));
            return .close;
        };

        // Thread the identity onto the connection so the ACL hook can see it.
        if (c.username) |uname| {
            if (uname.len <= conn.username_buf.len) {
                @memcpy(conn.username_buf[0..uname.len], uname);
                conn.username_len = uname.len;
                conn.has_username = true;
            }
        }

        // Authentication hook (FIX D). Checked BEFORE take-over so an
        // unauthorized new connection cannot disturb a live session.
        if (b.config.authenticateFn) |authFn| {
            const decision = authFn(b.config.auth_ctx, .{
                .client_id = conn.clientId(),
                .username = conn.usernameOpt(),
                .password = c.password,
            });
            const rc: ?packet.ConnectReturnCode = switch (decision) {
                .allow => null,
                .deny_not_authorized => .not_authorized,
                .deny_bad_credentials => .bad_username_or_password,
            };
            if (rc) |code| {
                var cbuf: [4]u8 = undefined;
                try conn.lockedWrite(try packet.encodeConnack(&cbuf, .{
                    .session_present = false,
                    .return_code = code,
                }));
                return .close;
            }
        }

        // Session take-over: a live connection with the same client-id is
        // disconnected (spec 3.1.4-2), its routing state dropped and — FIX C —
        // its socket shut down so its owner thread wakes and reaps it. Clean
        // session → no state carried over.
        {
            b.mutex.lock();
            defer b.mutex.unlock();
            b.takeover(conn);
            conn.keep_alive_s = c.keep_alive_s;
            conn.last_packet_ms = now;
            conn.state = .connected;
        }

        var cbuf: [4]u8 = undefined;
        try conn.lockedWrite(try packet.encodeConnack(&cbuf, .{
            .session_present = false, // clean session only
            .return_code = .accepted,
        }));
        return .keep;
    }

    /// Caller holds `mutex`. Supersede any live connection sharing the new
    /// connection's client-id.
    fn takeover(b: *Broker, newconn: *Connection) void {
        const id = newconn.clientId();
        for (b.connections.items) |other| {
            if (other == newconn) continue;
            if (other.state == .disconnected) continue;
            if (std.mem.eql(u8, other.clientId(), id)) {
                b.dropSubscriptions(other);
                other.state = .disconnected;
                // FIX C: wake its (possibly keep_alive_0, forever-blocked) read
                // loop. We do NOT free it here — its own owner thread frees it
                // via `remove`; that path drains references safely.
                other.transport.close();
            }
        }
    }

    fn handleSubscribe(b: *Broker, conn: *Connection, s: packet.Subscribe) Error!void {
        // Validate the filter count BEFORE registering anything (a >max
        // SUBSCRIBE is rejected as a whole, never partial-registered).
        var count: usize = 0;
        var count_it = s.iterator();
        while (count_it.next()) |_| {
            count += 1;
            if (count > max_filters_per_subscribe) return error.TooManySubscriptions;
        }

        var codes: [max_filters_per_subscribe]u8 = undefined;
        var n: usize = 0;

        // Retained messages matching a newly-granted filter, snapshotted (owned
        // dups) under the lock so their delivery writes happen off it.
        var retsnap: std.ArrayListUnmanaged(RetSnap) = .empty;
        defer {
            for (retsnap.items) |r| {
                b.allocator.free(r.topic);
                b.allocator.free(r.payload);
            }
            retsnap.deinit(b.allocator);
        }

        {
            b.mutex.lock();
            defer b.mutex.unlock();
            var it = s.iterator();
            while (it.next()) |req| {
                var code: u8 = packet.suback_failure;
                var granted: QoS = .at_most_once;
                var ok = false;
                if (topic.validateFilter(req.filter)) |_| {
                    if (b.aclAllows(conn, req.filter, .subscribe)) {
                        granted = minQos(req.qos, .at_least_once); // support up to QoS 1
                        if (try b.registerSubscription(conn, req.filter, granted)) {
                            code = @intFromEnum(granted);
                            ok = true;
                        }
                        // else: over a cap → per-filter 0x80 (code unchanged).
                    }
                    // else: ACL denied this filter → per-filter 0x80.
                } else |_| {}
                codes[n] = code;
                n += 1;
                if (ok) {
                    for (b.retained.items) |r| {
                        if (topic.matches(req.filter, r.topic)) {
                            const t = try b.allocator.dupe(u8, r.topic);
                            const pl = b.allocator.dupe(u8, r.payload) catch |e| {
                                b.allocator.free(t);
                                return e;
                            };
                            retsnap.append(b.allocator, .{
                                .topic = t,
                                .payload = pl,
                                .qos = minQos(r.qos, granted),
                            }) catch |e| {
                                b.allocator.free(t);
                                b.allocator.free(pl);
                                return e;
                            };
                        }
                    }
                }
            }
            if (n == 0) return error.ProtocolViolation; // empty SUBSCRIBE (spec 3.8.3-3)
        }

        // SUBACK first (spec 3.9), then the matching retained messages
        // (spec 3.3.1.3) — both under this connection's tx_lock.
        conn.tx_lock.lock();
        defer conn.tx_lock.unlock();
        var sbuf: [4 + max_filters_per_subscribe]u8 = undefined;
        try conn.write(try packet.encodeSuback(&sbuf, s.packet_id, codes[0..n]));
        for (retsnap.items) |r| {
            try b.deliverLocked(conn, r.topic, r.payload, r.qos, true);
        }
    }

    /// Add (or, for an exact re-subscribe, update the QoS of) a subscription.
    /// Returns `false` (no mutation) when a cap would be exceeded by a
    /// genuinely new filter, or the filter is too deeply nested — the caller
    /// reports that as a per-filter SUBACK 0x80. Caller holds `mutex`.
    fn registerSubscription(b: *Broker, conn: *Connection, filter: []const u8, qos: QoS) Error!bool {
        for (conn.subs.items) |f| {
            if (std.mem.eql(u8, f, filter)) {
                b.index.updateQos(filter, conn, qos); // re-subscribe (spec 3.8.4-3)
                return true;
            }
        }
        if (b.subscriptions_total >= b.config.max_subscriptions_total) return false;
        if (conn.subs.items.len >= b.config.max_subscriptions_per_conn) return false;
        var level_count: usize = 0;
        var lv = std.mem.splitScalar(u8, filter, '/');
        while (lv.next()) |_| {
            level_count += 1;
            if (level_count > max_filter_levels) return false;
        }

        const owned = try b.allocator.dupe(u8, filter);
        errdefer b.allocator.free(owned);
        try conn.subs.append(b.allocator, owned);
        errdefer conn.subs.items.len -= 1; // undo the append on a later failure
        try b.index.add(b.allocator, filter, conn, qos);
        b.subscriptions_total += 1;
        return true;
    }

    fn handleUnsubscribe(b: *Broker, conn: *Connection, u: packet.Unsubscribe) Error!void {
        {
            b.mutex.lock();
            defer b.mutex.unlock();
            var it = u.iterator();
            while (it.next()) |filter| {
                var i: usize = 0;
                while (i < conn.subs.items.len) {
                    if (std.mem.eql(u8, conn.subs.items[i], filter)) {
                        b.index.removeFilter(b.allocator, filter, conn);
                        b.allocator.free(conn.subs.items[i]);
                        _ = conn.subs.swapRemove(i);
                        b.subscriptions_total -= 1;
                        continue; // a filter appears once per conn; scan on defensively
                    }
                    i += 1;
                }
            }
        }
        var ubuf: [4]u8 = undefined;
        try conn.lockedWrite(try packet.encodeUnsuback(&ubuf, u.packet_id));
    }

    fn handlePublish(b: *Broker, conn: *Connection, pub_pkt: packet.Publish) Error!Disposition {
        // QoS 2 inbound is deferred: refuse and tear the connection down.
        if (pub_pkt.qos == .exactly_once) return error.ProtocolViolation;

        // ACL (FIX D): a denied PUBLISH is silently dropped — not retained, not
        // fanned out — but still PUBACKed so the publisher stays well-behaved.
        if (b.aclAllows(conn, pub_pkt.topic, .publish)) {
            try b.fanout(conn, pub_pkt);
        }

        // Acknowledge an inbound QoS 1 publish (QoS 0: nothing).
        if (pub_pkt.qos == .at_least_once) {
            var buf: [4]u8 = undefined;
            try conn.lockedWrite(try packet.encodePuback(&buf, pub_pkt.packet_id));
        }
        return .keep;
    }

    /// Retained-store update + PUBLISH fan-out. The global lock is held only to
    /// mutate the retained store and snapshot the matching (conn, granted-QoS)
    /// targets from the index (FIX A); it is released before any socket write.
    /// A per-subscriber delivery failure is contained to that subscriber and
    /// never propagates to the publisher (FIX B).
    fn fanout(b: *Broker, conn: *Connection, pub_pkt: packet.Publish) Error!void {
        _ = conn;
        var targets: std.ArrayListUnmanaged(Target) = .empty;
        defer targets.deinit(b.allocator);

        {
            b.mutex.lock();
            defer b.mutex.unlock();

            // Retained store (spec 3.3.1.3): empty payload clears, else set.
            if (pub_pkt.retain) {
                if (pub_pkt.payload.len == 0) {
                    b.clearRetained(pub_pkt.topic);
                } else {
                    try b.storeRetained(pub_pkt.topic, pub_pkt.payload, pub_pkt.qos);
                }
            }

            var matches: std.ArrayListUnmanaged(SubRef) = .empty;
            defer matches.deinit(b.allocator);
            try b.index.collect(b.allocator, pub_pkt.topic, &matches);

            // Collapse to one target per connection at its highest granted QoS
            // (overlapping filters → a single copy, spec behavior).
            for (matches.items) |ref| {
                if (ref.conn.state != .connected) continue;
                var found = false;
                for (targets.items) |*t| {
                    if (t.conn == ref.conn) {
                        t.qos = maxQos(t.qos, ref.qos);
                        found = true;
                        break;
                    }
                }
                if (!found) try targets.append(b.allocator, .{ .conn = ref.conn, .qos = ref.qos });
            }

            // Reference every target so `remove` cannot free it under the
            // upcoming (lock-free) writes.
            for (targets.items) |t| _ = t.conn.refs.fetchAdd(1, .acquire);
        }

        // Off the global lock: deliver to each subscriber under its own
        // tx_lock. A failure is contained to that subscriber (FIX B).
        for (targets.items) |t| {
            var failed = false;
            {
                t.conn.tx_lock.lock();
                defer t.conn.tx_lock.unlock();
                if (t.conn.state == .connected) {
                    b.deliverLocked(t.conn, pub_pkt.topic, pub_pkt.payload, minQos(pub_pkt.qos, t.qos), false) catch {
                        failed = true;
                    };
                }
            }
            if (failed) disconnectPeer(t.conn);
        }

        for (targets.items) |t| _ = t.conn.refs.fetchSub(1, .release);
    }

    /// Contain a subscriber's delivery failure (FIX B): flag it disconnected
    /// and shut its socket so its owner thread reaps it. Never frees it (a
    /// reference is still held); never touches the publisher.
    fn disconnectPeer(conn: *Connection) void {
        conn.state = .disconnected;
        conn.transport.close();
    }

    /// Send one PUBLISH to a subscriber at `qos`. Caller holds `sub_conn`'s
    /// `tx_lock` (guards `tx_buf` + the packet-id pool). For QoS 1 a packet id
    /// is allocated in the subscriber's id space and tracked pending until its
    /// PUBACK; if that pool is exhausted the message is dropped for this
    /// subscriber. The QoS 0 → QoS 1 re-encode cannot overflow `tx_buf`
    /// (sized with `tx_headroom`, FIX B).
    fn deliverLocked(b: *Broker, sub_conn: *Connection, topic_name: []const u8, payload: []const u8, qos: QoS, retain: bool) Error!void {
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

    fn aclAllows(b: *Broker, conn: *Connection, topic_name: []const u8, op: Operation) bool {
        const f = b.config.authorizeFn orelse return true;
        return f(b.config.acl_ctx, .{
            .client_id = conn.clientId(),
            .username = conn.usernameOpt(),
            .topic = topic_name,
            .operation = op,
        });
    }

    /// Store (or update) one retained topic. Caller holds `mutex`. Past
    /// `Config.max_retained` a genuinely new topic is refused (the live fan-out
    /// still happens; only the retained copy is dropped).
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
        if (b.retained.items.len >= b.config.max_retained) return; // cap: refuse new topic
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

    /// Caller holds `mutex`. Drop every subscription this connection holds.
    fn dropSubscriptions(b: *Broker, conn: *Connection) void {
        for (conn.subs.items) |f| {
            b.index.removeFilter(b.allocator, f, conn);
            b.allocator.free(f);
            b.subscriptions_total -= 1;
        }
        conn.subs.clearRetainingCapacity();
    }
};

fn minQos(a: QoS, b: QoS) QoS {
    return if (@intFromEnum(a) <= @intFromEnum(b)) a else b;
}

fn maxQos(a: QoS, b: QoS) QoS {
    return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
}

// ── optional real transport: an MQTT broker over TCP via std.Io.net ─────────
// Demo convenience only — nothing in the codec, broker core, or tests needs it.
// Thread-per-connection over `std.Io.Group`, modeled on http/Server.zig's
// accept loop; the shared registry is guarded by the broker's mutex, which the
// fan-out path never holds across a socket write (FIX A).

/// Blocking TCP accept loop that fronts a `Broker`. Bind, then `serve` (blocks
/// on the caller's thread until `shutdown`). Each accepted connection is served
/// on its own task/thread: read → `feed` → `process`, with a poll-bounded
/// keep-alive check between reads.
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
                // (keep_alive_s == 0 ⇒ waitReadable blocks forever) would then
                // wedge accept() permanently. Reject the stream and keep going.
                stream.close(s.io);
                continue;
            };
        }
    }

    fn connMain(s: *TcpServer, stream: std.Io.net.Stream) void {
        defer stream.close(s.io);
        var sock = SocketTransport{ .io = s.io, .stream = stream };
        const conn = s.broker.accept(sock.transport()) catch return;
        // `remove` drains in-flight fan-out references before returning, so
        // `sock` (this stack frame) outlives every concurrent writer to it.
        defer s.broker.remove(conn);

        var read_buf: [4096]u8 = undefined;
        while (true) {
            if (!waitReadable(stream.socket.handle, connTimeoutMs(s.broker.config, conn))) {
                // Pre-CONNECT: keep_alive_s is still 0 (unset) — bound the wait
                // by connect_timeout_ms so a client that never sends CONNECT
                // can't pin this slot/thread forever.
                if (conn.state == .awaiting_connect) return;
                if (s.broker.keepAliveExpired(conn, milliTimestamp())) return;
                continue;
            }
            // Take-over (FIX C) or a contained delivery failure (FIX B) shuts
            // this socket down and flips the connection to .disconnected; the
            // read then returns 0/err and we reap promptly.
            const n = std.posix.read(stream.socket.handle, &read_buf) catch return;
            if (n == 0) return; // client closed (or socket shut down for reaping)
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
        return .{ .ctx = t, .writeFn = writeFn, .closeFn = closeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const t: *SocketTransport = @ptrCast(@alignCast(ctx));
        var wbuf: [512]u8 = undefined;
        var sw = t.stream.writer(t.io, &wbuf);
        sw.interface.writeAll(bytes) catch return error.TransportFailed;
        sw.interface.flush() catch return error.TransportFailed;
    }

    /// FIX C: shut the stream down so a blocked read in the owner thread wakes
    /// and the connection is reaped. shutdown (not close) is safe to race with
    /// the owner's own `stream.close` — no double close of the fd.
    fn closeFn(ctx: *anyopaque) void {
        const t: *SocketTransport = @ptrCast(@alignCast(ctx));
        t.stream.shutdown(t.io, .both) catch {};
    }
};

/// Poll a socket for readability, bounded by `timeout_ms` (-1 = indefinitely).
/// Returns true if data is ready, false on timeout. A poll failure is reported
/// as "ready" so the blocking read surfaces the real error.
fn waitReadable(handle: std.Io.net.Socket.Handle, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, timeout_ms) catch return true;
    return ready != 0;
}

/// The poll timeout (ms) for one iteration of `connMain`'s read loop.
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

/// Scripted fake client side of the seam: captures everything the broker writes
/// to this connection so tests can decode it in wire order. `fail` (flipped on
/// after setup) forces the write seam to fail — to exercise per-subscriber
/// delivery-failure containment (FIX B). `closed` records a take-over / reap
/// shutdown (FIX C).
const TestTransport = struct {
    written: [4096]u8 = undefined,
    len: usize = 0,
    read_off: usize = 0,
    fail: bool = false,
    closed: bool = false,

    fn transport(m: *TestTransport) Transport {
        return .{ .ctx = m, .writeFn = writeFn, .closeFn = closeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const m: *TestTransport = @ptrCast(@alignCast(ctx));
        if (m.fail) return error.TransportFailed;
        if (m.len + bytes.len > m.written.len) return error.TransportFailed;
        @memcpy(m.written[m.len..][0..bytes.len], bytes);
        m.len += bytes.len;
    }

    fn closeFn(ctx: *anyopaque) void {
        const m: *TestTransport = @ptrCast(@alignCast(ctx));
        m.closed = true;
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
    try testing.expectEqual(@as(?packet.Packet, null), try ta.next());
    try testing.expectEqual(@as(?packet.Packet, null), try tb.next());
}

test "first packet must be CONNECT; a second CONNECT is a violation" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());

    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodePublish(&buf, .{ .topic = "t", .payload = "x" }));
    try testing.expectError(error.ProtocolViolation, b.process(conn, 0));

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
    const delivered = (try tb.next()).?;
    try testing.expectEqualStrings("sport/tennis", delivered.publish.topic);
    try testing.expectEqualStrings("3:1", delivered.publish.payload);
    try testing.expectEqual(packet.QoS.at_most_once, delivered.publish.qos);
    try testing.expectEqual(@as(?packet.Packet, null), try ta.next());
}

test "overlapping filters deliver exactly one copy at the highest granted QoS" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    const bconn = try connectClient(&b, &tb, "B", 60, 0);

    try feedSubscribe(&b, bconn, 1, &.{
        .{ .filter = "sport/#", .qos = .at_most_once },
        .{ .filter = "sport/+", .qos = .at_least_once },
    });
    _ = (try tb.next()).?; // SUBACK

    _ = try feedPublish(&b, a, .{ .topic = "sport/tennis", .payload = "x", .qos = .at_least_once, .packet_id = 5 });
    const first = (try tb.next()).?;
    try testing.expect(first == .publish);
    try testing.expectEqual(packet.QoS.at_least_once, first.publish.qos);
    try testing.expectEqual(@as(?packet.Packet, null), try tb.next());
}

test "retain before subscribe: B gets the retained message after SUBACK" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);

    _ = try feedPublish(&b, a, .{ .topic = "x/y", .payload = "keep", .retain = true });
    try testing.expectEqual(@as(usize, 1), b.retained.items.len);

    const bconn = try connectClient(&b, &tb, "B", 60, 0);
    try feedSubscribe(&b, bconn, 1, &.{.{ .filter = "x/+" }});
    const suback = (try tb.next()).?;
    try testing.expect(suback == .suback);
    const retained = (try tb.next()).?;
    try testing.expectEqualStrings("x/y", retained.publish.topic);
    try testing.expectEqualStrings("keep", retained.publish.payload);
    try testing.expect(retained.publish.retain);

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

    const ack = (try ta.next()).?;
    try testing.expectEqual(@as(u16, 42), ack.puback);

    const delivered = (try tb.next()).?;
    try testing.expectEqual(packet.QoS.at_least_once, delivered.publish.qos);
    try testing.expectEqual(@as(u16, 1), delivered.publish.packet_id);
    try testing.expectEqual(@as(usize, 1), bconn.pending_len);

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
    try testing.expectEqual(@as(usize, 1), b.subscriptionCount());

    var buf: [64]u8 = undefined;
    try b.feed(bconn, try packet.encodeUnsubscribe(&buf, 2, &.{"sport/#"}));
    try testing.expectEqual(Disposition.keep, try b.process(bconn, 1));
    const unsuback = (try tb.next()).?;
    try testing.expectEqual(@as(u16, 2), unsuback.unsuback);
    try testing.expectEqual(@as(usize, 0), b.subscriptionCount());

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
    try testing.expectEqual(@as(usize, 1), b.subscriptionCount());

    var buf: [8]u8 = undefined;
    try b.feed(conn, try packet.encodePingreq(&buf));
    try testing.expectEqual(Disposition.keep, try b.process(conn, 1));
    try testing.expect((try tt.next()).? == .pingresp);

    try b.feed(conn, try packet.encodeDisconnect(&buf));
    try testing.expectEqual(Disposition.close, try b.process(conn, 1));
    try testing.expectEqual(Connection.State.disconnected, conn.state);
    try testing.expectEqual(@as(usize, 0), b.subscriptionCount());
}

test "keep-alive timeout: connection torn down and its subscriptions dropped" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var ta = TestTransport{};
    var tb = TestTransport{};
    const a = try connectClient(&b, &ta, "A", 60, 0);
    const bconn = try connectClient(&b, &tb, "B", 10, 0);
    try feedSubscribe(&b, bconn, 1, &.{.{ .filter = "sport/#" }});
    _ = (try tb.next()).?; // SUBACK
    try testing.expect(!b.keepAliveExpired(bconn, 15_001));
    try testing.expect(b.keepAliveExpired(bconn, 15_002));

    b.remove(bconn);
    try testing.expectEqual(@as(usize, 0), b.subscriptionCount());
    try testing.expectEqual(@as(usize, 1), b.connections.items.len);

    _ = try feedPublish(&b, a, .{ .topic = "sport/tennis", .payload = "x" });
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
    try testing.expectEqual(@as(usize, 1), b.subscriptionCount());

    _ = try connectClient(&b, &t2, "same", 60, 0);
    try testing.expectEqual(Connection.State.disconnected, first.state);
    try testing.expectEqual(@as(usize, 0), b.subscriptionCount()); // old subs dropped
    // FIX C: the superseded socket was shut down so its owner thread reaps it.
    try testing.expect(t1.closed);
}

test "empty client-id is accepted and assigned a generated id" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());
    var buf: [64]u8 = undefined;
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

// ── FIX A: subscription index (trie) correctness incl. wildcards ─────────────

test "FIX A: trie fan-out routes wildcards to exactly the matching subscribers" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tp = TestTransport{}; // publisher
    var t1 = TestTransport{}; // sport/+/score
    var t2 = TestTransport{}; // sport/#
    var t3 = TestTransport{}; // sport/tennis  (exact — must NOT match .../score)
    var t4 = TestTransport{}; // $SYS/#
    var t5 = TestTransport{}; // #  (must NOT match a $-topic)
    const pconn = try connectClient(&b, &tp, "P", 60, 0);
    const c1 = try connectClient(&b, &t1, "C1", 60, 0);
    const c2 = try connectClient(&b, &t2, "C2", 60, 0);
    const c3 = try connectClient(&b, &t3, "C3", 60, 0);
    const c4 = try connectClient(&b, &t4, "C4", 60, 0);
    const c5 = try connectClient(&b, &t5, "C5", 60, 0);

    try feedSubscribe(&b, c1, 1, &.{.{ .filter = "sport/+/score" }});
    try feedSubscribe(&b, c2, 1, &.{.{ .filter = "sport/#" }});
    try feedSubscribe(&b, c3, 1, &.{.{ .filter = "sport/tennis" }});
    try feedSubscribe(&b, c4, 1, &.{.{ .filter = "$SYS/#" }});
    try feedSubscribe(&b, c5, 1, &.{.{ .filter = "#" }});
    inline for (.{ &t1, &t2, &t3, &t4, &t5 }) |t| _ = (try t.next()).?; // SUBACKs

    // sport/tennis/score → sport/+/score (C1) and sport/# (C2) and # (C5).
    _ = try feedPublish(&b, pconn, .{ .topic = "sport/tennis/score", .payload = "6-4" });
    try expectDelivered(&t1, "sport/tennis/score");
    try expectDelivered(&t2, "sport/tennis/score");
    try testing.expectEqual(@as(?packet.Packet, null), try t3.next()); // exact sport/tennis: no
    try testing.expectEqual(@as(?packet.Packet, null), try t4.next()); // $SYS/#: no
    try expectDelivered(&t5, "sport/tennis/score"); // #: yes (non-$ topic)

    // $SYS/broker/uptime → only $SYS/# (C4). Leading-wildcard filters excluded.
    _ = try feedPublish(&b, pconn, .{ .topic = "$SYS/broker/uptime", .payload = "1" });
    try expectDelivered(&t4, "$SYS/broker/uptime");
    try testing.expectEqual(@as(?packet.Packet, null), try t1.next());
    try testing.expectEqual(@as(?packet.Packet, null), try t2.next());
    try testing.expectEqual(@as(?packet.Packet, null), try t5.next()); // '#' must not match $-topic
}

fn expectDelivered(t: *TestTransport, expect_topic: []const u8) !void {
    const p = (try t.next()).?;
    try testing.expect(p == .publish);
    try testing.expectEqualStrings(expect_topic, p.publish.topic);
}

test "FIX A: PUBLISH does not hold the global registry lock across writes" {
    // A subscriber whose write seam re-acquires the (non-reentrant) global
    // spinlock would hang forever if the fan-out held that lock across the
    // write. Reaching the assertions at all proves it is released first — and
    // it also covers CONNACK/SUBACK writes, which go through the same seam.
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tp = TestTransport{};
    var probe = LockProbe{ .broker = &b };
    const pconn = try connectClient(&b, &tp, "P", 60, 0);

    const sconn = try b.accept(probe.transport());
    var buf: [128]u8 = undefined;
    try b.feed(sconn, try packet.encodeConnect(&buf, .{ .client_id = "S", .keep_alive_s = 60 }));
    _ = try b.process(sconn, 0); // CONNACK write probes the lock (must not hang)
    try b.feed(sconn, try packet.encodeSubscribe(&buf, 1, &.{.{ .filter = "t/#" }}));
    _ = try b.process(sconn, 1); // SUBACK write probes the lock
    probe.hits = 0;

    _ = try feedPublish(&b, pconn, .{ .topic = "t/x", .payload = "hi" });
    try testing.expect(probe.hits >= 1); // fan-out delivery probed the lock and returned
}

const LockProbe = struct {
    broker: *Broker,
    hits: usize = 0,

    fn transport(m: *LockProbe) Transport {
        return .{ .ctx = m, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const m: *LockProbe = @ptrCast(@alignCast(ctx));
        _ = bytes;
        // If the caller held this lock, a same-thread re-acquire on a
        // non-reentrant spinlock would deadlock — reaching unlock proves the
        // fan-out released the global lock before writing.
        m.broker.mutex.lock();
        m.broker.mutex.unlock();
        m.hits += 1;
    }
};

// ── FIX B: per-subscriber delivery failure is contained ─────────────────────

test "FIX B: a subscriber whose write fails is dropped; publisher + peers survive" {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var tp = TestTransport{};
    var tgood = TestTransport{};
    var tbad = TestTransport{};
    const p = try connectClient(&b, &tp, "P", 60, 0);
    const good = try connectClient(&b, &tgood, "GOOD", 60, 0);
    const bad = try connectClient(&b, &tbad, "BAD", 60, 0);

    // BAD subscribes at QoS 1 so a QoS 0 publish is re-encoded (the FIX B path).
    try feedSubscribe(&b, good, 1, &.{.{ .filter = "t/#", .qos = .at_least_once }});
    try feedSubscribe(&b, bad, 1, &.{.{ .filter = "t/#", .qos = .at_least_once }});
    _ = (try tgood.next()).?;
    _ = (try tbad.next()).?;

    tbad.fail = true; // BAD's socket now fails every write.

    // QoS 1 publish → publisher must get its PUBACK and keep serving; GOOD must
    // receive; BAD's failure must be contained (dropped, marked disconnected).
    const disp = try feedPublish(&b, p, .{ .topic = "t/x", .payload = "hi", .qos = .at_least_once, .packet_id = 7 });
    try testing.expectEqual(Disposition.keep, disp);
    const ack = (try tp.next()).?;
    try testing.expectEqual(@as(u16, 7), ack.puback); // publisher unaffected
    try expectDelivered(&tgood, "t/x"); // healthy peer still delivered
    try testing.expectEqual(Connection.State.disconnected, bad.state); // offender dropped
    try testing.expect(tbad.closed); // and signaled for reaping
}

test "FIX B: a max-size QoS1 publish re-encoded for a QoS1 subscriber does not overflow" {
    // The subscriber delivery re-encodes with a FRESH packet id (allocated in
    // the subscriber's id space). tx_buf is sized max_packet_size + tx_headroom
    // so a max-size inbound publish always re-encodes without BufferTooSmall —
    // the publisher never eats a subscriber's buffer failure.
    const cfg = Config{ .max_packet_size = 64 };
    var b = Broker.init(testing.allocator, cfg);
    defer b.deinit();
    var tp = TestTransport{};
    var ts = TestTransport{};
    const p = try connectClient(&b, &tp, "P", 60, 0);
    const s = try connectClient(&b, &ts, "S", 60, 0);
    try feedSubscribe(&b, s, 1, &.{.{ .filter = "t", .qos = .at_least_once }});
    _ = (try ts.next()).?;

    // A QoS 1 publish that exactly fills max_packet_size: header(1) + rl(1) +
    // topic(2+1) + id(2) + payload(57) = 64.
    var payload: [57]u8 = undefined;
    @memset(&payload, 'z');
    var buf: [80]u8 = undefined;
    const bytes = try packet.encodePublish(&buf, .{ .topic = "t", .payload = &payload, .qos = .at_least_once, .packet_id = 3 });
    try testing.expectEqual(@as(usize, 64), bytes.len);
    try b.feed(p, bytes);
    try testing.expectEqual(Disposition.keep, try b.process(p, 1)); // publisher survives

    const ack = (try tp.next()).?;
    try testing.expectEqual(@as(u16, 3), ack.puback); // publisher PUBACKed, unaffected
    const delivered = (try ts.next()).?;
    try testing.expectEqual(packet.QoS.at_least_once, delivered.publish.qos); // re-encoded, no overflow
    try testing.expectEqual(@as(u16, 1), delivered.publish.packet_id); // fresh subscriber-space id
    try testing.expectEqualSlices(u8, &payload, delivered.publish.payload);
}

// ── FIX D: authentication + ACL hooks ───────────────────────────────────────

fn denyAllAuth(ctx: ?*anyopaque, req: AuthRequest) AuthDecision {
    _ = ctx;
    _ = req;
    return .deny_bad_credentials;
}

fn denyNotAuthorized(ctx: ?*anyopaque, req: AuthRequest) AuthDecision {
    _ = ctx;
    _ = req;
    return .deny_not_authorized;
}

fn credAuth(ctx: ?*anyopaque, req: AuthRequest) AuthDecision {
    _ = ctx;
    const u = req.username orelse return .deny_bad_credentials;
    const pw = req.password orelse return .deny_bad_credentials;
    if (std.mem.eql(u8, u, "user") and std.mem.eql(u8, pw, "pw")) return .allow;
    return .deny_bad_credentials;
}

fn secretDenyAcl(ctx: ?*anyopaque, req: AclRequest) bool {
    _ = ctx;
    // Deny anything under "secret/…"; allow the rest.
    return !std.mem.startsWith(u8, req.topic, "secret/");
}

fn connectRaw(b: *Broker, tt: *TestTransport, c: packet.Connect) !*Connection {
    const conn = try b.accept(tt.transport());
    var buf: [128]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&buf, c));
    const disp = try b.process(conn, 0);
    return switch (disp) {
        .keep => conn,
        .close => error.Refused,
    };
}

test "FIX D: authentication deny → CONNACK bad_username_or_password + close" {
    var b = Broker.init(testing.allocator, .{ .authenticateFn = denyAllAuth });
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());
    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = "x" }));
    try testing.expectEqual(Disposition.close, try b.process(conn, 0));
    const ack = (try tt.next()).?;
    try testing.expectEqual(packet.ConnectReturnCode.bad_username_or_password, ack.connack.return_code);
    try testing.expectEqual(Connection.State.awaiting_connect, conn.state); // never activated
    b.remove(conn);
}

test "FIX D: authentication deny → CONNACK not_authorized" {
    var b = Broker.init(testing.allocator, .{ .authenticateFn = denyNotAuthorized });
    defer b.deinit();
    var tt = TestTransport{};
    const conn = try b.accept(tt.transport());
    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = "x" }));
    try testing.expectEqual(Disposition.close, try b.process(conn, 0));
    const ack = (try tt.next()).?;
    try testing.expectEqual(packet.ConnectReturnCode.not_authorized, ack.connack.return_code);
    b.remove(conn);
}

test "FIX D: credential auth allow threads the username; ACL gates pub + sub" {
    var b = Broker.init(testing.allocator, .{ .authenticateFn = credAuth, .authorizeFn = secretDenyAcl });
    defer b.deinit();

    // Wrong credentials → refused (the refused connection is reaped on deinit).
    var tbad = TestTransport{};
    try testing.expectError(error.Refused, connectRaw(&b, &tbad, .{ .client_id = "bad", .username = "user", .password = "nope" }));

    // Correct credentials → accepted, username threaded onto the connection.
    var tp = TestTransport{};
    var ts = TestTransport{};
    const pconn = try connectRaw(&b, &tp, .{ .client_id = "P", .username = "user", .password = "pw", .keep_alive_s = 60 });
    _ = (try tp.next()).?; // CONNACK accepted
    try testing.expectEqualStrings("user", pconn.usernameOpt().?);
    const sconn = try connectRaw(&b, &ts, .{ .client_id = "S", .username = "user", .password = "pw", .keep_alive_s = 60 });
    _ = (try ts.next()).?;

    // Subscriber: "secret/#" denied → 0x80; "ok/#" granted.
    try feedSubscribe(&b, sconn, 1, &.{
        .{ .filter = "secret/#" },
        .{ .filter = "ok/#" },
    });
    const suback = (try ts.next()).?;
    try testing.expectEqualSlices(u8, &.{ packet.suback_failure, 0x00 }, suback.suback.codes);

    // Publish to a denied topic → dropped (subscriber gets nothing) but the
    // publisher is still PUBACKed and keeps serving.
    const d1 = try feedPublish(&b, pconn, .{ .topic = "secret/x", .payload = "no", .qos = .at_least_once, .packet_id = 9 });
    try testing.expectEqual(Disposition.keep, d1);
    const ack = (try tp.next()).?;
    try testing.expectEqual(@as(u16, 9), ack.puback);
    // Publish to an allowed topic → delivered.
    _ = try feedPublish(&b, pconn, .{ .topic = "ok/y", .payload = "yes" });
    try expectDelivered(&ts, "ok/y");
    // The denied publish never reached the subscriber (only ok/y did).
    try testing.expectEqual(@as(?packet.Packet, null), try ts.next());
}

test "TcpServer compiles (never bound or dialed in tests)" {
    if (true) return error.SkipZigTest;
    std.testing.refAllDecls(TcpServer);
}
