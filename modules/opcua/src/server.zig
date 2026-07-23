// SPDX-License-Identifier: MIT

//! The server (device) side of OPC UA binary: the opc.tcp connection state
//! machine (OPC 10000-6 §7 — HEL/ACK negotiation, OPN/CLO, chunking with
//! explicit limits), sessions (OPC 10000-4 §5.6), the attribute/browse/method
//! services over `nodestore`, and the subscription + Publish-queue state
//! machine (§5.12/§5.13).
//!
//! **Shape: a byte-in / byte-out state machine the caller drives.** There are
//! exactly two entry points —
//!
//! * `Connection.feed(bytes, out, now_ms)` — hand it whatever arrived on the
//!   socket (any framing: a whole chunk, half a chunk, ten chunks); responses
//!   are written to `out`.
//! * `Connection.tick(out, now_ms)` — hand it the current time; anything the
//!   clock made due (a Publish answer, a keep-alive, a session timeout) is
//!   written to `out`.
//!
//! No threads, no owned timers, no sockets: time is a parameter, not a
//! dependency. The same code therefore runs against a real TCP socket, a
//! `.fixed` buffer pair in a test, or a simulated fleet of devices sharing one
//! event loop — which is the point (a simulated OPC UA server is this
//! module's most valuable server-side use).
//!
//! **Security: `SecurityPolicy#None` only.** The client half of this module
//! also speaks Basic256Sha256 (`security.zig`), but that path is *client-only*
//! — the server side implements no asymmetric handshake, no certificate
//! validation and no message signing/encryption, and rejects any OPN asking
//! for one with `BadSecurityPolicyRejected`. Said plainly rather than
//! half-implemented: an unsigned OPC UA server belongs on an already-trusted
//! network segment only. See SPEC.md.
//!
//! Model: OPC 10000-4 (Services) + OPC 10000-6 (mappings), with open62541
//! (MPL-2.0) used as a live black-box interop oracle — its `client`,
//! `tutorial_client_firststeps` and `client_subscription_loop` example
//! binaries drive this server in `server_interop.zig`. See `NOTICE`.

const std = @import("std");
const encoding = @import("encoding.zig");
const transport = @import("transport.zig");
const services = @import("services.zig");
const nodestore = @import("nodestore.zig");

/// The StatusCode table (see `services.status`).
pub const status = services.status;

pub const ServerError = encoding.EncodeError || std.mem.Allocator.Error || error{
    /// The response would need more chunks than the connection negotiated
    /// (`Limits.max_chunk_count`). Surfaced only from the low-level
    /// `sendMessage`; the service layer turns it into a
    /// `BadEncodingLimitsExceeded` ServiceFault.
    ResponseTooLarge,
};

/// The 8-byte `MessageHeader` (§7.1).
const header_size: u32 = 8;
/// MSG/CLO chunk overhead: header + SecureChannelId + TokenId + SequenceHeader.
const symmetric_overhead: u32 = header_size + 4 + 4 + 8;
/// OPC 10000-6 §7.1.2: both buffer sizes a Hello proposes must be >= 8192.
const min_buffer_size: u32 = 8192;
/// §7.1.2: the endpoint URL "shall not exceed 4096 bytes".
const max_endpoint_url_len: usize = 4096;
/// Cap on publishing cycles run per subscription per `tick` — the bound that
/// keeps a long driver stall (or a hostile clock jump) from turning into an
/// unbounded loop.
const max_cycles_per_tick: usize = 64;

// ── configuration ───────────────────────────────────────────────────────────

/// The opc.tcp limits this server proposes; the effective values are these
/// negotiated against the client's Hello (`Connection.limits`). Every one of
/// them is a denial-of-service bound, not a tuning knob: a chunk bigger than
/// `receive_buffer_size`, more than `max_chunk_count` chunks in one message,
/// or a reassembled message over `max_message_size` all abort the connection
/// with an `ERR` rather than allocating.
pub const Limits = struct {
    /// Largest single chunk this server will accept.
    receive_buffer_size: u32 = 65_536,
    /// Largest single chunk this server will emit.
    send_buffer_size: u32 = 65_536,
    /// Largest reassembled request. `0` = no limit (not recommended).
    max_message_size: u32 = 4 * 1024 * 1024,
    /// Most chunks one reassembled message may consist of. `0` = no limit.
    max_chunk_count: u32 = 256,
};

/// One username/password pair accepted for `UserTokenType.user_name`
/// activation. Compared in constant time so a wrong password cannot be found
/// byte-by-byte from response timing.
pub const UserCredential = struct {
    user_name: []const u8,
    password: []const u8,
};

pub const Config = struct {
    application_uri: []const u8 = "urn:zig-libs:opcua:server",
    product_uri: []const u8 = "urn:zig-libs:opcua",
    application_name: encoding.LocalizedText = .{ .locale = "en", .text = "zig-libs opcua server" },
    /// The endpoints `GetEndpoints`/`CreateSession` answer with — borrowed,
    /// caller-owned, expected to have static lifetime. Only
    /// `MessageSecurityMode.none` endpoints can actually be *used* (see the
    /// module doc comment); build the list with `noneEndpoint`.
    endpoints: []const services.EndpointDescription,
    /// Accept `AnonymousIdentityToken` on ActivateSession.
    allow_anonymous: bool = true,
    /// Accept `UserNameIdentityToken` for any of these credentials.
    users: []const UserCredential = &.{},
    limits: Limits = .{},
    /// Longest session timeout this server grants, milliseconds; a client
    /// asking for more is revised down.
    max_session_timeout_ms: f64 = 600_000,
    min_session_timeout_ms: f64 = 10_000,
    max_sessions: usize = 16,
    max_subscriptions_per_session: usize = 16,
    max_monitored_items_per_subscription: usize = 256,
    /// Queued `PublishRequest`s per session; one more gets
    /// `BadTooManyPublishRequests`.
    max_publish_requests: usize = 32,
    /// Retained `NotificationMessage`s per subscription, for `Republish`.
    max_retransmission_queue: usize = 8,
    max_continuation_points: usize = 8,
    /// Operations (nodes to read, values to write, paths to translate, …) one
    /// request may carry.
    max_operations_per_request: usize = 1000,
    /// Cap on `Browse`'s references per node when the client asks for "as
    /// many as you like" (`requested_max_references_per_node == 0`).
    max_references_per_browse: u32 = 1000,
    /// Fastest sampling interval a monitored item may be granted, and the
    /// publishing-interval band a subscription may be granted (milliseconds)
    /// — the rate limiter that keeps a client from asking this server to spin.
    min_sampling_interval_ms: f64 = 50,
    min_publishing_interval_ms: f64 = 50,
    max_publishing_interval_ms: f64 = 3_600_000,
    max_notifications_per_publish: u32 = 1024,
};

/// The two `UserTokenPolicy`s this server implements, advertised by every
/// endpoint built with `noneEndpoint`. The PolicyIds are this
/// implementation's own names; a client echoes back whichever it picked.
pub const anonymous_policy_id = "anonymous";
pub const user_name_policy_id = "username";

pub const default_user_token_policies = [_]services.UserTokenPolicy{
    .{
        .policy_id = anonymous_policy_id,
        .token_type = .anonymous,
        .issued_token_type = null,
        .issuer_endpoint_url = null,
        .security_policy_uri = services.security_policy_none_uri,
    },
    .{
        .policy_id = user_name_policy_id,
        .token_type = .user_name,
        .issued_token_type = null,
        .issuer_endpoint_url = null,
        .security_policy_uri = services.security_policy_none_uri,
    },
};

/// The opc.tcp binary transport profile URI every endpoint advertises
/// (OPC 10000-7 §7.1).
pub const transport_profile_uri = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";

/// Build the one endpoint shape this server can honestly serve:
/// `SecurityPolicy#None` at `MessageSecurityMode.none`, offering the anonymous
/// + username identity tokens.
pub fn noneEndpoint(endpoint_url: []const u8, app: services.ApplicationDescription) services.EndpointDescription {
    return .{
        .endpoint_url = endpoint_url,
        .server = app,
        .server_certificate = null,
        .security_mode = .none,
        .security_policy_uri = services.security_policy_none_uri,
        .user_identity_tokens = &default_user_token_policies,
        .transport_profile_uri = transport_profile_uri,
        .security_level = 0,
    };
}

/// The `ApplicationDescription` matching a `Config` — handy when building the
/// endpoint list before the `Server` exists.
pub fn applicationDescription(config: Config, discovery_urls: ?[]const ?[]const u8) services.ApplicationDescription {
    return .{
        .application_uri = config.application_uri,
        .product_uri = config.product_uri,
        .application_name = config.application_name,
        .application_type = .server,
        .gateway_server_uri = null,
        .discovery_profile_uri = null,
        .discovery_urls = discovery_urls,
    };
}

// ── sessions, subscriptions, monitored items ────────────────────────────────

/// One queued `PublishRequest` (§5.13.5): the client parked a request with the
/// server, which answers it when a subscription has something to say (or its
/// keep-alive expires).
const PendingPublish = struct {
    request_id: u32,
    request_handle: u32,
    queued_ms: i64,
};

/// A `NotificationMessage` kept for `Republish` (§5.13.6), stored already
/// encoded: republishing must reproduce the exact bytes the client missed, and
/// keeping the encoding avoids deep-copying the whole notification tree.
const RetransmittedMessage = struct {
    sequence_number: u32,
    bytes: []u8,
};

const ContinuationPoint = struct {
    handle: u32,
    node_id: encoding.NodeId,
    reference_type_id: encoding.NodeId,
    browse_direction: services.BrowseDirection,
    include_subtypes: bool,
    node_class_mask: u32,
    result_mask: u32,
    /// Index into the source node's reference list to resume from.
    next_index: usize,
    max_references: u32,

    fn deinit(cp: *ContinuationPoint, a: std.mem.Allocator) void {
        encoding.freeNodeId(a, cp.node_id);
        encoding.freeNodeId(a, cp.reference_type_id);
    }
};

pub const MonitoredItem = struct {
    id: u32,
    client_handle: u32,
    node_id: encoding.NodeId,
    attribute_id: u32,
    monitoring_mode: services.MonitoringMode,
    sampling_interval_ms: f64,
    queue_size: u32,
    discard_oldest: bool,
    timestamps_to_return: services.TimestampsToReturn,
    next_sample_ms: i64,
    /// The last sampled value — the data-change comparison baseline. Owned.
    last_value: ?encoding.DataValue = null,
    /// Values sampled since the last publish, oldest first. Owned.
    queue: std.ArrayList(encoding.DataValue) = .empty,

    fn deinit(item: *MonitoredItem, a: std.mem.Allocator) void {
        encoding.freeNodeId(a, item.node_id);
        if (item.last_value) |v| encoding.freeDataValue(a, v);
        for (item.queue.items) |v| encoding.freeDataValue(a, v);
        item.queue.deinit(a);
    }
};

/// What a due publishing cycle decided this subscription owes the client.
const PendingMessage = enum { none, data, keep_alive };

pub const Subscription = struct {
    id: u32,
    publishing_interval_ms: f64,
    max_keep_alive_count: u32,
    lifetime_count: u32,
    max_notifications_per_publish: u32,
    publishing_enabled: bool,
    priority: u8,
    next_publish_ms: i64,
    keep_alive_counter: u32 = 0,
    lifetime_counter: u32 = 0,
    /// The sequence number the *next* NotificationMessage carrying data will
    /// use. A keep-alive announces this number without consuming it
    /// (§5.13.1.1).
    next_sequence_number: u32 = 1,
    pending: PendingMessage = .none,
    /// A cycle came due with something to say and no `PublishRequest` to say
    /// it in (§5.13.5's "late" subscription).
    late: bool = false,
    monitored_items: std.ArrayList(MonitoredItem) = .empty,
    retransmission: std.ArrayList(RetransmittedMessage) = .empty,

    fn deinit(sub: *Subscription, a: std.mem.Allocator) void {
        for (sub.monitored_items.items) |*item| item.deinit(a);
        sub.monitored_items.deinit(a);
        for (sub.retransmission.items) |m| a.free(m.bytes);
        sub.retransmission.deinit(a);
    }

    fn findItem(sub: *Subscription, monitored_item_id: u32) ?*MonitoredItem {
        for (sub.monitored_items.items) |*item| {
            if (item.id == monitored_item_id) return item;
        }
        return null;
    }

    fn hasReportable(sub: *const Subscription) bool {
        for (sub.monitored_items.items) |item| {
            if (item.monitoring_mode == .reporting and item.queue.items.len > 0) return true;
        }
        return false;
    }

    fn takeSequenceNumber(sub: *Subscription) u32 {
        const seq = sub.next_sequence_number;
        // §5.13.1.1: sequence numbers wrap to 1, never to 0.
        sub.next_sequence_number = if (seq == std.math.maxInt(u32)) 1 else seq + 1;
        return seq;
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    numeric_id: u32,
    /// The opaque 32-byte `AuthenticationToken` (§5.6.2.2) every subsequent
    /// request must carry. Random — never a guessable counter.
    auth_token: [32]u8,
    server_nonce: [32]u8,
    session_name: []u8,
    /// The SecureChannel this session was created on. A request arriving on a
    /// different channel is rejected (`BadSecureChannelIdInvalid`): session
    /// transfer between channels is not implemented.
    channel_id: u32,
    activated: bool = false,
    timeout_ms: f64,
    last_activity_ms: i64,
    subscriptions: std.ArrayList(*Subscription) = .empty,
    publish_queue: std.ArrayList(PendingPublish) = .empty,
    continuation_points: std.ArrayList(ContinuationPoint) = .empty,
    /// `SubscriptionAcknowledgement` results owed to the client; they ride the
    /// next PublishResponse this session gets (§5.13.5). Owned.
    pending_ack_results: ?[]encoding.StatusCode = null,

    fn deinit(session: *Session) void {
        const a = session.allocator;
        for (session.subscriptions.items) |sub| {
            sub.deinit(a);
            a.destroy(sub);
        }
        session.subscriptions.deinit(a);
        session.publish_queue.deinit(a);
        for (session.continuation_points.items) |*cp| cp.deinit(a);
        session.continuation_points.deinit(a);
        if (session.pending_ack_results) |r| a.free(r);
        a.free(session.session_name);
    }

    pub fn sessionId(session: *const Session) encoding.NodeId {
        return .{ .numeric = .{ .namespace = 1, .id = session.numeric_id } };
    }

    pub fn authenticationToken(session: *const Session) encoding.NodeId {
        return .{ .byte_string = .{ .namespace = 1, .id = &session.auth_token } };
    }

    fn findSubscription(session: *Session, subscription_id: u32) ?*Subscription {
        for (session.subscriptions.items) |sub| {
            if (sub.id == subscription_id) return sub;
        }
        return null;
    }
};

// ── the server ──────────────────────────────────────────────────────────────

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Caller-owned address space — the server never frees it.
    store: *nodestore.NodeStore,
    /// Session identifiers, authentication tokens and nonces come from here.
    /// Pass a real CSPRNG in production: an `AuthenticationToken` is a bearer
    /// credential.
    random: std.Random,
    /// The OPC UA `DateTime` (100ns ticks since 1601-01-01) corresponding to
    /// `now_ms == 0` — the whole server's wall clock, injected once. Every
    /// timestamp this server writes is `wall_clock_epoch + now_ms * 10_000`.
    wall_clock_epoch: encoding.DateTime = 0,
    sessions: std.ArrayList(*Session) = .empty,
    next_session_id: u32 = 1,
    next_channel_id: u32 = 1,
    next_token_id: u32 = 1,
    next_subscription_id: u32 = 1,
    next_monitored_item_id: u32 = 1,
    next_continuation_handle: u32 = 1,

    pub fn init(allocator: std.mem.Allocator, store: *nodestore.NodeStore, config: Config, random: std.Random) Server {
        return .{ .allocator = allocator, .config = config, .store = store, .random = random };
    }

    pub fn deinit(srv: *Server) void {
        for (srv.sessions.items) |session| {
            session.deinit();
            srv.allocator.destroy(session);
        }
        srv.sessions.deinit(srv.allocator);
        srv.* = undefined;
    }

    /// The OPC UA `DateTime` for a driver-supplied millisecond timestamp.
    pub fn dateTime(srv: *const Server, now_ms: i64) encoding.DateTime {
        return srv.wall_clock_epoch +% (now_ms *% 10_000);
    }

    /// Refresh `Server_ServerStatus` (i=2256) + `CurrentTime` (i=2258) from
    /// the driver's clock — the "this server is alive" heartbeat a simulation
    /// calls from its own loop (this module owns no timer).
    pub fn refreshTime(srv: *Server, now_ms: i64, start_time: encoding.DateTime) !void {
        try srv.store.refreshServerStatus(.{
            .start_time = start_time,
            .current_time = srv.dateTime(now_ms),
            .product_name = srv.config.application_name.text orelse "zig-libs opcua server",
            .product_uri = srv.config.product_uri,
        });
    }

    pub fn sessionCount(srv: *const Server) usize {
        return srv.sessions.items.len;
    }

    fn findSession(srv: *Server, auth_token: encoding.NodeId) ?*Session {
        const bytes = switch (auth_token) {
            .byte_string => |b| b.id orelse return null,
            else => return null,
        };
        if (bytes.len != 32) return null;
        for (srv.sessions.items) |session| {
            // Constant-time compare: the token is a bearer credential.
            if (std.crypto.timing_safe.eql([32]u8, session.auth_token, bytes[0..32].*)) return session;
        }
        return null;
    }

    fn removeSession(srv: *Server, session: *Session) void {
        for (srv.sessions.items, 0..) |s, i| {
            if (s == session) {
                _ = srv.sessions.orderedRemove(i);
                session.deinit();
                srv.allocator.destroy(session);
                return;
            }
        }
    }

    /// Close every session whose `RevisedSessionTimeout` elapsed without a
    /// request (§5.6.2: the server "shall" delete it, along with its
    /// subscriptions).
    pub fn expireSessions(srv: *Server, now_ms: i64) void {
        var i: usize = 0;
        while (i < srv.sessions.items.len) {
            const session = srv.sessions.items[i];
            const elapsed: f64 = @floatFromInt(now_ms - session.last_activity_ms);
            if (elapsed > session.timeout_ms) {
                _ = srv.sessions.orderedRemove(i);
                session.deinit();
                srv.allocator.destroy(session);
                continue;
            }
            i += 1;
        }
    }
};

// ── the connection state machine ────────────────────────────────────────────

pub const ConnectionState = enum {
    /// Nothing but a `HEL` may arrive (§7.1.2).
    awaiting_hello,
    /// Handshake done; OPN/MSG/CLO are accepted.
    open,
    /// A fatal transport error was reported (`ERR` already written) or the
    /// client closed the channel — the driver should close the socket.
    closed,
};

/// The negotiated limits (§7.1.3): the minimum of what each side proposed.
pub const Negotiated = struct {
    receive_buffer_size: u32 = 65_536,
    send_buffer_size: u32 = 65_536,
    max_message_size: u32 = 0,
    max_chunk_count: u32 = 0,
};

pub const Connection = struct {
    server: *Server,
    /// Caller-owned staging buffer for partial chunks. Must be at least
    /// `Limits.receive_buffer_size` bytes so one maximal chunk always fits.
    recv: []u8,
    recv_len: usize = 0,
    /// Caller-owned reassembly buffer for multi-chunk messages; bounds the
    /// largest request this connection accepts together with
    /// `Limits.max_message_size`.
    msg: []u8,
    msg_len: usize = 0,
    msg_type: ?transport.MessageType = null,
    msg_request_id: u32 = 0,
    chunk_count: u32 = 0,
    state: ConnectionState = .awaiting_hello,
    limits: Negotiated = .{},
    channel_id: u32 = 0,
    token_id: u32 = 0,
    token_created_ms: i64 = 0,
    token_lifetime_ms: u32 = 0,
    send_sequence_number: u32 = 0,
    endpoint_url_buf: [256]u8 = undefined,
    endpoint_url_len: usize = 0,

    pub const InitError = error{BufferTooSmall};

    /// `recv_buf` must be >= the configured `receive_buffer_size` (a chunk is
    /// processed only once complete, so a smaller buffer could deadlock on a
    /// legal maximum-size chunk); `msg_buf` bounds reassembly.
    pub fn init(server: *Server, recv_buf: []u8, msg_buf: []u8) InitError!Connection {
        if (recv_buf.len < server.config.limits.receive_buffer_size) return error.BufferTooSmall;
        if (msg_buf.len < min_buffer_size) return error.BufferTooSmall;
        return .{ .server = server, .recv = recv_buf, .msg = msg_buf };
    }

    pub fn endpointUrl(c: *const Connection) []const u8 {
        return c.endpoint_url_buf[0..c.endpoint_url_len];
    }

    /// `true` once the driver should stop reading and close the socket.
    pub fn isClosed(c: *const Connection) bool {
        return c.state == .closed;
    }

    // ── entry point 1: bytes in ─────────────────────────────────────────────

    /// Feed `input` (any amount, any framing) and write whatever the server
    /// answers into `out`. Never blocks, never allocates unboundedly: input is
    /// bounded by the negotiated receive buffer, reassembly by
    /// `max_message_size`/`max_chunk_count`, and any violation writes an `ERR`
    /// (§7.1.4) and closes the connection instead of growing.
    pub fn feed(c: *Connection, input: []const u8, out: *std.Io.Writer, now_ms: i64) ServerError!void {
        var rest = input;
        while (rest.len > 0) {
            if (c.state == .closed) return;
            const space = c.recv.len - c.recv_len;
            if (space == 0) {
                try c.fail(out, status.bad_tcp_message_too_large, "chunk exceeds the receive buffer");
                return;
            }
            const n = @min(space, rest.len);
            @memcpy(c.recv[c.recv_len..][0..n], rest[0..n]);
            c.recv_len += n;
            rest = rest[n..];
            try c.drain(out, now_ms);
        }
    }

    /// Pull complete chunks out of `recv` and process them.
    fn drain(c: *Connection, out: *std.Io.Writer, now_ms: i64) ServerError!void {
        while (c.state != .closed) {
            if (c.recv_len < header_size) return;
            const type_bytes: *const [3]u8 = c.recv[0..3];
            const chunk_byte = c.recv[3];
            const size = std.mem.readInt(u32, c.recv[4..8], .little);

            const message_type = transport.MessageType.fromCode(type_bytes) orelse {
                try c.fail(out, status.bad_tcp_message_type_invalid, "unknown message type");
                return;
            };
            const chunk_type = std.enums.fromInt(transport.ChunkType, chunk_byte) orelse {
                try c.fail(out, status.bad_tcp_message_type_invalid, "unknown chunk type");
                return;
            };
            if (size < header_size) {
                try c.fail(out, status.bad_tcp_message_type_invalid, "chunk size below the header size");
                return;
            }
            const accept_limit = if (c.state == .awaiting_hello)
                c.server.config.limits.receive_buffer_size
            else
                c.limits.receive_buffer_size;
            if (size > accept_limit) {
                try c.fail(out, status.bad_tcp_message_too_large, "chunk exceeds the negotiated receive buffer size");
                return;
            }
            if (c.recv_len < size) return; // wait for the rest of this chunk

            const body = c.recv[header_size..size];
            try c.processChunk(message_type, chunk_type, body, out, now_ms);

            const leftover = c.recv_len - size;
            if (leftover > 0) std.mem.copyForwards(u8, c.recv[0..leftover], c.recv[size..c.recv_len]);
            c.recv_len = leftover;
        }
    }

    fn processChunk(
        c: *Connection,
        message_type: transport.MessageType,
        chunk_type: transport.ChunkType,
        body: []const u8,
        out: *std.Io.Writer,
        now_ms: i64,
    ) ServerError!void {
        switch (c.state) {
            .closed => return,
            .awaiting_hello => {
                if (message_type != .hello) {
                    try c.fail(out, status.bad_tcp_message_type_invalid, "expected a Hello message");
                    return;
                }
                try c.handleHello(body, out);
            },
            .open => switch (message_type) {
                .hello => try c.fail(out, status.bad_tcp_message_type_invalid, "Hello after the handshake"),
                // A client never sends these.
                .acknowledge, .error_msg => try c.fail(out, status.bad_tcp_message_type_invalid, "server-only message type from a client"),
                .open_secure_channel, .message, .close_secure_channel => try c.handleSecureChunk(message_type, chunk_type, body, out, now_ms),
            },
        }
    }

    // ── §7.1.2/§7.1.3: Hello / Acknowledge ──────────────────────────────────

    fn handleHello(c: *Connection, body: []const u8, out: *std.Io.Writer) ServerError!void {
        if (body.len < 24) {
            try c.fail(out, status.bad_tcp_internal_error, "truncated Hello");
            return;
        }
        var r: std.Io.Reader = .fixed(body);
        const protocol_version = r.takeInt(u32, .little) catch unreachable;
        const client_receive_buffer = r.takeInt(u32, .little) catch unreachable;
        const client_send_buffer = r.takeInt(u32, .little) catch unreachable;
        const client_max_message = r.takeInt(u32, .little) catch unreachable;
        const client_max_chunks = r.takeInt(u32, .little) catch unreachable;
        const url_len = r.takeInt(i32, .little) catch unreachable;

        if (protocol_version != 0) {
            try c.fail(out, status.bad_protocol_version_unsupported, "only protocol version 0 exists");
            return;
        }
        if (url_len > 0) {
            const n: usize = @intCast(url_len);
            if (n > max_endpoint_url_len or n > body.len - 24) {
                try c.fail(out, status.bad_tcp_endpoint_url_invalid, "endpoint URL too long");
                return;
            }
            const url = r.take(n) catch {
                try c.fail(out, status.bad_tcp_endpoint_url_invalid, "truncated endpoint URL");
                return;
            };
            const keep = @min(url.len, c.endpoint_url_buf.len);
            @memcpy(c.endpoint_url_buf[0..keep], url[0..keep]);
            c.endpoint_url_len = keep;
        } else if (url_len < -1) {
            try c.fail(out, status.bad_tcp_endpoint_url_invalid, "negative endpoint URL length");
            return;
        }
        // §7.1.2: both of the client's buffer sizes must be at least 8192.
        if (client_receive_buffer < min_buffer_size or client_send_buffer < min_buffer_size) {
            try c.fail(out, status.bad_tcp_not_enough_resources, "buffer sizes below the 8192-byte minimum");
            return;
        }

        const own = c.server.config.limits;
        c.limits = .{
            // What we may put on the wire is bounded by what the client can
            // receive, and vice versa.
            .send_buffer_size = @min(own.send_buffer_size, client_receive_buffer),
            .receive_buffer_size = @min(own.receive_buffer_size, client_send_buffer),
            .max_message_size = minLimit(own.max_message_size, client_max_message),
            .max_chunk_count = minLimit(own.max_chunk_count, client_max_chunks),
        };
        c.state = .open;

        var ack: [20]u8 = undefined;
        std.mem.writeInt(u32, ack[0..4], 0, .little);
        std.mem.writeInt(u32, ack[4..8], c.limits.receive_buffer_size, .little);
        std.mem.writeInt(u32, ack[8..12], c.limits.send_buffer_size, .little);
        std.mem.writeInt(u32, ack[12..16], c.limits.max_message_size, .little);
        std.mem.writeInt(u32, ack[16..20], c.limits.max_chunk_count, .little);
        try writeChunkHeader(out, .acknowledge, .final, header_size + ack.len);
        try out.writeAll(&ack);
    }

    /// `0` means "no limit" on the wire, so it loses to any concrete value.
    fn minLimit(a: u32, b: u32) u32 {
        if (a == 0) return b;
        if (b == 0) return a;
        return @min(a, b);
    }

    // ── §6.7.2: secure-conversation chunks ──────────────────────────────────

    fn handleSecureChunk(
        c: *Connection,
        message_type: transport.MessageType,
        chunk_type: transport.ChunkType,
        body: []const u8,
        out: *std.Io.Writer,
        now_ms: i64,
    ) ServerError!void {
        if (body.len < 4) {
            try c.fail(out, status.bad_tcp_internal_error, "truncated secure-conversation header");
            return;
        }
        var r: std.Io.Reader = .fixed(body);
        const channel_id = r.takeInt(u32, .little) catch unreachable;

        switch (message_type) {
            .open_secure_channel => {
                // AsymmetricAlgorithmSecurityHeader: SecurityPolicyUri,
                // SenderCertificate, ReceiverCertificateThumbprint (§6.7.2).
                const policy_uri = takeStringSlice(&r) catch {
                    try c.fail(out, status.bad_tcp_internal_error, "truncated asymmetric security header");
                    return;
                };
                _ = takeStringSlice(&r) catch {
                    try c.fail(out, status.bad_tcp_internal_error, "truncated sender certificate");
                    return;
                };
                _ = takeStringSlice(&r) catch {
                    try c.fail(out, status.bad_tcp_internal_error, "truncated certificate thumbprint");
                    return;
                };
                const uri = policy_uri orelse "";
                if (!std.mem.eql(u8, uri, services.security_policy_none_uri)) {
                    // Said plainly rather than half-implemented: this server
                    // has no asymmetric crypto (see the module doc comment).
                    try c.fail(out, status.bad_security_policy_rejected, "only SecurityPolicy#None is implemented server-side");
                    return;
                }
                if (channel_id != 0 and channel_id != c.channel_id) {
                    try c.fail(out, status.bad_tcp_secure_channel_unknown, "unknown secure channel");
                    return;
                }
            },
            .message, .close_secure_channel => {
                if (c.channel_id == 0 or channel_id != c.channel_id) {
                    try c.fail(out, status.bad_tcp_secure_channel_unknown, "no such secure channel on this connection");
                    return;
                }
                const token_id = r.takeInt(u32, .little) catch {
                    try c.fail(out, status.bad_tcp_internal_error, "truncated symmetric security header");
                    return;
                };
                if (token_id != c.token_id) {
                    try c.fail(out, status.bad_tcp_secure_channel_unknown, "unknown security token");
                    return;
                }
            },
            else => unreachable,
        }

        // SequenceHeader (§6.7.3). SecurityMode=None gives no integrity
        // protection, so a sequence number is not independently validated —
        // it is only carried back on the response.
        _ = r.takeInt(u32, .little) catch {
            try c.fail(out, status.bad_tcp_internal_error, "truncated sequence header");
            return;
        };
        const request_id = r.takeInt(u32, .little) catch {
            try c.fail(out, status.bad_tcp_internal_error, "truncated sequence header");
            return;
        };
        const payload = r.buffered();

        if (chunk_type == .abort) {
            // §6.7.2: discard everything gathered for this message and carry
            // on — an abort cancels one request, it is not a connection-level
            // failure.
            c.resetAssembly();
            return;
        }

        // Reassembly, with every limit enforced explicitly.
        if (c.msg_len == 0) {
            c.msg_type = message_type;
            c.msg_request_id = request_id;
        } else if (c.msg_type != message_type or c.msg_request_id != request_id) {
            try c.fail(out, status.bad_tcp_message_type_invalid, "interleaved chunk runs are not supported");
            return;
        }
        c.chunk_count += 1;
        if (c.limits.max_chunk_count != 0 and c.chunk_count > c.limits.max_chunk_count) {
            try c.fail(out, status.bad_tcp_message_too_large, "chunk count exceeds the negotiated maximum");
            return;
        }
        if (c.msg_len + payload.len > c.msg.len) {
            try c.fail(out, status.bad_tcp_message_too_large, "reassembled message exceeds the reassembly buffer");
            return;
        }
        if (c.limits.max_message_size != 0 and c.msg_len + payload.len > c.limits.max_message_size) {
            try c.fail(out, status.bad_tcp_message_too_large, "reassembled message exceeds the negotiated maximum");
            return;
        }
        @memcpy(c.msg[c.msg_len..][0..payload.len], payload);
        c.msg_len += payload.len;
        if (chunk_type == .intermediate) return;

        const message = c.msg[0..c.msg_len];
        c.resetAssembly();
        try c.processMessage(message_type, request_id, message, out, now_ms);
    }

    fn resetAssembly(c: *Connection) void {
        c.msg_len = 0;
        c.msg_type = null;
        c.msg_request_id = 0;
        c.chunk_count = 0;
    }

    /// Read an OPC UA String/ByteString without allocating: the length prefix
    /// plus a borrowed slice of the reader's buffer.
    fn takeStringSlice(r: *std.Io.Reader) !?[]const u8 {
        const len = try r.takeInt(i32, .little);
        if (len == -1) return null;
        if (len < -1) return error.BadLength;
        return try r.take(@intCast(len));
    }

    // ── §7.1.4: the transport-level Error message ───────────────────────────

    /// Write an `ERR` message and close: every one of these is a protocol
    /// violation or a resource bound the peer blew through, and §7.1.4 takes
    /// the socket with it.
    fn fail(c: *Connection, out: *std.Io.Writer, code: encoding.StatusCode, reason: []const u8) ServerError!void {
        c.state = .closed;
        c.resetAssembly();
        const size: usize = header_size + 4 + 4 + reason.len;
        try writeChunkHeader(out, .error_msg, .final, size);
        try out.writeInt(u32, code, .little);
        try out.writeInt(i32, @intCast(reason.len), .little);
        try out.writeAll(reason);
    }

    fn writeChunkHeader(out: *std.Io.Writer, message_type: transport.MessageType, chunk_type: transport.ChunkType, size: usize) ServerError!void {
        try out.writeAll(message_type.code());
        try out.writeByte(@intFromEnum(chunk_type));
        try out.writeInt(u32, @intCast(size), .little);
    }

    // ── outgoing messages ───────────────────────────────────────────────────

    fn nextSequenceNumber(c: *Connection) u32 {
        // §6.7.2: sequence numbers are per-channel and wrap back to 1.
        c.send_sequence_number = if (c.send_sequence_number >= std.math.maxInt(u32) - 1024) 1 else c.send_sequence_number + 1;
        return c.send_sequence_number;
    }

    /// Send one service response, split across as many chunks as the
    /// negotiated `send_buffer_size` requires (`C`… then `F`).
    fn sendMessage(
        c: *Connection,
        out: *std.Io.Writer,
        message_type: transport.MessageType,
        request_id: u32,
        payload: []const u8,
    ) ServerError!void {
        const max_body: usize = @max(@as(usize, 1), c.limits.send_buffer_size -| symmetric_overhead);
        const chunks = (payload.len + max_body - 1) / max_body;
        if (c.limits.max_chunk_count != 0 and chunks > c.limits.max_chunk_count) return error.ResponseTooLarge;

        var offset: usize = 0;
        while (true) {
            const take = @min(payload.len - offset, max_body);
            const is_final = offset + take == payload.len;
            try writeChunkHeader(out, message_type, if (is_final) .final else .intermediate, symmetric_overhead + take);
            try out.writeInt(u32, c.channel_id, .little);
            try out.writeInt(u32, c.token_id, .little);
            try out.writeInt(u32, c.nextSequenceNumber(), .little);
            try out.writeInt(u32, request_id, .little);
            try out.writeAll(payload[offset..][0..take]);
            offset += take;
            if (is_final) break;
        }
    }

    /// The OPN response carries the `AsymmetricAlgorithmSecurityHeader`
    /// instead of a TokenId (§6.7.2). Always a single chunk: at
    /// SecurityMode=None the response is a couple of hundred bytes.
    fn sendOpenResponse(c: *Connection, out: *std.Io.Writer, request_id: u32, payload: []const u8) ServerError!void {
        const uri = services.security_policy_none_uri;
        const size = header_size + 4 + (4 + uri.len) + 4 + 4 + 8 + payload.len;
        try writeChunkHeader(out, .open_secure_channel, .final, size);
        try out.writeInt(u32, c.channel_id, .little);
        try out.writeInt(i32, @intCast(uri.len), .little);
        try out.writeAll(uri);
        try out.writeInt(i32, -1, .little); // SenderCertificate: none
        try out.writeInt(i32, -1, .little); // ReceiverCertificateThumbprint: none
        try out.writeInt(u32, c.nextSequenceNumber(), .little);
        try out.writeInt(u32, request_id, .little);
        try out.writeAll(payload);
    }

    // ── entry point 2: the clock ────────────────────────────────────────────

    /// Advance the server's time: expire sessions, run every due publishing
    /// cycle, and answer queued `PublishRequest`s. Call it whenever the
    /// driver's poll times out (`feed` already does it for the requests it
    /// processes).
    pub fn tick(c: *Connection, out: *std.Io.Writer, now_ms: i64) ServerError!void {
        if (c.state == .closed) return;
        c.server.expireSessions(now_ms);
        for (c.server.sessions.items) |session| {
            if (session.channel_id != c.channel_id) continue;
            try c.serviceSubscriptions(session, out, now_ms);
        }
    }

    // ── message dispatch ────────────────────────────────────────────────────

    const Ctx = struct {
        conn: *Connection,
        srv: *Server,
        arena: std.mem.Allocator,
        out: *std.Io.Writer,
        now_ms: i64,
        request_id: u32,
        request_handle: u32 = 0,
        message_type: transport.MessageType,

        fn responseHeader(ctx: *const Ctx, service_result: encoding.StatusCode) services.ResponseHeader {
            return .{
                .timestamp = ctx.srv.dateTime(ctx.now_ms),
                .request_handle = ctx.request_handle,
                .service_result = service_result,
                .service_diagnostics = .{},
                .string_table = null,
                .additional_header = services.no_additional_header,
            };
        }
    };

    const HandlerError = ServerError || encoding.DecodeError;

    fn processMessage(
        c: *Connection,
        message_type: transport.MessageType,
        request_id: u32,
        message: []const u8,
        out: *std.Io.Writer,
        now_ms: i64,
    ) ServerError!void {
        var arena_state = std.heap.ArenaAllocator.init(c.server.allocator);
        defer arena_state.deinit();
        var ctx: Ctx = .{
            .conn = c,
            .srv = c.server,
            .arena = arena_state.allocator(),
            .out = out,
            .now_ms = now_ms,
            .request_id = request_id,
            .message_type = message_type,
        };

        c.dispatch(&ctx, message) catch |err| switch (err) {
            error.OutOfMemory => try sendFault(&ctx, status.bad_out_of_memory),
            error.ResponseTooLarge => try sendFault(&ctx, status.bad_encoding_limits_exceeded),
            error.WriteFailed => return error.WriteFailed,
            // Everything remaining is a `DecodeError` (or the encoder's
            // ValueTooLarge): a malformed request is a fault, never a crash
            // and never a dropped connection.
            else => try sendFault(&ctx, status.bad_decoding_error),
        };
    }

    fn dispatch(c: *Connection, ctx: *Ctx, message: []const u8) HandlerError!void {
        var r: std.Io.Reader = .fixed(message);
        var d = encoding.Decoder.init(&r, ctx.arena);
        const type_id = try d.decodeNodeId();

        if (ctx.message_type == .open_secure_channel) {
            if (!services.nodeIdEql(type_id, services.type_id.open_secure_channel_request)) {
                try c.fail(ctx.out, status.bad_tcp_message_type_invalid, "OPN chunk carrying a non-OpenSecureChannel body");
                return;
            }
            return c.handleOpenSecureChannel(ctx, &d);
        }
        if (ctx.message_type == .close_secure_channel) {
            // §5.5.3: no response — the channel (and the socket) just close.
            c.state = .closed;
            return;
        }

        // MSG: every Part-4 service.
        const numeric = switch (type_id) {
            .numeric => |n| if (n.namespace == 0) n.id else 0,
            else => 0,
        };
        const t = services.type_id;
        return switch (numeric) {
            t.get_endpoints_request.numeric.id => c.handleGetEndpoints(ctx, &d),
            t.find_servers_request.numeric.id => c.handleFindServers(ctx, &d),
            t.create_session_request.numeric.id => c.handleCreateSession(ctx, &d),
            t.activate_session_request.numeric.id => c.handleActivateSession(ctx, &d),
            t.close_session_request.numeric.id => c.handleCloseSession(ctx, &d),
            t.read_request.numeric.id => c.handleRead(ctx, &d),
            t.write_request.numeric.id => c.handleWrite(ctx, &d),
            t.browse_request.numeric.id => c.handleBrowse(ctx, &d),
            t.browse_next_request.numeric.id => c.handleBrowseNext(ctx, &d),
            t.translate_browse_paths_to_node_ids_request.numeric.id => c.handleTranslateBrowsePaths(ctx, &d),
            t.call_request.numeric.id => c.handleCall(ctx, &d),
            t.create_subscription_request.numeric.id => c.handleCreateSubscription(ctx, &d),
            t.modify_subscription_request.numeric.id => c.handleModifySubscription(ctx, &d),
            t.set_publishing_mode_request.numeric.id => c.handleSetPublishingMode(ctx, &d),
            t.delete_subscriptions_request.numeric.id => c.handleDeleteSubscriptions(ctx, &d),
            t.create_monitored_items_request.numeric.id => c.handleCreateMonitoredItems(ctx, &d),
            t.modify_monitored_items_request.numeric.id => c.handleModifyMonitoredItems(ctx, &d),
            t.set_monitoring_mode_request.numeric.id => c.handleSetMonitoringMode(ctx, &d),
            t.delete_monitored_items_request.numeric.id => c.handleDeleteMonitoredItems(ctx, &d),
            t.publish_request.numeric.id => c.handlePublish(ctx, &d),
            t.republish_request.numeric.id => c.handleRepublish(ctx, &d),
            else => {
                // A service this server does not implement still gets a
                // well-formed answer (§7.38). The RequestHeader is decoded
                // first, best effort, so the fault can echo the RequestHandle.
                if (services.decodeRequestHeader(&d)) |header| {
                    ctx.request_handle = header.request_handle;
                } else |_| {}
                return sendFault(ctx, status.bad_service_unsupported);
            },
        };
    }

    fn sendResponse(
        ctx: *Ctx,
        type_id: encoding.NodeId,
        comptime T: type,
        value: T,
        comptime encodeFn: fn (*encoding.Encoder, T) encoding.EncodeError!void,
    ) ServerError!void {
        var body = std.Io.Writer.Allocating.init(ctx.arena);
        var e = encoding.Encoder.init(&body.writer);
        try e.encodeNodeId(type_id);
        try encodeFn(&e, value);
        try ctx.conn.sendMessage(ctx.out, .message, ctx.request_id, body.writer.buffered());
    }

    fn sendFault(ctx: *Ctx, service_result: encoding.StatusCode) ServerError!void {
        var body = std.Io.Writer.Allocating.init(ctx.arena);
        var e = encoding.Encoder.init(&body.writer);
        try e.encodeNodeId(services.type_id.service_fault);
        try services.encodeServiceFault(&e, .{ .response_header = ctx.responseHeader(service_result) });
        if (ctx.message_type == .open_secure_channel) {
            try ctx.conn.sendOpenResponse(ctx.out, ctx.request_id, body.writer.buffered());
        } else {
            try ctx.conn.sendMessage(ctx.out, .message, ctx.request_id, body.writer.buffered());
        }
    }

    /// Resolve the session a request claims, enforcing the three checks
    /// §5.6 requires on every service call: the token names a live session,
    /// it arrived on the channel that session was created on, and (for
    /// everything but ActivateSession) the session is activated. Writes the
    /// matching ServiceFault and returns `null` when any check fails.
    fn sessionOrFault(ctx: *Ctx, header: services.RequestHeader, require_activated: bool) ServerError!?*Session {
        const session = ctx.srv.findSession(header.authentication_token) orelse {
            try sendFault(ctx, status.bad_session_id_invalid);
            return null;
        };
        if (session.channel_id != ctx.conn.channel_id) {
            try sendFault(ctx, status.bad_secure_channel_id_invalid);
            return null;
        }
        if (require_activated and !session.activated) {
            try sendFault(ctx, status.bad_session_not_activated);
            return null;
        }
        session.last_activity_ms = ctx.now_ms;
        return session;
    }

    // ── §5.5.2: OpenSecureChannel ───────────────────────────────────────────

    fn handleOpenSecureChannel(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodeOpenSecureChannelRequest(d);
        ctx.request_handle = request.request_header.request_handle;

        if (request.security_mode != .none) {
            try sendFault(ctx, status.bad_security_mode_rejected);
            return;
        }
        switch (request.request_type) {
            .issue => {
                c.channel_id = c.server.next_channel_id;
                c.server.next_channel_id +%= 1;
                if (c.server.next_channel_id == 0) c.server.next_channel_id = 1;
                c.send_sequence_number = 0;
            },
            .renew => {
                if (c.channel_id == 0) {
                    try sendFault(ctx, status.bad_secure_channel_id_invalid);
                    return;
                }
            },
        }
        c.token_id = c.server.next_token_id;
        c.server.next_token_id +%= 1;
        if (c.server.next_token_id == 0) c.server.next_token_id = 1;
        c.token_created_ms = ctx.now_ms;
        c.token_lifetime_ms = clampLifetime(request.requested_lifetime);

        var body = std.Io.Writer.Allocating.init(ctx.arena);
        var e = encoding.Encoder.init(&body.writer);
        try e.encodeNodeId(services.type_id.open_secure_channel_response);
        try services.encodeOpenSecureChannelResponse(&e, .{
            .response_header = ctx.responseHeader(status.good),
            .server_protocol_version = 0,
            .security_token = .{
                .channel_id = c.channel_id,
                .token_id = c.token_id,
                .created_at = ctx.srv.dateTime(ctx.now_ms),
                .revised_lifetime = c.token_lifetime_ms,
            },
            // SecurityMode=None: the nonce is present but empty — exactly what
            // this module's own client sends in the same position.
            .server_nonce = &.{},
        });
        try c.sendOpenResponse(ctx.out, ctx.request_id, body.writer.buffered());
    }

    fn clampLifetime(requested: u32) u32 {
        if (requested == 0) return 600_000;
        return std.math.clamp(requested, 60_000, 3_600_000);
    }

    // ── §5.4: discovery ─────────────────────────────────────────────────────

    fn handleGetEndpoints(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeGetEndpointsRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        try sendResponse(ctx, services.type_id.get_endpoints_response, services.GetEndpointsResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .endpoints = ctx.srv.config.endpoints,
        }, services.encodeGetEndpointsResponse);
    }

    fn handleFindServers(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeFindServersRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const urls = try ctx.arena.alloc(?[]const u8, ctx.srv.config.endpoints.len);
        for (ctx.srv.config.endpoints, 0..) |ep, i| urls[i] = ep.endpoint_url;
        const app = applicationDescription(ctx.srv.config, urls);
        const servers = try ctx.arena.alloc(services.ApplicationDescription, 1);
        servers[0] = app;
        try sendResponse(ctx, services.type_id.find_servers_response, services.FindServersResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .servers = servers,
        }, services.encodeFindServersResponse);
    }

    // ── §5.6: sessions ──────────────────────────────────────────────────────

    fn handleCreateSession(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodeCreateSessionRequest(d);
        ctx.request_handle = request.request_header.request_handle;

        if (c.channel_id == 0) {
            try sendFault(ctx, status.bad_secure_channel_id_invalid);
            return;
        }
        if (ctx.srv.sessions.items.len >= ctx.srv.config.max_sessions) {
            try sendFault(ctx, status.bad_too_many_sessions);
            return;
        }

        const requested = request.requested_session_timeout;
        const timeout = if (!(requested > 0))
            ctx.srv.config.max_session_timeout_ms
        else
            std.math.clamp(requested, ctx.srv.config.min_session_timeout_ms, ctx.srv.config.max_session_timeout_ms);

        const session = try ctx.srv.allocator.create(Session);
        errdefer ctx.srv.allocator.destroy(session);
        const name = try ctx.srv.allocator.dupe(u8, request.session_name orelse "");
        errdefer ctx.srv.allocator.free(name);
        session.* = .{
            .allocator = ctx.srv.allocator,
            .numeric_id = ctx.srv.next_session_id,
            .auth_token = undefined,
            .server_nonce = undefined,
            .session_name = name,
            .channel_id = c.channel_id,
            .timeout_ms = timeout,
            .last_activity_ms = ctx.now_ms,
        };
        ctx.srv.random.bytes(&session.auth_token);
        ctx.srv.random.bytes(&session.server_nonce);
        ctx.srv.next_session_id +%= 1;
        if (ctx.srv.next_session_id == 0) ctx.srv.next_session_id = 1;
        try ctx.srv.sessions.append(ctx.srv.allocator, session);

        try sendResponse(ctx, services.type_id.create_session_response, services.CreateSessionResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .session_id = session.sessionId(),
            .authentication_token = session.authenticationToken(),
            .revised_session_timeout = timeout,
            .server_nonce = &session.server_nonce,
            .server_certificate = null, // SecurityMode=None: there is none
            .server_endpoints = ctx.srv.config.endpoints,
            .server_software_certificates = null,
            .server_signature = .{ .algorithm = null, .signature = null },
            .max_request_message_size = ctx.conn.limits.max_message_size,
        }, services.encodeCreateSessionResponse);
    }

    fn handleActivateSession(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodeActivateSessionRequest(d);
        ctx.request_handle = request.request_header.request_handle;

        const session = try sessionOrFault(ctx, request.request_header, false) orelse return;
        const identity_result = c.checkIdentity(ctx, request.user_identity_token);
        if (identity_result != status.good) {
            try sendFault(ctx, identity_result);
            return;
        }
        session.activated = true;
        // §5.6.3.2: a fresh nonce on every activation.
        ctx.srv.random.bytes(&session.server_nonce);

        try sendResponse(ctx, services.type_id.activate_session_response, services.ActivateSessionResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .server_nonce = &session.server_nonce,
            .results = null,
            .diagnostic_infos = null,
        }, services.encodeActivateSessionResponse);
    }

    /// Anonymous and username identity tokens (§7.36). A username token's
    /// password is compared in constant time; at SecurityPolicy#None it
    /// arrived in the clear, which is why `Config.users` is empty by default.
    fn checkIdentity(c: *Connection, ctx: *Ctx, token: encoding.ExtensionObject) encoding.StatusCode {
        _ = c;
        const cfg = ctx.srv.config;
        if (token.encoding == .no_body or token.body.len == 0) {
            // An absent token means Anonymous (several clients send one).
            return if (cfg.allow_anonymous) status.good else status.bad_identity_token_rejected;
        }
        if (services.nodeIdEql(token.type_id, services.type_id.anonymous_identity_token)) {
            return if (cfg.allow_anonymous) status.good else status.bad_identity_token_rejected;
        }
        if (services.nodeIdEql(token.type_id, services.type_id.user_name_identity_token)) {
            var r: std.Io.Reader = .fixed(token.body);
            var td = encoding.Decoder.init(&r, ctx.arena);
            const parsed = services.decodeUserNameIdentityToken(&td) catch return status.bad_identity_token_invalid;
            if (parsed.encryption_algorithm) |algo| {
                if (algo.len != 0) return status.bad_identity_token_invalid; // no decryption here
            }
            const user = parsed.user_name orelse return status.bad_identity_token_invalid;
            const password = parsed.password orelse &.{};
            var matched = false;
            for (cfg.users) |cred| {
                // Both comparisons run unconditionally (no early exit) so the
                // response time does not leak which prefix was right.
                const user_ok = constantTimeEql(cred.user_name, user);
                const pass_ok = constantTimeEql(cred.password, password);
                matched = matched or (user_ok and pass_ok);
            }
            return if (matched) status.good else status.bad_user_access_denied;
        }
        return status.bad_identity_token_invalid;
    }

    fn handleCloseSession(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeCloseSessionRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, false) orelse return;
        // §5.6.4: `deleteSubscriptions = false` would keep subscriptions alive
        // for a later transfer, which this server does not implement — they
        // die with the session either way.
        ctx.srv.removeSession(session);
        try sendResponse(ctx, services.type_id.close_session_response, services.CloseSessionResponse, .{
            .response_header = ctx.responseHeader(status.good),
        }, services.encodeCloseSessionResponse);
    }

    // ── §5.10: Read / Write ─────────────────────────────────────────────────

    fn handleRead(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeReadRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        _ = try sessionOrFault(ctx, request.request_header, true) orelse return;
        if (request.timestamps_to_return == .invalid) {
            try sendFault(ctx, status.bad_timestamps_to_return_invalid);
            return;
        }
        const nodes = request.nodes_to_read orelse &.{};
        if (nodes.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (nodes.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }

        const results = try ctx.arena.alloc(encoding.DataValue, nodes.len);
        for (nodes, 0..) |rv, i| results[i] = readOne(ctx, rv, request.timestamps_to_return);
        try sendResponse(ctx, services.type_id.read_response, services.ReadResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeReadResponse);
    }

    fn readOne(ctx: *Ctx, rv: services.ReadValueId, ttr: services.TimestampsToReturn) encoding.DataValue {
        if (rv.attribute_id == 0 or rv.attribute_id > 27) return .{ .status = status.bad_attribute_id_invalid };
        if (rv.index_range) |range| {
            // NumericRange (index-range) selection is not implemented — see
            // SPEC.md's deferred list. Rejected rather than silently ignored.
            if (range.len != 0) return .{ .status = status.bad_index_range_invalid };
        }
        if (rv.data_encoding.name) |name| {
            if (name.len != 0 and !std.mem.eql(u8, name, "Default Binary")) return .{ .status = status.bad_data_encoding_invalid };
        }
        const dv = ctx.srv.store.readAttribute(rv.node_id, rv.attribute_id);
        return applyTimestamps(dv, ttr, ctx.srv.dateTime(ctx.now_ms));
    }

    /// Trim/fill the timestamps a `DataValue` leaves the server with
    /// (§5.10.2.2's `TimestampsToReturn`).
    fn applyTimestamps(dv: encoding.DataValue, ttr: services.TimestampsToReturn, now: encoding.DateTime) encoding.DataValue {
        var out = dv;
        switch (ttr) {
            .source => {
                out.server_timestamp = null;
                out.server_pico_seconds = null;
            },
            .server => {
                out.source_timestamp = null;
                out.source_pico_seconds = null;
                out.server_timestamp = now;
            },
            .both => out.server_timestamp = now,
            .neither, .invalid => {
                out.source_timestamp = null;
                out.source_pico_seconds = null;
                out.server_timestamp = null;
                out.server_pico_seconds = null;
            },
        }
        return out;
    }

    fn handleWrite(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeWriteRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        _ = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const nodes = request.nodes_to_write orelse &.{};
        if (nodes.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (nodes.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }
        const now = ctx.srv.dateTime(ctx.now_ms);
        const results = try ctx.arena.alloc(encoding.StatusCode, nodes.len);
        for (nodes, 0..) |wv, i| {
            if (wv.attribute_id == 0 or wv.attribute_id > 27) {
                results[i] = status.bad_attribute_id_invalid;
                continue;
            }
            if (wv.index_range) |range| {
                if (range.len != 0) {
                    results[i] = status.bad_index_range_invalid;
                    continue;
                }
            }
            results[i] = try ctx.srv.store.writeAttribute(wv.node_id, wv.attribute_id, wv.value, now);
        }
        try sendResponse(ctx, services.type_id.write_response, services.WriteResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeWriteResponse);
    }

    // ── §5.8: Browse / BrowseNext / TranslateBrowsePathsToNodeIds ───────────

    fn handleBrowse(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodeBrowseRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const nodes = request.nodes_to_browse orelse &.{};
        if (nodes.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (nodes.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }
        // A View other than the null view: this server has no View nodes.
        if (!isNullNodeId(request.view.view_id)) {
            try sendFault(ctx, status.bad_view_id_unknown);
            return;
        }

        const max_refs = if (request.requested_max_references_per_node == 0)
            ctx.srv.config.max_references_per_browse
        else
            @min(request.requested_max_references_per_node, ctx.srv.config.max_references_per_browse);

        const results = try ctx.arena.alloc(services.BrowseResult, nodes.len);
        for (nodes, 0..) |desc, i| {
            results[i] = try c.browseOne(ctx, session, .{
                .node_id = desc.node_id,
                .reference_type_id = desc.reference_type_id,
                .browse_direction = desc.browse_direction,
                .include_subtypes = desc.include_subtypes,
                .node_class_mask = desc.node_class_mask,
                .result_mask = desc.result_mask,
            }, 0, max_refs);
        }
        try sendResponse(ctx, services.type_id.browse_response, services.BrowseResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeBrowseResponse);
    }

    fn isNullNodeId(node_id: encoding.NodeId) bool {
        return switch (node_id) {
            .numeric => |n| n.namespace == 0 and n.id == 0,
            else => false,
        };
    }

    const BrowseFilter = struct {
        node_id: encoding.NodeId,
        reference_type_id: encoding.NodeId,
        browse_direction: services.BrowseDirection,
        include_subtypes: bool,
        node_class_mask: u32,
        result_mask: u32,
    };

    fn browseOne(
        c: *Connection,
        ctx: *Ctx,
        session: *Session,
        filter: BrowseFilter,
        start_index: usize,
        max_refs: u32,
    ) ServerError!services.BrowseResult {
        _ = c;
        const empty: services.BrowseResult = .{ .status_code = status.good, .continuation_point = null, .references = null };
        if (filter.browse_direction == .invalid) {
            var r = empty;
            r.status_code = status.bad_browse_direction_invalid;
            return r;
        }
        const node = ctx.srv.store.getNode(filter.node_id) orelse {
            var r = empty;
            r.status_code = status.bad_node_id_unknown;
            return r;
        };
        const filter_by_type = !isNullNodeId(filter.reference_type_id);
        if (filter_by_type and !ctx.srv.store.contains(filter.reference_type_id)) {
            var r = empty;
            r.status_code = status.bad_reference_type_id_invalid;
            return r;
        }

        var refs: std.ArrayList(services.ReferenceDescription) = .empty;
        var index = start_index;
        var truncated = false;
        while (index < node.references.items.len) : (index += 1) {
            const ref = node.references.items[index];
            switch (filter.browse_direction) {
                .forward => if (!ref.is_forward) continue,
                .inverse => if (ref.is_forward) continue,
                .both, .invalid => {},
            }
            if (filter_by_type) {
                const matches = if (filter.include_subtypes)
                    ctx.srv.store.isSubtypeOf(ref.reference_type_id, filter.reference_type_id)
                else
                    services.nodeIdEql(ref.reference_type_id, filter.reference_type_id);
                if (!matches) continue;
            }
            const target = ctx.srv.store.getNode(ref.target_id.node_id);
            const node_class: services.NodeClass = if (target) |t| t.nodeClass() else .unspecified;
            if (filter.node_class_mask != 0 and (filter.node_class_mask & @intFromEnum(node_class)) == 0) continue;

            if (refs.items.len >= max_refs) {
                truncated = true;
                break;
            }
            const m = filter.result_mask;
            try refs.append(ctx.arena, .{
                .reference_type_id = if (m & nodestore.result_mask.reference_type_id != 0) ref.reference_type_id else services.null_node_id,
                .is_forward = if (m & nodestore.result_mask.is_forward != 0) ref.is_forward else false,
                .node_id = ref.target_id,
                .browse_name = if (m & nodestore.result_mask.browse_name != 0 and target != null)
                    target.?.browse_name
                else
                    .{ .namespace_index = 0, .name = null },
                .display_name = if (m & nodestore.result_mask.display_name != 0 and target != null)
                    target.?.display_name
                else
                    .{},
                .node_class = if (m & nodestore.result_mask.node_class != 0) node_class else .unspecified,
                .type_definition = if (m & nodestore.result_mask.type_definition != 0)
                    .{ .node_id = ctx.srv.store.typeDefinition(ref.target_id.node_id) orelse services.null_node_id }
                else
                    .{ .node_id = services.null_node_id },
            });
        }

        var continuation: ?[]const u8 = null;
        if (truncated) {
            if (session.continuation_points.items.len >= ctx.srv.config.max_continuation_points) {
                var r = empty;
                r.status_code = status.bad_no_continuation_points;
                return r;
            }
            const handle = ctx.srv.next_continuation_handle;
            ctx.srv.next_continuation_handle +%= 1;
            if (ctx.srv.next_continuation_handle == 0) ctx.srv.next_continuation_handle = 1;
            var cp: ContinuationPoint = .{
                .handle = handle,
                .node_id = try nodestore.dupNodeId(ctx.srv.allocator, filter.node_id),
                .reference_type_id = undefined,
                .browse_direction = filter.browse_direction,
                .include_subtypes = filter.include_subtypes,
                .node_class_mask = filter.node_class_mask,
                .result_mask = filter.result_mask,
                .next_index = index,
                .max_references = max_refs,
            };
            errdefer cp.deinit(ctx.srv.allocator);
            cp.reference_type_id = try nodestore.dupNodeId(ctx.srv.allocator, filter.reference_type_id);
            try session.continuation_points.append(ctx.srv.allocator, cp);
            const bytes = try ctx.arena.alloc(u8, 4);
            std.mem.writeInt(u32, bytes[0..4], handle, .little);
            continuation = bytes;
        }

        return .{
            .status_code = status.good,
            .continuation_point = continuation,
            .references = try refs.toOwnedSlice(ctx.arena),
        };
    }

    fn handleBrowseNext(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodeBrowseNextRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const points = request.continuation_points orelse &.{};
        if (points.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (points.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }
        const invalid: services.BrowseResult = .{
            .status_code = status.bad_continuation_point_invalid,
            .continuation_point = null,
            .references = null,
        };
        const results = try ctx.arena.alloc(services.BrowseResult, points.len);
        for (points, 0..) |maybe_point, i| {
            const bytes = maybe_point orelse {
                results[i] = invalid;
                continue;
            };
            if (bytes.len != 4) {
                results[i] = invalid;
                continue;
            }
            const handle = std.mem.readInt(u32, bytes[0..4], .little);
            // A continuation point is scoped to the session that created it:
            // one handed over from another session (or guessed) is invalid,
            // never someone else's cursor.
            var found: ?usize = null;
            for (session.continuation_points.items, 0..) |cp, idx| {
                if (cp.handle == handle) found = idx;
            }
            const idx = found orelse {
                results[i] = invalid;
                continue;
            };
            var cp = session.continuation_points.orderedRemove(idx);
            defer cp.deinit(ctx.srv.allocator);
            if (request.release_continuation_points) {
                results[i] = .{ .status_code = status.good, .continuation_point = null, .references = null };
                continue;
            }
            results[i] = try c.browseOne(ctx, session, .{
                .node_id = cp.node_id,
                .reference_type_id = cp.reference_type_id,
                .browse_direction = cp.browse_direction,
                .include_subtypes = cp.include_subtypes,
                .node_class_mask = cp.node_class_mask,
                .result_mask = cp.result_mask,
            }, cp.next_index, cp.max_references);
        }
        try sendResponse(ctx, services.type_id.browse_next_response, services.BrowseNextResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeBrowseNextResponse);
    }

    fn handleTranslateBrowsePaths(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeTranslateBrowsePathsToNodeIdsRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        _ = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const paths = request.browse_paths orelse &.{};
        if (paths.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (paths.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }
        const results = try ctx.arena.alloc(services.BrowsePathResult, paths.len);
        for (paths, 0..) |path, i| results[i] = try translateOne(ctx, path);
        try sendResponse(ctx, services.type_id.translate_browse_paths_to_node_ids_response, services.TranslateBrowsePathsToNodeIdsResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeTranslateBrowsePathsToNodeIdsResponse);
    }

    fn translateOne(ctx: *Ctx, path: services.BrowsePath) ServerError!services.BrowsePathResult {
        if (!ctx.srv.store.contains(path.starting_node)) {
            return .{ .status_code = status.bad_node_id_unknown, .targets = null };
        }
        const elements = path.relative_path.elements orelse &.{};
        if (elements.len == 0) return .{ .status_code = status.bad_nothing_to_do, .targets = null };

        var current = path.starting_node;
        for (elements) |element| {
            const node = ctx.srv.store.getNode(current) orelse
                return .{ .status_code = status.bad_no_match, .targets = null };
            const filter_by_type = !isNullNodeId(element.reference_type_id);
            var next: ?encoding.NodeId = null;
            for (node.references.items) |ref| {
                if (ref.is_forward == element.is_inverse) continue;
                if (filter_by_type) {
                    const matches = if (element.include_subtypes)
                        ctx.srv.store.isSubtypeOf(ref.reference_type_id, element.reference_type_id)
                    else
                        services.nodeIdEql(ref.reference_type_id, element.reference_type_id);
                    if (!matches) continue;
                }
                const target = ctx.srv.store.getNode(ref.target_id.node_id) orelse continue;
                if (element.target_name.name) |wanted| {
                    const have = target.browse_name.name orelse "";
                    if (element.target_name.namespace_index != target.browse_name.namespace_index) continue;
                    if (!std.mem.eql(u8, wanted, have)) continue;
                }
                next = ref.target_id.node_id;
                break;
            }
            current = next orelse return .{ .status_code = status.bad_no_match, .targets = null };
        }
        const targets = try ctx.arena.alloc(services.BrowsePathTarget, 1);
        targets[0] = .{
            .target_id = .{ .node_id = current },
            // §7.7: `maxUInt32` = "the whole path was resolved".
            .remaining_path_index = std.math.maxInt(u32),
        };
        return .{ .status_code = status.good, .targets = targets };
    }

    // ── §5.11: Call ─────────────────────────────────────────────────────────

    fn handleCall(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeCallRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        _ = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const calls = request.methods_to_call orelse &.{};
        if (calls.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (calls.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }
        const results = try ctx.arena.alloc(services.CallMethodResult, calls.len);
        for (calls, 0..) |call, i| results[i] = try callOne(ctx, call);
        try sendResponse(ctx, services.type_id.call_response, services.CallResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeCallResponse);
    }

    fn callOne(ctx: *Ctx, call: services.CallMethodRequest) ServerError!services.CallMethodResult {
        var result: services.CallMethodResult = .{
            .status_code = status.good,
            .input_argument_results = null,
            .input_argument_diagnostic_infos = null,
            .output_arguments = null,
        };
        const object = ctx.srv.store.getNode(call.object_id) orelse {
            result.status_code = status.bad_node_id_unknown;
            return result;
        };
        const method = ctx.srv.store.getNode(call.method_id) orelse {
            result.status_code = status.bad_method_invalid;
            return result;
        };
        if (method.attributes != .method) {
            result.status_code = status.bad_method_invalid;
            return result;
        }
        // §5.11.2: the method must be a component of the object it is called
        // on — otherwise any method could be invoked through any object.
        var owned = false;
        for (object.references.items) |ref| {
            if (ref.is_forward and services.nodeIdEql(ref.target_id.node_id, call.method_id)) owned = true;
        }
        if (!owned) {
            result.status_code = status.bad_method_invalid;
            return result;
        }
        const attrs = method.attributes.method;
        if (!attrs.executable or !attrs.user_executable) {
            result.status_code = status.bad_not_executable;
            return result;
        }
        const implementation = attrs.implementation orelse {
            result.status_code = status.bad_not_implemented;
            return result;
        };

        var outputs: std.ArrayList(encoding.Variant) = .empty;
        const inputs = call.input_arguments orelse &.{};
        result.status_code = try implementation(attrs.user_context, ctx.arena, inputs, &outputs);
        if (result.status_code == status.good) {
            result.output_arguments = try outputs.toOwnedSlice(ctx.arena);
            if (inputs.len > 0) {
                const arg_results = try ctx.arena.alloc(encoding.StatusCode, inputs.len);
                @memset(arg_results, status.good);
                result.input_argument_results = arg_results;
            }
        }
        return result;
    }

    // ── §5.13: subscriptions ────────────────────────────────────────────────

    fn handleCreateSubscription(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeCreateSubscriptionRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        if (session.subscriptions.items.len >= ctx.srv.config.max_subscriptions_per_session) {
            try sendFault(ctx, status.bad_too_many_subscriptions);
            return;
        }

        const interval = reviseInterval(ctx.srv.config, request.requested_publishing_interval);
        const keep_alive = reviseKeepAlive(request.requested_max_keep_alive_count);
        const lifetime = reviseLifetime(request.requested_lifetime_count, keep_alive);

        const sub = try ctx.srv.allocator.create(Subscription);
        errdefer ctx.srv.allocator.destroy(sub);
        sub.* = .{
            .id = ctx.srv.next_subscription_id,
            .publishing_interval_ms = interval,
            .max_keep_alive_count = keep_alive,
            .lifetime_count = lifetime,
            .max_notifications_per_publish = if (request.max_notifications_per_publish == 0)
                ctx.srv.config.max_notifications_per_publish
            else
                @min(request.max_notifications_per_publish, ctx.srv.config.max_notifications_per_publish),
            .publishing_enabled = request.publishing_enabled,
            .priority = request.priority,
            .next_publish_ms = ctx.now_ms + @as(i64, @intFromFloat(interval)),
        };
        ctx.srv.next_subscription_id +%= 1;
        if (ctx.srv.next_subscription_id == 0) ctx.srv.next_subscription_id = 1;
        try session.subscriptions.append(ctx.srv.allocator, sub);

        try sendResponse(ctx, services.type_id.create_subscription_response, services.CreateSubscriptionResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .subscription_id = sub.id,
            .revised_publishing_interval = interval,
            .revised_lifetime_count = lifetime,
            .revised_max_keep_alive_count = keep_alive,
        }, services.encodeCreateSubscriptionResponse);
    }

    fn reviseInterval(cfg: Config, requested: f64) f64 {
        if (!(requested > 0)) return cfg.min_publishing_interval_ms; // covers NaN
        return std.math.clamp(requested, cfg.min_publishing_interval_ms, cfg.max_publishing_interval_ms);
    }

    fn reviseKeepAlive(requested: u32) u32 {
        if (requested == 0) return 10;
        return @min(requested, 1000);
    }

    /// §5.13.2: the lifetime count must be at least three keep-alive counts.
    fn reviseLifetime(requested: u32, keep_alive: u32) u32 {
        const floor = keep_alive *| 3;
        return @max(if (requested == 0) floor else requested, floor);
    }

    fn handleModifySubscription(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeModifySubscriptionRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const sub = session.findSubscription(request.subscription_id) orelse {
            try sendFault(ctx, status.bad_subscription_id_invalid);
            return;
        };
        const interval = reviseInterval(ctx.srv.config, request.requested_publishing_interval);
        const keep_alive = reviseKeepAlive(request.requested_max_keep_alive_count);
        const lifetime = reviseLifetime(request.requested_lifetime_count, keep_alive);
        sub.publishing_interval_ms = interval;
        sub.max_keep_alive_count = keep_alive;
        sub.lifetime_count = lifetime;
        sub.max_notifications_per_publish = if (request.max_notifications_per_publish == 0)
            ctx.srv.config.max_notifications_per_publish
        else
            @min(request.max_notifications_per_publish, ctx.srv.config.max_notifications_per_publish);
        sub.priority = request.priority;
        sub.next_publish_ms = ctx.now_ms + @as(i64, @intFromFloat(interval));

        try sendResponse(ctx, services.type_id.modify_subscription_response, services.ModifySubscriptionResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .revised_publishing_interval = interval,
            .revised_lifetime_count = lifetime,
            .revised_max_keep_alive_count = keep_alive,
        }, services.encodeModifySubscriptionResponse);
    }

    fn handleSetPublishingMode(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeSetPublishingModeRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const ids = request.subscription_ids orelse &.{};
        if (ids.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        const results = try ctx.arena.alloc(encoding.StatusCode, ids.len);
        for (ids, 0..) |sub_id, i| {
            if (session.findSubscription(sub_id)) |sub| {
                sub.publishing_enabled = request.publishing_enabled;
                results[i] = status.good;
            } else {
                results[i] = status.bad_subscription_id_invalid;
            }
        }
        try sendResponse(ctx, services.type_id.set_publishing_mode_response, services.SetPublishingModeResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeSetPublishingModeResponse);
    }

    fn handleDeleteSubscriptions(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeDeleteSubscriptionsRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const ids = request.subscription_ids orelse &.{};
        if (ids.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        const results = try ctx.arena.alloc(encoding.StatusCode, ids.len);
        for (ids, 0..) |sub_id, i| {
            results[i] = status.bad_subscription_id_invalid;
            for (session.subscriptions.items, 0..) |sub, idx| {
                if (sub.id != sub_id) continue;
                _ = session.subscriptions.orderedRemove(idx);
                sub.deinit(ctx.srv.allocator);
                ctx.srv.allocator.destroy(sub);
                results[i] = status.good;
                break;
            }
        }
        try sendResponse(ctx, services.type_id.delete_subscriptions_response, services.DeleteSubscriptionsResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeDeleteSubscriptionsResponse);
    }

    // ── §5.12: monitored items ──────────────────────────────────────────────

    fn handleCreateMonitoredItems(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeCreateMonitoredItemsRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        if (request.timestamps_to_return == .invalid) {
            try sendFault(ctx, status.bad_timestamps_to_return_invalid);
            return;
        }
        const sub = session.findSubscription(request.subscription_id) orelse {
            try sendFault(ctx, status.bad_subscription_id_invalid);
            return;
        };
        const items = request.items_to_create orelse &.{};
        if (items.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        if (items.len > ctx.srv.config.max_operations_per_request) {
            try sendFault(ctx, status.bad_too_many_operations);
            return;
        }
        const results = try ctx.arena.alloc(services.MonitoredItemCreateResult, items.len);
        for (items, 0..) |spec, i| results[i] = try createMonitoredItem(ctx, sub, spec, request.timestamps_to_return);
        try sendResponse(ctx, services.type_id.create_monitored_items_response, services.CreateMonitoredItemsResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeCreateMonitoredItemsResponse);
    }

    fn createMonitoredItem(
        ctx: *Ctx,
        sub: *Subscription,
        spec: services.MonitoredItemCreateRequest,
        ttr: services.TimestampsToReturn,
    ) ServerError!services.MonitoredItemCreateResult {
        var result: services.MonitoredItemCreateResult = .{
            .status_code = status.good,
            .monitored_item_id = 0,
            .revised_sampling_interval = 0,
            .revised_queue_size = 0,
            .filter_result = services.no_filter,
        };
        if (sub.monitored_items.items.len >= ctx.srv.config.max_monitored_items_per_subscription) {
            result.status_code = status.bad_too_many_monitored_items;
            return result;
        }
        const target = spec.item_to_monitor;
        if (target.attribute_id == 0 or target.attribute_id > 27) {
            result.status_code = status.bad_attribute_id_invalid;
            return result;
        }
        const probe = ctx.srv.store.readAttribute(target.node_id, target.attribute_id);
        if (probe.status) |sc| {
            if (sc == status.bad_node_id_unknown or sc == status.bad_attribute_id_invalid) {
                result.status_code = sc;
                return result;
            }
        }
        // Only the "no filter" case is implemented — an event/deadband filter
        // is rejected rather than silently ignored (which would hand the
        // client values it did not ask for).
        if (spec.requested_parameters.filter.encoding != .no_body and spec.requested_parameters.filter.body.len != 0) {
            result.status_code = status.bad_monitored_item_filter_unsupported;
            return result;
        }

        const sampling = reviseSampling(ctx.srv.config, sub, spec.requested_parameters.sampling_interval);
        const queue_size = @max(@as(u32, 1), @min(spec.requested_parameters.queue_size, 1000));
        var item: MonitoredItem = .{
            .id = ctx.srv.next_monitored_item_id,
            .client_handle = spec.requested_parameters.client_handle,
            .node_id = try nodestore.dupNodeId(ctx.srv.allocator, target.node_id),
            .attribute_id = target.attribute_id,
            .monitoring_mode = spec.monitoring_mode,
            .sampling_interval_ms = sampling,
            .queue_size = queue_size,
            .discard_oldest = spec.requested_parameters.discard_oldest,
            .timestamps_to_return = ttr,
            .next_sample_ms = ctx.now_ms + @as(i64, @intFromFloat(sampling)),
        };
        errdefer item.deinit(ctx.srv.allocator);
        ctx.srv.next_monitored_item_id +%= 1;
        if (ctx.srv.next_monitored_item_id == 0) ctx.srv.next_monitored_item_id = 1;

        // §5.12.1.2: the initial value is reported as soon as the item is
        // created — every real client (open62541 included) expects it.
        if (item.monitoring_mode != .disabled) {
            const initial = applyTimestamps(probe, item.timestamps_to_return, ctx.srv.dateTime(ctx.now_ms));
            try item.queue.append(ctx.srv.allocator, try nodestore.dupDataValue(ctx.srv.allocator, initial));
            item.last_value = try nodestore.dupDataValue(ctx.srv.allocator, initial);
        }
        try sub.monitored_items.append(ctx.srv.allocator, item);

        result.monitored_item_id = item.id;
        result.revised_sampling_interval = sampling;
        result.revised_queue_size = queue_size;
        return result;
    }

    fn reviseSampling(cfg: Config, sub: *const Subscription, requested: f64) f64 {
        // -1 = "the publishing interval", 0 = "as fast as you can".
        if (!(requested >= 0)) return sub.publishing_interval_ms; // covers -1 and NaN
        if (requested == 0) return @max(cfg.min_sampling_interval_ms, sub.publishing_interval_ms);
        return @max(requested, cfg.min_sampling_interval_ms);
    }

    fn handleModifyMonitoredItems(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeModifyMonitoredItemsRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const sub = session.findSubscription(request.subscription_id) orelse {
            try sendFault(ctx, status.bad_subscription_id_invalid);
            return;
        };
        const items = request.items_to_modify orelse &.{};
        if (items.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        const results = try ctx.arena.alloc(services.MonitoredItemModifyResult, items.len);
        for (items, 0..) |mod, i| {
            const item = sub.findItem(mod.monitored_item_id) orelse {
                results[i] = .{
                    .status_code = status.bad_monitored_item_id_invalid,
                    .revised_sampling_interval = 0,
                    .revised_queue_size = 0,
                    .filter_result = services.no_filter,
                };
                continue;
            };
            const sampling = reviseSampling(ctx.srv.config, sub, mod.requested_parameters.sampling_interval);
            item.sampling_interval_ms = sampling;
            item.queue_size = @max(@as(u32, 1), @min(mod.requested_parameters.queue_size, 1000));
            item.discard_oldest = mod.requested_parameters.discard_oldest;
            item.client_handle = mod.requested_parameters.client_handle;
            item.next_sample_ms = ctx.now_ms + @as(i64, @intFromFloat(sampling));
            results[i] = .{
                .status_code = status.good,
                .revised_sampling_interval = sampling,
                .revised_queue_size = item.queue_size,
                .filter_result = services.no_filter,
            };
        }
        try sendResponse(ctx, services.type_id.modify_monitored_items_response, services.ModifyMonitoredItemsResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeModifyMonitoredItemsResponse);
    }

    fn handleSetMonitoringMode(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeSetMonitoringModeRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const sub = session.findSubscription(request.subscription_id) orelse {
            try sendFault(ctx, status.bad_subscription_id_invalid);
            return;
        };
        const ids = request.monitored_item_ids orelse &.{};
        if (ids.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        const results = try ctx.arena.alloc(encoding.StatusCode, ids.len);
        for (ids, 0..) |item_id, i| {
            if (sub.findItem(item_id)) |item| {
                item.monitoring_mode = request.monitoring_mode;
                results[i] = status.good;
            } else {
                results[i] = status.bad_monitored_item_id_invalid;
            }
        }
        try sendResponse(ctx, services.type_id.set_monitoring_mode_response, services.SetMonitoringModeResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeSetMonitoringModeResponse);
    }

    fn handleDeleteMonitoredItems(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        _ = c;
        const request = try services.decodeDeleteMonitoredItemsRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const sub = session.findSubscription(request.subscription_id) orelse {
            try sendFault(ctx, status.bad_subscription_id_invalid);
            return;
        };
        const ids = request.monitored_item_ids orelse &.{};
        if (ids.len == 0) {
            try sendFault(ctx, status.bad_nothing_to_do);
            return;
        }
        const results = try ctx.arena.alloc(encoding.StatusCode, ids.len);
        for (ids, 0..) |item_id, i| {
            results[i] = status.bad_monitored_item_id_invalid;
            for (sub.monitored_items.items, 0..) |*item, idx| {
                if (item.id != item_id) continue;
                var removed = sub.monitored_items.orderedRemove(idx);
                removed.deinit(ctx.srv.allocator);
                results[i] = status.good;
                break;
            }
        }
        try sendResponse(ctx, services.type_id.delete_monitored_items_response, services.DeleteMonitoredItemsResponse, .{
            .response_header = ctx.responseHeader(status.good),
            .results = results,
            .diagnostic_infos = null,
        }, services.encodeDeleteMonitoredItemsResponse);
    }

    // ── §5.13.5/§5.13.6: Publish / Republish ────────────────────────────────

    fn handlePublish(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodePublishRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        if (session.subscriptions.items.len == 0) {
            try sendFault(ctx, status.bad_no_subscription);
            return;
        }

        // Acknowledgements are processed on arrival; their results ride the
        // *next* response this session gets (§5.13.5), so they are stashed on
        // the session (owned — the per-request arena dies with this call).
        const acks = request.subscription_acknowledgements orelse &.{};
        if (acks.len > 0 and acks.len <= ctx.srv.config.max_operations_per_request) {
            const results = try ctx.srv.allocator.alloc(encoding.StatusCode, acks.len);
            for (acks, 0..) |ack, i| results[i] = acknowledge(session, ack);
            if (session.pending_ack_results) |old| ctx.srv.allocator.free(old);
            session.pending_ack_results = results;
        }

        if (session.publish_queue.items.len >= ctx.srv.config.max_publish_requests) {
            try sendFault(ctx, status.bad_too_many_publish_requests);
            return;
        }
        try session.publish_queue.append(ctx.srv.allocator, .{
            .request_id = ctx.request_id,
            .request_handle = ctx.request_handle,
            .queued_ms = ctx.now_ms,
        });

        // Anything already due goes out immediately — including this very
        // request's answer, if a subscription was waiting for one.
        try c.serviceSubscriptions(session, ctx.out, ctx.now_ms);
    }

    fn acknowledge(session: *Session, ack: services.SubscriptionAcknowledgement) encoding.StatusCode {
        const sub = session.findSubscription(ack.subscription_id) orelse return status.bad_subscription_id_invalid;
        for (sub.retransmission.items, 0..) |m, i| {
            if (m.sequence_number != ack.sequence_number) continue;
            session.allocator.free(m.bytes);
            _ = sub.retransmission.orderedRemove(i);
            return status.good;
        }
        return status.bad_sequence_number_unknown;
    }

    fn handleRepublish(c: *Connection, ctx: *Ctx, d: *encoding.Decoder) HandlerError!void {
        const request = try services.decodeRepublishRequest(d);
        ctx.request_handle = request.request_header.request_handle;
        const session = try sessionOrFault(ctx, request.request_header, true) orelse return;
        const sub = session.findSubscription(request.subscription_id) orelse {
            try sendFault(ctx, status.bad_subscription_id_invalid);
            return;
        };
        for (sub.retransmission.items) |m| {
            if (m.sequence_number != request.retransmit_sequence_number) continue;
            var body = std.Io.Writer.Allocating.init(ctx.arena);
            var e = encoding.Encoder.init(&body.writer);
            try e.encodeNodeId(services.type_id.republish_response);
            try services.encodeResponseHeader(&e, ctx.responseHeader(status.good));
            try body.writer.writeAll(m.bytes); // the NotificationMessage, byte-identical
            try c.sendMessage(ctx.out, .message, ctx.request_id, body.writer.buffered());
            return;
        }
        try sendFault(ctx, status.bad_message_not_available);
    }

    // ── the subscription engine ─────────────────────────────────────────────

    /// Run every due publishing cycle for `session`'s subscriptions and answer
    /// as many queued `PublishRequest`s as there is something to say.
    fn serviceSubscriptions(c: *Connection, session: *Session, out: *std.Io.Writer, now_ms: i64) ServerError!void {
        var i: usize = 0;
        while (i < session.subscriptions.items.len) {
            const sub = session.subscriptions.items[i];
            try sampleDue(c.server, sub, now_ms);

            var cycles: usize = 0;
            while (now_ms >= sub.next_publish_ms and cycles < max_cycles_per_tick) : (cycles += 1) {
                sub.next_publish_ms += @intFromFloat(@max(1.0, sub.publishing_interval_ms));
                try sampleDue(c.server, sub, now_ms);
                if (sub.publishing_enabled and sub.hasReportable()) {
                    sub.pending = .data;
                } else {
                    sub.keep_alive_counter += 1;
                    if (sub.keep_alive_counter >= sub.max_keep_alive_count) sub.pending = .keep_alive;
                }
                if (sub.pending != .none) {
                    if (session.publish_queue.items.len > 0) {
                        try c.publishNotification(session, sub, out, now_ms);
                    } else {
                        sub.late = true;
                        sub.lifetime_counter += 1;
                    }
                }
            }
            if (cycles == max_cycles_per_tick) {
                // A very long stall (a suspended driver, a debugger): resync
                // rather than grinding through thousands of empty cycles.
                sub.next_publish_ms = now_ms + @as(i64, @intFromFloat(@max(1.0, sub.publishing_interval_ms)));
            }
            // A message that could not go out earlier leaves as soon as a
            // Publish request arrives.
            if (sub.pending != .none and session.publish_queue.items.len > 0) {
                try c.publishNotification(session, sub, out, now_ms);
            }
            if (sub.lifetime_counter >= sub.lifetime_count) {
                // §5.13.2: the subscription expired because the client stopped
                // sending Publish requests. Tell it (best effort — that needs
                // a Publish request too), then delete it.
                try c.publishStatusChange(session, sub, out, now_ms, status.bad_timeout);
                _ = session.subscriptions.orderedRemove(i);
                sub.deinit(c.server.allocator);
                c.server.allocator.destroy(sub);
                continue;
            }
            i += 1;
        }
    }

    /// Sample every monitored item whose sampling deadline passed, queueing
    /// values that changed (§5.12.1.4's StatusValue trigger).
    fn sampleDue(srv: *Server, sub: *Subscription, now_ms: i64) ServerError!void {
        for (sub.monitored_items.items) |*item| {
            if (item.monitoring_mode == .disabled) continue;
            if (now_ms < item.next_sample_ms) continue;
            const step: i64 = @intFromFloat(@max(1.0, item.sampling_interval_ms));
            item.next_sample_ms += step;
            if (item.next_sample_ms <= now_ms) item.next_sample_ms = now_ms + step;

            const raw = srv.store.readAttribute(item.node_id, item.attribute_id);
            const dv = applyTimestamps(raw, item.timestamps_to_return, srv.dateTime(now_ms));
            const changed = if (item.last_value) |last| nodestore.dataValueChanged(last, dv) else true;
            if (!changed) continue;

            const owned = try nodestore.dupDataValue(srv.allocator, dv);
            if (item.queue.items.len >= item.queue_size) {
                if (item.discard_oldest) {
                    const dropped = item.queue.orderedRemove(0);
                    encoding.freeDataValue(srv.allocator, dropped);
                } else {
                    // Keep the oldest; drop this newest sample instead.
                    encoding.freeDataValue(srv.allocator, owned);
                    continue;
                }
            }
            try item.queue.append(srv.allocator, owned);
            if (item.last_value) |last| encoding.freeDataValue(srv.allocator, last);
            item.last_value = try nodestore.dupDataValue(srv.allocator, dv);
        }
    }

    /// Answer one queued `PublishRequest` with whatever `sub` owes: a
    /// DataChangeNotification or a keep-alive.
    fn publishNotification(c: *Connection, session: *Session, sub: *Subscription, out: *std.Io.Writer, now_ms: i64) ServerError!void {
        if (session.publish_queue.items.len == 0) return;
        const pending = session.publish_queue.orderedRemove(0);
        const srv = c.server;

        var arena_state = std.heap.ArenaAllocator.init(srv.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const keep_alive = sub.pending == .keep_alive or !sub.hasReportable();
        var more = false;
        var notification_bytes: []const u8 = &.{};

        if (keep_alive) {
            // §5.13.1.1: a keep-alive announces the sequence number the next
            // *real* message will use, without consuming it.
            notification_bytes = try encodeNotificationMessage(arena, sub.next_sequence_number, srv.dateTime(now_ms), null);
        } else {
            const sequence_number = sub.takeSequenceNumber();
            const notifications = try collectNotifications(arena, srv.allocator, sub, &more);
            notification_bytes = try encodeNotificationMessage(arena, sequence_number, srv.dateTime(now_ms), notifications);
            // Retain for Republish (bounded; oldest dropped first).
            const retained = try srv.allocator.dupe(u8, notification_bytes);
            errdefer srv.allocator.free(retained);
            if (sub.retransmission.items.len >= srv.config.max_retransmission_queue) {
                const dropped = sub.retransmission.orderedRemove(0);
                srv.allocator.free(dropped.bytes);
            }
            try sub.retransmission.append(srv.allocator, .{ .sequence_number = sequence_number, .bytes = retained });
        }

        const available = try arena.alloc(u32, sub.retransmission.items.len);
        for (sub.retransmission.items, 0..) |m, i| available[i] = m.sequence_number;

        var body = std.Io.Writer.Allocating.init(arena);
        var e = encoding.Encoder.init(&body.writer);
        try e.encodeNodeId(services.type_id.publish_response);
        try services.encodeResponseHeader(&e, .{
            .timestamp = srv.dateTime(now_ms),
            .request_handle = pending.request_handle,
            .service_result = status.good,
            .service_diagnostics = .{},
            .string_table = null,
            .additional_header = services.no_additional_header,
        });
        try e.encodeUInt32(sub.id);
        try encodeU32Array(&e, available);
        try e.encodeBoolean(more);
        try body.writer.writeAll(notification_bytes);
        try encodeStatusCodeArray(&e, session.pending_ack_results);
        if (session.pending_ack_results) |r| {
            srv.allocator.free(r);
            session.pending_ack_results = null;
        }
        try e.writer.writeInt(i32, -1, .little); // DiagnosticInfos: null array

        try c.sendMessage(out, .message, pending.request_id, body.writer.buffered());

        sub.pending = .none;
        sub.late = false;
        sub.keep_alive_counter = 0;
        sub.lifetime_counter = 0;
    }

    /// Best-effort `StatusChangeNotification` (§5.13.1.2) — sent when a
    /// subscription is about to be deleted for exceeding its lifetime.
    fn publishStatusChange(
        c: *Connection,
        session: *Session,
        sub: *Subscription,
        out: *std.Io.Writer,
        now_ms: i64,
        code: encoding.StatusCode,
    ) ServerError!void {
        if (session.publish_queue.items.len == 0) return;
        const pending = session.publish_queue.orderedRemove(0);
        const srv = c.server;
        var arena_state = std.heap.ArenaAllocator.init(srv.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var status_body = std.Io.Writer.Allocating.init(arena);
        var se = encoding.Encoder.init(&status_body.writer);
        try services.encodeStatusChangeNotification(&se, .{ .status = code, .diagnostic_info = .{} });
        const eo = try arena.alloc(encoding.ExtensionObject, 1);
        eo[0] = .{
            .type_id = services.type_id.status_change_notification,
            .encoding = .byte_string,
            .body = status_body.writer.buffered(),
        };
        const notification_bytes = try encodeNotificationMessage(arena, sub.takeSequenceNumber(), srv.dateTime(now_ms), eo);

        var body = std.Io.Writer.Allocating.init(arena);
        var e = encoding.Encoder.init(&body.writer);
        try e.encodeNodeId(services.type_id.publish_response);
        try services.encodeResponseHeader(&e, .{
            .timestamp = srv.dateTime(now_ms),
            .request_handle = pending.request_handle,
            .service_result = status.good,
            .service_diagnostics = .{},
            .string_table = null,
            .additional_header = services.no_additional_header,
        });
        try e.encodeUInt32(sub.id);
        try e.writer.writeInt(i32, -1, .little); // AvailableSequenceNumbers
        try e.encodeBoolean(false);
        try body.writer.writeAll(notification_bytes);
        try e.writer.writeInt(i32, -1, .little); // Results
        try e.writer.writeInt(i32, -1, .little); // DiagnosticInfos
        try c.sendMessage(out, .message, pending.request_id, body.writer.buffered());
    }

    /// Drain every reporting monitored item's queue into one
    /// `DataChangeNotification` ExtensionObject, capped by the subscription's
    /// `MaxNotificationsPerPublish` (`more` says whether anything was left).
    fn collectNotifications(
        arena: std.mem.Allocator,
        owner: std.mem.Allocator,
        sub: *Subscription,
        more: *bool,
    ) ServerError![]const encoding.ExtensionObject {
        var items: std.ArrayList(services.MonitoredItemNotification) = .empty;
        var budget = sub.max_notifications_per_publish;
        for (sub.monitored_items.items) |*item| {
            if (item.monitoring_mode != .reporting) continue;
            while (item.queue.items.len > 0) {
                if (budget == 0) {
                    more.* = true;
                    break;
                }
                const dv = item.queue.orderedRemove(0);
                // Move the value into the arena so the response outlives the
                // server-allocated queue entry, then release the original.
                const copy = try nodestore.dupDataValue(arena, dv);
                encoding.freeDataValue(owner, dv);
                try items.append(arena, .{ .client_handle = item.client_handle, .value = copy });
                budget -= 1;
            }
        }
        var notification_body = std.Io.Writer.Allocating.init(arena);
        var e = encoding.Encoder.init(&notification_body.writer);
        try services.encodeDataChangeNotification(&e, .{
            .monitored_items = items.items,
            .diagnostic_infos = null,
        });
        const eo = try arena.alloc(encoding.ExtensionObject, 1);
        eo[0] = .{
            .type_id = services.type_id.data_change_notification,
            .encoding = .byte_string,
            .body = notification_body.writer.buffered(),
        };
        return eo;
    }

    fn encodeNotificationMessage(
        arena: std.mem.Allocator,
        sequence_number: u32,
        publish_time: encoding.DateTime,
        notifications: ?[]const encoding.ExtensionObject,
    ) ServerError![]const u8 {
        var buf = std.Io.Writer.Allocating.init(arena);
        var e = encoding.Encoder.init(&buf.writer);
        try services.encodeNotificationMessage(&e, .{
            .sequence_number = sequence_number,
            .publish_time = publish_time,
            .notification_data = notifications,
        });
        return buf.writer.buffered();
    }
};

/// Constant-time byte-slice comparison for credentials of equal length (the
/// length itself is compared first: an OPC UA username is not a secret, and
/// making the comparison length-independent would mean hashing).
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    return acc == 0;
}

fn encodeU32Array(e: *encoding.Encoder, items: ?[]const u32) encoding.EncodeError!void {
    const arr = items orelse {
        try e.writer.writeInt(i32, -1, .little);
        return;
    };
    if (arr.len > std.math.maxInt(i32)) return error.ValueTooLarge;
    try e.writer.writeInt(i32, @intCast(arr.len), .little);
    for (arr) |v| try e.encodeUInt32(v);
}

fn encodeStatusCodeArray(e: *encoding.Encoder, items: ?[]const encoding.StatusCode) encoding.EncodeError!void {
    const arr = items orelse {
        try e.writer.writeInt(i32, -1, .little);
        return;
    };
    if (arr.len > std.math.maxInt(i32)) return error.ValueTooLarge;
    try e.writer.writeInt(i32, @intCast(arr.len), .little);
    for (arr) |v| try e.encodeStatusCode(v);
}

// ── tests ──
//
// The offline suite drives this server with the *module's own client half*
// (`services.Channel`, the same send/recv path `root.zig`'s `SecureChannel`/
// `Session` use) over an in-memory byte pipe: the client encodes a real
// request, `TestRig.pump` hands those bytes to `Connection.feed`, and the
// client decodes whatever came back. Both halves therefore have to agree on
// the wire, not just on a struct. `server_interop.zig` adds the other, harder
// half of the verification: a real open62541 client driving this server.

const testing = std.testing;

fn modifyMonitoredItemsResult(r: services.ModifyMonitoredItemsResponse) encoding.StatusCode {
    return r.response_header.service_result;
}

fn setMonitoringModeResult(r: services.SetMonitoringModeResponse) encoding.StatusCode {
    return r.response_header.service_result;
}

const test_app: services.ApplicationDescription = .{
    .application_uri = "urn:zig-libs:opcua:test-server",
    .product_uri = "urn:zig-libs:opcua",
    .application_name = .{ .locale = "en", .text = "zig-libs opcua test server" },
    .application_type = .server,
    .gateway_server_uri = null,
    .discovery_profile_uri = null,
    .discovery_urls = null,
};

/// Anonymised: a loopback URL, never a real deployment endpoint.
const test_endpoint_url = "opc.tcp://127.0.0.1:4840/";
const test_endpoints = [_]services.EndpointDescription{noneEndpoint(test_endpoint_url, test_app)};

const test_users = [_]UserCredential{.{ .user_name = "operator", .password = "correct horse" }};

/// The user namespace/nodes every rig gets on top of `addStandardNodes`.
const test_ns_uri = "urn:zig-libs:opcua:test";

fn testAnswerMethod(
    user_context: ?*anyopaque,
    allocator: std.mem.Allocator,
    inputs: []const encoding.Variant,
    outputs: *std.ArrayList(encoding.Variant),
) std.mem.Allocator.Error!encoding.StatusCode {
    _ = user_context;
    if (inputs.len != 1) return status.bad_arguments_missing;
    const in = switch (inputs[0]) {
        .scalar => |s| switch (s) {
            .int32 => |v| v,
            else => return status.bad_invalid_argument,
        },
        else => return status.bad_invalid_argument,
    };
    try outputs.append(allocator, .{ .scalar = .{ .int32 = in * 2 } });
    return status.good;
}

const TestRig = struct {
    gpa: std.mem.Allocator,
    store: nodestore.NodeStore,
    srv: Server,
    conn: Connection = undefined,
    prng: std.Random.DefaultPrng,
    recv_buf: []u8,
    msg_buf: []u8,
    server_out: std.Io.Writer.Allocating,
    client_out: std.Io.Writer.Allocating,
    client_reader: std.Io.Reader = undefined,
    client_conn: transport.Connection = undefined,
    channel: services.Channel = undefined,
    now_ms: i64 = 0,
    auth_token: [32]u8 = @splat(0),
    session_id: encoding.NodeId = services.null_node_id,
    /// The user variable every rig exposes (writable Int32, ns=1).
    answer_id: encoding.NodeId = undefined,
    method_id: encoding.NodeId = undefined,
    device_id: encoding.NodeId = undefined,

    const start_time: encoding.DateTime = 132_223_104_000_000_000;

    fn init(rig: *TestRig, gpa: std.mem.Allocator, config: Config) !void {
        rig.* = .{
            .gpa = gpa,
            .store = nodestore.NodeStore.init(gpa),
            .srv = undefined,
            .prng = std.Random.DefaultPrng.init(0x0000_5E_1234),
            .recv_buf = try gpa.alloc(u8, @max(config.limits.receive_buffer_size, 8192)),
            .msg_buf = try gpa.alloc(u8, 1 << 20),
            .server_out = std.Io.Writer.Allocating.init(gpa),
            .client_out = std.Io.Writer.Allocating.init(gpa),
        };
        try rig.store.addStandardNodes(.{ .start_time = start_time });
        const ns = try rig.store.addNamespace(test_ns_uri);
        try rig.store.refreshNamespaceArray();

        rig.device_id = .{ .numeric = .{ .namespace = ns, .id = 1000 } };
        rig.answer_id = .{ .string = .{ .namespace = ns, .id = "the.answer" } };
        rig.method_id = .{ .numeric = .{ .namespace = ns, .id = 62_541 } };
        try rig.store.addObject(.{
            .node_id = rig.device_id,
            .parent_id = nodestore.n0(nodestore.id.objects_folder),
            .browse_name = .{ .namespace_index = ns, .name = "Device" },
        });
        try rig.store.addVariable(.{
            .node_id = rig.answer_id,
            .parent_id = rig.device_id,
            .browse_name = .{ .namespace_index = ns, .name = "the.answer" },
            .value = .{ .scalar = .{ .int32 = 42 } },
            .data_type = nodestore.n0(nodestore.id.int32),
            .access_level = nodestore.access_level.read_write,
            .timestamp = start_time,
        });
        try rig.store.addMethod(.{
            .node_id = rig.method_id,
            .parent_id = rig.device_id,
            .browse_name = .{ .namespace_index = ns, .name = "Double" },
            .implementation = testAnswerMethod,
        });

        rig.srv = Server.init(gpa, &rig.store, config, rig.prng.random());
        rig.srv.wall_clock_epoch = start_time;
        rig.conn = try Connection.init(&rig.srv, rig.recv_buf, rig.msg_buf);
        rig.client_reader = .fixed(&.{});
        rig.client_conn = transport.Connection.init(&rig.client_reader, &rig.client_out.writer);
        rig.channel = .{ .conn = &rig.client_conn, .allocator = gpa };
    }

    fn deinit(rig: *TestRig) void {
        rig.srv.deinit();
        rig.store.deinit();
        rig.gpa.free(rig.recv_buf);
        rig.gpa.free(rig.msg_buf);
        rig.server_out.deinit();
        rig.client_out.deinit();
    }

    fn defaultConfig() Config {
        return .{ .endpoints = &test_endpoints, .users = &test_users };
    }

    /// Hand everything the client wrote to the server.
    fn pump(rig: *TestRig) !void {
        const bytes = rig.client_out.written();
        try rig.conn.feed(bytes, &rig.server_out.writer, rig.now_ms);
        rig.client_out.clearRetainingCapacity();
    }

    fn tick(rig: *TestRig, now_ms: i64) !void {
        rig.now_ms = now_ms;
        try rig.conn.tick(&rig.server_out.writer, now_ms);
    }

    /// Point the client's reader at whatever the server has written so far.
    fn aimReader(rig: *TestRig) void {
        rig.client_reader = .fixed(rig.server_out.written());
        rig.client_conn.reader = &rig.client_reader;
    }

    fn clearServerOut(rig: *TestRig) void {
        rig.server_out.clearRetainingCapacity();
    }

    fn handshake(rig: *TestRig) !void {
        var body: [128]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(u32, 65536, .little);
        try bw.writeInt(u32, 65536, .little);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(i32, @intCast(test_endpoint_url.len), .little);
        try bw.writeAll(test_endpoint_url);
        try rig.client_conn.sendChunk(.{
            .message_type = .hello,
            .chunk_type = .final,
            .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
        }, bw.buffered());
        try rig.pump();

        rig.aimReader();
        var ack_buf: [64]u8 = undefined;
        const chunk = try rig.client_conn.recvChunk(&ack_buf);
        try testing.expectEqual(transport.MessageType.acknowledge, chunk.header.message_type);
        rig.clearServerOut();
    }

    fn openChannel(rig: *TestRig) !void {
        const response = try rig.call(
            .open_secure_channel,
            services.type_id.open_secure_channel_request,
            services.OpenSecureChannelRequest,
            .{
                .request_header = rig.channel.nextRequestHeader(services.null_node_id, 10_000),
                .client_protocol_version = 0,
                .request_type = .issue,
                .security_mode = .none,
                .client_nonce = &.{},
                .requested_lifetime = 600_000,
            },
            services.encodeOpenSecureChannelRequest,
            services.OpenSecureChannelResponse,
            services.type_id.open_secure_channel_response,
            services.decodeOpenSecureChannelResponse,
            services.result_fns.open_secure_channel,
        );
        defer services.freeOpenSecureChannelResponse(rig.gpa, response);
        rig.channel.channel_id = response.security_token.channel_id;
        rig.channel.token_id = response.security_token.token_id;
    }

    fn authToken(rig: *const TestRig) encoding.NodeId {
        return .{ .byte_string = .{ .namespace = 1, .id = &rig.auth_token } };
    }

    fn header(rig: *TestRig, token: encoding.NodeId) services.RequestHeader {
        return rig.channel.nextRequestHeader(token, 10_000);
    }

    fn createSession(rig: *TestRig) !void {
        const response = try rig.call(
            .message,
            services.type_id.create_session_request,
            services.CreateSessionRequest,
            .{
                .request_header = rig.header(services.null_node_id),
                .client_description = .{
                    .application_uri = "urn:zig-libs:opcua:test-client",
                    .product_uri = "urn:zig-libs:opcua",
                    .application_name = .{ .locale = "en", .text = "zig-libs opcua test client" },
                    .application_type = .client,
                    .gateway_server_uri = null,
                    .discovery_profile_uri = null,
                    .discovery_urls = null,
                },
                .server_uri = null,
                .endpoint_url = test_endpoint_url,
                .session_name = "test",
                .client_nonce = &.{},
                .client_certificate = null,
                .requested_session_timeout = 120_000,
                .max_response_message_size = 0,
            },
            services.encodeCreateSessionRequest,
            services.CreateSessionResponse,
            services.type_id.create_session_response,
            services.decodeCreateSessionResponse,
            services.result_fns.create_session,
        );
        defer services.freeCreateSessionResponse(rig.gpa, response);
        // `freeCreateSessionResponse` leaves SessionId/AuthenticationToken to
        // the caller (the client keeps them past the response — see
        // `root.Session`), so this rig frees them itself.
        defer encoding.freeNodeId(rig.gpa, response.authentication_token);
        defer encoding.freeNodeId(rig.gpa, response.session_id);
        const token = response.authentication_token.byte_string.id.?;
        try testing.expectEqual(@as(usize, 32), token.len);
        @memcpy(&rig.auth_token, token);
        rig.session_id = response.session_id;
    }

    fn activateSession(rig: *TestRig, identity: encoding.ExtensionObject) !void {
        const response = try rig.call(
            .message,
            services.type_id.activate_session_request,
            services.ActivateSessionRequest,
            .{
                .request_header = rig.header(rig.authToken()),
                .client_signature = .{ .algorithm = null, .signature = null },
                .client_software_certificates = null,
                .locale_ids = null,
                .user_identity_token = identity,
                .user_token_signature = .{ .algorithm = null, .signature = null },
            },
            services.encodeActivateSessionRequest,
            services.ActivateSessionResponse,
            services.type_id.activate_session_response,
            services.decodeActivateSessionResponse,
            services.result_fns.activate_session,
        );
        services.freeActivateSessionResponse(rig.gpa, response);
    }

    fn anonymousToken(rig: *TestRig, buf: []u8) !encoding.ExtensionObject {
        _ = rig;
        var w: std.Io.Writer = .fixed(buf);
        var e = encoding.Encoder.init(&w);
        try services.encodeAnonymousIdentityToken(&e, .{ .policy_id = anonymous_policy_id });
        return .{
            .type_id = services.type_id.anonymous_identity_token,
            .encoding = .byte_string,
            .body = w.buffered(),
        };
    }

    /// Bring the connection all the way to an activated anonymous session.
    fn connect(rig: *TestRig) !void {
        try rig.handshake();
        try rig.openChannel();
        try rig.createSession();
        var token_buf: [128]u8 = undefined;
        try rig.activateSession(try rig.anonymousToken(&token_buf));
    }

    /// One request/response round trip through the real wire path.
    fn call(
        rig: *TestRig,
        message_type: transport.MessageType,
        request_type_id: encoding.NodeId,
        comptime Request: type,
        request: Request,
        comptime encodeFn: fn (*encoding.Encoder, Request) encoding.EncodeError!void,
        comptime Response: type,
        response_type_id: encoding.NodeId,
        comptime decodeFn: fn (*encoding.Decoder) encoding.DecodeError!Response,
        comptime resultFn: fn (Response) encoding.StatusCode,
    ) !Response {
        try rig.channel.sendService(message_type, request_type_id, Request, request, encodeFn);
        try rig.pump();
        rig.aimReader();
        // Clear on the error path too: a ServiceFault is a *response*, and
        // leaving its bytes in the pipe would desynchronise the next call.
        errdefer rig.clearServerOut();
        const response = try rig.channel.recvService(message_type, Response, response_type_id, decodeFn, resultFn);
        rig.clearServerOut();
        return response;
    }

    /// The `ERR` message (§7.1.4) the server wrote, if any.
    fn expectTransportError(rig: *TestRig, expected: encoding.StatusCode) !void {
        rig.aimReader();
        var buf: [512]u8 = undefined;
        const chunk = try rig.client_conn.recvChunk(&buf);
        try testing.expectEqual(transport.MessageType.error_msg, chunk.header.message_type);
        var r: std.Io.Reader = .fixed(chunk.body);
        try testing.expectEqual(expected, try r.takeInt(u32, .little));
        try testing.expect(rig.conn.isClosed());
        rig.clearServerOut();
    }
};

test "handshake: HEL/ACK negotiates the minimum of both sides' limits" {
    var rig: TestRig = undefined;
    var config = TestRig.defaultConfig();
    config.limits = .{ .receive_buffer_size = 65536, .send_buffer_size = 65536, .max_message_size = 1 << 20, .max_chunk_count = 16 };
    try rig.init(testing.allocator, config);
    defer rig.deinit();

    var body: [128]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&body);
    try bw.writeInt(u32, 0, .little);
    try bw.writeInt(u32, 16384, .little); // client receive buffer
    try bw.writeInt(u32, 32768, .little); // client send buffer
    try bw.writeInt(u32, 2 << 20, .little); // client max message size
    try bw.writeInt(u32, 0, .little); // client max chunk count: no limit
    try bw.writeInt(i32, @intCast(test_endpoint_url.len), .little);
    try bw.writeAll(test_endpoint_url);
    try rig.client_conn.sendChunk(.{
        .message_type = .hello,
        .chunk_type = .final,
        .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
    }, bw.buffered());
    try rig.pump();

    rig.aimReader();
    var ack_buf: [64]u8 = undefined;
    const chunk = try rig.client_conn.recvChunk(&ack_buf);
    try testing.expectEqual(transport.MessageType.acknowledge, chunk.header.message_type);
    var r: std.Io.Reader = .fixed(chunk.body);
    try testing.expectEqual(@as(u32, 0), try r.takeInt(u32, .little)); // protocol version
    try testing.expectEqual(@as(u32, 32768), try r.takeInt(u32, .little)); // we receive <= their send
    try testing.expectEqual(@as(u32, 16384), try r.takeInt(u32, .little)); // we send <= their receive
    try testing.expectEqual(@as(u32, 1 << 20), try r.takeInt(u32, .little)); // min of both
    try testing.expectEqual(@as(u32, 16), try r.takeInt(u32, .little)); // theirs is "no limit"
    try testing.expectEqualStrings(test_endpoint_url, rig.conn.endpointUrl());
}

test "handshake: a Hello below the 8192-byte minimum is refused with ERR" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();

    var body: [64]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&body);
    try bw.writeInt(u32, 0, .little);
    try bw.writeInt(u32, 1024, .little);
    try bw.writeInt(u32, 1024, .little);
    try bw.writeInt(u32, 0, .little);
    try bw.writeInt(u32, 0, .little);
    try bw.writeInt(i32, -1, .little);
    try rig.client_conn.sendChunk(.{
        .message_type = .hello,
        .chunk_type = .final,
        .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
    }, bw.buffered());
    try rig.pump();
    try rig.expectTransportError(status.bad_tcp_not_enough_resources);
}

test "handshake: an unsupported protocol version and a non-Hello first message are both refused" {
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        var body: [64]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, 7, .little); // no such protocol version
        try bw.writeInt(u32, 65536, .little);
        try bw.writeInt(u32, 65536, .little);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(i32, -1, .little);
        try rig.client_conn.sendChunk(.{ .message_type = .hello, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(bw.buffered().len)) }, bw.buffered());
        try rig.pump();
        try rig.expectTransportError(status.bad_protocol_version_unsupported);
    }
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.client_conn.sendChunk(.{ .message_type = .message, .chunk_type = .final, .message_size = 8 }, "");
        try rig.pump();
        try rig.expectTransportError(status.bad_tcp_message_type_invalid);
    }
}

test "session: OPN -> GetEndpoints -> CreateSession -> ActivateSession (anonymous)" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.handshake();
    try rig.openChannel();
    try testing.expect(rig.channel.channel_id != 0);

    // GetEndpoints is session-less: it works before CreateSession.
    const endpoints = try rig.call(
        .message,
        services.type_id.get_endpoints_request,
        services.GetEndpointsRequest,
        .{
            .request_header = rig.header(services.null_node_id),
            .endpoint_url = test_endpoint_url,
            .locale_ids = null,
            .profile_uris = null,
        },
        services.encodeGetEndpointsRequest,
        services.GetEndpointsResponse,
        services.type_id.get_endpoints_response,
        services.decodeGetEndpointsResponse,
        services.result_fns.get_endpoints,
    );
    defer services.freeGetEndpointsResponse(rig.gpa, endpoints);
    try testing.expectEqual(@as(usize, 1), endpoints.endpoints.?.len);
    const ep = endpoints.endpoints.?[0];
    try testing.expectEqualStrings(test_endpoint_url, ep.endpoint_url.?);
    try testing.expectEqual(services.MessageSecurityMode.none, ep.security_mode);
    try testing.expectEqualStrings(services.security_policy_none_uri, ep.security_policy_uri.?);
    try testing.expectEqual(@as(usize, 2), ep.user_identity_tokens.?.len);
    try testing.expectEqual(services.UserTokenType.anonymous, ep.user_identity_tokens.?[0].token_type);
    try testing.expectEqual(services.UserTokenType.user_name, ep.user_identity_tokens.?[1].token_type);

    const servers = try rig.call(
        .message,
        services.type_id.find_servers_request,
        services.FindServersRequest,
        .{ .request_header = rig.header(services.null_node_id), .endpoint_url = test_endpoint_url, .locale_ids = null, .server_uris = null },
        services.encodeFindServersRequest,
        services.FindServersResponse,
        services.type_id.find_servers_response,
        services.decodeFindServersResponse,
        services.result_fns.find_servers,
    );
    defer services.freeFindServersResponse(rig.gpa, servers);
    try testing.expectEqual(@as(usize, 1), servers.servers.?.len);
    try testing.expectEqualStrings("urn:zig-libs:opcua:server", servers.servers.?[0].application_uri.?);

    try rig.createSession();
    try testing.expectEqual(@as(usize, 1), rig.srv.sessionCount());

    // A service call before ActivateSession is BadSessionNotActivated.
    const nodes = [_]services.ReadValueId{.{
        .node_id = nodestore.n0(nodestore.id.server_status_current_time),
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .data_encoding = .{ .namespace_index = 0, .name = null },
    }};
    try testing.expectError(error.ServiceFault, rig.call(
        .message,
        services.type_id.read_request,
        services.ReadRequest,
        .{ .request_header = rig.header(rig.authToken()), .max_age = 0, .timestamps_to_return = .both, .nodes_to_read = &nodes },
        services.encodeReadRequest,
        services.ReadResponse,
        services.type_id.read_response,
        services.decodeReadResponse,
        services.result_fns.read,
    ));
    try testing.expectEqual(status.bad_session_not_activated, rig.channel.last_service_result);

    var token_buf: [128]u8 = undefined;
    try rig.activateSession(try rig.anonymousToken(&token_buf));

    // ...and it works afterwards.
    const read = try rig.call(
        .message,
        services.type_id.read_request,
        services.ReadRequest,
        .{ .request_header = rig.header(rig.authToken()), .max_age = 0, .timestamps_to_return = .both, .nodes_to_read = &nodes },
        services.encodeReadRequest,
        services.ReadResponse,
        services.type_id.read_response,
        services.decodeReadResponse,
        services.result_fns.read,
    );
    defer services.freeReadResponse(rig.gpa, read);
    try testing.expectEqual(TestRig.start_time, read.results.?[0].value.?.scalar.date_time);
}

test "session: an unknown authentication token is BadSessionIdInvalid, and a username token is checked" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.handshake();
    try rig.openChannel();
    try rig.createSession();

    // A guessed token names no session.
    const bogus: encoding.NodeId = .{ .byte_string = .{ .namespace = 1, .id = &[_]u8{0xAB} ** 32 } };
    try testing.expectError(error.ServiceFault, rig.call(
        .message,
        services.type_id.close_session_request,
        services.CloseSessionRequest,
        .{ .request_header = rig.header(bogus), .delete_subscriptions = true },
        services.encodeCloseSessionRequest,
        services.CloseSessionResponse,
        services.type_id.close_session_response,
        services.decodeCloseSessionResponse,
        services.result_fns.close_session,
    ));
    try testing.expectEqual(status.bad_session_id_invalid, rig.channel.last_service_result);

    // A wrong password is rejected...
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    try services.encodeUserNameIdentityToken(&e, .{
        .policy_id = user_name_policy_id,
        .user_name = "operator",
        .password = "wrong",
        .encryption_algorithm = null,
    });
    const bad_token: encoding.ExtensionObject = .{
        .type_id = services.type_id.user_name_identity_token,
        .encoding = .byte_string,
        .body = w.buffered(),
    };
    try testing.expectError(error.ServiceFault, rig.activateSession(bad_token));
    try testing.expectEqual(status.bad_user_access_denied, rig.channel.last_service_result);

    // ...and the right one is accepted.
    var buf2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    try services.encodeUserNameIdentityToken(&e2, .{
        .policy_id = user_name_policy_id,
        .user_name = "operator",
        .password = "correct horse",
        .encryption_algorithm = null,
    });
    try rig.activateSession(.{
        .type_id = services.type_id.user_name_identity_token,
        .encoding = .byte_string,
        .body = w2.buffered(),
    });
}

test "read/write: Good, BadNodeIdUnknown, BadAttributeIdInvalid, BadNotWritable" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const writes = [_]services.WriteValue{
        .{ .node_id = rig.answer_id, .attribute_id = services.attribute_id.value, .index_range = null, .value = .{ .value = .{ .scalar = .{ .int32 = 43 } } } },
        .{ .node_id = nodestore.n0(999_999), .attribute_id = services.attribute_id.value, .index_range = null, .value = .{ .value = .{ .scalar = .{ .int32 = 1 } } } },
        .{ .node_id = rig.answer_id, .attribute_id = 99, .index_range = null, .value = .{ .value = .{ .scalar = .{ .int32 = 1 } } } },
        .{ .node_id = nodestore.n0(nodestore.id.server_status_current_time), .attribute_id = services.attribute_id.value, .index_range = null, .value = .{ .value = .{ .scalar = .{ .date_time = 1 } } } },
        .{ .node_id = rig.answer_id, .attribute_id = services.attribute_id.value, .index_range = null, .value = .{ .value = .{ .scalar = .{ .string = "not an int32" } } } },
    };
    const write_response = try rig.call(
        .message,
        services.type_id.write_request,
        services.WriteRequest,
        .{ .request_header = rig.header(rig.authToken()), .nodes_to_write = &writes },
        services.encodeWriteRequest,
        services.WriteResponse,
        services.type_id.write_response,
        services.decodeWriteResponse,
        services.result_fns.write,
    );
    defer services.freeWriteResponse(rig.gpa, write_response);
    const results = write_response.results.?;
    try testing.expectEqual(@as(usize, 5), results.len);
    try testing.expectEqual(status.good, results[0]);
    try testing.expectEqual(status.bad_node_id_unknown, results[1]);
    try testing.expectEqual(status.bad_attribute_id_invalid, results[2]);
    try testing.expectEqual(status.bad_not_writable, results[3]);
    try testing.expectEqual(status.bad_type_mismatch, results[4]);

    // The Good write is visible on read-back, with both timestamps.
    const reads = [_]services.ReadValueId{
        .{ .node_id = rig.answer_id, .attribute_id = services.attribute_id.value, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
        .{ .node_id = rig.answer_id, .attribute_id = services.attribute_id.browse_name, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
        .{ .node_id = nodestore.n0(999_999), .attribute_id = services.attribute_id.value, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
    };
    const read_response = try rig.call(
        .message,
        services.type_id.read_request,
        services.ReadRequest,
        .{ .request_header = rig.header(rig.authToken()), .max_age = 0, .timestamps_to_return = .both, .nodes_to_read = &reads },
        services.encodeReadRequest,
        services.ReadResponse,
        services.type_id.read_response,
        services.decodeReadResponse,
        services.result_fns.read,
    );
    defer services.freeReadResponse(rig.gpa, read_response);
    try testing.expectEqual(@as(i32, 43), read_response.results.?[0].value.?.scalar.int32);
    try testing.expect(read_response.results.?[0].source_timestamp != null);
    try testing.expect(read_response.results.?[0].server_timestamp != null);
    try testing.expectEqualStrings("the.answer", read_response.results.?[1].value.?.scalar.qualified_name.name.?);
    try testing.expectEqual(status.bad_node_id_unknown, read_response.results.?[2].status.?);
}

test "browse: RootFolder -> Objects -> Device -> the.answer, with type definitions" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    // This is the acceptance criterion: a client can walk the standard
    // namespace from i=84 all the way down to a user variable.
    var current = nodestore.n0(nodestore.id.root_folder);
    const path = [_][]const u8{ "Objects", "Device", "the.answer" };
    for (path) |want| {
        const descriptions = [_]services.BrowseDescription{.{
            .node_id = current,
            .browse_direction = .forward,
            .reference_type_id = nodestore.n0(nodestore.id.hierarchical_references),
            .include_subtypes = true,
            .node_class_mask = 0,
            .result_mask = nodestore.result_mask.all,
        }};
        const response = try rig.call(
            .message,
            services.type_id.browse_request,
            services.BrowseRequest,
            .{
                .request_header = rig.header(rig.authToken()),
                .view = services.no_view,
                .requested_max_references_per_node = 0,
                .nodes_to_browse = &descriptions,
            },
            services.encodeBrowseRequest,
            services.BrowseResponse,
            services.type_id.browse_response,
            services.decodeBrowseResponse,
            services.result_fns.browse,
        );
        defer services.freeBrowseResponse(rig.gpa, response);
        try testing.expectEqual(status.good, response.results.?[0].status_code);
        var found: ?encoding.NodeId = null;
        for (response.results.?[0].references orelse &.{}) |ref| {
            if (ref.browse_name.name) |name| {
                if (std.mem.eql(u8, name, want)) {
                    found = ref.node_id.node_id;
                    // Every reference carries its type definition + class.
                    try testing.expect(ref.is_forward);
                    try testing.expect(ref.display_name.text != null);
                }
            }
        }
        if (found == null) {
            std.debug.print("\nbrowse: '{s}' not found\n", .{want});
            return error.TestUnexpectedResult;
        }
        current = try nodestore.dupNodeId(rig.gpa, found.?);
        defer encoding.freeNodeId(rig.gpa, current);
    }

    // Inverse browse from the Device object finds its parent folder.
    const inverse = [_]services.BrowseDescription{.{
        .node_id = rig.device_id,
        .browse_direction = .inverse,
        .reference_type_id = nodestore.n0(nodestore.id.organizes),
        .include_subtypes = false,
        .node_class_mask = 0,
        .result_mask = nodestore.result_mask.all,
    }};
    const response = try rig.call(
        .message,
        services.type_id.browse_request,
        services.BrowseRequest,
        .{ .request_header = rig.header(rig.authToken()), .view = services.no_view, .requested_max_references_per_node = 0, .nodes_to_browse = &inverse },
        services.encodeBrowseRequest,
        services.BrowseResponse,
        services.type_id.browse_response,
        services.decodeBrowseResponse,
        services.result_fns.browse,
    );
    defer services.freeBrowseResponse(rig.gpa, response);
    const refs = response.results.?[0].references.?;
    try testing.expectEqual(@as(usize, 1), refs.len);
    try testing.expect(!refs[0].is_forward);
    try testing.expectEqualStrings("Objects", refs[0].browse_name.name.?);
}

test "browse: a View id, an unknown node and a bogus reference type are per-operation failures" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const descriptions = [_]services.BrowseDescription{
        .{ .node_id = nodestore.n0(999_999), .browse_direction = .forward, .reference_type_id = services.null_node_id, .include_subtypes = true, .node_class_mask = 0, .result_mask = 0x3f },
        .{ .node_id = nodestore.n0(nodestore.id.root_folder), .browse_direction = .forward, .reference_type_id = nodestore.n0(999_999), .include_subtypes = true, .node_class_mask = 0, .result_mask = 0x3f },
        .{ .node_id = nodestore.n0(nodestore.id.root_folder), .browse_direction = .invalid, .reference_type_id = services.null_node_id, .include_subtypes = true, .node_class_mask = 0, .result_mask = 0x3f },
    };
    const response = try rig.call(
        .message,
        services.type_id.browse_request,
        services.BrowseRequest,
        .{ .request_header = rig.header(rig.authToken()), .view = services.no_view, .requested_max_references_per_node = 0, .nodes_to_browse = &descriptions },
        services.encodeBrowseRequest,
        services.BrowseResponse,
        services.type_id.browse_response,
        services.decodeBrowseResponse,
        services.result_fns.browse,
    );
    defer services.freeBrowseResponse(rig.gpa, response);
    try testing.expectEqual(status.bad_node_id_unknown, response.results.?[0].status_code);
    try testing.expectEqual(status.bad_reference_type_id_invalid, response.results.?[1].status_code);
    try testing.expectEqual(status.bad_browse_direction_invalid, response.results.?[2].status_code);

    // A non-null View id faults the whole service (there are no View nodes).
    try testing.expectError(error.ServiceFault, rig.call(
        .message,
        services.type_id.browse_request,
        services.BrowseRequest,
        .{
            .request_header = rig.header(rig.authToken()),
            .view = .{ .view_id = nodestore.n0(nodestore.id.views_folder), .timestamp = 0, .view_version = 0 },
            .requested_max_references_per_node = 0,
            .nodes_to_browse = &descriptions,
        },
        services.encodeBrowseRequest,
        services.BrowseResponse,
        services.type_id.browse_response,
        services.decodeBrowseResponse,
        services.result_fns.browse,
    ));
    try testing.expectEqual(status.bad_view_id_unknown, rig.channel.last_service_result);
}

test "browse: continuation points page, release, and never cross sessions" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const descriptions = [_]services.BrowseDescription{.{
        .node_id = nodestore.n0(nodestore.id.root_folder),
        .browse_direction = .both,
        .reference_type_id = services.null_node_id,
        .include_subtypes = true,
        .node_class_mask = 0,
        .result_mask = nodestore.result_mask.all,
    }};
    const first = try rig.call(
        .message,
        services.type_id.browse_request,
        services.BrowseRequest,
        .{ .request_header = rig.header(rig.authToken()), .view = services.no_view, .requested_max_references_per_node = 1, .nodes_to_browse = &descriptions },
        services.encodeBrowseRequest,
        services.BrowseResponse,
        services.type_id.browse_response,
        services.decodeBrowseResponse,
        services.result_fns.browse,
    );
    defer services.freeBrowseResponse(rig.gpa, first);
    try testing.expectEqual(@as(usize, 1), first.results.?[0].references.?.len);
    const point = first.results.?[0].continuation_point.?;
    try testing.expectEqual(@as(usize, 4), point.len);

    // A continuation point that was never issued is rejected — as is one
    // handed to a *different* session (modeled here by a made-up handle,
    // since handles are unique server-wide and looked up per session).
    const bogus_points = [_]?[]const u8{&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }};
    const bogus = try rig.call(
        .message,
        services.type_id.browse_next_request,
        services.BrowseNextRequest,
        .{ .request_header = rig.header(rig.authToken()), .release_continuation_points = false, .continuation_points = &bogus_points },
        services.encodeBrowseNextRequest,
        services.BrowseNextResponse,
        services.type_id.browse_next_response,
        services.decodeBrowseNextResponse,
        services.result_fns.browse_next,
    );
    defer services.freeBrowseNextResponse(rig.gpa, bogus);
    try testing.expectEqual(status.bad_continuation_point_invalid, bogus.results.?[0].status_code);

    // Paging with the real one continues where the first page stopped.
    const points = [_]?[]const u8{point};
    const second = try rig.call(
        .message,
        services.type_id.browse_next_request,
        services.BrowseNextRequest,
        .{ .request_header = rig.header(rig.authToken()), .release_continuation_points = false, .continuation_points = &points },
        services.encodeBrowseNextRequest,
        services.BrowseNextResponse,
        services.type_id.browse_next_response,
        services.decodeBrowseNextResponse,
        services.result_fns.browse_next,
    );
    defer services.freeBrowseNextResponse(rig.gpa, second);
    try testing.expectEqual(status.good, second.results.?[0].status_code);
    try testing.expectEqual(@as(usize, 1), second.results.?[0].references.?.len);
    try testing.expect(!services.nodeIdEql(
        first.results.?[0].references.?[0].node_id.node_id,
        second.results.?[0].references.?[0].node_id.node_id,
    ));

    // Releasing the (new) point frees the cursor without returning more.
    const release_points = [_]?[]const u8{second.results.?[0].continuation_point.?};
    const released = try rig.call(
        .message,
        services.type_id.browse_next_request,
        services.BrowseNextRequest,
        .{ .request_header = rig.header(rig.authToken()), .release_continuation_points = true, .continuation_points = &release_points },
        services.encodeBrowseNextRequest,
        services.BrowseNextResponse,
        services.type_id.browse_next_response,
        services.decodeBrowseNextResponse,
        services.result_fns.browse_next,
    );
    defer services.freeBrowseNextResponse(rig.gpa, released);
    try testing.expectEqual(status.good, released.results.?[0].status_code);
    try testing.expectEqual(@as(?[]const services.ReferenceDescription, null), released.results.?[0].references);
}

test "translateBrowsePathsToNodeIds resolves Objects/Device/the.answer" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const elements = [_]services.RelativePathElement{
        .{ .reference_type_id = nodestore.n0(nodestore.id.organizes), .is_inverse = false, .include_subtypes = true, .target_name = .{ .namespace_index = 0, .name = "Objects" } },
        .{ .reference_type_id = nodestore.n0(nodestore.id.organizes), .is_inverse = false, .include_subtypes = true, .target_name = .{ .namespace_index = 1, .name = "Device" } },
        .{ .reference_type_id = nodestore.n0(nodestore.id.has_component), .is_inverse = false, .include_subtypes = true, .target_name = .{ .namespace_index = 1, .name = "the.answer" } },
    };
    const missing = [_]services.RelativePathElement{
        .{ .reference_type_id = nodestore.n0(nodestore.id.organizes), .is_inverse = false, .include_subtypes = true, .target_name = .{ .namespace_index = 0, .name = "NoSuchChild" } },
    };
    const paths = [_]services.BrowsePath{
        .{ .starting_node = nodestore.n0(nodestore.id.root_folder), .relative_path = .{ .elements = &elements } },
        .{ .starting_node = nodestore.n0(nodestore.id.root_folder), .relative_path = .{ .elements = &missing } },
    };
    const response = try rig.call(
        .message,
        services.type_id.translate_browse_paths_to_node_ids_request,
        services.TranslateBrowsePathsToNodeIdsRequest,
        .{ .request_header = rig.header(rig.authToken()), .browse_paths = &paths },
        services.encodeTranslateBrowsePathsToNodeIdsRequest,
        services.TranslateBrowsePathsToNodeIdsResponse,
        services.type_id.translate_browse_paths_to_node_ids_response,
        services.decodeTranslateBrowsePathsToNodeIdsResponse,
        services.result_fns.translate_browse_paths_to_node_ids,
    );
    defer services.freeTranslateBrowsePathsToNodeIdsResponse(rig.gpa, response);
    try testing.expectEqual(status.good, response.results.?[0].status_code);
    try testing.expect(services.nodeIdEql(rig.answer_id, response.results.?[0].targets.?[0].target_id.node_id));
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), response.results.?[0].targets.?[0].remaining_path_index);
    try testing.expectEqual(status.bad_no_match, response.results.?[1].status_code);
}

test "call: a method doubles its input; wrong object, wrong node and a non-method all fail" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const inputs = [_]encoding.Variant{.{ .scalar = .{ .int32 = 21 } }};
    const calls = [_]services.CallMethodRequest{
        .{ .object_id = rig.device_id, .method_id = rig.method_id, .input_arguments = &inputs },
        // Right method, wrong object: the method is not its component.
        .{ .object_id = nodestore.n0(nodestore.id.objects_folder), .method_id = rig.method_id, .input_arguments = &inputs },
        .{ .object_id = rig.device_id, .method_id = nodestore.n0(999_999), .input_arguments = &inputs },
        // A Variable is not a Method.
        .{ .object_id = rig.device_id, .method_id = rig.answer_id, .input_arguments = &inputs },
        // Wrong argument type.
        .{ .object_id = rig.device_id, .method_id = rig.method_id, .input_arguments = null },
    };
    const response = try rig.call(
        .message,
        services.type_id.call_request,
        services.CallRequest,
        .{ .request_header = rig.header(rig.authToken()), .methods_to_call = &calls },
        services.encodeCallRequest,
        services.CallResponse,
        services.type_id.call_response,
        services.decodeCallResponse,
        services.result_fns.call,
    );
    defer services.freeCallResponse(rig.gpa, response);
    try testing.expectEqual(status.good, response.results.?[0].status_code);
    try testing.expectEqual(@as(i32, 42), response.results.?[0].output_arguments.?[0].scalar.int32);
    try testing.expectEqual(status.bad_method_invalid, response.results.?[1].status_code);
    try testing.expectEqual(status.bad_method_invalid, response.results.?[2].status_code);
    try testing.expectEqual(status.bad_method_invalid, response.results.?[3].status_code);
    try testing.expectEqual(status.bad_arguments_missing, response.results.?[4].status_code);
}

// ── subscriptions ───────────────────────────────────────────────────────────

fn createSubscription(rig: *TestRig, interval_ms: f64, keep_alive: u32) !services.CreateSubscriptionResponse {
    return rig.call(
        .message,
        services.type_id.create_subscription_request,
        services.CreateSubscriptionRequest,
        .{
            .request_header = rig.header(rig.authToken()),
            .requested_publishing_interval = interval_ms,
            .requested_lifetime_count = 100,
            .requested_max_keep_alive_count = keep_alive,
            .max_notifications_per_publish = 0,
            .publishing_enabled = true,
            .priority = 0,
        },
        services.encodeCreateSubscriptionRequest,
        services.CreateSubscriptionResponse,
        services.type_id.create_subscription_response,
        services.decodeCreateSubscriptionResponse,
        services.result_fns.create_subscription,
    );
}

fn rigCreateMonitoredItem(rig: *TestRig, subscription_id: u32, node_id: encoding.NodeId, client_handle: u32) !services.CreateMonitoredItemsResponse {
    const items = [_]services.MonitoredItemCreateRequest{.{
        .item_to_monitor = .{
            .node_id = node_id,
            .attribute_id = services.attribute_id.value,
            .index_range = null,
            .data_encoding = .{ .namespace_index = 0, .name = null },
        },
        .monitoring_mode = .reporting,
        .requested_parameters = .{
            .client_handle = client_handle,
            .sampling_interval = -1,
            .filter = services.no_filter,
            .queue_size = 10,
            .discard_oldest = true,
        },
    }};
    return rig.call(
        .message,
        services.type_id.create_monitored_items_request,
        services.CreateMonitoredItemsRequest,
        .{
            .request_header = rig.header(rig.authToken()),
            .subscription_id = subscription_id,
            .timestamps_to_return = .both,
            .items_to_create = &items,
        },
        services.encodeCreateMonitoredItemsRequest,
        services.CreateMonitoredItemsResponse,
        services.type_id.create_monitored_items_response,
        services.decodeCreateMonitoredItemsResponse,
        services.result_fns.create_monitored_items,
    );
}

/// Send a PublishRequest and read the PublishResponse the server queued or
/// answered immediately. `acks` piggy-backs acknowledgements.
fn publish(rig: *TestRig, acks: []const services.SubscriptionAcknowledgement) !services.PublishResponse {
    return rig.call(
        .message,
        services.type_id.publish_request,
        services.PublishRequest,
        .{
            .request_header = rig.header(rig.authToken()),
            .subscription_acknowledgements = if (acks.len == 0) null else acks,
        },
        services.encodePublishRequest,
        services.PublishResponse,
        services.type_id.publish_response,
        services.decodePublishResponse,
        services.result_fns.publish,
    );
}

/// Park a PublishRequest without reading a response (the long-poll shape: the
/// server answers it later, from `tick`).
fn parkPublish(rig: *TestRig, acks: []const services.SubscriptionAcknowledgement) !u32 {
    try rig.channel.sendService(.message, services.type_id.publish_request, services.PublishRequest, .{
        .request_header = rig.header(rig.authToken()),
        .subscription_acknowledgements = if (acks.len == 0) null else acks,
    }, services.encodePublishRequest);
    try rig.pump();
    return rig.channel.request_id;
}

fn readParkedPublish(rig: *TestRig) !services.PublishResponse {
    rig.aimReader();
    const response = try rig.channel.recvService(
        .message,
        services.PublishResponse,
        services.type_id.publish_response,
        services.decodePublishResponse,
        services.result_fns.publish,
    );
    rig.clearServerOut();
    return response;
}

test "subscription: initial value, data change on tick, keep-alive, acknowledgement, republish" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const sub = try createSubscription(&rig, 100, 3);
    defer services.freeCreateSubscriptionResponse(rig.gpa, sub);
    // 100ms is below the configured floor of 50ms? No: the floor revises up.
    try testing.expectEqual(@as(f64, 100), sub.revised_publishing_interval);
    try testing.expectEqual(@as(u32, 3), sub.revised_max_keep_alive_count);
    try testing.expect(sub.revised_lifetime_count >= 3 * sub.revised_max_keep_alive_count);

    const created = try rigCreateMonitoredItem(&rig, sub.subscription_id, rig.answer_id, 7);
    defer services.freeCreateMonitoredItemsResponse(rig.gpa, created);
    try testing.expectEqual(status.good, created.results.?[0].status_code);
    const monitored_item_id = created.results.?[0].monitored_item_id;
    try testing.expect(monitored_item_id != 0);

    // The first Publish request is parked; the item's initial value
    // (§5.12.1.2) goes out on the first publishing cycle, as sequence 1.
    _ = try parkPublish(&rig, &.{});
    try rig.tick(100);
    const first = try readParkedPublish(&rig);
    defer services.freePublishResponse(rig.gpa, first);
    try testing.expectEqual(sub.subscription_id, first.subscription_id);
    try testing.expectEqual(@as(u32, 1), first.notification_message.sequence_number);
    const data = first.notification_message.notification_data.?;
    try testing.expectEqual(@as(usize, 1), data.len);
    try testing.expect(services.nodeIdEql(data[0].type_id, services.type_id.data_change_notification));
    {
        var r: std.Io.Reader = .fixed(data[0].body);
        var d = encoding.Decoder.init(&r, rig.gpa);
        const dcn = try services.decodeDataChangeNotification(&d);
        defer services.freeDataChangeNotification(rig.gpa, dcn);
        try testing.expectEqual(@as(usize, 1), dcn.monitored_items.?.len);
        try testing.expectEqual(@as(u32, 7), dcn.monitored_items.?[0].client_handle);
        try testing.expectEqual(@as(i32, 42), dcn.monitored_items.?[0].value.value.?.scalar.int32);
    }

    // Park a Publish request, change the value, let the clock run: the parked
    // request comes back with the new value.
    _ = try rig.store.setValue(rig.answer_id, .{ .scalar = .{ .int32 = 99 } }, rig.srv.dateTime(150));
    _ = try parkPublish(&rig, &.{});
    try rig.tick(250);
    const second = try readParkedPublish(&rig);
    defer services.freePublishResponse(rig.gpa, second);
    try testing.expectEqual(@as(u32, 2), second.notification_message.sequence_number);
    {
        var r: std.Io.Reader = .fixed(second.notification_message.notification_data.?[0].body);
        var d = encoding.Decoder.init(&r, rig.gpa);
        const dcn = try services.decodeDataChangeNotification(&d);
        defer services.freeDataChangeNotification(rig.gpa, dcn);
        try testing.expectEqual(@as(i32, 99), dcn.monitored_items.?[0].value.value.?.scalar.int32);
    }
    // Both sequence numbers are still retained for Republish.
    try testing.expectEqual(@as(usize, 2), second.available_sequence_numbers.?.len);

    // Republish reproduces message 2 byte-for-byte.
    const republished = try rig.call(
        .message,
        services.type_id.republish_request,
        services.RepublishRequest,
        .{ .request_header = rig.header(rig.authToken()), .subscription_id = sub.subscription_id, .retransmit_sequence_number = 2 },
        services.encodeRepublishRequest,
        services.RepublishResponse,
        services.type_id.republish_response,
        services.decodeRepublishResponse,
        services.result_fns.republish,
    );
    defer services.freeRepublishResponse(rig.gpa, republished);
    try testing.expectEqual(@as(u32, 2), republished.notification_message.sequence_number);
    {
        var r: std.Io.Reader = .fixed(republished.notification_message.notification_data.?[0].body);
        var d = encoding.Decoder.init(&r, rig.gpa);
        const dcn = try services.decodeDataChangeNotification(&d);
        defer services.freeDataChangeNotification(rig.gpa, dcn);
        try testing.expectEqual(@as(i32, 99), dcn.monitored_items.?[0].value.value.?.scalar.int32);
    }

    // A keep-alive: nothing changed, so after `max_keep_alive_count` cycles
    // the parked request comes back with an empty NotificationMessage that
    // announces (without consuming) the next sequence number.
    _ = try parkPublish(&rig, &.{});
    try rig.tick(700);
    const keep_alive = try readParkedPublish(&rig);
    defer services.freePublishResponse(rig.gpa, keep_alive);
    try testing.expectEqual(@as(u32, 3), keep_alive.notification_message.sequence_number);
    try testing.expectEqual(@as(?[]const encoding.ExtensionObject, null), keep_alive.notification_message.notification_data);

    // Acknowledging sequence 1 removes it from the retransmission queue;
    // acknowledging an unknown sequence number is BadSequenceNumberUnknown.
    const acks = [_]services.SubscriptionAcknowledgement{
        .{ .subscription_id = sub.subscription_id, .sequence_number = 1 },
        .{ .subscription_id = sub.subscription_id, .sequence_number = 4242 },
        .{ .subscription_id = 9999, .sequence_number = 1 },
    };
    _ = try parkPublish(&rig, &acks);
    try rig.tick(1500);
    const acked = try readParkedPublish(&rig);
    defer services.freePublishResponse(rig.gpa, acked);
    try testing.expectEqual(@as(usize, 3), acked.results.?.len);
    try testing.expectEqual(status.good, acked.results.?[0]);
    try testing.expectEqual(status.bad_sequence_number_unknown, acked.results.?[1]);
    try testing.expectEqual(status.bad_subscription_id_invalid, acked.results.?[2]);

    // Republishing the acknowledged message is no longer possible.
    try testing.expectError(error.ServiceFault, rig.call(
        .message,
        services.type_id.republish_request,
        services.RepublishRequest,
        .{ .request_header = rig.header(rig.authToken()), .subscription_id = sub.subscription_id, .retransmit_sequence_number = 1 },
        services.encodeRepublishRequest,
        services.RepublishResponse,
        services.type_id.republish_response,
        services.decodeRepublishResponse,
        services.result_fns.republish,
    ));
    try testing.expectEqual(status.bad_message_not_available, rig.channel.last_service_result);

    // DeleteSubscriptions tears it down; a second delete is unknown.
    const ids = [_]u32{ sub.subscription_id, sub.subscription_id + 1000 };
    const deleted = try rig.call(
        .message,
        services.type_id.delete_subscriptions_request,
        services.DeleteSubscriptionsRequest,
        .{ .request_header = rig.header(rig.authToken()), .subscription_ids = &ids },
        services.encodeDeleteSubscriptionsRequest,
        services.DeleteSubscriptionsResponse,
        services.type_id.delete_subscriptions_response,
        services.decodeDeleteSubscriptionsResponse,
        services.result_fns.delete_subscriptions,
    );
    defer services.freeDeleteSubscriptionsResponse(rig.gpa, deleted);
    try testing.expectEqual(status.good, deleted.results.?[0]);
    try testing.expectEqual(status.bad_subscription_id_invalid, deleted.results.?[1]);
}

test "subscription: Publish without a subscription is BadNoSubscription; the queue is bounded" {
    var rig: TestRig = undefined;
    var config = TestRig.defaultConfig();
    config.max_publish_requests = 2;
    try rig.init(testing.allocator, config);
    defer rig.deinit();
    try rig.connect();

    try testing.expectError(error.ServiceFault, publish(&rig, &.{}));
    try testing.expectEqual(status.bad_no_subscription, rig.channel.last_service_result);

    const sub = try createSubscription(&rig, 1000, 100);
    defer services.freeCreateSubscriptionResponse(rig.gpa, sub);
    // No monitored items: nothing is ever ready, so the requests just queue.
    _ = try parkPublish(&rig, &.{});
    _ = try parkPublish(&rig, &.{});
    try testing.expectError(error.ServiceFault, publish(&rig, &.{}));
    try testing.expectEqual(status.bad_too_many_publish_requests, rig.channel.last_service_result);
}

test "subscription: SetPublishingMode/SetMonitoringMode/ModifyMonitoredItems/DeleteMonitoredItems" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const sub = try createSubscription(&rig, 100, 3);
    defer services.freeCreateSubscriptionResponse(rig.gpa, sub);
    const created = try rigCreateMonitoredItem(&rig, sub.subscription_id, rig.answer_id, 7);
    defer services.freeCreateMonitoredItemsResponse(rig.gpa, created);
    const item_id = created.results.?[0].monitored_item_id;

    const modified = try rig.call(
        .message,
        services.type_id.modify_monitored_items_request,
        services.ModifyMonitoredItemsRequest,
        .{
            .request_header = rig.header(rig.authToken()),
            .subscription_id = sub.subscription_id,
            .timestamps_to_return = .both,
            .items_to_modify = &[_]services.MonitoredItemModifyRequest{
                .{ .monitored_item_id = item_id, .requested_parameters = .{ .client_handle = 8, .sampling_interval = 250, .filter = services.no_filter, .queue_size = 5, .discard_oldest = true } },
                .{ .monitored_item_id = 4242, .requested_parameters = .{ .client_handle = 9, .sampling_interval = 250, .filter = services.no_filter, .queue_size = 5, .discard_oldest = true } },
            },
        },
        services.encodeModifyMonitoredItemsRequest,
        services.ModifyMonitoredItemsResponse,
        services.type_id.modify_monitored_items_response,
        services.decodeModifyMonitoredItemsResponse,
        modifyMonitoredItemsResult,
    );
    defer services.freeModifyMonitoredItemsResponse(rig.gpa, modified);
    try testing.expectEqual(status.good, modified.results.?[0].status_code);
    try testing.expectEqual(@as(f64, 250), modified.results.?[0].revised_sampling_interval);
    try testing.expectEqual(status.bad_monitored_item_id_invalid, modified.results.?[1].status_code);

    const monitoring = try rig.call(
        .message,
        services.type_id.set_monitoring_mode_request,
        services.SetMonitoringModeRequest,
        .{
            .request_header = rig.header(rig.authToken()),
            .subscription_id = sub.subscription_id,
            .monitoring_mode = .disabled,
            .monitored_item_ids = &[_]u32{ item_id, 4242 },
        },
        services.encodeSetMonitoringModeRequest,
        services.SetMonitoringModeResponse,
        services.type_id.set_monitoring_mode_response,
        services.decodeSetMonitoringModeResponse,
        setMonitoringModeResult,
    );
    defer services.freeSetMonitoringModeResponse(rig.gpa, monitoring);
    try testing.expectEqual(status.good, monitoring.results.?[0]);
    try testing.expectEqual(status.bad_monitored_item_id_invalid, monitoring.results.?[1]);

    const publishing = try rig.call(
        .message,
        services.type_id.set_publishing_mode_request,
        services.SetPublishingModeRequest,
        .{ .request_header = rig.header(rig.authToken()), .publishing_enabled = false, .subscription_ids = &[_]u32{sub.subscription_id} },
        services.encodeSetPublishingModeRequest,
        services.SetPublishingModeResponse,
        services.type_id.set_publishing_mode_response,
        services.decodeSetPublishingModeResponse,
        services.result_fns.set_publishing_mode,
    );
    defer services.freeSetPublishingModeResponse(rig.gpa, publishing);
    try testing.expectEqual(status.good, publishing.results.?[0]);

    const deleted = try rig.call(
        .message,
        services.type_id.delete_monitored_items_request,
        services.DeleteMonitoredItemsRequest,
        .{ .request_header = rig.header(rig.authToken()), .subscription_id = sub.subscription_id, .monitored_item_ids = &[_]u32{ item_id, 4242 } },
        services.encodeDeleteMonitoredItemsRequest,
        services.DeleteMonitoredItemsResponse,
        services.type_id.delete_monitored_items_response,
        services.decodeDeleteMonitoredItemsResponse,
        services.result_fns.delete_monitored_items,
    );
    defer services.freeDeleteMonitoredItemsResponse(rig.gpa, deleted);
    try testing.expectEqual(status.good, deleted.results.?[0]);
    try testing.expectEqual(status.bad_monitored_item_id_invalid, deleted.results.?[1]);
}

test "sessions expire once RevisedSessionTimeout elapses without a request" {
    var rig: TestRig = undefined;
    var config = TestRig.defaultConfig();
    config.min_session_timeout_ms = 1_000;
    config.max_session_timeout_ms = 5_000;
    try rig.init(testing.allocator, config);
    defer rig.deinit();
    try rig.connect();
    try testing.expectEqual(@as(usize, 1), rig.srv.sessionCount());

    try rig.tick(4_000);
    try testing.expectEqual(@as(usize, 1), rig.srv.sessionCount());
    try rig.tick(20_000);
    try testing.expectEqual(@as(usize, 0), rig.srv.sessionCount());

    // The token now names nothing.
    const nodes = [_]services.ReadValueId{.{
        .node_id = rig.answer_id,
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .data_encoding = .{ .namespace_index = 0, .name = null },
    }};
    try testing.expectError(error.ServiceFault, rig.call(
        .message,
        services.type_id.read_request,
        services.ReadRequest,
        .{ .request_header = rig.header(rig.authToken()), .max_age = 0, .timestamps_to_return = .both, .nodes_to_read = &nodes },
        services.encodeReadRequest,
        services.ReadResponse,
        services.type_id.read_response,
        services.decodeReadResponse,
        services.result_fns.read,
    ));
    try testing.expectEqual(status.bad_session_id_invalid, rig.channel.last_service_result);
}

// ── chunking + hostile input ────────────────────────────────────────────────

test "chunking: a multi-chunk response is emitted as C…F and a multi-chunk request is reassembled" {
    var rig: TestRig = undefined;
    var config = TestRig.defaultConfig();
    // A deliberately small send buffer so a real response needs several chunks.
    config.limits.send_buffer_size = 8192;
    try rig.init(testing.allocator, config);
    defer rig.deinit();

    // 200 children under the Device object: browsing it cannot fit in one
    // 8 KiB chunk.
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "sensor{d}", .{i});
        try rig.store.addVariable(.{
            .node_id = .{ .numeric = .{ .namespace = 1, .id = 2000 + i } },
            .parent_id = rig.device_id,
            .browse_name = .{ .namespace_index = 1, .name = name },
            .value = .{ .scalar = .{ .double = @floatFromInt(i) } },
            .data_type = nodestore.n0(nodestore.id.double),
        });
    }
    try rig.connect();

    const descriptions = [_]services.BrowseDescription{.{
        .node_id = rig.device_id,
        .browse_direction = .both,
        .reference_type_id = services.null_node_id,
        .include_subtypes = true,
        .node_class_mask = 0,
        .result_mask = nodestore.result_mask.all,
    }};
    try rig.channel.sendService(.message, services.type_id.browse_request, services.BrowseRequest, .{
        .request_header = rig.header(rig.authToken()),
        .view = services.no_view,
        .requested_max_references_per_node = 0,
        .nodes_to_browse = &descriptions,
    }, services.encodeBrowseRequest);
    try rig.pump();

    // Count the chunk headers the server wrote: C… then a final F.
    var chunks: usize = 0;
    var offset: usize = 0;
    const written = rig.server_out.written();
    while (offset + 8 <= written.len) {
        const size = std.mem.readInt(u32, written[offset..][4..8], .little);
        try testing.expect(size <= config.limits.send_buffer_size);
        const chunk_type = written[offset + 3];
        chunks += 1;
        offset += size;
        const is_last = offset >= written.len;
        try testing.expectEqual(
            @as(u8, if (is_last) @intFromEnum(transport.ChunkType.final) else @intFromEnum(transport.ChunkType.intermediate)),
            chunk_type,
        );
    }
    try testing.expect(chunks > 1);
    // …and the client reassembles them into one decodable response.
    rig.aimReader();
    const response = try rig.channel.recvService(.message, services.BrowseResponse, services.type_id.browse_response, services.decodeBrowseResponse, services.result_fns.browse);
    defer services.freeBrowseResponse(rig.gpa, response);
    rig.clearServerOut();
    try testing.expect(response.results.?[0].references.?.len > 200);

    // The other direction: one logical request split across three chunks by
    // hand (this module's own client never splits a request, so the server's
    // reassembly path needs driving directly).
    const nodes = [_]services.ReadValueId{.{
        .node_id = rig.answer_id,
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .data_encoding = .{ .namespace_index = 0, .name = null },
    }};
    var payload = std.Io.Writer.Allocating.init(rig.gpa);
    defer payload.deinit();
    var e = encoding.Encoder.init(&payload.writer);
    try e.encodeNodeId(services.type_id.read_request);
    rig.channel.request_id += 1;
    try services.encodeReadRequest(&e, .{
        .request_header = rig.header(rig.authToken()),
        .max_age = 0,
        .timestamps_to_return = .both,
        .nodes_to_read = &nodes,
    });
    const bytes = payload.written();
    const request_id = rig.channel.request_id;
    var sent: usize = 0;
    var part: usize = 0;
    while (sent < bytes.len) : (part += 1) {
        const take = @min(bytes.len - sent, (bytes.len + 2) / 3);
        const is_final = sent + take >= bytes.len;
        var frame = std.Io.Writer.Allocating.init(rig.gpa);
        defer frame.deinit();
        try frame.writer.writeInt(u32, rig.channel.channel_id, .little);
        try frame.writer.writeInt(u32, rig.channel.token_id, .little);
        try frame.writer.writeInt(u32, @intCast(700 + part), .little);
        try frame.writer.writeInt(u32, request_id, .little);
        try frame.writer.writeAll(bytes[sent..][0..take]);
        try rig.client_conn.sendChunk(.{
            .message_type = .message,
            .chunk_type = if (is_final) .final else .intermediate,
            .message_size = 8 + @as(u32, @intCast(frame.written().len)),
        }, frame.written());
        sent += take;
    }
    try testing.expect(part >= 2);
    try rig.pump();
    rig.aimReader();
    const read = try rig.channel.recvService(.message, services.ReadResponse, services.type_id.read_response, services.decodeReadResponse, services.result_fns.read);
    defer services.freeReadResponse(rig.gpa, read);
    rig.clearServerOut();
    try testing.expectEqual(@as(i32, 42), read.results.?[0].value.?.scalar.int32);
}

test "hostile: a chunk larger than the negotiated receive buffer is refused" {
    var rig: TestRig = undefined;
    var config = TestRig.defaultConfig();
    config.limits.receive_buffer_size = 8192;
    try rig.init(testing.allocator, config);
    defer rig.deinit();
    try rig.handshake();

    // A header claiming 100_000 bytes — never allocated, just refused.
    var header_bytes: [8]u8 = undefined;
    header_bytes[0..3].* = "MSG".*;
    header_bytes[3] = @intFromEnum(transport.ChunkType.final);
    std.mem.writeInt(u32, header_bytes[4..8], 100_000, .little);
    try rig.conn.feed(&header_bytes, &rig.server_out.writer, 0);
    try rig.expectTransportError(status.bad_tcp_message_too_large);
}

test "hostile: more chunks than the negotiated maximum, and an oversize reassembly" {
    var rig: TestRig = undefined;
    var config = TestRig.defaultConfig();
    config.limits.max_chunk_count = 3;
    try rig.init(testing.allocator, config);
    defer rig.deinit();
    try rig.handshake();
    try rig.openChannel();

    // Four intermediate chunks with a 3-chunk budget.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var body: [64]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, rig.channel.channel_id, .little);
        try bw.writeInt(u32, rig.channel.token_id, .little);
        try bw.writeInt(u32, @intCast(100 + i), .little);
        try bw.writeInt(u32, 4242, .little);
        try bw.writeAll("payload!");
        try rig.client_conn.sendChunk(.{
            .message_type = .message,
            .chunk_type = .intermediate,
            .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
        }, bw.buffered());
    }
    try rig.pump();
    try rig.expectTransportError(status.bad_tcp_message_too_large);
}

test "hostile: an abort chunk discards the partial message and the connection survives" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    // One intermediate chunk of a Read request, then an abort.
    {
        var body: [64]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, rig.channel.channel_id, .little);
        try bw.writeInt(u32, rig.channel.token_id, .little);
        try bw.writeInt(u32, 500, .little);
        try bw.writeInt(u32, 999, .little);
        try bw.writeAll("half a request");
        try rig.client_conn.sendChunk(.{ .message_type = .message, .chunk_type = .intermediate, .message_size = 8 + @as(u32, @intCast(bw.buffered().len)) }, bw.buffered());
    }
    {
        var body: [64]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, rig.channel.channel_id, .little);
        try bw.writeInt(u32, rig.channel.token_id, .little);
        try bw.writeInt(u32, 501, .little);
        try bw.writeInt(u32, 999, .little);
        try bw.writeInt(u32, status.bad_timeout, .little); // abort body: code + reason
        try bw.writeInt(i32, -1, .little);
        try rig.client_conn.sendChunk(.{ .message_type = .message, .chunk_type = .abort, .message_size = 8 + @as(u32, @intCast(bw.buffered().len)) }, bw.buffered());
    }
    try rig.pump();
    try testing.expect(!rig.conn.isClosed());
    try testing.expectEqual(@as(usize, 0), rig.server_out.written().len);
    try testing.expectEqual(@as(usize, 0), rig.conn.msg_len);

    // The connection still works afterwards.
    const nodes = [_]services.ReadValueId{.{
        .node_id = rig.answer_id,
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .data_encoding = .{ .namespace_index = 0, .name = null },
    }};
    const response = try rig.call(
        .message,
        services.type_id.read_request,
        services.ReadRequest,
        .{ .request_header = rig.header(rig.authToken()), .max_age = 0, .timestamps_to_return = .both, .nodes_to_read = &nodes },
        services.encodeReadRequest,
        services.ReadResponse,
        services.type_id.read_response,
        services.decodeReadResponse,
        services.result_fns.read,
    );
    defer services.freeReadResponse(rig.gpa, response);
    try testing.expectEqual(@as(i32, 42), response.results.?[0].value.?.scalar.int32);
}

test "hostile: MSG before OPN, a wrong token id, and a rejected security policy" {
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.handshake();
        var body: [32]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, 1, .little); // some channel id
        try bw.writeInt(u32, 1, .little);
        try bw.writeInt(u32, 1, .little);
        try bw.writeInt(u32, 1, .little);
        try rig.client_conn.sendChunk(.{ .message_type = .message, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(bw.buffered().len)) }, bw.buffered());
        try rig.pump();
        try rig.expectTransportError(status.bad_tcp_secure_channel_unknown);
    }
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.handshake();
        try rig.openChannel();
        var body: [32]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, rig.channel.channel_id, .little);
        try bw.writeInt(u32, rig.channel.token_id + 77, .little); // wrong token
        try bw.writeInt(u32, 1, .little);
        try bw.writeInt(u32, 1, .little);
        try rig.client_conn.sendChunk(.{ .message_type = .message, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(bw.buffered().len)) }, bw.buffered());
        try rig.pump();
        try rig.expectTransportError(status.bad_tcp_secure_channel_unknown);
    }
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.handshake();
        const policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
        var body: [256]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(i32, @intCast(policy.len), .little);
        try bw.writeAll(policy);
        try bw.writeInt(i32, -1, .little);
        try bw.writeInt(i32, -1, .little);
        try bw.writeInt(u32, 1, .little);
        try bw.writeInt(u32, 1, .little);
        try rig.client_conn.sendChunk(.{ .message_type = .open_secure_channel, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(bw.buffered().len)) }, bw.buffered());
        try rig.pump();
        try rig.expectTransportError(status.bad_security_policy_rejected);
    }
}

test "hostile: malformed bodies become ServiceFaults, never crashes" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    const Case = struct { name: []const u8, body: []const u8, expect: encoding.StatusCode };
    // Each body is a MSG payload: a type-id NodeId followed by (broken) fields.
    const cases = [_]Case{
        // A NodeId whose encoding byte is a reserved value (0x7F).
        .{ .name = "reserved NodeId encoding byte", .body = &[_]u8{0x7F} ++ &[_]u8{0} ** 8, .expect = status.bad_decoding_error },
        // A well-formed type id for a service this server does not implement
        // (RegisterServer, i=437).
        .{ .name = "unimplemented service", .body = &[_]u8{ 0x01, 0x00 } ++ &[_]u8{ 0xB5, 0x01 } ++ &[_]u8{0} ** 32, .expect = status.bad_service_unsupported },
        // A ReadRequest truncated in the middle of its RequestHeader.
        .{ .name = "truncated ReadRequest", .body = &[_]u8{ 0x01, 0x00, 0x77, 0x02, 0x00 }, .expect = status.bad_decoding_error },
    };
    for (cases) |case| {
        var framed: [128]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&framed);
        try bw.writeInt(u32, rig.channel.channel_id, .little);
        try bw.writeInt(u32, rig.channel.token_id, .little);
        try bw.writeInt(u32, 900, .little);
        rig.channel.request_id += 1;
        try bw.writeInt(u32, rig.channel.request_id, .little);
        try bw.writeAll(case.body);
        try rig.client_conn.sendChunk(.{
            .message_type = .message,
            .chunk_type = .final,
            .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
        }, bw.buffered());
        try rig.pump();
        try testing.expect(!rig.conn.isClosed());

        rig.aimReader();
        const err = rig.channel.recvService(.message, services.ReadResponse, services.type_id.read_response, services.decodeReadResponse, services.result_fns.read);
        try testing.expectError(error.ServiceFault, err);
        try testing.expectEqual(case.expect, rig.channel.last_service_result);
        rig.clearServerOut();
    }
}

test "hostile: an ExtensionObject body length that overruns the message is a decode fault" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.handshake();
    try rig.openChannel();
    try rig.createSession();

    // An ActivateSessionRequest whose UserIdentityToken ExtensionObject
    // claims a 1 GiB body.
    var framed: [256]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&framed);
    try bw.writeInt(u32, rig.channel.channel_id, .little);
    try bw.writeInt(u32, rig.channel.token_id, .little);
    try bw.writeInt(u32, 901, .little);
    rig.channel.request_id += 1;
    try bw.writeInt(u32, rig.channel.request_id, .little);

    var e = encoding.Encoder.init(&bw);
    try e.encodeNodeId(services.type_id.activate_session_request);
    try services.encodeRequestHeader(&e, rig.header(rig.authToken()));
    try services.encodeSignatureData(&e, .{ .algorithm = null, .signature = null });
    try bw.writeInt(i32, -1, .little); // ClientSoftwareCertificates
    try bw.writeInt(i32, -1, .little); // LocaleIds
    // UserIdentityToken: a byte-string ExtensionObject with an absurd length.
    try e.encodeNodeId(services.type_id.anonymous_identity_token);
    try bw.writeByte(0x01); // encoding: byte string
    try bw.writeInt(i32, 1 << 30, .little);
    try bw.writeAll("short");
    try rig.client_conn.sendChunk(.{
        .message_type = .message,
        .chunk_type = .final,
        .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
    }, bw.buffered());
    try rig.pump();
    try testing.expect(!rig.conn.isClosed());

    rig.aimReader();
    try testing.expectError(error.ServiceFault, rig.channel.recvService(
        .message,
        services.ActivateSessionResponse,
        services.type_id.activate_session_response,
        services.decodeActivateSessionResponse,
        services.result_fns.activate_session,
    ));
    try testing.expectEqual(status.bad_decoding_error, rig.channel.last_service_result);
}

test "fuzz: arbitrary bytes never crash or hang the connection state machine" {
    try std.testing.fuzz({}, fuzzConnection, .{});
}

fn fuzzConnection(_: void, smith: *std.testing.Smith) anyerror!void {
    const gpa = testing.allocator;
    var rig: TestRig = undefined;
    try rig.init(gpa, TestRig.defaultConfig());
    defer rig.deinit();

    // Half the runs start from a live session so the fuzzer reaches the
    // service layer, not just the handshake.
    if (smith.value(bool)) {
        rig.connect() catch {};
    }
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();

    var round: usize = 0;
    while (round < 4) : (round += 1) {
        var buf: [512]u8 = undefined;
        smith.bytes(&buf);
        const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
        rig.conn.feed(buf[0..len], &out.writer, @intCast(round * 100)) catch |err| switch (err) {
            error.OutOfMemory, error.WriteFailed, error.ValueTooLarge, error.ResponseTooLarge => {},
        };
        rig.conn.tick(&out.writer, @intCast(round * 100)) catch |err| switch (err) {
            error.OutOfMemory, error.WriteFailed, error.ValueTooLarge, error.ResponseTooLarge => {},
        };
        out.clearRetainingCapacity();
    }
}

test "hostile: a continuation point from another session on the same channel is rejected" {
    var rig: TestRig = undefined;
    try rig.init(testing.allocator, TestRig.defaultConfig());
    defer rig.deinit();
    try rig.connect();

    // Session A takes a continuation point.
    const descriptions = [_]services.BrowseDescription{.{
        .node_id = nodestore.n0(nodestore.id.root_folder),
        .browse_direction = .both,
        .reference_type_id = services.null_node_id,
        .include_subtypes = true,
        .node_class_mask = 0,
        .result_mask = nodestore.result_mask.all,
    }};
    const first = try rig.call(
        .message,
        services.type_id.browse_request,
        services.BrowseRequest,
        .{ .request_header = rig.header(rig.authToken()), .view = services.no_view, .requested_max_references_per_node = 1, .nodes_to_browse = &descriptions },
        services.encodeBrowseRequest,
        services.BrowseResponse,
        services.type_id.browse_response,
        services.decodeBrowseResponse,
        services.result_fns.browse,
    );
    defer services.freeBrowseResponse(rig.gpa, first);
    var point_buf: [8]u8 = undefined;
    const point = first.results.?[0].continuation_point.?;
    @memcpy(point_buf[0..point.len], point);
    const session_a_point = point_buf[0..point.len];

    // Session B is created on the same SecureChannel and activated.
    try rig.createSession();
    var token_buf: [128]u8 = undefined;
    try rig.activateSession(try rig.anonymousToken(&token_buf));
    try testing.expectEqual(@as(usize, 2), rig.srv.sessionCount());

    // Session B may not continue session A's browse.
    const points = [_]?[]const u8{session_a_point};
    const response = try rig.call(
        .message,
        services.type_id.browse_next_request,
        services.BrowseNextRequest,
        .{ .request_header = rig.header(rig.authToken()), .release_continuation_points = false, .continuation_points = &points },
        services.encodeBrowseNextRequest,
        services.BrowseNextResponse,
        services.type_id.browse_next_response,
        services.decodeBrowseNextResponse,
        services.result_fns.browse_next,
    );
    defer services.freeBrowseNextResponse(rig.gpa, response);
    try testing.expectEqual(status.bad_continuation_point_invalid, response.results.?[0].status_code);
}

test "hostile: a chunk header whose size disagrees with the bytes that follow" {
    // (a) Under-claiming: the header says 20 bytes but 40 arrive, so the
    // framing the server reads is garbage — the SecureChannelId it finds
    // belongs to no channel, and the connection is dropped rather than the
    // trailing bytes being re-interpreted as a request.
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.handshake();
        try rig.openChannel();

        var frame: [40]u8 = undefined;
        @memset(&frame, 0xAA);
        frame[0..3].* = "MSG".*;
        frame[3] = @intFromEnum(transport.ChunkType.final);
        std.mem.writeInt(u32, frame[4..8], 20, .little); // claims 20, sends 40
        try rig.conn.feed(&frame, &rig.server_out.writer, 0);
        try rig.expectTransportError(status.bad_tcp_secure_channel_unknown);
    }
    // (b) A size smaller than the 8-byte header itself.
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.handshake();

        var frame: [8]u8 = undefined;
        frame[0..3].* = "MSG".*;
        frame[3] = @intFromEnum(transport.ChunkType.final);
        std.mem.writeInt(u32, frame[4..8], 3, .little); // smaller than the header
        try rig.conn.feed(&frame, &rig.server_out.writer, 0);
        try rig.expectTransportError(status.bad_tcp_message_type_invalid);
    }
    // (c) A size just large enough for the SecureChannelId and nothing else:
    // the declared length disagrees with the framing the message type
    // requires.
    {
        var rig: TestRig = undefined;
        try rig.init(testing.allocator, TestRig.defaultConfig());
        defer rig.deinit();
        try rig.handshake();
        try rig.openChannel();

        var frame: [12]u8 = undefined;
        frame[0..3].* = "MSG".*;
        frame[3] = @intFromEnum(transport.ChunkType.final);
        std.mem.writeInt(u32, frame[4..8], 12, .little);
        std.mem.writeInt(u32, frame[8..12], rig.channel.channel_id, .little);
        try rig.conn.feed(&frame, &rig.server_out.writer, 0);
        try rig.expectTransportError(status.bad_tcp_internal_error);
    }
}
