// SPDX-License-Identifier: MIT

//! **The BACnet/SC node: the connection state machine (Annex AB.5/AB.6).**
//!
//! This is where BACnet/SC stops being a codec. A node's whole job is to keep
//! *one* WebSocket to a hub alive and to notice, promptly and without a timer
//! thread, when it is not.
//!
//! ```text
//!            start()                    onWebSocketOpen()
//!   idle ─────────────► awaiting_websocket ─────────────► awaiting_accept
//!     ▲                        ▲                                │
//!     │ stop()                 │ backoff expires                │ Connect-Accept
//!     │                        │                                ▼
//!  stopped                  backoff ◄──────────────────────  connected
//!                              ▲      socket closed /            │
//!                              │      heartbeat timeout /        │ disconnect()
//!                              │      Disconnect-Request         ▼
//!                              └──────────────────────────  disconnecting
//! ```
//!
//! **Pure and time-injected, exactly like `client` and `device`.** The caller
//! passes `now_ms` into every entry point, opens and closes the WebSocket
//! itself, and transmits whatever `nextOutgoing()` hands back. There is no
//! clock, no thread and no socket inside — which is what makes a 300-second
//! heartbeat timeout and a 300-second reconnect ceiling testable in
//! microseconds instead of unrunnable.
//!
//! Four things here are more subtle than they look:
//!
//! * **Reconnect backoff is bounded on both ends and jittered.** Annex AB's
//!   Network Port object gives a node `SC_Minimum_Reconnect_Time` (2 s) and
//!   `SC_Maximum_Reconnect_Time` (300 s); the doubling in between is what
//!   stops a hub reboot from being answered by every node in a building at
//!   once. The jitter comes from the caller's `std.Random`, never a global.
//! * **Hub failover alternates.** A node configured with a primary and a
//!   failover URI tries the *other* one after each failed attempt, rather than
//!   hammering the primary. `hubInUse()` reports which, and it is what the
//!   node advertises as its `HubConnectionStatus`.
//! * **A VMAC collision is a defined outcome, not an error.** The hub answers
//!   a Connect-Request whose VMAC is already taken by a *different* UUID with a
//!   `BVLC-Result` NAK carrying `node_duplicate_vmac`; the node's response is
//!   to draw a new VMAC and retry. That is the only reason the node holds a
//!   `std.Random` at all.
//! * **The negotiated maxima are enforced on send.** A Connect-Accept may
//!   propose *smaller* limits than we asked for; from then on an NPDU that
//!   would not fit is `error.MessageTooLong` at the point of queuing, not a
//!   frame the peer silently drops.
//!
//! Everything is fixed-size: the outbox is a compile-time-sized ring, so a
//! caller that stops draining gets `error.OutboxFull` rather than an
//! allocation.

const std = @import("std");
const types = @import("types.zig");
const sc = @import("sc.zig");
const sc_ws = @import("sc_ws.zig");

pub const Error = error{
    /// A data message arrived while the connection was not established. Before
    /// Connect-Accept the peer has no business sending anything but a
    /// Connect-Accept or a `BVLC-Result`, so this is either a broken peer or
    /// one probing state it should not be able to reach.
    NotConnected,
    /// The caller tried to queue something the node cannot send in this state.
    InvalidState,
    /// The NPDU is larger than the maximum the peer accepted.
    MessageTooLong,
    /// The outbox is full: the caller has not been draining `nextOutgoing`.
    OutboxFull,
    /// The frame did not decode. Carries no detail on purpose — the detail is
    /// in `lastDecodeError`.
    BadMessage,
} || sc.Error;

/// Which of the two configured hub URIs a node is using.
pub const HubChoice = enum { primary, failover };

/// Why a connection ended. Each maps to an Annex AB error code a node can put
/// in an Advertisement or report upward.
pub const DisconnectReason = enum {
    /// The caller asked for it.
    local_request,
    /// The peer sent a Disconnect-Request.
    peer_request,
    /// The WebSocket went away underneath us.
    transport_closed,
    /// No Connect-Accept inside `connect_wait_ms`.
    connect_timeout,
    /// No traffic at all inside `heartbeat_timeout_ms`.
    heartbeat_timeout,
    /// No Disconnect-ACK inside `disconnect_wait_ms`; we gave up waiting.
    disconnect_timeout,
    /// The hub said our VMAC is already in use by another device.
    vmac_collision,
    /// The peer NAKed our Connect-Request for some other reason.
    connect_rejected,
};

/// The timers Annex AB names, with the standard's default values. All of them
/// are properties of the Network Port object in a real device, which is why
/// they are configuration here rather than constants.
pub const Timings = struct {
    /// `BACnetSC_Connect_Wait_Timeout` — how long a Connect-Request may go
    /// unanswered.
    connect_wait_ms: u32 = 10_000,
    /// `BACnetSC_Disconnect_Wait_Timeout` — how long to wait for a
    /// Disconnect-ACK before closing the socket anyway.
    disconnect_wait_ms: u32 = 10_000,
    /// `BACnetSC_Heartbeat_Timeout` — silence longer than this means the
    /// connection is dead even though the socket still looks open.
    heartbeat_timeout_ms: u32 = 300_000,
    /// How often to send a Heartbeat-Request while otherwise idle. Half the
    /// timeout, so one lost heartbeat does not tear the connection down.
    heartbeat_interval_ms: u32 = 150_000,
    /// `SC_Minimum_Reconnect_Time`.
    min_reconnect_ms: u32 = 2_000,
    /// `SC_Maximum_Reconnect_Time`.
    max_reconnect_ms: u32 = 300_000,
};

pub const Config = struct {
    /// This node's VMAC. May be replaced by the node itself after a collision.
    vmac: sc.Vmac,
    /// This device's permanent UUID.
    uuid: sc.Uuid,
    /// `SC_Primary_Hub_URI`.
    primary_uri: []const u8,
    /// `SC_Failover_Hub_URI`, if the deployment has one.
    failover_uri: ?[]const u8 = null,
    max_bvlc_length: u16 = sc.min_bvlc_length,
    max_npdu_length: u16 = sc.min_bvlc_length,
    /// What this node tells peers about accepting direct connections.
    direct_connections: sc.DirectConnectionSupport = .unsupported,
    /// What the caller asserts about the TLS underneath. Purely reported and
    /// used to decide whether a secure-path option may be claimed; never
    /// verified here (see `sc_ws.TlsAssertion`).
    tls: sc_ws.TlsAssertion = .none,
    timings: Timings = .{},
};

pub const State = enum {
    idle,
    /// The caller has been told to open a WebSocket and has not reported back.
    awaiting_websocket,
    /// Socket up, Connect-Request sent, waiting for Connect-Accept.
    awaiting_accept,
    connected,
    /// Disconnect-Request sent, waiting for Disconnect-ACK.
    disconnecting,
    /// Waiting out the reconnect delay.
    backoff,
    stopped,
};

/// What `poll` and `onMessage` report. One event per call; the caller loops
/// until `.none`, draining `nextOutgoing()` as it goes.
pub const Event = union(enum) {
    none,
    /// Open a WebSocket to `uri`, offering `subprotocol`, over TLS, then call
    /// `onWebSocketOpen`. Failing to open is reported with
    /// `onWebSocketClosed`.
    open_websocket: struct { uri: []const u8, subprotocol: []const u8 },
    /// Close the WebSocket now.
    close_websocket,
    /// The connection is up. `peer` is the hub's own VMAC and UUID.
    connected: struct {
        peer: sc.ConnectInfo,
        max_bvlc_length: u16,
        max_npdu_length: u16,
    },
    /// An NPDU arrived. `bytes` borrows the frame the caller passed in.
    npdu: struct { source: ?sc.Vmac, destination: ?sc.Vmac, bytes: []const u8 },
    advertisement: struct { source: ?sc.Vmac, info: sc.Advertisement },
    address_resolution_ack: struct { source: ?sc.Vmac, uris: []const u8 },
    /// A `BVLC-Result` NAK about something we sent.
    rejected: sc.Result,
    /// A proprietary message, passed through uninterpreted.
    proprietary: struct { source: ?sc.Vmac, message: sc.ProprietaryMessage },
    disconnected: DisconnectReason,
};

/// A node with `outbox_len` queued outgoing frames of at most `frame_cap`
/// octets each.
pub fn NodeWith(comptime outbox_len: usize, comptime frame_cap: usize) type {
    return struct {
        const Self = @This();

        config: Config,
        rand: std.Random,
        state: State = .idle,
        hub: HubChoice = .primary,

        /// Monotonically increasing, wrapping. Annex AB only requires that a
        /// request and its answer share an id, so wrapping is fine; what is
        /// not fine is reusing an id while its answer is still outstanding,
        /// and with one request in flight at a time that cannot happen.
        next_message_id: u16 = 1,
        /// The id of the Connect-Request or Disconnect-Request in flight.
        pending_id: u16 = 0,

        peer: ?sc.ConnectInfo = null,
        negotiated_bvlc: u16 = sc.min_bvlc_length,
        negotiated_npdu: u16 = sc.min_bvlc_length,

        /// When the current connect/disconnect wait expires.
        deadline_ms: u64 = 0,
        /// When the last frame arrived, for the heartbeat timeout.
        last_rx_ms: u64 = 0,
        /// When the next Heartbeat-Request is due.
        next_heartbeat_ms: u64 = 0,
        /// When the backoff ends.
        retry_at_ms: u64 = 0,
        /// The current backoff, doubling from `min_reconnect_ms`.
        backoff_ms: u32 = 0,

        /// Counters a caller can assert on and a fleet simulator can graph.
        attempts: u32 = 0,
        connects: u32 = 0,
        vmac_collisions: u32 = 0,

        outbox: [outbox_len]Slot = @splat(.{}),
        head: usize = 0,
        tail: usize = 0,

        const Slot = struct {
            buf: [frame_cap]u8 = undefined,
            len: usize = 0,
        };

        pub fn init(config: Config, rand: std.Random) Self {
            return .{
                .config = config,
                .rand = rand,
                .negotiated_bvlc = config.max_bvlc_length,
                .negotiated_npdu = config.max_npdu_length,
            };
        }

        // ── outbox ─────────────────────────────────────────────────────────

        /// The next frame to transmit as one binary WebSocket frame, or null.
        /// Borrowed until the call after next.
        pub fn nextOutgoing(self: *Self) ?[]const u8 {
            if (self.head == self.tail) return null;
            const slot = &self.outbox[self.head];
            self.head = (self.head + 1) % outbox_len;
            return slot.buf[0..slot.len];
        }

        pub fn pending(self: *const Self) usize {
            return (self.tail + outbox_len - self.head) % outbox_len;
        }

        fn queue(self: *Self, msg: sc.Message) Error!void {
            const next = (self.tail + 1) % outbox_len;
            if (next == self.head) return error.OutboxFull;
            const slot = &self.outbox[self.tail];
            const written = try sc.encode(msg, &slot.buf);
            slot.len = written.len;
            self.tail = next;
        }

        fn takeMessageId(self: *Self) u16 {
            const id = self.next_message_id;
            self.next_message_id +%= 1;
            // Zero is a perfectly legal id, but keeping it out of rotation
            // makes "no request in flight" unambiguous in `pending_id`.
            if (self.next_message_id == 0) self.next_message_id = 1;
            return id;
        }

        fn header(self: *Self, dest: ?sc.Vmac, id: u16) sc.Header {
            return .{
                .message_id = id,
                .source = self.config.vmac,
                .destination = dest,
            };
        }

        // ── lifecycle ──────────────────────────────────────────────────────

        /// Bring the node up. The returned event tells the caller to open the
        /// WebSocket.
        pub fn start(self: *Self, now_ms: u64) Event {
            self.state = .awaiting_websocket;
            self.backoff_ms = 0;
            self.attempts += 1;
            self.last_rx_ms = now_ms;
            return self.openEvent();
        }

        /// Take the node down. Queues a Disconnect-Request if there is a live
        /// connection to be polite about; otherwise it is immediate.
        pub fn stop(self: *Self, now_ms: u64) Error!Event {
            switch (self.state) {
                .connected => {
                    self.pending_id = self.takeMessageId();
                    // No VMACs: a connection-control message travels between
                    // this node and its hub and goes nowhere else, so there is
                    // nothing to address and nothing to attribute. Heartbeats
                    // and the Disconnect-ACK are spelled the same way.
                    try self.queue(.{
                        .header = .{ .message_id = self.pending_id },
                        .payload = .disconnect_request,
                    });
                    self.state = .disconnecting;
                    self.deadline_ms = now_ms + self.config.timings.disconnect_wait_ms;
                    return .none;
                },
                else => {
                    self.state = .stopped;
                    self.peer = null;
                    return .close_websocket;
                },
            }
        }

        fn openEvent(self: *Self) Event {
            return .{ .open_websocket = .{
                .uri = self.currentUri(),
                .subprotocol = sc.subprotocol_hub,
            } };
        }

        pub fn currentUri(self: *const Self) []const u8 {
            return switch (self.hub) {
                .primary => self.config.primary_uri,
                .failover => self.config.failover_uri orelse self.config.primary_uri,
            };
        }

        pub fn hubInUse(self: *const Self) HubChoice {
            return self.hub;
        }

        /// What this node reports in an Advertisement.
        pub fn hubStatus(self: *const Self) sc.HubConnectionStatus {
            if (self.state != .connected) return .no_hub_connection;
            return switch (self.hub) {
                .primary => .connected_to_primary,
                .failover => .connected_to_failover,
            };
        }

        /// The caller's WebSocket handshake succeeded. Sends the
        /// Connect-Request and starts the connect-wait timer.
        pub fn onWebSocketOpen(self: *Self, now_ms: u64) Error!Event {
            if (self.state != .awaiting_websocket) return error.InvalidState;
            self.pending_id = self.takeMessageId();
            try self.queue(.{
                .header = .{ .message_id = self.pending_id },
                .payload = .{ .connect_request = .{
                    .vmac = self.config.vmac,
                    .uuid = self.config.uuid,
                    .max_bvlc_length = self.config.max_bvlc_length,
                    .max_npdu_length = self.config.max_npdu_length,
                } },
            });
            self.state = .awaiting_accept;
            self.deadline_ms = now_ms + self.config.timings.connect_wait_ms;
            self.last_rx_ms = now_ms;
            return .none;
        }

        /// The caller's WebSocket closed, failed to open, or errored.
        pub fn onWebSocketClosed(self: *Self, now_ms: u64) Event {
            if (self.state == .stopped or self.state == .idle) return .none;
            const reason: DisconnectReason = switch (self.state) {
                .disconnecting => .local_request,
                else => .transport_closed,
            };
            self.enterBackoff(now_ms);
            return .{ .disconnected = reason };
        }

        fn enterBackoff(self: *Self, now_ms: u64) void {
            self.peer = null;
            self.state = .backoff;
            self.flipHub();
            const t = self.config.timings;
            // Double, then clamp, then jitter downward by up to 25%. Jitter is
            // the point of the exercise: a hub that reboots must not be met by
            // every node in the building at the same instant.
            self.backoff_ms = if (self.backoff_ms == 0)
                t.min_reconnect_ms
            else
                @min(t.max_reconnect_ms, self.backoff_ms *| 2);
            const spread = self.backoff_ms / 4;
            const jitter: u32 = if (spread == 0) 0 else self.rand.uintLessThan(u32, spread);
            self.retry_at_ms = now_ms + self.backoff_ms - jitter;
        }

        fn flipHub(self: *Self) void {
            // With no failover configured there is nothing to alternate with.
            if (self.config.failover_uri == null) return;
            self.hub = switch (self.hub) {
                .primary => .failover,
                .failover => .primary,
            };
        }

        // ── timers ─────────────────────────────────────────────────────────

        /// Drives every timer. Call it whenever convenient; it is idempotent
        /// between deadlines and does nothing at all in `idle` or `stopped`.
        pub fn poll(self: *Self, now_ms: u64) Error!Event {
            switch (self.state) {
                .idle, .stopped, .awaiting_websocket => return .none,
                .backoff => {
                    if (now_ms < self.retry_at_ms) return .none;
                    self.state = .awaiting_websocket;
                    self.attempts += 1;
                    return self.openEvent();
                },
                .awaiting_accept => {
                    if (now_ms < self.deadline_ms) return .none;
                    self.enterBackoff(now_ms);
                    return .{ .disconnected = .connect_timeout };
                },
                .disconnecting => {
                    if (now_ms < self.deadline_ms) return .none;
                    self.enterBackoff(now_ms);
                    return .{ .disconnected = .disconnect_timeout };
                },
                .connected => {
                    const t = self.config.timings;
                    if (now_ms -| self.last_rx_ms >= t.heartbeat_timeout_ms) {
                        self.enterBackoff(now_ms);
                        return .{ .disconnected = .heartbeat_timeout };
                    }
                    if (now_ms >= self.next_heartbeat_ms) {
                        try self.queue(.{
                            .header = .{ .message_id = self.takeMessageId() },
                            .payload = .heartbeat_request,
                        });
                        self.next_heartbeat_ms = now_ms + t.heartbeat_interval_ms;
                    }
                    return .none;
                },
            }
        }

        // ── inbound ────────────────────────────────────────────────────────

        /// One inbound BVLC-SC frame, already de-framed from the WebSocket.
        pub fn onMessage(self: *Self, now_ms: u64, frame: []const u8) Error!Event {
            const msg = sc.decode(frame) catch return error.BadMessage;
            self.last_rx_ms = now_ms;

            // The must-understand rule comes before anything else: a message
            // carrying an option we are obliged to understand and do not is
            // refused whole, whatever its function.
            if (try msg.header.unsupportedOption()) |bad| {
                var marker: u8 = @intFromEnum(bad.type);
                if (bad.must_understand) marker |= sc.option_flags.must_understand;
                if (bad.data != null) marker |= sc.option_flags.header_data;
                try self.queue(sc.nak(
                    msg.function(),
                    msg.header.message_id,
                    self.config.vmac,
                    msg.header.source,
                    .{
                        .header_marker = marker,
                        .class = .communication,
                        .code = .header_not_understood,
                    },
                ));
                return .none;
            }

            switch (self.state) {
                .stopped, .idle => return error.NotConnected,
                .awaiting_websocket, .backoff => return error.NotConnected,
                .awaiting_accept => return self.whileAwaitingAccept(now_ms, msg),
                .disconnecting => return self.whileDisconnecting(now_ms, msg),
                .connected => return self.whileConnected(now_ms, msg),
            }
        }

        fn whileAwaitingAccept(self: *Self, now_ms: u64, msg: sc.Message) Error!Event {
            switch (msg.payload) {
                .connect_accept => |accept| {
                    // A hub whose own VMAC is ours is the collision case seen
                    // from the other side: keeping it would make every message
                    // ambiguous.
                    if (accept.vmac.eql(self.config.vmac)) return self.collide(now_ms);

                    const mine: sc.ConnectInfo = .{
                        .vmac = self.config.vmac,
                        .uuid = self.config.uuid,
                        .max_bvlc_length = self.config.max_bvlc_length,
                        .max_npdu_length = self.config.max_npdu_length,
                    };
                    const n = mine.negotiate(accept);
                    self.negotiated_bvlc = n.bvlc;
                    self.negotiated_npdu = n.npdu;
                    self.peer = accept;
                    self.state = .connected;
                    self.connects += 1;
                    self.backoff_ms = 0;
                    self.next_heartbeat_ms = now_ms + self.config.timings.heartbeat_interval_ms;
                    return .{ .connected = .{
                        .peer = accept,
                        .max_bvlc_length = n.bvlc,
                        .max_npdu_length = n.npdu,
                    } };
                },
                .result => |r| {
                    if (r.code != .nak) return .none;
                    if (r.err) |e| {
                        if (e.code == .node_duplicate_vmac) return self.collide(now_ms);
                    }
                    self.enterBackoff(now_ms);
                    return .{ .disconnected = .connect_rejected };
                },
                // Anything else before the connection exists is out of order.
                else => return error.NotConnected,
            }
        }

        fn collide(self: *Self, now_ms: u64) Event {
            self.vmac_collisions += 1;
            self.config.vmac = sc.Vmac.random(self.rand);
            self.enterBackoff(now_ms);
            // A collision is our problem to fix, not the hub's fault, so the
            // retry is at the floor rather than at the doubled backoff.
            self.backoff_ms = self.config.timings.min_reconnect_ms;
            self.retry_at_ms = now_ms + self.backoff_ms;
            return .{ .disconnected = .vmac_collision };
        }

        fn whileDisconnecting(self: *Self, now_ms: u64, msg: sc.Message) Error!Event {
            switch (msg.payload) {
                .disconnect_ack => {
                    self.state = .stopped;
                    self.peer = null;
                    return .close_websocket;
                },
                // A peer may still be draining messages it had queued; ignore
                // them rather than treating the teardown as broken.
                else => {
                    _ = now_ms;
                    return .none;
                },
            }
        }

        fn whileConnected(self: *Self, now_ms: u64, msg: sc.Message) Error!Event {
            switch (msg.payload) {
                .encapsulated_npdu => |bytes| return .{ .npdu = .{
                    .source = msg.header.source,
                    .destination = msg.header.destination,
                    .bytes = bytes,
                } },
                .heartbeat_request => {
                    try self.queue(.{
                        .header = .{ .message_id = msg.header.message_id },
                        .payload = .heartbeat_ack,
                    });
                    return .none;
                },
                .heartbeat_ack => return .none,
                .advertisement => |a| return .{ .advertisement = .{
                    .source = msg.header.source,
                    .info = a,
                } },
                .advertisement_solicitation => {
                    try self.queue(.{
                        .header = self.header(msg.header.source, msg.header.message_id),
                        .payload = .{ .advertisement = .{
                            .hub_status = self.hubStatus(),
                            .direct_connections = self.config.direct_connections,
                            .max_bvlc_length = self.config.max_bvlc_length,
                            .max_npdu_length = self.config.max_npdu_length,
                        } },
                    });
                    return .none;
                },
                .address_resolution => {
                    // A node with no direct-connection URIs of its own answers
                    // with an empty list, which is a legal ACK meaning exactly
                    // that.
                    try self.queue(.{
                        .header = self.header(msg.header.source, msg.header.message_id),
                        .payload = .{ .address_resolution_ack = "" },
                    });
                    return .none;
                },
                .address_resolution_ack => |uris| return .{ .address_resolution_ack = .{
                    .source = msg.header.source,
                    .uris = uris,
                } },
                .disconnect_request => {
                    try self.queue(.{
                        .header = .{ .message_id = msg.header.message_id },
                        .payload = .disconnect_ack,
                    });
                    self.enterBackoff(now_ms);
                    return .{ .disconnected = .peer_request };
                },
                .disconnect_ack => return .none,
                .result => |r| {
                    if (r.code == .nak) return .{ .rejected = r };
                    return .none;
                },
                .proprietary_message => |p| return .{ .proprietary = .{
                    .source = msg.header.source,
                    .message = p,
                } },
                // A node is not a hub: answering a Connect-Request would be
                // claiming to be one.
                .connect_request => {
                    try self.queue(sc.nak(
                        .connect_request,
                        msg.header.message_id,
                        self.config.vmac,
                        msg.header.source,
                        .{ .class = .communication, .code = .not_a_bacnet_sc_hub },
                    ));
                    return .none;
                },
                .connect_accept => return .none,
            }
        }

        // ── outbound ───────────────────────────────────────────────────────

        /// Queues an NPDU for `dest` — null or the broadcast VMAC for the whole
        /// network.
        pub fn sendNpdu(self: *Self, dest: ?sc.Vmac, npdu: []const u8) Error!void {
            if (self.state != .connected) return error.InvalidState;
            if (npdu.len > self.negotiated_npdu) return error.MessageTooLong;
            const msg: sc.Message = .{
                .header = self.header(dest, self.takeMessageId()),
                .payload = .{ .encapsulated_npdu = npdu },
            };
            if (sc.encodedLen(msg) > self.negotiated_bvlc) return error.MessageTooLong;
            try self.queue(msg);
        }

        /// Asks the peer for the URIs it can be reached at directly.
        pub fn resolveAddress(self: *Self, dest: sc.Vmac) Error!u16 {
            if (self.state != .connected) return error.InvalidState;
            const id = self.takeMessageId();
            try self.queue(.{
                .header = self.header(dest, id),
                .payload = .address_resolution,
            });
            return id;
        }

        /// Asks every node on the network to advertise itself.
        pub fn solicitAdvertisement(self: *Self, dest: ?sc.Vmac) Error!u16 {
            if (self.state != .connected) return error.InvalidState;
            const id = self.takeMessageId();
            try self.queue(.{
                .header = self.header(dest, id),
                .payload = .advertisement_solicitation,
            });
            return id;
        }

        /// Sends a vendor-defined message.
        pub fn sendProprietary(
            self: *Self,
            dest: ?sc.Vmac,
            vendor_id: u16,
            function: u8,
            data: []const u8,
        ) Error!void {
            if (self.state != .connected) return error.InvalidState;
            try self.queue(.{
                .header = self.header(dest, self.takeMessageId()),
                .payload = .{ .proprietary_message = .{
                    .vendor_id = vendor_id,
                    .function = function,
                    .data = data,
                } },
            });
        }

        /// The secure-path option this node may legitimately attach, if any.
        pub fn securePathOption(self: *const Self) ?sc.Option {
            return sc_ws.securePathOption(self.config.tls);
        }
    };
}

/// A node with a four-frame outbox and room for the standard's minimum
/// message size.
pub const Node = NodeWith(4, sc.min_bvlc_length);

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const test_uuid = sc.Uuid{ .octets = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } };
const hub_uuid = sc.Uuid{ .octets = @splat(0xA5) };
const node_vmac = sc.Vmac{ .octets = .{ 1, 2, 3, 4, 5, 6 } };
const hub_vmac = sc.Vmac{ .octets = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } };

fn testConfig() Config {
    return .{
        .vmac = node_vmac,
        .uuid = test_uuid,
        .primary_uri = "wss://192.0.2.1/",
        .failover_uri = "wss://192.0.2.2/",
    };
}

fn testNode(prng: *std.Random.DefaultPrng) Node {
    return Node.init(testConfig(), prng.random());
}

/// Encodes a frame a hub would send, into caller storage.
fn hubFrame(msg: sc.Message, buf: []u8) []u8 {
    return sc.encode(msg, buf) catch unreachable;
}

fn connectAccept(id: u16, bvlc: u16, npdu: u16, buf: []u8) []u8 {
    return hubFrame(.{
        .header = .{ .message_id = id, .source = hub_vmac },
        .payload = .{ .connect_accept = .{
            .vmac = hub_vmac,
            .uuid = hub_uuid,
            .max_bvlc_length = bvlc,
            .max_npdu_length = npdu,
        } },
    }, buf);
}

/// Drives a node from `idle` to `connected` and returns the connected event.
fn bringUp(node: *Node, now: u64, buf: []u8) !Event {
    const opened = node.start(now);
    try testing.expectEqualStrings("wss://192.0.2.1/", opened.open_websocket.uri);
    try testing.expectEqualStrings(sc.subprotocol_hub, opened.open_websocket.subprotocol);
    _ = try node.onWebSocketOpen(now);
    const request = node.nextOutgoing().?;
    const decoded = try sc.decode(request);
    return node.onMessage(now, connectAccept(decoded.header.message_id, 1497, 1497, buf));
}

test "the happy path: open, connect, negotiate" {
    var prng = std.Random.DefaultPrng.init(1);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;

    try testing.expectEqual(State.idle, node.state);
    const opened = node.start(0);
    try testing.expectEqual(State.awaiting_websocket, node.state);
    try testing.expectEqualStrings("wss://192.0.2.1/", opened.open_websocket.uri);

    _ = try node.onWebSocketOpen(0);
    try testing.expectEqual(State.awaiting_accept, node.state);

    // The Connect-Request carries our VMAC, our UUID and our proposed maxima —
    // and deliberately *no* source VMAC, because until the hub accepts we do
    // not have an address on this network.
    const request = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.connect_request, request.function());
    try testing.expectEqual(@as(?sc.Vmac, null), request.header.source);
    try testing.expect(request.payload.connect_request.vmac.eql(node_vmac));
    try testing.expect(request.payload.connect_request.uuid.eql(test_uuid));
    try testing.expectEqual(@as(?[]const u8, null), node.nextOutgoing());

    const ev = try node.onMessage(0, connectAccept(request.header.message_id, 1497, 1497, &buf));
    try testing.expectEqual(State.connected, node.state);
    try testing.expect(ev.connected.peer.vmac.eql(hub_vmac));
    try testing.expectEqual(@as(u16, 1497), ev.connected.max_npdu_length);
    try testing.expectEqual(@as(u32, 1), node.connects);
    try testing.expectEqual(sc.HubConnectionStatus.connected_to_primary, node.hubStatus());
}

test "a Connect-Accept with smaller maxima wins, and is then enforced" {
    var prng = std.Random.DefaultPrng.init(2);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;

    const opened = node.start(0);
    _ = opened;
    _ = try node.onWebSocketOpen(0);
    const request = try sc.decode(node.nextOutgoing().?);
    // We proposed 1497/1497; the hub comes back with 600/400.
    const ev = try node.onMessage(0, connectAccept(request.header.message_id, 600, 400, &buf));
    try testing.expectEqual(@as(u16, 600), ev.connected.max_bvlc_length);
    try testing.expectEqual(@as(u16, 400), ev.connected.max_npdu_length);

    var npdu: [401]u8 = @splat(0);
    try testing.expectError(error.MessageTooLong, node.sendNpdu(null, &npdu));
    try node.sendNpdu(null, npdu[0..300]);

    // ... and the BVLC ceiling bites before the NPDU ceiling does when the
    // header is big enough to matter.
    var big: [598]u8 = @splat(0);
    node.negotiated_npdu = 1497;
    try testing.expectError(error.MessageTooLong, node.sendNpdu(hub_vmac, &big));
}

test "a Connect-Accept the node never asked for cannot arrive first" {
    var prng = std.Random.DefaultPrng.init(3);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    // Straight from idle: the node has no socket and no request outstanding.
    try testing.expectError(error.NotConnected, node.onMessage(0, connectAccept(1, 1497, 1497, &buf)));
    _ = node.start(0);
    try testing.expectError(error.NotConnected, node.onMessage(0, connectAccept(1, 1497, 1497, &buf)));
}

test "onWebSocketOpen out of order is a typed error, not a wedged state" {
    var prng = std.Random.DefaultPrng.init(4);
    var node = testNode(&prng);
    try testing.expectError(error.InvalidState, node.onWebSocketOpen(0));
}

test "a heartbeat while disconnected is refused, not answered" {
    var prng = std.Random.DefaultPrng.init(5);
    var node = testNode(&prng);
    var buf: [16]u8 = undefined;
    const hb = hubFrame(.{ .header = .{ .message_id = 9 }, .payload = .heartbeat_request }, &buf);

    try testing.expectError(error.NotConnected, node.onMessage(0, hb));
    _ = node.start(0);
    try testing.expectError(error.NotConnected, node.onMessage(0, hb));
    _ = try node.onWebSocketOpen(0);
    _ = node.nextOutgoing();
    // Even with a socket up, before Connect-Accept there is no connection to
    // heartbeat.
    try testing.expectError(error.NotConnected, node.onMessage(0, hb));
    try testing.expectEqual(@as(usize, 0), node.pending());
}

test "a heartbeat while connected is answered with the same message id" {
    var prng = std.Random.DefaultPrng.init(6);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    var hbuf: [16]u8 = undefined;
    const hb = hubFrame(.{ .header = .{ .message_id = 0x4242 }, .payload = .heartbeat_request }, &hbuf);
    try testing.expectEqual(Event.none, try node.onMessage(1000, hb));
    const reply = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.heartbeat_ack, reply.function());
    try testing.expectEqual(@as(u16, 0x4242), reply.header.message_id);
}

test "the node sends its own heartbeat when the link goes quiet" {
    var prng = std.Random.DefaultPrng.init(7);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    try testing.expectEqual(Event.none, try node.poll(1000));
    try testing.expectEqual(@as(?[]const u8, null), node.nextOutgoing());

    // Halfway to the timeout, a Heartbeat-Request goes out.
    try testing.expectEqual(Event.none, try node.poll(150_000));
    const hb = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.heartbeat_request, hb.function());
    // ... and not again until the next interval.
    _ = try node.poll(150_001);
    try testing.expectEqual(@as(?[]const u8, null), node.nextOutgoing());
}

test "total silence past the heartbeat timeout tears the connection down" {
    var prng = std.Random.DefaultPrng.init(8);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    try testing.expectEqual(Event.none, try node.poll(299_999));
    const ev = try node.poll(300_000);
    try testing.expectEqual(DisconnectReason.heartbeat_timeout, ev.disconnected);
    try testing.expectEqual(State.backoff, node.state);
    try testing.expectEqual(sc.HubConnectionStatus.no_hub_connection, node.hubStatus());
}

test "no Connect-Accept inside the connect wait is a timeout, then a retry" {
    var prng = std.Random.DefaultPrng.init(9);
    var node = testNode(&prng);
    _ = node.start(0);
    _ = try node.onWebSocketOpen(0);
    _ = node.nextOutgoing();

    try testing.expectEqual(Event.none, try node.poll(9_999));
    const ev = try node.poll(10_000);
    try testing.expectEqual(DisconnectReason.connect_timeout, ev.disconnected);
    try testing.expectEqual(State.backoff, node.state);

    // The retry goes to the *failover* URI, not the one that just failed.
    var t: u64 = 10_000;
    while (t < 20_000) : (t += 100) {
        const e = try node.poll(t);
        if (e == .open_websocket) {
            try testing.expectEqualStrings("wss://192.0.2.2/", e.open_websocket.uri);
            try testing.expectEqual(HubChoice.failover, node.hubInUse());
            return;
        }
    }
    return error.NeverRetried;
}

test "with no failover URI configured the node keeps retrying the primary" {
    var prng = std.Random.DefaultPrng.init(10);
    var cfg = testConfig();
    cfg.failover_uri = null;
    var node = Node.init(cfg, prng.random());
    _ = node.start(0);
    _ = try node.onWebSocketOpen(0);
    _ = node.nextOutgoing();
    _ = try node.poll(10_000);
    try testing.expectEqual(HubChoice.primary, node.hubInUse());
    try testing.expectEqualStrings("wss://192.0.2.1/", node.currentUri());
}

test "backoff doubles, is jittered downward, and is clamped at the ceiling" {
    var prng = std.Random.DefaultPrng.init(11);
    var node = testNode(&prng);
    var last: u32 = 0;
    var now: u64 = 0;
    _ = node.start(now);

    // Fail the connection over and over and watch the delay grow. `start` is
    // called once: a fresh start resets the backoff, and the point here is the
    // ladder a node climbs while a hub stays down.
    for (0..12) |_| {
        _ = try node.onWebSocketOpen(now);
        while (node.nextOutgoing()) |_| {}
        now += 10_000;
        const ev = try node.poll(now);
        try testing.expectEqual(DisconnectReason.connect_timeout, ev.disconnected);

        try testing.expect(node.backoff_ms >= 2_000);
        try testing.expect(node.backoff_ms <= 300_000);
        if (last != 0) try testing.expect(node.backoff_ms >= last);
        // Jitter only ever shortens the wait, and never below 75% of it.
        const delay = node.retry_at_ms - now;
        try testing.expect(delay <= node.backoff_ms);
        try testing.expect(delay * 4 >= @as(u64, node.backoff_ms) * 3);
        last = node.backoff_ms;

        now = node.retry_at_ms;
        try testing.expect((try node.poll(now)) == .open_websocket);
    }
    try testing.expectEqual(@as(u32, 300_000), node.backoff_ms);
}

test "a reconnect storm cannot exhaust anything: 10_000 failures, fixed memory" {
    var prng = std.Random.DefaultPrng.init(12);
    var node = testNode(&prng);
    var now: u64 = 0;
    for (0..10_000) |_| {
        switch (node.state) {
            .idle => _ = node.start(now),
            .awaiting_websocket => {
                _ = try node.onWebSocketOpen(now);
                // Drain, so the outbox can never be the thing that breaks.
                while (node.nextOutgoing()) |_| {}
                _ = node.onWebSocketClosed(now);
            },
            .backoff => {
                // Jump straight to the retry instant: the whole point of a
                // time-injected state machine is that 300 s costs nothing.
                now = node.retry_at_ms;
                _ = try node.poll(now);
            },
            else => _ = try node.poll(now),
        }
        now += 1;
    }
    try testing.expect(node.attempts > 100);
    try testing.expectEqual(@as(u32, 0), node.connects);
    try testing.expectEqual(@as(usize, 0), node.pending());
    // The delay is at the ceiling and stayed there; nothing ran away.
    try testing.expectEqual(@as(u32, 300_000), node.backoff_ms);
}

test "a duplicate-VMAC NAK makes the node pick a new VMAC and retry quickly" {
    var prng = std.Random.DefaultPrng.init(13);
    var node = testNode(&prng);
    _ = node.start(0);
    _ = try node.onWebSocketOpen(0);
    const request = try sc.decode(node.nextOutgoing().?);

    var buf: [64]u8 = undefined;
    const refusal = hubFrame(sc.nak(
        .connect_request,
        request.header.message_id,
        hub_vmac,
        null,
        .{ .class = .communication, .code = .node_duplicate_vmac, .details = "taken" },
    ), &buf);

    const ev = try node.onMessage(0, refusal);
    try testing.expectEqual(DisconnectReason.vmac_collision, ev.disconnected);
    try testing.expect(!node.config.vmac.eql(node_vmac));
    try testing.expect(!node.config.vmac.isReserved());
    try testing.expectEqual(@as(u32, 1), node.vmac_collisions);
    // Retried at the floor, not at a doubled backoff — the collision is ours
    // to fix and fixing it is instant.
    try testing.expectEqual(@as(u64, 2_000), node.retry_at_ms);
}

test "a hub that hands back our own VMAC is the same collision, seen locally" {
    var prng = std.Random.DefaultPrng.init(14);
    var node = testNode(&prng);
    _ = node.start(0);
    _ = try node.onWebSocketOpen(0);
    const request = try sc.decode(node.nextOutgoing().?);

    var buf: [64]u8 = undefined;
    const accept = hubFrame(.{
        .header = .{ .message_id = request.header.message_id },
        .payload = .{
            .connect_accept = .{
                .vmac = node_vmac, // the hub claims our address
                .uuid = hub_uuid,
                .max_bvlc_length = 1497,
                .max_npdu_length = 1497,
            },
        },
    }, &buf);
    const ev = try node.onMessage(0, accept);
    try testing.expectEqual(DisconnectReason.vmac_collision, ev.disconnected);
    try testing.expectEqual(State.backoff, node.state);
}

test "a NAK for any other reason ends the attempt without changing our VMAC" {
    var prng = std.Random.DefaultPrng.init(15);
    var node = testNode(&prng);
    _ = node.start(0);
    _ = try node.onWebSocketOpen(0);
    const request = try sc.decode(node.nextOutgoing().?);

    var buf: [64]u8 = undefined;
    const refusal = hubFrame(sc.nak(
        .connect_request,
        request.header.message_id,
        hub_vmac,
        null,
        .{ .class = .communication, .code = .not_a_bacnet_sc_hub },
    ), &buf);
    const ev = try node.onMessage(0, refusal);
    try testing.expectEqual(DisconnectReason.connect_rejected, ev.disconnected);
    try testing.expect(node.config.vmac.eql(node_vmac));
    try testing.expectEqual(@as(u32, 0), node.vmac_collisions);
}

test "a must-understand option we do not know is NAKed, whatever the function" {
    var prng = std.Random.DefaultPrng.init(16);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    // Option type 7, must-understand set, on a Heartbeat-Request.
    var opts: [4]u8 = undefined;
    const list = try sc.encodeOptions(&.{
        .{ .type = @enumFromInt(7), .must_understand = true },
    }, &opts);
    var fbuf: [32]u8 = undefined;
    const frame = hubFrame(.{
        .header = .{ .message_id = 77, .destination_options = list },
        .payload = .heartbeat_request,
    }, &fbuf);

    try testing.expectEqual(Event.none, try node.onMessage(0, frame));
    const reply = try sc.decode(node.nextOutgoing().?);
    const r = reply.payload.result;
    try testing.expectEqual(sc.ResultCode.nak, r.code);
    try testing.expectEqual(sc.Function.heartbeat_request, r.function);
    try testing.expectEqual(types.ErrorCode.header_not_understood, r.err.?.code);
    // The marker echoed back is the offending option's, so the peer can see
    // exactly which one we choked on.
    try testing.expectEqual(@as(u8, 0x47), r.err.?.header_marker);
    // ... and no Heartbeat-ACK was sent.
    try testing.expectEqual(@as(?[]const u8, null), node.nextOutgoing());
}

test "an option we understand does not stop the message being processed" {
    var prng = std.Random.DefaultPrng.init(17);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    var opts: [4]u8 = undefined;
    const list = try sc.encodeOptions(&.{sc.Option.secure_path}, &opts);
    var fbuf: [32]u8 = undefined;
    const frame = hubFrame(.{
        .header = .{ .message_id = 78, .data_options = list },
        .payload = .heartbeat_request,
    }, &fbuf);
    _ = try node.onMessage(0, frame);
    try testing.expectEqual(sc.Function.heartbeat_ack, (try sc.decode(node.nextOutgoing().?)).function());
}

test "an NPDU round-trips through the connected node" {
    var prng = std.Random.DefaultPrng.init(18);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    // Outbound: a Who-Is to the whole network.
    const who_is = [_]u8{ 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    try node.sendNpdu(sc.Vmac.broadcast, &who_is);
    const out = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.encapsulated_npdu, out.function());
    try testing.expect(out.header.source.?.eql(node_vmac));
    try testing.expect(out.isBroadcast());
    try testing.expectEqualSlices(u8, &who_is, out.payload.encapsulated_npdu);

    // Inbound: an I-Am coming back from another node via the hub.
    const i_am = [_]u8{ 0x01, 0x00, 0x10, 0x00 };
    var ibuf: [64]u8 = undefined;
    const frame = hubFrame(.{
        .header = .{
            .message_id = 5,
            .source = .{ .octets = .{ 9, 9, 9, 9, 9, 9 } },
            .destination = node_vmac,
        },
        .payload = .{ .encapsulated_npdu = &i_am },
    }, &ibuf);
    const ev = try node.onMessage(1, frame);
    try testing.expectEqualSlices(u8, &i_am, ev.npdu.bytes);
    try testing.expect(ev.npdu.source.?.eql(.{ .octets = .{ 9, 9, 9, 9, 9, 9 } }));
}

test "sending anything before the connection exists is a typed error" {
    var prng = std.Random.DefaultPrng.init(19);
    var node = testNode(&prng);
    try testing.expectError(error.InvalidState, node.sendNpdu(null, "x"));
    try testing.expectError(error.InvalidState, node.resolveAddress(hub_vmac));
    try testing.expectError(error.InvalidState, node.solicitAdvertisement(null));
    try testing.expectError(error.InvalidState, node.sendProprietary(null, 1, 2, "x"));
}

test "an Advertisement-Solicitation is answered with our own status" {
    var prng = std.Random.DefaultPrng.init(20);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    var sbuf: [16]u8 = undefined;
    const solicit = hubFrame(.{
        .header = .{ .message_id = 31, .source = hub_vmac },
        .payload = .advertisement_solicitation,
    }, &sbuf);
    _ = try node.onMessage(0, solicit);
    const reply = try sc.decode(node.nextOutgoing().?);
    const a = reply.payload.advertisement;
    try testing.expectEqual(sc.HubConnectionStatus.connected_to_primary, a.hub_status);
    try testing.expectEqual(sc.DirectConnectionSupport.unsupported, a.direct_connections);
    try testing.expect(reply.header.destination.?.eql(hub_vmac));
    try testing.expectEqual(@as(u16, 31), reply.header.message_id);
}

test "an Address-Resolution is answered, with an empty URI list when we have none" {
    var prng = std.Random.DefaultPrng.init(21);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    var rbuf: [16]u8 = undefined;
    const ask = hubFrame(.{
        .header = .{ .message_id = 44, .source = hub_vmac },
        .payload = .address_resolution,
    }, &rbuf);
    _ = try node.onMessage(0, ask);
    const reply = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.address_resolution_ack, reply.function());
    try testing.expectEqual(@as(usize, 0), reply.payload.address_resolution_ack.len);
}

test "a node refuses to act as a hub" {
    var prng = std.Random.DefaultPrng.init(22);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    var cbuf: [64]u8 = undefined;
    const req = hubFrame(.{
        .header = .{ .message_id = 2 },
        .payload = .{ .connect_request = .{
            .vmac = .{ .octets = .{ 7, 7, 7, 7, 7, 7 } },
            .uuid = hub_uuid,
            .max_bvlc_length = 1497,
            .max_npdu_length = 1497,
        } },
    }, &cbuf);
    _ = try node.onMessage(0, req);
    const reply = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(types.ErrorCode.not_a_bacnet_sc_hub, reply.payload.result.err.?.code);
}

test "a peer Disconnect-Request is acknowledged and then reconnected from" {
    var prng = std.Random.DefaultPrng.init(23);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    var dbuf: [16]u8 = undefined;
    const bye = hubFrame(.{ .header = .{ .message_id = 12 }, .payload = .disconnect_request }, &dbuf);
    const ev = try node.onMessage(100, bye);
    try testing.expectEqual(DisconnectReason.peer_request, ev.disconnected);
    const ack = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.disconnect_ack, ack.function());
    try testing.expectEqual(@as(u16, 12), ack.header.message_id);
    try testing.expectEqual(State.backoff, node.state);
}

test "a graceful local stop waits for the Disconnect-ACK, then gives up on time" {
    var prng = std.Random.DefaultPrng.init(24);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    try testing.expectEqual(Event.none, try node.stop(0));
    try testing.expectEqual(State.disconnecting, node.state);
    const bye = try sc.decode(node.nextOutgoing().?);
    try testing.expectEqual(sc.Function.disconnect_request, bye.function());
    // Connection control carries no addressing at all.
    try testing.expectEqual(@as(?sc.Vmac, null), bye.header.source);
    try testing.expectEqual(@as(?sc.Vmac, null), bye.header.destination);

    // The ACK arrives: clean stop.
    var abuf: [16]u8 = undefined;
    const ack = hubFrame(.{
        .header = .{ .message_id = bye.header.message_id },
        .payload = .disconnect_ack,
    }, &abuf);
    try testing.expectEqual(Event.close_websocket, try node.onMessage(1, ack));
    try testing.expectEqual(State.stopped, node.state);

    // A second node whose ACK never comes gives up at the deadline instead.
    var node2 = testNode(&prng);
    _ = try bringUp(&node2, 0, &buf);
    _ = try node2.stop(0);
    _ = node2.nextOutgoing();
    try testing.expectEqual(Event.none, try node2.poll(9_999));
    try testing.expectEqual(
        DisconnectReason.disconnect_timeout,
        (try node2.poll(10_000)).disconnected,
    );
}

test "stopping a node that never connected is immediate" {
    var prng = std.Random.DefaultPrng.init(25);
    var node = testNode(&prng);
    try testing.expectEqual(Event.close_websocket, try node.stop(0));
    try testing.expectEqual(State.stopped, node.state);
    try testing.expectEqual(Event.none, try node.poll(1_000_000));
}

test "a malformed frame is a typed error and leaves the state alone" {
    var prng = std.Random.DefaultPrng.init(26);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);

    try testing.expectError(error.BadMessage, node.onMessage(0, &.{}));
    try testing.expectError(error.BadMessage, node.onMessage(0, &.{ 0x0A, 0x10, 0, 1 }));
    try testing.expectError(error.BadMessage, node.onMessage(0, &.{ 0xFF, 0, 0, 1 }));
    try testing.expectError(error.BadMessage, node.onMessage(0, &.{ 0x01, 0x02, 0, 1, 0xC1 }));
    try testing.expectEqual(State.connected, node.state);
}

test "an undrained outbox is a typed error, not an allocation" {
    var prng = std.Random.DefaultPrng.init(27);
    var node = testNode(&prng);
    var buf: [64]u8 = undefined;
    _ = try bringUp(&node, 0, &buf);
    // Room for outbox_len - 1; the ring keeps one slot to tell full from empty.
    try node.sendNpdu(null, "a");
    try node.sendNpdu(null, "b");
    try node.sendNpdu(null, "c");
    try testing.expectError(error.OutboxFull, node.sendNpdu(null, "d"));
    _ = node.nextOutgoing();
    try node.sendNpdu(null, "d");
}

test "the secure-path option follows the caller's TLS assertion" {
    var prng = std.Random.DefaultPrng.init(28);
    var plain = testNode(&prng);
    try testing.expectEqual(@as(?sc.Option, null), plain.securePathOption());

    var cfg = testConfig();
    cfg.tls = sc_ws.TlsAssertion.mutual("CN=zig-node");
    var secure = Node.init(cfg, prng.random());
    try testing.expectEqual(sc.OptionType.secure_path, secure.securePathOption().?.type);
}

test "the transport dropping at any point lands in backoff, never in limbo" {
    var prng = std.Random.DefaultPrng.init(29);
    var buf: [64]u8 = undefined;
    for ([_]u8{ 0, 1, 2 }) |stage| {
        var node = testNode(&prng);
        _ = node.start(0);
        if (stage >= 1) {
            _ = try node.onWebSocketOpen(0);
            _ = node.nextOutgoing();
        }
        if (stage >= 2) {
            const req = try sc.decode(hubFrame(.{
                .header = .{ .message_id = 1 },
                .payload = .heartbeat_request,
            }, &buf));
            _ = req;
            var cbuf: [64]u8 = undefined;
            _ = try node.onMessage(0, connectAccept(1, 1497, 1497, &cbuf));
        }
        const ev = node.onWebSocketClosed(500);
        try testing.expectEqual(DisconnectReason.transport_closed, ev.disconnected);
        try testing.expectEqual(State.backoff, node.state);
        try testing.expectEqual(@as(?sc.ConnectInfo, null), node.peer);
    }
}

test "fuzz: a node survives arbitrary frames in every state" {
    try std.testing.fuzz({}, fuzzNode, .{});
}

fn fuzzNode(_: void, smith: *std.testing.Smith) !void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    var node = testNode(&prng);
    var accept_buf: [64]u8 = undefined;

    // Land in a random state.
    switch (smith.valueRangeAtMost(u8, 0, 3)) {
        0 => {},
        1 => _ = node.start(0),
        2 => {
            _ = node.start(0);
            _ = try node.onWebSocketOpen(0);
            _ = node.nextOutgoing();
        },
        else => {
            _ = node.start(0);
            _ = try node.onWebSocketOpen(0);
            const req = try sc.decode(node.nextOutgoing().?);
            _ = try node.onMessage(0, connectAccept(req.header.message_id, 1497, 1497, &accept_buf));
        },
    }

    var buf: [256]u8 = undefined;
    var now: u64 = 0;
    for (0..8) |_| {
        smith.bytes(&buf);
        const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
        _ = node.onMessage(now, buf[0..len]) catch {};
        _ = node.poll(now) catch {};
        while (node.nextOutgoing()) |frame| {
            // Everything the node emits must be a decodable BVLC-SC message.
            _ = try sc.decode(frame);
        }
        now += smith.valueRangeAtMost(u32, 0, 400_000);
    }
}
