// SPDX-License-Identifier: MIT

//! **The BACnet/SC hub function (Annex AB.5.2).**
//!
//! A hub is the thing that makes BACnet/SC a *network* rather than a set of
//! point-to-point links: every node holds one WebSocket to the hub, and the
//! hub is the only participant that knows which VMAC lives behind which
//! socket. It is also what makes the node side testable at all — which is why
//! it is here and not deferred.
//!
//! What a hub owes its nodes:
//!
//! * **Admission.** A Connect-Request is checked against the VMAC/UUID table
//!   before it is accepted. The interesting case is not the happy one:
//!   - the **same UUID** arriving again is *the same device reconnecting*
//!     (its old socket is stale, perhaps because the hub never saw it drop);
//!     the old entry is evicted and the old socket closed.
//!   - a **different UUID** claiming a VMAC that is already taken is a real
//!     collision, and gets a `BVLC-Result` NAK with `node_duplicate_vmac` —
//!     which is precisely the message `sc_node` reacts to by drawing a new
//!     VMAC.
//! * **Attribution.** A node talking to its hub may leave the originating
//!   VMAC out — the hub knows who it is talking to. The hub **fills it in**
//!   when forwarding, because the receiving node has no other way to know who
//!   sent it. A node that fills in a source VMAC that is *not* the one it
//!   connected with is spoofing another node, and is refused.
//! * **Distribution.** A message with no destination VMAC, or the all-ones
//!   broadcast, goes to every other connected node — never back to the sender.
//! * **Liveness.** Per-connection heartbeat timeouts, so a socket that a TCP
//!   stack has not noticed is dead does not hold a VMAC hostage forever.
//!
//! Same discipline as the node: **pure, time-injected, fixed-size**. The
//! caller runs the WebSocket listener, hands each accepted connection an id,
//! feeds frames in and drains frames out. No clock, no thread, no socket, no
//! allocation.

const std = @import("std");
const types = @import("types.zig");
const sc = @import("sc.zig");
const sc_ws = @import("sc_ws.zig");

pub const Error = error{
    /// No free connection slot. A hub is sized at compile time; refusing is
    /// better than an allocation a building controller cannot afford.
    TooManyConnections,
    /// The caller referred to a connection id the hub does not have.
    UnknownConnection,
    /// The outbox is full: the caller has not been draining `nextOutgoing`.
    OutboxFull,
    /// The frame did not decode.
    BadMessage,
} || sc.Error;

/// Opaque to the caller: whatever it uses to name a socket, mapped to a slot.
pub const ConnId = usize;

pub const Timings = struct {
    /// How long a socket may stay open without completing a Connect-Request.
    connect_wait_ms: u32 = 10_000,
    /// Silence longer than this on an established connection drops it.
    heartbeat_timeout_ms: u32 = 300_000,
};

pub const Config = struct {
    /// The hub's own VMAC — nodes address the hub itself with it, and a node
    /// that proposes it in a Connect-Request is refused.
    vmac: sc.Vmac,
    uuid: sc.Uuid,
    max_bvlc_length: u16 = sc.min_bvlc_length,
    max_npdu_length: u16 = sc.min_bvlc_length,
    /// The URIs this hub hands out in an Address-Resolution-ACK for itself.
    /// Space separated, exactly as it goes on the wire. Borrowed.
    websocket_uris: []const u8 = "",
    tls: sc_ws.TlsAssertion = .none,
    timings: Timings = .{},
};

/// Why a node left.
pub const DisconnectReason = enum {
    peer_request,
    transport_closed,
    /// Never completed a Connect-Request in time.
    connect_timeout,
    heartbeat_timeout,
    /// Evicted because the same device UUID connected again.
    superseded,
};

pub const Event = union(enum) {
    none,
    /// A node completed its Connect-Request.
    node_connected: struct { conn: ConnId, vmac: sc.Vmac, uuid: sc.Uuid },
    /// A node's entry was removed.
    node_disconnected: struct { conn: ConnId, vmac: sc.Vmac, reason: DisconnectReason },
    /// Close this WebSocket.
    close_connection: ConnId,
    /// A message named a destination VMAC that is not connected. Annex AB
    /// leaves this to the hub; reporting beats silently swallowing it.
    undeliverable: struct { conn: ConnId, destination: sc.Vmac },
    /// An NPDU addressed to the hub's own VMAC — for a hub that also hosts a
    /// device, which is common.
    npdu_for_hub: struct { source: sc.Vmac, bytes: []const u8 },
    proprietary: struct { source: ?sc.Vmac, message: sc.ProprietaryMessage },
};

/// One frame to transmit, and which socket it belongs to.
pub const Outgoing = struct { conn: ConnId, bytes: []const u8 };

/// A hub for `max_nodes` simultaneous connections, with an outbox of
/// `outbox_len` frames of at most `frame_cap` octets.
///
/// The outbox must be at least `max_nodes` deep for a broadcast to fit in one
/// go, which is asserted at compile time rather than discovered at 3 a.m.
pub fn HubWith(
    comptime max_nodes: usize,
    comptime outbox_len: usize,
    comptime frame_cap: usize,
) type {
    comptime std.debug.assert(outbox_len > max_nodes);
    return struct {
        const Self = @This();

        config: Config,
        rand: std.Random,

        slots: [max_nodes]Slot = @splat(.{}),
        next_message_id: u16 = 1,

        outbox: [outbox_len]OutSlot = @splat(.{}),
        head: usize = 0,
        tail: usize = 0,

        /// Counters for a fleet simulator or an operator page.
        admitted: u32 = 0,
        rejected: u32 = 0,
        superseded: u32 = 0,
        forwarded: u32 = 0,

        pub const Slot = struct {
            /// False for a slot nobody is using.
            open: bool = false,
            /// True once the Connect-Request was accepted.
            connected: bool = false,
            vmac: sc.Vmac = sc.Vmac.unspecified,
            uuid: sc.Uuid = sc.Uuid.nil,
            max_bvlc_length: u16 = 0,
            max_npdu_length: u16 = 0,
            opened_ms: u64 = 0,
            last_rx_ms: u64 = 0,
        };

        const OutSlot = struct {
            conn: ConnId = 0,
            buf: [frame_cap]u8 = undefined,
            len: usize = 0,
        };

        pub fn init(config: Config, rand: std.Random) Self {
            return .{ .config = config, .rand = rand };
        }

        // ── connections ────────────────────────────────────────────────────

        /// Claims a slot for a WebSocket the caller just accepted. The
        /// returned id is what every other call takes.
        pub fn accept(self: *Self, now_ms: u64) Error!ConnId {
            for (&self.slots, 0..) |*s, i| {
                if (s.open) continue;
                s.* = .{ .open = true, .opened_ms = now_ms, .last_rx_ms = now_ms };
                return i;
            }
            return error.TooManyConnections;
        }

        /// The caller's WebSocket for `conn` went away.
        pub fn onConnectionClosed(self: *Self, conn: ConnId) Error!Event {
            if (conn >= max_nodes or !self.slots[conn].open) return error.UnknownConnection;
            return self.drop(conn, .transport_closed);
        }

        fn drop(self: *Self, conn: ConnId, reason: DisconnectReason) Event {
            const s = &self.slots[conn];
            const was_connected = s.connected;
            const address = s.vmac;
            s.* = .{};
            if (!was_connected) return .none;
            return .{ .node_disconnected = .{ .conn = conn, .vmac = address, .reason = reason } };
        }

        pub fn nodeCount(self: *const Self) usize {
            var n: usize = 0;
            for (self.slots) |s| {
                if (s.connected) n += 1;
            }
            return n;
        }

        /// Which connection a VMAC lives behind, if any.
        pub fn lookup(self: *const Self, address: sc.Vmac) ?ConnId {
            for (self.slots, 0..) |s, i| {
                if (s.connected and s.vmac.eql(address)) return i;
            }
            return null;
        }

        fn byUuid(self: *const Self, id: sc.Uuid) ?ConnId {
            for (self.slots, 0..) |s, i| {
                if (s.connected and s.uuid.eql(id)) return i;
            }
            return null;
        }

        // ── outbox ─────────────────────────────────────────────────────────

        pub fn nextOutgoing(self: *Self) ?Outgoing {
            if (self.head == self.tail) return null;
            const slot = &self.outbox[self.head];
            self.head = (self.head + 1) % outbox_len;
            return .{ .conn = slot.conn, .bytes = slot.buf[0..slot.len] };
        }

        pub fn pending(self: *const Self) usize {
            return (self.tail + outbox_len - self.head) % outbox_len;
        }

        fn queue(self: *Self, conn: ConnId, msg: sc.Message) Error!void {
            const next = (self.tail + 1) % outbox_len;
            if (next == self.head) return error.OutboxFull;
            const slot = &self.outbox[self.tail];
            const written = try sc.encode(msg, &slot.buf);
            slot.conn = conn;
            slot.len = written.len;
            self.tail = next;
        }

        fn takeMessageId(self: *Self) u16 {
            const id = self.next_message_id;
            self.next_message_id +%= 1;
            if (self.next_message_id == 0) self.next_message_id = 1;
            return id;
        }

        fn refuse(
            self: *Self,
            conn: ConnId,
            func: sc.Function,
            id: u16,
            dest: ?sc.Vmac,
            code: types.ErrorCode,
            details: []const u8,
        ) Error!void {
            self.rejected += 1;
            try self.queue(conn, sc.nak(func, id, self.config.vmac, dest, .{
                .class = .communication,
                .code = code,
                .details = details,
            }));
        }

        // ── timers ─────────────────────────────────────────────────────────

        /// Ages out sockets that never connected and connections that have
        /// gone quiet. One event per call; loop until `.none`.
        pub fn poll(self: *Self, now_ms: u64) Error!Event {
            const t = self.config.timings;
            for (&self.slots, 0..) |*s, i| {
                if (!s.open) continue;
                if (!s.connected) {
                    if (now_ms -| s.opened_ms >= t.connect_wait_ms) {
                        _ = self.drop(i, .connect_timeout);
                        return .{ .close_connection = i };
                    }
                    continue;
                }
                if (now_ms -| s.last_rx_ms >= t.heartbeat_timeout_ms) {
                    const ev = self.drop(i, .heartbeat_timeout);
                    // The caller still has to close the socket; the event it
                    // gets first is the interesting one, so queue the close as
                    // the *next* poll's answer by leaving the slot free — the
                    // caller closes on `node_disconnected`.
                    return ev;
                }
            }
            return .none;
        }

        // ── inbound ────────────────────────────────────────────────────────

        pub fn onMessage(self: *Self, now_ms: u64, conn: ConnId, frame: []const u8) Error!Event {
            if (conn >= max_nodes or !self.slots[conn].open) return error.UnknownConnection;
            const msg = sc.decode(frame) catch return error.BadMessage;
            self.slots[conn].last_rx_ms = now_ms;

            if (try msg.header.unsupportedOption()) |bad| {
                var marker: u8 = @intFromEnum(bad.type);
                if (bad.must_understand) marker |= sc.option_flags.must_understand;
                if (bad.data != null) marker |= sc.option_flags.header_data;
                self.rejected += 1;
                try self.queue(conn, sc.nak(
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

            if (!self.slots[conn].connected) {
                switch (msg.payload) {
                    .connect_request => |req| return self.admit(now_ms, conn, msg.header.message_id, req),
                    // Nothing else may precede the Connect-Request. Saying so
                    // explicitly is what stops a stranger driving hub state
                    // through a socket it has not been admitted on.
                    else => {
                        try self.refuse(
                            conn,
                            msg.function(),
                            msg.header.message_id,
                            msg.header.source,
                            .inconsistent_parameters,
                            "not connected",
                        );
                        return .none;
                    },
                }
            }
            return self.established(now_ms, conn, msg);
        }

        fn admit(
            self: *Self,
            now_ms: u64,
            conn: ConnId,
            id: u16,
            req: sc.ConnectInfo,
        ) Error!Event {
            // The two reserved VMACs and the hub's own are not addresses a
            // node may take.
            if (req.vmac.isReserved() or req.vmac.eql(self.config.vmac)) {
                try self.refuse(conn, .connect_request, id, null, .inconsistent_parameters, "reserved vmac");
                return .none;
            }

            var superseded: ?ConnId = null;
            if (self.byUuid(req.uuid)) |old| {
                // Same device, new socket: its old connection is stale, and
                // keeping both would leave the old VMAC pointing at a socket
                // nobody is reading.
                if (old != conn) superseded = old;
            } else if (self.lookup(req.vmac)) |other| {
                // A different device wants a VMAC that is taken. This is the
                // collision the standard defines a code for.
                if (other != conn) {
                    try self.refuse(
                        conn,
                        .connect_request,
                        id,
                        null,
                        .node_duplicate_vmac,
                        "vmac in use",
                    );
                    return .none;
                }
            }

            const s = &self.slots[conn];
            s.connected = true;
            s.vmac = req.vmac;
            s.uuid = req.uuid;
            s.last_rx_ms = now_ms;
            const mine: sc.ConnectInfo = .{
                .vmac = self.config.vmac,
                .uuid = self.config.uuid,
                .max_bvlc_length = self.config.max_bvlc_length,
                .max_npdu_length = self.config.max_npdu_length,
            };
            const n = mine.negotiate(req);
            s.max_bvlc_length = n.bvlc;
            s.max_npdu_length = n.npdu;

            try self.queue(conn, .{
                .header = .{ .message_id = id },
                .payload = .{ .connect_accept = mine },
            });
            self.admitted += 1;

            if (superseded) |old| {
                self.superseded += 1;
                _ = self.drop(old, .superseded);
                // The caller must close the stale socket; it learns which from
                // this event, and the *new* connection is already accepted.
                return .{ .close_connection = old };
            }
            return .{ .node_connected = .{ .conn = conn, .vmac = req.vmac, .uuid = req.uuid } };
        }

        fn established(self: *Self, now_ms: u64, conn: ConnId, msg: sc.Message) Error!Event {
            const s = &self.slots[conn];

            // A node may leave its own VMAC out — the hub knows it. What it may
            // not do is claim to be somebody else.
            if (msg.header.source) |src| {
                if (!src.eql(s.vmac)) {
                    try self.refuse(
                        conn,
                        msg.function(),
                        msg.header.message_id,
                        null,
                        .inconsistent_parameters,
                        "source vmac mismatch",
                    );
                    return .none;
                }
            }

            switch (msg.payload) {
                .heartbeat_request => {
                    try self.queue(conn, .{
                        .header = .{ .message_id = msg.header.message_id },
                        .payload = .heartbeat_ack,
                    });
                    return .none;
                },
                .heartbeat_ack, .connect_accept, .disconnect_ack => return .none,
                .disconnect_request => {
                    try self.queue(conn, .{
                        .header = .{ .message_id = msg.header.message_id },
                        .payload = .disconnect_ack,
                    });
                    const ev = self.drop(conn, .peer_request);
                    return ev;
                },
                .connect_request => {
                    // Already admitted on this socket; a second request is a
                    // confused peer, not a re-admission.
                    try self.refuse(
                        conn,
                        .connect_request,
                        msg.header.message_id,
                        null,
                        .inconsistent_parameters,
                        "already connected",
                    );
                    return .none;
                },
                .result => return .none,
                .proprietary_message => |p| {
                    if (msg.header.destination) |d| {
                        if (!d.eql(self.config.vmac)) return self.relay(conn, msg);
                    } else return self.relay(conn, msg);
                    return .{ .proprietary = .{ .source = s.vmac, .message = p } };
                },
                .encapsulated_npdu => |bytes| {
                    if (bytes.len > s.max_npdu_length) {
                        try self.refuse(
                            conn,
                            .encapsulated_npdu,
                            msg.header.message_id,
                            null,
                            .message_incomplete,
                            "npdu over negotiated maximum",
                        );
                        return .none;
                    }
                    if (msg.header.destination) |d| {
                        if (d.eql(self.config.vmac)) {
                            return .{ .npdu_for_hub = .{ .source = s.vmac, .bytes = bytes } };
                        }
                    }
                    return self.relay(conn, msg);
                },
                .advertisement_solicitation => {
                    if (msg.header.destination) |d| {
                        if (!d.eql(self.config.vmac)) return self.relay(conn, msg);
                    }
                    // Addressed to the hub itself, or broadcast: answer for
                    // ourselves and let the broadcast reach the others too.
                    try self.queue(conn, .{
                        .header = .{
                            .message_id = msg.header.message_id,
                            .source = self.config.vmac,
                            .destination = s.vmac,
                        },
                        .payload = .{
                            .advertisement = .{
                                // A hub function is the network; it is not itself
                                // connected to one.
                                .hub_status = .no_hub_connection,
                                .direct_connections = .unsupported,
                                .max_bvlc_length = self.config.max_bvlc_length,
                                .max_npdu_length = self.config.max_npdu_length,
                            },
                        },
                    });
                    if (msg.isBroadcast()) return self.relay(conn, msg);
                    return .none;
                },
                .address_resolution => {
                    if (msg.header.destination) |d| {
                        if (!d.eql(self.config.vmac)) return self.relay(conn, msg);
                    }
                    try self.queue(conn, .{
                        .header = .{
                            .message_id = msg.header.message_id,
                            .source = self.config.vmac,
                            .destination = s.vmac,
                        },
                        .payload = .{ .address_resolution_ack = self.config.websocket_uris },
                    });
                    return .none;
                },
                .advertisement, .address_resolution_ack => return self.relay(conn, msg),
            }
            _ = now_ms;
        }

        /// Forwards a message on behalf of `from`, filling in the originating
        /// VMAC the node was entitled to omit.
        fn relay(self: *Self, from: ConnId, msg: sc.Message) Error!Event {
            var out = msg;
            out.header.source = self.slots[from].vmac;

            if (msg.header.destination) |d| {
                if (!d.isBroadcast()) {
                    const target = self.lookup(d) orelse
                        return .{ .undeliverable = .{ .conn = from, .destination = d } };
                    try self.queue(target, out);
                    self.forwarded += 1;
                    return .none;
                }
            }

            // Broadcast: everyone but the sender. The destination is left
            // exactly as it arrived, so a receiver can still tell a
            // hub-distributed broadcast from a unicast.
            for (self.slots, 0..) |slot, i| {
                if (!slot.connected or i == from) continue;
                try self.queue(i, out);
                self.forwarded += 1;
            }
            return .none;
        }
    };
}

/// A hub sized for a small plant: eight nodes, a broadcast plus a few replies
/// in flight, and the standard's minimum message size.
pub const Hub = HubWith(8, 16, sc.min_bvlc_length);

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const hub_vmac = sc.Vmac{ .octets = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } };
const hub_uuid = sc.Uuid{ .octets = @splat(0xA5) };

fn testHub(prng: *std.Random.DefaultPrng) Hub {
    return Hub.init(.{
        .vmac = hub_vmac,
        .uuid = hub_uuid,
        .websocket_uris = "wss://192.0.2.1/",
    }, prng.random());
}

fn vmac(n: u8) sc.Vmac {
    return .{ .octets = .{ n, n, n, n, n, n } };
}

fn uuid(n: u8) sc.Uuid {
    return .{ .octets = @splat(n) };
}

fn connectRequest(id: u16, v: sc.Vmac, u: sc.Uuid, buf: []u8) []u8 {
    return sc.encode(.{
        .header = .{ .message_id = id },
        .payload = .{ .connect_request = .{
            .vmac = v,
            .uuid = u,
            .max_bvlc_length = 1497,
            .max_npdu_length = 1497,
        } },
    }, buf) catch unreachable;
}

/// Admits a node and returns its connection id, draining the Connect-Accept.
fn admitNode(hub: *Hub, now: u64, v: sc.Vmac, u: sc.Uuid) !ConnId {
    var buf: [64]u8 = undefined;
    const conn = try hub.accept(now);
    const ev = try hub.onMessage(now, conn, connectRequest(1, v, u, &buf));
    try testing.expectEqual(conn, ev.node_connected.conn);
    const out = hub.nextOutgoing().?;
    try testing.expectEqual(sc.Function.connect_accept, (try sc.decode(out.bytes)).function());
    return conn;
}

test "a hub admits a node and answers with its own VMAC and UUID" {
    var prng = std.Random.DefaultPrng.init(1);
    var hub = testHub(&prng);
    var buf: [64]u8 = undefined;

    const conn = try hub.accept(0);
    const ev = try hub.onMessage(0, conn, connectRequest(9, vmac(1), uuid(1), &buf));
    try testing.expect(ev.node_connected.vmac.eql(vmac(1)));

    const accept = try sc.decode(hub.nextOutgoing().?.bytes);
    try testing.expectEqual(sc.Function.connect_accept, accept.function());
    try testing.expectEqual(@as(u16, 9), accept.header.message_id);
    try testing.expect(accept.payload.connect_accept.vmac.eql(hub_vmac));
    try testing.expect(accept.payload.connect_accept.uuid.eql(hub_uuid));
    try testing.expectEqual(@as(usize, 1), hub.nodeCount());
    try testing.expectEqual(conn, hub.lookup(vmac(1)).?);
}

test "a second device claiming a taken VMAC gets node_duplicate_vmac" {
    var prng = std.Random.DefaultPrng.init(2);
    var hub = testHub(&prng);
    var buf: [64]u8 = undefined;
    _ = try admitNode(&hub, 0, vmac(1), uuid(1));

    const conn = try hub.accept(0);
    // Same VMAC, *different* UUID: a real collision.
    const ev = try hub.onMessage(0, conn, connectRequest(2, vmac(1), uuid(2), &buf));
    try testing.expectEqual(Event.none, ev);
    const r = (try sc.decode(hub.nextOutgoing().?.bytes)).payload.result;
    try testing.expectEqual(sc.ResultCode.nak, r.code);
    try testing.expectEqual(sc.Function.connect_request, r.function);
    try testing.expectEqual(types.ErrorCode.node_duplicate_vmac, r.err.?.code);
    try testing.expectEqual(@as(usize, 1), hub.nodeCount());
    try testing.expectEqual(@as(u32, 1), hub.rejected);
}

test "the same device reconnecting supersedes its stale connection" {
    var prng = std.Random.DefaultPrng.init(3);
    var hub = testHub(&prng);
    var buf: [64]u8 = undefined;
    const first = try admitNode(&hub, 0, vmac(1), uuid(1));

    const second = try hub.accept(100);
    // Same UUID — same device — even with a brand new VMAC.
    const ev = try hub.onMessage(100, second, connectRequest(3, vmac(7), uuid(1), &buf));
    try testing.expectEqual(first, ev.close_connection);
    try testing.expectEqual(@as(u32, 1), hub.superseded);
    try testing.expectEqual(@as(usize, 1), hub.nodeCount());
    try testing.expectEqual(second, hub.lookup(vmac(7)).?);
    try testing.expectEqual(@as(?ConnId, null), hub.lookup(vmac(1)));
    try testing.expectEqual(sc.Function.connect_accept, (try sc.decode(hub.nextOutgoing().?.bytes)).function());
}

test "a reserved VMAC, or the hub's own, is refused" {
    var prng = std.Random.DefaultPrng.init(4);
    var hub = testHub(&prng);
    var buf: [64]u8 = undefined;
    for ([_]sc.Vmac{ sc.Vmac.broadcast, sc.Vmac.unspecified, hub_vmac }) |bad| {
        const conn = try hub.accept(0);
        _ = try hub.onMessage(0, conn, connectRequest(1, bad, uuid(9), &buf));
        const r = (try sc.decode(hub.nextOutgoing().?.bytes)).payload.result;
        try testing.expectEqual(sc.ResultCode.nak, r.code);
        try testing.expectEqual(types.ErrorCode.inconsistent_parameters, r.err.?.code);
        try testing.expectEqual(@as(usize, 0), hub.nodeCount());
    }
}

test "nothing may precede the Connect-Request on a fresh socket" {
    var prng = std.Random.DefaultPrng.init(5);
    var hub = testHub(&prng);
    var buf: [64]u8 = undefined;
    const conn = try hub.accept(0);
    const hb = sc.encode(.{
        .header = .{ .message_id = 4 },
        .payload = .heartbeat_request,
    }, &buf) catch unreachable;
    try testing.expectEqual(Event.none, try hub.onMessage(0, conn, hb));
    const r = (try sc.decode(hub.nextOutgoing().?.bytes)).payload.result;
    try testing.expectEqual(types.ErrorCode.inconsistent_parameters, r.err.?.code);
    try testing.expectEqual(sc.Function.heartbeat_request, r.function);
}

test "a socket that never connects is aged out" {
    var prng = std.Random.DefaultPrng.init(6);
    var hub = testHub(&prng);
    const conn = try hub.accept(0);
    try testing.expectEqual(Event.none, try hub.poll(9_999));
    try testing.expectEqual(conn, (try hub.poll(10_000)).close_connection);
    try testing.expectError(error.UnknownConnection, hub.onMessage(0, conn, &.{ 0x0A, 0, 0, 1 }));
}

test "an established connection that goes silent is dropped" {
    var prng = std.Random.DefaultPrng.init(7);
    var hub = testHub(&prng);
    const conn = try admitNode(&hub, 0, vmac(1), uuid(1));
    try testing.expectEqual(Event.none, try hub.poll(299_999));
    const ev = try hub.poll(300_000);
    try testing.expectEqual(conn, ev.node_disconnected.conn);
    try testing.expectEqual(DisconnectReason.heartbeat_timeout, ev.node_disconnected.reason);
    try testing.expectEqual(@as(usize, 0), hub.nodeCount());
}

test "the hub fills in the originating VMAC a node was entitled to omit" {
    var prng = std.Random.DefaultPrng.init(8);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));
    const b = try admitNode(&hub, 0, vmac(2), uuid(2));

    var buf: [64]u8 = undefined;
    const npdu = sc.encode(.{
        // No source: the node knows the hub knows.
        .header = .{ .message_id = 5, .destination = vmac(2) },
        .payload = .{ .encapsulated_npdu = &.{ 0x01, 0x00, 0x10, 0x08 } },
    }, &buf) catch unreachable;
    try testing.expectEqual(Event.none, try hub.onMessage(1, a, npdu));

    const out = hub.nextOutgoing().?;
    try testing.expectEqual(b, out.conn);
    const fwd = try sc.decode(out.bytes);
    try testing.expect(fwd.header.source.?.eql(vmac(1)));
    try testing.expect(fwd.header.destination.?.eql(vmac(2)));
    try testing.expectEqual(@as(u32, 1), hub.forwarded);
}

test "a node claiming somebody else's VMAC is refused, not forwarded" {
    var prng = std.Random.DefaultPrng.init(9);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));
    _ = try admitNode(&hub, 0, vmac(2), uuid(2));

    var buf: [64]u8 = undefined;
    const spoof = sc.encode(.{
        .header = .{ .message_id = 6, .source = vmac(2), .destination = vmac(2) },
        .payload = .{ .encapsulated_npdu = &.{0x01} },
    }, &buf) catch unreachable;
    try testing.expectEqual(Event.none, try hub.onMessage(1, a, spoof));
    const out = hub.nextOutgoing().?;
    try testing.expectEqual(a, out.conn); // the NAK goes back to the liar
    const r = (try sc.decode(out.bytes)).payload.result;
    try testing.expectEqual(types.ErrorCode.inconsistent_parameters, r.err.?.code);
    try testing.expectEqual(@as(u32, 0), hub.forwarded);
}

test "a broadcast reaches everyone but the sender" {
    var prng = std.Random.DefaultPrng.init(10);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));
    const b = try admitNode(&hub, 0, vmac(2), uuid(2));
    const c = try admitNode(&hub, 0, vmac(3), uuid(3));

    var buf: [64]u8 = undefined;
    const who_is = sc.encode(.{
        .header = .{ .message_id = 7, .destination = sc.Vmac.broadcast },
        .payload = .{ .encapsulated_npdu = &.{ 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 } },
    }, &buf) catch unreachable;
    _ = try hub.onMessage(1, a, who_is);

    var seen_b = false;
    var seen_c = false;
    while (hub.nextOutgoing()) |o| {
        try testing.expect(o.conn != a);
        if (o.conn == b) seen_b = true;
        if (o.conn == c) seen_c = true;
        try testing.expect((try sc.decode(o.bytes)).header.source.?.eql(vmac(1)));
    }
    try testing.expect(seen_b and seen_c);
    try testing.expectEqual(@as(u32, 2), hub.forwarded);
}

test "a message with no destination at all is also a broadcast" {
    var prng = std.Random.DefaultPrng.init(11);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));
    _ = try admitNode(&hub, 0, vmac(2), uuid(2));

    var buf: [64]u8 = undefined;
    const msg = sc.encode(.{
        .header = .{ .message_id = 8 },
        .payload = .{ .encapsulated_npdu = &.{0x01} },
    }, &buf) catch unreachable;
    _ = try hub.onMessage(1, a, msg);
    try testing.expectEqual(@as(usize, 1), hub.pending());
    try testing.expectEqual(@as(u32, 1), hub.forwarded);
}

test "a destination nobody answers to is reported, not swallowed" {
    var prng = std.Random.DefaultPrng.init(12);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));

    var buf: [64]u8 = undefined;
    const msg = sc.encode(.{
        .header = .{ .message_id = 9, .destination = vmac(9) },
        .payload = .{ .encapsulated_npdu = &.{0x01} },
    }, &buf) catch unreachable;
    const ev = try hub.onMessage(1, a, msg);
    try testing.expect(ev.undeliverable.destination.eql(vmac(9)));
    try testing.expectEqual(@as(usize, 0), hub.pending());
}

test "an NPDU addressed to the hub's own VMAC comes up, not out" {
    var prng = std.Random.DefaultPrng.init(13);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));

    var buf: [64]u8 = undefined;
    const msg = sc.encode(.{
        .header = .{ .message_id = 10, .destination = hub_vmac },
        .payload = .{ .encapsulated_npdu = &.{ 0x01, 0x00, 0x10, 0x08 } },
    }, &buf) catch unreachable;
    const ev = try hub.onMessage(1, a, msg);
    try testing.expect(ev.npdu_for_hub.source.eql(vmac(1)));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x10, 0x08 }, ev.npdu_for_hub.bytes);
    try testing.expectEqual(@as(usize, 0), hub.pending());
}

test "the hub answers its own heartbeats, address resolutions and solicitations" {
    var prng = std.Random.DefaultPrng.init(14);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));
    var buf: [64]u8 = undefined;

    const hb = sc.encode(.{
        .header = .{ .message_id = 11 },
        .payload = .heartbeat_request,
    }, &buf) catch unreachable;
    _ = try hub.onMessage(1, a, hb);
    const ack = try sc.decode(hub.nextOutgoing().?.bytes);
    try testing.expectEqual(sc.Function.heartbeat_ack, ack.function());
    try testing.expectEqual(@as(u16, 11), ack.header.message_id);

    const ar = sc.encode(.{
        .header = .{ .message_id = 12, .destination = hub_vmac },
        .payload = .address_resolution,
    }, &buf) catch unreachable;
    _ = try hub.onMessage(2, a, ar);
    const ar_ack = try sc.decode(hub.nextOutgoing().?.bytes);
    try testing.expectEqualStrings("wss://192.0.2.1/", ar_ack.payload.address_resolution_ack);

    const sol = sc.encode(.{
        .header = .{ .message_id = 13, .destination = hub_vmac },
        .payload = .advertisement_solicitation,
    }, &buf) catch unreachable;
    _ = try hub.onMessage(3, a, sol);
    const adv = try sc.decode(hub.nextOutgoing().?.bytes);
    try testing.expectEqual(sc.HubConnectionStatus.no_hub_connection, adv.payload.advertisement.hub_status);
    try testing.expect(adv.header.source.?.eql(hub_vmac));
}

test "an NPDU over the negotiated maximum is refused at the hub" {
    var prng = std.Random.DefaultPrng.init(15);
    var hub = testHub(&prng);
    var small = Hub.init(.{
        .vmac = hub_vmac,
        .uuid = hub_uuid,
        .max_bvlc_length = 200,
        .max_npdu_length = 100,
    }, prng.random());
    _ = &hub;

    var buf: [512]u8 = undefined;
    const conn = try small.accept(0);
    _ = try small.onMessage(0, conn, connectRequest(1, vmac(1), uuid(1), &buf));
    _ = small.nextOutgoing();

    var payload: [150]u8 = @splat(0x11);
    const msg = sc.encode(.{
        .header = .{ .message_id = 2, .destination = vmac(2) },
        .payload = .{ .encapsulated_npdu = &payload },
    }, &buf) catch unreachable;
    _ = try small.onMessage(1, conn, msg);
    const r = (try sc.decode(small.nextOutgoing().?.bytes)).payload.result;
    try testing.expectEqual(types.ErrorCode.message_incomplete, r.err.?.code);
}

test "a Disconnect-Request is acknowledged and the entry removed" {
    var prng = std.Random.DefaultPrng.init(16);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));

    var buf: [64]u8 = undefined;
    const bye = sc.encode(.{
        .header = .{ .message_id = 14 },
        .payload = .disconnect_request,
    }, &buf) catch unreachable;
    const ev = try hub.onMessage(1, a, bye);
    try testing.expectEqual(DisconnectReason.peer_request, ev.node_disconnected.reason);
    const ack = try sc.decode(hub.nextOutgoing().?.bytes);
    try testing.expectEqual(sc.Function.disconnect_ack, ack.function());
    try testing.expectEqual(@as(usize, 0), hub.nodeCount());
}

test "a must-understand option we do not know is NAKed by the hub too" {
    var prng = std.Random.DefaultPrng.init(17);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));

    var opts: [4]u8 = undefined;
    const list = try sc.encodeOptions(&.{
        .{ .type = @enumFromInt(11), .must_understand = true },
    }, &opts);
    var buf: [64]u8 = undefined;
    const msg = sc.encode(.{
        .header = .{ .message_id = 15, .destination_options = list },
        .payload = .heartbeat_request,
    }, &buf) catch unreachable;
    _ = try hub.onMessage(1, a, msg);
    const r = (try sc.decode(hub.nextOutgoing().?.bytes)).payload.result;
    try testing.expectEqual(types.ErrorCode.header_not_understood, r.err.?.code);
    try testing.expectEqual(@as(u8, 0x4B), r.err.?.header_marker);
}

test "the connection table is finite and says so" {
    var prng = std.Random.DefaultPrng.init(18);
    var hub = testHub(&prng);
    for (0..8) |i| _ = try hub.accept(@intCast(i));
    try testing.expectError(error.TooManyConnections, hub.accept(9));

    // Closing one frees exactly one slot.
    _ = try hub.onConnectionClosed(3);
    _ = try hub.accept(10);
    try testing.expectError(error.TooManyConnections, hub.accept(11));
}

test "an unknown connection id is a typed error" {
    var prng = std.Random.DefaultPrng.init(19);
    var hub = testHub(&prng);
    try testing.expectError(error.UnknownConnection, hub.onMessage(0, 99, &.{ 0x0A, 0, 0, 1 }));
    try testing.expectError(error.UnknownConnection, hub.onMessage(0, 0, &.{ 0x0A, 0, 0, 1 }));
    try testing.expectError(error.UnknownConnection, hub.onConnectionClosed(0));
}

test "a malformed frame from a connected node is a typed error" {
    var prng = std.Random.DefaultPrng.init(20);
    var hub = testHub(&prng);
    const a = try admitNode(&hub, 0, vmac(1), uuid(1));
    try testing.expectError(error.BadMessage, hub.onMessage(1, a, &.{}));
    try testing.expectError(error.BadMessage, hub.onMessage(1, a, &.{ 0x01, 0x02, 0, 1, 0xC1 }));
    try testing.expectEqual(@as(usize, 1), hub.nodeCount());
}

test "fuzz: a hub survives arbitrary frames from an admitted node" {
    try std.testing.fuzz({}, fuzzHub, .{});
}

fn fuzzHub(_: void, smith: *std.testing.Smith) !void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    var hub = testHub(&prng);
    var cbuf: [64]u8 = undefined;

    const a = try hub.accept(0);
    _ = try hub.onMessage(0, a, connectRequest(1, vmac(1), uuid(1), &cbuf));
    while (hub.nextOutgoing()) |_| {}
    const b = try hub.accept(0);
    _ = try hub.onMessage(0, b, connectRequest(1, vmac(2), uuid(2), &cbuf));
    while (hub.nextOutgoing()) |_| {}

    var buf: [256]u8 = undefined;
    var now: u64 = 0;
    for (0..8) |_| {
        smith.bytes(&buf);
        const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
        const which: ConnId = if (smith.value(bool)) a else b;
        _ = hub.onMessage(now, which, buf[0..len]) catch {};
        _ = hub.poll(now) catch {};
        while (hub.nextOutgoing()) |o| {
            // Everything a hub emits must be a decodable BVLC-SC message, and
            // must be aimed at a slot that exists.
            _ = try sc.decode(o.bytes);
            try testing.expect(o.conn < 8);
        }
        now += smith.valueRangeAtMost(u32, 0, 400_000);
    }
}
