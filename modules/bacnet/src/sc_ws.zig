// SPDX-License-Identifier: MIT

//! **The BACnet/SC WebSocket binding (Annex AB.7), and the TLS seam.**
//!
//! Annex AB is unusual among the BACnet data links in that it does not define
//! a wire transport of its own: it borrows RFC 6455 wholesale and adds three
//! rules.
//!
//! 1. **A registered subprotocol name.** `hub.bsc.bacnet.org` for a connection
//!    to a hub, `dc.bsc.bacnet.org` for a direct node-to-node connection. The
//!    name is how a BACnet/SC endpoint and an ordinary WebSocket application
//!    can share a port and a path without either mis-parsing the other's
//!    traffic, so an endpoint that does **not** negotiate it must be treated
//!    as a failure, not as a bare WebSocket. `verifyNegotiated` is that check.
//! 2. **Binary frames only, one message per BVLC message.** There is no length
//!    field in the BACnet/SC BVLC (see `sc.zig`), so the frame boundary *is*
//!    the message boundary. A text frame is a protocol error.
//! 3. **TLS underneath, with mutual authentication.** See the seam below.
//!
//! Everything here is a thin adapter over the sibling `websocket` module —
//! this file deliberately contains no framing code of its own, because a
//! second RFC 6455 implementation living inside a BACnet module is exactly the
//! kind of duplication that goes stale.
//!
//! ## The TLS seam
//!
//! **This module does not implement TLS and does not pretend to.** Annex AB
//! (AB.8) requires, and a conforming deployment must provide:
//!
//! * **TLS 1.3** (AB permits 1.2 for legacy peers; prefer 1.3).
//! * **Mutual authentication** — *both* ends present a certificate and *both*
//!   verify. This is the single most important difference from ordinary
//!   `wss://`: a BACnet/SC hub authenticates every node, and every node
//!   authenticates the hub. A one-way `wss://` is not BACnet/SC.
//! * An **operational certificate** per device, signed by an issuer the peer
//!   trusts, held in the Network Port object's `Operational_Certificate_File`,
//!   with up to three `Issuer_Certificate_Files` for the trust anchors and a
//!   `Certificate_Signing_Request_File` for enrolment.
//! * Certificate **expiry and revocation** are real: a node whose operational
//!   certificate has expired is expected to fail the handshake, which is why
//!   `types.ErrorCode` has distinct `tls_client_certificate_expired`,
//!   `tls_server_certificate_expired` and `..._revoked` codes to report in a
//!   `BVLC-Result` NAK or an Advertisement's failure reason.
//!
//! The seam is therefore: **the caller hands this module a stream that is
//! already TLS**, and tells it so. `TlsAssertion` is the value the caller
//! passes to say "I terminated TLS, mutually, against these identities". It is
//! recorded, reported and used to decide whether a `secure_path` header option
//! may be asserted — and it is **never** verified here, because a module that
//! cannot see the certificate cannot verify anything. Passing
//! `TlsAssertion.none` is legal (it is what a plaintext `ws://` test harness
//! does) and makes `securePathOption()` return null, so a node cannot
//! accidentally claim a secure path it does not have.

const std = @import("std");
const websocket = @import("websocket");
const sc = @import("sc.zig");

pub const Error = error{
    /// The peer did not negotiate a BACnet/SC subprotocol. Per AB.7.1 this is
    /// a failed connection, not a plain WebSocket to fall back to.
    SubprotocolNotNegotiated,
    /// The peer negotiated the *other* BACnet/SC subprotocol — a hub
    /// connection where a direct one was asked for, or the reverse.
    WrongSubprotocol,
    /// A text frame arrived. BACnet/SC is binary-only (AB.7.2).
    TextFrame,
    /// The caller's buffer is too small.
    NoSpace,
};

/// Which of the two BACnet/SC WebSocket endpoints a connection is.
pub const Role = enum {
    /// `hub.bsc.bacnet.org` — a node talking to a hub, or a hub's listener.
    hub,
    /// `dc.bsc.bacnet.org` — a direct node-to-node connection.
    direct,

    pub fn subprotocol(self: Role) []const u8 {
        return switch (self) {
            .hub => sc.subprotocol_hub,
            .direct => sc.subprotocol_direct,
        };
    }
};

/// Both subprotocol names, in the order a node that supports each should
/// offer them. Useful as `ServerAcceptOptions.protocols` for an endpoint that
/// accepts both.
pub const both_subprotocols = [_][]const u8{ sc.subprotocol_hub, sc.subprotocol_direct };

/// What the caller asserts about the TLS layer it terminated underneath this
/// WebSocket. Nothing here is verified by this module — it cannot be, because
/// the certificates never reach it. It exists so the assertion is *explicit*
/// and can be logged, tested and refused.
pub const TlsAssertion = struct {
    /// The caller terminated TLS on this connection.
    tls: bool = false,
    /// The caller verified the peer's certificate chain against a trusted
    /// issuer **and** the peer verified ours. Annex AB requires both
    /// directions; a connection with `tls` but not `mutually_authenticated` is
    /// ordinary `wss://` and is *not* conforming BACnet/SC.
    mutually_authenticated: bool = false,
    /// Optional, purely for logging: the peer's certificate subject as the
    /// caller's TLS stack reported it. Borrowed; never parsed here.
    peer_identity: []const u8 = "",

    /// A plaintext connection — a test harness, or a deployment that
    /// terminates TLS in a separate process. Legal, and honest about it.
    pub const none: TlsAssertion = .{};

    /// The assertion a conforming deployment makes.
    pub fn mutual(peer_identity: []const u8) TlsAssertion {
        return .{ .tls = true, .mutually_authenticated = true, .peer_identity = peer_identity };
    }

    /// True when this connection satisfies what Annex AB asks of the transport.
    pub fn isConforming(self: TlsAssertion) bool {
        return self.tls and self.mutually_authenticated;
    }
};

/// The `secure_path` header option, *only* if the caller's TLS assertion
/// justifies it. AB.2.3.2's secure-path option means "every hop this message
/// took was protected"; asserting it over a plaintext socket would be a lie
/// that a peer has no way to detect, so this function refuses to.
pub fn securePathOption(tls: TlsAssertion) ?sc.Option {
    return if (tls.isConforming()) sc.Option.secure_path else null;
}

// ── handshake helpers ──────────────────────────────────────────────────────

/// The client-side upgrade request options for a BACnet/SC connection.
/// `key` must come from `websocket.handshake.generateKey(random)` and be kept
/// for `verifyResponse`.
pub fn clientRequest(
    role: Role,
    host: []const u8,
    target: []const u8,
    key: []const u8,
) websocket.handshake.ClientRequestOptions {
    return .{
        .host = host,
        .target = target,
        .key = key,
        .protocols = switch (role) {
            .hub => &.{sc.subprotocol_hub},
            .direct => &.{sc.subprotocol_direct},
        },
    };
}

/// The server-side accept options for an endpoint that speaks `roles`.
pub fn serverAccept(protocols: []const []const u8) websocket.handshake.ServerAcceptOptions {
    return .{ .protocols = protocols };
}

/// Checks that the negotiated subprotocol is the BACnet/SC one we asked for.
///
/// RFC 6455 lets a server answer with **no** `Sec-WebSocket-Protocol` header
/// at all, which an ordinary WebSocket client treats as "no subprotocol, carry
/// on". For BACnet/SC that is a failed connection: the peer is not a BACnet/SC
/// endpoint, and sending it a Connect-Request would be sending BVLC octets to
/// something that will interpret them as an application message.
pub fn verifyNegotiated(negotiated: ?[]const u8, expected: Role) Error!void {
    const p = negotiated orelse return error.SubprotocolNotNegotiated;
    if (std.ascii.eqlIgnoreCase(p, expected.subprotocol())) return;
    // The other BACnet/SC name is a distinguishable, more useful error than
    // "not negotiated": it means the peer *is* BACnet/SC but of the other kind.
    for ([_]Role{ .hub, .direct }) |r| {
        if (std.ascii.eqlIgnoreCase(p, r.subprotocol())) return error.WrongSubprotocol;
    }
    return error.SubprotocolNotNegotiated;
}

/// Which role a server should treat an accepted connection as.
pub fn roleFromSubprotocol(negotiated: ?[]const u8) Error!Role {
    const p = negotiated orelse return error.SubprotocolNotNegotiated;
    if (std.ascii.eqlIgnoreCase(p, sc.subprotocol_hub)) return .hub;
    if (std.ascii.eqlIgnoreCase(p, sc.subprotocol_direct)) return .direct;
    return error.SubprotocolNotNegotiated;
}

// ── framing ────────────────────────────────────────────────────────────────

/// Writes one BVLC-SC message as a single **binary** WebSocket frame.
///
/// `mask_key` is required for a client (RFC 6455 §5.3 makes masking mandatory
/// client-to-server) and must be null for a server. The caller supplies it,
/// from its own `std.Random`, for the same reason the rest of this collection
/// takes a `std.Random`: the module never reaches for a global CSPRNG.
pub fn writeMessage(
    w: *std.Io.Writer,
    payload: []const u8,
    mask_key: ?[4]u8,
) std.Io.Writer.Error!void {
    try websocket.frame.writeFrame(w, .{
        .opcode = .binary,
        .fin = true,
        .payload = payload,
        .mask_key = mask_key,
    });
}

/// One inbound event, already narrowed to what BACnet/SC cares about.
pub const Inbound = union(enum) {
    /// Not a whole frame yet; read more and call again.
    need_more,
    /// A non-final fragment was consumed. Annex AB does not forbid
    /// fragmentation, and a peer that fragments is not broken — the message is
    /// simply not complete yet.
    partial,
    /// One complete BVLC-SC message. Borrows the caller's buffer (or the
    /// `Connection`'s reassembly buffer) until the next call.
    message: []const u8,
    /// A ping; the caller must answer with `websocket.frame.pongFor`.
    ping: []const u8,
    pong: []const u8,
    /// The peer began the closing handshake.
    close: websocket.frame.CloseInfo,
};

pub const Result = struct { event: Inbound, consumed: usize };

/// Feeds bytes to a `websocket.Connection` and returns a BACnet/SC-shaped
/// event. The only thing this adds over `Connection.receive` is the binary-only
/// rule: a text frame is `error.TextFrame` rather than a message the BVLC
/// decoder would then reject with a confusing `UnknownFunction`.
pub fn receive(
    conn: *websocket.connection.Connection,
    buf: []u8,
) (websocket.connection.Connection.Error || Error)!Result {
    const r = try conn.receive(buf);
    return .{
        .consumed = r.consumed,
        .event = switch (r.event) {
            .need_more => .need_more,
            .frame_consumed => .partial,
            .message => |m| switch (m.opcode) {
                .binary => .{ .message = m.payload },
                else => return error.TextFrame,
            },
            .ping => |p| .{ .ping = p },
            .pong => |p| .{ .pong = p },
            .close => |c| .{ .close = c },
        },
    };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the two subprotocol names are the registered ones, spelled exactly" {
    try testing.expectEqualStrings("hub.bsc.bacnet.org", Role.hub.subprotocol());
    try testing.expectEqualStrings("dc.bsc.bacnet.org", Role.direct.subprotocol());
}

test "a server that answers without a subprotocol is not a BACnet/SC peer" {
    try testing.expectError(error.SubprotocolNotNegotiated, verifyNegotiated(null, .hub));
    try testing.expectError(error.SubprotocolNotNegotiated, verifyNegotiated("chat", .hub));
    try testing.expectError(error.WrongSubprotocol, verifyNegotiated(sc.subprotocol_direct, .hub));
    try testing.expectError(error.WrongSubprotocol, verifyNegotiated(sc.subprotocol_hub, .direct));
    try verifyNegotiated(sc.subprotocol_hub, .hub);
    // RFC 6455 subprotocol matching is case-insensitive on the token.
    try verifyNegotiated("HUB.BSC.BACNET.ORG", .hub);
}

test "roleFromSubprotocol sorts an accepted connection into the right kind" {
    try testing.expectEqual(Role.hub, try roleFromSubprotocol(sc.subprotocol_hub));
    try testing.expectEqual(Role.direct, try roleFromSubprotocol(sc.subprotocol_direct));
    try testing.expectError(error.SubprotocolNotNegotiated, roleFromSubprotocol(null));
    try testing.expectError(error.SubprotocolNotNegotiated, roleFromSubprotocol("x"));
}

test "the secure-path option cannot be asserted over a plaintext socket" {
    try testing.expectEqual(@as(?sc.Option, null), securePathOption(TlsAssertion.none));
    // TLS without mutual authentication is ordinary wss://, not BACnet/SC.
    try testing.expectEqual(@as(?sc.Option, null), securePathOption(.{ .tls = true }));
    const opt = securePathOption(TlsAssertion.mutual("CN=node-1")).?;
    try testing.expectEqual(sc.OptionType.secure_path, opt.type);
    try testing.expect(opt.must_understand);
    try testing.expect(TlsAssertion.mutual("CN=node-1").isConforming());
}

test "the client's upgrade request offers exactly one BACnet/SC subprotocol" {
    var prng = std.Random.DefaultPrng.init(0xBAC0);
    const key = websocket.handshake.generateKey(prng.random());

    var req_buf: [512]u8 = undefined;
    var req_w = std.Io.Writer.fixed(&req_buf);
    try websocket.handshake.writeRequest(
        &req_w,
        clientRequest(.hub, "hub.example:47808", "/", &key),
    );
    const request = req_w.buffered();
    try testing.expect(std.mem.startsWith(u8, request, "GET / HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, request, "Host: hub.example:47808\r\n") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        request,
        "Sec-WebSocket-Protocol: hub.bsc.bacnet.org\r\n",
    ) != null);
    // Offering both names would let a hub answer with the direct-connection
    // subprotocol for what the caller asked to be a hub connection.
    try testing.expect(std.mem.indexOf(u8, request, sc.subprotocol_direct) == null);

    var dir_buf: [512]u8 = undefined;
    var dir_w = std.Io.Writer.fixed(&dir_buf);
    try websocket.handshake.writeRequest(
        &dir_w,
        clientRequest(.direct, "node.example", "/bacnet", &key),
    );
    try testing.expect(std.mem.indexOf(
        u8,
        dir_w.buffered(),
        "Sec-WebSocket-Protocol: dc.bsc.bacnet.org\r\n",
    ) != null);
}

test "a server endpoint offers both names, hub first" {
    const opts = serverAccept(&both_subprotocols);
    try testing.expectEqual(@as(usize, 2), opts.protocols.len);
    try testing.expectEqualStrings(sc.subprotocol_hub, opts.protocols[0]);
    try testing.expectEqualStrings(sc.subprotocol_direct, opts.protocols[1]);
}

test "a BVLC message rides in one binary frame and comes back whole" {
    var scratch: [64]u8 = undefined;
    const bvlc = try sc.encode(.{
        .header = .{ .message_id = 7 },
        .payload = .heartbeat_request,
    }, &scratch);

    var wire: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&wire);
    try writeMessage(&w, bvlc, .{ 0xDE, 0xAD, 0xBE, 0xEF });
    const framed = w.buffered();
    // Client-to-server frames are masked, so the octets on the wire are not
    // the BVLC octets — which is exactly why the framing must be a real
    // implementation rather than a length prefix.
    try testing.expect(!std.mem.eql(u8, framed[framed.len - bvlc.len ..], bvlc));

    var msg_buf: [256]u8 = undefined;
    var conn = websocket.connection.Connection.init(.server, &msg_buf, 4096);
    var inbox: [128]u8 = undefined;
    @memcpy(inbox[0..framed.len], framed);
    const r = try receive(&conn, inbox[0..framed.len]);
    try testing.expectEqualSlices(u8, bvlc, r.event.message);
    try testing.expectEqual(sc.Function.heartbeat_request, (try sc.decode(r.event.message)).function());
}

test "a text frame is refused rather than handed to the BVLC decoder" {
    var wire: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&wire);
    try websocket.frame.writeFrame(&w, .{
        .opcode = .text,
        .fin = true,
        .payload = "hello",
        .mask_key = null,
    });
    var msg_buf: [64]u8 = undefined;
    var conn = websocket.connection.Connection.init(.client, &msg_buf, 4096);
    var inbox: [64]u8 = undefined;
    const framed = w.buffered();
    @memcpy(inbox[0..framed.len], framed);
    try testing.expectError(error.TextFrame, receive(&conn, inbox[0..framed.len]));
}

test "a fragmented BVLC message reassembles" {
    // Annex AB says nothing about fragmentation, so a peer is free to do it;
    // the reassembly is the `websocket` module's, not a second copy here.
    var scratch: [64]u8 = undefined;
    const bvlc = try sc.encode(.{
        .header = .{ .message_id = 0x0102, .source = .{ .octets = .{ 1, 2, 3, 4, 5, 6 } } },
        .payload = .heartbeat_ack,
    }, &scratch);

    var wire: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&wire);
    try websocket.frame.writeFrame(&w, .{
        .opcode = .binary,
        .fin = false,
        .payload = bvlc[0..4],
        .mask_key = null,
    });
    try websocket.frame.writeFrame(&w, .{
        .opcode = .continuation,
        .fin = true,
        .payload = bvlc[4..],
        .mask_key = null,
    });

    var msg_buf: [256]u8 = undefined;
    var conn = websocket.connection.Connection.init(.client, &msg_buf, 4096);
    var inbox: [128]u8 = undefined;
    const framed = w.buffered();
    @memcpy(inbox[0..framed.len], framed);

    var at: usize = 0;
    const first = try receive(&conn, inbox[at..framed.len]);
    try testing.expectEqual(Inbound.partial, first.event);
    at += first.consumed;
    const second = try receive(&conn, inbox[at..framed.len]);
    try testing.expectEqualSlices(u8, bvlc, second.event.message);
}

test "an incomplete frame asks for more instead of guessing" {
    var inbox: [4]u8 = .{ 0x82, 0x7E, 0x01, 0x40 };
    var msg_buf: [64]u8 = undefined;
    var conn = websocket.connection.Connection.init(.client, &msg_buf, 4096);
    const r = try receive(&conn, &inbox);
    try testing.expectEqual(Inbound.need_more, r.event);
    try testing.expectEqual(@as(usize, 0), r.consumed);
}
