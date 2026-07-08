// SPDX-License-Identifier: MIT

//! SNMP trap / notification receiver (the manager / NMS ingest side) — **T-A**.
//!
//! The `message` layer already decodes every notification PDU; this layer turns
//! a received datagram into a single normalized `TrapEvent` regardless of which
//! of the three notification shapes it arrived as, and dispatches it to a
//! handler:
//!
//! - **v1 Trap** (RFC 1157 §4.1.6) — enterprise OID, agent address, generic +
//!   specific trap numbers, and the sysUpTime time-stamp are first-class fields.
//! - **v2c SNMPv2-Trap** (RFC 3416 §4.2.6) — an unacknowledged notification; by
//!   convention varbind[0] is `sysUpTime.0` and varbind[1] is `snmpTrapOID.0`.
//! - **v2c InformRequest** — an *acknowledged* notification: the receiver must
//!   echo a Response with the same request-id and varbinds (that ack encoder is
//!   T-B; `TrapEvent.needsAck` + `request_id` flag it here).
//!
//! Transport-agnostic, allocation-free, and offline-testable in the same spirit
//! as `Client`: `parseTrap` works on an in-memory datagram, and `Dispatcher`
//! pairs a decoded event with a caller handler. Binding UDP/162 and the source
//! address are the caller's concern (capture the peer in the handler's context).
//! SNMPv3 / USM notifications are a follow-up (T-D…T-H).

const std = @import("std");
const ber = @import("ber.zig");
const oid = @import("oid.zig");
const message = @import("message.zig");

const Oid = oid.Oid;

/// Which of the three notification shapes a `TrapEvent` was decoded from.
pub const TrapKind = enum {
    /// SNMPv1 Trap-PDU (RFC 1157).
    v1,
    /// SNMPv2-Trap-PDU (RFC 3416) — unacknowledged.
    v2c,
    /// InformRequest-PDU (RFC 3416) — acknowledged (needs a Response).
    inform,
};

/// `parseTrap` errors: any `message` decode failure, plus `NotATrap` when the
/// datagram is a well-formed SNMP message that is not a notification (e.g. a
/// GetRequest or a Response).
pub const ParseError = message.DecodeError || error{NotATrap};

/// A decoded notification, normalized across v1 Trap / v2c Trap / Inform. All
/// slices and the `varbinds` list borrow the input datagram, which must outlive
/// this value.
pub const TrapEvent = struct {
    version: message.Version,
    /// The community string (borrowed). SNMPv3 will carry security parameters
    /// instead; this stays the v1/v2c community.
    community: []const u8,
    kind: TrapKind,
    /// The request-id — present for v2c Trap and Inform (an Inform needs it to
    /// build the Response ack); null for a v1 Trap, which has no request-id.
    request_id: ?i32,
    /// The variable bindings, decoded lazily via `varbinds.iterator()`. For a
    /// v2c notification the first two are conventionally `sysUpTime.0` then
    /// `snmpTrapOID.0` (see `sysUpTime` / `snmpTrapOid`).
    varbinds: message.VarBindList,
    /// The full v1 Trap-PDU (enterprise / agent_addr / generic_trap /
    /// specific_trap / time_stamp), present only when `kind == .v1`.
    v1: ?message.TrapV1Pdu,

    /// Whether the sender expects a Response acknowledgement (true only for an
    /// InformRequest). The ack itself is built by the T-B encoder.
    pub fn needsAck(self: TrapEvent) bool {
        return self.kind == .inform;
    }

    /// The notification's sysUpTime in TimeTicks (hundredths of a second), or
    /// null if unavailable. For a v1 Trap this is the PDU's time-stamp field;
    /// for a v2c notification it is varbind[0]'s value when that is a TimeTicks
    /// (the RFC 3416 §4.2.6 convention).
    pub fn sysUpTime(self: TrapEvent) ?u32 {
        if (self.kind == .v1) return if (self.v1) |t| t.time_stamp else null;
        var it = self.varbinds.iterator();
        const first = (it.next() catch return null) orelse return null;
        return switch (first.value) {
            .time_ticks => |t| t,
            else => null,
        };
    }

    /// The `snmpTrapOID.0` value of a v2c notification (varbind[1], per RFC 3416
    /// §4.2.6), or null (including for a v1 Trap, whose trap identity lives in
    /// the `enterprise` + `generic_trap` / `specific_trap` fields instead).
    pub fn snmpTrapOid(self: TrapEvent) ?Oid {
        if (self.kind == .v1) return null;
        var it = self.varbinds.iterator();
        _ = (it.next() catch return null) orelse return null; // skip sysUpTime.0
        const second = (it.next() catch return null) orelse return null;
        return switch (second.value) {
            .oid => |o| o,
            else => null,
        };
    }
};

/// Normalize an already-decoded `message.Message` into a `TrapEvent`, or
/// `error.NotATrap` when it is not a notification PDU.
pub fn fromMessage(msg: message.Message) error{NotATrap}!TrapEvent {
    return switch (msg.pdu) {
        .trap_v1 => |t| .{
            .version = msg.version,
            .community = msg.community,
            .kind = .v1,
            .request_id = null,
            .varbinds = t.varbinds,
            .v1 = t,
        },
        .trap_v2 => |b| .{
            .version = msg.version,
            .community = msg.community,
            .kind = .v2c,
            .request_id = b.request_id,
            .varbinds = b.varbinds,
            .v1 = null,
        },
        .inform_request => |b| .{
            .version = msg.version,
            .community = msg.community,
            .kind = .inform,
            .request_id = b.request_id,
            .varbinds = b.varbinds,
            .v1 = null,
        },
        else => error.NotATrap,
    };
}

/// Decode a received datagram into a `TrapEvent`. Rejects a well-formed
/// non-notification message with `error.NotATrap`; any malformed bytes surface
/// as a typed `message.DecodeError` (never a panic).
pub fn parseTrap(datagram: []const u8) ParseError!TrapEvent {
    return fromMessage(try message.decode(datagram));
}

/// A minimal notification dispatcher: decode a datagram and hand the event to a
/// context-carrying callback. The caller drives it (one call per received
/// datagram) and owns the socket + the peer address (capture the peer in `ctx`).
pub const Dispatcher = struct {
    /// Opaque handler state (e.g. the socket, a counter, the last peer address).
    ctx: *anyopaque,
    /// Invoked once per successfully-decoded notification.
    onTrap: *const fn (ctx: *anyopaque, event: *const TrapEvent) void,

    /// Decode `datagram` and, on success, invoke the handler. A decode failure /
    /// non-notification is returned to the caller and the handler is NOT called.
    pub fn dispatch(self: Dispatcher, datagram: []const u8) ParseError!void {
        var event = try parseTrap(datagram);
        self.onTrap(self.ctx, &event);
    }
};

/// `ackInform` errors: any encoder failure (`error.BufferTooSmall`), plus
/// `NotAnInform` when the event is not an InformRequest.
pub const AckError = ber.EncodeError || error{NotAnInform};

/// Build the Response acknowledgement for an InformRequest (RFC 3416 §4.2.7):
/// a Response-PDU echoing the inform's request-id, error-status = 0,
/// error-index = 0, and the **identical** variable-bindings. Only informs are
/// acknowledged — a v1/v2c Trap yields `error.NotAnInform`.
///
/// The response is written into `buf` (aligned to its END — the BER encoder
/// writes backwards) and the encoded slice is returned; send those bytes back
/// to the notifier's source address. The variable-bindings are copied verbatim
/// from `event` (byte-faithful), so `event` must still borrow its datagram.
pub fn ackInform(event: TrapEvent, buf: []u8) AckError![]const u8 {
    if (event.kind != .inform) return error.NotAnInform;
    const request_id = event.request_id orelse return error.NotAnInform;

    var e = ber.Encoder.init(buf);

    // variable-bindings: re-wrap the inform's raw varbind-list content verbatim.
    const list_mark = e.len();
    try e.prependBytes(event.varbinds.bytes);
    try e.wrap(ber.tag.sequence, list_mark);

    // error-index = 0, error-status = 0, request-id (echoed).
    try e.prependInteger(ber.tag.integer, 0);
    try e.prependInteger(ber.tag.integer, 0);
    try e.prependInteger(ber.tag.integer, request_id);
    try e.wrap(@intFromEnum(message.PduType.response), 0);

    // community + version, then the outer message SEQUENCE.
    try e.prependTlv(ber.tag.octet_string, event.community);
    try e.prependInteger(ber.tag.integer, @intFromEnum(event.version));
    try e.wrap(ber.tag.sequence, 0);
    return e.encoded();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Encode a v2c notification (trap or inform) into `buf` via the message layer,
/// with the standard sysUpTime.0 + snmpTrapOID.0 leading varbinds.
fn encodeV2cNotify(
    buf: []u8,
    pdu_type: message.PduType,
    request_id: i32,
    uptime: u32,
    trap_oid: Oid,
) ![]const u8 {
    const vbs = [_]message.VarBind{
        .{ .name = try Oid.parse("1.3.6.1.2.1.1.3.0"), .value = .{ .time_ticks = uptime } }, // sysUpTime.0
        .{ .name = try Oid.parse("1.3.6.1.6.3.1.1.4.1.0"), .value = .{ .oid = trap_oid } }, // snmpTrapOID.0
    };
    return message.encode(buf, .v2c, "public", .{
        .type = pdu_type,
        .request_id = request_id,
        .varbinds = &vbs,
    });
}

// A hand-built v1 Trap datagram: enterprise 1.3.6.1, agent 192.168.1.1,
// generic 6 (enterpriseSpecific), specific 42, time-stamp 10, no varbinds.
const v1_trap_bytes = [_]u8{
    0x30, 0x23, // Message SEQUENCE, 35
    0x02, 0x01, 0x00, // version = 0 (v1)
    0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community "public"
    0xa4, 0x16, // Trap-PDU [4], 22
    0x06, 0x03, 0x2b, 0x06, 0x01, // enterprise OID 1.3.6.1
    0x40, 0x04, 0xc0, 0xa8, 0x01, 0x01, // agent-addr IpAddress 192.168.1.1
    0x02, 0x01, 0x06, // generic-trap = 6
    0x02, 0x01, 0x2a, // specific-trap = 42
    0x43, 0x01, 0x0a, // time-stamp TimeTicks = 10
    0x30, 0x00, // empty varbind list
};

test "parseTrap: v1 Trap fields" {
    const ev = try parseTrap(&v1_trap_bytes);
    try testing.expectEqual(message.Version.v1, ev.version);
    try testing.expectEqualStrings("public", ev.community);
    try testing.expectEqual(TrapKind.v1, ev.kind);
    try testing.expect(!ev.needsAck());
    try testing.expectEqual(@as(?i32, null), ev.request_id);

    const t = ev.v1.?;
    const ent = try Oid.parse("1.3.6.1");
    try testing.expect(t.enterprise.eql(&ent));
    try testing.expectEqual([4]u8{ 192, 168, 1, 1 }, t.agent_addr);
    try testing.expectEqual(message.GenericTrap.enterprise_specific, t.generic_trap);
    try testing.expectEqual(@as(i32, 42), t.specific_trap);
    try testing.expectEqual(@as(u32, 10), t.time_stamp);
    // sysUpTime unifies to the v1 time-stamp; snmpTrapOid is v1-absent.
    try testing.expectEqual(@as(?u32, 10), ev.sysUpTime());
    try testing.expectEqual(@as(?Oid, null), ev.snmpTrapOid());
}

test "parseTrap: v2c SNMPv2-Trap with standard varbinds" {
    var buf: [128]u8 = undefined;
    const cold_start = try Oid.parse("1.3.6.1.6.3.1.1.5.1"); // coldStart trap OID
    const dg = try encodeV2cNotify(&buf, .trap_v2, 7, 12345, cold_start);

    const ev = try parseTrap(dg);
    try testing.expectEqual(message.Version.v2c, ev.version);
    try testing.expectEqual(TrapKind.v2c, ev.kind);
    try testing.expect(!ev.needsAck());
    try testing.expectEqual(@as(?i32, 7), ev.request_id);
    try testing.expectEqual(@as(?u32, 12345), ev.sysUpTime());
    const got = ev.snmpTrapOid().?;
    try testing.expect(got.eql(&cold_start));
}

test "parseTrap: InformRequest needs an ack and carries a request-id" {
    var buf: [128]u8 = undefined;
    const trap_oid = try Oid.parse("1.3.6.1.6.3.1.1.5.3"); // linkDown
    const dg = try encodeV2cNotify(&buf, .inform_request, 4242, 99, trap_oid);

    const ev = try parseTrap(dg);
    try testing.expectEqual(TrapKind.inform, ev.kind);
    try testing.expect(ev.needsAck());
    try testing.expectEqual(@as(?i32, 4242), ev.request_id);
    try testing.expect(ev.snmpTrapOid().?.eql(&trap_oid));
}

test "parseTrap: a non-notification PDU is NotATrap" {
    var buf: [128]u8 = undefined;
    const dg = try message.encode(&buf, .v2c, "public", .{
        .type = .get_request,
        .request_id = 1,
        .varbinds = &.{.{ .name = try Oid.parse("1.3.6.1.2.1.1.1.0"), .value = .null }},
    });
    try testing.expectError(error.NotATrap, parseTrap(dg));
}

test "parseTrap: malformed bytes surface a typed decode error, no panic" {
    // A truncated SEQUENCE (declared length exceeds the buffer) and an empty
    // datagram both fail in the BER layer as a typed error, never a panic.
    try testing.expectError(error.Truncated, parseTrap(&.{ 0x30, 0x05, 0x02 }));
    try testing.expectError(error.Truncated, parseTrap(&.{}));
}

test "sysUpTime / snmpTrapOid are null when varbinds are absent or wrong-typed" {
    var buf: [64]u8 = undefined;
    // A v2c trap with zero varbinds: both accessors yield null.
    const dg = try message.encode(&buf, .v2c, "public", .{ .type = .trap_v2, .request_id = 1 });
    const ev = try parseTrap(dg);
    try testing.expectEqual(@as(?u32, null), ev.sysUpTime());
    try testing.expectEqual(@as(?Oid, null), ev.snmpTrapOid());
}

const DispatchCtx = struct {
    count: usize = 0,
    last_kind: ?TrapKind = null,
    last_uptime: ?u32 = null,

    fn onTrap(ctx_ptr: *anyopaque, event: *const TrapEvent) void {
        const self: *DispatchCtx = @ptrCast(@alignCast(ctx_ptr));
        self.count += 1;
        self.last_kind = event.kind;
        self.last_uptime = event.sysUpTime();
    }
};

test "Dispatcher: routes a decoded event to the handler; skips it on error" {
    var ctx: DispatchCtx = .{};
    const d = Dispatcher{ .ctx = &ctx, .onTrap = DispatchCtx.onTrap };

    var buf: [128]u8 = undefined;
    const dg = try encodeV2cNotify(&buf, .trap_v2, 1, 555, try Oid.parse("1.3.6.1.6.3.1.1.5.1"));
    try d.dispatch(dg);
    try testing.expectEqual(@as(usize, 1), ctx.count);
    try testing.expectEqual(TrapKind.v2c, ctx.last_kind.?);
    try testing.expectEqual(@as(u32, 555), ctx.last_uptime.?);

    // A non-notification is returned as an error and the handler is not run.
    const req = try message.encode(&buf, .v2c, "public", .{ .type = .get_request, .request_id = 9 });
    try testing.expectError(error.NotATrap, d.dispatch(req));
    try testing.expectEqual(@as(usize, 1), ctx.count); // unchanged
}

test "ackInform: Response echoes request-id, zero error slots, identical varbinds" {
    var in_buf: [128]u8 = undefined;
    const trap_oid = try Oid.parse("1.3.6.1.6.3.1.1.5.3");
    const inform = try encodeV2cNotify(&in_buf, .inform_request, 4242, 99, trap_oid);
    const ev = try parseTrap(inform);
    const inform_vb_bytes = ev.varbinds.bytes;

    var ack_buf: [128]u8 = undefined;
    const ack = try ackInform(ev, &ack_buf);

    // The ack decodes as a v2c Response with the echoed request-id + zero errors.
    const msg = try message.decode(ack);
    try testing.expectEqual(message.Version.v2c, msg.version);
    try testing.expectEqualStrings("public", msg.community);
    const resp = msg.pdu.response;
    try testing.expectEqual(@as(i32, 4242), resp.request_id);
    try testing.expectEqual(message.ErrorStatus.no_error, resp.error_status);
    try testing.expectEqual(@as(u32, 0), resp.error_index);
    // Variable-bindings are byte-identical to the inform's.
    try testing.expectEqualSlices(u8, inform_vb_bytes, resp.varbinds.bytes);
    // And they still parse: snmpTrapOID.0 round-trips.
    const ack_ev_oid = (TrapEvent{
        .version = .v2c,
        .community = "public",
        .kind = .inform,
        .request_id = 4242,
        .varbinds = resp.varbinds,
        .v1 = null,
    }).snmpTrapOid().?;
    try testing.expect(ack_ev_oid.eql(&trap_oid));
}

test "ackInform: refuses a non-inform notification" {
    var buf: [128]u8 = undefined;
    const dg = try encodeV2cNotify(&buf, .trap_v2, 1, 1, try Oid.parse("1.3.6.1.6.3.1.1.5.1"));
    const ev = try parseTrap(dg);
    var ack_buf: [128]u8 = undefined;
    try testing.expectError(error.NotAnInform, ackInform(ev, &ack_buf));

    const v1 = try parseTrap(&v1_trap_bytes);
    try testing.expectError(error.NotAnInform, ackInform(v1, &ack_buf));
}

test "ackInform: buffer too small is a typed error, not a panic" {
    var buf: [128]u8 = undefined;
    const inform = try encodeV2cNotify(&buf, .inform_request, 7, 5, try Oid.parse("1.3.6.1.6.3.1.1.5.1"));
    const ev = try parseTrap(inform);
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, ackInform(ev, &tiny));
}
