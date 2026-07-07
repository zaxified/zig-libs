// SPDX-License-Identifier: MIT

//! SNMP message + PDU model for v1 (RFC 1157) and v2c (RFC 1905/3416).
//!
//! Wire form: `SEQUENCE { version INTEGER, community OCTET STRING, PDU }`.
//! PDUs: GetRequest [0], GetNextRequest [1], Response [2], SetRequest [3],
//! v1 Trap [4], GetBulkRequest [5], InformRequest [6], SNMPv2-Trap [7].
//!
//! `decode` produces a typed `Message`; varbinds are validated lazily via
//! `VarBindList.iterator()` so hostile lists cost nothing until walked, and
//! every malformed byte is a typed error, never a panic. `encode` builds
//! request-side messages (all PDU shapes except the v1 Trap, which this
//! manager-side module only decodes).

const std = @import("std");
const ber = @import("ber.zig");
const oid_mod = @import("oid.zig");

const Oid = oid_mod.Oid;

pub const Version = enum(u8) {
    v1 = 0,
    v2c = 1,
};

/// PDU tag bytes (context class, constructed).
pub const PduType = enum(u8) {
    get_request = 0xa0,
    get_next_request = 0xa1,
    /// GetResponse in v1 parlance, Response in v2c — same tag [2].
    response = 0xa2,
    set_request = 0xa3,
    /// v1 only (RFC 1157).
    trap_v1 = 0xa4,
    /// v2c only (RFC 3416).
    get_bulk_request = 0xa5,
    /// v2c only.
    inform_request = 0xa6,
    /// v2c only.
    trap_v2 = 0xa7,
};

/// error-status values: 0-5 from RFC 1157, 6-18 added by RFC 3416.
/// Non-exhaustive — agents may emit values outside the published table.
pub const ErrorStatus = enum(u8) {
    no_error = 0,
    too_big = 1,
    no_such_name = 2,
    bad_value = 3,
    read_only = 4,
    gen_err = 5,
    no_access = 6,
    wrong_type = 7,
    wrong_length = 8,
    wrong_encoding = 9,
    wrong_value = 10,
    no_creation = 11,
    inconsistent_value = 12,
    resource_unavailable = 13,
    commit_failed = 14,
    undo_failed = 15,
    authorization_error = 16,
    not_writable = 17,
    inconsistent_name = 18,
    _,
};

/// generic-trap values of the v1 Trap-PDU (RFC 1157 §4.1.6).
pub const GenericTrap = enum(u8) {
    cold_start = 0,
    warm_start = 1,
    link_down = 2,
    link_up = 3,
    authentication_failure = 4,
    egp_neighbor_loss = 5,
    enterprise_specific = 6,
    _,
};

pub const VarBind = struct {
    name: Oid,
    value: ber.Value,
};

pub const DecodeError = ber.DecodeError || error{ UnsupportedVersion, UnknownPduType };
pub const EncodeError = ber.EncodeError || error{ InvalidOid, UnsupportedPdu };

/// The raw `SEQUENCE OF VarBind` content of a decoded PDU. Varbinds are
/// decoded lazily: `iterator().next()` yields typed entries and surfaces
/// malformed ones as typed errors.
pub const VarBindList = struct {
    bytes: []const u8,

    pub const empty: VarBindList = .{ .bytes = &.{} };

    pub const Iterator = struct {
        dec: ber.Decoder,

        pub fn next(it: *Iterator) DecodeError!?VarBind {
            if (it.dec.done()) return null;
            const content = try it.dec.expect(ber.tag.sequence);
            var inner = ber.Decoder.init(content);
            const name = try ber.parseOid(try inner.expect(ber.tag.object_identifier));
            const value = try ber.parseValue(try inner.any());
            if (!inner.done()) return error.TrailingData;
            return .{ .name = name, .value = value };
        }
    };

    pub fn iterator(l: VarBindList) Iterator {
        return .{ .dec = ber.Decoder.init(l.bytes) };
    }

    pub fn count(l: VarBindList) DecodeError!usize {
        var it = l.iterator();
        var n: usize = 0;
        while (try it.next()) |_| n += 1;
        return n;
    }

    /// Decode every varbind into `out`; the filled prefix is returned.
    pub fn collect(l: VarBindList, out: []VarBind) (DecodeError || error{BufferTooSmall})![]VarBind {
        var it = l.iterator();
        var n: usize = 0;
        while (try it.next()) |vb| {
            if (n == out.len) return error.BufferTooSmall;
            out[n] = vb;
            n += 1;
        }
        return out[0..n];
    }
};

/// Get/GetNext/Response/Set/Inform/SNMPv2-Trap body.
pub const BasicPdu = struct {
    request_id: i32,
    error_status: ErrorStatus,
    error_index: u32,
    varbinds: VarBindList,
};

/// GetBulkRequest body (RFC 3416 §4.2.3): the error-status / error-index
/// wire slots carry non-repeaters / max-repetitions. Negative values are
/// treated as 0, as the RFC prescribes.
pub const BulkPdu = struct {
    request_id: i32,
    non_repeaters: u32,
    max_repetitions: u32,
    varbinds: VarBindList,
};

/// v1 Trap-PDU body (RFC 1157 §4.1.6).
pub const TrapV1Pdu = struct {
    enterprise: Oid,
    agent_addr: [4]u8,
    generic_trap: GenericTrap,
    specific_trap: i32,
    /// sysUpTime at trap generation, in TimeTicks.
    time_stamp: u32,
    varbinds: VarBindList,
};

pub const Pdu = union(PduType) {
    get_request: BasicPdu,
    get_next_request: BasicPdu,
    response: BasicPdu,
    set_request: BasicPdu,
    trap_v1: TrapV1Pdu,
    get_bulk_request: BulkPdu,
    inform_request: BasicPdu,
    trap_v2: BasicPdu,
};

pub const Message = struct {
    version: Version,
    /// Borrowed from the input buffer.
    community: []const u8,
    pdu: Pdu,
};

// ── decoding ────────────────────────────────────────────────────────────────

/// Decode one SNMP message. Slices in the result (community, octet-string
/// values) borrow from `bytes`. Varbind contents are validated lazily.
pub fn decode(bytes: []const u8) DecodeError!Message {
    var top = ber.Decoder.init(bytes);
    const msg_content = try top.expect(ber.tag.sequence);
    if (!top.done()) return error.TrailingData;

    var m = ber.Decoder.init(msg_content);
    const version: Version = switch (try ber.parseInteger(try m.expect(ber.tag.integer))) {
        0 => .v1,
        1 => .v2c,
        else => return error.UnsupportedVersion,
    };
    const community = try m.expect(ber.tag.octet_string);
    const pdu_tlv = try m.any();
    if (!m.done()) return error.TrailingData;

    const pdu: Pdu = switch (pdu_tlv.tag) {
        @intFromEnum(PduType.get_request) => .{ .get_request = try parseBasic(pdu_tlv.content) },
        @intFromEnum(PduType.get_next_request) => .{ .get_next_request = try parseBasic(pdu_tlv.content) },
        @intFromEnum(PduType.response) => .{ .response = try parseBasic(pdu_tlv.content) },
        @intFromEnum(PduType.set_request) => .{ .set_request = try parseBasic(pdu_tlv.content) },
        @intFromEnum(PduType.trap_v1) => .{ .trap_v1 = try parseTrapV1(pdu_tlv.content) },
        @intFromEnum(PduType.get_bulk_request) => .{ .get_bulk_request = try parseBulk(pdu_tlv.content) },
        @intFromEnum(PduType.inform_request) => .{ .inform_request = try parseBasic(pdu_tlv.content) },
        @intFromEnum(PduType.trap_v2) => .{ .trap_v2 = try parseBasic(pdu_tlv.content) },
        else => return error.UnknownPduType,
    };
    return .{ .version = version, .community = community, .pdu = pdu };
}

const PduFields = struct {
    request_id: i32,
    f1: i64,
    f2: i64,
    varbinds: VarBindList,
};

fn parseFields(content: []const u8) DecodeError!PduFields {
    var d = ber.Decoder.init(content);
    const rid = try ber.parseInteger(try d.expect(ber.tag.integer));
    const f1 = try ber.parseInteger(try d.expect(ber.tag.integer));
    const f2 = try ber.parseInteger(try d.expect(ber.tag.integer));
    const vbs = try d.expect(ber.tag.sequence);
    if (!d.done()) return error.TrailingData;
    return .{
        .request_id = std.math.cast(i32, rid) orelse return error.IntegerTooLarge,
        .f1 = f1,
        .f2 = f2,
        .varbinds = .{ .bytes = vbs },
    };
}

fn parseBasic(content: []const u8) DecodeError!BasicPdu {
    const f = try parseFields(content);
    if (f.f1 < 0 or f.f1 > 255) return error.InvalidValue;
    return .{
        .request_id = f.request_id,
        .error_status = @enumFromInt(@as(u8, @intCast(f.f1))),
        .error_index = std.math.cast(u32, f.f2) orelse return error.InvalidValue,
        .varbinds = f.varbinds,
    };
}

fn parseBulk(content: []const u8) DecodeError!BulkPdu {
    const f = try parseFields(content);
    return .{
        .request_id = f.request_id,
        .non_repeaters = clampToU32(f.f1),
        .max_repetitions = clampToU32(f.f2),
        .varbinds = f.varbinds,
    };
}

fn clampToU32(v: i64) u32 {
    if (v < 0) return 0;
    return std.math.cast(u32, v) orelse std.math.maxInt(u32);
}

fn parseTrapV1(content: []const u8) DecodeError!TrapV1Pdu {
    var d = ber.Decoder.init(content);
    const enterprise = try ber.parseOid(try d.expect(ber.tag.object_identifier));
    const addr = try d.expect(ber.tag.ip_address);
    if (addr.len != 4) return error.InvalidValue;
    const generic = try ber.parseInteger(try d.expect(ber.tag.integer));
    if (generic < 0 or generic > 255) return error.InvalidValue;
    const specific = try ber.parseInteger(try d.expect(ber.tag.integer));
    // Lenient on the time-stamp tag: RFC 1157 says TimeTicks, but plain
    // INTEGER is seen in the wild (net-snmp tolerates it too).
    const ts_tlv = try d.any();
    const time_stamp: u32 = switch (ts_tlv.tag) {
        ber.tag.time_ticks, ber.tag.integer => try ber.parseUnsigned32(ts_tlv.content),
        else => return error.UnexpectedTag,
    };
    const vbs = try d.expect(ber.tag.sequence);
    if (!d.done()) return error.TrailingData;
    return .{
        .enterprise = enterprise,
        .agent_addr = addr[0..4].*,
        .generic_trap = @enumFromInt(@as(u8, @intCast(generic))),
        .specific_trap = std.math.cast(i32, specific) orelse return error.IntegerTooLarge,
        .time_stamp = time_stamp,
        .varbinds = .{ .bytes = vbs },
    };
}

// ── encoding ────────────────────────────────────────────────────────────────

/// Manager-side encodable PDU. The v1 Trap-PDU has a different shape and is
/// decode-only here (`error.UnsupportedPdu`).
pub const EncodePdu = struct {
    type: PduType,
    request_id: i32,
    /// error-status slot; GetBulkRequest reuses it as non-repeaters.
    error_status: i32 = 0,
    /// error-index slot; GetBulkRequest reuses it as max-repetitions.
    error_index: i32 = 0,
    varbinds: []const VarBind = &.{},
};

/// Encode a complete SNMP message into `buf`; returns the encoded slice
/// (aligned to the **end** of `buf` — the encoder writes backwards).
pub fn encode(
    buf: []u8,
    version: Version,
    community: []const u8,
    pdu: EncodePdu,
) EncodeError![]const u8 {
    if (pdu.type == .trap_v1) return error.UnsupportedPdu;
    var e = ber.Encoder.init(buf);

    const list_mark = e.len();
    var i = pdu.varbinds.len;
    while (i > 0) {
        i -= 1;
        const vb = &pdu.varbinds[i];
        const vb_mark = e.len();
        try e.prependValue(&vb.value);
        try e.prependOid(&vb.name);
        try e.wrap(ber.tag.sequence, vb_mark);
    }
    try e.wrap(ber.tag.sequence, list_mark);

    try e.prependInteger(ber.tag.integer, pdu.error_index);
    try e.prependInteger(ber.tag.integer, pdu.error_status);
    try e.prependInteger(ber.tag.integer, pdu.request_id);
    try e.wrap(@intFromEnum(pdu.type), 0);

    try e.prependTlv(ber.tag.octet_string, community);
    try e.prependInteger(ber.tag.integer, @intFromEnum(version));
    try e.wrap(ber.tag.sequence, 0);
    return e.encoded();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "v2c GetRequest for two OIDs: exact bytes" {
    // GetRequest(request-id 1, community "public") for sysDescr.0 and
    // sysUpTime.0 — transcribed by hand from RFC 1157/3416 + X.690.
    const expected = [_]u8{
        0x30, 0x34, // Message SEQUENCE, 52
        0x02, 0x01, 0x01, // version = 1 (v2c)
        0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community
        0xa0, 0x27, // GetRequest-PDU, 39
        0x02, 0x01, 0x01, // request-id = 1
        0x02, 0x01, 0x00, // error-status = 0
        0x02, 0x01, 0x00, // error-index = 0
        0x30, 0x1c, // varbind list, 28
        0x30, 0x0c, // varbind 1
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // sysDescr.0
        0x05, 0x00, // NULL
        0x30, 0x0c, // varbind 2
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, // sysUpTime.0
        0x05, 0x00, // NULL
    };
    var buf: [128]u8 = undefined;
    const got = try encode(&buf, .v2c, "public", .{
        .type = .get_request,
        .request_id = 1,
        .varbinds = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.1.1.0"), .value = .null },
            .{ .name = try Oid.parse("1.3.6.1.2.1.1.3.0"), .value = .null },
        },
    });
    try testing.expectEqualSlices(u8, &expected, got);

    // And it round-trips through decode.
    const msg = try decode(got);
    try testing.expectEqual(Version.v2c, msg.version);
    try testing.expectEqualStrings("public", msg.community);
    const p = msg.pdu.get_request;
    try testing.expectEqual(@as(i32, 1), p.request_id);
    try testing.expectEqual(@as(usize, 2), try p.varbinds.count());
}

test "GetBulkRequest: exact bytes" {
    // GetBulk(request-id 5, non-repeaters 0, max-repetitions 10) for 1.3.6.1.2.1.
    const expected = [_]u8{
        0x30, 0x23,
        0x02, 0x01,
        0x01, 0x04,
        0x06, 'p',
        'u',  'b',
        'l',  'i',
        'c',
        0xa5, 0x16, // GetBulkRequest-PDU, 22
        0x02, 0x01, 0x05, // request-id = 5
        0x02, 0x01, 0x00, // non-repeaters = 0
        0x02, 0x01, 0x0a, // max-repetitions = 10
        0x30, 0x0b, 0x30,
        0x09, 0x06, 0x05,
        0x2b, 0x06, 0x01,
        0x02, 0x01, 0x05,
        0x00,
    };
    var buf: [64]u8 = undefined;
    const got = try encode(&buf, .v2c, "public", .{
        .type = .get_bulk_request,
        .request_id = 5,
        .error_status = 0, // non-repeaters
        .error_index = 10, // max-repetitions
        .varbinds = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1"), .value = .null },
        },
    });
    try testing.expectEqualSlices(u8, &expected, got);

    const msg = try decode(got);
    const p = msg.pdu.get_bulk_request;
    try testing.expectEqual(@as(i32, 5), p.request_id);
    try testing.expectEqual(@as(u32, 0), p.non_repeaters);
    try testing.expectEqual(@as(u32, 10), p.max_repetitions);
}

test "decode a captured-style GetResponse into typed varbinds" {
    // Response(request-id 1234) carrying sysDescr.0 = "hello" and
    // sysUpTime.0 = TimeTicks 100494 — transcribed by hand.
    const wire = [_]u8{
        0x30, 0x3d,
        0x02, 0x01,
        0x01, 0x04,
        0x06, 'p',
        'u',  'b',
        'l',  'i',
        'c',
        0xa2, 0x30, // Response-PDU, 48
        0x02, 0x02, 0x04, 0xd2, // request-id = 1234
        0x02, 0x01, 0x00, 0x02,
        0x01, 0x00, 0x30, 0x24,
        0x30, 0x11, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x02,
        0x01, 0x01, 0x01, 0x00,
        0x04, 0x05, 'h',  'e',
        'l',  'l',  'o',  0x30,
        0x0f, 0x06, 0x08, 0x2b,
        0x06, 0x01, 0x02, 0x01,
        0x01, 0x03, 0x00, 0x43,
        0x03, 0x01, 0x88, 0x8e,
    };
    const msg = try decode(&wire);
    try testing.expectEqual(Version.v2c, msg.version);
    try testing.expectEqualStrings("public", msg.community);
    const p = msg.pdu.response;
    try testing.expectEqual(@as(i32, 1234), p.request_id);
    try testing.expectEqual(ErrorStatus.no_error, p.error_status);
    try testing.expectEqual(@as(u32, 0), p.error_index);

    var vbs: [4]VarBind = undefined;
    const got = try p.varbinds.collect(&vbs);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectFmt("1.3.6.1.2.1.1.1.0", "{f}", .{got[0].name});
    try testing.expectEqualStrings("hello", got[0].value.octet_string);
    try testing.expectFmt("1.3.6.1.2.1.1.3.0", "{f}", .{got[1].name});
    try testing.expectEqual(@as(u32, 100494), got[1].value.time_ticks);
}

test "decode a v1 Trap-PDU" {
    // Trap from enterprise 1.3.6.1.4.1.8072, agent 192.168.0.1,
    // enterpriseSpecific(6)/42, sysUpTime 12345, one INTEGER varbind.
    const wire = [_]u8{
        0x30, 0x37,
        0x02, 0x01, 0x00, // version = 0 (v1)
        0x04, 0x06, 'p',
        'u',  'b',  'l',
        'i',  'c',
        0xa4, 0x2a, // Trap-PDU, 42
        0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, // enterprise
        0x40, 0x04, 0xc0, 0xa8, 0x00, 0x01, // agent-addr
        0x02, 0x01, 0x06, // generic-trap = enterpriseSpecific
        0x02, 0x01, 0x2a, // specific-trap = 42
        0x43, 0x02, 0x30, 0x39, // time-stamp = TimeTicks 12345
        0x30, 0x0f, 0x30, 0x0d,
        0x06, 0x08, 0x2b, 0x06,
        0x01, 0x04, 0x01, 0xbf,
        0x08, 0x01, 0x02, 0x01,
        0x07,
    };
    const msg = try decode(&wire);
    try testing.expectEqual(Version.v1, msg.version);
    const p = msg.pdu.trap_v1;
    try testing.expectFmt("1.3.6.1.4.1.8072", "{f}", .{p.enterprise});
    try testing.expectEqual([4]u8{ 192, 168, 0, 1 }, p.agent_addr);
    try testing.expectEqual(GenericTrap.enterprise_specific, p.generic_trap);
    try testing.expectEqual(@as(i32, 42), p.specific_trap);
    try testing.expectEqual(@as(u32, 12345), p.time_stamp);
    var it = p.varbinds.iterator();
    const vb = (try it.next()).?;
    try testing.expectFmt("1.3.6.1.4.1.8072.1", "{f}", .{vb.name});
    try testing.expectEqual(@as(i64, 7), vb.value.integer);
    try testing.expectEqual(@as(?VarBind, null), try it.next());
}

test "decode an SNMPv2-Trap" {
    // sysUpTime.0 = TimeTicks 1234, snmpTrapOID.0 = linkDown (1.3.6.1.6.3.1.1.5.3).
    const wire = [_]u8{
        0x30, 0x41,
        0x02, 0x01,
        0x01, 0x04,
        0x06, 'p',
        'u',  'b',
        'l',  'i',
        'c',
        0xa7, 0x34, // SNMPv2-Trap-PDU, 52
        0x02, 0x01, 0x63, // request-id = 99
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x29, 0x30,
        0x0e, 0x06, 0x08,
        0x2b, 0x06, 0x01,
        0x02, 0x01, 0x01,
        0x03, 0x00, 0x43,
        0x02, 0x04, 0xd2,
        0x30, 0x17, 0x06,
        0x0a, 0x2b, 0x06,
        0x01, 0x06, 0x03,
        0x01, 0x01, 0x04,
        0x01, 0x00, 0x06,
        0x09, 0x2b, 0x06,
        0x01, 0x06, 0x03,
        0x01, 0x01, 0x05,
        0x03,
    };
    const msg = try decode(&wire);
    try testing.expectEqual(Version.v2c, msg.version);
    const p = msg.pdu.trap_v2;
    try testing.expectEqual(@as(i32, 99), p.request_id);
    var vbs: [4]VarBind = undefined;
    const got = try p.varbinds.collect(&vbs);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqual(@as(u32, 1234), got[0].value.time_ticks);
    try testing.expectFmt("1.3.6.1.6.3.1.1.5.3", "{f}", .{got[1].value.oid});
}

test "error-status responses and v2c exception varbinds surface" {
    // v1-style noSuchName(2) at index 1.
    var buf: [128]u8 = undefined;
    const err_wire = try encode(&buf, .v1, "private", .{
        .type = .response,
        .request_id = 7,
        .error_status = 2,
        .error_index = 1,
        .varbinds = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.99.1.0"), .value = .null },
        },
    });
    const msg = try decode(err_wire);
    try testing.expectEqual(Version.v1, msg.version);
    try testing.expectEqual(ErrorStatus.no_such_name, msg.pdu.response.error_status);
    try testing.expectEqual(@as(u32, 1), msg.pdu.response.error_index);

    // v2c-style: noError but an exception value in the varbind.
    var buf2: [128]u8 = undefined;
    const exc_wire = try encode(&buf2, .v2c, "public", .{
        .type = .response,
        .request_id = 8,
        .varbinds = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.99.1.0"), .value = .no_such_instance },
        },
    });
    const msg2 = try decode(exc_wire);
    var it = msg2.pdu.response.varbinds.iterator();
    const vb = (try it.next()).?;
    try testing.expectEqual(ber.Value.no_such_instance, vb.value);

    // Unknown error-status codes decode via the non-exhaustive enum.
    const custom = try encode(&buf, .v2c, "public", .{
        .type = .response,
        .request_id = 9,
        .error_status = 200,
    });
    const msg3 = try decode(custom);
    try testing.expectEqual(@as(u8, 200), @intFromEnum(msg3.pdu.response.error_status));
}

test "set request round-trips typed values" {
    var buf: [256]u8 = undefined;
    const wire = try encode(&buf, .v2c, "private", .{
        .type = .set_request,
        .request_id = 77,
        .varbinds = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.1.6.0"), .value = .{ .octet_string = "rack 4" } },
            .{ .name = try Oid.parse("1.3.6.1.2.1.4.1.0"), .value = .{ .integer = 2 } },
            .{ .name = try Oid.parse("1.3.6.1.2.1.4.20.1.1"), .value = .{ .ip_address = .{ 10, 0, 0, 1 } } },
            .{ .name = try Oid.parse("1.3.6.1.2.1.31.1.1.1.6.1"), .value = .{ .counter64 = 1 << 40 } },
        },
    });
    const msg = try decode(wire);
    var vbs: [8]VarBind = undefined;
    const got = try msg.pdu.set_request.varbinds.collect(&vbs);
    try testing.expectEqual(@as(usize, 4), got.len);
    try testing.expectEqualStrings("rack 4", got[0].value.octet_string);
    try testing.expectEqual(@as(i64, 2), got[1].value.integer);
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, got[2].value.ip_address);
    try testing.expectEqual(@as(u64, 1 << 40), got[3].value.counter64);
}

test "malformed messages are typed errors" {
    // v1 Trap PDU tag is not encodable here.
    var buf: [64]u8 = undefined;
    try testing.expectError(error.UnsupportedPdu, encode(&buf, .v1, "public", .{
        .type = .trap_v1,
        .request_id = 1,
    }));

    // Unsupported version.
    const v3 = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x03, 0x04, 0x01, 'x' };
    try testing.expectError(error.UnsupportedVersion, decode(&v3));

    // Unknown PDU tag (context 8).
    const bad_pdu = [_]u8{
        0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x03, 'p', 'u', 'b', 0xa8, 0x00,
    };
    try testing.expectError(error.UnknownPduType, decode(&bad_pdu));

    // Trailing bytes after the message.
    const trailing = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00, 0xff };
    try testing.expectError(error.TrailingData, decode(&trailing));

    // Malformed varbind inside an otherwise valid response is surfaced by
    // the iterator, not at decode time.
    const bad_vb = [_]u8{
        0x30, 0x18,
        0x02, 0x01,
        0x01, 0x04,
        0x03, 'p',
        'u',  'b',
        0xa2, 0x0e,
        0x02, 0x01,
        0x01, 0x02,
        0x01, 0x00,
        0x02, 0x01,
        0x00, 0x30,
        0x03,
        0x02, 0x01, 0x05, // INTEGER where a varbind SEQUENCE must be
    };
    const msg = try decode(&bad_vb);
    var it = msg.pdu.response.varbinds.iterator();
    try testing.expectError(error.UnexpectedTag, it.next());
}

test "garbage and truncation sweep: decode never panics" {
    // Pseudo-random buffers.
    var prng = std.Random.DefaultPrng.init(0x534e4d50);
    const random = prng.random();
    var noise: [512]u8 = undefined;
    for (0..256) |_| {
        random.bytes(&noise);
        const n = random.intRangeAtMost(usize, 0, noise.len);
        if (decode(noise[0..n])) |msg| {
            // In the unlikely event it parses, walking varbinds must not panic.
            switch (msg.pdu) {
                inline else => |p| {
                    var it = p.varbinds.iterator();
                    while (it.next() catch null) |_| {}
                },
            }
        } else |_| {}
    }

    // Every truncation of a valid message decodes to a typed error.
    var buf: [128]u8 = undefined;
    const full = try encode(&buf, .v2c, "public", .{
        .type = .get_request,
        .request_id = 42,
        .varbinds = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.1.1.0"), .value = .null },
        },
    });
    for (0..full.len) |n| {
        try testing.expect(std.meta.isError(decode(full[0..n])));
    }

    // Bit-flip sweep over the same message.
    var mut: [128]u8 = undefined;
    for (0..full.len) |byte_i| {
        @memcpy(mut[0..full.len], full);
        mut[byte_i] ^= 0xff;
        if (decode(mut[0..full.len])) |msg| {
            switch (msg.pdu) {
                inline else => |p| {
                    var it = p.varbinds.iterator();
                    while (it.next() catch null) |_| {}
                },
            }
        } else |_| {}
    }
}
