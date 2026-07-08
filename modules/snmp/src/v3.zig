// SPDX-License-Identifier: MIT

//! SNMPv3 message framing (RFC 3412) — **T-D**: the message envelope +
//! ScopedPDU, at the `noAuthNoPriv` / plaintext level (no crypto).
//!
//! Wire form (RFC 3412 §6):
//! ```
//! SNMPv3Message ::= SEQUENCE {
//!     msgVersion            INTEGER (3),
//!     msgGlobalData         HeaderData,
//!     msgSecurityParameters OCTET STRING,   -- opaque; USM (RFC 3414) is T-E
//!     msgData               ScopedPduData
//! }
//! HeaderData ::= SEQUENCE {
//!     msgID INTEGER, msgMaxSize INTEGER, msgFlags OCTET STRING (SIZE(1)),
//!     msgSecurityModel INTEGER            -- USM = 3
//! }
//! ScopedPduData ::= CHOICE { plaintext ScopedPDU, encryptedPDU OCTET STRING }
//! ScopedPDU ::= SEQUENCE { contextEngineID OCTET STRING,
//!                          contextName OCTET STRING, data <PDU> }
//! ```
//!
//! This layer captures `msgSecurityParameters` as an opaque slice (USM parse is
//! T-E, auth is T-F, privacy is T-G) and decodes the ScopedPDU's inner PDU with
//! the shared `message.decodePdu`. When the privacy flag is set the msgData is
//! an encrypted OCTET STRING, surfaced verbatim as `.encrypted` for T-G to
//! decrypt (then `decodeScopedPdu`). Encoding is the symmetric plaintext path.

const std = @import("std");
const ber = @import("ber.zig");
const message = @import("message.zig");

/// The USM security model number (RFC 3411) — the only model this stack targets.
pub const security_model_usm: u32 = 3;

/// SNMPv3 `msgFlags` (RFC 3412 §6.4): a one-octet bit set.
pub const MsgFlags = struct {
    /// authFlag (0x01): the message is authenticated (USM auth params present).
    auth: bool = false,
    /// privFlag (0x02): the scoped PDU is encrypted (msgData is encryptedPDU).
    priv: bool = false,
    /// reportableFlag (0x04): the sender wants a Report on error.
    reportable: bool = false,

    const auth_bit: u8 = 0x01;
    const priv_bit: u8 = 0x02;
    const reportable_bit: u8 = 0x04;

    pub fn fromByte(b: u8) MsgFlags {
        return .{
            .auth = b & auth_bit != 0,
            .priv = b & priv_bit != 0,
            .reportable = b & reportable_bit != 0,
        };
    }

    pub fn toByte(self: MsgFlags) u8 {
        var b: u8 = 0;
        if (self.auth) b |= auth_bit;
        if (self.priv) b |= priv_bit;
        if (self.reportable) b |= reportable_bit;
        return b;
    }
};

/// The `msgGlobalData` header fields (RFC 3412 §6).
pub const HeaderData = struct {
    msg_id: i32,
    msg_max_size: i32,
    flags: MsgFlags,
    security_model: u32,
};

/// A decoded ScopedPDU (RFC 3412 §6.8): the context identity plus the inner PDU.
/// Slices borrow the source buffer.
pub const ScopedPdu = struct {
    context_engine_id: []const u8,
    context_name: []const u8,
    pdu: message.Pdu,
};

/// The msgData CHOICE: a plaintext ScopedPDU, or the still-encrypted ScopedPDU
/// bytes (privacy flag set) awaiting decryption (T-G) then `decodeScopedPdu`.
pub const ScopedData = union(enum) {
    plaintext: ScopedPdu,
    encrypted: []const u8,
};

/// A decoded SNMPv3 message. `security_parameters` is the opaque USM blob
/// (parse with the USM layer, T-E); all slices borrow the input datagram.
pub const V3Message = struct {
    header: HeaderData,
    security_parameters: []const u8,
    data: ScopedData,
};

pub const DecodeError = message.DecodeError || error{NotV3};

/// Decode an SNMPv3 message envelope. A non-v3 `msgVersion` is `error.NotV3`.
/// The ScopedPDU is fully parsed when plaintext (privacy clear); when the
/// privacy flag / an encryptedPDU OCTET STRING is present, its bytes are
/// returned as `.encrypted` (decrypt in T-G). Malformed bytes stay typed BER
/// errors — never a panic.
pub fn decode(bytes: []const u8) DecodeError!V3Message {
    var top = ber.Decoder.init(bytes);
    const msg_content = try top.expect(ber.tag.sequence);
    if (!top.done()) return error.TrailingData;

    var m = ber.Decoder.init(msg_content);
    if (try ber.parseInteger(try m.expect(ber.tag.integer)) != 3) return error.NotV3;

    const header = try decodeHeader(try m.expect(ber.tag.sequence));
    const security_parameters = try m.expect(ber.tag.octet_string);

    const data_tlv = try m.any();
    if (!m.done()) return error.TrailingData;

    const data: ScopedData = switch (data_tlv.tag) {
        ber.tag.sequence => .{ .plaintext = try decodeScopedPdu(data_tlv.content) },
        ber.tag.octet_string => .{ .encrypted = data_tlv.content },
        else => return error.UnexpectedTag,
    };
    return .{ .header = header, .security_parameters = security_parameters, .data = data };
}

fn decodeHeader(content: []const u8) DecodeError!HeaderData {
    var d = ber.Decoder.init(content);
    const msg_id = try ber.parseInteger(try d.expect(ber.tag.integer));
    const max_size = try ber.parseInteger(try d.expect(ber.tag.integer));
    const flags_os = try d.expect(ber.tag.octet_string);
    if (flags_os.len != 1) return error.InvalidValue;
    const security_model = try ber.parseInteger(try d.expect(ber.tag.integer));
    if (!d.done()) return error.TrailingData;
    return .{
        .msg_id = std.math.cast(i32, msg_id) orelse return error.IntegerTooLarge,
        .msg_max_size = std.math.cast(i32, max_size) orelse return error.IntegerTooLarge,
        .flags = MsgFlags.fromByte(flags_os[0]),
        .security_model = std.math.cast(u32, security_model) orelse return error.IntegerTooLarge,
    };
}

/// Decode a plaintext ScopedPDU (RFC 3412 §6.8): contextEngineID, contextName,
/// and the inner PDU. Public so the T-G privacy layer can call it on a decrypted
/// buffer.
pub fn decodeScopedPdu(content: []const u8) DecodeError!ScopedPdu {
    var d = ber.Decoder.init(content);
    const engine_id = try d.expect(ber.tag.octet_string);
    const context_name = try d.expect(ber.tag.octet_string);
    const pdu_tlv = try d.any();
    if (!d.done()) return error.TrailingData;
    return .{
        .context_engine_id = engine_id,
        .context_name = context_name,
        .pdu = try message.decodePdu(pdu_tlv),
    };
}

/// Parameters for `encode` — the plaintext (noAuthNoPriv / authNoPriv) path.
/// `security_parameters` is the caller-supplied opaque USM blob (build it with
/// the USM layer, T-E/F); it may be empty for framing tests. Encrypting the
/// ScopedPDU (privacy) is T-G.
pub const EncodeParams = struct {
    msg_id: i32,
    msg_max_size: i32 = 65507,
    flags: MsgFlags = .{},
    security_model: u32 = security_model_usm,
    security_parameters: []const u8 = &.{},
    context_engine_id: []const u8,
    context_name: []const u8 = &.{},
    pdu: message.EncodePdu,
};

/// Encode a plaintext SNMPv3 message into `buf` (written backwards; the encoded
/// slice, aligned to the end of `buf`, is returned).
pub fn encode(buf: []u8, params: EncodeParams) message.EncodeError![]const u8 {
    var e = ber.Encoder.init(buf);

    // msgData = plaintext ScopedPDU { contextEngineID, contextName, <PDU> }.
    const scoped_mark = e.len();
    try message.encodePdu(&e, params.pdu);
    try e.prependTlv(ber.tag.octet_string, params.context_name);
    try e.prependTlv(ber.tag.octet_string, params.context_engine_id);
    try e.wrap(ber.tag.sequence, scoped_mark);

    // msgSecurityParameters (opaque).
    try e.prependTlv(ber.tag.octet_string, params.security_parameters);

    // msgGlobalData / HeaderData (prepended in reverse wire order).
    const hdr_mark = e.len();
    try e.prependInteger(ber.tag.integer, params.security_model);
    try e.prependTlv(ber.tag.octet_string, &.{params.flags.toByte()});
    try e.prependInteger(ber.tag.integer, params.msg_max_size);
    try e.prependInteger(ber.tag.integer, params.msg_id);
    try e.wrap(ber.tag.sequence, hdr_mark);

    // msgVersion = 3, then the outer message SEQUENCE.
    try e.prependInteger(ber.tag.integer, 3);
    try e.wrap(ber.tag.sequence, 0);
    return e.encoded();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const Oid = @import("oid.zig").Oid;

test "MsgFlags round-trip across all 8 bit combinations" {
    var b: u8 = 0;
    while (b < 8) : (b += 1) {
        const f = MsgFlags.fromByte(b);
        try testing.expectEqual(b, f.toByte());
    }
    // Reserved high bits are ignored on decode.
    const f = MsgFlags.fromByte(0xff);
    try testing.expect(f.auth and f.priv and f.reportable);
}

fn sampleTrapVarbinds() ![2]message.VarBind {
    return .{
        .{ .name = try Oid.parse("1.3.6.1.2.1.1.3.0"), .value = .{ .time_ticks = 4242 } },
        .{ .name = try Oid.parse("1.3.6.1.6.3.1.1.4.1.0"), .value = .{ .oid = try Oid.parse("1.3.6.1.6.3.1.1.5.1") } },
    };
}

test "encode/decode round-trip: plaintext v3 with an inner SNMPv2-Trap" {
    const vbs = try sampleTrapVarbinds();
    var buf: [256]u8 = undefined;
    const dg = try encode(&buf, .{
        .msg_id = 123456,
        .flags = .{ .reportable = true },
        .security_parameters = "usm-blob",
        .context_engine_id = "\x80\x00\x1f\x88\x80",
        .context_name = "ctx",
        .pdu = .{ .type = .trap_v2, .request_id = 99, .varbinds = &vbs },
    });

    const m = try decode(dg);
    try testing.expectEqual(@as(i32, 123456), m.header.msg_id);
    try testing.expectEqual(@as(i32, 65507), m.header.msg_max_size);
    try testing.expect(!m.header.flags.auth and !m.header.flags.priv and m.header.flags.reportable);
    try testing.expectEqual(security_model_usm, m.header.security_model);
    try testing.expectEqualStrings("usm-blob", m.security_parameters);

    const scoped = m.data.plaintext;
    try testing.expectEqualStrings("\x80\x00\x1f\x88\x80", scoped.context_engine_id);
    try testing.expectEqualStrings("ctx", scoped.context_name);
    try testing.expectEqual(@as(i32, 99), scoped.pdu.trap_v2.request_id);
}

test "encode/decode round-trip: inner InformRequest, empty security params" {
    const vbs = try sampleTrapVarbinds();
    var buf: [256]u8 = undefined;
    const dg = try encode(&buf, .{
        .msg_id = 7,
        .context_engine_id = "eng",
        .pdu = .{ .type = .inform_request, .request_id = 4242, .varbinds = &vbs },
    });
    const m = try decode(dg);
    try testing.expectEqual(@as(usize, 0), m.security_parameters.len);
    try testing.expectEqualStrings("", m.data.plaintext.context_name);
    try testing.expectEqual(@as(i32, 4242), m.data.plaintext.pdu.inform_request.request_id);
}

test "decode: privacy flag / encryptedPDU is surfaced verbatim for T-G" {
    // Hand-assemble a v3 message whose msgData is an encryptedPDU OCTET STRING.
    var buf: [128]u8 = undefined;
    var e = ber.Encoder.init(&buf);
    const cipher = "\xde\xad\xbe\xef";
    try e.prependTlv(ber.tag.octet_string, cipher); // msgData = encryptedPDU
    try e.prependTlv(ber.tag.octet_string, "sp"); // msgSecurityParameters
    const hdr_mark = e.len();
    try e.prependInteger(ber.tag.integer, security_model_usm);
    try e.prependTlv(ber.tag.octet_string, &.{(MsgFlags{ .auth = true, .priv = true }).toByte()});
    try e.prependInteger(ber.tag.integer, 1500);
    try e.prependInteger(ber.tag.integer, 5);
    try e.wrap(ber.tag.sequence, hdr_mark);
    try e.prependInteger(ber.tag.integer, 3);
    try e.wrap(ber.tag.sequence, 0);

    const m = try decode(e.encoded());
    try testing.expect(m.header.flags.priv);
    try testing.expectEqualStrings(cipher, m.data.encrypted);
}

test "decode: a non-v3 message is NotV3" {
    var buf: [64]u8 = undefined;
    const v2 = try message.encode(&buf, .v2c, "public", .{ .type = .trap_v2, .request_id = 1 });
    try testing.expectError(error.NotV3, decode(v2));
}

test "decode: malformed / truncated bytes are typed errors, no panic" {
    try testing.expectError(error.Truncated, decode(&.{}));
    try testing.expectError(error.Truncated, decode(&.{ 0x30, 0x7f, 0x02 }));
}

test "decodeScopedPdu on a hand-built ScopedPDU SEQUENCE content" {
    // Build just a ScopedPDU: contextEngineID "E", contextName "N", inner
    // SNMPv2-Trap, then feed its SEQUENCE *content* to decodeScopedPdu.
    const vbs = try sampleTrapVarbinds();
    var buf: [256]u8 = undefined;
    var e = ber.Encoder.init(&buf);
    try message.encodePdu(&e, .{ .type = .trap_v2, .request_id = 55, .varbinds = &vbs });
    try e.prependTlv(ber.tag.octet_string, "N");
    try e.prependTlv(ber.tag.octet_string, "E");
    // e.encoded() is now the ScopedPDU's SEQUENCE content (unwrapped).
    const scoped = try decodeScopedPdu(e.encoded());
    try testing.expectEqualStrings("E", scoped.context_engine_id);
    try testing.expectEqualStrings("N", scoped.context_name);
    try testing.expectEqual(@as(i32, 55), scoped.pdu.trap_v2.request_id);
}
