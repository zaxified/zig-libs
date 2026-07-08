// SPDX-License-Identifier: MIT

//! USM — User-based Security Model (RFC 3414) — **T-E: the
//! `UsmSecurityParameters` (de)serializer**.
//!
//! An SNMPv3 message carries its security-model parameters in the opaque
//! `msgSecurityParameters` OCTET STRING (see `v3.V3Message.security_parameters`).
//! For USM that blob is itself a BER-encoded SEQUENCE (RFC 3414 §2.4):
//!
//! ```
//! UsmSecurityParameters ::= SEQUENCE {
//!     msgAuthoritativeEngineID     OCTET STRING,
//!     msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
//!     msgAuthoritativeEngineTime   INTEGER (0..2147483647),
//!     msgUserName                  OCTET STRING (SIZE(0..32)),
//!     msgAuthenticationParameters  OCTET STRING,  -- HMAC digest, or empty
//!     msgPrivacyParameters         OCTET STRING   -- privacy salt, or empty
//! }
//! ```
//!
//! This layer only (de)serializes that structure — it does NOT authenticate or
//! decrypt. Verifying `msgAuthenticationParameters` (HMAC + key localization) is
//! T-F; using `msgPrivacyParameters` to decrypt the scoped PDU is T-G; the
//! engine-boots/time anti-replay window is T-H. `msgAuthenticationParameters` is
//! the field T-F zero-fills before computing the HMAC over the whole message and
//! then overwrites, so `encode` here writes it exactly as given.

const std = @import("std");
const ber = @import("ber.zig");

pub const DecodeError = ber.DecodeError;

/// The parsed USM security parameters. All slices borrow the input buffer
/// (which must outlive this value); the integers are copied.
pub const UsmSecurityParameters = struct {
    /// msgAuthoritativeEngineID — the authoritative engine's SnmpEngineID
    /// (RFC 3411, SIZE 5..32 on the wire; not length-enforced here).
    engine_id: []const u8,
    /// msgAuthoritativeEngineBoots.
    engine_boots: u32,
    /// msgAuthoritativeEngineTime (seconds since the engine's last boot).
    engine_time: u32,
    /// msgUserName (SIZE 0..32).
    user_name: []const u8,
    /// msgAuthenticationParameters — the HMAC digest bytes (12 for the
    /// HMAC-*-96 auth protocols), or empty for noAuth.
    auth_params: []const u8,
    /// msgPrivacyParameters — the privacy salt (8 bytes for DES/AES), or empty
    /// for noPriv.
    priv_params: []const u8,
};

/// Parse the `UsmSecurityParameters` SEQUENCE from `bytes` (the content of the
/// message's `msgSecurityParameters` OCTET STRING, i.e. `v3`'s
/// `security_parameters` slice). Malformed input is a typed error, never a panic.
pub fn parse(bytes: []const u8) DecodeError!UsmSecurityParameters {
    var top = ber.Decoder.init(bytes);
    const seq = try top.expect(ber.tag.sequence);
    if (!top.done()) return error.TrailingData;

    var d = ber.Decoder.init(seq);
    const engine_id = try d.expect(ber.tag.octet_string);
    const eb = try ber.parseInteger(try d.expect(ber.tag.integer));
    const engine_boots = std.math.cast(u32, eb) orelse return error.IntegerTooLarge;
    const et = try ber.parseInteger(try d.expect(ber.tag.integer));
    const engine_time = std.math.cast(u32, et) orelse return error.IntegerTooLarge;
    const user_name = try d.expect(ber.tag.octet_string);
    const auth_params = try d.expect(ber.tag.octet_string);
    const priv_params = try d.expect(ber.tag.octet_string);
    if (!d.done()) return error.TrailingData;

    return .{
        .engine_id = engine_id,
        .engine_boots = engine_boots,
        .engine_time = engine_time,
        .user_name = user_name,
        .auth_params = auth_params,
        .priv_params = priv_params,
    };
}

/// Serialize `params` into `buf` as the `UsmSecurityParameters` SEQUENCE,
/// returning the encoded slice (the BER encoder writes backwards, so the slice
/// is aligned to the END of `buf`). The bytes are suitable to hand to
/// `v3.EncodeParams.security_parameters`. `auth_params` is written verbatim —
/// T-F supplies either a zero-filled placeholder (pre-HMAC) or the final digest.
pub fn encode(buf: []u8, params: UsmSecurityParameters) ber.EncodeError![]const u8 {
    var e = ber.Encoder.init(buf);
    try e.prependTlv(ber.tag.octet_string, params.priv_params);
    try e.prependTlv(ber.tag.octet_string, params.auth_params);
    try e.prependTlv(ber.tag.octet_string, params.user_name);
    try e.prependInteger(ber.tag.integer, params.engine_time);
    try e.prependInteger(ber.tag.integer, params.engine_boots);
    try e.prependTlv(ber.tag.octet_string, params.engine_id);
    try e.wrap(ber.tag.sequence, 0);
    return e.encoded();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectRoundTrip(params: UsmSecurityParameters) !void {
    var buf: [128]u8 = undefined;
    const wire = try encode(&buf, params);
    const back = try parse(wire);
    try testing.expectEqualStrings(params.engine_id, back.engine_id);
    try testing.expectEqual(params.engine_boots, back.engine_boots);
    try testing.expectEqual(params.engine_time, back.engine_time);
    try testing.expectEqualStrings(params.user_name, back.user_name);
    try testing.expectEqualStrings(params.auth_params, back.auth_params);
    try testing.expectEqualStrings(params.priv_params, back.priv_params);
}

test "encode/parse round-trip: authPriv" {
    try expectRoundTrip(.{
        .engine_id = "\x80\x00\x1f\x88\x04",
        .engine_boots = 3,
        .engine_time = 900,
        .user_name = "admin",
        .auth_params = &(.{0} ** 12),
        .priv_params = &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
    });
}

test "encode/parse round-trip: noAuthNoPriv empties" {
    var buf: [64]u8 = undefined;
    const wire = try encode(&buf, .{
        .engine_id = "\x80\x00\x1f\x88\x04",
        .engine_boots = 0,
        .engine_time = 0,
        .user_name = "",
        .auth_params = "",
        .priv_params = "",
    });
    const back = try parse(wire);
    try testing.expectEqual(@as(usize, 0), back.user_name.len);
    try testing.expectEqual(@as(usize, 0), back.auth_params.len);
    try testing.expectEqual(@as(usize, 0), back.priv_params.len);
    try testing.expectEqual(@as(u32, 0), back.engine_boots);
    try testing.expectEqual(@as(u32, 0), back.engine_time);
}

test "encode/parse round-trip: boots/time near u32 max" {
    try expectRoundTrip(.{
        .engine_id = "\x80\x00\x1f\x88\x04",
        .engine_boots = std.math.maxInt(u32),
        .engine_time = std.math.maxInt(u32) - 1,
        .user_name = "u",
        .auth_params = "",
        .priv_params = "",
    });
}

/// Hand-build a UsmSecurityParameters SEQUENCE with an arbitrary i64 for
/// msgAuthoritativeEngineBoots (encode() can't produce out-of-range values).
fn buildWithBoots(buf: []u8, boots: i64) ![]const u8 {
    var e = ber.Encoder.init(buf);
    try e.prependTlv(ber.tag.octet_string, ""); // priv
    try e.prependTlv(ber.tag.octet_string, ""); // auth
    try e.prependTlv(ber.tag.octet_string, "u"); // user
    try e.prependInteger(ber.tag.integer, 1); // time
    try e.prependInteger(ber.tag.integer, boots);
    try e.prependTlv(ber.tag.octet_string, "\x80\x00\x1f\x88\x04");
    try e.wrap(ber.tag.sequence, 0);
    return e.encoded();
}

test "parse rejects boots overflowing u32 -> IntegerTooLarge" {
    var buf: [64]u8 = undefined;
    // 0x1_0000_0000 encodes as a 5-byte INTEGER, one past u32 max.
    const wire = try buildWithBoots(&buf, 0x1_0000_0000);
    try testing.expectError(error.IntegerTooLarge, parse(wire));
}

test "parse rejects negative boots -> IntegerTooLarge" {
    var buf: [64]u8 = undefined;
    const wire = try buildWithBoots(&buf, -1);
    try testing.expectError(error.IntegerTooLarge, parse(wire));
}

test "parse of truncated / empty input is a typed error, never a panic" {
    try testing.expectError(error.Truncated, parse(&.{}));
    try testing.expectError(error.Truncated, parse(&.{0x30})); // tag, no length
    // SEQUENCE claiming more content than present.
    try testing.expectError(error.Truncated, parse(&.{ 0x30, 0x10, 0x04, 0x00 }));

    // A valid encoding cut short anywhere inside must also fail typed.
    var buf: [64]u8 = undefined;
    const wire = try encode(&buf, .{
        .engine_id = "\x80\x00\x1f\x88\x04",
        .engine_boots = 3,
        .engine_time = 900,
        .user_name = "admin",
        .auth_params = &(.{0} ** 12),
        .priv_params = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
    });
    try testing.expectError(error.Truncated, parse(wire[0 .. wire.len - 1]));
}

test "parse rejects a 7th element inside the SEQUENCE -> TrailingData" {
    var buf: [64]u8 = undefined;
    var e = ber.Encoder.init(&buf);
    try e.prependTlv(ber.tag.octet_string, "junk"); // stray 7th field
    try e.prependTlv(ber.tag.octet_string, ""); // priv
    try e.prependTlv(ber.tag.octet_string, ""); // auth
    try e.prependTlv(ber.tag.octet_string, "u"); // user
    try e.prependInteger(ber.tag.integer, 1); // time
    try e.prependInteger(ber.tag.integer, 1); // boots
    try e.prependTlv(ber.tag.octet_string, "\x80\x00\x1f\x88\x04");
    try e.wrap(ber.tag.sequence, 0);
    try testing.expectError(error.TrailingData, parse(e.encoded()));
}

test "parse rejects trailing junk after the SEQUENCE -> TrailingData" {
    var buf: [64]u8 = undefined;
    const wire = try encode(&buf, .{
        .engine_id = "\x80\x00\x1f\x88\x04",
        .engine_boots = 1,
        .engine_time = 1,
        .user_name = "u",
        .auth_params = "",
        .priv_params = "",
    });
    var padded: [65]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xaa;
    try testing.expectError(error.TrailingData, parse(padded[0 .. wire.len + 1]));
}
