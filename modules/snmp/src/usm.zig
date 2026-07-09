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

// ── T-F: authentication — key localization + HMAC-*-96 (RFC 3414 §2.6/§6/§7) ──

const hash = std.crypto.hash;
const hmac = std.crypto.auth.hmac;

/// USM authentication protocols (RFC 3414). Classic HMAC-*-96 only; the RFC 7860
/// SHA-2 variants are a later addition.
pub const AuthProtocol = enum {
    /// usmHMACMD5AuthProtocol (RFC 3414 §6) — HMAC-MD5-96, 16-byte key.
    hmac_md5,
    /// usmHMACSHAAuthProtocol (RFC 3414 §7) — HMAC-SHA-1-96, 20-byte key.
    hmac_sha1,

    /// The localized-key length in bytes (= the hash's digest length).
    pub fn keyLen(self: AuthProtocol) usize {
        return switch (self) {
            .hmac_md5 => 16,
            .hmac_sha1 => 20,
        };
    }
};

/// The truncated HMAC length carried in `msgAuthenticationParameters`
/// (HMAC-*-96 → 12 bytes; RFC 3414 §6.3.1/§7.3.1).
pub const digest_len = 12;

/// Longest localized key across the protocols (SHA-1 = 20).
pub const max_key_len = 20;

pub const AuthError = error{
    /// The computed digest did not match the message's (constant-time compared).
    AuthenticationFailed,
    /// `msgAuthenticationParameters` was not the expected `digest_len`, or does
    /// not lie within `message` (so its offset can't be located).
    BadAuthParams,
};

/// Errors from the password->key derivation (RFC 3414 §2.6 / Appendix A.2).
pub const KeyDerivationError = error{
    /// `password` was empty — the cyclic expansion divides by `password.len`,
    /// so an empty password has no well-defined key and is rejected rather
    /// than dividing by zero.
    EmptyPassword,
};

/// Derive the user key `Ku` from a password (RFC 3414 §2.6 / Appendix A.2): the
/// password bytes are cycled to fill exactly 2^20 (1048576) octets, hashed once
/// with the protocol's digest. Writes `proto.keyLen()` bytes into `out` (which
/// must be at least that long) and returns that prefix. `password` must be
/// non-empty — `error.EmptyPassword` otherwise (never a division-by-zero
/// panic).
pub fn passwordToUserKey(proto: AuthProtocol, password: []const u8, out: []u8) KeyDerivationError![]u8 {
    return switch (proto) {
        .hmac_md5 => pwToUk(hash.Md5, password, out),
        .hmac_sha1 => pwToUk(hash.Sha1, password, out),
    };
}

fn pwToUk(comptime Hash: type, password: []const u8, out: []u8) KeyDerivationError![]u8 {
    if (password.len == 0) return error.EmptyPassword;
    // RFC 3414 Appendix A.2: cycle the password to fill exactly 2^20 octets,
    // digested in 64-byte blocks.
    var h = Hash.init(.{});
    var buf: [64]u8 = undefined;
    var idx: usize = 0;
    var count: usize = 0;
    while (count < 1048576) : (count += 64) {
        for (&buf) |*b| {
            b.* = password[idx % password.len];
            idx += 1;
        }
        h.update(&buf);
    }
    var d: [Hash.digest_length]u8 = undefined;
    h.final(&d);
    @memcpy(out[0..Hash.digest_length], &d);
    return out[0..Hash.digest_length];
}

/// Localize a user key `Ku` to an authoritative engine (RFC 3414 §2.6):
/// `Kul = H(Ku ++ engineID ++ Ku)`. `user_key` must be `proto.keyLen()` bytes;
/// writes `proto.keyLen()` bytes into `out` and returns that prefix.
pub fn localizeKey(proto: AuthProtocol, user_key: []const u8, engine_id: []const u8, out: []u8) []u8 {
    return switch (proto) {
        .hmac_md5 => localizeT(hash.Md5, user_key, engine_id, out),
        .hmac_sha1 => localizeT(hash.Sha1, user_key, engine_id, out),
    };
}

fn localizeT(comptime Hash: type, user_key: []const u8, engine_id: []const u8, out: []u8) []u8 {
    // RFC 3414 §2.6: Kul = H(Ku ++ engineID ++ Ku).
    var h = Hash.init(.{});
    h.update(user_key);
    h.update(engine_id);
    h.update(user_key);
    var d: [Hash.digest_length]u8 = undefined;
    h.final(&d);
    @memcpy(out[0..Hash.digest_length], &d);
    return out[0..Hash.digest_length];
}

/// Convenience: `localizeKey(proto, passwordToUserKey(...), engineID)` — the
/// full password→localized-key path. `out` must be ≥ `proto.keyLen()`.
/// `error.EmptyPassword` propagates from `passwordToUserKey` for an empty
/// password.
pub fn passwordToKey(proto: AuthProtocol, password: []const u8, engine_id: []const u8, out: []u8) KeyDerivationError![]u8 {
    var uk_buf: [max_key_len]u8 = undefined;
    const uk = try passwordToUserKey(proto, password, &uk_buf);
    return localizeKey(proto, uk, engine_id, out);
}

/// Compute the 12-byte HMAC-*-96 auth digest over `message`, treating the
/// `digest_len` bytes at `auth_offset` as zero (RFC 3414 §6.3.1/§7.3.1: the
/// digest is computed over the whole message with `msgAuthenticationParameters`
/// zero-filled). Streams the three regions — no copy, no mutation of `message`.
pub fn computeDigest(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []const u8,
    auth_offset: usize,
    out: *[digest_len]u8,
) void {
    switch (proto) {
        .hmac_md5 => digestT(hmac.Hmac(hash.Md5), localized_key, message, auth_offset, out),
        .hmac_sha1 => digestT(hmac.Hmac(hash.Sha1), localized_key, message, auth_offset, out),
    }
}

fn digestT(
    comptime Hmac: type,
    key: []const u8,
    message: []const u8,
    auth_offset: usize,
    out: *[digest_len]u8,
) void {
    // HMAC over message with [auth_offset..+digest_len] treated as zero,
    // then truncate to the first digest_len bytes (HMAC-*-96).
    var m = Hmac.init(key);
    m.update(message[0..auth_offset]);
    m.update(&[_]u8{0} ** digest_len);
    m.update(message[auth_offset + digest_len ..]);
    var full: [Hmac.mac_length]u8 = undefined;
    m.final(&full);
    @memcpy(out, full[0..digest_len]);
}

/// The byte offset of `params.auth_params` within `message` — valid only when
/// `params` was parsed from `message` and `auth_params` is exactly `digest_len`
/// bytes lying inside `message`. Null otherwise (so the caller reports
/// `BadAuthParams`). Uses pointer identity; do not pass a `params` parsed from a
/// different buffer.
pub fn authOffset(message: []const u8, params: UsmSecurityParameters) ?usize {
    if (params.auth_params.len != digest_len) return null;
    const base = @intFromPtr(message.ptr);
    const ap = @intFromPtr(params.auth_params.ptr);
    if (ap < base or ap + digest_len > base + message.len) return null;
    return ap - base;
}

/// Verify a received authenticated v3 `message` (RFC 3414 §6.3.2/§7.3.2):
/// recompute the digest over the message with the auth field zeroed and compare
/// it to `params.auth_params` in **constant time**. `localized_key` is the
/// engine-localized key for the message's user. `error.AuthenticationFailed` on
/// mismatch, `error.BadAuthParams` when the digest field is malformed / not in
/// `message`.
pub fn verify(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []const u8,
    params: UsmSecurityParameters,
) AuthError!void {
    const off = authOffset(message, params) orelse return error.BadAuthParams;
    var expected: [digest_len]u8 = undefined;
    computeDigest(proto, localized_key, message, off, &expected);
    // CONSTANT-TIME compare (never std.mem.eql on a MAC).
    const got: [digest_len]u8 = params.auth_params[0..digest_len].*;
    if (!std.crypto.timing_safe.eql([digest_len]u8, expected, got))
        return error.AuthenticationFailed;
}

/// Sign an outgoing v3 `message` in place (RFC 3414 §6.3.1/§7.3.1): compute the
/// digest over the message (with the auth field currently zero-filled) and write
/// it into `message[auth_offset..][0..digest_len]`. The caller must have
/// serialized the message with a `digest_len`-byte zero placeholder for
/// `msgAuthenticationParameters` at `auth_offset`.
pub fn sign(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []u8,
    auth_offset: usize,
) void {
    var d: [digest_len]u8 = undefined;
    computeDigest(proto, localized_key, message, auth_offset, &d);
    @memcpy(message[auth_offset..][0..digest_len], &d);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// T-F test checklist (add these below the existing T-E tests):
//  KEY DERIVATION — RFC 3414 Appendix A.3 known-answer vectors (password
//  "maplesyrup", engineID = 12 bytes 00 00 00 00 00 00 00 00 00 00 00 02):
//   - MD5 Ku  == 9f af 32 83 88 4e 92 83 4e bc 98 47 d8 ed d9 63
//   - MD5 Kul == 52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b
//   - SHA-1 Ku == 66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f
//     (SHA-1 Kul: assert passwordToKey == localizeKey(passwordToUserKey(...)) —
//      an internal-consistency check is fine; the MD5 KAT pins the algorithm.)
//   engineID bytes: &[_]u8{0,0,0,0,0,0,0,0,0,0,0,2}.
//  keyLen: hmac_md5 → 16, hmac_sha1 → 20.
//  SIGN/VERIFY round-trip (both protocols): build a v3 message (use
//  @import("v3.zig").encode) whose security_parameters is a usm.encode(...) blob
//  carrying a 12-ZERO auth_params placeholder; decode it, parse the usm params
//  (usm.parse over m.security_parameters), locate authOffset **within the whole
//  datagram**, sign(...) into a MUTABLE copy of the datagram, then verify(...)
//  succeeds; flip one message byte (or one key byte) → error.AuthenticationFailed.
//   NOTE: authOffset needs params.auth_params to point INTO the same buffer you
//   sign/verify — parse the usm params from a slice of the mutable datagram copy.
//  authOffset / BadAuthParams: a params whose auth_params.len != 12 → verify
//  returns error.BadAuthParams.
//  computeDigest determinism: same inputs → same 12 bytes; different auth_offset
//  region zeroing changes nothing if the zeroed bytes were already zero.

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

// ── T-F tests: key derivation + HMAC-*-96 sign/verify ───────────────────────

const v3 = @import("v3.zig");

/// RFC 3414 Appendix A.3 known-answer engine ID.
const rfc3414_engine_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

test "keyLen: hmac_md5 -> 16, hmac_sha1 -> 20" {
    try testing.expectEqual(@as(usize, 16), AuthProtocol.hmac_md5.keyLen());
    try testing.expectEqual(@as(usize, 20), AuthProtocol.hmac_sha1.keyLen());
}

test "RFC 3414 A.3.1 KAT: MD5 Ku from password 'maplesyrup'" {
    var buf: [max_key_len]u8 = undefined;
    const ku = try passwordToUserKey(.hmac_md5, "maplesyrup", &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x9f, 0xaf, 0x32, 0x83, 0x88, 0x4e, 0x92, 0x83,
        0x4e, 0xbc, 0x98, 0x47, 0xd8, 0xed, 0xd9, 0x63,
    }, ku);
}

test "RFC 3414 A.3.1 KAT: MD5 Kul localized to the example engine" {
    var buf: [max_key_len]u8 = undefined;
    const kul = try passwordToKey(.hmac_md5, "maplesyrup", &rfc3414_engine_id, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f,
        0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b,
    }, kul);
}

test "RFC 3414 A.3.2 KAT: SHA-1 Ku from password 'maplesyrup'" {
    var buf: [max_key_len]u8 = undefined;
    const ku = try passwordToUserKey(.hmac_sha1, "maplesyrup", &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x9f, 0xb5, 0xcc, 0x03, 0x81, 0x49, 0x7b, 0x37, 0x93, 0x52,
        0x89, 0x39, 0xff, 0x78, 0x8d, 0x5d, 0x79, 0x14, 0x52, 0x11,
    }, ku);
}

test "RFC 3414 A.3.2 KAT: SHA-1 Kul localized to the example engine" {
    var buf: [max_key_len]u8 = undefined;
    const kul = try passwordToKey(.hmac_sha1, "maplesyrup", &rfc3414_engine_id, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23,
        0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f,
    }, kul);
}

test "SHA-1: passwordToKey == localizeKey(passwordToUserKey(...))" {
    var uk_buf: [max_key_len]u8 = undefined;
    const uk = try passwordToUserKey(.hmac_sha1, "maplesyrup", &uk_buf);
    var kul_a_buf: [max_key_len]u8 = undefined;
    const kul_a = localizeKey(.hmac_sha1, uk, &rfc3414_engine_id, &kul_a_buf);
    var kul_b_buf: [max_key_len]u8 = undefined;
    const kul_b = try passwordToKey(.hmac_sha1, "maplesyrup", &rfc3414_engine_id, &kul_b_buf);
    try testing.expectEqual(@as(usize, 20), kul_a.len);
    try testing.expectEqualSlices(u8, kul_a, kul_b);
}

test "passwordToUserKey / passwordToKey reject an empty password (typed error, no div-by-zero panic)" {
    var buf: [max_key_len]u8 = undefined;
    try testing.expectError(error.EmptyPassword, passwordToUserKey(.hmac_md5, "", &buf));
    try testing.expectError(error.EmptyPassword, passwordToUserKey(.hmac_sha1, "", &buf));
    try testing.expectError(error.EmptyPassword, passwordToKey(.hmac_md5, "", &rfc3414_engine_id, &buf));
    try testing.expectError(error.EmptyPassword, passwordToKey(.hmac_sha1, "", &rfc3414_engine_id, &buf));
}

/// Build an authenticated v3 datagram (12-zero auth placeholder) in `msg_buf`,
/// then sign it in place and verify; tamper checks included.
fn expectSignVerifyRoundTrip(proto: AuthProtocol) !void {
    var key_buf: [max_key_len]u8 = undefined;
    const key = try passwordToKey(proto, "maplesyrup", &rfc3414_engine_id, &key_buf);

    // USM blob carrying a 12-zero msgAuthenticationParameters placeholder.
    var usm_buf: [128]u8 = undefined;
    const usm_wire = try encode(&usm_buf, .{
        .engine_id = &rfc3414_engine_id,
        .engine_boots = 1,
        .engine_time = 42,
        .user_name = "bert",
        .auth_params = &(.{0} ** digest_len),
        .priv_params = "",
    });

    var enc_buf: [256]u8 = undefined;
    const dg = try v3.encode(&enc_buf, .{
        .msg_id = 100,
        .flags = .{ .auth = true, .reportable = true },
        .security_parameters = usm_wire,
        .context_engine_id = &rfc3414_engine_id,
        .pdu = .{ .type = .trap_v2, .request_id = 7 },
    });

    // Mutable copy: auth_params must point INTO the buffer we sign/verify.
    var msg_buf: [256]u8 = undefined;
    @memcpy(msg_buf[0..dg.len], dg);
    const msg = msg_buf[0..dg.len];

    const m = try v3.decode(msg);
    const params = try parse(m.security_parameters);
    const off = authOffset(msg, params) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &(.{0} ** digest_len), params.auth_params);

    sign(proto, key, msg, off);
    try verify(proto, key, msg, params);

    // The written digest must be non-zero (a zero HMAC would be astronomical).
    var all_zero = true;
    for (params.auth_params) |b| {
        if (b != 0) all_zero = false;
    }
    try testing.expect(!all_zero);

    // Tamper with a message byte outside the auth field -> AuthenticationFailed.
    msg[msg.len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, verify(proto, key, msg, params));
    msg[msg.len - 1] ^= 0x01;
    try verify(proto, key, msg, params);

    // Tamper with a digest byte -> AuthenticationFailed.
    msg[off] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, verify(proto, key, msg, params));
    msg[off] ^= 0x01;
    try verify(proto, key, msg, params);

    // Wrong key -> AuthenticationFailed.
    key_buf[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, verify(proto, key, msg, params));
    key_buf[0] ^= 0x01;
}

test "sign/verify round-trip over a real v3 datagram: HMAC-MD5-96" {
    try expectSignVerifyRoundTrip(.hmac_md5);
}

test "sign/verify round-trip over a real v3 datagram: HMAC-SHA-1-96" {
    try expectSignVerifyRoundTrip(.hmac_sha1);
}

test "verify: non-12-byte auth_params -> BadAuthParams" {
    const msg = [_]u8{0} ** 32;
    const params: UsmSecurityParameters = .{
        .engine_id = "",
        .engine_boots = 0,
        .engine_time = 0,
        .user_name = "",
        .auth_params = msg[0..8], // wrong length
        .priv_params = "",
    };
    const key = [_]u8{0} ** 16;
    try testing.expectError(error.BadAuthParams, verify(.hmac_md5, &key, &msg, params));
}

test "authOffset: 12-byte auth_params from a DIFFERENT buffer -> null / BadAuthParams" {
    const msg = [_]u8{0xaa} ** 32;
    const elsewhere = [_]u8{0} ** digest_len;
    const params: UsmSecurityParameters = .{
        .engine_id = "",
        .engine_boots = 0,
        .engine_time = 0,
        .user_name = "",
        .auth_params = &elsewhere, // outside msg
        .priv_params = "",
    };
    try testing.expectEqual(@as(?usize, null), authOffset(&msg, params));
    const key = [_]u8{0} ** 16;
    try testing.expectError(error.BadAuthParams, verify(.hmac_md5, &key, &msg, params));
}

test "computeDigest: deterministic; equals plain HMAC when the region is already zero" {
    const key = [_]u8{0xaa} ** 16;
    var msg: [40]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i);
    @memset(msg[10 .. 10 + digest_len], 0); // auth region already zero

    var d1: [digest_len]u8 = undefined;
    var d2: [digest_len]u8 = undefined;
    computeDigest(.hmac_md5, &key, &msg, 10, &d1);
    computeDigest(.hmac_md5, &key, &msg, 10, &d2);
    try testing.expectEqualSlices(u8, &d1, &d2);

    // Zero-filling an already-zero region changes nothing: the streamed digest
    // must equal a plain HMAC over the whole message.
    var full: [hmac.Hmac(hash.Md5).mac_length]u8 = undefined;
    hmac.Hmac(hash.Md5).create(&full, &msg, &key);
    try testing.expectEqualSlices(u8, full[0..digest_len], &d1);
}
