// SPDX-License-Identifier: MIT

//! USM — User-based Security Model (RFC 3414, extended by RFC 7860): the
//! `UsmSecurityParameters` (de)serializer plus key derivation/localization and
//! message authentication.
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
//! `parse`/`encode` handle that structure; `passwordToKey` / `localizeKey` /
//! `computeDigestInto` / `sign` / `verify` handle authentication. Using
//! `msgPrivacyParameters` to decrypt the scoped PDU is the `priv` layer, and
//! the engine-boots/time anti-replay window is `timewin`.
//! `msgAuthenticationParameters` is the field the digest zero-fills (to its
//! **final, protocol-specific** length) before hashing the whole message and
//! then overwrites, so `encode` here writes it exactly as given — callers must
//! pass a placeholder of `proto.digestLen()` zero bytes on the send path.

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
/// the send path supplies either a zero-filled placeholder (pre-HMAC) or the
/// final digest.
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

// ── authentication: key localization + HMAC (RFC 3414 §2.6/§6/§7, RFC 7860) ──

const hash = std.crypto.hash;
const hmac = std.crypto.auth.hmac;

/// USM authentication protocols: the classic HMAC-*-96 pair of RFC 3414 plus
/// the SHA-2 family of RFC 7860. Every member shares the same password→key
/// derivation (RFC 3414 §A.2 with the protocol's hash substituted, restated by
/// RFC 7860 §11.2) and the same "HMAC over the whole message with
/// msgAuthenticationParameters zero-filled" rule; they differ in the hash, the
/// localized-key length (= digest length of that hash) and — crucially — the
/// **truncation length** written into `msgAuthenticationParameters`.
pub const AuthProtocol = enum {
    /// usmHMACMD5AuthProtocol (RFC 3414 §6) — HMAC-MD5-96, 16-byte key,
    /// 12-byte digest.
    hmac_md5,
    /// usmHMACSHAAuthProtocol (RFC 3414 §7) — HMAC-SHA-1-96, 20-byte key,
    /// 12-byte digest.
    hmac_sha1,
    /// usmHMAC128SHA224AuthProtocol (RFC 7860 §4) — 28-byte key, 16-byte
    /// (128-bit) digest.
    hmac_sha224,
    /// usmHMAC192SHA256AuthProtocol (RFC 7860 §4) — 32-byte key, 24-byte
    /// (192-bit) digest.
    hmac_sha256,
    /// usmHMAC256SHA384AuthProtocol (RFC 7860 §4) — 48-byte key, 32-byte
    /// (256-bit) digest.
    hmac_sha384,
    /// usmHMAC384SHA512AuthProtocol (RFC 7860 §4) — 64-byte key, 48-byte
    /// (384-bit) digest.
    hmac_sha512,

    /// The localized-key length in bytes (= the hash's digest length).
    pub fn keyLen(self: AuthProtocol) usize {
        return switch (self) {
            .hmac_md5 => 16,
            .hmac_sha1 => 20,
            .hmac_sha224 => 28,
            .hmac_sha256 => 32,
            .hmac_sha384 => 48,
            .hmac_sha512 => 64,
        };
    }

    /// The length of `msgAuthenticationParameters` on the wire — the HMAC
    /// truncation length. RFC 3414 §6.3.1/§7.3.1 fix 12 for MD5/SHA-1; RFC 7860
    /// §4.2.1 gives 16/24/32/48 for SHA-224/256/384/512. Getting this wrong is
    /// the classic RFC 7860 implementation bug (reusing 12 everywhere).
    pub fn digestLen(self: AuthProtocol) usize {
        return switch (self) {
            .hmac_md5, .hmac_sha1 => 12,
            .hmac_sha224 => 16,
            .hmac_sha256 => 24,
            .hmac_sha384 => 32,
            .hmac_sha512 => 48,
        };
    }

    /// The `usmHMAC*AuthProtocol` OID (RFC 3414 §6/§7 under snmpAuthProtocols
    /// 1.3.6.1.6.3.10.1.1, RFC 7860 §8) — useful when writing a usmUserTable
    /// row or matching an agent's advertised protocol.
    pub fn oidArc(self: AuthProtocol) u32 {
        return switch (self) {
            .hmac_md5 => 2, // usmHMACMD5AuthProtocol
            .hmac_sha1 => 3, // usmHMACSHAAuthProtocol
            .hmac_sha224 => 4, // usmHMAC128SHA224AuthProtocol
            .hmac_sha256 => 5, // usmHMAC192SHA256AuthProtocol
            .hmac_sha384 => 6, // usmHMAC256SHA384AuthProtocol
            .hmac_sha512 => 7, // usmHMAC384SHA512AuthProtocol
        };
    }
};

/// The truncated HMAC length of the two **HMAC-*-96** protocols (RFC 3414
/// §6.3.1/§7.3.1). Kept for the original MD5/SHA-1 API surface; for anything
/// protocol-generic use `AuthProtocol.digestLen()` — the RFC 7860 protocols do
/// **not** truncate to 12.
pub const digest_len = 12;

/// Longest `msgAuthenticationParameters` across all protocols (SHA-512 → 48).
pub const max_digest_len = 48;

/// Longest localized key across all protocols (SHA-512 → 64).
pub const max_key_len = 64;

pub const AuthError = error{
    /// The computed digest did not match the message's (constant-time compared).
    AuthenticationFailed,
    /// `msgAuthenticationParameters` was not the protocol's `digestLen()`, or
    /// does not lie within `message` (so its offset can't be located).
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
        .hmac_sha224 => pwToUk(hash.sha2.Sha224, password, out),
        .hmac_sha256 => pwToUk(hash.sha2.Sha256, password, out),
        .hmac_sha384 => pwToUk(hash.sha2.Sha384, password, out),
        .hmac_sha512 => pwToUk(hash.sha2.Sha512, password, out),
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
        .hmac_sha224 => localizeT(hash.sha2.Sha224, user_key, engine_id, out),
        .hmac_sha256 => localizeT(hash.sha2.Sha256, user_key, engine_id, out),
        .hmac_sha384 => localizeT(hash.sha2.Sha384, user_key, engine_id, out),
        .hmac_sha512 => localizeT(hash.sha2.Sha512, user_key, engine_id, out),
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

/// Compute the auth digest over `message`, treating the `proto.digestLen()`
/// bytes at `auth_offset` as zero (RFC 3414 §6.3.1/§7.3.1, RFC 7860 §4.2.1: the
/// digest is computed over the whole message with `msgAuthenticationParameters`
/// zero-filled), and write the truncated result into `out`. Returns the
/// `proto.digestLen()`-byte prefix of `out`; `out` must be at least that long
/// (`max_digest_len` always suffices). Streams the three regions — no copy, no
/// mutation of `message`.
///
/// This is the protocol-generic entry point. `computeDigest` is the fixed
/// 12-byte HMAC-*-96 form kept for the original MD5/SHA-1 API.
pub fn computeDigestInto(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []const u8,
    auth_offset: usize,
    out: []u8,
) []u8 {
    const n = proto.digestLen();
    std.debug.assert(out.len >= n);
    switch (proto) {
        .hmac_md5 => digestT(hmac.Hmac(hash.Md5), localized_key, message, auth_offset, n, out),
        .hmac_sha1 => digestT(hmac.Hmac(hash.Sha1), localized_key, message, auth_offset, n, out),
        .hmac_sha224 => digestT(hmac.Hmac(hash.sha2.Sha224), localized_key, message, auth_offset, n, out),
        .hmac_sha256 => digestT(hmac.Hmac(hash.sha2.Sha256), localized_key, message, auth_offset, n, out),
        .hmac_sha384 => digestT(hmac.Hmac(hash.sha2.Sha384), localized_key, message, auth_offset, n, out),
        .hmac_sha512 => digestT(hmac.Hmac(hash.sha2.Sha512), localized_key, message, auth_offset, n, out),
    }
    return out[0..n];
}

/// Compute the 12-byte HMAC-*-96 auth digest over `message` — the RFC 3414
/// MD5/SHA-1 form. Only valid for protocols whose `digestLen()` is 12
/// (`hmac_md5`, `hmac_sha1`); passing an RFC 7860 protocol is a programming
/// error (asserted), because silently truncating SHA-2 to 12 bytes would
/// produce a wrong-but-plausible digest. Use `computeDigestInto` instead.
pub fn computeDigest(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []const u8,
    auth_offset: usize,
    out: *[digest_len]u8,
) void {
    std.debug.assert(proto.digestLen() == digest_len);
    _ = computeDigestInto(proto, localized_key, message, auth_offset, out);
}

fn digestT(
    comptime Hmac: type,
    key: []const u8,
    message: []const u8,
    auth_offset: usize,
    trunc: usize,
    out: []u8,
) void {
    // HMAC over message with [auth_offset..+trunc] treated as zero, then
    // truncated to the protocol's first `trunc` bytes.
    var m = Hmac.init(key);
    m.update(message[0..auth_offset]);
    const zeros = [_]u8{0} ** max_digest_len;
    m.update(zeros[0..trunc]);
    m.update(message[auth_offset + trunc ..]);
    var full: [Hmac.mac_length]u8 = undefined;
    m.final(&full);
    @memcpy(out[0..trunc], full[0..trunc]);
}

/// The byte offset of `params.auth_params` within `message` for `proto` — valid
/// only when `params` was parsed from `message` and `auth_params` is exactly
/// `proto.digestLen()` bytes lying inside `message`. Null otherwise (so the
/// caller reports `BadAuthParams`). Uses pointer identity; do not pass a
/// `params` parsed from a different buffer.
pub fn authOffsetFor(proto: AuthProtocol, message: []const u8, params: UsmSecurityParameters) ?usize {
    const n = proto.digestLen();
    if (params.auth_params.len != n) return null;
    const base = @intFromPtr(message.ptr);
    const ap = @intFromPtr(params.auth_params.ptr);
    if (ap < base or ap + n > base + message.len) return null;
    return ap - base;
}

/// `authOffsetFor` fixed to the 12-byte HMAC-*-96 field length (RFC 3414).
/// Kept for the original MD5/SHA-1 API; use `authOffsetFor` when the protocol
/// may be one of the RFC 7860 SHA-2 members.
pub fn authOffset(message: []const u8, params: UsmSecurityParameters) ?usize {
    return authOffsetFor(.hmac_md5, message, params);
}

/// Verify a received authenticated v3 `message` (RFC 3414 §6.3.2/§7.3.2, RFC
/// 7860 §4.2.2): recompute the digest over the message with the auth field
/// zeroed and compare it to `params.auth_params` in **constant time**.
/// `localized_key` is the engine-localized key for the message's user.
/// `error.AuthenticationFailed` on mismatch, `error.BadAuthParams` when the
/// digest field is not exactly `proto.digestLen()` bytes or does not lie inside
/// `message`.
pub fn verify(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []const u8,
    params: UsmSecurityParameters,
) AuthError!void {
    const off = authOffsetFor(proto, message, params) orelse return error.BadAuthParams;
    var expected_buf: [max_digest_len]u8 = undefined;
    const expected = computeDigestInto(proto, localized_key, message, off, &expected_buf);
    // CONSTANT-TIME compare (never std.mem.eql on a MAC). timing_safe.eql wants
    // a fixed-size array type, so dispatch on the protocol's truncation length.
    const got = params.auth_params;
    const ok = switch (proto.digestLen()) {
        12 => std.crypto.timing_safe.eql([12]u8, expected[0..12].*, got[0..12].*),
        16 => std.crypto.timing_safe.eql([16]u8, expected[0..16].*, got[0..16].*),
        24 => std.crypto.timing_safe.eql([24]u8, expected[0..24].*, got[0..24].*),
        32 => std.crypto.timing_safe.eql([32]u8, expected[0..32].*, got[0..32].*),
        48 => std.crypto.timing_safe.eql([48]u8, expected[0..48].*, got[0..48].*),
        else => unreachable, // digestLen() is closed over the enum
    };
    if (!ok) return error.AuthenticationFailed;
}

/// Sign an outgoing v3 `message` in place (RFC 3414 §6.3.1/§7.3.1, RFC 7860
/// §4.2.1): compute the digest over the message (with the auth field currently
/// zero-filled) and write it into `message[auth_offset..][0..proto.digestLen()]`.
/// The caller must have serialized the message with a `proto.digestLen()`-byte
/// zero placeholder for `msgAuthenticationParameters` at `auth_offset`.
pub fn sign(
    proto: AuthProtocol,
    localized_key: []const u8,
    message: []u8,
    auth_offset: usize,
) void {
    var buf: [max_digest_len]u8 = undefined;
    const d = computeDigestInto(proto, localized_key, message, auth_offset, &buf);
    @memcpy(message[auth_offset..][0..d.len], d);
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

// ── tests: key derivation + sign/verify ──────────────────────────────────────

const v3 = @import("v3.zig");

/// RFC 3414 Appendix A.3 known-answer engine ID.
const rfc3414_engine_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

test "keyLen: hmac_md5 -> 16, hmac_sha1 -> 20" {
    try testing.expectEqual(@as(usize, 16), AuthProtocol.hmac_md5.keyLen());
    try testing.expectEqual(@as(usize, 20), AuthProtocol.hmac_sha1.keyLen());
}

test "RFC 7860 §4.2.1: key and digest lengths per protocol" {
    // {protocol, localized-key length, msgAuthenticationParameters length}.
    const table = [_]struct { AuthProtocol, usize, usize }{
        .{ .hmac_md5, 16, 12 }, // RFC 3414 §6
        .{ .hmac_sha1, 20, 12 }, // RFC 3414 §7
        .{ .hmac_sha224, 28, 16 }, // usmHMAC128SHA224AuthProtocol
        .{ .hmac_sha256, 32, 24 }, // usmHMAC192SHA256AuthProtocol
        .{ .hmac_sha384, 48, 32 }, // usmHMAC256SHA384AuthProtocol
        .{ .hmac_sha512, 64, 48 }, // usmHMAC384SHA512AuthProtocol
    };
    for (table) |row| {
        try testing.expectEqual(row[1], row[0].keyLen());
        try testing.expectEqual(row[2], row[0].digestLen());
        try testing.expect(row[1] <= max_key_len);
        try testing.expect(row[2] <= max_digest_len);
    }
    // The snmpAuthProtocols arcs are distinct and match RFC 3414 §6/§7 + 7860 §8.
    var seen = [_]bool{false} ** 8;
    for (table) |row| {
        const arc = row[0].oidArc();
        try testing.expect(!seen[arc]);
        seen[arc] = true;
    }
    try testing.expectEqual(@as(u32, 2), AuthProtocol.hmac_md5.oidArc());
    try testing.expectEqual(@as(u32, 7), AuthProtocol.hmac_sha512.oidArc());
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

    // USM blob carrying a zero-filled msgAuthenticationParameters placeholder
    // of exactly the protocol's truncation length.
    const zeros = [_]u8{0} ** max_digest_len;
    const dlen = proto.digestLen();
    var usm_buf: [160]u8 = undefined;
    const usm_wire = try encode(&usm_buf, .{
        .engine_id = &rfc3414_engine_id,
        .engine_boots = 1,
        .engine_time = 42,
        .user_name = "bert",
        .auth_params = zeros[0..dlen],
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
    const off = authOffsetFor(proto, msg, params) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, zeros[0..dlen], params.auth_params);

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

test "sign/verify round-trip over a real v3 datagram: all RFC 7860 SHA-2 protocols" {
    for ([_]AuthProtocol{ .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 }) |p| {
        try expectSignVerifyRoundTrip(p);
    }
}

/// The engine ID used by the local net-snmp `snmpd` the goldens were captured
/// from: `80 00 1F 88 04` (RFC 3411 enterprise 8072, text format) + the literal
/// text "rfc3414-example". Synthetic — nothing from a real device.
pub const netsnmp_engine_id = [_]u8{ 0x80, 0x00, 0x1f, 0x88, 0x04 } ++ "rfc3414-example".*;

test "cross-implementation KAT: localized keys match net-snmp for all six protocols" {
    // Password "maplesyrup" (the RFC 3414 A.3 example password) localized to
    // `netsnmp_engine_id`. Expected values read out of net-snmp 5.9.4's own
    // persistent `usmUser` rows (`createUser <name> <proto> "maplesyrup"`), and
    // independently recomputed from the RFC 3414 §A.2 formula. For MD5/SHA-1
    // the RFC 3414 A.3 vectors above already pin the algorithm; these extend the
    // same pinning to the RFC 7860 SHA-2 members, which the RFC itself
    // publishes no vectors for.
    const cases = [_]struct { AuthProtocol, []const u8 }{
        .{ .hmac_md5, &[_]u8{
            0x4b, 0x62, 0xb6, 0x04, 0xdb, 0x88, 0xd6, 0xf5,
            0xbd, 0xe5, 0xdc, 0xab, 0xb3, 0xba, 0xd1, 0x36,
        } },
        .{ .hmac_sha1, &[_]u8{
            0x87, 0x51, 0xd2, 0x57, 0x3e, 0xd7, 0x9b, 0xaa, 0x96, 0xcd,
            0xc3, 0x5f, 0x59, 0x78, 0x4d, 0x41, 0xf3, 0x0b, 0xa4, 0xc0,
        } },
        .{ .hmac_sha224, &[_]u8{
            0x16, 0xda, 0x9b, 0x15, 0xef, 0x71, 0x9b, 0xbf, 0xbc, 0x4a,
            0xd0, 0x14, 0x6b, 0x5b, 0x86, 0x41, 0xa9, 0x1a, 0x47, 0xa4,
            0x25, 0xbd, 0x83, 0xff, 0xb6, 0xa5, 0x00, 0x85,
        } },
        .{ .hmac_sha256, &[_]u8{
            0xdb, 0x1d, 0xd5, 0x0d, 0xcc, 0xca, 0xf3, 0xd0, 0x2d, 0x36, 0xa0,
            0x39, 0x18, 0xfd, 0x2d, 0x91, 0xa1, 0x02, 0x4a, 0x23, 0x42, 0x4d,
            0x2e, 0x6f, 0x45, 0x25, 0x3a, 0x9d, 0x79, 0x61, 0x9a, 0x57,
        } },
        .{ .hmac_sha384, &[_]u8{
            0x06, 0x85, 0xe6, 0x9d, 0x64, 0x75, 0xd6, 0x02, 0xa1, 0x47, 0xad, 0x05,
            0xb3, 0xea, 0x94, 0x09, 0x89, 0xeb, 0xe4, 0xe0, 0x11, 0x4e, 0xe8, 0xd8,
            0xc1, 0x34, 0x6e, 0xdd, 0x64, 0x5a, 0xce, 0x9e, 0xa0, 0xbc, 0x4e, 0x69,
            0xac, 0x1a, 0x82, 0xba, 0xb9, 0xa9, 0x2c, 0x3f, 0xc6, 0xca, 0x53, 0xdb,
        } },
        .{ .hmac_sha512, &[_]u8{
            0x8b, 0xda, 0x63, 0x80, 0x49, 0xec, 0x88, 0x2a, 0x5e, 0xf3, 0xe5, 0x87,
            0x0f, 0x08, 0x84, 0xc8, 0x4f, 0x32, 0x3f, 0xde, 0x53, 0x4c, 0x50, 0xf5,
            0xc7, 0x29, 0x2d, 0x3f, 0x73, 0xbc, 0x26, 0x24, 0x21, 0x8b, 0x27, 0x4f,
            0x03, 0x9e, 0x05, 0xfb, 0x59, 0x40, 0xca, 0x63, 0xcc, 0xaf, 0xb1, 0xea,
            0x6c, 0x3a, 0x53, 0xe0, 0x8b, 0x36, 0xec, 0xc6, 0x9c, 0x2d, 0x6d, 0x45,
            0xfa, 0x28, 0x0a, 0x46,
        } },
    };
    for (cases) |c| {
        var buf: [max_key_len]u8 = undefined;
        const kul = try passwordToKey(c[0], "maplesyrup", &netsnmp_engine_id, &buf);
        try testing.expectEqual(c[0].keyLen(), kul.len);
        try testing.expectEqualSlices(u8, c[1], kul);
    }
}

test "verify: an auth field of the WRONG protocol length -> BadAuthParams" {
    // A 12-byte HMAC-*-96 field presented to an RFC 7860 protocol (and vice
    // versa) must be rejected, not silently truncated-compared.
    const msg = [_]u8{0xab} ** 96;
    const key = [_]u8{0x11} ** max_key_len;
    inline for (.{
        .{ AuthProtocol.hmac_sha256, 12 },
        .{ AuthProtocol.hmac_sha256, 32 },
        .{ AuthProtocol.hmac_sha512, 12 },
        .{ AuthProtocol.hmac_md5, 24 },
        .{ AuthProtocol.hmac_sha224, 0 },
    }) |case| {
        const params: UsmSecurityParameters = .{
            .engine_id = "",
            .engine_boots = 0,
            .engine_time = 0,
            .user_name = "",
            .auth_params = msg[0..case[1]],
            .priv_params = "",
        };
        try testing.expectError(error.BadAuthParams, verify(case[0], &key, &msg, params));
    }
}

test "computeDigestInto: truncation length is the protocol's, and is a real prefix" {
    // Zero-length auth region at offset 0 over a message that is all zeros in
    // that region: the streamed digest must equal a plain HMAC of the message,
    // truncated to digestLen().
    const key = [_]u8{0x5a} ** 32;
    var msg: [64]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i);
    @memset(msg[8..][0..24], 0); // sha256's 24-byte auth region, already zero

    var out: [max_digest_len]u8 = undefined;
    const d = computeDigestInto(.hmac_sha256, &key, &msg, 8, &out);
    try testing.expectEqual(@as(usize, 24), d.len);

    var full: [hmac.Hmac(hash.sha2.Sha256).mac_length]u8 = undefined;
    hmac.Hmac(hash.sha2.Sha256).create(&full, &msg, &key);
    try testing.expectEqualSlices(u8, full[0..24], d);
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

// ── fuzz: USM security-parameters decode, never panics ──────────────────────
//
// `parse` runs on the `msgSecurityParameters` OCTET STRING of an SNMPv3
// datagram *before* the HMAC in `auth_params` has been checked — i.e. on
// fully unauthenticated, attacker-controlled BER.

test "fuzz: parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = parse(buf[0..len]) catch return;
}
