// SPDX-License-Identifier: MIT

//! tlsserver.delegated — delegated credentials (RFC 9345), the server's
//! side: a short-lived key signed by the certificate's key, so the
//! certificate's key can stay offline (or with the CA's customer) while the
//! edge holds only a credential that expires within days.
//!
//! ```
//! struct {
//!     uint32 valid_time;                   // seconds after the leaf's notBefore
//!     SignatureScheme dc_cert_verify_algorithm;
//!     opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
//! } Credential;
//!
//! struct {
//!     Credential cred;
//!     SignatureScheme algorithm;           // the leaf key's signature over it
//!     opaque signature<1..2^16-1>;
//! } DelegatedCredential;
//! ```
//!
//! The signature covers 64 spaces, "TLS, server delegated credentials", a
//! zero octet, the leaf certificate's DER, `cred` and `algorithm` (§4). The
//! credential travels as the leaf's `delegated_credential` (34) extension in
//! the Certificate message; the CertificateVerify is then made with the
//! credential's key under `dc_cert_verify_algorithm`. A client offers it with
//! a `delegated_credential` extension listing the `dc_cert_verify_algorithm`s
//! it takes; `algorithm` must be among its `signature_algorithms`.

const std = @import("std");
const tls13 = @import("tls13");
const clientauth = @import("clientauth.zig");

const certverify = tls13.certverify;

pub const ext_delegated_credential: u16 = 34;

/// §4.1.3: a credential valid for more than 7 days is invalid.
pub const max_valid_time_s: u32 = 7 * 24 * 3600;

pub const context_string = "TLS, server delegated credentials";

/// DelegationUsage (§4.2), 1.3.6.1.4.1.44363.44, as the OID's DER TLV.
pub const delegation_usage_oid = [_]u8{ 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2c };

pub const Error = error{
    /// Not a well-formed DelegatedCredential.
    Malformed,
    /// `valid_time` over 7 days.
    ValidTooLong,
    /// The credential's scheme is not one a TLS 1.3 server's CertificateVerify
    /// may use under it: ECDSA or Ed25519 (BoringSSL refuses RSA ones).
    UnsupportedAlgorithm,
    /// The leaf's signature over the credential does not verify (or the
    /// leaf's key cannot be read).
    BadSignature,
};

pub const Credential = struct {
    valid_time: u32,
    /// `dc_cert_verify_algorithm`: the CertificateVerify's scheme.
    scheme: u16,
    /// The credential key's DER SubjectPublicKeyInfo.
    spki: []const u8,
    /// `Credential` as encoded (what the signature covers).
    cred: []const u8,
    /// The leaf key's scheme for `signature`.
    algorithm: u16,
    signature: []const u8,
};

/// One `DelegatedCredential`, exactly.
pub fn parse(raw: []const u8) Error!Credential {
    if (raw.len < 4 + 2 + 3) return error.Malformed;
    const valid_time = std.mem.readInt(u32, raw[0..4], .big);
    const scheme = std.mem.readInt(u16, raw[4..6], .big);
    const spki_len: usize = std.mem.readInt(u24, raw[6..9], .big);
    if (spki_len == 0 or raw.len - 9 < spki_len) return error.Malformed;
    const cred_end = 9 + spki_len;
    const rest = raw[cred_end..];
    if (rest.len < 2 + 2) return error.Malformed;
    const algorithm = std.mem.readInt(u16, rest[0..2], .big);
    const sig_len: usize = std.mem.readInt(u16, rest[2..4], .big);
    if (sig_len == 0 or rest.len != 4 + sig_len) return error.Malformed;
    return .{
        .valid_time = valid_time,
        .scheme = scheme,
        .spki = raw[9..cred_end],
        .cred = raw[0..cred_end],
        .algorithm = algorithm,
        .signature = rest[4..],
    };
}

/// The CertificateVerify schemes a credential may carry.
pub fn schemeAllowed(scheme: u16) bool {
    return switch (scheme) {
        0x0403, 0x0503, 0x0603, 0x0807 => true,
        else => false,
    };
}

/// §4: what the leaf key signs, into `out`.
pub fn signedMessage(out: []u8, leaf_der: []const u8, cred: []const u8, algorithm: u16) error{BufferTooSmall}![]u8 {
    const n = 64 + context_string.len + 1 + leaf_der.len + cred.len + 2;
    if (out.len < n) return error.BufferTooSmall;
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context_string.len], context_string);
    out[64 + context_string.len] = 0;
    var at: usize = 64 + context_string.len + 1;
    @memcpy(out[at..][0..leaf_der.len], leaf_der);
    at += leaf_der.len;
    @memcpy(out[at..][0..cred.len], cred);
    at += cred.len;
    std.mem.writeInt(u16, out[at..][0..2], algorithm, .big);
    return out[0..n];
}

/// The longest leaf `check` verifies a credential over.
pub const max_leaf_len = 16 * 1024;

/// The credential parses, its scheme is allowed, it lives at most 7 days,
/// the leaf signed it. That the leaf carries DelegationUsage (§4.2) is the
/// client's check (BoringSSL's server does not make it either):
/// `hasDelegationUsage` tells.
pub fn check(raw: []const u8, leaf_der: []const u8) Error!Credential {
    const c = try parse(raw);
    if (c.valid_time > max_valid_time_s) return error.ValidTooLong;
    if (!schemeAllowed(c.scheme)) return error.UnsupportedAlgorithm;
    if (leaf_der.len > max_leaf_len) return error.BadSignature;
    var buf: [64 + context_string.len + 1 + max_leaf_len + 9 + 1024 + 2]u8 = undefined;
    if (c.cred.len > 9 + 1024) return error.Malformed;
    const msg = signedMessage(&buf, leaf_der, c.cred, c.algorithm) catch return error.Malformed;
    const public = clientauth.leafPublicKey(leaf_der) catch return error.BadSignature;
    certverify.verifyContent(@fromBackingInt(c.algorithm), public, msg, c.signature) catch return error.BadSignature;
    return c;
}

/// Whether the leaf's DER carries the DelegationUsage extension's OID (a
/// configuration check: clients refuse a credential from a leaf without it).
pub fn hasDelegationUsage(leaf_der: []const u8) bool {
    return std.mem.indexOf(u8, leaf_der, &delegation_usage_oid) != null;
}

/// Issue a credential: `cred` for `spki` under `scheme`, valid `valid_time`
/// seconds past the leaf's notBefore, signed by the leaf's key under
/// `algorithm`. For tools and tests; the leaf's key is the CA customer's.
// secret-api-ok: `leaf_key` is a union of pointers; `certverify.signContent` burns its own frames.
pub fn issue(out: []u8, leaf_der: []const u8, leaf_key: certverify.SecretKey, algorithm: u16, spki: []const u8, scheme: u16, valid_time: u32, random: ?std.Random) ![]u8 {
    // The credential's SPKI length is a u24 on the wire.
    if (spki.len > std.math.maxInt(u24)) return error.ValueTooLong;
    const cred_len = 4 + 2 + 3 + spki.len;
    if (out.len < cred_len + 4 + certverify.maxSignatureLen(@fromBackingInt(algorithm))) return error.BufferTooSmall;
    std.mem.writeInt(u32, out[0..4], valid_time, .big);
    std.mem.writeInt(u16, out[4..6], scheme, .big);
    std.mem.writeInt(u24, out[6..9], @intCast(spki.len), .big); // checked above
    @memcpy(out[9..][0..spki.len], spki);
    std.mem.writeInt(u16, out[cred_len..][0..2], algorithm, .big);
    var mbuf: [64 + context_string.len + 1 + max_leaf_len + 9 + 1024 + 2]u8 = undefined;
    const msg = try signedMessage(&mbuf, leaf_der, out[0..cred_len], algorithm);
    const sig = try certverify.signContent(@fromBackingInt(algorithm), leaf_key, msg, random, out[cred_len + 4 ..]);
    std.mem.writeInt(u16, out[cred_len + 2 ..][0..2], @intCast(sig.len), .big);
    return out[0 .. cred_len + 4 + sig.len];
}

/// The DER SubjectPublicKeyInfo of a P-256 public key (uncompressed point).
pub fn spkiP256(out: *[91]u8, point: *const [65]u8) []const u8 {
    const prefix = [_]u8{ 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };
    @memcpy(out[0..prefix.len], &prefix);
    @memcpy(out[prefix.len..], point);
    return out;
}

/// The DER SubjectPublicKeyInfo of an Ed25519 public key.
pub fn spkiEd25519(out: *[44]u8, key: *const [32]u8) []const u8 {
    const prefix = [_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    @memcpy(out[0..prefix.len], &prefix);
    @memcpy(out[prefix.len..], key);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parse: lengths add up exactly" {
    const raw = [_]u8{ 0, 0, 0, 60, 0x04, 0x03, 0, 0, 2, 0xaa, 0xbb, 0x08, 0x04, 0, 1, 0xcc };
    const c = try parse(&raw);
    try testing.expectEqual(@as(u32, 60), c.valid_time);
    try testing.expectEqual(@as(u16, 0x0403), c.scheme);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, c.spki);
    try testing.expectEqual(@as(usize, 11), c.cred.len);
    try testing.expectEqual(@as(u16, 0x0804), c.algorithm);
    try testing.expectError(error.Malformed, parse(raw[0 .. raw.len - 1]));
    try testing.expectError(error.Malformed, parse(&(raw ++ [_]u8{0})));
}

test "parse: an empty SubjectPublicKeyInfo or signature is malformed" {
    // spki_len 0 (RFC 9345 §4: opaque ASN1_subjectPublicKeyInfo<1..2^24-1>).
    try testing.expectError(error.Malformed, parse(&.{ 0, 0, 0, 60, 0x04, 0x03, 0, 0, 0, 0x08, 0x04, 0, 1, 0xcc }));
    // signature<1..2^16-1> empty.
    try testing.expectError(error.Malformed, parse(&.{ 0, 0, 0, 60, 0x04, 0x03, 0, 0, 2, 0xaa, 0xbb, 0x08, 0x04, 0, 0 }));
    _ = try parse(&.{ 0, 0, 0, 60, 0x04, 0x03, 0, 0, 2, 0xaa, 0xbb, 0x08, 0x04, 0, 1, 0xcc });
}

test "signedMessage: 64 spaces, the context string, a zero octet, the leaf, the credential, the algorithm (RFC 9345 §4)" {
    const cred = "\x00\x00\x00\x3c\x04\x03\x00\x00\x02\xaa\xbb";
    // Built here, not by `signedMessage`.
    const want = @as([64]u8, @splat(0x20)) ++ "TLS, server delegated credentials" ++ "\x00" ++ "LEAF" ++ cred ++ "\x08\x04";
    var buf: [200]u8 = undefined;
    try testing.expectEqualSlices(u8, want, try signedMessage(&buf, "LEAF", cred, 0x0804));
    try testing.expectError(error.BufferTooSmall, signedMessage(buf[0 .. want.len - 1], "LEAF", cred, 0x0804));
}

test "check: valid for exactly 7 days is taken, a second more is not; only ECDSA and Ed25519 schemes" {
    const certs = @import("test_certs.zig");
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const sk = EcdsaP256.SecretKey.fromBytes(certs.p256_scalar) catch unreachable;
    var spki_buf: [44]u8 = undefined;
    const spki = spkiEd25519(&spki_buf, &@as([32]u8, @splat(0x42)));
    var raw: [600]u8 = undefined;
    const leaf = certs.p256_cert;
    const key: certverify.SecretKey = .{ .ecdsa_p256 = &sk };
    const at_limit = try issue(&raw, &leaf, key, 0x0403, spki, 0x0807, max_valid_time_s, null);
    try testing.expectEqual(max_valid_time_s, (try check(at_limit, &leaf)).valid_time);
    const over = try issue(&raw, &leaf, key, 0x0403, spki, 0x0807, max_valid_time_s + 1, null);
    try testing.expectError(error.ValidTooLong, check(over, &leaf));
    // An RSA-PSS credential scheme, though the leaf signed it fine.
    const rsa_scheme = try issue(&raw, &leaf, key, 0x0403, spki, 0x0804, 60, null);
    try testing.expectError(error.UnsupportedAlgorithm, check(rsa_scheme, &leaf));
    // Signed over another leaf: not verified.
    const fine = try issue(&raw, &leaf, key, 0x0403, spki, 0x0807, 60, null);
    _ = try check(fine, &leaf);
    try testing.expectError(error.BadSignature, check(fine, "another leaf"));
}

test "issue: an SPKI over 2^24 - 1 octets is ValueTooLong, not a cast panic" {
    const big = try testing.allocator.alloc(u8, (1 << 24));
    defer testing.allocator.free(big);
    var out: [16]u8 = undefined;
    // Refused before the key or the buffer is looked at.
    try testing.expectError(error.ValueTooLong, issue(&out, "", undefined, 0x0804, big, 0x0804, 1, null));
}

test "re-audit 2026-10-28: issue: an SPKI of exactly 2^24 - 1 octets passes the length guard" {
    const big = try testing.allocator.alloc(u8, (1 << 24) - 1);
    defer testing.allocator.free(big);
    var out: [16]u8 = undefined;
    // Not ValueTooLong: the u24 holds it; only the small buffer refuses.
    try testing.expectError(error.BufferTooSmall, issue(&out, "", undefined, 0x0804, big, 0x0804, 1, null));
}
