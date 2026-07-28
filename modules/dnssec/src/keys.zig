// SPDX-License-Identifier: MIT

//! DNSKEY public-key wire decoding + signature verification, per algorithm:
//! RSA (RFC 3110, algorithms 5/7/8/10 — RSASHA1/RSASHA1-NSEC3-SHA1/
//! RSASHA256/RSASHA512), ECDSA (RFC 6605, algorithms 13/14 —
//! ECDSAP256SHA256/ECDSAP384SHA384), and Ed25519 (RFC 8080, algorithm 15).
//!
//! This is mechanical wire-format glue over two already-real primitive
//! sources — Zig std's own `std.crypto.sign.ecdsa`/`std.crypto.sign.Ed25519`
//! (public, verify-capable) and this repo's own `rsa` module
//! (`rsa.verifyPkcs1v15`, since std's internal RSA verifier
//! (`std.crypto.Certificate.rsa`) is not `pub`) — no cryptographic
//! primitive is implemented here, only correctly wiring DNSKEY's wire
//! encoding to each library's public API.
//!
//! What this file does NOT do: build the actual bytes that get verified
//! (the RFC 4034 §3.1.8.1 canonical RRset signed-data stream) — that is
//! `canonical.zig`'s job; this file's `verifySignature` takes the result as a
//! plain `signed_data: []const u8` parameter, agnostic to how it was built.

const std = @import("std");
const rsa = @import("rsa");
const rdata = @import("rdata.zig");

pub const DecodeKeyError = error{
    UnsupportedAlgorithm,
    InvalidKeyEncoding,
};

/// A DNSKEY's public key material, decoded per its algorithm's wire format
/// into whichever library type actually verifies signatures for it.
pub const DecodedKey = union(enum) {
    rsa: rsa.PublicKey,
    ecdsa_p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey,
    ecdsa_p384: std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey,
    ed25519: std.crypto.sign.Ed25519.PublicKey,
};

/// Decode `public_key` (a DNSKEY RDATA's public-key field, RFC 4034 §2.1.4)
/// per `algorithm` (IANA DNSSEC Algorithm Numbers; see `rdata.algorithm`).
pub fn decodePublicKey(algorithm: u8, public_key: []const u8) DecodeKeyError!DecodedKey {
    return switch (algorithm) {
        rdata.algorithm.rsasha1, rdata.algorithm.rsasha1_nsec3_sha1, rdata.algorithm.rsasha256, rdata.algorithm.rsasha512 => .{ .rsa = try decodeRsaKey(public_key) },
        rdata.algorithm.ecdsap256sha256 => .{ .ecdsa_p256 = try decodeEcdsaP256Key(public_key) },
        rdata.algorithm.ecdsap384sha384 => .{ .ecdsa_p384 = try decodeEcdsaP384Key(public_key) },
        rdata.algorithm.ed25519 => .{ .ed25519 = try decodeEd25519Key(public_key) },
        else => error.UnsupportedAlgorithm,
    };
}

/// RFC 3110 §2: the RSA public key wire format used inside a DNSKEY RDATA —
/// distinct from PKCS#1 DER (no ASN.1, just a length-prefixed exponent
/// followed by the modulus):
///   exponent_length (1 byte, or 0 followed by a 2-byte big-endian length
///   for exponents > 255 bytes) || exponent || modulus.
fn decodeRsaKey(public_key: []const u8) DecodeKeyError!rsa.PublicKey {
    if (public_key.len < 1) return error.InvalidKeyEncoding;
    var pos: usize = 1;
    var e_len: usize = public_key[0];
    if (e_len == 0) {
        if (public_key.len < 3) return error.InvalidKeyEncoding;
        e_len = std.mem.readInt(u16, public_key[1..3], .big);
        pos = 3;
    }
    if (public_key.len < pos + e_len) return error.InvalidKeyEncoding;
    const exponent = public_key[pos..][0..e_len];
    const modulus = public_key[pos + e_len ..];
    if (modulus.len == 0) return error.InvalidKeyEncoding;
    return rsa.PublicKey.fromBytes(modulus, exponent) catch error.InvalidKeyEncoding;
}

/// RFC 6605 §4: the ECDSA public key wire format inside a DNSKEY RDATA is
/// the raw concatenation of the big-endian X and Y affine coordinates — no
/// SEC1 `0x04` uncompressed-point prefix (unlike TLS/X.509 conventions).
fn decodeEcdsaP256Key(public_key: []const u8) DecodeKeyError!std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
    const coord_len = 32;
    if (public_key.len != coord_len * 2) return error.InvalidKeyEncoding;
    const p = std.crypto.ecc.P256.fromSerializedAffineCoordinates(public_key[0..coord_len].*, public_key[coord_len..][0..coord_len].*, .big) catch return error.InvalidKeyEncoding;
    return .{ .p = p };
}

fn decodeEcdsaP384Key(public_key: []const u8) DecodeKeyError!std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey {
    const coord_len = 48;
    if (public_key.len != coord_len * 2) return error.InvalidKeyEncoding;
    const p = std.crypto.ecc.P384.fromSerializedAffineCoordinates(public_key[0..coord_len].*, public_key[coord_len..][0..coord_len].*, .big) catch return error.InvalidKeyEncoding;
    return .{ .p = p };
}

/// RFC 8080 §3: the Ed25519 public key wire format inside a DNSKEY RDATA is
/// exactly the 32-byte raw Ed25519 public key — no wrapping at all.
fn decodeEd25519Key(public_key: []const u8) DecodeKeyError!std.crypto.sign.Ed25519.PublicKey {
    if (public_key.len != std.crypto.sign.Ed25519.PublicKey.encoded_length) return error.InvalidKeyEncoding;
    return std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key[0..std.crypto.sign.Ed25519.PublicKey.encoded_length].*) catch error.InvalidKeyEncoding;
}

pub const VerifyError = error{
    UnsupportedAlgorithm,
    InvalidSignatureEncoding,
    SignatureVerificationFailed,
};

/// Verify `signature` (an RRSIG RDATA's Signature field, RFC 4034 §3.1.8/
/// RFC 6605 §5/RFC 8080 §4 — a raw, algorithm-specific encoding, never DER)
/// over `signed_data` (the caller-supplied canonical byte stream — see
/// `canonical.zig`) under `key`, per `algorithm`.
pub fn verifySignature(algorithm: u8, key: DecodedKey, signed_data: []const u8, signature: []const u8) VerifyError!void {
    switch (algorithm) {
        rdata.algorithm.rsasha1, rdata.algorithm.rsasha1_nsec3_sha1 => {
            rsa.verifyPkcs1v15(key.rsa, std.crypto.hash.Sha1, signed_data, signature) catch return error.SignatureVerificationFailed;
        },
        rdata.algorithm.rsasha256 => {
            rsa.verifyPkcs1v15(key.rsa, std.crypto.hash.sha2.Sha256, signed_data, signature) catch return error.SignatureVerificationFailed;
        },
        rdata.algorithm.rsasha512 => {
            rsa.verifyPkcs1v15(key.rsa, std.crypto.hash.sha2.Sha512, signed_data, signature) catch return error.SignatureVerificationFailed;
        },
        rdata.algorithm.ecdsap256sha256 => {
            const Sig = std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature;
            if (signature.len != Sig.encoded_length) return error.InvalidSignatureEncoding;
            const sig = Sig.fromBytes(signature[0..Sig.encoded_length].*);
            sig.verify(signed_data, key.ecdsa_p256) catch return error.SignatureVerificationFailed;
        },
        rdata.algorithm.ecdsap384sha384 => {
            const Sig = std.crypto.sign.ecdsa.EcdsaP384Sha384.Signature;
            if (signature.len != Sig.encoded_length) return error.InvalidSignatureEncoding;
            const sig = Sig.fromBytes(signature[0..Sig.encoded_length].*);
            sig.verify(signed_data, key.ecdsa_p384) catch return error.SignatureVerificationFailed;
        },
        rdata.algorithm.ed25519 => {
            const Sig = std.crypto.sign.Ed25519.Signature;
            if (signature.len != Sig.encoded_length) return error.InvalidSignatureEncoding;
            const sig = Sig.fromBytes(signature[0..Sig.encoded_length].*);
            sig.verify(signed_data, key.ed25519) catch return error.SignatureVerificationFailed;
        },
        else => return error.UnsupportedAlgorithm,
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "decodeRsaKey: short exponent-length form" {
    // e_len=1(0x01), e=0x03, then a tiny (too-small-for-real-use but
    // structurally valid) modulus so PublicKey.fromBytes' min-bits floor
    // isn't hit — use a 512-bit-plus modulus of all-0xff-ish bytes.
    var public_key: [1 + 1 + 64]u8 = undefined;
    public_key[0] = 1;
    public_key[1] = 3;
    @memset(public_key[2..], 0xab);
    const pk = try decodeRsaKey(&public_key);
    _ = pk;
}

test "decodeRsaKey: long exponent-length form (e_len byte 0)" {
    var public_key: [3 + 3 + 64]u8 = undefined;
    public_key[0] = 0;
    std.mem.writeInt(u16, public_key[1..3], 3, .big);
    public_key[3] = 0;
    public_key[4] = 1;
    public_key[5] = 0x01; // exponent = 0x000101 = 257
    @memset(public_key[6..], 0xab);
    const pk = try decodeRsaKey(&public_key);
    _ = pk;
}

test "decodeRsaKey: truncated key rejected" {
    try testing.expectError(error.InvalidKeyEncoding, decodeRsaKey("\x05\x01\x02"));
}

test "decodeEd25519Key: wrong length rejected" {
    try testing.expectError(error.InvalidKeyEncoding, decodeEd25519Key("\x01\x02\x03"));
}

test "Ed25519 sign/verify round-trip through this module's decode + verifySignature" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const msg = "hello dnssec";
    const sig = try kp.sign(msg, null);

    const pk_bytes = kp.public_key.toBytes();
    const decoded = try decodePublicKey(rdata.algorithm.ed25519, &pk_bytes);
    const sig_bytes = sig.toBytes();
    try verifySignature(rdata.algorithm.ed25519, decoded, msg, &sig_bytes);
}

test "Ed25519 verify rejects a tampered message" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(31 - i);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const sig = try kp.sign("original", null);
    const pk_bytes = kp.public_key.toBytes();
    const decoded = try decodePublicKey(rdata.algorithm.ed25519, &pk_bytes);
    const sig_bytes = sig.toBytes();
    try testing.expectError(error.SignatureVerificationFailed, verifySignature(rdata.algorithm.ed25519, decoded, "tampered", &sig_bytes));
}

test "ECDSA P-256 sign/verify round-trip through this module's decode + verifySignature" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i + 1);
    const kp = try Ecdsa.KeyPair.generateDeterministic(seed);
    const msg = "hello ecdsa dnssec";
    const sig = try kp.sign(msg, null);

    const coords = kp.public_key.p.affineCoordinates();
    const x_bytes = coords.x.toBytes(.big);
    const y_bytes = coords.y.toBytes(.big);
    var wire_key: [64]u8 = undefined;
    @memcpy(wire_key[0..32], &x_bytes);
    @memcpy(wire_key[32..64], &y_bytes);

    const decoded = try decodePublicKey(rdata.algorithm.ecdsap256sha256, &wire_key);
    const sig_bytes = sig.toBytes();
    try verifySignature(rdata.algorithm.ecdsap256sha256, decoded, msg, &sig_bytes);
}

test "UnsupportedAlgorithm surfaces for an unregistered algorithm number" {
    try testing.expectError(error.UnsupportedAlgorithm, decodePublicKey(200, "\x00"));
}

// ── fuzz: DNSKEY public-key material decode, never panics ──────────────────
//
// `decodePublicKey` loads the RSA/ECDSA/Ed25519 key bytes straight out of a
// DNSKEY RDATA — an unauthenticated DNS response is exactly where this key
// material comes from (this decode has to succeed *before* anything can be
// verified with it), so `public_key` here is fully attacker-controlled.

test "fuzz: decodePublicKey never panics on arbitrary bytes/algorithm" {
    try testing.fuzz({}, fuzzDecodePublicKey, .{});
}

fn fuzzDecodePublicKey(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const algorithm = smith.value(u8);
    _ = decodePublicKey(algorithm, buf[0..len]) catch return;
}
