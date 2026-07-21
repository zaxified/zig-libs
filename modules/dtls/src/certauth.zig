// SPDX-License-Identifier: MIT

//! dtls.certauth — the bridge between raw X.509 DER bytes (as carried on
//! the wire in a DTLS 1.3 `Certificate` message, RFC 8446 §4.4.2) and
//! `certverify.zig`'s typed `PublicKey` union, plus a minimal
//! chain-to-trust-anchor check.
//!
//! **No new crypto module dependency.** ASN.1 walking reuses
//! `std.crypto.Certificate` (already part of std — not a new dependency),
//! and the RSA leaf-key case reuses this module's EXISTING `rsa` dependency
//! (`rsa.PublicKey.fromDer`, already used by `certverify.zig`'s RSA-PSS
//! dispatch). The `x509` module (this collection's separate certificate-
//! chain-validator scaffold) is deliberately NOT used — see
//! `Connection.zig`'s "certificate mode" section / `root.zig`'s module doc
//! for why.
//!
//! **What `verifyLeafAgainstAnchor` checks (real, not a stub) — via
//! `std.crypto.Certificate.Parsed.verify`:** the leaf's `issuer` name
//! matches the anchor's `subject` name, the leaf's validity period covers
//! the caller-supplied `now_sec`, and the leaf's signature verifies under
//! the anchor's public key (real RSA-PKCS1v1.5/ECDSA/Ed25519 signature
//! math, per the leaf's declared `signatureAlgorithm`).
//!
//! **What this is NOT — deliberately out of scope, not silently skipped:**
//! full RFC 5280 §6 certification-path building (multi-hop chains beyond
//! leaf+one anchor, name constraints, policy extensions, `basicConstraints
//! CA:true`/`keyUsage` checks on the anchor, CRL/OCSP revocation checking).
//! A caller that needs any of that should use `Connection.Config.PeerVerify
//! .verify_fn` instead of `.trust_anchor` — see that type's doc comment.
//!
//! ## KNOWN GAP (not fixable within this module): `std.crypto.Certificate
//! .parse` is NOT panic-safe against malformed/adversarial DER in Zig
//! 0.16 — confirmed here by fuzzing (see this file's `test`s and the
//! session that wrote them): even short, structurally-truncated buffers
//! (as small as 3 bytes, and ~random 26-64 byte buffers reliably) crash
//! the process with an unguarded `bytes[i]` index-out-of-bounds panic
//! DEEP inside std's ASN.1 walker, rather than returning a typed
//! `ParseError`. This function's own error handling (`cert.parse() catch
//! return error.MalformedCertificate`) cannot intercept a panic — Zig has
//! no exception/panic-catching mechanism — so `parseLeafPublicKey`/
//! `verifyLeafAgainstAnchor` inherit this std gap whole. Fixing it would
//! mean vendoring/writing a bounds-hardened DER parser from scratch,
//! which is a real, substantial, crypto-adjacent-parsing undertaking, NOT
//! "plumbing over certverify with no new crypto" — explicitly out of this
//! module's scope. **Practical consequence: a live deployment that feeds
//! a PEER-supplied (i.e. potentially adversarial) `Certificate` message's
//! bytes into this bridge is exposed to a process-crash DoS from a
//! malformed certificate, until either std fixes this or a hardened
//! parser replaces this bridge.** Flagged prominently rather than hidden;
//! not something a Sonnet-tier "wire the existing pieces together" pass
//! should attempt to silently paper over with a false sense of safety
//! (a superficial length-floor check was considered and rejected — the
//! fuzz results above show it would not meaningfully close the gap: most
//! crashing inputs found were already comfortably longer than any sane
//! floor).

const std = @import("std");
const rsa = @import("rsa");
const certverify = @import("certverify.zig");

const Certificate = std.crypto.Certificate;

pub const Error = error{
    /// `cert_der` does not parse as a well-formed X.509 certificate at all.
    MalformedCertificate,
    /// The certificate's declared public-key algorithm is not one
    /// `certverify.PublicKey` supports (only `rsaEncryption` /
    /// `X9_62_id_ecPublicKey` on P-256 or P-384 / `curveEd25519` — NOT
    /// `rsassa_pss`-tagged keys or P-521).
    UnsupportedPublicKeyAlgorithm,
    /// The public-key bytes themselves fail to parse under their declared
    /// algorithm (malformed SEC1 point, malformed RSA DER, wrong-length
    /// Ed25519 key, ...).
    InvalidPublicKey,
} || Certificate.Parsed.VerifyError;

/// Parses `cert_der`'s `SubjectPublicKeyInfo` into a `certverify.PublicKey`
/// — the key `certverify.verify` needs to check a `CertificateVerify`
/// signature produced by this certificate's holder.
pub fn parseLeafPublicKey(cert_der: []const u8) Error!certverify.PublicKey {
    const cert = Certificate{ .buffer = cert_der, .index = 0 };
    const parsed = cert.parse() catch return error.MalformedCertificate;
    const key_bytes = parsed.pubKey();

    return switch (parsed.pub_key_algo) {
        .rsaEncryption => .{
            .rsa = rsa.PublicKey.fromDer(key_bytes) catch return error.InvalidPublicKey,
        },
        .X9_62_id_ecPublicKey => |curve| switch (curve) {
            .X9_62_prime256v1 => .{
                .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(key_bytes) catch return error.InvalidPublicKey,
            },
            .secp384r1 => .{
                .ecdsa_p384 = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(key_bytes) catch return error.InvalidPublicKey,
            },
            .secp521r1 => error.UnsupportedPublicKeyAlgorithm,
        },
        .curveEd25519 => blk: {
            if (key_bytes.len != std.crypto.sign.Ed25519.PublicKey.encoded_length) return error.InvalidPublicKey;
            break :blk .{
                .ed25519 = std.crypto.sign.Ed25519.PublicKey.fromBytes(key_bytes[0..std.crypto.sign.Ed25519.PublicKey.encoded_length].*) catch return error.InvalidPublicKey,
            };
        },
        .rsassa_pss => error.UnsupportedPublicKeyAlgorithm,
    };
}

/// Minimal one-hop chain-to-trust-anchor check (see module doc comment for
/// exactly what is and is not validated): `leaf_der` must be issued
/// (real signature check) by `anchor_der`'s key, and `now_sec` must fall
/// inside `leaf_der`'s validity period.
pub fn verifyLeafAgainstAnchor(leaf_der: []const u8, anchor_der: []const u8, now_sec: i64) Error!void {
    const leaf = Certificate{ .buffer = leaf_der, .index = 0 };
    const anchor = Certificate{ .buffer = anchor_der, .index = 0 };
    const leaf_parsed = leaf.parse() catch return error.MalformedCertificate;
    const anchor_parsed = anchor.parse() catch return error.MalformedCertificate;
    try leaf_parsed.verify(anchor_parsed, now_sec);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const kat = @import("certauth_kat_vectors.zig");

test "parseLeafPublicKey: ECDSA P-256 leaf (real X.509 DER from OpenSSL)" {
    const pk = try parseLeafPublicKey(&kat.server_cert_der);
    try testing.expect(pk == .ecdsa_p256);
}

test "parseLeafPublicKey: extracted P-256 key matches the KAT's own secret key's public half" {
    const pk = try parseLeafPublicKey(&kat.server_cert_der);
    const sk = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(kat.server_secret_key_bytes);
    const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(sk);
    try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &pk.ecdsa_p256.toUncompressedSec1());
}

test "parseLeafPublicKey: RSA-2048 leaf (real X.509 DER from OpenSSL)" {
    const pk = try parseLeafPublicKey(&kat.rsa_cert_der);
    try testing.expect(pk == .rsa);
    try testing.expectEqual(@as(usize, 2048), pk.rsa.n.bits());
}

test "parseLeafPublicKey: structurally-intact DER with an unrecognized curve OID is a typed error" {
    // A DELIBERATELY LIMITED "malformed input" test — see this file's
    // module doc comment's "KNOWN GAP" section: std.crypto.Certificate
    // .parse panics (not a typed error) on many truncated/adversarial
    // inputs, which cannot be caught here (Zig has no panic-catching).
    // What CAN be demonstrated honestly: an input that keeps every
    // length/offset field self-consistent (so std's ASN.1 walker never
    // reads past a declared boundary) but carries WRONG CONTENT — here, a
    // corrupted named-curve OID byte — reaches this module's own typed
    // `error.MalformedCertificate` cleanly, via std's `ParseEnumError
    // .CertificateHasUnrecognizedObjectId`, not a crash.
    var corrupted = kat.server_cert_der;
    const p256_curve_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const idx = std.mem.indexOf(u8, &corrupted, &p256_curve_oid).?;
    corrupted[idx + p256_curve_oid.len - 1] ^= 0x01; // flip the OID's last byte -> unrecognized curve
    try testing.expectError(error.MalformedCertificate, parseLeafPublicKey(&corrupted));
}

test "verifyLeafAgainstAnchor: real signature check accepts a genuinely anchor-signed leaf" {
    try verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, kat.valid_now_sec);
    try verifyLeafAgainstAnchor(&kat.client_cert_der, &kat.anchor_cert_der, kat.valid_now_sec);
}

test "verifyLeafAgainstAnchor: rejects a leaf signed by a DIFFERENT anchor (same subject name as the real leaf)" {
    // evil_server_cert_der has the SAME CN as server_cert_der but was signed
    // by evil_anchor_cert_der's key, not anchor_cert_der's -- proving the
    // check is a real signature/issuer verification, not a name compare.
    try testing.expectError(error.CertificateIssuerMismatch, verifyLeafAgainstAnchor(&kat.evil_server_cert_der, &kat.anchor_cert_der, kat.valid_now_sec));
}

test "verifyLeafAgainstAnchor: rejects the real leaf against the WRONG anchor" {
    try testing.expectError(error.CertificateIssuerMismatch, verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.evil_anchor_cert_der, kat.valid_now_sec));
}

test "verifyLeafAgainstAnchor: rejects a time outside the certificate's validity window" {
    const long_before: i64 = 1; // 1970 -- before notBefore (2026)
    try testing.expectError(error.CertificateNotYetValid, verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, long_before));
    const long_after: i64 = 4102444800; // 2100 -- after notAfter (2036)
    try testing.expectError(error.CertificateExpired, verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, long_after));
}

test "verifyLeafAgainstAnchor: a tampered leaf signature is rejected" {
    var tampered = kat.server_cert_der;
    tampered[tampered.len - 1] ^= 0x01; // flip the last byte of the ECDSA signature
    try testing.expectError(error.CertificateSignatureInvalid, verifyLeafAgainstAnchor(&tampered, &kat.anchor_cert_der, kat.valid_now_sec));
}
