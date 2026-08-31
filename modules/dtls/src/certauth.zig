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
//! **Peer IDENTITY is checked only when the caller asks for it**
//! (`verifyLeafAgainstAnchor`'s `expected_name`, reached from
//! `Connection.Config.expected_peer_name`). Issuance and identity are two
//! different questions and only the first is answered by a chain check: an
//! anchor that issues a fleet of certificates vouches for every one of them,
//! so without a name the check accepts any fleet member as any other. See
//! that parameter's doc comment.
//!
//! **What this is NOT — deliberately out of scope, not silently skipped:**
//! full RFC 5280 §6 certification-path building (multi-hop chains beyond
//! leaf+one anchor, name constraints, policy extensions, `basicConstraints
//! CA:true`/`keyUsage` checks on the anchor, CRL/OCSP revocation checking).
//! A caller that needs any of that should use `Connection.Config.PeerVerify
//! .verify_fn` instead of `.trust_anchor` — see that type's doc comment.
//!
//! ## CLOSED GAP: `std.crypto.Certificate.parse` is NOT panic-safe against
//! malformed/adversarial DER in Zig 0.16 — confirmed here by fuzzing: even
//! short, structurally-truncated buffers (as small as 3 bytes, and ~random
//! 26-64 byte buffers reliably) crash the process with an unguarded
//! `bytes[i]` index-out-of-bounds panic deep inside std's ASN.1 walker,
//! rather than returning a typed `ParseError`. Since a `Certificate`
//! message is peer-supplied, that was a crash-DoS on this bridge.
//!
//! Both entry points now go through `x509`'s bounds-checked decoder first:
//! `parseLeafPublicKey` reads the `SubjectPublicKeyInfo` with
//! `x509.spkiOf`, which never invokes std's parser at all, and
//! `verifyLeafAgainstAnchor` — which genuinely needs issuer/validity/
//! signature, fields `spkiOf` deliberately does not decode — feeds std a
//! copy vetted and zero-padded by `x509.safe.safeCertificate`. The
//! hardened parser this note once called out of scope was written
//! separately (`x509/src/safe.zig`) and is shared with `iec62351` and
//! `opcua`, which had each grown their own guard against the same hazard.

const std = @import("std");
const rsa = @import("rsa");
const x509 = @import("x509");
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
} || Certificate.Parsed.VerifyError || Certificate.Parsed.VerifyHostNameError;

/// Parses `cert_der`'s `SubjectPublicKeyInfo` into a `certverify.PublicKey`
/// — the key `certverify.verify` needs to check a `CertificateVerify`
/// signature produced by this certificate's holder.
pub fn parseLeafPublicKey(cert_der: []const u8) Error!certverify.PublicKey {
    // Routed through `x509.spkiOf`, NOT `std.crypto.Certificate.parse`: std's
    // DER reader indexes without bounds checks and panics or reads out of
    // bounds on hostile input, and a peer's Certificate message is exactly
    // that. `spkiOf` walks the certificate with x509's own bounds-checked
    // decoder, decodes no field contents at all, and fails closed.
    const spki = x509.spkiOf(cert_der) catch return error.MalformedCertificate;
    const key_bytes = spki.key_bits;

    if (spki.algorithmIs(&x509.safe.oid_rsa_encryption)) {
        return .{ .rsa = rsa.PublicKey.fromDer(key_bytes) catch return error.InvalidPublicKey };
    }
    if (spki.algorithmIs(&x509.safe.oid_ec_public_key)) {
        // No named curve (implicitCurve/specifiedCurve) is deliberately not
        // decoded by `namedCurveOid`, so it lands here as unsupported rather
        // than being guessed at.
        const curve = spki.namedCurveOid() orelse return error.UnsupportedPublicKeyAlgorithm;
        if (std.mem.eql(u8, curve, &x509.safe.oid_prime256v1)) {
            return .{
                .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(key_bytes) catch return error.InvalidPublicKey,
            };
        }
        if (std.mem.eql(u8, curve, &x509.safe.oid_secp384r1)) {
            return .{
                .ecdsa_p384 = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(key_bytes) catch return error.InvalidPublicKey,
            };
        }
        return error.UnsupportedPublicKeyAlgorithm; // P-521 and anything else
    }
    if (spki.algorithmIs(&x509.safe.oid_ed25519)) {
        const len = std.crypto.sign.Ed25519.PublicKey.encoded_length;
        if (key_bytes.len != len) return error.InvalidPublicKey;
        return .{
            .ed25519 = std.crypto.sign.Ed25519.PublicKey.fromBytes(key_bytes[0..len].*) catch return error.InvalidPublicKey,
        };
    }
    // Includes rsassa_pss-tagged keys, which carry their own OID.
    return error.UnsupportedPublicKeyAlgorithm;
}

/// Minimal one-hop chain-to-trust-anchor check (see module doc comment for
/// exactly what is and is not validated): `leaf_der` must be issued
/// (real signature check) by `anchor_der`'s key, and `now_sec` must fall
/// inside `leaf_der`'s validity period.
///
/// ⭐ `expected_name`, when non-null, additionally binds the certificate to
/// an IDENTITY — the leaf's `subjectAltName` dNSNames, or its `commonName`
/// when the certificate carries no SAN at all (RFC 6125 / std's
/// `verifyHostName`, wildcards included).
///
/// **Passing null is only safe when the anchor issues exactly one identity.**
/// Chain verification answers "was this issued by the anchor", never "is this
/// the peer I meant to reach": under a fleet CA every device certificate is
/// anchor-issued, so with null any holder of any such certificate
/// authenticates as any other — device impersonation, and on a client, a
/// server-impersonation MITM. That is the whole reason this parameter is not
/// optional-by-omission but an explicit `?[]const u8` the caller must decide.
pub fn verifyLeafAgainstAnchor(
    leaf_der: []const u8,
    anchor_der: []const u8,
    now_sec: i64,
    expected_name: ?[]const u8,
) Error!void {
    // Unlike `parseLeafPublicKey`, this needs fields `spkiOf` deliberately does
    // not decode — issuer, validity, signature — so std's parser is still the
    // one doing the work. It is fed through `x509.safe.safeCertificate`, which
    // walks the DER with a bounds-checked decoder first and hands std a
    // zero-padded copy that absorbs its boundary probes. Feeding a peer's
    // certificate to std's parser unguarded is a crash-DoS.
    var leaf_scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    var anchor_scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const leaf = x509.safe.safeCertificate(leaf_der, &leaf_scratch) catch return error.MalformedCertificate;
    const anchor = x509.safe.safeCertificate(anchor_der, &anchor_scratch) catch return error.MalformedCertificate;
    const leaf_parsed = leaf.parse() catch return error.MalformedCertificate;
    const anchor_parsed = anchor.parse() catch return error.MalformedCertificate;
    try leaf_parsed.verify(anchor_parsed, now_sec);
    if (expected_name) |name| try leaf_parsed.verifyHostName(name);
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
    // An input that keeps every length/offset field self-consistent but
    // carries wrong CONTENT — a corrupted named-curve OID byte — must reach
    // a typed error, not a crash.
    //
    // The error changed when this moved off std's parser, and the new one is
    // the accurate one. std mapped OIDs onto a closed enum, so an unknown
    // curve surfaced as `CertificateHasUnrecognizedObjectId` and this module
    // reported `MalformedCertificate` — but the certificate is not malformed.
    // It is structurally perfect and simply names a curve we do not support,
    // which is exactly what `UnsupportedPublicKeyAlgorithm` is documented to
    // mean. `x509.spkiOf` returns the OID's raw bytes without deciding
    // whether they are "recognized", so the classification is now made here,
    // deliberately, rather than inherited from std's enum coverage.
    var corrupted = kat.server_cert_der;
    const p256_curve_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const idx = std.mem.indexOf(u8, &corrupted, &p256_curve_oid).?;
    corrupted[idx + p256_curve_oid.len - 1] ^= 0x01; // flip the OID's last byte -> unrecognized curve
    try testing.expectError(error.UnsupportedPublicKeyAlgorithm, parseLeafPublicKey(&corrupted));
}

test "parseLeafPublicKey: adversarial DER returns a typed error instead of panicking" {
    // Previously impossible to assert: std's parser panicked on inputs like
    // these, and Zig cannot catch a panic. Routing through x509's
    // bounds-checked decoder makes it expressible as an ordinary test.
    const cases: []const []const u8 = &.{
        &.{},
        &.{0x30},
        &.{ 0x30, 0x82, 0xff, 0xff },
        &.{ 0x30, 0x03, 0x02, 0x01, 0x00 },
        &.{ 0x02, 0x01, 0x00 }, // INTEGER, not a SEQUENCE
    };
    for (cases) |c| try testing.expect(std.meta.isError(parseLeafPublicKey(c)));

    // Every truncation of a real certificate must also stay typed.
    var i: usize = 0;
    while (i < kat.server_cert_der.len) : (i += 7) {
        _ = parseLeafPublicKey(kat.server_cert_der[0..i]) catch continue;
    }
}

test "verifyLeafAgainstAnchor: real signature check accepts a genuinely anchor-signed leaf" {
    try verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, kat.valid_now_sec, null);
    try verifyLeafAgainstAnchor(&kat.client_cert_der, &kat.anchor_cert_der, kat.valid_now_sec, null);
}

test "verifyLeafAgainstAnchor: expected_name binds the chain to an identity" {
    // ⭐ The reason this parameter exists. Both certificates below are issued
    // by the SAME anchor and both pass every chain check there is — issuer,
    // validity, signature. Only the name tells them apart, so without one the
    // client certificate authenticates perfectly well AS THE SERVER, which is
    // what a fleet CA hands every device holding a certificate.
    try verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, kat.valid_now_sec, "dtls-test-server");
    try testing.expectError(error.CertificateHostMismatch, verifyLeafAgainstAnchor(
        &kat.client_cert_der,
        &kat.anchor_cert_der,
        kat.valid_now_sec,
        "dtls-test-server",
    ));
    // The impersonation the null case allows, spelled out: same call, no name.
    try verifyLeafAgainstAnchor(&kat.client_cert_der, &kat.anchor_cert_der, kat.valid_now_sec, null);
}

test "verifyLeafAgainstAnchor: rejects a leaf signed by a DIFFERENT anchor (same subject name as the real leaf)" {
    // evil_server_cert_der has the SAME CN as server_cert_der but was signed
    // by evil_anchor_cert_der's key, not anchor_cert_der's -- proving the
    // check is a real signature/issuer verification, not a name compare.
    try testing.expectError(error.CertificateIssuerMismatch, verifyLeafAgainstAnchor(&kat.evil_server_cert_der, &kat.anchor_cert_der, kat.valid_now_sec, null));
}

test "verifyLeafAgainstAnchor: rejects the real leaf against the WRONG anchor" {
    try testing.expectError(error.CertificateIssuerMismatch, verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.evil_anchor_cert_der, kat.valid_now_sec, null));
}

test "verifyLeafAgainstAnchor: rejects a time outside the certificate's validity window" {
    const long_before: i64 = 1; // 1970 -- before notBefore (2026)
    try testing.expectError(error.CertificateNotYetValid, verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, long_before, null));
    const long_after: i64 = 4102444800; // 2100 -- after notAfter (2036)
    try testing.expectError(error.CertificateExpired, verifyLeafAgainstAnchor(&kat.server_cert_der, &kat.anchor_cert_der, long_after, null));
}

test "verifyLeafAgainstAnchor: a tampered leaf signature is rejected" {
    var tampered = kat.server_cert_der;
    tampered[tampered.len - 1] ^= 0x01; // flip the last byte of the ECDSA signature
    try testing.expectError(error.CertificateSignatureInvalid, verifyLeafAgainstAnchor(&tampered, &kat.anchor_cert_der, kat.valid_now_sec, null));
}

// ── fuzz: parseLeafPublicKey off the wire, never panics ─────────────────────
//
// `cert_der` here is a `Certificate` message entry straight off the wire
// (RFC 8446 §4.4.2), from an unauthenticated peer, during the handshake —
// same threat model as the record layer. NOTE most of this function's own
// logic is deliberately NOT re-fuzzed here: it is a thin dispatcher over
// `x509.spkiOf` (already fuzzed directly at `x509/src/safe.zig`'s "fuzz:
// arbitrary bytes through spkiOf never panic", which itself drives
// `rsa.PublicKey.fromDer` and `EcdsaP256Sha256.fromSec1` on the exact same
// extracted `key_bits`/`der` this function passes them), and `rsa
// .PublicKey.fromDer` is fuzzed a second time, independently, in
// `rsa/src/root.zig`. Re-fuzzing that path here would test nothing new.
// What genuinely has no existing coverage is the P-384 and Ed25519 dispatch
// arms (`EcdsaP384Sha384.fromSec1` / `Ed25519.PublicKey.fromBytes`), which
// only this function reaches — hence a harness at this level rather than
// skipping it entirely.

test "fuzz: parseLeafPublicKey never panics on arbitrary DER" {
    try testing.fuzz({}, fuzzParseLeafPublicKey, .{});
}

fn fuzzParseLeafPublicKey(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = parseLeafPublicKey(buf[0..len]) catch return;
}
