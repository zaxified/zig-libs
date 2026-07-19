// SPDX-License-Identifier: MIT

//! sign — ECDSA-P256/SHA-256 sign + verify over p256, present so the scaffold
//! can be anchored against EXTERNAL vectors (the RFC 6979 P-256 test vectors)
//! and against std's signer, not just against std's low-level field/group. Every
//! field multiply, point op, and scalar multiply the scheme below touches runs
//! on p256's own arithmetic, so a passing external vector is an end-to-end proof
//! that the whole p256 stack agrees with the reference.
//!
//!   * `ecdsaVerify` — P-256 ECDSA/SHA-256 verification, cross-checked in
//!     `oracle_test.zig` against signatures produced by
//!     `std.crypto.sign.ecdsa.EcdsaP256Sha256` and in `kat_test.zig` against the
//!     official RFC 6979 vectors.
//!   * `ecdsaSign` — P-256 ECDSA/SHA-256 signing with a caller-supplied nonce
//!     `k`. Signatures round-trip through both p256's and std's verifier
//!     (`oracle_test.zig`), proving sign+verify agree with std end-to-end.
//!
//! This layer is intentionally thin: it is a verification-harness surface, not
//! the module's reason to exist. A later phase can grow it into a full drop-in
//! for `std.crypto.sign.ecdsa` (DER codec, RFC 6979 deterministic nonces) if
//! desired; for now it proves the primitives against external anchors.

const std = @import("std");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const P256 = group.P256;
const Scalar = scalarmod.Scalar;
const Fe = @import("field.zig").Fe;

pub const SignError = error{ InvalidSecretKey, InvalidNonce };

/// `int(bytes32) mod n` — reduce a 32-byte value into the scalar field (a
/// 32-byte hash or field x-coordinate can exceed `n`, so a plain `fromBytes`
/// would wrongly reject it). This is the ECDSA `e = int(H(m))` and `x(R) mod n`.
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

/// Sign `SHA-256(msg)` under P-256 ECDSA with the caller-supplied nonce `k`
/// (32-byte big-endian, `0 < k < n`). Returns the 64-byte `r || s` signature.
///
/// `r = x(k·G) mod n`, `s = k⁻¹·(e + r·d) mod n` with `e = int(SHA256(msg)) mod n`.
/// Rejects a zero/oversized key or nonce and the (negligible-probability)
/// `r == 0` / `s == 0` degeneracies — the caller retries with a fresh `k`. The
/// nonce is a parameter (not derived here) to keep the scaffold free of an
/// RFC 6979 HMAC-DRBG; the test harness supplies random nonces and cross-checks
/// every signature against std's verifier.
pub fn ecdsaSign(secret_key: [32]u8, msg: []const u8, nonce_k: [32]u8) SignError![64]u8 {
    const d = Scalar.fromBytes(secret_key, .big) catch return error.InvalidSecretKey;
    if (d.isZero()) return error.InvalidSecretKey;
    const k = Scalar.fromBytes(nonce_k, .big) catch return error.InvalidNonce;
    if (k.isZero()) return error.InvalidNonce;

    // R = k·G (constant-time fixed-base); r = x(R) mod n.
    const R = P256.combMulBase(nonce_k, .big) catch return error.InvalidNonce;
    const rx = R.affineCoordinates().x.toBytes(.big);
    const r = reduceToScalar(rx);
    if (r.isZero()) return error.InvalidNonce;

    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    const e = reduceToScalar(h);

    // s = k⁻¹·(e + r·d) mod n.
    const s = k.invert().mul(e.add(r.mul(d)));
    if (s.isZero()) return error.InvalidNonce;

    var sig: [64]u8 = undefined;
    sig[0..32].* = r.toBytes(.big);
    sig[32..64].* = s.toBytes(.big);
    return sig;
}

/// Verify a P-256 ECDSA signature over SHA-256(`msg`). `pubkey_sec1` is a
/// SEC1-encoded public key (compressed 33-byte or uncompressed 65-byte);
/// `sig_rs` is `r (32) || s (32)` big-endian. Variable-time (all inputs public).
pub fn ecdsaVerify(pubkey_sec1: []const u8, msg: []const u8, sig_rs: [64]u8) bool {
    const Q = P256.fromSec1(pubkey_sec1) catch return false;
    const r = Scalar.fromBytes(sig_rs[0..32].*, .big) catch return false;
    const s = Scalar.fromBytes(sig_rs[32..64].*, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    const e = reduceToScalar(h);

    const sinv = s.invert();
    const u1v = e.mul(sinv);
    const u2v = r.mul(sinv);

    const R = P256.mulDoubleBasePublic(
        P256.basePoint,
        u1v.toBytes(.big),
        Q,
        u2v.toBytes(.big),
        .big,
    ) catch return false;
    // v = x(R) mod n; accept iff v == r.
    const v = reduceToScalar(R.affineCoordinates().x.toBytes(.big));
    return v.equivalent(r);
}

// A minimal round-trip smoke test (the deep anchors live in oracle_test.zig +
// kat_test.zig).
test "ecdsa sign→verify round-trip (fixed key + nonce)" {
    const sk = [_]u8{0x11} ** 32;
    const k = [_]u8{0x22} ** 32;
    const msg = "p256 scaffold smoke";
    const sig = try ecdsaSign(sk, msg, k);
    const pk = (P256.combMulBase(sk, .big) catch unreachable).toUncompressedSec1();
    try std.testing.expect(ecdsaVerify(&pk, msg, sig));
    // tamper → reject.
    var bad = sig;
    bad[5] ^= 1;
    try std.testing.expect(!ecdsaVerify(&pk, msg, bad));
}
