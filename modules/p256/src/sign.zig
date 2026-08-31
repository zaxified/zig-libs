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
//!   * `ecdsaSignDeterministic` — the same signer with the RFC 6979 nonce, so
//!     the RFC's own published `(r, s)` come back byte for byte.
//!
//! This layer is intentionally thin: it is a verification-harness surface, not
//! the module's reason to exist. A later phase can grow it into a full drop-in
//! for `std.crypto.sign.ecdsa` (DER codec) if desired; for now it proves the
//! primitives against external anchors.

const std = @import("std");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const P256 = group.P256;
const Scalar = scalarmod.Scalar;
const Fe = @import("field.zig").Fe;

/// Std-compatible ECDSA-P256/SHA-256, instantiated over p256's fast curve.
/// This is `std.crypto.sign.ecdsa.Ecdsa` driven by `group.P256`, so it reuses
/// std's ECDSA scaffolding verbatim (`KeyPair`/`PublicKey`/`Signature`, DER +
/// raw codecs, RFC 6979 deterministic nonces, `generateDeterministic`) while
/// every field/point op runs on p256's asm-accelerated arithmetic. It is the
/// drop-in for `std.crypto.sign.ecdsa.EcdsaP256Sha256` that the P2 HTTPS-API
/// JWT ES256 hot path (and jwe ECDH-ES) rewires onto.
///
/// Constant-time split is exactly std's: signing/keygen commit `k·G` / `d·G`
/// through `group.P256.basePoint.mul` (the CT windowed core), while `verify`
/// runs the two public scalar mults through `group.P256.mulPublic` (vartime
/// wNAF on PUBLIC inputs only). No secret scalar ever touches a vartime mul.
///
/// Byte-exact to `std.crypto.sign.ecdsa.EcdsaP256Sha256`: same construction,
/// same curve math (p256's group is the byte-exact std oracle).
///
/// That argument used to be written here as "so every RFC 6979 / Wycheproof
/// vector that passes on std passes here unchanged" — which was reasoning, not
/// evidence, and in any case said nothing about `ecdsaVerify` below, a
/// separate implementation. Both are now run against all 241 Wycheproof
/// P1363 vectors in `wycheproof_kat_test.zig`.
pub const EcdsaP256Sha256 = std.crypto.sign.ecdsa.Ecdsa(P256, Sha256);

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

// ── signature encoding: DER ↔ IEEE P1363 (raw r||s) ─────────────────────────
//
// X.509, OCSP, CMS and TLS 1.2 carry ECDSA signatures as the ASN.1
// `Ecdsa-Sig-Value`; JWS/COSE/XML-DSig and this module's own API use raw
// `r || s`. Converting between them is where signature malleability creeps in:
// a decoder that accepts non-minimal INTEGERs, negative INTEGERs, or trailing
// bytes inside the SEQUENCE lets the same signature be re-encoded many ways,
// all of which still verify. `derToRaw` therefore enforces DER strictly rather
// than accepting the wider BER, and is anchored on the 484 Wycheproof
// `ecdsa_secp256r1_sha256` vectors, 310 of which are malformed encodings.
//
// Deliberately self-contained: p256 declares no module dependencies, and
// pulling in an ASN.1 module for two INTEGERs would trade that for far more
// code than the parser below.

/// Longest DER `Ecdsa-Sig-Value` for P-256: `30 46 02 21 00 <32> 02 21 00 <32>`.
pub const der_max_len = 2 + 2 * (2 + 33);

/// Decode a DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` into
/// raw `r || s` (32 bytes each, big-endian). Returns null for anything that is
/// not valid DER for this type, including encodings that are legal BER.
///
/// Rejected on purpose, each one a way to mint a second encoding of the same
/// signature: a non-minimal length octet, a leading `0x00` that is not needed
/// for the sign bit, a negative INTEGER (high bit set), an empty INTEGER, a
/// value wider than 32 bytes, bytes left over inside the SEQUENCE, and bytes
/// after it. Zero values are left to the verifier, which rejects `r` or `s`
/// of zero anyway.
pub fn derToRaw(sig_der: []const u8) ?[64]u8 {
    if (sig_der.len < 2 or sig_der[0] != 0x30) return null;
    const body = readLen(sig_der[1..]) orelse return null;
    if (body.len_bytes + 1 + body.len != sig_der.len) return null; // trailing data
    var rest = sig_der[1 + body.len_bytes ..][0..body.len];

    var out = [_]u8{0} ** 64;
    inline for (.{ 0, 32 }) |off| {
        if (rest.len < 2 or rest[0] != 0x02) return null;
        const int = readLen(rest[1..]) orelse return null;
        const start = 1 + int.len_bytes;
        if (start + int.len > rest.len) return null;
        const v = rest[start..][0..int.len];
        if (v.len == 0) return null; // INTEGER must have content
        if (v[0] & 0x80 != 0) return null; // negative
        if (v[0] == 0 and (v.len == 1 or v[1] & 0x80 == 0)) return null; // non-minimal
        const mag = if (v[0] == 0) v[1..] else v;
        if (mag.len > 32) return null;
        @memcpy(out[off + 32 - mag.len ..][0..mag.len], mag);
        rest = rest[start + int.len ..];
    }
    if (rest.len != 0) return null; // extra content inside the SEQUENCE
    return out;
}

const Len = struct { len: usize, len_bytes: usize };

/// DER definite-form length: short form below 128, otherwise the minimal
/// number of length octets with no leading zero. Indefinite form (`0x80`) is
/// BER only and rejected.
fn readLen(bytes: []const u8) ?Len {
    if (bytes.len == 0) return null;
    const first = bytes[0];
    if (first < 0x80) return .{ .len = first, .len_bytes = 1 };
    const n = first & 0x7f;
    if (n == 0 or n > 2 or bytes.len < 1 + n) return null; // 2 octets spans any P-256 sig
    if (bytes[1] == 0) return null; // non-minimal
    var v: usize = 0;
    for (bytes[1..][0..n]) |b| v = (v << 8) | b;
    if (v < 0x80) return null; // should have used the short form
    return .{ .len = v, .len_bytes = 1 + n };
}

/// Encode raw `r || s` as a DER `Ecdsa-Sig-Value` into `buf` (at least
/// `der_max_len` bytes) and return the written slice.
pub fn rawToDer(sig_rs: [64]u8, buf: *[der_max_len]u8) []const u8 {
    var body: [2 * (2 + 33)]u8 = undefined;
    var n: usize = 0;
    inline for (.{ 0, 32 }) |off| {
        var v: []const u8 = sig_rs[off..][0..32];
        while (v.len > 1 and v[0] == 0) v = v[1..];
        const pad: usize = @intFromBool(v[0] & 0x80 != 0);
        body[n] = 0x02;
        body[n + 1] = @intCast(v.len + pad);
        if (pad != 0) body[n + 2] = 0x00;
        @memcpy(body[n + 2 + pad ..][0..v.len], v);
        n += 2 + pad + v.len;
    }
    buf[0] = 0x30;
    buf[1] = @intCast(n); // always < 0x80 for P-256
    @memcpy(buf[2..][0..n], body[0..n]);
    return buf[0 .. 2 + n];
}

// ── RFC 6979 §3.2 deterministic nonce (HMAC-SHA256 DRBG) ────────────────────

/// The RFC 6979 nonce for `(privkey, hash32)`.
///
/// Specialised to P-256/SHA-256, where the hash length equals the group-order
/// byte length (32 == 32), so RFC 6979's `bits2int` is the identity and
/// `bits2octets(H(m))` is just `H(m) mod n` re-encoded. A curve/hash pairing
/// with different sizes would need the bit-shifting the RFC describes; this is
/// deliberately not written generically for a case the module cannot reach.
/// Mirrors `k256.ecdsa_recover`'s DRBG, which the same reasoning covers.
fn rfc6979Nonce(privkey: [32]u8, hash32: [32]u8) Scalar {
    const h1 = reduceToScalar(hash32).toBytes(.big);

    var v: [32]u8 = [_]u8{0x01} ** 32;
    var k: [32]u8 = [_]u8{0x00} ** 32;

    var buf: [32 + 1 + 32 + 32]u8 = undefined;
    buf[0..32].* = v;
    buf[32] = 0x00;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    buf[0..32].* = v;
    buf[32] = 0x01;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    while (true) {
        HmacSha256.create(&v, &v, &k);
        // `Scalar.fromBytes` rejects `>= n`, which is exactly RFC 6979's
        // "discard and re-derive" condition; zero is discarded too.
        if (Scalar.fromBytes(v, .big)) |cand| {
            if (!cand.isZero()) return cand;
        } else |_| {}
        var buf2: [32 + 1]u8 = undefined;
        buf2[0..32].* = v;
        buf2[32] = 0x00;
        HmacSha256.create(&k, &buf2, &k);
        HmacSha256.create(&v, &v, &k);
    }
}

/// Sign `SHA-256(msg)` with the RFC 6979 deterministic nonce — no entropy
/// source, and the same message under the same key always yields the same
/// bytes. That reproducibility is what makes the signer anchorable: the RFC's
/// own published `(r, s)` for "sample" and "test" must come back byte for
/// byte (`kat_test.zig`), which `ecdsaSign` with a caller-chosen nonce can
/// never demonstrate.
///
/// Prefer this over `ecdsaSign` unless you have a specific reason to supply
/// `k` yourself: a nonce that repeats across two different messages leaks the
/// private key outright, and deriving it from the key and message removes that
/// failure mode along with any dependence on the platform's RNG.
pub fn ecdsaSignDeterministic(secret_key: [32]u8, msg: []const u8) SignError![64]u8 {
    _ = Scalar.fromBytes(secret_key, .big) catch return error.InvalidSecretKey;
    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    return ecdsaSign(secret_key, msg, rfc6979Nonce(secret_key, h).toBytes(.big));
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
    // std's verifier rejects `e == 0` and this one did not. With `e ≡ 0
    // (mod n)` the verification equation collapses to `R = u2·Q`, which
    // anyone can satisfy without a private key: pick `t`, set `R = t·Q`,
    // `r = x(R) mod n`, `s = r·t⁻¹`. Unreachable here — `e` is SHA-256 of the
    // message, so triggering it needs a preimage of 0 or of n — but this
    // module is anchored on being behaviourally identical to std, and a
    // divergence in a rejection rule is exactly what such an anchor is for.
    if (e.isZero()) return false;

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

test "ecdsaVerify: r=0 and s=0 are rejected explicitly (never fed to any test before)" {
    // No existing test had ever called ecdsaVerify with a zero r or s.
    // Mutation testing (disable the `r.isZero() or s.isZero()` guard)
    // shows this module's downstream math happens to fail closed anyway
    // for BOTH cases against a real signature — s=0 forces sinv=0 (std's
    // documented invert(0)==0), zeroing both mulDoubleBasePublic
    // coefficients and hitting the already-checked identity rejection;
    // r=0 zeroes only the Q-coefficient, leaving u1v*G's x-coordinate
    // essentially never equal to r=0 by chance — so this guard is an
    // explicit, defense-in-depth check of a documented invariant (RFC
    // 6979-adjacent "r, s in [1, n-1]") rather than the only thing
    // standing between here and a forgery. Pinned directly regardless,
    // matching this module's own sign-side r=0/s=0 rejection tests.
    const sk = [_]u8{0x11} ** 32;
    const k = [_]u8{0x22} ** 32;
    const msg = "p256 zero r/s smoke";
    const sig = try ecdsaSign(sk, msg, k);
    const pk = (P256.combMulBase(sk, .big) catch unreachable).toUncompressedSec1();

    var zero_r = sig;
    @memset(zero_r[0..32], 0);
    try std.testing.expect(!ecdsaVerify(&pk, msg, zero_r));

    var zero_s = sig;
    @memset(zero_s[32..64], 0);
    try std.testing.expect(!ecdsaVerify(&pk, msg, zero_s));
}

// The std-compatible `EcdsaP256Sha256` must interoperate byte-for-byte with
// `std.crypto.sign.ecdsa.EcdsaP256Sha256`: same keypair from the same seed,
// each side's signature verifies under the other. This pins the drop-in the
// jwt/jwe rewire relies on.
test "EcdsaP256Sha256 cross-verifies with std both directions" {
    const Std = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const seed = [_]u8{0x37} ** Std.KeyPair.seed_length;
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const std_kp = try Std.KeyPair.generateDeterministic(seed);

    // Same seed ⇒ byte-identical public key (SEC1).
    try std.testing.expectEqualSlices(
        u8,
        &kp.public_key.toUncompressedSec1(),
        &std_kp.public_key.toUncompressedSec1(),
    );

    const msg = "p256 ecdsa drop-in oracle";

    // p256-signed ⇒ verifies under std.
    const sig_ours = try kp.sign(msg, null);
    try Std.Signature.fromBytes(sig_ours.toBytes()).verify(msg, std_kp.public_key);

    // std-signed ⇒ verifies under p256.
    const sig_std = try std_kp.sign(msg, null);
    try EcdsaP256Sha256.Signature.fromBytes(sig_std.toBytes()).verify(msg, kp.public_key);
}
