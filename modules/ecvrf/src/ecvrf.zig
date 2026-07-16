// SPDX-License-Identifier: MIT
//! ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5), the elliptic-curve
//! Verifiable Random Function ciphersuite built on edwards25519/SHA-512.
//! Transcribed directly from RFC 9381 §5.1-§5.4 (the ciphersuite-generic
//! `ECVRF_prove`/`ECVRF_proof_to_hash`/`ECVRF_verify` algorithms and their
//! auxiliary functions) and §5.5's ECVRF-EDWARDS25519-SHA512-TAI parameter
//! fixing, against `std.crypto.ecc.Edwards25519` + `std.crypto.hash.
//! sha2.Sha512` — no new field/curve arithmetic, this ciphersuite reuses
//! std's edwards25519 wholesale (`mulDoubleBasePublic` is exactly the
//! primitive `ECVRF_verify`'s `U = s*B - c*Y` / `V = s*H - c*Gamma` need).
//!
//! **suite_string = 0x03.** RFC 9381 §5.5 defines `ECVRF-EDWARDS25519-
//! SHA512-TAI` with `suite_string = 0x03` and a SEPARATE ciphersuite,
//! `ECVRF-EDWARDS25519-SHA512-ELL2` (RFC 9380 Elligator2 hash-to-curve
//! instead of try-and-increment), with `suite_string = 0x04` — the two
//! are easy to conflate since both mine edwards25519/SHA-512, but they
//! are NOT interchangeable (different `encode_to_curve`, different
//! `suite_string` byte feeding every hash in the scheme). This module
//! implements ONLY the TAI (try-and-increment) ciphersuite, `suite_string
//! = 0x03` — ELL2 is out of scope (would need RFC 9380's Elligator2 map,
//! `std.crypto.ecc.Edwards25519.fromUniform`/`elligator2` — a real
//! candidate for a follow-up module, not attempted here).
//!
//! Algorithm map (RFC 9381 section -> this file):
//!   - §5.1 `ECVRF_prove`                    -> `prove`
//!   - §5.2 `ECVRF_proof_to_hash`             -> `proofToHash`
//!   - §5.3 `ECVRF_verify`                    -> `verify`
//!   - §5.4.1.1 `..._try_and_increment`       -> `encodeToCurve`
//!   - §5.4.2.2 `..._nonce_generation_RFC8032`-> `nonceGeneration` /
//!                                                `nonceGenerationString`
//!   - §5.4.3 `ECVRF_challenge_generation`    -> `challengeGeneration`
//!   - §5.4.4 `ECVRF_decode_proof`            -> `decodeProof`
//!   - §5.4.5 `ECVRF_validate_key`            -> `validateKey`
//!   - §5.1.5 of RFC 8032 (secret scalar/pubkey derivation, referenced by
//!     RFC 9381 §5.5)                          -> `expandSecretKey` /
//!                                                `secretScalar` / `publicKey`
//!
//! **Byte-order note (a real trap in this ciphersuite):** RFC 9381 §5.5
//! fixes `int_to_string`/`string_to_int` for ECVRF-EDWARDS25519-SHA512-TAI
//! to RFC 8032 §5.1.2's LITTLE-endian convention — the OPPOSITE of
//! ECVRF-P256-SHA256-TAI's big-endian (I2OSP/OS2IP) convention in the same
//! document. `point_to_string`/`string_to_point` are exactly
//! `Edwards25519.toBytes`/`fromBytes` (already little-endian-with-sign-bit
//! per RFC 8032 §5.1.2), so `Gamma`'s 32 bytes need no conversion; `c`
//! (16 bytes) and `s` (32 bytes) inside `pi_string` are RAW little-endian
//! integers — `s` doubles as `std.crypto.ecc.Edwards25519.scalar.
//! CompressedScalar` directly (same encoding), `c` is zero-extended to 32
//! bytes (`padChallenge`) before any scalar-field arithmetic.
//!
//! **`Y`/`PK_string` re-canonicalization.** RFC 9381's parameter list
//! defines `PK_string = point_to_string(Y)` categorically — i.e. always
//! the FRESH canonical re-encoding of the decoded/derived point `Y`, not
//! necessarily byte-identical to whatever octet string a caller handed
//! `verify`. This module honors that literally: `verify` decodes the
//! caller's `PublicKey` bytes to a point, then re-encodes
//! (`y_point.toBytes()`) before using it as `encode_to_curve_salt` AND as
//! `ECVRF_challenge_generation`'s `P1` — matching what `prove` does with
//! its freshly-derived `Y = x*B`. For every canonically-encoded public
//! key (the only kind `ECVRF_validate_key`/`Edwards25519.fromBytes`
//! accept as VALID in the first place) this is a no-op, so it does not
//! affect any KAT vector; it only matters for the theoretical edge case
//! of a non-canonical-but-decodable input, where re-encoding is the
//! spec-faithful choice over trusting the caller's raw bytes.
//!
//! **`ECVRF_challenge_generation` hashes FIVE points, not four** — a
//! detail easy to miss skimming the surrounding prose: `ECVRF_
//! challenge_generation(P1, P2, P3, P4, P5)` with `P1 = Y` (the public
//! key) ALWAYS included first, then `H, Gamma` and either `(k*B, k*H)`
//! (proving) or `(U, V)` (verifying) — omitting `Y` from the hash would
//! silently make two different key pairs share nonce-independent
//! challenges for the same `(H, Gamma, U, V)`, breaking the "trusted
//! collision resistance" property RFC 9381 §3/§7 requires.
//!
//! Provenance: clean-room from RFC 9381 (S. Goldberg, L. Reyzin,
//! D. Papadopoulos, J. Včelák, "Verifiable Random Functions (VRFs)",
//! IRTF CFRG, August 2023, https://www.rfc-editor.org/rfc/rfc9381.txt)
//! §5 and §5.5, and RFC 8032 (EdDSA) §5.1.2/§5.1.5 as RFC 9381 §5.5
//! references for point/scalar encoding and key derivation — both public
//! IETF/IRTF specifications; see `../NOTICE`. Known-answer vectors: RFC
//! 9381 Appendix B.3 (`kat_vectors.zig`/`kat_test.zig`).

const std = @import("std");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const scalar = Edwards25519.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// RFC 9381 §5.5: the one-byte ciphersuite identifier for
/// ECVRF-EDWARDS25519-SHA512-TAI. NOT 0x04 (that is the sibling ELL2
/// ciphersuite, §5.5's very next paragraph) — see the module doc comment.
pub const suite_string: u8 = 0x03;

/// RFC 9381 §5.5: challenge length in octets (`cLen`).
pub const c_len: usize = 16;
/// RFC 9381 §5.5: length of the group order `q` in octets (`qLen`) —
/// edwards25519's subgroup order is ~2^252, so 32 octets.
pub const q_len: usize = 32;
/// RFC 9381 §5.5: length of a compressed point in octets (`ptLen`) —
/// `fLen` for edwards25519 (no extra sign byte; the sign bit is folded
/// into the top bit of the 32nd byte, RFC 8032 §5.1.2).
pub const pt_len: usize = 32;
/// RFC 9381 §5.5: `Hash` output length in octets (`hLen`) — SHA-512.
pub const h_len: usize = 64;
/// `pi_string`'s total length: `ptLen + cLen + qLen` (RFC 9381 §5.1 step 8).
pub const proof_len: usize = pt_len + c_len + q_len;

pub const SecretKey = [32]u8;
pub const PublicKey = [pt_len]u8;
pub const Proof = [proof_len]u8;
pub const Output = [h_len]u8;

/// Every failure mode of `decodeProof`/`validateKey`/`verify` collapses
/// to one of these two — matching RFC 9381's own "output INVALID and
/// stop" fail-closed shape (the spec never distinguishes failure
/// reasons at the API boundary).
pub const Error = error{
    /// `pi_string` does not decode to `(Gamma, c, s)` per §5.4.4 (`Gamma`
    /// not a valid curve point, or `s >= q`), or `ECVRF_verify`'s final
    /// challenge comparison (§5.3 step 11) did not match.
    InvalidProof,
    /// `PK_string` does not decode to a valid point (§5.3 step 1/2), or
    /// `ECVRF_validate_key` (§5.4.5) rejects it as a low-order point.
    InvalidPublicKey,
};

/// RFC 9381 §5.5 (referencing RFC 8032 §5.1.5): `SK` is a 32-byte seed;
/// `hashed_sk_string = SHA-512(SK)`; the VRF secret scalar `x` is the
/// LOW 32 bytes after RFC 8032 clamping (`h[0] &= 248; h[31] = (h[31] &
/// 127) | 64`) — used un-reduced-mod-`q` as the scalar-multiplication
/// exponent (matching `std.crypto.sign.Ed25519`'s own key derivation;
/// `Edwards25519.mul` computes the correct point regardless, since point
/// order divides `q` exactly); the HIGH 32 bytes (`prefix`) are folded
/// into `nonceGeneration` (RFC 8032 §5.1.6 steps 2-3, RFC 9381 §5.4.2.2)
/// but are NOT otherwise part of the VRF secret scalar.
const ExpandedSecretKey = struct { x: [32]u8, prefix: [32]u8 };

fn expandSecretKey(sk: SecretKey) ExpandedSecretKey {
    var h: [64]u8 = undefined;
    Sha512.hash(&sk, &h, .{});
    defer std.crypto.secureZero(u8, &h);
    var x: [32]u8 = h[0..32].*;
    scalar.clamp(&x);
    return .{ .x = x, .prefix = h[32..64].* };
}

/// The VRF secret scalar `x` (RFC 9381's parameter list: "`x`: VRF secret
/// scalar... Depending on the ciphersuite... derived from SK") — exposed
/// so callers/tests can pin it against RFC 9381 Appendix B.3's published
/// `x` values independent of `prove`'s end-to-end output.
pub fn secretScalar(sk: SecretKey) [32]u8 {
    return expandSecretKey(sk).x;
}

/// `Y = x*B` (RFC 9381's parameter list), compressed — RFC 9381 §5.5 /
/// RFC 8032 §5.1.5's public-key derivation.
pub fn publicKey(sk: SecretKey) PublicKey {
    const x = secretScalar(sk);
    const y = Edwards25519.basePoint.mul(x) catch
        @panic("ecvrf: degenerate secret key (clamped scalar is 0 mod the group order — probability ~2^-252)");
    return y.toBytes();
}

/// RFC 9381 §5.4.1.1 `ECVRF_encode_to_curve_try_and_increment`, fixed to
/// this ciphersuite's `interpret_hash_value_as_a_point(s) =
/// string_to_point(s[0]...s[31])` (§5.5) and `cofactor = 8`
/// (`Edwards25519.clearCofactor`, `p.dbl().dbl().dbl()`).
/// `encode_to_curve_salt` is `PK_string` per §5.5 ("encode_to_curve_salt
/// = PK_string"); `alpha_string` is the VRF input.
///
/// The `ctr < 256` bound matches the RFC's own analysis ("ctr is
/// overwhelmingly unlikely, probability about 2^-256, to reach 256") —
/// `int_to_string(ctr, 1)` genuinely cannot represent 256, so exhausting
/// the loop is a `@panic`, not a caller-observable error.
pub fn encodeToCurve(pk_string: PublicKey, alpha_string: []const u8) PublicKey {
    var ctr: u16 = 0;
    while (ctr < 256) : (ctr += 1) {
        var st = Sha512.init(.{});
        st.update(&[_]u8{suite_string});
        st.update(&[_]u8{0x01}); // encode_to_curve_domain_separator_front
        st.update(&pk_string);
        st.update(alpha_string);
        st.update(&[_]u8{@intCast(ctr)}); // ctr_string = int_to_string(ctr, 1)
        st.update(&[_]u8{0x00}); // encode_to_curve_domain_separator_back
        var hash_string: [64]u8 = undefined;
        st.final(&hash_string);

        const candidate = Edwards25519.fromBytes(hash_string[0..32].*) catch continue;
        const h = candidate.clearCofactor(); // cofactor = 8 for edwards25519
        h.rejectIdentity() catch continue;
        return h.toBytes();
    }
    @panic("ecvrf: encode_to_curve_try_and_increment exhausted ctr in [0,256) — probability ~2^-256");
}

/// RFC 9381 §5.4.2.2 `ECVRF_nonce_generation_RFC8032`, the PRE-reduction
/// `k_string = Hash(truncated_hashed_sk_string || h_string)` (RFC 8032
/// §5.1.6 step 2's `r`, before "interpret ... as little-endian ... mod
/// q") — exposed separately from `nonceGeneration` so callers/tests can
/// pin it against RFC 9381 Appendix B.3's published `k_string` values.
pub fn nonceGenerationString(sk: SecretKey, h_string: PublicKey) [64]u8 {
    var hashed_sk: [64]u8 = undefined;
    Sha512.hash(&sk, &hashed_sk, .{});
    defer std.crypto.secureZero(u8, &hashed_sk);

    var st = Sha512.init(.{});
    st.update(hashed_sk[32..64]); // truncated_hashed_sk_string
    st.update(&h_string);
    var k_string: [64]u8 = undefined;
    st.final(&k_string);
    return k_string;
}

/// RFC 9381 §5.4.2.2 `ECVRF_nonce_generation_RFC8032` step 4:
/// `k = string_to_int(k_string) mod q` — `scalar.reduce64` is exactly
/// "interpret 64 little-endian bytes as an integer, reduce mod the
/// group order".
pub fn nonceGeneration(sk: SecretKey, h_string: PublicKey) [32]u8 {
    var k_string = nonceGenerationString(sk, h_string);
    defer std.crypto.secureZero(u8, &k_string);
    return scalar.reduce64(k_string);
}

/// RFC 9381 §5.4.3 `ECVRF_challenge_generation(P1, P2, P3, P4, P5)`: hash
/// `suite_string || 0x02 || point_to_string(P1) || ... || point_to_string(P5)
/// || 0x00`, truncate to the first `cLen` (16) octets. Every caller in
/// this module supplies `P1 = Y` (see the module doc comment on why `Y`
/// must not be dropped from this hash).
fn challengeGeneration(p1: PublicKey, p2: PublicKey, p3: PublicKey, p4: PublicKey, p5: PublicKey) [c_len]u8 {
    var st = Sha512.init(.{});
    st.update(&[_]u8{suite_string});
    st.update(&[_]u8{0x02}); // challenge_generation_domain_separator_front
    st.update(&p1);
    st.update(&p2);
    st.update(&p3);
    st.update(&p4);
    st.update(&p5);
    st.update(&[_]u8{0x00}); // challenge_generation_domain_separator_back
    var c_string: [64]u8 = undefined;
    st.final(&c_string);
    return c_string[0..c_len].*;
}

/// Zero-extend a `cLen`-byte (16-byte) little-endian challenge to a full
/// 32-byte `Edwards25519.scalar.CompressedScalar` for use in scalar-field
/// arithmetic (`c < 2^128`, always `< q`, so no reduction is needed).
fn padChallenge(c: [c_len]u8) scalar.CompressedScalar {
    var out = [_]u8{0} ** 32;
    out[0..c_len].* = c;
    return out;
}

/// RFC 9381 §5.4.4 `ECVRF_decode_proof`: split `pi_string` into `(Gamma,
/// c, s)` and reject a structurally invalid proof — `Gamma` not a valid
/// curve-point encoding, or `s >= q` (non-canonical scalar). Does NOT
/// reject a `Gamma` in a low-order subgroup (the RFC does not ask for
/// that check here; `ECVRF_verify`'s challenge comparison is what makes
/// a forged low-order `Gamma` fail in practice).
pub const DecodedProof = struct { gamma: PublicKey, c: [c_len]u8, s: scalar.CompressedScalar };

pub fn decodeProof(pi: Proof) Error!DecodedProof {
    const gamma_string = pi[0..pt_len].*;
    const c = pi[pt_len..][0..c_len].*;
    const s = pi[pt_len + c_len ..][0..q_len].*;
    _ = Edwards25519.fromBytes(gamma_string) catch return error.InvalidProof;
    scalar.rejectNonCanonical(s) catch return error.InvalidProof;
    return .{ .gamma = gamma_string, .c = c, .s = s };
}

/// RFC 9381 §5.4.5 `ECVRF_validate_key`: reject a public key whose
/// cofactor-cleared form is the identity element (the eight low-order
/// edwards25519 points table §5.4.5 discusses, generalized via
/// `Edwards25519.clearCofactor`/`rejectIdentity` rather than the fixed
/// bad-point list — same input/output behavior the RFC explicitly
/// permits substituting). Returns the decoded point on success so
/// callers do not need to re-decode `PK_string`.
pub fn validateKey(pk_string: PublicKey) Error!Edwards25519 {
    const y = Edwards25519.fromBytes(pk_string) catch return error.InvalidPublicKey;
    y.clearCofactor().rejectIdentity() catch return error.InvalidPublicKey;
    return y;
}

/// RFC 9381 §5.1 `ECVRF_prove(SK, alpha_string)`. `encode_to_curve_salt`
/// is not passed separately — this ciphersuite fixes it to `PK_string`
/// (§5.5), derived internally from `SK`.
pub fn prove(sk: SecretKey, alpha_string: []const u8) Proof {
    var exp = expandSecretKey(sk);
    defer std.crypto.secureZero(u8, &exp.x);
    defer std.crypto.secureZero(u8, &exp.prefix);

    // Step 1: x, Y = x*B.
    const y_point = Edwards25519.basePoint.mul(exp.x) catch
        @panic("ecvrf: degenerate secret key (clamped scalar is 0 mod the group order)");
    const y_string = y_point.toBytes();

    // Step 2-3: H = encode_to_curve(PK_string, alpha), h_string = point_to_string(H).
    const h_string = encodeToCurve(y_string, alpha_string);
    // encode_to_curve always returns a canonical toBytes() encoding of a
    // real (cofactor-cleared, non-identity) point — decoding it back can
    // never fail.
    const h_point = Edwards25519.fromBytes(h_string) catch unreachable;

    // Step 4: Gamma = x*H. H has prime order q (cofactor already
    // cleared, identity already excluded by encodeToCurve), and x != 0
    // mod q (else the Y = x*B step above would already have panicked),
    // so this can neither hit WeakPublicKey (H is not low-order) nor
    // IdentityElement (x is nonzero mod ord(H)).
    const gamma_point = h_point.mul(exp.x) catch unreachable;
    const gamma_string = gamma_point.toBytes();

    // Step 5: k = nonce_generation(SK, h_string).
    const k = nonceGeneration(sk, h_string);

    // Step 6: c = challenge_generation(Y, H, Gamma, k*B, k*H).
    const u_point = Edwards25519.basePoint.mul(k) catch
        @panic("ecvrf: nonce reduced to 0 mod the group order — probability ~2^-252");
    const v_point = h_point.mul(k) catch unreachable; // same non-low-order/non-identity argument as gamma_point
    const c = challengeGeneration(y_string, h_string, gamma_string, u_point.toBytes(), v_point.toBytes());

    // Step 7: s = (k + c*x) mod q.
    const s = scalar.mulAdd(padChallenge(c), exp.x, k);

    // Step 8: pi_string = point_to_string(Gamma) || int_to_string(c, cLen) || int_to_string(s, qLen).
    var pi: Proof = undefined;
    pi[0..pt_len].* = gamma_string;
    pi[pt_len..][0..c_len].* = c;
    pi[pt_len + c_len ..][0..q_len].* = s;
    return pi;
}

/// RFC 9381 §5.2 `ECVRF_proof_to_hash(pi_string)`.
pub fn proofToHash(pi: Proof) Error!Output {
    const d = try decodeProof(pi);
    const gamma_point = Edwards25519.fromBytes(d.gamma) catch unreachable; // decodeProof already validated
    const cofactor_gamma = gamma_point.clearCofactor();

    var st = Sha512.init(.{});
    st.update(&[_]u8{suite_string});
    st.update(&[_]u8{0x03}); // proof_to_hash_domain_separator_front
    st.update(&cofactor_gamma.toBytes());
    st.update(&[_]u8{0x00}); // proof_to_hash_domain_separator_back
    var beta: Output = undefined;
    st.final(&beta);
    return beta;
}

/// RFC 9381 §5.3 `ECVRF_verify(PK_string, alpha_string, pi_string)`, with
/// `validate_key` always TRUE (this module supports only that option —
/// RFC 9381 §5.3 explicitly permits an implementation to fix one option
/// and requires it to document which; unvalidated verification against a
/// possibly-low-order key is not exposed). Returns `beta_string` on
/// success ("VALID"), `error.InvalidPublicKey`/`error.InvalidProof` on
/// "INVALID" — every RFC "output INVALID and stop" step maps to one of
/// these two `return error...` points, never a panic on attacker input.
pub fn verify(pk_string: PublicKey, alpha_string: []const u8, pi: Proof) Error!Output {
    // Steps 1-3: Y = string_to_point(PK_string); validate_key.
    const y_point = try validateKey(pk_string);
    const y_string = y_point.toBytes(); // canonical PK_string (see module doc comment)

    // Steps 4-6: D = decode_proof(pi_string); (Gamma, c, s) = D.
    const d = try decodeProof(pi);
    const gamma_point = Edwards25519.fromBytes(d.gamma) catch unreachable; // decodeProof already validated

    // Step 7: H = encode_to_curve(PK_string, alpha_string).
    const h_string = encodeToCurve(y_string, alpha_string);
    const h_point = Edwards25519.fromBytes(h_string) catch unreachable; // see prove()'s identical argument

    // Steps 8-9: U = s*B - c*Y; V = s*H - c*Gamma (variable-time,
    // public inputs only — mirrors std.crypto.sign.Ed25519's own
    // verifier and this repo's bip340/xeddsa/adaptor convention).
    const c_scalar = padChallenge(d.c);
    const u_point = Edwards25519.mulDoubleBasePublic(Edwards25519.basePoint, d.s, y_point.neg(), c_scalar) catch
        return error.InvalidProof;
    const v_point = Edwards25519.mulDoubleBasePublic(h_point, d.s, gamma_point.neg(), c_scalar) catch
        return error.InvalidProof;

    // Step 10: c' = challenge_generation(Y, H, Gamma, U, V).
    const c_prime = challengeGeneration(y_string, h_string, d.gamma, u_point.toBytes(), v_point.toBytes());

    // Step 11: accept iff c == c'.
    if (!std.crypto.timing_safe.eql([c_len]u8, c_prime, d.c)) return error.InvalidProof;
    return proofToHash(pi) catch unreachable; // pi already fully validated above
}

test "wire-shape constants match RFC 9381 §5.5 (ECVRF-EDWARDS25519-SHA512-TAI)" {
    try std.testing.expectEqual(@as(u8, 0x03), suite_string);
    try std.testing.expectEqual(@as(usize, 16), c_len);
    try std.testing.expectEqual(@as(usize, 32), q_len);
    try std.testing.expectEqual(@as(usize, 32), pt_len);
    try std.testing.expectEqual(@as(usize, 64), h_len);
    try std.testing.expectEqual(@as(usize, 80), proof_len);
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(Proof));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(Output));
}

test "padChallenge zero-extends the low 16 bytes and leaves the high 16 zero" {
    var c: [c_len]u8 = undefined;
    for (&c, 0..) |*b, i| b.* = @intCast(i + 1);
    const padded = padChallenge(c);
    try std.testing.expectEqualSlices(u8, &c, padded[0..c_len]);
    for (padded[c_len..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "prove -> verify round-trips and recovers the same beta as proofToHash" {
    // No official-vector dependency here (kat_test.zig covers those) —
    // just the internal self-consistency every (sk, alpha) pair must
    // satisfy, exercised on a handful of deterministic non-RFC inputs.
    var i: u8 = 0;
    while (i < 8) : (i += 1) {
        var sk_wide: [64]u8 = undefined;
        Sha512.hash(&[_]u8{ 'e', 'c', 'v', 'r', 'f', 's', 'k', i }, &sk_wide, .{});
        const sk: SecretKey = sk_wide[0..32].*;
        const pk = publicKey(sk);

        var alpha_wide: [64]u8 = undefined;
        Sha512.hash(&[_]u8{ 'e', 'c', 'v', 'r', 'f', 'a', 'l', i }, &alpha_wide, .{});
        const alpha: [4]u8 = alpha_wide[0..4].*;

        const pi = prove(sk, &alpha);
        const beta_direct = try proofToHash(pi);
        const beta_verify = try verify(pk, &alpha, pi);
        try std.testing.expectEqualSlices(u8, &beta_direct, &beta_verify);

        // Wrong alpha must reject.
        var wrong_alpha = alpha;
        wrong_alpha[0] ^= 0x01;
        try std.testing.expectError(error.InvalidProof, verify(pk, &wrong_alpha, pi));
    }
}
