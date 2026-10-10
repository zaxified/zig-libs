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
//! its freshly-derived `Y = x*B`. The same holds for `Gamma` (A1 E14).
//! Because `string_to_point` decodes strictly (`stringToPoint`, RFC 8032
//! §5.1.3 — `Edwards25519.fromBytes` alone would take a non-canonical `y`
//! or a stray sign bit), a non-canonical key or `Gamma` is rejected before
//! it gets here, so the re-encoding is always the caller's own bytes and
//! neither a key nor a proof has a second valid spelling (A1 E16).
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
const ct25519 = @import("ct25519");
const burn = @import("burn.zig");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const scalar = Edwards25519.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;

// ── constant-time scalar multiplication on a SECRET scalar ──────────────
//
// `Edwards25519.mul` (std) is internally constant-time — a 4-bit fixed
// window over a 16-entry precomputed table selected with `cMov`, 64 fixed
// iterations regardless of the scalar — EXCEPT that `pcMul16`
// (`std/crypto/25519/edwards25519.zig`) ends with `try q.rejectIdentity()`,
// turning "the product is the neutral element" into
// `error.IdentityElement`. `rejectIdentity` is `if (p.x.isZero())` — a
// BRANCH on a value derived from the scalar — and the error union then
// forces every caller to branch a second time. Both branches are
// secret-dependent when the scalar is the VRF secret `x` or the nonce `k`:
// they reveal whether that scalar was zero mod the group order. The old
// shape here was `catch @panic(...)` / `catch unreachable` at five call
// sites, which is the loudest possible form of that branch.
//
// `ct25519.mul`/`ct25519.mulBase` (sibling module) are std's own
// constant-time ladder with the trailing rejection removed: the neutral
// element is simply returned as a value. They have no error union, so no
// call site can branch on the scalar, and their control flow (precompute
// or load the base table, then 64 window iterations, each an unconditional
// 15-entry `cMov` select + add + 4 doublings) is identical for every
// scalar including zero. This module used to carry its own private copy of
// that ladder; it now depends on `ct25519` instead, so the fix (and its
// test coverage) lives in one place for every caller that needs it
// (`voprf`, `opaque`, `signal`, `bulletproofs`, and this module).
//
// Nothing is validated away by dropping the rejection. All five call sites
// treated the error as UNREACHABLE, and it provably is: RFC 8032 clamping
// puts `x` in `[2^254, 2^254 + 2^251)`, and `2^254/L ≈ 4.004` while
// `(2^254 + 2^251)/L ≈ 4.504`, so no clamped `x` is a multiple of `L` and
// `[x]B` is never the identity. For the nonce `k` the identity result has
// probability ~2^-252 and, if it ever occurred, the proof would simply
// carry `U = O` — `verify` recomputes `U` the same way, and a degenerate
// PUBLIC key is still rejected by `validateKey` (§5.4.5) on the verifier
// side, which is where that check belongs. The point-side guard std also
// has (`xpc[4].rejectIdentity()` ⇒ `error.WeakPublicKey`) is likewise not
// a validation here: `ct25519.mul`'s only non-base argument is `H`, which
// `encodeToCurve` has already cofactor-cleared and checked non-identity,
// so it cannot be low-order.
//
// The VERIFIER is untouched: `mulDoubleBasePublic` runs over public inputs
// only and stays variable-time by design.

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
    // Not `Sha512.hash`: its state keeps `sk` in the block buffer on a frame
    // nothing wipes. Hashing through a local state lets us wipe it (A1 E4).
    var st = Sha512.init(.{});
    st.update(&sk);
    st.final(&h);
    std.crypto.secureZero(u8, std.mem.asBytes(&st));
    defer std.crypto.secureZero(u8, &h);
    var x: [32]u8 = h[0..32].*;
    scalar.clamp(&x);
    // `x` is copied into the return value below; wiping this local AFTER
    // that copy leaves the caller's copy intact while erasing this
    // function's own dead frame (A1 E4 — one of the three surviving
    // dead-frame copies of `x` the audit's stack-scan probe found; this is
    // the one inside ecvrf's own module, not `ct25519`'s or std's).
    defer std.crypto.secureZero(u8, &x);
    return .{ .x = x, .prefix = h[32..64].* };
}

/// The VRF secret scalar `x` (RFC 9381's parameter list: "`x`: VRF secret
/// scalar... Depending on the ciphersuite... derived from SK") — exposed
/// so callers/tests can pin it against RFC 9381 Appendix B.3's published
/// `x` values independent of `prove`'s end-to-end output.
///
/// `x` goes into `out` (zeroed by the caller's own discipline; never
/// returned) and `sk` comes by pointer; the body is burned (`burn.zig`,
/// `stackprobe2_test.zig`).
pub fn secretScalar(out: *[32]u8, sk: *const SecretKey) void {
    secretScalarUnburned(out, sk);
    burn.stack(burn.key_burn);
}

noinline fn secretScalarUnburned(out: *[32]u8, sk: *const SecretKey) void {
    var e = expandSecretKey(sk.*);
    defer std.crypto.secureZero(u8, &e.x);
    defer std.crypto.secureZero(u8, &e.prefix);
    out.* = e.x;
}

/// `Y = x*B` (RFC 9381's parameter list), compressed — RFC 9381 §5.5 /
/// RFC 8032 §5.1.5's public-key derivation. `ct25519.mulBase`, not
/// `Edwards25519.mul`: `x` is secret and std's `mul` ends in a branch on
/// whether `[x]B` is the identity (see the module doc comment).
///
/// Burned (`burn.zig`), like `prove`.
pub fn publicKey(sk: *const SecretKey) PublicKey {
    const r = publicKeyUnburned(sk);
    burn.stack(burn.key_burn);
    return r;
}

noinline fn publicKeyUnburned(sk: *const SecretKey) PublicKey {
    var x = expandSecretKey(sk.*).x;
    defer std.crypto.secureZero(u8, &x);
    return ct25519.mulBase(x).toBytes();
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

        // interpret_hash_value_as_a_point = string_to_point (§5.5), strict.
        const candidate = stringToPoint(hash_string[0..32].*) catch continue;
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
///
/// `sk` by pointer, `k_string` into `out`; burned (`burn.zig`).
pub fn nonceGenerationString(out: *[64]u8, sk: *const SecretKey, h_string: PublicKey) void {
    nonceGenerationStringUnburned(out, sk, h_string);
    burn.stack(burn.key_burn);
}

noinline fn nonceGenerationStringUnburned(out: *[64]u8, sk: *const SecretKey, h_string: PublicKey) void {
    out.* = nonceStringFrom(sk, h_string);
}

/// `nonceGenerationString` over a borrowed seed, so `prove` does not hand
/// its caller's secret over by value once more (A1 E4).
fn nonceStringFrom(sk: *const SecretKey, h_string: PublicKey) [64]u8 {
    var hashed_sk: [64]u8 = undefined;
    // Local hash states, wiped after use: each holds secret input in its
    // block buffer (`sk`, then the prefix), which `Sha512.hash` would leave
    // on a dead frame (A1 E4).
    var sk_st = Sha512.init(.{});
    sk_st.update(sk);
    sk_st.final(&hashed_sk);
    std.crypto.secureZero(u8, std.mem.asBytes(&sk_st));
    defer std.crypto.secureZero(u8, &hashed_sk);

    var st = Sha512.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&st));
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
///
/// `sk` by pointer, `k` into `out`; burned (`burn.zig`).
pub fn nonceGeneration(out: *[32]u8, sk: *const SecretKey, h_string: PublicKey) void {
    nonceGenerationUnburned(out, sk, h_string);
    burn.stack(burn.key_burn);
}

noinline fn nonceGenerationUnburned(out: *[32]u8, sk: *const SecretKey, h_string: PublicKey) void {
    var k_string = nonceStringFrom(sk, h_string);
    defer std.crypto.secureZero(u8, &k_string);
    out.* = scalar.reduce64(k_string);
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

/// RFC 9381 §5.5 `string_to_point`, which is RFC 8032 §5.1.3 decoding —
/// strictly. `Edwards25519.fromBytes` accepts two things §5.1.3 refuses,
/// each a second 32-byte string for a point that already has one: a `y` in
/// `[p, 2^255)`, which it reduces mod `p` ("If the resulting value is >= p,
/// decoding fails"), and sign bit 1 on a point whose `x` is 0 ("If x = 0,
/// and x_0 = 1, decoding fails"). A1 E14/E16: with both refused, every
/// point this module decodes re-encodes to the very bytes it came from, so
/// `point_to_string(Gamma)` and `PK_string` are the caller's bytes and no
/// proof or key has a second spelling.
pub fn stringToPoint(s: [32]u8) error{InvalidEncoding}!Edwards25519 {
    Edwards25519.rejectNonCanonical(s) catch return error.InvalidEncoding;
    const p = Edwards25519.fromBytes(s) catch return error.InvalidEncoding;
    if (s[31] >> 7 == 1 and p.x.isZero()) return error.InvalidEncoding;
    return p;
}

/// RFC 9381 §5.4.4 `ECVRF_decode_proof`: split `pi_string` into `(Gamma,
/// c, s)` and reject a structurally invalid proof — `Gamma` not a valid
/// curve-point encoding under RFC 8032 §5.1.3's strict rules (see
/// `stringToPoint`), or `s >= q` (non-canonical scalar). Does NOT
/// reject a `Gamma` in a low-order subgroup (the RFC does not ask for
/// that check here; `ECVRF_verify`'s challenge comparison is what makes
/// a forged low-order `Gamma` fail in practice).
pub const DecodedProof = struct { gamma: PublicKey, c: [c_len]u8, s: scalar.CompressedScalar };

pub fn decodeProof(pi: Proof) Error!DecodedProof {
    const gamma_string = pi[0..pt_len].*;
    const c = pi[pt_len..][0..c_len].*;
    const s = pi[pt_len + c_len ..][0..q_len].*;
    _ = stringToPoint(gamma_string) catch return error.InvalidProof;
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
    const y = stringToPoint(pk_string) catch return error.InvalidPublicKey;
    y.clearCofactor().rejectIdentity() catch return error.InvalidPublicKey;
    return y;
}

/// RFC 9381 §5.1 `ECVRF_prove(SK, alpha_string)`. `encode_to_curve_salt`
/// is not passed separately — this ciphersuite fixes it to `PK_string`
/// (§5.5), derived internally from `SK`. A caller proving many inputs
/// under one key should use `KeyPair.prove`, which does not recompute `Y`.
///
/// Burned (`burn.zig`): the per-frame wipes of A1 E4 left the nonce `k` and
/// the seed on the dead stack in the callees' frames (`stackprobe_test.zig`,
/// 2026-10-08) — `k` beside the proof's `s` and `c` is the secret scalar.
pub fn prove(sk: *const SecretKey, alpha_string: []const u8) Proof {
    const r = proveUnburned(sk, alpha_string);
    burn.stack(burn.prove_burn);
    return r;
}

noinline fn proveUnburned(sk_ptr: *const SecretKey, alpha_string: []const u8) Proof {
    const sk = sk_ptr;
    var exp = expandSecretKey(sk.*);
    defer std.crypto.secureZero(u8, &exp.x);
    defer std.crypto.secureZero(u8, &exp.prefix);

    // Step 1: x, Y = x*B. `ct25519.mulBase` (constant-time, no error union)
    // — `x` is the VRF secret scalar; see the module doc comment for why
    // std's `mul` is not usable on a secret here.
    return proveExpanded(sk, &exp, ct25519.mulBase(exp.x).toBytes(), alpha_string);
}

/// A secret key with its public key derived once (A1 E10). `prove` spends
/// about a fifth of its time recomputing `Y = x*B` (measured 21.4 %); a
/// `KeyPair` pays that in `fromSecretKey` and proves without it.
///
/// Build it with `fromSecretKey`, never by filling the fields: a
/// `public_key` that is not `publicKey(secret_key)` makes every proof one
/// that no key verifies (the challenge binds the wrong `Y`, so `U = s*B -
/// c*Y` misses), a safe failure but a useless one. `secret_key` is the
/// caller's secret; wipe the `KeyPair` when done with it.
pub const KeyPair = struct {
    secret_key: SecretKey,
    public_key: PublicKey,

    /// Fills `out` (the key pair is never returned: a returned value is a
    /// copy of the seed in the caller's frame). `publicKey` carries the burn.
    pub fn fromSecretKey(out: *KeyPair, sk: *const SecretKey) void {
        out.secret_key = sk.*;
        out.public_key = publicKey(sk);
    }

    /// `ECVRF_prove` under this key pair; the same 80 bytes `prove` returns.
    ///
    /// Burned like the free `prove`.
    pub fn prove(kp: *const KeyPair, alpha_string: []const u8) Proof {
        const r = keyPairProveUnburned(kp, alpha_string);
        burn.stack(burn.prove_burn);
        return r;
    }

    noinline fn keyPairProveUnburned(kp: *const KeyPair, alpha_string: []const u8) Proof {
        var exp = expandSecretKey(kp.secret_key);
        defer std.crypto.secureZero(u8, &exp.x);
        defer std.crypto.secureZero(u8, &exp.prefix);
        return proveExpanded(&kp.secret_key, &exp, kp.public_key, alpha_string);
    }
};

/// `ECVRF_prove` steps 2-8, given step 1's `x` and `PK_string`. `sk` and
/// `exp` come by pointer: passed by value, `sk` left one more copy of the
/// seed on the dead stack (measured by a dead-stack probe, A1 E4).
fn proveExpanded(sk: *const SecretKey, exp: *const ExpandedSecretKey, y_string: PublicKey, alpha_string: []const u8) Proof {
    // Step 2-3: H = encode_to_curve(PK_string, alpha), h_string = point_to_string(H).
    const h_string = encodeToCurve(y_string, alpha_string);
    // encode_to_curve always returns a canonical toBytes() encoding of a
    // real (cofactor-cleared, non-identity) point — decoding it back can
    // never fail.
    const h_point = Edwards25519.fromBytes(h_string) catch unreachable;

    // Step 4: Gamma = x*H. H has prime order q (cofactor already cleared,
    // identity already excluded by encodeToCurve) and clamped x is never 0
    // mod q, so neither of std's two rejections could ever have fired here
    // — they were pure secret-dependent branches, which is why
    // `ct25519.mul` drops them rather than keeping a `catch unreachable`.
    const gamma_point = ct25519.mul(h_point, exp.x);
    const gamma_string = gamma_point.toBytes();

    // Step 5: k = nonce_generation(SK, h_string).
    var k_string = nonceStringFrom(sk, h_string);
    defer std.crypto.secureZero(u8, &k_string);
    var k = scalar.reduce64(k_string);
    // A1 E4: the secret nonce was never zeroed — unlike `exp.x`/`exp.prefix`
    // just above, nothing wiped this function's own copy of `k` once it was
    // no longer needed. `s = k + c*x mod q` makes a leaked `k` equivalent to
    // a leaked `x` (`x = (s-k)*c^-1 mod q`), so this copy is exactly as
    // sensitive as the ones `defer secureZero(&exp.x)` already covers.
    defer std.crypto.secureZero(u8, &k);

    // Step 6: c = challenge_generation(Y, H, Gamma, k*B, k*H). `k` is the
    // secret nonce — the one scalar here that CAN legitimately be 0 mod q
    // (probability ~2^-252), and therefore the one whose rejection branch
    // was a genuine leak rather than dead code. `ct25519.mul`/`mulBase`
    // return the neutral element as a value; `verify` recomputes `U`/`V`
    // identically.
    const u_point = ct25519.mulBase(k);
    const v_point = ct25519.mul(h_point, k);
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
///
/// RFC 9381 §5.2 (A1 E13): "`ECVRF_proof_to_hash` should be run only on a
/// `pi_string` value that is known to have been produced by
/// `ECVRF_prove`, or from within `ECVRF_verify`" — i.e. NOT called
/// directly on an attacker-supplied `pi` a caller has not itself already
/// run `verify` on. This function only checks `pi`'s STRUCTURAL validity
/// (`decodeProof`); it has no way to check that `Gamma` was honestly
/// derived from `(PK_string, alpha_string)` by the claimed key holder —
/// that is exactly what `verify`'s challenge/response check establishes
/// and `proofToHash` alone does not. A caller who wants "the random
/// output for this `(pk, alpha, pi)`" should call `verify`, not this
/// function directly on unauthenticated `pi`.
pub fn proofToHash(pi: Proof) Error!Output {
    const d = try decodeProof(pi);
    const gamma_point = Edwards25519.fromBytes(d.gamma) catch unreachable; // decodeProof already validated
    return hashOutputFromGamma(gamma_point);
}

/// The tail of `ECVRF_proof_to_hash` (RFC 9381 §5.2), given an already
/// STRUCTURALLY-VALIDATED `Gamma` point rather than the raw `pi_string` —
/// factored out so `verify` doesn't have to re-decode `pi` and re-parse
/// `Gamma` a second time just to reach this hash (A1 E10 point 3: measured
/// ~9.2us of `verify`'s ~180us, 5.1%, was exactly that repeat of work
/// `verify` already has the result of).
fn hashOutputFromGamma(gamma_point: Edwards25519) Output {
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

    // Step 10: c' = challenge_generation(Y, H, Gamma, U, V), with
    // point_to_string(Gamma) as the RFC writes it (A1 E14). Since
    // `decodeProof` decodes strictly, this is byte-for-byte `d.gamma`.
    const c_prime = challengeGeneration(y_string, h_string, gamma_point.toBytes(), u_point.toBytes(), v_point.toBytes());

    // Step 11: accept iff c == c'.
    if (!std.crypto.timing_safe.eql([c_len]u8, c_prime, d.c)) return error.InvalidProof;
    // A1 E10 point 3: was `proofToHash(pi) catch unreachable`, which
    // re-decoded `pi` (re-checking `s`'s canonicity and re-parsing `Gamma`'s
    // curve-point encoding, both already done above via `decodeProof`/
    // `gamma_point`) purely to reach the same hash tail. `gamma_point` here
    // is bit-for-bit `Edwards25519.fromBytes(d.gamma)` on the SAME `pi`, so
    // this is the identical output, not an approximation of it.
    return hashOutputFromGamma(gamma_point);
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

// The ladder's own correctness oracle ("agrees with std's Edwards25519.mul
// on every nonzero scalar, base point and non-base point alike") and its
// "neutral element is a VALUE, not error.IdentityElement" pin now live in
// `ct25519`'s own test suite (`modules/ct25519/src/root.zig`: "mul:
// bit-exact against std's Edwards25519.mul on the base point", "... on
// non-base points", and "mul: the neutral element is a VALUE, where std
// raises an error") — this module used to carry a private copy of both
// checks alongside its private copy of the ladder; now that the ladder is
// `ct25519.mul`/`mulBase`, so is the coverage. Not re-duplicated here.

test "every secret-scalar multiply in this module is total (no error union to branch on)" {
    // Structural, not behavioural: the leak the constant-time ladder closes
    // is a TIMING property, and a revert that keeps the branch but
    // swallows the error (`catch identityElement`) is behaviourally
    // indistinguishable. What is NOT indistinguishable is the signature —
    // an error union is what forces a second, caller-side, secret-dependent
    // branch. `ct25519.mul`/`mulBase` are pinned total in their own test
    // suite ("mul: carries no error set, so no call site can branch on the
    // scalar"); `publicKey` and `prove` are likewise total here: neither
    // can report, or branch on, "your secret scalar was zero".
    try std.testing.expectEqual(PublicKey, @typeInfo(@TypeOf(publicKey)).@"fn".return_type.?);
    try std.testing.expectEqual(Proof, @typeInfo(@TypeOf(prove)).@"fn".return_type.?);

    // The defect being worked around, pinned at its source.
    try std.testing.expect(@typeInfo(@typeInfo(@TypeOf(Edwards25519.mul)).@"fn".return_type.?) == .error_union);
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
        const pk = publicKey(&sk);

        var alpha_wide: [64]u8 = undefined;
        Sha512.hash(&[_]u8{ 'e', 'c', 'v', 'r', 'f', 'a', 'l', i }, &alpha_wide, .{});
        const alpha: [4]u8 = alpha_wide[0..4].*;

        const pi = prove(&sk, &alpha);
        const beta_direct = try proofToHash(pi);
        const beta_verify = try verify(pk, &alpha, pi);
        try std.testing.expectEqualSlices(u8, &beta_direct, &beta_verify);

        // Wrong alpha must reject.
        var wrong_alpha = alpha;
        wrong_alpha[0] ^= 0x01;
        try std.testing.expectError(error.InvalidProof, verify(pk, &wrong_alpha, pi));
    }
}

test "verify: no longer re-decodes pi to reach proofToHash's tail (audit E10 point 3, informational)" {
    // Print-only, no threshold assertion: the audited saving is ~5.1% of
    // `verify`'s total cost (9.2us / 179.9us), which is too small a margin
    // to assert on reliably against a shared, possibly-loaded machine (this
    // audit's own numbers were taken at load 5.7 from concurrent agents).
    // Kept as a standing measurement for whoever next touches this path,
    // not as a pass/fail gate.
    //
    // Opt-in, like every other bench in this repo (`K256_BENCH`, `TC_BENCH`, …):
    // a test that asserts nothing and prints unconditionally is counted as a
    // PASS while the lane turns its stderr into a FAIL (scripts/test-lib.sh).
    // Skipping when unasked says what this is; printing said it every run.
    if (std.process.Environ.getPosix(std.testing.environ, "ECVRF_BENCH") == null) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sk_wide: [64]u8 = undefined;
    Sha512.hash("ecvrf-e10-perf-sk", &sk_wide, .{});
    const sk: SecretKey = sk_wide[0..32].*;
    const pk = publicKey(&sk);
    const alpha = "ecvrf-e10-perf-alpha";
    const pi = prove(&sk, alpha);

    const iters = 400;
    const start = std.Io.Clock.Timestamp.now(io, .awake);
    var i: usize = 0;
    while (i < iters) : (i += 1) std.mem.doNotOptimizeAway(verify(pk, alpha, pi) catch unreachable);
    const elapsed_ns = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    std.debug.print(
        "verify: {d:.0} ns/op over {d} iters\n",
        .{ @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iters)), iters },
    );
}

// ── fuzz harnesses (untrusted-wire decoders) ────────────────────────────

const fz = @import("fuzz_test.zig");
const DecodeMark = fz.Marker(enum { accepted, refused, canonical });
const VerifyMark = fz.Marker(enum { accepted, bad_key, bad_proof, bad_challenge });
const ProveVerifyMark = fz.Marker(enum { genuine_accepted, flipped_refused, wrong_alpha_refused, wrong_key_refused });

const testkit = @import("testkit");

fn drawProof(comptime S: type, src: *S, pi: *Proof) void {
    // Under the driver half the proofs are a real one with 0-3 octets damaged.
    if (S != fz.fuzz_driver.Rng or !src.value(bool)) {
        src.bytes(pi);
        return;
    }
    const sk: SecretKey = @splat(src.value(u8));
    const pi0 = prove(&sk, "fuzz");
    var tmp: [proof_len]u8 = undefined;
    const n = fz.damage(src, &tmp, &pi0);
    @memset(pi, 0);
    @memcpy(pi[0..n], tmp[0..n]);
}

test "fuzz: decodeProof never crashes on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzDecodeProofSmith, .{});
}

test "fuzz driver: ECVRF_FUZZ (decode proof)" {
    try fz.fuzz_driver.run(fuzzDecodeProof, .{ .prefix = "ECVRF_FUZZ", .name = "ecvrf-decode-proof" });
}

test "fuzz harness: decode proof, 300 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecodeProof, "ecvrf-decode-proof", 300);
}

fn fuzzDecodeProofSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDecodeProof(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzDecodeProof(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var pi: Proof = undefined;
    drawProof(S, src, &pi);
    const d = decodeProof(pi) catch {
        DecodeMark.mark(.refused);
        return;
    };
    DecodeMark.mark(.accepted);
    // Canonical: what decodes re-encodes to the very bytes it came from
    // (no proof has a second spelling), and the split is lossless.
    const g = try stringToPoint(d.gamma);
    if (!std.mem.eql(u8, &g.toBytes(), pi[0..pt_len])) return error.GammaNotCanonical;
    if (!std.mem.eql(u8, &d.c, pi[pt_len..][0..c_len]) or !std.mem.eql(u8, &d.s, pi[pt_len + c_len ..])) return error.SplitLossy;
    DecodeMark.mark(.canonical);
}

test "fuzz: verify never crashes on arbitrary pk/proof bytes" {
    try std.testing.fuzz({}, fuzzVerifySmith, .{});
}

test "fuzz driver: ECVRF_FUZZ (verify)" {
    try fz.fuzz_driver.run(fuzzVerify, .{ .prefix = "ECVRF_FUZZ", .name = "ecvrf-verify", .scale = 2 });
}

test "fuzz harness: verify, 300 seeds, reaches every outcome" {
    try VerifyMark.reach(fuzzVerify, "ecvrf-verify", 300);
}

fn fuzzVerifySmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzVerify(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var pk: PublicKey = undefined;
    var pi: Proof = undefined;
    if (S == fz.fuzz_driver.Rng and src.value(bool)) {
        // A real (pk, alpha, proof) with 0-3 octets of the pair damaged.
        const sk: SecretKey = @splat(src.value(u8));
        pk = publicKey(&sk);
        pi = prove(&sk, "fuzz");
        var both: [pt_len + proof_len]u8 = undefined;
        @memcpy(both[0..pt_len], &pk);
        @memcpy(both[pt_len..], &pi);
        var tmp: [pt_len + proof_len]u8 = undefined;
        _ = fz.damage(src, &tmp, &both);
        pk = tmp[0..pt_len].*;
        pi = tmp[pt_len..][0..proof_len].*;
    } else {
        src.bytes(&pk);
        src.bytes(&pi);
    }
    const alpha = "fuzz";
    const out = verify(pk, alpha, pi) catch |e| {
        if (e == error.InvalidPublicKey) {
            VerifyMark.mark(.bad_key);
        } else if (decodeProof(pi)) |_| {
            VerifyMark.mark(.bad_challenge);
        } else |_| VerifyMark.mark(.bad_proof);
        return;
    };
    VerifyMark.mark(.accepted);
    // What verifies yields exactly the hash of its Gamma.
    const again = try proofToHash(pi);
    if (!std.mem.eql(u8, &out, &again)) return error.HashMismatch;
}

test "fuzz: a genuine proof verifies and every damaged copy is refused" {
    try std.testing.fuzz({}, fuzzProveVerifySmith, .{});
}

test "fuzz driver: ECVRF_FUZZ (prove + verify)" {
    try fz.fuzz_driver.run(fuzzProveVerify, .{ .prefix = "ECVRF_FUZZ", .name = "ecvrf-prove-verify", .scale = 4 });
}

test "fuzz harness: prove + verify, 100 seeds, reaches every outcome" {
    try ProveVerifyMark.reach(fuzzProveVerify, "ecvrf-prove-verify", 100);
}

fn fuzzProveVerifySmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzProveVerify(std.testing.Smith, smith, std.testing.allocator);
}

/// `prove` output is ACCEPTED by `verify` (and `proofToHash` agrees); a proof
/// with any one bit flipped, another alpha, or another key is REFUSED.
fn fuzzProveVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [96]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: testkit.fuzz.Cursor = .{ .bytes = raw[0..n] };
    var sk: SecretKey = undefined;
    for (&sk) |*b| b.* = k.byte();
    var alpha_buf: [40]u8 = undefined;
    for (&alpha_buf) |*b| b.* = k.byte();
    const alpha = alpha_buf[0..k.ranged(0, 40)];
    const pk = publicKey(&sk);
    const pi = prove(&sk, alpha);
    const out = verify(pk, alpha, pi) catch return error.GenuineProofRefused;
    if (!std.mem.eql(u8, &out, &(try proofToHash(pi)))) return error.HashMismatch;
    ProveVerifyMark.mark(.genuine_accepted);

    var bad = pi;
    bad[k.ranged(0, proof_len - 1)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (verify(pk, alpha, bad)) |_| return error.FlippedProofAccepted else |_| {}
    ProveVerifyMark.mark(.flipped_refused);

    var other_alpha: [41]u8 = undefined;
    @memcpy(other_alpha[0..alpha.len], alpha);
    other_alpha[alpha.len] = k.byte();
    if (verify(pk, other_alpha[0 .. alpha.len + 1], pi)) |_| return error.WrongAlphaAccepted else |_| {}
    ProveVerifyMark.mark(.wrong_alpha_refused);

    var other_sk = sk;
    other_sk[k.ranged(0, 31)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (verify(publicKey(&other_sk), alpha, pi)) |_| return error.WrongKeyAccepted else |_| {}
    ProveVerifyMark.mark(.wrong_key_refused);
}
