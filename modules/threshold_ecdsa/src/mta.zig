// SPDX-License-Identifier: MIT
//! mta — the multiplicative-to-additive (MtA) share-conversion protocol of
//! GG18/GG20 threshold-ECDSA, **semi-honest core only** (I2 Phase 2b).
//!
//! Setting: Alice holds a secret `a ∈ Zq`, Bob holds a secret `b ∈ Zq`
//! (`q` = secp256k1's group order). MtA lets them convert the *product*
//! `a·b` into an *additive* sharing: Alice ends up with `α ∈ Zq`, Bob with
//! `β ∈ Zq`, such that
//!
//! ```text
//!     α + β ≡ a · b   (mod q)
//! ```
//!
//! and neither party learns the other's secret input. This is the workhorse
//! GG20 signing invokes O(t²) times (to turn the multiplicative sharing of
//! `k·γ` / `k·x` implicit in the parties' Shamir shares into the additive
//! sharing the ECDSA signing equation needs).
//!
//! ## Construction (Paillier-based, GG18 §3)
//!
//! Built directly on the sibling `paillier` module's additively-homomorphic
//! ops — MtA is *literally* those ops composed:
//!
//! ```text
//!   Alice → Bob :  c_A = Enc_A(a)                    (mtaAliceInit)
//!   Bob:           β' ← Zq                           (fresh, uniform)
//!                  c_B = (b ⊙ c_A) ⊕ Enc_A(β')       (mtaBobResponse)
//!                      = Enc_A(a·b + β')             (homomorphically)
//!                  β  = −β' (mod q)
//!   Bob → Alice :  c_B
//!   Alice:         α' = Dec_A(c_B) = a·b + β'  (an integer, no wrap)
//!                  α  = α' (mod q)               (mtaAliceFinalize)
//! ```
//!
//! Then `α + β ≡ (a·b + β') − β' ≡ a·b (mod q)`. The `⊙`/`⊕` are
//! `paillier.mulPlaintext` (`c^b → Enc(b·m)`) and `paillier.addPlaintext`
//! (`c ⊕ g^{β'} → Enc(m + β')`).
//!
//! **β sign convention:** Bob's additive share is `β = −β' (mod q)` — the
//! *negation* of the plaintext blinding value `β'` he folds into `c_B`. This
//! is the load-bearing sign choice: `α` carries `+β'` (it decrypts
//! `a·b + β'`), so `β` must carry `−β'` for the two to cancel.
//!
//! **Z_N → Zq reduction:** `α' = Dec_A(c_B)` is a Paillier plaintext in
//! `[0, N)` (N = Alice's Paillier modulus). Because `a, b < q` and `β' < q`,
//! the integer `a·b + β' < q² + q`; as long as the Paillier modulus
//! satisfies `N > q² + q` (true for any real 2048-bit Paillier key, and for
//! the ≥1024-bit keys these tests use — see the range note below), the
//! homomorphic sum never wraps mod N, so `α'` *is* the true integer
//! `a·b + β'`. Alice reduces it into `Zq` with the curve's own wide
//! reduction `Scalar.fromBytes64` (`α'` fits in 64 bytes since
//! `a·b + β' < q² + q < 2^512`).
//!
//! ## Typing over `KeyShare`'s Paillier material
//!
//! The three entry points take `paillier.PublicKey`/`paillier.SecretKey`
//! directly, so the signing layer wires them straight from a
//! `threshold_ecdsa.KeyShare`:
//!
//!   - **Alice** (the party who will *finalize*, i.e. decrypt) uses her OWN
//!     Paillier keypair: `alice_pk` = `key_share.public_keys.get(alice_index)
//!     .?.paillier_pk`, `alice_sk` = `key_share.paillier_secret`.
//!   - **Bob** (the responder) uses *Alice's* public key, which he already
//!     holds in his own broadcast view: `key_share_bob.public_keys
//!     .get(alice_index).?.paillier_pk`. Bob never needs a secret key here.
//!
//! The additive shares `α`, `β` come back as `Secp256k1.scalar.Scalar` (Zq
//! field elements), ready to drop into the Phase-2c signing arithmetic.
//!
//! ## Security scope
//!
//! The three plain entry points (`mtaAliceInit`/`mtaBobResponse`/
//! `mtaAliceFinalize`) are the **semi-honest correctness core**: secure
//! against *passive* (honest-but-curious) adversaries only. The Phase-2c
//! layer is now REAL: the `*Checked` entry points below plus
//! `zkproofs.zig`'s GG18-Appendix-A range/MtA proofs (verified against
//! the actual paper — see that file's module doc comment) upgrade the
//! flow to malicious security, and `zkproofs.proveBobMtaWc`/
//! `verifyBobMtaWc` cover the "MtAwc" variant (Bob additionally proves
//! his `b` matches the public `B = b·G`).
//!
//! ## Const-time posture
//!
//! MtA touches secrets `a`, `b`, `α`, `β`, `β'` and Alice's Paillier secret
//! key. Every operation goes through an already-constant-time primitive:
//! `paillier.encrypt`/`mulPlaintext`/`addPlaintext`/`decrypt` use `ff`'s
//! constant-time `pow`/`mul` (Alice's secret exponent `lambda` never touches
//! `powPublic`; see `paillier`'s own timing note), and `Scalar.neg`/
//! `fromBytes64` are the curve's constant-time scalar-field ops. `β'` is
//! sampled from CSPRNG bytes via `Scalar.fromBytes64`'s constant-time wide
//! reduction. The one variable-time step is inside `paillier.decrypt`'s
//! `L`-function big-int division (a plaintext-derived value — see
//! `paillier`'s SPEC timing note); that is inherited, not introduced here.

const std = @import("std");
const paillier = @import("paillier");
const root = @import("root.zig");
const zkproofs = @import("zkproofs.zig");

/// secp256k1 scalar field Zq — the domain of MtA's inputs `a`, `b` and
/// additive outputs `α`, `β`. Same type `threshold_ecdsa`'s root module
/// exposes as `Scalar`.
pub const Scalar = std.crypto.ecc.Secp256k1.scalar.Scalar;

/// Errors MtA can surface, all inherited from the underlying `paillier`
/// homomorphic-PKE ops (this module introduces no new failure mode of its
/// own — every branch is either a `paillier` call or infallible curve
/// arithmetic).
pub const MtaError = paillier.EncryptError ||
    paillier.HomomorphicError ||
    paillier.DecryptError ||
    std.crypto.ff.OverflowError;

/// Encode a `Zq` scalar as a Paillier plaintext `Fe` canonical mod `n_sq`
/// (per `paillier`'s "Fe construction contract" — plaintexts/scalars used
/// as a base/exponent under `n_sq` must be constructed against `n_sq`, not
/// `n`). Every scalar value is `< q < n`, hence `< n_sq`, so the
/// canonicality check can never fire — `catch unreachable`.
fn scalarToFe(s: Scalar, pk: paillier.PublicKey) paillier.Fe {
    const bytes = s.toBytes(.big); // 32-byte big-endian, value < q
    return paillier.Fe.fromBytes(pk.n_sq, &bytes, .big) catch unreachable;
}

/// Sample a uniform `Zq` scalar from CSPRNG bytes (48-byte draw folded mod
/// `q` via the curve's constant-time wide reduction — statistically uniform
/// over `Zq`, same idiom as this module's test `Scalar`s and
/// `Scalar.random`'s own internal reduction).
fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

/// What Alice sends Bob to open an MtA instance: her Paillier encryption of
/// `a`. (Alice retains nothing from this step — `mtaAliceFinalize` needs
/// only `c_B` and her secret key.)
pub const AliceInit = struct {
    /// `c_A = Enc_A(a)` — send to Bob.
    c_a: paillier.Ciphertext,
};

/// **Alice, round 1.** `c_A = Enc_A(a)` under Alice's OWN Paillier public
/// key, freshly blinded (IND-CPA randomness sampled internally via
/// `paillier.encryptRandom`). Send `result.c_a` to Bob.
pub fn mtaAliceInit(a: Scalar, alice_pk: paillier.PublicKey, random: std.Random) MtaError!AliceInit {
    const a_fe = scalarToFe(a, alice_pk);
    const c_a = try paillier.encryptRandom(alice_pk, a_fe, random);
    return .{ .c_a = c_a };
}

/// What Bob produces: the response ciphertext for Alice, plus Bob's own
/// additive share `β` (which he keeps).
pub const BobResponse = struct {
    /// `c_B = Enc_A(a·b + β')` — send to Alice.
    c_b: paillier.Ciphertext,
    /// Bob's additive share `β = −β' (mod q)` — Bob KEEPS this (SECRET).
    beta: Scalar,
};

/// **Bob, round 2.** Given Alice's `c_A` and Alice's public key, Bob:
///   1. samples a fresh uniform `β' ∈ Zq`;
///   2. computes `c_B = (b ⊙ c_A) ⊕ Enc_A(β') = Enc_A(a·b + β')` via the
///      Paillier homomorphic ops (`mulPlaintext` then `addPlaintext`);
///   3. sets his additive share `β = −β' (mod q)`.
///
/// Send `result.c_b` to Alice; keep `result.beta`.
///
/// **Range precondition (semi-honest correctness):** requires Alice's
/// Paillier modulus `N > q² + q` so `a·b + β'` never wraps mod N — trivially
/// true for a real 2048-bit Paillier key (`q ≈ 2^256`, `q² ≈ 2^512 ≪ N`).
/// A malicious Bob could pick `β'` out of range to attack Alice; the
/// Phase-2c range proofs (TODO(2c)) are what forbid that.
pub fn mtaBobResponse(
    b: Scalar,
    c_a: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    random: std.Random,
) MtaError!BobResponse {
    const beta_prime = randomScalar(random);

    // c_B = Enc_A(a·b + β'): scale the encryption of a by the plaintext b,
    // then homomorphically add β'. (b = 0 is handled by mulPlaintext's k=0
    // case → Enc(0); β' = 0 is the addPlaintext identity — both still yield
    // a valid ciphertext that decrypts correctly.)
    const b_fe = scalarToFe(b, alice_pk);
    const bp_fe = scalarToFe(beta_prime, alice_pk);
    const c_ab = try paillier.mulPlaintext(alice_pk, c_a, b_fe);
    const c_b = try paillier.addPlaintext(alice_pk, c_ab, bp_fe);

    // β = −β' (mod q): the negation that makes α + β cancel β'.
    const beta = beta_prime.neg();

    return .{ .c_b = c_b, .beta = beta };
}

/// **Alice, finalize.** Decrypt Bob's `c_B` with Alice's secret key and
/// reduce the resulting plaintext `α' = a·b + β'` (an integer in `[0, N)`,
/// unwrapped by the range precondition above) into `Zq`, giving Alice's
/// additive share `α = α' (mod q)`. Guarantees `α + β ≡ a·b (mod q)`.
///
/// The plaintext `α' < q² + q < 2^512` fits in 64 bytes; `Scalar.fromBytes64`
/// performs the constant-time `mod q` reduction.
pub fn mtaAliceFinalize(c_b: paillier.Ciphertext, alice_sk: paillier.SecretKey) MtaError!Scalar {
    const alpha_fe = try paillier.decrypt(alice_sk, c_b); // = a·b + β' (mod n), no wrap

    // decrypt's Fe is backed by the FULL modulus width, so it must be
    // serialized into an `n`-wide buffer (Fe.toBytes rejects a buffer smaller
    // than the modulus, even when the value itself is small). The plaintext
    // α' = a·b + β' < q² + q < 2^512, so only its low 64 bytes are nonzero;
    // reduce those mod q via the curve's constant-time wide reduction. The
    // range precondition (N > q²+q, hence nByteLen > 64) guarantees the slice.
    const n_len = alice_sk.nByteLen();
    std.debug.assert(n_len >= 64);
    var wide: [paillier.modulus_bytes]u8 = [_]u8{0} ** paillier.modulus_bytes;
    defer std.crypto.secureZero(u8, wide[0..n_len]);
    try alpha_fe.toBytes(wide[0..n_len], .big);

    var buf: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    @memcpy(&buf, wide[n_len - 64 .. n_len]);
    return Scalar.fromBytes64(buf, .big); // reduce mod q
}

// ── Phase 2c: malicious-secure ("checked") MtA — REAL wiring + REAL proofs
//
// The three entry points below are the Phase-2c counterparts of
// `mtaAliceInit`/`mtaBobResponse`/`mtaAliceFinalize` above: same underlying
// arithmetic, PLUS the `zkproofs` range/MtA proofs that reject a malicious
// counterparty's out-of-range input before it can be used (see
// `zkproofs.zig`'s module doc comment for the Alpha-Rays/TSSHOCK threat
// model this closes). The semi-honest functions above are UNCHANGED and
// remain the Phase-2b path — nothing here alters their behavior or their
// already-passing tests.

/// Sample a Paillier ciphertext-level randomness value `r`, uniform in
/// `[1, pk.n)`, canonical mod `pk.n_sq` (the paillier module's own Fe-
/// construction-contract convention — see `scalarToFe`'s doc comment).
/// Mirrors `paillier`'s private `sampleNonzeroLtN` (not `pub`, so not
/// importable) — same rejection-sampling shape, duplicated locally per
/// this repo's established "small mechanical helper, copied per file"
/// convention (see e.g. `root.zig`/`rsa`'s own `stripLeadingZeros`
/// copies).
fn samplePaillierRandomness(pk: paillier.PublicKey, random: std.Random) paillier.Fe {
    const n_bits = pk.n.bits();
    const n_len = (n_bits + 7) / 8;
    var buf: [paillier.modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        // Bug fix (surfaced by `signing.zig`'s end-to-end driver, which runs
        // this sampler far more often per test than any prior caller): a
        // masked n_bits-wide draw is only < 2^n_bits, NOT necessarily < N —
        // this function's own doc comment promises `[1, pk.n)`. Checking
        // canonicality mod `pk.n_sq` alone (as this used to do) is nearly a
        // no-op (n_sq is ~2·n_bits wide, so it accepts almost everything,
        // including values in [N, 2^n_bits)) and was silently violating the
        // "r_a/r_b < N" witness precondition `zkproofs.zig`'s
        // `proveAliceRangeInner`/`proveBobInner` document and rely on
        // (`catch unreachable` on that exact invariant) — with real random
        // 1024-bit keys this fires often enough (observed ~10% of draws) to
        // crash real signing runs. Fix: reject-sample against `pk.n` itself
        // (canonicality mod N IS "< N"), THEN re-encode the same bytes mod
        // `n_sq` (always canonical there once it's `< N < n_sq`).
        const in_range = paillier.Fe.fromBytes(pk.n, buf[0..n_len], .big) catch continue;
        if (in_range.isZero()) continue;
        const r = paillier.Fe.fromBytes(pk.n_sq, buf[0..n_len], .big) catch unreachable; // < N < n_sq: always canonical
        return r;
    }
}

/// What `mtaAliceInitChecked` produces: `c_a` (send to Bob, same as
/// `AliceInit`), plus Alice's OWN Paillier encryption randomness `r_a` —
/// SECRET, and the ONE thing the semi-honest `mtaAliceInit` throws away
/// (it calls `paillier.encryptRandom`, which samples and discards its `r`
/// internally). `r_a` is exactly the witness `zkproofs.proveAliceRange`
/// needs to prove `c_a` is a well-formed, in-range encryption of `a`.
pub const AliceInitChecked = struct {
    /// `c_A = Enc_A(a; r_a)` — send to Bob.
    c_a: paillier.Ciphertext,
    /// SECRET. Retain until `zkproofs.proveAliceRange` has produced
    /// Alice's range proof, then zero it alongside `a`.
    r_a: paillier.Fe,
};

/// **Phase-2c Alice, round 1 — REAL plumbing.** Identical to `mtaAliceInit`
/// except it samples+retains `r_a` explicitly (via `encrypt` +
/// `samplePaillierRandomness`, rather than `encryptRandom`'s internal
/// sample-and-discard) so the caller can feed it to
/// `zkproofs.proveAliceRange`. Produces the exact same `c_a` distribution
/// as `mtaAliceInit` — this is not a different protocol, just a version
/// that keeps a value the semi-honest path doesn't need.
pub fn mtaAliceInitChecked(a: Scalar, alice_pk: paillier.PublicKey, random: std.Random) MtaError!AliceInitChecked {
    const a_fe = scalarToFe(a, alice_pk);
    const r_a = samplePaillierRandomness(alice_pk, random);
    const c_a = try paillier.encrypt(alice_pk, a_fe, r_a);
    return .{ .c_a = c_a, .r_a = r_a };
}

/// What `mtaBobResponseChecked` produces: `c_b` and `beta` (same role as
/// `BobResponse`), plus Bob's fresh Paillier blinding factor `r_b` —
/// SECRET, the witness `zkproofs.proveBobMta` needs.
pub const BobResponseChecked = struct {
    /// `c_B = Enc_A(a·b + β'; r_A^b · r_b)` — send to Alice. Decrypts to
    /// the identical plaintext `mtaBobResponse`'s `c_b` would (Paillier
    /// decryption does not depend on the ciphertext's randomness) — see
    /// this function's doc comment for why the RANDOMNESS differs.
    c_b: paillier.Ciphertext,
    /// Bob's additive share `β = −β' (mod q)` — SECRET, same convention
    /// as `BobResponse.beta`.
    beta: Scalar,
    /// SECRET. The fresh Paillier blinding factor folded into `c_b`'s
    /// additive term — retain until `zkproofs.proveBobMta` has produced
    /// Bob's MtA proof, then zero it alongside `b`/`beta_prime`.
    r_b: paillier.Fe,
};

/// **Phase-2c Bob, round 2 — REAL plumbing, differs from `mtaBobResponse`
/// in one load-bearing way.**
///
/// `mtaBobResponse` (Phase 2b) folds `β'` into `c_B` via
/// `paillier.addPlaintext`, whose `g^m` term carries NO extra Paillier
/// rerandomization (see that function's own doc comment: no `r^n`
/// factor) — fine for semi-honest correctness (the ciphertext already
/// inherits Alice's original `c_A` randomness raised to `b`), but it
/// leaves Bob with no randomness of his OWN to prove knowledge of. GG18's
/// Π^MtA proof (`zkproofs.proveBobMta`) needs Bob to prove a witness
/// `(b, β', r_b)` where `r_b` is a FRESH random Paillier blinding factor
/// HE chose — the verifier can compute `c_A^b` itself from the public
/// `c_A`, so only the fresh part needs proving (Alice's own `r_A` is her
/// secret; Bob never learns it and a proof about it can't require him
/// to).
///
/// This function therefore reconstructs `c_B` via `addCiphertexts` over
/// `mulPlaintext(c_A, b)` and a FRESH `encrypt(β'; r_b)`, instead of
/// `mtaBobResponse`'s `addPlaintext`. Both decrypt to the identical
/// `a·b + β'` — `mtaAliceFinalize`/`mtaAliceFinalizeChecked` accept
/// either output identically — but only THIS version's `result.r_b` is a
/// real witness for `zkproofs.proveBobMta`.
pub fn mtaBobResponseChecked(
    b: Scalar,
    c_a: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    random: std.Random,
) MtaError!BobResponseChecked {
    const beta_prime = randomScalar(random);
    const b_fe = scalarToFe(b, alice_pk);
    const bp_fe = scalarToFe(beta_prime, alice_pk);
    const r_b = samplePaillierRandomness(alice_pk, random);

    const c_ab = try paillier.mulPlaintext(alice_pk, c_a, b_fe);
    const bp_enc = try paillier.encrypt(alice_pk, bp_fe, r_b);
    const c_b = paillier.addCiphertexts(alice_pk, c_ab, bp_enc);

    const beta = beta_prime.neg();
    return .{ .c_b = c_b, .beta = beta, .r_b = r_b };
}

/// Errors `mtaAliceFinalizeChecked` can surface beyond `MtaError`: a
/// proof that fails `zkproofs.verifyBobMta`.
pub const MtaCheckedError = MtaError || error{InvalidMtaProof};

/// **Phase-2c Alice, finalize — fail-closed. REAL control flow + REAL
/// predicate.** Verifies Bob's `zkproofs.MtaProof` against Alice's OWN
/// view of `c_a` BEFORE ever decrypting `c_b` — a malicious Bob who fed
/// an out-of-range `b`/`β'` (the Alpha-Rays/TSSHOCK failure class — see
/// `zkproofs.zig`'s module doc comment / `SPEC.md`'s threat model) is
/// rejected here, never reaching `mtaAliceFinalize`'s decryption.
///
/// `verifier_aux` is ALICE's OWN `AuxParams` (she is the verifier here —
/// see `zkproofs.zig`'s "verifier-vs-prover aux-param ownership" note).
///
/// **The fail-closed CONTROL FLOW (verify-then-decrypt, reject on
/// failure) is REAL, and so is `zkproofs.verifyBobMta` now** (GG18
/// Appendix A.3, implemented and verified against the paper) — the
/// end-to-end test at the bottom of this file exercises the full round
/// and asserts a tampered `c_b`/wrong-witness proof is refused before
/// decryption.
pub fn mtaAliceFinalizeChecked(
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    proof: zkproofs.MtaProof,
    alice_sk: paillier.SecretKey,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
) MtaCheckedError!Scalar {
    if (!zkproofs.verifyBobMta(proof, c_a, c_b, alice_pk, verifier_aux)) {
        return error.InvalidMtaProof;
    }
    return mtaAliceFinalize(c_b, alice_sk);
}

// ── tests ──────────────────────────────────────────────────────────────────
//
// No external KAT exists for MtA (like threshold-BLS/paillier) — the
// decisive net is the additive-sharing identity α + β ≡ a·b (mod q), checked
// over many random (a, b) plus edge cases, with a real-Paillier-key
// composition test to prove the pieces compose over KeyShare material.

const testing = std.testing;

fn scalarFromU64(v: u64) Scalar {
    var buf = [_]u8{0} ** 48;
    std.mem.writeInt(u64, buf[40..48], v, .big);
    return Scalar.fromBytes48(buf, .big);
}

/// Run one full MtA instance and return (α, β).
fn runMta(
    a: Scalar,
    b: Scalar,
    pk: paillier.PublicKey,
    sk: paillier.SecretKey,
    random: std.Random,
) !struct { alpha: Scalar, beta: Scalar } {
    const alice = try mtaAliceInit(a, pk, random);
    const bob = try mtaBobResponse(b, alice.c_a, pk, random);
    const alpha = try mtaAliceFinalize(bob.c_b, sk);
    return .{ .alpha = alpha, .beta = bob.beta };
}

/// Assert α + β ≡ a·b (mod q).
fn expectAdditiveShare(a: Scalar, b: Scalar, alpha: Scalar, beta: Scalar) !void {
    const sum = alpha.add(beta); // α + β (mod q)
    const prod = a.mul(b); // a · b (mod q)
    try testing.expectEqualSlices(u8, &prod.toBytes(.big), &sum.toBytes(.big));
}

test "MtA correctness: α + β ≡ a·b (mod q) over many random (a,b)" {
    // One reusable 1024-bit Paillier key (N ≈ 2^1024 ≫ q²+q ≈ 2^512, so the
    // homomorphic sum a·b+β' never wraps for full-range a,b). Kept fast by
    // reusing the key across every (a,b) draw.
    var kprng = std.Random.DefaultPrng.init(0x6d7461_6b6579); // "mta key"
    const kp = try paillier.generate(kprng.random(), 1024);

    var prng = std.Random.DefaultPrng.init(0x6d74615f72616e64); // "mta_rand"
    const random = prng.random();

    var i: usize = 0;
    while (i < 24) : (i += 1) {
        const a = randomScalar(random);
        const b = randomScalar(random);
        const r = try runMta(a, b, kp.public, kp.secret, random);
        try expectAdditiveShare(a, b, r.alpha, r.beta);
    }
}

test "MtA correctness: edge cases a/b ∈ {0, 1, q-1}" {
    var kprng = std.Random.DefaultPrng.init(0x656467_65); // "edge"
    const kp = try paillier.generate(kprng.random(), 1024);
    var prng = std.Random.DefaultPrng.init(0x6564676572616e64);
    const random = prng.random();

    const zero = Scalar.zero;
    const one = Scalar.one;
    const q_minus_1 = Scalar.zero.sub(Scalar.one); // −1 ≡ q−1 (mod q), the largest scalar
    const mid = scalarFromU64(0x123456789abcdef);

    const cases = [_][2]Scalar{
        .{ zero, zero },
        .{ zero, mid },
        .{ mid, zero },
        .{ one, one },
        .{ one, mid },
        .{ mid, one },
        .{ q_minus_1, q_minus_1 }, // (q−1)² — the tightest range case
        .{ q_minus_1, one },
        .{ q_minus_1, mid },
        .{ mid, q_minus_1 },
    };

    for (cases) |c| {
        const r = try runMta(c[0], c[1], kp.public, kp.secret, random);
        try expectAdditiveShare(c[0], c[1], r.alpha, r.beta);
    }
}

test "MtA composes over real keygenTrustedDealer KeyShare Paillier material" {
    // `root` is now a top-level import (added for Phase 2c's
    // `mtaAliceFinalizeChecked`) — this test used to import it locally,
    // back when mta.zig had no top-level dependency on root.zig.
    const allocator = testing.allocator;

    var kprng = std.Random.DefaultPrng.init(0x636f6d706f7365); // "compose"
    const krandom = kprng.random();

    // Two parties, each a real (small-but-real) 1024-bit Paillier keypair —
    // large enough that even full-range a·b never wraps mod N.
    const kp_alice = try paillier.generate(krandom, 1024);
    const kp_bob = try paillier.generate(krandom, 1024);
    const paillier_keys = [_]paillier.KeyPair{ kp_alice, kp_bob };

    // Toy aux params (MtA's semi-honest core doesn't consume them; they only
    // need to exist to assemble a KeyShare — the range proofs that DO use
    // them are Phase 2c).
    const n_tilde = root.AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
    const aux: root.AuxParams = .{
        .n_tilde = n_tilde,
        .h1 = root.AuxFe.fromBytes(n_tilde, &[_]u8{5}, .big) catch unreachable,
        .h2 = root.AuxFe.fromBytes(n_tilde, &[_]u8{25}, .big) catch unreachable,
    };
    const aux_params = [_]root.AuxParams{ aux, aux };

    const secret = scalarFromU64(0xa11ce);
    const coeffs = [_]Scalar{scalarFromU64(0xb0b)};
    const key_shares = try root.keygenTrustedDealer(allocator, 2, 2, secret, &coeffs, &paillier_keys, &aux_params);
    defer allocator.free(key_shares);
    defer allocator.free(key_shares[0].public_keys.entries);

    // Alice = party 1 (finalizer): her OWN pubkey (from her broadcast view)
    // + her secret key. Bob = party 2: uses Alice's pubkey from HIS view.
    const alice_index: u32 = 1;
    const alice_pk = key_shares[0].public_keys.get(alice_index).?.paillier_pk;
    const alice_sk = key_shares[0].paillier_secret;
    const bobs_view_of_alice_pk = key_shares[1].public_keys.get(alice_index).?.paillier_pk;

    var prng = std.Random.DefaultPrng.init(0x6d74615f636f6d70);
    const random = prng.random();

    // Arbitrary secret inputs (in a real signing round these are functions
    // of the parties' k/γ shares; here they just exercise the plumbing).
    const a = scalarFromU64(0xdeadbeef);
    const b = scalarFromU64(0xfeedface);

    const alice = try mtaAliceInit(a, alice_pk, random);
    const bob = try mtaBobResponse(b, alice.c_a, bobs_view_of_alice_pk, random);
    const alpha = try mtaAliceFinalize(bob.c_b, alice_sk);
    try expectAdditiveShare(a, b, alpha, bob.beta);
}

// ── Phase 2c wiring tests ────────────────────────────────────────────────
//
// `mtaAliceInitChecked`/`mtaBobResponseChecked` are REAL (just a different,
// witness-retaining composition of the same `paillier` primitives) — the
// tests below assert their OWN correctness net (α + β ≡ a·b, same as
// Phase 2b) directly, decrypting via the semi-honest `mtaAliceFinalize`;
// the malicious-secure `mtaAliceFinalizeChecked` path (which verifies
// `zkproofs.verifyBobMta` fail-closed before decrypting) has its own
// dedicated accept/reject tests below.

test "Phase 2c checked init/response compose correctly: α + β ≡ a·b (mod q), same as Phase 2b" {
    var kprng = std.Random.DefaultPrng.init(0x636865636b6564); // "checked"
    const kp = try paillier.generate(kprng.random(), 1024);

    var prng = std.Random.DefaultPrng.init(0x636b645f72616e64); // "ckd_rand"
    const random = prng.random();

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const a = randomScalar(random);
        const b = randomScalar(random);

        const alice = try mtaAliceInitChecked(a, kp.public, random);
        const bob = try mtaBobResponseChecked(b, alice.c_a, kp.public, random);
        const alpha = try mtaAliceFinalize(bob.c_b, kp.secret); // Phase-2b finalize; correctness is randomness-independent
        try expectAdditiveShare(a, b, alpha, bob.beta);
    }
}

test "Phase 2c: mtaBobResponseChecked's c_b differs byte-for-byte from mtaBobResponse's (fresh r_b changes the ciphertext, not the plaintext)" {
    var kprng = std.Random.DefaultPrng.init(0x64696666_6572); // "differ"
    const kp = try paillier.generate(kprng.random(), 1024);

    var prng = std.Random.DefaultPrng.init(0x646966665f726e64); // "diff_rnd"
    const random = prng.random();

    const a = scalarFromU64(0x1234);
    const b = scalarFromU64(0x5678);

    // Same c_a fed to both the semi-honest and checked Bob-response paths.
    const alice = try mtaAliceInit(a, kp.public, random);

    const bob_semi = try mtaBobResponse(b, alice.c_a, kp.public, random);
    const bob_checked = try mtaBobResponseChecked(b, alice.c_a, kp.public, random);

    var semi_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try bob_semi.c_b.toBytes(&semi_buf);
    var checked_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try bob_checked.c_b.toBytes(&checked_buf);
    // Different randomness (β' is independently sampled AND checked's path
    // folds in a fresh r_b) makes byte-equality astronomically unlikely.
    try testing.expect(!std.mem.eql(u8, &semi_buf, &checked_buf));

    // Both still decrypt to a valid additive sharing of a*b (with their
    // OWN respective beta), proving the differently-randomized c_b is
    // still a correct ciphertext, not just a differently-shaped one.
    const alpha_checked = try mtaAliceFinalize(bob_checked.c_b, kp.secret);
    try expectAdditiveShare(a, b, alpha_checked, bob_checked.beta);
}

test "Phase 2c end-to-end: mtaAliceInitChecked -> verifyAliceRange -> mtaBobResponseChecked -> proveBobMta -> mtaAliceFinalizeChecked, alpha + beta == a*b; fail-closed on tampering" {
    // The FULL malicious-secure MtA round over real Paillier keys and
    // real-composite ring-Pedersen aux params — every arrow in the title
    // is the real production call. This is the wiring counterpart of
    // zkproofs.zig's own proof-level accept/reject tests.
    var kprng = std.Random.DefaultPrng.init(0x66696e616c697a65); // "finalize"
    const krandom = kprng.random();
    const kp = try paillier.generate(krandom, 1024);
    var prng = std.Random.DefaultPrng.init(0x66696e5f72616e64); // "fin_rand"
    const random = prng.random();

    // Real-composite aux params (Ñ = a genuine 512-bit two-prime product,
    // h1 a square, h2 = h1^lambda) — same construction root.zig's
    // generateAuxParams produces, minus the slow safe-prime search (the
    // proofs' completeness/reject behavior doesn't depend on safe primes).
    // Shared by both verification directions in this test; in a real
    // deployment each VERIFIER uses its own tuple (see zkproofs.zig's
    // ownership note).
    const nt_kp = try paillier.generate(krandom, 512);
    var nt_buf: [paillier.modulus_bytes]u8 = undefined;
    const nt_len = nt_kp.public.nByteLen();
    nt_kp.public.nToBytes(nt_buf[0..nt_len]) catch unreachable;
    var strip: usize = 0;
    while (strip < nt_len and nt_buf[strip] == 0) : (strip += 1) {}
    const n_tilde = root.AuxModulus.fromBytes(nt_buf[strip..nt_len], .big) catch unreachable;
    const x_root = samplePaillierRandomness(nt_kp.public, random); // reuse: uniform < Ñ
    var x_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    const nt_sq_len = (nt_kp.public.n_sq.bits() + 7) / 8;
    x_root.toBytes(x_buf[0..nt_sq_len], .big) catch unreachable;
    var xs: usize = 0;
    while (xs < nt_sq_len and x_buf[xs] == 0) : (xs += 1) {}
    const x_fe = root.AuxFe.fromBytes(n_tilde, x_buf[xs..nt_sq_len], .big) catch unreachable;
    const h1 = n_tilde.sq(x_fe);
    const h2 = n_tilde.sq(h1); // h2 = h1² = h1^lambda for lambda = 2 — a valid squares-subgroup pair for this test
    const aux: root.AuxParams = .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };

    const a = scalarFromU64(0xdead_a11ce);
    const b = scalarFromU64(0xfeed_b0b);

    // Alice round 1 + her range proof; Bob verifies it before doing any
    // homomorphic work on c_a (his fail-closed gate).
    const alice = try mtaAliceInitChecked(a, kp.public, random);
    const alice_proof = try zkproofs.proveAliceRange(testing.allocator, a, alice.r_a, kp.public, aux, random);
    defer alice_proof.deinit(testing.allocator);
    try testing.expect(zkproofs.verifyAliceRange(alice_proof, alice.c_a, kp.public, aux));

    // Bob round 2 + his MtA proof (beta_prime = -beta mod q, the witness
    // mtaBobResponseChecked folded into c_b).
    const bob = try mtaBobResponseChecked(b, alice.c_a, kp.public, random);
    const beta_prime = bob.beta.neg();
    const bob_proof = try zkproofs.proveBobMta(testing.allocator, b, beta_prime, bob.r_b, alice.c_a, bob.c_b, kp.public, aux, random);
    defer bob_proof.deinit(testing.allocator);

    // Alice finalize: verify-then-decrypt, and the additive sharing holds.
    const alpha = try mtaAliceFinalizeChecked(alice.c_a, bob.c_b, bob_proof, kp.secret, kp.public, aux);
    try expectAdditiveShare(a, b, alpha, bob.beta);

    // Fail-closed: a tampered c_b (proof no longer matches) must be
    // REFUSED before decryption, not decrypted-then-shrugged-at.
    const one_fe = paillier.Fe.fromPrimitive(u64, kp.public.n_sq, 1) catch unreachable;
    const c_b_bad = try paillier.addPlaintext(kp.public, bob.c_b, one_fe);
    try testing.expectError(error.InvalidMtaProof, mtaAliceFinalizeChecked(alice.c_a, c_b_bad, bob_proof, kp.secret, kp.public, aux));

    // Fail-closed: a proof produced for a DIFFERENT b must be refused too.
    const bad_proof = try zkproofs.proveBobMta(testing.allocator, b.add(Scalar.one), beta_prime, bob.r_b, alice.c_a, bob.c_b, kp.public, aux, random);
    defer bad_proof.deinit(testing.allocator);
    try testing.expectError(error.InvalidMtaProof, mtaAliceFinalizeChecked(alice.c_a, bob.c_b, bad_proof, kp.secret, kp.public, aux));
}
