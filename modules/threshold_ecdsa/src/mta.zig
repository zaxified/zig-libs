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
//! ## Security scope — SEMI-HONEST ONLY
//!
//! This is the **correctness core** of MtA. It is secure against *passive*
//! (honest-but-curious) adversaries who follow the protocol, and is
//! **NOT** secure against a *malicious* party. In particular:
//!
//!   - **TODO(2c):** the GG20 zero-knowledge *range proofs* (proving `a`,
//!     `b`, `β'` lie in the agreed bounded ranges without revealing them —
//!     GG18 §3's "MtA with check" / the range-proof machinery that consumes
//!     this module's `AuxParams` ring-Pedersen commitment base) are the
//!     Phase-2c layer that upgrades this to malicious security. Without
//!     them a cheating party can e.g. feed an out-of-range `a`/`b` and leak
//!     the counterparty's secret. They are deliberately OUT OF SCOPE here.
//!   - **TODO(2c):** the "MtAwc" variant (MtA *with check*), which
//!     additionally proves Bob used the same `b` that appears in his public
//!     `B = b·G`, is likewise Phase-2c.
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
    const root = @import("root.zig");
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
