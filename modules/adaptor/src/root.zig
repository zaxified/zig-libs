// SPDX-License-Identifier: MIT
//! adaptor — Schnorr adaptor signatures ("one-time verifiably encrypted
//! signatures" / scriptless scripts) over BIP340 Schnorr on secp256k1: the
//! primitive behind PTLCs (point-time-locked contracts) in Lightning and
//! atomic swaps. Builds directly on the sibling `bip340` module for tagged
//! hashing, x-only key/signature handling, and — crucially — the exact
//! challenge tag, so `adapt`'s output is a plain, ordinary BIP340 signature
//! (any BIP340 verifier, including `bip340.verify` itself, accepts it with
//! no idea an adaptor scheme produced it).
//!
//! **Status: complete — the wire codecs (`AdaptorPoint`, `PreSignature`) and
//! all four crypto cores (`preSign`, `preVerify`, `adapt`, `extract`) are
//! implemented and KAT-validated.** Each core's doc comment spells out the
//! exact construction, including the parity/`needs_negation` handling that is
//! this scheme's single subtlest correctness property — see `SPEC.md`'s threat
//! model. `kat_vectors.zig` carries six SELF-
//! AUTHORED, byte-exact reference vectors (no official BIP/spec exists for
//! Schnorr adaptor signatures — computed independently in Python from this
//! exact construction, cross-checked against `bip340`'s own verify
//! equation; see `NOTICE`) covering both `needs_negation` branches and both
//! the "secret key already even-y" / "needed BIP340 normalization"
//! branches. `kat_test.zig` asserts byte-exact `PreSign` output against all
//! six, plus the full round-trip property (`preVerify` accepts,
//! `bip340.verify` accepts the adapted signature, `extract` recovers the
//! exact adaptor secret, and every tamper — wrong `T`, wrong message,
//! wrong pre-signature — is rejected).
//!
//! Because a self-authored corpus cannot catch a convention error it shares
//! with the code, `interop_vectors.zig` additionally carries EXTERNAL vectors
//! captured from LLFourn/secp256kfun's `schnorr_fun::adaptor` (0BSD): twelve
//! pre-signatures that implementation ORIGINATED (which `preSign` here can
//! never produce — the nonce derivations differ by design), plus its verdict
//! on all six self-authored vectors. `interop_test.zig` asserts `preVerify`
//! accepts them, and that `adapt`/`extract` reproduce `decrypt_signature`/
//! `recover_decryption_key` byte-for-byte. The bytes are frozen, so those
//! tests are fully offline; see `NOTICE` for versions and the regeneration
//! command.
//!
//! Zig std GAP: yes, same shape as `bip340`/`musig2` — `std.crypto.ecc.
//! Secp256k1` supplies the curve group; this module supplies the adaptor-
//! signature-specific convention (the adapted-nonce point `R + T`, the
//! `needs_negation` parity bookkeeping, and the PreSign/PreVerify/Adapt/
//! Extract algorithms) on top. Clean-room from the public scriptless-
//! scripts literature; the exact parity/negation handling was additionally
//! cross-validated against `secp256kfun`'s `schnorr_fun::adaptor` module
//! (a named design reference, not a copied source — see `NOTICE`).

const std = @import("std");
const bip340 = @import("bip340");
const Secp256k1 = @import("k256").Secp256k1;
const Fe = Secp256k1.Fe;
const scalar_mod = Secp256k1.scalar;
const Scalar = scalar_mod.Scalar;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Schnorr adaptor signatures over BIP340 (scriptless scripts for Lightning PTLCs / atomic swaps) — preSign, adapt, extract.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys/points are plain value types
    .model_after = "Schnorr adaptor signatures / \"one-time verifiably encrypted signatures\" (the scriptless-scripts construction, as implemented by secp256kfun's schnorr_fun::adaptor module) layered on BIP340; the k256 module supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1), the sibling bip340 module supplies tagged hashing + x-only key/signature handling + the BIP340 challenge tag",
    .deps = .{ "bip340", "k256" },
};

// ── domain tags ─────────────────────────────────────────────────────────
//
// Unlike BIP340's/BIP327's tags (official BIP text), no BIP numbers a
// Schnorr adaptor-signature scheme — these two tag strings are THIS
// module's own choice, used only to get the same tagged-hash domain
// separation `bip340.taggedHash`'s construction provides generically (it
// is not itself BIP340-specific — `hash.zig`'s construction works for any
// comptime tag string). The FINAL challenge hash below deliberately does
// NOT get a new tag: it reuses `bip340.hash.challenge_tag` directly, by
// design (see `preSign`'s doc comment).
pub const aux_tag = "adaptor/aux";
pub const nonce_tag = "adaptor/nonce";

/// `int(bytes32) mod n`: the same reducing conversion `bip340`/`musig2`
/// use internally (a 32-byte hash output can exceed `n`; `Scalar.fromBytes`
/// would reject instead of reduce). Duplicated locally per `musig2`'s own
/// precedent — `bip340` does not export its private `reduceToScalar`.
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

// ── AdaptorPoint (33-byte compressed, general point) ───────────────────
//
// REAL — built directly on `std.crypto.ecc.Secp256k1.fromSec1`/
// `toCompressedSec1` (CONVENTIONS.md §1: prefer std). No crypto CORE logic
// lives here; only wire parsing.

pub const AdaptorPointError = error{InvalidAdaptorPoint};

/// The adaptor point `T = t·G` — the public "statement" half of the
/// adaptor secret `t` that `preSign` binds a pre-signature to, and that
/// `extract` later recovers from a completed signature. Unlike
/// `bip340.XOnlyPublicKey`, `T` is a GENERAL secp256k1 point: 33-byte
/// SEC1-compressed, with a real (possibly-ODD) y — the counterparty
/// choosing `t` (e.g. a Lightning PTLC's payment point, or a fresh random
/// scalar for a generic scriptless-script swap) has no reason to restrict
/// it to the even-y half of the curve, and nothing in this scheme requires
/// that. See `SPEC.md` for why this is NOT the same shape as an x-only key.
pub const AdaptorPoint = struct {
    bytes: [33]u8,

    pub const encoded_length = 33;

    /// Parses AND validates eagerly via `Secp256k1.fromSec1` (rejects a
    /// bad prefix byte, `x >= p`, or an `x` with no on-curve solution) —
    /// mirrors `musig2.PlainPublicKey.fromBytes`'s eager-parse convention
    /// for the identical reason: a 33-byte compressed point can encode
    /// either y-parity, unlike a 32-byte x-only key.
    pub fn fromBytes(bytes: [33]u8) AdaptorPointError!AdaptorPoint {
        _ = Secp256k1.fromSec1(&bytes) catch return error.InvalidAdaptorPoint;
        return .{ .bytes = bytes };
    }

    /// The real secp256k1 point (whatever y-parity the prefix byte
    /// encodes). Re-validates so this is safe on hand-constructed values.
    pub fn point(t: AdaptorPoint) AdaptorPointError!Secp256k1 {
        return Secp256k1.fromSec1(&t.bytes) catch error.InvalidAdaptorPoint;
    }

    /// `T = t·G` from the adaptor SECRET `t` directly — the usual way a
    /// counterparty derives the public `AdaptorPoint` it hands to the
    /// presigner.
    pub fn fromSecret(adaptor_secret: [32]u8) AdaptorPointError!AdaptorPoint {
        const p = Secp256k1.combMulBase(adaptor_secret, .big) catch return error.InvalidAdaptorPoint;
        return .{ .bytes = p.toCompressedSec1() };
    }

    pub fn toBytes(t: AdaptorPoint) [33]u8 {
        return t.bytes;
    }
};

// ── PreSignature (65-byte: 32-byte x-only r || 32-byte s' || 1-byte flag) ─
//
// REAL — pure wire codec, range-checked exactly like `bip340.Signature`.

pub const PreSignatureError = error{InvalidPreSignature};

/// A Schnorr adaptor pre-signature (the literature's "encrypted
/// signature"): `r` — 32 bytes, the x-only nonce commitment, ALWAYS the
/// EVEN-y representative of `R + T` (`R` = the presigner's own local
/// nonce point, `T` = the adaptor point) — same shape/convention as a
/// plain `bip340.Signature.r`; `s_prime` — 32 bytes, the pre-signature
/// scalar (the literature's `s'`/`s_hat`); `needs_negation` — whether
/// `R + T` itself had ODD y before being canonicalized into `r`'s even-y
/// representative.
///
/// `needs_negation` is NOT redundant, and NOT recomputable by a verifier:
/// only the presigner (who alone knows the local nonce `R` before folding
/// in the public `T`) can observe the TRUE, uncanonicalized parity of
/// `R + T`. A verifier holding only `r` (x-only, canonical even-y) and `T`
/// cannot recover that parity bit — both `lift_x(r) + T` and
/// `lift_x(r) - T` are equally valid candidate points, and nothing about
/// `r`/`T` alone picks the right one. This is the central parity subtlety
/// of Schnorr adaptor signatures (cross-validated against secp256kfun's
/// `schnorr_fun::adaptor::EncryptedSignature.needs_negation` field, which
/// exists for the exact same reason — see `SPEC.md` and `NOTICE`).
pub const PreSignature = struct {
    r: [32]u8,
    s_prime: [32]u8,
    needs_negation: bool,

    pub const encoded_length = 65;

    /// Parse a 65-byte pre-signature. Rejects a non-canonical `r`
    /// (`r >= p`), a non-canonical `s_prime` (`s_prime >= n`) — the same
    /// two range checks `bip340.Signature.fromBytes` performs on a plain
    /// signature — and a flag byte other than `0`/`1`.
    pub fn fromBytes(bytes: [65]u8) PreSignatureError!PreSignature {
        const r = bytes[0..32].*;
        const s_prime = bytes[32..64].*;
        _ = Fe.fromBytes(r, .big) catch return error.InvalidPreSignature;
        _ = Scalar.fromBytes(s_prime, .big) catch return error.InvalidPreSignature;
        const flag = bytes[64];
        if (flag > 1) return error.InvalidPreSignature;
        return .{ .r = r, .s_prime = s_prime, .needs_negation = flag == 1 };
    }

    pub fn toBytes(ps: PreSignature) [65]u8 {
        var out: [65]u8 = undefined;
        out[0..32].* = ps.r;
        out[32..64].* = ps.s_prime;
        out[64] = @intFromBool(ps.needs_negation);
        return out;
    }
};

// ── crypto cores (implemented + KAT-validated — see each doc comment) ──

pub const PreSignError = error{
    InvalidSecretKey,
    InvalidAdaptorPoint,
    /// Step 4's `k0 == 0`, or step 5's `R + T` landing exactly on the
    /// point at infinity (only possible if `T == -R`) — both
    /// negligible-probability-for-honest-inputs guards, mirroring
    /// `bip340.SignError.InvalidNonce`.
    InvalidNonce,
    /// The mandatory self-verification (this function's step 9) failed —
    /// never returned by a correct implementation on correct hardware;
    /// exists to fail CLOSED under fault injection / silent corruption
    /// rather than emit a maybe-bad pre-signature (same philosophy as
    /// `bip340.sign`'s step-10 self-check / `musig2.sign`'s self-verify).
    PreSignatureVerificationFailed,
};

/// Schnorr **PreSign** (a.k.a. "encrypted sign" — secp256kfun's
/// terminology): produces a *pre-signature* cryptographically bound to the
/// adaptor point `T = t·G`, which `adapt` later completes into an ordinary
/// BIP340 signature once the adaptor SECRET `t` is known — and which
/// `extract` can turn back into `t` once that completed signature is
/// public. This is the whole "encryption" in "encrypted signature": the
/// pre-signature is a signature encrypted under `T`, decryptable only by
/// whoever knows `t`, and decrypting it leaks `t` to anyone who already
/// held the pre-signature.
///
/// Construction (clean-room from the public scriptless-scripts
/// literature; the exact parity/negation handling below was additionally
/// cross-validated against secp256kfun's `schnorr_fun::adaptor::
/// encrypted_sign` — see `NOTICE`):
///
/// 1. `d`, `P` = the even-y-normalized effective secret scalar and x-only
///    public key — `bip340.KeyPair.fromSecretKey(secret_key)`, EXACTLY
///    `bip340.sign`'s own steps 1-2 (this scheme reuses BIP340's key
///    normalization unchanged; `px = bytes(P)`).
/// 2. `t_pad = bytes(d) xor taggedHash(aux_tag, aux_rand)` — BIP340's own
///    aux-rand masking pattern (its step 3), reusing `bip340.taggedHash`
///    with THIS module's own `aux_tag`.
/// 3. `rand = taggedHash(nonce_tag, t_pad || px || bytes(T) || msg)` —
///    note `bytes(T)` (the 33-byte SEC1-compressed adaptor point,
///    `adaptor_point.toBytes()`) is folded into the nonce preimage,
///    UNLIKE plain BIP340 signing. This binds the nonce to the SPECIFIC
///    adaptor point: pre-signing the same message under two different
///    `T`s can then never reuse a nonce (secp256kfun's own
///    `derive_nonce!` includes its `Y` — this module's `T` — in its
///    public preimage for the identical reason).
/// 4. `k0 = int(rand) mod n`; fail (`error.InvalidNonce`) if `k0 == 0`.
/// 5. `R = k0·G` (`Secp256k1.basePoint.mul`); `R_hat = R + T` — a REAL
///    point addition (`T` is a general point, NOT x-only, so this is
///    `Secp256k1.add`, not a scalar operation); fail
///    (`error.InvalidNonce`) if `R_hat` is the point at infinity (only
///    possible if `T == -R`, negligible probability for an honestly
///    random `k0`, checked defensively per `bip340.sign`'s own precedent
///    on `R`).
/// 6. `needs_negation = has_odd_y(R_hat)`. `k = k0` if `!needs_negation`,
///    else `k = n - k0` — THE SAME constant-time masked byte-select
///    technique `bip340.sign`'s own step 7 / `musig2.sign`'s step 1 use
///    (never branch on the parity bit itself, which is derived from
///    secret nonce material). Crucially, negating `k0` does NOT change
///    `x(R_hat)` — negating a POINT flips only its y coordinate — so
///    `r = bytes(x(R_hat))` is the identical 32 bytes on both branches;
///    only `needs_negation` (and, downstream, `s_prime`) differs.
/// 7. `e = int(taggedHash(bip340.hash.challenge_tag, r || px || msg)) mod
///    n` — reuses BIP340's OWN challenge tag, NOT a new `adaptor`-scoped
///    one: the entire point of an adaptor signature is that `adapt`'s
///    64-byte output is a plain, ordinary BIP340 signature over exactly
///    this challenge (the scheme's headline property, asserted end-to-end
///    in `kat_test.zig` via `bip340.verify`).
/// 8. `s_prime = (k + e·d) mod n` (`Secp256k1.scalar`'s constant-time
///    field ops — `k`/`d` are both secret-derived).
/// 9. Mandatory self-check (same fail-closed philosophy as
///    `bip340.sign`'s step 10 / `musig2.sign`'s self-verify): run
///    `preVerify` on the freshly-built `PreSignature{ .r = r, .s_prime =
///    s_prime, .needs_negation = needs_negation }` against `(P, msg, T)`;
///    return `error.PreSignatureVerificationFailed` if it does not pass —
///    NEVER the unverified pre-signature.
///
/// `io` is threaded through for API symmetry with the sibling modules'
/// `sign` functions (unused: deterministic once `aux_rand` is in hand).
pub fn preSign(
    secret_key: bip340.SecretKey,
    msg: []const u8,
    aux_rand: [32]u8,
    adaptor_point: AdaptorPoint,
    io: std.Io,
) PreSignError!PreSignature {
    _ = io; // deterministic once aux_rand is in hand (see doc comment)

    // Step 1: even-y-normalized effective scalar d + x-only public key —
    // exactly bip340.sign's own steps 1-2.
    const kp = bip340.KeyPair.fromSecretKey(secret_key) catch return error.InvalidSecretKey;
    const d_bytes = kp.secret;
    const px = kp.public.x;

    // Parse T eagerly (needed both as bytes for the nonce preimage and as
    // a real point for step 5's addition).
    const t_point = adaptor_point.point() catch return error.InvalidAdaptorPoint;
    const t_bytes = adaptor_point.toBytes();

    // Step 2: t_pad = bytes(d) xor taggedHash(aux_tag, aux_rand).
    const aux_hash = bip340.taggedHash(aux_tag, &aux_rand);
    var t_pad: [32]u8 = undefined;
    for (&t_pad, d_bytes, aux_hash) |*ti, di, ai| ti.* = di ^ ai;

    // Step 3: rand = taggedHash(nonce_tag, t_pad || px || bytes(T) || msg)
    // — bytes(T) folded in, unlike plain BIP340 (binds the nonce to the
    // specific adaptor point).
    var nonce_hasher = bip340.hash.taggedHasher(nonce_tag);
    nonce_hasher.update(&t_pad);
    nonce_hasher.update(&px);
    nonce_hasher.update(&t_bytes);
    nonce_hasher.update(msg);
    const rand = nonce_hasher.finalResult();

    // Step 4: k0 = int(rand) mod n; fail if 0.
    const k0 = reduceToScalar(rand);
    if (k0.isZero()) return error.InvalidNonce;

    // Step 5: R = k0*G; R_hat = R + T (a REAL point addition — T is a
    // general point). Reject the identity (only possible if T == -R).
    const r_local = Secp256k1.combMulBase(k0.toBytes(.big), .big) catch return error.InvalidNonce;
    const r_hat = r_local.add(t_point);
    r_hat.rejectIdentity() catch return error.InvalidNonce;

    // Step 6: needs_negation = has_odd_y(R_hat); k = k0 if even else n-k0,
    // via the same constant-time masked byte select bip340.sign's step 7
    // uses — no data-dependent branch on the parity bit (it is derived
    // from secret nonce material). Negating a POINT flips only y, so
    // r = bytes(x(R_hat)) is identical on both branches.
    const r_hat_xy = r_hat.affineCoordinates();
    const rx = r_hat_xy.x.toBytes(.big);
    const needs_negation = r_hat_xy.y.isOdd();
    const k_even = k0.toBytes(.big);
    const k_odd = k0.neg().toBytes(.big);
    const mask: u8 = @as(u8, 0) -% @intFromBool(needs_negation);
    var k_bytes: [32]u8 = undefined;
    for (&k_bytes, k_even, k_odd) |*ki, ke, ko| ki.* = (ke & ~mask) | (ko & mask);
    const k = Scalar.fromBytes(k_bytes, .big) catch unreachable; // both candidates canonical

    // Step 7: e = int(taggedHash(BIP0340/challenge, r || px || msg)) mod n
    // — BIP340's OWN challenge tag, so adapt's output is a plain BIP340
    // signature over exactly this challenge.
    var challenge_hasher = bip340.hash.taggedHasher(bip340.hash.challenge_tag);
    challenge_hasher.update(&rx);
    challenge_hasher.update(&px);
    challenge_hasher.update(msg);
    const e = reduceToScalar(challenge_hasher.finalResult());

    // Step 8: s_prime = (k + e*d) mod n.
    const d = Scalar.fromBytes(d_bytes, .big) catch return error.InvalidSecretKey;
    const s_prime = k.add(e.mul(d));

    // Step 9: mandatory self-verification before returning (fail closed).
    const presig = PreSignature{
        .r = rx,
        .s_prime = s_prime.toBytes(.big),
        .needs_negation = needs_negation,
    };
    if (!preVerify(kp.public, msg, adaptor_point, presig)) return error.PreSignatureVerificationFailed;
    return presig;
}

/// Schnorr **PreVerify**: verifies a pre-signature was correctly produced
/// for `(pubkey, msg, T)` WITHOUT knowledge of the adaptor secret `t` —
/// the property that lets a counterparty accept a pre-signature as binding
/// before it is adapted. Returns `false` on every failure path — like
/// `bip340.verify`, this never panics and never errors.
///
/// Construction (cross-validated against secp256kfun's `schnorr_fun::
/// adaptor::verify_encrypted_signature` — see `NOTICE`):
///
/// 1. `P = pubkey.lift()` — fail (return `false`) if `pubkey` does not
///    lift (off-curve / non-canonical x).
/// 2. `T = adaptor_point.point()` — fail if `T` does not parse.
/// 3. `r < p`, `s_prime < n` — re-checked defensively (already enforced
///    by `PreSignature.fromBytes`, but `preVerify` re-runs every check
///    itself so it stays safe on hand-constructed values, per
///    `bip340.verify`'s own precedent).
/// 4. `e = int(taggedHash(bip340.hash.challenge_tag, presig.r ||
///    pubkey.x || msg)) mod n` — IDENTICAL computation to `preSign`'s
///    step 7 (same tag, same preimage shape).
/// 5. `lhs = s_prime·G - e·P` (`Secp256k1.mulDoubleBasePublic(basePoint,
///    s_prime, P, n-e, .big)`, negate `e` mod n first — exactly
///    `bip340.verify`'s own `s*G - e*P` pattern). This recovers the
///    presigner's EFFECTIVE nonce point `k·G` (`k` = whichever of
///    `k0`/`n-k0` `preSign` actually used) — secp256kfun's own
///    `R_hat_verify` in its `verify_encrypted_signature`.
/// 6. `R_even = lift_x(presig.r)` — the canonical EVEN-y point `r`
///    encodes (via `bip340.XOnlyPublicKey.fromBytes(presig.r).lift()`).
/// 7. `rhs = R_even + T` if `presig.needs_negation`, else `rhs = R_even -
///    T` — THE key identity that makes `needs_negation` meaningful:
///    reconstructs `k·G` from the PUBLIC `(r, needs_negation, T)` alone,
///    without ever needing the presigner's local `R`. (Derivation: if
///    `!needs_negation`, `R_even == R_hat == k0·G + T`, so `R_even - T ==
///    k0·G == k·G`. If `needs_negation`, `R_even == -R_hat == -(k0·G +
///    T)`, and `k == n - k0`, so `R_even + T == -k0·G == k·G`. Both
///    branches land on `k·G`.)
/// 8. Accept iff `lhs.equivalent(rhs)` — both sides are `k·G`,
///    reconstructed by two independent routes (the equation side from
///    `(s_prime, e, P)`; the identity side from `(r, needs_negation,
///    T)`) — exactly the check that binds `s_prime` to `T` without
///    revealing `t`.
pub fn preVerify(
    pubkey: bip340.XOnlyPublicKey,
    msg: []const u8,
    adaptor_point: AdaptorPoint,
    presig: PreSignature,
) bool {
    // Steps 1-2: lift P; parse T.
    const p = pubkey.lift() catch return false;
    const t_point = adaptor_point.point() catch return false;

    // Step 3: r < p, s_prime < n — re-checked defensively.
    _ = Fe.fromBytes(presig.r, .big) catch return false;
    const s_prime = Scalar.fromBytes(presig.s_prime, .big) catch return false;

    // Step 4: e — identical computation to preSign's step 7.
    var challenge_hasher = bip340.hash.taggedHasher(bip340.hash.challenge_tag);
    challenge_hasher.update(&presig.r);
    challenge_hasher.update(&pubkey.x);
    challenge_hasher.update(msg);
    const e = reduceToScalar(challenge_hasher.finalResult());

    // Step 5: lhs = s_prime*G - e*P — recovers the presigner's EFFECTIVE
    // nonce point k*G (variable-time is fine: all inputs are public).
    const lhs = Secp256k1.mulDoubleBasePublic(
        Secp256k1.basePoint,
        s_prime.toBytes(.big),
        p,
        e.neg().toBytes(.big),
        .big,
    ) catch return false;

    // Step 6: R_even = lift_x(presig.r) — the canonical even-y point.
    const r_xonly = bip340.XOnlyPublicKey.fromBytes(presig.r) catch return false;
    const r_even = r_xonly.lift() catch return false;

    // Step 7: rhs = R_even + T if needs_negation else R_even - T — both
    // branches reconstruct k*G from public data alone (see doc comment).
    const rhs = if (presig.needs_negation) r_even.add(t_point) else r_even.sub(t_point);

    // Step 8: accept iff both routes land on the same k*G.
    return lhs.equivalent(rhs);
}

pub const AdaptError = error{
    /// `presig.s_prime` failed its canonical `< n` re-check (defensive;
    /// `PreSignature.fromBytes` already enforces this, but `adapt`
    /// re-validates so it stays safe on hand-constructed values).
    InvalidPreSignature,
    /// `adaptor_secret` (`t`) is `0` or `>= n` — not a valid scalar.
    InvalidAdaptorSecret,
};

/// Schnorr **Adapt**: completes a pre-signature into an ordinary 64-byte
/// BIP340 signature, given the adaptor SECRET `t` (such that `T = t·G`
/// was the `adaptor_point` `preSign`/`preVerify` were run against). This
/// is the "decrypt" half of the encryption metaphor: anyone who knows `t`
/// can turn `presig` into a real signature; anyone who later sees BOTH
/// `presig` and the real signature can run `extract` to recover `t` (the
/// scheme's deliberate, one-time key-leaking property).
///
/// Construction (cross-validated against secp256kfun's `schnorr_fun::
/// adaptor::decrypt_signature` — see `NOTICE`):
///
/// 1. `t = int(adaptor_secret) mod n`-as-scalar; fail
///    (`error.InvalidAdaptorSecret`) if `adaptor_secret == 0` or `>= n`
///    (`Scalar.fromBytes` rejects non-canonical/`>= n`; additionally
///    reject the zero scalar — `T` would be the point at infinity, never
///    a legitimate adaptor point).
/// 2. `t_used = t` if `!presig.needs_negation`, else `t_used = n - t` —
///    the SAME `needs_negation` flag `preSign` computed, now correcting
///    the ADAPTOR secret's sign instead of the nonce's (secp256kfun:
///    `y.conditional_negate(needs_negation)` before adding).
/// 3. `s = (s_prime + t_used) mod n` (`presig.s_prime` as a `Scalar`).
/// 4. `sig = presig.r || bytes(32, s)` — the `r` half is carried through
///    UNCHANGED (adapting never touches the nonce commitment, only `s`).
///
/// Correctness (why this yields a valid BIP340 signature — verified
/// end-to-end via `bip340.verify` in `kat_test.zig`, not re-checked
/// inside `adapt` itself, since `adapt` is not given `pubkey`/message
/// context): `preSign` built `s_prime = k + e·d` where `k·G` is `R_hat -
/// T` or `R_hat + T` depending on `needs_negation` (see `preVerify`'s
/// doc comment step 7), i.e. `k·G = ±(R_even ∓ T)`. Adding `t_used` (the
/// SAME-signed `±t`) yields `s·G = k·G + t_used·G = R_even + e·P`
/// (working through both parity branches — see `SPEC.md`), which is
/// exactly BIP340's verification equation for `R = R_even` (`presig.r`)
/// and challenge `e`.
pub fn adapt(presig: PreSignature, adaptor_secret: [32]u8) AdaptError![64]u8 {
    // Defensive re-check of s_prime < n (fromBytes already enforces it,
    // but adapt stays safe on hand-constructed values).
    const s_prime = Scalar.fromBytes(presig.s_prime, .big) catch return error.InvalidPreSignature;

    // Step 1: t as a canonical non-zero scalar.
    const t = Scalar.fromBytes(adaptor_secret, .big) catch return error.InvalidAdaptorSecret;
    if (t.isZero()) return error.InvalidAdaptorSecret;

    // Step 2: t_used = t, negated iff needs_negation — the SAME flag
    // preSign computed, now correcting the adaptor secret's sign.
    // (needs_negation is a PUBLIC wire bit here, so a plain branch leaks
    // nothing; Scalar.neg itself is constant-time.)
    const t_used = if (presig.needs_negation) t.neg() else t;

    // Steps 3-4: s = s_prime + t_used; sig = r || bytes(s) — r carried
    // through unchanged.
    const s = s_prime.add(t_used);
    var sig: [64]u8 = undefined;
    sig[0..32].* = presig.r;
    sig[32..64].* = s.toBytes(.big);
    return sig;
}

pub const ExtractError = error{
    /// `presig.s_prime` failed its canonical `< n` re-check.
    InvalidPreSignature,
    /// `full_sig.s` failed its canonical `< n` re-check (defensive;
    /// `bip340.Signature.fromBytes` already enforces this).
    InvalidSignature,
    InvalidAdaptorPoint,
    /// `full_sig.r != presig.r` — `full_sig` is not a completion of THIS
    /// pre-signature (different nonce commitment entirely), so no
    /// adaptor-secret recovery is possible from this pair.
    NonceMismatch,
    /// The recovered scalar's public point does not equal `adaptor_point`
    /// — `full_sig` was not produced by `adapt`ing `presig` with `T`'s
    /// discrete log (e.g. `full_sig` is a genuinely independent BIP340
    /// signature that merely happens to share the same `r`, or the wrong
    /// `adaptor_point` was passed in).
    AdaptorSecretMismatch,
};

/// Schnorr **Extract**: the scheme's headline "leak" — given a
/// pre-signature and the FULL signature it was adapted into (observed
/// once the counterparty broadcasts/reveals it), recovers the adaptor
/// SECRET `t` such that `T = t·G` is `adaptor_point`. This is the exact
/// algebraic inverse of `adapt`.
///
/// Construction (cross-validated against secp256kfun's `schnorr_fun::
/// adaptor::recover_decryption_key` — see `NOTICE`):
///
/// 1. Fail (`error.NonceMismatch`) unless `full_sig.r == presig.r` —
///    secp256kfun's own first check (`if signature.R != encrypted_
///    signature.R { return None }`): a completed signature over a
///    DIFFERENT nonce commitment cannot have come from adapting this
///    particular pre-signature.
/// 2. `y = (s - s_prime) mod n` (`full_sig.s` minus `presig.s_prime`, as
///    `Scalar`s — `Scalar.sub`).
/// 3. `y_used = y` if `!presig.needs_negation`, else `y_used = n - y` —
///    the algebraic inverse of `adapt`'s step 2 (secp256kfun:
///    `y.conditional_negate(*needs_negation)` on `s - s_hat`, note the
///    SAME flag, SAME direction as `adapt` — extraction undoes exactly
///    the sign flip `adapt` applied).
/// 4. `implied = y_used·G`; fail (`error.AdaptorSecretMismatch`) unless
///    `implied.equivalent(T)` (`T = adaptor_point.point()`) — the
///    recovered scalar must actually be `t` (this is what makes
///    `extract` meaningful rather than just "subtract two scalars": the
///    check confirms `full_sig` really was `presig` adapted with THIS
///    `T`'s discrete log, not some unrelated signature that coincidentally
///    shares `r`).
/// 5. Return `bytes(32, y_used)`.
///
/// On success, the returned bytes are BYTE-IDENTICAL to whatever
/// `adaptor_secret` `adapt` originally consumed (not merely
/// group-equivalent) — `kat_test.zig` asserts this directly against
/// `kat_vectors.zig`'s `t` field.
pub fn extract(presig: PreSignature, full_sig: bip340.Signature, adaptor_point: AdaptorPoint) ExtractError![32]u8 {
    // Step 1: full_sig must complete THIS pre-signature (same nonce
    // commitment).
    if (!std.mem.eql(u8, &full_sig.r, &presig.r)) return error.NonceMismatch;

    // Defensive canonical re-checks + T parse.
    const s_prime = Scalar.fromBytes(presig.s_prime, .big) catch return error.InvalidPreSignature;
    const s = Scalar.fromBytes(full_sig.s, .big) catch return error.InvalidSignature;
    const t_point = adaptor_point.point() catch return error.InvalidAdaptorPoint;

    // Steps 2-3: y = s - s_prime; y_used = y, negated iff needs_negation —
    // the exact algebraic inverse of adapt's sign flip (same flag, same
    // direction; the flag is a public wire bit, so a plain branch is fine).
    const y = s.sub(s_prime);
    const y_used = if (presig.needs_negation) y.neg() else y;

    // Step 4: the recovered scalar's public point must equal T. A zero
    // y_used makes basePoint.mul error (identity) — never a valid T.
    const implied = Secp256k1.combMulBase(y_used.toBytes(.big), .big) catch return error.AdaptorSecretMismatch;
    if (!implied.equivalent(t_point)) return error.AdaptorSecretMismatch;

    // Step 5.
    return y_used.toBytes(.big);
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("interop_vectors.zig");
    _ = @import("interop_test.zig");
}

test "meta.model_after names the scriptless-scripts construction and the sibling bip340 dep" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "adaptor") != null);
    try std.testing.expectEqualStrings("bip340", meta.deps[0]);
}

test "encoded_length constants match this module's wire sizes" {
    try std.testing.expectEqual(@as(usize, 33), AdaptorPoint.encoded_length);
    try std.testing.expectEqual(@as(usize, 65), PreSignature.encoded_length);
}

test "PreSignature round-trips through fromBytes/toBytes (codec only, no crypto core)" {
    var bytes: [65]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 251);
    bytes[0] = 0x01; // keep r's leading byte small/canonical (< field order)
    bytes[32] = 0x01; // keep s_prime's leading byte small/canonical (< curve order)
    bytes[64] = 1; // needs_negation = true
    const ps = try PreSignature.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, bytes[0..64], ps.toBytes()[0..64]);
    try std.testing.expect(ps.needs_negation);
    try std.testing.expectEqualSlices(u8, &bytes, &ps.toBytes());
}

test "PreSignature.fromBytes rejects a flag byte other than 0/1" {
    var bytes: [65]u8 = [_]u8{0} ** 65;
    bytes[0] = 1;
    bytes[32] = 1;
    bytes[64] = 2;
    try std.testing.expectError(error.InvalidPreSignature, PreSignature.fromBytes(bytes));
}

test "AdaptorPoint.fromSecret round-trips through .point() to the same secp256k1 point basePoint.mul gives directly" {
    const t_bytes = [_]u8{0x01} ** 31 ++ [_]u8{0x02}; // arbitrary small nonzero scalar
    const ap = try AdaptorPoint.fromSecret(t_bytes);
    const got = try ap.point();
    const want = try Secp256k1.combMulBase(t_bytes, .big);
    try std.testing.expect(got.equivalent(want));
}
