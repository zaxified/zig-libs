// SPDX-License-Identifier: MIT

//! scalar — the secp256k1 scalar field (arithmetic mod the group order
//! `n = 2^256 − 432420386565659656852420866394968145599`), plus the **GLV
//! balanced-length decomposition** the gated variable-base scalarmul builds on.
//!
//! ## Scope / dedup: the scalar field is re-exported from std, on purpose
//!
//! k256's reason to exist is the *field* and *group* arithmetic hot path (the
//! ~hundreds of base-field multiplies per scalar multiply), which it accelerates
//! with the special-prime reduction + `MULX/ADX` core + GLV. Scalar-field
//! arithmetic mod `n` is a negligible slice of an ECDSA/Schnorr operation (a
//! handful of `mul`/`add`/`invert` mod `n` per signature vs. the point multiply's
//! field-op storm), and `n` has no exploitable special form — so accelerating it
//! would be effort with no measurable payoff. k256 therefore re-exports std's
//! constant-time scalar field verbatim and spends its complexity budget where the
//! cost is. This is a deliberate scope decision, documented in `SPEC.md`.
//!
//! What IS k256's own here: the GLV decomposition `splitScalar` (the endomorphism
//! `λ`, `β`, and the decomposition lattice basis), tested byte-exact against
//! std's `Endormorphism.splitScalar`. The gated GLV scalarmul (`group.mulPublicGlv`)
//! consumes it.

const std = @import("std");
const math = std.math;

/// The secp256k1 scalar field, re-exported from std (see the scope note above).
pub const scalar = std.crypto.ecc.Secp256k1.scalar;
pub const Scalar = scalar.Scalar;
pub const CompressedScalar = scalar.CompressedScalar;

/// The scalar field (group) order `n`.
pub const field_order: u256 = scalar.field_order;

// ── GLV endomorphism constants ──────────────────────────────────────────────
//
// secp256k1 admits the efficiently-computable endomorphism φ(x, y) = (β·x, y),
// which acts on the prime-order subgroup as multiplication by λ (a cube root of
// 1 mod n). `λ`, `β`, and the short lattice basis {(a1,b1),(a2,b2)} of the
// kernel of (k1, k2) ↦ k1 + k2·λ (mod n) are the standard secp256k1 GLV
// constants (Guide to ECC §3.5; the exact integers below match std's
// `Endormorphism`). The decomposition writes any k as k = k1 + k2·λ with both
// |k1|, |k2| ≈ √n (~128-bit), halving the scalar multiply's doublings.

/// `λ`: the eigenvalue of the endomorphism on the prime-order subgroup.
pub const lambda: u256 = 37718080363155996902926221483475020450927657555482586988616620542887997980018;

/// `β`: the field constant with φ(x, y) = (β·x, y). (A nontrivial cube root of
/// 1 in the base field.)
pub const beta: u256 = 55594575648329892869085402983802832744385952214688224221778511981742606582254;

// Rounded-division multipliers g1 = round(2^384·b2/n), g2 = round(2^384·b1/n),
// and the negated basis components -b1, -b2 (mod n) — the exact split constants.
const glv_g1: u256 = 21949224512762693861512883645436906316123769664773102907882521278123970637873;
const glv_g2: u256 = 103246583619904461035481197785446227098457807945486720222659797044629401272177;
const glv_b1_neg: u256 = 303414439467246543595250775667605759171;
const glv_b2_neg: u256 = field_order - 64502973549206556628585045361533709077;

/// A balanced GLV split: `k ≡ r1 + r2·λ (mod n)`, both `|r1|, |r2| ≈ √n`. Bytes
/// are in the requested endianness (as std returns them).
pub const SplitScalar = struct {
    r1: CompressedScalar,
    r2: CompressedScalar,
};

/// Compute the balanced GLV decomposition of a scalar `k`: returns `(r1, r2)`
/// with `k ≡ r1 + r2·λ (mod n)`. This is k256's own reference implementation of
/// the lattice split (constants documented above); the gated
/// `group.mulPublicGlv` uses it, and `oracle_test.zig` pins it byte-exact
/// against std's `Endormorphism.splitScalar`.
///
/// Mirrors the classic rounded-lattice method: `c_i = round(k·g_i / 2^384)`
/// (via a shift plus the rounding bit), then `r2 = c1·(−b1) + c2·(−b2)` and
/// `r1 = k − r2·λ`, all mod `n`.
pub fn splitScalar(s: CompressedScalar, endian: std.builtin.Endian) error{NonCanonical}!SplitScalar {
    const b1_neg_s = leBytes(glv_b1_neg);
    const b2_neg_s = leBytes(glv_b2_neg);
    const lambda_s = leBytes(lambda);

    const k = std.mem.readInt(u256, &s, endian);

    // c_i = round(k·g_i / 2^384): high 128 bits of the 512-bit product, plus the
    // bit just below the truncation point (round-to-nearest).
    const t1 = math.mulWide(u256, k, glv_g1);
    const t2 = math.mulWide(u256, k, glv_g2);
    const c1: u256 = @as(u256, @truncate(t1 >> 384)) + @as(u1, @truncate(t1 >> 383));
    const c2: u256 = @as(u256, @truncate(t2 >> 384)) + @as(u1, @truncate(t2 >> 383));

    // r2 = c1·(−b1) + c2·(−b2)  (mod n)
    const c1x = try scalar.mul(leBytes(c1), b1_neg_s, .little);
    const c2x = try scalar.mul(leBytes(c2), b2_neg_s, .little);
    const r2_le = try scalar.add(c1x, c2x, .little);

    // r1 = k − r2·λ  (mod n)
    var r1_le = try scalar.mul(r2_le, lambda_s, .little);
    r1_le = try scalar.sub(leBytes(k), r1_le, .little);

    return .{
        .r1 = if (endian == .little) r1_le else orderSwap(r1_le),
        .r2 = if (endian == .little) r2_le else orderSwap(r2_le),
    };
}

inline fn leBytes(x: u256) [32]u8 {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, x, .little);
    return b;
}

inline fn orderSwap(s: [32]u8) [32]u8 {
    var t = s;
    for (s, 0..) |x, i| t[t.len - 1 - i] = x;
    return t;
}

// ── tests: GLV decomposition vs std + reconstruction ────────────────────────

const StdEndo = std.crypto.ecc.Secp256k1.Endormorphism;

test "GLV eigenvalue λ is a nontrivial cube root of 1 mod n" {
    // λ ≠ 1 and λ³ ≡ 1 (mod n): the endomorphism has order 3 on the subgroup.
    // (std's λ/β are private; the splitScalar differential below transitively
    // pins λ to std's, and the β endomorphism is checked in group.zig.)
    const one = Scalar.one;
    const lam = Scalar.fromBytes(leBytes(lambda), .little) catch unreachable;
    try std.testing.expect(!lam.equivalent(one));
    try std.testing.expect(lam.mul(lam).mul(lam).equivalent(one));
}

test "splitScalar byte-exact vs std + reconstructs k = r1 + r2·λ (mod n)" {
    var prng = std.Random.DefaultPrng.init(0x6417_1A3B);
    const rand = prng.random();
    const lambda_s = leBytes(lambda);
    var i: usize = 0;
    while (i < 3000) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const k = Scalar.fromBytes(kb, .little) catch continue;

        const got = try splitScalar(kb, .little);
        const want = try StdEndo.splitScalar(kb, .little);
        try std.testing.expectEqualSlices(u8, &want.r1, &got.r1);
        try std.testing.expectEqualSlices(u8, &want.r2, &got.r2);

        // Reconstruction: r1 + r2·λ ≡ k (mod n).
        const r1 = Scalar.fromBytes(got.r1, .little) catch unreachable;
        const r2 = Scalar.fromBytes(got.r2, .little) catch unreachable;
        const recon = r1.add(r2.mul(Scalar.fromBytes(lambda_s, .little) catch unreachable));
        try std.testing.expect(recon.equivalent(k));
    }
}
