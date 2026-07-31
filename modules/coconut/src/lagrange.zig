// SPDX-License-Identifier: MIT

//! lagrange — the Lagrange interpolation coefficient at `x = 0` over the
//! `bls12_381` scalar field `Fr`, evaluated for a set of PUBLIC authority
//! indices. This is the mechanical helper both the (gated)
//! `credential.aggregateCredential` and the (real)
//! `keys.aggregateVerificationKeys` build on: a Shamir-shared secret
//! `f(0)` is recovered from `t` evaluations `f(iⱼ)` as
//! `Σⱼ lⱼ · f(iⱼ)`, where `lⱼ = Πₖ≠ⱼ (0 − iₖ)/(iⱼ − iₖ)`. In the
//! EXPONENT (aggregating group elements `[f(iⱼ)]P`) the same coefficients
//! recombine the shared point — that is Coconut's "Lagrange-in-exponent"
//! threshold aggregation.
//!
//! Indices are 1-based, distinct, PUBLIC authority identifiers (never a
//! secret) — the `O(t²)` double loop and the equality early-returns are
//! not secret-dependent. Mirrors `frost`'s `deriveInterpolatingValue`
//! (RFC 9591 §4.2) and `bls12_381.threshold`'s combine coefficients,
//! specialised to `u64` indices over `Fr`.

const std = @import("std");
const bls = @import("bls12_381");

const Fr = bls.Fr;

pub const LagrangeError = error{
    /// `i` does not appear in `indices` — cannot interpolate for a node
    /// that is not one of the evaluation points.
    NotAnIndex,
    /// Two entries of `indices` are equal — Lagrange interpolation is
    /// undefined on a repeated x-coordinate (the `iⱼ − iₖ` denominator
    /// would be zero).
    DuplicateIndex,
    /// `indices` is empty, or an index is `0` (index `0` collides with
    /// the interpolation point `x = 0`, making `(0 − iₖ)` vanish).
    InvalidIndex,
};

/// `Fr` embedding of a positive authority index `i` (1-based). Index `0`
/// is rejected by the callers (it is the interpolation point).
pub fn indexScalar(i: u64) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], i, .big);
    // i < 2^64 ≪ r, so `fromBytes` never overflows the modulus.
    return Fr.fromBytes(buf) catch unreachable;
}

/// The Lagrange coefficient `lⱼ = Πₖ≠ⱼ (0 − iₖ)/(iⱼ − iₖ)` for node
/// `i` (which must be one of `indices`), evaluated at `x = 0`. Real,
/// mechanical, constant folding aside — used by both the credential and
/// verification-key aggregation.
pub fn coefficientAtZero(indices: []const u64, i: u64) LagrangeError!Fr {
    if (indices.len == 0 or i == 0) return error.InvalidIndex;

    var found = false;
    for (indices, 0..) |a, ai| {
        if (a == 0) return error.InvalidIndex;
        if (a == i) found = true;
        for (indices[ai + 1 ..]) |b| {
            if (a == b) return error.DuplicateIndex;
        }
    }
    if (!found) return error.NotAnIndex;

    const xi = indexScalar(i);
    var num = Fr.one;
    var den = Fr.one;
    for (indices) |k| {
        if (k == i) continue;
        const xk = indexScalar(k);
        // numerator factor (0 − xk) = −xk ; denominator factor (xi − xk).
        num = num.mul(xk.neg());
        den = den.mul(xi.sub(xk));
    }
    // den is a product of nonzero factors (distinct indices), invertible.
    const den_inv = den.inv() catch unreachable;
    return num.mul(den_inv);
}

test "coefficientAtZero: reconstructs a degree-(t-1) polynomial's constant term" {
    // f(x) = 7 + 3x + 5x^2 over Fr; sample at x=1,2,3; Lagrange-combine at 0 → 7.
    //
    // NOTE on why this is checked at BOTH t=3 and t=4 below: with t=3 indices,
    // each coefficient's numerator product skips exactly 1 index, leaving an
    // EVEN count (2) of `(0 - xk) = -xk` factors — so a mutant that drops the
    // negation entirely (`num.mul(xk)` instead of `num.mul(xk.neg())`) flips
    // an even number of signs per coefficient and the errors cancel: this
    // t=3 case alone does NOT distinguish the correct sign convention from
    // its negation-free mutant (an "oracle blind to the answer", the exact
    // shape this campaign's method calls out). The t=4 case below has an ODD
    // count (3) of such factors per coefficient, where the sign is load-bearing.
    const c0 = Fr.fromBytes(scalarFromU64(7)) catch unreachable;
    const c1 = Fr.fromBytes(scalarFromU64(3)) catch unreachable;
    const c2 = Fr.fromBytes(scalarFromU64(5)) catch unreachable;
    const indices = [_]u64{ 1, 2, 3 };
    var acc = Fr.zero;
    for (indices) |i| {
        const x = indexScalar(i);
        const fx = c0.add(c1.mul(x)).add(c2.mul(x.square())); // Horner-ish
        const l = try coefficientAtZero(&indices, i);
        acc = acc.add(l.mul(fx));
    }
    try std.testing.expect(acc.eql(c0));

    // t=4: an odd (3) number of numerator factors per coefficient, where a
    // dropped negation does NOT cancel out and must change the result.
    const c3 = Fr.fromBytes(scalarFromU64(2)) catch unreachable;
    const indices4 = [_]u64{ 1, 2, 3, 4 };
    var acc4 = Fr.zero;
    for (indices4) |i| {
        const x = indexScalar(i);
        const fx = c0.add(c1.mul(x)).add(c2.mul(x.square())).add(c3.mul(x.square().mul(x)));
        const l = try coefficientAtZero(&indices4, i);
        acc4 = acc4.add(l.mul(fx));
    }
    try std.testing.expect(acc4.eql(c0));
}

test "coefficientAtZero: rejects bad inputs" {
    const idx = [_]u64{ 1, 2, 2 };
    try std.testing.expectError(error.DuplicateIndex, coefficientAtZero(&idx, 1));
    const idx2 = [_]u64{ 1, 2, 3 };
    try std.testing.expectError(error.NotAnIndex, coefficientAtZero(&idx2, 9));
    try std.testing.expectError(error.InvalidIndex, coefficientAtZero(&idx2, 0));
}

fn scalarFromU64(v: u64) [32]u8 {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], v, .big);
    return buf;
}
