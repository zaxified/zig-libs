// SPDX-License-Identifier: MIT
//! Multi-scalar multiplication (MSM) in `G1`/`G2`: `Σ sᵢ·Pᵢ`. The Groth16
//! proof elements are MSMs of witness/quotient coefficients against the
//! proving-key group elements. This is the naive schoolbook MSM (one
//! `scalarMul` per term, accumulated) — the same shape as the sibling
//! `bn254` verifier's own public-input accumulation. REAL and ungated.
//!
//! A batched/Pippenger MSM is an explicit performance non-goal for Phase 1
//! (`SPEC.md`) — at SNARK scale it matters, but correctness is identical and
//! the naive form is the reference the fast path would be checked against.

const std = @import("std");
const bn254 = @import("bn254");
const field = @import("field.zig");
const Fr = field.Fr;

const G1 = bn254.G1;
const G2 = bn254.G2;

/// `Σ scalarsᵢ · basesᵢ` in `G1`. `scalars.len` must equal `bases.len`.
/// Returns the identity for empty input.
pub fn msmG1(bases: []const G1.Affine, scalars: []const Fr) G1.Jacobian {
    std.debug.assert(bases.len == scalars.len);
    var acc = G1.Jacobian.identity;
    for (bases, scalars) |base, s| {
        acc = acc.add(G1.Jacobian.fromAffine(base).scalarMul(s));
    }
    return acc;
}

/// `Σ scalarsᵢ · basesᵢ` in `G2`. `scalars.len` must equal `bases.len`.
pub fn msmG2(bases: []const G2.Affine, scalars: []const Fr) G2.Jacobian {
    std.debug.assert(bases.len == scalars.len);
    var acc = G2.Jacobian.identity;
    for (bases, scalars) |base, s| {
        acc = acc.add(G2.Jacobian.fromAffine(base).scalarMul(s));
    }
    return acc;
}

// ── tests ────────────────────────────────────────────────────────────────

const frFromU64 = field.frFromU64;

fn g1Eql(a: G1.Jacobian, b: G1.Jacobian) bool {
    const aa = a.toAffine();
    const bb = b.toAffine();
    if (aa.infinity or bb.infinity) return aa.infinity == bb.infinity;
    return aa.x.eql(bb.x) and aa.y.eql(bb.y);
}

test "msmG1: single term equals scalarMul" {
    const g = G1.Affine.generator;
    const s = frFromU64(7);
    const got = msmG1(&.{g}, &.{s});
    const want = G1.Jacobian.fromAffine(g).scalarMul(s);
    try std.testing.expect(g1Eql(got, want));
}

test "msmG1: linearity — [2]G + [3]G == [5]G" {
    const g = G1.Affine.generator;
    const two = msmG1(&.{ g, g }, &.{ frFromU64(2), frFromU64(3) });
    const five = G1.Jacobian.fromAffine(g).scalarMul(frFromU64(5));
    try std.testing.expect(g1Eql(two, five));
}

test "msmG1: empty input is identity" {
    const got = msmG1(&.{}, &.{});
    try std.testing.expect(got.toAffine().infinity);
}

test "msmG2: single term equals scalarMul" {
    const g = G2.Affine.generator;
    const s = frFromU64(9);
    const got = msmG2(&.{g}, &.{s}).toAffine();
    const want = G2.Jacobian.fromAffine(g).scalarMul(s).toAffine();
    try std.testing.expect(got.x.eql(want.x) and got.y.eql(want.y));
}
