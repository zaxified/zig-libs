// SPDX-License-Identifier: MIT

//! scalarvec — mechanical scalar/vector arithmetic helpers over the
//! Ristretto255 scalar field (`std.crypto.ecc.Ristretto255.scalar`, order
//! `L = 2^252 + 27742317777372353535851937790883648493`) plus
//! multi-scalar-multiplication over the Ristretto255 group itself.
//!
//! **REAL — not a Fable stub.** Every function here is ordinary,
//! non-secret-judgment arithmetic (inner products, elementwise vector ops,
//! scalar powers, a weighted point sum): the Bulletproofs "hard part" is
//! not any single one of these operations but the SEQUENCE/STRUCTURE the
//! Inner-Product Argument (`ipa.zig`) and the range-proof polynomial
//! construction (`rangeproof.zig`) apply them in — both of which are
//! genuinely stubbed and will import this file's functions once
//! implemented. This module's own test block below exercises every
//! function directly against hand-computed small values.
//!
//! Scalars are represented throughout this module (and `ipa.zig`/
//! `rangeproof.zig`) as raw `[32]u8` little-endian canonical encodings —
//! `Ristretto255.scalar.CompressedScalar` — the SAME representation
//! `std.crypto.ecc.Ristretto255.scalar`'s own free functions
//! (`add`/`sub`/`mul`/`mulAdd`/`neg`/`reduce64`) already operate on
//! directly, so no wrapper type is introduced (mirrors the sibling `voprf`
//! module's convention — see its `root.zig` doc comment).

const std = @import("std");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;

/// The scalar `0` — `Ristretto255.scalar.zero`, re-exported here for
/// call-site clarity alongside `one` below (std only names `zero`).
pub const zero: [32]u8 = scalar.zero;

/// The scalar `1` (32-byte little-endian: `[1, 0, 0, ..., 0]`).
pub const one: [32]u8 = [_]u8{1} ++ [_]u8{0} ** 31;

/// The scalar `2` (32-byte little-endian: `[2, 0, 0, ..., 0]`).
pub const two: [32]u8 = [_]u8{2} ++ [_]u8{0} ** 31;

/// The Ristretto255 identity (neutral) element — `Ristretto255` exposes no
/// direct constant for it (only `basePoint`), so it is built once here from
/// the underlying `Edwards25519.identityElement`. Used by `multiScalarMul`
/// (a zero-scalar term contributes nothing) and by callers that need an
/// explicit additive-identity starting accumulator.
pub const identity_point: Ristretto255 = .{ .p = Ristretto255.Curve.identityElement };

pub const VectorLengthError = error{LengthMismatch};

/// `<a, b> = sum_i a_i * b_i (mod L)` — Bulletproofs' inner product,
/// computed via `scalar.mulAdd` (one fused multiply-add per element, same
/// primitive `std.crypto.ecc.Ristretto255.scalar.mulAdd` already exposes).
pub fn innerProduct(a: []const [32]u8, b: []const [32]u8) VectorLengthError![32]u8 {
    if (a.len != b.len) return error.LengthMismatch;
    var acc = zero;
    for (a, b) |ai, bi| acc = scalar.mulAdd(ai, bi, acc);
    return acc;
}

/// Elementwise (Hadamard) product: `out_i = a_i * b_i (mod L)`.
/// `out.len` must equal `a.len` and `b.len`; `out` may alias `a` or `b`.
pub fn hadamard(out: [][32]u8, a: []const [32]u8, b: []const [32]u8) VectorLengthError!void {
    if (out.len != a.len or a.len != b.len) return error.LengthMismatch;
    for (out, a, b) |*o, ai, bi| o.* = scalar.mul(ai, bi);
}

/// Elementwise sum: `out_i = a_i + b_i (mod L)`.
pub fn addVec(out: [][32]u8, a: []const [32]u8, b: []const [32]u8) VectorLengthError!void {
    if (out.len != a.len or a.len != b.len) return error.LengthMismatch;
    for (out, a, b) |*o, ai, bi| o.* = scalar.add(ai, bi);
}

/// Elementwise difference: `out_i = a_i - b_i (mod L)`.
pub fn subVec(out: [][32]u8, a: []const [32]u8, b: []const [32]u8) VectorLengthError!void {
    if (out.len != a.len or a.len != b.len) return error.LengthMismatch;
    for (out, a, b) |*o, ai, bi| o.* = scalar.sub(ai, bi);
}

/// Scale every element by a single scalar: `out_i = a_i * s (mod L)`.
pub fn scaleVec(out: [][32]u8, a: []const [32]u8, s: [32]u8) VectorLengthError!void {
    if (out.len != a.len) return error.LengthMismatch;
    for (out, a) |*o, ai| o.* = scalar.mul(ai, s);
}

/// `[x^0, x^1, ..., x^(n-1)] (mod L)` — allocated via `allocator` (caller
/// frees). `n == 0` returns an empty (zero-length) slice.
pub fn powers(allocator: std.mem.Allocator, x: [32]u8, n: usize) std.mem.Allocator.Error![][32]u8 {
    const out = try allocator.alloc([32]u8, n);
    if (n == 0) return out;
    out[0] = one;
    var i: usize = 1;
    while (i < n) : (i += 1) out[i] = scalar.mul(out[i - 1], x);
    return out;
}

pub const MultiScalarMulError = error{LengthMismatch};

/// `sum_i scalars_i * points_i` over Ristretto255 — a naive (non-Pippenger)
/// weighted sum: one `Ristretto255.mul` + `.add` per term. `s_i == 0`
/// (or, negligibly, `s_i * points_i` landing on the identity for any other
/// reason) is handled by skipping that term's contribution (`p.mul(s)`
/// returns `error.IdentityElement`/`error.WeakPublicKey` in exactly that
/// case per std's own doc comment — a zero contribution either way, so
/// `catch continue` is exact, not an approximation).
///
/// Performance note: this is the mechanical, obviously-correct version —
/// good enough for a scaffold and for the KAT harness below. A production
/// pass MAY swap this for a windowed/Pippenger multi-scalar-multiplication
/// without changing this function's signature or the callers in `ipa.zig`/
/// `rangeproof.zig`; that is a performance optimization, not a
/// cryptographic-judgment change, so it is explicitly OUT of scope for the
/// Fable core pass (see `ipa.zig`'s module doc comment).
pub fn multiScalarMul(scalars: []const [32]u8, points: []const Ristretto255) MultiScalarMulError!Ristretto255 {
    if (scalars.len != points.len) return error.LengthMismatch;
    var acc = identity_point;
    for (scalars, points) |s, p| {
        const term = p.mul(s) catch continue;
        acc = acc.add(term);
    }
    return acc;
}

// ── tests ─────────────────────────────────────────────────────────────────

test "innerProduct: hand-computed small vectors" {
    // a = [2, 3], b = [5, 7] -> <a,b> = 10 + 21 = 31.
    const a = [_][32]u8{ two, [_]u8{3} ++ [_]u8{0} ** 31 };
    const b = [_][32]u8{ [_]u8{5} ++ [_]u8{0} ** 31, [_]u8{7} ++ [_]u8{0} ** 31 };
    const got = try innerProduct(&a, &b);
    const want = [_]u8{31} ++ [_]u8{0} ** 31;
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "innerProduct: length mismatch rejected" {
    const a = [_][32]u8{one};
    const b = [_][32]u8{ one, one };
    try std.testing.expectError(error.LengthMismatch, innerProduct(&a, &b));
}

test "innerProduct: empty vectors give zero" {
    const got = try innerProduct(&.{}, &.{});
    try std.testing.expectEqualSlices(u8, &zero, &got);
}

test "hadamard/addVec/subVec/scaleVec: hand-computed" {
    const a = [_][32]u8{ two, [_]u8{4} ++ [_]u8{0} ** 31 };
    const b = [_][32]u8{ [_]u8{3} ++ [_]u8{0} ** 31, [_]u8{5} ++ [_]u8{0} ** 31 };

    var had: [2][32]u8 = undefined;
    try hadamard(&had, &a, &b);
    try std.testing.expectEqualSlices(u8, &([_]u8{6} ++ [_]u8{0} ** 31), &had[0]); // 2*3
    try std.testing.expectEqualSlices(u8, &([_]u8{20} ++ [_]u8{0} ** 31), &had[1]); // 4*5

    var sum: [2][32]u8 = undefined;
    try addVec(&sum, &a, &b);
    try std.testing.expectEqualSlices(u8, &([_]u8{5} ++ [_]u8{0} ** 31), &sum[0]); // 2+3
    try std.testing.expectEqualSlices(u8, &([_]u8{9} ++ [_]u8{0} ** 31), &sum[1]); // 4+5

    var diff: [2][32]u8 = undefined;
    try subVec(&diff, &b, &a);
    try std.testing.expectEqualSlices(u8, &one, &diff[0]); // 3-2 = 1
    try std.testing.expectEqualSlices(u8, &one, &diff[1]); // 5-4 = 1

    var scaled: [2][32]u8 = undefined;
    try scaleVec(&scaled, &a, [_]u8{10} ++ [_]u8{0} ** 31);
    try std.testing.expectEqualSlices(u8, &([_]u8{20} ++ [_]u8{0} ** 31), &scaled[0]); // 2*10
    try std.testing.expectEqualSlices(u8, &([_]u8{40} ++ [_]u8{0} ** 31), &scaled[1]); // 4*10
}

test "hadamard/addVec/subVec/scaleVec: length mismatch rejected" {
    var out2: [2][32]u8 = undefined;
    const a1 = [_][32]u8{one};
    const a2 = [_][32]u8{ one, one };
    try std.testing.expectError(error.LengthMismatch, hadamard(&out2, &a1, &a2));
    try std.testing.expectError(error.LengthMismatch, addVec(&out2, &a1, &a2));
    try std.testing.expectError(error.LengthMismatch, subVec(&out2, &a1, &a2));
    try std.testing.expectError(error.LengthMismatch, scaleVec(&out2, &a1, one));
}

test "powers: x^0..x^(n-1), x=3, n=5" {
    const three = [_]u8{3} ++ [_]u8{0} ** 31;
    const got = try powers(std.testing.allocator, three, 5);
    defer std.testing.allocator.free(got);
    const want = [_]u32{ 1, 3, 9, 27, 81 };
    for (got, want) |g, w| {
        var wb = [_]u8{0} ** 32;
        std.mem.writeInt(u32, wb[0..4], w, .little);
        try std.testing.expectEqualSlices(u8, &wb, &g);
    }
}

test "powers: n=0 gives empty slice" {
    const got = try powers(std.testing.allocator, two, 0);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqual(@as(usize, 0), got.len);
}

test "multiScalarMul: 2*G + 3*basePoint.dbl() matches direct computation" {
    const g = Ristretto255.basePoint;
    const h = g.dbl();
    const scalars = [_][32]u8{ two, [_]u8{3} ++ [_]u8{0} ** 31 };
    const points = [_]Ristretto255{ g, h };
    const got = try multiScalarMul(&scalars, &points);

    const want = (try g.mul(two)).add(try h.mul([_]u8{3} ++ [_]u8{0} ** 31));
    try std.testing.expect(got.equivalent(want));
}

test "multiScalarMul: a zero scalar contributes nothing" {
    const g = Ristretto255.basePoint;
    const h = g.dbl();
    const scalars = [_][32]u8{ zero, [_]u8{3} ++ [_]u8{0} ** 31 };
    const points = [_]Ristretto255{ g, h };
    const got = try multiScalarMul(&scalars, &points);
    const want = try h.mul([_]u8{3} ++ [_]u8{0} ** 31);
    try std.testing.expect(got.equivalent(want));
}

test "multiScalarMul: all-zero scalars give the identity" {
    const g = Ristretto255.basePoint;
    const h = g.dbl();
    const scalars = [_][32]u8{ zero, zero };
    const points = [_]Ristretto255{ g, h };
    const got = try multiScalarMul(&scalars, &points);
    try std.testing.expect(got.equivalent(identity_point));
}

test "multiScalarMul: length mismatch rejected" {
    const g = Ristretto255.basePoint;
    const scalars = [_][32]u8{ one, one };
    const points = [_]Ristretto255{g};
    try std.testing.expectError(error.LengthMismatch, multiScalarMul(&scalars, &points));
}

test "identity_point is the group identity (adding it is a no-op)" {
    const g = Ristretto255.basePoint;
    try std.testing.expect(g.add(identity_point).equivalent(g));
}
