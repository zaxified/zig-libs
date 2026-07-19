// SPDX-License-Identifier: MIT
//! `Fp12 = Fp6[w] / (w^2 - v)` — the top of the extension-field tower,
//! i.e. `w^2 = v` (`v` = `Fp6`'s indeterminate, `fp6.zig`). An element
//! is `c0 + c1*w`, `c0, c1 ∈ Fp6`. This is the future pairing's TARGET
//! field: the output of `e: G1 x G2 -> Gt`, `Gt` being the order-`r`
//! subgroup of `Fp12*` (the Miller loop + final exponentiation
//! themselves are a later part; this file supplies the field ops they
//! would run on).
//!
//! **Status: implemented** — general field arithmetic (`add`/`sub`/
//! `neg`/`mul`/`square`/`inv`/`conjugate`/`frobenius`) plus
//! `cyclotomicSquare` (Granger–Scott) and `frobeniusMap` (repeated
//! Frobenius). The `w^2 = v` tower construction is IDENTICAL to
//! `bls12_381`'s (only the underlying `Fp2`/`Fp6` non-residue differs —
//! see `fp6.zig`'s `nonresidue` doc comment), so every formula here is
//! byte-for-byte the same shape as `bls12_381/src/fp12.zig`'s, expressed
//! only through `Fp6`/`Fp2` primitives that themselves carry BN254's
//! constants. The sparse Miller-loop line multiplication is out of
//! scope for this field-tower module (a later part's optimization, not
//! a correctness prerequisite).

const std = @import("std");
const fp = @import("fp.zig");
const fp2mod = @import("fp2.zig");
const fp6mod = @import("fp6.zig");

pub const Fp = fp.Fp;
pub const Fp2 = fp2mod.Fp2;
pub const Fp6 = fp6mod.Fp6;
pub const FpError = fp.FpError;

/// The `Fp12` non-residue is `v` itself, i.e. the `Fp6` element `(c0=0,
/// c1=1, c2=0)` — `w^2 = v` is fixed to this (see module doc comment).
/// Same as `bls12_381.fp12.nonresidue` (the `w^2 = v` construction is
/// identical between the two curves). REAL: a plain comptime `Fp6`
/// literal, no arithmetic.
pub const nonresidue: Fp6 = .{ .c0 = Fp2.zero, .c1 = Fp2.one, .c2 = Fp2.zero };

/// An element of `Fp12`: `c0 + c1*w`.
pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    /// Wire encoding: `c1 (192B, HIGH) || c0 (192B, LOW)` — 384 bytes
    /// total. Same high-to-low convention as `Fp2`/`Fp6`. This is the
    /// shape a future pairing OUTPUT (`Gt` element) would serialize as,
    /// if this module ever exposes raw `Fp12` serialization.
    pub const encoded_bytes = 2 * Fp6.encoded_bytes; // 384

    pub const zero: Fp12 = .{ .c0 = Fp6.zero, .c1 = Fp6.zero };
    pub const one: Fp12 = .{ .c0 = Fp6.one, .c1 = Fp6.zero };

    /// Parses `c1 || c0`. REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FpError!Fp12 {
        const c1 = try Fp6.fromBytes(bytes[0..Fp6.encoded_bytes].*);
        const c0 = try Fp6.fromBytes(bytes[Fp6.encoded_bytes..encoded_bytes].*);
        return .{ .c0 = c0, .c1 = c1 };
    }

    /// Serializes `c1 || c0`. REAL.
    pub fn toBytes(self: Fp12) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..Fp6.encoded_bytes].* = self.c1.toBytes();
        out[Fp6.encoded_bytes..encoded_bytes].* = self.c0.toBytes();
        return out;
    }

    /// REAL: component-wise `Fp6.isZero`.
    pub fn isZero(self: Fp12) bool {
        return self.c0.isZero() and self.c1.isZero();
    }

    /// REAL: component-wise `Fp6.eql`.
    pub fn eql(a: Fp12, b: Fp12) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    // ── field arithmetic ────────────────────────────────────────────────

    /// Component-wise `Fp6.add`.
    pub fn add(a: Fp12, b: Fp12) Fp12 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }

    /// Component-wise `Fp6.sub`.
    pub fn sub(a: Fp12, b: Fp12) Fp12 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }

    /// Component-wise `Fp6.neg`.
    pub fn neg(a: Fp12) Fp12 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }

    /// Degree-2 extension multiplication over `w^2 = v`. Karatsuba: for
    /// `a = a0+a1 w`, `b = b0+b1 w`:
    /// ```
    /// v0 = a0*b0,  v1 = a1*b1   (two Fp6.mul)
    /// c0 = v0 + v*v1            (v*v1 is Fp6.mulByNonresidue)
    /// c1 = (a0+a1)*(b0+b1) - v0 - v1
    /// ```
    /// Same construction as `bls12_381.Fp12.mul` (`w^2 = v` is
    /// identical between the two curves).
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        return .{
            .c0 = v0.add(v1.mulByNonresidue()),
            .c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(v0).sub(v1),
        };
    }

    /// `Fp12` squaring via the same Karatsuba-style dedicated formula as
    /// `mul(a,a)` — the general one, valid for any `Fp12` element (see
    /// `cyclotomicSquare` for the specialized subgroup-only variant).
    /// Same construction as `bls12_381.Fp12.square`:
    ///   `ab = a0*a1; c0 = (a0+a1)(a0+v*a1) - ab - v*ab; c1 = 2 ab`.
    pub fn square(a: Fp12) Fp12 {
        const ab = a.c0.mul(a.c1);
        const c0 = a.c0.add(a.c1).mul(a.c0.add(a.c1.mulByNonresidue())).sub(ab).sub(ab.mulByNonresidue());
        return .{ .c0 = c0, .c1 = ab.add(ab) };
    }

    /// Multiplicative inverse. Construction: `a^-1 = conj(a) *
    /// norm(a)^-1` where `norm(a) = a0^2 - v*a1^2 ∈ Fp6` (mirrors
    /// `Fp2.inv`'s norm trick, one tower level up) — one `Fp6.inv` plus
    /// a few `Fp6.mul`/`Fp6.square`. Same as `bls12_381.Fp12.inv`.
    pub fn inv(a: Fp12) error{NotInvertible}!Fp12 {
        const norm = a.c0.square().sub(a.c1.square().mulByNonresidue());
        const norm_inv = try norm.inv(); // norm == 0 iff a == 0
        return .{
            .c0 = a.c0.mul(norm_inv),
            .c1 = a.c1.neg().mul(norm_inv),
        };
    }

    /// The `Fp12/Fp6` conjugation automorphism: `w -> -w`, i.e.
    /// `conjugate(c0+c1 w) = c0 - c1 w`. Central to a future pairing's
    /// final-exponentiation "easy part": `a^(p^6-1) = conjugate(a) *
    /// a^-1` (a standard identity for THIS tower construction,
    /// `[Fp12:Fp6]=2` with the `Fp6`-Frobenius-to-the-6th collapsing to
    /// conjugation — same as `bls12_381.Fp12.conjugate`).
    pub fn conjugate(a: Fp12) Fp12 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    /// The Frobenius endomorphism `x -> x^p` restricted to `Fp12`: for
    /// `a = c0+c1 w`, `a^p = c0^p + c1^p w^p` — `c_i^p` is
    /// `Fp6.frobenius(c_i)`, and `w^p` reduces to the `Fp2` coefficient
    /// `γ = ξ^((p-1)/6)` scaling `c1^p` (`w^p = w^(p-1)*w =
    /// (w^2)^((p-1)/2)*w = v^((p-1)/2)*w`, and since `p ≡ 1 (mod 6)` for
    /// BN254 the exponent `(p-1)/2` is a multiple of 3, so
    /// `v^((p-1)/2) = (v^3)^((p-1)/6) = ξ^((p-1)/6)`). Computed
    /// PROGRAMMATICALLY (same policy as `Fp6.frobenius`) and PRECOMPUTED
    /// ONCE at comptime (see `frobenius_gamma`), so no runtime `pow` runs
    /// per call; validated by the definitional "frobenius == pow(p)" test
    /// below. Same construction as `bls12_381.Fp12.frobenius`.
    pub fn frobenius(a: Fp12) Fp12 {
        return .{
            .c0 = a.c0.frobenius(),
            .c1 = a.c1.frobenius().mulByFp2(frobenius_gamma),
        };
    }

    /// Squaring specialized to the CYCLOTOMIC SUBGROUP (elements `a`
    /// with `a * conjugate(a) = 1` — the subgroup every
    /// final-exponentiation intermediate lives in after the easy part).
    /// Granger–Scott cyclotomic-squaring formula ("Faster Squaring in
    /// the Cyclotomic Subgroup of Sixth Degree Extensions", PKC 2010),
    /// via the `Fp4`-subfield decomposition — GENERIC in the tower's
    /// non-residues (it only calls `mulByNonresidue`/`add`/`sub`, never
    /// a literal constant), so this formula is IDENTICAL to
    /// `bls12_381.Fp12.cyclotomicSquare`. With `s = w^3` (`s^2 = ξ`),
    /// an `Fp12` element splits into three `Fp4` components `A = (a_0,
    /// a_3)`, `B = (a_1, a_4)`, `C = (a_2, a_5)` (`a_i` = the `Fp2`
    /// coefficient of `w^i`), and for cyclotomic inputs:
    /// ```
    /// A' = 3*A^2 - 2*conj(A)
    /// B' = 3*s*C^2 + 2*conj(B)
    /// C' = 3*B^2 - 2*conj(C)
    /// ```
    /// INCORRECT to call on an arbitrary `Fp12` element not in the
    /// cyclotomic subgroup (silently wrong answer, no error). Pinned by
    /// the "cyclotomicSquare == square on subgroup elements" oracle
    /// test below.
    pub fn cyclotomicSquare(a: Fp12) Fp12 {
        // Fp4 pairs: A=(a0,a3)=(c0.c0,c1.c1), B=(a1,a4)=(c1.c0,c0.c2),
        // C=(a2,a5)=(c0.c1,c1.c2).
        const asq = fp4Square(a.c0.c0, a.c1.c1);
        const bsq = fp4Square(a.c1.c0, a.c0.c2);
        const csq = fp4Square(a.c0.c1, a.c1.c2);

        var r00 = asq.c0.sub(a.c0.c0);
        r00 = r00.add(r00).add(asq.c0);
        var r11 = asq.c1.add(a.c1.c1);
        r11 = r11.add(r11).add(asq.c1);

        var r01 = bsq.c0.sub(a.c0.c1);
        r01 = r01.add(r01).add(bsq.c0);
        var r12 = bsq.c1.add(a.c1.c2);
        r12 = r12.add(r12).add(bsq.c1);

        const t = csq.c1.mulByNonresidue();
        var r10 = t.add(a.c1.c0);
        r10 = r10.add(r10).add(t);
        var r02 = csq.c0.sub(a.c0.c2);
        r02 = r02.add(r02).add(csq.c0);

        return .{
            .c0 = .{ .c0 = r00, .c1 = r01, .c2 = r02 },
            .c1 = .{ .c0 = r10, .c1 = r11, .c2 = r12 },
        };
    }

    /// `a^(p^power)`: the Frobenius endomorphism applied `power` times.
    /// NAIVE baseline — `power % 12` repeated calls to `frobenius()`
    /// (`frobenius` has order 12 on `Fp12`, pinned by the order-12 test
    /// below, so reducing mod 12 is exact). Same construction as
    /// `bls12_381.Fp12.frobeniusMap`.
    pub fn frobeniusMap(a: Fp12, power: usize) Fp12 {
        var out = a;
        for (0..power % 12) |_| out = out.frobenius();
        return out;
    }
};

/// Squaring in the `Fp4` subfield `Fp2[s]/(s^2 - ξ)` (`s = w^3`), on a
/// pair `(c0, c1)` representing `c0 + c1*s`:
/// `(c0 + c1 s)^2 = (c0^2 + ξ c1^2) + 2 c0 c1 s`, with `2 c0 c1 =
/// (c0+c1)^2 - c0^2 - c1^2` (no extra mul). Same as
/// `bls12_381.fp12.fp4Square` — `cyclotomicSquare`'s sole building
/// block.
fn fp4Square(c0: Fp2, c1: Fp2) struct { c0: Fp2, c1: Fp2 } {
    const t0 = c0.square();
    const t1 = c1.square();
    return .{
        .c0 = t1.mulByNonresidue().add(t0),
        .c1 = c0.add(c1).square().sub(t0).sub(t1),
    };
}

/// `(p-1)/6`, big-endian — the `Fp12` Frobenius-coefficient exponent
/// (comptime-derived from `fp.zig`'s verified `p_bytes`; `p ≡ 1 (mod
/// 6)` for BN254, so the division is exact — enforced at comptime).
const p_minus_1_over_6_bytes: [32]u8 = fp.pExponentBytes(-1, 6);

/// `γ = ξ^((p-1)/6)` — the `w^p` reduction coefficient scaling `c1^p`
/// (see `Fp12.frobenius`). PRECOMPUTED ONCE at COMPTIME (the fixed-public
/// `Fp2.pow` is evaluated by the compiler), so `frobenius` costs one
/// `Fp6.mulByFp2` at runtime instead of re-deriving a 254-bit `pow` on
/// every call. The byte-exact `γ` KAT and the definitional
/// "frobenius == pow(p)" test below remain the anchors.
const frobenius_gamma: Fp2 = blk: {
    @setEvalBranchQuota(50_000_000);
    break :blk fp6mod.nonresidue.pow(&p_minus_1_over_6_bytes);
};

// ── tests ────────────────────────────────────────────────────────────────

test "Fp12.zero / Fp12.one round-trip through bytes" {
    const z = Fp12.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));

    const o = Fp12.one.toBytes();
    var expected = [_]u8{0} ** Fp12.encoded_bytes;
    expected[Fp12.encoded_bytes - 1] = 1; // c0's innermost Fp low byte
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fp12.fromBytes / toBytes round-trip" {
    var bytes = [_]u8{0} ** Fp12.encoded_bytes;
    // Byte 0 is the top byte of the innermost Fp element; must stay <
    // p's own top byte (0x30) to be guaranteed canonical regardless of
    // the remaining 31 bytes.
    bytes[0] = 0x11;
    bytes[Fp12.encoded_bytes - 1] = 0x44;
    const el = try Fp12.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &el.toBytes());
}

test "Fp12.isZero / eql are component-wise" {
    try std.testing.expect(Fp12.zero.isZero());
    try std.testing.expect(!Fp12.one.isZero());
    try std.testing.expect(Fp12.one.eql(Fp12.one));
    try std.testing.expect(!Fp12.one.eql(Fp12.zero));
}

test "nonresidue is the Fp6 element v (c1=1)" {
    try std.testing.expect(nonresidue.c0.isZero());
    try std.testing.expect(nonresidue.c1.eql(Fp2.one));
    try std.testing.expect(nonresidue.c2.isZero());
}

fn mkFp2(k: u64) !Fp2 {
    return .{
        .c0 = try Fp.fromInt(u64, k * 0x1111_1111),
        .c1 = try Fp.fromInt(u64, k * k + 7),
    };
}

// A fixed, arbitrary test element with all twelve Fp coefficients
// distinct and nonzero — the SAME construction (k = 3..8) used by the
// independent Python KAT generator (see SPEC.md).
fn testElement() !Fp12 {
    return .{
        .c0 = .{ .c0 = try mkFp2(3), .c1 = try mkFp2(4), .c2 = try mkFp2(5) },
        .c1 = .{ .c0 = try mkFp2(6), .c1 = try mkFp2(7), .c2 = try mkFp2(8) },
    };
}

// A second independent test element (k = 9..14) — used only by the
// Fp12 multiplication KAT below, matching the Python reference's `b12`.
fn testElementB() !Fp12 {
    return .{
        .c0 = .{ .c0 = try mkFp2(9), .c1 = try mkFp2(10), .c2 = try mkFp2(11) },
        .c1 = .{ .c0 = try mkFp2(12), .c1 = try mkFp2(13), .c2 = try mkFp2(14) },
    };
}

// Test-local generic exponentiation over Fp12 — used only for the
// definitional frobenius check below.
fn pow12(a: Fp12, e: []const u8) Fp12 {
    var acc = Fp12.one;
    for (e) |byte| {
        var bit: u3 = 7;
        while (true) : (bit -= 1) {
            acc = acc.square();
            if ((byte >> bit) & 1 == 1) acc = acc.mul(a);
            if (bit == 0) break;
        }
    }
    return acc;
}

test "Fp12 ring identities: a + (-a) = 0, square == mul(a,a), w^2 == v" {
    const a = try testElement();
    try std.testing.expect(a.add(a.neg()).isZero());
    try std.testing.expect(a.square().eql(a.mul(a)));
    const w = Fp12{ .c0 = Fp6.zero, .c1 = Fp6.one };
    const w2 = w.mul(w);
    try std.testing.expect(w2.c0.eql(nonresidue));
    try std.testing.expect(w2.c1.isZero());
}

test "Fp12.inv: a * a^-1 == 1; inv(0) errors" {
    const a = try testElement();
    try std.testing.expect(a.mul(try a.inv()).eql(Fp12.one));
    try std.testing.expectError(error.NotInvertible, Fp12.zero.inv());
}

test "Fp12.conjugate: conj(a)*a has no w component (lands in Fp6)" {
    const a = try testElement();
    const n = a.conjugate().mul(a);
    try std.testing.expect(n.c1.isZero());
    try std.testing.expect(a.conjugate().conjugate().eql(a));
}

test "Fp12.frobenius equals pow(p) (definitional) and has order 12" {
    const a = try testElement();
    try std.testing.expect(a.frobenius().eql(pow12(a, &fp.p_bytes)));
    var x = a;
    for (0..12) |_| x = x.frobenius();
    try std.testing.expect(x.eql(a));
    x = a;
    for (0..6) |_| x = x.frobenius();
    try std.testing.expect(x.eql(a.conjugate()));
}

// Builds a REAL cyclotomic-subgroup element without any pairing (same
// construction as bls12_381's identically-named test helper): for any
// unit a, c = conjugate(a) * a^-1 is a^(p^6-1), and d =
// frobenius^2(c) * c is a^((p^6-1)(p^2+1)) — order dividing
// p^4 - p^2 + 1 (the cyclotomic subgroup).
fn cyclotomicTestElement() !Fp12 {
    const a = try testElement();
    const c = a.conjugate().mul(try a.inv());
    return c.frobenius().frobenius().mul(c);
}

test "Fp12.cyclotomicSquare == square on cyclotomic-subgroup elements" {
    const d = try cyclotomicTestElement();
    try std.testing.expect(d.mul(d.conjugate()).eql(Fp12.one));
    var x = d;
    for (0..3) |_| {
        try std.testing.expect(x.cyclotomicSquare().eql(x.square()));
        x = x.cyclotomicSquare();
    }
    try std.testing.expect(Fp12.one.cyclotomicSquare().eql(Fp12.one));
}

test "Fp12.frobeniusMap: power 0/1/2/6/12 consistency with frobenius/conjugate" {
    const a = try testElement();
    try std.testing.expect(a.frobeniusMap(0).eql(a));
    try std.testing.expect(a.frobeniusMap(1).eql(a.frobenius()));
    try std.testing.expect(a.frobeniusMap(2).eql(a.frobenius().frobenius()));
    try std.testing.expect(a.frobeniusMap(3).eql(a.frobenius().frobenius().frobenius()));
    try std.testing.expect(a.frobeniusMap(6).eql(a.conjugate()));
    try std.testing.expect(a.frobeniusMap(12).eql(a));
    try std.testing.expect(a.frobeniusMap(13).eql(a.frobenius()));
}

test "KAT: Fp12 Frobenius gamma (xi^((p-1)/6)) byte-exact against an independent reference" {
    // Independently recomputed with Python big-integer exponentiation
    // outside this module (see SPEC.md's cited script).
    const gamma = fp6mod.nonresidue.pow(&p_minus_1_over_6_bytes);
    var expected: [Fp2.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "246996f3b4fae7e6a6327cfe12150b8e747992778eeec7e5ca5cf05f80f362ac1284b71c2865a7dfe8b99fdd76e68b605c521e08292f2176d60b35dadcc9e470");
    try std.testing.expectEqualSlices(u8, &expected, &gamma.toBytes());
}

test "KAT: Fp12 multiplication byte-exact against an independent reference" {
    const a = try testElement();
    const b = try testElementB();
    const got = a.mul(b);
    var expected: [Fp12.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "000000000000000000000000000000000000000000000000000001c9dddddc140000000000000000000000000000000000000000000000019be02465753077fa000000000000000000000000000000000000000000000000b3c4de8c3b29d38200000000000000000000000000000000000000000000000740da732547abb3b20000000000000000000000000000000000000000000000013c4d6bbdd4c3436800000000000000000000000000000000000000000000000b851eb6cbae10f2ea0000000000000000000000000000000000000000000000007f6e64ceb3c49617000000000000000000000000000000000000000000000005b9753032aceee0440000000000000000000000000000000000000000000000012468ba87db96d83f00000000000000000000000000000000000000000000000ae4b17cc4c5f52eee0000000000000000000000000000000000000000000000019f4a06333e934c4f00000000000000000000000000000000000000000000000eb851e97658ba3be2");
    try std.testing.expectEqualSlices(u8, &expected, &got.toBytes());
}
