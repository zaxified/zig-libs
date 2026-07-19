// SPDX-License-Identifier: MIT
//! `Fp6 = Fp2[v] / (v^3 - ξ)` — the second extension-field tower level,
//! `ξ = 9+u ∈ Fp2` (**DIFFERENT from `bls12_381`'s `ξ = u+1`** — see
//! `nonresidue`'s doc comment). An element is `c0 + c1*v + c2*v^2`,
//! `c0, c1, c2 ∈ Fp2`. `Fp6` has no direct geometric meaning on its own
//! — it exists purely as the base of `Fp12` (`fp12.zig`), which IS the
//! future pairing's target group `Gt` (`e: G1 x G2 -> Gt ⊂ Fp12*`, a
//! later part).
//!
//! **Status: implemented** — full `Fp6` arithmetic, same construction
//! as `bls12_381/src/fp6.zig` (the `mul`/`square`/`inv` formulas from
//! Devegili–Ó hÉigeartaigh–Scott–Dahab are generic in the non-residue,
//! expressed only via `Fp2.mulByNonresidue` calls, so they carry over
//! unchanged; only `fp2.zig`'s `mulByNonresidue` implementation itself
//! differs). The Frobenius coefficients are derived PROGRAMMATICALLY
//! from the verified `p` (`γ_1 = ξ^((p-1)/3)` via `Fp2.pow` with a
//! comptime-derived exponent), never hand-transcribed — same discipline
//! as `bls12_381`.

const std = @import("std");
const fp = @import("fp.zig");
const fp2mod = @import("fp2.zig");

pub const Fp = fp.Fp;
pub const Fp2 = fp2mod.Fp2;
pub const FpError = fp.FpError;

/// The `Fp6` non-residue `ξ = 9 + u ∈ Fp2` — the value `v^3` is fixed
/// to (see the module doc comment). **Differs from `bls12_381`'s `ξ =
/// u+1`** — this is the standard BN254/alt-bn128 tower construction
/// (EIP-197's `FQ6` base field; `py_ecc.bn128`'s `FQ12.modulus_coeffs`
/// implies the same `v^3 = 9+u` relation — see `SPEC.md`'s cited
/// sources). REAL: a plain comptime `Fp2` literal (`c0 = 9, c1 = 1`),
/// no arithmetic.
pub const nonresidue: Fp2 = .{ .c0 = Fp.fromInt(u8, 9) catch unreachable, .c1 = Fp.one };

/// An element of `Fp6`: `c0 + c1*v + c2*v^2`.
pub const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    /// Wire encoding: `c2 (64B, HIGH) || c1 (64B) || c0 (64B, LOW)` —
    /// 192 bytes total. Same high-to-low convention as `Fp2.encoded_bytes`.
    /// `Fp6` is never serialized directly on the wire by any current
    /// EIP-196/197 precompile (only `Fp`/`Fp2` coordinates are) — this
    /// encoding exists for tower completeness/testability.
    pub const encoded_bytes = 3 * Fp2.encoded_bytes; // 192

    pub const zero: Fp6 = .{ .c0 = Fp2.zero, .c1 = Fp2.zero, .c2 = Fp2.zero };
    pub const one: Fp6 = .{ .c0 = Fp2.one, .c1 = Fp2.zero, .c2 = Fp2.zero };

    /// Parses `c2 || c1 || c0`. REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FpError!Fp6 {
        const c2 = try Fp2.fromBytes(bytes[0..Fp2.encoded_bytes].*);
        const c1 = try Fp2.fromBytes(bytes[Fp2.encoded_bytes .. 2 * Fp2.encoded_bytes].*);
        const c0 = try Fp2.fromBytes(bytes[2 * Fp2.encoded_bytes .. 3 * Fp2.encoded_bytes].*);
        return .{ .c0 = c0, .c1 = c1, .c2 = c2 };
    }

    /// Serializes `c2 || c1 || c0`. REAL.
    pub fn toBytes(self: Fp6) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..Fp2.encoded_bytes].* = self.c2.toBytes();
        out[Fp2.encoded_bytes .. 2 * Fp2.encoded_bytes].* = self.c1.toBytes();
        out[2 * Fp2.encoded_bytes .. 3 * Fp2.encoded_bytes].* = self.c0.toBytes();
        return out;
    }

    /// REAL: component-wise `Fp2.isZero`.
    pub fn isZero(self: Fp6) bool {
        return self.c0.isZero() and self.c1.isZero() and self.c2.isZero();
    }

    /// REAL: component-wise `Fp2.eql`.
    pub fn eql(a: Fp6, b: Fp6) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1) and a.c2.eql(b.c2);
    }

    // ── field arithmetic ────────────────────────────────────────────────

    /// Component-wise `Fp2.add` (`c0`, `c1`, `c2` independently).
    pub fn add(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }

    /// Component-wise `Fp2.sub`.
    pub fn sub(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }

    /// Component-wise `Fp2.neg`.
    pub fn neg(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg(), .c2 = a.c2.neg() };
    }

    /// Degree-3 extension multiplication over `v^3 = ξ` (this file's
    /// `nonresidue`). The standard construction (Devegili et al.,
    /// "Multiplication and Squaring on Pairing-Friendly Fields") —
    /// GENERIC in `ξ` (expressed only via `Fp2.mulByNonresidue`, this
    /// module's `fp2.zig`, which carries the BN254-specific `9+u`
    /// value), so this formula is IDENTICAL to `bls12_381.Fp6.mul`:
    ///
    /// For `a = a0+a1 v+a2 v^2`, `b = b0+b1 v+b2 v^2`:
    /// ```
    /// v0 = a0*b0,  v1 = a1*b1,  v2 = a2*b2   (three Fp2.mul)
    /// c0 = v0 + ξ*((a1+a2)*(b1+b2) - v1 - v2)
    /// c1 = (a0+a1)*(b0+b1) - v0 - v1 + ξ*v2
    /// c2 = (a0+a2)*(b0+b2) - v0 + v1 - v2
    /// ```
    /// 6 `Fp2.mul` total (vs. 9 for pure schoolbook).
    pub fn mul(a: Fp6, b: Fp6) Fp6 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        const v2 = a.c2.mul(b.c2);
        return .{
            .c0 = a.c1.add(a.c2).mul(b.c1.add(b.c2)).sub(v1).sub(v2).mulByNonresidue().add(v0),
            .c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(v0).sub(v1).add(v2.mulByNonresidue()),
            .c2 = a.c0.add(a.c2).mul(b.c0.add(b.c2)).sub(v0).add(v1).sub(v2),
        };
    }

    /// `Fp6` squaring — the CH-SQR2 formula (Devegili et al., same
    /// reference cited in `mul`'s doc comment); GENERIC in `ξ`, so
    /// identical to `bls12_381.Fp6.square`.
    pub fn square(a: Fp6) Fp6 {
        const s0 = a.c0.square();
        const ab = a.c0.mul(a.c1);
        const s1 = ab.add(ab);
        const s2 = a.c0.sub(a.c1).add(a.c2).square();
        const bc = a.c1.mul(a.c2);
        const s3 = bc.add(bc);
        const s4 = a.c2.square();
        return .{
            .c0 = s3.mulByNonresidue().add(s0),
            .c1 = s4.mulByNonresidue().add(s1),
            .c2 = s1.add(s2).add(s3).sub(s0).sub(s4),
        };
    }

    /// Multiplicative inverse. Construction: the closed-form `Fp6`
    /// inversion formula from Devegili et al. (same reference cited in
    /// `mul`'s doc comment) — GENERIC in `ξ`, identical to
    /// `bls12_381.Fp6.inv`. Needs one `Fp2.inv` plus several
    /// `Fp2.mul`s, not three independent `Fp2.inv` calls.
    pub fn inv(a: Fp6) error{NotInvertible}!Fp6 {
        const c0 = a.c0.square().sub(a.c1.mul(a.c2).mulByNonresidue());
        const c1 = a.c2.square().mulByNonresidue().sub(a.c0.mul(a.c1));
        const c2 = a.c1.square().sub(a.c0.mul(a.c2));
        const t = a.c1.mul(c2).add(a.c2.mul(c1)).mulByNonresidue().add(a.c0.mul(c0));
        const t_inv = try t.inv(); // t == 0 iff a == 0 (norm is multiplicative)
        return .{ .c0 = c0.mul(t_inv), .c1 = c1.mul(t_inv), .c2 = c2.mul(t_inv) };
    }

    /// Multiplication by the `Fp12` non-residue `v` (`fp12.zig`'s
    /// `nonresidue`) — i.e. `(c0+c1 v+c2 v^2) * v = c2*ξ + c0*v + c1*v^2`
    /// (using `v^3 = ξ`). A cyclic coefficient rotation plus one
    /// `Fp2.mulByNonresidue` — cheap, called heavily by
    /// `Fp12.mul`/`Fp12.square`. Same shape as `bls12_381.Fp6.mulByNonresidue`
    /// (the `Fp12` construction `w^2 = v` is identical between the two
    /// curves; only `Fp2.mulByNonresidue`'s `ξ` differs).
    pub fn mulByNonresidue(a: Fp6) Fp6 {
        return .{ .c0 = a.c2.mulByNonresidue(), .c1 = a.c0, .c2 = a.c1 };
    }

    /// Scales every `Fp2` coefficient by a single `Fp2` value —
    /// `(c0 + c1 v + c2 v^2) * s` for `s ∈ Fp2 ⊂ Fp6`. Cheaper than a
    /// general `Fp6.mul` by an embedded `Fp2` element; needed by
    /// `fp12.zig`'s Frobenius.
    pub fn mulByFp2(a: Fp6, s: Fp2) Fp6 {
        return .{ .c0 = a.c0.mul(s), .c1 = a.c1.mul(s), .c2 = a.c2.mul(s) };
    }

    /// The Frobenius endomorphism `x -> x^p` restricted to `Fp6`: for
    /// `a = c0+c1 v+c2 v^2`, `a^p = Fp2.frobenius(c0) +
    /// γ_1*Fp2.frobenius(c1)*v + γ_2*Fp2.frobenius(c2)*v^2`, with
    /// `γ_1 = ξ^((p-1)/3)`, `γ_2 = γ_1^2` — same construction as
    /// `bls12_381.Fp6.frobenius` (`p ≡ 1 (mod 3)` confirmed for BN254's
    /// `p`, so the division is exact — enforced at comptime).
    ///
    /// The Frobenius coefficients are computed PROGRAMMATICALLY, never
    /// hand-transcribed: `γ_1` via `Fp2.pow` with a comptime-derived
    /// exponent, PRECOMPUTED ONCE at comptime (see `frobenius_gamma_1`).
    /// A derivation bug breaks the "frobenius == pow(p)" definitional
    /// test below immediately.
    pub fn frobenius(a: Fp6) Fp6 {
        return .{
            .c0 = a.c0.frobenius(),
            .c1 = a.c1.frobenius().mul(frobenius_gamma_1),
            .c2 = a.c2.frobenius().mul(frobenius_gamma_2),
        };
    }
};

/// `(p-1)/3`, big-endian — the `Fp6` Frobenius-coefficient exponent
/// (comptime-derived; `p ≡ 1 (mod 3)` for BN254, so the division is
/// exact).
const p_minus_1_over_3_bytes: [32]u8 = fp.pExponentBytes(-1, 3);

/// `γ_1 = ξ^((p-1)/3)` and `γ_2 = γ_1^2` — the `v^p`/`v^(2p)` reduction
/// coefficients (see `Fp6.frobenius`). PRECOMPUTED ONCE at COMPTIME from
/// the tower's own `ξ` and the comptime-derived exponent (the
/// fixed-public `Fp2.pow` is evaluated by the compiler, not per call),
/// so `Fp6.frobenius` costs only two `Fp2.mul`s at runtime instead of
/// re-deriving a 254-bit `pow` on every call — that recompute was ~half
/// the whole pairing's cost (final exponentiation applies Frobenius a
/// dozen-plus times). Still derived, never hand-transcribed: the
/// "frobenius == pow(p)" definitional test and the byte-exact `γ_1` KAT
/// below remain the anchors, and the field ops ride `std.crypto.ff`,
/// which is comptime-evaluable.
const frobenius_gamma_1: Fp2 = blk: {
    @setEvalBranchQuota(50_000_000);
    break :blk nonresidue.pow(&p_minus_1_over_3_bytes);
};
const frobenius_gamma_2: Fp2 = blk: {
    @setEvalBranchQuota(50_000_000);
    break :blk frobenius_gamma_1.square();
};

/// Test/back-compat accessor for the comptime-precomputed `γ_1`.
fn frobeniusGamma1() Fp2 {
    return frobenius_gamma_1;
}

// ── tests ────────────────────────────────────────────────────────────────

test "Fp6.zero / Fp6.one round-trip through bytes" {
    const z = Fp6.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));

    const o = Fp6.one.toBytes();
    var expected = [_]u8{0} ** Fp6.encoded_bytes;
    expected[Fp6.encoded_bytes - 1] = 1; // c0's Fp2 low byte
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fp6.fromBytes / toBytes round-trip" {
    var bytes = [_]u8{0} ** Fp6.encoded_bytes;
    bytes[0] = 0x11; // top byte of c2
    bytes[Fp6.encoded_bytes - 1] = 0x22; // low byte of c0
    const el = try Fp6.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &el.toBytes());
}

test "Fp6.isZero / eql are component-wise" {
    try std.testing.expect(Fp6.zero.isZero());
    try std.testing.expect(!Fp6.one.isZero());
    try std.testing.expect(Fp6.one.eql(Fp6.one));
    try std.testing.expect(!Fp6.one.eql(Fp6.zero));
}

test "nonresidue is 9+u" {
    try std.testing.expect(nonresidue.c0.eql(try Fp.fromInt(u8, 9)));
    try std.testing.expect(nonresidue.c1.eql(Fp.one));
}

// A fixed, arbitrary test element with all six Fp coefficients distinct
// and nonzero — the SAME values used by the independent Python KAT
// generator (see SPEC.md's "Verification performed").
fn testElement() !Fp6 {
    return .{
        .c0 = .{ .c0 = try Fp.fromInt(u64, 0x1111_2222_3333_4444), .c1 = try Fp.fromInt(u64, 5) },
        .c1 = .{ .c0 = try Fp.fromInt(u64, 0x5555_6666_7777_8888), .c1 = try Fp.fromInt(u64, 7) },
        .c2 = .{ .c0 = try Fp.fromInt(u64, 0x9999_aaaa_bbbb_cccc), .c1 = try Fp.fromInt(u64, 11) },
    };
}

// Test-local generic exponentiation over Fp6 (square-and-multiply) —
// used only for the definitional frobenius check below.
fn pow6(a: Fp6, e: []const u8) Fp6 {
    var acc = Fp6.one;
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

test "Fp6 ring identities: a + (-a) = 0, square == mul(a,a), (a+b)^2 law" {
    const a = try testElement();
    const b = Fp6{ .c0 = Fp2.one, .c1 = nonresidue, .c2 = Fp2.one };
    try std.testing.expect(a.add(a.neg()).isZero());
    try std.testing.expect(a.square().eql(a.mul(a)));
    const two_ab = a.mul(b).add(a.mul(b));
    try std.testing.expect(a.add(b).square().eql(a.square().add(two_ab).add(b.square())));
}

test "Fp6.inv: a * a^-1 == 1; inv(0) errors" {
    const a = try testElement();
    try std.testing.expect(a.mul(try a.inv()).eql(Fp6.one));
    try std.testing.expectError(error.NotInvertible, Fp6.zero.inv());
}

test "Fp6.mulByNonresidue == mul by v; v^3 == xi (the defining relation)" {
    const a = try testElement();
    const v = Fp6{ .c0 = Fp2.zero, .c1 = Fp2.one, .c2 = Fp2.zero };
    try std.testing.expect(a.mulByNonresidue().eql(a.mul(v)));
    const v3 = v.mul(v).mul(v);
    try std.testing.expect(v3.c0.eql(nonresidue));
    try std.testing.expect(v3.c1.isZero());
    try std.testing.expect(v3.c2.isZero());
}

test "Fp6.mulByFp2 matches mul by the embedded Fp2 element" {
    const a = try testElement();
    const s = Fp2{ .c0 = try Fp.fromInt(u64, 13), .c1 = try Fp.fromInt(u64, 17) };
    const s6 = Fp6{ .c0 = s, .c1 = Fp2.zero, .c2 = Fp2.zero };
    try std.testing.expect(a.mulByFp2(s).eql(a.mul(s6)));
}

test "Fp6.frobenius equals pow(p) (definitional) and has order 6" {
    const a = try testElement();
    try std.testing.expect(a.frobenius().eql(pow6(a, &fp.p_bytes)));
    var x = a;
    for (0..6) |_| x = x.frobenius();
    try std.testing.expect(x.eql(a));
    x = a;
    for (0..5) |_| {
        x = x.frobenius();
        try std.testing.expect(!x.eql(a));
    }
}

test "KAT: Fp6 gamma_1 (xi^((p-1)/3)) byte-exact against an independent reference" {
    // Independently recomputed with Python big-integer exponentiation
    // outside this module (pow(9+u as Fp2, (p-1)//3) via the
    // hand-rolled Fp2 arithmetic in SPEC.md's cited script) — NOT
    // transcribed from any third-party source.
    const g = frobeniusGamma1();
    var expected: [Fp2.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba22fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d");
    try std.testing.expectEqualSlices(u8, &expected, &g.toBytes());
}

test "KAT: Fp6 multiplication byte-exact against an independent reference" {
    const a = try testElement();
    const b = Fp6{ .c0 = Fp2.one, .c1 = nonresidue, .c2 = Fp2.one };
    const got = a.mul(b);
    var expected: [Fp6.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "00000000000000000000000000000000000000000000000055556666777788d7000000000000000000000000000000000000000000000003aaab66672222ddd1000000000000000000000000000000000000000000000000aaaacccceeef11a70000000000000000000000000000000000000000000000065556999adddf220800000000000000000000000000000000000000000000000b22236667aaabf2940000000000000000000000000000000000000000000000331117111711170fff");
    try std.testing.expectEqualSlices(u8, &expected, &got.toBytes());
}

test "KAT: Fp6 inverse byte-exact against an independent reference" {
    const a = try testElement();
    const got = try a.inv();
    var expected: [Fp6.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "061feeaffe5d413365fc5631581ebe5399832f4503d9eb3ef26414ec52ae991e192c5cc3bb07aefc8286b2572293a7a6858944d4d8cee3d654926a27b635ca9709cd19404b7d25e303f9f1b3a78ea11d84288f588471952e0b57e6c7740725d924744d678555e6d66c97b4d5f387c1c9f4084b4e89927973c80d1d27ec29895d1d49d2ffcb2940b274ae378e08c215c9e9d54faf7195e89bde6419f97601b8071a3ace39d34fc145bf802cbfea482adcca276e922bf535f8cad1a2327c4201b9");
    try std.testing.expectEqualSlices(u8, &expected, &got.toBytes());
}
