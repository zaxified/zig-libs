// SPDX-License-Identifier: MIT
//! `Fp2 = Fp[u] / (u^2 + 1)` — the first extension-field tower level
//! above `Fp` (`fp.zig`), i.e. `u^2 = -1`. An element is `c0 + c1*u`,
//! `c0, c1 ∈ Fp`. This is the field a future `G2` part's coordinates
//! would live in, and the base of the further `Fp6`/`Fp12` extensions
//! (`fp6.zig`/`fp12.zig`).
//!
//! **Status: implemented** — full `Fp2` arithmetic including `sqrt`
//! (the complex method for `p ≡ 3 (mod 4)`) and a public-exponent `pow`
//! (used by `Fp6`/`Fp12`'s programmatically-derived Frobenius
//! coefficients). Same construction as `bls12_381/src/fp2.zig`.
//!
//! **Non-residue convention**: `u^2 = -1` — SAME convention as
//! `bls12_381` (confirmed independently: `py_ecc`'s `bn128` uses
//! `modulus_coeffs = (1, 0)` for its `FQ2`, i.e. `i^2 + 1 = 0`) and
//! confirmed here by cross-checking the well-published BN254 `G2`
//! generator against exactly this convention (see `fp6.zig`'s KAT test
//! citing the on-twist check; the group itself is not implemented in
//! this Part 1-2 field-tower module). A DIFFERENT non-residue choice
//! would silently produce a DIFFERENT — but internally self-consistent
//! — curve/pairing; every constant and formula in this module's tower
//! (`Fp6`'s `v^3 = ξ = 9+u`, `Fp12`'s `w^2 = v`) MUST use this same
//! `u^2 = -1` convention throughout.

const std = @import("std");
const fp = @import("fp.zig");

pub const Fp = fp.Fp;
pub const FpError = fp.FpError;

/// An element of `Fp2`: `c0 + c1*u`.
pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    /// Wire encoding: `c1 (32 bytes, HIGH) || c0 (32 bytes, LOW)` — 64
    /// bytes total. NOTE: unlike `bls12_381` (which follows the
    /// ZCash/IETF `c1||c0` high-to-low convention because it is
    /// COMPRESSING points and needs a stable byte-string to attach a
    /// sign bit to), Ethereum's EIP-197 `G2` precompile encoding is
    /// UNCOMPRESSED and actually lays out `Fp2` coordinates as `c1||c0`
    /// too (the imaginary part first) — see `SPEC.md`'s "EIP-197 G2
    /// encoding" note. This module keeps the same `c1||c0` order as
    /// `bls12_381.Fp2` for INTERNAL tower consistency and so this
    /// encoding is ready to match EIP-197 once a `G2` part lands; it is
    /// not exercised by any EIP-196/197 precompile in Part 1-2 itself
    /// (only `Fp`/`G1`, which are plain `Fp`, are precompile-facing
    /// yet).
    pub const encoded_bytes = 2 * Fp.encoded_bytes; // 64

    pub const zero: Fp2 = .{ .c0 = Fp.zero, .c1 = Fp.zero };
    pub const one: Fp2 = .{ .c0 = Fp.one, .c1 = Fp.zero };

    /// Parses `c1 || c0` (see `encoded_bytes`'s doc comment for the
    /// order). REAL: pure byte-slicing plus `Fp.fromBytes`'s own
    /// canonical check on each half.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FpError!Fp2 {
        const c1 = try Fp.fromBytes(bytes[0..Fp.encoded_bytes].*);
        const c0 = try Fp.fromBytes(bytes[Fp.encoded_bytes..encoded_bytes].*);
        return .{ .c0 = c0, .c1 = c1 };
    }

    /// Serializes `c1 || c0`. REAL.
    pub fn toBytes(self: Fp2) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..Fp.encoded_bytes].* = self.c1.toBytes();
        out[Fp.encoded_bytes..encoded_bytes].* = self.c0.toBytes();
        return out;
    }

    /// REAL: component-wise `Fp.isZero`.
    pub fn isZero(self: Fp2) bool {
        return self.c0.isZero() and self.c1.isZero();
    }

    /// REAL: component-wise `Fp.eql`.
    pub fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    // ── field arithmetic ────────────────────────────────────────────────

    /// `(a0+a1 u) + (b0+b1 u) = (a0+b0) + (a1+b1) u` — component-wise
    /// `Fp.add`.
    pub fn add(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }

    /// Component-wise `Fp.sub`.
    pub fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }

    /// Component-wise `Fp.neg`.
    pub fn neg(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }

    /// `(a0+a1 u)(b0+b1 u) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) u` (using
    /// `u^2 = -1`). Karatsuba 3-multiplication form — same construction
    /// as `bls12_381.Fp2.mul` (this formula's shape is independent of
    /// the specific field, only `u^2 = -1` matters): `v0 = a0*b0`,
    /// `v1 = a1*b1`, `c0 = v0 - v1`, `c1 = (a0+a1)*(b0+b1) - v0 - v1`.
    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        return .{
            .c0 = v0.sub(v1),
            .c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(v0).sub(v1),
        };
    }

    /// `(c0+c1 u)^2 = (c0^2 - c1^2) + 2 c0 c1 u = (c0+c1)(c0-c1) +
    /// 2 c0 c1 u` — same two-`Fp.mul` construction as `bls12_381.Fp2.square`.
    pub fn square(a: Fp2) Fp2 {
        const t = a.c0.mul(a.c1);
        return .{
            .c0 = a.c0.add(a.c1).mul(a.c0.sub(a.c1)),
            .c1 = t.add(t),
        };
    }

    /// Multiplicative inverse. Construction: the norm trick — for
    /// `a = c0+c1 u`, `norm(a) = c0^2+c1^2 ∈ Fp`, so `a^-1 = (c0 - c1
    /// u) * norm(a)^-1` — ONE `Fp.inv` plus a few `Fp.mul`s. Same as
    /// `bls12_381.Fp2.inv` (the formula depends only on `u^2 = -1`).
    pub fn inv(a: Fp2) error{NotInvertible}!Fp2 {
        const norm_inv = try a.c0.square().add(a.c1.square()).inv();
        return .{
            .c0 = a.c0.mul(norm_inv),
            .c1 = a.c1.neg().mul(norm_inv),
        };
    }

    /// RFC 9380 §4's `inv0` lifted to `Fp2` — mirrors `Fp.inv0`/
    /// `bls12_381.Fp2.inv0`.
    pub fn inv0(a: Fp2) Fp2 {
        return a.inv() catch Fp2.zero;
    }

    /// Multiplication by the `Fp6` non-residue `ξ = 9+u` (`fp6.zig`'s
    /// `nonresidue`) — NOT a general `Fp2.mul`, but a dedicated
    /// operation because `Fp6`/`Fp12` arithmetic calls it extremely
    /// often. **THIS IS THE ONE FORMULA THAT DIFFERS FROM
    /// `bls12_381.Fp2.mulByNonresidue`** (which multiplies by `1+u`,
    /// BLS12-381's `Fp6` non-residue) — BN254 instead uses `ξ = 9+u`:
    /// `(c0+c1 u)(9+u) = (9 c0 - c1) + (c0 + 9 c1) u` (expand
    /// `(c0+c1u)(9+u) = 9c0 + c0 u + 9c1 u + c1 u^2 = 9c0 - c1 + (c0 +
    /// 9c1) u`, using `u^2 = -1`). Pinned equal to the general `mul` by
    /// this file's own test below.
    pub fn mulByNonresidue(a: Fp2) Fp2 {
        const nine_c0 = a.c0.add(a.c0).add(a.c0).add(a.c0).add(a.c0).add(a.c0).add(a.c0).add(a.c0).add(a.c0);
        const nine_c1 = a.c1.add(a.c1).add(a.c1).add(a.c1).add(a.c1).add(a.c1).add(a.c1).add(a.c1).add(a.c1);
        return .{ .c0 = nine_c0.sub(a.c1), .c1 = a.c0.add(nine_c1) };
    }

    /// The Frobenius endomorphism `x -> x^p` restricted to `Fp2`: for
    /// `a = c0+c1 u`, `a^p = c0^p + c1^p u^p`. Since `c0, c1 ∈ Fp`,
    /// `c0^p = c0` and `c1^p = c1` (Fermat), and because `u^2 = -1`
    /// with `p ≡ 3 (mod 4)` (confirmed: `p`'s low byte `0x47 mod 4 ==
    /// 3`), `u^p = -u` — same derivation as `bls12_381.Fp2.frobenius`,
    /// independent of the specific `p` beyond `p ≡ 3 (mod 4)`. So
    /// `Frobenius(c0+c1 u) = c0 - c1 u` — conjugation.
    pub fn frobenius(a: Fp2) Fp2 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    /// `a^e`, `e` a big-endian byte string — plain left-to-right
    /// square-and-multiply. VARIABLE-TIME in the exponent's bit
    /// pattern: for PUBLIC exponents only (every current caller —
    /// `sqrt`'s fixed exponents, `fp6.zig`/`fp12.zig`'s Frobenius
    /// coefficients, tests). Same as `bls12_381.Fp2.pow`.
    pub fn pow(a: Fp2, e: []const u8) Fp2 {
        var acc = Fp2.one;
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

    /// Constant-time select: returns `a` if `cond`, else `b` —
    /// component-wise `Fp.ctSelect`.
    pub fn ctSelect(cond: bool, a: Fp2, b: Fp2) Fp2 {
        return .{
            .c0 = Fp.ctSelect(cond, a.c0, b.c0),
            .c1 = Fp.ctSelect(cond, a.c1, b.c1),
        };
    }

    /// Square root over `Fp2`, or `null` if `a` is not a QR. Algorithm:
    /// the same "complex method" for even extension fields with
    /// `p ≡ 3 (mod 4)` as `bls12_381.Fp2.sqrt` — Adj &
    /// Rodriguez-Henriquez, IACR ePrint 2012/685, Algorithm 9:
    ///
    /// ```
    /// a1    = a^((p-3)/4)
    /// x0    = a1 * a          (= a^((p+1)/4))
    /// alpha = a1 * x0         (= a^((p-1)/2), the Euler symbol shape)
    /// if alpha == -1:  x = x0 * u          (u = sqrt(-1), u^2 = -1)
    /// else:            x = x0 * (1 + alpha)^((p-1)/2)
    /// ```
    ///
    /// The candidate `x` is a real square root iff `a` is a QR, so the
    /// final `x^2 == a` check decides QR-ness. Both exponents are
    /// FIXED PUBLIC constants derived at comptime from the verified
    /// `p_bytes` (`fp.pExponentBytes`).
    pub fn sqrt(a: Fp2) ?Fp2 {
        const a1 = a.pow(&p_minus_3_over_4_bytes);
        const x0 = a1.mul(a);
        const alpha = a1.mul(x0);

        const neg_one = Fp2.one.neg();
        const u = Fp2{ .c0 = Fp.zero, .c1 = Fp.one };
        const x = if (alpha.eql(neg_one))
            x0.mul(u)
        else
            x0.mul(Fp2.one.add(alpha).pow(&p_minus_1_over_2_bytes));

        return if (x.square().eql(a)) x else null;
    }
};

/// `(p-3)/4`, big-endian — `Fp2.sqrt`'s first exponent (comptime-derived
/// from `fp.zig`'s verified `p_bytes`; `p ≡ 3 (mod 4)` so the division
/// is exact — enforced at comptime by `pExponentBytes`).
const p_minus_3_over_4_bytes: [32]u8 = fp.pExponentBytes(-3, 4);

/// `(p-1)/2`, big-endian — `Fp2.sqrt`'s second exponent.
const p_minus_1_over_2_bytes: [32]u8 = fp.pExponentBytes(-1, 2);

// ── tests ────────────────────────────────────────────────────────────────

test "Fp2.zero / Fp2.one round-trip through bytes" {
    const z = Fp2.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));

    const o = Fp2.one.toBytes();
    var expected = [_]u8{0} ** Fp2.encoded_bytes;
    expected[Fp2.encoded_bytes - 1] = 1; // c0's low byte; c1 is all-zero (high half)
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fp2.fromBytes / toBytes preserve c1||c0 ordering" {
    var bytes = [_]u8{0} ** Fp2.encoded_bytes;
    bytes[Fp.encoded_bytes - 1] = 0xaa; // c1's low byte
    bytes[Fp2.encoded_bytes - 1] = 0xbb; // c0's low byte
    const el = try Fp2.fromBytes(bytes);
    try std.testing.expectEqual(@as(u8, 0xaa), el.c1.toBytes()[Fp.encoded_bytes - 1]);
    try std.testing.expectEqual(@as(u8, 0xbb), el.c0.toBytes()[Fp.encoded_bytes - 1]);
    try std.testing.expectEqualSlices(u8, &bytes, &el.toBytes());
}

test "Fp2.isZero / eql are component-wise" {
    try std.testing.expect(Fp2.zero.isZero());
    try std.testing.expect(!Fp2.one.isZero());
    try std.testing.expect(Fp2.one.eql(Fp2.one));
    try std.testing.expect(!Fp2.one.eql(Fp2.zero));
}

// A fixed, arbitrary non-trivial test element (both components nonzero).
fn testElement() !Fp2 {
    return .{
        .c0 = try Fp.fromInt(u64, 0x0123_4567_89ab_cdef),
        .c1 = try Fp.fromInt(u64, 0xfedc_ba98_7654_3210),
    };
}

test "Fp2 ring identities: a + (-a) = 0, (a+b)^2 = a^2 + 2ab + b^2, square == mul(a,a)" {
    const a = try testElement();
    const b = Fp2{ .c0 = try Fp.fromInt(u64, 42), .c1 = try Fp.fromInt(u64, 31337) };
    try std.testing.expect(a.add(a.neg()).isZero());
    const two_ab = a.mul(b).add(a.mul(b));
    try std.testing.expect(a.add(b).square().eql(a.square().add(two_ab).add(b.square())));
    try std.testing.expect(a.square().eql(a.mul(a)));
}

test "Fp2 Karatsuba mul: u * u == -1" {
    const u = Fp2{ .c0 = Fp.zero, .c1 = Fp.one };
    try std.testing.expect(u.mul(u).eql(Fp2.one.neg()));
}

test "Fp2.inv: a * a^-1 == 1; inv(0) errors" {
    const a = try testElement();
    try std.testing.expect(a.mul(try a.inv()).eql(Fp2.one));
    try std.testing.expectError(error.NotInvertible, Fp2.zero.inv());
}

test "Fp2.inv0 (RFC 9380): inv0(0) == 0, inv0(a) == a^-1 otherwise" {
    try std.testing.expect(Fp2.zero.inv0().isZero());
    const a = try testElement();
    try std.testing.expect(a.mul(a.inv0()).eql(Fp2.one));
}

test "Fp2.mulByNonresidue == mul by (9+u)" {
    const a = try testElement();
    const xi = Fp2{ .c0 = try Fp.fromInt(u8, 9), .c1 = Fp.one };
    try std.testing.expect(a.mulByNonresidue().eql(a.mul(xi)));
}

test "KAT: Fp2.mulByNonresidue on a=1 gives xi=9+u exactly (byte-exact)" {
    const r = Fp2.one.mulByNonresidue();
    try std.testing.expect(r.c0.eql(try Fp.fromInt(u8, 9)));
    try std.testing.expect(r.c1.eql(Fp.one));
}

test "Fp2.frobenius is an involution and equals pow(p) (definitional)" {
    const a = try testElement();
    try std.testing.expect(a.frobenius().frobenius().eql(a));
    try std.testing.expect(a.frobenius().eql(a.pow(&fp.p_bytes)));
}

test "Fp2.sqrt: sqrt(a^2) in {a, -a}; xi = 9+u is a non-residue (null)" {
    const a = try testElement();
    const c = a.square();
    const s = c.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(s.eql(a) or s.eql(a.neg()));
    try std.testing.expect(s.square().eql(c));
    // xi = 9+u is a quadratic non-residue in Fp2 (verified independently
    // with big-int arithmetic outside this module: xi^((p^2-1)/2) ==
    // -1) — sqrt must return null, exercising the reject path. This is
    // also the property that makes xi a valid Fp6 cubic non-residue
    // (fp6.zig).
    const xi = Fp2{ .c0 = try Fp.fromInt(u8, 9), .c1 = Fp.one };
    try std.testing.expect(xi.sqrt() == null);
    const z = Fp2.zero.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(z.isZero());
    const o = Fp2.one.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(o.square().eql(Fp2.one));
}

test "Fp2.sqrt exercises the alpha == -1 branch (a = u^2 shape inputs)" {
    const u = Fp2{ .c0 = Fp.zero, .c1 = Fp.one };
    if (u.sqrt()) |s| try std.testing.expect(s.square().eql(u));
    const minus_one = Fp2.one.neg();
    const s2 = minus_one.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(s2.square().eql(minus_one));
    try std.testing.expect(s2.eql(u) or s2.eql(u.neg()));
}

test "Fp2.pow: a^0 = 1, a^1 = a; Fp2.ctSelect picks the right operand" {
    const a = try testElement();
    try std.testing.expect(a.pow(&[_]u8{0}).eql(Fp2.one));
    try std.testing.expect(a.pow(&[_]u8{1}).eql(a));
    try std.testing.expect(Fp2.ctSelect(true, a, Fp2.zero).eql(a));
    try std.testing.expect(Fp2.ctSelect(false, a, Fp2.zero).eql(Fp2.zero));
}

test "KAT: Fp2 multiplication byte-exact against an independent reference" {
    // a = 0x0123456789abcdef + 0xfedcba9876543210*u, b = 42 + 31337*u.
    // Independently computed with plain Python big-integer arithmetic
    // outside this module (a0*b0 - a1*b1, a0*b1 + a1*b0 mod p; see
    // SPEC.md's "Verification performed" for the script). Encoding is
    // c1||c0, 32 bytes each.
    const a = try testElement();
    const b = Fp2{ .c0 = try Fp.fromInt(u16, 42), .c1 = try Fp.fromInt(u16, 31337) };
    const got = a.mul(b);
    var expected: [Fp2.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0000000000000000000000000000000000000000000000b516c16c16c16b93a730644e72e131a029b85045b68181585d97816a91687150afb274be26c6489ded");
    try std.testing.expectEqualSlices(u8, &expected, &got.toBytes());
}

test "KAT: Fp2 inverse byte-exact against an independent reference" {
    const a = try testElement();
    const got = try a.inv();
    var expected: [Fp2.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "20980b37a18ff748de2e47bb25de1cf9fe91c04fde54a01fb031d455c76e56ce18a0ccf7c074414698abb52543b18d4b11d865e78cf46702e46403b15b6312f9");
    try std.testing.expectEqualSlices(u8, &expected, &got.toBytes());
}
