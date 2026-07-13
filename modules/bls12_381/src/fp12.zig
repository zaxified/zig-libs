// SPDX-License-Identifier: MIT
//! `Fp12 = Fp6[w] / (w^2 - v)` — the top of the extension-field tower,
//! i.e. `w^2 = v` (`v` = `Fp6`'s indeterminate, `fp6.zig`). An element is
//! `c0 + c1*w`, `c0, c1 ∈ Fp6`. This is the pairing's TARGET field: the
//! output of `e: G1 x G2 -> Gt`, `Gt` being the order-`r` subgroup of
//! `Fp12*` (Part 2 — the Miller loop + final exponentiation, NOT
//! scaffolded here beyond the markers below).
//!
//! **Status: implemented** (general field arithmetic: `add`/`sub`/
//! `neg`/`mul`/`square`/`inv`/`conjugate`/`frobenius`). Pairing-SPECIFIC
//! helpers remain Part 2's job: `cyclotomicSquare` (whose only consumer
//! is the final exponentiation's hard part) is deliberately still a
//! `@panic("TODO(part2)")` stub, and the sparse Miller-loop
//! multiplication / final-exponentiation helpers are `// TODO(part2)`
//! markers at the bottom of this file.

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
/// REAL: a plain comptime `Fp6` literal, no arithmetic.
pub const nonresidue: Fp6 = .{ .c0 = Fp2.zero, .c1 = Fp2.one, .c2 = Fp2.zero };

/// An element of `Fp12`: `c0 + c1*w`.
pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    /// Wire encoding: `c1 (288B, HIGH) || c0 (288B, LOW)` — 576 bytes
    /// total. Same high-to-low convention as `Fp2`/`Fp6` (see
    /// `fp2.zig`'s doc comment). This is the shape a pairing OUTPUT
    /// (`Gt` element) would serialize as, if this module ever exposes
    /// raw `Fp12` serialization — the more common wire format for a
    /// `Gt` element in downstream protocols is a COMPRESSED form (not
    /// scaffolded here; out of Part 1's scope, see `README.md`).
    pub const encoded_bytes = 2 * Fp6.encoded_bytes; // 576

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

    /// Degree-2 extension multiplication over `w^2 = v`
    /// (`nonresidue`, this file). Karatsuba: for `a = a0+a1 w`,
    /// `b = b0+b1 w`:
    /// ```
    /// v0 = a0*b0,  v1 = a1*b1   (two Fp6.mul)
    /// c0 = v0 + v*v1            (v*v1 is Fp6.mulByNonresidue)
    /// c1 = (a0+a1)*(b0+b1) - v0 - v1
    /// ```
    /// 3 `Fp6.mul` total (vs. 4 for schoolbook) — the standard
    /// construction (same Devegili et al. reference cited throughout
    /// `fp6.zig`).
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        // Karatsuba (doc comment): v0 = a0*b0, v1 = a1*b1,
        // c0 = v0 + v*v1, c1 = (a0+a1)(b0+b1) - v0 - v1.
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        return .{
            .c0 = v0.add(v1.mulByNonresidue()),
            .c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(v0).sub(v1),
        };
    }

    /// `Fp12` squaring via the same Karatsuba-style dedicated formula as
    /// `mul(a,a)`, or (once the Part-2 pairing needs performance) the
    /// CYCLOTOMIC squaring formula for elements already known to be in
    /// the cyclotomic subgroup (`cyclotomicSquare`, below) — those are
    /// TWO DIFFERENT operations with different preconditions; do not
    /// conflate them. This `square` is the general one, valid for any
    /// `Fp12` element.
    pub fn square(a: Fp12) Fp12 {
        // Standard 2-mul complex-style squaring for w^2 = v (same shape
        // as zkcrypto/bls12_381's Fp12::square — see NOTICE):
        //   ab = a0*a1
        //   c0 = (a0 + a1)(a0 + v*a1) - ab - v*ab
        //   c1 = 2 ab
        const ab = a.c0.mul(a.c1);
        const c0 = a.c0.add(a.c1).mul(a.c0.add(a.c1.mulByNonresidue())).sub(ab).sub(ab.mulByNonresidue());
        return .{ .c0 = c0, .c1 = ab.add(ab) };
    }

    /// Multiplicative inverse. Construction: `a^-1 = conj(a) *
    /// norm(a)^-1` where `norm(a) = a0^2 - v*a1^2 ∈ Fp6` (mirrors
    /// `Fp2.inv`'s norm trick, one tower level up) — one `Fp6.inv` plus
    /// a few `Fp6.mul`/`Fp6.square`.
    pub fn inv(a: Fp12) error{NotInvertible}!Fp12 {
        // Norm trick (doc comment): a^-1 = conj(a) * (a0^2 - v*a1^2)^-1.
        const norm = a.c0.square().sub(a.c1.square().mulByNonresidue());
        const norm_inv = try norm.inv(); // norm == 0 iff a == 0
        return .{
            .c0 = a.c0.mul(norm_inv),
            .c1 = a.c1.neg().mul(norm_inv),
        };
    }

    /// The `Fp12/Fp6` conjugation automorphism: `w -> -w`, i.e.
    /// `conjugate(c0+c1 w) = c0 - c1 w`. NOTE this is a DIFFERENT
    /// operation from `Fp2.frobenius` (which happens to also BE
    /// conjugation, one tower level down, as a special case of `p ≡ 3
    /// mod 4` — see `fp2.zig`'s `frobenius` doc comment) — `Fp12`
    /// conjugation is the degree-2-extension automorphism `w -> -w`
    /// unconditionally, independent of `p mod 4`. Central to the
    /// pairing's FINAL EXPONENTIATION "easy part": `a^(p^6-1) =
    /// conjugate(a) * a^-1` (since `a^(p^6) = conjugate(a)` for `a ∈
    /// Fp12*` — a standard identity for THIS specific tower
    /// construction, `[Fp12:Fp6]=2` with the Fp6-Frobenius-to-the-6th
    /// collapsing to conjugation; Part 2's job to use, not this file's).
    pub fn conjugate(a: Fp12) Fp12 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    /// The Frobenius endomorphism `x -> x^p` restricted to `Fp12`: for
    /// `a = c0+c1 w`, `a^p = c0^p + c1^p w^p` — `c_i^p` is
    /// `Fp6.frobenius(c_i)` (`fp6.zig`), and `w^p` reduces to the `Fp2`
    /// coefficient `γ = ξ^((p-1)/6)` scaling `c1^p`. Derivation of the
    /// exponent (the scaffold's doc comment said `(p-1)/2`; the exact
    /// reduction is): `w^p = w^(p-1) · w = (w^2)^((p-1)/2) · w =
    /// v^((p-1)/2) · w`, and since `p ≡ 1 (mod 6)` the exponent
    /// `(p-1)/2` is a multiple of 3, so `v^((p-1)/2) = (v^3)^((p-1)/6)
    /// = ξ^((p-1)/6)` — both readings agree, the `(p-1)/6` form just
    /// lands the coefficient in `Fp2` explicitly. Computed
    /// PROGRAMMATICALLY (same policy as `Fp6.frobenius` — no
    /// transcribed table); validated by the definitional
    /// "frobenius == pow(p)" test below.
    pub fn frobenius(a: Fp12) Fp12 {
        const gamma = fp6mod.nonresidue.pow(&p_minus_1_over_6_bytes);
        return .{
            .c0 = a.c0.frobenius(),
            .c1 = a.c1.frobenius().mulByFp2(gamma),
        };
    }

    /// Squaring specialized to the CYCLOTOMIC SUBGROUP (elements `a`
    /// with `a^(p^4-p^2+1) = 1`, i.e. `a * conjugate(a) = 1` — the
    /// subgroup every Miller-loop intermediate value and every
    /// final-exponentiation intermediate lives in AFTER the easy part).
    /// The Karabina / Granger–Scott compressed-cyclotomic-squaring
    /// formula (the standard choice cited by every BLS12-381 pairing
    /// implementation in `NOTICE`) is significantly cheaper than
    /// `square` for exactly these elements — it is INCORRECT to call on
    /// an arbitrary `Fp12` element that is NOT in the cyclotomic
    /// subgroup (silently produces a wrong answer with no error, since
    /// the formula's correctness relies on the subgroup's defining
    /// relation, not on any input validation this function could
    /// cheaply perform). Part 2 (the final exponentiation's
    /// square-and-multiply-heavy "hard part") is the primary consumer;
    /// scaffolded here (rather than deferred to `// TODO(part2)`) per
    /// this task's explicit instruction to include it as an `Fp12` op.
    pub fn cyclotomicSquare(a: Fp12) Fp12 {
        _ = a;
        // Deliberately NOT implemented in Part 1 (crypto-core pass
        // included): this is a pairing-specific fast path whose only
        // consumer is the Part-2 final exponentiation — per this
        // module's Part-1 scope it lands WITH that consumer (and its
        // Miller-loop-derived test vectors), not before. Note for the
        // implementer: a cyclotomic test element CAN be built without
        // the pairing (c = conjugate(a) * a^-1, then d = c.frobenius()
        // .frobenius().mul(c) gives a^((p^6-1)(p^2+1))), so a
        // "cyclotomicSquare == square on subgroup elements" oracle is
        // available on day one of Part 2.
        @panic("TODO(part2): Fp12.cyclotomicSquare — Granger-Scott compressed squaring; lands with the final exponentiation (its only consumer)");
    }

    // TODO(part2): pairing-specific Fp12 helpers NOT scaffolded here —
    // e.g. a sparse "line-function times Fp12" multiplication (the
    // Miller loop's inner accumulation step, which multiplies by a
    // structurally-sparse Fp12 element much cheaper than a general
    // `mul`), and the final-exponentiation "hard part" exponentiation
    // itself (a fixed square-and-multiply chain keyed to the BLS
    // parameter z = -0xd201000000010000). Both belong with the Miller
    // loop / pairing function itself, not this field-arithmetic file.
};

/// `(p-1)/6`, big-endian — the `Fp12` Frobenius-coefficient exponent
/// (comptime-derived from `fp.zig`'s verified `p_bytes`; `p ≡ 1 (mod
/// 6)`, so the division is exact — enforced at comptime).
const p_minus_1_over_6_bytes: [48]u8 = fp.pExponentBytes(-1, 6);

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
    // NOTE: byte 0 is the top byte of the innermost Fp element (c1's
    // Fp6.c2's Fp2.c1), which must stay < p's own top byte (0x1a) to be
    // guaranteed canonical regardless of the remaining 47 bytes — 0x11
    // (same margin as fp6.zig's identical test) is safely below that.
    bytes[0] = 0x11; // top byte of c1
    bytes[Fp12.encoded_bytes - 1] = 0x44; // low byte of c0 (safe: not a top byte)
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

// A fixed, arbitrary test element with all twelve Fp coefficients
// distinct and nonzero.
fn testElement() !Fp12 {
    var out: Fp12 = undefined;
    var k: u64 = 3;
    inline for (.{ &out.c0, &out.c1 }) |c6| {
        inline for (.{ &c6.c0, &c6.c1, &c6.c2 }) |c2| {
            c2.* = .{
                .c0 = try Fp.fromInt(u64, k * 0x1111_1111),
                .c1 = try Fp.fromInt(u64, k * k + 7),
            };
            k += 1;
        }
    }
    return out;
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
    // w^2 must equal v embedded in the c0 (Fp6) component.
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
    // conjugation is an involution
    try std.testing.expect(a.conjugate().conjugate().eql(a));
}

test "Fp12.frobenius equals pow(p) (definitional) and has order 12" {
    const a = try testElement();
    try std.testing.expect(a.frobenius().eql(pow12(a, &fp.p_bytes)));
    var x = a;
    for (0..12) |_| x = x.frobenius();
    try std.testing.expect(x.eql(a));
    // frobenius^6 == conjugate on Fp12 (the final-exponentiation "easy
    // part" identity from conjugate's doc comment).
    x = a;
    for (0..6) |_| x = x.frobenius();
    try std.testing.expect(x.eql(a.conjugate()));
}

test "Fp12 Frobenius gamma matches the independently-derived constant" {
    // gamma = xi^((p-1)/6) with
    //   c0 = 0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d7
    //          84bab9c4f67ea53d63e7813d8d0775ed92235fb8
    //   c1 = 0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec9
    //          71f63c5f282d5ac14d6c7ec22cf78a126ddc4af3
    // Independently recomputed with big-integer exponentiation outside
    // this module (see NOTICE); also equals zkcrypto/bls12_381
    // fp12.rs FROBENIUS_COEFF_FP12_C1[1].
    const gamma = fp6mod.nonresidue.pow(&p_minus_1_over_6_bytes);
    var expected_c0: [48]u8 = undefined;
    var expected_c1: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_c0, "1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8");
    _ = try std.fmt.hexToBytes(&expected_c1, "00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3");
    try std.testing.expectEqualSlices(u8, &expected_c0, &gamma.c0.toBytes());
    try std.testing.expectEqualSlices(u8, &expected_c1, &gamma.c1.toBytes());
}
