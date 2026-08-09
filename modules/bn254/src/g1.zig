// SPDX-License-Identifier: MIT
//! `G1` — the prime-order-`r` subgroup of `E(Fp): y^2 = x^3 + 3`, the
//! FIRST of BN254's two pairing groups (`e: G1 x G2 -> Gt`, a future
//! Part 4). Generator `G1 = (1, 2)` (EIP-196 / `py_ecc.bn128`).
//!
//! **`G1`'s cofactor is 1** — a deliberate, load-bearing difference from
//! the sibling `bls12_381` module's `G1` (cofactor `h1 =
//! 0x396c8c005555e1568c00aaab0000aaab`, nontrivial). BN254's defining
//! polynomial family gives `#E(Fp) = p + 1 - t = r` EXACTLY (`t = 6x^2+1`
//! the trace of Frobenius, `r(x) = 36x^4+36x^3+18x^2+6x+1` — see
//! `fp.zig`'s/`scalar.zig`'s own doc comments and `SPEC.md`), i.e. `r`
//! IS `E(Fp)`'s full order, not merely a large prime factor of it. Since
//! `r` is prime, `E(Fp)` has no nontrivial proper subgroups (Lagrange) —
//! `E(Fp)` and `G1` are THE SAME SET. Consequences that shape this
//! file's API, spelled out so a reader used to `bls12_381`'s pattern
//! does not go looking for the missing pieces:
//!   - `subgroupCheck` is exactly `isOnCurve` (no `[r]P == O`
//!     scalar-mul needed, though `scalarMulBytes` is still exposed and
//!     tested against `r` directly — see `SPEC.md`'s "Verification
//!     performed" and this file's own KAT tests).
//!   - There is no `clearCofactor` / `cofactor_bytes` — nothing to
//!     clear.
//!
//! **Status: implemented.** Jacobian add/double/negate, constant-time
//! double-and-add-always `scalarMul`, `isOnCurve`, EIP-196 64-byte
//! uncompressed (de)serialization (`(0,0)` = point at infinity — see
//! `SPEC.md`'s "EIP-196/197 encoding" section). EIP-196/197 has no
//! compressed point format (unlike BLS12-381's ZCash/IETF wire format),
//! so there is no `toBytesCompressed`/`fromBytesCompressed`/`recoverY`
//! here either — this file's codec section is correspondingly simpler
//! than `bls12_381/src/g1.zig`'s.

const std = @import("std");
const fp = @import("fp.zig");
const scalarmod = @import("scalar.zig");

pub const Fp = fp.Fp;
pub const Fr = scalarmod.Fr;

/// The curve equation constant: `E: y^2 = x^3 + b`, `b = 3` (EIP-196 /
/// `py_ecc.bn128_curve.b`). REAL: `Fp.fromInt` is pure `std.crypto.ff`
/// delegation (see `fp.zig`).
pub const b: Fp = Fp.fromInt(u8, 3) catch @compileError("bn254: bad G1 b constant");

pub const G1Error = error{
    /// Byte length is not `encoded_bytes` (64).
    InvalidEncoding,
    /// A coordinate failed `Fp.fromBytes` (non-canonical, i.e. `>= p`).
    InvalidFieldElement,
    /// The decoded `(x, y)` does not satisfy `y^2 = x^3 + b`.
    NotOnCurve,
};

/// An affine `G1` point: `(x, y)`, or the point at infinity
/// (`infinity = true`, `x`/`y` unspecified — encoded as all-zero per
/// EIP-196, see `toBytes`/`fromBytes`).
pub const Affine = struct {
    x: Fp,
    y: Fp,
    infinity: bool = false,

    /// `G1`'s standard fixed generator, `(1, 2)` — EIP-196 §"Precompiled
    /// contracts for optimal Ate pairing" and `py_ecc.bn128.G1` agree.
    /// On-curve by direct computation: `2^2 == 1^3 + 3` (`4 == 4`) — see
    /// `fp.zig`'s own KAT test, and this file's `"G1 generator is on
    /// the curve"` test below.
    pub const generator: Affine = .{
        .x = Fp.one,
        .y = Fp.fromInt(u8, 2) catch @compileError("bn254: bad G1 generator y"),
    };

    /// The point at infinity (`G1`'s group identity).
    pub const identity: Affine = .{ .x = Fp.zero, .y = Fp.zero, .infinity = true };

    /// `true` iff this is the point at infinity. REAL: a field read.
    pub fn isInfinity(self: Affine) bool {
        return self.infinity;
    }
};

/// A `G1` point in Jacobian projective coordinates `(X, Y, Z)`,
/// representing the affine point `(X/Z^2, Y/Z^3)` — avoids an `Fp.inv`
/// per operation; only `toAffine` needs one.
pub const Jacobian = struct {
    x: Fp,
    y: Fp,
    z: Fp,

    /// The point at infinity, conventionally `(1, 1, 0)` in Jacobian
    /// coordinates.
    pub const identity: Jacobian = .{ .x = Fp.one, .y = Fp.one, .z = Fp.zero };

    /// `true` iff this represents the point at infinity: `Z == 0`.
    pub fn isIdentity(self: Jacobian) bool {
        return self.z.isZero();
    }

    /// Alias for `isIdentity` — EIP-196 vocabulary ("point at
    /// infinity"), same predicate.
    pub fn isInfinity(self: Jacobian) bool {
        return self.isIdentity();
    }

    /// Lifts an affine point into Jacobian coordinates: `(x, y, 1)`, or
    /// `identity` if `p.infinity`.
    pub fn fromAffine(p: Affine) Jacobian {
        if (p.infinity) return identity;
        return .{ .x = p.x, .y = p.y, .z = Fp.one };
    }

    /// Converts back to affine: `(X/Z^2, Y/Z^3)`, or `Affine.identity`
    /// if `isIdentity()`.
    pub fn toAffine(self: Jacobian) Affine {
        if (self.isIdentity()) return Affine.identity;
        const z_inv = self.z.inv() catch unreachable; // z != 0 checked above
        const z_inv2 = z_inv.square();
        return .{
            .x = self.x.mul(z_inv2),
            .y = self.y.mul(z_inv2).mul(z_inv),
        };
    }

    /// Constant-time select: returns `a` if `cond`, else `b` —
    /// coordinate-wise `Fp.ctSelect`.
    fn ctSelect(cond: bool, on_true: Jacobian, on_false: Jacobian) Jacobian {
        return .{
            .x = Fp.ctSelect(cond, on_true.x, on_false.x),
            .y = Fp.ctSelect(cond, on_true.y, on_false.y),
            .z = Fp.ctSelect(cond, on_true.z, on_false.z),
        };
    }

    // ── group arithmetic ────────────────────────────────────────────
    //
    // Same constructions as `bls12_381/src/g1.zig`'s `Jacobian`
    // (add-2007-bl / dbl-2009-l, EFD `shortw/jacobian-0`) — both
    // formulas are GENERIC in the curve constant `b` (only the `a = 0`
    // short-Weierstrass coefficient matters, true for BN254's `G1`
    // too), so they carry over unchanged. See that file's doc comments
    // for the full derivation and the branchless degenerate-case
    // discipline (constant-time w.r.t. which case fired — `scalarMul`'s
    // accumulator is commonly secret-dependent).

    pub fn add(a: Jacobian, other: Jacobian) Jacobian {
        const z1z1 = a.z.square();
        const z2z2 = other.z.square();
        const ua = a.x.mul(z2z2); // U1
        const ub = other.x.mul(z1z1); // U2
        const sa = a.y.mul(other.z).mul(z2z2); // S1
        const sb = other.y.mul(a.z).mul(z1z1); // S2
        const h = ub.sub(ua); // 0 iff same x (P == Q or P == -Q)
        const s_diff = sb.sub(sa); // 0 (given h == 0) iff P == Q

        const i = h.add(h).square();
        const j = h.mul(i);
        const rr = s_diff.add(s_diff);
        const v = ua.mul(i);
        const x3 = rr.square().sub(j).sub(v.add(v));
        const s1j = sa.mul(j);
        const y3 = rr.mul(v.sub(x3)).sub(s1j.add(s1j));
        const z3 = a.z.add(other.z).square().sub(z1z1).sub(z2z2).mul(h);

        var out: Jacobian = .{ .x = x3, .y = y3, .z = z3 };
        const dbl = a.double();
        const h_zero: u1 = @intFromBool(h.isZero());
        const s_zero: u1 = @intFromBool(s_diff.isZero());
        out = ctSelect((h_zero & (1 - s_zero)) == 1, identity, out); // P == -Q
        out = ctSelect((h_zero & s_zero) == 1, dbl, out); // P == Q
        out = ctSelect(other.isIdentity(), a, out);
        out = ctSelect(a.isIdentity(), other, out);
        return out;
    }

    pub fn double(a: Jacobian) Jacobian {
        const xx = a.x.square(); // A
        const yy = a.y.square(); // B
        const yyyy = yy.square(); // C
        const d0 = a.x.add(yy).square().sub(xx).sub(yyyy);
        const d = d0.add(d0); // D = 2((X1+B)^2 - A - C)
        const e = xx.add(xx).add(xx); // E = 3A
        const f = e.square(); // F = E^2
        const x3 = f.sub(d.add(d));
        const c8 = blk: { // 8C
            const c2 = yyyy.add(yyyy);
            const c4 = c2.add(c2);
            break :blk c4.add(c4);
        };
        const y3 = e.mul(d.sub(x3)).sub(c8);
        const yz = a.y.mul(a.z);
        return .{ .x = x3, .y = y3, .z = yz.add(yz) };
    }

    /// Negation: `(X, Y, Z) -> (X, -Y, Z)`.
    pub fn negate(a: Jacobian) Jacobian {
        return .{ .x = a.x, .y = a.y.neg(), .z = a.z };
    }

    /// Scalar multiplication `[s]P`, constant-time double-and-add-always
    /// over `s`'s 32-byte (`Fr.encoded_bytes`) encoding. Same
    /// construction as `bls12_381.g1.Jacobian.scalarMul`.
    ///
    /// `s` is commonly a SECRET scalar for any future signer/prover built
    /// on this module (a private key, a witness scalar, blinding
    /// randomness) even though today's shipped consumers only ever pass
    /// public data — so the plaintext big-endian byte serialization this
    /// function itself produces is wiped before returning (wave-2 audit
    /// `bn254` F9).
    pub fn scalarMul(p: Jacobian, s: Fr) Jacobian {
        var buf: [Fr.encoded_bytes]u8 = undefined;
        return scalarMulZeroing(p, s, &buf);
    }

    /// `scalarMul`'s body, factored out with the scratch buffer as an
    /// explicit out-parameter so a test can hold onto it after the call
    /// returns and confirm the wipe actually happened — a caller cannot
    /// observe a callee's own stack scratch once the call unwinds.
    fn scalarMulZeroing(p: Jacobian, s: Fr, buf: *[Fr.encoded_bytes]u8) Jacobian {
        buf.* = s.toBytes();
        defer std.crypto.secureZero(u8, buf);
        return scalarMulBytes(p, buf);
    }

    /// `[s]P` for an arbitrary-width big-endian scalar byte string — the
    /// shared engine behind `scalarMul` (32-byte `Fr` scalars) and
    /// `subgroupCheck`'s KAT tests (the 32-byte group order `r` itself,
    /// NOT a canonical `Fr` value, since `r mod r == 0`). Constant-time
    /// double-and-add-ALWAYS: every bit performs one `double` and one
    /// (complete, branchless) `add`; the only quantity leaked is
    /// `s.len`, static at every call site.
    pub fn scalarMulBytes(p: Jacobian, s: []const u8) Jacobian {
        var acc = identity;
        for (s) |byte| {
            var bit: u3 = 7;
            while (true) : (bit -= 1) {
                acc = acc.double();
                const sum = acc.add(p);
                acc = ctSelect((byte >> bit) & 1 == 1, sum, acc);
                if (bit == 0) break;
            }
        }
        return acc;
    }

    /// `true` iff this point satisfies the curve equation `y^2 = x^3 +
    /// b` (Jacobian form: `Y^2 = X^3 + b*Z^6`), OR is the identity
    /// (vacuously on-curve).
    pub fn isOnCurve(self: Jacobian) bool {
        if (self.isIdentity()) return true;
        const z2 = self.z.square();
        const z6 = z2.square().mul(z2);
        const rhs = self.x.square().mul(self.x).add(b.mul(z6));
        return self.y.square().eql(rhs);
    }

    /// `true` iff this point is in the order-`r` subgroup `G1`. For
    /// BN254's `G1`, this is EXACTLY `isOnCurve()` — see the module doc
    /// comment's "cofactor is 1" discussion: `E(Fp)` has prime order `r`
    /// (no proper nontrivial subgroups), so on-curve implies
    /// subgroup-member, unconditionally. `[r]P == O` (the general-curve
    /// technique `bls12_381`'s `G1`/`G2` both need, via
    /// `scalarMulBytes`) is exercised as an independent SANITY CHECK in
    /// this file's own tests, not as this function's implementation —
    /// implementing `subgroupCheck` as a ~254-bit scalar-mul here would
    /// be needless work re-deriving a fact already guaranteed by the
    /// curve's defining parameters.
    pub fn subgroupCheck(self: Jacobian) bool {
        return self.isOnCurve();
    }
};

// ── wire codec (EIP-196 uncompressed encoding) ──────────────────────────
//
// EIP-196 (https://eips.ethereum.org/EIPS/eip-196) encodes `G1` points as
// raw big-endian `(x, y)` coordinate pairs, 32 bytes each, NO compression
// flag bits (unlike `bls12_381`'s ZCash/IETF wire format, `g1.zig`'s
// `Flags`/`splitFlags`/`packFlags`) — the point at infinity is the
// all-zero 64-byte string (`(0, 0)` is never on-curve for `b = 3`: `0^2 =
// 0 != 0^3 + 3 = 3`, so the all-zero encoding is unambiguous and needs no
// separate flag bit).

/// EIP-196 encoding width: 64 bytes, `x (32B) || y (32B)`.
pub const encoded_bytes = 2 * Fp.encoded_bytes;

/// Serializes `p` in the 64-byte EIP-196 form. REAL: mechanical
/// `Fp.toBytes` concatenation (or all-zero for infinity) — no curve
/// arithmetic.
pub fn toBytes(p: Affine) [encoded_bytes]u8 {
    var out: [encoded_bytes]u8 = undefined;
    if (p.infinity) {
        @memset(&out, 0);
        return out;
    }
    out[0..Fp.encoded_bytes].* = p.x.toBytes();
    out[Fp.encoded_bytes..encoded_bytes].* = p.y.toBytes();
    return out;
}

/// Parses the EIP-196 64-byte form, including the on-curve check.
/// Accepts a runtime-length slice (not a fixed `[64]u8`) so a
/// wrong-length input is a normal `error.InvalidEncoding`, matching how
/// an EIP-196/197 precompile actually receives its calldata (an
/// arbitrary-length byte string, not a statically-sized one). All-zero
/// input decodes to the point at infinity (see this section's module
/// doc comment for why that convention is unambiguous for `b = 3`).
pub fn fromBytes(bytes: []const u8) G1Error!Affine {
    if (bytes.len != encoded_bytes) return error.InvalidEncoding;
    if (std.mem.allEqual(u8, bytes, 0)) return Affine.identity;
    const x = Fp.fromBytes(bytes[0..Fp.encoded_bytes].*) catch return error.InvalidFieldElement;
    const y = Fp.fromBytes(bytes[Fp.encoded_bytes..encoded_bytes].*) catch return error.InvalidFieldElement;
    const p = Affine{ .x = x, .y = y };
    if (!Jacobian.fromAffine(p).isOnCurve()) return error.NotOnCurve;
    return p;
}

// ── tests ────────────────────────────────────────────────────────────────

test "b == 3" {
    try std.testing.expectEqual(@as(u8, 3), b.toBytes()[31]);
}

test "G1 generator is on the curve y^2 = x^3 + 3 (definitional, not via isOnCurve)" {
    const x = Affine.generator.x;
    const y = Affine.generator.y;
    try std.testing.expect(y.square().eql(x.square().mul(x).add(b)));
}

test "Jacobian.identity.isIdentity / isInfinity" {
    try std.testing.expect(Jacobian.identity.isIdentity());
    try std.testing.expect(Jacobian.identity.isInfinity());
    try std.testing.expect(!Jacobian.fromAffine(Affine.generator).isIdentity());
    try std.testing.expect(!Affine.generator.isInfinity());
    try std.testing.expect(Affine.identity.isInfinity());
}

fn jacGen() Jacobian {
    return Jacobian.fromAffine(Affine.generator);
}

// Affine equality through toAffine (Jacobian representations of the
// same point differ coordinate-wise).
fn expectSamePoint(lhs: Jacobian, rhs: Jacobian) !void {
    const aa = lhs.toAffine();
    const bb = rhs.toAffine();
    try std.testing.expectEqual(aa.infinity, bb.infinity);
    if (!aa.infinity) {
        try std.testing.expect(aa.x.eql(bb.x));
        try std.testing.expect(aa.y.eql(bb.y));
    }
}

test "G1 generator is on the curve (isOnCurve); corrupted point is not" {
    try std.testing.expect(jacGen().isOnCurve());
    try std.testing.expect(Jacobian.identity.isOnCurve());
    var bad = jacGen();
    bad.x = bad.x.add(Fp.one);
    try std.testing.expect(!bad.isOnCurve());
}

test "G1 group law: identity element, inverses, add/double consistency" {
    const g = jacGen();
    try expectSamePoint(g.add(Jacobian.identity), g);
    try expectSamePoint(Jacobian.identity.add(g), g);
    try std.testing.expect(g.add(g.negate()).isIdentity());
    try expectSamePoint(g.add(g), g.double());
    try std.testing.expect(Jacobian.identity.double().isIdentity());
    try std.testing.expect(g.double().isOnCurve());
    try std.testing.expect(g.double().add(g).isOnCurve());
}

test "G1 group law: associativity and commutativity ((G+2G)+4G == G+(2G+4G))" {
    const g = jacGen();
    const g2 = g.double();
    const g4 = g2.double();
    try expectSamePoint(g.add(g2).add(g4), g.add(g2.add(g4)));
    try expectSamePoint(g.add(g2), g2.add(g));
}

test "G1 scalarMul edge cases: [0]P = O, [1]P = P, [2]P = double(P)" {
    const g = jacGen();
    try std.testing.expect(g.scalarMul(Fr.zero).isIdentity());
    try expectSamePoint(g.scalarMul(Fr.one), g);
    const two = Fr.one.add(Fr.one);
    try expectSamePoint(g.scalarMul(two), g.double());
    try std.testing.expect(Jacobian.identity.scalarMul(two).isIdentity());
}

test "G1 scalarMul wipes its own secret-scalar byte scratch before returning (F9)" {
    // Regression for the wave-2 audit's F9: scalarMul's plaintext
    // big-endian serialization of a (potentially secret) scalar used to be
    // left on the stack with no secureZero. Using the out-parameter seam
    // (`scalarMulZeroing`) to hold onto the scratch buffer after the call:
    // if the wipe did not run, `buf` would still hold `s`'s nonzero bytes.
    var s_bytes = [_]u8{0xff} ** 32;
    s_bytes[0] = 0x01; // stay < r (r's top byte is 0x30)
    const s = try Fr.fromBytes(s_bytes);
    var buf: [Fr.encoded_bytes]u8 = undefined;
    _ = Jacobian.scalarMulZeroing(jacGen(), s, &buf);
    try std.testing.expect(std.mem.allEqual(u8, &buf, 0));
}

test "G1 scalarMul distributes: [a+b]G == [a]G + [b]G and [a*b]G == [a]([b]G)" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 0x35;
    a_bytes[16] = 0x9c;
    const sa = try Fr.fromBytes(a_bytes);
    var b_bytes = [_]u8{0} ** 32;
    b_bytes[31] = 0x0b;
    b_bytes[8] = 0x77;
    const sb = try Fr.fromBytes(b_bytes);
    const g = jacGen();
    try expectSamePoint(g.scalarMul(sa.add(sb)), g.scalarMul(sa).add(g.scalarMul(sb)));
    try expectSamePoint(g.scalarMul(sa.mul(sb)), g.scalarMul(sb).scalarMul(sa));
}

test "G1 subgroup: [r]G == O (sanity check on the cofactor=1 claim); subgroupCheck matches" {
    // r itself is NOT a canonical Fr value (r mod r == 0), so this goes
    // through scalarMulBytes directly, not scalarMul/Fr — see
    // scalarMulBytes' doc comment.
    try std.testing.expect(jacGen().scalarMulBytes(&scalarmod.r_bytes).isIdentity());
    try std.testing.expect(jacGen().subgroupCheck());
    try std.testing.expect(Jacobian.identity.subgroupCheck());
}

// Cross-check vectors: [k]G1 for small k and a larger scalar, computed
// with an INDEPENDENT from-scratch implementation (textbook
// affine-coordinate EC formulas over Python big integers — a different
// algorithm family from this module's Jacobian/std.crypto.ff-Montgomery
// arithmetic; see SPEC.md's "Verification performed").
const k2_x_hex = "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3";
const k2_y_hex = "15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4";
const k_scalar_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const kg_x_hex = "14c6615c4fbecfa4a2c2197ae8152904ce2c0d9daab228650993959c9d5c322c";
const kg_y_hex = "1310113ec96bd4f56c1a3abb96dea45ffb8d785ea7a55faf38e12bfd92ba179b";

fn hexFp(comptime hex: *const [64:0]u8) !Fp {
    var bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex);
    return Fp.fromBytes(bytes);
}

test "G1 KAT: [2]G matches the independent cross-check vector" {
    const two_g = jacGen().double().toAffine();
    try std.testing.expect(two_g.x.eql(try hexFp(k2_x_hex)));
    try std.testing.expect(two_g.y.eql(try hexFp(k2_y_hex)));
}

test "G1 KAT: [k]G matches the independent cross-check vector" {
    var k_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&k_bytes, k_scalar_hex);
    const k = try Fr.fromBytes(k_bytes);
    const kg = jacGen().scalarMul(k).toAffine();
    try std.testing.expect(kg.x.eql(try hexFp(kg_x_hex)));
    try std.testing.expect(kg.y.eql(try hexFp(kg_y_hex)));
}

// ── EIP-196 codec tests ─────────────────────────────────────────────────

test "toBytes/fromBytes round-trip the generator; byte-exact KAT" {
    const bytes = toBytes(Affine.generator);
    var expected = [_]u8{0} ** encoded_bytes;
    expected[31] = 1; // x = 1
    expected[63] = 2; // y = 2
    try std.testing.expectEqualSlices(u8, &expected, &bytes);

    const back = try fromBytes(&bytes);
    try std.testing.expect(back.x.eql(Affine.generator.x));
    try std.testing.expect(back.y.eql(Affine.generator.y));
}

test "toBytes/fromBytes round-trip [2]G (both coordinates nonzero, non-generator)" {
    const p = jacGen().double().toAffine();
    const bytes = toBytes(p);
    const back = try fromBytes(&bytes);
    try std.testing.expect(back.x.eql(p.x));
    try std.testing.expect(back.y.eql(p.y));
}

test "toBytes(identity) is all-zero; fromBytes(all-zero) is identity" {
    const bytes = toBytes(Affine.identity);
    try std.testing.expect(std.mem.allEqual(u8, &bytes, 0));
    const p = try fromBytes(&bytes);
    try std.testing.expect(p.infinity);
}

test "fromBytes rejects the wrong length" {
    var short = [_]u8{0} ** (encoded_bytes - 1);
    try std.testing.expectError(error.InvalidEncoding, fromBytes(&short));
    var long = [_]u8{0} ** (encoded_bytes + 1);
    try std.testing.expectError(error.InvalidEncoding, fromBytes(&long));
}

test "fromBytes rejects a coordinate >= p" {
    var bytes = [_]u8{0} ** encoded_bytes;
    bytes[0..32].* = fp.p_bytes; // x == p, non-canonical
    bytes[63] = 2;
    try std.testing.expectError(error.InvalidFieldElement, fromBytes(&bytes));
}

test "fromBytes rejects an off-curve (x, y) pair" {
    // (1, 3): 3^2 = 9 != 1^3 + 3 = 4.
    var bytes = [_]u8{0} ** encoded_bytes;
    bytes[31] = 1;
    bytes[63] = 3;
    try std.testing.expectError(error.NotOnCurve, fromBytes(&bytes));
}
