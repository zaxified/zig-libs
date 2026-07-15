// SPDX-License-Identifier: MIT
//! `G2` — the prime-order-`r` subgroup of the SEXTIC TWIST `E':
//! y^2 = x^3 + b'` over `Fp2` (`fp2.zig`), `b' = 3/ξ = 3*(9+u)^-1`,
//! the SECOND of BN254's two pairing groups (`e: G1 x G2 -> Gt`, a
//! future Part 4). Structurally a mirror of `g1.zig` one field-tower
//! level up — see that file's module doc comment for the shared design
//! reasoning (branchless point arithmetic); this file's own doc
//! comments only call out what's DIFFERENT for `G2`.
//!
//! **`b'` is DERIVED, not transcribed**: `twistB()` computes
//! `3 * (9+u)^-1` via real `Fp2` inversion + multiplication (`fp6.zig`'s
//! `ξ = 9+u` non-residue) — see that function's doc comment and
//! `SPEC.md`'s "Verification performed" for the independent Python
//! cross-check this is pinned against byte-exactly.
//!
//! **`G2` HAS a nontrivial cofactor** (unlike `G1`, `g1.zig`'s module
//! doc comment) — `#E'(Fp2) = r * h2` for some `h2 > 1`. This module
//! does NOT compute or expose `h2`/`cofactor_bytes`/`clearCofactor`:
//! per `SPEC.md`'s Part 3 scope, BN254 has no standardized
//! hash-to-`G2` needed for EIP-197 precompile semantics or Groth16
//! verification (both only ever consume caller-supplied, already-valid
//! `G2` points — e.g. a proof's `π_2` — never hash an arbitrary message
//! onto the twist), so cofactor CLEARING has no consumer in this arc.
//! What every future pairing/Groth16 consumer DOES need is
//! `subgroupCheck` (`[r]P == O`) — implemented below, mandatory before
//! trusting any externally-supplied `G2` point (an unchecked
//! small-subgroup point lets an attacker force a degenerate/predictable
//! pairing result — same pitfall `bls12_381/src/g2.zig`'s `SPEC.md`
//! documents for its own `G2`).
//!
//! **Status: implemented.** Same construction set as `g1.zig`, over
//! `Fp2`: Jacobian add/double/negate, constant-time double-and-add
//! `scalarMul`, `isOnCurve`, `subgroupCheck`, EIP-197 128-byte
//! uncompressed (de)serialization with the mandatory `(c1, c0)`
//! imaginary-first `Fp2` coordinate ordering (see the codec section
//! below — this is the classic footgun the task brief calls out).

const std = @import("std");
const fp = @import("fp.zig");
const fp2mod = @import("fp2.zig");
const scalarmod = @import("scalar.zig");

pub const Fp = fp.Fp;
pub const Fp2 = fp2mod.Fp2;
pub const Fr = scalarmod.Fr;

/// The `Fp6`/`Fp12` tower non-residue `ξ = 9+u` (`fp6.zig`'s
/// `nonresidue`) — NOT re-imported from `fp6.zig` to avoid pulling in
/// the whole `Fp6`/`Fp12` tower for a single `Fp2` constant; the value
/// itself is pinned equal to `fp6.nonresidue` by this file's own test.
const xi: Fp2 = .{ .c0 = Fp.fromInt(u8, 9) catch unreachable, .c1 = Fp.one };

/// The twist curve equation constant `b' = 3/ξ = 3*(9+u)^-1 ∈ Fp2`.
/// Construction: REAL `Fp2.inv` (Fermat via `std.crypto.ff`) plus a
/// real `Fp2.mul` — not a hand-transcribed literal. A runtime function
/// (not a `comptime` constant) deliberately, mirroring `fp6.zig`'s
/// `frobeniusGamma1()`: this module has no hot-loop caller of `b'`
/// (unlike `Fp6.frobenius`'s per-tower-multiplication Frobenius
/// coefficient), so a cached comptime constant would be premature
/// optimization — `isOnCurve` calls this once per invocation, itself
/// not a hot path (see `SPEC.md`'s Backlog re: deferred optimization).
///
/// Provenance: independently cross-checked in Python (`SPEC.md`'s
/// "Verification performed") — `3 * pow(9+u_norm_form, p-2, ...)`
/// computed with plain big-integer `Fp2` arithmetic, a DIFFERENT
/// implementation strategy than this module's `std.crypto.ff`-backed
/// Zig code — and pinned byte-exact by this file's own KAT test.
pub fn twistB() Fp2 {
    const xi_inv = xi.inv() catch unreachable; // xi != 0
    const three: Fp2 = .{ .c0 = Fp.fromInt(u8, 3) catch unreachable, .c1 = Fp.zero };
    return three.mul(xi_inv);
}

pub const G2Error = error{
    /// Byte length is not `encoded_bytes` (128).
    InvalidEncoding,
    /// A coordinate failed `Fp.fromBytes` (non-canonical, i.e. `>= p`).
    InvalidFieldElement,
    /// The decoded `(x, y)` does not satisfy `y^2 = x^3 + b'`.
    NotOnCurve,
};

/// An affine `G2` point: `(x, y) ∈ Fp2 x Fp2`, or the point at infinity.
pub const Affine = struct {
    x: Fp2,
    y: Fp2,
    infinity: bool = false,

    /// `G2`'s standard fixed generator point.
    ///
    /// Coordinates (`Fp2` elements, `c0 + c1*u`, decimal, matching
    /// `py_ecc.bn128.bn128_curve.G2`'s `FQ2([c0, c1])` convention and
    /// EIP-197's own test-vector citations — also the values Ethereum
    /// tooling (`gnark`, common Solidity `BN254`/`Pairing` libraries)
    /// publish for the `G2` generator, cross-checked byte-for-byte):
    /// ```
    /// x.c0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781
    /// x.c1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634
    /// y.c0 = 8495653923123431417604973247489272438418190587263600148770280649306958101930
    /// y.c1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531
    /// ```
    ///
    /// Independently verified on-twist (`y^2 == x^3 + b'`, `b' =
    /// twistB()`) by direct computation — see this file's own tests and
    /// `SPEC.md`'s "Verification performed".
    pub const generator: Affine = .{
        .x = .{
            .c0 = Fp.fromBytes(hexBytes(32, "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed")) catch
                @compileError("bn254: bad G2 generator x.c0"),
            .c1 = Fp.fromBytes(hexBytes(32, "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2")) catch
                @compileError("bn254: bad G2 generator x.c1"),
        },
        .y = .{
            .c0 = Fp.fromBytes(hexBytes(32, "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")) catch
                @compileError("bn254: bad G2 generator y.c0"),
            .c1 = Fp.fromBytes(hexBytes(32, "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b")) catch
                @compileError("bn254: bad G2 generator y.c1"),
        },
    };

    /// The point at infinity (`G2`'s group identity).
    pub const identity: Affine = .{ .x = Fp2.zero, .y = Fp2.zero, .infinity = true };

    pub fn isInfinity(self: Affine) bool {
        return self.infinity;
    }
};

/// A `G2` point in Jacobian projective coordinates over `Fp2`.
pub const Jacobian = struct {
    x: Fp2,
    y: Fp2,
    z: Fp2,

    pub const identity: Jacobian = .{ .x = Fp2.one, .y = Fp2.one, .z = Fp2.zero };

    pub fn isIdentity(self: Jacobian) bool {
        return self.z.isZero();
    }

    pub fn isInfinity(self: Jacobian) bool {
        return self.isIdentity();
    }

    pub fn fromAffine(p: Affine) Jacobian {
        if (p.infinity) return identity;
        return .{ .x = p.x, .y = p.y, .z = Fp2.one };
    }

    pub fn toAffine(self: Jacobian) Affine {
        if (self.isIdentity()) return Affine.identity;
        const z_inv = self.z.inv() catch unreachable; // z != 0 checked above
        const z_inv2 = z_inv.square();
        return .{
            .x = self.x.mul(z_inv2),
            .y = self.y.mul(z_inv2).mul(z_inv),
        };
    }

    /// Constant-time select over Jacobian points — see `g1.zig`.
    fn ctSelect(cond: bool, on_true: Jacobian, on_false: Jacobian) Jacobian {
        return .{
            .x = Fp2.ctSelect(cond, on_true.x, on_false.x),
            .y = Fp2.ctSelect(cond, on_true.y, on_false.y),
            .z = Fp2.ctSelect(cond, on_true.z, on_false.z),
        };
    }

    // ── group arithmetic ────────────────────────────────────────────
    //
    // Same constructions as g1.zig's Jacobian, over Fp2 instead of Fp —
    // GENERIC in the curve constant (only the `a = 0` short-Weierstrass
    // coefficient matters, true for both G1 and the twist E') so the
    // formulas carry over unchanged, one tower level up.

    pub fn add(a: Jacobian, other: Jacobian) Jacobian {
        const z1z1 = a.z.square();
        const z2z2 = other.z.square();
        const ua = a.x.mul(z2z2); // U1
        const ub = other.x.mul(z1z1); // U2
        const sa = a.y.mul(other.z).mul(z2z2); // S1
        const sb = other.y.mul(a.z).mul(z1z1); // S2
        const h = ub.sub(ua);
        const s_diff = sb.sub(sa);

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
        const xx = a.x.square();
        const yy = a.y.square();
        const yyyy = yy.square();
        const d0 = a.x.add(yy).square().sub(xx).sub(yyyy);
        const d = d0.add(d0);
        const e = xx.add(xx).add(xx);
        const f = e.square();
        const x3 = f.sub(d.add(d));
        const c8 = blk: {
            const c2 = yyyy.add(yyyy);
            const c4 = c2.add(c2);
            break :blk c4.add(c4);
        };
        const y3 = e.mul(d.sub(x3)).sub(c8);
        const yz = a.y.mul(a.z);
        return .{ .x = x3, .y = y3, .z = yz.add(yz) };
    }

    pub fn negate(a: Jacobian) Jacobian {
        return .{ .x = a.x, .y = a.y.neg(), .z = a.z };
    }

    pub fn scalarMul(p: Jacobian, s: Fr) Jacobian {
        return scalarMulBytes(p, &s.toBytes());
    }

    /// `[s]P` for an arbitrary-width big-endian scalar byte string —
    /// see `g1.zig`'s `scalarMulBytes` (identical constant-time
    /// double-and-add-always construction, over `Fp2` point
    /// arithmetic). The engine behind both `scalarMul` (32-byte `Fr`
    /// scalars) and `subgroupCheck` (the 32-byte group order `r`
    /// itself, NOT a canonical `Fr` value).
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

    /// `y^2 = x^3 + b'` (Jacobian: `Y^2 = X^3 + b'*Z^6`) over `Fp2`,
    /// `b' = twistB()`. See `g1.zig`'s `Jacobian.isOnCurve`.
    pub fn isOnCurve(self: Jacobian) bool {
        if (self.isIdentity()) return true;
        const z2 = self.z.square();
        const z6 = z2.square().mul(z2);
        const rhs = self.x.square().mul(self.x).add(twistB().mul(z6));
        return self.y.square().eql(rhs);
    }

    /// `true` iff this point is in the order-`r` subgroup `G2` — NOT
    /// implied by `isOnCurve()` here, unlike `G1` (`g1.zig`'s module
    /// doc comment): `G2`'s cofactor `h2 > 1`, so `E'(Fp2)` has proper
    /// nontrivial subgroups an attacker-supplied point could land in.
    /// Construction: the simple, always-correct `[r]P == O` via
    /// `scalarMulBytes` — mandatory before trusting any externally
    /// supplied `G2` point in a future pairing consumer (see module doc
    /// comment).
    pub fn subgroupCheck(self: Jacobian) bool {
        return scalarMulBytes(self, &scalarmod.r_bytes).isIdentity();
    }
};

// ── wire codec (EIP-197 uncompressed encoding, imaginary-first Fp2 order) ──
//
// EIP-197 (https://eips.ethereum.org/EIPS/eip-197) encodes a `G2` point
// as FOUR big-endian 32-byte `Fp` limbs, 128 bytes total — but NOT in
// the naive `x.c0 || x.c1 || y.c0 || y.c1` order. Per the precompile
// spec's own field-element encoding (an `Fp2` element `a + b*i` is
// encoded `(b, a)`, i.e. the IMAGINARY COMPONENT FIRST), the wire order
// is:
//
//     x.c1 (32B) || x.c0 (32B) || y.c1 (32B) || y.c0 (32B)
//
// (`c1` is this module's `u`-coefficient, i.e. the "imaginary" part
// under the `u^2 = -1` convention — see `fp2.zig`.) THIS IS THE CLASSIC
// FOOTGUN the task brief warns about: getting `c0`/`c1` backwards here
// silently produces a DIFFERENT but well-formed-looking point. Pinned
// against a KAT with `c0 != c1` (the generator itself already
// qualifies — see the tests below) so a swapped order would be caught
// immediately, not masked by a coincidentally-symmetric test vector.

/// EIP-197 encoding width: 128 bytes, `x.c1 || x.c0 || y.c1 || y.c0`.
pub const encoded_bytes = 4 * Fp.encoded_bytes;

/// Serializes `p` in the 128-byte EIP-197 form (imaginary-first `Fp2`
/// ordering — see this section's doc comment). REAL: mechanical
/// `Fp.toBytes` concatenation (or all-zero for infinity).
pub fn toBytes(p: Affine) [encoded_bytes]u8 {
    var out: [encoded_bytes]u8 = undefined;
    if (p.infinity) {
        @memset(&out, 0);
        return out;
    }
    out[0 * Fp.encoded_bytes .. 1 * Fp.encoded_bytes].* = p.x.c1.toBytes();
    out[1 * Fp.encoded_bytes .. 2 * Fp.encoded_bytes].* = p.x.c0.toBytes();
    out[2 * Fp.encoded_bytes .. 3 * Fp.encoded_bytes].* = p.y.c1.toBytes();
    out[3 * Fp.encoded_bytes .. 4 * Fp.encoded_bytes].* = p.y.c0.toBytes();
    return out;
}

/// Parses the EIP-197 128-byte form (imaginary-first ordering),
/// including the on-curve check. Accepts a runtime-length slice — see
/// `g1.zig`'s `fromBytes` doc comment for why. All-zero input decodes
/// to the point at infinity (`(0,0)` is never on-twist for `b' != 0`).
/// Does NOT check subgroup membership — callers that need a validated
/// `G2` element (anything crossing a network/deserialization boundary
/// into a future pairing consumer) MUST additionally call
/// `Jacobian.subgroupCheck` (see the module doc comment's pitfall
/// note).
pub fn fromBytes(bytes: []const u8) G2Error!Affine {
    if (bytes.len != encoded_bytes) return error.InvalidEncoding;
    if (std.mem.allEqual(u8, bytes, 0)) return Affine.identity;
    const x_c1 = Fp.fromBytes(bytes[0 * Fp.encoded_bytes .. 1 * Fp.encoded_bytes].*) catch return error.InvalidFieldElement;
    const x_c0 = Fp.fromBytes(bytes[1 * Fp.encoded_bytes .. 2 * Fp.encoded_bytes].*) catch return error.InvalidFieldElement;
    const y_c1 = Fp.fromBytes(bytes[2 * Fp.encoded_bytes .. 3 * Fp.encoded_bytes].*) catch return error.InvalidFieldElement;
    const y_c0 = Fp.fromBytes(bytes[3 * Fp.encoded_bytes .. 4 * Fp.encoded_bytes].*) catch return error.InvalidFieldElement;
    const p = Affine{
        .x = .{ .c0 = x_c0, .c1 = x_c1 },
        .y = .{ .c0 = y_c0, .c1 = y_c1 },
    };
    if (!Jacobian.fromAffine(p).isOnCurve()) return error.NotOnCurve;
    return p;
}

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

test "twistB == xi (fp6.zig's nonresidue, 9+u) confirmation" {
    try std.testing.expect(xi.c0.eql(try Fp.fromInt(u8, 9)));
    try std.testing.expect(xi.c1.eql(Fp.one));
}

test "KAT: twistB() byte-exact against the independent Python cross-check" {
    // 3 * (9+u)^-1, independently recomputed with plain Python big-int
    // Fp2 arithmetic outside this module (SPEC.md's "Verification
    // performed"). c0||c1 hex (this test reads Fp components directly,
    // not through Fp2.toBytes' c1||c0 wire order).
    const b2 = twistB();
    var c0_expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&c0_expected, "2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5");
    var c1_expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&c1_expected, "009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2");
    try std.testing.expectEqualSlices(u8, &c0_expected, &b2.c0.toBytes());
    try std.testing.expectEqualSlices(u8, &c1_expected, &b2.c1.toBytes());
}

test "twistB() is nonzero and equals the definitional 3 * xi^-1" {
    const b2 = twistB();
    try std.testing.expect(!b2.isZero());
    try std.testing.expect(b2.mul(xi).eql(.{ .c0 = try Fp.fromInt(u8, 3), .c1 = Fp.zero }));
}

test "G2 generator components are nonzero" {
    try std.testing.expect(!Affine.generator.x.isZero());
    try std.testing.expect(!Affine.generator.y.isZero());
}

test "G2 generator is on the twist y^2 = x^3 + b' (definitional, not via isOnCurve)" {
    const x = Affine.generator.x;
    const y = Affine.generator.y;
    const rhs = x.square().mul(x).add(twistB());
    try std.testing.expect(y.square().eql(rhs));
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

fn expectSamePoint(lhs: Jacobian, rhs: Jacobian) !void {
    const aa = lhs.toAffine();
    const bb = rhs.toAffine();
    try std.testing.expectEqual(aa.infinity, bb.infinity);
    if (!aa.infinity) {
        try std.testing.expect(aa.x.eql(bb.x));
        try std.testing.expect(aa.y.eql(bb.y));
    }
}

test "G2 generator is on the twist (isOnCurve); corrupted point is not" {
    try std.testing.expect(jacGen().isOnCurve());
    try std.testing.expect(Jacobian.identity.isOnCurve());
    var bad = jacGen();
    bad.x = bad.x.add(Fp2.one);
    try std.testing.expect(!bad.isOnCurve());
}

test "G2 group law: identity, inverses, add/double consistency, associativity, commutativity" {
    const g = jacGen();
    try expectSamePoint(g.add(Jacobian.identity), g);
    try expectSamePoint(Jacobian.identity.add(g), g);
    try std.testing.expect(g.add(g.negate()).isIdentity());
    try expectSamePoint(g.add(g), g.double());
    try std.testing.expect(Jacobian.identity.double().isIdentity());
    try std.testing.expect(g.double().isOnCurve());
    const g2p = g.double();
    const g4p = g2p.double();
    try expectSamePoint(g.add(g2p).add(g4p), g.add(g2p.add(g4p)));
    try expectSamePoint(g.add(g2p), g2p.add(g));
}

test "G2 scalarMul edge cases: [0]P = O, [1]P = P, [2]P = double(P)" {
    const g = jacGen();
    try std.testing.expect(g.scalarMul(Fr.zero).isIdentity());
    try expectSamePoint(g.scalarMul(Fr.one), g);
    const two = Fr.one.add(Fr.one);
    try expectSamePoint(g.scalarMul(two), g.double());
    try std.testing.expect(Jacobian.identity.scalarMul(two).isIdentity());
}

test "G2 scalarMul distributes: [a+b]G == [a]G + [b]G and [a*b]G == [a]([b]G)" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 0x2f;
    a_bytes[20] = 0xe1;
    const sa = try Fr.fromBytes(a_bytes);
    var b_bytes = [_]u8{0} ** 32;
    b_bytes[31] = 0x0b;
    b_bytes[10] = 0x44;
    const sb = try Fr.fromBytes(b_bytes);
    const g = jacGen();
    try expectSamePoint(g.scalarMul(sa.add(sb)), g.scalarMul(sa).add(g.scalarMul(sb)));
    try expectSamePoint(g.scalarMul(sa.mul(sb)), g.scalarMul(sb).scalarMul(sa));
}

test "G2 subgroupCheck: generator passes ([r]G2 == O)" {
    try std.testing.expect(jacGen().subgroupCheck());
    try std.testing.expect(Jacobian.identity.subgroupCheck());
    // A scalar multiple of the generator is still a subgroup member.
    try std.testing.expect(jacGen().double().add(jacGen()).subgroupCheck());
}

test "G2 subgroupCheck: an on-twist point OUTSIDE the subgroup fails; isOnCurve still passes" {
    // x = u (c0 = 0, c1 = 1) — on the twist (b' = twistB()) but NOT in
    // the order-r subgroup. Verified independently in Python
    // (SPEC.md's "Verification performed"): on_curve == True,
    // [r]P == O is False.
    var c1_bytes = [_]u8{0} ** 32;
    c1_bytes[31] = 1;
    const x = Fp2{ .c0 = Fp.zero, .c1 = try Fp.fromBytes(c1_bytes) };
    var y_c0_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c0_bytes, "0cf32d3c49a2cb8a092f24ec3201e68dc299b6216e6321ee60573e3a7f596ea8");
    var y_c1_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c1_bytes, "07bca656753ef8cbee60335acbffe3def91636952d4ab9eb0b839c7f3566c0e2");
    const y = Fp2{ .c0 = try Fp.fromBytes(y_c0_bytes), .c1 = try Fp.fromBytes(y_c1_bytes) };

    const jac = Jacobian.fromAffine(.{ .x = x, .y = y });
    try std.testing.expect(jac.isOnCurve());
    try std.testing.expect(!jac.subgroupCheck());
}

// Cross-check vectors: [k]G2 for small k and a larger scalar, computed
// with an INDEPENDENT from-scratch implementation (textbook
// affine-coordinate Fp2 EC formulas over Python big integers; see
// SPEC.md's "Verification performed").
const k2_x_c0_hex = "27dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9";
const k2_x_c1_hex = "203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad79";
const k2_y_c0_hex = "04bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e";
const k2_y_c1_hex = "195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de152";
const k_scalar_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const kg_x_c0_hex = "1a6c86889d8def8c193aab2b29277b6a82ef9e1fbf54855a4c369b8e34542901";
const kg_x_c1_hex = "2b73f15f298e190b6e223b4c765dad2d2f3321fc95071d190a6a1ff24b5c586d";
const kg_y_c0_hex = "2eaad97fb187e54262f442819e8e0092648b26caa9b0cbfd3d349f7ae90064e0";
const kg_y_c1_hex = "104cd5b9c8a9041a2a023c489e594a99cab291389e19fe304a28f08db39f5330";

fn hexFp(comptime hex: *const [64:0]u8) !Fp {
    var bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex);
    return Fp.fromBytes(bytes);
}

test "G2 KAT: [2]G2 matches the independent cross-check vector" {
    const two_g = jacGen().double().toAffine();
    try std.testing.expect(two_g.x.c0.eql(try hexFp(k2_x_c0_hex)));
    try std.testing.expect(two_g.x.c1.eql(try hexFp(k2_x_c1_hex)));
    try std.testing.expect(two_g.y.c0.eql(try hexFp(k2_y_c0_hex)));
    try std.testing.expect(two_g.y.c1.eql(try hexFp(k2_y_c1_hex)));
}

test "G2 KAT: [k]G2 matches the independent cross-check vector" {
    var k_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&k_bytes, k_scalar_hex);
    const k = try Fr.fromBytes(k_bytes);
    const kg = jacGen().scalarMul(k).toAffine();
    try std.testing.expect(kg.x.c0.eql(try hexFp(kg_x_c0_hex)));
    try std.testing.expect(kg.x.c1.eql(try hexFp(kg_x_c1_hex)));
    try std.testing.expect(kg.y.c0.eql(try hexFp(kg_y_c0_hex)));
    try std.testing.expect(kg.y.c1.eql(try hexFp(kg_y_c1_hex)));
}

// ── EIP-197 codec tests ─────────────────────────────────────────────────

// Generator encoding, byte-exact: x.c1 || x.c0 || y.c1 || y.c0. c0 != c1
// on every coordinate here, so this vector genuinely exercises the
// imaginary-first ordering (a c0==c1 vector could pass with the halves
// swapped and hide a bug).
const generator_eip197_hex =
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2" ++
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed" ++
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b" ++
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

test "toBytes(generator) matches the byte-exact EIP-197 KAT (imaginary-first ordering)" {
    var expected: [encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, generator_eip197_hex);
    try std.testing.expectEqualSlices(u8, &expected, &toBytes(Affine.generator));
}

test "fromBytes(generator KAT) round-trips to the generator coordinates" {
    var bytes: [encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, generator_eip197_hex);
    const p = try fromBytes(&bytes);
    try std.testing.expect(p.x.eql(Affine.generator.x));
    try std.testing.expect(p.y.eql(Affine.generator.y));
}

test "toBytes/fromBytes round-trip [2]G2 (non-generator, c0 != c1 throughout)" {
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
    var bytes: [encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, generator_eip197_hex);
    bytes[0..32].* = fp.p_bytes; // x.c1 == p, non-canonical
    try std.testing.expectError(error.InvalidFieldElement, fromBytes(&bytes));
}

test "fromBytes rejects an off-curve (x, y) pair" {
    // (x, y) = (1, 1): swap the generator's y for 1 (definitely off-twist).
    var bytes: [encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, generator_eip197_hex);
    var one_bytes = [_]u8{0} ** 32;
    one_bytes[31] = 1;
    bytes[64..96].* = [_]u8{0} ** 32; // y.c1 = 0
    bytes[96..128].* = one_bytes; // y.c0 = 1
    try std.testing.expectError(error.NotOnCurve, fromBytes(&bytes));
}
