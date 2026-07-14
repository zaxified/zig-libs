// SPDX-License-Identifier: MIT
//! `Fp` — the BLS12-381 base field, `GF(p)` for the 381-bit prime `p`
//! (decimal/hex value below). Every other type in this module (`Fp2`,
//! `Fp6`, `Fp12`, and the `G1`/`G2` curve point coordinates) is built as a
//! tower on top of this single field.
//!
//! **Status: implemented.** All arithmetic delegates to `std.crypto.ff`
//! (constant-time Montgomery modular arithmetic). The Montgomery-storage
//! question the scaffold left open is settled as: **canonical
//! (non-Montgomery) storage at rest**, converting per operation inside
//! `std.crypto.ff` — see the convention note above `add` below;
//! persistent Montgomery storage is a deferred Part-2 optimization
//! (SPEC.md Backlog).
//!
//! Zig std GAP: yes — `std.crypto.ff.Modulus`/`Fe` supply constant-time
//! Montgomery modular arithmetic for an arbitrary odd modulus of a fixed
//! bit width, but ship no BLS12-381-specific field: the modulus value,
//! the `Fp`-specific constructors (`fromInt`, the sign/lexicographic-order
//! helper `isLexicographicallyLargest` used by point compression), and
//! every field-arithmetic entry point are this module's own.

const std = @import("std");

/// Number of bits reserved for the fixed-width big-integer container
/// backing `Fp` — 384 (48 bytes), the next byte-aligned width above `p`'s
/// actual 381 bits. `std.crypto.ff.Modulus`/`Uint` track the modulus's
/// true bit length internally (`Modulus.bits()`); the extra 3 bits are
/// just container padding, not part of the field.
pub const modulus_bits = 384;

const FfModulus = std.crypto.ff.Modulus(modulus_bits);
const FfFe = FfModulus.Fe;

/// Parses a fixed-length compile-time hex string into bytes. Shared
/// comptime helper (same pattern as `bip340`/`adaptor`'s `kat_test.zig`
/// `hexN` helpers) — used only for the module's own embedded constants
/// below, not exposed as public API.
fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// The BLS12-381 base field modulus `p`, big-endian, 48 bytes:
///
/// ```
/// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6
///       241eabfffeb153ffffb9feffffffffaaab
/// ```
///
/// Source: draft-irtf-cfrg-pairing-friendly-curves (the BLS12-381
/// parameter set) and every BLS12-381 reference implementation cited in
/// `NOTICE` agree on this value byte-for-byte; independently re-derived
/// here from the defining BLS polynomial family with parameter
/// `z = -0xd201000000010000` — `p(z) = (z-1)^2 * (z^4 - z^2 + 1) / 3 + z`
/// — and confirmed to match (see `NOTICE`'s "Verification performed"
/// section for the exact recomputation).
pub const p_bytes: [48]u8 = hexBytes(48, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

/// `(p-1)/2`, big-endian, 48 bytes — the fixed threshold used by
/// `Fp.isLexicographicallyLargest` (an `Fp` element `y` is the
/// "lexicographically largest" of `{y, -y}` iff `y > (p-1)/2`; this is a
/// FIXED per-modulus constant, so precomputing it here avoids needing a
/// runtime `Fp.sub`/`Fp.neg` — see that function's doc comment). Value:
/// `0x0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b1
/// 20f55ffff58a9ffffdcff7fffffffd555` — mechanically `(p-1)/2` (see
/// `NOTICE`'s recomputation note).
pub const half_p_bytes: [48]u8 = hexBytes(48, "0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555");

/// The BLS12-381 base field modulus, as a `std.crypto.ff.Modulus(384)`
/// instance — computed once, at comptime, from `p_bytes`. REAL: this is
/// exactly what `std.crypto.ff.Modulus.fromBytes` is for; no field
/// arithmetic of this module's own is involved in constructing it. The
/// raised `@setEvalBranchQuota` is comptime-loop budget only (Montgomery
/// `R^2` precomputation loops over the modulus's ~384 bits) — not a
/// sign of any actual arithmetic happening in THIS module's own code.
pub const modulus: FfModulus = blk: {
    @setEvalBranchQuota(100_000);
    break :blk FfModulus.fromBytes(&p_bytes, .big) catch
        @compileError("bls12_381: malformed base field modulus bytes");
};

/// `(p-1)/2` as an `Fp` element (comptime; see `half_p_bytes`).
const half_p: FfFe = blk: {
    @setEvalBranchQuota(100_000);
    break :blk FfFe.fromBytes(modulus, &half_p_bytes, .big) catch
        @compileError("bls12_381: malformed (p-1)/2 bytes");
};

/// Comptime helper: computes `(p + delta) / div` as a big-endian 48-byte
/// exponent, asserting the division is EXACT — used to derive every
/// fixed exponent this module's tower needs (`p-2` for `Fp.inv`,
/// `(p+1)/4` for `Fp.sqrt`, `(p-3)/4` and `(p-1)/2` for `Fp2.sqrt`,
/// `(p-1)/3` and `(p-1)/6` for the `Fp6`/`Fp12` Frobenius coefficients)
/// directly from the verified `p_bytes` rather than hand-transcribing
/// more magic constants. Pure comptime big-integer arithmetic via
/// `comptime_int` (arbitrary precision) — no runtime cost, and a wrong
/// `delta`/`div` pair fails the build.
pub fn pExponentBytes(comptime delta: comptime_int, comptime div: comptime_int) [48]u8 {
    @setEvalBranchQuota(100_000);
    comptime var x: comptime_int = 0;
    inline for (p_bytes) |byte| x = x * 256 + @as(comptime_int, byte);
    const v = x + delta;
    if (v % div != 0) @compileError("bls12_381: (p + delta) not divisible by div");
    comptime var q = v / div;
    comptime var out: [48]u8 = undefined;
    comptime var i: usize = 48;
    inline while (i > 0) {
        i -= 1;
        out[i] = q % 256;
        q = q / 256;
    }
    if (q != 0) @compileError("bls12_381: exponent does not fit in 48 bytes");
    return out;
}

/// `p - 2`, big-endian — the Fermat inversion exponent (`Fp.inv`).
const p_minus_2_bytes: [48]u8 = pExponentBytes(-2, 1);

/// `(p + 1) / 4`, big-endian — the square-root exponent for the
/// `p ≡ 3 (mod 4)` simple case (`Fp.sqrt`).
const sqrt_exponent_bytes: [48]u8 = pExponentBytes(1, 4);

/// Errors from `Fp` byte/primitive parsing — the exact `std.crypto.ff`
/// error set `Fe.fromBytes`/`Fe.fromPrimitive` can return.
pub const FpError = std.crypto.ff.OverflowError || std.crypto.ff.FieldElementError;

/// An element of the BLS12-381 base field `GF(p)`.
pub const Fp = struct {
    fe: FfFe,

    /// Fixed-size big-endian wire encoding: 48 bytes (matches the
    /// ZCash/IETF BLS12-381 serialization convention's per-coordinate
    /// width — see `g1.zig`/`g2.zig`).
    pub const encoded_bytes = 48;

    /// The additive identity. REAL: a struct-field access on
    /// `std.crypto.ff.Modulus`, no arithmetic.
    pub const zero: Fp = .{ .fe = modulus.zero };

    /// The multiplicative identity. REAL: `Modulus.one()` is a
    /// std-provided helper (sets the low limb to 1), not this module's
    /// arithmetic.
    pub const one: Fp = .{ .fe = modulus.one() };

    /// Parses a big-endian 48-byte value, REJECTING anything `>= p`
    /// (non-canonical) — `std.crypto.ff.Fe.fromBytes`'s own canonical
    /// check, not a design choice of this module. REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FpError!Fp {
        return .{ .fe = try FfFe.fromBytes(modulus, &bytes, .big) };
    }

    /// Serializes to big-endian 48 bytes. REAL, PROVIDED the value is
    /// canonical (non-Montgomery) at the struct boundary — see this
    /// file's module doc comment re: the Montgomery-storage decision a
    /// crypto-core pass must make; if that pass chooses persistent
    /// Montgomery storage, this function's body must convert out first
    /// (`modulus.fromMontgomery`) before calling `Fe.toBytes`.
    pub fn toBytes(self: Fp) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        self.fe.toBytes(&out, .big) catch unreachable; // canonical by construction (see doc comment)
        return out;
    }

    /// Builds a small `Fp` value from a native integer (e.g. the curve
    /// constant `b = 4`). REAL: `std.crypto.ff.Fe.fromPrimitive` is pure
    /// std delegation.
    pub fn fromInt(comptime T: type, v: T) FpError!Fp {
        return .{ .fe = try FfFe.fromPrimitive(T, modulus, v) };
    }

    /// `true` iff the value is `0`. REAL: `Fe.isZero` is a std helper.
    pub fn isZero(self: Fp) bool {
        return self.fe.isZero();
    }

    /// Constant-time equality. REAL: `Fe.eql` is a std helper (constant
    /// time over the limb representation).
    pub fn eql(a: Fp, b: Fp) bool {
        return a.fe.eql(b.fe);
    }

    /// `true` iff `self` is the lexicographically-larger of `{self,
    /// -self}` — i.e. `self > (p-1)/2` as an integer. This is the
    /// "sign of y" bit used by G1/G2 point COMPRESSION (`g1.zig`/
    /// `g2.zig`'s `sort` flag, per the ZCash/IETF serialization format).
    /// REAL: comparing against the FIXED precomputed `half_p` threshold
    /// needs no `Fp.sub`/`Fp.neg` at all (`self > (p-1)/2  <=>  self >
    /// -self`, since `p` is odd and has no fixed point under negation
    /// except `0`) — `Fe.compare` is std's own constant-time comparator.
    pub fn isLexicographicallyLargest(self: Fp) bool {
        return self.fe.compare(half_p) == .gt;
    }

    // ── field arithmetic ────────────────────────────────────────────────
    //
    // MONTGOMERY-STORAGE CONVENTION (the open question the module doc
    // comment poses, settled here): `Fp` stores values CANONICALLY
    // (non-Montgomery) at rest. Every `std.crypto.ff.Modulus` operation
    // preserves the first operand's form, so canonical in => canonical
    // out holds across all of the operations below, and
    // `toBytes`/`fromBytes` need no conversion at the struct boundary.
    // Cost: each `mul`/`sq` converts in/out of Montgomery form
    // internally (a few extra Montgomery multiplications per call) —
    // acceptable for Part 1; persistent Montgomery storage is a
    // documented follow-up optimization for the Part-2 pairing
    // (SPEC.md Backlog).

    /// `a + b (mod p)`. Constant time (`std.crypto.ff.Modulus.add`).
    pub fn add(a: Fp, b: Fp) Fp {
        return .{ .fe = modulus.add(a.fe, b.fe) };
    }

    /// `a - b (mod p)`. Constant time.
    pub fn sub(a: Fp, b: Fp) Fp {
        return .{ .fe = modulus.sub(a.fe, b.fe) };
    }

    /// `-a (mod p)`, i.e. `p - a` (or `0` if `a == 0`). Constant time
    /// (`modulus.sub(0, a)` — no separate primitive in `std.crypto.ff`).
    pub fn neg(a: Fp) Fp {
        return .{ .fe = modulus.sub(Fp.zero.fe, a.fe) };
    }

    /// `a * b (mod p)`. Constant time (Montgomery multiplication; both
    /// operands canonical per the storage convention above, so the
    /// result is canonical too).
    pub fn mul(a: Fp, b: Fp) Fp {
        return .{ .fe = modulus.mul(a.fe, b.fe) };
    }

    /// `a^2 (mod p)`. Constant time (`modulus.sq`, the dedicated
    /// Montgomery-squaring primitive).
    pub fn square(a: Fp) Fp {
        return .{ .fe = modulus.sq(a.fe) };
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`.
    /// Construction: Fermat's little theorem, `a^(p-2) mod p`, via
    /// `modulus.powPublic(a.fe, (p-2))` — SAFE to use the PUBLIC-exponent
    /// variant here only when `a` itself is public (e.g. inverting a
    /// batch-normalization denominator); inverting a SECRET `Fp` value
    /// (rare in this module — pairing/point arithmetic only inverts
    /// public denominators during affine conversion) must instead use
    /// `modulus.pow` (the constant-time-with-respect-to-the-exponent
    /// variant) — note the EXPONENT `p-2` is always public either way,
    /// so `Fe.fromBytes`'s `NullExponentError` guard is the only
    /// possible failure besides `a == 0` itself (`0^(p-2) = 0`, which
    /// `pow`'s null-exponent guard does NOT catch — `a == 0` must be
    /// checked explicitly and mapped to `error.NotInvertible` before
    /// calling `pow`, matching Fermat's theorem's precondition).
    pub fn inv(a: Fp) error{NotInvertible}!Fp {
        if (a.isZero()) return error.NotInvertible;
        // Fermat: a^(p-2). The exponent p-2 is a FIXED PUBLIC constant,
        // so the public-exponent variant is safe AND constant-time with
        // respect to `a` itself (see `powWithEncodedPublicExponent`'s
        // doc comment in std.crypto.ff — "public" refers to the
        // exponent only; the base is still processed in constant time).
        const fe = modulus.powWithEncodedPublicExponent(a.fe, &p_minus_2_bytes, .big) catch
            unreachable; // p-2 is nonzero, so NullExponent cannot fire
        return .{ .fe = fe };
    }

    /// RFC 9380 §4's `inv0`: the zero-preserving multiplicative inverse
    /// (`inv0(0) = 0`, otherwise `a^-1`) — the variant hash-to-curve's
    /// Simplified SWU map (`hash_to_curve.zig`) is specified over, where
    /// a zero denominator must flow through as zero rather than error.
    pub fn inv0(a: Fp) Fp {
        return a.inv() catch Fp.zero;
    }

    /// RFC 9380 §4.1's `sgn0_m_eq_1`: the "sign" of a base-field
    /// element, defined as the PARITY of its canonical integer
    /// representative (`x mod 2`). NOT the same notion of sign as
    /// `isLexicographicallyLargest` (which compares MAGNITUDE against
    /// `(p-1)/2` for the point-compression sort bit) — RFC 9380's
    /// `sgn0` and the ZCash sort bit are different conventions; do not
    /// conflate them.
    pub fn sgn0(self: Fp) u1 {
        return @intCast(self.toBytes()[encoded_bytes - 1] & 1);
    }

    /// `a^e (mod p)`, `e` a big-endian byte string. Construction:
    /// `modulus.powWithEncodedExponent(a.fe, e, .big)` (secret exponent,
    /// constant time) or `...PublicExponent` (public exponent, faster) —
    /// caller's `io`/`comptime` context decides which; see `Fp.inv`'s
    /// doc comment for the concrete example (`e = p-2`, always public).
    pub fn pow(a: Fp, e: [encoded_bytes]u8) Fp {
        // Constant-time-with-respect-to-the-exponent variant (the
        // conservative default; callers with a known-public exponent
        // that need speed can use std.crypto.ff's public variant
        // directly, mirroring inv's internal choice). ff rejects an
        // all-zero exponent (NullExponent); map that to the
        // mathematical convention a^0 = 1 (this leaks only whether
        // e == 0, which any caller of pow-with-zero already knows).
        const fe = modulus.powWithEncodedExponent(a.fe, &e, .big) catch return Fp.one;
        return .{ .fe = fe };
    }

    /// Square root, or `null` if `a` is not a quadratic residue.
    /// Construction: `p ≡ 3 (mod 4)` — confirmed directly from `p_bytes`
    /// (`p`'s low byte is `0xab`, `0xab mod 4 == 3`) — so the SIMPLE
    /// case applies: candidate root `c = a^((p+1)/4) mod p`, with the
    /// exponent comptime-derived (`sqrt_exponent_bytes`). The candidate
    /// is correct ONLY if `c^2 == a` (verified; `null` on mismatch) —
    /// `a^((p+1)/4)` is defined for every `a` but only actually equals
    /// a square root when `a` is a QR. No Tonelli-Shanks general case
    /// is needed (that machinery is only for `p ≡ 1 (mod 4)`).
    pub fn sqrt(a: Fp) ?Fp {
        // p ≡ 3 (mod 4) simple case: candidate c = a^((p+1)/4); it is a
        // real square root iff a is a QR, so verify c^2 == a and return
        // null otherwise. Exponent is a fixed public constant; the
        // usual caller (point decompression) has a public input anyway.
        const c = Fp{ .fe = modulus.powWithEncodedPublicExponent(a.fe, &sqrt_exponent_bytes, .big) catch
            unreachable }; // (p+1)/4 is nonzero
        return if (c.square().eql(a)) c else null;
    }

    /// A uniformly random field element. Construction: rejection-sample
    /// 48 random bytes from `io` until `Fp.fromBytes` accepts (rejects
    /// non-canonical, i.e. `>= p`, with probability roughly `2^-128` per
    /// draw for this modulus width — negligible retry cost). Must NOT
    /// use a biased reduction (`bytes mod p` over a same-width sample) —
    /// that skews the low ~`2^(384-381)` probability mass and is a
    /// classic constant-time-but-NOT-uniform footgun in exactly this
    /// kind of "prime just under a byte boundary" field.
    pub fn random(io: std.Io) Fp {
        var buf: [encoded_bytes]u8 = undefined;
        while (true) {
            io.random(&buf);
            return Fp.fromBytes(buf) catch continue; // >= p: reject, redraw
        }
    }

    /// Constant-time select: returns `a` if `cond`, else `b` — the
    /// building block `g1.zig`/`g2.zig`'s branchless (complete) point
    /// addition and constant-time scalar multiplication use to avoid
    /// secret-dependent branches. Implemented as a byte-mask merge over
    /// the canonical serializations (no data-dependent branch or
    /// index): `mask = 0x00/0xff` derived arithmetically from `cond`.
    pub fn ctSelect(cond: bool, a: Fp, b: Fp) Fp {
        const mask: u8 = @as(u8, 0) -% @intFromBool(cond);
        const ab = a.toBytes();
        const bb = b.toBytes();
        var out: [encoded_bytes]u8 = undefined;
        for (&out, ab, bb) |*o, x, y| o.* = (x & mask) | (y & ~mask);
        // Both inputs were canonical, so the merged value (== one of
        // them exactly) is canonical too.
        return Fp.fromBytes(out) catch unreachable;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "p is odd and 381 bits" {
    try std.testing.expect(p_bytes[47] & 1 == 1);
    try std.testing.expectEqual(@as(usize, 381), modulus.bits());
}

test "half_p is exactly (p-1)/2" {
    // Cross-check by directly computing (p-1) >> 1 over the raw
    // big-endian byte form (right-shift-by-1-with-borrow across the
    // 48-byte array) — pure byte arithmetic, independent of any Fp
    // method or std big-int type, so this test does not depend on any
    // stub and needs no library beyond what this loop does itself.
    var p_minus_1 = p_bytes;
    var borrow: u1 = 1; // subtract 1 from the whole big-endian value
    var i: usize = p_minus_1.len;
    while (i > 0) {
        i -= 1;
        const r = @subWithOverflow(p_minus_1[i], borrow);
        p_minus_1[i] = r[0];
        borrow = r[1];
        if (borrow == 0) break;
    }

    var shifted = [_]u8{0} ** 48;
    var carry: u8 = 0;
    for (p_minus_1, 0..) |byte, idx| {
        shifted[idx] = (byte >> 1) | (carry << 7);
        carry = byte & 1;
    }

    try std.testing.expectEqualSlices(u8, &half_p_bytes, &shifted);
}

test "Fp.zero / Fp.one round-trip through bytes" {
    const z = Fp.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));
    const o = Fp.one.toBytes();
    var expected = [_]u8{0} ** 48;
    expected[47] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fp.fromBytes rejects p itself (non-canonical) and accepts p-1" {
    try std.testing.expectError(error.NonCanonical, Fp.fromBytes(p_bytes));

    var p_minus_1 = p_bytes;
    p_minus_1[47] -= 1;
    _ = try Fp.fromBytes(p_minus_1); // must not error
}

test "Fp.fromInt(4) matches the b=4 curve-constant byte pattern" {
    const four = try Fp.fromInt(u8, 4);
    var expected = [_]u8{0} ** 48;
    expected[47] = 4;
    try std.testing.expectEqualSlices(u8, &expected, &four.toBytes());
}

test "Fp.isLexicographicallyLargest: half_p+1 is largest, half_p is not, half_p-1 is not" {
    // half_p itself: NOT largest (self > half_p is false when self == half_p).
    const hp = try Fp.fromBytes(half_p_bytes);
    try std.testing.expect(!hp.isLexicographicallyLargest());
    try std.testing.expect(hp.add(Fp.one).isLexicographicallyLargest());
    try std.testing.expect(!hp.sub(Fp.one).isLexicographicallyLargest());
}

test "Fp arithmetic: additive identities (a + 0 = a, a + (-a) = 0, a - a = 0)" {
    const a = try Fp.fromInt(u64, 0xdead_beef_1234_5678);
    try std.testing.expect(a.add(Fp.zero).eql(a));
    try std.testing.expect(a.add(a.neg()).isZero());
    try std.testing.expect(a.sub(a).isZero());
    try std.testing.expect(Fp.zero.neg().isZero());
}

test "Fp arithmetic: (a + b)^2 == a^2 + 2ab + b^2 and square == mul(a, a)" {
    const a = try Fp.fromInt(u64, 0x0123_4567_89ab_cdef);
    const b = try Fp.fromBytes(half_p_bytes);
    const lhs = a.add(b).square();
    const two_ab = a.mul(b).add(a.mul(b));
    const rhs = a.square().add(two_ab).add(b.square());
    try std.testing.expect(lhs.eql(rhs));
    try std.testing.expect(a.square().eql(a.mul(a)));
}

test "Fp.inv: a * a^-1 == 1; inv(0) errors; inv(1) == 1" {
    const a = try Fp.fromInt(u64, 987_654_321);
    const a_inv = try a.inv();
    try std.testing.expect(a.mul(a_inv).eql(Fp.one));
    try std.testing.expectError(error.NotInvertible, Fp.zero.inv());
    try std.testing.expect((try Fp.one.inv()).eql(Fp.one));
}

test "Fp.inv0 (RFC 9380): inv0(0) == 0, inv0(a) == a^-1 otherwise" {
    try std.testing.expect(Fp.zero.inv0().isZero());
    const a = try Fp.fromInt(u64, 123_456_789);
    try std.testing.expect(a.mul(a.inv0()).eql(Fp.one));
}

test "Fp.sgn0 (RFC 9380 sgn0_m_eq_1): parity of the canonical representative" {
    try std.testing.expectEqual(@as(u1, 0), Fp.zero.sgn0());
    try std.testing.expectEqual(@as(u1, 1), Fp.one.sgn0());
    try std.testing.expectEqual(@as(u1, 0), (try Fp.fromInt(u8, 2)).sgn0());
    // p is odd, so -1 = p-1 is even: sgn0(-1) == 0 (canonical
    // representative's parity, NOT a magnitude-based sign).
    try std.testing.expectEqual(@as(u1, 0), Fp.one.neg().sgn0());
}

test "Fp.pow: a^0 == 1, a^1 == a, a^2 == square(a)" {
    const a = try Fp.fromInt(u64, 31337);
    var e = [_]u8{0} ** 48;
    try std.testing.expect(a.pow(e).eql(Fp.one));
    e[47] = 1;
    try std.testing.expect(a.pow(e).eql(a));
    e[47] = 2;
    try std.testing.expect(a.pow(e).eql(a.square()));
}

test "Fp.sqrt: sqrt(a^2) in {a, -a}; sqrt(-1) is null (p = 3 mod 4)" {
    const a = try Fp.fromInt(u64, 0xfeed_face_cafe_f00d);
    const c = a.square();
    const s = c.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(s.eql(a) or s.eql(a.neg()));
    try std.testing.expect(s.square().eql(c));
    // -1 is a quadratic NON-residue exactly when p = 3 (mod 4) (fp.zig's
    // own Fp.sqrt doc comment confirms p's low byte 0xab = 3 mod 4).
    try std.testing.expect(Fp.one.neg().sqrt() == null);
    // sqrt(0) == 0 (0 is its own square root).
    const z = Fp.zero.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(z.isZero());
}

test "Fp.ctSelect picks the right operand" {
    const a = try Fp.fromInt(u8, 7);
    const b = try Fp.fromInt(u8, 9);
    try std.testing.expect(Fp.ctSelect(true, a, b).eql(a));
    try std.testing.expect(Fp.ctSelect(false, a, b).eql(b));
}

test "Fp.random produces a canonical, (overwhelmingly) nonzero element" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = Fp.random(io);
    const b = Fp.random(io);
    // Round-trips (i.e. is canonical) and two draws collide with
    // probability ~2^-381 — a deterministic failure means a broken RNG
    // hookup, not bad luck.
    _ = try Fp.fromBytes(a.toBytes());
    try std.testing.expect(!a.eql(b));
}

test "pExponentBytes: (p-1)/2 reproduces half_p_bytes and p-2 = p_bytes minus 2" {
    try std.testing.expectEqualSlices(u8, &half_p_bytes, &pExponentBytes(-1, 2));
    var expected = p_bytes;
    expected[47] -= 2; // p's low byte is 0xab, no borrow
    try std.testing.expectEqualSlices(u8, &expected, &p_minus_2_bytes);
}
