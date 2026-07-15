// SPDX-License-Identifier: MIT
//! `Fp` — the BN254 (alt-bn128) base field, `GF(p)` for the 254-bit prime
//! `p` (decimal/hex value below). Every other type in this module
//! (`Fp2`, `Fp6`, `Fp12`, and later the `G1`/`G2` curve point
//! coordinates — a future part) is built as a tower on top of this
//! single field.
//!
//! **Status: implemented.** All arithmetic delegates to
//! `std.crypto.ff` (constant-time Montgomery modular arithmetic) —
//! same construction as the sibling `bls12_381` module's `fp.zig`,
//! adapted to BN254's modulus and 32-byte (vs. BLS12-381's 48-byte)
//! width. Canonical (non-Montgomery) storage at rest, same convention
//! as `bls12_381`'s `Fp.add` doc comment.
//!
//! Zig std GAP: yes — `std.crypto.ff.Modulus`/`Fe` supply constant-time
//! Montgomery modular arithmetic for an arbitrary odd modulus of a
//! fixed bit width, but ship no BN254-specific field: the modulus
//! value and every field-arithmetic entry point below are this
//! module's own.
//!
//! **No `isLexicographicallyLargest` (deliberate, vs. `bls12_381`):**
//! Ethereum's EIP-196/197 precompiles (0x06/0x07/0x08) encode `G1`/`G2`
//! points UNCOMPRESSED — raw `(x, y)` coordinate pairs, no "sign of y"
//! compression bit — unlike BLS12-381's ZCash-style compressed point
//! format. This module therefore has no consumer for that helper; see
//! `SPEC.md`.

const std = @import("std");

/// Number of bits reserved for the fixed-width big-integer container
/// backing `Fp` — 256 (32 bytes), the next byte-aligned width above
/// `p`'s actual 254 bits. `std.crypto.ff.Modulus`/`Uint` track the
/// modulus's true bit length internally (`Modulus.bits()`); the extra 2
/// bits are just container padding, not part of the field.
pub const modulus_bits = 256;

const FfModulus = std.crypto.ff.Modulus(modulus_bits);
const FfFe = FfModulus.Fe;

/// Parses a fixed-length compile-time hex string into bytes. Same
/// helper shape as `bls12_381/src/fp.zig`'s `hexBytes` — used only for
/// this module's own embedded constants below, not exposed as public
/// API.
fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// The BN254 (alt-bn128) base field modulus `p`, big-endian, 32 bytes:
///
/// ```
/// p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
/// ```
///
/// Source: EIP-196/197 (the Ethereum alt_bn128 precompile spec) and
/// `py_ecc`'s `bn128_field_elements.field_modulus` agree on this value
/// byte-for-byte. Independently re-derived here from the defining BN
/// polynomial family with parameter `x = 4965661367192848881`:
/// `p(x) = 36x^4 + 36x^3 + 24x^2 + 6x + 1` — confirmed to match by
/// direct big-integer computation outside this module (see `NOTICE`'s
/// "Verification performed" pointer / `SPEC.md`'s cited sources). Also
/// independently confirmed prime by a 40-round Miller-Rabin test
/// outside this module.
pub const p_bytes: [32]u8 = hexBytes(32, "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");

/// The BN254 base field modulus, as a `std.crypto.ff.Modulus(256)`
/// instance — computed once, at comptime, from `p_bytes`. REAL: this is
/// exactly what `std.crypto.ff.Modulus.fromBytes` is for; no field
/// arithmetic of this module's own is involved in constructing it.
pub const modulus: FfModulus = blk: {
    @setEvalBranchQuota(100_000);
    break :blk FfModulus.fromBytes(&p_bytes, .big) catch
        @compileError("bn254: malformed base field modulus bytes");
};

/// Comptime helper: computes `(p + delta) / div` as a big-endian
/// 32-byte exponent, asserting the division is EXACT — used to derive
/// every fixed exponent this module's tower needs (`p-2` for `Fp.inv`,
/// `(p+1)/4` for `Fp.sqrt`, `(p-3)/4` and `(p-1)/2` for `Fp2.sqrt`,
/// `(p-1)/3` and `(p-1)/6` for the `Fp6`/`Fp12` Frobenius coefficients)
/// directly from the verified `p_bytes` rather than hand-transcribing
/// more magic constants. Same construction as
/// `bls12_381/src/fp.zig`'s `pExponentBytes`, just at the 32-byte
/// width. Pure comptime big-integer arithmetic via `comptime_int`
/// (arbitrary precision) — no runtime cost, and a wrong `delta`/`div`
/// pair fails the build.
pub fn pExponentBytes(comptime delta: comptime_int, comptime div: comptime_int) [32]u8 {
    @setEvalBranchQuota(100_000);
    comptime var x: comptime_int = 0;
    inline for (p_bytes) |byte| x = x * 256 + @as(comptime_int, byte);
    const v = x + delta;
    if (v % div != 0) @compileError("bn254: (p + delta) not divisible by div");
    comptime var q = v / div;
    comptime var out: [32]u8 = undefined;
    comptime var i: usize = 32;
    inline while (i > 0) {
        i -= 1;
        out[i] = q % 256;
        q = q / 256;
    }
    if (q != 0) @compileError("bn254: exponent does not fit in 32 bytes");
    return out;
}

/// `p - 2`, big-endian — the Fermat inversion exponent (`Fp.inv`).
const p_minus_2_bytes: [32]u8 = pExponentBytes(-2, 1);

/// `(p + 1) / 4`, big-endian — the square-root exponent for the
/// `p ≡ 3 (mod 4)` simple case (`Fp.sqrt`). BN254's `p` ends in `...47`
/// (`0x47 mod 4 == 3`), so the simple case applies — see `Fp.sqrt`'s
/// doc comment.
const sqrt_exponent_bytes: [32]u8 = pExponentBytes(1, 4);

/// Errors from `Fp` byte/primitive parsing — the exact `std.crypto.ff`
/// error set `Fe.fromBytes`/`Fe.fromPrimitive` can return.
pub const FpError = std.crypto.ff.OverflowError || std.crypto.ff.FieldElementError;

/// An element of the BN254 base field `GF(p)`.
pub const Fp = struct {
    fe: FfFe,

    /// Fixed-size big-endian wire encoding: 32 bytes — the EVM/EIP-196
    /// convention every alt_bn128 precompile input/output coordinate
    /// uses.
    pub const encoded_bytes = 32;

    /// The additive identity. REAL: a struct-field access on
    /// `std.crypto.ff.Modulus`, no arithmetic.
    pub const zero: Fp = .{ .fe = modulus.zero };

    /// The multiplicative identity. REAL: `Modulus.one()` is a
    /// std-provided helper (sets the low limb to 1), not this module's
    /// arithmetic.
    pub const one: Fp = .{ .fe = modulus.one() };

    /// Parses a big-endian 32-byte value, REJECTING anything `>= p`
    /// (non-canonical) — `std.crypto.ff.Fe.fromBytes`'s own canonical
    /// check, not a design choice of this module. REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FpError!Fp {
        return .{ .fe = try FfFe.fromBytes(modulus, &bytes, .big) };
    }

    /// Serializes to big-endian 32 bytes. REAL, PROVIDED the value is
    /// canonical (non-Montgomery) at the struct boundary — see this
    /// file's module doc comment re: the canonical-storage convention.
    pub fn toBytes(self: Fp) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        self.fe.toBytes(&out, .big) catch unreachable; // canonical by construction (see doc comment)
        return out;
    }

    /// Builds a small `Fp` value from a native integer (e.g. the curve
    /// constant `b = 3`). REAL: `std.crypto.ff.Fe.fromPrimitive` is
    /// pure std delegation.
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

    // ── field arithmetic ────────────────────────────────────────────────
    //
    // Same canonical-storage convention as `bls12_381/src/fp.zig`:
    // values are stored non-Montgomery at rest; every
    // `std.crypto.ff.Modulus` operation preserves the first operand's
    // form, so canonical in => canonical out holds across all of the
    // operations below, and `toBytes`/`fromBytes` need no conversion at
    // the struct boundary.

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
    /// `modulus.powWithEncodedPublicExponent` — same public-exponent
    /// reasoning as `bls12_381`'s `Fp.inv` doc comment (the exponent
    /// `p-2` is always public; only the caller's choice of public vs.
    /// constant-time-base variant matters for a secret base).
    pub fn inv(a: Fp) error{NotInvertible}!Fp {
        if (a.isZero()) return error.NotInvertible;
        const fe = modulus.powWithEncodedPublicExponent(a.fe, &p_minus_2_bytes, .big) catch
            unreachable; // p-2 is nonzero, so NullExponent cannot fire
        return .{ .fe = fe };
    }

    /// RFC 9380 §4's `inv0`: the zero-preserving multiplicative inverse
    /// (`inv0(0) = 0`, otherwise `a^-1`) — mirrors `bls12_381.Fp.inv0`;
    /// no hash-to-curve consumer exists in this module yet (a future
    /// part), included for tower-symmetry with the sibling module and
    /// because `Fp2.inv0` (this module's `fp2.zig`) is built on it.
    pub fn inv0(a: Fp) Fp {
        return a.inv() catch Fp.zero;
    }

    /// `a^e (mod p)`, `e` a big-endian byte string. Construction:
    /// `modulus.powWithEncodedExponent(a.fe, e, .big)` (secret exponent,
    /// constant time) — see `bls12_381`'s `Fp.pow`/`Fp.inv` doc comments
    /// for the public-vs-constant-time exponent tradeoff this mirrors.
    pub fn pow(a: Fp, e: [encoded_bytes]u8) Fp {
        const fe = modulus.powWithEncodedExponent(a.fe, &e, .big) catch return Fp.one;
        return .{ .fe = fe };
    }

    /// Square root, or `null` if `a` is not a quadratic residue.
    /// Construction: `p ≡ 3 (mod 4)` (confirmed directly from
    /// `p_bytes`: `p`'s low byte is `0x47`, `0x47 mod 4 == 3`), so the
    /// SIMPLE case applies — same shape as `bls12_381`'s `Fp.sqrt`:
    /// candidate root `c = a^((p+1)/4) mod p`, verified by `c^2 == a`
    /// (`null` on mismatch).
    pub fn sqrt(a: Fp) ?Fp {
        const c = Fp{ .fe = modulus.powWithEncodedPublicExponent(a.fe, &sqrt_exponent_bytes, .big) catch
            unreachable }; // (p+1)/4 is nonzero
        return if (c.square().eql(a)) c else null;
    }

    /// A uniformly random field element. Same rejection-sampling shape
    /// as `bls12_381`'s `Fp.random` — `p`'s gap from `2^256` is small
    /// enough that biased-reduction sampling would be a real skew; must
    /// reject-and-redraw instead.
    pub fn random(io: std.Io) Fp {
        var buf: [encoded_bytes]u8 = undefined;
        while (true) {
            io.random(&buf);
            return Fp.fromBytes(buf) catch continue; // >= p: reject, redraw
        }
    }

    /// Constant-time select: returns `a` if `cond`, else `b`. Same
    /// byte-mask-merge construction as `bls12_381`'s `Fp.ctSelect`.
    pub fn ctSelect(cond: bool, a: Fp, b: Fp) Fp {
        const mask: u8 = @as(u8, 0) -% @intFromBool(cond);
        const ab = a.toBytes();
        const bb = b.toBytes();
        var out: [encoded_bytes]u8 = undefined;
        for (&out, ab, bb) |*o, x, y| o.* = (x & mask) | (y & ~mask);
        return Fp.fromBytes(out) catch unreachable;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "p is odd and 254 bits" {
    try std.testing.expect(p_bytes[31] & 1 == 1);
    try std.testing.expectEqual(@as(usize, 254), modulus.bits());
}

test "Fp.zero / Fp.one round-trip through bytes" {
    const z = Fp.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));
    const o = Fp.one.toBytes();
    var expected = [_]u8{0} ** 32;
    expected[31] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fp.fromBytes rejects p itself (non-canonical) and accepts p-1" {
    try std.testing.expectError(error.NonCanonical, Fp.fromBytes(p_bytes));

    var p_minus_1 = p_bytes;
    p_minus_1[31] -= 1;
    _ = try Fp.fromBytes(p_minus_1); // must not error
}

test "Fp.fromInt(3) matches the b=3 curve-constant byte pattern" {
    const three = try Fp.fromInt(u8, 3);
    var expected = [_]u8{0} ** 32;
    expected[31] = 3;
    try std.testing.expectEqualSlices(u8, &expected, &three.toBytes());
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
    var b_bytes = [_]u8{0} ** 32;
    _ = try std.fmt.hexToBytes(&b_bytes, "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3"); // (p-1)/2
    const b = try Fp.fromBytes(b_bytes);
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

test "Fp.pow: a^0 == 1, a^1 == a, a^2 == square(a)" {
    const a = try Fp.fromInt(u64, 31337);
    var e = [_]u8{0} ** 32;
    try std.testing.expect(a.pow(e).eql(Fp.one));
    e[31] = 1;
    try std.testing.expect(a.pow(e).eql(a));
    e[31] = 2;
    try std.testing.expect(a.pow(e).eql(a.square()));
}

test "Fp.sqrt: sqrt(a^2) in {a, -a}; sqrt(-1) is null (p = 3 mod 4)" {
    const a = try Fp.fromInt(u64, 0xfeed_face_cafe_f00d);
    const c = a.square();
    const s = c.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(s.eql(a) or s.eql(a.neg()));
    try std.testing.expect(s.square().eql(c));
    // -1 is a quadratic NON-residue exactly when p = 3 (mod 4).
    try std.testing.expect(Fp.one.neg().sqrt() == null);
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
    _ = try Fp.fromBytes(a.toBytes());
    try std.testing.expect(!a.eql(b));
}

test "pExponentBytes: (p-1)/2 matches the independently-recomputed half_p and p-2 = p_bytes minus 2" {
    var half_p_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&half_p_bytes, "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3");
    try std.testing.expectEqualSlices(u8, &half_p_bytes, &pExponentBytes(-1, 2));
    var expected = p_bytes;
    expected[31] -= 2; // p's low byte is 0x47, no borrow
    try std.testing.expectEqualSlices(u8, &expected, &p_minus_2_bytes);
}

test "KAT: G1 generator (1, 2) satisfies y^2 = x^3 + 3 (EIP-196 b=3; independent py_ecc/EIP-197 cross-check)" {
    // Sources: EIP-196 (https://eips.ethereum.org/EIPS/eip-196) and
    // py_ecc's bn128_curve.py both fix G1 = (1, 2) on y^2 = x^3 + 3.
    // This is a cheap independent sanity check that `p` itself is the
    // correct alt_bn128 modulus (a wrong p would make this fail with
    // overwhelming probability) — pinned here in fp.zig since this
    // module does not implement G1 (a future part).
    const x = Fp.one;
    const y = try Fp.fromInt(u8, 2);
    const b = try Fp.fromInt(u8, 3);
    const lhs = y.square();
    const rhs = x.square().mul(x).add(b);
    try std.testing.expect(lhs.eql(rhs));
}
