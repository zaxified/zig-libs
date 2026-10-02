// SPDX-License-Identifier: MIT
//! `Fr` — the BN254 (alt-bn128) SCALAR field, `GF(r)` for the 254-bit
//! prime group order `r` (NOT the base field `Fp` — see `fp.zig`). This
//! is the field secret keys / Groth16 witness scalars / proof
//! randomness live in for anything built on top of this module (a
//! future Groth16-verifier part — see `README.md`'s multi-part arc).
//!
//! **Status: implemented** — arithmetic is `montint.Field(r)`: Montgomery
//! form (`R = 2^256`), built only from montint's constant-time primitives,
//! the same type `bls12_381.Fr` uses. Until 2026-10-02 this type wrapped
//! `std.crypto.ff` (Montgomery storage over ff's 63-bit limbs, with a
//! hand-rolled constant-time `toBytes` because ff's `fromMontgomery`
//! branched). Measured then (ctgrind, ReleaseFast): ff's `montgomeryMul`
//! itself branches on its extra-reduction bit and its secret-exponent pow
//! on the exponent windows, so `mul`/`square`/`pow` over a Groth16 witness
//! or proof randomness leaked — the toBytes fix closed one of the three
//! sites. `modulus` (the ff value) and `FrError` stay for API
//! compatibility; no arithmetic uses ff.

const std = @import("std");
const montint = @import("montint");

/// Container width for `Fr`: 256 bits (32 bytes) — same width as
/// `fp.zig`'s `modulus_bits` for `Fp` (both `p` and `r` are 254-bit
/// primes for BN254; see this file's module doc comment).
pub const modulus_bits = 256;

const FfModulus = std.crypto.ff.Modulus(modulus_bits);

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// The BN254 scalar field modulus (the order of `G1`/`G2`/`Gt`),
/// big-endian, 32 bytes:
///
/// ```
/// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
/// ```
///
/// Source: same defining BN polynomial family as `fp.zig`'s `p` —
/// `r(x) = 36x^4 + 36x^3 + 18x^2 + 6x + 1` for `x = 4965661367192848881`
/// — independently re-derived and confirmed to match EIP-196/197 and
/// `py_ecc`'s `bn128_curve.curve_order` (see `SPEC.md`'s cited
/// sources). Also independently confirmed prime by a 40-round
/// Miller-Rabin test outside this module.
pub const r_bytes: [32]u8 = hexBytes(32, "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

/// The BN254 scalar field modulus, as a `std.crypto.ff.Modulus(256)`
/// instance, computed once at comptime. REAL (see `fp.zig`'s `modulus`
/// for the identical reasoning).
pub const modulus: FfModulus = blk: {
    @setEvalBranchQuota(100_000);
    break :blk FfModulus.fromBytes(&r_bytes, .big) catch
        @compileError("bn254: malformed scalar field modulus bytes");
};

pub const FrError = std.crypto.ff.OverflowError || std.crypto.ff.FieldElementError;

/// `r` as a `comptime_int`, re-derived from `r_bytes`.
const r_int: comptime_int = blk: {
    var x: comptime_int = 0;
    for (r_bytes) |b| x = x * 256 + @as(comptime_int, b);
    break :blk x;
};

/// The constant-time field `Fr` is a view of.
const F = montint.Field(r_int);

/// An element of the BN254 scalar field `GF(r)`, Montgomery-resident
/// (`montint.Field`): `mul`/`square` are one Montgomery multiplication each.
pub const Fr = struct {
    v: F,

    /// Fixed-size big-endian wire encoding: 32 bytes.
    pub const encoded_bytes = 32;

    pub const zero: Fr = .{ .v = F.zero };
    pub const one: Fr = .{ .v = F.one };

    /// Parses a big-endian 32-byte value, REJECTING anything `>= r`.
    /// Constant-time up to the accept/reject outcome.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FrError!Fr {
        return .{ .v = F.fromBytesBE(&bytes) catch return error.NonCanonical };
    }

    /// Serializes to big-endian 32 bytes (the Montgomery factor removed).
    /// Constant time.
    pub fn toBytes(self: Fr) [encoded_bytes]u8 {
        return self.v.toBytesBE();
    }

    pub fn isZero(self: Fr) bool {
        return self.v.isZero();
    }

    pub fn eql(a: Fr, b: Fr) bool {
        return a.v.eql(b.v);
    }

    // ── field arithmetic (all constant time; montint.Field) ──────────────

    /// `a + b (mod r)`.
    pub fn add(a: Fr, b: Fr) Fr {
        return .{ .v = a.v.add(b.v) };
    }

    /// `a - b (mod r)`.
    pub fn sub(a: Fr, b: Fr) Fr {
        return .{ .v = a.v.sub(b.v) };
    }

    /// `-a (mod r)`.
    pub fn neg(a: Fr) Fr {
        return .{ .v = a.v.neg() };
    }

    /// `a * b (mod r)`.
    pub fn mul(a: Fr, b: Fr) Fr {
        return .{ .v = a.v.mul(b.v) };
    }

    /// `a^2 (mod r)`.
    pub fn square(a: Fr) Fr {
        return .{ .v = a.v.sq() };
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`. Fermat,
    /// `a^(r-2) mod r`, constant-time in `a` (a witness scalar, a blinding
    /// factor); the zero check is the only branch.
    pub fn inv(a: Fr) error{NotInvertible}!Fr {
        return .{ .v = try a.v.inv() };
    }

    /// `a^e (mod r)`, `e` a big-endian byte string. Constant time with
    /// respect to BOTH the base and the exponent (montint `powMont`);
    /// `e == 0` returns `one`.
    pub fn pow(a: Fr, e: [encoded_bytes]u8) Fr {
        return .{ .v = a.v.pow(&e) };
    }

    /// Reduces a wider byte string (e.g. a 32-/48-/64-byte hash output)
    /// into an `Fr` element via `int(bytes) mod r` — a REDUCING
    /// conversion, unlike `fromBytes` (which REJECTS non-canonical
    /// input). Same shape and same 64-byte ceiling as
    /// `bls12_381.Fr.reduceWide`; constant time in the bytes.
    pub fn reduceWide(bytes: []const u8) Fr {
        std.debug.assert(bytes.len <= 64);
        return .{ .v = F.reduceBytesBE(bytes) };
    }

    /// A uniformly random scalar. Same rejection-sampling shape as
    /// `fp.zig`'s `Fp.random`.
    pub fn random(io: std.Io) Fr {
        var buf: [encoded_bytes]u8 = undefined;
        while (true) {
            io.random(&buf);
            return Fr.fromBytes(buf) catch continue; // >= r: reject, redraw
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "r is odd and 254 bits" {
    try std.testing.expect(r_bytes[31] & 1 == 1);
    try std.testing.expectEqual(@as(usize, 254), modulus.bits());
}

test "Fr.zero / Fr.one round-trip through bytes" {
    const z = Fr.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));
    const o = Fr.one.toBytes();
    var expected = [_]u8{0} ** 32;
    expected[31] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fr.fromBytes rejects r itself (non-canonical) and accepts r-1" {
    try std.testing.expectError(error.NonCanonical, Fr.fromBytes(r_bytes));

    var r_minus_1 = r_bytes;
    r_minus_1[31] -= 1;
    _ = try Fr.fromBytes(r_minus_1); // must not error
}

test "Fr arithmetic identities: a + (-a) = 0, square == mul(a,a), (a+b)^2 law" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 0xef;
    a_bytes[0] = 0x11; // large-ish, still < r (r's top byte is 0x30)
    const a = try Fr.fromBytes(a_bytes);
    var b_bytes = [_]u8{0} ** 32;
    b_bytes[30] = 0xab;
    const b = try Fr.fromBytes(b_bytes);
    try std.testing.expect(a.add(a.neg()).isZero());
    try std.testing.expect(a.square().eql(a.mul(a)));
    const two_ab = a.mul(b).add(a.mul(b));
    try std.testing.expect(a.add(b).square().eql(a.square().add(two_ab).add(b.square())));
}

test "Fr.inv: a * a^-1 == 1; inv(0) errors" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 42;
    const a = try Fr.fromBytes(a_bytes);
    try std.testing.expect(a.mul(try a.inv()).eql(Fr.one));
    try std.testing.expectError(error.NotInvertible, Fr.zero.inv());
}

test "Fr.pow: a^0 = 1, a^1 = a, a^2 = square" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 5;
    const a = try Fr.fromBytes(a_bytes);
    var e = [_]u8{0} ** 32;
    try std.testing.expect(a.pow(e).eql(Fr.one));
    e[31] = 1;
    try std.testing.expect(a.pow(e).eql(a));
    e[31] = 2;
    try std.testing.expect(a.pow(e).eql(a.square()));
}

test "Fr.reduceWide: r reduces to 0, r+1 to 1, canonical values unchanged, 64-byte KAT" {
    try std.testing.expect(Fr.reduceWide(&r_bytes).isZero());

    var r_plus_1 = r_bytes;
    r_plus_1[31] += 1; // r's low byte is 0x01, no carry
    try std.testing.expect(Fr.reduceWide(&r_plus_1).eql(Fr.one));

    var small = [_]u8{0} ** 32;
    small[31] = 0x7f;
    try std.testing.expect(Fr.reduceWide(&small).eql(try Fr.fromBytes(small)));

    // 64 bytes of 0xff mod r — independently computed with big-integer
    // arithmetic outside this module (Python `int.from_bytes(b'\xff'*64,
    // 'big') % r`; see SPEC.md's "Verification performed").
    const wide = [_]u8{0xff} ** 64;
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, "0216d0b17f4e44a58c49833d53bb808553fe3ab1e35c59e31bb8e645ae216da6");
    try std.testing.expectEqualSlices(u8, &expected_bytes, &Fr.reduceWide(&wide).toBytes());
}

test "Fr agrees with std.crypto.ff on random operands (the replaced backend as oracle)" {
    var prng = std.Random.DefaultPrng.init(0x626e3235_34667231);
    const rnd = prng.random();
    for (0..200) |_| {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rnd.bytes(&ab);
        rnd.bytes(&bb);
        ab[0] &= 0x1f; // < r (top byte 0x30)
        bb[0] &= 0x1f;
        const a = try Fr.fromBytes(ab);
        const b = try Fr.fromBytes(bb);
        const fa = try FfModulus.Fe.fromBytes(modulus, &ab, .big);
        const fb = try FfModulus.Fe.fromBytes(modulus, &bb, .big);
        var want: [32]u8 = undefined;
        try modulus.mul(fa, fb).toBytes(&want, .big);
        try std.testing.expectEqualSlices(u8, &want, &a.mul(b).toBytes());
        try modulus.sub(fa, fb).toBytes(&want, .big);
        try std.testing.expectEqualSlices(u8, &want, &a.sub(b).toBytes());
        try (try modulus.powWithEncodedPublicExponent(fa, &bb, .big)).toBytes(&want, .big);
        try std.testing.expectEqualSlices(u8, &want, &a.pow(bb).toBytes());
        var wide: [64]u8 = undefined;
        rnd.bytes(&wide);
        try modulus.reduce(try std.crypto.ff.Uint(512).fromBytes(&wide, .big)).toBytes(&want, .big);
        try std.testing.expectEqualSlices(u8, &want, &Fr.reduceWide(&wide).toBytes());
    }
}

test "Fr.random produces canonical, distinct draws" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const a = Fr.random(io);
    const b = Fr.random(io);
    _ = try Fr.fromBytes(a.toBytes());
    try std.testing.expect(!a.eql(b));
}
