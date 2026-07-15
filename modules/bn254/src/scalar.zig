// SPDX-License-Identifier: MIT
//! `Fr` — the BN254 (alt-bn128) SCALAR field, `GF(r)` for the 254-bit
//! prime group order `r` (NOT the base field `Fp` — see `fp.zig`). This
//! is the field secret keys / Groth16 witness scalars / proof
//! randomness live in for anything built on top of this module (a
//! future Groth16-verifier part — see `README.md`'s multi-part arc).
//!
//! **Status: implemented** — all arithmetic delegates to
//! `std.crypto.ff` with the same canonical-storage convention as
//! `fp.zig` (see that file's convention note above `Fp.add`). Same
//! construction as `bls12_381/src/scalar.zig`, adapted to BN254's
//! `r` — which, unlike BLS12-381 (`Fp`: 381 bits / `Fr`: 255 bits, two
//! different container widths), happens to be the SAME 254-bit
//! magnitude class as `Fp` (`p` and `r` are both 254 bits), so `Fr`
//! shares `Fp`'s 256-bit/32-byte container width exactly.

const std = @import("std");

/// Container width for `Fr`: 256 bits (32 bytes) — same width as
/// `fp.zig`'s `modulus_bits` for `Fp` (both `p` and `r` are 254-bit
/// primes for BN254; see this file's module doc comment).
pub const modulus_bits = 256;

const FfModulus = std.crypto.ff.Modulus(modulus_bits);
const FfFe = FfModulus.Fe;

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

/// An element of the BN254 scalar field `GF(r)`.
pub const Fr = struct {
    fe: FfFe,

    /// Fixed-size big-endian wire encoding: 32 bytes.
    pub const encoded_bytes = 32;

    pub const zero: Fr = .{ .fe = modulus.zero };
    pub const one: Fr = .{ .fe = modulus.one() };

    /// Parses a big-endian 32-byte value, REJECTING anything `>= r`. REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FrError!Fr {
        return .{ .fe = try FfFe.fromBytes(modulus, &bytes, .big) };
    }

    /// Serializes to big-endian 32 bytes. REAL, provided canonical
    /// (non-Montgomery) storage at the struct boundary — see `fp.zig`'s
    /// module doc comment for the same caveat, applied here to `Fr`.
    pub fn toBytes(self: Fr) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        self.fe.toBytes(&out, .big) catch unreachable;
        return out;
    }

    pub fn isZero(self: Fr) bool {
        return self.fe.isZero();
    }

    pub fn eql(a: Fr, b: Fr) bool {
        return a.fe.eql(b.fe);
    }

    // ── field arithmetic ────────────────────────────────────────────────

    /// `a + b (mod r)`. Constant time.
    pub fn add(a: Fr, b: Fr) Fr {
        return .{ .fe = modulus.add(a.fe, b.fe) };
    }

    /// `a - b (mod r)`. Constant time.
    pub fn sub(a: Fr, b: Fr) Fr {
        return .{ .fe = modulus.sub(a.fe, b.fe) };
    }

    /// `-a (mod r)`. Constant time.
    pub fn neg(a: Fr) Fr {
        return .{ .fe = modulus.sub(Fr.zero.fe, a.fe) };
    }

    /// `a * b (mod r)`. Constant time (Montgomery multiplication).
    pub fn mul(a: Fr, b: Fr) Fr {
        return .{ .fe = modulus.mul(a.fe, b.fe) };
    }

    /// `a^2 (mod r)`. Constant time.
    pub fn square(a: Fr) Fr {
        return .{ .fe = modulus.sq(a.fe) };
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`.
    /// Construction: Fermat, `a^(r-2) mod r`. The base IS commonly a
    /// SECRET value here (a witness scalar, blinding factor), so the
    /// fully constant-time exponentiation variant is used — same
    /// reasoning as `bls12_381`'s `Fr.inv`.
    pub fn inv(a: Fr) error{NotInvertible}!Fr {
        if (a.isZero()) return error.NotInvertible;
        const fe = modulus.powWithEncodedExponent(a.fe, &r_minus_2_bytes, .big) catch
            unreachable; // r-2 is nonzero
        return .{ .fe = fe };
    }

    /// `a^e (mod r)`, `e` a big-endian byte string. Constant time with
    /// respect to BOTH the base and the exponent.
    pub fn pow(a: Fr, e: [encoded_bytes]u8) Fr {
        const fe = modulus.powWithEncodedExponent(a.fe, &e, .big) catch return Fr.one;
        return .{ .fe = fe };
    }

    /// Reduces a wider byte string (e.g. a 32-/48-/64-byte hash output)
    /// into an `Fr` element via `int(bytes) mod r` — a REDUCING
    /// conversion, unlike `fromBytes` (which REJECTS non-canonical
    /// input). Same shape and same 512-bit widening ceiling as
    /// `bls12_381.Fr.reduceWide`.
    pub fn reduceWide(bytes: []const u8) Fr {
        std.debug.assert(bytes.len <= 64);
        const wide = std.crypto.ff.Uint(512).fromBytes(bytes, .big) catch unreachable;
        return .{ .fe = modulus.reduce(wide) };
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

/// `r - 2`, big-endian — the Fermat inversion exponent (`Fr.inv`),
/// comptime-derived from the verified `r_bytes`.
const r_minus_2_bytes: [32]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var x: comptime_int = 0;
    for (r_bytes) |byte| x = x * 256 + @as(comptime_int, byte);
    x -= 2;
    var out: [32]u8 = undefined;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        out[i] = x % 256;
        x = x / 256;
    }
    break :blk out;
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

test "Fr.random produces canonical, distinct draws" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const a = Fr.random(io);
    const b = Fr.random(io);
    _ = try Fr.fromBytes(a.toBytes());
    try std.testing.expect(!a.eql(b));
}
