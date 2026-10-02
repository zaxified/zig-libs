// SPDX-License-Identifier: MIT
//! `Field(p)` — the prime field `GF(p)` for a comptime prime `p`, stored in
//! montint's Montgomery domain and built only from `Modint`'s constant-time
//! primitives (`montMul`, `montSqr`, `add`, `sub`, `powMont`).
//!
//! Why it exists: the pairing modules' scalar fields (`bls12_381.Fr`,
//! `bn254.Fr`) were `std.crypto.ff` wrappers, and measured 2026-10-02
//! (ctgrind, Zig 0.16, ReleaseFast) `std.crypto.ff` is not constant-time
//! there: `montgomeryMul`'s extra-reduction select
//! (`need_sub = ct.eql(overflow, underflow)`) compiles to a conditional jump,
//! so every `mul`/`sq` over a secret leaks that bit, and
//! `powWithEncodedExponent`'s window select branches on the secret exponent.
//! This type is the replacement both share, so the constant-time evidence is
//! one ctgrind target (`field`) instead of one per caller.
//!
//! Every operation keeps `Modint`'s input contract (operands `< p`): bytes are
//! reduced limb by limb (each limb `< 2^64 < p`), never by handing a value
//! `>= p` to `montMul`. The only data-dependent branches are the ones the
//! API returns as a value: `fromBytesBE`'s canonical check (accept/reject),
//! `isZero`, `eql`, and `inv`'s zero check.

const std = @import("std");
const montint = @import("montint.zig");
const limbs = @import("limbs.zig");

/// `GF(p)` for an odd prime `p > 2^64` (comptime). `p` is not checked for
/// primality; `inv` (Fermat) is only correct for a prime.
pub fn Field(comptime p: comptime_int) type {
    comptime std.debug.assert(p > (1 << 64) and p & 1 == 1);
    const bit_len: comptime_int = comptime blk: {
        var n: comptime_int = 0;
        var x: comptime_int = p;
        while (x > 0) : (x >>= 1) n += 1;
        break :blk n;
    };
    const M = montint.Modint(bit_len);
    const L = M.L;

    return struct {
        const Self = @This();

        /// The underlying `Modint` (public modulus, constants precomputed).
        pub const Mod = M;
        /// `L` little-endian 64-bit limbs.
        pub const Elem = M.Elem;
        /// The prime's bit length.
        pub const bits: usize = bit_len;
        /// Width of the fixed big-endian encoding.
        pub const encoded_bytes: usize = M.encoded_bytes;

        /// The modulus with its Montgomery constants, computed at comptime
        /// from `comptime_int` arithmetic (no `computeConstants` loop).
        pub const modulus: M = .{
            .m = limbsOf(p),
            .n0inv = montint.negInvMod2_64(limbsOf(p)[0]),
            .r2 = limbsOf((1 << (128 * L)) % p),
            .one_mont = limbsOf((1 << (64 * L)) % p),
        };

        /// `2^64` in the Montgomery domain — the Horner step of `reduceBytesBE`.
        const two64_mont: Elem = limbsOf(((1 << 64) * (1 << (64 * L))) % p);
        /// `p - 2`, the Fermat inversion exponent (public).
        const p_minus_2: Elem = limbsOf(p - 2);

        /// The value, Montgomery form (`x·2^(64L) mod p`), always `< p`.
        mont: Elem,

        pub const zero: Self = .{ .mont = [_]u64{0} ** L };
        pub const one: Self = .{ .mont = modulus.one_mont };

        fn limbsOf(comptime x: comptime_int) Elem {
            comptime var v = x;
            var out: Elem = undefined;
            inline for (&out) |*w| {
                w.* = @as(u64, @truncate(v));
                v >>= 64;
            }
            if (v != 0) @compileError("montint.Field: value wider than L limbs");
            return out;
        }

        /// Big-endian bytes → limbs with no value-dependent branch (positions
        /// only). `be.len <= 8·L`.
        fn loadBE(be: []const u8) Elem {
            std.debug.assert(be.len <= 8 * L);
            var v = [_]u64{0} ** L;
            for (be, 0..) |b, i| {
                const pos = be.len - 1 - i; // byte position from the LSB
                v[pos / 8] |= @as(u64, b) << @intCast(8 * (pos % 8));
            }
            return v;
        }

        /// Parse a canonical big-endian encoding; `error.NonCanonical` for
        /// a value `>= p`. Constant-time up to the accept/reject outcome.
        pub fn fromBytesBE(bytes: *const [encoded_bytes]u8) error{NonCanonical}!Self {
            const v = loadBE(bytes);
            var t = v;
            const borrow = limbs.subInto(&t, &modulus.m); // 1 ⟺ v < p
            if (borrow == 0) return error.NonCanonical;
            return .{ .mont = modulus.toMontgomery(&v) };
        }

        /// The canonical big-endian encoding.
        pub fn toBytesBE(self: Self) [encoded_bytes]u8 {
            const v = modulus.fromMontgomery(&self.mont);
            var out: [encoded_bytes]u8 = undefined;
            modulus.toBytesBE(&v, &out);
            return out;
        }

        /// `int(bytes) mod p` for a big-endian string of any length (a hash
        /// output, a wide random draw). Horner over 64-bit limbs, each limb
        /// `< p`, so `Modint`'s operand contract holds throughout; the work
        /// depends on `bytes.len` only.
        pub fn reduceBytesBE(bytes: []const u8) Self {
            var acc: Elem = [_]u64{0} ** L;
            const n_limbs = (bytes.len + 7) / 8;
            var k: usize = n_limbs;
            while (k > 0) {
                k -= 1;
                // Bytes of limb k (from the LSB end); a short top limb is
                // zero-extended.
                const lo = bytes.len -| 8 * (k + 1);
                const hi = bytes.len - 8 * k;
                var limb = [_]u64{0} ** L;
                for (bytes[lo..hi]) |b| limb[0] = (limb[0] << 8) | b;
                acc = modulus.montMul(&acc, &two64_mont);
                const limb_mont = modulus.toMontgomery(&limb);
                acc = modulus.add(&acc, &limb_mont);
            }
            return .{ .mont = acc };
        }

        pub fn isZero(self: Self) bool {
            var acc: u64 = 0;
            for (self.mont) |w| acc |= w;
            return acc == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            var acc: u64 = 0;
            for (a.mont, b.mont) |x, y| acc |= x ^ y;
            return acc == 0;
        }

        pub fn add(a: Self, b: Self) Self {
            return .{ .mont = modulus.add(&a.mont, &b.mont) };
        }

        pub fn sub(a: Self, b: Self) Self {
            return .{ .mont = modulus.sub(&a.mont, &b.mont) };
        }

        pub fn neg(a: Self) Self {
            return .{ .mont = modulus.sub(&zero.mont, &a.mont) };
        }

        pub fn mul(a: Self, b: Self) Self {
            return .{ .mont = modulus.montMul(&a.mont, &b.mont) };
        }

        pub fn sq(a: Self) Self {
            return .{ .mont = modulus.montSqr(&a.mont) };
        }

        /// `a^e`, `e` an `L`-limb little-endian exponent; constant-time in
        /// both `a` and `e` (`powMont`: every one of the `64·L` bits is
        /// processed). `e = 0` gives `one`.
        pub fn powLimbs(a: Self, e: *const Elem) Self {
            const base = modulus.fromMontgomery(&a.mont);
            const r = modulus.powMont(&base, e);
            return .{ .mont = modulus.toMontgomery(&r) };
        }

        /// `a^e`, `e` big-endian, at most `8·L` bytes; constant-time in both.
        pub fn pow(a: Self, e_be: []const u8) Self {
            var e = loadBE(e_be);
            defer std.crypto.secureZero(u64, &e);
            return a.powLimbs(&e);
        }

        /// `a⁻¹` by Fermat (`a^(p-2)`), constant-time in `a`;
        /// `error.NotInvertible` for zero.
        pub fn inv(a: Self) error{NotInvertible}!Self {
            if (a.isZero()) return error.NotInvertible;
            return a.powLimbs(&p_minus_2);
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// BLS12-381's scalar order (255 bits, L=4) and ed448's group order (446
/// bits, L=7) — one full-width-ish and one odd-limb-count prime.
const bls_r: comptime_int = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
const ed448_l: comptime_int = (1 << 446) - 13818066809895115352007386748515426880336692474882178609894547503885;

fn diffAgainstFf(comptime p: comptime_int) !void {
    const F = Field(p);
    const Ff = std.crypto.ff.Modulus(F.encoded_bytes * 8);
    var p_be: [F.encoded_bytes]u8 = undefined;
    std.mem.writeInt(std.meta.Int(.unsigned, F.encoded_bytes * 8), &p_be, p, .big);
    const ff = try Ff.fromBytes(&p_be, .big);

    var prng = std.Random.DefaultPrng.init(0x6d6f6e74_6669656c);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var ab: [F.encoded_bytes]u8 = undefined;
        var bb: [F.encoded_bytes]u8 = undefined;
        rnd.bytes(&ab);
        rnd.bytes(&bb);
        ab[0] >>= 2; // below p for both primes (top bits of p are set)
        bb[0] >>= 2;
        const a = try F.fromBytesBE(&ab);
        const b = try F.fromBytesBE(&bb);
        const fa = try Ff.Fe.fromBytes(ff, &ab, .big);
        const fb = try Ff.Fe.fromBytes(ff, &bb, .big);

        var want: [F.encoded_bytes]u8 = undefined;
        try ff.mul(fa, fb).toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &a.mul(b).toBytesBE());
        try ff.add(fa, fb).toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &a.add(b).toBytesBE());
        try ff.sub(fa, fb).toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &a.sub(b).toBytesBE());
        try ff.sq(fa).toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &a.sq().toBytesBE());
        try (try ff.powWithEncodedPublicExponent(fa, &bb, .big)).toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &a.pow(&bb).toBytesBE());
        try testing.expect(a.mul(try a.inv()).eql(F.one));
        try testing.expectEqualSlices(u8, &ab, &a.toBytesBE());

        // reduceBytesBE over a 2×-wide draw against ff's reduce.
        var wide: [2 * F.encoded_bytes]u8 = undefined;
        rnd.bytes(&wide);
        const Wide = std.crypto.ff.Uint(2 * F.encoded_bytes * 8);
        const fw = ff.reduce(try Wide.fromBytes(&wide, .big));
        try fw.toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &F.reduceBytesBE(&wide).toBytesBE());
        // …and over a length that is not a multiple of 8 (ff sees it
        // zero-extended to the same wide width).
        const odd = wide[0 .. F.encoded_bytes + 3];
        var padded = [_]u8{0} ** (2 * F.encoded_bytes);
        @memcpy(padded[padded.len - odd.len ..], odd);
        try ff.reduce(try Wide.fromBytes(&padded, .big)).toBytes(&want, .big);
        try testing.expectEqualSlices(u8, &want, &F.reduceBytesBE(odd).toBytesBE());
    }
}

test "Field matches std.crypto.ff (bls12_381 r, L=4)" {
    try diffAgainstFf(bls_r);
}

test "Field matches std.crypto.ff (ed448 l, L=7)" {
    try diffAgainstFf(ed448_l);
}

test "Field.modulus constants equal Modint.fromElem's" {
    const F = Field(bls_r);
    const runtime = try F.Mod.fromElem(F.modulus.m);
    try testing.expectEqualSlices(u64, &runtime.r2, &F.modulus.r2);
    try testing.expectEqualSlices(u64, &runtime.one_mont, &F.modulus.one_mont);
    try testing.expectEqual(runtime.n0inv, F.modulus.n0inv);
}

test "Field edges: canonical check, zero/one, pow 0, inv 0, reduce of p and short input" {
    const F = Field(bls_r);
    var p_be: [32]u8 = undefined;
    std.mem.writeInt(u256, &p_be, bls_r, .big);
    try testing.expectError(error.NonCanonical, F.fromBytesBE(&p_be));
    var pm1 = p_be;
    pm1[31] -= 1;
    const m1 = try F.fromBytesBE(&pm1);
    try testing.expect(m1.add(F.one).isZero());
    try testing.expect(F.reduceBytesBE(&p_be).isZero());
    try testing.expect(F.reduceBytesBE(&[_]u8{7}).eql(F.one.add(F.one).add(F.one).add(F.one).add(F.one).add(F.one).add(F.one)));
    try testing.expect(F.reduceBytesBE(&[_]u8{}).isZero());
    try testing.expect(m1.pow(&[_]u8{0} ** 32).eql(F.one));
    try testing.expect(m1.pow(&[_]u8{}).eql(F.one));
    try testing.expectError(error.NotInvertible, F.zero.inv());
    try testing.expect(F.zero.toBytesBE()[31] == 0 and F.one.toBytesBE()[31] == 1);
}
