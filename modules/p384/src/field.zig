// SPDX-License-Identifier: MIT

//! The P-384 base field, GF(p) with p = 2^384 − 2^128 − 2^96 + 2^32 − 1.
//!
//! Representation: six saturated 64-bit limbs, little-endian, in the
//! Montgomery domain — an element a is held as a·R mod p with R = 2^384 —
//! and always canonical (< p). That is std's `P384.Fe` representation
//! (fiat-crypto's), so `limbs` convert one to one and the comb table's
//! generator writes the same numbers for either.
//!
//! The arithmetic is `mont.zig`'s (shared with the scalar field): a 6 × 6
//! schoolbook product, a six-round word-by-word Montgomery reduction
//! (−p⁻¹ mod 2^64 = 2^32 + 1), one masked final subtraction; `add`/`sub`
//! end in a masked subtract / add of p. Every operation is branch-free and table-free in its inputs;
//! `fromBytes` branches once on the canonical verdict of a public encoding,
//! `sqrt` once on the residue verdict.
//!
//! Hand-written from the definition (no vendored fiat-crypto, as for p521);
//! held by a wide-integer differential and a bound test (tests below).

const std = @import("std");
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

const mont = @import("mont.zig");
const fast_core = @import("fast_core.zig");
const Limbs = mont.Limbs;
const limbsOf = mont.limbsOf;

/// The field order p.
const P_INT: u384 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff;

/// Montgomery arithmetic mod p (−p⁻¹ mod 2^64 = 2^32 + 1).
const A = mont.Mont(P_INT);

/// An element of GF(p), Montgomery form, canonical.
pub const Fe = struct {
    limbs: Limbs,

    /// The field order p.
    pub const field_order: u384 = P_INT;
    /// Bits in the field order.
    pub const field_bits = 384;
    /// Bits a canonical encoding can carry.
    pub const saturated_bits = 384;
    /// Length of a serialized element (bytes).
    pub const encoded_length = 48;

    pub const zero: Fe = .{ .limbs = @splat(0) };
    pub const one: Fe = fromIntUnchecked(1);

    fn fromIntUnchecked(comptime x: u384) Fe {
        @setEvalBranchQuota(100_000);
        return .{ .limbs = limbsOf((@as(u768, x) << 384) % P_INT) };
    }

    /// An element from an integer; `error.NonCanonical` if it is ≥ p.
    pub fn fromInt(comptime x: u384) NonCanonicalError!Fe {
        if (x >= field_order) return error.NonCanonical;
        return fromIntUnchecked(x);
    }

    /// Decode 48 bytes. `error.NonCanonical` unless the value is < p. The
    /// check is branch-free; the single branch is on the verdict, which the
    /// error reveals anyway.
    pub fn fromBytes(s: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!Fe {
        var l: Limbs = undefined;
        inline for (0..6) |i| l[i] = switch (endian) {
            .little => std.mem.readInt(u64, s[8 * i ..][0..8], .little),
            .big => std.mem.readInt(u64, s[40 - 8 * i ..][0..8], .big),
        };
        if (A.lt(l) == 0) return error.NonCanonical;
        return .{ .limbs = A.mul(l, A.R2) };
    }

    /// The plain (non-Montgomery) limbs of a, in [0, p).
    fn fromMont(a: Fe) Limbs {
        return A.fromMont(a.limbs);
    }

    /// Encode as 48 bytes (value in [0, p)).
    pub fn toBytes(a: Fe, endian: std.builtin.Endian) [encoded_length]u8 {
        const l = a.fromMont();
        var out: [encoded_length]u8 = undefined;
        inline for (0..6) |i| switch (endian) {
            .little => std.mem.writeInt(u64, out[8 * i ..][0..8], l[i], .little),
            .big => std.mem.writeInt(u64, out[40 - 8 * i ..][0..8], l[i], .big),
        };
        return out;
    }

    pub fn add(a: Fe, b: Fe) Fe {
        return .{ .limbs = A.add(a.limbs, b.limbs) };
    }

    pub fn sub(a: Fe, b: Fe) Fe {
        return .{ .limbs = A.sub(a.limbs, b.limbs) };
    }

    pub fn neg(a: Fe) Fe {
        return zero.sub(a);
    }

    pub fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    /// Multiply by a small public constant (1 ≤ k < 2^4), by doublings and
    /// additions.
    pub fn mulSmall(a: Fe, comptime k: u64) Fe {
        comptime std.debug.assert(k >= 1 and k < 16);
        const top = comptime std.math.log2_int(u64, k);
        var r = a;
        inline for (0..top) |i| {
            r = r.dbl();
            if ((k >> (top - 1 - i)) & 1 != 0) r = r.add(a);
        }
        return r;
    }

    pub fn mul(a: Fe, b: Fe) Fe {
        if (comptime fast_core.supported) {
            var buf: [12]u64 = a.limbs ++ A.M;
            fast_core.montMul(&buf, &b.limbs);
            return .{ .limbs = buf[0..6].* };
        }
        return mulPortable(a, b);
    }

    /// On amd64 with ADX the same product as `mul` (a dedicated asm square
    /// would save ~15 of 72 `mulx`; not written).
    pub fn sq(a: Fe) Fe {
        if (comptime fast_core.supported) return a.mul(a);
        return sqPortable(a);
    }

    /// `mont.zig`'s product: every target, and the reference the amd64
    /// core is pinned to.
    pub fn mulPortable(a: Fe, b: Fe) Fe {
        return .{ .limbs = A.mul(a.limbs, b.limbs) };
    }

    pub fn sqPortable(a: Fe) Fe {
        return .{ .limbs = A.sq(a.limbs) };
    }

    /// `mul` forced inline at the call site: the point formulas use it so
    /// independent products overlap (LLVM keeps `mul` out of line otherwise).
    pub inline fn mulI(a: Fe, b: Fe) Fe {
        @setEvalBranchQuota(100_000);
        return @call(.always_inline, mul, .{ a, b });
    }

    /// `sq`, forced inline (see `mulI`).
    pub inline fn sqI(a: Fe) Fe {
        @setEvalBranchQuota(100_000);
        return @call(.always_inline, sq, .{a});
    }

    /// `n` successive squarings (n is public).
    pub fn sqn(a: Fe, comptime n: usize) Fe {
        var r = a;
        for (0..n) |_| r = r.sq();
        return r;
    }

    /// a^(2^k − 1) for the runs of ones the chains below need.
    const Runs = struct { x1: Fe, x2: Fe, x15: Fe, x30: Fe, x32: Fe, x255: Fe };

    fn runs(a: Fe) Runs {
        const x2 = a.sq().mul(a);
        const x3 = x2.sq().mul(a);
        const x6 = x3.sqn(3).mul(x3);
        const x12 = x6.sqn(6).mul(x6);
        const x15 = x12.sqn(3).mul(x3);
        const x30 = x15.sqn(15).mul(x15);
        const x32 = x30.sqn(2).mul(x2);
        const x60 = x30.sqn(30).mul(x30);
        const x120 = x60.sqn(60).mul(x60);
        const x240 = x120.sqn(120).mul(x120);
        const x255 = x240.sqn(15).mul(x15);
        return .{ .x1 = a, .x2 = x2, .x15 = x15, .x30 = x30, .x32 = x32, .x255 = x255 };
    }

    /// a^(p−2) = a⁻¹ (0 for 0), by a fixed addition chain: constant time.
    /// p − 2 from the top: 255 ones, 0, 32 ones, 64 zeros, 30 ones, 0, 1.
    pub fn invert(a: Fe) Fe {
        const x = runs(a);
        var r = x.x255.sqn(1 + 32).mul(x.x32);
        r = r.sqn(64 + 30).mul(x.x30);
        return r.sqn(2).mul(x.x1);
    }

    /// A square root. p ≡ 3 (mod 4), so it is a^((p+1)/4); (p+1)/4 from the
    /// top: 255 ones, 0, 32 ones, 63 zeros, 1, 30 zeros.
    /// `error.NotSquare` when a is not a quadratic residue.
    pub fn sqrt(a: Fe) NotSquareError!Fe {
        const x = runs(a);
        var r = x.x255.sqn(1 + 32).mul(x.x32);
        r = r.sqn(64).mul(x.x1);
        r = r.sqn(30);
        if (!r.sq().equivalent(a)) return error.NotSquare;
        return r;
    }

    pub fn isSquare(a: Fe) bool {
        return if (a.sqrt()) |_| true else |_| false;
    }

    pub fn isZero(a: Fe) bool {
        var acc: u64 = 0;
        inline for (0..6) |i| acc |= a.limbs[i];
        return acc == 0;
    }

    pub fn equivalent(a: Fe, b: Fe) bool {
        var acc: u64 = 0;
        inline for (0..6) |i| acc |= a.limbs[i] ^ b.limbs[i];
        return acc == 0;
    }

    pub fn isOdd(a: Fe) bool {
        return a.fromMont()[0] & 1 != 0;
    }

    /// `a.* = b` when `c == 1`, unchanged when `c == 0`; no branch.
    pub fn cMov(a: *Fe, b: Fe, c: u1) void {
        const m = 0 -% @as(u64, c);
        inline for (0..6) |i| a.limbs[i] ^= (a.limbs[i] ^ b.limbs[i]) & m;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const PW: u1152 = P_INT;
const RINV: u1152 = blk: {
    @setEvalBranchQuota(1_000_000);
    // R⁻¹ mod p by Fermat over u1152 (comptime, test-only).
    var r: u1152 = 1;
    var b: u1152 = (@as(u1152, 1) << 384) % PW;
    var e: u1152 = PW - 2;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) r = r * b % PW;
        b = b * b % PW;
    }
    break :blk r;
};

/// The integer value of a (out of the Montgomery domain).
fn valueOf(a: Fe) u1152 {
    var v: u1152 = 0;
    inline for (0..6) |i| v += @as(u1152, a.limbs[i]) << (64 * i);
    return v * RINV % PW;
}

fn fromU(v: u1152) Fe {
    const m = (v % PW) * ((@as(u1152, 1) << 384) % PW) % PW;
    return .{ .limbs = limbsOf(@as(u384, @intCast(m))) };
}

fn randFe(r: std.Random) Fe {
    return fromU(r.int(u384));
}

fn isCanonical(a: Fe) bool {
    return A.lt(a.limbs) == 1;
}

test "field: constants" {
    try testing.expectEqual(@as(u64, 0x100000001), A.M0INV);
    try testing.expectEqual(@as(u1152, 1), valueOf(Fe.one));
    try testing.expectEqual(@as(u1152, 0), valueOf(Fe.zero));
}

test "field: differential against wide integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x384);
    const r = prng.random();
    const edges = [_]u1152{ 0, 1, 2, PW - 1, PW - 2, (PW + 1) / 2, 1 << 383, (1 << 383) - 1, 1 << 128, (1 << 256) - 1, (1 << 64) - 1, PW - (1 << 32) };
    const iters: usize = if (@import("builtin").mode == .debug) 1000 else 3000;
    for (0..iters) |i| {
        const a = if (i < edges.len * edges.len) fromU(edges[i % edges.len]) else randFe(r);
        const b = if (i < edges.len * edges.len) fromU(edges[i / edges.len]) else randFe(r);
        const av = valueOf(a);
        const bv = valueOf(b);
        const m = a.mul(b);
        try testing.expectEqual(av * bv % PW, valueOf(m));
        try testing.expect(isCanonical(m));
        const s = a.sq();
        try testing.expectEqual(av * av % PW, valueOf(s));
        try testing.expect(isCanonical(s));
        try testing.expect(s.equivalent(a.mul(a)));
        const ad = a.add(b);
        try testing.expectEqual((av + bv) % PW, valueOf(ad));
        try testing.expect(isCanonical(ad));
        const sb = a.sub(b);
        try testing.expectEqual((av + PW - bv) % PW, valueOf(sb));
        try testing.expect(isCanonical(sb));
        try testing.expectEqual((PW - av) % PW, valueOf(a.neg()));
        try testing.expectEqual(av * 3 % PW, valueOf(a.mulSmall(3)));
        try testing.expectEqual(av * 8 % PW, valueOf(a.mulSmall(8)));
        try testing.expectEqual(av * 15 % PW, valueOf(a.mulSmall(15)));
        try testing.expectEqual(av == bv, a.equivalent(b));
        try testing.expectEqual(av == 0, a.isZero());
        try testing.expectEqual(av & 1 == 1, a.isOdd());
        // Round trip through bytes, both endians.
        const be = a.toBytes(.big);
        var want_be: [48]u8 = undefined;
        std.mem.writeInt(u384, &want_be, @intCast(av), .big);
        try testing.expectEqualSlices(u8, &want_be, &be);
        try testing.expect(a.equivalent(try Fe.fromBytes(be, .big)));
        try testing.expect(a.equivalent(try Fe.fromBytes(a.toBytes(.little), .little)));
    }
}

test "field: invert and sqrt against generic exponentiation" {
    var prng = std.Random.DefaultPrng.init(0x3840);
    const r = prng.random();
    try testing.expect(Fe.zero.invert().isZero());
    for (0..40) |_| {
        const a = randFe(r);
        if (a.isZero()) continue;
        const inv = a.invert();
        try testing.expect(a.mul(inv).equivalent(Fe.one));
        const av = valueOf(a);
        // Independent check of the chain: square-and-multiply on wide ints.
        var want: u1152 = 1;
        var b = av;
        var e: u1152 = PW - 2;
        while (e != 0) : (e >>= 1) {
            if (e & 1 != 0) want = want * b % PW;
            b = b * b % PW;
        }
        try testing.expectEqual(want, valueOf(inv));
        const s = a.sq();
        const root = try s.sqrt();
        try testing.expect(root.equivalent(a) or root.equivalent(a.neg()));
    }
    // −1 is a non-residue when p ≡ 3 (mod 4).
    try testing.expectError(error.NotSquare, Fe.one.neg().sqrt());
    try testing.expect((try Fe.zero.sqrt()).isZero());
}

test "field: fromBytes rejects p and above, accepts p − 1" {
    var b: [48]u8 = undefined;
    std.mem.writeInt(u384, &b, P_INT, .big);
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .big));
    std.mem.writeInt(u384, &b, P_INT - 1, .big);
    try testing.expectEqual(PW - 1, valueOf(try Fe.fromBytes(b, .big)));
    std.mem.writeInt(u384, &b, P_INT + 1, .big);
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .big));
    b = @splat(0xff);
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .big));
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .little));
    try testing.expectError(error.NonCanonical, Fe.fromInt(Fe.field_order));
}

test "field: extreme limbs (no carry lost, results canonical)" {
    // p − 1 and the values whose Montgomery limbs are p − 1, 0, all-ones-ish
    // patterns: products of the largest canonical limbs and the reduction's
    // largest intermediate (T close to p·R).
    const big: Fe = .{ .limbs = limbsOf(P_INT - 1) };
    const vb = valueOf(big);
    var x = big;
    var xv = vb;
    for (0..64) |_| {
        try testing.expectEqual(xv * vb % PW, valueOf(x.mul(big)));
        try testing.expectEqual(xv * xv % PW, valueOf(x.sq()));
        x = x.mul(big).add(big).sub(Fe.one);
        xv = (xv * vb + vb + PW - 1) % PW;
        try testing.expect(isCanonical(x));
        try testing.expectEqual(xv, valueOf(x));
    }
}

test "field: amd64 core == portable product (edges and random)" {
    if (comptime !fast_core.supported) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x3842);
    const r = prng.random();
    const edges = [_]Fe{ Fe.zero, Fe.one, .{ .limbs = limbsOf(P_INT - 1) }, .{ .limbs = limbsOf(P_INT - 2) }, .{ .limbs = limbsOf(1) }, .{ .limbs = limbsOf((1 << 383) + 5) }, .{ .limbs = limbsOf((1 << 384) - (1 << 128) - (1 << 96)) }, .{ .limbs = .{ ~@as(u64, 0), 0, ~@as(u64, 0), 0, ~@as(u64, 0), 0 } } };
    for (edges) |a| for (edges) |b| {
        try testing.expectEqualSlices(u64, &a.mulPortable(b).limbs, &a.mul(b).limbs);
    };
    const iters: usize = if (@import("builtin").mode == .debug) 20_000 else 200_000;
    for (0..iters) |_| {
        const a = randFe(r);
        const b = randFe(r);
        try testing.expectEqualSlices(u64, &a.mulPortable(b).limbs, &a.mul(b).limbs);
        try testing.expectEqualSlices(u64, &a.sqPortable().limbs, &a.sq().limbs);
    }
}

test "field: std P384.Fe holds the same limbs" {
    const S = std.crypto.ecc.P384.Fe;
    var prng = std.Random.DefaultPrng.init(0x3841);
    for (0..20) |_| {
        var b: [48]u8 = undefined;
        prng.random().bytes(&b);
        b[0] &= 0x7f;
        const ours = try Fe.fromBytes(b, .big);
        const theirs = try S.fromBytes(b, .big);
        try testing.expectEqualSlices(u64, &theirs.limbs, &ours.limbs);
    }
}
