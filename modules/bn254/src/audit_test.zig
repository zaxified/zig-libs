// SPDX-License-Identifier: MIT
//! Tests added by the 2026-11-17 whole-module mutation audit: each pins a
//! behaviour that no earlier test distinguished (a mutant of the guarded
//! condition survived the whole suite).

const std = @import("std");
const root = @import("root.zig");

const Fp = root.Fp;
const Fp2 = root.Fp2;
const Fp6 = root.Fp6;
const Fp12 = root.Fp12;
const G1 = root.g1;
const G2 = root.g2;
const groth16 = root.groth16;

test "Fp.sub: a borrow rippling through a limb that is equal in both operands" {
    // limb 0: 0 - 1 borrows; limb 1: 1 - 1 - borrow borrows again (the
    // second `@subWithOverflow`), so the borrow must reach the top and add p.
    const a = Fp{ .limbs = .{ 0, 1, 0, 0 } };
    const b = Fp{ .limbs = .{ 1, 1, 0, 0 } };
    try std.testing.expect(a.sub(b).add(b).eql(a));
    try std.testing.expect(!a.sub(b).isZero());
    try std.testing.expect(b.sub(a).add(a).eql(b));
    try std.testing.expect(a.sub(a).isZero());
}

test "Fp.fromInt: p is refused, p - 1 and a value spanning all four limbs round-trip" {
    const p = std.mem.readInt(u256, &root.fp.p_bytes, .big);
    try std.testing.expectError(error.Overflow, Fp.fromInt(u256, p));
    var expected: [32]u8 = undefined;
    std.mem.writeInt(u256, &expected, p - 1, .big);
    try std.testing.expectEqualSlices(u8, &expected, &(try Fp.fromInt(u256, p - 1)).toBytes());
    const wide: u256 = (1 << 200) | (1 << 130) | (1 << 70) | 12345;
    std.mem.writeInt(u256, &expected, wide, .big);
    try std.testing.expectEqualSlices(u8, &expected, &(try Fp.fromInt(u256, wide)).toBytes());
}

test "Fp.isZero and Fp.eql look at every limb" {
    try std.testing.expect(Fp.zero.isZero());
    const base = Fp{ .limbs = .{ 11, 22, 33, 44 } };
    try std.testing.expect(base.eql(base));
    inline for (0..4) |k| {
        var l = [4]u64{ 0, 0, 0, 0 };
        l[k] = 1;
        const x = Fp{ .limbs = l };
        try std.testing.expect(!x.isZero());
        try std.testing.expect(!x.eql(Fp.zero));
        try std.testing.expect(!Fp.zero.eql(x));
        var m = base.limbs;
        m[k] ^= 1;
        try std.testing.expect(!base.eql(Fp{ .limbs = m }));
    }
}

test "Fp2/Fp6/Fp12 isZero and eql: every component alone decides" {
    try std.testing.expect(!(Fp2{ .c0 = Fp.zero, .c1 = Fp.one }).isZero());
    try std.testing.expect(!(Fp2{ .c0 = Fp.one, .c1 = Fp.zero }).isZero());
    try std.testing.expect(!(Fp2{ .c0 = Fp.one, .c1 = Fp.one }).eql(Fp2{ .c0 = Fp.one, .c1 = Fp.zero }));
    try std.testing.expect(!(Fp2{ .c0 = Fp.one, .c1 = Fp.one }).eql(Fp2{ .c0 = Fp.zero, .c1 = Fp.one }));

    inline for (.{ "c0", "c1", "c2" }) |name| {
        var x = Fp6.zero;
        @field(x, name) = Fp2.one;
        try std.testing.expect(!x.isZero());
        try std.testing.expect(!x.eql(Fp6.zero));
        try std.testing.expect(!Fp6.zero.eql(x));
        try std.testing.expect(x.eql(x));
    }
    inline for (.{ "c0", "c1" }) |name| {
        var x = Fp12.zero;
        @field(x, name) = Fp6.one;
        try std.testing.expect(!x.isZero());
        try std.testing.expect(!x.eql(Fp12.zero));
        try std.testing.expect(!Fp12.zero.eql(x));
        try std.testing.expect(x.eql(x));
    }
}

test "G1: a non-canonical identity is on the curve; off-curve is not a subgroup member" {
    const J = G1.Jacobian;
    const ident = J{ .x = try Fp.fromInt(u8, 5), .y = try Fp.fromInt(u8, 7), .z = Fp.zero };
    try std.testing.expect(ident.isOnCurve());
    try std.testing.expect(ident.subgroupCheck());
    const g = J.fromAffine(G1.Affine.generator);
    try std.testing.expect(g.add(g.negate()).isOnCurve());
    const off = J{ .x = Fp.one, .y = Fp.one, .z = Fp.one };
    try std.testing.expect(!off.isOnCurve());
    try std.testing.expect(!off.subgroupCheck());
}

test "G1.fromBytes: y >= p is InvalidFieldElement; compressed input of 33 bytes is InvalidEncoding" {
    var enc: [G1.encoded_bytes]u8 = undefined;
    enc[0..32].* = Fp.one.toBytes();
    enc[32..64].* = root.fp.p_bytes;
    try std.testing.expectError(error.InvalidFieldElement, G1.fromBytes(&enc));

    var cb: [G1.compressed_bytes + 1]u8 = @splat(0);
    cb[0..G1.compressed_bytes].* = G1.toBytesCompressed(G1.Affine.generator);
    try std.testing.expectError(error.InvalidEncoding, G1.fromBytesCompressed(&cb));
}

test "G2: a non-canonical identity is on the twist" {
    const ident = G2.Jacobian{
        .x = .{ .c0 = try Fp.fromInt(u8, 5), .c1 = Fp.zero },
        .y = .{ .c0 = try Fp.fromInt(u8, 7), .c1 = Fp.one },
        .z = Fp2.zero,
    };
    try std.testing.expect(ident.isOnCurve());
    const g = G2.Jacobian.fromAffine(G2.Affine.generator);
    try std.testing.expect(g.add(g.negate()).isOnCurve());
}

test "G2.fromBytes: each of the four coordinates >= p is InvalidFieldElement" {
    const enc = G2.toBytes(G2.Affine.generator);
    inline for (0..4) |k| {
        var bad = enc;
        @memcpy(bad[k * 32 ..][0..32], &root.fp.p_bytes);
        try std.testing.expectError(error.InvalidFieldElement, G2.fromBytesUnchecked(&bad));
        try std.testing.expectError(error.InvalidFieldElement, G2.fromBytes(&bad));
    }
}

test "G2 compressed: the flag follows the lexicographic order of y and -y; 65 bytes are refused" {
    const g = G2.Affine.generator;
    const neg = G2.Affine{ .x = g.x, .y = g.y.neg() };
    var flags: [2]u8 = undefined;
    for ([_]G2.Affine{ g, neg }, 0..) |p, i| {
        const a = p.y.toBytes();
        const n = p.y.neg().toBytes();
        const want: u8 = if (std.mem.order(u8, &a, &n) == .gt) 0b1100_0000 else 0b1000_0000;
        flags[i] = G2.toBytesCompressed(p)[0] & 0b1100_0000;
        try std.testing.expectEqual(want, flags[i]);
    }
    try std.testing.expect(flags[0] != flags[1]);

    var cb: [G2.compressed_bytes + 1]u8 = @splat(0);
    cb[0..G2.compressed_bytes].* = G2.toBytesCompressed(g);
    try std.testing.expectError(error.InvalidEncoding, G2.fromBytesCompressed(&cb));
}

// ── groth16.verify's untrusted-input validation ───────────────────────────
//
// A pair with a point at infinity contributes 1 to the pairing product, so a
// verifying key whose alpha and IC[0] are the identity leaves the check
// resting on A, B, C alone. An A or C of (0, 0) (off the curve, but NOT
// flagged as infinity) makes every Miller line collapse to `c * w^3`, which
// the final exponentiation maps to 1: the pairing check alone ACCEPTS it, so
// only `verify`'s own validation refuses it. Likewise a B outside the
// r-subgroup: with A = C = infinity every pair is skipped and the pairing
// check accepts any B.

const degenerate_ic = [_]G1.Affine{G1.Affine.identity};

fn degenerateVk() groth16.VerifyingKey {
    return .{
        .alpha_g1 = G1.Affine.identity,
        .beta_g2 = G2.Affine.generator,
        .gamma_g2 = G2.Affine.generator,
        .delta_g2 = G2.Affine.generator,
        .ic = &degenerate_ic,
    };
}

test "groth16.verify: A or C off the curve is refused although the pairing alone would accept it" {
    const off = G1.Affine{ .x = Fp.zero, .y = Fp.zero };
    try std.testing.expect(!G1.Jacobian.fromAffine(off).isOnCurve());
    // The premise: the pairing check by itself sees e((0,0), Q) == 1.
    const pairing = root.pairing;
    try std.testing.expect(pairing.pairingCheck(&.{.{ .p = off, .q = G2.Affine.generator }}));

    const vk = degenerateVk();
    // Control: with A = C = infinity and a member B the degenerate key verifies.
    const ctl = groth16.Proof{ .a = G1.Affine.identity, .b = G2.Affine.generator, .c = G1.Affine.identity };
    try std.testing.expect(try groth16.verify(vk, ctl, &.{}));

    try std.testing.expect(!(try groth16.verify(vk, .{ .a = off, .b = G2.Affine.generator, .c = G1.Affine.identity }, &.{})));
    try std.testing.expect(!(try groth16.verify(vk, .{ .a = G1.Affine.identity, .b = G2.Affine.generator, .c = off }, &.{})));
}

test "groth16.verify: B on the twist but outside the r-subgroup is refused" {
    // x = u, the same on-twist non-member as the one used in groth16.zig and precompiles.zig.
    var c1_bytes = @as([32]u8, @splat(0));
    c1_bytes[31] = 1;
    var y_c0_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c0_bytes, "0cf32d3c49a2cb8a092f24ec3201e68dc299b6216e6321ee60573e3a7f596ea8");
    var y_c1_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c1_bytes, "07bca656753ef8cbee60335acbffe3def91636952d4ab9eb0b839c7f3566c0e2");
    const bad_b = G2.Affine{
        .x = .{ .c0 = Fp.zero, .c1 = try Fp.fromBytes(c1_bytes) },
        .y = .{ .c0 = try Fp.fromBytes(y_c0_bytes), .c1 = try Fp.fromBytes(y_c1_bytes) },
    };
    try std.testing.expect(G2.Jacobian.fromAffine(bad_b).isOnCurve());
    try std.testing.expect(!G2.Jacobian.fromAffine(bad_b).subgroupCheck());
    // Premise: every pair is skipped, so the pairing check accepts.
    const proof = groth16.Proof{ .a = G1.Affine.identity, .b = bad_b, .c = G1.Affine.identity };
    try std.testing.expect(root.pairing.pairingCheck(&.{.{ .p = G1.Affine.identity, .q = bad_b }}));
    try std.testing.expect(!(try groth16.verify(degenerateVk(), proof, &.{})));
}
