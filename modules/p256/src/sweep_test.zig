// SPDX-License-Identifier: MIT

//! No-panic sweep (wave GP) regression tests.

const std = @import("std");
const sign = @import("sign.zig");

test "rawToDer / derToRaw are total on zero and extreme r, s (sweep P2-1)" {
    // std's `Signature.toDer` panics on r = 0 or s = 0; the module's own codec
    // must not, and must round-trip them.
    var buf: [sign.der_max_len]u8 = undefined;
    const cases = [_][64]u8{
        @as([64]u8, @splat(0)),
        @as([32]u8, @splat(0)) ++ @as([32]u8, @splat(0xff)),
        @as([32]u8, @splat(0xff)) ++ @as([32]u8, @splat(0)),
        @as([64]u8, @splat(0xff)),
    };
    for (cases) |raw| {
        const der = sign.rawToDer(raw, &buf);
        // a lone 0x00 INTEGER is deliberately refused by the strict decoder
        // (non-minimal), everything else round-trips
        if (std.mem.eql(u8, raw[0..32], &@as([32]u8, @splat(0))) or std.mem.eql(u8, raw[32..], &@as([32]u8, @splat(0)))) {
            try std.testing.expect(sign.derToRaw(der) == null);
        } else {
            try std.testing.expectEqualSlices(u8, &raw, &sign.derToRaw(der).?);
        }
    }
}

test "derToRaw: lying lengths and truncations are null, never a panic (sweep P2-2)" {
    const good = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    try std.testing.expect(sign.derToRaw(&good) != null);
    var i: usize = 0;
    while (i < good.len) : (i += 1) try std.testing.expect(sign.derToRaw(good[0..i]) == null);
    // every single-byte substitution at every position
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        var m = good;
        for (0..m.len) |p| {
            m = good;
            m[p] = @intCast(b);
            _ = sign.derToRaw(&m);
        }
    }
    // length claims beyond the buffer, two-octet forms
    try std.testing.expect(sign.derToRaw(&.{ 0x30, 0x82, 0xff, 0xff, 0x02 }) == null);
    try std.testing.expect(sign.derToRaw(&.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }) == null);
    try std.testing.expect(sign.derToRaw(&.{ 0x30, 0x80 }) == null);
}

test "Signature.toDer is total: zero r and/or s encode and reparse (sweep P2-1)" {
    const E = sign.EcdsaP256Sha256;
    const cases = [_][]const u8{
        &.{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00 }, // r = 0, s = 0
        &.{ 0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x01, 0x01 }, // r = 0
        &.{ 0x30, 0x07, 0x02, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00 }, // s = 0
    };
    for (cases) |der| {
        // fromDer still accepts them (std's parser); toDer must not panic.
        const sig = try E.Signature.fromDer(der);
        var buf: [E.Signature.der_encoded_length_max]u8 = undefined;
        try std.testing.expectEqualSlices(u8, der, sig.toDer(&buf));
    }
    // all-zero via fromBytes, and the interop pair
    const z = E.Signature.fromBytes(@splat(0));
    var buf: [E.Signature.der_encoded_length_max]u8 = undefined;
    try std.testing.expectEqualSlices(u8, cases[0], z.toDer(&buf));
    try std.testing.expectEqualSlices(u8, &z.toBytes(), &E.Signature.fromStd(z.toStd()).toBytes());
}

test "Signature.toDer agrees with std's on every nonzero signature shape (sweep P2-1)" {
    const E = sign.EcdsaP256Sha256;
    var prng = std.Random.DefaultPrng.init(0xd3a);
    for (0..400) |i| {
        var raw: [64]u8 = undefined;
        prng.random().bytes(&raw);
        // exercise leading zeros and the sign-bit pad on both halves
        const zr = prng.random().uintLessThan(usize, 33);
        const zs = prng.random().uintLessThan(usize, 33);
        @memset(raw[0..@min(zr, 31)], 0);
        @memset(raw[32..][0..@min(zs, 31)], 0);
        if (i % 3 == 0) raw[@min(zr, 31)] |= 0x80;
        if (raw[31] == 0 and std.mem.allEqual(u8, raw[0..32], 0)) continue;
        if (raw[63] == 0 and std.mem.allEqual(u8, raw[32..], 0)) continue;
        var a: [E.Signature.der_encoded_length_max]u8 = undefined;
        var b: [E.Signature.der_encoded_length_max]u8 = undefined;
        const ours = E.Signature.fromBytes(raw).toDer(&a);
        const theirs = E.StdSignature.fromBytes(raw).toDer(&b);
        try std.testing.expectEqualSlices(u8, theirs, ours);
    }
}

const group = @import("group.zig");
const scalarmod = @import("scalar.zig");

test "ecdsaVerifyDigest refuses a forged signature under the identity key (sweep REV-P2-1)" {
    const msg = "forge me";
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &h, .{});
    // With Q = O the equation reduces to R = e*s^-1 * G. Take s = 1: R = e*G,
    // r = x(R) mod n.
    const R = try group.P256.combMulBase(h, .big);
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = R.affineCoordinates().x.toBytes(.big);
    const r = scalarmod.Scalar.fromBytes48(wide, .big).toBytes(.big);
    var sig: [64]u8 = undefined;
    sig[0..32].* = r;
    sig[32..64].* = @as([31]u8, @splat(0)) ++ [_]u8{1};
    const o1 = [_]u8{0};
    const o2 = [_]u8{4} ++ @as([64]u8, @splat(0));
    try std.testing.expect(!sign.ecdsaVerify(&o1, msg, sig));
    try std.testing.expect(!sign.ecdsaVerifyDigest(&o1, &h, sig));
    try std.testing.expect(!sign.ecdsaVerify(&o2, msg, sig));
    try std.testing.expect(!sign.ecdsaVerifyDigest(&o2, &h, sig));
}

test "derToRaw is strict where Signature.fromDer is lenient (sweep REV-P2-2)" {
    const E = sign.EcdsaP256Sha256;
    const zero_r = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 };
    try std.testing.expect(sign.derToRaw(&zero_r) == null);
    _ = try E.Signature.fromDer(&zero_r);
    const padded = [_]u8{ 0x30, 0x09, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x01 };
    try std.testing.expect(sign.derToRaw(&padded) == null);
    // std's parser is lenient (documented on fromDer).
    _ = try E.Signature.fromDer(&padded);
}
