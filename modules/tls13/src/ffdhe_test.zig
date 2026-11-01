// SPDX-License-Identifier: MIT

//! Tests of the RFC 7919 named FFDHE groups through the `kex` entry points:
//! Python-`pow()` known answers, the zero-padding of the shared secret, peer
//! values that must be refused, and agreement of both sides for each group.

const std = @import("std");
const builtin = @import("builtin");
const kex = @import("kex.zig");
const ffdhe = @import("ffdhe.zig");
const vec = @import("ffdhe_kat_vectors.zig");
const testing = std.testing;

const all_groups = [_]u16{ kex.ffdhe2048_group, kex.ffdhe3072_group, kex.ffdhe4096_group, kex.ffdhe6144_group, kex.ffdhe8192_group };

/// A `std.Random` that serves `bytes` (cycled): the exponent a test wants.
const FixedRng = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *FixedRng = @ptrCast(@alignCast(ptr));
        for (buf) |*b| {
            b.* = self.bytes[self.pos % self.bytes.len];
            self.pos += 1;
        }
    }

    fn random(self: *FixedRng) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

test "FFDHE groups: sizes, exponent lengths (OpenSSL ffc_dh.c) and the RFC 7919 prime shape" {
    const plens = [_]usize{ 256, 384, 512, 768, 1024 };
    const xlens = [_]usize{ 29, 35, 41, 47, 50 }; // 225 / 275 / 325 / 375 / 400 bits
    const xbits = [_]u16{ 225, 275, 325, 375, 400 };
    for (all_groups, 0..) |g, i| {
        try testing.expectEqual(plens[i], kex.expectedShareLen(g));
        try testing.expectEqual(xlens[i], kex.scalarLen(g));
        const f = ffdhe.find(g).?;
        try testing.expectEqual(xbits[i], f.xbits);
        try testing.expectEqual(plens[i], f.plen());
        try testing.expectEqual(g, f.code);
        // q = (p - 1) / 2: 2q + 1 = p.
        var twice: [1024]u8 = undefined;
        var carry: u8 = 1;
        var k = f.q.len;
        while (k > 0) {
            k -= 1;
            const v = @as(u16, f.q[k]) * 2 + carry;
            twice[k] = @truncate(v);
            carry = @truncate(v >> 8);
        }
        try testing.expectEqual(@as(u8, 0), carry);
        try testing.expectEqualSlices(u8, f.p, twice[0..f.p.len]);
    }
    try testing.expect(ffdhe.find(0x0105) == null);
    try testing.expectEqual(@as(usize, 0), kex.expectedShareLen(0x00ff));
    try testing.expectEqual(@as(usize, 0), kex.scalarLen(0x0105));
}

fn katGroup(comptime group: u16, comptime k: []const u8, comptime plen: usize) !void {
    const xa = @field(vec, k ++ "_xa");
    const xb = @field(vec, k ++ "_xb");
    const ya = @field(vec, k ++ "_ya");
    const yb = @field(vec, k ++ "_yb");
    const z = @field(vec, k ++ "_z");
    // generate with a fixed exponent: the secret is the exponent, the share is 2^x mod p.
    var rng: FixedRng = .{ .bytes = &xa };
    var kp: kex.KeyPair = undefined;
    try kex.generate(group, rng.random(), &kp);
    try testing.expectEqual(group, kp.group);
    try testing.expectEqual(plen, kp.public_len);
    try testing.expectEqualSlices(u8, &xa, kp.secret[0..xa.len]);
    try testing.expectEqualSlices(u8, &ya, kp.public[0..plen]);
    // Both directions give Python's Z.
    var ss: kex.SharedSecret = undefined;
    try kex.sharedSecret(group, &xa, &yb, &ss);
    try testing.expectEqual(plen, ss.len);
    try testing.expectEqualSlices(u8, &z, ss.slice());
    try kex.sharedSecret(group, &xb, &ya, &ss);
    try testing.expectEqualSlices(u8, &z, ss.slice());
    // The largest exponent: the draw is masked to xbits bits (all-ones bytes -> 2^xbits - 1).
    var ones: FixedRng = .{ .bytes = &[_]u8{0xff} };
    try kex.generate(group, ones.random(), &kp);
    try testing.expectEqualSlices(u8, &@field(vec, k ++ "_xmax"), kp.secret[0..xa.len]);
    try testing.expectEqualSlices(u8, &@field(vec, k ++ "_ymax"), kp.public[0..plen]);
    // Leading zero byte of Z is kept (RFC 8446 §7.4.1): the secret is still len(p) bytes.
    const lz = @field(vec, k ++ "_lz_z");
    try testing.expectEqual(@as(u8, 0), lz[0]);
    try kex.sharedSecret(group, &@field(vec, k ++ "_lz_xc"), &@field(vec, k ++ "_lz_ys"), &ss);
    try testing.expectEqual(plen, ss.len);
    try testing.expectEqualSlices(u8, &lz, ss.slice());
    // ... and so on the server side (serverExchange hands out the same padded secret).
    var ex: kex.ServerExchange = undefined;
    var srv: FixedRng = .{ .bytes = &xb };
    try kex.serverExchange(group, &ya, srv.random(), &ex);
    try testing.expectEqualSlices(u8, &yb, ex.public[0..ex.public_len]);
    try testing.expectEqualSlices(u8, &z, ex.shared.slice());
}

test "ffdhe2048 KAT: generate / sharedSecret / serverExchange against Python pow()" {
    try katGroup(kex.ffdhe2048_group, "ffdhe2048", 256);
}

test "ffdhe3072 KAT: generate / sharedSecret / serverExchange against Python pow()" {
    try katGroup(kex.ffdhe3072_group, "ffdhe3072", 384);
}

test "FFDHE: both sides agree for every group, secret is len(p) bytes, shares are len(p) bytes" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xd1)));
    for (all_groups) |g| {
        // Debug-mode 6144/8192-bit exponentiations are slow; ReleaseSafe/Fast covers them
        // (and `stackprobe_test.zig` runs ffdhe8192 end to end).
        if (builtin.mode == .debug and g >= kex.ffdhe6144_group) continue;
        const plen = kex.expectedShareLen(g);
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, csprng.random(), &kp);
        try testing.expectEqual(plen, kp.public_len);
        var ex: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], csprng.random(), &ex);
        try testing.expectEqual(plen, ex.public_len);
        try testing.expectEqual(plen, ex.shared.len);
        var ss: kex.SharedSecret = undefined;
        try kex.sharedSecret(g, kp.secret[0..kex.scalarLen(g)], ex.public[0..ex.public_len], &ss);
        try testing.expectEqual(plen, ss.len);
        try testing.expectEqualSlices(u8, ex.shared.slice(), ss.slice());
        // expand is a no-op for a finite-field group.
        var exp: kex.Expanded = .{ .mlkem512 = undefined };
        try kex.expand(g, kp.secret[0..kex.scalarLen(g)], &exp);
        try testing.expect(exp == .none);
    }
}

/// p as a big-endian byte array plus a few neighbours for the peer-value tests.
fn pPlus(comptime f: *const ffdhe.Info, delta: i2) [f.p.len]u8 {
    var out: [f.p.len]u8 = f.p[0..f.p.len].*;
    if (delta < 0) {
        out[out.len - 1] -= 1; // p ends in 0xff
    } else if (delta > 0) {
        var i: usize = out.len;
        while (i > 0) {
            i -= 1;
            out[i] +%= 1;
            if (out[i] != 0) break;
        }
    }
    return out;
}

test "FFDHE peer values: 0, 1, p-1, p, p+1, a non-residue, 0xff..ff and wrong lengths are refused" {
    inline for (.{ kex.ffdhe2048_group, kex.ffdhe3072_group }) |g| {
        const f = comptime ffdhe.find(g).?;
        const plen = comptime f.plen();
        var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xd2)));
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, csprng.random(), &kp);
        const sec = kp.secret[0..kex.scalarLen(g)];

        const zero: [plen]u8 = @splat(0);
        var one: [plen]u8 = @splat(0);
        one[plen - 1] = 1;
        var two = one;
        two[plen - 1] = 2;
        var pm2 = comptime pPlus(f, -1);
        pm2[plen - 1] -= 1; // p - 2 = -2: a non-residue, since p = 7 mod 8 makes 2 a residue and q odd
        const bad = [_][plen]u8{
            zero,
            one,
            comptime pPlus(f, -1), // p - 1
            comptime pPlus(f, 0), // p
            comptime pPlus(f, 1), // p + 1
            pm2, // Y^q = -1
            @as([plen]u8, @splat(0xff)), // >= p
        };
        var ss: kex.SharedSecret = undefined;
        for (bad) |y| {
            try testing.expectError(error.KeyExchangeFailed, kex.sharedSecret(g, sec, &y, &ss));
            try testing.expectEqual(@as(usize, 0), ss.len);
            try testing.expect(std.mem.allEqual(u8, &ss.bytes, 0));
            var ex: kex.ServerExchange = undefined;
            try testing.expectError(error.KeyExchangeFailed, kex.serverExchange(g, &y, csprng.random(), &ex));
            try testing.expectEqual(@as(usize, 0), ex.shared.len);
            try testing.expect(std.mem.allEqual(u8, &ex.shared.bytes, 0));
        }
        // Lengths +-1 and an empty share: the group fixes the exact length.
        const long: [plen + 1]u8 = @splat(0x02);
        try testing.expectError(error.MissingKeyShare, kex.sharedSecret(g, sec, long[0..plen -| 1], &ss));
        try testing.expectError(error.MissingKeyShare, kex.sharedSecret(g, sec, &long, &ss));
        try testing.expectError(error.MissingKeyShare, kex.sharedSecret(g, sec, &.{}, &ss));
        var ex: kex.ServerExchange = undefined;
        try testing.expectError(error.MissingKeyShare, kex.serverExchange(g, long[0..plen -| 1], csprng.random(), &ex));
        try testing.expectError(error.MissingKeyShare, kex.serverExchange(g, &long, csprng.random(), &ex));
        // A share of another FFDHE group (wrong length).
        const other: [if (g == kex.ffdhe2048_group) 384 else 256]u8 = @splat(2);
        try testing.expectError(error.MissingKeyShare, kex.sharedSecret(g, sec, &other, &ss));
        // A secret shorter than the exponent, and a wiped (zero) one.
        try testing.expectError(error.KeyExchangeFailed, kex.sharedSecret(g, sec[0 .. sec.len - 1], &two, &ss));
        try testing.expectError(error.KeyExchangeFailed, kex.sharedSecret(g, &@as([64]u8, @splat(0)), &two, &ss));

        // The generator itself is a valid peer value: Z = 2^x = our own public value.
        try kex.sharedSecret(g, sec, &two, &ss);
        try testing.expectEqualSlices(u8, kp.public[0..plen], ss.slice());
    }
}

test "FFDHE generate: a dead RNG (all zero exponents) fails closed and wipes the secret" {
    var zeros: FixedRng = .{ .bytes = &[_]u8{0} };
    var kp: kex.KeyPair = undefined;
    kp.secret = @splat(0x5a);
    try testing.expectError(error.KeyExchangeFailed, kex.generate(kex.ffdhe2048_group, zeros.random(), &kp));
    try testing.expect(std.mem.allEqual(u8, &kp.secret, 0));
    try testing.expectEqual(@as(usize, 0), kp.public_len);
}

test "FFDHE: a key share of a different kind is not mistaken (curve group id, FFDHE secret)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xd3)));
    var kp: kex.KeyPair = undefined;
    try kex.generate(kex.ffdhe2048_group, csprng.random(), &kp);
    var ss: kex.SharedSecret = undefined;
    // 256 bytes are no x25519 / P-256 share.
    try testing.expectError(error.MissingKeyShare, kex.sharedSecret(kex.x25519_group, kp.secret[0..32], kp.public[0..256], &ss));
    try testing.expectError(error.MissingKeyShare, kex.sharedSecret(kex.secp256r1_group, kp.secret[0..32], kp.public[0..256], &ss));
}
