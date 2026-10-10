// SPDX-License-Identifier: MIT

//! A textbook AES-192 written straight from FIPS-197 §5 — byte state,
//! S-box table, xtime MixColumns, the plain (not equivalent) inverse cipher
//! — as the fuzz harness's differential model. It shares nothing with the
//! module but the standard: its own key expansion, its own rounds, its own
//! S-box lookup. Not constant time and never shipped (test file only).
//!
//! The S-box is transcribed from FIPS-197 (2023 update, Table 4) and was
//! checked, when transcribed, against the algebraic definition of §5.1.1
//! (multiplicative inverse in GF(2^8) followed by the affine map with 0x63)
//! for all 256 entries; `test "model S-box ..."` below repeats that check.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

/// FIPS-197 Table 4, SBOX(xy) at index 16*x + y.
pub const sbox = [256]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

const inv_sbox = blk: {
    var t: [256]u8 = undefined;
    for (sbox, 0..) |s, i| t[s] = @intCast(i);
    break :blk t;
};

fn xtime(b: u8) u8 {
    return (b << 1) ^ (if (b & 0x80 != 0) @as(u8, 0x1b) else 0);
}

fn gmul(a: u8, b: u8) u8 {
    var p: u8 = 0;
    var x = a;
    var y = b;
    while (y != 0) : (y >>= 1) {
        if (y & 1 != 0) p ^= x;
        x = xtime(x);
    }
    return p;
}

/// KEYEXPANSION() for Nk = 6, FIPS-197 Algorithm 2: 52 words, as bytes.
pub fn expandKey(key: *const [24]u8) [52][4]u8 {
    var w: [52][4]u8 = undefined;
    for (0..6) |i| w[i] = key[4 * i ..][0..4].*;
    var rc: u8 = 1;
    for (6..52) |i| {
        var t = w[i - 1];
        if (i % 6 == 0) {
            // Through a temporary: `t = .{ ..t[0].. }` would read t[0]
            // after the result location had already overwritten it.
            const sub = [4]u8{ sbox[t[1]] ^ rc, sbox[t[2]], sbox[t[3]], sbox[t[0]] };
            t = sub;
            rc = xtime(rc);
        }
        for (0..4) |j| w[i][j] = w[i - 6][j] ^ t[j];
    }
    return w;
}

fn addRoundKey(s: *[16]u8, w: *const [52][4]u8, round: usize) void {
    for (0..4) |c| for (0..4) |r| {
        s[4 * c + r] ^= w[4 * round + c][r];
    };
}

/// CIPHER(), FIPS-197 Algorithm 1. State byte (r, c) is `s[r + 4c]`.
pub fn encrypt(key: *const [24]u8, in: *const [16]u8) [16]u8 {
    const w = expandKey(key);
    var s = in.*;
    addRoundKey(&s, &w, 0);
    for (1..13) |round| {
        for (&s) |*b| b.* = sbox[b.*];
        var t: [16]u8 = undefined; // ShiftRows: row r rotates left by r
        for (0..4) |r| for (0..4) |c| {
            t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
        };
        s = t;
        if (round != 12) for (0..4) |c| {
            const a = s[4 * c ..][0..4].*;
            s[4 * c + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
            s[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
            s[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
            s[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
        };
        addRoundKey(&s, &w, round);
    }
    return s;
}

/// INVCIPHER(), FIPS-197 Algorithm 3 (the plain inverse, not §5.3.5's
/// equivalent one the module uses — so the two decrypt paths differ in shape).
pub fn decrypt(key: *const [24]u8, in: *const [16]u8) [16]u8 {
    const w = expandKey(key);
    var s = in.*;
    addRoundKey(&s, &w, 12);
    var round: usize = 11;
    while (true) : (round -= 1) {
        var t: [16]u8 = undefined; // InvShiftRows
        for (0..4) |r| for (0..4) |c| {
            t[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
        };
        s = t;
        for (&s) |*b| b.* = inv_sbox[b.*];
        addRoundKey(&s, &w, round);
        if (round == 0) break;
        for (0..4) |c| {
            const a = s[4 * c ..][0..4].*;
            s[4 * c + 0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
            s[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
            s[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
            s[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
        }
    }
    return s;
}

test "model S-box is the algebraic one: inverse in GF(2^8), then the 0x63 affine map" {
    for (0..256) |x| {
        const v: u8 = @intCast(x);
        var inv: u8 = 0;
        if (v != 0) {
            for (1..256) |y| if (gmul(v, @intCast(y)) == 1) {
                inv = @intCast(y);
            };
        }
        const aff = inv ^ std.math.rotl(u8, inv, 1) ^ std.math.rotl(u8, inv, 2) ^
            std.math.rotl(u8, inv, 3) ^ std.math.rotl(u8, inv, 4) ^ 0x63;
        try testing.expectEqual(aff, sbox[v]);
    }
}

test "model reproduces FIPS-197 Appendix C.2 and A.2 (it is anchored before it judges)" {
    var key: [24]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    var pt: [16]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @intCast(i * 0x11);
    var ct: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ct, "dda97ca4864cdfe06eaf70a0ec0d7191");
    try testing.expectEqual(ct, encrypt(&key, &pt));
    try testing.expectEqual(pt, decrypt(&key, &ct));
    var k2: [24]u8 = undefined;
    _ = try std.fmt.hexToBytes(&k2, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    try testing.expectEqual([4]u8{ 0x01, 0x00, 0x22, 0x02 }, expandKey(&k2)[51]);
}

test "module agrees with the model on 2000 derived keys and blocks, schedule included" {
    var prng = std.Random.DefaultPrng.init(0xae5192);
    const r = prng.random();
    for (0..2000) |_| {
        var key: [24]u8 = undefined;
        var pt: [16]u8 = undefined;
        r.bytes(&key);
        r.bytes(&pt);
        const enc = root.Aes192.initEnc(key);
        const w = expandKey(&key);
        for (enc.key_schedule.round_keys, 0..) |rk, i|
            try testing.expectEqualSlices(u8, std.mem.asBytes(w[4 * i ..][0..4]), &rk.toBytes());
        var ct: [16]u8 = undefined;
        enc.encrypt(&ct, &pt);
        try testing.expectEqual(encrypt(&key, &pt), ct);
        var back: [16]u8 = undefined;
        root.Aes192.initDec(key).decrypt(&back, &ct);
        try testing.expectEqual(pt, back);
        try testing.expectEqual(decrypt(&key, &pt), blk: {
            var o: [16]u8 = undefined;
            root.Aes192.initDec(key).decrypt(&o, &pt);
            break :blk o;
        });
    }
}
