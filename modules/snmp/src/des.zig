// SPDX-License-Identifier: MIT

//! DES (FIPS 46-3) block cipher + CBC chaining, from scratch — the cipher SNMP
//! USM privacy needs (`usmDESPrivProtocol`, RFC 3414 §8). Zig std ships AES but
//! no DES and no CBC/CFB modes, so this is a clean-room implementation of the
//! FIPS 46-3 permutation/S-box tables plus the CBC mode from RFC 3414 §8.1.
//!
//! DES is legacy and cryptographically weak (56-bit key); it exists here only
//! because deployed SNMPv3 agents still negotiate `usmDESPrivProtocol`. Prefer
//! AES-128-CFB (`priv.zig`) for anything new.
//!
//! Provenance: clean-room from FIPS PUB 46-3 (the permutation tables, S-boxes,
//! and key schedule are the published standard constants) and RFC 3414 §8.1
//! (CBC use + key/IV derivation, handled in `priv.zig`). No source consulted.

const std = @import("std");

// ── FIPS 46-3 constant tables (1-indexed bit positions, counted from the MSB) ─

/// Initial Permutation (IP): 64 → 64 bits.
const ip_table = [64]u8{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

/// Final Permutation (IP^-1 / FP): 64 → 64 bits.
const fp_table = [64]u8{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25,
};

/// Expansion (E): 32 → 48 bits.
const e_table = [48]u8{
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

/// Permutation (P) inside the round function: 32 → 32 bits.
const p_table = [32]u8{
    16, 7,  20, 21, 29, 12, 28, 17,
    1,  15, 23, 26, 5,  18, 31, 10,
    2,  8,  24, 14, 32, 27, 3,  9,
    19, 13, 30, 6,  22, 11, 4,  25,
};

/// Permuted Choice 1 (PC-1): 64-bit key → 56 bits (drops the 8 parity bits).
const pc1_table = [56]u8{
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4,
};

/// Permuted Choice 2 (PC-2): 56-bit C‖D → 48-bit round key.
const pc2_table = [48]u8{
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

/// Left-shift schedule for the 16 rounds of the key schedule.
const shifts = [16]u3{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

/// The eight S-boxes, each stored row-major as 64 entries indexed `row*16 + col`
/// (row = outer bits b1‖b6, col = inner bits b2 b3 b4 b5).
const sbox = [8][64]u8{
    .{
        14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
        0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
        4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
        15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13,
    },
    .{
        15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
        3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
        0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
        13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9,
    },
    .{
        10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
        13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
        13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
        1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12,
    },
    .{
        7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
        13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
        10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
        3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14,
    },
    .{
        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
        14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
        4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
        11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3,
    },
    .{
        12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
        10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
        9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
        4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13,
    },
    .{
        4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
        13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
        1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
        6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12,
    },
    .{
        13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
        1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
        7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
        2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11,
    },
};

/// Permute `input` (whose `in_bits` significant bits are numbered 1..in_bits
/// from the MSB) through `table`, producing `table.len` output bits packed into
/// the low bits of the result.
fn permute(input: u64, in_bits: u7, table: []const u8) u64 {
    var out: u64 = 0;
    for (table) |pos| {
        const shift: u6 = @intCast(in_bits - pos);
        out = (out << 1) | ((input >> shift) & 1);
    }
    return out;
}

fn rotl28(v: u32, n: u3) u32 {
    const mask: u32 = 0x0FFF_FFFF;
    const nn: u5 = n;
    return ((v << nn) | (v >> @intCast(28 - @as(u6, nn)))) & mask;
}

/// The DES round (Feistel) function f(R, K): expand R to 48 bits, mix the 48-bit
/// round key, substitute through the eight S-boxes, then permute with P.
fn feistel(r: u32, k: u48) u32 {
    const e: u48 = @intCast(permute(r, 32, &e_table));
    const x: u48 = e ^ k;
    var out: u32 = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast(42 - 6 * i);
        const six: u8 = @intCast((@as(u64, x) >> shift) & 0x3F);
        const row: u8 = (((six >> 5) & 1) << 1) | (six & 1);
        const col: u8 = (six >> 1) & 0x0F;
        out = (out << 4) | sbox[i][@as(usize, row) * 16 + col];
    }
    return @intCast(permute(out, 32, &p_table));
}

/// A DES cipher instance holding the 16 expanded 48-bit round keys.
pub const Des = struct {
    round_keys: [16]u48,

    /// Build the key schedule from an 8-byte key (parity bits are ignored, as in
    /// FIPS 46-3 — only PC-1's chosen 56 bits are used).
    pub fn init(key: [8]u8) Des {
        const k64 = std.mem.readInt(u64, &key, .big);
        const cd = permute(k64, 64, &pc1_table); // 56 bits
        var c: u32 = @intCast(cd >> 28);
        var d: u32 = @intCast(cd & 0x0FFF_FFFF);
        var rk: [16]u48 = undefined;
        for (0..16) |i| {
            c = rotl28(c, shifts[i]);
            d = rotl28(d, shifts[i]);
            const combined: u64 = (@as(u64, c) << 28) | d;
            rk[i] = @intCast(permute(combined, 56, &pc2_table));
        }
        return .{ .round_keys = rk };
    }

    fn crypt(self: Des, block: [8]u8, comptime decrypt: bool) [8]u8 {
        const b = std.mem.readInt(u64, &block, .big);
        const ip = permute(b, 64, &ip_table);
        var l: u32 = @intCast(ip >> 32);
        var r: u32 = @intCast(ip & 0xFFFF_FFFF);
        for (0..16) |round| {
            const k = self.round_keys[if (decrypt) 15 - round else round];
            const f = feistel(r, k);
            const nl = r;
            r = l ^ f;
            l = nl;
        }
        // Pre-output swaps the halves: R16 ‖ L16.
        const pre: u64 = (@as(u64, r) << 32) | l;
        const out = permute(pre, 64, &fp_table);
        var res: [8]u8 = undefined;
        std.mem.writeInt(u64, &res, out, .big);
        return res;
    }

    /// Encrypt a single 8-byte block.
    pub fn encryptBlock(self: Des, block: [8]u8) [8]u8 {
        return self.crypt(block, false);
    }

    /// Decrypt a single 8-byte block.
    pub fn decryptBlock(self: Des, block: [8]u8) [8]u8 {
        return self.crypt(block, true);
    }
};

pub const block_len = 8;

pub const CbcError = error{
    /// Ciphertext length was not a positive multiple of the 8-byte block size.
    InvalidLength,
    /// Plaintext to encrypt was not a multiple of the block size (the caller
    /// must pad first — RFC 3414 §8.1.1.2).
    NotPadded,
    /// `out` was too small for the result.
    BufferTooSmall,
};

/// DES-CBC encrypt `plaintext` (which must already be a multiple of 8 bytes)
/// under `key` with the 8-byte `iv`, writing to `out` and returning the written
/// slice. `out` must be at least `plaintext.len`.
pub fn cbcEncrypt(key: [8]u8, iv: [8]u8, plaintext: []const u8, out: []u8) CbcError![]u8 {
    if (plaintext.len % block_len != 0) return error.NotPadded;
    if (out.len < plaintext.len) return error.BufferTooSmall;
    const des = Des.init(key);
    var prev = iv;
    var i: usize = 0;
    while (i < plaintext.len) : (i += block_len) {
        var blk: [block_len]u8 = plaintext[i..][0..block_len].*;
        for (&blk, prev) |*b, p| b.* ^= p;
        const ct = des.encryptBlock(blk);
        @memcpy(out[i..][0..block_len], &ct);
        prev = ct;
    }
    return out[0..plaintext.len];
}

/// DES-CBC decrypt `ciphertext` (which must be a positive multiple of 8 bytes)
/// under `key` with the 8-byte `iv`, writing to `out` and returning the written
/// slice. No un-padding is performed (the caller's BER length delimits the
/// payload; RFC 3414 leaves the pad value undefined). `out` must be at least
/// `ciphertext.len`.
pub fn cbcDecrypt(key: [8]u8, iv: [8]u8, ciphertext: []const u8, out: []u8) CbcError![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % block_len != 0) return error.InvalidLength;
    if (out.len < ciphertext.len) return error.BufferTooSmall;
    const des = Des.init(key);
    var prev = iv;
    var i: usize = 0;
    while (i < ciphertext.len) : (i += block_len) {
        const ct: [block_len]u8 = ciphertext[i..][0..block_len].*;
        var pt = des.decryptBlock(ct);
        for (&pt, prev) |*b, p| b.* ^= p;
        @memcpy(out[i..][0..block_len], &pt);
        prev = ct;
    }
    return out[0..ciphertext.len];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "FIPS 46-3 single-block KAT" {
    // The classic FIPS 46-3 / FIPS 81 known-answer vector.
    const key = [8]u8{ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    const pt = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const expect_ct = [8]u8{ 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

    const des = Des.init(key);
    const ct = des.encryptBlock(pt);
    try testing.expectEqualSlices(u8, &expect_ct, &ct);

    // Decrypt is the inverse.
    const back = des.decryptBlock(ct);
    try testing.expectEqualSlices(u8, &pt, &back);
}

test "DES all-zero key/plaintext KAT" {
    // Independent vector: key=0, plaintext=0 → 8CA64DE9C1B123A7 (well-known).
    const des = Des.init(.{0} ** 8);
    const ct = des.encryptBlock(.{0} ** 8);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7,
    }, &ct);
}

test "DES single-block encrypt/decrypt round-trip over many blocks" {
    const key = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const des = Des.init(key);
    var blk: [8]u8 = undefined;
    for (0..256) |seed| {
        for (&blk, 0..) |*b, j| b.* = @intCast((seed *% 7 +% j *% 31) & 0xFF);
        const ct = des.encryptBlock(blk);
        const back = des.decryptBlock(ct);
        try testing.expectEqualSlices(u8, &blk, &back);
    }
}

test "DES-CBC multi-block round-trip" {
    const key = [8]u8{ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    const iv = [8]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    var pt: [64]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @intCast(i);
    var ct_buf: [64]u8 = undefined;
    var back_buf: [64]u8 = undefined;
    const ct = try cbcEncrypt(key, iv, &pt, &ct_buf);
    const back = try cbcDecrypt(key, iv, ct, &back_buf);
    try testing.expectEqualSlices(u8, &pt, back);
    // CBC diffuses: identical plaintext blocks must not yield identical
    // ciphertext blocks.
    try testing.expect(!std.mem.eql(u8, ct[0..8], ct[8..16]) or !std.mem.eql(u8, pt[0..8], pt[8..16]));
}

test "DES-CBC rejects non-block-aligned lengths" {
    var buf: [16]u8 = undefined;
    try testing.expectError(error.InvalidLength, cbcDecrypt(.{0} ** 8, .{0} ** 8, &.{}, &buf));
    try testing.expectError(error.InvalidLength, cbcDecrypt(.{0} ** 8, .{0} ** 8, &[_]u8{0} ** 7, &buf));
    try testing.expectError(error.NotPadded, cbcEncrypt(.{0} ** 8, .{0} ** 8, &[_]u8{0} ** 7, &buf));
}

test "DES-CBC one block equals raw block XOR IV" {
    // With a single block, CBC = ECB(P XOR IV).
    const key = [8]u8{ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    const iv = [8]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
    const pt = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const des = Des.init(key);
    var xored = pt;
    for (&xored, iv) |*b, v| b.* ^= v;
    const expect = des.encryptBlock(xored);
    var out: [8]u8 = undefined;
    const ct = try cbcEncrypt(key, iv, &pt, &out);
    try testing.expectEqualSlices(u8, &expect, ct);
}
