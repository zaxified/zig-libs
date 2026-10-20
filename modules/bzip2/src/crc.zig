// SPDX-License-Identifier: MIT

//! bzip2's CRC-32: the AUTODIN-II / Ethernet polynomial 0x04c11db7 run
//! most-significant-bit first (not the reflected CRC-32 of zlib and ZIP),
//! initial value 0xffffffff, result complemented. Slicing-by-8 for runs of
//! bytes; the stream's combined CRC is `rotl(combined, 1) ^ block_crc`.

const std = @import("std");

const tables: [8][256]u32 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [8][256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = @as(u32, @intCast(i)) << 24;
        for (0..8) |_| c = if (c & 0x8000_0000 != 0) (c << 1) ^ 0x04c1_1db7 else c << 1;
        t[0][i] = c;
    }
    for (1..8) |k| for (0..256) |i| {
        const p = t[k - 1][i];
        t[k][i] = (p << 8) ^ t[0][p >> 24];
    };
    break :blk t;
};

pub const init: u32 = 0xffff_ffff;

pub inline fn finalize(crc: u32) u32 {
    return ~crc;
}

pub inline fn updateByte(crc: u32, b: u8) u32 {
    return (crc << 8) ^ tables[0][(crc >> 24) ^ b];
}

pub fn update(crc_in: u32, data: []const u8) u32 {
    var crc = crc_in;
    var d = data;
    while (d.len >= 8) {
        const x = crc ^ std.mem.readInt(u32, d[0..4], .big);
        const y = std.mem.readInt(u32, d[4..8], .big);
        crc = tables[7][x >> 24] ^ tables[6][(x >> 16) & 0xff] ^ tables[5][(x >> 8) & 0xff] ^ tables[4][x & 0xff] ^
            tables[3][y >> 24] ^ tables[2][(y >> 16) & 0xff] ^ tables[1][(y >> 8) & 0xff] ^ tables[0][y & 0xff];
        d = d[8..];
    }
    for (d) |b| crc = updateByte(crc, b);
    return crc;
}

pub fn updateRun(crc_in: u32, b: u8, n: usize) u32 {
    var crc = crc_in;
    for (0..n) |_| crc = updateByte(crc, b);
    return crc;
}

/// The stream CRC folds each block CRC in as `rotl(combined, 1) ^ block`.
pub inline fn combine(combined: u32, block_crc: u32) u32 {
    return std.math.rotl(u32, combined, 1) ^ block_crc;
}

test "CRC of '123456789' is the CRC-32/BZIP2 check value 0xFC891918" {
    try std.testing.expectEqual(@as(u32, 0xfc89_1918), finalize(update(init, "123456789")));
}

test "slicing-by-8 agrees with the bytewise update at every length" {
    var buf: [100]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    for (0..buf.len + 1) |n| {
        var slow = init;
        for (buf[0..n]) |b| slow = updateByte(slow, b);
        try std.testing.expectEqual(slow, update(init, buf[0..n]));
    }
}
