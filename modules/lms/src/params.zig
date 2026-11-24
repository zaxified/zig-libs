// SPDX-License-Identifier: MIT
//! RFC 8554 parameter sets (§3.2, §4.1 Table 1, §5.1 Table 2, Appendix B) and
//! RFC 9858's additional ones (SHA-256/192, SHAKE256/256, SHAKE256/192;
//! Table 1 LM-OTS typecodes 5..16, Table 2 LMS typecodes 10..24).

const std = @import("std");

/// The hash a parameter set uses (RFC 8554 §3.2 `H`; RFC 9858 §2): SHA-256
/// (truncated to 192 bits for the N24/M24 sets, FIPS 180-4 §7) or SHAKE256
/// (its first 24 or 32 output bytes).
pub const Hash = enum {
    sha256,
    shake256,
};

/// A parameter set's hash and output length `n` (LM-OTS) / `m` (LMS) in bytes.
pub const HashFn = struct {
    hash: Hash,
    /// 24 or 32.
    len: u8,
};

/// Storage width of every hash value, seed and node in this module: the
/// largest `n`/`m` (32). A 24-byte set uses the first 24 bytes; the rest is
/// zero. A SEED for a 24-byte set is the first 24 bytes of the 32 passed in.
pub const n = 32;
/// Bytes of the LMS key-pair identifier `I` (§3.3, §7.1; 16 for every set,
/// RFC 9858 §5).
pub const id_len = 16;
/// Highest number of HSS levels (§6: "between one and eight, inclusive").
pub const max_levels = 8;

/// LM-OTS typecodes (§3.3 `lmots_algorithm_type`, RFC 9858 Table 1;
/// `lmots_reserved = 0` is not a member, so a zero typecode fails to convert).
pub const OtsParamSet = enum(u32) {
    sha256_n32_w1 = 1,
    sha256_n32_w2 = 2,
    sha256_n32_w4 = 3,
    sha256_n32_w8 = 4,
    sha256_n24_w1 = 5,
    sha256_n24_w2 = 6,
    sha256_n24_w4 = 7,
    sha256_n24_w8 = 8,
    shake_n32_w1 = 9,
    shake_n32_w2 = 10,
    shake_n32_w4 = 11,
    shake_n32_w8 = 12,
    shake_n24_w1 = 13,
    shake_n24_w2 = 14,
    shake_n24_w4 = 15,
    shake_n24_w8 = 16,

    pub fn fromTypecode(code: u32) ?OtsParamSet {
        return std.enums.fromInt(OtsParamSet, code);
    }

    pub fn typecode(self: OtsParamSet) u32 {
        return @backingInt(self);
    }

    /// Typecodes come in groups of four (W1, W2, W4, W8) per hash and `n`.
    fn group(self: OtsParamSet) u32 {
        return (self.typecode() - 1) / 4;
    }

    pub fn hashFn(self: OtsParamSet) HashFn {
        return switch (self.group()) {
            0 => .{ .hash = .sha256, .len = 32 },
            1 => .{ .hash = .sha256, .len = 24 },
            2 => .{ .hash = .shake256, .len = 32 },
            else => .{ .hash = .shake256, .len = 24 },
        };
    }

    /// `n`: hash output length in bytes.
    pub fn nLen(self: OtsParamSet) u8 {
        return self.hashFn().len;
    }

    /// Winternitz width in bits.
    pub fn w(self: OtsParamSet) u4 {
        return switch ((self.typecode() - 1) % 4) {
            0 => 1,
            1 => 2,
            2 => 4,
            else => 8,
        };
    }

    /// `p`: number of n-byte strings in an LM-OTS signature / private key,
    /// `u + v` of Appendix B (RFC 8554 Table 1 / Table 6, RFC 9858 Table 1).
    pub fn p(self: OtsParamSet) u16 {
        const n32 = self.nLen() == 32;
        return switch (self.w()) {
            1 => if (n32) 265 else 200,
            2 => if (n32) 133 else 101,
            4 => if (n32) 67 else 51,
            else => if (n32) 34 else 26,
        };
    }

    /// `ls`: left shift of the checksum (Appendix B: `16 - v*w`).
    pub fn ls(self: OtsParamSet) u4 {
        const n32 = self.nLen() == 32;
        return switch (self.w()) {
            1 => if (n32) 7 else 8,
            2 => 6,
            4 => 4,
            else => 0,
        };
    }

    /// LM-OTS signature length: `4 + n * (p + 1)` bytes (§4.1).
    pub fn sigLen(self: OtsParamSet) usize {
        return 4 + @as(usize, self.nLen()) * (@as(usize, self.p()) + 1);
    }
};

/// LMS typecodes (§3.3 `lms_algorithm_type`, RFC 9858 Table 2).
pub const ParamSet = enum(u32) {
    sha256_m32_h5 = 5,
    sha256_m32_h10 = 6,
    sha256_m32_h15 = 7,
    sha256_m32_h20 = 8,
    sha256_m32_h25 = 9,
    sha256_m24_h5 = 10,
    sha256_m24_h10 = 11,
    sha256_m24_h15 = 12,
    sha256_m24_h20 = 13,
    sha256_m24_h25 = 14,
    shake_m32_h5 = 15,
    shake_m32_h10 = 16,
    shake_m32_h15 = 17,
    shake_m32_h20 = 18,
    shake_m32_h25 = 19,
    shake_m24_h5 = 20,
    shake_m24_h10 = 21,
    shake_m24_h15 = 22,
    shake_m24_h20 = 23,
    shake_m24_h25 = 24,

    pub fn fromTypecode(code: u32) ?ParamSet {
        return std.enums.fromInt(ParamSet, code);
    }

    pub fn typecode(self: ParamSet) u32 {
        return @backingInt(self);
    }

    pub fn hashFn(self: ParamSet) HashFn {
        return switch ((self.typecode() - 5) / 5) {
            0 => .{ .hash = .sha256, .len = 32 },
            1 => .{ .hash = .sha256, .len = 24 },
            2 => .{ .hash = .shake256, .len = 32 },
            else => .{ .hash = .shake256, .len = 24 },
        };
    }

    /// `m`: hash output length in bytes (the size of a tree node).
    pub fn mLen(self: ParamSet) u8 {
        return self.hashFn().len;
    }

    /// Tree height `h`; the tree has `2^h` leaves.
    pub fn height(self: ParamSet) u5 {
        return @intCast(5 * ((self.typecode() - 5) % 5 + 1));
    }

    /// Number of one-time keys (`2^h`).
    pub fn leaves(self: ParamSet) u32 {
        return @as(u32, 1) << self.height();
    }

    /// Whether `ots` uses the same hash and length: the only pairing this
    /// module accepts in a key (one `H` per LMS key, RFC 9858 §5).
    pub fn matches(self: ParamSet, ots: OtsParamSet) bool {
        const a = self.hashFn();
        const b = ots.hashFn();
        return a.hash == b.hash and a.len == b.len;
    }
};

/// One level of an HSS hierarchy: the LMS tree height and its LM-OTS set.
pub const Level = struct {
    lms: ParamSet,
    ots: OtsParamSet,
};

test "Table 1 / Table 6 / RFC 9858 Table 1: p and ls follow Appendix B from n and w" {
    // u = ceil(8n/w), v = ceil((floor(lg((2^w - 1) * u)) + 1) / w),
    // ls = 16 - v*w, p = u + v.
    for (std.enums.values(OtsParamSet)) |set| {
        const wd: u32 = set.w();
        const nb: u32 = set.nLen();
        const u = (8 * nb + wd - 1) / wd;
        const prod: u32 = ((@as(u32, 1) << @intCast(wd)) - 1) * u;
        const v = (std.math.log2_int(u32, prod) + 1 + wd - 1) / wd;
        try std.testing.expectEqual(16 - v * wd, set.ls());
        try std.testing.expectEqual(u + v, set.p());
    }
    try std.testing.expectEqual(@as(usize, 8516), OtsParamSet.sha256_n32_w1.sigLen());
    try std.testing.expectEqual(@as(usize, 4292), OtsParamSet.sha256_n32_w2.sigLen());
    try std.testing.expectEqual(@as(usize, 2180), OtsParamSet.sha256_n32_w4.sigLen());
    try std.testing.expectEqual(@as(usize, 1124), OtsParamSet.sha256_n32_w8.sigLen());
    // RFC 9858 Table 1 rows, as printed.
    try std.testing.expectEqual(@as(u16, 200), OtsParamSet.sha256_n24_w1.p());
    try std.testing.expectEqual(@as(u4, 8), OtsParamSet.shake_n24_w1.ls());
    try std.testing.expectEqual(@as(u16, 26), OtsParamSet.shake_n24_w8.p());
    try std.testing.expectEqual(@as(u16, 133), OtsParamSet.shake_n32_w2.p());
}

test "typecodes: RFC 8554 and RFC 9858 assignments, hash, length and height" {
    try std.testing.expect(OtsParamSet.fromTypecode(0) == null);
    try std.testing.expect(OtsParamSet.fromTypecode(17) == null);
    try std.testing.expect(ParamSet.fromTypecode(0) == null);
    try std.testing.expect(ParamSet.fromTypecode(4) == null);
    try std.testing.expect(ParamSet.fromTypecode(25) == null);
    try std.testing.expectEqual(ParamSet.sha256_m32_h10, ParamSet.fromTypecode(6).?);
    try std.testing.expectEqual(@as(u32, 1 << 25), ParamSet.sha256_m32_h25.leaves());
    // RFC 9858 Table 2.
    try std.testing.expectEqual(ParamSet.sha256_m24_h5, ParamSet.fromTypecode(0x0a).?);
    try std.testing.expectEqual(ParamSet.shake_m32_h25, ParamSet.fromTypecode(0x13).?);
    try std.testing.expectEqual(ParamSet.shake_m24_h25, ParamSet.fromTypecode(0x18).?);
    try std.testing.expectEqual(@as(u5, 25), ParamSet.shake_m24_h25.height());
    try std.testing.expectEqual(@as(u5, 15), ParamSet.sha256_m24_h15.height());
    try std.testing.expectEqual(@as(u8, 24), ParamSet.shake_m24_h10.mLen());
    try std.testing.expectEqual(Hash.shake256, ParamSet.shake_m32_h5.hashFn().hash);
    // RFC 9858 Table 1.
    try std.testing.expectEqual(OtsParamSet.sha256_n24_w8, OtsParamSet.fromTypecode(8).?);
    try std.testing.expectEqual(OtsParamSet.shake_n32_w1, OtsParamSet.fromTypecode(9).?);
    try std.testing.expectEqual(OtsParamSet.shake_n24_w8, OtsParamSet.fromTypecode(0x10).?);
    try std.testing.expectEqual(@as(u4, 8), OtsParamSet.shake_n24_w8.w());
    try std.testing.expect(ParamSet.sha256_m24_h5.matches(.sha256_n24_w4));
    try std.testing.expect(!ParamSet.sha256_m24_h5.matches(.shake_n24_w4));
    try std.testing.expect(!ParamSet.sha256_m32_h5.matches(.sha256_n24_w4));
}
