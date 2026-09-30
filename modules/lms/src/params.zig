// SPDX-License-Identifier: MIT
//! RFC 8554 parameter sets (§3.2, §4.1 Table 1, §5.1 Table 2, Appendix B).
//!
//! Only the SHA-256, n = m = 32 sets have IANA typecodes in RFC 8554 itself;
//! every other typecode (SHA-256/192, SHAKE — SP 800-208, RFC 9858) is an
//! unsupported typecode here and rejected by the wire parsers.

const std = @import("std");

/// Hash output length in bytes: `n` for LM-OTS, `m` for LMS. Both are 32 for
/// every set this module supports.
pub const n = 32;
/// Bytes of the LMS key-pair identifier `I` (§3.3, §7.1).
pub const id_len = 16;
/// Highest number of HSS levels (§6: "between one and eight, inclusive").
pub const max_levels = 8;

/// LM-OTS typecodes (§3.3 `lmots_algorithm_type`; `lmots_reserved = 0` is not
/// a member, so a zero typecode fails to convert).
pub const OtsParamSet = enum(u32) {
    sha256_n32_w1 = 1,
    sha256_n32_w2 = 2,
    sha256_n32_w4 = 3,
    sha256_n32_w8 = 4,

    pub fn fromTypecode(code: u32) ?OtsParamSet {
        return std.enums.fromInt(OtsParamSet, code);
    }

    pub fn typecode(self: OtsParamSet) u32 {
        return @intFromEnum(self);
    }

    /// Winternitz width in bits.
    pub fn w(self: OtsParamSet) u4 {
        return switch (self) {
            .sha256_n32_w1 => 1,
            .sha256_n32_w2 => 2,
            .sha256_n32_w4 => 4,
            .sha256_n32_w8 => 8,
        };
    }

    /// `p`: number of n-byte strings in an LM-OTS signature / private key,
    /// `u + v` of Appendix B (Table 1 / Table 6).
    pub fn p(self: OtsParamSet) u16 {
        return switch (self) {
            .sha256_n32_w1 => 265,
            .sha256_n32_w2 => 133,
            .sha256_n32_w4 => 67,
            .sha256_n32_w8 => 34,
        };
    }

    /// `ls`: left shift of the checksum (Appendix B: `16 - v*w`).
    pub fn ls(self: OtsParamSet) u4 {
        return switch (self) {
            .sha256_n32_w1 => 7,
            .sha256_n32_w2 => 6,
            .sha256_n32_w4 => 4,
            .sha256_n32_w8 => 0,
        };
    }

    /// LM-OTS signature length: `4 + n * (p + 1)` bytes (§4.1).
    pub fn sigLen(self: OtsParamSet) usize {
        return 4 + n * (@as(usize, self.p()) + 1);
    }
};

/// LMS typecodes (§3.3 `lms_algorithm_type`).
pub const ParamSet = enum(u32) {
    sha256_m32_h5 = 5,
    sha256_m32_h10 = 6,
    sha256_m32_h15 = 7,
    sha256_m32_h20 = 8,
    sha256_m32_h25 = 9,

    pub fn fromTypecode(code: u32) ?ParamSet {
        return std.enums.fromInt(ParamSet, code);
    }

    pub fn typecode(self: ParamSet) u32 {
        return @intFromEnum(self);
    }

    /// Tree height `h`; the tree has `2^h` leaves.
    pub fn height(self: ParamSet) u5 {
        return switch (self) {
            .sha256_m32_h5 => 5,
            .sha256_m32_h10 => 10,
            .sha256_m32_h15 => 15,
            .sha256_m32_h20 => 20,
            .sha256_m32_h25 => 25,
        };
    }

    /// Number of one-time keys (`2^h`).
    pub fn leaves(self: ParamSet) u32 {
        return @as(u32, 1) << self.height();
    }
};

/// One level of an HSS hierarchy: the LMS tree height and its LM-OTS set.
pub const Level = struct {
    lms: ParamSet,
    ots: OtsParamSet,
};

test "Table 1 / Table 6: p and ls follow Appendix B from w" {
    // u = ceil(8n/w), v = ceil((floor(lg((2^w - 1) * u)) + 1) / w),
    // ls = 16 - v*w, p = u + v.
    inline for (.{ .sha256_n32_w1, .sha256_n32_w2, .sha256_n32_w4, .sha256_n32_w8 }) |o| {
        const set: OtsParamSet = o;
        const wd: u32 = set.w();
        const u = (8 * n + wd - 1) / wd;
        const prod: u32 = ((@as(u32, 1) << @intCast(wd)) - 1) * u;
        const v = (std.math.log2_int(u32, prod) + 1 + wd - 1) / wd;
        try std.testing.expectEqual(16 - v * wd, set.ls());
        try std.testing.expectEqual(u + v, set.p());
    }
    try std.testing.expectEqual(@as(usize, 8516), OtsParamSet.sha256_n32_w1.sigLen());
    try std.testing.expectEqual(@as(usize, 4292), OtsParamSet.sha256_n32_w2.sigLen());
    try std.testing.expectEqual(@as(usize, 2180), OtsParamSet.sha256_n32_w4.sigLen());
    try std.testing.expectEqual(@as(usize, 1124), OtsParamSet.sha256_n32_w8.sigLen());
}

test "typecode 0 and unassigned codes are not parameter sets" {
    try std.testing.expect(OtsParamSet.fromTypecode(0) == null);
    try std.testing.expect(OtsParamSet.fromTypecode(5) == null);
    try std.testing.expect(ParamSet.fromTypecode(0) == null);
    try std.testing.expect(ParamSet.fromTypecode(4) == null);
    try std.testing.expect(ParamSet.fromTypecode(10) == null);
    try std.testing.expectEqual(ParamSet.sha256_m32_h10, ParamSet.fromTypecode(6).?);
    try std.testing.expectEqual(@as(u32, 1 << 25), ParamSet.sha256_m32_h25.leaves());
}
