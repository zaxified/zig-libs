// SPDX-License-Identifier: MIT
//! params — SLH-DSA (FIPS 205) parameter sets.
//!
//! All twelve FIPS 205 Table 2 rows: SLH-DSA-SHA2-{128,192,256}{s,f} and
//! SLH-DSA-SHAKE-{128,192,256}{s,f}. `engine.SlhDsa` implements both §11
//! hash instantiations, so every row here is usable end-to-end.

const std = @import("std");

/// Which §11 hash instantiation a parameter set uses.
pub const HashFamily = enum {
    /// FIPS 205 §11.2 — SHA-2 family: SHA-256 throughout for security
    /// category 1 (§11.2.1); categories 3/5 keep SHA-256 for F/PRF but use
    /// SHA-512 for H/T_l/H_msg/PRF_msg (§11.2.2).
    sha2,
    /// FIPS 205 §11.1 — SHAKE256 for every function, full 32-byte ADRS.
    shake,
};

/// One FIPS 205 Table 2 row. All lengths in bytes unless noted.
pub const Params = struct {
    /// Parameter-set name as FIPS 205 spells it, e.g. "SLH-DSA-SHA2-128f".
    name: []const u8,
    hash: HashFamily,
    /// Security parameter n — hash output / seed length.
    n: usize,
    /// Total hypertree height h (bits of leaf index).
    h: usize,
    /// Number of XMSS layers d in the hypertree.
    d: usize,
    /// Height h' = h/d of each XMSS tree.
    hp: usize,
    /// Height a of each FORS tree (indices are a-bit values).
    a: usize,
    /// Number k of FORS trees.
    k: usize,
    /// WOTS+ Winternitz log2(w); FIPS 205 fixes lg_w = 4 for all sets.
    lg_w: usize,
    /// H_msg digest length m = ceil(k*a/8) + ceil((h-h/d)/8) + ceil(h/8d).
    m: usize,

    /// WOTS+ w = 2^lg_w.
    pub fn w(comptime p: Params) usize {
        return 1 << p.lg_w;
    }

    /// WOTS+ len1 = ceil(8n / lg_w) — message-hash chains.
    pub fn len1(comptime p: Params) usize {
        return std.math.divCeil(usize, 8 * p.n, p.lg_w) catch unreachable;
    }

    /// WOTS+ len2 = floor(log2(len1 * (w-1)) / lg_w) + 1 — checksum chains.
    pub fn len2(comptime p: Params) usize {
        return std.math.log2(p.len1() * (p.w() - 1)) / p.lg_w + 1;
    }

    /// WOTS+ len = len1 + len2 — total chains per one-time key.
    pub fn wotsLen(comptime p: Params) usize {
        return p.len1() + p.len2();
    }

    /// ceil(k*a/8) — FORS message-digest slice length within H_msg output.
    pub fn mdLen(comptime p: Params) usize {
        return (p.k * p.a + 7) / 8;
    }

    /// ceil((h - h/d)/8) — tree-index slice length within H_msg output.
    pub fn idxTreeLen(comptime p: Params) usize {
        return (p.h - p.hp + 7) / 8;
    }

    /// ceil(h/8d) — leaf-index slice length within H_msg output.
    pub fn idxLeafLen(comptime p: Params) usize {
        return (p.hp + 7) / 8;
    }

    /// Total signature length (1 + k(1+a) + h + d*len) * n.
    pub fn sigLen(comptime p: Params) usize {
        return (1 + p.k * (1 + p.a) + p.h + p.d * p.wotsLen()) * p.n;
    }

    /// Compile-time consistency checks (Table 2 internal relations).
    pub fn validate(comptime p: Params) void {
        if (p.n != 16 and p.n != 24 and p.n != 32)
            @compileError("params: FIPS 205 defines only n = 16, 24, 32");
        if (p.hp * p.d != p.h) @compileError("params: h' * d must equal h");
        if (p.m != p.mdLen() + p.idxTreeLen() + p.idxLeafLen())
            @compileError("params: m must match its three digest slices");
        if (p.h - p.hp > 64) @compileError("params: tree index must fit u64");
        if (p.lg_w != 4) @compileError("params: FIPS 205 fixes lg_w = 4");
    }
};

/// The six Table 2 numeric rows (shared by the SHA2 and SHAKE families).
fn tableRow(
    comptime name: []const u8,
    comptime hash: HashFamily,
    comptime n: usize,
    comptime h: usize,
    comptime d: usize,
    comptime hp: usize,
    comptime a: usize,
    comptime k: usize,
    comptime m: usize,
) Params {
    return .{
        .name = name,
        .hash = hash,
        .n = n,
        .h = h,
        .d = d,
        .hp = hp,
        .a = a,
        .k = k,
        .lg_w = 4,
        .m = m,
    };
}

// FIPS 205 Table 2, all twelve parameter sets. "s" = small signature /
// slow signing, "f" = fast signing / large signature. pk = 2n, sk = 4n.

/// SLH-DSA-SHA2-128s: category 1, pk 32 B, sk 64 B, sig 7 856 B.
pub const sha2_128s: Params = tableRow("SLH-DSA-SHA2-128s", .sha2, 16, 63, 7, 9, 12, 14, 30);
/// SLH-DSA-SHA2-128f: category 1, pk 32 B, sk 64 B, sig 17 088 B.
pub const sha2_128f: Params = tableRow("SLH-DSA-SHA2-128f", .sha2, 16, 66, 22, 3, 6, 33, 34);
/// SLH-DSA-SHA2-192s: category 3, pk 48 B, sk 96 B, sig 16 224 B.
pub const sha2_192s: Params = tableRow("SLH-DSA-SHA2-192s", .sha2, 24, 63, 7, 9, 14, 17, 39);
/// SLH-DSA-SHA2-192f: category 3, pk 48 B, sk 96 B, sig 35 664 B.
pub const sha2_192f: Params = tableRow("SLH-DSA-SHA2-192f", .sha2, 24, 66, 22, 3, 8, 33, 42);
/// SLH-DSA-SHA2-256s: category 5, pk 64 B, sk 128 B, sig 29 792 B.
pub const sha2_256s: Params = tableRow("SLH-DSA-SHA2-256s", .sha2, 32, 64, 8, 8, 14, 22, 47);
/// SLH-DSA-SHA2-256f: category 5, pk 64 B, sk 128 B, sig 49 856 B.
pub const sha2_256f: Params = tableRow("SLH-DSA-SHA2-256f", .sha2, 32, 68, 17, 4, 9, 35, 49);

/// SLH-DSA-SHAKE-128s: category 1, pk 32 B, sk 64 B, sig 7 856 B.
pub const shake_128s: Params = tableRow("SLH-DSA-SHAKE-128s", .shake, 16, 63, 7, 9, 12, 14, 30);
/// SLH-DSA-SHAKE-128f: category 1, pk 32 B, sk 64 B, sig 17 088 B.
pub const shake_128f: Params = tableRow("SLH-DSA-SHAKE-128f", .shake, 16, 66, 22, 3, 6, 33, 34);
/// SLH-DSA-SHAKE-192s: category 3, pk 48 B, sk 96 B, sig 16 224 B.
pub const shake_192s: Params = tableRow("SLH-DSA-SHAKE-192s", .shake, 24, 63, 7, 9, 14, 17, 39);
/// SLH-DSA-SHAKE-192f: category 3, pk 48 B, sk 96 B, sig 35 664 B.
pub const shake_192f: Params = tableRow("SLH-DSA-SHAKE-192f", .shake, 24, 66, 22, 3, 8, 33, 42);
/// SLH-DSA-SHAKE-256s: category 5, pk 64 B, sk 128 B, sig 29 792 B.
pub const shake_256s: Params = tableRow("SLH-DSA-SHAKE-256s", .shake, 32, 64, 8, 8, 14, 22, 47);
/// SLH-DSA-SHAKE-256f: category 5, pk 64 B, sk 128 B, sig 49 856 B.
pub const shake_256f: Params = tableRow("SLH-DSA-SHAKE-256f", .shake, 32, 68, 17, 4, 9, 35, 49);

/// All twelve sets, for test iteration.
pub const all = [_]Params{
    sha2_128s,  sha2_128f,  sha2_192s,  sha2_192f,  sha2_256s,  sha2_256f,
    shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f,
};

test "every set validates and derives the FIPS 205 Table 2 signature size" {
    // (set, sig bytes) — signature sizes as printed in FIPS 205 Table 2.
    const expected = [_]struct { Params, usize }{
        .{ sha2_128s, 7856 },  .{ shake_128s, 7856 },
        .{ sha2_128f, 17088 }, .{ shake_128f, 17088 },
        .{ sha2_192s, 16224 }, .{ shake_192s, 16224 },
        .{ sha2_192f, 35664 }, .{ shake_192f, 35664 },
        .{ sha2_256s, 29792 }, .{ shake_256s, 29792 },
        .{ sha2_256f, 49856 }, .{ shake_256f, 49856 },
    };
    inline for (expected) |case| {
        comptime case[0].validate();
        try std.testing.expectEqual(case[1], comptime case[0].sigLen());
    }
    try std.testing.expectEqual(expected.len, all.len);
}

test "derived lengths for SLH-DSA-SHA2-128f match FIPS 205 Table 2" {
    comptime sha2_128f.validate();
    try std.testing.expectEqual(@as(usize, 16), comptime sha2_128f.w());
    try std.testing.expectEqual(@as(usize, 32), comptime sha2_128f.len1());
    try std.testing.expectEqual(@as(usize, 3), comptime sha2_128f.len2());
    try std.testing.expectEqual(@as(usize, 35), comptime sha2_128f.wotsLen());
    try std.testing.expectEqual(@as(usize, 25), comptime sha2_128f.mdLen());
    try std.testing.expectEqual(@as(usize, 8), comptime sha2_128f.idxTreeLen());
    try std.testing.expectEqual(@as(usize, 1), comptime sha2_128f.idxLeafLen());
    try std.testing.expectEqual(@as(usize, 17088), comptime sha2_128f.sigLen());
}
