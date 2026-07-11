// SPDX-License-Identifier: MIT
//! params — SLH-DSA (FIPS 205) parameter sets.
//!
//! Only `sha2_128f` (SLH-DSA-SHA2-128f, Table 2 of FIPS 205) is wired to an
//! implemented hash instantiation today; the struct carries every FIPS 205
//! knob so the remaining eleven sets are a matter of adding the table rows
//! plus the SHA2 category-3/5 and SHAKE hash instantiations in `engine.zig`.

const std = @import("std");

/// Which §11 hash instantiation a parameter set uses.
pub const HashFamily = enum {
    /// FIPS 205 §11.2 — SHA-2 family (SHA-256 throughout for security
    /// category 1; categories 3/5 additionally use SHA-512).
    sha2,
    /// FIPS 205 §11.1 — SHAKE256 for every function. Not implemented yet.
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
        if (p.hp * p.d != p.h) @compileError("params: h' * d must equal h");
        if (p.m != p.mdLen() + p.idxTreeLen() + p.idxLeafLen())
            @compileError("params: m must match its three digest slices");
        if (p.h - p.hp > 64) @compileError("params: tree index must fit u64");
        if (p.lg_w != 4) @compileError("params: FIPS 205 fixes lg_w = 4");
    }
};

/// SLH-DSA-SHA2-128f (FIPS 205 Table 2): security category 1, "fast"
/// (larger signature, faster signing). pk 32 B, sk 64 B, sig 17 088 B.
pub const sha2_128f: Params = .{
    .name = "SLH-DSA-SHA2-128f",
    .hash = .sha2,
    .n = 16,
    .h = 66,
    .d = 22,
    .hp = 3,
    .a = 6,
    .k = 33,
    .lg_w = 4,
    .m = 34,
};

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
