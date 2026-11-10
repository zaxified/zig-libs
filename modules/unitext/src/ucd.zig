// SPDX-License-Identifier: MIT

//! Lookups in the generated tables (`tables.zig`): the three-stage indexing and the
//! packed record layouts. Nothing here allocates or can fail; a code point above
//! U+10FFFF (a `u21` can hold up to 0x1FFFFF) reads as the table's default record.

const std = @import("std");
const t = @import("tables.zig");

pub const max_cp: u21 = 0x10FFFF;

/// `table.vals[leaf[...]]` for a three-stage table built by `tools/ucd_gen/gen.py`. A value above
/// U+10FFFF reads as U+10FFFF, a noncharacter: category Cn, no flags, no mappings.
pub inline fn look(comptime table: type, cp: u21) table.Value {
    const c: usize = @min(cp, max_cp);
    const a = table.shift_a;
    const b = table.shift_b;
    const x1: usize = table.t1[c >> (a + b)];
    const x2: usize = table.t2[(x1 << b) | ((c >> a) & ((1 << b) - 1))];
    const x3: usize = table.leaf[(x2 << a) | (c & ((1 << a) - 1))];
    return table.vals[x3];
}

/// Unicode General_Category, in the order the tables use.
pub const GeneralCategory = enum(u8) {
    Lu,
    Ll,
    Lt,
    Lm,
    Lo,
    Mn,
    Mc,
    Me,
    Nd,
    Nl,
    No,
    Pc,
    Pd,
    Ps,
    Pe,
    Pi,
    Pf,
    Po,
    Sm,
    Sc,
    Sk,
    So,
    Zs,
    Zl,
    Zp,
    Cc,
    Cf,
    Cs,
    Co,
    Cn,
};

comptime {
    std.debug.assert(@typeInfo(GeneralCategory).@"enum".field_names.len == t.gc_count);
}

pub const f_upper: u16 = 1 << 5;
pub const f_lower: u16 = 1 << 6;
pub const f_cased: u16 = 1 << 7;
pub const f_ignorable: u16 = 1 << 8;
pub const f_space: u16 = 1 << 9;
pub const num_shift = 10;
pub const f_alphabetic: u16 = 1 << 12;

/// The packed `gcflags` record of `cp`.
pub inline fn flags(cp: u21) u16 {
    return look(t.gcflags, cp);
}

pub inline fn category(cp: u21) GeneralCategory {
    return @fromBackingInt(@intCast(flags(cp) & 31));
}

/// Numeric_Type (bits 10-11 of the record; bit 12 is `f_alphabetic`): 0 none, 1 Numeric, 2 Digit, 3 Decimal.
pub inline fn numericType(cp: u21) u2 {
    return @intCast((flags(cp) >> num_shift) & 3);
}

/// The packed `norm` record of `cp`.
pub inline fn normInfo(cp: u21) u16 {
    return look(t.norm, cp);
}

pub inline fn ccc(cp: u21) u8 {
    return @truncate(normInfo(cp));
}

pub const Qc = enum(u2) { yes = 0, maybe = 1, no = 2 };

/// NFC_QC (also used for NFKC, whose Maybe set is the same).
pub inline fn nfcQc(cp: u21) Qc {
    return @fromBackingInt(@intCast((normInfo(cp) >> 8) & 3));
}

pub inline fn nfkcQc(cp: u21) Qc {
    return @fromBackingInt(@intCast((normInfo(cp) >> 10) & 3));
}

/// Hangul syllable arithmetic (Unicode §3.12).
pub const hangul = struct {
    pub const s_base: u21 = 0xAC00;
    pub const l_base: u21 = 0x1100;
    pub const v_base: u21 = 0x1161;
    pub const t_base: u21 = 0x11A7;
    pub const l_count = 19;
    pub const v_count = 21;
    pub const t_count = 28;
    pub const n_count = v_count * t_count;
    pub const s_count = l_count * n_count;

    pub inline fn isSyllable(cp: u21) bool {
        return cp >= s_base and cp < s_base + s_count;
    }
};

test "look: out-of-range code points read the default record" {
    try std.testing.expectEqual(@as(u16, @backingInt(GeneralCategory.Cn)), flags(0x110000) & 31);
    try std.testing.expectEqual(@as(u16, @backingInt(GeneralCategory.Cn)), flags(0x1FFFFF) & 31);
    try std.testing.expectEqual(GeneralCategory.Lu, category('A'));
    try std.testing.expectEqual(GeneralCategory.Zs, category(0x3000));
    try std.testing.expectEqual(@as(u8, 230), ccc(0x0301));
    try std.testing.expectEqual(@as(u8, 0), ccc(0x1FFFFF));
}
