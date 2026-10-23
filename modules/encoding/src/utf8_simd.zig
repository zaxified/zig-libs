// SPDX-License-Identifier: MIT
//! Vector UTF-8 validation: the "lookup" algorithm of Keiser and Lemire,
//! "Validating UTF-8 In Less Than One Instruction Per Byte" (2021), as
//! simdjson implements it (`src/generic/utf8_lookup4_algorithm.h`; simdjson
//! is Apache-2.0 OR MIT — the three nibble tables and the error-bit layout
//! are ported from it, see this module's NOTICE). Each 32-byte block is
//! checked with three 16-entry table lookups on nibbles of the byte and its
//! predecessor, plus a check that the bytes owed to a 3- or 4-byte lead are
//! continuations.
//!
//! `validPrefix` answers how far input is certainly valid, ending on a
//! character boundary; the scalar decoder takes over from there and makes
//! every exact decision (maximal subparts, replacement), so this file only
//! ever decides "valid", never "how to repair".

const std = @import("std");
const builtin = @import("builtin");

const lanes = 32;
const V = @Vector(lanes, u8);

const has_avx2 = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

/// `table[idx[i]]` for every lane (`idx` < 16).
inline fn lookup16(idx: V, comptime table: [16]u8) V {
    if (has_avx2) {
        // vpshufb looks up within each 128-bit half, so the table is in both.
        const t: V = table ++ table;
        return asm ("vpshufb %[idx], %[tbl], %[out]"
            : [out] "=x" (-> V),
            : [tbl] "x" (t),
              [idx] "x" (idx),
        );
    }
    return lookup16Portable(idx, table);
}

/// `lookup16` without vpshufb: a binary tree of selects over the four
/// index bits (every target; tested against the table on this one too).
inline fn lookup16Portable(idx: V, comptime table: [16]u8) V {
    var level: [16]V = undefined;
    inline for (0..16) |k| level[k] = @splat(table[k]);
    comptime var width = 16;
    comptime var bit = 0;
    inline while (width > 1) : ({
        width /= 2;
        bit += 1;
    }) {
        const mask = (idx >> @splat(@as(u3, bit))) & @as(V, @splat(1)) == @as(V, @splat(1));
        inline for (0..width / 2) |k| level[k] = @select(u8, mask, level[2 * k + 1], level[2 * k]);
    }
    return level[0];
}

/// Lane `i` = the byte `n` positions before `cur[i]`, reaching into `prev`.
inline fn shiftIn(cur: V, prev: V, comptime n: comptime_int) V {
    const mask = comptime blk: {
        var m: [lanes]i32 = undefined;
        for (0..lanes) |i| m[i] = if (i >= n) @intCast(i - n) else ~@as(i32, @intCast(lanes - n + i));
        break :blk m;
    };
    return @shuffle(u8, cur, prev, mask);
}

const too_short: u8 = 1 << 0; // 11______ 0_______ / 11______ 11______
const too_long: u8 = 1 << 1; // 0_______ 10______
const overlong_3: u8 = 1 << 2; // 11100000 100_____
const too_large: u8 = 1 << 3; // 11110100 1001____, 11110100 101_____, …
const surrogate: u8 = 1 << 4; // 11101101 101_____
const overlong_2: u8 = 1 << 5; // 1100000_ 10______
const too_large_1000: u8 = 1 << 6; // 11110101 1000____, …
const overlong_4: u8 = 1 << 6; // 11110000 1000____
const two_conts: u8 = 1 << 7; // 10______ 10______
const carry = too_short | too_long | two_conts;

const byte_1_high = [16]u8{
    too_long, too_long, too_long, too_long, // 0_______ ASCII
    too_long, too_long, too_long, too_long,
    two_conts, two_conts, two_conts, two_conts, // 10______ continuation
    too_short | overlong_2, // 1100____
    too_short, // 1101____
    too_short | overlong_3 | surrogate, // 1110____
    too_short | too_large | too_large_1000 | overlong_4, // 1111____
};

const byte_1_low = [16]u8{
    carry | overlong_3 | overlong_2 | overlong_4, // ____0000
    carry | overlong_2, // ____0001
    carry,
    carry,
    carry | too_large, // ____0100
    carry | too_large | too_large_1000, // ____0101
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000, // ____1___
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000 | surrogate, // ____1101
    carry | too_large | too_large_1000,
    carry | too_large | too_large_1000,
};

const byte_2_high = [16]u8{
    too_short, too_short, too_short, too_short, // 0_______
    too_short, too_short, too_short, too_short,
    too_long | overlong_2 | two_conts | overlong_3 | too_large_1000 | overlong_4, // 1000____
    too_long | overlong_2 | two_conts | overlong_3 | too_large, // 1001____
    too_long | overlong_2 | two_conts | surrogate | too_large, // 101_____
    too_long | overlong_2 | two_conts | surrogate | too_large,
    too_short, too_short, too_short, too_short, // 11______
};

/// Error bits for `cur` given the block before it.
inline fn blockErrors(cur: V, prev: V) V {
    const four: V = @splat(4);
    const low: V = @splat(0x0F);
    const prev1 = shiftIn(cur, prev, 1);
    const sc = lookup16(prev1 >> four, byte_1_high) &
        lookup16(prev1 & low, byte_1_low) &
        lookup16(cur >> four, byte_2_high);
    const prev2 = shiftIn(cur, prev, 2);
    const prev3 = shiftIn(cur, prev, 3);
    // >= 0x80 exactly where the byte 2 (3) before is a 3-byte (4-byte) lead.
    const must23 = (prev2 -| @as(V, @splat(0xE0 - 0x80))) | (prev3 -| @as(V, @splat(0xF0 - 0x80)));
    return (must23 & @as(V, @splat(0x80))) ^ sc;
}

/// Non-zero where the block's last bytes open a sequence it does not finish.
inline fn incompleteTail(cur: V) V {
    const max = comptime blk: {
        var m: [lanes]u8 = @splat(0xFF);
        m[lanes - 3] = 0xF0 - 1;
        m[lanes - 2] = 0xE0 - 1;
        m[lanes - 1] = 0xC0 - 1;
        break :blk m;
    };
    return @select(u8, cur > @as(V, max), @as(V, @splat(1)), @as(V, @splat(0)));
}

inline fn any(v: V) bool {
    return @reduce(.Or, v) != 0;
}

/// Where the last character that starts before `end` ends, given that
/// `s[0..end]` is valid except possibly for a sequence cut at `end`.
fn boundaryBefore(s: []const u8, end: usize) usize {
    var j: usize = 1;
    while (j <= 3 and j <= end) : (j += 1) {
        const b = s[end - j];
        if (b & 0xC0 == 0x80) continue; // continuation: keep looking for its lead
        if (b < 0x80) return end; // ASCII: nothing is cut
        const need: usize = if (b >= 0xF0) 4 else if (b >= 0xE0) 3 else 2;
        return if (need > j) end - j else end;
    }
    return end;
}

/// `validPrefix(s)`, copying `s` into `dst` (`dst.len >= s.len`) on the
/// way: only `dst[0..result]` is meaningful.
pub fn copyValidPrefix(s: []const u8, dst: []u8) usize {
    return scan(s, dst);
}

/// A prefix of `s` that is certainly well-formed UTF-8 and ends on a
/// character boundary. It may stop short of the longest such prefix (at
/// the start of a block holding an error, or of the tail shorter than a
/// block); never past it.
pub fn validPrefix(s: []const u8) usize {
    return scan(s, null);
}

inline fn scan(s: []const u8, dst: ?[]u8) usize {
    // Every inline loop below (lookup16Portable's select tree above all, on a
    // target without AVX2) charges this one function's branch quota; the
    // x86_64-windows baseline build ran past the default 1000.
    @setEvalBranchQuota(10_000);
    var prev: V = @splat(0);
    var pending: V = @splat(0);
    var i: usize = 0;
    var ok: usize = 0;
    // Groups of four blocks with one error test per group (a horizontal
    // test per block is what costs); a group with an error is left to the
    // block loop below, which finds the last good boundary in it.
    while (i + 4 * lanes <= s.len) {
        const c0: V = s[i..][0..lanes].*;
        const c1: V = s[i + lanes ..][0..lanes].*;
        const c2: V = s[i + 2 * lanes ..][0..lanes].*;
        const c3: V = s[i + 3 * lanes ..][0..lanes].*;
        if (dst) |d| {
            d[i..][0..lanes].* = c0;
            d[i + lanes ..][0..lanes].* = c1;
            d[i + 2 * lanes ..][0..lanes].* = c2;
            d[i + 3 * lanes ..][0..lanes].* = c3;
        }
        const high = (c0 | c1 | c2 | c3) & @as(V, @splat(0x80));
        if (!any(high)) {
            if (any(pending)) break;
        } else {
            const e = blockErrors(c0, prev) | blockErrors(c1, c0) | blockErrors(c2, c1) | blockErrors(c3, c2);
            if (any(e)) break;
        }
        pending = incompleteTail(c3);
        prev = c3;
        i += 4 * lanes;
        ok = i; // may cut a sequence; `boundaryBefore` at the end settles it
    }
    ok = boundaryBefore(s, ok);
    while (i + lanes <= s.len) : (i += lanes) {
        const cur: V = s[i..][0..lanes].*;
        if (dst) |d| d[i..][0..lanes].* = cur;
        if (@reduce(.Or, cur & @as(V, @splat(0x80))) == 0) {
            // All ASCII: only a sequence left open by the last block can be wrong.
            if (any(pending)) break;
            ok = i + lanes;
            prev = cur;
            continue;
        }
        if (any(blockErrors(cur, prev))) break;
        pending = incompleteTail(cur);
        prev = cur;
        ok = if (any(pending)) boundaryBefore(s, i + lanes) else i + lanes;
    }
    return ok;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "lookup16: both paths give the table for every index" {
    var arr: [lanes]u8 = undefined;
    for (&arr, 0..) |*x, i| x.* = @intCast(i % 16);
    const idx: V = arr;
    inline for (.{ byte_1_high, byte_1_low, byte_2_high }) |table| {
        const a: [lanes]u8 = lookup16(idx, table);
        const b: [lanes]u8 = lookup16Portable(idx, table);
        for (0..lanes) |i| {
            try testing.expectEqual(table[i % 16], a[i]);
            try testing.expectEqual(table[i % 16], b[i]);
        }
    }
}

/// Is `s[0..n]` well-formed and does `n` fall on a character boundary?
fn checkPrefix(s: []const u8) !void {
    const n = validPrefix(s);
    try testing.expect(n <= s.len);
    try testing.expect(std.unicode.utf8ValidateSlice(s[0..n]));
    if (std.unicode.utf8ValidateSlice(s)) {
        // Valid input: everything but a tail shorter than one block.
        try testing.expect(s.len - n < lanes + 3);
    }
    var buf: [600]u8 = undefined;
    try testing.expectEqual(n, copyValidPrefix(s, buf[0..s.len]));
    try testing.expectEqualSlices(u8, s[0..n], buf[0..n]);
}

test "validPrefix: valid text of every sequence length at every alignment" {
    const pieces = [_][]const u8{ "a", "é", "€", "\u{1F600}", "\u{10FFFF}", "\u{D7FF}", "\u{E000}", "\u{FFFF}", "\u{80}", "\u{800}", "\u{10000}" };
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    var buf: [520]u8 = undefined;
    for (0..2000) |_| {
        var n: usize = 0;
        while (n + 4 < buf.len) {
            const p = pieces[r.uintLessThan(usize, pieces.len)];
            @memcpy(buf[n..][0..p.len], p);
            n += p.len;
            if (r.uintLessThan(u8, 50) == 0) break;
        }
        try checkPrefix(buf[0..n]);
        // One corrupted byte somewhere: still a valid, boundary-aligned prefix.
        if (n > 0) {
            var bad = buf;
            bad[r.uintLessThan(usize, n)] = r.int(u8);
            try checkPrefix(bad[0..n]);
        }
    }
}

test "validPrefix: every ill-formed class is caught (never inside the prefix)" {
    const bad = [_][]const u8{
        "\x80",             "\xbf",             "\xc0\x80",         "\xc1\xbf",         "\xe0\x80\x80", "\xe0\x9f\xbf", "\xed\xa0\x80", "\xed\xbf\xbf",
        "\xf0\x80\x80\x80", "\xf0\x8f\xbf\xbf", "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff",         "\xfe",         "\xc3",         "\xe2\x82",
        "\xf0\x9f\x98",     "\xc3\xc3",         "\xe2\x82a",        "\xf0\x9f\x98a",
    };
    for (bad) |b| {
        for (0..70) |pre| {
            var buf: [200]u8 = @splat('x');
            @memcpy(buf[pre..][0..b.len], b);
            const s = buf[0 .. pre + b.len + 40];
            try checkPrefix(s);
            try testing.expect(validPrefix(s) <= pre);
        }
    }
}
