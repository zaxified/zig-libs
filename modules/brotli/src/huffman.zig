// SPDX-License-Identifier: MIT
//! Canonical + simple prefix-code tables for RFC 7932.
//!
//! Codes are read least-significant-bit first, so the canonical (MSB-first)
//! code assigned to each symbol is bit-reversed before being placed into a
//! lookup table. Two levels, as in zlib and google/brotli: a root table of
//! `1 << root_bits` entries holds every code up to that length, a shorter one
//! repeated; a longer code's root entry links to a subtable indexed by the bits
//! after the root. The root is always `root_bits` wide (as google/brotli's), so
//! a decoder masks with a constant (2026-10-15: `bits` was `min(max length,
//! root_bits)`, a load and a variable mask per symbol). A flat table of `1 << 15` entries (128 KiB) per literal
//! tree missed the cache on most lookups (bench 2026-10-11). Decoding peeks
//! `bits` bits, indexes the root, follows a link once, and drops the entry's
//! actual code length.

const std = @import("std");
const BrotliError = @import("errors.zig").BrotliError;

/// A symbol and its code length, or -- `len & link_flag` -- a link from the
/// root: the subtable starts at `entries[sym]` and is indexed by
/// `len & ~link_flag` bits.
pub const Entry = struct { sym: u16, len: u8 };
pub const link_flag: u8 = 0x80;

/// Root table index width for codes longer than this (google/brotli's
/// `HUFFMAN_TABLE_BITS`).
pub const root_bits = 8;

pub const Table = struct {
    entries: []Entry,
    bits: u5, // root index width: always `root_bits`

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        gpa.free(self.entries);
        self.* = undefined;
    }
};

/// The low `len` bits of `code`, reversed (`len` ≤ 16; 0 gives 0).
fn reverseBits(code: u32, len: u5) u32 {
    if (len == 0) return 0;
    return @as(u32, @bitReverse(@as(u16, @truncate(code)))) >> @intCast(16 - @as(u6, len));
}

/// Number of bits to represent `x` (bit length): 0 for x==0, else floor(log2(x))+1.
/// Matches google/brotli's `Log2Floor`, used to size simple-code symbol reads.
pub fn symbolBits(x: u32) u5 {
    if (x == 0) return 0;
    return @intCast(32 - @clz(x));
}

fn singleSymbol(gpa: std.mem.Allocator, sym: u16) BrotliError!Table {
    return replicated(gpa, &.{.{ .sym = sym, .len = 0 }});
}

/// A root of `root_bits` from a full table of `small.len` (a power of two
/// up to `1 << root_bits`) entries: each repeated.
fn replicated(gpa: std.mem.Allocator, small: []const Entry) BrotliError!Table {
    const entries = try gpa.alloc(Entry, 1 << root_bits);
    for (entries, 0..) |*e, i| e.* = small[i & (small.len - 1)];
    return .{ .entries = entries, .bits = root_bits };
}

/// Build a table from per-symbol `code_lengths` (complex prefix code, 3.5).
/// Enforces a complete (Kraft-equality) code, except the single-symbol case.
pub fn buildComplex(gpa: std.mem.Allocator, code_lengths: []const u8) BrotliError!Table {
    var count = [_]u16{0} ** 16;
    var max_len: u5 = 0;
    var nonzero: usize = 0;
    var last_sym: u16 = 0;
    for (code_lengths, 0..) |l, sym| {
        if (l == 0) continue;
        if (l > 15) return error.InvalidHuffman;
        count[l] += 1;
        if (l > max_len) max_len = @intCast(l);
        nonzero += 1;
        last_sym = @intCast(sym);
    }
    if (nonzero == 0) return error.InvalidHuffman;
    if (nonzero == 1) return singleSymbol(gpa, last_sym);

    // Kraft completeness check.
    var total: u32 = 0;
    var len: u5 = 1;
    while (len <= max_len) : (len += 1) {
        total += @as(u32, count[len]) << @intCast(max_len - len);
    }
    if (total != (@as(u32, 1) << max_len)) return error.InvalidHuffman;

    var next_code = [_]u32{0} ** 16;
    var code: u32 = 0;
    len = 1;
    while (len <= max_len) : (len += 1) {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    const root: u5 = root_bits;
    const root_size = @as(usize, 1) << root;

    // Subtables: a code longer than `root` belongs to the one of its first
    // `root` bits (MSB-first: `key`). In canonical order the codes under one
    // key are contiguous and, the code being complete, fill its subtree; the
    // subtable is as deep as the longest of them.
    var sub_max = [_]u5{0} ** (1 << root_bits);
    if (max_len > root) {
        var nc = next_code;
        for (code_lengths) |l| {
            if (l == 0) continue;
            const L: u5 = @intCast(l);
            const c = nc[L];
            nc[L] += 1;
            if (L <= root) continue;
            const key = c >> @intCast(L - root);
            sub_max[key] = @max(sub_max[key], L);
        }
    }
    var sub_off = [_]u16{0} ** (1 << root_bits);
    var size = root_size;
    for (sub_max[0..root_size], sub_off[0..root_size]) |m, *off| {
        if (m == 0) continue;
        off.* = @intCast(size);
        size += @as(usize, 1) << (m - root);
    }

    const entries = try gpa.alloc(Entry, size);
    for (sub_max[0..root_size], sub_off[0..root_size], 0..) |m, off, key| {
        if (m == 0) continue;
        entries[reverseBits(@intCast(key), root)] = .{ .sym = off, .len = link_flag | (m - root) };
    }
    for (code_lengths, 0..) |l, sym| {
        if (l == 0) continue;
        const L: u5 = @intCast(l);
        const c = next_code[L];
        next_code[L] += 1;
        const rev = reverseBits(c, L);
        if (L <= root) {
            const step = @as(usize, 1) << L;
            var idx: usize = rev;
            while (idx < root_size) : (idx += step) entries[idx] = .{ .sym = @intCast(sym), .len = l };
        } else {
            const key = c >> @intCast(L - root);
            const sub_size = @as(usize, 1) << (sub_max[key] - root);
            const step = @as(usize, 1) << (L - root);
            var idx: usize = rev >> root;
            while (idx < sub_size) : (idx += step) entries[sub_off[key] + idx] = .{ .sym = @intCast(sym), .len = l };
        }
    }
    return .{ .entries = entries, .bits = root };
}

/// Build a simple prefix code (3.4). `num_symbols` is the decoded selector
/// (0..4); `vals` holds the read symbols (its length matches the selector).
pub fn buildSimple(gpa: std.mem.Allocator, num_symbols: u8, vals_in: []const u16) BrotliError!Table {
    var v: [4]u16 = undefined;
    for (vals_in, 0..) |x, i| v[i] = x;

    switch (num_symbols) {
        0 => return singleSymbol(gpa, v[0]),
        1 => {
            var entries: [2]Entry = undefined;
            const a = @min(v[0], v[1]);
            const b = @max(v[0], v[1]);
            entries[0] = .{ .sym = a, .len = 1 };
            entries[1] = .{ .sym = b, .len = 1 };
            return replicated(gpa, &entries);
        },
        2 => {
            var entries: [4]Entry = undefined;
            const lo = @min(v[1], v[2]);
            const hi = @max(v[1], v[2]);
            entries[0] = .{ .sym = v[0], .len = 1 };
            entries[2] = .{ .sym = v[0], .len = 1 };
            entries[1] = .{ .sym = lo, .len = 2 };
            entries[3] = .{ .sym = hi, .len = 2 };
            return replicated(gpa, &entries);
        },
        3 => {
            // 4 symbols, all length 2. Sort ascending.
            sort4(&v);
            var entries: [4]Entry = undefined;
            entries[0] = .{ .sym = v[0], .len = 2 };
            entries[2] = .{ .sym = v[1], .len = 2 };
            entries[1] = .{ .sym = v[2], .len = 2 };
            entries[3] = .{ .sym = v[3], .len = 2 };
            return replicated(gpa, &entries);
        },
        4 => {
            // 4 symbols, lengths [1,2,3,3]; swap v[2],v[3] if out of order.
            if (v[3] < v[2]) {
                const t = v[3];
                v[3] = v[2];
                v[2] = t;
            }
            var entries: [8]Entry = undefined;
            entries[0] = .{ .sym = v[0], .len = 1 };
            entries[1] = .{ .sym = v[1], .len = 2 };
            entries[2] = .{ .sym = v[0], .len = 1 };
            entries[3] = .{ .sym = v[2], .len = 3 };
            entries[4] = .{ .sym = v[0], .len = 1 };
            entries[5] = .{ .sym = v[1], .len = 2 };
            entries[6] = .{ .sym = v[0], .len = 1 };
            entries[7] = .{ .sym = v[3], .len = 3 };
            return replicated(gpa, &entries);
        },
        else => return error.InvalidHuffman,
    }
}

fn sort4(v: *[4]u16) void {
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var k: usize = i + 1;
        while (k < 4) : (k += 1) {
            if (v[k] < v[i]) {
                const t = v[k];
                v[k] = v[i];
                v[i] = t;
            }
        }
    }
}

test "buildComplex: only complete codes are accepted (RFC 7932 section 3.5)" {
    const gpa = std.testing.allocator;
    // Lengths 1,2,2 are complete; 1,2 leaves a quarter unused; 1,1,1 is over-subscribed.
    var ok = try buildComplex(gpa, &.{ 1, 2, 2 });
    ok.deinit(gpa);
    try std.testing.expectError(error.InvalidHuffman, buildComplex(gpa, &.{ 1, 2 }));
    try std.testing.expectError(error.InvalidHuffman, buildComplex(gpa, &.{ 1, 1, 1 }));
}
