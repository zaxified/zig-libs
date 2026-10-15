// SPDX-License-Identifier: MIT
//! Serialized shared dictionaries (RFC 9841 §5, SPEC.md backlog R7) — the
//! decoder's side: custom word lists and transforms that replace or extend
//! the RFC 7932 static dictionary, possibly chosen by the literal context,
//! and an LZ77 dictionary that acts as a raw prefix dictionary.
//!
//! `parse` reads the format into views of the caller's bytes (which must
//! outlive the result) plus a few small tables; `Options.shared_dictionary`
//! hands it to a decoder.

const std = @import("std");
const builtin_dict = @import("dictionary.zig");
const transforms = @import("transforms.zig");

pub const signature = [2]u8{ 0x91, 0x00 };
/// The most word lists, transform lists and dictionaries (RFC 9841 §5).
pub const max_lists = 64;
/// A static-dictionary word is 4..31 bytes long (RFC 9841 §3.1).
pub const min_word_length = 4;
pub const max_word_length = 31;
/// A prefix or suffix stringlet is at most 255 bytes.
pub const max_affix_len = 255;

pub const ParseError = error{
    /// Not the format: a wrong signature, a field out of its range, a
    /// length past the end, or bytes after it.
    InvalidSharedDictionary,
    OutOfMemory,
};

/// A word list: `size_bits[len]` is log2 of how many words of `len` bytes
/// it has (0: none); they are stored in `data` from `offsets[len]`, shortest
/// first.
pub const WordList = struct {
    size_bits: [32]u8,
    offsets: [32]u32,
    data: []const u8,

    pub const builtin: WordList = .{
        .size_bits = builtin_dict.size_bits_by_length,
        .offsets = builtin_dict.offsets_by_length,
        .data = builtin_dict.data,
    };

    /// Words of `len` bytes (a power of two, or 0).
    pub fn count(w: *const WordList, len: usize) usize {
        const b = w.size_bits[len];
        return if (b == 0) 0 else @as(usize, 1) << @intCast(b);
    }

    pub fn word(w: *const WordList, len: usize, idx: usize) []const u8 {
        return w.data[w.offsets[len] + idx * len ..][0..len];
    }
};

/// A transform list: transform `i` puts stringlet `prefix[i]` before the
/// word, applies operation `op[i]` (RFC 9841 §3.1.1; `param[i]` for
/// ShiftFirst/ShiftAll) and puts stringlet `suffix[i]` after.
pub const TransformList = struct {
    /// The prefix/suffix data: length-prefixed stringlets, the last empty.
    stringlet_data: []const u8,
    /// Where each stringlet starts in `stringlet_data` (at its length byte).
    stringlets: []const u16,
    /// NTRANSFORMS triplets: prefix index, operation, suffix index — the
    /// order google/brotli reads (`BROTLI_TRANSFORM_TYPE` is byte 1, as in
    /// RFC 7932's own table); RFC 9841 §5's text lists prefix, suffix,
    /// operation. The reference implementation is the one that makes these
    /// dictionaries, so its order is the one that interoperates.
    triplets: []const u8,
    /// Two bytes per transform (little-endian), or empty without shifts.
    params: []const u8,

    pub fn len(t: *const TransformList) usize {
        return t.triplets.len / 3;
    }

    pub fn affix(t: *const TransformList, which: usize) []const u8 {
        const at = t.stringlets[which];
        return t.stringlet_data[at + 1 ..][0..t.stringlet_data[at]];
    }

    pub fn param(t: *const TransformList, i: usize) u16 {
        if (t.params.len == 0) return 0;
        return std.mem.readInt(u16, t.params[2 * i ..][0..2], .little);
    }
};

/// One word list with one transform list; null = RFC 7932's own.
pub const Pair = struct { words: ?*const WordList, transforms: ?*const TransformList };

pub const SharedDictionary = struct {
    arena: std.heap.ArenaAllocator,
    /// The LZ77 dictionary: a raw prefix dictionary (RFC 9841 §3.2).
    prefix: []const u8,
    word_lists: []WordList,
    transform_lists: []TransformList,
    /// NUM_DICTIONARIES pairs, in their order (one, RFC 7932's, when the
    /// stream has no custom lists).
    dictionaries: []Pair,
    /// For a context-dependent dictionary: the index into `dictionaries`
    /// tried first for each of the 64 literal contexts.
    context_map: ?[64]u8,

    pub fn deinit(sd: *SharedDictionary) void {
        sd.arena.deinit();
        sd.* = undefined;
    }

    /// Any custom words or transforms (else only `prefix` matters).
    pub fn custom(sd: *const SharedDictionary) bool {
        return sd.word_lists.len != 0 or sd.transform_lists.len != 0;
    }
};

const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn byte(r: *Reader) ParseError!u8 {
        if (r.i >= r.b.len) return error.InvalidSharedDictionary;
        r.i += 1;
        return r.b[r.i - 1];
    }
    fn take(r: *Reader, n: usize) ParseError![]const u8 {
        if (n > r.b.len - r.i) return error.InvalidSharedDictionary;
        r.i += n;
        return r.b[r.i - n ..][0..n];
    }
    /// RFC 9841 §4: base 128, least significant group first, at most 63
    /// bits (a ninth byte with its high bit set is invalid).
    fn varint(r: *Reader) ParseError!u64 {
        var v: u64 = 0;
        var k: u6 = 0;
        while (true) : (k += 1) {
            const c = try r.byte();
            if (k == 8 and c & 0x80 != 0) return error.InvalidSharedDictionary;
            v |= @as(u64, c & 0x7f) << (7 * k);
            if (c & 0x80 == 0) return v;
        }
    }
};

/// Read a serialized shared dictionary. The result refers to `bytes`.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) ParseError!SharedDictionary {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var r: Reader = .{ .b = bytes };
    if (!std.mem.eql(u8, try r.take(2), &signature)) return error.InvalidSharedDictionary;

    // The LZ77 dictionary: at most a large window's worth (2^62 - 16; this
    // side keeps it in memory, so any length that fits is taken).
    const lz_len = try r.varint();
    if (lz_len > bytes.len) return error.InvalidSharedDictionary;
    const prefix = try r.take(@intCast(lz_len));

    const n_words = try r.byte();
    if (n_words > max_lists) return error.InvalidSharedDictionary;
    const word_lists = try a.alloc(WordList, n_words);
    for (word_lists) |*w| {
        const sizes = try r.take(28);
        w.size_bits = @splat(0);
        var total: u64 = 0;
        for (sizes, min_word_length..) |b, l| {
            if (b > 15) return error.InvalidSharedDictionary;
            w.size_bits[l] = b;
        }
        for (0..32) |l| {
            w.offsets[l] = @intCast(total);
            if (w.size_bits[l] != 0) total += @as(u64, l) << @intCast(w.size_bits[l]);
        }
        if (total > bytes.len) return error.InvalidSharedDictionary;
        w.data = try r.take(@intCast(total));
    }

    const n_transforms = try r.byte();
    if (n_transforms > max_lists) return error.InvalidSharedDictionary;
    const transform_lists = try a.alloc(TransformList, n_transforms);
    for (transform_lists) |*t| {
        const ps_len = std.mem.readInt(u16, (try r.take(2))[0..2], .little);
        if (ps_len == 0) return error.InvalidSharedDictionary;
        const ps = try r.take(ps_len);
        // Stringlets: 1..255 bytes each, then the empty one, which must be
        // the last byte; 1..256 of them in all.
        var offs: std.ArrayList(u16) = .empty;
        var at: usize = 0;
        while (true) {
            if (offs.items.len == 256) return error.InvalidSharedDictionary;
            try offs.append(a, @intCast(at));
            const l = ps[at];
            if (l == 0) {
                if (at != ps.len - 1) return error.InvalidSharedDictionary;
                break;
            }
            at += 1 + @as(usize, l);
            if (at >= ps.len) return error.InvalidSharedDictionary;
        }
        t.stringlet_data = ps;
        t.stringlets = offs.items;
        const nt = try r.byte();
        t.triplets = try r.take(@as(usize, nt) * 3);
        var shifts = false;
        for (0..nt) |i| {
            const tri = t.triplets[3 * i ..][0..3];
            if (tri[0] >= offs.items.len or tri[2] >= offs.items.len) return error.InvalidSharedDictionary;
            if (tri[1] > op_shift_all) return error.InvalidSharedDictionary;
            if (tri[1] >= op_shift_first) shifts = true;
        }
        t.params = &.{};
        if (shifts) {
            t.params = try r.take(@as(usize, nt) * 2);
            for (0..nt) |i| {
                if (t.triplets[3 * i + 1] < op_shift_first and t.param(i) != 0) return error.InvalidSharedDictionary;
            }
        }
    }

    var dictionaries: []Pair = undefined;
    var context_map: ?[64]u8 = null;
    if (n_words > 0 or n_transforms > 0) {
        const nd = try r.byte();
        if (nd == 0 or nd > max_lists) return error.InvalidSharedDictionary;
        dictionaries = try a.alloc(Pair, nd);
        for (dictionaries) |*d| {
            const wi = try r.byte();
            const ti = try r.byte();
            if (wi > n_words or ti > n_transforms) return error.InvalidSharedDictionary;
            d.* = .{
                .words = if (wi == n_words) null else &word_lists[wi],
                .transforms = if (ti == n_transforms) null else &transform_lists[ti],
            };
        }
        const ctx = try r.byte();
        if (ctx > 1) return error.InvalidSharedDictionary;
        if (ctx == 1) {
            const m = try r.take(64);
            for (m) |x| if (x >= nd) return error.InvalidSharedDictionary;
            context_map = m[0..64].*;
        }
    } else {
        dictionaries = try a.alloc(Pair, 1);
        dictionaries[0] = .{ .words = null, .transforms = null };
    }
    if (r.i != bytes.len) return error.InvalidSharedDictionary;
    return .{
        .arena = arena,
        .prefix = prefix,
        .word_lists = word_lists,
        .transform_lists = transform_lists,
        .dictionaries = dictionaries,
        .context_map = context_map,
    };
}

pub const op_shift_first = 21;
pub const op_shift_all = 22;

test "parse: every cut of a valid dictionary, and every bad field, is refused — never a crash" {
    const corpus = @import("interop_corpus.zig");
    const gpa = std.testing.allocator;
    inline for (corpus.serial_cases) |c| {
        const dict = try corpus.serialize(gpa, c.dict);
        defer gpa.free(dict);
        var sd = try parse(gpa, dict);
        sd.deinit();
        for (0..dict.len) |n| {
            if (parse(gpa, dict[0..n])) |x| {
                var y = x;
                y.deinit();
                return error.TestUnexpectedResult;
            } else |e| try std.testing.expectEqual(error.InvalidSharedDictionary, e);
        }
        // A byte more is refused too.
        const longer = try std.mem.concat(gpa, u8, &.{ dict, "x" });
        defer gpa.free(longer);
        try std.testing.expectError(error.InvalidSharedDictionary, parse(gpa, longer));
        // Every single-byte change either parses or is refused.
        const copy = try gpa.dupe(u8, dict);
        defer gpa.free(copy);
        for (0..@min(dict.len, 600)) |i| {
            for ([_]u8{ 0x01, 0x80, 0xff }) |x| {
                copy[i] ^= x;
                if (parse(gpa, copy)) |ok| {
                    var y = ok;
                    y.deinit();
                } else |_| {}
                copy[i] ^= x;
            }
        }
    }
}

test "parse: the fields of a hand-made dictionary" {
    const gpa = std.testing.allocator;
    // LZ77 "abc"; one word list with two 4-byte words; one transform list
    // (stringlets "x", ""; transforms identity and ShiftAll by 2); two
    // dictionaries (custom pair, RFC 7932's words with the custom
    // transforms); a context map.
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);
    try b.appendSlice(gpa, &.{ 0x91, 0x00, 3, 'a', 'b', 'c', 1 });
    var sizes: [28]u8 = @splat(0);
    sizes[0] = 1; // length 4: 2 words
    try b.appendSlice(gpa, &sizes);
    try b.appendSlice(gpa, "wordtext");
    try b.appendSlice(gpa, &.{ 1, 3, 0, 1, 'x', 0, 2, 0, 0, 1, 1, 22, 1, 0, 0, 2, 0 });
    try b.appendSlice(gpa, &.{ 2, 0, 0, 1, 0, 1 });
    for (0..64) |i| try b.append(gpa, @intFromBool(i % 2 == 1));
    var sd = try parse(gpa, b.items);
    defer sd.deinit();
    try std.testing.expectEqualStrings("abc", sd.prefix);
    try std.testing.expectEqual(@as(usize, 2), sd.word_lists[0].count(4));
    try std.testing.expectEqualStrings("text", sd.word_lists[0].word(4, 1));
    const t = &sd.transform_lists[0];
    try std.testing.expectEqual(@as(usize, 2), t.len());
    try std.testing.expectEqualStrings("x", t.affix(0));
    try std.testing.expectEqualStrings("", t.affix(1));
    try std.testing.expectEqual(@as(u16, 2), t.param(1));
    try std.testing.expectEqual(@as(usize, 2), sd.dictionaries.len);
    try std.testing.expect(sd.dictionaries[1].words == null);
    try std.testing.expectEqual(@as(u8, 1), sd.context_map.?[63]);
}
