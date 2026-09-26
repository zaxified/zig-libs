// SPDX-License-Identifier: MIT
//! Deterministic sequence lists for the sequence-API goldens
//! (`corpus.seq_cases`): a greedy parse of a corpus input, cut into blocks
//! with explicit delimiters or merged, then optionally damaged in one
//! chosen way. `tools/dump_corpus.zig` writes the same lists to disk for
//! `tools/zseq.c` (16 bytes per sequence: offset, litLength, matchLength,
//! rep, little-endian u32), so both sides read the same sequences.
//!
//! Standalone (no module import): a sequence is four u32s in the order of
//! `ZSTD_Sequence` / `zstd.Sequence`.

const std = @import("std");

pub const Seq = extern struct { offset: u32, lit_length: u32, match_length: u32, rep: u32 = 0 };

pub const Damage = enum {
    none,
    /// one offset `add` further back (past the input's start, into a
    /// dictionary, or past the window)
    offset_add,
    /// one match of 2 bytes (below any minimum)
    match_2,
    /// one match of 3 bytes (below minMatch 4)
    match_3,
    /// one match turned into offset 0 (a delimiter in explicit mode when
    /// the match length is 0 too, else a repcode 3 to libzstd)
    offset_0,
    /// the last delimiter's literals one too many (block larger than the input)
    last_lits_plus_1,
    /// the last delimiter dropped
    no_last_delimiter,
    /// a delimiter with a match length
    delimiter_with_match,
    /// two blocks merged past the block size (drop one delimiter)
    merge_blocks,
    /// all offsets 0xFFFFFFFF - offset (wrap to repcodes)
    offset_wrap,
};

pub const Gen = struct {
    /// Blocks of at most this many bytes, each ended by a delimiter; 0
    /// for no delimiters (one run of sequences, then the last literals).
    block: u32 = 131072,
    /// Shortest match taken.
    min_len: u32 = 4,
    /// Longest distance back.
    window_log: u5 = 17,
    /// Try the last three offsets first (repcode-friendly parses).
    reps: bool = true,
    damage: Damage = .none,
    /// Which match the damage hits (modulo the count).
    at: u32 = 0,
    /// For `offset_add`.
    add: u32 = 1 << 24,
    /// When set, these sequences as they are (a hand-made list), instead of
    /// a parse.
    list: []const Seq = &.{},
};

const hash_log = 16;

fn hash4(p: []const u8) u32 {
    return (std.mem.readInt(u32, p[0..4], .little) *% 2654435761) >> (32 - hash_log);
}

fn count(src: []const u8, a: usize, b: usize, limit: usize) usize {
    var n: usize = 0;
    while (b + n < limit and src[a + n] == src[b + n]) n += 1;
    return n;
}

/// The sequences for `src` under `g`, into `out`; returns how many.
/// `bound(src.len)` is always room enough.
pub fn generate(src: []const u8, g: Gen, table: *[1 << hash_log]u32, out: []Seq) usize {
    if (g.list.len != 0) {
        @memcpy(out[0..g.list.len], g.list);
        return g.list.len;
    }
    @memset(table, 0xFFFFFFFF);
    var ns: usize = 0;
    var rep = [3]u32{ 1, 4, 8 };
    const window: usize = @as(usize, 1) << g.window_log;
    var block_start: usize = 0;
    while (true) {
        const block_end = if (g.block == 0) src.len else @min(src.len, block_start + g.block);
        var i = block_start;
        var anchor = block_start;
        while (i + 4 <= block_end) {
            var best_len: usize = 0;
            var best_off: usize = 0;
            if (g.reps) for (rep) |r| {
                if (r == 0 or r > i or r > window) continue;
                const l = count(src, i - r, i, block_end);
                if (l > best_len) {
                    best_len = l;
                    best_off = r;
                }
            };
            const h = hash4(src[i..]);
            const cand = table[h];
            table[h] = @intCast(i);
            if (cand != 0xFFFFFFFF and i - cand <= window) {
                const l = count(src, cand, i, block_end);
                if (l > best_len + 1) {
                    best_len = l;
                    best_off = i - cand;
                }
            }
            if (best_len >= g.min_len) {
                out[ns] = .{ .offset = @intCast(best_off), .lit_length = @intCast(i - anchor), .match_length = @intCast(best_len) };
                ns += 1;
                if (best_off != rep[0]) {
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = @intCast(best_off);
                }
                i += best_len;
                anchor = i;
                continue;
            }
            i += 1;
        }
        if (g.block == 0) {
            // no delimiters: the last literals are implied
            break;
        }
        out[ns] = .{ .offset = 0, .lit_length = @intCast(block_end - anchor), .match_length = 0 };
        ns += 1;
        block_start = block_end;
        if (block_start >= src.len) break;
    }
    return damage(out[0..ns], g);
}

/// Room for `generate`'s output for an input of `n` bytes.
pub fn bound(n: usize) usize {
    return n / 3 + n / 1024 + 4;
}

fn damage(s: []Seq, g: Gen) usize {
    if (s.len == 0) return 0;
    // the matches (not delimiters) the damage may hit
    var n_match: usize = 0;
    for (s) |x| n_match += @intFromBool(x.match_length != 0);
    const target: ?usize = if (n_match == 0) null else blk: {
        var k = g.at % n_match;
        for (s, 0..) |x, i| if (x.match_length != 0) {
            if (k == 0) break :blk i;
            k -= 1;
        };
        unreachable;
    };
    switch (g.damage) {
        .none => {},
        .offset_add => if (target) |t| {
            s[t].offset +%= g.add;
        },
        .match_2 => if (target) |t| {
            s[t].lit_length +%= s[t].match_length - 2;
            s[t].match_length = 2;
        },
        .match_3 => if (target) |t| {
            s[t].lit_length +%= s[t].match_length - 3;
            s[t].match_length = 3;
        },
        .offset_0 => if (target) |t| {
            s[t].offset = 0;
        },
        .last_lits_plus_1 => s[s.len - 1].lit_length += 1,
        .no_last_delimiter => return s.len - 1,
        .delimiter_with_match => {
            for (s) |*x| if (x.offset == 0 and x.match_length == 0) {
                x.match_length = 5;
                break;
            };
        },
        .merge_blocks => {
            // drop the first delimiter, adding its literals to the next
            for (s[0 .. s.len - 1], 0..) |x, i| if (x.offset == 0 and x.match_length == 0) {
                s[i + 1].lit_length += x.lit_length;
                std.mem.copyForwards(Seq, s[i..], s[i + 1 ..]);
                return s.len - 1;
            };
        },
        .offset_wrap => if (target) |t| {
            s[t].offset = 0xFFFFFFFE;
        },
    }
    return s.len;
}

/// The literals the sequences leave, in order, clamped to `src`
/// (`tools/zseq.c`'s `clit`).
pub fn literals(src: []const u8, seqs: []const Seq, out: []u8) usize {
    var pos: usize = 0;
    var nl: usize = 0;
    for (seqs) |s| {
        pos = @min(pos, src.len);
        const ll = @min(@as(usize, s.lit_length), src.len - pos);
        @memcpy(out[nl..][0..ll], src[pos..][0..ll]);
        nl += ll;
        pos += @as(usize, s.lit_length) + s.match_length;
    }
    return nl;
}

test "a generated parse covers its input" {
    var src: [5000]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = "abcabcabd"[i % 9] +% @as(u8, @intCast((i / 700) % 3));
    var table: [1 << hash_log]u32 = undefined;
    var out: [bound(5000)]Seq = undefined;
    for ([_]u32{ 0, 1024, 131072 }) |blk| {
        const n = generate(&src, .{ .block = blk }, &table, &out);
        var sum: usize = 0;
        for (out[0..n]) |s| sum += @as(usize, s.lit_length) + s.match_length;
        if (blk == 0) try std.testing.expect(sum <= src.len) else try std.testing.expectEqual(src.len, sum);
    }
}
