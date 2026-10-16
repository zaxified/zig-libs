// SPDX-License-Identifier: MIT

//! The interop corpus: every input shape the encoder is judged on, plus the
//! matrix of reference-produced streams the decoder is judged on.
//!
//! It exists as its own file, reachable from `root.zig`, for one structural
//! reason. Until 2026-09-06 these shapes lived in `src/reference_interop.zig`,
//! which spawned `python3` from inside `test-brotli`. That file is now a
//! standalone program under `tools/`, and a program cannot `@import` a path
//! outside its own module root — so the one shared table has to live in the
//! module. Keeping ONE table is the point: the live run against google/brotli
//! and the frozen replay must work from the same shapes, or the replay
//! quietly stops covering what the live run covers.
//!
//! Every shape is a pure function of its descriptor: the random ones carry
//! their own seed, so shape N is reproducible without running shapes 0..N-1.
//! (The old file drew all ten `alphabet` buffers from ONE walking xorshift
//! state, which made every buffer depend on its predecessors — fine for a
//! sweep that always runs whole, useless as a fixture key.)
//!
//! Nothing here is part of the compression API. `root.zig` exposes it as
//! `brotli.interop_corpus` purely so the interop program can import it.

const std = @import("std");

pub const alice = @embedFile("testdata/alice29.txt");
/// Made-up words in seven scripts (`tools/gen_utf8_mix.py`): UTF-8 lead bytes
/// 0xC3..0xDC two positions back select the UTF8 mode's literal context.
pub const utf8_mix = @embedFile("testdata/utf8-mix");

/// Deterministic xorshift64: a failure is reproducible from the seed alone.
pub const Rng = struct {
    s: u64,
    pub fn next(self: *Rng) u64 {
        self.s ^= self.s << 13;
        self.s ^= self.s >> 7;
        self.s ^= self.s << 17;
        return self.s;
    }
    pub fn byte(self: *Rng) u8 {
        return @truncate(self.next() >> 24);
    }
};

/// Binary data shaped like a TrueType font (R12): big-endian tables whose
/// statistics differ, one after another — a table directory, glyph outlines
/// (flag bytes, small signed coordinate deltas; glyphs often a variation of
/// an earlier one), offsets, metrics, a character map, kerning pairs and
/// UTF-16BE names. Not a valid font; the same bytes for the same `n` and
/// `seed`. What block splitting and the SIGNED context mode are for, in the
/// interop corpus and the bench (`tools/bench.zig`).
pub fn fontLike(gpa: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var rng = Rng{ .s = seed };
    const F = struct {
        fn be16(o: *std.ArrayList(u8), g: std.mem.Allocator, v: u16) !void {
            try o.appendSlice(g, &.{ @intCast(v >> 8), @truncate(v) });
        }
        fn be32(o: *std.ArrayList(u8), g: std.mem.Allocator, v: u32) !void {
            try be16(o, g, @intCast(v >> 16));
            try be16(o, g, @truncate(v));
        }
        fn below(r: *Rng, m: usize) usize {
            return @intCast((r.next() >> 11) % m);
        }
        fn signed(r: *Rng, m: usize) i32 {
            return @as(i32, @intCast(below(r, 2 * m + 1))) - @as(i32, @intCast(m));
        }
    };
    // Table directory.
    const tags = [_]*const [4]u8{ "cmap", "glyf", "head", "hhea", "hmtx", "kern", "loca", "maxp", "name", "post", "GDEF", "GPOS", "GSUB", "OS/2" };
    for (tags, 0..) |t, i| {
        try out.appendSlice(gpa, t);
        try F.be32(&out, gpa, @truncate(rng.next()));
        try F.be32(&out, gpa, @intCast(0x100 + i * 0x2000));
        try F.be32(&out, gpa, @intCast(0x400 + F.below(&rng, 0x8000)));
    }
    // Glyph outlines, to about 55 % of `n`.
    var glyph_starts: std.ArrayList(u32) = .empty;
    defer glyph_starts.deinit(gpa);
    const flag_set = [_]u8{ 0x01, 0x33, 0x37, 0x27, 0x07, 0x15, 0x35, 0x23, 0x31, 0x21 };
    while (out.items.len < n * 55 / 100) {
        try glyph_starts.append(gpa, @intCast(out.items.len));
        // A variation of an earlier glyph a third of the time.
        if (glyph_starts.items.len > 8 and F.below(&rng, 3) == 0) {
            const k = glyph_starts.items.len - 2 - F.below(&rng, @min(glyph_starts.items.len - 2, 40));
            const a = glyph_starts.items[k];
            const b = glyph_starts.items[k + 1];
            // Room first: the copy comes from the list itself.
            try out.ensureUnusedCapacity(gpa, b - a);
            out.appendSliceAssumeCapacity(out.items[a..b]);
            const len = b - a;
            for (0..F.below(&rng, 4)) |_| {
                const at = out.items.len - len + F.below(&rng, len);
                out.items[at] +%= @intCast(F.below(&rng, 5));
            }
            continue;
        }
        const contours = 1 + F.below(&rng, 3);
        try F.be16(&out, gpa, @intCast(contours));
        for (0..4) |_| try F.be16(&out, gpa, @bitCast(@as(i16, @intCast(F.signed(&rng, 1200)))));
        var pts: usize = 0;
        for (0..contours) |_| {
            pts += 4 + F.below(&rng, 24);
            try F.be16(&out, gpa, @intCast(pts - 1));
        }
        try F.be16(&out, gpa, 0); // no instructions
        var flags = try gpa.alloc(u8, pts);
        defer gpa.free(flags);
        var i: usize = 0;
        while (i < pts) {
            const f = flag_set[F.below(&rng, flag_set.len)];
            const run = @min(pts - i, 1 + F.below(&rng, 4));
            @memset(flags[i..][0..run], f);
            i += run;
        }
        try out.appendSlice(gpa, flags);
        // x then y deltas: a byte when the flag says short, else two.
        for ([2]u8{ 0x02, 0x04 }) |short| {
            for (flags) |f| {
                if (f & short != 0) {
                    try out.append(gpa, @intCast(F.below(&rng, 90)));
                } else if (f & (short << 3) == 0) {
                    try F.be16(&out, gpa, @bitCast(@as(i16, @intCast(F.signed(&rng, 400)))));
                }
            }
        }
        if (out.items.len % 2 == 1) try out.append(gpa, 0);
    }
    const glyphs = glyph_starts.items.len;
    // Offsets: increasing.
    for (glyph_starts.items) |g| try F.be32(&out, gpa, g);
    // Metrics: advance widths around a few common values, small bearings.
    const widths = [_]u16{ 600, 600, 600, 520, 680, 1000, 280 };
    for (0..glyphs) |_| {
        try F.be16(&out, gpa, widths[F.below(&rng, widths.len)] + @as(u16, @intCast(F.below(&rng, 3))));
        try F.be16(&out, gpa, @bitCast(@as(i16, @intCast(F.signed(&rng, 80)))));
    }
    // Character map segments: increasing codes.
    var code: u32 = 0x20;
    for (0..@min(glyphs, 2000)) |_| {
        const start = code + @as(u32, @intCast(F.below(&rng, 40)));
        const end = start + @as(u32, @intCast(F.below(&rng, 30)));
        try F.be16(&out, gpa, @truncate(end));
        try F.be16(&out, gpa, @truncate(start));
        try F.be16(&out, gpa, @truncate(F.below(&rng, glyphs)));
        try F.be16(&out, gpa, 0);
        code = end + 1;
    }
    // Kerning pairs: sorted left glyph, small negative values.
    var left: u64 = 0;
    while (out.items.len < n * 95 / 100) {
        left += F.below(&rng, 3);
        try F.be16(&out, gpa, @truncate(left));
        try F.be16(&out, gpa, @truncate(F.below(&rng, glyphs)));
        try F.be16(&out, gpa, @bitCast(@as(i16, @intCast(-@as(i32, @intCast(F.below(&rng, 120)))))));
    }
    // Names in UTF-16BE.
    const names = [_][]const u8{ "Copyright ", "Example Sans ", "Regular ", "Version 2.004 ", "ExampleSans-Regular ", "Designed by nobody in particular ", "Licensed for testing " };
    while (out.items.len < n) {
        for (names[F.below(&rng, names.len)]) |ch| try F.be16(&out, gpa, ch);
    }
    out.shrinkRetainingCapacity(n);
    return out.toOwnedSlice(gpa);
}

/// Literal runs over 64 letters (6 bits a literal: coded, never stored, and
/// no five-byte repeats by chance) alternating with copies of an earlier
/// stretch, each cut by a byte outside the letters: the insert and copy
/// lengths around the boundaries of `.q0`'s length codes (inserts 130,
/// 2114, 6210; copies 10, 72, 134, 136, 2118, 2120). The boundary copies
/// all come from the same distance after short inserts, so `.q0`, which
/// tries the last distance at every byte there, finds each at its first.
pub fn lengthsInput(gpa: std.mem.Allocator, seed: u64) ![]u8 {
    const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const inserts = [_]usize{ 1, 2, 3, 5, 6, 7 };
    const copies = [_]usize{ 5, 6, 9, 10, 11, 12, 13, 70, 71, 72, 73, 133, 134, 135, 136, 137, 2117, 2118, 2119, 2120, 2121 };
    const long_inserts = [_]usize{ 129, 130, 131, 2113, 2114, 2115, 4000, 6209, 6210, 7000 };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var rng = Rng{ .s = seed };
    const F = struct {
        fn run(o: *std.ArrayList(u8), g: std.mem.Allocator, r: *Rng, n: usize) !void {
            for (0..n) |_| try o.append(g, letters[@intCast(r.next() >> 58)]);
        }
        /// From `dist` back, or (0) from anywhere before.
        fn copy(o: *std.ArrayList(u8), g: std.mem.Allocator, r: *Rng, n: usize, dist: usize) !void {
            const src: usize = if (dist != 0) o.items.len - dist else @intCast(r.next() % (o.items.len - n - 1) + 1);
            // Not one byte longer at either end.
            const last = o.items.len - 1;
            if (o.items[last] == o.items[src - 1]) o.items[last] = if (o.items[last] == 'A') 'B' else 'A';
            try o.ensureUnusedCapacity(g, n + 1);
            const next = o.items[src + n];
            o.appendSliceAssumeCapacity(o.items[src..][0..n]);
            o.appendAssumeCapacity(if (next == '.') ',' else '.');
        }
    };
    try F.run(&out, gpa, &rng, 8000);
    for (copies, 0..) |c, k| {
        try F.run(&out, gpa, &rng, inserts[k % inserts.len]);
        try F.copy(&out, gpa, &rng, c, 5000);
    }
    for (long_inserts) |n| {
        try F.run(&out, gpa, &rng, n);
        try F.copy(&out, gpa, &rng, 300, 0);
    }
    return out.toOwnedSlice(gpa);
}

/// The encoder's meta-block size. `mixed`/`alice_cycle` shapes straddle it on
/// purpose: a stream that ends exactly on the boundary, and one byte past it,
/// have to terminate correctly.
pub const block = 1 << 20;

pub const Gen = union(enum) {
    /// Bytes given literally.
    literal: []const u8,
    /// `n` copies of one byte — the copy/insert length code boundaries.
    run: struct { byte: u8, n: usize },
    /// `buf[i] = i` truncated: every byte value, forcing a dense literal code.
    ramp: usize,
    /// `buf[i] = (i*7 + i/256) & 0xff` — the same alphabet, many times over.
    stride: usize,
    /// `alpha` distinct literals, flat or skewed: every simple-code shape and
    /// the first complex one.
    alphabet: struct { n: usize, alpha: usize, skewed: bool, seed: u64 },
    /// Incompressible: the store-mode fallback must still produce a stream
    /// the reference accepts.
    random: struct { n: usize, seed: u64 },
    /// `alice29.txt[0..n]` — text, including both sides of the window-bits
    /// switch at 65520 bytes.
    alice_prefix: usize,
    /// `alice[i % alice.len]`, `n` bytes: text repeated past a meta-block.
    alice_cycle: usize,
    /// `utf8_mix[0..n]` — non-Latin UTF-8 text.
    utf8_mix: usize,
    /// `fontLike(n, seed)` — binary data with sections.
    font_like: struct { n: usize, seed: u64 },
    /// Random on one side of `split`, text on the other: a stored block
    /// followed by a compressed final block, and the reverse.
    mixed: struct { n: usize, split: usize, random_first: bool, seed: u64 },
    /// `lengthsInput(seed)`: inserts and copies of chosen lengths.
    lengths: u64,
    /// `n` random bytes, then their first `copy` again: a long insert of
    /// incompressible literals before a match.
    random_copy: struct { n: usize, copy: usize, seed: u64 },
};

pub const Shape = struct { name: []const u8, gen: Gen };

/// Caller owns the returned bytes.
pub fn build(gpa: std.mem.Allocator, shape: Shape) ![]u8 {
    switch (shape.gen) {
        .literal => |s| return gpa.dupe(u8, s),
        .run => |r| {
            const buf = try gpa.alloc(u8, r.n);
            @memset(buf, r.byte);
            return buf;
        },
        .ramp => |n| {
            const buf = try gpa.alloc(u8, n);
            for (buf, 0..) |*b, i| b.* = @truncate(i);
            return buf;
        },
        .stride => |n| {
            const buf = try gpa.alloc(u8, n);
            for (buf, 0..) |*b, i| b.* = @truncate((i * 7 + i / 256) & 0xff);
            return buf;
        },
        .alphabet => |a| {
            const buf = try gpa.alloc(u8, a.n);
            var rng = Rng{ .s = a.seed };
            for (buf) |*b| {
                const r = rng.next();
                const pick: usize = if (a.skewed and (r >> 40) % 10 != 0)
                    0
                else
                    // The remainder in u64, never in `usize`: truncating
                    // first kept 32 bits on a 32-bit target, a different
                    // input than the reference judged (alpha 3 and 5).
                    @intCast((r >> 3) % a.alpha);
                b.* = @intCast(pick * 37 + 1);
            }
            return buf;
        },
        .random => |r| {
            const buf = try gpa.alloc(u8, r.n);
            var rng = Rng{ .s = r.seed };
            for (buf) |*b| b.* = rng.byte();
            return buf;
        },
        .alice_prefix => |n| return gpa.dupe(u8, alice[0..n]),
        .utf8_mix => |n| return gpa.dupe(u8, utf8_mix[0..n]),
        .font_like => |f| return fontLike(gpa, f.n, f.seed),
        .alice_cycle => |n| {
            const buf = try gpa.alloc(u8, n);
            for (buf, 0..) |*b, i| b.* = alice[i % alice.len];
            return buf;
        },
        .lengths => |seed| return lengthsInput(gpa, seed),
        .random_copy => |r| {
            const buf = try gpa.alloc(u8, r.n + r.copy);
            var rng = Rng{ .s = r.seed };
            for (buf[0..r.n]) |*b| b.* = rng.byte();
            @memcpy(buf[r.n..], buf[0..r.copy]);
            return buf;
        },
        .mixed => |m| {
            const buf = try gpa.alloc(u8, m.n);
            var rng = Rng{ .s = m.seed };
            for (buf, 0..) |*b, i| {
                const random_here = (i < m.split) == m.random_first;
                b.* = if (random_here) rng.byte() else alice[i % alice.len];
            }
            return buf;
        },
    }
}

const seed_a = 0x9e37_79b9_7f4a_7c15;
const seed_b = 0x243f_6a88_85a3_08d3;

/// Every shape google/brotli has decoded our encoder's output for. The names
/// are the fixture keys in `testdata/interop_blessed.zig`, so renaming one is
/// a loud failure, not a silent loss.
pub const shapes = [_]Shape{
    // Degenerate and tiny.
    .{ .name = "empty", .gen = .{ .literal = "" } },
    .{ .name = "one_byte", .gen = .{ .literal = "x" } },
    .{ .name = "two_bytes", .gen = .{ .literal = "xy" } },
    .{ .name = "three_bytes", .gen = .{ .literal = "xyz" } },
    .{ .name = "four_same", .gen = .{ .literal = "aaaa" } },
    .{ .name = "nul", .gen = .{ .literal = "\x00" } },
    .{ .name = "five_ff", .gen = .{ .literal = "\xff\xff\xff\xff\xff" } },
    .{ .name = "hello_repeated", .gen = .{ .literal = "hello world hello world hello world" } },

    // Runs of one byte around the copy/insert length code boundaries.
    .{ .name = "run_1", .gen = .{ .run = .{ .byte = 'q', .n = 1 } } },
    .{ .name = "run_2", .gen = .{ .run = .{ .byte = 'q', .n = 2 } } },
    .{ .name = "run_3", .gen = .{ .run = .{ .byte = 'q', .n = 3 } } },
    .{ .name = "run_4", .gen = .{ .run = .{ .byte = 'q', .n = 4 } } },
    .{ .name = "run_5", .gen = .{ .run = .{ .byte = 'q', .n = 5 } } },
    .{ .name = "run_6", .gen = .{ .run = .{ .byte = 'q', .n = 6 } } },
    .{ .name = "run_9", .gen = .{ .run = .{ .byte = 'q', .n = 9 } } },
    .{ .name = "run_10", .gen = .{ .run = .{ .byte = 'q', .n = 10 } } },
    .{ .name = "run_63", .gen = .{ .run = .{ .byte = 'q', .n = 63 } } },
    .{ .name = "run_64", .gen = .{ .run = .{ .byte = 'q', .n = 64 } } },
    .{ .name = "run_65", .gen = .{ .run = .{ .byte = 'q', .n = 65 } } },
    .{ .name = "run_1000", .gen = .{ .run = .{ .byte = 'q', .n = 1000 } } },
    .{ .name = "run_22593", .gen = .{ .run = .{ .byte = 'q', .n = 22593 } } },
    .{ .name = "run_22594", .gen = .{ .run = .{ .byte = 'q', .n = 22594 } } },
    .{ .name = "run_22595", .gen = .{ .run = .{ .byte = 'q', .n = 22595 } } },

    // Dense literal alphabets.
    .{ .name = "ramp_256", .gen = .{ .ramp = 256 } },
    .{ .name = "stride_10240", .gen = .{ .stride = 256 * 40 } },

    // 1..5 distinct literals, flat and skewed.
    .{ .name = "alpha1_flat", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 1, .skewed = false, .seed = seed_a } } },
    .{ .name = "alpha1_skew", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 1, .skewed = true, .seed = seed_a +% 1 } } },
    .{ .name = "alpha2_flat", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 2, .skewed = false, .seed = seed_a +% 2 } } },
    .{ .name = "alpha2_skew", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 2, .skewed = true, .seed = seed_a +% 3 } } },
    .{ .name = "alpha3_flat", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 3, .skewed = false, .seed = seed_a +% 4 } } },
    .{ .name = "alpha3_skew", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 3, .skewed = true, .seed = seed_a +% 5 } } },
    .{ .name = "alpha4_flat", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 4, .skewed = false, .seed = seed_a +% 6 } } },
    .{ .name = "alpha4_skew", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 4, .skewed = true, .seed = seed_a +% 7 } } },
    .{ .name = "alpha5_flat", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 5, .skewed = false, .seed = seed_a +% 8 } } },
    .{ .name = "alpha5_skew", .gen = .{ .alphabet = .{ .n = 30000, .alpha = 5, .skewed = true, .seed = seed_a +% 9 } } },

    // Incompressible: the store-mode fallback.
    .{ .name = "random_16", .gen = .{ .random = .{ .n = 16, .seed = seed_b } } },
    .{ .name = "random_1000", .gen = .{ .random = .{ .n = 1000, .seed = seed_b +% 1 } } },
    .{ .name = "random_70000", .gen = .{ .random = .{ .n = 70000, .seed = seed_b +% 2 } } },

    // Text, and text across the window-bits switch at 65520 bytes.
    .{ .name = "alice_65519", .gen = .{ .alice_prefix = 65519 } },
    .{ .name = "alice_65521", .gen = .{ .alice_prefix = 65521 } },
    .{ .name = "alice_full", .gen = .{ .alice_prefix = alice.len } },
    // Sizes `.q0` treats apart: a match table of 2^13 slots (an odd power
    // from 2^12), and a meta-block of exactly 2^16 (four MLEN nibbles).
    .{ .name = "alice_3000", .gen = .{ .alice_prefix = 3000 } },
    .{ .name = "alice_65536", .gen = .{ .alice_prefix = 65536 } },
    // `.q0`'s length codes at their boundaries; a long incompressible
    // insert before a match (`.q0` stores what came before it).
    .{ .name = "lengths", .gen = .{ .lengths = seed_a +% 11 } },
    .{ .name = "random_8000_copy", .gen = .{ .random_copy = .{ .n = 8000, .copy = 600, .seed = seed_b +% 5 } } },
    // Non-Latin UTF-8: the UTF8 context mode's lead-byte classes.
    .{ .name = "utf8_mix", .gen = .{ .utf8_mix = utf8_mix.len } },
    // Binary data with sections of different statistics: block types.
    .{ .name = "font_like", .gen = .{ .font_like = .{ .n = 200_000, .seed = seed_a +% 10 } } },

    // Multi-meta-block: stored and compressed blocks in both orders, and the
    // block boundary itself.
    .{ .name = "mixed_random_first", .gen = .{ .mixed = .{ .n = block + 40000, .split = block, .random_first = true, .seed = seed_b +% 3 } } },
    .{ .name = "mixed_text_first", .gen = .{ .mixed = .{ .n = block + 40000, .split = block, .random_first = false, .seed = seed_b +% 4 } } },
    .{ .name = "block_exact", .gen = .{ .alice_cycle = block } },
    .{ .name = "block_plus_one", .gen = .{ .alice_cycle = block + 1 } },
};

/// The shape named `name` (a corpus typo is a build failure).
pub fn shapeNamed(comptime name: []const u8) Shape {
    inline for (shapes) |sh| {
        if (comptime std.mem.eql(u8, sh.name, name)) return sh;
    }
    @compileError("no corpus shape '" ++ name ++ "'");
}

// ── raw prefix dictionaries (RFC 9841 §3.2, RFC 9842 `dcb`) ────────────────

/// A slice of a shape's bytes.
pub const Piece = struct {
    shape: []const u8,
    from: usize = 0,
    to: ?usize = null,

    pub fn build(comptime p: Piece, gpa: std.mem.Allocator) ![]u8 {
        const all = try corpusBuild(gpa, shapeNamed(p.shape));
        defer gpa.free(all);
        return gpa.dupe(u8, all[p.from..(p.to orelse all.len)]);
    }
};

/// An input compressed against a raw prefix dictionary. Python's `brotli`
/// cannot attach one, so the reference here is libbrotli itself
/// (`tools/c_oracle/shared_oracle.c`).
pub const DictCase = struct {
    name: []const u8,
    dict: Piece,
    input: Piece,
    lgwin: u5,
};

pub const dict_cases = [_]DictCase{
    // Overlapping text: long copies out of the dictionary.
    .{ .name = "alice_head_tail", .dict = .{ .shape = "alice_full", .to = 60_000 }, .input = .{ .shape = "alice_full", .from = 52_089, .to = 100_000 }, .lgwin = 22 },
    // The input goes on where the dictionary stops: copies that start in
    // the dictionary and run on into the window's first bytes.
    .{ .name = "alice_split", .dict = .{ .shape = "alice_full", .to = 1_000 }, .input = .{ .shape = "alice_full", .from = 1_000, .to = 40_000 }, .lgwin = 22 },
    // An input past a 64 KiB window: the dictionary stays reachable beyond
    // the window, at distances past `max_backward`.
    .{ .name = "alice_w16", .dict = .{ .shape = "alice_full", .to = 30_000 }, .input = .{ .shape = "alice_full", .to = 80_000 }, .lgwin = 16 },
    // Binary: the dictionary is random bytes the input repeats.
    .{ .name = "random_w18", .dict = .{ .shape = "random_70000", .to = 40_000 }, .input = .{ .shape = "random_70000", .from = 15_000, .to = 35_000 }, .lgwin = 18 },
    // A dictionary five times a 1 KiB window.
    .{ .name = "alice_w10", .dict = .{ .shape = "alice_full", .to = 5_000 }, .input = .{ .shape = "alice_full", .from = 3_000, .to = 20_000 }, .lgwin = 10 },
};

/// The qualities the reference compresses each `DictCase` at: q2 does not
/// search the dictionary (its quick hashers have no compound-dictionary
/// form: 18 836 vs 18 832 bytes without, alice29, 2026-10-16) but still
/// counts static-dictionary words past it; q5+ search it with the deep
/// hashers and context modelling, q11 with the optimal parse.
pub const dict_qualities = [_]u8{ 2, 5, 9, 11 };

/// `testdata/ref/dict/<case>.q<Q>.br`.
pub fn dictRefFile(comptime c: DictCase, comptime q: u8) []const u8 {
    return std.fmt.comptimePrint("dict/{s}.q{d}.br", .{ c.name, q });
}

/// Our encoder's stream for a `DictCase` at `effort` (its window, its
/// dictionary). Blessed as `.name = case`, `.effort = "dict_" ++ effort`.
pub fn encodeDict(gpa: std.mem.Allocator, comptime c: DictCase, effort: brotli.Effort) ![]u8 {
    const dict = try c.dict.build(gpa);
    defer gpa.free(dict);
    const input = try c.input.build(gpa);
    defer gpa.free(input);
    return brotli.compressWith(gpa, input, .{ .effort = effort, .window_bits = c.lgwin, .dictionary = dict });
}

pub const dict_efforts = [_][]const u8{ "q0", "q1", "q4", "q6", "q9", "q11" };

// ── the large window (RFC 9841 §6) ──────────────────────────────────────────

/// An input for a large-window stream.
pub const LargeInput = union(enum) {
    piece: Piece,
    /// `block` random bytes, `gap` zeros, the same `block` bytes again: a
    /// copy from `block + gap` back, past a 24-bit window when `gap` is.
    far: struct { block: usize, gap: usize, seed: u64 },

    pub fn build(comptime li: LargeInput, gpa: std.mem.Allocator) ![]u8 {
        switch (li) {
            .piece => |p| return p.build(gpa),
            .far => |f| {
                const out = try gpa.alloc(u8, 2 * f.block + f.gap);
                var rng: Rng = .{ .s = f.seed };
                for (out[0..f.block]) |*b| b.* = rng.byte();
                @memset(out[f.block..][0..f.gap], 0);
                @memcpy(out[f.block + f.gap ..], out[0..f.block]);
                return out;
            },
        }
    }
};

pub const LargeCase = struct { name: []const u8, input: LargeInput, lgwin: u6 };

/// Large-window streams libbrotli makes (`BROTLI_PARAM_LARGE_WINDOW`).
pub const large_cases = [_]LargeCase{
    // The header and the 62-bit distance alphabet's code widths, short
    // distances.
    .{ .name = "alice_w25", .input = .{ .piece = .{ .shape = "alice_full", .to = 20_000 } }, .lgwin = 25 },
    // A copy from 17 MiB back: beyond any RFC 7932 window.
    .{ .name = "far_w25", .input = .{ .far = .{ .block = 32 * 1024, .gap = 17 << 20, .seed = 0x1a59e } }, .lgwin = 25 },
    .{ .name = "far_w30", .input = .{ .far = .{ .block = 4 * 1024, .gap = 17 << 20, .seed = 0x1a59f } }, .lgwin = 30 },
};
pub const large_qualities = [_]u8{ 5, 11 };

/// Our encoder's large-window stream for `c` at `effort` (the case's
/// window). Blessed as `.name = case`, `.effort = "large_" ++ effort`.
pub fn encodeLarge(gpa: std.mem.Allocator, comptime c: LargeCase, effort: brotli.Effort) ![]u8 {
    const input = try c.input.build(gpa);
    defer gpa.free(input);
    return brotli.compressWith(gpa, input, .{ .effort = effort, .window_bits = c.lgwin });
}

pub const large_efforts = [_][]const u8{ "q1", "q4", "q6", "q11" };

/// `testdata/ref/large/<case>.q<Q>.br`.
pub fn largeRefFile(comptime c: LargeCase, comptime q: u8) []const u8 {
    return std.fmt.comptimePrint("large/{s}.q{d}.br", .{ c.name, q });
}

// ── serialized shared dictionaries (RFC 9841 §5) ──────────────────────────

/// A serialized shared dictionary, generated: an LZ77 part, a word list
/// harvested from text, a transform list, one or two dictionaries.
pub const SerialSpec = struct {
    lz77: ?Piece = null,
    /// Words of 4..31 letters (and `'`), first occurrences in order, up to
    /// `1 << words_bits` per length.
    words: ?Piece = null,
    words_bits: u4 = 8,
    /// A custom transform list (`custom_transforms`).
    transforms: bool = false,
    /// Two dictionaries — the custom pair and RFC 7932's words with the same
    /// transforms — chosen by the literal context (contexts 0..31 the first,
    /// 32..63 the second).
    by_context: bool = false,
};

/// The custom transform list: stringlets " ", ", ", "the ", "." and the
/// empty one; triplets in google/brotli's order (prefix, operation,
/// suffix); every operation kind once, the shifts with parameters.
pub const custom_transforms = struct {
    pub const stringlets = [_][]const u8{ " ", ", ", "the ", "." };
    /// prefix index, operation, suffix index (4 = the empty stringlet).
    pub const triplets = [_][3]u8{
        .{ 4, 0, 4 },  .{ 4, 0, 0 },  .{ 0, 0, 4 },  .{ 2, 0, 0 },  .{ 4, 10, 4 }, .{ 4, 11, 0 },
        .{ 4, 1, 4 },  .{ 4, 3, 1 },  .{ 4, 9, 4 },  .{ 4, 12, 4 }, .{ 0, 14, 3 }, .{ 4, 20, 4 },
        .{ 4, 21, 4 }, .{ 4, 22, 4 }, .{ 0, 22, 0 },
    };
    pub const params = [_]u16{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFFFF, 0x20 };
};

/// The bytes of `spec`'s dictionary.
pub fn serialize(gpa: std.mem.Allocator, comptime spec: SerialSpec) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, &.{ 0x91, 0x00 });
    // LZ77_DICTIONARY_LENGTH as a varint, then the bytes.
    const lz = if (spec.lz77) |p| try p.build(gpa) else try gpa.alloc(u8, 0);
    defer gpa.free(lz);
    var n = lz.len;
    while (true) {
        const b: u8 = @intCast(n & 0x7f);
        n >>= 7;
        try out.append(gpa, if (n != 0) b | 0x80 else b);
        if (n == 0) break;
    }
    try out.appendSlice(gpa, lz);
    // NUM_CUSTOM_WORD_LISTS and the list.
    if (spec.words) |p| {
        try out.append(gpa, 1);
        const text = try p.build(gpa);
        defer gpa.free(text);
        var by_len: [32]std.ArrayList([]const u8) = @splat(.empty);
        defer for (&by_len) |*l| l.deinit(gpa);
        var i: usize = 0;
        while (i < text.len) {
            if (!isWordByte(text[i])) {
                i += 1;
                continue;
            }
            var j = i;
            while (j < text.len and isWordByte(text[j])) j += 1;
            const w = text[i..j];
            i = j;
            if (w.len < 4 or w.len > 31) continue;
            const list = &by_len[w.len];
            if (list.items.len >= @as(usize, 1) << spec.words_bits) continue;
            for (list.items) |x| {
                if (std.mem.eql(u8, x, w)) break;
            } else try list.append(gpa, w);
        }
        var bits: [32]u8 = @splat(0);
        for (4..32) |l| {
            const have = by_len[l].items.len;
            if (have == 0) continue;
            bits[l] = @intCast(std.math.log2_int(usize, have));
        }
        try out.appendSlice(gpa, bits[4..32]);
        for (4..32) |l| {
            if (bits[l] == 0) continue;
            for (by_len[l].items[0 .. @as(usize, 1) << @intCast(bits[l])]) |w| try out.appendSlice(gpa, w);
        }
    } else try out.append(gpa, 0);
    // NUM_CUSTOM_TRANSFORM_LISTS and the list.
    if (spec.transforms) {
        try out.append(gpa, 1);
        const ct = custom_transforms;
        var ps: std.ArrayList(u8) = .empty;
        defer ps.deinit(gpa);
        for (ct.stringlets) |x| {
            try ps.append(gpa, @intCast(x.len));
            try ps.appendSlice(gpa, x);
        }
        try ps.append(gpa, 0);
        try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(ps.items.len))));
        try out.appendSlice(gpa, ps.items);
        try out.append(gpa, ct.triplets.len);
        for (ct.triplets) |t| try out.appendSlice(gpa, &t);
        for (ct.params) |x| try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, x)));
    } else try out.append(gpa, 0);
    // NUM_DICTIONARIES, the map, CONTEXT_ENABLED, the context map.
    if (spec.words != null or spec.transforms) {
        const nw: u8 = @intFromBool(spec.words != null);
        const nt: u8 = @intFromBool(spec.transforms);
        const custom_pair = [2]u8{ 0, if (nt == 1) 0 else nt };
        if (spec.by_context) {
            try out.append(gpa, 2);
            try out.appendSlice(gpa, &custom_pair);
            try out.appendSlice(gpa, &.{ nw, if (nt == 1) 0 else nt }); // RFC 7932's words
            try out.append(gpa, 1);
            for (0..64) |c| try out.append(gpa, @intFromBool(c >= 32));
        } else {
            try out.append(gpa, 1);
            try out.appendSlice(gpa, &custom_pair);
            try out.append(gpa, 0);
        }
    }
    return out.toOwnedSlice(gpa);
}

fn isWordByte(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '\'';
}

pub const SerialCase = struct { name: []const u8, dict: SerialSpec, input: Piece };

/// Streams libbrotli makes against a serialized dictionary — which only a
/// build of it with BROTLI_EXPERIMENTAL can (`interop -- --brotli-src`).
pub const serial_cases = [_]SerialCase{
    .{ .name = "ser_lz77", .dict = .{ .lz77 = .{ .shape = "alice_full", .to = 20_000 } }, .input = .{ .shape = "alice_full", .from = 10_000, .to = 40_000 } },
    .{ .name = "ser_words", .dict = .{ .words = .{ .shape = "alice_full" } }, .input = .{ .shape = "alice_full", .from = 100_000, .to = 130_000 } },
    .{ .name = "ser_words_tr", .dict = .{ .words = .{ .shape = "alice_full" }, .transforms = true }, .input = .{ .shape = "alice_full", .from = 100_000, .to = 130_000 } },
    .{ .name = "ser_tr", .dict = .{ .transforms = true }, .input = .{ .shape = "alice_full", .from = 100_000, .to = 130_000 } },
    .{ .name = "ser_ctx", .dict = .{ .lz77 = .{ .shape = "alice_full", .to = 4_000 }, .words = .{ .shape = "alice_full" }, .transforms = true, .by_context = true }, .input = .{ .shape = "alice_full", .from = 100_000, .to = 130_000 } },
};
pub const serial_qualities = [_]u8{ 5, 9, 11 };

/// `testdata/ref/serial/<case>.q<Q>.br`.
pub fn serialRefFile(comptime c: SerialCase, comptime q: u8) []const u8 {
    return std.fmt.comptimePrint("serial/{s}.q{d}.br", .{ c.name, q });
}

const corpusBuild = build;

// ── the reference's own streams ─────────────────────────────────────────────

/// One `brotli.compress(input, quality=q, lgwin=w, mode=MODE_GENERIC)` run,
/// captured into `testdata/ref/`. Our decoder must reproduce `input` from it.
///
/// `input` names a file already committed under `testdata/` (the google/brotli
/// corpus), so the plaintext side needs no new bytes and the comparison is
/// against data the reference project itself publishes.
pub const RefStream = struct {
    input: []const u8,
    quality: u8,
    lgwin: u8,
    /// File under `testdata/ref/`.
    file: []const u8,
};

/// The matrix. `alice29.txt` at five qualities is what the live test compared
/// before this became a fixture; the rest is what a committed fixture makes
/// affordable — the reference exercising encoder features this module does not
/// emit itself (context modelling, block splitting, distance short codes) over
/// text, UTF-16 bytes, incompressible data, long runs and the degenerate
/// inputs, plus three window sizes our own encoder never chooses.
pub const ref_streams = [_]RefStream{
    .{ .input = "alice29.txt", .quality = 0, .lgwin = 22, .file = "alice29.txt.q0.w22.br" },
    .{ .input = "alice29.txt", .quality = 1, .lgwin = 22, .file = "alice29.txt.q1.w22.br" },
    .{ .input = "alice29.txt", .quality = 5, .lgwin = 22, .file = "alice29.txt.q5.w22.br" },
    .{ .input = "alice29.txt", .quality = 9, .lgwin = 22, .file = "alice29.txt.q9.w22.br" },
    .{ .input = "alice29.txt", .quality = 11, .lgwin = 22, .file = "alice29.txt.q11.w22.br" },

    // Window bits the header must carry, on an input long enough to use them.
    .{ .input = "quickfox_repeated", .quality = 11, .lgwin = 10, .file = "quickfox_repeated.q11.w10.br" },
    .{ .input = "quickfox_repeated", .quality = 11, .lgwin = 16, .file = "quickfox_repeated.q11.w16.br" },
    .{ .input = "quickfox_repeated", .quality = 11, .lgwin = 24, .file = "quickfox_repeated.q11.w24.br" },

    .{ .input = "monkey", .quality = 1, .lgwin = 22, .file = "monkey.q1.w22.br" },
    .{ .input = "monkey", .quality = 11, .lgwin = 22, .file = "monkey.q11.w22.br" },
    .{ .input = "ukkonooa", .quality = 1, .lgwin = 22, .file = "ukkonooa.q1.w22.br" },
    .{ .input = "ukkonooa", .quality = 11, .lgwin = 22, .file = "ukkonooa.q11.w22.br" },
    .{ .input = "cp852-utf8", .quality = 1, .lgwin = 22, .file = "cp852-utf8.q1.w22.br" },
    .{ .input = "cp852-utf8", .quality = 11, .lgwin = 22, .file = "cp852-utf8.q11.w22.br" },
    .{ .input = "cp1251-utf16le", .quality = 1, .lgwin = 22, .file = "cp1251-utf16le.q1.w22.br" },
    .{ .input = "cp1251-utf16le", .quality = 11, .lgwin = 22, .file = "cp1251-utf16le.q11.w22.br" },
    .{ .input = "zeros", .quality = 1, .lgwin = 22, .file = "zeros.q1.w22.br" },
    .{ .input = "zeros", .quality = 11, .lgwin = 22, .file = "zeros.q11.w22.br" },
    .{ .input = "random_org_10k.bin", .quality = 1, .lgwin = 22, .file = "random_org_10k.bin.q1.w22.br" },
    .{ .input = "random_org_10k.bin", .quality = 11, .lgwin = 22, .file = "random_org_10k.bin.q11.w22.br" },
    .{ .input = "x", .quality = 1, .lgwin = 22, .file = "x.q1.w22.br" },
    .{ .input = "x", .quality = 11, .lgwin = 22, .file = "x.q11.w22.br" },
    .{ .input = "empty", .quality = 1, .lgwin = 22, .file = "empty.q1.w22.br" },
    .{ .input = "empty", .quality = 11, .lgwin = 22, .file = "empty.q11.w22.br" },

    // UTF8-mode context modelling over every two-byte lead-byte class
    // (`tools/gen_utf8_mix.py`): 0xD0..0xDF as `p2` was misclassed until
    // 2026-10-15, and these streams were refused.
    .{ .input = "utf8-mix", .quality = 5, .lgwin = 22, .file = "utf8-mix.q5.w22.br" },
    .{ .input = "utf8-mix", .quality = 9, .lgwin = 22, .file = "utf8-mix.q9.w22.br" },
    .{ .input = "utf8-mix", .quality = 11, .lgwin = 22, .file = "utf8-mix.q11.w22.br" },
};

/// How a shape is encoded for the reference to judge. Every effort is
/// blessed separately on every shape: they emit different streams (match
/// search depth, context modelling or not), so one blessing cannot stand
/// for the others. The variants after them cover what the defaults never
/// emit — the window sizes `compressWith` does not pick by itself (the
/// header's rarer WBITS codes, copies capped by a small window) and the
/// `StreamWriter` (flushes: empty metadata meta-blocks, blocks cut where a
/// flush falls; history slid under a small window) — on a few shapes each.
pub const Encoding = struct {
    /// The blessed entry's `effort` field.
    tag: []const u8,
    effort: []const u8,
    window_bits: ?u5 = null,
    block_size: usize = brotli.CompressOptions.default_block_size,
    /// Through a `StreamWriter` (written in pieces of 4 093 bytes), with a
    /// flush after each of these input offsets that the input reaches.
    /// Null: `compressWith`.
    flushes: ?[]const usize = null,
    /// With `flushes`: metadata meta-blocks (`StreamWriter.writeMetadata`,
    /// 300 bytes each) at these input offsets, after the flushes there.
    metadata_at: []const usize = &.{},
    /// The shapes it is blessed on; null: all of them.
    shapes: ?[]const []const u8 = null,

    pub fn covers(e: Encoding, shape: []const u8) bool {
        const list = e.shapes orelse return true;
        for (list) |n| if (std.mem.eql(u8, n, shape)) return true;
        return false;
    }
};

pub const encodings = [_]Encoding{
    .{ .tag = "q0", .effort = "q0" },
    .{ .tag = "q1", .effort = "q1" },
    .{ .tag = "q4", .effort = "q4" },
    .{ .tag = "q6", .effort = "q6" },
    .{ .tag = "q9", .effort = "q9" },
    .{ .tag = "q11", .effort = "q11" },
    .{ .tag = "w10", .effort = "q6", .window_bits = 10, .shapes = &.{ "hello_repeated", "run_1000", "alice_full" } },
    .{ .tag = "w15_q4", .effort = "q4", .window_bits = 15, .shapes = &.{ "random_70000", "alice_full" } },
    .{ .tag = "w17_q9", .effort = "q9", .window_bits = 17, .shapes = &.{ "mixed_text_first", "alice_full" } },
    .{ .tag = "w24", .effort = "q6", .window_bits = 24, .shapes = &.{"block_plus_one"} },
    .{ .tag = "stream", .effort = "q6", .window_bits = 22, .block_size = 65_536, .flushes = &.{ 0, 1, 1_000, 65_536, 100_000 }, .shapes = &.{ "empty", "one_byte", "mixed_random_first", "alice_full" } },
    .{ .tag = "stream_q4_w16", .effort = "q4", .window_bits = 16, .block_size = 40_000, .flushes = &.{12_345}, .shapes = &.{ "random_70000", "alice_full" } },
    .{ .tag = "stream_q1_w16", .effort = "q1", .window_bits = 16, .block_size = 40_000, .flushes = &.{12_345}, .shapes = &.{ "random_70000", "alice_full" } },
    // `.q0` across flushes: each block's command code comes from the one
    // before; a first block of 3 000 bytes in a table sized for the stream
    // takes `.q0`'s odd-power table (2^13), as a one-shot input never does.
    .{ .tag = "stream_q0", .effort = "q0", .window_bits = 22, .flushes = &.{ 3_000, 20_000, 120_000 }, .shapes = &.{ "alice_full", "lengths" } },
    .{ .tag = "stream_metadata", .effort = "q6", .window_bits = 22, .flushes = &.{}, .metadata_at = &.{ 0, 5_000, 5_000 }, .shapes = &.{ "empty", "alice_full" } },
};

/// The stream `e` makes of `input`.
pub fn encode(gpa: std.mem.Allocator, input: []const u8, e: Encoding) ![]u8 {
    const effort = std.meta.stringToEnum(brotli.Effort, e.effort).?;
    const flushes = e.flushes orelse
        return brotli.compressWith(gpa, input, .{ .effort = effort, .window_bits = e.window_bits, .block_size = e.block_size });
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var buf: [4093]u8 = undefined;
    var sw: brotli.StreamWriter = try .init(gpa, &out.writer, &buf, .{ .effort = effort, .window_bits = e.window_bits.?, .block_size = e.block_size });
    defer sw.deinit();
    const meta: [300]u8 = @splat('m');
    var i: usize = 0;
    var f: usize = 0;
    var m: usize = 0;
    while (true) {
        while (f < flushes.len and flushes[f] == i) : (f += 1) try sw.writer.flush();
        while (m < e.metadata_at.len and e.metadata_at[m] == i) : (m += 1) try sw.writeMetadata(&meta);
        if (i == input.len) break;
        var next = if (f < flushes.len) @min(flushes[f], input.len) else input.len;
        if (m < e.metadata_at.len) next = @min(next, e.metadata_at[m]);
        const end = @min(next, i + buf.len);
        try sw.writer.writeAll(input[i..end]);
        i = end;
    }
    try sw.finish();
    return out.toOwnedSlice();
}

const brotli = @import("root.zig");

/// What the reference's decoder said about our encoder's output, frozen.
pub const blessed = @import("testdata/interop_blessed.zig");
