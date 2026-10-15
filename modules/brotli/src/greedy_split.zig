// SPDX-License-Identifier: MIT
//! The meta-block model of `.q6` and `.q9`: greedy, one-pass block splitting
//! of the literal, command and distance streams, and a static literal context
//! map of one to three contexts chosen from a sample of the input — no
//! histogram clustering. `.q11` keeps the iterative splitter
//! (`block_split.zig`) and clustered context maps.
//!
//! Ported from google/brotli 1.2.0 (MIT; copyright Google Inc., see this
//! module's NOTICE): `c/enc/metablock_inc.h` (`BlockSplitter`),
//! `c/enc/metablock.c` (`ContextBlockSplitter`, `BrotliBuildMetaBlockGreedy`),
//! `c/enc/encode.c` (`ChooseContextMap`, `DecideOverLiteralContextModeling`)
//! and `c/enc/bit_cost.c` (`BrotliBitsEntropy`) — the reference's model for
//! qualities 4–9. Changes: block lengths are the real symbol counts (the
//! reference rounds a short last block up to the minimum, which a decoder
//! never notices but `BlockCodes` checks); the 13-context map the reference
//! uses for inputs of 1 MiB and more is not ported (SPEC Backlog R14).

const std = @import("std");
const block_split = @import("block_split.zig");

/// RFC 7932 §6: at most 256 block types per category.
pub const max_block_types = 256;
/// Most literal contexts of a static map here.
pub const max_contexts = 3;

const log2_table: [256]f64 = blk: {
    var t: [256]f64 = undefined;
    t[0] = 0;
    for (1..256) |i| t[i] = @log2(@as(f64, @floatFromInt(i)));
    break :blk t;
};

inline fn fastLog2(v: usize) f64 {
    if (v < log2_table.len) return log2_table[v];
    return @log2(@as(f64, @floatFromInt(v)));
}

/// `BrotliBitsEntropy`: Shannon bits of the counts, at least one bit per
/// symbol (each is coded alone by a prefix code).
pub fn bitsEntropy(h: []const u32) f64 {
    var sum: usize = 0;
    var r: f64 = 0;
    for (h) |p| {
        sum += p;
        r -= @as(f64, @floatFromInt(p)) * fastLog2(p);
    }
    if (sum != 0) r += @as(f64, @floatFromInt(sum)) * fastLog2(sum);
    return @max(r, @as(f64, @floatFromInt(sum)));
}

/// `EstimateEntropy`: Shannon bits of the counts, no floor.
fn estimateEntropy(h: []const u32) f64 {
    var total: usize = 0;
    var r: f64 = 0;
    for (h) |p| {
        total += p;
        r += @as(f64, @floatFromInt(p)) * fastLog2(p);
    }
    return @as(f64, @floatFromInt(total)) * fastLog2(total) - r;
}

/// Zero `buf` with vector stores: `@memset` on a few hundred bytes or more is
/// Zig 0.16's byte-wise `compiler_rt.memset` (as `Matcher.fillZero`).
fn zero(buf: []u32) void {
    const V = @Vector(8, u32);
    const v: V = @splat(0);
    const p: [*]volatile u32 = buf.ptr;
    var i: usize = 0;
    while (i + 8 <= buf.len) : (i += 8) {
        const w: *align(4) volatile V = @ptrCast(p + i);
        w.* = v;
    }
    while (i < buf.len) : (i += 1) p[i] = 0;
}

/// Context id (UTF8 mode) -> one of two contexts: after a byte 0x80..0xBF
/// or not (`kStaticContextMapSimpleUTF8`).
const map_simple_utf8: [64]u8 = .{ 0, 0, 1, 1 } ++ .{0} ** 60;
/// Three contexts: after ASCII, after a UTF-8 lead byte, after a
/// continuation byte (`kStaticContextMapContinuation`).
const map_continuation: [64]u8 = .{ 1, 1, 2, 2 } ++ .{0} ** 60;
pub const map_single: [64]u8 = .{0} ** 64;

pub const StaticContexts = struct {
    n: u32,
    /// UTF8-mode context id -> context.
    map: *const [64]u8,
};

/// The literal contexts for a meta-block over `data` at `quality` (5..9;
/// `DecideOverLiteralContextModeling` without the 1 MiB branch): the bigram
/// entropy of the top two bits of each byte, sampled as 64-byte strides
/// every 4 KiB. Three contexts only from quality 7.
pub fn chooseStaticContexts(data: []const u8, quality: u4) StaticContexts {
    const one: StaticContexts = .{ .n = 1, .map = &map_single };
    if (quality < 5 or data.len < 64) return one;
    const lut = [4]u32{ 0, 0, 1, 2 };
    var bigram: [9]u32 = @splat(0);
    var at: usize = 0;
    while (at + 64 <= data.len) : (at += 4096) {
        var prev = lut[data[at] >> 6] * 3;
        for (data[at + 1 .. at + 64]) |b| {
            bigram[prev + lut[b >> 6]] += 1;
            prev = lut[b >> 6] * 3;
        }
    }
    var mono: [3]u32 = @splat(0);
    var two: [6]u32 = @splat(0);
    for (bigram, 0..) |c, i| {
        mono[i % 3] += c;
        two[i % 6] += c;
    }
    var e: [4]f64 = undefined;
    e[1] = estimateEntropy(&mono);
    e[2] = estimateEntropy(two[0..3]) + estimateEntropy(two[3..6]);
    e[3] = 0;
    for (0..3) |i| e[3] += estimateEntropy(bigram[3 * i ..][0..3]);
    const total = mono[0] + mono[1] + mono[2];
    e[0] = 1.0 / @as(f64, @floatFromInt(total));
    e[1] *= e[0];
    e[2] *= e[0];
    e[3] *= e[0];
    // Three contexts cost decoding speed: not below quality 7.
    if (quality < 7) e[3] = e[1] * 10;
    // Under 0.2 bits saved per literal: one context, for decoding speed.
    if (e[1] - e[2] < 0.2 and e[1] - e[3] < 0.2) return one;
    if (e[2] - e[3] < 0.02) return .{ .n = 2, .map = &map_simple_utf8 };
    return .{ .n = 3, .map = &map_continuation };
}

/// One category's greedy splitter (`BlockSplitter` / `ContextBlockSplitter`):
/// symbols go into the current block's histograms (one per context); every
/// `target` symbols the block either joins the last block's type, takes the
/// second-last type, or opens a new type — whichever the entropy of the
/// merged histograms says, with `threshold` bits the price of a new type.
pub const Splitter = struct {
    alphabet: u32,
    nctx: u32,
    max_types: u32,
    min_block: u32,
    threshold: f64,
    types: []u8,
    lens: []u32,
    nblocks: u32 = 0,
    ntypes: u32 = 0,
    /// `nslots` sets of `nctx` histograms: one per block type, then the
    /// current block's.
    hist: []u32,
    nslots: u32,
    /// The current block merged with the last (first `nctx`) and the
    /// second-last type (next `nctx`).
    combined: []u32,
    last_entropy: [2 * max_contexts]f64 = undefined,
    target: u32,
    size: u32 = 0,
    cur: u32 = 0,
    last: [2]u32 = .{ 0, 0 },
    merge_last: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, alphabet: u32, nctx: u32, min_block: u32, threshold: f64, nsyms: usize) std.mem.Allocator.Error!Splitter {
        std.debug.assert(nctx >= 1 and nctx <= max_contexts);
        const max_blocks: usize = nsyms / min_block + 1;
        const max_types = max_block_types / nctx;
        // One more set than types: the current block when no type is left.
        const nslots: u32 = @intCast(@min(max_blocks, max_types + 1));
        const types = try gpa.alloc(u8, max_blocks);
        errdefer gpa.free(types);
        const lens = try gpa.alloc(u32, max_blocks);
        errdefer gpa.free(lens);
        const hist = try gpa.alloc(u32, @as(usize, nslots) * nctx * alphabet);
        errdefer gpa.free(hist);
        const combined = try gpa.alloc(u32, 2 * @as(usize, nctx) * alphabet);
        var s: Splitter = .{
            .alphabet = alphabet,
            .nctx = nctx,
            .max_types = max_types,
            .min_block = min_block,
            .threshold = threshold,
            .types = types,
            .lens = lens,
            .hist = hist,
            .nslots = nslots,
            .combined = combined,
            .target = min_block,
        };
        zero(s.slot(0));
        return s;
    }

    pub fn deinit(s: *Splitter, gpa: std.mem.Allocator) void {
        gpa.free(s.types);
        gpa.free(s.lens);
        gpa.free(s.hist);
        gpa.free(s.combined);
        s.* = undefined;
    }

    inline fn slot(s: *const Splitter, k: u32) []u32 {
        const n = @as(usize, s.nctx) * s.alphabet;
        return s.hist[k * n ..][0..n];
    }

    inline fn ctxHist(s: *const Splitter, k: u32, c: u32) []u32 {
        return s.hist[(@as(usize, k) * s.nctx + c) * s.alphabet ..][0..s.alphabet];
    }

    pub inline fn add(s: *Splitter, sym: u32, ctx: u32) void {
        s.hist[(@as(usize, s.cur) * s.nctx + ctx) * s.alphabet + sym] += 1;
        s.size += 1;
        if (s.size == s.target) s.finishBlock();
    }

    fn finishBlock(s: *Splitter) void {
        const n = s.nctx;
        const a = s.alphabet;
        const le = &s.last_entropy;
        if (s.nblocks == 0) {
            // The first block.
            s.types[0] = 0;
            s.lens[0] = s.size;
            for (0..n) |c| {
                le[c] = bitsEntropy(s.ctxHist(0, @intCast(c)));
                le[n + c] = le[c];
            }
            s.nblocks = 1;
            s.ntypes = 1;
            s.cur = 1;
            if (s.cur < s.nslots) zero(s.slot(s.cur));
            s.size = 0;
            return;
        }
        if (s.size == 0) return;
        var entropy: [max_contexts]f64 = undefined;
        var combined_entropy: [2 * max_contexts]f64 = undefined;
        var diff = [2]f64{ 0, 0 };
        for (0..n) |c| {
            const cur = s.ctxHist(s.cur, @intCast(c));
            entropy[c] = bitsEntropy(cur);
            for (0..2) |j| {
                const jx = j * n + c;
                const comb = s.combined[jx * a ..][0..a];
                for (comb, cur, s.ctxHist(s.last[j], @intCast(c))) |*o, x, y| o.* = x + y;
                combined_entropy[jx] = bitsEntropy(comb);
                diff[j] += combined_entropy[jx] - entropy[c] - le[jx];
            }
        }
        if (s.ntypes < s.max_types and diff[0] > s.threshold and diff[1] > s.threshold) {
            // A new block type.
            s.lens[s.nblocks] = s.size;
            s.types[s.nblocks] = @intCast(s.ntypes);
            s.last[1] = s.last[0];
            s.last[0] = s.ntypes;
            for (0..n) |c| {
                le[n + c] = le[c];
                le[c] = entropy[c];
            }
            s.nblocks += 1;
            s.ntypes += 1;
            s.cur += 1;
            if (s.cur < s.nslots) zero(s.slot(s.cur));
            s.size = 0;
            s.merge_last = 0;
            s.target = s.min_block;
        } else if (diff[1] < diff[0] - 20.0) {
            // The second-last block's type.
            s.lens[s.nblocks] = s.size;
            s.types[s.nblocks] = s.types[s.nblocks - 2];
            std.mem.swap(u32, &s.last[0], &s.last[1]);
            for (0..n) |c| {
                @memcpy(s.ctxHist(s.last[0], @intCast(c)), s.combined[(n + c) * a ..][0..a]);
                le[n + c] = le[c];
                le[c] = combined_entropy[n + c];
                zero(s.ctxHist(s.cur, @intCast(c)));
            }
            s.nblocks += 1;
            s.size = 0;
            s.merge_last = 0;
            s.target = s.min_block;
        } else {
            // Into the last block.
            s.lens[s.nblocks - 1] += s.size;
            for (0..n) |c| {
                @memcpy(s.ctxHist(s.last[0], @intCast(c)), s.combined[c * a ..][0..a]);
                le[c] = combined_entropy[c];
                if (s.ntypes == 1) le[n + c] = le[c];
                zero(s.ctxHist(s.cur, @intCast(c)));
            }
            s.size = 0;
            s.merge_last += 1;
            if (s.merge_last > 1) s.target += s.min_block;
        }
    }

    /// The split, owned by the caller; `s.hist`'s first `ntypes` sets are
    /// then each type's histograms (contexts in a row). No symbols: one
    /// empty block.
    pub fn finish(s: *Splitter, gpa: std.mem.Allocator) std.mem.Allocator.Error!block_split.Split {
        s.finishBlock();
        if (s.nblocks == 0) {
            s.ntypes = 1;
            return block_split.Split.single(gpa, 0);
        }
        const types = try gpa.dupe(u8, s.types[0..s.nblocks]);
        errdefer gpa.free(types);
        const lens = try gpa.dupe(u32, s.lens[0..s.nblocks]);
        return .{ .types = types, .lens = lens, .ntypes = s.ntypes };
    }
};

const testing = std.testing;

test "bitsEntropy: at least a bit a symbol, Shannon above" {
    try testing.expectEqual(@as(f64, 0), bitsEntropy(&.{ 0, 0, 0 }));
    try testing.expectEqual(@as(f64, 10), bitsEntropy(&.{ 10, 0 }));
    try testing.expectApproxEqAbs(@as(f64, 2000), bitsEntropy(&.{ 250, 250, 250, 250, 0, 0, 0, 0 }), 1e-9);
}

test "Splitter: alternating sections get their own types, lengths add up" {
    const gpa = testing.allocator;
    var syms: std.ArrayListUnmanaged(u32) = .empty;
    defer syms.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    for (0..6) |sec| {
        const base: u32 = if (sec % 2 == 0) 0 else 128;
        for (0..4096) |_| try syms.append(gpa, base + r.uintLessThan(u32, 16));
    }
    var s = try Splitter.init(gpa, 256, 1, 512, 400, syms.items.len);
    defer s.deinit(gpa);
    for (syms.items) |x| s.add(x, 0);
    var sp = try s.finish(gpa);
    defer sp.deinit(gpa);
    // Greedy: a block straddling a section boundary may get a type of its
    // own, but the sections do not share one.
    try testing.expect(sp.ntypes >= 2 and sp.ntypes <= 6);
    try testing.expectEqual(@as(u8, 0), sp.types[0]);
    var total: usize = 0;
    for (sp.lens, sp.types) |l, t| {
        try testing.expect(l > 0);
        try testing.expect(t < sp.ntypes);
        total += l;
    }
    try testing.expectEqual(syms.items.len, total);
    // The types' histograms hold every symbol once; none mixes a whole
    // low section with a whole high one.
    var all: u64 = 0;
    for (0..sp.ntypes) |t| {
        var lo: u64 = 0;
        var hi: u64 = 0;
        for (s.slot(@intCast(t)), 0..) |c, sym| {
            if (sym < 128) lo += c else hi += c;
        }
        all += lo + hi;
        try testing.expect(lo < 4096 or hi < 4096);
    }
    try testing.expectEqual(@as(u64, syms.items.len), all);
}

test "Splitter: a short stream is one block of its real length; none is one empty block" {
    const gpa = testing.allocator;
    var s = try Splitter.init(gpa, 704, 1, 1024, 500, 100);
    defer s.deinit(gpa);
    for (0..100) |i| s.add(@intCast(i % 7), 0);
    var sp = try s.finish(gpa);
    defer sp.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), sp.lens.len);
    try testing.expectEqual(@as(u32, 100), sp.lens[0]);

    var e = try Splitter.init(gpa, 64, 1, 512, 100, 0);
    defer e.deinit(gpa);
    var se = try e.finish(gpa);
    defer se.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), se.ntypes);
    try testing.expectEqual(@as(u32, 0), se.lens[0]);
}

test "chooseStaticContexts: ASCII text one context, mixed UTF-8 more, quality 6 never three" {
    const ascii = "the quick brown fox jumps over the lazy dog " ** 200;
    try testing.expectEqual(@as(u32, 1), chooseStaticContexts(ascii, 9).n);
    // Two-byte UTF-8 (Cyrillic): lead and continuation bytes alternate.
    const cyr = "привет мир, как дела? " ** 400;
    const q9 = chooseStaticContexts(cyr, 9);
    try testing.expect(q9.n >= 2);
    try testing.expect(chooseStaticContexts(cyr, 6).n <= 2);
    try testing.expectEqual(@as(u32, 1), chooseStaticContexts(cyr[0..63], 9).n);
}
