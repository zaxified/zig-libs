// SPDX-License-Identifier: MIT

//! The input shapes the differential tests judge the encoder and decoder on:
//! deterministic generators, so a shape is a name plus numbers and the same
//! bytes come out in the tests, in `tools/interop.zig` and in the fuzz
//! harness. Each one is chosen for a path of liblzma it exercises (literal
//! coding with and without a match byte, the 273-byte length limit, repeat
//! distances, the dictionary boundary, stored LZMA2 chunks, chunk limits).
//!
//! Public from the module root only because `tools/interop.zig` is a
//! separate program and cannot import a path inside the module; nothing here
//! is part of the compression API.

const std = @import("std");

pub const Kind = enum {
    /// Pseudo-English from a small word list.
    text,
    /// Uniform random bytes.
    random,
    zeros,
    /// `param` bytes of random seed text repeated.
    periodic,
    /// Runs of 1..`param` copies of random bytes.
    runs,
    /// Two symbols, `param`/256 ones.
    sparse,
    /// Every byte value, shuffled blocks of 256.
    all_bytes,
    /// A random walk over a few symbols.
    skewed,
    /// Fixed-size little-endian records with counters (binary-like).
    records,
    /// Random block of `param` bytes, then text, then the block again: a match
    /// at distance about `param + text` (dictionary boundary).
    far_repeat,
    /// Text, random, zeros, records in turn (`param` bytes per part).
    mixed,
};

pub const Shape = struct {
    name: []const u8,
    kind: Kind,
    len: usize,
    param: u32 = 0,
    seed: u64 = 1,
};

pub const shapes = [_]Shape{
    .{ .name = "empty", .kind = .zeros, .len = 0 },
    .{ .name = "one", .kind = .random, .len = 1 },
    .{ .name = "two-same", .kind = .zeros, .len = 2 },
    .{ .name = "three", .kind = .text, .len = 3 },
    .{ .name = "run272", .kind = .zeros, .len = 272 },
    .{ .name = "run273", .kind = .zeros, .len = 273 },
    .{ .name = "run274", .kind = .zeros, .len = 274 },
    .{ .name = "run275", .kind = .zeros, .len = 275 },
    .{ .name = "run1000", .kind = .zeros, .len = 1000 },
    .{ .name = "text-small", .kind = .text, .len = 3000 },
    .{ .name = "text-150k", .kind = .text, .len = 150_000 },
    .{ .name = "text-1m", .kind = .text, .len = 1_000_000, .seed = 7 },
    .{ .name = "random-small", .kind = .random, .len = 777, .seed = 3 },
    .{ .name = "random-70k", .kind = .random, .len = 70_000 },
    .{ .name = "random-300k", .kind = .random, .len = 300_000 },
    .{ .name = "zeros-2m", .kind = .zeros, .len = 2_000_000 },
    .{ .name = "zeros-5m", .kind = .zeros, .len = 5_000_000 },
    .{ .name = "periodic-3", .kind = .periodic, .len = 50_000, .param = 3 },
    .{ .name = "periodic-7", .kind = .periodic, .len = 400_000, .param = 7 },
    .{ .name = "periodic-1000", .kind = .periodic, .len = 600_000, .param = 1000 },
    .{ .name = "periodic-70000", .kind = .periodic, .len = 400_000, .param = 70_000 },
    .{ .name = "runs-300", .kind = .runs, .len = 300_000, .param = 300 },
    .{ .name = "runs-5", .kind = .runs, .len = 200_000, .param = 5, .seed = 9 },
    .{ .name = "sparse-3", .kind = .sparse, .len = 300_000, .param = 3 },
    .{ .name = "sparse-100", .kind = .sparse, .len = 100_000, .param = 100 },
    .{ .name = "all-bytes", .kind = .all_bytes, .len = 70_000 },
    .{ .name = "skewed", .kind = .skewed, .len = 500_000, .seed = 5 },
    .{ .name = "records-400k", .kind = .records, .len = 400_000 },
    .{ .name = "far-100k", .kind = .far_repeat, .len = 400_000, .param = 100_000 },
    .{ .name = "far-300k", .kind = .far_repeat, .len = 1_200_000, .param = 300_000 },
    .{ .name = "far-1100k", .kind = .far_repeat, .len = 3_000_000, .param = 1_100_000 },
    .{ .name = "mixed-200k", .kind = .mixed, .len = 1_600_000, .param = 200_000 },
    .{ .name = "mixed-3m", .kind = .mixed, .len = 6_000_000, .param = 750_000, .seed = 4 },
};

pub fn find(name: []const u8) ?Shape {
    for (shapes) |s| if (std.mem.eql(u8, s.name, name)) return s;
    return null;
}

pub fn generate(gpa: std.mem.Allocator, s: Shape) std.mem.Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, s.len);
    fill(out, s);
    return out;
}

const words = [_][]const u8{
    "the ",      "quick ",     "brown ",  "fox ",     "jumps ", "over ",   "a ",   "lazy ", "dog\n",   "range ",
    "coder ",    "dictionary", " match ", "literal ", "of ",    "Lempel ", "and ", "Ziv, ", "Markov ", "chain ",
    "encoding ", "is ",
};

pub fn fill(out: []u8, s: Shape) void {
    var prng: std.Random.DefaultPrng = .init(s.seed);
    const rnd = prng.random();
    switch (s.kind) {
        .text => {
            var i: usize = 0;
            while (i < out.len) {
                const w = words[rnd.uintLessThan(usize, words.len)];
                const k = @min(w.len, out.len - i);
                @memcpy(out[i..][0..k], w[0..k]);
                i += k;
            }
        },
        .random => rnd.bytes(out),
        .zeros => @memset(out, 0),
        .periodic => {
            const seedbuf = std.heap.page_allocator.alloc(u8, s.param) catch unreachable;
            defer std.heap.page_allocator.free(seedbuf);
            for (seedbuf) |*b| b.* = 'a' + rnd.uintLessThan(u8, 26);
            var i: usize = 0;
            for (out) |*b| {
                b.* = seedbuf[i];
                i += 1;
                if (i == seedbuf.len) i = 0;
            }
        },
        .runs => {
            var i: usize = 0;
            while (i < out.len) {
                const n = @min(1 + rnd.uintLessThan(usize, s.param), out.len - i);
                @memset(out[i..][0..n], rnd.int(u8));
                i += n;
            }
        },
        .sparse => for (out) |*b| {
            b.* = @intFromBool(rnd.uintLessThan(u32, 256) < s.param);
        },
        .all_bytes => {
            var i: usize = 0;
            while (i < out.len) {
                var perm: [256]u8 = undefined;
                for (&perm, 0..) |*p, j| p.* = @intCast(j);
                rnd.shuffle(u8, &perm);
                const n = @min(256, out.len - i);
                @memcpy(out[i..][0..n], perm[0..n]);
                i += n;
            }
        },
        .skewed => {
            var cur: u8 = 0;
            for (out) |*b| {
                const r = rnd.uintLessThan(u32, 100);
                if (r < 55) {} else if (r < 80) cur +%= 1 else if (r < 92) cur -%= 1 else if (r < 98) cur = rnd.int(u8) % 12 else cur = rnd.int(u8);
                b.* = cur;
            }
        },
        .records => {
            var i: usize = 0;
            var id: u32 = 0;
            while (i < out.len) {
                var rec: [16]u8 = undefined;
                std.mem.writeInt(u32, rec[0..4], id, .little);
                std.mem.writeInt(u32, rec[4..8], rnd.uintLessThan(u32, 1000), .little);
                std.mem.writeInt(u64, rec[8..16], 0x7f00_0000_0000 + @as(u64, rnd.uintLessThan(u32, 1 << 20)) * 8, .little);
                id += 1;
                const k = @min(16, out.len - i);
                @memcpy(out[i..][0..k], rec[0..k]);
                i += k;
            }
        },
        .far_repeat => {
            const n = @min(@as(usize, s.param), out.len);
            rnd.bytes(out[0..n]);
            const mid = (out.len - n) / 2;
            fill(out[n..][0..mid], .{ .name = "", .kind = .text, .len = mid, .seed = s.seed + 1 });
            const rest = out.len - n - mid;
            const again = @min(rest, n);
            @memcpy(out[n + mid ..][0..again], out[0..again]);
            if (rest > again) fill(out[n + mid + again ..], .{ .name = "", .kind = .text, .len = rest - again, .seed = s.seed + 2 });
        },
        .mixed => {
            var i: usize = 0;
            var part: usize = 0;
            while (i < out.len) : (part += 1) {
                const n = @min(@as(usize, s.param), out.len - i);
                const kind: Kind = switch (part % 4) {
                    0 => .text,
                    1 => .random,
                    2 => .zeros,
                    else => .records,
                };
                fill(out[i..][0..n], .{ .name = "", .kind = kind, .len = n, .seed = s.seed + part });
                i += n;
            }
        },
    }
}
