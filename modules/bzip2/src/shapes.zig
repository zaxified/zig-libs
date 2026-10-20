// SPDX-License-Identifier: MIT

//! The input shapes the differential tests judge the encoder and decoder on:
//! deterministic generators, so a shape is a name plus numbers and the same
//! bytes come out in the tests, in `tools/interop.zig` and in the bench. Each
//! one is chosen for a path of libbzip2 it exercises (the fallback sort, the
//! work-factor switch, a block that fills exactly, runs at the RLE1 limits,
//! the 256-symbol alphabet, one to six Huffman tables).
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
    /// `i % 251` for `len - param` bytes, then `param` copies of 'z'.
    cycle_run,
    /// Every byte value, shuffled blocks of 256.
    all_bytes,
    /// A random walk over a few symbols (skewed, many Huffman tables).
    skewed,
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
    .{ .name = "run4", .kind = .zeros, .len = 4 },
    .{ .name = "run5", .kind = .zeros, .len = 5 },
    .{ .name = "run254", .kind = .zeros, .len = 254 },
    .{ .name = "run255", .kind = .zeros, .len = 255 },
    .{ .name = "run256", .kind = .zeros, .len = 256 },
    .{ .name = "run259", .kind = .zeros, .len = 259 },
    .{ .name = "run260", .kind = .zeros, .len = 260 },
    .{ .name = "run1000", .kind = .zeros, .len = 1000 },
    .{ .name = "text-small", .kind = .text, .len = 3000 },
    .{ .name = "text-9999", .kind = .text, .len = 9999 },
    .{ .name = "text-10000", .kind = .text, .len = 10000 },
    .{ .name = "text-150k", .kind = .text, .len = 150_000 },
    .{ .name = "text-1m", .kind = .text, .len = 1_000_000, .seed = 7 },
    .{ .name = "random-300k", .kind = .random, .len = 300_000 },
    .{ .name = "random-small", .kind = .random, .len = 777, .seed = 3 },
    .{ .name = "zeros-2m", .kind = .zeros, .len = 2_000_000 },
    .{ .name = "periodic-7", .kind = .periodic, .len = 400_000, .param = 7 },
    .{ .name = "periodic-1000", .kind = .periodic, .len = 1_200_000, .param = 1000 },
    .{ .name = "runs-300", .kind = .runs, .len = 500_000, .param = 300 },
    .{ .name = "runs-5", .kind = .runs, .len = 200_000, .param = 5, .seed = 9 },
    .{ .name = "sparse-3", .kind = .sparse, .len = 700_000, .param = 3 },
    .{ .name = "sparse-100", .kind = .sparse, .len = 100_000, .param = 100 },
    .{ .name = "all-bytes", .kind = .all_bytes, .len = 70_000 },
    .{ .name = "skewed", .kind = .skewed, .len = 900_000, .seed = 5 },
    // Level 1 closes a block at 99 981 symbols: exactly full, one over, a
    // pending run at the end of the input.
    .{ .name = "edge-99979", .kind = .cycle_run, .len = 99_979 },
    .{ .name = "edge-99980", .kind = .cycle_run, .len = 99_980 },
    .{ .name = "edge-99981", .kind = .cycle_run, .len = 99_981 },
    .{ .name = "edge-99982", .kind = .cycle_run, .len = 99_982 },
    .{ .name = "edge-99981-run", .kind = .cycle_run, .len = 99_981, .param = 6 },
    .{ .name = "edge-99977-run4", .kind = .cycle_run, .len = 99_981, .param = 4 },
    .{ .name = "edge-99970-run11", .kind = .cycle_run, .len = 99_981, .param = 11 },
    .{ .name = "edge-two-blocks", .kind = .cycle_run, .len = 199_962 },
    .{ .name = "edge-two-blocks-run", .kind = .cycle_run, .len = 199_962, .param = 300 },
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

pub fn fill(out: []u8, s: Shape) void {
    var prng: std.Random.DefaultPrng = .init(s.seed);
    const rnd = prng.random();
    switch (s.kind) {
        .text => {
            const words = [_][]const u8{
                "the ",     "quick ",     "brown ", "fox ",     "jumps ", "over ",     "a ",   "lazy ",   "dog\n",     "block ",
                "sorting ", "transform ", "of ",    "Burrows ", "and ",   "Wheeler, ", "run ", "length ", "encoding ", "is ",
            };
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
            var seedbuf: [4096]u8 = undefined;
            const p = s.param;
            for (seedbuf[0..p]) |*b| b.* = 'a' + rnd.uintLessThan(u8, 26);
            for (out, 0..) |*b, i| b.* = seedbuf[i % p];
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
        .cycle_run => {
            const tail = @min(s.param, out.len);
            const head = out.len - tail;
            for (out[0..head], 0..) |*b, i| b.* = @intCast(i % 251);
            @memset(out[head..], 'z');
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
    }
}
