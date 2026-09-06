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
    /// Random on one side of `split`, text on the other: a stored block
    /// followed by a compressed final block, and the reverse.
    mixed: struct { n: usize, split: usize, random_first: bool, seed: u64 },
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
                    @as(usize, @truncate(r >> 3)) % a.alpha;
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
        .alice_cycle => |n| {
            const buf = try gpa.alloc(u8, n);
            for (buf, 0..) |*b, i| b.* = alice[i % alice.len];
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

    // Multi-meta-block: stored and compressed blocks in both orders, and the
    // block boundary itself.
    .{ .name = "mixed_random_first", .gen = .{ .mixed = .{ .n = block + 40000, .split = block, .random_first = true, .seed = seed_b +% 3 } } },
    .{ .name = "mixed_text_first", .gen = .{ .mixed = .{ .n = block + 40000, .split = block, .random_first = false, .seed = seed_b +% 4 } } },
    .{ .name = "block_exact", .gen = .{ .alice_cycle = block } },
    .{ .name = "block_plus_one", .gen = .{ .alice_cycle = block + 1 } },
};

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
};

/// What the reference's decoder said about our encoder's output, frozen.
pub const blessed = @import("testdata/interop_blessed.zig");
