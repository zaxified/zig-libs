// SPDX-License-Identifier: MIT

//! The input shapes the differential tests judge the codec on: deterministic
//! generators, so a shape is a name plus numbers and the same bytes come out
//! in the tests, in `tools/interop.zig` and in `tools/bench.zig`. Each one is
//! chosen for an edge of the format: empty and tiny inputs (below the 13 bytes
//! a block needs before it may hold a match), incompressible data (stored
//! blocks), long runs (length extension bytes), overlapping matches at every
//! offset 1..15, matches at the 64 KB window edge, block-size boundaries.
//!
//! Public from the module root only because the tools are separate programs;
//! nothing here is part of the compression API.

const std = @import("std");

pub const Kind = enum {
    /// Pseudo-English from a small word list.
    text,
    /// Uniform random bytes.
    random,
    zeros,
    /// `param` random bytes repeated (offset `param` overlap matches).
    periodic,
    /// Runs of 1..`param` copies of random bytes.
    runs,
    /// A random 1000-byte chunk, `param` random bytes, the chunk again: a
    /// match at offset `param + 1000`.
    far_repeat,
    /// Mostly text with random bytes sprinkled in.
    noisy_text,
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
    .{ .name = "zeros-12", .kind = .zeros, .len = 12 },
    .{ .name = "zeros-13", .kind = .zeros, .len = 13 },
    .{ .name = "zeros-17", .kind = .zeros, .len = 17 },
    .{ .name = "text-100", .kind = .text, .len = 100 },
    .{ .name = "random-4k", .kind = .random, .len = 4096 },
    .{ .name = "random-70k", .kind = .random, .len = 70_000, .seed = 2 },
    .{ .name = "zeros-1m", .kind = .zeros, .len = 1 << 20 },
    .{ .name = "runs-300k", .kind = .runs, .len = 300_000, .param = 600 },
    .{ .name = "period-1", .kind = .periodic, .len = 5000, .param = 1 },
    .{ .name = "period-2", .kind = .periodic, .len = 5000, .param = 2 },
    .{ .name = "period-3", .kind = .periodic, .len = 5000, .param = 3 },
    .{ .name = "period-4", .kind = .periodic, .len = 5000, .param = 4 },
    .{ .name = "period-5", .kind = .periodic, .len = 5000, .param = 5 },
    .{ .name = "period-7", .kind = .periodic, .len = 5000, .param = 7 },
    .{ .name = "period-8", .kind = .periodic, .len = 5000, .param = 8 },
    .{ .name = "period-11", .kind = .periodic, .len = 5000, .param = 11 },
    .{ .name = "period-15", .kind = .periodic, .len = 5000, .param = 15 },
    .{ .name = "period-16", .kind = .periodic, .len = 5000, .param = 16 },
    .{ .name = "offset-65533", .kind = .far_repeat, .len = 0, .param = 64_533 },
    .{ .name = "offset-65534", .kind = .far_repeat, .len = 0, .param = 64_534 },
    .{ .name = "offset-65535", .kind = .far_repeat, .len = 0, .param = 64_535 },
    .{ .name = "offset-65536", .kind = .far_repeat, .len = 0, .param = 64_536 },
    .{ .name = "text-64k", .kind = .text, .len = 65_536 },
    .{ .name = "text-64k+1", .kind = .text, .len = 65_537 },
    .{ .name = "text-256k+1", .kind = .text, .len = 262_145, .seed = 3 },
    .{ .name = "text-1m+7", .kind = .text, .len = (1 << 20) + 7, .seed = 4 },
    .{ .name = "text-5m", .kind = .text, .len = 5 << 20, .seed = 5 },
    .{ .name = "noisy-200k", .kind = .noisy_text, .len = 200_000, .param = 40 },
};

const words = [_][]const u8{
    "the ",   "of ",     "and ",  "lz4 ",   "block ", "frame ",   "match ", "offset ",
    "a ",     "to ",     "in ",   "that ",  "is ",    "literal ", "token ", "length ",
    "data\n", "window ", "fast ", "bytes ", "zig ",   "with ",    "for ",   "\n",
};

/// The length a shape generates (`far_repeat` derives its own).
pub fn length(s: Shape) usize {
    return switch (s.kind) {
        .far_repeat => 2000 + s.param,
        else => s.len,
    };
}

/// Generate `s` into a new slice. Caller owns it.
pub fn generate(gpa: std.mem.Allocator, s: Shape) ![]u8 {
    const n = length(s);
    const out = try gpa.alloc(u8, n);
    fill(s, out);
    return out;
}

/// Generate `s` into `out` (`out.len == length(s)`).
pub fn fill(s: Shape, out: []u8) void {
    var prng = std.Random.DefaultPrng.init(s.seed);
    const r = prng.random();
    switch (s.kind) {
        .zeros => @memset(out, 0),
        .random => r.bytes(out),
        .text, .noisy_text => {
            var i: usize = 0;
            while (i < out.len) {
                const w = words[r.uintLessThan(usize, words.len)];
                const k = @min(w.len, out.len - i);
                @memcpy(out[i..][0..k], w[0..k]);
                i += k;
            }
            if (s.kind == .noisy_text) {
                for (out) |*c| {
                    if (r.uintLessThan(u32, s.param) == 0) c.* = r.int(u8);
                }
            }
        },
        .periodic => {
            var seed: [64]u8 = undefined;
            r.bytes(&seed);
            for (out, 0..) |*c, i| c.* = seed[i % s.param];
        },
        .runs => {
            var i: usize = 0;
            while (i < out.len) {
                const k = @min(1 + r.uintLessThan(usize, s.param), out.len - i);
                @memset(out[i..][0..k], r.int(u8));
                i += k;
            }
        },
        .far_repeat => {
            r.bytes(out);
            @memcpy(out[1000 + s.param ..][0..1000], out[0..1000]);
        },
    }
}

test "shapes: deterministic and of the declared length" {
    const gpa = std.testing.allocator;
    for (shapes) |s| {
        if (length(s) > 300_000) continue;
        const a = try generate(gpa, s);
        defer gpa.free(a);
        const b = try generate(gpa, s);
        defer gpa.free(b);
        try std.testing.expectEqual(length(s), a.len);
        try std.testing.expectEqualSlices(u8, a, b);
    }
}
