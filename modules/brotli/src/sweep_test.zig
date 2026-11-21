// SPDX-License-Identifier: MIT

//! A no-panic and round-trip sweep over the match finders' internals: every
//! `Effort` (the q0, q1, q4, q6, q9 and q11 pipelines, with `block_split` and
//! `greedy_split` behind them) on inputs shaped to reach their corners: runs, short
//! periods, a few symbols, binary noise, static-dictionary text, copies at and just
//! past the window, sizes around every power of two a table or block is sized by, a raw
//! dictionary, a tiny window, small blocks. Each stream must decode to its input within
//! `maxCompressedSize`; a debug build turns an overflow or a bad index in any finder
//! into a failure.

const std = @import("std");
const testing = std.testing;
const brotli = @import("root.zig");

const efforts = [_]brotli.Effort{ .q0, .q1, .q4, .q6, .q9, .q11 };

fn fill(gpa: std.mem.Allocator, shape: u8, n: usize, seed: u64) ![]u8 {
    const buf = try gpa.alloc(u8, n);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    switch (shape) {
        0 => @memset(buf, 0), // one long run
        1 => @memset(buf, 0xff),
        2 => for (buf, 0..) |*b, i| {
            b.* = @truncate(i); // period 256
        },
        3 => for (buf, 0..) |*b, i| {
            b.* = "ab"[i % 2]; // period 2
        },
        4 => for (buf, 0..) |*b, i| {
            b.* = "abcdefg"[i % 7];
        },
        5 => r.bytes(buf), // noise
        6 => for (buf) |*b| {
            b.* = "acgt"[r.uintLessThan(usize, 4)]; // four symbols
        },
        7 => { // dictionary words and spaces
            const words = [_][]const u8{ "the ", "and ", "of ", "time ", "people ", "information ", "because ", "<div class=\"", "</span>", "http://www.", "function ", "return " };
            var i: usize = 0;
            while (i < n) {
                const w = words[r.uintLessThan(usize, words.len)];
                const k = @min(w.len, n - i);
                @memcpy(buf[i..][0..k], w[0..k]);
                i += k;
            }
        },
        8 => { // a block of noise copied again far back, then mutated
            r.bytes(buf);
            const half = n / 2;
            if (half > 0) {
                @memcpy(buf[half..][0..half], buf[0..half]);
                var k: usize = 0;
                while (k < n / 50 + 1) : (k += 1) buf[r.uintLessThan(usize, n)] ^= 1;
            }
        },
        9 => { // runs of random lengths of random bytes
            var i: usize = 0;
            while (i < n) {
                const run = @min(n - i, r.uintLessThan(usize, 600) + 1);
                @memset(buf[i..][0..run], r.int(u8));
                i += run;
            }
        },
        else => { // UTF-8 and high bytes
            for (buf) |*b| b.* = if (r.boolean()) 0xc3 else r.int(u8) | 0x80;
        },
    }
    return buf;
}

fn roundTrip(gpa: std.mem.Allocator, input: []const u8, opts: brotli.CompressOptions) !void {
    const comp = try brotli.compressWith(gpa, input, opts);
    defer gpa.free(comp);
    try testing.expect(comp.len <= brotli.maxCompressedSize(input.len, opts));
    const back = try brotli.decompress(gpa, comp, .{ .dictionary = opts.dictionary, .max_ratio = 1 << 30 });
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
}

test "sweep: every effort over every shape at sizes around the tables' and blocks' limits" {
    const gpa = testing.allocator;
    const sizes = [_]usize{ 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 9000 };
    for (efforts) |effort| {
        for (0..11) |shape| {
            for (sizes, 0..) |n, i| {
                // The deep finders are slow in a debug build: the small sizes reach the same corners.
                if ((effort == .q9 or effort == .q11) and n > 1100) continue;
                const input = try fill(gpa, @intCast(shape), n, shape * 1000 + i);
                defer gpa.free(input);
                try roundTrip(gpa, input, .{ .effort = effort });
            }
        }
    }
}

test "sweep: larger inputs, window and block settings, modes, and a raw dictionary" {
    const gpa = testing.allocator;
    const Case = struct { n: usize, wbits: ?u5, block: usize, mode: brotli.Mode };
    const cases = [_]Case{
        .{ .n = 70_000, .wbits = null, .block = 1 << 20, .mode = .generic },
        .{ .n = 70_000, .wbits = 16, .block = 4096, .mode = .text },
        .{ .n = 131_072 + 5, .wbits = null, .block = 1 << 20, .mode = .font },
        .{ .n = 12_000, .wbits = 10, .block = 1 << 20, .mode = .generic }, // copies past a 1 KiB window are refused, not wrapped
        .{ .n = 9_000, .wbits = 18, .block = 777, .mode = .font },
        .{ .n = 12_000, .wbits = null, .block = 4096, .mode = .text },
    };
    for (efforts) |effort| {
        for (cases) |c| {
            // The shortest-path parse and the 256-candidate finder are slow in a debug build: fewer, smaller.
            if ((effort == .q11 or effort == .q9) and c.n > 12_000) continue;
            for ([_]u8{ 0, 3, 5, 6, 7, 8, 9, 10 }) |shape| {
                const input = try fill(gpa, shape, c.n, c.n + shape);
                defer gpa.free(input);
                try roundTrip(gpa, input, .{ .effort = effort, .window_bits = c.wbits, .block_size = c.block, .mode = c.mode });
            }
        }
    }
    // A raw dictionary: the input's own head, and text the dictionary holds.
    for (efforts) |effort| {
        const dict = try fill(gpa, 7, 5000, 1);
        defer gpa.free(dict);
        for ([_]u8{ 7, 5, 0 }) |shape| {
            const input = try fill(gpa, shape, 3000, 2);
            defer gpa.free(input);
            try roundTrip(gpa, input, .{ .effort = effort, .dictionary = dict });
        }
        try roundTrip(gpa, dict[1000..4000], .{ .effort = effort, .dictionary = dict });
    }
}

test "sweep: the one-shot, `compressInto` and `Compressor` paths agree on the bytes" {
    const gpa = testing.allocator;
    var comp: brotli.Compressor = .init(gpa);
    defer comp.deinit();
    for (efforts) |effort| {
        for ([_]u8{ 5, 7, 9 }) |shape| {
            for ([_]usize{ 1, 100, 5000 }) |n| {
                const input = try fill(gpa, shape, n, n);
                defer gpa.free(input);
                const opts: brotli.CompressOptions = .{ .effort = effort };
                const a = try brotli.compressWith(gpa, input, opts);
                defer gpa.free(a);
                const out = try gpa.alloc(u8, brotli.maxCompressedSize(n, opts));
                defer gpa.free(out);
                const b = try brotli.compressInto(gpa, out, input, opts);
                try testing.expectEqualSlices(u8, a, b);
                const c = try comp.compress(input, opts);
                defer gpa.free(c);
                try testing.expectEqualSlices(u8, a, c);
            }
        }
    }
}

test "DistanceParams: sanitized, round-trips, equals the font mode's pair, changes nothing below q4, streams like one-shot" {
    const gpa = testing.allocator;
    try testing.expectEqual(brotli.DistanceParams{ .npostfix = 2, .ndirect = 60 }, (brotli.DistanceParams{ .npostfix = 2, .ndirect = 255 }).sanitized());
    try testing.expectEqual(brotli.DistanceParams{ .npostfix = 1, .ndirect = 12 }, (brotli.DistanceParams{ .npostfix = 1, .ndirect = 13 }).sanitized());
    try testing.expectEqual(brotli.DistanceParams{ .npostfix = 0, .ndirect = 15 }, (brotli.DistanceParams{ .npostfix = 0, .ndirect = 99 }).sanitized());

    const input = try brotli.interop_corpus.fontLike(gpa, 30_000, 5);
    defer gpa.free(input);
    for (efforts) |effort| {
        const plain = try brotli.compressWith(gpa, input, .{ .effort = effort });
        defer gpa.free(plain);
        for ([_]brotli.DistanceParams{ .{}, .{ .npostfix = 1, .ndirect = 12 }, .{ .npostfix = 2, .ndirect = 8 }, .{ .npostfix = 3, .ndirect = 120 }, .{ .npostfix = 3, .ndirect = 255 } }) |d| {
            try roundTrip(gpa, input, .{ .effort = effort, .distance = d });
        }
        // The pair the font mode writes, asked for by hand, is the font mode's stream.
        const font = try brotli.compressWith(gpa, input, .{ .effort = effort, .mode = .font });
        defer gpa.free(font);
        const by_hand = try brotli.compressWith(gpa, input, .{ .effort = effort, .distance = .{ .npostfix = 1, .ndirect = 12 } });
        defer gpa.free(by_hand);
        try testing.expectEqualSlices(u8, font, by_hand);
        // Below .q4 the meta-block header carries no parameters of its own.
        if (effort == .q0 or effort == .q1) {
            const other = try brotli.compressWith(gpa, input, .{ .effort = effort, .distance = .{ .npostfix = 3, .ndirect = 120 } });
            defer gpa.free(other);
            try testing.expectEqualSlices(u8, plain, other);
        }
        // A stream (no flush) writes the one-shot bytes.
        const opts: brotli.CompressOptions = .{ .effort = effort, .distance = .{ .npostfix = 2, .ndirect = 8 } };
        const one = try brotli.compressWith(gpa, input, opts);
        defer gpa.free(one);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var sw = try brotli.StreamWriter.init(gpa, &out.writer, &.{}, .{ .effort = effort, .window_bits = 16, .size_hint = input.len, .distance = opts.distance });
        defer sw.deinit();
        try sw.writer.writeAll(input);
        try sw.finish();
        try testing.expectEqualSlices(u8, one, out.written());
    }
}
