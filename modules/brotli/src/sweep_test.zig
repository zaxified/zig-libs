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
    const all_sizes = [_]usize{ 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 9000 };
    // An unoptimized build is ~5x slower (the whole sweep took minutes): there every power-of-two edge keeps
    // one side (0, 1, 3, 8, 17, 64, 129, 256, 1025, 4096, 9000); the optimized lanes (CI) run all of them.
    const quick_sizes = [_]usize{ 0, 1, 3, 8, 17, 64, 129, 256, 1025, 4096, 9000 };
    const sizes: []const usize = if (@import("builtin").mode == .debug) &quick_sizes else &all_sizes;
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

test "literal_context_modeling = false: every effort round-trips, below .q6 nothing changes, from .q6 the literals take one code (never smaller on font-like data), a stream writes the one-shot bytes" {
    const gpa = testing.allocator;
    const input = try brotli.interop_corpus.fontLike(gpa, 40_000, 7);
    defer gpa.free(input);
    for (efforts) |effort| {
        const on = try brotli.compressWith(gpa, input, .{ .effort = effort });
        defer gpa.free(on);
        const off = try brotli.compressWith(gpa, input, .{ .effort = effort, .literal_context_modeling = false });
        defer gpa.free(off);
        try roundTrip(gpa, input, .{ .effort = effort, .literal_context_modeling = false });
        if (effort == .q0 or effort == .q1 or effort == .q4) {
            try testing.expectEqualSlices(u8, on, off);
        } else {
            try testing.expect(off.len >= on.len);
        }
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var sw = try brotli.StreamWriter.init(gpa, &out.writer, &.{}, .{ .effort = effort, .window_bits = 16, .size_hint = input.len, .literal_context_modeling = false });
        defer sw.deinit();
        try sw.writer.writeAll(input);
        try sw.finish();
        const one = try brotli.compressWith(gpa, input, .{ .effort = effort, .window_bits = 16, .literal_context_modeling = false });
        defer gpa.free(one);
        try testing.expectEqualSlices(u8, one, out.written());
    }
    // On font-like data context modelling pays at .q9 (the reason it is on by default).
    const on9 = try brotli.compressWith(gpa, input, .{ .effort = .q9 });
    defer gpa.free(on9);
    const off9 = try brotli.compressWith(gpa, input, .{ .effort = .q9, .literal_context_modeling = false });
    defer gpa.free(off9);
    try testing.expect(off9.len > on9.len);
}

const Peak = struct {
    backing: std.mem.Allocator,
    cur: usize = 0,
    peak: usize = 0,
    fn allocator(w: *Peak) std.mem.Allocator {
        return .{ .ptr = w, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn bump(w: *Peak, d: isize) void {
        w.cur = @intCast(@as(isize, @intCast(w.cur)) + d);
        w.peak = @max(w.peak, w.cur);
    }
    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const w: *Peak = @ptrCast(@alignCast(ctx));
        const p = w.backing.rawAlloc(len, al, ra) orelse return null;
        w.bump(@intCast(len));
        return p;
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        // Refused, like `remap`: a buffer that grows in place or shrinks to fit (the `mremap` of Linux on x86-64)
        // holds less at its peak than one an allocator can only grow by copying (the testing allocator on
        // aarch64, `smp_allocator` past its size classes), and the estimate has to bound the second.
        _ = .{ ctx, m, al, n, ra };
        return false;
    }
    fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        _ = .{ ctx, m, al, n, ra }; // refused: see `resize`
        return null;
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const w: *Peak = @ptrCast(@alignCast(ctx));
        w.backing.rawFree(m, al, ra);
        w.bump(-@as(isize, @intCast(m.len)));
    }
};

test "estimatePeakMemory bounds what compressWith allocates at its peak (output included), on every effort, shape, window and size tried" {
    const gpa = testing.allocator;
    const debug = @import("builtin").mode == .debug;
    const sizes = if (debug) [_]usize{ 0, 1, 1000, 20_000, 70_000, 150_000 } else [_]usize{ 0, 1, 1000, 20_000, 70_000, 150_000, 300_000, 600_000 };
    for (sizes) |n| {
        for ([_]u8{ 5, 7, 8 }) |shape| {
            const input = try fill(gpa, shape, n, 1);
            defer gpa.free(input);
            for (efforts) |effort| {
                for ([_]?u5{ null, 12, 16 }) |wb| {
                    var pk: Peak = .{ .backing = gpa };
                    const opts: brotli.CompressOptions = .{ .effort = effort, .window_bits = wb };
                    const out = try brotli.compressWith(pk.allocator(), input, opts);
                    pk.allocator().free(out);
                    const est = brotli.estimatePeakMemory(opts, n);
                    // The estimate leaves the input and the output out, as google's does.
                    if (pk.peak > est + brotli.maxCompressedSize(n, opts)) {
                        std.debug.print("UNDER n={d} shape={d} {s} wb={?d} peak={d} est={d}\n", .{ n, shape, @tagName(effort), wb, pk.peak, est });
                        return error.EstimateTooLow;
                    }
                    // And is not a wild over-estimate: within 40x for a stream of any size here (tiny inputs pay the fixed parts).
                    if (est > 40 * pk.peak + (1 << 20)) {
                        std.debug.print("OVER n={d} shape={d} {s} wb={?d} peak={d} est={d}\n", .{ n, shape, @tagName(effort), wb, pk.peak, est });
                        return error.EstimateTooHigh;
                    }
                }
            }
        }
    }
    // Monotone in the input length and the effort's cost class, and finite for the largest window.
    try testing.expect(brotli.estimatePeakMemory(.{ .effort = .q11 }, 1 << 20) > brotli.estimatePeakMemory(.{ .effort = .q9 }, 1 << 20));
    try testing.expect(brotli.estimatePeakMemory(.{ .effort = .q9 }, 1 << 20) >= brotli.estimatePeakMemory(.{ .effort = .q9 }, 1 << 10));
    _ = brotli.estimatePeakMemory(.{ .effort = .q11, .window_bits = 30 }, std.math.maxInt(usize));
}

// ── delta mutation 2026-11-25 ───────────────────────────────────────────────

test "mutation 2026-11-25: a StreamWriter sanitizes an unaligned NDIRECT like compressWith (bytes equal the one-shot stream)" {
    const gpa = testing.allocator;
    const input = try brotli.interop_corpus.fontLike(gpa, 30_000, 5);
    defer gpa.free(input);
    for (efforts) |effort| {
        const opts: brotli.CompressOptions = .{ .effort = effort, .distance = .{ .npostfix = 2, .ndirect = 255 } };
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

test "mutation 2026-11-25: compressPart takes the distance, literal-context, mode and block-size options (a first-and-last part is compressWith's stream)" {
    const gpa = testing.allocator;
    const input = try brotli.interop_corpus.fontLike(gpa, 30_000, 5);
    defer gpa.free(input);
    const variants = [_]brotli.CompressOptions{
        .{ .window_bits = 16, .distance = .{ .npostfix = 2, .ndirect = 8 } },
        .{ .window_bits = 16, .literal_context_modeling = false },
        .{ .window_bits = 16, .mode = .font },
        .{ .window_bits = 16, .block_size = 6000 },
    };
    for (efforts) |effort| {
        for (variants) |v| {
            var opts = v;
            opts.effort = effort;
            const want = try brotli.compressWith(gpa, input, opts);
            defer gpa.free(want);
            const got = try brotli.parallel.compressPart(gpa, &.{}, input, opts, .{});
            defer gpa.free(got);
            try testing.expectEqualSlices(u8, want, got);
        }
    }
}

test "mutation 2026-11-25: compressPart refuses a prepared dictionary, uses its history for matches, and keeps copies inside the window" {
    const gpa = testing.allocator;
    var prepared = try brotli.PreparedDictionary.init(gpa, "some dictionary bytes to prepare, long enough to hash");
    defer prepared.deinit(gpa);
    try testing.expectError(error.Unsupported, brotli.parallel.compressPart(gpa, &.{}, "abc", .{ .window_bits = 16, .prepared_dictionary = &prepared }, .{}));

    var prng = std.Random.DefaultPrng.init(0xd14);
    const r = prng.random();
    // 1. history is searched: the second part repeats the first, so it is a few copies, not a literal run.
    const noise = try gpa.alloc(u8, 4000);
    defer gpa.free(noise);
    r.bytes(noise);
    for ([_]brotli.Effort{ .q1, .q4, .q6, .q9 }) |effort| {
        const opts: brotli.CompressOptions = .{ .effort = effort, .window_bits = 16 };
        const first = try brotli.parallel.compressPart(gpa, &.{}, noise, opts, .{ .last = false });
        defer gpa.free(first);
        const second = try brotli.parallel.compressPart(gpa, noise, noise, opts, .{ .first = false });
        defer gpa.free(second);
        try testing.expect(second.len < 200);
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(gpa);
        try joined.appendSlice(gpa, first);
        try joined.appendSlice(gpa, second);
        const both = try gpa.alloc(u8, 2 * noise.len);
        defer gpa.free(both);
        @memcpy(both[0..noise.len], noise);
        @memcpy(both[noise.len..], noise);
        const back = try brotli.decompress(gpa, joined.items, .{ .max_ratio = 1 << 30 });
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, both, back);
    }
    // 2. a window of 1 KiB reaches back at most 1008 bytes: the second part starts with bytes that sit
    // exactly 1009 back in the history (one too far), followed by noise.
    const hist = try gpa.alloc(u8, 3000);
    defer gpa.free(hist);
    r.bytes(hist);
    const tail = try gpa.alloc(u8, 400);
    defer gpa.free(tail);
    r.bytes(tail);
    var second_in: std.ArrayList(u8) = .empty;
    defer second_in.deinit(gpa);
    try second_in.appendSlice(gpa, hist[hist.len - 1009 ..][0..48]);
    try second_in.appendSlice(gpa, tail);
    for ([_]brotli.Effort{ .q1, .q4, .q6, .q9 }) |effort| {
        const opts: brotli.CompressOptions = .{ .effort = effort, .window_bits = 10 };
        const first = try brotli.parallel.compressPart(gpa, &.{}, hist, opts, .{ .last = false });
        defer gpa.free(first);
        const second = try brotli.parallel.compressPart(gpa, hist, second_in.items, opts, .{ .first = false });
        defer gpa.free(second);
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(gpa);
        try joined.appendSlice(gpa, first);
        try joined.appendSlice(gpa, second);
        const both = try gpa.alloc(u8, hist.len + second_in.items.len);
        defer gpa.free(both);
        @memcpy(both[0..hist.len], hist);
        @memcpy(both[hist.len..], second_in.items);
        const back = try brotli.decompress(gpa, joined.items, .{ .max_ratio = 1 << 30 });
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, both, back);
    }
}

test "mutation 2026-11-25: parallel.compress hands the distance and literal-context options to every job" {
    const gpa = testing.allocator;
    const input = try brotli.interop_corpus.fontLike(gpa, 200_000, 9);
    defer gpa.free(input);
    for ([_]brotli.Effort{ .q6, .q9 }) |effort| {
        const par: brotli.parallel.ParallelOptions = .{ .job_size = 64 << 10, .threads = 2 };
        const plain = try brotli.parallel.compress(gpa, testing.io, input, .{ .effort = effort }, par);
        defer gpa.free(plain);
        const dist = try brotli.parallel.compress(gpa, testing.io, input, .{ .effort = effort, .distance = .{ .npostfix = 2, .ndirect = 8 } }, par);
        defer gpa.free(dist);
        const nolcm = try brotli.parallel.compress(gpa, testing.io, input, .{ .effort = effort, .literal_context_modeling = false }, par);
        defer gpa.free(nolcm);
        try testing.expect(!std.mem.eql(u8, plain, dist));
        try testing.expect(!std.mem.eql(u8, plain, nolcm));
        inline for (.{ dist, nolcm }) |stream| {
            const back = try brotli.decompress(gpa, stream, .{ .max_ratio = 1 << 30 });
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, input, back);
        }
    }
}

test "mutation 2026-11-25: estimatePeakMemory bounds the peak past 1 MiB too (the q1, q4 and q6 terms), within 2x" {
    if (@import("builtin").mode == .debug) return error.SkipZigTest; // minutes in an unoptimized build
    const gpa = testing.allocator;
    const n: usize = 2 << 20; // the largest size the estimate covers
    const input = try fill(gpa, 8, n, 1);
    defer gpa.free(input);
    for ([_]brotli.Effort{ .q0, .q1, .q4, .q6 }) |effort| {
        var pk: Peak = .{ .backing = gpa };
        const opts: brotli.CompressOptions = .{ .effort = effort };
        const out = try brotli.compressWith(pk.allocator(), input, opts);
        defer pk.allocator().free(out);
        const est = brotli.estimatePeakMemory(opts, n);
        try testing.expect(pk.peak <= est + brotli.maxCompressedSize(n, opts));
        try testing.expect(est <= 2 * pk.peak);
    }
}
