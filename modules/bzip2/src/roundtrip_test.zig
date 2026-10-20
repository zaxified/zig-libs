// SPDX-License-Identifier: MIT

const std = @import("std");
const testing = std.testing;
const bz = @import("root.zig");
const corpus = @import("shapes.zig");

fn textInput(gpa: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    const words = [_][]const u8{ "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog\n", "bzip2 ", "block ", "sort, " };
    var prng: std.Random.DefaultPrng = .init(seed);
    const out = try gpa.alloc(u8, n);
    var i: usize = 0;
    while (i < n) {
        const w = words[prng.random().uintLessThan(usize, words.len)];
        const k = @min(w.len, n - i);
        @memcpy(out[i..][0..k], w[0..k]);
        i += k;
    }
    return out;
}

test "round trip: empty, tiny and text, every level" {
    const gpa = testing.allocator;
    const text = try textInput(gpa, 250_000, 1);
    defer gpa.free(text);
    const inputs = [_][]const u8{ "", "a", "ab", "aaaa", "aaaaa", "hello hello hello", text };
    for (inputs) |input| {
        for (1..10) |level| {
            const z = try bz.compress(gpa, input, .{ .level = @intCast(level) });
            defer gpa.free(z);
            const back = try bz.decompress(gpa, z, .{});
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, input, back);
        }
    }
}

test "StreamWriter: any write pattern gives compress()'s bytes; finish ends it" {
    const gpa = testing.allocator;
    const plain = try textInput(gpa, 123_457, 3);
    defer gpa.free(plain);
    const want = try bz.compress(gpa, plain, .{ .level = 1 });
    defer gpa.free(want);
    for ([_]usize{ 0, 1, 7, 4096 }) |bufsize| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        const buf = try gpa.alloc(u8, bufsize);
        defer gpa.free(buf);
        var sw = try bz.StreamWriter.init(gpa, &out.writer, buf, .{ .level = 1 });
        defer sw.deinit();
        var at: usize = 0;
        var step: usize = 1;
        while (at < plain.len) {
            const n = @min(step, plain.len - at);
            try sw.writer.writeAll(plain[at..][0..n]);
            at += n;
            step = step * 3 + 1;
            if (step > 20_000) step = 1;
        }
        try sw.finish();
        try testing.expectEqualSlices(u8, want, out.written());
        try testing.expectError(error.WriteFailed, sw.writer.writeAll("more"));
    }
}

test "block closing does not depend on how the input is cut into writes" {
    const gpa = testing.allocator;
    for ([_][]const u8{ "edge-99981", "edge-99982", "edge-99981-run", "edge-two-blocks", "edge-two-blocks-run" }) |name| {
        const plain = try corpus.generate(gpa, corpus.find(name).?);
        defer gpa.free(plain);
        const want = try bz.compress(gpa, plain, .{ .level = 1 });
        defer gpa.free(want);
        for ([_]usize{ 1, 5000, 99_981, 99_982 }) |piece| {
            var out: std.Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            var enc = try bz.Encoder.init(gpa, &out.writer, .{ .level = 1 });
            defer enc.deinit();
            var at: usize = 0;
            while (at < plain.len) : (at += piece) try enc.write(plain[at..@min(at + piece, plain.len)]);
            try enc.finish();
            try testing.expectEqualSlices(u8, want, out.written());
        }
        const back = try bz.decompress(gpa, want, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
}

test "compressInto and compressBound; bad levels" {
    const gpa = testing.allocator;
    const plain = try textInput(gpa, 20_000, 9);
    defer gpa.free(plain);
    const want = try bz.compress(gpa, plain, .{ .level = 2 });
    defer gpa.free(want);
    const dest = try gpa.alloc(u8, bz.compressBound(plain.len));
    defer gpa.free(dest);
    const n = try bz.compressInto(gpa, dest, plain, .{ .level = 2 });
    try testing.expectEqualSlices(u8, want, dest[0..n]);
    try testing.expectError(error.OutputTooLarge, bz.compressInto(gpa, dest[0 .. want.len - 1], plain, .{ .level = 2 }));
    _ = try bz.compressInto(gpa, dest[0..want.len], plain, .{ .level = 2 });
    try testing.expectError(error.InvalidLevel, bz.compress(gpa, plain, .{ .level = 0 }));
    try testing.expectError(error.InvalidLevel, bz.compress(gpa, plain, .{ .level = 10 }));
    // Incompressible input stays within the bound.
    const rnd = try corpus.generate(gpa, corpus.find("random-300k").?);
    defer gpa.free(rnd);
    const zr = try bz.compress(gpa, rnd, .{ .level = 9 });
    defer gpa.free(zr);
    try testing.expect(zr.len <= bz.compressBound(rnd.len));
}
