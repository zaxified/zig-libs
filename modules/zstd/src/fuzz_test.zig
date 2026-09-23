// SPDX-License-Identifier: MIT
//! Fuzz: compress arbitrary bytes (one-shot, and streamed), decode them with
//! std, demand the input back.
//!
//! The compressor's input is caller data, so every byte pattern must yield a
//! valid frame without a panic. The oracle is std's independent decoder: a
//! frame it rejects or decodes to anything else is a finding. (Byte-equality
//! with libzstd is the golden test's job; a fuzz target has no reference to
//! call.)
//!
//! One byte-first draw, then nothing: the level and checksum setting are
//! derived from the input length, so a seed's bytes arrive intact and the
//! corpus below is what the ordinary lane actually runs (see the brotli
//! harness for what a draw before the bytes cost that module).

const std = @import("std");
const zstd = @import("root.zig");
const fuzzSeed = @import("testkit").fuzz.seed;

const fuzz_buf_len = 1 << 16;
const levels = [_]i32{ -3, 1, 2, 3, -1, 4, 5, 6, 7, 8, 10, 12, 14, 17, 19, 21 };

fn roundTrip(input: []const u8) !void {
    const gpa = std.testing.allocator;
    const level = levels[input.len % levels.len];
    const checksum = input.len & 8 != 0;
    const z = try zstd.compressAlloc(gpa, input, .{ .level = level, .checksum = checksum });
    defer gpa.free(z);
    if (z.len > zstd.compressBound(input.len)) return error.ExceededBound;

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(z);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
    _ = try d.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualSlices(u8, input, out.written());
}

/// The same through a `Stream` with a 1 KB window, so the input buffer
/// (window + block) wraps within the harness's 64 KB and the extDict match
/// finders run. The schedule is fixed by the length, like the level: chunks
/// of 1, 7, 1000 and 3000 bytes, every third followed by a flush, into a
/// 64-byte output buffer.
fn streamRoundTrip(input: []const u8) !void {
    const gpa = std.testing.allocator;
    const stream_levels = [_]i32{ -3, 1, 2, 3, 5, 6, 8, 10 };
    var s = try zstd.Stream.init(gpa, .{ .level = stream_levels[input.len % stream_levels.len], .checksum = input.len & 8 != 0 });
    defer s.deinit();
    s.window_log = 10;
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    var obuf: [64]u8 = undefined;
    const chunks = [_]usize{ 1, 7, 1000, 3000 };
    var fed: usize = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        const n = @min(chunks[i % chunks.len], input.len - fed);
        const dir: zstd.EndDirective = if (fed + n == input.len) .end else if (i % 3 == 2) .flush else .@"continue";
        var in: zstd.InBuffer = .{ .src = input[fed..][0..n] };
        while (true) {
            var o: zstd.OutBuffer = .{ .dst = &obuf };
            const left = try s.compressStream2(&o, &in, dir);
            try z.appendSlice(gpa, obuf[0..o.pos]);
            if (if (dir == .@"continue") in.pos == in.src.len else left == 0) break;
        }
        fed += n;
        if (dir == .end) break;
    }

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(z.items);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
    _ = try d.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualSlices(u8, input, out.written());
}

fn fuzzStream(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    try streamRoundTrip(buf[0..len]);
}

fn fuzzCompress(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    try roundTrip(buf[0..len]);
}

const seed_words = "the frame of the block of the window, the match of the literal; " ** 40;
const seed_runs = ("a" ** 300) ++ ("b" ** 300) ++ ("a" ** 300);
const seed_noise = blk: {
    @setEvalBranchQuota(10_000);
    var b: [4096]u8 = undefined;
    var x: u32 = 0x12345678;
    for (&b) |*v| {
        x = x *% 1103515245 +% 12345;
        v.* = @truncate(x >> 16);
    }
    break :blk b;
};

const fuzz_seed_corpus = [_][]const u8{
    fuzzSeed(""),
    fuzzSeed("x"),
    fuzzSeed("seven!!"), // the smallest block the matcher sees
    fuzzSeed(seed_words),
    fuzzSeed(seed_runs),
    fuzzSeed(&seed_noise),
    fuzzSeed(seed_words ++ seed_noise ++ seed_words),
    // over 16 KB: the lazy levels switch from the hash chain to the row finder
    // (17 927 bytes -> levels[7], level 6)
    fuzzSeed(seed_words ** 7 ++ "abcdefg"),
};

test "fuzz: every input round-trips through std's decoder" {
    try std.testing.fuzz({}, fuzzCompress, .{ .corpus = &fuzz_seed_corpus });
}

test "fuzz: every input streamed round-trips through std's decoder" {
    try std.testing.fuzz({}, fuzzStream, .{ .corpus = &fuzz_seed_corpus });
}

test "fuzz corpus reaches the compressor intact" {
    // Draws exactly as the harness does: a seed must come back as its own
    // bytes, or the ordinary lane is not running what the corpus says.
    var nonempty: usize = 0;
    for (fuzz_seed_corpus) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        try std.testing.expectEqual(sd.len - 4, len);
        try roundTrip(buf[0..len]);
        try streamRoundTrip(buf[0..len]);
    }
    try std.testing.expectEqual(fuzz_seed_corpus.len - 1, nonempty);
}
