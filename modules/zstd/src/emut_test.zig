// SPDX-License-Identifier: MIT
//! Encoder tests found by whole-module mutation (phase 1): the
//! sequence count in every header form, built through the caller's-sequences
//! API so that the count is exact. Expectations: RFC 8878 section 3.1.1.3.2.1
//! and libzstd's `ZSTD_entropyCompressSeqStore` (which `frame.zig` ports).

const std = @import("std");
const zstd = @import("root.zig");
const seq_test = @import("seq_test.zig");

const gpa = std.testing.allocator;

fn roundTrip(comptime n_seq: usize, level: i32) !void {
    // n_seq matches of 4 bytes over "abcd" repeated: one literal run of 4 first.
    const len = 4 * n_seq + 4;
    const src = try gpa.alloc(u8, len);
    defer gpa.free(src);
    for (src, 0..) |*b, i| b.* = "abcd"[i % 4];
    const seqs = try gpa.alloc(zstd.Sequence, n_seq + 1);
    defer gpa.free(seqs);
    for (seqs[0..n_seq], 0..) |*s, i| s.* = .{ .offset = 4, .lit_length = if (i == 0) 4 else 0, .match_length = 4 };
    seqs[n_seq] = .{ .offset = 0, .lit_length = 0, .match_length = 0 };
    const dst = try gpa.alloc(u8, zstd.compressBound(len) + 64);
    defer gpa.free(dst);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try c.compressSequences(dst, seqs, src, .{ .level = level, .advanced = .{ .block_delimiters = .explicit } });
    const back = try gpa.alloc(u8, len + 1);
    defer gpa.free(back);
    var dec = try zstd.Decompressor.init(gpa, .{});
    defer dec.deinit();
    const got = try dec.decompress(back, dst[0..n]);
    try std.testing.expectEqualSlices(u8, src, back[0..got]);
}

test "the sequence count is written in its three forms at every edge (sequences header)" {
    inline for (.{ 1, 2, 126, 127, 128, 129, 254, 255, 256, 257, 0x7EFE, 0x7EFF, 0x7F00, 0x7F01, 0x7FFF }) |n| {
        try roundTrip(n, 3);
    }
}

/// `roundTrip`, but the sequences come from a block-level producer and the
/// block is cut by `targetCBlockSize` (the largest, so a single sub-block
/// holds all `n_seq` sequences): the sequences header of a sub-block
/// (ZSTD_compressSubBlock_sequences).
fn subBlockRoundTrip(comptime n_seq: usize) !void {
    const len = 4 * n_seq + 4;
    const src = try gpa.alloc(u8, len);
    defer gpa.free(src);
    for (src, 0..) |*b, i| b.* = "abcd"[i % 4];
    const seqs = try gpa.alloc(zstd.Sequence, n_seq + 1);
    defer gpa.free(seqs);
    for (seqs[0..n_seq], 0..) |*s, i| s.* = .{ .offset = 4, .lit_length = if (i == 0) 4 else 0, .match_length = 4 };
    seqs[n_seq] = .{ .offset = 0, .lit_length = 0, .match_length = 0 };
    var prod: seq_test.ExampleProducer = .{ .mode = 8192, .list = seqs };
    const dst = try gpa.alloc(u8, zstd.compressBound(len) + 64);
    defer gpa.free(dst);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try c.compress(dst, src, .{ .level = 3, .advanced = .{ .target_c_block_size = 131072 }, .sequence_producer = prod.producer() });
    const back = try gpa.alloc(u8, len + 1);
    defer gpa.free(back);
    var dec = try zstd.Decompressor.init(gpa, .{});
    defer dec.deinit();
    const got = try dec.decompress(back, dst[0..n]);
    try std.testing.expectEqualSlices(u8, src, back[0..got]);
}

test "a sub-block's sequence count is written in its three forms at every edge (superblock sequences header)" {
    inline for (.{ 127, 128, 0x7EFF, 0x7F00, 0x7F01, 0x7FFF }) |n| {
        try subBlockRoundTrip(n);
    }
}

// ----------------------------------------------------------------- room

fn fill(buf: []u8, kind: u8, seed: u64) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    switch (kind) {
        0 => @memset(buf, 0), // one RLE block
        1 => prng.random().bytes(buf), // incompressible: a raw block
        else => for (buf, 0..) |*b, i| {
            b.* = "the quick brown fox jumps over the lazy dog; "[(i * 7 + prng.random().uintLessThan(usize, 3)) % 44];
        },
    }
}

test "short room: DstSizeTooSmall below the frame, the same frame from the least room up, never a panic or a stray byte" {
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const big = try gpa.alloc(u8, 3 * 131072 + 4096);
    defer gpa.free(big);
    const small = try gpa.alloc(u8, 3 * 131072 + 4096);
    defer gpa.free(small);
    var bad: usize = 0;
    for ([_]u8{ 0, 1, 2 }) |kind| for ([_]usize{ 1, 2, 5, 100, 1000, 3000, 131072 + 2, 262144 + 3 }) |len| for ([_]i32{ -3, 1, 3, 19 }) |level| for ([_]bool{ false, true }) |ck| {
        if (len > 10000 and (level != 1 or ck)) continue; // the tail blocks, at the cheapest level
        const src = try gpa.alloc(u8, len);
        defer gpa.free(src);
        fill(src, kind, len);
        const opts: zstd.Options = .{ .level = level, .checksum = ck };
        const n = try c.compress(big, src, opts);
        var ok_seen = false;
        var l: usize = 0;
        while (l <= n + 24) : (l = if (l < 12 or l + 20 >= n) l + 1 else n - 20) {
            @memset(small[0 .. l + 8], 0xA5);
            if (c.compress(small[0..l], src, opts)) |m| {
                ok_seen = true;
                if (l < n or m != n or !std.mem.eql(u8, small[0..m], big[0..n])) bad += 1;
            } else |e| {
                if (e != error.DstSizeTooSmall or ok_seen or l >= n + 24) bad += 1;
            }
            // nothing is written past the room it was given
            for (small[l .. l + 8]) |b| if (b != 0xA5) {
                bad += 1;
                break;
            };
            if (bad != 0) {
                std.debug.print("kind {d} len {d} level {d} ck {} room {d} (frame {d})\n", .{ kind, len, level, ck, l, n });
                return error.TestUnexpectedResult;
            }
        }
        try std.testing.expect(ok_seen);
    };
}

// ------------------------------------------------------------- stream API

test "compressStream2 refuses a position past either buffer, and accepts one at its end (InvalidBuffer)" {
    var s: zstd.Stream = try .init(gpa, .{});
    defer s.deinit();
    var obuf: [64]u8 = undefined;
    // positions past the end of either buffer
    var o: zstd.OutBuffer = .{ .dst = &obuf, .pos = obuf.len + 1 };
    var i: zstd.InBuffer = .{ .src = "abc" };
    try std.testing.expectError(error.InvalidBuffer, s.compressStream2(&o, &i, .@"continue"));
    o = .{ .dst = &obuf };
    i = .{ .src = "abc", .pos = 4 };
    try std.testing.expectError(error.InvalidBuffer, s.compressStream2(&o, &i, .@"continue"));
    // the refusal leaves the stream usable; a position AT the end is fine
    o = .{ .dst = &obuf, .pos = obuf.len };
    i = .{ .src = "abc", .pos = 3 };
    _ = try s.compressStream2(&o, &i, .@"continue");
    try std.testing.expectEqual(obuf.len, o.pos);
    try std.testing.expectEqual(@as(usize, 3), i.pos);
}

test "FrameWriter accepts the highest level and refuses the next one" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [64]u8 = undefined;
    var fw = try zstd.FrameWriter.init(gpa, &out.writer, &buf, .{ .level = 22 });
    fw.deinit();
    try std.testing.expectError(error.LevelUnsupported, zstd.FrameWriter.init(gpa, &out.writer, &buf, .{ .level = 23 }));
}

test "a prefix dictionary serves one frame of a stream, the next frame is made without it" {
    var prefix: [4096]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(5);
    prng.random().bytes(&prefix);
    var src: [3000]u8 = undefined;
    @memcpy(&src, prefix[100..][0..3000]); // matches the prefix completely
    const with: zstd.StreamOptions = .{ .dictionary = .{ .prefix = .{ .bytes = &prefix } } };
    var first: [4096]u8 = undefined;
    var second: [4096]u8 = undefined;
    var plain: [4096]u8 = undefined;
    var s: zstd.Stream = try .init(gpa, with);
    defer s.deinit();
    var n1: usize = 0;
    var n2: usize = 0;
    inline for (.{ &first, &second }, 0..) |buf, k| {
        var o: zstd.OutBuffer = .{ .dst = buf };
        var i: zstd.InBuffer = .{ .src = &src };
        while (try s.compressStream2(&o, &i, .end) != 0) {}
        if (k == 0) n1 = o.pos else n2 = o.pos;
    }
    var s2: zstd.Stream = try .init(gpa, .{});
    defer s2.deinit();
    var o: zstd.OutBuffer = .{ .dst = &plain };
    var i: zstd.InBuffer = .{ .src = &src };
    while (try s2.compressStream2(&o, &i, .end) != 0) {}
    try std.testing.expect(n1 < o.pos / 2); // the first frame used the prefix
    try std.testing.expectEqualSlices(u8, plain[0..o.pos], second[0..n2]); // the second did not
}

test "stable_in_buffer: a held-back input resumed at the wrong position is refused" {
    var data: [64]u8 = undefined;
    for (&data, 0..) |*b, k| b.* = @intCast(k);
    var out: [4096]u8 = undefined;
    var s: zstd.Stream = try .init(gpa, .{ .advanced = .{ .stable_in_buffer = true } });
    defer s.deinit();
    var o: zstd.OutBuffer = .{ .dst = &out };
    var in: zstd.InBuffer = .{ .src = data[0..10] };
    _ = try s.compressStream2(&o, &in, .@"continue");
    try std.testing.expectEqual(@as(usize, 10), in.pos);
    // the same buffer pointer, a position above the held-back count but not where the last call left it
    var wrong: zstd.InBuffer = .{ .src = data[0..20], .pos = 12 };
    try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&o, &wrong, .@"continue"));
}
