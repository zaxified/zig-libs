// SPDX-License-Identifier: MIT
//! Regression tests of the no-panic sweep over the decoder side (SPEC.md,
//! Backlog; wave GL, findings ZD-*). Each test names its finding and fails
//! (panics) without the fix it belongs to.

const std = @import("std");
const zstd = @import("root.zig");
const dblock = @import("dblock.zig");

const gpa = std.testing.allocator;

/// One `decompressContinue` step with exactly the bytes it asks for.
fn feed(d: *zstd.Decompressor, dst: []u8, src: []const u8) !usize {
    try std.testing.expectEqual(src.len, d.nextSrcSizeWithInputSize(src.len));
    return d.decompressContinue(dst, src);
}

test "stream: an offset into the wrapped output ring does not copy over itself (sweep ZD-1)" {
    // A window of 1 KiB: blocks of 1 KiB, a ring of window + 2 blocks + 64 =
    // 3136 bytes. Three raw blocks fill 3072 of it; the next block starts at
    // the front again, and the 3072 bytes behind it are the older segment
    // (`ext`) -- which is the ring itself. A conforming encoder never reaches
    // further back than the window; a corrupt offset of exactly 3072 names
    // the bytes this very match writes over (`ext[0..3]` onto `out[0..3]`).
    const block = 1024;
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    try frame.appendSlice(gpa, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00 });
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    for (0..3) |i| {
        try frame.appendSlice(gpa, &.{ 0x00, 0x20, 0x00 }); // raw, 1024 bytes, not last
        for (0..block) |k| {
            const b: u8 = @truncate(k *% 7 +% i);
            try frame.append(gpa, b);
            try plain.append(gpa, b);
        }
    }
    // The offset code with 11 extra bits (default table) and the offset 3072.
    var of_state: u32 = 0;
    var of_base: u32 = 0;
    for (dblock.of_default.cells[0..32], 0..) |c, i| {
        if (c.nb_additional_bits == 11) {
            of_state = @intCast(i);
            of_base = c.base_value;
        }
    }
    try std.testing.expect(of_base != 0);
    const extra: u32 = 3072 - of_base;
    // Backward bit stream, read top down after the end mark: the LL, OF and ML
    // states (6, 5, 6 bits; state 0 of LL and ML is literal length 0 and match
    // length 3 without extra bits), then the 11 offset bits.
    const bits: u32 = (1 << 28) | (of_state << 17) | extra;
    try frame.appendSlice(gpa, &.{ 0x3d, 0x00, 0x00 }); // compressed, 7 bytes, last
    try frame.appendSlice(gpa, &.{ 0x00, 0x01, 0x00 }); // no literals, 1 sequence, default tables
    var w: [4]u8 = undefined;
    std.mem.writeInt(u32, &w, bits, .little);
    try frame.appendSlice(gpa, &w);

    var s = try zstd.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var out_buf: [8192]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = frame.items };
    var out: zstd.OutBuffer = .{ .dst = &out_buf };
    var calls: usize = 0;
    while ((try s.decompressStream(&out, &in)) != 0) {
        calls += 1;
        try std.testing.expect(calls < 64);
    }
    try std.testing.expectEqual(plain.items.len + 3, out.pos);
    try std.testing.expectEqualSlices(u8, plain.items, out_buf[0..plain.items.len]);
}

/// A decoding state ready for `decompressBlock`, its literal buffer's first
/// 16 bytes holding 100..115 (the 16-byte literal copy of every sequence
/// writes them to `out`, empty literals or not).
fn newState() !*dblock.State {
    const st = try gpa.create(dblock.State);
    st.* = .{};
    st.huf_ptr = &st.huf;
    @memset(st.lit_buf[dblock.block_size_max..], 0);
    st.begin();
    for (0..16) |i| st.lit_buf[i] = @intCast(100 + i);
    return st;
}

/// A compressed block of no literals and one sequence (literal length 0,
/// match length 3, `offset` >= 1) in the default tables, the offset's code
/// being the one with `of_base[code] <= offset < of_base[code] + 2^code`.
fn oneSequenceBlock(offset: u32, buf: *[7]u8) []const u8 {
    var code: u5 = 2;
    while (offset >= dblock.of_base[code] + (@as(u32, 1) << code)) code += 1;
    var of_state: u32 = 0;
    for (dblock.of_default.cells[0..32], 0..) |c, i| {
        if (c.nb_additional_bits == code and c.base_value == dblock.of_base[code]) of_state = @intCast(i);
    }
    // Backward bit stream, read top down after the end mark: the LL, OF and
    // ML states (6, 5, 6 bits; state 0 of LL and ML is length 0 and 3 without
    // extra bits), then the offset's extra bits.
    const k: u5 = code;
    const bits: u32 = (@as(u32, 1) << (k + 17)) | (of_state << (k + 6)) | (offset - dblock.of_base[code]);
    buf[0..3].* = .{ 0x00, 0x01, 0x00 }; // no literals, 1 sequence, default tables
    var w: [4]u8 = undefined;
    std.mem.writeInt(u32, &w, bits, .little);
    const n = (@as(usize, k) + 18 + 7) / 8;
    @memcpy(buf[3..][0..n], w[0..n]);
    return buf[0 .. 3 + n];
}

test "dblock: a match that starts in the older segment, which lies on the output (sweep ZD-1)" {
    // The segment behind the output may be the output's own memory (the
    // stream's ring after a wrap), so the copy is a memmove, not a memcpy.
    const st = try newState();
    defer gpa.destroy(st);
    var buf: [128]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @intCast(i);
    var blk: [7]u8 = undefined;
    // out[0..3) <- ext[0..3) = buf[2..5), 2 bytes ahead of it
    const h: dblock.History = .{ .out = &buf, .prefix = 0, .ext = buf[2..34] };
    const n = try dblock.decompressBlock(st, &h, 0, buf.len, oneSequenceBlock(32, &blk), true);
    try std.testing.expectEqual(@as(usize, 3), n);
    // buf[2..5) was 2, 3, 4 before the literal copy wrote 100.. over buf[0..16)
    try std.testing.expectEqualSlices(u8, &.{ 102, 103, 104 }, buf[0..3]);
}

test "dblock: a match that starts in the older segment and runs on into the output (sweep ZD-1)" {
    const st = try newState();
    defer gpa.destroy(st);
    var buf: [128]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @intCast(i);
    var blk: [7]u8 = undefined;
    // The output starts at 31, the older segment is buf[0..32): the 2 bytes
    // before the prefix are buf[30..32) and go to buf[31..33), one byte over
    // themselves; the last byte of the match then comes from the prefix.
    const h: dblock.History = .{ .out = &buf, .prefix = 31, .ext = buf[0..32] };
    const n = try dblock.decompressBlock(st, &h, 31, buf.len - 31, oneSequenceBlock(2, &blk), true);
    try std.testing.expectEqual(@as(usize, 3), n);
    // buf[31] was 100 after the literal copy: a memmove reads it before it
    // is overwritten, a forward byte copy would give 30, 30 instead of 30, 100
    try std.testing.expectEqualSlices(u8, &.{ 30, 100, 30 }, buf[31..34]);
}

test "decompressContinue: an empty src once the frame is over is an error (sweep ZD-2)" {
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    d.begin();
    const frame = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 }; // the empty frame
    var dst: [16]u8 = undefined;
    var pos: usize = 0;
    while (d.nextSrcSizeToDecompress() != 0) {
        const n = d.nextSrcSizeWithInputSize(frame.len - pos);
        _ = try d.decompressContinue(&dst, frame[pos..][0..n]);
        pos += n;
    }
    try std.testing.expectEqual(frame.len, pos);
    // nothing is expected any more; asking for one more step is a mistake
    try std.testing.expectError(error.SrcSizeWrong, d.decompressContinue(&dst, &.{}));
    // and the context goes on with the next frame
    d.begin();
    pos = 0;
    while (d.nextSrcSizeToDecompress() != 0) {
        const n = d.nextSrcSizeWithInputSize(frame.len - pos);
        _ = try d.decompressContinue(&dst, frame[pos..][0..n]);
        pos += n;
    }
    try std.testing.expectEqual(frame.len, pos);
}

test "decompressContinue: an empty output parked elsewhere leaves no negative history (sweep ZD-3)" {
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    d.begin();
    var buf: [16]u8 = undefined;
    // an empty slice of some other (here: lower) address than `buf`
    const park: []u8 = @as([*]u8, @ptrFromInt(1))[0..0];

    _ = try feed(&d, &buf, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x00 }); // magic, descriptor
    _ = try feed(&d, &buf, &.{0x00}); // window of 1 KiB
    _ = try feed(&d, &buf, &.{ 0x20, 0x00, 0x00 }); // raw block of 4, not last
    try std.testing.expectEqual(@as(usize, 4), try feed(&d, buf[0..4], "abcd"));
    _ = try feed(&d, &buf, &.{ 0x14, 0x00, 0x00 }); // compressed block of 2 bytes, not last
    // no literals, no sequences: decodes to nothing, into nothing
    try std.testing.expectEqual(@as(usize, 0), try feed(&d, park, &.{ 0x00, 0x00 }));
    _ = try feed(&d, &buf, &.{ 0x21, 0x00, 0x00 }); // raw block of 4, last
    // the next output follows `buf[0..4]`, not the parked empty one
    try std.testing.expectEqual(@as(usize, 4), try feed(&d, buf[4..8], "wxyz"));
    try std.testing.expectEqualStrings("abcdwxyz", buf[0..8]);
    try std.testing.expectEqual(@as(usize, 0), d.nextSrcSizeToDecompress());
}

test "SeekableStream.compressStream: in.pos past the end is an error (sweep ZD-4)" {
    var s = try zstd.seekable.SeekableStream.init(gpa, .{ .max_frame_size = 4096 });
    defer s.deinit();
    var buf: [64]u8 = undefined;
    var out: zstd.OutBuffer = .{ .dst = &buf };
    var in: zstd.InBuffer = .{ .src = "abc", .pos = 4 };
    try std.testing.expectError(error.InvalidBuffer, s.compressStream(&out, &in));
    try std.testing.expectEqual(@as(usize, 0), out.pos);
}

test "FrameLog.writeSeekTable: out.pos past the end writes nothing (sweep ZD-5)" {
    var fl = zstd.seekable.FrameLog.init(false);
    defer fl.deinit(gpa);
    try fl.logFrame(gpa, 10, 20, 0);
    var small: [8]u8 = undefined;
    var bad: zstd.OutBuffer = .{ .dst = &small, .pos = 9 };
    try std.testing.expectEqual(fl.seekTableSize(), fl.writeSeekTable(&bad));
    try std.testing.expectEqual(@as(usize, 9), bad.pos);
    // no room is no room: a later call with a real buffer writes the whole table
    var big: [64]u8 = undefined;
    var ok: zstd.OutBuffer = .{ .dst = &big };
    try std.testing.expectEqual(@as(usize, 0), fl.writeSeekTable(&ok));
    try std.testing.expectEqual(fl.seekTableSize(), ok.pos);
}

/// Frame "abcd" raw, an empty compressed block parked into `park` (an empty
/// slice at a HIGHER address than the output), then the one-sequence block
/// with `offset` into `big[4..]`.
fn parkedHigher(offset: u32, big: []u8) !usize {
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    d.begin();
    const none = big[0..0];
    const park = big[2048..2048]; // empty, above everything decoded
    _ = try feed(&d, none, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x00 }); // magic, descriptor
    _ = try feed(&d, none, &.{0x00}); // window of 1 KiB
    _ = try feed(&d, none, &.{ 0x20, 0x00, 0x00 }); // raw block of 4, not last
    try std.testing.expectEqual(@as(usize, 4), try feed(&d, big[0..4], "abcd"));
    _ = try feed(&d, none, &.{ 0x14, 0x00, 0x00 }); // compressed block of 2 bytes, not last
    try std.testing.expectEqual(@as(usize, 0), try feed(&d, park, &.{ 0x00, 0x00 })); // no literals, no sequences
    var blk: [7]u8 = undefined;
    const b = oneSequenceBlock(offset, &blk);
    _ = try feed(&d, none, &.{ @as(u8, @intCast(b.len << 3 | 4)), 0x00, 0x00 }); // compressed, not last
    return feed(&d, big[4..64], b);
}

test "decompressContinue: an empty output parked at a higher address adds no history (sweep R-Z-1)" {
    var big: [4096]u8 = undefined;
    // offset 4 is "abcd" itself: fine; offset 100 reaches past the real
    // history, which is 4 bytes -- not the bytes up to the parked address
    @memset(&big, 0xee);
    try std.testing.expectEqual(@as(usize, 3), try parkedHigher(4, &big));
    try std.testing.expectEqualStrings("abcdabc", big[0..7]);
    @memset(&big, 0xee);
    try std.testing.expectError(error.CorruptionDetected, parkedHigher(100, &big));
}
