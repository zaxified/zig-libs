// SPDX-License-Identifier: MIT
//! Decoder edge cases: frame structure, frame utilities and the errors a
//! malformed frame must produce. Every expectation here was checked
//! against libzstd 1.5.7 (`tools/zdec.c`): same result, same error code
//! (named after `ZSTD_error_*`), except where a comment says otherwise.
//! Whole-corpus decoding is in the golden and stream tests.

const std = @import("std");
const builtin = @import("builtin");
const zstd = @import("root.zig");

const gpa = std.testing.allocator;

const magic = [4]u8{ 0x28, 0xb5, 0x2f, 0xfd };
/// Single-segment frame, 1-byte content size 0, one empty raw last block.
const empty_frame = magic ++ [_]u8{ 0x20, 0x00, 0x01, 0x00, 0x00 };
/// Content size 5, one raw last block "hello".
const raw_frame = magic ++ [_]u8{ 0x20, 0x05, 0x29, 0x00, 0x00 } ++ "hello".*;
/// Content size 64, one RLE last block of 'z'.
const rle_frame = magic ++ [_]u8{ 0x20, 0x40, 0x03, 0x02, 0x00, 'z' };
/// Skippable frame (magic variant 0xA) carrying "hi".
const skippable = [_]u8{ 0x5a, 0x2a, 0x4d, 0x18, 0x02, 0x00, 0x00, 0x00, 'h', 'i' };
/// Window 1 KB, no content size; a compressed block with raw literals
/// "abc" and no sequence.
const zero_seq_frame = magic ++ [_]u8{ 0x00, 0x00, 0x2d, 0x00, 0x00, 0x18, 'a', 'b', 'c', 0x00 };

fn decodeAll(src: []const u8) ![]u8 {
    return zstd.decompressAlloc(gpa, src, 1 << 24);
}

test "hand-built frames: empty, raw, RLE, compressed with zero sequences" {
    const e = try decodeAll(&empty_frame);
    defer gpa.free(e);
    try std.testing.expectEqual(@as(usize, 0), e.len);
    const r = try decodeAll(&raw_frame);
    defer gpa.free(r);
    try std.testing.expectEqualStrings("hello", r);
    const z = try decodeAll(&rle_frame);
    defer gpa.free(z);
    try std.testing.expectEqualSlices(u8, &([_]u8{'z'} ** 64), z);
    const s = try decodeAll(&zero_seq_frame);
    defer gpa.free(s);
    try std.testing.expectEqualStrings("abc", s);
}

test "a zero-sequence section with a byte after it is corrupt" {
    var f = zero_seq_frame ++ [_]u8{0};
    f[6] = 0x35; // block size 6
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.CorruptionDetected, zstd.decompress(gpa, &out, &f));
}

test "skippable frames are skipped, read, and recognised" {
    const src = skippable ++ raw_frame ++ skippable;
    const out = try decodeAll(&src);
    defer gpa.free(out);
    try std.testing.expectEqualStrings("hello", out);

    try std.testing.expect(zstd.isFrame(&skippable) and zstd.isSkippableFrame(&skippable));
    try std.testing.expect(zstd.isFrame(&raw_frame) and !zstd.isSkippableFrame(&raw_frame));
    try std.testing.expect(!zstd.isFrame("abcd"));
    var buf: [4]u8 = undefined;
    const sk = try zstd.readSkippableFrame(&buf, &skippable);
    try std.testing.expectEqual(@as(usize, 2), sk.len);
    try std.testing.expectEqual(@as(u32, 0xA), sk.magic_variant);
    try std.testing.expectEqualStrings("hi", buf[0..2]);
    var small: [1]u8 = undefined;
    try std.testing.expectError(error.DstSizeTooSmall, zstd.readSkippableFrame(&small, &skippable));
    try std.testing.expectEqual(@as(?u64, 0), try zstd.getFrameContentSize(&skippable));
    try std.testing.expectEqual(@as(usize, skippable.len), try zstd.findFrameCompressedSize(&skippable));
    // a skippable frame claiming more than is there
    try std.testing.expectError(error.SrcSizeWrong, zstd.findFrameCompressedSize(skippable[0..9]));
}

test "concatenated frames decode to the concatenation; size queries agree" {
    const a = try zstd.compressAlloc(gpa, "first frame " ** 50, .{ .level = 3 });
    defer gpa.free(a);
    const b = try zstd.compressAlloc(gpa, "second one, checksummed " ** 70, .{ .level = 19, .checksum = true });
    defer gpa.free(b);
    const src = try std.mem.concat(gpa, u8, &.{ a, &skippable, b });
    defer gpa.free(src);
    const out = try decodeAll(src);
    defer gpa.free(out);
    try std.testing.expectEqualStrings("first frame " ** 50 ++ "second one, checksummed " ** 70, out);
    try std.testing.expectEqual(a.len, try zstd.findFrameCompressedSize(src));
    try std.testing.expectEqual(@as(?u64, out.len), try zstd.findDecompressedSize(src));
    try std.testing.expectEqual(@as(u64, out.len), try zstd.decompressBound(src));
    const h = (try zstd.getFrameHeader(b)).header;
    try std.testing.expect(h.checksum);
    try std.testing.expectEqual(@as(?u64, 24 * 70), h.content_size);
    try std.testing.expectEqual(@as(usize, h.header_size), try zstd.frameHeaderSize(b));
    // trailing bytes after the frames
    for ([_]usize{ 1, 4, 5 }) |extra| {
        const t = try std.mem.concat(gpa, u8, &.{ src, ("\x00" ** 5)[0..extra] });
        defer gpa.free(t);
        const buf = try gpa.alloc(u8, out.len + 16);
        defer gpa.free(buf);
        try std.testing.expectError(error.SrcSizeWrong, zstd.decompress(gpa, buf, t));
    }
}

test "a streamed frame of unknown size decodes through the bound" {
    var s = try zstd.Stream.init(gpa, .{ .level = 1 });
    defer s.deinit();
    var buf: [512]u8 = undefined;
    var o: zstd.OutBuffer = .{ .dst = &buf };
    const text = "no content size in this header " ** 10;
    // `continue` first: ended in its first call, a stream records the size
    var in: zstd.InBuffer = .{ .src = text };
    _ = try s.compressStream2(&o, &in, .@"continue");
    var none: zstd.InBuffer = .{ .src = "" };
    try std.testing.expectEqual(@as(usize, 0), try s.compressStream2(&o, &none, .end));
    const z = buf[0..o.pos];
    try std.testing.expectEqual(@as(?u64, null), try zstd.getFrameContentSize(z));
    try std.testing.expectEqual(@as(?u64, null), try zstd.findDecompressedSize(z));
    const out = try decodeAll(z);
    defer gpa.free(out);
    try std.testing.expectEqualStrings(text, out);
    // the bound is one maximal block per block, capped by `max_size` in decompressAlloc
    try std.testing.expect(try zstd.decompressBound(z) >= text.len);
}

test "content checksum: a wrong one is refused unless ignored" {
    const z = try zstd.compressAlloc(gpa, "checksummed content " ** 20, .{ .checksum = true });
    defer gpa.free(z);
    z[z.len - 1] ^= 1;
    var out: [512]u8 = undefined;
    try std.testing.expectError(error.ChecksumWrong, zstd.decompress(gpa, &out, z));
    var d = try zstd.Decompressor.init(gpa, .{ .ignore_checksum = true });
    defer d.deinit();
    try std.testing.expectEqual(@as(usize, 400), try d.decompress(&out, z));
    // the checksum field cut off
    try std.testing.expectError(error.ChecksumWrong, zstd.decompress(gpa, &out, z[0 .. z.len - 1]));
}

test "frame header errors" {
    var out: [64]u8 = undefined;
    // reserved bit
    var f = raw_frame;
    f[4] |= 0x08;
    try std.testing.expectError(error.FrameParameterUnsupported, zstd.decompress(gpa, &out, &f));
    // window log 10 + 22 = 32 > 31
    const wide = magic ++ [_]u8{ 0x00, 22 << 3, 0x01, 0x00, 0x00 };
    try std.testing.expectError(error.FrameParameterWindowTooLarge, zstd.decompress(gpa, &out, &wide));
    // unknown magic, and garbage where a second frame should start
    try std.testing.expectError(error.PrefixUnknown, zstd.decompress(gpa, &out, "not a zstd frame"));
    // under 9 bytes the size check comes first, as in libzstd
    try std.testing.expectError(error.SrcSizeWrong, zstd.decompress(gpa, &out, "not zstd"));
    // after a complete frame, a wrong magic is reported as a size error
    // (at least 9 bytes of it, or the size check alone catches it)
    const two = raw_frame ++ "garbage, not a frame".*;
    try std.testing.expectError(error.SrcSizeWrong, zstd.decompress(gpa, &out, &two));
    // a dictionary ID with no dictionary loaded
    const with_dict = magic ++ [_]u8{ 0x21, 0x07, 0x05, 0x29, 0x00, 0x00 } ++ "hello".*;
    try std.testing.expectEqual(@as(u32, 7), zstd.getDictIdFromFrame(&with_dict));
    try std.testing.expectError(error.DictionaryWrong, zstd.decompress(gpa, &out, &with_dict));
    // the content size disagrees with the blocks
    var short = raw_frame;
    short[5] = 4;
    try std.testing.expectError(error.CorruptionDetected, zstd.decompress(gpa, &out, &short));
    // reserved block type
    var reserved = raw_frame;
    reserved[6] = 0x2f;
    try std.testing.expectError(error.CorruptionDetected, zstd.decompress(gpa, &out, &reserved));
}

test "every truncation of a frame is refused" {
    const z = try zstd.compressAlloc(gpa, "truncate me somewhere, anywhere at all " ** 30, .{ .level = 5, .checksum = true });
    defer gpa.free(z);
    var out: [2048]u8 = undefined;
    for (1..z.len) |n| {
        if (zstd.decompress(gpa, &out, z[0..n])) |_| {
            std.debug.print("accepted a frame cut at {d} of {d}\n", .{ n, z.len });
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "a destination too small is refused" {
    const z = try zstd.compressAlloc(gpa, "x" ** 1000 ++ "yz" ** 500, .{});
    defer gpa.free(z);
    var out: [1999]u8 = undefined;
    try std.testing.expectError(error.DstSizeTooSmall, zstd.decompress(gpa, &out, z));
    try std.testing.expectError(error.DstSizeTooSmall, zstd.decompressAlloc(gpa, z, 1999));
    try std.testing.expectError(error.DstSizeTooSmall, zstd.decompress(gpa, out[0..10], &raw_frame ++ raw_frame ++ raw_frame));
}

test "a raw block larger than the block maximum: one-shot takes it, the piecewise decoder does not" {
    // window 1 KB => Block_Maximum_Size 1 KB; one raw block of 1025 bytes,
    // no content size. libzstd's one-shot decoder does not bound raw
    // blocks; its streaming decoder (without the single-pass shortcut)
    // refuses them, as RFC 8878 asks.
    var f: [4 + 2 + 3 + 1025]u8 = undefined;
    @memcpy(f[0..4], &magic);
    f[4] = 0x00;
    f[5] = 0x00; // window log 10
    const h: u32 = (1025 << 3) | 1;
    f[6] = @truncate(h);
    f[7] = @truncate(h >> 8);
    f[8] = @truncate(h >> 16);
    @memset(f[9..], 'q');
    var out: [2048]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1025), try zstd.decompress(gpa, &out, &f));

    var s = try zstd.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var o: zstd.OutBuffer = .{ .dst = &out };
    // header and block header only: refused at the block header already
    // ("Block Size Exceeds Maximum")
    var in: zstd.InBuffer = .{ .src = f[0..9] };
    try std.testing.expectError(error.CorruptionDetected, s.decompressStream(&o, &in));
}

test "a context is reusable across frames and after errors" {
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    var out: [4096]u8 = undefined;
    const z = try zstd.compressAlloc(gpa, "reuse " ** 400, .{ .level = 9 });
    defer gpa.free(z);
    for (0..3) |_| {
        try std.testing.expectEqual(@as(usize, 2400), try d.decompress(&out, z));
        try std.testing.expectError(error.PrefixUnknown, d.decompress(&out, "junk, not a frame"));
    }
    try std.testing.expectEqualStrings("reuse " ** 400, out[0..2400]);
}

test "window size: exponent and mantissa" {
    // window byte 0x0B: log 10 + 1 = 11 (2048), mantissa 3: + 3 * 2048/8
    const f = magic ++ [_]u8{ 0x00, 0x0B, 0x01, 0x00, 0x00 };
    const h = (try zstd.getFrameHeader(&f)).header;
    try std.testing.expectEqual(@as(u64, 2816), h.window_size);
    try std.testing.expectEqual(@as(u32, 2816), h.block_size_max);
    try std.testing.expectEqual(@as(?u64, null), h.content_size);
}

test "header queries on short input" {
    try std.testing.expectEqual(zstd.HeaderResult{ .need = 5 }, try zstd.getFrameHeader(magic[0..3]));
    try std.testing.expectEqual(zstd.HeaderResult{ .need = 6 }, try zstd.getFrameHeader(empty_frame[0..5]));
    try std.testing.expectEqual(zstd.HeaderResult{ .need = 8 }, try zstd.getFrameHeader(skippable[0..6]));
    try std.testing.expectError(error.SrcSizeWrong, zstd.getFrameContentSize(magic[0..3]));
    try std.testing.expectEqual(@as(u32, 0), zstd.getDictIdFromFrame("xx"));
    try std.testing.expectEqual(@as(usize, 9), try zstd.decompressionMargin(&empty_frame));
}

test "damaged frames give libzstd's verdict (mutation-sweep fixtures)" {
    // Each frame pins one decision the rest of the suite does not reach
    // (see testdata/decode_kats.zig for which).
    const kats = @import("testdata/decode_kats.zig").kats;
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    // libzstd's fast Huffman loop (and this port's) runs on 64-bit
    // little-endian only; a few damaged frames get another verdict without it
    const fast_loop = builtin.cpu.arch.endian() == .little and @sizeOf(usize) == 8;
    var failures: usize = 0;
    for (kats) |kat| {
        var k = kat;
        if (!fast_loop) if (kat.expect_no_fast_loop) |e| {
            k.expect = e;
        };
        const bound = zstd.decompressBound(k.frame) catch |e| {
            if (!(k.expect == .err and k.expect.err == e)) {
                std.debug.print("{s}: decompressBound {s}\n", .{ k.name, @errorName(e) });
                failures += 1;
            }
            continue;
        };
        // capped: a damaged header may claim terabytes (libzstd's verdict on
        // each frame is the same at this capacity)
        const out = try gpa.alloc(u8, @intCast(@min(bound, 1 << 20)));
        defer gpa.free(out);
        if (d.decompress(out, k.frame)) |n| {
            var h: u64 = 0xcbf29ce484222325;
            for (out[0..n]) |b| {
                h ^= b;
                h *%= 0x100000001b3;
            }
            if (!(k.expect == .ok and k.expect.ok.len == n and k.expect.ok.fnv1a64 == h)) {
                std.debug.print("{s}: decoded {d} bytes ({s})\n", .{ k.name, n, k.kills });
                failures += 1;
            }
        } else |e| {
            if (!(k.expect == .err and k.expect.err == e)) {
                std.debug.print("{s}: {s} ({s})\n", .{ k.name, @errorName(e), k.kills });
                failures += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
    try std.testing.expectEqual(@as(usize, 11), kats.len);
}
