// SPDX-License-Identifier: MIT
//! Decoder boundary tests found by whole-module mutation: the
//! literals section header of a compressed block at every size form and at
//! the exact edges of the block, built byte by byte. The expectations follow
//! RFC 8878 section 3.1.1.3.1 and libzstd's `ZSTD_decodeLiteralsBlock`
//! (which `dblock.zig` ports): the same error where libzstd reports one.

const std = @import("std");
const zstd = @import("root.zig");
const literals = @import("literals.zig");

const gpa = std.testing.allocator;
const magic = [4]u8{ 0x28, 0xb5, 0x2f, 0xfd };

/// A frame of unknown content size and window byte `win` (0: 1 KiB, so the
/// block maximum is 1024; 0x38: 128 KiB) whose blocks are `blocks`, the
/// last one marked last. Every block is a compressed one.
fn frameOf(win: u8, blocks: []const []const u8) ![]u8 {
    var f: std.ArrayList(u8) = .empty;
    errdefer f.deinit(gpa);
    try f.appendSlice(gpa, &(magic ++ [_]u8{ 0x00, win }));
    for (blocks, 0..) |block, i| {
        const last: u32 = @intFromBool(i + 1 == blocks.len);
        const bh: u32 = last | (2 << 1) | (@as(u32, @intCast(block.len)) << 3);
        try f.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, bh))[0..3]);
        try f.appendSlice(gpa, block);
    }
    return f.toOwnedSlice(gpa);
}

fn decodeBlocks(win: u8, blocks: []const []const u8, out: []u8) !usize {
    const f = try frameOf(win, blocks);
    defer gpa.free(f);
    return zstd.decompress(gpa, out, f);
}

fn decode1(win: u8, block: []const u8, out: []u8) !usize {
    return decodeBlocks(win, &.{block}, out);
}

fn pattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
}

/// Skewed bytes over 16 values, which Huffman-code well.
fn skewed(buf: []u8, seed: u64) void {
    var s = seed;
    for (buf) |*b| {
        s = s *% 6364136223846793005 +% 1442695040888963407;
        const r: u32 = @truncate(s >> 40);
        b.* = @intCast(@min(@ctz(r | 0x8000), 15));
    }
}

fn hdr16(n: usize) [2]u8 {
    const v: u32 = (1 << 2) | (@as(u32, @intCast(n)) << 4);
    return .{ @truncate(v), @truncate(v >> 8) };
}

fn hdr24(n: usize) [3]u8 {
    const v: u32 = (3 << 2) | (@as(u32, @intCast(n)) << 4);
    return .{ @truncate(v), @truncate(v >> 8), @truncate(v >> 16) };
}

test "raw literals: every header form and the block's edges" {
    var out: [4096]u8 = undefined;
    var lits: [1100]u8 = undefined;
    pattern(&lits);
    // one-byte header: the size is bits 3..7, so odd sizes read as size code 2, even as 0
    for ([_]usize{ 0, 1, 2, 30, 31 }) |n| {
        var blk: [1 + 31 + 1]u8 = undefined;
        blk[0] = @intCast(n << 3);
        @memcpy(blk[1..][0..n], lits[0..n]);
        blk[1 + n] = 0; // no sequences
        try std.testing.expectEqual(n, try decode1(0, blk[0 .. n + 2], &out));
        try std.testing.expectEqualSlices(u8, lits[0..n], out[0..n]);
    }
    // two-byte header, 12-bit size
    for ([_]usize{ 0, 1, 31, 32, 300, 1021 }) |n| {
        var blk: [2 + 1024 + 1]u8 = undefined;
        const h = hdr16(n);
        @memcpy(blk[0..2], &h);
        @memcpy(blk[2..][0..n], lits[0..n]);
        blk[2 + n] = 0;
        try std.testing.expectEqual(n, try decode1(0, blk[0 .. n + 3], &out));
        try std.testing.expectEqualSlices(u8, lits[0..n], out[0..n]);
    }
    // three-byte header
    for ([_]usize{ 0, 1, 1020 }) |n| {
        var blk: [3 + 1024 + 1]u8 = undefined;
        const h = hdr24(n);
        @memcpy(blk[0..3], &h);
        @memcpy(blk[3..][0..n], lits[0..n]);
        blk[3 + n] = 0;
        try std.testing.expectEqual(n, try decode1(0, blk[0 .. n + 4], &out));
        try std.testing.expectEqualSlices(u8, lits[0..n], out[0..n]);
    }
    // too short for its own header
    try std.testing.expectError(error.CorruptionDetected, decode1(0, &.{0x00}, &out)); // min block 2
    try std.testing.expectEqual(@as(usize, 0), try decode1(0, &.{ 0x00, 0x00 }, &out));
    try std.testing.expectError(error.CorruptionDetected, decode1(0, &.{ 0x0c, 0x00 }, &out)); // 3-byte header in 2 bytes
    try std.testing.expectError(error.SrcSizeWrong, decode1(0, &.{ 0x0c, 0x00, 0x00 }, &out)); // header only, no sequences
    try std.testing.expectEqual(@as(usize, 0), try decode1(0, &.{ 0x0c, 0x00, 0x00, 0x00 }, &out));
    try std.testing.expectError(error.SrcSizeWrong, decode1(0, &.{ 0x04, 0x00 }, &out)); // 2-byte header, no sequences
    try std.testing.expectEqual(@as(usize, 0), try decode1(0, &.{ 0x04, 0x00, 0x00 }, &out));
    // the literals run past the block / end exactly where it ends
    {
        var blk: [11]u8 = undefined;
        blk[0] = 10 << 3;
        @memcpy(blk[1..11], lits[0..10]);
        try std.testing.expectError(error.SrcSizeWrong, decode1(0, &blk, &out)); // fits, no sequences section
        try std.testing.expectError(error.CorruptionDetected, decode1(0, blk[0..10], &out)); // one byte short
    }
    // a destination below the literals
    {
        const h = hdr24(100);
        var b2: [104]u8 = undefined;
        @memcpy(b2[0..3], &h);
        @memcpy(b2[3..][0..100], lits[0..100]);
        b2[103] = 0;
        try std.testing.expectEqual(@as(usize, 100), try decode1(0, &b2, out[0..100]));
        try std.testing.expectError(error.DstSizeTooSmall, decode1(0, &b2, out[0..99]));
    }
}

test "RLE literals: every header form and edge" {
    var out: [4096]u8 = undefined;
    // one-byte header
    for ([_]usize{ 0, 1, 31 }) |n| {
        try std.testing.expectEqual(n, try decode1(0, &.{ @as(u8, @intCast((n << 3) | 1)), 'q', 0 }, &out));
        try std.testing.expect(std.mem.allEqual(u8, out[0..n], 'q'));
    }
    // two-byte header: 12-bit size; the value byte must be there
    for ([_]usize{ 0, 1, 31, 32, 1024 }) |n| {
        const v: u32 = 1 | (1 << 2) | (@as(u32, @intCast(n)) << 4);
        const b = [_]u8{ @truncate(v), @truncate(v >> 8), 'r', 0 };
        try std.testing.expectEqual(n, try decode1(0, &b, &out));
        try std.testing.expect(std.mem.allEqual(u8, out[0..n], 'r'));
    }
    try std.testing.expectError(error.CorruptionDetected, decode1(0, &.{ 0x05, 0x00 }, &out)); // no value byte
    try std.testing.expectError(error.SrcSizeWrong, decode1(0, &.{ 0x05, 0x00, 'x' }, &out)); // value, no sequences
    // three-byte header
    for ([_]usize{ 0, 1, 1024 }) |n| {
        const v: u32 = 1 | (3 << 2) | (@as(u32, @intCast(n)) << 4);
        const b = [_]u8{ @truncate(v), @truncate(v >> 8), @truncate(v >> 16), 's', 0 };
        try std.testing.expectEqual(n, try decode1(0, &b, &out));
        try std.testing.expect(std.mem.allEqual(u8, out[0..n], 's'));
    }
    const h3 = [_]u8{ 0x0d, 0x00, 0x00 };
    try std.testing.expectError(error.CorruptionDetected, decode1(0, &h3, &out)); // no value byte
    try std.testing.expectError(error.SrcSizeWrong, decode1(0, &(h3 ++ [_]u8{'x'}), &out));
    {
        const v: u32 = 1 | (3 << 2) | (@as(u32, 1025) << 4);
        const b = [_]u8{ @truncate(v), @truncate(v >> 8), @truncate(v >> 16), 's', 0 };
        try std.testing.expectError(error.CorruptionDetected, decode1(0, &b, &out));
        const v2: u32 = 1 | (1 << 2) | (@as(u32, 1025) << 4);
        const b2 = [_]u8{ @truncate(v2), @truncate(v2 >> 8), 's', 0 };
        try std.testing.expectError(error.CorruptionDetected, decode1(0, &b2, &out));
        const b3 = [_]u8{ (31 << 3) | 1, 's', 0 };
        try std.testing.expectError(error.DstSizeTooSmall, decode1(0, &b3, out[0..30]));
        try std.testing.expectEqual(@as(usize, 31), try decode1(0, &b3, out[0..31]));
    }
}

fn compressedLiterals(strategy: u32, dst: []u8, src: []const u8, prev: *const literals.HufState, next: *literals.HufState) !usize {
    return literals.compress(dst, src, prev, next, strategy, false, false);
}

test "compressed literals: header forms, edges of the section, the four-stream minimum" {
    var out: [32768]u8 = undefined;
    var src: [20000]u8 = undefined;
    skewed(&src, 7);
    var sec: [20100]u8 = undefined;
    const prev: literals.HufState = .{};
    var next: literals.HufState = .{};
    // header sizes 3 (one stream, four streams), 4 and 5
    for ([_]usize{ 40, 300, 1100, 20000 }) |n| {
        const len = try compressedLiterals(9, &sec, src[0..n], &prev, &next);
        try std.testing.expectEqual(@as(u8, 2), sec[0] & 3); // a new table
        var blk: [20100]u8 = undefined;
        @memcpy(blk[0..len], sec[0..len]);
        blk[len] = 0;
        try std.testing.expectEqual(n, try decode1(0x38, blk[0 .. len + 1], &out));
        try std.testing.expectEqualSlices(u8, src[0..n], out[0..n]);
        // no sequences section behind the literals
        try std.testing.expectError(error.SrcSizeWrong, decode1(0x38, blk[0..len], &out));
        // one byte of the compressed literals missing
        try std.testing.expectError(error.CorruptionDetected, decode1(0x38, blk[0 .. len - 1], &out));
    }
    // the block maximum (1 KiB window): 1024 literals pass, 1025 do not
    for ([_]usize{ 1024, 1025 }) |n| {
        const len = try compressedLiterals(9, &sec, src[0..n], &prev, &next);
        sec[len] = 0;
        if (n == 1024) {
            try std.testing.expectEqual(n, try decode1(0, sec[0 .. len + 1], &out));
        } else {
            try std.testing.expectError(error.CorruptionDetected, decode1(0, sec[0 .. len + 1], &out));
        }
    }
    // a four-stream header (size code 1) with fewer than 6 literals is refused,
    // a one-stream header with 5 is not (the table is garbage: corrupt)
    {
        var b: [3 + 12 + 1]u8 = @splat(0x55);
        const four: u32 = 2 | (1 << 2) | (5 << 4) | (12 << 14);
        b[0] = @truncate(four);
        b[1] = @truncate(four >> 8);
        b[2] = @truncate(four >> 16);
        b[15] = 0;
        try std.testing.expectError(error.LiteralsHeaderWrong, decode1(0, &b, &out));
        const one: u32 = 2 | (0 << 2) | (5 << 4) | (12 << 14);
        b[0] = @truncate(one);
        b[1] = @truncate(one >> 8);
        b[2] = @truncate(one >> 16);
        try std.testing.expectError(error.CorruptionDetected, decode1(0, &b, &out));
        const four6: u32 = 2 | (1 << 2) | (6 << 4) | (12 << 14);
        b[0] = @truncate(four6);
        b[1] = @truncate(four6 >> 8);
        b[2] = @truncate(four6 >> 16);
        try std.testing.expectError(error.CorruptionDetected, decode1(0, &b, &out));
    }
    // a repeat-table section with no table before it; and too short (< 5)
    try std.testing.expectError(error.DictionaryCorrupted, decode1(0, &.{ 0x03, 0, 0, 0, 0, 0 }, &out));
    try std.testing.expectError(error.DictionaryCorrupted, decode1(0, &.{ 0x03, 0, 0, 0 }, &out));
    try std.testing.expectError(error.CorruptionDetected, decode1(0, &.{ 0x02, 0, 0, 0 }, &out));
    try std.testing.expectError(error.CorruptionDetected, decode1(0, &.{ 0x0e, 0, 0, 0 }, &out)); // the 5-byte header cut at 4
}

test "treeless literals reuse the previous block's table, down to a 5-byte block" {
    var out: [4096]u8 = undefined;
    var src1: [300]u8 = undefined;
    for (&src1, 0..) |*b, i| b.* = @intCast((i * 2654435761 >> 7) & 1);
    var sec1: [400]u8 = undefined;
    const prev: literals.HufState = .{};
    var next1: literals.HufState = .{};
    const len1 = try compressedLiterals(1, &sec1, &src1, &prev, &next1);
    try std.testing.expectEqual(@as(u8, 2), sec1[0] & 3);
    sec1[len1] = 0;
    // six symbols of the same table: 3-byte header, one byte of stream, no sequences = 5 bytes
    const src2 = [_]u8{ 0, 1, 1, 0, 1, 1 };
    var sec2: [64]u8 = undefined;
    var p2 = next1;
    p2.repeat = .valid;
    var next2: literals.HufState = .{};
    const len2 = try compressedLiterals(1, &sec2, &src2, &p2, &next2);
    try std.testing.expectEqual(@as(u8, 3), sec2[0] & 3);
    try std.testing.expectEqual(@as(usize, 4), len2);
    sec2[len2] = 0;
    // the first block is not the last
    const f = blk: {
        var fr: std.ArrayList(u8) = .empty;
        errdefer fr.deinit(gpa);
        try fr.appendSlice(gpa, &(magic ++ [_]u8{ 0x00, 0x00 }));
        const bh1: u32 = 0 | (2 << 1) | (@as(u32, @intCast(len1 + 1)) << 3);
        try fr.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, bh1))[0..3]);
        try fr.appendSlice(gpa, sec1[0 .. len1 + 1]);
        const bh2: u32 = 1 | (2 << 1) | (@as(u32, @intCast(len2 + 1)) << 3);
        try fr.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, bh2))[0..3]);
        try fr.appendSlice(gpa, sec2[0 .. len2 + 1]);
        break :blk try fr.toOwnedSlice(gpa);
    };
    defer gpa.free(f);
    const n = try zstd.decompress(gpa, &out, f);
    try std.testing.expectEqual(@as(usize, 306), n);
    try std.testing.expectEqualSlices(u8, &src1, out[0..300]);
    try std.testing.expectEqualSlices(u8, &src2, out[300..306]);
}

const huf = @import("huf.zig");
const huf_dec = @import("huf_dec.zig");

fn readStatsOf(src: []const u8, weights: *[256]u8, nb_symbols: *u32, table_log: *u32) !usize {
    var rank: [huf_dec.tablelog_max + 1]u32 = undefined;
    return huf_dec.readStats(weights, &rank, nb_symbols, table_log, src);
}

test "readStats: the direct (4-bit) representation, its edges and every refusal" {
    var w: [256]u8 = undefined;
    var nb: u32 = 0;
    var tl: u32 = 0;
    // weights 2 1 1 and the implied 3; header byte 127 + 3
    const ok = [_]u8{ 130, 0x21, 0x10 };
    try std.testing.expectEqual(@as(usize, 3), try readStatsOf(&ok, &w, &nb, &tl));
    try std.testing.expectEqual(@as(u32, 4), nb);
    try std.testing.expectEqual(@as(u32, 3), tl);
    try std.testing.expectEqualSlices(u8, &.{ 2, 1, 1, 3 }, w[0..4]);
    try std.testing.expectEqual(@as(usize, 3), try readStatsOf(&(ok ++ [_]u8{ 9, 9 }), &w, &nb, &tl)); // trailing bytes are not read
    try std.testing.expectError(error.SrcSizeWrong, readStatsOf(&.{}, &w, &nb, &tl));
    try std.testing.expectError(error.SrcSizeWrong, readStatsOf(ok[0..2], &w, &nb, &tl)); // one byte short
    try std.testing.expectError(error.SrcSizeWrong, readStatsOf(ok[0..1], &w, &nb, &tl));
    // a weight above 11, a total of zero, a total whose rest is no power of two
    try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 130, 0xc1, 0x10 }, &w, &nb, &tl));
    try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 129, 0x00 }, &w, &nb, &tl));
    try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 130, 0x22, 0x10 }, &w, &nb, &tl)); // 2 2 1: total 5
    // table log 12 (three weights of 11) is too large, 11 is not
    try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 130, 0xbb, 0xb0 }, &w, &nb, &tl));
    // 11 and the rest: weights 11 then ones, total 1024 + 512 = ... a valid table of log 11
    {
        var src: [1 + 4]u8 = .{ 128 + 6, 0xb1, 0x11, 0x11, 0x00 };
        // 7 weights: 11, 1 x 6 -> total 1024 + 6 = 1030, log 11, rest 1018: not a power of two
        try std.testing.expectError(error.CorruptionDetected, readStatsOf(&src, &w, &nb, &tl));
        // 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 then implied: 1024+512+256+128+64+32+16+8+4+2+1 = 2047
        // is table log 11 with rest 1: valid; the implied weight is 1
        var s2: [1 + 6]u8 = .{ 128 + 10, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
        try std.testing.expectEqual(@as(usize, 7), try readStatsOf(&s2, &w, &nb, &tl));
        try std.testing.expectEqual(@as(u32, 11), tl);
        try std.testing.expectEqual(@as(u32, 12), nb);
        try std.testing.expectEqual(@as(u8, 1), w[10]);
        try std.testing.expectEqual(@as(u8, 1), w[11]);
        src[0] = 0;
    }
    // the largest table: weights 12, 11 .. 1 and the implied 1 make log 12; a weight of 13, or log 13, is refused
    {
        var s3: [1 + 6]u8 = .{ 128 + 11, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21 };
        try std.testing.expectEqual(@as(usize, 7), try readStatsOf(&s3, &w, &nb, &tl));
        try std.testing.expectEqual(@as(u32, 12), tl);
        try std.testing.expectEqual(@as(u32, 13), nb);
        try std.testing.expectEqual(@as(u8, 12), w[0]);
        try std.testing.expectEqual(@as(u8, 1), w[12]);
        try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 130, 0xcc, 0xc0 }, &w, &nb, &tl)); // log 13
        try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 130, 0xd1, 0x10 }, &w, &nb, &tl)); // a weight of 13
    }
    // too few symbols of weight 1: 3 2 -> total 6, log 3, rest 2: last weight 2, no weight 1 at all
    try std.testing.expectError(error.CorruptionDetected, readStatsOf(&.{ 129, 0x32 }, &w, &nb, &tl));
}

test "readStats reads back what writeCTable wrote, FSE-coded or direct, at every alphabet size" {
    var prng = std.Random.DefaultPrng.init(0x57a7);
    const rnd = prng.random();
    var trial: usize = 0;
    while (trial < 1500) : (trial += 1) {
        const max_symbol: u32 = 2 + rnd.uintLessThan(u32, 254);
        var counts: [256]u32 = @splat(0);
        const skew = 1 + rnd.uintLessThan(u32, 6);
        for (counts[0 .. max_symbol + 1], 0..) |*c, i| {
            const sh: u5 = @intCast(@min(i / 8 * skew, 11));
            const base = rnd.uintLessThan(u32, @as(u32, 3000) >> sh);
            c.* = base + 1;
        }
        var ct: huf.CTable = .{};
        const log = huf.buildCTable(&ct, counts[0 .. max_symbol + 1], max_symbol, 11) catch continue;
        var buf: [300]u8 = @splat(0xaa);
        const len = try huf.writeCTable(&buf, &ct, max_symbol, log);
        var w: [256]u8 = undefined;
        var nb: u32 = 0;
        var tl: u32 = 0;
        try std.testing.expectEqual(len, try readStatsOf(buf[0 .. len + 5], &w, &nb, &tl));
        try std.testing.expectEqual(max_symbol + 1, nb);
        try std.testing.expectEqual(log, tl);
        for (ct.elt[0 .. max_symbol + 1], w[0 .. max_symbol + 1]) |e, wt| {
            try std.testing.expectEqual(@as(u8, if (e.nb_bits == 0) 0 else @intCast(log + 1 - e.nb_bits)), wt);
        }
        try std.testing.expectEqual(len, try readStatsOf(buf[0..len], &w, &nb, &tl));
        try std.testing.expectError(error.SrcSizeWrong, readStatsOf(buf[0 .. len - 1], &w, &nb, &tl));
    }
}

/// Raw literals `lits`, then `seqs` as the sequences section.
fn withSeqs(gpa_: std.mem.Allocator, lits: []const u8, seqs: []const u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(gpa_);
    try b.appendSlice(gpa_, &hdr24(lits.len));
    try b.appendSlice(gpa_, lits);
    try b.appendSlice(gpa_, seqs);
    return b.toOwnedSlice(gpa_);
}

/// A sequences section of `n` sequences, each one literal and a 3-byte match
/// at offset 1 (every table an RLE one: no bits per sequence), `nb` being the
/// sequence count as the format codes it.
fn rleSeqSection(gpa_: std.mem.Allocator, nb: []const u8, ll: u8, of: u8, ml: u8, modes: u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(gpa_);
    try b.appendSlice(gpa_, nb);
    try b.appendSlice(gpa_, &.{ modes, ll, of, ml, 0x01 });
    return b.toOwnedSlice(gpa_);
}

test "sequence counts in every coding form, and a section cut anywhere in its header" {
    const Case = struct { n: usize, nb: []const u8 };
    const cases = [_]Case{
        .{ .n = 1, .nb = &.{0x01} },
        .{ .n = 127, .nb = &.{0x7f} },
        .{ .n = 128, .nb = &.{ 0x80, 0x80 } },
        .{ .n = 255, .nb = &.{ 0x80, 0xff } },
        .{ .n = 256, .nb = &.{ 0x81, 0x00 } },
        .{ .n = 0x7eff, .nb = &.{ 0xfe, 0xff } },
        .{ .n = 0x7f00, .nb = &.{ 0xff, 0x00, 0x00 } },
    };
    const out = try gpa.alloc(u8, 140000);
    defer gpa.free(out);
    const lits = try gpa.alloc(u8, 0x7f00 + 8);
    defer gpa.free(lits);
    pattern(lits);
    for (cases) |c| {
        const sec = try rleSeqSection(gpa, c.nb, 1, 0, 0, 0x54);
        defer gpa.free(sec);
        const blk = try withSeqs(gpa, lits[0 .. c.n + 5], sec); // 5 literals trail the last sequence
        defer gpa.free(blk);
        const n = try decode1(0x38, blk, out);
        try std.testing.expectEqual(c.n * 4 + 5, n);
        for (0..c.n) |i| {
            try std.testing.expectEqualSlices(u8, &@as([4]u8, @splat(lits[i])), out[i * 4 ..][0..4]);
        }
        try std.testing.expectEqualSlices(u8, lits[c.n..][0..5], out[c.n * 4 ..][0..5]);
    }
    const l8 = lits[0..8];
    // the header cut short: SrcSizeWrong where libzstd says so
    for ([_][]const u8{ &.{}, &.{0xff}, &.{ 0xff, 0x00 }, &.{0x80}, &.{0x01}, &.{ 0xff, 0x00, 0x00 } }) |sec| {
        const blk = try withSeqs(gpa, l8, sec);
        defer gpa.free(blk);
        try std.testing.expectError(error.SrcSizeWrong, decode1(0x38, blk, out));
    }
    // one sequence, default tables, and no bitstream at all
    {
        const blk = try withSeqs(gpa, l8, &.{ 0x01, 0x00 });
        defer gpa.free(blk);
        try std.testing.expectError(error.CorruptionDetected, decode1(0x38, blk, out));
    }
    // reserved bits of the modes byte; an RLE table without its symbol; a symbol past the alphabet
    {
        const sec = try rleSeqSection(gpa, &.{0x01}, 1, 0, 0, 0x55);
        defer gpa.free(sec);
        const blk = try withSeqs(gpa, l8, sec);
        defer gpa.free(blk);
        try std.testing.expectError(error.CorruptionDetected, decode1(0x38, blk, out));
        const blk2 = try withSeqs(gpa, l8, &.{ 0x01, 0x54 });
        defer gpa.free(blk2);
        try std.testing.expectError(error.CorruptionDetected, decode1(0x38, blk2, out));
        for ([_][3]u8{ .{ 36, 0, 0 }, .{ 1, 32, 0 }, .{ 1, 0, 53 } }) |sym| {
            const s3 = try rleSeqSection(gpa, &.{0x01}, sym[0], sym[1], sym[2], 0x54);
            defer gpa.free(s3);
            const b3 = try withSeqs(gpa, l8, s3);
            defer gpa.free(b3);
            try std.testing.expectError(error.CorruptionDetected, decode1(0x38, b3, out));
        }
    }
    // the repeat mode with no table before it
    {
        const blk = try withSeqs(gpa, l8, &.{ 0x01, 0xfc, 0x01 });
        defer gpa.free(blk);
        try std.testing.expectError(error.CorruptionDetected, decode1(0x38, blk, out));
    }
}

const fse = @import("fse.zig");
const dbits = @import("dbits.zig");

/// An FSE-coded weight stream (header ++ data) of `n` random weights over
/// the distribution `norm` (symbols 0..max_symbol), as `writeNCount` and
/// `compressUsingCTable` make it. Returns the stream length.
fn weightStream(rnd: std.Random, out: []u8, weights: []u8, norm: []const i16, max_symbol: u32, tl: u32) !usize {
    var live: [16]u8 = undefined;
    var nl: usize = 0;
    for (norm[0 .. max_symbol + 1], 0..) |c, s| {
        if (c != 0) {
            live[nl] = @intCast(s);
            nl += 1;
        }
    }
    for (weights) |*w| w.* = live[rnd.uintLessThan(usize, nl)];
    const hl = try fse.writeNCount(out, norm, max_symbol, tl);
    var ct: fse.CTable = undefined;
    try ct.build(norm, max_symbol, tl);
    const n = fse.compressUsingCTable(out[hl..], weights, &ct);
    try std.testing.expect(n != 0);
    return hl + n;
}

test "decompressWeights: low-probability symbols, the destination edge, a table log of 7, a stream too short for its states" {
    var prng = std.Random.DefaultPrng.init(0x9e11);
    const rnd = prng.random();
    var trial: usize = 0;
    while (trial < 600) : (trial += 1) {
        const tl: u32 = 5 + rnd.uintLessThan(u32, 3);
        const total: i32 = @as(i32, 1) << @intCast(tl);
        var norm: [16]i16 = @splat(0);
        var remaining = total;
        var n: u32 = 0;
        const low = rnd.boolean();
        while (remaining > 0 and n < 12) {
            var v: i32 = if (low and rnd.uintLessThan(u32, 3) == 0) -1 else 1 + @as(i32, @intCast(rnd.uintLessThan(u32, @intCast(@min(remaining, 14)))));
            if (n >= 11 or v > remaining) v = remaining;
            if (v == total) v -= 1;
            norm[n] = @intCast(v);
            remaining -= if (v < 0) -v else v;
            n += 1;
        }
        if (remaining != 0) continue;
        var weights: [180]u8 = undefined;
        const nw = 3 + rnd.uintLessThan(usize, 170);
        var stream: [400]u8 = undefined;
        const len = weightStream(rnd, &stream, weights[0..nw], &norm, n - 1, tl) catch continue;
        var got: [256]u8 = undefined;
        if (tl > 6) {
            try std.testing.expectError(error.TableLogTooLarge, dbits.decompressWeights(got[0..], stream[0..len], 6));
            try std.testing.expectError(error.TableLogTooLarge, dbits.decompressWeights(got[0..], stream[0..len], 7)); // the weight table holds 2^6 cells
            continue;
        }
        try std.testing.expectEqual(nw, try dbits.decompressWeights(got[0..], stream[0..len], 6));
        try std.testing.expectEqualSlices(u8, weights[0..nw], got[0..nw]);
        try std.testing.expectEqual(nw, try dbits.decompressWeights(got[0..], stream[0..len], tl));
        // the destination: exactly the symbols is enough, one less is not
        try std.testing.expectEqual(nw, try dbits.decompressWeights(got[0..nw], stream[0..len], 6));
        try std.testing.expectError(error.DstSizeTooSmall, dbits.decompressWeights(got[0 .. nw - 1], stream[0..len], 6));
        // a table log above the limit
        try std.testing.expectError(error.TableLogTooLarge, dbits.decompressWeights(got[0..], stream[0..len], tl - 1));
        // a stream with only an end mark behind the table
        const hl = try fse.writeNCount(&stream, &norm, n - 1, tl);
        stream[hl] = 0x01;
        try std.testing.expectError(error.CorruptionDetected, dbits.decompressWeights(got[0..], stream[0 .. hl + 1], 6));
    }
}

const dec = @import("decompress.zig");

const HeaderModel = union(enum) { header: dec.FrameHeader, need: usize, err: anyerror };

/// RFC 8878 section 3.1.1 (frame header), written from the format
/// description and not from `decompress.zig`.
fn modelHeader(src: []const u8) HeaderModel {
    const zmagic = [4]u8{ 0x28, 0xb5, 0x2f, 0xfd };
    if (src.len < 5) {
        if (src.len > 0) {
            var is_z = true;
            var is_s = true;
            const smagic = [4]u8{ 0x50, 0x2a, 0x4d, 0x18 };
            for (src, 0..) |byte, i| {
                if (byte != zmagic[i]) is_z = false;
                const masked = if (i == 0) byte & 0xf0 else byte;
                if (masked != smagic[i]) is_s = false;
            }
            if (!is_z and !is_s) return .{ .err = error.PrefixUnknown };
        }
        return .{ .need = 5 };
    }
    if (src[0] & 0xf0 == 0x50 and src[1] == 0x2a and src[2] == 0x4d and src[3] == 0x18) {
        if (src.len < 8) return .{ .need = 8 };
        return .{ .header = .{
            .content_size = std.mem.readInt(u32, src[4..8], .little),
            .window_size = 0,
            .block_size_max = 0,
            .frame_type = .skippable,
            .header_size = 8,
            .dict_id = src[0] & 0x0f,
            .checksum = false,
        } };
    }
    if (!std.mem.eql(u8, src[0..4], &zmagic)) return .{ .err = error.PrefixUnknown };
    const fhd = src[4];
    const single = fhd & 0x20 != 0;
    const did_sizes = [4]usize{ 0, 1, 2, 4 };
    const did_bytes = did_sizes[fhd & 3];
    const fcs_bytes: usize = switch (fhd >> 6) {
        0 => if (single) 1 else 0,
        1 => 2,
        2 => 4,
        else => 8,
    };
    const size = 5 + @as(usize, if (single) 0 else 1) + did_bytes + fcs_bytes;
    if (src.len < size) return .{ .need = size };
    if (fhd & 0x08 != 0) return .{ .err = error.FrameParameterUnsupported };
    var pos: usize = 5;
    var window: u64 = 0;
    if (!single) {
        const wd = src[pos];
        pos += 1;
        const exponent: u6 = @intCast(wd >> 3);
        if (exponent + 10 > 31) return .{ .err = error.FrameParameterWindowTooLarge };
        const base = @as(u64, 1) << (10 + exponent);
        window = base + base / 8 * (wd & 7);
    }
    var did: u32 = 0;
    for (0..did_bytes) |i| did |= @as(u32, src[pos + i]) << @intCast(8 * i);
    pos += did_bytes;
    var fcs: ?u64 = null;
    if (fcs_bytes != 0) {
        var v: u64 = 0;
        for (0..fcs_bytes) |i| v |= @as(u64, src[pos + i]) << @intCast(8 * i);
        if (fcs_bytes == 2) v += 256;
        fcs = v;
    }
    if (single) window = fcs.?;
    return .{ .header = .{
        .content_size = fcs,
        .window_size = window,
        .block_size_max = @intCast(@min(window, 128 * 1024)),
        .frame_type = .frame,
        .header_size = @intCast(size),
        .dict_id = did,
        .checksum = fhd & 4 != 0,
    } };
}

test "frame headers: the parser against a model of the format, every descriptor, every cut" {
    var prng = std.Random.DefaultPrng.init(0x4ead);
    const rnd = prng.random();
    var buf: [24]u8 = undefined;
    var trial: usize = 0;
    while (trial < 60000) : (trial += 1) {
        rnd.bytes(&buf);
        switch (rnd.uintLessThan(u32, 8)) {
            0, 1, 2, 3, 4 => @memcpy(buf[0..4], &magic),
            5 => {
                buf[0] = 0x50 | (buf[0] & 0x0f);
                buf[1] = 0x2a;
                buf[2] = 0x4d;
                buf[3] = 0x18;
            },
            6 => {
                // a near miss: one byte of a real magic wrong
                @memcpy(buf[0..4], &magic);
                buf[rnd.uintLessThan(usize, 4)] ^= @as(u8, 1) << @intCast(rnd.uintLessThan(u32, 8));
            },
            else => {},
        }
        if (rnd.boolean()) buf[4] &= 0xf7; // mostly without the reserved bit
        const len = rnd.uintLessThan(usize, 24);
        const src = buf[0..len];
        const want = modelHeader(src);
        const got: HeaderModel = if (dec.getFrameHeader(src)) |r| switch (r) {
            .header => |h| .{ .header = h },
            .need => |n| .{ .need = n },
        } else |e| .{ .err = e };
        switch (want) {
            .err => |e| try std.testing.expectEqual(e, got.err),
            else => try std.testing.expectEqualDeep(want, got),
        }
        // the same bytes as a frame without its magic number
        {
            var with: [28]u8 = undefined;
            @memcpy(with[0..4], &magic);
            @memcpy(with[4..][0..len], src);
            const w2 = modelHeader(with[0 .. 4 + len]);
            const g2: HeaderModel = if (dec.getFrameHeaderAdvanced(src, .magicless)) |r| switch (r) {
                .header => |h| .{ .header = h },
                .need => |n| .{ .need = n },
            } else |e| .{ .err = e };
            switch (w2) {
                .err => |e| try std.testing.expectEqual(e, g2.err),
                .need => |n| try std.testing.expectEqual(n - 4, g2.need),
                .header => |h| {
                    var h2 = h;
                    h2.header_size -= 4;
                    try std.testing.expectEqualDeep(h2, g2.header);
                },
            }
        }
        // the size query alone agrees on frames (not on skippable magics)
        if (len >= 5 and std.mem.eql(u8, src[0..4], &magic)) {
            const fs = try dec.frameHeaderSize(src);
            switch (want) {
                .header => |h| try std.testing.expectEqual(@as(usize, h.header_size), fs),
                .need => |n| try std.testing.expectEqual(n, fs),
                .err => {},
            }
        }
    }
}

fn mustFail(r: anytype) !void {
    if (r) |_| return error.TestUnexpectedResult else |_| {}
}

test "Huffman decoding: round trips with both table kinds, one and four streams, assembly on and off, and the edges of the streams" {
    defer huf_dec.setAsmForTest(true);
    const sizes = [_]usize{ 1, 2, 3, 5, 6, 7, 8, 9, 12, 17, 31, 32, 33, 40, 64, 100, 150, 200, 220, 255, 256, 257, 1000, 4096, 5000, 40000 };
    var src: [40000]u8 = undefined;
    var comp: [41000]u8 = undefined;
    var out: [40002]u8 = undefined;
    var dt: huf_dec.DTable = .{};
    var done: usize = 0;
    for ([_]bool{ false, true }) |asm_on| {
        huf_dec.setAsmForTest(asm_on);
        for (sizes, 0..) |n, si| {
            for ([_]u32{ 9, 11, 10, 12 }) |log| {
                for ([_]huf.Streams{ .single, .four }) |streams| {
                    skewed(src[0..n], si * 31 + log);
                    // log 10 and 12: two symbols only (one bit each: four streams shorter than the fast loop's 8 bytes)
                    if (log >= 10) for (src[0..n], 0..) |*b, i| {
                        b.* = @intCast((i * 2654435761 >> 9) & 1);
                    };
                    var old: huf.CTable = .{};
                    var rep: huf.Repeat = .none;
                    const c = huf.compress(&comp, src[0..n], log, streams, &old, &rep, .{}) catch continue;
                    if (c <= 1) continue; // 1: a single repeated symbol, no table
                    const sec = comp[0..c];
                    done += 1;
                    // a table of each kind, then the streams with it
                    for ([_]bool{ false, true }) |x2| {
                        const h = if (x2) try huf_dec.readDTableX2(&dt, sec) else try huf_dec.readDTableX1(&dt, sec);
                        const body = sec[h..];
                        if (streams == .single) {
                            try huf_dec.decompress1XUsing(&dt, out[0..n], body);
                            try std.testing.expectEqualSlices(u8, src[0..n], out[0..n]);
                            if (!x2) {
                                try mustFail(huf_dec.decompress1XUsing(&dt, out[0 .. n + 1], body));
                                if (n > 1) try mustFail(huf_dec.decompress1XUsing(&dt, out[0 .. n - 1], body));
                            }
                        } else if (n >= 6) {
                            try huf_dec.decompress4XUsing(&dt, out[0..n], body);
                            try std.testing.expectEqualSlices(u8, src[0..n], out[0..n]);
                            // another segment size: refused, or a different output
                            for ([_]usize{ n - 1, n + 1 }) |m| {
                                if (m < 6) continue;
                                if (huf_dec.decompress4XUsing(&dt, out[0..m], body)) |_| {
                                    try std.testing.expect(!std.mem.eql(u8, out[0..m], src[0..@min(m, n)]) or m != n);
                                } else |_| {}
                            }
                            // refusals before any decoding
                            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(&dt, out[0..n], body[0..@min(body.len, 9)]));
                            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(&dt, out[0..5], body));
                            var bad: [64]u8 = undefined;
                            const m = @min(body.len, 64);
                            @memcpy(bad[0..m], body[0..m]);
                            if (m >= 10) {
                                std.mem.writeInt(u16, bad[0..2], 0xffff, .little);
                                try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(&dt, out[0..n], bad[0..m]));
                            }
                        }
                    }
                    // the table and the streams in one call
                    if (streams == .single) {
                        try huf_dec.decompress1X1Table(&dt, out[0..n], sec);
                    } else if (n >= 6) {
                        try huf_dec.decompress4XTable(&dt, out[0..n], sec);
                    } else continue;
                    try std.testing.expectEqualSlices(u8, src[0..n], out[0..n]);
                    // a section that is only a table has no streams
                    const h1 = try huf_dec.readDTableX1(&dt, sec);
                    try std.testing.expectError(error.SrcSizeWrong, if (streams == .single) huf_dec.decompress1X1Table(&dt, out[0..n], sec[0..h1]) else huf_dec.decompress4XTable(&dt, out[0..n], sec[0..h1]));
                }
            }
        }
    }
    try std.testing.expect(done > 40);
    try std.testing.expectError(error.DstSizeTooSmall, huf_dec.decompress4XTable(&dt, out[0..0], comp[0..20]));
    try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XTable(&dt, out[0..20], comp[0..0]));
}

const ddict = @import("ddict.zig");
const dict_kats = @import("testdata/dict_kats.zig");

test "a zstd dictionary cut at every length: its entropy tables, repeat offsets and the content they refer to" {
    for ([_][]const u8{ dict_kats.full_dict, dict_kats.full_dict2 }) |dict| {
        var ent: ddict.Entropy = .{};
        const e = try ddict.loadDEntropy(&ent, dict);
        try std.testing.expectEqual([3]u32{ 1, 4, 8 }, ent.rep);
        try std.testing.expect(e + 8 <= dict.len);
        for (0..dict.len + 1) |len| {
            var t: ddict.Entropy = .{};
            if (len >= e + 8) {
                // the largest repeat offset (8) must lie inside the content that follows
                try std.testing.expectEqual(e, try ddict.loadDEntropy(&t, dict[0..len]));
            } else {
                try std.testing.expectError(error.DictionaryCorrupted, ddict.loadDEntropy(&t, dict[0..len]));
            }
        }
        // the magic and the id alone: a zstd dictionary without tables is corrupt, not raw content
        try std.testing.expectError(error.DictionaryCorrupted, ddict.DDict.init(gpa, dict[0..8], .auto));
        try std.testing.expectError(error.DictionaryCorrupted, ddict.DDict.init(gpa, dict[0..8], .full));
        var d7 = try ddict.DDict.init(gpa, dict[0..7], .auto); // too short to be anything else
        defer d7.deinit(gpa);
        try std.testing.expectEqual(@as(u32, 0), d7.dictId());
        try std.testing.expectError(error.DictionaryCorrupted, ddict.DDict.init(gpa, dict[0..7], .full));
        try std.testing.expectEqual(@as(u32, 0), ddict.getDictId(dict[0..7]));
        try std.testing.expect(ddict.getDictId(dict[0..8]) != 0);
    }
}

const seekable = @import("seekable.zig");

test "seek table queries: the last frame answers, one past it is refused" {
    var entries = [_]seekable.SeekEntry{
        .{ .c_offset = 0, .d_offset = 0, .checksum = 0 },
        .{ .c_offset = 10, .d_offset = 100, .checksum = 1 },
        .{ .c_offset = 25, .d_offset = 130, .checksum = 2 },
    };
    const t: seekable.SeekTable = .{ .entries = &entries, .checksum_flag = true };
    try std.testing.expectEqual(@as(u32, 2), t.numFrames());
    try std.testing.expectEqual(@as(u64, 10), try t.frameCompressedOffset(1));
    try std.testing.expectEqual(@as(u64, 100), try t.frameDecompressedOffset(1));
    try std.testing.expectEqual(@as(u64, 15), try t.frameCompressedSize(1));
    try std.testing.expectEqual(@as(u64, 30), try t.frameDecompressedSize(1));
    try std.testing.expectEqual(@as(u64, 10), try t.frameCompressedSize(0));
    try std.testing.expectEqual(@as(u64, 100), try t.frameDecompressedSize(0));
    try std.testing.expectError(error.FrameIndexTooLarge, t.frameCompressedOffset(2));
    try std.testing.expectError(error.FrameIndexTooLarge, t.frameDecompressedOffset(2));
    try std.testing.expectError(error.FrameIndexTooLarge, t.frameCompressedSize(2));
    try std.testing.expectError(error.FrameIndexTooLarge, t.frameDecompressedSize(2));
    try std.testing.expectError(error.FrameIndexTooLarge, t.frameCompressedSize(3));
}

const raw_frame = magic ++ [_]u8{ 0x20, 0x05, 0x29, 0x00, 0x00 } ++ "hello".*; // 14 bytes, content "hello"
const rle_frame = magic ++ [_]u8{ 0x20, 0x40, 0x03, 0x02, 0x00, 'z' }; // 64 x 'z'
const skip2 = [_]u8{ 0x5e, 0x2a, 0x4d, 0x18, 0x02, 0x00, 0x00, 0x00, 'h', 'i' }; // variant 14, "hi"
const sums_frame = magic ++ [_]u8{ 0x24, 0x05, 0x29, 0x00, 0x00 } ++ "hello".* ++ [_]u8{ 1, 2, 3, 4 }; // checksum flag, 18 bytes
const zero_seq_frame = magic ++ [_]u8{ 0x00, 0x00, 0x2d, 0x00, 0x00, 0x18, 'a', 'b', 'c', 0x00 }; // window 1 KiB, no content size

test "frame utilities at the edges of their inputs" {
    // isFrame / isSkippableFrame: four bytes are enough, three are not
    try std.testing.expect(dec.isFrame(&magic));
    try std.testing.expect(!dec.isFrame(magic[0..3]));
    try std.testing.expect(dec.isFrame(skip2[0..4]));
    try std.testing.expect(!dec.isFrame(skip2[0..3]));
    try std.testing.expect(dec.isSkippableFrame(skip2[0..4]));
    try std.testing.expect(!dec.isSkippableFrame(skip2[0..3]));
    try std.testing.expect(!dec.isSkippableFrame(&magic));
    // the size of the header from its first five bytes
    try std.testing.expectError(error.SrcSizeWrong, dec.frameHeaderSize(raw_frame[0..4]));
    try std.testing.expectEqual(@as(usize, 6), try dec.frameHeaderSize(raw_frame[0..5]));
    // readSkippableFrame
    var dst: [8]u8 = undefined;
    const r = try dec.readSkippableFrame(&dst, &skip2);
    try std.testing.expectEqual(@as(usize, 2), r.len);
    try std.testing.expectEqual(@as(u32, 14), r.magic_variant);
    try std.testing.expectEqualStrings("hi", dst[0..2]);
    try std.testing.expectError(error.SrcSizeWrong, dec.readSkippableFrame(&dst, skip2[0..7]));
    try std.testing.expectError(error.SrcSizeWrong, dec.readSkippableFrame(&dst, skip2[0..9])); // one byte of the data missing
    try std.testing.expectError(error.DstSizeTooSmall, dec.readSkippableFrame(dst[0..1], &skip2));
    try std.testing.expectEqual(@as(usize, 2), (try dec.readSkippableFrame(dst[0..2], &skip2)).len);
    var big = skip2;
    std.mem.writeInt(u32, big[4..8], 0xffff_fff8, .little); // size + 8 wraps to 0
    try std.testing.expectError(error.FrameParameterUnsupported, dec.readSkippableFrame(&dst, &big));
    std.mem.writeInt(u32, big[4..8], 0xffff_fff7, .little); // size + 8 is the largest u32: more than there is
    try std.testing.expectError(error.SrcSizeWrong, dec.readSkippableFrame(&dst, &big));
    var notskip = raw_frame;
    std.mem.writeInt(u32, notskip[4..8], 0, .little);
    try std.testing.expectError(error.FrameParameterUnsupported, dec.readSkippableFrame(&dst, &notskip));
    // findFrameCompressedSize
    var empty_skip = skip2[0..8].*;
    std.mem.writeInt(u32, empty_skip[4..8], 0, .little);
    try std.testing.expectEqual(@as(usize, 8), try dec.findFrameCompressedSize(&empty_skip));
    try std.testing.expectError(error.SrcSizeWrong, dec.findFrameCompressedSize(empty_skip[0..7]));
    try std.testing.expectEqual(@as(usize, 10), try dec.findFrameCompressedSize(&skip2));
    try std.testing.expectEqual(@as(usize, 14), try dec.findFrameCompressedSize(&raw_frame));
    try std.testing.expectEqual(@as(usize, 14), try dec.findFrameCompressedSize(&(raw_frame ++ rle_frame)));
    try std.testing.expectError(error.SrcSizeWrong, dec.findFrameCompressedSize(raw_frame[0..13]));
    try std.testing.expectEqual(@as(usize, 18), try dec.findFrameCompressedSize(&sums_frame));
    try std.testing.expectError(error.SrcSizeWrong, dec.findFrameCompressedSize(sums_frame[0..17]));
    var reserved = raw_frame;
    reserved[6] = 0x2f; // the block header: last, type 3 (reserved)
    try std.testing.expectError(error.CorruptionDetected, dec.findFrameCompressedSize(&reserved));
    // sizes of whole inputs
    const all = skip2 ++ raw_frame ++ rle_frame;
    try std.testing.expectEqual(@as(?u64, 69), try dec.findDecompressedSize(&all));
    try std.testing.expectEqual(@as(?u64, 0), try dec.findDecompressedSize(&.{}));
    try std.testing.expectError(error.SrcSizeWrong, dec.findDecompressedSize((raw_frame ++ [_]u8{ 1, 2, 3 })[0..]));
    try std.testing.expectEqual(@as(?u64, null), try dec.findDecompressedSize(&zero_seq_frame));
    try std.testing.expectEqual(@as(u64, 69), try dec.decompressBound(&all));
    try std.testing.expectEqual(@as(u64, 1024), try dec.decompressBound(&zero_seq_frame)); // one block of the window's size
    try std.testing.expectEqual(@as(u64, 0), try dec.decompressBound(skip2[0..]));
    // the in-place margin: header + checksum + 3 per block, the largest block, skippable frames whole
    try std.testing.expectEqual(@as(usize, 14), try dec.decompressionMargin(&raw_frame));
    try std.testing.expectEqual(@as(usize, 18), try dec.decompressionMargin(&sums_frame));
    try std.testing.expectEqual(@as(usize, 24), try dec.decompressionMargin(&(skip2 ++ raw_frame)));
    try std.testing.expectEqual(@as(usize, 10), try dec.decompressionMargin(&skip2));
    // two frames: both headers and blocks, the larger block size once (rle: window 64)
    try std.testing.expectEqual(@as(usize, (6 + 3) + (6 + 3) + 64), try dec.decompressionMargin(&(raw_frame ++ rle_frame)));
}

test "a new frame starts with no table of the last one: treeless literals and repeat modes are refused" {
    var out: [4096]u8 = undefined;
    var src1: [300]u8 = undefined;
    skewed(&src1, 3);
    var sec1: [400]u8 = undefined;
    const prev: literals.HufState = .{};
    var next1: literals.HufState = .{};
    const len1 = try compressedLiterals(9, &sec1, &src1, &prev, &next1);
    try std.testing.expectEqual(@as(u8, 2), sec1[0] & 3);
    sec1[len1] = 0;
    // frame B: the table-reusing form of that section, which only a block that follows one may use
    var sec2: [400]u8 = undefined;
    var p2 = next1;
    p2.repeat = .valid;
    var next2: literals.HufState = .{};
    const len2 = try compressedLiterals(1, &sec2, src1[0..100], &p2, &next2);
    try std.testing.expectEqual(@as(u8, 3), sec2[0] & 3);
    sec2[len2] = 0;
    const fa = try frameOf(0, &.{sec1[0 .. len1 + 1]});
    defer gpa.free(fa);
    const fb = try frameOf(0, &.{sec2[0 .. len2 + 1]});
    defer gpa.free(fb);
    // alone, B is refused; after A in the same context it is refused too
    try std.testing.expectError(error.DictionaryCorrupted, zstd.decompress(gpa, &out, fb));
    const both = try std.mem.concat(gpa, u8, &.{ fa, fb });
    defer gpa.free(both);
    try std.testing.expectError(error.DictionaryCorrupted, zstd.decompress(gpa, &out, both));
    // sequence tables: A uses RLE tables, B asks to repeat them
    const lits = "abcdefgh";
    const sa = try rleSeqSection(gpa, &.{0x01}, 1, 0, 0, 0x54);
    defer gpa.free(sa);
    const ba = try withSeqs(gpa, lits, sa);
    defer gpa.free(ba);
    const bb = try withSeqs(gpa, lits, &.{ 0x01, 0xfc, 0x01 });
    defer gpa.free(bb);
    const fsa = try frameOf(0, &.{ba});
    defer gpa.free(fsa);
    const fsb = try frameOf(0, &.{bb});
    defer gpa.free(fsb);
    const two = try std.mem.concat(gpa, u8, &.{ fsa, fsb });
    defer gpa.free(two);
    try std.testing.expectEqual(@as(usize, 11), try zstd.decompress(gpa, &out, fsa));
    try std.testing.expectError(error.CorruptionDetected, zstd.decompress(gpa, &out, two));
}

test "writeSkippableFrame: the exact room, the largest variant, one past each limit" {
    var dst: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 11), try zstd.writeSkippableFrame(&dst, "abc", 15)); // 3 + 8: no byte to spare
    try std.testing.expectEqualSlices(u8, &.{ 0x5f, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 'a', 'b', 'c' }, dst[0..11]);
    try std.testing.expectError(error.NoSpaceLeft, zstd.writeSkippableFrame(dst[0..10], "abc", 15));
    try std.testing.expectError(error.ParameterOutOfBound, zstd.writeSkippableFrame(&dst, "abc", 16));
    try std.testing.expectEqual(@as(usize, 8), try zstd.writeSkippableFrame(&dst, "", 0));
    // a source of 4 GiB: refused before any byte is read or written (the slices are never dereferenced).
    // Only where `usize` can hold it: on a 32-bit target such a slice cannot exist.
    if (comptime @bitSizeOf(usize) > 32) {
        const p: [*]u8 = @ptrFromInt(4096);
        const n: usize = @as(usize, std.math.maxInt(u32)) + 1;
        try std.testing.expectError(error.SrcSizeWrong, zstd.writeSkippableFrame(p[0 .. n + 8], p[0..n], 0));
    }
}
