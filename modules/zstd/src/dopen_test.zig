// SPDX-License-Identifier: MIT
//! Decoder tests for the mutants wave 6 left open (2026-11-18, second pass):
//! the piecewise decoder's state machine, `begin`, the history cursors, raw
//! dictionaries, the streaming decoder's buffers and resets, the Huffman
//! tables (every table log, the X2 cell layout) and the four-stream fast
//! path on hand-built one-bit streams, the seek table and `Seekable`'s
//! guards. The expectations follow RFC 8878 and libzstd's
//! `ZSTD_decompressContinue` / `ZSTD_decompressStream` / `HUF_*` (which the
//! decoder ports); nothing here observes more than a public field or a
//! return value.

const std = @import("std");
const zstd = @import("root.zig");
const dec = @import("decompress.zig");
const dblock = @import("dblock.zig");
const ddict_mod = @import("ddict.zig");
const dstream = @import("dstream.zig");
const huf = @import("huf.zig");
const huf_dec = @import("huf_dec.zig");
const seekable = @import("seekable.zig");
const kats = @import("testdata/dict_kats.zig");

const gpa = std.testing.allocator;
const magic = [4]u8{ 0x28, 0xb5, 0x2f, 0xfd };

const raw5 = magic ++ [_]u8{ 0x20, 0x05, 0x29, 0x00, 0x00 } ++ "hello".*; // content "hello"
const rle64 = magic ++ [_]u8{ 0x20, 0x40, 0x03, 0x02, 0x00, 'z' }; // 64 x 'z'
const zero_seq = magic ++ [_]u8{ 0x00, 0x00, 0x2d, 0x00, 0x00, 0x18, 'a', 'b', 'c', 0x00 }; // compressed block, "abc"

// ------------------------------------------------------------ the piecewise decoder

const Step = struct { n: usize, stage: dec.Stage, expected: usize, wrote: usize = 0 };

/// Feeds `frame` to `d` in the pieces of `steps` and checks the stage and the
/// size asked for next after each (`ZSTD_nextSrcSizeToDecompress`).
fn runSteps(d: *dec.Decompressor, frame: []const u8, steps: []const Step) !void {
    var out: [64]u8 = undefined;
    var ip: usize = 0;
    var op: usize = 0;
    d.begin();
    for (steps) |s| {
        const wrote = try d.decompressContinue(out[op..], frame[ip..][0..s.n]);
        ip += s.n;
        op += wrote;
        try std.testing.expectEqual(s.wrote, wrote);
        try std.testing.expectEqual(s.stage, d.stage);
        try std.testing.expectEqual(s.expected, d.nextSrcSizeToDecompress());
    }
    try std.testing.expectEqual(frame.len, ip);
}

test "decompressContinue: the stage and the next size after every piece of a frame" {
    var d = try dec.Decompressor.init(gpa, .{});
    defer d.deinit();
    // a frame with a checksum: an empty block, a 2-byte block, an empty last block, the checksum
    const sum: u32 = @truncate(std.hash.XxHash64.hash(0, "ab"));
    var f1: [4 + 2 + 3 + 3 + 2 + 3 + 4]u8 = undefined;
    @memcpy(f1[0..6], &(magic ++ [_]u8{ 0x04, 0x00 }));
    @memcpy(f1[6..9], &[_]u8{ 0x00, 0x00, 0x00 }); // raw, not last, empty
    @memcpy(f1[9..12], &[_]u8{ 0x10, 0x00, 0x00 }); // raw, not last, 2 bytes
    @memcpy(f1[12..14], "ab");
    @memcpy(f1[14..17], &[_]u8{ 0x01, 0x00, 0x00 }); // raw, last, empty
    std.mem.writeInt(u32, f1[17..21], sum, .little);
    try runSteps(&d, &f1, &.{
        .{ .n = 5, .stage = .decode_frame_header, .expected = 1 },
        .{ .n = 1, .stage = .decode_block_header, .expected = 3 },
        .{ .n = 3, .stage = .decode_block_header, .expected = 3 },
        .{ .n = 3, .stage = .decompress_block, .expected = 2 },
        .{ .n = 2, .stage = .decode_block_header, .expected = 3, .wrote = 2 },
        .{ .n = 3, .stage = .check_checksum, .expected = 4 },
        .{ .n = 4, .stage = .get_frame_header_size, .expected = 0 },
    });
    // the same without the checksum: the empty last block ends the frame
    const f2 = magic ++ [_]u8{ 0x00, 0x00, 0x01, 0x00, 0x00 };
    try runSteps(&d, &f2, &.{
        .{ .n = 5, .stage = .decode_frame_header, .expected = 1 },
        .{ .n = 1, .stage = .decode_block_header, .expected = 3 },
        .{ .n = 3, .stage = .get_frame_header_size, .expected = 0 },
    });
    // a skippable frame: its header, its size, its content
    const f3 = [_]u8{ 0x5e, 0x2a, 0x4d, 0x18, 0x02, 0x00, 0x00, 0x00, 'h', 'i' };
    try runSteps(&d, &f3, &.{
        .{ .n = 5, .stage = .decode_skippable_header, .expected = 3 },
        .{ .n = 3, .stage = .skip_frame, .expected = 2 },
        .{ .n = 2, .stage = .get_frame_header_size, .expected = 0 },
    });
    // an empty one: nothing to skip, the last call has no bytes
    const f4 = [_]u8{ 0x50, 0x2a, 0x4d, 0x18, 0x00, 0x00, 0x00, 0x00 };
    try runSteps(&d, &f4, &.{
        .{ .n = 5, .stage = .decode_skippable_header, .expected = 3 },
        .{ .n = 3, .stage = .skip_frame, .expected = 0 },
        .{ .n = 0, .stage = .get_frame_header_size, .expected = 0 },
    });
}

test "decompressContinue: a piece of the wrong size, a destination too small" {
    var d = try dec.Decompressor.init(gpa, .{});
    defer d.deinit();
    var out: [16]u8 = undefined;
    d.begin();
    try std.testing.expectError(error.SrcSizeWrong, d.decompressContinue(&out, raw5[0..4]));
    // at a block header (3 bytes asked): two and four are refused
    _ = try d.decompressContinue(&out, raw5[0..5]);
    try std.testing.expectEqual(dec.Stage.decode_frame_header, d.stage);
    d.begin();
    const f = magic ++ [_]u8{ 0x00, 0x00 };
    _ = try d.decompressContinue(&out, f[0..5]);
    _ = try d.decompressContinue(&out, f[5..6]);
    try std.testing.expectEqual(dec.Stage.decode_block_header, d.stage);
    try std.testing.expectError(error.SrcSizeWrong, d.decompressContinue(&out, &.{ 1, 0 }));
    try std.testing.expectError(error.SrcSizeWrong, d.decompressContinue(&out, &.{ 1, 0, 0, 0 }));
    // a raw block of five bytes into a destination of two
    const raw_last = [_]u8{ 0x29, 0x00, 0x00 };
    _ = try d.decompressContinue(&out, &raw_last);
    try std.testing.expectEqual(dec.Stage.decompress_last_block, d.stage);
    try std.testing.expectError(error.DstSizeTooSmall, d.decompressContinue(out[0..2], "abcde"));
    // an RLE block of ten bytes into a destination of four
    d.begin();
    _ = try d.decompressContinue(&out, f[0..5]);
    _ = try d.decompressContinue(&out, f[5..6]);
    _ = try d.decompressContinue(&out, &[_]u8{ 0x53, 0x00, 0x00 }); // last, RLE, 10 bytes
    try std.testing.expectEqual(dec.Stage.decompress_last_block, d.stage);
    try std.testing.expectError(error.DstSizeTooSmall, d.decompressContinue(out[0..4], "z"));
}

test "begin puts every cursor of the context back" {
    var d = try dec.Decompressor.init(gpa, .{});
    defer d.deinit();
    var out: [32]u8 = undefined;
    d.begin();
    _ = try d.decompressContinue(&out, zero_seq[0..5]);
    d.dict_id = 5;
    d.prefix_addr = 123;
    d.prev_end_addr = 456;
    d.ext = "history";
    d.block_type = 1;
    d.expected = 77;
    d.decoded_size = 9;
    d.begin();
    try std.testing.expectEqual(@as(u32, 0), d.dict_id);
    try std.testing.expectEqual(dec.Stage.get_frame_header_size, d.stage);
    try std.testing.expectEqual(@as(usize, 5), d.nextSrcSizeToDecompress());
    try std.testing.expectEqual(@as(u64, 0), d.decoded_size);
    try std.testing.expectEqual(@as(usize, 0), d.prefix_addr);
    try std.testing.expectEqual(@as(usize, 0), d.prev_end_addr);
    try std.testing.expectEqual(@as(usize, 0), d.ext.len);
    try std.testing.expectEqual(@as(u2, 3), d.block_type);
    // and a magicless context asks for one byte
    var m = try dec.Decompressor.init(gpa, .{ .format = .magicless });
    defer m.deinit();
    m.expected = 9;
    m.begin();
    try std.testing.expectEqual(@as(usize, 1), m.nextSrcSizeToDecompress());
}

test "the history cursors repair an end below the start, and an empty prefix reads no history" {
    var d = try dec.Decompressor.init(gpa, .{});
    defer d.deinit();
    var buf: [32]u8 = undefined;
    // the previous output "ends" below where the prefix starts: the next write starts a new prefix at its own address
    d.begin();
    d.prev_end_addr = @intFromPtr(&buf);
    d.prefix_addr = @intFromPtr(&buf) + 8;
    _ = try d.decompressContinue(&buf, zero_seq[0..5]);
    try std.testing.expectEqual(@intFromPtr(&buf), d.prefix_addr);
    try std.testing.expectEqual(@as(usize, 0), d.ext.len);
    // a context with no prefix (address 0) decodes a block without history, whatever its destination
    d.begin();
    _ = try d.decompressContinue(&buf, zero_seq[0..5]);
    _ = try d.decompressContinue(&buf, zero_seq[5..6]);
    _ = try d.decompressContinue(&buf, zero_seq[6..9]);
    d.prefix_addr = 0;
    const n = try d.decompressContinue(&buf, zero_seq[9..14]);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("abc", buf[0..3]);
    // copying a context onto itself changes nothing
    d.begin();
    _ = try d.decompressContinue(&buf, zero_seq[0..5]);
    d.copyFrom(&d);
    try std.testing.expectEqual(dec.Stage.decode_frame_header, d.stage);
    try std.testing.expectEqual(@as(usize, 1), d.nextSrcSizeToDecompress());
}

// ------------------------------------------------------------ queries and skippable frames

test "skippable frames and size queries on inputs of 0 to 8 bytes" {
    var dst: [8]u8 = undefined;
    const skip0 = [_]u8{ 0x52, 0x2a, 0x4d, 0x18, 0x00, 0x00, 0x00, 0x00 }; // variant 2, nothing in it
    for (0..8) |n| try std.testing.expectError(error.SrcSizeWrong, dec.readSkippableFrame(&dst, skip0[0..n]));
    const r = try dec.readSkippableFrame(&dst, &skip0); // exactly the header: an empty frame
    try std.testing.expectEqual(@as(usize, 0), r.len);
    try std.testing.expectEqual(@as(u32, 2), r.magic_variant);
    // findDecompressedSize: five to seven bytes of a skippable frame are a header cut short
    for (5..8) |n| try std.testing.expectError(error.SrcSizeWrong, dec.findDecompressedSize(skip0[0..n]));
    try std.testing.expectEqual(@as(?u64, 0), try dec.findDecompressedSize(&skip0));
    // five bytes that are no frame: the magic is refused, the length is not what is wrong
    try std.testing.expectError(error.PrefixUnknown, dec.findDecompressedSize("abcde"));
    try std.testing.expectError(error.SrcSizeWrong, dec.findDecompressedSize("abcd"));
}

test "a corrupt dictionary is refused when a frame could start, not before" {
    const bad = [_]u8{ 0x37, 0xa4, 0x30, 0xec, 1, 0, 0, 0, 0 }; // the magic, an ID, no tables
    var d = try dec.Decompressor.init(gpa, .{ .dictionary = &bad });
    defer d.deinit();
    var out: [16]u8 = undefined;
    // five bytes are as many as the header prefix: a frame is started, and its dictionary loaded
    try std.testing.expectError(error.DictionaryCorrupted, d.decompress(&out, &.{ 1, 2, 3, 4, 5 }));
    try std.testing.expectError(error.SrcSizeWrong, d.decompress(&out, &.{ 1, 2, 3, 4 }));
}

// ------------------------------------------------------------ magicless frames that look skippable

const lookalike_len = 0x184D + 256;

/// A magicless frame whose first four bytes read as the magic of a skippable
/// frame: descriptor 0x50 (content size in two bytes), window byte 0x2A,
/// content size 0x184D + 256; one RLE block of 'x'.
fn lookalike() [8]u8 {
    var f = [8]u8{ 0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 'x' };
    const bh: u32 = 1 | (1 << 1) | (lookalike_len << 3);
    f[4] = @truncate(bh);
    f[5] = @truncate(bh >> 8);
    f[6] = @truncate(bh >> 16);
    return f;
}

/// One call per piece: `in_chunk` bytes of input and `out_chunk` bytes of
/// output at a time, every output byte appended to `sink`.
fn pump(s: *dstream.DecompressStream, input: []const u8, in_chunk: usize, out_chunk: usize, sink: *std.ArrayList(u8)) !void {
    var ip: usize = 0;
    var buf: [8192]u8 = undefined;
    var guard: usize = 0;
    while (true) {
        guard += 1;
        if (guard > 100_000) return error.TestUnexpectedResult;
        const end = @min(input.len, ip + in_chunk);
        var in: zstd.InBuffer = .{ .src = input[0..end], .pos = ip };
        var out: zstd.OutBuffer = .{ .dst = buf[0..out_chunk] };
        const hint = try s.decompressStream(&out, &in);
        try sink.appendSlice(gpa, buf[0..out.pos]);
        ip = in.pos;
        if (hint == 0 and ip == input.len) return;
    }
}

test "a magicless frame is never taken for a skippable one" {
    const f = lookalike();
    try std.testing.expectEqual(@as(usize, 8), try dec.findFrameCompressedSizeAdvanced(&f, .magicless));
    var out: [lookalike_len + 8]u8 = undefined;
    var d = try dec.Decompressor.init(gpa, .{ .format = .magicless });
    defer d.deinit();
    try std.testing.expectEqual(@as(usize, lookalike_len), try d.decompress(&out, &f));
    try std.testing.expect(std.mem.allEqual(u8, out[0..lookalike_len], 'x'));
    // a one-byte input is a header cut short, in both formats' terms
    try std.testing.expectError(error.SrcSizeWrong, d.decompress(&out, f[0..1]));
    try std.testing.expectError(error.SrcSizeWrong, d.decompress(&out, f[0..3]));
    // piece by piece: one byte asked first
    var out2: [lookalike_len]u8 = undefined;
    var ip: usize = 0;
    var op: usize = 0;
    d.begin();
    while (true) {
        const n = d.nextSrcSizeWithInputSize(f.len - ip);
        if (n == 0) break;
        op += try d.decompressContinue(out2[op..], f[ip..][0..n]);
        ip += n;
    }
    try std.testing.expectEqual(f.len, ip);
    try std.testing.expectEqual(@as(usize, lookalike_len), op);
    // streamed, with an output smaller than the content: no single-pass shortcut
    var s = try dstream.DecompressStream.init(gpa, .{ .format = .magicless });
    defer s.deinit();
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(gpa);
    try pump(&s, &f, 8, 1000, &sink);
    try std.testing.expectEqual(@as(usize, lookalike_len), sink.items.len);
    try std.testing.expect(std.mem.allEqual(u8, sink.items, 'x'));
}

// ------------------------------------------------------------ raw dictionaries

fn decodeWith(opts: zstd.DecompressOptions, frame: []const u8, out: []u8) !usize {
    var d = try dec.Decompressor.init(gpa, opts);
    defer d.deinit();
    return d.decompress(out, frame);
}

test "a raw dictionary: the shortest zstd-format one is eight bytes, and what is shorter is content" {
    var out: [16]u8 = undefined;
    // a prefix of a zstd dictionary, up to seven bytes, is content: the frame decodes
    for (0..8) |n| try std.testing.expectEqual(@as(usize, 5), try decodeWith(.{ .dictionary = kats.full_dict[0..n] }, &raw5, &out));
    // eight bytes are the magic and an ID: a zstd dictionary with no tables
    try std.testing.expectError(error.DictionaryCorrupted, decodeWith(.{ .dictionary = kats.eight_byte_dict }, &raw5, &out));
}

test "a raw dictionary's tables are the context's own, and its literals can be reused" {
    var out: [256]u8 = undefined;
    const n = try decodeWith(.{ .dictionary = kats.full_dict }, kats.lit_repeat_frame, &out);
    try std.testing.expectEqualStrings(kats.lit_repeat_content, out[0..n]);
    // loading it points the four table pointers at the context's own tables, whatever they pointed at
    var d = try dec.Decompressor.init(gpa, .{ .dictionary = kats.full_dict });
    defer d.deinit();
    d.begin();
    var other: huf_dec.DTable = .{};
    d.st.ll_ptr = &d.st.of;
    d.st.of_ptr = &d.st.ml;
    d.st.ml_ptr = &d.st.ll;
    d.st.huf_ptr = &other;
    const f = kats.frame_full_l3;
    const hs = try dec.frameHeaderSize(f[0..5]);
    d.st.lit_entropy = false;
    try d.decodeFrameHeader(f[0..hs]);
    try std.testing.expect(d.st.ll_ptr == &d.st.ll);
    try std.testing.expect(d.st.of_ptr == &d.st.of);
    try std.testing.expect(d.st.ml_ptr == &d.st.ml);
    try std.testing.expect(d.st.huf_ptr == &d.st.huf);
    try std.testing.expect(d.st.lit_entropy);
}

test "dictionary identity: a prefix names none, and a set of DDicts leaves the last one's ID" {
    var a = try ddict_mod.DDict.init(gpa, kats.full_dict, .auto);
    defer a.deinit(gpa);
    var b = try ddict_mod.DDict.init(gpa, kats.full_dict2, .auto);
    defer b.deinit(gpa);
    try std.testing.expect(a.dictId() != b.dictId());
    var out: [512]u8 = undefined;
    // a prefix is applied to the frame: it has no ID, so a frame that names one is refused even with DDicts around
    const set = [_]*const ddict_mod.DDict{&a};
    try std.testing.expectError(error.DictionaryWrong, decodeWith(.{ .prefix_once = "some content", .ddicts = &set }, kats.frame_full_l3, &out));
    // one-shot: the last DDict of the set is the dictionary, and its ID is the context's, for a frame that names none
    const both = [_]*const ddict_mod.DDict{ &a, &b };
    var d = try dec.Decompressor.init(gpa, .{ .ddicts = &both });
    defer d.deinit();
    try std.testing.expectEqual(@as(usize, 5), try d.decompress(&out, &raw5));
    try std.testing.expectEqual(b.dictId(), d.dict_id);
}

// ------------------------------------------------------------ literals through a DDict

/// A frame of 1 KiB windows, no content size, no dictionary ID, whose blocks are `n`
/// compressed blocks each holding `lits` as treeless literals (the previous table is
/// reused) coded with `ct`, and no sequences.
fn treelessFrame(ct: *const huf.CTable, lits: []const u8, n: usize) ![]u8 {
    var f: std.ArrayList(u8) = .empty;
    errdefer f.deinit(gpa);
    try f.appendSlice(gpa, &(magic ++ [_]u8{ 0x00, 0x00 }));
    var cs: [1024]u8 = undefined;
    const c = huf.compress1X(&cs, lits, ct);
    try std.testing.expect(c > 0 and c < 1024);
    for (0..n) |i| {
        const lh: u32 = 3 | (0 << 2) | (@as(u32, @intCast(lits.len)) << 4) | (@as(u32, @intCast(c)) << 14); // treeless, one stream, 10-bit sizes
        const block_len: u32 = 3 + @as(u32, @intCast(c)) + 1;
        const bh: u32 = @as(u32, @intFromBool(i + 1 == n)) | (2 << 1) | (block_len << 3);
        try f.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, bh))[0..3]);
        try f.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, lh))[0..3]);
        try f.appendSlice(gpa, cs[0..c]);
        try f.append(gpa, 0); // no sequences
    }
    return f.toOwnedSlice(gpa);
}

test "two blocks in a row reuse the dictionary's Huffman table" {
    var dd = try ddict_mod.DDict.init(gpa, kats.full_dict, .auto);
    defer dd.deinit(gpa);
    var ct: huf.CTable = .{};
    var zero: bool = false;
    _ = try huf.readCTable(&ct, kats.full_dict[8..], &zero);
    const lits = kats.lit_repeat_content[0..@min(90, kats.lit_repeat_content.len)];
    var counts: [256]u32 = @splat(0);
    var max_symbol: u32 = 0;
    for (lits) |b| {
        counts[b] += 1;
        max_symbol = @max(max_symbol, b);
    }
    try std.testing.expect(huf.validateCTable(&ct, counts[0 .. max_symbol + 1], max_symbol));
    const f = try treelessFrame(&ct, lits, 2);
    defer gpa.free(f);
    var out: [256]u8 = undefined;
    const n = try decodeWith(.{ .ddict = &dd }, f, &out);
    try std.testing.expectEqual(2 * lits.len, n);
    try std.testing.expectEqualSlices(u8, lits, out[0..lits.len]);
    try std.testing.expectEqualSlices(u8, lits, out[lits.len..n]);
}

/// A compressed block holding only literals (no sequences): `kind` 2 carries its own table in `payload`, 3 reuses the previous one.
fn litBlock(f: *std.ArrayList(u8), last: bool, kind: u32, regen: usize, payload: []const u8) !void {
    const lh: u32 = kind | (@as(u32, @intCast(regen)) << 4) | (@as(u32, @intCast(payload.len)) << 14);
    const block_len: u32 = @intCast(3 + payload.len + 1);
    const bh: u32 = @as(u32, @intFromBool(last)) | (2 << 1) | (block_len << 3);
    try f.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, bh))[0..3]);
    try f.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, lh))[0..3]);
    try f.appendSlice(gpa, payload);
    try f.append(gpa, 0); // no sequences
}

test "a block with a table of its own replaces the dictionary's for the blocks that reuse it" {
    var dd = try ddict_mod.DDict.init(gpa, kats.full_dict, .auto);
    defer dd.deinit(gpa);
    const lits = kats.lit_repeat_content[0..@min(90, kats.lit_repeat_content.len)];
    var comp: [1024]u8 = undefined;
    var old: huf.CTable = .{};
    var rep: huf.Repeat = .none;
    const c = try huf.compress(&comp, lits, 11, .single, &old, &rep, .{});
    try std.testing.expect(c > 1);
    var own: huf.CTable = .{};
    var zero: bool = false;
    _ = try huf.readCTable(&own, comp[0..c], &zero);
    var cs: [1024]u8 = undefined;
    const c2 = huf.compress1X(&cs, lits, &own);
    try std.testing.expect(c2 > 0);
    var f: std.ArrayList(u8) = .empty;
    defer f.deinit(gpa);
    try f.appendSlice(gpa, &(magic ++ [_]u8{ 0x00, 0x00 }));
    try litBlock(&f, false, 2, lits.len, comp[0..c]); // its own table
    try litBlock(&f, true, 3, lits.len, cs[0..c2]); // and that one again
    var out: [256]u8 = undefined;
    const n = try decodeWith(.{ .ddict = &dd }, f.items, &out);
    try std.testing.expectEqual(2 * lits.len, n);
    try std.testing.expectEqualSlices(u8, lits, out[0..lits.len]);
    try std.testing.expectEqualSlices(u8, lits, out[lits.len..n]);
}

// ------------------------------------------------------------ the streaming decoder

test "a stream's state after a reset: input loaded, output waiting, expected output" {
    const fa = magic ++ [_]u8{ 0x00, 0x00, 0x2d, 0x00, 0x00, 0x18, 'x', 'y', 'z', 0x00 };
    const fb = magic ++ [_]u8{ 0x00, 0x00, 0x2d, 0x00, 0x00, 0x18, 'a', 'b', 'c', 0x00 };
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    // part of a compressed block loaded (two of its five bytes), then given up
    var in1: zstd.InBuffer = .{ .src = fa[0..11] };
    var none: [0]u8 = .{};
    var out1: zstd.OutBuffer = .{ .dst = &none };
    _ = try s.decompressStream(&out1, &in1);
    s.reset();
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(gpa);
    try pump(&s, &fb, 1, 8, &sink);
    try std.testing.expectEqualStrings("abc", sink.items);
    // decoded output not yet handed out (one byte of three), then given up: an empty frame ends cleanly
    var in2: zstd.InBuffer = .{ .src = &fa };
    var buf1: [1]u8 = undefined;
    var out2: zstd.OutBuffer = .{ .dst = &buf1 };
    _ = try s.decompressStream(&out2, &in2);
    try std.testing.expectEqual(@as(usize, 1), out2.pos);
    s.reset();
    const empty_frame = magic ++ [_]u8{ 0x20, 0x00, 0x01, 0x00, 0x00 };
    var sink2: std.ArrayList(u8) = .empty;
    defer sink2.deinit(gpa);
    try pump(&s, &empty_frame, 100, 8, &sink2);
    try std.testing.expectEqual(@as(usize, 0), sink2.items.len);
}

test "a stable output buffer is the one the header was read into, even when the header comes in two calls" {
    var s = try dstream.DecompressStream.init(gpa, .{ .stable_output = true });
    defer s.deinit();
    var obuf: [16]u8 = undefined;
    var in1: zstd.InBuffer = .{ .src = raw5[0..2] };
    var out1: zstd.OutBuffer = .{ .dst = &obuf };
    _ = try s.decompressStream(&out1, &in1);
    var in2: zstd.InBuffer = .{ .src = &raw5, .pos = 2 };
    var out2: zstd.OutBuffer = .{ .dst = &obuf };
    try std.testing.expectEqual(@as(usize, 0), try s.decompressStream(&out2, &in2));
    try std.testing.expectEqualStrings("hello", obuf[0..out2.pos]);
    // a different buffer in the middle of a frame is refused
    var s2 = try dstream.DecompressStream.init(gpa, .{ .stable_output = true });
    defer s2.deinit();
    var other: [16]u8 = undefined;
    var in3: zstd.InBuffer = .{ .src = raw5[0..2] };
    var out3: zstd.OutBuffer = .{ .dst = &obuf };
    _ = try s2.decompressStream(&out3, &in3);
    var in4: zstd.InBuffer = .{ .src = &raw5, .pos = 2 };
    var out4: zstd.OutBuffer = .{ .dst = &other };
    try std.testing.expectError(error.DstBufferWrong, s2.decompressStream(&out4, &in4));
}

test "a stream: positions beyond the buffers are refused" {
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var buf: [4]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = "ab", .pos = 3 };
    var out: zstd.OutBuffer = .{ .dst = &buf };
    try std.testing.expectError(error.SrcSizeWrong, s.decompressStream(&out, &in));
    var in2: zstd.InBuffer = .{ .src = "ab", .pos = 2 };
    var out2: zstd.OutBuffer = .{ .dst = &buf, .pos = 5 };
    try std.testing.expectError(error.DstSizeTooSmall, s.decompressStream(&out2, &in2));
}

test "a skippable frame: output is not required for its content, in either output mode, and it takes buffers" {
    const skip = [_]u8{ 0x5a, 0x2a, 0x4d, 0x18, 100, 0, 0, 0 } ++ @as([100]u8, @splat(7));
    for ([_]bool{ false, true }) |stable| {
        var s = try dstream.DecompressStream.init(gpa, .{ .stable_output = stable });
        defer s.deinit();
        var sink: std.ArrayList(u8) = .empty;
        defer sink.deinit(gpa);
        try pump(&s, &skip, 108, 8, &sink); // all at once, into 8 bytes of output
        try std.testing.expectEqual(@as(usize, 0), sink.items.len);
        var s2 = try dstream.DecompressStream.init(gpa, .{ .stable_output = stable });
        defer s2.deinit();
        try pump(&s2, &skip, 13, 8, &sink); // the content arrives in pieces: the loaded-input path
        try std.testing.expectEqual(@as(usize, 0), sink.items.len);
        try std.testing.expectEqual(dec.Stage.get_frame_header_size, s2.d.stage);
        try std.testing.expectEqual(@as(usize, 0), s2.d.expected);
    }
    // a skippable frame in one call, with room for its content, is not decoded in a single pass: the stream has its buffers
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var out: [200]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = &skip };
    var o: zstd.OutBuffer = .{ .dst = &out };
    try std.testing.expectEqual(@as(usize, 0), try s.decompressStream(&o, &in));
    try std.testing.expect(s.workspaceSize() > dec.estimateDCtxSize());
}

test "a frame after a single-pass frame is read from its own header" {
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(gpa);
    try pump(&s, &(raw5 ++ rle64), 1000, 10, &sink);
    const want = "hello".* ++ @as([64]u8, @splat('z'));
    try std.testing.expectEqualSlices(u8, &want, sink.items);
}

test "raw block bytes come out as they arrive" {
    const f = magic ++ [_]u8{ 0x00, 0x00, 0x51, 0x00, 0x00 } ++ "abcdefghij".*; // one raw last block of ten
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var buf: [16]u8 = undefined;
    var in1: zstd.InBuffer = .{ .src = f[0..9] };
    var out1: zstd.OutBuffer = .{ .dst = &buf };
    try std.testing.expect((try s.decompressStream(&out1, &in1)) > 0);
    try std.testing.expectEqual(@as(usize, 9), in1.pos);
    var in2: zstd.InBuffer = .{ .src = f[0..13], .pos = 9 };
    var out2: zstd.OutBuffer = .{ .dst = &buf };
    _ = try s.decompressStream(&out2, &in2);
    try std.testing.expectEqualStrings("abcd", buf[0..out2.pos]);
}

/// A frame of one RLE block of `len` 'a', its size in the header (single segment).
const rle300 = blk: {
    const bh: u32 = 1 | (1 << 1) | (300 << 3);
    break :blk magic ++ [_]u8{ 0x60, 44, 0, @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16), 'a' };
};
const rle100 = blk: {
    const bh: u32 = 1 | (1 << 1) | (100 << 3);
    break :blk magic ++ [_]u8{ 0x20, 100, @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16), 'a' };
};

test "the buffers shrink after 128 frames of a third of their size, and no sooner" {
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(gpa);
    const est = dec.estimateDCtxSize();
    const big: []const u8 = &rle300;
    const small: []const u8 = &rle100;
    try pump(&s, big, 100, 50, &sink);
    try std.testing.expectEqual(est + 600, s.workspaceSize());
    for (0..127) |_| try pump(&s, small, 100, 50, &sink);
    try std.testing.expectEqual(est + 600, s.workspaceSize());
    try pump(&s, small, 100, 50, &sink); // the 128th
    try std.testing.expectEqual(est + 200, s.workspaceSize());
    // a frame that is not oversized starts the count again
    var s2 = try dstream.DecompressStream.init(gpa, .{});
    defer s2.deinit();
    try pump(&s2, big, 100, 50, &sink);
    for (0..100) |_| try pump(&s2, small, 100, 50, &sink);
    try pump(&s2, big, 100, 50, &sink);
    for (0..100) |_| try pump(&s2, small, 100, 50, &sink);
    try std.testing.expectEqual(est + 600, s2.workspaceSize());
}

test "a stream whose buffer could not be made can be reset and used again" {
    var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 2 }); // the state, the first buffers, then the shrink fails
    var s = try dstream.DecompressStream.init(fa.allocator(), .{});
    defer s.deinit();
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(gpa);
    const big: []const u8 = &rle300;
    const small: []const u8 = &rle100;
    try pump(&s, big, 100, 50, &sink);
    for (0..127) |_| try pump(&s, small, 100, 50, &sink);
    try std.testing.expectError(error.OutOfMemory, pump(&s, small, 100, 50, &sink));
    s.reset();
    fa.fail_index = std.math.maxInt(usize);
    sink.clearRetainingCapacity();
    try pump(&s, big, 100, 50, &sink);
    try std.testing.expectEqual(@as(usize, 300), sink.items.len);
}

test "estimateSizeFromFrame: the largest content size that fits, and one more" {
    const rest = dec.block_size_max + dec.estimateDCtxSize();
    if (comptime @bitSizeOf(usize) < 64) return;
    var hdr = magic ++ [_]u8{ 0xe0, 0, 0, 0, 0, 0, 0, 0, 0 }; // single segment, content size in 8 bytes
    const fit: u64 = std.math.maxInt(usize) - rest;
    std.mem.writeInt(u64, hdr[5..13], fit, .little);
    const sz = try dstream.estimateSizeFromFrame(&hdr, .{ .max_window_size = std.math.maxInt(u64) });
    try std.testing.expectEqual(@as(usize, std.math.maxInt(usize)), sz);
    std.mem.writeInt(u64, hdr[5..13], fit + 1, .little);
    try std.testing.expectError(error.FrameParameterWindowTooLarge, dstream.estimateSizeFromFrame(&hdr, .{ .max_window_size = std.math.maxInt(u64) }));
}

// ------------------------------------------------------------ the Reader

const SlowReader = struct {
    data: []const u8,
    pos: usize = 0,
    interface: std.Io.Reader,

    fn init(data: []const u8, buffer: []u8) SlowReader {
        return .{ .data = data, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    /// One byte per call.
    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *SlowReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.pos == self.data.len) return error.EndOfStream;
        if (limit == .nothing) return 0;
        try w.writeAll(self.data[self.pos..][0..1]);
        self.pos += 1;
        return 1;
    }
};

test "Reader: a stable output option does not apply, an error is kept, no room is no read, a slow input is waited for" {
    var plain: [6000]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @truncate(i *% 7 +% i / 13);
    const z = try zstd.compressAlloc(gpa, &plain, .{});
    defer gpa.free(z);
    // the Reader gives the stream a different output every call: its stable_output is forced off
    {
        var in: std.Io.Reader = .fixed(z);
        var buf: [64]u8 = undefined;
        var r = try dstream.Reader.init(gpa, &in, &buf, .{ .stable_output = true });
        defer r.deinit();
        var got: [6000]u8 = undefined;
        try r.interface.readSliceAll(&got);
        try std.testing.expectEqualSlices(u8, &plain, &got);
    }
    // the same for a frame of unknown content size (no single pass), whose output the Reader hands out in pieces
    {
        var f: std.ArrayList(u8) = .empty;
        defer f.deinit(gpa);
        try f.appendSlice(gpa, &(magic ++ [_]u8{ 0x00, 0x00 }));
        var want: [6000]u8 = undefined;
        for (0..6) |i| {
            const bh: u32 = @as(u32, @intFromBool(i == 5)) | (1000 << 3);
            try f.appendSlice(gpa, &.{ @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16) });
            for (want[i * 1000 ..][0..1000], 0..) |*b, j| b.* = @truncate(i * 31 + j * 7);
            try f.appendSlice(gpa, want[i * 1000 ..][0..1000]);
        }
        var in: std.Io.Reader = .fixed(f.items);
        var buf: [64]u8 = undefined;
        var r = try dstream.Reader.init(gpa, &in, &buf, .{ .stable_output = true });
        defer r.deinit();
        var got: [6000]u8 = undefined;
        try r.interface.readSliceAll(&got);
        try std.testing.expectEqualSlices(u8, &want, &got);
        // and with an input that gives a byte at a time, so that the frame is decoded in many calls
        var ibuf: [16]u8 = undefined;
        var slow = SlowReader.init(f.items, &ibuf);
        var none: [0]u8 = .{};
        var r2 = try dstream.Reader.init(gpa, &slow.interface, &none, .{ .stable_output = true });
        defer r2.deinit();
        @memset(&got, 0);
        try r2.interface.readSliceAll(&got);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
    // a damaged frame: ReadFailed, and why
    {
        const bad = magic ++ [_]u8{ 0x20, 0x05, 0x2f, 0x00, 0x00 } ++ "hello".*; // last block of the reserved type
        var in: std.Io.Reader = .fixed(&bad);
        var r = try dstream.Reader.init(gpa, &in, &.{}, .{});
        defer r.deinit();
        var got: [8]u8 = undefined;
        try std.testing.expectError(error.ReadFailed, r.interface.readSliceAll(&got));
        try std.testing.expectEqual(@as(?dstream.Error, error.CorruptionDetected), r.err);
    }
    // a limit of nothing: nothing is read, and nothing is consumed
    {
        var in: std.Io.Reader = .fixed(&raw5);
        var r = try dstream.Reader.init(gpa, &in, &.{}, .{});
        defer r.deinit();
        var sink: [16]u8 = undefined;
        var w: std.Io.Writer = .fixed(&sink);
        try std.testing.expectEqual(@as(usize, 0), try r.interface.stream(&w, .nothing));
        try std.testing.expectEqual(@as(usize, 0), in.seek);
    }
    // an input that gives one byte at a time: the decoder waits for it
    {
        var ibuf: [16]u8 = undefined;
        var slow = SlowReader.init(z, &ibuf);
        var r = try dstream.Reader.init(gpa, &slow.interface, &.{}, .{});
        defer r.deinit();
        var got: [6000]u8 = undefined;
        try r.interface.readSliceAll(&got);
        try std.testing.expectEqualSlices(u8, &plain, &got);
    }
}

test "sixteen calls that move nothing are an error, fifteen are not, and any progress starts the count again" {
    const f = magic ++ [_]u8{ 0x00, 0x00, 0x51, 0x00, 0x00 } ++ "abcdefghij".*; // a raw last block of ten
    var s = try dstream.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var buf: [16]u8 = undefined;
    var in0: zstd.InBuffer = .{ .src = f[0..9] };
    var out0: zstd.OutBuffer = .{ .dst = &buf };
    _ = try s.decompressStream(&out0, &in0);
    var pos: usize = 9;
    for (0..2) |_| {
        for (0..15) |_| {
            var in: zstd.InBuffer = .{ .src = f[0..pos], .pos = pos };
            var out: zstd.OutBuffer = .{ .dst = &buf };
            _ = try s.decompressStream(&out, &in);
        }
        var in: zstd.InBuffer = .{ .src = f[0 .. pos + 1], .pos = pos };
        var out: zstd.OutBuffer = .{ .dst = &buf };
        _ = try s.decompressStream(&out, &in);
        try std.testing.expectEqual(@as(usize, 1), out.pos);
        pos += 1;
    }
    for (0..15) |_| {
        var in: zstd.InBuffer = .{ .src = f[0..pos], .pos = pos };
        var out: zstd.OutBuffer = .{ .dst = &buf };
        _ = try s.decompressStream(&out, &in);
    }
    var in: zstd.InBuffer = .{ .src = f[0..pos], .pos = pos };
    var out: zstd.OutBuffer = .{ .dst = &buf };
    try std.testing.expectError(error.NoForwardProgressInputEmpty, s.decompressStream(&out, &in));
}
