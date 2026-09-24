// SPDX-License-Identifier: MIT
//! Decoding with a dictionary: `DDict`, raw-content and zstd-format
//! dictionaries, one-shot and streaming, the dictID check, and
//! `ZSTD_d_refMultipleDDicts`. Every frame here is one libzstd 1.5.7
//! actually emits with `ZSTD_compress_usingDict` (`testdata/dict_kats.zig`,
//! `tools/gen-dict-testdata.sh`) -- this module's own compressor does not
//! support dictionaries yet (Z4).

const std = @import("std");
const zstd = @import("root.zig");
const kats = @import("testdata/dict_kats.zig");

const gpa = std.testing.allocator;

/// One-shot decode with `opts` (the free `zstd.decompress` takes none).
fn decodeOpts(dst: []u8, src: []const u8, opts: zstd.DecompressOptions) !usize {
    var d = try zstd.Decompressor.init(gpa, opts);
    defer d.deinit();
    return d.decompress(dst, src);
}

test "one-shot, full (zstd-format) dictionary, raw bytes: auto-detected, entropy applied" {
    var out: [512]u8 = undefined;
    const n = try decodeOpts(&out, kats.frame_full_l3, .{ .dictionary = kats.full_dict });
    try std.testing.expectEqualStrings(kats.in1_content, out[0..n]);
    const n19 = try decodeOpts(&out, kats.frame_full_l19, .{ .dictionary = kats.full_dict });
    try std.testing.expectEqualStrings(kats.in1_content, out[0..n19]);
}

test "one-shot, digested DDict (auto content type)" {
    var dd = try zstd.DDict.init(gpa, kats.full_dict, .auto);
    defer dd.deinit(gpa);
    try std.testing.expect(dd.dictId() != 0);
    try std.testing.expectEqual(zstd.getDictId(kats.full_dict), dd.dictId());

    var out: [512]u8 = undefined;
    const n = try decodeOpts(&out, kats.frame_full_l3, .{ .ddict = &dd });
    try std.testing.expectEqualStrings(kats.in1_content, out[0..n]);
}

test "one-shot, raw-content dictionary (no entropy, no dictID)" {
    var out: [512]u8 = undefined;
    const n = try decodeOpts(&out, kats.frame_raw_l3, .{ .dictionary = kats.raw_dict });
    try std.testing.expectEqualStrings(kats.in1_content, out[0..n]);
    const n2 = try decodeOpts(&out, kats.frame_raw_l5, .{ .dictionary = kats.raw_dict });
    try std.testing.expectEqualStrings(kats.in2_content, out[0..n2]);
}

test "wrong dictionary: dictID mismatch is DictionaryWrong" {
    var wrong = try zstd.DDict.init(gpa, kats.full_dict2, .auto);
    defer wrong.deinit(gpa);
    var out: [512]u8 = undefined;
    try std.testing.expectError(error.DictionaryWrong, decodeOpts(&out, kats.frame_full_l3, .{ .ddict = &wrong }));
    // no dictionary at all: same error, the frame still names one
    try std.testing.expectError(error.DictionaryWrong, decodeOpts(&out, kats.frame_full_l3, .{}));
}

test "corrupted dictionary: entropy tables truncated is DictionaryCorrupted" {
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, kats.full_dict_corrupt, .full));
    // .auto is lenient about a missing magic/too-short buffer, but this one
    // has the magic and claims to be a full dict, so truncation still errors
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, kats.full_dict_corrupt, .auto));
    // forced raw content never parses entropy, so the same bytes load fine
    var d = try zstd.DDict.init(gpa, kats.full_dict_corrupt, .raw_content);
    defer d.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 0), d.dictId());
}

test "a 7-byte buffer (one short of magic+dictID) never reads past its end" {
    // kats.full_dict starts with a valid magic number; a prefix of it one
    // byte short of holding the dictID field must be treated the same as
    // any too-short buffer (raw content for .auto, DictionaryCorrupted
    // for .full), never read past index 6 for the dictID.
    const seven = kats.full_dict[0..7];
    var raw = try zstd.DDict.init(gpa, seven, .auto);
    defer raw.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 0), raw.dictId());
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, seven, .full));
    try std.testing.expectEqual(@as(u32, 0), zstd.getDictId(seven));
}

test "refMultipleDDicts: picks the dictionary by the frame's dictID" {
    var d1 = try zstd.DDict.init(gpa, kats.full_dict, .auto);
    defer d1.deinit(gpa);
    var d2 = try zstd.DDict.init(gpa, kats.full_dict2, .auto);
    defer d2.deinit(gpa);
    const set = [_]*const zstd.DDict{ &d2, &d1 }; // deliberately not sorted/matching order
    var out: [512]u8 = undefined;
    const n = try decodeOpts(&out, kats.frame_full_l3, .{ .ddicts = &set });
    try std.testing.expectEqualStrings(kats.in1_content, out[0..n]);
}

test "streaming: full dictionary, one byte at a time (no shortcut)" {
    var dd = try zstd.DDict.init(gpa, kats.full_dict, .auto);
    defer dd.deinit(gpa);
    var stream = try zstd.DecompressStream.init(gpa, .{ .ddict = &dd });
    defer stream.deinit();

    var out: [512]u8 = undefined;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var i: usize = 0;
    while (i < kats.frame_full_l19.len) : (i += 1) {
        var in: zstd.InBuffer = .{ .src = kats.frame_full_l19[0 .. i + 1], .pos = i };
        while (in.pos < in.src.len) {
            var ob: zstd.OutBuffer = .{ .dst = &out, .pos = 0 };
            _ = try stream.decompressStream(&ob, &in);
            try got.appendSlice(gpa, out[0..ob.pos]);
        }
    }
    try std.testing.expectEqualStrings(kats.in1_content, got.items);
}

test "streaming: raw dictionary via loadDictionary (raw bytes option)" {
    var stream = try zstd.DecompressStream.init(gpa, .{ .dictionary = kats.raw_dict });
    defer stream.deinit();
    var out: [512]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = kats.frame_raw_l5 };
    var ob: zstd.OutBuffer = .{ .dst = &out };
    _ = try stream.decompressStream(&ob, &in);
    try std.testing.expectEqualStrings(kats.in2_content, out[0..ob.pos]);
}

test "streaming: refPrefix applies to exactly one frame" {
    // frame_raw_l3 was compressed with raw_dict as content (equivalent to
    // a prefix on the compress side: no header to strip either way).
    var stream = try zstd.DecompressStream.init(gpa, .{ .prefix = kats.raw_dict });
    defer stream.deinit();
    var out: [512]u8 = undefined;
    {
        var in: zstd.InBuffer = .{ .src = kats.frame_raw_l3 };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        _ = try stream.decompressStream(&ob, &in);
        try std.testing.expectEqualStrings(kats.in1_content, out[0..ob.pos]);
    }
    // a second frame gets no dictionary any more: use one that actually
    // needs a dictionary for its header to be accepted at all, so the
    // prefix being gone is observable as an error rather than silently
    // wrong output.
    {
        var in: zstd.InBuffer = .{ .src = kats.frame_full_l3 };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        try std.testing.expectError(error.DictionaryWrong, stream.decompressStream(&ob, &in));
    }
}

test "getDictId / getFrameDictId" {
    try std.testing.expect(zstd.getDictId(kats.full_dict) != 0);
    try std.testing.expectEqual(@as(u32, 0), zstd.getDictId(kats.raw_dict));
    try std.testing.expectEqual(zstd.getDictId(kats.full_dict), zstd.getFrameDictId(kats.frame_full_l3));
    try std.testing.expectEqual(@as(u32, 0), zstd.getFrameDictId(kats.frame_raw_l3));
}
