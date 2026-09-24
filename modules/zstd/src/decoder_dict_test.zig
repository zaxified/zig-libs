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

test "a buffer without the magic number requested as .full is DictionaryCorrupted" {
    // raw_dict is >= 8 bytes (so past the too-short check) but does not
    // start with the magic number: .full must still refuse it, not
    // silently fall back to pure-content mode the way .auto does.
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, kats.raw_dict, .full));
    // .auto and .raw_content both accept the same bytes as pure content
    var da = try zstd.DDict.init(gpa, kats.raw_dict, .auto);
    defer da.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 0), da.dictId());
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

test "mutation-sweep KAT: .dictionary takes priority over .ddict for the one-shot dictID check" {
    // Options says at most one of dictionary/ddict/ddicts should be set,
    // but the one-shot check-only path (decodeFrameHeaderImpl's
    // apply_content=false branch) must still skip the ddicts/ddict
    // selection when `.dictionary` is what actually got applied
    // (applyFixedDictionary), or an unrelated `.ddict` sitting alongside
    // it could overwrite `d.dict_id` with the wrong value for the check.
    var wrong = try zstd.DDict.init(gpa, kats.full_dict2, .auto);
    defer wrong.deinit(gpa);
    var out: [512]u8 = undefined;
    const n = try decodeOpts(&out, kats.frame_full_l3, .{ .dictionary = kats.full_dict, .ddict = &wrong });
    try std.testing.expectEqualStrings(kats.in1_content, out[0..n]);
}

test "mutation-sweep KAT: refPrefix is actually wired to the first frame" {
    // frame_raw_l3 (used elsewhere as frame1) happens to decode correctly
    // even with no dictionary at all, so it cannot by itself prove
    // `Options.prefix` reaches the stream's decoder; frame_raw_l5 does
    // need raw_dict's content, so using it as the very first frame does.
    var stream = try zstd.DecompressStream.init(gpa, .{ .prefix = kats.raw_dict });
    defer stream.deinit();
    var out: [256]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = kats.frame_raw_l5 };
    var ob: zstd.OutBuffer = .{ .dst = &out };
    _ = try stream.decompressStream(&ob, &in);
    try std.testing.expectEqualStrings(kats.in2_content, out[0..ob.pos]);
}

test "mutation-sweep KAT: loadDictionary (raw bytes) auto-detects a zstd-format dictionary, streaming" {
    // Options.dictionary builds its DDict with content type .auto; forcing
    // .raw_content there would treat full_dict's magic/entropy header as
    // literal content instead of parsing it, changing both its dictID
    // (always 0 for raw content) and its history (unstripped either way,
    // but never entropy-backed) -- frame_full_l3 needs the real dictID
    // and, at this small size, is not proven wrong until decode fails.
    var stream = try zstd.DecompressStream.init(gpa, .{ .dictionary = kats.full_dict });
    defer stream.deinit();
    var out: [512]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = kats.frame_full_l3 };
    var ob: zstd.OutBuffer = .{ .dst = &out };
    _ = try stream.decompressStream(&ob, &in);
    try std.testing.expectEqualStrings(kats.in1_content, out[0..ob.pos]);
}

test "mutation-sweep KAT: refPrefix is not still active for a later frame (single-pass shortcut)" {
    // frame_raw_l3 and frame_raw_l5 both need raw_dict to decode
    // correctly, so if the prefix incorrectly outlived frame_raw_l3 (the
    // single-pass shortcut has its own place that must clear it --
    // dstream.zig, `d.decompress` call in the header-consume step),
    // frame_raw_l5 would decode successfully using it, wrongly -- instead
    // of correctly failing with no dictionary at all. Both frames are
    // small enough that this exercises the shortcut, not the regular
    // block-by-block path (see the "no shortcut" variant below).
    var stream = try zstd.DecompressStream.init(gpa, .{ .prefix = kats.raw_dict });
    defer stream.deinit();
    var out: [512]u8 = undefined;
    {
        var in: zstd.InBuffer = .{ .src = kats.frame_raw_l3 };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        _ = try stream.decompressStream(&ob, &in);
    }
    {
        var in: zstd.InBuffer = .{ .src = kats.frame_raw_l5 };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        try std.testing.expectError(error.CorruptionDetected, stream.decompressStream(&ob, &in));
    }
}

test "mutation-sweep KAT: refPrefix is not still active for a later frame (no shortcut)" {
    // same as above, but frame_raw_l3 is fed one byte at a time so the
    // single-pass shortcut never triggers, exercising the regular
    // (non-skippable) header-consume path's own clear instead.
    var stream = try zstd.DecompressStream.init(gpa, .{ .prefix = kats.raw_dict });
    defer stream.deinit();
    var out: [512]u8 = undefined;
    var i: usize = 0;
    while (i < kats.frame_raw_l3.len) : (i += 1) {
        var in: zstd.InBuffer = .{ .src = kats.frame_raw_l3[0 .. i + 1], .pos = i };
        while (in.pos < in.src.len) {
            var ob: zstd.OutBuffer = .{ .dst = &out };
            _ = try stream.decompressStream(&ob, &in);
        }
    }
    {
        var in: zstd.InBuffer = .{ .src = kats.frame_raw_l5 };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        try std.testing.expectError(error.CorruptionDetected, stream.decompressStream(&ob, &in));
    }
}

test "mutation-sweep KAT: refPrefix is consumed by an intervening skippable frame" {
    // matches libzstd: ZSTD_getDDict (which flips a "use once" dictionary
    // to "don't use") runs before the skippable-frame check, so a
    // skippable frame between the prefix and the next real frame
    // consumes it too, even though it is never applied to anything (see
    // SPEC.md, Decoder).
    var stream = try zstd.DecompressStream.init(gpa, .{ .prefix = kats.raw_dict });
    defer stream.deinit();
    var out: [512]u8 = undefined;
    const skippable = [_]u8{ 0x50, 0x2a, 0x4d, 0x18, 0x00, 0x00, 0x00, 0x00 }; // magic variant 0, empty
    {
        var in: zstd.InBuffer = .{ .src = &skippable };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        _ = try stream.decompressStream(&ob, &in);
    }
    {
        var in: zstd.InBuffer = .{ .src = kats.frame_raw_l5 };
        var ob: zstd.OutBuffer = .{ .dst = &out };
        try std.testing.expectError(error.CorruptionDetected, stream.decompressStream(&ob, &in));
    }
}

test "mutation-sweep KAT: a dictionary whose content size is exactly 0 is rejected" {
    // full_dict truncated to exactly its entropy header: every valid
    // repeat offset is >= 1, which always exceeds a content size of 0, so
    // the dictionary is corrupted regardless of how that is detected --
    // libzstd rejects it too (dictionary_corrupted), confirmed via
    // tools/zdec.c when this was crafted.
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, kats.full_dict_zero_content, .full));
}

test "mutation-sweep KAT: a dictID-0 frame decodes with an unrelated dictionary active, no DictionaryWrong" {
    // frame_raw_l5 names no dictionary (dictID 0); libzstd's dictID check
    // is `fParams.dictID && (dctx->dictID != fParams.dictID)`, which
    // short-circuits entirely when fParams.dictID is 0 -- so decoding it
    // with some other, unrelated dictionary active never trips
    // DictionaryWrong, no matter what that dictionary's own ID is
    // (confirmed via tools/zdec.c: OK, not ERR 32, with full_dict
    // active). The content this decodes to is unrelated garbage (full_dict
    // is the wrong history for it) but that is not what this pins -- see
    // the "dictID-0 frame matches a raw-content dictionary too" tests
    // above for the content-correctness angle.
    var dd = try zstd.DDict.init(gpa, kats.full_dict, .auto);
    defer dd.deinit(gpa);
    var out: [256]u8 = undefined;
    const n = try decodeOpts(&out, kats.frame_raw_l5, .{ .ddict = &dd });
    try std.testing.expectEqual(@as(usize, 52), n);
    try std.testing.expect(!std.mem.eql(u8, kats.in2_content, out[0..n]));
}

test "mutation-sweep KAT: a frame whose literals reuse the dictionary's Huffman table" {
    // found by hunting: most frames here don't exercise set_repeat
    // literals against the dictionary's own table at all, so a mutation
    // that stops applyEntropy from marking it reusable went uncaught
    // until this one (level 1, a 106-byte input -- see
    // tools/gen-dict-testdata.sh's history for how it was found).
    var dd = try zstd.DDict.init(gpa, kats.full_dict, .auto);
    defer dd.deinit(gpa);
    var out: [256]u8 = undefined;
    const n = try decodeOpts(&out, kats.lit_repeat_frame, .{ .ddict = &dd });
    try std.testing.expectEqualStrings(kats.lit_repeat_content, out[0..n]);
}

test "mutation-sweep KAT: exactly 8 bytes (magic + dictID, no entropy header) is rejected, no OOB read" {
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, kats.eight_byte_dict, .full));
}

test "mutation-sweep KAT: a repeat offset of exactly 0 is rejected" {
    // full_dict with its first repeat offset patched to 0 (otherwise
    // identical, so content size is unaffected and still > 0); libzstd
    // rejects this too (dictionary_corrupted), confirmed via tools/zdec.c.
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.init(gpa, kats.full_dict_rep0_zero, .full));
}

test "refMultipleDDicts: a dictID-0 frame matches a raw-content dictionary too, one-shot" {
    // small_frame names no dictionary (dictID 0), but needs small_raw_a's
    // content to decode correctly. small_raw_b is a different raw-content
    // dictionary (dictID 0 too, like every raw-content dictionary).
    // libzstd's ZSTD_DDictHashSet keys on dictID, so both hash to the
    // same bucket and only the *last*-registered one survives
    // (ZSTD_DDictHashSet_emplaceDDict replaces on a duplicate ID) -- a
    // dictID-0 frame is not special-cased away from this, confirmed
    // against libzstd, not assumed (SPEC.md, Decoder). This port matches:
    // small_raw_b (last in the list) is applied, producing the same wrong
    // (but deterministic) bytes libzstd's own C reference produced.
    var da = try zstd.DDict.init(gpa, kats.small_raw_a, .raw_content);
    defer da.deinit(gpa);
    var db = try zstd.DDict.init(gpa, kats.small_raw_b, .raw_content);
    defer db.deinit(gpa);
    const set = [_]*const zstd.DDict{ &da, &db };

    var out: [256]u8 = undefined;
    const n_correct = try decodeOpts(&out, kats.small_frame, .{ .ddict = &da });
    try std.testing.expectEqualStrings(kats.small_in_content, out[0..n_correct]);

    const n = try decodeOpts(&out, kats.small_frame, .{ .ddicts = &set });
    // libzstd's own reference, given small_raw_b instead of small_raw_a,
    // decodes small_frame to exactly this (garbage, since it is the wrong
    // dictionary's content, but reproducible garbage): the point pinned
    // here is that this port picks the same "wrong" dictionary libzstd
    // does, not that the result is meaningful.
    try std.testing.expectEqualStrings(
        ", \"gamma\",:\"alpha\", \"delta\",:\"alpha\",\"fields\":\"beta\", \":\"alpha\",\"fields\":delta\", \"\"beta\", \":\"alph]}",
        out[0..n],
    );
}

test "refMultipleDDicts: a dictID-0 frame matches a raw-content dictionary too, streaming (no shortcut)" {
    var da = try zstd.DDict.init(gpa, kats.small_raw_a, .raw_content);
    defer da.deinit(gpa);
    var db = try zstd.DDict.init(gpa, kats.small_raw_b, .raw_content);
    defer db.deinit(gpa);
    const set = [_]*const zstd.DDict{ &da, &db };

    var stream = try zstd.DecompressStream.init(gpa, .{ .ddicts = &set });
    defer stream.deinit();
    var out: [256]u8 = undefined;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var i: usize = 0;
    while (i < kats.small_frame.len) : (i += 1) {
        var in: zstd.InBuffer = .{ .src = kats.small_frame[0 .. i + 1], .pos = i };
        while (in.pos < in.src.len) {
            var ob: zstd.OutBuffer = .{ .dst = &out, .pos = 0 };
            _ = try stream.decompressStream(&ob, &in);
            try got.appendSlice(gpa, out[0..ob.pos]);
        }
    }
    // same "last DDict wins" result as the one-shot case above
    try std.testing.expectEqualStrings(
        ", \"gamma\",:\"alpha\", \"delta\",:\"alpha\",\"fields\":\"beta\", \":\"alpha\",\"fields\":delta\", \"\"beta\", \":\"alph]}",
        got.items,
    );
}

test "one-shot ddicts: concatenated frames naming different dictionary IDs refuse like libzstd's own one-shot API" {
    // frame_full_l3 needs full_dict; frame2_full_l3 (appended) needs
    // full_dict2. One-shot with both in `ddicts` fixes ONE dictionary
    // (the last entry, full_dict here) for the whole call, so the SECOND
    // frame gets the wrong content applied -- confirmed against libzstd
    // itself (tools/zdec.c, five adversarial cases, SPEC.md Decoder):
    // it never silently returns wrong output for this, only ever a clean
    // CorruptionDetected or (when the wrong dictionary's content happens
    // not to be needed) the correct result, so this port matches exactly.
    var d1 = try zstd.DDict.init(gpa, kats.full_dict, .auto);
    defer d1.deinit(gpa);
    var d2 = try zstd.DDict.init(gpa, kats.full_dict2, .auto);
    defer d2.deinit(gpa);
    const set = [_]*const zstd.DDict{ &d2, &d1 }; // last = d1 (full_dict)
    var out: [2048]u8 = undefined; // generous: >= decompressBound(concat_full_l3_then_frame2)
    try std.testing.expectError(error.CorruptionDetected, decodeOpts(&out, kats.concat_full_l3_then_frame2, .{ .ddicts = &set }));
}

test "getDictId / getFrameDictId" {
    try std.testing.expect(zstd.getDictId(kats.full_dict) != 0);
    try std.testing.expectEqual(@as(u32, 0), zstd.getDictId(kats.raw_dict));
    try std.testing.expectEqual(zstd.getDictId(kats.full_dict), zstd.getFrameDictId(kats.frame_full_l3));
    try std.testing.expectEqual(@as(u32, 0), zstd.getFrameDictId(kats.frame_raw_l3));
}
