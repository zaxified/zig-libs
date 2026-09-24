// SPDX-License-Identifier: MIT
//! libzstd's advanced parameters (`zstd.Advanced`) against libzstd 1.5.7.
//!
//! Every `corpus.param_cases` entry is compressed one-shot with its
//! parameters; the frame must have the length and SHA-256 libzstd's
//! `ZSTD_compress2` gave with the same parameters set
//! (`testdata/param_goldens.zig`, from `tools/gen-goldens.sh` through
//! `tools/zref.c`), and decode back. Both sides read the same `name=value`
//! list, by libzstd's parameter names; `applyParam` is this side's reader,
//! shared with the streaming test's schedules.

const std = @import("std");
const zstd = @import("root.zig");
const params = @import("params.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/param_goldens.zig");

/// Apply one `name=value` token (libzstd's parameter name; switches 0 auto,
/// 1 enable, 2 disable) to `adv`, or `srcSizeHint` to `hint`. False when
/// the token is not a parameter.
pub fn applyParam(adv: *zstd.Advanced, hint: *?u32, tok: []const u8) !bool {
    const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return false;
    const name = tok[0..eq];
    const v = try std.fmt.parseInt(u32, tok[eq + 1 ..], 10);
    const Eq = struct {
        fn f(a: []const u8, b: []const u8) bool {
            return std.mem.eql(u8, a, b);
        }
    };
    const switches = [_]zstd.Switch{ .auto, .enable, .disable };
    if (Eq.f(name, "windowLog")) {
        adv.window_log = v;
    } else if (Eq.f(name, "hashLog")) {
        adv.hash_log = v;
    } else if (Eq.f(name, "chainLog")) {
        adv.chain_log = v;
    } else if (Eq.f(name, "searchLog")) {
        adv.search_log = v;
    } else if (Eq.f(name, "minMatch")) {
        adv.min_match = v;
    } else if (Eq.f(name, "targetLength")) {
        adv.target_length = v;
    } else if (Eq.f(name, "strategy")) {
        adv.strategy = std.enums.fromInt(zstd.Strategy, v) orelse return error.BadParam;
    } else if (Eq.f(name, "contentSizeFlag")) {
        adv.content_size = v != 0;
    } else if (Eq.f(name, "format")) {
        adv.format = if (v == 1) .magicless else .zstd1;
    } else if (Eq.f(name, "literalCompressionMode")) {
        adv.literal_compression = switches[v];
    } else if (Eq.f(name, "useRowMatchFinder")) {
        adv.row_match_finder = switches[v];
    } else if (Eq.f(name, "splitAfterSequences")) {
        adv.split_after_sequences = switches[v];
    } else if (Eq.f(name, "blockSplitterLevel")) {
        adv.block_splitter_level = v;
    } else if (Eq.f(name, "maxBlockSize")) {
        adv.max_block_size = v;
    } else if (Eq.f(name, "enableLongDistanceMatching")) {
        adv.long_distance_matching = switches[v];
    } else if (Eq.f(name, "ldmHashLog")) {
        adv.ldm_hash_log = v;
    } else if (Eq.f(name, "ldmMinMatch")) {
        adv.ldm_min_match = v;
    } else if (Eq.f(name, "ldmBucketSizeLog")) {
        adv.ldm_bucket_size_log = v;
    } else if (Eq.f(name, "ldmHashRateLog")) {
        adv.ldm_hash_rate_log = v;
    } else if (Eq.f(name, "targetCBlockSize")) {
        adv.target_c_block_size = v;
    } else if (Eq.f(name, "srcSizeHint")) {
        hint.* = v;
    } else if (Eq.f(name, "dictIDFlag")) {
        adv.dict_id_flag = v != 0;
    } else if (Eq.f(name, "forceAttachDict")) {
        adv.force_attach_dict = std.enums.fromInt(zstd.DictAttachPref, v) orelse return error.BadParam;
    } else if (Eq.f(name, "deterministicRefPrefix")) {
        adv.deterministic_ref_prefix = v != 0;
    } else if (Eq.f(name, "forceMaxWindow")) {
        adv.force_max_window = v != 0;
    } else return error.BadParam;
    return true;
}

pub fn parse(list: []const u8) !zstd.Advanced {
    var adv: zstd.Advanced = .{};
    var hint: ?u32 = null;
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |tok| if (!try applyParam(&adv, &hint, tok)) return error.BadParam;
    return adv;
}

fn findCase(name: []const u8) corpus.Case {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

fn find(pc: corpus.ParamCase, level: i32, checksum: bool) ?goldens.Golden {
    for (goldens.rows) |g| {
        if (g.level == level and g.checksum == checksum and std.mem.eql(u8, g.case, pc.case) and std.mem.eql(u8, g.params, pc.params)) return g;
    }
    return null;
}

test "every parameter case has a golden row, and nothing else does" {
    var n: usize = 0;
    for (corpus.param_cases) |pc| for (pc.levels) |level| for (pc.checksums) |ck| {
        n += 1;
        if (find(pc, level, ck) == null) {
            std.debug.print("no golden row for {s} {s} level {d} checksum {}\n", .{ pc.case, pc.params, level, ck });
            return error.MissingGolden;
        }
    };
    try std.testing.expectEqual(n, goldens.rows.len);
}

test "output with advanced parameters is byte-identical to libzstd 1.5.7, and decodes back" {
    const gpa = std.testing.allocator;
    var mismatches: usize = 0;
    // one context for every frame (see golden_test.zig)
    var ctx: zstd.Compressor = .init(gpa);
    defer ctx.deinit();
    for (corpus.param_cases) |pc| {
        const case = findCase(pc.case);
        const src = try gpa.alloc(u8, case.len);
        defer gpa.free(src);
        corpus.generate(case, src);
        const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
        defer gpa.free(dst);
        const back = try gpa.alloc(u8, src.len + 1);
        defer gpa.free(back);
        const adv = try parse(pc.params);
        var dec = try zstd.Decompressor.init(gpa, .{ .format = adv.format });
        defer dec.deinit();
        for (pc.levels) |level| for (pc.checksums) |ck| {
            const g = find(pc, level, ck).?;
            const n = try ctx.compress(dst, src, .{ .level = level, .checksum = ck, .advanced = adv });
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(dst[0..n], &digest, .{});
            const hex = std.fmt.bytesToHex(digest, .lower);
            if (n != g.len or !std.mem.eql(u8, &hex, g.sha256)) {
                std.debug.print("MISMATCH {s} {s} level {d} checksum {}: len {d} (libzstd {d})\n", .{ pc.case, pc.params, level, ck, n, g.len });
                mismatches += 1;
            }
            const got = dec.decompress(back, dst[0..n]) catch |e| {
                std.debug.print("DECODE ERROR {s} {s} level {d}: {s}\n", .{ pc.case, pc.params, level, @errorName(e) });
                mismatches += 1;
                continue;
            };
            if (got != src.len or !std.mem.eql(u8, back[0..got], src)) {
                std.debug.print("DECODE MISMATCH {s} {s} level {d}\n", .{ pc.case, pc.params, level });
                mismatches += 1;
            }
        };
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

test "long-distance matching at a fresh window's first indices" {
    // The reused context above indexes each frame past the last, so the
    // window's first indices (2..) are reached only on a fresh one: there
    // `fast` and `dfast` run on stretches ending below index 8 (see
    // `saturated_limit` in match.zig).
    const gpa = std.testing.allocator;
    for (corpus.param_cases) |pc| {
        if (!std.mem.eql(u8, pc.case, "zeros-300000") and !std.mem.eql(u8, pc.case, "mix-70000-0")) continue;
        const case = findCase(pc.case);
        const src = try gpa.alloc(u8, case.len);
        defer gpa.free(src);
        corpus.generate(case, src);
        const adv = try parse(pc.params);
        for (pc.levels) |level| {
            const out = try zstd.compressAlloc(gpa, src, .{ .level = level, .advanced = adv });
            defer gpa.free(out);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(out, &digest, .{});
            const g = find(pc, level, false).?;
            try std.testing.expectEqual(g.len, out.len);
            try std.testing.expectEqualStrings(g.sha256, &std.fmt.bytesToHex(digest, .lower));
        }
    }
}

test "parameters outside libzstd's bounds are refused, its edges accepted" {
    const gpa = std.testing.allocator;
    var buf: [128]u8 = undefined; // compressBound(3) is 66
    // ZSTD_cParam_getBounds, 64-bit
    const edges = [_]struct { ok: []const zstd.Advanced, bad: []const zstd.Advanced }{
        .{ .ok = &.{ .{ .window_log = 10 }, .{ .window_log = 31 } }, .bad = &.{ .{ .window_log = 9 }, .{ .window_log = 32 } } },
        .{ .ok = &.{ .{ .hash_log = 6 }, .{ .hash_log = 30 } }, .bad = &.{ .{ .hash_log = 5 }, .{ .hash_log = 31 } } },
        .{ .ok = &.{ .{ .chain_log = 6 }, .{ .chain_log = 30 } }, .bad = &.{ .{ .chain_log = 5 }, .{ .chain_log = 31 } } },
        .{ .ok = &.{ .{ .search_log = 1 }, .{ .search_log = 30 } }, .bad = &.{ .{ .search_log = 0 }, .{ .search_log = 31 } } },
        .{ .ok = &.{ .{ .min_match = 3 }, .{ .min_match = 7 } }, .bad = &.{ .{ .min_match = 2 }, .{ .min_match = 8 } } },
        .{ .ok = &.{ .{ .target_length = 0 }, .{ .target_length = 131072 } }, .bad = &.{.{ .target_length = 131073 }} },
        .{ .ok = &.{.{ .block_splitter_level = 6 }}, .bad = &.{.{ .block_splitter_level = 7 }} },
        .{ .ok = &.{ .{ .max_block_size = 1024 }, .{ .max_block_size = 131072 } }, .bad = &.{ .{ .max_block_size = 1023 }, .{ .max_block_size = 131073 } } },
        // the LDM parameters: 0 is "not set", as in libzstd
        .{ .ok = &.{ .{ .ldm_hash_log = 0 }, .{ .ldm_hash_log = 6 }, .{ .ldm_hash_log = 30 } }, .bad = &.{ .{ .ldm_hash_log = 5 }, .{ .ldm_hash_log = 31 } } },
        .{ .ok = &.{ .{ .ldm_min_match = 0 }, .{ .ldm_min_match = 4 }, .{ .ldm_min_match = 4096 } }, .bad = &.{ .{ .ldm_min_match = 3 }, .{ .ldm_min_match = 4097 } } },
        .{ .ok = &.{ .{ .ldm_bucket_size_log = 0 }, .{ .ldm_bucket_size_log = 1 }, .{ .ldm_bucket_size_log = 8 } }, .bad = &.{.{ .ldm_bucket_size_log = 9 }} },
        .{ .ok = &.{ .{ .ldm_hash_rate_log = 0 }, .{ .ldm_hash_rate_log = 25 } }, .bad = &.{.{ .ldm_hash_rate_log = 26 }} },
        // below 1340 counts as 1340, as in libzstd
        .{ .ok = &.{ .{ .target_c_block_size = 0 }, .{ .target_c_block_size = 1 }, .{ .target_c_block_size = 131072 } }, .bad = &.{.{ .target_c_block_size = 131073 }} },
    };
    for (edges) |e| {
        for (e.ok) |adv| _ = try zstd.compress(gpa, &buf, "abc", .{ .advanced = adv });
        for (e.bad) |adv| {
            try std.testing.expectError(error.ParameterOutOfBound, zstd.compress(gpa, &buf, "abc", .{ .advanced = adv }));
            try std.testing.expectError(error.ParameterOutOfBound, zstd.Stream.init(gpa, .{ .advanced = adv }));
            var sink: [16]u8 = undefined;
            var w: std.Io.Writer = .fixed(&sink);
            try std.testing.expectError(error.ParameterOutOfBound, zstd.FrameWriter.init(gpa, &w, &buf, .{ .advanced = adv }));
        }
    }
    try std.testing.expectError(error.ParameterOutOfBound, zstd.Stream.init(gpa, .{ .src_size_hint = 0 }));
    try std.testing.expectError(error.ParameterOutOfBound, zstd.Stream.init(gpa, .{ .src_size_hint = 1 << 31 }));
    var s = try zstd.Stream.init(gpa, .{ .src_size_hint = (1 << 31) - 1 });
    s.deinit();
}

test "switching the row match finder off lifts its cap on the hash log" {
    // unknown size: nothing else shrinks the hash log. Rows of 16 hash
    // hashLog - 4 + 8 bits into 32, so the cap is 28.
    const unknown = params.unknown_size;
    try std.testing.expectEqual(@as(u32, 28), params.getOverridden(5, unknown, .{ .hash_log = 30, .search_log = 4 }).hash_log);
    try std.testing.expectEqual(@as(u32, 28), params.getOverridden(5, unknown, .{ .hash_log = 30, .search_log = 4, .row_match_finder = .enable }).hash_log);
    try std.testing.expectEqual(@as(u32, 30), params.getOverridden(5, unknown, .{ .hash_log = 30, .search_log = 4, .row_match_finder = .disable }).hash_log);
    // 64-entry rows: 30
    try std.testing.expectEqual(@as(u32, 30), params.getOverridden(5, unknown, .{ .hash_log = 30, .search_log = 6 }).hash_log);
    // strategies without rows are never capped
    try std.testing.expectEqual(@as(u32, 30), params.getOverridden(13, unknown, .{ .hash_log = 30, .search_log = 4 }).hash_log);
}

test "a magicless frame is the frame without its magic number, and needs a decoder told so" {
    const gpa = std.testing.allocator;
    const src = "magicless, magicless, magicless frames" ** 20;
    for ([_]bool{ false, true }) |ck| {
        const plain = try zstd.compressAlloc(gpa, src, .{ .checksum = ck });
        defer gpa.free(plain);
        const ml = try zstd.compressAlloc(gpa, src, .{ .checksum = ck, .advanced = .{ .format = .magicless } });
        defer gpa.free(ml);
        try std.testing.expectEqualSlices(u8, plain[4..], ml);

        const h = (try zstd.getFrameHeaderAdvanced(ml, .magicless)).header;
        try std.testing.expectEqual(@as(?u64, src.len), h.content_size);
        try std.testing.expectEqual(@as(u32, @intCast(ml.len)), @as(u32, @intCast(try @import("decompress.zig").findFrameCompressedSizeAdvanced(ml, .magicless))));
        var out: [src.len]u8 = undefined;
        var d = try zstd.Decompressor.init(gpa, .{ .format = .magicless });
        defer d.deinit();
        try std.testing.expectEqual(src.len, try d.decompress(&out, ml));
        try std.testing.expectEqualSlices(u8, src, &out);
        // two in a row
        const two = try std.mem.concat(gpa, u8, &.{ ml, ml });
        defer gpa.free(two);
        var out2: [2 * src.len]u8 = undefined;
        try std.testing.expectEqual(2 * src.len, try d.decompress(&out2, two));
        // a plain decoder does not know it; a magicless one reads the magic
        // number as a header and fails
        var dp = try zstd.Decompressor.init(gpa, .{});
        defer dp.deinit();
        try std.testing.expectError(error.PrefixUnknown, dp.decompress(&out, ml));
        try std.testing.expect(std.meta.isError(d.decompress(&out, plain)));

        // in pieces, one byte of input at a time
        var ds = try zstd.DecompressStream.init(gpa, .{ .format = .magicless });
        defer ds.deinit();
        var got: [src.len]u8 = undefined;
        var o: zstd.OutBuffer = .{ .dst = &got };
        var i: usize = 0;
        var left: usize = 1;
        while (i < ml.len) : (i += 1) {
            var in: zstd.InBuffer = .{ .src = ml[i..][0..1] };
            left = try ds.decompressStream(&o, &in);
            try std.testing.expectEqual(@as(usize, 1), in.pos);
            // after the descriptor byte, libzstd's hint: the rest of the
            // 3-byte header (a 2-byte size, single segment; at least
            // ZSTD_FRAMEHEADERSIZE_MIN of the format, 2) plus a block header
            if (i == 0) try std.testing.expectEqual(@as(usize, (3 - 1) + 3), left);
        }
        try std.testing.expectEqual(@as(usize, 0), left);
        try std.testing.expectEqualSlices(u8, src, o.dst[0..o.pos]);
    }
}

test "without the content size flag the header records no size" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "", "x", "abcabcabcabc" ** 100 }) |src| {
        const z = try zstd.compressAlloc(gpa, src, .{ .advanced = .{ .content_size = false } });
        defer gpa.free(z);
        try std.testing.expectEqual(@as(?u64, null), try zstd.getFrameContentSize(z));
        const back = try zstd.decompressAlloc(gpa, z, 1 << 20);
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, src, back);
    }
}

test "FrameWriter frames carry the advanced parameters" {
    const gpa = std.testing.allocator;
    const src = "frame writer, frame writer, frame writer" ** 30;
    const adv: zstd.Advanced = .{ .format = .magicless, .content_size = false, .strategy = .btopt };
    const one = try zstd.compressAlloc(gpa, src, .{ .level = 3, .advanced = adv });
    defer gpa.free(one);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [src.len]u8 = undefined;
    var fw = try zstd.FrameWriter.init(gpa, &out.writer, &buf, .{ .level = 3, .advanced = adv });
    defer fw.deinit();
    try fw.writer.writeAll(src);
    try fw.finish();
    try std.testing.expectEqualSlices(u8, one, out.written());
}

test "a magicless frame that starts like a skippable magic number is still a frame" {
    // A magicless header whose first four bytes read 0x184D2A5x: the
    // descriptor 0x50 (a 2-byte content size, the unused bit 4 set, no
    // single segment), the window byte 0x2A, the size 0x184D + 256 = 6477;
    // then one raw last block of that size. Only a zstd1 decoder may take
    // those bytes for a skippable frame.
    const gpa = std.testing.allocator;
    const size = 0x184D + 256;
    var frame: [4 + 3 + size]u8 = undefined;
    @memcpy(frame[0..4], &[_]u8{ 0x50, 0x2A, 0x4D, 0x18 });
    const bh: u32 = 1 | (0 << 1) | (size << 3); // last, raw
    frame[4] = @truncate(bh);
    frame[5] = @truncate(bh >> 8);
    frame[6] = @truncate(bh >> 16);
    for (frame[7..], 0..) |*b, i| b.* = @truncate(i *% 31);
    const content = frame[7..];

    var out: [size]u8 = undefined;
    // one-shot
    var d = try zstd.Decompressor.init(gpa, .{ .format = .magicless });
    defer d.deinit();
    try std.testing.expectEqual(@as(usize, size), try d.decompress(&out, &frame));
    try std.testing.expectEqualSlices(u8, content, &out);
    try std.testing.expectEqual(@as(usize, frame.len), try @import("decompress.zig").findFrameCompressedSizeAdvanced(&frame, .magicless));

    // piece by piece (`ZSTD_decompressContinue`)
    d.begin();
    var ip: usize = 0;
    var op: usize = 0;
    while (d.nextSrcSizeToDecompress() != 0) {
        const n = d.nextSrcSizeWithInputSize(frame.len - ip);
        op += try d.decompressContinue(out[op..], frame[ip..][0..n]);
        ip += n;
    }
    try std.testing.expectEqual(frame.len, ip);
    try std.testing.expectEqualSlices(u8, content, out[0..op]);

    // streaming: one byte at a time, and whole (the single-pass shortcut)
    for ([_]usize{ 1, frame.len }) |piece| {
        var ds = try zstd.DecompressStream.init(gpa, .{ .format = .magicless });
        defer ds.deinit();
        var o: zstd.OutBuffer = .{ .dst = &out };
        var i: usize = 0;
        var left: usize = 1;
        while (i < frame.len) : (i += piece) {
            var in: zstd.InBuffer = .{ .src = frame[i..][0..@min(piece, frame.len - i)] };
            left = try ds.decompressStream(&o, &in);
        }
        try std.testing.expectEqual(@as(usize, 0), left);
        try std.testing.expectEqualSlices(u8, content, o.dst[0..o.pos]);
    }
}
