// SPDX-License-Identifier: MIT
//! Buffer-less compression (`Compressor.begin`, `compressContinue`,
//! `compressEnd`) and `Compressor.copyFrom` (`ZSTD_copyCCtx`) against
//! libzstd 1.5.7.
//!
//! Every `testdata/copy_goldens.zig` row is a call plan of `tools/zcopy.c`:
//! a context begun one of four ways, copied twice into one reused context
//! (each copy compressing the input in the same pieces), then the original
//! compressing it itself. The three frames (or the errors) must be
//! libzstd's. The rows cover the four `begin`s, a dictionary loaded, copied
//! from a `CDict`, attached, and reloaded, the strategies from `fast` to
//! `btultra2` and long-distance matching, pledged sizes (known, unknown, 0,
//! wrong), frame parameters, and too little output room; an input right
//! behind its dictionary in memory (the window goes on from it); and, mode
//! `F`, a context left begun by a one-shot frame that failed for room on its
//! header -- the one way a copy's original carries parameters no `begin`
//! sets (a block size, explicit switches, long-distance matching's own
//! parameters), which the copy keeps. Where libzstd's
//! copy leaves something behind (the row match finder's tags, an attached
//! `CDict`, the LDM table, the frame parameters), its frames differ from the
//! original's, and so must this port's.

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/copy_goldens.zig");
const param_test = @import("param_test.zig");

const trained_files = .{
    .{ "zd-words", @embedFile("testdata/zd-words.zdict") },
    .{ "zd-csv", @embedFile("testdata/zd-csv.zdict") },
};

fn trained(name: []const u8) []const u8 {
    inline for (trained_files) |t| if (std.mem.eql(u8, t[0], name)) return t[1];
    unreachable;
}

fn input(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) {
        const buf = try gpa.alloc(u8, c.len);
        corpus.generate(c, buf);
        return buf;
    };
    unreachable;
}

/// The frame `c` makes of `src` in `chunks` pieces into `dst` (the room
/// left of it at each call), or the error.
fn run(c: *zstd.Compressor, dst: []u8, src: []const u8, chunks: u32) zstd.BufferlessError![]const u8 {
    var op: usize = 0;
    var ip: usize = 0;
    for (0..chunks) |i| {
        const last = i + 1 == chunks;
        const piece = if (last) src.len - ip else src.len / chunks;
        op += if (last) try c.compressEnd(dst[op..], src[ip..][0..piece]) else try c.compressContinue(dst[op..], src[ip..][0..piece]);
        ip += piece;
    }
    return dst[0..op];
}

fn expectFrame(want: goldens.Frame, got: zstd.BufferlessError![]const u8, what: []const u8, row: usize) !void {
    const z = got catch |e| {
        if (std.mem.eql(u8, want.err, @errorName(e))) return;
        std.debug.print("row {d} {s}: {t}, libzstd {s}\n", .{ row, what, e, if (want.err.len != 0) want.err else "a frame" });
        return error.TestUnexpectedResult;
    };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(z, &digest, .{});
    if (want.err.len == 0 and z.len == want.len and std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), want.sha256)) return;
    std.debug.print("row {d} {s}: {d} bytes, libzstd {d}{s}{s}\n", .{ row, what, z.len, want.len, if (want.err.len != 0) " error " else "", want.err });
    return error.TestUnexpectedResult;
}

fn begin(c: *zstd.Compressor, r: goldens.Row, src: []const u8, dict: []const u8, cdict: ?*const zstd.CDict) !void {
    const fp: zstd.FrameParams = .{ .content_size = r.flags & 4 == 0, .checksum = r.flags & 1 != 0, .dict_id = r.flags & 2 == 0 };
    switch (r.mode) {
        'L' => try c.begin(.{ .level = .{ .level = r.level, .dict = dict } }),
        'A' => {
            var cp = zstd.getCParams(r.level, r.pledged, dict.len);
            if (r.cparams) |v| cp = .{ .window_log = v[0], .chain_log = v[1], .hash_log = v[2], .search_log = v[3], .min_match = v[4], .target_length = v[5], .strategy = @enumFromInt(v[6]) };
            try c.begin(.{ .advanced = .{ .cparams = cp, .frame = fp, .dict = dict, .pledged_size = r.pledged } });
        },
        'C' => try c.begin(.{ .cdict = .{ .cdict = cdict.?, .frame = fp, .pledged_size = r.pledged } }),
        'c' => try c.begin(.{ .cdict = .{ .cdict = cdict.? } }),
        'F' => {
            // zcopy: ZSTD_compress2 into 17 bytes, refused on the header
            var adv: zstd.Advanced = .{};
            var hint: ?u32 = null;
            var it = std.mem.tokenizeScalar(u8, r.params.?, ',');
            while (it.next()) |tok| try std.testing.expect(try param_test.applyParam(&adv, &hint, tok));
            var tiny: [17]u8 = undefined;
            try std.testing.expectError(error.DstSizeTooSmall, c.compress(&tiny, src, .{ .level = r.level, .advanced = adv }));
        },
        else => unreachable,
    }
}

test "buffer-less frames and their copies are libzstd's" {
    const gpa = std.testing.allocator;
    for (goldens.rows, 0..) |r, i| {
        // New contexts, as zcopy's: a copy keeps the tag table its context
        // had (libzstd's init-once space), so what the copy's context held
        // before shows (see the next test).
        var copy: zstd.Compressor = .init(gpa);
        defer copy.deinit();
        var orig: zstd.Compressor = .init(gpa);
        defer orig.deinit();
        const src_only = try input(gpa, r.case);
        defer gpa.free(src_only);
        const dict_buf = try gpa.alloc(u8, if (r.dict) |name| corpus.dictLen(corpus.findDict(name), &trained) else 0);
        defer gpa.free(dict_buf);
        const dict_only = if (r.dict) |name| dict_buf[0..corpus.buildDict(corpus.findDict(name), &trained, dict_buf)] else dict_buf;
        // flag 8: the input right behind the dictionary, in one buffer
        const joined = try gpa.alloc(u8, if (r.flags & 8 != 0) dict_only.len + src_only.len else 0);
        defer gpa.free(joined);
        if (r.flags & 8 != 0) {
            @memcpy(joined[0..dict_only.len], dict_only);
            @memcpy(joined[dict_only.len..], src_only);
        }
        const dict = if (r.flags & 8 != 0) joined[0..dict_only.len] else dict_only;
        const src = if (r.flags & 8 != 0) joined[dict_only.len..] else src_only;
        var cdict: ?zstd.CDict = null;
        defer if (cdict) |*c| c.deinit();
        if (r.mode == 'C' or r.mode == 'c') cdict = try zstd.CDict.init(gpa, dict, r.level);
        const dst = try gpa.alloc(u8, r.capacity orelse zstd.compressBound(src.len) + 18);
        defer gpa.free(dst);

        try begin(&orig, r, src, dict, if (cdict) |*c| c else null);
        for ([_]goldens.Frame{ r.copy1, r.copy2 }, [_][]const u8{ "copy1", "copy2" }) |want, what| {
            try copy.copyFrom(&orig, r.copy_pledged);
            try expectFrame(want, run(&copy, dst, src, r.chunks), what, i);
        }
        try expectFrame(r.orig, run(&orig, dst, src, r.chunks), "orig", i);
        if (copy.copyFrom(&orig, r.copy_pledged)) {
            try std.testing.expectEqualStrings(r.copy_after, "ok");
        } else |e| try std.testing.expectEqualStrings(r.copy_after, @errorName(e));
    }
}

test "the buffer-less calls need a begin, and a copy a context just begun" {
    const gpa = std.testing.allocator;
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    var d: zstd.Compressor = .init(gpa);
    defer d.deinit();
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.StageWrong, c.compressContinue(&buf, "abc"));
    try std.testing.expectError(error.StageWrong, c.compressEnd(&buf, "abc"));
    try std.testing.expectError(error.StageWrong, d.copyFrom(&c, null));
    try c.begin(.{ .level = .{} });
    try d.copyFrom(&c, null);
    _ = try c.compressContinue(&buf, "abc");
    try std.testing.expectError(error.StageWrong, d.copyFrom(&c, null));
    _ = try c.compressEnd(&buf, "def");
    try std.testing.expectError(error.StageWrong, c.compressContinue(&buf, "abc"));
    try std.testing.expectError(error.StageWrong, d.copyFrom(&c, null));
    // after a one-shot frame, too
    _ = try c.compress(&buf, "abc", .{});
    try std.testing.expectError(error.StageWrong, d.copyFrom(&c, null));
    // the copy made before is still begun
    const n = try d.compressEnd(&buf, "abcabcabc");
    var back: [16]u8 = undefined;
    try std.testing.expectEqualStrings("abcabcabc", back[0..try zstd.decompress(gpa, &back, buf[0..n])]);
    // a level above 22 is refused, as by `compress`
    try std.testing.expectError(error.LevelUnsupported, c.begin(.{ .level = .{ .level = 23 } }));
    // explicit parameters out of libzstd's bounds
    var cp = zstd.getCParams(3, null, 0);
    cp.window_log = 9;
    try std.testing.expectError(error.ParameterOutOfBound, c.begin(.{ .advanced = .{ .cparams = cp } }));
}

test "a pledged size is held to exactly" {
    const gpa = std.testing.allocator;
    const src = try input(gpa, "words-16384");
    defer gpa.free(src);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len) + 18);
    defer gpa.free(dst);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const cp = zstd.getCParams(3, src.len, 0);
    // more than pledged, in a continue
    try c.begin(.{ .advanced = .{ .cparams = cp, .pledged_size = 1000 } });
    try std.testing.expectError(error.SrcSizeWrong, c.compressContinue(dst, src[0..1001]));
    // less at the end
    try c.begin(.{ .advanced = .{ .cparams = cp, .pledged_size = src.len } });
    _ = try c.compressContinue(dst, src[0..1000]);
    try std.testing.expectError(error.SrcSizeWrong, c.compressEnd(dst, src[1000 .. src.len - 1]));
    // exactly: the frame records the size
    try c.begin(.{ .advanced = .{ .cparams = cp, .pledged_size = src.len } });
    const a = try c.compressContinue(dst, src[0..1000]);
    const b = try c.compressEnd(dst[a..], src[1000..]);
    try std.testing.expectEqual(@as(?u64, src.len), try zstd.getFrameContentSize(dst[0 .. a + b]));
    // a copy pledged 0 is of unknown size, as in libzstd
    var d: zstd.Compressor = .init(gpa);
    defer d.deinit();
    try c.begin(.{ .advanced = .{ .cparams = cp, .pledged_size = src.len } });
    try d.copyFrom(&c, 0);
    const n = try d.compressEnd(dst, src);
    try std.testing.expectEqual(@as(?u64, null), try zstd.getFrameContentSize(dst[0..n]));
}

test "a copy is independent of its original, and without tags of what it held before" {
    // The copy owns its tables: the original compressing first, or the copy
    // having served another dictionary, changes nothing. Level 3 (`dfast`,
    // no row match finder, whose tags are not copied but kept) with a
    // dictionary loaded: the copy's frame is the original's.
    const gpa = std.testing.allocator;
    const src = try input(gpa, "csv-131073");
    defer gpa.free(src);
    const dict = trained("zd-csv");
    const cap = zstd.compressBound(src.len) + 18;
    const want = try gpa.alloc(u8, cap);
    defer gpa.free(want);
    const got = try gpa.alloc(u8, cap);
    defer gpa.free(got);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    var d: zstd.Compressor = .init(gpa);
    defer d.deinit();
    const cp = zstd.getCParams(3, src.len, dict.len);
    const how: zstd.Begin = .{ .advanced = .{ .cparams = cp, .dict = dict, .pledged_size = src.len } };
    // the copy serves another dictionary and level first
    try c.begin(.{ .level = .{ .level = 12, .dict = trained("zd-words") } });
    try d.copyFrom(&c, null);
    _ = try run(&d, got, src[0..5000], 1);
    try c.begin(how);
    try d.copyFrom(&c, src.len);
    const w = try run(&c, want, src, 2);
    const g = try run(&d, got, src, 2);
    try std.testing.expectEqualSlices(u8, w, g);
}

test "a copy into a static workspace that is too small fails cleanly" {
    const gpa = std.testing.allocator;
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    try c.begin(.{ .level = .{ .level = 3, .dict = trained("zd-words") } });
    const need = c.workspaceSize();
    const ws = try gpa.alignedAlloc(u8, .fromByteUnits(zstd.workspace_alignment), need);
    defer gpa.free(ws);
    var small: zstd.Compressor = .initStatic(ws[0 .. need - zstd.workspace_alignment]);
    defer small.deinit();
    try std.testing.expectError(error.OutOfMemory, small.copyFrom(&c, null));
    var fits: zstd.Compressor = .initStatic(ws);
    defer fits.deinit();
    try fits.copyFrom(&c, null);
    var buf: [64]u8 = undefined;
    const n = try fits.compressEnd(&buf, "hello hello");
    var dd = try zstd.DDict.init(gpa, trained("zd-words"), .auto);
    defer dd.deinit(gpa);
    var dec = try zstd.Decompressor.init(gpa, .{ .ddict = &dd });
    defer dec.deinit();
    var back: [16]u8 = undefined;
    try std.testing.expectEqualStrings("hello hello", back[0..try dec.decompress(&back, buf[0..n])]);
}
