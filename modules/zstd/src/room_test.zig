// SPDX-License-Identifier: MIT
//! One-shot compression into less room than `compressBound` (Z29) against
//! libzstd 1.5.7.
//!
//! For every `corpus.room_cases` entry the recipe bisected the least
//! destination capacity libzstd's one-shot call (`ZSTD_compress2`, with
//! workers too, `ZSTD_compress_usingDict`, `ZSTD_compress_usingCDict_advanced`)
//! succeeds in, checked that one byte less is `dstSize_tooSmall`, and
//! recorded the frame it writes there (`testdata/room_goldens.zig`, from
//! `tools/gen-goldens.sh` through `tools/zref.c`'s capacity argument). The
//! same call here, into a `dst` of exactly that length, must give that
//! frame, and one byte less `error.DstSizeTooSmall`; the frame decodes back.

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/room_goldens.zig");
const param_test = @import("param_test.zig");

const trained_files = .{
    .{ "zd-words", @embedFile("testdata/zd-words.zdict") },
    .{ "zd-csv", @embedFile("testdata/zd-csv.zdict") },
};

fn trained(name: []const u8) []const u8 {
    inline for (trained_files) |t| if (std.mem.eql(u8, t[0], name)) return t[1];
    unreachable;
}

fn find(rc: corpus.RoomCase) ?goldens.Golden {
    for (goldens.rows) |g| if (std.mem.eql(u8, g.case, rc.name)) return g;
    return null;
}

fn findCase(name: []const u8) corpus.Case {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

test "every room case has a golden row, and nothing else does" {
    for (corpus.room_cases) |rc| if (find(rc) == null) {
        std.debug.print("no golden row for {s}\n", .{rc.name});
        return error.MissingGolden;
    };
    try std.testing.expectEqual(corpus.room_cases.len, goldens.rows.len);
}

/// `rc` one-shot into `dst`, as the recipe's `zref` call makes it.
fn compressCase(gpa: std.mem.Allocator, c: *zstd.Compressor, rc: corpus.RoomCase, dict: []const u8, src: []const u8, dst: []u8) zstd.Error!usize {
    const adv = if (std.mem.eql(u8, rc.params, "-")) zstd.Advanced{} else param_test.parse(rc.params) catch unreachable;
    var opts: zstd.Options = .{ .level = rc.level, .checksum = rc.checksum, .advanced = adv };
    if (rc.dict == null) return c.compress(dst, src, opts);
    switch (rc.path) {
        .load => opts.dictionary = .{ .raw = .{ .bytes = dict } },
        .prefix => opts.dictionary = .{ .prefix = .{ .bytes = dict } },
        .usingdict => return c.compressUsingDict(dst, src, dict, rc.level),
        .cdict, .usingcdict => {
            var cd = try zstd.CDict.init(gpa, dict, rc.level);
            defer cd.deinit();
            if (rc.path == .usingcdict) return c.compressUsingCDict(dst, src, &cd, .{ .content_size = adv.content_size, .checksum = rc.checksum, .dict_id = adv.dict_id_flag });
            opts.dictionary = .{ .cdict = &cd };
            return c.compress(dst, src, opts);
        },
        else => unreachable,
    }
    return c.compress(dst, src, opts);
}

test "the least room libzstd succeeds in gives its frame here, one byte less DstSizeTooSmall" {
    const gpa = std.testing.allocator;
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    var fails: usize = 0;
    var other_frames: usize = 0;
    for (corpus.room_cases) |rc| {
        const g = find(rc).?;
        const case = rc.gen orelse findCase(rc.input);
        const src = try gpa.alloc(u8, case.len);
        defer gpa.free(src);
        corpus.generate(case, src);
        const dict_buf = try gpa.alloc(u8, if (rc.dict) |name| corpus.dictLen(corpus.findDict(name), &trained) else 0);
        defer gpa.free(dict_buf);
        const dict = if (rc.dict) |name| dict_buf[0..corpus.buildDict(corpus.findDict(name), &trained, dict_buf)] else dict_buf;
        // exactly the room: a heap block of that length, so that a write
        // past it would not go unnoticed by the allocator's checks
        const dst = try gpa.alloc(u8, g.room);
        defer gpa.free(dst);
        const n = compressCase(gpa, &c, rc, dict, src, dst) catch |e| {
            std.debug.print("{s}: {t} in {d} bytes, libzstd succeeds\n", .{ rc.name, e, g.room });
            fails += 1;
            continue;
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(dst[0..n], &digest, .{});
        if (n != g.len or !std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), g.sha256)) {
            std.debug.print("{s}: {d} bytes in {d} of room, libzstd {d}\n", .{ rc.name, n, g.room, g.len });
            fails += 1;
        }
        // the frame for the least room is not always the one with room to
        // spare (raw where a compressed block does not fit)
        const roomy = try gpa.alloc(u8, zstd.compressBound(src.len));
        defer gpa.free(roomy);
        if (!std.mem.eql(u8, dst[0..n], roomy[0..try compressCase(gpa, &c, rc, dict, src, roomy)])) other_frames += 1;
        const back = try gpa.alloc(u8, src.len);
        defer gpa.free(back);
        var dd: ?zstd.DDict = if (rc.dict != null and rc.path != .prefix) try zstd.DDict.init(gpa, dict, .auto) else null;
        defer if (dd) |*x| x.deinit(gpa);
        const format = (if (std.mem.eql(u8, rc.params, "-")) zstd.Advanced{} else try param_test.parse(rc.params)).format;
        var d = try zstd.Decompressor.init(gpa, if (dd) |*x| .{ .ddict = x, .format = format } else if (rc.dict != null) .{ .prefix_once = dict, .format = format } else .{ .format = format });
        defer d.deinit();
        try std.testing.expectEqualSlices(u8, src, back[0..try d.decompress(back, dst[0..n])]);
        if (g.room == 0) continue;
        const less = compressCase(gpa, &c, rc, dict, src, dst[0 .. g.room - 1]);
        if (less) |m| {
            std.debug.print("{s}: {d} bytes in {d} of room, libzstd dstSize_tooSmall\n", .{ rc.name, m, g.room - 1 });
            fails += 1;
        } else |e| if (e != error.DstSizeTooSmall) {
            std.debug.print("{s}: {t} in {d} of room, libzstd dstSize_tooSmall\n", .{ rc.name, e, g.room - 1 });
            fails += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), fails);
    // room-csv-33-raw only
    try std.testing.expectEqual(@as(usize, 1), other_frames);
}

test "a context that ran out of room compresses the next frame as a fresh one would" {
    const gpa = std.testing.allocator;
    const case = findCase("csv-600000");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    const want = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(want);
    for ([_]zstd.Advanced{ .{}, .{ .nb_workers = 2, .job_size = 524288 } }) |adv| {
        var fresh: zstd.Compressor = .init(gpa);
        defer fresh.deinit();
        const n = try fresh.compress(want, src, .{ .level = 3, .advanced = adv });
        var c: zstd.Compressor = .init(gpa);
        defer c.deinit();
        // stopped in the header, in the middle, and one byte short
        for ([_]usize{ 10, n / 2, n - 1 }) |room|
            try std.testing.expectError(error.DstSizeTooSmall, c.compress(dst[0..room], src, .{ .level = 3, .advanced = adv }));
        try std.testing.expectEqualSlices(u8, want[0..n], dst[0..try c.compress(dst, src, .{ .level = 3, .advanced = adv })]);
    }
}
