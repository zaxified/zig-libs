// SPDX-License-Identifier: MIT
//! The entropy-table builders against libzstd 1.5.7 on fixed counts
//! (`testdata/entropy_kats.zig`, from `tools/gen-entropy-kats.sh` through
//! `tools/zentropy.c`): `fse.normalizeCount` (every branch of
//! `FSE_normalizeM2` included), `fse.writeNCount` at every room up to the
//! least libzstd accepts, `huf.optimalTableLog` with and without the
//! optimal-depth search, `huf.buildCTable` and `huf.writeCTable` likewise.
//! Found by the encoder's mutation audit (2026-11-19, group 2): the
//! byte-parity goldens never reach these branches with the distributions
//! real inputs produce.

const std = @import("std");
const fse = @import("fse.zig");
const huf = @import("huf.zig");
const kats = @import("testdata/entropy_kats.zig");

fn sum(counts: []const u32) usize {
    var t: usize = 0;
    for (counts) |c| t += c;
    return t;
}

test "FSE normalization and table headers are libzstd's, at every room" {
    for (kats.norm_kats) |k| {
        errdefer std.debug.print("norm kat: {s}\n", .{k.why});
        const max_symbol: u32 = @intCast(k.counts.len - 1);
        var norm: [256]i16 = undefined;
        const log = try fse.normalizeCount(&norm, k.table_log, k.counts, sum(k.counts), max_symbol, k.low_prob);
        try std.testing.expectEqual(k.norm_log, log);
        try std.testing.expectEqualSlices(i16, k.norm, norm[0..k.counts.len]);
        var buf: [600]u8 = undefined;
        for (0..k.least) |room| {
            if (fse.writeNCount(buf[0..room], &norm, max_symbol, log)) |n| {
                std.debug.print("room {d}: wrote {d} bytes, libzstd refuses below {d}\n", .{ room, n, k.least });
                return error.TestUnexpectedResult;
            } else |_| {}
        }
        for ([_]usize{ k.least, buf.len }, [_][]const u8{ k.header, k.full }) |room, want| {
            const n = try fse.writeNCount(buf[0..room], &norm, max_symbol, log);
            try std.testing.expectEqualSlices(u8, want, buf[0..n]);
        }
    }
}

test "Huffman table logs and table headers are libzstd's, at every room" {
    for (kats.huf_kats) |k| {
        errdefer std.debug.print("huf kat: {s}\n", .{k.why});
        const max_symbol: u32 = @intCast(k.counts.len - 1);
        const opt = huf.optimalTableLog(k.max_log, sum(k.counts), max_symbol, k.counts, k.depth);
        try std.testing.expectEqual(k.opt_log, opt);
        var ct: huf.CTable = .{};
        const built = try huf.buildCTable(&ct, k.counts, max_symbol, opt);
        try std.testing.expectEqual(k.built_log, built);
        var buf: [600]u8 = undefined;
        for (0..k.least) |room| {
            if (huf.writeCTable(buf[0..room], &ct, max_symbol, built)) |n| {
                std.debug.print("room {d}: wrote {d} bytes, libzstd refuses below {d}\n", .{ room, n, k.least });
                return error.TestUnexpectedResult;
            } else |_| {}
        }
        // With little room the weights go raw where ample room codes them
        // with FSE (its payload needs 8 bytes of slack), as in libzstd.
        for ([_]usize{ k.least, buf.len }, [_][]const u8{ k.header, k.full }) |room, want| {
            const n = try huf.writeCTable(buf[0..room], &ct, max_symbol, built);
            try std.testing.expectEqualSlices(u8, want, buf[0..n]);
        }
    }
}
