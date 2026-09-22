// SPDX-License-Identifier: MIT
//! Byte-exactness against libzstd 1.5.7.
//!
//! For every corpus case, level and checksum setting, the frame this module
//! produces must have the length and SHA-256 that libzstd's `ZSTD_compress2`
//! produced for the same input (`testdata/goldens.zig`, written by
//! `tools/gen-goldens.sh`). A digest rather than the frame itself keeps the
//! repository small; the recipe regenerates the reference bytes when a
//! mismatch needs to be looked at.

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/goldens.zig");

fn find(case: []const u8, level: i32, checksum: bool) ?goldens.Golden {
    for (goldens.rows) |g| {
        if (g.level == level and g.checksum == checksum and std.mem.eql(u8, g.case, case)) return g;
    }
    return null;
}

test "every covered corpus combination has a golden row, and nothing else does" {
    var n: usize = 0;
    for (corpus.cases) |case| for (corpus.levels) |level| for ([_]bool{ false, true }) |ck| {
        if (!corpus.covered(case, level, ck)) continue;
        n += 1;
        if (find(case.name, level, ck) == null) {
            std.debug.print("no golden row for {s} level {d} checksum {}\n", .{ case.name, level, ck });
            return error.MissingGolden;
        }
    };
    try std.testing.expectEqual(n, goldens.rows.len);
}

test "output is byte-identical to libzstd 1.5.7 on the whole corpus" {
    const gpa = std.testing.allocator;
    var mismatches: usize = 0;
    for (corpus.cases) |case| {
        const src = try gpa.alloc(u8, case.len);
        defer gpa.free(src);
        corpus.generate(case, src);
        const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
        defer gpa.free(dst);
        for (corpus.levels) |level| for ([_]bool{ false, true }) |ck| {
            if (!corpus.covered(case, level, ck)) continue;
            const g = find(case.name, level, ck).?;
            const n = try zstd.compress(gpa, dst, src, .{ .level = level, .checksum = ck });
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(dst[0..n], &digest, .{});
            const hex = std.fmt.bytesToHex(digest, .lower);
            if (n != g.len or !std.mem.eql(u8, &hex, g.sha256)) {
                std.debug.print("MISMATCH {s} level {d} checksum {}: len {d} (libzstd {d})\n", .{ case.name, level, ck, n, g.len });
                mismatches += 1;
            }
        };
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

test "corpus inputs are the ones the goldens were made from" {
    // Pins the generator itself: if it drifted, every golden above would fail
    // for a reason that has nothing to do with the encoder. The digest is
    // `sha256sum` over the recipe's corpus files concatenated in case order.
    const gpa = std.testing.allocator;
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (corpus.cases) |case| {
        const buf = try gpa.alloc(u8, case.len);
        defer gpa.free(buf);
        corpus.generate(case, buf);
        h.update(buf);
    }
    const hex = std.fmt.bytesToHex(h.finalResult(), .lower);
    try std.testing.expectEqualStrings("b89750fbc20548584ec426ab40932599a042504847f8656f4b5b188405410911", &hex);
}
