// SPDX-License-Identifier: MIT
//! Write every golden-test input to a directory, one file per case, named after
//! the case, and the covered (case, level, checksum) set to a manifest, one
//! "name level checksum ldm window_log ocf" line each (`corpus.covered`; the
//! flags 0|1, ldm for long-distance matching switched on by hand, window_log
//! 0 for the level's own, ocf for the frequent-overflow-correction
//! reference), and the streaming set to a second manifest, one
//! "case level checksum schedule" line each (`corpus.stream_cases`). Part of
//! the golden recipe
//! (see README.md); not built by `zig build`.
//!
//!   zig run --dep corpus -Mroot=modules/zstd/tools/dump_corpus.zig \
//!       -Mcorpus=modules/zstd/src/testdata/corpus.zig -- <out-dir> <manifest> \
//!       <stream-manifest>

const std = @import("std");
const corpus = @import("corpus");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.next();
    const out_path = args.next() orelse return error.MissingOutDir;
    const manifest_path = args.next() orelse return error.MissingManifest;
    const stream_manifest_path = args.next() orelse return error.MissingManifest;

    var dir = try std.Io.Dir.cwd().openDir(io, out_path, .{});
    defer dir.close(io);
    for (corpus.cases) |case| {
        const buf = try gpa.alloc(u8, case.len);
        defer gpa.free(buf);
        corpus.generate(case, buf);
        try dir.writeFile(io, .{ .sub_path = case.name, .data = buf });
    }

    var manifest: std.ArrayList(u8) = .empty;
    defer manifest.deinit(gpa);
    for (corpus.cases) |case| for (corpus.levels) |level| for ([_]bool{ false, true }) |ck| {
        if (!corpus.covered(case, level, ck)) continue;
        try manifest.print(gpa, "{s} {d} {d} {d} {d} {d}\n", .{ case.name, level, @intFromBool(ck), @intFromBool(case.ldm), case.window_log orelse 0, @intFromBool(case.ocf) });
    };
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = manifest_path, .data = manifest.items });

    var stream_manifest: std.ArrayList(u8) = .empty;
    defer stream_manifest.deinit(gpa);
    for (corpus.stream_cases) |sc| for (sc.levels) |level| for ([_]bool{ false, true }) |ck| {
        try stream_manifest.print(gpa, "{s} {d} {d} {s}\n", .{ sc.case, level, @intFromBool(ck), sc.schedule });
    };
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = stream_manifest_path, .data = stream_manifest.items });
}
