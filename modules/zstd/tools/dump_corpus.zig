// SPDX-License-Identifier: MIT
//! Write every golden-test input to a directory, one file per case, named after
//! the case, and the covered (case, level, checksum) set to a manifest, one
//! "name level checksum ldm window_log ocf" line each (`corpus.covered`; the
//! flags 0|1, ldm for long-distance matching switched on by hand, window_log
//! 0 for the level's own, ocf for the frequent-overflow-correction
//! reference), and the streaming set to a second manifest, one
//! "case level checksum schedule" line each (`corpus.stream_cases`), and the
//! advanced-parameter set to a third, one "case level checksum params" line
//! each (`corpus.param_cases`). With a dictionary manifest and the
//! testdata directory, also the dictionary goldens' inputs and dictionaries
//! (`dict-in-<case>`, `dict-<name>`; a trained dictionary is read from
//! `<testdata>/<name>.zdict`, and skipped while it is missing), the training
//! samples (`train-<set>/<i>`), and one "case dict path content-type level
//! checksum params schedule ocf" line per dictionary golden
//! (`corpus.dict_cases`; params and schedule "-" when none). Part of the
//! golden recipe (see README.md); not built by `zig build`.
//!
//!   zig run --dep corpus -Mroot=modules/zstd/tools/dump_corpus.zig \
//!       -Mcorpus=modules/zstd/src/testdata/corpus.zig -- <out-dir> <manifest> \
//!       <stream-manifest> <param-manifest> [<dict-manifest> <testdata-dir>]

const std = @import("std");
const corpus = @import("corpus");

/// The trained dictionaries as read from the testdata directory.
var trained_names: [corpus.train_sets.len][]const u8 = undefined;
var trained_bytes: [corpus.train_sets.len]?[]const u8 = @splat(null);

fn trained(name: []const u8) []const u8 {
    for (trained_names, trained_bytes) |n, b| if (std.mem.eql(u8, n, name)) return b.?;
    unreachable;
}

fn available(d: corpus.DictDef) bool {
    const need = switch (d.source) {
        .trained => |n| n,
        .reid => |x| x.of,
        else => return true,
    };
    for (trained_names, trained_bytes) |n, b| if (std.mem.eql(u8, n, need)) return b != null;
    return false;
}
pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.next();
    const out_path = args.next() orelse return error.MissingOutDir;
    const manifest_path = args.next() orelse return error.MissingManifest;
    const stream_manifest_path = args.next() orelse return error.MissingManifest;
    const param_manifest_path = args.next() orelse return error.MissingManifest;

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

    var param_manifest: std.ArrayList(u8) = .empty;
    defer param_manifest.deinit(gpa);
    for (corpus.param_cases) |pc| for (pc.levels) |level| for (pc.checksums) |ck| {
        try param_manifest.print(gpa, "{s} {d} {d} {s}\n", .{ pc.case, level, @intFromBool(ck), pc.params });
    };
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = param_manifest_path, .data = param_manifest.items });

    const dict_manifest_path = args.next() orelse return;
    const testdata_path = args.next() orelse return error.MissingTestdataDir;
    var testdata = try std.Io.Dir.cwd().openDir(io, testdata_path, .{});
    defer testdata.close(io);
    defer for (trained_bytes) |b| if (b) |x| gpa.free(x);
    for (corpus.train_sets, 0..) |ts, k| {
        trained_names[k] = ts.name;
        const file = try std.fmt.allocPrint(gpa, "{s}.zdict", .{ts.name});
        defer gpa.free(file);
        trained_bytes[k] = testdata.readFileAlloc(io, file, gpa, .limited(1 << 20)) catch |e| switch (e) {
            error.FileNotFound => null,
            else => return e,
        };
        // the samples it is trained on
        const sub = try std.fmt.allocPrint(gpa, "train-{s}", .{ts.name});
        defer gpa.free(sub);
        dir.createDir(io, sub, .default_dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
        var i: usize = 0;
        while (i < ts.count) : (i += 1) {
            var len: usize = undefined;
            const c = corpus.trainSample(ts, i, &len);
            const buf = try gpa.alloc(u8, len);
            defer gpa.free(buf);
            corpus.generate(c, buf);
            const name = try std.fmt.allocPrint(gpa, "{s}/{d:0>4}", .{ sub, i });
            defer gpa.free(name);
            try dir.writeFile(io, .{ .sub_path = name, .data = buf });
        }
    }
    for (corpus.dict_defs) |d| {
        if (!available(d)) continue;
        const buf = try gpa.alloc(u8, corpus.dictLen(d, &trained));
        defer gpa.free(buf);
        const n = corpus.buildDict(d, &trained, buf);
        const name = try std.fmt.allocPrint(gpa, "dict-{s}", .{d.name});
        defer gpa.free(name);
        try dir.writeFile(io, .{ .sub_path = name, .data = buf[0..n] });
    }
    var dict_manifest: std.ArrayList(u8) = .empty;
    defer dict_manifest.deinit(gpa);
    for (corpus.dict_cases) |dc| {
        const buf = try gpa.alloc(u8, dc.input.len);
        defer gpa.free(buf);
        corpus.generate(dc.input, buf);
        const name = try std.fmt.allocPrint(gpa, "dict-in-{s}", .{dc.name});
        defer gpa.free(name);
        try dir.writeFile(io, .{ .sub_path = name, .data = buf });
        for (dc.levels) |level| for (dc.checksums) |ck| {
            try dict_manifest.print(gpa, "{s} {s} {s} {d} {d} {d} {s} {s} {d}\n", .{ dc.name, dc.dict, @tagName(dc.path), dc.content_type, level, @intFromBool(ck), dc.params, dc.schedule orelse "-", @intFromBool(dc.ocf) });
        };
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = dict_manifest_path, .data = dict_manifest.items });
}
