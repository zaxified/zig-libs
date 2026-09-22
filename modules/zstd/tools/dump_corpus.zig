// SPDX-License-Identifier: MIT
//! Write every golden-test input to a directory, one file per case, named after
//! the case. Part of the golden recipe (see README.md); not built by `zig build`.
//!
//!   zig run --dep corpus -Mroot=modules/zstd/tools/dump_corpus.zig \
//!       -Mcorpus=modules/zstd/src/testdata/corpus.zig -- <out-dir>

const std = @import("std");
const corpus = @import("corpus");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.next();
    const out_path = args.next() orelse return error.MissingOutDir;

    var dir = try std.Io.Dir.cwd().openDir(io, out_path, .{});
    defer dir.close(io);
    for (corpus.cases) |case| {
        const buf = try gpa.alloc(u8, case.len);
        defer gpa.free(buf);
        corpus.generate(case, buf);
        try dir.writeFile(io, .{ .sub_path = case.name, .data = buf });
    }
}
