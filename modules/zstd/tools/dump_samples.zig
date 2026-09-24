// SPDX-License-Identifier: MIT
//! Write every dictionary-training sample set (`src/testdata/dict_samples.zig`)
//! to a directory as `<name>.bin` in the form `ztrain.c` reads, and the
//! golden runs to a manifest, one "trainer set capacity k d f accel split"
//! line each. Part of the dictionary golden recipe (`gen-dict-goldens.sh`);
//! not built by `zig build`.
//!
//!   zig run --dep samples -Mroot=modules/zstd/tools/dump_samples.zig \
//!       -Msamples=modules/zstd/src/testdata/dict_samples.zig -- <out-dir> <manifest>

const std = @import("std");
const samples = @import("samples");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.next();
    const out_path = args.next() orelse return error.MissingOutDir;
    const manifest_path = args.next() orelse return error.MissingManifest;

    var dir = try std.Io.Dir.cwd().openDir(io, out_path, .{});
    defer dir.close(io);
    for (samples.sets) |set| {
        const g = try samples.generate(gpa, set);
        defer g.deinit(gpa);
        const bytes = try samples.serialize(gpa, g);
        defer gpa.free(bytes);
        const name = try std.fmt.allocPrint(gpa, "{s}.bin", .{set.name});
        defer gpa.free(name);
        try dir.writeFile(io, .{ .sub_path = name, .data = bytes });
    }

    var manifest: std.ArrayList(u8) = .empty;
    defer manifest.deinit(gpa);
    for (samples.runs) |r| {
        try manifest.print(gpa, "{s} {s} {d} {d} {d} {d} {d} {s}\n", .{ @tagName(r.trainer), r.set, r.capacity, r.k, r.d, r.f, r.accel, r.split });
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = manifest_path, .data = manifest.items });
}
