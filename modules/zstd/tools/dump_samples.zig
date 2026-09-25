// SPDX-License-Identifier: MIT
//! Write every dictionary-training sample set (`src/testdata/dict_samples.zig`)
//! to a directory as `<name>.bin` in the form `ztrain.c` reads, and the
//! golden runs to a manifest, one "trainer set capacity k d f accel split"
//! line each, and, given a third path, the finished-dictionary runs
//! (`final_runs`) to a second manifest. Part of the dictionary golden
//! recipe (`gen-dict-goldens.sh`); not built by `zig build`.
//!
//!   zig run --dep samples -Mroot=modules/zstd/tools/dump_samples.zig \
//!       -Msamples=modules/zstd/src/testdata/dict_samples.zig -- \
//!       <out-dir> <manifest> [<final-manifest>]

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

    // the finished-dictionary runs: "op set capacity off len nb_finalize
    // nb_train k d f accel steps split level dict_id shrink max_regression"
    const final_path = args.next() orelse return;
    manifest.clearRetainingCapacity();
    for (samples.final_runs) |r| {
        const nb_finalize = r.nb_finalize orelse samples.find(r.set).nb;
        try manifest.print(gpa, "{s} {s} {d} {d} {d} {d} {d} {d} {d} {d} {d} {d} {s} {d} {d} {d} {d}\n", .{
            @tagName(r.op), r.set,   r.capacity, r.off,     r.len,                  nb_finalize,      r.nb_train, r.k, r.d, r.f, r.accel,
            r.steps,        r.split, r.level,    r.dict_id, @intFromBool(r.shrink), r.max_regression,
        });
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = final_path, .data = manifest.items });
}
