// SPDX-License-Identifier: MIT
//! `df`-shaped dump from this module, for `df-diff.sh` (the differential
//! oracle against GNU coreutils `df`). For every path given on the command
//! line — or, with none, every mount point in `/proc/self/mounts` — prints
//!
//!     <size>\t<used>\t<avail>\t<itotal>\t<iused>\t<iavail>\t<pcent>\t<path>
//!
//! from `diskfree.query` and the module's own `Usage` helpers
//! (`totalBytes`, `usedBytes`, `availableBytes`, `usePercent`, the inode
//! counts) — the columns `df -B1 --output=size,used,avail,itotal,iused,iavail,pcent`
//! prints. The point of the oracle is to find out whether they agree with `df`.
//! A path that `query` refuses prints `ERR <error>\t<path>`.
//!
//! Not built by `zig build`; `df-diff.sh` compiles it with the module.

const std = @import("std");
const diskfree = @import("diskfree");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var out_buf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &fw.interface;

    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.skip();
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(gpa);
    while (args.next()) |a| try paths.append(gpa, a);

    var mounts: ?[]diskfree.mounts.MountEntry = null;
    defer if (mounts) |m| diskfree.mounts.freeAll(gpa, m);
    if (paths.items.len == 0) {
        mounts = try diskfree.mounts.readMounts(gpa, io);
        for (mounts orelse &.{}) |m| try paths.append(gpa, m.mount_point);
    }

    for (paths.items) |p| {
        const u = diskfree.query(p) catch |e| {
            try w.print("ERR {s}\t{s}\n", .{ @errorName(e), p });
            continue;
        };
        try w.print("{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t", .{ u.totalBytes(), u.usedBytes(), u.availableBytes(), u.inodes_total, u.inodes_total -| u.inodes_free, u.inodes_free });
        if (u.usePercent()) |pc| try w.print("{d}%", .{pc}) else try w.writeAll("-");
        try w.print("\t{s}\n", .{p});
    }
    try w.flush();
}
