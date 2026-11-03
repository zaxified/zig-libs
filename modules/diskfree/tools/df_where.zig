// SPDX-License-Identifier: MIT
//! Module side of `df-where-diff.sh` (the oracle against GNU coreutils `df`
//! for the listing and path -> mount features):
//!
//!     df_where list            the mount points of `table.readTable(.{})`
//!                              (what a default `df` lists), one per line
//!     df_where list-all        the same with `include_pseudo` (like `df -a`)
//!     df_where where PATH...   `<mount_point>\t<PATH>` per path: the mount
//!                              `lookup.containing` picks over /proc/self/mounts
//!                              (the path must be absolute and canonical)
//!
//! Not built by `zig build`; `df-where-diff.sh` compiles it with the module.

const std = @import("std");
const diskfree = @import("diskfree");

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var out_buf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &fw.interface;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.skip();
    const cmd = args.next() orelse return 2;
    if (std.mem.startsWith(u8, cmd, "list")) {
        const o = (try diskfree.table.readTable(gpa, io, .{ .include_pseudo = std.mem.eql(u8, cmd, "list-all") })) orelse return 3;
        defer o.deinit(gpa);
        for (o.table.rows) |r| try w.print("{s}\n", .{r.mount_point});
    } else if (std.mem.eql(u8, cmd, "flags")) {
        // `<f_flags>\t<PATH>`; compared with python's os.statvfs(PATH).f_flag by df-where-diff.sh.
        while (args.next()) |p| {
            const u = diskfree.query(p) catch |e| {
                try w.print("ERR {s}\t{s}\n", .{ @errorName(e), p });
                continue;
            };
            try w.print("{d}\t{s}\n", .{ u.flags, p });
        }
    } else if (std.mem.eql(u8, cmd, "where")) {
        const es = (try diskfree.mounts.readMounts(gpa, io)) orelse return 3;
        defer diskfree.mounts.freeAll(gpa, es);
        while (args.next()) |p| {
            if (try diskfree.lookup.containing(es, p)) |i| {
                try w.print("{s}\t{s}\n", .{ es[i].mount_point, p });
            } else try w.print("NONE\t{s}\n", .{p});
        }
    } else return 2;
    try w.flush();
    return 0;
}
