// SPDX-License-Identifier: MIT

//! seglog-crash — the workload and the checker for the dm-log-writes crash
//! test (`run.sh`, next to this file).
//!
//!     seglog-crash write <dir> <records> [prealloc bytes]
//!     seglog-crash check <dir>
//!
//! `write` creates a log in `<dir>` and appends `records` records with the
//! default `.always` sync, rotating every 64 records and compressing each
//! segment it rotates away from once the one before it is closed; it prints
//! `acked <lsn>` after each append returns. `check` opens the log as a writer
//! would after a crash (repairing its tail), reads everything, and prints
//! `records <n>`; it exits 1 if the log does not open, a record is not the
//! one its LSN says, the LSNs are not 1, 2, 3 … without a gap, or `verify`
//! finds damage.

const std = @import("std");
const seglog = @import("seglog");

fn payloadOf(buf: []u8, lsn: u64) []const u8 {
    // Lengths vary (records straddle blocks and frames); content is the LSN.
    const len = 40 + (lsn * 37) % 300;
    var w: std.Io.Writer = .fixed(buf[0..len]);
    while (w.end < len) w.print("{d:0>12};", .{lsn}) catch break;
    @memset(buf[w.end..len], '#');
    return buf[0..len];
}

pub fn main(init: std.process.Init.Minimal) u8 {
    var it = init.args.iterate();
    _ = it.next();
    const cmd = it.next() orelse return usage();
    const dir = it.next() orelse return usage();
    const gpa = std.heap.smp_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const result = if (std.mem.eql(u8, cmd, "write")) blk: {
        const n = std.fmt.parseInt(u64, it.next() orelse return usage(), 10) catch return usage();
        const pa = if (it.next()) |s| std.fmt.parseInt(u64, s, 10) catch return usage() else 0;
        break :blk write(gpa, io, dir, n, pa);
    } else if (std.mem.eql(u8, cmd, "check")) check(gpa, io, dir) else return usage();
    result catch |err| {
        std.debug.print("seglog-crash {s}: {s}\n", .{ cmd, @errorName(err) });
        return 1;
    };
    return 0;
}

fn usage() u8 {
    std.debug.print("usage: seglog-crash write <dir> <records> [prealloc] | check <dir>\n", .{});
    return 2;
}

fn write(gpa: std.mem.Allocator, io: std.Io, path: []const u8, n: u64, prealloc: u64) !void {
    const cwd = std.Io.Dir.cwd();
    cwd.createDir(io, path, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const d = try cwd.openDir(io, path, .{});
    defer d.close(io);
    var fs = seglog.FsStorage.init(io, d);
    var log = try seglog.Log.open(gpa, fs.storage(), .{ .create = true, .preallocate = prealloc });
    defer log.close();
    var out_buf: [256]u8 = undefined;
    var ow = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &ow.interface;
    var buf: [512]u8 = undefined;
    var seg: u64 = 1;
    try log.rotate(seg);
    var lsn: u64 = 1;
    while (lsn <= n) : (lsn += 1) {
        const a = try log.appendAt(@intCast(lsn), payloadOf(&buf, lsn));
        if (a.lsn != lsn) return error.LsnMismatch;
        try w.print("acked {d}\n", .{lsn});
        try w.flush();
        if (lsn % 64 == 0) {
            seg += 1;
            try log.rotate(seg);
            if (seg >= 3) _ = try log.compress(seg - 2);
        }
    }
}

fn check(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const d = std.Io.Dir.cwd().openDir(io, path, .{}) catch |e| switch (e) {
        error.FileNotFound => return report(io, 0), // mkfs'd, nothing written yet
        else => return e,
    };
    defer d.close(io);
    var fs = seglog.FsStorage.init(io, d);
    var log = seglog.Log.open(gpa, fs.storage(), .{}) catch |e| switch (e) {
        error.NotFound => return report(io, 0), // no manifest committed yet
        else => return e,
    };
    defer log.close();
    var buf: [512]u8 = undefined;
    var iter = log.iterator(null);
    defer iter.deinit();
    var want: u64 = 1;
    while (try iter.next()) |rec| : (want += 1) {
        if (rec.lsn != want) return error.LsnGap;
        if (!std.mem.eql(u8, rec.payload, payloadOf(&buf, rec.lsn))) return error.WrongPayload;
    }
    var r = try log.verify(gpa);
    defer r.deinit(gpa);
    if (!r.clean()) return error.Damaged;
    return report(io, want - 1);
}

fn report(io: std.Io, n: u64) !void {
    var out_buf: [64]u8 = undefined;
    var ow = std.Io.File.stdout().writerStreaming(io, &out_buf);
    try ow.interface.print("records {d}\n", .{n});
    try ow.interface.flush();
}
