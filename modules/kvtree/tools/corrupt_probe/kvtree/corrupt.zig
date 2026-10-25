// SPDX-License-Identifier: MIT
//! kvtree side of the damaged-file probe; backs the kvtree "never crashes on
//! a damaged file" **Ahead:** claim. `corrupt build DIR` makes DIR/t.db
//! (N=2000 keys); `corrupt check DIR` opens it through plain `FsStorage`
//! (pread), point-gets every key, scans; `corrupt check-mmap DIR` does the same
//! through `FsStorage.initMmap` (the production shape: pages lent from a
//! mapping).
//! Exit: 0 CLEAN, 10 WRONG, 11 ERROR (typed error); anything else = crash.
const std = @import("std");
const kvtree = @import("kvtree");

const N = 2000;
const VL = 100;

fn key(buf: *[9]u8, id: usize) []const u8 {
    return std.mem.print(buf, "k{d:0>8}", .{id}) catch unreachable;
}
fn val(buf: *[VL]u8, id: usize) []const u8 {
    for (buf, 0..) |*b, i| b.* = @intCast((id + i) % 251);
    return buf;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.page_allocator;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) return 2;
    var dir = try std.Io.Dir.cwd().openDir(io, args[2], .{});
    defer dir.close(io);
    if (std.mem.eql(u8, args[1], "build")) {
        var fs = kvtree.FsStorage.init(io, dir);
        var db = try kvtree.Db.open(gpa, fs.storage(), "t.db", .{});
        var tx = try db.begin();
        for (0..N) |id| {
            var kb: [9]u8 = undefined;
            var vb: [VL]u8 = undefined;
            try tx.put(key(&kb, id), val(&vb, id));
        }
        try tx.commit();
        db.close();
        return 0;
    }
    var fs = if (std.mem.eql(u8, args[1], "check-mmap")) kvtree.FsStorage.initMmap(io, dir) else kvtree.FsStorage.init(io, dir);
    return check(gpa, fs.storage());
}

fn check(gpa: std.mem.Allocator, store: kvtree.Storage) u8 {
    var db = kvtree.Db.open(gpa, store, "t.db", .{}) catch |e| return fail(e, "open");
    defer db.close();
    var wrong: ?[]const u8 = null; // "structural" beats "value-only"
    var structural = false;
    for (0..N) |id| {
        var kb: [9]u8 = undefined;
        var vb: [VL]u8 = undefined;
        const got = db.get(gpa, key(&kb, id)) catch |e| return fail(e, "get");
        if (got) |g| {
            defer gpa.free(g);
            if (!std.mem.eql(u8, g, val(&vb, id))) wrong = "value-only";
        } else {
            structural = true;
        }
    }
    var snap = db.snapshot() catch |e| return fail(e, "snapshot");
    defer snap.release();
    var cur = snap.cursor() catch |e| return fail(e, "cursor");
    defer cur.deinit();
    cur.first() catch |e| return fail(e, "first");
    var n: usize = 0;
    while (cur.next() catch |e| return fail(e, "next")) |e| {
        var kb: [9]u8 = undefined;
        var vb: [VL]u8 = undefined;
        if (n >= N) {
            structural = true;
            break;
        }
        if (!std.mem.eql(u8, e.key, key(&kb, n))) structural = true else if (!std.mem.eql(u8, e.val, val(&vb, n))) wrong = "value-only";
        n += 1;
    }
    if (n != N) structural = true;
    if (structural) wrong = "structural";
    if (wrong) |w| {
        std.debug.print("WRONG {s}\n", .{w});
        return 10;
    }
    return 0;
}

fn fail(e: anyerror, what: []const u8) u8 {
    std.debug.print("ERROR {s} {t}\n", .{ what, e });
    return 11;
}
