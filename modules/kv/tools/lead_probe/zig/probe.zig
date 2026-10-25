// SPDX-License-Identifier: MIT
//! kv side of the lead probe (backs the kv "Ahead" claims on read-only open,
//! torn tail and flipped byte). CLI identical to the Go probes in ../common.go:
//! `probe plain|mmap write|check|putnew|getnew|holder|reader DIR ...`.
const std = @import("std");
const kv = @import("kv");

var out_buf: [4096]u8 = undefined;
var out_w: std.Io.File.Writer = undefined;
fn out() *std.Io.Writer {
    return &out_w.interface;
}

fn key(buf: *[16]u8, id: usize) []const u8 {
    return std.mem.print(buf, "k{d:0>8}", .{id}) catch unreachable;
}
fn val(buf: *[100]u8, id: usize) []const u8 {
    for (buf, 0..) |*b, i| b.* = @intCast((id + i) % 251);
    return buf;
}

fn check(db: *kv.Db, gpa: std.mem.Allocator, a: usize, b: usize) !void {
    var ok: usize = 0;
    var wrong: usize = 0;
    var missing: usize = 0;
    var errs: usize = 0;
    var first: []const u8 = "";
    for (a..b) |id| {
        var kb: [16]u8 = undefined;
        var vb: [100]u8 = undefined;
        const got = db.get(gpa, key(&kb, id)) catch |e| {
            errs += 1;
            if (first.len == 0) first = @errorName(e);
            continue;
        };
        if (got) |g| {
            defer gpa.free(g);
            if (std.mem.eql(u8, g, val(&vb, id))) ok += 1 else wrong += 1;
        } else missing += 1;
    }
    try out().print("check [{d},{d}) ok={d} wrong={d} missing={d} err={d} firsterr=\"{s}\"\n", .{ a, b, ok, wrong, missing, errs, first });
    try out().flush();
}

const Ctx = struct {
    fs: kv.FsStorage,
    db: kv.Db,
};

fn openDb(gpa: std.mem.Allocator, io: std.Io, dirp: []const u8, mmap: bool, role_ro: bool, seg: u64, ctx: *Ctx) !bool {
    const dir = try std.Io.Dir.cwd().openDir(io, dirp, .{});
    ctx.fs = if (mmap) kv.FsStorage.initMmap(io, dir) else kv.FsStorage.init(io, dir);
    var opts: kv.Options = .{ .sync = .none, .read_only = role_ro };
    if (seg > 0) opts.max_file_size = seg;
    ctx.db = kv.Db.open(gpa, ctx.fs.storage(), "kv.db", opts) catch |e| {
        try out().print("open=ERR \"{s}\"\n", .{@errorName(e)});
        try out().flush();
        return false;
    };
    try out().print("open=OK\n", .{});
    try out().flush();
    return true;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    out_w = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const a = try init.minimal.args.toSlice(arena);
    const mmap = std.mem.eql(u8, a[1], "mmap");
    const cmd = a[2];
    const dirp = a[3];
    var ctx: Ctx = undefined;
    if (std.mem.eql(u8, cmd, "write")) {
        const n = try std.fmt.parseInt(usize, a[4], 10);
        const seg = try std.fmt.parseInt(u64, a[5], 10);
        if (!try openDb(gpa, io, dirp, mmap, false, seg, &ctx)) return;
        for (0..n) |i| {
            var kb: [16]u8 = undefined;
            var vb: [100]u8 = undefined;
            try ctx.db.put(key(&kb, i), val(&vb, i));
        }
        ctx.db.close();
        try out().print("close: ok\n", .{});
    } else if (std.mem.eql(u8, cmd, "check")) {
        const n = try std.fmt.parseInt(usize, a[4], 10);
        const ro = a.len > 5 and std.mem.eql(u8, a[5], "ro");
        if (!try openDb(gpa, io, dirp, mmap, ro, 0, &ctx)) return;
        try check(&ctx.db, gpa, 0, n);
        ctx.db.close();
    } else if (std.mem.eql(u8, cmd, "putnew")) {
        if (!try openDb(gpa, io, dirp, mmap, false, 0, &ctx)) return;
        if (ctx.db.put("newkey", "newvalue-0123456789")) |_| try out().print("put: ok\n", .{}) else |e| try out().print("put: ERR {s}\n", .{@errorName(e)});
        ctx.db.close();
        try out().print("close: ok\n", .{});
    } else if (std.mem.eql(u8, cmd, "getnew")) {
        if (!try openDb(gpa, io, dirp, mmap, false, 0, &ctx)) return;
        if (ctx.db.get(gpa, "newkey")) |g| {
            if (g) |v| {
                defer gpa.free(v);
                try out().print("newkey={s}\n", .{if (std.mem.eql(u8, v, "newvalue-0123456789")) "OK" else "WRONG"});
            } else try out().print("newkey=MISSING\n", .{});
        } else |e| try out().print("newkey=ERR \"{s}\"\n", .{@errorName(e)});
        ctx.db.close();
    } else if (std.mem.eql(u8, cmd, "holder") or std.mem.eql(u8, cmd, "reader")) {
        const holder = std.mem.eql(u8, cmd, "holder");
        const ro_role = !holder and !(a.len > 4 and std.mem.eql(u8, a[4], "rw"));
        if (!try openDb(gpa, io, dirp, mmap, ro_role, 0, &ctx)) return;
        if (holder) {
            const n = try std.fmt.parseInt(usize, a[4], 10);
            for (0..n) |i| {
                var kb: [16]u8 = undefined;
                var vb: [100]u8 = undefined;
                try ctx.db.put(key(&kb, i), val(&vb, i));
            }
        }
        try out().print("READY\n", .{});
        try out().flush();
        var ib: [256]u8 = undefined;
        var rd = std.Io.File.stdin().reader(io, &ib);
        while (try rd.interface.takeDelimiter('\n')) |line| {
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const c = it.next() orelse continue;
            if (std.mem.eql(u8, c, "more")) {
                const x = try std.fmt.parseInt(usize, it.next().?, 10);
                const y = try std.fmt.parseInt(usize, it.next().?, 10);
                for (x..y) |i| {
                    var kb: [16]u8 = undefined;
                    var vb: [100]u8 = undefined;
                    try ctx.db.put(key(&kb, i), val(&vb, i));
                }
                try out().print("DONE\n", .{});
            } else if (std.mem.eql(u8, c, "check")) {
                const x = try std.fmt.parseInt(usize, it.next().?, 10);
                const y = try std.fmt.parseInt(usize, it.next().?, 10);
                try check(&ctx.db, gpa, x, y);
            } else if (std.mem.eql(u8, c, "refresh")) {
                if (ctx.db.refresh()) |_| try out().print("refresh=OK\n", .{}) else |e| try out().print("refresh=ERR \"{s}\"\n", .{@errorName(e)});
            } else if (std.mem.eql(u8, c, "put")) {
                if (ctx.db.put("rk", "rv")) |_| try out().print("put-on-reader: nil\n", .{}) else |e| try out().print("put-on-reader: {s}\n", .{@errorName(e)});
            } else if (std.mem.eql(u8, c, "quit")) break;
            try out().flush();
        }
        ctx.db.close();
        try out().print("close: ok\n", .{});
    }
    try out().flush();
}
