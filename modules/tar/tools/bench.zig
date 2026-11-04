// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tar`'s Reader and Writer against Go's `archive/tar`
//! (Go 1.26 standard library, BSD-3-Clause; the reference, `tools/go_bench`),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3). Zig's `std.tar` is timed in
//! the same process as an informational second candidate for "fastest".
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tar` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26, the
//! standard library only (`GOPROXY=off`). Run from the repository root.
//!
//! Corpora, fixed seed, written by this driver into `.zig-cache/bench-tar/`
//! with this module's Writer (Go reads the same files):
//!   many.tar  2048 members, GNU format: 40 files per 1 in 40 directories,
//!             sizes 0..4096 (mean ~2 KiB), uid/gid 1000, every 50th a
//!             directory, every 37th a symlink; paths <= 100 bytes.
//!   pax.tar   1024 members written with `long_names = .pax`, paths 110..200
//!             bytes (a pax `path` record each), sizes 0..1024.
//!   big.tar   one 32 MiB file.
//! Ops (one op = the whole archive):
//!   read_many / read_pax  walk every member and read every content byte in
//!             32 KiB reads, from memory. Ours `Reader.next`/`read`; Go
//!             `tar.Reader.Next`/`Read` over a `bytes.Reader`. Count: per member
//!             size + uid + gid + mtime + len(path) + len(link), plus the bytes
//!             read.
//!   read_big  the same over big.tar (32 MiB of content: the copy cost).
//!   write_many  write the members of many.tar to a counting sink with no
//!             buffering on either side: ours `writeEntry`; Go `WriteHeader` +
//!             `Write` + `Close` (Go picks USTAR for these headers). Count: bytes
//!             written, which must be equal.
//!   write_big  one 32 MiB file in 64 KiB writes: `writeHeader` + `writeAll` +
//!             `writePadding` + `finish`; Go `WriteHeader` + `Write` + `Close`.
//!
//! What Go does that ours does not (so the rows are fair, not equal): the
//! `Header` is a heap-allocated struct per member with `Uname`/`Gname`/times and
//! a PAX-records map, built by Go's GC'd allocator; ours returns a value that
//! borrows two buffers. What ours does that Go does not: nothing extra on read
//! (both verify the header checksum and parse the numeric fields).
//!
//! `std.tar` rows are informational and do LESS work (the iterator surfaces no
//! uid, gid or mtime): read_many and read_pax only.

const std = @import("std");
const bench = @import("testkit").bench;
const tar = @import("tar");

const ref_short = "Go";
const ref_card = "Go 1.26.8 archive/tar";
const bench_name = "bench-tar";
const work_dir = ".zig-cache/bench-tar";
const go_dir = "modules/tar/tools/go_bench";
// global-alloc-ok: bench driver, one per-member allocation pair per entry as any consumer would pay.
const bench_gpa = std.heap.smp_allocator;

const Op = enum { read_many, read_pax, read_big, write_many, write_big };

const Item = struct { e: tar.Entry, off: usize = 0 };

const Ctx = struct {
    op: Op = .read_many,
    many: []const u8 = "",
    pax: []const u8 = "",
    big: []const u8 = "",
    items: []const Item = &.{},
    pool: []const u8 = "",
    chunk: [64 * 1024]u8 = undefined,
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn readAll(gpa: std.mem.Allocator, bytes: []const u8) u64 {
    var src: std.Io.Reader = .fixed(bytes);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    var buf: [32 * 1024]u8 = undefined;
    var t: u64 = 0;
    while (tr.next() catch @panic("bench-tar: read")) |e| {
        t +%= e.size +% e.uid +% e.gid +% @as(u64, @bitCast(e.mtime)) +% e.path.len +% e.link_target.len;
        while (true) {
            const n = tr.read(&buf) catch @panic("bench-tar: content");
            if (n == 0) break;
            t +%= n;
        }
    }
    return t;
}

fn writeMany(c: *Ctx) u64 {
    var d = std.Io.Writer.Discarding.init(&.{});
    const tw = tar.Writer.init(&d.writer);
    for (c.items) |it| {
        const body: []const u8 = if (it.e.kind == .file) c.pool[it.off..][0..it.e.size] else "";
        tw.writeEntry(it.e, body) catch @panic("bench-tar: write");
    }
    tw.finish() catch @panic("bench-tar: finish");
    return d.fullCount();
}

fn writeBig(c: *Ctx) u64 {
    var d = std.Io.Writer.Discarding.init(&.{});
    const tw = tar.Writer.init(&d.writer);
    const size: u64 = 32 << 20;
    tw.writeHeader(.{ .path = "big.bin", .mode = 0o644, .uid = 1000, .gid = 1000, .mtime = 1_600_000_000, .size = size }) catch @panic("bench-tar: header");
    var left = size;
    while (left > 0) {
        const n: usize = @intCast(@min(left, c.chunk.len));
        d.writer.writeAll(c.chunk[0..n]) catch @panic("bench-tar: body");
        left -= n;
    }
    tw.writePadding(size) catch @panic("bench-tar: pad");
    tw.finish() catch @panic("bench-tar: finish");
    return d.fullCount();
}

fn once(c: *Ctx) u64 {
    return switch (c.op) {
        .read_many => readAll(bench_gpa, c.many),
        .read_pax => readAll(bench_gpa, c.pax),
        .read_big => readAll(bench_gpa, c.big),
        .write_many => writeMany(c),
        .write_big => writeBig(c),
    };
}

// ── std.tar (informational, does less) ───────────────────────────────────────

fn stdRead(bytes: []const u8) u64 {
    var src: std.Io.Reader = .fixed(bytes);
    var name: [512]u8 = undefined;
    var link: [512]u8 = undefined;
    var it = std.tar.Iterator.init(&src, .{ .file_name_buffer = &name, .link_name_buffer = &link });
    var d = std.Io.Writer.Discarding.init(&.{});
    var t: u64 = 0;
    while (it.next() catch @panic("bench-tar: std.tar")) |f| {
        t +%= f.size +% f.name.len +% f.link_name.len;
        if (f.kind == .file) {
            it.streamRemaining(f, &d.writer) catch @panic("bench-tar: std.tar content");
            t +%= f.size;
        }
    }
    return t;
}

// ── corpus ───────────────────────────────────────────────────────────────────

fn build(arena: std.mem.Allocator, items: []const Item, pool: []const u8, mode: tar.LongNames) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const tw = tar.Writer.initOptions(&out.writer, .{ .long_names = mode });
    for (items) |it| {
        const body: []const u8 = if (it.e.kind == .file) pool[it.off..][0..it.e.size] else "";
        try tw.writeEntry(it.e, body);
    }
    try tw.finish();
    return out.toOwnedSlice();
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x7a2_b3c4);
    const r = prng.random();
    const pool = try arena.alloc(u8, 64 * 1024);
    r.bytes(pool);
    c.pool = pool;
    r.bytes(&c.chunk);

    var many: std.ArrayList(Item) = .empty;
    for (0..2048) |i| {
        var e: tar.Entry = .{ .path = "", .mode = 0o644, .uid = 1000, .gid = 1000, .mtime = 1_600_000_000 + @as(i64, @intCast(i)) };
        if (i % 50 == 0) {
            e.kind = .dir;
            e.mode = 0o755;
            e.path = try arena.print("dir{d:0>3}/sub{d:0>4}/", .{ i / 40, i });
        } else if (i % 37 == 0) {
            e.kind = .symlink;
            e.link_target = "dir000/file0001.txt";
            e.path = try arena.print("dir{d:0>3}/link{d:0>4}", .{ i / 40, i });
        } else {
            e.path = try arena.print("dir{d:0>3}/file{d:0>4}.txt", .{ i / 40, i });
            e.size = r.uintLessThan(u32, 4097);
        }
        try many.append(arena, .{ .e = e, .off = r.uintLessThan(usize, pool.len - 4096) });
    }
    c.items = many.items;
    c.many = try build(arena, many.items, pool, .gnu);

    var paxs: std.ArrayList(Item) = .empty;
    for (0..1024) |i| {
        const pad_len = 110 + r.uintLessThan(usize, 90);
        const stem = try arena.alloc(u8, pad_len);
        @memset(stem, 'p');
        const e: tar.Entry = .{
            .path = try arena.print("long/{s}/{d:0>4}", .{ stem, i }),
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .mtime = 1_600_000_000 + @as(i64, @intCast(i)),
            .size = r.uintLessThan(u32, 1025),
        };
        try paxs.append(arena, .{ .e = e, .off = r.uintLessThan(usize, pool.len - 4096) });
    }
    c.pax = try build(arena, paxs.items, pool, .pax);

    var big: std.Io.Writer.Allocating = .init(arena);
    const tw = tar.Writer.init(&big.writer);
    const size: u32 = 32 << 20;
    try tw.writeHeader(.{ .path = "big.bin", .mode = 0o644, .uid = 1000, .gid = 1000, .mtime = 1_600_000_000, .size = size });
    var left: usize = size;
    while (left > 0) {
        const n = @min(left, c.chunk.len);
        try big.writer.writeAll(c.chunk[0..n]);
        left -= n;
    }
    try tw.writePadding(size);
    try tw.finish();
    c.big = try big.toOwnedSlice();

    try dir.writeFile(io, .{ .sub_path = "many.tar", .data = c.many });
    try dir.writeFile(io, .{ .sub_path = "pax.tar", .data = c.pax });
    try dir.writeFile(io, .{ .sub_path = "big.tar", .data = c.big });
    std.debug.print("{s}: many.tar {d} B ({d} members), pax.tar {d} B (1024), big.tar {d} B\n", .{ bench_name, c.many.len, c.items.len, c.pax.len, c.big.len });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    const ctx = try arena.create(Ctx);
    ctx.* = .{};
    try setup(arena, io, dir, ctx);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "read_many", .op = .read_many, .ref = "read_many", .wall_only = true },
        .{ .name = "read_pax", .op = .read_pax, .ref = "read_pax", .wall_only = true },
        .{ .name = "read_big", .op = .read_big, .ref = "read_big", .wall_only = true },
        .{ .name = "write_many", .op = .write_many, .ref = "write_many", .wall_only = true },
        .{ .name = "write_big", .op = .write_big, .ref = "write_big", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, s.worst_ref, s.best_ref });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}-{d:.2}x {s} · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card });

    // std.tar: informational, the same process, does less work.
    if (args.len <= 1) {
        const cyc: bench.Cycles = .open();
        defer cyc.close();
        inline for (.{ .{ "read_many", "many" }, .{ "read_pax", "pax" } }) |p| {
            const data: []const u8 = @field(ctx, p[1]);
            const std_ns = bench.timeIt(io, cyc, stdRead, .{data}, true).ns;
            const ours_ns = bench.timeIt(io, cyc, readAll, .{ bench_gpa, data }, true).ns;
            try w.print("{s:<12} std.tar {d:>10.0} ns vs ours {d:>10.0} ns  std/ours {d:.2} (std.tar surfaces no uid/gid/mtime: less work; informational)\n", .{ p[0], std_ns, ours_ns, std_ns / ours_ns });
        }
    }
    try w.flush();
    return 0;
}
