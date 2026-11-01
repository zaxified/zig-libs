// SPDX-License-Identifier: MIT

//! Comparative benchmark: `filestore` against peterbourgon/diskv v3.0.0 (the
//! reference, `tools/go_bench`), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-filestore` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! github.com/peterbourgon/diskv/v3 v3.0.0 (+ google/btree v1.0.0) in the
//! module cache (pinned by `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`).
//! Run from the repository root: the stores live in `.zig-cache/bench-filestore`
//! on the REAL disk — on tmpfs an `fsync` is free and flatters both sides.
//!
//! One op = 16 records of 1 KiB (keys k00..k15), except `keys` (one walk over
//! 1,000 records). Like for like by DURABILITY: diskv's atomic mode (TempDir)
//! never fsyncs a directory, so its strongest level is ours `.data`:
//!   put_none  ours `.none` (temp + rename)      vs diskv `Write`
//!   put_data  ours `.data` (+ fsync of the file) vs diskv `WriteStream(sync)`
//!   put_full  ours `.full` (+ fsync of the dir)  vs diskv `WriteStream(sync)`:
//!             INFO only — diskv has no such level, the row prices ours
//!   get       `getBytes` (`ttl = false`, as diskv has no TTL) vs `Read`
//!   has       `has` (`ttl = false`) vs `Has`
//!   keys      `iterate` drained vs `Keys(nil)` drained
//! The count is bytes written or read, or records found; the sides must agree.

const std = @import("std");
const bench = @import("testkit").bench;
const filestore = @import("filestore");

const bench_name = "bench-filestore";
const work_dir = ".zig-cache/bench-filestore";
const go_dir = "modules/filestore/tools/go_bench";
const ref_card = "peterbourgon/diskv v3.0.0 (TempDir atomic mode)";

const n_rec = 16;
const rec_len = 1024;
const n_keys = 1000;

const Op = enum { put_none, put_data, put_full, get, has, keys };

const Ctx = struct {
    op: Op = .get,
    store: filestore.Store,
    keys: [n_rec][]const u8,
    val: []const u8,
    arena: *std.heap.ArenaAllocator,
};

fn once(c: *Ctx) u64 {
    return run(c) catch |e| std.debug.panic("{s}: {t}", .{ bench_name, e });
}

fn run(c: *Ctx) !u64 {
    var sum: u64 = 0;
    switch (c.op) {
        .put_none, .put_data, .put_full => {
            var s = c.store;
            s.durability = switch (c.op) {
                .put_none => .none,
                .put_data => .data,
                else => .full,
            };
            for (c.keys) |k| {
                try s.putBytes("w", k, c.val);
                sum += rec_len;
            }
        },
        .get => {
            _ = c.arena.reset(.retain_capacity);
            for (c.keys) |k| sum += (try c.store.getBytes(c.arena.allocator(), "r", k)).?.len;
        },
        .has => for (c.keys) |k| {
            if (try c.store.has("r", k)) sum += 1;
        },
        .keys => {
            var it = try c.store.iterate("many");
            defer it.deinit();
            while (try it.next()) |_| sum += 1;
        },
    }
    return sum;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    const base = try arena.print("{s}/zig-store", .{abs});
    var store = try filestore.Store.init(io, base);
    store.ttl = false;
    var keys: [n_rec][]const u8 = undefined;
    for (&keys, 0..) |*k, i| k.* = try arena.print("k{d:0>2}", .{i});
    const val = try arena.alloc(u8, rec_len);
    @memset(val, 'v');
    // Read side: 16 records; walk side: 1,000 small ones (as the Go side).
    for (keys) |k| try store.putBytes("r", k, val);
    var mk_store = store;
    mk_store.durability = .none;
    for (0..n_keys) |i| try mk_store.putBytes("many", try arena.print("key{d:0>4}", .{i}), val[0..16]);

    var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();
    var ctx: Ctx = .{ .store = store, .keys = keys, .val = val, .arena = &scratch };

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "put_none", .op = .put_none, .ref = "put_none", .wall_only = true },
        .{ .name = "put_data", .op = .put_data, .ref = "put_data", .wall_only = true },
        .{ .name = "put_full", .op = .put_full, .ref = "put_full", .wall_only = true, .info = true },
        .{ .name = "get", .op = .get, .ref = "get", .wall_only = true },
        .{ .name = "has", .op = .has, .ref = "has", .wall_only = true },
        .{ .name = "keys", .op = .keys, .ref = "keys", .wall_only = true },
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
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/diskv = {d:.2} (best {d:.2})\n", .{ s.worst_ref, s.best_ref });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest not measured (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card });
    try w.flush();
    return 0;
}
