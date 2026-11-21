// SPDX-License-Identifier: MIT

//! Comparative benchmark: `arrow` against pyarrow (Arrow C++), the program
//! behind the `**Performance:**` line of the maturity card.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-arrow` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs python3 with
//! pyarrow (see `tools/interop.zig` for the venv); run from the repository root.
//!
//! One table of `ARROW_BENCH_ROWS` (default 1 000 000) rows -- an Int64 column with a
//! null in every 13th row, a Float64 column and a Utf8 column of short strings --
//! built the same way on both sides, as an IPC stream of 65 536-row record
//! batches. Workloads: `write` (frame / table to the stream bytes in memory),
//! `read` (the stream to a materialised frame / to a table whose chunks are
//! combined into contiguous columns, which is what a `dataframe.Frame` holds) and
//! `read_zc` (pyarrow's zero-copy `read_all` against our materialising read; printed
//! for information, kept out of the verdict). Method (`benchkit`): each side doubles its
//! batch until it takes over 100 ms and keeps the best of five; the sides alternate
//! for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; ratios are ours /
//! theirs by wall time (the foreign side counts no cycles). pyarrow is run
//! single-threaded. The count both sides report is the row count.

const std = @import("std");
const bench = @import("benchkit");
const Work = bench.Work(Op);
const df = @import("dataframe");
const arrow = @import("arrow");

const bench_name = "bench-arrow";
const work_dir = ".zig-cache/bench-arrow";
const Allocator = std.mem.Allocator;

const Op = struct { read: bool = false };

const Ctx = struct {
    gpa: Allocator,
    op: Op,
    frame: df.Frame,
    bytes: []const u8,
};

fn once(c: *Ctx) u64 {
    if (c.op.read) {
        var arena: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena.deinit();
        const f = arrow.readStream(arena.allocator(), c.bytes, .{}) catch unreachable;
        return f.len;
    }
    const b = arrow.writeStream(c.gpa, c.frame, .{}) catch unreachable;
    defer c.gpa.free(b);
    std.mem.doNotOptimizeAway(b.ptr);
    return c.frame.len;
}

fn validBits(a: Allocator, n: usize, nulls: []const usize) ![]u64 {
    const w = try a.alloc(u64, (n + 63) / 64);
    @memset(w, ~@as(u64, 0));
    for (nulls) |i| w[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
    return w;
}

fn textCol(a: Allocator, cells: []const ?[]const u8) !df.TextColumn {
    const offs = try a.alloc(usize, cells.len + 1);
    var bytes: std.ArrayList(u8) = .empty;
    var nulls: std.ArrayList(usize) = .empty;
    offs[0] = 0;
    for (cells, 0..) |c, i| {
        if (c) |t| try bytes.appendSlice(a, t) else try nulls.append(a, i);
        offs[i + 1] = bytes.items.len;
    }
    return .{ .offsets = offs, .bytes = bytes.items, .valid = if (nulls.items.len > 0) try validBits(a, cells.len, nulls.items) else null };
}

fn makeFrame(a: Allocator, n: usize) !df.Frame {
    const ints = try a.alloc(i64, n);
    const floats = try a.alloc(f64, n);
    const offs = try a.alloc(usize, n + 1);
    var text: std.ArrayList(u8) = .empty;
    const valid = try a.alloc(u64, (n + 63) / 64);
    @memset(valid, ~@as(u64, 0));
    offs[0] = 0;
    var tmp: [32]u8 = undefined;
    for (0..n) |i| {
        ints[i] = @intCast((i * 7919) % 1000003);
        if (i % 13 == 0) valid[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
        floats[i] = @as(f64, @floatFromInt(i)) * 0.5 + @as(f64, @floatFromInt(i % 97));
        const s = try std.fmt.bufPrint(&tmp, "row-{d}", .{(i * 31) % 10007});
        try text.appendSlice(a, s);
        offs[i + 1] = text.items.len;
    }
    const cols = [_]df.Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .float }, .{ .name = "c", .type = .text } };
    const data = [_]df.ColumnData{
        .{ .int = .{ .values = ints, .valid = valid } },
        .{ .float = .{ .values = floats } },
        .{ .text = .{ .offsets = offs, .bytes = text.items } },
    };
    return .{ .columns = try a.dupe(df.Column, &cols), .data = try a.dupe(df.ColumnData, &data), .len = n };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;
    const n: usize = if (init.environ_map.get("ARROW_BENCH_ROWS")) |r| try std.fmt.parseInt(usize, r, 10) else 1_000_000;

    var ctx: Ctx = undefined;
    ctx.gpa = std.heap.smp_allocator;
    ctx.frame = try makeFrame(arena, n);
    ctx.bytes = try arrow.writeStream(arena, ctx.frame, .{});
    ctx.op = .{};

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{d} rows; our stream is {d} bytes\n", .{ n, ctx.bytes.len });

    const ws = [_]Work{
        .{ .name = "write", .op = .{}, .ref = "write" },
        .{ .name = "read", .op = .{ .read = true }, .ref = "read" },
        .{ .name = "read_vs_zerocopy", .op = .{ .read = true }, .ref = "read_zc", .info = true },
    };
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{"modules/arrow/tools/bench_pyarrow.sh"}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
    try w.print("reference: {s}\nworst ours/pyarrow = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    try w.flush();
    return 0;
}
