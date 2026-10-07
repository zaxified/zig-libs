// SPDX-License-Identifier: MIT

//! Comparative benchmark: `zstd` against libzstd (the reference), the program
//! behind the `**Performance:**` line of the maturity card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-zstd` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/libzstd_bench.c` with `zig cc`), the system
//! libzstd (`libzstd.so.1`, path below or `LIBZSTD_SO`; no headers needed) and
//! the Silesia corpus: `ZSTD_BENCH_CORPUS=<dir>`, default
//! `.zig-cache/zstd-compare/silesia` (fetch it from
//! https://sun.aei.polsl.pl//~sdeor/corpus/silesia.zip and unzip there). Run
//! from the repository root; takes several minutes.
//!
//! Workloads: four Silesia files of different kinds (dickens: English text,
//! xml, x-ray: medical image, ooffice: executable), each compressed one-shot at
//! levels 1, 3 and 19 and its level-3 and level-19 frames decompressed, every
//! side on one reused context. Both sides double the batch until it takes over
//! 100 ms and keep the best of five. A compressed size must equal libzstd's to
//! the byte (the module emits libzstd's frames), a decompressed size the
//! input's; otherwise the run fails.

const std = @import("std");
const zstd = @import("zstd");

const work_dir = ".zig-cache/bench-zstd";
const default_so = "/usr/lib/x86_64-linux-gnu/libzstd.so.1";
const files = [_][]const u8{ "dickens", "xml", "x-ray", "ooffice" };
const Op = struct { tag: []const u8, decompress: bool, level: i32 };
const ops = [_]Op{
    .{ .tag = "c1", .decompress = false, .level = 1 },
    .{ .tag = "c3", .decompress = false, .level = 3 },
    .{ .tag = "c19", .decompress = false, .level = 19 },
    .{ .tag = "d3", .decompress = true, .level = 3 },
    .{ .tag = "d19", .decompress = true, .level = 19 },
};

const Row = struct { ns: f64, count: u64 };

const Ctx = struct {
    c: *zstd.Compressor,
    d: *zstd.Decompressor,
    src: []const u8,
    frame: []const u8,
    out: []u8,
    op: Op,
};

fn once(x: Ctx) usize {
    if (x.op.decompress) return x.d.decompress(x.out[0..x.src.len], x.frame) catch unreachable;
    return x.c.compress(x.out, x.src, .{ .level = x.op.level }) catch unreachable;
}

fn timeIt(io: std.Io, x: Ctx) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(x));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = once(x);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.smp_allocator;

    const corpus = init.environ_map.get("ZSTD_BENCH_CORPUS") orelse ".zig-cache/zstd-compare/silesia";
    const cwd = std.Io.Dir.cwd();
    const corpus_abs = cwd.realPathFileAlloc(io, corpus, arena) catch {
        std.debug.print("bench-zstd: no Silesia corpus at {s} -- see this file's header\n", .{corpus});
        return 1;
    };
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var list: std.Io.Writer.Allocating = .init(arena);
    for (files) |f| for (ops) |op| {
        try list.writer.print("{s}.{s}\t{s}\t{d}\t{s}/{s}\n", .{ f, op.tag, if (op.decompress) "d" else "c", op.level, corpus_abs, f });
    };
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    try dir.writeFile(io, .{ .sub_path = "workloads.tsv", .data = list.written() });

    const so = init.environ_map.get("LIBZSTD_SO") orelse default_so;
    const exe = try std.fmt.allocPrint(arena, "{s}/libzstd_bench", .{abs});
    std.debug.print("bench-zstd: building the libzstd side against {s} ...\n", .{so});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O3", "-march=native", "modules/zstd/tools/c_bench/libzstd_bench.c", so, "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-zstd: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    std.debug.print("bench-zstd: libzstd (minutes) ...\n", .{});
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-zstd: libzstd side failed:\n{s}\n", .{res.stderr});
        return 1;
    }
    var rows: std.StringHashMapUnmanaged(Row) = .empty;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try rows.put(arena, name, .{ .ns = ns, .count = count });
    }

    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("reference: {s}", .{res.stderr});
    try w.print("{s:<12} {s:>14} {s:>14} {s:>10}  bytes\n", .{ "workload", "ours ns/op", "libzstd ns/op", "ours/lib" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    for (files) |fname| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ corpus_abs, fname });
        const src = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 30));
        defer gpa.free(src);
        const out = try gpa.alloc(u8, zstd.compressBound(src.len));
        defer gpa.free(out);
        for (ops) |op| {
            const frame_buf = try gpa.alloc(u8, zstd.compressBound(src.len));
            defer gpa.free(frame_buf);
            const flen = try c.compress(frame_buf, src, .{ .level = op.level });
            const ours = timeIt(io, .{ .c = &c, .d = &d, .src = src, .frame = frame_buf[0..flen], .out = out, .op = op });
            const name = try std.fmt.allocPrint(arena, "{s}.{s}", .{ fname, op.tag });
            const t = rows.get(name) orelse return error.MissingRow;
            const ratio = ours.ns / t.ns;
            worst = @max(worst, ratio);
            best = @min(best, ratio);
            const same = ours.count == t.count;
            if (!same) mismatch = true;
            try w.print("{s:<12} {d:>14.0} {d:>14.0} {d:>10.2}  {d}{s}\n", .{ name, ours.ns, t.ns, ratio, ours.count, if (same) "" else " ≠ libzstd" });
            try w.flush();
        }
    }
    if (mismatch) {
        try w.writeAll("bench-zstd: FAILED -- an output size differs from libzstd's\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/libzstd = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libzstd <version> · fastest ref (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
