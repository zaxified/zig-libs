// SPDX-License-Identifier: MIT

//! Comparative benchmark: `crc32` against zlib's `crc32_z` (the reference) and
//! Go's `hash/crc32` (hardware-accelerated; a candidate for the fastest in the
//! field), the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-crc32` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/zlib_bench.c` with `zig cc` against the system
//! zlib: `zlib.h` + `libz.so`) and go 1.26.0 (standard library only). Run
//! from the repository root.
//!
//! One op = one CRC of a 64 B / 1 KiB / 64 KiB / 1 MiB slice of the same
//! random buffer (`.zig-cache/bench-crc32/data.bin`, fixed seed). Every side
//! doubles the batch until it takes over 100 ms and keeps the best of five,
//! and reports the CRC itself, which must agree. The card's `ref` is the worst
//! ratio against zlib. Go is printed beside it but is NOT recorded as the
//! fastest: zlib-ng and crc32fast (not measured here) are the candidates.

const std = @import("std");
const crc32 = @import("crc32");

const work_dir = ".zig-cache/bench-crc32";
const names = [_][]const u8{ "crc_64", "crc_1k", "crc_64k", "crc_1m" };
const sizes = [_]usize{ 64, 1024, 65536, 1 << 20 };

const Row = struct { ns: f64, count: u64 };

fn timeIt(io: std.Io, data: []const u8) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(crc32.hash(data));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var crc: u32 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            crc = crc32.hash(data);
            std.mem.doNotOptimizeAway(crc);
        }
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = crc };
}

/// Run a foreign side and parse its `name\tns\tcount` lines.
fn foreign(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, argv: []const []const u8, cwd: ?[]const u8) !std.StringHashMapUnmanaged(Row) {
    const res = try std.process.run(arena, io, .{
        .argv = argv,
        .environ_map = env,
        .cwd = if (cwd) |c| .{ .path = c } else .inherit,
    });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-crc32: {s} failed:\n{s}\n", .{ argv[0], res.stderr });
        return error.ForeignSideFailed;
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
    return rows;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const data = try arena.alloc(u8, 1 << 20);
    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_c3c3);
    prng.random().bytes(data);
    try dir.writeFile(io, .{ .sub_path = "data.bin", .data = data });
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");

    std.debug.print("bench-crc32: building the zlib side ...\n", .{});
    const exe = try std.fmt.allocPrint(arena, "{s}/zlib_bench", .{abs});
    const cc = try std.process.run(arena, io, .{
        .argv = &.{ "zig", "cc", "-O3", "-march=native", "modules/crc32/tools/c_bench/zlib_bench.c", "-lz", "-o", exe },
        .environ_map = &env,
    });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-crc32: zig cc failed (needs zlib.h and libz):\n{s}\n", .{cc.stderr});
        return 1;
    }
    std.debug.print("bench-crc32: zlib ...\n", .{});
    const zlib = foreign(arena, io, &env, &.{ exe, abs }, null) catch return 1;
    std.debug.print("bench-crc32: Go hash/crc32 ...\n", .{});
    const go = foreign(arena, io, &env, &.{ "go", "run", ".", abs }, "modules/crc32/tools/go_bench") catch return 1;

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<8} {s:>12} {s:>12} {s:>12} {s:>9} {s:>8}  crc\n", .{ "workload", "ours ns/op", "zlib ns/op", "go ns/op", "ours/zlib", "ours/go" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var worst_go: f64 = 0;
    var mismatch = false;
    for (names, sizes) |name, size| {
        const ours = timeIt(io, data[0..size]);
        const z = zlib.get(name) orelse return error.MissingRow;
        const g = go.get(name) orelse return error.MissingRow;
        const r = ours.ns / z.ns;
        worst = @max(worst, r);
        best = @min(best, r);
        worst_go = @max(worst_go, ours.ns / g.ns);
        const same = ours.count == z.count and ours.count == g.count;
        if (!same) mismatch = true;
        try w.print("{s:<8} {d:>12.1} {d:>12.1} {d:>12.1} {d:>9.2} {d:>8.2}  {x:0>8}{s}\n", .{ name, ours.ns, z.ns, g.ns, r, ours.ns / g.ns, ours.count, if (same) "" else " ≠" });
        try w.flush();
    }
    if (mismatch) {
        try w.writeAll("bench-crc32: FAILED -- a CRC differs between the sides\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/zlib = {d:.2} (best {d:.2}); worst ours/go = {d:.2}\n", .{ worst, best, worst_go });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× zlib crc32_z · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
