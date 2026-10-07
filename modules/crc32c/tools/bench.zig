// SPDX-License-Identifier: MIT

//! Comparative benchmark: `crc32c` against Go's `hash/crc32` with the
//! Castagnoli table (the reference; SSE4.2 on amd64), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-crc32c` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (standard library only). Run from the repository root.
//!
//! One op = one CRC of a 64 B / 1 KiB / 64 KiB / 1 MiB slice of the same
//! random buffer (`.zig-cache/bench-crc32c/data.bin`, fixed seed). Both sides
//! double the batch until it takes over 100 ms and keep the best of five, and
//! report the CRC itself, which must agree. google/crc32c (the other reference
//! in the survey) is not measured here, so the fastest stays unrecorded.

const std = @import("std");
const crc32c = @import("crc32c");

const work_dir = ".zig-cache/bench-crc32c";
const names = [_][]const u8{ "crc_64", "crc_1k", "crc_64k", "crc_1m" };
const sizes = [_]usize{ 64, 1024, 65536, 1 << 20 };

const Row = struct { ns: f64, count: u64 };

fn timeIt(io: std.Io, data: []const u8) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(crc32c.hash(data));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var crc: u32 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            crc = crc32c.hash(data);
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
        std.debug.print("bench-crc32c: {s} failed:\n{s}\n", .{ argv[0], res.stderr });
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

    std.debug.print("bench-crc32c: Go hash/crc32 Castagnoli ...\n", .{});
    const go = foreign(arena, io, &env, &.{ "go", "run", ".", abs }, "modules/crc32c/tools/go_bench") catch return 1;

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<8} {s:>12} {s:>12} {s:>8}  crc\n", .{ "workload", "ours ns/op", "go ns/op", "ours/go" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    for (names, sizes) |name, size| {
        const ours = timeIt(io, data[0..size]);
        const g = go.get(name) orelse return error.MissingRow;
        const r = ours.ns / g.ns;
        worst = @max(worst, r);
        best = @min(best, r);
        const same = ours.count == g.count;
        if (!same) mismatch = true;
        try w.print("{s:<8} {d:>12.1} {d:>12.1} {d:>8.2}  {x:0>8}{s}\n", .{ name, ours.ns, g.ns, r, ours.count, if (same) "" else " ≠" });
        try w.flush();
    }
    if (mismatch) {
        try w.writeAll("bench-crc32c: FAILED -- a CRC differs between the sides\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/go = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go hash/crc32 Castagnoli · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
