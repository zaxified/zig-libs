// SPDX-License-Identifier: MIT

//! Comparative benchmark: `fastmem.set` against musl's `memset` (the
//! reference) and glibc's `memset` (a candidate for the fastest in the field),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-fastmem` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/memset_bench.c` twice with `zig cc`: glibc,
//! dynamic) and `musl-gcc` (static musl). Run from the repository root.
//!
//! One op = one `memset` of 16 B / 256 B / 4 KiB / 64 KiB / 1 MiB, with the
//! destination 64-byte aligned ("a") and 5 bytes past that ("u"), of the same
//! canvas (`.zig-cache/bench-fastmem/canvas.bin`, fixed seed). Every side
//! calls through a runtime function pointer, so the call is a real call on all
//! of them, doubles the batch until it takes over 100 ms and keeps the best of
//! five. Per workload the three sides alternate for `BENCH_ROUNDS` (default 3)
//! rounds -- the C sides are re-run with the workload's name each round -- and
//! each keeps its best round; the spread printed is (worst round - best round)
//! / best round per side, so a noisy run shows itself instead of moving the
//! ratio. Before timing, each side memsets the pristine canvas once and
//! fingerprints the whole canvas (FNV-1a), which must agree: a benchmark of
//! two functions that write different bytes measures nothing. The extra column
//! is Zig's compiler_rt `@memset` (what a libc-free binary gets today), shown
//! for context and not part of the card's ratio.

const std = @import("std");
const fastmem = @import("fastmem");

const work_dir = ".zig-cache/bench-fastmem";
const pat: u8 = 0xA5;
const canvas_len = (1 << 20) + 256;
const misalign = 5;

const sizes = [_]usize{ 16, 256, 4096, 65536, 1 << 20 };
const snames = [_][]const u8{ "16", "256", "4k", "64k", "1m" };

const Row = struct { ns: f64, count: u64 };

const SetFn = *const fn ([*]u8, u8, usize) void;

fn rtSet(p: [*]u8, c: u8, n: usize) void {
    @memset(p[0..n], c);
}

fn fnv(b: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (b) |x| h = (h ^ x) *% 0x100000001b3;
    return h;
}

/// Best and worst of the rounds of one side.
const Side = struct {
    best: f64 = std.math.inf(f64),
    worst: f64 = 0,

    fn add(s: *Side, ns: f64) void {
        s.best = @min(s.best, ns);
        s.worst = @max(s.worst, ns);
    }

    fn spread(s: Side) f64 {
        return (s.worst - s.best) / s.best;
    }
};

fn timeIt(io: std.Io, f0: SetFn, p: [*]u8, len: usize) f64 {
    var f = f0;
    std.mem.doNotOptimizeAway(&f); // an opaque target: the call stays a call
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| f(p, pat, len);
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| f(p, pat, len);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

/// Run a foreign side and parse its `name\tns\tcount` lines.
fn foreign(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !std.StringHashMapUnmanaged(Row) {
    const res = try std.process.run(arena, io, .{ .argv = argv });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-fastmem: {s} failed:\n{s}\n", .{ argv[0], res.stderr });
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

fn build(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    const cc = try std.process.run(arena, io, .{ .argv = argv });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-fastmem: {s} failed:\n{s}\n", .{ argv[0], cc.stderr });
        return error.CompileFailed;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const pristine = try arena.alloc(u8, canvas_len);
    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_3e3e);
    prng.random().bytes(pristine);
    try dir.writeFile(io, .{ .sub_path = "canvas.bin", .data = pristine });
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    const src = "modules/fastmem/tools/c_bench/memset_bench.c";
    const musl_exe = try arena.print("{s}/memset_musl", .{abs});
    const glibc_exe = try arena.print("{s}/memset_glibc", .{abs});
    std.debug.print("bench-fastmem: building the musl and glibc sides ...\n", .{});
    build(arena, io, &.{ "musl-gcc", "-O2", "-static", "-fno-builtin", src, "-o", musl_exe }) catch return 1;
    build(arena, io, &.{ "zig", "cc", "-O2", "-fno-builtin", src, "-o", glibc_exe }) catch return 1;
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    // 64-byte aligned canvas; the memset target sits 64 bytes in (+ misalign).
    const canvas = try arena.alignedAlloc(u8, .@"64", canvas_len);

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<9} {s:>10} {s:>10} {s:>10} {s:>10} {s:>9} {s:>9} {s:>9} {s:>7} {s:>7} {s:>7}\n", .{ "workload", "ours ns", "musl ns", "glibc ns", "crt ns", "ours/musl", "ours/glibc", "crt/ours", "spr us", "spr mu", "spr gl" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var worst_g: f64 = 0;
    var best_g: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    for (sizes, snames) |len, sn| {
        for ([_]bool{ false, true }) |mis| {
            const name = try arena.print("set_{s}_{s}", .{ sn, if (mis) "u" else "a" });
            const mis_off: usize = misalign;
            const off: usize = 64 + if (mis) mis_off else 0;
            @memcpy(canvas, pristine);
            fastmem.set(canvas.ptr + off, pat, len);
            const h = fnv(canvas);
            const p = canvas.ptr + off;

            // The sides alternate, `rounds` times, each keeping its best.
            var ours: Side = .{};
            var m: Side = .{};
            var g: Side = .{};
            var same = true;
            for (0..rounds) |_| {
                ours.add(timeIt(io, &fastmem.set, p, len));
                const mr = (foreign(arena, io, &.{ musl_exe, abs, name }) catch return 1).get(name) orelse return error.MissingRow;
                m.add(mr.ns);
                const gr = (foreign(arena, io, &.{ glibc_exe, abs, name }) catch return 1).get(name) orelse return error.MissingRow;
                g.add(gr.ns);
                if (h != mr.count or h != gr.count) same = false;
            }
            if (!same) mismatch = true;
            const crt = timeIt(io, &rtSet, p, len);

            const r = ours.best / m.best;
            const rg = ours.best / g.best;
            worst = @max(worst, r);
            best = @min(best, r);
            worst_g = @max(worst_g, rg);
            best_g = @min(best_g, rg);
            max_spread = @max(max_spread, @max(ours.spread(), @max(m.spread(), g.spread())));
            try w.print("{s:<9} {d:>10.2} {d:>10.2} {d:>10.2} {d:>10.2} {d:>9.2} {d:>9.2} {d:>9.1} {d:>6.1}% {d:>6.1}% {d:>6.1}%{s}\n", .{ name, ours.best, m.best, g.best, crt, r, rg, crt / ours.best, 100 * ours.spread(), 100 * m.spread(), 100 * g.spread(), if (same) "" else "  ≠ BYTES DIFFER" });
            try w.flush();
        }
    }
    try w.print("rounds: {d}; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll("bench-fastmem: FAILED -- a memset wrote different bytes than the libc ones\n");
        try w.flush();
        return 1;
    }
    try w.print("\nours/musl {d:.2}–{d:.2} (worst {d:.2}); ours/glibc {d:.2}–{d:.2} (worst {d:.2})\n", .{ best, worst, worst, best_g, worst_g, worst_g });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× musl memset · fastest {d:.2}–{d:.2}× glibc memset (measured <date of this run>)\n", .{ best, worst, best_g, worst_g });
    try w.flush();
    return 0;
}
