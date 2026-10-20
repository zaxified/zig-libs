// SPDX-License-Identifier: MIT

//! The fuzz driver's cost per input: `fuzz.driver` against a bare seed loop
//! over the same harness, the program behind the `**Performance:**` line of
//! testkit's maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-testkit` runs it (always
//! ReleaseFast). No foreign side: the reference is what a hand-written verdict
//! loop costs — `DefaultPrng.init(seed)`, an `Rng`, the harness, a
//! `SafeAllocator` over the same backing allocator — so the ratio is exactly what the driver adds (watchdog
//! timestamps, the seed file a runner always sets, reach bookkeeping).
//!
//! Workloads, each one batch of 10 000 seeds per op (one driver call: its
//! set-up, the seed file mapped, is paid per call as a runner pays it per
//! harness, here over far fewer seeds than a verdict run), the seeds running on
//! from batch to batch as a runner's do (a seed file is resized only when
//! the seed gains a digit): `hex` — a 160-byte slice
//! decoded by `testkit.hex.into` (as cheap as the collection's harnesses
//! get, so the driver's share is largest); `alloc` — the same plus two
//! allocations through the harness's `SafeAllocator` (the common shape; the
//! driver renews its one per batch of seeds, 2026-10-20).
//! `+seedfile` rows run the driver with a seed file, as `MOD_FUZZ_SEEDFILE`.
//! Method: `testkit.bench.timeIt` on both sides, alternating for
//! `BENCH_ROUNDS` (default 3) rounds, ratio by WALL time: the seed file's
//! cost is kernel time, which user-mode cycles do not count (measured
//! 2026-10-17 before the fix: 1.43× by cycles, 29× by the clock).

const std = @import("std");
const testkit = @import("testkit");
const bench = testkit.bench;
const driver = testkit.fuzz.driver;

const bench_name = "bench-testkit";
const work_dir = ".zig-cache/bench-testkit";
const batch = 10_000;

fn hexHarness(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var sbuf: [160]u8 = undefined;
    const s = sbuf[0..src.slice(&sbuf)];
    for (s) |*b| b.* = "0123456789abcdef"[b.* & 15];
    var out: [80]u8 = undefined;
    _ = testkit.hex.into(&out, s[0 .. s.len & ~@as(usize, 1)]) catch unreachable;
    std.mem.doNotOptimizeAway(&out);
}

fn allocHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var sbuf: [160]u8 = undefined;
    const s = sbuf[0..src.slice(&sbuf)];
    for (s) |*b| b.* = "0123456789abcdef"[b.* & 15];
    const a = try gpa.alloc(u8, s.len / 2 + 1);
    defer gpa.free(a);
    const c = try gpa.dupe(u8, s);
    defer gpa.free(c);
    _ = try testkit.hex.into(a, c[0 .. c.len & ~@as(usize, 1)]);
    std.mem.doNotOptimizeAway(a);
}

const Ctx = struct {
    gpa: std.mem.Allocator,
    seed_fd: ?i32,
    first: u64 = 0,
};

fn bare(comptime harness: anytype) fn (*Ctx) usize {
    return struct {
        fn f(x: *Ctx) usize {
            // The allocator a hand-written 0.17 loop hands its harness: one
            // leak-checking `SafeAllocator` for the run, as the driver's
            // (renewed per batch of seeds there).
            var sa: std.heap.SafeAllocator = .init(x.gpa, .{ .stack_trace_frames = 0 });
            defer _ = sa.deinit();
            for (0..batch) |i| {
                var prng = std.Random.DefaultPrng.init(x.first + i);
                var rng: testkit.fuzz.Rng = .{ .r = prng.random() };
                harness(testkit.fuzz.Rng, &rng, sa.allocator()) catch unreachable;
            }
            x.first += batch;
            return batch;
        }
    }.f;
}

fn viaDriver(comptime harness: anytype, comptime with_seedfile: bool) fn (*Ctx) usize {
    return struct {
        fn f(x: *Ctx) usize {
            driver.runSeedsReporting(harness, "bench", .{ .runs = batch, .first = x.first }, x.gpa, if (with_seedfile) x.seed_fd else null, false) catch unreachable;
            x.first += batch;
            return batch;
        }
    }.f;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var da: std.heap.DebugAllocator(.{ .stack_trace_frames = 0 }) = .init; // global-alloc-ok: the same allocator the driver gives a harness, on both sides of the comparison
    defer _ = da.deinit();
    const seed_path = work_dir ++ "/seed";
    const rc = std.os.linux.open(seed_path, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true }, 0o644);
    const seed_fd: ?i32 = if (std.os.linux.errno(rc) == .SUCCESS) @intCast(rc) else null;
    var ctx: Ctx = .{ .gpa = da.allocator(), .seed_fd = seed_fd };

    // name, ours, ref (a comptime tuple: `timeIt` takes the op at comptime)
    const rows = .{
        .{ "hex", viaDriver(hexHarness, false), bare(hexHarness) },
        .{ "hex+seedfile", viaDriver(hexHarness, true), bare(hexHarness) },
        .{ "alloc", viaDriver(allocHarness, false), bare(allocHarness) },
        .{ "alloc+seedfile", viaDriver(allocHarness, true), bare(allocHarness) },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const cyc: bench.Cycles = .open();
    var s: bench.Summary = .{};
    try w.print("{s:<16} {s:>12} {s:>12} {s:>7} {s:>6} {s:>6}\n", .{ "workload", "driver ns", "bare ns", "/bare", "spr d", "spr b" });
    inline for (rows) |r| {
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        for (0..rounds) |_| {
            ref.add(bench.timeIt(io, cyc, r[2], .{&ctx}, true));
            ours.add(bench.timeIt(io, cyc, r[1], .{&ctx}, true));
        }
        const l = bench.score(ours, ref, null, false);
        s.add(l);
        try w.print("{s:<16} {d:>12.0} {d:>12.0} {d:>7.3} {d:>5.1}% {d:>5.1}%\n", .{ r[0], ours.best_ns / batch, ref.best_ns / batch, l.ref, 100 * ours.spread(l.by_cycles), 100 * ref.spread(l.by_cycles) });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (s.by_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× a bare seed loop (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    if (seed_fd) |fd| _ = std.os.linux.close(fd);
    return 0;
}
