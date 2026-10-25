// SPDX-License-Identifier: MIT

//! Comparative benchmark: `workerpool` against Pithikos/C-Thread-Pool at commit
//! 2b56942a (the reference, pinned unmodified under `tools/c_bench/thpool/`), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-workerpool` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/main.c` + `thpool.c` with `zig cc -O2 -DDISABLE_PRINT
//! -pthread`, nothing else). Run from the repository root.
//!
//! Both sides run ONE pool of 4 workers, created before the timing and
//! destroyed after (thpool keeps global state: one pool per process). Ours:
//! `n_workers = 4`, the default `spin_ns` (50 µs since 2026-10-25; `BENCH_SPIN_NS`
//! overrides it, 0 = park at once). A job adds 1 to a shared atomic counter and
//! its result to a shared atomic sum (the checksum); the job argument is its
//! index + 1 passed as the pointer value. Rows (one op = the whole row):
//!   burst_noop      submit 100 000 no-op jobs from the main thread, then wait
//!   burst_work      the same, ~1 us of work per job (64 rounds of splitmix64)
//!   pingpong        10 000 x (submit one job, wait): wakeup latency
//!   multi_producer  4 producer threads x 25 000 no-op jobs, then wait (ours: one
//!                   `Submitter` per producer, registered before the timing;
//!                   thpool_add_work is thread-safe). Spawning and joining the
//!                   four threads is inside the timing on both sides.
//!   inline          the 100 000 no-op jobs run directly on the caller, no pool:
//!                   the floor both sides share. INFO ONLY, not in the verdict.
//! Both sides print count and sum per row and the run fails unless they agree.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/thpool by wall time; the verdict is the
//! WORST ratio over the four pool rows. Arguments filter rows by name part.
//!
//! Fastest in the field (skipped with arguments or BENCH_FAST=0): the four
//! pool rows against rayon-core 1.13.0 and threadpool 1.8.1
//! (`tools/rust_fast_bench`, needs cargo and the crates fetched) and
//! panjf2000/ants v2.12.0 (`tools/go_fast_bench`, needs go and the module
//! cached), each in its own idiom (see those programs). The card's `fastest`
//! is the worst row's ratio to its fastest contender.
//!
//! Not like-for-like, by design (neither side is tuned around it): thpool does a
//! malloc/free per job under a mutex-protected queue and wakes workers through a
//! binary semaphore (mutex + condvar), ours carries the job by value in a lock-free queue
//! and parks on a futex; thpool's `thpool_wait` is a condvar wait that every
//! finishing worker signals, ours a futex wait that costs a worker one load
//! when nobody waits.

const std = @import("std");
const workerpool = @import("workerpool");

const bench_name = "bench-workerpool";
const work_dir = ".zig-cache/bench-workerpool";
const c_dir = "modules/workerpool/tools/c_bench";
const ref_short = "thpool";
const ref_card = "Pithikos/C-Thread-Pool 2b56942a";

const names = [_][]const u8{ "burst_noop", "burst_work", "pingpong", "multi_producer", "inline" };
const info_only = [_][]const u8{"inline"};
const n_workers = 4;
const burst = 100_000;
const pingpong_n = 10_000;
const producers = 4;
const per_producer = 25_000;

var g_count: std.atomic.Value(u64) = .init(0);
var g_sum: std.atomic.Value(u64) = .init(0);

fn splitmix64(x: *u64) u64 {
    x.* +%= 0x9e3779b97f4a7c15;
    var z = x.*;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

fn argPtr(i: usize) *anyopaque {
    return @ptrFromInt(i + 1);
}

fn jobNoop(ctx: *anyopaque) void {
    _ = g_count.fetchAdd(1, .monotonic);
    _ = g_sum.fetchAdd(@intFromPtr(ctx), .monotonic);
}

fn jobWork(ctx: *anyopaque) void {
    var s: u64 = @intFromPtr(ctx);
    var h: u64 = 0;
    for (0..64) |_| h ^= splitmix64(&s);
    _ = g_count.fetchAdd(1, .monotonic);
    _ = g_sum.fetchAdd(h, .monotonic);
}

const Ours = struct {
    pool: *workerpool.WorkerPool,
    subs: [producers]workerpool.Submitter,
};

fn produce(sub: *workerpool.Submitter, base: usize) void {
    for (0..per_producer) |i| sub.submit(.{ .func = jobNoop, .ctx = argPtr(base + i) }) catch unreachable;
}

/// One op of row `w`; the counters hold its result afterwards.
fn once(o: *Ours, w: usize) void {
    g_count.store(0, .seq_cst);
    g_sum.store(0, .seq_cst);
    switch (w) {
        0 => {
            for (0..burst) |i| o.pool.submit(.{ .func = jobNoop, .ctx = argPtr(i) }) catch unreachable;
            _ = o.pool.wait();
        },
        1 => {
            for (0..burst) |i| o.pool.submit(.{ .func = jobWork, .ctx = argPtr(i) }) catch unreachable;
            _ = o.pool.wait();
        },
        2 => for (0..pingpong_n) |i| {
            o.pool.submit(.{ .func = jobNoop, .ctx = argPtr(i) }) catch unreachable;
            _ = o.pool.wait();
        },
        3 => {
            var threads: [producers]std.Thread = undefined;
            for (&threads, &o.subs, 0..) |*t, *s, k| t.* = std.Thread.spawn(.{}, produce, .{ s, k * per_producer }) catch unreachable;
            for (threads) |t| t.join();
            _ = o.pool.wait();
        },
        4 => {
            // An indirect call, as the pool makes it: the compiler may not see
            // through `f`.
            var f: *const fn (*anyopaque) void = jobNoop;
            std.mem.doNotOptimizeAway(&f);
            for (0..burst) |i| f(argPtr(i));
        },
        else => unreachable,
    }
}

const Row = struct { ns: f64, count: u64, sum: u64 };

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    sum: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
        s.sum = r.sum;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

fn timeIt(io: std.Io, o: *Ours, w: usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| once(o, w);
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| once(o, w);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{
        .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)),
        .count = g_count.load(.seq_cst),
        .sum = g_sum.load(.seq_cst),
    };
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

    const exe = try ccBuild(arena, io, abs);

    const pool = try workerpool.WorkerPool.init(std.heap.smp_allocator, .{
        .io = io,
        .n_workers = n_workers,
        .spin_ns = if (init.environ_map.get("BENCH_SPIN_NS")) |s| try std.fmt.parseInt(u64, s, 10) else (workerpool.Options{ .io = io }).spin_ns,
        .max_submitters = producers,
    });
    defer pool.deinit();
    var o: Ours = .{ .pool = pool, .subs = undefined };
    for (&o.subs) |*s| s.* = try pool.registerSubmitter();
    defer for (&o.subs) |*s| s.deinit();

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<16} {s:>12} {s:>12} {s:>8} {s:>7} {s:>7}  count / sum\n", .{ "workload", "ours ns", ref_short ++ " ns", "ratio", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: Side = .{};
        var ref: Side = .{};
        for (0..rounds) |_| {
            ref.add(try ccRun(arena, io, exe, name));
            ours.add(timeIt(io, &o, wi));
        }
        const ratio = ours.best_ns / ref.best_ns;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(), ref.spread()));
        const same = ours.count == ref.count and ours.sum == ref.sum;
        mismatch = mismatch or !same;
        try w.print("{s:<16} {d:>12.0} {d:>12.0} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d} / {d}{s}\n", .{
            name,                ours.best_ns,       ref.best_ns, ratio,
            100 * ours.spread(), 100 * ref.spread(), ours.count,  ours.sum,
            if (!same) " ≠ " ++ ref_short else if (info) "  (info only, not in the verdict)" else "",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count or sum differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    if (filters.len > 0 or !use_fast) {
        if (filters.len == 0)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
        try w.flush();
        return 0;
    }

    // ---- fastest in the field: the four pool rows against the contenders ----
    // Per row the verdict is ours over the fastest contender; the card's
    // `fastest` is the worst row.
    try w.flush();
    const go_exe = try goBuild(arena, io, abs, init.environ_map);
    try rustBuild(arena, io, init.environ_map);
    try w.print("\nfastest in the field -- {d} rounds, ours re-timed beside each\n", .{rounds});
    try w.print("{s:<16} {s:<22} {s:>12} {s:>12} {s:>8}  count / sum\n", .{ "workload", "contender", "its ns", "ours ns", "ours/it" });
    var worst_fast: f64 = 0;
    var worst_row: []const u8 = "";
    var worst_who: []const u8 = "";
    for (names[0..4], 0..) |name, wi| {
        var row_ratio: f64 = 0;
        var row_who: []const u8 = "";
        for (fast) |c| {
            var ours: Side = .{};
            var it: Side = .{};
            for (0..rounds) |_| {
                it.add(try foreignRun(arena, io, if (c.rust) |p| &.{ rust_exe, p, name } else &.{ go_exe, name }, name));
                ours.add(timeIt(io, &o, wi));
            }
            const r = ours.best_ns / it.best_ns;
            if (r > row_ratio) {
                row_ratio = r;
                row_who = c.label;
            }
            const same = ours.count == it.count and ours.sum == it.sum;
            mismatch = mismatch or !same;
            try w.print("{s:<16} {s:<22} {d:>12.0} {d:>12.0} {d:>8.3}  {d} / {d}{s}\n", .{ name, c.label, it.best_ns, ours.best_ns, r, it.count, it.sum, if (same) "" else " ≠ ours" });
            try w.flush();
        }
        if (row_ratio > worst_fast) {
            worst_fast = row_ratio;
            worst_row = name;
            worst_who = row_who;
        }
    }
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a contender's count or sum differs from ours; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/fastest = {d:.2} ({s}, {s})\n", .{ worst_fast, worst_row, worst_who });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} ({s}) (measured <today>)\n", .{ best, worst, ref_card, worst_fast, worst_who, worst_row });
    try w.flush();
    return 0;
}

/// A contender: one of the Rust pools (`rust` = its first argument) or ants.
const Fast = struct { label: []const u8, rust: ?[]const u8 };
const fast = [_]Fast{
    .{ .label = "rayon-core 1.13.0", .rust = "rayon" },
    .{ .label = "threadpool 1.8.1", .rust = "threadpool" },
    .{ .label = "ants v2.12.0", .rust = null },
};
const go_dir = "modules/workerpool/tools/go_fast_bench";
const rust_manifest = "modules/workerpool/tools/rust_fast_bench/Cargo.toml";
const rust_target = work_dir ++ "/rust-target";
const rust_exe = rust_target ++ "/release/rust_fast_bench";

/// Build the Go side once, offline (`GOPROXY=off`, `GOTOOLCHAIN=local`; ants
/// in the module cache, pinned by go.sum).
fn goBuild(arena: std.mem.Allocator, io: std.Io, abs: []const u8, environ: *const std.process.Environ.Map) ![]const u8 {
    const exe = try arena.print("{s}/go_fast_bench", .{abs});
    var env = try environ.clone(arena);
    try env.put("GOPROXY", "off");
    try env.put("GOTOOLCHAIN", "local");
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{ .argv = &.{ "go", "build", "-o", exe, "." }, .cwd = .{ .path = go_dir }, .environ_map = &env }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- BENCH_FAST=0 skips the contenders\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// Build the Rust side once, offline (the crates are in the cargo registry
/// after `cargo fetch`; Cargo.lock is committed).
fn rustBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map) !void {
    var env = try environ.clone(arena);
    try env.put("CARGO_NET_OFFLINE", "true");
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--locked", "--manifest-path", rust_manifest, "--target-dir", rust_target },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- BENCH_FAST=0 skips the contenders\n", .{ bench_name, e });
        return error.RustBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.RustBuildFailed;
    }
}

/// Build the C side once, so the timed runs do not pay for it.
fn ccBuild(arena: std.mem.Allocator, io: std.Io, abs: []const u8) ![]const u8 {
    const exe = try arena.print("{s}/thpool_bench", .{abs});
    std.debug.print("{s}: building the C side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "zig", "cc", "-O2", "-DDISABLE_PRINT", "-pthread", c_dir ++ "/main.c", c_dir ++ "/thpool/thpool.c", "-o", exe },
    }) catch |e| {
        std.debug.print("{s}: could not run zig cc ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.CcBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CcBuildFailed;
    }
    return exe;
}

/// Run the C side for one workload: `<exe> <name>` prints
/// `name \t ns/op \t count \t sum`.
fn ccRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, name: []const u8) !Row {
    return foreignRun(arena, io, &.{ exe, name }, name);
}

/// Run a foreign side (`argv` ends with the workload) and parse its line, as
/// `ccRun` describes.
fn foreignRun(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = argv });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed on {s}:\n{s}\n", .{ bench_name, argv[0], name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    const sum = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count, .sum = sum };
}
