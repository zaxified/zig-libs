// SPDX-License-Identifier: MIT

//! Comparative benchmark: `resilience` against the Go libraries its maturity
//! card compares with -- sony/gobreaker v2 (consecutive-failure breaker),
//! failsafe-go (breaker incl. ratio threshold, bulkhead, retry executor) and
//! cenkalti/backoff (delay schedule). The card's Scope reference is
//! resilience4j (Java); the owner chose these Go libraries as the measured
//! comparators (2026-10-16). CONVENTIONS.md §9, kept instrument kind 3.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-resilience` runs it
//! (always ReleaseFast). Needs `go` 1.26 and the three Go modules in the
//! module cache (`tools/go_bench/go.sum` pins them; built with
//! `GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0`). Run from the repository
//! root.
//!
//! Workloads (ours / ref / alt):
//! - `breaker_pair` -- a closed breaker's admit + success report, 1000 per
//!   op: `CircuitBreaker.allow` + `onSuccess` / gobreaker TwoStep `Allow` +
//!   `done(nil)` / failsafe-go `TryAcquirePermit` + `RecordSuccess`;
//! - `breaker_pair_8t` -- the same on one breaker from 8 threads x 100000
//!   (by wall time: a cycle counter sees one thread);
//! - `rate_pair` -- `RateCircuitBreaker(100)` (count window, 50 %) / failsafe-go
//!   `WithFailureThresholdRatio(50, 100)`;
//! - `bulkhead_pair`, `bulkhead_pair_8t` -- `tryAcquire` + `release` /
//!   failsafe-go `TryAcquirePermit` + `ReleasePermit`;
//! - `run_breaker` -- `run(no-op, .{ .breaker })` / gobreaker `Execute`;
//! - `run_retry_breaker` -- `run(no-op, .{ .breaker, .retry })` /
//!   `failsafe.With(retry, breaker).Get`;
//! - `schedule` -- ten delays of a 100 ms x2 schedule capped at 30 s with
//!   ±50 % jitter (`Retry.nextDelayFrom` fed `DefaultPrng.next()`,
//!   `.proportional`; through `std.Random` it is 1.24×) / cenkalti
//!   `ExponentialBackOff` Reset + 10 `NextBackOff`.
//!
//! Method: the shared driver below (same as every module's bench): each side
//! doubles its batch past 100 ms, keeps the best of five, the sides alternate
//! for `BENCH_ROUNDS` (default 3) rounds.

const std = @import("std");
const resilience = @import("resilience");

const bench_name = "bench-resilience";
const work_dir = ".zig-cache/bench-resilience";
const go_dir = "modules/resilience/tools/go_bench";
const inner = 1000;
const inner8 = 100_000;
const threads = 8;

const Op = enum { breaker_pair, breaker_pair_8t, rate_pair, bulkhead_pair, bulkhead_pair_8t, run_breaker, run_retry_breaker, schedule };

const Noop = struct {
    pub fn call(_: *Noop) error{Never}!u32 {
        return 1;
    }
};

const Ctx = struct {
    cb: resilience.CircuitBreaker,
    rate: resilience.RateCircuitBreaker(100),
    bh: resilience.Bulkhead,
    prng: std.Random.DefaultPrng,
    op: Op = undefined,
};

fn pairs(cb: *resilience.CircuitBreaker, n: usize) void {
    for (0..n) |_| {
        if (!cb.allow()) @panic("refused");
        cb.onSuccess();
    }
}

fn bulk(bh: *resilience.Bulkhead, n: usize) void {
    for (0..n) |_| {
        if (bh.tryAcquire()) bh.release();
    }
}

fn par(comptime f: anytype, arg: anytype) usize {
    var ts: [threads]std.Thread = undefined;
    for (&ts) |*t| t.* = std.Thread.spawn(.{}, f, .{ arg, inner8 }) catch @panic("spawn");
    for (ts) |t| t.join();
    return threads * inner8;
}

fn threaded(op: Op) bool {
    return op == .breaker_pair_8t or op == .bulkhead_pair_8t;
}

fn once(x: *Ctx) usize {
    switch (x.op) {
        .breaker_pair => {
            pairs(&x.cb, inner);
            return inner;
        },
        .breaker_pair_8t => return par(pairs, &x.cb),
        .rate_pair => {
            for (0..inner) |_| {
                if (!x.rate.allow()) @panic("refused");
                x.rate.onSuccess();
            }
            return inner;
        },
        .bulkhead_pair => {
            bulk(&x.bh, inner);
            return inner;
        },
        .bulkhead_pair_8t => return par(bulk, &x.bh),
        .run_breaker, .run_retry_breaker => {
            var noop: Noop = .{};
            var s: usize = 0;
            const policy: resilience.Policy = .{
                .breaker = x.cb.handle(),
                .retry = if (x.op == .run_retry_breaker) .{ .max_attempts = 3, .base_delay_ms = 100 } else null,
            };
            for (0..inner) |_| s += resilience.run(&noop, policy) catch @panic("run");
            return s;
        },
        .schedule => {
            const r: resilience.Retry = .{ .base_delay_ms = 100, .factor = 2, .max_delay_ms = 30_000, .jitter = .proportional, .jitter_factor = 0.5 };
            var s: u64 = 0;
            for (0..inner) |_| {
                for (1..11) |k| s +%= r.nextDelayFrom(@intCast(k), x.prng.next());
            }
            std.mem.doNotOptimizeAway(s);
            return inner * 10;
        },
    }
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

    var ctx: Ctx = .{
        .cb = .init(.{ .failure_threshold = 5 }),
        .rate = .init(.{ .failure_rate_pct = 50 }),
        .bh = .init(.{ .max_concurrent = threads * 2 }),
        .prng = .init(0x7e5),
    };
    const go_exe = try buildGo(arena, io, init.environ_map, abs) orelse return 1;

    const ws = [_]Work{
        .{ .name = "breaker_pair", .op = .breaker_pair, .ref = "breaker_pair", .alt = "breaker_pair_alt" },
        .{ .name = "breaker_pair_8t", .op = .breaker_pair_8t, .ref = "breaker_pair_8t", .alt = "breaker_pair_8t_alt" },
        .{ .name = "rate_pair", .op = .rate_pair, .ref = "rate_pair" },
        .{ .name = "bulkhead_pair", .op = .bulkhead_pair, .ref = "bulkhead_pair" },
        .{ .name = "bulkhead_pair_8t", .op = .bulkhead_pair_8t, .ref = "bulkhead_pair_8t" },
        .{ .name = "run_breaker", .op = .run_breaker, .ref = "run_breaker" },
        .{ .name = "run_retry_breaker", .op = .run_retry_breaker, .ref = "run_retry_breaker" },
        .{ .name = "schedule", .op = .schedule, .ref = "schedule" },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{go_exe}, abs, &ctx, &ws, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/ref = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{
        std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse s.worst_ref,
    });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× gobreaker/failsafe-go/cenkalti (Go <version>) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

/// The Go side, built from `tools/go_bench` with the local toolchain and no
/// network (stdlib only). Null after printing why.
fn buildGo(arena: std.mem.Allocator, io: std.Io, environ: anytype, abs: []const u8) !?[]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    try env.put("CGO_ENABLED", "0");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const build = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return null;
    };
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, build.stderr });
        return null;
    }
    return exe;
}

// ---- comparison driver (the same in every crypto module's tools/bench.zig) ----

/// One timed side: per-op wall time and user-mode cycles (0 = no counter).
const Row = struct { ns: f64, cycles: f64 = 0, count: u64 };

/// Best and worst of the rounds of one side.
const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    best_cyc: f64 = std.math.inf(f64),
    worst_cyc: f64 = 0,
    count: u64 = 0,

    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.best_cyc = @min(s.best_cyc, r.cycles);
        s.worst_cyc = @max(s.worst_cyc, r.cycles);
        s.count = r.count;
    }
    fn best(s: Side, cyc: bool) f64 {
        return if (cyc) s.best_cyc else s.best_ns;
    }
    fn spread(s: Side, cyc: bool) f64 {
        return if (cyc) s.worst_cyc / s.best_cyc - 1 else s.worst_ns / s.best_ns - 1;
    }
};

/// This thread's user-mode cycle counter (`perf stat -e cycles:u`).
const Cycles = struct {
    fd: ?i32,

    fn open() Cycles {
        if (@import("builtin").os.tag != .linux) return .{ .fd = null };
        const linux = std.os.linux;
        var attr: linux.perf_event_attr = .{
            .type = .HARDWARE,
            .config = @intFromEnum(linux.PERF.COUNT.HW.CPU_CYCLES),
            .flags = .{ .exclude_kernel = true, .exclude_hv = true },
        };
        const rc = linux.perf_event_open(&attr, 0, -1, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return .{ .fd = null };
        return .{ .fd = @intCast(rc) };
    }

    fn read(c: Cycles) u64 {
        const fd = c.fd orelse return 0;
        var v: u64 = 0;
        _ = std.os.linux.read(fd, @ptrCast(&v), @sizeOf(u64));
        return v;
    }
};

fn timeIt(io: std.Io, cyc: Cycles, x: *Ctx) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(x));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var best_cycles: u64 = std.math.maxInt(u64);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        const c0 = cyc.read();
        for (0..n) |_| count = once(x);
        best_cycles = @min(best_cycles, cyc.read() - c0);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    // A threaded op's cycles are mostly other threads': wall time decides.
    const cyc_per: f64 = if (threaded(x.op)) 0 else @as(f64, @floatFromInt(best_cycles)) / nf;
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = cyc_per, .count = count };
}

/// Run the foreign program for one workload: `<exe> <work dir> <name>`, which
/// prints `name \t ns/op \t cycles/op \t count` and its banner on stderr.
fn foreign(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8, banner: *[]const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    banner.* = res.stderr;
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const cycles = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .cycles = cycles, .count = count };
}

/// One workload: `op` for our side, the foreign program's workload `ref`
/// (the reference) and optionally `alt` (a second implementation in the
/// field, for the `fastest` ratio); `*_exe` index the foreign programs.
const Work = struct { name: []const u8, op: Op, ref: []const u8, alt: ?[]const u8 = null, ref_exe: usize = 0, alt_exe: usize = 0 };

const Summary = struct {
    best_ref: f64 = std.math.inf(f64),
    worst_ref: f64 = 0,
    /// Worst of ours / min(ref, alt) over the workloads that have an `alt`.
    worst_fast: ?f64 = null,
    max_spread: f64 = 0,
    banner: []const u8 = "",
    alt_banner: []const u8 = "",
};

fn drive(io: std.Io, arena: std.mem.Allocator, exes: []const []const u8, abs: []const u8, ctx: *Ctx, ws: []const Work, filters: []const [:0]const u8, rounds: usize, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    var s: Summary = .{};
    var metric_cycles = true;
    var mismatch = false;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, x.name, f) != null;
            if (!hit) continue;
        }
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        // The sides alternate, `rounds` times, each keeping its best: timed one
        // after the other they would see different loads of a shared machine.
        for (0..rounds) |_| {
            ref.add(try foreign(arena, io, exes[x.ref_exe], abs, x.ref, &s.banner));
            ours.add(timeIt(io, cyc, ctx));
            if (x.alt) |a| alt.add(try foreign(arena, io, exes[x.alt_exe], abs, a, &s.alt_banner));
        }
        const by_cyc = ours.best_cyc > 0 and ref.best_cyc > 0 and (x.alt == null or alt.best_cyc > 0);
        metric_cycles = metric_cycles and by_cyc;
        const r_ref = ours.best(by_cyc) / ref.best(by_cyc);
        s.worst_ref = @max(s.worst_ref, r_ref);
        s.best_ref = @min(s.best_ref, r_ref);
        var r_fast: f64 = r_ref;
        if (x.alt != null) {
            r_fast = ours.best(by_cyc) / @min(ref.best(by_cyc), alt.best(by_cyc));
            s.worst_fast = @max(s.worst_fast orelse 0, r_fast);
        }
        const spr_alt = if (x.alt != null) alt.spread(by_cyc) else 0;
        s.max_spread = @max(s.max_spread, @max(ours.spread(by_cyc), @max(ref.spread(by_cyc), spr_alt)));
        const same = ours.count == ref.count and (x.alt == null or ours.count == alt.count);
        mismatch = mismatch or !same;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            x.name,        ours.best_ns, ref.best_ns,               if (x.alt != null) alt.best_ns else 0,
            r_ref,         r_fast,       100 * ours.spread(by_cyc), 100 * ref.spread(by_cyc),
            100 * spr_alt, ours.count,
            if (same) "" else " ≠",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (metric_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.flush();
    if (mismatch) {
        std.debug.print("{s}: FAILED -- an output size differs between the sides\n", .{bench_name});
        return error.CountMismatch;
    }
    return s;
}

/// The foreign program, built from `src` with `zig cc -O3 -march=native`
/// against `libs` (shared objects named by path, so no headers are needed).
fn buildForeign(arena: std.mem.Allocator, io: std.Io, abs: []const u8, src: []const u8, libs: []const []const u8) ![]const u8 {
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const cc = try std.process.run(arena, io, .{ .argv = argv.items });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, cc.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
fn foreignOnce(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, mode } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed in {s}:\n{s}\n", .{ bench_name, mode, res.stderr });
        return error.ForeignFailed;
    }
}
