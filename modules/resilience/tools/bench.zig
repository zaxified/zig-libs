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
//! Method: `testkit.bench` (same as every module's bench): each side
//! doubles its batch past 100 ms, keeps the best of five, the sides alternate
//! for `BENCH_ROUNDS` (default 3) rounds.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
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
        .{ .name = "breaker_pair_8t", .op = .breaker_pair_8t, .ref = "breaker_pair_8t", .alt = "breaker_pair_8t_alt", .wall_only = threaded(.breaker_pair_8t) },
        .{ .name = "rate_pair", .op = .rate_pair, .ref = "rate_pair" },
        .{ .name = "bulkhead_pair", .op = .bulkhead_pair, .ref = "bulkhead_pair" },
        .{ .name = "bulkhead_pair_8t", .op = .bulkhead_pair_8t, .ref = "bulkhead_pair_8t", .wall_only = threaded(.bulkhead_pair_8t) },
        .{ .name = "run_breaker", .op = .run_breaker, .ref = "run_breaker" },
        .{ .name = "run_retry_breaker", .op = .run_retry_breaker, .ref = "run_retry_breaker" },
        .{ .name = "schedule", .op = .schedule, .ref = "schedule" },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{go_exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
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
    const exe = try arena.print("{s}/go_bench", .{abs});
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
