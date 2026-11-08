// SPDX-License-Identifier: MIT

//! Comparative benchmark: `finstats`' scalar statistics against empyrical-reloaded
//! 0.5.12 on NumPy (the reference, `tools/py_bench.py`), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-finstats` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs the oracle venv of
//! `tools/oracle.py` (`FINSTATS_BENCH_PY` names its python). Run from the
//! repository root.
//!
//! The series: 1,000,000 daily returns (fixed seed, normal, mean 0.0003, sd 0.01),
//! written as raw f64 to `.zig-cache/bench-finstats/returns.f64`; the Python side
//! reads the same bytes. Python times ONLY the library call on a ready NumPy
//! array; ours times only the function call on a ready `[]f64`.
//! One op per workload, same work on both sides:
//!   sharpe     ours `sharpeRatio(xs, 0, 252)`          empyrical `sharpe_ratio`
//!   sortino    `sortinoRatio`                          `sortino_ratio`
//!   max_dd     `maxDrawdown`                           `max_drawdown`
//!   cagr       `cagrPeriods`                           `annual_return`
//!   calmar     `calmarRatio`                           `calmar_ratio`
//!   stability  `stability`                             `stability_of_timeseries`
//!   risk_row   `riskMetrics` (9 metrics, it also        `annual_volatility`, `downside_risk`,
//!              computes ulcer, sharpe, sortino,         `value_at_risk`, `conditional_value_at_risk`,
//!              calmar that empyrical lacks)             `max_drawdown` (5 metrics)
//! `risk_row` is therefore a handicap against us (more work on our side).
//! Count = series length on both sides; value agreement is the oracle tests' job.
//!
//! "Fastest": no compiled (C/Rust/Go) implementation of this metric set was
//! found by name search (2026-11-02); the card says `fastest ?`.

const std = @import("std");
const bench = @import("testkit").bench;
const fin = @import("finstats");

const bench_name = "bench-finstats";
const work_dir = ".zig-cache/bench-finstats";
const N = 1_000_000;

const Op = enum { sharpe, sortino, max_dd, cagr, calmar, stability, risk_row };

const Ctx = struct {
    op: Op = .sharpe,
    xs: []f64 = &.{},
    arena: std.heap.ArenaAllocator,
};

fn once(c: *Ctx) u64 {
    var sink: f64 = 0;
    switch (c.op) {
        .sharpe => sink = fin.sharpeRatio(c.xs, 0, 252),
        .sortino => sink = fin.sortinoRatio(c.xs, 0, 252),
        .max_dd => sink = fin.maxDrawdown(c.xs),
        .cagr => sink = fin.cagrPeriods(c.xs, 252),
        .calmar => sink = fin.calmarRatio(c.xs, 252),
        .stability => sink = fin.stability(c.xs),
        .risk_row => {
            _ = c.arena.reset(.retain_capacity);
            const r = fin.riskMetrics(c.arena.allocator(), c.xs, .{}) catch @panic("bench-finstats: riskMetrics");
            sink = r.ann_vol;
        },
    }
    std.mem.doNotOptimizeAway(sink);
    return c.xs.len;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const exe = try cwd.realPathFileAlloc(io, "modules/finstats/tools/py_bench.sh", arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    // The series: Box-Muller from a fixed-seed PRNG.
    var prng = std.Random.DefaultPrng.init(20261102);
    const rnd = prng.random();
    const xs = try arena.alloc(f64, N);
    for (xs) |*x| {
        const u1_ = @max(rnd.float(f64), 1e-300);
        const u2_ = rnd.float(f64);
        x.* = 0.0003 + 0.01 * @sqrt(-2 * @log(u1_)) * @cos(2 * std.math.pi * u2_);
    }
    try dir.writeFile(io, .{ .sub_path = "returns.f64", .data = std.mem.sliceAsBytes(xs) });

    var ctx: Ctx = .{ .xs = xs, .arena = .init(std.heap.page_allocator) };

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "sharpe", .op = .sharpe, .ref = "sharpe" },
        .{ .name = "sortino", .op = .sortino, .ref = "sortino" },
        .{ .name = "max_dd", .op = .max_dd, .ref = "max_dd" },
        .{ .name = "cagr", .op = .cagr, .ref = "cagr" },
        .{ .name = "calmar", .op = .calmar, .ref = "calmar" },
        .{ .name = "stability", .op = .stability, .ref = "stability" },
        .{ .name = "risk_row", .op = .risk_row, .ref = "risk_row" },
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
    try w.print("\nworst ours/empyrical = {d:.2} (best {d:.2})\n{s}", .{ s.worst_ref, s.best_ref, s.banner });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× empyrical-reloaded 0.5.12 on NumPy · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
