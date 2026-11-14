// SPDX-License-Identifier: MIT

//! `benchkit` example — the scoring a `tools/bench.zig` gets back from `drive`,
//! on made-up rows instead of timed ones.
//!
//! benchkit is bench-only: `build.zig` hands it to each `tools/bench.zig`
//! program, never to the module a downstream user imports. A real bench calls
//! `drive`, which times our side in-process and runs the reference and the
//! alternative as foreign programs; that part needs those programs, so this
//! example shows only the pure part a reader has to understand to read a
//! `**Performance:**` line: per workload the best of each side's rounds, the
//! ratios ours/ref and ours/min(ref, alt), and the summary over workloads.
//!
//! Allocation: none.

const std = @import("std");
const bench = @import("benchkit");

/// A gate, not a printout: `ReleaseFast` compiles debug assertions out, and
/// an example meant to fail loudly must not rely on it.
fn check(cond: bool, comptime what: []const u8) !void {
    if (!cond) {
        std.debug.print("FAILED: {s}\n", .{what});
        return error.ExampleCheckFailed;
    }
}

fn side(rows: []const bench.Row) bench.Side {
    var s: bench.Side = .{};
    for (rows) |r| s.add(r);
    return s;
}

pub fn main() !void {
    // Workload 1: three rounds per side, cycles counted everywhere.
    const ours1 = side(&.{ .{ .ns = 105, .cycles = 400, .count = 7 }, .{ .ns = 100, .cycles = 380, .count = 7 }, .{ .ns = 110, .cycles = 390, .count = 7 } });
    const ref1 = side(&.{ .{ .ns = 200, .cycles = 760, .count = 7 }, .{ .ns = 190, .cycles = 770, .count = 7 }, .{ .ns = 195, .cycles = 765, .count = 7 } });
    const alt1 = side(&.{ .{ .ns = 95, .cycles = 360, .count = 7 }, .{ .ns = 98, .cycles = 365, .count = 7 }, .{ .ns = 99, .cycles = 370, .count = 7 } });
    const l1 = bench.score(ours1, ref1, alt1, false);
    try check(l1.by_cycles, "compared by cycles when every side counted them");
    try check(l1.ref == 380.0 / 760.0, "ours/ref from the best rounds (0.5x)");
    try check(l1.fast == 380.0 / 360.0, "ours/min(ref, alt): the alternative is the fastest");
    try check(l1.same_count, "all sides produced the same output count");

    // Workload 2: the reference counted no cycles, so wall time decides.
    const ours2 = side(&.{.{ .ns = 300, .count = 1 }});
    const ref2 = side(&.{.{ .ns = 250, .count = 1 }});
    const l2 = bench.score(ours2, ref2, null, false);
    try check(!l2.by_cycles, "a side without cycles falls back to wall time");

    var sum: bench.Summary = .{};
    sum.add(l1);
    sum.add(l2);
    try check(sum.worst_ref == 300.0 / 250.0, "the card quotes the WORST workload (1.2x)");
    try check(sum.best_ref == 0.5, "and the best");
    try check(!sum.by_cycles, "one wall-time workload makes the summary wall time");
    try check(!sum.mismatch, "no workload's counts differed");

    std.debug.print("ref {d:.2}–{d:.2}×, fastest {d:.2}× (worst over workloads with an alternative)\n", .{ sum.best_ref, sum.worst_ref, sum.worst_fast.? });
}
