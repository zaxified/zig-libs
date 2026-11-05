// SPDX-License-Identifier: MIT

//! Tests for `overfit.zig`: replay of `testdata/overfit_vectors.zig` (made by
//! `tools/overfit_oracle.py` from ffn 1.3.0 run as a black box), hand values,
//! and the edge conventions (odd/zero/huge block counts, one strategy, size
//! caps checked before any allocation, NaN and infinite input, ties, allocation
//! failure).

const std = @import("std");
const testing = std.testing;
const o = @import("overfit.zig");
const ref = @import("testdata/overfit_vectors.zig");

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);

/// Relative 1e-11, as for every other oracle replay in this module.
const tol: f64 = 1e-11;

fn near(want: f64, got: f64, rel: f64) !void {
    if (std.math.isNan(want)) {
        if (std.math.isNan(got)) return;
    } else if (@abs(want - got) <= rel * @abs(want) + 1e-13) return;
    std.debug.print("want {e}, got {e}\n", .{ want, got });
    return error.TestUnexpectedResult;
}

fn meanMetric(xs: []const f64) f64 {
    var s: f64 = 0;
    for (xs) |x| s += x;
    return s / @as(f64, @floatFromInt(xs.len));
}

fn lastMetric(xs: []const f64) f64 {
    return xs[xs.len - 1];
}

fn flatMetric(_: []const f64) f64 {
    return 1.0;
}

fn infMetric(_: []const f64) f64 {
    return inf;
}

test "overfit.zig is referenced" {
    _ = o;
}

test "oracle: PBO, mean rank and logits against ffn" {
    const a = testing.allocator;
    for (ref.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const d = switch (c.metric) {
            .sharpe => try o.probBacktestOverfittingDetail(a, c.trials, c.n_blocks, o.sharpePerPeriod),
            .mean => try o.probBacktestOverfittingDetail(a, c.trials, c.n_blocks, meanMetric),
            .last => try o.probBacktestOverfittingDetail(a, c.trials, c.n_blocks, lastMetric),
        };
        defer d.deinit(a);
        try near(c.pbo, d.pbo, tol);
        try near(c.mean_oos_rank, d.mean_oos_rank, tol);
        try testing.expectEqual(c.n_logits, d.logits.len);
        for (c.logits, d.logits[0..c.logits.len]) |w, g| try near(w, g, tol);
        var sum: f64 = 0;
        for (d.logits) |l| sum += l;
        try near(c.logit_sum, sum, 1e-9);
        // The plain form is the same number.
        const plain = switch (c.metric) {
            .sharpe => try o.probBacktestOverfitting(a, c.trials, c.n_blocks, o.sharpePerPeriod),
            .mean => try o.probBacktestOverfitting(a, c.trials, c.n_blocks, meanMetric),
            .last => try o.probBacktestOverfitting(a, c.trials, c.n_blocks, lastMetric),
        };
        try near(c.pbo, plain, 0);
    }
}

test "oracle: sanity of the reference itself (noise vs a dominant strategy)" {
    for (ref.cases) |c| {
        if (std.mem.startsWith(u8, c.name, "dominant_")) try testing.expectEqual(@as(f64, 0), c.pbo);
        if (std.mem.startsWith(u8, c.name, "noise")) try testing.expect(c.pbo >= 0 and c.pbo <= 1);
    }
}

test "hand value: two strategies, two blocks" {
    const a = testing.allocator;
    const trials = [_][]const f64{ &.{ 1, 2, 5, 6 }, &.{ 3, 4, 1, 2 } };
    // Block 0 selects B (3.5 > 1.5) which is worst out of sample (1.5 < 5.5):
    // rank 1, omega 1/3, logit ln(1/2). Block 1 selects A, worst on block 0: same.
    const d = try o.probBacktestOverfittingDetail(a, &trials, 2, meanMetric);
    defer d.deinit(a);
    try testing.expectEqual(@as(f64, 1), d.pbo);
    try near(1.0 / 3.0, d.mean_oos_rank, 1e-15);
    try testing.expectEqual(@as(usize, 2), d.logits.len);
    for (d.logits) |l| try near(@log(0.5), l, 1e-15);

    // A better in both halves: winner of both, rank 2 of 2, omega 2/3.
    const dom = [_][]const f64{ &.{ 4, 5, 6, 7 }, &.{ 1, 2, 3, 2 } };
    const e = try o.probBacktestOverfittingDetail(a, &dom, 2, meanMetric);
    defer e.deinit(a);
    try testing.expectEqual(@as(f64, 0), e.pbo);
    try near(2.0 / 3.0, e.mean_oos_rank, 1e-15);
    for (e.logits) |l| try near(@log(2.0), l, 1e-15);
}

test "ties: every out-of-sample rank is the average, in-sample tie takes the first" {
    const a = testing.allocator;
    const trials = [_][]const f64{ &.{ 1, 2, 3, 4 }, &.{ 4, 3, 2, 1 }, &.{ 0, 0, 0, 0 } };
    // All metrics equal: rank (1+2+3)/3 = 2 of 3, omega 1/2, logit exactly 0, which counts for PBO.
    const d = try o.probBacktestOverfittingDetail(a, &trials, 2, flatMetric);
    defer d.deinit(a);
    try testing.expectEqual(@as(f64, 1), d.pbo);
    try testing.expectEqual(@as(f64, 0.5), d.mean_oos_rank);
    for (d.logits) |l| try testing.expectEqual(@as(f64, 0), l);
}

test "undefined shapes answer NaN, never an error or a panic" {
    const a = testing.allocator;
    const x = [_]f64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const y = [_]f64{ 2, 1, 4, 3, 6, 5, 8, 7 };
    const two = [_][]const f64{ &x, &y };
    const one = [_][]const f64{&x};
    const none = [_][]const f64{};
    const sh = o.sharpePerPeriod;
    for ([_]usize{ 0, 1, 3, 5, 7, 9, 10, 16, 1 << 40, std.math.maxInt(usize), std.math.maxInt(usize) - 1 }) |nb| {
        try testing.expect(std.math.isNan(try o.probBacktestOverfitting(a, &two, nb, sh)));
    }
    try testing.expect(std.math.isNan(try o.probBacktestOverfitting(a, &one, 4, sh)));
    try testing.expect(std.math.isNan(try o.probBacktestOverfitting(a, &none, 4, sh)));
    const empty = [_][]const f64{ &.{}, &.{} };
    try testing.expect(std.math.isNan(try o.probBacktestOverfitting(a, &empty, 2, sh)));
    // The detail form: NaN and no logits (deinit of the empty slice is fine).
    const d = try o.probBacktestOverfittingDetail(a, &one, 4, sh);
    defer d.deinit(a);
    try testing.expect(std.math.isNan(d.pbo) and std.math.isNan(d.mean_oos_rank));
    try testing.expectEqual(@as(usize, 0), d.logits.len);
    // Blocks of one period, two blocks: one value per half, no Sharpe ratio.
    const two_periods = [_][]const f64{ x[0..2], y[0..2] };
    try testing.expect(std.math.isNan(try o.probBacktestOverfitting(a, &two_periods, 2, sh)));
}

test "length mismatch is an error, even for an otherwise undefined shape" {
    const a = testing.allocator;
    const t = [_][]const f64{ &.{ 1, 2, 3, 4 }, &.{ 1, 2, 3 } };
    try testing.expectError(error.LengthMismatch, o.probBacktestOverfitting(a, &t, 2, meanMetric));
    try testing.expectError(error.LengthMismatch, o.probBacktestOverfitting(a, &t, 3, meanMetric));
    try testing.expectError(error.LengthMismatch, o.probBacktestOverfittingDetail(a, &t, 2, meanMetric));
}

test "size caps are errors raised before anything is allocated" {
    const fa = testing.failing_allocator;
    const x = @as([8]f64, @splat(0));
    const two = [_][]const f64{ &x, &x };
    // 24 blocks: C(24, 12) = 2 704 156 > max_combinations (needs 24 periods).
    const big = @as([24]f64, @splat(0));
    const big2 = [_][]const f64{ &big, &big };
    try testing.expectError(error.TooLarge, o.probBacktestOverfitting(fa, &big2, 24, meanMetric));
    try testing.expectError(error.TooLarge, o.probBacktestOverfittingDetail(fa, &big2, 24, meanMetric));
    // 22 blocks fit the combination cap (705 432) ...
    // ... but with 47 strategies of 88 periods the work cap trips,
    const w = @as([88]f64, @splat(0));
    var rows47: [47][]const f64 = undefined;
    for (&rows47) |*r| r.* = &w;
    try testing.expectError(error.TooLarge, o.probBacktestOverfitting(fa, &rows47, 22, meanMetric));
    // and with 48 strategies of 22 periods the cell cap does.
    const w22 = @as([22]f64, @splat(0));
    var rows48: [48][]const f64 = undefined;
    for (&rows48) |*r| r.* = &w22;
    try testing.expectError(error.TooLarge, o.probBacktestOverfitting(fa, &rows48, 22, meanMetric));
    // A small valid call on the failing allocator is OutOfMemory, not a crash.
    try testing.expectError(error.OutOfMemory, o.probBacktestOverfitting(fa, &two, 2, meanMetric));
}

test "non-finite metric makes the combination, and so the answer, NaN" {
    const a = testing.allocator;
    const trials = [_][]const f64{ &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &.{ 8, 7, 6, 5, 4, 3, 2, 1 } };
    const d = try o.probBacktestOverfittingDetail(a, &trials, 4, infMetric);
    defer d.deinit(a);
    try testing.expect(std.math.isNan(d.pbo) and std.math.isNan(d.mean_oos_rank));
    try testing.expectEqual(@as(usize, 6), d.logits.len);
    for (d.logits) |l| try testing.expect(std.math.isNan(l));
    // A custom metric sees NaN as it is: the mean of a half with a hole is NaN.
    var holes = trials;
    const h = [_]f64{ 1, 2, nan, 4, 5, 6, 7, 8 };
    holes[0] = &h;
    try testing.expect(std.math.isNan(try o.probBacktestOverfitting(a, &holes, 4, meanMetric)));
    // The default Sharpe skips the hole.
    try testing.expect(!std.math.isNan(try o.probBacktestOverfitting(a, &holes, 4, o.sharpePerPeriod)));
}

test "sharpePerPeriod: skips NaN, constant or short input is NaN" {
    try near(2.0, o.sharpePerPeriod(&.{ 1, 2, 3 }), 1e-15);
    try near(2.0, o.sharpePerPeriod(&.{ 1, nan, 2, 3 }), 1e-15);
    try testing.expect(std.math.isNan(o.sharpePerPeriod(&.{})));
    try testing.expect(std.math.isNan(o.sharpePerPeriod(&.{5})));
    try testing.expect(std.math.isNan(o.sharpePerPeriod(&.{ nan, 5, nan })));
    try testing.expect(std.math.isNan(o.sharpePerPeriod(&.{ 0.1 / 3.0, 0.1 / 3.0, 0.1 / 3.0 })));
    try testing.expect(std.math.isNan(o.sharpePerPeriod(&.{ 1, inf })));
    try testing.expect(std.math.isNan(o.sharpePerPeriod(&.{ 1e308, -1e308, 1e308 })));
}

fn allocCase(a: std.mem.Allocator, trials: []const []const f64) !void {
    const d = try o.probBacktestOverfittingDetail(a, trials, 4, o.sharpePerPeriod);
    d.deinit(a);
    _ = try o.probBacktestOverfitting(a, trials, 4, o.sharpePerPeriod);
}

test "allocation failure at every allocation is clean" {
    const c = ref.cases[0];
    const small = [_][]const f64{ c.trials[0][0..16], c.trials[1][0..16], c.trials[2][0..16] };
    try testing.checkAllAllocationFailures(testing.allocator, allocCase, .{@as([]const []const f64, &small)});
}
