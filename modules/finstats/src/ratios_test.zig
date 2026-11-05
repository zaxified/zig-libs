// SPDX-License-Identifier: MIT

//! Tests for `ratios.zig`: replay of `testdata/ratios_vectors.zig` (made by
//! `tools/ratios_oracle.py` from quantstats, ffn and scipy run as black boxes;
//! the generator's docstring names the foreign function per value), hand values,
//! and the edge conventions (empty series, zero denominators, non-finite input,
//! bad ppy, allocation failure).

const std = @import("std");
const testing = std.testing;
const r = @import("ratios.zig");
const slice = @import("slice.zig");
const ref = @import("testdata/ratios_vectors.zig");

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);
const ppy: f64 = ref.ppy;

/// Relative 1e-11 unless a caller passes a wider, measured tolerance.
const tol: f64 = 1e-11;

fn near(want: f64, got: f64, rel: f64) !void {
    if (@abs(want - got) <= rel * @abs(want) + 1e-300) return;
    std.debug.print("want {e}, got {e} (relative diff {e})\n", .{ want, got, (want - got) / want });
    return error.TestUnexpectedResult;
}

fn isNan(x: f64) !void {
    if (!std.math.isNan(x)) {
        std.debug.print("want NaN, got {e}\n", .{x});
        return error.TestUnexpectedResult;
    }
}

test "ratios.zig is referenced" {
    _ = r;
}

test "oracle: per-series ratios against quantstats / ffn" {
    const a = testing.allocator;
    for (ref.series) |s| {
        errdefer std.debug.print("series {s}\n", .{s.name});
        try near(s.avg_return, r.avgReturn(s.values), tol);
        try near(s.risk_return, r.riskReturnRatio(s.values), tol);
        try near(s.profit_ratio, r.profitRatio(s.values), tol);
        try near(s.win_loss, r.winLossRatio(s.values), tol);
        try near(s.exposure, r.exposure(s.values), tol);
        try near(s.csr, try r.commonSenseRatio(a, s.values), tol);
        try near(s.cpc, r.cpcIndex(s.values), tol);
        try near(s.outlier_win, try r.outlierWinRatio(a, s.values, 0.99), tol);
        try near(s.outlier_loss, try r.outlierLossRatio(a, s.values, 0.01), tol);
        try near(s.autocorr, r.autocorrPenalty(s.values), tol);
        try near(s.skew_s, r.skewSample(s.values), tol);
        try near(s.kurt_s, r.kurtosisSample(s.values), tol);
        try near(s.prom, r.probMom(s.values, s.other), tol);
        const up = try r.outliers(a, s.values, 0.95);
        defer a.free(up);
        try testing.expectEqualSlices(f64, s.outliers95, up);
        const low = try r.removeOutliers(a, s.values, 0.9);
        defer a.free(low);
        try testing.expectEqualSlices(f64, s.removed90, low);
        const pct = try r.pctRank(a, s.prices, 20);
        defer a.free(pct);
        try testing.expectEqual(s.pct20.len, pct.len);
        for (s.pct20, pct) |want, got| try near(want, got, tol);
    }
}

test "oracle: rf-dependent ratios against quantstats / ffn" {
    const a = testing.allocator;
    for (ref.rows) |w| {
        const s = ref.series[w.series];
        errdefer std.debug.print("series {s} rf {d}\n", .{ s.name, w.rf });
        const x = s.values;
        try near(w.upi, r.ulcerPerformanceIndex(x, w.rf), tol);
        try near(w.serenity, try r.serenityIndex(a, x, w.rf), tol);
        try near(w.rar, r.rar(x, w.rf, ppy), tol);
        if (w.rf == 0) try near(w.rar_qs, r.rar(x, w.rf, ppy), tol);
        try near(w.smart_sharpe, r.smartSharpe(x, w.rf, ppy), tol);
        try near(w.smart_sortino, r.smartSortino(x, w.rf, ppy), tol);
        try near(w.sortino_sqrt2, r.sortinoSqrt2(x, w.rf, ppy), tol);
        try near(w.sortino_sqrt2, r.adjustedSortino(x, w.rf, ppy), tol);
        try near(w.smart_sortino_sqrt2, r.smartSortinoSqrt2(x, w.rf, ppy), tol);
        try near(w.psr, r.probabilisticSharpeRatio(x, w.rf, ppy), tol);
        try near(w.pso, r.probabilisticSortinoRatio(x, w.rf, ppy), tol);
        try near(w.paso, r.probabilisticAdjustedSortinoRatio(x, w.rf, ppy), tol);
        try near(w.psr_smart, r.probabilisticRatio(x, .sharpe, w.rf, ppy, true), tol);
        try near(w.pso_smart, r.probabilisticRatio(x, .sortino, w.rf, ppy, true), tol);
        try near(w.paso_smart, r.probabilisticRatio(x, .adjusted_sortino, w.rf, ppy, true), tol);
        try near(w.dsr, r.deflatedSharpeRatio(x, &ref.trials, w.rf, ppy), tol);
    }
}

test "oracle: normalCdf against scipy, expectedMaxSharpe against ffn" {
    for (ref.normal_cdf) |p| try near(p[1], r.normalCdf(p[0]), 1e-13);
    for (ref.exp_max) |p| {
        try near(p[2], r.expectedMaxSharpe(@intFromFloat(p[0]), p[1]), tol);
    }
}

test "normalCdf: symmetry, limits, NaN" {
    var z: f64 = -12;
    while (z <= 12) : (z += 0.37) {
        try testing.expect(@abs(r.normalCdf(z) + r.normalCdf(-z) - 1) < 4e-16);
    }
    try testing.expectEqual(@as(f64, 0.5), r.normalCdf(0));
    try testing.expectEqual(@as(f64, 1), r.normalCdf(50));
    try testing.expectEqual(@as(f64, 0), r.normalCdf(-50));
    try testing.expectEqual(@as(f64, 1), r.normalCdf(inf));
    try isNan(r.normalCdf(nan));
}

test "hand values" {
    const a = testing.allocator;
    try near(0.1, r.avgReturn(&.{ 0.1, 0, -0.1, 0.3 }), 1e-14);
    try testing.expectEqual(@as(f64, 0.5), r.exposure(&.{ 0.1, 0, 0, 0.2 }));
    try near(0.43, r.exposure(&.{ 1, 1, 1, 0, 0, 0, 0 }), 1e-15); // ceil(42.857) / 100
    try testing.expectEqual(@as(f64, 2), r.autocorrPenalty(&.{ 1, 2, 3, 4 })); // c = 1
    try near(0.9352195295828235, r.skewSample(&.{ 1, 2, 4 }), 1e-14); // scipy skew(bias=False)
    try near(0.7576559546313799, r.kurtosisSample(&.{ 1, 2, 4, 8 }), 1e-14); // scipy kurtosis(bias=False)
    try near(0.9893441794356217, r.probMom(&.{ 1, 2, 4, 3, 5 }, &.{ 0, 1, 1, 2, 2 }), 1e-12); // ffn
    const up = try r.outliers(a, &.{ 1, 2, 3, 4, 5 }, 0.5);
    defer a.free(up);
    try testing.expectEqualSlices(f64, &.{ 4, 5 }, up);
    const low = try r.removeOutliers(a, &.{ 5, 4, 3, 2, 1 }, 0.5);
    defer a.free(low);
    try testing.expectEqualSlices(f64, &.{ 2, 1 }, low);
    const pct = try r.pctRank(a, &.{ 1, 2, 3, 4, 5, 3, 3, 1 }, 3); // ties: average rank
    defer a.free(pct);
    const want = [_]f64{ 100, 100, 100, 100, 100, 100.0 / 3.0, 50, 100.0 / 3.0 };
    for (want, pct) |w, g| try near(w, g, 1e-14);
    // winLoss is payoff: mean win 0.2 over |mean loss| 0.1
    try near(2, r.winLossRatio(&.{ 0.1, 0.3, -0.1, 0 }), 1e-14);
}

test "riskOfRuin: classical form, hand values" {
    try testing.expectEqual(@as(f64, 1), r.riskOfRuin(0, 10)); // p = 0.5
    try near(1.0 / 9.0, r.riskOfRuin(0.5, 2), 1e-15);
    try near(8.0 / 27.0, r.riskOfRuin(0.2, 3), 1e-15);
    try testing.expectEqual(@as(f64, 1), r.riskOfRuin(-0.3, 5)); // negative edge: certain ruin
    try testing.expectEqual(@as(f64, 0), r.riskOfRuin(1, 5));
    try testing.expectEqual(@as(f64, 1), r.riskOfRuin(1, 0));
    try testing.expectEqual(@as(f64, 1), r.riskOfRuin(0.3, 0));
    try isNan(r.riskOfRuin(nan, 1));
    try isNan(r.riskOfRuin(0.1, nan));
    try isNan(r.riskOfRuin(0.1, -1));
    // monotone in the edge
    try testing.expect(r.riskOfRuin(0.3, 4) < r.riskOfRuin(0.1, 4));
}

test "expectedMaxSharpe: one trial, none, bad spread" {
    try testing.expectEqual(@as(f64, 0), r.expectedMaxSharpe(1, 0.5));
    try isNan(r.expectedMaxSharpe(0, 0.5));
    try isNan(r.expectedMaxSharpe(5, -1));
    try isNan(r.expectedMaxSharpe(5, nan));
    try testing.expectEqual(@as(f64, 0), r.expectedMaxSharpe(5, 0));
}

test "empty series and short series have defined answers" {
    const a = testing.allocator;
    const e: []const f64 = &.{};
    try testing.expectEqual(@as(f64, 0), r.avgReturn(e));
    try testing.expectEqual(@as(f64, 0), r.riskReturnRatio(e));
    try testing.expectEqual(@as(f64, 0), r.ulcerPerformanceIndex(e, 0.02));
    try testing.expectEqual(@as(f64, 0), try r.serenityIndex(a, e, 0.02));
    try testing.expectEqual(@as(f64, 0), try r.commonSenseRatio(a, e));
    try testing.expectEqual(@as(f64, 0), r.cpcIndex(e));
    try testing.expectEqual(@as(f64, 0), r.profitRatio(e));
    try testing.expectEqual(@as(f64, 0), r.winLossRatio(e));
    try testing.expectEqual(@as(f64, 0), r.exposure(e));
    try testing.expectEqual(@as(f64, 0), r.rar(e, 0.02, ppy));
    try testing.expectEqual(@as(f64, 0), try r.outlierWinRatio(a, e, 0.99));
    try testing.expectEqual(@as(f64, 0), try r.outlierLossRatio(a, e, 0.01));
    try testing.expectEqual(@as(f64, 1), r.autocorrPenalty(e));
    try testing.expectEqual(@as(f64, 1), r.autocorrPenalty(&.{ 0.1, 0.2 }));
    try testing.expectEqual(@as(f64, 0), r.smartSharpe(e, 0, ppy));
    try testing.expectEqual(@as(f64, 0), r.smartSortino(e, 0, ppy));
    try testing.expectEqual(@as(f64, 0), r.skewSample(&.{ 1, 2 }));
    try testing.expectEqual(@as(f64, 0), r.kurtosisSample(&.{ 1, 2, 3 }));
    try isNan(r.probabilisticSharpeRatio(e, 0, ppy));
    try isNan(r.probabilisticSharpeRatio(&.{0.01}, 0, ppy));
    try isNan(r.deflatedSharpeRatio(e, &ref.trials, 0, ppy));
    try isNan(r.probMom(e, e));
    for (try r.outliers(a, e, 0.9)) |_| return error.TestUnexpectedResult;
    const p = try r.pctRank(a, e, 5);
    defer a.free(p);
    try testing.expectEqual(@as(usize, 0), p.len);
}

test "zero denominators" {
    const a = testing.allocator;
    // no losses, no drawdown: +inf for a positive numerator
    try testing.expectEqual(inf, r.profitRatio(&.{ 0.1, 0.2 }));
    try testing.expectEqual(inf, r.ulcerPerformanceIndex(&.{ 0.01, 0.02 }, 0));
    try testing.expectEqual(inf, try r.serenityIndex(a, &.{ 0.01, 0.02 }, 0));
    try testing.expectEqual(inf, try r.outlierLossRatio(a, &.{ 0.1, 0.2 }, 0.01));
    // ... and 0 when the numerator is not positive
    try testing.expectEqual(@as(f64, 0), r.ulcerPerformanceIndex(&.{ 0, 0, 0 }, 0));
    try testing.expectEqual(@as(f64, 0), try r.serenityIndex(a, &.{ 0, 0, 0 }, 0));
    try testing.expectEqual(@as(f64, 0), try r.serenityIndex(a, &.{ -0.01, -0.01, -0.01 }, 0)); // zero spread
    try testing.expectEqual(@as(f64, 0), try r.outlierWinRatio(a, &.{ -0.1, -0.2 }, 0.99));
    // all-zero series: no exposure, cagr 0
    try testing.expectEqual(@as(f64, 0), r.rar(&.{ 0, 0, 0 }, 0, ppy));
    try testing.expectEqual(@as(f64, 0), r.exposure(&.{ 0, 0, 0 }));
    try testing.expectEqual(@as(f64, 0), r.riskReturnRatio(&.{ 0.01, 0.01, 0.01 })); // constant
    try testing.expectEqual(@as(f64, 0.5), r.probMom(&.{ 1, 2, 3 }, &.{ 1, 2, 3 }));
    try testing.expectEqual(@as(f64, 1), r.probMom(&.{ 1.5, 2.5, 3.5 }, &.{ 1, 2, 3 }));
    try testing.expectEqual(@as(f64, 0), r.probMom(&.{ 1, 2, 3 }, &.{ 1.5, 2.5, 3.5 }));
    try testing.expectEqual(@as(f64, 1), r.autocorrPenalty(&.{ 0.02, 0.02, 0.02, 0.02 }));
    try testing.expectEqual(@as(f64, 0), r.skewSample(&.{ 0.02, 0.02, 0.02, 0.02 }));
    try testing.expectEqual(@as(f64, 0), r.kurtosisSample(&.{ 0.02, 0.02, 0.02, 0.02 }));
}

test "non-finite input, bad ppy and rf, length mismatch" {
    const a = testing.allocator;
    const bad = [_][]const f64{ &.{ 0.01, nan, 0.02, 0.03 }, &.{ 0.01, inf, 0.02, 0.03 }, &.{ 0.01, -inf, 0.02, 0.03 } };
    for (bad) |x| {
        try isNan(r.avgReturn(x));
        try isNan(r.riskReturnRatio(x));
        try isNan(r.ulcerPerformanceIndex(x, 0));
        try isNan(try r.serenityIndex(a, x, 0));
        try isNan(try r.commonSenseRatio(a, x));
        try isNan(r.cpcIndex(x));
        try isNan(r.profitRatio(x));
        try isNan(r.winLossRatio(x));
        try isNan(r.exposure(x));
        try isNan(r.rar(x, 0, ppy));
        try isNan(try r.outlierWinRatio(a, x, 0.99));
        try isNan(try r.outlierLossRatio(a, x, 0.01));
        try isNan(r.autocorrPenalty(x));
        try isNan(r.smartSharpe(x, 0, ppy));
        try isNan(r.smartSortino(x, 0, ppy));
        try isNan(r.sortinoSqrt2(x, 0, ppy));
        try isNan(r.smartSortinoSqrt2(x, 0, ppy));
        try isNan(r.adjustedSortino(x, 0, ppy));
        try isNan(r.skewSample(x));
        try isNan(r.kurtosisSample(x));
        try isNan(r.probabilisticSharpeRatio(x, 0, ppy));
        try isNan(r.probabilisticSortinoRatio(x, 0, ppy));
        try isNan(r.probabilisticAdjustedSortinoRatio(x, 0, ppy));
        try isNan(r.deflatedSharpeRatio(x, &ref.trials, 0, ppy));
        try isNan(r.probMom(x, x));
        const o = try r.outliers(a, x, 0.9);
        try testing.expectEqual(@as(usize, 0), o.len);
        a.free(o);
        const p = try r.pctRank(a, x, 2);
        defer a.free(p);
        for (p) |v| try isNan(v);
    }
    const ok = [_]f64{ 0.01, -0.02, 0.03, 0.005, -0.01 };
    for ([_]f64{ 0, -1, nan, inf, -inf }) |p| {
        try isNan(r.rar(&ok, 0, p));
        try isNan(r.smartSharpe(&ok, 0, p));
        try isNan(r.smartSortino(&ok, 0, p));
        try isNan(r.sortinoSqrt2(&ok, 0, p));
        try isNan(r.probabilisticSharpeRatio(&ok, 0, p));
        try isNan(r.probabilisticAdjustedSortinoRatio(&ok, 0, p));
        try isNan(r.deflatedSharpeRatio(&ok, &ref.trials, 0, p));
    }
    for ([_]f64{ nan, inf, -1, -2 }) |rf| {
        try isNan(r.rar(&ok, rf, ppy));
        try isNan(r.smartSharpe(&ok, rf, ppy));
        try isNan(r.probabilisticSharpeRatio(&ok, rf, ppy));
    }
    for ([_]f64{ nan, inf, -inf }) |rf| {
        try isNan(r.ulcerPerformanceIndex(&ok, rf));
        try isNan(try r.serenityIndex(a, &ok, rf));
    }
    try isNan(r.deflatedSharpeRatio(&ok, &.{0.5}, 0, ppy));
    try isNan(r.deflatedSharpeRatio(&ok, &.{ 0.5, nan }, 0, ppy));
    try isNan(r.probMom(&.{ 1, 2, 3 }, &.{ 1, 2 }));
    try isNan(try r.outlierWinRatio(a, &ok, nan));
    // a return below -1 is not a return: the compounding functions say NaN
    try isNan(r.ulcerPerformanceIndex(&.{ 0.1, -1.5 }, 0));
    try isNan(try r.serenityIndex(a, &.{ 0.1, -1.5 }, 0));
    try isNan(r.rar(&.{ 0.1, -1.5 }, 0, ppy));
}

test "pctRank: window 0, window larger than the series, TooLarge" {
    const a = testing.allocator;
    const px = [_]f64{ 3, 1, 2 };
    const z = try r.pctRank(a, &px, 0);
    defer a.free(z);
    for (z) |v| try isNan(v);
    const big = try r.pctRank(a, &px, 1000); // expanding window
    defer a.free(big);
    try near(100, big[0], 1e-15);
    try near(50, big[1], 1e-15); // [3, 1]: 1 is the lowest of 2
    try near(200.0 / 3.0, big[2], 1e-14); // [3, 1, 2]: 2 is second of 3
    var long: [16385]f64 = @splat(1);
    try testing.expectError(error.TooLarge, r.pctRank(a, &long, long.len));
    try testing.expectError(error.TooLarge, r.pctRank(a, &long, std.math.maxInt(usize)));
}

test "rar: Python's cagr / exposure, excess returns" {
    // 2 of 4 periods in the market: exposure 0.5, cagr over 4 periods at ppy 4 is the total
    const x = [_]f64{ 0.1, 0, 0, 0.1 };
    try near(0.21 / 0.5, r.rar(&x, 0, 4), 1e-14);
    // rf = 0 cagr unchanged, rf > 0 lowers it
    try testing.expect(r.rar(&x, 0.05, 4) < r.rar(&x, 0, 4));
}

test "allocation failure: no leak, no crash" {
    const x = ref.series[0].values;
    const F = struct {
        fn serenity(a: std.mem.Allocator, v: []const f64) !void {
            _ = try r.serenityIndex(a, v, 0.01);
        }
        fn csr(a: std.mem.Allocator, v: []const f64) !void {
            _ = try r.commonSenseRatio(a, v);
        }
        fn out(a: std.mem.Allocator, v: []const f64) !void {
            a.free(try r.outliers(a, v, 0.9));
            a.free(try r.removeOutliers(a, v, 0.9));
        }
        fn ow(a: std.mem.Allocator, v: []const f64) !void {
            _ = try r.outlierWinRatio(a, v, 0.99);
            _ = try r.outlierLossRatio(a, v, 0.01);
        }
        fn pct(a: std.mem.Allocator, v: []const f64) !void {
            a.free(try r.pctRank(a, v, 20));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, F.serenity, .{x});
    try testing.checkAllAllocationFailures(testing.allocator, F.csr, .{x});
    try testing.checkAllAllocationFailures(testing.allocator, F.out, .{x});
    try testing.checkAllAllocationFailures(testing.allocator, F.ow, .{x});
    try testing.checkAllAllocationFailures(testing.allocator, F.pct, .{x});
}

// ── mutation survivors (2026-11-05): expected values by hand ──

test "riskReturnRatio of an all-zero series is 0, not 0/0" {
    try testing.expectEqual(@as(f64, 0), r.riskReturnRatio(&.{ 0, 0, 0 }));
}

test "rar: a -100 % period is a total loss (CAGR -1), not NaN" {
    // excess f = 1 + x - rfp = 0 for x = -1 and rfp = 0: the product is 0, so cagr = -1;
    // both periods are non-zero, exposure = ceil(100 * 2 / 2) / 100 = 1: rar = -1 / 1.
    try near(-1.0, r.rar(&.{ -1.0, 0.1 }, 0, 252), 1e-12);
}
