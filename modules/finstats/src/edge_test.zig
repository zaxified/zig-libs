// SPDX-License-Identifier: MIT
//! Edge cases of the statistics a consumer feeds with arbitrary data (survey
//! 2026-11-02): empty series, zero variance, all-negative returns, NaN and
//! infinity, very long series. Each is a DEFINED result or an error, never a
//! panic and never a finite number computed around a NaN.
const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const dsmod = @import("dataset");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);

fn isNan(x: f64) bool {
    return std.math.isNan(x);
}

fn ds(a: std.mem.Allocator, vals: []const f64) !Dataset {
    const cols = try a.dupe(Column, &.{.{ .name = "r", .type = .float }});
    const rows = try a.alloc([]const Value, vals.len);
    for (vals, 0..) |v, i| rows[i] = try a.dupe(Value, &.{.{ .float = v }});
    return .{ .columns = cols, .rows = rows };
}

test "empty series: every scalar is 0, never NaN" {
    const e: []const f64 = &.{};
    try testing.expectEqual(@as(f64, 0), fs.totalReturn(e));
    try testing.expectEqual(@as(f64, 0), fs.cagrPeriods(e, 252));
    try testing.expectEqual(@as(f64, 0), fs.geometricMean(e));
    try testing.expectEqual(@as(f64, 0), fs.maxDrawdown(e));
    try testing.expectEqual(@as(f64, 0), fs.sharpeRatio(e, 0.02, 252));
    try testing.expectEqual(@as(f64, 0), fs.sortinoRatio(e, 0.02, 252));
    try testing.expectEqual(@as(f64, 0), fs.calmarRatio(e, 252));
    try testing.expectEqual(@as(f64, 0), fs.gainToPain(e));
    try testing.expectEqual(@as(f64, 0), fs.recoveryFactor(e));
    try testing.expectEqual(@as(f64, 0), fs.bestReturn(e));
    try testing.expectEqual(@as(f64, 0), fs.worstReturn(e));
    try testing.expectEqual(@as(f64, 0), fs.avgWin(e));
    try testing.expectEqual(@as(f64, 0), fs.avgLoss(e));
    try testing.expectEqual(@as(usize, 0), fs.maxConsecutiveWins(e));
    try testing.expectEqual(@as(f64, 0), fs.stability(e));

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try ds(a, e);
    for ((try fs.periodStats(a, d, .{ .ret_col = "r" })).rows[0]) |v| try testing.expect(!isNan(v.float));
    for ((try fs.riskMetrics(a, d, .{ .ret_col = "r" })).rows[0]) |v| try testing.expect(!isNan(v.float));
    for ((try fs.tradeStats(a, d, .{ .ret_col = "r" })).rows[0]) |v| try testing.expect(!isNan(v.float));
    const cu = try fs.cumulativeReturns(a, d, .{ .ret_col = "r" });
    try testing.expectEqual(@as(usize, 0), cu.rows.len);
}

test "zero variance: ratios are 0, a constant 1% series is not a huge Sharpe" {
    const xs: [100]f64 = @splat(0.01);
    try testing.expectEqual(@as(f64, 0), fs.sharpeRatio(&xs, 0, 252));
    try testing.expectEqual(@as(f64, 0), fs.sortinoRatio(&xs, 0, 252)); // no downside
    try testing.expectEqual(@as(f64, 0), fs.calmarRatio(&xs, 252)); // no drawdown
    try testing.expectEqual(@as(f64, 0), fs.stability(&@as([10]f64, @splat(0)))); // flat cumulative line
    try testing.expect(std.math.isInf(fs.gainToPain(&xs))); // gains, no pain
    try testing.expect(std.math.isInf(fs.recoveryFactor(&xs)));
    try testing.expectEqual(@as(usize, 100), fs.maxConsecutiveWins(&xs));
    try testing.expectEqual(@as(f64, 0), fs.sharpeRatio(&[_]f64{0.3}, 0, 252)); // one period
}

test "all-negative returns: finite, signed, ratios follow the conventions" {
    const xs = [_]f64{ -0.01, -0.02, -0.005, -0.03 };
    try testing.expect(fs.totalReturn(&xs) < 0);
    try testing.expect(fs.sharpeRatio(&xs, 0, 252) < 0);
    try testing.expect(fs.sortinoRatio(&xs, 0, 252) < 0);
    try testing.expect(fs.calmarRatio(&xs, 252) < 0);
    try testing.expectEqual(@as(f64, 0), fs.avgWin(&xs));
    try testing.expectEqual(@as(usize, 4), fs.maxConsecutiveLosses(&xs));
    try testing.expectApproxEqAbs(@as(f64, -1), fs.gainToPain(&xs), 1e-15);
    // the level fell monotonically: max drawdown is the whole total return
    try testing.expectApproxEqAbs(fs.totalReturn(&xs), fs.maxDrawdown(&xs), 1e-15);
}

test "NaN and infinity: every statistic answers NaN; a loss over 100 percent is not compoundable" {
    const bad = [_][]const f64{
        &.{ 0.01, nan, 0.02 },
        &.{ 0.01, inf, 0.02 },
        &.{ 0.01, -inf, 0.02 },
    };
    for (bad) |xs| {
        try testing.expect(isNan(fs.totalReturn(xs)));
        try testing.expect(isNan(fs.cagrPeriods(xs, 252)));
        try testing.expect(isNan(fs.maxDrawdown(xs)));
        try testing.expect(isNan(fs.sharpeRatio(xs, 0, 252)));
        try testing.expect(isNan(fs.sortinoRatio(xs, 0, 252)));
        try testing.expect(isNan(fs.calmarRatio(xs, 252)));
        try testing.expect(isNan(fs.gainToPain(xs)));
        try testing.expect(isNan(fs.recoveryFactor(xs)));
        try testing.expect(isNan(fs.bestReturn(xs)));
        try testing.expect(isNan(fs.worstReturn(xs)));
        try testing.expect(isNan(fs.avgWin(xs)));
        try testing.expect(isNan(fs.avgLoss(xs)));
        try testing.expect(isNan(fs.stability(xs)));

        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const d = try ds(a, xs);
        for ((try fs.periodStats(a, d, .{ .ret_col = "r" })).rows[0]) |v| try testing.expect(isNan(v.float));
        for ((try fs.riskMetrics(a, d, .{ .ret_col = "r" })).rows[0]) |v| try testing.expect(isNan(v.float));
        for ((try fs.tradeStats(a, d, .{ .ret_col = "r" })).rows[0]) |v| try testing.expect(isNan(v.float));
    }
    // a loss of more than the whole stake is not a return
    const over = [_]f64{ 0.01, -1.5, 0.02 };
    try testing.expect(isNan(fs.totalReturn(&over)));
    try testing.expect(isNan(fs.maxDrawdown(&over)));
    try testing.expect(!isNan(fs.sharpeRatio(&over, 0, 252))); // mean/std need no level
    // exactly -100 %: total loss, defined
    try testing.expectEqual(@as(f64, -1), fs.totalReturn(&[_]f64{ 0.5, -1 }));
    try testing.expect(isNan(fs.stability(&[_]f64{ 0.5, -1 }))); // log(0)
    // bad parameters
    try testing.expect(isNan(fs.sharpeRatio(&[_]f64{ 0.01, 0.02 }, 0, 0)));
    try testing.expect(isNan(fs.sharpeRatio(&[_]f64{ 0.01, 0.02 }, -1, 252)));
    try testing.expect(isNan(fs.cagrPeriods(&[_]f64{0.01}, nan)));
    // cumulative curve: NaN from the first bad row on, finite before
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cu = try fs.cumulativeReturns(a, try ds(a, &.{ 0.1, nan, 0.1 }), .{ .ret_col = "r" });
    try testing.expectApproxEqAbs(@as(f64, 0.1), cu.rows[0][0].float, 1e-15);
    try testing.expect(isNan(cu.rows[1][0].float) and isNan(cu.rows[2][0].float));
    // unknown column is an error, not a panic
    try testing.expectError(error.NoSuchColumn, fs.periodStats(a, try ds(a, &.{0.1}), .{ .ret_col = "zz" }));
    try testing.expectError(error.NoSuchColumn, fs.cumulativeReturns(a, try ds(a, &.{0.1}), .{ .ret_col = "zz" }));
}

test "riskMetrics var95 by selection equals the sorted quantile: ties, orderings, sizes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    var buf: [700]f64 = undefined;
    for ([_]usize{ 1, 2, 3, 5, 16, 17, 20, 21, 40, 99, 100, 101, 399, 700 }) |n| {
        for (0..6) |shape| {
            for (buf[0..n], 0..) |*x, i| x.* = switch (shape) {
                0 => (rnd.float(f64) - 0.5) * 0.05,
                1 => @as(f64, @floatFromInt(rnd.uintLessThan(u8, 4))) * 0.01 - 0.01, // heavy ties
                2 => @as(f64, @floatFromInt(i)) * 1e-4, // ascending
                3 => -@as(f64, @floatFromInt(i)) * 1e-4, // descending
                4 => 0.003, // constant
                else => if (i % 2 == 0) 0.01 else -0.01, // organ pipe of two values
            };
            const d = try ds(a, buf[0..n]);
            const rm = try fs.riskMetrics(a, d, .{ .ret_col = "r" });
            const want = -(try fs.quantile(a, buf[0..n], 0.05));
            try testing.expectEqual(want, rm.rows[0][2].float); // var95: bit-identical
        }
    }
}

test "drawdownSeries: hand-computed, its minimum is maxDrawdown, NaN poisons from the bad row" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const xs = [_]f64{ 0.1, -0.2, 0.05, 0.3 };
    const dd = try fs.drawdownSeries(a, try ds(a, &xs), .{ .ret_col = "r" });
    // levels 1.1, 0.88, 0.924, 1.2012; peaks 1.1, 1.1, 1.1, 1.2012
    const want = [_]f64{ 0, -0.2, -0.16, 0 };
    var lo: f64 = 0;
    for (want, 0..) |w, i| {
        try testing.expectApproxEqAbs(w, dd.rows[i][0].float, 1e-15);
        lo = @min(lo, dd.rows[i][0].float);
    }
    try testing.expectApproxEqAbs(fs.maxDrawdown(&xs), lo, 1e-15);
    const bad = try fs.drawdownSeries(a, try ds(a, &.{ -0.5, nan, 0.1 }), .{ .ret_col = "r" });
    try testing.expectApproxEqAbs(@as(f64, -0.5), bad.rows[0][0].float, 1e-15);
    try testing.expect(isNan(bad.rows[1][0].float) and isNan(bad.rows[2][0].float));
}

test "review fixes: a long constant series has zero spread whatever n and c (MED-1)" {
    const ns = [_]usize{ 3, 7, 8, 16, 1000, 10000, 10007, 1_000_000 };
    const cs = [_]f64{ 0.001, 0.01, 0.1, -0.01 };
    const buf = try testing.allocator.alloc(f64, 1_000_000);
    defer testing.allocator.free(buf);
    for (ns) |n| for (cs) |c| {
        @memset(buf[0..n], c);
        errdefer std.debug.print("n {d} c {d}\n", .{ n, c });
        try testing.expectEqual(@as(f64, 0), fs.sharpeRatio(buf[0..n], 0, 252));
        try testing.expectEqual(@as(f64, 0), fs.sharpeRatio(buf[0..n], 0.03, 252));
    };
}

test "review fixes: sharpeRatio on n < 8 and n % 8 == 0 against a naive loop (MED-1)" {
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    var buf: [24]f64 = undefined;
    for ([_]usize{ 2, 3, 5, 7, 8, 9, 16, 24 }) |n| {
        for (buf[0..n]) |*x| x.* = (rnd.float(f64) - 0.45) * 0.04;
        var s: f64 = 0;
        for (buf[0..n]) |x| s += x;
        const m = s / @as(f64, @floatFromInt(n));
        var ss: f64 = 0;
        for (buf[0..n]) |x| ss += (x - m) * (x - m);
        const sd = @sqrt(ss / @as(f64, @floatFromInt(n - 1)));
        const want = m / sd * @sqrt(@as(f64, 252));
        try testing.expectApproxEqRel(want, fs.sharpeRatio(buf[0..n], 0, 252), 1e-12);
    }
}

test "review fixes: -100 percent period, return below -1, tiny ppy, drawdown past f64 range" {
    // LOW-1: the -1 check runs before the length check
    try testing.expect(isNan(fs.stability(&[_]f64{-1})));
    // LOW-2: riskMetrics follows maxDrawdown: a return below -1 is NaN, not dd = -150
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rm = try fs.riskMetrics(a, try ds(a, &.{ 0.01, -1.5, 0.02 }), .{ .ret_col = "r" });
    for (rm.rows[0]) |v| try testing.expect(isNan(v.float));
    // LOW-3: 1 / ppy overflows
    try testing.expect(isNan(fs.sharpeRatio(&[_]f64{ 0.01, 0.02 }, 0.03, 1e-310)));
    try testing.expect(isNan(fs.sortinoRatio(&[_]f64{ 0.01, -0.02 }, 0.03, 1e-310)));
    // LOW-5: 70 000 periods of -1 % underflow the plain product (1e-306 and below)
    const down = try testing.allocator.alloc(f64, 80_000);
    defer testing.allocator.free(down);
    @memset(down, -0.01);
    const one: f64 = -0.01;
    const want = std.math.expm1(@as(f64, 252) * std.math.log1p(one));
    try testing.expectApproxEqRel(want, fs.cagrPeriods(down, 252), 1e-9);
    // an overflowing level: true max drawdown is the single -50 % period
    const up = try testing.allocator.alloc(f64, 8002);
    defer testing.allocator.free(up);
    @memset(up, 0.1);
    up[8000] = -0.5;
    try testing.expectApproxEqAbs(@as(f64, -0.5), fs.maxDrawdown(up), 1e-9);
    const rmu = try fs.riskMetrics(a, try ds(a, up), .{ .ret_col = "r" });
    try testing.expectApproxEqAbs(@as(f64, -0.5), rmu.rows[0][4].float, 1e-9);
    // LOW-6: an explicit out_name is kept, even "cum_return"
    const dd = try fs.drawdownSeries(a, try ds(a, &.{0.1}), .{ .ret_col = "r", .out_name = "cum_return" });
    try testing.expectEqualStrings("cum_return", dd.columns[0].name);
    const dd2 = try fs.drawdownSeries(a, try ds(a, &.{0.1}), .{ .ret_col = "r" });
    try testing.expectEqualStrings("drawdown", dd2.columns[0].name);
}

test "very long series: 2 million periods, finite results, no panic" {
    const n = 2_000_000;
    const xs = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(xs);
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (xs) |*x| x.* = (r.float(f64) - 0.5) * 0.002 + 0.00001;
    try testing.expect(std.math.isFinite(fs.sharpeRatio(xs, 0.02, 252)));
    try testing.expect(std.math.isFinite(fs.sortinoRatio(xs, 0.02, 252)));
    try testing.expect(std.math.isFinite(fs.calmarRatio(xs, 252)));
    try testing.expect(std.math.isFinite(fs.stability(xs)));
    try testing.expect(fs.maxConsecutiveWins(xs) < 60);
    // compounding 2e6 periods of +1 % overflows the level to +inf: defined, not NaN
    const big = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(big);
    @memset(big, 0.01);
    try testing.expect(std.math.isInf(fs.totalReturn(big)));
    _ = fs.cagrPeriods(big, 252);
    _ = fs.calmarRatio(big, 252);
}
