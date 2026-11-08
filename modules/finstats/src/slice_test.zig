// SPDX-License-Identifier: MIT
//! The slice functions on their own terms: errors, caps, degenerate and hostile input,
//! hand-computed values. The foreign oracles are in oracle_test, period_test and
//! attrib_oracle_test. (Until 2026-11-08 this file also ran every function against the
//! removed `Dataset` one on seeded data; those differential tests went with it.)

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const sl = fs;

test "dayNumber: real dates only, differences are calendar days" {
    try testing.expectEqual(@as(i64, 0), try sl.dayNumber("1970-01-01"));
    try testing.expectEqual(@as(i64, 19782), try sl.dayNumber("2024-02-29"));
    try testing.expectEqual(@as(f64, 366), try sl.daySpan("2024-01-01", "2025-01-01"));
    try testing.expectEqual(try sl.dayNumber("2024-03-01"), try sl.dayNumber("2024-03-01T12:30:00Z"));
    try testing.expectEqual(try sl.dayNumber("2024-03-01"), try sl.dayNumber("2024-03-01 12:30"));
    for ([_][]const u8{ "", "2024", "2023-02-29", "2024-13-01", "2024-00-10", "2024-01-00", "2024-01-32", "2024/01/01", "20x4-01-01", "2024-01-01x", "-024-01-01" }) |bad| {
        try testing.expectError(error.BadDate, sl.dayNumber(bad));
    }
    // against an independent days-from-civil over 400 years, including every leap rule
    var y: u16 = 1800;
    var prev: i64 = (try sl.dayNumber("1800-01-01")) - 1;
    var buf: [10]u8 = undefined;
    while (y < 2200) : (y += 1) {
        for (1..13) |m| {
            for (1..32) |d| {
                const s = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ y, m, d }) catch unreachable;
                const ours = core_day(s);
                const valid = realDay(y, m, d);
                try testing.expectEqual(!valid, ours == null);
                if (ours) |o| {
                    try testing.expectEqual(prev + 1, o);
                    prev = o;
                }
            }
        }
    }
}

fn realDay(y: u16, m: usize, d: usize) bool {
    const leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0;
    const dim = [_]usize{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return d <= dim[m - 1];
}

fn core_day(s: []const u8) ?i64 {
    return sl.dayNumber(s) catch null;
}

test "a bad date is an error wherever dates go in, not 1970" {
    const a = testing.allocator;
    const d2 = [_][]const u8{ "2024-01-01", "not-a-date" };
    const fl = [_]f64{ 100, 0 };
    const v = [_]f64{ 100, 110 };
    try testing.expectError(error.BadDate, sl.xirr(a, &d2, &fl, &v, .none, null));
    try testing.expectError(error.BadDate, sl.xirrPrecise(a, &d2, &fl, &v, .none, .{}));
    try testing.expectError(error.BadDate, sl.drawdownEpisodes(a, &d2, &v, 3));
    try testing.expectError(error.BadDate, sl.daySpan(d2[0], d2[1]));
    // a flow-free middle row too: the check is not limited to dates that are used
    const d3 = [_][]const u8{ "2024-01-01", "x", "2025-01-01" };
    try testing.expectError(error.BadDate, sl.xirr(a, &d3, &[_]f64{ 100, 0, 0 }, &[_]f64{ 100, 0, 110 }, .none, null));
}

test "series of different lengths never panic" {
    const a = testing.allocator;
    const x = [_]f64{ 0.1, 0.2, 0.3 };
    const y = [_]f64{ 0.1, 0.2 };
    const d = [_][]const u8{"2024-01-01"};
    var out: [2]f64 = undefined;
    try testing.expectError(error.LengthMismatch, sl.xirr(a, &d, &x, &y, .none, null));
    try testing.expectError(error.LengthMismatch, sl.twrDaily(a, &x, &y, &x, 0));
    try testing.expectError(error.LengthMismatch, sl.benchmarkStats(a, &x, &y, 0.1, 0, 252));
    try testing.expectError(error.LengthMismatch, sl.rollingBetaAlpha(a, &x, &y, 1, 252));
    try testing.expectError(error.LengthMismatch, sl.brinsonAttribution(a, &x, &y, &x, &x));
    try testing.expectError(error.LengthMismatch, sl.correlationMatrix(a, &.{ &x, &y }, 1));
    try testing.expectError(error.LengthMismatch, sl.drawdownEpisodes(a, &d, &x, 1));
    try testing.expectError(error.LengthMismatch, sl.cumulativeReturnsInto(&out, &x));
    try testing.expectError(error.LengthMismatch, sl.drawdownSeriesInto(&out, &x));
    try testing.expect(std.math.isNan(sl.beta(&x, &y)));
    try testing.expect(std.math.isNan(sl.rSquared(&x, &y)));
    try testing.expect(std.math.isNan(sl.pearson(&x, &y)));
    try testing.expect(std.math.isNan(sl.betaAlpha(&x, &y, 0, 0).r2));
    try testing.expect(std.math.isNan(sl.trackingRisk(&x, &y, 252).tracking_error));
}

test "caps: more work than stated is TooLarge, before anything is allocated" {
    const a = testing.failing_allocator;
    const x = [_]f64{0.1};
    try testing.expectError(error.TooLarge, sl.histogram(a, &x, sl.max_histogram_bins + 1));
    try testing.expectError(error.TooLarge, sl.monteCarlo(a, .{ .start = 1, .mu_ann = 0, .vol_ann = 0, .monthly = 0, .years = 1e12 }));
    try testing.expectError(error.TooLarge, sl.monteCarlo(a, .{ .start = 1, .mu_ann = 0, .vol_ann = 0, .monthly = 0, .years = 1000, .paths = std.math.maxInt(usize) }));
    const many: [sl.max_corr_keys + 1][]const f64 = @splat(&x);
    try testing.expectError(error.TooLarge, sl.correlationMatrix(a, &many, 1));
    const huge: []const f64 = @as([*]const f64, @ptrFromInt(8))[0 .. 1 << 40];
    try testing.expectError(error.TooLarge, sl.rollingMean(a, huge, 1 << 39));
}

test "empty and degenerate inputs have defined answers" {
    const a = testing.allocator;
    const none: []const f64 = &.{};
    const no_dates: []const []const u8 = &.{};
    try testing.expectError(error.EmptyWindow, sl.xirr(a, no_dates, none, none, .none, null));
    try testing.expectEqual(@as(f64, 0), try sl.varHistoric(a, none, 0.95));
    try testing.expectEqual(@as(f64, 0), try sl.cvarHistoric(a, none, 0.95));
    try testing.expectEqual(@as(f64, 0), sl.ulcerIndex(none));
    try testing.expectEqual(@as(f64, 0), sl.volatility(none, 252));
    try testing.expectEqual(@as(f64, 0), sl.downsideDeviation(none, 0, 252));
    const empty_hist = try sl.histogram(a, &[_]f64{ std.math.nan(f64), std.math.inf(f64) }, 4);
    defer a.free(empty_hist);
    try testing.expectEqual(@as(usize, 0), empty_hist.len);
    const r0 = try sl.rollingMean(a, &[_]f64{ 1, 2 }, 0);
    defer a.free(r0);
    try testing.expectEqual(@as(usize, 0), r0.len);
    const rr = try sl.riskMetrics(a, none, .{});
    try testing.expectEqual(@as(f64, 0), rr.ann_vol);
    try testing.expect(std.math.isNan((try sl.riskMetrics(a, &[_]f64{-1.5}, .{})).mdd));
    try testing.expect(std.math.isNan(sl.volatility(&[_]f64{ 0.1, 0.2 }, 0)));
    try testing.expect(std.math.isNan(sl.volatility(&[_]f64{ std.math.nan(f64), 0.2 }, 252)));
    try testing.expect(std.math.isNan(try sl.varHistoric(a, &[_]f64{0.1}, 1.5)));
    try testing.expect(std.math.isNan(try sl.cvarHistoric(a, &[_]f64{std.math.nan(f64)}, 0.9)));
    // A NaN flow is no answer, never the rate without that flow.
    const d = [_][]const u8{ "2024-01-01", "2024-06-01", "2025-01-01" };
    try testing.expectError(error.XirrNoRoot, sl.xirr(a, &d, &[_]f64{ 100, std.math.nan(f64), 0 }, &[_]f64{ 100, 100, 110 }, .none, null));
}

test "named statistics match their definitions" {
    const a = testing.allocator;
    const xs = [_]f64{ 0.1, -0.2, 0.05, -0.05, 0.1 };
    // two periods under water from the running peak, by hand
    const lv = [_]f64{ 1.1, 0.88, 0.924, 0.8778, 0.96558 };
    var s: f64 = 0;
    var peak: f64 = 1;
    for (lv) |l| {
        peak = @max(peak, l);
        s += (l / peak - 1) * (l / peak - 1);
    }
    try testing.expectApproxEqRel(@sqrt(s / 5), sl.ulcerIndex(&xs), 1e-14);
    // ulcer as percent in the row
    try testing.expectApproxEqRel(sl.ulcerIndex(&xs) * 100, (try sl.riskMetrics(a, &xs, .{})).ulcer, 1e-13);
    // VaR and CVaR at 95 % are the row's var95 and cvar95
    const row = try sl.riskMetrics(a, &xs, .{});
    try testing.expectApproxEqRel(row.var95, try sl.varHistoric(a, &xs, 0.95), 1e-14);
    try testing.expectApproxEqRel(row.cvar95, try sl.cvarHistoric(a, &xs, 0.95), 1e-14);
    try testing.expectApproxEqRel(row.downside, sl.downsideDeviation(&xs, 0, 252), 1e-14);
    try testing.expectApproxEqRel(row.ann_vol, sl.volatility(&xs, 252), 1e-14);
    // rollingApplyCtx passes its parameter
    const r = try sl.rollingApplyCtx(a, &xs, 2, @as(f64, 2), struct {
        fn f(k: f64, w: []const f64) f64 {
            return k * (w[0] + w[1]);
        }
    }.f);
    defer a.free(r);
    try testing.expectApproxEqRel(@as(f64, -0.2), r[0], 1e-14);
    try testing.expectEqual(@as(usize, 4), r.len);
    const t = try sl.twrDaily(a, &[_]f64{ 100, 110 }, &[_]f64{ 0, 0 }, &[_]f64{ 100, 100 }, 0);
    defer a.free(t);
    try testing.expectEqual(sl.Twr{ .row = 1, .r = 0.1 }, t[0]);
}

test "drawdownSeries keeps its answer past the f64 range of the level" {
    const a = testing.allocator;
    var xs: [4000]f64 = undefined;
    @memset(&xs, 1.0); // doubles every period: 2^4000 is out of range
    xs[3999] = -0.5;
    const dd = try sl.drawdownSeries(a, &xs);
    defer a.free(dd);
    try testing.expectApproxEqRel(@as(f64, -0.5), dd[3999], 1e-12);
    try testing.expectApproxEqRel(sl.maxDrawdown(&xs), dd[3999], 1e-12);
}

test "allocation failure is an error and leaks nothing" {
    const f = struct {
        fn run(a: std.mem.Allocator) !void {
            const x = [_]f64{ 0.1, -0.2, 0.05, -0.05, 0.1, 0.02 };
            const y = [_]f64{ 0.05, -0.1, 0.02, -0.02, 0.2, 0.01 };
            const lv = [_]f64{ 1, 0.9, 1.1, 1.0, 0.95, 1.2 };
            const d = [_][]const u8{ "2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04", "2024-01-05", "2024-01-06" };
            // This series has no root; only the allocation path matters here.
            _ = sl.xirr(a, &d, &y, &lv, .value_includes_flow, null) catch |e| switch (e) {
                error.OutOfMemory => return e,
                else => {},
            };
            a.free(try sl.twrDaily(a, &lv, &x, &lv, 0));
            a.free(try sl.histogram(a, &x, 3));
            _ = try sl.riskMetrics(a, &x, .{});
            _ = try sl.benchmarkStats(a, &x, &y, 0.1, 0, 252);
            const br = try sl.brinsonAttribution(a, &x, &y, &x, &y);
            a.free(br.rows);
            a.free(try sl.cumulativeReturns(a, &x));
            a.free(try sl.drawdownSeries(a, &x));
            a.free(try sl.drawdownEpisodes(a, &d, &lv, 2));
            a.free(try sl.rollingSharpe(a, &x, 2));
            a.free(try sl.rollingBetaAlpha(a, &x, &y, 2, 252));
            a.free(try sl.correlationMatrix(a, &.{ &x, &y }, 2));
            a.free(try sl.monteCarlo(a, .{ .start = 1, .mu_ann = 0, .vol_ann = 0.1, .monthly = 0, .years = 1, .paths = 3 }));
            _ = try sl.tradeStats(a, &x);
            _ = try sl.varHistoric(a, &x, 0.9);
            _ = try sl.cvarHistoric(a, &x, 0.9);
        }
    }.run;
    try testing.checkAllAllocationFailures(testing.allocator, f, .{});
}

test "informationRatio, treynorRatio, greeks, rSquared against quantstats and ffn" {
    const ref = @import("testdata/benchmark_vectors.zig");
    for (ref.cases) |c| {
        try testing.expectApproxEqRel(c.info_qs, sl.informationRatio(c.p, c.b), 1e-11);
        try testing.expectApproxEqRel(c.info_ffn, sl.informationRatio(c.p, c.b), 1e-11);
        try testing.expectApproxEqRel(c.treynor, sl.treynorRatio(c.p, c.b, c.rf), 1e-11);
        const g = sl.greeks(c.p, c.b, 252);
        try testing.expectApproxEqRel(c.beta, g.beta, 1e-11);
        try testing.expectApproxEqRel(c.alpha, g.alpha, 1e-10);
        try testing.expectApproxEqRel(c.r2, sl.rSquared(c.p, c.b), 1e-11);
    }
    const x = [_]f64{ 0.1, 0.2 };
    const y = [_]f64{0.1};
    const nan = std.math.nan(f64);
    try testing.expect(std.math.isNan(sl.informationRatio(&x, &y)));
    try testing.expect(std.math.isNan(sl.treynorRatio(&x, &y, 0)));
    try testing.expect(std.math.isNan(sl.greeks(&x, &y, 252).beta));
    try testing.expect(std.math.isNan(sl.informationRatio(&[_]f64{ nan, 0.1 }, &x)));
    try testing.expect(std.math.isNan(sl.treynorRatio(&[_]f64{ -2, 0.1 }, &x, 0)));
    try testing.expectEqual(@as(f64, 0), sl.informationRatio(&x, &x));
    try testing.expectEqual(@as(f64, 0), sl.treynorRatio(&x, &[_]f64{ 0.1, 0.1 }, 0));
}

test "capture, rolling alpha and beta against empyrical and quantstats" {
    const ref = @import("testdata/benchmark_vectors.zig");
    const a = testing.allocator;
    for (ref.cases) |c| {
        try testing.expectApproxEqRel(c.capture, sl.capture(c.p, c.b, 252), 1e-11);
        try testing.expectApproxEqRel(c.up, try sl.upCapture(a, c.p, c.b, 252), 1e-11);
        try testing.expectApproxEqRel(c.down, try sl.downCapture(a, c.p, c.b, 252), 1e-11);
        try testing.expectApproxEqRel(c.up_down, try sl.upDownCapture(a, c.p, c.b, 252), 1e-11);
        const ud = try sl.rollUpDownCapture(a, c.p, c.b, c.window, 252);
        defer a.free(ud);
        try testing.expectEqual(c.roll_up_down.len, ud.len);
        for (ud, c.roll_up_down) |g, e| try testing.expectApproxEqRel(e, g, 1e-10);
        const ab = try sl.rollAlphaBeta(a, c.p, c.b, c.window, 0, 252);
        defer a.free(ab);
        try testing.expectEqual(c.roll_alpha.len, ab.len);
        for (ab, c.roll_alpha, c.roll_beta) |g, ea, eb| {
            try testing.expectApproxEqRel(ea, g.alpha, 1e-10);
            try testing.expectApproxEqRel(eb, g.beta, 1e-10);
        }
        const gr = try sl.rollingGreeks(a, c.p, c.b, c.window);
        defer a.free(gr);
        try testing.expectEqual(c.greeks_alpha.len, gr.len);
        for (gr, c.greeks_alpha, c.greeks_beta) |g, ea, eb| {
            try testing.expectApproxEqRel(ea, g.alpha, 1e-10);
            try testing.expectApproxEqRel(eb, g.beta, 1e-10);
        }
    }
}

test "the small converters and their edges" {
    const a = testing.allocator;
    try testing.expectApproxEqRel(366.0 / 365.25, try sl.yearFrac("2020-01-01", "2021-01-01"), 1e-15);
    try testing.expectError(error.BadDate, sl.yearFrac("2020-01-01", "x"));
    const x = [_]f64{ 0.1, -0.2, 0.3 };
    const y = [_]f64{0.1};
    const nan = std.math.nan(f64);
    try testing.expect(std.math.isNan(sl.capture(&x, &y, 252)));
    try testing.expectError(error.LengthMismatch, sl.upCapture(a, &x, &y, 252));
    try testing.expectError(error.LengthMismatch, sl.downCapture(a, &x, &y, 252));
    try testing.expectError(error.LengthMismatch, sl.upDownCapture(a, &x, &y, 252));
    try testing.expectError(error.LengthMismatch, sl.rollUpDownCapture(a, &x, &y, 1, 252));
    try testing.expectError(error.LengthMismatch, sl.rollAlphaBeta(a, &x, &y, 1, 0, 252));
    try testing.expect(std.math.isNan(try sl.upCapture(a, &[_]f64{ nan, 0, 0 }, &x, 252)));
    try testing.expect(std.math.isNan(try sl.upDownCapture(a, &x, &x, 0)));
    // no falling period: no down capture, so an up capture over nothing
    try testing.expect(std.math.isInf(try sl.upDownCapture(a, &[_]f64{ 0.1, 0.1 }, &[_]f64{ 0.1, 0.2 }, 252)));

    const mean = struct {
        fn f(w: []const f64) f64 {
            var s: f64 = 0;
            for (w) |v| s += v;
            return s / @as(f64, @floatFromInt(w.len));
        }
    }.f;
    const r = try sl.resampleReturns(a, &x, mean, 7, 500);
    defer a.free(r);
    try testing.expectEqual(@as(usize, 500), r.len);
    // every sample's mean lies between the smallest and the largest value
    for (r) |v| try testing.expect(v >= -0.2 - 1e-12 and v <= 0.3 + 1e-12);
    const r2 = try sl.resampleReturns(a, &x, mean, 7, 500);
    defer a.free(r2);
    try testing.expectEqualSlices(f64, r, r2);
    const none = try sl.resampleReturns(a, &[_]f64{}, mean, 7, 5);
    defer a.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    const bad = try sl.resampleReturns(a, &[_]f64{nan}, mean, 7, 2);
    defer a.free(bad);
    try testing.expect(std.math.isNan(bad[0]));
    try testing.expectError(error.TooLarge, sl.resampleReturns(a, &x, mean, 7, sl.max_resample_sims + 1));
}

test "review 2026-11-05: bad input is NaN, not a finite wrong number" {
    const a = testing.allocator;
    const nan = std.math.nan(f64);
    const x = [_]f64{ 0.01, -0.02, 0.03, 0.01 };
    const hole = [_]f64{ 0.01, nan, 0.02, 0.01 };
    const inf_b = [_]f64{ 0.01, std.math.inf(f64), 0.02, 0.01 };
    // a hole in the benchmark used to read as "no variance": beta 0, alpha = port_ann
    for ([_][]const f64{ &hole, &inf_b }) |b| {
        try testing.expect(std.math.isNan(sl.beta(&x, b)));
        try testing.expect(std.math.isNan(sl.rSquared(&x, b)));
        const ba = sl.betaAlpha(&x, b, 0.1, 0.05);
        try testing.expect(std.math.isNan(ba.beta) and std.math.isNan(ba.alpha) and std.math.isNan(ba.r2));
        try testing.expect(std.math.isNan(sl.trackingRisk(&x, b, 252).tracking_error));
        try testing.expect(std.math.isNan((try sl.benchmarkStats(a, &x, b, 0.1, 0, 252)).treynor));
        const rb = try sl.rollingBetaAlpha(a, &x, b, 4, 252);
        defer a.free(rb);
        try testing.expect(std.math.isNan(rb[0].beta));
    }
    // only the window holding the hole is undefined
    const rb2 = try sl.rollingBetaAlpha(a, &[_]f64{ 0.1, 0.2, 0.1, 0.3, 0.2 }, &[_]f64{ nan, 0.1, 0.2, 0.1, 0.3 }, 2, 252);
    defer a.free(rb2);
    try testing.expect(std.math.isNan(rb2[0].beta));
    try testing.expect(!std.math.isNan(rb2[1].beta));

    // a return below -1 used to pass through an integer power as a finite capture
    const up = [_]f64{ 0.1, 0.1 };
    const br = try sl.benchmarkStats(a, &[_]f64{ -2, 0.1 }, &up, 0, 0, 2);
    try testing.expect(std.math.isNan(br.up_capture));
    const rc = try sl.rollUpCapture(a, &[_]f64{ -2, 0.1 }, &up, 2, 2);
    defer a.free(rc);
    try testing.expect(std.math.isNan(rc[0]));
    try testing.expect(std.math.isNan((try sl.benchmarkStats(a, &up, &up, 0, 0, 0)).up_capture));

    // parameters
    try testing.expect(std.math.isNan(sl.trackingRisk(&x, &x, 0).tracking_error));
    try testing.expect(std.math.isNan((try sl.riskMetrics(a, &x, .{ .periods_per_year = 0 })).ann_vol));

    // NaN parameters used to floor at 0: a plausible projection of nothing
    for ([_]sl.MonteCarloSpec{
        .{ .start = nan, .mu_ann = 0, .vol_ann = 0.1, .monthly = 0, .years = 1, .paths = 3 },
        .{ .start = 1, .mu_ann = -1.5, .vol_ann = 0.1, .monthly = 0, .years = 1, .paths = 3 },
        .{ .start = 1, .mu_ann = 0, .vol_ann = nan, .monthly = 0, .years = 1, .paths = 3 },
        .{ .start = 1, .mu_ann = 0, .vol_ann = -0.1, .monthly = 0, .years = 1, .paths = 3 },
        .{ .start = 1, .mu_ann = 0, .vol_ann = 0.1, .monthly = std.math.inf(f64), .years = 1, .paths = 3 },
    }) |spec| {
        const m = try sl.monteCarlo(a, spec);
        defer a.free(m);
        try testing.expectEqual(@as(usize, 13), m.len);
        try testing.expect(std.math.isNan(m[12].p50));
    }

    const mc = try sl.montecarlo(a, &x, 5, 1, nan, nan);
    try testing.expect(std.math.isNan(mc.bust_probability.?) and std.math.isNan(mc.goal_probability.?));
}

test "review 2026-11-05: drawdownEpisodes skips a missing price, as ffn's forward fill" {
    const a = testing.allocator;
    const nan = std.math.nan(f64);
    const d = [_][]const u8{ "2020-01-01", "2020-01-02", "2020-01-03", "2020-01-04", "2020-01-05", "2020-01-06", "2020-01-07", "2020-01-08" };
    // ffn on these prices: episodes of -0.181818 and -0.166667
    const e = try sl.drawdownEpisodes(a, &d, &[_]f64{ 100, 110, nan, 90, 95, 120, 100, 105 }, 5);
    defer a.free(e);
    try testing.expectEqual(@as(usize, 2), e.len);
    try testing.expectApproxEqRel(@as(f64, -20.0 / 110.0), e[0].depth, 1e-14);
    try testing.expectEqual(@as(usize, 1), e[0].peak_i);
    try testing.expectEqual(@as(usize, 3), e[0].trough_i);
    try testing.expectEqual(@as(?usize, 5), e[0].recovery_i);
    try testing.expectApproxEqRel(@as(f64, -20.0 / 120.0), e[1].depth, 1e-14);
    try testing.expectEqual(@as(?usize, null), e[1].recovery_i);
    // a zero start and a wipe-out both have an answer
    const e2 = try sl.drawdownEpisodes(a, d[0..4], &[_]f64{ 0, 10, 0, 10 }, 5);
    defer a.free(e2);
    try testing.expectEqual(@as(usize, 1), e2.len);
    try testing.expectEqual(@as(f64, -1), e2[0].depth);
    try testing.expectError(error.DatesNotSorted, sl.drawdownEpisodes(a, &[_][]const u8{ "2020-01-02", "2020-01-01" }, &[_]f64{ 1, 2 }, 1));
}

test "review 2026-11-05: xirrPrecise does not stop at the first guess on tiny cashflows" {
    const a = testing.allocator;
    const d = [_][]const u8{ "2024-01-01", "2025-01-01" };
    // 2e-3 flows would pass the 1e-6 flow filter; the NPV tolerance is set above them
    const r = try sl.xirrPrecise(a, &d, &[_]f64{ 2e-3, 0 }, &[_]f64{ 2e-3, 2.4e-3 }, .none, .{ .tol = 1e-2, .initial_guess = 0.05 });
    try testing.expectApproxEqAbs(std.math.pow(f64, 1.2, 365.25 / 366.0) - 1, r, 1e-8);
}

test "review 2026-11-05: exposure is exact, factor shape alone costs nothing" {
    const r = @import("ratios.zig");
    var xs: [100]f64 = @splat(0);
    for (xs[0..7]) |*x| x.* = 0.01;
    try testing.expectEqual(@as(f64, 0.07), r.exposure(&xs));
    const f = @import("factor.zig");
    const none: []const f64 = &.{};
    const out = try f.computeExposures(testing.allocator, .{ .periods = std.math.maxInt(usize), .assets = 0, .factors = 0 }, none, none);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 0), out.len);
}

// ── mutation survivors (2026-11-05): every expected value below is derived by hand ──

test "annualize: zero or negative days is 0, not a pole" {
    try testing.expectEqual(@as(f64, 0), sl.annualize(0.5, 0));
    try testing.expectEqual(@as(f64, 0), sl.annualize(0.5, -10));
}

test "gaussianCVaR at confidence 1 is the (infinite) Gaussian VaR, not NaN" {
    // alpha = 0 hands over to gaussianVaR: z = -inf, VaR = -(mean + z * sd) = +inf for sd > 0.
    const c = sl.gaussianCVaR(0.01, 0.02, 1.0);
    try testing.expect(std.math.isInf(c) and c > 0);
}

test "sharpeRatio and stability on degenerate series" {
    // All-zero series: zero spread, mean 0, so the answer is the documented 0 (not 0/0).
    try testing.expectEqual(@as(f64, 0), sl.sharpeRatio(&.{ 0, 0, 0 }, 0, 252));
    // Two points always lie on a line: R^2 of the cumulative log return is 1.
    try testing.expectApproxEqAbs(@as(f64, 1), sl.stability(&.{ 0.1, 0.2 }), 1e-12);
    // A flat cumulative line (every return 0) has no straightness to measure: 0.
    try testing.expectEqual(@as(f64, 0), sl.stability(&.{ 0, 0, 0 }));
}

test "xirr: a flow of exactly 1e-6 is no flow, 1.5e-6 is one" {
    const a = testing.allocator;
    const dates = [_][]const u8{ "2023-01-01", "2024-01-01" };
    // 1e-6 is dropped ("at most 1e-6 counts as no flow"): only the terminal value is left,
    // a single cash flow has no root.
    try testing.expectError(error.XirrNoRoot, sl.xirr(a, &dates, &.{ 1e-6, 0 }, &.{ 0, 2e-6 }, .none, sl.default_rate_tol));
    // 1.5e-6 is kept: -1.5e-6 on day 0 and +3e-6 after 365 days, ACT/365.25,
    // so (1 + r)^(365 / 365.25) = 2.
    const r = try sl.xirr(a, &dates, &.{ 1.5e-6, 0 }, &.{ 0, 3e-6 }, .none, sl.default_rate_tol);
    try testing.expectApproxEqAbs(std.math.pow(f64, 2.0, 365.25 / 365.0) - 1.0, r, 1e-6);
}

test "twrDaily: a row exactly at min_value seeds the previous value" {
    const a = testing.allocator;
    // Row 0 (value 5) is not below min_value 5, so it seeds; row 1 gives (6 - 5 - 0) / 10.
    const out = try sl.twrDaily(a, &.{ 5, 6 }, &.{ 0, 0 }, &.{ 10, 10 }, 5);
    defer a.free(out);
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqual(@as(usize, 1), out[0].row);
    try testing.expectApproxEqAbs(@as(f64, 0.1), out[0].r, 1e-15);
}

test "riskMetrics: cvar tail includes the quantile element; one return ignores span_days" {
    const a = testing.allocator;
    // 21 returns: the 5 % quantile sits at position 0.05 * 20 = 1 exactly, i.e. on the
    // second-smallest value -0.05. VaR = 0.05; the tail is {-0.10, -0.05}, CVaR = 0.075.
    var rets: [21]f64 = undefined;
    rets[0] = -0.10;
    rets[1] = -0.05;
    @memset(rets[2..], 0.01);
    const row = try sl.riskMetrics(a, &rets, .{});
    try testing.expectApproxEqAbs(@as(f64, 0.05), row.var95, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.075), row.cvar95, 1e-12);

    // One return of -10 %: drawdown -0.1. span_days only applies from two returns on,
    // so the annualised return is ann_return = 0.5 and calmar = 0.5 / 0.1 = 5 (with the
    // span it would be 0.9^1 - 1 = -0.1 and calmar -1).
    const one = try sl.riskMetrics(a, &.{-0.10}, .{ .ann_return = 0.5, .span_days = 365.25 });
    try testing.expectApproxEqRel(@as(f64, -0.1), one.mdd, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 5.0), one.calmar, 1e-12);
}

test "rSquared of a constant series is 0, treynorRatio with a negative beta" {
    try testing.expectEqual(@as(f64, 0), sl.rSquared(&.{ 1, 1, 1 }, &.{ 1, 2, 3 }));
    // p = -2 b exactly, so beta = -2. total return of p: 0.98 * 1.04 * 0.94 * 1.02 - 1 =
    // 0.97720896 - 1 = -0.02279104; treynor = (total - 0) / beta = 0.01139552.
    const b = [_]f64{ 0.01, -0.02, 0.03, -0.01 };
    const p = [_]f64{ -0.02, 0.04, -0.06, 0.02 };
    try testing.expectApproxEqRel(@as(f64, 0.01139552), sl.treynorRatio(&p, &b, 0), 1e-12);
}

test "brinsonAttribution: a held segment outside the benchmark keeps its stated benchmark return" {
    const a = testing.allocator;
    // C has benchmark weight 0 but a stated benchmark return 0.05 (finite): that stated
    // return is used. rb_total = 0.6 * 0.08 + 0.4 * 0.03 = 0.06.
    // C: allocation = (0.2 - 0) * (0.05 - 0.06) = -0.002; selection = 0;
    //    interaction = (0.2 - 0) * (0.07 - 0.05) = 0.004.
    const res = try sl.brinsonAttribution(a, &.{ 0.5, 0.3, 0.2 }, &.{ 0.6, 0.4, 0 }, &.{ 0.10, 0.02, 0.07 }, &.{ 0.08, 0.03, 0.05 });
    defer a.free(res.rows);
    try testing.expectApproxEqAbs(@as(f64, -0.002), res.rows[2].allocation, 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0), res.rows[2].selection, 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0.004), res.rows[2].interaction, 1e-15);
}

test "cumulativeReturns: a -100 % period wipes the level out, it is not NaN" {
    const a = testing.allocator;
    // levels 1.1, 1.1 * 0 = 0, 0 * 1.5 = 0, so the curve is 0.1, -1, -1.
    const out = try sl.cumulativeReturns(a, &.{ 0.1, -1.0, 0.5 });
    defer a.free(out);
    try testing.expectApproxEqAbs(@as(f64, 0.1), out[0], 1e-15);
    try testing.expectEqual(@as(f64, -1), out[1]);
    try testing.expectEqual(@as(f64, -1), out[2]);
}

test "drawdownEpisodes: equal dates, recovery to exactly the peak, tied troughs" {
    const a = testing.allocator;
    // Two rows on one day are sorted (not backwards): one open episode of depth
    // (90 - 100) / 100 = -0.1 and a fall of 0 days.
    const dup = try sl.drawdownEpisodes(a, &.{ "2020-01-01", "2020-01-01" }, &.{ 100, 90 }, 5);
    defer a.free(dup);
    try testing.expectEqual(@as(usize, 1), dup.len);
    try testing.expectEqual(@as(i64, 0), dup[0].fall_days);
    try testing.expectEqual(@as(?usize, null), dup[0].recovery_i);
    try testing.expectApproxEqAbs(@as(f64, -0.1), dup[0].depth, 1e-15);

    // Back to exactly 100 on the 3rd day ends the episode (a level at the peak ends it).
    const rec = try sl.drawdownEpisodes(a, &.{ "2020-01-01", "2020-01-02", "2020-01-03" }, &.{ 100, 90, 100 }, 5);
    defer a.free(rec);
    try testing.expectEqual(@as(usize, 1), rec.len);
    try testing.expectEqual(@as(?usize, 2), rec[0].recovery_i);
    try testing.expectEqual(@as(?i64, 1), rec[0].recover_days);

    // Two equal lows (90, 90): the trough is the FIRST one: index 1, fall 1 day, recovery
    // 2 days after the trough.
    const tie = try sl.drawdownEpisodes(a, &.{ "2020-01-01", "2020-01-02", "2020-01-03", "2020-01-04" }, &.{ 100, 90, 90, 100 }, 5);
    defer a.free(tie);
    try testing.expectEqual(@as(usize, 1), tie.len);
    try testing.expectEqual(@as(usize, 1), tie[0].trough_i);
    try testing.expectEqual(@as(i64, 1), tie[0].fall_days);
    try testing.expectEqual(@as(?i64, 2), tie[0].recover_days);
}

test "correlationMatrix: min_overlap equal to the shared count passes, one more is NaN" {
    const a = testing.allocator;
    // y = 2x: deviations (-1, 0, 1) and (-2, 0, 2): cov 4, vx 2, vy 8, r = 4 / sqrt(16) = 1.
    const series = [_][]const f64{ &.{ 1, 2, 3 }, &.{ 2, 4, 6 } };
    const m = try sl.correlationMatrix(a, &series, 3);
    defer a.free(m);
    try testing.expectApproxEqAbs(@as(f64, 1), m[1], 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 1), m[2], 1e-15);
    const m4 = try sl.correlationMatrix(a, &series, 4);
    defer a.free(m4);
    try testing.expect(std.math.isNan(m4[1]));
}

test "correlationMatrix: exactly max_corr_keys series is allowed, one more is TooLarge" {
    const a = testing.allocator;
    const empty: []const f64 = &.{};
    const many = try a.alloc([]const f64, sl.max_corr_keys + 1);
    defer a.free(many);
    @memset(many, empty);
    const k = sl.max_corr_keys;
    const out = try sl.correlationMatrix(a, many[0..k], 1);
    defer a.free(out);
    try testing.expectEqual(k * k, out.len);
    try testing.expectEqual(@as(f64, 1), out[k * k - 1]);
    try testing.expectError(error.TooLarge, sl.correlationMatrix(a, many, 1));
}

test "monteCarlo: a rounded one-month horizon has month 1; percentiles are at 0.1 / 0.5 / 0.9" {
    const a = testing.allocator;
    // years = 0.1 -> round(1.2) = 1 month. mu = 0, vol = 0, monthly 100: every path is
    // 1000 * 1 + 100 = 1100 after month 1.
    const flat = try sl.monteCarlo(a, .{ .start = 1000, .mu_ann = 0, .vol_ann = 0, .monthly = 100, .years = 0.1, .paths = 5 });
    defer a.free(flat);
    try testing.expectEqual(@as(usize, 2), flat.len);
    try testing.expectEqual(@as(f64, 1100), flat[1].p10);
    try testing.expectEqual(@as(f64, 1100), flat[1].p90);

    // sig_m = sqrt(12) / sqrt(12) = 1, mu_m = 0: v = max(0, 100 (1 + Z)). The path is
    // floored at 0 when Z < -1, which has probability 15.9 %: more than 10 %, less than
    // 20 %, so p10 is exactly 0 and a 20 % quantile would not be (2000 paths: the share
    // has a standard error of 0.8 %).
    const mc = try sl.monteCarlo(a, .{ .start = 100, .mu_ann = 0, .vol_ann = @sqrt(12.0), .monthly = 0, .years = 0.1 });
    defer a.free(mc);
    try testing.expectEqual(@as(f64, 0), mc[1].p10);
    try testing.expect(mc[1].p50 > 50 and mc[1].p50 < 150);
    try testing.expect(mc[1].p90 > mc[1].p50);
}

test "histogram: 0 bins means 1, exactly max_histogram_bins is allowed" {
    const a = testing.allocator;
    // 0 bins -> 1 bin holding all three values (not 2 bins).
    const one = try sl.histogram(a, &.{ 1, 2, 3 }, 0);
    defer a.free(one);
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqual(@as(u64, 3), one[0].count);
    // The cap is inclusive: 65 536 bins are fine, one more is TooLarge.
    const cap = try sl.histogram(a, &.{ 1, 2 }, sl.max_histogram_bins);
    defer a.free(cap);
    try testing.expectEqual(sl.max_histogram_bins, cap.len);
    try testing.expectError(error.TooLarge, sl.histogram(a, &.{ 1, 2 }, sl.max_histogram_bins + 1));
}

test "xirrPrecise: tiny cash flows still converge on the rate, not on the first |NPV| < tol" {
    const a = testing.allocator;
    // -2e-6 on day 0, +2.2e-6 after 365 days (ACT/365.25): (1 + r)^(365/365.25) = 1.1.
    // |NPV| at the first guess 0.1 is about 1e-10, far below tol 1e-8, but the rate is
    // 1.1^(365.25/365) - 1 = 0.100066..., not 0.1.
    const dates = [_][]const u8{ "2023-01-01", "2024-01-01" };
    const r = try sl.xirrPrecise(a, &dates, &.{ 2e-6, 0 }, &.{ 0, 2.2e-6 }, .none, .{});
    try testing.expectApproxEqAbs(std.math.pow(f64, 1.1, 365.25 / 365.0) - 1.0, r, 1e-7);
}
