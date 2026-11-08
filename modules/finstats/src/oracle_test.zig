// SPDX-License-Identifier: MIT

//! **External anchor: reference values from foreign implementations.**
//!
//! `testdata/oracle_vectors.zig` was made by `tools/oracle.py`: seeded
//! synthetic return series (fat tails, crashes, a calm one, a benchmark and a
//! portfolio regressed on it) and dated cash-flow schedules, with every
//! expected value computed by a library this module did not write -- pyxirr,
//! scipy, numpy, pandas, empyrical-reloaded (the generator's docstring names
//! which function answers for which). Here each is recomputed by this module
//! and compared within the tolerance the function documents.
//!
//! Also replayed (see the generator's docstring for the exact foreign function
//! and any convention conversion): correlationMatrix (pandas), drawdownEpisodes
//! and ulcer (ffn, quantstats), tradeStats (quantstats), benchmarkStats
//! (empyrical, quantstats) and sharpe / sortino / calmar (CAGR from ffn,
//! denominators from empyrical; the division stays this module's own).
//!
//! The Cornish-Fisher pair is anchored on R PerformanceAnalytics through a
//! second generator, `tools/cf_oracle.R` → `testdata/cf_vectors.zig` (R is a
//! one-shot tool: the vectors are committed, R is not needed to replay them).
//!
//! `twrDaily` and `brinsonAttribution`: published numbers, `attrib_oracle_test.zig`
//! (see SPEC Anchoring).

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const ref = @import("testdata/oracle_vectors.zig");

fn near(want: f64, got: f64, abs_tol: f64, rel_tol: f64) !void {
    if (@abs(want - got) <= abs_tol + rel_tol * @abs(want)) return;
    std.debug.print("want {d}, got {d} (diff {e})\n", .{ want, got, want - got });
    return error.TestUnexpectedResult;
}

test "oracle: per-series statistics against scipy, numpy, pandas and empyrical" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for (ref.series) |s| {
        errdefer std.debug.print("series {s}\n", .{s.name});
        try near(s.skew, fs.skewness(s.values), 1e-12, 1e-10);
        try near(s.kurt, fs.excessKurtosis(s.values), 1e-12, 1e-10);
        for (s.quantiles) |q| try near(q[1], try fs.quantile(a, s.values, q[0]), 1e-15, 1e-12);
        for (s.omega) |o| try near(o[1], fs.omegaRatio(s.values, o[0]), 0, 1e-12);

        const rm = try fs.riskMetrics(a, s.values, .{});
        try near(s.ann_vol, rm.ann_vol, 0, 1e-12);
        try near(s.downside, rm.downside, 0, 1e-12);
        try near(s.var95, rm.var95, 1e-15, 1e-12);
        try near(s.cvar95, rm.cvar95, 1e-15, 1e-12);
        try near(s.mdd, rm.mdd, 1e-15, 1e-10);

        // Acklam's quantile carries |rel err| < 1.15e-9 into z; the tail
        // mean came from scipy's numerical integration.
        for (s.gauss) |g| {
            try near(g.var_, fs.gaussianVaR(g.mean, g.sd, g.conf), 1e-12, 1e-8);
            try near(g.cvar, fs.gaussianCVaR(g.mean, g.sd, g.conf), 1e-12, 1e-8);
        }

        const rmean = try fs.rollingMean(a, s.values, ref.window);
        const rstd = try fs.rollingVolatility(a, s.values, ref.window);
        try testing.expectEqual(s.roll_mean.len, rmean.len);
        try testing.expectEqual(s.roll_std.len, rstd.len);
        for (s.roll_mean, rmean) |want, got| try near(want, got, 1e-15, 1e-9);
        for (s.roll_std, rstd) |want, got| try near(want, got, 1e-15, 1e-9);
    }
}

test "oracle: beta and r2 against scipy.stats.linregress" {
    const port = ref.series[4].values;
    const bench = ref.series[3].values;
    try testing.expectEqualStrings("port", ref.series[4].name);
    try testing.expectEqualStrings("bench", ref.series[3].name);
    const out = fs.betaAlpha(port, bench, 0, 0);
    try near(ref.beta, out.beta, 0, 1e-12);
    try near(ref.r2, out.r2, 0, 1e-12);
}

test "oracle: the standard normal against scipy.stats.norm" {
    // Acklam: |relative error| < 1.15e-9 (the doc comment's claim, held here
    // on both tails, both region seams and the centre).
    for (ref.ppf) |p| try near(p[1], fs.invNormCdf(p[0]), 1e-15, 1.15e-9);
    for (ref.pdf) |z| try near(z[1], fs.normalPdf(z[0]), 1e-300, 1e-14);
}

test "oracle: xirr and xirrPrecise against pyxirr (ACT/365.25)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ref.schedules, 0..) |s, k| {
        errdefer std.debug.print("schedule {d}\n", .{k});
        const dates = try a.alloc([]const u8, s.rows.len);
        const flows = try a.alloc(f64, s.rows.len);
        const values = try a.alloc(f64, s.rows.len);
        for (s.rows, 0..) |r, i| {
            dates[i] = r.date;
            flows[i] = r.flow;
            values[i] = r.value;
        }
        const opening: fs.Opening = switch (s.opening) {
            .none => .none,
            .value_includes_flow => .value_includes_flow,
        };
        // `rate_tol` defaults to 1e-9; Newton's `tol` to 1e-8 on NPV.
        try near(s.xirr, try fs.xirr(a, dates, flows, values, opening, fs.default_rate_tol), 1e-8, 0);
        try near(s.xirr, try fs.xirrPrecise(a, dates, flows, values, opening, .{}), 1e-8, 0);
    }
}

test "oracle: ulcer, sharpe, sortino, calmar (CAGR from ffn, denominators from empyrical)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ref.ratios) |rr| {
        const s = ref.series[rr.series];
        errdefer std.debug.print("series {s} rf {d}\n", .{ s.name, rr.rf });
        const rm = try fs.riskMetrics(a, s.values, .{ .rf = rr.rf, .span_days = try fs.daySpan(ref.dates[0], ref.dates[s.values.len - 1]) });
        // Both foreign ulcers were given a level that starts at 1 (baseline point) and
        // converted to this module's mean-over-n percent convention (see oracle.py).
        try near(rr.ulcer_ffn, rm.ulcer, 0, 1e-12);
        try near(rr.ulcer_qs_as_ours, rm.ulcer, 0, 1e-12);
        try near(rr.sharpe, rm.sharpe, 1e-15, 1e-10);
        try near(rr.sortino, rm.sortino, 1e-15, 1e-10);
        try near(rr.calmar, rm.calmar, 1e-15, 1e-10);
    }
}

test "oracle: tradeStats against quantstats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ref.trades) |t| {
        errdefer std.debug.print("series {s}\n", .{t.name});
        const ts = try fs.tradeStats(a, t.values);
        try near(t.win_rate, ts.win_rate, 0, 1e-14);
        try near(t.payoff, ts.payoff, 0, 1e-12);
        try near(t.profit_factor, ts.profit_factor, 0, 1e-12);
        try near(t.kelly, ts.kelly, 1e-15, 1e-12);
        try near(t.tail_ratio, ts.tail_ratio, 0, 1e-12);
    }
}

test "oracle: up/down capture against empyrical, treynor against quantstats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bvals = ref.series[3].values;
    try testing.expectEqualStrings("bench", ref.series[3].name);
    for (ref.bench) |b| {
        errdefer std.debug.print("port {s} rf {d}\n", .{ ref.series[b.port].name, b.rf });
        const pv = ref.series[b.port].values;
        const out = try fs.benchmarkStats(a, pv, bvals, b.port_ann, b.rf, 252);
        try near(b.up, out.up_capture, 1e-15, 1e-12);
        try near(b.down, out.down_capture, 1e-15, 1e-12);
        try near(b.treynor, out.treynor, 1e-15, 1e-10);
    }
}

test "oracle: drawdownEpisodes against ffn drawdown_details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ref.dd_cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.label});
        const dates = ref.dates[0..c.levels.len];
        const out = try fs.drawdownEpisodes(a, dates, c.levels, 100_000);
        try testing.expectEqual(c.episodes.len, out.len);
        // Worst first; equal depths may come in either order, so each ffn
        // episode is looked up by its peak date.
        var prev: f64 = -std.math.inf(f64);
        for (out) |ep| {
            const depth = ep.depth * 100;
            try testing.expect(depth >= prev);
            prev = depth;
        }
        for (c.episodes) |e| {
            errdefer std.debug.print("episode peak {s}\n", .{e.peak});
            var found = false;
            for (out) |ep| {
                if (!std.mem.eql(u8, dates[ep.peak_i], e.peak)) continue;
                found = true;
                try testing.expectEqualStrings(e.trough, dates[ep.trough_i]);
                if (e.recovery) |rec| {
                    try testing.expect(ep.recovery_i != null and ep.recover_days != null);
                    try testing.expectEqualStrings(rec, dates[ep.recovery_i.?]);
                    try testing.expectEqual(e.recover_days.?, ep.recover_days.?);
                } else {
                    try testing.expect(ep.recovery_i == null);
                    try testing.expect(ep.recover_days == null);
                }
                try near(e.depth_pct, ep.depth * 100, 1e-12, 1e-9);
                try testing.expectEqual(e.fall_days, ep.fall_days);
            }
            try testing.expect(found);
        }
    }
}

/// The series of `ref.corr_series` on the union of their dates (pandas' outer join):
/// a date a series does not have is NaN, which `correlationMatrix` reads as missing.
fn alignedByDate(a: std.mem.Allocator) ![]const []const f64 {
    var all: std.ArrayList([]const u8) = .empty;
    for (ref.corr_series) |s| for (s.dates) |d| try all.append(a, d);
    std.mem.sort([]const u8, all.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    var uniq: std.ArrayList([]const u8) = .empty;
    for (all.items) |d| {
        if (uniq.items.len == 0 or !std.mem.eql(u8, uniq.items[uniq.items.len - 1], d)) try uniq.append(a, d);
    }
    const out = try a.alloc([]const f64, ref.corr_series.len);
    for (ref.corr_series, out) |s, *col| {
        const buf = try a.alloc(f64, uniq.items.len);
        col.* = buf;
        @memset(buf, std.math.nan(f64));
        for (s.dates, s.values) |d, v| {
            const at = for (uniq.items, 0..) |u, i| {
                if (std.mem.eql(u8, u, d)) break i;
            } else unreachable;
            buf[at] = v;
        }
    }
    return out;
}

test "oracle: correlationMatrix against pandas DataFrame.corr(min_periods)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const aligned = try alignedByDate(a);
    const k = ref.corr_series.len;
    const out = try fs.correlationMatrix(a, aligned, ref.corr_min_overlap);
    try testing.expectEqual(k * k, out.len);
    for (0..k) |i| {
        for (0..k) |j| {
            errdefer std.debug.print("pair {d},{d}\n", .{ i, j });
            const got = out[i * k + j];
            if (i == j) { // pandas gives NaN for a constant/short series; the module defines 1
                try near(1, got, 0, 0);
                continue;
            }
            if (ref.corr_matrix[i][j]) |want| {
                try testing.expect(!std.math.isNan(got));
                try near(want, got, 1e-12, 1e-10);
            } else {
                try testing.expect(std.math.isNan(got));
            }
        }
    }
}

const cf = @import("testdata/cf_vectors.zig");

test "oracle: Cornish-Fisher VaR/CVaR against R PerformanceAnalytics" {
    for (cf.cases) |c| {
        errdefer std.debug.print("series {s} conf {d}\n", .{ c.series, c.conf });
        // The moments PerformanceAnalytics used: same skew/kurtosis definitions
        // as this module's (population), on the same series.
        const s = for (ref.series) |x| {
            if (std.mem.eql(u8, x.name, c.series)) break x;
        } else unreachable;
        try near(c.skew, fs.skewness(s.values), 1e-12, 1e-10);
        try near(c.kurt, fs.excessKurtosis(s.values), 1e-12, 1e-10);
        const v = fs.cornishFisherVaR(c.mean, c.sd, c.skew, c.kurt, c.conf);
        const cv = fs.cornishFisherCVaR(c.mean, c.sd, c.skew, c.kurt, c.conf);
        // Acklam's Φ⁻¹ (|rel err| < 1.15e-9 on z) is the whole error budget:
        // measured ≤ 2.5e-9 (VaR) and ≤ 3.3e-9 (CVaR) relative on these cases.
        try near(c.var_, v, 1e-12, 1e-8);
        try near(c.cvar, cv, 1e-12, 1e-8);
        try testing.expect(cv >= v);
        // The oracle's own uncertainty is well inside the tolerance: R's two
        // integrations (in z and in p) agree.
        try near(c.cvar, c.cvar_p, 0, 1e-9);
    }
}
