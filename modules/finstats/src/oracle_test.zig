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
//! Not covered, for want of a foreign implementation: `twrDaily`,
//! `brinsonAttribution`, the Cornish-Fisher pair (see SPEC Anchoring).

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const dsmod = @import("dataset");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;
const ref = @import("testdata/oracle_vectors.zig");

fn near(want: f64, got: f64, abs_tol: f64, rel_tol: f64) !void {
    if (@abs(want - got) <= abs_tol + rel_tol * @abs(want)) return;
    std.debug.print("want {d}, got {d} (diff {e})\n", .{ want, got, want - got });
    return error.TestUnexpectedResult;
}

/// A one-column (`r`) dataset over `values`.
fn returns(a: std.mem.Allocator, values: []const f64) !Dataset {
    const cols = try a.dupe(Column, &.{.{ .name = "r", .type = .float }});
    const rows = try a.alloc([]const Value, values.len);
    for (values, 0..) |v, i| rows[i] = try a.dupe(Value, &.{.{ .float = v }});
    return .{ .columns = cols, .rows = rows };
}

fn cell(d: Dataset, name: []const u8) f64 {
    for (d.columns, 0..) |c, i| if (std.mem.eql(u8, c.name, name)) return d.rows[0][i].asFloat().?;
    unreachable;
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

        const d = try returns(a, s.values);
        const rm = try fs.riskMetrics(a, d, .{ .ret_col = "r" });
        try near(s.ann_vol, cell(rm, "ann_vol"), 0, 1e-12);
        try near(s.downside, cell(rm, "downside"), 0, 1e-12);
        try near(s.var95, cell(rm, "var95"), 1e-15, 1e-12);
        try near(s.cvar95, cell(rm, "cvar95"), 1e-15, 1e-12);
        try near(s.mdd, cell(rm, "mdd"), 1e-15, 1e-10);

        // Acklam's quantile carries |rel err| < 1.15e-9 into z; the tail
        // mean came from scipy's numerical integration.
        for (s.gauss) |g| {
            try near(g.var_, fs.gaussianVaR(g.mean, g.sd, g.conf), 1e-12, 1e-8);
            try near(g.cvar, fs.gaussianCVaR(g.mean, g.sd, g.conf), 1e-12, 1e-8);
        }

        const rmean = try fs.rollingMean(a, d, .{ .value_col = "r", .window = ref.window });
        const rstd = try fs.rollingVolatility(a, d, .{ .value_col = "r", .window = ref.window });
        try testing.expectEqual(s.roll_mean.len, rmean.rows.len);
        try testing.expectEqual(s.roll_std.len, rstd.rows.len);
        for (s.roll_mean, rmean.rows) |want, row| try near(want, row[0].asFloat().?, 1e-15, 1e-9);
        for (s.roll_std, rstd.rows) |want, row| try near(want, row[0].asFloat().?, 1e-15, 1e-9);
    }
}

test "oracle: beta and r2 against scipy.stats.linregress" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const port = ref.series[4].values;
    const bench = ref.series[3].values;
    try testing.expectEqualStrings("port", ref.series[4].name);
    try testing.expectEqualStrings("bench", ref.series[3].name);

    const cols = [_]Column{ .{ .name = "p", .type = .float }, .{ .name = "b", .type = .float } };
    const rows = try a.alloc([]const Value, port.len);
    for (port, bench, 0..) |p, b, i| rows[i] = try a.dupe(Value, &.{ .{ .float = p }, .{ .float = b } });
    const out = try fs.betaAlpha(a, .{ .columns = &cols, .rows = rows }, .{
        .port_ret_col = "p",
        .bench_ret_col = "b",
        .port_ann = 0,
        .bench_ann = 0,
    });
    try near(ref.beta, cell(out, "beta"), 0, 1e-12);
    try near(ref.r2, cell(out, "r2"), 0, 1e-12);
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
    const cols = [_]Column{
        .{ .name = "d", .type = .date },
        .{ .name = "flow", .type = .float },
        .{ .name = "v", .type = .float },
    };
    for (ref.schedules, 0..) |s, k| {
        errdefer std.debug.print("schedule {d}\n", .{k});
        const rows = try a.alloc([]const Value, s.rows.len);
        for (s.rows, 0..) |r, i| rows[i] = try a.dupe(Value, &.{ .{ .text = r.date }, .{ .float = r.flow }, .{ .float = r.value } });
        const d: Dataset = .{ .columns = &cols, .rows = rows };
        const opening: fs.Opening = switch (s.opening) {
            .none => .none,
            .value_includes_flow => .value_includes_flow,
        };
        // `rate_tol` defaults to 1e-9; Newton's `tol` to 1e-8 on NPV.
        try near(s.xirr, try fs.xirr(a, d, .{ .date_col = "d", .flow_col = "flow", .value_col = "v", .opening = opening }), 1e-8, 0);
        try near(s.xirr, try fs.xirrPrecise(a, d, .{ .date_col = "d", .flow_col = "flow", .value_col = "v", .opening = opening }), 1e-8, 0);
    }
}

/// A two-column dataset: `dt` (ISO date text) and `r` (float).
fn datedReturns(a: std.mem.Allocator, values: []const f64) !Dataset {
    const cols = try a.dupe(Column, &.{ .{ .name = "dt", .type = .date }, .{ .name = "r", .type = .float } });
    const rows = try a.alloc([]const Value, values.len);
    for (values, 0..) |v, i| rows[i] = try a.dupe(Value, &.{ .{ .text = ref.dates[i] }, .{ .float = v } });
    return .{ .columns = cols, .rows = rows };
}

test "oracle: ulcer, sharpe, sortino, calmar (CAGR from ffn, denominators from empyrical)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ref.ratios) |rr| {
        const s = ref.series[rr.series];
        errdefer std.debug.print("series {s} rf {d}\n", .{ s.name, rr.rf });
        const d = try datedReturns(a, s.values);
        const rm = try fs.riskMetrics(a, d, .{ .ret_col = "r", .date_col = "dt", .rf = rr.rf });
        // Both foreign ulcers were given a level that starts at 1 (baseline point) and
        // converted to this module's mean-over-n percent convention (see oracle.py).
        try near(rr.ulcer_ffn, cell(rm, "ulcer"), 0, 1e-12);
        try near(rr.ulcer_qs_as_ours, cell(rm, "ulcer"), 0, 1e-12);
        try near(rr.sharpe, cell(rm, "sharpe"), 1e-15, 1e-10);
        try near(rr.sortino, cell(rm, "sortino"), 1e-15, 1e-10);
        try near(rr.calmar, cell(rm, "calmar"), 1e-15, 1e-10);
    }
}

test "oracle: tradeStats against quantstats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ref.trades) |t| {
        errdefer std.debug.print("series {s}\n", .{t.name});
        const d = try returns(a, t.values);
        const ts = try fs.tradeStats(a, d, .{ .ret_col = "r" });
        try near(t.win_rate, cell(ts, "win_rate"), 0, 1e-14);
        try near(t.payoff, cell(ts, "payoff"), 0, 1e-12);
        try near(t.profit_factor, cell(ts, "profit_factor"), 0, 1e-12);
        try near(t.kelly, cell(ts, "kelly"), 1e-15, 1e-12);
        try near(t.tail_ratio, cell(ts, "tail_ratio"), 0, 1e-12);
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
        const cols = [_]Column{ .{ .name = "p", .type = .float }, .{ .name = "b", .type = .float } };
        const rows = try a.alloc([]const Value, pv.len);
        for (pv, bvals, 0..) |p, bb, i| rows[i] = try a.dupe(Value, &.{ .{ .float = p }, .{ .float = bb } });
        const out = try fs.benchmarkStats(a, .{ .columns = &cols, .rows = rows }, .{
            .port_ret_col = "p",
            .bench_ret_col = "b",
            .port_ann = b.port_ann,
            .rf = b.rf,
        });
        try near(b.up, cell(out, "up_capture"), 1e-15, 1e-12);
        try near(b.down, cell(out, "down_capture"), 1e-15, 1e-12);
        try near(b.treynor, cell(out, "treynor"), 1e-15, 1e-10);
    }
}

test "oracle: drawdownEpisodes against ffn drawdown_details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "dt", .type = .date }, .{ .name = "v", .type = .float } };
    for (ref.dd_cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.label});
        const rows = try a.alloc([]const Value, c.levels.len);
        for (c.levels, 0..) |v, i| rows[i] = try a.dupe(Value, &.{ .{ .text = ref.dates[i] }, .{ .float = v } });
        const out = try fs.drawdownEpisodes(a, .{ .columns = &cols, .rows = rows }, .{
            .date_col = "dt",
            .value_col = "v",
            .top_n = 100_000,
        });
        try testing.expectEqual(c.episodes.len, out.rows.len);
        // Worst first; equal depths may come in either order, so each ffn
        // episode is looked up by its peak date.
        var prev: f64 = -std.math.inf(f64);
        for (out.rows) |row| {
            const depth = row[3].asFloat().?;
            try testing.expect(depth >= prev);
            prev = depth;
        }
        for (c.episodes) |e| {
            errdefer std.debug.print("episode peak {s}\n", .{e.peak});
            var found = false;
            for (out.rows) |row| {
                if (!std.mem.eql(u8, row[0].asText().?, e.peak)) continue;
                found = true;
                try testing.expectEqualStrings(e.trough, row[1].asText().?);
                if (e.recovery) |rec| {
                    try testing.expect(row[2] != .null and row[5] != .null);
                    try testing.expectEqualStrings(rec, row[2].asText().?);
                    try testing.expectEqual(e.recover_days.?, row[5].asInt().?);
                } else {
                    try testing.expect(row[2] == .null);
                    try testing.expect(row[5] == .null);
                }
                try near(e.depth_pct, row[3].asFloat().?, 1e-12, 1e-9);
                try testing.expectEqual(e.fall_days, row[4].asInt().?);
            }
            try testing.expect(found);
        }
    }
}

test "oracle: correlationMatrix against pandas DataFrame.corr(min_periods)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "k", .type = .text }, .{ .name = "dt", .type = .date }, .{ .name = "v", .type = .float } };
    var rows: std.ArrayList([]const Value) = .empty;
    for (ref.corr_series) |s| {
        for (s.dates, s.values) |dt, v| {
            try rows.append(a, try a.dupe(Value, &.{ .{ .text = s.key }, .{ .text = dt }, .{ .float = v } }));
        }
    }
    const out = try fs.correlationMatrix(a, .{ .columns = &cols, .rows = rows.items }, .{
        .key_col = "k",
        .date_col = "dt",
        .value_col = "v",
        .min_overlap = ref.corr_min_overlap,
    });
    try testing.expectEqual(ref.corr_series.len, out.rows.len);
    for (ref.corr_series, 0..) |s, i| {
        try testing.expectEqualStrings(s.key, out.rows[i][0].asText().?);
        for (ref.corr_series, 0..) |_, j| {
            errdefer std.debug.print("pair {d},{d}\n", .{ i, j });
            const got = out.rows[i][j + 1];
            if (i == j) { // pandas gives NaN for a constant/short series; the module defines 1
                try near(1, got.asFloat().?, 0, 0);
                continue;
            }
            if (ref.corr_matrix[i][j]) |want| {
                try testing.expect(got != .null);
                try near(want, got.asFloat().?, 1e-12, 1e-10);
            } else {
                try testing.expect(got == .null);
            }
        }
    }
}
