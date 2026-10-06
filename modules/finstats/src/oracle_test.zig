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
