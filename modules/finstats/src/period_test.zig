// SPDX-License-Identifier: MIT

//! **External anchor for the period statistics** (survey 2026-11-02):
//! `testdata/oracle_vectors.zig` `period_ref`, made by `tools/oracle.py`
//! `periods()`, holds the values empyrical-reloaded 0.5.12, ffn 1.3.0 and
//! quantstats 0.0.86 compute over the five seeded 250-day series, at rf = 0 and
//! rf = 3 %. Where the libraries agree (they do, to 2e-15 relative) all of them
//! are compared; the conventions we follow are written on each function and in
//! SPEC "Conventions".
//!
//! Also here: independent models for `twrDaily` and `brinsonAttribution`
//! (`tools/attrib_model.py` -> `testdata/attrib_vectors.zig`). Their published
//! anchors are in `attrib_oracle_test.zig`.

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

// The foreign libraries agree with each other to 2e-15 relative on these series
// (numpy pairwise sums vs a plain loop, pow/sqrt rounding); 1e-11 leaves four
// orders of margin and still catches a wrong divisor (ddof), a wrong rf
// conversion or a wrong downside threshold.
const period_tol = 1e-11;

test "oracle: period statistics against empyrical, ffn and quantstats" {
    for (ref.period_ref) |p| {
        errdefer std.debug.print("series {d} rf {d}\n", .{ p.series, p.rf });
        const xs = ref.series[p.series].values;
        const sh = fs.sharpeRatio(xs, p.rf, 252);
        try near(p.sharpe_qs, sh, 0, period_tol);
        try near(p.sharpe_ep, sh, 0, period_tol);
        try near(p.sharpe_ffn, sh, 0, period_tol);
        const so = fs.sortinoRatio(xs, p.rf, 252);
        try near(p.sortino_qs, so, 0, period_tol);
        try near(p.sortino_ep, so, 0, period_tol);
        try near(p.sortino_ffn, so, 0, period_tol);
        const cg = fs.cagrPeriods(xs, 252);
        try near(p.cagr_ep, cg, 0, period_tol);
        try near(p.cagr_qs, cg, 0, period_tol);
        const cm = fs.calmarRatio(xs, 252);
        try near(p.calmar_ep, cm, 0, period_tol);
        try near(p.calmar_qs, cm, 0, period_tol);
        try near(p.total, fs.totalReturn(xs), 0, period_tol);
        try near(p.geo, fs.geometricMean(xs), 0, period_tol);
        try near(p.gain_to_pain, fs.gainToPain(xs), 0, period_tol);
        try near(p.recovery, fs.recoveryFactor(xs), 0, period_tol);
        try near(p.best, fs.bestReturn(xs), 0, 0);
        try near(p.worst, fs.worstReturn(xs), 0, 0);
        try near(p.avg_win, fs.avgWin(xs), 0, period_tol);
        try near(p.avg_loss, fs.avgLoss(xs), 0, period_tol);
        try testing.expectEqual(p.wins, fs.maxConsecutiveWins(xs));
        try testing.expectEqual(p.losses, fs.maxConsecutiveLosses(xs));
        // R² from scipy's linregress (correlation first), ours from running co-moments.
        try near(p.stability, fs.stability(xs), 0, 1e-9);
    }
}

const am = @import("testdata/attrib_vectors.zig");

test "model: twrDaily recovers the known daily returns (start- and end-of-day flows)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (am.twr_cases, 0..) |c, k| {
        errdefer std.debug.print("twr case {d}\n", .{k});
        const cols = try a.dupe(Column, &.{
            .{ .name = "d", .type = .date },  .{ .name = "v", .type = .float },
            .{ .name = "f", .type = .float }, .{ .name = "pe", .type = .float },
        });
        const rows = try a.alloc([]const Value, c.dates.len);
        for (rows, 0..) |*r, i| r.* = try a.dupe(Value, &.{
            .{ .text = c.dates[i] }, .{ .float = c.value[i] }, .{ .float = c.flow[i] }, .{ .float = c.pe[i] },
        });
        const t = try fs.twrDaily(a, .{ .columns = cols, .rows = rows }, .{
            .date_col = "d",
            .value_col = "v",
            .flow_col = "f",
            .pe_col = "pe",
        });
        try testing.expectEqual(c.ret.len, t.rows.len);
        var comp: f64 = 1;
        for (t.rows, 0..) |r, i| {
            // the only error is rounding in value = base * (1 + r)
            try near(c.ret[i], r[1].float, 1e-12, 0);
            comp *= 1 + r[1].float;
        }
        try near(c.cum_final, comp - 1, 1e-11, 1e-11);
    }
}

test "model: brinsonAttribution against Brinson-Fachler written from the definition" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (am.bf_cases, 0..) |c, k| {
        errdefer std.debug.print("bf case {d}\n", .{k});
        const m = c.wp.len;
        const cols = try a.dupe(Column, &.{
            .{ .name = "s", .type = .text },   .{ .name = "wp", .type = .float },
            .{ .name = "wb", .type = .float }, .{ .name = "rp", .type = .float },
            .{ .name = "rb", .type = .float },
        });
        const rows = try a.alloc([]const Value, m);
        for (rows, 0..) |*r, i| r.* = try a.dupe(Value, &.{
            .{ .text = try std.fmt.allocPrint(a, "S{d}", .{i}) }, .{ .float = c.wp[i] },
            .{ .float = c.wb[i] },                                .{ .float = c.rp[i] },
            .{ .float = c.rb[i] },
        });
        const b = try fs.brinsonAttribution(a, .{ .columns = cols, .rows = rows }, .{
            .segment_col = "s",
            .port_weight_col = "wp",
            .bench_weight_col = "wb",
            .port_return_col = "rp",
            .bench_return_col = "rb",
        });
        try testing.expectEqual(m + 1, b.rows.len);
        var sa: f64 = 0;
        var ss: f64 = 0;
        var si: f64 = 0;
        for (0..m) |i| {
            // plain f64 arithmetic of the same few operations: 1e-14 absolute
            try near(c.alloc[i], b.rows[i][1].float, 1e-14, 0);
            try near(c.sel[i], b.rows[i][2].float, 1e-14, 0);
            try near(c.inter[i], b.rows[i][3].float, 1e-14, 0);
            // per-segment total is the sum of its three effects
            try near(c.alloc[i] + c.sel[i] + c.inter[i], b.rows[i][4].float, 1e-14, 0);
            sa += b.rows[i][1].float;
            ss += b.rows[i][2].float;
            si += b.rows[i][3].float;
        }
        // invariant: the three effects sum to the active return, and the TOTAL row says so
        try near(c.active, sa + ss + si, 1e-13, 0);
        try near(c.active, b.rows[m][4].float, 1e-13, 0);
        try near(sa, b.rows[m][1].float, 1e-13, 0);
    }
}

test "brinsonAttribution pins the FACHLER allocation term, which BHB would get wrong" {
    // Two segments, portfolio return = benchmark return per segment (so selection
    // and interaction are 0 and only allocation is left).
    //   wp = 0.7 / 0.3, wb = 0.5 / 0.5, r = 0.10 / 0.02
    //   Rb = 0.5*0.10 + 0.5*0.02 = 0.06
    // Brinson-Fachler allocation_i = (wp_i - wb_i) * (rb_i - Rb):
    //   seg 0:  0.2 * (0.10 - 0.06) =  0.008     seg 1: -0.2 * (0.02 - 0.06) = 0.008
    // BHB (no Rb) would give (wp_i - wb_i) * rb_i:
    //   seg 0:  0.2 * 0.10          =  0.020     seg 1: -0.2 * 0.02          = -0.004
    // Both sum to 0.016 = Rp - Rb (0.076 - 0.06), so the identity cannot tell them
    // apart; the per-segment value can.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{
        .{ .name = "s", .type = .text },   .{ .name = "wp", .type = .float },
        .{ .name = "wb", .type = .float }, .{ .name = "rp", .type = .float },
        .{ .name = "rb", .type = .float },
    });
    const rows = try a.dupe([]const Value, &.{
        try a.dupe(Value, &.{ .{ .text = "A" }, .{ .float = 0.7 }, .{ .float = 0.5 }, .{ .float = 0.10 }, .{ .float = 0.10 } }),
        try a.dupe(Value, &.{ .{ .text = "B" }, .{ .float = 0.3 }, .{ .float = 0.5 }, .{ .float = 0.02 }, .{ .float = 0.02 } }),
    });
    const b = try fs.brinsonAttribution(a, .{ .columns = cols, .rows = rows }, .{
        .segment_col = "s",
        .port_weight_col = "wp",
        .bench_weight_col = "wb",
        .port_return_col = "rp",
        .bench_return_col = "rb",
    });
    try near(0.008, b.rows[0][1].float, 1e-15, 0);
    try near(0.008, b.rows[1][1].float, 1e-15, 0);
    try testing.expect(@abs(b.rows[0][1].float - 0.020) > 0.01); // not BHB
    try near(0.016, b.rows[2][4].float, 1e-15, 0);
}

test "oracle: periodStats row carries the same numbers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = ref.period_ref[3]; // series 1, rf 0.03
    const d = try returns(a, ref.series[p.series].values);
    const row = try fs.periodStats(a, d, .{ .ret_col = "r", .rf = p.rf });
    try near(p.sharpe_qs, cell(row, "sharpe_mean"), 0, period_tol);
    try near(p.sortino_qs, cell(row, "sortino_mean"), 0, period_tol);
    try near(p.calmar_ep, cell(row, "calmar_periods"), 0, period_tol);
    try near(p.total, cell(row, "total_return"), 0, period_tol);
    try near(@floatFromInt(p.wins), cell(row, "max_consec_wins"), 0, 0);
}
