// SPDX-License-Identifier: MIT
//! `finstats.slice`: what it adds to the `Dataset` functions, and a differential
//! run against them on seeded data while both exist. The `Dataset` side carries the
//! foreign oracles (oracle_test, period_test, attrib_oracle_test), so agreement here
//! extends those anchors to the slices. Goes with the `Dataset` functions at step R,
//! except the tests that do not name `root`.

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const sl = fs.slice;
const dsmod = @import("dataset");
const Column = dsmod.Column;
const Value = dsmod.Value;

const n_rows = 300;

const Fixture = struct {
    p: [n_rows]f64,
    b: [n_rows]f64,
    level: [n_rows]f64,
    flow: [n_rows]f64,
    value: [n_rows]f64,
    base: [n_rows]f64,
    dates: [n_rows][]const u8,
    ds: dsmod.Dataset,
};

fn fixture(a: std.mem.Allocator, seed: u64) !*Fixture {
    const f = try a.create(Fixture);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var lv: f64 = 100;
    var val: f64 = 1000;
    const rows = try a.alloc([]const Value, n_rows);
    for (0..n_rows) |i| {
        f.b[i] = (r.floatNorm(f64) * 0.01) + 0.0003;
        f.p[i] = 0.8 * f.b[i] + r.floatNorm(f64) * 0.008;
        lv *= 1 + f.p[i];
        f.level[i] = lv;
        f.flow[i] = if (r.uintLessThan(u8, 10) == 0) r.float(f64) * 100 - 30 else 0;
        val = val * (1 + f.p[i]) + f.flow[i];
        f.value[i] = val;
        f.base[i] = val * 0.99;
        // 28 days in every month: valid for any year and month
        f.dates[i] = try std.fmt.allocPrint(a, "20{d:0>2}-{d:0>2}-{d:0>2}", .{ 10 + i / 336, (i / 28) % 12 + 1, i % 28 + 1 });
        const row = try a.alloc(Value, 7);
        row[0] = .{ .text = f.dates[i] };
        row[1] = .{ .float = f.p[i] };
        row[2] = .{ .float = f.b[i] };
        row[3] = .{ .float = f.level[i] };
        row[4] = .{ .float = f.flow[i] };
        row[5] = .{ .float = f.value[i] };
        row[6] = .{ .float = f.base[i] };
        rows[i] = row;
    }
    const cols = try a.alloc(Column, 7);
    for (cols, [_][]const u8{ "d", "p", "b", "level", "flow", "value", "base" }, 0..) |*c, name, i| {
        c.* = .{ .name = name, .type = if (i == 0) .date else .float };
    }
    f.ds = .{ .columns = cols, .rows = rows };
    return f;
}

fn cell(d: dsmod.Dataset, row: usize, name: []const u8) f64 {
    return d.cell(row, name).?.asFloat().?;
}

fn same(expected: f64, got: f64) !void {
    if (std.math.isNan(expected) and std.math.isNan(got)) return;
    try testing.expectApproxEqRel(expected, got, 1e-12);
}

test "slice and Dataset functions agree on seeded series" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]u64{ 1, 2, 3, 4, 5 }) |seed| {
        const f = try fixture(a, seed);
        const d = f.ds;

        // xirr, both openings that apply to a window
        for ([_]fs.Opening{ .value_includes_flow, .value_excludes_flow }) |op| {
            const old = fs.xirr(a, d, .{ .date_col = "d", .flow_col = "flow", .value_col = "value", .opening = op });
            const new = sl.xirr(a, &f.dates, &f.flow, &f.value, op, sl.default_rate_tol);
            if (old) |v| try same(v, try new) else |_| try testing.expectError(error.XirrNoRoot, new);
            const old2 = fs.xirrPrecise(a, d, .{ .date_col = "d", .flow_col = "flow", .value_col = "value", .opening = op });
            const new2 = sl.xirrPrecise(a, &f.dates, &f.flow, &f.value, op, .{});
            if (old2) |v| try same(v, try new2) else |_| try testing.expectError(error.XirrNoRoot, new2);
        }

        const tw_old = try fs.twrDaily(a, d, .{ .date_col = "d", .value_col = "value", .flow_col = "flow", .pe_col = "base", .min_value = 500 });
        const tw_new = try sl.twrDaily(a, &f.value, &f.flow, &f.base, 500);
        try testing.expectEqual(tw_old.rows.len, tw_new.len);
        for (tw_new, 0..) |t, i| {
            try same(cell(tw_old, i, "r"), t.r);
            try testing.expectEqualStrings(f.dates[t.row], tw_old.cell(i, "d").?.asText().?);
        }

        const h_old = try fs.histogram(a, d, .{ .value_col = "p", .bins = 9 });
        const h_new = try sl.histogram(a, &f.p, 9);
        try testing.expectEqual(h_old.rows.len, h_new.len);
        for (h_new, 0..) |b, i| {
            try same(cell(h_old, i, "bin_lo"), b.lo);
            try same(cell(h_old, i, "bin_hi"), b.hi);
            try testing.expectEqual(d_int(h_old, i, "count"), @as(i64, @intCast(b.count)));
        }

        const rm_old = try fs.riskMetrics(a, d, .{ .ret_col = "p", .date_col = "d", .rf = 0.02 });
        const rm_new = try sl.riskMetrics(a, &f.p, .{ .rf = 0.02, .span_days = try sl.daySpan(f.dates[0], f.dates[n_rows - 1]) });
        inline for (.{ "ann_vol", "downside", "var95", "cvar95", "mdd", "ulcer", "sharpe", "sortino", "calmar" }) |name| {
            try same(cell(rm_old, 0, name), @field(rm_new, name));
        }

        const ba_old = try fs.betaAlpha(a, d, .{ .port_ret_col = "p", .bench_ret_col = "b", .port_ann = 0.1, .bench_ann = 0.07 });
        const ba_new = sl.betaAlpha(&f.p, &f.b, 0.1, 0.07);
        try same(cell(ba_old, 0, "beta"), ba_new.beta);
        try same(cell(ba_old, 0, "alpha"), ba_new.alpha);
        try same(cell(ba_old, 0, "r2"), ba_new.r2);

        const pr_old = try fs.parametricRisk(a, d, .{ .ret_col = "p", .confidence = 0.99 });
        const pr_new = sl.parametricRisk(&f.p, 0.99);
        inline for (.{ "mean", "std", "skew", "kurt", "var_gaussian", "cvar_gaussian", "var_cf", "cvar_cf" }) |name| {
            try same(cell(pr_old, 0, name), @field(pr_new, name));
        }

        const tr_old = try fs.trackingRisk(a, d, .{ .port_ret_col = "p", .bench_ret_col = "b" });
        const tr_new = sl.trackingRisk(&f.p, &f.b, 252);
        try same(cell(tr_old, 0, "tracking_error"), tr_new.tracking_error);
        try same(cell(tr_old, 0, "information_ratio"), tr_new.information_ratio);

        const bs_old = try fs.benchmarkStats(a, d, .{ .port_ret_col = "p", .bench_ret_col = "b", .port_ann = 0.1, .rf = 0.01 });
        const bs_new = try sl.benchmarkStats(a, &f.p, &f.b, 0.1, 0.01, 252);
        inline for (.{ "treynor", "up_capture", "down_capture" }) |name| {
            try same(cell(bs_old, 0, name), @field(bs_new, name));
        }

        const ts_old = try fs.tradeStats(a, d, .{ .ret_col = "p" });
        const ts_new = try sl.tradeStats(a, &f.p);
        inline for (.{ .{ "win_rate", "win_rate" }, .{ "payoff", "payoff" }, .{ "profit_factor", "profit_factor" }, .{ "kelly", "kelly" }, .{ "tail_ratio", "tail_ratio" } }) |pair| {
            try same(cell(ts_old, 0, pair[0]), @field(ts_new, pair[1]));
        }

        const ps_old = try fs.periodStats(a, d, .{ .ret_col = "p", .rf = 0.01 });
        const ps_new = sl.periodStats(&f.p, 252, 0.01);
        try same(cell(ps_old, 0, "sharpe_mean"), ps_new.sharpe);
        try same(cell(ps_old, 0, "sortino_mean"), ps_new.sortino);
        try same(cell(ps_old, 0, "calmar_periods"), ps_new.calmar);
        try same(cell(ps_old, 0, "stability"), ps_new.stability);
        try same(cell(ps_old, 0, "max_consec_wins"), @floatFromInt(ps_new.max_consec_wins));

        const cum_old = try fs.cumulativeReturns(a, d, .{ .ret_col = "p" });
        const dd_old = try fs.drawdownSeries(a, d, .{ .ret_col = "p" });
        const cum_new = try sl.cumulativeReturns(a, &f.p);
        const dd_new = try sl.drawdownSeries(a, &f.p);
        for (0..n_rows) |i| {
            try same(cell(cum_old, i, "cum_return"), cum_new[i]);
            try testing.expectApproxEqAbs(cell(dd_old, i, "drawdown"), dd_new[i], 1e-13);
        }

        const ep_old = try fs.drawdownEpisodes(a, d, .{ .date_col = "d", .value_col = "level", .top_n = 5 });
        const ep_new = try sl.drawdownEpisodes(a, &f.dates, &f.level, 5);
        try testing.expectEqual(ep_old.rows.len, ep_new.len);
        for (ep_new, 0..) |e, i| {
            try same(cell(ep_old, i, "depth_pct"), e.depth * 100);
            try testing.expectEqualStrings(f.dates[e.peak_i], ep_old.cell(i, "peak").?.asText().?);
            try testing.expectEqualStrings(f.dates[e.trough_i], ep_old.cell(i, "trough").?.asText().?);
            try testing.expectEqual(d_int(ep_old, i, "fall_days"), e.fall_days);
        }

        const rm_old2 = try fs.rollingVolatility(a, d, .{ .value_col = "p", .window = 20 });
        const rm_new2 = try sl.rollingVolatility(a, &f.p, 20);
        try testing.expectEqual(rm_old2.rows.len, rm_new2.len);
        for (rm_new2, 0..) |v, i| try same(cell(rm_old2, i, "value"), v);

        const rb_old = try fs.rollingBetaAlpha(a, d, .{ .port_ret_col = "p", .bench_ret_col = "b", .window = 30 });
        const rb_new = try sl.rollingBetaAlpha(a, &f.p, &f.b, 30, 252);
        for (rb_new, 0..) |v, i| {
            try same(cell(rb_old, i, "beta"), v.beta);
            try same(cell(rb_old, i, "alpha"), v.alpha);
        }

        const mc_old = try fs.monteCarlo(a, .{ .start = 1000, .mu_ann = 0.07, .vol_ann = 0.15, .monthly = 10, .years = 3, .paths = 200 });
        const mc_new = try sl.monteCarlo(a, .{ .start = 1000, .mu_ann = 0.07, .vol_ann = 0.15, .monthly = 10, .years = 3, .paths = 200 });
        try testing.expectEqual(mc_old.rows.len, mc_new.len);
        for (mc_new, 0..) |m, i| {
            try testing.expectEqual(cell(mc_old, i, "p50"), m.p50);
            try testing.expectEqual(cell(mc_old, i, "p90"), m.p90);
        }
    }
}

fn d_int(d: dsmod.Dataset, row: usize, name: []const u8) i64 {
    return d.cell(row, name).?.int;
}

test "correlationMatrix against the long-form Dataset function" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fixture(a, 11);
    var rows: std.ArrayList([]const Value) = .empty;
    for (0..n_rows) |i| {
        for ([_][]const u8{ "P", "B" }, [_]f64{ f.p[i], f.b[i] }) |k, v| {
            const r = try a.alloc(Value, 3);
            r[0] = .{ .text = k };
            r[1] = .{ .text = f.dates[i] };
            r[2] = .{ .float = v };
            try rows.append(a, r);
        }
    }
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "k", .type = .text };
    cols[1] = .{ .name = "d", .type = .text };
    cols[2] = .{ .name = "v", .type = .float };
    const old = try fs.correlationMatrix(a, .{ .columns = cols, .rows = rows.items }, .{ .key_col = "k", .date_col = "d", .value_col = "v" });
    const new = try sl.correlationMatrix(a, &.{ &f.p, &f.b }, 30);
    try same(cell(old, 0, "B"), new[1]);
    try testing.expectEqual(@as(f64, 1), new[0]);
    try testing.expectEqual(new[1], new[2]);
    // below the overlap: missing, not a number
    try testing.expect(std.math.isNan((try sl.correlationMatrix(a, &.{ f.p[0..5], f.b[0..5] }, 30))[1]));
}

test "brinsonAttribution against the Dataset function, unheld and outside segments included" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const wp = [_]f64{ 0.5, 0.5, 0.0, 0.0 };
    const wb = [_]f64{ 0.4, 0.3, 0.3, 0.0 };
    const rp = [_]f64{ 0.03, -0.01, nan, nan };
    const rb = [_]f64{ 0.02, 0.01, -0.02, nan };
    var rows: [4][]const Value = undefined;
    for (&rows, 0..) |*row, i| {
        const r = try a.alloc(Value, 5);
        r[0] = .{ .text = "s" };
        r[1] = .{ .float = wp[i] };
        r[2] = .{ .float = wb[i] };
        r[3] = .{ .float = rp[i] };
        r[4] = .{ .float = rb[i] };
        row.* = r;
    }
    const cols = try a.alloc(Column, 5);
    for (cols, [_][]const u8{ "s", "wp", "wb", "rp", "rb" }) |*c, name| c.* = .{ .name = name, .type = .float };
    const old = try fs.brinsonAttribution(a, .{ .columns = cols, .rows = &rows }, .{ .segment_col = "s", .port_weight_col = "wp", .bench_weight_col = "wb", .port_return_col = "rp", .bench_return_col = "rb" });
    const new = try sl.brinsonAttribution(a, &wp, &wb, &rp, &rb);
    for (new.rows, 0..) |row, i| {
        try same(cell(old, i, "allocation"), row.allocation);
        try same(cell(old, i, "selection"), row.selection);
        try same(cell(old, i, "interaction"), row.interaction);
    }
    try same(cell(old, 4, "total"), new.total.total);
}

test "dayNumber: real dates only, differences are calendar days" {
    try testing.expectEqual(@as(i64, 0), try sl.dayNumber("1970-01-01"));
    try testing.expectEqual(@as(i64, 19782), try sl.dayNumber("2024-02-29"));
    try testing.expectEqual(@as(f64, 366), try sl.daySpan("2024-01-01", "2025-01-01"));
    try testing.expectEqual(try sl.dayNumber("2024-03-01"), try sl.dayNumber("2024-03-01T12:30:00Z"));
    try testing.expectEqual(try sl.dayNumber("2024-03-01"), try sl.dayNumber("2024-03-01 12:30"));
    for ([_][]const u8{ "", "2024", "2023-02-29", "2024-13-01", "2024-00-10", "2024-01-00", "2024-01-32", "2024/01/01", "20x4-01-01", "2024-01-01x", "-024-01-01" }) |bad| {
        try testing.expectError(error.BadDate, sl.dayNumber(bad));
    }
    // against dataset's calendar over 400 years, including every leap rule
    var y: u16 = 1800;
    var prev: i64 = (try sl.dayNumber("1800-01-01")) - 1;
    var buf: [10]u8 = undefined;
    while (y < 2200) : (y += 1) {
        for (1..13) |m| {
            for (1..32) |d| {
                const s = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ y, m, d }) catch unreachable;
                const ours = core_day(s);
                const theirs = dsmod.parseIsoDate(s);
                try testing.expectEqual(theirs == null, ours == null);
                if (ours) |o| {
                    try testing.expectEqual(prev + 1, o);
                    prev = o;
                }
            }
        }
    }
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
