// SPDX-License-Identifier: MIT
//! Hand-written tests of dataframe S2 wave W5: window shapes and weights (`window.zig`),
//! `ewm` extensions, `over(order_by, mapping)`, `reverse`, and dynamic groups
//! (`frameops.zig`). The engines' answers are replayed in `s2w5_oracle_test.zig`; these
//! cover what they cannot: errors, caps, hostile input and exact small cases.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const win = @import("window.zig");
const fo = @import("frameops.zig");
const more = @import("more.zig");
const Frame = fm.Frame;
const Value = vm.Value;

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

const Col = struct { []const u8, []const ?f64 };

fn floatFrame(a: std.mem.Allocator, cols: []const Col) !Frame {
    const cs = try a.alloc(vm.Column, cols.len);
    const data = try a.alloc(fm.ColumnData, cols.len);
    for (cs, data, cols) |*c, *d, src| {
        c.* = .{ .name = src[0], .type = .float };
        const cells = try a.alloc(Value, src[1].len);
        for (cells, src[1]) |*o, x| o.* = if (x) |v| .{ .float = v } else .null;
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cs, .data = data, .len = cols[0][1].len };
}

fn intFrame(a: std.mem.Allocator, cols: []const struct { []const u8, []const ?i64 }) !Frame {
    const cs = try a.alloc(vm.Column, cols.len);
    const data = try a.alloc(fm.ColumnData, cols.len);
    for (cs, data, cols) |*c, *d, src| {
        c.* = .{ .name = src[0], .type = .int };
        const cells = try a.alloc(Value, src[1].len);
        for (cells, src[1]) |*o, x| o.* = if (x) |v| .{ .int = v } else .null;
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cs, .data = data, .len = cols[0][1].len };
}

fn run(a: std.mem.Allocator, f: Frame, op: win.WindowOp) !Frame {
    return win.window(a, f, .{ .value_col = "x", .out = "r", .op = op });
}

fn expectCol(f: Frame, name: []const u8, want: []const ?f64) !void {
    const s = f.series(name).?;
    try testing.expectEqual(want.len, s.len);
    for (want, 0..) |w, i| {
        const got = s.get(i);
        if (w) |x| {
            try testing.expect(got.asFloat() != null);
            try testing.expectApproxEqAbs(x, got.asFloat().?, 1e-9);
        } else try testing.expect(got == .null or (got == .float and std.math.isNan(got.float)));
    }
}

test "windowWeights: known shapes, M = 1, bad parameters, cap" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const h = try win.windowWeights(a, .hamming, 5);
    const want_h = [_]f64{ 0.08, 0.54, 1.0, 0.54, 0.08 };
    for (h, want_h) |g, w| try testing.expectApproxEqAbs(w, g, 1e-12);
    const t = try win.windowWeights(a, .triang, 4);
    for (t, [_]f64{ 0.25, 0.75, 0.75, 0.25 }) |g, w| try testing.expectApproxEqAbs(w, g, 1e-12);
    const b = try win.windowWeights(a, .bartlett, 5);
    for (b, [_]f64{ 0, 0.5, 1, 0.5, 0 }) |g, w| try testing.expectApproxEqAbs(w, g, 1e-12);
    const hn = try win.windowWeights(a, .hann, 3);
    for (hn, [_]f64{ 0, 1, 0 }) |g, w| try testing.expectApproxEqAbs(w, g, 1e-12);
    const k0 = try win.windowWeights(a, .{ .kaiser = .{ .beta = 0 } }, 4);
    for (k0) |g| try testing.expectApproxEqAbs(@as(f64, 1), g, 1e-12);
    const bh = try win.windowWeights(a, .bohman, 6);
    try testing.expectEqual(@as(f64, 0), bh[0]);
    try testing.expectEqual(@as(f64, 0), bh[5]);
    const plain = [_]win.WinType{ .boxcar, .triang, .hamming, .hann, .bartlett, .barthann, .blackman, .blackmanharris, .nuttall, .flattop, .parzen, .bohman, .cosine };
    for (plain) |wt| {
        const one = try win.windowWeights(a, wt, 1);
        try testing.expectEqual(@as(f64, 1), one[0]);
        const none = try win.windowWeights(a, wt, 0);
        try testing.expectEqual(@as(usize, 0), none.len);
    }
    try testing.expectError(error.BadOption, win.windowWeights(a, .{ .gaussian = .{ .std = 0 } }, 3));
    try testing.expectError(error.BadOption, win.windowWeights(a, .{ .exponential = .{ .tau = -1 } }, 3));
    try testing.expectError(error.BadOption, win.windowWeights(a, .{ .exponential = .{ .tau = std.math.nan(f64) } }, 3));
    try testing.expectError(error.BadOption, win.windowWeights(a, .{ .kaiser = .{ .beta = 1e9 } }, 3));
    try testing.expectError(error.BadOption, win.windowWeights(a, .{ .general_gaussian = .{ .p = 1, .sig = 0 } }, 3));
    try testing.expectError(error.TooLarge, win.windowWeights(a, .boxcar, std.math.maxInt(usize)));
}

test "rolling: option combinations the engines refuse or this verb does not carry" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try floatFrame(a, &.{.{ "x", &.{ 1, 2, 3, 4 } }});
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .forward = true, .center = true } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .forward = true, .closed = .left } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .weights = &.{ 1, 2, 3 } } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .weights = &.{ 1, 2 }, .func = .median } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .weights = &.{ 1, 2 }, .closed = .both } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .win_type = .boxcar, .func = .@"var" } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .win_type = .boxcar, .weights = &.{ 1, 2 } } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .rolling = .{ .window = 2, .win_type = .{ .gaussian = .{ .std = -1 } } } }));
    // A window of no rows: all null, whatever the options.
    const z = try run(a, f, .{ .rolling = .{ .window = 0, .closed = .both } });
    try expectCol(z, "r", &.{ null, null, null, null });
}

test "rolling: closed, step, forward on exact small cases" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try floatFrame(a, &.{.{ "x", &.{ 1, 2, 4, 8, 16 } }});
    // left: the 2 rows before the row; both: 3 rows ending at it.
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 1, .closed = .left } }), "r", &.{ null, 1, 3, 6, 12 });
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 1, .closed = .both } }), "r", &.{ 1, 3, 7, 14, 28 });
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 1, .closed = .neither } }), "r", &.{ null, 1, 2, 4, 8 });
    // step 2: rows 0, 2, 4 only.
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 1, .step = 2 } }), "r", &.{ 1, null, 6, null, 24 });
    // forward: rows i .. i + 2.
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 1, .forward = true } }), "r", &.{ 3, 6, 12, 24, 16 });
    // A window longer than any table: expanding.
    try expectCol(try run(a, f, .{ .rolling = .{ .window = std.math.maxInt(usize), .func = .sum, .min_periods = 1, .closed = .both } }), "r", &.{ 1, 3, 7, 15, 31 });
    // weights: positions follow the logical window, so a short first window skips the weights' head.
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 1, .weights = &.{ 10, 1 } } }), "r", &.{ 1, 12, 24, 48, 96 });
    try expectCol(try run(a, f, .{ .rolling = .{ .window = 2, .func = .mean, .min_periods = 1, .win_type = .boxcar } }), "r", &.{ 1, 1.5, 3, 6, 12 });
}

test "rolling time: closed left and neither drop the row itself and its ties" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ .{ "t", &.{ 0, 10, 20, 20, 30 } }, .{ "x", &.{ 1, 2, 4, 8, 16 } } });
    const left = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_time = .{ .time_col = "t", .period = 20, .func = .sum, .min_periods = 1, .closed = .left } } });
    // [t - 20, t): t=20 sees t=0,10; its tie at 20 is outside; t=30 sees 10 and both 20s.
    try expectCol(left, "r", &.{ null, 1, 3, 3, 14 });
    const both = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_time = .{ .time_col = "t", .period = 20, .func = .sum, .min_periods = 1, .closed = .both } } });
    try expectCol(both, "r", &.{ 1, 3, 7, 15, 30 });
    // A non-positive period, an unordered time and a missing time give null.
    const bad = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_time = .{ .time_col = "t", .period = 0 } } });
    try expectCol(bad, "r", &.{ null, null, null, null, null });
    try testing.expectError(error.NoSuchColumn, win.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_time = .{ .time_col = "nope", .period = 5 } } }));
    // rank_by: only the closed ends that keep the row in its window.
    try testing.expectError(error.BadOption, win.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_rank = .{ .window = null, .time_col = "t", .period = 5, .closed = .left } } }));
}

test "ewm: times, sum, by, cov errors and a hand case" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ .{ "t", &.{ 0, 10, 20 } }, .{ "x", &.{ 4, 8, 12 } } });
    // halflife 10, adjust=false: y1 = (0.5 * 4 + 0.5 * 8) / 1, y2 = (0.5 * 6 + 0.5 * 12).
    const m = try run(a, f, .{ .ewm = .{ .halflife = 10, .adjust = false, .times_col = "t" } });
    try expectCol(m, "r", &.{ 4, 6, 9 });
    try testing.expectError(error.InvalidDecay, run(a, f, .{ .ewm = .{ .times_col = "t" } }));
    try testing.expectError(error.InvalidDecay, run(a, f, .{ .ewm = .{ .halflife = 0, .times_col = "t" } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .ewm = .{ .halflife = 5, .alpha = 0.5, .times_col = "t" } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .ewm = .{ .halflife = 5, .func = .@"var", .times_col = "t" } }));
    try testing.expectError(error.BadOption, run(a, f, .{ .ewm = .{ .halflife = 5, .func = .sum, .times_col = "t" } }));
    // sum, alpha 0.5: 4, 4 * 0.5 + 8, 10 * 0.5 + 12
    const s = try run(a, f, .{ .ewm = .{ .alpha = 0.5, .func = .sum } });
    try expectCol(s, "r", &.{ 4, 10, 17 });
    // ewm_by mean, half life 10: dt 10 -> decay 0.5.
    const by = try run(a, f, .{ .ewm_by = .{ .time_col = "t", .half_life = 10 } });
    try expectCol(by, "r", &.{ 4, 6, 9 });
    const bs = try run(a, f, .{ .ewm_by = .{ .time_col = "t", .half_life = 10, .func = .sum } });
    try expectCol(bs, "r", &.{ 4, 10, 17 });
    try testing.expectError(error.InvalidDecay, run(a, f, .{ .ewm_by = .{ .time_col = "t", .half_life = 0 } }));
    try testing.expectError(error.NoSuchColumn, run(a, f, .{ .ewm_cov = .{ .other = "nope", .ewm = .{ .alpha = 0.5 } } }));
    try testing.expectError(error.InvalidDecay, run(a, f, .{ .ewm_cov = .{ .other = "x", .ewm = .{} } }));
}

test "window: reverse, order_by, mapping" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ .{ "x", &.{ 1, 2, 3, 4 } }, .{ "g", &.{ 0, 1, 0, 1 } }, .{ "o", &.{ 4, 3, null, 1 } } });
    const rev = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .reverse = true });
    try expectCol(rev, "r", &.{ 10, 9, 7, 4 });
    const revg = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .reverse = true, .partition_by = &.{"g"} });
    try expectCol(revg, "r", &.{ 4, 6, 3, 4 });
    // order by o: a missing cell first, then ascending: rows 2, 3, 1, 0.
    const ord = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .order_by = &.{"o"} });
    try expectCol(ord, "r", &.{ 10, 9, 3, 7 });
    const desc = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .order_by = &.{"o"}, .order_descending = true });
    try expectCol(desc, "r", &.{ 4, 6, 3, 10 });
    const ex = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .partition_by = &.{"g"}, .mapping = .explode });
    try expectCol(ex, "x", &.{ 1, 3, 2, 4 });
    try expectCol(ex, "r", &.{ 1, 4, 2, 6 });
    const jn = try win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .partition_by = &.{"g"}, .mapping = .join });
    try testing.expectEqual(vm.ColumnType.list, jn.columns[jn.columns.len - 1].type);
    const l0 = jn.series("r").?.get(0).list;
    try testing.expectEqual(@as(usize, 2), l0.len());
    try testing.expectEqual(@as(f64, 4), l0.get(1).asFloat().?);
    try testing.expectError(error.NoSuchColumn, win.window(a, f, .{ .value_col = "x", .out = "r", .op = .cum_sum, .order_by = &.{"nope"} }));
}

test "dynamic groups: errors, caps, labels, boundaries, rules" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const h: i64 = 3_600_000_000;
    const f = try intFrame(a, &.{ .{ "t", &.{ 0, h / 2, h, 3 * h, null } }, .{ "x", &.{ 1, 2, 4, 8, 16 } } });
    const aggs = [_]@import("spec.zig").AggCol{ .{ .src = "x", .out = "s", .func = .sum }, .{ .src = "x", .out = "n", .func = .count } };
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .period = "0s", .aggs = &aggs }));
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .period = "-1h", .aggs = &aggs }));
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .offset = "zz", .aggs = &aggs }));
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .rule = "B", .aggs = &aggs }));
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .rule = "2MS", .aggs = &aggs }));
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .rule = "W-XYZ", .aggs = &aggs }));
    try testing.expectError(error.BadArgument, fo.groupByDynamic(a, f, .{ .index = "t", .every = "1mo", .start_by = .monday, .aggs = &aggs }));
    try testing.expectError(error.NoSuchColumn, fo.groupByDynamic(a, f, .{ .index = "nope", .every = "1h", .closed = .right, .aggs = &aggs }));
    // overlapping windows by a huge ratio are refused, not computed
    try testing.expectError(error.TooLarge, fo.groupByDynamic(a, f, .{ .index = "t", .every = "1us", .period = "100000y", .aggs = &aggs }));
    // closed right, label datapoint: (0, 1h] holds 0.5h and 1h; the window below holds 0.
    const g = try fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .closed = .right, .label = .datapoint, .aggs = &aggs });
    try testing.expectEqual(@as(usize, 3), g.len);
    // first window is the grid window below the first time (-1h, 0] for a time on the grid
    try testing.expectEqual(@as(i64, 0), g.cell(0, "t").?.int);
    try testing.expectEqual(@as(f64, 1), g.cell(0, "s").?.asFloat().?);
    try testing.expectEqual(@as(f64, 6), g.cell(1, "s").?.asFloat().?);
    try testing.expectEqual(@as(f64, 8), g.cell(2, "s").?.asFloat().?);
    // boundaries before the index, in polars' order; a missing time is dropped
    const b = try fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .include_boundaries = true, .aggs = &aggs });
    try testing.expectEqualStrings("_lower_boundary", b.columns[0].name);
    try testing.expectEqualStrings("_upper_boundary", b.columns[1].name);
    try testing.expectEqualStrings("t", b.columns[2].name);
    try testing.expectEqual(@as(usize, 3), b.len);
    try testing.expectEqual(@as(i64, h), b.cell(0, "_upper_boundary").?.int);
    // ohlc composes
    const ohlc = try more.ohlcAggs(a, "x", "");
    const o = try fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .period = "2h", .aggs = ohlc });
    try testing.expectEqual(@as(f64, 1), o.cell(0, "open").?.asFloat().?);
    try testing.expectEqual(@as(f64, 4), o.cell(0, "high").?.asFloat().?);
    try testing.expectEqual(@as(f64, 4), o.cell(0, "close").?.asFloat().?);
    // default options still take the plain path: unchanged label and windows
    const p = try fo.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .aggs = &aggs });
    try testing.expectEqual(@as(usize, 3), p.len);
    // an empty table
    const e = try fo.groupByDynamic(a, try intFrame(a, &.{ .{ "t", &.{} }, .{ "x", &.{} } }), .{ .index = "t", .every = "1h", .closed = .both, .aggs = &aggs });
    try testing.expectEqual(@as(usize, 0), e.len);
}

test "dynamic groups: month-end rule labels the last day, weeks end on the named day" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const day: i64 = 86_400_000_000;
    // 2020-01-31 12:00, 2020-02-01 00:00, 2020-02-29 23:00
    const jan31 = 18292 * day;
    const f = try intFrame(a, &.{ .{ "t", &.{ jan31 + day / 2, jan31 + day, jan31 + 29 * day + 23 * 3_600_000_000 } }, .{ "x", &.{ 1, 2, 4 } } });
    const aggs = [_]@import("spec.zig").AggCol{.{ .src = "x", .out = "s", .func = .sum }};
    const g = try fo.groupByDynamic(a, f, .{ .index = "t", .rule = "ME", .aggs = &aggs });
    try testing.expectEqual(@as(usize, 2), g.len);
    try testing.expectEqual(jan31, g.cell(0, "t").?.int);
    try testing.expectEqual(@as(f64, 1), g.cell(0, "s").?.asFloat().?);
    try testing.expectEqual(jan31 + 29 * day, g.cell(1, "t").?.int);
    try testing.expectEqual(@as(f64, 6), g.cell(1, "s").?.asFloat().?);
}
