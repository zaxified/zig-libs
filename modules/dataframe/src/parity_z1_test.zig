// SPDX-License-Identifier: MIT
//! dataframe parity, agent Z1 (2026-11-10): `interpolate` methods `quadratic`, `cubic`,
//! `pchip`, `akima` (pandas 3.1 `Series.interpolate` through SciPy 1.18.1), `toLatex`
//! `column_format` / `longtable` / `position` (pandas `to_latex`) and `binary + binary`
//! (polars). Every expected value was produced by running the engine
//! (`~/CML/20261110-df-parity/z1_probe.py`, `z2_probe.py`, `z3_probe.py`); hostile inputs
//! must give an error or a value and never a panic.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const Column = df.Column;

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);

// ── Z1: interpolate ─────────────────────────────────────────────────────────

const Mode = enum { vals, err, nopanic };

const InterpCase = struct {
    id: []const u8,
    method: @TypeOf(@as(df.InterpolateSpec, undefined).method),
    y: []const f64,
    x: ?[]const f64,
    dir: @TypeOf(@as(df.InterpolateSpec, undefined).limit_direction),
    area: @TypeOf(@as(df.InterpolateSpec, undefined).limit_area),
    limit: ?usize,
    mode: Mode,
    want: ?[]const f64,
};

fn yxFrame(a: std.mem.Allocator, y: []const f64, x: ?[]const f64) !Frame {
    const ys = try a.alloc(Value, y.len);
    for (ys, y) |*v, e| v.* = if (std.math.isNan(e)) .null else .{ .float = e };
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(df.ColumnData) = .empty;
    try cols.append(a, .{ .name = "y", .type = .float });
    try data.append(a, try df.columnFromCells(a, ys));
    if (x) |xv| {
        const xs = try a.alloc(Value, xv.len);
        for (xs, xv) |*v, e| v.* = .{ .float = e };
        try cols.append(a, .{ .name = "x", .type = .float });
        try data.append(a, try df.columnFromCells(a, xs));
    }
    return .{ .columns = cols.items, .data = data.items, .len = y.len };
}

fn closeTo(got: f64, want: f64) bool {
    if (std.math.isNan(want)) return std.math.isNan(got);
    if (std.math.isInf(want)) return got == want;
    return @abs(got - want) <= 1e-12 * @max(@abs(want), 1.0);
}

fn runInterp(a: std.mem.Allocator, c: InterpCase) !void {
    const f = try yxFrame(a, c.y, c.x);
    const got = df.interpolate(a, f, .{
        .col = "y",
        .method = c.method,
        .by = if (c.x != null) "x" else null,
        .limit = c.limit,
        .limit_direction = c.dir,
        .limit_area = c.area,
    }) catch |e| {
        if (c.mode == .err) {
            try testing.expectEqual(error.BadArgument, e);
            return;
        }
        if (c.mode == .nopanic) return;
        std.debug.print("{s}: unexpected {t}\n", .{ c.id, e });
        return error.TestUnexpectedResult;
    };
    if (c.mode == .err) {
        std.debug.print("{s}: expected an error\n", .{c.id});
        return error.TestUnexpectedResult;
    }
    if (c.mode == .nopanic) return;
    const want = c.want.?;
    for (want, 0..) |w, i| {
        const cell = got.cell(i, "y").?;
        const g: f64 = switch (cell) {
            .float => |v| v,
            .null => nan,
            else => return error.TestUnexpectedResult,
        };
        if (!closeTo(g, w)) {
            std.debug.print("{s}: row {d}: got {d}, pandas {d}\n", .{ c.id, i, g, w });
            return error.TestUnexpectedResult;
        }
    }
}

/// pandas 3.1.0 / SciPy 1.18.1 `Series.interpolate(method=..., limit_direction=...,
/// limit_area=..., limit=...)` over a float Series (default RangeIndex, or a float index
/// for `x`); `pandas`' default limit_direction is "forward". `.err` is a `ValueError`.
const interp_cases = [_]InterpCase{
    .{ .id = "cubic-y1-default-", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 4.241269841269841, 4.0, 2.288095238095236, 1.1174603174603162, 2.5, 7.0, 9.39126984126984, 3.0, nan, nan } },
    .{ .id = "cubic-y1-both-limit_direction=both", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 4.241269841269841, 4.0, 2.288095238095236, 1.1174603174603162, 2.5, 7.0, 9.39126984126984, 3.0, nan, nan } },
    .{ .id = "cubic-y1-backward-limit_direction=backward", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 4.241269841269841, 4.0, 2.288095238095236, 1.1174603174603162, 2.5, 7.0, 9.39126984126984, 3.0, nan, nan } },
    .{ .id = "cubic-y1-inside-limit_area=inside", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 4.241269841269841, 4.0, 2.288095238095236, 1.1174603174603162, 2.5, 7.0, 9.39126984126984, 3.0, nan, nan } },
    .{ .id = "cubic-y1-outside-limit_area=outside-limit_direction=both", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan } },
    .{ .id = "cubic-y1-limit1-limit=1", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 4.241269841269841, 4.0, 2.288095238095236, nan, 2.5, 7.0, 9.39126984126984, 3.0, nan, nan } },
    .{ .id = "cubic-y1-limit1both-limit=1-limit_direction=both", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 4.241269841269841, 4.0, 2.288095238095236, 1.1174603174603162, 2.5, 7.0, 9.39126984126984, 3.0, nan, nan } },
    .{ .id = "cubic-y2-default-", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, -9.84291666666667, -7.395277777777777, 1.5, 8.0, 6.206493055555555, 2.0, 2.2, 5.603055555555557, 9.0 } },
    .{ .id = "cubic-y2-both-limit_direction=both", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, -9.84291666666667, -7.395277777777777, 1.5, 8.0, 6.206493055555555, 2.0, 2.2, 5.603055555555557, 9.0 } },
    .{ .id = "cubic-y2-backward-limit_direction=backward", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, -9.84291666666667, -7.395277777777777, 1.5, 8.0, 6.206493055555555, 2.0, 2.2, 5.603055555555557, 9.0 } },
    .{ .id = "cubic-y2-inside-limit_area=inside", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ 3.0, -9.84291666666667, -7.395277777777777, 1.5, 8.0, 6.206493055555555, 2.0, 2.2, 5.603055555555557, 9.0 } },
    .{ .id = "cubic-y2-outside-limit_area=outside-limit_direction=both", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 } },
    .{ .id = "cubic-y2-limit1-limit=1", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, -9.84291666666667, nan, 1.5, 8.0, 6.206493055555555, 2.0, 2.2, 5.603055555555557, 9.0 } },
    .{ .id = "cubic-y2-limit1both-limit=1-limit_direction=both", .method = .cubic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, -9.84291666666667, -7.395277777777777, 1.5, 8.0, 6.206493055555555, 2.0, 2.2, 5.603055555555557, 9.0 } },
    .{ .id = "cubic-y1-by-limit_direction=both", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.263697604790419, 4.0, 1.0108532934131758, -0.39610778443113537, 2.5, 7.0, 16.42964071856286, 3.0, nan, nan } },
    .{ .id = "cubic-y1-by-default-", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.263697604790419, 4.0, 1.0108532934131758, -0.39610778443113537, 2.5, 7.0, 16.42964071856286, 3.0, nan, nan } },
    .{ .id = "cubic-y1-unsorted-limit_direction=both", .method = .cubic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 5.0, 1.0, 9.0, 3.0, 0.0, 12.0, 2.0, 7.0, 4.0, 11.0, 6.0, 8.0, 10.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 4.685763888888889, 8.442708333333334, 1.0, 9.015625, 4.0, nan, 9.805555555555557, 2.5, 7.0, nan, 3.0, 2.2638888888888884, nan } },
    .{ .id = "cubic-few0-limit_direction=both", .method = .cubic, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "cubic-fewmid0-limit_direction=both", .method = .cubic, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "cubic-few1-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-fewmid1-limit_direction=both", .method = .cubic, .y = &.{ nan, 1.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-few2-limit_direction=both", .method = .cubic, .y = &.{ 1.0, 5.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-fewmid2-limit_direction=both", .method = .cubic, .y = &.{ nan, 1.0, nan, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-few3-limit_direction=both", .method = .cubic, .y = &.{ 1.0, 5.0, 2.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-fewmid3-limit_direction=both", .method = .cubic, .y = &.{ nan, 1.0, nan, 5.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-few4-limit_direction=both", .method = .cubic, .y = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan } },
    .{ .id = "cubic-fewmid4-limit_direction=both", .method = .cubic, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 7.75, 5.0, 2.0, 8.0 } },
    .{ .id = "cubic-few5-limit_direction=both", .method = .cubic, .y = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan } },
    .{ .id = "cubic-fewmid5-limit_direction=both", .method = .cubic, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 9.470588235294118, 5.0, 2.0, 8.0, 3.0 } },
    .{ .id = "cubic-nogap-", .method = .cubic, .y = &.{ 1.0, 2.0, 5.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 5.0 } },
    .{ .id = "cubic-allnull-", .method = .cubic, .y = &.{ nan, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, nan } },
    .{ .id = "cubic-dup-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 1.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-dup-hit-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0, 6.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.0, 5.0, 2.0, nan } },
    .{ .id = "cubic-inf-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, inf, 4.0, nan, 5.0, 6.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, nan, inf, 4.0, nan, 5.0, 6.0 } },
    .{ .id = "cubic-huge-limit_direction=both", .method = .cubic, .y = &.{ 1e+300, nan, -1e+300, 4.0, nan, 5.0, 6.0, 1e+308 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .nopanic, .want = null },
    .{ .id = "cubic-idxinf-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0 }, .x = &.{ 0.0, 1.0, inf, 3.0, 4.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, nan, 3.0, 4.0, 5.0 } },
    .{ .id = "cubic-tinyx-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 7.0 }, .x = &.{ 0.0, 1e-09, 2e-09, 3e-09, 1.0, 2.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.999999999249999, 3.0, 4.0, 5.0, 7.0 } },
    .{ .id = "cubic-missing-on-present-x-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, nan, 5.0, 4.0 }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.4, 5.0, 4.0 } },
    .{ .id = "cubic-exact4-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, 2.0, 4.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.75, 3.0, 2.0, 4.0 } },
    .{ .id = "cubic-exact3-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-n3gap-limit_direction=both", .method = .cubic, .y = &.{ 1.0, 4.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-ex2-limit_direction=both", .method = .cubic, .y = &.{ 1.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-ex1-limit_direction=both", .method = .cubic, .y = &.{ nan, 3.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "cubic-plateau-limit_direction=both", .method = .cubic, .y = &.{ 1.0, 1.0, nan, 1.0, 1.0, 2.0, nan, 2.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.0, 1.0693277310924372, 1.0, 1.0, 2.0, 2.2836134453781516, 2.0, 2.0 } },
    .{ .id = "cubic-plateau2-limit_direction=both", .method = .cubic, .y = &.{ 0.0, 0.0, 0.0, nan, 0.0, 0.0, 5.0, nan, 5.0, 5.0, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 0.0, 0.0, 0.0, 0.3071120689655172, 0.0, 0.0, 5.0, 6.244612068965518, 5.0, 5.0, 5.0 } },
    .{ .id = "quadratic-y1-default-", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.3392857142857144, 4.0, 2.9821428571428577, 1.0178571428571432, 2.5, 7.0, 7.553571428571428, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-both-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.3392857142857144, 4.0, 2.9821428571428577, 1.0178571428571432, 2.5, 7.0, 7.553571428571428, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-backward-limit_direction=backward", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.3392857142857144, 4.0, 2.9821428571428577, 1.0178571428571432, 2.5, 7.0, 7.553571428571428, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-inside-limit_area=inside", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.3392857142857144, 4.0, 2.9821428571428577, 1.0178571428571432, 2.5, 7.0, 7.553571428571428, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-outside-limit_area=outside-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-limit1-limit=1", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.3392857142857144, 4.0, 2.9821428571428577, nan, 2.5, 7.0, 7.553571428571428, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-limit1both-limit=1-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.3392857142857144, 4.0, 2.9821428571428577, 1.0178571428571432, 2.5, 7.0, 7.553571428571428, 3.0, nan, nan } },
    .{ .id = "quadratic-y2-default-", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, -1.9008980115458618, -2.4008980115458614, 1.5, 8.0, 6.288325849903784, 2.0, 2.2, 4.657280307889674, 9.0 } },
    .{ .id = "quadratic-y2-both-limit_direction=both", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, -1.9008980115458618, -2.4008980115458614, 1.5, 8.0, 6.288325849903784, 2.0, 2.2, 4.657280307889674, 9.0 } },
    .{ .id = "quadratic-y2-backward-limit_direction=backward", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, -1.9008980115458618, -2.4008980115458614, 1.5, 8.0, 6.288325849903784, 2.0, 2.2, 4.657280307889674, 9.0 } },
    .{ .id = "quadratic-y2-inside-limit_area=inside", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ 3.0, -1.9008980115458618, -2.4008980115458614, 1.5, 8.0, 6.288325849903784, 2.0, 2.2, 4.657280307889674, 9.0 } },
    .{ .id = "quadratic-y2-outside-limit_area=outside-limit_direction=both", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 } },
    .{ .id = "quadratic-y2-limit1-limit=1", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, -1.9008980115458618, nan, 1.5, 8.0, 6.288325849903784, 2.0, 2.2, 4.657280307889674, 9.0 } },
    .{ .id = "quadratic-y2-limit1both-limit=1-limit_direction=both", .method = .quadratic, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, -1.9008980115458618, -2.4008980115458614, 1.5, 8.0, 6.288325849903784, 2.0, 2.2, 4.657280307889674, 9.0 } },
    .{ .id = "quadratic-y1-by-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.9249020034843203, 4.0, 2.126469947735192, -0.1976480836236938, 2.5, 7.0, 10.353702090592336, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-by-default-", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.9249020034843203, 4.0, 2.126469947735192, -0.1976480836236938, 2.5, 7.0, 10.353702090592336, 3.0, nan, nan } },
    .{ .id = "quadratic-y1-unsorted-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 5.0, 1.0, 9.0, 3.0, 0.0, 12.0, 2.0, 7.0, 4.0, 11.0, 6.0, 8.0, 10.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 4.880681818181818, 6.471590909090908, 1.0, 7.971590909090909, 4.0, nan, 7.795454545454546, 2.5, 7.0, nan, 3.0, 1.914772727272727, nan } },
    .{ .id = "quadratic-few0-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "quadratic-fewmid0-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "quadratic-few1-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-fewmid1-limit_direction=both", .method = .quadratic, .y = &.{ nan, 1.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-few2-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, 5.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-fewmid2-limit_direction=both", .method = .quadratic, .y = &.{ nan, 1.0, nan, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-few3-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, 5.0, 2.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, nan, nan } },
    .{ .id = "quadratic-fewmid3-limit_direction=both", .method = .quadratic, .y = &.{ nan, 1.0, nan, 5.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 4.666666666666667, 5.0, 2.0 } },
    .{ .id = "quadratic-few4-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan } },
    .{ .id = "quadratic-fewmid4-limit_direction=both", .method = .quadratic, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 5.31578947368421, 5.0, 2.0, 8.0 } },
    .{ .id = "quadratic-few5-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan } },
    .{ .id = "quadratic-fewmid5-limit_direction=both", .method = .quadratic, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 5.513513513513513, 5.0, 2.0, 8.0, 3.0 } },
    .{ .id = "quadratic-nogap-", .method = .quadratic, .y = &.{ 1.0, 2.0, 5.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 5.0 } },
    .{ .id = "quadratic-allnull-", .method = .quadratic, .y = &.{ nan, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, nan } },
    .{ .id = "quadratic-dup-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 1.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-dup-hit-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0, 6.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.0, 5.0, 2.0, nan } },
    .{ .id = "quadratic-inf-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, inf, 4.0, nan, 5.0, 6.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, nan, inf, 4.0, nan, 5.0, 6.0 } },
    .{ .id = "quadratic-huge-limit_direction=both", .method = .quadratic, .y = &.{ 1e+300, nan, -1e+300, 4.0, nan, 5.0, 6.0, 1e+308 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .nopanic, .want = null },
    .{ .id = "quadratic-idxinf-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0 }, .x = &.{ 0.0, 1.0, inf, 3.0, 4.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, nan, 3.0, 4.0, 5.0 } },
    .{ .id = "quadratic-tinyx-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 7.0 }, .x = &.{ 0.0, 1e-09, 2e-09, 3e-09, 1.0, 2.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.999999999872727, 3.0, 4.0, 5.0, 7.0 } },
    .{ .id = "quadratic-missing-on-present-x-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, nan, 5.0, 4.0 }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.352941176470589, 5.0, 4.0 } },
    .{ .id = "quadratic-exact4-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, 2.0, 4.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.8947368421052624, 3.0, 2.0, 4.0 } },
    .{ .id = "quadratic-exact3-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.666666666666667, 3.0, 2.0 } },
    .{ .id = "quadratic-n3gap-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, 4.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 4.0, 4.666666666666666, 3.0 } },
    .{ .id = "quadratic-ex2-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-ex1-limit_direction=both", .method = .quadratic, .y = &.{ nan, 3.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "quadratic-plateau-limit_direction=both", .method = .quadratic, .y = &.{ 1.0, 1.0, nan, 1.0, 1.0, 2.0, nan, 2.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.0, 1.0360090022505626, 1.0, 1.0, 2.0, 2.2220555138784697, 2.0, 2.0 } },
    .{ .id = "quadratic-plateau2-limit_direction=both", .method = .quadratic, .y = &.{ 0.0, 0.0, 0.0, nan, 0.0, 0.0, 5.0, nan, 5.0, 5.0, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 0.0, 0.0, 0.0, 0.1754420626296552, 0.0, 0.0, 5.0, 6.081102439988146, 5.0, 5.0, 5.0 } },
    .{ .id = "pchip-y1-default-", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.075, 4.0, 3.611111111111111, 2.888888888888889, 2.5, 7.0, 6.5, 3.0, -6.5, -25.0 } },
    .{ .id = "pchip-y1-both-limit_direction=both", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -2.3999999999999986, -1.1749999999999996, 1.0, 3.075, 4.0, 3.611111111111111, 2.888888888888889, 2.5, 7.0, 6.5, 3.0, -6.5, -25.0 } },
    .{ .id = "pchip-y1-backward-limit_direction=backward", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ -2.3999999999999986, -1.1749999999999996, 1.0, 3.075, 4.0, 3.611111111111111, 2.888888888888889, 2.5, 7.0, 6.5, 3.0, nan, nan } },
    .{ .id = "pchip-y1-inside-limit_area=inside", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.075, 4.0, 3.611111111111111, 2.888888888888889, 2.5, 7.0, 6.5, 3.0, nan, nan } },
    .{ .id = "pchip-y1-outside-limit_area=outside-limit_direction=both", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ -2.3999999999999986, -1.1749999999999996, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, -6.5, -25.0 } },
    .{ .id = "pchip-y1-limit1-limit=1", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 3.075, 4.0, 3.611111111111111, nan, 2.5, 7.0, 6.5, 3.0, -6.5, nan } },
    .{ .id = "pchip-y1-limit1both-limit=1-limit_direction=both", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, -1.1749999999999996, 1.0, 3.075, 4.0, 3.611111111111111, 2.888888888888889, 2.5, 7.0, 6.5, 3.0, -6.5, nan } },
    .{ .id = "pchip-y2-default-", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, 1.9444444444444444, 1.5555555555555556, 1.5, 8.0, 5.0, 2.0, 2.2, 4.3026217228464425, 9.0 } },
    .{ .id = "pchip-y2-both-limit_direction=both", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, 1.9444444444444444, 1.5555555555555556, 1.5, 8.0, 5.0, 2.0, 2.2, 4.3026217228464425, 9.0 } },
    .{ .id = "pchip-y2-backward-limit_direction=backward", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, 1.9444444444444444, 1.5555555555555556, 1.5, 8.0, 5.0, 2.0, 2.2, 4.3026217228464425, 9.0 } },
    .{ .id = "pchip-y2-inside-limit_area=inside", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ 3.0, 1.9444444444444444, 1.5555555555555556, 1.5, 8.0, 5.0, 2.0, 2.2, 4.3026217228464425, 9.0 } },
    .{ .id = "pchip-y2-outside-limit_area=outside-limit_direction=both", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 } },
    .{ .id = "pchip-y2-limit1-limit=1", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, 1.9444444444444444, nan, 1.5, 8.0, 5.0, 2.0, 2.2, 4.3026217228464425, 9.0 } },
    .{ .id = "pchip-y2-limit1both-limit=1-limit_direction=both", .method = .pchip, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, 1.9444444444444444, 1.5555555555555556, 1.5, 8.0, 5.0, 2.0, 2.2, 4.3026217228464425, 9.0 } },
    .{ .id = "pchip-y1-by-limit_direction=both", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 18.85, 7.046875000000002, 1.0, 2.959375, 4.0, 3.525390625, 3.25, 2.5, 7.0, 6.136, 3.0, -16.328000000000007, -35.59200000000001 } },
    .{ .id = "pchip-y1-by-default-", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.959375, 4.0, 3.525390625, 3.25, 2.5, 7.0, 6.136, 3.0, -16.328000000000007, -35.59200000000001 } },
    .{ .id = "pchip-y1-unsorted-limit_direction=both", .method = .pchip, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 5.0, 1.0, 9.0, 3.0, 0.0, 12.0, 2.0, 7.0, 4.0, 11.0, 6.0, 8.0, 10.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-few0-limit_direction=both", .method = .pchip, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "pchip-fewmid0-limit_direction=both", .method = .pchip, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "pchip-few1-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-fewmid1-limit_direction=both", .method = .pchip, .y = &.{ nan, 1.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-few2-limit_direction=both", .method = .pchip, .y = &.{ 1.0, 5.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 9.0, 13.0 } },
    .{ .id = "pchip-fewmid2-limit_direction=both", .method = .pchip, .y = &.{ nan, 1.0, nan, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -1.0, 1.0, 3.0, 5.0 } },
    .{ .id = "pchip-few3-limit_direction=both", .method = .pchip, .y = &.{ 1.0, 5.0, 2.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, -9.0, -31.0 } },
    .{ .id = "pchip-fewmid3-limit_direction=both", .method = .pchip, .y = &.{ nan, 1.0, nan, 5.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -6.999999999999999, 1.0, 4.333333333333333, 5.0, 2.0 } },
    .{ .id = "pchip-few4-limit_direction=both", .method = .pchip, .y = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, 20.0, 29.0 } },
    .{ .id = "pchip-fewmid4-limit_direction=both", .method = .pchip, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -6.999999999999999, 1.0, 4.333333333333333, 5.0, 2.0, 8.0 } },
    .{ .id = "pchip-few5-limit_direction=both", .method = .pchip, .y = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, -14.0, -46.0 } },
    .{ .id = "pchip-fewmid5-limit_direction=both", .method = .pchip, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -6.999999999999999, 1.0, 4.333333333333333, 5.0, 2.0, 8.0, 3.0 } },
    .{ .id = "pchip-nogap-", .method = .pchip, .y = &.{ 1.0, 2.0, 5.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 5.0 } },
    .{ .id = "pchip-allnull-", .method = .pchip, .y = &.{ nan, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, nan } },
    .{ .id = "pchip-dup-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 1.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-dup-hit-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0, 6.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.0, 5.0, 2.0, -3.0 } },
    .{ .id = "pchip-inf-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, inf, 4.0, nan, 5.0, 6.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-huge-limit_direction=both", .method = .pchip, .y = &.{ 1e+300, nan, -1e+300, 4.0, nan, 5.0, 6.0, 1e+308 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-idxinf-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0 }, .x = &.{ 0.0, 1.0, inf, 3.0, 4.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-tinyx-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 7.0 }, .x = &.{ 0.0, 1e-09, 2e-09, 3e-09, 1.0, 2.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.9999999999999998, 3.0, 4.0, 5.0, 7.0 } },
    .{ .id = "pchip-missing-on-present-x-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, nan, 5.0, 4.0 }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.25, 5.0, 4.0 } },
    .{ .id = "pchip-exact4-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, 2.0, 4.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.5833333333333335, 3.0, 2.0, 4.0 } },
    .{ .id = "pchip-exact3-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.5833333333333335, 3.0, 2.0 } },
    .{ .id = "pchip-n3gap-limit_direction=both", .method = .pchip, .y = &.{ 1.0, 4.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 4.0, 3.875, 3.0 } },
    .{ .id = "pchip-ex2-limit_direction=both", .method = .pchip, .y = &.{ 1.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 3.0 } },
    .{ .id = "pchip-ex1-limit_direction=both", .method = .pchip, .y = &.{ nan, 3.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "pchip-plateau-limit_direction=both", .method = .pchip, .y = &.{ 1.0, 1.0, nan, 1.0, 1.0, 2.0, nan, 2.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0 } },
    .{ .id = "pchip-plateau2-limit_direction=both", .method = .pchip, .y = &.{ 0.0, 0.0, 0.0, nan, 0.0, 0.0, 5.0, nan, 5.0, 5.0, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 5.0, 5.0, 5.0, 5.0, 5.0 } },
    .{ .id = "akima-y1-default-", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.892857142857143, 4.0, 3.873482726423903, 2.7945845004668537, 2.5, 7.0, 6.730978260869566, 3.0, nan, nan } },
    .{ .id = "akima-y1-both-limit_direction=both", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.892857142857143, 4.0, 3.873482726423903, 2.7945845004668537, 2.5, 7.0, 6.730978260869566, 3.0, nan, nan } },
    .{ .id = "akima-y1-backward-limit_direction=backward", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.892857142857143, 4.0, 3.873482726423903, 2.7945845004668537, 2.5, 7.0, 6.730978260869566, 3.0, nan, nan } },
    .{ .id = "akima-y1-inside-limit_area=inside", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.892857142857143, 4.0, 3.873482726423903, 2.7945845004668537, 2.5, 7.0, 6.730978260869566, 3.0, nan, nan } },
    .{ .id = "akima-y1-outside-limit_area=outside-limit_direction=both", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan } },
    .{ .id = "akima-y1-limit1-limit=1", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.892857142857143, 4.0, 3.873482726423903, nan, 2.5, 7.0, 6.730978260869566, 3.0, nan, nan } },
    .{ .id = "akima-y1-limit1both-limit=1-limit_direction=both", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.892857142857143, 4.0, 3.873482726423903, 2.7945845004668537, 2.5, 7.0, 6.730978260869566, 3.0, nan, nan } },
    .{ .id = "akima-y2-default-", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, 0.2845117845117845, -0.0976430976430977, 1.5, 8.0, 5.146672842365293, 2.0, 2.2, 4.8, 9.0 } },
    .{ .id = "akima-y2-both-limit_direction=both", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, 0.2845117845117845, -0.0976430976430977, 1.5, 8.0, 5.146672842365293, 2.0, 2.2, 4.8, 9.0 } },
    .{ .id = "akima-y2-backward-limit_direction=backward", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .backward, .area = null, .limit = null, .mode = .vals, .want = &.{ 3.0, 0.2845117845117845, -0.0976430976430977, 1.5, 8.0, 5.146672842365293, 2.0, 2.2, 4.8, 9.0 } },
    .{ .id = "akima-y2-inside-limit_area=inside", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = .inside, .limit = null, .mode = .vals, .want = &.{ 3.0, 0.2845117845117845, -0.0976430976430977, 1.5, 8.0, 5.146672842365293, 2.0, 2.2, 4.8, 9.0 } },
    .{ .id = "akima-y2-outside-limit_area=outside-limit_direction=both", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = .outside, .limit = null, .mode = .vals, .want = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 } },
    .{ .id = "akima-y2-limit1-limit=1", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .forward, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, 0.2845117845117845, nan, 1.5, 8.0, 5.146672842365293, 2.0, 2.2, 4.8, 9.0 } },
    .{ .id = "akima-y2-limit1both-limit=1-limit_direction=both", .method = .akima, .y = &.{ 3.0, nan, nan, 1.5, 8.0, nan, 2.0, 2.2, nan, 9.0 }, .x = null, .dir = .both, .area = null, .limit = 1, .mode = .vals, .want = &.{ 3.0, 0.2845117845117845, -0.0976430976430977, 1.5, 8.0, 5.146672842365293, 2.0, 2.2, 4.8, 9.0 } },
    .{ .id = "akima-y1-by-limit_direction=both", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.822610294117647, 4.0, 4.095604523324871, 3.358764995264653, 2.5, 7.0, 7.858007509386733, 3.0, nan, nan } },
    .{ .id = "akima-y1-by-default-", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 0.0, 0.5, 2.0, 2.5, 3.0, 4.5, 5.0, 7.0, 7.5, 9.0, 10.0, 12.0, 13.0 }, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, 1.0, 2.822610294117647, 4.0, 4.095604523324871, 3.358764995264653, 2.5, 7.0, 7.858007509386733, 3.0, nan, nan } },
    .{ .id = "akima-y1-unsorted-limit_direction=both", .method = .akima, .y = &.{ nan, nan, 1.0, nan, 4.0, nan, nan, 2.5, 7.0, nan, 3.0, nan, nan }, .x = &.{ 5.0, 1.0, 9.0, 3.0, 0.0, 12.0, 2.0, 7.0, 4.0, 11.0, 6.0, 8.0, 10.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-few0-limit_direction=both", .method = .akima, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "akima-fewmid0-limit_direction=both", .method = .akima, .y = &.{ nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan } },
    .{ .id = "akima-few1-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-fewmid1-limit_direction=both", .method = .akima, .y = &.{ nan, 1.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-few2-limit_direction=both", .method = .akima, .y = &.{ 1.0, 5.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, nan, nan } },
    .{ .id = "akima-fewmid2-limit_direction=both", .method = .akima, .y = &.{ nan, 1.0, nan, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 3.0, 5.0 } },
    .{ .id = "akima-few3-limit_direction=both", .method = .akima, .y = &.{ 1.0, 5.0, 2.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, nan, nan } },
    .{ .id = "akima-fewmid3-limit_direction=both", .method = .akima, .y = &.{ nan, 1.0, nan, 5.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 4.25, 5.0, 2.0 } },
    .{ .id = "akima-few4-limit_direction=both", .method = .akima, .y = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, nan, nan } },
    .{ .id = "akima-fewmid4-limit_direction=both", .method = .akima, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 4.071428571428571, 5.0, 2.0, 8.0 } },
    .{ .id = "akima-few5-limit_direction=both", .method = .akima, .y = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 5.0, 2.0, 8.0, 3.0, nan, nan } },
    .{ .id = "akima-fewmid5-limit_direction=both", .method = .akima, .y = &.{ nan, 1.0, nan, 5.0, 2.0, 8.0, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 1.0, 4.071428571428571, 5.0, 2.0, 8.0, 3.0 } },
    .{ .id = "akima-nogap-", .method = .akima, .y = &.{ 1.0, 2.0, 5.0 }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 5.0 } },
    .{ .id = "akima-allnull-", .method = .akima, .y = &.{ nan, nan, nan }, .x = null, .dir = .forward, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, nan } },
    .{ .id = "akima-dup-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 1.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-dup-hit-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 2.0, nan }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0, 6.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.0, 5.0, 2.0, nan } },
    .{ .id = "akima-inf-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, inf, 4.0, nan, 5.0, 6.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-huge-limit_direction=both", .method = .akima, .y = &.{ 1e+300, nan, -1e+300, 4.0, nan, 5.0, 6.0, 1e+308 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-idxinf-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0 }, .x = &.{ 0.0, 1.0, inf, 3.0, 4.0 }, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-tinyx-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, 4.0, 5.0, 7.0 }, .x = &.{ 0.0, 1e-09, 2e-09, 3e-09, 1.0, 2.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 3.0, 4.0, 5.0, 7.0 } },
    .{ .id = "akima-missing-on-present-x-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, nan, 5.0, 4.0 }, .x = &.{ 0.0, 2.0, 2.0, 3.0, 4.0, 5.0 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 3.0, 3.0, 4.0, 5.0, 4.0 } },
    .{ .id = "akima-exact4-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, 2.0, 4.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.45, 3.0, 2.0, 4.0 } },
    .{ .id = "akima-exact3-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.5, 3.0, 2.0 } },
    .{ .id = "akima-n3gap-limit_direction=both", .method = .akima, .y = &.{ 1.0, 4.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 4.0, 4.375, 3.0 } },
    .{ .id = "akima-ex2-limit_direction=both", .method = .akima, .y = &.{ 1.0, nan, 3.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 2.0, 3.0 } },
    .{ .id = "akima-ex1-limit_direction=both", .method = .akima, .y = &.{ nan, 3.0, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .err, .want = null },
    .{ .id = "akima-plateau-limit_direction=both", .method = .akima, .y = &.{ 1.0, 1.0, nan, 1.0, 1.0, 2.0, nan, 2.0, 2.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0 } },
    .{ .id = "akima-plateau2-limit_direction=both", .method = .akima, .y = &.{ 0.0, 0.0, 0.0, nan, 0.0, 0.0, 5.0, nan, 5.0, 5.0, 5.0 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 5.0, 5.0, 5.0, 5.0, 5.0 } },
    .{ .id = "cubic-rand60-limit_direction=both", .method = .cubic, .y = &.{ nan, 2.623412361299464, nan, 6.371091680854704, 8.187374455493105, nan, nan, 10.509967091516636, 8.846871008981152, 7.470494518969241, 6.229642466132164, nan, nan, -1.547185367655186, -3.5224581881278354, -5.367961590194293, -8.240132226721823, nan, nan, -10.637696759646268, nan, nan, nan, nan, -2.715779438677146, -0.4252576377905454, nan, 4.231094289882858, 6.545615514487355, nan, 8.614931884994693, 9.707111153094797, 9.404322927205499, 8.821623482680602, 8.515320437927942, 5.843472199875976, 4.104923999944806, 2.1810897874959227, -1.043311420989744, -3.2510429110148165, nan, -7.315093416920423, -9.409485512925547, nan, -9.320490354636267, -10.451652314176856, nan, -7.22697274542341, -5.68646437705796, -2.1109852766400614, -0.282089117469651, 1.2263468952587284, nan, 6.604454669017479, nan, 9.601279561683874, nan, 10.27003479174479, 10.068211851074906, 7.842386509044116 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 2.623412361299464, 4.510854655824231, 6.371091680854704, 8.187374455493105, 9.843137688598635, 10.82255084805844, 10.509967091516636, 8.846871008981152, 7.470494518969241, 6.229642466132164, 4.005076238917839, 1.153170541441027, -1.547185367655186, -3.5224581881278354, -5.367961590194293, -8.240132226721823, -10.176578696147422, -10.85878767959233, -10.637696759646268, -9.819845282410833, -8.534179648035176, -6.865248020180324, -4.897598562507303, -2.715779438677146, -0.4252576377905454, 1.850660584744141, 4.231094289882858, 6.545615514487355, 7.7474184607039085, 8.614931884994693, 9.707111153094797, 9.404322927205499, 8.821623482680602, 8.515320437927942, 5.843472199875976, 4.104923999944806, 2.1810897874959227, -1.043311420989744, -3.2510429110148165, -5.137923938470364, -7.315093416920423, -9.409485512925547, -9.441357296702666, -9.320490354636267, -10.451652314176856, -9.289342646839808, -7.22697274542341, -5.68646437705796, -2.1109852766400614, -0.282089117469651, 1.2263468952587284, 3.8120637514633664, 6.604454669017479, 8.533213828561577, 9.601279561683874, 10.083614558432155, 10.27003479174479, 10.068211851074906, 7.842386509044116 } },
    .{ .id = "cubic-rand60-by-limit_direction=both", .method = .cubic, .y = &.{ nan, 2.623412361299464, nan, 6.371091680854704, 8.187374455493105, nan, nan, 10.509967091516636, 8.846871008981152, 7.470494518969241, 6.229642466132164, nan, nan, -1.547185367655186, -3.5224581881278354, -5.367961590194293, -8.240132226721823, nan, nan, -10.637696759646268, nan, nan, nan, nan, -2.715779438677146, -0.4252576377905454, nan, 4.231094289882858, 6.545615514487355, nan, 8.614931884994693, 9.707111153094797, 9.404322927205499, 8.821623482680602, 8.515320437927942, 5.843472199875976, 4.104923999944806, 2.1810897874959227, -1.043311420989744, -3.2510429110148165, nan, -7.315093416920423, -9.409485512925547, nan, -9.320490354636267, -10.451652314176856, nan, -7.22697274542341, -5.68646437705796, -2.1109852766400614, -0.282089117469651, 1.2263468952587284, nan, 6.604454669017479, nan, 9.601279561683874, nan, 10.27003479174479, 10.068211851074906, 7.842386509044116 }, .x = &.{ 1.8630208010145963, 3.0124411275823975, 3.4554908746353297, 5.235198973608623, 6.554185213531336, 7.736604335031571, 8.55155122367842, 9.432366259776966, 9.987395763872472, 10.159704608585827, 11.924520343993441, 12.913207755940224, 14.05371463444632, 14.765824923028749, 16.29334227075311, 16.441216325276457, 17.248368343150343, 17.406033902480154, 17.739528896669672, 19.67711054392467, 21.026855930997847, 21.940474399137862, 23.035580604167777, 24.793918100440848, 25.5479183677333, 26.769471234083756, 28.16847154342889, 28.94375771977356, 30.03004484411594, 31.584014872345136, 33.41145556892718, 33.798473897273134, 35.67197074265725, 35.78181058770657, 37.312467844542304, 38.95246882214507, 39.31232052007598, 40.20823745681103, 41.857224385001615, 41.98433964540237, 43.27841734634833, 44.88516229673459, 45.95986910409679, 47.43898300314385, 47.96918762026843, 48.44637780145451, 49.23631900750018, 49.67719045987776, 50.43470719419147, 52.33614291087201, 53.525475074333144, 54.27160440243274, 54.887501180069435, 56.796376212413726, 57.74088481074324, 59.70363483741636, 60.78312790871827, 61.8733435538681, 63.676770548928495, 65.18802864353707 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, 2.623412361299464, 3.5259528146701746, 6.371091680854704, 8.187374455493105, 9.82199850563188, 10.546165710249525, 10.509967091516636, 8.846871008981152, 7.470494518969241, 6.229642466132164, 3.7557755931630115, -0.8251402301154379, -1.547185367655186, -3.5224581881278354, -5.367961590194293, -8.240132226721823, -8.253036088898074, -8.414165954248245, -10.637696759646268, -10.653592437240269, -9.716076128144353, -7.906130045485495, -4.2601746662765665, -2.715779438677146, -0.4252576377905454, 2.4403398613623697, 4.231094289882858, 6.545615514487355, 7.1218612576459615, 8.614931884994693, 9.707111153094797, 9.404322927205499, 8.821623482680602, 8.515320437927942, 5.843472199875976, 4.104923999944806, 2.1810897874959227, -1.043311420989744, -3.2510429110148165, -11.825213217061659, -7.315093416920423, -9.409485512925547, -8.84004433533936, -9.320490354636267, -10.451652314176856, -8.839816295797753, -7.22697274542341, -5.68646437705796, -2.1109852766400614, -0.282089117469651, 1.2263468952587284, 2.6065020870953504, 6.604454669017479, 7.985519800300651, 9.601279561683874, 10.022230628577217, 10.27003479174479, 10.068211851074906, 7.842386509044116 } },
    .{ .id = "quadratic-rand60-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, nan, 6.419739398631819, 8.101673298218866, 8.850983617730277, 10.603484522897741, nan, nan, nan, 5.637519677188118, nan, 1.1310845553472224, -1.077971795708627, -3.695465696734676, -5.865574045394336, -8.257312295147239, nan, nan, nan, -10.116289640443132, -8.420681767978405, -6.351767155925653, nan, -2.8984159061148937, nan, 1.270690143714454, 4.8679040924353725, 6.558144027910468, 8.266529712261358, 9.003844031524594, 10.17337987261022, nan, nan, 7.430740730144146, 5.639188157437827, 4.7889507800675775, 1.485342501535098, -0.605671026440192, nan, -5.6607837102747895, -7.6009647892165635, -8.481916303993907, -9.85091248147374, -10.07562388959268, nan, nan, -6.946394270955131, nan, -3.392979246487894, -1.3542033335152395, 2.300756312178991, 4.684893935376848, 6.245755677620716, 8.308786186317969, 9.650545955028974, 10.321665783281194, nan, 9.121141729916264, nan }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, nan, 6.419739398631819, 8.101673298218866, 8.850983617730277, 10.603484522897741, 11.102092834463079, 9.904571031246839, 7.8150147624286435, 5.637519677188118, 3.3720857755252593, 1.1310845553472224, -1.077971795708627, -3.695465696734676, -5.865574045394336, -8.257312295147239, -9.998875332600608, -10.916302598430363, -10.968979048942536, -10.116289640443132, -8.420681767978405, -6.351767155925653, -4.5415573239301885, -2.8984159061148937, -1.2357791825028117, 1.270690143714454, 4.8679040924353725, 6.558144027910468, 8.266529712261358, 9.003844031524594, 10.17337987261022, 10.272213938852344, 9.11538757858121, 7.430740730144146, 5.639188157437827, 4.7889507800675775, 1.485342501535098, -0.605671026440192, -3.071254740597774, -5.6607837102747895, -7.6009647892165635, -8.481916303993907, -9.85091248147374, -10.07562388959268, -9.537340551113738, -8.403210792708439, -6.946394270955131, -5.212417595283544, -3.392979246487894, -1.3542033335152395, 2.300756312178991, 4.684893935376848, 6.245755677620716, 8.308786186317969, 9.650545955028974, 10.321665783281194, 10.15750439714282, 9.121141729916264, nan } },
    .{ .id = "quadratic-rand60-by-limit_direction=both", .method = .quadratic, .y = &.{ nan, nan, nan, 6.419739398631819, 8.101673298218866, 8.850983617730277, 10.603484522897741, nan, nan, nan, 5.637519677188118, nan, 1.1310845553472224, -1.077971795708627, -3.695465696734676, -5.865574045394336, -8.257312295147239, nan, nan, nan, -10.116289640443132, -8.420681767978405, -6.351767155925653, nan, -2.8984159061148937, nan, 1.270690143714454, 4.8679040924353725, 6.558144027910468, 8.266529712261358, 9.003844031524594, 10.17337987261022, nan, nan, 7.430740730144146, 5.639188157437827, 4.7889507800675775, 1.485342501535098, -0.605671026440192, nan, -5.6607837102747895, -7.6009647892165635, -8.481916303993907, -9.85091248147374, -10.07562388959268, nan, nan, -6.946394270955131, nan, -3.392979246487894, -1.3542033335152395, 2.300756312178991, 4.684893935376848, 6.245755677620716, 8.308786186317969, 9.650545955028974, 10.321665783281194, nan, 9.121141729916264, nan }, .x = &.{ 1.189918241047194, 2.5035431764891896, 3.7612782657251294, 4.044145053218412, 5.400408829146816, 6.701122806037901, 8.366505235141728, 9.993179363489352, 10.714798958561397, 12.18668889112185, 13.934508327509327, 15.731109068071827, 16.137982489271124, 16.288716954435063, 17.625251096937298, 18.13313601515045, 19.304184491257878, 21.199313097890876, 22.020020383970756, 22.600292029700938, 23.56766112462849, 24.916424559842884, 25.208512598766735, 26.031623649417767, 26.38569390821096, 27.74434172927804, 29.42239154057809, 30.238413725254777, 31.04468923552617, 32.169780387526295, 32.678390168838675, 33.24846839291054, 33.97518773114712, 34.94429655760974, 35.19920633218463, 36.72939739128194, 37.92960108269752, 38.599019441189476, 38.84635792865638, 40.3964017363192, 40.74545181407271, 41.0985444345371, 41.44684450157092, 41.701242892691305, 43.523388386951794, 44.134952556331235, 44.81713265682427, 46.4994418458282, 47.777296419280624, 48.23286885370799, 49.15901433722351, 50.93846702019559, 51.75167765253257, 53.20235260360599, 53.48628725039528, 54.96820432619851, 56.54350402192248, 58.21246090715653, 59.59344278898343, 60.39783509915331 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ nan, nan, nan, 6.419739398631819, 8.101673298218866, 8.850983617730277, 10.603484522897741, 9.968900212514814, 8.747366935936006, 5.76416608529604, 5.637519677188118, 5.682148474921661, 1.1310845553472224, -1.077971795708627, -3.695465696734676, -5.865574045394336, -8.257312295147239, -9.579043989336938, -9.699601953372351, -9.821809845907804, -10.116289640443132, -8.420681767978405, -6.351767155925653, -3.4402868449963098, -2.8984159061148937, -1.8409210422378022, 1.270690143714454, 4.8679040924353725, 6.558144027910468, 8.266529712261358, 9.003844031524594, 10.17337987261022, 10.091295865653956, 7.919579868437543, 7.430740730144146, 5.639188157437827, 4.7889507800675775, 1.485342501535098, -0.605671026440192, -4.2422755027917525, -5.6607837102747895, -7.6009647892165635, -8.481916303993907, -9.85091248147374, -10.07562388959268, -9.363221056716364, -8.76190874076832, -6.946394270955131, -4.4038844182369425, -3.392979246487894, -1.3542033335152395, 2.300756312178991, 4.684893935376848, 6.245755677620716, 8.308786186317969, 9.650545955028974, 10.321665783281194, 10.25962766265529, 9.121141729916264, nan } },
    .{ .id = "pchip-rand60-limit_direction=both", .method = .pchip, .y = &.{ 0.12519900813879525, nan, nan, nan, 8.280036324968764, 9.400716811864715, nan, 10.007072998934877, 9.090196753155485, 8.545216967834682, 5.707097476157742, nan, nan, nan, -3.0256660927989842, -5.257189165167583, -7.233575729855814, -8.89481928845401, -9.667556707059806, -10.118931184887433, nan, -8.562193128409072, -6.299488499922031, -4.804946824088545, nan, -0.6214881906972662, 1.8337006371723257, 5.301793243392421, nan, nan, nan, 9.391461085261497, nan, 9.662871119628502, 7.788602502816158, 6.133618246041644, 4.010667676698077, 1.79369203780342, -1.5480166439908976, nan, nan, -6.904691787766652, -9.18225693799913, nan, -9.237683339143654, nan, -9.055309872946017, nan, -5.366743693808863, -3.6080017234811286, -0.4327592656553171, 2.833749373049044, 4.072614370633548, nan, 7.515378253731667, 9.419368653929546, 9.28258544459489, 9.382945499151885, nan, 7.72749110484962 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 0.12519900813879525, 2.70298877028836, 4.905742413883406, 6.7569336838136405, 8.280036324968764, 9.400716811864715, 9.831336543133094, 10.007072998934877, 9.090196753155485, 8.545216967834682, 5.707097476157742, 3.3319395852182696, 1.1796599474207428, -0.892091818247466, -3.0256660927989842, -5.257189165167583, -7.233575729855814, -8.89481928845401, -9.667556707059806, -10.118931184887433, -9.646738946221044, -8.562193128409072, -6.299488499922031, -4.804946824088545, -2.855075766125221, -0.6214881906972662, 1.8337006371723257, 5.301793243392421, 6.896323851236864, 8.122371149395434, 8.960546455019768, 9.391461085261497, 9.582371452011909, 9.662871119628502, 7.788602502816158, 6.133618246041644, 4.010667676698077, 1.79369203780342, -1.5480166439908976, -3.5723346021227607, -5.152697813602064, -6.904691787766652, -9.18225693799913, -9.225325264220256, -9.237683339143654, -9.189941910093902, -9.055309872946017, -7.616521475421423, -5.366743693808863, -3.6080017234811286, -0.4327592656553171, 2.833749373049044, 4.072614370633548, 5.693222603743306, 7.515378253731667, 9.419368653929546, 9.28258544459489, 9.382945499151885, 8.916831309906556, 7.72749110484962 } },
    .{ .id = "pchip-rand60-by-limit_direction=both", .method = .pchip, .y = &.{ 0.12519900813879525, nan, nan, nan, 8.280036324968764, 9.400716811864715, nan, 10.007072998934877, 9.090196753155485, 8.545216967834682, 5.707097476157742, nan, nan, nan, -3.0256660927989842, -5.257189165167583, -7.233575729855814, -8.89481928845401, -9.667556707059806, -10.118931184887433, nan, -8.562193128409072, -6.299488499922031, -4.804946824088545, nan, -0.6214881906972662, 1.8337006371723257, 5.301793243392421, nan, nan, nan, 9.391461085261497, nan, 9.662871119628502, 7.788602502816158, 6.133618246041644, 4.010667676698077, 1.79369203780342, -1.5480166439908976, nan, nan, -6.904691787766652, -9.18225693799913, nan, -9.237683339143654, nan, -9.055309872946017, nan, -5.366743693808863, -3.6080017234811286, -0.4327592656553171, 2.833749373049044, 4.072614370633548, nan, 7.515378253731667, 9.419368653929546, 9.28258544459489, 9.382945499151885, nan, 7.72749110484962 }, .x = &.{ 1.2942138224233883, 2.413009173551797, 3.264656977412108, 4.867203195076113, 6.6267343484529135, 7.067539749460505, 7.426526326614763, 7.741590444100644, 9.702824231952446, 11.59184770737869, 12.130115353750785, 14.07293974355691, 14.567793311091378, 15.630097741848827, 16.675129325865907, 18.513545541069703, 18.69055037486978, 19.389716922295104, 20.629668849379986, 20.855825464536217, 21.405271559707657, 22.388892122492983, 24.162520473544514, 25.70834356469431, 27.383406456861618, 28.92943902466731, 30.3741084991619, 32.088525850190145, 33.48333156258985, 34.9811293752857, 35.654253930514905, 36.07277130402252, 37.61016876441852, 38.025259626378975, 39.87222574426691, 41.10584713524354, 41.83177194970001, 43.71139394733948, 44.106141464021384, 45.18362750564235, 45.457580244753196, 47.391892892013885, 48.58510740945598, 50.21207394527608, 50.84772654070672, 52.47114013137694, 53.90653986599623, 55.22953465860233, 57.135604006925696, 58.05923754930666, 58.9479055731317, 60.362935717823234, 62.049540799495006, 62.786185237559216, 64.15853364148111, 64.65570471642292, 65.80393466636339, 67.36536089991284, 67.58945930709817, 69.07235923144228 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ 0.12519900813879525, 1.0850960787559116, 2.1646528569659576, 4.810632070990677, 8.280036324968764, 9.400716811864715, 9.841304715225395, 10.007072998934877, 9.090196753155485, 8.545216967834682, 5.707097476157742, 0.925936614511219, 0.057711195453132635, -1.5532704936923294, -3.0256660927989842, -5.257189165167583, -7.233575729855814, -8.89481928845401, -9.667556707059806, -10.118931184887433, -9.80485923109101, -8.562193128409072, -6.299488499922031, -4.804946824088545, -2.7932688380282498, -0.6214881906972662, 1.8337006371723257, 5.301793243392421, 7.221762560192866, 8.818173232824988, 9.246058760187669, 9.391461085261497, 9.646940302004086, 9.662871119628502, 7.788602502816158, 6.133618246041644, 4.010667676698077, 1.79369203780342, -1.5480166439908976, -4.092842252273519, -4.4949725649553205, -6.904691787766652, -9.18225693799913, -9.233923343122349, -9.237683339143654, -9.183551648941773, -9.055309872946017, -8.132380723206738, -5.366743693808863, -3.6080017234811286, -0.4327592656553171, 2.833749373049044, 4.072614370633548, 4.932985629186246, 7.515378253731667, 9.419368653929546, 9.28258544459489, 9.382945499151885, 9.343430626612314, 7.72749110484962 } },
    .{ .id = "akima-rand60-limit_direction=both", .method = .akima, .y = &.{ -0.08772711270357438, 3.267806188586202, 4.47060916034839, 6.898308196399891, 7.579033604793926, 9.298412619172478, 10.466827320240558, nan, 9.629088040724124, 7.949350876803443, nan, 3.56581128481048, 1.1816672422459655, nan, nan, nan, -7.720318804336691, nan, -10.420064462972508, nan, -9.1478056338541, nan, -7.05364917997194, -5.407768872393232, -3.2827277005566033, 0.09492666088174129, nan, 5.249591579338616, nan, 8.424059786927971, 9.266358264468787, 9.56897688654858, 10.187419987522695, 9.148550815855998, 8.286476416591725, nan, 3.578276724766847, 1.6878602322098821, nan, -2.715960459282138, nan, -7.366649230681607, nan, nan, nan, -10.581259735654418, -8.784130164021652, -6.733807278940277, nan, -3.6552113425054866, -1.0348564190386476, 1.2612430231403384, 4.3913843124337015, nan, nan, nan, 9.528316241464362, 10.152801060217987, 8.863257969305808, 7.574148377439297 }, .x = null, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -0.08772711270357438, 3.267806188586202, 4.47060916034839, 6.898308196399891, 7.579033604793926, 9.298412619172478, 10.466827320240558, 10.562442583812636, 9.629088040724124, 7.949350876803443, 5.811243444282157, 3.56581128481048, 1.1816672422459655, -1.1291391439118241, -3.3667478016489327, -5.555645449084256, -7.720318804336691, -9.610815794620441, -10.420064462972508, -10.021460955013417, -9.1478056338541, -8.193641995019421, -7.05364917997194, -5.407768872393232, -3.2827277005566033, 0.09492666088174129, 2.8887876801864785, 5.249591579338616, 7.076685733898433, 8.424059786927971, 9.266358264468787, 9.56897688654858, 10.187419987522695, 9.148550815855998, 8.286476416591725, 6.106520258538804, 3.578276724766847, 1.6878602322098821, -0.4924347379211098, -2.715960459282138, -5.032926731187141, -7.366649230681607, -9.405552594958579, -10.815212434945318, -11.304243299043403, -10.581259735654418, -8.784130164021652, -6.733807278940277, -5.256344457179747, -3.6552113425054866, -1.0348564190386476, 1.2612430231403384, 4.3913843124337015, 6.194934635399832, 7.529431584070447, 8.579137879180355, 9.528316241464362, 10.152801060217987, 8.863257969305808, 7.574148377439297 } },
    .{ .id = "akima-rand60-by-limit_direction=both", .method = .akima, .y = &.{ -0.08772711270357438, 3.267806188586202, 4.47060916034839, 6.898308196399891, 7.579033604793926, 9.298412619172478, 10.466827320240558, nan, 9.629088040724124, 7.949350876803443, nan, 3.56581128481048, 1.1816672422459655, nan, nan, nan, -7.720318804336691, nan, -10.420064462972508, nan, -9.1478056338541, nan, -7.05364917997194, -5.407768872393232, -3.2827277005566033, 0.09492666088174129, nan, 5.249591579338616, nan, 8.424059786927971, 9.266358264468787, 9.56897688654858, 10.187419987522695, 9.148550815855998, 8.286476416591725, nan, 3.578276724766847, 1.6878602322098821, nan, -2.715960459282138, nan, -7.366649230681607, nan, nan, nan, -10.581259735654418, -8.784130164021652, -6.733807278940277, nan, -3.6552113425054866, -1.0348564190386476, 1.2612430231403384, 4.3913843124337015, nan, nan, nan, 9.528316241464362, 10.152801060217987, 8.863257969305808, 7.574148377439297 }, .x = &.{ 0.9703270448804888, 1.7797040912209847, 2.916893146723847, 3.3994406043268817, 4.100907501599011, 5.54331216711343, 7.107288732029323, 7.315034189090307, 8.807403855190529, 10.460520733017132, 11.406388522188838, 11.625050956624554, 13.022586141971097, 13.590297095270325, 14.912676020222541, 15.728258787450798, 17.0388694761878, 17.629325748335326, 18.634746091227118, 19.731628095392644, 21.030553142011154, 21.516572041004043, 23.444469083888777, 24.093831427801153, 24.775269678159365, 25.362263206163643, 25.590468101243022, 26.494021635755878, 28.060510627257635, 29.508687806958847, 29.980275467735446, 30.340446082548777, 31.05115916931176, 32.610843960752895, 33.63819241887212, 35.492242365509426, 36.839371520770605, 38.11909440393366, 39.67770754342357, 41.2031982140402, 41.95649065156755, 42.54480661485014, 43.476287255328934, 44.50585689879443, 44.87513016259987, 45.813661333182424, 47.12932551935758, 47.48718307882619, 47.849455066138205, 48.27952574991342, 48.9178554200941, 50.84510304236504, 50.99410649829642, 51.443210823030626, 51.856801717847304, 52.85806296563917, 52.98670124484696, 53.95723036387747, 54.36678301871312, 54.97909944177298 }, .dir = .both, .area = null, .limit = null, .mode = .vals, .want = &.{ -0.08772711270357438, 3.267806188586202, 4.47060916034839, 6.898308196399891, 7.579033604793926, 9.298412619172478, 10.466827320240558, 10.47535493467247, 9.629088040724124, 7.949350876803443, 4.211571540582157, 3.56581128481048, 1.1816672422459655, -0.03999130663989123, -2.9988820264630256, -4.843802494815597, -7.720318804336691, -9.00560801331635, -10.420064462972508, -10.169933144036566, -9.1478056338541, -8.818510926986429, -7.05364917997194, -5.407768872393232, -3.2827277005566033, 0.09492666088174129, 1.3136938869922956, 5.249591579338616, 7.153548900460778, 8.424059786927971, 9.266358264468787, 9.56897688654858, 10.187419987522695, 9.148550815855998, 8.286476416591725, 5.569730888497199, 3.578276724766847, 1.6878602322098821, -0.5409759668273559, -2.715960459282138, -5.251666982306083, -7.366649230681607, -9.077557721468356, -10.113520842151328, -10.320096312587895, -10.581259735654418, -8.784130164021652, -6.733807278940277, -5.324445057720622, -3.6552113425054866, -1.0348564190386476, 1.2612430231403384, 4.3913843124337015, 6.116692543197861, 7.409928858328465, 9.390021546641009, 9.528316241464362, 10.152801060217987, 8.863257969305808, 7.574148377439297 } },
};

test "interpolate quadratic / cubic / pchip / akima follow pandas + SciPy (Z1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var checked: usize = 0;
    for (interp_cases) |c| {
        _ = arena.reset(.retain_capacity);
        try runInterp(arena.allocator(), c);
        if (c.mode == .vals) checked += 1;
    }
    try testing.expect(checked > 120);
}

const smooth_methods = [_]@TypeOf(@as(df.InterpolateSpec, undefined).method){ .quadratic, .cubic, .pchip, .akima };

test "interpolate smooth methods: hostile inputs give an error or numbers, never a panic (Z1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const big = 1e308;
    const shapes = [_][]const f64{
        &.{},
        &.{nan},
        &.{ nan, nan, nan },
        &.{1},
        &.{ 1, nan },
        &.{ inf, nan, -inf, nan, 1, 2 },
        &.{ 1e308, nan, -1e308, 1e308, nan, 5 },
        &.{ 1, nan, 1, nan, 1, nan, 1, nan },
        &.{ 5e-324, nan, 1e-320, 0, nan, 2.2250738585072014e-308, 3 },
    };
    const xs = [_]?[]const f64{
        null,
        &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8 },
        &.{ -big, -1, 0, 1, big, big, 2, 3, 4 },
        &.{ inf, 0, 1, 2, 3, 4, 5, 6, 7 },
        &.{ 5, 4, 3, 2, 1, 0, -1, -2, -3 },
        &.{ 1, 1, 1, 1, 1, 1, 1, 1, 1 },
    };
    for (smooth_methods) |m| for (shapes) |y| for (xs) |xo| {
        const xv: ?[]const f64 = if (xo) |q| (if (q.len >= y.len) q[0..y.len] else null) else null;
        const f = try yxFrame(a, y, xv);
        const dirs = [_]@TypeOf(@as(df.InterpolateSpec, undefined).limit_direction){ null, .forward, .backward, .both };
        for (dirs) |dir| {
            _ = df.interpolate(a, f, .{ .col = "y", .method = m, .by = if (xv != null) "x" else null, .limit_direction = dir, .limit = 2 }) catch |e| {
                try testing.expect(e == error.BadArgument);
                continue;
            };
        }
    };
}

test "interpolate smooth methods: a long column and a column that is all gaps (Z1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 30_000;
    const y = try a.alloc(f64, n);
    var s: u64 = 12345;
    for (y, 0..) |*v, i| {
        s = s *% 6364136223846793005 +% 1442695040888963407;
        v.* = if ((s >> 33) % 3 == 0) nan else @as(f64, @floatFromInt(i % 97)) + @as(f64, @floatFromInt((s >> 40) % 1000)) / 1000.0;
    }
    for (smooth_methods) |m| {
        const g = try df.interpolate(a, try yxFrame(a, y, null), .{ .col = "y", .method = m, .limit_direction = .both });
        var finite: usize = 0;
        for (0..n) |i| {
            switch (g.cell(i, "y").?) {
                .float => |v| {
                    try testing.expect(std.math.isFinite(v));
                    finite += 1;
                },
                .null => {},
                else => return error.TestUnexpectedResult,
            }
        }
        try testing.expect(finite > n * 9 / 10);
        const z = try a.alloc(f64, 50);
        @memset(z, nan);
        const h = try df.interpolate(a, try yxFrame(a, z, null), .{ .col = "y", .method = m });
        for (0..50) |i| try testing.expect(h.cell(i, "y").? == .null);
    }
}

// ── Z2: toLatex column_format / longtable / position ─────────────────────────

const Tbl = enum { people, empty, wide, one, nullmix, esc, zerocols };

const LatexCase = struct { id: []const u8, tbl: Tbl, opts: df.LatexOptions, want: []const u8 };

fn tblFrame(a: std.mem.Allocator, t: Tbl) !Frame {
    const T = struct {
        fn col(al: std.mem.Allocator, cs: *std.ArrayList(Column), ds: *std.ArrayList(df.ColumnData), name: []const u8, ty: df.ColumnType, cells: []const Value) !void {
            try cs.append(al, .{ .name = name, .type = ty });
            try ds.append(al, try df.columnFromCells(al, cells));
        }
    };
    var cs: std.ArrayList(Column) = .empty;
    var ds: std.ArrayList(df.ColumnData) = .empty;
    var len: usize = 0;
    switch (t) {
        .people, .empty => {
            const n: usize = if (t == .people) 2 else 0;
            try T.col(a, &cs, &ds, "name", .text, ([_]Value{ .{ .text = "Raphael" }, .{ .text = "Donatello" } })[0..n]);
            try T.col(a, &cs, &ds, "age", .int, ([_]Value{ .{ .int = 26 }, .{ .int = 45 } })[0..n]);
            try T.col(a, &cs, &ds, "height", .float, ([_]Value{ .{ .float = 181.23 }, .{ .float = 177.65 } })[0..n]);
            len = n;
        },
        .wide => {
            for ([_][]const u8{ "a", "b", "c", "d", "e" }, 1..) |nm, v| try T.col(a, &cs, &ds, nm, .int, &.{.{ .int = @intCast(v) }});
            len = 1;
        },
        .one => {
            try T.col(a, &cs, &ds, "a", .int, &.{.{ .int = 1 }});
            len = 1;
        },
        .nullmix => {
            try T.col(a, &cs, &ds, "a", .float, &.{ .{ .float = 1.5 }, .null });
            try T.col(a, &cs, &ds, "b", .text, &.{ .{ .text = "x" }, .null });
            len = 2;
        },
        .esc => {
            try T.col(a, &cs, &ds, "a_b", .int, &.{.{ .int = 1 }});
            try T.col(a, &cs, &ds, "50%", .text, &.{.{ .text = "x&y" }});
            len = 1;
        },
        .zerocols => {},
    }
    return .{ .columns = cs.items, .data = ds.items, .len = len };
}

/// pandas 3.1.0 `DataFrame.to_latex(index=False, ...)` (jinja2 from the system's python, as
/// oracle2k); `.id` says what was passed.
const latex_cases = [_]LatexCase{
    .{ .id = "base", .tbl = .people, .opts = .{}, .want = "\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf lrc", .tbl = .people, .opts = .{ .column_format = "lrc" }, .want = "\\begin{tabular}{lrc}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf |l|r|r|", .tbl = .people, .opts = .{ .column_format = "|l|r|r|" }, .want = "\\begin{tabular}{|l|r|r|}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf ", .tbl = .people, .opts = .{ .column_format = "" }, .want = "\\begin{tabular}{}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf p{3cm}ll", .tbl = .people, .opts = .{ .column_format = "p{3cm}ll" }, .want = "\\begin{tabular}{p{3cm}ll}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf lr", .tbl = .people, .opts = .{ .column_format = "lr" }, .want = "\\begin{tabular}{lr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf lrrrr", .tbl = .people, .opts = .{ .column_format = "lrrrr" }, .want = "\\begin{tabular}{lrrrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf l{r}%", .tbl = .people, .opts = .{ .column_format = "l{r}%" }, .want = "\\begin{tabular}{l{r}%}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "cf l r", .tbl = .people, .opts = .{ .column_format = "l r" }, .want = "\\begin{tabular}{l r}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "lt", .tbl = .people, .opts = .{ .longtable = true }, .want = "\\begin{longtable}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-cap", .tbl = .people, .opts = .{ .longtable = true, .caption = "People" }, .want = "\\begin{longtable}{lrr}\n\\caption{People} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{People} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-label", .tbl = .people, .opts = .{ .longtable = true, .label = "tab:p" }, .want = "\\begin{longtable}{lrr}\n\\label{tab:p} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-cap-label", .tbl = .people, .opts = .{ .longtable = true, .caption = "People", .label = "tab:p" }, .want = "\\begin{longtable}{lrr}\n\\caption{People} \\label{tab:p} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{People} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-noheader", .tbl = .people, .opts = .{ .longtable = true, .header = false }, .want = "\\begin{longtable}{lrr}\n\\toprule\n\\midrule\n\\endfirsthead\n\\toprule\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-noheader-cap", .tbl = .people, .opts = .{ .longtable = true, .header = false, .caption = "C" }, .want = "\\begin{longtable}{lrr}\n\\caption{C} \\\\\n\\toprule\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-empty", .tbl = .empty, .opts = .{ .longtable = true }, .want = "\\begin{longtable}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{0}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n\\end{longtable}\n" },
    .{ .id = "lt-empty-cap", .tbl = .empty, .opts = .{ .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{0}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n\\end{longtable}\n" },
    .{ .id = "lt-cf", .tbl = .people, .opts = .{ .longtable = true, .column_format = "lll" }, .want = "\\begin{longtable}{lll}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-cf-lr", .tbl = .people, .opts = .{ .longtable = true, .column_format = "lr" }, .want = "\\begin{longtable}{lr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-cf-empty", .tbl = .people, .opts = .{ .longtable = true, .column_format = "" }, .want = "\\begin{longtable}{}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-cf-5", .tbl = .people, .opts = .{ .longtable = true, .column_format = "lllll" }, .want = "\\begin{longtable}{lllll}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-esc", .tbl = .people, .opts = .{ .longtable = true, .escape = true, .caption = "a_b" }, .want = "\\begin{longtable}{lrr}\n\\caption{a_b} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{a_b} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-esc-header", .tbl = .esc, .opts = .{ .longtable = true, .escape = true }, .want = "\\begin{longtable}{rl}\n\\toprule\na\\_b & 50\\% \\\\\n\\midrule\n\\endfirsthead\n\\toprule\na\\_b & 50\\% \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{2}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n1 & x\\&y \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-wide", .tbl = .wide, .opts = .{ .longtable = true }, .want = "\\begin{longtable}{rrrrr}\n\\toprule\na & b & c & d & e \\\\\n\\midrule\n\\endfirsthead\n\\toprule\na & b & c & d & e \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{5}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n1 & 2 & 3 & 4 & 5 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-wide-empty", .tbl = .empty, .opts = .{ .longtable = true, .column_format = "rrrrr" }, .want = "\\begin{longtable}{rrrrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{0}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n\\end{longtable}\n" },
    .{ .id = "lt-onecol", .tbl = .one, .opts = .{ .longtable = true }, .want = "\\begin{longtable}{r}\n\\toprule\na \\\\\n\\midrule\n\\endfirsthead\n\\toprule\na \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{1}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n1 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-null", .tbl = .nullmix, .opts = .{ .longtable = true, .null_text = "--" }, .want = "\\begin{longtable}{rl}\n\\toprule\na & b \\\\\n\\midrule\n\\endfirsthead\n\\toprule\na & b \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{2}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n1.500000 & x \\\\\n-- & -- \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-zerocols", .tbl = .zerocols, .opts = .{ .longtable = true }, .want = "\\begin{longtable}{}\n\\toprule\n\\midrule\n\\endfirsthead\n\\toprule\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{0}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n\\end{longtable}\n" },
    .{ .id = "lt-cap-special", .tbl = .people, .opts = .{ .longtable = true, .caption = "a_b & 50%", .label = "x_y" }, .want = "\\begin{longtable}{lrr}\n\\caption{a_b & 50%} \\label{x_y} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{a_b & 50%} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-newline-cap", .tbl = .people, .opts = .{ .longtable = true, .caption = "a\nb" }, .want = "\\begin{longtable}{lrr}\n\\caption{a\nb} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{a\nb} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "lt-cap-empty", .tbl = .people, .opts = .{ .longtable = true, .caption = "", .label = "" }, .want = "\\begin{longtable}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "cap-empty", .tbl = .people, .opts = .{ .caption = "", .label = "" }, .want = "\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "label-empty", .tbl = .people, .opts = .{ .label = "" }, .want = "\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "pos 'h'", .tbl = .people, .opts = .{ .position = "h" }, .want = "\\begin{table}[h]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap 'h'", .tbl = .people, .opts = .{ .position = "h", .caption = "C" }, .want = "\\begin{table}[h]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt 'h'", .tbl = .people, .opts = .{ .position = "h", .longtable = true }, .want = "\\begin{longtable}[h]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label 'h'", .tbl = .people, .opts = .{ .position = "h", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[h]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label 'h'", .tbl = .people, .opts = .{ .position = "h", .caption = "C", .label = "l" }, .want = "\\begin{table}[h]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos 'htbp'", .tbl = .people, .opts = .{ .position = "htbp" }, .want = "\\begin{table}[htbp]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap 'htbp'", .tbl = .people, .opts = .{ .position = "htbp", .caption = "C" }, .want = "\\begin{table}[htbp]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt 'htbp'", .tbl = .people, .opts = .{ .position = "htbp", .longtable = true }, .want = "\\begin{longtable}[htbp]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label 'htbp'", .tbl = .people, .opts = .{ .position = "htbp", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[htbp]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label 'htbp'", .tbl = .people, .opts = .{ .position = "htbp", .caption = "C", .label = "l" }, .want = "\\begin{table}[htbp]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos '!ht'", .tbl = .people, .opts = .{ .position = "!ht" }, .want = "\\begin{table}[!ht]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap '!ht'", .tbl = .people, .opts = .{ .position = "!ht", .caption = "C" }, .want = "\\begin{table}[!ht]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt '!ht'", .tbl = .people, .opts = .{ .position = "!ht", .longtable = true }, .want = "\\begin{longtable}[!ht]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label '!ht'", .tbl = .people, .opts = .{ .position = "!ht", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[!ht]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label '!ht'", .tbl = .people, .opts = .{ .position = "!ht", .caption = "C", .label = "l" }, .want = "\\begin{table}[!ht]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos ''", .tbl = .people, .opts = .{ .position = "" }, .want = "\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "pos-cap ''", .tbl = .people, .opts = .{ .position = "", .caption = "C" }, .want = "\\begin{table}\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt ''", .tbl = .people, .opts = .{ .position = "", .longtable = true }, .want = "\\begin{longtable}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label ''", .tbl = .people, .opts = .{ .position = "", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label ''", .tbl = .people, .opts = .{ .position = "", .caption = "C", .label = "l" }, .want = "\\begin{table}\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos 'H'", .tbl = .people, .opts = .{ .position = "H" }, .want = "\\begin{table}[H]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap 'H'", .tbl = .people, .opts = .{ .position = "H", .caption = "C" }, .want = "\\begin{table}[H]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt 'H'", .tbl = .people, .opts = .{ .position = "H", .longtable = true }, .want = "\\begin{longtable}[H]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label 'H'", .tbl = .people, .opts = .{ .position = "H", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[H]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label 'H'", .tbl = .people, .opts = .{ .position = "H", .caption = "C", .label = "l" }, .want = "\\begin{table}[H]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos ' '", .tbl = .people, .opts = .{ .position = " " }, .want = "\\begin{table}[]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap ' '", .tbl = .people, .opts = .{ .position = " ", .caption = "C" }, .want = "\\begin{table}[]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt ' '", .tbl = .people, .opts = .{ .position = " ", .longtable = true }, .want = "\\begin{longtable}[]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label ' '", .tbl = .people, .opts = .{ .position = " ", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label ' '", .tbl = .people, .opts = .{ .position = " ", .caption = "C", .label = "l" }, .want = "\\begin{table}[]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos 'h t'", .tbl = .people, .opts = .{ .position = "h t" }, .want = "\\begin{table}[h t]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap 'h t'", .tbl = .people, .opts = .{ .position = "h t", .caption = "C" }, .want = "\\begin{table}[h t]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt 'h t'", .tbl = .people, .opts = .{ .position = "h t", .longtable = true }, .want = "\\begin{longtable}[h t]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label 'h t'", .tbl = .people, .opts = .{ .position = "h t", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[h t]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label 'h t'", .tbl = .people, .opts = .{ .position = "h t", .caption = "C", .label = "l" }, .want = "\\begin{table}[h t]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos '\\th\\n'", .tbl = .people, .opts = .{ .position = "\th\n" }, .want = "\\begin{table}[h]\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-cap '\\th\\n'", .tbl = .people, .opts = .{ .position = "\th\n", .caption = "C" }, .want = "\\begin{table}[h]\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-lt '\\th\\n'", .tbl = .people, .opts = .{ .position = "\th\n", .longtable = true }, .want = "\\begin{longtable}[h]{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-lt-cap-label '\\th\\n'", .tbl = .people, .opts = .{ .position = "\th\n", .longtable = true, .caption = "C", .label = "l" }, .want = "\\begin{longtable}[h]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "pos-cap-label '\\th\\n'", .tbl = .people, .opts = .{ .position = "\th\n", .caption = "C", .label = "l" }, .want = "\\begin{table}[h]\n\\caption{C}\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "pos-label", .tbl = .people, .opts = .{ .position = "h", .label = "l" }, .want = "\\begin{table}[h]\n\\label{l}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "all", .tbl = .people, .opts = .{ .position = "h", .longtable = true, .caption = "C", .label = "l", .column_format = "lrr" }, .want = "\\begin{longtable}[h]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\nname & age & height \\\\\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "all-noheader", .tbl = .people, .opts = .{ .position = "h", .longtable = true, .caption = "C", .label = "l", .column_format = "lrr", .header = false }, .want = "\\begin{longtable}[h]{lrr}\n\\caption{C} \\label{l} \\\\\n\\toprule\n\\midrule\n\\endfirsthead\n\\caption[]{C} \\\\\n\\toprule\n\\midrule\n\\endhead\n\\midrule\n\\multicolumn{3}{r}{Continued on next page} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\end{longtable}\n" },
    .{ .id = "cf-cap", .tbl = .people, .opts = .{ .column_format = "lrr", .caption = "C" }, .want = "\\begin{table}\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "cf-noheader", .tbl = .people, .opts = .{ .column_format = "lrr", .header = false }, .want = "\\begin{tabular}{lrr}\n\\toprule\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n" },
    .{ .id = "empty-cap", .tbl = .empty, .opts = .{ .caption = "C" }, .want = "\\begin{table}\n\\caption{C}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" },
    .{ .id = "zerocols-plain", .tbl = .zerocols, .opts = .{}, .want = "\\begin{tabular}{}\n\\toprule\n\\midrule\n\\bottomrule\n\\end{tabular}\n" },
};

test "toLatex column_format, longtable and position are pandas' (Z2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for (latex_cases) |c| {
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const got = try df.toLatex(a, try tblFrame(a, c.tbl), c.opts);
        testing.expectEqualStrings(c.want, got) catch |e| {
            std.debug.print("case {s}\n", .{c.id});
            return e;
        };
    }
}

test "toLatex: hostile column_format, caption and position never panic (Z2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try tblFrame(a, .people);
    // 2 MiB of column spec, a caption with braces and newlines, a position of only blanks
    const huge = try a.alloc(u8, 2 << 20);
    @memset(huge, 'p');
    const got = try df.toLatex(a, f, .{ .column_format = huge, .longtable = true, .caption = "}{\\\n\x00", .label = "{", .position = " \t\n" });
    try testing.expect(got.len > huge.len);
    try testing.expect(std.mem.startsWith(u8, got, "\\begin{longtable}[]{ppp"));
    const wide = try df.toLatex(a, f, .{ .column_format = huge });
    try testing.expectEqual(got.len - wide.len < 1000, true);
    // a frame with columns and no rows, and one without columns, in every mode
    for ([_]Tbl{ .empty, .zerocols }) |t| for ([_]bool{ false, true }) |lt| {
        const e = try df.toLatex(a, try tblFrame(a, t), .{ .longtable = lt, .position = "h", .caption = "c", .header = false });
        try testing.expect(e.len > 20);
    };
}

// ── Z3: binary + binary ─────────────────────────────────────────────────────

const ex = @import("expr.zig");
const fm = @import("frame.zig");
const Expr = ex.Expr;

/// polars: `pl.DataFrame({"a": [b"ab", b"", None, b"\xff\x00", b"x"], "b": [b"cd", b"zz", b"q", None, b""],
/// "s": ["1", "2", "3", "4", "5"], "n": [1, 2, 3, 4, 5]}, schema={"a": Binary, "b": Binary, ...})`.
fn binFixture(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{
        .{ .name = "a", .type = .binary },
        .{ .name = "b", .type = .binary },
        .{ .name = "s", .type = .text },
        .{ .name = "n", .type = .int },
    });
    var fb = try fm.FrameBuilder.init(a, cols, 5);
    const av = [_]Value{ .{ .text = "ab" }, .{ .text = "" }, .null, .{ .text = "\xff\x00" }, .{ .text = "x" } };
    const bv = [_]Value{ .{ .text = "cd" }, .{ .text = "zz" }, .{ .text = "q" }, .null, .{ .text = "" } };
    const sv = [_][]const u8{ "1", "2", "3", "4", "5" };
    for (0..5) |i| try fb.appendRow(&.{ av[i], bv[i], .{ .text = sv[i] }, .{ .int = @intCast(i + 1) } });
    return fb.toOwned();
}

fn bx(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

fn bcol(a: std.mem.Allocator, n: []const u8) !*const Expr {
    return bx(a, .{ .col = n });
}

fn blit(a: std.mem.Allocator, s: []const u8) !*const Expr {
    return bx(a, .{ .cast = .{ .x = try bx(a, .{ .lit = .{ .text = s } }), .to = .binary } });
}

fn badd(a: std.mem.Allocator, l: *const Expr, r: *const Expr) !*const Expr {
    return bx(a, .{ .binary = .{ .op = .add, .l = l, .r = r } });
}

fn expectBin(a: std.mem.Allocator, f: Frame, e: *const Expr, want: []const ?[]const u8) !void {
    const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = e.* }});
    try testing.expectEqual(df.ColumnType.binary, out.columnType("o").?);
    for (want, 0..) |w, i| {
        const cell = out.cell(i, "o").?;
        if (w) |bytes| {
            try testing.expect(cell == .text);
            try testing.expectEqualSlices(u8, bytes, cell.text);
        } else try testing.expect(cell == .null);
    }
}

test "binary + binary concatenates the bytes, null propagates (polars, Z3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try binFixture(a);
    const ca = try bcol(a, "a");
    const cb = try bcol(a, "b");
    // polars: a + b -> [b'abcd', b'zz', None, None, b'x']
    try expectBin(a, f, try badd(a, ca, cb), &.{ "abcd", "zz", null, null, "x" });
    // polars: a + a -> [b'abab', b'', None, b'\xff\x00\xff\x00', b'xx']
    try expectBin(a, f, try badd(a, ca, ca), &.{ "abab", "", null, "\xff\x00\xff\x00", "xx" });
    // polars: a + pl.lit(b"-") and pl.lit(b"-") + a
    try expectBin(a, f, try badd(a, ca, try blit(a, "-")), &.{ "ab-", "-", null, "\xff\x00-", "x-" });
    try expectBin(a, f, try badd(a, try blit(a, "-"), ca), &.{ "-ab", "-", null, "-\xff\x00", "-x" });
    // polars: a + b + a -> [b'abcdab', b'zz', None, None, b'xx']
    try expectBin(a, f, try badd(a, try badd(a, ca, cb), ca), &.{ "abcdab", "zz", null, null, "xx" });
    // polars: a + pl.lit(None) (and the other way) -> all null, still Binary
    const nl = try bx(a, .{ .lit = .null });
    try expectBin(a, f, try badd(a, ca, nl), &.{ null, null, null, null, null });
    try expectBin(a, f, try badd(a, nl, ca), &.{ null, null, null, null, null });
    try expectBin(a, f, try badd(a, try badd(a, ca, ca), nl), &.{ null, null, null, null, null });
    // polars: a + s (String) and s + a are Binary: the text is its bytes; a text literal too
    const cs = try bcol(a, "s");
    try expectBin(a, f, try badd(a, ca, cs), &.{ "ab1", "2", null, "\xff\x004", "x5" });
    try expectBin(a, f, try badd(a, cs, ca), &.{ "1ab", "2", null, "4\xff\x00", "5x" });
    try expectBin(a, f, try badd(a, ca, try bx(a, .{ .lit = .{ .text = "-" } })), &.{ "ab-", "-", null, "\xff\x00-", "x-" });
    try expectBin(a, f, try badd(a, try bx(a, .{ .lit = .{ .text = "-" } }), ca), &.{ "-ab", "-", null, "-\xff\x00", "-x" });
    // polars: a + s.cast(Binary)
    try expectBin(a, f, try badd(a, ca, try bx(a, .{ .cast = .{ .x = cs, .to = .binary } })), &.{ "ab1", "2", null, "\xff\x004", "x5" });
    // polars: (a + b).bin.size() -> [4, 2, None, None, 1] (UInt32)
    const sz = try ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .bin = .{ .x = try badd(a, ca, cb), .op = .{ .size = .b } } } }});
    try testing.expectEqual(@as(i64, 4), sz.cell(0, "o").?.int);
    try testing.expect(sz.cell(2, "o").? == .null);
    try testing.expectEqual(@as(i64, 1), sz.cell(4, "o").?.int);
    // polars: when(n > 2).then(a + b).otherwise(a) -> [b'ab', b'', None, None, b'x']
    const gt = try bx(a, .{ .binary = .{ .op = .gt, .l = try bcol(a, "n"), .r = try bx(a, .{ .lit = .{ .int = 2 } }) } });
    try expectBin(a, f, try bx(a, .{ .if_else = .{ .cond = gt, .then = try badd(a, ca, cb), .otherwise = ca } }), &.{ "ab", "", null, null, "x" });
}

test "binary + a number and the other arithmetic stay BadExpr (polars SchemaError / InvalidOperationError, Z3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try binFixture(a);
    const ca = try bcol(a, "a");
    const cb = try bcol(a, "b");
    // polars: a + n -> "failed to determine supertype of binary and i64"; a + pl.lit(1) likewise
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = (try badd(a, ca, try bcol(a, "n"))).* }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = (try badd(a, try bx(a, .{ .lit = .{ .int = 1 } }), ca)).* }}));
    // polars: a - b, a * b, a / b, a // b, a % b: operation not supported for binary
    inline for (.{ ex.Binary.sub, .mul, .div, .floordiv, .mod }) |op| {
        try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .binary = .{ .op = op, .l = ca, .r = cb } } }}));
    }
    // text + text is untouched: a number-style `add` of two texts is null, as before
    const ss = try ex.mutate(a, f, &.{.{ .out = "o", .expr = (try badd(a, try bcol(a, "s"), try bcol(a, "s"))).* }});
    try testing.expect(ss.cell(0, "o").? == .null);
}

test "binary + binary: the result is capped at max_text_result, empty and all-null columns work (Z3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cap = df.max_text_result;
    const l = try a.alloc(u8, cap / 2);
    @memset(l, 0xAB);
    const r1 = try a.alloc(u8, cap - l.len);
    @memset(r1, 0xCD);
    const r2 = try a.alloc(u8, cap - l.len + 1);
    @memset(r2, 0xCD);
    const cols = try a.dupe(Column, &.{ .{ .name = "a", .type = .binary }, .{ .name = "b", .type = .binary } });
    var fb = try fm.FrameBuilder.init(a, cols, 1);
    try fb.appendRow(&.{ .{ .text = l }, .{ .text = r1 } });
    const f1 = try fb.toOwned();
    const sum = try ex.mutate(a, f1, &.{.{ .out = "o", .expr = (try badd(a, try bcol(a, "a"), try bcol(a, "b"))).* }});
    try testing.expectEqual(cap, sum.cell(0, "o").?.text.len);
    var fb2 = try fm.FrameBuilder.init(a, cols, 1);
    try fb2.appendRow(&.{ .{ .text = l }, .{ .text = r2 } });
    const f2 = try fb2.toOwned();
    try testing.expectError(error.TooLarge, ex.mutate(a, f2, &.{.{ .out = "o", .expr = (try badd(a, try bcol(a, "a"), try bcol(a, "b"))).* }}));
    // polars: an empty Binary column and an all-null one give Binary columns of the same length
    var fb3 = try fm.FrameBuilder.init(a, cols, 0);
    const f3 = try fb3.toOwned();
    try expectBin(a, f3, try badd(a, try bcol(a, "a"), try bcol(a, "b")), &.{});
    var fb4 = try fm.FrameBuilder.init(a, cols, 2);
    try fb4.appendRow(&.{ .null, .null });
    try fb4.appendRow(&.{ .null, .null });
    try expectBin(a, try fb4.toOwned(), try badd(a, try bcol(a, "a"), try bcol(a, "b")), &.{ null, null });
    // a long chain of additions does not blow the compiler or the stack
    var e = try bcol(a, "a");
    for (0..200) |_| e = try badd(a, e, try bcol(a, "b"));
    _ = ex.mutate(a, f1, &.{.{ .out = "o", .expr = e.* }}) catch |err| try testing.expect(err == error.TooLarge or err == error.ExprTooLarge);
}

test "binary + binary: an x + x tower is walked in linear time (Z3 regression)" {
    // `cur + cur` 40 deep is a DAG of 2^40 paths; the static binary check once re-walked it
    // with a fresh step budget per node and hung the suite. It must be refused or computed,
    // quickly (without the shared budget in `binAddOkB` this never returns).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try binFixture(a);
    var e = try bcol(a, "a");
    for (0..40) |_| e = try badd(a, e, e);
    _ = ex.mutate(a, f, &.{.{ .out = "o", .expr = e.* }}) catch |err| {
        try testing.expect(err == error.TooLarge or err == error.ExprTooLarge or err == error.BadExpr);
    };
}
