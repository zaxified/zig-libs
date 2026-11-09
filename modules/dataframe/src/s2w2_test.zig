// SPDX-License-Identifier: MIT
//! Dataframe S2 wave W2: the everyday single-parameter gaps (`describe`, `valueCounts`,
//! `cut`/`qcut`, `rank`, `quantiles`, `join`, `sort`, `fillna`, `pivot`, `interpolate`,
//! groupby `ohlc`). Expected cells are what pandas 3.1 / polars 2.1 printed for the same
//! inputs (the engine-checked cases are in `oracle2_vectors.json`).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;
const mk = st.mk;
const expectCol = st.expectCol;

fn i(x: i64) Value {
    return .{ .int = x };
}
fn fl(x: f64) Value {
    return .{ .float = x };
}
fn t(x: []const u8) Value {
    return .{ .text = x };
}
const nul: Value = .null;

fn col1(a: std.mem.Allocator, name: []const u8, ty: df.ColumnType, xs: []const Value) !Frame {
    const rows = try a.alloc([]const Value, xs.len);
    for (rows, xs) |*r, x| r.* = try a.dupe(Value, &.{x});
    return mk(a, try a.dupe(Column, &.{.{ .name = name, .type = ty }}), rows);
}

fn arena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

// ── describe ────────────────────────────────────────────────────────────────

test "describe takes percentiles and always prints the median (W2-1)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try mk(a, &.{ .{ .name = "n", .type = .float }, .{ .name = "m", .type = .int } }, &.{
        &.{ fl(1), i(4) }, &.{ fl(2), i(5) }, &.{ fl(3), i(6) }, &.{ nul, i(8) },
    });
    const d = try df.describeWith(a, f, .{ .percentiles = &.{ 0.9, 0.1 } });
    try expectCol(d, "statistic", &.{ t("count"), t("mean"), t("std"), t("min"), t("10%"), t("50%"), t("90%"), t("max") });
    try expectCol(d, "n", &.{ fl(3), fl(2), fl(1), fl(1), fl(1.2), fl(2), fl(2.8), fl(3) });
    try expectCol(d, "m", &.{ fl(4), fl(5.75), fl(1.707825127659933), fl(4), fl(4.3), fl(5.5), fl(7.4), fl(8) });
    try testing.expectError(error.BadArgument, df.describeWith(a, f, .{ .percentiles = &.{1.5} }));
    // A label like pandas': 7.5%.
    const e = try df.describeWith(a, f, .{ .percentiles = &.{0.075} });
    try expectCol(e, "statistic", &.{ t("count"), t("mean"), t("std"), t("min"), t("7.5%"), t("50%"), t("max") });
}

test "describe of text, bool and mixed columns (W2-1)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try mk(a, &.{ .{ .name = "t", .type = .text }, .{ .name = "n", .type = .float }, .{ .name = "b", .type = .bool } }, &.{
        &.{ t("a"), fl(1), .{ .bool = true } },
        &.{ t("b"), fl(2), .{ .bool = false } },
        &.{ t("a"), fl(3), .{ .bool = true } },
        &.{ nul, nul, .{ .bool = true } },
    });
    // Default: the numeric column only.
    const d0 = try df.describeWith(a, f, .{});
    try testing.expectEqual(@as(usize, 2), d0.columns.len);
    // include all: rows by first appearance; a column lacks the other kind's rows.
    const d = try df.describeWith(a, f, .{ .all = true });
    try expectCol(d, "statistic", &.{ t("count"), t("unique"), t("top"), t("freq"), t("mean"), t("std"), t("min"), t("25%"), t("50%"), t("75%"), t("max") });
    try expectCol(d, "t", &.{ i(3), i(2), t("a"), i(2), nul, nul, nul, nul, nul, nul, nul });
    try expectCol(d, "b", &.{ i(4), i(2), .{ .bool = true }, i(3), nul, nul, nul, nul, nul, nul, nul });
    try expectCol(d, "n", &.{ fl(3), nul, nul, nul, fl(2), fl(1), fl(1), fl(1.5), fl(2), fl(2.5), fl(3) });
    // exclude by type, include by type.
    const ex = try df.describeWith(a, f, .{ .exclude = &.{.float} });
    try expectCol(ex, "statistic", &.{ t("count"), t("unique"), t("top"), t("freq") });
    try testing.expectEqual(@as(usize, 3), ex.columns.len);
    const inc = try df.describeWith(a, f, .{ .include = &.{.bool} });
    try testing.expectEqual(@as(usize, 2), inc.columns.len);
    try testing.expectEqualStrings("b", inc.columns[1].name);
}

test "describe of timestamps: no std, ISO text, std last beside a number (W2-1)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const day: i64 = 86_400_000_000;
    const base: i64 = 18262 * day; // 2020-01-01
    const f = try mk(a, &.{ .{ .name = "n", .type = .float }, .{ .name = "d", .type = .timestamp } }, &.{
        &.{ fl(1), i(base) }, &.{ fl(2), i(base + 2 * day) }, &.{ fl(3), nul }, &.{ nul, i(base + 4 * day) },
    });
    const d = try df.describeWith(a, f, .{});
    try expectCol(d, "statistic", &.{ t("count"), t("mean"), t("min"), t("25%"), t("50%"), t("75%"), t("max"), t("std") });
    try expectCol(d, "d", &.{ i(3), t("2020-01-03T00:00:00Z"), t("2020-01-01T00:00:00Z"), t("2020-01-02T00:00:00Z"), t("2020-01-03T00:00:00Z"), t("2020-01-04T00:00:00Z"), t("2020-01-05T00:00:00Z"), nul });
}

// ── value_counts ────────────────────────────────────────────────────────────

test "valueCounts normalize, sort off and ascending (W2-1)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try col1(a, "x", .float, &.{ fl(1), fl(2), fl(2), nul, fl(3) });
    const n = try df.valueCounts(a, f, .{ .cols = &.{"x"}, .normalize = true });
    try expectCol(n, "x", &.{ fl(2), fl(1), fl(3) });
    try expectCol(n, "count", &.{ fl(0.5), fl(0.25), fl(0.25) });
    const u = try df.valueCounts(a, f, .{ .cols = &.{"x"}, .sort = false });
    try expectCol(u, "x", &.{ fl(1), fl(2), fl(3) });
    try expectCol(u, "count", &.{ i(1), i(2), i(1) });
    const asc = try df.valueCounts(a, f, .{ .cols = &.{"x"}, .ascending = true });
    try expectCol(asc, "x", &.{ fl(1), fl(3), fl(2) });
    const m = try df.valueCounts(a, f, .{ .cols = &.{"x"}, .normalize = true, .keep_missing = true });
    try expectCol(m, "x", &.{ fl(2), fl(1), nul, fl(3) });
    try expectCol(m, "count", &.{ fl(0.4), fl(0.2), fl(0.2), fl(0.2) });
}

// ── cut / qcut ──────────────────────────────────────────────────────────────

test "cut with a bin count: pandas' edges and interval labels (W2-2)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try col1(a, "x", .float, &.{ fl(1), fl(2), fl(3), fl(4), fl(5), fl(10), nul });
    const e = try df.binEdges(a, f, "x", 3, true);
    try testing.expectEqual(@as(usize, 4), e.len);
    for (e, [_]f64{ 0.991, 4, 7, 10 }) |x, w| try testing.expectApproxEqAbs(w, x, 1e-12);
    const c = try df.cut(a, f, .{ .col = "x", .out = "o", .bins = 3, .interval_labels = true });
    try expectCol(c, "o", &.{ t("(0.991, 4.0]"), t("(0.991, 4.0]"), t("(0.991, 4.0]"), t("(0.991, 4.0]"), t("(4.0, 7.0]"), t("(7.0, 10.0]"), nul });
    const n = try df.cut(a, f, .{ .col = "x", .out = "o", .bins = 3, .break_out = "brk" });
    try expectCol(n, "o", &.{ i(0), i(0), i(0), i(0), i(1), i(2), nul });
    try expectCol(n, "brk", &.{ fl(4), fl(4), fl(4), fl(4), fl(7), fl(10), nul });
    try testing.expectError(error.BadEdges, df.cut(a, f, .{ .col = "x", .out = "o" }));
}

test "cut precision, left-closed bins and a constant column (W2-2)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try col1(a, "x", .float, &.{ fl(0), fl(1), fl(2), fl(3), fl(4) });
    const p = try df.cut(a, f, .{ .col = "x", .out = "o", .bins = 4, .precision = 2, .interval_labels = true });
    try expectCol(p, "o", &.{ t("(-0.004, 1.0]"), t("(-0.004, 1.0]"), t("(1.0, 2.0]"), t("(2.0, 3.0]"), t("(3.0, 4.0]") });
    const l = try df.cut(a, f, .{ .col = "x", .out = "o", .bins = 4, .right = false, .interval_labels = true });
    try expectCol(l, "o", &.{ t("[0.0, 1.0)"), t("[1.0, 2.0)"), t("[2.0, 3.0)"), t("[3.0, 4.004)"), t("[3.0, 4.004)") });
    const k = try col1(a, "x", .float, &.{ fl(3), fl(3), fl(3) });
    const c = try df.cut(a, k, .{ .col = "x", .out = "o", .bins = 2, .interval_labels = true });
    try expectCol(c, "o", &.{ t("(2.997, 3.0]"), t("(2.997, 3.0]"), t("(2.997, 3.0]") });
}

test "cut with infinite outer edges gives polars' breakpoints (W2-2)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try col1(a, "x", .float, &.{ fl(1), fl(2), fl(3), fl(4), fl(10) });
    const inf = std.math.inf(f64);
    const c = try df.cut(a, f, .{ .col = "x", .out = "o", .edges = &.{ -inf, 2, 5, inf }, .interval_labels = true, .break_out = "b" });
    try expectCol(c, "o", &.{ t("(-inf, 2.0]"), t("(-inf, 2.0]"), t("(2.0, 5.0]"), t("(2.0, 5.0]"), t("(5.0, inf]") });
    try expectCol(c, "b", &.{ fl(2), fl(2), fl(5), fl(5), fl(inf) });
}

test "qcut interval labels step the lowest edge down (W2-2)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try col1(a, "x", .float, &.{ fl(1), fl(2), fl(3), fl(4), fl(5), fl(10) });
    const q = try df.qcut(a, f, .{ .col = "x", .out = "o", .bins = 3, .interval_labels = true });
    try expectCol(q, "o", &.{ t("(0.999, 2.667]"), t("(0.999, 2.667]"), t("(2.667, 4.333]"), t("(2.667, 4.333]"), t("(4.333, 10.0]"), t("(4.333, 10.0]") });
    const e = try df.qcutEdges(a, f, .{ .col = "x", .out = "o", .bins = 3 });
    try testing.expectEqual(@as(usize, 4), e.len);
    try testing.expectApproxEqAbs(@as(f64, 8.0 / 3.0), e[1], 1e-12);
}

// ── rank / quantiles ────────────────────────────────────────────────────────

fn rankOf(a: std.mem.Allocator, f: Frame, op: @FieldType(df.WindowOp, "rank")) !Frame {
    return df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rank = op } });
}

test "rank pct and na_option (W2-3)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try col1(a, "x", .float, &.{ fl(2), fl(1), nul, fl(1) });
    try expectCol(try rankOf(a, f, .{ .pct = true }), "r", &.{ fl(1), fl(0.5), nul, fl(0.5) });
    try expectCol(try rankOf(a, f, .{ .na_option = .top }), "r", &.{ fl(4), fl(2.5), fl(1), fl(2.5) });
    try expectCol(try rankOf(a, f, .{ .na_option = .bottom, .pct = true }), "r", &.{ fl(0.75), fl(0.375), fl(1), fl(0.375) });
    // Dense ranks over the largest rank; min over the count.
    try expectCol(try rankOf(a, f, .{ .method = .dense, .pct = true }), "r", &.{ fl(1), fl(0.5), nul, fl(0.5) });
    try expectCol(try rankOf(a, f, .{ .method = .min, .na_option = .top }), "r", &.{ i(4), i(2), i(1), i(2) });
    // Several missing cells tie with each other.
    const g = try col1(a, "x", .float, &.{ nul, fl(5), nul });
    try expectCol(try rankOf(a, g, .{ .na_option = .bottom }), "r", &.{ fl(2.5), fl(1), fl(2.5) });
}

test "quantiles: a row per probability, polars' equiprobable (W2-3)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try mk(a, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .float }, .{ .name = "s", .type = .text } }, &.{
        &.{ fl(1), fl(2), t("x") }, &.{ fl(2), fl(4), t("y") }, &.{ fl(3), fl(6), t("z") }, &.{ fl(4), fl(8), nul }, &.{ fl(10), fl(20), nul },
    });
    const q = try df.quantiles(a, f, .{ .qs = &.{ 0.1, 0.5 } });
    try testing.expectEqual(@as(usize, 3), q.columns.len);
    try expectCol(q, "quantile", &.{ fl(0.1), fl(0.5) });
    try expectCol(q, "a", &.{ fl(1.4), fl(3) });
    try expectCol(q, "b", &.{ fl(2.8), fl(6) });
    const e = try df.quantiles(a, f, .{ .cols = &.{"a"}, .qs = &.{ 0.3, 0.5, 0.1, 0, 1 }, .interpolation = .equiprobable });
    try expectCol(e, "a", &.{ fl(2), fl(3), fl(1), fl(1), fl(10) });
    try testing.expectError(error.BadArgument, df.quantiles(a, f, .{ .qs = &.{-0.1} }));
    try testing.expectError(error.NoSuchColumn, df.quantiles(a, f, .{ .cols = &.{"zz"}, .qs = &.{0.5} }));
}

// ── join ────────────────────────────────────────────────────────────────────

fn joinSides(a: std.mem.Allocator) !struct { l: Frame, r: Frame } {
    const l = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "a", .type = .text }, .{ .name = "v", .type = .int } }, &.{
        &.{ i(1), t("x"), i(1) }, &.{ i(2), t("y"), i(2) }, &.{ i(3), t("z"), i(3) }, &.{ i(3), t("w"), i(4) },
    });
    const r = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "b", .type = .int }, .{ .name = "v", .type = .int } }, &.{
        &.{ i(3), i(10), i(7) }, &.{ i(4), i(20), i(8) }, &.{ i(3), i(30), i(9) },
    });
    return .{ .l = l, .r = r };
}

test "join indicator and two-sided suffixes (W2-4)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const s = try joinSides(a);
    const j = try df.join(a, s.l, s.r, .{ .on = "k", .how = .full, .suffix = "_y", .left_suffix = "_x", .indicator = "_merge" });
    var names: [6][]const u8 = undefined;
    for (j.columns, 0..) |c, ix| names[ix] = c.name;
    try testing.expectEqualDeep([6][]const u8{ "k", "a", "v_x", "b", "v_y", "_merge" }, names);
    try expectCol(j, "_merge", &.{ t("left_only"), t("left_only"), t("both"), t("both"), t("both"), t("both"), t("right_only") });
    try expectCol(j, "k", &.{ i(1), i(2), i(3), i(3), i(3), i(3), nul });
    // Only the left half: the right keeps its name.
    const l = try df.join(a, s.l, s.r, .{ .on = "k", .how = .left, .left_suffix = "_l" });
    try testing.expectEqualStrings("v_l", l.columns[2].name);
    try testing.expectEqualStrings("v", l.columns[4].name);
    const lm = try df.join(a, s.l, s.r, .{ .on = "k", .how = .inner, .indicator = "m" });
    try expectCol(lm, "m", &.{ t("both"), t("both"), t("both"), t("both") });
    const rr = try df.join(a, s.l, s.r, .{ .on = "k", .how = .right, .indicator = "m" });
    try expectCol(rr, "m", &.{ t("both"), t("both"), t("right_only"), t("both"), t("both") });
}

test "join validate (W2-4)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const s = try joinSides(a);
    // left has two 3s, right has two 3s.
    try testing.expectError(error.ValidationFailed, df.join(a, s.l, s.r, .{ .on = "k", .validate = .many_to_one }));
    try testing.expectError(error.ValidationFailed, df.join(a, s.l, s.r, .{ .on = "k", .validate = .one_to_many }));
    try testing.expectError(error.ValidationFailed, df.join(a, s.l, s.r, .{ .on = "k", .validate = .one_to_one }));
    _ = try df.join(a, s.l, s.r, .{ .on = "k", .validate = .many_to_many });
    const u = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "z", .type = .int } }, &.{ &.{ i(1), i(1) }, &.{ i(3), i(3) } });
    _ = try df.join(a, s.l, u, .{ .on = "k", .validate = .many_to_one });
    try testing.expectError(error.ValidationFailed, df.join(a, s.l, u, .{ .on = "k", .validate = .one_to_one }));
    _ = try df.join(a, u, u, .{ .on = "k", .validate = .one_to_one });
}

test "join on defaults to the common columns; sort orders by the key (W2-4)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const l = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "a", .type = .int } }, &.{ &.{ i(3), i(30) }, &.{ i(1), i(10) } });
    const r = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "b", .type = .int } }, &.{ &.{ i(2), i(20) }, &.{ i(3), i(33) } });
    const inner = try df.join(a, l, r, .{});
    try expectCol(inner, "k", &.{i(3)});
    try expectCol(inner, "b", &.{i(33)});
    const full = try df.join(a, l, r, .{ .how = .full, .sort = true });
    try expectCol(full, "k", &.{ i(1), i(2), i(3) });
    try expectCol(full, "a", &.{ i(10), nul, i(30) });
    try expectCol(full, "b", &.{ nul, i(20), i(33) });
    const none = try mk(a, &.{.{ .name = "q", .type = .int }}, &.{&.{i(1)}});
    try testing.expectError(error.NoSuchColumn, df.join(a, l, none, .{}));
}

test "join keeps both key columns with keep_right_keys (polars coalesce=False) (W2-4)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const s = try joinSides(a);
    const j = try df.join(a, s.l, s.r, .{ .on = "k", .how = .full, .keep_right_keys = true });
    var names: [6][]const u8 = undefined;
    for (j.columns, 0..) |c, ix| names[ix] = c.name;
    try testing.expectEqualDeep([6][]const u8{ "k", "a", "v", "k_right", "b", "v_right" }, names);
    try expectCol(j, "k", &.{ i(1), i(2), i(3), i(3), i(3), i(3), nul });
    try expectCol(j, "k_right", &.{ nul, nul, i(3), i(3), i(3), i(3), i(4) });
}

// ── sort ────────────────────────────────────────────────────────────────────

test "sort places missing cells per key (W2-5)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try mk(a, &.{ .{ .name = "id", .type = .int }, .{ .name = "a", .type = .float }, .{ .name = "b", .type = .float } }, &.{
        &.{ i(0), fl(1), nul }, &.{ i(1), nul, fl(5) }, &.{ i(2), fl(1), fl(2) }, &.{ i(3), nul, fl(1) },
    });
    const s = try df.sort(a, f, .{ .key = "a", .missing = .first, .then_by = &.{.{ .key = "b", .missing = .last }} });
    try expectCol(s, "id", &.{ i(3), i(1), i(2), i(0) });
    const d = try df.sort(a, f, .{ .key = "a", .missing = .last, .then_by = &.{.{ .key = "b", .dir = .desc, .missing = .first }} });
    try expectCol(d, "id", &.{ i(0), i(2), i(1), i(3) });
    const g = try df.argSort(a, f, .{ .key = "a", .missing = .first, .then_by = &.{.{ .key = "b", .missing = .last }} });
    try testing.expectEqualSlices(u32, &.{ 3, 1, 2, 0 }, g);
}

fn lower(_: void, al: std.mem.Allocator, v: Value) !Value {
    const x = switch (v) {
        .text => |s| s,
        else => return v,
    };
    const out = try al.alloc(u8, x.len);
    for (out, x) |*o, c| o.* = std.ascii.toLower(c);
    return .{ .text = out };
}

test "sortByKey orders by a function of the cell (W2-5)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try mk(a, &.{ .{ .name = "s", .type = .text }, .{ .name = "n", .type = .int } }, &.{
        &.{ t("b"), i(0) }, &.{ t("A"), i(1) }, &.{ t("c"), i(2) }, &.{ t("B"), i(3) },
    });
    const r = try df.sortByKey(a, f, .{ .key = "s" }, {}, lower);
    try testing.expectEqual(@as(usize, 2), r.columns.len);
    try expectCol(r, "s", &.{ t("A"), t("b"), t("B"), t("c") });
    try expectCol(r, "n", &.{ i(1), i(0), i(3), i(2) });
    const d = try df.sortByKey(a, f, .{ .key = "s", .dir = .desc }, {}, lower);
    try expectCol(d, "n", &.{ i(2), i(0), i(3), i(1) });
}
