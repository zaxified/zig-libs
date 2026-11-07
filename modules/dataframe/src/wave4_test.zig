// SPDX-License-Identifier: MIT
//! D2's fourth wave: the window functions past the first eight, `reshape.zig` and
//! `seriesfn.zig`, on hand-built tables. Expected cells from pandas' and polars'
//! documented behaviour (not run here); the rolling moments are checked against
//! `aggregate` over the same values, the one formula for both.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;
const mk = st.mk;
const expectCol = st.expectCol;

fn col1(a: std.mem.Allocator, name: []const u8, ty: df.ColumnType, xs: []const Value) !Frame {
    const rows = try a.alloc([]const Value, xs.len);
    for (rows, xs) |*r, x| r.* = try a.dupe(Value, &.{x});
    return mk(a, try a.dupe(Column, &.{.{ .name = name, .type = ty }}), rows);
}

fn i(x: i64) Value {
    return .{ .int = x };
}
fn fl(x: f64) Value {
    return .{ .float = x };
}
fn t(x: []const u8) Value {
    return .{ .text = x };
}

fn win(a: std.mem.Allocator, f: Frame, op: df.WindowOp) !Frame {
    return df.window(a, f, .{ .value_col = "x", .out = "r", .op = op });
}

test "window functions past the first eight" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try col1(a, "x", .int, &.{ i(1), i(2), i(4), i(8) });
    try expectCol(try win(a, f, .{ .rolling = .{ .window = 3, .func = .prod } }), "r", &.{ .null, .null, fl(8), fl(64) });
    try expectCol(try win(a, f, .{ .rolling = .{ .window = 3, .func = .quantile, .q = 0.5 } }), "r", &.{ .null, .null, fl(2), fl(4) });
    try expectCol(try win(a, f, .{ .rolling = .{ .window = 2, .func = .std, .ddof = 0 } }), "r", &.{ .null, fl(0.5), fl(1), fl(2) });
    try expectCol(try win(a, f, .{ .expanding = .{ .func = .prod } }), "r", &.{ fl(1), fl(2), fl(8), fl(64) });
    try expectCol(try win(a, f, .{ .expanding = .{ .func = .last } }), "r", &.{ fl(1), fl(2), fl(4), fl(8) });

    // skew / kurt / sem: the window's value is `aggregate`'s over the same cells.
    const agg = try df.aggregate(a, f, .{ .group_by = &.{}, .aggs = &.{
        .{ .src = "x", .out = "skew", .func = .skew },
        .{ .src = "x", .out = "kurt", .func = .kurt },
        .{ .src = "x", .out = "sem", .func = .sem },
    }, .skip_na = true });
    const r_skew = try win(a, f, .{ .rolling = .{ .window = 4, .func = .skew } });
    const r_kurt = try win(a, f, .{ .rolling = .{ .window = 4, .func = .kurt } });
    const r_sem = try win(a, f, .{ .expanding = .{ .func = .sem } });
    try testing.expectApproxEqAbs(agg.cell(0, "skew").?.float, r_skew.cell(3, "r").?.float, 1e-12);
    try testing.expectApproxEqAbs(agg.cell(0, "kurt").?.float, r_kurt.cell(3, "r").?.float, 1e-12);
    try testing.expectApproxEqAbs(agg.cell(0, "sem").?.float, r_sem.cell(3, "r").?.float, 1e-12);
    try testing.expect(r_skew.cell(2, "r").? == .null);

    const g = try col1(a, "x", .float, &.{ fl(1), .null, fl(3), fl(3) });
    try expectCol(try win(a, g, .{ .rolling = .{ .window = 2, .func = .first, .min_periods = 1 } }), "r", &.{ fl(1), fl(1), fl(3), fl(3) });
    try expectCol(try win(a, g, .{ .rolling = .{ .window = 2, .func = .last, .min_periods = 1 } }), "r", &.{ fl(1), fl(1), fl(3), fl(3) });
    try expectCol(try win(a, g, .{ .rolling = .{ .window = 3, .func = .nunique, .min_periods = 1 } }), "r", &.{ fl(1), fl(1), fl(2), fl(1) });
}

test "groupFilter and ngroup" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "k", .type = .text }, .{ .name = "v", .type = .int } }, &.{
        &.{ t("b"), i(1) }, &.{ t("a"), i(2) }, &.{ t("b"), i(3) }, &.{ .null, i(4) }, &.{ t("b"), i(5) },
    });
    const big = try df.groupFilter(a, f, .{ .by = &.{"k"}, .agg = .{ .src = "v", .out = "s", .func = .sum }, .op = .gt, .value = i(5) });
    try expectCol(big, "v", &.{ i(1), i(3), i(5) });
    const many = try df.groupFilter(a, f, .{ .by = &.{"k"}, .agg = .{ .src = "v", .out = "s", .func = .size }, .op = .lt, .value = i(2) });
    try expectCol(many, "v", &.{ i(2), i(4) });
    try expectCol(try df.ngroup(a, f, .{ .by = &.{"k"} }), "ngroup", &.{ i(1), i(0), i(1), .null, i(1) });
    try expectCol(try df.ngroup(a, f, .{ .by = &.{"k"}, .sort = false }), "ngroup", &.{ i(0), i(1), i(0), .null, i(0) });
}

test "joinWhere, mergeOrdered, mergeSorted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try mk(a, &.{ .{ .name = "t", .type = .int }, .{ .name = "id", .type = .int } }, &.{ &.{ i(1), i(0) }, &.{ i(5), i(1) }, &.{ i(10), i(2) }, &.{ .null, i(3) } });
    const r = try mk(a, &.{ .{ .name = "lo", .type = .int }, .{ .name = "hi", .type = .int }, .{ .name = "id", .type = .int } }, &.{ &.{ i(0), i(3), i(7) }, &.{ i(4), i(8), i(8) } });
    const j = try df.joinWhere(a, l, r, &.{ .{ .left = "t", .op = .ge, .right = "lo" }, .{ .left = "t", .op = .le, .right = "hi" } }, "_right");
    try expectCol(j, "id", &.{ i(0), i(1) });
    try expectCol(j, "id_right", &.{ i(7), i(8) });
    try testing.expectError(error.BadArgument, df.joinWhere(a, l, r, &.{.{ .left = "t", .op = .is_null, .right = "lo" }}, "_right"));

    const x = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "a", .type = .int } }, &.{ &.{ i(3), i(30) }, &.{ i(1), i(10) } });
    const y = try mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "b", .type = .int } }, &.{ &.{ i(2), i(20) }, &.{ i(3), i(31) } });
    const m = try df.mergeOrdered(a, x, y, .{ .on = &.{"k"} });
    try expectCol(m, "k", &.{ i(1), i(2), i(3) });
    try expectCol(m, "a", &.{ i(10), .null, i(30) });
    try expectCol(m, "b", &.{ .null, i(20), i(31) });
    const mf = try df.mergeOrdered(a, x, y, .{ .on = &.{"k"}, .fill_forward = true });
    try expectCol(mf, "a", &.{ i(10), i(10), i(30) });

    const s1 = try col1(a, "k", .int, &.{ i(1), i(3) });
    const s2 = try col1(a, "k", .int, &.{ i(2), i(4) });
    try expectCol(try df.mergeSorted(a, s1, s2, "k"), "k", &.{ i(1), i(2), i(3), i(4) });
}

test "pivotMany and dummies" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "r", .type = .text }, .{ .name = "c", .type = .text }, .{ .name = "v1", .type = .int }, .{ .name = "v2", .type = .int } }, &.{
        &.{ t("x"), t("p"), i(1), i(10) }, &.{ t("x"), t("q"), i(2), i(20) }, &.{ t("y"), t("p"), i(3), i(30) },
    });
    const p = try df.pivotMany(a, f, .{ .row_key = "r", .col_key = "c", .values = &.{ "v1", "v2" }, .skip_na = true });
    try testing.expectEqual(@as(usize, 5), p.columns.len);
    try expectCol(p, "r", &.{ t("x"), t("y") });
    try expectCol(p, "v1_p", &.{ fl(1), fl(3) });
    try expectCol(p, "v1_q", &.{ fl(2), .null });
    try expectCol(p, "v2_p", &.{ fl(10), fl(30) });
    try expectCol(p, "v2_q", &.{ fl(20), .null });

    const k = try mk(a, &.{ .{ .name = "r1", .type = .text }, .{ .name = "r2", .type = .int }, .{ .name = "c1", .type = .text }, .{ .name = "c2", .type = .int }, .{ .name = "v", .type = .int } }, &.{
        &.{ t("x"), i(1), t("p"), i(0), i(1) },
        &.{ t("x"), i(1), t("p"), i(1), i(2) },
        &.{ t("x"), i(2), t("p"), i(0), i(3) },
        &.{ t("x"), i(1), t("p"), i(0), i(4) },
        &.{ .null, i(1), t("p"), i(0), i(5) },
    });
    const pk = try df.pivotKeys(a, k, .{ .row_keys = &.{ "r1", "r2" }, .col_keys = &.{ "c1", "c2" }, .values = &.{"v"}, .skip_na = true });
    try testing.expectEqual(@as(usize, 4), pk.columns.len);
    try expectCol(pk, "r1", &.{ t("x"), t("x"), .null });
    try expectCol(pk, "r2", &.{ i(1), i(2), .null });
    try expectCol(pk, "v_p_0", &.{ fl(5), fl(3), fl(5) });
    try expectCol(pk, "v_p_1", &.{ fl(2), .null, .null });

    const d = try mk(a, &.{ .{ .name = "n", .type = .int }, .{ .name = "c", .type = .text } }, &.{ &.{ i(1), t("b") }, &.{ i(2), t("a") }, &.{ i(3), .null }, &.{ i(4), t("b") } });
    const dd = try df.dummies(a, d, .{});
    try testing.expectEqual(@as(usize, 3), dd.columns.len);
    try testing.expectEqualStrings("n", dd.columns[0].name);
    try expectCol(dd, "c_a", &.{ i(0), i(1), i(0), i(0) });
    try expectCol(dd, "c_b", &.{ i(1), i(0), i(0), i(1) });
    const df1 = try df.dummies(a, d, .{ .drop_first = true, .dummy_na = true });
    try testing.expect(df1.columnIndex("c_a") == null);
    try expectCol(df1, "c_null", &.{ i(0), i(0), i(1), i(0) });
}

test "combineFirst, update, repeatRows, scatter, dropNans" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try col1(a, "x", .int, &.{ i(1), .null });
    const g = try mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{ &.{ i(9), i(5) }, &.{ i(8), i(6) }, &.{ i(7), i(7) } });
    const c = try df.combineFirst(a, f, g);
    try expectCol(c, "x", &.{ i(1), i(8), i(7) });
    try expectCol(c, "y", &.{ i(5), i(6), i(7) });
    const u = try df.update(a, try col1(a, "x", .int, &.{ i(1), i(2), i(3) }), try col1(a, "x", .int, &.{ .null, i(20) }));
    try expectCol(u, "x", &.{ i(1), i(20), i(3) });

    const r = try mk(a, &.{ .{ .name = "v", .type = .int }, .{ .name = "n", .type = .int } }, &.{ &.{ i(1), i(0) }, &.{ i(2), i(2) }, &.{ i(3), .null } });
    try expectCol(try df.repeatRows(a, r, .{ .times = 2 }), "v", &.{ i(1), i(1), i(2), i(2), i(3), i(3) });
    try expectCol(try df.repeatRows(a, r, .{ .by = "n" }), "v", &.{ i(2), i(2) });
    const neg = try col1(a, "n", .int, &.{i(-1)});
    try testing.expectError(error.BadArgument, df.repeatRows(a, neg, .{ .by = "n" }));
    try testing.expectError(error.TooLarge, df.repeatRows(a, r, .{ .times = 1 << 40 }));

    const s = try df.scatter(a, r, .{ .col = "v", .idx = &.{ -1, 0 }, .values = &.{i(9)} });
    try expectCol(s, "v", &.{ i(9), i(2), i(9) });
    try testing.expectError(error.IndexOutOfBounds, df.scatter(a, r, .{ .col = "v", .idx = &.{3}, .values = &.{i(9)} }));
    try testing.expectError(error.BadArgument, df.scatter(a, r, .{ .col = "v", .idx = &.{ 0, 1 }, .values = &.{ i(9), i(8), i(7) } }));

    const n = try col1(a, "x", .float, &.{ fl(1), fl(std.math.nan(f64)), .null });
    try expectCol(try df.dropNans(a, n, &.{}), "x", &.{ fl(1), .null });
}

test "matchToSchema, toFloatMatrix, hashRows, betweenTime" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text } }, &.{ &.{ i(1), t("x") }, &.{ .null, t("y") } });
    const m = try df.matchToSchema(a, f, &.{ .{ .name = "b", .type = .text }, .{ .name = "a", .type = .int } }, .{});
    try testing.expectEqualStrings("b", m.columns[0].name);
    try expectCol(m, "a", &.{ i(1), .null });
    try testing.expectError(error.SchemaMismatch, df.matchToSchema(a, f, &.{.{ .name = "a", .type = .int }}, .{}));
    const ins = try df.matchToSchema(a, f, &.{ .{ .name = "a", .type = .int }, .{ .name = "c", .type = .float } }, .{ .missing_columns = .insert, .extra_columns = .ignore });
    try expectCol(ins, "c", &.{ .null, .null });
    try testing.expectError(error.SchemaMismatch, df.matchToSchema(a, f, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .text } }, .{}));
    const cast = try df.matchToSchema(a, f, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .text } }, .{ .cast = true });
    try expectCol(cast, "a", &.{ fl(1), .null });
    try testing.expectError(error.CastFailed, df.matchToSchema(a, f, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } }, .{ .cast = true }));

    const mx = try df.toFloatMatrix(a, f, &.{});
    try testing.expectEqual(@as(usize, 2), mx.rows);
    try testing.expectEqual(@as(usize, 2), mx.cols);
    try testing.expectEqual(@as(f64, 1), mx.data[0]);
    try testing.expect(std.math.isNan(mx.data[1]) and std.math.isNan(mx.data[2]) and std.math.isNan(mx.data[3]));

    const h = try mk(a, &.{.{ .name = "v", .type = .float }}, &.{ &.{i(1)}, &.{fl(1)}, &.{fl(2)}, &.{.null}, &.{fl(std.math.nan(f64))} });
    const hr = try df.hashRows(a, h, 7, "h");
    try testing.expectEqual(hr.cell(0, "h").?.int, hr.cell(1, "h").?.int);
    try testing.expect(hr.cell(0, "h").?.int != hr.cell(2, "h").?.int);
    try testing.expectEqual(hr.cell(3, "h").?.int, hr.cell(4, "h").?.int);
    const hr2 = try df.hashRows(a, h, 8, "h");
    try testing.expect(hr.cell(0, "h").?.int != hr2.cell(0, "h").?.int);

    const tt = try col1(a, "ts", .timestamp, &.{
        i(df.parseIsoTimestamp("2024-01-01T09:00:00Z").?),
        i(df.parseIsoTimestamp("2024-01-01T12:00:00Z").?),
        i(df.parseIsoTimestamp("2024-01-02T23:30:00Z").?),
        .null,
    });
    const day = try df.betweenTime(a, tt, .{ .col = "ts", .start = "08:00", .end = "12:00" });
    try testing.expectEqual(@as(usize, 2), day.len);
    const open_hi = try df.betweenTime(a, tt, .{ .col = "ts", .start = "08:00", .end = "12:00", .inclusive = .left });
    try testing.expectEqual(@as(usize, 1), open_hi.len);
    const night = try df.betweenTime(a, tt, .{ .col = "ts", .start = "23:00", .end = "01:00" });
    try testing.expectEqual(@as(usize, 1), night.len);
    try testing.expectError(error.BadArgument, df.betweenTime(a, tt, .{ .col = "ts", .start = "25:00", .end = "01:00" }));
}

test "series functions: rle, peaks, autocorr, entropy, extremes, positions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try col1(a, "x", .int, &.{ i(1), i(1), i(2), .null, .null });
    const r = try df.rle(a, f.series("x").?);
    try expectCol(r, "len", &.{ i(2), i(1), i(2) });
    try expectCol(r, "value", &.{ i(1), i(2), .null });
    try expectCol(try df.rleId(a, f, "x", "id"), "id", &.{ i(0), i(0), i(1), i(2), i(2) });

    const up = try col1(a, "x", .int, &.{ i(1), i(2), i(3), i(4), i(5) });
    try expectCol(try df.peaks(a, up, "x", .max, "p"), "p", &.{ .{ .bool = false }, .{ .bool = false }, .{ .bool = false }, .{ .bool = false }, .{ .bool = true } });
    const v = try col1(a, "x", .int, &.{ i(3), i(1), i(2) });
    try expectCol(try df.peaks(a, v, "x", .min, "p"), "p", &.{ .{ .bool = false }, .{ .bool = true }, .{ .bool = false } });
    try expectCol(try df.peaks(a, v, "x", .max, "p"), "p", &.{ .{ .bool = true }, .{ .bool = false }, .{ .bool = true } });

    try testing.expectApproxEqAbs(@as(f64, 1), df.autocorr(up.series("x").?, 1).?, 1e-12);
    const alt = try col1(a, "x", .int, &.{ i(1), i(-1), i(1), i(-1) });
    try testing.expectApproxEqAbs(@as(f64, -1), df.autocorr(alt.series("x").?, 1).?, 1e-12);
    try testing.expect(df.autocorr(up.series("x").?, 9) == null);
    const two = try col1(a, "x", .int, &.{ i(1), i(1) });
    try testing.expectApproxEqAbs(@as(f64, 1), df.entropy(two.series("x").?, 2, true).?, 1e-12);

    const n = try col1(a, "x", .float, &.{ fl(1), fl(std.math.nan(f64)), fl(3) });
    try testing.expect(std.math.isNan(df.nanExtreme(n.series("x").?, .max).float));
    const nn = try col1(a, "x", .float, &.{ fl(1), .null, fl(3) });
    try testing.expectEqual(@as(f64, 3), df.nanExtreme(nn.series("x").?, .max).float);
    try testing.expectEqual(@as(f64, 1), df.nanExtreme(nn.series("x").?, .min).float);

    const by = try mk(a, &.{ .{ .name = "name", .type = .text }, .{ .name = "s", .type = .int } }, &.{ &.{ t("a"), i(2) }, &.{ t("b"), i(9) }, &.{ t("c"), i(9) }, &.{ t("d"), .null } });
    try testing.expectEqualStrings("b", (try df.extremeBy(by, "name", "s", .max)).text);
    try testing.expectEqualStrings("a", (try df.extremeBy(by, "name", "s", .min)).text);

    const u = try col1(a, "x", .int, &.{ i(1), i(1), .null, i(2) });
    try testing.expectEqual(@as(usize, 2), try df.nUnique(a, u, "x", false));
    try testing.expectEqual(@as(usize, 3), try df.nUnique(a, u, "x", true));
    const fv = try col1(a, "x", .float, &.{ .null, fl(std.math.nan(f64)), fl(3), .null });
    try testing.expectEqual(@as(?usize, 2), df.firstValid(fv.series("x").?));
    try testing.expectEqual(@as(?usize, 2), df.lastValid(fv.series("x").?));
    const b = try col1(a, "x", .bool, &.{ .{ .bool = true }, .{ .bool = false }, .null, .{ .bool = true } });
    try testing.expectEqualSlices(usize, &.{ 0, 3 }, try df.argTrue(a, b.series("x").?));
    const au = try col1(a, "x", .text, &.{ t("a"), t("b"), t("a"), t("c") });
    try testing.expectEqualSlices(usize, &.{ 0, 1, 3 }, try df.argUnique(a, au, "x"));
    const so = try col1(a, "x", .int, &.{ .null, i(1), i(3), i(5) });
    try testing.expectEqual(@as(?usize, 2), df.asofIndex(so.series("x").?, i(4)));
    try testing.expectEqual(@as(?usize, 3), df.asofIndex(so.series("x").?, i(9)));
    try testing.expectEqual(@as(?usize, null), df.asofIndex(so.series("x").?, i(0)));
    const ext = try df.extendConstant(a, so.series("x").?, i(7), 2);
    try testing.expectEqual(@as(usize, 6), ext.len);
    try testing.expectEqual(@as(i64, 7), ext.get(5).int);
    try testing.expect(ext.get(0) == .null);
}
