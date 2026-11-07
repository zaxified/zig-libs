// SPDX-License-Identifier: MIT
//! `frameops.zig` on hand-built tables: frame arithmetic, `compare`, `dot`,
//! `interpolate`, `groupByDynamic`, `upsample`. Expected cells from pandas' and polars'
//! documented behaviour (not run here).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
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
fn ts(s: []const u8) Value {
    return .{ .int = df.parseIsoTimestamp(s).? };
}

test "arith between frames and with a scalar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .float } }, &.{ &.{ i(1), fl(1.5) }, &.{ i(2), .null } });
    const g = try mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "c", .type = .int } }, &.{ &.{ i(10), i(1) }, &.{ i(20), .null }, &.{ i(30), .null } });
    const s = try df.arith(a, f, g, .add, .{});
    try testing.expectEqual(@as(usize, 3), s.columns.len);
    try testing.expectEqual(df.ColumnType.int, s.columns[0].type);
    try expectCol(s, "a", &.{ i(11), i(22), .null });
    try expectCol(s, "b", &.{ .null, .null, .null });
    try expectCol(s, "c", &.{ .null, .null, .null });
    const z = try df.arith(a, f, g, .add, .{ .fill_value = i(0) });
    try expectCol(z, "a", &.{ i(11), i(22), i(30) });
    try expectCol(z, "b", &.{ fl(1.5), .null, .null });
    try expectCol(z, "c", &.{ i(1), .null, .null });
    const d = try df.arith(a, f, g, .div, .{});
    try testing.expectEqual(df.ColumnType.float, d.columns[0].type);
    try expectCol(d, "a", &.{ fl(0.1), fl(0.1), .null });
    try testing.expectError(error.BadArgument, df.arith(a, f, g, .eq, .{}));

    const h = try mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "t", .type = .text } }, &.{ &.{ i(1), t("x") }, &.{ i(2), t("y") } });
    const m = try df.arithScalar(a, h, .mul, i(2), .{});
    try expectCol(m, "a", &.{ i(2), i(4) });
    try expectCol(m, "t", &.{ t("x"), t("y") });
    try expectCol(try df.arithScalar(a, h, .sub, i(10), .{ .reverse = true }), "a", &.{ i(9), i(8) });
}

test "compare and dot" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols: []const df.Column = &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text } };
    const f = try mk(a, cols, &.{ &.{ i(1), t("x") }, &.{ i(2), t("y") }, &.{ i(3), t("z") } });
    const g = try mk(a, cols, &.{ &.{ i(1), t("x") }, &.{ i(5), t("y") }, &.{ i(3), t("w") } });
    const c = try df.compare(a, f, g);
    try testing.expectEqual(@as(usize, 5), c.columns.len);
    try expectCol(c, "row", &.{ i(1), i(2) });
    try expectCol(c, "a_self", &.{ i(2), .null });
    try expectCol(c, "a_other", &.{ i(5), .null });
    try expectCol(c, "b_self", &.{ .null, t("z") });
    try expectCol(c, "b_other", &.{ .null, t("w") });
    try testing.expectEqual(@as(usize, 0), (try df.compare(a, f, f)).len);
    try testing.expectError(error.SchemaMismatch, df.compare(a, f, try df.reverse(a, try df.take(a, f, &.{0}))));

    const p = try mk(a, &.{ .{ .name = "p", .type = .int }, .{ .name = "q", .type = .int } }, &.{ &.{ i(1), i(2) }, &.{ i(3), i(4) } });
    const q = try mk(a, &.{.{ .name = "r", .type = .int }}, &.{ &.{i(5)}, &.{i(6)} });
    try expectCol(try df.dot(a, p, q), "r", &.{ fl(17), fl(39) });
    try testing.expectError(error.SchemaMismatch, df.dot(a, p, try df.take(a, q, &.{0})));
}

test "interpolate: linear and nearest, by position or by a column" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{.{ .name = "y", .type = .int }}, &.{ &.{i(1)}, &.{.null}, &.{i(3)}, &.{.null} });
    try expectCol(try df.interpolate(a, f, .{ .col = "y" }), "y", &.{ fl(1), fl(2), fl(3), .null });
    const n = try mk(a, &.{.{ .name = "y", .type = .int }}, &.{ &.{i(1)}, &.{.null}, &.{.null}, &.{i(4)} });
    try expectCol(try df.interpolate(a, n, .{ .col = "y", .method = .nearest, .out = "z" }), "z", &.{ fl(1), fl(1), fl(4), fl(4) });
    const b = try mk(a, &.{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } }, &.{ &.{ fl(0), fl(0) }, &.{ fl(1), .null }, &.{ fl(10), fl(10) }, &.{ .null, .null } });
    try expectCol(try df.interpolate(a, b, .{ .col = "y", .by = "x" }), "y", &.{ fl(0), fl(1), fl(10), .null });
    const tm = try mk(a, &.{ .{ .name = "t", .type = .timestamp }, .{ .name = "y", .type = .float } }, &.{
        &.{ ts("2024-01-01T00:00:00Z"), fl(0) },
        &.{ ts("2024-01-01T06:00:00Z"), .null },
        &.{ ts("2024-01-02T00:00:00Z"), fl(4) },
    });
    try expectCol(try df.interpolate(a, tm, .{ .col = "y", .by = "t" }), "y", &.{ fl(0), fl(1), fl(4) });
}

test "groupByDynamic and upsample" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "t", .type = .timestamp }, .{ .name = "k", .type = .text }, .{ .name = "v", .type = .int } }, &.{
        &.{ ts("2024-01-01T00:10:00Z"), t("a"), i(1) },
        &.{ ts("2024-01-01T00:50:00Z"), t("b"), i(2) },
        &.{ ts("2024-01-01T01:05:00Z"), t("a"), i(3) },
        &.{ ts("2024-01-01T02:30:00Z"), t("a"), i(4) },
        &.{ .null, t("a"), i(100) },
    });
    const g = try df.groupByDynamic(a, f, .{ .index = "t", .every = "1h", .aggs = &.{.{ .src = "v", .out = "s", .func = .sum }} });
    try expectCol(g, "t", &.{ ts("2024-01-01T00:00:00Z"), ts("2024-01-01T01:00:00Z"), ts("2024-01-01T02:00:00Z") });
    try expectCol(g, "s", &.{ fl(3), fl(3), fl(4) });
    const gb = try df.groupByDynamic(a, f, .{ .index = "t", .every = "2h", .by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "n", .func = .count }} });
    try expectCol(gb, "k", &.{ t("a"), t("a"), t("b") });
    try expectCol(gb, "t", &.{ ts("2024-01-01T00:00:00Z"), ts("2024-01-01T02:00:00Z"), ts("2024-01-01T00:00:00Z") });
    try testing.expectError(error.BadArgument, df.groupByDynamic(a, f, .{ .index = "t", .every = "1mo1d", .aggs = &.{} }));

    const d = try mk(a, &.{ .{ .name = "day", .type = .date }, .{ .name = "v", .type = .int } }, &.{ &.{ t("2024-01-03"), i(3) }, &.{ t("2024-01-01"), i(1) }, &.{ t("2024-01-02T12:00"), i(9) } });
    const u = try df.upsample(a, d, .{ .time = "day", .every = "1d" });
    try expectCol(u, "day", &.{ t("2024-01-01"), t("2024-01-02"), t("2024-01-03") });
    try expectCol(u, "v", &.{ i(1), .null, i(3) });
    const m = try df.upsample(a, try mk(a, &.{.{ .name = "t", .type = .timestamp }}, &.{ &.{ts("2024-01-31T00:00:00Z")}, &.{ts("2024-03-31T00:00:00Z")} }), .{ .time = "t", .every = "1mo" });
    try expectCol(m, "t", &.{ ts("2024-01-31T00:00:00Z"), ts("2024-02-29T00:00:00Z"), ts("2024-03-31T00:00:00Z") });
    try testing.expectError(error.BadArgument, df.upsample(a, d, .{ .time = "day", .every = "-1d" }));
}
