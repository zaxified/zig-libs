// SPDX-License-Identifier: MIT
//! dataframe parity close (2026-11-10): `jsonDecode` (polars `str.json_decode`, survey row 97).
//! Expected values are polars 2.1's documented `json_decode` example and hand-checked cases;
//! the inference rules are `readNdjson`'s (`jsonread_test.zig` covers them in depth).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const Column = df.Column;

fn textFrame(a: std.mem.Allocator, cells: []const ?[]const u8) !Frame {
    const vals = try a.alloc(Value, cells.len);
    for (vals, cells) |*v, c| v.* = if (c) |t| .{ .text = t } else .null;
    const cols = try a.dupe(Column, &.{ .{ .name = "j", .type = .text }, .{ .name = "k", .type = .int } });
    const ks = try a.alloc(Value, cells.len);
    for (ks, 0..) |*v, i| v.* = .{ .int = @intCast(i) };
    const data = try a.dupe(df.ColumnData, &.{ try df.columnFromCells(a, vals), try df.columnFromCells(a, ks) });
    return .{ .columns = cols, .data = data, .len = cells.len };
}

test "jsonDecode: polars' documented example, objects to a struct" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // polars docs: ['{"a":1, "b": true}', None, '{"a":2, "b": false}'] -> struct{a: i64, b: bool}
    const f = try textFrame(a, &.{ "{\"a\":1, \"b\": true}", null, "{\"a\":2, \"b\": false}" });
    const g = try df.jsonDecode(a, f, .{ .column = "j" });
    try testing.expectEqual(@as(usize, 2), g.columns.len);
    try testing.expectEqual(df.ColumnType.@"struct", g.columnType("j").?);
    try testing.expectEqual(@as(usize, 2), g.columns[0].inner.len);
    try testing.expectEqualStrings("a", g.columns[0].inner[0].name);
    try testing.expectEqual(df.ColumnType.int, g.columns[0].inner[0].type);
    try testing.expectEqual(df.ColumnType.bool, g.columns[0].inner[1].type);
    const r0 = g.cell(0, "j").?.record;
    try testing.expectEqual(@as(i64, 1), r0.field("a").?.int);
    try testing.expectEqual(true, r0.field("b").?.bool);
    try testing.expect(g.cell(1, "j").? == .null);
    try testing.expectEqual(@as(i64, 2), g.cell(2, "j").?.record.field("a").?.int);
    // The other column is untouched.
    try testing.expectEqual(@as(i64, 2), g.cell(2, "k").?.int);
}

test "jsonDecode: the schema is inferred over every row, missing keys null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try textFrame(a, &.{ "{\"a\":1}", "{\"b\":\"x\",\"a\":2.5}", "null" });
    const g = try df.jsonDecode(a, f, .{ .column = "j", .out = "d" });
    try testing.expectEqual(@as(usize, 3), g.columns.len);
    try testing.expectEqualStrings("d", g.columns[2].name);
    try testing.expectEqual(df.ColumnType.text, g.columnType("j").?); // the source stays
    const inner = g.columns[2].inner;
    try testing.expectEqual(@as(usize, 2), inner.len);
    try testing.expectEqual(df.ColumnType.float, inner[0].type); // 1 and 2.5
    try testing.expectEqual(df.ColumnType.text, inner[1].type);
    try testing.expect(g.cell(0, "d").?.record.field("b").? == .null);
    try testing.expectEqual(@as(f64, 1), g.cell(0, "d").?.record.field("a").?.float);
    try testing.expect(g.cell(2, "d").? == .null); // JSON null
}

test "jsonDecode: arrays, scalars, mixed kinds, dtype" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    {
        const g = try df.jsonDecode(a, try textFrame(a, &.{ "[1,2,3]", " [] ", null }), .{ .column = "j" });
        try testing.expectEqual(df.ColumnType.list, g.columnType("j").?);
        try testing.expectEqual(df.ColumnType.int, g.columns[0].inner[0].type);
        try testing.expectEqual(@as(usize, 3), g.cell(0, "j").?.list.len());
        try testing.expectEqual(@as(i64, 3), g.cell(0, "j").?.list.get(2).int);
        try testing.expectEqual(@as(usize, 0), g.cell(1, "j").?.list.len());
    }
    {
        const g = try df.jsonDecode(a, try textFrame(a, &.{ "7", "-2" }), .{ .column = "j" });
        try testing.expectEqual(df.ColumnType.int, g.columnType("j").?);
        try testing.expectEqual(@as(i64, -2), g.cell(1, "j").?.int);
    }
    {
        // A number and an object: text, each cell in its source form (module doc).
        const g = try df.jsonDecode(a, try textFrame(a, &.{ "1", "{\"a\":1}", "\"s\"" }), .{ .column = "j" });
        try testing.expectEqual(df.ColumnType.text, g.columnType("j").?);
        try testing.expectEqualStrings("{\"a\":1}", g.cell(1, "j").?.text);
        try testing.expectEqualStrings("s", g.cell(2, "j").?.text);
    }
    {
        // dtype: a width, its storage narrow; out of range refused.
        const g = try df.jsonDecode(a, try textFrame(a, &.{ "7", null, "-2" }), .{ .column = "j", .type = .int8 });
        try testing.expectEqual(df.ColumnType.int8, g.columnType("j").?);
        try testing.expect(g.columnAt(0) == .int8);
        try testing.expectError(error.BadValue, df.jsonDecode(a, try textFrame(a, &.{"300"}), .{ .column = "j", .type = .int8 }));
        // Nested values kept as their text.
        const h = try df.jsonDecode(a, try textFrame(a, &.{ "{\"a\":1}", "[2]" }), .{ .column = "j", .type = .text });
        try testing.expectEqualStrings("[2]", h.cell(1, "j").?.text);
        // parse_dates.
        const d = try df.jsonDecode(a, try textFrame(a, &.{ "\"2026-11-10\"", null }), .{ .column = "j", .parse_dates = true });
        try testing.expectEqual(df.ColumnType.date, d.columnType("j").?);
    }
}

test "jsonDecode: refusals" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bad = [_][]const u8{ "", "  ", "{", "1 2", "[1,]", "{\"a\":1}x", "nul", "\"\xff\"", "{\"a\":1,\"a\":2}" };
    for (bad) |s| try testing.expectError(error.BadJson, df.jsonDecode(a, try textFrame(a, &.{s}), .{ .column = "j" }));
    // `.last` keeps a repeated key's last value.
    const g = try df.jsonDecode(a, try textFrame(a, &.{"{\"a\":1,\"a\":2}"}), .{ .column = "j", .duplicate_keys = .last });
    try testing.expectEqual(@as(i64, 2), g.cell(0, "j").?.record.field("a").?.int);
    const f = try textFrame(a, &.{"1"});
    try testing.expectError(error.NoSuchColumn, df.jsonDecode(a, f, .{ .column = "nope" }));
    try testing.expectError(error.BadValue, df.jsonDecode(a, f, .{ .column = "k" })); // not text
    // Limits: a long value, many key paths, many cells, deep nesting (text past the depth).
    try testing.expectError(error.CellTooLarge, df.jsonDecode(a, try textFrame(a, &.{"\"abcdef\""}), .{ .column = "j", .max_cell_bytes = 4 }));
    try testing.expectError(error.TooManyColumns, df.jsonDecode(a, try textFrame(a, &.{"{\"a\":1,\"b\":2,\"c\":3}"}), .{ .column = "j", .max_columns = 2 }));
    try testing.expectError(error.TooManyCells, df.jsonDecode(a, try textFrame(a, &.{ "[1,2,3]", "[4,5]" }), .{ .column = "j", .max_cells = 4 }));
    const deep: [400]u8 = @as([200]u8, @splat('[')) ++ @as([200]u8, @splat(']'));
    const d = try df.jsonDecode(a, try textFrame(a, &.{&deep}), .{ .column = "j" });
    try testing.expectEqual(df.ColumnType.list, d.columnType("j").?);
    // An empty frame decodes to an all-null text column.
    const e = try df.jsonDecode(a, try textFrame(a, &.{}), .{ .column = "j" });
    try testing.expectEqual(@as(usize, 0), e.len);
}
