// SPDX-License-Identifier: MIT
//! The LOW items of SPEC § Backlog closed by the 2026-11-10 triage (the S2 review and
//! sweep bullets of 2026-11-09/10): each test names its bullet as "(<file> <letter>)".

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;

test "table JSON: a field that is not an object is skipped, not read as the closing bracket (jsonread a)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"schema":{"fields":[1,{"name":"ts","type":"datetime","tz":"Europe/Prague"},"x"],"primaryKey":[]},"data":[{"ts":"2024-07-15T10:00:00.000Z"}]}
    ;
    const f = try df.readJson(a, doc, .{ .orient = .table, .parse_dates = true });
    try testing.expectEqualStrings("Europe/Prague", f.columns[0].time_zone.?);
    const plain =
        \\{"schema":{"fields":[1]},"data":[{"a":1}]}
    ;
    const g = try df.readJson(a, plain, .{ .orient = .table });
    try testing.expectEqual(@as(usize, 1), g.len);
}

const st = @import("structure_test.zig");

fn i(x: i64) Value {
    return .{ .int = x };
}

test "describe: a percentile of -0.0 is labelled 0% (more a)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "n", .type = .int }}, &.{ &.{i(1)}, &.{i(2)} });
    const d = try df.describeWith(a, f, .{ .percentiles = &.{ -0.0, 0.5 } });
    try st.expectCol(d, "statistic", &.{ .{ .text = "count" }, .{ .text = "mean" }, .{ .text = "std" }, .{ .text = "min" }, .{ .text = "0%" }, .{ .text = "50%" }, .{ .text = "max" } });
}

test "describe: two columns of one name are each described, not the first twice (more f)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "x", .type = .int } }, &.{
        &.{ i(1), i(10) }, &.{ i(3), i(30) },
    });
    const d = try df.describeWith(a, f, .{});
    try testing.expectEqual(@as(usize, 3), d.columns.len);
    // row 1 is `mean`
    try testing.expectEqual(@as(f64, 2), d.columnAt(1).get(1).float);
    try testing.expectEqual(@as(f64, 20), d.columnAt(2).get(1).float);
}

test "CSV of a zoned column keeps the seconds of an offset (textio g)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Africa/Monrovia kept -00:44:30 until 1972-01-07; 1971-01-01T00:00:00Z.
    const us: i64 = 31_536_000 * 1_000_000;
    const cols = try a.dupe(Column, &.{.{ .name = "ts", .type = .timestamp, .time_zone = "Africa/Monrovia" }});
    const data = try a.alloc(df.ColumnData, 1);
    data[0] = try df.columnFromCells(a, &.{.{ .int = us }});
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    var w: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &w.writer, f, .{});
    try testing.expectEqualStrings("ts\n1970-12-31 23:15:30-00:44:30\n", w.written());
    // RFC 3339 has no seconds in an offset: the JSON writer cuts them.
    var j: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&j.writer, f, .records);
    try testing.expect(std.mem.find(u8, j.written(), "-00:44") != null);
}
