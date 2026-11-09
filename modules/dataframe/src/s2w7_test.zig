// SPDX-License-Identifier: MIT
//! A time zone carried by a column (dataframe S2 wave W7): the verbs that make and change it
//! (`convert_time_zone`, `replace_time_zone`, a cast to a zoned type), the readers of it (the
//! `dt` parts, `strftime` with `%z`/`%Z`, `truncate`, `group_by_dynamic`) and the text I/O.
//! The engines' answers for the same operations are replayed in `s2w7_oracle_test.zig`;
//! these are the cases around them that no engine can be asked: the values are worked out by
//! hand (Europe/Prague 2024: clocks forward on 31 March at 01:00Z, back on 27 October at 01:00Z).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;
const Expr = df.Expr;

const s_us: i64 = 1_000_000;
const prague = "Europe/Prague";
const X: Expr = .{ .col = "ts" };

fn stamp(text: []const u8) i64 {
    return vm.parseIsoTimestamp(text) orelse unreachable;
}

fn one(a: std.mem.Allocator, zone: ?[]const u8, us: []const i64) !Frame {
    const cells = try a.alloc(Value, us.len);
    for (cells, us) |*c, x| c.* = .{ .int = x };
    const cols = try a.dupe(Column, &.{.{ .name = "ts", .type = .timestamp, .time_zone = zone }});
    const data = try a.alloc(df.ColumnData, 1);
    data[0] = try df.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = us.len };
}

fn eval(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
}

fn cellOf(g: Frame, ri: usize) Value {
    return g.cell(ri, "out").?;
}

fn expectInt(want: i64, got: Value) !void {
    if (got != .int or got.int != want) {
        std.debug.print("got {any}, want {d}\n", .{ got, want });
        return error.TestUnexpectedResult;
    }
}

fn expectText(want: []const u8, got: Value) !void {
    if (got != .text or !std.mem.eql(u8, got.text, want)) {
        std.debug.print("got {any}, want {s}\n", .{ got, want });
        return error.TestUnexpectedResult;
    }
}

test "dt parts of a zoned column read the zone's wall clock, the epoch parts the instant" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 2024-03-30T23:30:00Z is 00:30 on Sunday 31 March in Prague; 2024-07-15T12:00:00Z is 14:00 CEST.
    const f = try one(a, prague, &.{ stamp("2024-03-30T23:30:00Z"), stamp("2024-07-15T12:00:00Z") });
    try expectInt(31, cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .day } }), 0));
    try expectInt(0, cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .hour } }), 0));
    try expectInt(7, cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .weekday } }), 0));
    try expectText("2024-03-31", cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .date } }), 0));
    try expectInt(14, cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .hour } }), 1));
    // the epoch is the instant's own
    try expectInt(@divFloor(stamp("2024-07-15T12:00:00Z"), s_us), cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .epoch_seconds } }), 1));
    // a naive column is UTC wall clock, as before
    const n = try one(a, null, &.{stamp("2024-07-15T12:00:00Z")});
    try expectInt(12, cellOf(try eval(a, n, .{ .dt = .{ .x = &X, .part = .hour } }), 0));
    // month_start keeps the time of day and is an instant again, in the zone: 1 July 14:00 CEST = 12:00Z
    const ms = try eval(a, f, .{ .dt = .{ .x = &X, .part = .month_start } });
    try expectInt(stamp("2024-07-01T12:00:00Z"), cellOf(ms, 1));
    // ... and across the change: 31 March 00:30 CET is 1 March 00:30 CET = 29 February 23:30Z
    try expectInt(stamp("2024-02-29T23:30:00Z"), cellOf(ms, 0));
}

test "strftime of a zoned column: %z, %:z and %Z" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try one(a, prague, &.{ stamp("2024-07-15T12:00:00Z"), stamp("2024-01-15T12:00:00Z") });
    const g = try eval(a, f, .{ .strftime = .{ .x = &X, .format = "%Y-%m-%d %H:%M %z %:z %Z" } });
    try expectText("2024-07-15 14:00 +0200 +02:00 CEST", cellOf(g, 0));
    try expectText("2024-01-15 13:00 +0100 +01:00 CET", cellOf(g, 1));
    // a format the translator refuses is refused for a zoned column too
    try testing.expectError(error.BadExpr, eval(a, f, .{ .strftime = .{ .x = &X, .format = "%Q %Z" } }));
    try testing.expectError(error.BadExpr, eval(a, f, .{ .strftime = .{ .x = &X, .format = "%Q" } }));
}

test "truncate cuts on the wall clock: a DST day is 23 hours long" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 31 March 2024 12:00Z; the day began at 00:00 CET = 30 March 23:00Z and the next one
    // begins at 00:00 CEST = 31 March 22:00Z, 23 hours later.
    const f = try one(a, prague, &.{ stamp("2024-03-31T12:00:00Z"), stamp("2024-03-31T21:59:59Z"), stamp("2024-03-31T22:00:00Z") });
    const g = try eval(a, f, .{ .truncate = .{ .x = &X, .every = "1d" } });
    try expectInt(stamp("2024-03-30T23:00:00Z"), cellOf(g, 0));
    try expectInt(stamp("2024-03-30T23:00:00Z"), cellOf(g, 1));
    try expectInt(stamp("2024-03-31T22:00:00Z"), cellOf(g, 2));
    const c = try eval(a, f, .{ .truncate = .{ .x = &X, .every = "1d", .mode = .ceil } });
    try expectInt(stamp("2024-03-31T22:00:00Z"), cellOf(c, 0));
    try expectInt(stamp("2024-03-31T22:00:00Z"), cellOf(c, 2));
    // the fold hour: 02:30 CET (01:30Z) floors to 02:00 CET (01:00Z), not to 02:00 CEST (00:00Z)
    const fold = try one(a, prague, &.{ stamp("2024-10-27T00:30:00Z"), stamp("2024-10-27T01:30:00Z") });
    const h = try eval(a, fold, .{ .truncate = .{ .x = &X, .every = "1h" } });
    try expectInt(stamp("2024-10-27T00:00:00Z"), cellOf(h, 0));
    try expectInt(stamp("2024-10-27T01:00:00Z"), cellOf(h, 1));
}

test "convert_time_zone changes the tag only; replace_time_zone reads the wall clock again" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inst = stamp("2024-07-15T12:00:00Z");
    const f = try one(a, prague, &.{ inst, std.math.minInt(i64) });
    const g = try eval(a, f, .{ .convert_time_zone = .{ .x = &X, .zone = "Asia/Tokyo" } });
    try expectInt(inst, cellOf(g, 0));
    try expectInt(std.math.minInt(i64), cellOf(g, 1));
    try testing.expectEqualStrings("Asia/Tokyo", g.columns[g.columnIndex("out").?].time_zone.?);
    // 14:00 CEST read as 14:00 in Tokyo (+9) is 05:00Z
    const r = try eval(a, f, .{ .replace_time_zone = .{ .x = &X, .zone = "Asia/Tokyo" } });
    try expectInt(stamp("2024-07-15T05:00:00Z"), cellOf(r, 0));
    // replace with no zone: the wall clock as a naive column
    const w = try eval(a, f, .{ .replace_time_zone = .{ .x = &X, .zone = null } });
    try expectInt(stamp("2024-07-15T14:00:00Z"), cellOf(w, 0));
    try testing.expect(w.columns[w.columnIndex("out").?].time_zone == null);
    // and a naive column localised in Prague, the fold under each policy
    const naive = try one(a, null, &.{stamp("2024-10-27T02:30:00Z")});
    const early = try eval(a, naive, .{ .replace_time_zone = .{ .x = &X, .zone = prague, .policy = .earlier } });
    const late = try eval(a, naive, .{ .replace_time_zone = .{ .x = &X, .zone = prague, .policy = .later } });
    try expectInt(stamp("2024-10-27T00:30:00Z"), cellOf(early, 0));
    try expectInt(stamp("2024-10-27T01:30:00Z"), cellOf(late, 0));
    // refused: an unknown zone, a non-timestamp operand
    try testing.expectError(error.BadExpr, eval(a, f, .{ .convert_time_zone = .{ .x = &X, .zone = "Europe/Atlantis" } }));
    try testing.expectError(error.BadExpr, eval(a, f, .{ .replace_time_zone = .{ .x = &X, .zone = "Europe/Atlantis" } }));
    const d = try df.cast(a, f, .{ .col = "ts", .to = .duration });
    try testing.expectError(error.BadExpr, eval(a, d, .{ .convert_time_zone = .{ .x = &X, .zone = "UTC" } }));
}

test "the zone follows an expression that keeps an instant an instant" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try one(a, prague, &.{stamp("2024-07-15T12:00:00Z")});
    const g = try eval(a, f, .{ .offset_by = .{ .x = &X, .by = "1h" } });
    try testing.expectEqualStrings(prague, g.columns[g.columnIndex("out").?].time_zone.?);
    try expectInt(stamp("2024-07-15T13:00:00Z"), cellOf(g, 0));
    const t = try eval(a, f, .{ .convert_time_zone = .{ .x = &.{ .offset_by = .{ .x = &X, .by = "1h" } }, .zone = "UTC" } });
    try testing.expectEqualStrings("UTC", t.columns[t.columnIndex("out").?].time_zone.?);
    // an int column cast away from a timestamp loses the zone
    const i = try df.cast(a, f, .{ .col = "ts", .to = .int });
    try testing.expect(i.columns[0].time_zone == null);
    // a zoned cast of an expression
    const z = try eval(a, f, .{ .cast = .{ .x = &X, .to = .timestamp, .zone = "Asia/Tokyo" } });
    try testing.expectEqualStrings("Asia/Tokyo", z.columns[z.columnIndex("out").?].time_zone.?);
    try testing.expectError(error.BadExpr, eval(a, f, .{ .cast = .{ .x = &X, .to = .int, .zone = "UTC" } }));
}

test "before 1970 the zone shows its state at the epoch (tz.zones has no history)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 1960-06-15T12:00Z was EDT (07:00... 08:00 local) in New York; the table gives EST, 07:00.
    const f = try one(a, "America/New_York", &.{stamp("1960-06-15T12:00:00Z")});
    try expectInt(7, cellOf(try eval(a, f, .{ .dt = .{ .x = &X, .part = .hour } }), 0));
}

test "groupByDynamic on a zoned index through the general path (rule D) cuts at local midnight" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const start = stamp("2024-03-29T12:00:00Z");
    var us: [96]i64 = undefined;
    for (&us, 0..) |*u, i| u.* = start + @as(i64, @intCast(i)) * 3600 * s_us;
    const f0 = try one(a, prague, &us);
    const vs = try a.alloc(Value, 96);
    for (vs, 0..) |*v, i| v.* = .{ .int = @intCast(i) };
    const cols = try a.dupe(Column, &.{ f0.columns[0], .{ .name = "v", .type = .int } });
    const data = try a.dupe(df.ColumnData, &.{ f0.data[0], try df.columnFromCells(a, vs) });
    const f: Frame = .{ .columns = cols, .data = data, .len = 96 };
    const g = try df.groupByDynamic(a, f, .{ .index = "ts", .rule = "D", .aggs = &.{.{ .src = "v", .out = "n", .func = .count }} });
    const want = [_]i64{ 11, 24, 23, 24, 14 };
    try testing.expectEqual(want.len, g.len);
    for (want, 0..) |n, ri| try expectInt(n, g.cell(ri, "n").?);
    try testing.expectEqualStrings(prague, g.columns[g.columnIndex("ts").?].time_zone.?);
    // the first label is local midnight of 29 March (CET): 28 March 23:00Z
    try expectInt(stamp("2024-03-28T23:00:00Z"), g.cell(0, "ts").?);
    try expectInt(stamp("2024-03-30T23:00:00Z"), g.cell(2, "ts").?);
}

test "CSV: a zoned column is written as the wall clock with its offset and reads back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try one(a, "America/New_York", &.{ stamp("2024-07-15T12:00:00Z"), stamp("2024-01-15T12:00:00Z"), stamp("2024-03-10T07:00:00Z") });
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &aw.writer, f, .{});
    try testing.expectEqualStrings("ts\n2024-07-15 08:00:00-04:00\n2024-01-15 07:00:00-05:00\n2024-03-10 03:00:00-04:00\n", aw.written());
    const g = try df.readCsv(a, aw.written(), .{ .types = &.{.{ .name = "ts", .type = .timestamp, .time_zone = "America/New_York" }} });
    try testing.expectEqualStrings("America/New_York", g.columns[0].time_zone.?);
    for (0..3) |ri| try testing.expect(st.same(f.cell(ri, "ts").?, g.cell(ri, "ts").?));
    // a naive cell is UTC (polars); an offset is applied
    const h = try df.readCsv(a, "ts\n2024-07-15T10:00:00\n2024-07-15T12:00:00+02:00\n", .{ .types = &.{.{ .name = "ts", .type = .timestamp, .time_zone = prague }} });
    try expectInt(stamp("2024-07-15T10:00:00Z"), h.cell(0, "ts").?);
    try expectInt(stamp("2024-07-15T10:00:00Z"), h.cell(1, "ts").?);
    // refused at the boundary
    try testing.expectError(error.BadOptions, df.readCsv(a, "ts\n1\n", .{ .types = &.{.{ .name = "ts", .type = .int, .time_zone = prague }} }));
    try testing.expectError(error.BadOptions, df.readCsv(a, "ts\n2024-07-15T10:00:00Z\n", .{ .types = &.{.{ .name = "ts", .type = .timestamp, .time_zone = "Nowhere/Land" }} }));
    // datetime_format on a zoned column formats the wall clock
    var bw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &bw.writer, f, .{ .datetime_format = "%d.%m.%Y %H:%M %z" });
    try testing.expectEqualStrings("ts\n15.07.2024 08:00 -0400\n15.01.2024 07:00 -0500\n10.03.2024 03:00 -0400\n", bw.written());
}

test "JSON: records carry the offset, the Table Schema its tz, both read back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try one(a, prague, &.{ stamp("2024-07-15T10:00:00Z"), stamp("2024-01-15T11:30:05Z") });
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&aw.writer, f, .records);
    try testing.expectEqualStrings("[{\"ts\":\"2024-07-15T12:00:00+02:00\"},{\"ts\":\"2024-01-15T12:30:05+01:00\"}]", aw.written());
    var tw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&tw.writer, f, .table);
    try testing.expect(std.mem.find(u8, tw.written(), "{\"name\":\"ts\",\"type\":\"datetime\",\"tz\":\"Europe/Prague\"}") != null);
    const g = try df.readJson(a, tw.written(), .{ .orient = .table, .parse_dates = true });
    try testing.expectEqualStrings(prague, g.columns[0].time_zone.?);
    for (0..2) |ri| try testing.expect(st.same(f.cell(ri, "ts").?, g.cell(ri, "ts").?));
    // what pandas writes: UTC with Z and the zone in the schema
    const pandas =
        \\{"schema":{"fields":[{"name":"index","type":"integer"},{"name":"ts","type":"datetime","tz":"Europe/Prague"}],"primaryKey":["index"],"pandas_version":"1.4.0"},"data":[{"index":0,"ts":"2024-07-15T10:00:00.000Z"}]}
    ;
    const p = try df.readJson(a, pandas, .{ .orient = .table, .parse_dates = true });
    try testing.expectEqualStrings(prague, p.columns[0].time_zone.?);
    try expectInt(stamp("2024-07-15T10:00:00Z"), p.cell(0, "ts").?);
    const bad =
        \\{"schema":{"fields":[{"name":"index","type":"integer"},{"name":"ts","type":"datetime","tz":"Nowhere/Land"}],"primaryKey":["index"],"pandas_version":"1.4.0"},"data":[{"index":0,"ts":"2024-07-15T10:00:00.000Z"}]}
    ;
    try testing.expectError(error.BadValue, df.readJson(a, bad, .{ .orient = .table, .parse_dates = true }));
    // a declared zone on read
    const r = try df.readJson(a, "[{\"ts\":\"2024-07-15T12:00:00+02:00\"}]", .{ .parse_dates = true, .types = &.{.{ .name = "ts", .type = .timestamp, .time_zone = prague }} });
    try testing.expectEqualStrings(prague, r.columns[0].time_zone.?);
    try expectInt(stamp("2024-07-15T10:00:00Z"), r.cell(0, "ts").?);
}

test "HTML shows the wall clock with its offset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try one(a, prague, &.{stamp("2024-07-15T12:00:00Z")});
    const html = try df.toHtml(a, f, .{});
    try testing.expect(std.mem.find(u8, html, "<td>2024-07-15 14:00:00+02:00</td>") != null);
}

test "matchToSchema: another zone is another type; cast retags without moving the instant" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try one(a, prague, &.{stamp("2024-07-15T12:00:00Z")});
    const schema: []const Column = &.{.{ .name = "ts", .type = .timestamp, .time_zone = "Asia/Tokyo" }};
    try testing.expectError(error.SchemaMismatch, df.matchToSchema(a, f, schema, .{}));
    const g = try df.matchToSchema(a, f, schema, .{ .cast = true });
    try testing.expectEqualStrings("Asia/Tokyo", g.columns[0].time_zone.?);
    try expectInt(stamp("2024-07-15T12:00:00Z"), g.cell(0, "ts").?);
    const same_zone: []const Column = &.{.{ .name = "ts", .type = .timestamp, .time_zone = prague }};
    _ = try df.matchToSchema(a, f, same_zone, .{});
    const bad: []const Column = &.{.{ .name = "ts", .type = .int, .time_zone = prague }};
    try testing.expectError(error.SchemaMismatch, df.matchToSchema(a, f, bad, .{ .cast = true }));
}
