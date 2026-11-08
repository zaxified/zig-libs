// SPDX-License-Identifier: MIT
//! JSON read (`readJson`, `readNdjson`): shapes, inference, repeated and missing keys,
//! limits, and the round trip through `writeJson`/`writeNdjson`.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const ColumnType = df.ColumnType;

fn expectType(f: Frame, name: []const u8, ty: ColumnType) !void {
    try testing.expectEqual(ty, f.columnType(name).?);
}

fn expectCell(f: Frame, row: usize, name: []const u8, want: Value) !void {
    const got = f.cell(row, name).?;
    switch (want) {
        .float => |x| {
            try testing.expect(got == .float);
            try testing.expectEqual(x, got.float);
        },
        .text => |t| {
            try testing.expect(got == .text);
            try testing.expectEqualStrings(t, got.text);
        },
        else => try testing.expect(Value.eql(want, got) or (want == .null and got == .null)),
    }
}

fn names(f: Frame) ![]const u8 {
    var buf: [256]u8 = undefined;
    var n: usize = 0;
    for (f.columns) |c| {
        if (n != 0) {
            buf[n] = ',';
            n += 1;
        }
        @memcpy(buf[n..][0..c.name.len], c.name);
        n += c.name.len;
    }
    return testing.allocator.dupe(u8, buf[0..n]);
}

test "readJson records: types, missing keys, key order of first appearance" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readJson(arena.allocator(),
        \\[{"i":1,"f":1.5,"b":true,"s":"x"},
        \\ {"i":-2,"f":2,"s":"y\né","late":null},
        \\ {"b":false,"i":3,"f":-0.5e1}]
    , .{});
    try testing.expectEqual(@as(usize, 3), f.len);
    const n = try names(f);
    defer testing.allocator.free(n);
    try testing.expectEqualStrings("i,f,b,s,late", n);
    try expectType(f, "i", .int);
    try expectType(f, "f", .float);
    try expectType(f, "b", .bool);
    try expectType(f, "s", .text);
    try expectType(f, "late", .text);
    try expectCell(f, 1, "i", .{ .int = -2 });
    try expectCell(f, 1, "f", .{ .float = 2 });
    try expectCell(f, 2, "f", .{ .float = -5 });
    try expectCell(f, 1, "b", .null);
    try expectCell(f, 2, "b", .{ .bool = false });
    try expectCell(f, 1, "s", .{ .text = "y\n\u{e9}" });
    try expectCell(f, 2, "s", .null);
    try expectCell(f, 0, "late", .null);
}

test "readJson records: a mix of kinds, a nested value and an int past i64 are text from the source" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readJson(arena.allocator(),
        \\[{"m":1,"n":{"a": [1, 2]},"big":9223372036854775808,"e":1e2},
        \\ {"m":"x","n":[],"big":1,"e":2},
        \\ {"m":true,"n":null,"big":null,"e":null}]
    , .{});
    try expectType(f, "m", .text);
    try expectCell(f, 0, "m", .{ .text = "1" });
    try expectCell(f, 1, "m", .{ .text = "x" });
    try expectCell(f, 2, "m", .{ .text = "true" });
    try expectType(f, "n", .text);
    try expectCell(f, 0, "n", .{ .text = "{\"a\": [1, 2]}" });
    try expectCell(f, 1, "n", .{ .text = "[]" });
    try expectCell(f, 2, "n", .null);
    try expectType(f, "big", .text);
    try expectCell(f, 0, "big", .{ .text = "9223372036854775808" });
    try expectType(f, "e", .float);
    try expectCell(f, 0, "e", .{ .float = 100 });
}

test "readJson: a repeated key is refused by default; `.last` keeps its last value, and its type follows that value" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.BadJson, df.readJson(arena.allocator(),
        \\[{"a":"x","a":1},{"a":2}]
    , .{}));
    try testing.expectError(error.BadJson, df.readJson(arena.allocator(),
        \\{"a":["x","y"],"b":[true,false],"a":[1,2]}
    , .{ .orient = .columns }));
    try testing.expectError(error.BadJson, df.readNdjson(arena.allocator(), "{\"a\":1,\"a\":2}\n", .{}));
    const f = try df.readJson(arena.allocator(),
        \\[{"a":"x","a":1},{"a":2}]
    , .{ .duplicate_keys = .last });
    try expectType(f, "a", .int);
    try expectCell(f, 0, "a", .{ .int = 1 });
    const g = try df.readJson(arena.allocator(),
        \\{"a":["x","y"],"b":[true,false],"a":[1,2]}
    , .{ .orient = .columns, .duplicate_keys = .last });
    try testing.expectEqual(@as(usize, 2), g.columns.len);
    try expectType(g, "a", .int);
    try expectCell(g, 1, "a", .{ .int = 2 });
}

test "readJson columns: arrays, an empty object, ragged arrays refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a,
        \\{"x":[1,null,3],"y":["a","b",null]}
    , .{ .orient = .columns });
    try testing.expectEqual(@as(usize, 3), f.len);
    try expectType(f, "x", .int);
    try expectCell(f, 1, "x", .null);
    try expectCell(f, 2, "y", .null);
    const e = try df.readJson(a, " {} ", .{ .orient = .columns });
    try testing.expectEqual(@as(usize, 0), e.columns.len);
    try testing.expectEqual(@as(usize, 0), e.len);
    try testing.expectError(error.RaggedColumns, df.readJson(a,
        \\{"x":[1,2],"y":[1]}
    , .{ .orient = .columns }));
    try testing.expectError(error.BadShape, df.readJson(a,
        \\{"x":1}
    , .{ .orient = .columns }));
}

test "readNdjson: blank lines and CRLF, n_rows stops but the rest must be JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = "{\"a\":1}\r\n\n  \n{\"a\":2,\"b\":\"z\"}\n{\"a\":3}\n";
    const f = try df.readNdjson(a, text, .{});
    try testing.expectEqual(@as(usize, 3), f.len);
    try expectCell(f, 1, "b", .{ .text = "z" });
    try expectCell(f, 2, "b", .null);
    const g = try df.readNdjson(a, text, .{ .n_rows = 1 });
    try testing.expectEqual(@as(usize, 1), g.len);
    try testing.expectEqual(@as(usize, 1), g.columns.len);
    try testing.expectError(error.BadJson, df.readNdjson(a, "{\"a\":1}\n{oops\n", .{ .n_rows = 1 }));
    try testing.expectError(error.BadShape, df.readNdjson(a, "{\"a\":1}\n[1]\n", .{}));
    const e = try df.readNdjson(a, "", .{});
    try testing.expectEqual(@as(usize, 0), e.columns.len);
}

test "readJson: parse_dates types ISO dates and instants, only on request" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\[{"d":"2024-02-29","t":"2024-01-02T03:04:05Z","x":"2024-01-01"},
        \\ {"d":"1999-12-31","t":"2024-01-02T04:04:05+01:00","x":"nope"}]
    ;
    const f = try df.readJson(a, doc, .{ .parse_dates = true });
    try expectType(f, "d", .date);
    try expectCell(f, 0, "d", .{ .text = "2024-02-29" });
    try expectType(f, "t", .timestamp);
    try testing.expect(Value.eql(f.cell(0, "t").?, f.cell(1, "t").?));
    try expectType(f, "x", .text);
    const g = try df.readJson(a, doc, .{});
    try expectType(g, "d", .text);
    try expectType(g, "t", .text);
}

test "readJson: columns and types options" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\[{"a":"1","b":2,"c":"1.25"},{"a":" 7 ","b":3,"c":"2"}]
    ;
    const f = try df.readJson(a, doc, .{
        .columns = &.{ "c", "a" },
        .types = &.{ .{ .name = "a", .type = .int }, .{ .name = "c", .type = .decimal } },
    });
    try testing.expectEqual(@as(usize, 2), f.columns.len);
    try testing.expectEqualStrings("a", f.columns[0].name);
    try expectCell(f, 1, "a", .{ .int = 7 });
    try expectType(f, "c", .decimal);
    try testing.expectError(error.NoSuchColumn, df.readJson(a, doc, .{ .columns = &.{"zz"} }));
    try testing.expectError(error.NoSuchColumn, df.readJson(a, doc, .{ .types = &.{.{ .name = "zz", .type = .int }} }));
    try testing.expectError(error.BadValue, df.readJson(a,
        \\[{"a":"x"}]
    , .{ .types = &.{.{ .name = "a", .type = .int }} }));
    try testing.expectError(error.BadValue, df.readJson(a,
        \\[{"a":[1]}]
    , .{ .types = &.{.{ .name = "a", .type = .int }} }));
}

test "readJson: malformed input, wrong shapes and limits are errors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.BadJson, df.readJson(a, "[{\"a\":1}", .{}));
    try testing.expectError(error.BadJson, df.readJson(a, "", .{}));
    try testing.expectError(error.BadJson, df.readJson(a, "[{\"a\":\"\xff\"}]", .{}));
    try testing.expectError(error.BadJson, df.readJson(a, "[{\"a\":1}] x", .{}));
    try testing.expectError(error.BadShape, df.readJson(a, "[1,2]", .{}));
    try testing.expectError(error.BadShape, df.readJson(a, "{\"a\":[1]}", .{}));
    try testing.expectError(error.BadShape, df.readJson(a, "7", .{ .orient = .columns }));
    try testing.expectError(error.InputTooLarge, df.readJson(a, "[{\"a\":1}]", .{ .max_bytes = 4 }));
    try testing.expectError(error.TooManyColumns, df.readJson(a, "[{\"a\":1,\"b\":2,\"c\":3}]", .{ .max_columns = 2 }));
    try testing.expectError(error.TooManyRows, df.readJson(a, "[{},{},{}]", .{ .max_rows = 2 }));
    try testing.expectError(error.TooManyRows, df.readJson(a, "{\"a\":[1,2,3]}", .{ .orient = .columns, .max_rows = 2 }));
    try testing.expectError(error.TooManyCells, df.readJson(a, "[{\"a\":1,\"b\":2},{}]", .{ .max_cells = 3 }));
    try testing.expectError(error.CellTooLarge, df.readJson(a, "[{\"a\":\"abcdef\"}]", .{ .max_cell_bytes = 4 }));
    try testing.expectError(error.CellTooLarge, df.readJson(a, "[{\"abcdef\":1}]", .{ .max_cell_bytes = 4 }));
    try testing.expectError(error.CellTooLarge, df.readJson(a, "[{\"a\":[1,2,3,4]}]", .{ .max_cell_bytes = 4 }));
    // Records of no keys: rows without columns.
    const e = try df.readJson(a, "[{},{}]", .{});
    try testing.expectEqual(@as(usize, 2), e.len);
    try testing.expectEqual(@as(usize, 0), e.columns.len);
}

test "readJson: deep nesting is a bounded walk, not recursion" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const depth = 100_000;
    const doc = try a.alloc(u8, 8 + 2 * depth);
    @memcpy(doc[0..6], "[{\"a\":");
    @memset(doc[6..][0..depth], '[');
    @memset(doc[6 + depth ..][0..depth], ']');
    @memcpy(doc[6 + 2 * depth ..], "}]");
    const f = try df.readJson(a, doc, .{});
    // `max_nesting_depth` levels of lists (the walk recurses only that far), then the
    // rest of the value as its JSON text.
    try expectType(f, "a", .list);
    var v = f.cell(0, "a").?;
    for (0..df.max_nesting_depth) |_| v = v.list.get(0);
    try testing.expectEqual(@as(usize, 2 * (depth - @as(usize, df.max_nesting_depth))), v.text.len);
    // Asked for as text, the whole value is its source.
    const t = try df.readJson(a, doc, .{ .types = &.{.{ .name = "a", .type = .text }} });
    try testing.expectEqual(@as(usize, 2 * depth), t.cell(0, "a").?.text.len);
}

test "readJson and readNdjson read back what writeJson and writeNdjson wrote" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try df.readCsv(a,
        \\i,f,b,s,t
        \\1,1.0,true,"a ""q"" b",2024-01-02T03:04:05Z
        \\,-2.5,false,,2024-01-02T03:04:05.250Z
        \\-3,,,"line
        \\two",
        \\
    , .{ .parse_dates = true, .null_values = &.{""} });
    try expectType(src, "t", .timestamp);
    for ([_]df.JsonReadOrient{ .records, .columns }) |orient| {
        var out: std.Io.Writer.Allocating = .init(a);
        try df.writeJson(&out.writer, src, if (orient == .records) .records else .columns);
        const back = try df.readJson(a, out.written(), .{ .orient = orient, .parse_dates = true });
        try testing.expect(df.equals(src, back));
    }
    var nd: std.Io.Writer.Allocating = .init(a);
    try df.writeNdjson(&nd.writer, src);
    const back = try df.readNdjson(a, nd.written(), .{ .parse_dates = true });
    try testing.expect(df.equals(src, back));
}
