// SPDX-License-Identifier: MIT
//! List and struct columns (S3 step 2, 2026-11-08): the model (`ListColumn`,
//! `StructColumn`, `Value.list`/`.record`), every structural verb carrying them, keys
//! over them, `readJson` building them from nested values, the writers and the
//! rendering, and the nesting-depth bound on hand-built storage.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const ColumnData = df.ColumnData;

fn json(a: std.mem.Allocator, text: []const u8) !Frame {
    return df.readJson(a, text, .{});
}

fn jsonOf(a: std.mem.Allocator, f: Frame) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&out.writer, f, .records);
    return out.written();
}

fn expectInts(want: []const i64, v: Value) !void {
    try testing.expect(v == .list);
    try testing.expectEqual(want.len, v.list.len());
    for (want, 0..) |w, i| try testing.expectEqual(w, v.list.get(i).int);
}

const doc =
    \\[{"id":1,"xs":[3,1,2],"p":{"a":1,"b":"x"},"ps":[{"a":1,"b":"u"},{"a":2,"b":null}]},
    \\ {"id":2,"xs":[],"p":null,"ps":[]},
    \\ {"id":3,"xs":null,"p":{"b":"y"},"ps":null},
    \\ {"id":4,"xs":[1,null],"p":{"a":4,"b":"z","c":true},"ps":[{"a":9}]}]
;

test "nested: a cell is still 32 bytes, the views 16" {
    try testing.expectEqual(@as(usize, 32), @sizeOf(Value));
    try testing.expectEqual(@as(usize, 16), @sizeOf(df.ListView));
    try testing.expectEqual(@as(usize, 16), @sizeOf(df.RecordView));
}

test "readJson: arrays of one shape are a list column, objects a struct column, with their schema" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try json(arena.allocator(), doc);
    try testing.expectEqual(@as(usize, 4), f.len);
    try testing.expectEqual(df.ColumnType.list, f.columnType("xs").?);
    try testing.expectEqual(df.ColumnType.@"struct", f.columnType("p").?);
    try testing.expectEqual(df.ColumnType.list, f.columnType("ps").?);
    try testing.expect(f.column("xs").? == .list);
    try testing.expect(f.column("p").? == .@"struct");

    // Schema: list(int); struct{a: int, b: text, c: bool} (keys in first-seen order); list(struct{a, b}).
    const xs = f.columns[f.columnIndex("xs").?];
    try testing.expectEqual(@as(usize, 1), xs.inner.len);
    try testing.expectEqual(df.ColumnType.int, xs.inner[0].type);
    const p = f.columns[f.columnIndex("p").?];
    try testing.expectEqual(@as(usize, 3), p.inner.len);
    try testing.expectEqualStrings("a", p.inner[0].name);
    try testing.expectEqual(df.ColumnType.int, p.inner[0].type);
    try testing.expectEqualStrings("c", p.inner[2].name);
    try testing.expectEqual(df.ColumnType.bool, p.inner[2].type);
    const ps = f.columns[f.columnIndex("ps").?];
    try testing.expectEqual(df.ColumnType.@"struct", ps.inner[0].type);
    try testing.expectEqual(@as(usize, 2), ps.inner[0].inner.len);

    // Cells.
    try expectInts(&.{ 3, 1, 2 }, f.cell(0, "xs").?);
    try expectInts(&.{}, f.cell(1, "xs").?);
    try testing.expect(f.cell(2, "xs").? == .null);
    const x3 = f.cell(3, "xs").?.list;
    try testing.expectEqual(@as(usize, 2), x3.len());
    try testing.expect(x3.get(1) == .null);
    const r0 = f.cell(0, "p").?.record;
    try testing.expectEqual(@as(usize, 3), r0.len());
    try testing.expectEqual(@as(i64, 1), r0.field("a").?.int);
    try testing.expectEqualStrings("x", r0.field("b").?.text);
    try testing.expect(r0.field("c").? == .null); // a key missing from an object is null
    try testing.expect(f.cell(1, "p").? == .null);
    try testing.expect(f.cell(2, "p").?.record.field("a").? == .null);
    const ps0 = f.cell(0, "ps").?.list;
    try testing.expectEqual(@as(usize, 2), ps0.len());
    try testing.expectEqualStrings("u", ps0.get(0).record.field("b").?.text);
    try testing.expect(ps0.get(1).record.field("b").? == .null);
    try testing.expectEqual(@as(i64, 9), f.cell(3, "ps").?.list.get(0).record.field("a").?.int);
}

test "writeJson writes nested values natively, and they read back equal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try json(a, doc);
    const text = try jsonOf(a, f);
    try testing.expectEqualStrings(
        \\[{"id":1,"xs":[3,1,2],"p":{"a":1,"b":"x","c":null},"ps":[{"a":1,"b":"u"},{"a":2,"b":null}]},{"id":2,"xs":[],"p":null,"ps":[]},{"id":3,"xs":null,"p":{"a":null,"b":"y","c":null},"ps":null},{"id":4,"xs":[1,null],"p":{"a":4,"b":"z","c":true},"ps":[{"a":9,"b":null}]}]
    , text);
    const g = try json(a, text);
    try testing.expect(df.equals(f, g));
    var nd: std.Io.Writer.Allocating = .init(a);
    try df.writeNdjson(&nd.writer, f);
    try testing.expect(df.equals(f, try df.readNdjson(a, nd.written(), .{})));
    var cw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&cw.writer, f, .columns);
    try testing.expect(df.equals(f, try df.readJson(a, cw.written(), .{ .orient = .columns })));
}

test "readJson: a mix of shapes stays the JSON text, deep nesting past the bound is text, parse_dates reaches inside" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try json(a,
        \\[{"m":[1],"e":[1,"x",[2]],"o":[{"a":1},2]},{"m":3,"e":[],"o":[]}]
    );
    try testing.expectEqual(df.ColumnType.text, f.columnType("m").?);
    try testing.expectEqualStrings("[1]", f.cell(0, "m").?.text);
    // Elements of mixed kinds: a list of text, each its source (as a column of them is).
    try testing.expectEqual(df.ColumnType.list, f.columnType("e").?);
    const e0 = f.cell(0, "e").?.list;
    try testing.expectEqualStrings("1", e0.get(0).text);
    try testing.expectEqualStrings("x", e0.get(1).text);
    try testing.expectEqualStrings("[2]", e0.get(2).text);
    try testing.expectEqualStrings("2", f.cell(0, "o").?.list.get(1).text);

    // 100 levels: the first 64 are lists, the rest is the JSON text at the bottom.
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(a, "[{\"d\":");
    for (0..100) |_| try deep.append(a, '[');
    for (0..100) |_| try deep.append(a, ']');
    try deep.appendSlice(a, "}]");
    const g = try json(a, deep.items);
    var v = g.cell(0, "d").?;
    var levels: usize = 0;
    while (v == .list) : (levels += 1) v = v.list.get(0);
    try testing.expectEqual(@as(usize, df.max_nesting_depth), levels);
    try testing.expect(v == .text);
    try testing.expectEqual(@as(usize, 2 * (100 - df.max_nesting_depth)), v.text.len);

    const h = try df.readJson(a,
        \\[{"d":["2024-01-02","2024-03-04"],"t":{"at":"2024-01-02T03:04:05Z"}}]
    , .{ .parse_dates = true });
    try testing.expectEqual(df.ColumnType.date, h.columns[0].inner[0].type);
    try testing.expectEqual(df.ColumnType.timestamp, h.columns[1].inner[0].type);
    // The writer reads the inner schema: the instant is written back as RFC 3339.
    try testing.expectEqualStrings(
        \\[{"d":["2024-01-02","2024-03-04"],"t":{"at":"2024-01-02T03:04:05Z"}}]
    , try jsonOf(a, h));
}

test "readJson: duplicate keys inside nested objects, refused by default, the last with `.last`" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text =
        \\[{"p":{"a":1,"b":2,"a":[7]}},{"p":{"a":[8],"b":3}}]
    ;
    try testing.expectError(error.BadJson, df.readJson(a, text, .{}));
    try testing.expectError(error.BadJson, df.readJson(a, "[{\"l\":[{\"x\":1,\"x\":2}]}]", .{}));
    const f = try df.readJson(a, text, .{ .duplicate_keys = .last });
    // The type follows every value the key had (int and list: text), the cell the last one.
    const p0 = f.cell(0, "p").?.record;
    try testing.expectEqualStrings("[7]", p0.field("a").?.text);
    try testing.expectEqual(@as(i64, 2), p0.field("b").?.int);
    try testing.expectEqualStrings("[8]", f.cell(1, "p").?.record.field("a").?.text);
    const g = try df.readJson(a, "[{\"p\":{\"x\":[1],\"x\":[2,3]}}]", .{ .duplicate_keys = .last });
    try expectInts(&.{ 2, 3 }, g.cell(0, "p").?.record.field("x").?);
}

test "readJson: max_cells counts the elements and fields, a nested type in `types`" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 1 row, 1 column: 1 cell; its list 5 more; a struct of 2 fields per element 10 more.
    const text = "[{\"l\":[{\"a\":1,\"b\":2},{},{},{},{}]}]";
    try testing.expectError(error.TooManyCells, df.readJson(a, text, .{ .max_cells = 15 }));
    _ = try df.readJson(a, text, .{ .max_cells = 16 });
    // `types`: text keeps the source; the nested kind the input has; another kind is refused.
    const t = try df.readJson(a, text, .{ .types = &.{.{ .name = "l", .type = .text }} });
    try testing.expectEqualStrings("[{\"a\":1,\"b\":2},{},{},{},{}]", t.cell(0, "l").?.text);
    _ = try df.readJson(a, text, .{ .types = &.{.{ .name = "l", .type = .list }} });
    try testing.expectError(error.BadValue, df.readJson(a, text, .{ .types = &.{.{ .name = "l", .type = .@"struct" }} }));
    try testing.expectError(error.BadValue, df.readJson(a, "[{\"l\":1}]", .{ .types = &.{.{ .name = "l", .type = .list }} }));
    // CSV has no nesting: a nested type reads only nulls.
    try testing.expectError(error.BadValue, df.readCsv(a, "l\n[1]\n", .{ .types = &.{.{ .name = "l", .type = .list }} }));
}

test "verbs: filter, sort and take carry list and struct cells; keys over them work" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try json(a, doc);

    const kept = try df.filter(a, f, .{ .where = &.{.{ .col = "id", .op = .ge, .value = .{ .int = 3 } }} });
    try testing.expectEqual(@as(usize, 2), kept.len);
    try testing.expect(kept.cell(0, "xs").? == .null);
    try testing.expectEqual(@as(usize, 2), kept.cell(1, "xs").?.list.len());
    try testing.expectEqual(@as(i64, 1), kept.cell(1, "xs").?.list.get(0).int);
    try testing.expectEqual(@as(i64, 4), kept.cell(1, "p").?.record.field("a").?.int);
    try testing.expectEqual(@as(i64, 9), kept.cell(1, "ps").?.list.get(0).record.field("a").?.int);

    // Sorting by a list column: lexicographic, the shorter first, null lowest (polars).
    const s = try df.sort(a, f, .{ .key = "xs" });
    const ids = [_]i64{ 3, 2, 4, 1 }; // null, [], [1,null], [3,1,2]
    for (ids, 0..) |id, i| try testing.expectEqual(id, s.cell(i, "id").?.int);
    try expectInts(&.{ 3, 1, 2 }, s.cell(3, "xs").?);
    try testing.expectEqualStrings("x", s.cell(3, "p").?.record.field("b").?.text);

    // take with repeats and an out-of-range-free permutation; the result is well formed.
    const t = try df.take(a, f, &.{ 3, 0, 0 });
    try expectInts(&.{ 3, 1, 2 }, t.cell(1, "xs").?);
    try expectInts(&.{ 3, 1, 2 }, t.cell(2, "xs").?);
    try testing.expectEqualStrings("z", t.cell(0, "p").?.record.field("b").?.text);
    try testing.expect(df.equals(try json(a, try jsonOf(a, t)), t));

    // A list key: equal lists are one group (and `[1]` and `[1.0]` too, as `Value.order` says).
    const g = try json(a,
        \\[{"k":[1,2],"v":1},{"k":[1],"v":2},{"k":[1,2],"v":3},{"k":[1.0],"v":4},{"k":null,"v":5}]
    );
    const agg = try df.aggregate(a, g, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "n", .func = .count }} });
    try testing.expectEqual(@as(usize, 3), agg.len);
    try testing.expectEqual(@as(i64, 2), agg.cell(0, "n").?.int);
    try testing.expectEqual(@as(i64, 2), agg.cell(1, "n").?.int);
    const d = try df.distinct(a, g, .{ .keys = &.{"k"} });
    try testing.expectEqual(@as(usize, 3), d.len);
    // A struct key joins.
    const r = try json(a,
        \\[{"p":{"a":1,"b":"x"},"w":10},{"p":{"a":4,"b":"z","c":true},"w":40}]
    );
    const fp = try df.select(a, f, &.{ "id", "p" });
    const j = try df.join(a, fp, r, .{ .on = "p" });
    try testing.expectEqual(@as(usize, 2), j.len);
    try testing.expectEqual(@as(i64, 40), j.cell(1, "w").?.int);
}

test "concat and FrameBuilder: nested cells are copied into storage of the column's own" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try json(a, doc);
    const two = try df.concat(a, &.{ f, f }, .vertical);
    try testing.expectEqual(@as(usize, 8), two.len);
    try testing.expect(two.column("xs").? == .list);
    try expectInts(&.{ 3, 1, 2 }, two.cell(4, "xs").?);
    try testing.expectEqualStrings("u", two.cell(4, "ps").?.list.get(0).record.field("b").?.text);
    try testing.expect(df.equals(try df.take(a, two, &.{ 0, 1, 2, 3 }), f));

    // A FrameBuilder row with cells read from `f`: the builder copies them.
    const cols = [_]df.Column{ .{ .name = "l", .type = .list }, .{ .name = "r", .type = .@"struct" } };
    var b = try df.FrameBuilder.init(a, &cols, 0);
    try b.appendRow(&.{ f.cell(0, "xs").?, f.cell(0, "p").? });
    try b.appendRow(&.{ .null, .null });
    try b.appendRow(&.{ f.cell(3, "xs").?, f.cell(3, "p").? });
    const g = try b.toOwned();
    try testing.expect(g.column("l").? == .list);
    try testing.expect(g.column("r").? == .@"struct");
    try testing.expect(g.cell(0, "l").?.list.items != f.cell(0, "xs").?.list.items);
    try testing.expect(g.cell(0, "l").?.eql(f.cell(0, "xs").?));
    try testing.expect(g.cell(2, "r").?.eql(f.cell(3, "p").?));
    try testing.expect(g.cell(1, "l").? == .null);

    // A list after an int, records of other fields: a boxed column of copies.
    const mix = try df.columnFromCells(a, &.{ .{ .int = 1 }, f.cell(0, "xs").?, f.cell(0, "p").?, f.cell(3, "ps").?.list.get(0) });
    try testing.expect(mix == .boxed);
    try testing.expect(mix.boxed[1].list.items != f.cell(0, "xs").?.list.items);
    try testing.expect(mix.get(1).eql(f.cell(0, "xs").?));
    try testing.expectEqualStrings("x", mix.get(2).record.field("b").?.text);
    const recs = try df.columnFromCells(a, &.{ f.cell(0, "p").?, f.cell(3, "ps").?.list.get(0) });
    try testing.expect(recs == .boxed); // {a,b,c} and {a,b}
}

test "writeCsv writes a nested cell as its JSON text, format and toMarkdown show it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.select(a, try json(a, doc), &.{ "id", "xs", "p" });
    var out: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &out.writer, f, .{});
    try testing.expectEqualStrings(
        \\id,xs,p
        \\1,"[3,1,2]","{""a"":1,""b"":""x"",""c"":null}"
        \\2,[],
        \\3,,"{""a"":null,""b"":""y"",""c"":null}"
        \\4,"[1,null]","{""a"":4,""b"":""z"",""c"":true}"
        \\
    , out.written());
    const s = try df.format(a, f, .{ .max_cell_chars = 12 });
    try testing.expect(std.mem.indexOf(u8, s, "[3,1,2]") != null);
    try testing.expect(std.mem.indexOf(u8, s, "{\"a\":1,\"b\":…") != null);
    const md = try df.toMarkdown(a, f, .{});
    try testing.expect(std.mem.indexOf(u8, md, "{\"a\":4,\"b\":\"z\",\"c\":true}") != null);
    try testing.expect(df.columnBytes(f, 1) > 0 and df.columnBytes(f, 2) > 0);
}

test "mutate and cast: a nested column carried over keeps its kind and schema; to text it is JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try json(a, doc);
    const xs: df.Expr = .{ .col = "xs" };
    const m = try df.mutate(a, f, &.{.{ .out = "ys", .expr = xs }});
    const ys = m.columns[m.columnIndex("ys").?];
    try testing.expectEqual(df.ColumnType.list, ys.type);
    try testing.expectEqual(df.ColumnType.int, ys.inner[0].type);
    try expectInts(&.{ 3, 1, 2 }, m.cell(0, "ys").?);
    const c = try df.cast(a, f, .{ .col = "p", .to = .text });
    try testing.expectEqualStrings("{\"a\":1,\"b\":\"x\",\"c\":null}", c.cell(0, "p").?.text);
    // Comparing two list cells is `Value.order`'s.
    const lt: df.Expr = .{ .binary = .{ .op = .lt, .l = &xs, .r = &.{ .col = "xs" } } };
    const w = try df.mutate(a, f, &.{.{ .out = "b", .expr = lt }});
    try testing.expectEqual(false, w.cell(0, "b").?.bool);
    // Arithmetic and string functions give null on a nested cell, as on a bool.
    const plus: df.Expr = .{ .binary = .{ .op = .add, .l = &xs, .r = &.{ .lit = .{ .int = 1 } } } };
    const n = try df.mutate(a, f, &.{.{ .out = "n", .expr = plus }});
    for (0..n.len) |i| try testing.expect(n.cell(i, "n").? == .null);
    const up: df.Expr = .{ .binary = .{ .op = .contains, .l = &xs, .r = &.{ .lit = .{ .text = "1" } } } };
    try testing.expect((try df.mutate(a, f, &.{.{ .out = "c", .expr = up }})).cell(0, "c").? == .null);
}

test "a hand-built list that holds itself ends at the nesting bound, in every walker" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Row 0 is a list of one element: row 0 of the same column.
    const self = try a.create(ColumnData);
    self.* = .{ .list = .{ .offsets = &.{ 0, 1 }, .items = self } };
    const cols = [_]df.Column{.{ .name = "l", .type = .list }};
    const f: Frame = .{ .columns = &cols, .data = &.{self.*}, .len = 1 };
    const v = f.cell(0, "l").?;
    try testing.expect(v.eql(v));
    try testing.expectEqual(std.math.Order.eq, v.order(v));
    const text = try jsonOf(a, f);
    const closes: [df.max_nesting_depth]u8 = @splat(']');
    try testing.expect(std.mem.endsWith(u8, text, "null" ++ closes ++ "}]"));
    _ = try df.format(a, f, .{});
    const t = try df.take(a, f, &.{ 0, 0 });
    try testing.expectEqual(@as(usize, 2), t.len);
    const d = try df.distinct(a, try df.concat(a, &.{ f, f }, .vertical), .{ .keys = &.{"l"} });
    try testing.expectEqual(@as(usize, 1), d.len);
    _ = df.estimatedSize(f);
}

test "review fixes: names are the frame's own, a key-path budget, inner kept by concat and aggregate, predicates and reused storage" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // M3: the input buffer goes away; column and field names stay.
    const buf = try testing.allocator.dupe(u8, "[{\"col\":{\"fld\":[1]}}]");
    const f = try df.readJson(a, buf, .{});
    @memset(buf, 'x');
    testing.allocator.free(buf);
    try testing.expectEqualStrings("col", f.columns[0].name);
    try testing.expectEqualStrings("fld", f.columns[0].inner[0].name);
    try testing.expectEqualStrings("fld", f.cell(0, "col").?.record.name(0));

    // M1: columns, fields and list elements share `max_columns` (here: col, s, s.a, s.b, s.b[]).
    const doc5 = "[{\"col\":1,\"s\":{\"a\":1,\"b\":[2]}}]";
    try testing.expectError(error.TooManyColumns, df.readJson(a, doc5, .{ .max_columns = 4 }));
    _ = try df.readJson(a, doc5, .{ .max_columns = 5 });

    // L2: concat and aggregate(first) keep the declared inner columns.
    const g = try df.readJson(a, "[{\"k\":1,\"t\":[\"2024-01-02T00:00:00Z\"]}]", .{ .parse_dates = true });
    const c = try df.concat(a, &.{ g, g }, .vertical);
    try testing.expectEqual(df.ColumnType.timestamp, c.columns[1].inner[0].type);
    const ag = try df.aggregate(a, g, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "t", .out = "t", .func = .first }} });
    try testing.expectEqual(df.ColumnType.timestamp, ag.columns[1].inner[0].type);

    // L4: a list cell against a record literal matches nothing, `ne` included.
    const h = try json(a, doc);
    const rec = h.cell(0, "p").?;
    const kept = try df.filter(a, h, .{ .where = &.{.{ .col = "xs", .op = .ne, .value = rec }} });
    try testing.expectEqual(@as(usize, 0), kept.len);

    // L5: one storage reused for every row with other names: the builder compares names.
    var names_buf = [_][]const u8{"x"};
    const child = [_]ColumnData{try df.columnFromCells(a, &.{.{ .int = 1 }})};
    var st: df.StructColumn = .{ .names = &names_buf, .children = &child, .len = 1 };
    const first: Value = .{ .record = .{ .fields = &st, .row = 0 } };
    var b: @import("frame.zig").ColBuilder = .{ .a = a, .hint = 2 };
    try b.append(first);
    names_buf[0] = "y";
    try b.append(first);
    const col = b.finish();
    try testing.expect(col == .boxed);
    try testing.expectEqualStrings("x", col.get(0).record.name(0));
    try testing.expectEqualStrings("y", col.get(1).record.name(0));
}
