// SPDX-License-Identifier: MIT
//! D3: CSV in and out, JSON out, text rendering. Hand-written cases here; the engines'
//! answers are in `oracle3_io_test.zig`.

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
            if (std.math.isNan(x)) try testing.expect(std.math.isNan(got.float)) else try testing.expectEqual(x, got.float);
        },
        .text => |t| {
            try testing.expect(got == .text);
            try testing.expectEqualStrings(t, got.text);
        },
        else => try testing.expect(Value.eql(want, got) or (want == .null and got == .null)),
    }
}

test "readCsv: types are inferred from all cells, int then float then bool then text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(),
        \\i,f,mix,b,s,e
        \\1,1.5,1,true,x,
        \\-2,2,2.5,FALSE,y,
        \\+3,.5,z,True,"a,b",NA
        \\
    , .{});
    try testing.expectEqual(@as(usize, 3), f.len);
    try expectType(f, "i", .int);
    try expectType(f, "f", .float);
    try expectType(f, "mix", .text);
    try expectType(f, "b", .bool);
    try expectType(f, "s", .text);
    try expectType(f, "e", .text); // all null: polars' String
    try expectCell(f, 2, "i", .{ .int = 3 });
    try expectCell(f, 2, "f", .{ .float = 0.5 });
    try expectCell(f, 0, "mix", .{ .text = "1" });
    try expectCell(f, 1, "b", .{ .bool = false });
    try expectCell(f, 2, "s", .{ .text = "a,b" });
    try expectCell(f, 2, "e", .null);
}

test "readCsv: null markers, blanks around numbers, big ints, specials" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(), "a,b,c,d\n1,x,1e3,\nNA, y ,Infinity,2\n 4 ,null,-inf,3\n9223372036854775808,z,.,4\n", .{});
    // 9223372036854775808 does not fit i64 -> text (pandas: uint64/object, polars: i128)
    try expectType(f, "a", .text);
    try expectType(f, "c", .text); // "." is not a number
    try expectType(f, "d", .int);
    try expectCell(f, 1, "a", .null);
    try expectCell(f, 2, "b", .null);
    try expectCell(f, 1, "b", .{ .text = " y " });
    const g = try df.readCsv(arena.allocator(), "a,c\n 4 ,1e3\n-7,Infinity\n,-INF\n", .{});
    try expectType(g, "a", .int);
    try expectCell(g, 0, "a", .{ .int = 4 });
    try expectCell(g, 2, "a", .null);
    try expectType(g, "c", .float);
    try expectCell(g, 1, "c", .{ .float = std.math.inf(f64) });
    try expectCell(g, 2, "c", .{ .float = -std.math.inf(f64) });
}

test "readCsv: header handling, BOM, CRLF, quoted newlines, ragged rows" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "\xEF\xBB\xBFa,a,,b\r\n1,2,3,\"x\ny\"\r\n4,5\r\n", .{});
    try testing.expectEqualStrings("a", f.columns[0].name);
    try testing.expectEqualStrings("a.1", f.columns[1].name);
    try testing.expectEqualStrings("Unnamed: 2", f.columns[2].name);
    try testing.expectEqualStrings("b", f.columns[3].name);
    try testing.expectEqual(@as(usize, 2), f.len);
    try expectCell(f, 0, "b", .{ .text = "x\ny" });
    try expectCell(f, 1, "Unnamed: 2", .null); // short row: padded with nulls
    try expectCell(f, 1, "b", .null);
    try testing.expectError(error.RaggedRow, df.readCsv(a, "a,b\n1,2,3\n", .{}));
    const t = try df.readCsv(a, "a,b\n1,2,3\n4,5\n", .{ .truncate_ragged = true });
    try testing.expectEqual(@as(usize, 2), t.len);
    try expectCell(t, 0, "b", .{ .int = 2 });
    // no header, given names, skipped rows, comments, row limit
    const n = try df.readCsv(a, "junk\n# note\n1;2\n3;4\n5;6\n", .{ .delimiter = ';', .has_header = false, .skip_rows = 1, .comment = '#', .n_rows = 2 });
    try testing.expectEqualStrings("column_0", n.columns[0].name);
    try testing.expectEqual(@as(usize, 2), n.len);
    try expectCell(n, 1, "column_1", .{ .int = 4 });
    const g = try df.readCsv(a, "x,y\n1,2\n", .{ .names = &.{ "p", "q" } });
    try testing.expectEqualStrings("q", g.columns[1].name);
    try testing.expectError(error.BadNames, df.readCsv(a, "x,y\n1,2\n", .{ .names = &.{"p"} }));
    try testing.expectError(error.BadNames, df.readCsv(a, "x,y\n1,2\n", .{ .names = &.{ "p", "p" } }));
}

test "readCsv: column subset, type overrides, no inference, dates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = "id,price,d,t\n001,1.50,2021-01-02,2021-01-02 03:04:05\n002,2,2021-03-04,2021-01-02T03:04:06.5Z\n";
    const f = try df.readCsv(a, text, .{ .columns = &.{ "price", "id" } });
    try testing.expectEqual(@as(usize, 2), f.columns.len);
    try testing.expectEqualStrings("id", f.columns[0].name); // the file's order
    try testing.expectError(error.NoSuchColumn, df.readCsv(a, text, .{ .columns = &.{"nope"} }));
    const o = try df.readCsv(a, text, .{ .types = &.{ .{ .name = "id", .type = .text }, .{ .name = "price", .type = .decimal } } });
    try expectCell(o, 0, "id", .{ .text = "001" });
    try expectCell(o, 1, "price", .{ .decimal = 2_000_000_000_000 });
    try testing.expectError(error.BadValue, df.readCsv(a, text, .{ .types = &.{.{ .name = "d", .type = .int }} }));
    try testing.expectError(error.NoSuchColumn, df.readCsv(a, text, .{ .types = &.{.{ .name = "zz", .type = .int }} }));
    const s = try df.readCsv(a, text, .{ .infer_types = false });
    for (s.columns) |c| try testing.expectEqual(ColumnType.text, c.type);
    const d = try df.readCsv(a, text, .{ .parse_dates = true });
    try expectType(d, "d", .date);
    try expectType(d, "t", .timestamp);
    try expectCell(d, 0, "d", .{ .text = "2021-01-02" });
    try expectCell(d, 0, "t", .{ .int = 1609556645000000 });
    try expectCell(d, 1, "t", .{ .int = 1609556646500000 });
    const plain = try df.readCsv(a, text, .{});
    try expectType(plain, "d", .text); // neither engine parses dates by default
}

test "readCsv: only the empty field is null with polars' markers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(), "a,b\nNA,1\n,2\n", .{ .null_values = &df.polars_na_values });
    try expectCell(f, 0, "a", .{ .text = "NA" });
    try expectCell(f, 1, "a", .null);
}

test "readCsv: hostile input answers errors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // empty
    try testing.expectError(error.EmptyInput, df.readCsv(a, "", .{}));
    try testing.expectError(error.EmptyInput, df.readCsv(a, "\xEF\xBB\xBF", .{}));
    try testing.expectError(error.EmptyInput, df.readCsv(a, "a,b\n", .{ .skip_rows = 5 }));
    // too many columns
    try testing.expectError(error.TooManyColumns, df.readCsv(a, "a,b,c,d\n1,2,3,4\n", .{ .max_columns = 3 }));
    var wide: std.ArrayList(u8) = .empty;
    for (0..70_000) |_| try wide.append(a, ',');
    try testing.expectError(error.TooManyColumns, df.readCsv(a, wide.items, .{}));
    // oversized cell, and an oversized record
    try testing.expectError(error.CellTooLarge, df.readCsv(a, "a\nxxxxxxxxxx\n", .{ .max_cell_bytes = 5 }));
    try testing.expectError(error.CellTooLarge, df.readCsv(a, "xxxxxxxxxx\n1\n", .{ .max_cell_bytes = 5 }));
    try testing.expectError(error.RecordTooLarge, df.readCsv(a, "a,b\n1,2222222222222\n", .{ .max_record_bytes = 8 }));
    // unterminated quote: mid-file, at the end, and a quote that spans lines but never closes
    try testing.expectError(error.UnterminatedQuote, df.readCsv(a, "a,b\n1,\"2\n3,4\n", .{}));
    try testing.expectError(error.UnterminatedQuote, df.readCsv(a, "a,b\n1,\"2", .{}));
    try testing.expectError(error.UnterminatedQuote, df.readCsv(a, "\"a,b\n1,2\n", .{}));
    const lazy = try df.readCsv(a, "a,b\n1,\"2\n", .{ .strict_quotes = false });
    try testing.expectEqual(@as(usize, 1), lazy.len);
    // ragged
    try testing.expectError(error.RaggedRow, df.readCsv(a, "a\n1,2\n", .{}));
    // rows, cells, bytes
    try testing.expectError(error.TooManyRows, df.readCsv(a, "a\n1\n2\n3\n", .{ .max_rows = 2 }));
    try testing.expectError(error.TooManyCells, df.readCsv(a, "a,b\n1,2\n3,4\n5,6\n", .{ .max_cells = 4 }));
    try testing.expectError(error.InputTooLarge, df.readCsv(a, "a\n1\n", .{ .max_bytes = 3 }));
    // n_rows below max_rows: no error however long the file
    const cut = try df.readCsv(a, "a\n1\n2\n3\n", .{ .max_rows = 2, .n_rows = 2 });
    try testing.expectEqual(@as(usize, 2), cut.len);
    // an input of delimiters only, a header of one huge name
    var commas: std.ArrayList(u8) = .empty;
    for (0..1000) |_| try commas.appendSlice(a, ",,,,,,,,\n");
    const z = try df.readCsv(a, commas.items, .{ .has_header = false });
    try testing.expectEqual(@as(usize, 1000), z.len);
    // control bytes and invalid UTF-8 are just text
    const b = try df.readCsv(a, "a\n\x00\xff\xfe\n", .{});
    try testing.expectEqual(@as(usize, 1), b.len);
    // quote = 0 turns quoting off
    const nq = try df.readCsv(a, "a,b\n\"x,y\n", .{ .quote = 0, .strict_quotes = true });
    try testing.expectEqual(@as(usize, 1), nq.len);
}

test "readCsvReader reads a stream within max_bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var r: std.Io.Reader = .fixed("a,b\n1,2\n");
    const f = try df.readCsvReader(arena.allocator(), &r, .{});
    try testing.expectEqual(@as(usize, 1), f.len);
    var r2: std.Io.Reader = .fixed("a,b\n1,2\n");
    try testing.expectError(error.InputTooLarge, df.readCsvReader(arena.allocator(), &r2, .{ .max_bytes = 4 }));
}

fn csvOf(a: std.mem.Allocator, f: Frame, opts: df.CsvWriteOptions) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

test "writeCsv: pandas' spelling, quoting, null text, header, line ends" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "i,f,b,s,e\n1,1.0,true,\"a,b\",x\nNA,0.1,false,\"q\"\"x\",\"\"\n-3,1e-5,NA,\"l\nb\",y\n", .{ .null_values = &.{"NA"} });
    try testing.expectEqualStrings(
        "i,f,b,s,e\n1,1.0,True,\"a,b\",x\n,0.1,False,\"q\"\"x\",\"\"\n-3,1e-05,,\"l\nb\",y\n",
        try csvOf(a, f, .{}),
    );
    try testing.expectEqualStrings(
        "1;1.0;True;a,b;x\r\nNA;0.1;False;\"q\"\"x\";\"\"\r\n-3;1e-05;NA;\"l\nb\";y\r\n",
        try csvOf(a, f, .{ .delimiter = ';', .header = false, .null_text = "NA", .line_terminator = .crlf }),
    );
    try testing.expectEqualStrings("\"i\",\"f\"\n\"1\",\"1.0\"\n", try csvOf(a, try df.take(a, try df.select(a, f, &.{ "i", "f" }), &[_]i64{0}), .{ .quote_style = .always }));
    try testing.expectEqualStrings("1.00\n0.10\n0.00\n", try csvOf(a, try df.select(a, f, &.{"f"}), .{ .header = false, .float_precision = 2 }));
}

test "writeCsv: a lone empty field is quoted, and read back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "s\nx\n\"\"\nz\n", .{ .null_values = &.{} });
    const out = try csvOf(a, f, .{});
    try testing.expectEqualStrings("s\nx\n\"\"\nz\n", out);
    const g = try df.readCsv(a, out, .{ .null_values = &.{} });
    try testing.expectEqual(@as(usize, 3), g.len);
    try expectCell(g, 1, "s", .{ .text = "" });
}

test "writeCsv then readCsv round-trips every column kind" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text =
        "i,f,b,s,d,t,m\n" ++
        "1,1.5,True,hello,2021-01-02,2021-01-02 03:04:05.123456,1.25\n" ++
        ",1e-07,False,\"a,\"\"b\"\"\n\",1999-12-31,2000-02-29 00:00:00.000000,-0.5\n" ++
        "9223372036854775807,1e+16,True,é€ü,2020-02-29,1970-01-01 00:00:00.000000,3\n";
    const types = [_]df.TypeOverride{.{ .name = "m", .type = .decimal }};
    const f = try df.readCsv(a, text, .{ .parse_dates = true, .types = &types });
    const out = try csvOf(a, f, .{});
    try testing.expectEqualStrings(text, out);
    const g = try df.readCsv(a, out, .{ .parse_dates = true, .types = &types });
    try testing.expect(df.equals(f, g));
}

fn jsonOf(a: std.mem.Allocator, f: Frame, orient: df.JsonOrient) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&aw.writer, f, orient);
    return aw.toOwnedSlice();
}

test "writeJson and writeNdjson" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "i,f,b,s,d\n1,1.0,true,\"a\"\"b\\\",2021-01-02\n,nan,,\"é\ttab\",\n", .{ .parse_dates = true });
    try testing.expectEqualStrings(
        "[{\"i\":1,\"f\":1.0,\"b\":true,\"s\":\"a\\\"b\\\\\",\"d\":\"2021-01-02\"},{\"i\":null,\"f\":null,\"b\":null,\"s\":\"é\\ttab\",\"d\":null}]",
        try jsonOf(a, f, .records),
    );
    try testing.expectEqualStrings(
        "{\"i\":[1,null],\"f\":[1.0,null],\"b\":[true,null],\"s\":[\"a\\\"b\\\\\",\"é\\ttab\"],\"d\":[\"2021-01-02\",null]}",
        try jsonOf(a, f, .columns),
    );
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeNdjson(&aw.writer, try df.select(a, f, &.{ "i", "b" }));
    try testing.expectEqualStrings("{\"i\":1,\"b\":true}\n{\"i\":null,\"b\":null}\n", aw.written());
    try testing.expectEqualStrings("[]", try jsonOf(a, try df.clear(a, f, 0), .records));
    try testing.expectEqualStrings("{\"i\":[],\"f\":[],\"b\":[],\"s\":[],\"d\":[]}", try jsonOf(a, try df.clear(a, f, 0), .columns));
    // bad UTF-8 and controls give a valid document
    const bad = try df.readCsv(a, "s\nx\xffy\x01\n", .{});
    const j = try jsonOf(a, bad, .records);
    try testing.expectEqualStrings("[{\"s\":\"x\xEF\xBF\xBDy\\u0001\"}]", j);
    try testing.expect(std.unicode.utf8ValidateSlice(j));
    _ = try std.json.parseFromSliceLeaky(std.json.Value, a, j, .{});
}

test "format: aligned text, elided rows and columns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "i,f,s\n1,1.5,a\n,2,\"b|c\"\n300,0.25,\n", .{});
    try testing.expectEqualStrings("   i    f    s\n   1  1.5    a\nnull  2.0  b|c\n 300 0.25 null\n", try df.format(a, f, .{}));
    var big: std.ArrayList(u8) = .empty;
    try big.appendSlice(a, "a,b,c,d\n");
    for (0..30) |i| try big.print(a, "{d},{d},{d},{d}\n", .{ i, i * 2, i * 3, i * 4 });
    const g = try df.readCsv(a, big.items, .{});
    try testing.expectEqualStrings(
        " a …   d\n 0 …   0\n 1 …   4\n 2 …   8\n … …   …\n28 … 112\n29 … 116\n",
        try df.format(a, g, .{ .max_rows = 5, .max_cols = 2 }),
    );
    try testing.expectEqualStrings("shape: (30, 4)\n  a   b   c   d\nint int int int\n  …   …   …   …\n", try df.format(a, g, .{ .max_rows = 0, .show_shape = true, .show_dtypes = true }));
    const long = try df.readCsv(a, "s\n0123456789012345678901234567890123456789\n", .{});
    try testing.expectEqualStrings("                               s\n0123456789012345678901234567890…\n", try df.format(a, long, .{}));
}

test "toMarkdown: a pipe table" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "item,qty\nspam,42\neggs,451\n\"a|b\",\n", .{});
    try testing.expectEqualStrings(
        "| item   |   qty |\n|:-------|------:|\n| spam   |    42 |\n| eggs   |   451 |\n| a\\|b   |  null |\n",
        try df.toMarkdown(a, f, .{}),
    );
}

test "writeCsv: extreme floats under a float precision are written, never lost" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fb = try df.FrameBuilder.init(a, &.{.{ .name = "f", .type = .float }}, 4);
    for ([_]f64{ 1.7976931348623157e308, -1e300, 5e-324, 0.5 }) |x| try fb.appendRow(&.{.{ .float = x }});
    const f = try fb.toOwned();
    for ([_]u8{ 0, 2, 22, 255 }) |p| {
        const out = try csvOf(a, f, .{ .header = false, .float_precision = p });
        var lines = std.mem.splitScalar(u8, out, '\n');
        var n: usize = 0;
        while (lines.next()) |l| {
            if (l.len == 0) continue;
            try testing.expect(l.len >= 1);
            n += 1;
        }
        try testing.expectEqual(@as(usize, 4), n);
    }
}
