// SPDX-License-Identifier: MIT
//! Input/output options added in dataframe S2 (2026-11-09): `readCsv`'s number, bool, null,
//! row and date options, `writeCsv`'s formats, `writeJsonOpts` and the JSON orients, `toHtml`,
//! `glimpse`. Where pandas or polars define the answer the vectors are in
//! `oracle3_io_test.zig`; the hand-written cases here pin the documented behaviour.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const encoding = @import("encoding");
const bzip2 = @import("bzip2");
const Frame = df.Frame;
const Value = df.Value;

fn arena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

fn expectInt(f: Frame, row: usize, name: []const u8, want: i64) !void {
    const got = f.cell(row, name).?;
    try testing.expect(got == .int);
    try testing.expectEqual(want, got.int);
}

fn expectFloat(f: Frame, row: usize, name: []const u8, want: f64) !void {
    const got = f.cell(row, name).?;
    try testing.expect(got == .float);
    try testing.expectEqual(want, got.float);
}

fn expectText(f: Frame, row: usize, name: []const u8, want: []const u8) !void {
    const got = f.cell(row, name).?;
    try testing.expect(got == .text);
    try testing.expectEqualStrings(want, got.text);
}

fn expectNull(f: Frame, row: usize, name: []const u8) !void {
    try testing.expect(f.cell(row, name).? == .null);
}

fn csvOut(a: std.mem.Allocator, f: Frame, o: df.CsvWriteOptions) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &aw.writer, f, o);
    return aw.written();
}

fn jsonOut(a: std.mem.Allocator, f: Frame, orient: df.JsonOrient, o: df.JsonWriteOptions) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJsonOpts(a, &aw.writer, f, orient, o);
    return aw.written();
}

// ── readCsv ─────────────────────────────────────────────────────────────────

test "readCsv: thousands and decimal (pandas thousands/decimal, polars decimal_comma)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "i;f;t\n1.234;1.234,5;x\n-2.000;2,25;y\n", .{ .delimiter = ';', .thousands = '.', .decimal = ',' });
    try testing.expectEqual(df.ColumnType.int, f.columnType("i").?);
    try expectInt(f, 0, "i", 1234);
    try expectInt(f, 1, "i", -2000);
    try testing.expectEqual(df.ColumnType.float, f.columnType("f").?);
    try expectFloat(f, 0, "f", 1234.5);
    try expectFloat(f, 1, "f", 2.25);
    // A text column keeps its text, thousands byte and all.
    const g = try df.readCsv(a, "t\n\"1,234\"\nabc\n", .{ .thousands = ',' });
    try testing.expectEqual(df.ColumnType.text, g.columnType("t").?);
    try expectText(g, 0, "t", "1,234");
    // With a decimal comma a '.' is not a decimal point: the column is text.
    const h = try df.readCsv(a, "v\n\"1,5\"\n\"2.5\"\n", .{ .decimal = ',' });
    try testing.expectEqual(df.ColumnType.text, h.columnType("v").?);
    // A decimal comma on its own (comma delimiter: quoted cells).
    const k = try df.readCsv(a, "v\n\"1,5\"\n\"2,5\"\n", .{ .decimal = ',' });
    try expectFloat(k, 1, "v", 2.5);
    try testing.expectError(error.BadOptions, df.readCsv(a, "a\n1\n", .{ .thousands = ',', .decimal = ',' }));
    try testing.expectError(error.BadOptions, df.readCsv(a, "a\n1\n", .{ .decimal = 0 }));
    // A fixed type reads through the same rules.
    const t = try df.readCsv(a, "v\n\"1,5\"\n", .{ .decimal = ',', .types = &.{.{ .name = "v", .type = .decimal }} });
    try testing.expect(t.cell(0, "v").? == .decimal);
}

test "readCsv: true_values and false_values" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a,b,c\nyes,1,yes\nno,0,maybe\nyes,,no\n", .{ .true_values = &.{ "yes", "1" }, .false_values = &.{ "no", "0" } });
    try testing.expectEqual(df.ColumnType.bool, f.columnType("a").?);
    try testing.expect(f.cell(0, "a").?.bool);
    try testing.expect(!f.cell(1, "a").?.bool);
    try testing.expectEqual(df.ColumnType.bool, f.columnType("b").?);
    try testing.expect(f.cell(0, "b").?.bool);
    try expectNull(f, 2, "b");
    try testing.expectEqual(df.ColumnType.text, f.columnType("c").?); // "maybe" is neither
    // The usual spellings stay bool alongside the listed ones.
    const g = try df.readCsv(a, "a\nTrue\nyes\n", .{ .true_values = &.{"yes"} });
    try testing.expectEqual(df.ColumnType.bool, g.columnType("a").?);
}

test "readCsv: null markers, per column markers, na_filter, empty_string_is_null" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a,b\n1,x\n-,y\n3,missing\n", .{ .extra_null_values = &.{"-"}, .column_null_values = &.{.{ .name = "b", .values = &.{"missing"} }} });
    try testing.expectEqual(df.ColumnType.int, f.columnType("a").?);
    try expectNull(f, 1, "a");
    try expectNull(f, 2, "b");
    try expectText(f, 1, "b", "y");
    // `NA` stays a marker (the pandas default list is kept) and `-` is added.
    const g = try df.readCsv(a, "a\nNA\n-\n1\n", .{ .extra_null_values = &.{"-"} });
    try expectNull(g, 0, "a");
    try expectNull(g, 1, "a");
    // na_filter off: nothing is null; a hole makes the column text.
    const h = try df.readCsv(a, "a,b\n1,NA\n,2\n", .{ .na_filter = false });
    try testing.expectEqual(df.ColumnType.text, h.columnType("a").?);
    try expectText(h, 1, "a", "");
    try expectText(h, 0, "b", "NA");
    // empty_string_is_null off: the empty cell is an empty text, `NA` is still null.
    const k = try df.readCsv(a, "a,b\nx,NA\n,y\n", .{ .empty_string_is_null = false });
    try expectText(k, 1, "a", "");
    try expectNull(k, 0, "b");
    try testing.expectError(error.NoSuchColumn, df.readCsv(a, "a\n1\n", .{ .column_null_values = &.{.{ .name = "zz", .values = &.{"x"} }} }));
}

test "readCsv: skipinitialspace, skipfooter, skip_rows_after_header, row index" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a, b\n1, \"x,y\"\n2,  z\n", .{ .skipinitialspace = true });
    try testing.expectEqual(@as(usize, 2), f.len);
    try expectText(f, 0, "b", "x,y");
    try expectText(f, 1, "b", "z");
    const g = try df.readCsv(a, "a\n1\n2\n3\n4\n", .{ .skipfooter = 2 });
    try testing.expectEqual(@as(usize, 2), g.len);
    try expectInt(g, 1, "a", 2);
    const h = try df.readCsv(a, "a\n1\n2\n3\n4\n", .{ .skip_rows_after_header = 1, .skipfooter = 1 });
    try testing.expectEqual(@as(usize, 2), h.len);
    try expectInt(h, 0, "a", 2);
    try expectInt(h, 1, "a", 3);
    // More footer than rows: nothing is left.
    const k = try df.readCsv(a, "a\n1\n2\n", .{ .skipfooter = 5 });
    try testing.expectEqual(@as(usize, 0), k.len);
    // Comments and blank lines are not records.
    const c = try df.readCsv(a, "a\n1\n#x\n\n2\n3\n", .{ .comment = '#', .skipfooter = 1 });
    try testing.expectEqual(@as(usize, 2), c.len);
    // No header: the first data row is skipped too.
    const nh = try df.readCsv(a, "1\n2\n3\n", .{ .has_header = false, .skip_rows_after_header = 1 });
    try expectInt(nh, 0, "column_0", 2);
    const r = try df.readCsv(a, "a\nx\ny\n", .{ .row_index_name = "i", .row_index_offset = 10 });
    try testing.expectEqualStrings("i", r.columns[0].name);
    try expectInt(r, 0, "i", 10);
    try expectInt(r, 1, "i", 11);
    try expectText(r, 1, "a", "y");
    try testing.expectError(error.BadOptions, df.readCsv(a, "i\n1\n", .{ .row_index_name = "i" }));
    const e = try df.readCsv(a, "a\n", .{ .row_index_name = "i" });
    try testing.expectEqual(@as(usize, 0), e.len);
    try testing.expectEqual(@as(usize, 2), e.columns.len);
}

test "readCsv: on_bad_lines skip counts, error is the default" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const text = "a,b\n1,2\n3,4,5\n6,7\n8,9,10,11\n";
    try testing.expectError(error.RaggedRow, df.readCsv(a, text, .{}));
    var n: usize = 99;
    const f = try df.readCsv(a, text, .{ .on_bad_lines = .skip, .bad_lines_skipped = &n });
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expectEqual(@as(usize, 2), n);
    try expectInt(f, 1, "a", 6);
    // The same through the cell-by-cell reader.
    var n2: usize = 99;
    const g = try df.readCsv(a, text, .{ .on_bad_lines = .skip, .bad_lines_skipped = &n2, .thousands = ',' });
    try testing.expectEqual(@as(usize, 2), g.len);
    try testing.expectEqual(@as(usize, 2), n2);
    // n_rows counts kept rows.
    const h = try df.readCsv(a, text, .{ .on_bad_lines = .skip, .n_rows = 2 });
    try testing.expectEqual(@as(usize, 2), h.len);
}

test "readCsv: date_format for parse_dates" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "d,t\n31/12/2021,2021-12-31 10:30\n01/02/2022,2022-01-01 00:00\n", .{
        .parse_dates = true,
        .date_format = "%d/%m/%Y",
        .types = &.{.{ .name = "t", .type = .text }},
    });
    try testing.expectEqual(df.ColumnType.date, f.columnType("d").?);
    try expectText(f, 0, "d", "2021-12-31");
    try expectText(f, 1, "d", "2022-02-01");
    const g = try df.readCsv(a, "t\n2021-12-31 10:30\n", .{ .parse_dates = true, .date_format = "%Y-%m-%d %H:%M" });
    try testing.expectEqual(df.ColumnType.timestamp, g.columnType("t").?);
    try expectInt(g, 0, "t", 1640946600000000);
    // A cell that does not match: the column is text.
    const h = try df.readCsv(a, "d\n31/12/2021\n2021-12-31\n", .{ .parse_dates = true, .date_format = "%d/%m/%Y" });
    try testing.expectEqual(df.ColumnType.text, h.columnType("d").?);
    // Without parse_dates the layout does nothing.
    const k = try df.readCsv(a, "d\n31/12/2021\n", .{ .date_format = "%d/%m/%Y" });
    try testing.expectEqual(df.ColumnType.text, k.columnType("d").?);
    try testing.expectError(error.BadOptions, df.readCsv(a, "d\n1\n", .{ .parse_dates = true, .date_format = "%Q" }));
}

test "readCsv: escape_char and double_quote" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a\n\"x\\\"y\"\n\"p,q\"\n", .{ .escape_char = '\\', .double_quote = false });
    try expectText(f, 0, "a", "x\"y");
    try expectText(f, 1, "a", "p,q");
    const g = try df.readCsv(a, "a\n\"x\"\"y\"\n", .{});
    try expectText(g, 0, "a", "x\"y");
}

// ── writeCsv ────────────────────────────────────────────────────────────────

test "writeCsv: date and datetime layouts, columns, bom" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "d,t,n\n2021-12-31,2021-12-31T10:30:00Z,1\n,,2\n", .{
        .parse_dates = true,
        .types = &.{ .{ .name = "d", .type = .date }, .{ .name = "t", .type = .timestamp } },
    });
    const s = try csvOut(a, f, .{ .date_format = "%d/%m/%Y", .datetime_format = "%H:%M on %b %d" });
    try testing.expectEqualStrings("d,t,n\n31/12/2021,10:30 on Dec 31,1\n,,2\n", s);
    const c = try csvOut(a, f, .{ .columns = &.{ "n", "d" }, .include_bom = true });
    try testing.expectEqualStrings("\xEF\xBB\xBFn,d\n1,2021-12-31\n2,\n", c);
    try testing.expectError(error.NoSuchColumn, csvOut(a, f, .{ .columns = &.{"zz"} }));
    try testing.expectError(error.BadOptions, csvOut(a, f, .{ .date_format = "%Q" }));
    const none = try csvOut(a, f, .{ .columns = &.{} });
    try testing.expectEqualStrings("", none);
}

test "writeCsv: float_scientific, float_precision, decimal comma" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "x\n1234.5\n0.00001\n2\n", .{ .types = &.{.{ .name = "x", .type = .float }} });
    try testing.expectEqualStrings("x\n1.2345e3\n1e-5\n2e0\n", try csvOut(a, f, .{ .float_scientific = true }));
    try testing.expectEqualStrings("x\n1234.5\n0.00001\n2\n", try csvOut(a, f, .{ .float_scientific = false }));
    try testing.expectEqualStrings("x\n1.23e3\n1.00e-5\n2.00e0\n", try csvOut(a, f, .{ .float_scientific = true, .float_precision = 2 }));
    try testing.expectEqualStrings("x\n1234.50\n0.00\n2.00\n", try csvOut(a, f, .{ .float_scientific = false, .float_precision = 2 }));
    try testing.expectEqualStrings("x\n\"1234,5\"\n1e-05\n\"2,0\"\n", try csvOut(a, f, .{ .decimal = ',' }));
    try testing.expectEqualStrings("x\n1234,5\n1e-05\n2,0\n", try csvOut(a, f, .{ .decimal = ',', .delimiter = ';' }));
    try testing.expectError(error.BadOptions, csvOut(a, f, .{ .decimal = 0 }));
}

test "writeCsv: escape_char with double_quote off, and the round trip" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a\n\"x\"\"y\"\n", .{});
    const s = try csvOut(a, f, .{ .double_quote = false, .escape_char = '\\' });
    try testing.expectEqualStrings("a\n\"x\\\"y\"\n", s);
    const back = try df.readCsv(a, s, .{ .double_quote = false, .escape_char = '\\' });
    try expectText(back, 0, "a", "x\"y");
    try testing.expectError(error.BadOptions, csvOut(a, f, .{ .double_quote = false }));
}

// ── JSON ────────────────────────────────────────────────────────────────────

const small = "a,b\n1,x\n2,y\n";

test "writeJsonOpts: split, index, values, table" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, small, .{});
    try testing.expectEqualStrings("{\"columns\":[\"a\",\"b\"],\"index\":[0,1],\"data\":[[1,\"x\"],[2,\"y\"]]}", try jsonOut(a, f, .split, .{}));
    try testing.expectEqualStrings("{\"0\":{\"a\":1,\"b\":\"x\"},\"1\":{\"a\":2,\"b\":\"y\"}}", try jsonOut(a, f, .index, .{}));
    try testing.expectEqualStrings("[[1,\"x\"],[2,\"y\"]]", try jsonOut(a, f, .values, .{}));
    try testing.expectEqualStrings(
        "{\"schema\":{\"fields\":[{\"name\":\"index\",\"type\":\"integer\"},{\"name\":\"a\",\"type\":\"integer\"},{\"name\":\"b\",\"type\":\"string\"}]," ++
            "\"primaryKey\":[\"index\"],\"pandas_version\":\"1.4.0\"},\"data\":[{\"index\":0,\"a\":1,\"b\":\"x\"},{\"index\":1,\"a\":2,\"b\":\"y\"}]}",
        try jsonOut(a, f, .table, .{}),
    );
    // writeJson keeps working and agrees.
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&aw.writer, f, .values);
    try testing.expectEqualStrings("[[1,\"x\"],[2,\"y\"]]", aw.written());
    // No rows.
    const e = try df.readCsv(a, "a,b\n", .{});
    try testing.expectEqualStrings("{\"columns\":[\"a\",\"b\"],\"index\":[],\"data\":[]}", try jsonOut(a, e, .split, .{}));
    try testing.expectEqualStrings("{}", try jsonOut(a, e, .index, .{}));
}

test "writeJsonOpts: indent, force_ascii, double_precision" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, small, .{});
    try testing.expectEqualStrings("[\n  {\n    \"a\":1,\n    \"b\":\"x\"\n  },\n  {\n    \"a\":2,\n    \"b\":\"y\"\n  }\n]", try jsonOut(a, f, .records, .{ .indent = 2 }));
    const e = try df.readCsv(a, "a\n", .{});
    try testing.expectEqualStrings("[]", try jsonOut(a, e, .records, .{ .indent = 4 }));
    // A bracket or comma inside a string does not move the layout.
    const s = try df.readCsv(a, "a\n\"[x, \"\"{\"\n", .{});
    try testing.expectEqualStrings("[\n {\n  \"a\":\"[x, \\\"{\"\n }\n]", try jsonOut(a, s, .records, .{ .indent = 1 }));
    try testing.expectError(error.OutputTooLarge, jsonOut(a, f, .records, .{ .indent = 2, .max_indent_bytes = 5 }));

    const u = try df.readCsv(a, "a\n\xC3\xA9\xF0\x9F\x98\x80z\n", .{});
    try testing.expectEqualStrings("[{\"a\":\"\\u00e9\\ud83d\\ude00z\"}]", try jsonOut(a, u, .records, .{ .force_ascii = true }));
    try testing.expectEqualStrings("[{\"a\":\"\xC3\xA9\xF0\x9F\x98\x80z\"}]", try jsonOut(a, u, .records, .{}));
    const fl = try df.readCsv(a, "x\n0.30000000000000004\n2\n1.2345678901234\n", .{ .types = &.{.{ .name = "x", .type = .float }} });
    try testing.expectEqualStrings("[[0.3],[2.0],[1.2345678901]]", try jsonOut(a, fl, .values, .{ .double_precision = 10 }));
    try testing.expectEqualStrings("{\"x\":[0.3,2.0,1.2]}", try jsonOut(a, fl, .columns, .{ .double_precision = 1 }));
}

test "writeJsonOpts: epoch dates in the chosen unit" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "t,d\n2021-01-02T03:04:05.678Z,2021-01-02\n", .{
        .parse_dates = true,
        .types = &.{ .{ .name = "t", .type = .timestamp }, .{ .name = "d", .type = .date } },
    });
    try testing.expectEqualStrings("[[1609556645678,1609545600000]]", try jsonOut(a, f, .values, .{ .date_format = .epoch }));
    try testing.expectEqualStrings("[[1609556645,1609545600]]", try jsonOut(a, f, .values, .{ .date_format = .epoch, .date_unit = .s }));
    try testing.expectEqualStrings("[[1609556645678000,1609545600000000]]", try jsonOut(a, f, .values, .{ .date_format = .epoch, .date_unit = .us }));
    try testing.expectEqualStrings("[[1609556645678000000,1609545600000000000]]", try jsonOut(a, f, .values, .{ .date_format = .epoch, .date_unit = .ns }));
    try testing.expectEqualStrings("[[\"2021-01-02T03:04:05.678Z\",\"2021-01-02\"]]", try jsonOut(a, f, .values, .{}));
}

test "readJson: split, index, values, table" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const sp = try df.readJson(a, "{\"index\":[5,6],\"data\":[[1,\"x\"],[2,\"y\"]],\"columns\":[\"a\",\"b\"]}", .{ .orient = .split });
    try testing.expectEqual(@as(usize, 2), sp.len);
    try expectInt(sp, 1, "a", 2);
    try expectText(sp, 0, "b", "x");
    const sp0 = try df.readJson(a, "{\"columns\":[\"a\",\"b\"],\"index\":[],\"data\":[]}", .{ .orient = .split });
    try testing.expectEqual(@as(usize, 0), sp0.len);
    try testing.expectEqual(@as(usize, 2), sp0.columns.len);
    try testing.expectError(error.BadShape, df.readJson(a, "{\"columns\":[\"a\"],\"data\":[[1,2]]}", .{ .orient = .split }));
    try testing.expectError(error.BadShape, df.readJson(a, "{\"data\":[[1]]}", .{ .orient = .split }));
    try testing.expectError(error.BadShape, df.readJson(a, "{\"columns\":[\"a\",\"a\"],\"data\":[]}", .{ .orient = .split }));

    const ix = try df.readJson(a, "{\"0\":{\"a\":1,\"b\":\"x\"},\"1\":{\"a\":2}}", .{ .orient = .index });
    try testing.expectEqual(@as(usize, 2), ix.len);
    try expectInt(ix, 1, "a", 2);
    try expectNull(ix, 1, "b");

    const va = try df.readJson(a, "[[1,\"x\"],[2.5,\"y\",true]]", .{ .orient = .values });
    try testing.expectEqual(@as(usize, 3), va.columns.len);
    try testing.expectEqualStrings("column_2", va.columns[2].name);
    try expectFloat(va, 0, "column_0", 1);
    try expectNull(va, 0, "column_2");
    try testing.expectError(error.BadShape, df.readJson(a, "[1,2]", .{ .orient = .values }));

    const ta = try df.readJson(a, "{\"schema\":{\"fields\":[{\"name\":\"index\",\"type\":\"integer\"},{\"name\":\"a\",\"type\":\"integer\"}],\"primaryKey\":[\"index\"]},\"data\":[{\"index\":0,\"a\":7},{\"index\":1,\"a\":8}]}", .{ .orient = .table });
    try testing.expectEqual(@as(usize, 1), ta.columns.len);
    try expectInt(ta, 1, "a", 8);
    try testing.expectError(error.BadShape, df.readJson(a, "{\"schema\":{}}", .{ .orient = .table }));
}

test "JSON orients round trip through writeJsonOpts and readJson" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a,b,c\n1,x,1.5\n2,,2.5\n", .{});
    inline for (.{ .{ df.JsonOrient.split, df.JsonReadOrient.split }, .{ df.JsonOrient.index, df.JsonReadOrient.index }, .{ df.JsonOrient.table, df.JsonReadOrient.table }, .{ df.JsonOrient.records, df.JsonReadOrient.records }, .{ df.JsonOrient.columns, df.JsonReadOrient.columns } }) |pair| {
        const s = try jsonOut(a, f, pair[0], .{});
        const g = try df.readJson(a, s, .{ .orient = pair[1] });
        try testing.expectEqual(@as(usize, 2), g.len);
        try expectInt(g, 1, "a", 2);
        try expectNull(g, 1, "b");
        try expectFloat(g, 0, "c", 1.5);
    }
    const s = try jsonOut(a, f, .values, .{});
    const g = try df.readJson(a, s, .{ .orient = .values });
    try expectInt(g, 1, "column_0", 2);
}

test "readJson: epoch_dates and date_unit" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a, "[{\"t\":1609556645678,\"n\":1},{\"t\":null,\"n\":2}]", .{ .epoch_dates = &.{"t"} });
    try testing.expectEqual(df.ColumnType.timestamp, f.columnType("t").?);
    try expectInt(f, 0, "t", 1609556645678000);
    try expectNull(f, 1, "t");
    const g = try df.readJson(a, "[{\"t\":1609556645}]", .{ .epoch_dates = &.{"t"}, .date_unit = .s });
    try expectInt(g, 0, "t", 1609556645000000);
    const h = try df.readJson(a, "[{\"t\":1609556645678123456}]", .{ .epoch_dates = &.{"t"}, .date_unit = .ns });
    try expectInt(h, 0, "t", 1609556645678123);
    try testing.expectError(error.BadValue, df.readJson(a, "[{\"t\":\"x\"}]", .{ .epoch_dates = &.{"t"} }));
    try testing.expectError(error.BadValue, df.readJson(a, "[{\"t\":9223372036854775807}]", .{ .epoch_dates = &.{"t"} }));
}

// ── toHtml, glimpse ─────────────────────────────────────────────────────────

test "toHtml: pandas layout, escaping, na_rep, float precision" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, small, .{});
    const want =
        \\<table border="1" class="dataframe">
        \\  <thead>
        \\    <tr style="text-align: right;">
        \\      <th>a</th>
        \\      <th>b</th>
        \\    </tr>
        \\  </thead>
        \\  <tbody>
        \\    <tr>
        \\      <td>1</td>
        \\      <td>x</td>
        \\    </tr>
        \\    <tr>
        \\      <td>2</td>
        \\      <td>y</td>
        \\    </tr>
        \\  </tbody>
        \\</table>
        \\
    ;
    try testing.expectEqualStrings(want, try df.toHtml(a, f, .{}));
    const g = try df.readCsv(a, "n<&>,v\n\"<b>\"\"q\"\"&\",1.23456\n,\n", .{ .types = &.{.{ .name = "v", .type = .float }} });
    const s = try df.toHtml(a, g, .{ .float_precision = 2, .border = null, .classes = "wide" });
    try testing.expect(std.mem.startsWith(u8, s, "<table class=\"dataframe wide\">\n"));
    try testing.expect(std.mem.find(u8, s, "<th>n&lt;&amp;&gt;</th>") != null);
    try testing.expect(std.mem.find(u8, s, "<td>&lt;b&gt;&quot;q&quot;&amp;</td>") != null);
    try testing.expect(std.mem.find(u8, s, "<td>1.23</td>") != null);
    try testing.expect(std.mem.count(u8, s, "<td>NaN</td>") == 2);
    const raw = try df.toHtml(a, g, .{ .escape = false, .header = false, .null_text = "-" });
    try testing.expect(std.mem.find(u8, raw, "thead") == null);
    try testing.expect(std.mem.find(u8, raw, "<td><b>\"q\"&</td>") != null);
}

test "glimpse: polars layout" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readCsv(a, "a,longer,b\n1,x,true\n2,,false\n", .{});
    try testing.expectEqualStrings(
        "Rows: 2\nColumns: 3\n$ a       <i64> 1, 2\n$ longer  <str> 'x', null\n$ b      <bool> True, False\n",
        try df.glimpse(a, f, .{}),
    );
    var big: std.ArrayList(u8) = .empty;
    try big.appendSlice(a, "n\n");
    for (0..30) |i| try big.print(a, "{d}\n", .{i});
    const g = try df.readCsv(a, big.items, .{});
    try testing.expectEqualStrings("Rows: 30\nColumns: 1\n$ n <i64> 0, 1, 2\n", try df.glimpse(a, g, .{ .max_items = 3 }));
    try testing.expectEqualStrings("Rows: 30\nColumns: 1\n$ n <i64> 0, 1, 2, 3, 4, 5, 6, 7, 8, 9\n", try df.glimpse(a, g, .{}));
    try testing.expectEqualStrings("Rows: 30\nColumns: 1\n$ n <i64> …\n", try df.glimpse(a, g, .{ .max_width = 11 }));
}

// ── README: other encodings, compressed files ───────────────────────────────

test "README: a bzip2-compressed windows-1250 file through readCsv" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // What a file on disk holds: windows-1250 bytes, bzip2-compressed.
    const plain = "mesto;cena\nPlze\xF2;12,5\n\xC8esk\xE9 Bud\xECjovice;8,25\n";
    const bz = try bzip2.compress(a, plain, .{});

    // The README example, with `Reader.fixed` where a file reader would be.
    var file: std.Io.Reader = .fixed(bz);
    var buf: [4096]u8 = undefined;
    var dec = try bzip2.DecompressReader.init(a, &file, &buf, .{});
    defer dec.deinit();
    const raw = try dec.reader.allocRemaining(a, .limited(64 << 20));
    const utf8 = try encoding.decodeToUtf8(a, raw, .windows_1250);
    const f = try df.readCsv(a, utf8, .{ .delimiter = ';', .decimal = ',' });
    try testing.expectEqual(@as(usize, 2), f.len);
    try expectText(f, 1, "mesto", "\u{10C}esk\u{E9} Bud\u{11B}jovice");
    try expectFloat(f, 1, "cena", 8.25);

    // The decompressed UTF-8 can also be streamed straight into `readCsvReader`.
    var file2: std.Io.Reader = .fixed(try bzip2.compress(a, "a,b\n1,x\n", .{}));
    var dec2 = try bzip2.DecompressReader.init(a, &file2, &buf, .{});
    defer dec2.deinit();
    const g = try df.readCsvReader(a, &dec2.reader, .{});
    try expectInt(g, 0, "a", 1);
}

test "readCsv: two layout-parsed date columns of one row keep their own values" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // parse_dates: both columns inferred as dates (pass 1 and pass 2 both run the layout).
    const f = try df.readCsv(a, "a,b\n31/12/2021,01/02/2022\n15/03/2020,16/04/2019\n", .{ .parse_dates = true, .date_format = "%d/%m/%Y" });
    try testing.expectEqual(df.ColumnType.date, f.columnType("a").?);
    try testing.expectEqual(df.ColumnType.date, f.columnType("b").?);
    try expectText(f, 0, "a", "2021-12-31");
    try expectText(f, 0, "b", "2022-02-01");
    try expectText(f, 1, "a", "2020-03-15");
    try expectText(f, 1, "b", "2019-04-16");
    // A `types` override on both columns, plus a third, text column between them.
    const g = try df.readCsv(a, "a,m,b\n31/12/2021,x,01/02/2022\n01/01/1999,yy,31/10/2030\n", .{
        .parse_dates = true,
        .date_format = "%d/%m/%Y",
        .types = &.{ .{ .name = "a", .type = .date }, .{ .name = "b", .type = .date } },
    });
    try expectText(g, 0, "a", "2021-12-31");
    try expectText(g, 0, "b", "2022-02-01");
    try expectText(g, 1, "a", "1999-01-01");
    try expectText(g, 1, "b", "2030-10-31");
    // Timestamps: a date column and a timestamp column of different text lengths in one
    // row would need two layouts; with one layout both are timestamps.
    const h = try df.readCsv(a, "a,b\n2021-12-31 10:30,2022-02-01 00:00\n", .{ .parse_dates = true, .date_format = "%Y-%m-%d %H:%M" });
    try expectInt(h, 0, "a", 1640946600000000);
    try expectInt(h, 0, "b", 1643673600000000);
}
