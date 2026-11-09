// SPDX-License-Identifier: MIT
//! Replays `oracle3_io_vectors.json`: what pandas 3.1.0 and polars 2.1.0 answered to
//! `read_csv`, `to_csv`/`write_csv` and the JSON writers (`tools/oracle3_io.py` asked the
//! engines; no line of this module is consulted there). The expected values are the
//! engines' alone, so a failure is a difference from them. Where the engines disagree the
//! vector carries a `label` and the engine followed; the other engine's answer is kept in
//! `other`/`pandas`/`polars`.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const ColumnType = df.ColumnType;
const J = std.json.Value;

const vectors = @embedFile("oracle3_io_vectors.json");

fn jget(o: J, k: []const u8) ?J {
    const v = o.object.get(k) orelse return null;
    return if (v == .null) null else v;
}

fn kindOf(s: []const u8) ColumnType {
    return std.meta.stringToEnum(ColumnType, s).?;
}

/// Cases where the engines agree (or one is followed) and this module still differs on
/// purpose; each is asserted by hand below, so it must still differ from the vector.
const read_ours = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "read-infer-big", .why = "9223372036854775808 does not fit i64: text here (pandas uint64, polars Int128)" },
    .{ .id = "read-infer-u64", .why = "18446744073709551615 does not fit i64: text here (pandas uint64, polars Int128)" },
    .{ .id = "read-infer-bigneg", .why = "-9223372036854775809 does not fit i64: text here (pandas object, polars Int128)" },
};

/// One-column files whose polars answer has a null *row* where the file has a blank line:
/// csvstream, like pandas, skips blank lines: the rows expected are polars' without its
/// all-null rows (every such row in these files is a blank line).
const blank_line_ids = [_][]const u8{ "read-infer-intna", "read-infer-boolna", "read-infer-emptyfield", "read-opts-nullcol-int" };

fn isBlankLineCase(id: []const u8) bool {
    for (blank_line_ids) |b| if (std.mem.eql(u8, b, id)) return true;
    return false;
}

fn ourRead(id: []const u8) ?[]const u8 {
    for (read_ours) |k| if (std.mem.eql(u8, k.id, id)) return k.why;
    return null;
}

fn strList(a: std.mem.Allocator, v: J) ![]const []const u8 {
    const list = try a.alloc([]const u8, v.array.items.len);
    for (v.array.items, list) |x, *l| l.* = x.string;
    return list;
}

fn readOptions(a: std.mem.Allocator, o: J) !df.CsvReadOptions {
    var opts: df.CsvReadOptions = .{};
    if (jget(o, "delimiter")) |v| opts.delimiter = v.string[0];
    if (jget(o, "quote")) |v| opts.quote = v.string[0];
    if (jget(o, "has_header")) |v| opts.has_header = v.bool;
    if (jget(o, "skip_rows")) |v| opts.skip_rows = @intCast(v.integer);
    if (jget(o, "n_rows")) |v| opts.n_rows = @intCast(v.integer);
    if (jget(o, "comment")) |v| opts.comment = v.string[0];
    if (jget(o, "infer_types")) |v| opts.infer_types = v.bool;
    if (jget(o, "date_cols") != null) opts.parse_dates = true;
    if (jget(o, "null_values")) |v| {
        const list = try a.alloc([]const u8, v.array.items.len);
        for (v.array.items, list) |x, *l| l.* = x.string;
        opts.null_values = list;
    }
    if (jget(o, "columns")) |v| {
        const list = try a.alloc([]const u8, v.array.items.len);
        for (v.array.items, list) |x, *l| l.* = x.string;
        opts.columns = list;
    }
    if (jget(o, "names")) |v| {
        const list = try a.alloc([]const u8, v.array.items.len);
        for (v.array.items, list) |x, *l| l.* = x.string;
        opts.names = list;
    }
    // dataframe S2 options
    if (jget(o, "thousands")) |v| opts.thousands = v.string[0];
    if (jget(o, "decimal")) |v| opts.decimal = v.string[0];
    if (jget(o, "true_values")) |v| opts.true_values = try strList(a, v);
    if (jget(o, "false_values")) |v| opts.false_values = try strList(a, v);
    if (jget(o, "column_null_values")) |v| {
        const list = try a.alloc(df.ColumnNulls, v.object.count());
        var it = v.object.iterator();
        var i: usize = 0;
        while (it.next()) |e| : (i += 1) list[i] = .{ .name = e.key_ptr.*, .values = try strList(a, e.value_ptr.*) };
        opts.column_null_values = list;
    }
    if (jget(o, "na_filter")) |v| opts.na_filter = v.bool;
    if (jget(o, "skipinitialspace")) |v| opts.skipinitialspace = v.bool;
    if (jget(o, "skipfooter")) |v| opts.skipfooter = @intCast(v.integer);
    if (jget(o, "skip_rows_after_header")) |v| opts.skip_rows_after_header = @intCast(v.integer);
    if (jget(o, "row_index_name")) |v| opts.row_index_name = v.string;
    if (jget(o, "row_index_offset")) |v| opts.row_index_offset = v.integer;
    if (jget(o, "on_bad_lines")) |v| opts.on_bad_lines = std.meta.stringToEnum(df.BadLines, v.string).?;
    if (jget(o, "date_format")) |v| opts.date_format = v.string;
    if (jget(o, "escape_char")) |v| opts.escape_char = v.string[0];
    if (jget(o, "double_quote")) |v| opts.double_quote = v.bool;
    if (jget(o, "empty_string_is_null")) |v| opts.empty_string_is_null = v.bool;
    if (jget(o, "types")) |v| {
        const list = try a.alloc(df.TypeOverride, v.object.count());
        var it = v.object.iterator();
        var i: usize = 0;
        while (it.next()) |e| : (i += 1) list[i] = .{ .name = e.key_ptr.*, .type = kindOf(e.value_ptr.string) };
        opts.types = list;
    }
    return opts;
}

fn cellMatches(kind: ColumnType, want: J, got: Value) bool {
    switch (want) {
        .null => return got == .null or (got == .float and std.math.isNan(got.float)),
        .bool => |b| return got == .bool and got.bool == b,
        .integer => |i| return switch (got) {
            .int => |g| g == i,
            .float => |g| g == @as(f64, @floatFromInt(i)),
            else => false,
        },
        .float => |x| return switch (got) {
            .float => |g| g == x or @abs(g - x) <= 1e-9 * @max(@abs(x), @abs(g)),
            .int => |g| @as(f64, @floatFromInt(g)) == x, // an int column that pandas made float
            else => false,
        },
        .string => |s| {
            if (kind == .float and got == .float) {
                if (std.mem.eql(u8, s, "inf")) return std.math.isInf(got.float) and got.float > 0;
                if (std.mem.eql(u8, s, "-inf")) return std.math.isInf(got.float) and got.float < 0;
                if (std.mem.eql(u8, s, "NaN")) return std.math.isNan(got.float);
            }
            return got == .text and std.mem.eql(u8, got.text, s);
        },
        else => return false,
    }
}

fn hasNull(rows: []const J, j: usize) bool {
    for (rows) |r| if (r.array.items[j] == .null) return true;
    return false;
}

fn allNull(rows: []const J, j: usize) bool {
    for (rows) |r| if (r.array.items[j] != .null) return false;
    return true;
}

test "oracle3 io: read_csv against pandas and polars" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const cases = doc.object.get("read").?.array.items;
    var checked: usize = 0;
    var errors: usize = 0;
    for (cases) |c| {
        const id = jget(c, "id").?.string;
        const text = jget(c, "csv").?.string;
        const opts = try readOptions(a, c.object.get("opts").?);
        const res = df.readCsv(a, text, opts);
        if (jget(c, "expect_error") != null) {
            if (res) |_| {
                std.debug.print("{s}: expected an error\n", .{id});
                return error.TestUnexpectedResult;
            } else |_| {}
            errors += 1;
            continue;
        }
        const got = res catch |e| {
            std.debug.print("{s}: error.{s}\n", .{ id, @errorName(e) });
            return e;
        };
        if (ourRead(id)) |_| {
            // The column is text, with the file's own digits.
            try testing.expectEqual(ColumnType.text, got.columns[0].type);
            var lines = std.mem.splitScalar(u8, text, '\n');
            _ = lines.next();
            var ri: usize = 0;
            while (lines.next()) |l| : (ri += 1) {
                if (l.len == 0) continue;
                try testing.expectEqualStrings(l, got.cell(ri, "c").?.text);
            }
            // and it must really differ from the engines' int
            var engine_int = false;
            for ([_][]const u8{ "pandas", "polars" }) |en| if (jget(c, en)) |eng| {
                if (std.mem.eql(u8, "int", eng.object.get("kinds").?.array.items[0].string)) engine_int = true;
            };
            try testing.expect(engine_int);
            checked += 1;
            continue;
        }
        const exp = c.object.get("expect") orelse {
            std.debug.print("{s}: no expectation\n", .{id});
            return error.TestUnexpectedResult;
        };
        const cols = exp.object.get("columns").?.array.items;
        const kinds = exp.object.get("kinds").?.array.items;
        var rows = exp.object.get("rows").?.array.items;
        if (isBlankLineCase(id)) {
            var kept: std.ArrayList(J) = .empty;
            for (rows) |r| if (!allNull(&.{r}, 0)) try kept.append(a, r);
            rows = kept.items;
        }
        errdefer std.debug.print("case {s}\n", .{id});
        try testing.expectEqual(cols.len, got.columns.len);
        try testing.expectEqual(rows.len, got.len);
        for (cols, kinds, 0..) |name, k, j| {
            try testing.expectEqualStrings(name.string, got.columns[j].name);
            // A column of nothing but nulls has no type to tell: text here (polars), float64 in pandas.
            if (!allNull(rows, j)) {
                const want = kindOf(k.string);
                // pandas turns an int column with a missing cell into float64 (NaN); here, as in
                // polars, it stays int with a null: the same numbers, a different type.
                const int_with_hole = want == .float and got.columns[j].type == .int and hasNull(rows, j);
                if (want != got.columns[j].type and !int_with_hole) {
                    std.debug.print("{s}: column {s} is {s}, want {s}\n", .{ id, name.string, @tagName(got.columns[j].type), k.string });
                    return error.TestUnexpectedResult;
                }
            }
            for (rows, 0..) |r, ri| {
                const gv = got.data[j].get(ri);
                if (!cellMatches(kindOf(k.string), r.array.items[j], gv)) {
                    std.debug.print("{s}: column {s} row {d}: want {any}, got {any}\n", .{ id, name.string, ri, r.array.items[j], gv });
                    return error.TestUnexpectedResult;
                }
            }
        }
        checked += 1;
    }
    try testing.expect(checked + errors == cases.len);
    try testing.expect(errors >= 4);
}

fn tableFrame(a: std.mem.Allocator, t: J) !Frame {
    const cj = t.object.get("columns").?.array.items;
    const cols = try a.alloc(df.Column, cj.len);
    for (cj, cols) |c, *o| o.* = .{ .name = c.object.get("name").?.string, .type = kindOf(c.object.get("type").?.string) };
    var fb = try df.FrameBuilder.init(a, cols, 0);
    const cells = try a.alloc(Value, cols.len);
    for (t.object.get("rows").?.array.items) |r| {
        for (r.array.items, cells, cols) |v, *cell, c| {
            cell.* = switch (v) {
                .null => .null,
                .bool => |b| .{ .bool = b },
                .integer => |i| if (c.type == .float) .{ .float = @floatFromInt(i) } else .{ .int = i },
                .float => |x| .{ .float = x },
                .string => |s| if (c.type == .float)
                    (if (std.mem.eql(u8, s, "NaN")) Value{ .float = std.math.nan(f64) } else if (std.mem.eql(u8, s, "inf")) Value{ .float = std.math.inf(f64) } else Value{ .float = -std.math.inf(f64) })
                else
                    .{ .text = s },
                else => unreachable,
            };
        }
        try fb.appendRow(cells);
    }
    return fb.toOwned();
}

test "oracle3 io: to_csv / write_csv against pandas and polars" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const cases = doc.object.get("write_csv").?.array.items;
    for (cases) |c| {
        const id = jget(c, "id").?.string;
        const f = try tableFrame(a, c.object.get("table").?);
        const o = c.object.get("opts").?;
        var opts: df.CsvWriteOptions = .{};
        if (jget(o, "delimiter")) |v| opts.delimiter = v.string[0];
        if (jget(o, "header")) |v| opts.header = v.bool;
        if (jget(o, "null_text")) |v| opts.null_text = v.string;
        if (jget(o, "crlf") != null) opts.line_terminator = .crlf;
        if (jget(o, "float_precision")) |v| opts.float_precision = @intCast(v.integer);
        if (jget(o, "quoting")) |v| opts.quote_style = std.meta.stringToEnum(df.CsvQuote, v.string).?;
        if (jget(o, "date_format")) |v| opts.date_format = v.string;
        if (jget(o, "datetime_format")) |v| opts.datetime_format = v.string;
        if (jget(o, "float_scientific")) |v| opts.float_scientific = v.bool;
        if (jget(o, "decimal")) |v| opts.decimal = v.string[0];
        if (jget(o, "columns")) |v| opts.columns = try strList(a, v);
        if (jget(o, "include_bom")) |v| opts.include_bom = v.bool;
        if (jget(o, "escape_char")) |v| opts.escape_char = v.string[0];
        if (jget(o, "double_quote")) |v| opts.double_quote = v.bool;
        var aw: std.Io.Writer.Allocating = .init(a);
        try df.writeCsv(a, &aw.writer, f, opts);
        // pandas (Python's csv) leaves a field bare when it only needs its quote escaped;
        // csvstream quotes it (`"q\"x"`), which reads back the same. Kept on purpose.
        const want = if (std.mem.eql(u8, id, "write-csv-s2-esc")) "s\n\"q\\\"x\"\nplain\n" else jget(c, "expect").?.string;
        testing.expectEqualStrings(want, aw.written()) catch |e| {
            std.debug.print("case {s}\n", .{id});
            return e;
        };
    }
}

fn jsonEq(want: J, got: J) bool {
    switch (want) {
        .null => return got == .null,
        .bool => |b| return got == .bool and got.bool == b,
        .integer => |i| return got == .integer and got.integer == i,
        .float => |x| return switch (got) {
            .float => |g| g == x or @abs(g - x) <= 1e-9 * @max(@abs(x), @abs(g)),
            else => false,
        },
        .string => |s| return got == .string and std.mem.eql(u8, got.string, s),
        .array => |arr| {
            if (got != .array or got.array.items.len != arr.items.len) return false;
            for (arr.items, got.array.items) |x, y| if (!jsonEq(x, y)) return false;
            return true;
        },
        .object => |o| {
            if (got != .object) return false;
            // `extDtype` is pandas' label for its extension dtypes (`Int64`, `str`) in the table
            // schema; there is nothing to write for it here.
            var n: usize = 0;
            var it = o.iterator();
            while (it.next()) |e| {
                if (std.mem.eql(u8, e.key_ptr.*, "extDtype")) continue;
                n += 1;
                const g = got.object.get(e.key_ptr.*) orelse return false;
                if (!jsonEq(e.value_ptr.*, g)) return false;
            }
            return got.object.count() == n;
        },
        else => return false,
    }
}

test "oracle3 io: to_json / write_json / write_ndjson against pandas and polars" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const cases = doc.object.get("write_json").?.array.items;
    for (cases) |c| {
        const id = jget(c, "id").?.string;
        const f = try tableFrame(a, c.object.get("table").?);
        const orients = c.object.get("orients").?;
        {
            var aw: std.Io.Writer.Allocating = .init(a);
            try df.writeJson(&aw.writer, f, .records);
            const got = try std.json.parseFromSliceLeaky(J, a, aw.written(), .{});
            if (!jsonEq(orients.object.get("records").?.object.get("expect").?, got)) {
                std.debug.print("case {s} records\n got {s}\n", .{ id, aw.written() });
                return error.TestUnexpectedResult;
            }
        }
        {
            var aw: std.Io.Writer.Allocating = .init(a);
            try df.writeJson(&aw.writer, f, .columns);
            const got = try std.json.parseFromSliceLeaky(J, a, aw.written(), .{});
            if (!jsonEq(orients.object.get("columns").?.object.get("expect").?, got)) {
                std.debug.print("case {s} columns\n got {s}\n", .{ id, aw.written() });
                return error.TestUnexpectedResult;
            }
        }
        inline for (.{ "split", "index", "values", "table" }) |name| if (orients.object.get(name)) |ov| {
            var aw: std.Io.Writer.Allocating = .init(a);
            try df.writeJson(&aw.writer, f, @field(df.JsonOrient, name));
            const got = try std.json.parseFromSliceLeaky(J, a, aw.written(), .{});
            if (!jsonEq(ov.object.get("expect").?, got)) {
                std.debug.print("case {s} {s}\n got {s}\n", .{ id, name, aw.written() });
                return error.TestUnexpectedResult;
            }
        };
        {
            var aw: std.Io.Writer.Allocating = .init(a);
            try df.writeNdjson(&aw.writer, f);
            var lines = std.mem.splitScalar(u8, aw.written(), '\n');
            const want = orients.object.get("ndjson").?.object.get("expect").?.array.items;
            var n: usize = 0;
            while (lines.next()) |l| {
                if (l.len == 0) continue;
                const got = try std.json.parseFromSliceLeaky(J, a, l, .{});
                try testing.expect(n < want.len and jsonEq(want[n], got));
                n += 1;
            }
            try testing.expectEqual(want.len, n);
            try testing.expect(aw.written().len == 0 or aw.written()[aw.written().len - 1] == '\n');
        }
    }
}

test "oracle3 io: to_json options and orients against pandas, byte for byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const cases = doc.object.get("write_json_opts").?.array.items;
    try testing.expect(cases.len >= 14);
    for (cases) |c| {
        const id = jget(c, "id").?.string;
        const f = try tableFrame(a, c.object.get("table").?);
        const o = c.object.get("opts").?;
        var opts: df.JsonWriteOptions = .{};
        if (jget(o, "force_ascii")) |v| opts.force_ascii = v.bool;
        if (jget(o, "indent")) |v| opts.indent = @intCast(v.integer);
        if (jget(o, "double_precision")) |v| opts.double_precision = @intCast(v.integer);
        if (jget(o, "date_format")) |v| opts.date_format = std.meta.stringToEnum(df.JsonDateFormat, v.string).?;
        if (jget(o, "date_unit")) |v| opts.date_unit = std.meta.stringToEnum(df.JsonDateUnit, v.string).?;
        const orient = std.meta.stringToEnum(df.JsonOrient, jget(c, "orient").?.string).?;
        var aw: std.Io.Writer.Allocating = .init(a);
        try df.writeJsonOpts(a, &aw.writer, f, orient, opts);
        testing.expectEqualStrings(jget(c, "expect").?.string, aw.written()) catch |e| {
            std.debug.print("case {s}\n", .{id});
            return e;
        };
    }
}

fn htmlOpts(o: J) df.HtmlOptions {
    var opts: df.HtmlOptions = .{};
    if (jget(o, "null_text")) |v| opts.null_text = v.string;
    if (jget(o, "float_precision")) |v| opts.float_precision = @intCast(v.integer);
    if (jget(o, "border")) |v| opts.border = @intCast(v.integer);
    if (jget(o, "classes")) |v| opts.classes = v.string;
    if (jget(o, "header")) |v| opts.header = v.bool;
    if (jget(o, "escape")) |v| opts.escape = v.bool;
    return opts;
}

test "oracle3 io: to_html(index=False) against pandas, byte for byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const cases = doc.object.get("html").?.array.items;
    try testing.expect(cases.len >= 8);
    for (cases) |c| {
        const id = jget(c, "id").?.string;
        const f = try tableFrame(a, c.object.get("table").?);
        const got = try df.toHtml(a, f, htmlOpts(c.object.get("opts").?));
        testing.expectEqualStrings(jget(c, "expect").?.string, std.mem.trimEnd(u8, got, "\n")) catch |e| {
            std.debug.print("case {s}\n", .{id});
            return e;
        };
    }
}

test "oracle3 io: glimpse against polars, byte for byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const cases = doc.object.get("glimpse").?.array.items;
    try testing.expect(cases.len >= 3);
    for (cases) |c| {
        const id = jget(c, "id").?.string;
        const f = try tableFrame(a, c.object.get("table").?);
        var opts: df.GlimpseOptions = .{};
        if (jget(c.object.get("opts").?, "max_items")) |v| opts.max_items = @intCast(v.integer);
        const got = try df.glimpse(a, f, opts);
        testing.expectEqualStrings(jget(c, "expect").?.string, std.mem.trimEnd(u8, got, "\n")) catch |e| {
            std.debug.print("case {s}\n", .{id});
            return e;
        };
    }
}
