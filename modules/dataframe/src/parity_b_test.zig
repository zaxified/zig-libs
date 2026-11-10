// SPDX-License-Identifier: MIT
//! Parity wave, agent B: `str.extract_many` / `str.find_many` (polars) and `readFwf` (pandas
//! `read_fwf`). Vectors marked "docs" are the examples of the polars reference pages
//! (`Expr.str.extract_many`, `Expr.str.find_many`) and the pandas user guide ("Files with
//! fixed width columns"); the rest are hand-derived from the documented semantics, those
//! resting on an inference are marked "inferred". The last tests are the no-panic sweep.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Expr = df.Expr;

const X: Expr = .{ .col = "x" };

const Opts = struct { fold: bool = false, overlapping: bool = false, leftmost: bool = false };

fn manyExpr(offsets: bool, patterns: []const []const u8, o: Opts) Expr {
    return if (offsets)
        .{ .find_many = .{ .x = &X, .patterns = patterns, .ascii_case_insensitive = o.fold, .overlapping = o.overlapping, .leftmost = o.leftmost } }
    else
        .{ .extract_many = .{ .x = &X, .patterns = patterns, .ascii_case_insensitive = o.fold, .overlapping = o.overlapping, .leftmost = o.leftmost } };
}

fn runMany(a: std.mem.Allocator, text: Value, e: Expr) !df.Frame {
    const f = try st.mk(a, &.{.{ .name = "x", .type = .text }}, &.{&.{text}});
    return df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
}

/// The cell as `a|b|c` (texts) or `1,2,3` (ints); `-` for a null cell.
fn show(a: std.mem.Allocator, v: Value) ![]const u8 {
    if (v == .null) return "-";
    var out: std.ArrayList(u8) = .empty;
    for (0..v.list.len()) |i| {
        const el = v.list.get(i);
        if (i > 0) try out.append(a, if (el == .int) ',' else '|');
        switch (el) {
            .text => |t| try out.appendSlice(a, t),
            .int => |n| try out.print(a, "{d}", .{n}),
            else => return error.TestUnexpectedResult,
        }
    }
    return out.items;
}

fn expectMany(text: []const u8, e: Expr, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try runMany(a, .{ .text = text }, e);
    try testing.expectEqualStrings(want, try show(a, g.cell(0, "out").?));
}

fn expectEmptyList(text: []const u8, e: Expr) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try runMany(a, .{ .text = text }, e);
    const v = g.cell(0, "out").?;
    try testing.expect(v == .list);
    try testing.expectEqual(@as(usize, 0), v.list.len());
}

const disco = [_][]const u8{ "winter", "disco", "onte", "discontent" };

test "extract_many and find_many: the polars reference examples (docs)" {
    try expectMany("discontent", manyExpr(false, &disco, .{}), "disco");
    try expectMany("discontent", manyExpr(false, &disco, .{ .overlapping = true }), "disco|onte|discontent");
    try expectMany("discontent", manyExpr(true, &disco, .{}), "0");
    try expectMany("discontent", manyExpr(true, &disco, .{ .overlapping = true }), "0,4,0");
    const rh = [_][]const u8{ "rhap", "ody", "coalesce" };
    try expectMany("rhapsody", manyExpr(false, &rh, .{}), "rhap|ody");
    try expectMany("rhapsody", manyExpr(true, &rh, .{}), "0,5");
}

test "extract_many and find_many: case, UTF-8 byte offsets, ties, empty results" {
    const hello = [_][]const u8{"hello"};
    try expectMany("Hello HELLO", manyExpr(false, &hello, .{ .fold = true }), "Hello|HELLO");
    try expectMany("Hello HELLO", manyExpr(true, &hello, .{ .fold = true }), "0,6");
    try expectEmptyList("Hello HELLO", manyExpr(false, &hello, .{}));
    // Case folding is ASCII only: "É" does not match "é".
    const e = [_][]const u8{"é"};
    try expectEmptyList("É", manyExpr(false, &e, .{ .fold = true }));
    // Offsets are bytes: h=0 é=1..2 l=3 l=4 o=5 ' '=6 w=7 ö=8..9.
    const u = [_][]const u8{ "ö", "llo" };
    try expectMany("héllo wörld", manyExpr(true, &u, .{}), "3,8");
    try expectMany("héllo wörld", manyExpr(false, &u, .{}), "llo|ö");
    // No patterns, a pattern longer than the text, a miss: empty lists, not nulls.
    try expectEmptyList("abc", manyExpr(false, &.{}, .{}));
    try expectEmptyList("abc", manyExpr(true, &.{"abcd"}, .{}));
    try expectEmptyList("", manyExpr(true, &.{"a"}, .{}));
    try expectEmptyList("abc", manyExpr(true, &.{"x"}, .{ .overlapping = true }));
    // Same end: the match that ends first wins and of those the longest (as replace_many);
    // overlapping lists the longer first (inferred from the Aho-Corasick output chain).
    try expectMany("abc", manyExpr(false, &.{ "c", "bc", "abc" }, .{}), "abc");
    try expectMany("abc", manyExpr(false, &.{ "ab", "a" }, .{}), "a");
    try expectMany("abc", manyExpr(false, &.{ "bc", "abc", "c" }, .{ .overlapping = true }), "abc|bc|c");
    // Overlapping reports every occurrence, "aa" in "aaa" twice.
    try expectMany("aaa", manyExpr(true, &.{"aa"}, .{ .overlapping = true }), "0,1");
    try expectMany("aaa", manyExpr(true, &.{"aa"}, .{}), "0");
    // leftmost: the earliest start, at one start the pattern listed first.
    const lm = [_][]const u8{ "bc", "abcd", "ab" };
    try expectMany("abcd", manyExpr(false, &lm, .{}), "ab");
    try expectMany("abcd", manyExpr(false, &lm, .{ .leftmost = true }), "abcd");
    try expectMany("abcd", manyExpr(true, &.{ "ab", "abcd" }, .{ .leftmost = true }), "0");
}

test "extract_many and find_many: nulls, refusals, output types" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try runMany(a, .null, manyExpr(false, &.{"a"}, .{}));
    try testing.expect(g.cell(0, "out").? == .null);
    try testing.expectError(error.BadExpr, runMany(a, .{ .text = "a" }, manyExpr(false, &.{ "a", "" }, .{})));
    try testing.expectError(error.BadExpr, runMany(a, .{ .text = "a" }, manyExpr(true, &.{"a"}, .{ .overlapping = true, .leftmost = true })));
    // The declared element types: text for extract_many, UInt32 for find_many.
    const gt = try runMany(a, .{ .text = "ab" }, manyExpr(false, &.{"a"}, .{}));
    try testing.expectEqual(df.ColumnType.list, gt.columns[gt.columnIndex("out").?].type);
    try testing.expectEqual(df.ColumnType.text, gt.columns[gt.columnIndex("out").?].inner[0].type);
    const gu = try runMany(a, .{ .text = "ab" }, manyExpr(true, &.{"b"}, .{}));
    try testing.expectEqual(df.ColumnType.uint32, gu.columns[gu.columnIndex("out").?].inner[0].type);
    try testing.expectEqualStrings("1", try show(a, gu.cell(0, "out").?));
}

// ── read_fwf ────────────────────────────────────────────────────────────────

const pandas_doc =
    "id8141  360.242940   149.910199   11950.7\n" ++
    "id1594  444.953632   166.985655   11788.4\n" ++
    "id1849  364.136849   183.628767   11806.2\n" ++
    "id1230  413.836124   184.375703   11916.0\n" ++
    "id1948  502.953953   173.237159   12468.3\n";

test "readFwf: the pandas user guide example, colspecs (docs)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const specs = [_]df.Colspec{ .{ .start = 0, .end = 6 }, .{ .start = 8, .end = 20 }, .{ .start = 21, .end = 33 }, .{ .start = 34, .end = 43 } };
    const f = try df.readFwf(a, pandas_doc, .{
        .spec = .{ .colspecs = &specs },
        .csv = .{ .has_header = false, .names = &.{ "id", "a", "b", "c" } },
    });
    try testing.expectEqual(@as(usize, 5), f.len);
    try testing.expectEqual(df.ColumnType.text, f.columnType("id").?);
    try testing.expectEqual(df.ColumnType.float, f.columnType("a").?);
    try testing.expectEqualStrings("id8141", f.cell(0, "id").?.text);
    try testing.expectEqual(@as(f64, 360.242940), f.cell(0, "a").?.float);
    try testing.expectEqual(@as(f64, 149.910199), f.cell(0, "b").?.float);
    try testing.expectEqual(@as(f64, 12468.3), f.cell(4, "c").?.float);
}

test "readFwf: infer finds the same columns as the colspecs (docs rule: columns where every row has a delimiter between)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readFwf(a, pandas_doc, .{ .csv = .{ .has_header = false, .names = &.{ "id", "a", "b", "c" } } });
    try testing.expectEqual(@as(usize, 5), f.len);
    try testing.expectEqualStrings("id1948", f.cell(4, "id").?.text);
    try testing.expectEqual(@as(f64, 502.953953), f.cell(4, "a").?.float);
    try testing.expectEqual(@as(f64, 11806.2), f.cell(2, "c").?.float);
}

test "readFwf: widths, header, int typing, short and long lines, blank lines" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = "k   v\nab  12\n\ncd   7\nef\nxx  99 trailing\n";
    const f = try df.readFwf(a, text, .{ .spec = .{ .widths = &.{ 4, 2 } } });
    // The blank line is dropped; "ef" is short (v null); the tail past the last spec is cut.
    try testing.expectEqual(@as(usize, 4), f.len);
    try testing.expectEqual(df.ColumnType.int, f.columnType("v").?);
    try testing.expectEqual(@as(i64, 12), f.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 7), f.cell(1, "v").?.int);
    try testing.expect(f.cell(2, "v").? == .null);
    try testing.expectEqualStrings("ef", f.cell(2, "k").?.text);
    try testing.expectEqual(@as(i64, 99), f.cell(3, "v").?.int);
    // infer gives the same two columns (the header line takes part).
    const g = try df.readFwf(a, "k   v\nab  12\ncd   7\n", .{});
    try testing.expectEqual(@as(usize, 2), g.len);
    try testing.expectEqual(@as(i64, 7), g.cell(1, "v").?.int);
}

test "readFwf: offsets are characters, not bytes; BOM, CRLF, skip_rows, comment" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readFwf(a, "\xEF\xBB\xBFname 1\r\nÉé   2\r\nüö   3\r\n", .{ .spec = .{ .widths = &.{ 5, 1 } } });
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expectEqualStrings("Éé", f.cell(0, "name").?.text);
    try testing.expectEqualStrings("üö", f.cell(1, "name").?.text);
    try testing.expectEqual(@as(i64, 3), f.cell(1, "1").?.int);
    const s = try df.readFwf(a, "junk\nk v\na 1\n# c\nb 2\n", .{ .spec = .{ .widths = &.{ 2, 1 } }, .csv = .{ .skip_rows = 1, .comment = '#' } });
    try testing.expectEqual(@as(usize, 2), s.len);
    try testing.expectEqual(@as(i64, 2), s.cell(1, "v").?.int);
}

test "readFwf: cells with commas and quotes survive, types and nulls go through readCsv" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readFwf(a, "t     n\n\"a,b\" NA\nx\"y   5\n", .{ .spec = .{ .widths = &.{ 6, 2 } }, .csv = .{ .types = &.{.{ .name = "n", .type = .float }} } });
    try testing.expectEqualStrings("\"a,b\"", f.cell(0, "t").?.text);
    try testing.expectEqualStrings("x\"y", f.cell(1, "t").?.text);
    try testing.expect(f.cell(0, "n").? == .null);
    try testing.expectEqual(@as(f64, 5), f.cell(1, "n").?.float);
}

test "readFwf: limits and refusals" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.EmptyInput, df.readFwf(a, "", .{}));
    try testing.expectError(error.EmptyInput, df.readFwf(a, "   \n\n", .{}));
    try testing.expectError(error.TooManyColumns, df.readFwf(a, "abc\n", .{ .spec = .{ .widths = &.{ 1, 1, 1 } }, .csv = .{ .max_columns = 2 } }));
    try testing.expectError(error.TooManyColumns, df.readFwf(a, "a b c\n", .{ .csv = .{ .max_columns = 2 } }));
    try testing.expectError(error.InputTooLarge, df.readFwf(a, "abc\n", .{ .spec = .{ .widths = &.{3} }, .csv = .{ .max_bytes = 3 } }));
    try testing.expectError(error.RecordTooLarge, df.readFwf(a, "abcd\n", .{ .spec = .{ .widths = &.{3} }, .csv = .{ .max_record_bytes = 3 } }));
    try testing.expectError(error.TooManyRows, df.readFwf(a, "h\na\nb\nc\n", .{ .spec = .{ .widths = &.{1} }, .csv = .{ .max_rows = 2 } }));
    try testing.expectError(error.BadOptions, df.readFwf(a, "a\n", .{ .spec = .{ .widths = &.{1} }, .delimiter = "é" }));
    try testing.expectError(error.NoSuchColumn, df.readFwf(a, "a\n1\n", .{ .spec = .{ .widths = &.{1} }, .csv = .{ .columns = &.{"zz"} } }));
}

// ── no-panic sweep ──

fn rep(comptime c: u8, comptime n: usize) []const u8 {
    const arr: [n]u8 = @splat(c);
    return &arr;
}

const x100 = rep('x', 100);

fn repeatLine(a: std.mem.Allocator, n: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (0..n) |_| try out.appendSlice(a, x100 ++ "\n");
    return out.items;
}

fn fwfOk(a: std.mem.Allocator, bytes: []const u8, o: df.FwfReadOptions) !void {
    _ = df.readFwf(a, bytes, o) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return,
    };
}

test "sweep: readFwf over hostile specs and inputs returns, never traps" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const big = std.math.maxInt(usize);
    const texts = [_][]const u8{ "", "\n", "abc\n", "a b\nc d\n", "é ü\n\xff\xfe \xc3\n", "\xEF\xBB\xBF", "\r\r\n\n", x100 ++ "\n" };
    const specs = [_][]const df.Colspec{
        &.{},
        &.{.{ .start = 0, .end = 0 }},
        &.{.{ .start = 5, .end = 2 }},
        &.{ .{ .start = 0, .end = 10 }, .{ .start = 2, .end = 4 }, .{ .start = 3, .end = 100 } },
        &.{.{ .start = big, .end = big }},
        &.{.{ .start = 0, .end = big }},
        &.{.{ .start = big - 1, .end = big }},
        &.{ .{ .start = 4294967295, .end = 4294967297 }, .{ .start = 0, .end = 4294967296 } },
    };
    const widths = [_][]const usize{ &.{}, &.{0}, &.{ 0, 0, 0 }, &.{big}, &.{ big, big }, &.{ 1, big, 1 }, &.{ 4294967295, 2 }, &.{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 } };
    const csvs = [_]df.CsvReadOptions{ .{}, .{ .has_header = false }, .{ .skip_rows = 5, .skipfooter = 3 }, .{ .names = &.{"a"} }, .{ .max_cells = 3, .max_rows = 1 }, .{ .thousands = ',', .parse_dates = true, .comment = 'a' } };
    for (texts) |t| for (csvs) |c| {
        try fwfOk(a, t, .{ .csv = c });
        try fwfOk(a, t, .{ .infer_nrows = 0, .csv = c });
        try fwfOk(a, t, .{ .infer_nrows = big, .delimiter = "", .csv = c });
        for (specs) |s| try fwfOk(a, t, .{ .spec = .{ .colspecs = s }, .csv = c });
        for (widths) |w| try fwfOk(a, t, .{ .spec = .{ .widths = w }, .csv = c });
    };
    // Overlapping specs multiply the text: `max_bytes` stops them.
    const many = try a.alloc(df.Colspec, 4000);
    @memset(many, .{ .start = 0, .end = 100 });
    try testing.expectError(error.InputTooLarge, df.readFwf(a, try repeatLine(a, 10), .{ .spec = .{ .colspecs = many }, .csv = .{ .max_bytes = 1000 } }));
    // More specs than `max_columns` by default.
    const lots = try a.alloc(usize, 70000);
    @memset(lots, 1);
    try testing.expectError(error.TooManyColumns, df.readFwf(a, "abc\n", .{ .spec = .{ .widths = lots } }));
    const wide = try a.alloc(u8, 140001);
    for (wide, 0..) |*c, i| c.* = if (i % 2 == 0) 'a' else ' ';
    try testing.expectError(error.TooManyColumns, df.readFwf(a, wide, .{}));
}

test "sweep: extract_many and find_many over hostile patterns and texts return, never trap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const texts = [_][]const u8{ "", "a", "aaaa", "é", "\xff\xfe\xc3", "héllo wörld", rep('a', 200) };
    // 10k patterns, a pattern longer than the text, patterns that are invalid UTF-8.
    const ten_k = try a.alloc([]const u8, 10_000);
    for (ten_k, 0..) |*p, i| p.* = if (i % 3 == 0) "a" else if (i % 3 == 1) "\xc3" else "ab";
    const sets = [_][]const []const u8{ &.{}, &.{"a"}, &.{ "a", "aa", "aaa" }, &.{rep('x', 300)}, &.{ "\xff", "\xc3", "\xa9" }, &.{ "é", "É" }, ten_k };
    const flags = [_]Opts{ .{}, .{ .fold = true }, .{ .overlapping = true }, .{ .leftmost = true }, .{ .fold = true, .overlapping = true } };
    for (texts) |t| for (sets) |ps| for (flags) |o| for ([_]bool{ false, true }) |offs| {
        var one = std.heap.ArenaAllocator.init(testing.allocator);
        defer one.deinit();
        _ = runMany(one.allocator(), .{ .text = t }, manyExpr(offs, ps, o)) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => continue,
        };
    };
    // 10k one-letter patterns over a 1000-letter text: 10M overlapping matches, past the cap.
    const same = try a.alloc([]const u8, 10_000);
    @memset(same, "a");
    try testing.expectError(error.TooLarge, runMany(a, .{ .text = rep('a', 1000) }, manyExpr(true, same, .{ .overlapping = true })));
}
