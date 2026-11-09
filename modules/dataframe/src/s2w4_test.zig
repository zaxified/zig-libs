// SPDX-License-Identifier: MIT
//! Hand-written tests of dataframe S2 wave W4: the str, dt and duration gaps. The engines'
//! answers are replayed in `s2w4_oracle_test.zig`; these cover what they cannot: errors,
//! caps, hostile input, and the behaviours where this module deliberately differs.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const sf = @import("strfn.zig");
const dtf = @import("dtfn.zig");
const jr = @import("jsonread.zig");
const vb = @import("verbs.zig");
const Frame = fm.Frame;
const Value = vm.Value;

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

fn colFrame(a: std.mem.Allocator, name: []const u8, ty: vm.ColumnType, cells: []const Value) !Frame {
    const cols = try a.alloc(vm.Column, 1);
    cols[0] = .{ .name = name, .type = ty };
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = cells.len };
}

fn texts(a: std.mem.Allocator, xs: []const ?[]const u8) !Frame {
    const cells = try a.alloc(Value, xs.len);
    for (cells, xs) |*c, x| c.* = if (x) |t| .{ .text = t } else .null;
    return colFrame(a, "x", .text, cells);
}

fn col(a: std.mem.Allocator, name: []const u8) !*const ex.Expr {
    const p = try a.create(ex.Expr);
    p.* = .{ .col = name };
    return p;
}

/// The cell `e` gives on row `row` of `f`.
fn evalAt(a: std.mem.Allocator, f: Frame, e: ex.Expr, row: usize) !Value {
    const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
    return out.cell(row, "o").?;
}

fn expectText(want: []const u8, got: Value) !void {
    try testing.expect(got == .text);
    try testing.expectEqualStrings(want, got.text);
}

fn expectPieces(want: []const []const u8, got: Value) !void {
    try testing.expect(got == .list);
    try testing.expectEqual(want.len, got.list.len());
    for (want, 0..) |w, i| try expectText(w, got.list.get(i));
}

test "split_ws: Python's rules, limit, hostile whitespace" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "  a b  c ", "", "a\u{a0}b\u{3000}c", "x\x1cy", "\xff a \xfe" });
    const x = try col(a, "x");
    try expectPieces(&.{ "a", "b", "c" }, try evalAt(a, f, .{ .split_ws = .{ .x = x } }, 0));
    try expectPieces(&.{}, try evalAt(a, f, .{ .split_ws = .{ .x = x } }, 1));
    try expectPieces(&.{ "a", "b", "c" }, try evalAt(a, f, .{ .split_ws = .{ .x = x } }, 2)); // no-break and ideographic spaces split
    try expectPieces(&.{ "x", "y" }, try evalAt(a, f, .{ .split_ws = .{ .x = x } }, 3)); // U+001C is whitespace in Python
    try expectPieces(&.{ "\xff", "a", "\xfe" }, try evalAt(a, f, .{ .split_ws = .{ .x = x } }, 4)); // invalid UTF-8 is not space
    // The last piece is the rest from its first non-space character, trailing space kept.
    try expectPieces(&.{ "a", "b  c " }, try evalAt(a, f, .{ .split_ws = .{ .x = x, .limit = 2 } }, 0));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .split_ws = .{ .x = x, .limit = 0 } } }}));
}

test "rsplit, partition and split fields: edges and refusals" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "a,b,c", "", null });
    const x = try col(a, "x");
    try expectPieces(&.{ "a,b", "c" }, try evalAt(a, f, .{ .rsplit = .{ .x = x, .by = ",", .limit = 2 } }, 0));
    try expectPieces(&.{""}, try evalAt(a, f, .{ .rsplit = .{ .x = x, .by = "," } }, 1));
    try testing.expect((try evalAt(a, f, .{ .rsplit = .{ .x = x, .by = "," } }, 2)) == .null);
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .rsplit = .{ .x = x, .by = "" } } }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .rsplit = .{ .x = x, .by = ",", .limit = 0 } } }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .partition = .{ .x = x, .sep = "" } } }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .split_fields = .{ .x = x, .by = "", .n = 1 } } }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .split_fields = .{ .x = x, .by = ",", .n = 0, .rest = true } } }}));
    try testing.expectError(error.TooLarge, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .split_fields = .{ .x = x, .by = ",", .n = std.math.maxInt(usize) } } }}));
    // split_exact with n = 0 is one field; the rest of the text is dropped.
    const r = try evalAt(a, f, .{ .split_fields = .{ .x = x, .by = ",", .n = 0 } }, 0);
    try testing.expect(r == .record);
    try expectText("a", r.record.get(0));
}

test "wrap: width 0, tabs, long words, hostile size" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "abcdefghij klm", "a\tb", "hello world" });
    const x = try col(a, "x");
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .wrap = .{ .x = x, .width = 0 } } }}));
    try expectText("abcde\nfghij\nklm", try evalAt(a, f, .{ .wrap = .{ .x = x, .width = 5 } }, 0));
    try expectText("abcdefghij\nklm", try evalAt(a, f, .{ .wrap = .{ .x = x, .width = 5, .break_long_words = false } }, 0));
    try expectText("a       b", try evalAt(a, f, .{ .wrap = .{ .x = x, .width = 20 } }, 1)); // tab to column 8
    try expectText("hello\nworld", try evalAt(a, f, .{ .wrap = .{ .x = x, .width = 5 } }, 2));
    // A text of tabs would grow eightfold: the cap, not the allocator, stops it.
    const big = try a.alloc(u8, fnxCap() / 4);
    @memset(big, '\t');
    const g = try texts(a, &.{big});
    const gx = try col(a, "x");
    try testing.expectError(error.TooLarge, ex.mutate(a, g, &.{.{ .out = "o", .expr = .{ .wrap = .{ .x = gx, .width = 10 } } }}));
}

fn fnxCap() usize {
    return @import("exprfn.zig").max_text_result;
}

test "slice_replace, encode and decode: pandas and polars corners" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "abcdef", "h\u{e9}llo" });
    const x = try col(a, "x");
    try expectText("aXdef", try evalAt(a, f, .{ .slice_replace = .{ .x = x, .start = 1, .stop = 3, .with = "X" } }, 0));
    try expectText("abXcdef", try evalAt(a, f, .{ .slice_replace = .{ .x = x, .start = 2, .stop = 2, .with = "X" } }, 0));
    try expectText("abcXdef", try evalAt(a, f, .{ .slice_replace = .{ .x = x, .start = 3, .stop = 1, .with = "X" } }, 0)); // empty slice: insert
    try expectText("hXllo", try evalAt(a, f, .{ .slice_replace = .{ .x = x, .start = 1, .stop = 2, .with = "X" } }, 1)); // characters
    try expectText("68c3a96c6c6f", try evalAt(a, f, .{ .encode = .{ .x = x, .how = .hex } }, 1));
    // Invalid input is null, never a panic: odd hex, bad digits, padding missing, not UTF-8.
    const bad = try texts(a, &.{ "abc", "zz", "aGk", "/w==", "6869", "aGk=" });
    const bx = try col(a, "x");
    try testing.expect((try evalAt(a, bad, .{ .decode = .{ .x = bx, .how = .hex } }, 0)) == .null);
    try testing.expect((try evalAt(a, bad, .{ .decode = .{ .x = bx, .how = .hex } }, 1)) == .null);
    try testing.expect((try evalAt(a, bad, .{ .decode = .{ .x = bx, .how = .base64 } }, 2)) == .null);
    try testing.expect((try evalAt(a, bad, .{ .decode = .{ .x = bx, .how = .base64 } }, 3)) == .null);
    try expectText("hi", try evalAt(a, bad, .{ .decode = .{ .x = bx, .how = .hex } }, 4));
    try expectText("hi", try evalAt(a, bad, .{ .decode = .{ .x = bx, .how = .base64 } }, 5));
}

test "match_regex anchors the whole pattern; an invalid one is BadPattern" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "ab", "xab", "abc" });
    const x = try col(a, "x");
    try testing.expect((try evalAt(a, f, .{ .match_regex = .{ .x = x, .pattern = "a|ab" } }, 0)).bool);
    try testing.expect(!(try evalAt(a, f, .{ .match_regex = .{ .x = x, .pattern = "ab" } }, 1)).bool);
    try testing.expect((try evalAt(a, f, .{ .match_regex = .{ .x = x, .pattern = "a|ab", .full = true } }, 0)).bool);
    try testing.expect(!(try evalAt(a, f, .{ .match_regex = .{ .x = x, .pattern = "ab", .full = true } }, 2)).bool);
    try testing.expectError(error.BadPattern, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .match_regex = .{ .x = x, .pattern = "a)|(b" } } }}));
}

test "splitColumns and getDummies: caps, refusals, names" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "a|b", "c" });
    try testing.expectError(error.BadArgument, sf.splitColumns(a, f, .{ .col = "x", .by = "" }));
    try testing.expectError(error.BadArgument, sf.splitColumns(a, f, .{ .col = "x", .by = "|", .limit = 0 }));
    try testing.expectError(error.BadArgument, sf.splitColumns(a, f, .{ .col = "x", .by = "(", .regex = true }));
    try testing.expectError(error.NoSuchColumn, sf.splitColumns(a, f, .{ .col = "nope" }));
    const out = try sf.splitColumns(a, f, .{ .col = "x", .by = "|", .prefix = "p", .keep_source = true });
    try testing.expectEqual(@as(usize, 3), out.columns.len);
    try testing.expectEqualStrings("p1", out.columns[2].name);
    try testing.expect(out.cell(1, "p1").? == .null);
    // More pieces than columns may be made: TooLarge, not a huge frame.
    const many = try a.alloc(u8, 2 * (sf.max_str_columns + 2));
    for (many, 0..) |*c, i| c.* = if (i % 2 == 0) 'a' else '|';
    const g = try texts(a, &.{many});
    try testing.expectError(error.TooLarge, sf.splitColumns(a, g, .{ .col = "x", .by = "|" }));
    try testing.expectError(error.TooLarge, sf.getDummies(a, try dummiesInput(a), .{ .col = "x", .sep = "|" }));
    try testing.expectError(error.BadArgument, sf.getDummies(a, f, .{ .col = "x", .sep = "" }));
    // A new name equal to another column's is refused.
    const two = try a.alloc(vm.Column, 2);
    two[0] = .{ .name = "x", .type = .text };
    two[1] = .{ .name = "0", .type = .text };
    const d2 = try a.alloc(fm.ColumnData, 2);
    d2[0] = f.data[0];
    d2[1] = f.data[0];
    try testing.expectError(error.DuplicateColumn, sf.splitColumns(a, .{ .columns = two, .data = d2, .len = 2 }, .{ .col = "x", .by = "|" }));
    // get_dummies as bool.
    const dm = try sf.getDummies(a, f, .{ .col = "x", .sep = "|", .prefix = "t", .as_bool = true });
    try testing.expectEqual(@as(usize, 3), dm.columns.len);
    try testing.expectEqualStrings("t_a", dm.columns[0].name);
    try testing.expect(dm.cell(0, "t_a").?.bool);
    try testing.expect(!dm.cell(1, "t_a").?.bool);
}

test "wrap: one huge word at width 1 is linear (not n^2 per line)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const n = 256 * 1024;
    // ASCII: n lines of one character, below the output cap.
    const ascii = try a.alloc(u8, n);
    @memset(ascii, 'a');
    const w1 = try sf.wrap(a, ascii, 1, true, true);
    try testing.expectEqual(2 * n - 1, w1.len);
    try testing.expectEqual(@as(usize, n - 1), std.mem.count(u8, w1, "\n"));
    // 2-byte characters: the UTF-8 path.
    const e = try a.alloc(u8, 2 * n);
    for (0..n) |i| {
        e[2 * i] = 0xC3;
        e[2 * i + 1] = 0xA9;
    }
    const w2 = try sf.wrap(a, e, 1, true, true);
    try testing.expectEqual(3 * n - 1, w2.len);
    try testing.expectEqualStrings("\xC3\xA9\n\xC3\xA9", w2[0..5]);
}

test "splitColumns: a cell with too many pieces is TooLarge before they are all built" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // Exactly the cap: max_str_columns pieces (cap - 1 separators) still works.
    const ok = try a.alloc(u8, sf.max_str_columns - 1);
    @memset(ok, ',');
    const fo = try sf.splitColumns(a, try texts(a, &.{ok}), .{ .col = "x", .by = "," });
    try testing.expectEqual(sf.max_str_columns, fo.columns.len);
    // One past it, in each splitter.
    const big = try a.alloc(u8, sf.max_str_columns + 10);
    @memset(big, ',');
    const g = try texts(a, &.{big});
    try testing.expectError(error.TooLarge, sf.splitColumns(a, g, .{ .col = "x", .by = "," }));
    try testing.expectError(error.TooLarge, sf.splitColumns(a, g, .{ .col = "x", .by = ",", .regex = true }));
    const ws = try a.alloc(u8, 2 * (sf.max_str_columns + 10));
    for (ws, 0..) |*c, i| c.* = if (i % 2 == 0) 'a' else ' ';
    try testing.expectError(error.TooLarge, sf.splitColumns(a, try texts(a, &.{ws}), .{ .col = "x" }));
}

fn dummiesInput(a: std.mem.Allocator) !Frame {
    // One distinct token per row, past the cap.
    const n = sf.max_str_columns + 1;
    const cells = try a.alloc(Value, n);
    for (cells, 0..) |*c, i| c.* = .{ .text = try a.print("t{d}", .{i}) };
    return colFrame(a, "x", .text, cells);
}

test "durations: float seconds, normalised fields, components" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try colFrame(a, "x", .duration, &.{ .{ .int = -1 }, .{ .int = 90_061_000_000 }, .{ .text = "x" }, .null });
    const x = try col(a, "x");
    try testing.expectEqual(@as(f64, -1e-6), (try evalAt(a, f, .{ .dt = .{ .x = x, .part = .total_seconds_f64 } }, 0)).float);
    try testing.expectEqual(@as(i64, -1), (try evalAt(a, f, .{ .dt = .{ .x = x, .part = .td_days } }, 0)).int);
    try testing.expectEqual(@as(i64, 86399), (try evalAt(a, f, .{ .dt = .{ .x = x, .part = .td_seconds } }, 0)).int);
    try testing.expectEqual(@as(i64, 999_999), (try evalAt(a, f, .{ .dt = .{ .x = x, .part = .td_microseconds } }, 0)).int);
    try testing.expectEqual(@as(i64, 0), (try evalAt(a, f, .{ .dt = .{ .x = x, .part = .td_nanoseconds } }, 1)).int);
    // Not an int: null.
    try testing.expect((try evalAt(a, f, .{ .dt = .{ .x = x, .part = .td_days } }, 2)) == .null);
    try testing.expect((try evalAt(a, f, .{ .td_components = .{ .x = x } }, 2)) == .null);
    const comp = try evalAt(a, f, .{ .td_components = .{ .x = x } }, 1);
    try testing.expectEqual(@as(i64, 1), comp.record.get(0).int); // days
    try testing.expectEqual(@as(i64, 1), comp.record.get(3).int); // seconds
    const mn = dtf.components(std.math.minInt(i64)); // no overflow at the extreme
    try testing.expect(mn[0] < 0);
}

test "aggregate keeps durations and timestamps as times" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const cols = try a.alloc(vm.Column, 2);
    cols[0] = .{ .name = "g", .type = .text };
    cols[1] = .{ .name = "d", .type = .duration };
    const data = try a.alloc(fm.ColumnData, 2);
    data[0] = try fm.columnFromCells(a, &.{ .{ .text = "a" }, .{ .text = "a" }, .{ .text = "b" } });
    data[1] = try fm.columnFromCells(a, &.{ .{ .int = 1_000_001 }, .{ .int = 2 }, .null });
    const f: Frame = .{ .columns = cols, .data = data, .len = 3 };
    const out = try vb.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{
        .{ .src = "d", .out = "sum", .func = .sum },
        .{ .src = "d", .out = "mean", .func = .mean },
        .{ .src = "d", .out = "var", .func = .@"var" },
        .{ .src = "d", .out = "count", .func = .count },
    }, .skip_na = true });
    try testing.expectEqual(vm.ColumnType.duration, out.columns[out.columnIndex("sum").?].type);
    try testing.expectEqual(vm.ColumnType.duration, out.columns[out.columnIndex("mean").?].type);
    try testing.expectEqual(vm.ColumnType.float, out.columns[out.columnIndex("var").?].type);
    try testing.expectEqual(vm.ColumnType.int, out.columns[out.columnIndex("count").?].type);
    try testing.expectEqual(@as(i64, 1_000_003), out.cell(0, "sum").?.int);
    try testing.expectEqual(@as(i64, 500_001), out.cell(0, "mean").?.int); // 500001.5 truncated
}

test "json: a number read as a duration, both lists refused" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try jr.readJson(a, "[{\"d\":1500},{\"d\":null}]", .{ .epoch_durations = &.{"d"} });
    try testing.expectEqual(vm.ColumnType.duration, f.columns[0].type);
    try testing.expectEqual(@as(i64, 1_500_000), f.cell(0, "d").?.int); // ms by default
    try testing.expect(f.cell(1, "d").? == .null);
    try testing.expectError(error.BadValue, jr.readJson(a, "[{\"d\":\"x\"}]", .{ .epoch_durations = &.{"d"} }));
    try testing.expectError(error.BadValue, jr.readJson(a, "[{\"d\":1.5}]", .{ .epoch_durations = &.{"d"} }));
    try testing.expectError(error.BadValue, jr.readJson(a, "[{\"d\":1}]", .{ .epoch_durations = &.{"d"}, .epoch_dates = &.{"d"} }));
    try testing.expectError(error.BadValue, jr.readJson(a, "[{\"d\":9223372036854775807}]", .{ .epoch_durations = &.{"d"} }));
}

test "dt_replace: invalid result is null; combine; zone offsets" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const jan31 = vm.parseIsoTimestamp("2024-01-31T10:20:30Z").?;
    const f = try colFrame(a, "x", .timestamp, &.{ .{ .int = jan31 }, .null });
    const x = try col(a, "x");
    const two = try a.create(ex.Expr);
    two.* = .{ .lit = .{ .int = 2 } };
    const y2000 = try a.create(ex.Expr);
    y2000.* = .{ .lit = .{ .int = 2000 } };
    const h24 = try a.create(ex.Expr);
    h24.* = .{ .lit = .{ .int = 24 } };
    const nul = try a.create(ex.Expr);
    nul.* = .{ .lit = .null };
    try testing.expect((try evalAt(a, f, .{ .dt_replace = .{ .x = x, .month = two } }, 0)) == .null); // Feb 31
    try testing.expect((try evalAt(a, f, .{ .dt_replace = .{ .x = x, .hour = h24 } }, 0)) == .null);
    try testing.expect((try evalAt(a, f, .{ .dt_replace = .{ .x = x, .year = nul } }, 0)) == .null);
    try testing.expect((try evalAt(a, f, .{ .dt_replace = .{ .x = x, .year = y2000 } }, 1)) == .null);
    try testing.expectEqual(vm.parseIsoTimestamp("2000-01-31T10:20:30Z").?, (try evalAt(a, f, .{ .dt_replace = .{ .x = x, .year = y2000 } }, 0)).int);
    // combine: a date and a time of day as text or as microseconds; junk is null.
    const cols = try a.alloc(vm.Column, 2);
    cols[0] = .{ .name = "d", .type = .date };
    cols[1] = .{ .name = "t", .type = .text };
    const data = try a.alloc(fm.ColumnData, 2);
    data[0] = try fm.columnFromCells(a, &.{ .{ .text = "2024-01-05" }, .{ .text = "2024-01-05" }, .{ .text = "2024-01-05" } });
    data[1] = try fm.columnFromCells(a, &.{ .{ .text = "10:20:30" }, .{ .text = "25:00:00" }, .{ .text = "x" } });
    const g: Frame = .{ .columns = cols, .data = data, .len = 3 };
    const dd = try col(a, "d");
    const tt = try col(a, "t");
    const base = vm.parseIsoTimestamp("2024-01-05T00:00:00Z").?;
    try testing.expectEqual(base + (10 * 3600 + 20 * 60 + 30) * 1_000_000, (try evalAt(a, g, .{ .dt_combine = .{ .date = dd, .time = tt } }, 0)).int);
    try testing.expect((try evalAt(a, g, .{ .dt_combine = .{ .date = dd, .time = tt } }, 1)) == .null);
    try testing.expect((try evalAt(a, g, .{ .dt_combine = .{ .date = dd, .time = tt } }, 2)) == .null);
    // Zones: an unknown one is BadExpr; a date names no instant.
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .tz_offset = .{ .x = x, .zone = "Nowhere/Land" } } }}));
    try testing.expectEqual(@as(i64, 3600 * 1_000_000), (try evalAt(a, f, .{ .tz_offset = .{ .x = x, .zone = "Europe/Prague" } }, 0)).int);
}

test "combine: a signed or non-digit time of day is null (review fix)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const times = [_][]const u8{ "-1:30", "10:-5", "+1:30", "12:30:-5", "12:30:00.-5", "12:30:00.+5", "1a:30", "12:30:00x5", "12:30:00.5" };
    const cols = try a.alloc(vm.Column, 2);
    cols[0] = .{ .name = "d", .type = .date };
    cols[1] = .{ .name = "t", .type = .text };
    const dcells = try a.alloc(Value, times.len);
    const tcells = try a.alloc(Value, times.len);
    for (dcells, tcells, times) |*d, *t, s| {
        d.* = .{ .text = "2024-01-02" };
        t.* = .{ .text = s };
    }
    const data = try a.alloc(fm.ColumnData, 2);
    data[0] = try fm.columnFromCells(a, dcells);
    data[1] = try fm.columnFromCells(a, tcells);
    const g: Frame = .{ .columns = cols, .data = data, .len = times.len };
    const e: ex.Expr = .{ .dt_combine = .{ .date = try col(a, "d"), .time = try col(a, "t") } };
    for (0..times.len - 1) |i| try testing.expect((try evalAt(a, g, e, i)) == .null);
    // The well-formed control: half a second past 12:30.
    const base = vm.parseIsoTimestamp("2024-01-02T00:00:00Z").?;
    try testing.expectEqual(base + (12 * 3600 + 30 * 60) * 1_000_000 + 500_000, (try evalAt(a, g, e, times.len - 1)).int);
}

test "business days with a mask and holidays: degenerate and hostile inputs" {
    const hol = [_]i64{ 19723, 19724 }; // 2024-01-01, 2024-01-02
    const all_off: [7]bool = @splat(false);
    // No business day at all: null, never a loop.
    try testing.expect(dtf.addBizDaysGeneral(19700, 1, all_off, &.{}, .forward) == null);
    // The extremes of n do not overflow.
    try testing.expect(dtf.addBizDaysGeneral(19700, std.math.maxInt(i64), dtf.monday_to_friday, &.{}, .forward) == null);
    try testing.expect(dtf.addBizDaysGeneral(19700, std.math.minInt(i64), dtf.monday_to_friday, &.{}, .forward) == null);
    try testing.expect(dtf.addBizDaysGeneral(std.math.maxInt(i64), 1, dtf.monday_to_friday, &.{}, .forward) == null);
    // 2023-12-29 (Fri) + 1 business day skips the weekend and the two holidays: Wed Jan 3.
    try testing.expectEqual(@as(?i64, 19725), dtf.addBizDaysGeneral(19720, 1, dtf.monday_to_friday, &hol, .forward));
    // Backward from the holiday itself: Fri Dec 29.
    try testing.expectEqual(@as(?i64, 19720), dtf.addBizDaysGeneral(19723, 0, dtf.monday_to_friday, &hol, .backward));
    // A holiday run longer than the refinement allows must end in a number or null, quickly.
    var run: [5000]i64 = undefined;
    for (&run, 0..) |*h, i| h.* = 19700 + @as(i64, @intCast(i));
    _ = dtf.addBizDaysGeneral(19700, 1, dtf.monday_to_friday, &run, .forward);
    // Default arguments keep the original path: Friday + 1 is Monday.
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const fri = vm.parseIsoTimestamp("2024-01-05T09:00:00Z").?;
    const f = try colFrame(a, "x", .timestamp, &.{.{ .int = fri }});
    const x = try col(a, "x");
    const plain = try evalAt(a, f, .{ .add_business_days = .{ .x = x, .n = 1 } }, 0);
    try testing.expectEqual(vm.parseIsoTimestamp("2024-01-08T09:00:00Z").?, plain.int);
    const holi = [_]vm.Date{.{ .y = 2024, .m = 1, .d = 8 }};
    const masked = try evalAt(a, f, .{ .add_business_days = .{ .x = x, .n = 1, .holidays = &holi } }, 0);
    try testing.expectEqual(vm.parseIsoTimestamp("2024-01-09T09:00:00Z").?, masked.int);
    const isb = try evalAt(a, f, .{ .is_business_day = .{ .x = x, .holidays = &.{.{ .y = 2024, .m = 1, .d = 5 }} } }, 0);
    try testing.expect(!isb.bool);
}

test "to_datetime: infer needs a column, an unreadable first cell is BadExpr, ISO mode is per cell" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ null, "05.03.2024", "06.03.2024", "2024-03-07" });
    const x = try col(a, "x");
    // The pattern is the first non-null cell's; the ISO cell then does not match it.
    const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .to_datetime = .{ .x = x, .dayfirst = true } } }});
    try testing.expect(out.cell(0, "o").? == .null);
    try testing.expectEqual(vm.parseIsoTimestamp("2024-03-05T00:00:00Z").?, out.cell(1, "o").?.int);
    try testing.expect(out.cell(3, "o").? == .null);
    const lit = try a.create(ex.Expr);
    lit.* = .{ .lit = .{ .text = "2024-01-01" } };
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .to_datetime = .{ .x = lit } } }}));
    const g = try texts(a, &.{"not a date"});
    try testing.expectError(error.BadExpr, ex.mutate(a, g, &.{.{ .out = "o", .expr = .{ .to_datetime = .{ .x = x } } }}));
    // As a date, an ISO instant loses its time of day; mixed mode reads each cell by itself.
    const h = try texts(a, &.{ "2024-01-05T10:00:00", "5 January 2024", "13/01/2024" });
    const m = try ex.mutate(a, h, &.{.{ .out = "o", .expr = .{ .to_datetime = .{ .x = x, .mode = .mixed, .to = .date } } }});
    try expectText("2024-01-05", m.cell(0, "o").?);
    try expectText("2024-01-05", m.cell(1, "o").?);
    try expectText("2024-01-13", m.cell(2, "o").?);
    // Every column type was kept: a date result is a date column.
    try testing.expectEqual(vm.ColumnType.date, m.columns[m.columnIndex("o").?].type);
}

test "small cell functions: affixes, replace n, is_ascii, replace_regex n" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try texts(a, &.{ "banana", "h\u{e9}", "" });
    const x = try col(a, "x");
    try testing.expect((try evalAt(a, f, .{ .affix_any = .{ .x = x, .patterns = &.{ "ba", "zz" } } }, 0)).bool);
    try testing.expect(!(try evalAt(a, f, .{ .affix_any = .{ .x = x, .patterns = &.{} } }, 0)).bool);
    try testing.expect((try evalAt(a, f, .{ .affix_any = .{ .x = x, .patterns = &.{ "", "q" }, .end = true } }, 2)).bool);
    try expectText("bXnXna", try evalAt(a, f, .{ .replace_n = .{ .x = x, .from = "a", .to = "X", .n = 2 } }, 0));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .replace_n = .{ .x = x, .from = "a", .to = "X", .n = 0 } } }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .replace_n = .{ .x = x, .from = "", .to = "X", .n = 1 } } }}));
    try testing.expect((try evalAt(a, f, .{ .unary = .{ .op = .is_ascii, .x = x } }, 0)).bool);
    try testing.expect(!(try evalAt(a, f, .{ .unary = .{ .op = .is_ascii, .x = x } }, 1)).bool);
    try testing.expect((try evalAt(a, f, .{ .unary = .{ .op = .is_ascii, .x = x } }, 2)).bool);
    try expectText("bXnXna", try evalAt(a, f, .{ .replace_regex = .{ .x = x, .pattern = "a", .with = "X", .n = 2 } }, 0));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .replace_regex = .{ .x = x, .pattern = "a", .with = "X", .n = 0 } } }}));
}

test "describe: a duration or timestamp quantile stays a float of microseconds on both paths (fuzz seed 1841)" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const more = @import("more.zig");
    const d4b = @import("d4b_test.zig");
    for ([_]vm.ColumnType{ .duration, .timestamp }) |ty| {
        const f = try colFrame(a, "t", ty, &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 } });
        const typed = try more.describe(a, f, &.{"t"});
        // linear 25 % of 1..4 is 1.75; the aggregate path once cut it to 1 µs.
        try testing.expectEqual(@as(f64, 1.75), typed.columnAt(1).get(4).float);
        try d4b.agree("describe temporal", more.describe(a, f, &.{"t"}), more.test_hooks.describeCells(a, f, &.{"t"}));
    }
    // `aggregate` itself still keeps the time by default.
    const g = try colFrame(a, "t", .duration, &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 } });
    const q = try vb.aggregate(a, g, .{ .group_by = &.{}, .aggs = &.{.{ .src = "t", .out = "q", .func = .quantile, .q = 0.25 }} });
    try testing.expectEqual(vm.ColumnType.duration, q.columns[0].type);
}

test "describe and aggregate: min/max over signed zeros agree between the typed and cell paths (fuzz seed 14963)" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const more = @import("more.zig");
    const d4b = @import("d4b_test.zig");
    const orders = [_][2]f64{ .{ -0.0, 0.0 }, .{ 0.0, -0.0 } };
    for (orders) |o| {
        const f = try colFrame(a, "x", .float, &.{ .{ .float = o[0] }, .{ .float = o[1] }, .{ .float = 1 } });
        const ag = try vb.aggregate(a, f, .{ .group_by = &.{}, .aggs = &.{.{ .src = "x", .out = "m", .func = .min }} });
        // The first zero seen is the minimum on every path.
        try testing.expectEqual(std.math.signbit(o[0]), std.math.signbit(ag.columnAt(0).get(0).asFloat().?));
        try d4b.agree("describe signed zeros", more.describe(a, f, &.{"x"}), more.test_hooks.describeCells(a, f, &.{"x"}));
    }
}

test "describe: a duration column over float storage keeps -0.0 on both paths (fuzz seed 14963)" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const more = @import("more.zig");
    const d4b = @import("d4b_test.zig");
    const cols = try a.alloc(vm.Column, 1);
    cols[0] = .{ .name = "d", .type = .duration };
    const data = try a.alloc(fm.ColumnData, 1);
    const vals = try a.dupe(f64, &.{-0.0});
    data[0] = .{ .float = .{ .values = vals } };
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    try d4b.agree("describe float storage", more.describe(a, f, &.{"d"}), more.test_hooks.describeCells(a, f, &.{"d"}));
    const t = try more.describe(a, f, &.{"d"});
    try testing.expect(std.math.signbit(t.columnAt(1).get(3).float));
    // The default selection still goes by the declared type: a duration is not described.
    try testing.expectEqual(@as(usize, 1), (try more.describe(a, f, &.{})).columns.len);
}
