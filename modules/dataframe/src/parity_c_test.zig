// SPDX-License-Identifier: MIT
//! dataframe parity close, agent C (2026-11-10): the plural ranges (`dateRanges`,
//! `datetimeRanges`, `linearSpaces`), `toLatex` and `argWhere`. The polars examples
//! (`date_ranges`, `datetime_ranges`, `linear_spaces`) and pandas' `to_latex` layout are the
//! vectors; the rest is hostile input, which must give an error and never a panic.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const Column = df.Column;

const day_us: i64 = 86_400 * 1_000_000;

fn d(y: i32, m: u8, dd: u8) df.Date {
    return .{ .y = y, .m = m, .d = dd };
}

test "dateRanges: polars' documented example" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // start = [2022-01-01, 2022-01-02], end = 2022-01-03 (broadcast)
    const f = try df.dateRanges(a, "r", &.{ d(2022, 1, 1), d(2022, 1, 2) }, &.{d(2022, 1, 3)}, .{});
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expectEqual(df.ColumnType.list, f.columns[0].type);
    try testing.expectEqual(df.ColumnType.date, f.columns[0].inner[0].type);
    const r0 = f.cell(0, "r").?.list;
    try testing.expectEqual(@as(usize, 3), r0.len());
    try testing.expectEqualStrings("2022-01-01", r0.get(0).text);
    try testing.expectEqualStrings("2022-01-03", r0.get(2).text);
    const r1 = f.cell(1, "r").?.list;
    try testing.expectEqual(@as(usize, 2), r1.len());
    try testing.expectEqualStrings("2022-01-02", r1.get(0).text);
    // closed = none, a null bound, a reversed row
    const g = try df.dateRanges(a, "r", &.{ d(2022, 1, 1), null, d(2022, 1, 9) }, &.{d(2022, 1, 3)}, .{ .closed = .none });
    try testing.expectEqual(@as(usize, 1), g.cell(0, "r").?.list.len());
    try testing.expect(g.cell(1, "r").? == .null);
    try testing.expectEqual(@as(usize, 0), g.cell(2, "r").?.list.len());
}

test "datetimeRanges: polars' documented example" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base: i64 = 18993 * day_us; // 2022-01-01
    const f = try df.datetimeRanges(a, "r", &.{ base, base + day_us }, &.{base + 2 * day_us}, .{ .interval = "1d" });
    try testing.expectEqual(df.ColumnType.timestamp, f.columns[0].inner[0].type);
    const r0 = f.cell(0, "r").?.list;
    try testing.expectEqual(@as(usize, 3), r0.len());
    try testing.expectEqual(base + day_us, r0.get(1).int);
    try testing.expectEqual(@as(usize, 2), f.cell(1, "r").?.list.len());
    // an interval finer than a day is fine here, a month steps from the start
    const h = try df.datetimeRanges(a, "r", &.{base}, &.{base + 3 * 3600 * 1_000_000}, .{ .interval = "1h", .closed = .left });
    try testing.expectEqual(@as(usize, 3), h.cell(0, "r").?.list.len());
}

test "linearSpaces: one list per row" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // polars' example has num_samples per row; here one count is broadcast.
    const f = try df.linearSpaces(a, "r", &.{ 1, -1, null }, &.{ 3, 2, 5 }, &.{3}, .both);
    try testing.expectEqual(@as(usize, 3), f.len);
    const r0 = f.cell(0, "r").?.list;
    try testing.expectEqual(@as(f64, 1), r0.get(0).float);
    try testing.expectEqual(@as(f64, 2), r0.get(1).float);
    try testing.expectEqual(@as(f64, 3), r0.get(2).float);
    const r1 = f.cell(1, "r").?.list;
    try testing.expectEqual(@as(f64, -1), r1.get(0).float);
    try testing.expectEqual(@as(f64, 0.5), r1.get(1).float);
    try testing.expectEqual(@as(f64, 2), r1.get(2).float);
    try testing.expect(f.cell(2, "r").? == .null);
    const g = try df.linearSpaces(a, "r", &.{0}, &.{4}, &.{4}, .left);
    try testing.expectEqual(@as(f64, 3), g.cell(0, "r").?.list.get(3).float);
}

test "plural ranges: hostile input is an error or empty, never a panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base: i64 = 0;
    // mismatched lengths
    try testing.expectError(error.BadArgument, df.dateRanges(a, "r", &.{ d(2022, 1, 1), d(2022, 1, 2) }, &.{ d(2022, 1, 3), d(2022, 1, 3), d(2022, 1, 4) }, .{}));
    try testing.expectError(error.BadArgument, df.datetimeRanges(a, "r", &.{ 1, 2 }, &.{ 1, 2, 3 }, .{}));
    try testing.expectError(error.BadArgument, df.linearSpaces(a, "r", &.{ 1, 2 }, &.{ 1, 2, 3 }, &.{3}, .both));
    try testing.expectError(error.BadArgument, df.dateRanges(a, "r", &.{}, &.{ d(2022, 1, 3), d(2022, 1, 3) }, .{}));
    // empty inputs: no rows
    try testing.expectEqual(@as(usize, 0), (try df.dateRanges(a, "r", &.{}, &.{d(2022, 1, 3)}, .{})).len);
    try testing.expectEqual(@as(usize, 0), (try df.linearSpaces(a, "r", &.{1}, &.{}, &.{3}, .both)).len);
    // bad intervals: zero, negative, empty, finer than a day, garbage
    for ([_][]const u8{ "0d", "-1d", "", "12h", "1mo1d", "xyz", "99999999999999999999d" }) |iv| {
        try testing.expectError(error.BadInterval, df.dateRanges(a, "r", &.{d(2022, 1, 1)}, &.{d(2022, 1, 5)}, .{ .interval = iv }));
    }
    for ([_][]const u8{ "0h", "-1h", "", "1mo1d", "abc" }) |iv| {
        try testing.expectError(error.BadInterval, df.datetimeRanges(a, "r", &.{base}, &.{base + day_us}, .{ .interval = iv }));
    }
    // reversed ranges are empty rows
    const rev = try df.datetimeRanges(a, "r", &.{base + day_us}, &.{base}, .{});
    try testing.expectEqual(@as(usize, 0), rev.cell(0, "r").?.list.len());
    // caps: one huge row, and many rows adding up
    try testing.expectError(error.TooLarge, df.datetimeRanges(a, "r", &.{0}, &.{std.math.maxInt(i64)}, .{ .interval = "1us" }));
    var many: [64]?i64 = undefined;
    @memset(&many, 0);
    try testing.expectError(error.TooLarge, df.datetimeRanges(a, "r", &many, &.{1 << 20}, .{ .interval = "1us" }));
    // caller-built dates far outside the timestamp range
    const huge: df.Date = .{ .y = std.math.maxInt(i32), .m = 12, .d = 31 };
    const tiny: df.Date = .{ .y = std.math.minInt(i32), .m = 0, .d = 0 };
    try testing.expectError(error.BadArgument, df.dateRanges(a, "r", &.{d(2022, 1, 1)}, &.{huge}, .{}));
    try testing.expectError(error.BadArgument, df.dateRanges(a, "r", &.{tiny}, &.{d(2022, 1, 1)}, .{}));
    // extreme timestamps do not overflow
    _ = df.datetimeRanges(a, "r", &.{std.math.minInt(i64)}, &.{std.math.maxInt(i64)}, .{ .interval = "1d" }) catch {};
    _ = df.datetimeRanges(a, "r", &.{std.math.maxInt(i64) - 5}, &.{std.math.maxInt(i64)}, .{ .interval = "1us" }) catch {};
    // linearSpaces: n = 0, 1, huge; non-finite bounds
    const z = try df.linearSpaces(a, "r", &.{ 0, 1 }, &.{ 1, 2 }, &.{0}, .both);
    try testing.expectEqual(@as(usize, 0), z.cell(0, "r").?.list.len());
    const one = try df.linearSpaces(a, "r", &.{7}, &.{9}, &.{1}, .both);
    try testing.expectEqual(@as(f64, 7), one.cell(0, "r").?.list.get(0).float);
    for ([_]df.Closed{ .both, .left, .right, .none }) |c| {
        _ = try df.linearSpaces(a, "r", &.{ std.math.inf(f64), std.math.nan(f64) }, &.{ 1, std.math.inf(f64) }, &.{3}, c);
        _ = try df.linearSpaces(a, "r", &.{1}, &.{2}, &.{1}, c);
    }
    try testing.expectError(error.TooLarge, df.linearSpaces(a, "r", &.{1}, &.{2}, &.{std.math.maxInt(usize)}, .both));
    try testing.expectError(error.TooLarge, df.linearSpaces(a, "r", &.{ 1, 2, 3 }, &.{4}, &.{df.max_range_rows / 2 + 1}, .both));
}

fn sample(a: std.mem.Allocator) !Frame {
    const names = try a.alloc(Value, 2);
    names[0] = .{ .text = "Raphael" };
    names[1] = .{ .text = "Donatello" };
    const ages = try a.alloc(Value, 2);
    ages[0] = .{ .int = 26 };
    ages[1] = .{ .int = 45 };
    const hs = try a.alloc(Value, 2);
    hs[0] = .{ .float = 181.23 };
    hs[1] = .{ .float = 177.65 };
    const cols = try a.dupe(Column, &.{ .{ .name = "name", .type = .text }, .{ .name = "age", .type = .int }, .{ .name = "height", .type = .float } });
    const data = try a.dupe(df.ColumnData, &.{ try df.columnFromCells(a, names), try df.columnFromCells(a, ages), try df.columnFromCells(a, hs) });
    return .{ .columns = cols, .data = data, .len = 2 };
}

test "toLatex: pandas' to_latex(index=False) layout" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample(a);
    // pandas docs example (without its formatters/float_format): lrr, booktabs rules.
    try testing.expectEqualStrings(
        "\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n" ++
            "Raphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n",
        try df.toLatex(a, f, .{}),
    );
    try testing.expectEqualStrings(
        "\\begin{table}\n\\caption{People}\n\\label{tab:p}\n\\begin{tabular}{lrr}\n\\toprule\nname & age & height \\\\\n\\midrule\n" ++
            "Raphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n",
        try df.toLatex(a, f, .{ .caption = "People", .label = "tab:p" }),
    );
    try testing.expectEqualStrings(
        "\\begin{tabular}{lrr}\n\\toprule\n\\midrule\nRaphael & 26 & 181.230000 \\\\\nDonatello & 45 & 177.650000 \\\\\n\\bottomrule\n\\end{tabular}\n",
        try df.toLatex(a, f, .{ .header = false }),
    );
}

test "toLatex: escape, na_rep, empty frames, hostile text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cells = try a.dupe(Value, &.{ .{ .text = "a&b%c$d#e_f{g}h~i^j\\k" }, .null, .{ .text = "\xff\xfe bad \x00 \n" } });
    const cols = try a.dupe(Column, &.{.{ .name = "x_y & \xff", .type = .text }});
    const data = try a.dupe(df.ColumnData, &.{try df.columnFromCells(a, cells)});
    const f: Frame = .{ .columns = cols, .data = data, .len = 3 };
    const raw = try df.toLatex(a, f, .{});
    try testing.expect(std.mem.indexOf(u8, raw, "a&b%c$d#e_f{g}h~i^j\\k") != null);
    const esc = try df.toLatex(a, f, .{ .escape = true, .null_text = "--" });
    try testing.expect(std.mem.indexOf(u8, esc, "x\\_y \\& \xff \\\\\n") != null);
    try testing.expect(std.mem.indexOf(u8, esc, "a\\&b\\%c\\$d\\#e\\_f\\{g\\}h\\textasciitilde i\\textasciicircum j\\textbackslash k \\\\\n") != null);
    try testing.expect(std.mem.indexOf(u8, esc, "\n-- \\\\\n") != null);
    // no rows, no columns
    const empty: Frame = .{ .columns = cols, .data = data, .len = 0 };
    try testing.expectEqualStrings("\\begin{tabular}{l}\n\\toprule\nx\\_y \\& \xff \\\\\n\\midrule\n\\bottomrule\n\\end{tabular}\n", try df.toLatex(a, empty, .{ .escape = true }));
    // pandas 3.1 `pd.DataFrame({"a": []}).iloc[:, 0:0].to_latex(index=False)` has no header line
    // (probe ~/CML/20261110-df-parity/z2_gen.py, case "zerocols-plain"; parity_z1_test.zig)
    const none: Frame = .{ .columns = &.{}, .data = &.{}, .len = std.math.maxInt(usize) };
    try testing.expectEqualStrings("\\begin{tabular}{}\n\\toprule\n\\midrule\n\\bottomrule\n\\end{tabular}\n", try df.toLatex(a, none, .{}));
}

test "argWhere: positions of true rows, null is false" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cells = try a.dupe(Value, &.{ .{ .int = 5 }, .null, .{ .int = 1 }, .{ .int = 9 } });
    const cols = try a.dupe(Column, &.{.{ .name = "n", .type = .int }});
    const data = try a.dupe(df.ColumnData, &.{try df.columnFromCells(a, cells)});
    const f: Frame = .{ .columns = cols, .data = data, .len = 4 };
    const c: df.Expr = .{ .col = "n" };
    const two: df.Expr = .{ .lit = .{ .int = 2 } };
    const idx = try df.argWhere(a, f, &.{ .binary = .{ .op = .gt, .l = &c, .r = &two } });
    try testing.expectEqualSlices(u32, &.{ 0, 3 }, idx);
    // the same rows `where` keeps
    const w = try df.where(a, f, &.{ .binary = .{ .op = .gt, .l = &c, .r = &two } });
    try testing.expectEqual(idx.len, w.len);
    // a non-bool condition keeps nothing; an unknown column is an error; no rows
    try testing.expectEqual(@as(usize, 0), (try df.argWhere(a, f, &c)).len);
    const bad: df.Expr = .{ .col = "nope" };
    try testing.expect(if (df.argWhere(a, f, &bad)) |_| false else |_| true);
    const e0: Frame = .{ .columns = cols, .data = data, .len = 0 };
    try testing.expectEqual(@as(usize, 0), (try df.argWhere(a, e0, &.{ .binary = .{ .op = .gt, .l = &c, .r = &two } })).len);
}
