// SPDX-License-Identifier: MIT
//! Hand-written tests of dataframe S2 wave W3: constructors (`ranges.zig`), the small `Expr`
//! functions, selectors, name verbs and column functions (`colfn.zig`). The engines'
//! answers are replayed in `s2w3_oracle_test.zig`; these cover what they cannot: caps,
//! errors, hostile input, and the pieces the oracle script could not generate.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const st = @import("structure.zig");
const rg = @import("ranges.zig");
const nm = @import("names.zig");
const cf = @import("colfn.zig");
const dtf = @import("dtfn.zig");
const Frame = fm.Frame;
const Value = vm.Value;

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

fn intFrame(a: std.mem.Allocator, names: []const []const u8, rows: []const []const ?i64) !Frame {
    const cols = try a.alloc(vm.Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    for (cols, data, names, rows) |*c, *d, n, r| {
        c.* = .{ .name = n, .type = .int };
        const cells = try a.alloc(Value, r.len);
        for (cells, r) |*o, x| o.* = if (x) |v| .{ .int = v } else .null;
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = rows[0].len };
}

test "intRange: caps, zero step, direction" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    try testing.expectError(error.BadArgument, rg.intRange(a, "r", 0, 10, 0));
    try testing.expectError(error.TooLarge, rg.intRange(a, "r", 0, std.math.maxInt(i64), 1));
    try testing.expectError(error.TooLarge, rg.intRange(a, "r", std.math.minInt(i64), std.math.maxInt(i64), 1));
    const f = try rg.intRange(a, "r", std.math.maxInt(i64) - 3, std.math.maxInt(i64), 2);
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expectEqual(@as(i64, std.math.maxInt(i64) - 1), f.cell(1, "r").?.int);
    const g = try rg.intRange(a, "r", 5, 0, 1);
    try testing.expectEqual(@as(usize, 0), g.len);
}

test "ranges: cap on every constructor" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    try testing.expectError(error.TooLarge, rg.linearSpace(a, "r", 0, 1, rg.max_range_rows + 1, .both));
    try testing.expectError(error.TooLarge, rg.repeatValue(a, "r", .{ .int = 1 }, std.math.maxInt(usize), null));
    try testing.expectError(error.TooLarge, rg.dateRangePeriods(a, "r", .{ .y = 2024, .m = 1, .d = 1 }, std.math.maxInt(usize), .{}));
    try testing.expectError(error.TooLarge, rg.datetimeRange(a, "r", 0, std.math.maxInt(i64), .{ .interval = "1us" }));
    try testing.expectError(error.TooLarge, rg.datetimeSpace(a, "r", 0, 10, std.math.maxInt(usize)));
    try testing.expectError(error.TooLarge, rg.intRanges(a, "r", &.{0}, &.{std.math.maxInt(i64)}, 1));
}

test "calendar ranges: bad intervals" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const d1: vm.Date = .{ .y = 2024, .m = 1, .d = 1 };
    const d2: vm.Date = .{ .y = 2024, .m = 2, .d = 1 };
    try testing.expectError(error.BadInterval, rg.dateRange(a, "r", d1, d2, .{ .interval = "" }));
    try testing.expectError(error.BadInterval, rg.dateRange(a, "r", d1, d2, .{ .interval = "-1d" }));
    try testing.expectError(error.BadInterval, rg.dateRange(a, "r", d1, d2, .{ .interval = "0d" }));
    try testing.expectError(error.BadInterval, rg.dateRange(a, "r", d1, d2, .{ .interval = "12h" }));
    try testing.expectError(error.BadInterval, rg.dateRange(a, "r", d1, d2, .{ .interval = "1mo1d" }));
    try testing.expectError(error.BadInterval, rg.dateRange(a, "r", d1, d2, .{ .interval = "1mo", .business = true }));
    const ok = try rg.datetimeRange(a, "r", 0, 3 * 3600 * 1_000_000, .{ .interval = "1h" });
    try testing.expectEqual(@as(usize, 4), ok.len);
    try testing.expectEqual(vm.ColumnType.timestamp, ok.columns[0].type);
}

test "calendar ranges: a caller-built Date beyond the timestamp range is an error, not an overflow" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const huge: vm.Date = .{ .y = std.math.maxInt(i32), .m = 12, .d = 31 };
    const tiny: vm.Date = .{ .y = std.math.minInt(i32), .m = 1, .d = 1 };
    const d1: vm.Date = .{ .y = 2024, .m = 1, .d = 1 };
    try testing.expectError(error.BadArgument, rg.dateRange(a, "r", d1, huge, .{}));
    try testing.expectError(error.BadArgument, rg.dateRange(a, "r", tiny, d1, .{}));
    try testing.expectError(error.BadArgument, rg.dateRangePeriods(a, "r", huge, 3, .{}));
}

test "intRanges: broadcast, null bound, mismatch" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try rg.intRanges(a, "r", &.{ 0, null, 2 }, &.{3}, 1);
    try testing.expectEqual(@as(usize, 3), f.len);
    try testing.expectEqual(@as(usize, 3), f.cell(0, "r").?.list.len());
    try testing.expect(f.cell(1, "r").? == .null);
    try testing.expectEqual(@as(usize, 1), f.cell(2, "r").?.list.len());
    try testing.expectError(error.BadArgument, rg.intRanges(a, "r", &.{ 0, 1 }, &.{ 1, 2, 3 }, 1));
    try testing.expectError(error.BadArgument, rg.intRanges(a, "r", &.{0}, &.{1}, 0));
}

test "repeatValue / ones / zeros types" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const t = try rg.repeatValue(a, "r", .{ .text = "x" }, 3, null);
    try testing.expectEqual(vm.ColumnType.text, t.columns[0].type);
    try testing.expectEqualStrings("x", t.cell(2, "r").?.text);
    const o = try rg.ones(a, "r", 2, true);
    try testing.expectEqual(vm.ColumnType.float, o.columns[0].type);
    const z = try rg.zeros(a, "r", 0, false);
    try testing.expectEqual(@as(usize, 0), z.len);
}

test "Expr: hostile inputs give null or errors, never a panic" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ "x", "y" }, &.{ &.{ std.math.minInt(i64), 5, 0, 1 }, &.{ -1, 0, 0, std.math.maxInt(i64) } });
    const x: ex.Expr = .{ .col = "x" };
    const y: ex.Expr = .{ .col = "y" };
    const out = try ex.mutate(a, f, &.{
        .{ .out = "q", .expr = .{ .binary = .{ .op = .truncdiv, .l = &x, .r = &y } } },
        .{ .out = "d", .expr = .{ .make_duration = .{ .weeks = &x, .days = &y } } },
        .{ .out = "e", .expr = .{ .from_epoch = .{ .x = &x, .unit = .s } } },
        .{ .out = "m", .expr = .{ .make_date = .{ .year = &x, .month = &y, .day = &y } } },
    });
    try testing.expect(out.cell(0, "q").? == .null); // minInt / -1
    try testing.expect(out.cell(1, "q").? == .null); // 5 / 0
    try testing.expect(out.cell(3, "q").?.int == 0);
    try testing.expect(out.cell(0, "d").? == .null); // overflow
    try testing.expect(out.cell(0, "e").? == .null);
    try testing.expect(out.cell(0, "m").? == .null);
}

test "Expr: fold and concat_str edge cases" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{"x"}, &.{&.{ 1, 2 }});
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .fold = .{ .op = .add, .parts = &.{} } } }}));
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .concat_str = .{ .parts = &.{} } } }}));
    // a fold of one part with an acc
    const zero: ex.Expr = .{ .lit = .{ .int = 10 } };
    const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .fold = .{ .op = .add, .parts = &.{.{ .col = "x" }}, .acc = &zero } } }});
    try testing.expectEqual(@as(i64, 12), out.cell(1, "o").?.int);
}

test "Expr: business_day_count dedups holidays and handles reversed bounds" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fm.FrameBuilder.init(a, &.{ .{ .name = "s", .type = .date }, .{ .name = "e", .type = .date } }, 1);
    var b = f;
    try b.appendRow(&.{ .{ .text = "2024-01-01" }, .{ .text = "2024-01-15" } });
    const fr = try b.toOwned();
    const s: ex.Expr = .{ .col = "s" };
    const e: ex.Expr = .{ .col = "e" };
    const h = [_]vm.Date{ .{ .y = 2024, .m = 1, .d = 3 }, .{ .y = 2024, .m = 1, .d = 3 }, .{ .y = 2024, .m = 1, .d = 6 } };
    const out = try ex.mutate(a, fr, &.{
        .{ .out = "n", .expr = .{ .business_day_count = .{ .start = &s, .end = &e, .holidays = &h } } },
        .{ .out = "r", .expr = .{ .business_day_count = .{ .start = &e, .end = &s } } },
    });
    try testing.expectEqual(@as(i64, 9), out.cell(0, "n").?.int); // 10 weekdays minus the 3rd; the 6th is a Saturday
    try testing.expectEqual(@as(i64, -10), out.cell(0, "r").?.int);
}

test "Selector: alpha, alphanumeric, digit, nested" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ "abc", "ab1", "123", "a b" }, &.{ &.{1}, &.{1}, &.{1}, &.{1} });
    try testing.expectEqual(@as(usize, 1), (try st.selectColumns(a, f, .alpha)).len);
    try testing.expectEqual(@as(usize, 3), (try st.selectColumns(a, f, .alphanumeric)).len);
    try testing.expectEqualStrings("123", (try st.selectColumns(a, f, .digit))[0]);
    try testing.expectEqual(@as(usize, 0), (try st.selectColumns(a, f, .nested)).len);
}

test "names: duplicates refused, selector scoping, bad pattern" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ "A", "a", "B" }, &.{ &.{1}, &.{1}, &.{1} });
    try testing.expectError(error.DuplicateColumn, nm.renameLower(a, f, .all));
    const g = try nm.renameLower(a, f, .{ .by_name = &.{"B"} });
    try testing.expectEqualStrings("b", g.columns[2].name);
    try testing.expectEqualStrings("A", g.columns[0].name);
    try testing.expectError(error.BadPattern, nm.renameReplace(a, f, .{ .pattern = "(", .with = "" }));
    try testing.expectError(error.BadArgument, nm.renameReplace(a, f, .{ .pattern = "", .with = "x", .literal = true }));
    const h = try nm.renameReplace(a, f, .{ .pattern = "A", .with = "Z", .literal = true, .all = false });
    try testing.expectEqualStrings("Z", h.columns[0].name);
}

test "item, uniqueCounts, hist errors" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const one = try intFrame(a, &.{"x"}, &.{&.{7}});
    try testing.expectEqual(@as(i64, 7), (try cf.item(one, null)).int);
    try testing.expectEqual(@as(i64, 7), (try cf.item(one, "x")).int);
    const two = try intFrame(a, &.{"x"}, &.{&.{ 7, 8 }});
    try testing.expectError(error.NotOneValue, cf.item(two, "x"));
    try testing.expectError(error.NoSuchColumn, cf.item(one, "nope"));
    try testing.expectError(error.BadArgument, cf.hist(a, two, .{ .col = "x", .bin_count = 0 }));
    try testing.expectError(error.BadArgument, cf.hist(a, two, .{ .col = "x", .bins = &.{ 1, 1 } }));
    try testing.expectError(error.BadArgument, cf.hist(a, two, .{ .col = "x", .bins = &.{1} }));
    try testing.expectError(error.BadArgument, cf.hist(a, two, .{ .col = "x", .bin_count = std.math.maxInt(usize) }));
}

fn maxCells(_: void, a: std.mem.Allocator, acc: Value, x: Value) error{OutOfMemory}!Value {
    _ = a;
    return if (acc.order(x) == .lt) x else acc;
}

test "foldColumns and cumFoldColumns with a callback" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try intFrame(a, &.{ "a", "b", "c" }, &.{ &.{ 1, 9 }, &.{ 5, 2 }, &.{ 3, 4 } });
    const r = try cf.foldColumns(a, f, .{ .out = "m" }, {}, maxCells);
    try testing.expectEqual(@as(i64, 5), r.cell(0, "m").?.int);
    try testing.expectEqual(@as(i64, 9), r.cell(1, "m").?.int);
    const c = try cf.cumFoldColumns(a, f, .{}, {}, maxCells);
    try testing.expectEqual(@as(i64, 5), c.cell(0, "b").?.int);
    try testing.expectEqual(@as(i64, 5), c.cell(0, "c").?.int);
    try testing.expectEqual(@as(i64, 9), c.cell(1, "a").?.int);
    try testing.expectError(error.NoSuchColumn, cf.foldColumns(a, f, .{ .out = "m", .cols = &.{"zz"} }, {}, maxCells));
}

test "alignFrames: sorted union, missing rows null, descending (hand-derived from polars' definition)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f1 = try intFrame(a, &.{ "k", "u" }, &.{ &.{ 3, 1, 2 }, &.{ 30, 10, 20 } });
    const f2 = try intFrame(a, &.{ "k", "v" }, &.{ &.{ 2, 5 }, &.{ 200, 500 } });
    const out = try cf.alignFrames(a, &.{ f1, f2 }, .{ .on = &.{"k"} });
    try testing.expectEqual(@as(usize, 4), out[0].len);
    try testing.expectEqual(@as(i64, 5), out[0].cell(3, "k").?.int);
    try testing.expect(out[0].cell(3, "u").? == .null);
    try testing.expectEqual(@as(i64, 10), out[0].cell(0, "u").?.int);
    try testing.expect(out[1].cell(0, "v").? == .null);
    try testing.expectEqual(@as(i64, 200), out[1].cell(1, "v").?.int);
    const d = try cf.alignFrames(a, &.{ f1, f2 }, .{ .on = &.{"k"}, .reverse = true });
    try testing.expectEqual(@as(i64, 5), d[1].cell(0, "k").?.int);
    try testing.expectError(error.BadArgument, cf.alignFrames(a, &.{f1}, .{ .on = &.{} }));
    try testing.expectError(error.NoSuchColumn, cf.alignFrames(a, &.{ f1, f2 }, .{ .on = &.{"zz"} }));
}

test "dtfn helpers: businessDayCount closed form, makeDatetime ranges" {
    // 1970-01-01 is a Thursday (epoch day 0): [0, 14) holds 10 weekdays.
    try testing.expectEqual(@as(i64, 10), dtf.businessDayCount(0, 14, dtf.monday_to_friday, &.{}));
    try testing.expectEqual(@as(i64, -10), dtf.businessDayCount(14, 0, dtf.monday_to_friday, &.{}));
    try testing.expectEqual(@as(i64, 0), dtf.businessDayCount(2, 4, dtf.monday_to_friday, &.{})); // Sat, Sun
    try testing.expect(dtf.makeDatetime(2024, 1, 1, 24, 0, 0, 0) == .null);
    try testing.expect(dtf.makeDatetime(std.math.maxInt(i64), 1, 1, 0, 0, 0, 0) == .null);
    try testing.expect(dtf.makeDatetime(2024, 2, 30, 0, 0, 0, 0) == .null);
    try testing.expectEqual(@as(i64, 86_400_000_000), dtf.makeDatetime(1970, 1, 2, 0, 0, 0, 0).int);
}
