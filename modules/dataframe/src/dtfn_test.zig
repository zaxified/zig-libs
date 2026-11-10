// SPDX-License-Identifier: MIT
//! The `dt` accessor, `strptime`/`strftime`, `offset_by`, `truncate` and business days,
//! through `mutate`. Expected values from the calendar (checked by hand against the
//! weekdays of known dates) and pandas'/polars' documented semantics.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Expr = df.Expr;

const X: Expr = .{ .col = "x" };

fn run(a: std.mem.Allocator, x: Value, e: Expr) !Value {
    const f = try st.mk(a, &.{.{ .name = "x", .type = .text }}, &.{&.{x}});
    const g = try df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
    return g.cell(0, "out").?;
}

fn part(a: std.mem.Allocator, x: Value, p: df.DtPart) !Value {
    return run(a, x, .{ .dt = .{ .x = &X, .part = p } });
}

fn expectV(want: Value, got: Value) !void {
    if (!st.same(got, want)) {
        std.debug.print("got {any}, want {any}\n", .{ got, want });
        return error.TestUnexpectedResult;
    }
}

fn txt(t: []const u8) Value {
    return .{ .text = t };
}

fn ts(s: []const u8) Value {
    return .{ .int = df.parseIsoTimestamp(s).? };
}

test "dt components of a date and of a timestamp" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = txt("2024-02-29"); // a Thursday
    try expectV(.{ .int = 2024 }, try part(a, d, .year));
    try expectV(.{ .int = 2 }, try part(a, d, .month));
    try expectV(.{ .int = 29 }, try part(a, d, .day));
    try expectV(.{ .int = 4 }, try part(a, d, .weekday));
    try expectV(.{ .int = 60 }, try part(a, d, .day_of_year));
    try expectV(.{ .int = 9 }, try part(a, d, .iso_week));
    try expectV(.{ .int = 1 }, try part(a, d, .quarter));
    try expectV(.{ .int = 29 }, try part(a, d, .days_in_month));
    try expectV(.{ .bool = true }, try part(a, d, .is_leap_year));
    try expectV(.{ .bool = true }, try part(a, d, .is_month_end));
    try expectV(.{ .bool = false }, try part(a, d, .is_quarter_end));
    try expectV(.{ .bool = false }, try part(a, d, .is_month_start));
    try expectV(txt("February"), try part(a, d, .month_name));
    try expectV(txt("Thursday"), try part(a, d, .day_name));
    try expectV(.{ .int = 0 }, try part(a, d, .hour));
    try expectV(txt("2024-02-01"), try part(a, txt("2024-02-10"), .month_start));
    try expectV(txt("2024-02-29"), try part(a, txt("2024-02-10"), .month_end));
    try expectV(.{ .bool = true }, try part(a, txt("2023-12-31"), .is_year_end));
    try expectV(.{ .bool = true }, try part(a, txt("2023-10-01"), .is_quarter_start));

    const t = ts("2021-01-03T12:34:56.789012Z"); // a Sunday, ISO week 53 of 2020
    try expectV(.{ .int = 2021 }, try part(a, t, .year));
    try expectV(.{ .int = 2020 }, try part(a, t, .iso_year));
    try expectV(.{ .int = 53 }, try part(a, t, .iso_week));
    try expectV(.{ .int = 7 }, try part(a, t, .weekday));
    try expectV(.{ .bool = false }, try part(a, t, .is_business_day));
    try expectV(.{ .int = 12 }, try part(a, t, .hour));
    try expectV(.{ .int = 34 }, try part(a, t, .minute));
    try expectV(.{ .int = 56 }, try part(a, t, .second));
    try expectV(.{ .int = 789 }, try part(a, t, .millisecond));
    try expectV(.{ .int = 789012 }, try part(a, t, .microsecond));
    try expectV(.{ .int = 789012000 }, try part(a, t, .nanosecond));
    try expectV(.{ .int = 18630 }, try part(a, t, .epoch_days));
    try expectV(.{ .int = @divFloor(t.int, 1_000_000) }, try part(a, t, .epoch_seconds));
    try expectV(txt("2021-01-03"), try part(a, t, .date));
    // `dt.time` is a time-of-day cell (microseconds since midnight), no longer text.
    try expectV(.{ .int = (12 * 3600 + 34 * 60 + 56) * 1_000_000 + 789012 }, try part(a, t, .time));
    try expectV(.{ .int = 0 }, try part(a, d, .time));
    try expectV(ts("2021-01-01T12:34:56.789012Z"), try part(a, t, .month_start));
    // A timestamp as ISO text keeps that shape.
    try expectV(.{ .int = 56 }, try part(a, txt("2021-01-03 12:34:56"), .second));
    // Before the epoch: floors, not truncation.
    try expectV(.{ .int = 1969 }, try part(a, .{ .int = -1 }, .year));
    try expectV(.{ .int = 999999 }, try part(a, .{ .int = -1 }, .microsecond));
    try expectV(.null, try part(a, txt("2024-02-30"), .year));
    try expectV(.null, try part(a, .{ .float = 1 }, .year));
    try expectV(.null, try part(a, .null, .year));
    // The whole i64 range is a valid timestamp: nothing to panic on.
    _ = try part(a, .{ .int = std.math.minInt(i64) }, .iso_week);
    _ = try part(a, .{ .int = std.math.maxInt(i64) }, .month_end);
}

test "strptime and strftime with % directives" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parse = struct {
        fn f(al: std.mem.Allocator, x: Value, fmt: []const u8, to: df.ParseTo) !Value {
            return run(al, x, .{ .strptime = .{ .x = &X, .format = fmt, .to = to } });
        }
    }.f;
    const fmtf = struct {
        fn f(al: std.mem.Allocator, x: Value, fmt: []const u8) !Value {
            return run(al, x, .{ .strftime = .{ .x = &X, .format = fmt } });
        }
    }.f;
    try expectV(txt("2024-03-15"), try parse(a, txt("03/15/2024"), "%m/%d/%Y", .date));
    try expectV(ts("2024-03-15T10:20:30Z"), try parse(a, txt("2024-03-15 10:20:30"), "%Y-%m-%d %H:%M:%S", .timestamp));
    try expectV(ts("2024-03-15T08:20:30Z"), try parse(a, txt("2024-03-15T10:20:30+0200"), "%Y-%m-%dT%H:%M:%S%z", .timestamp));
    try expectV(ts("2024-03-15T10:20:30.123456Z"), try parse(a, txt("2024-03-15 10:20:30.123456"), "%F %T.%f", .timestamp));
    try expectV(txt("2024-03-15"), try parse(a, txt("15 Mar 2024"), "%d %b %Y", .date));
    try expectV(.null, try parse(a, txt("2024-03-15x"), "%Y-%m-%d", .date));
    try expectV(.null, try parse(a, txt("2024-02-30"), "%Y-%m-%d", .date));
    try expectV(.null, try parse(a, .{ .int = 1 }, "%Y", .date));
    try testing.expectError(error.BadExpr, parse(a, txt("x"), "%Q", .date));
    // `[` and `]` are literals in a layout, as in the engines'
    try expectV(txt("2024-03-15"), try parse(a, txt("[2024-03-15]"), "[%Y-%m-%d]", .date));
    try expectV(.null, try parse(a, txt("2024-03-15"), "[%Y-%m-%d]", .date));
    try testing.expectError(error.BadExpr, parse(a, txt("x"), "%", .date));

    const t = ts("2021-01-03T12:34:56.789012Z");
    try expectV(txt("2021/01/03 12:34"), try fmtf(a, t, "%Y/%m/%d %H:%M"));
    try expectV(txt("Thursday 29 February 2024, day 060, 100%"), try fmtf(a, txt("2024-02-29"), "%A %d %B %Y, day %j, 100%%"));
    try expectV(txt("12:34:56.789012 PM"), try fmtf(a, t, "%T.%f %p"));
    try expectV(.null, try fmtf(a, txt("nope"), "%Y"));
}

test "offset_by, truncate, business days" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const off = struct {
        fn f(al: std.mem.Allocator, x: Value, by: []const u8) !Value {
            return run(al, x, .{ .offset_by = .{ .x = &X, .by = by } });
        }
    }.f;
    const tr = struct {
        fn f(al: std.mem.Allocator, x: Value, every: []const u8) !Value {
            return run(al, x, .{ .truncate = .{ .x = &X, .every = every } });
        }
    }.f;
    const bd = struct {
        fn f(al: std.mem.Allocator, x: Value, n: i64) !Value {
            return run(al, x, .{ .add_business_days = .{ .x = &X, .n = n } });
        }
    }.f;
    try expectV(txt("2024-02-29"), try off(a, txt("2024-01-31"), "1mo"));
    try expectV(txt("2023-01-31"), try off(a, txt("2024-01-31"), "-1y"));
    try expectV(txt("2025-04-03"), try off(a, txt("2024-01-31"), "1y2mo3d"));
    const t = ts("2021-01-03T12:34:56.789012Z");
    try expectV(ts("2021-01-04T14:34:56.789012Z"), try off(a, t, "1d2h"));
    try expectV(ts("2021-01-03T12:34:56.789013Z"), try off(a, t, "1000ns"));
    try expectV(.null, try off(a, .{ .int = std.math.maxInt(i64) }, "1us"));
    try testing.expectError(error.BadExpr, off(a, t, "1x"));
    try testing.expectError(error.BadExpr, off(a, t, ""));
    try testing.expectError(error.BadExpr, off(a, t, "d"));
    try testing.expectError(error.BadExpr, off(a, t, "99999999999999999999d"));

    try expectV(ts("2021-01-03T12:00:00Z"), try tr(a, t, "1h"));
    try expectV(ts("2021-01-03T12:30:00Z"), try tr(a, t, "15m"));
    try expectV(ts("2021-01-03T00:00:00Z"), try tr(a, t, "1d"));
    try expectV(ts("2020-12-28T00:00:00Z"), try tr(a, t, "1w")); // the Monday
    try expectV(ts("2021-01-01T00:00:00Z"), try tr(a, t, "1mo"));
    try expectV(txt("2024-07-01"), try tr(a, txt("2024-08-15"), "3mo"));
    try expectV(txt("2024-01-01"), try tr(a, txt("2024-08-15"), "1y"));
    try expectV(.{ .int = -1_000_000 }, try tr(a, .{ .int = -1 }, "1s"));
    _ = try tr(a, .{ .int = std.math.minInt(i64) }, "7d");
    try testing.expectError(error.BadExpr, tr(a, t, "0h"));
    try testing.expectError(error.BadExpr, tr(a, t, "-1h"));
    try testing.expectError(error.BadExpr, tr(a, t, "1mo1d"));

    try expectV(txt("2024-03-11"), try bd(a, txt("2024-03-08"), 1)); // Friday + 1
    try expectV(txt("2024-03-11"), try bd(a, txt("2024-03-09"), 0)); // Saturday rolls
    try expectV(txt("2024-03-08"), try bd(a, txt("2024-03-11"), -1));
    try expectV(txt("2024-03-18"), try bd(a, txt("2024-03-11"), 5));
    try expectV(txt("2024-03-25"), try bd(a, txt("2024-03-13"), 8));
    try expectV(.null, try bd(a, txt("2024-03-13"), std.math.maxInt(i64)));
    try expectV(ts("2021-01-05T12:34:56.789012Z"), try bd(a, t, 1)); // Sunday rolls to Monday, + 1
}

test "parseDuration" {
    const d = df.parseDuration("1y2mo3d").?;
    try testing.expectEqual(@as(i64, 14), d.months);
    try testing.expectEqual(@as(i64, 3 * 86_400_000_000), d.us);
    const n = df.parseDuration("-1q90m").?;
    try testing.expectEqual(@as(i64, -3), n.months);
    try testing.expectEqual(@as(i64, -90 * 60_000_000), n.us);
    try testing.expect(df.parseDuration("1.5h") == null);
    try testing.expect(df.parseDuration("-") == null);
}

test "truncate modes: ceil and nearest (polars dt.round, pandas dt.ceil), on a boundary, months, range edges" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tr = struct {
        fn f(al: std.mem.Allocator, x: Value, every: []const u8, mode: df.RoundTo) !Value {
            return run(al, x, .{ .truncate = .{ .x = &X, .every = every, .mode = mode } });
        }
    }.f;
    const t = ts("2021-01-03T12:34:56.789012Z");
    try expectV(ts("2021-01-03T13:00:00Z"), try tr(a, t, "1h", .ceil));
    try expectV(ts("2021-01-03T13:00:00Z"), try tr(a, t, "1h", .nearest));
    try expectV(ts("2021-01-03T12:30:00Z"), try tr(a, t, "15m", .nearest));
    // A tie goes to the later bucket start (polars).
    try expectV(ts("2021-01-03T13:00:00Z"), try tr(a, ts("2021-01-03T12:30:00Z"), "1h", .nearest));
    // On a boundary every mode stays.
    const on = ts("2021-01-03T12:00:00Z");
    try expectV(on, try tr(a, on, "1h", .ceil));
    try expectV(on, try tr(a, on, "1h", .nearest));
    // Months: 2024-02-15 is 14 days after Feb 1 and 15 before Mar 1.
    try expectV(txt("2024-03-01"), try tr(a, txt("2024-02-15"), "1mo", .ceil));
    try expectV(txt("2024-02-01"), try tr(a, txt("2024-02-15"), "1mo", .nearest));
    try expectV(txt("2024-03-01"), try tr(a, txt("2024-02-16"), "1mo", .nearest));
    try expectV(txt("2024-02-01"), try tr(a, txt("2024-02-01"), "1mo", .ceil));
    // Past the end of the range: the ceiling is null, the floor and the nearest still exist.
    try expectV(.null, try tr(a, .{ .int = std.math.maxInt(i64) }, "7d", .ceil));
    _ = try tr(a, .{ .int = std.math.maxInt(i64) }, "7d", .nearest);
    _ = try tr(a, .{ .int = std.math.minInt(i64) }, "1mo", .ceil);
    _ = try tr(a, .{ .int = std.math.maxInt(i64) }, "1y", .nearest);
}
