// SPDX-License-Identifier: MIT
//! Operations over the time-of-day column (`ColumnType.time`, cells `Value.int` microseconds
//! since midnight), 2026-11-10. Expected values are polars 2.1's where the module's own
//! decision list quotes them (hour/minute/second parts, `mean`/`median` of times, `time_range`,
//! `strftime("%H-%M-%S%.f")`, `str.to_time("%I.%M%p")`, `time - time`); the rest are
//! hand-checked. The sweep runs the public verbs over a frame that holds a time column.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const dtf = @import("dtfn.zig");
const verbs = @import("verbs.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const Expr = ex.Expr;

const us_s: i64 = 1_000_000;
const t0102_03: i64 = (1 * 3600 + 2 * 60 + 3) * us_s; // 01:02:03
const t_last: i64 = 86_399_999_999; // 23:59:59.999999
const t_120ms: i64 = 120_000; // 00:00:00.120
const t_noon5: i64 = 12 * 3600 * us_s + 5; // 12:00:00.000005

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

fn ci(x: i64) Value {
    return .{ .int = x };
}

/// Columns `t` (time), `g` (int group), `s` (text), `z` (null only), `i` (int), `d` (timestamp).
fn fixture(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{
        .{ .name = "t", .type = .time },
        .{ .name = "g", .type = .int },
        .{ .name = "s", .type = .text },
        .{ .name = "z", .type = .int },
        .{ .name = "i", .type = .int },
    });
    var b = try fm.FrameBuilder.init(a, cols, 5);
    try b.appendRow(&.{ ci(t0102_03), ci(1), .{ .text = "a" }, .null, ci(10) });
    try b.appendRow(&.{ ci(t_last), ci(1), .{ .text = "b" }, .null, ci(20) });
    try b.appendRow(&.{ ci(t_120ms), ci(2), .{ .text = "a" }, .null, ci(30) });
    try b.appendRow(&.{ .null, ci(2), .null, .null, ci(40) });
    try b.appendRow(&.{ ci(t_noon5), ci(2), .{ .text = "c" }, .null, ci(50) });
    return b.toOwned();
}

fn col(a: std.mem.Allocator, name: []const u8) !*const Expr {
    const p = try a.create(Expr);
    p.* = .{ .col = name };
    return p;
}

fn lit(a: std.mem.Allocator, v: Value) !*const Expr {
    const p = try a.create(Expr);
    p.* = .{ .lit = v };
    return p;
}

fn mutate(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
}

fn cellOf(a: std.mem.Allocator, f: Frame, e: Expr, row: usize) !Value {
    return (try mutate(a, f, e)).cell(row, "o").?;
}

fn expectInt(want: i64, got: Value) !void {
    try testing.expect(got == .int);
    try testing.expectEqual(want, got.int);
}

fn expectText(want: []const u8, got: Value) !void {
    try testing.expect(got == .text);
    try testing.expectEqualStrings(want, got.text);
}

fn boxed(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

fn bin(a: std.mem.Allocator, op: ex.Binary, l: *const Expr, r: *const Expr) Expr {
    _ = a;
    return .{ .binary = .{ .op = op, .l = l, .r = r } };
}

// ── T1, T2, T10: the `dt` parts ─────────────────────────────────────────────

test "T1 dt clock parts of a time column (polars hour/minute/second/millisecond/microsecond/nanosecond)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const x = try col(a, "t");
    const Part = df.DtPart;
    // 01:02:03
    try expectInt(1, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.hour } }, 0));
    try expectInt(2, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.minute } }, 0));
    try expectInt(3, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.second } }, 0));
    // 23:59:59.999999
    try expectInt(999, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.millisecond } }, 1));
    try expectInt(999_999, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.microsecond } }, 1));
    try expectInt(999_999_000, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.nanosecond } }, 1));
    try expectInt(23, try cellOf(a, f, .{ .dt = .{ .x = x, .part = Part.hour } }, 1));
    // a null stays null; the result is a plain int column
    const g = try mutate(a, f, .{ .dt = .{ .x = x, .part = Part.hour } });
    try testing.expect(g.cell(3, "o").? == .null);
    try testing.expectEqual(ColumnType.int, g.columnType("o").?);
    // every other part is refused
    inline for (comptime std.meta.fieldNames(Part)) |pn| {
        const p = @field(Part, pn);
        switch (p) {
            .hour, .minute, .second, .millisecond, .microsecond, .nanosecond => {},
            else => try testing.expectError(error.BadExpr, mutate(a, f, .{ .dt = .{ .x = x, .part = p } })),
        }
    }
}

test "T2 dt.time of a timestamp is a time column (zoned: the local wall clock)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const stamp = vm.parseIsoTimestamp("2024-07-01T10:20:30.5Z").?;
    const cols = try a.dupe(Column, &.{
        .{ .name = "u", .type = .timestamp },
        .{ .name = "p", .type = .timestamp, .time_zone = "Europe/Prague" },
    });
    var b = try fm.FrameBuilder.init(a, cols, 2);
    try b.appendRow(&.{ ci(stamp), ci(stamp) });
    try b.appendRow(&.{ .null, .null });
    const f = try b.toOwned();
    const u = try mutate(a, f, .{ .dt = .{ .x = try col(a, "u"), .part = .time } });
    try testing.expectEqual(ColumnType.time, u.columnType("o").?);
    try expectInt((10 * 3600 + 20 * 60 + 30) * us_s + 500_000, u.cell(0, "o").?);
    try testing.expect(u.cell(1, "o").? == .null);
    const p = try mutate(a, f, .{ .dt = .{ .x = try col(a, "p"), .part = .time } });
    try testing.expectEqual(ColumnType.time, p.columnType("o").?);
    try expectInt((12 * 3600 + 20 * 60 + 30) * us_s + 500_000, p.cell(0, "o").?); // CEST = UTC+2
    // and it prints as a time
    try expectText("10:20:30.500", (try df.cast(a, u, .{ .col = "o", .to = .text })).cell(0, "o").?);
}

test "T10 instant-only operations refuse a time column" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const x = try col(a, "t");
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .truncate = .{ .x = x, .every = "1h" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .offset_by = .{ .x = x, .by = "1h" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .replace_time_zone = .{ .x = x, .zone = "UTC" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .convert_time_zone = .{ .x = x, .zone = "UTC" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .to_local = .{ .x = x, .zone = "UTC" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .from_local = .{ .x = x, .zone = "UTC" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .tz_offset = .{ .x = x, .zone = "UTC" } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .add_business_days = .{ .x = x, .n = 1 } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .is_business_day = .{ .x = x } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .dt_replace = .{ .x = x, .hour = try lit(a, ci(1)) } }));
    // a timestamp is still fine
    const d = try df.cast(a, f, .{ .col = "i", .to = .timestamp });
    _ = try mutate(a, d, .{ .truncate = .{ .x = try col(a, "i"), .every = "1h" } });
}

// ── T3, T4: comparisons and arithmetic ──────────────────────────────────────

test "T3 comparisons, is_between, min and max of times work on the microseconds" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const t = try col(a, "t");
    const noon = try lit(a, ci(12 * 3600 * us_s));
    const g = try mutate(a, f, bin(a, .lt, t, noon));
    try testing.expectEqual(true, g.cell(0, "o").?.bool);
    try testing.expectEqual(false, g.cell(1, "o").?.bool);
    try testing.expect(g.cell(3, "o").? == .null);
    try testing.expectEqual(true, (try cellOf(a, f, bin(a, .eq, t, t), 2)).bool);
    try testing.expectEqual(false, (try cellOf(a, f, bin(a, .ne, t, t), 2)).bool);
    try testing.expectEqual(true, (try cellOf(a, f, bin(a, .ge, t, try lit(a, ci(t0102_03))), 0)).bool);
    const lo = try lit(a, ci(t_120ms));
    const hi = try lit(a, ci(t_noon5));
    const bt = try mutate(a, f, .{ .is_between = .{ .x = t, .lower = lo, .upper = hi, .closed = .both } });
    try testing.expectEqual(true, bt.cell(0, "o").?.bool);
    try testing.expectEqual(true, bt.cell(2, "o").?.bool);
    try testing.expectEqual(true, bt.cell(4, "o").?.bool);
    try testing.expectEqual(false, bt.cell(1, "o").?.bool);
    const bn = try mutate(a, f, .{ .is_between = .{ .x = t, .lower = lo, .upper = hi, .closed = .none } });
    try testing.expectEqual(false, bn.cell(2, "o").?.bool);
    // horizontal min / max keep the type
    const noon_t = try boxed(a, .{ .cast = .{ .x = noon, .to = .time } });
    const mx = try mutate(a, f, bin(a, .max, t, noon_t));
    try testing.expectEqual(ColumnType.time, mx.columnType("o").?);
    try expectInt(12 * 3600 * us_s, mx.cell(0, "o").?);
    try expectInt(t_last, mx.cell(1, "o").?);
    const mn = try mutate(a, f, bin(a, .min, t, t));
    try testing.expectEqual(ColumnType.time, mn.columnType("o").?);
    // The timestamp rule: text beside an instant is not parsed, the comparison is null; the
    // same for a time.
    try testing.expect((try cellOf(a, f, bin(a, .eq, t, try lit(a, .{ .text = "01:02:03" })), 0)) == .null);
}

test "T4 time - time is a duration; every other arithmetic on a time is refused" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const t = try col(a, "t");
    // polars: 01:02:03 - 00:30 = 1923 s
    const half = try lit(a, ci(30 * 60 * us_s));
    const cast_half = try a.create(Expr);
    cast_half.* = .{ .cast = .{ .x = half, .to = .time } };
    const d = try mutate(a, f, bin(a, .sub, t, cast_half));
    try testing.expectEqual(ColumnType.duration, d.columnType("o").?);
    try expectInt(1923 * us_s, d.cell(0, "o").?);
    try testing.expect(d.cell(3, "o").? == .null);
    const dur = try lit(a, ci(us_s));
    const one = try a.create(Expr);
    one.* = .{ .cast = .{ .x = dur, .to = .duration } };
    const ops = [_]ex.Binary{ .add, .sub, .mul, .div, .floordiv, .mod, .pow };
    for (ops) |op| {
        try testing.expectError(error.BadExpr, mutate(a, f, bin(a, op, t, one)));
        try testing.expectError(error.BadExpr, mutate(a, f, bin(a, op, one, t)));
        try testing.expectError(error.BadExpr, mutate(a, f, bin(a, op, t, try lit(a, ci(2)))));
    }
    // `time + time`, `time * time`
    try testing.expectError(error.BadExpr, mutate(a, f, bin(a, .add, t, t)));
    try testing.expectError(error.BadExpr, mutate(a, f, bin(a, .mul, t, t)));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .unary = .{ .op = .neg, .x = t } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .unary = .{ .op = .abs, .x = t } }));
    // an int column beside an int stays arithmetic
    _ = try mutate(a, f, bin(a, .add, try col(a, "i"), try lit(a, ci(1))));
}

// ── T5: aggregates, windows, describe ───────────────────────────────────────

fn fourTimes(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{ .{ .name = "t", .type = .time }, .{ .name = "g", .type = .int } });
    var b = try fm.FrameBuilder.init(a, cols, 4);
    try b.appendRow(&.{ ci(t0102_03), ci(1) });
    try b.appendRow(&.{ ci(t_last), ci(1) });
    try b.appendRow(&.{ ci(t_120ms), ci(1) });
    try b.appendRow(&.{ ci(t_noon5), ci(1) });
    return b.toOwned();
}

fn agg1(a: std.mem.Allocator, f: Frame, func: df.AggFn) !Frame {
    return df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "t", .out = "o", .func = func }}, .skip_na = true });
}

test "T5 aggregate: order statistics keep time, mean/median/quantile are times (polars values)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fourTimes(a);
    inline for (.{ .min, .max, .first, .last, .mode }) |fn_| {
        const g = try agg1(a, f, fn_);
        try testing.expectEqual(ColumnType.time, g.columnType("o").?);
    }
    inline for (.{ .count, .nunique }) |fn_| {
        const g = try agg1(a, f, fn_);
        try testing.expectEqual(ColumnType.int, g.columnType("o").?);
    }
    try expectInt(t_120ms, (try agg1(a, f, .min)).cell(0, "o").?);
    try expectInt(t_last, (try agg1(a, f, .max)).cell(0, "o").?);
    try expectInt(t0102_03, (try agg1(a, f, .first)).cell(0, "o").?);
    try expectInt(t_noon5, (try agg1(a, f, .last)).cell(0, "o").?);
    // polars: mean 09:15:30.780001 (the microsecond mean, truncated), median 06:31:01.500002
    const m = try agg1(a, f, .mean);
    try testing.expectEqual(ColumnType.time, m.columnType("o").?);
    try expectInt(((9 * 60 + 15) * 60 + 30) * us_s + 780_001, m.cell(0, "o").?);
    const md = try agg1(a, f, .median);
    try testing.expectEqual(ColumnType.time, md.columnType("o").?);
    try expectInt(((6 * 60 + 31) * 60 + 1) * us_s + 500_002, md.cell(0, "o").?);
    const q = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "t", .out = "o", .func = .quantile, .q = 0 }}, .skip_na = true });
    try testing.expectEqual(ColumnType.time, q.columnType("o").?);
    try expectInt(t_120ms, q.cell(0, "o").?);
    // sum, prod, var: no time comes out (as for a timestamp: a float of microseconds)
    inline for (.{ .sum, .prod, .@"var" }) |fn_| {
        const g = try agg1(a, f, fn_);
        try testing.expectEqual(ColumnType.float, g.columnType("o").?);
    }
    // std is a duration, as for a timestamp
    try testing.expectEqual(ColumnType.duration, (try agg1(a, f, .std)).columnType("o").?);
}

test "T5 window: cum_min/cum_max/shift/fills keep time, diff is a duration, transform mean is a time" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const cm = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .cum_max });
    try testing.expectEqual(ColumnType.time, cm.columnType("o").?);
    try expectInt(t0102_03, cm.cell(0, "o").?);
    try expectInt(t_last, cm.cell(1, "o").?);
    try expectInt(t_last, cm.cell(2, "o").?);
    const cn = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .cum_min });
    try testing.expectEqual(ColumnType.time, cn.columnType("o").?);
    try expectInt(t_120ms, cn.cell(2, "o").?);
    const sh = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .{ .shift = .{ .n = 1 } } });
    try testing.expectEqual(ColumnType.time, sh.columnType("o").?);
    try testing.expect(sh.cell(0, "o").? == .null);
    try expectInt(t0102_03, sh.cell(1, "o").?);
    const ff = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .{ .ffill = null } });
    try testing.expectEqual(ColumnType.time, ff.columnType("o").?);
    try expectInt(t_120ms, ff.cell(3, "o").?);
    const bf = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .{ .bfill = null } });
    try expectInt(t_noon5, bf.cell(3, "o").?);
    const di = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .{ .diff = 1 } });
    try testing.expectEqual(ColumnType.duration, di.columnType("o").?);
    try expectInt(t_last - t0102_03, di.cell(1, "o").?);
    try testing.expect(di.cell(0, "o").? == .null);
    const tm = try df.window(a, try fourTimes(a), .{ .value_col = "t", .out = "o", .op = .{ .transform = .{ .func = .mean } } });
    try testing.expectEqual(ColumnType.time, tm.columnType("o").?);
    try expectInt(((9 * 60 + 15) * 60 + 30) * us_s + 780_001, tm.cell(0, "o").?);
    const tmax = try df.window(a, try fourTimes(a), .{ .value_col = "t", .out = "o", .op = .{ .transform = .{ .func = .max } } });
    try testing.expectEqual(ColumnType.time, tmax.columnType("o").?);
}

test "T5 describe of a time column: times, no std" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fourTimes(a);
    const d = try df.describeWith(a, f, .{ .cols = &.{"t"} });
    var mean_seen = false;
    for (0..d.len) |r| {
        const label = d.cell(r, "statistic").?.text;
        if (std.mem.eql(u8, label, "mean")) {
            try expectText("09:15:30.780001", d.cell(r, "t").?);
            mean_seen = true;
        }
        if (std.mem.eql(u8, label, "min")) try expectText("00:00:00.120", d.cell(r, "t").?);
        if (std.mem.eql(u8, label, "max")) try expectText("23:59:59.999999", d.cell(r, "t").?);
        try testing.expect(!std.mem.eql(u8, label, "std"));
    }
    try testing.expect(mean_seen);
}

// ── T7: strftime, strptime, str.to_time ─────────────────────────────────────

test "T7 strftime of a time (polars %H-%M-%S%.f and the usual directives)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const t = try col(a, "t");
    // polars: 23:59:59.999999 -> 23-59-59.999999, 00:00:00.12 -> 00-00-00.120
    try expectText("23-59-59.999999", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%H-%M-%S%.f" } }, 1));
    try expectText("00-00-00.120", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%H-%M-%S%.f" } }, 2));
    try expectText("01-02-03", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%H-%M-%S%.f" } }, 0));
    try expectText("01:02:03 AM", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%I:%M:%S %p" } }, 0));
    try expectText("11:59 PM", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%I:%M %p" } }, 1));
    try expectText("12:00:00", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%T" } }, 4));
    try expectText("12:00", try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%R" } }, 4));
    try testing.expect((try cellOf(a, f, .{ .strftime = .{ .x = t, .format = "%H" } }, 3)) == .null);
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .strftime = .{ .x = t, .format = "%Q%.f" } }));
}

test "T7 strptime and to_datetime to a time" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "s", .type = .text }});
    var b = try fm.FrameBuilder.init(a, cols, 5);
    try b.appendRow(&.{.{ .text = "1.30pm" }});
    try b.appendRow(&.{.{ .text = "12.05am" }});
    try b.appendRow(&.{.{ .text = "13.30pm" }});
    try b.appendRow(&.{.{ .text = "junk" }});
    try b.appendRow(&.{.null});
    const f = try b.toOwned();
    const s = try col(a, "s");
    // polars: str.to_time("%I.%M%p") of "1.30pm" is 13:30
    const g = try mutate(a, f, .{ .strptime = .{ .x = s, .format = "%I.%M%p", .to = .time } });
    try testing.expectEqual(ColumnType.time, g.columnType("o").?);
    try expectInt(13 * 3600 * us_s + 30 * 60 * us_s, g.cell(0, "o").?);
    try expectInt(5 * 60 * us_s, g.cell(1, "o").?);
    try testing.expect(g.cell(2, "o").? == .null);
    try testing.expect(g.cell(3, "o").? == .null);
    try testing.expect(g.cell(4, "o").? == .null);
    // no format: parseTimeOfDay
    const cols2 = try a.dupe(Column, &.{.{ .name = "s", .type = .text }});
    var b2 = try fm.FrameBuilder.init(a, cols2, 4);
    try b2.appendRow(&.{.{ .text = "01:02:03" }});
    try b2.appendRow(&.{.{ .text = "23:59:59.999999" }});
    try b2.appendRow(&.{.{ .text = "24:00:00" }});
    try b2.appendRow(&.{.{ .text = "10:15" }});
    const f2 = try b2.toOwned();
    inline for (.{ df.DateMode.infer, df.DateMode.iso8601, df.DateMode.mixed }) |mode| {
        const h = try mutate(a, f2, .{ .to_datetime = .{ .x = try col(a, "s"), .mode = mode, .to = .time } });
        try testing.expectEqual(ColumnType.time, h.columnType("o").?);
        try expectInt(t0102_03, h.cell(0, "o").?);
        try expectInt(t_last, h.cell(1, "o").?);
        try testing.expect(h.cell(2, "o").? == .null);
        try expectInt(10 * 3600 * us_s + 15 * 60 * us_s, h.cell(3, "o").?);
    }
}

// ── T8: time ranges ─────────────────────────────────────────────────────────

test "T8 timeRange (polars time_range)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const h: i64 = 3600 * us_s;
    const m30 = dtf.parseDuration("30m").?;
    // time_range(01:00, 03:00, "30m") -> 01:00, 01:30, 02:00, 02:30, 03:00
    const r = try df.timeRange(a, "t", h, 3 * h, m30, .both);
    try testing.expectEqual(ColumnType.time, r.columnType("t").?);
    try testing.expectEqual(@as(usize, 5), r.len);
    for (0..5) |i| try expectInt(h + @as(i64, @intCast(i)) * 30 * 60 * us_s, r.cell(i, "t").?);
    // time_range(interval="6h"): the defaults are 00:00 and 23:59:59.999999 -> 00, 06, 12, 18
    const d = try df.timeRange(a, "t", 0, 86_399_999_999, dtf.parseDuration("6h").?, .both);
    try testing.expectEqual(@as(usize, 4), d.len);
    try expectInt(18 * h, d.cell(3, "t").?);
    // closed
    const left = try df.timeRange(a, "t", h, 3 * h, m30, .left);
    try testing.expectEqual(@as(usize, 4), left.len);
    const none = try df.timeRange(a, "t", h, 3 * h, m30, .none);
    try testing.expectEqual(@as(usize, 3), none.len);
    // an empty range, and the bad inputs
    try testing.expectEqual(@as(usize, 0), (try df.timeRange(a, "t", 3 * h, h, m30, .both)).len);
    try testing.expectError(error.BadArgument, df.timeRange(a, "t", 0, h, dtf.parseDuration("1mo").?, .both));
    try testing.expectError(error.BadArgument, df.timeRange(a, "t", 0, h, dtf.parseDuration("0s").?, .both));
    try testing.expectError(error.BadArgument, df.timeRange(a, "t", 0, h, dtf.parseDuration("-1h").?, .both));
    try testing.expectError(error.BadArgument, df.timeRange(a, "t", -1, h, m30, .both));
    try testing.expectError(error.BadArgument, df.timeRange(a, "t", 0, 86_400 * us_s, m30, .both));
    try testing.expectError(error.TooLarge, df.timeRange(a, "t", 0, 86_399_999_999, .{ .us = 1 }, .both));
}

test "T8 timeRanges: one list per row, broadcast, nulls" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const h: i64 = 3600 * us_s;
    const r = try df.timeRanges(a, "r", &.{ h, null, 2 * h }, &.{ 3 * h, 4 * h, 2 * h + 1 }, dtf.parseDuration("1h").?, .both);
    try testing.expectEqual(ColumnType.list, r.columnType("r").?);
    try testing.expectEqual(ColumnType.time, r.columns[0].inner[0].type);
    try testing.expectEqual(@as(usize, 3), r.cell(0, "r").?.list.len());
    try expectInt(3 * h, r.cell(0, "r").?.list.get(2));
    try testing.expect(r.cell(1, "r").? == .null);
    try testing.expectEqual(@as(usize, 1), r.cell(2, "r").?.list.len());
    try testing.expectError(error.BadArgument, df.timeRanges(a, "r", &.{-5}, &.{h}, dtf.parseDuration("1h").?, .both));
    try testing.expectError(error.BadArgument, df.timeRanges(a, "r", &.{h}, &.{h}, dtf.parseDuration("1mo").?, .both));
    try testing.expectError(error.BadArgument, df.timeRanges(a, "r", &.{ 1, 2 }, &.{ 1, 2, 3 }, dtf.parseDuration("1h").?, .both));
}

// ── T9: the selector ────────────────────────────────────────────────────────

test "T9 the temporal selector includes a time column" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const picked = try df.selectColumns(a, f, .temporal);
    try testing.expectEqual(@as(usize, 1), picked.len);
    try testing.expectEqualStrings("t", picked[0]);
}

// ── T6: every verb keeps the type ───────────────────────────────────────────

/// Every `.time` column of `f` holds only times of day or nulls; when `t` is there it is a time.
fn kept(f: Frame) !void {
    for (f.columns, 0..) |c, k| {
        if (std.mem.eql(u8, c.name, "t")) try testing.expectEqual(ColumnType.time, c.type);
        if (c.type != .time) continue;
        const d = f.columnAt(k);
        for (0..f.len) |r| {
            const v = d.get(r);
            if (v == .null) continue;
            try testing.expect(v == .int);
            try testing.expect(vm.isTimeOfDay(v.int));
        }
    }
}

/// Like `kept` for a result where `t` may be gone or retyped (an aggregate, a reshape).
fn valid(f: Frame) !void {
    for (f.columns, 0..) |c, k| {
        if (c.type != .time) continue;
        const d = f.columnAt(k);
        for (0..f.len) |r| {
            const v = d.get(r);
            if (v == .null) continue;
            try testing.expect(v == .int);
            try testing.expect(vm.isTimeOfDay(v.int));
        }
    }
}

fn side(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{ .{ .name = "t", .type = .time }, .{ .name = "r", .type = .int }, .{ .name = "g", .type = .int } });
    var b = try fm.FrameBuilder.init(a, cols, 3);
    try b.appendRow(&.{ ci(t0102_03), ci(1), ci(1) });
    try b.appendRow(&.{ ci(t_noon5), ci(2), ci(2) });
    try b.appendRow(&.{ ci(5), ci(3), ci(3) });
    return b.toOwned();
}

test "T6 sweep: the public verbs keep the time type and every cell a time of day or null" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try kept(f);
    const r = try side(a);

    try kept(try verbs.takeRows(a, f, &.{ 4, 0, 0, 3 }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "i", .op = .ge, .value = ci(20) }} }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "t", .op = .gt, .value = ci(t_120ms) }} }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "t", .op = .is_null }} }));
    try kept(try df.distinct(a, f, .{ .keys = &.{} }));
    try kept(try df.distinct(a, f, .{ .keys = &.{"t"}, .keep = .last }));
    try kept(try df.sort(a, f, .{ .key = "t" }));
    try kept(try df.sort(a, f, .{ .key = "t", .dir = .desc, .missing = .last, .then_by = &.{.{ .key = "i" }} }));
    try kept(try df.dropna(a, f, .{ .subset = &.{"t"} }));
    try kept(try df.dropna(a, f, .{}));
    try kept(try df.fillna(a, f, .{ .subset = &.{"t"}, .value = ci(5) }));
    try kept(try df.select(a, f, &.{ "i", "t" }));
    try kept(try df.drop(a, f, &.{"s"}));
    try kept(try df.page(a, f, .{ .offset = 1, .limit = 3 }));
    try kept(try df.tail(a, f, 2));
    try kept(try df.clone(a, f));
    try kept(try df.clear(a, f, 3));
    try kept(try df.take(a, f, &.{ 0, -1, 2, 2 }));
    try kept(try df.gatherEvery(a, f, 2, 1));
    try kept(try df.reverse(a, f));
    try kept(try df.concat(a, &.{ f, f }, .vertical));
    try kept(try df.concat(a, &.{ f, f }, .diagonal));
    try kept(try df.concatByName(a, &.{ f, f }));
    inline for (.{ .forward, .backward }) |st| {
        try kept(try df.fillNull(a, f, .{ .subset = &.{"t"}, .strategy = st }));
    }
    try kept(try df.topN(a, f, .{ .n = 2 }));
    inline for (.{ .inner, .left, .right, .full, .semi, .anti }) |how| {
        // time keys join on the equal microseconds
        const j = try df.join(a, f, r, .{ .on = "t", .how = how });
        try valid(j);
        const k = try df.join(a, f, r, .{ .on = "g", .how = how, .coalesce_keys = true });
        try valid(k);
    }
    try testing.expectEqual(@as(usize, 2), (try df.join(a, f, r, .{ .on = "t", .how = .inner })).len);
    try valid(try df.join(a, f, try df.drop(a, r, &.{"t"}), .{ .how = .cross }));
    // group keys, aggregates, pivots
    {
        const g = try df.aggregate(a, f, .{ .group_by = &.{"t"}, .aggs = &.{.{ .src = "i", .out = "n", .func = .sum }}, .sort_groups = true });
        try testing.expectEqual(ColumnType.time, g.columnType("t").?);
        try valid(g);
        const g2 = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{ .{ .src = "t", .out = "lo", .func = .min }, .{ .src = "t", .out = "hi", .func = .max }, .{ .src = "t", .out = "md", .func = .median }, .{ .src = "t", .out = "uq", .func = .nunique } } });
        try testing.expectEqual(ColumnType.time, g2.columnType("lo").?);
        try testing.expectEqual(ColumnType.time, g2.columnType("md").?);
        try valid(g2);
        const v = try df.valueCounts(a, f, .{ .cols = &.{"t"} });
        try testing.expectEqual(ColumnType.time, v.columnType("t").?);
        try valid(v);
        const u = try df.unpivot(a, f, .{ .id_cols = &.{"t"}, .value_cols = &.{"i"} });
        try testing.expectEqual(ColumnType.time, u.columnType("t").?);
        try valid(u);
        const un2 = try df.unpivot(a, f, .{ .id_cols = &.{"i"}, .value_cols = &.{"t"} });
        try valid(un2);
        const p = try df.pivot(a, f, .{ .row_key = "g", .col_key = "s", .value_col = "t", .agg = .first });
        try valid(p);
        const p2 = try df.pivot(a, f, .{ .row_key = "t", .col_key = "s", .value_col = "i", .agg = .first });
        try valid(p2);
    }
    // windows over the other columns, partitions by the time
    {
        const w = try df.window(a, f, .{ .value_col = "i", .out = "o", .op = .cum_sum, .partition_by = &.{"t"} });
        try kept(w);
        const w2 = try df.window(a, f, .{ .value_col = "t", .out = "o", .op = .{ .shift = .{ .n = -1 } }, .partition_by = &.{"g"}, .order_by = &.{"i"} });
        try kept(w2);
        try testing.expectEqual(ColumnType.time, w2.columnType("o").?);
    }
    // a time column through expressions, cast and text
    {
        const t = try col(a, "t");
        const c = try mutate(a, f, .{ .coalesce = &.{ t.*, t.* } });
        try testing.expectEqual(ColumnType.time, c.columnType("o").?);
        try valid(c);
        const ie = try mutate(a, f, .{ .if_else = .{ .cond = try boxed(a, bin(a, .lt, t, try lit(a, ci(t_noon5)))), .then = t, .otherwise = t } });
        try valid(ie);
        const tx = try df.cast(a, f, .{ .col = "t", .to = .text });
        try testing.expectEqual(ColumnType.text, tx.columnType("t").?);
        const back = try df.cast(a, tx, .{ .col = "t", .to = .time });
        try testing.expectEqual(ColumnType.time, back.columnType("t").?);
        try kept(back);
        try testing.expectEqual(t_noon5, back.cell(4, "t").?.int);
        const bi = try df.cast(a, f, .{ .col = "t", .to = .int });
        try testing.expectEqual(t_last, bi.cell(1, "t").?.int);
        const fromi = try df.cast(a, bi, .{ .col = "t", .to = .time });
        try kept(fromi);
        // an int outside the day is null, not a bad time
        const big = try df.cast(a, try df.cast(a, f, .{ .col = "i", .to = .int }), .{ .col = "i", .to = .time });
        try valid(big);
        try testing.expect(big.cell(0, "i").? == .int); // 10 µs is a time
    }
    // the shape verbs
    {
        const tr = try df.transpose(a, try df.select(a, f, &.{"t"}), .{});
        try valid(tr);
        const rr = try df.repeatRows(a, f, .{ .times = 2 });
        try kept(rr);
        const d = try df.describeWith(a, f, .{ .cols = &.{ "t", "i" } });
        try valid(d);
        const info = try df.info(a, f);
        _ = info;
        try testing.expect(df.hasNulls(f));
        try testing.expect(df.equals(f, try df.clone(a, f)));
    }
}

// ── no panic: an out-of-range int in a hand-built time column ───────────────

test "a time column holding an out-of-range int never panics" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "t", .type = .time }, .{ .name = "g", .type = .int } });
    var b = try fm.FrameBuilder.init(a, cols, 5);
    inline for (.{ -1, 86_400_000_000, std.math.maxInt(i64), std.math.minInt(i64), 5 }) |x| try b.appendRow(&.{ ci(x), ci(1) });
    const f = try b.toOwned();
    const t = try col(a, "t");
    inline for (comptime std.meta.fieldNames(df.DtPart)) |pn| {
        _ = mutate(a, f, .{ .dt = .{ .x = t, .part = @field(df.DtPart, pn) } }) catch {};
    }
    _ = mutate(a, f, .{ .strftime = .{ .x = t, .format = "%H-%M-%S%.f" } }) catch {};
    _ = mutate(a, f, bin(a, .sub, t, t)) catch {};
    _ = mutate(a, f, bin(a, .lt, t, t)) catch {};
    inline for (.{ ColumnType.text, .int, .float, .duration, .timestamp, .time, .categorical }) |to| _ = df.cast(a, f, .{ .col = "t", .to = to }) catch {};
    _ = df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{ .{ .src = "t", .out = "m", .func = .mean }, .{ .src = "t", .out = "q", .func = .median }, .{ .src = "t", .out = "x", .func = .max } } }) catch {};
    _ = df.window(a, f, .{ .value_col = "t", .out = "o", .op = .cum_max }) catch {};
    _ = df.window(a, f, .{ .value_col = "t", .out = "o", .op = .{ .diff = 1 } }) catch {};
    _ = df.sort(a, f, .{ .key = "t" }) catch {};
    _ = df.describeWith(a, f, .{ .cols = &.{"t"} }) catch {};
    _ = df.valueCounts(a, f, .{ .cols = &.{"t"} }) catch {};
    // display and text: null for a cell that is no time
    const txt = try df.cast(a, f, .{ .col = "t", .to = .text });
    try testing.expect(txt.cell(0, "t").? == .null);
    try testing.expect(txt.cell(4, "t").? == .text);
    const shown = try df.format(a, f, .{});
    try testing.expect(shown.len > 0);
}
