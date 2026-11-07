// SPDX-License-Identifier: MIT
//! Findings of the independent review of 2026-11-07, one test each, named by the
//! finding (MED1..MED3, L4..L8). Each was seen red before its fix, except where the
//! test says otherwise. MED1 is last: before its fix it panicked, which ends the run.

const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const verbs = @import("verbs.zig");
const more = @import("more.zig");
const ex = @import("expr.zig");
const Value = vm.Value;
const Column = vm.Column;
const Frame = fm.Frame;

fn frameOf(a: std.mem.Allocator, cols: []const Column, rows: []const []const Value) !Frame {
    var b = try fm.FrameBuilder.init(a, cols, rows.len);
    for (rows) |r| try b.appendRow(r);
    return b.toOwned();
}

test "review MED2: drop_missing_keys with no group columns keeps the one result row" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const f = try frameOf(a, &cols, &.{&.{.{ .float = 1 }}});
    const g = try verbs.aggregate(a, f, .{ .group_by = &.{}, .aggs = &.{.{ .src = "v", .out = "s", .func = .std }}, .drop_missing_keys = true });
    try testing.expectEqual(@as(usize, 1), g.len);
    try testing.expectEqual(Value.null, g.columnAt(0).get(0)); // std of one value
}

test "review MED3: cumsum and rolling skip a missing cell, as pandas and polars" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const f = try frameOf(a, &cols, &.{ &.{.{ .float = 1 }}, &.{.null}, &.{.{ .float = 2 }}, &.{.{ .float = 4 }} });
    // pandas `[1, NaN, 2, 4].cumsum()` = [1, NaN, 3, 7]; polars `cum_sum` the same, null.
    const c = try verbs.cumsum(a, f, .{ .value_col = "v", .out = "s" });
    const want_c = [_]?f64{ 1, null, 3, 7 };
    for (want_c, 0..) |w, ri| {
        const g = c.columnAt(1).get(ri);
        if (w) |x| try testing.expectEqual(x, g.float) else try testing.expectEqual(Value.null, g);
    }
    // pandas `rolling(2).mean()` = [NaN, NaN, NaN, 3]: a window with a missing value has
    // fewer than `min_periods = 2` values.
    const r = try verbs.rolling(a, f, .{ .value_col = "v", .out = "m", .window = 2 });
    const want_r = [_]?f64{ null, null, null, 3 };
    for (want_r, 0..) |w, ri| {
        const g = r.columnAt(1).get(ri);
        if (w) |x| try testing.expectEqual(x, g.float) else try testing.expectEqual(Value.null, g);
    }
    // An int column stays int, as both engines keep it.
    const icols = [_]Column{.{ .name = "k", .type = .int }};
    const fi = try frameOf(a, &icols, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    const ci = try verbs.cumsum(a, fi, .{ .value_col = "k", .out = "s" });
    try testing.expectEqual(@as(i64, 3), ci.columnAt(1).get(1).int);
}

test "review L4: distinct keep=last keeps the rows in input order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "k", .type = .text }, .{ .name = "n", .type = .int } };
    const f = try frameOf(a, &cols, &.{
        &.{ .{ .text = "a" }, .{ .int = 0 } },
        &.{ .{ .text = "b" }, .{ .int = 1 } },
        &.{ .{ .text = "a" }, .{ .int = 2 } },
    });
    // pandas `drop_duplicates("k", keep="last")`: rows 1, 2 (b then a).
    const d = try verbs.distinct(a, f, .{ .keys = &.{"k"}, .keep = .last });
    try testing.expectEqual(@as(i64, 1), d.columnAt(1).get(0).int);
    try testing.expectEqual(@as(i64, 2), d.columnAt(1).get(1).int);
}

test "review L5: a suffixed right column that collides with a left name is numbered" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lcols = [_]Column{ .{ .name = "k", .type = .int }, .{ .name = "x", .type = .int }, .{ .name = "x_r", .type = .int } };
    const rcols = [_]Column{ .{ .name = "k", .type = .int }, .{ .name = "x", .type = .int } };
    const l = try frameOf(a, &lcols, &.{&.{ .{ .int = 1 }, .{ .int = 10 }, .{ .int = 20 } }});
    const r = try frameOf(a, &rcols, &.{&.{ .{ .int = 1 }, .{ .int = 30 } }});
    for ([_]Frame{
        try verbs.join(a, l, r, .{ .on = "k", .suffix = "_r" }),
        try more.joinAsof(a, l, r, .{ .on = "k", .suffix = "_r" }),
    }) |j| {
        try testing.expectEqual(@as(usize, 4), j.columns.len);
        for (j.columns, 0..) |c, i| {
            for (j.columns[i + 1 ..]) |o| try testing.expect(!std.mem.eql(u8, c.name, o.name));
        }
        try testing.expectEqual(@as(i64, 20), j.cell(0, "x_r").?.int);
        try testing.expectEqual(@as(i64, 30), j.columnAt(3).get(0).int);
    }
}

test "review L6: a decimal cast to text keeps every digit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]struct { raw: i128, text: []const u8 }{
        .{ .raw = 123456789012345678901234567, .text = "123456789012345.678901234567" },
        .{ .raw = -1_500_000_000_000, .text = "-1.5" },
        .{ .raw = 7 * vm.decimal_scale, .text = "7" },
        .{ .raw = 1, .text = "0.000000000001" },
        .{ .raw = std.math.minInt(i128), .text = "-170141183460469231731687303.715884105728" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.text, (try ex.castValue(a, .{ .decimal = c.raw }, .text)).text);
}

test "review L7: pivot orders column keys as `cast` reads numbers, hex and separators are text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "r", .type = .int }, .{ .name = "c", .type = .text }, .{ .name = "v", .type = .float } };
    const f = try frameOf(a, &cols, &.{
        &.{ .{ .int = 1 }, .{ .text = "2" }, .{ .float = 1 } },
        &.{ .{ .int = 1 }, .{ .text = "0x10" }, .{ .float = 2 } },
        &.{ .{ .int = 1 }, .{ .text = "1_0" }, .{ .float = 3 } },
    });
    // Not every key is a number: byte order, as pandas sorts text column labels.
    const p = try verbs.pivot(a, f, .{ .row_key = "r", .col_key = "c", .value_col = "v" });
    try testing.expectEqualStrings("0x10", p.columns[1].name);
    try testing.expectEqualStrings("1_0", p.columns[2].name);
    try testing.expectEqualStrings("2", p.columns[3].name);
}

test "review L8: big blocks free with the alignment they were allocated with (not seen red)" {
    // `page_allocator` frees by length today, so the wrong alignment did not show: this
    // pins the round trip, many times over, without a leak or a fault.
    const a = fm.big_block_allocator;
    for (0..64) |_| {
        const m = try a.alignedAlloc(u8, .@"16", 3 * 1024 * 1024 + 5);
        m[m.len - 1] = 1;
        a.free(m);
    }
}

test "review MED1: a huge row hint is a reservation at most, never an overflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "t", .type = .text }, .{ .name = "i", .type = .int }, .{ .name = "m", .type = .text } };
    for ([_]usize{ std.math.maxInt(usize), std.math.maxInt(usize) - 1, 1 << 40 }) |hint| {
        var b = try fm.FrameBuilder.init(a, &cols, hint);
        try b.appendRow(&.{ .null, .null, .{ .int = 1 } });
        try b.appendRow(&.{ .{ .text = "x" }, .{ .int = 2 }, .{ .text = "y" } }); // `m` turns boxed
        const f = try b.toOwned();
        try testing.expectEqualStrings("x", f.cell(1, "t").?.text);
        try testing.expectEqualStrings("y", f.cell(1, "m").?.text);
    }
}
