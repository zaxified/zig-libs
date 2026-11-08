// SPDX-License-Identifier: MIT
//! The verbs over generated tables of every column shape and over hand-built frames:
//! shared columns, oversized work refused, bitmaps and arrays shorter than `len`, typed
//! paths and their limits. Until step R (2026-11-08) this file also ran every verb
//! against `tabular`'s row verb of the same name; that module is retired, and the
//! anchors are the pandas/polars vectors (`oracle_test.zig`, `oracle2_test.zig`), the
//! `*Cells` reference paths (`d4*_test.zig`, the fuzz driver) and the tests here.

const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const sp = @import("spec.zig");
const frame = @import("verbs.zig");
const bridge = @import("storage_test.zig");
const Column = vm.Column;
const Dataset = bridge.Rows;
const Frame = fm.Frame;
const Value = vm.Value;

/// The frame of a row table, as `FrameBuilder` makes it.
pub fn F(a: std.mem.Allocator, d: Dataset) !Frame {
    return bridge.frameOf(a, d);
}

/// A frame's cells as rows.
pub fn rowsOf(a: std.mem.Allocator, f: Frame) !Dataset {
    const rows = try a.alloc([]const Value, f.len);
    for (rows, 0..) |*r, ri| {
        const cells = try a.alloc(Value, f.columns.len);
        for (cells, 0..) |*c, ci| c.* = f.columnAt(ci).get(ri);
        r.* = cells;
    }
    return .{ .columns = f.columns, .rows = rows };
}

const Rng = std.Random;

/// Small, often a whole number so keys meet across kinds, zero and -0.0 included.
pub fn randFloat(r: Rng) f64 {
    return switch (r.uintLessThan(u8, 5)) {
        0 => 0,
        1 => -0.0,
        2 => @floatFromInt(r.intRangeAtMost(i64, -3, 3)),
        3 => @as(f64, @floatFromInt(r.intRangeAtMost(i64, -40, 40))) * 0.25,
        else => r.float(f64) * 1e6 - 5e5,
    };
}

test "frame verbs share the columns they do not touch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "t", .type = .text }, .{ .name = "v", .type = .float } });
    const rows = try a.alloc([]const Value, 3);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .text = "x" }, .{ .float = 2 } });
    const f = try F(a, .{ .columns = cols, .rows = rows });

    const m = try frame.map(a, f, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .mul, .rhs = .{ .num = 2 } });
    try testing.expectEqual(f.data[1].text.bytes.ptr, m.data[1].text.bytes.ptr);
    try testing.expectEqual(f.data[2].float.values.ptr, m.data[2].float.values.ptr);

    // A left join on a unique right key gives the left side back row for row.
    const rcols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "rv", .type = .float } });
    const rrows = try a.alloc([]const Value, 2);
    for (rrows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .float = 7 } });
    const rf = try F(a, .{ .columns = rcols, .rows = rrows });
    const j = try frame.join(a, f, rf, .{ .on = "k", .how = .left });
    try testing.expectEqual(f.data[1].text.bytes.ptr, j.data[1].text.bytes.ptr);
    try testing.expect(j.data[3].float.valid != null);
    try testing.expectEqual(vm.Value.null, j.data[3].get(2));
}

test "frame verbs: a hand-built frame shorter than its schema reads as null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(vm.Column, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .float } });
    const data = try a.dupe(fm.ColumnData, &.{.{ .float = .{ .values = &.{ 1, 2 } } }});
    const f: Frame = .{ .columns = cols, .data = data, .len = 4 };
    const m = try frame.map(a, f, .{ .out = "p", .lhs = .{ .col = "a" }, .op = .add, .rhs = .{ .col = "b" }, .on_missing = .null });
    try testing.expectEqual(vm.Value.null, m.data[2].get(0));
    const c = try frame.cumsum(a, f, .{ .value_col = "a", .out = "s" });
    try testing.expectEqual(@as(f64, 3), c.data[2].get(1).float);
    try testing.expectEqual(vm.Value.null, c.data[2].get(3));
    const j = try frame.join(a, f, f, .{ .on = "a", .how = .inner });
    try testing.expect(j.len > 0);
}

test "frame verbs refuse oversized work" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
    const rows = try a.alloc([]const Value, 1 << 16);
    for (rows) |*row| row.* = try a.dupe(Value, &.{ .{ .int = 1 }, .{ .float = 1 } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);

    // (2^16 - 2^15 + 1) * 2^15 visits, past `max_rolling_work`.
    try testing.expectError(error.TooLarge, frame.rolling(a, f, .{ .value_col = "v", .out = "p", .window = 1 << 15 }));

    // Every pair of one key, and every pair outright: 2^32 rows.
    try testing.expectError(error.TooLarge, frame.join(a, f, f, .{ .on = "k" }));
    try testing.expectError(error.TooLarge, frame.join(a, f, f, .{ .how = .cross }));
}

test "frame verbs: a null cell holds 0 in its array, as `TypedColumn` promises" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
    const rows = try a.dupe([]const Value, &.{
        try a.dupe(Value, &.{ .{ .int = 1 }, .{ .float = 5 } }),
        try a.dupe(Value, &.{ .{ .int = 2 }, .null }),
        try a.dupe(Value, &.{ .{ .int = 3 }, .{ .float = -4 } }),
    });
    const f = try F(a, .{ .columns = cols, .rows = rows });

    const m = try frame.map(a, f, .{ .out = "p", .lhs = .{ .num = 7 }, .op = .add, .rhs = .{ .col = "v" }, .on_missing = .null });
    try testing.expectEqualSlices(f64, &.{ 12, 0, 3 }, m.data[2].float.values);
    const s = try frame.map(a, f, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .sqrt, .on_missing = .null });
    try testing.expectEqual(@as(f64, 0), s.data[2].float.values[2]);
    const d = try frame.map(a, f, .{ .out = "p", .lhs = .{ .num = 1 }, .op = .div, .rhs = .{ .col = "v" }, .on_missing = .null });
    try testing.expectEqual(@as(f64, 0), d.data[2].float.values[1]);

    const r = try frame.rolling(a, f, .{ .value_col = "k", .out = "p", .window = 2 });
    try testing.expectEqual(@as(f64, 0), r.data[2].float.values[0]);

    const rcols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "rv", .type = .int } });
    const rrows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{ .{ .int = 1 }, .{ .int = 9 } })});
    const rf = try F(a, .{ .columns = rcols, .rows = rrows });
    const j = try frame.join(a, f, rf, .{ .on = "k", .how = .left });
    try testing.expectEqualSlices(i64, &.{ 9, 0, 0 }, j.data[2].int.values);
}

test "frame join: a semi join that keeps every row shares the left side" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "t", .type = .text } });
    const rows = try a.alloc([]const Value, 3);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .text = "x" } });
    const f = try F(a, .{ .columns = cols, .rows = rows });
    const s = try frame.join(a, f, f, .{ .on = "k", .how = .semi });
    try testing.expectEqual(f.data[1].text.bytes.ptr, s.data[1].text.bytes.ptr);
}

test "frame join: a key count that differs between the sides is NoSuchColumn" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "j", .type = .int } });
    const rows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{ .{ .int = 1 }, .{ .int = 2 } })});
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    try testing.expectError(error.NoSuchColumn, frame.join(a, f, f, .{ .on = "k", .right_on = &.{ "k", "j" } }));
}

test "frame join: a hand-built frame past u32 rows is refused, an empty side costs nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const huge: Frame = .{ .columns = &.{}, .data = &.{}, .len = 1 << 40 };
    const empty: Frame = .{ .columns = &.{}, .data = &.{}, .len = 0 };
    try testing.expectError(error.TooLarge, frame.join(a, huge, empty, .{ .how = .cross }));
    try testing.expectError(error.TooLarge, frame.join(a, empty, huge, .{ .how = .cross }));

    // Below the row limit, and nothing to pair: no loop over the left side's rows. The
    // row width cap cannot refuse it, the product is 0.
    const big: Frame = .{ .columns = &.{}, .data = &.{}, .len = (1 << 32) - 2 };
    const j = try frame.join(a, big, empty, .{ .how = .cross });
    try testing.expectEqual(@as(usize, 0), j.len);
}

test "frame group keys: missing as one group next to the whole i64 range" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lo = std.math.minInt(i64);
    const hi = std.math.maxInt(i64);
    // The sentinel below the lowest, above the highest, and neither fits: bytes then.
    for ([_][2]i64{ .{ -1, 5 }, .{ lo, 5 }, .{ lo, hi } }) |pair| {
        const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
        const rows = try a.dupe([]const Value, &.{
            try a.dupe(Value, &.{ .{ .int = pair[0] }, .{ .float = 1 } }),
            try a.dupe(Value, &.{ .null, .{ .float = 2 } }),
            try a.dupe(Value, &.{ .{ .int = pair[1] }, .{ .float = 4 } }),
            try a.dupe(Value, &.{ .null, .{ .float = 8 } }),
            try a.dupe(Value, &.{ .{ .int = pair[0] }, .{ .float = 16 } }),
        });
        const d: Dataset = .{ .columns = cols, .rows = rows };
        const f = try F(a, d);
        const gs: sp.AggregateSpec = .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "s", .func = .sum }} };
        const got = try frame.aggregate(a, f, gs);
        try testing.expectEqual(@as(usize, 3), got.len);
        try testing.expectEqual(vm.Value.null, got.data[0].get(1));
        try testing.expectEqual(@as(f64, 17), got.data[1].get(0).float);
        try testing.expectEqual(@as(f64, 10), got.data[1].get(1).float);
    }
}

test "frame filter: all rows kept shares, a NaN literal keeps nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "v", .type = .float }});
    const rows = try a.dupe([]const Value, &.{
        try a.dupe(Value, &.{.{ .float = 1 }}),
        try a.dupe(Value, &.{.{ .float = std.math.nan(f64) }}),
    });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    const k = try frame.filter(a, f, .{ .where = &.{} });
    try testing.expectEqual(f.data[0].float.values.ptr, k.data[0].float.values.ptr);
    // A missing cell (here the NaN) satisfies only `is_null`, whatever the literal.
    for (std.enums.values(sp.CmpOp)) |op| {
        if (op == .is_null) continue;
        const p: sp.Predicate = .{ .col = "v", .op = op, .value = .{ .float = std.math.nan(f64) } };
        for ([_]sp.FilterSpec{ .{ .where = &.{p} }, .{ .where = &.{p}, .mode = .any } }) |spec| {
            const got = try frame.filter(a, f, spec);
            for (0..got.len) |ri| try testing.expect(!std.math.isNan(got.data[0].get(ri).float));
        }
    }
}

test "frame verbs refuse a frame past u32 rows, and melt's cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const huge: Frame = .{ .columns = &.{}, .data = &.{}, .len = 1 << 40 };
    try testing.expectError(error.TooLarge, frame.filter(a, huge, .{ .where = &.{} }));
    try testing.expectError(error.TooLarge, frame.distinct(a, huge, .{ .keys = &.{} }));
    try testing.expectError(error.TooLarge, frame.aggregate(a, huge, .{ .group_by = &.{}, .aggs = &.{} }));
    try testing.expectError(error.TooLarge, frame.unpivot(a, huge, .{ .id_cols = &.{} }));

    const cols = try a.dupe(vm.Column, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .float } });
    const f: Frame = .{ .columns = cols, .data = &.{}, .len = 1 << 22 };
    try testing.expectError(error.TooLarge, frame.unpivot(a, f, .{ .id_cols = &.{} }));
}

test "frame take: a selection from a column with nulls, words full and part full" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "v", .type = .int }});
    const rows = try a.alloc([]const Value, 200);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{if (i % 7 == 3) .null else Value{ .int = @intCast(i + 1) }});
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    // Past and short of a word boundary, with and without a null among the kept rows.
    // The kept rows are counted by hand: the non-null cells that satisfy the comparison.
    for ([_]i64{ 0, 1, 40, 64, 65, 128, 150 }) |limit| {
        for ([_]sp.CmpOp{ .lt, .gt }) |op| {
            const spec: sp.FilterSpec = .{ .where = &.{.{ .col = "v", .op = op, .value = .{ .int = limit } }} };
            const got = try frame.filter(a, f, spec);
            var want: usize = 0;
            for (rows) |row| {
                const c = row[0];
                if (c == .null) continue;
                if ((op == .lt and c.int < limit) or (op == .gt and c.int > limit)) want += 1;
            }
            try testing.expectEqual(want, got.len);
            var k: usize = 0;
            for (rows) |row| {
                const c = row[0];
                if (c == .null) continue;
                if ((op == .lt and c.int < limit) or (op == .gt and c.int > limit)) {
                    try testing.expectEqual(c.int, got.data[0].get(k).int);
                    k += 1;
                }
            }
            for (0..got.len) |ri| try testing.expect(got.data[0] != .int or got.data[0].int.isValid(ri) or got.data[0].int.values[ri] == 0);
        }
    }
    // Every row kept but none of them null: the result needs no bitmap.
    const spec: sp.FilterSpec = .{ .where = &.{.{ .col = "v", .op = .not_null }} };
    const kept = try frame.filter(a, f, spec);
    try testing.expect(kept.data[0].int.valid == null);
    try testing.expect(kept.len == 200 - 29);
}

test "frame verbs: a hand-built bitmap or array too short reads as null, never past the end" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(vm.Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
    // 100 rows, one word of bits, 80 values, and a garbage value under a null bit.
    var ks: [80]i64 = undefined;
    for (&ks, 0..) |*k, i| k.* = @intCast(i);
    var vs: [100]f64 = @splat(9);
    const short_bits = try a.dupe(u64, &.{0xFFFF_FFFF_FFFF_FFFE});
    const data = try a.dupe(fm.ColumnData, &.{
        .{ .int = .{ .values = &ks } },
        .{ .float = .{ .values = &vs, .valid = short_bits } },
    });
    const f: Frame = .{ .columns = cols, .data = data, .len = 100 };
    // Rows 80..99 have no `k` value; `v` is null at row 0 and at 64..99 (the bitmap covers 64 rows).
    const fs: sp.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .is_null }}, .mode = .any };
    try testing.expectEqual(@as(usize, 20), (try frame.filter(a, f, fs)).len);
    const keep: sp.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .not_null }} };
    try testing.expectEqual(@as(usize, 80), (try frame.filter(a, f, keep)).len);
    const every: sp.FilterSpec = .{ .where = &.{.{ .col = "v", .op = .is_null }}, .mode = .any };
    try testing.expectEqual(@as(usize, 37), (try frame.filter(a, f, every)).len); // 1 + 36
    // Two groups of `v`: the null one (row 0 and 64..99) and 9 (rows 1..63).
    const gs: sp.AggregateSpec = .{ .group_by = &.{"v"}, .aggs = &.{.{ .src = "k", .out = "s", .func = .sum }} };
    try testing.expectEqual(@as(usize, 2), (try frame.aggregate(a, f, gs)).len);
    const us: sp.UnpivotSpec = .{ .id_cols = &.{"k"}, .value_cols = &.{"v"} };
    try testing.expectEqual(@as(usize, 100), (try frame.unpivot(a, f, us)).len);

    // A bit clear over a value that is not 0, taken from the part the bitmap covers.
    const first: sp.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .lt, .value = .{ .int = 3 } }} };
    const got = try frame.filter(a, f, first);
    try testing.expectEqual(@as(f64, 0), got.data[1].float.values[0]);
    try testing.expectEqual(vm.Value.null, got.data[1].get(0));
    try testing.expectEqual(@as(f64, 9), got.data[1].get(1).float);
}

test "frame text: a selection reaching the column's last bytes, and long cells" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "t", .type = .text }});
    const long = "a text cell longer than the block the short copy moves at once";
    const rows = try a.dupe([]const Value, &.{
        try a.dupe(Value, &.{.{ .text = long }}),
        try a.dupe(Value, &.{.{ .text = "ab" }}),
        try a.dupe(Value, &.{.{ .text = "" }}),
        try a.dupe(Value, &.{.{ .text = "tail" }}),
    });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    for ([_]usize{ 0, 1, 2, 3 }) |skip| {
        const spec: sp.FilterSpec = .{ .where = &.{.{ .col = "t", .op = .ne, .value = .{ .text = (rows[skip][0]).text } }} };
        const got = try frame.filter(a, f, spec);
        try testing.expectEqual(@as(usize, 3), got.len); // every row but the skipped one
        for (0..got.len) |ri| try testing.expect(!std.mem.eql(u8, got.data[0].get(ri).text, rows[skip][0].text));
    }
}

test "frame aggregate refuses an oversized result" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "k", .type = .int }});
    const rows = try a.alloc([]const Value, 5000);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{.{ .int = @intCast(i) }});
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    // 5000 groups x 3400 aggregates, past `max_aggregate_cells`.
    const aggs = try a.alloc(sp.AggCol, 3400);
    @memset(aggs, .{ .src = "k", .out = "c", .func = .count });
    const spec: sp.AggregateSpec = .{ .group_by = &.{"k"}, .aggs = aggs };
    try testing.expectError(error.TooLarge, frame.aggregate(a, f, spec));
}

test "frame unpivot: long melted names are stored boxed, and one kind stays typed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const long_name: [200]u8 = @splat('n');
    const long: []const u8 = &long_name;
    const cols = try a.dupe(Column, &.{ .{ .name = long, .type = .int }, .{ .name = "t", .type = .text }, .{ .name = "u", .type = .text } });
    const rows = try a.alloc([]const Value, 50);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .text = "x" }, .{ .text = "yy" } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);

    const big: sp.UnpivotSpec = .{ .id_cols = &.{"t"}, .value_cols = &.{long} };
    const m = try frame.unpivot(a, f, big);
    try testing.expect(m.data[1] == .boxed); // 200 bytes a cell against a `Value`'s 32
    try testing.expect(m.data[2] == .int);

    const texts: sp.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ "t", "u" } };
    const n = try frame.unpivot(a, f, texts);
    try testing.expect(n.data[0] == .text);
    try testing.expect(n.data[1] == .text);

    const mixed: sp.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ long, "t" } };
    try testing.expect((try frame.unpivot(a, f, mixed)).data[1] == .boxed);
}

test "frame join: a coalesced key of one kind stays typed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "k", .type = .int }});
    const lrows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{.{ .int = 1 }})});
    const rrows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{.{ .int = 2 }})});
    const l = try F(a, .{ .columns = cols, .rows = lrows });
    const r = try F(a, .{ .columns = cols, .rows = rrows });
    const j = try frame.join(a, l, r, .{ .on = "k", .how = .full, .coalesce_keys = true });
    try testing.expect(j.data[0] == .int);
    try testing.expectEqual(@as(i64, 2), j.data[0].get(1).int);
}

test "frame sort: an all-int or all-float key takes the image path, a mixed one the ranks" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "i", .type = .int }, .{ .name = "f", .type = .float }, .{ .name = "m", .type = .float } });
    const rows = try a.alloc([]const Value, 300);
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{
        if (i % 17 == 0) .null else Value{ .int = r.intRangeAtMost(i64, std.math.minInt(i64), std.math.maxInt(i64)) },
        if (i % 13 == 0) Value{ .float = std.math.nan(f64) } else Value{ .float = randFloat(r) },
        if (i % 2 == 0) Value{ .int = r.intRangeAtMost(i64, -3, 3) } else Value{ .float = randFloat(r) },
    });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    try testing.expect(f.data[0] == .int and f.data[1] == .float and f.data[2] == .boxed);
    for ([_][]const u8{ "i", "f", "m" }) |k| {
        const ci: usize = if (k[0] == 'i') 0 else if (k[0] == 'f') 1 else 2;
        for (std.enums.values(sp.SortDir)) |dir| {
            inline for (.{ .auto, .first, .last }) |missing| {
                const spec: sp.SortSpec = .{ .key = k, .dir = dir, .then_by = &.{.{ .key = "i" }}, .missing = missing };
                const got = try frame.sort(a, f, spec);
                try testing.expectEqual(f.len, got.len);
                // Neighbours that are both present come in the asked direction.
                var prev: ?Value = null;
                for (0..got.len) |ri| {
                    const c = got.columnAt(ci).get(ri);
                    if (c == .null or (c == .float and std.math.isNan(c.float))) continue;
                    if (prev) |p| {
                        const o = p.order(c);
                        try testing.expect(if (dir == .asc) o != .gt else o != .lt);
                    }
                    prev = c;
                }
            }
        }
    }
    // A sort that leaves every row in place shares the columns.
    const sorted = try frame.sort(a, f, .{ .key = "i" });
    const again = try frame.sort(a, sorted, .{ .key = "i" });
    try testing.expectEqual(sorted.data[1].float.values.ptr, again.data[1].float.values.ptr);
}

test "frame sort, dropna, pivot: past u32 rows is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(vm.Column, &.{.{ .name = "k", .type = .int }});
    const huge: Frame = .{ .columns = cols, .data = &.{}, .len = 1 << 40 };
    try testing.expectError(error.TooLarge, frame.sort(a, huge, .{ .key = "k" }));
    try testing.expectError(error.TooLarge, frame.dropna(a, huge, .{}));
    try testing.expectError(error.TooLarge, frame.pivot(a, huge, .{ .row_key = "k", .col_key = "k", .value_col = "k" }));
}

test "frame pivot refuses an oversized matrix" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "r", .type = .int }, .{ .name = "c", .type = .int } });
    const rows = try a.alloc([]const Value, 3000);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .int = @intCast(i) } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    // 3000 x 3000 cells, past `max_pivot_cells`.
    const spec: sp.PivotSpec = .{ .row_key = "r", .col_key = "c", .value_col = "r" };
    try testing.expectError(error.TooLarge, frame.pivot(a, f, spec));
}
