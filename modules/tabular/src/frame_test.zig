// SPDX-License-Identifier: MIT
//! Every verb of `frame.zig` against its row verb, over generated tables of every column
//! shape: the same cells, or the same error. The row verbs are pinned to pandas and polars
//! by `oracle_test.zig`, so agreeing with them carries that anchor over.

const std = @import("std");
const testing = std.testing;
const ds = @import("dataset");
const frame = @import("frame.zig");
const series = @import("series.zig");
const transforms = @import("transforms.zig");
const Column = ds.Column;
const Dataset = ds.Dataset;
const Frame = ds.Frame;
const Value = ds.Value;

const Rng = std.Random;

const Shape = enum { floats, floats_nan, floats_null, whole_missing, ints, ints_null, text, text_null, bools, decimals, mixed, all_null };

fn cellOf(r: Rng, a: std.mem.Allocator, shape: Shape) !Value {
    switch (shape) {
        .floats => return .{ .float = randFloat(r) },
        .floats_nan => return .{ .float = if (r.uintLessThan(u8, 4) == 0) std.math.nan(f64) else randFloat(r) },
        .floats_null => return if (r.uintLessThan(u8, 4) == 0) .null else .{ .float = randFloat(r) },
        .whole_missing => return switch (r.uintLessThan(u8, 5)) {
            0 => .null,
            1 => .{ .float = std.math.nan(f64) },
            else => .{ .float = @floatFromInt(r.intRangeAtMost(i64, -3, 3)) },
        },
        .ints => return .{ .int = r.intRangeAtMost(i64, -3, 3) },
        .ints_null => return if (r.uintLessThan(u8, 4) == 0) .null else .{ .int = r.intRangeAtMost(i64, -3, 3) },
        .text => return .{ .text = try a.dupe(u8, words[r.uintLessThan(usize, words.len)]) },
        .text_null => return if (r.uintLessThan(u8, 4) == 0) .null else .{ .text = try a.dupe(u8, words[r.uintLessThan(usize, words.len)]) },
        .bools => return .{ .bool = r.boolean() },
        .decimals => return .{ .decimal = @as(i128, r.intRangeAtMost(i64, -3, 3)) * ds.decimal_scale },
        .mixed => return switch (r.uintLessThan(u8, 6)) {
            0 => .null,
            1 => .{ .int = r.intRangeAtMost(i64, -3, 3) },
            2 => .{ .float = randFloat(r) },
            3 => .{ .text = try a.dupe(u8, words[r.uintLessThan(usize, words.len)]) },
            4 => .{ .bool = r.boolean() },
            else => .{ .decimal = @as(i128, r.intRangeAtMost(i64, -3, 3)) * ds.decimal_scale },
        },
        .all_null => return .null,
    }
}

const words = [_][]const u8{ "", "a", "b", "1", "key-000001", "a longer text cell over sixteen" };

/// Small, often a whole number so keys meet across kinds, zero and -0.0 included.
fn randFloat(r: Rng) f64 {
    return switch (r.uintLessThan(u8, 5)) {
        0 => 0,
        1 => -0.0,
        2 => @floatFromInt(r.intRangeAtMost(i64, -3, 3)),
        3 => @as(f64, @floatFromInt(r.intRangeAtMost(i64, -40, 40))) * 0.25,
        else => r.float(f64) * 1e6 - 5e5,
    };
}

const names = [_][]const u8{ "c0", "c1", "c2", "c3" };

fn table(a: std.mem.Allocator, r: Rng, prefix: []const u8, w: usize, rows: usize) !Dataset {
    const cols = try a.alloc(Column, w);
    const shapes = try a.alloc(Shape, w);
    for (cols, shapes, 0..) |*c, *s, i| {
        s.* = r.enumValue(Shape);
        c.* = .{ .name = try a.print("{s}{s}", .{ prefix, names[i] }), .type = switch (s.*) {
            .ints, .ints_null => .int,
            .text, .text_null => .text,
            .bools => .bool,
            .decimals => .decimal,
            else => .float,
        } };
    }
    const out = try a.alloc([]const Value, rows);
    for (out) |*row| {
        const cells = try a.alloc(Value, w);
        for (cells, shapes) |*c, s| c.* = try cellOf(r, a, s);
        row.* = cells;
    }
    return .{ .columns = cols, .rows = out };
}

fn sameCell(x: Value, y: Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .int => |v| v == y.int,
        .bool => |v| v == y.bool,
        .decimal => |v| v == y.decimal,
        .text => |v| std.mem.eql(u8, v, y.text),
        // To the bit, any NaN being NaN: the verbs promise the row verb's arithmetic.
        .float => |v| (std.math.isNan(v) and std.math.isNan(y.float)) or @as(u64, @bitCast(v)) == @as(u64, @bitCast(y.float)),
    };
}

fn expectSameTable(want: Dataset, got: Frame) !void {
    try testing.expectEqual(want.columns.len, got.columns.len);
    for (want.columns, got.columns) |w, g| {
        try testing.expectEqualStrings(w.name, g.name);
        try testing.expectEqual(w.type, g.type);
    }
    try testing.expectEqual(want.rows.len, got.len);
    for (want.rows, 0..) |row, ri| {
        for (row, 0..) |cell, ci| {
            const g = got.data[ci].get(ri);
            if (!sameCell(cell, g)) {
                std.debug.print("row {d} col {s}: row verb {any}, frame verb {any}\n", .{ ri, want.columns[ci].name, cell, g });
                return error.TestUnexpectedResult;
            }
        }
    }
}

/// The two results, whichever way: both the same error, or the same cells.
fn agree(row: anytype, col: anytype) !void {
    if (row) |want| {
        try expectSameTable(want, try col);
    } else |e| {
        try testing.expectError(e, col);
    }
}

fn pickName(r: Rng, d: Dataset) []const u8 {
    if (d.columns.len == 0 or r.uintLessThan(u8, 40) == 0) return "no such column";
    return d.columns[r.uintLessThan(usize, d.columns.len)].name;
}

fn operand(r: Rng, d: Dataset) transforms.Operand {
    if (r.uintLessThan(u8, 4) == 0) return .{ .num = randFloat(r) };
    return .{ .col = pickName(r, d) };
}

const seeds = 4000;

test "frame verbs agree with the row verbs: map, cumsum, rolling" {
    for (0..seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        const rows = if (r.boolean()) r.uintLessThan(usize, 12) else r.uintLessThan(usize, 140);
        const d = try table(a, r, "", 1 + r.uintLessThan(usize, 4), rows);
        const f = try Frame.fromDataset(a, d);

        const mspec: transforms.MapSpec = .{
            .out = "out",
            .lhs = operand(r, d),
            .op = r.enumValue(transforms.BinOp),
            .rhs = operand(r, d),
            .on_missing = r.enumValue(transforms.OnMissing),
            .out_type = if (r.boolean()) .float else .int,
        };
        try agree(transforms.map(a, d, mspec), frame.map(a, f, mspec));

        const cs: series.ColSpec = .{ .value_col = pickName(r, d), .out = "out" };
        try agree(series.cumsum(a, d, cs), frame.cumsum(a, f, cs));

        const rs: series.RollSpec = .{
            .value_col = pickName(r, d),
            .out = "out",
            .window = r.uintLessThan(usize, 24),
            .func = r.enumValue(series.RollFn),
        };
        try agree(series.rolling(a, d, rs), frame.rolling(a, f, rs));
    }
}

test "frame verbs agree with the row verbs: join, every how and option" {
    for (0..seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0x51ab);
        const r = prng.random();
        const l = try table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 30));
        const rt = try table(a, r, if (r.boolean()) "" else "r_", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 30));
        const lf = try Frame.fromDataset(a, l);
        const rf = try Frame.fromDataset(a, rt);

        var spec: series.JoinSpec = .{ .on = "c0" };
        spec.how = r.enumValue(series.JoinHow);
        spec.null_keys = if (r.boolean()) .match else .no_match;
        spec.coalesce_keys = r.boolean();
        spec.suffix = if (r.boolean()) "_r" else null;
        const lk = pickName(r, l);
        const rk = pickName(r, rt);
        switch (r.uintLessThan(u8, 3)) {
            0 => spec.on = lk,
            1 => {
                spec.on = lk;
                spec.right_on = try a.dupe([]const u8, &.{rk});
            },
            else => {
                spec.keys = try a.dupe([]const u8, &.{ lk, pickName(r, l) });
                spec.right_on = try a.dupe([]const u8, &.{ rk, pickName(r, rt) });
            },
        }
        try agree(series.join(a, l, rt, spec), frame.join(a, lf, rf, spec));
    }
}

test "frame join: plain int keys, the path that skips the rows" {
    for (0..1000) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0x77);
        const r = prng.random();
        const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
        const rcols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "rv", .type = .text } });
        const lrows = try a.alloc([]const Value, 1 + r.uintLessThan(usize, 40));
        const rrows = try a.alloc([]const Value, 1 + r.uintLessThan(usize, 40));
        for (lrows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = r.intRangeAtMost(i64, 0, 20) }, .{ .float = @floatFromInt(i) } });
        for (rrows) |*row| row.* = try a.dupe(Value, &.{ .{ .int = r.intRangeAtMost(i64, 0, 20) }, try cellOf(r, a, .text_null) });
        const l: Dataset = .{ .columns = cols, .rows = lrows };
        const rt: Dataset = .{ .columns = rcols, .rows = rrows };
        const lf = try Frame.fromDataset(a, l);
        const rf = try Frame.fromDataset(a, rt);
        try testing.expect(lf.data[0] == .int and lf.data[0].int.valid == null);
        for (std.enums.values(series.JoinHow)) |how| {
            const spec: series.JoinSpec = .{ .on = "k", .how = how, .coalesce_keys = r.boolean() };
            try agree(series.join(a, l, rt, spec), frame.join(a, lf, rf, spec));
        }
    }
}

test "frame verbs share the columns they do not touch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "t", .type = .text }, .{ .name = "v", .type = .float } });
    const rows = try a.alloc([]const Value, 3);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .text = "x" }, .{ .float = 2 } });
    const f = try Frame.fromDataset(a, .{ .columns = cols, .rows = rows });

    const m = try frame.map(a, f, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .mul, .rhs = .{ .num = 2 } });
    try testing.expectEqual(f.data[1].text.bytes.ptr, m.data[1].text.bytes.ptr);
    try testing.expectEqual(f.data[2].float.values.ptr, m.data[2].float.values.ptr);

    // A left join on a unique right key gives the left side back row for row.
    const rcols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "rv", .type = .float } });
    const rrows = try a.alloc([]const Value, 2);
    for (rrows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .float = 7 } });
    const rf = try Frame.fromDataset(a, .{ .columns = rcols, .rows = rrows });
    const j = try frame.join(a, f, rf, .{ .on = "k", .how = .left });
    try testing.expectEqual(f.data[1].text.bytes.ptr, j.data[1].text.bytes.ptr);
    try testing.expect(j.data[3].float.valid != null);
    try testing.expectEqual(Value.null, j.data[3].get(2));
}

test "frame verbs: a hand-built frame shorter than its schema reads as null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .float } });
    const data = try a.dupe(ds.ColumnData, &.{.{ .float = .{ .values = &.{ 1, 2 } } }});
    const f: Frame = .{ .columns = cols, .data = data, .len = 4 };
    const m = try frame.map(a, f, .{ .out = "p", .lhs = .{ .col = "a" }, .op = .add, .rhs = .{ .col = "b" }, .on_missing = .null });
    try testing.expectEqual(Value.null, m.data[2].get(0));
    const c = try frame.cumsum(a, f, .{ .value_col = "a", .out = "s" });
    try testing.expectEqual(@as(f64, 3), c.data[2].get(3).float);
    const j = try frame.join(a, f, f, .{ .on = "a", .how = .inner });
    try testing.expect(j.len > 0);
}

test "frame verbs refuse the same oversized work as the row verbs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
    const rows = try a.alloc([]const Value, 1 << 16);
    for (rows) |*row| row.* = try a.dupe(Value, &.{ .{ .int = 1 }, .{ .float = 1 } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try Frame.fromDataset(a, d);

    // (2^16 - 2^15 + 1) * 2^15 visits, past `max_rolling_work`.
    const rs: series.RollSpec = .{ .value_col = "v", .out = "p", .window = 1 << 15 };
    try testing.expectError(error.TooLarge, series.rolling(a, d, rs));
    try testing.expectError(error.TooLarge, frame.rolling(a, f, rs));

    // Every pair of one key, and every pair outright: 2^32 rows.
    try testing.expectError(error.TooLarge, series.join(a, d, d, .{ .on = "k" }));
    try testing.expectError(error.TooLarge, frame.join(a, f, f, .{ .on = "k" }));
    try testing.expectError(error.TooLarge, series.join(a, d, d, .{ .how = .cross }));
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
    const f = try Frame.fromDataset(a, .{ .columns = cols, .rows = rows });

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
    const rf = try Frame.fromDataset(a, .{ .columns = rcols, .rows = rrows });
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
    const f = try Frame.fromDataset(a, .{ .columns = cols, .rows = rows });
    const s = try frame.join(a, f, f, .{ .on = "k", .how = .semi });
    try testing.expectEqual(f.data[1].text.bytes.ptr, s.data[1].text.bytes.ptr);
}

test "frame join: a key count that differs between the sides is the row verb's error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "j", .type = .int } });
    const rows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{ .{ .int = 1 }, .{ .int = 2 } })});
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try Frame.fromDataset(a, d);
    const spec: series.JoinSpec = .{ .on = "k", .right_on = &.{ "k", "j" } };
    try testing.expectError(error.NoSuchColumn, series.join(a, d, d, spec));
    try testing.expectError(error.NoSuchColumn, frame.join(a, f, f, spec));
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

fn randomPredicate(a: std.mem.Allocator, r: Rng, d: Dataset) !transforms.Predicate {
    const shape = r.enumValue(Shape);
    return .{ .col = pickName(r, d), .op = r.enumValue(transforms.CmpOp), .value = try cellOf(r, a, shape) };
}

test "frame verbs agree with the row verbs: filter, unpivot, distinct, aggregate" {
    for (0..seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0xa66);
        const r = prng.random();
        const rows = if (r.boolean()) r.uintLessThan(usize, 12) else r.uintLessThan(usize, 140);
        const d = try table(a, r, "", 1 + r.uintLessThan(usize, 4), rows);
        const f = try Frame.fromDataset(a, d);

        const preds = try a.alloc(transforms.Predicate, r.uintLessThan(usize, 4));
        for (preds) |*p| p.* = try randomPredicate(a, r, d);
        const fs: transforms.FilterSpec = .{ .where = preds, .mode = if (r.boolean()) .all else .any };
        try agree(transforms.filter(a, d, fs), frame.filter(a, f, fs));

        const ids = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (ids) |*n| n.* = pickName(r, d);
        const vals = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (vals) |*n| n.* = pickName(r, d);
        const us: transforms.UnpivotSpec = .{ .id_cols = ids, .value_cols = vals };
        try agree(transforms.unpivot(a, d, us), frame.unpivot(a, f, us));

        const ds_keys = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (ds_keys) |*n| n.* = pickName(r, d);
        var dspec: series.DistinctSpec = .{ .keys = ds_keys };
        dspec.keep = switch (r.uintLessThan(u8, 3)) {
            0 => .first,
            1 => .last,
            else => .none,
        };
        try agree(series.distinct(a, d, dspec), frame.distinct(a, f, dspec));

        const by = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (by) |*n| n.* = pickName(r, d);
        const aggs = try a.alloc(transforms.AggCol, 1 + r.uintLessThan(usize, 3));
        for (aggs) |*g| g.* = .{
            .src = pickName(r, d),
            .out = pickName(r, d),
            .func = r.enumValue(transforms.AggFn),
            .q = if (r.uintLessThan(u8, 8) == 0) 2 else r.float(f64),
        };
        const gs: transforms.AggregateSpec = .{
            .group_by = by,
            .aggs = aggs,
            .fx = if (r.uintLessThan(u8, 4) == 0) .{ .rate_col = pickName(r, d) } else null,
            .skip_na = r.boolean(),
            .sort_groups = r.boolean(),
            .drop_missing_keys = r.boolean(),
        };
        try agree(transforms.aggregate(a, d, gs), frame.aggregate(a, f, gs));
    }
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
        const f = try Frame.fromDataset(a, d);
        const gs: transforms.AggregateSpec = .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "s", .func = .sum }} };
        const got = try frame.aggregate(a, f, gs);
        try testing.expectEqual(@as(usize, 3), got.len);
        try testing.expectEqual(Value.null, got.data[0].get(1));
        try testing.expectEqual(@as(f64, 17), got.data[1].get(0).float);
        try testing.expectEqual(@as(f64, 10), got.data[1].get(1).float);
        try agree(transforms.aggregate(a, d, gs), frame.aggregate(a, f, gs));
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
    const f = try Frame.fromDataset(a, d);
    const k = try frame.filter(a, f, .{ .where = &.{} });
    try testing.expectEqual(f.data[0].float.values.ptr, k.data[0].float.values.ptr);
    for (std.enums.values(transforms.CmpOp)) |op| {
        const p: transforms.Predicate = .{ .col = "v", .op = op, .value = .{ .float = std.math.nan(f64) } };
        const all: transforms.FilterSpec = .{ .where = &.{p} };
        const any: transforms.FilterSpec = .{ .where = &.{p}, .mode = .any };
        try agree(transforms.filter(a, d, all), frame.filter(a, f, all));
        try agree(transforms.filter(a, d, any), frame.filter(a, f, any));
        const q: transforms.Predicate = .{ .col = "v", .op = op, .value = .{ .float = 1 } };
        const sq: transforms.FilterSpec = .{ .where = &.{q} };
        try agree(transforms.filter(a, d, sq), frame.filter(a, f, sq));
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

    const cols = try a.dupe(Column, &.{ .{ .name = "a", .type = .float }, .{ .name = "b", .type = .float } });
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
    const f = try Frame.fromDataset(a, d);
    // Past and short of a word boundary, with and without a null among the kept rows.
    for ([_]i64{ 0, 1, 40, 64, 65, 128, 150 }) |limit| {
        for ([_]transforms.CmpOp{ .lt, .gt }) |op| {
            const spec: transforms.FilterSpec = .{ .where = &.{.{ .col = "v", .op = op, .value = .{ .int = limit } }} };
            const got = try frame.filter(a, f, spec);
            try agree(transforms.filter(a, d, spec), frame.filter(a, f, spec));
            for (0..got.len) |ri| try testing.expect(got.data[0] != .int or got.data[0].int.isValid(ri) or got.data[0].int.values[ri] == 0);
        }
    }
    // Every row kept but none of them null: the result needs no bitmap.
    const spec: transforms.FilterSpec = .{ .where = &.{.{ .col = "v", .op = .not_null }} };
    const kept = try frame.filter(a, f, spec);
    try testing.expect(kept.data[0].int.valid == null);
    try testing.expect(kept.len == 200 - 29);
}

test "frame verbs: a hand-built bitmap or array too short reads as null, never past the end" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
    // 100 rows, one word of bits, 80 values, and a garbage value under a null bit.
    var ks: [80]i64 = undefined;
    for (&ks, 0..) |*k, i| k.* = @intCast(i);
    var vs: [100]f64 = @splat(9);
    const short_bits = try a.dupe(u64, &.{0xFFFF_FFFF_FFFF_FFFE});
    const data = try a.dupe(ds.ColumnData, &.{
        .{ .int = .{ .values = &ks } },
        .{ .float = .{ .values = &vs, .valid = short_bits } },
    });
    const f: Frame = .{ .columns = cols, .data = data, .len = 100 };
    const d = try f.toDataset(a);

    const fs: transforms.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .is_null }}, .mode = .any };
    try agree(transforms.filter(a, d, fs), frame.filter(a, f, fs));
    const keep: transforms.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .not_null }} };
    try agree(transforms.filter(a, d, keep), frame.filter(a, f, keep));
    const every: transforms.FilterSpec = .{ .where = &.{.{ .col = "v", .op = .is_null }}, .mode = .any };
    try agree(transforms.filter(a, d, every), frame.filter(a, f, every));
    const gs: transforms.AggregateSpec = .{ .group_by = &.{"v"}, .aggs = &.{.{ .src = "k", .out = "s", .func = .sum }} };
    try agree(transforms.aggregate(a, d, gs), frame.aggregate(a, f, gs));
    const us: transforms.UnpivotSpec = .{ .id_cols = &.{"k"}, .value_cols = &.{"v"} };
    try agree(transforms.unpivot(a, d, us), frame.unpivot(a, f, us));

    // A bit clear over a value that is not 0, taken from the part the bitmap covers.
    const first: transforms.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .lt, .value = .{ .int = 3 } }} };
    const got = try frame.filter(a, f, first);
    try testing.expectEqual(@as(f64, 0), got.data[1].float.values[0]);
    try testing.expectEqual(Value.null, got.data[1].get(0));
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
    const f = try Frame.fromDataset(a, d);
    for ([_]usize{ 0, 1, 2, 3 }) |skip| {
        const spec: transforms.FilterSpec = .{ .where = &.{.{ .col = "t", .op = .ne, .value = .{ .text = (rows[skip][0]).text } }} };
        try agree(transforms.filter(a, d, spec), frame.filter(a, f, spec));
    }
}

test "frame aggregate refuses the same oversized result as the row verb" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "k", .type = .int }});
    const rows = try a.alloc([]const Value, 5000);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{.{ .int = @intCast(i) }});
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try Frame.fromDataset(a, d);
    // 5000 groups x 3400 aggregates, past `max_aggregate_cells`.
    const aggs = try a.alloc(transforms.AggCol, 3400);
    @memset(aggs, .{ .src = "k", .out = "c", .func = .count });
    const spec: transforms.AggregateSpec = .{ .group_by = &.{"k"}, .aggs = aggs };
    try testing.expectError(error.TooLarge, transforms.aggregate(a, d, spec));
    try testing.expectError(error.TooLarge, frame.aggregate(a, f, spec));
}

test "frame unpivot: long melted names cost what the row verb's cells cost, and one kind stays typed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const long_name: [200]u8 = @splat('n');
    const long: []const u8 = &long_name;
    const cols = try a.dupe(Column, &.{ .{ .name = long, .type = .int }, .{ .name = "t", .type = .text }, .{ .name = "u", .type = .text } });
    const rows = try a.alloc([]const Value, 50);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .text = "x" }, .{ .text = "yy" } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try Frame.fromDataset(a, d);

    const big: transforms.UnpivotSpec = .{ .id_cols = &.{"t"}, .value_cols = &.{long} };
    const m = try frame.unpivot(a, f, big);
    try testing.expect(m.data[1] == .boxed); // 200 bytes a cell against a `Value`'s 32
    try testing.expect(m.data[2] == .int);
    try agree(transforms.unpivot(a, d, big), frame.unpivot(a, f, big));

    const texts: transforms.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ "t", "u" } };
    const n = try frame.unpivot(a, f, texts);
    try testing.expect(n.data[0] == .text);
    try testing.expect(n.data[1] == .text);
    try agree(transforms.unpivot(a, d, texts), frame.unpivot(a, f, texts));

    const mixed: transforms.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ long, "t" } };
    try testing.expect((try frame.unpivot(a, f, mixed)).data[1] == .boxed);
}

test "frame join: a coalesced key of one kind stays typed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{.{ .name = "k", .type = .int }});
    const lrows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{.{ .int = 1 }})});
    const rrows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{.{ .int = 2 }})});
    const l = try Frame.fromDataset(a, .{ .columns = cols, .rows = lrows });
    const r = try Frame.fromDataset(a, .{ .columns = cols, .rows = rrows });
    const j = try frame.join(a, l, r, .{ .on = "k", .how = .full, .coalesce_keys = true });
    try testing.expect(j.data[0] == .int);
    try testing.expectEqual(@as(i64, 2), j.data[0].get(1).int);
}
