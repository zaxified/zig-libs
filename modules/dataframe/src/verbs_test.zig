// SPDX-License-Identifier: MIT
//! Every verb against `tabular`'s row verb of the same name, over generated tables of
//! every column shape: the same cells, or the same error. The row verbs are pinned to
//! pandas and polars by `tabular`'s oracle vectors (and the verbs here by the same
//! vectors in `oracle_test.zig`), so agreeing with them carries that anchor over.
//!
//! Tables are generated as `dataset` rows, the oracle's input, and handed to the verbs
//! here through `FrameBuilder`; specs are written as `tabular`'s and converted field by
//! field (`conv`), so one spec drives both sides.

const std = @import("std");
const testing = std.testing;
const ds = @import("dataset");
const tab = @import("tabular");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const sp = @import("spec.zig");
const frame = @import("verbs.zig");
const bridge = @import("storage_test.zig");
const series = tab.series;
const transforms = tab.transforms;
const Column = ds.Column;
const Dataset = ds.Dataset;
const Frame = fm.Frame;
const Value = ds.Value;

/// A `tabular` spec as this module's spec type of the same shape: struct fields by
/// name, enums and union tags by name, slices and optionals element by element.
pub fn conv(comptime To: type, a: std.mem.Allocator, x: anytype) error{OutOfMemory}!To {
    const From = @TypeOf(x);
    if (From == To) return x;
    switch (@typeInfo(To)) {
        .@"struct" => |info| {
            var out: To = undefined;
            inline for (info.field_names, info.field_types, info.field_attrs) |name, FT, attr| {
                // A field this module added after the move: the row verb has no such
                // option, so the default (the row verb's behaviour) is what it means.
                if (comptime !@hasField(From, name)) {
                    @field(out, name) = comptime attr.defaultValue(FT).?;
                } else {
                    @field(out, name) = try conv(FT, a, @field(x, name));
                }
            }
            return out;
        },
        .@"enum" => return std.meta.stringToEnum(To, @tagName(x)).?,
        .@"union" => switch (x) {
            inline else => |payload, tag| return @unionInit(To, @tagName(tag), try conv(@FieldType(To, @tagName(tag)), a, payload)),
        },
        .optional => |o| return if (x) |v| try conv(o.child, a, v) else null,
        .pointer => |p| {
            if (p.size == .one) {
                const one = try a.create(p.child);
                one.* = try conv(p.child, a, x.*);
                return one;
            }
            const out = try a.alloc(p.child, x.len);
            for (out, x) |*o, v| o.* = try conv(p.child, a, v);
            return out;
        },
        else => return x,
    }
}

/// The frame of a row table, as `FrameBuilder` makes it.
pub fn F(a: std.mem.Allocator, d: Dataset) !Frame {
    return bridge.frameOf(a, d);
}

/// A frame's cells as `dataset` rows, for the oracle's side of a hand-built frame.
pub fn rowsOf(a: std.mem.Allocator, f: Frame) !Dataset {
    const cols = try a.alloc(Column, f.columns.len);
    for (cols, f.columns) |*c, x| c.* = .{ .name = x.name, .type = std.meta.stringToEnum(ds.ColumnType, @tagName(x.type)).? };
    const rows = try a.alloc([]const Value, f.len);
    for (rows, 0..) |*r, ri| {
        const cells = try a.alloc(Value, cols.len);
        for (cells, 0..) |*c, ci| c.* = try conv(Value, a, f.columnAt(ci).get(ri));
        r.* = cells;
    }
    return .{ .columns = cols, .rows = rows };
}

const Rng = std.Random;

pub const Shape = enum { floats, floats_nan, floats_null, whole_missing, ints, ints_null, text, text_null, bools, decimals, mixed, all_null };

pub fn cellOf(r: Rng, a: std.mem.Allocator, shape: Shape) !Value {
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
pub fn randFloat(r: Rng) f64 {
    return switch (r.uintLessThan(u8, 5)) {
        0 => 0,
        1 => -0.0,
        2 => @floatFromInt(r.intRangeAtMost(i64, -3, 3)),
        3 => @as(f64, @floatFromInt(r.intRangeAtMost(i64, -40, 40))) * 0.25,
        else => r.float(f64) * 1e6 - 5e5,
    };
}

const names = [_][]const u8{ "c0", "c1", "c2", "c3" };

pub fn table(a: std.mem.Allocator, r: Rng, prefix: []const u8, w: usize, rows: usize) !Dataset {
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

pub fn expectSameTable(want: Dataset, got: Frame) !void {
    try testing.expectEqual(want.columns.len, got.columns.len);
    for (want.columns, got.columns) |w, g| {
        try testing.expectEqualStrings(w.name, g.name);
        try testing.expectEqualStrings(@tagName(w.type), @tagName(g.type));
    }
    try testing.expectEqual(want.rows.len, got.len);
    for (want.rows, 0..) |row, ri| {
        for (row, 0..) |cell, ci| {
            const g = got.columnAt(ci).get(ri);
            if (!bridge.sameCell(cell, g)) {
                std.debug.print("row {d} col {s}: row verb {any}, frame verb {any}\n", .{ ri, want.columns[ci].name, cell, g });
                return error.TestUnexpectedResult;
            }
        }
    }
}

/// The two results, whichever way: both the same error, or the same cells.
/// `agree` up to row order: both sides' rows sorted by `Value.order`, cell by cell.
pub fn agreeUnordered(row: anytype, col: anytype) !void {
    const want = row catch |e| return testing.expectError(e, col);
    const got = try col;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try rowsOf(a, got);
    const Lt = struct {
        fn lt(_: void, l: []const Value, m: []const Value) bool {
            for (l, m) |x, y| {
                const o = x.order(y);
                if (o != .eq) return o == .lt;
            }
            return false;
        }
    };
    const w = try a.dupe([]const Value, want.rows);
    const h = try a.dupe([]const Value, g.rows);
    std.mem.sort([]const Value, w, {}, Lt.lt);
    std.mem.sort([]const Value, h, {}, Lt.lt);
    try expectSameTable(.{ .columns = want.columns, .rows = w }, try F(a, .{ .columns = g.columns, .rows = h }));
}

pub fn agree(row: anytype, col: anytype) !void {
    if (row) |want| {
        try expectSameTable(want, try col);
    } else |e| {
        try testing.expectError(e, col);
    }
}

pub fn pickName(r: Rng, d: Dataset) []const u8 {
    if (d.columns.len == 0 or r.uintLessThan(u8, 40) == 0) return "no such column";
    return d.columns[r.uintLessThan(usize, d.columns.len)].name;
}

fn operand(r: Rng, d: Dataset) transforms.Operand {
    if (r.uintLessThan(u8, 4) == 0) return .{ .num = randFloat(r) };
    return .{ .col = pickName(r, d) };
}

pub const seeds = 4000;

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
        const f = try F(a, d);

        const mspec: transforms.MapSpec = .{
            .out = "out",
            .lhs = operand(r, d),
            .op = r.enumValue(transforms.BinOp),
            .rhs = operand(r, d),
            .on_missing = r.enumValue(transforms.OnMissing),
            .out_type = if (r.boolean()) .float else .int,
        };
        try agree(transforms.map(a, d, mspec), frame.map(a, f, try conv(sp.MapSpec, a, mspec)));

        const cs: series.ColSpec = .{ .value_col = pickName(r, d), .out = "out" };
        // `cumsum` and `rolling` follow pandas and polars (review 2026-11-07), which is
        // `window`'s rule, not `series`' missing-as-0: the oracle is `window` here, and
        // `window` is pinned to both engines by the vectors.
        try agree(tab.window.window(a, d, .{ .value_col = cs.value_col, .out = cs.out, .op = .cum_sum }), frame.cumsum(a, f, try conv(sp.ColSpec, a, cs)));

        const rs: series.RollSpec = .{
            .value_col = pickName(r, d),
            .out = "out",
            .window = r.uintLessThan(usize, 24),
            .func = r.enumValue(series.RollFn),
        };
        const wf: tab.window.WinFn = switch (rs.func) {
            .mean => .mean,
            .sum => .sum,
            .std_sample => .std,
            .min => .min,
            .max => .max,
        };
        try agree(tab.window.window(a, d, .{ .value_col = rs.value_col, .out = rs.out, .op = .{ .rolling = .{ .window = rs.window, .func = wf } } }), frame.rolling(a, f, try conv(sp.RollSpec, a, rs)));
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
        const lf = try F(a, l);
        const rf = try F(a, rt);

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
        try agree(series.join(a, l, rt, spec), frame.join(a, lf, rf, try conv(sp.JoinSpec, a, spec)));
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
        const lf = try F(a, l);
        const rf = try F(a, rt);
        try testing.expect(lf.data[0] == .int and lf.data[0].int.valid == null);
        for (std.enums.values(series.JoinHow)) |how| {
            const spec: series.JoinSpec = .{ .on = "k", .how = how, .coalesce_keys = r.boolean() };
            try agree(series.join(a, l, rt, spec), frame.join(a, lf, rf, try conv(sp.JoinSpec, a, spec)));
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

test "frame verbs refuse the same oversized work as the row verbs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } });
    const rows = try a.alloc([]const Value, 1 << 16);
    for (rows) |*row| row.* = try a.dupe(Value, &.{ .{ .int = 1 }, .{ .float = 1 } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);

    // (2^16 - 2^15 + 1) * 2^15 visits, past `max_rolling_work`.
    const rs: series.RollSpec = .{ .value_col = "v", .out = "p", .window = 1 << 15 };
    try testing.expectError(error.TooLarge, tab.window.window(a, d, .{ .value_col = "v", .out = "p", .op = .{ .rolling = .{ .window = 1 << 15 } } }));
    try testing.expectError(error.TooLarge, frame.rolling(a, f, try conv(sp.RollSpec, a, rs)));

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

test "frame join: a key count that differs between the sides is the row verb's error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "j", .type = .int } });
    const rows = try a.dupe([]const Value, &.{try a.dupe(Value, &.{ .{ .int = 1 }, .{ .int = 2 } })});
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    const spec: series.JoinSpec = .{ .on = "k", .right_on = &.{ "k", "j" } };
    try testing.expectError(error.NoSuchColumn, series.join(a, d, d, spec));
    try testing.expectError(error.NoSuchColumn, frame.join(a, f, f, try conv(sp.JoinSpec, a, spec)));
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
        const f = try F(a, d);

        const preds = try a.alloc(transforms.Predicate, r.uintLessThan(usize, 4));
        for (preds) |*p| p.* = try randomPredicate(a, r, d);
        const fs: transforms.FilterSpec = .{ .where = preds, .mode = if (r.boolean()) .all else .any };
        try agree(transforms.filter(a, d, fs), frame.filter(a, f, try conv(sp.FilterSpec, a, fs)));

        const ids = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (ids) |*n| n.* = pickName(r, d);
        const vals = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (vals) |*n| n.* = pickName(r, d);
        const us: transforms.UnpivotSpec = .{ .id_cols = ids, .value_cols = vals };
        try agree(transforms.unpivot(a, d, us), frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, us)));

        const ds_keys = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (ds_keys) |*n| n.* = pickName(r, d);
        var dspec: series.DistinctSpec = .{ .keys = ds_keys };
        dspec.keep = switch (r.uintLessThan(u8, 3)) {
            0 => .first,
            1 => .last,
            else => .none,
        };
        // `.last` keeps its rows in input order here (pandas, polars; review 2026-11-07),
        // first-seen key order in the row verb: the same rows, compared as a set.
        if (dspec.keep == .last) {
            try agreeUnordered(series.distinct(a, d, dspec), frame.distinct(a, f, try conv(sp.DistinctSpec, a, dspec)));
        } else try agree(series.distinct(a, d, dspec), frame.distinct(a, f, try conv(sp.DistinctSpec, a, dspec)));

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
        // With no group columns the row verb's `drop_missing_keys` drops its one row
        // when any result is missing (`tabular` SPEC § Backlog); here it does nothing.
        var row_gs = gs;
        if (gs.group_by.len == 0) row_gs.drop_missing_keys = false;
        try agree(transforms.aggregate(a, d, row_gs), frame.aggregate(a, f, try conv(sp.AggregateSpec, a, gs)));
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
        const f = try F(a, d);
        const gs: transforms.AggregateSpec = .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "s", .func = .sum }} };
        const got = try frame.aggregate(a, f, try conv(sp.AggregateSpec, a, gs));
        try testing.expectEqual(@as(usize, 3), got.len);
        try testing.expectEqual(vm.Value.null, got.data[0].get(1));
        try testing.expectEqual(@as(f64, 17), got.data[1].get(0).float);
        try testing.expectEqual(@as(f64, 10), got.data[1].get(1).float);
        // With no group columns the row verb's `drop_missing_keys` drops its one row
        // when any result is missing (`tabular` SPEC § Backlog); here it does nothing.
        var row_gs = gs;
        if (gs.group_by.len == 0) row_gs.drop_missing_keys = false;
        try agree(transforms.aggregate(a, d, row_gs), frame.aggregate(a, f, try conv(sp.AggregateSpec, a, gs)));
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
    for (std.enums.values(transforms.CmpOp)) |op| {
        const p: transforms.Predicate = .{ .col = "v", .op = op, .value = .{ .float = std.math.nan(f64) } };
        const all: transforms.FilterSpec = .{ .where = &.{p} };
        const any: transforms.FilterSpec = .{ .where = &.{p}, .mode = .any };
        try agree(transforms.filter(a, d, all), frame.filter(a, f, try conv(sp.FilterSpec, a, all)));
        try agree(transforms.filter(a, d, any), frame.filter(a, f, try conv(sp.FilterSpec, a, any)));
        const q: transforms.Predicate = .{ .col = "v", .op = op, .value = .{ .float = 1 } };
        const sq: transforms.FilterSpec = .{ .where = &.{q} };
        try agree(transforms.filter(a, d, sq), frame.filter(a, f, try conv(sp.FilterSpec, a, sq)));
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
    for ([_]i64{ 0, 1, 40, 64, 65, 128, 150 }) |limit| {
        for ([_]transforms.CmpOp{ .lt, .gt }) |op| {
            const spec: transforms.FilterSpec = .{ .where = &.{.{ .col = "v", .op = op, .value = .{ .int = limit } }} };
            const got = try frame.filter(a, f, try conv(sp.FilterSpec, a, spec));
            try agree(transforms.filter(a, d, spec), frame.filter(a, f, try conv(sp.FilterSpec, a, spec)));
            for (0..got.len) |ri| try testing.expect(got.data[0] != .int or got.data[0].int.isValid(ri) or got.data[0].int.values[ri] == 0);
        }
    }
    // Every row kept but none of them null: the result needs no bitmap.
    const spec: transforms.FilterSpec = .{ .where = &.{.{ .col = "v", .op = .not_null }} };
    const kept = try frame.filter(a, f, try conv(sp.FilterSpec, a, spec));
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
    const d = try rowsOf(a, f);

    const fs: transforms.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .is_null }}, .mode = .any };
    try agree(transforms.filter(a, d, fs), frame.filter(a, f, try conv(sp.FilterSpec, a, fs)));
    const keep: transforms.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .not_null }} };
    try agree(transforms.filter(a, d, keep), frame.filter(a, f, try conv(sp.FilterSpec, a, keep)));
    const every: transforms.FilterSpec = .{ .where = &.{.{ .col = "v", .op = .is_null }}, .mode = .any };
    try agree(transforms.filter(a, d, every), frame.filter(a, f, try conv(sp.FilterSpec, a, every)));
    const gs: transforms.AggregateSpec = .{ .group_by = &.{"v"}, .aggs = &.{.{ .src = "k", .out = "s", .func = .sum }} };
    try agree(transforms.aggregate(a, d, gs), frame.aggregate(a, f, try conv(sp.AggregateSpec, a, gs)));
    const us: transforms.UnpivotSpec = .{ .id_cols = &.{"k"}, .value_cols = &.{"v"} };
    try agree(transforms.unpivot(a, d, us), frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, us)));

    // A bit clear over a value that is not 0, taken from the part the bitmap covers.
    const first: transforms.FilterSpec = .{ .where = &.{.{ .col = "k", .op = .lt, .value = .{ .int = 3 } }} };
    const got = try frame.filter(a, f, try conv(sp.FilterSpec, a, first));
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
        const spec: transforms.FilterSpec = .{ .where = &.{.{ .col = "t", .op = .ne, .value = .{ .text = (rows[skip][0]).text } }} };
        try agree(transforms.filter(a, d, spec), frame.filter(a, f, try conv(sp.FilterSpec, a, spec)));
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
    const f = try F(a, d);
    // 5000 groups x 3400 aggregates, past `max_aggregate_cells`.
    const aggs = try a.alloc(transforms.AggCol, 3400);
    @memset(aggs, .{ .src = "k", .out = "c", .func = .count });
    const spec: transforms.AggregateSpec = .{ .group_by = &.{"k"}, .aggs = aggs };
    try testing.expectError(error.TooLarge, transforms.aggregate(a, d, spec));
    try testing.expectError(error.TooLarge, frame.aggregate(a, f, try conv(sp.AggregateSpec, a, spec)));
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
    const f = try F(a, d);

    const big: transforms.UnpivotSpec = .{ .id_cols = &.{"t"}, .value_cols = &.{long} };
    const m = try frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, big));
    try testing.expect(m.data[1] == .boxed); // 200 bytes a cell against a `Value`'s 32
    try testing.expect(m.data[2] == .int);
    try agree(transforms.unpivot(a, d, big), frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, big)));

    const texts: transforms.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ "t", "u" } };
    const n = try frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, texts));
    try testing.expect(n.data[0] == .text);
    try testing.expect(n.data[1] == .text);
    try agree(transforms.unpivot(a, d, texts), frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, texts)));

    const mixed: transforms.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ long, "t" } };
    try testing.expect((try frame.unpivot(a, f, try conv(sp.UnpivotSpec, a, mixed))).data[1] == .boxed);
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

// ── the verbs `tabular.frame` did not have ──────────────────────────────────

fn randomNames(a: std.mem.Allocator, r: Rng, d: Dataset, max: usize) ![]const []const u8 {
    const out = try a.alloc([]const u8, r.uintLessThan(usize, max));
    for (out) |*n| n.* = pickName(r, d);
    return out;
}

test "frame verbs agree with the row verbs: sort, dropna, fillna, pivot" {
    for (0..seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0x5047);
        const r = prng.random();
        const rows = if (r.boolean()) r.uintLessThan(usize, 12) else r.uintLessThan(usize, 140);
        const d = try table(a, r, "", 1 + r.uintLessThan(usize, 4), rows);
        const f = try F(a, d);

        const then = try a.alloc(transforms.SortKey, r.uintLessThan(usize, 3));
        for (then) |*t| t.* = .{ .key = pickName(r, d), .dir = r.enumValue(transforms.SortDir) };
        var ss: transforms.SortSpec = .{ .key = pickName(r, d), .dir = r.enumValue(transforms.SortDir), .then_by = then };
        ss.missing = switch (r.uintLessThan(u8, 3)) {
            0 => .auto,
            1 => .first,
            else => .last,
        };
        try agree(transforms.sort(a, d, ss), frame.sort(a, f, try conv(sp.SortSpec, a, ss)));

        var dn: transforms.DropNaSpec = .{ .subset = try randomNames(a, r, d, 3) };
        dn.how = if (r.boolean()) .any else .all;
        try agree(transforms.dropna(a, d, dn), frame.dropna(a, f, try conv(sp.DropNaSpec, a, dn)));

        const fill: transforms.FillNaSpec = .{ .subset = try randomNames(a, r, d, 3), .value = try cellOf(r, a, r.enumValue(Shape)) };
        try agree(transforms.fillna(a, d, fill), frame.fillna(a, f, try conv(sp.FillNaSpec, a, fill)));

        const ps: transforms.PivotSpec = .{
            .row_key = pickName(r, d),
            .col_key = pickName(r, d),
            .value_col = pickName(r, d),
            .agg = r.enumValue(transforms.AggFn),
            .q = if (r.uintLessThan(u8, 8) == 0) 2 else r.float(f64),
            .skip_na = r.boolean(),
            .fill_value = if (r.boolean()) randFloat(r) else null,
        };
        try agree(transforms.pivot(a, d, ps), frame.pivot(a, f, try conv(sp.PivotSpec, a, ps)));
    }
}

test "frame verbs agree with the row verbs: select, drop, rename" {
    for (0..seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0xc015);
        const r = prng.random();
        const d = try table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 20));
        const f = try F(a, d);
        const picked = try randomNames(a, r, d, 4);
        try agree(transforms.select(a, d, picked), frame.select(a, f, picked));
        try agree(transforms.drop(a, d, picked), frame.drop(a, f, picked));
        const rn = try a.alloc(transforms.Rename, r.uintLessThan(usize, 3));
        for (rn) |*x| x.* = .{ .from = pickName(r, d), .to = if (r.boolean()) pickName(r, d) else "fresh" };
        try agree(transforms.rename(a, d, rn), frame.rename(a, f, try conv([]const sp.Rename, a, rn)));
    }
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
        for (std.enums.values(transforms.SortDir)) |dir| {
            inline for (.{ .auto, .first, .last }) |missing| {
                const spec: transforms.SortSpec = .{ .key = k, .dir = dir, .then_by = &.{.{ .key = "i" }}, .missing = missing };
                try agree(transforms.sort(a, d, spec), frame.sort(a, f, try conv(sp.SortSpec, a, spec)));
            }
        }
    }
    // A sort that leaves every row in place shares the columns.
    const sorted = try frame.sort(a, f, .{ .key = "i" });
    const again = try frame.sort(a, sorted, .{ .key = "i" });
    try testing.expectEqual(sorted.data[1].float.values.ptr, again.data[1].float.values.ptr);
}

test "frame sort, dropna, pivot: past u32 rows is refused, as the row verbs do by their row count" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(vm.Column, &.{.{ .name = "k", .type = .int }});
    const huge: Frame = .{ .columns = cols, .data = &.{}, .len = 1 << 40 };
    try testing.expectError(error.TooLarge, frame.sort(a, huge, .{ .key = "k" }));
    try testing.expectError(error.TooLarge, frame.dropna(a, huge, .{}));
    try testing.expectError(error.TooLarge, frame.pivot(a, huge, .{ .row_key = "k", .col_key = "k", .value_col = "k" }));
}

test "frame pivot refuses the same oversized matrix as the row verb" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "r", .type = .int }, .{ .name = "c", .type = .int } });
    const rows = try a.alloc([]const Value, 3000);
    for (rows, 0..) |*row, i| row.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .int = @intCast(i) } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const f = try F(a, d);
    // 3000 x 3000 cells, past `max_pivot_cells`.
    const spec: transforms.PivotSpec = .{ .row_key = "r", .col_key = "c", .value_col = "r" };
    try testing.expectError(error.TooLarge, transforms.pivot(a, d, spec));
    try testing.expectError(error.TooLarge, frame.pivot(a, f, try conv(sp.PivotSpec, a, spec)));
}

test "conv: a spec arrives field by field, enums and unions by name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t: series.JoinSpec = .{ .on = "k", .keys = &.{ "a", "b" }, .how = .anti, .suffix = "_r", .null_keys = .no_match, .coalesce_keys = true };
    const g = try conv(sp.JoinSpec, a, t);
    try testing.expectEqual(sp.JoinHow.anti, g.how);
    try testing.expectEqualStrings("_r", g.suffix.?);
    try testing.expect(g.null_keys == .no_match and g.coalesce_keys);
    try testing.expectEqualStrings("b", g.keys[1]);
    const p: transforms.Predicate = .{ .col = "x", .op = .ge, .value = .{ .decimal = 5 } };
    const q = try conv(sp.Predicate, a, p);
    try testing.expectEqual(@as(i128, 5), q.value.decimal);
    try testing.expectEqual(sp.CmpOp.ge, q.op);
}
