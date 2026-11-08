// SPDX-License-Identifier: MIT
//! D4-D differential tests: the typed kernels of `verbs` (`pivot`, ...) and `more`
//! against the cell-by-cell paths they replaced (`test_hooks.*Cells`), which are the
//! specification. Random frames from a seeded PRNG; outputs are compared cell by cell,
//! bit for bit, AND by storage kind and validity bitmap presence per column.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vb = @import("verbs.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;

// ── generator ───────────────────────────────────────────────────────────────

const lens = [_]usize{ 0, 1, 2, 63, 64, 65, 1000 };
const null_pcts = [_]u8{ 0, 1, 50, 100 };

fn genFloat(rng: std.Random) f64 {
    return switch (rng.uintLessThan(u8, 16)) {
        0 => std.math.nan(f64),
        1 => std.math.inf(f64),
        2 => -std.math.inf(f64),
        3 => -0.0,
        4 => 0.0,
        5 => 1e308,
        6 => -1e308,
        7, 8, 9, 10 => @as(f64, @floatFromInt(rng.intRangeAtMost(i32, -40, 40))) * 0.25,
        11 => @as(f64, @floatFromInt(rng.intRangeAtMost(i32, 0, 5))), // ties
        else => (rng.float(f64) - 0.5) * 2e6,
    };
}

fn genInt(rng: std.Random) i64 {
    return switch (rng.uintLessThan(u8, 12)) {
        0 => std.math.minInt(i64),
        1 => std.math.maxInt(i64),
        2 => (1 << 53) + 1,
        3 => rng.int(i64),
        4 => 0,
        5, 6 => rng.intRangeAtMost(i64, 0, 4), // ties
        else => rng.intRangeAtMost(i64, -50, 50),
    };
}

const Shape = enum { float, int, float_decl_int, int_decl_nan, mixed, text, bool, decimal };

fn genCell(rng: std.Random, shape: Shape, null_pct: u8, small_ints: bool) Value {
    if (rng.uintLessThan(u8, 100) < null_pct) return .null;
    return switch (shape) {
        .float => .{ .float = genFloat(rng) },
        .int, .float_decl_int => .{ .int = if (small_ints) rng.intRangeAtMost(i64, -9, 9) else genInt(rng) },
        .int_decl_nan => .{ .float = std.math.nan(f64) },
        .bool => .{ .bool = rng.boolean() },
        .decimal => .{ .decimal = @as(i128, rng.intRangeAtMost(i32, -5, 5)) * 1_000_000 },
        .mixed => switch (rng.uintLessThan(u8, 4)) {
            0 => .{ .int = genInt(rng) },
            1 => .{ .float = genFloat(rng) },
            2 => .{ .text = "x" },
            else => .{ .bool = rng.boolean() },
        },
        .text => .{ .text = switch (rng.uintLessThan(u8, 4)) {
            0 => "",
            1 => "a",
            2 => "bb",
            else => "ccc",
        } },
    };
}

/// A frame of `n` rows: value columns of every shape (`f`, `i`, `fi`, `ii`, `m`, `t`, `b`,
/// `d`) with the given null rate, group keys `g` (small ints, some null), `g2` (plain
/// ints), `gt` (text), `gf` (small whole floats, some null).
fn genFrame(a: std.mem.Allocator, rng: std.Random, n: usize, null_pct: u8) !Frame {
    const cols = [_]Column{
        .{ .name = "f", .type = .float },
        .{ .name = "i", .type = .int },
        .{ .name = "fi", .type = .float },
        .{ .name = "ii", .type = .int },
        .{ .name = "m", .type = .float },
        .{ .name = "t", .type = .text },
        .{ .name = "g", .type = .int },
        .{ .name = "g2", .type = .int },
        .{ .name = "gt", .type = .text },
        .{ .name = "b", .type = .bool },
        .{ .name = "d", .type = .decimal },
        .{ .name = "gf", .type = .float },
    };
    var b = try df.FrameBuilder.init(a, try a.dupe(Column, &cols), n);
    const small = rng.boolean();
    for (0..n) |_| {
        const gf: Value = if (rng.uintLessThan(u8, 10) == 0) .null else .{ .float = @floatFromInt(rng.intRangeAtMost(i32, 0, 3)) };
        const row = [_]Value{
            genCell(rng, .float, null_pct, small),
            genCell(rng, .int, null_pct, small),
            genCell(rng, .float_decl_int, null_pct, small),
            genCell(rng, .int_decl_nan, null_pct, small),
            genCell(rng, .mixed, null_pct, small),
            genCell(rng, .text, null_pct, small),
            genCell(rng, .int, if (rng.boolean()) 0 else 20, true),
            .{ .int = rng.intRangeAtMost(i64, 0, 4) },
            genCell(rng, .text, 0, small),
            genCell(rng, .bool, null_pct, small),
            genCell(rng, .decimal, null_pct, small),
            gf,
        };
        try b.appendRow(&row);
    }
    return b.toOwned();
}

// ── comparison ──────────────────────────────────────────────────────────────

fn sameCellBits(x: Value, y: Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .int => |v| v == y.int,
        .float => |v| @as(u64, @bitCast(v)) == @as(u64, @bitCast(y.float)) or (std.math.isNan(v) and std.math.isNan(y.float)),
        .bool => |v| v == y.bool,
        .decimal => |v| v == y.decimal,
        .text => |v| std.mem.eql(u8, v, y.text),
    };
}

fn validNullness(c: df.ColumnData) ?bool {
    return switch (c) {
        .nulls, .boxed => null,
        .int => |t| t.valid == null,
        .float => |t| t.valid == null,
        .bool => |t| t.valid == null,
        .decimal => |t| t.valid == null,
        .text => |t| t.valid == null,
    };
}

fn expectSameFrame(x: Frame, y: Frame) !void {
    try testing.expectEqual(x.len, y.len);
    try testing.expectEqual(x.columns.len, y.columns.len);
    for (x.columns, y.columns, 0..) |cx, cy, ci| {
        try testing.expectEqualStrings(cx.name, cy.name);
        try testing.expectEqual(cx.type, cy.type);
        const dx = x.columnAt(ci);
        const dy = y.columnAt(ci);
        testing.expectEqual(std.meta.activeTag(dx), std.meta.activeTag(dy)) catch |e| {
            std.debug.print("column {s}: storage {s} vs {s}\n", .{ cx.name, @tagName(dx), @tagName(dy) });
            return e;
        };
        try testing.expectEqual(validNullness(dx), validNullness(dy));
        for (0..x.len) |ri| {
            if (!sameCellBits(dx.get(ri), dy.get(ri))) {
                std.debug.print("column {s} row {d}: {any} vs {any}\n", .{ cx.name, ri, dx.get(ri), dy.get(ri) });
                return error.TestUnexpectedResult;
            }
        }
    }
}

fn expectSameResult(x: anytype, y: anytype) !void {
    if (x) |fx| {
        const fy = y catch |e| {
            std.debug.print("typed ok, cells error {s}\n", .{@errorName(e)});
            return error.TestUnexpectedResult;
        };
        try expectSameFrame(fx, fy);
    } else |ex| {
        if (y) |_| {
            std.debug.print("typed error {s}, cells ok\n", .{@errorName(ex)});
            return error.TestUnexpectedResult;
        } else |ey| try testing.expectEqual(ex, ey);
    }
}

fn pick(rng: std.Random, comptime T: type, xs: []const T) T {
    return xs[rng.uintLessThan(usize, xs.len)];
}

// ── pivot ───────────────────────────────────────────────────────────────────

const all_cols = [_][]const u8{ "f", "i", "fi", "ii", "m", "t", "g", "g2", "gt", "b", "d", "gf" };
const key_cols = [_][]const u8{ "g", "g2", "gt", "gf", "g", "g2", "gt", "i", "fi", "m", "t", "b", "d", "f", "ii" };
const pivot_aggs = [_]df.AggFn{ .sum, .sum, .sum, .mean, .mean, .count, .min, .max, .first, .last, .std, .@"var", .median, .quantile, .nunique, .size, .prod, .any, .all, .sem, .mode };

test "d4d pivot: typed keys and clean values equal the cell path" {
    var prng = std.Random.DefaultPrng.init(0xd4d0_0001);
    const rng = prng.random();
    var trial: usize = 0;
    while (trial < 600) : (trial += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const n = pick(rng, usize, &lens);
        const f = try genFrame(a, rng, n, pick(rng, u8, &null_pcts));
        const fills = [_]?f64{ null, null, 0, 2.5, 7, std.math.nan(f64) };
        const spec: df.PivotSpec = .{
            .row_key = pick(rng, []const u8, &key_cols),
            .col_key = pick(rng, []const u8, &key_cols),
            .value_col = pick(rng, []const u8, &all_cols),
            .agg = pick(rng, df.AggFn, &pivot_aggs),
            .q = if (rng.uintLessThan(u8, 6) == 0) 1.5 else rng.float(f64),
            .skip_na = rng.boolean(),
            .fill_value = pick(rng, ?f64, &fills),
        };
        expectSameResult(vb.pivot(a, f, spec), vb.test_hooks.pivotCells(a, f, spec)) catch |e| {
            std.debug.print("trial {d} n={d} row={s} col={s} val={s} agg={s}\n", .{ trial, n, spec.row_key, spec.col_key, spec.value_col, @tagName(spec.agg) });
            return e;
        };
    }
}

// ── factorizeInts presize ───────────────────────────────────────────────────

const keys = @import("keys.zig");

test "d4d factorizeInts: presized table gives the ids and firsts of the unsized one" {
    var prng = std.Random.DefaultPrng.init(0xd4d0_0002);
    const rng = prng.random();
    const sizes = [_]usize{ 0, 1, 1023, 1024, 1025, 100000 };
    const kinds = 8;
    for (sizes) |n| {
        for (0..kinds) |kind| {
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            const a = arena.allocator();
            const xs = try a.alloc(i64, n);
            for (xs, 0..) |*x, i| x.* = switch (kind) {
                0 => @intCast(i), // sorted, all distinct
                1 => @as(i64, @intCast(n)) - @as(i64, @intCast(i)), // reverse
                2 => 7, // all equal
                3 => rng.int(i64), // all distinct, random
                4 => @intCast(i % 2), // two values
                5 => rng.intRangeAtMost(i64, 0, 50_000), // random, high-ish
                6 => @intCast(i / 50), // sorted runs
                else => @intCast(i % 20_000), // cycle
            };
            const with = try keys.test_hooks.factorizeIntsPresize(a, xs, true);
            const without = try keys.test_hooks.factorizeIntsPresize(a, xs, false);
            try testing.expectEqualSlices(u32, without.ids, with.ids);
            try testing.expectEqualSlices(u32, without.firsts, with.firsts);
            try testing.expect(keys.test_hooks.presizeSlotsOf(xs) <= keys.max_presize_slots);
        }
    }
}

// ── unpivot ─────────────────────────────────────────────────────────────────

const id_sets = [_][]const []const u8{ &.{}, &.{"g"}, &.{"g2"}, &.{"gt"}, &.{ "g2", "f" }, &.{ "i", "t", "b", "d" }, &.{ "f", "f" }, &.{"zz"} };
const val_sets = [_][]const []const u8{ &.{}, &.{"f"}, &.{ "f", "m" }, &.{ "i", "ii" }, &.{ "i", "g2" }, &.{ "f", "fi" }, &.{ "b", "b" }, &.{ "d", "d" }, &.{ "t", "gt" }, &.{ "f", "i" }, &.{ "g2", "g2", "g2" }, &.{ "f", "f", "f", "f" }, &.{ "m", "t" } };

test "d4d unpivot: typed id repeat and weave equal the cell path" {
    var prng = std.Random.DefaultPrng.init(0xd4d0_0003);
    const rng = prng.random();
    var trial: usize = 0;
    while (trial < 800) : (trial += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const n = pick(rng, usize, &lens);
        const f = try genFrame(a, rng, n, pick(rng, u8, &null_pcts));
        const spec: df.UnpivotSpec = .{
            .id_cols = pick(rng, []const []const u8, &id_sets),
            .value_cols = pick(rng, []const []const u8, &val_sets),
        };
        expectSameResult(vb.unpivot(a, f, spec), vb.test_hooks.unpivotCells(a, f, spec)) catch |e| {
            std.debug.print("trial {d} n={d} ids={d} vals={d}\n", .{ trial, n, spec.id_cols.len, spec.value_cols.len });
            return e;
        };
    }
}
