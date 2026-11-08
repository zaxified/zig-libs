// SPDX-License-Identifier: MIT
//! D4-A differential tests: the typed kernels of `window` (`cum_*`, `shift`, `rolling`),
//! `fillNull` (forward / backward) and `topK` against the cell-by-cell paths they replaced
//! (`test_hooks.*Cells`), which are the specification. Random frames from a seeded PRNG;
//! outputs are compared cell by cell, bit for bit, AND by storage kind and validity
//! bitmap presence per column.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const win = @import("window.zig");
const ana = @import("analysis.zig");
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

const Shape = enum { float, int, float_decl_int, int_decl_nan, mixed, text };

fn genCell(rng: std.Random, shape: Shape, null_pct: u8, small_ints: bool) Value {
    if (rng.uintLessThan(u8, 100) < null_pct) return .null;
    return switch (shape) {
        .float => .{ .float = genFloat(rng) },
        .int, .float_decl_int => .{ .int = if (small_ints) rng.intRangeAtMost(i64, -9, 9) else genInt(rng) },
        .int_decl_nan => .{ .float = std.math.nan(f64) },
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

/// A frame of `n` rows: value columns of every shape (`f`, `i`, `fi`, `ii`, `m`, `t`) with
/// the given null rate, group keys `g` (ints, some null), `g2` (plain ints), `gt` (text).
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
    };
    var b = try df.FrameBuilder.init(a, try a.dupe(Column, &cols), n);
    const small = rng.boolean();
    for (0..n) |_| {
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

// ── window ──────────────────────────────────────────────────────────────────

const value_cols = [_][]const u8{ "f", "i", "fi", "ii", "m", "t" };
const part_sets = [_][]const []const u8{ &.{}, &.{"g"}, &.{"g2"}, &.{"gt"}, &.{ "g", "g2" } };
const win_fns = [_]win.WinFn{ .mean, .sum, .std, .@"var", .min, .max, .count, .median, .prod, .sem, .skew, .kurt, .first, .last, .nunique, .quantile };

fn genOp(rng: std.Random) win.WindowOp {
    switch (rng.uintLessThan(u8, 7)) {
        0 => return .cum_sum,
        1 => return .cum_prod,
        2 => return .cum_min,
        3 => return .cum_max,
        4 => {
            const ns = [_]i64{ 1, -1, 0, 2, 3, -7, 1000, -1000, std.math.minInt(i64), std.math.maxInt(i64) };
            return .{ .shift = .{ .n = ns[rng.uintLessThan(usize, ns.len)] } };
        },
        5 => {
            // Shift with a fill: the typed path must step aside for these.
            const fills = [_]Value{ .{ .int = 7 }, .{ .float = 0.5 }, .{ .float = std.math.nan(f64) }, .{ .text = "z" }, .{ .float = 3.0 } };
            return .{ .shift = .{ .n = rng.intRangeAtMost(i64, -3, 3), .fill = fills[rng.uintLessThan(usize, fills.len)] } };
        },
        else => {
            const wins = [_]usize{ 0, 1, 2, 3, 5, 20, 100, 1 << 40, std.math.maxInt(usize) };
            const mps = [_]?usize{ null, null, 0, 1, 2, 3 };
            return .{ .rolling = .{
                .window = wins[rng.uintLessThan(usize, wins.len)],
                .func = win_fns[rng.uintLessThan(usize, win_fns.len)],
                .min_periods = mps[rng.uintLessThan(usize, mps.len)],
                .center = rng.boolean(),
                .q = if (rng.uintLessThan(u8, 8) == 0) 1.5 else rng.float(f64),
                .ddof = rng.uintLessThan(u32, 3),
            } };
        },
    }
}

test "d4a window: typed kernels equal the cell path (cum_*, shift, rolling)" {
    var prng = std.Random.DefaultPrng.init(0xd4a0_0001);
    const rng = prng.random();
    var trial: usize = 0;
    while (trial < 1500) : (trial += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const n = lens[rng.uintLessThan(usize, lens.len)];
        const f = try genFrame(a, rng, n, null_pcts[rng.uintLessThan(usize, null_pcts.len)]);
        const spec: win.WindowSpec = .{
            .value_col = value_cols[rng.uintLessThan(usize, value_cols.len)],
            .out = "out",
            .op = genOp(rng),
            .partition_by = part_sets[rng.uintLessThan(usize, part_sets.len)],
        };
        const got = win.window(a, f, spec);
        const want = win.test_hooks.windowCells(a, f, spec);
        expectSameResult(got, want) catch |e| {
            std.debug.print("trial {d} n={d} col={s} op={s} part={d}\n", .{ trial, n, spec.value_col, @tagName(spec.op), spec.partition_by.len });
            return e;
        };
    }
}

/// Columns with nothing missing: the kernels' fast paths (vector `sum` / `mean`, the run
/// before the first NaN) that random frames with NaNs and nulls never reach.
fn genCleanFrame(a: std.mem.Allocator, rng: std.Random, n: usize, nan_at: ?usize) !Frame {
    const cols = [_]Column{ .{ .name = "f", .type = .float }, .{ .name = "i", .type = .int }, .{ .name = "g2", .type = .int } };
    var b = try df.FrameBuilder.init(a, try a.dupe(Column, &cols), n);
    for (0..n) |ri| {
        var x = genFloat(rng);
        while (std.math.isNan(x)) x = genFloat(rng);
        if (nan_at != null and ri == nan_at.?) x = std.math.nan(f64);
        try b.appendRow(&.{ .{ .float = x }, .{ .int = genInt(rng) }, .{ .int = rng.intRangeAtMost(i64, 0, 2) } });
    }
    return b.toOwned();
}

test "d4a window: clean columns take the fast paths and still equal the cell path" {
    var prng = std.Random.DefaultPrng.init(0xd4a0_0002);
    const rng = prng.random();
    const wins = [_]usize{ 1, 2, 3, 4, 5, 7, 20, 64, 65, 70 };
    var trial: usize = 0;
    while (trial < 800) : (trial += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const n = lens[rng.uintLessThan(usize, lens.len)];
        const nan_at: ?usize = if (n > 0 and rng.uintLessThan(u8, 3) == 0) rng.uintLessThan(usize, n) else null;
        const f = try genCleanFrame(a, rng, n, nan_at);
        const op: win.WindowOp = switch (rng.uintLessThan(u8, 3)) {
            0 => .cum_sum,
            1 => .cum_max,
            else => .{ .rolling = .{
                .window = wins[rng.uintLessThan(usize, wins.len)],
                .func = if (rng.boolean()) .mean else .sum,
                .min_periods = if (rng.boolean()) null else rng.uintLessThan(usize, 4),
                .center = rng.boolean(),
            } },
        };
        const spec: win.WindowSpec = .{
            .value_col = if (rng.boolean()) "f" else "i",
            .out = "out",
            .op = op,
            .partition_by = if (rng.boolean()) &.{} else &.{"g2"},
        };
        expectSameResult(win.window(a, f, spec), win.test_hooks.windowCells(a, f, spec)) catch |e| {
            std.debug.print("trial {d} n={d} col={s} op={s}\n", .{ trial, n, spec.value_col, @tagName(spec.op) });
            return e;
        };
    }
}
