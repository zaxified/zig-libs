// SPDX-License-Identifier: MIT
//! `mutate`, `where`, `cast` and `window` against `tabular`'s row verbs of the same
//! names, over the generated tables of `verbs_test.zig`: random expression trees and
//! every window operation with random parameters, per group or not. The same cells, or
//! the same error.

const std = @import("std");
const testing = std.testing;
const tab = @import("tabular");
const ds = @import("dataset");
const vt = @import("verbs_test.zig");
const ex = @import("expr.zig");
const win = @import("window.zig");
const Rng = std.Random;
const tex = tab.expr;
const twin = tab.window;
const conv = vt.conv;

fn randomExpr(a: std.mem.Allocator, r: Rng, d: ds.Dataset, depth: usize) error{OutOfMemory}!tex.Expr {
    const leaf = depth == 0 or r.uintLessThan(u8, 3) == 0;
    if (leaf) {
        if (r.boolean()) return .{ .col = vt.pickName(r, d) };
        return .{ .lit = try vt.cellOf(r, a, r.enumValue(vt.Shape)) };
    }
    const one = struct {
        fn f(al: std.mem.Allocator, rr: Rng, dd: ds.Dataset, dep: usize) error{OutOfMemory}!*const tex.Expr {
            const p = try al.create(tex.Expr);
            p.* = try randomExpr(al, rr, dd, dep);
            return p;
        }
    }.f;
    return switch (r.uintLessThan(u8, 7)) {
        0 => .{ .unary = .{ .op = r.enumValue(tex.Unary), .x = try one(a, r, d, depth - 1) } },
        1, 2 => .{ .binary = .{ .op = r.enumValue(tex.Binary), .l = try one(a, r, d, depth - 1), .r = try one(a, r, d, depth - 1) } },
        3 => blk: {
            const vals = try a.alloc(ds.Value, r.uintLessThan(usize, 4));
            for (vals) |*v| v.* = try vt.cellOf(r, a, r.enumValue(vt.Shape));
            break :blk .{ .is_in = .{ .x = try one(a, r, d, depth - 1), .values = vals } };
        },
        4 => .{ .if_else = .{ .cond = try one(a, r, d, depth - 1), .then = try one(a, r, d, depth - 1), .otherwise = try one(a, r, d, depth - 1) } },
        5 => blk: {
            const xs = try a.alloc(tex.Expr, r.uintLessThan(usize, 3));
            for (xs) |*x| x.* = try randomExpr(a, r, d, depth - 1);
            break :blk .{ .coalesce = xs };
        },
        else => if (r.boolean())
            .{ .cast = .{ .x = try one(a, r, d, depth - 1), .to = r.enumValue(ds.ColumnType) } }
        else
            .{ .replace = .{ .x = try one(a, r, d, depth - 1), .from = if (r.boolean()) "a" else "", .to = "xy" } },
    };
}

test "frame verbs agree with the row verbs: mutate, where, cast" {
    for (0..vt.seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0xe4e4);
        const r = prng.random();
        const rows = if (r.boolean()) r.uintLessThan(usize, 12) else r.uintLessThan(usize, 100);
        const d = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), rows);
        const f = try vt.F(a, d);

        const assigns = try a.alloc(tex.Assign, 1 + r.uintLessThan(usize, 2));
        for (assigns) |*as| as.* = .{
            .out = if (r.boolean()) vt.pickName(r, d) else "out",
            .expr = try randomExpr(a, r, d, 3),
            .type = if (r.uintLessThan(u8, 3) == 0) r.enumValue(ds.ColumnType) else null,
        };
        try vt.agree(tex.mutate(a, d, assigns), ex.mutate(a, f, try conv([]const ex.Assign, a, assigns)));

        const cond = try randomExpr(a, r, d, 3);
        const fcond = try conv(ex.Expr, a, cond);
        try vt.agree(tex.where(a, d, &cond), ex.where(a, f, &fcond));

        var cs: tex.CastSpec = .{ .col = vt.pickName(r, d), .to = r.enumValue(ds.ColumnType) };
        cs.on_error = if (r.boolean()) .null else .fail;
        try vt.agree(tex.cast(a, d, cs), ex.cast(a, f, try conv(ex.CastSpec, a, cs)));
    }
}

fn randomOp(a: std.mem.Allocator, r: Rng, d: ds.Dataset) !twin.Op {
    _ = a;
    const opt = struct {
        fn n(rr: Rng) ?usize {
            return if (rr.boolean()) null else rr.uintLessThan(usize, 6);
        }
    };
    return switch (r.uintLessThan(u8, 17)) {
        0 => .{ .shift = .{ .n = r.intRangeAtMost(i64, -4, 4), .fill = if (r.boolean()) .null else switch (r.uintLessThan(u8, 3)) {
            0 => ds.Value{ .int = 7 },
            1 => ds.Value{ .float = 0.5 },
            else => ds.Value{ .text = "f" },
        } } },
        1 => .{ .diff = r.intRangeAtMost(i64, -3, 3) },
        2 => .{ .pct_change = r.intRangeAtMost(i64, -3, 3) },
        3 => .cum_sum,
        4 => .cum_prod,
        5 => .cum_min,
        6 => .cum_max,
        7 => .cum_count,
        8 => .row_number,
        9 => .{ .rolling = .{ .window = r.uintLessThan(usize, 7), .func = r.enumValue(twin.WinFn), .min_periods = opt.n(r), .center = r.boolean() } },
        10 => .{ .rolling_time = .{ .time_col = vt.pickName(r, d), .period = r.intRangeAtMost(i64, -1, 4), .func = r.enumValue(twin.WinFn), .min_periods = r.uintLessThan(usize, 3) } },
        11 => .{ .expanding = .{ .func = r.enumValue(twin.WinFn), .min_periods = r.uintLessThan(usize, 4) } },
        12 => blk: {
            var e: twin.Ewm = .{ .adjust = r.boolean(), .ignore_na = r.boolean(), .min_periods = r.uintLessThan(usize, 3) };
            switch (r.uintLessThan(u8, 5)) {
                0 => e.alpha = r.float(f64) * 1.2,
                1 => e.span = r.float(f64) * 6,
                2 => e.com = r.float(f64) * 4 - 0.5,
                3 => e.halflife = r.float(f64) * 3,
                else => {
                    e.alpha = 0.5;
                    e.span = 3; // two at once: InvalidDecay on both sides
                },
            }
            e.func = switch (r.uintLessThan(u8, 3)) {
                0 => .mean,
                1 => .@"var",
                else => .std,
            };
            break :blk .{ .ewm = e };
        },
        13 => .{ .rank = .{ .method = r.enumValue(twin.RankMethod), .descending = r.boolean() } },
        14 => if (r.boolean()) .{ .ffill = opt.n(r) } else .{ .bfill = opt.n(r) },
        15 => .{ .interpolate = .{ .extend_last = r.boolean() } },
        else => .{ .transform = .{ .func = r.enumValue(tab.transforms.AggFn), .q = r.float(f64) } },
    };
}

test "frame verbs agree with the row verbs: window, every operation, per group or not" {
    for (0..vt.seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0x3d3d);
        const r = prng.random();
        const rows = if (r.boolean()) r.uintLessThan(usize, 12) else r.uintLessThan(usize, 100);
        const d = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), rows);
        const f = try vt.F(a, d);
        const by = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (by) |*n| n.* = vt.pickName(r, d);
        const spec: twin.Spec = .{ .value_col = vt.pickName(r, d), .out = "o", .op = try randomOp(a, r, d), .partition_by = by };
        try vt.agree(twin.window(a, d, spec), win.window(a, f, try conv(win.WindowSpec, a, spec)));
    }
}

test "window and where: a frame past u32 rows is refused before any work" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]@import("value.zig").Column{.{ .name = "k", .type = .int }};
    const huge: @import("frame.zig").Frame = .{ .columns = &cols, .data = &.{}, .len = 1 << 40 };
    try testing.expectError(error.TooLarge, win.window(a, huge, .{ .value_col = "k", .out = "o", .op = .cum_sum }));
    const e: ex.Expr = .{ .col = "k" };
    try testing.expectError(error.TooLarge, ex.where(a, huge, &e));
}
