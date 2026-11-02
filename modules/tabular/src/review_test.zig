// SPDX-License-Identifier: MIT
//! Regressions from the independent review of 2026-11-02, one test per finding,
//! through the public API. Each failed on the code it reviewed.
const std = @import("std");
const testing = std.testing;
const dsmod = @import("dataset");
const t0 = @import("transforms.zig");
const t1 = @import("series.zig");
const ex = @import("expr.zig");
const win = @import("window.zig");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;

const min_i = std.math.minInt(i64);
const max_i = std.math.maxInt(i64);

fn lit(v: Value) ex.Expr {
    return .{ .lit = v };
}

fn modOf(a: std.mem.Allocator, x: i64, y: i64) !Value {
    const cols = [_]Column{.{ .name = "z", .type = .int }};
    const rows = [_][]const Value{&.{.{ .int = 0 }}};
    const l = lit(.{ .int = x });
    const r = lit(.{ .int = y });
    const e: ex.Expr = .{ .binary = .{ .op = .mod, .l = &l, .r = &r } };
    const o = try ex.mutate(a, .{ .columns = &cols, .rows = &rows }, &.{.{ .out = "o", .expr = e }});
    return o.rows[0][1];
}

test "H1: int mod over extreme operands, against i128 arithmetic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqual(@as(i64, -1), (try modOf(a, max_i, -2)).int);
    try testing.expectEqual(@as(i64, 1), (try modOf(a, min_i, 3)).int);
    const xs = [_]i64{ min_i, min_i + 1, -3, -1, 0, 1, 3, max_i - 1, max_i };
    const ys = [_]i64{ min_i, min_i + 1, -3, -2, -1, 1, 2, 3, max_i - 1, max_i };
    for (xs) |x| {
        for (ys) |y| {
            const wx: i128 = x;
            const wy: i128 = y;
            const want = wx - @divFloor(wx, wy) * wy;
            try testing.expectEqual(want, @as(i128, (try modOf(a, x, y)).int));
        }
    }
    try testing.expect((try modOf(a, max_i, 0)) == .null);
}

test "M1: a float and a decimal equal under Value.order group together" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "k", .type = .float }, .{ .name = "v", .type = .int } };
    const f: Value = .{ .float = 62560.5634765625 };
    const d: Value = .{ .decimal = 62560563476562500 };
    try testing.expectEqual(std.math.Order.eq, f.order(d));
    const rows = [_][]const Value{ &.{ f, .{ .int = 1 } }, &.{ d, .{ .int = 2 } } };
    const g = try t0.aggregate(a, .{ .columns = &cols, .rows = &rows }, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "o", .func = .size }} });
    try testing.expectEqual(@as(usize, 1), g.rows.len);
}

test "M2: quantile under fx counts what it stores" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "v", .type = .float }, .{ .name = "fx", .type = .float } };
    const inf = std.math.inf(f64);
    const rows = [_][]const Value{
        &.{ .{ .float = 5 }, .{ .float = 1 } },
        &.{ .{ .float = inf }, .{ .float = 0 } }, // inf x 0 is NaN: not stored
    };
    const g = try t0.aggregate(a, .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{},
        .aggs = &.{.{ .src = "v", .out = "o", .func = .median }},
        .fx = .{ .rate_col = "fx" },
    });
    try testing.expectEqual(@as(f64, 5), g.rows[0][0].float);
}

test "M4: valueCounts of a column named like its output; no duplicate output names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "count", .type = .int }, .{ .name = "x", .type = .text } };
    const rows = [_][]const Value{
        &.{ .{ .int = 1 }, .{ .text = "1" } },
        &.{ .{ .int = 2 }, .{ .text = "1" } },
        &.{ .{ .int = 2 }, .{ .text = "1" } },
        &.{ .{ .int = 3 }, .{ .text = "1" } },
        &.{ .{ .int = 3 }, .{ .text = "1" } },
        &.{ .{ .int = 3 }, .{ .text = "1" } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const v = try t0.valueCounts(a, d, .{ .cols = &.{"count"} });
    try testing.expectEqual(@as(i64, 3), v.rows[0][0].int); // most frequent key first
    try testing.expectEqual(@as(i64, 3), v.rows[0][1].int);
    try testing.expectEqual(@as(i64, 1), v.rows[2][1].int);
    try testing.expect(!std.mem.eql(u8, v.columns[0].name, v.columns[1].name));

    const pc = [_]Column{ .{ .name = "r", .type = .text }, .{ .name = "c", .type = .text }, .{ .name = "v", .type = .float } };
    const pr = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .int = 1 }, .{ .float = 1 } },
        &.{ .{ .text = "a" }, .{ .text = "1" }, .{ .float = 2 } },
        &.{ .{ .text = "a" }, .{ .text = "r" }, .{ .float = 3 } },
    };
    const p = try t0.pivot(a, .{ .columns = &pc, .rows = &pr }, .{ .row_key = "r", .col_key = "c", .value_col = "v" });
    for (p.columns, 0..) |x, i| {
        for (p.columns[i + 1 ..]) |y| try testing.expect(!std.mem.eql(u8, x.name, y.name));
    }
    const ag = try t0.aggregate(a, d, .{ .group_by = &.{"x"}, .aggs = &.{
        .{ .src = "count", .out = "x", .func = .sum },
        .{ .src = "count", .out = "o", .func = .sum },
        .{ .src = "count", .out = "o", .func = .max },
    } });
    for (ag.columns, 0..) |x, i| {
        for (ag.columns[i + 1 ..]) |y| try testing.expect(!std.mem.eql(u8, x.name, y.name));
    }
    const um = try t0.unpivot(a, d, .{ .id_cols = &.{"x"}, .value_cols = &.{"count"}, .out_key = "x", .out_value = "x" });
    try testing.expect(!std.mem.eql(u8, um.columns[0].name, um.columns[1].name));
    try testing.expect(!std.mem.eql(u8, um.columns[1].name, um.columns[2].name));
}

test "L1: a ragged row is an error from every verb" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .float } };
    const short = [_][]const Value{ &.{ .{ .int = 1 }, .{ .float = 1 } }, &.{.{ .int = 2 }} };
    const long = [_][]const Value{ &.{ .{ .int = 1 }, .{ .float = 1 } }, &.{ .{ .int = 2 }, .{ .float = 1 }, .null } };
    const good = [_][]const Value{&.{ .{ .int = 1 }, .{ .float = 1 } }};
    const ok: Dataset = .{ .columns = &cols, .rows = &good };
    for ([_]Dataset{ .{ .columns = &cols, .rows = &short }, .{ .columns = &cols, .rows = &long } }) |d| {
        const e = error.NoSuchColumn;
        try testing.expectError(e, t0.aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "o", .func = .sum }} }));
        try testing.expectError(e, t0.map(a, d, .{ .out = "o", .lhs = .{ .col = "v" }, .op = .abs }));
        try testing.expectError(e, t0.sort(a, d, .{ .key = "v" }));
        try testing.expectError(e, t0.filter(a, d, .{ .where = &.{.{ .col = "v", .op = .is_null }} }));
        try testing.expectError(e, t0.filterBy(a, d, {}, struct {
            fn f(_: void, _: []const Value) bool {
                return true;
            }
        }.f));
        try testing.expectError(e, t0.pivot(a, d, .{ .row_key = "k", .col_key = "k", .value_col = "v" }));
        try testing.expectError(e, t0.unpivot(a, d, .{ .id_cols = &.{"k"} }));
        try testing.expectError(e, t0.select(a, d, &.{"v"}));
        try testing.expectError(e, t0.drop(a, d, &.{"v"}));
        try testing.expectError(e, t0.dropna(a, d, .{}));
        try testing.expectError(e, t0.fillna(a, d, .{ .value = .null }));
        try testing.expectError(e, t0.clip(a, d, .{ .col = "v" }));
        try testing.expectError(e, t0.percentOfTotal(a, d, .{ .value_col = "v", .out = "o" }));
        try testing.expectError(e, t0.concatByName(a, &.{ ok, d }));
        try testing.expectError(e, t1.join(a, ok, d, .{ .on = "k" }));
        try testing.expectError(e, t1.join(a, d, ok, .{ .on = "k", .how = .full }));
        try testing.expectError(e, t1.join(a, d, ok, .{ .how = .cross }));
        try testing.expectError(e, t1.joinAsof(a, d, ok, .{ .on = "k" }));
        try testing.expectError(e, t1.distinct(a, d, .{ .keys = &.{} }));
        try testing.expectError(e, t1.cumsum(a, d, .{ .value_col = "v", .out = "o" }));
        try testing.expectError(e, t1.rolling(a, d, .{ .value_col = "v", .out = "o", .window = 1 }));
        try testing.expectError(e, t1.mergeByKey(a, d, "k"));
        try testing.expectError(e, ex.mutate(a, d, &.{.{ .out = "o", .expr = .{ .col = "v" } }}));
        try testing.expectError(e, ex.where(a, d, &.{ .col = "v" }));
        try testing.expectError(e, ex.cast(a, d, .{ .col = "v", .to = .int }));
        try testing.expectError(e, win.window(a, d, .{ .value_col = "v", .out = "o", .op = .cum_sum }));
    }
}

test "L2: a cross join of tables without columns is capped by rows" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const empty_row = [_]Value{};
    const rows = try a.alloc([]const Value, 1 << 16);
    @memset(rows, &empty_row);
    const d: Dataset = .{ .columns = &.{}, .rows = rows };
    try testing.expectError(error.TooLarge, t1.join(a, d, d, .{ .how = .cross }));
}

test "L5: the declared type holds for every cell a verb writes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "c", .type = .bool }, .{ .name = "n", .type = .int } };
    const rows = [_][]const Value{ &.{ .{ .bool = true }, .{ .int = 1 } }, &.{ .{ .bool = false }, .{ .int = 2 } } };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const c: ex.Expr = .{ .col = "c" };
    const n: ex.Expr = .{ .col = "n" };
    const half = lit(.{ .float = 0.5 });
    const word = lit(.{ .text = "w" });
    // int then float: promoted, as both engines do.
    const m = try ex.mutate(a, d, &.{.{ .out = "o", .expr = .{ .if_else = .{ .cond = &c, .then = &n, .otherwise = &half } } }});
    try testing.expectEqual(dsmod.ColumnType.float, m.columns[2].type);
    try testing.expect(m.rows[0][2] == .float);
    try testing.expect(m.rows[1][2] == .float);
    // int then text: no type holds them.
    try testing.expectError(error.BadExpr, ex.mutate(a, d, &.{.{ .out = "o", .expr = .{ .if_else = .{ .cond = &c, .then = &n, .otherwise = &word } } }}));
    // a declared type is applied, not just written down.
    const typed = try ex.mutate(a, d, &.{.{ .out = "o", .expr = n, .type = .float }});
    try testing.expect(typed.rows[0][2] == .float);

    // window: a fill of another kind.
    const sf = try win.window(a, d, .{ .value_col = "n", .out = "o", .op = .{ .shift = .{ .fill = .{ .float = 0.5 } } } });
    try testing.expectEqual(dsmod.ColumnType.float, sf.columns[2].type);
    for (sf.rows) |r| try testing.expect(r[2] == .float);
    const si = try win.window(a, d, .{ .value_col = "n", .out = "o", .op = .{ .shift = .{ .fill = .{ .float = 7 } } } });
    try testing.expectEqual(dsmod.ColumnType.int, si.columns[2].type);
    try testing.expect(si.rows[0][2] == .int);
    try testing.expectError(error.BadFill, win.window(a, d, .{ .value_col = "n", .out = "o", .op = .{ .shift = .{ .fill = .{ .text = "x" } } } }));

    // clip keeps an int column int under integral bounds, and goes float otherwise.
    const ci = try t0.clip(a, d, .{ .col = "n", .upper = 1 });
    try testing.expectEqual(dsmod.ColumnType.int, ci.columns[1].type);
    try testing.expect(ci.rows[1][1] == .int);
    const cf = try t0.clip(a, d, .{ .col = "n", .upper = 1.5 });
    try testing.expectEqual(dsmod.ColumnType.float, cf.columns[1].type);
    try testing.expect(cf.rows[0][1] == .float);

    // pivot says what it holds; aggregate under fx turns a numeric min into a float.
    const pv = try t0.pivot(a, d, .{ .row_key = "c", .col_key = "n", .value_col = "n", .agg = .count });
    try testing.expectEqual(dsmod.ColumnType.int, pv.columns[1].type);
    const fxc = [_]Column{ .{ .name = "n", .type = .int }, .{ .name = "fx", .type = .float } };
    const fxr = [_][]const Value{&.{ .{ .int = 2 }, .{ .float = 1.5 } }};
    const fg = try t0.aggregate(a, .{ .columns = &fxc, .rows = &fxr }, .{ .group_by = &.{}, .aggs = &.{.{ .src = "n", .out = "o", .func = .min }}, .fx = .{ .rate_col = "fx" } });
    try testing.expectEqual(dsmod.ColumnType.float, fg.columns[0].type);
}

test "L6: rolling min_periods 0 over an all-missing window, as both engines" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "x", .type = .float }};
    const rows = [_][]const Value{ &.{.null}, &.{.null}, &.{.{ .float = 1 }} };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const s = try win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 2, .func = .sum, .min_periods = 0 } } });
    try testing.expectEqual(@as(f64, 0), s.rows[0][1].float);
    const m = try win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 2, .func = .mean, .min_periods = 0 } } });
    try testing.expect(m.rows[0][1] == .null);
    const c = try win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 2, .func = .count, .min_periods = 0 } } });
    try testing.expectEqual(@as(f64, 0), c.rows[0][1].asFloat().?);
}

test "L8: text to number takes what the engines take, no hex, no underscores, no truncation" {
    const a = testing.allocator;
    try testing.expect(std.math.isNan((try ex.castValue(a, .{ .text = "nan" }, .float)).float));
    try testing.expect(std.math.isNan((try ex.castValue(a, .{ .text = "NaN" }, .float)).float));
    try testing.expectEqual(std.math.inf(f64), (try ex.castValue(a, .{ .text = "inf" }, .float)).float);
    try testing.expectEqual(-std.math.inf(f64), (try ex.castValue(a, .{ .text = "-inf" }, .float)).float);
    try testing.expectEqual(std.math.inf(f64), (try ex.castValue(a, .{ .text = "Infinity" }, .float)).float);
    try testing.expectEqual(@as(f64, 100), (try ex.castValue(a, .{ .text = "1e2" }, .float)).float);
    try testing.expect((try ex.castValue(a, .{ .text = "0x10" }, .float)) == .null);
    try testing.expect((try ex.castValue(a, .{ .text = "1_000" }, .float)) == .null);
    try testing.expect((try ex.castValue(a, .{ .text = "0x10" }, .int)) == .null);
    try testing.expect((try ex.castValue(a, .{ .text = "1_000" }, .int)) == .null);
    try testing.expect((try ex.castValue(a, .{ .text = "12.9" }, .int)) == .null);
    try testing.expect((try ex.castValue(a, .{ .text = "inf" }, .int)) == .null);
    try testing.expectEqual(@as(i64, 100), (try ex.castValue(a, .{ .text = "1e2" }, .int)).int);
    try testing.expectEqual(@as(i64, 12), (try ex.castValue(a, .{ .text = " 12 " }, .int)).int);
}

/// Keys every one of which landed in one slot of the unseeded table this replaced:
/// equal low and high words cancel in its `u ^ (u >> 32)`, multiples of 2^8 clear the
/// bits its index would have seen from the high word.
fn attackKeys(a: std.mem.Allocator, n: usize) ![]const []const Value {
    const rows = try a.alloc([]const Value, n);
    for (rows, 0..) |*r, i| {
        const t: u64 = @as(u64, i + 1) << 8;
        r.* = try a.dupe(Value, &.{.{ .int = @bitCast((t << 32) | t) }});
    }
    return rows;
}

test "M5 attack: constructed int keys stay linear" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "k", .type = .int }};
    const n = 60_000;
    const d: Dataset = .{ .columns = &cols, .rows = try attackKeys(a, n) };
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const t = std.Io.Clock.Timestamp.now(io, .awake);
    const g = try t0.aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "k", .out = "o", .func = .size }} });
    try testing.expectEqual(@as(usize, n), g.rows.len);
    const j = try t1.join(a, d, d, .{ .on = "k" });
    try testing.expectEqual(@as(usize, n), j.rows.len);
    const ms = t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    // Measured 2026-11-02: 35 ms in Debug; the unseeded table took 5854 ms in ReleaseSafe.
    // The margin is for a loaded machine.
    try testing.expect(ms < 3000);
}

test "M3: window keeps an int column exact past 2^53; aggregate sum states its loss" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const big: i64 = (1 << 53) + 1;
    const cols = [_]Column{.{ .name = "x", .type = .int }};
    const rows = [_][]const Value{ &.{.{ .int = big }}, &.{.null}, &.{.{ .int = 2 }}, &.{.{ .int = max_i }} };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const c = try win.window(a, d, .{ .value_col = "x", .out = "o", .op = .cum_sum });
    try testing.expectEqual(dsmod.ColumnType.int, c.columns[1].type);
    try testing.expectEqual(big, c.rows[0][1].int);
    try testing.expect(c.rows[1][1] == .null);
    try testing.expectEqual(big + 2, c.rows[2][1].int);
    try testing.expect(c.rows[3][1] == .null); // overflow: null, not wrapped
    const df = try win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .diff = 2 } });
    try testing.expectEqual(2 - big, df.rows[2][1].int);
    const small = [_][]const Value{ &.{.{ .int = big }}, &.{.{ .int = 2 }} };
    const tr = try win.window(a, .{ .columns = &cols, .rows = &small }, .{ .value_col = "x", .out = "o", .op = .{ .transform = .{ .func = .sum } } });
    try testing.expectEqual(big + 2, tr.rows[0][1].int);
    // The documented loss, pinned so that a change to it is a decision.
    const g = try t0.reduce(a, .{ .columns = &cols, .rows = &small }, &.{.{ .src = "x", .out = "o", .func = .sum }});
    try testing.expectEqual(@as(f64, @floatFromInt(big)) + 2, g.rows[0][0].float);
    const ex_sum = try t0.reduce(a, .{ .columns = &cols, .rows = &small }, &.{.{ .src = "x", .out = "o", .func = .sum_exact }});
    try testing.expectEqual(@as(i128, big + 2) * dsmod.decimal_scale, ex_sum.rows[0][0].decimal);
}
