// SPDX-License-Identifier: MIT
//! Tests of dataframe S2 wave W11, the computing half: arithmetic, literals, aggregates,
//! cumulative and window operations and the combining forms over the width types. What the
//! engines answer is in `s2w11a_oracle_test.zig`; these are the nulls, the empty frame, every
//! width, the caps and the errors.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const fm = @import("frame.zig");
const vm = @import("value.zig");
const dtype = @import("dtype.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;

const NamedCol = struct { []const u8, ColumnType, []const Value };

fn built(a: std.mem.Allocator, specs: []const NamedCol) !Frame {
    const cols = try a.alloc(Column, specs.len);
    for (cols, specs) |*c, s| c.* = .{ .name = s[0], .type = s[1] };
    var b = try fm.FrameBuilder.init(a, cols, specs[0][2].len);
    const row = try a.alloc(Value, specs.len);
    for (0..specs[0][2].len) |ri| {
        for (row, specs) |*o, s| o.* = s[2][ri];
        try b.appendRow(row);
    }
    return b.toOwned();
}

fn bx(a: std.mem.Allocator, e: df.Expr) !*const df.Expr {
    const p = try a.create(df.Expr);
    p.* = e;
    return p;
}

fn col(a: std.mem.Allocator, name: []const u8) !*const df.Expr {
    return bx(a, .{ .col = name });
}

fn lit(a: std.mem.Allocator, v: Value) !*const df.Expr {
    return bx(a, .{ .lit = v });
}

fn bin(op: df.Binary, l: *const df.Expr, r: *const df.Expr) df.Expr {
    return .{ .binary = .{ .op = op, .l = l, .r = r } };
}

fn mut(a: std.mem.Allocator, f: Frame, e: df.Expr) !Frame {
    const g = try df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
    try testing.expect(fm.widthsConform(g));
    return g;
}

fn cell(g: Frame, name: []const u8, i: usize) Value {
    return g.columnAt(g.columnIndex(name).?).get(i);
}

fn ty(g: Frame, name: []const u8) ColumnType {
    return g.columns[g.columnIndex(name).?].type;
}

const nul: Value = .null;

fn iv(x: i64) Value {
    return .{ .int = x };
}

fn fl(x: f64) Value {
    return .{ .float = x };
}

test "W11a arithmetic: the node type is the supertype, an overflow is null, nulls pass" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "x", .int8, &.{ iv(100), iv(-128), nul, iv(1) } },
        .{ "y", .int8, &.{ iv(100), iv(-1), iv(1), nul } },
    });
    const g = try mut(a, f, bin(.add, try col(a, "x"), try col(a, "y")));
    try testing.expectEqual(ColumnType.int8, ty(g, "r"));
    try testing.expect(cell(g, "r", 0) == .null); // 200: outside Int8, null where polars wraps
    try testing.expect(cell(g, "r", 1) == .null); // -129
    try testing.expect(cell(g, "r", 2) == .null and cell(g, "r", 3) == .null);
    // Int8 with UInt8 meets in Int16: 100 + 200 fits.
    const h = try built(a, &.{
        .{ "x", .int8, &.{ iv(100), iv(-128) } },
        .{ "u", .uint8, &.{ iv(200), iv(255) } },
    });
    const m = try mut(a, h, bin(.add, try col(a, "x"), try col(a, "u")));
    try testing.expectEqual(ColumnType.int16, ty(m, "r"));
    try testing.expectEqual(@as(i64, 300), cell(m, "r", 0).int);
    try testing.expectEqual(@as(i64, 127), cell(m, "r", 1).int);
}

test "W11a arithmetic: every width computes, floordiv and mod by zero are null, / is a float" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const widths = [_]ColumnType{ .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 };
    for (widths) |t| {
        const f = try built(a, &.{.{ "x", t, &.{ iv(7), iv(0), nul, iv(100) } }});
        const sum = try mut(a, f, bin(.add, try col(a, "x"), try lit(a, iv(1))));
        try testing.expectEqual(t, ty(sum, "r")); // the literal fits: the column's type
        try testing.expectEqual(@as(i64, 8), cell(sum, "r", 0).int);
        try testing.expect(cell(sum, "r", 2) == .null);
        const fd = try mut(a, f, bin(.floordiv, try col(a, "x"), try lit(a, iv(0))));
        try testing.expectEqual(t, ty(fd, "r"));
        for (0..4) |k| try testing.expect(cell(fd, "r", k) == .null);
        const md = try mut(a, f, bin(.mod, try col(a, "x"), try lit(a, iv(0))));
        for (0..4) |k| try testing.expect(cell(md, "r", k) == .null);
        const dv = try mut(a, f, bin(.div, try col(a, "x"), try lit(a, iv(2))));
        try testing.expectEqual(ColumnType.float, ty(dv, "r"));
        try testing.expectEqual(@as(f64, 3.5), cell(dv, "r", 0).float);
    }
}

test "W11a weak literals: the column's type when the literal fits, else the supertype" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s", .int8, &.{ iv(1), iv(-128) } },
        .{ "u", .uint8, &.{ iv(1), iv(255) } },
        .{ "w", .uint64, &.{ iv(1), .{ .uint = std.math.maxInt(u64) } } },
    });
    const s1000 = try mut(a, f, bin(.add, try col(a, "s"), try lit(a, iv(1000))));
    try testing.expectEqual(ColumnType.int16, ty(s1000, "r"));
    try testing.expectEqual(@as(i64, 872), cell(s1000, "r", 1).int);
    const u_neg = try mut(a, f, bin(.add, try col(a, "u"), try lit(a, iv(-1))));
    try testing.expectEqual(ColumnType.int16, ty(u_neg, "r"));
    try testing.expectEqual(@as(i64, 254), cell(u_neg, "r", 1).int);
    const u16w = try mut(a, f, bin(.add, try col(a, "u"), try lit(a, iv(256))));
    try testing.expectEqual(ColumnType.uint16, ty(u16w, "r"));
    // A float literal: Float64 beside an integer.
    const sf = try mut(a, f, bin(.add, try col(a, "s"), try lit(a, fl(1.5))));
    try testing.expectEqual(ColumnType.float, ty(sf, "r"));
    // A UInt64 above maxInt(i64) is exact, and its sum past u64 is null.
    const w1 = try mut(a, f, bin(.add, try col(a, "w"), try lit(a, iv(1))));
    try testing.expectEqual(ColumnType.uint64, ty(w1, "r"));
    try testing.expectEqual(@as(i64, 2), cell(w1, "r", 0).int);
    try testing.expect(cell(w1, "r", 1) == .null);
    const wm = try mut(a, f, bin(.sub, try col(a, "w"), try lit(a, iv(1))));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64) - 1), cell(wm, "r", 1).uint);
    // Int8 beside 2^63: no integer type holds both here, Float64.
    const huge = try mut(a, f, bin(.add, try col(a, "s"), try lit(a, .{ .uint = 1 << 63 })));
    try testing.expectEqual(ColumnType.float, ty(huge, "r"));
    // A comparison is exact whatever the types.
    const eq = try mut(a, f, bin(.eq, try col(a, "w"), try lit(a, .{ .uint = std.math.maxInt(u64) })));
    try testing.expect(cell(eq, "r", 1).bool);
}

test "W11a Float32: operands and result are rounded to f32, a literal is weak" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "x", .float32, &.{ fl(1.0), nul, fl(3.4028234663852886e+38) } },
        .{ "i", .int8, &.{ iv(3), iv(3), iv(3) } },
        .{ "j", .int32, &.{ iv(3), iv(3), iv(3) } },
    });
    const g = try mut(a, f, bin(.add, try col(a, "x"), try lit(a, fl(0.1))));
    try testing.expectEqual(ColumnType.float32, ty(g, "r"));
    const want: f32 = 1.0 + @as(f32, 0.1);
    try testing.expectEqual(@as(f64, want), cell(g, "r", 0).float);
    try testing.expect(cell(g, "r", 1) == .null);
    const big = try mut(a, f, bin(.mul, try col(a, "x"), try lit(a, iv(2))));
    try testing.expect(std.math.isInf(cell(big, "r", 2).float)); // past f32: infinity, as polars
    // Float32 with Int8 is Float32, with Int32 Float64.
    try testing.expectEqual(ColumnType.float32, ty(try mut(a, f, bin(.add, try col(a, "x"), try col(a, "i"))), "r"));
    try testing.expectEqual(ColumnType.float, ty(try mut(a, f, bin(.add, try col(a, "x"), try col(a, "j"))), "r"));
    // Division: f32 / i8 is f32, i8 / f32 is f64 (polars is not symmetric).
    try testing.expectEqual(ColumnType.float32, ty(try mut(a, f, bin(.div, try col(a, "x"), try col(a, "i"))), "r"));
    try testing.expectEqual(ColumnType.float, ty(try mut(a, f, bin(.div, try col(a, "i"), try col(a, "x"))), "r"));
}

test "W11a Int64 with UInt64 is Float64, and a plain Int64 expression is unchanged" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s", .int, &.{ iv(-1), iv(5) } },
        .{ "w", .uint64, &.{ iv(1), .{ .uint = 1 << 63 } } },
    });
    const g = try mut(a, f, bin(.add, try col(a, "s"), try col(a, "w")));
    try testing.expectEqual(ColumnType.float, ty(g, "r"));
    try testing.expectEqual(@as(f64, 0), cell(g, "r", 0).float);
    const h = try mut(a, f, bin(.add, try col(a, "s"), try lit(a, iv(1))));
    try testing.expectEqual(ColumnType.int, ty(h, "r"));
    try testing.expectEqual(@as(i64, 0), cell(h, "r", 0).int);
}

test "W11a unary: neg of an unsigned column is an error, abs and neg keep the width, bit counts follow it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s", .int8, &.{ iv(-128), iv(5), nul, iv(-1) } },
        .{ "u", .uint8, &.{ iv(0), iv(5), nul, iv(255) } },
    });
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .unary = .{ .op = .neg, .x = try col(a, "u") } } }}));
    const ng = try mut(a, f, .{ .unary = .{ .op = .neg, .x = try col(a, "s") } });
    try testing.expectEqual(ColumnType.int8, ty(ng, "r"));
    try testing.expect(cell(ng, "r", 0) == .null); // 128: outside Int8
    try testing.expectEqual(@as(i64, -5), cell(ng, "r", 1).int);
    const ab = try mut(a, f, .{ .unary = .{ .op = .abs, .x = try col(a, "s") } });
    try testing.expectEqual(@as(i64, 1), cell(ab, "r", 3).int);
    const sg = try mut(a, f, .{ .unary = .{ .op = .sign, .x = try col(a, "s") } });
    try testing.expectEqual(ColumnType.int8, ty(sg, "r"));
    try testing.expectEqual(@as(i64, -1), cell(sg, "r", 0).int);
    // ~x of an unsigned byte stays in 0..255; the counts are those of eight bits.
    const bn = try mut(a, f, .{ .unary = .{ .op = .bit_not, .x = try col(a, "u") } });
    try testing.expectEqual(@as(i64, 255), cell(bn, "r", 0).int);
    try testing.expectEqual(@as(i64, 0), cell(bn, "r", 3).int);
    const ones = try mut(a, f, .{ .unary = .{ .op = .count_ones, .x = try col(a, "s") } });
    try testing.expectEqual(@as(i64, 1), cell(ones, "r", 0).int); // -128 = 0b1000_0000
    try testing.expectEqual(@as(i64, 8), cell(ones, "r", 3).int); // -1: all eight
    const lz = try mut(a, f, .{ .unary = .{ .op = .leading_zeros, .x = try col(a, "u") } });
    try testing.expectEqual(@as(i64, 8), cell(lz, "r", 0).int);
    try testing.expectEqual(@as(i64, 5), cell(lz, "r", 1).int);
}

test "W11a pow: an integer width keeps its type, a huge exponent is null and fast" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{.{ "s", .int8, &.{ iv(2), iv(-2), iv(1), iv(0), iv(-1), nul } }});
    const sq = try mut(a, f, bin(.pow, try col(a, "s"), try lit(a, iv(2))));
    try testing.expectEqual(ColumnType.int8, ty(sq, "r"));
    try testing.expectEqual(@as(i64, 4), cell(sq, "r", 0).int);
    const huge = try mut(a, f, bin(.pow, try col(a, "s"), try lit(a, iv(99))));
    try testing.expectEqual(ColumnType.int8, ty(huge, "r"));
    try testing.expect(cell(huge, "r", 0) == .null); // 2^99: past Int8
    try testing.expectEqual(@as(i64, 1), cell(huge, "r", 2).int);
    try testing.expectEqual(@as(i64, 0), cell(huge, "r", 3).int);
    try testing.expectEqual(@as(i64, -1), cell(huge, "r", 4).int); // (-1)^odd
    // An exponent of 2^31 - 1 on an Int32 column ends within 127 products, whatever it is.
    const g32 = try built(a, &.{.{ "s", .int32, &.{ iv(2), iv(-1), iv(0) } }});
    const h32 = try mut(a, g32, bin(.pow, try col(a, "s"), try lit(a, iv(std.math.maxInt(i32)))));
    try testing.expectEqual(ColumnType.int32, ty(h32, "r"));
    try testing.expect(cell(h32, "r", 0) == .null);
    try testing.expectEqual(@as(i64, -1), cell(h32, "r", 1).int);
    const neg = try mut(a, f, bin(.pow, try col(a, "s"), try lit(a, iv(-1))));
    try testing.expect(cell(neg, "r", 0) == .null); // no integer result
    const half = try mut(a, f, bin(.pow, try col(a, "s"), try lit(a, fl(0.5))));
    try testing.expectEqual(ColumnType.float, ty(half, "r"));
}

test "W11a mutate: an empty frame and an all-null result still carry the static type" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const empty = try built(a, &.{.{ "x", .int16, &.{} }});
    const g = try mut(a, empty, bin(.mul, try col(a, "x"), try lit(a, iv(2))));
    try testing.expectEqual(ColumnType.int16, ty(g, "r"));
    try testing.expectEqual(@as(usize, 0), g.len);
    const nulls = try built(a, &.{.{ "x", .uint32, &.{ nul, nul } }});
    const h = try mut(a, nulls, bin(.add, try col(a, "x"), try lit(a, iv(1))));
    try testing.expectEqual(ColumnType.uint32, ty(h, "r"));
    try testing.expect(cell(h, "r", 0) == .null);
    // A column carried over keeps its width.
    const c = try mut(a, nulls, .{ .col = "x" });
    try testing.expectEqual(ColumnType.uint32, ty(c, "r"));
}

test "W11a if_else and coalesce: the supertype of the branches, a literal weak" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "c", .bool, &.{ .{ .bool = true }, .{ .bool = false }, .{ .bool = false } } },
        .{ "s", .int8, &.{ iv(1), nul, iv(3) } },
        .{ "u", .uint8, &.{ iv(200), iv(201), nul } },
    });
    const w = try mut(a, f, .{ .if_else = .{ .cond = try col(a, "c"), .then = try col(a, "s"), .otherwise = try col(a, "u") } });
    try testing.expectEqual(ColumnType.int16, ty(w, "r"));
    try testing.expectEqual(@as(i64, 1), cell(w, "r", 0).int);
    try testing.expectEqual(@as(i64, 201), cell(w, "r", 1).int);
    const co = try mut(a, f, .{ .coalesce = &.{ .{ .col = "s" }, .{ .lit = iv(1000) } } });
    try testing.expectEqual(ColumnType.int16, ty(co, "r"));
    try testing.expectEqual(@as(i64, 1000), cell(co, "r", 1).int);
    // A literal that fits keeps the column's type.
    const small = try mut(a, f, .{ .coalesce = &.{ .{ .col = "s" }, .{ .lit = iv(7) } } });
    try testing.expectEqual(ColumnType.int8, ty(small, "r"));
}

test "W11a aggregate: polars' result types, exact sums, nulls and empty groups" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const big: u64 = (1 << 63) + 5;
    const f = try built(a, &.{
        .{ "k", .int, &.{ iv(1), iv(1), iv(2), iv(2), iv(3) } },
        .{ "s8", .int8, &.{ iv(127), iv(127), iv(-128), iv(3), nul } },
        .{ "s32", .int32, &.{ iv(std.math.maxInt(i32)), iv(1), iv(2), iv(3), nul } },
        .{ "u64", .uint64, &.{ .{ .uint = big }, iv(5), iv(1), iv(2), nul } },
        .{ "f32", .float32, &.{ fl(1.5), fl(2.5), fl(0.1), nul, nul } },
    });
    const g = try df.aggregate(a, f, .{
        .group_by = &.{"k"},
        .aggs = &.{
            .{ .src = "s8", .out = "s8", .func = .sum },
            .{ .src = "s32", .out = "s32", .func = .sum },
            .{ .src = "u64", .out = "u64", .func = .sum },
            .{ .src = "u64", .out = "u64max", .func = .max },
            .{ .src = "f32", .out = "f32sum", .func = .sum },
            .{ .src = "f32", .out = "f32mean", .func = .mean },
            .{ .src = "s8", .out = "s8mean", .func = .mean },
            .{ .src = "s8", .out = "s8min", .func = .min },
            .{ .src = "s8", .out = "s8prod", .func = .prod },
        },
        .skip_na = true,
    });
    try testing.expect(fm.widthsConform(g));
    try testing.expectEqual(ColumnType.int, ty(g, "s8")); // polars: Int8 sums are Int64
    try testing.expectEqual(@as(i64, 254), cell(g, "s8", 0).int);
    try testing.expectEqual(@as(i64, 0), cell(g, "s8", 2).int); // an all-null group: 0
    try testing.expectEqual(ColumnType.int32, ty(g, "s32"));
    try testing.expect(cell(g, "s32", 0) == .null); // 2^31: outside Int32, null where polars wraps
    try testing.expectEqual(@as(i64, 5), cell(g, "s32", 1).int);
    try testing.expectEqual(ColumnType.uint64, ty(g, "u64"));
    try testing.expectEqual(big + 5, cell(g, "u64", 0).uint); // exact past 2^53
    try testing.expectEqual(ColumnType.uint64, ty(g, "u64max"));
    try testing.expectEqual(big, cell(g, "u64max", 0).uint);
    try testing.expectEqual(ColumnType.float32, ty(g, "f32sum"));
    try testing.expectEqual(@as(f64, 4.0), cell(g, "f32sum", 0).float);
    try testing.expectEqual(@as(f64, @as(f32, 0.1)), cell(g, "f32sum", 1).float);
    try testing.expectEqual(ColumnType.float32, ty(g, "f32mean"));
    try testing.expectEqual(ColumnType.float, ty(g, "s8mean"));
    try testing.expectEqual(ColumnType.int8, ty(g, "s8min"));
    try testing.expectEqual(ColumnType.int, ty(g, "s8prod"));
    try testing.expectEqual(@as(i64, -384), cell(g, "s8prod", 1).int);
    // No rows: one row of the identities, typed.
    const e = try built(a, &.{.{ "x", .uint8, &.{} }});
    const ge = try df.aggregate(a, e, .{ .group_by = &.{}, .aggs = &.{.{ .src = "x", .out = "s", .func = .sum }}, .skip_na = true });
    try testing.expectEqual(ColumnType.int, ty(ge, "s"));
}

test "W11a window: cumulative and diff types, overflow kills the rest, shift keeps the width" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s8", .int8, &.{ iv(100), iv(100), nul, iv(-5) } },
        .{ "s32", .int32, &.{ iv(std.math.maxInt(i32)), iv(1), iv(-1), iv(5) } },
        .{ "u8", .uint8, &.{ iv(5), iv(3), nul, iv(255) } },
        .{ "f32", .float32, &.{ fl(0.1), fl(0.2), nul, fl(1) } },
    });
    const cs = try df.window(a, f, .{ .value_col = "s8", .out = "r", .op = .cum_sum });
    try testing.expect(fm.widthsConform(cs));
    try testing.expectEqual(ColumnType.int, ty(cs, "r"));
    try testing.expectEqual(@as(i64, 200), cell(cs, "r", 1).int);
    try testing.expect(cell(cs, "r", 2) == .null);
    try testing.expectEqual(@as(i64, 195), cell(cs, "r", 3).int);
    // Int32 keeps its type; past it the total is null and so is every later one.
    const c32 = try df.window(a, f, .{ .value_col = "s32", .out = "r", .op = .cum_sum });
    try testing.expectEqual(ColumnType.int32, ty(c32, "r"));
    try testing.expectEqual(@as(i64, std.math.maxInt(i32)), cell(c32, "r", 0).int);
    try testing.expect(cell(c32, "r", 1) == .null and cell(c32, "r", 3) == .null);
    // diff of an unsigned byte is Int16 and may be negative.
    const d = try df.window(a, f, .{ .value_col = "u8", .out = "r", .op = .{ .diff = 1 } });
    try testing.expectEqual(ColumnType.int16, ty(d, "r"));
    try testing.expect(cell(d, "r", 0) == .null);
    try testing.expectEqual(@as(i64, -2), cell(d, "r", 1).int);
    const cm = try df.window(a, f, .{ .value_col = "u8", .out = "r", .op = .cum_max });
    try testing.expectEqual(ColumnType.uint8, ty(cm, "r"));
    try testing.expectEqual(@as(i64, 255), cell(cm, "r", 3).int);
    // Float32: every result rounds to f32.
    const cf = try df.window(a, f, .{ .value_col = "f32", .out = "r", .op = .cum_sum });
    try testing.expectEqual(ColumnType.float32, ty(cf, "r"));
    const want: f32 = @as(f32, 0.1) + @as(f32, 0.2);
    try testing.expectEqual(@as(f64, want), cell(cf, "r", 1).float);
    // shift: the fill is cast to the width, a fraction promotes.
    const sh = try df.window(a, f, .{ .value_col = "s8", .out = "r", .op = .{ .shift = .{ .n = 1, .fill = iv(7) } } });
    try testing.expectEqual(ColumnType.int8, ty(sh, "r"));
    try testing.expectEqual(@as(i64, 7), cell(sh, "r", 0).int);
    const shf = try df.window(a, f, .{ .value_col = "s8", .out = "r", .op = .{ .shift = .{ .n = 1, .fill = fl(0.5) } } });
    try testing.expectEqual(ColumnType.float, ty(shf, "r"));
    // The partition's aggregate on every row.
    const tr = try df.window(a, f, .{ .value_col = "s8", .out = "r", .op = .{ .transform = .{ .func = .sum } } });
    try testing.expectEqual(ColumnType.int, ty(tr, "r"));
    try testing.expectEqual(@as(i64, 195), cell(tr, "r", 0).int);
}

test "W11a concat: pieces of other widths meet in the supertype" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const x = try built(a, &.{.{ "v", .int8, &.{ iv(-1), nul } }});
    const y = try built(a, &.{.{ "v", .uint8, &.{iv(255)} }});
    const g = try df.concatByName(a, &.{ x, y });
    try testing.expect(fm.widthsConform(g));
    try testing.expectEqual(ColumnType.int16, ty(g, "v"));
    try testing.expectEqual(@as(i64, 255), cell(g, "v", 2).int);
    try testing.expect(cell(g, "v", 1) == .null);
    // Int64 with UInt64: Float64. Int64 with Int64 is as before.
    const z = try built(a, &.{.{ "v", .uint64, &.{.{ .uint = std.math.maxInt(u64) }} }});
    const w = try built(a, &.{.{ "v", .int, &.{iv(-1)} }});
    const h = try df.concatByName(a, &.{ w, z });
    try testing.expectEqual(ColumnType.float, ty(h, "v"));
    try testing.expectEqual(@as(f64, -1), cell(h, "v", 0).float);
    // A width piece beside a missing column.
    const m = try df.concatByName(a, &.{ x, try built(a, &.{.{ "o", .int, &.{iv(1)} }}) });
    try testing.expectEqual(ColumnType.int8, ty(m, "v"));
    try testing.expect(cell(m, "v", 2) == .null);
}

test "W11a fill_null, clip, describe and the horizontal sum follow the width" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s", .int8, &.{ iv(1), nul, iv(5), iv(100) } },
        .{ "t", .int8, &.{ iv(1), iv(2), iv(3), iv(4) } },
        .{ "h", .float32, &.{ fl(0.5), nul, fl(1.5), fl(2) } },
    });
    const z = try df.fillNull(a, f, .{ .strategy = .zero, .subset = &.{"s"} });
    try testing.expect(fm.widthsConform(z));
    try testing.expectEqual(ColumnType.int8, ty(z, "s"));
    try testing.expectEqual(@as(i64, 0), cell(z, "s", 1).int);
    const mean = try df.fillNull(a, f, .{ .strategy = .mean, .subset = &.{"h"} });
    try testing.expectEqual(ColumnType.float32, ty(mean, "h"));
    try testing.expect(fm.widthsConform(mean));
    const cl = try df.clip(a, f, .{ .col = "s", .lower = 2, .upper = 50 });
    try testing.expectEqual(ColumnType.int8, ty(cl, "s"));
    try testing.expectEqual(@as(i64, 50), cell(cl, "s", 3).int);
    const cl2 = try df.clip(a, f, .{ .col = "s", .lower = 0, .upper = 1000 }); // 1000 is not an Int8
    try testing.expectEqual(ColumnType.float, ty(cl2, "s"));
    const ds = try df.describe(a, f, &.{});
    try testing.expectEqual(@as(usize, 4), ds.columns.len); // statistic, s, t, h
    const hz = try df.horizontal(a, f, .{ .func = .max, .cols = &.{ "s", "t" }, .out = "m" });
    try testing.expectEqual(ColumnType.int8, ty(hz, "m"));
    try testing.expect(fm.widthsConform(hz));
    try testing.expectEqual(@as(i64, 100), cell(hz, "m", 3).int);
}

test "W11a every width: aggregates of a column of nothing but nulls and of one row" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const widths = [_]ColumnType{ .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 };
    for (widths) |t| {
        const f = try built(a, &.{.{ "x", t, &.{nul} }});
        const one = try built(a, &.{.{ "x", t, &.{iv(3)} }});
        for ([_]df.AggFn{ .sum, .mean, .min, .max, .std, .median, .prod, .first, .last, .nunique }) |func| {
            const spec: df.AggregateSpec = .{ .group_by = &.{}, .aggs = &.{.{ .src = "x", .out = "r", .func = func }}, .skip_na = true };
            const g = try df.aggregate(a, f, spec);
            try testing.expect(fm.widthsConform(g));
            const g1 = try df.aggregate(a, one, spec);
            try testing.expect(fm.widthsConform(g1));
        }
    }
}

test "W11a a shared subexpression does not make the type walk exponential" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{.{ "x", .int8, &.{ iv(1), iv(2) } }});
    // e = x; e = e + e, 200 times: 2^200 paths through the tree, 200 nodes through the DAG.
    var e: *const df.Expr = try col(a, "x");
    for (0..200) |_| e = try bx(a, bin(.add, e, e));
    // The compiler's own budget refuses it (ExprTooLarge); what matters is that it returns.
    if (df.mutate(a, f, &.{.{ .out = "r", .expr = e.* }})) |g| {
        try testing.expect(fm.widthsConform(g));
    } else |err| try testing.expect(err == error.ExprTooLarge or err == error.TooLarge);
}

test "W11a corr, rolling, rank and ffill over widths" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s", .int8, &.{ iv(1), nul, iv(3), iv(5) } },
        .{ "u", .uint8, &.{ iv(2), iv(4), iv(6), iv(9) } },
        .{ "h", .float32, &.{ fl(0.1), fl(0.2), fl(0.4), fl(0.8) } },
    });
    const cr = try df.corr(a, f, .{});
    try testing.expectEqual(@as(usize, 4), cr.columns.len); // the label column and the three numbers
    const ro = try df.window(a, f, .{ .value_col = "h", .out = "r", .op = .{ .rolling = .{ .window = 2, .func = .mean } } });
    try testing.expectEqual(ColumnType.float32, ty(ro, "r"));
    try testing.expect(fm.widthsConform(ro));
    const rk = try df.window(a, f, .{ .value_col = "u", .out = "r", .op = .{ .rank = .{} } });
    try testing.expectEqual(ColumnType.float, ty(rk, "r"));
    const ff = try df.window(a, f, .{ .value_col = "s", .out = "r", .op = .{ .ffill = null } });
    try testing.expectEqual(ColumnType.int8, ty(ff, "r"));
    try testing.expect(fm.widthsConform(ff));
    try testing.expectEqual(@as(i64, 1), cell(ff, "r", 1).int);
}

test "W11a binning: cut and the bin verbs take a width column and keep it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, &.{
        .{ "s", .int8, &.{ iv(1), iv(5), iv(9), nul } },
        .{ "w", .uint64, &.{ iv(1), .{ .uint = std.math.maxInt(u64) }, iv(9), iv(2) } },
        .{ "h", .float32, &.{ fl(0.5), fl(1.5), fl(2.5), fl(3.5) } },
    });
    const c = try df.cut(a, f, .{ .col = "s", .out = "bin", .edges = &.{ 0, 4, 8, 12 }, .labels = &.{ "lo", "mid", "hi" } });
    try testing.expectEqual(ColumnType.int8, ty(c, "s"));
    try testing.expect(fm.widthsConform(c));
    try testing.expectEqualStrings("mid", cell(c, "bin", 1).text);
    try testing.expect(cell(c, "bin", 3) == .null);
    const bi = try df.binIntervals(a, f, .{ .col = "s", .out = "bin", .breaks = .{ .at = &.{ iv(4), iv(8) } } });
    try testing.expectEqual(ColumnType.int8, ty(bi, "s"));
    try testing.expect(fm.widthsConform(bi));
    try testing.expectEqual(@as(i64, 1), cell(bi, "bin", 1).int);
    const bq = try df.binQuantiles(a, f, .{ .col = "h", .out = "bin", .quantiles = .{ .count = 2 } });
    try testing.expectEqual(ColumnType.float32, ty(bq, "h"));
    try testing.expect(fm.widthsConform(bq));
    // A UInt64 above maxInt(i64) is missing for the binning, and the column is untouched.
    const bw = try df.binIntervals(a, f, .{ .col = "w", .out = "bin", .breaks = .{ .at = &.{iv(5)} } });
    try testing.expectEqual(ColumnType.uint64, ty(bw, "w"));
    try testing.expect(cell(bw, "bin", 1) == .null);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), cell(bw, "w", 1).uint);
}
