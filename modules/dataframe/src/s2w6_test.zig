// SPDX-License-Identifier: MIT
//! Dataframe S2 wave W6: the rest of the `list` and `struct` namespaces (`list_eval`,
//! `list_filter`, set operations, `gather`, `gather_every`, `shift`, `diff`, `item`,
//! `sample`, `repeat_by`, `to_struct`, the struct field operations, `explodeAll`,
//! `flattenList`, `structDtypes`) and ordered categoricals. Most expected values are the
//! ones polars 2.1 / pandas 3.1 answered on the same cells while the wave was written (the
//! replayed engine vectors are in `s2w6_oracle_test.zig`); where this module deliberately
//! differs the test says so.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const expr = @import("expr.zig");
const st = @import("structure_test.zig");
const Frame = df.Frame;
const Value = df.Value;
const Expr = df.Expr;

// ── helpers ─────────────────────────────────────────────────────────────────────

fn write(w: *std.Io.Writer, v: Value) std.Io.Writer.Error!void {
    switch (v) {
        .null => try w.writeAll("null"),
        .int => |i| try w.print("{d}", .{i}),
        .float => |x| try w.print("{d}", .{x}),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .decimal => |d| try w.print("d{d}", .{d}),
        .text => |t| try w.print("\"{s}\"", .{t}),
        .list => |l| {
            try w.writeByte('[');
            for (0..l.len()) |i| {
                if (i > 0) try w.writeByte(',');
                try write(w, l.get(i));
            }
            try w.writeByte(']');
        },
        .record => |r| {
            try w.writeByte('{');
            for (0..r.len()) |i| {
                if (i > 0) try w.writeByte(',');
                try w.print("{s}:", .{r.name(i)});
                try write(w, r.get(i));
            }
            try w.writeByte('}');
        },
    }
}

/// A cell as compact text: `[1,null]`, `{a:1,b:"x"}`.
fn show(a: std.mem.Allocator, v: Value) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    try write(&out.writer, v);
    return out.toOwnedSlice();
}

fn expectShown(a: std.mem.Allocator, want: []const []const u8, got: []const Value) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got, 0..) |w, g, i| {
        const s = try show(a, g);
        testing.expectEqualStrings(w, s) catch |e| {
            std.debug.print("row {d}\n", .{i});
            return e;
        };
    }
}

fn evalCol(a: std.mem.Allocator, f: Frame, e: Expr) ![]Value {
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
    const cells = try a.alloc(Value, out.len);
    for (cells, 0..) |*c, ri| c.* = out.cell(ri, "r").?;
    return cells;
}

const doc =
    \\[{"a":[1,2,2,3,null],"b":[3,4,3,null],"i":[0,2,-1],"j":[0],"x":[1,3,6,10],"y":[1],"v":1,"n":2},
    \\ {"a":[3,1,null],"b":[1,1,7],"i":[0,2,-1],"j":[1,5],"x":[5],"y":[],"v":null,"n":1},
    \\ {"a":[],"b":[1],"i":[0,2,-1],"j":[0],"x":[],"y":null,"v":3,"n":0},
    \\ {"a":null,"b":[1],"i":[0,2,-1],"j":[0],"x":null,"y":[2,3],"v":4,"n":null},
    \\ {"a":[5,5],"b":null,"i":[0,2,-1],"j":[0],"x":[1,null,4],"y":[7],"v":7,"n":1}]
;

fn load(a: std.mem.Allocator) !Frame {
    return df.readJson(a, doc, .{});
}

fn col(name: []const u8) Expr {
    return .{ .col = name };
}

fn lop(comptime name: []const u8, op: df.ListOp) Expr {
    return .{ .list = .{ .x = &.{ .col = name }, .op = op } };
}

// ── set operations ───────────────────────────────────────────────────────────────

test "list set operations: polars' order, duplicates once, null in either side is null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const ca = col("a");
    const cb = col("b");
    // polars 2.1 on the same rows.
    try expectShown(a, &.{ "[1,2,3,null,4]", "[3,1,null,7]", "[1]", "null", "null" }, try evalCol(a, f, .{ .list_set = .{ .x = &ca, .y = &cb, .op = .@"union" } }));
    try expectShown(a, &.{ "[3,null]", "[1]", "[]", "null", "null" }, try evalCol(a, f, .{ .list_set = .{ .x = &ca, .y = &cb, .op = .intersection } }));
    try expectShown(a, &.{ "[1,2]", "[3,null]", "[]", "null", "null" }, try evalCol(a, f, .{ .list_set = .{ .x = &ca, .y = &cb, .op = .difference } }));
    try expectShown(a, &.{ "[1,2,4]", "[3,null,7]", "[1]", "null", "null" }, try evalCol(a, f, .{ .list_set = .{ .x = &ca, .y = &cb, .op = .symmetric_difference } }));
    // The result keeps the source's element type.
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .list_set = .{ .x = &ca, .y = &cb, .op = .@"union" } } }});
    try testing.expectEqual(df.ColumnType.list, out.columnType("r").?);
}

// ── gather, gather_every, shift, diff, item, concat ──────────────────────────────

test "list gather, gather_every, shift, diff, item" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const ca = col("a");
    // gather by a list of positions; negative from the end; out of range null (polars null_on_oob).
    try expectShown(a, &.{ "[1,2,null]", "[3,null,null]", "[null,null,null]", "null", "[5,null,5]" }, try evalCol(a, f, .{ .list_gather = .{ .x = &ca, .idx = &col("i") } }));
    try expectShown(a, &.{ "[1]", "[1,null]", "[null]", "null", "[5]" }, try evalCol(a, f, .{ .list_gather = .{ .x = &ca, .idx = &col("j") } }));
    // One int position: a list of one.
    try expectShown(a, &.{ "[2]", "[1]", "[null]", "null", "[5]" }, try evalCol(a, f, .{ .list_gather = .{ .x = &ca, .idx = &.{ .lit = .{ .int = 1 } } } }));
    try expectShown(a, &.{ "[2,3]", "[1]", "[]", "null", "[5]" }, try evalCol(a, f, lop("a", .{ .gather_every = .{ .n = 2, .offset = 1 } })));
    try testing.expectError(error.BadExpr, evalCol(a, f, lop("a", .{ .gather_every = .{ .n = 0 } })));
    try expectShown(a, &.{ "[null,1,2,2,3]", "[null,3,1]", "[]", "null", "[null,5]" }, try evalCol(a, f, lop("a", .{ .shift = 1 })));
    try expectShown(a, &.{ "[2,3,null,null,null]", "[null,null,null]", "[]", "null", "[null,null]" }, try evalCol(a, f, lop("a", .{ .shift = -2 })));
    try expectShown(a, &.{ "[null,null,null,null,null]", "[null,null,null]", "[]", "null", "[null,null]" }, try evalCol(a, f, lop("a", .{ .shift = std.math.minInt(i64) })));
    // diff: n = 1 / 2, and null_behavior "drop".
    try expectShown(a, &.{ "[null,2,3,4]", "[null]", "[]", "null", "[null,null,null]" }, try evalCol(a, f, lop("x", .{ .diff = .{} })));
    try expectShown(a, &.{ "[null,null,5,7]", "[null]", "[]", "null", "[null,null,3]" }, try evalCol(a, f, lop("x", .{ .diff = .{ .n = 2 } })));
    try expectShown(a, &.{ "[2,3,4]", "[]", "[]", "null", "[null,null]" }, try evalCol(a, f, lop("x", .{ .diff = .{ .drop = true } })));
    // item: a list of one gives its element; empty, null, longer: null (polars raises on the last).
    try expectShown(a, &.{ "1", "null", "null", "null", "7" }, try evalCol(a, f, lop("y", .item)));
    // concat is `concat_list`: a null part is a null result (polars).
    try expectShown(a, &.{ "[1,2,2,3,null,3,4,3,null]", "[3,1,null,1,1,7]", "[1]", "null", "null" }, try evalCol(a, f, .{ .concat_list = &.{ col("a"), col("b") } }));
}

test "diff: overflow is null, decimal and float follow their kinds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"x\":[9223372036854775807,-5]},{\"x\":[3,4]}]", .{});
    const g = try df.mutate(a, f, &.{.{ .out = "r", .expr = lop("x", .{ .diff = .{} }) }});
    try testing.expectEqualStrings("[null,null]", try show(a, g.cell(0, "r").?)); // -5 - maxInt overflows
    try testing.expectEqualStrings("[null,1]", try show(a, g.cell(1, "r").?));
    const h = try df.readJson(a, "[{\"x\":[1.5,4.0]}]", .{});
    const k = try df.mutate(a, h, &.{.{ .out = "r", .expr = lop("x", .{ .diff = .{} }) }});
    try testing.expectEqualStrings("[null,2.5]", try show(a, k.cell(0, "r").?));
}

// ── repeat_by, to_struct, sample ─────────────────────────────────────────────────

test "repeat_by and to_struct follow polars" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    try expectShown(a, &.{ "[1,1]", "[null]", "[]", "null", "[7]" }, try evalCol(a, f, .{ .repeat_by = .{ .x = &col("v"), .by = &col("n") } }));
    const names: []const []const u8 = &.{ "p", "q" };
    try expectShown(a, &.{ "{p:1,q:3}", "{p:5,q:null}", "{p:null,q:null}", "null", "{p:1,q:null}" }, try evalCol(a, f, .{ .list_to_struct = .{ .x = &col("x"), .names = names } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .list_to_struct = .{ .x = &col("x"), .names = &.{ "p", "p" } } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .list_to_struct = .{ .x = &col("x"), .names = &.{} } }));
    // A count past the cap is refused, not built.
    const big = try df.readJson(a, "[{\"v\":1,\"n\":1000000000}]", .{});
    try testing.expectError(error.TooLarge, evalCol(a, big, .{ .repeat_by = .{ .x = &col("v"), .by = &col("n") } }));
}

test "list sample: size, membership, repeatable by seed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const e: Expr = .{ .list_sample = .{ .x = &col("a"), .n = 2, .seed = 42 } };
    const r1 = try evalCol(a, f, e);
    const r2 = try evalCol(a, f, e);
    for (r1, r2, 0..) |x, y, ri| {
        try testing.expectEqualStrings(try show(a, x), try show(a, y));
        if (ri == 3) {
            try testing.expect(x == .null);
            continue;
        }
        if (ri == 2) { // an empty list has nothing to draw
            try testing.expectEqual(@as(usize, 0), x.list.len());
            continue;
        }
        try testing.expectEqual(@as(usize, 2), x.list.len());
        // A subset (the source's rows hold distinct positions; elements may repeat in value).
        const src = f.cell(ri, "a").?.list;
        for (0..2) |k| {
            var hit = false;
            for (0..src.len()) |m| hit = hit or src.get(m).eql(x.list.get(k));
            try testing.expect(hit);
        }
    }
    // With replacement the count may exceed the length; fraction rounds.
    const w = try evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .n = 7, .with_replacement = true, .seed = 1 } });
    try testing.expectEqual(@as(usize, 7), w[0].list.len());
    const fr = try evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .fraction = 0.5, .seed = 1 } });
    try testing.expectEqual(@as(usize, 3), fr[0].list.len()); // round(5 * 0.5) = 3 (half away from zero)
    // Both n and fraction, or a negative fraction: BadExpr.
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .n = 1, .fraction = 0.5 } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .fraction = -1 } }));
    // More than the list holds, without replacement: a null cell (polars raises).
    const over = try evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .n = 9 } });
    try testing.expect(over[0] == .null);
}

// ── list.eval / list.filter ─────────────────────────────────────────────────────

const elem: Expr = .element;

test "list_eval and list_filter over pl.element(), list.agg as a composition" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const x = col("x");
    const times2: Expr = .{ .binary = .{ .op = .mul, .l = &elem, .r = &.{ .lit = .{ .int = 2 } } } };
    const gt2: Expr = .{ .binary = .{ .op = .gt, .l = &elem, .r = &.{ .lit = .{ .int = 2 } } } };
    // polars 2.1: list.eval(pl.element() * 2), list.filter(pl.element() > 2).
    try expectShown(a, &.{ "[2,6,12,20]", "[10]", "[]", "null", "[2,null,8]" }, try evalCol(a, f, .{ .list_eval = .{ .x = &x, .body = &times2 } }));
    try expectShown(a, &.{ "[3,6,10]", "[5]", "[]", "null", "[4]" }, try evalCol(a, f, .{ .list_filter = .{ .x = &x, .pred = &gt2 } }));
    // list.agg(pl.element().sum()) = list reduction of the mapped list: [20, 5, 0, null, 5].
    const mapped: Expr = .{ .list_eval = .{ .x = &x, .body = &elem } };
    try expectShown(a, &.{ "20", "5", "0", "null", "5" }, try evalCol(a, f, .{ .list = .{ .x = &mapped, .op = .sum } }));
    // A text body allocates per element: the evaluator's budget bounds it.
    const up: Expr = .{ .unary = .{ .op = .upper, .x = &elem } };
    const tf = try df.readJson(a, "[{\"t\":[\"ab\",null,\"c\"]},{\"t\":null}]", .{});
    try expectShown(a, &.{ "[\"AB\",null,\"C\"]", "null" }, try evalCol(a, tf, .{ .list_eval = .{ .x = &col("t"), .body = &up } }));
    // Elements of elements: the body may itself be a list op on an element that is a list.
    const nf = try df.readJson(a, "[{\"l\":[[1,2],[3],[]]},{\"l\":[]}]", .{});
    const inner: Expr = .{ .list = .{ .x = &elem, .op = .len } };
    try expectShown(a, &.{ "[2,1,0]", "[]" }, try evalCol(a, nf, .{ .list_eval = .{ .x = &col("l"), .body = &inner } }));
    // `.element` outside a list scope, and a column inside the body, are errors.
    try testing.expectError(error.BadExpr, evalCol(a, f, elem));
    try testing.expectError(error.NoSuchColumn, evalCol(a, f, .{ .list_eval = .{ .x = &x, .body = &col("v") } }));
}

test "list_eval is bounded by the evaluator's budget (a list of n elements is n bodies)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // One cell of 16 elements, each repeated to 1 MiB by the body: 16 MiB asked.
    const f = try df.readJson(a, "[{\"s\":[\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]}]", .{});
    const rep: Expr = .{ .binary = .{ .op = .repeat, .l = &elem, .r = &.{ .lit = .{ .int = 1 << 20 } } } };
    const e: Expr = .{ .list_eval = .{ .x = &col("s"), .body = &rep } };
    expr.test_hooks.eval_limit = 4 << 20;
    defer expr.test_hooks.eval_limit = null;
    try testing.expectError(error.TooLarge, evalCol(a, f, e));
    expr.test_hooks.eval_limit = 64 << 20;
    const ok = try evalCol(a, f, e);
    try testing.expectEqual(@as(usize, 16), ok[0].list.len());
    try testing.expectEqual(@as(usize, 1 << 20), ok[0].list.get(15).text.len);
    // The work bound too: the bodies' allocations are counted even though freed after the cell.
    expr.test_hooks.eval_limit = null;
    expr.test_hooks.eval_work_limit = 8 << 20;
    defer expr.test_hooks.eval_work_limit = null;
    try testing.expectError(error.TooLarge, evalCol(a, f, e));
}

// ── struct ──────────────────────────────────────────────────────────────────────

fn structFrame(a: std.mem.Allocator) !Frame {
    return df.readJson(a, "[{\"s\":{\"a\":1,\"b\":\"x\"}},{\"s\":{\"a\":2,\"b\":null}},{\"s\":null}]", .{});
}

fn sop(op: df.StructOp) Expr {
    return .{ .struct_op = .{ .x = &.{ .col = "s" }, .op = op } };
}

test "struct rename_fields, map_fields (prefix, suffix, case, replace) and drop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try structFrame(a);
    try expectShown(a, &.{ "{p:1,q:\"x\"}", "{p:2,q:null}", "null" }, try evalCol(a, f, sop(.{ .rename_fields = &.{ "p", "q" } })));
    // A count that is not the field count: null here, ShapeError in polars.
    try expectShown(a, &.{ "null", "null", "null" }, try evalCol(a, f, sop(.{ .rename_fields = &.{"p"} })));
    try testing.expectError(error.BadExpr, evalCol(a, f, sop(.{ .rename_fields = &.{ "p", "p" } })));
    try expectShown(a, &.{ "{f_a:1,f_b:\"x\"}", "{f_a:2,f_b:null}", "null" }, try evalCol(a, f, sop(.{ .map_fields = .{ .prefix = "f_" } })));
    try expectShown(a, &.{ "{a_z:1,b_z:\"x\"}", "{a_z:2,b_z:null}", "null" }, try evalCol(a, f, sop(.{ .map_fields = .{ .suffix = "_z" } })));
    try expectShown(a, &.{ "{A:1,B:\"x\"}", "{A:2,B:null}", "null" }, try evalCol(a, f, sop(.{ .map_fields = .upper })));
    try expectShown(a, &.{ "{a:1}", "{a:2}", "null" }, try evalCol(a, f, sop(.{ .drop = &.{ "b", "zzz" } })));
    // Two names that come out alike: a null cell (polars raises Duplicate).
    try expectShown(a, &.{ "null", "null", "null" }, try evalCol(a, f, sop(.{ .map_fields = .{ .replace = .{ .from = "b", .to = "a" } } })));
    try testing.expectError(error.BadExpr, evalCol(a, f, sop(.{ .map_fields = .{ .replace = .{ .from = "", .to = "a" } } })));
}

test "struct with_fields and eval run expressions over the record's fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try structFrame(a);
    const times10: Expr = .{ .binary = .{ .op = .mul, .l = &col("a"), .r = &.{ .lit = .{ .int = 10 } } } };
    const upper: Expr = .{ .unary = .{ .op = .upper, .x = &col("b") } };
    const plus1: Expr = .{ .binary = .{ .op = .add, .l = &col("a"), .r = &.{ .lit = .{ .int = 1 } } } };
    // polars 2.1: with_fields((a * 10).alias("c"), b.str.to_uppercase().alias("b")) replaces b in place
    // and appends c.
    try expectShown(a, &.{ "{a:1,b:\"X\",c:10}", "{a:2,b:null,c:20}", "null" }, try evalCol(a, f, .{ .struct_fields = .{ .x = &col("s"), .fields = &.{ .{ .name = "c", .x = times10 }, .{ .name = "b", .x = upper } } } }));
    // struct.eval(a + 1) is a struct of just that field.
    try expectShown(a, &.{ "{a:2}", "{a:3}", "null" }, try evalCol(a, f, .{ .struct_fields = .{ .x = &col("s"), .fields = &.{.{ .name = "a", .x = plus1 }}, .keep = false } }));
    // A column that is not a struct, an unknown field, a name twice, nothing to evaluate.
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .struct_fields = .{ .x = &.{ .lit = .{ .int = 1 } }, .fields = &.{.{ .name = "a", .x = plus1 }} } }));
    try testing.expectError(error.NoSuchColumn, evalCol(a, f, .{ .struct_fields = .{ .x = &col("s"), .fields = &.{.{ .name = "z", .x = col("nope") }} } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .struct_fields = .{ .x = &col("s"), .fields = &.{ .{ .name = "z", .x = plus1 }, .{ .name = "z", .x = plus1 } } } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .struct_fields = .{ .x = &col("s"), .fields = &.{}, .keep = false } }));
}

// ── frame verbs ─────────────────────────────────────────────────────────────────

test "explodeAll, flattenList, structDtypes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"k\":1,\"p\":[1,2],\"q\":[\"a\",\"b\"]},{\"k\":2,\"p\":null,\"q\":[]},{\"k\":3,\"p\":[7],\"q\":[\"z\"]}]", .{});
    const e = try df.explodeAll(a, f);
    try testing.expectEqual(@as(usize, 4), e.len);
    try st.expectCol(e, "k", &.{ .{ .int = 1 }, .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } });
    try st.expectCol(e, "p", &.{ .{ .int = 1 }, .{ .int = 2 }, .null, .{ .int = 7 } });
    try st.expectCol(e, "q", &.{ .{ .text = "a" }, .{ .text = "b" }, .null, .{ .text = "z" } });
    // Lists of different lengths on a row cannot explode together.
    const bad = try df.readJson(a, "[{\"p\":[1,2],\"q\":[\"a\"]}]", .{});
    try testing.expectError(error.LengthMismatch, df.explodeAll(a, bad));
    // No list column: the frame as it is.
    const plain = try df.readJson(a, "[{\"k\":1}]", .{});
    try testing.expectEqual(@as(usize, 1), (try df.explodeAll(a, plain)).len);

    // pandas Series.list.flatten: [1,2], null, [7] -> 1,2,7 (null lists contribute nothing).
    const fl = try df.flattenList(a, f, "p");
    try testing.expectEqual(@as(usize, 3), fl.len);
    try st.expectCol(fl, "p", &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 7 } });
    try testing.expectEqual(df.ColumnType.int, fl.columnType("p").?);
    try testing.expectError(error.NotNested, df.flattenList(a, f, "k"));
    try testing.expectError(error.NoSuchColumn, df.flattenList(a, f, "nope"));

    // pandas Series.struct.dtypes.
    const sf = try structFrame(a);
    const dt = try df.structDtypes(a, sf, "s");
    try testing.expectEqual(@as(usize, 2), dt.len);
    try testing.expectEqualStrings("a", dt[0].name);
    try testing.expectEqual(df.ColumnType.int, dt[0].type);
    try testing.expectEqualStrings("b", dt[1].name);
    try testing.expectEqual(df.ColumnType.text, dt[1].type);
    try testing.expectError(error.NotNested, df.structDtypes(a, f, "k"));
}

// ── ordered categoricals ────────────────────────────────────────────────────────

fn txt(s: []const u8) Value {
    return .{ .text = s };
}

fn int(i: i64) Value {
    return .{ .int = i };
}

/// Text column "s" holding `vals`, cast to a categorical with `cats` in that order (polars
/// `Enum(cats)` / pandas `CategoricalDtype(cats, ordered)`).
fn catFrame(a: std.mem.Allocator, vals: []const Value, cats: ?[]const []const u8, ordered: bool) !Frame {
    const rows = try a.alloc([]const Value, vals.len);
    for (rows, vals) |*r, v| {
        const cell = try a.alloc(Value, 1);
        cell[0] = v;
        r.* = cell;
    }
    const raw = try st.mk(a, &.{.{ .name = "s", .type = .text }}, rows);
    return df.cast(a, raw, .{ .col = "s", .to = .categorical, .categories = cats, .ordered = ordered });
}

fn expectCats(a: std.mem.Allocator, want: []const []const u8, f: Frame) !void {
    const got = try df.catCategories(a, f, "s");
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualStrings(w, g);
}

const enum_vals = [_]Value{ txt("mid"), txt("low"), .null, txt("high"), txt("low") };
const lmh: []const []const u8 = &.{ "low", "mid", "high" };

test "Enum: cast with a category list keeps the list's order and unused categories" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try catFrame(a, &enum_vals, &.{ "low", "mid", "high", "unused" }, true);
    try expectCats(a, &.{ "low", "mid", "high", "unused" }, f);
    try testing.expect(try df.catIsOrdered(a, f, "s"));
    try st.expectCol(f, "s", &enum_vals);
    // polars `to_physical()`: [1, 0, null, 2, 0]; pandas `cat.codes` writes -1 for the null.
    const p = try df.catCodes(a, f, "s");
    try testing.expectEqual(df.ColumnType.int, p.columnType("s").?);
    try st.expectCol(p, "s", &.{ int(1), int(0), .null, int(2), int(0) });
    // A value outside the list: null (polars strict=False, pandas astype), CastFailed with .fail (polars strict).
    const raw = try st.mk(a, &.{.{ .name = "s", .type = .text }}, &.{ &.{txt("mid")}, &.{txt("zzz")} });
    const lax = try df.cast(a, raw, .{ .col = "s", .to = .categorical, .categories = lmh });
    try st.expectCol(lax, "s", &.{ txt("mid"), .null });
    try testing.expectError(error.CastFailed, df.cast(a, raw, .{ .col = "s", .to = .categorical, .categories = lmh, .on_error = .fail }));
    // A category twice, or a list for another target type: BadExpr.
    try testing.expectError(error.BadExpr, df.cast(a, raw, .{ .col = "s", .to = .categorical, .categories = &.{ "a", "a" } }));
    try testing.expectError(error.BadExpr, df.cast(a, raw, .{ .col = "s", .to = .text, .categories = lmh }));
    // Without a list `ordered` flags the observed lexical dictionary (pandas ordered=True, categories inferred).
    const g = try catFrame(a, &enum_vals, null, true);
    try expectCats(a, &.{ "high", "low", "mid" }, g);
    try testing.expect(try df.catIsOrdered(a, g, "s"));
}

test "Enum: sort, comparison and take follow the category order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try catFrame(a, &enum_vals, lmh, true);
    // polars: sort -> [null, low, low, mid, high]; descending -> [null, high, mid, low, low].
    const up = try df.sort(a, f, .{ .key = "s", .missing = .first });
    try st.expectCol(up, "s", &.{ .null, txt("low"), txt("low"), txt("mid"), txt("high") });
    const down = try df.sort(a, f, .{ .key = "s", .dir = .desc, .missing = .first });
    try st.expectCol(down, "s", &.{ .null, txt("high"), txt("mid"), txt("low"), txt("low") });
    // The ordered flag and the dictionary survive the gather.
    try testing.expect(up.column("s").?.categorical.ordered);
    try expectCats(a, &.{ "low", "mid", "high" }, up);
    // polars `s < "high"`, `s > "low"`.
    try expectShown(a, &.{ "true", "true", "null", "false", "true" }, try evalCol(a, f, .{ .binary = .{ .op = .lt, .l = &col("s"), .r = &.{ .lit = txt("high") } } }));
    try expectShown(a, &.{ "true", "false", "null", "true", "false" }, try evalCol(a, f, .{ .binary = .{ .op = .gt, .l = &col("s"), .r = &.{ .lit = txt("low") } } }));
    // The literal on the left, and two columns of the same dictionary.
    try expectShown(a, &.{ "true", "true", "null", "false", "true" }, try evalCol(a, f, .{ .binary = .{ .op = .ge, .l = &.{ .lit = txt("mid") }, .r = &col("s") } }));
    try expectShown(a, &.{ "true", "true", "null", "true", "true" }, try evalCol(a, f, .{ .binary = .{ .op = .le, .l = &col("s"), .r = &col("s") } }));
    // Equality is unchanged (text), a text that is no category in an order comparison is an error
    // (polars InvalidOperationError, pandas TypeError).
    try expectShown(a, &.{ "true", "false", "null", "false", "false" }, try evalCol(a, f, .{ .binary = .{ .op = .eq, .l = &col("s"), .r = &.{ .lit = txt("mid") } } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .binary = .{ .op = .lt, .l = &col("s"), .r = &.{ .lit = txt("zzz") } } }));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .binary = .{ .op = .lt, .l = &col("s"), .r = &.{ .lit = int(1) } } }));
    // `where` keeps the rows the order comparison selects.
    const kept = try df.where(a, f, &.{ .binary = .{ .op = .lt, .l = &col("s"), .r = &.{ .lit = txt("high") } } });
    try st.expectCol(kept, "s", &.{ txt("mid"), txt("low"), txt("low") });
    // An unordered categorical still compares as text.
    const u = try catFrame(a, &enum_vals, lmh, false);
    try expectShown(a, &.{ "true", "false", "null", "false", "false" }, try evalCol(a, u, .{ .binary = .{ .op = .gt, .l = &col("s"), .r = &.{ .lit = txt("low") } } }));
    // pandas sorts an unordered categorical with a custom category order by its codes too.
    const v = try catFrame(a, &.{ txt("a"), txt("b"), txt("c"), txt("a") }, &.{ "c", "b", "a" }, false);
    try st.expectCol(try df.sort(a, v, .{ .key = "s" }), "s", &.{ txt("c"), txt("b"), txt("a"), txt("a") });
}

test "is_between and fold comparisons use the order of an ordered categorical (review fix)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sml: []const []const u8 = &.{ "S", "M", "L" };
    const f = try catFrame(a, &.{ txt("M"), txt("S"), txt("L") }, sml, true);
    // Lexically "M" is not between "S" and "L"; by the categories' order it is.
    try expectShown(a, &.{ "true", "true", "true" }, try evalCol(a, f, .{ .is_between = .{ .x = &col("s"), .lower = &.{ .lit = txt("S") }, .upper = &.{ .lit = txt("L") } } }));
    try expectShown(a, &.{ "true", "false", "false" }, try evalCol(a, f, .{ .is_between = .{ .x = &col("s"), .lower = &.{ .lit = txt("M") }, .upper = &.{ .lit = txt("M") } } }));
    // fold: s >= "M" is true, false, true (lexically the S row would be true).
    try expectShown(a, &.{ "true", "false", "true" }, try evalCol(a, f, .{ .fold = .{ .op = .ge, .parts = &.{ col("s"), .{ .lit = txt("M") } } } }));
    // cast: `ordered` without a categorical target is refused like `categories`.
    try testing.expectError(error.BadExpr, df.cast(a, f, .{ .col = "s", .to = .int, .ordered = true }));
}

test "list_eval over a list of zoned timestamps keeps the element's zone (review fix)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try df.readJson(a, "[{\"l\":[1721044800000000]}]", .{}); // 2024-07-15T12:00:00Z
    f.columns = try a.dupe(df.Column, &.{.{ .name = "l", .type = .list, .inner = &.{.{ .name = "", .type = .timestamp, .time_zone = "Europe/Prague" }} }});
    const hour: Expr = .{ .dt = .{ .x = &elem, .part = .hour } };
    try expectShown(a, &.{"[14]"}, try evalCol(a, f, .{ .list_eval = .{ .x = &col("l"), .body = &hour } }));
}

test "cat verbs: add, remove, remove_unused, set, reorder, rename, as_ordered (pandas Series.cat)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // pandas 3.1: Series(["a","b","c","a"], dtype="category") -> categories a, b, c.
    const f = try catFrame(a, &.{ txt("a"), txt("b"), txt("c"), txt("a") }, null, false);
    try expectCats(a, &.{ "a", "b", "c" }, f);
    try testing.expect(!(try df.catIsOrdered(a, f, "s")));

    const added = try df.catAddCategories(a, f, "s", &.{"z"});
    try expectCats(a, &.{ "a", "b", "c", "z" }, added);
    try st.expectCol(added, "s", &.{ txt("a"), txt("b"), txt("c"), txt("a") });
    try testing.expectError(error.BadCategories, df.catAddCategories(a, f, "s", &.{"a"}));
    try testing.expectError(error.BadCategories, df.catAddCategories(a, f, "s", &.{ "z", "z" }));

    const removed = try df.catRemoveCategories(a, f, "s", &.{"b"});
    try expectCats(a, &.{ "a", "c" }, removed);
    try st.expectCol(removed, "s", &.{ txt("a"), .null, txt("c"), txt("a") });
    try testing.expectError(error.BadCategories, df.catRemoveCategories(a, f, "s", &.{"nope"}));

    const unused = try df.catRemoveUnusedCategories(a, added, "s");
    try expectCats(a, &.{ "a", "b", "c" }, unused);

    // set_categories(["c","a","q"]): ['a', NaN, 'c', 'a'], codes [1, -1, 0, 1].
    const set = try df.catSetCategories(a, f, "s", &.{ "c", "a", "q" }, null);
    try expectCats(a, &.{ "c", "a", "q" }, set);
    try st.expectCol(set, "s", &.{ txt("a"), .null, txt("c"), txt("a") });
    try st.expectCol(try df.catCodes(a, set, "s"), "s", &.{ int(1), .null, int(0), int(1) });
    try testing.expect(try df.catIsOrdered(a, try df.catSetCategories(a, f, "s", &.{ "c", "a" }, true), "s"));

    // reorder_categories(["c","b","a"]): codes [2, 1, 0, 2]; must be a permutation.
    const re = try df.catReorderCategories(a, f, "s", &.{ "c", "b", "a" }, true);
    try expectCats(a, &.{ "c", "b", "a" }, re);
    try st.expectCol(try df.catCodes(a, re, "s"), "s", &.{ int(2), int(1), int(0), int(2) });
    try testing.expect(try df.catIsOrdered(a, re, "s"));
    try testing.expectError(error.BadCategories, df.catReorderCategories(a, f, "s", &.{ "a", "b" }, null));
    try testing.expectError(error.BadCategories, df.catReorderCategories(a, f, "s", &.{ "a", "b", "x" }, null));

    // rename_categories: a mapping (a -> A) and a list; the count and the uniqueness are checked.
    const m = try df.catRenameCategories(a, f, "s", .{ .map = &.{.{ "a", "A" }} });
    try st.expectCol(m, "s", &.{ txt("A"), txt("b"), txt("c"), txt("A") });
    const l = try df.catRenameCategories(a, f, "s", .{ .list = &.{ "x", "y", "z" } });
    try st.expectCol(l, "s", &.{ txt("x"), txt("y"), txt("z"), txt("x") });
    try testing.expectError(error.BadCategories, df.catRenameCategories(a, f, "s", .{ .list = &.{ "x", "y" } }));
    try testing.expectError(error.BadCategories, df.catRenameCategories(a, f, "s", .{ .list = &.{ "x", "x", "z" } }));

    // as_ordered / as_unordered.
    const o = try df.catSetOrdered(a, f, "s", true);
    try testing.expect(try df.catIsOrdered(a, o, "s"));
    try testing.expect(!(try df.catIsOrdered(a, try df.catSetOrdered(a, o, "s", false), "s")));

    // A column that is not categorical, and one that does not exist.
    const t = try st.mk(a, &.{.{ .name = "s", .type = .text }}, &.{&.{txt("a")}});
    try testing.expectError(error.NotCategorical, df.catCodes(a, t, "s"));
    try testing.expectError(error.NoSuchColumn, df.catCodes(a, t, "q"));
    // A column declared categorical but stored as text is encoded on the way (lexical).
    const decl = try st.mk(a, &.{.{ .name = "s", .type = .categorical }}, &.{ &.{txt("b")}, &.{txt("a")} });
    try expectCats(a, &.{ "a", "b" }, decl);
}

test "concat of equal ordered categoricals keeps the dictionary; unequal ones encode again" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const x = try catFrame(a, &.{ txt("mid"), .null }, lmh, true);
    const y = try catFrame(a, &.{txt("low")}, lmh, true);
    const both = try df.concatByName(a, &.{ x, y });
    try expectCats(a, &.{ "low", "mid", "high" }, both);
    try testing.expect(try df.catIsOrdered(a, both, "s"));
    try st.expectCol(both, "s", &.{ txt("mid"), .null, txt("low") });
    const z = try catFrame(a, &.{txt("hi")}, &.{ "hi", "lo" }, true);
    const mixed = try df.concatByName(a, &.{ x, z });
    try st.expectCol(mixed, "s", &.{ txt("mid"), .null, txt("hi") });
    try expectCats(a, &.{ "hi", "mid" }, mixed); // re-encoded: lexical, unordered
    try testing.expect(!(try df.catIsOrdered(a, mixed, "s")));
}

test "list sample: an infinite fraction is BadExpr; a draw past the length is null before allocating (review fix)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"a\":[]},{\"a\":[1,2]}]", .{});
    // len * inf is NaN for the empty list: refused when compiled, never cast.
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .fraction = std.math.inf(f64) } }));
    const big = try evalCol(a, f, .{ .list_sample = .{ .x = &col("a"), .n = 1 << 24, .seed = 1 } });
    try testing.expectEqual(@as(usize, 0), big[0].list.len());
    try testing.expect(big[1] == .null);
}

test "join: a coalesced categorical key keeps its dictionary and sorts by category (review fix)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The same Enum on both sides: a right-only row's key takes its right code; sorted by the
    // category order low < high (lexically "high" < "low").
    const l = try catFrame(a, &.{txt("low")}, lmh, true);
    const r = try catFrame(a, &.{txt("high")}, lmh, true);
    for ([_]df.JoinSpec{
        .{ .on = "s", .how = .full, .sort = true },
        .{ .on = "s", .how = .full, .sort = true, .coalesce_keys = true },
    }) |spec| {
        const j = try df.join(a, l, r, spec);
        const kc = j.columnAt(j.columnIndex("s").?);
        try testing.expect(kc == .categorical);
        try testing.expect(kc.categorical.ordered);
        try testing.expectEqualStrings("low", kc.get(0).text);
        try testing.expectEqualStrings("high", kc.get(1).text);
        try expectCats(a, lmh, j);
    }
    // Different dictionaries: the union is encoded again (lexical, as concat does), and the
    // storage stays categorical, as the column's declared type says.
    const r2 = try catFrame(a, &.{txt("high")}, null, false);
    const j2 = try df.join(a, l, r2, .{ .on = "s", .how = .full, .coalesce_keys = true });
    const k2 = j2.columnAt(j2.columnIndex("s").?);
    try testing.expect(k2 == .categorical);
    try testing.expectEqual(df.ColumnType.categorical, j2.columns[j2.columnIndex("s").?].type);
    try testing.expectEqualStrings("low", k2.get(0).text);
    try testing.expectEqualStrings("high", k2.get(1).text);
    // Kept right keys (polars `coalesce=False`): `sort` no longer fills the left key of a
    // right-only row; it sorts last, and the right key holds the value.
    const j3 = try df.join(a, l, r, .{ .on = "s", .how = .full, .sort = true, .keep_right_keys = true });
    const k3 = j3.columnAt(j3.columnIndex("s").?);
    const r3 = j3.columnAt(j3.columnIndex("s_right").?);
    try testing.expectEqual(@as(usize, 2), j3.len);
    try testing.expectEqualStrings("low", k3.get(0).text);
    try testing.expect(k3.get(1) == .null);
    try testing.expectEqualStrings("high", r3.get(1).text);
}

test "min and max of an ordered categorical follow the category order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try st.mk(a, &.{ .{ .name = "g", .type = .text }, .{ .name = "s", .type = .text } }, &.{
        &.{ txt("a"), txt("mid") }, &.{ txt("a"), txt("low") }, &.{ txt("b"), txt("high") }, &.{ txt("b"), .null }, &.{ txt("c"), .null },
    });
    const f = try df.cast(a, raw, .{ .col = "s", .to = .categorical, .categories = lmh, .ordered = true });
    const aggs: []const df.AggCol = &.{ .{ .src = "s", .out = "lo", .func = .min }, .{ .src = "s", .out = "hi", .func = .max }, .{ .src = "s", .out = "at", .func = .arg_max } };
    const g = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = aggs, .skip_na = true });
    // pandas / polars: the least by category order ("low" < "mid" < "high"), nulls skipped.
    try st.expectCol(g, "lo", &.{ txt("low"), txt("high"), .null });
    try st.expectCol(g, "hi", &.{ txt("mid"), txt("high"), .null });
    try st.expectCol(g, "at", &.{ int(0), int(2), .null }); // arg_max: the row in the frame
    try testing.expectEqual(df.ColumnType.categorical, g.columnType("hi").?);
    try testing.expect(g.column("hi").?.categorical.ordered);
    // Unordered: the text order, as before (pandas refuses, polars' Categorical is lexical).
    const u = try df.cast(a, raw, .{ .col = "s", .to = .categorical, .categories = lmh });
    const h = try df.aggregate(a, u, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "s", .out = "lo", .func = .min }}, .skip_na = true });
    try st.expectCol(h, "lo", &.{ txt("low"), txt("high"), .null });
    try testing.expect(h.columnType("lo").? == .categorical or h.columnType("lo").? == .text);
}

test "readers: a column declared with a category list is checked against it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const decl: []const df.EnumDecl = &.{.{ .name = "s", .categories = lmh }};
    const f = try df.readCsv(a, "s,n\nmid,1\nlow,2\n,3\n", .{ .enums = decl });
    try testing.expectEqual(df.ColumnType.categorical, f.columnType("s").?);
    try expectCats(a, lmh, f);
    try testing.expect(try df.catIsOrdered(a, f, "s"));
    try st.expectCol(f, "s", &.{ txt("mid"), txt("low"), .null });
    // The values are matched as text whatever they look like.
    const digits = try df.readCsv(a, "s\n10\n9\n", .{ .enums = &.{.{ .name = "s", .categories = &.{ "9", "10" }, .ordered = false }} });
    try st.expectCol(digits, "s", &.{ txt("10"), txt("9") });
    try testing.expect(!(try df.catIsOrdered(a, digits, "s")));
    // polars raises on a value outside the list.
    try testing.expectError(error.BadValue, df.readCsv(a, "s\nmid\nzzz\n", .{ .enums = decl }));
    const j = try df.readJson(a, "[{\"s\":\"high\"},{\"s\":null}]", .{ .enums = decl });
    try st.expectCol(j, "s", &.{ txt("high"), .null });
    try testing.expectError(error.BadValue, df.readJson(a, "[{\"s\":\"zzz\"}]", .{ .enums = decl }));
    const nd = try df.readNdjson(a, "{\"s\":\"low\"}\n{\"s\":\"mid\"}\n", .{ .enums = decl });
    try st.expectCol(try df.catCodes(a, nd, "s"), "s", &.{ int(0), int(1) });
    // A name that is no column is `NoSuchColumn`, as for `types`; a category twice is an error.
    try testing.expectError(error.NoSuchColumn, df.readCsv(a, "s\nmid\n", .{ .enums = &.{.{ .name = "nope", .categories = lmh }} }));
    try testing.expectError(error.BadValue, df.readCsv(a, "s\nmid\n", .{ .enums = &.{.{ .name = "s", .categories = &.{ "mid", "mid" } }} }));
}
