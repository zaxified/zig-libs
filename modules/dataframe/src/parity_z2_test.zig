// SPDX-License-Identifier: MIT
//! dataframe parity close (2026-11-10), agent Z2: aggregations and order-dependent operations
//! over a list's own elements inside `list.eval` / `list.filter` (`Expr.element_op`, polars
//! `pl.element().sum()`, `.rank()`, `.cum_sum()`, ...). Every expected value was answered by
//! polars 2.1 (`list.eval(<expr>)` on the same lists); the probe script and its output are
//! in the agent's notes. Where this module differs the test says so.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const expr = @import("expr.zig");
const lf = @import("listfn.zig");
const Frame = df.Frame;
const Value = df.Value;
const Expr = df.Expr;

fn write(w: *std.Io.Writer, v: Value) std.Io.Writer.Error!void {
    switch (v) {
        .null => try w.writeAll("null"),
        .int => |i| try w.print("{d}", .{i}),
        .uint => |u| try w.print("{d}", .{u}),
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
        .record => try w.writeAll("{record}"),
    }
}

fn expectShown(a: std.mem.Allocator, want: []const []const u8, got: []const Value) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got, 0..) |w, g, i| {
        var out: std.Io.Writer.Allocating = .init(a);
        try write(&out.writer, g);
        testing.expectEqualStrings(w, out.written()) catch |e| {
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

const elem: Expr = .element;
const lcol: Expr = .{ .col = "l" };

fn eo(op: df.ElemOp) Expr {
    return .{ .element_op = .{ .x = &elem, .op = op } };
}

/// `list.eval(body)` of column `l`.
fn evalBody(a: std.mem.Allocator, f: Frame, body: Expr) ![]Value {
    return evalCol(a, f, .{ .list_eval = .{ .x = &lcol, .body = &body } });
}

fn check(a: std.mem.Allocator, f: Frame, op: df.ElemOp, want: []const []const u8) !void {
    try expectShown(a, want, try evalBody(a, f, eo(op)));
}

/// polars 2.1: pl.DataFrame({"l": [[1,2,3],[],[None,None],None,[4,None,6],[3,1,3,2]]}).
const int_doc =
    \\[{"l":[1,2,3]},{"l":[]},{"l":[null,null]},{"l":null},{"l":[4,null,6]},{"l":[3,1,3,2]}]
;

test "element aggregations give one element per list (polars list.eval(pl.element().sum()) ...)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, int_doc, .{});
    try check(a, f, .sum, &.{ "[6]", "[0]", "[0]", "null", "[10]", "[9]" });
    try check(a, f, .mean, &.{ "[2]", "[null]", "[null]", "null", "[5]", "[2.25]" });
    try check(a, f, .median, &.{ "[2]", "[null]", "[null]", "null", "[5]", "[2.5]" });
    try check(a, f, .min, &.{ "[1]", "[null]", "[null]", "null", "[4]", "[1]" });
    try check(a, f, .max, &.{ "[3]", "[null]", "[null]", "null", "[6]", "[3]" });
    try check(a, f, .count, &.{ "[3]", "[0]", "[0]", "null", "[2]", "[4]" });
    try check(a, f, .len, &.{ "[3]", "[0]", "[2]", "null", "[3]", "[4]" });
    try check(a, f, .n_unique, &.{ "[3]", "[0]", "[1]", "null", "[3]", "[3]" });
    try check(a, f, .first, &.{ "[1]", "[null]", "[null]", "null", "[4]", "[3]" });
    try check(a, f, .last, &.{ "[3]", "[null]", "[null]", "null", "[6]", "[2]" });
    try check(a, f, .{ .std = 1 }, &.{ "[1]", "[null]", "[null]", "null", "[1.4142135623730951]", "[0.9574271077563381]" });
    try check(a, f, .{ .std = 0 }, &.{ "[0.816496580927726]", "[null]", "[null]", "null", "[1]", "[0.82915619758885]" });
    try check(a, f, .{ .@"var" = 1 }, &.{ "[1]", "[null]", "[null]", "null", "[2]", "[0.9166666666666666]" });
    try check(a, f, .{ .@"var" = 0 }, &.{ "[0.6666666666666666]", "[null]", "[null]", "null", "[1]", "[0.6875]" });
    // polars quantile(0.3, "linear") and ("nearest").
    try check(a, f, .{ .quantile = .{ .q = 0.3, .interpolation = .linear } }, &.{ "[1.6]", "[null]", "[null]", "null", "[4.6]", "[1.9]" });
    try check(a, f, .{ .quantile = .{ .q = 0.3, .interpolation = .nearest } }, &.{ "[2]", "[null]", "[null]", "null", "[4]", "[2]" });
    try check(a, f, .arg_min, &.{ "[0]", "[null]", "[null]", "null", "[0]", "[1]" });
    try check(a, f, .arg_max, &.{ "[2]", "[null]", "[null]", "null", "[2]", "[0]" });
}

test "element order-dependent operations keep the list's length (polars rank, cum_*, diff, shift, ...)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, int_doc, .{});
    try check(a, f, .{ .rank = .{} }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[1,null,2]", "[3.5,1,3.5,2]" });
    try check(a, f, .{ .rank = .{ .method = .min } }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[1,null,2]", "[3,1,3,2]" });
    try check(a, f, .{ .rank = .{ .method = .max } }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[1,null,2]", "[4,1,4,2]" });
    try check(a, f, .{ .rank = .{ .method = .dense } }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[1,null,2]", "[3,1,3,2]" });
    try check(a, f, .{ .rank = .{ .method = .first } }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[1,null,2]", "[3,1,4,2]" }); // polars "ordinal"
    try check(a, f, .{ .rank = .{ .descending = true } }, &.{ "[3,2,1]", "[]", "[null,null]", "null", "[2,null,1]", "[1.5,4,1.5,3]" });
    try check(a, f, .{ .cum = .{ .kind = .sum } }, &.{ "[1,3,6]", "[]", "[null,null]", "null", "[4,null,10]", "[3,4,7,9]" });
    try check(a, f, .{ .cum = .{ .kind = .prod } }, &.{ "[1,2,6]", "[]", "[null,null]", "null", "[4,null,24]", "[3,3,9,18]" });
    try check(a, f, .{ .cum = .{ .kind = .min } }, &.{ "[1,1,1]", "[]", "[null,null]", "null", "[4,null,4]", "[3,1,1,1]" });
    try check(a, f, .{ .cum = .{ .kind = .max } }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[4,null,6]", "[3,3,3,3]" });
    try check(a, f, .{ .cum = .{ .kind = .count } }, &.{ "[1,2,3]", "[]", "[0,0]", "null", "[1,1,2]", "[1,2,3,4]" });
    try check(a, f, .{ .cum = .{ .kind = .sum, .reverse = true } }, &.{ "[6,5,3]", "[]", "[null,null]", "null", "[10,null,6]", "[9,6,5,2]" });
    try check(a, f, .{ .diff = 1 }, &.{ "[null,1,1]", "[]", "[null,null]", "null", "[null,null,null]", "[null,-2,2,-1]" });
    try check(a, f, .{ .diff = 2 }, &.{ "[null,null,2]", "[]", "[null,null]", "null", "[null,null,2]", "[null,null,0,1]" });
    try check(a, f, .{ .shift = 1 }, &.{ "[null,1,2]", "[]", "[null,null]", "null", "[null,4,null]", "[null,3,1,3]" });
    try check(a, f, .{ .shift = -1 }, &.{ "[2,3,null]", "[]", "[null,null]", "null", "[null,6,null]", "[1,3,2,null]" });
    try check(a, f, .reverse, &.{ "[3,2,1]", "[]", "[null,null]", "null", "[6,null,4]", "[2,3,1,3]" });
    try check(a, f, .{ .sort = .{} }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[null,4,6]", "[1,2,3,3]" });
    try check(a, f, .{ .sort = .{ .descending = true } }, &.{ "[3,2,1]", "[]", "[null,null]", "null", "[null,6,4]", "[3,3,2,1]" });
    try check(a, f, .{ .sort = .{ .nulls_last = true } }, &.{ "[1,2,3]", "[]", "[null,null]", "null", "[4,6,null]", "[1,2,3,3]" });
    // unique (maintain order; polars' default order is unspecified, the observed one was first appearance) may change the length.
    try check(a, f, .unique, &.{ "[1,2,3]", "[]", "[null]", "null", "[4,null,6]", "[3,1,2]" });
}

test "element operations combine with the element row-wise (broadcast of an aggregate)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, int_doc, .{});
    const mean = eo(.mean);
    const sum = eo(.sum);
    const rank = eo(.{ .rank = .{} });
    // pl.element() - pl.element().mean()
    try expectShown(a, &.{ "[-1,0,1]", "[]", "[null,null]", "null", "[-1,null,1]", "[0.75,-1.25,0.75,-0.25]" }, try evalBody(a, f, .{ .binary = .{ .op = .sub, .l = &elem, .r = &mean } }));
    // pl.element() / pl.element().sum(): polars multiplies by the reciprocal of a scalar divisor, so its 6/10 is
    // 0.6000000000000001 where this module's division gives 0.6 (a last-ulp difference of the arithmetic).
    try expectShown(a, &.{ "[0.16666666666666666,0.3333333333333333,0.5]", "[]", "[null,null]", "null", "[0.4,null,0.6]", "[0.3333333333333333,0.1111111111111111,0.3333333333333333,0.2222222222222222]" }, try evalBody(a, f, .{ .binary = .{ .op = .div, .l = &elem, .r = &sum } }));
    // pl.element().sum() + pl.element(): the aggregate broadcasts
    try expectShown(a, &.{ "[7,8,9]", "[]", "[null,null]", "null", "[14,null,16]", "[12,10,12,11]" }, try evalBody(a, f, .{ .binary = .{ .op = .add, .l = &sum, .r = &elem } }));
    // pl.element().rank() + pl.element()
    try expectShown(a, &.{ "[2,4,6]", "[]", "[null,null]", "null", "[5,null,8]", "[6.5,2,6.5,4]" }, try evalBody(a, f, .{ .binary = .{ .op = .add, .l = &rank, .r = &elem } }));
    // An aggregate of a vector: pl.element().rank().sum() (an argument that is itself an element operation).
    try expectShown(a, &.{ "[6]", "[0]", "[0]", "null", "[3]", "[10]" }, try evalBody(a, f, .{ .element_op = .{ .x = &rank, .op = .sum } }));
    // pl.element() * 2 under a cumulative sum: (pl.element() * 2).cum_sum()
    const dbl: Expr = .{ .binary = .{ .op = .mul, .l = &elem, .r = &.{ .lit = .{ .int = 2 } } } };
    try expectShown(a, &.{ "[2,6,12]", "[]", "[null,null]", "null", "[8,null,20]", "[6,8,14,18]" }, try evalBody(a, f, .{ .element_op = .{ .x = &dbl, .op = .{ .cum = .{ .kind = .sum } } } }));
    // A body of aggregates alone is ONE element, also with arithmetic on them:
    // pl.element().sum() + 1, and sum / count (an empty list divides 0 by 0: NaN, not null).
    try expectShown(a, &.{ "[7]", "[1]", "[1]", "null", "[11]", "[10]" }, try evalBody(a, f, .{ .binary = .{ .op = .add, .l = &sum, .r = &.{ .lit = .{ .int = 1 } } } }));
    // pl.lit(1) is row-wise, not an aggregate: one per element.
    try expectShown(a, &.{ "[1,1,1]", "[]", "[1,1]", "null", "[1,1,1]", "[1,1,1,1]" }, try evalBody(a, f, .{ .lit = .{ .int = 1 } }));
}

test "list_filter with element operations in the predicate" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, int_doc, .{});
    const flt = struct {
        fn run(al: std.mem.Allocator, fr: Frame, pred: Expr) ![]Value {
            return evalCol(al, fr, .{ .list_filter = .{ .x = &lcol, .pred = &pred } });
        }
    }.run;
    const mean = eo(.mean);
    const median = eo(.median);
    const rank = eo(.{ .rank = .{} });
    const first = eo(.first);
    const csum = eo(.{ .cum = .{ .kind = .sum } });
    // list.filter(pl.element() > pl.element().mean()) and > median
    try expectShown(a, &.{ "[3]", "[]", "[]", "null", "[6]", "[3,3]" }, try flt(a, f, .{ .binary = .{ .op = .gt, .l = &elem, .r = &mean } }));
    try expectShown(a, &.{ "[3]", "[]", "[]", "null", "[6]", "[3,3]" }, try flt(a, f, .{ .binary = .{ .op = .gt, .l = &elem, .r = &median } }));
    // list.filter(pl.element().rank() == 1)
    try expectShown(a, &.{ "[1]", "[]", "[]", "null", "[4]", "[1]" }, try flt(a, f, .{ .binary = .{ .op = .eq, .l = &rank, .r = &.{ .lit = .{ .int = 1 } } } }));
    // list.filter(pl.element() == pl.element().first())
    try expectShown(a, &.{ "[1]", "[]", "[]", "null", "[4]", "[3,3]" }, try flt(a, f, .{ .binary = .{ .op = .eq, .l = &elem, .r = &first } }));
    // list.filter(pl.element().cum_sum() < 5)
    try expectShown(a, &.{ "[1,2]", "[]", "[]", "null", "[4]", "[3,1]" }, try flt(a, f, .{ .binary = .{ .op = .lt, .l = &csum, .r = &.{ .lit = .{ .int = 5 } } } }));
    // A scalar predicate keeps all or none: pl.element().sum() > 0
    try expectShown(a, &.{ "[1,2,3]", "[]", "[]", "null", "[4,null,6]", "[3,1,3,2]" }, try flt(a, f, .{ .binary = .{ .op = .gt, .l = &eo(.sum), .r = &.{ .lit = .{ .int = 0 } } } }));
}

test "element operations over floats, text and nested lists" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"l\":[4.0,null,6.0]},{\"l\":[3.0,1.0,3.0,2.0]},{\"l\":[]}]", .{});
    try check(a, f, .sum, &.{ "[10]", "[9]", "[0]" });
    try check(a, f, .mean, &.{ "[5]", "[2.25]", "[null]" });
    try check(a, f, .{ .cum = .{ .kind = .sum } }, &.{ "[4,null,10]", "[3,4,7,9]", "[]" });
    try check(a, f, .{ .rank = .{} }, &.{ "[1,null,2]", "[3.5,1,3.5,2]", "[]" });
    // polars 2.1: strings: min -> ['a'], n_unique 2, rank [2.5,1,2.5], sort, first; empty list: min [None], n_unique [0]
    const tf = try df.readJson(a, "[{\"l\":[\"b\",\"a\",\"b\"]},{\"l\":[]}]", .{});
    try check(a, tf, .min, &.{ "[\"a\"]", "[null]" });
    try check(a, tf, .n_unique, &.{ "[2]", "[0]" });
    try check(a, tf, .{ .rank = .{} }, &.{ "[2.5,1,2.5]", "[]" });
    try check(a, tf, .{ .sort = .{} }, &.{ "[\"a\",\"b\",\"b\"]", "[]" });
    try check(a, tf, .first, &.{ "[\"b\"]", "[null]" });
    try check(a, tf, .{ .cum = .{ .kind = .count } }, &.{ "[1,2,3]", "[]" });
    // polars: sum of strings is an error; here a null result, as `list.sum`.
    try check(a, tf, .sum, &.{ "[null]", "[0]" });
    // Nested lists: the elements are lists. polars: pl.element().reverse() -> [[3],[1,2]], first -> [[1,2]].
    const nf = try df.readJson(a, "[{\"l\":[[1,2],[3]]},{\"l\":[[]]},{\"l\":null}]", .{});
    try check(a, nf, .reverse, &.{ "[[3],[1,2]]", "[[]]", "null" });
    try check(a, nf, .first, &.{ "[[1,2]]", "[[]]", "null" });
    try check(a, nf, .len, &.{ "[2]", "[1]", "null" });
}

test "element operations treat NaN as missing, as every aggregation of the module" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const cells = [_]Value{ .{ .float = 1.5 }, .{ .float = 2.5 }, .{ .float = nan } };
    const lst = try lf.makeList(a, &cells);
    const cols = try a.dupe(df.Column, &.{.{ .name = "l", .type = .list, .inner = &.{.{ .name = "", .type = .float }} }});
    const data = try a.dupe(df.ColumnData, &.{try df.columnFromCells(a, &.{lst})});
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    // DIFFERENCE from polars 2.1, which keeps NaN as a value on [1.5, 2.5, nan]: sum nan, mean nan, median 2.5,
    // count 3, n_unique 3, last nan, rank [1,2,3], cum_sum [1.5,4,nan], diff [null,1,nan]. Here NaN is a missing
    // cell, as in `list.sum` and the window functions (SPEC: NaN is missing).
    try check(a, f, .sum, &.{"[4]"});
    try check(a, f, .min, &.{"[1.5]"});
    try check(a, f, .max, &.{"[2.5]"});
    try check(a, f, .count, &.{"[2]"});
    try check(a, f, .{ .rank = .{} }, &.{"[1,2,null]"});
    try check(a, f, .{ .cum = .{ .kind = .sum } }, &.{"[1.5,4,null]"});
}

test "element operations outside an element scope and malformed bodies are BadExpr" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, int_doc, .{});
    try testing.expectError(error.BadExpr, evalCol(a, f, eo(.sum)));
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .binary = .{ .op = .add, .l = &.{ .lit = .{ .int = 1 } }, .r = &eo(.{ .rank = .{} }) } }));
    // quantile outside [0, 1] or NaN
    try testing.expectError(error.BadExpr, evalBody(a, f, eo(.{ .quantile = .{ .q = 1.5 } })));
    try testing.expectError(error.BadExpr, evalBody(a, f, eo(.{ .quantile = .{ .q = std.math.nan(f64) } })));
    // unique is the whole body or nothing: inside arithmetic or another element operation it is refused
    // (polars: a ShapeError when the lengths differ).
    try testing.expectError(error.BadExpr, evalBody(a, f, .{ .binary = .{ .op = .add, .l = &eo(.unique), .r = &elem } }));
    try testing.expectError(error.BadExpr, evalBody(a, f, .{ .element_op = .{ .x = &eo(.unique), .op = .sum } }));
    const pred = eo(.unique);
    try testing.expectError(error.BadExpr, evalCol(a, f, .{ .list_filter = .{ .x = &lcol, .pred = &pred } }));
    // a column in the body is still NoSuchColumn
    try testing.expectError(error.NoSuchColumn, evalBody(a, f, .{ .element_op = .{ .x = &.{ .col = "zz" }, .op = .sum } }));
}

test "element operations on a 10^5 element list stay inside the budget" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 100_000;
    const cells = try a.alloc(Value, n);
    for (cells, 0..) |*c, i| c.* = .{ .int = @intCast((i * 7919) % 1009) };
    const lst = try lf.makeList(a, cells);
    const cols = try a.dupe(df.Column, &.{.{ .name = "l", .type = .list, .inner = &.{.{ .name = "", .type = .int }} }});
    const data = try a.dupe(df.ColumnData, &.{try df.columnFromCells(a, &.{lst})});
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    const rank = try evalBody(a, f, eo(.{ .rank = .{ .method = .dense } }));
    try testing.expectEqual(@as(usize, n), rank[0].list.len());
    try testing.expectEqual(@as(i64, 1009), (try evalBody(a, f, eo(.n_unique)))[0].list.get(0).int);
    try testing.expectEqual(@as(usize, 1009), (try evalBody(a, f, eo(.unique)))[0].list.len());
    const csum = try evalBody(a, f, eo(.{ .cum = .{ .kind = .sum } }));
    try testing.expectEqual(@as(usize, n), csum[0].list.len());
    // sum - mean * n broadcast: the aggregate is computed once per list, not once per element
    const mean = eo(.mean);
    const centred = try evalBody(a, f, .{ .binary = .{ .op = .sub, .l = &elem, .r = &mean } });
    try testing.expectEqual(@as(usize, n), centred[0].list.len());
    // the work budget still bounds it
    expr.test_hooks.eval_work_limit = 1 << 20;
    defer expr.test_hooks.eval_work_limit = null;
    try testing.expectError(error.TooLarge, evalBody(a, f, eo(.{ .rank = .{} })));
}

test "element operations: empty, all-null and many-row frames do not panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"l\":[]},{\"l\":[null]},{\"l\":null}]", .{});
    const ops = [_]df.ElemOp{
        .sum,          .mean,            .median,                        .min,     .max,     .count,           .len,                           .n_unique,                                        .first,         .last,
        .{ .std = 1 }, .{ .@"var" = 0 }, .{ .quantile = .{ .q = 0.5 } }, .arg_min, .arg_max, .{ .rank = .{} }, .{ .cum = .{ .kind = .prod } }, .{ .cum = .{ .kind = .count, .reverse = true } }, .{ .diff = 1 }, .{ .shift = -3 },
        .reverse,      .{ .sort = .{} }, .unique,
    };
    for (ops) |op| {
        const r = try evalBody(a, f, eo(op));
        // an empty list: [] for a vector operation, one null / zero for an aggregation; a null list: null
        try testing.expect(r[2] == .null);
        try testing.expect(r[0] == .list);
    }
}

test "binIntervals count over a declared column holding a non-numeric cell: an error, not a panic (fuzz driver 2026-11-10)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const D = @import("root.zig");
    const cells = [_]D.Value{ .{ .text = "x" }, .{ .float = 1 }, .{ .float = 3 } };
    for ([_]D.ColumnType{ .float, .int }) |ty| {
        const cols = try a.dupe(D.Column, &.{.{ .name = "v", .type = ty }});
        const data = try a.dupe(D.ColumnData, &.{try D.columnFromCells(a, &cells)});
        const f: D.Frame = .{ .columns = cols, .data = data, .len = cells.len };
        if (D.binIntervals(a, f, .{ .col = "v", .out = "b", .breaks = .{ .count = 3 } })) |_| {} else |e| try std.testing.expect(e == error.NotOrderable or e == error.BadEdges);
    }
}
