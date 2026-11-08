// SPDX-License-Identifier: MIT
//! S3 step 3 (2026-11-08): the `list` and `struct` namespaces in `Expr`
//! (`listfn.zig`), the list and record results of the text functions, `explode`,
//! `unnest` and the `implode` aggregation (`nestverbs.zig`, `core.accumulateImplode`).
//! Expected values are worked by hand from polars' documented behaviour (pandas has no
//! list namespace); where this module's rule differs (NaN is missing in a reduction,
//! `get` out of range is null) the test says so.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const Expr = df.Expr;

const doc =
    \\[{"id":1,"xs":[3,1,2],"p":{"a":1,"b":"x"},"ps":[{"a":1,"b":"u"},{"a":2,"b":null}],"t":"a,b,,c"},
    \\ {"id":2,"xs":[],"p":null,"ps":[],"t":""},
    \\ {"id":3,"xs":null,"p":{"b":"y"},"ps":null,"t":null},
    \\ {"id":4,"xs":[1,null],"p":{"a":4,"b":"z","c":true},"ps":[{"a":9}],"t":"x1y22z"}]
;

fn load(a: std.mem.Allocator) !Frame {
    return df.readJson(a, doc, .{});
}

const xs: Expr = .{ .col = "xs" };

/// `mutate` one expression into column "r" and return its cells.
fn evalCol(a: std.mem.Allocator, f: Frame, e: Expr) ![]Value {
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
    const cells = try a.alloc(Value, out.len);
    for (cells, 0..) |*c, ri| c.* = out.cell(ri, "r").?;
    return cells;
}

fn expectCells(want: []const ?i64, got: []const Value) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got, 0..) |w, g, i| {
        errdefer std.debug.print("row {d}: want {any}, got {any}\n", .{ i, w, g });
        if (w) |x| {
            try testing.expect(g == .int);
            try testing.expectEqual(x, g.int);
        } else try testing.expect(g == .null);
    }
}

fn expectList(want: []const ?i64, v: Value) !void {
    try testing.expect(v == .list);
    try testing.expectEqual(want.len, v.list.len());
    for (want, 0..) |w, i| {
        const e = v.list.get(i);
        if (w) |x| try testing.expectEqual(x, e.int) else try testing.expect(e == .null);
    }
}

fn expectTexts(want: []const ?[]const u8, v: Value) !void {
    try testing.expect(v == .list);
    errdefer std.debug.print("got {d} elements\n", .{v.list.len()});
    try testing.expectEqual(want.len, v.list.len());
    for (want, 0..) |w, i| {
        const e = v.list.get(i);
        if (w) |x| try testing.expectEqualStrings(x, e.text) else try testing.expect(e == .null);
    }
}

fn listOf(op: df.ListOp) Expr {
    return .{ .list = .{ .x = &xs, .op = op } };
}

test "list: len, get, first, last" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    // xs = [3,1,2], [], null, [1,null]; `len` counts null elements (polars).
    try expectCells(&.{ 3, 0, null, 2 }, try evalCol(a, f, listOf(.len)));
    try expectCells(&.{ 2, null, null, null }, try evalCol(a, f, listOf(.{ .get = -1 })));
    try expectCells(&.{ 3, null, null, 1 }, try evalCol(a, f, listOf(.{ .get = 0 })));
    // Out of range: null, not an error (polars' `null_on_oob=True`).
    try expectCells(&.{ null, null, null, null }, try evalCol(a, f, listOf(.{ .get = 5 })));
    try expectCells(&.{ null, null, null, null }, try evalCol(a, f, listOf(.{ .get = std.math.minInt(i64) })));
    try expectCells(&.{ 3, null, null, 1 }, try evalCol(a, f, listOf(.first)));
    try expectCells(&.{ 2, null, null, null }, try evalCol(a, f, listOf(.last)));
    // The result column is int, the element type.
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = listOf(.first) }});
    try testing.expectEqual(df.ColumnType.int, out.columnType("r").?);
}

test "list: reductions skip missing; an int sum stays int, null on overflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    try expectCells(&.{ 6, 0, null, 1 }, try evalCol(a, f, listOf(.sum)));
    try expectCells(&.{ 1, null, null, 1 }, try evalCol(a, f, listOf(.min)));
    try expectCells(&.{ 3, null, null, 1 }, try evalCol(a, f, listOf(.max)));
    try expectCells(&.{ 1, null, null, 0 }, try evalCol(a, f, listOf(.arg_min)));
    try expectCells(&.{ 0, null, null, 0 }, try evalCol(a, f, listOf(.arg_max)));
    // n_unique counts null as a value (polars): [1, null] has 2.
    try expectCells(&.{ 3, 0, null, 2 }, try evalCol(a, f, listOf(.n_unique)));
    const mean = try evalCol(a, f, listOf(.mean));
    try testing.expectEqual(@as(f64, 2), mean[0].float);
    try testing.expect(mean[1] == .null); // empty: no value
    try testing.expectEqual(@as(f64, 1), mean[3].float);
    const med = try evalCol(a, f, listOf(.median));
    try testing.expectEqual(@as(f64, 2), med[0].float);
    // std of [3,1,2], ddof 1: mean 2, squares 1+1+0 = 2, / 2 = 1.
    const sd = try evalCol(a, f, listOf(.{ .std = 1 }));
    try testing.expectEqual(@as(f64, 1), sd[0].float);
    try testing.expect(sd[3] == .null); // one value, n - ddof = 0
    const vr = try evalCol(a, f, listOf(.{ .@"var" = 0 }));
    try testing.expectApproxEqAbs(@as(f64, 2.0 / 3.0), vr[0].float, 1e-15);

    // Hand-built lists, one frame each (`mutate` would promote a column of mixed results).
    try testing.expect((try oneList(a, &.{ .{ .int = std.math.maxInt(i64) }, .{ .int = 1 } }, .sum)) == .null); // overflow
    // NaN is missing here (polars would let it through `sum`).
    try testing.expectEqual(@as(f64, 3.5), (try oneList(a, &.{ .{ .float = 1.5 }, .{ .float = std.math.nan(f64) }, .{ .int = 2 } }, .sum)).float);
    try testing.expectEqual(@as(f64, 1.75), (try oneList(a, &.{ .{ .float = 1.5 }, .{ .float = std.math.nan(f64) }, .{ .int = 2 } }, .mean)).float);
    try testing.expectEqual(@as(f64, 2), (try oneList(a, &.{ .{ .float = 1.5 }, .{ .float = std.math.nan(f64) }, .{ .int = 2 } }, .max)).asFloat().?);
    // 2.5 + 1 = 3.5, exact in decimal.
    try testing.expectEqual(@as(i128, 35 * df.decimal_scale / 10), (try oneList(a, &.{ .{ .decimal = 25 * df.decimal_scale / 10 }, .{ .int = 1 } }, .sum)).decimal);
    // A decimal after an int total near the edge: the decimal total is exact, no overflow.
    try testing.expectEqual(@as(i128, std.math.maxInt(i64)) * df.decimal_scale + 1, (try oneList(a, &.{ .{ .int = std.math.maxInt(i64) }, .{ .decimal = 1 } }, .sum)).decimal);
    try testing.expectEqual(@as(i64, 2), (try oneList(a, &.{ .{ .bool = true }, .{ .bool = true }, .{ .bool = false } }, .sum)).int); // polars counts true
    try testing.expect((try oneList(a, &.{ .{ .int = 1 }, .{ .text = "x" } }, .sum)) == .null); // not a number
}

/// `op` over one hand-built list cell holding `cells`.
fn oneList(a: std.mem.Allocator, cells: []const Value, op: df.ListOp) !Value {
    const items = try a.create(df.ColumnData);
    items.* = .{ .boxed = cells };
    const offsets = try a.dupe(u32, &.{ 0, @intCast(cells.len) });
    const lc = try a.dupe(df.ColumnData, &.{.{ .list = .{ .offsets = offsets, .items = items } }});
    const g: Frame = .{ .columns = &.{.{ .name = "xs", .type = .list }}, .data = lc, .len = 1 };
    return (try evalCol(a, g, listOf(op)))[0];
}

test "list: contains, count_matches, any, all" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const c1 = try evalCol(a, f, listOf(.{ .contains = .{ .int = 1 } }));
    try testing.expect(c1[0].bool and !c1[1].bool and c1[2] == .null and c1[3].bool);
    // A null item asks for a null element (polars `nulls_equal=True`).
    const cn = try evalCol(a, f, listOf(.{ .contains = .null }));
    try testing.expect(!cn[0].bool and !cn[1].bool and cn[3].bool);
    // 1.0 equals the int 1 (`Value.eql` across numeric kinds).
    try expectCells(&.{ 1, 0, null, 1 }, try evalCol(a, f, listOf(.{ .count_matches = .{ .float = 1 } })));

    const items: df.ColumnData = .{ .boxed = &.{ .{ .bool = true }, .null, .{ .bool = false }, .{ .bool = true }, .{ .int = 1 } } };
    const lc: df.ColumnData = .{ .list = .{ .offsets = &.{ 0, 2, 4, 4, 5 }, .items = &items } };
    const g: Frame = .{ .columns = &.{.{ .name = "xs", .type = .list }}, .data = &.{lc}, .len = 4 };
    const any = try evalCol(a, g, listOf(.any));
    const all = try evalCol(a, g, listOf(.all));
    // [true, null], [false, true], [], [1]
    try testing.expect(any[0].bool and any[1].bool and !any[2].bool and any[3] == .null);
    try testing.expect(all[0].bool and !all[1].bool and all[2].bool and all[3] == .null);
}

test "list: sort, reverse, unique, drop_nulls, slice, head, tail keep the list type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const s = try evalCol(a, f, listOf(.{ .sort = .{} }));
    try expectList(&.{ 1, 2, 3 }, s[0]);
    try expectList(&.{}, s[1]);
    try testing.expect(s[2] == .null);
    try expectList(&.{ null, 1 }, s[3]); // nulls first (polars' default)
    try expectList(&.{ 1, null }, (try evalCol(a, f, listOf(.{ .sort = .{ .nulls_last = true } })))[3]);
    try expectList(&.{ 3, 2, 1 }, (try evalCol(a, f, listOf(.{ .sort = .{ .descending = true } })))[0]);
    try expectList(&.{ 2, 1, 3 }, (try evalCol(a, f, listOf(.reverse)))[0]);
    try expectList(&.{1}, (try evalCol(a, f, listOf(.drop_nulls)))[3]);
    try expectList(&.{ 1, 2 }, (try evalCol(a, f, listOf(.{ .slice = .{ .offset = 1 } })))[0]);
    try expectList(&.{1}, (try evalCol(a, f, listOf(.{ .slice = .{ .offset = -2, .length = 1 } })))[0]);
    try expectList(&.{}, (try evalCol(a, f, listOf(.{ .slice = .{ .offset = std.math.maxInt(i64) } })))[0]);
    try expectList(&.{ 3, 1 }, (try evalCol(a, f, listOf(.{ .head = 2 })))[0]);
    try expectList(&.{ 1, 2 }, (try evalCol(a, f, listOf(.{ .tail = 2 })))[0]);
    try expectList(&.{ 3, 1, 2 }, (try evalCol(a, f, listOf(.{ .tail = std.math.maxInt(usize) })))[0]);

    // First appearance order, missing as one value.
    const items: df.ColumnData = .{ .boxed = &.{ .{ .int = 2 }, .null, .{ .int = 1 }, .{ .int = 2 }, .{ .float = std.math.nan(f64) }, .{ .int = 1 } } };
    const lc: df.ColumnData = .{ .list = .{ .offsets = &.{ 0, 6 }, .items = &items } };
    const g: Frame = .{ .columns = &.{.{ .name = "xs", .type = .list }}, .data = &.{lc}, .len = 1 };
    try expectList(&.{ 2, null, 1 }, (try evalCol(a, g, listOf(.unique)))[0]);
    try expectCells(&.{3}, try evalCol(a, g, listOf(.n_unique)));

    // The result column is a list of the source's element type.
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = listOf(.{ .sort = .{} }) }});
    const col = out.columns[out.columnIndex("r").?];
    try testing.expectEqual(df.ColumnType.list, col.type);
    try testing.expectEqual(df.ColumnType.int, col.inner[0].type);
}

test "list: join text elements" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const items: df.ColumnData = .{ .boxed = &.{ .{ .text = "a" }, .null, .{ .text = "b" }, .{ .text = "c" }, .{ .int = 1 } } };
    const lc: df.ColumnData = .{ .list = .{ .offsets = &.{ 0, 3, 3, 5 }, .items = &items } };
    const g: Frame = .{ .columns = &.{.{ .name = "xs", .type = .list }}, .data = &.{lc}, .len = 3 };
    const j = try evalCol(a, g, listOf(.{ .join = .{ .sep = "-" } }));
    try testing.expectEqualStrings("a-b", j[0].text); // the null left out (polars `ignore_nulls=True`)
    try testing.expectEqualStrings("", j[1].text);
    try testing.expect(j[2] == .null); // an int element: not a list of text
    const k = try evalCol(a, g, listOf(.{ .join = .{ .sep = "-", .ignore_nulls = false } }));
    try testing.expect(k[0] == .null);
}

test "struct: field, struct_of, concat_list" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const p: Expr = .{ .col = "p" };
    // p = {a:1,b:x}, null, {b:y}, {a:4,b:z,c:true}
    try expectCells(&.{ 1, null, null, 4 }, try evalCol(a, f, .{ .field = .{ .x = &p, .name = "a" } }));
    const b = try evalCol(a, f, .{ .field = .{ .x = &p, .name = "b" } });
    try testing.expectEqualStrings("y", b[2].text);
    // The column declares its fields: an unknown name is a wrong expression.
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .field = .{ .x = &p, .name = "zz" } } }}));

    const id: Expr = .{ .col = "id" };
    const fields = [_]df.NamedExpr{ .{ .name = "k", .x = id }, .{ .name = "n", .x = listOf(.len) } };
    const r = try evalCol(a, f, .{ .struct_of = &fields });
    try testing.expect(r[0] == .record);
    try testing.expectEqual(@as(i64, 1), r[0].record.field("k").?.int);
    try testing.expectEqual(@as(i64, 3), r[0].record.field("n").?.int);
    try testing.expect(r[2].record.field("n").? == .null);
    const dup = [_]df.NamedExpr{ .{ .name = "k", .x = id }, .{ .name = "k", .x = id } };
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .struct_of = &dup } }}));
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .struct_of = &.{} } }}));

    const parts = [_]Expr{ xs, id };
    const c = try evalCol(a, f, .{ .concat_list = &parts });
    try expectList(&.{ 3, 1, 2, 1 }, c[0]);
    try expectList(&.{2}, c[1]);
    try testing.expect(c[2] == .null); // a null part (polars)
    try expectList(&.{ 1, null, 4 }, c[3]);
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .concat_list = &.{} } }}));
}

test "text: split, split_regex, extract_all, extract_groups" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const t: Expr = .{ .col = "t" };
    // t = "a,b,,c", "", null, "x1y22z"
    const s = try evalCol(a, f, .{ .split = .{ .x = &t, .by = "," } });
    try expectTexts(&.{ "a", "b", "", "c" }, s[0]);
    try expectTexts(&.{""}, s[1]); // "" is one empty piece (polars, Python)
    try testing.expect(s[2] == .null);
    try expectTexts(&.{ "a,", "b,", ",", "c" }, (try evalCol(a, f, .{ .split = .{ .x = &t, .by = ",", .inclusive = true } }))[0]);
    try expectTexts(&.{ "a", "b,,c" }, (try evalCol(a, f, .{ .split = .{ .x = &t, .by = ",", .limit = 2 } }))[0]);
    try expectTexts(&.{ "x", "1", "y", "2", "2", "z" }, (try evalCol(a, f, .{ .split = .{ .x = &t, .by = "" } }))[3]);
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .split = .{ .x = &t, .by = ",", .limit = 0 } } }}));

    try expectTexts(&.{ "x", "y", "z" }, (try evalCol(a, f, .{ .split_regex = .{ .x = &t, .pattern = "[0-9]+" } }))[3]);

    const all = try evalCol(a, f, .{ .extract_all = .{ .x = &t, .pattern = "[0-9]+" } });
    try expectTexts(&.{}, all[0]); // no match: an empty list (polars)
    try expectTexts(&.{ "1", "22" }, all[3]);
    try expectTexts(&.{ "1", "2" }, (try evalCol(a, f, .{ .extract_all = .{ .x = &t, .pattern = "([0-9])[0-9]?", .group = 1 } }))[3]);
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .extract_all = .{ .x = &t, .pattern = "x", .group = 1 } } }}));
    // The column is a list of text.
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .extract_all = .{ .x = &t, .pattern = "[0-9]+" } } }});
    const col = out.columns[out.columnIndex("r").?];
    try testing.expectEqual(df.ColumnType.list, col.type);
    try testing.expectEqual(df.ColumnType.text, col.inner[0].type);

    const g = try evalCol(a, f, .{ .extract_groups = .{ .x = &t, .pattern = "(?P<letter>[a-z])([0-9]+)" } });
    try testing.expect(g[0] == .record);
    try testing.expect(g[0].record.field("letter").? == .null); // no match: every field null (polars)
    try testing.expectEqualStrings("x", g[3].record.field("letter").?.text);
    try testing.expectEqualStrings("1", g[3].record.field("2").?.text); // unnamed: its number
    try testing.expect(g[2] == .null);
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .extract_groups = .{ .x = &t, .pattern = "[0-9]" } } }}));
}

test "list: an element of a timestamp list keeps the column type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const items: df.ColumnData = .{ .int = .{ .values = &.{ 1_000_000, 5_000_000 } } };
    const lc: df.ColumnData = .{ .list = .{ .offsets = &.{ 0, 2 }, .items = &items } };
    const inner = [_]df.Column{.{ .name = "", .type = .timestamp }};
    const g: Frame = .{ .columns = &.{.{ .name = "xs", .type = .list, .inner = &inner }}, .data = &.{lc}, .len = 1 };
    const out = try df.mutate(a, g, &.{.{ .out = "r", .expr = listOf(.max) }});
    try testing.expectEqual(df.ColumnType.timestamp, out.columnType("r").?);
    try testing.expectEqual(@as(i64, 5_000_000), out.cell(0, "r").?.int);
}

test "list: where over a list function, and the evaluation budget" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const n = listOf(.len);
    const one: Expr = .{ .lit = .{ .int = 1 } };
    const w = try df.where(a, f, &.{ .binary = .{ .op = .gt, .l = &n, .r = &one } });
    try testing.expectEqual(@as(usize, 2), w.len); // ids 1 and 4
    try testing.expectEqual(@as(i64, 4), w.cell(1, "id").?.int);

    // Lists built per cell count against `max_eval_bytes` like any text result.
    const big = try a.alloc(u8, 4096);
    @memset(big, ',');
    const bf: Frame = .{ .columns = &.{.{ .name = "t", .type = .text }}, .data = &.{.{ .text = .{ .offsets = &.{ 0, big.len }, .bytes = big } }}, .len = 1 };
    const t: Expr = .{ .col = "t" };
    const hooks = @import("expr.zig").test_hooks;
    hooks.eval_limit = 1024;
    defer hooks.eval_limit = null;
    try testing.expectError(error.TooLarge, df.mutate(a, bf, &.{.{ .out = "r", .expr = .{ .split = .{ .x = &t, .by = "," } } }}));
}

test "explode: one row per element, the other columns repeated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const e = try df.explode(a, f, &.{"xs"});
    // [3,1,2] → 3 rows, [] → 1 null, null → 1 null, [1,null] → 2.
    try testing.expectEqual(@as(usize, 7), e.len);
    const ids = [_]i64{ 1, 1, 1, 2, 3, 4, 4 };
    const vals = [_]?i64{ 3, 1, 2, null, null, 1, null };
    for (ids, vals, 0..) |id, v, ri| {
        try testing.expectEqual(id, e.cell(ri, "id").?.int);
        if (v) |x| try testing.expectEqual(x, e.cell(ri, "xs").?.int) else try testing.expect(e.cell(ri, "xs").? == .null);
    }
    try testing.expectEqual(df.ColumnType.int, e.columnType("xs").?);
    try testing.expect(e.column("xs").? == .int); // a typed gather, not boxed

    // A list of records explodes into a struct column with the element's schema.
    const ps = try df.explode(a, f, &.{"ps"});
    try testing.expectEqual(@as(usize, 5), ps.len); // 2 + 1 + 1 + 1
    try testing.expectEqual(df.ColumnType.@"struct", ps.columnType("ps").?);
    try testing.expectEqual(@as(i64, 2), ps.cell(1, "ps").?.record.field("a").?.int);
    try testing.expect(ps.cell(2, "ps").? == .null);

    // Two columns explode together when their lengths agree on every row.
    const twin = try df.mutate(a, f, &.{.{ .out = "ys", .expr = listOf(.{ .sort = .{} }) }});
    const both = try df.explode(a, twin, &.{ "xs", "ys" });
    try testing.expectEqual(@as(usize, 7), both.len);
    try testing.expectEqual(@as(i64, 1), both.cell(0, "ys").?.int);
    try testing.expectError(error.LengthMismatch, df.explode(a, f, &.{ "xs", "ps" }));
    try testing.expectError(error.NotNested, df.explode(a, f, &.{"id"}));
    try testing.expectError(error.DuplicateColumn, df.explode(a, f, &.{ "xs", "xs" }));
    try testing.expectError(error.NoSuchColumn, df.explode(a, f, &.{"nope"}));
    const same = try df.explode(a, f, &.{});
    try testing.expectEqual(f.len, same.len);
}

test "explode: the cell cap counts the repeated columns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // One row whose list claims 2^27 elements, over a frame of 3 columns: 3 x 2^27 > 2^28.
    const n: u32 = 1 << 27;
    const items: df.ColumnData = .nulls;
    const lc: df.ColumnData = .{ .list = .{ .offsets = &.{ 0, n }, .items = &items } };
    const g: Frame = .{
        .columns = &.{ .{ .name = "xs", .type = .list }, .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } },
        .data = &.{ lc, .nulls, .nulls },
        .len = 1,
    };
    try testing.expectError(error.TooLarge, df.explode(a, g, &.{"xs"}));
}

test "unnest: fields in place of the struct column" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try load(a);
    const u = try df.unnest(a, f, .{ .cols = &.{"p"} });
    const names = [_][]const u8{ "id", "xs", "a", "b", "c", "ps", "t" };
    try testing.expectEqual(names.len, u.columns.len);
    for (names, u.columns) |n, c| try testing.expectEqualStrings(n, c.name);
    try testing.expectEqual(df.ColumnType.int, u.columnType("a").?);
    try testing.expectEqual(df.ColumnType.bool, u.columnType("c").?);
    try testing.expectEqual(@as(i64, 4), u.cell(3, "a").?.int);
    try testing.expect(u.cell(1, "b").? == .null); // a null record: null fields
    try testing.expectEqualStrings("y", u.cell(2, "b").?.text);
    try testing.expect(u.cell(0, "c").? == .null);

    const s = try df.unnest(a, f, .{ .cols = &.{"p"}, .separator = "." });
    try testing.expectEqualStrings("p.a", s.columns[2].name);
    try testing.expectError(error.NotNested, df.unnest(a, f, .{ .cols = &.{"xs"} }));
    try testing.expectError(error.DuplicateColumn, df.unnest(a, f, .{ .cols = &.{ "p", "p" } }));
    // A field named like another column (polars refuses too).
    const clash = try df.mutate(a, f, &.{.{ .out = "a", .expr = .{ .col = "id" } }});
    try testing.expectError(error.DuplicateColumn, df.unnest(a, clash, .{ .cols = &.{"p"} }));

    // A column of mixed records: the union of the names, first seen first.
    const boxed: df.ColumnData = .{ .boxed = &.{ (f.cell(0, "p").?), .{ .int = 7 }, (f.cell(3, "p").?) } };
    const g: Frame = .{ .columns = &.{.{ .name = "p", .type = .@"struct" }}, .data = &.{boxed}, .len = 3 };
    const m = try df.unnest(a, g, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(usize, 3), m.columns.len);
    try testing.expect(m.cell(1, "a").? == .null); // a non-record cell: null fields
    try testing.expect(m.cell(2, "c").?.bool);
}

test "implode: each group's cells as one list; explode inverts it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fb = try df.FrameBuilder.init(a, &.{ .{ .name = "k", .type = .text }, .{ .name = "v", .type = .int } }, 5);
    const rows = [_][2]Value{
        .{ .{ .text = "a" }, .{ .int = 1 } },
        .{ .{ .text = "b" }, .null },
        .{ .{ .text = "a" }, .{ .int = 3 } },
        .{ .{ .text = "c" }, .{ .int = 5 } },
        .{ .{ .text = "a" }, .{ .int = 2 } },
    };
    for (rows) |r| try fb.appendRow(&r);
    const f = try fb.toOwned();
    const g = try df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "vs", .func = .implode }} });
    try testing.expectEqual(@as(usize, 3), g.len);
    try expectList(&.{ 1, 3, 2 }, g.cell(0, "vs").?); // row order kept
    try expectList(&.{null}, g.cell(1, "vs").?); // the null kept (polars, pandas `agg(list)`)
    try expectList(&.{5}, g.cell(2, "vs").?);
    const col = g.columns[g.columnIndex("vs").?];
    try testing.expectEqual(df.ColumnType.list, col.type);
    try testing.expectEqual(df.ColumnType.int, col.inner[0].type);
    const back = try df.explode(a, g, &.{"vs"});
    try testing.expectEqual(@as(usize, 5), back.len);
    try testing.expectEqual(df.ColumnType.int, back.columnType("vs").?);
    try testing.expectEqual(@as(i64, 2), back.cell(2, "vs").?.int);
    // In a window: each row sees its partition's list (polars `implode().over()`).
    const w = try df.window(a, f, .{ .value_col = "v", .out = "w", .partition_by = &.{"k"}, .op = .{ .transform = .{ .func = .implode } } });
    try expectList(&.{ 1, 3, 2 }, w.cell(4, "w").?);
}

test "list and nested verbs: every allocation failure is an error, never a panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try load(arena.allocator());
    const t: Expr = .{ .col = "t" };
    const assigns = [_]df.Assign{
        .{ .out = "a", .expr = listOf(.{ .sort = .{} }) },
        .{ .out = "b", .expr = listOf(.unique) },
        .{ .out = "c", .expr = listOf(.n_unique) },
        .{ .out = "d", .expr = .{ .split = .{ .x = &t, .by = "," } } },
        .{ .out = "e", .expr = .{ .extract_groups = .{ .x = &t, .pattern = "([a-z])([0-9]+)" } } },
    };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        var inner = std.heap.ArenaAllocator.init(testing.allocator);
        defer inner.deinit();
        var fa = std.testing.FailingAllocator.init(inner.allocator(), .{ .fail_index = i });
        const a = fa.allocator();
        const ok = blk: {
            const m = df.mutate(a, f, &assigns) catch |e| {
                try testing.expect(e == error.OutOfMemory);
                break :blk false;
            };
            const x = df.explode(a, m, &.{ "xs", "a" }) catch |e| {
                try testing.expect(e == error.OutOfMemory);
                break :blk false;
            };
            _ = df.unnest(a, x, .{ .cols = &.{ "p", "e" }, .separator = "_" }) catch |e| {
                try testing.expect(e == error.OutOfMemory);
                break :blk false;
            };
            _ = df.aggregate(a, f, .{ .group_by = &.{"id"}, .aggs = &.{.{ .src = "xs", .out = "l", .func = .implode }} }) catch |e| {
                try testing.expect(e == error.OutOfMemory);
                break :blk false;
            };
            break :blk true;
        };
        if (ok) break;
    } else return error.TestUnexpectedResult; // the sweep never reached a clean run
}
