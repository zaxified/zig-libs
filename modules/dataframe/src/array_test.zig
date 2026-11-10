// SPDX-License-Identifier: MIT
//! The fixed-size array column (`ColumnType.array`, polars `Array(inner, n)`), 2026-11-10:
//! cast between list and array, the `arr` operations and their result types, `arr.dot` and
//! `list.dot`, `concat_arr`, `arr.to_struct`, JSON read and write, display, the verbs, and
//! hostile columns. Expected values are polars 2.1's (probe_arr2.py, probe_arr3.py in the
//! session notes); a line that differs from polars says so and why.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const verbs = @import("verbs.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const Expr = ex.Expr;

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

/// `id`, three arrays of width 3 (`a` ints with a null element, `s` texts) and of width 2 (`b`
/// bools): the probe's `a = [[1,2,3],[4,None,6],None]`.
const doc =
    \\[{"id":1,"a":[1,2,3],"b":[true,false],"s":["x","y","z"]},
    \\ {"id":2,"a":[4,null,6],"b":[true,true],"s":["p",null,"q"]},
    \\ {"id":3,"a":null,"b":null,"s":null}]
;

fn fixture(a: std.mem.Allocator) !Frame {
    return df.readJson(a, doc, .{ .types = &.{
        .{ .name = "a", .type = .array, .array_width = 3 },
        .{ .name = "b", .type = .array, .array_width = 2 },
        .{ .name = "s", .type = .array, .array_width = 3 },
    } });
}

fn col(a: std.mem.Allocator, name: []const u8) !*const Expr {
    const p = try a.create(Expr);
    p.* = .{ .col = name };
    return p;
}

fn mutate(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
}

fn arrOp(a: std.mem.Allocator, name: []const u8, op: df.ListOp) !Expr {
    return .{ .arr = .{ .x = try col(a, name), .op = op } };
}

fn typeOf(f: Frame, name: []const u8) ColumnType {
    return f.columnType(name).?;
}

fn widthOf(f: Frame, name: []const u8) u32 {
    return f.columns[f.columnIndex(name).?].array_width;
}

/// Cells of column `name` against `want` (ints, null for a null cell).
fn expectInts(f: Frame, name: []const u8, want: []const ?i64) !void {
    try testing.expectEqual(want.len, f.len);
    for (want, 0..) |w, r| {
        const g = f.cell(r, name).?;
        errdefer std.debug.print("row {d}: want {any}, got {any}\n", .{ r, w, g });
        if (w) |x| {
            try testing.expect(g == .int);
            try testing.expectEqual(x, g.int);
        } else try testing.expect(g == .null);
    }
}

fn expectFloats(f: Frame, name: []const u8, want: []const ?f64) !void {
    for (want, 0..) |w, r| {
        const g = f.cell(r, name).?;
        if (w) |x| {
            try testing.expect(g == .float);
            try testing.expectApproxEqAbs(x, g.float, 1e-12);
        } else try testing.expect(g == .null);
    }
}

fn expectBools(f: Frame, name: []const u8, want: []const ?bool) !void {
    for (want, 0..) |w, r| {
        const g = f.cell(r, name).?;
        if (w) |x| {
            try testing.expect(g == .bool);
            try testing.expectEqual(x, g.bool);
        } else try testing.expect(g == .null);
    }
}

/// A list cell against `want`; `null` as a whole for a null cell.
fn expectList(v: Value, want: ?[]const ?i64) !void {
    const w = want orelse return try testing.expect(v == .null);
    try testing.expect(v == .list);
    errdefer std.debug.print("got a list of {d}\n", .{v.list.len()});
    try testing.expectEqual(w.len, v.list.len());
    for (w, 0..) |x, i| {
        const e = v.list.get(i);
        if (x) |n| {
            try testing.expect(e == .int);
            try testing.expectEqual(n, e.int);
        } else try testing.expect(e == .null);
    }
}

fn json(a: std.mem.Allocator, f: Frame) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&aw.writer, f, .records);
    return aw.written();
}

// ── A1, A5: the type, JSON read and write, display ─────────────────────────

test "fixed array: A1 readJson with an array type: width and element kept, every row conforms" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try testing.expectEqual(ColumnType.array, typeOf(f, "a"));
    try testing.expectEqual(@as(u32, 3), widthOf(f, "a"));
    try testing.expectEqual(@as(u32, 2), widthOf(f, "b"));
    try testing.expect(fm.arraysConform(f));
    try expectList(f.cell(0, "a").?, &.{ 1, 2, 3 });
    try expectList(f.cell(1, "a").?, &.{ 4, null, 6 });
    try expectList(f.cell(2, "a").?, null);
    // a row of another length: polars cannot read an array from JSON at all (superset here)
    const bad = "[{\"a\":[1,2]},{\"a\":[3]}]";
    try testing.expectError(error.BadValue, df.readJson(a, bad, .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 2 }} }));
    // width 0, and an empty frame
    const w0 = try df.readJson(a, "[{\"a\":[]},{\"a\":[]},{\"a\":null}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 0 }} });
    try testing.expect(fm.arraysConform(w0));
    try expectList(w0.cell(1, "a").?, &.{});
    try testing.expectError(error.BadValue, df.readJson(a, "[{\"a\":[1]}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 0 }} }));
}

test "fixed array: A5 writeJson writes an array as a JSON array (polars [{\"k\":1,\"a\":[2,1]},...], null as null)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const text = try json(a, try df.select(a, f, &.{ "id", "a" }));
    try testing.expectEqualStrings("[{\"id\":1,\"a\":[1,2,3]},{\"id\":2,\"a\":[4,null,6]},{\"id\":3,\"a\":null}]", text);
    // and it reads back
    const back = try df.readJson(a, text, .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 3 }} });
    try testing.expect(df.equals(try df.select(a, f, &.{ "id", "a" }), back));
}

test "fixed array: A5 display: array[i64, 3] in the dtype line and glimpse (polars repr)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const shown = try df.format(a, try df.select(a, f, &.{ "a", "s" }), .{ .show_dtypes = true });
    errdefer std.debug.print("{s}\n", .{shown});
    try testing.expect(std.mem.find(u8, shown, "array[i64, 3]") != null);
    try testing.expect(std.mem.find(u8, shown, "array[str, 3]") != null);
    try testing.expect(std.mem.find(u8, shown, "[1,2,3]") != null);
    const g = try df.glimpse(a, try df.select(a, f, &.{ "a", "b" }), .{});
    try testing.expect(std.mem.find(u8, g, "<array[i64, 3]>") != null);
    try testing.expect(std.mem.find(u8, g, "<array[bool, 2]>") != null);
}

test "fixed array: A5 CSV writes the cell as JSON text (polars refuses to write an array); readCsv reads no array" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &aw.writer, try df.select(a, f, &.{ "id", "a" }), .{});
    try testing.expect(std.mem.find(u8, aw.written(), "[1,2,3]") != null);
    try testing.expectError(error.BadValue, df.readCsv(a, "a\n\"[1,2]\"\n", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 2 }} }));
}

// ── A2: cast list <-> array ─────────────────────────────────────────────────

const lists_doc =
    \\[{"l":[1,2]},{"l":[3,4]},{"l":null},{"l":[5,6]}]
;

test "fixed array: A2 cast list to array: every valid row of the width, a null row stays null (polars [[1,2],[3,4],None,[5,6]])" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a, lists_doc, .{});
    try testing.expectEqual(ColumnType.list, typeOf(f, "l"));
    const g = try df.cast(a, f, .{ .col = "l", .to = .array, .array_width = 2, .on_error = .fail });
    try testing.expectEqual(ColumnType.array, typeOf(g, "l"));
    try testing.expectEqual(@as(u32, 2), widthOf(g, "l"));
    try testing.expect(fm.arraysConform(g));
    try expectList(g.cell(3, "l").?, &.{ 5, 6 });
    try testing.expect(g.cell(2, "l").? == .null);
    // the element column is kept, array back to list drops the width
    try testing.expectEqual(@as(usize, 1), g.columns[0].inner.len);
    const back = try df.cast(a, g, .{ .col = "l", .to = .list });
    try testing.expectEqual(ColumnType.list, typeOf(back, "l"));
    try testing.expectEqual(@as(u32, 0), widthOf(back, "l"));
    try testing.expect(df.equals(f, back));
}

test "fixed array: A2 cast list to array of a width some row breaks: null per row, CastFailed with .fail (polars raises even with strict=False)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a, "[{\"l\":[1,2]},{\"l\":[3]},{\"l\":null}]", .{});
    try testing.expectError(error.CastFailed, df.cast(a, f, .{ .col = "l", .to = .array, .array_width = 2, .on_error = .fail }));
    const g = try df.cast(a, f, .{ .col = "l", .to = .array, .array_width = 2 });
    try testing.expect(fm.arraysConform(g));
    try expectList(g.cell(0, "l").?, &.{ 1, 2 });
    try testing.expect(g.cell(1, "l").? == .null);
    // width 0: only empty lists are arrays (polars [[], []])
    const e = try df.readJson(a, "[{\"l\":[]},{\"l\":[]}]", .{});
    const e0 = try df.cast(a, e, .{ .col = "l", .to = .array, .array_width = 0, .on_error = .fail });
    try testing.expectEqual(ColumnType.array, typeOf(e0, "l"));
    try expectList(e0.cell(0, "l").?, &.{});
}

test "fixed array: A2 cast: an array to another width is refused (polars InvalidOperationError), the same width and a list to text are fine" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try testing.expectError(error.BadExpr, df.cast(a, f, .{ .col = "a", .to = .array, .array_width = 2 }));
    const same = try df.cast(a, f, .{ .col = "a", .to = .array, .array_width = 3 });
    try testing.expect(df.equals(f, same));
    // polars cannot cast an array to a string, a string or an int to an array; here the text is the
    // JSON of the cell (as for a list) and the other two are null per row
    const t = try df.cast(a, f, .{ .col = "a", .to = .text });
    try testing.expect(t.cell(0, "a").? == .text);
    try testing.expectEqualStrings("[1,2,3]", t.cell(0, "a").?.text);
    const from_int = try df.cast(a, f, .{ .col = "id", .to = .array, .array_width = 1 });
    try testing.expect(from_int.cell(0, "id").? == .null);
    try testing.expectError(error.CastFailed, df.cast(a, f, .{ .col = "id", .to = .array, .array_width = 1, .on_error = .fail }));
}

test "fixed array: A2 Expr.cast to an array and back" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a, lists_doc, .{});
    const to_arr = try ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .cast = .{ .x = try col(a, "l"), .to = .array, .array_width = 2 } } }});
    try testing.expectEqual(ColumnType.array, typeOf(to_arr, "o"));
    try testing.expectEqual(@as(u32, 2), widthOf(to_arr, "o"));
    try testing.expect(fm.arraysConform(to_arr));
    // wrong width on an array operand is refused when compiled
    const arr = try fixture(a);
    try testing.expectError(error.BadExpr, mutate(a, arr, .{ .cast = .{ .x = try col(a, "a"), .to = .array, .array_width = 2 } }));
    // to_list (polars arr.to_list) is the cast to a list: a list column, no width
    const l = try mutate(a, arr, .{ .cast = .{ .x = try col(a, "a"), .to = .list } });
    try testing.expectEqual(ColumnType.list, typeOf(l, "o"));
    try expectList(l.cell(1, "o").?, &.{ 4, null, 6 });
}

// ── A3: arr.* — values and result types (polars 2.1 probe) ─────────────────

test "fixed array: A3 arr scalar results (len, first, last, get, contains, count_matches, n_unique, sum, min, max, arg_min, arg_max)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const N: ?i64 = null;
    try expectInts(try mutate(a, f, try arrOp(a, "a", .len)), "o", &.{ 3, 3, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .first)), "o", &.{ 1, 4, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .last)), "o", &.{ 3, 6, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .{ .get = 1 })), "o", &.{ 2, N, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .{ .get = -1 })), "o", &.{ 3, 6, N });
    // polars get(9, null_on_oob=True): all null; the default raises, a cell cannot
    try expectInts(try mutate(a, f, try arrOp(a, "a", .{ .get = 9 })), "o", &.{ N, N, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .{ .get = std.math.maxInt(i64) })), "o", &.{ N, N, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .{ .get = std.math.minInt(i64) })), "o", &.{ N, N, N });
    try expectBools(try mutate(a, f, try arrOp(a, "a", .{ .contains = .{ .int = 2 } })), "o", &.{ true, false, null });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .{ .count_matches = .{ .int = 2 } })), "o", &.{ 1, 0, N });
    // polars: contains(None) is [True, True, False] over [[None,None],[1,None],[1,2]]
    try expectInts(try mutate(a, f, try arrOp(a, "a", .n_unique)), "o", &.{ 3, 3, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .sum)), "o", &.{ 6, 10, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .min)), "o", &.{ 1, 4, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .max)), "o", &.{ 3, 6, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .arg_min)), "o", &.{ 0, 0, N });
    try expectInts(try mutate(a, f, try arrOp(a, "a", .arg_max)), "o", &.{ 2, 2, N });
    // none of them is an array
    try testing.expect(typeOf(try mutate(a, f, try arrOp(a, "a", .sum)), "o") != .array);
}

test "fixed array: A3 arr statistics and any/all, join" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try expectFloats(try mutate(a, f, try arrOp(a, "a", .mean)), "o", &.{ 2.0, 5.0, null });
    try expectFloats(try mutate(a, f, try arrOp(a, "a", .median)), "o", &.{ 2.0, 5.0, null });
    try expectFloats(try mutate(a, f, try arrOp(a, "a", .{ .std = 1 })), "o", &.{ 1.0, 1.4142135623730951, null });
    try expectFloats(try mutate(a, f, try arrOp(a, "a", .{ .@"var" = 1 })), "o", &.{ 1.0, 2.0, null });
    // bool arrays: polars any [True, True, None], all [False, True, None]
    try expectBools(try mutate(a, f, try arrOp(a, "b", .any)), "o", &.{ true, true, null });
    try expectBools(try mutate(a, f, try arrOp(a, "b", .all)), "o", &.{ false, true, null });
    // join: polars '1-2-3' / ['x'] for ["x", None] with the nulls ignored, None when not
    const j = try mutate(a, f, try arrOp(a, "s", .{ .join = .{ .sep = "-" } }));
    try testing.expectEqualStrings("x-y-z", j.cell(0, "o").?.text);
    try testing.expectEqualStrings("p-q", j.cell(1, "o").?.text);
    try testing.expect(j.cell(2, "o").? == .null);
    const jn = try mutate(a, f, try arrOp(a, "s", .{ .join = .{ .sep = "-", .ignore_nulls = false } }));
    try testing.expect(jn.cell(1, "o").? == .null);
}

test "fixed array: A3 arr reverse, sort, shift keep the Array type and width; unique gives a List (polars dtypes)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const N: ?i64 = null;
    const rev = try mutate(a, f, try arrOp(a, "a", .reverse));
    try testing.expectEqual(ColumnType.array, typeOf(rev, "o"));
    try testing.expectEqual(@as(u32, 3), widthOf(rev, "o"));
    try testing.expect(fm.arraysConform(rev));
    try expectList(rev.cell(0, "o").?, &.{ 3, 2, 1 });
    try expectList(rev.cell(1, "o").?, &.{ 6, N, 4 });
    try expectList(rev.cell(2, "o").?, null);
    const srt = try mutate(a, f, try arrOp(a, "a", .{ .sort = .{} }));
    try testing.expectEqual(ColumnType.array, typeOf(srt, "o"));
    try expectList(srt.cell(1, "o").?, &.{ N, 4, 6 }); // nulls first
    const srtd = try mutate(a, f, try arrOp(a, "a", .{ .sort = .{ .descending = true, .nulls_last = true } }));
    try expectList(srtd.cell(0, "o").?, &.{ 3, 2, 1 });
    try expectList(srtd.cell(1, "o").?, &.{ 6, 4, N });
    const s1 = try mutate(a, f, try arrOp(a, "a", .{ .shift = 1 }));
    try testing.expectEqual(ColumnType.array, typeOf(s1, "o"));
    try testing.expectEqual(@as(u32, 3), widthOf(s1, "o"));
    try expectList(s1.cell(0, "o").?, &.{ N, 1, 2 });
    try expectList(s1.cell(1, "o").?, &.{ N, 4, N });
    const sm = try mutate(a, f, try arrOp(a, "a", .{ .shift = -1 }));
    try expectList(sm.cell(0, "o").?, &.{ 2, 3, N });
    try expectList(sm.cell(1, "o").?, &.{ N, 6, N });
    try testing.expect(fm.arraysConform(s1) and fm.arraysConform(sm));
    const uq = try mutate(a, f, try arrOp(a, "a", .unique));
    try testing.expectEqual(ColumnType.list, typeOf(uq, "o"));
    try testing.expectEqual(@as(u32, 0), widthOf(uq, "o"));
    try expectList(uq.cell(1, "o").?, &.{ 4, N, 6 });
    // a chain keeps the width: reverse of reverse of a column
    const rr = try mutate(a, f, .{ .arr = .{ .x = try boxedExpr(a, try arrOp(a, "a", .reverse)), .op = .reverse } });
    try testing.expectEqual(ColumnType.array, typeOf(rr, "o"));
    try expectList(rr.cell(0, "o").?, &.{ 1, 2, 3 });
}

fn boxedExpr(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

test "fixed array: A3 arr refuses what is no array, and the list functions polars' arr lacks (BadExpr)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    // an int column, a list column (polars InvalidOperationError "expected Array datatype")
    try testing.expectError(error.BadExpr, mutate(a, f, try arrOp(a, "id", .sum)));
    const lf = try df.readJson(a, lists_doc, .{});
    try testing.expectError(error.BadExpr, mutate(a, lf, try arrOp(a, "l", .sum)));
    try testing.expectError(error.NoSuchColumn, mutate(a, f, try arrOp(a, "nope", .sum)));
    // polars' arr has no slice, head, tail, drop_nulls, gather_every, diff, item
    const refused = [_]df.ListOp{ .{ .slice = .{ .offset = 0 } }, .{ .head = 1 }, .{ .tail = 1 }, .drop_nulls, .{ .gather_every = .{ .n = 1 } }, .{ .diff = .{} }, .item };
    for (refused) |op| {
        try testing.expectError(error.BadExpr, mutate(a, f, try arrOp(a, "a", op)));
    }
}

test "fixed array: A3 arr.to_struct: field_0.. by default, names of the width, a count that is not the width is refused" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const g = try mutate(a, f, .{ .arr_to_struct = .{ .x = try col(a, "a") } });
    try testing.expectEqual(ColumnType.@"struct", typeOf(g, "o"));
    const r0 = g.cell(0, "o").?;
    try testing.expect(r0 == .record);
    try testing.expectEqualStrings("field_0", r0.record.name(0));
    try testing.expectEqualStrings("field_2", r0.record.name(2));
    try testing.expectEqual(@as(i64, 3), r0.record.get(2).int);
    // polars: {'field_0': 4, 'field_1': None, 'field_2': 6}
    const r1 = g.cell(1, "o").?;
    try testing.expect(r1.record.get(1) == .null);
    try testing.expect(g.cell(2, "o").? == .null);
    const named = try mutate(a, f, .{ .arr_to_struct = .{ .x = try col(a, "a"), .names = &.{ "x", "y", "z" } } });
    try testing.expectEqualStrings("y", named.cell(0, "o").?.record.name(1));
    // polars ComputeError "number of field names provided"
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .arr_to_struct = .{ .x = try col(a, "a"), .names = &.{"x"} } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .arr_to_struct = .{ .x = try col(a, "a"), .names = &.{ "x", "y", "z", "w" } } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .arr_to_struct = .{ .x = try col(a, "id") } }));
    // width 0 is a record of no fields (polars Struct({}))
    const w0 = try df.readJson(a, "[{\"a\":[]}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 0 }} });
    const s0 = try mutate(a, w0, .{ .arr_to_struct = .{ .x = try col(a, "a") } });
    try testing.expect(s0.cell(0, "o").? == .record);
    try testing.expectEqual(@as(usize, 0), s0.cell(0, "o").?.record.len());
}

// ── arr.dot, list.dot ───────────────────────────────────────────────────────

test "fixed array: A3 arr.dot (polars [14, 52, None]; nulls are left out: [[None,None],[1,None],[1,2]].[[1,2],[3,4],[None,1]] = [0, 3, 2])" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const self = try mutate(a, f, .{ .arr_dot = .{ .l = try col(a, "a"), .r = try col(a, "a") } });
    try testing.expectEqual(ColumnType.int, typeOf(self, "o"));
    try expectInts(self, "o", &.{ 14, 52, null });
    const nd = try df.readJson(a,
        \\[{"x":[null,null],"y":[1,2]},{"x":[1,null],"y":[3,4]},{"x":[1,2],"y":[null,1]}]
    , .{ .types = &.{ .{ .name = "x", .type = .array, .array_width = 2 }, .{ .name = "y", .type = .array, .array_width = 2 } } });
    try expectInts(try mutate(a, nd, .{ .arr_dot = .{ .l = try col(a, "x"), .r = try col(a, "y") } }), "o", &.{ 0, 3, 2 });
    // int . float is a float (polars [5.5]); width 0 is 0 (polars [0])
    const mix = try df.readJson(a, "[{\"x\":[1,2],\"y\":[1.5,2.0]}]", .{ .types = &.{ .{ .name = "x", .type = .array, .array_width = 2 }, .{ .name = "y", .type = .array, .array_width = 2 } } });
    try expectFloats(try mutate(a, mix, .{ .arr_dot = .{ .l = try col(a, "x"), .r = try col(a, "y") } }), "o", &.{5.5});
    const z = try df.readJson(a, "[{\"x\":[]}]", .{ .types = &.{.{ .name = "x", .type = .array, .array_width = 0 }} });
    try expectInts(try mutate(a, z, .{ .arr_dot = .{ .l = try col(a, "x"), .r = try col(a, "x") } }), "o", &.{0});
    // polars ShapeError "equal array widths": refused when compiled; a list is no array
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .arr_dot = .{ .l = try col(a, "a"), .r = try col(a, "b") } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .arr_dot = .{ .l = try col(a, "a"), .r = try col(a, "id") } }));
    // the product overflows Int64: null here (polars wraps: [0] for 2^62 * 2^62 twice)
    const big = try df.readJson(a, "[{\"x\":[4611686018427387904,4611686018427387904]}]", .{ .types = &.{.{ .name = "x", .type = .array, .array_width = 2 }} });
    try expectInts(try mutate(a, big, .{ .arr_dot = .{ .l = try col(a, "x"), .r = try col(a, "x") } }), "o", &.{null});
}

test "fixed array: A3 list.dot: two lists of one length, unequal lengths and nulls give null (polars has no list.dot: the design's superset)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a,
        \\[{"x":[1,2],"y":[1,1]},{"x":[3,4],"y":[2,2]},{"x":[1,2,3],"y":[1,1]},{"x":null,"y":[1,1]},{"x":[],"y":[]}]
    , .{});
    const g = try mutate(a, f, .{ .list_dot = .{ .l = try col(a, "x"), .r = try col(a, "y") } });
    try expectInts(g, "o", &.{ 3, 14, null, null, 0 });
    // on arrays it is the same dot
    const arr = try fixture(a);
    try expectInts(try mutate(a, arr, .{ .list_dot = .{ .l = try col(a, "a"), .r = try col(a, "a") } }), "o", &.{ 14, 52, null });
}

// ── A4: concat_arr ──────────────────────────────────────────────────────────

const xyz =
    \\[{"x":1,"y":3,"z":null},{"x":2,"y":4,"z":6}]
;

test "fixed array: A4 concat_arr of columns: one array of the summed width (polars [[1,3,None],[2,4,6]], Array(Int64, 3))" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a, xyz, .{});
    const xs: []const Expr = &.{ .{ .col = "x" }, .{ .col = "y" }, .{ .col = "z" } };
    const g = try mutate(a, f, .{ .concat_arr = xs });
    try testing.expectEqual(ColumnType.array, typeOf(g, "o"));
    try testing.expectEqual(@as(u32, 3), widthOf(g, "o"));
    try testing.expect(fm.arraysConform(g));
    try expectList(g.cell(0, "o").?, &.{ 1, 3, null });
    try expectList(g.cell(1, "o").?, &.{ 2, 4, 6 });
    // the element column is declared (the first part's type)
    try testing.expectEqual(ColumnType.int, g.columns[g.columnIndex("o").?].inner[0].type);
    // a single part is an array of one
    const one = try mutate(a, f, .{ .concat_arr = &.{.{ .col = "x" }} });
    try testing.expectEqual(@as(u32, 1), widthOf(one, "o"));
    try expectList(one.cell(1, "o").?, &.{2});
    // a literal scalar is one element (polars refuses a dyn literal; coerced here)
    const lit = try mutate(a, f, .{ .concat_arr = &.{ .{ .col = "x" }, .{ .lit = .{ .int = 9 } } } });
    try expectList(lit.cell(0, "o").?, &.{ 1, 9 });
}

test "fixed array: A4 concat_arr of arrays and scalars (polars: array+column, array+array, a null array row gives null, width 0 + x)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f0 = try df.readJson(a, xyz, .{});
    const f = try mutate(a, f0, .{ .concat_arr = &.{ .{ .col = "x" }, .{ .col = "y" } } });
    var named = f;
    const cols = try a.dupe(Column, f.columns);
    cols[f.columnIndex("o").?].name = "xy";
    named.columns = cols;
    const ac = try mutate(a, named, .{ .concat_arr = &.{ .{ .col = "xy" }, .{ .col = "z" } } });
    try testing.expectEqual(@as(u32, 3), widthOf(ac, "o"));
    try expectList(ac.cell(0, "o").?, &.{ 1, 3, null });
    const aa = try mutate(a, named, .{ .concat_arr = &.{ .{ .col = "xy" }, .{ .col = "xy" } } });
    try testing.expectEqual(@as(u32, 4), widthOf(aa, "o"));
    try expectList(aa.cell(1, "o").?, &.{ 2, 4, 2, 4 });
    // a null array row: the whole cell is null (polars [[1,2,1], None])
    const nr = try df.readJson(a, "[{\"a\":[1,2],\"x\":1},{\"a\":null,\"x\":2}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 2 }} });
    const n = try mutate(a, nr, .{ .concat_arr = &.{ .{ .col = "a" }, .{ .col = "x" } } });
    try expectList(n.cell(0, "o").?, &.{ 1, 2, 1 });
    try expectList(n.cell(1, "o").?, null);
    try testing.expect(fm.arraysConform(n));
    // width 0 plus a scalar (polars [[1], [2]])
    const w0 = try df.readJson(a, "[{\"a\":[],\"x\":1},{\"a\":[],\"x\":2}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 0 }} });
    const z = try mutate(a, w0, .{ .concat_arr = &.{ .{ .col = "a" }, .{ .col = "x" } } });
    try testing.expectEqual(@as(u32, 1), widthOf(z, "o"));
    try expectList(z.cell(1, "o").?, &.{2});
    // arr operations over it keep working: its width is known
    const s = try mutate(a, w0, .{ .arr = .{ .x = try boxedExpr(a, .{ .concat_arr = &.{ .{ .col = "a" }, .{ .col = "x" } } }), .op = .sum } });
    try expectInts(s, "o", &.{ 1, 2 });
}

test "fixed array: A4 concat_arr refuses what polars does: no parts, a list part (SchemaError), and a width too big" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.readJson(a, "[{\"l\":[1,2],\"x\":1}]", .{});
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .concat_arr = &.{} }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .concat_arr = &.{ .{ .col = "l" }, .{ .col = "x" } } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .concat_arr = &.{ .{ .col = "x" }, .{ .lit = try litList(a) } } }));
    // an array of u32-max width plus one more does not fit a width: refused, not wrapped
    const huge: Expr = .{ .cast = .{ .x = try col(a, "l"), .to = .array, .array_width = std.math.maxInt(u32) } };
    try testing.expectError(error.TooLarge, mutate(a, f, .{ .concat_arr = &.{ huge, .{ .col = "x" } } }));
}

fn litList(a: std.mem.Allocator) !Value {
    const f = try df.readJson(a, "[{\"l\":[1,2]}]", .{});
    return f.cell(0, "l").?;
}

// ── A6: verbs ───────────────────────────────────────────────────────────────

const verbs_doc =
    \\[{"k":3,"a":[2,1]},{"k":1,"a":[1,1]},{"k":2,"a":null},{"k":1,"a":[1,1]},{"k":null,"a":[0,9]}]
;

fn verbsFrame(a: std.mem.Allocator) !Frame {
    return df.readJson(a, verbs_doc, .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 2 }} });
}

/// A verb that may refuse an array column: when it answers, the answer conforms.
fn conformsOrErr(r: anytype) !void {
    if (r) |f| try testing.expect(fm.arraysConform(f)) else |_| {}
}

fn keptArray(f: Frame) !void {
    try testing.expect(fm.arraysConform(f));
    const ci = f.columnIndex("a") orelse return;
    try testing.expectEqual(ColumnType.array, f.columns[ci].type);
    try testing.expectEqual(@as(u32, 2), f.columns[ci].array_width);
}

test "fixed array: A6 sort by an array is the list order, nulls first (polars [(2,None),(None,[0,9]),(1,[1,1]),(1,[1,1]),(3,[2,1])])" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try verbsFrame(a);
    const s = try df.sort(a, f, .{ .key = "a" });
    try keptArray(s);
    try expectInts(s, "k", &.{ 2, null, 1, 1, 3 });
    const d = try df.sort(a, f, .{ .key = "a", .dir = .desc });
    try keptArray(d);
    try expectInts(d, "k", &.{ 3, 1, 1, null, 2 });
}

test "fixed array: A6 filter, group keys, distinct, join keys, value counts on an array (polars group_by/unique/join work on Array)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try verbsFrame(a);
    try keptArray(try df.filter(a, f, .{ .where = &.{.{ .col = "k", .op = .ge, .value = .{ .int = 2 } }} }));
    try keptArray(try df.distinct(a, f, .{ .keys = &.{"a"} }));
    // polars unique(subset="a", maintain_order=True): rows k = 3, 1, 2, None
    const u = try df.distinct(a, f, .{ .keys = &.{"a"} });
    try expectInts(u, "k", &.{ 3, 1, 2, null });
    const g = try df.aggregate(a, f, .{ .group_by = &.{"a"}, .aggs = &.{.{ .src = "k", .out = "n", .func = .count }} });
    try testing.expectEqual(ColumnType.array, typeOf(g, "a"));
    try testing.expectEqual(@as(u32, 2), widthOf(g, "a"));
    try testing.expect(fm.arraysConform(g));
    try testing.expectEqual(@as(usize, 4), g.len);
    // first of an array column per group keeps Array (polars agg first)
    const fg = try df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "a", .out = "af", .func = .first }} });
    try testing.expectEqual(ColumnType.array, typeOf(fg, "af"));
    try testing.expectEqual(@as(u32, 2), widthOf(fg, "af"));
    try testing.expect(fm.arraysConform(fg));
    // implode is a List of Arrays
    const ig = try df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "a", .out = "al", .func = .implode }} });
    try testing.expectEqual(ColumnType.list, typeOf(ig, "al"));
    try testing.expectEqual(ColumnType.array, ig.columns[ig.columnIndex("al").?].inner[0].type);
    // join on the array key: (1,[1,1]) twice on each side is four rows, plus (3,[2,1]) and (None,[0,9])
    const side = try df.select(a, f, &.{"a"});
    const j = try df.join(a, f, side, .{ .on = "a", .how = .inner });
    // (polars joins no null key; a null array row matches the other one here, as a null key of
    // any type does in this module, so seven rows)
    try testing.expectEqual(@as(usize, 7), j.len);
    const jn = try df.join(a, f, side, .{ .on = "a", .how = .inner, .null_keys = .no_match });
    try testing.expectEqual(@as(usize, 6), jn.len); // polars: no null key joins
    try keptArray(j);
    const vc = try df.valueCounts(a, f, .{ .cols = &.{"a"} });
    try testing.expect(fm.arraysConform(vc));
    try testing.expectEqual(ColumnType.array, typeOf(vc, "a"));
}

test "fixed array: A6 explode gives the element column (polars: a null array row is one null row)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try verbsFrame(a);
    const e = try df.explode(a, f, &.{"a"});
    try testing.expectEqual(ColumnType.int, typeOf(e, "a"));
    try testing.expectEqual(@as(usize, 9), e.len);
    // polars explode frame: (3,2) (3,1) (1,1) (1,1) (2,None) (1,1) (1,1) (None,0) (None,9)
    try expectInts(e, "a", &.{ 2, 1, 1, 1, null, 1, 1, 0, 9 });
    try expectInts(e, "k", &.{ 3, 3, 1, 1, 2, 1, 1, null, null });
    const all = try df.explodeAll(a, f);
    try testing.expectEqual(@as(usize, 9), all.len);
}

test "fixed array: A6 concat: arrays of different widths are refused (polars SchemaError), array with list relaxes to a list" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try verbsFrame(a);
    const g = try df.readJson(a, "[{\"k\":1,\"a\":[1,2,3]}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 3 }} });
    try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ f, g }, .vertical));
    const same = try df.concat(a, &.{ f, f }, .vertical);
    try keptArray(same);
    try testing.expectEqual(@as(usize, 10), same.len);
    const l = try df.readJson(a, "[{\"k\":1,\"a\":[1,2]}]", .{});
    // a strict vertical concat of array and list is a schema mismatch too
    try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ f, l }, .vertical));
    const mixed = try df.concat(a, &.{ f, l }, .vertical_relaxed);
    try testing.expectEqual(ColumnType.list, typeOf(mixed, "a"));
    try testing.expect(fm.arraysConform(mixed));
}

test "fixed array: A6 sweep: the public verbs keep the array type and its width, and every row conforms" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try verbsFrame(a);
    try keptArray(f);
    try keptArray(try verbs.takeRows(a, f, &.{ 4, 0, 0, 3 }));
    try keptArray(try df.filter(a, f, .{ .where = &.{.{ .col = "k", .op = .ge, .value = .{ .int = 1 } }} }));
    try keptArray(try df.filter(a, f, .{ .where = &.{.{ .col = "a", .op = .is_null }} }));
    try keptArray(try df.distinct(a, f, .{ .keys = &.{} }));
    try keptArray(try df.distinct(a, f, .{ .keys = &.{"k"}, .keep = .last }));
    try keptArray(try df.sort(a, f, .{ .key = "k" }));
    try keptArray(try df.sort(a, f, .{ .key = "k", .dir = .desc, .missing = .last, .then_by = &.{.{ .key = "a" }} }));
    try keptArray(try df.dropna(a, f, .{ .subset = &.{"a"} }));
    try keptArray(try df.dropna(a, f, .{}));
    try keptArray(try df.select(a, f, &.{ "a", "k" }));
    try keptArray(try df.drop(a, f, &.{"k"}));
    try keptArray(try df.page(a, f, .{ .offset = 1, .limit = 3 }));
    try keptArray(try df.tail(a, f, 2));
    try keptArray(try df.clone(a, f));
    try keptArray(try df.clear(a, f, 3));
    try keptArray(try df.take(a, f, &.{ 0, -1, 2, 2 }));
    try keptArray(try df.gatherEvery(a, f, 2, 1));
    try keptArray(try df.reverse(a, f));
    try keptArray(try df.concat(a, &.{ f, f }, .vertical));
    try keptArray(try df.concat(a, &.{ f, f }, .diagonal));
    try keptArray(try df.concatByName(a, &.{ f, f }));
    try keptArray(try df.repeatRows(a, f, .{ .times = 2 }));
    inline for (.{ .forward, .backward }) |st| {
        try keptArray(try df.fillNull(a, f, .{ .subset = &.{"a"}, .strategy = st }));
    }
    try keptArray(try df.topN(a, f, .{ .n = 2 }));
    inline for (.{ .inner, .left, .right, .full, .semi, .anti }) |how| {
        const j = try df.join(a, f, try df.select(a, f, &.{ "k", "a" }), .{ .on = "k", .how = how, .coalesce_keys = true });
        try testing.expect(fm.arraysConform(j));
    }
    {
        const w = try df.window(a, f, .{ .value_col = "a", .out = "o", .op = .{ .shift = .{ .n = 1 } }, .partition_by = &.{"k"} });
        try testing.expect(fm.arraysConform(w));
        try testing.expectEqual(ColumnType.array, typeOf(w, "o"));
        try testing.expectEqual(@as(u32, 2), widthOf(w, "o"));
        try conformsOrErr(df.window(a, f, .{ .value_col = "a", .out = "o", .op = .{ .transform = .{ .func = .first } }, .partition_by = &.{"k"} }));
        try conformsOrErr(df.window(a, f, .{ .value_col = "a", .out = "o", .op = .{ .transform = .{ .func = .implode } }, .partition_by = &.{"k"} }));
    }
    {
        const u = try df.unpivot(a, f, .{ .id_cols = &.{"a"}, .value_cols = &.{"k"} });
        try testing.expect(fm.arraysConform(u));
        try testing.expectEqual(ColumnType.array, typeOf(u, "a"));
        try conformsOrErr(df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{"a"} }));
        try conformsOrErr(df.pivot(a, f, .{ .row_key = "k", .col_key = "k", .value_col = "a", .agg = .first }));
    }
    {
        try conformsOrErr(df.transpose(a, try df.select(a, f, &.{"a"}), .{}));
        try conformsOrErr(df.describeWith(a, f, .{ .cols = &.{ "a", "k" } }));
        _ = try df.info(a, f);
        try testing.expect(df.hasNulls(f));
        try testing.expect(df.equals(f, try df.clone(a, f)));
    }
    // expressions that keep the column: a column, coalesce, if_else, a cast back
    {
        const c = try mutate(a, f, .{ .coalesce = &.{ .{ .col = "a" }, .{ .col = "a" } } });
        try testing.expectEqual(ColumnType.array, typeOf(c, "o"));
        try testing.expectEqual(@as(u32, 2), widthOf(c, "o"));
        try testing.expect(fm.arraysConform(c));
        const ie = try mutate(a, f, .{ .if_else = .{ .cond = try boxedExpr(a, .{ .binary = .{ .op = .gt, .l = try col(a, "k"), .r = try boxedExpr(a, .{ .lit = .{ .int = 1 } }) } }), .then = try col(a, "a"), .otherwise = try boxedExpr(a, try arrOp(a, "a", .reverse)) } });
        try testing.expectEqual(ColumnType.array, typeOf(ie, "o"));
        try testing.expect(fm.arraysConform(ie));
        const cc = try mutate(a, f, .{ .col = "a" });
        try testing.expectEqual(ColumnType.array, typeOf(cc, "o"));
        const to_l = try df.cast(a, f, .{ .col = "a", .to = .list });
        const back = try df.cast(a, to_l, .{ .col = "a", .to = .array, .array_width = 2 });
        try keptArray(back);
        try testing.expect(df.equals(f, back));
    }
}

test "fixed array: a verb that puts a value in an array column keeps its width (the cell is null when it does not fit, as a width number out of range)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try verbsFrame(a);
    // fillna with an int, with a list of the wrong length, with a list of the width
    const one = try df.readJson(a, "[{\"l\":[7,8]},{\"l\":[7]}]", .{});
    const fit = one.cell(0, "l").?;
    const short = one.cell(1, "l").?;
    const by_int = try df.fillna(a, f, .{ .subset = &.{"a"}, .value = .{ .int = 5 } });
    try keptArray(by_int);
    try testing.expect(by_int.cell(2, "a").? == .null);
    const by_short = try df.fillna(a, f, .{ .subset = &.{"a"}, .value = short });
    try keptArray(by_short);
    try testing.expect(by_short.cell(2, "a").? == .null);
    const by_fit = try df.fillna(a, f, .{ .subset = &.{"a"}, .value = fit });
    try keptArray(by_fit);
    try expectList(by_fit.cell(2, "a").?, &.{ 7, 8 });
    try expectList(by_fit.cell(0, "a").?, &.{ 2, 1 });
    // fillNull with a strategy keeps the arrays; a frame built with a row of another width is conformed
    try keptArray(try df.fillNull(a, f, .{ .subset = &.{"a"}, .strategy = .min }));
    const cols = try a.dupe(Column, &.{.{ .name = "a", .type = .array, .array_width = 2 }});
    var b = try fm.FrameBuilder.init(a, cols, 2);
    try b.appendRow(&.{fit});
    try b.appendRow(&.{short});
    const built = try b.toOwned();
    try testing.expect(fm.arraysConform(built));
    try expectList(built.cell(0, "a").?, &.{ 7, 8 });
    try testing.expect(built.cell(1, "a").? == .null);
}

// ── hostile: a column whose rows break the width, extreme widths ───────────

/// A column declared `.array` of width 2 whose rows are of every length (a hand-built frame:
/// the invariant `arraysConform` is the caller's, the verbs must still never panic).
fn hostile(a: std.mem.Allocator, declared: u32) !Frame {
    // built as a list column (the builder conforms an array column), declared an array after
    const cols = try a.dupe(Column, &.{ .{ .name = "a", .type = .list, .inner = &.{.{ .name = "", .type = .int }} }, .{ .name = "k", .type = .int } });
    var b = try fm.FrameBuilder.init(a, cols, 5);
    const lens = [_]?usize{ 0, 1, 2, 3, null };
    for (lens, 0..) |maybe, i| {
        const cell: Value = if (maybe) |n| blk: {
            const cells = try a.alloc(Value, n);
            for (cells, 0..) |*c, j| c.* = .{ .int = @intCast(j + 1) };
            const items = try a.create(fm.ColumnData);
            items.* = try fm.columnFromCells(a, cells);
            break :blk .{ .list = .{ .items = items, .start = 0, .end = @intCast(n) } };
        } else .null;
        try b.appendRow(&.{ cell, .{ .int = @intCast(i) } });
    }
    var f = try b.toOwned();
    const typed = try a.dupe(Column, f.columns);
    typed[0].type = .array;
    typed[0].array_width = declared;
    f.columns = typed;
    return f;
}

test "fixed array: hostile: an array column whose rows break the width: every verb errors or answers, none panics" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try hostile(a, 2);
    try testing.expect(!fm.arraysConform(f));
    _ = df.format(a, f, .{ .show_dtypes = true }) catch {};
    _ = df.glimpse(a, f, .{}) catch {};
    _ = verbs.takeRows(a, f, &.{ 4, 0, 0, 3 }) catch {};
    _ = df.filter(a, f, .{ .where = &.{.{ .col = "a", .op = .is_null }} }) catch {};
    _ = df.distinct(a, f, .{ .keys = &.{"a"} }) catch {};
    _ = df.sort(a, f, .{ .key = "a" }) catch {};
    _ = df.sort(a, f, .{ .key = "a", .dir = .desc }) catch {};
    _ = df.explode(a, f, &.{"a"}) catch {};
    _ = df.explodeAll(a, f) catch {};
    _ = df.concat(a, &.{ f, f }, .vertical) catch {};
    _ = df.join(a, f, f, .{ .on = "a", .how = .full }) catch {};
    _ = df.aggregate(a, f, .{ .group_by = &.{"a"}, .aggs = &.{.{ .src = "k", .out = "n", .func = .sum }} }) catch {};
    _ = df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "a", .out = "n", .func = .first }} }) catch {};
    _ = df.window(a, f, .{ .value_col = "a", .out = "o", .op = .{ .shift = .{ .n = 1 } } }) catch {};
    _ = df.transpose(a, try df.select(a, f, &.{"a"}), .{}) catch {};
    _ = df.valueCounts(a, f, .{ .cols = &.{"a"} }) catch {};
    _ = df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{"a"} }) catch {};
    _ = df.describeWith(a, f, .{ .cols = &.{"a"} }) catch {};
    _ = df.cast(a, f, .{ .col = "a", .to = .list }) catch {};
    _ = df.cast(a, f, .{ .col = "a", .to = .text }) catch {};
    _ = df.cast(a, f, .{ .col = "a", .to = .array, .array_width = 2 }) catch {};
    // the arr operations answer cell by cell (the schema says 2; a row of 3 is what it is)
    const ops = [_]df.ListOp{ .len, .first, .last, .sum, .reverse, .{ .get = 2 }, .{ .shift = 1 }, .{ .sort = .{} } };
    for (ops) |op| {
        const r = mutate(a, f, try arrOp(a, "a", op));
        // the array-typed results check their cells against the width: BadExpr, not a column that lies
        if (r) |g| {
            if (typeOf(g, "o") == .array) try testing.expect(fm.arraysConform(g));
        } else |e| try testing.expect(e == error.BadExpr);
    }
    // a bare column of rows that break the width cannot become an array result either
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .col = "a" }));
    // the dot of mismatched cells is null, never a crash
    const d = try mutate(a, f, .{ .arr_dot = .{ .l = try col(a, "a"), .r = try col(a, "a") } });
    try testing.expectEqual(@as(usize, 5), d.len);
}

test "fixed array: hostile: widths 0 and near u32 max, a huge get index" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // declared width 0 over empty rows only
    const z = try df.readJson(a, "[{\"a\":[]},{\"a\":null}]", .{ .types = &.{.{ .name = "a", .type = .array, .array_width = 0 }} });
    try testing.expect(fm.arraysConform(z));
    const ops = [_]df.ListOp{ .len, .first, .last, .sum, .mean, .min, .reverse, .{ .get = 0 }, .{ .get = -1 }, .{ .shift = 5 }, .unique, .any, .all, .arg_min, .n_unique, .{ .join = .{} } };
    for (ops) |op| {
        const g = try mutate(a, z, try arrOp(a, "a", op));
        try testing.expectEqual(@as(usize, 2), g.len);
        if (typeOf(g, "o") == .array) try testing.expect(fm.arraysConform(g));
    }
    try keptArray2(try df.explode(a, z, &.{"a"}), 2);
    // u32 max: a cast to it makes every row null (no row has that many elements); the schema keeps it
    const f = try verbsFrame(a);
    const l = try df.cast(a, f, .{ .col = "a", .to = .list });
    const huge = try df.cast(a, l, .{ .col = "a", .to = .array, .array_width = std.math.maxInt(u32) });
    try testing.expectEqual(std.math.maxInt(u32), widthOf(huge, "a"));
    try testing.expect(fm.arraysConform(huge));
    for (0..huge.len) |r| try testing.expect(huge.cell(r, "a").? == .null);
    try testing.expectError(error.CastFailed, df.cast(a, l, .{ .col = "a", .to = .array, .array_width = std.math.maxInt(u32), .on_error = .fail }));
    // arr.to_struct of that width: refused as too many fields, not allocated
    try testing.expectError(error.TooLarge, ex.mutate(a, l, &.{.{ .out = "o", .expr = .{ .arr_to_struct = .{ .x = try boxedExpr(a, .{ .cast = .{ .x = try col(a, "a"), .to = .array, .array_width = std.math.maxInt(u32) } }) } } }}));
    // a huge get index, every value of it
    const g = try verbsFrame(a);
    inline for (.{ std.math.maxInt(i64), std.math.minInt(i64), std.math.maxInt(i32) + 1, -3, 2 }) |ix| {
        const r = try mutate(a, g, try arrOp(a, "a", .{ .get = ix }));
        try testing.expectEqual(@as(usize, 5), r.len);
    }
    // the u32-wide cast of the array itself is refused when compiled (a width mismatch)
    try testing.expectError(error.BadExpr, mutate(a, g, .{ .cast = .{ .x = try col(a, "a"), .to = .array, .array_width = std.math.maxInt(u32) } }));
}

fn keptArray2(f: Frame, rows: usize) !void {
    try testing.expectEqual(rows, f.len);
    try testing.expect(fm.arraysConform(f));
}

test "fixed array: hostile: Assign.type array needs a schema that says an array; a nested array and a callback result keep their width" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try testing.expectError(error.BadExpr, ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .col = "id" }, .type = .array }}));
    const ok = try ex.mutate(a, f, &.{.{ .out = "o", .expr = .{ .col = "a" }, .type = .array }});
    try testing.expectEqual(@as(u32, 3), widthOf(ok, "o"));
    // an array of arrays: the inner column is itself an array of width 2
    const nested = try df.readJson(a, "[{\"m\":[[1,2],[3,4]]},{\"m\":null}]", .{ .types = &.{.{ .name = "m", .type = .array, .array_width = 2 }} });
    try testing.expect(fm.arraysConform(nested));
    const ex1 = try mutate(a, nested, try arrOp(a, "m", .first));
    try testing.expect(ex1.cell(0, "o").? == .list);
    try testing.expectEqual(@as(usize, 2), ex1.cell(0, "o").?.list.len());
}
