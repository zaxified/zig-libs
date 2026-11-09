// SPDX-License-Identifier: MIT
//! Replays `oracle2f_vectors.json` (dataframe S2 wave W8): what pandas 3.1 (Python `str`
//! methods) and polars 2.1 answered for the Unicode text functions: case mapping, `normalize`,
//! the `is*` classes, the `alpha`/`alphanumeric`/`digit` selectors and the name case verbs
//! (`tools/oracle2f.py` asked the engines; no line of this module is consulted there).
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const st = @import("structure.zig");
const nm = @import("names.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle2f_vectors.json");

/// Deliberate differences from what the engines answered: id substring and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "title-pl", .why = "polars `to_titlecase` treats an apostrophe as part of the word (They're); pandas and Python title() start a word after it (They'Re), and that is what `title` follows" },
    .{ .id = "unaccent-recipe", .why = "checked against the pandas NFKD recipe in a separate test on the cells both agree on (run below with the same vectors)" },
};

fn strOf(o: J, k: []const u8) ?[]const u8 {
    const v = o.object.get(k) orelse return null;
    return if (v == .string) v.string else null;
}

fn jcell(j: J) Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .string => |s| .{ .text = s },
        else => .null,
    };
}

fn textFrame(a: std.mem.Allocator, arr: []const J) !Frame {
    const cs = try a.alloc(Value, arr.len);
    for (cs, arr) |*c, j| c.* = jcell(j);
    const cols = try a.alloc(Column, 1);
    cols[0] = .{ .name = "x", .type = .text };
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cs);
    return .{ .columns = cols, .data = data, .len = arr.len };
}

fn same(want: J, got: Value) bool {
    return switch (want) {
        .null => got == .null,
        .bool => |b| got == .bool and got.bool == b,
        .string => |s| got == .text and std.mem.eql(u8, got.text, s),
        else => false,
    };
}

var fails: usize = 0;
var ran: usize = 0;

fn fail(id: []const u8, comptime fmt: []const u8, args: anytype) void {
    fails += 1;
    std.debug.print("MISMATCH {s}: " ++ fmt ++ "\n", .{id} ++ args);
}

fn isKnown(id: []const u8) bool {
    for (known) |k| if (std.mem.find(u8, id, k.id) != null) return true;
    return false;
}

fn runExpr(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const texts = c.object.get("cols").?.object.get("x").?.array.items;
    const f = try textFrame(a, texts);
    const op = strOf(c, "op").?;
    const x = try a.create(ex.Expr);
    x.* = .{ .col = "x" };
    const e: ex.Expr = if (std.mem.eql(u8, op, "normalize"))
        .{ .normalize = .{ .x = x, .form = std.meta.stringToEnum(ex.NormalForm, strOf(c, "form").?).? } }
    else
        .{ .unary = .{ .op = std.meta.stringToEnum(ex.Unary, op).?, .x = x } };
    const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
    const s = out.series("o") orelse return fail(id, "no output", .{});
    const want = c.object.get("expect").?.array.items;
    for (want, 0..) |w, i| {
        if (!same(w, s.get(i))) fail(id, "input {any}: got {any}, want {any}", .{ texts[i], s.get(i), w });
    }
}

fn namesFrame(a: std.mem.Allocator, names: []const J) !Frame {
    const cols = try a.alloc(Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    for (cols, data, names) |*cc, *d, n| {
        cc.* = .{ .name = n.string, .type = .int };
        d.* = try fm.columnFromCells(a, &.{.{ .int = 1 }});
    }
    return .{ .columns = cols, .data = data, .len = 1 };
}

fn runSelector(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try namesFrame(a, c.object.get("names").?.array.items);
    const sel_name = strOf(c, "sel").?;
    const sel: st.Selector = if (std.mem.eql(u8, sel_name, "alpha")) .alpha else if (std.mem.eql(u8, sel_name, "alphanumeric")) .alphanumeric else .digit;
    const got = try st.selectColumns(a, f, sel);
    const want = c.object.get("expect").?.array.items;
    if (got.len != want.len) return fail(id, "picked {d} names, want {d}", .{ got.len, want.len });
    for (got, want) |g, w| if (!std.mem.eql(u8, g, w.string)) fail(id, "picked {s}, want {s}", .{ g, w.string });
}

fn runRename(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const names = c.object.get("names").?.array.items;
    const lower = std.mem.eql(u8, strOf(c, "op").?, "lower");
    const want = c.object.get("expect").?.array.items;
    // One column per frame: two names may map to the same one (`straße` / `STRASSE`).
    for (names, want) |n, w| {
        const f = try namesFrame(a, &.{n});
        const r = if (lower) try nm.renameLower(a, f, .all) else try nm.renameUpper(a, f, .all);
        if (!std.mem.eql(u8, r.columns[0].name, w.string)) fail(id, "{s}: got {s}, want {s}", .{ n.string, r.columns[0].name, w.string });
    }
}

test "oracle2f: replay the engines' answers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    fails = 0;
    ran = 0;
    for (root.array.items) |c| {
        const id = strOf(c, "id").?;
        if (isKnown(id)) continue;
        const kind = strOf(c, "kind").?;
        const r = if (std.mem.eql(u8, kind, "expr")) runExpr(a, c) else if (std.mem.eql(u8, kind, "selector")) runSelector(a, c) else runRename(a, c);
        r catch |e| fail(id, "error {s}", .{@errorName(e)});
        ran += 1;
    }
    std.debug.print("oracle2f: {d} cases replayed, {d} mismatches\n", .{ ran, fails });
    try testing.expect(ran > 20);
    try testing.expectEqual(@as(usize, 0), fails);
}

test "oracle2f: unaccent against the pandas NFKD recipe" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    var seen = false;
    for (root.array.items) |c| {
        if (!std.mem.eql(u8, strOf(c, "id").?, "unaccent-recipe")) continue;
        seen = true;
        const before = fails;
        try runExpr(a, c);
        try testing.expectEqual(before, fails);
    }
    try testing.expect(seen);
}
