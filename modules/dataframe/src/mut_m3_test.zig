// SPDX-License-Identifier: MIT
//! S3 steps 3 and 4 mutation run (group M3, 2026-11-08): `listfn.zig`, `nestverbs.zig`,
//! `callback.zig` and the step 3/4 parts of `expr.zig`, `core.zig`, `verbs.zig`,
//! `window.zig`. One test per surviving mutant that is not equivalent. Test names end
//! "(mut <id>)"; each id is a mutant of `s3-mut-m3`, killed by its test.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const lf = @import("listfn.zig");
const nv = @import("nestverbs.zig");
const cb = @import("callback.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");

const Value = df.Value;
const Frame = df.Frame;
const Column = df.Column;
const ColumnData = df.ColumnData;
const Expr = df.Expr;

const null_v: Value = .null;

fn int(x: i64) Value {
    return .{ .int = x };
}

fn flt(x: f64) Value {
    return .{ .float = x };
}

fn txt(s: []const u8) Value {
    return .{ .text = s };
}

fn list(a: std.mem.Allocator, cells: []const Value) !Value {
    return lf.makeList(a, cells);
}

/// An allocator that fills every fresh allocation with 0x01 (a valid `true`, a tiny
/// float, a small-ish integer): memory a function forgot to initialise is then wrong
/// on every run, not zero by luck of a fresh page.
const Poison = struct {
    backing: std.mem.Allocator,

    fn allocator(p: *Poison) std.mem.Allocator {
        return .{ .ptr = p, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const p: *Poison = @ptrCast(@alignCast(ctx));
        const r = p.backing.rawAlloc(len, alignment, ra) orelse return null;
        @memset(r[0..len], 0x01);
        return r;
    }
    fn resize(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) bool {
        const p: *Poison = @ptrCast(@alignCast(ctx));
        return p.backing.rawResize(m, alignment, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const p: *Poison = @ptrCast(@alignCast(ctx));
        return p.backing.rawRemap(m, alignment, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const p: *Poison = @ptrCast(@alignCast(ctx));
        p.backing.rawFree(m, alignment, ra);
    }
};

fn expectInts(want: []const i64, v: Value) !void {
    try testing.expect(v == .list);
    try testing.expectEqual(want.len, v.list.len());
    for (want, 0..) |w, i| try testing.expectEqual(w, v.list.get(i).int);
}

// ── listfn ──────────────────────────────────────────────────────────────────

test "list contains null: a NaN is not null (mut 20012; 20011 is equivalent)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = list(a, &.{flt(std.math.nan(f64))}) catch unreachable;
    const r = try lf.listCell(a, nan, .{ .contains = .null });
    try testing.expectEqual(false, r.bool);
    const c = try lf.listCell(a, nan, .{ .count_matches = .null });
    try testing.expectEqual(@as(i64, 0), c.int);
    // 20011 (the `item == .null` shortcut) is `e.eql(.null)`, which is `e == .null` for
    // every kind of element: the differential below pins that.
    const kinds = [_]Value{ .null, int(0), flt(0), flt(std.math.nan(f64)), .{ .bool = false }, txt(""), .{ .decimal = 0 }, nan };
    for (kinds) |k| try testing.expectEqual(k == .null, k.eql(.null));
}

test "list.join: the text cap is exact (mut 20018, 20019)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const chunk = try a.alloc(u8, 1 << 16);
    @memset(chunk, 'x');
    const per = (1 << 24) / chunk.len;
    const cells = try a.alloc(Value, per + 1);
    for (cells) |*c| c.* = txt(chunk);
    const exact = try list(a, cells[0..per]);
    const r = try lf.listCell(a, exact, .{ .join = .{ .sep = "" } });
    try testing.expectEqual(@as(usize, 1 << 24), r.text.len);
    const over = try list(a, cells);
    try testing.expectError(error.TooLarge, lf.listCell(a, over, .{ .join = .{ .sep = "" } }));
    // The separators count too.
    const half = try a.alloc(u8, 1 << 23);
    @memset(half, 'y');
    const two = try list(a, &.{ txt(half), txt(half[0 .. half.len - 1]) });
    try testing.expectError(error.TooLarge, lf.listCell(a, two, .{ .join = .{ .sep = "yy" } }));
}

test "list.sum: overflow is sticky per running total (mut 20023, 20024, 20025, 20029)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const max = std.math.maxInt(i64);
    const l1 = try list(a, &.{ int(max), int(1), int(0) });
    try testing.expect((try lf.listCell(a, l1, .sum)) == .null);
    const dmax: Value = .{ .decimal = std.math.maxInt(i128) };
    // int after a decimal that overflows the i128 total, then one that does not.
    const l2 = try list(a, &.{ dmax, int(1), int(0) });
    try testing.expect((try lf.listCell(a, l2, .sum)) == .null);
    const l3 = try list(a, &.{ dmax, .{ .decimal = 1 }, .{ .decimal = 0 } });
    try testing.expect((try lf.listCell(a, l3, .sum)) == .null);
    const l4 = try list(a, &.{ dmax, .{ .decimal = 1 } });
    try testing.expect((try lf.listCell(a, l4, .sum)) == .null);
}

test "list.sum: a decimal after a float stays float (mut 20026)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try list(a, &.{ flt(1.5), .{ .decimal = 2 * vm.decimal_scale } });
    const r = try lf.listCell(a, l, .sum);
    try testing.expect(r == .float);
    try testing.expectEqual(@as(f64, 3.5), r.float);
}

test "list min/max/arg_*: a tie keeps the first element (mut 20038, 20039)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try list(a, &.{ int(1), flt(1.0) });
    try testing.expect((try lf.listCell(a, l, .min)) == .int);
    try testing.expect((try lf.listCell(a, l, .max)) == .int);
    try testing.expectEqual(@as(i64, 0), (try lf.listCell(a, l, .arg_min)).int);
    try testing.expectEqual(@as(i64, 0), (try lf.listCell(a, l, .arg_max)).int);
}

test "list.median skips the missing elements it did not store (mut 20043)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var p: Poison = .{ .backing = arena.allocator() };
    const a = p.allocator();
    const l = try list(arena.allocator(), &.{ int(1), .null, int(3), flt(std.math.nan(f64)) });
    const r = try lf.listCell(a, l, .median);
    try testing.expectEqual(@as(f64, 2), r.float);
}

test "list.unique and n_unique initialise their first-seen marks (mut 20051)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var p: Poison = .{ .backing = arena.allocator() };
    const a = p.allocator();
    const l = try list(arena.allocator(), &.{ int(1), int(1), int(2), int(1), .null, .null });
    const u = try lf.listCell(a, l, .unique);
    try testing.expectEqual(@as(usize, 3), u.list.len());
    try testing.expectEqual(@as(i64, 3), (try lf.listCell(a, l, .n_unique)).int);
}

test "list.slice: offset 0, the length clamp, a view that does not start at 0 (mut 20056, 20058, 20061, 20062)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const all = try list(a, &.{ int(1), int(2), int(3), int(7), int(8), int(9) });
    const items = all.list.items;
    const row0: Value = .{ .list = .{ .items = items, .start = 0, .end = 3 } };
    const row1: Value = .{ .list = .{ .items = items, .start = 3, .end = 6 } };
    try expectInts(&.{ 1, 2 }, try lf.listCell(a, row0, .{ .slice = .{ .offset = 0, .length = 2 } }));
    // The length is clamped to what is left, not to the whole list.
    try expectInts(&.{ 2, 3 }, try lf.listCell(a, row0, .{ .slice = .{ .offset = 1, .length = 100 } }));
    try expectInts(&.{ 8, 9 }, try lf.listCell(a, row1, .{ .slice = .{ .offset = 1, .length = 100 } }));
    try expectInts(&.{ 7, 8 }, try lf.listCell(a, row1, .{ .slice = .{ .offset = 0, .length = 2 } }));
    try expectInts(&.{ 8, 9 }, try lf.listCell(a, row1, .{ .slice = .{ .offset = -2 } }));
    // The view's end is as far from the items' start as its own start (mut 20062).
    const mid: Value = .{ .list = .{ .items = items, .start = 3, .end = 5 } };
    try expectInts(&.{7}, try lf.listCell(a, mid, .{ .slice = .{ .offset = 0, .length = 1 } }));
}

test "list.head and tail on a view past the list's end (mut 20063, 20065)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const all = try list(a, &.{ int(1), int(2), int(3), int(7), int(8), int(9) });
    const row0: Value = .{ .list = .{ .items = all.list.items, .start = 0, .end = 3 } };
    try expectInts(&.{ 1, 2, 3 }, try lf.listCell(a, row0, .{ .head = 5 }));
    try expectInts(&.{ 1, 2, 3 }, try lf.listCell(a, row0, .{ .tail = 5 }));
    const empty: Value = .{ .list = .{ .items = all.list.items, .start = 2, .end = 2 } };
    try testing.expectEqual(@as(usize, 0), (try lf.listCell(a, empty, .{ .head = 0 })).list.len());
    try testing.expectEqual(@as(usize, 0), (try lf.listCell(a, empty, .{ .head = 3 })).list.len());
}

test "list.sort descending keeps equal elements in order (mut 20070)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try list(a, &.{ int(1), flt(1.0), int(1), flt(1.0), int(1), flt(1.0), int(2), flt(1.0) });
    const r = try lf.listCell(a, l, .{ .sort = .{ .descending = true } });
    try testing.expectEqual(@as(i64, 2), r.list.get(0).int);
    // Stable: the five equal 1s come out in input order int, float, int, float, ...
    const tags = [_]std.meta.Tag(Value){ .int, .float, .int, .float, .int, .float, .float };
    for (tags, 1..) |t, i| try testing.expectEqual(t, std.meta.activeTag(r.list.get(i)));
}

test "list.drop_nulls keeps a NaN (mut 20072)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try list(a, &.{ int(1), .null, flt(std.math.nan(f64)), int(2) });
    const r = try lf.listCell(a, l, .drop_nulls);
    try testing.expectEqual(@as(usize, 3), r.list.len());
    try testing.expect(std.math.isNan(r.list.get(1).float));
}

test "concat_list: parts that together pass u32 are TooLarge (mut 20078)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nulls: ColumnData = .nulls;
    // Three lists claiming 2^31 elements each (a view over no storage): 3 x 2^31 > 2^32.
    const big: Value = .{ .list = .{ .items = &nulls, .start = 0, .end = 1 << 31 } };
    try testing.expectError(error.TooLarge, lf.concatList(a, &.{ big, big, big }));
}

test "split: literal separators, limits and inclusive pieces (mut 20083, 20085, 20087)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const chars = try lf.splitLiteral(a, "abcd", "", false, 2);
    try testing.expectEqual(@as(usize, 2), chars.list.len());
    try testing.expectEqualStrings("a", chars.list.get(0).text);
    try testing.expectEqualStrings("bcd", chars.list.get(1).text);
    const one = try lf.splitLiteral(a, "abcd", "", false, 1);
    try testing.expectEqual(@as(usize, 1), one.list.len());
    try testing.expectEqualStrings("abcd", one.list.get(0).text);
    // A separator longer than one byte that overlaps itself: "aaaa" by "aa" is 3 pieces.
    const over = try lf.splitLiteral(a, "aaaaa", "aa", false, null);
    try testing.expectEqual(@as(usize, 3), over.list.len());
    try testing.expectEqualStrings("", over.list.get(0).text);
    try testing.expectEqualStrings("", over.list.get(1).text);
    try testing.expectEqualStrings("a", over.list.get(2).text);
    const lim = try lf.splitLiteral(a, "a,b,c,d", ",", false, 2);
    try testing.expectEqual(@as(usize, 2), lim.list.len());
    try testing.expectEqualStrings("b,c,d", lim.list.get(1).text);
}

// ── nestverbs ───────────────────────────────────────────────────────────────

const fz = @import("fuzz.zig");

fn listFrame(cols: []const Column, data: []const ColumnData, len: usize) Frame {
    return .{ .columns = cols, .data = data, .len = len };
}

test "explode: a frame past the u32 row bound is TooLarge at once (mut 20200)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = listFrame(&.{.{ .name = "xs", .type = .list }}, &.{.nulls}, std.math.maxInt(u32));
    try testing.expectError(error.TooLarge, df.explode(arena.allocator(), f, &.{"xs"}));
}

test "explode: which storage a declared list column may have (mut 20203, 20204, 20205, 20222, 20223)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Declared list over int storage: not a list.
    const ints = listFrame(&.{.{ .name = "xs", .type = .list }}, &.{.{ .int = .{ .values = &.{ 1, 2 } } }}, 2);
    try testing.expectError(error.NotNested, df.explode(a, ints, &.{"xs"}));
    // Declared list over no storage: every row null, one row each.
    const nulls = listFrame(&.{.{ .name = "xs", .type = .list }}, &.{.nulls}, 2);
    const en = try df.explode(a, nulls, &.{"xs"});
    try testing.expectEqual(@as(usize, 2), en.len);
    try testing.expect(fz.wellFormed(en));
    // Declared list over mixed cells: a list gives its elements, an empty list and a
    // null one null, a scalar itself.
    const l12 = try list(a, &.{ int(1), int(2) });
    const l0 = try list(a, &.{});
    const cells = [_]Value{ l12, l0, int(7), .null };
    const boxed = listFrame(&.{.{ .name = "xs", .type = .list }}, &.{.{ .boxed = &cells }}, 4);
    const eb = try df.explode(a, boxed, &.{"xs"});
    try testing.expectEqual(@as(usize, 5), eb.len);
    try testing.expect(fz.wellFormed(eb));
    const want = [_]?i64{ 1, 2, null, 7, null };
    for (want, 0..) |w, i| {
        const v = eb.cell(i, "xs").?;
        if (w) |x| try testing.expectEqual(x, v.int) else try testing.expect(v == .null);
    }
}

test "explode: a list column's declared element type and its inner columns (mut 20216, 20217)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const items: ColumnData = .{ .int = .{ .values = &.{ 1, 2 } } };
    const lc: ColumnData = .{ .list = .{ .offsets = &.{ 0, 2 }, .items = &items } };
    // A malformed schema (two element columns) is not trusted: the storage decides.
    const two = listFrame(&.{.{ .name = "xs", .type = .list, .inner = &.{ .{ .name = "", .type = .text }, .{ .name = "", .type = .text } } }}, &.{lc}, 1);
    const e2 = try df.explode(a, two, &.{"xs"});
    try testing.expectEqual(df.ColumnType.int, e2.columnType("xs").?);
    // One declared element column: its type and its own inner columns carry over.
    const el: Column = .{ .name = "", .type = .@"struct", .inner = &.{.{ .name = "k", .type = .int }} };
    const one = listFrame(&.{.{ .name = "xs", .type = .list, .inner = &.{el} }}, &.{lc}, 1);
    const e1 = try df.explode(a, one, &.{"xs"});
    try testing.expectEqual(df.ColumnType.@"struct", e1.columns[0].type);
    try testing.expectEqual(@as(usize, 1), e1.columns[0].inner.len);
    try testing.expectEqualStrings("k", e1.columns[0].inner[0].name);
}

test "storageType: each storage kind names its type (mut 20224 .. 20241)" {
    const st = nv.storageType;
    try testing.expectEqual(df.ColumnType.float, st(.nulls));
    try testing.expectEqual(df.ColumnType.int, st(.{ .int = .{ .values = &.{} } }));
    try testing.expectEqual(df.ColumnType.float, st(.{ .float = .{ .values = &.{} } }));
    try testing.expectEqual(df.ColumnType.bool, st(.{ .bool = .{ .values = &.{} } }));
    try testing.expectEqual(df.ColumnType.decimal, st(.{ .decimal = .{ .values = &.{} } }));
    try testing.expectEqual(df.ColumnType.text, st(.{ .text = .{ .offsets = &.{0}, .bytes = "" } }));
    const dict: fm.TextColumn = .{ .offsets = &.{0}, .bytes = "" };
    try testing.expectEqual(df.ColumnType.categorical, st(.{ .categorical = .{ .codes = .{ .values = &.{} }, .dict = dict } }));
    const items: ColumnData = .nulls;
    try testing.expectEqual(df.ColumnType.list, st(.{ .list = .{ .offsets = &.{0}, .items = &items } }));
    const sc: fm.StructColumn = .{ .names = &.{}, .children = &.{}, .len = 0 };
    try testing.expectEqual(df.ColumnType.@"struct", st(.{ .@"struct" = &sc }));
    // A mix: by its first present cell; none present, float.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rec = try lf.makeRecord(a, &.{"a"}, &.{int(1)});
    const l = try list(a, &.{int(1)});
    const probes = [_]struct { Value, df.ColumnType }{
        .{ int(1), .int },
        .{ flt(1), .float },
        .{ .{ .bool = true }, .bool },
        .{ .{ .decimal = 1 }, .decimal },
        .{ txt("x"), .text },
        .{ l, .list },
        .{ rec, .@"struct" },
    };
    for (probes) |p| {
        const cells = [_]Value{ .null, p[0] };
        try testing.expectEqual(p[1], st(.{ .boxed = &cells }));
    }
    const none = [_]Value{ .null, .null };
    try testing.expectEqual(df.ColumnType.float, st(.{ .boxed = &none }));
    try testing.expectEqual(df.ColumnType.float, st(.{ .boxed = &.{} }));
}

fn structFrame(a: std.mem.Allocator, cols: []const Column, children: []const ColumnData, len: usize, frame_len: usize) !Frame {
    const names = try a.alloc([]const u8, children.len);
    for (names, 0..) |*n, i| n.* = if (i == 0) "a" else "b";
    const sc = try a.create(fm.StructColumn);
    sc.* = .{ .names = names, .children = children, .len = len };
    const data = try a.alloc(ColumnData, 1);
    data[0] = .{ .@"struct" = sc };
    return .{ .columns = cols, .data = data, .len = frame_len };
}

test "unnest: a field shorter than the frame is rebuilt, never shared (mut 20259 .. 20273)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const one_nulls: ColumnData = .nulls;
    const sc1: fm.StructColumn = .{ .names = &.{"z"}, .children = &.{.{ .int = .{ .values = &.{5} } }}, .len = 1 };
    const kids = [_]ColumnData{
        .{ .int = .{ .values = &.{1} } },
        .{ .float = .{ .values = &.{1.0} } },
        .{ .bool = .{ .values = &.{true} } },
        .{ .decimal = .{ .values = &.{1} } },
        .{ .text = .{ .offsets = &.{ 0, 1 }, .bytes = "x" } },
        .{ .categorical = .{ .codes = .{ .values = &.{0} }, .dict = .{ .offsets = &.{ 0, 1 }, .bytes = "x" } } },
        .{ .list = .{ .offsets = &.{ 0, 1 }, .items = &one_nulls } },
        .{ .@"struct" = &sc1 },
        .{ .boxed = &.{int(1)} },
    };
    const cols = [_]Column{.{ .name = "p", .type = .@"struct" }};
    for (kids) |k| {
        // The frame has 2 rows, the struct column and its one field only 1.
        const f = try structFrame(a, &cols, &.{k}, 2, 2);
        const u = try df.unnest(a, f, .{ .cols = &.{"p"} });
        try testing.expectEqual(@as(usize, 2), u.len);
        try testing.expect(fz.wellFormed(u));
        // A struct column of one row in a frame of two: the second row is null.
        try testing.expect(u.cell(1, "a").? == .null);
        // The same field in a struct column of the frame's own length is shared as it is.
        const g = try structFrame(a, &cols, &.{k}, 1, 1);
        const v = try df.unnest(a, g, .{ .cols = &.{"p"} });
        try testing.expect(fz.wellFormed(v));
        try testing.expectEqual(std.meta.activeTag(k), std.meta.activeTag(v.data[0]));
    }
    // A name with no stored child (a hand-built struct with fewer children): null.
    const short = try structFrame(a, &cols, &.{}, 1, 1);
    const names2 = try a.dupe([]const u8, &.{ "a", "b" });
    const sc2 = try a.create(fm.StructColumn);
    sc2.* = .{ .names = names2, .children = short.data[0].@"struct".children, .len = 1 };
    const data2 = try a.dupe(ColumnData, &.{.{ .@"struct" = sc2 }});
    const h = try df.unnest(a, .{ .columns = &cols, .data = data2, .len = 1 }, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(usize, 2), h.columns.len);
    try testing.expect(h.cell(0, "b").? == .null);
    try testing.expect(fz.wellFormed(h));
}

test "unnest: a struct column with a null record gives null fields, not the child's cell (mut 20260)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sc = try a.create(fm.StructColumn);
    sc.* = .{ .names = &.{"a"}, .children = &.{.{ .int = .{ .values = &.{ 1, 2 } } }}, .len = 2, .valid = &.{0b01} };
    const f: Frame = .{ .columns = &.{.{ .name = "p", .type = .@"struct" }}, .data = &.{.{ .@"struct" = sc }}, .len = 2 };
    const u = try df.unnest(a, f, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(i64, 1), u.cell(0, "a").?.int);
    try testing.expect(u.cell(1, "a").? == .null);
}

test "unnest: which storage a declared struct column may have (mut 20243, 20244, 20245)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inner = [_]Column{.{ .name = "a", .type = .int }};
    const cols = [_]Column{.{ .name = "p", .type = .@"struct", .inner = &inner }};
    const ints = listFrame(&cols, &.{.{ .int = .{ .values = &.{ 1, 2 } } }}, 2);
    try testing.expectError(error.NotNested, df.unnest(a, ints, .{ .cols = &.{"p"} }));
    const nulls = listFrame(&cols, &.{.nulls}, 2);
    const un = try df.unnest(a, nulls, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(usize, 1), un.columns.len);
    try testing.expectEqual(df.ColumnType.int, un.columns[0].type);
    const rec = try lf.makeRecord(a, &.{"a"}, &.{int(4)});
    const cells = [_]Value{ rec, .null };
    const boxed = listFrame(&cols, &.{.{ .boxed = &cells }}, 2);
    const ub = try df.unnest(a, boxed, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(i64, 4), ub.cell(0, "a").?.int);
    try testing.expect(ub.cell(1, "a").? == .null);
}

test "unnest: declared field types and inner columns win over the storage's (mut 20248, 20249)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const deep: Column = .{ .name = "a", .type = .@"struct", .inner = &.{.{ .name = "z", .type = .int }} };
    const cols = [_]Column{.{ .name = "p", .type = .@"struct", .inner = &.{deep} }};
    const sc = try a.create(fm.StructColumn);
    sc.* = .{ .names = &.{"a"}, .children = &.{.{ .int = .{ .values = &.{ 1, 2 } } }}, .len = 2 };
    const f: Frame = .{ .columns = &cols, .data = &.{.{ .@"struct" = sc }}, .len = 2 };
    const u = try df.unnest(a, f, .{ .cols = &.{"p"} });
    try testing.expectEqual(df.ColumnType.@"struct", u.columns[0].type);
    try testing.expectEqual(@as(usize, 1), u.columns[0].inner.len);
    // The separator joins the column name and the field name, in that order.
    const s = try df.unnest(a, f, .{ .cols = &.{"p"}, .separator = "::" });
    try testing.expectEqualStrings("p::a", s.columns[0].name);
}

test "unnest: a mix's field names are the declared ones, once, then the stored ones (mut 20253, 20254)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const decl = [_]Column{ .{ .name = "b", .type = .int }, .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    const cols = [_]Column{.{ .name = "p", .type = .@"struct", .inner = &decl }};
    const r1 = try lf.makeRecord(a, &.{ "a", "c" }, &.{ int(1), int(2) });
    const cells = [_]Value{ r1, .null };
    const f = listFrame(&cols, &.{.{ .boxed = &cells }}, 2);
    const u = try df.unnest(a, f, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(usize, 3), u.columns.len);
    try testing.expectEqualStrings("b", u.columns[0].name);
    try testing.expectEqualStrings("a", u.columns[1].name);
    try testing.expectEqualStrings("c", u.columns[2].name);
    try testing.expectEqual(@as(i64, 1), u.cell(0, "a").?.int);
    try testing.expectEqual(@as(i64, 2), u.cell(0, "c").?.int);
}

test "unnest: mixed records with more than 65536 field names are TooLarge (mut 20257)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = nv.max_unnest_fields + 1;
    const names = try a.alloc([]const u8, n);
    const vals = try a.alloc(Value, n);
    for (names, vals, 0..) |*nm, *v, i| {
        nm.* = try std.fmt.allocPrint(a, "f{d}", .{i});
        v.* = int(1);
    }
    const rec = try lf.makeRecord(a, names, vals);
    const cells = [_]Value{rec};
    const f = listFrame(&.{.{ .name = "p", .type = .@"struct" }}, &.{.{ .boxed = &cells }}, 1);
    try testing.expectError(error.TooLarge, df.unnest(a, f, .{ .cols = &.{"p"} }));
}

// ── callback ────────────────────────────────────────────────────────────────

const Ret = struct {
    fn value(ctx: Value, _: std.mem.Allocator, _: Value) Value {
        return ctx;
    }
    fn row(ctx: Value, _: std.mem.Allocator, _: cb.Row) Value {
        return ctx;
    }
    fn window(ctx: Value, _: std.mem.Allocator, _: []const Value) Value {
        return ctx;
    }
    fn group(_: void, _: std.mem.Allocator, g: Frame) Frame {
        return g;
    }
    fn keep(_: void, _: std.mem.Allocator, _: Frame) bool {
        return true;
    }
};

fn xFrame(a: std.mem.Allocator) !Frame {
    return df.readJson(a, "[{\"x\":1},{\"x\":2},{\"x\":3}]", .{});
}

test "mapElements: a result of another type than the declared one is WrongOutputType (mut 20301, 20302, 20306, 20307, 20308)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    const bad = [_]struct { df.ColumnType, Value }{
        .{ .int, flt(1.5) },
        .{ .int, txt("x") },
        .{ .timestamp, flt(1.5) },
        .{ .float, txt("x") },
        .{ .text, int(1) },
        .{ .bool, int(1) },
        .{ .decimal, int(1) },
        .{ .list, int(1) },
        .{ .@"struct", int(1) },
    };
    for (bad) |b| {
        const r = cb.mapElements(a, f, .{ .col = "x", .out = .{ .type = b[0] } }, b[1], Ret.value);
        try testing.expectError(error.WrongOutputType, r);
    }
    // And a null is every type's.
    const ok = try cb.mapElements(a, f, .{ .col = "x", .out = .{ .type = .decimal } }, null_v, Ret.value);
    try testing.expect(ok.cell(0, "x").? == .null);
}

test "mapElements: the undeclared result type follows the cells (mut 20312, 20313, 20316, 20317; 20315 is equivalent)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    const rec = try lf.makeRecord(a, &.{"k"}, &.{int(1)});
    const l = try list(a, &.{int(1)});
    const probes = [_]struct { Value, df.ColumnType }{
        .{ int(1), .int },
        .{ flt(1), .float },
        .{ .{ .bool = true }, .bool },
        .{ .{ .decimal = 5 }, .decimal },
        .{ txt("t"), .text },
        .{ l, .list },
        .{ rec, .@"struct" },
    };
    for (probes) |p| {
        const r = try cb.mapElements(a, f, .{ .col = "x" }, p[0], Ret.value);
        try testing.expectEqual(p[1], r.columnType("x").?);
        try testing.expect(fz.wellFormed(r));
    }
    // 20315: `inferred(.categorical)` is unreachable, the builders never make that
    // storage (`ColBuilder.finish` has no categorical kind); a declared categorical is
    // encoded after the inference, which the next check pins.
    const c = try cb.mapElements(a, f, .{ .col = "x", .out = .{ .type = .categorical } }, txt("t"), Ret.value);
    try testing.expect(c.column("x").? == .categorical);
}

fn backwards(items: *const ColumnData) Value {
    return .{ .list = .{ .items = items, .start = 5, .end = 2 } };
}

test "mapElements: list views a callback builds by hand (mut 20320, 20322, 20323)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    const nulls: ColumnData = .nulls;
    // An empty view (start == end) is a list like any other.
    const empty: Value = .{ .list = .{ .items = &nulls, .start = 3, .end = 3 } };
    const e = try cb.mapElements(a, f, .{ .col = "x" }, empty, Ret.value);
    try testing.expectEqual(@as(usize, 0), e.cell(0, "x").?.list.len());
    // A backwards view inside a record is refused, as one inside a list is.
    const kid: ColumnData = .{ .boxed = &.{backwards(&nulls)} };
    const sc: fm.StructColumn = .{ .names = &.{"k"}, .children = &.{kid}, .len = 1 };
    const rec: Value = .{ .record = .{ .fields = &sc, .row = 0 } };
    try testing.expectError(error.WrongOutputType, cb.mapElements(a, f, .{ .col = "x" }, rec, Ret.value));
    // Past `max_nesting_depth` a value reads as null, so a backwards view down there is
    // never read: the cell is accepted, cut off at the bound.
    const deep_n = vm.max_nesting_depth + 2;
    var cur: Value = backwards(&nulls);
    for (0..deep_n) |_| {
        const box = try a.create(ColumnData);
        const cells = try a.alloc(Value, 1);
        cells[0] = cur;
        box.* = .{ .boxed = cells };
        cur = .{ .list = .{ .items = box, .start = 0, .end = 1 } };
    }
    const d = try cb.mapElements(a, f, .{ .col = "x" }, cur, Ret.value);
    try testing.expect(d.cell(0, "x").? == .list);
}

test "callbacks: a frame past the u32 row bound is TooLarge before any call (mut 20330, 20336, 20340, 20360, 20380)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &.{.nulls}, .len = std.math.maxInt(u32) };
    try testing.expectError(error.TooLarge, cb.mapElements(a, f, .{ .col = "x" }, null_v, Ret.value));
    try testing.expectError(error.TooLarge, cb.mapRows(a, f, .{ .out = "r" }, null_v, Ret.row));
    try testing.expectError(error.TooLarge, cb.rollingMap(a, f, .{ .col = "x", .window = 2 }, null_v, Ret.window));
    // With no window the work count is 0, so only the row bound stops the verb.
    try testing.expectError(error.TooLarge, cb.rollingMap(a, f, .{ .col = "x", .window = 0 }, null_v, Ret.window));
    try testing.expectError(error.TooLarge, cb.mapGroups(a, f, .{ .by = &.{} }, {}, Ret.group));
    try testing.expectError(error.TooLarge, cb.filterGroups(a, f, .{ .by = &.{} }, {}, Ret.keep));
}

const Count = struct {
    n: usize = 0,
    fn call(c: *Count, _: std.mem.Allocator, v: Value) Value {
        c.n += 1;
        return v;
    }
    fn group(c: *Count, _: std.mem.Allocator, g: Frame) Frame {
        c.n += 1;
        return g;
    }
};

test "mapElements: skip_missing skips a NaN as it skips a null (mut 20332)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{
        .columns = &.{.{ .name = "x", .type = .float }},
        .data = &.{.{ .float = .{ .values = &.{ 1.0, std.math.nan(f64), 2.0 } } }},
        .len = 3,
    };
    var c: Count = .{};
    const r = try cb.mapElements(a, f, .{ .col = "x" }, &c, Count.call);
    try testing.expectEqual(@as(usize, 2), c.n);
    try testing.expect(r.cell(1, "x").? == .null);
    var c2: Count = .{};
    _ = try cb.mapElements(a, f, .{ .col = "x", .skip_missing = false }, &c2, Count.call);
    try testing.expectEqual(@as(usize, 3), c2.n);
}

fn sumWindow(_: void, _: std.mem.Allocator, w: []const Value) Value {
    var s: i64 = 0;
    for (w) |v| s += v.int;
    return .{ .int = s };
}

test "rollingMap: an even window centres with the lead (w - 1) / 2 (mut 20345)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"x\":1},{\"x\":2},{\"x\":3},{\"x\":4},{\"x\":5},{\"x\":6}]", .{});
    const r = try cb.rollingMap(a, f, .{ .col = "x", .window = 4, .min_periods = 1, .center = true }, {}, sumWindow);
    const want = [_]i64{ 3, 6, 10, 14, 18, 15 };
    for (want, 0..) |w, i| try testing.expectEqual(w, r.cell(i, "x").?.int);
}

const Buf = struct {
    bytes: [1]u8 = .{'?'},
    fn call(b: *Buf, _: std.mem.Allocator, w: []const Value) Value {
        b.bytes[0] = '0' + @as(u8, @intCast(w[0].int));
        return .{ .text = &b.bytes };
    }
};

test "rollingMap: a result is copied before the callback reuses its buffer (mut 20352)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    var b: Buf = .{};
    const r = try cb.rollingMap(a, f, .{ .col = "x", .window = 1, .out = .{ .type = .text } }, &b, Buf.call);
    try testing.expectEqualStrings("1", r.cell(0, "x").?.text);
    try testing.expectEqualStrings("2", r.cell(1, "x").?.text);
    try testing.expectEqualStrings("3", r.cell(2, "x").?.text);
}

test "mapGroups: a frame with no rows has no group, so the callback never runs (mut 20357)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &.{.nulls}, .len = 0 };
    var c: Count = .{};
    const r = try cb.mapGroups(a, f, .{ .by = &.{} }, &c, Count.group);
    try testing.expectEqual(@as(usize, 0), c.n);
    try testing.expectEqual(@as(usize, 1), r.columns.len);
    try testing.expectEqual(@as(usize, 0), r.len);
}

const Hand = struct {
    name: [1]u8 = .{'a'},
    cols: [1]Column = undefined,
    vals: [1]i64 = .{7},
    data: [1]ColumnData = undefined,
    fn call(h: *Hand, _: std.mem.Allocator, _: Frame) Frame {
        h.cols[0] = .{ .name = &h.name, .type = .int };
        h.data[0] = .{ .int = .{ .values = &h.vals } };
        return .{ .columns = &h.cols, .data = &h.data, .len = 1 };
    }
};

test "mapGroups: the first result's columns are copied, not borrowed (mut 20361, 20375)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    var h: Hand = .{};
    const r = try cb.mapGroups(a, f, .{ .by = &.{} }, &h, Hand.call);
    // The callback's buffers change after the verb has returned.
    h.name[0] = 'Z';
    h.cols[0].type = .text;
    try testing.expectEqualStrings("a", r.columns[0].name);
    try testing.expectEqual(df.ColumnType.int, r.columns[0].type);
}

const NoCols = struct {
    fn call(_: void, _: std.mem.Allocator, _: Frame) Frame {
        return .{ .columns = &.{}, .data = &.{}, .len = std.math.maxInt(u32) };
    }
};

test "mapGroups: a result claiming u32 rows with no columns is TooLarge (mut 20366)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    try testing.expectError(error.TooLarge, cb.mapGroups(a, f, .{ .by = &.{} }, {}, NoCols.call));
}

const Deep = struct {
    cols: []const Column,
    fn call(d: *const Deep, _: std.mem.Allocator, _: Frame) Frame {
        return .{ .columns = d.cols, .data = &.{.nulls}, .len = 1 };
    }
};

test "mapGroups: declared inner columns are copied down to max_nesting_depth levels (mut 20374)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    var chain: []const Column = &.{};
    for (0..vm.max_nesting_depth + 6) |_| {
        const one = try a.alloc(Column, 1);
        one[0] = .{ .name = "c", .type = .list, .inner = chain };
        chain = one;
    }
    const d: Deep = .{ .cols = chain };
    const r = try cb.mapGroups(a, f, .{ .by = &.{} }, &d, Deep.call);
    var depth: usize = 0;
    var at: []const Column = r.columns;
    while (at.len > 0) : (at = at[0].inner) depth += 1;
    try testing.expectEqual(@as(usize, vm.max_nesting_depth), depth);
}

// ── expr ────────────────────────────────────────────────────────────────────

const max_nodes = @import("expr.zig").max_nodes;

fn evalOne(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
}

fn col(name: []const u8) Expr {
    return .{ .col = name };
}

test "concat_list and struct_of with more than max_nodes parts are ExprTooLarge before any part is read (mut 20401, 20411)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try xFrame(a);
    const parts = try a.alloc(Expr, max_nodes + 1);
    @memset(parts, col("nope"));
    try testing.expectError(error.ExprTooLarge, evalOne(a, f, .{ .concat_list = parts }));
    const fields = try a.alloc(df.NamedExpr, max_nodes + 1);
    @memset(fields, .{ .name = "a", .x = .{ .lit = int(1) } });
    try testing.expectError(error.ExprTooLarge, evalOne(a, f, .{ .struct_of = fields }));
}

test "field: only a struct column that declares fields can name a wrong one (mut 20406, 20407)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rec = try lf.makeRecord(a, &.{"a"}, &.{int(1)});
    const cells = [_]Value{rec};
    // A struct column with no declared fields: any name compiles, the cells decide.
    const f1: Frame = .{ .columns = &.{.{ .name = "p", .type = .@"struct" }}, .data = &.{.{ .boxed = &cells }}, .len = 1 };
    const r1 = try evalOne(a, f1, .{ .field = .{ .x = &col("p"), .name = "a" } });
    try testing.expectEqual(@as(i64, 1), r1.cell(0, "r").?.int);
    // An int column that carries (meaningless) inner columns is not a struct column.
    const f2: Frame = .{
        .columns = &.{.{ .name = "q", .type = .int, .inner = &.{.{ .name = "z", .type = .int }} }},
        .data = &.{.{ .int = .{ .values = &.{1} } }},
        .len = 1,
    };
    const r2 = try evalOne(a, f2, .{ .field = .{ .x = &col("q"), .name = "a" } });
    try testing.expect(r2.cell(0, "r").? == .null);
}

const tcol: Expr = col("t");

test "split_regex: limit 0 is BadExpr and a limit stops splitting (mut 20415, 20418, 20428)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"t\":\"a1b2c\"}]", .{});
    try testing.expectError(error.BadExpr, evalOne(a, f, .{ .split_regex = .{ .x = &tcol, .pattern = "[0-9]", .limit = 0 } }));
    const r = try evalOne(a, f, .{ .split_regex = .{ .x = &tcol, .pattern = "[0-9]", .limit = 2 } });
    const l = r.cell(0, "r").?.list;
    try testing.expectEqual(@as(usize, 2), l.len());
    try testing.expectEqualStrings("a", l.get(0).text);
    try testing.expectEqualStrings("b2c", l.get(1).text);
}

test "extract_all: a group that took no part is a null element (mut 20427)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"t\":\"ab\"}]", .{});
    const r = try evalOne(a, f, .{ .extract_all = .{ .x = &tcol, .pattern = "(a)|(b)", .group = 2 } });
    const l = r.cell(0, "r").?.list;
    try testing.expectEqual(@as(usize, 2), l.len());
    try testing.expect(l.get(0) == .null);
    try testing.expectEqualStrings("b", l.get(1).text);
}

test "extract_groups: a row with no match has null fields, never the last row's spans (mut 20429)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"t\":\"ab\"},{\"t\":\"zz\"}]", .{});
    const g: Expr = .{ .extract_groups = .{ .x = &tcol, .pattern = "(a)(b)" } };
    const r = try evalOne(a, f, .{ .field = .{ .x = &g, .name = "1" } });
    try testing.expectEqualStrings("a", r.cell(0, "r").?.text);
    try testing.expect(r.cell(1, "r").? == .null);
}

const xs_e: Expr = col("xs");
const concat_e: Expr = .{ .concat_list = &.{ xs_e, xs_e } };
const struct_e: Expr = .{ .struct_of = &.{ .{ .name = "a", .x = col("id") }, .{ .name = "b", .x = col("id") } } };

test "concat_list and struct_of leave exactly one value for their consumer (mut 20432, 20434)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"id\":4,\"xs\":[3,1,2]},{\"id\":5,\"xs\":null}]", .{});
    const n = try evalOne(a, f, .{ .list = .{ .x = &concat_e, .op = .len } });
    try testing.expect(n.cell(1, "r").? == .null);
    try testing.expectEqual(@as(i64, 6), n.cell(0, "r").?.int);
    const b = try evalOne(a, f, .{ .field = .{ .x = &struct_e, .name = "b" } });
    try testing.expectEqual(@as(i64, 4), b.cell(0, "r").?.int);
    try testing.expectEqual(@as(i64, 5), b.cell(1, "r").?.int);
}

/// A one-row list column over `items` (n elements).
fn listCol(a: std.mem.Allocator, items: ColumnData, n: u32) !ColumnData {
    const ic = try a.create(ColumnData);
    ic.* = items;
    const offs = try a.dupe(u32, &.{ 0, n });
    return .{ .list = .{ .offsets = offs, .items = ic } };
}

/// A one-row struct column.
fn structCol(a: std.mem.Allocator, names: []const []const u8, children: []const ColumnData) !ColumnData {
    const sc = try a.create(fm.StructColumn);
    sc.* = .{ .names = names, .children = try a.dupe(ColumnData, children), .len = 1 };
    return .{ .@"struct" = sc };
}

fn ints1(x: i64) ColumnData {
    return .{ .int = .{ .values = &.{x} } };
}

/// A frame whose schemas declare nested columns: `ps` a list of structs {a: timestamp},
/// `p` a struct {a: struct {z: timestamp}}, `p2` a struct {a: timestamp, b: float} over
/// int cells, and one-element lists `q*` with declared element types over int cells.
fn schemaFrame(a: std.mem.Allocator) !Frame {
    const ts_a = [_]Column{.{ .name = "a", .type = .timestamp }};
    const ts_z = [_]Column{.{ .name = "z", .type = .timestamp }};
    const e_struct = [_]Column{.{ .name = "", .type = .@"struct", .inner = &ts_a }};
    const p_inner = [_]Column{.{ .name = "a", .type = .@"struct", .inner = &ts_z }};
    const p2_inner = [_]Column{ .{ .name = "a", .type = .timestamp }, .{ .name = "b", .type = .float } };
    const q_ts = [_]Column{.{ .name = "a", .type = .timestamp }};
    const q_float = [_]Column{.{ .name = "", .type = .float }};
    const q_dur = [_]Column{.{ .name = "", .type = .duration }};
    const q_date = [_]Column{.{ .name = "", .type = .date }};
    const q_two = [_]Column{ .{ .name = "", .type = .timestamp }, .{ .name = "", .type = .text } };
    const cols = [_]Column{
        .{ .name = "id", .type = .int },
        .{ .name = "ps", .type = .list, .inner = &e_struct },
        .{ .name = "p", .type = .@"struct", .inner = &p_inner },
        .{ .name = "p2", .type = .@"struct", .inner = &p2_inner },
        .{ .name = "q", .type = .list, .inner = &q_ts },
        .{ .name = "qf", .type = .list, .inner = &q_float },
        .{ .name = "qd", .type = .list, .inner = &q_dur },
        .{ .name = "qt", .type = .list, .inner = &q_date },
        .{ .name = "q2", .type = .list, .inner = &q_two },
    };
    const date_items: ColumnData = .{ .text = .{ .offsets = &.{ 0, 10 }, .bytes = "2024-01-01" } };
    const data = [_]ColumnData{
        ints1(1),
        try listCol(a, try structCol(a, &.{"a"}, &.{ints1(5)}), 1),
        try structCol(a, &.{"a"}, &.{try structCol(a, &.{"z"}, &.{ints1(7)})}),
        try structCol(a, &.{ "a", "b" }, &.{ ints1(1), ints1(2) }),
        try listCol(a, ints1(1), 1),
        try listCol(a, ints1(1), 1),
        try listCol(a, ints1(5), 1),
        try listCol(a, date_items, 1),
        try listCol(a, ints1(1), 1),
    };
    return .{ .columns = try a.dupe(Column, &cols), .data = try a.dupe(ColumnData, &data), .len = 1 };
}

fn first(x: *const Expr) Expr {
    return .{ .list = .{ .x = x, .op = .first } };
}

test "nested results declare the inner columns of their source (mut 20437, 20438, 20439, 20444, 20447, 20448)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try schemaFrame(a);
    const ps = col("ps");
    const id = col("id");
    const p = col("p");
    // first(ps), first(reverse(ps)), first(concat_list(ps, ps)): a record with ps's field.
    const rev: Expr = .{ .list = .{ .x = &ps, .op = .reverse } };
    const cc: Expr = .{ .concat_list = &.{ ps, ps } };
    const exprs = [_]Expr{ first(&ps), first(&rev), first(&cc) };
    for (exprs) |e| {
        const r = try evalOne(a, f, e);
        try testing.expectEqual(df.ColumnType.@"struct", r.columnType("r").?);
        try testing.expectEqual(@as(usize, 1), r.columns[r.columns.len - 1].inner.len);
    }
    // concat_list(id, ps): the first part declares nothing, the second does.
    const mix: Expr = .{ .concat_list = &.{ id, ps } };
    const m = try evalOne(a, f, mix);
    try testing.expectEqual(df.ColumnType.list, m.columnType("r").?);
    try testing.expectEqual(@as(usize, 1), m.columns[m.columns.len - 1].inner.len);
    // field(p, "a") is a struct with its own declared field.
    const fl: Expr = .{ .field = .{ .x = &p, .name = "a" } };
    const fr = try evalOne(a, f, fl);
    try testing.expectEqual(df.ColumnType.@"struct", fr.columnType("r").?);
    try testing.expectEqual(@as(usize, 1), fr.columns[fr.columns.len - 1].inner.len);
}

test "an element or field is temporal only where a list or struct column says so (mut 20441, 20442, 20443, 20445, 20446, 20449, 20450, 20451, 20452, 20453, 20454, 20455)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try schemaFrame(a);
    const T = df.ColumnType;
    const p = col("p");
    const p2 = col("p2");
    const ps = col("ps");
    const q = col("q");
    // A struct's field is not a list: its declared inner columns are no element column.
    const fa: Expr = .{ .field = .{ .x = &p, .name = "a" } };
    const first_fa = first(&fa);
    try testing.expectEqual(T.float, (try evalOne(a, f, first_fa)).columnType("r").?);
    const first_ps = first(&ps);
    const first_first = first(&first_ps);
    try testing.expectEqual(T.float, (try evalOne(a, f, first_first)).columnType("r").?);
    // A list column is not a struct column: no field of it.
    const fq: Expr = .{ .field = .{ .x = &q, .name = "a" } };
    try testing.expectEqual(T.float, (try evalOne(a, f, fq)).columnType("r").?);
    // The field named, not the first one that does not match.
    const f2a: Expr = .{ .field = .{ .x = &p2, .name = "a" } };
    const f2b: Expr = .{ .field = .{ .x = &p2, .name = "b" } };
    try testing.expectEqual(T.timestamp, (try evalOne(a, f, f2a)).columnType("r").?);
    // b is declared float over int cells: not a temporal type, the cells say int.
    try testing.expectEqual(T.int, (try evalOne(a, f, f2b)).columnType("r").?);
    // The element of a list of declared float, duration, date.
    const qf = col("qf");
    const qd = col("qd");
    const qt = col("qt");
    const q2 = col("q2");
    const first_qf = first(&qf);
    const first_qd = first(&qd);
    const first_qt = first(&qt);
    const first_q2 = first(&q2);
    try testing.expectEqual(T.int, (try evalOne(a, f, first_qf)).columnType("r").?);
    try testing.expectEqual(T.duration, (try evalOne(a, f, first_qd)).columnType("r").?);
    try testing.expectEqual(T.date, (try evalOne(a, f, first_qt)).columnType("r").?);
    // Two declared element columns are no element column.
    try testing.expectEqual(T.int, (try evalOne(a, f, first_q2)).columnType("r").?);
    // A cast to int is not a list: first() of it reads no element column.
    const cq: Expr = .{ .cast = .{ .x = &q, .to = .int } };
    const first_cq = first(&cq);
    const rc = evalOne(a, f, first_cq) catch |e| switch (e) {
        error.BadExpr => return, // a list cast to int is refused outright: nothing to type
        else => return e,
    };
    try testing.expectEqual(T.float, rc.columnType("r").?);
}

// ── core, verbs, window ─────────────────────────────────────────────────────

fn levels(v: Value) usize {
    var n: usize = 0;
    var c = v;
    while (c == .list) {
        n += 1;
        if (c.list.len() == 0) break;
        c = c.list.get(0);
    }
    return n;
}

test "implode: the result is one level of nesting, the elements start at depth 1 (mut 20507)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var cur: Value = int(1);
    for (0..vm.max_nesting_depth + 6) |_| {
        const c = try a.create(ColumnData);
        const cells = try a.alloc(Value, 1);
        cells[0] = cur;
        c.* = .{ .boxed = cells };
        cur = .{ .list = .{ .items = c, .start = 0, .end = 1 } };
    }
    const cells = [_]Value{cur};
    const f: Frame = .{
        .columns = &.{ .{ .name = "g", .type = .int }, .{ .name = "c", .type = .list } },
        .data = &.{ ints1(1), .{ .boxed = &cells } },
        .len = 1,
    };
    const r = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "c", .out = "r", .func = .implode }} });
    try testing.expectEqual(@as(usize, vm.max_nesting_depth), levels(r.cell(0, "r").?));
}

test "implode: the list's element column carries the source column's inner columns (mut 20511)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try schemaFrame(a);
    const r = try df.aggregate(a, f, .{ .group_by = &.{"id"}, .aggs = &.{.{ .src = "p", .out = "r", .func = .implode }} });
    const c = r.columns[r.columnIndex("r").?];
    try testing.expectEqual(df.ColumnType.list, c.type);
    try testing.expectEqual(@as(usize, 1), c.inner.len);
    try testing.expectEqual(df.ColumnType.@"struct", c.inner[0].type);
    try testing.expectEqual(@as(usize, 1), c.inner[0].inner.len);
}

test "rolling_rank: a window longer than the frame is clamped in the work count (mut 20521)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"x\":3},{\"x\":1},{\"x\":2},{\"x\":5}]", .{});
    const r = try df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_rank = .{ .window = std.math.maxInt(usize), .min_periods = 1 } } });
    const want = [_]f64{ 1, 1, 2, 4 };
    for (want, 0..) |w, i| try testing.expectEqual(w, r.cell(i, "r").?.float);
}

test "rolling_rank: an even centred window leads by (w - 1) / 2 (mut 20541)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"x\":10},{\"x\":20},{\"x\":30},{\"x\":40},{\"x\":50}]", .{});
    const r = try df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_rank = .{ .window = 4, .min_periods = 1, .center = true } } });
    const want = [_]f64{ 1, 2, 3, 3, 3 };
    for (want, 0..) |w, i| try testing.expectEqual(w, r.cell(i, "r").?.float);
}

test "rolling_corr: min_periods 0 still needs one complete pair (mut 20582)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"x\":1,\"y\":null},{\"x\":2,\"y\":null},{\"x\":3,\"y\":null}]", .{});
    const r = try df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_corr = .{ .other = "y", .window = 2, .min_periods = 0 } } });
    for (0..3) |i| try testing.expect(r.cell(i, "r").? == .null);
}

test "rolling_corr and cov: a pair with a missing x is left out, as one with a missing y (mut 20590)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"x\":1,\"y\":2},{\"x\":null,\"y\":4},{\"x\":3,\"y\":6},{\"x\":5,\"y\":10}]", .{});
    const c = try df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_corr = .{ .other = "y", .window = 4, .min_periods = 1 } } });
    try testing.expectApproxEqRel(@as(f64, 1), c.cell(3, "r").?.float, 1e-12);
    const v = try df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_cov = .{ .other = "y", .window = 4, .min_periods = 1 } } });
    try testing.expectApproxEqRel(@as(f64, 8), v.cell(3, "r").?.float, 1e-12);
}

test "list.mean counts a bool as 1 or 0 (mut 20092)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try list(a, &.{ .{ .bool = true }, .{ .bool = false }, .{ .bool = true } });
    const r = try lf.listCell(a, l, .mean);
    try testing.expectApproxEqRel(@as(f64, 2.0 / 3.0), r.float, 1e-12);
}

test "explode: several columns agree on counts, a scalar is one element and a null none (mut 20096, 20097)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sc = [_]Value{int(5)};
    const ls = [_]Value{try list(a, &.{int(9)})};
    const nl = [_]Value{.null};
    const cols = [_]Column{ .{ .name = "a", .type = .list }, .{ .name = "b", .type = .list } };
    const ok: Frame = .{ .columns = &cols, .data = &.{ .{ .boxed = &sc }, .{ .boxed = &ls } }, .len = 1 };
    const r = try df.explode(a, ok, &.{ "a", "b" });
    try testing.expectEqual(@as(usize, 1), r.len);
    try testing.expectEqual(@as(i64, 5), r.cell(0, "a").?.int);
    try testing.expectEqual(@as(i64, 9), r.cell(0, "b").?.int);
    const bad: Frame = .{ .columns = &cols, .data = &.{ .{ .boxed = &nl }, .{ .boxed = &ls } }, .len = 1 };
    try testing.expectError(error.LengthMismatch, df.explode(a, bad, &.{ "a", "b" }));
}

test "unnest: a field with more rows than its struct column is not shared (mut 20261)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sc = try a.create(fm.StructColumn);
    sc.* = .{ .names = &.{"a"}, .children = &.{.{ .int = .{ .values = &.{ 1, 2 } } }}, .len = 1 };
    const f: Frame = .{ .columns = &.{.{ .name = "p", .type = .@"struct" }}, .data = &.{.{ .@"struct" = sc }}, .len = 2 };
    const u = try df.unnest(a, f, .{ .cols = &.{"p"} });
    try testing.expectEqual(@as(i64, 1), u.cell(0, "a").?.int);
    try testing.expect(u.cell(1, "a").? == .null);
    try testing.expect(fz.wellFormed(u));
}

test "window transform(implode): the column is a list (mut 20524)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readJson(a, "[{\"k\":\"a\",\"v\":1},{\"k\":\"a\",\"v\":2}]", .{});
    const w = try df.window(a, f, .{ .value_col = "v", .out = "w", .partition_by = &.{"k"}, .op = .{ .transform = .{ .func = .implode } } });
    try testing.expectEqual(df.ColumnType.list, w.columnType("w").?);
    try testing.expect(fz.wellFormed(w));
}
