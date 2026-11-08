// SPDX-License-Identifier: MIT
//! S3 step 4: the callback verbs (`mapElements`, `mapRows`, `rollingMap`, `mapGroups`,
//! `filterGroups`; survey rows 21 and 25) and the window `rolling_rank`, `rolling_corr`,
//! `rolling_cov` (row 29). Where each expected value comes from is said at the value:
//! "pandas doc" are the examples of pandas 3.1's `Rolling.rank`/`Expanding.rank`
//! docstrings, the rest are worked by hand (pandas and polars were not run).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const fz = @import("fuzz.zig");
const Value = df.Value;
const Frame = df.Frame;

fn fl(x: f64) Value {
    return .{ .float = x };
}

fn int(x: i64) Value {
    return .{ .int = x };
}

fn cell(f: Frame, row: usize, name: []const u8) Value {
    return f.cell(row, name).?;
}

fn expectFloats(f: Frame, name: []const u8, want: []const ?f64) !void {
    try testing.expectEqual(want.len, f.len);
    for (want, 0..) |w, i| {
        const v = cell(f, i, name);
        if (w) |x| {
            if (std.math.isNan(x)) {
                try testing.expect(v == .float and std.math.isNan(v.float));
            } else {
                try testing.expect(v == .float);
                try testing.expectApproxEqRel(x, v.float, 1e-12);
            }
        } else try testing.expect(v == .null);
    }
    try testing.expect(fz.wellFormed(f));
}

fn expectInts(f: Frame, name: []const u8, want: []const ?i64) !void {
    try testing.expectEqual(want.len, f.len);
    for (want, 0..) |w, i| {
        const v = cell(f, i, name);
        if (w) |x| {
            try testing.expect(v == .int);
            try testing.expectEqual(x, v.int);
        } else try testing.expect(v == .null);
    }
    try testing.expect(fz.wellFormed(f));
}

// ── mapElements ─────────────────────────────────────────────────────────────

const Counter = struct { calls: usize = 0 };

fn double(c: *Counter, a: std.mem.Allocator, v: Value) error{Boom}!Value {
    _ = a;
    c.calls += 1;
    return switch (v) {
        .int => |x| if (x == 99) error.Boom else int(x * 2),
        else => int(0),
    };
}

test "mapElements: in place, declared type, nulls skipped or seen, the callback's error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "k", .type = .text } }, &.{
        &.{ int(1), .{ .text = "a" } }, &.{ int(2), .{ .text = "b" } }, &.{ .null, .{ .text = "c" } }, &.{ int(4), .{ .text = "d" } },
    });
    var c: Counter = .{};
    const r = try df.mapElements(a, f, .{ .col = "x", .out = .{ .type = .int } }, &c, double);
    try testing.expectEqual(@as(usize, 3), c.calls); // the null is not handed in (polars `skip_nulls`)
    try testing.expectEqual(@as(usize, 2), r.columns.len); // replaced in place
    try testing.expectEqualStrings("x", r.columns[0].name);
    try testing.expectEqual(df.ColumnType.int, r.columns[0].type);
    try expectInts(r, "x", &.{ 2, 4, null, 8 });
    try testing.expectEqualStrings("c", cell(r, 2, "k").text);

    c = .{};
    const seen = try df.mapElements(a, f, .{ .col = "x", .out = .{ .name = "y" }, .skip_missing = false }, &c, double);
    try testing.expectEqual(@as(usize, 4), c.calls);
    try testing.expectEqual(@as(usize, 3), seen.columns.len); // appended
    try testing.expectEqual(df.ColumnType.int, seen.columns[2].type); // inferred from the cells
    try expectInts(seen, "y", &.{ 2, 4, 0, 8 });

    // An int is taken for a declared float; a text is not.
    const asf = try df.mapElements(a, f, .{ .col = "x", .out = .{ .type = .float } }, &c, double);
    try expectFloats(asf, "x", &.{ 2, 4, null, 8 });
    try testing.expectError(error.WrongOutputType, df.mapElements(a, f, .{ .col = "x", .out = .{ .type = .text } }, &c, double));
    try testing.expectError(error.NoSuchColumn, df.mapElements(a, f, .{ .col = "q" }, &c, double));
    const g = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{int(1)}, &.{int(99)} });
    try testing.expectError(error.Boom, df.mapElements(a, g, .{ .col = "x" }, &c, double));
}

const Spell = struct { buf: [16]u8 = undefined };

/// Text in a buffer the callback reuses: each result must be copied before the next call.
fn spell(s: *Spell, a: std.mem.Allocator, v: Value) !Value {
    _ = a;
    return .{ .text = try std.fmt.bufPrint(&s.buf, "v{d}", .{v.int}) };
}

fn upTo(_: void, a: std.mem.Allocator, v: Value) !Value {
    // A list cell 0..n built in the verb's arena.
    const n: usize = @intCast(v.int);
    const cells = try a.alloc(Value, n);
    for (cells, 0..) |*x, i| x.* = int(@intCast(i));
    const items = try a.create(df.ColumnData);
    items.* = try df.columnFromCells(a, cells);
    return .{ .list = .{ .items = items, .start = 0, .end = @intCast(n) } };
}

fn mixed(_: void, _: std.mem.Allocator, v: Value) Value {
    return if (v.int == 2) .{ .text = "two" } else v;
}

test "mapElements: reused text buffer, list and categorical results, a mix" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{int(1)}, &.{int(2)}, &.{int(3)} });
    var s: Spell = .{};
    const r = try df.mapElements(a, f, .{ .col = "x", .out = .{ .name = "t" } }, &s, spell);
    try testing.expectEqual(df.ColumnType.text, r.columns[1].type);
    try testing.expectEqualStrings("v1", cell(r, 0, "t").text);
    try testing.expectEqualStrings("v2", cell(r, 1, "t").text);
    try testing.expectEqualStrings("v3", cell(r, 2, "t").text);

    const cat = try df.mapElements(a, f, .{ .col = "x", .out = .{ .name = "t", .type = .categorical } }, &s, spell);
    try testing.expect(cat.columnAt(1) == .categorical);
    try testing.expectEqualStrings("v2", cell(cat, 1, "t").text);
    try testing.expect(fz.wellFormed(cat));

    const inner = [_]df.Column{.{ .name = "item", .type = .int }};
    const l = try df.mapElements(a, f, .{ .col = "x", .out = .{ .name = "l", .type = .list, .inner = &inner } }, {}, upTo);
    try testing.expectEqual(df.ColumnType.list, l.columns[1].type);
    try testing.expectEqual(df.ColumnType.int, l.columns[1].inner[0].type);
    const third = cell(l, 2, "l").list;
    try testing.expectEqual(@as(usize, 3), third.len());
    try testing.expectEqual(@as(i64, 2), third.get(2).int);
    try testing.expect(fz.wellFormed(l));

    // A mix of kinds: boxed cells in a text-declared column (pandas' `object`).
    const m = try df.mapElements(a, f, .{ .col = "x" }, {}, mixed);
    try testing.expectEqual(df.ColumnType.text, m.columns[0].type);
    try testing.expectEqual(@as(i64, 1), cell(m, 0, "x").int);
    try testing.expectEqualStrings("two", cell(m, 1, "x").text);
    try testing.expect(fz.wellFormed(m));
}

const empty_items: df.ColumnData = .nulls;
const backwards: Value = .{ .list = .{ .items = &empty_items, .start = 3, .end = 1 } };
const boxed_items: df.ColumnData = .{ .boxed = &.{ int(1), backwards } };
const hides_backwards: Value = .{ .list = .{ .items = &boxed_items, .start = 0, .end = 2 } };

fn badView(deep: bool, _: std.mem.Allocator, _: Value) Value {
    return if (deep) hides_backwards else backwards;
}

fn badBoxedGroup(_: void, _: std.mem.Allocator, g: Frame) Frame {
    _ = g;
    const S = struct {
        const cols = [_]df.Column{.{ .name = "l", .type = .list }};
        const data = [_]df.ColumnData{.{ .boxed = &.{hides_backwards} }};
    };
    return .{ .columns = &S.cols, .data = &S.data, .len = 1 };
}

test "callback results: a hand-made list view running backwards is an error, at any depth" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{&.{int(1)}});
    try testing.expectError(error.WrongOutputType, df.mapElements(a, f, .{ .col = "x" }, false, badView));
    try testing.expectError(error.WrongOutputType, df.mapElements(a, f, .{ .col = "x" }, true, badView));
    try testing.expectError(error.WrongOutputType, df.mapGroups(a, f, .{ .by = &.{"x"} }, {}, badBoxedGroup));
}

const three_items: df.ColumnData = .{ .boxed = &.{ int(1), int(2), int(3) } };

fn pastStorage(_: void, _: std.mem.Allocator, _: Value) Value {
    return .{ .list = .{ .items = &three_items, .start = 0, .end = std.math.maxInt(u32) } };
}

fn nullsList(_: void, _: std.mem.Allocator, _: Value) Value {
    return .{ .list = .{ .items = &empty_items, .start = 0, .end = 2 } };
}

test "callback results: a hand-made list view past its storage is an error (fuzz seed 35)" {
    // It claimed 2^32 elements over three: the check walked, and the copy would have
    // copied, four billion of them (a hang the fuzz driver reported, 2026-11-08).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{&.{int(1)}});
    try testing.expectError(error.WrongOutputType, df.mapElements(a, f, .{ .col = "x" }, {}, pastStorage));
    // A list of null elements over `.nulls` storage is a legitimate view.
    const m = try df.mapElements(a, f, .{ .col = "x" }, {}, nullsList);
    try testing.expectEqual(@as(usize, 2), cell(m, 0, "x").list.len());
    try testing.expect(fz.wellFormed(m));
}

// ── mapRows ─────────────────────────────────────────────────────────────────

fn combine(_: void, _: std.mem.Allocator, row: df.Row) Value {
    const x = row.get("a").?;
    const y = row.at(1);
    if (x != .int or y != .int) return .null;
    return int(x.int * 10 + y.int);
}

fn noSuchCell(_: void, _: std.mem.Allocator, row: df.Row) Value {
    // A name the frame lacks and a position past its columns.
    std.debug.assert(row.get("zz") == null);
    return row.at(7);
}

test "mapRows: a row's cells by name and position, appended or replaced" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } }, &.{
        &.{ int(1), int(2) }, &.{ int(3), .null }, &.{ int(5), int(6) },
    });
    const r = try df.mapRows(a, f, .{ .out = "s" }, {}, combine); // 1*10+2, null, 5*10+6
    try expectInts(r, "s", &.{ 12, null, 56 });
    const rep = try df.mapRows(a, f, .{ .out = "b", .type = .int }, {}, combine);
    try testing.expectEqual(@as(usize, 2), rep.columns.len);
    try expectInts(rep, "b", &.{ 12, null, 56 });
    try testing.expectError(error.WrongOutputType, df.mapRows(a, f, .{ .out = "s", .type = .bool }, {}, combine));
    const n = try df.mapRows(a, f, .{ .out = "z" }, {}, noSuchCell);
    try testing.expect(n.columnAt(2) == .nulls);
    try testing.expectEqual(df.ColumnType.float, n.columns[2].type); // all null: pandas' NaN column
}

// ── rollingMap ──────────────────────────────────────────────────────────────

/// The spread of the present cells (max - min).
fn spread(_: void, _: std.mem.Allocator, w: []const Value) Value {
    var lo = std.math.inf(f64);
    var hi = -std.math.inf(f64);
    for (w) |c| {
        const x = c.asFloat() orelse continue;
        if (std.math.isNan(x)) continue;
        lo = @min(lo, x);
        hi = @max(hi, x);
    }
    return fl(hi - lo);
}

fn windowLen(_: void, _: std.mem.Allocator, w: []const Value) Value {
    return int(@intCast(w.len));
}

fn sumInts(_: void, _: std.mem.Allocator, w: []const Value) Value {
    var s: i64 = 0;
    for (w) |c| s += if (c == .int) c.int else 0;
    return int(s);
}

fn neverCalled(_: void, _: std.mem.Allocator, _: []const Value) error{Called}!Value {
    return error.Called;
}

test "rollingMap: windows, min_periods over present cells, center, partitions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .float }, .{ .name = "g", .type = .text }, .{ .name = "i", .type = .int } }, &.{
        &.{ fl(1), .{ .text = "a" }, int(1) },   &.{ fl(2), .{ .text = "b" }, int(2) }, &.{ fl(3), .{ .text = "a" }, int(3) },
        &.{ fl(nan), .{ .text = "b" }, int(4) }, &.{ fl(5), .{ .text = "a" }, int(5) },
    });
    // Window 3, min_periods 3: [1,2,3] -> 2; [2,3,NaN] and [3,NaN,5] have two present.
    const r = try df.rollingMap(a, f, .{ .col = "x", .out = .{ .name = "s" }, .window = 3 }, {}, spread);
    try expectFloats(r, "s", &.{ null, null, 2, null, null });
    // min_periods 2: [1,2] 1, [1,2,3] 2, [2,3,NaN] 1, [3,NaN,5] 2; the NaN is handed in.
    const r2 = try df.rollingMap(a, f, .{ .col = "x", .out = .{ .name = "s" }, .window = 3, .min_periods = 2 }, {}, spread);
    try expectFloats(r2, "s", &.{ null, 1, 2, 1, 2 });
    // center: rows 0 and 4 see two rows (lead (3-1)/2 = 1, as `Rolling.center`).
    const c = try df.rollingMap(a, f, .{ .col = "i", .out = .{ .name = "n" }, .window = 3, .min_periods = 1, .center = true }, {}, windowLen);
    try expectInts(c, "n", &.{ 2, 3, 3, 3, 2 });
    // Per partition: a = rows 0,2,4 (1,3,5) -> 1, 4, 8; b = rows 1,3 (2,4) -> 2, 6.
    const p = try df.rollingMap(a, f, .{ .col = "i", .window = 2, .min_periods = 1, .partition_by = &.{"g"} }, {}, sumInts);
    try testing.expectEqual(@as(usize, 3), p.columns.len); // "i" replaced
    try expectInts(p, "i", &.{ 1, 2, 4, 6, 8 });
    // Window 0: every row null and no call.
    const z = try df.rollingMap(a, f, .{ .col = "x", .out = .{ .name = "s" }, .window = 0 }, {}, neverCalled);
    try expectFloats(z, "s", &.{ null, null, null, null, null });
    try testing.expectError(error.Called, df.rollingMap(a, f, .{ .col = "x", .window = 1 }, {}, neverCalled));
    try testing.expectError(error.WrongOutputType, df.rollingMap(a, f, .{ .col = "x", .out = .{ .type = .text }, .window = 1 }, {}, spread));
    try testing.expectError(error.NoSuchColumn, df.rollingMap(a, f, .{ .col = "x", .window = 1, .partition_by = &.{"q"} }, {}, spread));
}

/// Two partitions of 2^15 rows, a column with no storage: 2^30 visits each, the cap,
/// 2^31 for the call.
fn capFrame(a: std.mem.Allocator) !Frame {
    const n = 1 << 16;
    const gs = try a.alloc(i64, n);
    for (gs, 0..) |*g, i| g.* = @intCast(i & 1);
    const cols = try a.dupe(df.Column, &.{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float }, .{ .name = "g", .type = .int } });
    const data = try a.dupe(df.ColumnData, &.{ .nulls, .nulls, .{ .int = .{ .values = gs } } });
    return .{ .columns = cols, .data = data, .len = n };
}

test "rollingMap and the window functions: the work cap is the call's, refused before any call" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try capFrame(a);
    const w = 1 << 15;
    try testing.expectError(error.TooLarge, df.rollingMap(a, f, .{ .col = "x", .window = w, .partition_by = &.{"g"} }, {}, neverCalled));
    // One partition of the two alone is within the cap: the callback is reached.
    const half: Frame = .{ .columns = f.columns, .data = f.data, .len = w };
    try testing.expectError(error.Called, df.rollingMap(a, half, .{ .col = "x", .window = w, .min_periods = 0 }, {}, neverCalled));
    try testing.expectError(error.TooLarge, df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_rank = .{ .window = w } }, .partition_by = &.{"g"} }));
    _ = try df.window(a, half, .{ .value_col = "x", .out = "r", .op = .{ .rolling_rank = .{ .window = 1 } } });
    // Expanding is the prefix: 2^16 rows is 2^32 visits.
    try testing.expectError(error.TooLarge, df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_rank = .{ .window = null } } }));
    // A pair reads two cells per row: 2 x 2^16 x 2^14 = 2^31.
    try testing.expectError(error.TooLarge, df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_corr = .{ .other = "y", .window = 1 << 14 } } }));
    try testing.expectError(error.TooLarge, df.window(a, f, .{ .value_col = "x", .out = "r", .op = .{ .rolling_cov = .{ .other = "y", .window = null } } }));
}

// ── mapGroups and filterGroups ──────────────────────────────────────────────

const sum_cols = [_]df.Column{ .{ .name = "g", .type = .text }, .{ .name = "s", .type = .int } };

/// One row per group: its key and the sum of `x`.
fn sumGroup(_: void, a: std.mem.Allocator, g: Frame) !Frame {
    var s: i64 = 0;
    for (0..g.len) |i| s += cell(g, i, "x").int;
    var b = try df.FrameBuilder.init(a, &sum_cols, 1);
    try b.appendRow(&.{ cell(g, 0, "g"), int(s) });
    return b.toOwned();
}

const Bad = enum { name, type, count, huge, fail };

fn badGroup(how: Bad, a: std.mem.Allocator, g: Frame) !Frame {
    const first = cell(g, 0, "g");
    if (first != .text or !std.mem.eql(u8, first.text, "b")) return sumGroup({}, a, g);
    switch (how) {
        .name => {
            const cols = [_]df.Column{ .{ .name = "g", .type = .text }, .{ .name = "t", .type = .int } };
            var b = try df.FrameBuilder.init(a, &cols, 1);
            try b.appendRow(&.{ first, int(0) });
            return b.toOwned();
        },
        .type => {
            const cols = [_]df.Column{ .{ .name = "g", .type = .text }, .{ .name = "s", .type = .float } };
            var b = try df.FrameBuilder.init(a, &cols, 1);
            try b.appendRow(&.{ first, fl(0) });
            return b.toOwned();
        },
        .count => return .{ .columns = sum_cols[0..1], .data = &.{}, .len = 0 },
        // A hand-built frame claiming 2^25 rows of no storage: refused before a cell is read.
        .huge => return .{ .columns = &sum_cols, .data = &.{}, .len = 1 << 25 },
        .fail => return error.GroupFailed,
    }
}

fn same(_: void, _: std.mem.Allocator, g: Frame) Frame {
    return g;
}

fn wholeLen(n: *usize, _: std.mem.Allocator, g: Frame) Frame {
    n.* = g.len;
    return g;
}

test "mapGroups: first-seen group order, schema checks, growth cap, the callback's error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "g", .type = .text }, .{ .name = "x", .type = .int } }, &.{
        &.{ .{ .text = "a" }, int(1) }, &.{ .{ .text = "b" }, int(2) }, &.{ .{ .text = "a" }, int(3) }, &.{ .{ .text = "c" }, int(4) },
    });
    // a: 1 + 3, b: 2, c: 4, in the order the keys first appear.
    const r = try df.mapGroups(a, f, .{ .by = &.{"g"} }, {}, sumGroup);
    try testing.expectEqual(@as(usize, 3), r.len);
    try testing.expectEqualStrings("a", cell(r, 0, "g").text);
    try testing.expectEqualStrings("c", cell(r, 2, "g").text);
    try expectInts(r, "s", &.{ 4, 2, 4 });
    // The groups themselves, stacked: rows regrouped.
    const id = try df.mapGroups(a, f, .{ .by = &.{"g"} }, {}, same);
    try expectInts(id, "x", &.{ 1, 3, 2, 4 });
    // No key: one group of every row.
    var n: usize = 0;
    const whole = try df.mapGroups(a, f, .{ .by = &.{} }, &n, wholeLen);
    try testing.expectEqual(@as(usize, 4), n);
    try expectInts(whole, "x", &.{ 1, 2, 3, 4 });
    inline for (.{ Bad.name, Bad.type, Bad.count }) |how| {
        try testing.expectError(error.SchemaMismatch, df.mapGroups(a, f, .{ .by = &.{"g"} }, how, badGroup));
    }
    try testing.expectError(error.TooLarge, df.mapGroups(a, f, .{ .by = &.{"g"} }, Bad.huge, badGroup));
    try testing.expectError(error.GroupFailed, df.mapGroups(a, f, .{ .by = &.{"g"} }, Bad.fail, badGroup));
    try testing.expectError(error.NoSuchColumn, df.mapGroups(a, f, .{ .by = &.{"q"} }, {}, same));
    // No rows, no group, no call: the input's columns, empty.
    const e = try df.mapGroups(a, try df.clear(a, f, 0), .{ .by = &.{"g"} }, Bad.fail, badGroup);
    try testing.expectEqual(@as(usize, 0), e.len);
    try testing.expectEqual(@as(usize, 2), e.columns.len);
}

test "mapGroups: a missing key is a group; categorical and list columns rebuilt well-formed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "g", .type = .text }, .{ .name = "x", .type = .int } }, &.{
        &.{ .null, int(1) }, &.{ .{ .text = "a" }, int(2) }, &.{ .null, int(3) },
    });
    const id = try df.mapGroups(a, f, .{ .by = &.{"g"} }, {}, same);
    try expectInts(id, "x", &.{ 1, 3, 2 });
    const c = try df.cast(a, f, .{ .col = "g", .to = .categorical });
    const ci = try df.mapGroups(a, c, .{ .by = &.{"x"} }, {}, same);
    try testing.expect(ci.columnAt(0) == .categorical);
    try testing.expect(fz.wellFormed(ci));
    const l = try df.mapElements(a, f, .{ .col = "x", .out = .{ .name = "l", .type = .list } }, {}, upTo);
    const li = try df.mapGroups(a, l, .{ .by = &.{"g"} }, {}, same);
    try testing.expect(fz.wellFormed(li));
    try testing.expectEqual(@as(usize, 3), cell(li, 1, "l").list.len()); // row x = 3 moved up
}

fn sumAbove(limit: i64, _: std.mem.Allocator, g: Frame) bool {
    var s: i64 = 0;
    for (0..g.len) |i| s += cell(g, i, "x").int;
    return s > limit;
}

fn atLeast(k: usize, _: std.mem.Allocator, g: Frame) bool {
    return g.len >= k;
}

fn failPred(_: void, _: std.mem.Allocator, _: Frame) error{PredFailed}!bool {
    return error.PredFailed;
}

test "filterGroups: rows of the kept groups in input order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "g", .type = .text }, .{ .name = "x", .type = .int } }, &.{
        &.{ .{ .text = "a" }, int(1) }, &.{ .{ .text = "b" }, int(2) }, &.{ .{ .text = "a" }, int(3) }, &.{ .{ .text = "c" }, int(4) },
    });
    // Sums a 4, b 2, c 4: keep a and c (pandas `filter(lambda g: g.x.sum() > 3)`).
    const r = try df.filterGroups(a, f, .{ .by = &.{"g"} }, @as(i64, 3), sumAbove);
    try expectInts(r, "x", &.{ 1, 3, 4 });
    const big = try df.filterGroups(a, f, .{ .by = &.{"g"} }, @as(usize, 2), atLeast);
    try expectInts(big, "x", &.{ 1, 3 });
    const all = try df.filterGroups(a, f, .{ .by = &.{} }, @as(usize, 4), atLeast);
    try expectInts(all, "x", &.{ 1, 2, 3, 4 });
    try testing.expectError(error.PredFailed, df.filterGroups(a, f, .{ .by = &.{"g"} }, {}, failPred));
    try testing.expectError(error.NoSuchColumn, df.filterGroups(a, f, .{ .by = &.{"q"} }, {}, failPred));
    const e = try df.filterGroups(a, try df.clear(a, f, 0), .{ .by = &.{"g"} }, {}, failPred);
    try testing.expectEqual(@as(usize, 0), e.len);
}

// ── window rank, corr, cov ──────────────────────────────────────────────────

fn win(a: std.mem.Allocator, f: Frame, op: df.WindowOp) !Frame {
    return df.window(a, f, .{ .value_col = "x", .out = "r", .op = op });
}

test "rolling_rank: pandas doc examples, methods, descending, pct, missing cells, center" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{
        &.{int(1)}, &.{int(4)}, &.{int(2)}, &.{int(3)}, &.{int(5)}, &.{int(3)},
    });
    // pandas doc (`Rolling.rank`): s = [1, 4, 2, 3, 5, 3], s.rolling(3).rank().
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3 } }), "r", &.{ null, null, 2, 2, 3, 1.5 });
    // pandas doc: method="max" and method="min".
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .method = .max } }), "r", &.{ null, null, 2, 2, 3, 2 });
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .method = .min } }), "r", &.{ null, null, 2, 2, 3, 1 });
    // pandas doc (`Expanding.rank`): s.expanding().rank().
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = null } }), "r", &.{ 1, 2, 2, 3, 5, 3.5 });
    // By hand: descending, [1,4,2] 2 -> 2; [4,2,3] 3 -> 2; [2,3,5] 5 -> 1; [3,5,3] 3 -> 1 + 1.5.
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .descending = true } }), "r", &.{ null, null, 2, 2, 1, 2.5 });
    // pct: rank / 3 present values.
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .pct = true } }), "r", &.{ null, null, 2.0 / 3.0, 2.0 / 3.0, 1, 0.5 });
    // first: the tie in [3,5,3] goes in row order (row 5 is the second 3) -> 2.
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .method = .first } }), "r", &.{ null, null, 2, 2, 3, 2 });
    // dense over [3,5,3]: distinct {3,5}, 3 -> 1; pct divides by the 2 distinct values.
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .method = .dense } }), "r", &.{ null, null, 2, 2, 3, 1 });
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .method = .dense, .pct = true } }), "r", &.{ null, null, 2.0 / 3.0, 2.0 / 3.0, 1, 0.5 });
    // center (the labelled row ranked, min_periods 1): [1,4] 1; [1,4,2] 4; [4,2,3] 2;
    // [2,3,5] 3; [3,5,3] 5; [5,3] 3.
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 3, .min_periods = 1, .center = true } }), "r", &.{ 1, 3, 1, 2, 3, 1 });
    try expectFloats(try win(a, f, .{ .rolling_rank = .{ .window = 0 } }), "r", &.{ null, null, null, null, null, null });

    // A missing row is null and does not count for the others: [1, null, 3, NaN, 2].
    const g = try st.mk(a, &.{.{ .name = "x", .type = .float }}, &.{
        &.{fl(1)}, &.{.null}, &.{fl(3)}, &.{fl(std.math.nan(f64))}, &.{fl(2)},
    });
    // window 2, min_periods 1: [1] 1; null; [null,3] 1; NaN; [NaN,2] 1.
    try expectFloats(try win(a, g, .{ .rolling_rank = .{ .window = 2, .min_periods = 1 } }), "r", &.{ 1, null, 1, null, 1 });
    // expanding: [1] 1; null; [1,3] 2; NaN; [1,3,2] 2.
    try expectFloats(try win(a, g, .{ .rolling_rank = .{ .window = null } }), "r", &.{ 1, null, 2, null, 2 });
}

test "rolling_corr and rolling_cov: two-pass values, pairwise-complete rows, ddof, partitions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .float }, .{ .name = "z", .type = .float }, .{ .name = "k", .type = .float } }, &.{
        &.{ int(1), fl(2), fl(2), fl(1) },   &.{ int(2), fl(4), fl(4), fl(1) },
        &.{ int(3), fl(6), fl(6), fl(1) },   &.{ int(4), fl(8), .null, fl(1) },
        &.{ int(5), fl(11), fl(11), fl(1) },
    });
    // Window 3 over x and y: [1,2,3]/[2,4,6] and [2,3,4]/[4,6,8] lie on a line (1); the
    // last window [3,4,5]/[6,8,11]: sxy 5, sxx 2, syy 114/9, r = 15 / sqrt(228).
    try expectFloats(try win(a, f, .{ .rolling_corr = .{ .other = "y", .window = 3 } }), "r", &.{ null, null, 1, 1, 15.0 / @sqrt(228.0) });
    // cov = sxy / (n - 1): 4/2, 4/2, 5/2; ddof 0: / n.
    try expectFloats(try win(a, f, .{ .rolling_cov = .{ .other = "y", .window = 3 } }), "r", &.{ null, null, 2, 2, 2.5 });
    try expectFloats(try win(a, f, .{ .rolling_cov = .{ .other = "y", .window = 3, .ddof = 0 } }), "r", &.{ null, null, 4.0 / 3.0, 4.0 / 3.0, 5.0 / 3.0 });
    // Expanding: cov of the prefixes 1, 4/2, 10/3, 22/4 (sxy 22, sxx 10, syy 48.8 over all
    // five, r = 22 / sqrt(488)).
    // Row 0: one pair, no spread: NaN (pandas' 0/0); its cov has n <= ddof: null.
    try expectFloats(try win(a, f, .{ .rolling_corr = .{ .other = "y", .window = null } }), "r", &.{ std.math.nan(f64), 1, 1, 1, 22.0 / @sqrt(488.0) });
    try expectFloats(try win(a, f, .{ .rolling_cov = .{ .other = "y", .window = null } }), "r", &.{ null, 1, 2, 10.0 / 3.0, 5.5 });
    // Pairwise-complete: z is missing on row 3. Window 3 (min_periods 3) loses rows 3, 4;
    // with min_periods 2, row 3 is the pairs (2,4),(3,6): r 1, cov 1; row 4 (3,6),(5,11):
    // r 1, cov ((-1)(-2.5) + (1)(2.5)) / 1 = 5.
    try expectFloats(try win(a, f, .{ .rolling_corr = .{ .other = "z", .window = 3 } }), "r", &.{ null, null, 1, null, null });
    try expectFloats(try win(a, f, .{ .rolling_corr = .{ .other = "z", .window = 3, .min_periods = 2 } }), "r", &.{ null, 1, 1, 1, 1 });
    try expectFloats(try win(a, f, .{ .rolling_cov = .{ .other = "z", .window = 3, .min_periods = 2 } }), "r", &.{ null, 1, 2, 1, 5 });
    // A constant side: NaN correlation (pandas), 0 covariance.
    try expectFloats(try win(a, f, .{ .rolling_corr = .{ .other = "k", .window = 3 } }), "r", &.{ null, null, std.math.nan(f64), std.math.nan(f64), std.math.nan(f64) });
    try expectFloats(try win(a, f, .{ .rolling_cov = .{ .other = "k", .window = 3 } }), "r", &.{ null, null, 0, 0, 0 });
    // center, window 3, min_periods 2: row 0 sees rows 0..1 (cov 1), row 4 rows 3..4:
    // (4,8),(5,11), ((-0.5)(-1.5) + (0.5)(1.5)) / 1 = 1.5.
    try expectFloats(try win(a, f, .{ .rolling_cov = .{ .other = "y", .window = 3, .min_periods = 2, .center = true } }), "r", &.{ 1, 2, 2, 2.5, 1.5 });
    try expectFloats(try win(a, f, .{ .rolling_corr = .{ .other = "y", .window = 0 } }), "r", &.{ null, null, null, null, null });
    try testing.expectError(error.NoSuchColumn, win(a, f, .{ .rolling_corr = .{ .other = "q", .window = 3 } }));

    // Per partition: g = a a b b; x 1 2 1 2 against y 1 2 2 1: +1 and -1.
    const p = try st.mk(a, &.{ .{ .name = "g", .type = .text }, .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{
        &.{ .{ .text = "a" }, int(1), int(1) }, &.{ .{ .text = "a" }, int(2), int(2) },
        &.{ .{ .text = "b" }, int(1), int(2) }, &.{ .{ .text = "b" }, int(2), int(1) },
    });
    const pr = try df.window(a, p, .{ .value_col = "x", .out = "r", .op = .{ .rolling_corr = .{ .other = "y", .window = 2 } }, .partition_by = &.{"g"} });
    try expectFloats(pr, "r", &.{ null, 1, null, -1 });
    try testing.expectEqual(df.ColumnType.float, pr.columns[3].type);
}
