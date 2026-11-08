// SPDX-License-Identifier: MIT
//! `Frame` storage against `dataset`'s `Frame`, which it was taken from: the same cells
//! give the same storage kind, the same arrays, the same bitmaps, and the same answers
//! from every accessor both have, on tables built to reach each storage kind and each
//! move between them. Then what only this module promises: hand-built frames read as
//! null past their arrays, the builder's failure is sticky, `big_block_allocator`.

const std = @import("std");
const testing = std.testing;
const ds = @import("dataset");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const Value = vm.Value;
const Column = vm.Column;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;

// ── the bridge to `dataset` (test-only) ─────────────────────────────────────

pub fn cellOf(v: ds.Value) Value {
    return switch (v) {
        .null => .null,
        .int => |x| .{ .int = x },
        .float => |x| .{ .float = x },
        .text => |x| .{ .text = x },
        .bool => |x| .{ .bool = x },
        .decimal => |x| .{ .decimal = x },
    };
}

pub fn columnsOf(a: std.mem.Allocator, cols: []const ds.Column) ![]const Column {
    const out = try a.alloc(Column, cols.len);
    for (out, cols) |*o, c| o.* = .{ .name = c.name, .type = std.meta.stringToEnum(vm.ColumnType, @tagName(c.type)).? };
    return out;
}

/// `d` as a `Frame`, through `FrameBuilder`: what a caller of this module does.
pub fn frameOf(a: std.mem.Allocator, d: ds.Dataset) !Frame {
    var b = try fm.FrameBuilder.init(a, try columnsOf(a, d.columns), d.rows.len);
    const row = try a.alloc(Value, d.columns.len);
    for (d.rows) |r| {
        for (row, r) |*o, c| o.* = cellOf(c);
        try b.appendRow(row);
    }
    return b.toOwned();
}

pub fn sameCell(w: ds.Value, g: Value) bool {
    if (!std.mem.eql(u8, @tagName(std.meta.activeTag(w)), @tagName(std.meta.activeTag(g)))) return false;
    return switch (g) {
        .null => true,
        .int => |x| x == w.int,
        // To the bit, any NaN being NaN.
        .float => |x| (std.math.isNan(x) and std.math.isNan(w.float)) or @as(u64, @bitCast(x)) == @as(u64, @bitCast(w.float)),
        .text => |x| std.mem.eql(u8, x, w.text),
        .bool => |x| x == w.bool,
        .decimal => |x| x == w.decimal,
    };
}

fn expectSameBits(want: ?[]const u64, got: ?[]const u64) !void {
    try testing.expectEqual(want == null, got == null);
    if (got) |g| try testing.expectEqualSlices(u64, want.?, g);
}

/// The same storage kind and the same arrays, to the bit.
fn expectSameStorage(want: ds.ColumnData, got: ColumnData) !void {
    try testing.expectEqualStrings(@tagName(std.meta.activeTag(want)), @tagName(std.meta.activeTag(got)));
    switch (got) {
        .nulls => {},
        .int => |c| {
            try testing.expectEqualSlices(i64, want.int.values, c.values);
            try expectSameBits(want.int.valid, c.valid);
        },
        .float => |c| {
            try testing.expectEqualSlices(u64, @ptrCast(want.float.values), @ptrCast(c.values));
            try expectSameBits(want.float.valid, c.valid);
        },
        .bool => |c| {
            try testing.expectEqualSlices(bool, want.bool.values, c.values);
            try expectSameBits(want.bool.valid, c.valid);
        },
        .decimal => |c| {
            try testing.expectEqualSlices(i128, want.decimal.values, c.values);
            try expectSameBits(want.decimal.valid, c.valid);
        },
        .text => |c| {
            try testing.expectEqualSlices(usize, want.text.offsets, c.offsets);
            try testing.expectEqualSlices(u8, want.text.bytes, c.bytes);
            try expectSameBits(want.text.valid, c.valid);
        },
        .categorical => return error.TestUnexpectedResult, // `dataset` has no such storage
        .boxed => |c| {
            try testing.expectEqual(want.boxed.len, c.len);
            for (want.boxed, c) |w, g| try testing.expect(sameCell(w, g));
        },
    }
}

/// Everything both frames answer, on one table.
fn expectAgree(a: std.mem.Allocator, d: ds.Dataset) !void {
    const want = try ds.Frame.fromDataset(a, d);
    const f = try frameOf(a, d);
    try testing.expectEqual(want.len, f.len);
    try testing.expectEqual(d.rowCount(), f.rowCount());
    for (want.data, f.data, 0..) |w, g, ci| {
        try expectSameStorage(w, g);
        const cells = try a.alloc(Value, d.rows.len);
        for (cells, d.rows) |*c, r| c.* = cellOf(r[ci]);
        try expectSameStorage(w, try fm.columnFromCells(a, cells));
    }
    for (d.columns) |c| {
        try testing.expectEqualStrings(@tagName(want.columnType(c.name).?), @tagName(f.columnType(c.name).?));
        const wf = try want.floatColumn(a, c.name);
        const gf = try f.floatColumn(a, c.name);
        try testing.expectEqualSlices(u64, @ptrCast(wf), @ptrCast(gf));
        for (0..d.rows.len) |r| try testing.expect(sameCell(want.cell(r, c.name).?, f.cell(r, c.name).?));
        try testing.expectEqual(@as(?Value, null), f.cell(d.rows.len, c.name));
        const wxy = try want.seriesXY(a, c.name, d.columns[0].name);
        const gxy = try f.seriesXY(a, c.name, d.columns[0].name);
        try testing.expectEqualSlices(u64, @ptrCast(wxy), @ptrCast(gxy));
        const s = f.series(c.name).?;
        try testing.expectEqual(f.len, s.len);
        var nulls: usize = 0;
        for (0..d.rows.len) |r| {
            try testing.expect(sameCell(want.cell(r, c.name).?, s.get(r)));
            const v = s.get(r);
            nulls += @intFromBool(v == .null or (v == .float and std.math.isNan(v.float)));
        }
        try testing.expectEqual(nulls, s.nullCount());
        try testing.expectEqual(Value.null, s.get(f.len));
    }
    try testing.expectEqual(@as(?Value, null), f.cell(0, "no such column"));
    try testing.expectEqual(@as(?fm.Series, null), f.series("no such column"));
    try testing.expectError(error.NoSuchColumn, f.floatColumn(a, "no such column"));
}

const all_types = [_]ds.Column{
    .{ .name = "i", .type = .int },
    .{ .name = "f", .type = .float },
    .{ .name = "t", .type = .text },
    .{ .name = "b", .type = .bool },
    .{ .name = "d", .type = .date },
    .{ .name = "x", .type = .decimal },
    .{ .name = "s", .type = .timestamp },
};

fn randomValue(r: std.Random, a: std.mem.Allocator, tag: u8) !ds.Value {
    return switch (tag) {
        0 => .null,
        1 => .{ .int = @bitCast(r.int(u64)) },
        2 => .{ .float = @bitCast(r.int(u64)) }, // NaNs, infinities, -0.0, all of it
        3 => blk: {
            const t = try a.alloc(u8, r.uintLessThan(usize, 12));
            r.bytes(t); // not UTF-8: a cell is bytes
            break :blk .{ .text = t };
        },
        4 => .{ .bool = r.boolean() },
        else => .{ .decimal = @bitCast(r.int(u128)) },
    };
}

test "Frame storage agrees with dataset's on one table of each column type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = [_][]const ds.Value{
        &.{ .{ .int = 1 }, .{ .float = 1.5 }, .{ .text = "a" }, .{ .bool = true }, .{ .text = "2024-01-02" }, .{ .decimal = 1_500_000_000_000 }, .{ .int = 1_700_000_000_000_000 } },
        &.{ .null, .null, .null, .null, .null, .null, .null },
        &.{ .{ .int = -3 }, .{ .float = std.math.nan(f64) }, .{ .text = "" }, .{ .bool = false }, .{ .text = "1999-12-31" }, .{ .decimal = -7 }, .{ .int = 0 } },
    };
    try expectAgree(a, .{ .columns = &all_types, .rows = &rows });
}

test "Frame: a null is not an empty string, nor NaN, nor zero" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "t", .type = .text }, .{ .name = "f", .type = .float }, .{ .name = "i", .type = .int } };
    var b = try fm.FrameBuilder.init(a, &cols, 0);
    try b.appendRow(&.{ .{ .text = "" }, .{ .float = std.math.nan(f64) }, .{ .int = 0 } });
    try b.appendRow(&.{ .null, .null, .null });
    const f = try b.toOwned();
    try testing.expectEqualStrings("", f.cell(0, "t").?.text);
    try testing.expect(f.cell(1, "t").? == .null);
    try testing.expect(std.math.isNan(f.cell(0, "f").?.float));
    try testing.expect(f.cell(1, "f").? == .null);
    try testing.expectEqual(@as(i64, 0), f.cell(0, "i").?.int);
    try testing.expect(f.cell(1, "i").? == .null);
    try testing.expectEqual(@as(?[]const u8, null), f.column("t").?.text.at(1));
    // NaN counts as missing in a `Series`, as it does in every verb.
    try testing.expectEqual(@as(usize, 2), f.series("f").?.nullCount());
    try testing.expectEqual(@as(usize, 1), f.series("t").?.nullCount());
}

test "Frame: storage follows the cells, not the declared type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{
        .{ .name = "float_of_ints", .type = .float },
        .{ .name = "mixed", .type = .float },
        .{ .name = "empty", .type = .decimal },
        .{ .name = "date", .type = .date },
        .{ .name = "ts", .type = .timestamp },
    };
    const rows = [_][]const ds.Value{
        &.{ .{ .int = 2 }, .{ .int = 2 }, .null, .{ .text = "2024-01-01" }, .{ .int = 9 } },
        &.{ .{ .int = 3 }, .{ .float = 2.5 }, .null, .{ .text = "2024-01-02" }, .{ .int = 10 } },
        &.{ .{ .int = 4 }, .{ .text = "n/a" }, .null, .{ .text = "2024-01-03" }, .null },
    };
    const d: ds.Dataset = .{ .columns = &cols, .rows = &rows };
    try expectAgree(a, d);
    const f = try frameOf(a, d);
    try testing.expect(f.column("float_of_ints").? == .int);
    try testing.expect(f.column("mixed").? == .boxed);
    try testing.expect(f.column("empty").? == .nulls);
    try testing.expect(f.column("date").? == .text);
    try testing.expect(f.column("ts").? == .int);
    try testing.expectEqual(vm.ColumnType.float, f.columnType("float_of_ints").?);
}

test "Frame.floatColumn borrows a float column, and a null there reads 0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "f", .type = .float }};
    var b = try fm.FrameBuilder.init(a, &cols, 3);
    for ([_]Value{ .{ .float = 1.5 }, .null, .{ .float = 2.5 } }) |v| try b.appendRow(&.{v});
    const f = try b.toOwned();
    const v = try f.floatColumn(testing.failing_allocator, "f"); // no allocation
    try testing.expectEqual(f.column("f").?.float.values.ptr, v.ptr);
    try testing.expectEqualSlices(f64, &.{ 1.5, 0, 2.5 }, v);
}

test "Frame: every move between storage kinds, around the validity word boundary" {
    // A column of `n` cells: nulls up to `first`, one tag, then another tag at `change`.
    // 63, 64, 65 are the bitmap's word edge.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{.{ .name = "c", .type = .text }};
    const samples = [_]ds.Value{ .{ .int = 7 }, .{ .float = 0.5 }, .{ .text = "txt" }, .{ .bool = true }, .{ .decimal = 11 } };
    const n = 130;
    for ([_]usize{ 0, 1, 63, 64, 65, 129 }) |first| {
        for ([_]usize{ 1, 63, 64, 65, 128, n }) |change| {
            for (samples) |one| {
                for (samples) |two| {
                    for ([_]usize{ n + 1, 3, 64 }) |hole_every| { // no holes, and two rhythms
                        _ = arena.reset(.retain_capacity);
                        const rows = try a.alloc([]const ds.Value, n);
                        for (rows, 0..) |*r, i| {
                            const c = try a.alloc(ds.Value, 1);
                            c[0] = if (i < first or i % hole_every == hole_every - 1) .null else if (i < change) one else two;
                            r.* = c;
                        }
                        try expectAgree(a, .{ .columns = &cols, .rows = rows });
                    }
                }
            }
        }
    }
}

test "Frame: 2000 random tables, any tag in any column" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0x4652414d45);
    const r = prng.random();
    for (0..2000) |_| {
        _ = arena.reset(.retain_capacity);
        const ncol = 1 + r.uintLessThan(usize, 5);
        const nrow = r.uintLessThan(usize, 80);
        const cols = try a.alloc(ds.Column, ncol);
        for (cols, 0..) |*c, i| c.* = .{ .name = try a.print("c{d}", .{i}), .type = @fromBackingInt(r.uintLessThan(u3, 7)) };
        // Per column: the tags it may draw, so that pure and mixed columns both occur.
        const fixed = try a.alloc(?u8, ncol);
        for (fixed) |*t| t.* = if (r.boolean()) r.uintLessThan(u8, 6) else null;
        const rows = try a.alloc([]const ds.Value, nrow);
        for (rows) |*row| {
            const cells = try a.alloc(ds.Value, ncol);
            for (cells, fixed) |*c, t| {
                const tag = if (r.uintLessThan(u8, 5) == 0) 0 else t orelse r.uintLessThan(u8, 6);
                c.* = try randomValue(r, a, tag);
            }
            row.* = cells;
        }
        try expectAgree(a, .{ .columns = cols, .rows = rows });
    }
}

test "Frame: no columns, no rows" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectAgree(a, .{ .columns = &all_types, .rows = &.{} });
    var b = try fm.FrameBuilder.init(a, &.{}, 0);
    for (0..3) |_| try b.appendRow(&.{});
    const f = try b.toOwned();
    try testing.expectEqual(@as(usize, 3), f.len);
    try testing.expectEqual(@as(usize, 0), f.data.len);
}

test "FrameBuilder: a wrong row length is an error, not a panic, and adds nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    for ([_][]const Value{ &.{.{ .int = 1 }}, &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } } }) |bad| {
        var b = try fm.FrameBuilder.init(a, &cols, 0);
        try testing.expectError(error.RowLength, b.appendRow(bad));
        try testing.expectEqual(@as(usize, 0), (try b.toOwned()).len);
    }
}

test "FrameBuilder keeps nothing of what it was given" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "t", .type = .text }, .{ .name = "m", .type = .text } };
    // The caller's buffer, reused between rows.
    var buf: [4]u8 = "aaaa".*;
    var b = try fm.FrameBuilder.init(a, &cols, 0);
    try b.appendRow(&.{ .{ .text = &buf }, .{ .int = 1 } });
    @memcpy(&buf, "bbbb");
    try b.appendRow(&.{ .{ .text = &buf }, .{ .text = &buf } }); // `m` is boxed from here
    @memcpy(&buf, "cccc");
    const f = try b.toOwned();
    try testing.expectEqualStrings("aaaa", f.cell(0, "t").?.text);
    try testing.expectEqualStrings("bbbb", f.cell(1, "t").?.text);
    try testing.expectEqualStrings("bbbb", f.cell(1, "m").?.text);
}

test "Frame: a hand-built one with short arrays reads as null past their end, no panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "i", .type = .int },  .{ .name = "t", .type = .text },
        .{ .name = "b", .type = .text }, .{ .name = "bad", .type = .text },
        .{ .name = "v", .type = .int },  .{ .name = "gone", .type = .int },
    };
    const data = [_]ColumnData{
        .{ .int = .{ .values = &.{1} } },
        .{ .text = .{ .offsets = &.{ 0, 1 }, .bytes = "x" } },
        .{ .boxed = &.{.{ .int = 5 }} },
        .{ .text = .{ .offsets = &.{ 5, 1, 99 }, .bytes = "x" } }, // offsets out of order, past the bytes
        .{ .int = .{ .values = &.{ 1, 2, 3 }, .valid = &.{} } }, // a bitmap too short
    };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 3 };
    for (cols) |c| {
        for (0..4) |r| _ = f.cell(r, c.name);
        _ = try f.floatColumn(a, c.name);
        const s = f.series(c.name).?;
        for (0..4) |r| _ = s.get(r);
        _ = s.nullCount();
    }
    try testing.expect(f.cell(2, "i").? == .null);
    try testing.expect(f.cell(0, "bad").? == .null);
    try testing.expect(f.cell(0, "v").? == .null);
    // Fewer arrays than columns: the missing one is all null, not an error.
    try testing.expect(f.cell(0, "gone").? == .null);
    try testing.expect(f.columnAt(5) == .nulls);
    try testing.expect(f.column("gone").? == .nulls);
    try testing.expectEqualSlices(f64, &.{ 0, 0, 0 }, try f.floatColumn(a, "gone"));
    try testing.expectEqual(@as(usize, 3), f.series("gone").?.nullCount());
    _ = try f.seriesXY(a, "i", "t");
}

test "Frame: the first null past the bitmap's first word keeps every row before it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{ .{ .name = "i", .type = .int }, .{ .name = "t", .type = .text } };
    for ([_]usize{ 63, 64, 65, 127, 128, 129, 199 }) |at| {
        _ = arena.reset(.retain_capacity);
        const rows = try a.alloc([]const ds.Value, 200);
        for (rows, 0..) |*r, i| {
            const c = try a.alloc(ds.Value, 2);
            c[0] = if (i == at) .null else .{ .int = @intCast(i) };
            c[1] = if (i == at) .null else .{ .text = "x" };
            r.* = c;
        }
        try expectAgree(a, .{ .columns = &cols, .rows = rows });
    }
}

test "Frame.floatColumn: a hand-built array shorter than len is not handed back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "f", .type = .float }, .{ .name = "i", .type = .int } };
    const data = [_]ColumnData{
        .{ .float = .{ .values = &.{1.5} } },
        // Bits set past len: they must not make a row past len readable.
        .{ .int = .{ .values = &.{ 1, 2, 3, 4 }, .valid = &.{~@as(u64, 0)} } },
    };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 3 };
    try testing.expectEqualSlices(f64, &.{ 1.5, 0, 0 }, try f.floatColumn(a, "f"));
    try testing.expectEqual(@as(?Value, null), f.cell(3, "i"));
    try testing.expectEqual(Value.null, f.series("i").?.get(3));
}

test "ColumnData.get: any row past the end is null, even the largest one" {
    const m = std.math.maxInt(usize);
    const text: ColumnData = .{ .text = .{ .offsets = &.{ 0, 1 }, .bytes = "x" } };
    try testing.expect(text.get(m) == .null);
    try testing.expect(text.get(m - 1) == .null);
    try testing.expect(text.get(1) == .null);
    try testing.expectEqualStrings("x", text.get(0).text);
    const no_offsets: ColumnData = .{ .text = .{ .offsets = &.{}, .bytes = "" } };
    try testing.expect(no_offsets.get(0) == .null);
    const int: ColumnData = .{ .int = .{ .values = &.{1} } };
    try testing.expect(int.get(m) == .null);
    const boxed: ColumnData = .{ .boxed = &.{.{ .int = 1 }} };
    try testing.expect(boxed.get(m) == .null);
}

test "FrameBuilder: an allocation that fails leaves no half row behind" {
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text }, .{ .name = "c", .type = .text } };
    const row = [_]Value{ .{ .int = 1 }, .{ .text = "text" }, .{ .int = 2 } };
    var saw_failure = false;
    for (0..60) |fail_at| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var fa = std.testing.FailingAllocator.init(arena.allocator(), .{ .fail_index = fail_at });
        const a = fa.allocator();
        var b = fm.FrameBuilder.init(a, &cols, 0) catch continue;
        var failed = false;
        for (0..80) |_| {
            b.appendRow(&row) catch {
                failed = true;
                break;
            };
        }
        if (!failed) continue;
        saw_failure = true;
        fa.fail_index = std.math.maxInt(usize); // memory is back; the builder stays spent
        try testing.expectError(error.OutOfMemory, b.appendRow(&row));
        try testing.expectError(error.OutOfMemory, b.toOwned());
    }
    try testing.expect(saw_failure);
}

test "big_block_allocator: under an arena, small and big blocks, and big ones aligned" {
    var arena = std.heap.ArenaAllocator.init(fm.big_block_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const small = try a.alloc(u8, 100);
    @memset(small, 1);
    const big = try fm.big_block_allocator.alloc(u8, 3 * 1024 * 1024);
    defer fm.big_block_allocator.free(big);
    try testing.expect(@intFromPtr(big.ptr) % (2 * 1024 * 1024) == 0);
    @memset(big, 2);
    try testing.expectEqual(@as(u8, 2), big[big.len - 1]);
    const huge = try a.alloc(f64, 1 << 20);
    @memset(huge, 3);
    try testing.expectEqual(@as(f64, 3), huge[huge.len - 1]);
}

test "big_block_allocator: a length near the address space is a refusal, not an overflow" {
    const a = fm.big_block_allocator;
    const top = std.math.maxInt(usize);
    for ([_]usize{ top - 5000, top - 1024 * 1024, top - 2 * 1024 * 1024 - 8192 }) |len| {
        try testing.expect(a.rawAlloc(len, .@"1", 0) == null);
    }
}

test "huge_page_allocator: under an arena, small and big blocks, big ones aligned, a huge length refused" {
    var arena = std.heap.ArenaAllocator.init(fm.huge_page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const small = try a.alloc(u8, 100);
    @memset(small, 7);
    const big = try fm.huge_page_allocator.alloc(u8, 3 * 1024 * 1024);
    defer fm.huge_page_allocator.free(big);
    try testing.expect(@intFromPtr(big.ptr) % (2 * 1024 * 1024) == 0);
    big[big.len - 1] = 9;
    try testing.expect(fm.huge_page_allocator.rawAlloc(std.math.maxInt(usize) - 5000, .@"1", 0) == null);
}

test "big_block_allocator: huge-page advice only where defrag does not compact directly" {
    const f = fm.defragWithoutDirectCompaction;
    // The selected value is the bracketed word; only `defer` and `never` skip direct
    // compaction for an advised region (kernel admin-guide/mm/transhuge).
    try testing.expect(f("always defer defer+madvise madvise [never]\n"));
    try testing.expect(f("always [defer] defer+madvise madvise never\n"));
    try testing.expect(!f("always defer defer+madvise [madvise] never\n"));
    try testing.expect(!f("[always] defer defer+madvise madvise never\n"));
    try testing.expect(!f("always defer [defer+madvise] madvise never\n"));
    // Unreadable, empty or malformed: no advice.
    try testing.expect(!f(""));
    try testing.expect(!f("defer"));
    try testing.expect(!f("[defer"));
    try testing.expect(!f("]defer["));
    try testing.expect(!f("[]"));
}

test "columnFromCells: the array the tags call for" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fl = try fm.columnFromCells(a, &.{ .{ .float = 1 }, .null });
    try testing.expect(fl == .float);
    try testing.expectEqual(Value.null, fl.get(1));
    try testing.expect(try fm.columnFromCells(a, &.{ .{ .float = 1 }, .{ .int = 1 } }) == .boxed);
    try testing.expect(try fm.columnFromCells(a, &.{}) == .nulls);
}
