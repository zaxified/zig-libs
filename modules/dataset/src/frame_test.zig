// SPDX-License-Identifier: MIT

//! `Frame` against `Dataset`: every function that exists on both gives the same
//! answer, on tables built to reach each storage kind and each move between them.

const std = @import("std");
const testing = std.testing;
const ds = @import("root.zig");
const Value = ds.Value;
const Dataset = ds.Dataset;
const Frame = ds.Frame;

const all_types = [_]ds.Column{
    .{ .name = "i", .type = .int },
    .{ .name = "f", .type = .float },
    .{ .name = "t", .type = .text },
    .{ .name = "b", .type = .bool },
    .{ .name = "d", .type = .date },
    .{ .name = "x", .type = .decimal },
    .{ .name = "s", .type = .timestamp },
};

/// Same cells, compared by bit pattern (`Value.eql` calls NaN unequal to itself and
/// -0.0 equal to 0.0; a round trip must keep both).
fn expectSameCells(want: Dataset, got: Dataset) !void {
    try testing.expectEqual(want.rows.len, got.rows.len);
    for (want.rows, got.rows) |wr, gr| {
        try testing.expectEqual(wr.len, gr.len);
        for (wr, gr) |w, g| {
            try testing.expectEqual(std.meta.activeTag(w), std.meta.activeTag(g));
            switch (w) {
                .null => {},
                .int => |x| try testing.expectEqual(x, g.int),
                .float => |x| try testing.expectEqual(@as(u64, @bitCast(x)), @as(u64, @bitCast(g.float))),
                .text => |x| try testing.expectEqualStrings(x, g.text),
                .bool => |x| try testing.expectEqual(x, g.bool),
                .decimal => |x| try testing.expectEqual(x, g.decimal),
            }
        }
    }
}

/// Everything `Dataset` and `Frame` both answer, on one table.
fn expectAgree(a: std.mem.Allocator, d: Dataset) !void {
    const f = try Frame.fromDataset(a, d);
    try testing.expectEqual(d.rowCount(), f.rowCount());
    try expectSameCells(d, try f.toDataset(a));

    const wire = try ds.serialize(a, d);
    try testing.expectEqualSlices(u8, wire, try ds.serializeFrame(a, f));
    const back = try ds.deserializeFrame(a, wire);
    try expectSameCells(d, try back.toDataset(a));
    try testing.expectEqualSlices(u8, wire, try ds.serializeFrame(a, back));
    try testing.expectEqualSlices(u8, try ds.toJson(a, d), try ds.frameToJson(a, f));

    for (d.columns) |c| {
        try testing.expectEqual(d.columnType(c.name), f.columnType(c.name));
        const want = try d.floatColumn(a, c.name);
        const got = try f.floatColumn(a, c.name);
        try testing.expectEqual(want.len, got.len);
        for (want, got) |w, g| try testing.expectEqual(@as(u64, @bitCast(w)), @as(u64, @bitCast(g)));
        for (0..d.rows.len) |r| {
            const w = d.cell(r, c.name).?;
            const g = f.cell(r, c.name).?;
            try testing.expectEqual(std.meta.activeTag(w), std.meta.activeTag(g));
        }
        try testing.expectEqual(@as(?Value, null), f.cell(d.rows.len, c.name));
        const wxy = try d.seriesXY(a, c.name, d.columns[0].name);
        const gxy = try f.seriesXY(a, c.name, d.columns[0].name);
        for (wxy, gxy) |w, g| {
            try testing.expectEqual(@as(u64, @bitCast(w[0])), @as(u64, @bitCast(g[0])));
            try testing.expectEqual(@as(u64, @bitCast(w[1])), @as(u64, @bitCast(g[1])));
        }
    }
    try testing.expectEqual(@as(?Value, null), f.cell(0, "no such column"));
    try testing.expectError(error.NoSuchColumn, f.floatColumn(a, "no such column"));

    // The builder gives the same frame as the conversion.
    var b = try ds.FrameBuilder.init(a, d.columns, 0);
    for (d.rows) |r| try b.appendRow(r);
    try testing.expectEqualSlices(u8, wire, try ds.serializeFrame(a, try b.toOwned()));
}

fn randomValue(r: std.Random, a: std.mem.Allocator, tag: u8) !Value {
    return switch (tag) {
        0 => .null,
        1 => .{ .int = @bitCast(r.int(u64)) },
        2 => .{ .float = @bitCast(r.int(u64)) }, // NaNs, infinities, -0.0, all of it
        3 => blk: {
            const t = try a.alloc(u8, r.uintLessThan(usize, 12));
            r.bytes(t); // not UTF-8, as `deserialize` allows
            break :blk .{ .text = t };
        },
        4 => .{ .bool = r.boolean() },
        else => .{ .decimal = @bitCast(r.int(u128)) },
    };
}

test "Frame agrees with Dataset on one table of each column type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = [_][]const Value{
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
    const cols = [_]ds.Column{ .{ .name = "t", .type = .text }, .{ .name = "f", .type = .float }, .{ .name = "i", .type = .int } };
    const rows = [_][]const Value{
        &.{ .{ .text = "" }, .{ .float = std.math.nan(f64) }, .{ .int = 0 } },
        &.{ .null, .null, .null },
    };
    const f = try Frame.fromDataset(a, .{ .columns = &cols, .rows = &rows });
    try testing.expectEqualStrings("", f.cell(0, "t").?.text);
    try testing.expect(f.cell(1, "t").? == .null);
    try testing.expect(std.math.isNan(f.cell(0, "f").?.float));
    try testing.expect(f.cell(1, "f").? == .null);
    try testing.expectEqual(@as(i64, 0), f.cell(0, "i").?.int);
    try testing.expect(f.cell(1, "i").? == .null);
    try testing.expectEqual(@as(?[]const u8, null), f.column("t").?.text.at(1));
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
    const rows = [_][]const Value{
        &.{ .{ .int = 2 }, .{ .int = 2 }, .null, .{ .text = "2024-01-01" }, .{ .int = 9 } },
        &.{ .{ .int = 3 }, .{ .float = 2.5 }, .null, .{ .text = "2024-01-02" }, .{ .int = 10 } },
        &.{ .{ .int = 4 }, .{ .text = "n/a" }, .null, .{ .text = "2024-01-03" }, .null },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    try expectAgree(a, d);
    const f = try Frame.fromDataset(a, d);
    try testing.expect(f.column("float_of_ints").? == .int);
    try testing.expect(f.column("mixed").? == .boxed);
    try testing.expect(f.column("empty").? == .nulls);
    try testing.expect(f.column("date").? == .text);
    try testing.expect(f.column("ts").? == .int);
    try testing.expectEqual(ds.ColumnType.float, f.columnType("float_of_ints").?);
}

test "Frame.floatColumn borrows a float column, and a null there reads 0 as in Dataset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{.{ .name = "f", .type = .float }};
    const rows = [_][]const Value{ &.{.{ .float = 1.5 }}, &.{.null}, &.{.{ .float = 2.5 }} };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const f = try Frame.fromDataset(a, d);
    const v = try f.floatColumn(testing.failing_allocator, "f"); // no allocation
    try testing.expectEqual(f.column("f").?.float.values.ptr, v.ptr);
    try testing.expectEqualSlices(f64, try d.floatColumn(a, "f"), v);
    try testing.expectEqualSlices(f64, &.{ 1.5, 0, 2.5 }, v);
}

test "Frame: every move between storage kinds, around the validity word boundary" {
    // A column of `n` cells: nulls up to `first`, one tag, then another tag at `change`.
    // 63, 64, 65 are the bitmap's word edge.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{.{ .name = "c", .type = .text }};
    const samples = [_]Value{ .{ .int = 7 }, .{ .float = 0.5 }, .{ .text = "txt" }, .{ .bool = true }, .{ .decimal = 11 } };
    const n = 130;
    for ([_]usize{ 0, 1, 63, 64, 65, 129 }) |first| {
        for ([_]usize{ 1, 63, 64, 65, 128, n }) |change| {
            for (samples) |one| {
                for (samples) |two| {
                    for ([_]usize{ n + 1, 3, 64 }) |hole_every| { // no holes, and two rhythms
                        _ = arena.reset(.retain_capacity);
                        const rows = try a.alloc([]const Value, n);
                        for (rows, 0..) |*r, i| {
                            const c = try a.alloc(Value, 1);
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
        for (cols, 0..) |*c, i| c.* = .{ .name = try std.fmt.allocPrint(a, "c{d}", .{i}), .type = @fromBackingInt(r.uintLessThan(u3, 7)) };
        // Per column: the tags it may draw, so that pure and mixed columns both occur.
        const fixed = try a.alloc(?u8, ncol);
        for (fixed) |*t| t.* = if (r.boolean()) r.uintLessThan(u8, 6) else null;
        const rows = try a.alloc([]const Value, nrow);
        for (rows) |*row| {
            const cells = try a.alloc(Value, ncol);
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
    const empty_row = [_][]const Value{ &.{}, &.{}, &.{} };
    const d: Dataset = .{ .columns = &.{}, .rows = &empty_row };
    const f = try Frame.fromDataset(a, d);
    try testing.expectEqual(@as(usize, 3), f.len);
    try expectSameCells(d, try f.toDataset(a));
    try testing.expectEqualSlices(u8, try ds.serialize(a, d), try ds.serializeFrame(a, f));
    // Rows with no cells encode to nothing, so the input cannot prove their count:
    // both decoders refuse them.
    const image = try ds.serializeFrame(a, f);
    try testing.expectError(error.Corrupt, ds.deserialize(a, image));
    try testing.expectError(error.Corrupt, ds.deserializeFrame(a, image));
}

test "Frame: a ragged row and a wrong row length are errors, not panics" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    for ([_][]const Value{ &.{.{ .int = 1 }}, &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } } }) |bad| {
        const rows = [_][]const Value{ &.{ .{ .int = 1 }, .{ .int = 2 } }, bad };
        try testing.expectError(error.RaggedRow, Frame.fromDataset(a, .{ .columns = &cols, .rows = &rows }));
        var b = try ds.FrameBuilder.init(a, &cols, 0);
        try testing.expectError(error.RowLength, b.appendRow(bad));
        try testing.expectEqual(@as(usize, 0), (try b.toOwned()).len);
    }
}

test "Frame keeps nothing of what it was built from" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{ .{ .name = "t", .type = .text }, .{ .name = "m", .type = .text } };

    // The caller's buffer, reused between rows.
    var buf: [4]u8 = "aaaa".*;
    var b = try ds.FrameBuilder.init(a, &cols, 0);
    try b.appendRow(&.{ .{ .text = &buf }, .{ .int = 1 } });
    @memcpy(&buf, "bbbb");
    try b.appendRow(&.{ .{ .text = &buf }, .{ .text = &buf } }); // `m` is boxed from here
    @memcpy(&buf, "cccc");
    const f = try b.toOwned();
    try testing.expectEqualStrings("aaaa", f.cell(0, "t").?.text);
    try testing.expectEqualStrings("bbbb", f.cell(1, "t").?.text);
    try testing.expectEqualStrings("bbbb", f.cell(1, "m").?.text);

    // The wire image, overwritten after the decode: typed and boxed text alike.
    const rows = [_][]const Value{
        &.{ .{ .text = "keep" }, .{ .int = 1 } },
        &.{ .{ .text = "this" }, .{ .text = "too" } },
    };
    const wire = try ds.serialize(a, .{ .columns = &cols, .rows = &rows });
    const g = try ds.deserializeFrame(a, wire);
    @memset(wire, 0xAA);
    try testing.expectEqualStrings("this", g.cell(1, "t").?.text);
    try testing.expectEqualStrings("too", g.cell(1, "m").?.text);
}

test "deserializeFrame refuses every cut of a document, and every bad tag, as deserialize does" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = [_][]const Value{
        &.{ .{ .int = 1 }, .{ .float = 1.5 }, .{ .text = "abc" }, .{ .bool = true }, .{ .text = "2024-01-02" }, .{ .decimal = 5 }, .null },
    };
    const wire = try ds.serialize(a, .{ .columns = &all_types, .rows = &rows });
    for (0..wire.len) |n| {
        try testing.expectError(error.Corrupt, ds.deserialize(a, wire[0..n]));
        try testing.expectError(error.Corrupt, ds.deserializeFrame(a, wire[0..n]));
    }
    // Every byte flipped to every value: the two agree on accept or refuse, and on the
    // bytes they would write back (a bool's non-zero byte normalises in both).
    const bad = try a.dupe(u8, wire);
    for (0..wire.len) |i| {
        for ([_]u8{ 0, 1, 2, 3, 4, 5, 6, 0x7f, 0xff }) |x| {
            var scratch = std.heap.ArenaAllocator.init(testing.allocator);
            defer scratch.deinit();
            const s = scratch.allocator();
            @memcpy(bad, wire);
            bad[i] = x;
            if (ds.deserialize(s, bad)) |d| {
                const f = try ds.deserializeFrame(s, bad);
                try testing.expectEqualSlices(u8, try ds.serialize(s, d), try ds.serializeFrame(s, f));
            } else |e| try testing.expectError(e, ds.deserializeFrame(s, bad));
        }
    }
}

test "Frame: a wire count larger than the input can prove is refused before allocating" {
    // 4 columns' worth of header claiming 2^32 - 1 rows; a failing allocator past the
    // header would show an attempt to reserve them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{.{ .name = "a", .type = .int }};
    const image = try ds.serialize(a, .{ .columns = &cols, .rows = &.{} });
    std.mem.writeInt(u32, image[image.len - 4 ..][0..4], std.math.maxInt(u32), .little);
    try testing.expectError(error.Corrupt, ds.deserializeFrame(a, image));
}

test "Frame: a hand-built one with short arrays reads as null past their end, no panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{
        .{ .name = "i", .type = .int },  .{ .name = "t", .type = .text },
        .{ .name = "b", .type = .text }, .{ .name = "bad", .type = .text },
        .{ .name = "v", .type = .int },  .{ .name = "gone", .type = .int },
    };
    const data = [_]ds.ColumnData{
        .{ .int = .{ .values = &.{1} } },
        .{ .text = .{ .offsets = &.{ 0, 1 }, .bytes = "x" } },
        .{ .boxed = &.{.{ .int = 5 }} },
        .{ .text = .{ .offsets = &.{ 5, 1, 99 }, .bytes = "x" } }, // offsets out of order, past the bytes
        .{ .int = .{ .values = &.{ 1, 2, 3 }, .valid = &.{} } }, // a bitmap too short
    };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 3 };
    for (cols) |c| {
        for (0..4) |r| _ = f.cell(r, c.name);
        if (std.mem.eql(u8, c.name, "gone")) {
            try testing.expectError(error.NoSuchColumn, f.floatColumn(a, c.name));
        } else {
            _ = try f.floatColumn(a, c.name);
        }
    }
    try testing.expect(f.cell(2, "i").? == .null);
    try testing.expect(f.cell(0, "bad").? == .null);
    try testing.expect(f.cell(0, "v").? == .null);
    try testing.expectEqual(@as(?Value, null), f.cell(0, "gone"));
    _ = try f.toDataset(a);
    _ = try ds.serializeFrame(a, f);
    _ = try ds.frameToJson(a, f);
    _ = try f.seriesXY(a, "i", "t");
}

test "Frame: the first null past the bitmap's first word keeps every row before it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{ .{ .name = "i", .type = .int }, .{ .name = "t", .type = .text } };
    for ([_]usize{ 63, 64, 65, 127, 128, 129, 199 }) |at| {
        _ = arena.reset(.retain_capacity);
        const rows = try a.alloc([]const Value, 200);
        for (rows, 0..) |*r, i| {
            const c = try a.alloc(Value, 2);
            c[0] = if (i == at) .null else .{ .int = @intCast(i) };
            c[1] = if (i == at) .null else .{ .text = "x" };
            r.* = c;
        }
        try expectAgree(a, .{ .columns = &cols, .rows = rows });
    }
}

test "Frame: hand-built arrays that disagree with len write what they read" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{ .{ .name = "f", .type = .float }, .{ .name = "i", .type = .int }, .{ .name = "t", .type = .text } };
    const data = [_]ds.ColumnData{
        // Shorter than len: `floatColumn` must not hand back the short array.
        .{ .float = .{ .values = &.{1.5} } },
        // Bits set past len: must not count towards the output's size.
        .{ .int = .{ .values = &.{ 1, 2, 3, 4 }, .valid = &.{~@as(u64, 0)} } },
        .{ .text = .{ .offsets = &.{ 0, 1, 2, 3, 4 }, .bytes = "abcd", .valid = &.{~@as(u64, 0)} } },
    };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 3 };
    const v = try f.floatColumn(a, "f");
    try testing.expectEqualSlices(f64, &.{ 1.5, 0, 0 }, v);
    const rows = [_][]const Value{
        &.{ .{ .float = 1.5 }, .{ .int = 1 }, .{ .text = "a" } },
        &.{ .null, .{ .int = 2 }, .{ .text = "b" } },
        &.{ .null, .{ .int = 3 }, .{ .text = "c" } },
    };
    const want = try ds.serialize(a, .{ .columns = &cols, .rows = &rows });
    try testing.expectEqualSlices(u8, want, try ds.serializeFrame(a, f));
}

test "deserializeFrame: a long first text does not reserve its length times the row count" {
    // 4 KiB of text, then 4000 null rows: the guess from the first cell would be
    // 16 MB. What the decoder may reserve is bounded by what the input proves.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{.{ .name = "t", .type = .text }};
    const rows = try a.alloc([]const Value, 4000);
    const long = try a.alloc(u8, 4096);
    @memset(long, 'x');
    rows[0] = &.{.{ .text = long }};
    for (rows[1..]) |*r| r.* = &.{.null};
    const wire = try ds.serialize(a, .{ .columns = &cols, .rows = rows });
    const budget = try a.alloc(u8, 2 * 1024 * 1024);
    var fba = std.heap.FixedBufferAllocator.init(budget);
    const f = try ds.deserializeFrame(fba.allocator(), wire);
    try testing.expectEqual(@as(usize, 4000), f.len);
    try testing.expectEqualStrings(long, f.cell(0, "t").?.text);
}

test "deserializeFrame: the text reservation is not granted to every column at once" {
    // About 2 MB: 1000 columns, a 1000-byte text in each of them in row 0, then null
    // cells. A per-column grant of the whole remaining input reserved about 1 GB.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 1000;
    const cols = try a.alloc(ds.Column, n);
    for (cols, 0..) |*c, i| c.* = .{ .name = try std.fmt.allocPrint(a, "c{d}", .{i}), .type = .text };
    const long = try a.alloc(u8, n);
    @memset(long, 'x');
    const first = try a.alloc(Value, n);
    @memset(first, Value{ .text = long });
    const nulls = try a.alloc(Value, n);
    @memset(nulls, Value.null);
    const rows = try a.alloc([]const Value, n);
    rows[0] = first;
    for (rows[1..]) |*r| r.* = nulls;
    const wire = try ds.serialize(a, .{ .columns = cols, .rows = rows });
    // Measured 7.85× the document on x86-64, 8.04× on s390x (a list's first capacity
    // follows the cache line); a grant per column was about 500×.
    const budget = try testing.allocator.alloc(u8, 16 * wire.len);
    defer testing.allocator.free(budget);
    var fba = std.heap.FixedBufferAllocator.init(budget);
    const f = try ds.deserializeFrame(fba.allocator(), wire);
    try testing.expectEqual(@as(usize, n), f.len);
    try testing.expectEqualStrings(long, f.cell(0, "c999").?.text);
}

test "ColumnData.get: any row past the end is null, even the largest one" {
    const m = std.math.maxInt(usize);
    const text: ds.ColumnData = .{ .text = .{ .offsets = &.{ 0, 1 }, .bytes = "x" } };
    try testing.expect(text.get(m) == .null);
    try testing.expect(text.get(m - 1) == .null);
    try testing.expect(text.get(1) == .null);
    try testing.expectEqualStrings("x", text.get(0).text);
    const no_offsets: ds.ColumnData = .{ .text = .{ .offsets = &.{}, .bytes = "" } };
    try testing.expect(no_offsets.get(0) == .null);
    const int: ds.ColumnData = .{ .int = .{ .values = &.{1} } };
    try testing.expect(int.get(m) == .null);
    const boxed: ds.ColumnData = .{ .boxed = &.{.{ .int = 1 }} };
    try testing.expect(boxed.get(m) == .null);
}

test "FrameBuilder: an allocation that fails leaves no half row behind" {
    const cols = [_]ds.Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text }, .{ .name = "c", .type = .text } };
    const row = [_]Value{ .{ .int = 1 }, .{ .text = "text" }, .{ .int = 2 } };
    var saw_failure = false;
    for (0..60) |fail_at| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var fa = std.testing.FailingAllocator.init(arena.allocator(), .{ .fail_index = fail_at });
        const a = fa.allocator();
        var b = ds.FrameBuilder.init(a, &cols, 0) catch continue;
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
        // Spent: more rows and the result both say so, rather than columns that
        // disagree on which row is which.
        try testing.expectError(error.OutOfMemory, b.appendRow(&row));
        try testing.expectError(error.OutOfMemory, b.toOwned());
    }
    try testing.expect(saw_failure);
}

test "Frame.toDataset: as wide as the schema, like the wire and the JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]ds.Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    const data = [_]ds.ColumnData{.{ .int = .{ .values = &.{ 1, 2 } } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 2 };
    const d = try f.toDataset(a);
    try testing.expectEqual(@as(usize, 2), d.rows[0].len);
    try testing.expectEqualSlices(u8, try ds.frameToJson(a, f), try ds.toJson(a, d));
    try testing.expectEqualSlices(u8, try ds.serializeFrame(a, f), try ds.serialize(a, d));
}

test "big_block_allocator: under an arena, small and big blocks, and big ones aligned" {
    var arena = std.heap.ArenaAllocator.init(ds.big_block_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const small = try a.alloc(u8, 100);
    @memset(small, 1);
    const big = try ds.big_block_allocator.alloc(u8, 3 * 1024 * 1024);
    defer ds.big_block_allocator.free(big);
    try std.testing.expect(@intFromPtr(big.ptr) % (2 * 1024 * 1024) == 0);
    @memset(big, 2);
    try std.testing.expectEqual(@as(u8, 2), big[big.len - 1]);
    const huge = try a.alloc(f64, 1 << 20);
    @memset(huge, 3);
    try std.testing.expectEqual(@as(f64, 3), huge[huge.len - 1]);
}

test "columnFromCells: the array the tags call for" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fl = try ds.columnFromCells(a, &.{ .{ .float = 1 }, .null });
    try std.testing.expect(fl == .float);
    try std.testing.expectEqual(ds.Value.null, fl.get(1));
    try std.testing.expect(try ds.columnFromCells(a, &.{ .{ .float = 1 }, .{ .int = 1 } }) == .boxed);
    try std.testing.expect(try ds.columnFromCells(a, &.{}) == .nulls);
}

test "big_block_allocator: a length near the address space is a refusal, not an overflow" {
    const a = ds.big_block_allocator;
    const top = std.math.maxInt(usize);
    for ([_]usize{ top - 5000, top - 1024 * 1024, top - 2 * 1024 * 1024 - 8192 }) |len| {
        try std.testing.expect(a.rawAlloc(len, .@"1", 0) == null);
    }
}
