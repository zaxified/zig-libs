// SPDX-License-Identifier: MIT
//! Tests of dataframe S2 wave W11, part B (real dtype widths): the verbs that move, reorder,
//! reshape or combine cells keep a width column's declared type and its own array, the I/O
//! edges (chunk readers, render, schema text) and the fuzz generators' width columns.
//! `sweep` runs every public verb of the files of part B over one frame that holds all eight
//! width columns, an Int64, a text and a null-only column.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const dtype = @import("dtype.zig");
const verbs = @import("verbs.zig");
const reshape = @import("reshape.zig");
const nestverbs = @import("nestverbs.zig");
const frameops = @import("frameops.zig");
const colfn = @import("colfn.zig");
const callback = @import("callback.zig");
const names_mod = @import("names.zig");
const catfn = @import("catfn.zig");
const ranges = @import("ranges.zig");
const cc = @import("csvchunk.zig");
const ndc = @import("ndjsonchunk.zig");
const s2w9 = @import("s2w9_test.zig");
const render = @import("render.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const ColumnData = fm.ColumnData;
const Value = vm.Value;

const big: u64 = (1 << 63) + 5; // above every i64

const names = [_][]const u8{ "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "k", "txt", "nul" };
const types = [_]ColumnType{ .int8, .int16, .int32, .int, .uint8, .uint16, .uint32, .uint64, .float32, .int, .text, .uint16 };

const rows = 6;

fn cell(ci: usize, ri: usize) Value {
    // Row 3 is null in every column; row 4 repeats row 0 (distinct, unique).
    const r = if (ri == 4) 0 else ri;
    if (r == 3) return .null;
    return switch (ci) {
        0 => .{ .int = ([_]i64{ -128, 127, 0, 0, 5, 1 })[r] },
        1 => .{ .int = ([_]i64{ -32768, 32767, 0, 0, 5, 1 })[r] },
        2 => .{ .int = ([_]i64{ -2147483648, 2147483647, 0, 0, 5, 1 })[r] },
        3 => .{ .int = ([_]i64{ std.math.minInt(i64), std.math.maxInt(i64), 0, 0, 5, 1 })[r] },
        4 => .{ .int = ([_]i64{ 0, 255, 7, 0, 5, 1 })[r] },
        5 => .{ .int = ([_]i64{ 0, 65535, 7, 0, 5, 1 })[r] },
        6 => .{ .int = ([_]i64{ 0, 4294967295, 7, 0, 5, 1 })[r] },
        7 => if (r == 1) .{ .uint = big } else if (r == 2) .{ .uint = std.math.maxInt(u64) } else .{ .int = ([_]i64{ 0, 0, 0, 0, 5, 1 })[r] },
        8 => .{ .float = @as(f32, ([_]f32{ 0.1, -std.math.inf(f32), std.math.floatTrueMin(f32), 0, std.math.nan(f32), 1.5 })[r]) },
        9 => .{ .int = ([_]i64{ 1, 2, 1, 2, 3, 3 })[ri] },
        10 => .{ .text = ([_][]const u8{ "a", "b", "a", "b", "c", "c" })[ri] },
        else => .null,
    };
}

fn fixture(a: std.mem.Allocator) !Frame {
    const cols = try a.alloc(Column, names.len);
    for (cols, names, types) |*c, n, t| c.* = .{ .name = n, .type = t };
    var b = try fm.FrameBuilder.init(a, cols, rows);
    var row: [names.len]Value = undefined;
    for (0..rows) |ri| {
        for (&row, 0..) |*c, ci| c.* = cell(ci, ri);
        try b.appendRow(&row);
    }
    return b.toOwned();
}

/// A second frame keyed by `k`, holding every width again under other names.
fn side(a: std.mem.Allocator) !Frame {
    const cols = try a.alloc(Column, 4);
    cols[0] = .{ .name = "k", .type = .int8 };
    cols[1] = .{ .name = "r_i16", .type = .int16 };
    cols[2] = .{ .name = "r_u64", .type = .uint64 };
    cols[3] = .{ .name = "r_f32", .type = .float32 };
    var b = try fm.FrameBuilder.init(a, cols, 3);
    try b.appendRow(&.{ .{ .int = 1 }, .{ .int = -7 }, .{ .uint = big }, .{ .float = 0.5 } });
    try b.appendRow(&.{ .{ .int = 3 }, .null, .{ .int = 9 }, .null });
    try b.appendRow(&.{ .{ .int = 9 }, .{ .int = 4 }, .null, .{ .float = 2 } });
    return b.toOwned();
}

/// Every column of `f` that carries a fixture column's name has that column's type, every
/// width column holds its array.
fn kept(f: Frame) !void {
    try testing.expect(fm.widthsConform(f));
    for (f.columns) |c| {
        if (std.mem.eql(u8, c.name, "txt")) continue; // the catfn tests make it categorical
        for (names, types) |n, t| {
            if (std.mem.eql(u8, n, c.name)) try testing.expectEqual(t, c.type);
        }
    }
}

/// Column `name` of `f` has type `ty` and its array.
fn has(f: Frame, name: []const u8, ty: ColumnType) !void {
    const ci = f.columnIndex(name) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(ty, f.columns[ci].type);
    try testing.expect(fm.widthsConform(f));
    if (dtype.isWidth(ty)) {
        const d = f.columnAt(ci);
        if (d != .nulls) try testing.expectEqualStrings(@tagName(ty), @tagName(std.meta.activeTag(d)));
    }
}

fn all(f: Frame) !void {
    return kept(f);
}

fn sweepVerbsZig(a: std.mem.Allocator) !void {
    const f = try fixture(a);
    try kept(f);
    const r = try side(a);

    try kept(try verbs.takeRows(a, f, &.{ 5, 0, 0, 3 }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "k", .op = .ge, .value = .{ .int = 2 } }} }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "u64", .op = .gt, .value = .{ .int = 5 } }} }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "f32", .op = .is_null }} }));
    try kept(try df.distinct(a, f, .{ .keys = &.{} }));
    try kept(try df.distinct(a, f, .{ .keys = &.{"i8"}, .keep = .last }));
    try kept(try df.distinct(a, f, .{ .keys = &.{ "u64", "f32" }, .keep = .none }));
    for (names[0..9]) |n| {
        try kept(try df.sort(a, f, .{ .key = n }));
        try kept(try df.sort(a, f, .{ .key = n, .dir = .desc, .missing = .last, .then_by = &.{.{ .key = "k" }} }));
    }
    try kept(try df.dropna(a, f, .{ .subset = &.{"i16"} }));
    try kept(try df.dropna(a, f, .{}));
    try kept(try df.fillna(a, f, .{ .subset = &.{ "i8", "u8" }, .value = .{ .int = 3 } }));
    try kept(try df.fillna(a, f, .{ .subset = &.{ "u64", "f32" }, .value = .{ .int = 3 } }));
    try kept(try df.fillna(a, f, .{ .per_column = &.{ .{ .col = "i32", .value = .{ .int = -1 } }, .{ .col = "u32", .value = .{ .int = 99 } } } }));
    try kept(try df.select(a, f, &.{ "u16", "f32", "i8" }));
    try kept(try df.drop(a, f, &.{ "k", "txt" }));
    {
        const g = try df.rename(a, f, &.{ .{ .from = "i8", .to = "x8" }, .{ .from = "f32", .to = "y32" } });
        try has(g, "x8", .int8);
        try has(g, "y32", .float32);
    }
    // joins, every kind
    inline for (.{ .inner, .left, .right, .full, .semi, .anti }) |how| {
        const g = try df.join(a, f, r, .{ .on = "k", .how = how });
        try kept(g);
        const h = try df.join(a, f, r, .{ .on = "k", .how = how, .coalesce_keys = true, .indicator = "_merge", .sort = true });
        try kept(h);
        const m = try df.join(a, r, f, .{ .on = "k", .how = how, .keep_right_keys = true });
        for (r.columns) |c| if (m.columnIndex(c.name)) |_| try has(m, c.name, c.type);
    }
    {
        const g = try df.join(a, f, r, .{ .on = "k", .how = .left });
        try has(g, "r_i16", .int16);
        try has(g, "r_u64", .uint64);
        try has(g, "r_f32", .float32);
        // The key keeps the left type (D10): Int64 `k` joined with Int8 `k`.
        try has(g, "k", .int);
        const x = try df.join(a, r, f, .{ .on = "k", .how = .full, .coalesce_keys = true });
        try has(x, "k", .int8);
    }
    try kept(try df.join(a, f, try df.drop(a, r, &.{"k"}), .{ .how = .cross }));
    {
        const g = try df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{ "i8", "u8" } });
        try testing.expect(fm.widthsConform(g));
        const g2 = try df.unpivot(a, f, .{ .id_cols = &.{ "i8", "u64", "f32" }, .value_cols = &.{"k"} });
        try has(g2, "i8", .int8);
        try has(g2, "u64", .uint64);
        try has(g2, "f32", .float32);
        const g3 = try df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{ "u8", "u8" } });
        try testing.expect(fm.widthsConform(g3));
    }
    {
        const g = try df.pivot(a, f, .{ .row_key = "u8", .col_key = "txt", .value_col = "i64", .agg = .first });
        try has(g, "u8", .uint8);
        try testing.expect(fm.widthsConform(g));
    }
}

fn numericOnly(a: std.mem.Allocator, f: Frame) !Frame {
    return df.select(a, f, &.{ "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32" });
}

fn series(f: Frame, name: []const u8) df.Series {
    return f.series(name).?;
}

fn sweepStructureZig(a: std.mem.Allocator) !void {
    const f = try fixture(a);
    const r = try side(a);

    try kept(try df.clone(a, f));
    try kept(try df.clear(a, f, 3));
    try kept(try df.take(a, f, &.{ 0, -1, 2, 2 }));
    try kept(try df.gatherEvery(a, f, 2, 1));
    try kept(try df.reverse(a, f));
    {
        const s = series(f, "u8");
        const g = try df.insertColumn(a, f, 1, .{ .name = "extra", .type = s.type, .data = s.data, .len = s.len });
        try has(g, "extra", .uint8);
        const h = try df.hstack(a, r, &.{.{ .name = "extra2", .type = .float32, .data = try verbs.take(a, series(f, "f32").data, &.{ 0, 1, 2 }, false), .len = 3 }});
        try has(h, "extra2", .float32);
        try has(h, "r_f32", .float32);
    }
    {
        const s = series(f, "f32");
        const g = try df.replaceColumn(a, f, 0, .{ .name = "i8", .type = s.type, .data = s.data, .len = s.len });
        try has(g, "i8", .float32);
        const p = try df.popColumn(a, f, "u16");
        try kept(p.frame);
        try testing.expectEqual(ColumnType.uint16, p.series.type);
    }
    {
        const g = try df.addAffix(a, f, .{ .prefix = "x_" });
        try testing.expect(fm.widthsConform(g));
        try has(g, "x_u32", .uint32);
        const picked = try df.selectColumns(a, f, .numeric);
        try testing.expectEqual(@as(usize, 11), picked.len); // every number column incl. `nul`, not `txt`
        try kept(try df.selectBy(a, f, .{ .by_type = &.{ .uint8, .float32 } }));
    }
    {
        const nc = try df.nullCount(a, f);
        try testing.expectEqual(@as(i64, 1), nc.cell(0, "u64").?.int);
        try testing.expect(df.hasNulls(f));
        try testing.expect(df.columnBytes(f, 0) > 0 and df.estimatedSize(f) > 0);
        const info = try df.info(a, f);
        try testing.expectEqualStrings("i8", info.cell(0, "type").?.text);
        try testing.expectEqualStrings("f32", info.cell(8, "type").?.text);
        try testing.expectEqualStrings("int", info.cell(3, "type").?.text);
        try testing.expect(df.equals(f, try df.clone(a, f)));
        try testing.expect(!df.equals(f, try df.fillna(a, f, .{ .subset = &.{"u64"}, .value = .{ .int = 1 } })));
    }
    // transpose: the one type stays, mixed numbers meet in their supertype.
    {
        const same = try df.select(a, f, &.{"i8"});
        const t = try df.transpose(a, same, .{});
        try testing.expectEqual(ColumnType.int8, t.columns[0].type);
        try testing.expect(fm.widthsConform(t));
        const m = try df.select(a, f, &.{ "i8", "u8" });
        const tm = try df.transpose(a, m, .{});
        try testing.expectEqual(ColumnType.int16, tm.columns[0].type);
        try testing.expect(fm.widthsConform(tm));
        try testing.expectEqual(@as(i64, 255), tm.cell(1, "column_1").?.int);
        const mf = try df.select(a, f, &.{ "u8", "f32" });
        try testing.expectEqual(ColumnType.float32, (try df.transpose(a, mf, .{})).columns[0].type);
        const mi = try df.select(a, f, &.{ "i64", "u8" });
        try testing.expectEqual(ColumnType.int, (try df.transpose(a, mi, .{ .header_name = "h" })).columns[1].type);
        try kept(try df.transpose(a, try numericOnly(a, f), .{ .header_name = "h" }));
    }
    // concat: `.vertical` and `.diagonal` stack through `more.concatByName` (part A's file;
    // the stacked widths are checked after the merge), `.horizontal` is this file's.
    {
        const g = try df.concat(a, &.{ try df.drop(a, f, &.{"k"}), r }, .horizontal);
        try has(g, "r_u64", .uint64);
        try has(g, "u64", .uint64);
        try has(g, "r_f32", .float32);
        // Another width of the same name is another schema for `.vertical`.
        const cast16 = try df.cast(a, f, .{ .col = "i8", .to = .int16 });
        try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ f, cast16 }, .vertical));
    }
}

fn timeFrame(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{
        .{ .name = "t", .type = .timestamp },
        .{ .name = "k", .type = .int8 },
        .{ .name = "v", .type = .int32 },
        .{ .name = "w", .type = .float32 },
        .{ .name = "u", .type = .uint64 },
    });
    var b = try fm.FrameBuilder.init(a, cols, 5);
    const h: i64 = 3_600_000_000;
    try b.appendRow(&.{ .{ .int = 0 }, .{ .int = 1 }, .{ .int = 10 }, .{ .float = 0.5 }, .{ .uint = big } });
    try b.appendRow(&.{ .{ .int = h }, .{ .int = 1 }, .null, .null, .{ .int = 2 } });
    try b.appendRow(&.{ .{ .int = 3 * h }, .{ .int = 2 }, .{ .int = 30 }, .{ .float = 1.5 }, .null });
    try b.appendRow(&.{ .{ .int = 3 * h + 5 }, .{ .int = 2 }, .{ .int = 40 }, .{ .float = 2.5 }, .{ .int = 4 } });
    try b.appendRow(&.{ .{ .int = 4 * h }, .null, .{ .int = 50 }, .null, .{ .int = 5 } });
    return b.toOwned();
}

fn sweepReshapeZig(a: std.mem.Allocator) !void {
    const f = try fixture(a);
    const r = try side(a);
    const tf = try timeFrame(a);

    try kept(try reshape.groupFilter(a, f, .{ .by = &.{"k"}, .agg = .{ .src = "i16", .out = "x", .func = .max }, .op = .ge, .value = .{ .int = 0 } }));
    try kept(try reshape.ngroup(a, f, .{ .by = &.{"u8"} }));
    {
        const g = try reshape.joinWhere(a, f, r, &.{.{ .left = "i32", .op = .ge, .right = "k" }}, "_r");
        try has(g, "i32", .int32);
        try has(g, "r_u64", .uint64);
        try has(g, "f32", .float32);
        // A UInt64 above 2^63 compares exactly against an Int8.
        const h = try reshape.joinWhere(a, f, r, &.{.{ .left = "u64", .op = .gt, .right = "k" }}, "_r");
        try testing.expect(h.len > 0);
    }
    {
        const g = try reshape.mergeOrdered(a, f, r, .{ .on = &.{"k"} });
        try testing.expect(fm.widthsConform(g));
        try has(g, "i8", .int8);
        try has(g, "r_i16", .int16);
        const h = try reshape.mergeOrdered(a, f, r, .{ .on = &.{"k"}, .fill_forward = true });
        try testing.expect(fm.widthsConform(h));
        try has(h, "r_u64", .uint64);
    }
    // `mergeSorted` stacks with `concat(.vertical)`: the stacked widths are part A's file
    // (`more.concatByName`); the call is checked for the sorted result, the widths after the merge.
    {
        const sorted = try verbs.sort(a, f, .{ .key = "k" });
        const g = try reshape.mergeSorted(a, sorted, sorted, "k");
        try testing.expectEqual(@as(usize, 2 * rows), g.len);
    }
    {
        const g = try reshape.pivotMany(a, f, .{ .row_key = "u8", .col_key = "txt", .values = &.{ "i16", "f32" }, .agg = .first });
        try has(g, "u8", .uint8);
        try testing.expect(fm.widthsConform(g));
        const h = try reshape.pivotKeys(a, f, .{ .row_keys = &.{ "u16", "i8" }, .col_keys = &.{"txt"}, .values = &.{"i32"}, .agg = .first });
        try has(h, "u16", .uint16);
        try has(h, "i8", .int8);
    }
    try kept(try reshape.dummies(a, f, .{}));
    {
        const g = try reshape.combineFirst(a, f, try verbs.takeRows(a, f, &.{ 1, 0 }));
        try kept(g);
        const h = try reshape.update(a, f, try verbs.takeRows(a, f, &.{ 1, 0 }));
        try kept(h);
        // `update` takes g's present cells over f's, by row.
        try testing.expectEqual(@as(i64, 127), h.cell(0, "i8").?.int);
        try testing.expectEqual(big, h.cell(0, "u64").?.uint);
    }
    try kept(try reshape.repeatRows(a, f, .{ .times = 2 }));
    try kept(try reshape.repeatRows(a, f, .{ .by = "k" }));
    {
        const g = try reshape.scatter(a, f, .{ .col = "i8", .idx = &.{ 0, -1 }, .values = &.{ .{ .int = 7 }, .null } });
        try kept(g);
        try testing.expectEqual(@as(i64, 7), g.cell(0, "i8").?.int);
        try testing.expect(g.cell(5, "i8").? == .null);
        // A value the width does not hold is refused, not turned into a null.
        try testing.expectError(error.BadArgument, reshape.scatter(a, f, .{ .col = "i8", .idx = &.{0}, .values = &.{.{ .int = 200 }} }));
        try testing.expectError(error.BadArgument, reshape.scatter(a, f, .{ .col = "u8", .idx = &.{0}, .values = &.{.{ .int = -1 }} }));
        const u = try reshape.scatter(a, f, .{ .col = "u64", .idx = &.{0}, .values = &.{.{ .uint = big }} });
        try testing.expectEqual(big, u.cell(0, "u64").?.uint);
        const fl = try reshape.scatter(a, f, .{ .col = "f32", .idx = &.{0}, .values = &.{.{ .float = 0.25 }} });
        try has(fl, "f32", .float32);
    }
    try kept(try reshape.dropNans(a, f, &.{}));
    {
        const g = try reshape.matchToSchema(a, f, f.columns, .{});
        try kept(g);
        const schema = [_]Column{ .{ .name = "i8", .type = .int16 }, .{ .name = "u64", .type = .float } };
        const h = try reshape.matchToSchema(a, try df.select(a, f, &.{ "i8", "u64" }), &schema, .{ .cast = true });
        try has(h, "i8", .int16);
        try testing.expectError(error.SchemaMismatch, reshape.matchToSchema(a, try df.select(a, f, &.{ "i8", "u64" }), &schema, .{}));
    }
    {
        const m = try reshape.toFloatMatrix(a, f, &.{ "u64", "f32" });
        try testing.expectEqual(@as(usize, 2), m.cols);
        try testing.expectEqual(@as(f64, @floatFromInt(big)), m.data[2]);
    }
    try kept(try reshape.hashRows(a, f, 7, "h"));
    {
        const g = try reshape.betweenTime(a, tf, .{ .col = "t", .start = "00:00", .end = "03:00" });
        try testing.expect(fm.widthsConform(g));
        try testing.expectEqual(ColumnType.uint64, g.columns[4].type);
    }
    {
        const g = try reshape.unstack(a, try numericOnly(a, f), .{ .step = 4 });
        try testing.expect(fm.widthsConform(g));
        try has(g, "i8_0", .int8);
        try has(g, "u64_1", .uint64);
        try has(g, "f32_1", .float32);
        const h = try reshape.unstack(a, try numericOnly(a, f), .{ .step = 4, .how = .horizontal, .fill_value = .{ .int = 1 } });
        try has(h, "u8_3", .uint8);
        try testing.expect(fm.widthsConform(h));
        // A fill that is no value of the width is refused.
        try testing.expectError(error.BadArgument, reshape.unstack(a, try df.select(a, f, &.{"u8"}), .{ .step = 4, .fill_value = .{ .int = 300 } }));
    }
    {
        const cols = try a.dupe(Column, &.{
            .{ .name = "id", .type = .uint16 },
            .{ .name = "x1", .type = .int8 },
            .{ .name = "x2", .type = .int8 },
            .{ .name = "y1", .type = .float32 },
            .{ .name = "y2", .type = .float32 },
        });
        var b = try fm.FrameBuilder.init(a, cols, 2);
        try b.appendRow(&.{ .{ .int = 1 }, .{ .int = -3 }, .{ .int = 4 }, .{ .float = 0.5 }, .null });
        try b.appendRow(&.{ .{ .int = 2 }, .null, .{ .int = 5 }, .{ .float = 1.5 }, .{ .float = 2.5 } });
        const w = try b.toOwned();
        const g = try reshape.wideToLong(a, w, .{ .stubnames = &.{ "x", "y" }, .i = &.{"id"}, .j = "j" });
        try has(g, "id", .uint16);
        try has(g, "x", .int8);
        try has(g, "y", .float32);
        try testing.expectEqual(@as(usize, 4), g.len);
        // Stub columns of two widths meet in their supertype.
        const cols2 = try a.dupe(Column, &.{ .{ .name = "id", .type = .int }, .{ .name = "x1", .type = .int8 }, .{ .name = "x2", .type = .uint8 } });
        var b2 = try fm.FrameBuilder.init(a, cols2, 1);
        try b2.appendRow(&.{ .{ .int = 1 }, .{ .int = -3 }, .{ .int = 200 } });
        const g2 = try reshape.wideToLong(a, try b2.toOwned(), .{ .stubnames = &.{"x"}, .i = &.{"id"}, .j = "j" });
        try has(g2, "x", .int16);
        try testing.expectEqual(@as(i64, 200), g2.cell(1, "x").?.int);
    }
}

fn identity(_: void, _: std.mem.Allocator, v: Value) error{}!Value {
    return v;
}

fn firstCell(_: void, _: std.mem.Allocator, acc: Value, _: Value) error{}!Value {
    return acc;
}

fn windowFirst(_: void, _: std.mem.Allocator, w: []const Value) error{}!Value {
    return w[0];
}

fn groupAsIs(_: void, _: std.mem.Allocator, g: Frame) error{}!Frame {
    return g;
}

fn groupBig(_: void, _: std.mem.Allocator, g: Frame) error{}!bool {
    return g.len > 1;
}

fn lowerName(_: void, a: std.mem.Allocator, n: []const u8) error{OutOfMemory}![]const u8 {
    return std.fmt.allocPrint(a, "{s}_x", .{n});
}

fn sweepNestverbsZig(a: std.mem.Allocator) !void {
    const doc =
        \\[{"id":1,"xs":[3,1,2],"ys":[1.5,2.5,3.5],"p":{"a":1,"b":"x"}},
        \\ {"id":2,"xs":[],"ys":[],"p":null},
        \\ {"id":3,"xs":null,"ys":null,"p":{"b":"y"}},
        \\ {"id":4,"xs":[100,null],"ys":[0.25,null],"p":{"a":4,"b":"z"}}]
    ;
    const j = try df.readJson(a, doc, .{});
    // Declare the element and field types as widths: the storage holds Int64 and Float64
    // arrays, what a hand-built frame may do; the verbs must still hand out the width.
    const cols = try a.dupe(Column, j.columns);
    for (cols) |*c| {
        const inner = try a.dupe(Column, c.inner);
        c.inner = inner;
        if (std.mem.eql(u8, c.name, "xs")) inner[0].type = .int8;
        if (std.mem.eql(u8, c.name, "ys")) inner[0].type = .float32;
        if (std.mem.eql(u8, c.name, "p")) inner[0].type = .uint16;
    }
    const f: Frame = .{ .columns = cols, .data = j.data, .len = j.len };

    const e = try nestverbs.explode(a, f, &.{ "xs", "ys" });
    try has(e, "xs", .int8);
    try has(e, "ys", .float32);
    try testing.expectEqual(@as(usize, 7), e.len);
    try testing.expectEqual(@as(i64, 100), e.cell(5, "xs").?.int);
    const e1 = try nestverbs.explode(a, try df.select(a, f, &.{ "id", "xs", "p" }), &.{"xs"});
    try has(e1, "xs", .int8);
    try testing.expect(fm.widthsConform(try nestverbs.explodeAll(a, try df.select(a, f, &.{ "id", "xs", "ys" }))));
    const fl = try nestverbs.flattenList(a, f, "xs");
    try has(fl, "xs", .int8);
    try testing.expectEqual(@as(usize, 5), fl.len);
    const fy = try nestverbs.flattenList(a, f, "ys");
    try has(fy, "ys", .float32);
    const dt = try nestverbs.structDtypes(a, f, "p");
    try testing.expectEqual(ColumnType.uint16, dt[0].type);
    const un = try nestverbs.unnest(a, f, .{ .cols = &.{"p"} });
    try has(un, "a", .uint16);
    try testing.expectEqual(@as(i64, 4), un.cell(3, "a").?.int);
    try testing.expect(fm.widthsConform(un));
    // A hand-built mix that the width does not hold becomes null, never a panic.
    const bad_cols = try a.dupe(Column, cols);
    for (bad_cols) |*c| if (std.mem.eql(u8, c.name, "xs")) {
        c.inner = &.{.{ .name = "", .type = .uint8 }};
    };
    const bad = try nestverbs.explode(a, .{ .columns = bad_cols, .data = j.data, .len = j.len }, &.{"xs"});
    try has(bad, "xs", .uint8);
}

fn sweepFrameopsZig(a: std.mem.Allocator) !void {
    const f = try fixture(a);
    const num = try numericOnly(a, f);
    const tf = try timeFrame(a);

    {
        const g = try frameops.arith(a, num, num, .add, .{});
        try testing.expect(fm.widthsConform(g));
        try has(g, "i8", .int8);
        try has(g, "u32", .uint32);
        try has(g, "f32", .float32);
        try has(g, "i64", .int);
        // 127 + 127 overflows an Int8: the module's rule is null.
        try testing.expect(g.cell(1, "i8").? == .null);
        try testing.expectEqual(@as(i64, 2), g.cell(5, "i8").?.int);
        const m = try frameops.arith(a, num, num, .div, .{});
        try has(m, "i8", .float);
        const mn = try frameops.arith(a, num, num, .min, .{ .fill_value = .{ .int = 0 } });
        try has(mn, "u16", .uint16);
    }
    {
        const g = try frameops.arithScalar(a, num, .add, .{ .int = 1 }, .{});
        try testing.expect(fm.widthsConform(g));
        try has(g, "i8", .int8);
        // (u64 + 1: the type of a UInt64 operand's results is `expr.binaryValue`'s, part A.)
        try testing.expect(fm.widthsConform(g));
        try has(g, "u32", .uint32);
        try has(g, "f32", .float32);
        // An int literal that does not fit widens the type (polars' weak literal).
        const w = try frameops.arithScalar(a, num, .add, .{ .int = 1000 }, .{ .cols = &.{ "i8", "u8" } });
        try has(w, "i8", .int16);
        try testing.expectEqual(@as(i64, 872), w.cell(0, "i8").?.int);
        try has(w, "u8", .int16); // a UInt8 and the smallest signed type holding 1000
        // A float literal: Float32 stays Float32, an integer column becomes Float64.
        const fl = try frameops.arithScalar(a, num, .mul, .{ .float = 1.5 }, .{ .cols = &.{ "f32", "i8" } });
        try has(fl, "f32", .float32);
        try has(fl, "i8", .float);
        const rev = try frameops.arithScalar(a, num, .sub, .{ .int = 3 }, .{ .reverse = true, .cols = &.{"i16"} });
        try has(rev, "i16", .int16);
    }
    {
        const other = try verbs.fillna(a, num, .{ .subset = &.{ "i8", "f32" }, .value = .{ .int = 0 } });
        const c = try frameops.compare(a, num, other);
        try testing.expect(fm.widthsConform(c));
        try has(c, "i8_self", .int8);
        try has(c, "f32_other", .float32);
    }
    {
        const d = try frameops.dot(a, try df.select(a, f, &.{ "i8", "u8" }), try df.select(a, try verbs.takeRows(a, f, &.{ 0, 1 }), &.{ "i16", "f32" }));
        try testing.expect(fm.widthsConform(d));
    }
    {
        const g = try frameops.interpolate(a, f, .{ .col = "f32" });
        try has(g, "f32", .float32);
        const h = try frameops.interpolate(a, f, .{ .col = "i16", .out = "i16f" });
        try has(h, "i16f", .float);
        try has(h, "i16", .int16);
        const k = try frameops.interpolate(a, f, .{ .col = "i32", .by = "u8", .method = .nearest });
        try has(k, "i32", .float);
        try has(k, "u8", .uint8);
    }
    {
        // The aggregate columns are built by `verbs.aggregate` (part A's region): their widths are
        // checked after the merge; the key, window and boundary columns are this file's.
        const g = try frameops.groupByDynamic(a, tf, .{ .index = "t", .every = "1h", .by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "vmax", .func = .max }} });
        const gk = try df.select(a, g, &.{ "k", "t" });
        try testing.expect(fm.widthsConform(gk));
        try has(gk, "k", .int8);
        const g2 = try frameops.groupByDynamic(a, tf, .{ .index = "t", .every = "2h", .include_boundaries = true, .closed = .right, .label = .right, .aggs = &.{.{ .src = "u", .out = "ufirst", .func = .first }} });
        try testing.expect(fm.widthsConform(try df.select(a, g2, &.{ "_lower_boundary", "_upper_boundary", "t" })));
        const g3 = try frameops.groupByDynamic(a, tf, .{ .index = "t", .rule = "h", .aggs = &.{.{ .src = "w", .out = "wmean", .func = .mean }} });
        try testing.expect(fm.widthsConform(try df.select(a, g3, &.{"t"})));
        const up = try frameops.upsample(a, tf, .{ .time = "t", .every = "1h" });
        try testing.expectEqual(@as(usize, 5), up.len);
        try has(up, "k", .int8);
        try has(up, "v", .int32);
        try has(up, "w", .float32);
        try has(up, "u", .uint64);
        try testing.expectEqual(big, up.cell(0, "u").?.uint);
    }
}

fn sweepColfnCallbackNamesCatfnRanges(a: std.mem.Allocator) !void {
    const f = try fixture(a);
    const num = try numericOnly(a, f);

    // colfn
    try testing.expectEqual(@as(i64, 1), (try colfn.item(try df.select(a, try verbs.takeRows(a, f, &.{5}), &.{"i8"}), null)).int);
    try testing.expect(fm.widthsConform(try colfn.uniqueCounts(a, f, "u16")));
    try testing.expect(fm.widthsConform(try colfn.hist(a, f, .{ .col = "f32", .bins = &.{ 0, 1, 2 } })));
    try kept(try colfn.foldColumns(a, f, .{ .cols = &.{ "i8", "i16" }, .out = "first" }, {}, firstCell));
    try testing.expect(fm.widthsConform(try colfn.cumFoldColumns(a, f, .{ .cols = &.{ "i8", "u8" } }, {}, firstCell)));
    try testing.expect(fm.widthsConform(try colfn.cumSumHorizontal(a, f, &.{ "i8", "i16" })));
    {
        // The union of the keys is stacked by `concat(.vertical)` (part A's `more.concatByName`):
        // the widths of the aligned frames are checked after the merge.
        const al = try colfn.alignFrames(a, &.{ try df.select(a, f, &.{ "u8", "f32" }), try df.select(a, f, &.{ "u8", "i16" }) }, .{ .on = &.{"u8"} });
        try testing.expectEqual(@as(usize, 2), al.len);
        try testing.expectEqual(al[0].len, al[1].len);
    }

    // callback
    {
        const g = try callback.mapElements(a, f, .{ .col = "i8", .out = .{ .name = "y", .type = .int16 } }, {}, identity);
        try has(g, "y", .int16);
        const h = try callback.mapElements(a, f, .{ .col = "u64", .out = .{ .type = .uint64 } }, {}, identity);
        try has(h, "u64", .uint64);
        try testing.expectEqual(big, h.cell(1, "u64").?.uint);
        // Not a value of the declared width: the verb's own refusal.
        try testing.expectError(error.WrongOutputType, callback.mapElements(a, f, .{ .col = "i16", .out = .{ .type = .int8 } }, {}, identity));
        const k = try callback.mapElements(a, f, .{ .col = "f32", .out = .{ .name = "z" } }, {}, identity);
        try testing.expect(fm.widthsConform(k));
        const m = try callback.mapRows(a, f, .{ .out = "r", .type = .uint8 }, {}, rowFirstU8);
        try has(m, "r", .uint8);
        try kept(try callback.sortByKey(a, f, .{ .key = "i8" }, {}, identity));
        const rm = try callback.rollingMap(a, f, .{ .col = "i32", .out = .{ .name = "rm", .type = .int32 }, .window = 2, .min_periods = 1 }, {}, windowFirst);
        try has(rm, "rm", .int32);
        const mg = try callback.mapGroups(a, f, .{ .by = &.{"k"} }, {}, groupAsIs);
        try kept(mg);
        try kept(try callback.filterGroups(a, f, .{ .by = &.{"k"} }, {}, groupBig));
    }

    // names: only the schema changes, the arrays and their widths stay
    {
        const g = try names_mod.renameWith(a, f, .all, {}, lowerName);
        try testing.expect(fm.widthsConform(g));
        try has(g, "u8_x", .uint8);
        try has(try names_mod.renameUpper(a, f, .{ .by_type = &.{.uint16} }), "U16", .uint16);
        try has(try names_mod.renameLower(a, f, .{ .by_type = &.{.float32} }), "f32", .float32);
        try has(try names_mod.renameReplace(a, f, .{ .pattern = "i", .with = "j", .literal = true }), "j8", .int8);
    }

    // catfn: the other columns of a frame with a categorical keep their widths
    {
        const g = try df.cast(a, f, .{ .col = "txt", .to = .categorical });
        try kept(try catfn.setOrdered(a, g, "txt", true));
        try kept(try catfn.addCategories(a, g, "txt", &.{"zz"}));
        try kept(try catfn.removeUnusedCategories(a, g, "txt"));
        try kept(try catfn.setCategories(a, g, "txt", &.{ "a", "b", "c" }, null));
        try kept(try catfn.reorderCategories(a, g, "txt", &.{ "c", "b", "a" }, null));
        try kept(try catfn.renameCategories(a, g, "txt", .{ .map = &.{.{ "a", "A" }} }));
        const codes = try catfn.codes(a, g, "txt");
        try kept(codes);
        try has(codes, "u64", .uint64);
        _ = try catfn.categories(a, g, "txt");
        _ = try catfn.isOrdered(a, g, "txt");
    }

    // ranges
    {
        const u = try ranges.repeatValue(a, "x", .{ .uint = big }, 3, null);
        try has(u, "x", .uint64);
        try testing.expectEqual(big, u.cell(2, "x").?.uint);
        const v = try ranges.repeatValue(a, "x", .{ .int = 5 }, 3, .uint8);
        try has(v, "x", .uint8);
        const w = try ranges.repeatValue(a, "x", .null, 2, .float32);
        try has(w, "x", .float32);
        try testing.expect(fm.widthsConform(try ranges.intRange(a, "r", 0, 5, 1)));
        try testing.expect(fm.widthsConform(try ranges.ones(a, "o", 3, true)));
        try testing.expect(fm.widthsConform(try ranges.linearSpace(a, "l", 0, 1, 3, .both)));
        _ = num;
    }
}

fn rowFirstU8(_: void, _: std.mem.Allocator, r: callback.Row) error{}!Value {
    const v = r.at(4);
    return if (v == .null) .null else v;
}

test "W11B io: chunk readers accept the widths like readCsv and readNdjson" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const types_csv = [_]df.TypeOverride{ .{ .name = "a", .type = .int8 }, .{ .name = "b", .type = .uint64 }, .{ .name = "c", .type = .float32 }, .{ .name = "d", .type = .uint16 } };
    const doc = "a,b,c,d\n-128,18446744073709551615,0.1,\n127,9223372036854775808,1e39,65535\n5,0,,7\n";
    // Whole read: the types, the arrays, the cells.
    const whole = try df.readCsv(a, doc, .{ .types = &types_csv });
    try testing.expect(fm.widthsConform(whole));
    try has(whole, "a", .int8);
    try has(whole, "d", .uint16);
    // The chunks, put end to end, are the whole read; every chunk holds its widths.
    for ([_]usize{ 0, 1, 3 }) |step| {
        var slow: s2w9.Slow = undefined;
        slow.init(doc, step);
        var rd = try cc.CsvChunkReader.init(a, &slow.interface, .{ .types = &types_csv }, .{});
        defer rd.deinit();
        var row: usize = 0;
        while (try rd.next(a, 2)) |ch| {
            try testing.expect(fm.widthsConform(ch));
            try has(ch, "b", .uint64);
            for (0..ch.len) |ri| {
                for (0..4) |ci| {
                    const x = whole.columnAt(ci).get(row);
                    const y = ch.columnAt(ci).get(ri);
                    try testing.expectEqual(std.meta.activeTag(x), std.meta.activeTag(y));
                    if (x == .float) try testing.expect(x.float == y.float) else if (x == .uint) try testing.expectEqual(x.uint, y.uint) else if (x == .int) try testing.expectEqual(x.int, y.int);
                }
                row += 1;
            }
        }
        try testing.expectEqual(whole.len, row);
    }
    // Out of range is `error.BadValue`, as in `readCsv`; a Float32 beyond its range is infinity.
    const bad = "a,b,c,d\n128,1,1,1\n";
    try testing.expectError(error.BadValue, df.readCsv(a, bad, .{ .types = &types_csv }));
    var slow: s2w9.Slow = undefined;
    slow.init(bad, 0);
    var rd = try cc.CsvChunkReader.init(a, &slow.interface, .{ .types = &types_csv }, .{});
    defer rd.deinit();
    try testing.expectError(error.BadValue, rd.next(a, 4));
    try testing.expect(std.math.isInf(whole.cell(1, "c").?.float));
    // `ignore_errors` nulls the cell that does not fit the width, as it does for an Int64.
    slow.init(bad, 0);
    var rd2 = try cc.CsvChunkReader.init(a, &slow.interface, .{ .types = &types_csv, .null_values = &.{"NA"} }, .{ .ignore_errors = true });
    defer rd2.deinit();
    const ig = (try rd2.next(a, 4)).?;
    try testing.expect(ig.cell(0, "a").? == .null);
    try has(ig, "a", .int8);

    // NDJSON
    const json_types = [_]df.TypeOverride{ .{ .name = "a", .type = .int16 }, .{ .name = "b", .type = .uint64 }, .{ .name = "c", .type = .float32 } };
    const nd = "{\"a\":-32768,\"b\":18446744073709551615,\"c\":0.1}\n{\"a\":null,\"b\":1,\"c\":null}\n{\"a\":7,\"b\":9223372036854775808,\"c\":2.5}\n";
    slow.init(nd, 2);
    var jr = ndc.NdjsonChunkReader.init(testing.allocator, &slow.interface, .{ .types = &json_types });
    defer jr.deinit();
    var seen: usize = 0;
    while (try jr.next(a, 2)) |ch| {
        try testing.expect(fm.widthsConform(ch));
        try has(ch, "a", .int16);
        try has(ch, "c", .float32);
        seen += ch.len;
    }
    try testing.expectEqual(@as(usize, 3), seen);
    slow.init("{\"a\":40000,\"b\":1,\"c\":1}\n", 0);
    var jr2 = ndc.NdjsonChunkReader.init(testing.allocator, &slow.interface, .{ .types = &json_types });
    defer jr2.deinit();
    try testing.expectError(error.BadValue, jr2.next(a, 2));
}

test "W11B io: render, glimpse, info and the JSON schema name the widths" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.select(a, try fixture(a), &.{ "i8", "u64", "f32", "i64" });
    // The dtype row: polars' short names for the widths, the tag for Int64.
    const t = try df.format(a, f, .{ .show_dtypes = true });
    for ([_][]const u8{ "i8", "u64", "f32" }) |name| try testing.expect(std.mem.find(u8, t, name) != null);
    try testing.expect(std.mem.find(u8, t, "9223372036854775813") != null); // UInt64 above 2^63 whole
    try testing.expect(std.mem.find(u8, t, "inf") != null); // a Float32 infinity
    // Float32 cells in the shortest f32 text, not the widened double's.
    try testing.expect(std.mem.find(u8, t, "0.1") != null);
    try testing.expect(std.mem.find(u8, t, "0.10000000149011612") == null);
    const md = try df.toMarkdown(a, f, .{});
    try testing.expect(std.mem.find(u8, md, "0.1") != null);
    const html = try df.toHtml(a, f, .{});
    try testing.expect(std.mem.find(u8, html, "18446744073709551615") != null);
    const g = try df.glimpse(a, f, .{});
    try testing.expect(std.mem.find(u8, g, "<i8>") != null and std.mem.find(u8, g, "<u64>") != null and std.mem.find(u8, g, "<f32>") != null);
    // JSON Table Schema: an integer width is `integer`, Float32 `number`; reading it back
    // gives Int64 and Float64 (the schema has no width).
    var out: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&out.writer, try df.select(a, f, &.{ "i8", "u64", "f32" }), .table);
    try testing.expect(std.mem.find(u8, out.written(), "\"type\":\"integer\"") != null);
    try testing.expect(std.mem.find(u8, out.written(), "\"type\":\"number\"") != null);
    const back = try df.readJson(a, out.written(), .{ .orient = .table });
    try has(back, "i8", .int);
    try has(back, "f32", .float);
    _ = render;
}

fn sweepIoAndKeyHelpers(a: std.mem.Allocator) !void {
    const f = try fixture(a);
    const num = try numericOnly(a, f);
    // `map` appends a float column; the width columns it passes on are untouched.
    try kept(try df.map(a, num, .{ .out = "m", .lhs = .{ .col = "i8" }, .op = .add, .rhs = .{ .col = "u16" } }));
    // The row order `sort` gives and the same through `sortedRows`, a width key included.
    const order = try verbs.sortedRows(a, f, &.{7}, &.{.asc}, .auto);
    try testing.expectEqual(@as(usize, rows), order.len);
    const jc = try verbs.joinChecked(a, f, try side(a), .{ .on = "k", .how = .left });
    try has(jc, "r_f32", .float32);
    const fac = try verbs.factorKeys(a, f, &.{ 7, 8 });
    try testing.expectEqual(@as(usize, rows), fac.ids.len);
    // Every writer takes every width; the CSV round trip with the types given is exact.
    var csv: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &csv.writer, f, .{});
    const ts = try a.alloc(df.TypeOverride, f.columns.len);
    for (ts, f.columns) |*t, c| t.* = .{ .name = c.name, .type = c.type };
    const back = try df.readCsv(a, csv.written(), .{ .types = ts });
    try kept(back);
    try testing.expect(df.equals(f, back));
    var reader: std.Io.Reader = .fixed(csv.written());
    const via = try df.readCsvReader(a, &reader, .{ .types = ts });
    try testing.expect(df.equals(f, via));
    for ([_]df.JsonOrient{ .records, .columns, .split, .index, .values, .table }) |orient| {
        var out: std.Io.Writer.Allocating = .init(a);
        try df.writeJson(&out.writer, f, orient);
        _ = try std.json.parseFromSliceLeaky(std.json.Value, a, out.written(), .{});
    }
    var nd: std.Io.Writer.Allocating = .init(a);
    try df.writeNdjson(&nd.writer, f);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, nd.written(), "\n"), '\n');
    while (lines.next()) |l| _ = try std.json.parseFromSliceLeaky(std.json.Value, a, l, .{});
    _ = try df.format(a, f, .{ .show_dtypes = true });
    _ = try df.toMarkdown(a, f, .{});
    _ = try df.toHtml(a, f, .{});
    _ = try df.glimpse(a, f, .{});
    _ = try @import("csvio.zig").applyZones(a, f, &.{});
}

// ONE sweep: every public verb of part B (`verbs`, `structure`, `reshape`, `nestverbs`, `frameops`,
// `colfn`, `callback`, `names`, `catfn`, `ranges`) on a frame that holds all eight width columns
// beside an Int64, a text and a null-only column. Each keeps the types it passes on and every
// width column its own array (`frame.widthsConform`). The results part A's files build (the
// aggregates, `concat(.vertical)`/`.diagonal`, the arithmetic of a UInt64 column) are checked
// after the merge: the places are marked in the functions.
test "W11B sweep: every public verb of part B on a frame with all eight widths" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try sweepVerbsZig(a);
    try sweepStructureZig(a);
    try sweepReshapeZig(a);
    try sweepNestverbsZig(a);
    try sweepFrameopsZig(a);
    try sweepColfnCallbackNamesCatfnRanges(a);
    try sweepIoAndKeyHelpers(a);
}

test "W11B values: what the verbs do with a value the width does not hold" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fixture(a);
    // fillna with a value that is no Int8 leaves the cell null; one that is fills it.
    const none = try df.fillna(a, f, .{ .subset = &.{"i8"}, .value = .{ .int = 1000 } });
    try testing.expect(none.cell(3, "i8").? == .null);
    try has(none, "i8", .int8);
    const some = try df.fillna(a, f, .{ .subset = &.{"i8"}, .value = .{ .int = -7 } });
    try testing.expectEqual(@as(i64, -7), some.cell(3, "i8").?.int);
    // A full join that takes a right-only key from the right: Int8 against Int64 1000 widens
    // the key column instead of nulling the key.
    const lc = try a.dupe(Column, &.{ .{ .name = "k", .type = .int8 }, .{ .name = "v", .type = .int } });
    var lb = try fm.FrameBuilder.init(a, lc, 2);
    try lb.appendRow(&.{ .{ .int = 1 }, .{ .int = 10 } });
    try lb.appendRow(&.{ .{ .int = 2 }, .{ .int = 20 } });
    const rc = try a.dupe(Column, &.{ .{ .name = "k", .type = .int }, .{ .name = "w", .type = .int } });
    var rb = try fm.FrameBuilder.init(a, rc, 2);
    try rb.appendRow(&.{ .{ .int = 1000 }, .{ .int = 7 } });
    try rb.appendRow(&.{ .{ .int = 2 }, .{ .int = 8 } });
    const j = try df.join(a, try lb.toOwned(), try rb.toOwned(), .{ .on = "k", .how = .full, .coalesce_keys = true });
    try has(j, "k", .int);
    try testing.expectEqual(@as(i64, 1000), j.cell(2, "k").?.int);
    // Without a right-only key the Int8 key stays Int8.
    var rb2 = try fm.FrameBuilder.init(a, rc, 1);
    try rb2.appendRow(&.{ .{ .int = 2 }, .{ .int = 8 } });
    var lb2 = try fm.FrameBuilder.init(a, lc, 1);
    try lb2.appendRow(&.{ .{ .int = 2 }, .{ .int = 20 } });
    try has(try df.join(a, try lb2.toOwned(), try rb2.toOwned(), .{ .on = "k", .how = .full, .coalesce_keys = true }), "k", .int8);
    // unpivot: melted columns of different numeric types meet in their supertype.
    const m = try df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{ "i8", "u8" } });
    try has(m, "value", .int16);
    try testing.expectEqual(@as(i64, 255), m.cell(3, "value").?.int); // row 1, the u8 column
    const m2 = try df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{ "i8", "i64" } });
    try has(m2, "value", .int);
    // A pivot of a width cell type keeps it, and its fill follows the type.
    const pv = try df.pivot(a, f, .{ .row_key = "k", .col_key = "txt", .value_col = "i16", .agg = .first, .fill_value = 7 });
    try testing.expect(fm.widthsConform(pv));
}

test "W11B values: sort and distinct order and group width keys by their exact value" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fixture(a);
    for (names[0..9], 0..) |n, ci| {
        const asc = try df.sort(a, f, .{ .key = n });
        const desc = try df.sort(a, f, .{ .key = n, .dir = .desc });
        for (0..rows - 1) |i| {
            try testing.expect(asc.columnAt(ci).get(i).order(asc.columnAt(ci).get(i + 1)) != .gt);
            try testing.expect(desc.columnAt(ci).get(i).order(desc.columnAt(ci).get(i + 1)) != .lt);
        }
        // The null sorts first ascending (`.auto`), last descending.
        try testing.expect(asc.columnAt(ci).get(0) == .null);
        try testing.expect(desc.columnAt(ci).get(rows - 1) == .null);
        // Rows 0 and 4 repeat: one fewer distinct value than rows, per column.
        const d = try df.distinct(a, try df.select(a, f, &.{n}), .{ .keys = &.{} });
        try testing.expect(d.len < rows);
        try testing.expect(fm.widthsConform(d));
    }
    // The UInt64 key above 2^63 is its own group, apart from 2^63 itself and from any Int64.
    const kc = try a.dupe(Column, &.{ .{ .name = "k", .type = .uint64 }, .{ .name = "v", .type = .int } });
    var kb = try fm.FrameBuilder.init(a, kc, 5);
    const two63: u64 = 1 << 63;
    try kb.appendRow(&.{ .{ .uint = two63 }, .{ .int = 1 } });
    try kb.appendRow(&.{ .{ .uint = two63 + 1 }, .{ .int = 2 } });
    try kb.appendRow(&.{ .{ .uint = two63 }, .{ .int = 3 } });
    try kb.appendRow(&.{ .{ .int = 5 }, .{ .int = 4 } });
    try kb.appendRow(&.{ .{ .uint = std.math.maxInt(u64) }, .{ .int = 5 } });
    const kf = try kb.toOwned();
    const g = try df.aggregate(a, kf, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "v", .out = "n", .func = .size }} });
    try testing.expectEqual(@as(usize, 4), g.len);
    try testing.expectEqual(@as(i64, 2), g.cell(0, "n").?.int);
    try has(g, "k", .uint64);
    // A float key of 2^63 equals the UInt64 2^63 in a join, and the key keeps the left type.
    const fc = try a.dupe(Column, &.{ .{ .name = "k", .type = .float }, .{ .name = "w", .type = .int } });
    var fb = try fm.FrameBuilder.init(a, fc, 1);
    try fb.appendRow(&.{ .{ .float = 9223372036854775808.0 }, .{ .int = 9 } });
    const j = try df.join(a, kf, try fb.toOwned(), .{ .on = "k", .how = .inner });
    try testing.expectEqual(@as(usize, 2), j.len);
    try has(j, "k", .uint64);
}
