// SPDX-License-Identifier: MIT
//! `corr` and `cov` (pandas `DataFrame.corr`/`cov`). Expected values worked by hand
//! (and the tie case equals scipy's `spearmanr`, 0.9486832980505138).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;

fn fl(x: f64) Value {
    return .{ .float = x };
}

fn cell(f: df.Frame, row: usize, name: []const u8) Value {
    return f.cell(row, name).?;
}

test "corr: Pearson, perfect and inverse, pairwise-complete rows, text skipped, a constant column NaN" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{
        .{ .name = "x", .type = .int },  .{ .name = "y", .type = .float }, .{ .name = "z", .type = .int },
        .{ .name = "s", .type = .text }, .{ .name = "k", .type = .float },
    }, &.{
        &.{ .{ .int = 1 }, fl(2), .{ .int = 5 }, .{ .text = "a" }, fl(7) },
        &.{ .{ .int = 2 }, fl(4), .{ .int = 4 }, .{ .text = "b" }, fl(7) },
        &.{ .{ .int = 3 }, fl(6), .{ .int = 3 }, .null, fl(7) },
        &.{ .{ .int = 4 }, fl(std.math.nan(f64)), .{ .int = 2 }, .{ .text = "c" }, fl(7) },
        &.{ .{ .int = 5 }, fl(10), .null, .{ .text = "d" }, fl(7) },
    });
    const r = try df.corr(a, f, .{});
    try testing.expectEqual(@as(usize, 4), r.len);
    try testing.expectEqual(@as(usize, 5), r.columns.len);
    try testing.expectEqualStrings("column", r.columns[0].name);
    try testing.expectEqualStrings("z", cell(r, 2, "column").text);
    try testing.expectEqual(@as(f64, 1), cell(r, 0, "y").float); // rows 0,1,2,4
    try testing.expectEqual(@as(f64, -1), cell(r, 0, "z").float); // rows 0..3
    try testing.expectEqual(@as(f64, 1), cell(r, 1, "y").float);
    try testing.expect(std.math.isNan(cell(r, 0, "k").float));
    // min_periods: y and z share rows 0..2 only.
    const m = try df.corr(a, f, .{ .cols = &.{ "y", "z" }, .min_periods = 4 });
    try testing.expect(cell(m, 0, "z") == .null);
    try testing.expectEqual(@as(f64, 1), cell(m, 0, "y").float);
    try testing.expectError(error.NotNumeric, df.corr(a, f, .{ .cols = &.{"s"} }));
    try testing.expectError(error.NoSuchColumn, df.corr(a, f, .{ .cols = &.{"q"} }));
    try testing.expectError(error.DuplicateColumn, df.corr(a, f, .{ .cols = &.{ "x", "x" } }));
}

test "corr spearman: monotone is 1, ties take the average rank" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } }, &.{
        &.{ fl(1), fl(1) }, &.{ fl(2), fl(4) }, &.{ fl(3), fl(9) }, &.{ fl(4), fl(16) }, &.{ fl(100), fl(25) },
    });
    const r = try df.corr(a, f, .{ .method = .spearman });
    try testing.expectEqual(@as(f64, 1), cell(r, 0, "y").float);
    const g = try st.mk(a, &.{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } }, &.{
        &.{ fl(1), fl(1) }, &.{ fl(2), fl(2) }, &.{ fl(2), fl(3) }, &.{ fl(3), fl(4) },
    });
    const t = try df.corr(a, g, .{ .method = .spearman });
    try testing.expectApproxEqRel(@as(f64, 0.9486832980505138), cell(t, 0, "y").float, 1e-15);
}

test "cov: sample covariance, ddof, too few rows null; a wide frame is TooLarge" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .decimal } }, &.{
        &.{ .{ .int = 1 }, .{ .decimal = 2 * df.decimal_scale } },
        &.{ .{ .int = 2 }, .{ .decimal = 4 * df.decimal_scale } },
        &.{ .{ .int = 3 }, .{ .decimal = 6 * df.decimal_scale } },
        &.{ .{ .int = 4 }, .{ .decimal = 8 * df.decimal_scale } },
        &.{ .{ .int = 5 }, .{ .decimal = 10 * df.decimal_scale } },
    });
    const c = try df.cov(a, f, .{});
    try testing.expectEqual(@as(f64, 2.5), cell(c, 0, "x").float);
    try testing.expectEqual(@as(f64, 5), cell(c, 0, "y").float);
    try testing.expectEqual(@as(f64, 10), cell(c, 1, "y").float);
    const p = try df.cov(a, f, .{ .ddof = 0 });
    try testing.expectEqual(@as(f64, 4), cell(p, 0, "y").float);
    const one = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 1 }}});
    try testing.expect(cell(try df.cov(a, one, .{}), 0, "x") == .null);
    // 2^16 columns of 2^16 rows: 2^47 visits, refused before any work.
    const cols = try a.alloc(df.Column, 1 << 16);
    for (cols, 0..) |*col, i| col.* = .{ .name = try std.fmt.allocPrint(a, "c{d}", .{i}), .type = .float };
    const data = try a.alloc(df.ColumnData, cols.len);
    @memset(data, .nulls);
    const wide: df.Frame = .{ .columns = cols, .data = data, .len = 1 << 16 };
    try testing.expectError(error.TooLarge, df.cov(a, wide, .{}));
}
