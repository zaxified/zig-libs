// SPDX-License-Identifier: MIT
//! `structure.zig`'s verbs on hand-built tables, the expected cells written from pandas'
//! and polars' documented behaviour (the engines were not run for these: where the two
//! differ the test says which one is followed).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;

pub fn mk(a: std.mem.Allocator, cols: []const Column, rows: []const []const Value) !Frame {
    var b = try df.FrameBuilder.init(a, cols, rows.len);
    for (rows) |r| try b.appendRow(r);
    return b.toOwned();
}

pub fn same(x: Value, y: Value) bool {
    const xn = x == .float and std.math.isNan(x.float);
    const yn = y == .float and std.math.isNan(y.float);
    if (xn or yn) return xn and yn;
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .int => |i| i == y.int,
        .float => |v| v == y.float or @abs(v - y.float) <= 1e-12 * @max(@abs(v), 1),
        .bool => |b| b == y.bool,
        .decimal => |d| d == y.decimal,
        .text => |t| std.mem.eql(u8, t, y.text),
    };
}

/// Column `name`'s cells are `want`, kind and value.
pub fn expectCol(f: Frame, name: []const u8, want: []const Value) !void {
    try testing.expectEqual(want.len, f.len);
    for (want, 0..) |w, ri| {
        const got = f.cell(ri, name) orelse return error.TestUnexpectedResult;
        if (!same(got, w)) {
            std.debug.print("column {s} row {d}: got {any}, want {any}\n", .{ name, ri, got, w });
            return error.TestUnexpectedResult;
        }
    }
}

const cols3: []const Column = &.{
    .{ .name = "i", .type = .int },
    .{ .name = "f", .type = .float },
    .{ .name = "t", .type = .text },
};

fn sample3(a: std.mem.Allocator) !Frame {
    return mk(a, cols3, &.{
        &.{ .{ .int = 1 }, .{ .float = 1.5 }, .{ .text = "a" } },
        &.{ .{ .int = 2 }, .null, .{ .text = "bb" } },
        &.{ .null, .{ .float = std.math.nan(f64) }, .{ .text = "c" } },
    });
}

test "clone is a deep copy, clear keeps the schema" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    const g = try df.clone(a, f);
    try testing.expect(df.equals(f, g));
    try testing.expect(f.columns[2].name.ptr != g.columns[2].name.ptr);
    try testing.expect(f.cell(0, "t").?.text.ptr != g.cell(0, "t").?.text.ptr);

    const c = try df.clear(a, f, 2);
    try testing.expectEqual(@as(usize, 2), c.len);
    try testing.expectEqual(@as(usize, 3), c.columns.len);
    try expectCol(c, "t", &.{ .null, .null });
    try testing.expectEqual(@as(usize, 0), (try df.clear(a, f, 0)).len);
}

test "take, gatherEvery, reverse" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    const t = try df.take(a, f, &.{ -1, 0, 0 });
    try expectCol(t, "t", &.{ .{ .text = "c" }, .{ .text = "a" }, .{ .text = "a" } });
    try testing.expectError(error.IndexOutOfBounds, df.take(a, f, &.{3}));
    try testing.expectError(error.IndexOutOfBounds, df.take(a, f, &.{-4}));
    try expectCol(try df.gatherEvery(a, f, 2, 1), "i", &.{.{ .int = 2 }});
    try expectCol(try df.gatherEvery(a, f, 2, 0), "i", &.{ .{ .int = 1 }, .null });
    try expectCol(try df.gatherEvery(a, f, 1, 9), "i", &.{});
    try testing.expectError(error.BadArgument, df.gatherEvery(a, f, 0, 0));
    try expectCol(try df.reverse(a, f), "t", &.{ .{ .text = "c" }, .{ .text = "bb" }, .{ .text = "a" } });
}

test "insertColumn, hstack, replaceColumn, popColumn" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    const s = f.series("i").?;
    var renamed = s;
    renamed.name = "j";
    const g = try df.insertColumn(a, f, 0, renamed);
    try testing.expectEqualStrings("j", g.columns[0].name);
    try testing.expectEqualStrings("i", g.columns[1].name);
    try expectCol(g, "j", &.{ .{ .int = 1 }, .{ .int = 2 }, .null });
    try testing.expectError(error.DuplicateColumn, df.insertColumn(a, f, 0, s));
    try testing.expectError(error.IndexOutOfBounds, df.insertColumn(a, f, 4, renamed));
    var short = renamed;
    short.len = 2;
    try testing.expectError(error.LengthMismatch, df.insertColumn(a, f, 0, short));
    // An empty frame takes its height from its first column.
    const e = try df.hstack(a, .{ .columns = &.{}, .data = &.{}, .len = 0 }, &.{renamed});
    try testing.expectEqual(@as(usize, 3), e.len);

    const h = try df.hstack(a, f, &.{renamed});
    try testing.expectEqualStrings("j", h.columns[3].name);
    const r = try df.replaceColumn(a, f, 1, renamed);
    try testing.expectEqualStrings("j", r.columns[1].name);
    try testing.expectEqual(df.ColumnType.int, r.columns[1].type);
    try testing.expectError(error.DuplicateColumn, df.replaceColumn(a, f, 1, s));
    const p = try df.popColumn(a, f, "f");
    try testing.expectEqual(@as(usize, 2), p.frame.columns.len);
    try testing.expectEqualStrings("f", p.series.name);
    try testing.expectEqual(@as(usize, 3), p.series.len);
    try testing.expectError(error.NoSuchColumn, df.popColumn(a, f, "zz"));
}

test "addAffix renames all or a subset, refuses a collision" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    const p = try df.addAffix(a, f, .{ .prefix = "x_" });
    try testing.expectEqualStrings("x_i", p.columns[0].name);
    try testing.expectEqualStrings("x_t", p.columns[2].name);
    const s = try df.addAffix(a, f, .{ .suffix = "_s", .cols = &.{"f"} });
    try testing.expectEqualStrings("i", s.columns[0].name);
    try testing.expectEqualStrings("f_s", s.columns[1].name);
    const clash = try mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "xa", .type = .int } }, &.{});
    try testing.expectError(error.DuplicateColumn, df.addAffix(a, clash, .{ .prefix = "x", .cols = &.{"a"} }));
}

test "selectors and select_dtypes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    const num = try df.selectColumns(a, f, .numeric);
    try testing.expectEqual(@as(usize, 2), num.len);
    const not_text = try df.selectColumns(a, f, .{ .not = &.text });
    try testing.expectEqualStrings("f", not_text[1]);
    // pandas select_dtypes(include="number", exclude="float").
    const inc = try df.selectBy(a, f, .{ .all_of = &.{ .numeric, .{ .not = &.{ .by_type = &.{.float} } } } });
    try testing.expectEqual(@as(usize, 1), inc.columns.len);
    try testing.expectEqualStrings("i", inc.columns[0].name);
    const either = try df.selectColumns(a, f, .{ .any_of = &.{ .last, .{ .starts_with = "f" } } });
    try testing.expectEqual(@as(usize, 2), either.len);
    try testing.expectError(error.NoSuchColumn, df.selectColumns(a, f, .{ .by_name = &.{"zz"} }));
    try testing.expectError(error.IndexOutOfBounds, df.selectColumns(a, f, .{ .by_index = &.{7} }));
    // A nesting past the bound is refused, not followed into a stack overflow.
    var nest: [70]df.Selector = undefined;
    nest[0] = .all;
    for (1..70) |i| nest[i] = .{ .not = &nest[i - 1] };
    try testing.expectError(error.BadArgument, df.selectColumns(a, f, nest[69]));
}

test "nullCount, hasNulls, info, estimatedSize" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    const n = try df.nullCount(a, f);
    try testing.expectEqual(@as(usize, 1), n.len);
    try expectCol(n, "i", &.{.{ .int = 1 }});
    try expectCol(n, "f", &.{.{ .int = 2 }}); // null and NaN: the module's one rule
    try expectCol(n, "t", &.{.{ .int = 0 }});
    try testing.expect(df.hasNulls(f));
    const ok = try mk(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }}, &.{.{ .int = 3 }} });
    try testing.expect(!df.hasNulls(ok));
    try testing.expectEqual(@as(usize, 24), df.estimatedSize(ok));
    const i = try df.info(a, f);
    try testing.expectEqual(@as(usize, 3), i.len);
    try expectCol(i, "column", &.{ .{ .text = "i" }, .{ .text = "f" }, .{ .text = "t" } });
    try expectCol(i, "type", &.{ .{ .text = "int" }, .{ .text = "float" }, .{ .text = "text" } });
    try expectCol(i, "non_null", &.{ .{ .int = 2 }, .{ .int = 1 }, .{ .int = 3 } });
    // 3 ints + one bitmap word; 3 floats + a word; 4 offsets + 4 bytes.
    try expectCol(i, "bytes", &.{ .{ .int = 32 }, .{ .int = 32 }, .{ .int = 4 * @sizeOf(usize) + 4 } });
}

test "equals: NaN equals NaN, null is not NaN, names and types count" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try sample3(a);
    try testing.expect(df.equals(f, try sample3(a)));
    const g = try mk(a, cols3, &.{
        &.{ .{ .int = 1 }, .{ .float = 1.5 }, .{ .text = "a" } },
        &.{ .{ .int = 2 }, .null, .{ .text = "bb" } },
        &.{ .null, .null, .{ .text = "c" } },
    });
    try testing.expect(!df.equals(f, g));
    try testing.expect(!df.equals(f, try df.addAffix(a, f, .{ .suffix = "2", .cols = &.{"t"} })));
    const h = try df.cast(a, f, .{ .col = "i", .to = .float });
    try testing.expect(!df.equals(f, h));
}

test "transpose: names, header, names_from, type rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "k", .type = .text }, .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{
        &.{ .{ .text = "r0" }, .{ .int = 1 }, .{ .int = 2 } },
        &.{ .{ .text = "r1" }, .{ .int = 3 }, .{ .int = 4 } },
    });
    const t = try df.transpose(a, f, .{ .names_from = "k", .header_name = "column" });
    try testing.expectEqual(@as(usize, 2), t.len);
    try testing.expectEqualStrings("r0", t.columns[1].name);
    try testing.expectEqual(df.ColumnType.int, t.columns[1].type);
    try expectCol(t, "column", &.{ .{ .text = "x" }, .{ .text = "y" } });
    try expectCol(t, "r0", &.{ .{ .int = 1 }, .{ .int = 2 } });
    try expectCol(t, "r1", &.{ .{ .int = 3 }, .{ .int = 4 } });

    // polars' default names; text among numbers keeps the cells, declared text.
    const m = try df.transpose(a, f, .{});
    try testing.expectEqualStrings("column_1", m.columns[1].name);
    try testing.expectEqual(df.ColumnType.text, m.columns[0].type);
    try expectCol(m, "column_0", &.{ .{ .text = "r0" }, .{ .int = 1 }, .{ .int = 2 } });

    const nums = try mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .float } }, &.{&.{ .{ .int = 1 }, .{ .float = 0.5 } }});
    const nt = try df.transpose(a, nums, .{ .names = &.{"only"} });
    try testing.expectEqual(df.ColumnType.float, nt.columns[0].type);
    try expectCol(nt, "only", &.{ .{ .float = 1 }, .{ .float = 0.5 } });
    try testing.expectError(error.LengthMismatch, df.transpose(a, nums, .{ .names = &.{ "a", "b" } }));
    try testing.expectError(error.DuplicateColumn, df.transpose(a, f, .{ .names = &.{ "a", "a" } }));
}

test "concat: vertical checks the schema, horizontal pads, diagonal fills" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const x = try mk(a, &.{.{ .name = "a", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    const y = try mk(a, &.{.{ .name = "a", .type = .int }}, &.{&.{.{ .int = 3 }}});
    const z = try mk(a, &.{.{ .name = "b", .type = .float }}, &.{&.{.{ .float = 0.5 }}});
    const w = try mk(a, &.{.{ .name = "a", .type = .float }}, &.{&.{.{ .float = 0.5 }}});
    try expectCol(try df.concat(a, &.{ x, y }, .vertical), "a", &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } });
    try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ x, z }, .vertical));
    try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ x, w }, .vertical));
    try expectCol(try df.concat(a, &.{ x, w }, .vertical_relaxed), "a", &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .float = 0.5 } });
    const d = try df.concat(a, &.{ x, z }, .diagonal);
    try expectCol(d, "b", &.{ .null, .null, .{ .float = 0.5 } });
    const h = try df.concat(a, &.{ x, z }, .horizontal);
    try testing.expectEqual(@as(usize, 2), h.len);
    try expectCol(h, "b", &.{ .{ .float = 0.5 }, .null });
    try testing.expectError(error.DuplicateColumn, df.concat(a, &.{ x, y }, .horizontal));
    try testing.expectEqual(@as(usize, 0), (try df.concat(a, &.{}, .vertical)).len);
}
