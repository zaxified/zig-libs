// SPDX-License-Identifier: MIT
//! `analysis.zig`'s verbs and the `aggregate` options added after the move (`ddof`,
//! `interpolation`, `min_count`, `dropna(thresh)`), on hand-built tables. Expected cells
//! from pandas' and polars' documented behaviour and numpy's quantile methods (not run
//! here; pandas is not installed on this host).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Frame = df.Frame;
const mk = st.mk;
const expectCol = st.expectCol;

fn ints(a: std.mem.Allocator, name: []const u8, xs: []const ?i64) !Frame {
    const rows = try a.alloc([]const Value, xs.len);
    for (rows, xs) |*r, x| r.* = try a.dupe(Value, &.{if (x) |v| Value{ .int = v } else .null});
    return mk(a, try a.dupe(df.Column, &.{.{ .name = name, .type = .int }}), rows);
}

fn bools(xs: []const ?bool, a: std.mem.Allocator) ![]const Value {
    const out = try a.alloc(Value, xs.len);
    for (out, xs) |*o, x| o.* = if (x) |b| .{ .bool = b } else .null;
    return out;
}

test "duplicateMask: pandas duplicated(keep) and polars is_* masks, missing is one key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ints(a, "k", &.{ 1, 2, 1, null, null });
    const cases = .{
        .{ df.DupMask.duplicated_first, [_]?bool{ false, false, true, false, true } },
        .{ df.DupMask.duplicated_last, [_]?bool{ true, false, false, true, false } },
        .{ df.DupMask.is_duplicated, [_]?bool{ true, false, true, true, true } },
        .{ df.DupMask.is_unique, [_]?bool{ false, true, false, false, false } },
        .{ df.DupMask.is_first_distinct, [_]?bool{ true, true, false, true, false } },
        .{ df.DupMask.is_last_distinct, [_]?bool{ false, true, true, false, true } },
    };
    inline for (cases) |c| {
        const g = try df.duplicateMask(a, f, .{ .mask = c[0], .out = "m" });
        const want: [5]?bool = c[1];
        try expectCol(g, "m", try bools(&want, a));
    }
    try testing.expectError(error.DuplicateColumn, df.duplicateMask(a, f, .{ .out = "k" }));
}

test "horizontal: sum stays int, skip_na, min_count, Kleene all/any" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{
        &.{ .{ .int = 1 }, .{ .int = 2 } },
        &.{ .null, .{ .int = 3 } },
        &.{ .null, .null },
    });
    try expectCol(try df.horizontal(a, f, .{ .func = .sum, .out = "s" }), "s", &.{ .{ .int = 3 }, .{ .int = 3 }, .{ .int = 0 } });
    try expectCol(try df.horizontal(a, f, .{ .func = .sum, .out = "s", .skip_na = false }), "s", &.{ .{ .int = 3 }, .null, .null });
    try expectCol(try df.horizontal(a, f, .{ .func = .sum, .out = "s", .min_count = 2 }), "s", &.{ .{ .int = 3 }, .null, .null });
    try expectCol(try df.horizontal(a, f, .{ .func = .mean, .out = "s" }), "s", &.{ .{ .float = 1.5 }, .{ .float = 3 }, .null });
    try expectCol(try df.horizontal(a, f, .{ .func = .max, .out = "s" }), "s", &.{ .{ .int = 2 }, .{ .int = 3 }, .null });
    try expectCol(try df.horizontal(a, f, .{ .func = .count, .out = "s" }), "s", &.{ .{ .int = 2 }, .{ .int = 1 }, .{ .int = 0 } });
    const over = try mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{&.{ .{ .int = std.math.maxInt(i64) }, .{ .int = 1 } }});
    try expectCol(try df.horizontal(a, over, .{ .func = .sum, .out = "s" }), "s", &.{.null});
    const mixed = try mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .float } }, &.{&.{ .{ .int = 4 }, .{ .float = 0.5 } }});
    try expectCol(try df.horizontal(a, mixed, .{ .func = .sum, .out = "s" }), "s", &.{.{ .float = 4.5 }});
    try expectCol(try df.horizontal(a, mixed, .{ .func = .max, .out = "s" }), "s", &.{.{ .float = 4 }});

    const b = try mk(a, &.{ .{ .name = "p", .type = .bool }, .{ .name = "q", .type = .bool } }, &.{
        &.{ .{ .bool = true }, .null },
        &.{ .{ .bool = false }, .null },
        &.{ .{ .bool = true }, .{ .bool = true } },
    });
    try expectCol(try df.horizontal(a, b, .{ .func = .all, .out = "r" }), "r", &.{ .{ .bool = true }, .{ .bool = false }, .{ .bool = true } });
    try expectCol(try df.horizontal(a, b, .{ .func = .all, .out = "r", .skip_na = false }), "r", &.{ .null, .{ .bool = false }, .{ .bool = true } });
    try expectCol(try df.horizontal(a, b, .{ .func = .any, .out = "r", .skip_na = false }), "r", &.{ .{ .bool = true }, .null, .{ .bool = true } });
}

test "fillNull strategies, limit; dropna thresh; replaceStrict" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ints(a, "x", &.{ 1, null, null, 4, null });
    try expectCol(try df.fillNull(a, f, .{ .strategy = .forward }), "x", &.{ .{ .int = 1 }, .{ .int = 1 }, .{ .int = 1 }, .{ .int = 4 }, .{ .int = 4 } });
    try expectCol(try df.fillNull(a, f, .{ .strategy = .forward, .limit = 1 }), "x", &.{ .{ .int = 1 }, .{ .int = 1 }, .null, .{ .int = 4 }, .{ .int = 4 } });
    try expectCol(try df.fillNull(a, f, .{ .strategy = .backward, .limit = 1 }), "x", &.{ .{ .int = 1 }, .null, .{ .int = 4 }, .{ .int = 4 }, .null });
    try expectCol(try df.fillNull(a, f, .{ .strategy = .zero }), "x", &.{ .{ .int = 1 }, .{ .int = 0 }, .{ .int = 0 }, .{ .int = 4 }, .{ .int = 0 } });
    try expectCol(try df.fillNull(a, f, .{ .strategy = .max }), "x", &.{ .{ .int = 1 }, .{ .int = 4 }, .{ .int = 4 }, .{ .int = 4 }, .{ .int = 4 } });
    const m = try df.fillNull(a, f, .{ .strategy = .mean });
    try testing.expectEqual(df.ColumnType.float, m.columns[0].type);
    try expectCol(m, "x", &.{ .{ .float = 1 }, .{ .float = 2.5 }, .{ .float = 2.5 }, .{ .float = 4 }, .{ .float = 2.5 } });

    const w = try mk(a, &.{ .{ .name = "p", .type = .int }, .{ .name = "q", .type = .int }, .{ .name = "r", .type = .int } }, &.{
        &.{ .{ .int = 1 }, .null, .null },
        &.{ .{ .int = 1 }, .{ .int = 2 }, .null },
        &.{ .null, .null, .null },
    });
    try testing.expectEqual(@as(usize, 1), (try df.dropna(a, w, .{ .thresh = 2 })).len);
    try testing.expectEqual(@as(usize, 2), (try df.dropna(a, w, .{ .thresh = 1 })).len);
    try testing.expectEqual(@as(usize, 3), (try df.dropna(a, w, .{ .thresh = 0 })).len);

    const pairs: []const df.ReplacePair = &.{ .{ .from = .{ .int = 1 }, .to = .{ .text = "one" } }, .{ .from = .{ .int = 4 }, .to = .{ .text = "four" } } };
    try testing.expectError(error.Unmatched, df.replaceStrict(a, try ints(a, "x", &.{ 1, 2 }), .{ .col = "x", .pairs = pairs }));
    const r = try df.replaceStrict(a, f, .{ .col = "x", .pairs = pairs, .default = .{ .text = "?" }, .type = .text });
    try expectCol(r, "x", &.{ .{ .text = "one" }, .null, .null, .{ .text = "four" }, .null });
    try testing.expectEqual(df.ColumnType.text, r.columns[0].type);
}

test "argSort, isSorted, searchSorted, indexOf" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ints(a, "x", &.{ 3, 1, null, 2 });
    try testing.expectEqualSlices(u32, &.{ 2, 1, 3, 0 }, try df.argSort(a, f, .{ .key = "x" }));
    try testing.expectEqualSlices(u32, &.{ 1, 3, 0, 2 }, try df.argSort(a, f, .{ .key = "x", .missing = .last }));
    try testing.expect(!try df.isSorted(a, f, .{ .key = "x" }));
    const s = try ints(a, "x", &.{ null, 1, 2, 2, 3 });
    try testing.expect(try df.isSorted(a, s, .{ .key = "x" }));
    try testing.expect(!try df.isSorted(a, s, .{ .key = "x", .dir = .desc }));
    try testing.expect(!try df.isSorted(a, s, .{ .key = "x", .missing = .last }));
    const ser = s.series("x").?;
    try testing.expectEqual(@as(usize, 2), df.searchSorted(ser, .{ .int = 2 }, .left));
    try testing.expectEqual(@as(usize, 4), df.searchSorted(ser, .{ .int = 2 }, .right));
    try testing.expectEqual(@as(usize, 5), df.searchSorted(ser, .{ .float = 9 }, .left));
    try testing.expectEqual(@as(usize, 1), df.searchSorted(ser, .{ .float = 0.5 }, .left));
    try testing.expectEqual(@as(?usize, 2), df.indexOf(ser, .{ .float = 2 }));
    try testing.expectEqual(@as(?usize, 0), df.indexOf(ser, .null));
    try testing.expectEqual(@as(?usize, null), df.indexOf(ser, .{ .int = 7 }));
}

test "factorize: first-seen or sorted codes, -1 or null for missing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{.{ .name = "k", .type = .text }}, &.{ &.{.{ .text = "b" }}, &.{.{ .text = "a" }}, &.{.{ .text = "b" }}, &.{.null} });
    const r = try df.factorize(a, f, .{ .cols = &.{"k"} });
    try expectCol(r.frame, "code", &.{ .{ .int = 0 }, .{ .int = 1 }, .{ .int = 0 }, .{ .int = -1 } });
    try expectCol(r.uniques, "k", &.{ .{ .text = "b" }, .{ .text = "a" } });
    const s = try df.factorize(a, f, .{ .cols = &.{"k"}, .sort = true, .missing = .null });
    try expectCol(s.frame, "code", &.{ .{ .int = 1 }, .{ .int = 0 }, .{ .int = 1 }, .null });
    try expectCol(s.uniques, "k", &.{ .{ .text = "a" }, .{ .text = "b" } });
}

test "topK over several columns, keep first/last/all" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try mk(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int }, .{ .name = "id", .type = .int } }, &.{
        &.{ .{ .int = 5 }, .{ .int = 1 }, .{ .int = 0 } },
        &.{ .{ .int = 7 }, .{ .int = 0 }, .{ .int = 1 } },
        &.{ .{ .int = 5 }, .{ .int = 2 }, .{ .int = 2 } },
        &.{ .{ .int = 5 }, .{ .int = 1 }, .{ .int = 3 } },
        &.{ .null, .{ .int = 9 }, .{ .int = 4 } },
    });
    try expectCol(try df.topK(a, f, .{ .by = &.{ "x", "y" }, .n = 3 }), "id", &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 0 } });
    try expectCol(try df.topK(a, f, .{ .by = &.{ "x", "y" }, .n = 3, .keep = .last }), "id", &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } });
    try expectCol(try df.topK(a, f, .{ .by = &.{ "x", "y" }, .n = 3, .keep = .all }), "id", &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 0 }, .{ .int = 3 } });
    try expectCol(try df.topK(a, f, .{ .by = &.{"x"}, .n = 1, .largest = false }), "id", &.{.{ .int = 0 }});
}

test "qcut: type-7 edges, lowest included, duplicates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ints(a, "x", &.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    // pandas.qcut(range(1, 9), 4, labels=False) == [0, 0, 1, 1, 2, 2, 3, 3].
    try expectCol(try df.qcut(a, f, .{ .col = "x", .out = "q" }), "q", &.{ .{ .int = 0 }, .{ .int = 0 }, .{ .int = 1 }, .{ .int = 1 }, .{ .int = 2 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 3 } });
    const l = try df.qcut(a, f, .{ .col = "x", .out = "q", .probs = &.{ 0, 0.5, 1 }, .labels = &.{ "lo", "hi" } });
    try expectCol(l, "q", &.{ .{ .text = "lo" }, .{ .text = "lo" }, .{ .text = "lo" }, .{ .text = "lo" }, .{ .text = "hi" }, .{ .text = "hi" }, .{ .text = "hi" }, .{ .text = "hi" } });
    const d = try ints(a, "x", &.{ 1, 1, 1, 1, 2 });
    try testing.expectError(error.BadEdges, df.qcut(a, d, .{ .col = "x", .out = "q" }));
    try expectCol(try df.qcut(a, d, .{ .col = "x", .out = "q", .duplicates = .drop }), "q", &.{ .{ .int = 0 }, .{ .int = 0 }, .{ .int = 0 }, .{ .int = 0 }, .{ .int = 0 } });
    try testing.expectError(error.BadEdges, df.qcut(a, try ints(a, "x", &.{null}), .{ .col = "x", .out = "q" }));
    try testing.expectError(error.BadArgument, df.qcut(a, f, .{ .col = "x", .out = "q", .bins = 0 }));
}

test "aggregate ddof, interpolation, min_count" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ints(a, "x", &.{ 1, 2, 3, 4 });
    const agg = struct {
        fn one(al: std.mem.Allocator, fr: Frame, c: df.AggCol) !Value {
            const g = try df.aggregate(al, fr, .{ .group_by = &.{}, .aggs = &.{c}, .skip_na = true });
            return g.cell(0, c.out).?;
        }
    }.one;
    try testing.expectApproxEqAbs(@as(f64, 1.25), (try agg(a, f, .{ .src = "x", .out = "v", .func = .@"var", .ddof = 0 })).float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 5.0 / 3.0), (try agg(a, f, .{ .src = "x", .out = "v", .func = .@"var" })).float, 1e-12);
    try testing.expect((try agg(a, f, .{ .src = "x", .out = "v", .func = .std, .ddof = 4 })) == .null);
    // numpy.quantile([1, 2, 3, 4], 0.5, method=...): h = 1.5.
    const q = [_]struct { df.Interpolation, f64 }{ .{ .linear, 2.5 }, .{ .lower, 2 }, .{ .higher, 3 }, .{ .midpoint, 2.5 }, .{ .nearest, 3 } };
    for (q) |c| {
        const v = try agg(a, f, .{ .src = "x", .out = "v", .func = .quantile, .q = 0.5, .interpolation = c[0] });
        try testing.expectApproxEqAbs(c[1], v.float, 1e-12);
    }
    // h = 0.75 * 3 = 2.25: nearest rounds to 2, midpoint (3 + 4) / 2.
    try testing.expectApproxEqAbs(@as(f64, 3), (try agg(a, f, .{ .src = "x", .out = "v", .func = .quantile, .q = 0.75, .interpolation = .nearest })).float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 3.5), (try agg(a, f, .{ .src = "x", .out = "v", .func = .quantile, .q = 0.75, .interpolation = .midpoint })).float, 1e-12);
    const n = try ints(a, "x", &.{ null, 2 });
    try testing.expect((try agg(a, n, .{ .src = "x", .out = "v", .func = .sum, .min_count = 2 })) == .null);
    try testing.expect((try agg(a, n, .{ .src = "x", .out = "v", .func = .sum, .min_count = 1 })) != .null);
}
