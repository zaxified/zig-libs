// SPDX-License-Identifier: MIT
//! Tests of dataframe S2 wave W10 (the cheap parity gaps): the cases no engine is asked (nulls,
//! empty frames, invalid UTF-8, caps, error paths). What the engines answer is in
//! `s2w10_oracle_test.zig`.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const lf = @import("listfn.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const Value = vm.Value;
const Expr = df.Expr;

fn frame1(a: std.mem.Allocator, name: []const u8, ty: vm.ColumnType, cells: []const Value) !Frame {
    const cols = try a.dupe(Column, &.{.{ .name = name, .type = ty }});
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = cells.len };
}

fn frameN(a: std.mem.Allocator, names: []const []const u8, types: []const vm.ColumnType, cols: []const []const Value) !Frame {
    const cs = try a.alloc(Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    for (cs, data, names, types, cols) |*c, *d, n, t, cells| {
        c.* = .{ .name = n, .type = t };
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cs, .data = data, .len = cols[0].len };
}

fn evalOne(a: std.mem.Allocator, f: Frame, e: Expr) !Value {
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = e }});
    return out.series("o").?.get(0);
}

fn expectCell(want: Value, got: Value) !void {
    try testing.expectEqual(std.meta.activeTag(want), std.meta.activeTag(got));
    switch (want) {
        .null => {},
        .int => |i| try testing.expectEqual(i, got.int),
        .bool => |b| try testing.expectEqual(b, got.bool),
        .float => |x| try testing.expect(x == got.float or (std.math.isNan(x) and std.math.isNan(got.float))),
        .text => |t| try testing.expectEqualStrings(t, got.text),
        else => return error.Unsupported,
    }
}

const X: Expr = .{ .col = "x" };

test "w10 find_regex: byte offsets, nulls, non-text, invalid UTF-8, literal, bad pattern" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frame1(a, "x", .text, &.{ .{ .text = "é1" }, .null, .{ .text = "" }, .{ .text = "\xff\xfe9" }, .{ .text = "a.b" } });
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .find_regex = .{ .x = &X, .pattern = "\\d" } } }});
    const s = out.series("o").?;
    try expectCell(.{ .int = 2 }, s.get(0)); // the byte offset: é is two bytes
    try expectCell(.null, s.get(1));
    try expectCell(.null, s.get(2));
    try expectCell(.{ .int = 2 }, s.get(3));
    // Empty pattern matches at 0 in every text, null stays null.
    const e2 = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .find_regex = .{ .x = &X, .pattern = "" } } }});
    try expectCell(.{ .int = 0 }, e2.series("o").?.get(2));
    try expectCell(.null, e2.series("o").?.get(1));
    // Literal: `.` is a dot, not a wildcard.
    const e3 = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .find_regex = .{ .x = &X, .pattern = ".b", .literal = true } } }});
    try expectCell(.{ .int = 1 }, e3.series("o").?.get(4));
    try expectCell(.null, e3.series("o").?.get(0));
    try testing.expectError(error.BadPattern, df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .find_regex = .{ .x = &X, .pattern = "(" } } }}));
    // A non-text cell is null.
    const g = try frame1(a, "x", .int, &.{.{ .int = 5 }});
    try expectCell(.null, try evalOne(a, g, .{ .find_regex = .{ .x = &X, .pattern = "5" } }));
}

test "w10 json_encode: null struct is the text null, non-struct is null, declared instants stay RFC 3339" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const names: []const []const u8 = &.{ "t", "s" };
    const rec = try lf.makeRecord(a, names, &.{ .{ .int = 0 }, .{ .text = "q\"" } });
    const inner = try a.dupe(Column, &.{ .{ .name = "t", .type = .timestamp }, .{ .name = "s", .type = .text } });
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .@"struct", .inner = inner }});
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, &.{ rec, .null });
    const f: Frame = .{ .columns = cols, .data = data, .len = 2 };
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .json_encode = .{ .x = &X } } }});
    try expectCell(.{ .text = "{\"t\":\"1970-01-01T00:00:00Z\",\"s\":\"q\\\"\"}" }, out.series("o").?.get(0));
    try expectCell(.{ .text = "null" }, out.series("o").?.get(1));
    // No declared schema (an expression, not a column): the cell alone decides, the int stays a number.
    const out2 = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .json_encode = .{ .x = &.{ .struct_op = .{ .x = &X, .op = .{ .drop = &.{"s"} } } } } } }});
    try expectCell(.{ .text = "{\"t\":0}" }, out2.series("o").?.get(0));
    const g = try frame1(a, "x", .int, &.{.{ .int = 5 }});
    try expectCell(.null, try evalOne(a, g, .{ .json_encode = .{ .x = &X } }));
}

test "w10 corrWith: length mismatch, text columns, one-sided columns, no complete rows" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try frameN(a, &.{ "x", "s", "zl" }, &.{ .float, .text, .int }, &.{
        &.{ .{ .float = 1 }, .{ .float = 2 }, .{ .float = 3 } },
        &.{ .{ .text = "a" }, .{ .text = "b" }, .{ .text = "c" } },
        &.{ .{ .int = 1 }, .null, .{ .int = 3 } },
    });
    const r = try frameN(a, &.{ "x", "ar", "zl" }, &.{ .float, .int, .int }, &.{
        &.{ .{ .float = 3 }, .{ .float = 2 }, .{ .float = 1 } },
        &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } },
        &.{ .null, .{ .int = 5 }, .null },
    });
    const g = try df.corrWith(a, l, r, .{});
    // shared in the left frame's order (x, zl), then the one-sided ones sorted (ar, s)
    try testing.expectEqual(@as(usize, 4), g.len);
    try testing.expectEqualStrings("x", g.columnAt(0).get(0).text);
    try testing.expectEqualStrings("zl", g.columnAt(0).get(1).text);
    try testing.expectEqualStrings("ar", g.columnAt(0).get(2).text);
    try testing.expectEqualStrings("s", g.columnAt(0).get(3).text);
    try testing.expectApproxEqAbs(@as(f64, -1), g.columnAt(1).get(0).float, 1e-12);
    try expectCell(.null, g.columnAt(1).get(1)); // no row where both are present
    try expectCell(.null, g.columnAt(1).get(2));
    const d = try df.corrWith(a, l, r, .{ .drop = true });
    try testing.expectEqual(@as(usize, 2), d.len);
    // A text column both frames have is an error.
    const r2 = try frameN(a, &.{"s"}, &.{.text}, &.{&.{ .{ .text = "a" }, .{ .text = "b" }, .{ .text = "c" } }});
    try testing.expectError(error.NotNumeric, df.corrWith(a, l, r2, .{}));
    // Different lengths.
    const short = try frameN(a, &.{"x"}, &.{.float}, &.{&.{ .{ .float = 1 }, .{ .float = 2 } }});
    try testing.expectError(error.LengthMismatch, df.corrWith(a, l, short, .{}));
    // Empty frames: every shared column is null.
    const e1 = try frameN(a, &.{"x"}, &.{.float}, &.{&.{}});
    const e = try df.corrWith(a, e1, e1, .{});
    try testing.expectEqual(@as(usize, 1), e.len);
    try expectCell(.null, e.columnAt(1).get(0));
}

test "w10 unstack: errors, fill casts, caps, names" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameN(a, &.{ "a", "b" }, &.{ .int, .text }, &.{
        &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } },
        &.{ .{ .text = "x" }, .{ .text = "y" }, .{ .text = "z" } },
    });
    try testing.expectError(error.BadArgument, df.unstack(a, f, .{ .step = 0 }));
    const empty = try frameN(a, &.{"a"}, &.{.int}, &.{&.{}});
    try testing.expectError(error.BadArgument, df.unstack(a, empty, .{ .step = 1 }));
    try testing.expectError(error.TooLarge, df.unstack(a, f, .{ .step = std.math.maxInt(usize) }));
    try testing.expectError(error.TooLarge, df.unstack(a, f, .{ .step = 1 << 40, .how = .horizontal }));
    try testing.expectError(error.NoSuchColumn, df.unstack(a, f, .{ .step = 2, .columns = &.{"q"} }));
    try testing.expectError(error.BadArgument, df.unstack(a, f, .{ .step = 2, .fill_values = &.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } } }));
    try testing.expectError(error.BadArgument, df.unstack(a, f, .{ .step = 2, .columns = &.{"a"}, .fill_value = .{ .text = "no" } })); // "no" is not an int
    try testing.expectError(error.DuplicateColumn, df.unstack(a, f, .{ .step = 2, .columns = &.{ "a", "a" } }));
    const g = try df.unstack(a, f, .{ .step = 2, .columns = &.{"a"}, .fill_value = .{ .text = "7" } });
    try testing.expectEqualStrings("a_0", g.columns[0].name);
    try testing.expectEqual(@as(i64, 3), g.columnAt(1).get(0).int);
    try testing.expectEqual(@as(i64, 7), g.columnAt(1).get(1).int); // "7" cast to the int column
    const h = try df.unstack(a, f, .{ .step = 1, .how = .horizontal, .columns = &.{"b"} });
    try testing.expectEqual(@as(usize, 3), h.len);
    try testing.expectEqual(@as(usize, 1), h.columns.len);
    try testing.expectEqualStrings("b_0", h.columns[0].name);
}

test "w10 wideToLong: pattern, uniqueness, types and the existing j" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameN(a, &.{ "id", "A1", "A2", "B1" }, &.{ .int, .int, .int, .text }, &.{
        &.{ .{ .int = 1 }, .{ .int = 2 } },
        &.{ .{ .int = 10 }, .{ .int = 20 } },
        &.{ .{ .int = 11 }, .null },
        &.{ .{ .text = "p" }, .{ .text = "q" } },
    });
    const g = try df.wideToLong(a, f, .{ .stubnames = &.{ "A", "B" }, .i = &.{"id"}, .j = "n" });
    try testing.expectEqual(@as(usize, 4), g.len);
    try testing.expectEqualStrings("id", g.columns[0].name);
    try testing.expectEqualStrings("n", g.columns[1].name);
    try testing.expectEqual(vm.ColumnType.int, g.columns[1].type);
    try testing.expectEqual(vm.ColumnType.int, g.columns[2].type); // int with a null, where pandas makes a float
    try testing.expectEqual(vm.ColumnType.text, g.columns[3].type);
    try testing.expectEqual(@as(i64, 11), g.columnAt(2).get(2).int);
    try expectCell(.null, g.columnAt(2).get(3));
    try expectCell(.null, g.columnAt(3).get(2)); // B has no suffix 2
    try testing.expectError(error.DuplicateColumn, df.wideToLong(a, f, .{ .stubnames = &.{"A"}, .i = &.{"id"}, .j = "id" }));
    try testing.expectError(error.NoSuchColumn, df.wideToLong(a, f, .{ .stubnames = &.{"Q"}, .i = &.{"id"}, .j = "n" }));
    try testing.expectError(error.NoSuchColumn, df.wideToLong(a, f, .{ .stubnames = &.{"A"}, .i = &.{"nope"}, .j = "n" }));
    try testing.expectError(error.BadPattern, df.wideToLong(a, f, .{ .stubnames = &.{"A"}, .i = &.{"id"}, .j = "n", .suffix = "(" }));
    try testing.expectError(error.BadArgument, df.wideToLong(a, f, .{ .stubnames = &.{}, .i = &.{"id"}, .j = "n" }));
    // Stub columns of different types.
    const mixed = try frameN(a, &.{ "id", "A1", "A2" }, &.{ .int, .int, .text }, &.{
        &.{.{ .int = 1 }}, &.{.{ .int = 1 }}, &.{.{ .text = "x" }},
    });
    try testing.expectError(error.BadArgument, df.wideToLong(a, mixed, .{ .stubnames = &.{"A"}, .i = &.{"id"}, .j = "n" }));
    // The ids repeat.
    const dup = try frameN(a, &.{ "id", "A1" }, &.{ .int, .int }, &.{ &.{ .{ .int = 1 }, .{ .int = 1 } }, &.{ .{ .int = 1 }, .{ .int = 2 } } });
    try testing.expectError(error.NotUnique, df.wideToLong(a, dup, .{ .stubnames = &.{"A"}, .i = &.{"id"}, .j = "n" }));
    // Metacharacters in a stub or separator are literal; a text suffix makes a text j.
    const meta = try frameN(a, &.{ "id", "a.b_x", "a.b_y" }, &.{ .int, .int, .int }, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 5 }}, &.{.{ .int = 6 }} });
    const m = try df.wideToLong(a, meta, .{ .stubnames = &.{"a.b"}, .i = &.{"id"}, .j = "k", .sep = "_", .suffix = "[a-z]" });
    try testing.expectEqual(vm.ColumnType.text, m.columns[1].type);
    try testing.expectEqualStrings("y", m.columnAt(1).get(1).text);
}

test "w10 offset_by on a zoned column: calendar units keep the wall clock, sub-day units elapse" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const prague = "Europe/Prague";
    const us_h: i64 = 3_600_000_000;
    const t = vm.parseIsoTimestamp("2024-03-30T11:00:00Z").?; // 12:00 CET
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .timestamp, .time_zone = prague }});
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, &.{ .{ .int = t }, .null, .{ .int = std.math.maxInt(i64) } });
    const f: Frame = .{ .columns = cols, .data = data, .len = 3 };
    const day = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .offset_by = .{ .x = &X, .by = "1d" } } }});
    // 12:00 CET on the 30th, 12:00 CEST on the 31st: 23 hours.
    try testing.expectEqual(t + 23 * us_h, day.series("o").?.get(0).int);
    try expectCell(.null, day.series("o").?.get(1));
    try expectCell(.null, day.series("o").?.get(2)); // past the range
    const hrs = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .offset_by = .{ .x = &X, .by = "24h" } } }});
    try testing.expectEqual(t + 24 * us_h, hrs.series("o").?.get(0).int);
    const mix = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .offset_by = .{ .x = &X, .by = "1d1h" } } }});
    try testing.expectEqual(t + 24 * us_h, mix.series("o").?.get(0).int);
    // A naive column is still elapsed time (UTC has no DST).
    const ncols = try a.dupe(Column, &.{.{ .name = "x", .type = .timestamp }});
    const nf: Frame = .{ .columns = ncols, .data = data, .len = 3 };
    const nd = try df.mutate(a, nf, &.{.{ .out = "o", .expr = .{ .offset_by = .{ .x = &X, .by = "1d" } } }});
    try testing.expectEqual(t + 24 * us_h, nd.series("o").?.get(0).int);
}

test "w10 bin_*: NaN is missing, infinite breaks, orderable types, caps" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const f = try frame1(a, "x", .float, &.{ .{ .float = 1 }, .{ .float = nan }, .null, .{ .float = 3 }, .{ .float = 2 } });
    // NaN and null have no bin and are not counted among the ranks.
    const r = try df.binRanks(a, f, .{ .col = "x", .out = "o", .ranks = .{ .count = 3 } });
    const s = r.series("o").?;
    try expectCell(.{ .int = 0 }, s.get(0));
    try expectCell(.null, s.get(1));
    try expectCell(.null, s.get(2));
    try expectCell(.{ .int = 2 }, s.get(3));
    try expectCell(.{ .int = 1 }, s.get(4));
    // An infinite breakpoint is a break like any other.
    const inf = std.math.inf(f64);
    const g = try df.binIntervals(a, f, .{ .col = "x", .out = "o", .breaks = .{ .at = &.{ .{ .float = -inf }, .{ .float = inf } } } });
    try expectCell(.{ .int = 1 }, g.series("o").?.get(0));
    try expectCell(.null, g.series("o").?.get(1));
    // A count of bins over a column with no present cell: every row null.
    const none = try frame1(a, "x", .float, &.{ .null, .{ .float = nan } });
    const n = try df.binIntervals(a, none, .{ .col = "x", .out = "o", .breaks = .{ .count = 4 } });
    try expectCell(.null, n.series("o").?.get(0));
    // Errors.
    try testing.expectError(error.NotOrderable, df.binRanks(a, try frame1(a, "x", .bool, &.{.{ .bool = true }}), .{ .col = "x", .out = "o", .ranks = .{ .count = 2 } }));
    try testing.expectError(error.NotOrderable, df.binQuantiles(a, try frame1(a, "x", .text, &.{.{ .text = "a" }}), .{ .col = "x", .out = "o", .quantiles = .{ .count = 2 } }));
    try testing.expectError(error.NotOrderable, df.binIntervals(a, try frame1(a, "x", .text, &.{.{ .text = "a" }}), .{ .col = "x", .out = "o", .breaks = .{ .count = 2 } }));
    try testing.expectError(error.BadEdges, df.binIntervals(a, f, .{ .col = "x", .out = "o", .breaks = .{ .at = &.{.{ .text = "a" }} } })); // not the column's kind
    try testing.expectError(error.BadEdges, df.binQuantiles(a, f, .{ .col = "x", .out = "o", .quantiles = .{ .at = &.{nan} } }));
    try testing.expectError(error.BadEdges, df.binRanks(a, f, .{ .col = "x", .out = "o", .ranks = .{ .at = &.{ 0.5, 0.4 } } }));
    try testing.expectError(error.BadLabels, df.binRanks(a, f, .{ .col = "x", .out = "o", .ranks = .{ .count = 2 }, .labels = &.{ "a", "b", "c" } }));
    try testing.expectError(error.TooLarge, df.binRanks(a, f, .{ .col = "x", .out = "o", .ranks = .{ .count = df.max_bins + 1 } }));
    try testing.expectError(error.TooLarge, df.binQuantiles(a, f, .{ .col = "x", .out = "o", .quantiles = .{ .count = std.math.maxInt(usize) } }));
    try testing.expectError(error.NoSuchColumn, df.binRanks(a, f, .{ .col = "nope", .out = "o", .ranks = .{ .count = 2 } }));
    // An empty frame: an empty column.
    const empty = try frame1(a, "x", .int, &.{});
    const e = try df.binQuantiles(a, empty, .{ .col = "x", .out = "o", .quantiles = .{ .count = 3 } });
    try testing.expectEqual(@as(usize, 0), e.len);
    // The largest ints keep their order (no float round trip).
    const big = try frame1(a, "x", .int, &.{ .{ .int = std.math.maxInt(i64) }, .{ .int = std.math.maxInt(i64) - 1 } });
    const b = try df.binIntervals(a, big, .{ .col = "x", .out = "o", .breaks = .{ .at = &.{.{ .int = std.math.maxInt(i64) }} } });
    try expectCell(.{ .int = 1 }, b.series("o").?.get(0));
    try expectCell(.{ .int = 0 }, b.series("o").?.get(1));
    const bc = try df.binIntervals(a, big, .{ .col = "x", .out = "o", .breaks = .{ .count = 2 } });
    try expectCell(.{ .int = 1 }, bc.series("o").?.get(0));
    try expectCell(.{ .int = 0 }, bc.series("o").?.get(1));
}
