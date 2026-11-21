// SPDX-License-Identifier: MIT
//! Items of SPEC § Backlog closed in wave 14: each test names the review bullet it pins.

const std = @import("std");
const knob_skip = @import("knobs_skip.zig");
const testing = std.testing;
const df = @import("root.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;
const st = @import("structure_test.zig");

fn i(x: i64) Value {
    return .{ .int = x };
}

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

test "cut: out and break_out may not collide with a column or with each other (more c)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{i(1)}, &.{i(2)} });
    try testing.expectError(error.DuplicateColumn, df.cut(a, f, .{ .col = "x", .out = "x", .edges = &.{ 0, 5 } }));
    try testing.expectError(error.DuplicateColumn, df.cut(a, f, .{ .col = "x", .out = "o", .break_out = "x", .edges = &.{ 0, 5 } }));
    try testing.expectError(error.DuplicateColumn, df.cut(a, f, .{ .col = "x", .out = "o", .break_out = "o", .edges = &.{ 0, 5 } }));
    // labels win over interval_labels; precision is then unused
    const g = try df.cut(a, f, .{ .col = "x", .out = "o", .edges = &.{ 0, 5 }, .labels = &.{"low"}, .interval_labels = true, .precision = 9 });
    try testing.expectEqualStrings("low", g.cell(0, "o").?.text);
}

test "cut: interval edges print as Python's repr (more b)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.{ .float = 0.5e-7 }}});
    const g = try df.cut(a, f, .{ .col = "x", .out = "o", .edges = &.{ 0, 1e-7, 1e300 }, .interval_labels = true });
    try testing.expectEqualStrings("(0.0, 1e-07]", g.cell(0, "o").?.text);
}

test "describeWith: no column to describe is BadArgument (more f)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{&.{i(1)}});
    try testing.expectError(error.BadArgument, df.describeWith(a, f, .{ .include = &.{.bool} }));
    const e = try st.mk(a, &.{}, &.{});
    try testing.expectError(error.BadArgument, df.describeWith(a, e, .{}));
}

test "erfc: the fraction answers from 1 up, to 2e-15 relative (exprfn a)" {
    const fnx = @import("exprfn.zig");
    const cases = [_][2]f64{
        .{ 1.0, 0.15729920705028513 },
        .{ 1.2, 0.08968602177036464 },
        .{ 1.5, 0.033894853524689274 },
        .{ 1.75, 0.013328328780817557 },
        .{ 1.99, 0.004888586800383003 },
        .{ 2.0, 0.004677734981047266 },
        .{ 3.0, 2.209049699858544e-05 },
    };
    for (cases) |c| {
        const rel = @abs(fnx.erfc(c[0]) - c[1]) / c[1];
        try testing.expect(rel < 2e-15);
    }
}

test "escape_regex output compiles and matches the text it escaped (exprfn d)" {
    const fnx = @import("exprfn.zig");
    const regex = @import("regex");
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const text = "a\\b.c+d*e?f(g)h|i[j]k{l}m^n$o#p&q-r~s t";
    const pat = try fnx.escapeRegex(a, text);
    var re = try regex.Regex.compile(testing.allocator, pat);
    defer re.deinit(testing.allocator);
    try testing.expect(re.fullMatch(text));
    try testing.expect(!re.fullMatch("x"));
}

test "match_regex: a verbose pattern ending in a comment still compiles (expr a)" {
    try knob_skip.needRegex();
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{.{ .name = "s", .type = .text }}, &.{ &.{.{ .text = "ab" }}, &.{.{ .text = "abc" }} });
    const x = try a.create(df.Expr);
    x.* = .{ .col = "s" };
    const g = try df.mutate(a, f, &.{.{ .out = "m", .expr = .{ .match_regex = .{ .x = x, .pattern = "(?x) a b # tail", .full = true } } }});
    try testing.expectEqual(true, g.cell(0, "m").?.bool);
    try testing.expectEqual(false, g.cell(1, "m").?.bool);
}

test "join: validate on a cross join, under no_match, and an indicator that names a column (verbs a, f, b)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const two = try st.mk(a, &.{.{ .name = "k", .type = .int }}, &.{ &.{i(1)}, &.{i(2)} });
    const one = try st.mk(a, &.{.{ .name = "z", .type = .int }}, &.{&.{i(9)}});
    // cross: a side is unique only with one row (pandas merges on one constant key)
    _ = try df.join(a, two, one, .{ .how = .cross, .validate = .many_to_one });
    try testing.expectError(error.ValidationFailed, df.join(a, two, one, .{ .how = .cross, .validate = .one_to_many }));
    // two null keys: equal under .match, nothing under .no_match
    const nl = try st.mk(a, &.{.{ .name = "k", .type = .int }}, &.{ &.{.null}, &.{.null}, &.{i(1)} });
    const r = try st.mk(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .int } }, &.{&.{ i(1), i(5) }});
    try testing.expectError(error.ValidationFailed, df.join(a, nl, r, .{ .on = "k", .validate = .one_to_many }));
    const ok = try df.join(a, nl, r, .{ .on = "k", .how = .left, .validate = .one_to_many, .null_keys = .no_match });
    try testing.expectEqual(@as(usize, 3), ok.len);
    // an indicator may not take a column's name
    try testing.expectError(error.DuplicateColumn, df.join(a, nl, r, .{ .on = "k", .indicator = "v" }));
    const m = try df.join(a, nl, r, .{ .on = "k", .how = .left, .indicator = "_merge" });
    try testing.expectEqualStrings("both", m.cell(2, "_merge").?.text);
}

test "unpivot: numbers of different kinds meet in a supertype, differing zones leave none (verbs d)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{ .{ .name = "i", .type = .int }, .{ .name = "x", .type = .float } }, &.{&.{ i(1), .{ .float = 2.5 } }});
    const u = try df.unpivot(a, f, .{ .id_cols = &.{} });
    try testing.expectEqual(df.ColumnType.float, u.columnType("value").?);
    const z = try st.mk(a, &.{
        .{ .name = "p", .type = .timestamp, .time_zone = "Europe/Prague" },
        .{ .name = "n", .type = .timestamp, .time_zone = "America/New_York" },
    }, &.{&.{ i(0), i(0) }});
    const uz = try df.unpivot(a, z, .{ .id_cols = &.{} });
    try testing.expect(uz.columns[1].time_zone == null);
    const same_zone = try st.mk(a, &.{
        .{ .name = "p", .type = .timestamp, .time_zone = "Europe/Prague" },
        .{ .name = "q", .type = .timestamp, .time_zone = "Europe/Prague" },
    }, &.{&.{ i(0), i(0) }});
    const us = try df.unpivot(a, same_zone, .{ .id_cols = &.{} });
    try testing.expectEqualStrings("Europe/Prague", us.columns[1].time_zone.?);
}

test "window: transform with a mapping, reverse with a time op and a bad option on an empty table (window a, b, d, c)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{ .{ .name = "t", .type = .int }, .{ .name = "x", .type = .float } }, &.{ &.{ i(1), .{ .float = 1 } }, &.{ i(2), .{ .float = 2 } } });
    try testing.expectError(error.BadOption, df.window(a, f, .{ .value_col = "x", .out = "o", .op = .{ .transform = .{ .func = .sum } }, .mapping = .join }));
    try testing.expectError(error.BadOption, df.window(a, f, .{ .value_col = "x", .out = "o", .op = .{ .ewm_by = .{ .time_col = "t", .half_life = 1 } }, .reverse = true }));
    const empty = try st.mk(a, &.{ .{ .name = "t", .type = .int }, .{ .name = "x", .type = .float } }, &.{});
    try testing.expectError(error.InvalidDecay, df.window(a, empty, .{ .value_col = "x", .out = "o", .op = .{ .ewm_by = .{ .time_col = "t", .half_life = 0 } } }));
    // the joined list declares its element column
    const j = try df.window(a, f, .{ .value_col = "x", .out = "o", .op = .cum_sum, .mapping = .join });
    try testing.expectEqual(df.ColumnType.float, j.columns[2].inner[0].type);
}

test "interpolate: a text column is refused (frameops d)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{.{ .name = "s", .type = .text }}, &.{ &.{.{ .text = "1" }}, &.{.null}, &.{.{ .text = "3" }} });
    try testing.expectError(error.BadArgument, df.interpolate(a, f, .{ .col = "s" }));
}

test "writeJson: double_precision past 15 is BadOptions (jsonio d)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.{ .float = 0.5 }}});
    var aw: std.Io.Writer.Allocating = .init(a);
    try testing.expectError(error.BadOptions, df.writeJsonOpts(a, &aw.writer, f, .records, .{ .double_precision = 16 }));
    try df.writeJsonOpts(a, &aw.writer, f, .records, .{ .double_precision = 15 });
}

test "scaleDuration carries the calendar days (W10 a)" {
    const d = @import("dtfn.zig");
    const s = d.scaleDuration(.{ .days = 2, .us = 5 }, 3).?;
    try testing.expectEqual(@as(i64, 6), s.days);
    try testing.expectEqual(@as(i64, 15), s.us);
}

test "binIntervals: no float breakpoints for an instant, no equal-width bins over inf (W10 b)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const ts = try st.mk(a, &.{.{ .name = "t", .type = .timestamp }}, &.{ &.{i(1)}, &.{i(5)} });
    try testing.expectError(error.BadEdges, df.binIntervals(a, ts, .{ .col = "t", .out = "b", .breaks = .{ .at = &.{.{ .float = 2.5 }} } }));
    const ok = try df.binIntervals(a, ts, .{ .col = "t", .out = "b", .breaks = .{ .at = &.{i(2)} } });
    try testing.expectEqual(@as(i64, 1), ok.cell(1, "b").?.int);
    const fl = try st.mk(a, &.{.{ .name = "x", .type = .float }}, &.{ &.{.{ .float = 1 }}, &.{.{ .float = std.math.inf(f64) }} });
    try testing.expectError(error.BadEdges, df.binIntervals(a, fl, .{ .col = "x", .out = "b", .breaks = .{ .count = 3 } }));
}

test "formatTo: a frame claiming more rows than an index holds is refused (no-panic e)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const base = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{&.{i(1)}});
    const huge: Frame = .{ .columns = base.columns, .data = base.data, .len = @as(usize, 1) << 40 };
    var aw: std.Io.Writer.Allocating = .init(a);
    try testing.expectError(error.OutOfMemory, df.formatTo(a, &aw.writer, huge, .{ .max_rows = std.math.maxInt(usize) }));
}

test "explodeAll takes only the columns explode takes (layer e)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .list }, .{ .name = "y", .type = .int } }, &.{ &.{ .null, i(1) }, &.{ .null, i(2) } });
    const g = try df.explodeAll(a, f);
    try testing.expectEqual(@as(usize, 2), g.len);
}

test "fillNull mean keeps a timestamp, fills no bool; scatter refuses another kind (review leftovers)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{ .{ .name = "t", .type = .timestamp }, .{ .name = "b", .type = .bool } }, &.{ &.{ i(10), .{ .bool = true } }, &.{ .null, .null }, &.{ i(20), .{ .bool = false } } });
    const g = try df.fillNull(a, f, .{ .strategy = .mean });
    try testing.expectEqual(df.ColumnType.timestamp, g.columnType("t").?);
    try testing.expectEqual(@as(i64, 15), g.cell(1, "t").?.int);
    try testing.expectEqual(df.ColumnType.bool, g.columnType("b").?);
    try testing.expect(g.cell(1, "b").? == .null);
    const ints = try st.mk(a, &.{.{ .name = "n", .type = .int }}, &.{&.{i(1)}});
    try testing.expectError(error.BadArgument, df.scatter(a, ints, .{ .col = "n", .idx = &.{0}, .values = &.{.{ .text = "x" }} }));
    const ok = try df.scatter(a, ints, .{ .col = "n", .idx = &.{0}, .values = &.{i(7)} });
    try testing.expectEqual(@as(i64, 7), ok.cell(0, "n").?.int);
}

test "pivotMany: more aggs than values is refused; glimpse labels zoned and nested columns (layer i, f)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{ .{ .name = "r", .type = .int }, .{ .name = "c", .type = .text }, .{ .name = "v", .type = .int } }, &.{&.{ i(1), .{ .text = "a" }, i(2) }});
    try testing.expectError(error.BadArgument, df.pivotMany(a, f, .{ .row_key = "r", .col_key = "c", .values = &.{"v"}, .aggs = &.{ .sum, .max } }));
    const z = try st.mk(a, &.{.{ .name = "t", .type = .timestamp, .time_zone = "Europe/Prague" }}, &.{&.{i(0)}});
    const text = try df.glimpse(a, z, .{});
    try testing.expect(std.mem.find(u8, text, "<datetime[μs, Europe/Prague]>") != null);
}

test "dt_combine reads a time-of-day column as the time of day (time-of-day b)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try st.mk(a, &.{ .{ .name = "d", .type = .date }, .{ .name = "t", .type = .time } }, &.{&.{ i(19_000 * 86_400_000_000), i(3_600_000_000) }});
    const d = try a.create(df.Expr);
    d.* = .{ .col = "d" };
    const t = try a.create(df.Expr);
    t.* = .{ .col = "t" };
    const g = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .dt_combine = .{ .date = d, .time = t } } }});
    const day_us: i64 = 86_400_000_000;
    try testing.expectEqual(@as(i64, 19_000 * day_us + 3_600_000_000), g.cell(0, "o").?.int);
}
