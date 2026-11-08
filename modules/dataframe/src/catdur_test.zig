// SPDX-License-Identifier: MIT
//! Categorical and duration columns (survey rows 100, 101). Expected values from
//! polars 2.1.0 and pandas 3.1.0 run on the same cells (2026-11-08): polars' JSON
//! duration text (`PT93784.5S`, `-PT90S`, `P0D`) and display (`1d 2h 3m 4s 500ms`),
//! pandas' CSV timedelta text (`1 days 02:03:04.500000`, `-1 days +23:58:30`), pandas'
//! `cat.codes` (lexical categories, null -1 there, null here), both engines' lexical
//! sort of a categorical, `ts - ts` a duration and `total_seconds` truncating.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;

fn txt(s: []const u8) Value {
    return .{ .text = s };
}

fn int(i: i64) Value {
    return .{ .int = i };
}

const us: i64 = df.timestamp_units_per_second;

/// Same rows, same names, same cells (types aside: an encoded column keeps its tag).
fn expectSameCells(want: df.Frame, got: df.Frame) !void {
    try testing.expectEqual(want.len, got.len);
    try testing.expectEqual(want.columns.len, got.columns.len);
    for (want.columns, got.columns, 0..) |w, g, ci| {
        try testing.expectEqualStrings(w.name, g.name);
        for (0..want.len) |ri| {
            if (!st.same(want.columnAt(ci).get(ri), got.columnAt(ci).get(ri))) {
                std.debug.print("column {s} row {d}: {any} vs {any}\n", .{ w.name, ri, want.columnAt(ci).get(ri), got.columnAt(ci).get(ri) });
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "parseDurationCell: ISO 8601 and pandas' timedelta text" {
    const day = 86_400 * us;
    try testing.expectEqual(@as(?i64, 93_784 * us + 500_000), df.parseDurationCell("PT93784.5S"));
    try testing.expectEqual(@as(?i64, -90 * us), df.parseDurationCell("-PT90S"));
    try testing.expectEqual(@as(?i64, 0), df.parseDurationCell("P0D"));
    try testing.expectEqual(@as(?i64, 1 * day + 2 * 3600 * us + 3 * 60 * us + 4 * us), df.parseDurationCell("P1DT2H3M4S"));
    try testing.expectEqual(@as(?i64, 14 * day), df.parseDurationCell("P2W"));
    try testing.expectEqual(@as(?i64, 1 * day + 2 * 3600 * us + 3 * 60 * us + 4 * us + 500_000), df.parseDurationCell("1 days 02:03:04.500000"));
    try testing.expectEqual(@as(?i64, -90 * us), df.parseDurationCell("-1 days +23:58:30.000000"));
    try testing.expectEqual(@as(?i64, 0), df.parseDurationCell("0 days 00:00:00"));
    try testing.expectEqual(@as(?i64, -(3600 + 1) * us), df.parseDurationCell("-01:00:01"));
    try testing.expectEqual(@as(?i64, 1), df.parseDurationCell("PT0.0000019S")); // past the sixth digit: truncated
    // Refused: calendar units, a unit out of order or twice, a fraction not on seconds,
    // `PT` with nothing, junk, past i64.
    for ([_][]const u8{ "P1Y", "P1M", "PT1M1H", "P1D1D", "PT1.5H", "PT", "P", "", "-", "1 dey", "1 days 1:2", "12:60:00", "PT9223372036855S", "P1DX" }) |bad| {
        if (df.parseDurationCell(bad)) |v| {
            std.debug.print("accepted {s} as {d}\n", .{ bad, v });
            return error.TestUnexpectedResult;
        }
    }
}

test "formatIsoDuration and formatDuration: polars' JSON and display forms, round trip" {
    var b: [df.max_duration_len]u8 = undefined;
    const d = 93_784 * us + 500_000;
    try testing.expectEqualStrings("PT93784.5S", df.formatIsoDuration(&b, d));
    try testing.expectEqualStrings("-PT90S", df.formatIsoDuration(&b, -90 * us));
    try testing.expectEqualStrings("P0D", df.formatIsoDuration(&b, 0));
    try testing.expectEqualStrings("1d 2h 3m 4s 500ms", df.formatDuration(&b, d));
    try testing.expectEqualStrings("-1m -30s", df.formatDuration(&b, -90 * us));
    try testing.expectEqualStrings("0µs", df.formatDuration(&b, 0));
    try testing.expectEqualStrings("1ms 500µs", df.formatDuration(&b, 1500));
    // Every i64, the extremes included, reads back from its ISO form.
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    const edge = [_]i64{ std.math.minInt(i64), std.math.maxInt(i64), -1, 1, std.math.minInt(i64) + 1 };
    for (0..20_000) |i| {
        const x: i64 = if (i < edge.len) edge[i] else r.int(i64) >> @intCast(r.uintLessThan(u8, 63));
        const back = df.parseDurationCell(df.formatIsoDuration(&b, x));
        if (back != x) {
            std.debug.print("{d} -> {s} -> {any}\n", .{ x, df.formatIsoDuration(&b, x), back });
            return error.TestUnexpectedResult;
        }
        _ = df.formatDuration(&b, x); // fits the buffer
    }
}

test "cast to categorical: lexical dictionary, pandas' codes, nulls, cells read as text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "c", .type = .text }}, &.{ &.{txt("b")}, &.{txt("a")}, &.{.null}, &.{txt("b")} });
    const g = try df.cast(a, f, .{ .col = "c", .to = .categorical });
    try testing.expectEqual(df.ColumnType.categorical, g.columnType("c").?);
    const col = g.column("c").?;
    try testing.expect(col == .categorical);
    const cc = col.categorical;
    try testing.expectEqual(@as(usize, 3), cc.dict.offsets.len); // "a", "b"
    try testing.expectEqualStrings("a", cc.dict.at(0).?);
    try testing.expectEqualStrings("b", cc.dict.at(1).?);
    try testing.expectEqual(@as(u32, 1), cc.codes.values[0]);
    try testing.expectEqual(@as(u32, 0), cc.codes.values[1]);
    try testing.expect(!cc.codes.isValid(2));
    try testing.expectEqual(@as(u32, 1), cc.codes.values[3]);
    try st.expectCol(g, "c", &.{ txt("b"), txt("a"), .null, txt("b") });
    // Numbers cast print first, then encode (pandas `astype("category")` keeps numbers;
    // a categorical here is text).
    const n = try st.mk(a, &.{.{ .name = "n", .type = .int }}, &.{ &.{int(10)}, &.{int(9)}, &.{int(10)} });
    const nc = try df.cast(a, n, .{ .col = "n", .to = .categorical });
    try st.expectCol(nc, "n", &.{ txt("10"), txt("9"), txt("10") });
    try testing.expectEqualStrings("10", nc.column("n").?.categorical.dict.at(0).?); // lexical: "10" < "9"
    // Back to text: plain text storage.
    const back = try df.cast(a, g, .{ .col = "c", .to = .text });
    try testing.expect(back.column("c").? == .text);
    try st.expectCol(back, "c", &.{ txt("b"), txt("a"), .null, txt("b") });
}

test "categorical through take, filter, sort, concat, group, join and the writers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try st.mk(a, &.{ .{ .name = "c", .type = .text }, .{ .name = "v", .type = .int } }, &.{
        &.{ txt("b"), int(1) }, &.{ txt("a"), int(2) }, &.{ .null, int(3) }, &.{ txt("b"), int(4) },
    });
    const f = try df.cast(a, raw, .{ .col = "c", .to = .categorical });

    // take: codes gathered, dictionary shared.
    const t = try df.take(a, f, &.{ 3, 1 });
    try testing.expect(t.column("c").? == .categorical);
    try testing.expectEqual(f.column("c").?.categorical.dict.bytes.ptr, t.column("c").?.categorical.dict.bytes.ptr);
    try st.expectCol(t, "c", &.{ txt("b"), txt("a") });

    // sort: lexical, as both engines (polars puts the null first, pandas last; the
    // module's text rule decides, the same as for a text column).
    const s = try df.sort(a, f, .{ .key = "c" });
    const s_text = try df.sort(a, raw, .{ .key = "c" });
    for (0..f.len) |ri| try testing.expect(st.same(s.cell(ri, "c").?, s_text.cell(ri, "c").?));

    // group, distinct and join on the encoded column answer what they answer on the text.
    const aggs: []const df.AggCol = &.{.{ .src = "v", .out = "s", .func = .sum }};
    try expectSameCells(try df.aggregate(a, raw, .{ .group_by = &.{"c"}, .aggs = aggs }), try df.aggregate(a, f, .{ .group_by = &.{"c"}, .aggs = aggs }));
    try expectSameCells(try df.distinct(a, raw, .{ .keys = &.{"c"} }), try df.distinct(a, f, .{ .keys = &.{"c"} }));
    const right = try st.mk(a, &.{ .{ .name = "c", .type = .text }, .{ .name = "w", .type = .int } }, &.{ &.{ txt("b"), int(9) }, &.{ txt("z"), int(8) } });
    const right_cat = try df.cast(a, right, .{ .col = "c", .to = .categorical });
    for ([_]df.JoinHow{ .inner, .left }) |how| {
        const want = try df.join(a, raw, right, .{ .on = "c", .how = how });
        try expectSameCells(want, try df.join(a, f, right, .{ .on = "c", .how = how }));
        try expectSameCells(want, try df.join(a, f, right_cat, .{ .on = "c", .how = how }));
    }

    // concat: encoded again over the union of values.
    const g = try st.mk(a, &.{ .{ .name = "c", .type = .text }, .{ .name = "v", .type = .int } }, &.{&.{ txt("c"), int(5) }});
    const gc = try df.cast(a, g, .{ .col = "c", .to = .categorical });
    const cat = try df.concat(a, &.{ f, gc }, .vertical);
    try testing.expectEqual(df.ColumnType.categorical, cat.columnType("c").?);
    try testing.expect(cat.column("c").? == .categorical);
    try testing.expectEqual(@as(usize, 4), cat.column("c").?.categorical.dict.offsets.len); // a b c
    try st.expectCol(cat, "c", &.{ txt("b"), txt("a"), .null, txt("b"), txt("c") });

    // A frame declaring a column categorical over plain text storage (`FrameBuilder`):
    // `concat`'s typed path stacks the text, then encodes it as the cell path does (the
    // fuzz driver found the typed path leaving it text, 2026-11-08, seed 5426).
    const decl = try st.mk(a, &.{.{ .name = "c", .type = .categorical }}, &.{ &.{txt("y")}, &.{txt("x")} });
    try testing.expect(decl.column("c").? == .text);
    const both = try df.concat(a, &.{ decl, decl }, .vertical);
    try testing.expect(both.column("c").? == .categorical);
    try st.expectCol(both, "c", &.{ txt("y"), txt("x"), txt("y"), txt("x") });

    // CSV and JSON write it as text, `format` renders it as text.
    var buf: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &buf.writer, f, .{});
    try testing.expectEqualStrings("c,v\nb,1\na,2\n,3\nb,4\n", buf.written());
    var jb: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&jb.writer, f, .records);
    try testing.expectEqualStrings("[{\"c\":\"b\",\"v\":1},{\"c\":\"a\",\"v\":2},{\"c\":null,\"v\":3},{\"c\":\"b\",\"v\":4}]", jb.written());

    // readCsv with a `types` entry stores it encoded.
    const rd = try df.readCsv(a, "c,v\nb,1\na,2\n,3\nb,4\n", .{ .types = &.{.{ .name = "c", .type = .categorical }} });
    try testing.expect(rd.column("c").? == .categorical);
    try st.expectCol(rd, "c", &.{ txt("b"), txt("a"), .null, txt("b") });
    const rj = try df.readJson(a, "[{\"c\":\"b\"},{\"c\":\"a\"}]", .{ .types = &.{.{ .name = "c", .type = .categorical }} });
    try testing.expect(rj.column("c").? == .categorical);
    try st.expectCol(rj, "c", &.{ txt("b"), txt("a") });

    // mutate with a declared categorical output encodes it.
    const x: df.Expr = .{ .col = "c" };
    const m = try df.mutate(a, raw, &.{.{ .out = "d", .expr = x, .type = .categorical }});
    try testing.expect(m.column("d").? == .categorical);
    try st.expectCol(m, "d", &.{ txt("b"), txt("a"), .null, txt("b") });
}

test "duration: ts - ts, ts + dur, total_*, cast, writers and reader" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t0 = df.parseIsoTimestamp("2024-01-01T00:00:00Z").?;
    const t1 = df.parseIsoTimestamp("2024-01-02T03:00:00Z").?;
    const f = try st.mk(a, &.{ .{ .name = "a", .type = .timestamp }, .{ .name = "b", .type = .timestamp } }, &.{
        &.{ int(t1), int(t0) },
        &.{ int(t0), int(t1) },
        &.{ .null, int(t0) },
    });
    const ea: df.Expr = .{ .col = "a" };
    const eb: df.Expr = .{ .col = "b" };
    const diff: df.Expr = .{ .binary = .{ .op = .sub, .l = &ea, .r = &eb } };
    const m = try df.mutate(a, f, &.{.{ .out = "x", .expr = diff }});
    try testing.expectEqual(df.ColumnType.duration, m.columnType("x").?);
    const d = t1 - t0; // 1d 3h
    try st.expectCol(m, "x", &.{ int(d), int(-d), .null });

    // ts + dur is a timestamp; dur / 2 a duration, truncated to whole microseconds.
    const ex: df.Expr = .{ .col = "x" };
    const plus: df.Expr = .{ .binary = .{ .op = .add, .l = &ea, .r = &ex } };
    const two: df.Expr = .{ .lit = int(2) };
    const half: df.Expr = .{ .binary = .{ .op = .div, .l = &ex, .r = &two } };
    const secs: df.Expr = .{ .dt = .{ .x = &ex, .part = .total_seconds } };
    const hours: df.Expr = .{ .dt = .{ .x = &ex, .part = .total_hours } };
    const m2 = try df.mutate(a, m, &.{ .{ .out = "z", .expr = plus }, .{ .out = "h", .expr = half }, .{ .out = "s", .expr = secs }, .{ .out = "hh", .expr = hours } });
    try testing.expectEqual(df.ColumnType.timestamp, m2.columnType("z").?);
    try st.expectCol(m2, "z", &.{ int(t1 + d), int(t0 - d), .null });
    try testing.expectEqual(df.ColumnType.duration, m2.columnType("h").?);
    try st.expectCol(m2, "h", &.{ int(@divTrunc(d, 2)), int(@divTrunc(-d, 2)), .null });
    try testing.expectEqual(df.ColumnType.int, m2.columnType("s").?);
    try st.expectCol(m2, "s", &.{ int(97_200), int(-97_200), .null });
    try st.expectCol(m2, "hh", &.{ int(27), int(-27), .null });

    // A timestamp expression keeps its type (it used to come out `.int`).
    const tr: df.Expr = .{ .truncate = .{ .x = &ea, .every = "1d" } };
    const m3 = try df.mutate(a, f, &.{.{ .out = "day", .expr = tr }});
    try testing.expectEqual(df.ColumnType.timestamp, m3.columnType("day").?);

    // Writers: CSV and JSON ISO 8601 (polars' JSON form), `format` polars' display.
    const only = try df.select(a, m, &.{"x"});
    var cb: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &cb.writer, only, .{});
    try testing.expectEqualStrings("x\nPT97200S\n-PT97200S\n\"\"\n", cb.written()); // a lone null field is `""`
    var jb: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&jb.writer, only, .records);
    try testing.expectEqualStrings("[{\"x\":\"PT97200S\"},{\"x\":\"-PT97200S\"},{\"x\":null}]", jb.written());
    const shown = try df.format(a, only, .{});
    try testing.expect(std.mem.indexOf(u8, shown, "1d 3h") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "-1d -3h") != null);

    // Reader: ISO and pandas' text under a `types` entry, both back to the same cells.
    const rd = try df.readCsv(a, "x\nPT97200S\n-1 days -03:00:00\n1 days 03:00:00\n", .{ .types = &.{.{ .name = "x", .type = .duration }} });
    try testing.expectEqual(df.ColumnType.duration, rd.columnType("x").?);
    try st.expectCol(rd, "x", &.{ int(d), int(-d), int(d) });
    try testing.expectError(error.BadValue, df.readCsv(a, "x\n1 month\n", .{ .types = &.{.{ .name = "x", .type = .duration }} }));

    // cast: text parses, a duration to text is its ISO form, not its microseconds.
    const tx = try st.mk(a, &.{.{ .name = "t", .type = .text }}, &.{ &.{txt("PT1.5S")}, &.{txt("nope")} });
    const ct = try df.cast(a, tx, .{ .col = "t", .to = .duration });
    try st.expectCol(ct, "t", &.{ int(1_500_000), .null });
    const ctt = try df.cast(a, ct, .{ .col = "t", .to = .text });
    try st.expectCol(ctt, "t", &.{ txt("PT1.5S"), .null });
    try testing.expectError(error.CastFailed, df.cast(a, tx, .{ .col = "t", .to = .duration, .on_error = .fail }));
}
