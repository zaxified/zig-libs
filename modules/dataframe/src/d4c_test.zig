// SPDX-License-Identifier: MIT
//! D4-C differential tests: the typed second pass of `readCsv` (and the other kernels of
//! this wave, as they arrive) against the cell-by-cell paths they replaced
//! (`test_hooks.*Cells`), which are the specification. Seeded PRNG; outputs are compared
//! cell by cell, bit for bit, AND by storage kind and validity-bitmap presence per column.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const csvio = @import("csvio.zig");
const textio = @import("textio.zig");
const Frame = df.Frame;

// ── comparison ──────────────────────────────────────────────────────────────

fn sameCellBits(x: df.Value, y: df.Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .int => |v| v == y.int,
        .float => |v| @as(u64, @bitCast(v)) == @as(u64, @bitCast(y.float)) or (std.math.isNan(v) and std.math.isNan(y.float)),
        .bool => |v| v == y.bool,
        .decimal => |v| v == y.decimal,
        .text => |v| std.mem.eql(u8, v, y.text),
    };
}

fn validNullness(c: df.ColumnData) ?bool {
    return switch (c) {
        .nulls, .boxed => null,
        .int => |t| t.valid == null,
        .float => |t| t.valid == null,
        .bool => |t| t.valid == null,
        .decimal => |t| t.valid == null,
        .text => |t| t.valid == null,
    };
}

fn expectSameFrame(x: Frame, y: Frame) !void {
    try testing.expectEqual(x.len, y.len);
    try testing.expectEqual(x.columns.len, y.columns.len);
    for (x.columns, y.columns, 0..) |cx, cy, ci| {
        try testing.expectEqualStrings(cx.name, cy.name);
        try testing.expectEqual(cx.type, cy.type);
        const dx = x.columnAt(ci);
        const dy = y.columnAt(ci);
        testing.expectEqual(std.meta.activeTag(dx), std.meta.activeTag(dy)) catch |e| {
            std.debug.print("column {s}: storage {s} vs {s}\n", .{ cx.name, @tagName(dx), @tagName(dy) });
            return e;
        };
        try testing.expectEqual(validNullness(dx), validNullness(dy));
        for (0..x.len) |ri| {
            if (!sameCellBits(dx.get(ri), dy.get(ri))) {
                std.debug.print("column {s} row {d}: {any} vs {any}\n", .{ cx.name, ri, dx.get(ri), dy.get(ri) });
                return error.TestUnexpectedResult;
            }
        }
    }
}

fn expectSameResult(x: anytype, y: anytype) !void {
    if (x) |fx| {
        const fy = y catch |e| {
            std.debug.print("typed ok, cells error {s}\n", .{@errorName(e)});
            return error.TestUnexpectedResult;
        };
        try expectSameFrame(fx, fy);
    } else |ex| {
        if (y) |_| {
            std.debug.print("typed error {s}, cells ok\n", .{@errorName(ex)});
            return error.TestUnexpectedResult;
        } else |ey| try testing.expectEqual(ex, ey);
    }
}

// ── readCsv ─────────────────────────────────────────────────────────────────

const lens = [_]usize{ 0, 1, 2, 63, 64, 65, 1000 };
const null_pcts = [_]u8{ 0, 1, 50, 100 };

const CellKind = enum { int, float, bool, text, date, stamp, mixed, dec };

fn genToken(rng: std.Random, w: *std.ArrayList(u8), a: std.mem.Allocator, kind: CellKind, null_pct: u8) !void {
    if (rng.uintLessThan(u8, 100) < null_pct) {
        const marks = [_][]const u8{ "", "", "NA", "null", "NaN", "N/A", "None" };
        try w.appendSlice(a, marks[rng.uintLessThan(usize, marks.len)]);
        return;
    }
    const pool = [_]CellKind{ .int, .float, .bool, .text, .date, .stamp, .dec };
    const k: CellKind = if (kind == .mixed) pool[rng.uintLessThan(usize, pool.len)] else kind;
    switch (k) {
        .int => {
            const specials = [_][]const u8{ "9223372036854775807", "-9223372036854775808", "9223372036854775808", "-9223372036854775809", "+5", " 7 ", "\t-3", "00012", "-0", "+", "-", "99999999999999999999" };
            if (rng.uintLessThan(u8, 10) == 0) {
                try w.appendSlice(a, specials[rng.uintLessThan(usize, specials.len)]);
            } else try w.print(a, "{d}", .{rng.intRangeAtMost(i64, -1000, 1000)});
        },
        .float => {
            const specials = [_][]const u8{ "nan", "NaN", "inf", "-inf", "+Infinity", "-0.0", "1e308", "1e309", "-1E-5", ".5", "5.", "1e", " 2.5 ", "0x10", "1_0", "." };
            if (rng.uintLessThan(u8, 8) == 0) {
                try w.appendSlice(a, specials[rng.uintLessThan(usize, specials.len)]);
            } else try w.print(a, "{d}", .{@as(f64, @floatFromInt(rng.intRangeAtMost(i32, -400, 400))) * 0.25});
        },
        .bool => {
            const t = [_][]const u8{ "true", "false", "TRUE", "False", "tRuE", "1", "0", "yes" };
            try w.appendSlice(a, t[rng.uintLessThan(usize, t.len)]);
        },
        .text => {
            const t = [_][]const u8{ "a", "bb", "hello world", "\"x,y\"", "\"q\"\"uote\"", "\"multi\nline\"", " lead", "tail ", "é", "x" };
            try w.appendSlice(a, t[rng.uintLessThan(usize, t.len)]);
        },
        .date => {
            if (rng.uintLessThan(u8, 12) == 0) {
                const bad = [_][]const u8{ "2020-13-01", "2020-02-30", "20200101", "2020-1-1" };
                try w.appendSlice(a, bad[rng.uintLessThan(usize, bad.len)]);
            } else try w.print(a, "{d}-{d:0>2}-{d:0>2}", .{ rng.intRangeAtMost(u32, 1990, 2030), rng.intRangeAtMost(u32, 1, 12), rng.intRangeAtMost(u32, 1, 28) });
        },
        .stamp => {
            const t = [_][]const u8{ "2020-01-02T03:04:05Z", "2020-01-02 03:04:05", "2020-01-02T03:04:05.123456+02:00", "2020-01-02", "garbage" };
            try w.appendSlice(a, t[rng.uintLessThan(usize, t.len)]);
        },
        .dec => {
            const t = [_][]const u8{ "1.5", "-2.25", "100", "0.000000000001", "1.0000000000001", "+3.", "abc", "123456789012345678901234567890" };
            try w.appendSlice(a, t[rng.uintLessThan(usize, t.len)]);
        },
        .mixed => unreachable,
    }
}

const ncols = 8;

fn genCsv(rng: std.Random, a: std.mem.Allocator, n: usize, null_pct: u8, kinds: [ncols]CellKind, ragged: bool, crlf: bool) ![]const u8 {
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, "c0,c1,c2,c3,c4,c5,c6,c7");
    try w.appendSlice(a, if (crlf) "\r\n" else "\n");
    for (0..n) |_| {
        const upto: usize = if (ragged and rng.uintLessThan(u8, 10) == 0) rng.uintLessThan(usize, ncols) else ncols;
        for (0..upto) |c| {
            if (c != 0) try w.append(a, ',');
            // A short row ends here; an all-null column stays all null.
            try genToken(rng, &w, a, kinds[c], null_pct);
        }
        try w.appendSlice(a, if (crlf) "\r\n" else "\n");
    }
    return w.items;
}

test "d4c read_csv: typed second pass equals the cell path" {
    var prng = std.Random.DefaultPrng.init(0xd4c0_0001);
    const rng = prng.random();
    var errors: usize = 0;
    var trial: usize = 0;
    while (trial < 1200) : (trial += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const n = lens[rng.uintLessThan(usize, lens.len)];
        var kinds: [ncols]CellKind = undefined;
        for (&kinds) |*k| k.* = @fromBackingInt(@intCast(rng.uintLessThan(u8, 8)));
        // Make int/float/text columns common so most trials are not all text.
        if (rng.boolean()) {
            kinds[0] = .int;
            kinds[1] = .float;
            kinds[2] = .text;
        }
        const csv = try genCsv(rng, a, n, null_pcts[rng.uintLessThan(usize, null_pcts.len)], kinds, rng.boolean(), rng.boolean());
        var opts: csvio.CsvReadOptions = .{};
        opts.parse_dates = rng.boolean();
        opts.infer_types = rng.uintLessThan(u8, 8) != 0;
        opts.truncate_ragged = rng.boolean();
        opts.strict_quotes = rng.uintLessThan(u8, 4) != 0;
        if (rng.uintLessThan(u8, 4) == 0) opts.null_values = &csvio.polars_na_values;
        if (rng.uintLessThan(u8, 6) == 0) opts.n_rows = rng.uintLessThan(usize, n + 2);
        if (rng.uintLessThan(u8, 6) == 0) opts.columns = &.{ "c5", "c1", "c0" };
        if (rng.uintLessThan(u8, 40) == 0) opts.columns = &.{};
        const ov = [_]csvio.TypeOverride{
            .{ .name = "c0", .type = .float },
            .{ .name = "c1", .type = .decimal },
            .{ .name = "c2", .type = .timestamp },
            .{ .name = "c3", .type = .date },
            .{ .name = "c4", .type = .int },
            .{ .name = "c6", .type = .bool },
            .{ .name = "c7", .type = .text },
        };
        if (rng.uintLessThan(u8, 3) == 0) {
            const from = rng.uintLessThan(usize, ov.len);
            opts.types = ov[from .. from + 1 + rng.uintLessThan(usize, ov.len - from)];
        }
        const typed = csvio.readCsv(a, csv, opts);
        const cells = csvio.test_hooks.readCsvCells(a, csv, opts);
        if (typed) |_| {} else |_| errors += 1;
        expectSameResult(typed, cells) catch |e| {
            std.debug.print("trial {d} n={d} opts parse_dates={} infer={} types={d}\n{s}\n", .{ trial, n, opts.parse_dates, opts.infer_types, opts.types.len, csv[0..@min(csv.len, 600)] });
            return e;
        };
    }
    // Both outcomes must be exercised, and the one-pass reader both finishing and giving up.
    try testing.expect(errors > 20 and errors < 1100);
    try testing.expect(csvio.test_hooks.spec_done > 200);
    try testing.expect(csvio.test_hooks.spec_gave_up > 100);
}

test "d4c read_csv: header-less, odd delimiters and the empty file" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inputs = [_][]const u8{ "", "\n", "a,b\n", "a,b\n,\n", "1,2\n3,4\n", "x;y\n1;\n;2\n", "\xEF\xBB\xBFa\n1\n" };
    const optsets = [_]csvio.CsvReadOptions{ .{}, .{ .has_header = false }, .{ .delimiter = ';' }, .{ .quote = 0 }, .{ .names = &.{ "p", "q" } } };
    for (inputs) |inp| for (optsets) |o| {
        try expectSameResult(csvio.readCsv(a, inp, o), csvio.test_hooks.readCsvCells(a, inp, o));
    };
}

test "d4c read_csv: fastInt and the null prefilter equal the code they replaced" {
    var prng = std.Random.DefaultPrng.init(0xd4c0_0002);
    const rng = prng.random();
    var buf: [24]u8 = undefined;
    const alphabet = "0123456789+-. \tNAnulN/e";
    var i: usize = 0;
    while (i < 200_000) : (i += 1) {
        const len = rng.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*c| c.* = if (rng.uintLessThan(u8, 3) == 0) alphabet[rng.uintLessThan(usize, alphabet.len)] else '0' + rng.uintLessThan(u8, 10);
        if (len > 0 and rng.uintLessThan(u8, 4) == 0) buf[0] = if (rng.boolean()) '-' else '+';
        const t = buf[0..len];
        const want: ?i64 = if (textio.isIntGrammar(t)) (std.fmt.parseInt(i64, t, 10) catch null) else null;
        try testing.expectEqual(want, csvio.test_hooks.fastInt(t));
        for ([_]*const csvio.CsvReadOptions{ &.{}, &.{ .null_values = &csvio.polars_na_values }, &.{ .null_values = &.{ "x", "a-long-marker-of-many-bytes" } } }) |o| {
            try testing.expectEqual(csvio.test_hooks.isNullSlow(o, t), csvio.test_hooks.isNullFast(o, t));
        }
    }
    for ([_][]const u8{ "NA", "N/A", "#N/A N/A", "-1.#QNAN", "null", "NULL", "", "nan", "NaN", "none" }) |t| {
        try testing.expectEqual(csvio.test_hooks.isNullSlow(&.{}, t), csvio.test_hooks.isNullFast(&.{}, t));
    }
    const long = "x" ++ "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"[0..69];
    const lo: csvio.CsvReadOptions = .{ .null_values = &.{long} };
    try testing.expect(csvio.test_hooks.isNullFast(&lo, long));
    try testing.expect(!csvio.test_hooks.isNullFast(&lo, long ++ "y"));
}

test "d4c read_csv: fastFloat is parseFloat where it answers, and newlines are counted" {
    var prng = std.Random.DefaultPrng.init(0xd4c0_0003);
    const rng = prng.random();
    var buf: [24]u8 = undefined;
    const alphabet = "0123456789.+-eE ";
    var answered: usize = 0;
    var i: usize = 0;
    while (i < 400_000) : (i += 1) {
        const len = rng.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*c| c.* = if (rng.uintLessThan(u8, 5) == 0) alphabet[rng.uintLessThan(usize, alphabet.len)] else '0' + rng.uintLessThan(u8, 10);
        if (len > 2 and rng.uintLessThan(u8, 2) == 0) buf[rng.uintLessThan(usize, len)] = '.';
        const t = buf[0..len];
        const got = csvio.test_hooks.fastFloat(t) orelse continue;
        answered += 1;
        // It answers only inside the grammar, and then as the general parser.
        try testing.expect(textio.isFloatGrammar(t));
        const want = textio.parseFloatToken(t).?;
        try testing.expectEqual(@as(u64, @bitCast(want)), @as(u64, @bitCast(got)));
    }
    try testing.expect(answered > 10_000);
    for ([_][]const u8{ "-0.0", "-0", "+.5", "5.", "0.1", "123456789012345", "1234567890123456", "0.000000000000001", "9007199254740993", "-.0" }) |t| {
        if (csvio.test_hooks.fastFloat(t)) |g| try testing.expectEqual(@as(u64, @bitCast(textio.parseFloatToken(t).?)), @as(u64, @bitCast(g)));
    }
    var nl: [200]u8 = undefined;
    for (0..300) |_| {
        const len = rng.uintLessThan(usize, nl.len);
        var want: usize = 0;
        for (nl[0..len]) |*c| {
            c.* = if (rng.boolean()) '\n' else 'x';
            want += @intFromBool(c.* == '\n');
        }
        try testing.expectEqual(want, csvio.test_hooks.countNewlines(nl[0..len]));
    }
}
