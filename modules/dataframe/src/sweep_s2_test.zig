// SPDX-License-Identifier: MIT
//! The D5 no-panic sweep over `expr exprfn window more analysis csvio jsonio textio render
//! dtfn seriesfn` (2026-11-08): each finding's trigger, pinned. Names end "(sweep <ID>)".

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const csvio = @import("csvio.zig");
const expr = @import("expr.zig");
const exprfn = @import("exprfn.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;

// ── S2-1: the speculative CSV reader sized its arrays from the newline count ─────

test "a header of wide columns over blank lines does not reserve rows x columns (sweep S2-1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const w = 3000;
    var csv: std.ArrayList(u8) = .empty;
    for (0..w) |i| try csv.print(a, "{s}c{d}", .{ if (i == 0) "" else ",", i });
    try csv.append(a, '\n');
    for (0..w) |i| try csv.print(a, "{s}1", .{if (i == 0) "" else ","});
    try csv.append(a, '\n');
    // One real row, then thousands of blank lines: `lines + 1` rows were reserved for each column.
    for (0..w) |_| try csv.append(a, '\n');
    const before = arena.queryCapacity();
    const f = try df.readCsv(a, csv.items, .{});
    try testing.expectEqual(@as(usize, 1), f.len);
    try testing.expectEqual(@as(usize, w), f.columns.len);
    try testing.expectEqual(@as(i64, 1), f.cell(0, "c7").?.int);
    // The input is ~24 KB; the result needs ~100 KB. The guess was 3000 x 3000 x 8 = 72 MB.
    try testing.expect(arena.queryCapacity() - before < 4 * 1024 * 1024);
}

test "a file that fills its guess is still read in one pass (sweep S2-1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const done = csvio.test_hooks.spec_done;
    const f = try df.readCsv(a, "a,b,c\n1,2,3\n4,5,6\n7,8,9\n", .{});
    try testing.expectEqual(@as(usize, 3), f.len);
    try testing.expect(csvio.test_hooks.spec_done > done);
}

// ── S2-3: fillNull left validity bits set past the last row ──────────────────────

test "fillNull keeps no validity bit past the last row of its input (sweep S2-3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 70 rows; row 0 is null (it has nothing before it to be filled from), and the input's last
    // word carries garbage past row 69, as a hand-built or foreign bitmap may.
    const vals = try a.alloc(f64, 70);
    for (vals, 0..) |*v, i| v.* = @floatFromInt(i);
    const valid = try a.dupe(u64, &.{ ~@as(u64, 1), ~@as(u64, 0) });
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .float }});
    const data = try a.dupe(df.ColumnData, &.{.{ .float = .{ .values = vals, .valid = valid } }});
    const f: Frame = .{ .columns = cols, .data = data, .len = 70 };
    const out = try df.fillNull(a, f, .{ .strategy = .forward });
    const got = out.columnAt(0).float.valid.?;
    try testing.expectEqual(~@as(u64, 1), got[0]);
    try testing.expectEqual(@as(u64, (1 << 6) - 1), got[1]);
}

// ── S2-2: the window work cap held per partition, not per call ───────────────────

fn groupedFrame(a: std.mem.Allocator, groups: usize, per: usize) !Frame {
    const n = groups * per;
    const g = try a.alloc(i64, n);
    const v = try a.alloc(f64, n);
    const t = try a.alloc(i64, n);
    for (0..n) |i| {
        g[i] = @intCast(i / per);
        v[i] = @floatFromInt(i % 97);
        t[i] = @intCast(i % per);
    }
    const cols = try a.dupe(Column, &.{ .{ .name = "g", .type = .int }, .{ .name = "v", .type = .float }, .{ .name = "t", .type = .int } });
    const data = try a.dupe(df.ColumnData, &.{
        .{ .int = .{ .values = g } },
        .{ .float = .{ .values = v } },
        .{ .int = .{ .values = t } },
    });
    return .{ .columns = cols, .data = data, .len = n };
}

test "rolling over many partitions is capped as a whole (sweep S2-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 18 partitions of 8192 rows with a window of 8192: 18 x 2^26 > 2^30 visits, each partition 2^26.
    const f = try groupedFrame(a, 18, 8192);
    try testing.expectError(error.TooLarge, df.window(a, f, .{
        .value_col = "v",
        .out = "r",
        .op = .{ .rolling = .{ .window = 8192, .func = .min } },
        .partition_by = &.{"g"},
    }));
    // The cell path agrees.
    try testing.expectError(error.TooLarge, @import("window.zig").test_hooks.windowCells(a, f, .{
        .value_col = "v",
        .out = "r",
        .op = .{ .rolling = .{ .window = 8192, .func = .min } },
        .partition_by = &.{"g"},
    }));
    // Fewer partitions are fine.
    const ok = try groupedFrame(a, 2, 4096);
    _ = try df.window(a, ok, .{ .value_col = "v", .out = "r", .op = .{ .rolling = .{ .window = 4096, .func = .min } }, .partition_by = &.{"g"} });
}

test "expanding over many partitions is capped as a whole (sweep S2-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try groupedFrame(a, 18, 8192);
    try testing.expectError(error.TooLarge, df.window(a, f, .{
        .value_col = "v",
        .out = "r",
        .op = .{ .expanding = .{ .func = .first } },
        .partition_by = &.{"g"},
    }));
}

test "rolling_time over many partitions is capped as a whole (sweep S2-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 5 partitions of 24000 rows, a period that reaches back to the first row: 5 x ~2.9e8 > 2^30.
    const f = try groupedFrame(a, 5, 24000);
    try testing.expectError(error.TooLarge, df.window(a, f, .{
        .value_col = "v",
        .out = "r",
        .op = .{ .rolling_time = .{ .time_col = "t", .period = std.math.maxInt(i64), .func = .sum } },
        .partition_by = &.{"g"},
    }));
}

// ── S2-4: a column of cells could allocate without bound ─────────────────────────

test "repeat over many cells is capped as a whole (sweep S2-4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = try a.alloc([]const Value, 12);
    for (rows) |*r| {
        const cell = try a.alloc(Value, 2);
        cell[0] = .{ .text = "x" };
        cell[1] = .{ .int = 1 << 20 }; // 1 MiB per cell, under `max_text_result`
        r.* = cell;
    }
    const f = try st.mk(a, &.{ .{ .name = "s", .type = .text }, .{ .name = "n", .type = .int } }, rows);
    const rep: df.Expr = .{ .binary = .{ .op = .repeat, .l = &.{ .col = "s" }, .r = &.{ .col = "n" } } };
    expr.test_hooks.eval_limit = 4 << 20; // 12 MiB asked, 4 MiB allowed
    defer expr.test_hooks.eval_limit = null;
    try testing.expectError(error.TooLarge, df.mutate(a, f, &.{.{ .out = "r", .expr = rep }}));
    const len: df.Expr = .{ .unary = .{ .op = .length, .x = &rep } };
    const pred: df.Expr = .{ .binary = .{ .op = .gt, .l = &len, .r = &.{ .lit = .{ .int = 0 } } } };
    try testing.expectError(error.TooLarge, df.where(a, f, &pred));
    // Within the budget the same expression works.
    expr.test_hooks.eval_limit = 64 << 20;
    const g = try df.mutate(a, f, &.{.{ .out = "r", .expr = rep }});
    try testing.expectEqual(@as(usize, 1 << 20), g.cell(11, "r").?.text.len);
}

// ── S2-5: substring search was O(text x needle) with a needle that is a cell ─────

test "contains, find, rfind and count_matches with a long needle are linear (sweep S2-5)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hay = try a.alloc(u8, 120_000);
    @memset(hay, 'a');
    const needle = try a.alloc(u8, 60_001);
    @memset(needle, 'a');
    needle[needle.len - 1] = 'b'; // never found, after 60 000 matching bytes at every start
    const t0 = std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
    try testing.expectEqual(@as(?usize, null), try exprfn.findIn(a, hay, needle));
    try testing.expectEqual(@as(?usize, null), try exprfn.findLastIn(a, hay, needle));
    try testing.expectEqual(@as(usize, 0), try exprfn.countMatchesIn(a, hay, needle));
    const ms = @divFloor(std.Io.Timestamp.now(testing.io, .awake).nanoseconds - t0, std.time.ns_per_ms);
    try testing.expect(ms < 1000);
}

test "the long-needle search agrees with std.mem on random text (sweep S2-5)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    for (0..400) |_| {
        const hn = r.uintLessThan(usize, 600);
        const pn = r.uintLessThan(usize, 200);
        const h = try a.alloc(u8, hn);
        const p = try a.alloc(u8, pn);
        // A two-letter alphabet makes matches and near-matches common.
        for (h) |*c| c.* = 'a' + r.uintLessThan(u8, 2);
        for (p) |*c| c.* = 'a' + r.uintLessThan(u8, 2);
        if (pn > 0 and r.boolean() and hn >= pn) @memcpy(h[hn - pn ..], p); // a match at the end
        try testing.expectEqual(std.mem.find(u8, h, p), try exprfn.findIn(a, h, p));
        try testing.expectEqual(std.mem.findLast(u8, h, p), try exprfn.findLastIn(a, h, p));
        try testing.expectEqual(exprfn.countMatches(h, p), try exprfn.countMatchesIn(a, h, p));
    }
    // A needle past `long_needle` that occurs, overlapping itself.
    const h = try a.alloc(u8, 500);
    @memset(h, 'a');
    const p = try a.alloc(u8, 100);
    @memset(p, 'a');
    try testing.expectEqual(@as(?usize, 0), try exprfn.findIn(a, h, p));
    try testing.expectEqual(@as(?usize, 400), try exprfn.findLastIn(a, h, p));
    try testing.expectEqual(@as(usize, 5), try exprfn.countMatchesIn(a, h, p));
}

// ── S2-6: resolving many names against a wide frame scanned the columns each time ──

const wide = 50_000;

fn wideColumns(a: std.mem.Allocator, prefix: []const u8, n: usize) ![]Column {
    const cols = try a.alloc(Column, n);
    for (cols, 0..) |*c, i| c.* = .{ .name = try std.fmt.allocPrint(a, "{s}{d}", .{ prefix, i }), .type = .int };
    return cols;
}

fn elapsedMs(t0: i96) i96 {
    return @divFloor(std.Io.Timestamp.now(testing.io, .awake).nanoseconds - t0, std.time.ns_per_ms);
}

test "concatByName of wide frames resolves each name once (sweep S2-6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try wideColumns(a, "c", wide);
    // No storage at all: every column reads as null, one row each.
    const one: Frame = .{ .columns = cols, .data = &.{}, .len = 1 };
    const t0 = std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
    const out = try df.concatByName(a, &.{ one, one });
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expectEqual(@as(usize, wide), out.columns.len);
    try testing.expectEqual(@as(usize, 2), out.len);
}

test "joinAsof with a suffix over wide frames scans the left names once (sweep S2-6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lc = try wideColumns(a, "l", wide);
    const rc = try wideColumns(a, "r", wide);
    lc[0] = .{ .name = "t", .type = .int };
    rc[0] = .{ .name = "t", .type = .int };
    const ld = try a.alloc(df.ColumnData, 1);
    ld[0] = .{ .int = .{ .values = try a.dupe(i64, &.{5}) } };
    const rd = try a.alloc(df.ColumnData, 1);
    rd[0] = .{ .int = .{ .values = try a.dupe(i64, &.{ 1, 2, 3 }) } };
    const left: Frame = .{ .columns = lc, .data = ld, .len = 1 };
    const right: Frame = .{ .columns = rc, .data = rd, .len = 3 };
    const t0 = std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
    const out = try df.joinAsof(a, left, right, .{ .on = "t", .suffix = "_r" });
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expectEqual(@as(usize, 2 * wide - 1), out.columns.len);
}

test "a subset naming every column of a wide frame is resolved in one pass (sweep S2-6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try wideColumns(a, "c", wide);
    const names = try a.alloc([]const u8, wide);
    for (names, cols) |*n, c| n.* = c.name;
    const f: Frame = .{ .columns = cols, .data = &.{}, .len = 1 };
    const t0 = std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
    const out = try df.fillNull(a, f, .{ .subset = names, .strategy = .forward });
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expectEqual(@as(usize, wide), out.columns.len);
    // An unknown name is still refused.
    try testing.expectError(error.NoSuchColumn, df.fillNull(a, f, .{ .subset = &.{"nope"}, .strategy = .forward }));
}

test "window partition_by names are resolved in one pass (sweep S2-6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try wideColumns(a, "c", wide);
    cols[0].name = "v";
    cols[wide - 1].name = "g"; // the last column: a scan walks all of them
    const data = try a.alloc(df.ColumnData, wide);
    @memset(data, .nulls);
    data[0] = .{ .float = .{ .values = try a.dupe(f64, &.{1.5}) } };
    data[wide - 1] = .{ .int = .{ .values = try a.dupe(i64, &.{7}) } };
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    const by = try a.alloc([]const u8, wide);
    @memset(by, "g");
    const t0 = std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
    const out = try df.window(a, f, .{ .value_col = "v", .out = "n", .op = .row_number, .partition_by = by });
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expectEqual(@as(i64, 1), out.cell(0, "n").?.int);
    try testing.expectError(error.NoSuchColumn, df.window(a, f, .{ .value_col = "v", .out = "n", .op = .row_number, .partition_by = &.{"zz"} }));
}

test "describe of every column of a wide frame resolves each name once (sweep S2-6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 20_000;
    const cols = try wideColumns(a, "c", n);
    const names = try a.alloc([]const u8, n);
    for (names, cols) |*nm, c| nm.* = c.name;
    const f: Frame = .{ .columns = cols, .data = &.{}, .len = 0 };
    const t0 = std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
    const out = try df.describe(a, f, names);
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expectEqual(@as(usize, n + 1), out.columns.len);
}

// ── S2-7: an `is_in` key of 4 GiB or more was an unchecked @intCast ──────────────

test "the is_in set refuses a key whose length does not fit its u32 prefix (sweep S2-7)" {
    if (@bitSizeOf(usize) <= 32) return error.SkipZigTest;
    try testing.expectEqual(@as(u32, 0), try expr.test_hooks.keyLen(0));
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), try expr.test_hooks.keyLen(std.math.maxInt(u32)));
    try testing.expectError(error.TooLarge, expr.test_hooks.keyLen(@as(usize, std.math.maxInt(u32)) + 1));
    try testing.expectError(error.TooLarge, expr.test_hooks.keyLen(std.math.maxInt(usize)));
}

// ── hypotheses that did not crash: every operator over every extreme cell ────────

const un_names = std.meta.fieldNames(df.Unary);
const bin_names = std.meta.fieldNames(df.Binary);

fn extremeFrame(a: std.mem.Allocator) !Frame {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const imin = std.math.minInt(i64);
    const imax = std.math.maxInt(i64);
    const dmin = std.math.minInt(i128);
    const dmax = std.math.maxInt(i128);
    const ints = [_]i64{ imin, imin + 1, -1, 0, 1, 2, 62, 63, 64, 1 << 40, imax - 1, imax };
    const floats = [_]f64{ nan, inf, -inf, std.math.floatMax(f64), -std.math.floatMax(f64), std.math.floatMin(f64), 5e-324, -0.0, 0.5, -2.5, 1e308, 1e19 };
    const decs = [_]i128{ dmin, dmin + 1, -1, 0, 1, 1_500_000_000_000, dmax, dmax - 1, 999_999_999_999, -999_999_999_999, 7, 10 };
    const texts = [_][]const u8{ "", "abc", "héllo wörld", "\xff\xfe\xc3", "2020-01-01", "2020-02-30T25:61:61Z", "0000-01-01", "9999-12-31T23:59:59.999999Z", "-12", "+7", "1e400", "  x  " };
    const stamps = [_]i64{ imin, imin + 1, -62135596800 * 1_000_000, 0, 1, 253402300799 * 1_000_000, imax, imax - 1, -1, 1_600_000_000_000_000, 951782400 * 1_000_000, 86_400_000_000 };
    const cols = [_]Column{
        .{ .name = "i", .type = .int },
        .{ .name = "f", .type = .float },
        .{ .name = "d", .type = .decimal },
        .{ .name = "s", .type = .text },
        .{ .name = "b", .type = .bool },
        .{ .name = "ts", .type = .timestamp },
    };
    const rows = try a.alloc([]const Value, 12);
    for (rows, 0..) |*r, k| {
        const cell = try a.alloc(Value, 6);
        cell[0] = .{ .int = ints[k] };
        cell[1] = .{ .float = floats[k] };
        cell[2] = .{ .decimal = decs[k] };
        cell[3] = .{ .text = texts[k] };
        cell[4] = if (k % 3 == 0) .null else .{ .bool = k % 2 == 0 };
        cell[5] = .{ .int = stamps[k] };
        r.* = cell;
    }
    return st.mk(a, &cols, rows);
}

fn runAssign(a: std.mem.Allocator, f: Frame, e: df.Expr) !void {
    _ = df.mutate(a, f, &.{.{ .out = "out", .expr = e }}) catch |err| switch (err) {
        error.ExprTooLarge, error.BadExpr, error.TooLarge, error.NoSuchColumn => return,
        else => return err,
    };
    // Typed output too: every cell cast to text.
    _ = df.mutate(a, f, &.{.{ .out = "out", .expr = e, .type = .text }}) catch |err| switch (err) {
        error.ExprTooLarge, error.BadExpr, error.TooLarge, error.NoSuchColumn => return,
        else => return err,
    };
}

test "every unary and binary operator over extreme cells never traps (sweep clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try extremeFrame(a);
    const names = [_][]const u8{ "i", "f", "d", "s", "b", "ts" };
    inline for (un_names) |un| {
        for (names) |c| {
            const x: df.Expr = .{ .col = c };
            try runAssign(a, f, .{ .unary = .{ .op = @field(df.Unary, un), .x = &x } });
        }
    }
    inline for (bin_names) |bn| {
        for (names) |lc| for (names) |rc| {
            const l: df.Expr = .{ .col = lc };
            const r: df.Expr = .{ .col = rc };
            try runAssign(a, f, .{ .binary = .{ .op = @field(df.Binary, bn), .l = &l, .r = &r } });
        };
    }
}

test "the parameterised expressions over extreme cells never trap (sweep clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try extremeFrame(a);
    const names = [_][]const u8{ "i", "f", "d", "s", "ts" };
    const imin = std.math.minInt(i64);
    const imax = std.math.maxInt(i64);
    for (names) |c| {
        const x: df.Expr = .{ .col = c };
        for ([_]i32{ std.math.minInt(i32), -400, -309, -308, -13, -1, 0, 1, 12, 13, 300, 330, 331, std.math.maxInt(i32) }) |d| {
            for ([_]df.RoundMode{ .half_even, .half_away }) |m| try runAssign(a, f, .{ .round = .{ .x = &x, .decimals = d, .mode = m } });
        }
        for ([_]u32{ 1, 2, 15, 17, 308, 400, std.math.maxInt(u32) }) |d| try runAssign(a, f, .{ .round_sig_figs = .{ .x = &x, .digits = d } });
        for ([_]usize{ 0, 1, 5, 1 << 20, df.max_text_result, df.max_text_result + 1, std.math.maxInt(usize) }) |w| {
            for ([_]df.PadSide{ .left, .right, .both }) |sd| try runAssign(a, f, .{ .pad = .{ .x = &x, .width = w, .side = sd, .fill = 'é' } });
        }
        for ([_]i64{ imin, imin + 1, -5, -1, 0, 1, 3, imax }) |off| {
            for ([_]?usize{ null, 0, 1, 3, std.math.maxInt(usize) }) |len| try runAssign(a, f, .{ .slice = .{ .x = &x, .offset = off, .length = len } });
        }
        for ([_]u8{ 0, 1, 2, 10, 16, 36, 37, 255 }) |b| try runAssign(a, f, .{ .to_integer = .{ .x = &x, .base = b } });
        for ([_]i64{ imin, -7, 0, 1, 5, imax }) |n| try runAssign(a, f, .{ .add_business_days = .{ .x = &x, .n = n } });
        for ([_][]const u8{ "1mo", "-1mo", "2147483647mo", "2147483648mo", "9223372036854775807y", "1y2mo", "9223372036854775807ns", "-9223372036854775807d", "1w", "0s", "", "-", "7q", "1h30m" }) |by| {
            try runAssign(a, f, .{ .offset_by = .{ .x = &x, .by = by } });
            try runAssign(a, f, .{ .truncate = .{ .x = &x, .every = by } });
        }
        for ([_][]const u8{ "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%.f", "%F %T", "%y%j%u%V%G", "%d/%m/%Y %I:%M %p", "%z %:z %Z", "[x]", "%%", "%", "%Q", "%b %B %a %A %h", "%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y%Y" }) |fmt| {
            try runAssign(a, f, .{ .strftime = .{ .x = &x, .format = fmt } });
            try runAssign(a, f, .{ .strptime = .{ .x = &x, .format = fmt, .to = .date } });
            try runAssign(a, f, .{ .strptime = .{ .x = &x, .format = fmt, .to = .timestamp } });
        }
        inline for (comptime std.meta.fieldNames(df.DtPart)) |pn| try runAssign(a, f, .{ .dt = .{ .x = &x, .part = @field(df.DtPart, pn) } });
        try runAssign(a, f, .{ .strip_chars = .{ .x = &x, .chars = "é\xff", .side = .both } });
        try runAssign(a, f, .{ .translate = .{ .x = &x, .from = "aé", .to = "éa", .delete = "l" } });
        try runAssign(a, f, .{ .contains_any = .{ .x = &x, .patterns = &.{ "", "é", "abc" }, .ascii_case_insensitive = true } });
        try runAssign(a, f, .{ .replace_many = .{ .x = &x, .patterns = &.{ "a", "ab", "b" }, .with = &.{"é"} } });
        try runAssign(a, f, .{ .replace = .{ .x = &x, .from = "a", .to = "abc" } });
        try runAssign(a, f, .{ .is_in = .{ .x = &x, .values = &.{ .{ .int = 1 }, .{ .text = "abc" }, .{ .float = std.math.nan(f64) }, .{ .decimal = std.math.minInt(i128) } } } });
        for ([_]df.ColumnType{ .int, .float, .bool, .text, .date, .timestamp, .decimal }) |ty| try runAssign(a, f, .{ .cast = .{ .x = &x, .to = ty } });
    }
}

test "the writers over extreme cells never trap (sweep clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try extremeFrame(a);
    var aw: std.Io.Writer.Allocating = .init(a);
    inline for (.{ df.CsvQuote.necessary, df.CsvQuote.always, df.CsvQuote.never, df.CsvQuote.non_numeric }) |q| {
        for ([_]?u8{ null, 0, 2, 22, 255 }) |p| {
            aw.clearRetainingCapacity();
            try df.writeCsv(a, &aw.writer, f, .{ .quote_style = q, .float_precision = p });
        }
    }
    aw.clearRetainingCapacity();
    try df.writeJson(&aw.writer, f, .records);
    try df.writeJson(&aw.writer, f, .columns);
    try df.writeNdjson(&aw.writer, f);
    _ = try df.format(a, f, .{ .max_rows = std.math.maxInt(usize), .max_cols = std.math.maxInt(usize), .max_cell_chars = 0, .show_dtypes = true, .show_shape = true });
    _ = try df.format(a, f, .{ .max_rows = 0, .max_cols = 0, .max_cell_chars = 1 });
    _ = try df.toMarkdown(a, f, .{});
    // Fixed-point floats at every precision, the largest and the smallest.
    var buf: [400]u8 = undefined;
    for ([_]f64{ std.math.floatMax(f64), -std.math.floatMax(f64), 5e-324, 1e22, 1.7e38, 2.0e38, 1e300, -0.0 }) |x| {
        for (0..23) |d| _ = @import("textio.zig").formatFloatFixed(&buf, x, @intCast(d));
    }
}
