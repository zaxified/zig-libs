// SPDX-License-Identifier: MIT
//! D5-M, group MB (`expr exprfn window more analysis csvio jsonio textio render dtfn
//! seriesfn`): the tests the whole-module mutation run asked for. Each test is named after
//! the mutant ids it kills, "(mut <id>)", so a survivor in a later run can be traced here.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const csvio = @import("csvio.zig");
const textio = @import("textio.zig");
const Frame = df.Frame;
const Value = df.Value;
const ColumnType = df.ColumnType;

fn expectType(f: Frame, name: []const u8, ty: ColumnType) !void {
    try testing.expectEqual(ty, f.columnType(name).?);
}

fn expectCell(f: Frame, row: usize, name: []const u8, want: Value) !void {
    const got = f.cell(row, name).?;
    switch (want) {
        .float => |x| {
            try testing.expect(got == .float);
            if (std.math.isNan(x)) try testing.expect(std.math.isNan(got.float)) else try testing.expectEqual(x, got.float);
        },
        .text => |t| {
            try testing.expect(got == .text);
            try testing.expectEqualStrings(t, got.text);
        },
        else => try testing.expect(Value.eql(want, got) or (want == .null and got == .null)),
    }
}

// ── csvio: limits and the record scanner ────────────────────────────────────

test "a quoted field spanning past max_record_bytes is an unterminated quote (mut 10002)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.UnterminatedQuote, df.readCsv(arena.allocator(), "a\n\"x\nyyyy\nzzzz\n\"\n", .{ .max_record_bytes = 8 }));
}

test "limits are inclusive: a record, a cell, a header of exactly the cap reads (mut 10005 10008 10010)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try df.readCsv(a, "a\n12345\n", .{ .max_record_bytes = 5 });
    try expectCell(r, 0, "a", .{ .int = 12345 });
    const c = try df.readCsv(a, "a\nabc\n", .{ .max_cell_bytes = 3 });
    try expectCell(c, 0, "a", .{ .text = "abc" });
    const w = try df.readCsv(a, "a,b\n1,2\n", .{ .max_columns = 2 });
    try testing.expectEqual(@as(usize, 2), w.columns.len);
}

test "without a header the first record is a row once, and the second follows (mut 10022)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(), "a,b\nc,d\n", .{ .has_header = false });
    try testing.expectEqual(@as(usize, 2), f.len);
    try expectCell(f, 0, "column_0", .{ .text = "a" });
    try expectCell(f, 1, "column_0", .{ .text = "c" });
    try expectCell(f, 1, "column_1", .{ .text = "d" });
}

test "a null marker or a cell of exactly 64 bytes (mut 10032 10036)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m64: [64]u8 = @splat('n');
    const y64: [64]u8 = @splat('y');
    const z65: [65]u8 = @splat('z');
    const f = try df.readCsv(a, "a\n" ++ m64 ++ "\nx\n", .{ .null_values = &.{&m64} });
    try expectCell(f, 0, "a", .null);
    try expectCell(f, 1, "a", .{ .text = "x" });
    const g = try df.readCsv(a, "a\n" ++ y64 ++ "\n" ++ z65 ++ "\n", .{});
    try testing.expectEqual(@as(usize, 64), g.cell(0, "a").?.text.len);
    try testing.expectEqual(@as(usize, 65), g.cell(1, "a").?.text.len);
}

// ── csvio: the number grammar of type inference ─────────────────────────────

test "a byte just past the digits is no digit, in an int, a float, a wide int (mut 10044 10062 10046)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "a,b,c\n:,1.:,18446744073709551616\n12,x,5\n", .{});
    try expectType(f, "a", .text);
    try expectCell(f, 0, "a", .{ .text = ":" });
    try expectType(f, "b", .text);
    try expectCell(f, 0, "b", .{ .text = "1.:" });
    try expectType(f, "c", .text); // 2^64 does not fit i64
    try expectCell(f, 0, "c", .{ .text = "18446744073709551616" });
}

test "blanks around a number, with dates parsed, still read as a number (mut 10053)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(), "a\n 4 \n5\n", .{ .parse_dates = true });
    try expectType(f, "a", .int);
    try expectCell(f, 0, "a", .{ .int = 4 });
    try expectCell(f, 1, "a", .{ .int = 5 });
}

test "with dates parsed an int and a float make a float column (mut 10056)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(), "a\n1\n2.5\n", .{ .parse_dates = true });
    try expectType(f, "a", .float);
    try expectCell(f, 0, "a", .{ .float = 1.0 });
    try expectCell(f, 1, "a", .{ .float = 2.5 });
}

test "a bool token with blanks around it is text (mut 10059)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try df.readCsv(arena.allocator(), "a\n true\n", .{});
    try expectType(f, "a", .text);
    try expectCell(f, 0, "a", .{ .text = " true" });
}

test "every string the float grammar takes, std.fmt.parseFloat reads (mut 10057)" {
    const alpha = "+-.0eEiInNfF9";
    var buf: [5]u8 = undefined;
    var n: usize = 1;
    for (1..6) |len| {
        n *= alpha.len;
        for (0..n) |k| {
            var x = k;
            for (0..len) |j| {
                buf[j] = alpha[x % alpha.len];
                x /= alpha.len;
            }
            const s = buf[0..len];
            if (textio.isFloatGrammar(s)) try testing.expect(textio.parseFloatToken(s) != null);
        }
    }
    for ([_][]const u8{ "Infinity", "-INFINITY", "+nan", "-Inf", "1e400", "5.", ".5e-3", "0e0", "+.5E+2" }) |s| {
        if (textio.isFloatGrammar(s)) try testing.expect(textio.parseFloatToken(s) != null);
    }
}

test "a typed float or decimal cell: grammar and blanks (mut 10076 10078 10116)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fl: []const csvio.TypeOverride = &.{.{ .name = "a", .type = .float }};
    // std.fmt.parseFloat reads hex floats and `_` separators; a CSV cell must not.
    try testing.expectError(error.BadValue, csvio.test_hooks.readCsvCells(a, "a\n0x10\n", .{ .types = fl }));
    try testing.expectError(error.BadValue, df.readCsv(a, "a\n1_0\n", .{ .types = fl }));
    const dec: []const csvio.TypeOverride = &.{.{ .name = "a", .type = .decimal }};
    const f = try csvio.test_hooks.readCsvCells(a, "a\n 1.5 \n", .{ .types = dec });
    try testing.expectEqual(@as(i128, 1_500_000_000_000), f.cell(0, "a").?.decimal);
    const g = try df.readCsv(a, "a\n 1.5 \n", .{ .types = dec });
    try testing.expectEqual(@as(i128, 1_500_000_000_000), g.cell(0, "a").?.decimal);
}

test "max_bytes is inclusive and names must match the width (mut 10079 10082)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "a\n1\n", .{ .max_bytes = 4 });
    try testing.expectEqual(@as(usize, 1), f.len);
    try testing.expectError(error.InputTooLarge, df.readCsv(a, "a\n1\n", .{ .max_bytes = 3 }));
    try testing.expectError(error.BadNames, df.readCsv(a, "a,b\n1,2\n", .{ .names = &.{ "x", "y", "z" } }));
    try testing.expectError(error.BadNames, df.readCsv(a, "a,b\n1,2\n", .{ .names = &.{"x"} }));
}

test "max_cells is inclusive, on both readers (mut 10089 10126)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const four = "a,b\n1,2\n3,4\n";
    const six = "a,b\n1,2\n3,4\n5,6\n";
    const f = try df.readCsv(a, four, .{ .max_cells = 4 });
    try testing.expectEqual(@as(usize, 2), f.len);
    const g = try csvio.test_hooks.readCsvCells(a, four, .{ .max_cells = 4 });
    try testing.expectEqual(@as(usize, 2), g.len);
    try testing.expectError(error.TooManyCells, df.readCsv(a, six, .{ .max_cells = 4 }));
    try testing.expectError(error.TooManyCells, csvio.test_hooks.readCsvCells(a, six, .{ .max_cells = 4 }));
}

test "-0 keeps its sign when a float follows or precedes it (mut 10118 10122 10123)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "x,y,z\n-0,1,1.5\n1.5,-0,-0\n", .{});
    try expectType(f, "x", .float);
    try testing.expect(std.math.signbit(f.cell(0, "x").?.float));
    try expectType(f, "y", .int);
    const g = try df.readCsv(a, "y\n1\n-0\n1.5\n", .{});
    try expectType(g, "y", .float);
    try testing.expect(std.math.signbit(g.cell(1, "y").?.float));
    const h = try df.readCsv(a, "z\n1.5\n-0\n", .{});
    try testing.expect(std.math.signbit(h.cell(1, "z").?.float));
}

test "blanks around an int do not send the reader to its second pass (mut 10121)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const before = csvio.test_hooks.spec_gave_up;
    const f = try df.readCsv(arena.allocator(), "a\n1\n 2 \n", .{});
    try expectCell(f, 1, "a", .{ .int = 2 });
    try testing.expectEqual(before, csvio.test_hooks.spec_gave_up);
}

fn csvOf(a: std.mem.Allocator, f: Frame, opts: df.CsvWriteOptions) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

test "writeCsv: a timestamp column gets 6 fraction digits when a later cell needs them (mut 10141)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "t\n2021-01-02 03:04:05.12\n2021-01-02 03:04:05.123456\n", .{ .types = &.{.{ .name = "t", .type = .timestamp }} });
    try testing.expectEqualStrings("t\n2021-01-02 03:04:05.120000\n2021-01-02 03:04:05.123456\n", try csvOf(a, f, .{}));
}

test "writeCsv: float_precision past 22 is 22 (mut 10145)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "x\n0.1\n", .{});
    try testing.expectEqualStrings("x\n0.1000000000000000055511\n", try csvOf(a, f, .{ .float_precision = 30 }));
}

test "writeCsv: an empty bool text or an empty text without quoting (mut 10148 10150 10151)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try df.readCsv(a, "a,b\ntrue,1\n", .{});
    try testing.expectEqualStrings("a,b\n,1\n", try csvOf(a, b, .{ .true_text = "" }));
    const t = try df.readCsv(a, "a,b\n\"\",1\n", .{ .null_values = &.{"NA"} });
    try expectCell(t, 0, "a", .{ .text = "" });
    try testing.expectEqualStrings("a,b\n,1\n", try csvOf(a, t, .{ .quote = 0 }));
    try testing.expectEqualStrings("a,b\n,1\n", try csvOf(a, t, .{ .quote_style = .never }));
}

test "formatFloatFixed at the edges of its exact range (mut 10211 10213 10216 10217 10218)" {
    var b: [400]u8 = undefined;
    var b2: [400]u8 = undefined;
    // 22 digits are exact, 23 and more are the shortest digits padded.
    try testing.expectEqualStrings("0.1000000000000000055511", textio.formatFloatFixed(&b, 0.1, 22));
    const long = textio.formatFloatFixed(&b, 0.1, 25);
    try testing.expectEqual(@as(usize, 27), long.len);
    try testing.expect(std.mem.startsWith(u8, long, "0.1000000000000000"));
    // 2^127 and beyond: the shortest digits, not the exact integer.
    const big: f64 = 170141183460469231731687303715884105728.0;
    const want = try std.fmt.bufPrint(&b2, "{d:.0}", .{big});
    try testing.expectEqualStrings(want, textio.formatFloatFixed(&b, big, 0));
    // 2^52: an integer with no fraction bits (shift of 0).
    try testing.expectEqualStrings("4503599627370496.00", textio.formatFloatFixed(&b, 4503599627370496.0, 2));
    // 127 right shifts: 5.2e-23 rounds up at 22 digits.
    try testing.expectEqualStrings("0.0000000000000000000001", textio.formatFloatFixed(&b, 5.2e-23, 22));
}

fn jsonOf(a: std.mem.Allocator, f: Frame, orient: df.JsonOrient) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&aw.writer, f, orient);
    return aw.toOwnedSlice();
}

test "textio: fractionDigits keeps 6, hasFraction, tabs are blanks (mut 10236 10237 10238)" {
    try testing.expectEqual(@as(u8, 6), textio.fractionDigits(1609556645120000, 6));
    try testing.expect(textio.hasFraction(1609556645000001));
    try testing.expect(!textio.hasFraction(1609556645000000));
    try testing.expectEqualStrings("4", textio.trimBlank("\t4\t"));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try df.readCsv(a, "a\n\t4\t\n5\n", .{});
    try expectType(f, "a", .int);
    const t = try df.readCsv(a, "t\n2021-01-02 03:04:05\n2021-01-02 03:04:05.5\n", .{ .types = &.{.{ .name = "t", .type = .timestamp }} });
    const out = try df.format(a, t, .{});
    try testing.expect(std.mem.find(u8, out, "2021-01-02 03:04:05.500000") != null);
    try testing.expect(std.mem.find(u8, out, ".000000") == null);
}

test "decimal tokens: trailing junk, no digits, i128 overflow (mut 10256 10257 10260)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dec: []const csvio.TypeOverride = &.{.{ .name = "a", .type = .decimal }};
    for ([_][]const u8{ "1.5x", ".", "-", "170141183460469231731687303715884105728" }) |bad| {
        const text = try std.fmt.allocPrint(a, "a\n{s}\n", .{bad});
        try testing.expectError(error.BadValue, df.readCsv(a, text, .{ .types = dec }));
    }
    try testing.expectEqual(@as(?i128, null), textio.parseDecimalToken("1.5x"));
    try testing.expectEqual(@as(?i128, null), textio.parseDecimalToken("."));
    try testing.expectEqual(@as(?i128, null), textio.parseDecimalToken("170141183460469231731687303715884105728"));
}

test "json: timestamps are ISO strings, newline and carriage return are escaped (mut 10304 10314 10315)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try df.readCsv(a, "t\n2021-01-02 03:04:05\n", .{ .types = &.{.{ .name = "t", .type = .timestamp }} });
    try testing.expectEqualStrings("[{\"t\":\"2021-01-02T03:04:05Z\"}]", try jsonOf(a, t, .records));
    const s = try df.readCsv(a, "s\n\"a\nb\rc\td\"\n", .{});
    try testing.expectEqualStrings("{\"s\":[\"a\\nb\\rc\\td\"]}", try jsonOf(a, s, .columns));
}

// ── window ──────────────────────────────────────────────────────────────────

const st = @import("structure_test.zig");
const win = @import("window.zig");

fn wrun(a: std.mem.Allocator, f: Frame, op: df.WindowOp) !Frame {
    return df.window(a, f, .{ .value_col = "x", .out = "o", .op = op });
}

fn fx(vals: []const f64, a: std.mem.Allocator) !Frame {
    const rows = try a.alloc([]const Value, vals.len);
    for (rows, vals) |*r, v| r.* = try a.dupe(Value, &.{.{ .float = v }});
    return st.mk(a, &.{.{ .name = "x", .type = .float }}, rows);
}

fn ix(vals: []const i64, a: std.mem.Allocator) !Frame {
    const rows = try a.alloc([]const Value, vals.len);
    for (rows, vals) |*r, v| r.* = try a.dupe(Value, &.{.{ .int = v }});
    return st.mk(a, &.{.{ .name = "x", .type = .int }}, rows);
}

test "a column declared int that holds a float is not an exact int column (mut 13003)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cells = [_]Value{ .{ .int = 1 }, .{ .float = 2.5 } };
    const cols = [_]df.Column{.{ .name = "x", .type = .int }};
    const data = [_]df.ColumnData{try df.columnFromCells(a, &cells)};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 2 };
    const r = try wrun(a, f, .cum_sum);
    try testing.expectEqual(@as(f64, 3.5), r.cell(1, "o").?.float);
}

test "int overflow in transform sum and diff is null (mut 13022 13032)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const big = std.math.maxInt(i64);
    const f = try ix(&.{ big, 1 }, a);
    const t = try wrun(a, f, .{ .transform = .{ .func = .sum } });
    try expectCell(t, 0, "o", .null);
    try expectCell(t, 1, "o", .null);
    const g = try ix(&.{ std.math.minInt(i64), big }, a);
    const d = try wrun(a, g, .{ .diff = 1 });
    try expectCell(d, 1, "o", .null);
    const d2 = try win.test_hooks.windowCells(a, g, .{ .value_col = "x", .out = "o", .op = .{ .diff = 1 } });
    try expectCell(d2, 1, "o", .null);
}

test "rolling first and the quantile bounds (mut 13051 13053 13054)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fx(&.{ 1, 2, 3 }, a);
    const first = try wrun(a, f, .{ .rolling = .{ .window = 2, .func = .first, .min_periods = 1 } });
    try expectCell(first, 2, "o", .{ .float = 2 });
    const q1 = try wrun(a, f, .{ .rolling = .{ .window = 3, .func = .quantile, .q = 1 } });
    try expectCell(q1, 2, "o", .{ .float = 3 });
    const q0 = try wrun(a, f, .{ .rolling = .{ .window = 3, .func = .quantile, .q = 0 } });
    try expectCell(q0, 2, "o", .{ .float = 1 });
    const c1 = try win.test_hooks.windowCells(a, f, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 3, .func = .quantile, .q = 1 } } });
    try expectCell(c1, 2, "o", .{ .float = 3 });
    const c0 = try win.test_hooks.windowCells(a, f, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 3, .func = .quantile, .q = 0 } } });
    try expectCell(c0, 2, "o", .{ .float = 1 });
}

test "a window over more work than the cap is refused on the cell path (mut 13067)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 40000;
    const f = try fx(try a.alloc(f64, n), a);
    try testing.expectError(error.TooLarge, win.test_hooks.windowCells(a, f, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = n } } }));
}

test "rolling_time: the earliest representable time still sees itself (mut 13083)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "t", .type = .int }, .{ .name = "x", .type = .float } }, &.{&.{ .{ .int = std.math.minInt(i64) }, .{ .float = 3 } }});
    const r = try wrun(a, f, .{ .rolling_time = .{ .time_col = "t", .period = 10 } });
    try expectCell(r, 0, "o", .{ .float = 3 });
}

test "expanding var with ddof 0 and the ewm decay arguments (mut 13087 13102 13103 13104 13105 13108)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fx(&.{ 1, 2, 3, 4 }, a);
    const v = try wrun(a, f, .{ .expanding = .{ .func = .@"var", .min_periods = 1, .ddof = 0 } });
    try testing.expectApproxEqAbs(@as(f64, 0.25), v.cell(1, "o").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 2.0 / 3.0), v.cell(2, "o").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 1.25), v.cell(3, "o").?.float, 1e-12);
    // alpha 1, span 1, com 0 are all "the newest value only"; a zero half-life or an infinite span is not a decay.
    for ([_]df.Ewm{ .{ .alpha = 1 }, .{ .span = 1 }, .{ .com = 0 } }) |e| {
        const r = try wrun(a, f, .{ .ewm = e });
        try expectCell(r, 3, "o", .{ .float = 4 });
    }
    try testing.expectError(error.InvalidDecay, wrun(a, f, .{ .ewm = .{ .halflife = 0 } }));
    try testing.expectError(error.InvalidDecay, wrun(a, f, .{ .ewm = .{ .span = std.math.inf(f64) } }));
    try testing.expectError(error.InvalidDecay, wrun(a, f, .{ .ewm = .{ .com = std.math.inf(f64) } }));
}

test "json: control characters are lowercase hex (mut 10317)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try df.readCsv(a, "s\n\"a\x1fb\"\n", .{});
    try testing.expectEqualStrings("{\"s\":[\"a\\u001fb\"]}", try jsonOf(a, s, .columns));
}

test "a bitmap shorter than the rows is read as null, not out of bounds (mut 13136)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = try a.alloc(f64, 100);
    for (vals, 0..) |*v, i| v.* = @floatFromInt(i);
    const valid = try a.dupe(u64, &.{~@as(u64, 0)}); // rows 0..63 present, the rest read as null
    const cols = [_]df.Column{.{ .name = "x", .type = .float }};
    const data = [_]df.ColumnData{.{ .float = .{ .values = vals, .valid = valid } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 100 };
    const r = try wrun(a, f, .cum_sum);
    try expectCell(r, 63, "o", .{ .float = 63 * 64 / 2 });
    try expectCell(r, 70, "o", .null);
}

// ── more ────────────────────────────────────────────────────────────────────

const more = @import("more.zig");

fn nullsFrame(len: usize) Frame {
    const cols = [_]df.Column{.{ .name = "k", .type = .int }};
    const data = [_]df.ColumnData{.nulls};
    return .{ .columns = &cols, .data = &data, .len = len };
}

test "sample with replacement: the cell cap, with and without columns (mut 14015 14016 14017)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const none = try st.mk(a, &.{}, &.{&.{}});
    const cap: usize = 1 << 24;
    const ok = try df.sample(a, none, .{ .n = cap, .seed = 1, .replace = true });
    try testing.expectEqual(cap, ok.len);
    try testing.expectError(error.TooLarge, df.sample(a, none, .{ .n = cap + 1, .seed = 1, .replace = true }));
    try testing.expectError(error.TooLarge, df.sample(a, none, .{ .n = 1 << 40, .seed = 1, .replace = true }));
}

test "concatByName: declared type of the first frame, the cell cap on claimed rows (mut 14020 14021 14022)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f1 = try st.mk(a, &.{.{ .name = "a", .type = .int }}, &.{&.{.{ .int = 1 }}});
    const f2 = try st.mk(a, &.{.{ .name = "a", .type = .float }}, &.{&.{.{ .float = 2.5 }}});
    const c = try df.concatByName(a, &.{ f1, f2 });
    try testing.expectEqual(ColumnType.int, c.columns[0].type);
    const cap: usize = 1 << 24;
    const edge = try df.concatByName(a, &.{nullsFrame(cap)});
    try testing.expectEqual(cap, edge.len);
    try testing.expectError(error.TooLarge, df.concatByName(a, &.{nullsFrame(cap + 1)}));
}

test "concatByName reads short arrays, short bitmaps and bad offsets as null (mut 14030 14034 14038 14039)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const short_vals = [_]i64{ 7, 8 };
    const empty_bits: []const u64 = &.{};
    const ints = [_]df.Column{.{ .name = "x", .type = .int }};
    const txts = [_]df.Column{.{ .name = "s", .type = .text }};
    // claimed 4 rows, 2 values
    const d1 = [_]df.ColumnData{.{ .int = .{ .values = &short_vals } }};
    const f1: Frame = .{ .columns = &ints, .data = &d1, .len = 4 };
    const c1 = try df.concatByName(a, &.{f1});
    try expectCell(c1, 1, "x", .{ .int = 8 });
    try expectCell(c1, 2, "x", .null);
    try expectCell(c1, 3, "x", .null);
    // a bitmap with no words: every row null
    const d2 = [_]df.ColumnData{.{ .int = .{ .values = &short_vals, .valid = empty_bits } }};
    const f2: Frame = .{ .columns = &ints, .data = &d2, .len = 2 };
    const f3 = try st.mk(a, &ints, &.{&.{.{ .int = 9 }}});
    const c2 = try df.concatByName(a, &.{ f2, f3 });
    try expectCell(c2, 0, "x", .null);
    try expectCell(c2, 1, "x", .null);
    try expectCell(c2, 2, "x", .{ .int = 9 });
    // offsets past the bytes, and descending offsets
    const o1 = [_]usize{ 0, 5 };
    const t1 = [_]df.ColumnData{.{ .text = .{ .offsets = &o1, .bytes = "ab" } }};
    const g1: Frame = .{ .columns = &txts, .data = &t1, .len = 1 };
    const h1 = try st.mk(a, &txts, &.{&.{.{ .text = "z" }}});
    const c3 = try df.concatByName(a, &.{ g1, h1 });
    try expectCell(c3, 0, "s", .null);
    try expectCell(c3, 1, "s", .{ .text = "z" });
    const o2 = [_]usize{ 0, 3, 2 };
    const t2 = [_]df.ColumnData{.{ .text = .{ .offsets = &o2, .bytes = "abcd" } }};
    const g2: Frame = .{ .columns = &txts, .data = &t2, .len = 2 };
    const c4 = try df.concatByName(a, &.{g2});
    try expectCell(c4, 0, "s", .{ .text = "abc" });
    try expectCell(c4, 1, "s", .null);
}

test "concatByName: a text piece that is a view into a larger buffer (mut 14042)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const txts = [_]df.Column{.{ .name = "s", .type = .text }};
    const o = [_]usize{ 2, 4, 6 };
    const t = [_]df.ColumnData{.{ .text = .{ .offsets = &o, .bytes = "..abcd" } }};
    const g: Frame = .{ .columns = &txts, .data = &t, .len = 2 };
    const h = try st.mk(a, &txts, &.{&.{.{ .text = "ef" }}});
    const c = try df.concatByName(a, &.{ g, h });
    try expectCell(c, 0, "s", .{ .text = "ab" });
    try expectCell(c, 1, "s", .{ .text = "cd" });
    try expectCell(c, 2, "s", .{ .text = "ef" });
}

test "describe: a quartile that lands on an infinity is the infinity, not NaN (mut 14062)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inf = std.math.inf(f64);
    const f = try fx(&.{ 1, 2, inf, inf, inf }, a);
    const d = try df.describe(a, f, &.{});
    try expectCell(d, 4, "x", .{ .float = 2 });
    try expectCell(d, 5, "x", .{ .float = inf });
    try expectCell(d, 6, "x", .{ .float = inf });
}

test "cut: label count and the closed upper edge of a left-closed last bin (mut 14074 14079)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fx(&.{ 0, 2 }, a);
    try testing.expectError(error.BadEdges, df.cut(a, f, .{ .col = "x", .out = "b", .edges = &.{ 0, 1, 2 }, .labels = &.{"only"} }));
    const c = try df.cut(a, f, .{ .col = "x", .out = "b", .edges = &.{ 0, 1, 2 }, .right = false, .include_lowest = true });
    try expectCell(c, 0, "b", .{ .int = 0 });
    try expectCell(c, 1, "b", .{ .int = 1 });
}

test "joinAsof refuses an output over the cell cap before it builds the rows (mut 14082)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const right = try st.mk(a, &.{.{ .name = "k", .type = .int }}, &.{&.{.{ .int = 1 }}});
    try testing.expectError(error.TooLarge, df.joinAsof(a, nullsFrame((1 << 24) + 1), right, .{ .on = "k" }));
}

// ── render ──────────────────────────────────────────────────────────────────

fn txt(a: std.mem.Allocator, vals: []const []const u8) !Frame {
    const rows = try a.alloc([]const Value, vals.len);
    for (rows, vals) |*r, v| r.* = try a.dupe(Value, &.{.{ .text = v }});
    return st.mk(a, &.{.{ .name = "s", .type = .text }}, rows);
}

test "format: a cut at exactly the width, escapes of NUL and DEL, bytes that are not UTF-8 (mut 10403 10408 10410 10414 10416)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try txt(a, &.{ "abcde", "abcdef", "a\nb", "a\x00b", "a\x7fb", "\xe2\xe2\xe2\xe2" });
    const out = try df.format(a, f, .{ .max_cell_chars = 3 });
    // 3 code points fit, a 4th is cut to 2 and an ellipsis; the control texts of 3 stay whole.
    try testing.expect(std.mem.find(u8, out, "ab\u{2026}") != null);
    try testing.expect(std.mem.find(u8, out, "abc\u{2026}") == null);
    try testing.expect(std.mem.find(u8, out, "a\\nb") != null);
    try testing.expect(std.mem.find(u8, out, "a\\x00b") != null);
    try testing.expect(std.mem.find(u8, out, "a\\x7fb") != null);
    try testing.expect(std.mem.find(u8, out, "\xe2\xe2\xe2\xe2") != null);
    const g = try txt(a, &.{ "abcde", "abcdef" });
    const o2 = try df.format(a, g, .{ .max_cell_chars = 5 });
    try testing.expect(std.mem.find(u8, o2, "abcde\n") != null);
    try testing.expect(std.mem.find(u8, o2, "abcd\u{2026}") != null);
}

test "format: infinities, row and column cuts at the exact count, no columns (mut 10407 10422 10423 10425 10428)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inf = std.math.inf(f64);
    const fl = try fx(&.{ inf, -inf }, a);
    const o1 = try df.format(a, fl, .{});
    try testing.expect(std.mem.find(u8, o1, "-inf") != null);
    try testing.expect(std.mem.find(u8, o1, " inf") != null);
    const wide = try st.mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int }, .{ .name = "c", .type = .int }, .{ .name = "d", .type = .int } }, &.{&.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 } }});
    try testing.expectEqualStrings("a b \u{2026} d\n1 2 \u{2026} 4\n", try df.format(a, wide, .{ .max_cols = 3 }));
    const three = try st.mk(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int }, .{ .name = "c", .type = .int } }, &.{&.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } }});
    try testing.expectEqualStrings("a b c\n1 2 3\n", try df.format(a, three, .{ .max_cols = 3 }));
    const rows = try ix(&.{ 1, 2, 3 }, a);
    try testing.expectEqualStrings("x\n1\n2\n3\n", try df.format(a, rows, .{ .max_rows = 3 }));
    const none = try st.mk(a, &.{}, &.{ &.{}, &.{} });
    try testing.expectEqualStrings("", try df.format(a, none, .{}));
    try testing.expectEqualStrings("", try df.toMarkdown(a, none, .{}));
}

test "toMarkdown: floats and decimals are right-aligned numbers (mut 10419 10420)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .decimal } }, &.{&.{ .{ .float = 1.5 }, .{ .decimal = 1_500_000_000_000 } }});
    try testing.expectEqualStrings("|   x |   y |\n|----:|----:|\n| 1.5 | 1.5 |\n", try df.toMarkdown(a, f, .{}));
}

test "toMarkdown refuses a claimed row count it cannot size (mut 10436 10437)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c1 = [_]df.Column{.{ .name = "k", .type = .int }};
    const d1 = [_]df.ColumnData{.nulls};
    const huge: Frame = .{ .columns = &c1, .data = &d1, .len = std.math.maxInt(usize) };
    try testing.expectError(error.OutOfMemory, df.toMarkdown(a, huge, .{}));
    const c2 = [_]df.Column{ .{ .name = "k", .type = .int }, .{ .name = "l", .type = .int } };
    const d2 = [_]df.ColumnData{ .nulls, .nulls };
    const wide: Frame = .{ .columns = &c2, .data = &d2, .len = std.math.maxInt(usize) / 2 };
    try testing.expectError(error.OutOfMemory, df.toMarkdown(a, wide, .{}));
}

// ── dtfn ────────────────────────────────────────────────────────────────────

const dtfn = @import("dtfn.zig");

test "dtfn: dates of year 0 and 9999 are text (mut 10602 10603)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const y0 = try dtfn.part(a, .{ .text = "0000-03-05" }, .date);
    try testing.expectEqualStrings("0000-03-05", y0.text);
    const y9 = try dtfn.part(a, .{ .text = "9999-12-31" }, .date);
    try testing.expectEqualStrings("9999-12-31", y9.text);
}

// ── seriesfn ────────────────────────────────────────────────────────────────

fn series(f: Frame) df.Series {
    return f.series("x").?;
}

test "rle: NaN runs, rleId refuses an existing name (mut 10500 10505)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const f = try fx(&.{ nan, 1, nan, nan }, a);
    const r = try df.rle(a, series(f));
    try testing.expectEqual(@as(usize, 3), r.len);
    try expectCell(r, 2, "len", .{ .int = 2 });
    try testing.expectError(error.DuplicateColumn, df.rleId(a, f, "x", "x"));
}

test "autocorr: a NaN in one of the two series skips the pair; a constant side is null (mut 10522 10525 10526)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const f = try fx(&.{ 1, 2, nan, 4, 5, 7 }, a);
    const r = df.autocorr(series(f), 1).?;
    try testing.expectApproxEqAbs(@as(f64, 0.9862), r, 1e-3);
    try testing.expectEqual(@as(?f64, null), df.autocorr(series(try fx(&.{ 1, 2, 2, 2 }, a)), 1));
    try testing.expectEqual(@as(?f64, null), df.autocorr(series(try fx(&.{ 2, 2, 2, 1 }, a)), 1));
}

test "entropy: nothing present, a zero sum, a zero term, NaN skipped (mut 10528 10529 10530 10533)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    try testing.expectEqual(@as(?f64, null), df.entropy(series(try fx(&.{ nan, nan }, a)), std.math.e, false));
    try testing.expectEqual(@as(?f64, null), df.entropy(series(try fx(&.{ 0, 0 }, a)), std.math.e, true));
    try testing.expectEqual(@as(f64, 0), df.entropy(series(try fx(&.{ 0, 1 }, a)), std.math.e, true).?);
    try testing.expectApproxEqAbs(@as(f64, @log(2.0)), df.entropy(series(try fx(&.{ 1, nan, 1 }, a)), std.math.e, true).?, 1e-12);
}

test "nanExtreme: NaN wins, text has no extreme, ties keep the first (mut 10534 10535 10536 10537)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    try testing.expect(std.math.isNan(df.nanExtreme(series(try fx(&.{ 1, nan, 3 }, a)), .max).float));
    try testing.expect(df.nanExtreme((try txt(a, &.{ "a", "b" })).series("s").?, .max) == .null);
    const z = try fx(&.{ 0.0, -0.0 }, a);
    try testing.expect(!std.math.signbit(df.nanExtreme(series(z), .max).float));
    try testing.expect(!std.math.signbit(df.nanExtreme(series(z), .min).float));
}

test "firstValid, lastValid, asofIndex, extendConstant at their edges (mut 10545 10548 10550 10552 10554 10557 10559)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const lead = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 7 }}, &.{.null}, &.{.null} });
    try testing.expectEqual(@as(?usize, 0), df.lastValid(series(lead)));
    try testing.expectEqual(@as(?usize, 0), df.firstValid(series(lead)));
    try testing.expectEqual(@as(?usize, null), df.asofIndex(series(try fx(&.{ 1, 2, 3 }, a)), .{ .float = nan }));
    const nulls_first = try st.mk(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.null}, &.{.null}, &.{.null}, &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    try testing.expectEqual(@as(?usize, 4), df.asofIndex(series(nulls_first), .{ .int = 5 }));
    try testing.expectEqual(@as(?usize, 2), df.asofIndex(series(try ix(&.{ 1, 2, 2, 3 }, a)), .{ .int = 2 }));
    try testing.expectEqual(@as(?usize, 0), df.asofIndex(series(try ix(&.{ 1, 5 }, a)), .{ .int = 3 }));
    const base = try ix(&.{ 1, 2 }, a);
    const ext = try df.extendConstant(a, series(base), .{ .int = 9 }, 1);
    try testing.expectEqual(@as(usize, 3), ext.len);
    try testing.expectEqual(@as(i64, 1), ext.get(0).int);
    try testing.expectEqual(@as(i64, 2), ext.get(1).int);
    try testing.expectEqual(@as(i64, 9), ext.get(2).int);
    try testing.expectError(error.TooLarge, df.extendConstant(a, series(base), .{ .int = 9 }, (1 << 24) + 1));
}

test "dtfn: a date shifted before midnight floors, a format ending in %: is refused (mut 10604 10630)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try dtfn.offsetBy(a, .{ .text = "1970-01-01" }, .{ .us = -1 });
    try testing.expectEqualStrings("1969-12-31", r.text);
    try testing.expectError(error.BadFormat, dtfn.translateFormat(a, "%:"));
    try testing.expectError(error.BadFormat, dtfn.translateFormat(a, "%Y-%"));
}

test "dtfn: parseDuration overflow and sign (mut 10655 10656 10663 10664 10666 10667 10668)" {
    try testing.expectEqual(@as(?dtfn.Duration, null), dtfn.parseDuration("9223372036854775807y"));
    try testing.expectEqual(@as(?dtfn.Duration, null), dtfn.parseDuration("9223372036854775807mo1mo"));
    try testing.expectEqual(@as(?dtfn.Duration, null), dtfn.parseDuration("9223372036854775807d"));
    try testing.expectEqual(@as(?dtfn.Duration, null), dtfn.parseDuration("9223372036854775807us1us"));
    const d = dtfn.parseDuration("-1y2d3w").?;
    try testing.expectEqual(@as(i64, -12), d.months);
    try testing.expectEqual(@as(i64, -23 * 86_400_000_000), d.us);
    try testing.expectEqual(@as(i64, -3), d.weeks);
}

test "dtfn: months keep the fraction of a second, business days before 1969-12-29 (mut 10670 10683 10684)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try dtfn.offsetBy(a, .{ .int = 1609556645123456 }, .{ .months = 1 });
    try testing.expectEqual(@as(i64, 1612235045123456), r.int);
    const b = try dtfn.addBusinessDays(a, .{ .text = "1969-12-03" }, 1);
    try testing.expectEqualStrings("1969-12-04", b.text);
}

// ── expr ────────────────────────────────────────────────────────────────────

const expr = @import("expr.zig");
const Expr = df.Expr;

fn evalOne(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return df.mutate(a, f, &.{.{ .out = "o", .expr = e }});
}

test "expr: the node and depth caps are exact (mut 11011 11012 11014 11015)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ix(&.{1}, a);
    const kids = try a.alloc(Expr, expr.max_nodes);
    for (kids) |*k| k.* = .{ .lit = .null };
    kids[kids.len - 2] = .{ .lit = .{ .int = 5 } };
    const ok = try evalOne(a, f, .{ .coalesce = kids[0 .. kids.len - 1] });
    try expectCell(ok, 0, "o", .{ .int = 5 });
    try testing.expectError(error.ExprTooLarge, evalOne(a, f, .{ .coalesce = kids }));
    const nodes = try a.alloc(Expr, 300);
    nodes[0] = .{ .col = "x" };
    for (nodes[1..], 0..) |*n, i| n.* = .{ .unary = .{ .op = .neg, .x = &nodes[i] } };
    _ = try evalOne(a, f, nodes[255]);
    try testing.expectError(error.ExprTooLarge, evalOne(a, f, nodes[256]));
    try testing.expectError(error.ExprTooLarge, evalOne(a, f, nodes[299]));
}

test "expr: pad refuses fills that are not scalar values and widths past the cap (mut 11024 11025 11026 11027 11028)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const none = try st.mk(a, &.{.{ .name = "s", .type = .text }}, &.{});
    const col: Expr = .{ .col = "s" };
    for ([_]u21{ 0xD800, 0xDFFF, 0x110000 }) |fill| {
        try testing.expectError(error.BadExpr, evalOne(a, none, .{ .pad = .{ .x = &col, .width = 3, .fill = fill } }));
    }
    _ = try evalOne(a, none, .{ .pad = .{ .x = &col, .width = 3, .fill = 0xD7FF } });
    _ = try evalOne(a, none, .{ .pad = .{ .x = &col, .width = 3, .fill = 0xE000 } });
    _ = try evalOne(a, none, .{ .pad = .{ .x = &col, .width = df.max_text_result } });
    try testing.expectError(error.TooLarge, evalOne(a, none, .{ .pad = .{ .x = &col, .width = df.max_text_result + 1 } }));
}

test "expr: is_digit, strip, length of bytes that are not UTF-8, negating the smallest int (mut 11061 11064 11065 11066 11067 11068)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try txt(a, &.{ "12", "a1", "\r\x0bx\x0b\r", "\xff\xfe" });
    const col: Expr = .{ .col = "s" };
    const dg = try evalOne(a, f, .{ .unary = .{ .op = .is_digit, .x = &col } });
    try expectCell(dg, 0, "o", .{ .bool = true });
    try expectCell(dg, 1, "o", .{ .bool = false });
    const sp = try evalOne(a, f, .{ .unary = .{ .op = .strip, .x = &col } });
    try expectCell(sp, 2, "o", .{ .text = "x" });
    const ln = try evalOne(a, f, .{ .unary = .{ .op = .length, .x = &col } });
    try expectCell(ln, 3, "o", .{ .int = 2 });
    const m = try ix(&.{std.math.minInt(i64)}, a);
    const xc: Expr = .{ .col = "x" };
    const ng = try evalOne(a, m, .{ .unary = .{ .op = .neg, .x = &xc } });
    try expectCell(ng, 0, "o", .null);
    const ab = try evalOne(a, m, .{ .unary = .{ .op = .abs, .x = &xc } });
    try expectCell(ab, 0, "o", .null);
}

fn lit(v: Value) Expr {
    return .{ .lit = v };
}

fn bin(op: df.Binary, l: *const Expr, r: *const Expr) Expr {
    return .{ .binary = .{ .op = op, .l = l, .r = r } };
}

fn one(a: std.mem.Allocator, e: Expr) !Value {
    const f = try ix(&.{0}, a);
    const r = try evalOne(a, f, e);
    return r.cell(0, "o").?;
}

test "expr: cot, atan2 argument order, strip_suffix of a non-suffix (mut 11075 11090 11093)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f1 = lit(.{ .float = 1 });
    const c = try one(a, .{ .unary = .{ .op = .cot, .x = &f1 } });
    try testing.expectApproxEqAbs(@as(f64, 0.6420926159343306), c.float, 1e-12);
    const y = lit(.{ .int = 1 });
    const x = lit(.{ .int = 2 });
    const at = try one(a, bin(.atan2, &y, &x));
    try testing.expectApproxEqAbs(std.math.atan2(@as(f64, 1), 2), at.float, 1e-12);
    const abc = lit(.{ .text = "abc" });
    const nx = lit(.{ .text = "x" });
    const ss = try one(a, bin(.strip_suffix, &abc, &nx));
    try testing.expectEqualStrings("abc", ss.text);
}

test "expr: ties of min and max keep the left cell; int overflow is null (mut 11109 11110 11111 11112 11113 11115)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n1 = lit(.{ .int = 1 });
    const f1 = lit(.{ .float = 1 });
    try testing.expect((try one(a, bin(.min, &n1, &f1))) == .int);
    try testing.expect((try one(a, bin(.max, &n1, &f1))) == .int);
    const big = lit(.{ .int = std.math.maxInt(i64) });
    const small = lit(.{ .int = std.math.minInt(i64) });
    const two = lit(.{ .int = 2 });
    const neg1 = lit(.{ .int = -1 });
    try testing.expect((try one(a, bin(.add, &big, &n1))) == .null);
    try testing.expect((try one(a, bin(.sub, &small, &n1))) == .null);
    try testing.expect((try one(a, bin(.mul, &big, &two))) == .null);
    try testing.expect((try one(a, bin(.floordiv, &small, &neg1))) == .null);
}

test "expr: decimal arithmetic is exact, overflow is null, float mod by an infinity (mut 11119 11120 11123 11127)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d15 = lit(.{ .decimal = 1_500_000_000_000 });
    const n2 = lit(.{ .int = 2 });
    const s = try one(a, bin(.add, &d15, &n2));
    try testing.expectEqual(@as(i128, 3_500_000_000_000), s.decimal);
    const dd = try one(a, bin(.sub, &d15, &d15));
    try testing.expectEqual(@as(i128, 0), dd.decimal);
    const dmax = lit(.{ .decimal = std.math.maxInt(i128) });
    const d1 = lit(.{ .decimal = 1 });
    try testing.expect((try one(a, bin(.add, &dmax, &d1))) == .null);
    const z = lit(.{ .float = 0 });
    const ninf = lit(.{ .float = -std.math.inf(f64) });
    const m = try one(a, bin(.mod, &z, &ninf));
    try testing.expectEqual(@as(f64, 0), m.float);
}

test "expr: casts of text (mut 11136 11137 11138 11139 11140 11141)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cv = struct {
        fn f(al: std.mem.Allocator, t: []const u8, to: ColumnType) !Value {
            return df.castValue(al, .{ .text = t }, to);
        }
    }.f;
    try testing.expect((try cv(a, "1_000", .int)) == .null);
    try testing.expectEqual(@as(i64, 5), (try cv(a, " 5", .int)).int);
    try testing.expect((try cv(a, "12.9", .int)) == .null);
    try testing.expectEqual(true, (try cv(a, "TRUE", .bool)).bool);
    try testing.expectEqual(false, (try cv(a, "False", .bool)).bool);
    try testing.expectEqual(@as(f64, 1.5), (try cv(a, " 1.5 ", .float)).float);
}

test "expr: round of NaN is null, the text kernel only for an untyped plain predicate (mut 11147 11151 11152 11153 11154 11155 11162)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const fl = try fx(&.{nan}, a);
    const xc: Expr = .{ .col = "x" };
    const r = try evalOne(a, fl, .{ .round = .{ .x = &xc } });
    try expectCell(r, 0, "o", .null);
    const f = try txt(a, &.{ "abc", "xyz" });
    const col: Expr = .{ .col = "s" };
    const pat = lit(.{ .text = "a" });
    const has = bin(.contains, &col, &pat);
    const typed = try df.mutate(a, f, &.{.{ .out = "o", .expr = has, .type = .text }});
    try expectCell(typed, 0, "o", .{ .text = "true" });
    const not_has: Expr = .{ .unary = .{ .op = .not, .x = &has } };
    const nh = try evalOne(a, f, not_has);
    try expectCell(nh, 0, "o", .{ .bool = false });
    try expectCell(nh, 1, "o", .{ .bool = true });
    const abc = lit(.{ .text = "abc" });
    const b = lit(.{ .text = "b" });
    try testing.expectEqual(true, (try evalOne(a, f, bin(.contains, &abc, &b))).cell(0, "o").?.bool);
    try testing.expectEqual(true, (try evalOne(a, f, bin(.contains, &col, &col))).cell(0, "o").?.bool);
    const co: Expr = .{ .coalesce = &.{ col, pat } };
    try expectCell(try evalOne(a, f, co), 0, "o", .{ .text = "abc" });
    const nulls = try st.mk(a, &.{.{ .name = "s", .type = .text }}, &.{ &.{.null}, &.{.null} });
    const all_null = try evalOne(a, nulls, has);
    try testing.expectEqual(ColumnType.float, all_null.columnType("o").?);
}

test "expr: a NaN among a decimal and an int stays NaN (mut 11169)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cells = [_]Value{ .{ .decimal = 1_500_000_000_000 }, .{ .int = 2 }, .{ .float = std.math.nan(f64) } };
    const cols = [_]df.Column{.{ .name = "x", .type = .decimal }};
    const data = [_]df.ColumnData{try df.columnFromCells(a, &cells)};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 3 };
    const xc: Expr = .{ .col = "x" };
    const r = try evalOne(a, f, xc);
    try testing.expect(r.cell(2, "o").? == .float);
    try testing.expectEqual(@as(i128, 2_000_000_000_000), r.cell(1, "o").?.decimal);
}

// ── exprfn ──────────────────────────────────────────────────────────────────

const fnx = @import("exprfn.zig");

test "exprfn.round: huge scales, a decimal rounded at 10^38 (mut 12004 12008 12013)" {
    const r1 = fnx.round(.{ .float = 1.5 }, 320, .half_even);
    try testing.expectEqual(@as(f64, 1.5), r1.float);
    const r2 = fnx.round(.{ .float = 1e300 }, 10, .half_even);
    try testing.expectEqual(@as(f64, 1e300), r2.float);
    const raw: i128 = 70_000_000_000_000_000_000_000_000_000_000_000_000;
    const r3 = fnx.round(.{ .decimal = raw }, -26, .half_even);
    try testing.expectEqual(@as(i128, 100_000_000_000_000_000_000_000_000_000_000_000_000), r3.decimal);
}

test "exprfn.erf: known values on both sides of every switch (mut 12028 12030 12031 12032)" {
    try testing.expect(std.math.isNan(fnx.erf(std.math.nan(f64))));
    try testing.expectApproxEqAbs(@as(f64, 0.9927904292352575), fnx.erf(1.9), 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0.9661051464753108), fnx.erf(1.5), 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0.9999999999999926), fnx.erf(5.5), 1e-15);
    try testing.expectApproxEqAbs(@as(f64, -0.8427007929497149), fnx.erf(-1.0), 1e-15);
    try testing.expect(!std.math.signbit(fnx.erf(0)));
}

test "exprfn.isClose: an infinity and a number, a tolerance met exactly (mut 12039 12040 12042)" {
    const inf = std.math.inf(f64);
    try testing.expectEqual(false, fnx.isClose(.{ .float = inf }, .{ .float = 1 }, 1e-9, 0, false).bool);
    try testing.expectEqual(true, fnx.isClose(.{ .float = 1 }, .{ .float = 2 }, 0.5, 0, false).bool);
}

test "exprfn: pad, zfill and repeat reach exactly max_text_result (mut 12065 12066 12073 12074 12079 12080)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cap = fnx.max_text_result;
    try testing.expectEqual(cap, (try fnx.pad(a, "", cap, .left, ' ')).len);
    try testing.expectError(error.TooLarge, fnx.pad(a, "", cap + 1, .left, ' '));
    try testing.expectEqual(cap, (try fnx.zfill(a, "", @intCast(cap))).len);
    try testing.expectError(error.TooLarge, fnx.zfill(a, "", @intCast(cap + 1)));
    try testing.expectEqual(cap, (try fnx.repeat(a, "a", @intCast(cap))).len);
    try testing.expectError(error.TooLarge, fnx.repeat(a, "a", @intCast(cap + 1)));
}

test "exprfn: translate takes the first of a repeated source, title keeps non-ASCII as a letter, spaces of Python (mut 12091 12098 12103)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("x", try fnx.translate(a, "a", "aa", "xy", ""));
    try testing.expectEqualStrings("H\u{e9}llo", try fnx.title(a, "h\u{e9}llo"));
    try testing.expect(fnx.isClass("\x1c\x1f", .space));
}

test "exprfn: Python's istitle, a replacement that overflows through the tail, the last overlapping KMP match (mut 12104 12108 12120 12122 12126)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(!fnx.isClass("AB", .title));
    try testing.expect(fnx.isClass("Ab", .title));
    const cap = fnx.max_text_result;
    const big = try a.alloc(u8, cap);
    @memset(big, 'x');
    const exact = try fnx.replaceMany(a, "a", &.{"a"}, &.{big}, false);
    try testing.expectEqual(cap, exact.len);
    const short = try a.alloc(u8, cap - 5);
    @memset(short, 'x');
    try testing.expectError(error.TooLarge, fnx.replaceMany(a, "abbbbbbbbbb", &.{"a"}, &.{short}, false));
    const hay: [70]u8 = @splat('a');
    const needle: [65]u8 = @splat('a');
    try testing.expectEqual(@as(?usize, 5), try fnx.findLastIn(a, &hay, &needle));
}

// ── analysis ────────────────────────────────────────────────────────────────

fn colsFrame(a: std.mem.Allocator, cols: []const df.Column, rows: []const []const Value) !Frame {
    return st.mk(a, cols, rows);
}

test "horizontal: text counts as present for all/any, as missing for sum; ties keep the first (mut 15011 15013 15016 15017)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try colsFrame(a, &.{ .{ .name = "p", .type = .text }, .{ .name = "q", .type = .bool } }, &.{&.{ .{ .text = "a" }, .{ .bool = true } }});
    const all = try df.horizontal(a, t, .{ .func = .all, .out = "o" });
    try expectCell(all, 0, "o", .{ .bool = true });
    const mixed = try colsFrame(a, &.{ .{ .name = "p", .type = .text }, .{ .name = "q", .type = .int } }, &.{&.{ .{ .text = "a" }, .{ .int = 4 } }});
    const sum = try df.horizontal(a, mixed, .{ .func = .sum, .out = "o" });
    try expectCell(sum, 0, "o", .{ .float = 4 });
    const z = try colsFrame(a, &.{ .{ .name = "p", .type = .float }, .{ .name = "q", .type = .float } }, &.{&.{ .{ .float = 0.0 }, .{ .float = -0.0 } }});
    const mn = try df.horizontal(a, z, .{ .func = .min, .out = "o" });
    try testing.expect(!std.math.signbit(mn.cell(0, "o").?.float));
    const mx = try df.horizontal(a, z, .{ .func = .max, .out = "o" });
    try testing.expect(!std.math.signbit(mx.cell(0, "o").?.float));
}

test "horizontal: a float cell in int columns promotes; a decimal winner becomes float (mut 15030 15031)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cells = [_]Value{ .{ .int = 1 }, .{ .float = 2.5 } };
    const cols = [_]df.Column{ .{ .name = "p", .type = .int }, .{ .name = "q", .type = .int } };
    const data = [_]df.ColumnData{ try df.columnFromCells(a, &cells), try df.columnFromCells(a, &.{ Value{ .int = 1 }, Value{ .int = 1 } }) };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 2 };
    const r = try df.horizontal(a, f, .{ .func = .sum, .out = "o" });
    try testing.expectEqual(ColumnType.float, r.columnType("o").?);
    const dm = try colsFrame(a, &.{ .{ .name = "p", .type = .decimal }, .{ .name = "q", .type = .int } }, &.{&.{ .{ .decimal = 1_500_000_000_000 }, .{ .int = 3 } }});
    const mn = try df.horizontal(a, dm, .{ .func = .min, .out = "o" });
    try testing.expect(mn.cell(0, "o").? == .float);
}

test "fillNull: limits across a full word, mean of nothing, one of a decimal, a text column, short arrays (mut 15054 15038 15043 15045 15048)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = try a.alloc(f64, 129);
    for (vals, 0..) |*v, i| v.* = @floatFromInt(i);
    const valid = try a.dupe(u64, &.{ 1, ~@as(u64, 0), 0 });
    const cols = [_]df.Column{.{ .name = "x", .type = .float }};
    const data = [_]df.ColumnData{.{ .float = .{ .values = vals, .valid = valid } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 129 };
    const r = try df.fillNull(a, f, .{ .strategy = .forward, .limit = 2 });
    try expectCell(r, 128, "x", .{ .float = 127 });
    try expectCell(r, 3, "x", .null);
    const nn = try colsFrame(a, &.{.{ .name = "x", .type = .float }}, &.{ &.{.null}, &.{.null} });
    const m = try df.fillNull(a, nn, .{ .strategy = .mean });
    try expectCell(m, 0, "x", .null);
    const dn = try colsFrame(a, &.{.{ .name = "x", .type = .decimal }}, &.{ &.{.null}, &.{.{ .decimal = 5 }} });
    const one_ = try df.fillNull(a, dn, .{ .strategy = .one });
    try testing.expectEqual(@as(i128, 1_000_000_000_000), one_.cell(0, "x").?.decimal);
    const tx = try colsFrame(a, &.{.{ .name = "x", .type = .text }}, &.{ &.{.{ .text = "a" }}, &.{.null} });
    const tm = try df.fillNull(a, tx, .{ .strategy = .mean });
    try testing.expectEqual(ColumnType.text, tm.columnType("x").?);
    const short_vals = [_]f64{ 1, 2 };
    const sd = [_]df.ColumnData{.{ .float = .{ .values = &short_vals } }};
    const sf: Frame = .{ .columns = &cols, .data = &sd, .len = 4 };
    const sr = try df.fillNull(a, sf, .{ .strategy = .forward });
    try expectCell(sr, 3, "x", .{ .float = 2 });
}

test "replaceStrict: the first pair wins (mut 15063)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try ix(&.{1}, a);
    const r = try df.replaceStrict(a, f, .{ .col = "x", .pairs = &.{ .{ .from = .{ .int = 1 }, .to = .{ .int = 10 } }, .{ .from = .{ .int = 1 }, .to = .{ .int = 20 } } } });
    try expectCell(r, 0, "x", .{ .int = 10 });
}

test "argSort: then_by keeps its own direction; factorize and topK need columns; topK keep all with several keys (mut 15067 15073 15078 15083)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try colsFrame(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{ &.{ .{ .int = 1 }, .{ .int = 1 } }, &.{ .{ .int = 1 }, .{ .int = 2 } } });
    const o = try df.argSort(a, f, .{ .key = "x", .then_by = &.{.{ .key = "y", .dir = .desc }} });
    try testing.expectEqual(@as(u32, 1), o[0]);
    try testing.expectError(error.NoSuchColumn, df.factorize(a, f, .{ .cols = &.{} }));
    try testing.expectError(error.NoSuchColumn, df.topK(a, f, .{ .by = &.{}, .n = 1 }));
    const g = try colsFrame(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } }, &.{ &.{ .{ .int = 5 }, .{ .int = 1 } }, &.{ .{ .int = 5 }, .{ .int = 2 } } });
    const t = try df.topK(a, g, .{ .by = &.{ "a", "b" }, .n = 1, .keep = .all });
    try testing.expectEqual(@as(usize, 1), t.len);
}

test "topK over an int column longer than the frame claims (mut 15093)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = [_]i64{ 3, 5, 9 };
    const cols = [_]df.Column{.{ .name = "x", .type = .int }};
    const data = [_]df.ColumnData{.{ .int = .{ .values = &vals } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 2 };
    const t = try df.topK(a, f, .{ .by = &.{"x"}, .n = 1 });
    try testing.expectEqual(@as(usize, 1), t.len);
    try expectCell(t, 0, "x", .{ .int = 5 });
}

test "qcut: bins cap, probability bounds, NaN skipped, an existing output name (mut 15095 15096 15098 15099 15100 15101 15106)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const f = try fx(&.{ 1, 2, 3, 4, nan }, a);
    try testing.expectError(error.TooLarge, df.qcut(a, f, .{ .col = "x", .out = "b", .bins = (1 << 20) + 1 }));
    const many = try df.qcut(a, f, .{ .col = "x", .out = "b", .bins = 1 << 20 });
    try testing.expectEqual(@as(usize, 5), many.len);
    const ok = try df.qcut(a, f, .{ .col = "x", .out = "b", .probs = &.{ 0, 0.5, 1 } });
    try expectCell(ok, 0, "b", .{ .int = 0 });
    try expectCell(ok, 3, "b", .{ .int = 1 });
    try expectCell(ok, 4, "b", .null);
    try testing.expectError(error.BadEdges, df.qcut(a, f, .{ .col = "x", .out = "b", .probs = &.{ 0, 0.5, 0.5, 1 }, .duplicates = .drop }));
    try testing.expectError(error.DuplicateColumn, df.qcut(a, f, .{ .col = "x", .out = "x", .bins = 2 }));
}

test "expr compile: is_close tolerances, to_integer bases, replace_many with (mut 11022 11031 11033 11034)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fx(&.{1}, a);
    const xc: Expr = .{ .col = "x" };
    try testing.expectError(error.BadExpr, evalOne(a, f, .{ .is_close = .{ .l = &xc, .r = &xc, .abs_tol = -1 } }));
    const t = try txt(a, &.{"ab"});
    const sc: Expr = .{ .col = "s" };
    try testing.expectError(error.BadExpr, evalOne(a, t, .{ .to_integer = .{ .x = &sc, .base = 37 } }));
    try testing.expectError(error.BadExpr, evalOne(a, t, .{ .to_integer = .{ .x = &sc, .base = 1 } }));
    _ = try evalOne(a, t, .{ .to_integer = .{ .x = &sc, .base = 36 } });
    _ = try evalOne(a, t, .{ .to_integer = .{ .x = &sc, .base = 2 } });
    _ = try evalOne(a, t, .{ .replace_many = .{ .x = &sc, .patterns = &.{ "a", "b" }, .with = &.{"z"} } });
    _ = try evalOne(a, t, .{ .replace_many = .{ .x = &sc, .patterns = &.{ "a", "b" }, .with = &.{ "y", "z" } } });
    try testing.expectError(error.BadExpr, evalOne(a, t, .{ .replace_many = .{ .x = &sc, .patterns = &.{ "a", "b" }, .with = &.{ "y", "z", "w" } } }));
}

test "dtfn.truncate: weeks align to Monday only for whole weeks (mut 10677)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const day: i64 = 86_400_000_000;
    const r = try dtfn.truncate(a, .{ .int = 5 * day }, .{ .us = 8 * day, .weeks = 1 });
    try testing.expectEqual(@as(i64, 0), r.int);
}
