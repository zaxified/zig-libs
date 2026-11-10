// SPDX-License-Identifier: MIT
//! The binary column type (`ColumnType.binary`, cells `Value.text` holding bytes) and
//! `Expr.bin`, 2026-11-10. Expected values are polars 2.1's (probe run on the day; each test
//! names the call it quotes); where polars refuses (CSV, JSON, `==` against a text) the
//! answer is this module's own decision B1-B6 and the test says so. The sweep runs the public
//! verbs over a frame that holds a binary column.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const bf = @import("binfn.zig");
const verbs = @import("verbs.zig");
const render = @import("render.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const Expr = ex.Expr;

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

fn ci(x: i64) Value {
    return .{ .int = x };
}

fn bytes(s: []const u8) Value {
    return .{ .text = s };
}

/// polars: `pl.Series("b", [b"\x00ab", b"", None, b"\xff\xfe", b"hello"])`, plus `g` (int group),
/// `s` (text), `i` (int).
fn fixture(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{
        .{ .name = "b", .type = .binary },
        .{ .name = "g", .type = .int },
        .{ .name = "s", .type = .text },
        .{ .name = "i", .type = .int },
    });
    var fb = try fm.FrameBuilder.init(a, cols, 5);
    try fb.appendRow(&.{ bytes("\x00ab"), ci(1), .{ .text = "a" }, ci(10) });
    try fb.appendRow(&.{ bytes(""), ci(1), .{ .text = "b" }, ci(20) });
    try fb.appendRow(&.{ .null, ci(2), .{ .text = "a" }, ci(30) });
    try fb.appendRow(&.{ bytes("\xff\xfe"), ci(2), .null, ci(40) });
    try fb.appendRow(&.{ bytes("hello"), ci(2), .{ .text = "c" }, ci(50) });
    return fb.toOwned();
}

fn col(a: std.mem.Allocator, name: []const u8) !*const Expr {
    const p = try a.create(Expr);
    p.* = .{ .col = name };
    return p;
}

fn boxed(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

/// A binary literal: a text literal cast to `.binary`.
fn blit(a: std.mem.Allocator, s: []const u8) !*const Expr {
    const l = try boxed(a, .{ .lit = .{ .text = s } });
    return boxed(a, .{ .cast = .{ .x = l, .to = .binary } });
}

fn binop(a: std.mem.Allocator, x: []const u8, op: bf.BinOp) !Expr {
    return .{ .bin = .{ .x = try col(a, x), .op = op } };
}

fn mutate(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
}

fn expectCells(a: std.mem.Allocator, f: Frame, e: Expr, want: []const Value) !void {
    const out = try mutate(a, f, e);
    for (want, 0..) |w, r| {
        const got = out.cell(r, "o").?;
        if (!sameCell(w, got)) {
            std.debug.print("row {d}: want {any}, got {any}\n", .{ r, w, got });
            return error.TestExpectedEqual;
        }
    }
}

fn sameCell(w: Value, g: Value) bool {
    if (w == .null or g == .null) return w == .null and g == .null;
    return switch (w) {
        .text => g == .text and std.mem.eql(u8, w.text, g.text),
        .int => g == .int and g.int == w.int,
        .uint => g == .uint and g.uint == w.uint,
        .float => g == .float and (g.float == w.float or (std.math.isNan(w.float) and std.math.isNan(g.float))),
        .bool => g == .bool and g.bool == w.bool,
        else => false,
    };
}

fn outType(a: std.mem.Allocator, f: Frame, e: Expr) !ColumnType {
    return (try mutate(a, f, e)).columnType("o").?;
}

fn expectContains(hay: []const u8, needle: []const u8) !void {
    if (std.mem.find(u8, hay, needle) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ needle, hay });
        return error.TestUnexpectedResult;
    }
}

// ── B1, B5: the column, its display ─────────────────────────────────────────

test "B1 a binary column holds bytes in text storage; the cells read back" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try testing.expectEqual(ColumnType.binary, f.columnType("b").?);
    try testing.expect(f.columnAt(0) == .text);
    try testing.expectEqualStrings("\xff\xfe", f.cell(3, "b").?.text);
    try testing.expect(f.cell(2, "b").? == .null);
    try testing.expectEqual(@as(usize, 0), f.cell(1, "b").?.text.len);
}

test "B5 display: polars' b\"..\" form (printable ASCII 0x21-0x7e as is, every other byte \\xNN)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // polars: str(pl.DataFrame({"b": [b"\x00ab", b"", None, b"\xff\xfe", b"hello"]})) shows
    // b"\x00ab", b"", null, b"\xff\xfe", b"hello" under the dtype row `binary`.
    const f = try fixture(a);
    const shown = try df.format(a, try df.select(a, f, &.{"b"}), .{ .show_dtypes = true });
    try expectContains(shown, "binary");
    try expectContains(shown, "b\"\\x00ab\"");
    try expectContains(shown, "b\"\"");
    try expectContains(shown, "null");
    try expectContains(shown, "b\"\\xff\\xfe\"");
    try expectContains(shown, "b\"hello\"");
    // polars shows every byte outside 0x21..0x7e as \xNN (space is \x20), `"` and `\` raw.
    try testing.expectEqualStrings("b\"\\x09\\x0a\\x0d\\x20\\x7f\\x80\\xff\"", try bf.displayInto(a, "\t\n\r \x7f\x80\xff"));
    try testing.expectEqualStrings("b\"a\"\\|~!\"", try bf.displayInto(a, "a\"\\|~!"));
    // glimpse is Python's repr(bytes): probe `glimpse` of b"\x00\xff\"\\'" is b'\x00\xff"\\\''.
    try testing.expectEqualStrings("b'\\x00\\xff\"\\\\\\''", try bf.reprInto(a, "\x00\xff\"\\'"));
    try testing.expectEqualStrings("b\"it's\"", try bf.reprInto(a, "it's"));
    try testing.expectEqualStrings("b'\\t\\n\\r\\x7f \\x80~'", try bf.reprInto(a, "\t\n\r\x7f \x80~"));
    const g = try df.glimpse(a, try df.select(a, f, &.{"b"}), .{});
    try expectContains(g, "<binary>");
    try expectContains(g, "b'\\x00ab', b'', null, b'\\xff\\xfe', b'hello'");
    const md = try render.toMarkdown(a, try df.select(a, f, &.{"b"}), .{});
    try expectContains(md, "b\"hello\"");
}

// ── B2: order, equality, keys ───────────────────────────────────────────────

test "B2 sort, unique, group, join and min/max are bytewise (polars sort: None, b'', b'\\x00ab', b'hello', b'\\xff\\xfe')" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const s = try df.sort(a, f, .{ .key = "b", .missing = .first });
    try testing.expect(s.cell(0, "b").? == .null);
    try testing.expectEqualStrings("", s.cell(1, "b").?.text);
    try testing.expectEqualStrings("\x00ab", s.cell(2, "b").?.text);
    try testing.expectEqualStrings("hello", s.cell(3, "b").?.text);
    try testing.expectEqualStrings("\xff\xfe", s.cell(4, "b").?.text);
    try testing.expectEqual(ColumnType.binary, s.columnType("b").?);
    // polars: arg_sort descending puts the null first, then \xff\xfe.
    const d = try df.sort(a, f, .{ .key = "b", .dir = .desc });
    try testing.expectEqualStrings("\xff\xfe", d.cell(0, "b").?.text);

    const u = try df.distinct(a, try df.concat(a, &.{ f, f }, .vertical), .{ .keys = &.{"b"} });
    try testing.expectEqual(@as(usize, 5), u.len);
    try testing.expectEqual(ColumnType.binary, u.columnType("b").?);

    // polars: group_by("b").len().sort("b") has five groups of one, the null first.
    const g = try df.aggregate(a, f, .{ .group_by = &.{"b"}, .aggs = &.{.{ .src = "i", .out = "n", .func = .count }}, .sort_groups = true });
    try testing.expectEqual(@as(usize, 5), g.len);
    try testing.expectEqual(ColumnType.binary, g.columnType("b").?);

    // min / max: polars (b'', b'\xff\xfe')
    const mm = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{ .{ .src = "b", .out = "lo", .func = .min }, .{ .src = "b", .out = "hi", .func = .max }, .{ .src = "b", .out = "n", .func = .nunique } }, .sort_groups = true, .skip_na = true });
    try testing.expectEqual(ColumnType.binary, mm.columnType("lo").?);
    try testing.expectEqual(ColumnType.binary, mm.columnType("hi").?);
    // g = 1: b"\x00ab", b""; g = 2: None, b"\xff\xfe", b"hello"
    try testing.expectEqualStrings("", mm.cell(0, "lo").?.text);
    try testing.expectEqualStrings("\x00ab", mm.cell(0, "hi").?.text);
    try testing.expectEqualStrings("hello", mm.cell(1, "lo").?.text);
    try testing.expectEqualStrings("\xff\xfe", mm.cell(1, "hi").?.text);

    // polars: df.join(pl.DataFrame({"b": [b"hello"], "x": [1]}), on="b") is [(b"hello", 1)].
    const cols = try a.dupe(Column, &.{ .{ .name = "b", .type = .binary }, .{ .name = "x", .type = .int } });
    var rb = try fm.FrameBuilder.init(a, cols, 1);
    try rb.appendRow(&.{ bytes("hello"), ci(1) });
    const r = try rb.toOwned();
    const j = try df.join(a, f, r, .{ .on = "b", .how = .inner });
    try testing.expectEqual(@as(usize, 1), j.len);
    try testing.expectEqualStrings("hello", j.cell(0, "b").?.text);
    try testing.expectEqual(@as(i64, 1), j.cell(0, "x").?.int);
    // a null never joins
    try testing.expectEqual(@as(usize, 5), (try df.join(a, f, r, .{ .on = "b", .how = .left })).len);
}

test "B2 comparisons: binary with binary works, with a text or a number is BadExpr (polars SchemaError)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const b = try col(a, "b");
    // polars: (b < pl.Series([b"b"] * 5)) is [True, True, None, False, False]
    try expectCells(a, f, .{ .binary = .{ .op = .lt, .l = b, .r = try blit(a, "b") } }, &.{ .{ .bool = true }, .{ .bool = true }, .null, .{ .bool = false }, .{ .bool = false } });
    try expectCells(a, f, .{ .binary = .{ .op = .eq, .l = b, .r = try blit(a, "hello") } }, &.{ .{ .bool = false }, .{ .bool = false }, .null, .{ .bool = false }, .{ .bool = true } });
    // column against column
    try expectCells(a, f, .{ .binary = .{ .op = .eq, .l = b, .r = b } }, &.{ .{ .bool = true }, .{ .bool = true }, .null, .{ .bool = true }, .{ .bool = true } });
    // polars: s == b"hello" with s binary and the literal a text: SchemaError
    const text_lit = try boxed(a, .{ .lit = .{ .text = "hello" } });
    const int_lit = try boxed(a, .{ .lit = .{ .int = 1 } });
    const s = try col(a, "s");
    inline for (.{ ex.Binary.eq, .ne, .lt, .le, .gt, .ge, .eq_missing, .ne_missing }) |op| {
        try testing.expectError(error.BadExpr, mutate(a, f, .{ .binary = .{ .op = op, .l = b, .r = text_lit } }));
        try testing.expectError(error.BadExpr, mutate(a, f, .{ .binary = .{ .op = op, .l = int_lit, .r = b } }));
        try testing.expectError(error.BadExpr, mutate(a, f, .{ .binary = .{ .op = op, .l = b, .r = s } }));
    }
    // arithmetic, boolean logic and `concat` over binary are refused
    // (`add` of two binaries concatenates since Z3, polars `a + b`: `parity_z1_test.zig`)
    inline for (.{ ex.Binary.sub, .mul, .div, .concat, .contains, .starts_with, .@"and", .bit_and }) |op| {
        try testing.expectError(error.BadExpr, mutate(a, f, .{ .binary = .{ .op = op, .l = b, .r = try blit(a, "x") } }));
    }
    // filtering by a binary comparison keeps the rows
    const w = try df.where(a, f, &.{ .binary = .{ .op = .ge, .l = b, .r = try blit(a, "hello") } });
    try testing.expectEqual(@as(usize, 2), w.len);
    try testing.expectEqual(ColumnType.binary, w.columnType("b").?);
    // null tests, fill_null / coalesce and min/max stay
    try expectCells(a, f, .{ .unary = .{ .op = .is_null, .x = b } }, &.{ .{ .bool = false }, .{ .bool = false }, .{ .bool = true }, .{ .bool = false }, .{ .bool = false } });
    const fill = try mutate(a, f, .{ .coalesce = &.{ b.*, (try blit(a, "x")).* } });
    try testing.expectEqual(ColumnType.binary, fill.columnType("o").?);
    try testing.expectEqualStrings("x", fill.cell(2, "o").?.text);
    // polars: s.is_in([b"hello", b""]) is [False, True, None, False, True]
    try expectCells(a, f, .{ .is_in = .{ .x = b, .values = &.{ bytes("hello"), bytes("") } } }, &.{ .{ .bool = false }, .{ .bool = true }, .null, .{ .bool = false }, .{ .bool = true } });
}

// ── B3: casts ───────────────────────────────────────────────────────────────

test "B3 cast: text to binary is its UTF-8 bytes, binary to text is the bytes when valid UTF-8" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // polars: pl.Series(["ab", "é"]).cast(pl.Binary) is [b"ab", b"\xc3\xa9"]
    const cols = try a.dupe(Column, &.{.{ .name = "t", .type = .text }});
    var fb = try fm.FrameBuilder.init(a, cols, 3);
    try fb.appendRow(&.{.{ .text = "ab" }});
    try fb.appendRow(&.{.{ .text = "\u{e9}" }});
    try fb.appendRow(&.{.null});
    const t = try fb.toOwned();
    const bin = try df.cast(a, t, .{ .col = "t", .to = .binary });
    try testing.expectEqual(ColumnType.binary, bin.columnType("t").?);
    try testing.expectEqualStrings("\xc3\xa9", bin.cell(1, "t").?.text);
    try testing.expect(bin.cell(2, "t").? == .null);
    const back = try df.cast(a, bin, .{ .col = "t", .to = .text });
    try testing.expectEqual(ColumnType.text, back.columnType("t").?);
    try testing.expectEqualStrings("\u{e9}", back.cell(1, "t").?.text);

    // polars: b.cast(pl.String, strict=False) of the fixture is null for b"\xff\xfe" (strict:
    // ComputeError "invalid utf8"); b"\x00ab" is the NUL then "ab".
    const f = try fixture(a);
    const ts = try df.cast(a, f, .{ .col = "b", .to = .text });
    try testing.expectEqualStrings("\x00ab", ts.cell(0, "b").?.text);
    try testing.expect(ts.cell(3, "b").? == .null);
    try testing.expectEqualStrings("hello", ts.cell(4, "b").?.text);
    try testing.expectError(error.CastFailed, df.cast(a, f, .{ .col = "b", .to = .text, .on_error = .fail }));
    // the same through Expr.cast
    try expectCells(a, f, .{ .cast = .{ .x = try col(a, "b"), .to = .text } }, &.{ bytes("\x00ab"), bytes(""), .null, .null, bytes("hello") });
    try testing.expectEqual(ColumnType.text, try outType(a, f, .{ .cast = .{ .x = try col(a, "b"), .to = .text } }));
    // binary to binary is the identity; to anything else the cast has no answer
    const same = try df.cast(a, f, .{ .col = "b", .to = .binary });
    try testing.expect(df.equals(f, same));
    // polars: casting Binary to Int64 is InvalidOperationError ("not supported")
    const to_int = try df.cast(a, f, .{ .col = "b", .to = .int });
    for (0..5) |r| try testing.expect(to_int.cell(r, "b").? == .null);
    try testing.expectError(error.CastFailed, df.cast(a, f, .{ .col = "b", .to = .int, .on_error = .fail }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .cast = .{ .x = try col(a, "b"), .to = .int } }));
    // polars: pl.Series([1, 2]).cast(pl.Binary) is [b"1", b"2"]
    const ints = try df.cast(a, f, .{ .col = "i", .to = .binary });
    try testing.expectEqualStrings("10", ints.cell(0, "i").?.text);
    try testing.expectEqual(ColumnType.binary, ints.columnType("i").?);
}

// ── B4: Expr.bin ────────────────────────────────────────────────────────────

test "B4 contains, starts_with, ends_with, size (polars bin.*)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const t: Value = .{ .bool = true };
    const fl: Value = .{ .bool = false };
    // polars: contains(b"a") [True, False, None, False, False]
    try expectCells(a, f, try binop(a, "b", .{ .contains = "a" }), &.{ t, fl, .null, fl, fl });
    // starts_with(b"\x00") [True, False, None, False, False]
    try expectCells(a, f, try binop(a, "b", .{ .starts_with = "\x00" }), &.{ t, fl, .null, fl, fl });
    // ends_with(b"o") [False, False, None, False, True]
    try expectCells(a, f, try binop(a, "b", .{ .ends_with = "o" }), &.{ fl, fl, .null, fl, t });
    // an empty pattern: polars contains(b"") and starts_with(b"") are True for every present cell
    try expectCells(a, f, try binop(a, "b", .{ .contains = "" }), &.{ t, t, .null, t, t });
    try expectCells(a, f, try binop(a, "b", .{ .starts_with = "" }), &.{ t, t, .null, t, t });
    // size: [3, 0, None, 2, 5], UInt32
    try expectCells(a, f, try binop(a, "b", .{ .size = .b }), &.{ ci(3), ci(0), .null, ci(2), ci(5) });
    try testing.expectEqual(ColumnType.uint32, try outType(a, f, try binop(a, "b", .{ .size = .b })));
    // size("kb") [0.0029296875, 0.0, None, 0.001953125, 0.0048828125], Float64
    try expectCells(a, f, try binop(a, "b", .{ .size = .kb }), &.{ .{ .float = 0.0029296875 }, .{ .float = 0 }, .null, .{ .float = 0.001953125 }, .{ .float = 0.0048828125 } });
    try testing.expectEqual(ColumnType.float, try outType(a, f, try binop(a, "b", .{ .size = .kb })));
    // 2048 bytes: mb 0.001953125, gb 1.9073486328125e-06, tb 1.862645149230957e-09
    const big = try a.alloc(u8, 2048);
    @memset(big, 'a');
    try testing.expectEqual(@as(f64, 0.001953125), (try bf.cell(a, big, .{ .size = .mb })).float);
    try testing.expectEqual(@as(f64, 1.9073486328125e-06), (try bf.cell(a, big, .{ .size = .gb })).float);
    try testing.expectEqual(@as(f64, 1.862645149230957e-09), (try bf.cell(a, big, .{ .size = .tb })).float);
}

test "B4 get, head, tail, slice (polars bin.*)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    // get(1, null_on_oob=True) [97, None, None, 254, 101]; UInt8
    try expectCells(a, f, try binop(a, "b", .{ .get = 1 }), &.{ ci(97), .null, .null, ci(254), ci(101) });
    try testing.expectEqual(ColumnType.uint8, try outType(a, f, try binop(a, "b", .{ .get = 1 })));
    // get(-1) [98, None, None, 254, 111]
    try expectCells(a, f, try binop(a, "b", .{ .get = -1 }), &.{ ci(98), .null, .null, ci(254), ci(111) });
    // head(2) [b"\x00a", b"", None, b"\xff\xfe", b"he"]
    try expectCells(a, f, try binop(a, "b", .{ .head = 2 }), &.{ bytes("\x00a"), bytes(""), .null, bytes("\xff\xfe"), bytes("he") });
    try testing.expectEqual(ColumnType.binary, try outType(a, f, try binop(a, "b", .{ .head = 2 })));
    // tail(2) [b"ab", b"", None, b"\xff\xfe", b"lo"]
    try expectCells(a, f, try binop(a, "b", .{ .tail = 2 }), &.{ bytes("ab"), bytes(""), .null, bytes("\xff\xfe"), bytes("lo") });
    // slice(1, 2) [b"ab", b"", None, b"\xfe", b"el"]
    try expectCells(a, f, try binop(a, "b", .{ .slice = .{ .offset = 1, .length = 2 } }), &.{ bytes("ab"), bytes(""), .null, bytes("\xfe"), bytes("el") });
    // head(-1) [b"\x00a", b"", None, b"\xff", b"hell"], tail(-1) [b"ab", b"", None, b"\xfe", b"ello"]
    try expectCells(a, f, try binop(a, "b", .{ .head = -1 }), &.{ bytes("\x00a"), bytes(""), .null, bytes("\xff"), bytes("hell") });
    try expectCells(a, f, try binop(a, "b", .{ .tail = -1 }), &.{ bytes("ab"), bytes(""), .null, bytes("\xfe"), bytes("ello") });
    // head(0) is empty, head(10) the whole cell
    try expectCells(a, f, try binop(a, "b", .{ .head = 0 }), &.{ bytes(""), bytes(""), .null, bytes(""), bytes("") });
    try expectCells(a, f, try binop(a, "b", .{ .head = 10 }), &.{ bytes("\x00ab"), bytes(""), .null, bytes("\xff\xfe"), bytes("hello") });
    // slice(-2) [b"ab", b"", None, b"\xff\xfe", b"lo"]; slice(-2, 1) [b"a", b"", None, b"\xff", b"l"]
    try expectCells(a, f, try binop(a, "b", .{ .slice = .{ .offset = -2 } }), &.{ bytes("ab"), bytes(""), .null, bytes("\xff\xfe"), bytes("lo") });
    try expectCells(a, f, try binop(a, "b", .{ .slice = .{ .offset = -2, .length = 1 } }), &.{ bytes("a"), bytes(""), .null, bytes("\xff"), bytes("l") });
}

test "B4 get/head/tail/slice on b'abc', None, b'' (polars probe, incl. clamping)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const abc = "abc";
    const U = ?u64;
    const slices = [_]struct { o: i64, l: U, want: []const u8 }{
        .{ .o = -10, .l = 5, .want = "" }, // polars slice(-10, 5): [b'', None, b'']
        .{ .o = -4, .l = 2, .want = "a" },
        .{ .o = -4, .l = 3, .want = "ab" },
        .{ .o = -4, .l = 4, .want = "abc" },
        .{ .o = -3, .l = 2, .want = "ab" },
        .{ .o = 1, .l = 100, .want = "bc" },
        .{ .o = 3, .l = 1, .want = "" },
        .{ .o = 2, .l = null, .want = "c" },
        .{ .o = -1, .l = null, .want = "c" },
        .{ .o = 0, .l = 0, .want = "" },
        .{ .o = -10, .l = null, .want = "abc" },
        .{ .o = std.math.minInt(i64), .l = 5, .want = "" },
        .{ .o = 1 << 62, .l = 5, .want = "" },
        .{ .o = 1, .l = std.math.maxInt(u64), .want = "bc" },
        .{ .o = std.math.minInt(i64), .l = std.math.maxInt(u64), .want = "abc" },
    };
    for (slices) |s| {
        const got = try bf.cell(a, abc, .{ .slice = .{ .offset = s.o, .length = s.l } });
        try testing.expectEqualStrings(s.want, got.text);
    }
    const heads = [_]struct { n: i64, head: []const u8, tail: []const u8 }{
        .{ .n = -4, .head = "", .tail = "" },
        .{ .n = -3, .head = "", .tail = "" },
        .{ .n = -1, .head = "ab", .tail = "bc" },
        .{ .n = 0, .head = "", .tail = "" },
        .{ .n = 1, .head = "a", .tail = "c" },
        .{ .n = 3, .head = "abc", .tail = "abc" },
        .{ .n = 4, .head = "abc", .tail = "abc" },
        .{ .n = 1 << 40, .head = "abc", .tail = "abc" },
        .{ .n = -(1 << 40), .head = "", .tail = "" },
        .{ .n = std.math.minInt(i64), .head = "", .tail = "" },
        .{ .n = std.math.maxInt(i64), .head = "abc", .tail = "abc" },
    };
    for (heads) |h| {
        try testing.expectEqualStrings(h.head, (try bf.cell(a, abc, .{ .head = h.n })).text);
        try testing.expectEqualStrings(h.tail, (try bf.cell(a, abc, .{ .tail = h.n })).text);
    }
    const gets = [_]struct { i: i64, want: ?i64 }{
        .{ .i = 0, .want = 97 },
        .{ .i = 2, .want = 99 },
        .{ .i = 3, .want = null },
        .{ .i = -3, .want = 97 },
        .{ .i = -4, .want = null },
        .{ .i = 1 << 40, .want = null },
        .{ .i = -(1 << 40), .want = null },
        .{ .i = std.math.minInt(i64), .want = null },
        .{ .i = std.math.maxInt(i64), .want = null },
    };
    for (gets) |g| {
        const got = try bf.cell(a, abc, .{ .get = g.i });
        if (g.want) |w| try testing.expectEqual(w, got.int) else try testing.expect(got == .null);
    }
    // an empty cell: every op answers, none panics
    try testing.expect((try bf.cell(a, "", .{ .get = 0 })) == .null);
    try testing.expectEqual(@as(usize, 0), (try bf.cell(a, "", .{ .slice = .{ .offset = -1, .length = 9 } })).text.len);
}

test "B4 encode hex and base64, str.decode gives binary (polars encode / str.decode)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    // encode("hex") ['006162', '', None, 'fffe', '68656c6c6f']; encode("base64") ['AGFi', '', None, '//4=', 'aGVsbG8=']
    try expectCells(a, f, try binop(a, "b", .{ .encode = .hex }), &.{ bytes("006162"), bytes(""), .null, bytes("fffe"), bytes("68656c6c6f") });
    try expectCells(a, f, try binop(a, "b", .{ .encode = .base64 }), &.{ bytes("AGFi"), bytes(""), .null, bytes("//4="), bytes("aGVsbG8=") });
    try testing.expectEqual(ColumnType.text, try outType(a, f, try binop(a, "b", .{ .encode = .hex })));

    // pl.Series(["0061", "zz", None]).str.decode("hex", strict=False) is [b"\x00a", None, None], Binary
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .text }});
    var fb = try fm.FrameBuilder.init(a, cols, 5);
    for ([_]?[]const u8{ "0061", "zz", null, "4A4b", "" }) |t| try fb.appendRow(&.{if (t) |s| Value{ .text = s } else .null});
    const t = try fb.toOwned();
    const hex: Expr = .{ .decode = .{ .x = try col(a, "x"), .how = .hex } };
    try testing.expectEqual(ColumnType.binary, try outType(a, t, hex));
    try expectCells(a, t, hex, &.{ bytes("\x00a"), .null, .null, bytes("JK"), bytes("") });
    // pl.Series(["/w==", "aGk=", "aGk", "!!"]).str.decode("base64", strict=False): [b"\xff", b"hi", None, None]
    var fb2 = try fm.FrameBuilder.init(a, cols, 4);
    for ([_][]const u8{ "/w==", "aGk=", "aGk", "!!" }) |s| try fb2.appendRow(&.{.{ .text = s }});
    const t2 = try fb2.toOwned();
    try expectCells(a, t2, .{ .decode = .{ .x = try col(a, "x"), .how = .base64 } }, &.{ bytes("\xff"), bytes("hi"), .null, .null });
    // decode then encode is the identity on valid input; decode of a binary is refused
    const round = try mutate(a, t2, .{ .bin = .{ .x = try boxed(a, .{ .decode = .{ .x = try col(a, "x"), .how = .base64 } }), .op = .{ .encode = .base64 } } });
    try testing.expectEqualStrings("/w==", round.cell(0, "o").?.text);
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .decode = .{ .x = try col(a, "b"), .how = .hex } }));
}

test "B4 reinterpret (polars bin.reinterpret: exact width, little endian default, null otherwise)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // polars: pl.Series([b"\x01\x00\x00\x00", b"\x02\x00"]).bin.reinterpret(dtype=pl.Int32, endianness="little") is [1, None]
    const cols = try a.dupe(Column, &.{.{ .name = "b", .type = .binary }});
    var fb = try fm.FrameBuilder.init(a, cols, 4);
    for ([_]?[]const u8{ "\x01\x00\x00\x00", "\x02\x00", null, "\xff\xff\xff\xff" }) |t| try fb.appendRow(&.{if (t) |s| bytes(s) else .null});
    const f = try fb.toOwned();
    try expectCells(a, f, try binop(a, "b", .{ .reinterpret = .{ .to = .int32 } }), &.{ ci(1), .null, .null, ci(-1) });
    try testing.expectEqual(ColumnType.int32, try outType(a, f, try binop(a, "b", .{ .reinterpret = .{ .to = .int32 } })));
    try expectCells(a, f, try binop(a, "b", .{ .reinterpret = .{ .to = .uint32 } }), &.{ ci(1), .null, .null, ci(4294967295) });
    // big endian: pl.Series([b"\x00\x00\x00\x01"]).bin.reinterpret(dtype=pl.Int32, endianness="big") is [1]
    try testing.expectEqual(@as(i64, 1), (try bf.cell(a, "\x00\x00\x00\x01", .{ .reinterpret = .{ .to = .int32, .big_endian = true } })).int);
    // every width, on b"\x01" * n and b"\xff" * n (polars probe: Int8 [1, -1], UInt8 [1, 255], Int16 [257, -1],
    // UInt16 [257, 65535], Int32 [16843009, -1], UInt32 [16843009, 4294967295], Int64 [72340172838076673, -1],
    // UInt64 [72340172838076673, 18446744073709551615], Float32 [2.3694278276172396e-38, nan],
    // Float64 [7.748604185489348e-304, nan]); a cell of another length is null
    const Case = struct { to: ColumnType, n: usize, one: Value, ff: Value };
    const cases = [_]Case{
        .{ .to = .int8, .n = 1, .one = ci(1), .ff = ci(-1) },
        .{ .to = .uint8, .n = 1, .one = ci(1), .ff = ci(255) },
        .{ .to = .int16, .n = 2, .one = ci(257), .ff = ci(-1) },
        .{ .to = .uint16, .n = 2, .one = ci(257), .ff = ci(65535) },
        .{ .to = .int32, .n = 4, .one = ci(16843009), .ff = ci(-1) },
        .{ .to = .uint32, .n = 4, .one = ci(16843009), .ff = ci(4294967295) },
        .{ .to = .int, .n = 8, .one = ci(72340172838076673), .ff = ci(-1) },
        .{ .to = .uint64, .n = 8, .one = ci(72340172838076673), .ff = .{ .uint = std.math.maxInt(u64) } },
        .{ .to = .float32, .n = 4, .one = .{ .float = 2.3694278276172396e-38 }, .ff = .{ .float = std.math.nan(f64) } },
        .{ .to = .float, .n = 8, .one = .{ .float = 7.748604185489348e-304 }, .ff = .{ .float = std.math.nan(f64) } },
    };
    for (cases) |c| {
        var one: [9]u8 = @splat(1);
        var ff: [9]u8 = @splat(0xff);
        try testing.expect(sameCell(c.one, try bf.cell(a, one[0..c.n], .{ .reinterpret = .{ .to = c.to } })));
        try testing.expect(sameCell(c.ff, try bf.cell(a, ff[0..c.n], .{ .reinterpret = .{ .to = c.to } })));
        try testing.expect((try bf.cell(a, one[0 .. c.n + 1], .{ .reinterpret = .{ .to = c.to } })) == .null);
        try testing.expect((try bf.cell(a, "", .{ .reinterpret = .{ .to = c.to } })) == .null);
    }
    // polars: pl.Series([b"\x00\x00\x00\x00\x00\x00\xf0\x3f"]).bin.reinterpret(dtype=pl.Float64) is [1.0]
    try testing.expectEqual(@as(f64, 1.0), (try bf.cell(a, "\x00\x00\x00\x00\x00\x00\xf0\x3f", .{ .reinterpret = .{ .to = .float } })).float);
    // polars: Boolean and String are InvalidOperationError ("only numeric or temporal dtype")
    try testing.expectError(error.BadExpr, mutate(a, f, try binop(a, "b", .{ .reinterpret = .{ .to = .bool } })));
    try testing.expectError(error.BadExpr, mutate(a, f, try binop(a, "b", .{ .reinterpret = .{ .to = .text } })));
    // a UInt64 above Int64's top is a UInt64 column
    var fb3 = try fm.FrameBuilder.init(a, cols, 1);
    try fb3.appendRow(&.{bytes("\xff\xff\xff\xff\xff\xff\xff\xff")});
    const u = try mutate(a, try fb3.toOwned(), try binop(a, "b", .{ .reinterpret = .{ .to = .uint64 } }));
    try testing.expectEqual(ColumnType.uint64, u.columnType("o").?);
    try testing.expectEqual(std.math.maxInt(u64), u.cell(0, "o").?.uint);
}

test "B4 bin on a text, numeric or missing operand is BadExpr; on a binary expression it works" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    // polars: s.str.len_chars() over Binary is SchemaError; the reverse (bin.* over String) too
    try testing.expectError(error.BadExpr, mutate(a, f, try binop(a, "s", .{ .size = .b })));
    try testing.expectError(error.BadExpr, mutate(a, f, try binop(a, "i", .{ .contains = "a" })));
    try testing.expectError(error.NoSuchColumn, mutate(a, f, try binop(a, "nope", .{ .size = .b })));
    // a binary produced by an expression: cast of a text, head of a binary, if_else of binaries
    try expectCells(a, f, .{ .bin = .{ .x = try blit(a, "abc"), .op = .{ .size = .b } } }, &.{ ci(3), ci(3), ci(3), ci(3), ci(3) });
    const head = try boxed(a, try binop(a, "b", .{ .head = 1 }));
    try expectCells(a, f, .{ .bin = .{ .x = head, .op = .{ .size = .b } } }, &.{ ci(1), ci(0), .null, ci(1), ci(1) });
    const cond = try boxed(a, .{ .binary = .{ .op = .gt, .l = try col(a, "i"), .r = try boxed(a, .{ .lit = ci(25) }) } });
    const pick: Expr = .{ .if_else = .{ .cond = cond, .then = try col(a, "b"), .otherwise = try blit(a, "x") } };
    try testing.expectEqual(ColumnType.binary, try outType(a, f, pick));
    // `with_columns` of a text expression over a binary value is refused
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .concat_str = .{ .parts = &.{ (try col(a, "b")).*, (try col(a, "s")).* } } }));
}

// ── B5: CSV and JSON ────────────────────────────────────────────────────────

test "B5 CSV writes base64 and reads it back with types = binary; bad base64 is BadValue" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    var out: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &out.writer, try df.select(a, f, &.{ "b", "i" }), .{});
    // polars refuses CSV for Binary (ComputeError "cannot be written to CSV"), pandas writes reprs;
    // here base64, so the file reads back to the same bytes.
    const text = out.written();
    try expectContains(text, "AGFi");
    try expectContains(text, "//4=");
    try expectContains(text, "aGVsbG8=");
    const back = try df.readCsv(a, text, .{ .types = &.{.{ .name = "b", .type = .binary }} });
    try testing.expectEqual(ColumnType.binary, back.columnType("b").?);
    try testing.expectEqual(@as(usize, 5), back.len);
    try testing.expectEqualStrings("\x00ab", back.cell(0, "b").?.text);
    try testing.expectEqualStrings("\xff\xfe", back.cell(3, "b").?.text);
    try testing.expectEqualStrings("hello", back.cell(4, "b").?.text);
    try testing.expect(back.cell(2, "b").? == .null);
    try testing.expect(back.columnAt(0) == .text);
    // bad base64: a character outside the alphabet, missing padding, whitespace
    inline for (.{ "b\n!!!!\n", "b\naGk\n", "b\n\"aG k=\"\n", "b\n====\n" }) |bad| {
        try testing.expectError(error.BadValue, df.readCsv(a, bad, .{ .types = &.{.{ .name = "b", .type = .binary }} }));
    }
    // without the override a base64 column is plain text
    const plain = try df.readCsv(a, text, .{});
    try testing.expectEqual(ColumnType.text, plain.columnType("b").?);
}

test "B5 JSON writes a base64 string (polars panics, Go writes []byte as base64) and reads it back" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try df.select(a, try fixture(a), &.{"b"});
    var out: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&out.writer, f, .records);
    try testing.expectEqualStrings("[{\"b\":\"AGFi\"},{\"b\":\"\"},{\"b\":null},{\"b\":\"//4=\"},{\"b\":\"aGVsbG8=\"}]", out.written());
    const back = try df.readJson(a, out.written(), .{ .types = &.{.{ .name = "b", .type = .binary }} });
    try testing.expectEqual(ColumnType.binary, back.columnType("b").?);
    try testing.expect(df.equals(f, back));
    // ndjson, table schema (type string with contentEncoding), columns orient
    var nd: std.Io.Writer.Allocating = .init(a);
    try df.writeNdjson(&nd.writer, f);
    try expectContains(nd.written(), "{\"b\":\"//4=\"}\n");
    var tb: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&tb.writer, f, .table);
    try expectContains(tb.written(), "\"type\":\"string\",\"contentEncoding\":\"base64\"");
    // a number, a bool or bad base64 where bytes are declared
    inline for (.{ "[{\"b\":1}]", "[{\"b\":true}]", "[{\"b\":\"!!\"}]", "[{\"b\":\"aGk\"}]" }) |bad| {
        try testing.expectError(error.BadValue, df.readJson(a, bad, .{ .types = &.{.{ .name = "b", .type = .binary }} }));
    }
}

// ── sweep: every verb keeps `.binary` ──────────────────────────────────────

/// Every `.binary` column of `f` holds text storage or no storage, and `b` is one.
fn kept(f: Frame) !void {
    for (f.columns, 0..) |c, k| {
        if (std.mem.eql(u8, c.name, "b")) try testing.expectEqual(ColumnType.binary, c.type);
        if (c.type != .binary) continue;
        switch (f.columnAt(k)) {
            .text, .nulls => {},
            else => return error.BinaryNotText,
        }
    }
}

/// Like `kept` for a result where `b` may be gone or retyped.
fn valid(f: Frame) !void {
    for (f.columns, 0..) |c, k| {
        if (c.type != .binary) continue;
        switch (f.columnAt(k)) {
            .text, .nulls => {},
            else => return error.BinaryNotText,
        }
    }
}

fn side(a: std.mem.Allocator) !Frame {
    const cols = try a.dupe(Column, &.{ .{ .name = "b", .type = .binary }, .{ .name = "r", .type = .int }, .{ .name = "g", .type = .int } });
    var fb = try fm.FrameBuilder.init(a, cols, 3);
    try fb.appendRow(&.{ bytes("\x00ab"), ci(1), ci(1) });
    try fb.appendRow(&.{ bytes("hello"), ci(2), ci(2) });
    try fb.appendRow(&.{ bytes("zz"), ci(3), ci(3) });
    return fb.toOwned();
}

test "B6 sweep: the public verbs keep the binary type and every cell bytes in text storage" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    try kept(f);
    const r = try side(a);

    try kept(try verbs.takeRows(a, f, &.{ 4, 0, 0, 3 }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "i", .op = .ge, .value = ci(20) }} }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "b", .op = .is_null }} }));
    try kept(try df.filter(a, f, .{ .where = &.{.{ .col = "b", .op = .eq, .value = bytes("hello") }} }));
    try kept(try df.distinct(a, f, .{ .keys = &.{} }));
    try kept(try df.distinct(a, f, .{ .keys = &.{"b"}, .keep = .last }));
    try kept(try df.sort(a, f, .{ .key = "b" }));
    try kept(try df.sort(a, f, .{ .key = "b", .dir = .desc, .missing = .last, .then_by = &.{.{ .key = "i" }} }));
    try kept(try df.dropna(a, f, .{ .subset = &.{"b"} }));
    try kept(try df.dropna(a, f, .{}));
    try kept(try df.fillna(a, f, .{ .subset = &.{"b"}, .value = bytes("x") }));
    try kept(try df.select(a, f, &.{ "i", "b" }));
    try kept(try df.drop(a, f, &.{"s"}));
    try kept(try df.page(a, f, .{ .offset = 1, .limit = 3 }));
    try kept(try df.tail(a, f, 2));
    try kept(try df.clone(a, f));
    try kept(try df.clear(a, f, 3));
    try kept(try df.take(a, f, &.{ 0, -1, 2, 2 }));
    try kept(try df.gatherEvery(a, f, 2, 1));
    try kept(try df.reverse(a, f));
    try kept(try df.concat(a, &.{ f, f }, .vertical));
    try kept(try df.concat(a, &.{ f, f }, .diagonal));
    try kept(try df.concatByName(a, &.{ f, f }));
    inline for (.{ .forward, .backward }) |st| {
        try kept(try df.fillNull(a, f, .{ .subset = &.{"b"}, .strategy = st }));
    }
    try kept(try df.topN(a, f, .{ .n = 2 }));
    inline for (.{ .inner, .left, .right, .full, .semi, .anti }) |how| {
        const j = try df.join(a, f, r, .{ .on = "b", .how = how });
        try valid(j);
        const k = try df.join(a, f, r, .{ .on = "g", .how = how, .coalesce_keys = true });
        try valid(k);
    }
    try testing.expectEqual(@as(usize, 2), (try df.join(a, f, r, .{ .on = "b", .how = .inner })).len);
    try valid(try df.join(a, f, try df.drop(a, r, &.{"b"}), .{ .how = .cross }));
    {
        const g = try df.aggregate(a, f, .{ .group_by = &.{"b"}, .aggs = &.{.{ .src = "i", .out = "n", .func = .sum }}, .sort_groups = true });
        try testing.expectEqual(ColumnType.binary, g.columnType("b").?);
        try valid(g);
        const g2 = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{ .{ .src = "b", .out = "lo", .func = .min }, .{ .src = "b", .out = "hi", .func = .max }, .{ .src = "b", .out = "fi", .func = .first }, .{ .src = "b", .out = "la", .func = .last }, .{ .src = "b", .out = "uq", .func = .nunique }, .{ .src = "b", .out = "n", .func = .count } } });
        for ([_][]const u8{ "lo", "hi", "fi", "la" }) |c| try testing.expectEqual(ColumnType.binary, g2.columnType(c).?);
        try valid(g2);
        const v = try df.valueCounts(a, f, .{ .cols = &.{"b"} });
        try testing.expectEqual(ColumnType.binary, v.columnType("b").?);
        try valid(v);
        const u = try df.unpivot(a, f, .{ .id_cols = &.{"b"}, .value_cols = &.{"i"} });
        try testing.expectEqual(ColumnType.binary, u.columnType("b").?);
        try valid(u);
        // bytes melted with numbers: not all cells are bytes, the value column is not `.binary`
        const un2 = try df.unpivot(a, f, .{ .id_cols = &.{"i"}, .value_cols = &.{ "b", "g" } });
        try valid(un2);
        try testing.expect(un2.columnType("value").? != .binary);
        const un3 = try df.unpivot(a, r, .{ .id_cols = &.{"g"}, .value_cols = &.{"b"} });
        try testing.expectEqual(ColumnType.binary, un3.columnType("value").?);
        const p = try df.pivot(a, f, .{ .row_key = "g", .col_key = "s", .value_col = "b", .agg = .first });
        try valid(p);
        const p2 = try df.pivot(a, f, .{ .row_key = "b", .col_key = "s", .value_col = "i", .agg = .first });
        try valid(p2);
    }
    {
        const w = try df.window(a, f, .{ .value_col = "i", .out = "o", .op = .cum_sum, .partition_by = &.{"b"} });
        try kept(w);
        const w2 = try df.window(a, f, .{ .value_col = "b", .out = "o", .op = .{ .shift = .{ .n = -1 } }, .partition_by = &.{"g"}, .order_by = &.{"i"} });
        try kept(w2);
        try testing.expectEqual(ColumnType.binary, w2.columnType("o").?);
    }
    // through expressions and casts
    {
        const b = try col(a, "b");
        const c = try mutate(a, f, .{ .coalesce = &.{ b.*, b.* } });
        try testing.expectEqual(ColumnType.binary, c.columnType("o").?);
        try valid(c);
        const h = try mutate(a, f, try binop(a, "b", .{ .head = 1 }));
        try testing.expectEqual(ColumnType.binary, h.columnType("o").?);
        try valid(h);
        const tx = try df.cast(a, f, .{ .col = "b", .to = .text });
        try testing.expectEqual(ColumnType.text, tx.columnType("b").?);
        const to_bin = try df.cast(a, tx, .{ .col = "b", .to = .binary });
        try kept(to_bin);
    }
    {
        const tr = try df.transpose(a, try df.select(a, f, &.{"b"}), .{});
        try valid(tr);
        const rr = try df.repeatRows(a, f, .{ .times = 2 });
        try kept(rr);
        const d = try df.describeWith(a, f, .{ .cols = &.{ "b", "i" } });
        try valid(d);
        _ = try df.info(a, f);
        try testing.expect(df.hasNulls(f));
        try testing.expect(df.equals(f, try df.clone(a, f)));
        try testing.expect(!df.equals(f, try df.reverse(a, f)));
    }
}

// ── hostile inputs ──────────────────────────────────────────────────────────

/// Every text-only `Expr` arm over `x`.
fn strOps(a: std.mem.Allocator, x: *const Expr) ![]const Expr {
    const pats: []const []const u8 = &.{ "a", "\xff" };
    const parts = try a.dupe(Expr, &.{ x.*, x.* }); // the heap: the result outlives this frame
    return a.dupe(Expr, &.{
        .{ .unary = .{ .op = .lower, .x = x } },
        .{ .unary = .{ .op = .upper, .x = x } },
        .{ .unary = .{ .op = .strip, .x = x } },
        .{ .unary = .{ .op = .length, .x = x } },
        .{ .unary = .{ .op = .len_bytes, .x = x } },
        .{ .unary = .{ .op = .reverse, .x = x } },
        .{ .unary = .{ .op = .is_alpha, .x = x } },
        .{ .unary = .{ .op = .casefold, .x = x } },
        .{ .unary = .{ .op = .unaccent, .x = x } },
        .{ .unary = .{ .op = .title, .x = x } },
        .{ .binary = .{ .op = .contains, .l = x, .r = x } },
        .{ .binary = .{ .op = .find, .l = x, .r = x } },
        .{ .binary = .{ .op = .concat, .l = x, .r = x } },
        .{ .binary = .{ .op = .char_at, .l = x, .r = x } },
        .{ .replace = .{ .x = x, .from = "a", .to = "b" } },
        .{ .pad = .{ .x = x, .width = 4 } },
        .{ .slice = .{ .x = x, .offset = 1, .length = 2 } },
        .{ .strip_chars = .{ .x = x, .chars = "a" } },
        .{ .translate = .{ .x = x, .from = "a", .to = "b" } },
        .{ .to_integer = .{ .x = x } },
        .{ .contains_any = .{ .x = x, .patterns = pats } },
        .{ .replace_many = .{ .x = x, .patterns = pats, .with = &.{ "1", "2" } } },
        .{ .extract_many = .{ .x = x, .patterns = pats } },
        .{ .find_many = .{ .x = x, .patterns = pats } },
        .{ .strptime = .{ .x = x, .format = "%Y" } },
        .{ .to_datetime = .{ .x = x } },
        .{ .contains_regex = .{ .x = x, .pattern = "a" } },
        .{ .extract = .{ .x = x, .pattern = "(a)" } },
        .{ .count_regex = .{ .x = x, .pattern = "a" } },
        .{ .find_regex = .{ .x = x, .pattern = "a" } },
        .{ .replace_regex = .{ .x = x, .pattern = "a", .with = "b" } },
        .{ .split = .{ .x = x, .by = "a" } },
        .{ .split_regex = .{ .x = x, .pattern = "a" } },
        .{ .extract_all = .{ .x = x, .pattern = "a" } },
        .{ .extract_groups = .{ .x = x, .pattern = "(a)" } },
        .{ .split_ws = .{ .x = x } },
        .{ .rsplit = .{ .x = x, .by = "a" } },
        .{ .partition = .{ .x = x, .sep = "a" } },
        .{ .split_fields = .{ .x = x, .by = "a", .n = 2 } },
        .{ .wrap = .{ .x = x, .width = 3 } },
        .{ .slice_replace = .{ .x = x, .start = 0, .stop = 1, .with = "z" } },
        .{ .encode = .{ .x = x, .how = .hex } },
        .{ .decode = .{ .x = x, .how = .hex } },
        .{ .affix_any = .{ .x = x, .patterns = pats } },
        .{ .replace_n = .{ .x = x, .from = "a", .to = "b", .n = 1 } },
        .{ .match_regex = .{ .x = x, .pattern = "a" } },
        .{ .normalize = .{ .x = x } },
        .{ .concat_str = .{ .parts = parts } },
    });
}

test "hostile: every str operation over a binary operand is BadExpr; over text with invalid UTF-8 it answers or errors, never panics" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    // The text column holds the same bytes the binary column does, `\xff\xfe` and a NUL included.
    const cols = try a.dupe(Column, &.{.{ .name = "t", .type = .text }});
    var fb = try fm.FrameBuilder.init(a, cols, 7);
    for ([_][]const u8{ "\x00ab", "", "\xff\xfe", "hello", "\xed\xa0\x80", "\xc3", "a\xffb" }) |s| try fb.appendRow(&.{.{ .text = s }});
    const t = try fb.toOwned();
    var refused: usize = 0;
    for (try strOps(a, try col(a, "b"))) |e| {
        try testing.expectError(error.BadExpr, mutate(a, f, e));
        refused += 1;
    }
    // behind a cast, a head, a decode: still bytes
    const hd = try boxed(a, try binop(a, "b", .{ .head = 2 }));
    for (try strOps(a, hd)) |e| try testing.expectError(error.BadExpr, mutate(a, f, e));
    const bl = try blit(a, "x\xff");
    for (try strOps(a, bl)) |e| try testing.expectError(error.BadExpr, mutate(a, f, e));
    try testing.expect(refused >= 40);
    // text with invalid bytes: no panic through any of them
    var answered: usize = 0;
    for (try strOps(a, try col(a, "t"))) |e| {
        if (mutate(a, t, e)) |_| answered += 1 else |_| {}
    }
    try testing.expect(answered > 20);
    // unary ops over a binary: only the null tests
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .unary = .{ .op = .neg, .x = try col(a, "b") } }));
    try testing.expectError(error.BadExpr, mutate(a, f, .{ .unary = .{ .op = .not, .x = try col(a, "b") } }));
}

test "hostile: huge offsets, counts and indexes through Expr.bin and the cell function" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try fixture(a);
    const ops = [_]bf.BinOp{
        .{ .get = std.math.minInt(i64) },
        .{ .get = std.math.maxInt(i64) },
        .{ .head = std.math.minInt(i64) },
        .{ .head = std.math.maxInt(i64) },
        .{ .tail = std.math.minInt(i64) },
        .{ .tail = std.math.maxInt(i64) },
        .{ .slice = .{ .offset = std.math.minInt(i64), .length = std.math.maxInt(u64) } },
        .{ .slice = .{ .offset = std.math.maxInt(i64), .length = std.math.maxInt(u64) } },
        .{ .slice = .{ .offset = std.math.minInt(i64), .length = 0 } },
        .{ .slice = .{ .offset = -1, .length = std.math.maxInt(u64) } },
        .{ .contains = "" },
        .{ .contains = "a very long pattern that is longer than any cell here" },
        .{ .reinterpret = .{ .to = .uint64, .big_endian = true } },
    };
    for (ops) |op| {
        const out = try mutate(a, f, .{ .bin = .{ .x = try col(a, "b"), .op = op } });
        try valid(out);
    }
    // a non-text cell under a bin op (a hand-built frame with an int in a binary column) is null
    try testing.expect(df.Value.cast(.{ .int = 1 }, .binary) == null);
}

test "hostile: a binary column holding something that is not bytes never panics" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const cols = try a.dupe(Column, &.{ .{ .name = "b", .type = .binary }, .{ .name = "g", .type = .int } });
    var fb = try fm.FrameBuilder.init(a, cols, 4);
    try fb.appendRow(&.{ ci(5), ci(1) });
    try fb.appendRow(&.{ .{ .float = 1.5 }, ci(1) });
    try fb.appendRow(&.{ .{ .bool = true }, ci(2) });
    try fb.appendRow(&.{ bytes("x"), ci(2) });
    const f = try fb.toOwned();
    _ = df.format(a, f, .{}) catch {};
    _ = df.glimpse(a, f, .{}) catch {};
    var out: std.Io.Writer.Allocating = .init(a);
    df.writeCsv(a, &out.writer, f, .{}) catch {};
    df.writeJson(&out.writer, f, .records) catch {};
    _ = df.cast(a, f, .{ .col = "b", .to = .text }) catch {};
    _ = df.sort(a, f, .{ .key = "b" }) catch {};
    _ = df.distinct(a, f, .{ .keys = &.{"b"} }) catch {};
    _ = mutate(a, f, .{ .bin = .{ .x = try col(a, "b"), .op = .{ .size = .b } } }) catch {};
    _ = mutate(a, f, .{ .bin = .{ .x = try col(a, "b"), .op = .{ .encode = .hex } } }) catch {};
}

test "review H1/M2 2026-11-10: binary typing is bounded on a shared DAG; binary beside text is Binary (polars)" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const cols = try a.dupe(df.Column, &.{
        .{ .name = "c", .type = .bool },
        .{ .name = "b", .type = .binary },
        .{ .name = "s", .type = .text },
        .{ .name = "i", .type = .int },
        .{ .name = "l", .type = .list, .inner = &.{.{ .name = "", .type = .text }} },
    });
    const lists = try fm.columnFromCells(a, &.{ .null, .null });
    const data = try a.dupe(df.ColumnData, &.{
        try fm.columnFromCells(a, &.{ .{ .bool = true }, .{ .bool = false } }),
        try fm.columnFromCells(a, &.{ .{ .text = "\xff" }, .{ .text = "a" } }),
        try fm.columnFromCells(a, &.{ .{ .text = "x" }, .{ .text = "y" } }),
        try fm.columnFromCells(a, &.{ .{ .int = 1 }, .{ .int = 2 } }),
        lists,
    });
    const f: Frame = .{ .columns = cols, .data = data, .len = 2 };
    // H1: a 60-level DAG (both branches the same node) under `list.first`, inside `replace`:
    // 2^60 schema steps before the fix; now it compiles at once (an error or a column).
    var y: df.Expr = .{ .col = "l" };
    const cond: df.Expr = .{ .col = "c" };
    for (0..60) |_| {
        const node = try a.create(df.Expr);
        node.* = y;
        y = .{ .if_else = .{ .cond = &cond, .then = node, .otherwise = node } };
    }
    const first: df.Expr = .{ .list = .{ .x = &y, .op = .first } };
    _ = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .replace = .{ .x = &first, .from = "a", .to = "b" } } }}) catch {};
    // M2: polars `when(c).then(bin).otherwise(str)` is Binary; `.otherwise(int)` a SchemaError.
    const cb: df.Expr = .{ .col = "b" };
    const cs: df.Expr = .{ .col = "s" };
    const c_i: df.Expr = .{ .col = "i" };
    const g = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .if_else = .{ .cond = &cond, .then = &cb, .otherwise = &cs } } }});
    try testing.expectEqual(df.ColumnType.binary, g.columnType("r").?);
    try testing.expectEqualStrings("\xff", g.cell(0, "r").?.text);
    try testing.expectEqualStrings("y", g.cell(1, "r").?.text);
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .if_else = .{ .cond = &cond, .then = &cb, .otherwise = &c_i } } }}));
    const co = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .coalesce = &.{ cb, cs } } }});
    try testing.expectEqual(df.ColumnType.binary, co.columnType("r").?);
    try testing.expectError(error.BadExpr, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .coalesce = &.{ cb, c_i } } }}));
    const mn = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = .min, .l = &cb, .r = &cs } } }});
    try testing.expectEqual(df.ColumnType.binary, mn.columnType("r").?);
}
