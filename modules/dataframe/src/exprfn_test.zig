// SPDX-License-Identifier: MIT
//! The element functions added to `Expr` after the move, each through `mutate` on a
//! one-row frame. Expected values: numpy/pandas/polars documented results and Python's
//! `str` methods (not run here; the reference values of `erf` are the C library's).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Expr = df.Expr;

const X: Expr = .{ .col = "x" };
const Y: Expr = .{ .col = "y" };

/// `e` over a one-row frame with `x` and `y`.
fn run(a: std.mem.Allocator, x: Value, y: Value, e: Expr) !Value {
    const f = try st.mk(a, &.{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } }, &.{&.{ x, y }});
    const g = try df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
    return g.cell(0, "out").?;
}

fn un(a: std.mem.Allocator, op: df.Unary, x: Value) !Value {
    return run(a, x, .null, .{ .unary = .{ .op = op, .x = &X } });
}

fn bin(a: std.mem.Allocator, op: df.Binary, x: Value, y: Value) !Value {
    return run(a, x, y, .{ .binary = .{ .op = op, .l = &X, .r = &Y } });
}

fn expectV(want: Value, got: Value) !void {
    if (!st.same(got, want)) {
        std.debug.print("got {any}, want {any}\n", .{ got, want });
        return error.TestUnexpectedResult;
    }
}

fn txt(t: []const u8) Value {
    return .{ .text = t };
}

fn rnd(a: std.mem.Allocator, x: Value, d: i32, mode: df.RoundMode) !Value {
    return run(a, x, .null, .{ .round = .{ .x = &X, .decimals = d, .mode = mode } });
}

test "round(decimals): half to even as numpy, exact for ints and decimals" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(.{ .float = 2 }, try rnd(a, .{ .float = 2.5 }, 0, .half_even));
    try expectV(.{ .float = 4 }, try rnd(a, .{ .float = 3.5 }, 0, .half_even));
    try expectV(.{ .float = -2 }, try rnd(a, .{ .float = -2.5 }, 0, .half_even));
    try expectV(.{ .float = 3 }, try rnd(a, .{ .float = 2.5 }, 0, .half_away));
    try expectV(.{ .float = -3 }, try rnd(a, .{ .float = -2.5 }, 0, .half_away));
    // The binary 2.675 is below the tie, but `2.675 * 100` rounds to 267.5 exactly:
    // the scaling numpy and polars do gives 2.68 (Python's decimal `round` gives 2.67).
    try expectV(.{ .float = 2.68 }, try rnd(a, .{ .float = 2.675 }, 2, .half_even));
    try expectV(.{ .float = 0.12 }, try rnd(a, .{ .float = 0.125 }, 2, .half_even));
    try expectV(.{ .float = 1200 }, try rnd(a, .{ .float = 1234.5678 }, -2, .half_even));
    try expectV(.{ .float = std.math.inf(f64) }, try rnd(a, .{ .float = std.math.inf(f64) }, 2, .half_even));
    try expectV(.{ .float = 1e300 }, try rnd(a, .{ .float = 1e300 }, 400, .half_even));
    try expectV(.{ .int = 20 }, try rnd(a, .{ .int = 25 }, -1, .half_even));
    try expectV(.{ .int = 40 }, try rnd(a, .{ .int = 35 }, -1, .half_even));
    try expectV(.{ .int = -20 }, try rnd(a, .{ .int = -25 }, -1, .half_even));
    try expectV(.{ .int = -30 }, try rnd(a, .{ .int = -25 }, -1, .half_away));
    try expectV(.{ .int = 7 }, try rnd(a, .{ .int = 7 }, 3, .half_even));
    try expectV(.{ .int = 0 }, try rnd(a, .{ .int = 7 }, -30, .half_even));
    try expectV(.null, try rnd(a, .{ .int = std.math.maxInt(i64) }, -1, .half_even));
    const s = df.decimal_scale;
    try expectV(.{ .decimal = @divExact(124 * s, 100) }, try rnd(a, .{ .decimal = @divExact(1235 * s, 1000) }, 2, .half_even));
    try expectV(.{ .decimal = @divExact(122 * s, 100) }, try rnd(a, .{ .decimal = @divExact(1225 * s, 1000) }, 2, .half_even));
    try expectV(.{ .decimal = @divExact(123 * s, 100) }, try rnd(a, .{ .decimal = @divExact(12345 * s, 10000) }, 2, .half_even));
    try expectV(.null, try rnd(a, .null, 2, .half_even));
    try expectV(.null, try rnd(a, txt("1"), 2, .half_even));
}

test "round_sig_figs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sig = struct {
        fn f(al: std.mem.Allocator, x: Value, d: u32) !Value {
            return run(al, x, .null, .{ .round_sig_figs = .{ .x = &X, .digits = d } });
        }
    }.f;
    try expectV(.{ .float = 1200 }, try sig(a, .{ .float = 1234.5 }, 2));
    try expectV(.{ .float = 0.0123 }, try sig(a, .{ .float = 0.012345 }, 3));
    try expectV(.{ .float = -0.0123 }, try sig(a, .{ .float = -0.012345 }, 3));
    try expectV(.{ .int = 1200 }, try sig(a, .{ .int = 1234 }, 2));
    try expectV(.{ .float = 0 }, try sig(a, .{ .float = 0 }, 2));
    try testing.expectError(error.BadExpr, sig(a, .{ .float = 1 }, 0));
}

test "math functions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(.{ .float = 0.8427007929497149 }, try un(a, .erf, .{ .float = 1 }));
    try expectV(.{ .float = 0.5204998778130465 }, try un(a, .erf, .{ .float = 0.5 }));
    try expectV(.{ .float = 0.9953222650189527 }, try un(a, .erf, .{ .float = 2 }));
    try expectV(.{ .float = 0.9995930479825550 }, try un(a, .erf, .{ .float = 2.5 }));
    try expectV(.{ .float = 0.9999779095030014 }, try un(a, .erf, .{ .float = 3 }));
    try expectV(.{ .float = -0.8427007929497149 }, try un(a, .erf, .{ .float = -1 }));
    try expectV(.{ .float = 1 }, try un(a, .erf, .{ .float = 7 }));
    try expectV(.{ .float = 0 }, try un(a, .erf, .{ .int = 0 }));
    try expectV(.{ .float = 180 }, try un(a, .degrees, .{ .float = std.math.pi }));
    try expectV(.{ .float = std.math.pi }, try un(a, .radians, .{ .int = 180 }));
    try expectV(.{ .float = 3 }, try un(a, .cbrt, .{ .int = 27 }));
    try expectV(.{ .float = 1 }, try un(a, .cot, .{ .float = std.math.pi / 4.0 }));
    try expectV(.{ .float = 0 }, try un(a, .sin, .{ .int = 0 }));
    try expectV(.{ .float = std.math.pi / 2.0 }, try un(a, .asin, .{ .int = 1 }));
    try expectV(.{ .float = 3 }, try un(a, .log2, .{ .int = 8 }));
    try expectV(.{ .float = 0 }, try un(a, .log1p, .{ .int = 0 }));
    try expectV(.{ .float = 0 }, try un(a, .acosh, .{ .int = 1 }));
    try expectV(.null, try un(a, .tanh, txt("x")));
    try expectV(.{ .float = 3 }, try bin(a, .log_base, .{ .int = 8 }, .{ .int = 2 }));
    try expectV(.{ .float = std.math.pi / 4.0 }, try bin(a, .atan2, .{ .int = 1 }, .{ .int = 1 }));
}

test "NaN tests, eq_missing, fill_nan, is_close" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan: Value = .{ .float = std.math.nan(f64) };
    const inf: Value = .{ .float = std.math.inf(f64) };
    try expectV(.{ .bool = true }, try un(a, .is_nan, nan));
    try expectV(.{ .bool = false }, try un(a, .is_nan, .{ .int = 1 }));
    try expectV(.null, try un(a, .is_nan, .null));
    try expectV(.{ .bool = false }, try un(a, .is_not_nan, nan));
    try expectV(.{ .bool = false }, try un(a, .is_finite, inf));
    try expectV(.{ .bool = true }, try un(a, .is_finite, .{ .int = 3 }));
    try expectV(.{ .bool = true }, try un(a, .is_infinite, inf));
    try expectV(.null, try un(a, .is_infinite, txt("inf")));

    try expectV(.{ .bool = true }, try bin(a, .eq_missing, .null, .null));
    try expectV(.{ .bool = true }, try bin(a, .eq_missing, nan, .null));
    try expectV(.{ .bool = false }, try bin(a, .eq_missing, .{ .int = 1 }, .null));
    try expectV(.{ .bool = true }, try bin(a, .eq_missing, .{ .int = 1 }, .{ .float = 1 }));
    try expectV(.{ .bool = false }, try bin(a, .eq_missing, .{ .int = 1 }, txt("1")));
    try expectV(.{ .bool = true }, try bin(a, .ne_missing, .{ .int = 1 }, .null));
    try expectV(.{ .float = 0 }, try bin(a, .fill_nan, nan, .{ .float = 0 }));
    try expectV(.null, try bin(a, .fill_nan, .null, .{ .float = 0 }));
    try expectV(.{ .float = 2 }, try bin(a, .fill_nan, .{ .float = 2 }, .{ .float = 0 }));

    const close = struct {
        fn f(al: std.mem.Allocator, x: Value, y: Value, rel: f64, abs: f64, ne: bool) !Value {
            return run(al, x, y, .{ .is_close = .{ .l = &X, .r = &Y, .rel_tol = rel, .abs_tol = abs, .nans_equal = ne } });
        }
    }.f;
    try expectV(.{ .bool = true }, try close(a, .{ .float = 1 }, .{ .float = 1 + 1e-10 }, 1e-9, 0, false));
    try expectV(.{ .bool = false }, try close(a, .{ .float = 1 }, .{ .float = 1.1 }, 1e-9, 0, false));
    try expectV(.{ .bool = true }, try close(a, .{ .float = 1 }, .{ .float = 1.1 }, 1e-9, 0.2, false));
    try expectV(.{ .bool = true }, try close(a, inf, inf, 1e-9, 0, false));
    try expectV(.{ .bool = false }, try close(a, nan, nan, 1e-9, 0, false));
    try expectV(.{ .bool = true }, try close(a, nan, nan, 1e-9, 0, true));
    try expectV(.null, try close(a, .null, .{ .int = 1 }, 1e-9, 0, false));
    try testing.expectError(error.BadExpr, close(a, .null, .null, -1, 0, false));
}

test "bitwise" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(.{ .int = 3 }, try un(a, .count_ones, .{ .int = 7 }));
    try expectV(.{ .int = 64 }, try un(a, .count_ones, .{ .int = -1 }));
    try expectV(.{ .int = 61 }, try un(a, .count_zeros, .{ .int = 7 }));
    try expectV(.{ .int = 63 }, try un(a, .leading_zeros, .{ .int = 1 }));
    try expectV(.{ .int = 3 }, try un(a, .trailing_zeros, .{ .int = 8 }));
    try expectV(.{ .int = 2 }, try un(a, .trailing_ones, .{ .int = 3 }));
    try expectV(.{ .int = 64 }, try un(a, .leading_ones, .{ .int = -1 }));
    try expectV(.{ .int = -1 }, try un(a, .bit_not, .{ .int = 0 }));
    try expectV(.null, try un(a, .bit_not, .{ .float = 1 }));
    try expectV(.{ .int = 8 }, try bin(a, .bit_and, .{ .int = 12 }, .{ .int = 10 }));
    try expectV(.{ .int = 14 }, try bin(a, .bit_or, .{ .int = 12 }, .{ .int = 10 }));
    try expectV(.{ .int = 6 }, try bin(a, .bit_xor, .{ .int = 12 }, .{ .int = 10 }));
    try expectV(.null, try bin(a, .bit_and, .{ .int = 12 }, .null));
}

test "plain string methods" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(txt("Hello world"), try un(a, .capitalize, txt("hELLO wORLD")));
    try expectV(txt("Hello World-X2Y"), try un(a, .title, txt("hello wOrld-x2y")));
    try expectV(txt("hELLO"), try un(a, .swapcase, txt("Hello")));
    try expectV(txt("olléh"), try un(a, .reverse, txt("héllo")));
    try expectV(.{ .int = 2 }, try un(a, .len_bytes, txt("é")));
    try expectV(.{ .int = 1 }, try un(a, .length, txt("é")));
    try expectV(.{ .bool = true }, try un(a, .is_alpha, txt("abc")));
    try expectV(.{ .bool = false }, try un(a, .is_alpha, txt("ab1")));
    try expectV(.{ .bool = false }, try un(a, .is_alpha, txt("")));
    try expectV(.{ .bool = true }, try un(a, .is_digit, txt("042")));
    try expectV(.{ .bool = true }, try un(a, .is_alnum, txt("a1")));
    try expectV(.{ .bool = true }, try un(a, .is_space, txt(" \t\n")));
    try expectV(.{ .bool = true }, try un(a, .is_lower, txt("abc1")));
    try expectV(.{ .bool = false }, try un(a, .is_lower, txt("123")));
    try expectV(.{ .bool = true }, try un(a, .is_upper, txt("AB C")));
    try expectV(.{ .bool = true }, try un(a, .is_title, txt("Hello World")));
    try expectV(.{ .bool = false }, try un(a, .is_title, txt("Hello world")));
    try expectV(txt("ab  "), try un(a, .lstrip, txt("  ab  ")));
    try expectV(txt("  ab"), try un(a, .rstrip, txt("  ab  ")));

    try expectV(txt("cd"), try bin(a, .strip_prefix, txt("abcd"), txt("ab")));
    try expectV(txt("abcd"), try bin(a, .strip_prefix, txt("abcd"), txt("x")));
    try expectV(txt("ab"), try bin(a, .strip_suffix, txt("abcd"), txt("cd")));
    try expectV(.{ .int = 2 }, try bin(a, .find, txt("hello"), txt("l")));
    try expectV(.{ .int = 3 }, try bin(a, .rfind, txt("hello"), txt("l")));
    try expectV(.null, try bin(a, .find, txt("hello"), txt("z")));
    try expectV(.{ .int = 2 }, try bin(a, .count_matches, txt("aaaa"), txt("aa")));
    try expectV(.{ .int = 4 }, try bin(a, .count_matches, txt("abc"), txt("")));
    try expectV(txt("ababab"), try bin(a, .repeat, txt("ab"), .{ .int = 3 }));
    try expectV(txt(""), try bin(a, .repeat, txt("ab"), .{ .int = -1 }));
    try testing.expectError(error.TooLarge, bin(a, .repeat, txt("ab"), .{ .int = std.math.maxInt(i64) }));
    try expectV(txt("hel"), try bin(a, .head, txt("hello"), .{ .int = 3 }));
    try expectV(txt("hel"), try bin(a, .head, txt("hello"), .{ .int = -2 }));
    try expectV(txt("lo"), try bin(a, .tail, txt("hello"), .{ .int = 2 }));
    try expectV(txt("llo"), try bin(a, .tail, txt("hello"), .{ .int = -2 }));
    try expectV(txt(""), try bin(a, .tail, txt("hello"), .{ .int = -9 }));
    try expectV(txt(""), try bin(a, .tail, txt("hello"), .{ .int = std.math.minInt(i64) }));
    try expectV(txt(""), try bin(a, .head, txt("hello"), .{ .int = std.math.minInt(i64) }));
    try expectV(txt("hello"), try bin(a, .head, txt("hello"), .{ .int = std.math.maxInt(i64) }));
    try expectV(.null, try bin(a, .char_at, txt("hello"), .{ .int = std.math.minInt(i64) }));
    try expectV(txt("-0042"), try bin(a, .zfill, txt("-42"), .{ .int = 5 }));
    try expectV(txt("abc"), try bin(a, .zfill, txt("abc"), .{ .int = 2 }));
    try testing.expectError(error.TooLarge, bin(a, .zfill, txt("1"), .{ .int = 1 << 40 }));
    try expectV(txt("é"), try bin(a, .char_at, txt("héllo"), .{ .int = 1 }));
    try expectV(txt("o"), try bin(a, .char_at, txt("héllo"), .{ .int = -1 }));
    try expectV(.null, try bin(a, .char_at, txt("héllo"), .{ .int = 5 }));
}

test "pad, slice, strip_chars, translate, to_integer, contains_any, replace_many" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(txt("***ab"), try run(a, txt("ab"), .null, .{ .pad = .{ .x = &X, .width = 5, .fill = '*' } }));
    try expectV(txt("ab   "), try run(a, txt("ab"), .null, .{ .pad = .{ .x = &X, .width = 5, .side = .right } }));
    // CPython: 'ab'.center(5, '*') == '**ab*', 'a'.center(4, '*') == '*a**'.
    try expectV(txt("**ab*"), try run(a, txt("ab"), .null, .{ .pad = .{ .x = &X, .width = 5, .side = .both, .fill = '*' } }));
    try expectV(txt("*a**"), try run(a, txt("a"), .null, .{ .pad = .{ .x = &X, .width = 4, .side = .both, .fill = '*' } }));
    try expectV(txt("ééx"), try run(a, txt("x"), .null, .{ .pad = .{ .x = &X, .width = 3, .fill = 0xe9 } }));
    try expectV(txt("long"), try run(a, txt("long"), .null, .{ .pad = .{ .x = &X, .width = 2 } }));
    try testing.expectError(error.BadExpr, run(a, txt("x"), .null, .{ .pad = .{ .x = &X, .width = 2, .fill = 0xD800 } }));

    try expectV(txt("ll"), try run(a, txt("hello"), .null, .{ .slice = .{ .x = &X, .offset = -3, .length = 2 } }));
    try expectV(txt("éllo"), try run(a, txt("héllo"), .null, .{ .slice = .{ .x = &X, .offset = 1 } }));
    try expectV(txt(""), try run(a, txt("hello"), .null, .{ .slice = .{ .x = &X, .offset = 9 } }));
    try expectV(txt("he"), try run(a, txt("hello"), .null, .{ .slice = .{ .x = &X, .offset = -99, .length = 2 } }));

    try expectV(txt("hi"), try run(a, txt("xxhixy"), .null, .{ .strip_chars = .{ .x = &X, .chars = "xy" } }));
    try expectV(txt("hixy"), try run(a, txt("xxhixy"), .null, .{ .strip_chars = .{ .x = &X, .chars = "xy", .side = .start } }));
    try expectV(txt("ééa"), try run(a, txt("ééaé"), .null, .{ .strip_chars = .{ .x = &X, .chars = "é", .side = .end } }));
    try expectV(txt("a b"), try run(a, txt(" a b\t"), .null, .{ .strip_chars = .{ .x = &X } }));

    try expectV(txt("hippo"), try run(a, txt("hello"), .null, .{ .translate = .{ .x = &X, .from = "el", .to = "ip" } }));
    try expectV(txt("heo"), try run(a, txt("hello"), .null, .{ .translate = .{ .x = &X, .from = "", .to = "", .delete = "l" } }));
    try testing.expectError(error.BadExpr, run(a, txt("x"), .null, .{ .translate = .{ .x = &X, .from = "ab", .to = "c" } }));

    try expectV(.{ .int = 255 }, try run(a, txt("ff"), .null, .{ .to_integer = .{ .x = &X, .base = 16 } }));
    try expectV(.{ .int = -5 }, try run(a, txt("-101"), .null, .{ .to_integer = .{ .x = &X, .base = 2 } }));
    try expectV(.null, try run(a, txt("1_0"), .null, .{ .to_integer = .{ .x = &X } }));
    try expectV(.null, try run(a, txt("0x10"), .null, .{ .to_integer = .{ .x = &X, .base = 16 } }));
    try expectV(.null, try run(a, txt("99999999999999999999"), .null, .{ .to_integer = .{ .x = &X } }));
    try testing.expectError(error.BadExpr, run(a, txt("1"), .null, .{ .to_integer = .{ .x = &X, .base = 1 } }));

    try expectV(.{ .bool = true }, try run(a, txt("Hello"), .null, .{ .contains_any = .{ .x = &X, .patterns = &.{ "xy", "LL" }, .ascii_case_insensitive = true } }));
    try expectV(.{ .bool = false }, try run(a, txt("Hello"), .null, .{ .contains_any = .{ .x = &X, .patterns = &.{ "xy", "LL" } } }));
    try expectV(txt("XYXY"), try run(a, txt("abcabc"), .null, .{ .replace_many = .{ .x = &X, .patterns = &.{ "a", "bc" }, .with = &.{ "X", "Y" } } }));
    // Leftmost-first: at position 0 only "ab" matches.
    try expectV(txt("2c"), try run(a, txt("abc"), .null, .{ .replace_many = .{ .x = &X, .patterns = &.{ "b", "ab" }, .with = &.{ "1", "2" } } }));
    // Several match at one position: the first listed wins.
    try expectV(txt("1c"), try run(a, txt("abc"), .null, .{ .replace_many = .{ .x = &X, .patterns = &.{ "ab", "a" }, .with = &.{ "1", "2" } } }));
    try expectV(txt("-b-"), try run(a, txt("AbA"), .null, .{ .replace_many = .{ .x = &X, .patterns = &.{"a"}, .with = &.{"-"}, .ascii_case_insensitive = true } }));
    try testing.expectError(error.BadExpr, run(a, txt("x"), .null, .{ .replace_many = .{ .x = &X, .patterns = &.{""}, .with = &.{"-"} } }));
    try testing.expectError(error.BadExpr, run(a, txt("x"), .null, .{ .replace_many = .{ .x = &X, .patterns = &.{ "a", "b", "c" }, .with = &.{ "1", "2" } } }));
}
