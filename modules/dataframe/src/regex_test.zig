// SPDX-License-Identifier: MIT
//! The regex string functions (`contains_regex`, `extract`, `count_regex`,
//! `replace_regex`) through `mutate` and `where`. Expected values are polars 2.1's
//! documented answers (`str.contains`, `str.extract`, `str.count_matches`,
//! `str.replace`/`replace_all`), which share the Rust `regex` grammar used here.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Expr = df.Expr;

const X: Expr = .{ .col = "x" };

fn run(a: std.mem.Allocator, x: Value, e: Expr) !Value {
    const f = try st.mk(a, &.{.{ .name = "x", .type = .text }}, &.{&.{x}});
    const g = try df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
    return g.cell(0, "out").?;
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

test "contains_regex: Rust grammar, Unicode classes, anchors; null and non-text give null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(.{ .bool = true }, try run(a, txt("order 2026-11"), .{ .contains_regex = .{ .x = &X, .pattern = "\\d{4}-\\d{2}" } }));
    try expectV(.{ .bool = false }, try run(a, txt("order"), .{ .contains_regex = .{ .x = &X, .pattern = "\\d" } }));
    // Rust's `\w` is Unicode (Go's would be ASCII): polars matches "é".
    try expectV(.{ .bool = true }, try run(a, txt("é"), .{ .contains_regex = .{ .x = &X, .pattern = "^\\w$" } }));
    try expectV(.{ .bool = true }, try run(a, txt("ABC"), .{ .contains_regex = .{ .x = &X, .pattern = "(?i)abc" } }));
    try expectV(.null, try run(a, .null, .{ .contains_regex = .{ .x = &X, .pattern = "a" } }));
    try expectV(.null, try run(a, .{ .int = 5 }, .{ .contains_regex = .{ .x = &X, .pattern = "5" } }));
}

test "extract: a group of the first match, group 0, a group that took no part, no match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pat = "(?<y>\\d{4})-(\\d{2})(x)?";
    try expectV(txt("2026"), try run(a, txt("a 2026-11 b 2027-01"), .{ .extract = .{ .x = &X, .pattern = pat } }));
    try expectV(txt("11"), try run(a, txt("a 2026-11"), .{ .extract = .{ .x = &X, .pattern = pat, .group = 2 } }));
    try expectV(txt("2026-11"), try run(a, txt("a 2026-11"), .{ .extract = .{ .x = &X, .pattern = pat, .group = 0 } }));
    try expectV(.null, try run(a, txt("a 2026-11"), .{ .extract = .{ .x = &X, .pattern = pat, .group = 3 } }));
    try expectV(.null, try run(a, txt("none"), .{ .extract = .{ .x = &X, .pattern = pat } }));
    try testing.expectError(error.BadExpr, run(a, txt("x"), .{ .extract = .{ .x = &X, .pattern = pat, .group = 4 } }));
}

test "count_regex: non-overlapping, empty matches count once per position" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectV(.{ .int = 2 }, try run(a, txt("aaaa"), .{ .count_regex = .{ .x = &X, .pattern = "aa" } }));
    try expectV(.{ .int = 0 }, try run(a, txt("bbb"), .{ .count_regex = .{ .x = &X, .pattern = "a" } }));
    // polars `"abc".str.count_matches("")` = 4 (Rust's find_iter: one empty match per boundary).
    try expectV(.{ .int = 4 }, try run(a, txt("abc"), .{ .count_regex = .{ .x = &X, .pattern = "" } }));
}

test "replace_regex: first or all, templates with groups, literal replacement" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pat = "(?<y>\\d{4})-(?<m>\\d{2})";
    try expectV(txt("due 11/2026 and 01/2027"), try run(a, txt("due 2026-11 and 2027-01"), .{ .replace_regex = .{ .x = &X, .pattern = pat, .with = "${m}/$y" } }));
    try expectV(txt("due 11/2026 and 2027-01"), try run(a, txt("due 2026-11 and 2027-01"), .{ .replace_regex = .{ .x = &X, .pattern = pat, .with = "${m}/$y", .all = false } }));
    try expectV(txt("due $m and $m"), try run(a, txt("due 2026-11 and 2027-01"), .{ .replace_regex = .{ .x = &X, .pattern = pat, .with = "$m", .literal = true } }));
    try expectV(txt("a$b"), try run(a, txt("a-b"), .{ .replace_regex = .{ .x = &X, .pattern = "-", .with = "$$" } }));
}

test "regex functions: a bad pattern is error.BadPattern, a huge repetition too; where filters by a pattern" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.BadPattern, run(a, txt("x"), .{ .contains_regex = .{ .x = &X, .pattern = "(unclosed" } }));
    // RE2/Rust leave out backreferences, keeping linear time.
    try testing.expectError(error.BadPattern, run(a, txt("x"), .{ .contains_regex = .{ .x = &X, .pattern = "(a)\\1" } }));
    try testing.expectError(error.BadPattern, run(a, txt("x"), .{ .count_regex = .{ .x = &X, .pattern = "(a{1000}){1000}" } }));

    const f = try st.mk(a, &.{.{ .name = "x", .type = .text }}, &.{
        &.{txt("alpha")}, &.{txt("beta")}, &.{.null}, &.{txt("gamma")},
    });
    const g = try df.where(a, f, &.{ .contains_regex = .{ .x = &X, .pattern = "^(a|g)" } });
    try testing.expectEqual(@as(usize, 2), g.len);
    try expectV(txt("gamma"), g.cell(1, "x").?);
}

test "replace_regex: a template that multiplies the text past max_text_result is error.TooLarge" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = try a.alloc(u8, 1 << 16);
    @memset(text, 'a');
    const tmpl = try a.alloc(u8, 2 * 300);
    for (0..300) |i| @memcpy(tmpl[2 * i ..][0..2], "$0");
    try testing.expectError(error.TooLarge, run(a, txt(text), .{ .replace_regex = .{ .x = &X, .pattern = "a+", .with = tmpl } }));
}

test "Selector.matches: names by pattern, compiled once, freed; a bad pattern is BadPattern" {
    const a = testing.allocator; // not an arena: the compiled patterns must be released
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const f = try st.mk(arena.allocator(), &.{
        .{ .name = "price_eur", .type = .float },
        .{ .name = "price_usd", .type = .float },
        .{ .name = "qty", .type = .int },
        .{ .name = "Price", .type = .text },
    }, &.{});
    const pat = "^price_(eur|usd)$";
    const both = try df.selectColumns(a, f, .{ .matches = pat });
    defer a.free(both);
    try testing.expectEqual(@as(usize, 2), both.len);
    try testing.expectEqualStrings("price_usd", both[1]);
    // The same node twice in the tree, and a case-insensitive one beside it.
    const sel: df.Selector = .{ .any_of = &.{ .{ .matches = pat }, .{ .matches = pat }, .{ .matches = "(?i)^price$" } } };
    const three = try df.selectColumns(a, f, sel);
    defer a.free(three);
    try testing.expectEqual(@as(usize, 3), three.len);
    const none = try df.selectColumns(a, f, .{ .not = &.{ .matches = "." } });
    defer a.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    try testing.expectError(error.BadPattern, df.selectColumns(a, f, .{ .any_of = &.{ .{ .matches = "ok" }, .{ .matches = "(bad" } } }));
}
