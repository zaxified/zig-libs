// SPDX-License-Identifier: MIT
//! The build size knobs `-Ddataframe-regex` and `-Ddataframe-unicode` (`knobs.zig`): what each
//! path does. A test of the path the build does not have is skipped, so
//! `scripts/modtest dataframe -Ddataframe-regex=false -Ddataframe-unicode=false` runs the off
//! paths and the default build runs the on paths.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const df = @import("root.zig");
const knobs = @import("knobs.zig");
const fnx = @import("exprfn.zig");
const st = @import("structure_test.zig");

fn textFrame(a: std.mem.Allocator, t: []const u8) !df.Frame {
    return st.mk(a, &.{.{ .name = "x", .type = .text }}, &.{&.{.{ .text = t }}});
}

test "knobs: the constants are the build options, on by default" {
    if (knobs.regex_enabled and knobs.unicode_enabled) return;
    // A knob off: the stand-in of that module is in use, the other one is not touched.
    try testing.expect(!knobs.regex_enabled or !knobs.unicode_enabled);
}

test "dataframe-regex on: patterns compile and match" {
    if (!knobs.regex_enabled) return testkit.skip("-Ddataframe-regex=false", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try textFrame(a, "order 2026-11");
    const x: df.Expr = .{ .col = "x" };
    const g = try df.mutate(a, f, &.{.{ .out = "hit", .expr = .{ .contains_regex = .{ .x = &x, .pattern = "\\d{4}" } } }});
    try testing.expect(g.cell(0, "hit").?.bool);
}

test "dataframe-regex off: every pattern is BadPattern (BadArgument for splitColumns), nothing else changes" {
    if (knobs.regex_enabled) return testkit.skip("regex is built in", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try textFrame(a, "a1b2c");
    const x: df.Expr = .{ .col = "x" };
    try testing.expectError(error.BadPattern, df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .contains_regex = .{ .x = &x, .pattern = "\\d" } } }}));
    try testing.expectError(error.BadPattern, df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .replace_regex = .{ .x = &x, .pattern = "\\d", .with = "#" } } }}));
    try testing.expectError(error.BadPattern, df.selectColumns(a, f, .{ .matches = "^x$" }));
    try testing.expectError(error.BadArgument, df.splitColumns(a, f, .{ .col = "x", .by = "\\d", .regex = true }));
    // A literal split and the plain string functions need no regex.
    const g = try df.splitColumns(a, f, .{ .col = "x", .by = "b" });
    try testing.expectEqualStrings("a1", g.cell(0, "0").?.text);
    const h = try df.mutate(a, f, &.{.{ .out = "u", .expr = .{ .unary = .{ .op = .upper, .x = &x } } }});
    try testing.expectEqualStrings("A1B2C", h.cell(0, "u").?.text);
}

test "dataframe-unicode on: full case mapping, accent folding, normal forms" {
    if (!knobs.unicode_enabled) return testkit.skip("-Ddataframe-unicode=false", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("été", try fnx.lower(a, "ÉTÉ"));
    try testing.expectEqualStrings("SS", try fnx.upper(a, "ß"));
    try testing.expectEqualStrings("Zlutoucky", try fnx.unaccent(a, "Žluťoučký"));
    try testing.expect(fnx.isClass("été", .alpha));
}

test "dataframe-unicode off: ASCII case mapping and classes, normalize and unaccent of non-ASCII text are UnicodeNotBuilt" {
    if (knobs.unicode_enabled) return testkit.skip("unicode is built in", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The former ASCII behaviour: ASCII letters map, other bytes stay.
    try testing.expectEqualStrings("tÉt", try fnx.lower(a, "TÉT"));
    try testing.expectEqualStrings("Aß", try fnx.upper(a, "aß"));
    try testing.expectEqualStrings("Hello World", try fnx.title(a, "hello world"));
    try testing.expect(fnx.isClass("abc", .alpha));
    try testing.expect(!fnx.isClass("été", .alpha));
    try testing.expect(fnx.isClass("12", .digit));
    // ASCII text needs no tables, so it is accepted.
    try testing.expectEqualStrings("abc", try fnx.normalize(a, "abc", .nfc));
    try testing.expectEqualStrings("abc", try fnx.unaccent(a, "abc"));
    try testing.expectError(error.UnicodeNotBuilt, fnx.normalize(a, "é", .nfd));
    try testing.expectError(error.UnicodeNotBuilt, fnx.unaccent(a, "é"));
    // Through `mutate` as well.
    const f = try textFrame(a, "é");
    const x: df.Expr = .{ .col = "x" };
    try testing.expectError(error.UnicodeNotBuilt, df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .unary = .{ .op = .unaccent, .x = &x } } }}));
}
