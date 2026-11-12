// SPDX-License-Identifier: MIT

//! Tests added by the second 2026-11 mutation round over the Rust-grammar
//! parser and the emitter of `syntax.zig`: each one kills a mutant that
//! survived the first round (class set operations with an unsorted or unmerged
//! left side, the bytes-mode class mapping, the emit work budget, the loop
//! shape of a repeated alternation, the lazy/greedy loop of a body that can
//! match empty). Each block names what it pins.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const syntax = @import("syntax.zig");

const Regex = regex.Regex;
const Range = syntax.Range;

fn refuses(want: anyerror, pattern: []const u8, syn: regex.Syntax) !void {
    try testing.expectError(want, Regex.compileOptions(testing.allocator, pattern, .{ .syntax = syn }));
}

test "a Rust class set operation reads its left side sorted and merged: [ba&&a]" {
    // `ba` is two unsorted ranges until the first `&&` closes it: the
    // sweep of `appendSetOp` needs them sorted, or `a` is lost.
    var re = try Regex.compileOptions(testing.allocator, "[ba&&a]", .{ .syntax = .rust });
    defer re.deinit(testing.allocator);
    try testing.expect(re.fullMatch("a"));
    try testing.expect(!re.fullMatch("b"));
    var re2 = try Regex.compileOptions(testing.allocator, "[ca-b--b]", .{ .syntax = .rust });
    defer re2.deinit(testing.allocator);
    try testing.expect(re2.fullMatch("a"));
    try testing.expect(re2.fullMatch("c"));
    try testing.expect(!re2.fullMatch("b"));
}

test "a Rust class set operation's result is merged before the next one (range budget)" {
    // `a~~b` is two adjacent ranges that must merge to `a-b`; unmerged they pile
    // up (k + 1 ranges after k operations) and a 16-range builder runs out.
    const Tiny = syntax.BuilderOf(.{ .insts = 64, .ranges = 16, .nodes = 64 });
    var t: Tiny = undefined;
    try t.compileSyntax("[a~~b~~c~~d~~e~~f~~g~~h~~i~~j~~k~~l]", .rust);
    try testing.expectEqual(@as(u16, 1), t.nranges);
}

test "a trailing `--` of a Rust class is an operator: its work is done before the missing `]` is seen" {
    // Eight single members, then `--b--` at the very end of the pattern. The
    // last `--` closes `b` and runs the difference (8 + 1 + 8 ranges do not fit
    // 16: PatternTooLarge); read as two literals it would only be a missing `]`.
    const Tiny = syntax.BuilderOf(.{ .insts = 64, .ranges = 16, .nodes = 64 });
    var t: Tiny = undefined;
    try testing.expectError(error.PatternTooLarge, t.compileSyntax("[acegikmo--b--", .rust));
    // Without the ranges to run out of it is the missing bracket.
    var u: Tiny = undefined;
    try testing.expectError(error.MissingBracket, u.compileSyntax("[a--", .rust));
}

test "(?-u) class: a code point past ASCII is refused, however it is written; U+0080 included" {
    try refuses(error.InvalidUtf8, "(?-u)[\\u{80}]", .rust);
    try refuses(error.InvalidUtf8, "(?-u)[\u{80}]", .rust);
    try refuses(error.InvalidUtf8, "(?-u)[\\u{e9}]", .rust);
    // DEL is ASCII.
    var re = try Regex.compileOptions(testing.allocator, "(?-u)[\\x7f]", .{ .syntax = .rust });
    re.deinit(testing.allocator);
}

test "bytes mode: a negated class is cut at 0xff and a class that straddles 0x80 is split exactly" {
    const b = try testing.allocator.create(regex.Builder);
    defer testing.allocator.destroy(b);
    const bb = syntax.byte_base;

    // `[^\xff]`: the complement's tail starts at 0x100 and is dropped.
    try b.compileSyntaxBytes("(?-u)[^\\xff]", .rust, true);
    try testing.expectEqualSlices(Range, &.{
        .{ .lo = 0, .hi = 0x7f },
        .{ .lo = bb + 0x80, .hi = bb + 0xfe },
    }, b.ranges[0..b.nranges]);

    // `[^a]`: the tail is cut at 0xff exactly, ASCII stays ASCII.
    try b.compileSyntaxBytes("(?-u)[^a]", .rust, true);
    try testing.expectEqualSlices(Range, &.{
        .{ .lo = 0, .hi = 0x60 },
        .{ .lo = 0x62, .hi = 0x7f },
        .{ .lo = bb + 0x80, .hi = bb + 0xff },
    }, b.ranges[0..b.nranges]);

    // `[a-\xff]` straddles 0x80: `a-0x7f` and `byte_base + 0x80 .. byte_base + 0xff`.
    try b.compileSyntaxBytes("(?-u)[a-\\xff]", .rust, true);
    try testing.expectEqualSlices(Range, &.{
        .{ .lo = 'a', .hi = 0x7f },
        .{ .lo = bb + 0x80, .hi = bb + 0xff },
    }, b.ranges[0..b.nranges]);

    // And through the matcher: DEL and a byte past ASCII.
    var re = try Regex.compileOptions(testing.allocator, "(?-u)[a-\\xff]", .{ .syntax = .rust, .utf8 = false });
    defer re.deinit(testing.allocator);
    try testing.expect(re.fullMatch("\x7f"));
    try testing.expect(re.fullMatch("\x80"));
    try testing.expect(re.fullMatch("\xff"));
    try testing.expect(!re.fullMatch("`"));
}

test "a repeated alternation is the plain loop: the `x*` shape of a body that cannot be empty" {
    // `(?:ab|cd)*`: the alternation's own `jmp` plus the loop's `jmp`. Read as
    // a body that can match empty it would be a (x+)? with a split at its end.
    const b = try testing.allocator.create(regex.Builder);
    defer testing.allocator.destroy(b);
    try b.compile("(?:ab|cd)*");
    var jmps: usize = 0;
    for (b.insts[0..b.ninsts]) |in| {
        if (in == .jmp) jmps += 1;
    }
    try testing.expectEqual(@as(usize, 2), jmps);
}

test "x* with a body that can match empty: greedy takes every pass, lazy takes the fewest that let the rest match" {
    const gpa = testing.allocator;
    var greedy = try Regex.compile(gpa, "(?:a|)*");
    defer greedy.deinit(gpa);
    // After the first `a` the loop prefers another pass (Go: [0 2]).
    try testing.expectEqual(@as(?regex.Span, .{ .start = 0, .end = 2 }), try greedy.find(gpa, "aa"));
    try testing.expectEqual(@as(?regex.Span, .{ .start = 0, .end = 3 }), try greedy.find(gpa, "aaab"));

    // Lazy: `\B` fails at 0, so one pass is forced; then it prefers to stop
    // (a loop that stayed greedy after its first pass would end at 3).
    var lazy = try Regex.compile(gpa, "(?:a|)*?\\Ba");
    defer lazy.deinit(gpa);
    try testing.expectEqual(@as(?regex.Span, .{ .start = 0, .end = 2 }), try lazy.find(gpa, "aaa"));
    var lazy_rust = try Regex.compileOptions(gpa, "(?:a|)*?\\Ba", .{ .syntax = .rust });
    defer lazy_rust.deinit(gpa);
    try testing.expectEqual(@as(?regex.Span, .{ .start = 0, .end = 2 }), try lazy_rust.find(gpa, "aaa"));
    // Capturing bodies take the same route.
    var cap = try Regex.compile(gpa, "(a|)*");
    defer cap.deinit(gpa);
    try testing.expectEqual(@as(?regex.Span, .{ .start = 0, .end = 2 }), try cap.find(gpa, "aa"));
}

/// Builds `(?:){100000}` ** k followed by `(?:){m}` and returns the builder's
/// count of emit node visits.
fn emitWork(b: *regex.Builder, gpa: std.mem.Allocator, k: usize, m: usize) !usize {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    for (0..k) |_| try out.writer.writeAll("(?:){100000}");
    try out.writer.print("(?:){{{d}}}", .{m});
    try b.compileSyntax(out.written(), .rust);
    return b.work;
}

test "the emit work budget: exactly max_emit_work node visits compile, one more is PatternTooLarge" {
    const gpa = testing.allocator;
    const b = try gpa.create(regex.Builder);
    defer gpa.destroy(b);
    // Calibrate (the work is linear in the units and in `m`, from m = 2 on).
    const f = try emitWork(b, gpa, 1, 2);
    const wu = (try emitWork(b, gpa, 2, 2)) - f;
    const s = (try emitWork(b, gpa, 1, 3)) - f;
    try testing.expect(wu >= 100_000 and s >= 1);
    // Find k and m with work(k, m) == max_emit_work exactly.
    const target: usize = syntax.max_emit_work;
    var k: usize = (target - f) / wu + 1;
    const m: usize = while (k > 1) : (k -= 1) {
        const rest = target - f - (k - 1) * wu;
        if (rest % s == 0 and rest / s + 2 <= 100_000) break rest / s + 2;
    } else return error.TestUnexpectedResult;
    try testing.expectEqual(target, try emitWork(b, gpa, k, m));
    // One visit more is over the budget.
    try testing.expectError(error.PatternTooLarge, emitWork(b, gpa, k, m + 1));
}
