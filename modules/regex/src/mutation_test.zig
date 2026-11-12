// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11 whole-module mutation run over `syntax.zig`,
//! `root.zig` and `teddy.zig`: each one kills a mutant that the Go and Rust
//! oracle replays and the older tests let survive (limits of the parser, the
//! height bookkeeping of the Rust grammar, escape and class edge cases, the
//! case-fold orbit walk). Each block names what it pins.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const syntax = @import("syntax.zig");

const Regex = regex.Regex;

/// Comptime string repetition (`**` was removed in Zig 0.17).
inline fn rep(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &result;
}

fn compiles(pattern: []const u8, syn: regex.Syntax) !void {
    var re = try Regex.compileOptions(testing.allocator, pattern, .{ .syntax = syn });
    re.deinit(testing.allocator);
}

fn refuses(want: anyerror, pattern: []const u8, syn: regex.Syntax) !void {
    try testing.expectError(want, Regex.compileOptions(testing.allocator, pattern, .{ .syntax = syn }));
}

test "compileSyntax keeps bytes mode off; compileSyntaxBytes honours it for the Rust grammar only" {
    const b = try testing.allocator.create(regex.Builder);
    defer testing.allocator.destroy(b);
    try b.compileSyntax("a", .rust);
    try testing.expect(!b.bytes);
    try b.compileSyntaxBytes("a", .rust, true);
    try testing.expect(b.bytes);
    try b.compileSyntaxBytes("a", .perl, true);
    try testing.expect(!b.bytes);
}

test "Rust nest height: an alternation takes its tallest alternative, plus one" {
    const open = rep("(?:", regex.max_depth);
    const close = rep(")", regex.max_depth);
    const deep = open ++ "a" ++ close; // height 250: still allowed alone
    try compiles(deep, .rust);
    // Tallest alternative last / first: both exceed the limit by the alternation.
    try refuses(error.NestingDepth, "b|" ++ deep, .rust);
    try refuses(error.NestingDepth, deep ++ "|b", .rust);
    // The alternation itself adds a level inside a group chain.
    try compiles(rep("(?:", regex.max_depth - 1) ++ "a|b" ++ rep(")", regex.max_depth - 1), .rust);
    try refuses(error.NestingDepth, open ++ "a|b" ++ close, .rust);
}

test "a repetition nested max_depth deep is refused, one level less is not (Go, POSIX-free and Rust grammars)" {
    const open = rep("(?:", regex.max_depth);
    const close = rep(")", regex.max_depth);
    for ([_]regex.Syntax{ .perl, .rust }) |syn| {
        try refuses(error.NestingDepth, open ++ "a*" ++ close, syn);
        try compiles(rep("(?:", regex.max_depth - 1) ++ "a*" ++ rep(")", regex.max_depth - 1), syn);
    }
}

test "separate repetitions never count as stacked ones; a stacked chain stops at max_stacked" {
    const many = rep("a*", 100);
    try compiles(many, .perl);
    try compiles(many, .posix);
    try compiles(many, .rust);
    // Rust repeats a repetition (`a**`): 64 repeated operands are budgeted.
    try compiles("a" ++ rep("*", 65), .rust);
    try refuses(error.NestingDepth, "a" ++ rep("*", 66), .rust);
    try refuses(error.NestingDepth, "a" ++ rep("*", 2000), .rust);
}

test "a `{` that is no repetition is a literal operand of the next one" {
    var re = try Regex.compile(testing.allocator, "a*{*");
    defer re.deinit(testing.allocator);
    try testing.expect(re.fullMatch("aa{{"));
    try testing.expect(re.fullMatch("{"));
    var lone = try Regex.compile(testing.allocator, "{*");
    defer lone.deinit(testing.allocator);
    try testing.expect(lone.fullMatch("{{{"));
    try testing.expect(lone.fullMatch(""));
    // After a literal `{` the repetition is a first one: no nested-repeat error.
    try compiles("a{{*", .perl);
    try compiles(rep("{*", 80), .posix);
    // A true repetition of a repetition stays refused in the Go grammar.
    try refuses(error.InvalidNestedRepeat, "a*{2}", .perl);
}

test "nested counted repetitions multiply under the Rust limit too" {
    try refuses(error.InvalidRepeatSize, "(?:(?:a{0}){100000}){2}", .rust);
    try compiles("(?:(?:a{0}){1000}){100}", .rust);
}

test "flag groups: `(?-:` and `(?i-:` clear nothing and are refused, `(?-i:` is fine" {
    try refuses(error.InvalidPerlOp, "(?-:a)", .perl);
    try refuses(error.InvalidPerlOp, "(?i-:a)", .perl);
    try refuses(error.InvalidPerlOp, "(?-)", .perl);
    try compiles("(?-i:a)", .perl);
    try compiles("(?i-s:a)", .perl);
    try compiles("(?:a)", .perl);
}

test "group limit: 63 groups fit beside group 0, the 64th is PatternTooLarge" {
    const b = try testing.allocator.create(regex.Builder);
    defer testing.allocator.destroy(b);
    for ([_]regex.Syntax{ .perl, .posix, .rust }) |syn| {
        try b.compileSyntax(rep("(a)", regex.max_groups - 1), syn);
        try testing.expectEqual(@as(u16, regex.max_groups), b.ngroups);
        try testing.expectError(error.PatternTooLarge, b.compileSyntax(rep("(a)", regex.max_groups), syn));
    }
}

test "octal escapes: up to three digits of 0-7, a lone 1-7 is refused" {
    const Case = struct { []const u8, []const u8 };
    for ([_]Case{
        .{ "\\1234", "S4" }, // \123 then a literal 4
        .{ "\\100", "@" },
        .{ "\\017", "\x0f" },
        .{ "\\0", "\x00" },
        .{ "\\08", "\x008" }, // 8 is no octal digit
        .{ "\\077", "?" },
        .{ "\\0/", "\x00/" }, // '/' sits just below '0'
    }) |c| {
        var re = try Regex.compile(testing.allocator, c[0]);
        defer re.deinit(testing.allocator);
        try testing.expect(re.fullMatch(c[1]));
    }
    try refuses(error.InvalidEscape, "\\18", .perl);
    try refuses(error.InvalidEscape, "\\7", .perl);
    try refuses(error.InvalidEscape, "\\\u{e9}", .perl);
}

test "class syntax edges: POSIX `-`, a literal `[`, `[z-a`, `[a-a]`, `[[::]`" {
    // POSIX: a `-` that is the last character of the pattern is not a member.
    try refuses(error.InvalidCharRange, "[a-", .posix);
    try refuses(error.InvalidCharRange, "[a-c-e]", .posix);
    try compiles("[a-]", .posix);
    // `[` inside a class is a literal unless it opens `[:`.
    var lit = try Regex.compile(testing.allocator, "[[ab:]");
    defer lit.deinit(testing.allocator);
    for ([_][]const u8{ "[", "a", "b", ":" }) |s| try testing.expect(lit.fullMatch(s));
    try testing.expect(!lit.fullMatch("c"));
    // A range is read even when the pattern ends right after its upper end.
    try refuses(error.InvalidCharRange, "[z-a", .perl);
    try refuses(error.InvalidCharRange, "[z-a]", .perl);
    var same = try Regex.compile(testing.allocator, "[a-a]");
    defer same.deinit(testing.allocator);
    try testing.expect(same.fullMatch("a"));
    // An empty `[::]` name is an unknown class, not a literal run.
    try refuses(error.InvalidCharClass, "[[::]", .perl);
    try refuses(error.InvalidCharClass, "[[:nope:]]", .perl);
}

test "class ranges merge when adjacent; a negation reaches U+10FFFF" {
    const b = try testing.allocator.create(regex.Builder);
    defer testing.allocator.destroy(b);
    try b.compile("[a-cd-f]");
    try testing.expectEqual(@as(u16, 1), b.nranges);
    try b.compile("[a-dc-f]");
    try testing.expectEqual(@as(u16, 1), b.nranges);
    try b.compile("[a-ce-g]");
    try testing.expectEqual(@as(u16, 2), b.nranges);

    var top = try Regex.compile(testing.allocator, "[^\\x{0}-\\x{10fffe}]");
    defer top.deinit(testing.allocator);
    try testing.expect(top.fullMatch("\u{10ffff}"));
    try testing.expect(!top.fullMatch("\u{10fffe}"));
    try testing.expect(!top.fullMatch("a"));
}

test "case folding of a class: alternating runs, the all-of-Unicode shortcut, no stale ranges" {
    // U+0100..U+012F alternate upper/lower: whole pairs.
    var alt = try Regex.compile(testing.allocator, "(?i)[\\x{101}-\\x{103}]");
    defer alt.deinit(testing.allocator);
    for ([_][]const u8{ "\u{100}", "\u{101}", "\u{102}", "\u{103}" }) |s| try testing.expect(alt.fullMatch(s));
    try testing.expect(!alt.fullMatch("\u{104}"));
    try testing.expect(!alt.fullMatch("\u{ff}"));

    // Images of members above the class start still arrive (U+017F is `s`).
    var hi = try Regex.compile(testing.allocator, "(?i)[\\x{100}-\\x{10ffff}]");
    defer hi.deinit(testing.allocator);
    for ([_][]const u8{ "s", "S", "k", "K", "\u{17f}" }) |s| try testing.expect(hi.fullMatch(s));
    try testing.expect(!hi.fullMatch("a"));

    // A range that already spans every code point with a fold adds nothing:
    // it fits a builder of 16 ranges (without the shortcut each run would add
    // an image).
    const Tiny = syntax.BuilderOf(.{ .insts = 32, .ranges = 16, .nodes = 32 });
    var t: Tiny = undefined;
    try t.compile("(?i)[\\x{41}-\\x{1e943}]");
    try t.compile("(?i)[\\x{0}-\\x{10ffff}]");
    try t.compile("(?i)[\\x{41}-\\x{10ffff}]");
    try t.compile("(?i)[\\x{0}-\\x{1e943}]");

    // The walk stops at the ranges it was given: the slot after them holds a
    // stale range of the previous compile, which must not be folded.
    const b = try testing.allocator.create(regex.Builder);
    defer testing.allocator.destroy(b);
    var first = try Regex.compileUsing(testing.allocator, b, "[0-9][a-z]");
    first.deinit(testing.allocator);
    var digits = try Regex.compileUsing(testing.allocator, b, "(?i)[0-9]");
    defer digits.deinit(testing.allocator);
    try testing.expect(digits.fullMatch("5"));
    try testing.expect(!digits.fullMatch("A"));
    try testing.expect(!digits.fullMatch("a"));
    var first2 = try Regex.compileUsing(testing.allocator, b, "[0-9][a-z]");
    first2.deinit(testing.allocator);
    var esc = try Regex.compileUsing(testing.allocator, b, "(?i)\\d");
    defer esc.deinit(testing.allocator);
    try testing.expect(esc.fullMatch("5"));
    try testing.expect(!esc.fullMatch("A"));
}

test "Rust (?x): a `-` followed by space and `]` ends a class, it does not start a range" {
    var re = try Regex.compileOptions(testing.allocator, "(?x)[a- ]", .{ .syntax = .rust });
    defer re.deinit(testing.allocator);
    try testing.expect(re.fullMatch("a"));
    try testing.expect(re.fullMatch("-"));
    try testing.expect(!re.fullMatch("b"));
}

fn refusesAny(pattern: []const u8, syn: regex.Syntax) !void {
    if (Regex.compileOptions(testing.allocator, pattern, .{ .syntax = syn })) |re| {
        var r = re;
        r.deinit(testing.allocator);
        return error.TestUnexpectedResult;
    } else |_| {}
}

inline fn wrap(comptime inner: []const u8, comptime k: usize) *const [inner.len + 2 * k:0]u8 {
    return rep("[", k) ++ inner ++ rep("]", k);
}

test "Rust nest height of classes: unions, set operations, leading members" {
    // Each case: the class's own height `h`; `k` enclosing brackets add `k`.
    // 250 is allowed, 251 refused.
    const Case = struct { inner: []const u8, h: usize };
    inline for ([_]Case{
        .{ .inner = "[ab]", .h = 2 },
        .{ .inner = "[-a]", .h = 2 },
        .{ .inner = "[]a]", .h = 2 },
        .{ .inner = "[a&&b]", .h = 2 },
        .{ .inner = "[[ab]&&c]", .h = 4 },
        .{ .inner = "[[ab]&&c&&d]", .h = 5 },
        .{ .inner = "[[ab]&&cd]", .h = 4 },
        .{ .inner = "[ab&&c]", .h = 3 },
        .{ .inner = "[ab&&cd&&e]", .h = 4 },
    }) |c| {
        try compiles(wrap(c.inner, 250 - c.h), .rust);
        try refuses(error.NestingDepth, wrap(c.inner, 251 - c.h), .rust);
    }
    // A capture group adds its height without adding depth to a concat.
    try compiles(rep("(?:b", 124) ++ "(a)" ++ rep(")", 124), .rust);
    try refuses(error.NestingDepth, rep("(?:b", 125) ++ "(a)" ++ rep(")", 125), .rust);
    // A capture group is a level too.
    try compiles(rep("(?:", 249) ++ "(a)" ++ rep(")", 249), .rust);
    try refuses(error.NestingDepth, rep("(?:", 250) ++ "(a)" ++ rep(")", 250), .rust);
}

test "Rust nested classes far past the limit are refused before the stack is" {
    const Run = struct {
        fn go(out: *?anyerror) void {
            const deep = rep("[", 20000) ++ "a" ++ rep("]", 20000);
            var b = std.heap.page_allocator.create(regex.Builder) catch unreachable;
            defer std.heap.page_allocator.destroy(b);
            out.* = if (b.compileSyntax(deep, .rust)) |_| null else |e| e;
        }
    };
    var out: ?anyerror = null;
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const t = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, Run.go, .{&out});
    t.join();
    try testing.expectEqual(@as(?anyerror, error.NestingDepth), out);
}

fn rustFull(pattern: []const u8, bytes: bool, input: []const u8) !bool {
    var re = try Regex.compileOptions(testing.allocator, pattern, .{ .syntax = .rust, .utf8 = !bytes });
    defer re.deinit(testing.allocator);
    return re.fullMatch(input);
}

test "Rust grammar: classes with set operations, folding and byte classes" {
    // Set operations reach the last code point.
    try testing.expect(try rustFull("[\\x{10fffe}-\\x{10ffff}&&\\x{10ffff}]", false, "\u{10ffff}"));
    try testing.expect(!try rustFull("[\\x{10fffe}-\\x{10ffff}&&\\x{10ffff}]", false, "\u{10fffe}"));
    // `&` and `-` that do not double are members; at the end they refuse.
    try testing.expect(try rustFull("[a&b]", false, "&"));
    try testing.expect(try rustFull("[x&]", false, "&"));
    try refusesAny("[a&", .rust);
    try refusesAny("[a-", .rust);
    // `(?x)`: `-` + space + `]` ends the class.
    try testing.expect(try rustFull("(?x)[a- ]", false, "-"));
    // `[[xalpha:]]` is a class of letters, not `[:alpha:]` shifted by one.
    try testing.expect(try rustFull("[[xalpha:]]", false, "x"));
    try testing.expect(!try rustFull("[[xalpha:]]", false, "b"));
    // `(?i-u)` folds ASCII only, run by run.
    try testing.expect(try rustFull("(?i-u)[a-c]", false, "B"));
    try testing.expect(!try rustFull("(?i-u)[a-c]", false, "D"));
    try testing.expect(try rustFull("(?i-u)[z]", false, "Z"));
    try testing.expect(try rustFull("(?i-u)[X-Z]", false, "y"));
    try testing.expect(!try rustFull("(?i-u)[a-\\x{7b}]", false, "["));
    try testing.expect(!try rustFull("(?i-u)[k]", false, "\u{212a}"));
    try testing.expect(try rustFull("(?i)[k]", false, "\u{212a}"));
    // `[[:^alpha:]]` under `(?-u)` is a byte class: not on `&str`.
    try testing.expectError(error.InvalidUtf8, Regex.compileOptions(testing.allocator, "(?-u)[[:^alpha:]]", .{ .syntax = .rust }));
    try testing.expect(try rustFull("(?-u)[[:^alpha:]]", true, "\xff"));
    try testing.expect(try rustFull("(?-u)[[:^alpha:]]", true, "1"));
    try testing.expect(!try rustFull("(?-u)[[:^alpha:]]", true, "a"));
    try testing.expect(try rustFull("(?-u)[^a]", true, "\x80"));
    try testing.expect(!try rustFull("(?-u)[^a]", true, "a"));
    // Leading `-` and `]` are members.
    for ([_][]const u8{ "-", "a" }) |c| try testing.expect(try rustFull("[-a]", false, c));
    for ([_][]const u8{ "]", "a" }) |c| try testing.expect(try rustFull("[]a]", false, c));
    // Each side of a set operation is folded before it (`B` removes `b`).
    for ([_][]const u8{ "a", "A", "c", "C" }) |c| try testing.expect(try rustFull("(?i)[a-c--B]", false, c));
    for ([_][]const u8{ "b", "B" }) |c| try testing.expect(!try rustFull("(?i)[a-c--B]", false, c));
    // A byte range never matches the code point it shares a number with.
    try testing.expect(!try rustFull("(?-u)[\\x7f-\\x81]", true, "\u{80}"));
    // A byte range across 0x80.
    for ([_][]const u8{ "\x7f", "\x80", "\x81" }) |s| try testing.expect(try rustFull("(?-u)[\\x7f-\\x81]", true, s));
    for ([_][]const u8{ "\x7e", "\x82" }) |s| try testing.expect(!try rustFull("(?-u)[\\x7f-\\x81]", true, s));
    // `\x7f` is ASCII under `(?-u)`, `\x80` a byte.
    try testing.expect(try rustFull("(?-u)\\x7f", false, "\x7f"));
    try testing.expectError(error.InvalidUtf8, Regex.compileOptions(testing.allocator, "(?-u)\\x80", .{ .syntax = .rust }));
    try testing.expect(try rustFull("(?-u)\\x80", true, "\x80"));
    // Under `(?i-u)` a non-ASCII literal stays itself.
    try testing.expect(try rustFull("(?i-u)\u{e9}", false, "\u{e9}"));
    try testing.expect(!try rustFull("(?i-u)\u{e9}", false, "\u{c9}"));
}

test "Rust grammar: CRLF mode, look-around, property queries, limits" {
    // `(?R)`: `.` excludes both `\r` and `\n`, and takes the bytes between.
    try testing.expect(!try rustFull("(?R).", false, "\r"));
    try testing.expect(!try rustFull("(?R).", false, "\n"));
    for ([_][]const u8{ "a", "\x0b", "\x0c", "\x0e" }) |s| try testing.expect(try rustFull("(?R).", false, s));
    // `^` and `$` see a lone `\r` as a line end only in CRLF mode.
    var cr = try Regex.compileOptions(testing.allocator, "(?mR)^a", .{ .syntax = .rust });
    defer cr.deinit(testing.allocator);
    try testing.expect(cr.isMatch("\ra"));
    var lf = try Regex.compileOptions(testing.allocator, "(?m)^a", .{ .syntax = .rust });
    defer lf.deinit(testing.allocator);
    try testing.expect(!lf.isMatch("\ra"));
    var cr2 = try Regex.compileOptions(testing.allocator, "(?mR)a$", .{ .syntax = .rust });
    defer cr2.deinit(testing.allocator);
    try testing.expect(cr2.isMatch("a\r"));
    var lf2 = try Regex.compileOptions(testing.allocator, "(?m)a$", .{ .syntax = .rust });
    defer lf2.deinit(testing.allocator);
    try testing.expect(!lf2.isMatch("a\r"));
    // No look-around; `(?<=` is not a named group.
    try refuses(error.InvalidPerlOp, "(?<=a)b", .rust);
    try refuses(error.InvalidPerlOp, "(?<!a)b", .rust);
    try refusesAny("(?=a)b", .rust);
    try refusesAny("(?", .rust);
    // `!=` negates a property query.
    try testing.expect(try rustFull("\\p{Script!=Greek}", false, "a"));
    try testing.expect(!try rustFull("\\p{Script!=Greek}", false, "\u{3b1}"));
    try testing.expect(!try rustFull("\\P{Script!=Greek}", false, "a"));
    try testing.expect(try rustFull("\\P{Script!=Greek}", false, "\u{3b1}"));
    // An over-long query is refused, not copied past its buffer.
    try refuses(error.InvalidUnicodeClass, "\\p{" ++ rep("a", 300) ++ "}", .rust);
    // An over-long `\b{...}` name is refused.
    try refuses(error.InvalidEscape, "\\b{" ++ rep("a", 20) ++ "}", .rust);
    // Counts past the Rust limit.
    try refuses(error.InvalidRepeatSize, "a{100001}", .rust);
    try refuses(error.InvalidRepeatSize, "a{0,100001}", .rust);
    try refuses(error.InvalidRepeatSize, "a{3,2}", .rust);
    // `(?-u)\W` etc. are byte classes: not on `&str`.
    try testing.expectError(error.InvalidUtf8, Regex.compileOptions(testing.allocator, "(?-u)\\W", .{ .syntax = .rust }));
}

test "Teddy and the literal prefilter find a literal at every offset and tail" {
    const sets = [_][]const []const u8{
        &.{ "ab", "cd" },
        &.{ "abc", "abd", "xyz" },
        &.{ "ab", "cd", "efg", "hij", "klmn" },
        &.{ "ab", "cd", "ef", "gh", "ij", "kl", "mn", "op" },
        &.{ "ab", "cd", "ef", "gh", "ij", "kl", "mn", "op", "qr" },
    };
    inline for (sets) |set| {
        const pattern = comptime blk: {
            var s: []const u8 = "";
            for (set, 0..) |lit, i| s = s ++ (if (i == 0) "" else "|") ++ lit;
            break :blk s;
        };
        var re = try Regex.compile(testing.allocator, pattern);
        defer re.deinit(testing.allocator);
        var buf: [160]u8 = undefined;
        for ([_]usize{ 2, 15, 16, 17, 31, 32, 33, 47, 64, 100, 160 }) |n| {
            for (set) |lit| {
                var p: usize = 0;
                while (p + lit.len <= n) : (p += 1) {
                    @memset(buf[0..n], '_');
                    @memcpy(buf[p..][0..lit.len], lit);
                    const got = try re.find(testing.allocator, buf[0..n]);
                    errdefer std.debug.print("/{s}/ n={d} p={d}\n", .{ pattern, n, p });
                    try testing.expectEqual(@as(?regex.Span, .{ .start = p, .end = p + lit.len }), got);
                }
            }
            @memset(buf[0..n], '_');
            try testing.expectEqual(@as(?regex.Span, null), try re.find(testing.allocator, buf[0..n]));
        }
    }
}

const Matcher = regex.Matcher;
const Span = regex.Span;

fn expectSameCaptures(pm: *Matcher, m: *Matcher, k: usize, t: []const u8, from: usize) !void {
    var a: [10]?Span = undefined;
    var b: [10]?Span = undefined;
    const ra = pm.captures(t, from, a[0..k]);
    const rb = m.captures(t, from, b[0..k]);
    try testing.expectEqual(ra, rb);
    if (ra) try testing.expectEqualSlices(?Span, a[0..k], b[0..k]);
    try testing.expectEqual(pm.findAnchored(t, from), m.findAnchored(t, from));
}

test "every engine and table size agrees with the Pike VM, on text with multi-byte and invalid sequences" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x2611_0012);
    const rng = prng.random();
    const patterns = [_][]const u8{
        "a+",                       "a*b",                          "(a|b)+c?",        "(?i)k+",               "\\b\u{e9}\\w*",       "\\w+\\b",
        "[a-c\u{e9}\u{20ac}]+",     "(?m)^a.*$",                    "a$",              "^b",                   "\\Bb",                "(a+)(b+)?",
        "(?s).{2,4}b",              "(?U)a+",                       "a+?b",            "[^a\\n]+",             "\\pL+",               "\\PL",
        "(?i)\u{e9}+",              "(\u{e9}|\u{20ac}|\u{1f600})+", "\\x{FFFD}",       "(?:ab|a)(?:bc)?",      "x*",                  "a|",
        "\\b",                      "\\B",                          "(?i)\u{1c6}",     "[\\x{80}-\\x{7ff}]+$", "b+$",                 "(a|ab)(c|bcd)(d*)",
        "(?:a*)*b",                 "(a*)+",                        "[[:alpha:]]+",    "\\d+\\.\\d*",          "a{2,3}",              "(?i)stra\u{df}e",
        "\u{e9}\\x{fffd}b|\u{17e}", "(?i)k\\w*\u{212a}",            "(a)(b)(c)(d)(e)", "\\A\\w+\\z",           "[a-z]+\\d|\\d+[a-z]", "(?:\\n|^)b$",
    };
    const pieces = [_][]const u8{
        "a",       "a",        "b",    "b", "c", "d",       "\u{e9}",  "\u{20ac}", "\u{1f600}", "\n",       " ",      "k",
        "K",       "\u{212a}", "1",    "_", ".", "\u{1c6}", "\u{1c5}", "\xff",     "\xc3",      "\xe2\x82", "\u{df}", "s",
        "\u{17f}", "\u{17e}",  "\x82",
    };
    var text: [2300]u8 = undefined;
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        const k = @min(re.names.len, 10);
        for (0..4) |mode| {
            var m = try Matcher.init(gpa, &re);
            defer m.deinit();
            m.dfa_eager = mode >= 1;
            m.dfa_small = mode == 2;
            m.onepass_off = mode == 3;
            for (0..30) |round| {
                const want: usize = if (round % 10 == 9) 2200 else rng.uintLessThan(usize, 90);
                var n: usize = 0;
                const narrow = round % 3 == 1;
                while (n < want) {
                    const piece = pieces[rng.uintLessThan(usize, if (narrow) 8 else pieces.len)];
                    @memcpy(text[n..][0..piece.len], piece);
                    n += piece.len;
                }
                const t = text[0..n];
                errdefer std.debug.print("/{s}/ mode={d} on \"{f}\"\n", .{ p, mode, std.zig.fmtString(t) });
                var it = m.iterator(t);
                var pit = pm.iterator(t);
                while (true) {
                    const a = it.next();
                    try testing.expectEqual(pit.next(), a);
                    if (a == null) break;
                }
                for ([_]usize{ 0, n / 3, n / 2, n -| 1, n }) |from| {
                    try testing.expectEqual(pm.find(t, from), m.find(t, from));
                    try expectSameCaptures(&pm, &m, k, t, from);
                }
                if (n <= 120 and mode == 0) {
                    const want_match = re.isMatch(t);
                    var rb: [4]u8 = undefined;
                    for ([_]usize{ 1, 4 }) |size| {
                        var tr: std.testing.Reader = .init(rb[0..size], &.{.{ .buffer = t }});
                        try testing.expectEqual(want_match, try re.isMatchReader(&tr.interface));
                    }
                }
            }
        }
    }
}

test "longest-match (POSIX) agrees across engines" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x2611_0013);
    const rng = prng.random();
    const patterns = [_][]const u8{ "a|ab", "(a|ab)(c|bcd)", "a*", "[ab]+b", "(a+)(b*)", "a?", "(ab|a)(bc|c)?", "x*|y" };
    var text: [300]u8 = undefined;
    for (patterns) |p| {
        var re = try Regex.compilePosix(gpa, p);
        defer re.deinit(gpa);
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        for (0..60) |_| {
            const n = rng.uintLessThan(usize, text.len);
            for (text[0..n]) |*c| c.* = "abcdxy"[rng.uintLessThan(usize, 6)];
            const t = text[0..n];
            var it = m.iterator(t);
            var pit = pm.iterator(t);
            while (true) {
                const a = it.next();
                try testing.expectEqual(pit.next(), a);
                if (a == null) break;
            }
            try expectSameCaptures(&pm, &m, @min(re.names.len, 10), t, n / 2);
        }
    }
}

test "Rust hex escapes: widths, braces, surrogates and the top of the range" {
    try testing.expect(try rustFull("\\x41", false, "A"));
    try testing.expect(try rustFull("\\u00e9", false, "\u{e9}"));
    try testing.expect(try rustFull("\\U000000e9", false, "\u{e9}"));
    try testing.expect(try rustFull("\\x{10ffff}", false, "\u{10ffff}"));
    try testing.expect(try rustFull("\\x{0000e9}", false, "\u{e9}"));
    try refuses(error.InvalidEscape, "\\x{110000}", .rust);
    try refuses(error.InvalidEscape, "\\x{d800}", .rust);
    try refuses(error.InvalidEscape, "\\x{dfff}", .rust);
    try refuses(error.InvalidEscape, "\\x{}", .rust);
    try refuses(error.InvalidEscape, "\\x4", .rust);
    try refuses(error.InvalidEscape, "\\u00e", .rust);
    try refuses(error.InvalidEscape, "\\xZZ", .rust);
    try compiles("\\x{d7ff}\\x{e000}", .rust);
}
