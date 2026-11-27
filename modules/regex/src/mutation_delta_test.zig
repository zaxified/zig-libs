// SPDX-License-Identifier: MIT

//! Tests added by the delta mutation run of 2026-11-27 (the code that came in
//! since the 2026-11-12 card: bytes mode through a reader, the byte-stepping
//! DFAs, `ByteAutomaton`, the `large_programs` heap scratch, the
//! Unicode-word-assertion give-up of the DFAs). Public API only; the tests
//! that need the file-private probe hook sit at the end of `root.zig`.
//! Expected values come from the documented semantics (Go / Rust behaviour,
//! the doc comments of the public declarations) or from a second, independent
//! engine of this module (the Pike VM, the set VM, `fullMatch`).

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");

const Regex = regex.Regex;
const Matcher = regex.Matcher;
const ByteAutomaton = regex.ByteAutomaton;
const Span = regex.Span;

const gpa = testing.allocator;

/// Rust grammar over bytes that need not be UTF-8.
const bytes_opts: regex.Options = .{ .syntax = .rust, .utf8 = false };

/// A reader that serves `left`, then fails (`error.ReadFailed`).
const Half = struct {
    r: std.Io.Reader,
    left: []const u8,

    fn init(buf: []u8, data: []const u8) Half {
        return .{ .r = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 }, .left = data };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Half = @fieldParentPtr("r", r);
        if (self.left.len == 0) return error.ReadFailed;
        const n = limit.minInt(self.left.len);
        try w.writeAll(self.left[0..n]);
        self.left = self.left[n..];
        return n;
    }
};

fn repeated(comptime s: []const u8, comptime n: usize) []const u8 {
    return comptime blk: {
        var out: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
        const final = out;
        break :blk &final;
    };
}

// ── bytes mode through a reader that fails ─────────────────────────────────

test "mutation 2026-11-27: bytes mode through a failing reader — no error once the answer is settled, ReadFailed before it, buffered or not" {
    var re = try Regex.compileOptions(gpa, "ab", bytes_opts);
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    var storage: [8]u8 = undefined;
    for ([_][]u8{ storage[0..8], storage[0..0] }) |buf| {
        // The reader fails right after "ab": the answer stands.
        var h1 = Half.init(buf, "xab");
        try testing.expect(try re.isMatchReader(&h1.r));
        var h2 = Half.init(buf, "xab");
        try testing.expectEqual(@as(?Span, .{ .start = 1, .end = 3 }), try m.findReader(&h2.r));
        var h3 = Half.init(buf, "xab");
        var out: [1]?Span = undefined;
        try testing.expect(try m.capturesReader(&h3.r, &out));
        try testing.expectEqual(@as(?Span, .{ .start = 1, .end = 3 }), out[0]);
        // It fails before the answer is settled: an error, not "no match".
        var c1 = Half.init(buf, "xa");
        try testing.expectError(error.ReadFailed, re.isMatchReader(&c1.r));
        var c2 = Half.init(buf, "xa");
        try testing.expectError(error.ReadFailed, m.findReader(&c2.r));
        var c3 = Half.init(buf, "xa");
        try testing.expectError(error.ReadFailed, m.capturesReader(&c3.r, &out));
        // A settled "no match" over text that ended is none, not an error.
        var e1: std.testing.Reader = .init(buf, &.{.{ .buffer = "xyz" }});
        try testing.expect(!(try re.isMatchReader(&e1.interface)));
        var e2: std.testing.Reader = .init(buf, &.{.{ .buffer = "xyz" }});
        try testing.expectEqual(@as(?Span, null), try m.findReader(&e2.interface));
        var e3: std.testing.Reader = .init(buf, &.{.{ .buffer = "xyz" }});
        try testing.expect(!(try m.capturesReader(&e3.interface, &out)));
    }
}

test "mutation 2026-11-27: a large program's reader scan — same rule for the heap scratch (isMatchReaderAlloc)" {
    const pat = "a{1000}b{1000}c{1000}d{1000}e{1000}";
    var re = try Regex.compileOptions(gpa, pat, .{ .large_programs = true });
    defer re.deinit(gpa);
    try testing.expect(re.isLarge());
    const text = try gpa.alloc(u8, 5000);
    defer gpa.free(text);
    for (text, 0..) |*c, i| c.* = "abcde"[i / 1000];
    var buf: [64]u8 = undefined;
    var ok = Half.init(&buf, text);
    try testing.expect(try re.isMatchReaderAlloc(gpa, &ok.r)); // fails right after the match
    var cut = Half.init(&buf, text[0..4999]);
    try testing.expectError(error.ReadFailed, re.isMatchReaderAlloc(gpa, &cut.r));
}

test "mutation 2026-11-27: a large program's scratch holds two bitsets, two lists and a closure stack" {
    const pat = "a{1000}b{1000}c{1000}d{1000}e{1000}";
    var re = try Regex.compileOptions(gpa, pat, .{ .large_programs = true });
    defer re.deinit(gpa);
    try testing.expect(re.isLarge());
    const text = try gpa.alloc(u8, 5000);
    defer gpa.free(text);
    for (text, 0..) |*c, i| c.* = "abcde"[i / 1000];
    var fa = std.testing.FailingAllocator.init(gpa, .{});
    try testing.expect(try re.isMatchAlloc(fa.allocator(), text));
    const n = re.insts.len;
    const words = (n + 63) / 64;
    // Two `n`-bit sets (8 bytes a word), two lists of `n` u16, and a closure
    // stack of at least two entries for every instruction but the match.
    const need = 2 * words * 8 + 2 * n * 2 + (2 * (n - 1)) * 2;
    try testing.expect(fa.allocated_bytes >= need);
    try testing.expectEqual(@as(usize, 0), fa.allocated_bytes - fa.freed_bytes); // freed again
}

// ── Unicode word assertions past ASCII ────────────────────────────────────

test "mutation 2026-11-27: an end-anchored program under a Unicode word assertion, text ending past ASCII — the VM's answer, not the DFA's ASCII guess" {
    const cases = [_]struct { []const u8, []const u8, bool }{
        // é, À are word letters; — (U+2014) is not.
        .{ "\\w\\b$", "a\u{e9}", true },
        .{ "\\w\\b$", "\u{e9}", true },
        .{ "\\w\\b$", "x\u{c0}", true },
        .{ "\\w\\b$", "\u{e9} ", false },
        .{ "\\w\\b$", "a\u{2014}", false },
        .{ "\\B$", "a\u{e9}", false },
        .{ "\\B$", "\u{e9}", false },
        .{ "\\B$", "x\u{c0}", false },
        .{ "\\B$", "a\u{2014}", true },
        .{ "[a-z\u{e9}]+\\b$", "ab\u{e9}", true },
        .{ "\u{e9}\\b$", "a\u{e9}", true },
        .{ "\u{e9}\\B$", "a\u{e9}", false },
    };
    for (cases) |c| {
        errdefer std.debug.print("/{s}/ on \"{s}\"\n", .{ c[0], c[1] });
        var re = try Regex.compileOptions(gpa, c[0], .{ .syntax = .rust });
        defer re.deinit(gpa);
        try testing.expectEqual(c[2], re.isMatch(c[1]));
    }
}

test "mutation 2026-11-27: Matcher.find under a Unicode \\b, a prefilter landing right after a letter whose last byte is 0x80" {
    // U+00C0 (À) is c3 80: the byte before the landing is 0x80, a letter.
    var re = try Regex.compileOptions(gpa, "\\ba", .{ .syntax = .rust });
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    m.dfa_eager = true;
    try testing.expectEqual(@as(?Span, null), m.find(" \u{c0}a", 0));
    try testing.expectEqual(@as(?Span, .{ .start = 5, .end = 6 }), m.find(" \u{c0}a a", 0));
    var pike = try Matcher.init(gpa, &re);
    defer pike.deinit();
    pike.pike_only = true;
    try testing.expectEqual(@as(?Span, null), pike.find(" \u{c0}a", 0));
}

test "mutation 2026-11-27: Unicode word assertions — the find DFAs and the Pike VM agree on texts with letters, dashes and stray bytes" {
    const patterns = [_][]const u8{ "\\ba", "a\\b", "\\Bb", "b\\B", "\\b{start}a", "\\w\\b", "(a|\u{e9})\\b", "\\b(a+)" };
    const alphabet = [_][]const u8{ "a", "b", " ", "\u{e9}", "\u{c0}", "\u{2014}", "\x80", "\xff", "_", "1" };
    var prng = std.Random.DefaultPrng.init(0x5eed_0ff1ce);
    const rnd = prng.random();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (patterns) |pat| {
        var re = try Regex.compileOptions(gpa, pat, .{ .syntax = .rust });
        defer re.deinit(gpa);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        var pike = try Matcher.init(gpa, &re);
        defer pike.deinit();
        pike.pike_only = true;
        for (0..150) |_| {
            text.clearRetainingCapacity();
            const len = 1 + rnd.uintLessThan(usize, 9);
            for (0..len) |_| try text.appendSlice(gpa, alphabet[rnd.uintLessThan(usize, alphabet.len)]);
            var from: usize = 0;
            while (from <= text.items.len) : (from += 1) {
                errdefer std.debug.print("/{s}/ on \"{s}\" from {d}\n", .{ pat, text.items, from });
                try testing.expectEqual(pike.find(text.items, from), m.find(text.items, from));
            }
        }
    }
}

// ── bytes mode: the byte-stepping DFAs ─────────────────────────────────────

test "mutation 2026-11-27: bytes mode, Unicode \\b — a skip that lands after a letter ending in 0x80 hands the answer to the VM" {
    var re = try Regex.compileOptions(gpa, "\\bab", bytes_opts);
    defer re.deinit(gpa);
    // U+00C0 (c3 80) is a word letter: there is no boundary before "ab".
    try testing.expect(!re.isMatch(" \xc3\x80ab"));
    try testing.expect(re.isMatch(" \xc3\x80 ab"));
    try testing.expect(re.isMatch(" \xe2\x80\x94ab")); // an em dash is not a word character
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    m.dfa_eager = true;
    try testing.expectEqual(@as(?Span, null), m.find(" \xc3\x80ab", 0));
    try testing.expectEqual(@as(?Span, .{ .start = 4, .end = 6 }), m.find(" \xc3\x80 ab", 0));
    try testing.expectEqual(@as(?Span, .{ .start = 4, .end = 6 }), m.find(" \xe2\x80\x94ab", 0));
}

test "mutation 2026-11-27: bytes mode, a valid lead byte is never cached — what its sequence is depends on the bytes after it" {
    // Each text holds the lead byte twice from the same state: once cut
    // short (so it takes nothing), once with its whole sequence. (Two
    // alternatives: a pure literal would be found by the prefilter alone.)
    const cases = [_]struct { []const u8, []const u8, Span }{
        .{ "\\x{80}x|\\x{1ff}y", "a\xc2Aa\xc2\x80x", .{ .start = 4, .end = 7 } }, // c2 80 = U+0080
        .{ "\\x{100000}x|\\x{10ffff}y", "a\xf4Aa\xf4\x80\x80\x80x", .{ .start = 4, .end = 9 } }, // f4 80 80 80 = U+100000
        .{ "\\x{800}x|\\x{fff}y", "a\xe0Aa\xe0\xa0\x80x", .{ .start = 4, .end = 8 } }, // e0 a0 80 = U+0800
    };
    for (cases) |c| {
        errdefer std.debug.print("/{s}/\n", .{c[0]});
        var re = try Regex.compileOptions(gpa, c[0], bytes_opts);
        defer re.deinit(gpa);
        try testing.expect(re.isMatch(c[1]));
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        try testing.expectEqual(@as(?Span, c[2]), m.find(c[1], 0));
        var pike = try Matcher.init(gpa, &re);
        defer pike.deinit();
        pike.pike_only = true;
        try testing.expectEqual(@as(?Span, c[2]), pike.find(c[1], 0));
    }
}

test "mutation 2026-11-27: bytes mode, a chain of literals crossing the 64th instruction (a state is a two-word set)" {
    // Every length from one literal to ~120: the consuming instruction at
    // program counter 63 puts its successor into word 1 of the state.
    var pat: std.ArrayList(u8) = .empty;
    defer pat.deinit(gpa);
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    var k: usize = 1;
    while (k <= 118) : (k += 1) {
        try pat.append(gpa, 'a');
        try text.append(gpa, 'a');
        var re = try Regex.compileOptions(gpa, pat.items, bytes_opts);
        defer re.deinit(gpa);
        errdefer std.debug.print("k = {d} ({d} instructions)\n", .{ k, re.insts.len });
        try testing.expect(re.fullMatch(text.items));
        try testing.expect(re.isMatch(text.items));
        if (k > 1) {
            try testing.expect(!re.fullMatch(text.items[1..]));
            try testing.expect(!re.isMatch(text.items[1..]));
        }
    }
}

test "mutation 2026-11-27: bytes mode, states that differ only in the second word of the set are different states" {
    // 66 literals, then one of two branches: the branch's instructions sit
    // past program counter 64, so "after a" and "after b" differ only there.
    const z = comptime repeated("z", 66);
    var re = try Regex.compileOptions(gpa, "z{66}(?:ax|by)", bytes_opts);
    defer re.deinit(gpa);
    try testing.expect(re.insts.len <= 128);
    try testing.expect(re.isMatch(z ++ "ax"));
    try testing.expect(re.isMatch(z ++ "by"));
    try testing.expect(!re.isMatch(z ++ "ay"));
    try testing.expect(!re.isMatch(z ++ "bx"));
    // Both branches in one scan (one state table).
    try testing.expect(re.isMatch(z ++ "ay" ++ z ++ "by"));
    try testing.expect(re.isMatch(z ++ "bx" ++ z ++ "ax"));
    try testing.expect(!re.isMatch(z ++ "ay" ++ z ++ "bx"));
    try testing.expect(!re.isMatch(z ++ "bx" ++ z ++ "ay"));
    try testing.expect(re.fullMatch(z ++ "by"));
    try testing.expect(!re.fullMatch(z ++ "bx"));
}

test "mutation 2026-11-27: bytes mode, a scan that outgrows the 32-state table gives the set VM's answers (reader scan = set VM)" {
    const patterns = [_][]const u8{ "[ab].{5}c", "(?-u:\\b)[ab].{4}c", "\\b[ab].{5}c", "[ab].{4}c|(?-u:\\xff)z" };
    const alphabet = [_][]const u8{ "a", "b", "c", " ", "_", "-", "z", "\xff", "\xc3\xa9" };
    var prng = std.Random.DefaultPrng.init(0xb17e5);
    const rnd = prng.random();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (patterns) |pat| {
        var re = try Regex.compileOptions(gpa, pat, bytes_opts);
        defer re.deinit(gpa);
        var hits: usize = 0;
        for (0..700) |_| {
            text.clearRetainingCapacity();
            const len = 40 + rnd.uintLessThan(usize, 160);
            for (0..len) |_| try text.appendSlice(gpa, alphabet[rnd.uintLessThan(usize, alphabet.len)]);
            errdefer std.debug.print("/{s}/ on \"{s}\"\n", .{ pat, text.items });
            var r: std.Io.Reader = .fixed(text.items);
            const want = try re.isMatchReader(&r); // the byte-stepping set VM
            try testing.expectEqual(want, re.isMatch(text.items));
            if (want) hits += 1;
        }
        try testing.expect(hits > 0);
    }
}

// ── the reader window of bytes mode ────────────────────────────────────────

test "mutation 2026-11-27: bytes mode through a reader sees the whole four-byte letter before and after a position" {
    // U+10000 (f0 90 80 80) is a letter: no boundary beside it.
    const cases = [_]struct { []const u8, []const u8, bool }{
        .{ "\\ba", "\xf0\x90\x80\x80a", false },
        .{ "a\\b", "a\xf0\x90\x80\x80", false },
        .{ "\\ba", "\xf0\x90\x80\x80 a", true },
        .{ "a\\b", "a \xf0\x90\x80\x80", true },
        .{ "\\Ba", "\xf0\x90\x80\x80a", true },
        .{ "a\\B", "a\xf0\x90\x80\x80", true },
    };
    var storage: [9]u8 = undefined;
    for (cases) |c| {
        var re = try Regex.compileOptions(gpa, c[0], bytes_opts);
        defer re.deinit(gpa);
        try testing.expectEqual(c[2], re.isMatch(c[1])); // the slice scan
        for ([_]usize{ 0, 1, 2, 3, 4, 9 }) |bl| {
            errdefer std.debug.print("/{s}/ on \"{s}\" buffer {d}\n", .{ c[0], c[1], bl });
            var tr: std.testing.Reader = .init(storage[0..bl], &.{.{ .buffer = c[1] }});
            tr.artificial_limit = .limited(1);
            try testing.expectEqual(c[2], try re.isMatchReader(&tr.interface));
        }
    }
}

// ── ByteAutomaton ──────────────────────────────────────────────────────────

test "mutation 2026-11-27: ByteAutomaton.init takes exactly the programs of up to max_program instructions and the `^` / `$` assertions" {
    // The size bound, at every length around it.
    var saw_edge = false;
    var n: usize = 100;
    while (n <= 135) : (n += 1) {
        var buf: [16]u8 = undefined;
        const pat = try std.fmt.bufPrint(&buf, "a{{{d}}}", .{n});
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        if (re.insts.len == ByteAutomaton.max_program) saw_edge = true;
        if (re.insts.len <= ByteAutomaton.max_program) {
            _ = try ByteAutomaton.init(&re);
        } else {
            try testing.expectError(error.TooManyInstructions, ByteAutomaton.init(&re));
        }
    }
    try testing.expect(saw_edge);
    // `^` and `$` (without `(?m)`) are supported, each alone and together.
    for ([_][]const u8{ "^abc", "abc$", "^abc$", "^$", "\\A\\z", "^a|b$", "a$|^b" }) |pat| {
        errdefer std.debug.print("/{s}/\n", .{pat});
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        _ = try ByteAutomaton.init(&re);
    }
    // Anything else that looks at the text around the position is refused.
    for ([_][]const u8{ "\\bx", "x\\B", "(?m)^a", "(?m)a$", "a(?m:$)" }) |pat| {
        errdefer std.debug.print("/{s}/\n", .{pat});
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        try testing.expectError(error.UnsupportedAssertion, ByteAutomaton.init(&re));
    }
}

test "mutation 2026-11-27: ByteAutomaton accepts exactly the keys fullMatch does — assertions mid-pattern, empty loops, invalid sequences" {
    const patterns = [_][]const u8{
        "$^",       "^$",      "a^b",        "a$b",          "^a",         "a$",   "(a*)*b",      "(|a)+b",   "(a|b*)*c",
        "(?:^|a)b", "\\x{80}", "\\x{fffd}A", "\\x{fffd}{3}", "\\x{fffd}+", "[^a]", "\\x{10ffff}", "\\x{800}", "(a|ab)(c|bcd)",
        "\\A\\z",   "a\\z|b",
    };
    const keys = [_][]const u8{
        "",                 "a",     "b",            "ab",           "aab",              "ac",       "bc",     "c",        "abc",
        "\x80",             "\xc3A", "\xc3",         "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82", "\xff",   "\xc2\x80", "\xe0\xa0\x80",
        "\xf4\x8f\xbf\xbf", "A",     "\xc3\xc3\xa9", "\xe0\x80\x80", "\xf0\x9f\x98\x80", "aaab",     "abcbcd", "zz",
    };
    for (patterns) |pat| {
        errdefer std.debug.print("/{s}/\n", .{pat});
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        const au = try ByteAutomaton.init(&re);
        for (keys) |key| {
            errdefer std.debug.print("  key \"{s}\"\n", .{key});
            var s = au.start();
            for (key) |b| s = au.accept(s, b);
            try testing.expectEqual(re.fullMatch(key), au.isMatch(s));
        }
    }
}

test "mutation 2026-11-27: ByteAutomaton.canMatch sees threads past the 64th instruction" {
    var re = try Regex.compile(gpa, "z{70}");
    defer re.deinit(gpa);
    const au = try ByteAutomaton.init(&re);
    var s = au.start();
    for (0..70) |_| {
        // Alive until the key is whole: the continuation is still there.
        try testing.expect(au.canMatch(s));
        try testing.expect(!au.isMatch(s));
        s = au.accept(s, 'z');
    }
    try testing.expect(au.isMatch(s));
    try testing.expect(au.canMatch(s));
    s = au.accept(s, 'z');
    try testing.expect(!au.canMatch(s)); // 71 z's: no continuation matches
    try testing.expect(!au.isMatch(s));
    // A dead start: the first byte is wrong.
    try testing.expect(!au.canMatch(au.accept(au.start(), 'y')));
}

test "mutation 2026-11-27: bytes mode, a prefilter skip that needs a new context state when the 32-state table is exactly full" {
    // `[ab].{5}c` fills the table; `(?-u:\b)q` makes the contexts matter. After
    // a fill of every length, the threads die and a skip over two spaces
    // lands on an `a`: its context (after a space) has no state yet.
    var re = try Regex.compileOptions(gpa, "[ab].{5}c|(?-u:\\b)q", bytes_opts);
    defer re.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(0x7ab1e);
    const rnd = prng.random();
    var fill: [700]u8 = undefined;
    for (&fill) |*c| c.* = "abx"[rnd.uintLessThan(u8, 3)];
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..fill.len + 1) |len| {
        text.clearRetainingCapacity();
        try text.appendSlice(gpa, fill[0..len]);
        try text.appendSlice(gpa, "xxxxxxx  a");
        errdefer std.debug.print("fill length {d}\n", .{len});
        var r: std.Io.Reader = .fixed(text.items);
        try testing.expectEqual(try re.isMatchReader(&r), re.isMatch(text.items)); // the byte-stepping set VM
    }
    try testing.expect(re.isMatch("xxabxxxxc"));
    try testing.expect(re.isMatch("x q"));
    try testing.expect(!re.isMatch("xq a"));
}

test "mutation 2026-11-27: bytes mode through a reader, the window slides: the letter before a position stays whole at every offset" {
    // U+10000 (f0 90 80 80) after 5..12 word bytes: the window is dropped
    // from at different parities of the position.
    var re = try Regex.compileOptions(gpa, "\\ba", bytes_opts);
    defer re.deinit(gpa);
    var rb = try Regex.compileOptions(gpa, "\\Ba", bytes_opts);
    defer rb.deinit(gpa);
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    var storage: [9]u8 = undefined;
    for (5..13) |plen| {
        text.clearRetainingCapacity();
        for (0..plen) |_| try text.append(gpa, 'x');
        try text.appendSlice(gpa, "\xf0\x90\x80\x80a");
        for ([_]usize{ 0, 1, 4, 9 }) |bl| {
            errdefer std.debug.print("prefix {d}, buffer {d}\n", .{ plen, bl });
            var tr: std.testing.Reader = .init(storage[0..bl], &.{.{ .buffer = text.items }});
            tr.artificial_limit = .limited(1);
            try testing.expect(!(try re.isMatchReader(&tr.interface))); // no boundary between a letter and `a`
            var tr2: std.testing.Reader = .init(storage[0..bl], &.{.{ .buffer = text.items }});
            tr2.artificial_limit = .limited(1);
            try testing.expect(try rb.isMatchReader(&tr2.interface));
        }
    }
}
