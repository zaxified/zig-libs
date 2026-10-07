// SPDX-License-Identifier: MIT
//! Structure-aware harness over the whole module: a pattern drawn from the
//! grammar (literals, classes, Perl and POSIX classes, assertions, groups,
//! flags, every quantifier form, alternation) or that same text damaged
//! byte-wise, and an input over a small alphabet with invalid UTF-8.
//! Oracles:
//!
//!   - no crash, no hang, no leak (compile is `compile`-or-error; the
//!     driver's DebugAllocator sees the Matcher and the Regex freed);
//!   - `isMatch` ⇔ `Matcher.find` finds a match; `fullMatch` ⇒ `isMatch`;
//!   - `captures` group 0 is `find`'s span; every group span lies inside it
//!     and inside the input, start ≤ end;
//!   - the iterator yields non-overlapping spans in increasing order, its
//!     first span is `find`'s, no empty span right after the previous one,
//!     no span splitting a code point, and it ends;
//!   - a literal-only pattern (no metacharacter drawn) matches exactly where
//!     `std.mem.indexOf` finds it — a reference that shares no code;
//!   - the two engines agree: the backtracker (short texts) and the Pike VM
//!     (`pike_only`) give the same match and groups;
//!   - the reader front end agrees with the slice one (one byte per read);
//!   - leftmost-longest starts where leftmost-first does and ends no earlier;
//!   - `replaceAll(.., "$0")` gives the input back; `replaceAllLiteral(.., "")`
//!     removes exactly the iterator's spans; split pieces are disjoint from
//!     the matches; every match begins with `literalPrefix`, and a complete
//!     prefix is matched in full; `quoteMeta(input)` matches the input exactly.
//!
//! A share of the patterns is compiled in POSIX syntax (`compilePosix`).
//!
//! The Go oracle (`go_oracle_test.zig`) is what holds the answers to Go's;
//! this holds the engine to itself over far more shapes. Planted mutants
//! (2026-10-07): the harness fails on a broken unanchored restart, a missing
//! leftmost-first cut, a broken range search, a lost capture restore, a
//! byte-wise iterator advance and a kept empty-adjacent match; it does NOT see
//! `_` dropped from `\w` or a swapped split priority — pure semantics with no
//! reference here, both killed by the Go oracle.
//!
//! Driver: `REGEX_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there). 500 seeds also run in every
//! ordinary test run.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

/// Reach labels: the driver's `hit` (printed by `REGEX_FUZZ` runs) and a
/// local count the in-suite test checks.
const Label = enum { refused, compiled, full, matched, group, literal, posix };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn hit(comptime l: Label) void {
    fuzz_driver.hit(@tagName(l));
    reach[@intFromEnum(l)] += 1;
}

const Gen = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    literal_only: bool = true,
    groups: usize = 0,

    fn put(g: *Gen, s: []const u8) void {
        const n = @min(s.len, g.buf.len - g.len);
        @memcpy(g.buf[g.len..][0..n], s[0..n]);
        g.len += n;
    }

    fn meta(g: *Gen, s: []const u8) void {
        g.literal_only = false;
        g.put(s);
    }
};

fn genAtom(comptime S: type, src: *S, g: *Gen, depth: u32) void {
    switch (src.valueRangeAtMost(u8, 0, if (depth < 2) 13 else 7)) {
        0, 1, 2 => g.put(([_][]const u8{ "a", "b", "c", "é", "1", " ", "-" })[src.index(7)]),
        3 => g.meta("."),
        4 => g.meta(([_][]const u8{ "[ab]", "[^a]", "[a-c]", "[é1-2]", "[]a]", "[a-]", "[[:alpha:]]", "[^[:digit:]\\n]", "\\pL", "\\p{Greek}", "\\PN", "[\\p{Lu}a]", "(?i)\\p{Ll}" })[src.index(13)]),
        5 => g.meta(([_][]const u8{ "\\d", "\\w", "\\s", "\\D", "\\W", "\\S", "\\.", "\\x{e9}", "\\Qa.\\E" })[src.index(9)]),
        6 => g.meta(([_][]const u8{ "^", "$", "\\b", "\\B", "\\A", "\\z" })[src.index(6)]),
        7 => {
            // A flag group takes no repetition of its own.
            g.meta(([_][]const u8{ "(?i)", "(?m)", "(?s)", "(?U)", "(?-i)" })[src.index(5)]);
            return;
        },
        else => {
            g.meta(([_][]const u8{ "(", "(?:", "(?i:", "(?P<n>" })[src.index(4)]);
            g.groups += 1;
            genAlt(S, src, g, depth + 1);
            g.put(")");
        },
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) {
        g.meta(([_][]const u8{ "*", "+", "?", "{2}", "{0,2}", "{1,}", "*?", "+?", "{1,3}?" })[src.index(9)]);
    }
}

/// One to three alternatives of one to four atoms. A loop, not recursion:
/// a source that keeps answering the minimum (Smith outside `--fuzz`) must
/// still end.
fn genAlt(comptime S: type, src: *S, g: *Gen, depth: u32) void {
    for (0..src.valueRangeAtMost(u8, 1, 3), 0..) |_, i| {
        if (i != 0) g.meta("|");
        for (0..src.valueRangeAtMost(u8, 1, 3)) |_| genAtom(S, src, g, depth);
    }
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var g: Gen = .{};
    genAlt(S, src, &g, 0);
    // A share of the patterns is damaged byte-wise: the parser's error paths.
    if (src.valueRangeAtMost(u8, 0, 4) == 0 and g.len != 0) {
        g.literal_only = false;
        for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
            g.buf[src.index(g.len)] = ([_]u8{ '(', ')', '[', ']', '{', '}', '\\', '*', '|', 0xff, ':', '?' })[src.index(12)];
        }
    }
    const pattern = g.buf[0..g.len];

    var input_buf: [24]u8 = undefined;
    var il: usize = 0;
    for (0..src.valueRangeAtMost(u8, 0, 10)) |_| {
        const piece = ([_][]const u8{ "a", "b", "c", "1", " ", "\n", "é", "É", "-", "_", "\xff", "ab", "Ω", "ω" })[src.index(14)];
        if (il + piece.len > input_buf.len) break;
        @memcpy(input_buf[il..][0..piece.len], piece);
        il += piece.len;
    }
    // Now and then the input repeated to a few hundred bytes: the
    // prefilter's 32-byte scan and the backtracker's budget edge.
    var long_buf: [400]u8 = undefined;
    var input: []const u8 = input_buf[0..il];
    if (il != 0 and src.valueRangeAtMost(u8, 0, 7) == 0) {
        var ll: usize = 0;
        while (ll + il <= long_buf.len) : (ll += il) @memcpy(long_buf[ll..][0..il], input);
        input = long_buf[0..ll];
    }

    const posix = src.valueRangeAtMost(u8, 0, 5) == 0;
    var re = regex.Regex.compileOptions(gpa, pattern, .{ .syntax = if (posix) .posix else .perl }) catch |e| {
        if (e == error.OutOfMemory) return e;
        hit(.refused);
        return;
    };
    defer re.deinit(gpa);
    hit(.compiled);
    var m = try regex.Matcher.init(gpa, &re);
    defer m.deinit();

    const any = re.isMatch(input);
    const found = m.find(input, 0);
    if (any != (found != null)) return error.IsMatchDisagreesWithFind;
    if (re.fullMatch(input)) {
        hit(.full);
        if (!any) return error.FullMatchWithoutMatch;
    }
    if (found) |s| {
        hit(.matched);
        if (s.start > s.end or s.end > input.len) return error.SpanOutOfInput;
        var out: [regex.max_groups]?regex.Span = undefined;
        const groups = out[0..re.names.len];
        if (!m.captures(input, 0, groups)) return error.CapturesDisagreeWithFind;
        if (groups[0] == null or groups[0].?.start != s.start or groups[0].?.end != s.end) return error.GroupZeroIsNotTheMatch;
        for (groups[1..]) |gs| if (gs) |x| {
            hit(.group);
            if (x.start > x.end or x.start < s.start or x.end > s.end) return error.GroupOutsideMatch;
        };
    }
    var it = m.iterator(input);
    var prev_end: usize = 0;
    var n: usize = 0;
    while (it.next()) |s| : (n += 1) {
        if (n == 0 and (found == null or s.start != found.?.start or s.end != found.?.end)) return error.IteratorFirstIsNotFind;
        if (s.start < prev_end or s.end < s.start) return error.IteratorOverlaps;
        // Go's FindAll: an empty match right where the previous one ended is
        // skipped.
        if (n != 0 and s.start == s.end and s.start == prev_end) return error.IteratorEmptyNextToPrevious;
        if (!onBoundary(input, s.start) or !onBoundary(input, s.end)) return error.SpanSplitsACodePoint;
        prev_end = s.end;
        if (n > input.len + 1) return error.IteratorDoesNotEnd;
    }
    if ((n == 0) != (found == null)) return error.IteratorDisagreesWithFind;

    try crossChecks(gpa, &re, &m, input, found);
    if (posix) hit(.posix);

    if (g.literal_only and !posix) {
        hit(.literal);
        const want = std.mem.indexOf(u8, input, pattern);
        if ((want != null) != any) return error.LiteralReferenceDisagrees;
        if (want) |w| if (found.?.start != w or found.?.end != w + pattern.len) return error.LiteralReferenceSpan;
    }
}

/// The engine-against-engine and API invariants (see the file comment).
fn crossChecks(gpa: std.mem.Allocator, re: *const regex.Regex, m: *regex.Matcher, input: []const u8, found: ?regex.Span) anyerror!void {
    const ng = re.names.len;
    var g1: [regex.max_groups]?regex.Span = undefined;
    var g2: [regex.max_groups]?regex.Span = undefined;
    var pm = try regex.Matcher.init(gpa, re);
    defer pm.deinit();
    pm.pike_only = true;
    for (0..input.len + 1) |from| {
        const f1 = m.captures(input, from, g1[0..ng]);
        const f2 = pm.captures(input, from, g2[0..ng]);
        if (f1 != f2) return error.EnginesDisagree;
        if (f1) for (g1[0..ng], g2[0..ng]) |a, b| {
            if ((a == null) != (b == null)) return error.EnginesDisagreeOnGroups;
            if (a) |x| if (x.start != b.?.start or x.end != b.?.end) return error.EnginesDisagreeOnGroups;
        };
    }

    var rbuf: [4]u8 = undefined;
    var tr: std.testing.Reader = .init(&rbuf, &.{.{ .buffer = input }});
    tr.artificial_limit = .limited(1);
    const rf = try m.capturesReader(&tr.interface, g1[0..ng]);
    if (rf != (found != null)) return error.ReaderDisagrees;
    if (rf and (g1[0].?.start != found.?.start or g1[0].?.end != found.?.end)) return error.ReaderDisagreesOnSpan;
    var rbuf2: [4]u8 = undefined;
    var tr2: std.testing.Reader = .init(&rbuf2, &.{.{ .buffer = input }});
    tr2.artificial_limit = .limited(1);
    if (try re.isMatchReader(&tr2.interface) != (found != null)) return error.ReaderMatchDisagrees;

    if (!re.longest) {
        var lre = re.*;
        lre.longest = true;
        var lm = try regex.Matcher.init(gpa, &lre);
        defer lm.deinit();
        const l = lm.find(input, 0);
        if ((l == null) != (found == null)) return error.LongestDisagreesOnMatch;
        if (l) |x| if (x.start != found.?.start or x.end < found.?.end) return error.LongestNotLongest;
    }

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try m.replaceAll(&out.writer, input, "$0");
    if (!std.mem.eql(u8, out.written(), input)) return error.ReplaceIdentity;
    out.clearRetainingCapacity();
    try m.replaceAllLiteral(&out.writer, input, "");
    var removed: usize = 0;
    var it = m.iterator(input);
    while (it.next()) |x| removed += x.end - x.start;
    if (out.written().len + removed != input.len) return error.ReplaceRemovesOtherThanMatches;

    var sp = m.split(input, null);
    var pieces: usize = 0;
    while (sp.next()) |piece| : (pieces += 1) {
        const at = @intFromPtr(piece.ptr) - @intFromPtr(input.ptr);
        if (input.len != 0 and at + piece.len > input.len) return error.SplitOutsideInput;
        var it2 = m.iterator(input);
        while (it2.next()) |x| if (x.end > x.start and at < x.end and x.start < at + piece.len) return error.SplitOverlapsMatch;
    }
    if (pieces > input.len + 2) return error.SplitTooMany;

    out.clearRetainingCapacity();
    const complete = try re.literalPrefix(&out.writer);
    const prefix = out.written();
    var it3 = m.iterator(input);
    while (it3.next()) |x| if (!std.mem.startsWith(u8, input[x.start..], prefix)) return error.MatchWithoutLiteralPrefix;
    if (complete and !re.fullMatch(prefix)) return error.CompletePrefixNotMatched;

    if (std.unicode.utf8ValidateSlice(input)) {
        const q = try regex.quoteMetaAlloc(gpa, input);
        defer gpa.free(q);
        var qre = try regex.Regex.compile(gpa, q);
        defer qre.deinit(gpa);
        if (!qre.fullMatch(input)) return error.QuoteMetaDoesNotMatch;
    }
}

/// Not inside a UTF-8 sequence: the inputs hold only ASCII, `é`/`É` and a
/// lone 0xff, so a continuation byte is always the middle of `é`/`É`.
fn onBoundary(input: []const u8, i: usize) bool {
    return i == input.len or input[i] & 0xc0 != 0x80;
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor — so each seed is its own input
/// (a ranged draw first would collapse every seed to one, `check-fuzz-reach`).
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        comptime std.debug.assert(T == bool);
        return self.cur.byte() & 1 == 1;
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzOne(_: void, smith: *testing.Smith) anyerror!void {
    var script: [1024]u8 = undefined;
    const n = smith.slice(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return harness(ScriptSource, &src, testing.allocator);
}

test "fuzz: compile and match never trap, and the entry points agree" {
    try testing.fuzz({}, fuzzOne, .{});
}

test "fuzz driver: REGEX_FUZZ" {
    fuzz_driver.run(harness, .{ .prefix = "REGEX_FUZZ", .name = "regex" }) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
}

test "fuzz harness: 500 seeds in every test run, and it gets everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    // Reach before verdict: every oracle had something to judge.
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("unreached: {t}\n", .{@as(Label, @enumFromInt(i))});
        return error.Unreached;
    };
}
