// SPDX-License-Identifier: MIT

//! regex — RE2-syntax regular expressions in linear time.
//!
//! The grammar of Go's `regexp/syntax` (RE2): literals, `.`, classes
//! (`[a-z]`, `[^…]`, `\d\s\w`, `[[:alpha:]]`), groups (capturing, named
//! `(?P<n>…)`/`(?<n>…)`, non-capturing `(?:…)`), alternation, greedy and lazy
//! repetition up to `{1000}`, the flags `i m s U`, and the empty-width
//! assertions `^ $ \A \z \b \B`. Matching is a Pike VM over a Thompson NFA:
//! time linear in pattern × input, no backtracking, so no pattern can make it
//! explode (no backreferences or lookaround — RE2 leaves them out for that
//! reason). Leftmost-first semantics, as Go's `regexp` and Perl.
//!
//! Compiling needs no allocator: `comptimeCompile` builds the program at
//! compile time (a bad pattern is a compile error), `compile` at run time.
//! `isMatch` and `fullMatch` run in fixed stack scratch, with no allocator;
//! submatch positions (`Matcher`) take scratch sized by the program, once.
//!
//! Input is UTF-8 and matched per code point; an invalid byte reads as
//! U+FFFD, one byte wide (as Go). Not yet: Unicode property classes
//! (`\pL`, `\p{Greek}`) and case folding beyond ASCII (SPEC Backlog).

const std = @import("std");
const syntax = @import("syntax.zig");

pub const meta = .{
    .doc = "RE2-syntax regular expressions — Pike VM, linear time, comptime compile, alloc-free match",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // A compiled Regex is immutable; matching uses caller/stack scratch.
    .concurrency = .reentrant,
    .model_after = "Go regexp / RE2 (syntax and leftmost-first semantics)",
    .deps = .{},
};

pub const Error = syntax.Error;
pub const max_insts = syntax.max_insts;
pub const max_groups = syntax.max_groups;
pub const max_repeat = syntax.max_repeat;

const Inst = syntax.Inst;
const Range = syntax.Range;
const Assert = syntax.Assert;

/// A match: `input[start..end]`.
pub const Span = struct {
    start: usize,
    end: usize,

    pub fn slice(s: Span, input: []const u8) []const u8 {
        return input[s.start..s.end];
    }
};

/// A compiled pattern. Immutable; safe to share across threads.
pub const Regex = struct {
    insts: []const Inst,
    ranges: []const Range,
    /// Group names; [0] is the whole match, `""` an unnamed group.
    names: []const []const u8,
    /// Set by `compile`: the slices above are owned (free with `deinit`).
    owned: bool = false,

    /// Compile at run time. The result owns its tables; `deinit` frees them.
    pub fn compile(gpa: std.mem.Allocator, pattern: []const u8) (Error || std.mem.Allocator.Error)!Regex {
        const b = try gpa.create(syntax.Builder);
        defer gpa.destroy(b);
        try b.compile(pattern);
        const insts = try gpa.dupe(Inst, b.insts[0..b.ninsts]);
        errdefer gpa.free(insts);
        const ranges = try gpa.dupe(Range, b.ranges[0..b.nranges]);
        errdefer gpa.free(ranges);
        const names = try gpa.alloc([]const u8, b.ngroups);
        var done: usize = 0;
        errdefer {
            for (names[0..done]) |n| gpa.free(n);
            gpa.free(names);
        }
        for (names, b.names[0..b.ngroups]) |*slot, n| {
            slot.* = try gpa.dupe(u8, n);
            done += 1;
        }
        return .{ .insts = insts, .ranges = ranges, .names = names, .owned = true };
    }

    pub fn deinit(re: *Regex, gpa: std.mem.Allocator) void {
        if (re.owned) {
            gpa.free(re.insts);
            gpa.free(re.ranges);
            for (re.names) |n| gpa.free(n);
            gpa.free(re.names);
        }
        re.* = undefined;
    }

    /// Number of capture groups (group 0, the whole match, not counted).
    pub fn groupCount(re: *const Regex) usize {
        return re.names.len - 1;
    }

    /// Index of the first group named `name`, or null (Go lets two groups
    /// share a name).
    pub fn groupIndex(re: *const Regex, name: []const u8) ?usize {
        for (re.names[1..], 1..) |n, i| if (n.len != 0 and std.mem.eql(u8, n, name)) return i;
        return null;
    }

    /// Does the pattern match anywhere in `input`? (Go's `MatchString`.)
    /// No allocator; scratch on the stack, bounded by `max_insts`.
    pub fn isMatch(re: *const Regex, input: []const u8) bool {
        return re.runSet(input, false);
    }

    /// Does the pattern match all of `input`? (Go: `^(?:re)$` without `(?m)`.)
    /// Any way through the pattern counts, not only the leftmost-first one.
    pub fn fullMatch(re: *const Regex, input: []const u8) bool {
        return re.runSet(input, true);
    }

    /// Leftmost-first match, or null. Allocates the VM scratch for this one
    /// call; repeated matching should keep a `Matcher`.
    pub fn find(re: *const Regex, gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error!?Span {
        var m = try Matcher.init(gpa, re);
        defer m.deinit();
        return m.find(input, 0);
    }

    fn runSet(re: *const Regex, input: []const u8, full: bool) bool {
        var lists: [2]StateSet = .{ .{}, .{} };
        var stack: [2 * max_insts]u16 = undefined;
        var cur: *StateSet = &lists[0];
        var nxt: *StateSet = &lists[1];
        var pos: usize = 0;
        var prev: ?u21 = null;
        cur.clear();
        while (true) {
            const here = decode(input, pos);
            if (!full or pos == 0) re.closureSet(cur, 0, prev, here.cp, &stack);
            // No thread left: anchored, nothing can start later; unanchored,
            // the next position starts a new one.
            if (cur.n == 0 and (full or here.cp == null)) return false;
            nxt.clear();
            const after = if (here.cp != null) decode(input, pos + here.w) else here;
            for (cur.pcs[0..cur.n]) |pc| {
                switch (re.insts[pc]) {
                    .match => if (!full or pos == input.len) return true,
                    else => if (here.cp) |cp| if (re.consumes(pc, cp))
                        re.closureSet(nxt, pc + 1, cp, after.cp, &stack),
                }
            }
            if (here.cp == null) return false;
            pos += here.w;
            prev = here.cp;
            std.mem.swap(*StateSet, &cur, &nxt);
        }
    }

    /// Add `pc0` and every state reachable from it without consuming input,
    /// at a position between `prev` and `next`.
    fn closureSet(re: *const Regex, set: *StateSet, pc0: u16, prev: ?u21, next: ?u21, stack: *[2 * max_insts]u16) void {
        var sp: usize = 0;
        stack[sp] = pc0;
        sp += 1;
        while (sp != 0) {
            sp -= 1;
            const pc = stack[sp];
            if (set.seen.isSet(pc)) continue;
            set.seen.set(pc);
            switch (re.insts[pc]) {
                .jmp => |t| {
                    stack[sp] = t;
                    sp += 1;
                },
                .split => |s| {
                    stack[sp] = s.y;
                    stack[sp + 1] = s.x;
                    sp += 2;
                },
                .save => {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .assert => |a| if (assertHolds(a, prev, next)) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .rune, .any, .any_not_nl, .match => {
                    set.pcs[set.n] = pc;
                    set.n += 1;
                },
            }
        }
    }

    fn consumes(re: *const Regex, pc: u16, cp: u21) bool {
        return switch (re.insts[pc]) {
            .any => true,
            .any_not_nl => cp != '\n',
            .rune => |r| inRanges(re.ranges[r.start..][0..r.len], cp),
            else => false,
        };
    }
};

/// Compile `pattern` at compile time; a bad pattern is a compile error.
pub fn comptimeCompile(comptime pattern: []const u8) Regex {
    comptime {
        @setEvalBranchQuota(2_000_000);
        var b: syntax.Builder = .{};
        b.compile(pattern) catch |e| @compileError("regex: \"" ++ pattern ++ "\": " ++ @errorName(e));
        const insts = b.insts[0..b.ninsts].*;
        const ranges = b.ranges[0..b.nranges].*;
        var names: [b.ngroups][]const u8 = undefined;
        for (&names, b.names[0..b.ngroups]) |*slot, n| slot.* = n;
        const final_names = names;
        return .{ .insts = &insts, .ranges = &ranges, .names = &final_names };
    }
}

/// Check `pattern` without keeping a program (what `router` does at `add`).
pub fn validate(pattern: []const u8, scratch: *syntax.Builder) Error!void {
    return scratch.compile(pattern);
}

pub const Builder = syntax.Builder;

const StateSet = struct {
    pcs: [max_insts]u16 = undefined,
    n: u16 = 0,
    seen: std.StaticBitSet(max_insts) = .initEmpty(),

    fn clear(s: *StateSet) void {
        s.n = 0;
        s.seen = .initEmpty();
    }
};

// ── submatches ──────────────────────────────────────────────────────────────

const nil = std.math.maxInt(usize);

/// VM scratch for one `Regex`, sized once by its program: leftmost-first
/// `find`, `captures`, and a non-overlapping iterator. Not thread-safe — one
/// per thread; the `Regex` itself is shared.
pub const Matcher = struct {
    gpa: std.mem.Allocator,
    re: *const Regex,
    /// Capture slots per thread: two per group.
    k: usize,
    lists: [2]List,
    stack: []Entry,
    tmp: []usize,
    best: []usize,

    const List = struct {
        pcs: []u16,
        caps: []usize,
        seen: []u32,
        gen: u32 = 0,
        n: usize = 0,

        fn clear(l: *List) void {
            l.n = 0;
            l.gen +%= 1;
            if (l.gen == 0) {
                @memset(l.seen, 0);
                l.gen = 1;
            }
        }
    };

    const Entry = union(enum) { explore: u16, restore: struct { slot: u16, val: usize } };

    pub fn init(gpa: std.mem.Allocator, re: *const Regex) std.mem.Allocator.Error!Matcher {
        const n = re.insts.len;
        const k = re.names.len * 2;
        var m: Matcher = .{ .gpa = gpa, .re = re, .k = k, .lists = undefined, .stack = &.{}, .tmp = &.{}, .best = &.{} };
        var made: usize = 0;
        errdefer m.freeLists(made);
        for (&m.lists) |*l| {
            l.* = .{ .pcs = &.{}, .caps = &.{}, .seen = &.{} };
            l.pcs = try gpa.alloc(u16, n);
            l.caps = gpa.alloc(usize, n * k) catch |e| {
                gpa.free(l.pcs);
                return e;
            };
            l.seen = gpa.alloc(u32, n) catch |e| {
                gpa.free(l.pcs);
                gpa.free(l.caps);
                return e;
            };
            @memset(l.seen, 0);
            made += 1;
        }
        m.stack = try gpa.alloc(Entry, 3 * n);
        errdefer gpa.free(m.stack);
        m.tmp = try gpa.alloc(usize, k);
        errdefer gpa.free(m.tmp);
        m.best = try gpa.alloc(usize, k);
        return m;
    }

    fn freeLists(m: *Matcher, made: usize) void {
        for (m.lists[0..made]) |l| {
            m.gpa.free(l.pcs);
            m.gpa.free(l.caps);
            m.gpa.free(l.seen);
        }
    }

    pub fn deinit(m: *Matcher) void {
        m.freeLists(2);
        m.gpa.free(m.stack);
        m.gpa.free(m.tmp);
        m.gpa.free(m.best);
        m.* = undefined;
    }

    /// Leftmost-first match starting the search at `from` (the text before
    /// `from` still counts for `^`/`\b`), or null.
    pub fn find(m: *Matcher, input: []const u8, from: usize) ?Span {
        if (!m.run(input, from, false)) return null;
        return .{ .start = m.best[0], .end = m.best[1] };
    }

    /// Like `find`, filling `out[i]` with group i's span (null: the group
    /// took no part); `out` may be shorter or longer than the group count.
    pub fn captures(m: *Matcher, input: []const u8, from: usize, out: []?Span) bool {
        if (!m.run(input, from, false)) return false;
        for (out, 0..) |*slot, i| {
            slot.* = if (2 * i + 1 < m.k and m.best[2 * i] != nil and m.best[2 * i + 1] != nil)
                .{ .start = m.best[2 * i], .end = m.best[2 * i + 1] }
            else
                null;
        }
        return true;
    }

    /// Successive non-overlapping matches (Go's `FindAll`: an empty match
    /// right where the previous match ended is skipped).
    pub fn iterator(m: *Matcher, input: []const u8) Iterator {
        return .{ .m = m, .input = input };
    }

    pub const Iterator = struct {
        m: *Matcher,
        input: []const u8,
        pos: usize = 0,
        prev_end: ?usize = null,

        pub fn next(it: *Iterator) ?Span {
            while (it.pos <= it.input.len) {
                const s = it.m.find(it.input, it.pos) orelse {
                    it.pos = it.input.len + 1;
                    return null;
                };
                var accept = true;
                if (s.start == s.end) {
                    if (it.prev_end != null and s.start == it.prev_end.?) accept = false;
                    it.pos = if (s.end < it.input.len) s.end + decode(it.input, s.end).w else it.input.len + 1;
                } else it.pos = s.end;
                it.prev_end = s.end;
                if (accept) return s;
            }
            return null;
        }
    };

    /// The Pike VM. Threads in a list are in priority order; a match cuts
    /// every lower-priority thread of the same step (leftmost-first).
    fn run(m: *Matcher, input: []const u8, from: usize, full: bool) bool {
        const re = m.re;
        var cur = &m.lists[0];
        var nxt = &m.lists[1];
        cur.clear();
        var matched = false;
        var pos = from;
        var prev = runeBefore(input, from);
        while (true) {
            const here = decode(input, pos);
            if (!matched) {
                @memset(m.tmp, nil);
                m.addThread(cur, 0, pos, prev, here.cp);
            }
            if (cur.n == 0 and (matched or here.cp == null)) break;
            nxt.clear();
            const after = if (here.cp != null) decode(input, pos + here.w) else here;
            var i: usize = 0;
            while (i < cur.n) : (i += 1) {
                const pc = cur.pcs[i];
                const caps = cur.caps[i * m.k ..][0..m.k];
                switch (re.insts[pc]) {
                    .match => {
                        if (full and pos != input.len) continue;
                        @memcpy(m.best, caps);
                        m.best[1] = pos;
                        matched = true;
                        break; // cut the lower-priority threads
                    },
                    else => if (here.cp) |cp| if (re.consumes(pc, cp)) {
                        @memcpy(m.tmp, caps);
                        m.addThread(nxt, pc + 1, pos + here.w, cp, after.cp);
                    },
                }
            }
            if (here.cp == null) break;
            pos += here.w;
            prev = here.cp;
            std.mem.swap(*List, &cur, &nxt);
        }
        return matched;
    }

    /// Follow every empty transition from `pc0` at `pos`, in priority
    /// order, adding each consuming or matching state with the captures of
    /// the path that reached it first. `m.tmp` holds the thread's captures
    /// and is restored on the way back out.
    fn addThread(m: *Matcher, list: *List, pc0: u16, pos: usize, prev: ?u21, next: ?u21) void {
        const re = m.re;
        var sp: usize = 0;
        m.stack[sp] = .{ .explore = pc0 };
        sp += 1;
        while (sp != 0) {
            sp -= 1;
            switch (m.stack[sp]) {
                .restore => |r| m.tmp[r.slot] = r.val,
                .explore => |pc| {
                    if (list.seen[pc] == list.gen) continue;
                    list.seen[pc] = list.gen;
                    switch (re.insts[pc]) {
                        .jmp => |t| {
                            m.stack[sp] = .{ .explore = t };
                            sp += 1;
                        },
                        .split => |s| {
                            m.stack[sp] = .{ .explore = s.y };
                            m.stack[sp + 1] = .{ .explore = s.x };
                            sp += 2;
                        },
                        .save => |slot| {
                            if (slot < m.k) {
                                m.stack[sp] = .{ .restore = .{ .slot = slot, .val = m.tmp[slot] } };
                                sp += 1;
                                m.tmp[slot] = pos;
                            }
                            m.stack[sp] = .{ .explore = pc + 1 };
                            sp += 1;
                        },
                        .assert => |a| if (assertHolds(a, prev, next)) {
                            m.stack[sp] = .{ .explore = pc + 1 };
                            sp += 1;
                        },
                        .rune, .any, .any_not_nl, .match => {
                            list.pcs[list.n] = pc;
                            @memcpy(list.caps[list.n * m.k ..][0..m.k], m.tmp);
                            list.n += 1;
                        },
                    }
                },
            }
        }
    }
};

// ── text ────────────────────────────────────────────────────────────────────

const Decoded = struct { cp: ?u21, w: usize };

/// The code point at `i` (null at the end); an invalid sequence is U+FFFD,
/// one byte wide.
fn decode(input: []const u8, i: usize) Decoded {
    if (i >= input.len) return .{ .cp = null, .w = 0 };
    const c = input[i];
    if (c < 0x80) return .{ .cp = c, .w = 1 };
    const len = std.unicode.utf8ByteSequenceLength(c) catch return .{ .cp = 0xfffd, .w = 1 };
    if (i + len > input.len) return .{ .cp = 0xfffd, .w = 1 };
    const cp = std.unicode.utf8Decode(input[i..][0..len]) catch return .{ .cp = 0xfffd, .w = 1 };
    return .{ .cp = cp, .w = len };
}

/// The code point that ends just before `i`, or null at the start.
fn runeBefore(input: []const u8, i: usize) ?u21 {
    if (i == 0) return null;
    // A code point is at most four bytes: try each start, nearest first, and
    // take the one whose decoding ends exactly at `i`.
    var back: usize = 1;
    while (back <= 4 and back <= i) : (back += 1) {
        const d = decode(input, i - back);
        if (i - back + d.w == i and (back == 1 or d.cp != 0xfffd)) return d.cp;
    }
    return 0xfffd;
}

fn isWord(cp: ?u21) bool {
    const c = cp orelse return false;
    return c < 0x80 and (std.ascii.isAlphanumeric(@intCast(c)) or c == '_');
}

fn assertHolds(a: Assert, prev: ?u21, next: ?u21) bool {
    return switch (a) {
        .begin_text => prev == null,
        .end_text => next == null,
        .begin_line => prev == null or prev.? == '\n',
        .end_line => next == null or next.? == '\n',
        .word_boundary => isWord(prev) != isWord(next),
        .not_word_boundary => isWord(prev) == isWord(next),
    };
}

fn inRanges(ranges: []const Range, cp: u21) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (cp < ranges[mid].lo) hi = mid else if (cp > ranges[mid].hi) lo = mid + 1 else return true;
    }
    return false;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectFind(pattern: []const u8, input: []const u8, want: ?[]const u8) !void {
    var re = try Regex.compile(testing.allocator, pattern);
    defer re.deinit(testing.allocator);
    const got = try re.find(testing.allocator, input);
    errdefer std.debug.print("/{s}/ on \"{s}\": got {?any}\n", .{ pattern, input, got });
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(w, got.?.slice(input));
    } else try testing.expectEqual(@as(?Span, null), got);
    try testing.expectEqual(want != null, re.isMatch(input));
}

test "literals, classes, dot, anchors" {
    try expectFind("abc", "xxabcxx", "abc");
    try expectFind("a.c", "abc", "abc");
    try expectFind("a.c", "a\nc", null);
    try expectFind("(?s)a.c", "a\nc", "a\nc");
    try expectFind("[a-c]+", "xxbcay", "bca");
    try expectFind("[^a-c]+", "abxyc", "xy");
    try expectFind("\\d+", "ab123c", "123");
    try expectFind("\\w+", "  foo_1 ", "foo_1");
    try expectFind("[[:alpha:]]+", "12ab3", "ab");
    try expectFind("^ab", "ab", "ab");
    try expectFind("^ab", "cab", null);
    try expectFind("b$", "ab", "b");
    try expectFind("b$", "ab\n", null); // RE2: $ is end of text without (?m)
    try expectFind("(?m)b$", "ab\nc", "b");
    try expectFind("\\bfoo\\b", "a foo b", "foo");
    try expectFind("\\bfoo\\b", "afoob", null);
    try expectFind("é+", "aééb", "éé");
    try expectFind("(?i)HeLLo", "say hello", "hello");
    try expectFind("(?i)k", "\u{212a}", "\u{212a}");
    try expectFind("\\Qa.b\\E+", "a.bbb", "a.bbb");
    try expectFind("\\x41\\x{263a}", "A\u{263a}", "A\u{263a}");
}

test "leftmost-first, greedy and lazy" {
    try expectFind("a|ab", "ab", "a");
    try expectFind("ab|a", "ab", "ab");
    try expectFind("a+", "baaa", "aaa");
    try expectFind("a+?", "baaa", "a");
    try expectFind("a{2,3}", "aaaa", "aaa");
    try expectFind("a{2,3}?", "aaaa", "aa");
    try expectFind("(?U)a+", "aaa", "a");
    try expectFind("x*", "aaa", "");
    try expectFind("(a*)*b", "aaab", "aaab");
}

test "captures and names" {
    var re = try Regex.compile(testing.allocator, "(?P<y>\\d{4})-(\\d{2})(?:-(?<d>\\d{2}))?");
    defer re.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), re.groupCount());
    try testing.expectEqual(@as(?usize, 1), re.groupIndex("y"));
    try testing.expectEqual(@as(?usize, 3), re.groupIndex("d"));
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    var out: [4]?Span = undefined;
    const input = "on 2026-10 and";
    try testing.expect(m.captures(input, 0, &out));
    try testing.expectEqualStrings("2026-10", out[0].?.slice(input));
    try testing.expectEqualStrings("2026", out[1].?.slice(input));
    try testing.expectEqualStrings("10", out[2].?.slice(input));
    try testing.expectEqual(@as(?Span, null), out[3]);
}

test "iterator: non-overlapping, an empty match next to the previous is skipped" {
    var re = try Regex.compile(testing.allocator, "a*");
    defer re.deinit(testing.allocator);
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    var it = m.iterator("baaac");
    var got: [8]Span = undefined;
    var n: usize = 0;
    while (it.next()) |s| : (n += 1) got[n] = s;
    // Go: FindAllStringIndex("a*", "baaac") = [[0 0] [1 4] [5 5]]
    try testing.expectEqualSlices(Span, &.{ .{ .start = 0, .end = 0 }, .{ .start = 1, .end = 4 }, .{ .start = 5, .end = 5 } }, got[0..n]);
}

test "fullMatch takes any way through, comptimeCompile matches compile" {
    const re = comptime comptimeCompile("[0-9]+|[0-9]+x");
    try testing.expect(re.fullMatch("123x"));
    try testing.expect(re.fullMatch("123"));
    try testing.expect(!re.fullMatch("123y"));
    try testing.expect(!re.fullMatch(""));
    var rt = try Regex.compile(testing.allocator, "[0-9]+|[0-9]+x");
    defer rt.deinit(testing.allocator);
    try testing.expectEqualSlices(Inst, rt.insts, re.insts);
    try testing.expectEqualSlices(Range, rt.ranges, re.ranges);
}

test "syntax errors" {
    const bad = .{
        .{ "a**", error.InvalidNestedRepeat },
        .{ "*a", error.MissingRepeatArgument },
        .{ "a{1001}", error.InvalidRepeatSize },
        .{ "a{3,2}", error.InvalidRepeatSize },
        .{ "(a", error.MissingParen },
        .{ "a)", error.UnexpectedParen },
        .{ "[a", error.MissingBracket },
        .{ "[z-a]", error.InvalidCharRange },
        .{ "[[:foo:]]", error.InvalidCharClass },
        .{ "a\\", error.TrailingBackslash },
        .{ "\\1", error.InvalidEscape },
        .{ "\\y", error.InvalidEscape },
        .{ "(?P<>a)", error.InvalidNamedCapture },
        .{ "(?z)", error.InvalidPerlOp },
        .{ "\\pL", error.UnsupportedUnicodeClass },
        .{ "\xff", error.InvalidUtf8 },
    };
    inline for (bad) |c| {
        errdefer std.debug.print("pattern {s}\n", .{c[0]});
        try testing.expectError(c[1], Regex.compile(testing.allocator, c[0]));
    }
    // A `{` that is not a repetition is a literal.
    try expectFind("a{,2}", "a{,2}", "a{,2}");
    try expectFind("a{", "a{", "a{");
}

test "linear time: the classic exponential backtracking case is instant" {
    var re = try Regex.compile(testing.allocator, "(a+)+$");
    defer re.deinit(testing.allocator);
    const input = "a" ** 5000 ++ "b";
    try testing.expect(!re.isMatch(input));
    try testing.expect((try re.find(testing.allocator, input)) == null);
}

test "invalid UTF-8 in the input reads as U+FFFD, one byte" {
    try expectFind("a.b", "a\xffb", "a\xffb");
    try expectFind("\\x{fffd}", "x\xfey", "\xfe");
}

test {
    _ = syntax;
    _ = @import("go_oracle_test.zig");
}

test "robustness: random patterns and inputs compile or refuse, and match, without a trap" {
    // A deterministic driver (seeded PRNG): metacharacter-dense byte strings,
    // invalid UTF-8 included. Every outcome is fine but a safety trap.
    const alphabet = "ab()[]{}|*+?.^$\\-,:<>=!PQEdDwWsSbBAzx0179iUms_\xc3\xa9\xff";
    var prng: std.Random.DefaultPrng = .init(0x7265676578);
    const rng = prng.random();
    var pat: [24]u8 = undefined;
    var input: [16]u8 = undefined;
    var compiled: usize = 0;
    for (0..20_000) |_| {
        const pl = rng.uintLessThan(usize, pat.len);
        for (pat[0..pl]) |*c| c.* = alphabet[rng.uintLessThan(usize, alphabet.len)];
        var re = Regex.compile(testing.allocator, pat[0..pl]) catch continue;
        defer re.deinit(testing.allocator);
        compiled += 1;
        var m = try Matcher.init(testing.allocator, &re);
        defer m.deinit();
        for (0..4) |_| {
            const il = rng.uintLessThan(usize, input.len);
            for (input[0..il]) |*c| c.* = "ab\n é\xff1_"[rng.uintLessThan(usize, 9)];
            const in = input[0..il];
            const any = re.isMatch(in);
            const s = m.find(in, 0);
            // The three entry points agree with one another.
            try testing.expectEqual(any, s != null);
            if (re.fullMatch(in)) try testing.expect(any);
            var it = m.iterator(in);
            var n: usize = 0;
            while (it.next()) |_| n += 1;
            try testing.expect(n <= in.len + 1);
        }
    }
    try testing.expect(compiled > 2_000); // the driver reaches the matcher
}
