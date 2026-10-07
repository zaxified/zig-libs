// SPDX-License-Identifier: MIT

//! Replays `go_vectors.zig`: Go `regexp`'s answers (`tools/go_regexp_oracle`)
//! to this module's own crafted syntax cases and seeded random patterns.
//! Per pattern: the compile verdict and the group names; per input:
//! `isMatch` (MatchString), `fullMatch` (`\A(?:re)\z`), `Matcher.captures`
//! (FindStringSubmatchIndex) and the iterator (FindAllStringIndex) — for a
//! Perl-syntax pattern both leftmost-first and after `Longest()`
//! (`Regex.longest`); for the POSIX sets as `compilePosix` against Go's
//! `CompilePOSIX`. No Go at test time.
//!
//! Listed divergences, each counted and pinned so a drift either way shows:
//!  - GO_DEFECT: Go 1.26 refuses `\p{Name}` for every script whose name has
//!    an underscore or an inner capital (`Old_Persian`, `SignWriting` — 46 of
//!    163), in every spelling, although its documentation names
//!    `unicode.Scripts` as the classes and its 1.25 release notes promise TR18
//!    loose matching for script names. Here they compile, matched loosely like
//!    every other name; their tables were checked against Go's
//!    `unicode.Scripts` for every code point (`tools/go_unicode`).
//!  - LITERAL_PREFIX: `literalPrefix` follows every path and extends the
//!    prefix through a choice whose branches all agree (`Aa+a` → `Aaa`, Go
//!    `Aa`), and past a leading `\A` whatever follows; Go's stops at its
//!    program's first choice, and whether it passes `^` or calls `^a$`
//!    complete depends on its one-pass engine. Both are prefixes every match
//!    begins with; ours always extends Go's and is never complete where Go's
//!    is not.
//!  - CAPACITY: a pattern whose program needs more than `max_insts` (1024)
//!    instructions, or that nests deeper than `max_depth` (250), compiles in
//!    Go; here `error.PatternTooLarge` / `error.NestingDepth` — the price of
//!    matching in fixed stack scratch with no allocator, and of a recursive
//!    parser that fits a small thread stack.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const v = @import("go_vectors.zig");

const Tally = struct { patterns: usize = 0, cases: usize = 0, matched: usize = 0, capacity: usize = 0, go_defect: usize = 0, longest_differs: usize = 0, api: usize = 0, literal_prefix: usize = 0, bad: usize = 0 };

/// `\p{Name}` with a script name Go 1.26 cannot look up (GO_DEFECT above):
/// one with an underscore or a capital past its first letter.
fn goDefectScript(pattern: []const u8) bool {
    if (!std.mem.startsWith(u8, pattern, "\\p{") or pattern[pattern.len - 1] != '}') return false;
    const name = pattern[3 .. pattern.len - 1];
    if (name.len < 3) return false; // a two-letter category (`Lu`)
    for (name[1..]) |c| if (c == '_' or std.ascii.isUpper(c)) return true;
    return false;
}

const Mode = enum { perl, posix };

fn replay(set: []const v.Pattern, mode: Mode, t: *Tally) !void {
    for (set) |p| {
        t.patterns += 1;
        const opts: regex.Options = .{ .syntax = if (mode == .posix) .posix else .perl };
        var re = regex.Regex.compileOptions(testing.allocator, p.pattern, opts) catch |e| {
            if (p.ok and (e == error.PatternTooLarge or e == error.NestingDepth)) {
                t.capacity += 1;
            } else if (p.ok) {
                t.bad += 1;
                std.debug.print("/{s}/: Go compiles it, here {t}\n", .{ p.pattern, e });
            }
            continue;
        };
        defer re.deinit(testing.allocator);
        if (!p.ok and goDefectScript(p.pattern)) {
            t.go_defect += 1;
            continue;
        }
        if (!p.ok) {
            t.bad += 1;
            std.debug.print("/{s}/: Go refuses it, here it compiles\n", .{p.pattern});
            continue;
        }
        if (re.names.len != p.names.len) {
            t.bad += 1;
            std.debug.print("/{s}/: {d} groups, Go {d}\n", .{ p.pattern, re.names.len - 1, p.names.len - 1 });
            continue;
        }
        for (re.names, p.names) |a, b| if (!std.mem.eql(u8, a, b)) {
            t.bad += 1;
            std.debug.print("/{s}/: group name {s}, Go {s}\n", .{ p.pattern, a, b });
        };
        var m = try regex.Matcher.init(testing.allocator, &re);
        defer m.deinit();
        if (p.api) {
            var out: std.Io.Writer.Allocating = .init(testing.allocator);
            defer out.deinit();
            const complete = try re.literalPrefix(&out.writer);
            const got = out.written();
            if (complete != p.complete or !std.mem.eql(u8, got, p.prefix)) longer: {
                // LITERAL_PREFIX: ours extends Go's, and claims completeness no more often.
                if (std.mem.startsWith(u8, got, p.prefix) and !complete and (got.len > p.prefix.len or p.complete)) {
                    t.literal_prefix += 1;
                    break :longer;
                }
                t.bad += 1;
                std.debug.print("/{s}/: LiteralPrefix \"{s}\" {}, Go \"{s}\" {}\n", .{ p.pattern, out.written(), complete, p.prefix, p.complete });
            }
        }
        // Perl syntax: the same searches again after `Longest()`.
        var lre = re;
        lre.longest = true;
        var lm = try regex.Matcher.init(testing.allocator, &lre);
        defer lm.deinit();
        for (p.cases) |c| {
            t.cases += 1;
            if (c.match) t.matched += 1;
            var ok = re.isMatch(c.input) == c.match and re.fullMatch(c.input) == c.full;
            var out: [regex.max_groups]?regex.Span = undefined;
            const groups = out[0..re.names.len];
            if (!searches(&m, c.input, c.sub, c.all, groups)) ok = false;
            if (p.api) {
                t.api += 1;
                if (!try apiAgrees(&re, &m, p, c)) ok = false;
            }
            if (mode == .perl) {
                const lsub = if (c.same_longest) c.sub else c.lsub;
                const lall = if (c.same_longest) c.all else c.lall;
                if (!c.same_longest) t.longest_differs += 1;
                if (!searches(&lm, c.input, lsub, lall, groups)) {
                    ok = false;
                    std.debug.print("  (Longest)\n", .{});
                }
            }
            if (!ok) {
                t.bad += 1;
                if (t.bad <= 40) std.debug.print("{t} /{s}/ on \"{f}\": go match={} full={} sub={any} all={any} lsub={any}; ours match={} full={} sub={any}\n", .{
                    mode,                p.pattern,             std.zig.fmtString(c.input), c.match, c.full, c.sub, c.all, c.lsub,
                    re.isMatch(c.input), re.fullMatch(c.input), groups,
                });
            }
        }
    }
}

/// ReplaceAll (two templates), ReplaceAllLiteral, ReplaceAllFunc, Split (all
/// and limited), FindAllSubmatchIndex — each against Go's answer.
fn apiAgrees(re: *const regex.Regex, m: *regex.Matcher, p: v.Pattern, c: v.Case) !bool {
    var ok = true;
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const w = &buf.writer;
    for (c.repl) |r| {
        buf.clearRetainingCapacity();
        try m.replaceAll(w, c.input, v.templates[r.t]);
        if (!std.mem.eql(u8, buf.written(), r.out)) {
            ok = false;
            std.debug.print("/{s}/ on \"{f}\" ReplaceAll \"{s}\": \"{f}\", Go \"{f}\"\n", .{ p.pattern, std.zig.fmtString(c.input), v.templates[r.t], std.zig.fmtString(buf.written()), std.zig.fmtString(r.out) });
        }
    }
    buf.clearRetainingCapacity();
    try m.replaceAllLiteral(w, c.input, "<$1>");
    if (!std.mem.eql(u8, buf.written(), c.literal)) {
        ok = false;
        std.debug.print("/{s}/ on \"{f}\" ReplaceAllLiteral: \"{f}\", Go \"{f}\"\n", .{ p.pattern, std.zig.fmtString(c.input), std.zig.fmtString(buf.written()), std.zig.fmtString(c.literal) });
    }
    buf.clearRetainingCapacity();
    try m.replaceAllFunc(w, c.input, {}, struct {
        fn f(_: void, out: *std.Io.Writer, match: []const u8) std.Io.Writer.Error!void {
            try out.print("[{s}]", .{match});
        }
    }.f);
    if (!std.mem.eql(u8, buf.written(), c.func)) {
        ok = false;
        std.debug.print("/{s}/ on \"{f}\" ReplaceAllFunc: \"{f}\", Go \"{f}\"\n", .{ p.pattern, std.zig.fmtString(c.input), std.zig.fmtString(buf.written()), std.zig.fmtString(c.func) });
    }
    for ([_]struct { limit: ?usize, want: []const []const u8 }{ .{ .limit = null, .want = c.split }, .{ .limit = c.split_n, .want = c.split_some } }) |sp| {
        var it = m.split(c.input, sp.limit);
        var i: usize = 0;
        var same = true;
        while (it.next()) |piece| : (i += 1) {
            if (i >= sp.want.len or !std.mem.eql(u8, piece, sp.want[i])) same = false;
        }
        if (!same or i != sp.want.len) {
            ok = false;
            std.debug.print("/{s}/ on \"{f}\" Split {?d}: differs from Go {any}\n", .{ p.pattern, std.zig.fmtString(c.input), sp.limit, sp.want });
        }
    }
    var groups_buf: [regex.max_groups]?regex.Span = undefined;
    const groups = groups_buf[0..re.names.len];
    var it = m.iterator(c.input);
    var i: usize = 0;
    var same = true;
    while (it.nextCaptures(groups)) |_| {
        for (groups) |g| {
            if (i + 1 >= c.allsub.len) {
                same = false;
                break;
            }
            const want_s = c.allsub[i];
            const want_e = c.allsub[i + 1];
            if (g) |sp| {
                if (want_s != sp.start or want_e != sp.end) same = false;
            } else if (want_s != -1) same = false;
            i += 2;
        }
    }
    if (!same or i != c.allsub.len) {
        ok = false;
        std.debug.print("/{s}/ on \"{f}\" FindAllSubmatchIndex differs from Go\n", .{ p.pattern, std.zig.fmtString(c.input) });
    }
    return ok;
}

/// `Matcher.captures` against FindStringSubmatchIndex (`sub`) and the
/// iterator against FindAllStringIndex (`all`).
fn searches(m: *regex.Matcher, input: []const u8, sub: []const i32, all: []const i32, groups: []?regex.Span) bool {
    var ok = true;
    const found = m.captures(input, 0, groups);
    if (found != (sub.len != 0)) ok = false;
    if (found and sub.len == 2 * groups.len) for (groups, 0..) |g, i| {
        const ws = sub[2 * i];
        const we = sub[2 * i + 1];
        if (g) |s| {
            if (ws != s.start or we != s.end) ok = false;
        } else if (ws != -1) ok = false;
    };
    var it = m.iterator(input);
    var i: usize = 0;
    while (it.next()) |s| : (i += 2) {
        if (i + 1 >= all.len or all[i] != s.start or all[i + 1] != s.end) {
            ok = false;
            break;
        }
    }
    if (i != all.len) ok = false;
    return ok;
}

test "go oracle: QuoteMeta answers as Go's, and its output matches the text literally" {
    for (v.quote_meta) |q| {
        const got = try regex.quoteMetaAlloc(testing.allocator, q[0]);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(q[1], got);
        if (!std.unicode.utf8ValidateSlice(q[0])) continue;
        var re = try regex.Regex.compile(testing.allocator, got);
        defer re.deinit(testing.allocator);
        try testing.expect(re.fullMatch(q[0]));
    }
}

test "go oracle: crafted syntax cases and random patterns answer as Go regexp" {
    var t: Tally = .{};
    try replay(&v.crafted, .perl, &t);
    try replay(&v.unicode_classes, .perl, &t);
    try replay(&v.random, .perl, &t);
    try replay(&v.posix, .posix, &t);
    try replay(&v.posix_random, .posix, &t);
    // The tally only when a check fails: a passing step's stderr fails CI.
    errdefer std.debug.print("go oracle: {d} patterns, {d} cases ({d} matched), CAPACITY {d}, GO_DEFECT {d}, LITERAL_PREFIX {d}, Longest differs on {d} cases, API on {d} cases, unexplained {d}\n", .{ t.patterns, t.cases, t.matched, t.capacity, t.go_defect, t.literal_prefix, t.longest_differs, t.api, t.bad });
    try testing.expectEqual(@as(usize, 0), t.bad);
    try testing.expectEqual(@as(usize, 46), t.go_defect);
    try testing.expect(t.api > 10_000); // the API answers are reached
    try testing.expectEqual(@as(usize, 5), t.literal_prefix);
    try testing.expectEqual(@as(usize, 5), t.capacity); // 4 Perl + `((a{0}){100}){10}` in POSIX: 2,000 saves
}
