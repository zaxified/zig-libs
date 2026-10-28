// SPDX-License-Identifier: MIT

//! Replays `rust_vectors.zig`: Rust `regex` 1.13.1's answers
//! (`tools/rust_regex_oracle`) to this module's own crafted syntax cases,
//! Unicode property queries and seeded random patterns, compiled here with
//! `Options{ .syntax = .rust }` — and its `bytes::Regex` answers over
//! haystacks with invalid UTF-8, with `.utf8 = false` as well. Per pattern: the compile verdict and the
//! group names; per input: `isMatch` (`is_match`), `fullMatch`
//! (`\A(?:re)\z`), `Matcher.captures` (`captures_read`) and the iterator
//! (`find_iter`). No Rust at test time.
//!
//! Listed divergences, each counted:
//!  - CAPACITY: past the heap builder's 65,534 instructions or 65,535
//!    ranges, or 64 groups, where the crate's limit is its compiled size.
//!  - SHORTEST: `shortestMatch` is always the earliest end of any match;
//!    the crate's `shortest_match` is whatever end its engine of the moment
//!    sees first (documented as such) — the leftmost-first match's end when
//!    a Unicode `\b` sends it from the lazy DFA to the backtracker. Here never
//!    later than the crate's, and null exactly when it is `None`.
//!  - SIZE_LIMIT: the other way round — a Unicode class repeated a few
//!    hundred times (`\w{250}`) passes the crate's 10 MiB NFA limit, a UTF-8
//!    automaton per copy; here a class is one instruction per copy, and the
//!    pattern compiles.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const v = @import("rust_vectors.zig");

/// SIZE_LIMIT above: refused by the crate, compiled here.
const size_limit = [_][]const u8{ "\\w{250}", "\\w{500}", "\\w{1000}", "\\pL{1000}", "[\\w]{1000}", "(?:\\w{100}){10}", "\\w{10000}", "(\\w{10}){100}", "\\d{10000}" };

fn sizeLimited(pattern: []const u8) bool {
    for (size_limit) |s| if (std.mem.eql(u8, s, pattern)) return true;
    return false;
}

const Tally = struct { patterns: usize = 0, cases: usize = 0, capacity: usize = 0, size_limit: usize = 0, shortest_earlier: usize = 0, bad_verdict: usize = 0, bad_names: usize = 0, bad_cases: usize = 0, printed: usize = 0 };

const max_print = 60;

fn note(t: *Tally, comptime fmt: []const u8, args: anytype) void {
    if (t.printed < max_print) std.debug.print(fmt, args);
    t.printed += 1;
}

fn spansAgree(m: *regex.Matcher, c: v.Case, groups: []?regex.Span) bool {
    var ok = true;
    const found = m.captures(c.input, 0, groups);
    if (found != (c.caps.len != 0)) ok = false;
    if (found and c.caps.len == 2 * groups.len) for (groups, 0..) |g, i| {
        const ws = c.caps[2 * i];
        const we = c.caps[2 * i + 1];
        if (g) |s| {
            if (ws != s.start or we != s.end) ok = false;
        } else if (ws != -1) ok = false;
    };
    var it = m.iterator(c.input);
    var i: usize = 0;
    while (it.next()) |s| : (i += 2) {
        if (i + 1 >= c.all.len or c.all[i] != s.start or c.all[i + 1] != s.end) {
            ok = false;
            break;
        }
    }
    if (i != c.all.len) ok = false;
    return ok;
}

test "rust oracle: the crate's answers to the Rust grammar" {
    try replay(&v.patterns, false, 9, 5);
}

test "rust oracle: bytes mode (regex::bytes)" {
    try replay(&v.bytes_patterns, true, 0, 0);
}

fn replay(set: []const v.Pattern, bytes: bool, want_size_limit: usize, want_capacity: usize) !void {
    var t: Tally = .{};
    for (set) |p| {
        t.patterns += 1;
        var re = regex.Regex.compileOptions(testing.allocator, p.pattern, .{ .syntax = .rust, .utf8 = !bytes }) catch |e| {
            if (p.ok and (e == error.PatternTooLarge or e == error.NestingDepth or e == error.InvalidRepeatSize)) {
                t.capacity += 1;
            } else if (p.ok) {
                t.bad_verdict += 1;
                note(&t, "/{s}/: Rust compiles it, here {t}\n", .{ p.pattern, e });
            }
            continue;
        };
        defer re.deinit(testing.allocator);
        if (!p.ok and sizeLimited(p.pattern)) {
            t.size_limit += 1;
            continue;
        }
        if (!p.ok) {
            t.bad_verdict += 1;
            note(&t, "/{s}/: Rust refuses it, here it compiles\n", .{p.pattern});
            continue;
        }
        if (re.names.len != p.names.len) {
            t.bad_names += 1;
            note(&t, "/{s}/: {d} groups, Rust {d}\n", .{ p.pattern, re.names.len - 1, p.names.len - 1 });
            continue;
        }
        for (re.names, p.names) |a, b| if (!std.mem.eql(u8, a, b)) {
            t.bad_names += 1;
            note(&t, "/{s}/: group name {s}, Rust {s}\n", .{ p.pattern, a, b });
        };
        var m = try regex.Matcher.init(testing.allocator, &re);
        defer m.deinit();
        var out: [regex.max_groups]?regex.Span = undefined;
        const groups = out[0..re.names.len];
        for (p.cases) |c| {
            t.cases += 1;
            const is = try re.isMatchAlloc(testing.allocator, c.input);
            const full = try re.fullMatchAlloc(testing.allocator, c.input);
            const spans = spansAgree(&m, c, groups);
            const short: i32 = if (try re.shortestMatchAlloc(testing.allocator, c.input)) |e| @intCast(e) else -1;
            if (short != c.shortest and short >= 0 and c.shortest >= 0 and short < c.shortest) {
                t.shortest_earlier += 1;
            } else if (short != c.shortest) {
                t.bad_cases += 1;
                note(&t, "/{s}/ on \"{f}\": shortestMatch {d}, Rust {d}\n", .{ p.pattern, std.zig.fmtString(c.input), short, c.shortest });
            }
            if (is != c.is_match or (p.full_ok and full != c.full) or !spans) {
                t.bad_cases += 1;
                note(&t, "/{s}/ on \"{f}\": isMatch {} (Rust {}), full {} (Rust {}), spans {s}\n", .{
                    p.pattern, std.zig.fmtString(c.input), is, c.is_match, full, c.full, if (spans) "agree" else "differ",
                });
                if (!spans and t.printed <= max_print) {
                    std.debug.print("    Rust all {any}\n    here", .{c.all});
                    var it = m.iterator(c.input);
                    while (it.next()) |sp| std.debug.print(" {d}-{d}", .{ sp.start, sp.end });
                    std.debug.print("\n", .{});
                }
            }
        }
    }
    if (t.bad_verdict + t.bad_names + t.bad_cases != 0) std.debug.print("rust oracle: {d} patterns, {d} cases; CAPACITY {d}, SIZE_LIMIT {d}; bad: verdict {d}, names {d}, cases {d}\n", .{
        t.patterns, t.cases, t.capacity, t.size_limit, t.bad_verdict, t.bad_names, t.bad_cases,
    });
    try testing.expectEqual(@as(usize, 0), t.bad_verdict + t.bad_names + t.bad_cases);
    // Pinned, so a drift either way shows.
    try testing.expectEqual(want_size_limit, t.size_limit);
    try testing.expectEqual(want_capacity, t.capacity);
}

test "rust oracle: RegexSet" {
    var bad: usize = 0;
    var cases: usize = 0;
    var capacity: usize = 0;
    for (v.sets) |set| {
        var rs = regex.RegexSet.compile(testing.allocator, set.patterns, .{ .syntax = .rust, .utf8 = !set.bytes }) catch |e| {
            if (set.ok and (e == error.PatternTooLarge or e == error.InvalidRepeatSize or e == error.NestingDepth)) {
                capacity += 1; // CAPACITY (`a{1001}`)
            } else if (set.ok) {
                bad += 1;
                std.debug.print("set {any}: Rust compiles it, here {t}\n", .{ set.patterns, e });
            }
            continue;
        };
        defer rs.deinit(testing.allocator);
        if (!set.ok) {
            bad += 1;
            std.debug.print("set {any}: Rust refuses it, here it compiles\n", .{set.patterns});
            continue;
        }
        var out: [16]bool = undefined;
        const hits = out[0..set.patterns.len];
        for (set.cases) |c| {
            cases += 1;
            const any = rs.matches(c.input, hits);
            var ok = any == c.is_match and rs.isMatch(c.input) == c.is_match;
            var n: usize = 0;
            for (hits, 0..) |h, i| if (h) {
                if (n >= c.matches.len or c.matches[n] != i) ok = false;
                n += 1;
            };
            if (n != c.matches.len) ok = false;
            if (!ok) {
                bad += 1;
                std.debug.print("set {any} on \"{f}\": here {any}, Rust {any}\n", .{ set.patterns, std.zig.fmtString(c.input), hits, c.matches });
            }
        }
    }
    try testing.expect(cases > 1000);
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expectEqual(@as(usize, 0), capacity);
}
