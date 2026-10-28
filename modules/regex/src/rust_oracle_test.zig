// SPDX-License-Identifier: MIT

//! Replays `rust_vectors.zig`: Rust `regex` 1.13.1's answers
//! (`tools/rust_regex_oracle`) to this module's own crafted syntax cases,
//! Unicode property queries and seeded random patterns, compiled here with
//! `Options{ .syntax = .rust }`. Per pattern: the compile verdict and the
//! group names; per input: `isMatch` (`is_match`), `fullMatch`
//! (`\A(?:re)\z`), `Matcher.captures` (`captures_read`) and the iterator
//! (`find_iter`). No Rust at test time.
//!
//! Listed divergences, each counted:
//!  - CAPACITY: past `max_insts`, `max_ranges`, `max_depth` or a count of
//!    1000, where the crate's limit is its compiled size (10 MiB).
//!  - SIZE_LIMIT: the other way round — a Unicode class repeated a few
//!    hundred times (`\w{250}`) passes the crate's 10 MiB NFA limit, a UTF-8
//!    automaton per copy; here a class is one instruction per copy, and the
//!    pattern compiles.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const v = @import("rust_vectors.zig");

/// SIZE_LIMIT above: refused by the crate, compiled here.
const size_limit = [_][]const u8{ "\\w{250}", "\\w{500}", "\\w{1000}", "\\pL{1000}", "[\\w]{1000}", "(?:\\w{100}){10}" };

fn sizeLimited(pattern: []const u8) bool {
    for (size_limit) |s| if (std.mem.eql(u8, s, pattern)) return true;
    return false;
}

const Tally = struct { patterns: usize = 0, cases: usize = 0, capacity: usize = 0, size_limit: usize = 0, bad_verdict: usize = 0, bad_names: usize = 0, bad_cases: usize = 0, printed: usize = 0 };

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
    var t: Tally = .{};
    for (v.patterns) |p| {
        if (p.bytes) continue;
        t.patterns += 1;
        var re = regex.Regex.compileOptions(testing.allocator, p.pattern, .{ .syntax = .rust }) catch |e| {
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
            const is = re.isMatch(c.input);
            const full = re.fullMatch(c.input);
            const spans = spansAgree(&m, c, groups);
            if (is != c.is_match or (p.full_ok and full != c.full) or !spans) {
                t.bad_cases += 1;
                note(&t, "/{s}/ on \"{f}\": isMatch {} (Rust {}), full {} (Rust {}), spans {s}\n", .{
                    p.pattern, std.zig.fmtString(c.input), is, c.is_match, full, c.full, if (spans) "agree" else "differ",
                });
            }
        }
    }
    if (t.bad_verdict + t.bad_names + t.bad_cases != 0) std.debug.print("rust oracle: {d} patterns, {d} cases; CAPACITY {d}, SIZE_LIMIT {d}; bad: verdict {d}, names {d}, cases {d}\n", .{
        t.patterns, t.cases, t.capacity, t.size_limit, t.bad_verdict, t.bad_names, t.bad_cases,
    });
    try testing.expectEqual(@as(usize, 0), t.bad_verdict + t.bad_names + t.bad_cases);
    // Pinned, so a drift either way shows.
    try testing.expectEqual(@as(usize, 6), t.size_limit);
    try testing.expectEqual(@as(usize, 19), t.capacity);
}
