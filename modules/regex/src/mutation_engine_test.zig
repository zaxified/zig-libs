// SPDX-License-Identifier: MIT

//! Tests added by the second pass of the regex mutation audit (part B: the
//! set VM, `RegexSet`, the byte-mode VM, the one-pass engine, the prefilter
//! and the `Matcher`'s capture side). Public-API tests only: each block names
//! what it pins. Tests that need the file-private probe hook or call private
//! functions live in `root.zig`.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const teddy = @import("teddy.zig");

const Regex = regex.Regex;
const Matcher = regex.Matcher;
const RegexSet = regex.RegexSet;
const Span = regex.Span;

const gpa = testing.allocator;

fn filled(byte: u8, n: usize) ![]u8 {
    const buf = try gpa.alloc(u8, n);
    @memset(buf, byte);
    return buf;
}

/// `k` letters 'a', then `tail`.
fn lit(k: usize, tail: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, k + tail.len);
    @memset(out[0..k], 'a');
    @memcpy(out[k..], tail);
    return out;
}

/// `(a)` repeated `g` times.
fn groups(g: usize) ![]u8 {
    const out = try gpa.alloc(u8, 3 * g);
    for (0..g) |i| @memcpy(out[3 * i ..][0..3], "(a)");
    return out;
}

// ── set VM ──────────────────────────────────────────────────────────────────

test "set VM: programs of 1008..1024 and 4032..4096 instructions run (the cleared word count stays inside the bit set)" {
    // `(len + 64) / 64` and `(len + 63) / 63` clear one word too many: past
    // the 16 (non-wide) or 64 (wide) words of the scratch, a bounds panic.
    var saw_1024 = false;
    var saw_4096 = false;
    const spans = [_][2]usize{ .{ 1000, 1030 }, .{ 4080, 4100 } };
    for (spans) |sp| {
        for (sp[0]..sp[1]) |n| {
            const pat = try filled('a', n);
            defer gpa.free(pat);
            var re = Regex.compile(gpa, pat) catch |e| {
                if (e != error.PatternTooLarge) return e;
                continue;
            };
            defer re.deinit(gpa);
            if (re.insts.len == 1024) saw_1024 = true;
            if (re.insts.len == 4096) saw_4096 = true;
            try testing.expectEqual(@as(?usize, n), re.shortestMatch(pat));
            try testing.expect(re.isMatch(pat));
        }
    }
    try testing.expect(saw_1024 and saw_4096);
}

// ── RegexSet ────────────────────────────────────────────────────────────────

/// A one-pattern set whose joined program is exactly `total` instructions.
fn exactSetRuns(opts: regex.Options, total: usize) !void {
    var one = try Regex.compileOptions(gpa, "a", opts);
    const c0 = one.insts.len - 1; // instructions besides the letter
    one.deinit(gpa);
    const pat = try filled('a', total - c0);
    defer gpa.free(pat);
    var set = try RegexSet.compile(gpa, &[_][]const u8{pat}, opts);
    defer set.deinit(gpa);
    try testing.expectEqual(total, set.insts.len);
    try testing.expect(set.isMatch(pat));
    var out: [1]bool = undefined;
    try testing.expect(set.matches(pat, &out) and out[0]);
    try testing.expect(!set.isMatch("b"));
}

test "RegexSet: the joined program may be exactly 4 * max_insts (bytes mode: max_insts) instructions; its run clears only the words it has" {
    const bytes: regex.Options = .{ .syntax = .rust, .utf8 = false };
    try exactSetRuns(.{}, regex.max_insts); // a full non-wide scratch
    try exactSetRuns(.{}, 4 * regex.max_insts); // a full wide one
    try exactSetRuns(bytes, regex.max_insts);
}

test "RegexSet: one instruction past the cap is PatternTooLarge (and the bytes cap is max_insts, not 4 * max_insts)" {
    const bytes: regex.Options = .{ .syntax = .rust, .utf8 = false };
    for ([_]regex.Options{ .{}, bytes }) |opts| {
        const cap: usize = if (opts.utf8) 4 * regex.max_insts else regex.max_insts;
        var one = try Regex.compileOptions(gpa, "a", opts);
        const c0 = one.insts.len - 1;
        one.deinit(gpa);
        // 1 split + (cap - 24) + 24 instructions = cap + 1.
        const pa = try filled('a', cap - 24 - c0);
        defer gpa.free(pa);
        const pb = try filled('b', 24 - c0);
        defer gpa.free(pb);
        try testing.expectError(error.PatternTooLarge, RegexSet.compile(gpa, &[_][]const u8{ pa, pb }, opts));
    }
}

test "RegexSet: a joined range table of exactly 65535 ranges is accepted" {
    var pl = try Regex.compile(gpa, "\\pL");
    const per = pl.ranges.len;
    pl.deinit(gpa);
    var k = 65535 / per;
    var rem = 65535 - k * per;
    if (rem == 0) {
        k -= 1;
        rem = per;
    }
    // A class of `rem` single code points, none adjacent: `rem` ranges.
    var cls: std.ArrayList(u8) = .empty;
    defer cls.deinit(gpa);
    try cls.append(gpa, '[');
    for (0..rem) |i| {
        var buf: [4]u8 = undefined;
        const n = try std.unicode.utf8Encode(@intCast(0x4e00 + 2 * i), &buf);
        try cls.appendSlice(gpa, buf[0..n]);
    }
    try cls.append(gpa, ']');
    var filler = try Regex.compile(gpa, cls.items);
    try testing.expectEqual(rem, filler.ranges.len);
    filler.deinit(gpa);

    const pats = try gpa.alloc([]const u8, k + 1);
    defer gpa.free(pats);
    for (pats[0..k]) |*p| p.* = "\\pL";
    pats[k] = cls.items;
    var set = try RegexSet.compile(gpa, pats, .{});
    defer set.deinit(gpa);
    try testing.expectEqual(@as(usize, 65535), set.ranges.len);
    try testing.expect(set.isMatch("\u{e9}"));
    try testing.expect(!set.isMatch("123"));
}

test "RegexSet.matches: entries past the pattern count are false even past max_patterns; an empty set matches nothing" {
    var set = try RegexSet.compile(gpa, &[_][]const u8{ "a", "b" }, .{});
    defer set.deinit(gpa);
    const big = try gpa.alloc(bool, RegexSet.max_patterns + 10);
    defer gpa.free(big);
    @memset(big, true);
    try testing.expect(set.matches("xb", big));
    try testing.expect(!big[0] and big[1]);
    for (big[2..]) |v| try testing.expect(!v);

    // No pattern: no instruction to start from (a run would index insts[0]).
    for ([_]regex.Options{ .{}, .{ .syntax = .rust, .utf8 = false } }) |opts| {
        var empty = try RegexSet.compile(gpa, &[_][]const u8{}, opts);
        defer empty.deinit(gpa);
        try testing.expect(!empty.isMatch("abc"));
        var o: [2]bool = undefined;
        try testing.expect(!empty.matches("abc", &o));
        try testing.expect(!o[0] and !o[1]);
    }
}

// ── bytes mode ──────────────────────────────────────────────────────────────

/// Two alternatives: any byte, a chain of `m` optional letters and a `z`
/// (never matches "é"); then `é` followed by `n` optional letters. The
/// first alternative's closure visits instructions 3..2m+3 in one step, as
/// the second one's two-byte thread waits at a pending key that must not
/// land among those bits.
fn collisionPattern(m: usize, n: usize) ![]u8 {
    return std.fmt.allocPrint(gpa, "(?:[\\x00-\\xff](?:y?){{{d}}}z|\u{e9}(?:u?){{{d}}})", .{ m, n });
}

test "bytes mode set VM: a pending two-byte thread's key never collides with the closure bits of the other threads" {
    // `rem * stride - pc` lands on the bit of instruction `stride - pc`.
    const opts: regex.Options = .{ .syntax = .rust, .utf8 = false };
    var ran: usize = 0;
    for ([_]usize{ 260, 300, 400, 500 }) |mm| {
        const pat = try collisionPattern(mm, 2);
        defer gpa.free(pat);
        var re = Regex.compileOptions(gpa, pat, opts) catch |e| {
            if (e != error.PatternTooLarge) return e;
            continue;
        };
        defer re.deinit(gpa);
        ran += 1;
        try testing.expectEqual(@as(?usize, 2), re.shortestMatch("\xc3\xa9"));
        try testing.expect(re.isMatch("\xc3\xa9"));
    }
    try testing.expect(ran >= 1);
}

test "bytes mode Pike VM: a pending two-byte thread's key never collides with the visited marks of the other threads" {
    // `rem * len - pc` lands on the mark of instruction `len - pc`.
    const opts: regex.Options = .{ .syntax = .rust, .utf8 = false };
    for ([_][2]usize{ .{ 40, 10 }, .{ 60, 20 }, .{ 100, 30 } }) |mn| {
        const pat = try collisionPattern(mn[0], mn[1]);
        defer gpa.free(pat);
        var re = try Regex.compileOptions(gpa, pat, opts);
        defer re.deinit(gpa);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.pike_only = true;
        const sp = m.find("\xc3\xa9", 0);
        try testing.expect(sp != null);
        try testing.expectEqual(@as(usize, 0), sp.?.start);
        try testing.expectEqual(@as(usize, 2), sp.?.end);
    }
}

// ── one-pass engine ─────────────────────────────────────────────────────────

fn eager(re: *const Regex) !Matcher {
    var m = try Matcher.init(gpa, re);
    m.dfa_eager = true;
    return m;
}

test "one-pass engine: built for 11 and 15 groups (24 and 32 slots), refused for 16 (34 slots)" {
    for ([_]usize{ 11, 15, 16 }) |g| {
        const pat = try groups(g);
        defer gpa.free(pat);
        const text = try filled('a', g);
        defer gpa.free(text);
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        var m = try eager(&re);
        defer m.deinit();
        var out: [20]?Span = @splat(null);
        try testing.expect(m.captures(text, 0, &out));
        try testing.expectEqual(Span{ .start = 0, .end = g }, out[0].?);
        try testing.expectEqual(Span{ .start = g - 1, .end = g }, out[g].?);
        try testing.expect(out[g + 1] == null);
        if (g <= 15) try testing.expect(m.onepass != null) else try testing.expect(m.onepass == null);
    }
}

test "one-pass engine: built for a program of exactly 128 instructions, not for 129" {
    var saw_128 = false;
    for (100..140) |k| {
        const pat = try filled('a', k);
        defer gpa.free(pat);
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        var m = try eager(&re);
        defer m.deinit();
        var out: [1]?Span = undefined;
        try testing.expect(m.captures(pat, 0, &out));
        if (re.insts.len <= 128) {
            try testing.expect(m.onepass != null);
        } else {
            try testing.expect(m.onepass == null and !m.onepass_tried);
        }
        if (re.insts.len == 128) saw_128 = true;
    }
    try testing.expect(saw_128);
}

test "one-pass engine: not worked out for a text too short to pay for it; tried once for a program that is not one-pass" {
    var re = try Regex.compile(gpa, "(a)(b)");
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    var out: [3]?Span = undefined;
    try testing.expect(m.captures("ab", 0, &out));
    try testing.expect(m.onepass == null and !m.onepass_tried);

    // `(a*)ab`: two ways out of the start read 'a'.
    var np = try Regex.compile(gpa, "(a*)ab");
    defer np.deinit(gpa);
    var fa = std.testing.FailingAllocator.init(gpa, .{});
    var m2 = try Matcher.init(fa.allocator(), &np);
    defer m2.deinit();
    m2.dfa_eager = true;
    try testing.expect(m2.captures("aaab", 0, &out));
    try testing.expect(m2.onepass_tried and m2.onepass == null);
    const before = fa.alloc_index;
    try testing.expect(m2.captures("aaab", 0, &out));
    try testing.expectEqual(before, fa.alloc_index); // no second try
}

test "one-pass engine: an anchored program is answered without the DFA" {
    var re = try Regex.compile(gpa, "^(a)(b)");
    defer re.deinit(gpa);
    var m = try eager(&re);
    defer m.deinit();
    var out: [3]?Span = undefined;
    try testing.expect(m.captures("ab", 0, &out));
    try testing.expect(m.onepass != null);
    try testing.expect(m.dfa == null);
}

test "one-pass engine: `.` and a lone newline do not overlap; `.` and a class ending at newline do" {
    var re = try Regex.compile(gpa, "(?:.|\\n)a");
    defer re.deinit(gpa);
    var m = try eager(&re);
    defer m.deinit();
    var out: [1]?Span = undefined;
    try testing.expect(m.captures("xa", 0, &out));
    try testing.expect(m.captures("\na", 0, &out));
    try testing.expectEqual(Span{ .start = 0, .end = 2 }, out[0].?);
    try testing.expect(m.onepass != null);

    // `[\x00-\n]` overlaps `.` (on \x00-\x09): not one-pass, and the
    // leftmost-first alternative must win on "\x01x".
    var ov = try Regex.compile(gpa, "(?:(.)x|([\\x00-\\n])y)");
    defer ov.deinit(gpa);
    var m2 = try eager(&ov);
    defer m2.deinit();
    var o2: [3]?Span = undefined;
    try testing.expect(m2.captures("\x01x", 0, &o2));
    try testing.expect(m2.onepass == null);
    try testing.expectEqual(Span{ .start = 0, .end = 1 }, o2[1].?);
    try testing.expect(o2[2] == null);
}

test "one-pass engine: every transition no way out takes is 0" {
    var re = try Regex.compile(gpa, "(a)(b)");
    defer re.deinit(gpa);
    var m = try eager(&re);
    defer m.deinit();
    var out: [3]?Span = undefined;
    try testing.expect(m.captures("ab", 0, &out));
    const op = m.onepass.?;
    try testing.expect(op.trans.items.len >= 3);
    for (op.trans.items) |row| {
        var nonzero: usize = 0;
        for (row) |step| nonzero += @intFromBool(step != 0);
        try testing.expect(nonzero <= 1);
    }
}

test "one-pass engine: no leak when its memory runs out at any point" {
    var re = try Regex.compile(gpa, "(a)(b)");
    defer re.deinit(gpa);
    var k: usize = 0;
    while (k < 100) : (k += 1) {
        var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = k });
        var m = Matcher.init(fa.allocator(), &re) catch continue;
        defer m.deinit();
        m.dfa_eager = true;
        var out: [3]?Span = undefined;
        _ = m.captures("ab", 0, &out);
        if (!fa.has_induced_failure) break;
    }
    try testing.expect(k > 3 and k < 100);
}

test "one-pass engine: a byte 0x80 is never read through the next root's row" {
    // `trans[r + 0x80]` is the NUL entry of root r+1: here the one after "y".
    var re = try Regex.compile(gpa, "xy\\x00z");
    defer re.deinit(gpa);
    var m = try eager(&re);
    defer m.deinit();
    var out: [1]?Span = undefined;
    try testing.expect(m.capturesAnchored("xy\x00z", 0, &out));
    try testing.expect(!m.capturesAnchored("x\x80z", 0, &out));
    try testing.expect(!m.capturesAnchored("x\x81z", 0, &out));
    try testing.expect(m.onepass != null);
}

test "find via captures: the start read off the forward pass is used, the backward DFA stays unbuilt" {
    // No letter of the text after the start is one the start thread could
    // take too (no join), and the match ends before the end of the text (a
    // match found at the very end is not tracked).
    var re = try Regex.compile(gpa, "[a-f][0-9](x)");
    defer re.deinit(gpa);
    var m = try eager(&re);
    defer m.deinit();
    var out: [2]?Span = undefined;
    try testing.expect(m.captures("!!c5xZ", 0, &out));
    try testing.expectEqual(Span{ .start = 2, .end = 5 }, out[0].?);
    try testing.expectEqual(Span{ .start = 4, .end = 5 }, out[1].?);
    try testing.expectEqual(@as(usize, 1), m.dfa.?.tracked);
    try testing.expectEqual(@as(usize, 0), m.dfa.?.rev.keys.items.len);
}

test "captures: a start past the end is no match (also with the one-pass engine ready); `out` may be longer than the groups" {
    var re = try Regex.compile(gpa, "(a)(b)");
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    var out: [8]?Span = @splat(null);
    try testing.expect(!m.captures("ab", 3, &out));
    try testing.expect(!m.capturesAnchored("ab", 3, &out));
    m.dfa_eager = true;
    try testing.expect(!m.captures("ab", 3, &out));
    try testing.expect(m.captures("ab", 0, &out));
    try testing.expectEqual(Span{ .start = 0, .end = 2 }, out[0].?);
    try testing.expectEqual(Span{ .start = 0, .end = 1 }, out[1].?);
    try testing.expectEqual(Span{ .start = 1, .end = 2 }, out[2].?);
    for (out[3..]) |o| try testing.expect(o == null);
}

test "captures on a Matcher with onepass off: an anchored program answers a later start without scratch" {
    var re = try Regex.compile(gpa, "^abc");
    defer re.deinit(gpa);
    var fa = std.testing.FailingAllocator.init(gpa, .{});
    var m = try Matcher.init(fa.allocator(), &re);
    defer m.deinit();
    m.onepass_off = true;
    const before = fa.alloc_index;
    var out: [1]?Span = undefined;
    try testing.expect(!m.captures("xxabc", 2, &out));
    try testing.expectEqual(before, fa.alloc_index);
}

test "Iterator: after the last match the position is past the text" {
    var re = try Regex.compile(gpa, "a");
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    var it = m.iterator("ab");
    try testing.expect(it.next() != null);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(usize, 3), it.pos);
}

// ── prefilter ───────────────────────────────────────────────────────────────

test "assertions: `asserts` is set exactly for programs that have one" {
    for ([_][]const u8{ "abc", "a+b*", "(?:a|b)c" }) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        try testing.expect(!re.asserts);
    }
    for ([_][]const u8{ "\\bfoo", "^a", "a$" }) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        try testing.expect(re.asserts);
    }
}

test "prefilter: a class around U+FFFD gives up the first-byte set, its neighbours do not" {
    var a = try Regex.compile(gpa, "[\\x{fffe}\\x{ffff}]");
    defer a.deinit(gpa);
    try testing.expect(a.prefilter.first != null);
    var b = try Regex.compile(gpa, "[\\x{fff0}-\\x{fffc}]");
    defer b.deinit(gpa);
    try testing.expect(b.prefilter.first != null);
    var c = try Regex.compile(gpa, "[\\x{fff0}-\\x{fffd}]");
    defer c.deinit(gpa);
    try testing.expect(c.prefilter.first == null);
}

test "prefilter: the end-anchored tables exist only for end-anchored programs" {
    var re = try Regex.compile(gpa, "abc");
    defer re.deinit(gpa);
    try testing.expect(!re.prefilter.end_anchored);
    try testing.expect(re.prefilter.last == null);
    try testing.expectEqual(@as(u8, 0), re.prefilter.tail_len);
}

test "prefilter: the first-byte set is also built as a SIMD scan, and Teddy for a one-byte literal prefix" {
    var re = try Regex.compile(gpa, "[xyz]q");
    defer re.deinit(gpa);
    const want = teddy.ByteSet.build(re.prefilter.first.?) != null;
    try testing.expectEqual(want, re.prefilter.bytes != null);

    var hit = false;
    for ([_][]const u8{ "a[bcd]x", "a(?:b|c|d)x", "x(?:yz|yw)" }) |p| {
        var r = try Regex.compile(gpa, p);
        defer r.deinit(gpa);
        if (r.prefilter.lit_len != 1) continue;
        const built = teddy.Teddy.build(r.insts, r.ranges) != null;
        try testing.expectEqual(built, r.prefilter.teddy != null);
        if (built) hit = true;
    }
    try testing.expect(hit);
}

test "prefilter: the last-byte set at the edges of ASCII, the continuation bytes and U+FFFD" {
    const all: u64 = ~@as(u64, 0);
    // U+007F: ASCII, no continuation bytes.
    var del = try Regex.compile(gpa, "\\x7f\\z");
    defer del.deinit(gpa);
    try testing.expect(del.prefilter.end_anchored);
    try testing.expectEqual(@as(u64, 1) << 63, del.prefilter.last.?[1]);
    try testing.expectEqual(@as(u64, 0), del.prefilter.last.?[2]);
    try testing.expectEqual(@as(u64, 0), del.prefilter.last.?[3]);
    // U+0080: its last byte is a continuation byte.
    var c1 = try Regex.compile(gpa, "\\x{80}\\z");
    defer c1.deinit(gpa);
    try testing.expectEqual(all, c1.prefilter.last.?[2]);
    try testing.expectEqual(@as(u64, 0), c1.prefilter.last.?[3]);
    // A class just short of U+FFFD, and one just past it.
    var lo = try Regex.compile(gpa, "[\\x{fff0}-\\x{fffc}]\\z");
    defer lo.deinit(gpa);
    try testing.expectEqual(all, lo.prefilter.last.?[2]);
    try testing.expectEqual(@as(u64, 0), lo.prefilter.last.?[3]);
    var hi = try Regex.compile(gpa, "[\\x{fffe}\\x{ffff}]\\z");
    defer hi.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), hi.prefilter.last.?[3]);
    var at = try Regex.compile(gpa, "[\\x{fff0}-\\x{fffd}]\\z");
    defer at.deinit(gpa);
    try testing.expectEqual(all, at.prefilter.last.?[3]);
}

test "prefilter: the tail of an end-anchored program, its length, its bytes and its limits" {
    // 16 levels at most, whatever the length of the literal (20 and 80 long:
    // the latter's instructions live past the first 64-bit word).
    for ([_]usize{ 20, 80 }) |k| {
        const pat = try lit(k, "\\z");
        defer gpa.free(pat);
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        try testing.expectEqual(@as(u8, 16), re.prefilter.tail_len);
        try testing.expectEqual([2]u8{ 'a', 'a' }, re.prefilter.tail[15]);
    }
    // A program of 128 instructions is still worked out, one of 129 not.
    var saw_128 = false;
    for (100..140) |k| {
        const pat = try lit(k, "\\z");
        defer gpa.free(pat);
        var re = try Regex.compile(gpa, pat);
        defer re.deinit(gpa);
        if (re.insts.len == 128) saw_128 = true;
        const want: u8 = if (re.insts.len <= 128) 16 else 0;
        try testing.expectEqual(want, re.prefilter.tail_len);
    }
    try testing.expect(saw_128);
    // U+0080 is no ASCII byte; U+007F is one.
    var c1 = try Regex.compile(gpa, "\\x{80}\\z");
    defer c1.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), c1.prefilter.tail_len);
    var del = try Regex.compile(gpa, "\\x7f\\z");
    defer del.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), del.prefilter.tail_len);
    try testing.expectEqual([2]u8{ 0x7f, 0x7f }, del.prefilter.tail[0]);
    // Three instructions reading the same last byte are one byte, not three;
    // the level before them has three bytes and stops the tail.
    var dup = try Regex.compile(gpa, "(?:ax|bx|cx)\\z");
    defer dup.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), dup.prefilter.tail_len);
    try testing.expectEqual([2]u8{ 'x', 'x' }, dup.prefilter.tail[0]);
}

test "prefilter: a class that takes no byte ends the tail (and does not index an empty byte list)" {
    for ([_][]const u8{ "[^\\x00-\\x{10FFFF}]\\z", "[a&&b]\\z" }) |p| {
        var re = Regex.compileOptions(gpa, p, .{ .syntax = if (p[1] == 'a') .rust else .perl }) catch continue;
        defer re.deinit(gpa);
        try testing.expectEqual(@as(u8, 0), re.prefilter.tail_len);
    }
}

// ── backtracker ─────────────────────────────────────────────────────────────

test "backtracker: the visited table is the window's bits in whole words, nothing for a window under two positions" {
    var re = try Regex.compile(gpa, "(abcdefghij)(klmnopqrst)");
    defer re.deinit(gpa);
    const n = re.insts.len;
    for (0..131) |len| {
        for ([_]usize{ 0, 3 }) |from| {
            if (from > len) continue;
            const text = try filled('x', len);
            defer gpa.free(text);
            var m = try Matcher.init(gpa, &re);
            defer m.deinit();
            try testing.expect(m.find(text, from) == null);
            const width = len - from + 1;
            const want: usize = if (width < 2) 0 else (width * n + 63) / 64;
            try testing.expectEqual(want, m.bt_visited.items.len);
        }
    }
}

// ── readers ─────────────────────────────────────────────────────────────────

const Half = struct {
    r: std.Io.Reader,
    left: []const u8,
    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *@This() = @fieldParentPtr("r", r);
        if (self.left.len == 0) return error.ReadFailed;
        const n = limit.minInt(self.left.len);
        try w.writeAll(self.left[0..n]);
        self.left = self.left[n..];
        return n;
    }
};

test "findReader and capturesReader: the match anywhere in the stream, a failure after it changes nothing, one before it is an error" {
    var re = try Regex.compile(gpa, "(a)b");
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();

    // Not a full match: the stream goes on after it.
    var fixed: std.Io.Reader = .fixed("abz");
    try testing.expectEqual(Span{ .start = 0, .end = 2 }, (try m.findReader(&fixed)).?);
    var fixed2: std.Io.Reader = .fixed("abz");
    var out: [2]?Span = undefined;
    try testing.expect(try m.capturesReader(&fixed2, &out));
    try testing.expectEqual(Span{ .start = 0, .end = 1 }, out[1].?);

    // The reader fails right after "ab": the answer was settled.
    var b1: [8]u8 = undefined;
    var h1: Half = .{ .r = .{ .vtable = &.{ .stream = Half.stream }, .buffer = &b1, .seek = 0, .end = 0 }, .left = "xab" };
    try testing.expectEqual(Span{ .start = 1, .end = 3 }, (try m.findReader(&h1.r)).?);
    var b2: [8]u8 = undefined;
    var h2: Half = .{ .r = .{ .vtable = &.{ .stream = Half.stream }, .buffer = &b2, .seek = 0, .end = 0 }, .left = "xab" };
    try testing.expect(try m.capturesReader(&h2.r, &out));
    try testing.expectEqual(Span{ .start = 1, .end = 2 }, out[1].?);

    // It fails before: an error, not "no match".
    var b3: [8]u8 = undefined;
    var h3: Half = .{ .r = .{ .vtable = &.{ .stream = Half.stream }, .buffer = &b3, .seek = 0, .end = 0 }, .left = "xa" };
    try testing.expectError(error.ReadFailed, m.findReader(&h3.r));
    var b4: [8]u8 = undefined;
    var h4: Half = .{ .r = .{ .vtable = &.{ .stream = Half.stream }, .buffer = &b4, .seek = 0, .end = 0 }, .left = "xa" };
    try testing.expectError(error.ReadFailed, m.capturesReader(&h4.r, &out));
}
