// SPDX-License-Identifier: MIT
//! I-Regexp (RFC 9485) on top of the sibling `regex` engine: a checker of the
//! RFC's grammar that also rewrites the pattern into the engine's syntax.
//!
//! The grammar is a strict subset, and part of it means something else to the
//! engine, so the text is never handed over as written. Refused here, because
//! I-Regexp does not have them although the engine does: `\d \w \s \b`,
//! backreferences, lookaround, flags, `(?`, lazy quantifiers, `\x`, POSIX
//! classes. Rewritten here, because the meaning differs: `.` excludes `\r` as
//! well as `\n` (§5.3), and `(…)` does not capture.
//!
//! `^` is an anchor only as the first atom of a branch and `$` only as the last,
//! unquantified, in any branch, a group's too; anywhere else they are the
//! characters. RFC 9485's grammar calls both NormalChar and says no more, while
//! its own §5 mappings pass them to engines that anchor on them, and the
//! compliance suite pins that where they lead or end a pattern ("functions, match,
//! explicit caret": `match("abc", "^ab.*")` holds). So the suite's cases hold, and
//! `a$b`, which as anchors could never match, means what NormalChar says.
//!
//! `translate` returns null for a pattern outside the grammar or past a limit
//! below. RFC 9535 §2.4.6 and §2.4.7 make `match()`/`search()` false for such a
//! pattern, never an error: it can arrive from the document itself.

const std = @import("std");

/// A longer pattern is treated as invalid. Our limit, RFC 9485 §8 allows one:
/// this stops the walk over a megabyte of text that a hostile document can supply
/// per node; the program's size is what the `regex.Builder` limits (1024
/// instructions, `root.zig`: the engine's plain `compile` would go to 4096, in
/// 2 MiB of scratch).
pub const max_pattern_len: usize = 4096;
/// The room `translate` may need: `.` is the longest rewrite, seven bytes for one.
pub const max_output: usize = 7 * max_pattern_len;
/// Nested parentheses; the checker recurses once per level.
const max_depth: u32 = 32;
/// RFC 9485 leaves the bound of `{n,m}` open; the engine's `max_repeat`. A
/// count over it is invalid here rather than an engine error, same result.
const max_count: u32 = 1000;
/// How many copies of its atoms the counts ask for, nested counts multiplied. A
/// body that emits code meets the 1024 instructions first, but an empty one emits
/// nothing: `((){1000}){1000}` costs the engine's compiler tens of milliseconds
/// for no instruction, and it is 16 bytes a document can repeat.
const max_weight: u32 = 4096;

const Fail = error{NotIRegexp};

const T = struct {
    s: []const u8,
    i: usize = 0,
    out: []u8,
    n: usize = 0,

    fn peek(t: *const T) ?u8 {
        return if (t.i < t.s.len) t.s[t.i] else null;
    }
    fn emit(t: *T, text: []const u8) Fail!void {
        if (t.n + text.len > t.out.len) return error.NotIRegexp;
        @memcpy(t.out[t.n..][0..text.len], text);
        t.n += text.len;
    }
    /// Copy one whole code point as is. The input is known valid UTF-8.
    fn copyChar(t: *T) Fail!void {
        const n = std.unicode.utf8ByteSequenceLength(t.s[t.i]) catch return error.NotIRegexp;
        if (t.i + n > t.s.len) return error.NotIRegexp;
        try t.emit(t.s[t.i .. t.i + n]);
        t.i += n;
    }
};

/// The engine's pattern for I-Regexp `pattern`, written into `out` (no allocation:
/// a document may supply many), or null when `pattern` is not an I-Regexp or `out`
/// is too small. `max_output` bytes are always enough.
pub fn translate(out: []u8, pattern: []const u8) ?[]const u8 {
    if (pattern.len > max_pattern_len) return null;
    if (!std.unicode.utf8ValidateSlice(pattern)) return null;
    var t: T = .{ .s = pattern, .out = out };
    const weight = alternatives(&t, 0) catch return null;
    if (weight > max_weight) return null;
    if (t.i != t.s.len) return null; // an unmatched `)`
    return out[0..t.n];
}

/// Returns the weight of what it read (see `max_weight`), at least 1.
fn alternatives(t: *T, depth: u32) Fail!u32 {
    var total: u32 = 0;
    while (true) {
        var first = true;
        while (t.peek()) |c| {
            if (c == '|' or c == ')') break;
            total +|= try piece(t, depth, first);
            first = false;
        }
        if (t.peek() != '|') return @max(total, 1);
        t.i += 1;
        try t.emit("|");
    }
}

fn piece(t: *T, depth: u32, first: bool) Fail!u32 {
    const weight = try atom(t, depth, first);
    const c = t.peek() orelse return weight;
    switch (c) {
        '*', '+', '?' => {
            t.i += 1;
            try t.emit(&.{c});
            return weight;
        },
        '{' => return weight *| try rangeQuantifier(t),
        else => return weight,
    }
}

/// `{n}`, `{n,}`, `{n,m}`, counts rewritten without leading zeros. Returns the
/// largest count, at least 1.
fn rangeQuantifier(t: *T) Fail!u32 {
    t.i += 1;
    var buf: [32]u8 = undefined;
    const low = try count(t);
    var most = low;
    var text = std.fmt.bufPrint(&buf, "{{{d}", .{low}) catch return error.NotIRegexp;
    try t.emit(text);
    if (t.peek() == ',') {
        t.i += 1;
        try t.emit(",");
        if (t.peek() != '}') {
            const high = try count(t);
            most = @max(most, high);
            text = std.fmt.bufPrint(&buf, "{d}", .{high}) catch return error.NotIRegexp;
            try t.emit(text);
        }
    }
    if (t.peek() != '}') return error.NotIRegexp;
    t.i += 1;
    try t.emit("}");
    return @max(most, 1);
}

fn count(t: *T) Fail!u32 {
    const start = t.i;
    var v: u32 = 0;
    while (t.peek()) |c| {
        if (!std.ascii.isDigit(c)) break;
        v = v * 10 + (c - '0');
        if (v > max_count) return error.NotIRegexp;
        t.i += 1;
    }
    if (t.i == start) return error.NotIRegexp;
    return v;
}

fn atom(t: *T, depth: u32, first: bool) Fail!u32 {
    const c = t.s[t.i];
    switch (c) {
        '(' => {
            if (depth >= max_depth) return error.NotIRegexp;
            t.i += 1;
            try t.emit("(?:");
            const inner = try alternatives(t, depth + 1);
            if (t.peek() != ')') return error.NotIRegexp;
            t.i += 1;
            try t.emit(")");
            return inner;
        },
        '.' => {
            t.i += 1;
            try t.emit("[^\\n\\r]");
        },
        '[' => try classExpr(t),
        '\\' => try escape(t),
        // The characters NormalChar leaves out.
        ')', '*', '+', '?', ']', '{', '|', '}' => return error.NotIRegexp,
        '^' => {
            t.i += 1;
            const quantified = if (t.peek()) |n| n == '*' or n == '+' or n == '?' or n == '{' else false;
            try t.emit(if (first and !quantified) "^" else "\\^");
        },
        '$' => {
            t.i += 1;
            const last = if (t.peek()) |n| n == '|' or n == ')' else true;
            try t.emit(if (last) "$" else "\\$");
        },
        else => try t.copyChar(),
    }
    return 1;
}

/// `\` + SingleCharEsc, `\p{…}` or `\P{…}`, outside or inside a class; the
/// engine reads every one of them the same way.
fn escape(t: *T) Fail!void {
    t.i += 1;
    const c = t.peek() orelse return error.NotIRegexp;
    switch (c) {
        '(', ')', '*', '+', '-', '.', '?', '[', '\\', ']', '^', 'n', 'r', 't', '{', '|', '}' => {
            t.i += 1;
            try t.emit(&.{ '\\', c });
        },
        'p', 'P' => {
            t.i += 1;
            if (t.peek() != '{') return error.NotIRegexp;
            const start = t.i + 1;
            const close = std.mem.indexOfScalarPos(u8, t.s, start, '}') orelse return error.NotIRegexp;
            const cat = t.s[start..close];
            if (!isCategory(cat)) return error.NotIRegexp;
            try t.emit(&.{ '\\', c });
            try t.emit(t.s[start - 1 .. close + 1]);
            t.i = close + 1;
        },
        else => return error.NotIRegexp,
    }
}

/// RFC 9485 `IsCategory`: general categories only. `Cs` is not in the grammar,
/// and neither are scripts or long names, which the engine would take.
fn isCategory(cat: []const u8) bool {
    if (cat.len == 1) return std.mem.indexOfScalar(u8, "LMNPZSC", cat[0]) != null;
    if (cat.len != 2) return false;
    const seconds: []const u8 = switch (cat[0]) {
        'L' => "lmotu",
        'M' => "nce",
        'N' => "dlo",
        'P' => "cdseifo",
        'Z' => "slp",
        'S' => "mcko",
        'C' => "cfno",
        else => return false,
    };
    return std.mem.indexOfScalar(u8, seconds, cat[1]) != null;
}

/// `"[" ["^"] ("-" / CCE1) *CCE1 ["-"] "]"`.
fn classExpr(t: *T) Fail!void {
    t.i += 1;
    try t.emit("[");
    if (t.peek() == '^') {
        t.i += 1;
        try t.emit("^");
    }
    if (t.peek() == '-') {
        t.i += 1;
        try t.emit("\\-");
    } else try classElement(t); // at least one
    while (true) {
        const c = t.peek() orelse return error.NotIRegexp;
        if (c == ']') break;
        if (c == '-') {
            // Only just before the `]`.
            t.i += 1;
            if (t.peek() != ']') return error.NotIRegexp;
            try t.emit("\\-");
            break;
        }
        try classElement(t);
    }
    t.i += 1;
    try t.emit("]");
}

/// CCE1: `CCchar ["-" CCchar]`, or a category escape.
fn classElement(t: *T) Fail!void {
    const c = t.peek() orelse return error.NotIRegexp;
    if (c == '\\' and t.i + 1 < t.s.len and (t.s[t.i + 1] == 'p' or t.s[t.i + 1] == 'P')) return escape(t);
    try classChar(t);
    if (t.peek() != '-') return;
    // `a-]` is `a` and a closing `-`, which the caller's loop sees.
    if (t.i + 1 < t.s.len and t.s[t.i + 1] == ']') return;
    t.i += 1;
    try t.emit("-");
    try classChar(t);
}

fn classChar(t: *T) Fail!void {
    const c = t.peek() orelse return error.NotIRegexp;
    switch (c) {
        '-', '[', ']' => return error.NotIRegexp,
        '\\' => {
            const e = if (t.i + 1 < t.s.len) t.s[t.i + 1] else return error.NotIRegexp;
            if (e == 'p' or e == 'P') return error.NotIRegexp; // not a range end
            try escape(t);
        },
        // `^` is an ordinary CCchar, the engine must not see it as one first.
        '^' => {
            t.i += 1;
            try t.emit("\\^");
        },
        else => try t.copyChar(),
    }
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

fn expectTranslate(pattern: []const u8, want: ?[]const u8) !void {
    var buf: [max_output]u8 = undefined;
    const got = translate(&buf, pattern);
    if (want) |w| {
        if (got == null) {
            std.debug.print("refused, should be I-Regexp: {s}\n", .{pattern});
            return error.TestExpectedEqual;
        }
        try testing.expectEqualStrings(w, got.?);
    } else if (got) |g| {
        std.debug.print("accepted, is not I-Regexp: {s} -> {s}\n", .{ pattern, g });
        return error.TestExpectedEqual;
    }
}

test "I-Regexp: rewritten where the engine reads the text differently" {
    try expectTranslate("", "");
    try expectTranslate("abc", "abc");
    try expectTranslate("^a$", "^a$");
    try expectTranslate("^", "^");
    try expectTranslate("$", "$");
    try expectTranslate("a$b", "a\\$b");
    try expectTranslate("a^b", "a\\^b");
    try expectTranslate("x|^y$|z", "x|^y$|z");
    try expectTranslate("(^a$)b", "(?:^a$)b");
    try expectTranslate("^^a$$", "^\\^a\\$$");
    try expectTranslate("^*$+", "\\^*\\$+");
    try expectTranslate("[a$]", "[a$]");
    try expectTranslate(".", "[^\\n\\r]");
    try expectTranslate("[a-z&&b]", "[a-z&&b]"); // `&` is an ordinary CCchar
    try expectTranslate("(a|b)*", "(?:a|b)*");
    try expectTranslate("a{02,003}", "a{2,3}");
    try expectTranslate("a{2,}", "a{2,}");
    try expectTranslate("a{2}", "a{2}");
    try expectTranslate("[a-z]", "[a-z]");
    try expectTranslate("[^a]", "[^a]");
    try expectTranslate("[a^]", "[a\\^]");
    try expectTranslate("[-a]", "[\\-a]");
    try expectTranslate("[a-]", "[a\\-]");
    try expectTranslate("[-]", "[\\-]");
    try expectTranslate("[\\p{Lu}0]", "[\\p{Lu}0]");
    try expectTranslate("\\p{L}\\P{Nd}", "\\p{L}\\P{Nd}");
    try expectTranslate("\\.\\n\\-", "\\.\\n\\-");
    try expectTranslate("é∂", "é∂");
}

test "I-Regexp: the engine's wider syntax is refused, not passed on" {
    for ([_][]const u8{
        "\\d",     "\\w",        "\\s",        "\\b",         "\\1",     "\\x41",       "\\u0041",
        "\\Q",     "(?:a)",      "(?i)a",      "(?P<n>a)",    "(?<n>a)", "(?=a)",       "(?!a)",
        "a*?",     "a+?",        "a??",        "a{1,2}?",     "a**",     "*",           "+a",
        "?",       "(",          ")",          "a)",          "(a",      "[",           "]",
        "{",       "}",          "a{",         "a{,2}",       "a{1",     "a{1,2",       "a{x}",
        "a{1001}", "\\",         "[]",         "[^]",         "[a",      "[[:digit:]]", "[\\d]",
        "[a--b]",  "[a-b-c]",    "\\p{Greek}", "\\p{Letter}", "\\p{Cs}", "\\pL",        "\\p{}",
        "\\p{L",   "[a-\\p{L}]", "[\\p{L}-a]", "|)",
    }) |pattern| try expectTranslate(pattern, null);
    try expectTranslate("\xff", null); // not UTF-8
    var long: [max_pattern_len + 1]u8 = @splat('a');
    try expectTranslate(&long, null);
    try expectTranslate(long[0..max_pattern_len], long[0..max_pattern_len]);
    var deep: [2 * max_depth + 2]u8 = undefined;
    @memset(deep[0 .. max_depth + 1], '(');
    @memset(deep[max_depth + 1 ..], ')');
    try expectTranslate(&deep, null);
}

test "I-Regexp: every category of the grammar compiles in the engine, in and out of a class" {
    const regex = @import("regex");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{
        "L",  "Ll", "Lm", "Lo", "Lt", "Lu", "M",  "Mc", "Me", "Mn", "N",  "Nd", "Nl", "No", "P",  "Pc", "Pd", "Pe",
        "Pf", "Pi", "Po", "Ps", "Z",  "Zl", "Zp", "Zs", "S",  "Sc", "Sk", "Sm", "So", "C",  "Cc", "Cf", "Cn", "Co",
    }) |cat| {
        for ([_][]const u8{ "\\p{{{s}}}", "\\P{{{s}}}", "[\\p{{{s}}}a]" }, 0..) |_, form| {
            const pattern = switch (form) {
                0 => try a.print("\\p{{{s}}}", .{cat}),
                1 => try a.print("\\P{{{s}}}", .{cat}),
                else => try a.print("[\\p{{{s}}}a]", .{cat}),
            };
            var buf: [max_output]u8 = undefined;
            const text = translate(&buf, pattern) orelse return error.TestExpectedEqual;
            _ = regex.Regex.compile(a, text) catch |e| {
                std.debug.print("engine refused {s}: {t}\n", .{ pattern, e });
                return e;
            };
        }
    }
}

test "I-Regexp: the weight of nested counts is bounded, and so is the output" {
    try expectTranslate("(){1000}", "(?:){1000}");
    try expectTranslate("((a){4}){1000}", "(?:(?:a){4}){1000}");
    try expectTranslate("((a){5}){1000}", null);
    try expectTranslate("((){1000}){1000}", null);
    try expectTranslate("((a|b|c){1000}){2}", null);
    // Every rewrite fits `max_output`.
    var dots: [max_pattern_len]u8 = @splat('.');
    var buf: [max_output]u8 = undefined;
    try testing.expectEqual(max_output, translate(&buf, &dots).?.len);
    var small: [8]u8 = undefined;
    try testing.expectEqual(null, translate(&small, "...."));
}
