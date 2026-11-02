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
//! `^` and `$` outside a class stay anchors. RFC 9485's grammar calls them
//! NormalChar and says no more, while its own §5 mappings pass them to engines
//! that anchor on them, and the compliance suite pins that reading ("functions,
//! match, explicit caret": `match("abc", "^ab.*")` holds). The suite wins: a
//! literal reading would fail it, and disagree with the implementations a path
//! is written against.
//!
//! `translate` returns null for a pattern outside the grammar. RFC 9535 §2.4.6
//! and §2.4.7 make `match()`/`search()` false for such a pattern, never an
//! error: it can arrive from the document itself.

const std = @import("std");

/// A longer pattern is treated as invalid. Our limit, RFC 9485 §8 allows one:
/// the engine's own 1024-instruction limit stops the compile, this stops the
/// walk over a megabyte of text that a hostile document can supply per node.
pub const max_pattern_len: usize = 4096;
/// Nested parentheses; the checker recurses once per level.
const max_depth: u32 = 32;
/// RFC 9485 leaves the bound of `{n,m}` open; the engine's `max_repeat`. A
/// count over it is invalid here rather than an engine error, same result.
const max_count: u32 = 1000;

const Fail = error{ NotIRegexp, OutOfMemory };

const T = struct {
    a: std.mem.Allocator,
    s: []const u8,
    i: usize = 0,
    out: std.ArrayList(u8) = .empty,

    fn peek(t: *const T) ?u8 {
        return if (t.i < t.s.len) t.s[t.i] else null;
    }
    fn emit(t: *T, text: []const u8) Fail!void {
        try t.out.appendSlice(t.a, text);
    }
    /// Copy one whole code point as is. The input is known valid UTF-8.
    fn copyChar(t: *T) Fail!void {
        const n = std.unicode.utf8ByteSequenceLength(t.s[t.i]) catch return error.NotIRegexp;
        if (t.i + n > t.s.len) return error.NotIRegexp;
        try t.emit(t.s[t.i .. t.i + n]);
        t.i += n;
    }
};

/// The engine's pattern for I-Regexp `pattern`, allocated in `a`, or null when
/// `pattern` is not an I-Regexp.
pub fn translate(a: std.mem.Allocator, pattern: []const u8) error{OutOfMemory}!?[]const u8 {
    if (pattern.len > max_pattern_len) return null;
    if (!std.unicode.utf8ValidateSlice(pattern)) return null;
    var t: T = .{ .a = a, .s = pattern };
    alternatives(&t, 0) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NotIRegexp => return null,
    };
    if (t.i != t.s.len) return null; // an unmatched `)`
    return t.out.items;
}

fn alternatives(t: *T, depth: u32) Fail!void {
    while (true) {
        while (t.peek()) |c| {
            if (c == '|' or c == ')') break;
            try piece(t, depth);
        }
        if (t.peek() != '|') return;
        t.i += 1;
        try t.emit("|");
    }
}

fn piece(t: *T, depth: u32) Fail!void {
    try atom(t, depth);
    const c = t.peek() orelse return;
    switch (c) {
        '*', '+', '?' => {
            t.i += 1;
            try t.out.append(t.a, c);
        },
        '{' => try rangeQuantifier(t),
        else => {},
    }
}

/// `{n}`, `{n,}`, `{n,m}`, counts rewritten without leading zeros.
fn rangeQuantifier(t: *T) Fail!void {
    t.i += 1;
    var buf: [32]u8 = undefined;
    const low = try count(t);
    var text = std.fmt.bufPrint(&buf, "{{{d}", .{low}) catch unreachable;
    try t.emit(text);
    if (t.peek() == ',') {
        t.i += 1;
        try t.emit(",");
        if (t.peek() != '}') {
            const high = try count(t);
            text = std.fmt.bufPrint(&buf, "{d}", .{high}) catch unreachable;
            try t.emit(text);
        }
    }
    if (t.peek() != '}') return error.NotIRegexp;
    t.i += 1;
    try t.emit("}");
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

fn atom(t: *T, depth: u32) Fail!void {
    const c = t.s[t.i];
    switch (c) {
        '(' => {
            if (depth >= max_depth) return error.NotIRegexp;
            t.i += 1;
            try t.emit("(?:");
            try alternatives(t, depth + 1);
            if (t.peek() != ')') return error.NotIRegexp;
            t.i += 1;
            try t.emit(")");
        },
        '.' => {
            t.i += 1;
            try t.emit("[^\\n\\r]");
        },
        '[' => try classExpr(t),
        '\\' => try escape(t),
        // The characters NormalChar leaves out.
        ')', '*', '+', '?', ']', '{', '|', '}' => return error.NotIRegexp,
        else => try t.copyChar(),
    }
}

/// `\` + SingleCharEsc, `\p{…}` or `\P{…}`, outside or inside a class; the
/// engine reads every one of them the same way.
fn escape(t: *T) Fail!void {
    t.i += 1;
    const c = t.peek() orelse return error.NotIRegexp;
    switch (c) {
        '(', ')', '*', '+', '-', '.', '?', '[', '\\', ']', '^', 'n', 'r', 't', '{', '|', '}' => {
            t.i += 1;
            try t.out.append(t.a, '\\');
            try t.out.append(t.a, c);
        },
        'p', 'P' => {
            t.i += 1;
            if (t.peek() != '{') return error.NotIRegexp;
            const start = t.i + 1;
            const close = std.mem.indexOfScalarPos(u8, t.s, start, '}') orelse return error.NotIRegexp;
            const cat = t.s[start..close];
            if (!isCategory(cat)) return error.NotIRegexp;
            try t.out.append(t.a, '\\');
            try t.out.append(t.a, c);
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
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const got = try translate(arena.allocator(), pattern);
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
