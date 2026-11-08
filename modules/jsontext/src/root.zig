// SPDX-License-Identifier: MIT

//! jsontext — small, dependency-free JSON text helpers: write a byte string as a
//! JSON string literal (RFC 8259 §7) with a chosen policy for ill-formed UTF-8,
//! optional `\uXXXX` for all non-ASCII, optional HTML-safe escaping; and a
//! string-aware nesting prescan (`depthWithin`) to cap depth before a parser
//! allocates.
//!
//! It is a *text* helper, not a JSON library: it neither parses nor builds
//! documents (`std.json` does that). It exists so the string escaper, which a
//! dozen modules had each written again, is fixed in one place.

const std = @import("std");

pub const meta = .{
    .doc = "JSON text helpers: string-literal writer (RFC 8259 §7; U+FFFD / byte-escape / reject for ill-formed UTF-8, ASCII-only and HTML-safe options) and a string-aware nesting-depth prescan",
    .platform_note = "any",
    .targets = .{ .linux64, .linux32, .windows },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Go encoding/json string encoding (HTMLEscape) + Rust serde_json format_escaped_str + CPython json.dumps(ensure_ascii=)",
    .deps = .{},
};

// ── string literals ─────────────────────────────────────────────────────────

/// What to do with a byte sequence that is not well-formed UTF-8 (Unicode 16.0
/// Table 3-7: overlongs, surrogates `ED A0..BF`, anything above U+10FFFF, stray
/// continuation bytes and truncated sequences all count).
pub const InvalidUtf8 = enum {
    /// One U+FFFD per **maximal subpart** (Unicode §3.9 "best practice", the
    /// WHATWG Encoding Standard and Rust's `String::from_utf8_lossy`). The
    /// output is always a valid JSON string. Differs from Go's `encoding/json`
    /// (one U+FFFD per ill-formed *byte*) exactly on a truncated but otherwise
    /// valid prefix: `E2 82` is one U+FFFD here, two in Go.
    replace,
    /// Every byte of an ill-formed subsequence is written as `\u00XX` (so the
    /// byte values survive, read back as Latin-1 code points). Well-formed
    /// sequences next to it are written normally. The output is valid JSON.
    escape_bytes,
    /// Return `error.InvalidUtf8`. Output already written by the call stays in
    /// the writer: the opening quote and everything before the bad sequence
    /// (the partial literal is not valid JSON, do not use it).
    reject,
};

/// Options of `writeString` / `writeStringContents`. They are `comptime`
/// parameters, so each combination compiles to its own loop and the default one
/// pays for nothing it does not use.
pub const StringOptions = struct {
    invalid_utf8: InvalidUtf8 = .replace,
    /// Write every non-ASCII scalar as `\uXXXX` (a surrogate pair above U+FFFF,
    /// lowercase hex), like Python's `ensure_ascii=True`. With `.replace` the
    /// replacement character is then written `\ufffd`.
    ascii_only: bool = false,
    /// Also escape `<`, `>`, `&`, U+2028 and U+2029 as `\u003c`, `\u003e`,
    /// `\u0026`, `\u2028`, `\u2029` — Go's `encoding/json` default `HTMLEscape` set —
    /// so the text can sit inside an HTML `<script>` element or be `eval`ed by an
    /// older JavaScript engine.
    html_safe: bool = false,
};

/// `writeString` errors: the writer's, plus `InvalidUtf8` which only
/// `.invalid_utf8 = .reject` ever returns. With the other two policies a caller
/// that wants no error union can `catch |e| switch (e) { error.WriteFailed =>
/// return error.WriteFailed, error.InvalidUtf8 => unreachable }`.
pub const WriteError = std.Io.Writer.Error || error{InvalidUtf8};

/// Write `s` as a double-quoted JSON string literal. Always escaped: `"`, `\`
/// and every byte below 0x20 (`\b \t \n \f \r` short forms, else `\u00XX`).
/// DEL (0x7F) is not a JSON control character (RFC 8259 §7) and passes through.
/// `/` is never escaped. Hex digits are lowercase. See `StringOptions` for the
/// rest. Allocates nothing; well-formed bytes are never inspected twice and are
/// written in runs, not one at a time.
pub fn writeString(w: *std.Io.Writer, s: []const u8, comptime opts: StringOptions) WriteError!void {
    try w.writeByte('"');
    try writeStringContents(w, s, opts);
    try w.writeByte('"');
}

/// `writeString` without the surrounding quotes (to splice into a longer literal).
///
/// With `.replace` the output is valid UTF-8 for any input; for input that is
/// already well-formed UTF-8 the string it decodes to is exactly `s`.
pub fn writeStringContents(w: *std.Io.Writer, s: []const u8, comptime opts: StringOptions) WriteError!void {
    const verbatim = comptime verbatimTable(opts);
    var out: Pending = .{ .w = w };
    // Start of the pending verbatim run: everything in `s[run..i]` is passed
    // through untouched and handed over in one piece when something interrupts.
    var run: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        // The whole of the common case, one table lookup per byte.
        if (verbatim[c]) {
            i += 1;
            continue;
        }
        if (c < 0x80) {
            try out.put(s[run..i]);
            switch (c) {
                '"' => try out.putLit("\\\""),
                '\\' => try out.putLit("\\\\"),
                0x08 => try out.putLit("\\b"),
                0x09 => try out.putLit("\\t"),
                0x0A => try out.putLit("\\n"),
                0x0C => try out.putLit("\\f"),
                0x0D => try out.putLit("\\r"),
                else => try out.putUnit(c),
            }
            i += 1;
            run = i;
            continue;
        }
        const step = utf8Step(s[i..]);
        if (step.ok) {
            if (opts.ascii_only) {
                try out.put(s[run..i]);
                try out.putScalar(decodeScalar(s[i..][0..step.len]));
                i += step.len;
                run = i;
                continue;
            }
            // U+2028 / U+2029 are E2 80 A8 / E2 80 A9.
            if (opts.html_safe and step.len == 3 and c == 0xE2 and s[i + 1] == 0x80 and
                (s[i + 2] == 0xA8 or s[i + 2] == 0xA9))
            {
                try out.put(s[run..i]);
                try out.put(if (s[i + 2] == 0xA8) "\\u2028" else "\\u2029");
                i += 3;
                run = i;
                continue;
            }
            i += step.len; // well-formed non-ASCII — also stays in the run
            continue;
        }
        switch (opts.invalid_utf8) {
            .reject => {
                // Everything before the bad sequence is written, then the error.
                try out.put(s[run..i]);
                try out.flush();
                return error.InvalidUtf8;
            },
            .replace => {
                try out.put(s[run..i]);
                try out.putLit(if (opts.ascii_only) "\\ufffd" else replacement);
            },
            .escape_bytes => {
                try out.put(s[run..i]);
                for (s[i..][0..step.len]) |b| try out.putUnit(b);
            },
        }
        i += step.len;
        run = i;
    }
    try out.put(s[run..]);
    try out.flush();
}

/// Small pieces (escapes, short runs) are gathered here and handed to the
/// writer in blocks: one `writeAll` per escape made control-heavy input twice
/// as slow as Go's encoder (bench-jsontext, 2026-11-08). A piece of
/// `direct_len` bytes or more goes straight through, after what is pending, so
/// the order of the output is the order of the calls and long runs are not
/// copied twice.
const Pending = struct {
    w: *std.Io.Writer,
    n: usize = 0,
    buf: [256]u8 = undefined,

    const direct_len = 64;

    inline fn put(p: *Pending, bytes: []const u8) std.Io.Writer.Error!void {
        if (bytes.len >= direct_len) {
            try p.flush();
            return p.w.writeAll(bytes);
        }
        if (p.n + bytes.len > p.buf.len) try p.flush();
        // Runs between escapes are mostly a few bytes: a loop beats a `memcpy` call.
        for (bytes, p.buf[p.n..][0..bytes.len]) |b, *d| d.* = b;
        p.n += bytes.len;
    }

    /// A piece whose bytes are known at compile time (an escape sequence):
    /// the copy is a fixed-size move, not a `memcpy` call.
    inline fn putLit(p: *Pending, comptime lit: []const u8) std.Io.Writer.Error!void {
        if (p.n + lit.len > p.buf.len) try p.flush();
        p.buf[p.n..][0..lit.len].* = lit[0..lit.len].*;
        p.n += lit.len;
    }

    fn flush(p: *Pending) std.Io.Writer.Error!void {
        const n = p.n;
        p.n = 0;
        try p.w.writeAll(p.buf[0..n]);
    }

    /// `\uXXXX` (lowercase hex) for one UTF-16 code unit.
    inline fn putUnit(p: *Pending, unit: u16) std.Io.Writer.Error!void {
        if (p.n + 6 > p.buf.len) try p.flush();
        const hex = "0123456789abcdef";
        p.buf[p.n..][0..6].* = .{ '\\', 'u', hex[unit >> 12], hex[(unit >> 8) & 15], hex[(unit >> 4) & 15], hex[unit & 15] };
        p.n += 6;
    }

    /// One scalar as `\uXXXX`, a surrogate pair above U+FFFF.
    fn putScalar(p: *Pending, cp: u21) std.Io.Writer.Error!void {
        if (cp < 0x10000) return p.putUnit(@intCast(cp));
        const v: u32 = cp - 0x10000;
        try p.putUnit(@intCast(0xD800 + (v >> 10)));
        try p.putUnit(@intCast(0xDC00 + (v & 0x3FF)));
    }
};

/// U+FFFD REPLACEMENT CHARACTER, UTF-8 encoded (`EF BF BD`).
const replacement = "\u{fffd}";

/// Bytes `writeStringContents` may copy into the output untouched: printable
/// ASCII and DEL (`0x20-0x7F`) except `"` and `\` (and `<`, `>`, `&` when
/// `html_safe`). Everything else needs a decision — an escape below 0x20, or a
/// UTF-8 scan at or above 0x80.
fn verbatimTable(comptime opts: StringOptions) [256]bool {
    var t: [256]bool = @splat(false);
    for (0x20..0x80) |c| t[c] = true;
    t['"'] = false;
    t['\\'] = false;
    if (opts.html_safe) {
        t['<'] = false;
        t['>'] = false;
        t['&'] = false;
    }
    return t;
}

/// Decode one well-formed sequence (`utf8Step` already said so).
fn decodeScalar(seq: []const u8) u21 {
    return switch (seq.len) {
        2 => (@as(u21, seq[0] & 0x1F) << 6) | (seq[1] & 0x3F),
        3 => (@as(u21, seq[0] & 0x0F) << 12) | (@as(u21, seq[1] & 0x3F) << 6) | (seq[2] & 0x3F),
        else => (@as(u21, seq[0] & 0x07) << 18) | (@as(u21, seq[1] & 0x3F) << 12) |
            (@as(u21, seq[2] & 0x3F) << 6) | (seq[3] & 0x3F),
    };
}

/// One step of a UTF-8 scan. `len` is never zero, so a loop over
/// `utf8Step` always terminates.
const Utf8Step = struct {
    /// Number of bytes this step covers.
    len: usize,
    /// True when those bytes are exactly one well-formed UTF-8 sequence;
    /// false when they are a maximal ill-formed subsequence.
    ok: bool,
};

/// Classify the sequence starting at `s[0]` (`s` must be non-empty) against
/// Unicode 16.0 Table 3-7 (*Well-Formed UTF-8 Byte Sequences*) — the same
/// table that rejects surrogates (`ED A0..BF`), overlongs (`C0`/`C1`, `E0
/// 80..9F`, `F0 80..8F`) and anything above U+10FFFF (`F4 90..BF`, `F5..FF`).
///
/// On failure `len` is the **maximal subpart**: the longest prefix of `s` that
/// is still a prefix of some well-formed sequence, or 1 when even the first
/// byte cannot start one. That is Unicode 16.0 §3.9's "U+FFFD Substitution
/// of Maximal Subparts" recommendation. Running off the end of `s` (a truncated
/// sequence) is a failure with `len` equal to the bytes actually present, which
/// is the same rule.
fn utf8Step(s: []const u8) Utf8Step {
    const b0 = s[0];
    if (b0 < 0x80) return .{ .len = 1, .ok = true };

    // Every non-ASCII lead byte fixes the total length AND the allowed range
    // of the SECOND byte; bytes three and four are always 80..BF. Encoding
    // that second-byte range here is the whole of Table 3-7 — a plain
    // "80..BF times n" check would accept surrogates and overlongs.
    const total: usize, const b1_min: u8, const b1_max: u8 = switch (b0) {
        0xC2...0xDF => .{ 2, 0x80, 0xBF },
        0xE0 => .{ 3, 0xA0, 0xBF }, // E0 80..9F would be an overlong
        0xE1...0xEC => .{ 3, 0x80, 0xBF },
        0xED => .{ 3, 0x80, 0x9F }, // ED A0..BF is a surrogate, D800..DFFF
        0xEE...0xEF => .{ 3, 0x80, 0xBF },
        0xF0 => .{ 4, 0x90, 0xBF }, // F0 80..8F would be an overlong
        0xF1...0xF3 => .{ 4, 0x80, 0xBF },
        0xF4 => .{ 4, 0x80, 0x8F }, // F4 90..BF is past U+10FFFF
        // 0x80..0xC1 (continuation byte on its own, or a 2-byte overlong
        // lead) and 0xF5..0xFF (past U+10FFFF) can never start a sequence.
        else => return .{ .len = 1, .ok = false },
    };
    if (s.len < 2 or s[1] < b1_min or s[1] > b1_max) return .{ .len = 1, .ok = false };
    if (total == 2) return .{ .len = 2, .ok = true };
    if (s.len < 3 or s[2] < 0x80 or s[2] > 0xBF) return .{ .len = 2, .ok = false };
    if (total == 3) return .{ .len = 3, .ok = true };
    if (s.len < 4 or s[3] < 0x80 or s[3] > 0xBF) return .{ .len = 3, .ok = false };
    return .{ .len = 4, .ok = true };
}

// ── nesting prescan ─────────────────────────────────────────────────────────

/// True when no `[`/`{` in `bytes` nests deeper than `max_depth`. One pass, no
/// allocation, and string-aware: brackets inside a JSON string (including after
/// a `\` escape) are text, not structure, so a payload that merely CONTAINS
/// `"[[[[…"` is not penalised. Meant to run before a parser sees the input,
/// which is the point — rejecting afterwards would already have paid for the
/// allocations.
///
/// What it does **not** do: it does not validate. It does not check that
/// brackets match (`[}` counts as one level and is fine), that a string is
/// terminated, or that the rest is JSON at all. A closer with nothing open
/// saturates at depth 0 instead of going negative, so `]]]]` followed by
/// `[` is depth 1. Input the parser would reject can therefore pass here, and
/// the parser stays responsible for the verdict; a `false` here is always a
/// real nesting of more than `max_depth` open brackets outside strings.
/// `max_depth == 0` accepts only input with no bracket outside a string.
pub fn depthWithin(bytes: []const u8, max_depth: usize) bool {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (bytes) |c| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else switch (c) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '[', '{' => {
                depth += 1;
                if (depth > max_depth) return false;
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
    return true;
}

// ── tests ───────────────────────────────────────────────────────────────────

test {
    _ = @import("fuzz_test.zig");
}

const testing = std.testing;

fn render(buf: []u8, s: []const u8, comptime opts: StringOptions) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try writeStringContents(&w, s, opts);
    return w.buffered();
}

fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a comptime loop (O(n^2) in Sema).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "writeString: quotes, escapes and the C0 controls, exact bytes" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeString(&w, "a\"b\\c/d\x7f", .{});
    try testing.expectEqualStrings("\"a\\\"b\\\\c/d\x7f\"", w.buffered());
    for (0..0x20) |b| {
        const raw = [_]u8{@intCast(b)};
        var want_buf: [6]u8 = undefined;
        const want: []const u8 = switch (b) {
            0x08 => "\\b",
            0x09 => "\\t",
            0x0A => "\\n",
            0x0C => "\\f",
            0x0D => "\\r",
            else => try std.fmt.bufPrint(&want_buf, "\\u{x:0>4}", .{b}),
        };
        try testing.expectEqualStrings(want, try render(&buf, &raw, .{}));
    }
    try testing.expectEqualStrings("", try render(&buf, "", .{}));
}

test "replace: one U+FFFD per MAXIMAL SUBPART, exact bytes" {
    const R = replacement;
    const cases = [_]struct { in: []const u8, want: []const u8, why: []const u8 }{
        // A truncated but otherwise valid prefix is ONE subpart. Per byte (Go's
        // encoding/json) would give two here and three below.
        .{ .in = "\xe2\x82", .want = R, .why = "truncated 3-byte lead of U+20AC" },
        .{ .in = "\xf0\x9f\x98", .want = R, .why = "truncated 4-byte lead of U+1F600" },
        .{ .in = "\xc3", .want = R, .why = "truncated 2-byte lead" },
        .{ .in = "\xf0\x9f", .want = R, .why = "4-byte lead truncated after two" },
        // ED A0 is not a prefix of anything well-formed, so ED is alone.
        .{ .in = "\xed\xa0\x80", .want = R ++ R ++ R, .why = "U+D800 high surrogate" },
        .{ .in = "\xed\xbf\xbf", .want = R ++ R ++ R, .why = "U+DFFF low surrogate" },
        .{ .in = "\xed\xa0\xbd\xed\xb8\x80", .want = strRepeat(R, 6), .why = "CESU-8 surrogate pair" },
        .{ .in = "\xc0\xaf", .want = R ++ R, .why = "overlong '/' (C0 AF)" },
        .{ .in = "\xc1\xbf", .want = R ++ R, .why = "overlong U+007F" },
        .{ .in = "\xe0\x80\xaf", .want = strRepeat(R, 3), .why = "3-byte overlong '/'" },
        .{ .in = "\xf0\x80\x80\xaf", .want = strRepeat(R, 4), .why = "4-byte overlong '/'" },
        .{ .in = "\xf4\x90\x80\x80", .want = strRepeat(R, 4), .why = "U+110000" },
        .{ .in = "\xf5\x80\x80\x80", .want = strRepeat(R, 4), .why = "F5: no such lead byte" },
        .{ .in = "\xff", .want = R, .why = "FF: never appears in UTF-8" },
        .{ .in = "\xfe\xfe\xff\xff", .want = strRepeat(R, 4), .why = "a BOM-ish byte run" },
        .{ .in = "\x80", .want = R, .why = "lone continuation" },
        .{ .in = "\x80\xbf\x80", .want = strRepeat(R, 3), .why = "run of continuations" },
        .{ .in = "curl\xffbad", .want = "curl" ++ R ++ "bad", .why = "bad byte between letters" },
        .{ .in = "a\xe2\x82b", .want = "a" ++ R ++ "b", .why = "truncated lead between letters" },
        .{ .in = "\xe2\x82\xac\xff\xe2\x82\xac", .want = "\u{20ac}" ++ R ++ "\u{20ac}", .why = "bad byte between two euros" },
        // Well-formed input is untouched at every length and Table 3-7 boundary.
        .{ .in = "curl/8.0", .want = "curl/8.0", .why = "ASCII" },
        .{ .in = "\xc2\x80", .want = "\u{0080}", .why = "shortest 2-byte" },
        .{ .in = "\xdf\xbf", .want = "\u{07ff}", .why = "longest 2-byte" },
        .{ .in = "\xe0\xa0\x80", .want = "\u{0800}", .why = "shortest 3-byte" },
        .{ .in = "\xed\x9f\xbf", .want = "\u{d7ff}", .why = "last before the surrogates" },
        .{ .in = "\xee\x80\x80", .want = "\u{e000}", .why = "first after the surrogates" },
        .{ .in = "\xef\xbf\xbf", .want = "\u{ffff}", .why = "longest 3-byte" },
        .{ .in = "\xf0\x90\x80\x80", .want = "\u{10000}", .why = "shortest 4-byte" },
        .{ .in = "\xf4\x8f\xbf\xbf", .want = "\u{10ffff}", .why = "the last code point" },
        .{ .in = R, .want = R, .why = "a U+FFFD the caller sent is not touched" },
    };
    var buf: [64]u8 = undefined;
    for (cases) |c| {
        const got = try render(&buf, c.in, .{});
        testing.expectEqualStrings(c.want, got) catch |err| {
            std.debug.print("case: {s}\n", .{c.why});
            return err;
        };
    }
}

test "escape_bytes: ill-formed bytes as \\u00XX, well-formed text untouched" {
    var buf: [64]u8 = undefined;
    const o: StringOptions = .{ .invalid_utf8 = .escape_bytes };
    try testing.expectEqualStrings("a\\u00ffb", try render(&buf, "a\xffb", o));
    // A truncated sequence: both bytes escaped, the euro after it kept.
    try testing.expectEqualStrings("\\u00e2\\u0082\u{20ac}", try render(&buf, "\xe2\x82\xe2\x82\xac", o));
    try testing.expectEqualStrings("\\u00ed\\u00a0\\u0080", try render(&buf, "\xed\xa0\x80", o));
    try testing.expectEqualStrings("caf\u{e9}", try render(&buf, "caf\u{e9}", o));
}

test "reject: error.InvalidUtf8 on the first ill-formed sequence, nothing after it written" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidUtf8, writeString(&w, "ab\xffcd", .{ .invalid_utf8 = .reject }));
    try testing.expectEqualStrings("\"ab", w.buffered()); // the prefix before the bad byte is written, nothing after it
    var w2: std.Io.Writer = .fixed(&buf);
    try writeString(&w2, "ok \u{1f600}", .{ .invalid_utf8 = .reject });
    try testing.expectEqualStrings("\"ok \u{1f600}\"", w2.buffered());
}

test "ascii_only: \\uXXXX with surrogate pairs; values checked against CPython json.dumps(ensure_ascii=True)" {
    var buf: [64]u8 = undefined;
    const o: StringOptions = .{ .ascii_only = true };
    // CPython 3: json.dumps("€") == '"\\u20ac"', "😀" == '"\\ud83d\\ude00"', "café" == '"caf\\u00e9"'.
    try testing.expectEqualStrings("\\u20ac", try render(&buf, "\u{20ac}", o));
    try testing.expectEqualStrings("\\ud83d\\ude00", try render(&buf, "\u{1f600}", o));
    try testing.expectEqualStrings("caf\\u00e9", try render(&buf, "caf\u{e9}", o));
    try testing.expectEqualStrings("\\udbff\\udfff", try render(&buf, "\u{10ffff}", o));
    try testing.expectEqualStrings("\\u0080\\u07ff\\u0800\\uffff", try render(&buf, "\u{80}\u{7ff}\u{800}\u{ffff}", o));
    // Ill-formed input still gets its policy, the replacement written as an escape.
    try testing.expectEqualStrings("a\\ufffdb", try render(&buf, "a\xffb", o));
    try testing.expectEqualStrings("a\\u00ffb", try render(&buf, "a\xffb", .{ .ascii_only = true, .invalid_utf8 = .escape_bytes }));
    // DEL stays as is (Go); CPython would escape it. Documented in SPEC.
    try testing.expectEqualStrings("\x7f", try render(&buf, "\x7f", o));
}

test "html_safe: < > & U+2028 U+2029 escaped; everything else as before" {
    var buf: [96]u8 = undefined;
    const o: StringOptions = .{ .html_safe = true };
    try testing.expectEqualStrings("\\u003cscript\\u003e a \\u0026 b \\u003c/script\\u003e", try render(&buf, "<script> a & b </script>", o));
    try testing.expectEqualStrings("x\\u2028y\\u2029z", try render(&buf, "x\u{2028}y\u{2029}z", o));
    // U+2027 and U+202A neighbour the pair and are not touched.
    try testing.expectEqualStrings("\u{2027}\u{202a}\u{e9}", try render(&buf, "\u{2027}\u{202a}\u{e9}", o));
    // Without the option they pass.
    try testing.expectEqualStrings("<&>\u{2028}", try render(&buf, "<&>\u{2028}", .{}));
    // Combined with ascii_only the line separators come out as the same escapes.
    try testing.expectEqualStrings("\\u2028\\u003c", try render(&buf, "\u{2028}<", .{ .html_safe = true, .ascii_only = true }));
    // Truncated E2 80 does not read past the end.
    try testing.expectEqualStrings("\u{fffd}", try render(&buf, "\xe2\x80", o));
}

fn expectRoundTrip(s: []const u8, comptime opts: StringOptions) !void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeString(&w, s, opts);
    const out = w.buffered();
    if (opts.ascii_only) for (out) |b| try testing.expect(b < 0x80);
    if (opts.html_safe) for (out) |b| try testing.expect(b != '<' and b != '>' and b != '&');
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(s, parsed.value.string);
}

test "every option combination round-trips well-formed text through std.json" {
    const samples = [_][]const u8{
        "",                                        "plain", "q\"b\\s/ \x01\x1f\x7f", "\u{80}\u{7ff}\u{800}\u{d7ff}\u{e000}\u{fffd}\u{ffff}\u{10000}\u{10ffff}",
        "<a href=\"x\">&amp;</a>\u{2028}\u{2029}",
    };
    inline for ([_]bool{ false, true }) |ascii| inline for ([_]bool{ false, true }) |html| inline for (.{ .replace, .escape_bytes, .reject }) |pol| {
        const o: StringOptions = .{ .ascii_only = ascii, .html_safe = html, .invalid_utf8 = pol };
        for (samples) |s| try expectRoundTrip(s, o);
    };
}

test "ill-formed input always yields a parseable document (replace, escape_bytes)" {
    const vectors = [_][]const u8{
        "\xff",                "\x80",                 "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82", "\xf0\x9f\x98",
        "\xff\"\r\n{\"a\":1}", "\x80\x80\x80\x80\x80",
    };
    var buf: [256]u8 = undefined;
    inline for (.{ InvalidUtf8.replace, InvalidUtf8.escape_bytes }) |pol| {
        for (vectors) |v| {
            var w: std.Io.Writer = .fixed(&buf);
            try writeString(&w, v, .{ .invalid_utf8 = pol });
            var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, w.buffered(), .{});
            defer parsed.deinit();
            try testing.expect(std.unicode.utf8ValidateSlice(parsed.value.string));
        }
    }
}

test "utf8Step: well-formedness agrees with std.unicode over an exhaustive byte sweep" {
    // An independent oracle for the classification half of the policy: std's
    // validator over every 1- and 2-byte string and every 3-/4-byte string built
    // from the boundary bytes that Table 3-7 actually splits on.
    const tails = [_]u8{ 0x00, 0x7F, 0x80, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF };
    var b0: usize = 0;
    while (b0 < 0x100) : (b0 += 1) {
        var b1: usize = 0;
        while (b1 < 0x100) : (b1 += 1) {
            for (tails) |t2| for (tails) |t3| {
                const s = [_]u8{ @intCast(b0), @intCast(b1), t2, t3 };
                for (1..5) |n| {
                    const step = utf8Step(s[0..n]);
                    try testing.expect(step.len >= 1 and step.len <= n);
                    if (step.ok) {
                        try testing.expect(std.unicode.utf8ValidateSlice(s[0..step.len]));
                        try testing.expectEqual(step.len, try std.unicode.utf8ByteSequenceLength(s[0]));
                    } else {
                        var n2 = step.len;
                        while (n2 <= n) : (n2 += 1) {
                            try testing.expect(!std.unicode.utf8ValidateSlice(s[0..n2]));
                        }
                    }
                }
            };
        }
    }
}

test "utf8Step: the maximal subpart is a prefix of something well-formed, brute-forced" {
    // The subpart LENGTH is the half `utf8ValidateSlice` cannot check. A reported
    // ill-formed length L is maximal iff `s[0..L]` can still be completed into a
    // well-formed sequence (or L == 1) and `s[0..L+1]` cannot — brute-forced
    // over the 64 continuation bytes, so the expected value comes from std.
    const S = struct {
        fn completable(prefix: []const u8) bool {
            const want = std.unicode.utf8ByteSequenceLength(prefix[0]) catch return false;
            if (prefix.len > want) return false;
            if (prefix.len == want) return std.unicode.utf8ValidateSlice(prefix);
            var buf: [4]u8 = undefined;
            @memcpy(buf[0..prefix.len], prefix);
            const missing = want - prefix.len;
            var c: usize = 0;
            while (c < (@as(usize, 1) << @intCast(6 * missing))) : (c += 1) {
                for (0..missing) |k| {
                    buf[prefix.len + k] = 0x80 | @as(u8, @intCast((c >> @intCast(6 * k)) & 0x3F));
                }
                if (std.unicode.utf8ValidateSlice(buf[0..want])) return true;
            }
            return false;
        }
    };
    const inputs = [_][]const u8{
        "\xe2\x82",         "\xe2\x82\x28", "\xf0\x9f\x98", "\xf0\x9f",
        "\xc3",             "\xed\xa0\x80", "\xe0\x80\xaf", "\xf0\x80\x80\xaf",
        "\xf4\x90\x80\x80", "\xc0\xaf",     "\x80\xbf",     "\xff\xfe",
        "\xe0\xa0",         "\xed\x9f",     "\xf4\x8f\xbf", "\xf1\x80\x80",
    };
    for (inputs) |s| {
        const step = utf8Step(s);
        if (step.ok) continue;
        try testing.expect(step.len >= 1);
        if (step.len > 1) try testing.expect(S.completable(s[0..step.len]));
        if (step.len < s.len) try testing.expect(!S.completable(s[0 .. step.len + 1]));
    }
}

test "decodeScalar agrees with std.unicode over EVERY Unicode scalar value" {
    // Exhaustive: the function is only ever called on well-formed sequences, so
    // this covers its whole domain (and pins the masks/shifts, which a boundary
    // sample cannot: several of them are redundant on some lead bytes).
    var cp: u21 = 0x80;
    while (cp <= 0x10FFFF) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        var b: [4]u8 = undefined;
        const n = try std.unicode.utf8Encode(cp, &b);
        try testing.expectEqual(cp, decodeScalar(b[0..n]));
    }
}

test "escapes beyond one pending block and long runs around them keep their order" {
    // 100 controls = 600 output bytes through a 256-byte block; a 70-byte run
    // (written straight through) between and after escapes; every size of run.
    var buf: [4096]u8 = undefined;
    var want: [4096]u8 = undefined;
    var ctrl: [100]u8 = undefined;
    @memset(&ctrl, 0x01);
    try testing.expectEqualStrings(strRepeat("\\u0001", 100), try render(&buf, &ctrl, .{}));
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    var exp: std.ArrayList(u8) = .empty;
    defer exp.deinit(testing.allocator);
    for ([_]usize{ 0, 1, 5, 63, 64, 65, 70, 200, 300 }) |run_len| {
        in.clearRetainingCapacity();
        exp.clearRetainingCapacity();
        for (0..7) |k| {
            for (0..run_len) |_| {
                try in.append(testing.allocator, 'a' + @as(u8, @intCast(k)));
                try exp.append(testing.allocator, 'a' + @as(u8, @intCast(k)));
            }
            for (0..(k + 1) * 3) |_| {
                try in.appendSlice(testing.allocator, "\n\x02");
                try exp.appendSlice(testing.allocator, "\\n\\u0002");
            }
        }
        const got = try render(&buf, in.items, .{});
        @memcpy(want[0..exp.items.len], exp.items);
        try testing.expectEqualStrings(want[0..exp.items.len], got);
    }
}

test "depthWithin: strings are text, closers saturate, the cap is inclusive" {
    try testing.expect(depthWithin("{\"a\":\"\\\"" ++ strRepeat("[", 200) ++ "\"}", 8));
    try testing.expect(!depthWithin("{\"a\":" ++ strRepeat("[", 200), 8));
    try testing.expect(depthWithin(strRepeat("[]", 1000), 2));
    try testing.expect(depthWithin(strRepeat("]", 100) ++ "[", 1));
    try testing.expect(depthWithin("[[[]]]", 3));
    try testing.expect(!depthWithin("[[[]]]", 2));
    try testing.expect(depthWithin("", 0));
    try testing.expect(depthWithin("1 \"[[\"", 0));
    try testing.expect(!depthWithin("[", 0));
    // Not a validator: mismatched and unterminated input is accepted.
    try testing.expect(depthWithin("[}", 1));
    try testing.expect(depthWithin("\"unterminated [[[[", 0));
}

test "depthWithin: braces count like brackets, a string ends after an escape, closers decrement" {
    try testing.expect(depthWithin("{{{}}}", 3));
    try testing.expect(!depthWithin("{{{}}}", 2));
    try testing.expect(!depthWithin("{{{", 2));
    try testing.expect(!depthWithin("{\"a\":[{\"b\":[1]}]}", 3));
    try testing.expect(depthWithin("{\"a\":[{\"b\":[1]}]}", 4));
    try testing.expect(depthWithin("{}{}{}{}", 1));
    try testing.expect(!depthWithin("{}{}{}{}{", 0));
    // A closer lowers the depth by exactly one: 2,1,2,3.
    try testing.expect(!depthWithin("[[][[", 2));
    try testing.expect(depthWithin("[[][", 2));
    try testing.expect(!depthWithin("{{}{{", 2));
    try testing.expect(depthWithin("[}{}[", 2));
    // The string that follows an escape ends at its closing quote; the next brackets count.
    try testing.expect(!depthWithin("\"\\n\"[[[", 2));
    try testing.expect(!depthWithin("\"a\\\\\"[[[", 2)); // "a\\" ends: the backslash pair is one escape
    try testing.expect(depthWithin("\"\\\"[[[\"", 0)); // ...but \" keeps the string open
    // The escape flag is cleared after one byte, and is not set outside a string.
    try testing.expect(depthWithin("\\\"[[[", 0)); // backslash outside a string is plain text; the quote opens one
    try testing.expect(!depthWithin("\\[[[", 2));
}

// ── frozen foreign vectors ──────────────────────────────────────────────────
// `testdata/vectors.txt` (CPython json: default, ascii_only; own columns marked
// in tools/gen_vectors.py) and `testdata/vectors_go.txt` (Go encoding/json,
// html_safe) are produced by `tools/gen_vectors.py` and `tools/go_vectors`, not
// by this module; the tests only replay them.

const vectors_py = @embedFile("testdata/vectors.txt");
const vectors_go = @embedFile("testdata/vectors_go.txt");

fn unhex(a: std.mem.Allocator, h: []const u8) ![]u8 {
    if (std.mem.eql(u8, h, "-")) return a.alloc(u8, 0);
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// Run `s` through every policy x option for one column check.
fn expectColumn(a: std.mem.Allocator, s: []const u8, want_hex: []const u8, comptime opts: StringOptions) !void {
    if (std.mem.eql(u8, want_hex, "-")) return;
    const want = try unhex(a, want_hex);
    defer a.free(want);
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    try writeString(&aw.writer, s, opts);
    try testing.expectEqualStrings(want, aw.written());
}

test "vectors: replay of the frozen CPython (d, a) / own (ah, e, ea, eh, eah) / Go (h) rows" {
    const a = testing.allocator;
    var rows: usize = 0;
    var go_lines = std.mem.tokenizeScalar(u8, vectors_go, '\n');
    var lines = std.mem.tokenizeScalar(u8, vectors_py, '\n');
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var go_line = go_lines.next().?;
        while (go_line[0] == '#') go_line = go_lines.next().?;
        var f = std.mem.splitScalar(u8, line, '\t');
        const in_hex = f.next().?;
        const valid = std.mem.eql(u8, f.next().?, "1");
        const d, const asc, const ah, const e, const ea, const eh, const eah = .{
            f.next().?, f.next().?, f.next().?, f.next().?, f.next().?, f.next().?, f.next().?,
        };
        try testing.expect(f.next() == null);
        var gf = std.mem.splitScalar(u8, go_line, '\t');
        try testing.expectEqualStrings(in_hex, gf.next().?);
        const h = gf.next().?;
        const s = try unhex(a, in_hex);
        defer a.free(s);
        try expectColumn(a, s, d, .{});
        try expectColumn(a, s, asc, .{ .ascii_only = true });
        try expectColumn(a, s, h, .{ .html_safe = true });
        try expectColumn(a, s, ah, .{ .ascii_only = true, .html_safe = true });
        try expectColumn(a, s, e, .{ .invalid_utf8 = .escape_bytes });
        try expectColumn(a, s, ea, .{ .invalid_utf8 = .escape_bytes, .ascii_only = true });
        try expectColumn(a, s, eh, .{ .invalid_utf8 = .escape_bytes, .html_safe = true });
        try expectColumn(a, s, eah, .{ .invalid_utf8 = .escape_bytes, .ascii_only = true, .html_safe = true });
        // reject: the same bytes as `replace`/`escape_bytes` when well-formed, an error otherwise.
        inline for ([_]StringOptions{
            .{ .invalid_utf8 = .reject },
            .{ .invalid_utf8 = .reject, .ascii_only = true },
            .{ .invalid_utf8 = .reject, .html_safe = true },
            .{ .invalid_utf8 = .reject, .ascii_only = true, .html_safe = true },
        }) |o| {
            var aw: std.Io.Writer.Allocating = .init(a);
            defer aw.deinit();
            if (valid) {
                try writeString(&aw.writer, s, o);
                var aw2: std.Io.Writer.Allocating = .init(a);
                defer aw2.deinit();
                try writeString(&aw2.writer, s, .{ .ascii_only = o.ascii_only, .html_safe = o.html_safe });
                try testing.expectEqualStrings(aw2.written(), aw.written());
            } else {
                try testing.expectError(error.InvalidUtf8, writeString(&aw.writer, s, o));
            }
        }
        rows += 1;
    }
    try testing.expect(go_lines.next() == null);
    try testing.expect(rows >= 1000);
}
