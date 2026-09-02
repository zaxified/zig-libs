// SPDX-License-Identifier: MIT
//! json5 — single-pass JSON5→JSON preprocessor (comments, unquoted keys,
//! trailing commas, single-quote strings) + a source-location annotated variant.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Single-pass JSON5→JSON preprocessor (comments, unquoted keys, trailing commas, single-quoted strings).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "JSON5 spec (json5.org) preprocessor to std.json",
    .deps = .{},
};

/// Preprocess JSON5 source and return a new slice owned by alloc.
pub fn preprocess(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    const prefix = try diagnosticPrefix(alloc, input, "$err_trace_");
    defer alloc.free(prefix);
    var lines: LineCounter = .{};
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    // nest tracks the current container context ("{" or "[") per depth level.
    // This is needed to set key_pos correctly after a comma: inside an object
    // the next token is a key; inside an array it's a value.
    var nest: std.ArrayList(u8) = .empty; // '{' or '[' per nesting level
    defer nest.deinit(alloc);
    var key_pos = false; // true when next identifier is an object key
    var err_counter: u32 = 0;
    var i: usize = 0;

    while (i < input.len) {
        const c = input[i];

        // ── double-quoted string — copy verbatim ────────────────────────────
        if (c == '"') {
            key_pos = false;
            try out.append(alloc, c);
            i += 1;
            while (i < input.len) {
                const sc = input[i];
                try out.append(alloc, sc);
                i += 1;
                if (sc == '\\' and i < input.len) {
                    try out.append(alloc, input[i]);
                    i += 1;
                } else if (sc == '"') break;
            }
            continue;
        }

        // ── single-quoted string — convert to double-quoted ─────────────────
        if (c == '\'') {
            key_pos = false;
            try out.append(alloc, '"');
            i += 1;
            while (i < input.len) {
                const sc = input[i];
                i += 1;
                if (sc == '\\' and i < input.len) {
                    const esc = input[i];
                    i += 1;
                    if (esc == '\'') {
                        try out.append(alloc, '\''); // \' → ' (unescape)
                    } else {
                        try out.append(alloc, '\\');
                        try out.append(alloc, esc);
                    }
                } else if (sc == '"') {
                    try out.appendSlice(alloc, "\\\""); // escape " inside
                } else if (sc == '\'') {
                    break;
                } else {
                    try out.append(alloc, sc);
                }
            }
            try out.append(alloc, '"');
            continue;
        }

        // ── comments ────────────────────────────────────────────────────────
        if (c == '/' and i + 1 < input.len) {
            if (input[i + 1] == '/') { // single-line
                i += 2;
                // Line terminator is '\n' OR bare '\r' (old Mac-style line
                // endings, no LF at all) -- stopping at '\n' only meant a
                // bare-CR file had no line terminator anywhere for this loop
                // to find, so it silently consumed the rest of the input
                // (including any closing braces) as "comment". Found by the
                // json5-tests corpus: new-lines/comment-cr.json5.
                while (i < input.len and input[i] != '\n' and input[i] != '\r') i += 1;
                continue;
            }
            if (input[i + 1] == '*') { // multi-line
                const comment_start = i;
                i += 2;
                var closed = false;
                while (i + 1 < input.len) {
                    if (input[i] == '*' and input[i + 1] == '/') {
                        i += 2;
                        closed = true;
                        break;
                    }
                    i += 1;
                }
                if (!closed) {
                    // Ran off the end of input without finding the closing
                    // `*/`. Silently stripping to EOF here would make an
                    // unterminated block comment vanish -- turning
                    // otherwise-invalid input into something that
                    // (accidentally) parses. Instead, copy the unterminated
                    // comment's bytes through verbatim so std.json sees the
                    // stray `/*` and rejects downstream, matching the
                    // json5-tests corpus: comments/unterminated-block-comment.txt
                    // is a must-reject case the old silent-swallow accepted.
                    try out.appendSlice(alloc, input[comment_start..input.len]);
                    i = input.len;
                    continue;
                }
                // See the annotated entry point: a comment separates tokens.
                // `[1/*c*/2]` became `[12]`, turning a must-reject input into
                // a valid document with a fabricated value
                // (W2 re-audit 2026-09-02, `json5` F6).
                try out.append(alloc, ' ');
                continue;
            }
        }

        // ── structural tokens ────────────────────────────────────────────────
        switch (c) {
            '{' => {
                try nest.append(alloc, '{');
                key_pos = true;
                try out.append(alloc, c);
                i += 1;
            },
            '}' => {
                _ = nest.pop();
                key_pos = false;
                removeTrailingComma(&out);
                try out.append(alloc, c);
                i += 1;
            },
            '[' => {
                try nest.append(alloc, '[');
                key_pos = false;
                try out.append(alloc, c);
                i += 1;
            },
            ']' => {
                _ = nest.pop();
                key_pos = false;
                removeTrailingComma(&out);
                try out.append(alloc, c);
                i += 1;
            },
            ':' => {
                key_pos = false;
                try out.append(alloc, c);
                i += 1;
            },
            ',' => {
                // after a comma inside an object, the next token is a key
                key_pos = nest.items.len > 0 and nest.items[nest.items.len - 1] == '{';
                try out.append(alloc, c);
                i += 1;
            },
            // ── unquoted identifier in key position ─────────────────────────
            else => {
                if (key_pos and (std.ascii.isAlphabetic(c) or c == '_' or c == '$')) {
                    const key_start = i;
                    while (i < input.len) {
                        const kc = input[i];
                        if (!std.ascii.isAlphanumeric(kc) and kc != '_' and kc != '$') break;
                        i += 1;
                    }
                    // Peek ahead past whitespace to find ':'. Only horizontal
                    // whitespace here — a newline terminates the unquoted key
                    // identifier in the simple preprocessor (annotated variant
                    // handles newlines inside keys separately).
                    var j = i;
                    while (j < input.len and (input[j] == ' ' or input[j] == '\t')) : (j += 1) {}
                    if (j >= input.len or input[j] == ':') {
                        // Normal path: output quoted key
                        try out.append(alloc, '"');
                        try out.appendSlice(alloc, input[key_start..i]);
                        try out.append(alloc, '"');
                        key_pos = false;
                    } else {
                        // Error recovery: junk before ':' (e.g. space inside unquoted key).
                        // We scan forward to find the colon, grab the raw value that follows,
                        // and emit a synthetic $err_trace_N entry so the GUI can surface the
                        // problem without crashing the JSON parser. The key+value pair is
                        // consumed entirely so parsing continues from the next comma or '}'.
                        // Was `while (input[colon] != ':') colon += 1` — unbounded
                        // to EOF. Two consequences: a tail with no `:` scanned the
                        // whole remaining input for every malformed key (a second
                        // O(n²) on top of the one in `lineOf`), and a `:` further
                        // on absorbed everything up to it, commas and later keys
                        // included — `{a b: "x'y", c: 2}` swallowed `c` and lost
                        // the closing brace. The annotated entry point already had
                        // the bounded, string-aware scan; this one never got it
                        // (W2 re-audit 2026-09-02, `json5` F4).
                        const colon = findKeyColon(input, j);
                        const err_line = lines.at(input, key_start);
                        err_counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"{s}{d}\": ", .{ prefix, err_counter });
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        if (colon >= input.len or input[colon] != ':') {
                            // Malformed: unquoted key with no ':' before the end
                            // of this entry — end of input, or the next `,`/`}`/`]`
                            // (e.g. "{a b"). Consume to the next delimiter so we never
                            // slice past the buffer; mirrors preprocessAnnotated's has_colon guard.
                            const skip_end = skipValue(input, j);
                            const after = trimForMessage(input[key_start..skip_end]);
                            const msg = try std.fmt.allocPrint(alloc, "{s} --> missing colon after key at line {d}", .{
                                after, err_line,
                            });
                            defer alloc.free(msg);
                            try appendJsonStr(&out, alloc, msg);
                            i = skip_end;
                        } else {
                            const raw_key = trimForMessage(input[key_start..colon]);
                            var vs = colon + 1;
                            while (vs < input.len and (input[vs] == ' ' or input[vs] == '\t')) : (vs += 1) {}
                            const val_end = skipValue(input, vs);
                            // The value was already capped; the KEY and the
                            // no-colon tail were not, so a 200 KB key made a
                            // 200 KB "compact" message (F10). All three now go
                            // through `trimForMessage`.
                            const raw_val = trimForMessage(input[vs..val_end]);
                            const msg = try std.fmt.allocPrint(alloc, "{s}: '{s}' --> malformed key at line {d}", .{
                                raw_key, raw_val, err_line,
                            });
                            defer alloc.free(msg);
                            try appendJsonStr(&out, alloc, msg);
                            i = val_end;
                        }
                        key_pos = false;
                    }
                } else {
                    // See the annotated entry point: a byte that cannot start
                    // a key, copied out with `key_pos` still true, lands ahead
                    // of the `"$err_trace_…":` that follows it and breaks the
                    // document (W2 re-audit 2026-09-02, `json5` F7).
                    if (key_pos and c != '}' and c != ']' and !isWs(c)) {
                        const bad_start = i;
                        const colon = findKeyColon(input, i);
                        const has_colon = colon < input.len and input[colon] == ':';
                        const line = lines.at(input, bad_start);
                        const skip_from = if (has_colon) colon + 1 else bad_start;
                        const val_end = skipValue(input, skip_from);
                        const raw = trimForMessage(input[bad_start..val_end]);
                        err_counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"{s}{d}\": ", .{ prefix, err_counter });
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        const msg = try std.fmt.allocPrint(alloc, "'{s}' --> key is not an identifier this module accepts, at line {d}", .{ raw, line });
                        defer alloc.free(msg);
                        try appendJsonStr(&out, alloc, msg);
                        i = val_end;
                        key_pos = false;
                        continue;
                    }
                    try out.append(alloc, c);
                    i += 1;
                }
            },
        }
    }

    return out.toOwnedSlice(alloc);
}

/// Scan backwards in `out` and remove the last comma if it is only followed
/// by whitespace.  Called just before writing } or ].
///
/// Shrinking items.len directly (without a realloc) is intentional: the
/// capacity stays allocated and will be reused for the closing bracket that
/// follows immediately. The backing memory is not poisoned so this is safe
/// with any allocator.
fn removeTrailingComma(out: *std.ArrayList(u8)) void {
    var j = out.items.len;
    while (j > 0) {
        j -= 1;
        switch (out.items[j]) {
            ' ', '\t', '\n', '\r' => {},
            ',' => {
                // A comma preceded (skipping whitespace) by nothing but an
                // opening bracket or another comma is a LONE or LEADING
                // comma ("[,]", "{,}", "[1,,]"), not a legitimate trailing
                // comma after a real element. Leave it in place so the
                // surrounding structure stays invalid JSON and std.json
                // rejects it downstream, instead of silently eliding it into
                // a valid (and wrong) empty/short container. Found by the
                // json5-tests corpus: arrays/lone-trailing-comma-array.js and
                // objects/lone-trailing-comma-object.txt are must-reject
                // cases the old unconditional strip accepted as `[]`/`{}`.
                var k = j;
                const has_value_before = while (k > 0) {
                    k -= 1;
                    switch (out.items[k]) {
                        ' ', '\t', '\n', '\r' => continue,
                        '{', '[', ',' => break false,
                        else => break true,
                    }
                } else false;
                if (!has_value_before) return;
                out.items.len = j;
                return;
            },
            else => return,
        }
    }
}

/// Return the 1-based line number of position `pos` in `input`.
/// One numeric literal, starting at `start`, as the end index just past it.
/// Deliberately permissive — hex (`0x1f`), a leading or trailing dot, and an
/// exponent with a sign are all JSON5, and anything this accepts that JSON
/// does not is handed to `std.json` to reject. What matters is that the whole
/// literal is consumed as ONE token, so no part of it is later mistaken for
/// something else.
fn scanNumber(input: []const u8, start: usize) usize {
    var i = start;
    if (i < input.len and (input[i] == '+' or input[i] == '-')) i += 1;
    if (i + 1 < input.len and input[i] == '0' and (input[i + 1] == 'x' or input[i + 1] == 'X')) {
        i += 2;
        while (i < input.len and std.ascii.isHex(input[i])) : (i += 1) {}
        return i;
    }
    while (i < input.len and (std.ascii.isDigit(input[i]) or input[i] == '.')) : (i += 1) {}
    if (i < input.len and (input[i] == 'e' or input[i] == 'E')) {
        var j = i + 1;
        if (j < input.len and (input[j] == '+' or input[j] == '-')) j += 1;
        // Only an exponent with at least one digit is part of the number; a
        // bare `e` is a bare identifier and must stay one.
        if (j < input.len and std.ascii.isDigit(input[j])) {
            i = j;
            while (i < input.len and std.ascii.isDigit(input[i])) : (i += 1) {}
        }
    }
    // A lone sign or dot is not a number; leave it to the byte-copy path
    // rather than consuming nothing and spinning.
    return if (i == start) start + 1 else i;
}

/// The `:` that terminates a malformed key, starting the search at `from`.
/// Stops at the next `,` / `}` / `]` rather than running to end of input, and
/// steps over string literals (honouring `\\` escapes) so a colon or a comma
/// inside one cannot be mistaken for structure. Returns an index at which
/// `input[i] == ':'`, or an index that is not a colon when there is none.
/// Trim a raw source fragment for use inside a diagnostic message, and cap
/// it. The value was already capped at 30 characters "so the error message
/// stays compact in the GUI"; the raw key and the no-colon tail were not, so a
/// 200 KB key produced a 200 KB "compact" message
/// (W2 re-audit 2026-09-02, `json5` F10).
pub const message_fragment_max = 30;

fn trimForMessage(raw: []const u8) []const u8 {
    const t = std.mem.trim(u8, raw, " \t\r\n");
    return if (t.len > message_fragment_max) t[0..message_fragment_max] else t;
}

/// A diagnostic key prefix that provably does not occur in `input`.
///
/// Diagnostics are injected as ordinary object keys with fixed, predictable
/// names and a counter that starts at 1, and the input was never consulted.
/// Under `.use_last` — JS `JSON.parse` semantics, and what this module's own
/// corpus harness uses — a colliding key in the INPUT wins over the injected
/// one, so `{x y: 1, "$err_trace_1": "all fine"}` reported "all fine" and hid
/// the real error; under `std.json`'s default the same input turns any
/// recovered error into `error.DuplicateField`. Either way the caller is
/// misled (W2 re-audit 2026-09-02, `json5` F9).
///
/// The guarantee is by construction, not by hope: find the longest run of `_`
/// that follows `base` anywhere in the input, and use one more.
fn diagnosticPrefix(alloc: std.mem.Allocator, input: []const u8, comptime base: []const u8) ![]u8 {
    var extra: usize = 0;
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, input, at, base)) |found| : (at = found + 1) {
        var k: usize = found + base.len;
        while (k < input.len and input[k] == '_') : (k += 1) {}
        // One more underscore than the longest run that already follows the
        // base anywhere in the input. Absent from the input entirely, the
        // base is used unchanged — the common case pays nothing.
        const need = (k - (found + base.len)) + 1;
        if (need > extra) extra = need;
    }
    const out = try alloc.alloc(u8, base.len + extra);
    @memcpy(out[0..base.len], base);
    @memset(out[base.len..], '_');
    return out;
}

fn findKeyColon(input: []const u8, from: usize) usize {
    var colon = from;
    while (colon < input.len) : (colon += 1) {
        const ch = input[colon];
        if (ch == ':') break;
        if (ch == ',' or ch == '}' or ch == ']') break;
        if (ch == '"' or ch == '\'') {
            const qc = ch;
            colon += 1;
            while (colon < input.len) : (colon += 1) {
                if (input[colon] == '\\' and colon + 1 < input.len) {
                    colon += 1;
                    continue;
                }
                if (input[colon] == qc) break;
            }
        }
    }
    return colon;
}

/// Test-only: total bytes any line lookup has walked. The complexity claim in
/// `LineCounter`'s doc is asserted against this rather than against a clock —
/// a wall-clock ratio in the Debug lane is drowned by allocator noise, and a
/// timing test that cannot tell the fixed code from the broken code is not a
/// test (W2 re-audit 2026-09-02, `json5` F3).
pub var line_scan_bytes: usize = 0;

fn lineOf(input: []const u8, pos: usize) usize {
    const end = @min(pos, input.len);
    if (@import("builtin").is_test) line_scan_bytes += end;
    var line: usize = 1;
    for (input[0..end]) |ch| {
        if (ch == '\n') line += 1;
    }
    return line;
}

/// A forward-only line counter for the recovery paths.
///
/// `lineOf` rescans from byte 0, and both entry points call it once per
/// recovered error, so *n* errors cost O(n²): 1 MB of `{a b,a b,…}` took two
/// minutes where a well-formed file of the same size took 11 ms. The call
/// sites are monotonically increasing, so remembering where the last one
/// stopped makes the whole walk linear; a backwards query (there are none
/// today) still gets the right answer, just at the old price
/// (W2 re-audit 2026-09-02, `json5` F3).
const LineCounter = struct {
    pos: usize = 0,
    line: usize = 1,

    fn at(self: *LineCounter, input: []const u8, pos: usize) usize {
        const p = @min(pos, input.len);
        if (p < self.pos) return lineOf(input, p);
        if (@import("builtin").is_test) line_scan_bytes += p - self.pos;
        for (input[self.pos..p]) |ch| {
            if (ch == '\n') self.line += 1;
        }
        self.pos = p;
        return self.line;
    }
};

/// Skip one JSON5 value starting at `start`. Returns the index of the first
/// delimiter character after the value (`,` `}` `]`) without consuming it.
///
/// Used only during error recovery: when a malformed key is detected we need
/// to skip its associated value so that the remaining sibling keys can still
/// be parsed. The function is intentionally lenient — it doesn't validate the
/// value, just finds its end boundary. Nested objects/arrays are tracked via
/// `depth` so that a comma inside `{a: {b: 1, c: 2}}` doesn't stop too early.
fn skipValue(input: []const u8, start: usize) usize {
    var i = start;
    var depth: i32 = 0;
    // The quote that OPENED the current string, not merely "in a string".
    // Treating `'` and `"` as interchangeable meant an apostrophe inside a
    // double-quoted value closed it and the next `"` re-opened one, so the
    // scan ran past every delimiter to EOF: `{a b: "don't", c: 2, d: 3}` lost
    // the keys `c` and `d` into a diagnostic string. An apostrophe in English
    // prose is the trigger (W2 re-audit 2026-09-02, `json5` F5).
    var quote: ?u8 = null;
    while (i < input.len) : (i += 1) {
        const ch = input[i];
        if (quote) |q| {
            if (ch == '\\') {
                i += 1;
                continue;
            }
            if (ch == q) quote = null;
        } else switch (ch) {
            '"', '\'' => quote = ch,
            '{', '[' => depth += 1,
            '}', ']' => {
                if (depth == 0) return i;
                depth -= 1;
            },
            ',' => if (depth == 0) return i,
            else => {},
        }
    }
    // Clamp: a trailing backslash inside a string advances `i` TWICE -- once
    // here for the escaped byte and once more by the loop's `: (i += 1)`,
    // which `continue` also runs -- so `i` can leave the loop at `len + 1`.
    // Every caller slices `input[..this]`, so returning it read out of bounds
    // (found by the fuzzer on `{a"\`, and the guard's own comment claimed
    // "we never slice past the buffer"). The contract is an index INTO input.
    return @min(i, input.len);
}

test "skipValue never returns an index past the end of the input" {
    // Regression, found by the fuzzer as four separate out-of-bounds panics in
    // `preprocess` and `preprocessAnnotated`, all with the same signature:
    // index == len + 1. A trailing backslash inside a string advanced `i`
    // twice -- once for the escaped byte, once by the loop's `: (i += 1)`,
    // which `continue` also runs -- and every caller slices `input[..this]`.
    //
    // Asserted on the CONTRACT rather than on one caller, because the callers
    // are five separate slice sites and a per-caller clamp would have to be
    // right five times.
    const cases = [_][]const u8{
        "\\",
        "\"\\",
        "{a\"\\",
        "[\'\\",
        "{a: \"x\\",
    };
    for (cases) |c| {
        try std.testing.expect(skipValue(c, 0) <= c.len);
        try std.testing.expect(skipValue(c, c.len) <= c.len);
    }
}

/// Append `s` as a JSON-escaped double-quoted string to `out`.
fn appendJsonStr(out: *std.ArrayList(u8), alloc: std.mem.Allocator, s: []const u8) !void {
    try out.append(alloc, '"');
    for (s) |ch| switch (ch) {
        '"' => try out.appendSlice(alloc, "\\\""),
        '\\' => try out.appendSlice(alloc, "\\\\"),
        '\n' => try out.appendSlice(alloc, "\\n"),
        '\r' => try out.appendSlice(alloc, "\\r"),
        '\t' => try out.appendSlice(alloc, "\\t"),
        else => try out.append(alloc, ch),
    };
    try out.append(alloc, '"');
}

// ── annotated variant: silently strips comments, injects $err_<N> markers ─

pub const AnnotatedResult = struct {
    out: []u8,
    next_id: u32, // first unused id; the caller continues numbering from here
};

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

fn whitespaceKind(slice: []const u8) []const u8 {
    var has_nl = false;
    var has_tab = false;
    for (slice) |ch| {
        if (ch == '\n' or ch == '\r') has_nl = true;
        if (ch == '\t') has_tab = true;
    }
    if (has_nl) return "newline";
    if (has_tab) return "tab";
    return "whitespace";
}

/// True iff the next entry appended to `out` needs a leading comma — i.e.
/// `out` ends with a value rather than with `{`, `[`, `,`, or `:` (after
/// trailing whitespace).
fn needsLeadingComma(out: []const u8) bool {
    var k = out.len;
    while (k > 0) {
        k -= 1;
        const ch = out[k];
        if (ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r') continue;
        if (ch == '{' or ch == '[' or ch == ',' or ch == ':') return false;
        return true;
    }
    return false;
}

/// Errors discovered after a value has already been emitted (unterminated
/// strings, invalid bare-identifier literals). Flushed as `, "$err_<N>": "..."`
/// sibling entries before the next `,` or `}` in the parent object. Only
/// produced when nest top is `{` — array contents recover silently in v1.
fn flushValueErrs(
    out: *std.ArrayList(u8),
    alloc: std.mem.Allocator,
    errs: *std.ArrayList([]u8),
    counter: *u32,
    prefix: []const u8,
) !void {
    for (errs.items) |msg| {
        try out.appendSlice(alloc, ", ");
        counter.* += 1;
        const head = try std.fmt.allocPrint(alloc, "\"{s}{d}\": ", .{ prefix, counter.* });
        defer alloc.free(head);
        try out.appendSlice(alloc, head);
        try appendJsonStr(out, alloc, msg);
        alloc.free(msg);
    }
    errs.clearRetainingCapacity();
}

fn dropValueErrs(alloc: std.mem.Allocator, errs: *std.ArrayList([]u8)) void {
    for (errs.items) |m| alloc.free(m);
    errs.clearRetainingCapacity();
}

fn isInObject(nest: []const u8) bool {
    return nest.len > 0 and nest[nest.len - 1] == '{';
}

/// Like preprocess, but emits recovered syntax errors as `$err_<N>` entries.
/// Comments are stripped silently. The result is valid JSON with any
/// recovered-error diagnostics surfaced as sibling `$err_<N>` string entries.
///
/// AUDIT-OK: this is the most intricate state machine in the module — many
/// interacting recovery branches (unterminated string, missing colon, missing
/// comma, invalid literal, EOF auto-close). Not a bug, but a prime regression
/// site: gate any change here behind the existing recovery unit tests, not
/// just the happy path.
pub fn preprocessAnnotated(alloc: std.mem.Allocator, input: []const u8) !AnnotatedResult {
    const prefix = try diagnosticPrefix(alloc, input, "$err_");
    defer alloc.free(prefix);
    var lines: LineCounter = .{};
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(alloc);
    // pending_value_errs accumulates error strings discovered while emitting a
    // value (unterminated strings, invalid bare literals). They cannot be
    // flushed immediately because they must appear as sibling entries *after*
    // the value they describe — the JSON key has already been emitted. They are
    // flushed at the next ',' or '}' boundary. Errors inside arrays are dropped
    // because inserting $err_* inside a JSON array would break its structure.
    var pending_value_errs: std.ArrayList([]u8) = .empty;
    defer {
        for (pending_value_errs.items) |m| alloc.free(m);
        pending_value_errs.deinit(alloc);
    }
    // counter is the shared $err_<N> sequence. It is returned as next_id so
    // the caller can continue numbering without collisions.
    var counter: u32 = 0;
    var key_pos = false;
    var i: usize = 0;

    while (i < input.len) {
        const c = input[i];

        // ── double-quoted string ─────────────────────────────────────────
        if (c == '"') {
            key_pos = false;
            const str_start = i;
            try out.append(alloc, c);
            i += 1;
            var closed = false;
            while (i < input.len) {
                const sc = input[i];
                if (sc == '\n' or sc == '\r') {
                    // Recovery needs somewhere to put its diagnostic, and a
                    // `$err_<N>` can only be a sibling key inside an object.
                    // Outside one this branch closed the string, dropped the
                    // rest, and reported NOTHING: the must-reject fixture
                    // `"foo\nbar"` became the document `"foo"`, valid and
                    // silently truncated, while `preprocess` rejected it.
                    // With nowhere to report, the honest move is not to
                    // recover (W2 re-audit 2026-09-02, `json5` F2).
                    if (!isInObject(nest.items)) {
                        try out.append(alloc, sc);
                        i += 1;
                        continue;
                    }
                    try out.append(alloc, '"');
                    closed = true;
                    const msg = try std.fmt.allocPrint(alloc, "unterminated string at line {d}", .{lines.at(input, str_start)});
                    try pending_value_errs.append(alloc, msg);
                    i = skipValue(input, i);
                    break;
                }
                try out.append(alloc, sc);
                i += 1;
                if (sc == '\\' and i < input.len) {
                    try out.append(alloc, input[i]);
                    i += 1;
                } else if (sc == '"') {
                    closed = true;
                    break;
                }
            }
            if (!closed) {
                try out.append(alloc, '"');
                if (isInObject(nest.items)) {
                    const msg = try std.fmt.allocPrint(alloc, "unterminated string at end of input (line {d})", .{lines.at(input, str_start)});
                    try pending_value_errs.append(alloc, msg);
                }
            }
            continue;
        }

        // ── single-quoted string ─────────────────────────────────────────
        if (c == '\'') {
            key_pos = false;
            const str_start = i;
            try out.append(alloc, '"');
            i += 1;
            var closed = false;
            while (i < input.len) {
                const sc = input[i];
                if (sc == '\n' or sc == '\r') {
                    try out.append(alloc, '"');
                    closed = true;
                    if (isInObject(nest.items)) {
                        const msg = try std.fmt.allocPrint(alloc, "unterminated string at line {d}", .{lines.at(input, str_start)});
                        try pending_value_errs.append(alloc, msg);
                    }
                    i = skipValue(input, i);
                    break;
                }
                i += 1;
                if (sc == '\\' and i < input.len) {
                    const esc = input[i];
                    i += 1;
                    if (esc == '\'') {
                        try out.append(alloc, '\'');
                    } else {
                        try out.append(alloc, '\\');
                        try out.append(alloc, esc);
                    }
                } else if (sc == '"') {
                    try out.appendSlice(alloc, "\\\"");
                } else if (sc == '\'') {
                    closed = true;
                    try out.append(alloc, '"');
                    break;
                } else {
                    try out.append(alloc, sc);
                }
            }
            if (!closed) {
                try out.append(alloc, '"');
                if (isInObject(nest.items)) {
                    const msg = try std.fmt.allocPrint(alloc, "unterminated string at end of input (line {d})", .{lines.at(input, str_start)});
                    try pending_value_errs.append(alloc, msg);
                }
            }
            continue;
        }

        // ── comments → strip silently ─────────────────────────────────────
        if (c == '/' and i + 1 < input.len) {
            if (input[i + 1] == '/') {
                i += 2;
                // See preprocess()'s identical fix: bare '\r' is also a line
                // terminator (old Mac-style line endings), not just '\n'.
                while (i < input.len and input[i] != '\n' and input[i] != '\r') i += 1;
                continue;
            }
            if (input[i + 1] == '*') {
                const comment_start = i;
                var closed = false;
                i += 2;
                while (i + 1 < input.len) {
                    if (input[i] == '*' and input[i + 1] == '/') {
                        i += 2;
                        closed = true;
                        break;
                    }
                    i += 1;
                }
                if (!closed) {
                    // `preprocess` got this fix from the corpus; this entry
                    // point never did, and it had a second bug on top: the
                    // inner loop exits at `input.len - 1`, so the comment's
                    // LAST BYTE was reprocessed as ordinary input —
                    // `{a: 1 /*cZ` came out as `{"a": 1 "Z", "$err_1": …}`,
                    // and `[1,2/* junk]` had the `]` inside the comment close
                    // the array and parse clean. Copy the unterminated
                    // comment through so `std.json` rejects it, the way the
                    // must-reject fixture expects
                    // (W2 re-audit 2026-09-02, `json5` F8).
                    try out.appendSlice(alloc, input[comment_start..input.len]);
                    i = input.len;
                    continue;
                }
                // A comment is a token SEPARATOR, not nothing: deleting its
                // bytes made the tokens on either side adjacent, so
                // `[1/*c*/2]` became `[12]` — a must-reject input turned into
                // a valid document with a fabricated value, which is worse
                // than a rejection (W2 re-audit 2026-09-02, `json5` F6).
                try out.append(alloc, ' ');
                continue;
            }
        }

        // ── structural tokens ────────────────────────────────────────────
        switch (c) {
            '{' => {
                try nest.append(alloc, '{');
                key_pos = true;
                try out.append(alloc, c);
                i += 1;
            },
            '}' => {
                try flushValueErrs(&out, alloc, &pending_value_errs, &counter, prefix);
                _ = nest.pop();
                key_pos = false;
                removeTrailingComma(&out);
                try out.append(alloc, c);
                i += 1;
            },
            '[' => {
                try nest.append(alloc, '[');
                key_pos = false;
                try out.append(alloc, c);
                i += 1;
            },
            ']' => {
                dropValueErrs(alloc, &pending_value_errs);
                _ = nest.pop();
                key_pos = false;
                removeTrailingComma(&out);
                try out.append(alloc, c);
                i += 1;
            },
            ':' => {
                key_pos = false;
                try out.append(alloc, c);
                i += 1;
            },
            ',' => {
                try flushValueErrs(&out, alloc, &pending_value_errs, &counter, prefix);
                key_pos = nest.items.len > 0 and nest.items[nest.items.len - 1] == '{';
                try out.append(alloc, c);
                i += 1;
            },
            else => {
                if (key_pos and (std.ascii.isAlphabetic(c) or c == '_' or c == '$')) {
                    const key_start = i;
                    while (i < input.len) {
                        const kc = input[i];
                        if (!std.ascii.isAlphanumeric(kc) and kc != '_' and kc != '$') break;
                        i += 1;
                    }
                    // Peek past ALL whitespace incl. \n/\r — catches keys
                    // split by a newline (`file_type_o\n  ut: ...`).
                    var j = i;
                    while (j < input.len and isWs(input[j])) : (j += 1) {}
                    if (j >= input.len or input[j] == ':') {
                        try out.append(alloc, '"');
                        try out.appendSlice(alloc, input[key_start..i]);
                        try out.append(alloc, '"');
                        key_pos = false;
                    } else {
                        const colon = findKeyColon(input, j);
                        const has_colon = colon < input.len and input[colon] == ':';
                        const err_line = lines.at(input, key_start);
                        counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"{s}{d}\": ", .{ prefix, counter });
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        if (!has_colon) {
                            // Missing colon: skip up to next ',' or '}' so we
                            // don't lose subsequent keys in this object.
                            const skip_end = skipValue(input, j);
                            const after_full = std.mem.trim(u8, input[j..skip_end], " \t\r\n");
                            const after = trimForMessage(after_full);
                            const msg = try std.fmt.allocPrint(alloc, "{s} {s} --> missing colon after key at line {d}", .{
                                input[key_start..i], after, err_line,
                            });
                            defer alloc.free(msg);
                            try appendJsonStr(&out, alloc, msg);
                            i = skip_end;
                        } else {
                            const raw_key = trimForMessage(input[key_start..colon]);
                            var vs = colon + 1;
                            while (vs < input.len and (input[vs] == ' ' or input[vs] == '\t')) : (vs += 1) {}
                            const val_end = skipValue(input, vs);
                            const raw_val = trimForMessage(input[vs..val_end]);
                            const ws_kind = whitespaceKind(input[i..colon]);
                            const msg = try std.fmt.allocPrint(alloc, "{s}: '{s}' --> malformed key ({s} in key) at line {d}", .{
                                raw_key, raw_val, ws_kind, err_line,
                            });
                            defer alloc.free(msg);
                            try appendJsonStr(&out, alloc, msg);
                            i = val_end;
                        }
                        key_pos = false;
                    }
                } else if (!key_pos and (std.ascii.isDigit(c) or c == '+' or c == '-' or c == '.')) {
                    // A NUMERIC LITERAL is one token. Without this branch the
                    // scanner copied the digits through byte by byte and then
                    // met the `e` of an exponent in value position, where the
                    // bare-identifier branch below claimed it: `{"a": 1e10}`
                    // — plain RFC 8259 JSON, not even a JSON5 extension —
                    // came out as `{"a": 1"e10", "$err_1": …}`, which is not
                    // valid JSON at all. Eight must-parse fixtures already
                    // vendored in this repo exercise it, and none of them ran
                    // against this entry point
                    // (W2 re-audit 2026-09-02, `json5` F1).
                    const num_start = i;
                    i = scanNumber(input, i);
                    try out.appendSlice(alloc, input[num_start..i]);
                } else if (!key_pos and std.ascii.isAlphabetic(c)) {
                    // Bare identifier in value position. Two cases:
                    //   (a) Followed by ':' inside an object → the comma between the
                    //       previous entry and this one was omitted. Recovery: emit a
                    //       synthetic $err_<N> describing the problem, then emit the
                    //       identifier as the next key name so parsing continues.
                    //   (b) Otherwise → invalid literal (not true/false/null). Wrap it
                    //       as a string so the JSON stays valid, and queue a pending
                    //       value error that will be emitted as a sibling $err_<N> at
                    //       the next comma or closing brace. true/false/null are valid
                    //       JSON keywords and pass through without an error.
                    const start = i;
                    var jp: usize = i;
                    while (jp < input.len) {
                        const kc = input[jp];
                        if (!std.ascii.isAlphanumeric(kc) and kc != '_') break;
                        jp += 1;
                    }
                    const ident = input[start..jp];

                    var p = jp;
                    while (p < input.len and isWs(input[p])) : (p += 1) {}
                    const looks_like_key = p < input.len and input[p] == ':' and isInObject(nest.items);

                    if (looks_like_key) {
                        // Case (a): flush any pending errors first so they are
                        // associated with the previous value, then inject the separator.
                        try flushValueErrs(&out, alloc, &pending_value_errs, &counter, prefix);
                        if (needsLeadingComma(out.items)) try out.appendSlice(alloc, ", ");
                        const err_line = lines.at(input, start);
                        const msg = try std.fmt.allocPrint(alloc, "missing comma before '{s}' at line {d}", .{ ident, err_line });
                        defer alloc.free(msg);
                        counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"{s}{d}\": ", .{ prefix, counter });
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        try appendJsonStr(&out, alloc, msg);
                        try out.appendSlice(alloc, ", \"");
                        try out.appendSlice(alloc, ident);
                        try out.append(alloc, '"');
                        i = jp;
                        key_pos = false;
                    } else {
                        // Case (b): pass JSON keywords through; wrap anything else.
                        i = jp;
                        if (std.mem.eql(u8, ident, "true") or
                            std.mem.eql(u8, ident, "false") or
                            std.mem.eql(u8, ident, "null") or
                            // `Infinity`/`NaN` are JSON5 NUMBERS this module
                            // defers (README Deferred #3). Wrapping them in
                            // quotes did not defer them — it fabricated the
                            // string "Infinity" where a number belonged, and
                            // made a document parse that `preprocess` (and
                            // the deferred contract) rejects. Pass them
                            // through for `std.json` to refuse, like every
                            // other deferred construct
                            // (W2 re-audit 2026-09-02, `json5` F2).
                            std.mem.eql(u8, ident, "Infinity") or
                            std.mem.eql(u8, ident, "NaN"))
                        {
                            try out.appendSlice(alloc, ident);
                        } else {
                            // Wrap the bare word as a string so the output is valid JSON,
                            // then queue an error to be emitted as a sibling entry.
                            try out.append(alloc, '"');
                            try out.appendSlice(alloc, ident);
                            try out.append(alloc, '"');
                            if (isInObject(nest.items)) {
                                const err_line = lines.at(input, start);
                                const msg = try std.fmt.allocPrint(alloc, "'{s}' --> invalid literal in value position at line {d}", .{
                                    ident, err_line,
                                });
                                try pending_value_errs.append(alloc, msg);
                            }
                        }
                    }
                } else {
                    // A byte this module cannot start a key with, in key
                    // position. Copying it out here — with `key_pos` still
                    // true — put it in the document AHEAD of the `"$err_…":`
                    // the recovery path was about to emit, so `{été: 1}` came
                    // out as `{é"$err_1": …}`: not JSON, and the siblings
                    // after it were lost too. Route it into recovery instead,
                    // which is what every other unspellable key does
                    // (W2 re-audit 2026-09-02, `json5` F7).
                    if (key_pos and c != '}' and c != ']' and !isWs(c)) {
                        const bad_start = i;
                        const colon = findKeyColon(input, i);
                        const has_colon = colon < input.len and input[colon] == ':';
                        const line = lines.at(input, bad_start);
                        const skip_from = if (has_colon) colon + 1 else bad_start;
                        const val_end = skipValue(input, skip_from);
                        const raw = trimForMessage(input[bad_start..val_end]);
                        counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"{s}{d}\": ", .{ prefix, counter });
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        const msg = try std.fmt.allocPrint(alloc, "'{s}' --> key is not an identifier this module accepts, at line {d}", .{ raw, line });
                        defer alloc.free(msg);
                        try appendJsonStr(&out, alloc, msg);
                        i = val_end;
                        key_pos = false;
                        continue;
                    }
                    try out.append(alloc, c);
                    i += 1;
                }
            },
        }
    }

    // EOF recovery: flush any pending $err_<N> entries, then auto-close
    // remaining containers. Without this, an input that ends mid-string
    // or mid-object leaves the queued diagnostic stranded and emits
    // syntactically invalid JSON, losing the per-error context. Errs flush
    // only when the immediate parent is `{` (array siblings would corrupt
    // structure); array contexts drop their queued errs silently, mirroring
    // the in-stream `]` handler.
    if (isInObject(nest.items)) {
        try flushValueErrs(&out, alloc, &pending_value_errs, &counter, prefix);
    } else {
        dropValueErrs(alloc, &pending_value_errs);
    }
    while (nest.items.len > 0) {
        const top = nest.items[nest.items.len - 1];
        removeTrailingComma(&out);
        try out.append(alloc, if (top == '{') @as(u8, '}') else @as(u8, ']'));
        _ = nest.pop();
    }

    return .{ .out = try out.toOwnedSlice(alloc), .next_id = counter + 1 };
}

// ── tests ────────────────────────────────────────────────────────────────────

test "single-line comment" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{ // comment\n\"a\": 1 }");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{ \n\"a\": 1 }", out);
}

test "multi-line comment" {
    const alloc = std.testing.allocator;
    // A comment leaves a SPACE behind, not nothing: two tokens separated only
    // by a comment must not become adjacent (`[1/*c*/2]` -> `[12]`).
    const out = try preprocess(alloc, "{/* hi */\"a\":1}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{ \"a\":1}", out);
}

test "a block comment separates tokens instead of joining them" {
    const alloc = std.testing.allocator;
    // `[1/*c*/2]` used to come out `[12]` — a must-reject input turned into a
    // valid document with a value that is in neither the input nor the spec,
    // which is strictly worse than a rejection
    // (W2 re-audit 2026-09-02, `json5` F6).
    inline for (.{ "[1/*c*/2]", "{a:1/*c*/2}", "{a:1,b:2/*x*/3}" }) |src| {
        inline for (.{ true, false }) |annotated| {
            const out = if (annotated) blk: {
                const r = try preprocessAnnotated(alloc, src);
                break :blk r.out;
            } else try preprocess(alloc, src);
            defer alloc.free(out);
            if (std.json.parseFromSlice(std.json.Value, alloc, out, .{})) |p| {
                p.deinit();
                std.debug.print("\n{s} -> {s} parsed, but the input is not JSON5\n", .{ src, out });
                return error.CommentJoinedTwoTokens;
            } else |_| {}
        }
    }
}

test "unquoted key" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{foo: 1}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"foo\": 1}", out);
}

test "multiple unquoted keys" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{a: 1, b: 2, c: 3}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"a\": 1, \"b\": 2, \"c\": 3}", out);
}

test "nested unquoted keys" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{a: {b: {c: 1}}}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"a\": {\"b\": {\"c\": 1}}}", out);
}

test "trailing comma in object" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{\"a\": 1,}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"a\": 1}", out);
}

test "trailing comma in array" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "[1, 2, 3,]");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("[1, 2, 3]", out);
}

test "single-quoted string" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{'hello'}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"hello\"}", out);
}

test "comment inside string not stripped" {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{\"a\": \"val // not a comment\"}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"a\": \"val // not a comment\"}", out);
}

test "combined: comment + unquoted keys + trailing comma" {
    const alloc = std.testing.allocator;
    const src =
        \\{
        \\  // top comment
        \\  outer: {
        \\    inner: "val", // inline comment
        \\  },
        \\}
    ;
    const out = try preprocess(alloc, src);
    defer alloc.free(out);
    // outer trailing comma removed, inner trailing comma removed
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
}

test "error recovery: space inside unquoted key" {
    const alloc = std.testing.allocator;
    const src =
        \\{file_type_o ut: "csv", other: 1}
    ;
    const out = try preprocess(alloc, src);
    defer alloc.free(out);
    // Output must be valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer parsed.deinit();
    // Bad key replaced with $err_trace
    try std.testing.expect(parsed.value.object.get("$err_trace_1") != null);
    // Keys after the bad one still present
    try std.testing.expect(parsed.value.object.get("other") != null);
}

// ── annotated variant tests ──────────────────────────────────────────────

test "annotated: comments are silently stripped" {
    const alloc = std.testing.allocator;
    const r = try preprocessAnnotated(alloc, "// hi\n{a:1, /* inline */ b: 2\n// tail\n}");
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("a") != null);
    try std.testing.expect(parsed.value.object.get("b") != null);
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        try std.testing.expect(!std.mem.startsWith(u8, kv.key_ptr.*, "$comm_"));
        try std.testing.expect(!std.mem.startsWith(u8, kv.key_ptr.*, "$meta_"));
    }
}

test "annotated: stripped comment + space-in-key produces $err_1" {
    const alloc = std.testing.allocator;
    const src =
        \\{
        \\  // c
        \\  bad key: "v"
        \\}
    ;
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("$err_1") != null);
    try std.testing.expect(r.next_id == 2);
}

test "annotated: newline inside unquoted key" {
    const alloc = std.testing.allocator;
    const src = "{file_type_o\n  ut: \"csv\"}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    const err = parsed.value.object.get("$err_1") orelse return error.Missing;
    try std.testing.expect(std.mem.indexOf(u8, err.string, "newline in key") != null);
}

test "annotated: error message reports the correct line number (mutation guard)" {
    // Regression: lineOf's line count is never checked against a specific
    // number anywhere else in this file -- every other test only greps for
    // a substring like "missing colon" or "invalid literal", so a wrong line
    // number (e.g. lineOf counting '\n' twice) would sail through unnoticed.
    const alloc = std.testing.allocator;
    const src = "{\n  a: 1,\n  bad key: 2\n}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    const err = parsed.value.object.get("$err_1") orelse return error.Missing;
    try std.testing.expect(std.mem.indexOf(u8, err.string, "at line 3") != null);
}

test "annotated: tab inside a malformed key is labeled 'tab', not 'newline' (mutation guard)" {
    // whitespaceKind() has three return paths ("newline", "tab", "whitespace")
    // but no existing test supplies an actual tab byte between a key and its
    // colon, so the "tab" branch was reachable only by inspection, never by
    // an assertion on its output.
    const alloc = std.testing.allocator;
    const src = "{a: 1, bad\tkey: 2}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    const err = parsed.value.object.get("$err_1") orelse return error.Missing;
    try std.testing.expect(std.mem.indexOf(u8, err.string, "tab in key") != null);
}

test "annotated: missing colon after key" {
    const alloc = std.testing.allocator;
    const src = "{foo \"bar\", b: 1}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    const err = parsed.value.object.get("$err_1") orelse return error.Missing;
    try std.testing.expect(std.mem.indexOf(u8, err.string, "missing colon") != null);
    // Subsequent key still parsed — recovery resumes at next ',' / '}'.
    try std.testing.expect(parsed.value.object.get("b") != null);
}

test "annotated: unterminated string with newline" {
    const alloc = std.testing.allocator;
    const src = "{a: \"csv\nb: 1}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    // 'a' value is the closed-at-newline string; an $err_<N> sibling describes
    // the unterminated string. The salvaged tail ('b: 1') is reinterpreted —
    // 'b' becomes an invalid literal, also recorded as $err_<N>.
    try std.testing.expect(parsed.value.object.get("a") != null);
    var found_unterm = false;
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv.key_ptr.*, "$err_")) {
            if (std.mem.indexOf(u8, kv.value_ptr.string, "unterminated string") != null) {
                found_unterm = true;
            }
        }
    }
    try std.testing.expect(found_unterm);
}

test "annotated: unterminated string at EOF" {
    const alloc = std.testing.allocator;
    const src = "{a: \"no closing";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    // EOF recovery: the queued unterminated-string diagnostic flushes as a
    // sibling and the open `{` auto-closes, so the result parses as valid
    // JSON with the $err_<N> preserved.
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    var found = false;
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv.key_ptr.*, "$err_")) {
            if (std.mem.indexOf(u8, kv.value_ptr.string, "unterminated string") != null) {
                found = true;
                break;
            }
        }
    }
    try std.testing.expect(found);
}

test "annotated: invalid literal in value position" {
    const alloc = std.testing.allocator;
    const src = "{a: foo, b: 1}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    // 'foo' wrapped as string value
    const a = parsed.value.object.get("a") orelse return error.Missing;
    try std.testing.expectEqualStrings("foo", a.string);
    // Sibling $err_<N> describes the invalid literal
    var found = false;
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv.key_ptr.*, "$err_")) {
            if (std.mem.indexOf(u8, kv.value_ptr.string, "invalid literal") != null) {
                found = true;
            }
        }
    }
    try std.testing.expect(found);
    try std.testing.expect(parsed.value.object.get("b") != null);
}

test "annotated: missing comma between object entries" {
    const alloc = std.testing.allocator;
    const src = "{a: 1\nb: 2}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("a") != null);
    try std.testing.expect(parsed.value.object.get("b") != null);
    var found = false;
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv.key_ptr.*, "$err_")) {
            if (std.mem.indexOf(u8, kv.value_ptr.string, "missing comma") != null) {
                found = true;
            }
        }
    }
    try std.testing.expect(found);
}

test "annotated: true/false/null preserved as keywords" {
    const alloc = std.testing.allocator;
    const src = "{a: true, b: false, c: null}";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, r.out, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("a").?.bool == true);
    try std.testing.expect(parsed.value.object.get("b").?.bool == false);
    try std.testing.expect(parsed.value.object.get("c").? == .null);
    // No error keys produced.
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        try std.testing.expect(!std.mem.startsWith(u8, kv.key_ptr.*, "$err_"));
    }
}

test "preprocess: unquoted key with no colon before EOF does not slice OOB (audit F1 CRIT)" {
    const alloc = std.testing.allocator;
    // Batch-10 audit CRIT: preprocess("{a b") scanned for ':' to input.len, set
    // vs = colon + 1 = input.len + 1, then sliced input[vs..] past the buffer ->
    // index-out-of-bounds panic. The has_colon guard now consumes the malformed key
    // safely (emitting an $err_trace entry) instead of crashing.
    const out = try preprocess(alloc, "{a b");
    defer alloc.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "$err_trace") != null);
}

// ── fuzz: both preprocessors are the untrusted-input decode surface ─────────
// (arbitrary UTF-8/bytes, not necessarily well-formed JSON5) — must never
// panic or read/write out of bounds, only return a slice or a typed error.

test "fuzz: preprocess never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPreprocess, .{});
}

fn fuzzPreprocess(_: void, smith: *std.testing.Smith) !void {
    const alloc = std.testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const out = preprocess(alloc, buf[0..len]) catch return;
    alloc.free(out);
}

test "fuzz: preprocessAnnotated never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPreprocessAnnotated, .{});
}

fn fuzzPreprocessAnnotated(_: void, smith: *std.testing.Smith) !void {
    const alloc = std.testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];
    const r = preprocessAnnotated(alloc, input) catch return;
    defer alloc.free(r.out);

    // The ORACLE, which this target did not have: "does not panic" is
    // `preprocess`'s contract, not this one's. What a caller relies on here
    // is that turning diagnostics on does not change whether the document
    // parses — the two entry points must agree. Asserting "the output is
    // always valid JSON" instead would be asserting something untrue and
    // untrueable: empty input, and every JSON5 construct this module defers,
    // are passed through for `std.json` to reject on purpose
    // (W2 re-audit 2026-09-02, `json5` F2).
    const plain = preprocess(alloc, input) catch return;
    defer alloc.free(plain);
    const ann_ok = jsonParses(alloc, r.out);
    const plain_ok = jsonParses(alloc, plain);
    if (ann_ok != plain_ok) {
        std.debug.print(
            "\nentry points disagree on {f}\n  preprocess ({}): {f}\n  annotated  ({}): {f}\n",
            .{
                std.ascii.hexEscape(input, .lower),
                plain_ok,
                std.ascii.hexEscape(plain, .lower),
                ann_ok,
                std.ascii.hexEscape(r.out, .lower),
            },
        );
        return error.EntryPointsDisagree;
    }
}

fn jsonParses(alloc: std.mem.Allocator, text: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, text, .{
        .duplicate_field_behavior = .use_last,
    }) catch return false;
    parsed.deinit();
    return true;
}

// ── external anchor: json5/json5-tests corpus ───────────────────────────────
// See json5_tests_test.zig / json5_tests_vectors.zig / NOTICE.
test {
    _ = @import("json5_tests_vectors.zig");
    _ = @import("json5_tests_test.zig");
}

test "annotated: an exponent is part of the number, not a bare identifier" {
    const gpa = std.testing.allocator;
    // `1e10` is plain RFC 8259 JSON, not even a JSON5 extension. The
    // bare-identifier branch fired on the `e` because it is alphabetic and
    // the scanner had no idea it was inside a numeric literal, so the number
    // was split, quoted, and a bogus diagnostic queued — and the result was
    // not valid JSON at all (W2 re-audit 2026-09-02, `json5` F1).
    const cases = [_][]const u8{
        "{\"a\": 1e10}",
        "{a: 1.5e-3}",
        "{a: 2E7}",
        "[1e10]",
        "{a: 1.2e3, b: 2e-23}",
        "[0e0, -0E+0, 1e+2]",
    };
    for (cases) |src| {
        const r = try preprocessAnnotated(gpa, src);
        defer gpa.free(r.out);
        const parsed = std.json.parseFromSlice(std.json.Value, gpa, r.out, .{
            .duplicate_field_behavior = .use_last,
        }) catch |e| {
            std.debug.print("\nannotated({s}) -> {s} : {s}\n", .{ src, r.out, @errorName(e) });
            return error.AnnotatedEmittedInvalidJson;
        };
        parsed.deinit();
        if (std.mem.indexOf(u8, r.out, "$err") != null) {
            std.debug.print("\nannotated({s}) -> {s}\n", .{ src, r.out });
            return error.DiagnosedAValidNumber;
        }
    }
}

test "a malformed file costs work proportional to its size, not to its square" {
    const gpa = std.testing.allocator;
    // `lineOf` rescanned from byte 0 for every recovered error, and
    // `preprocess`'s colon scan ran to EOF for every malformed key: 1 MB of
    // `{a b,a b,…}` took 123 s through `preprocess` and 61 s through
    // `preprocessAnnotated`, against 11 ms for a well-formed file of the same
    // size — a 10 700x ratio on input a GUI accepts from a user
    // (W2 re-audit 2026-09-02, `json5` F3/F4).
    //
    // Asserted on WORK, not on a clock: `line_scan_bytes` counts every byte
    // any line lookup walks, so "linear" is a statement about this input and
    // not about this machine. A wall-clock ratio in the Debug lane could not
    // tell the fixed code from the broken code at any size a test may spend —
    // measured, 64 KB of this input gave 5x for 4x the input either way.
    const n = 2000;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    try src.append(gpa, '{');
    for (0..n) |_| try src.appendSlice(gpa, "a b,");
    try src.append(gpa, '}');

    inline for (.{ true, false }) |annotated| {
        line_scan_bytes = 0;
        const out = if (annotated) blk: {
            const r = try preprocessAnnotated(gpa, src.items);
            break :blk r.out;
        } else try preprocess(gpa, src.items);
        gpa.free(out);
        // One forward pass over the input, and nothing more. Quadratic would
        // be about n/2 * len ~= 8 million bytes here; the cap is 2x the input.
        if (line_scan_bytes > src.items.len * 2) {
            std.debug.print(
                "\n{s}: {d} bytes of input, {d} bytes walked counting lines\n",
                .{ if (annotated) "preprocessAnnotated" else "preprocess", src.items.len, line_scan_bytes },
            );
            return error.QuadraticInInputSize;
        }
    }
}

test "a key this module cannot spell does not corrupt the document around it" {
    const gpa = std.testing.allocator;
    // JSON5 unquoted keys are ECMAScript IdentifierName — Unicode letters,
    // `$`, `_`, `\uXXXX`. This module accepts ASCII alphanumerics, `_` and
    // `$` only, which is a documented limitation; what is not acceptable is
    // what happened next. A non-identifier byte in key position fell through
    // to the plain byte-copy path with `key_pos` still true, so it landed in
    // the output BEFORE the recovery machinery emitted its `"$err_…":` — and
    // `{été: 1, b: 2}` came out as `{é"$err_1": "…", "b": 2}`, which is not
    // JSON at all, so the sibling `b` was lost along with it
    // (W2 re-audit 2026-09-02, `json5` F7).
    const cases = [_][]const u8{
        "{\u{e9}t\u{e9}: 1, b: 2}",
        "{a /*c*/: 1, b: 2}",
        "{a\n: 1, b: 2}",
        "{\u{4e2d}\u{6587}: 1}",
    };
    for (cases) |src| {
        inline for (.{ true, false }) |annotated| {
            const out = if (annotated) blk: {
                const r = try preprocessAnnotated(gpa, src);
                break :blk r.out;
            } else try preprocess(gpa, src);
            defer gpa.free(out);
            const parsed = std.json.parseFromSlice(std.json.Value, gpa, out, .{
                .duplicate_field_behavior = .use_last,
            }) catch |e| {
                std.debug.print("\n{s}({s}) -> {s} : {s}\n", .{
                    if (annotated) "annotated" else "preprocess", src, out, @errorName(e),
                });
                return error.EmittedInvalidJson;
            };
            parsed.deinit();
        }
    }
}

test "a diagnostic key cannot be shadowed by one the input chose" {
    const gpa = std.testing.allocator;
    // The `$err` namespace was not reserved against the input: a colliding
    // key with a predictable name and a counter starting at 1 was enough to
    // hide the real diagnostic under `.use_last` (JS `JSON.parse` semantics,
    // and what this module's own corpus harness uses), or to turn any
    // recovered error into `error.DuplicateField` under `std.json`'s default
    // (W2 re-audit 2026-09-02, `json5` F9).
    {
        const src = "{x y: 1, \"$err_trace_1\": \"all fine\"}";
        const out = try preprocess(gpa, src);
        defer gpa.free(out);
        // The default duplicate behaviour is the sharper oracle: a collision
        // is a hard parse failure there, so this parsing at all is the claim.
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, out, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.get("$err_trace_1") != null);
        try std.testing.expectEqualStrings("all fine", parsed.value.object.get("$err_trace_1").?.string);
        // …and the real diagnostic is still there, under a name the input
        // could not have chosen.
        var found_real = false;
        var it = parsed.value.object.iterator();
        while (it.next()) |e| {
            if (std.mem.startsWith(u8, e.key_ptr.*, "$err_trace_") and
                !std.mem.eql(u8, e.key_ptr.*, "$err_trace_1")) found_real = true;
        }
        try std.testing.expect(found_real);
    }
    {
        // Escalation is by construction, not by hope: an input that already
        // uses the escaped name gets one more underscore again.
        const src = "{x y: 1, \"$err_1\": \"a\", \"$err__1\": \"b\", \"$err___1\": \"c\"}";
        const r = try preprocessAnnotated(gpa, src);
        defer gpa.free(r.out);
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, r.out, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.get("$err____1") != null);
    }
}
