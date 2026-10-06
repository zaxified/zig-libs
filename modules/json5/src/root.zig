// SPDX-License-Identifier: MIT
//! json5 — single-pass JSON5→JSON preprocessor (comments, unquoted keys,
//! trailing commas, single-quote strings, hex/`.5`/`5.`/`+1` numbers, string line
//! continuations, JSON5 whitespace; `Infinity`/`NaN` per `Options.non_finite`)
//! + a source-location annotated variant.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Single-pass JSON5→JSON preprocessor (comments, unquoted keys, trailing commas, single-quoted strings, JSON5 numbers, line continuations).",
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

/// What to do with the JSON5 non-finite numbers `Infinity`, `-Infinity`,
/// `+Infinity` and `NaN` (JSON has no such numbers).
pub const NonFinite = enum {
    /// The default. `preprocess` fails with `error.NonFiniteNumber` (and fills
    /// `Options.diagnostic`); `preprocessAnnotated` passes the token through
    /// unchanged so `std.json` rejects it, like every other deferred construct.
    reject,
    /// Rewrite them to the JSON STRINGS `"Infinity"`, `"-Infinity"`, `"NaN"`
    /// (`+Infinity` and `-NaN`/`+NaN` lose their sign). `std.json` decodes a
    /// string into an `f64` field through `std.fmt.parseFloat`, which reads
    /// exactly those, so a typed struct gets the `inf`/`nan` the reference
    /// json5 (JS) produces. Never `null`: that would silently lose the value.
    /// Into a `std.json.Value` or an untyped field they are plain strings.
    quoted,
};

/// Where and why `preprocess` refused a document. Filled only on an error the
/// module itself raises (`NonFiniteNumber`, `HexLiteralTooLarge`).
pub const Diagnostic = struct {
    /// 1-based source line of the offending literal.
    line: usize = 0,
    /// A static, human-readable message; empty until an error sets it.
    message: []const u8 = "",
};

pub const Options = struct {
    non_finite: NonFinite = .reject,
    /// Optional out-parameter for the error's line and message. Not used by
    /// `preprocessAnnotated`, which never fails on the input.
    diagnostic: ?*Diagnostic = null,
};

/// Preprocess JSON5 source and return a new slice owned by alloc.
/// Besides `error.OutOfMemory` it fails with `error.NonFiniteNumber`
/// (`Infinity`/`NaN` under the default `.reject`) and `error.HexLiteralTooLarge`
/// (a hex literal with more than `hex_digits_max` significant digits).
pub fn preprocess(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    return preprocessWithOptions(alloc, input, .{});
}

/// `preprocess` with `Options`.
pub fn preprocessWithOptions(alloc: std.mem.Allocator, input: []const u8, options: Options) ![]u8 {
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
                if (sc == '\\' and i + 1 < input.len) {
                    // JSON5 line continuation: backslash + line terminator
                    // contributes nothing to the string value. JSON has no such
                    // escape, so drop both — and never look at the next byte
                    // as an ordinary escape (`\` + CR + LF is ONE terminator).
                    const lt = lineTerminatorLen(input, i + 1);
                    if (lt > 0) {
                        i += 1 + lt;
                        continue;
                    }
                    i += 1 + try appendEscape(&out, alloc, input, i + 1);
                    continue;
                }
                try appendStringByte(&out, alloc, sc);
                i += 1;
                if (sc == '"') break;
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
                    const lt = lineTerminatorLen(input, i);
                    if (lt > 0) { // line continuation, see the double-quoted branch
                        i += lt;
                        continue;
                    }
                    i += try appendEscape(&out, alloc, input, i); // \' → ' among them
                } else if (sc == '"') {
                    try out.appendSlice(alloc, "\\\""); // escape " inside
                } else if (sc == '\'') {
                    try out.append(alloc, '"'); // the closing quote, only when the input has one
                    break;
                } else {
                    try appendStringByte(&out, alloc, sc);
                }
            }
            // ⛔ The closing `"` used to be appended UNCONDITIONALLY here, so a
            // single-quoted string the input never closed came out CLOSED:
            // `'unterminated` became the valid document `"unterminated"`. A
            // must-reject input turned silently into an accepted one — the same
            // failure the W2 F2 fix removed from `preprocessAnnotated`'s newline
            // branch, in the entry point that fix used as its reference for being
            // correct. The double-quoted branch above never closed an unterminated
            // string, so the two string kinds also disagreed with each other
            // (found 2026-09-07, by the first corpus that ever reached this
            // module's fuzz harnesses).
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
                // json5-tests corpus: new-lines/comment-cr.json5. U+2028/U+2029
                // end it too (JSON5 line terminators).
                while (i < input.len and input[i] != '\n' and input[i] != '\r' and !isLsPs(input, i)) i += 1;
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

        // ── JSON5-only whitespace → one plain space ─────────────────────────
        // Before the key/recovery branches: in key position an unrecognised
        // byte would otherwise be routed into error recovery.
        if (c == 0x0B or c == 0x0C or c >= 0x80) {
            const wl = json5WsLen(input, i);
            if (wl > 0) {
                try out.append(alloc, ' ');
                i += wl;
                continue;
            }
        }

        // ── numeric literal (hex, .5, 5., +1, Infinity, NaN) ────────────────
        // Value position only: `Infinity` as an object KEY is an identifier,
        // and a key never starts with a digit.
        if (!key_pos and (std.ascii.isDigit(c) or c == '+' or c == '-' or c == '.' or c == 'I' or c == 'N')) {
            i = try emitNumber(alloc, &out, input, i, options, true, &lines);
            continue;
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
                if (key_pos and identUnitLen(input, i, true) > 0) {
                    const key_start = i;
                    while (i < input.len) {
                        const n = identUnitLen(input, i, i == key_start);
                        if (n == 0) break;
                        i += n;
                    }
                    // Peek ahead past whitespace to find ':'. ALL JSON5
                    // whitespace, line terminators included (JSON5 §6:
                    // WhiteSpace and LineTerminator may separate any two
                    // tokens), as the annotated entry point does. This used to
                    // skip horizontal space only, so the valid `{a\n: 1}`
                    // went into error recovery (audit 2026-10-04).
                    const j = skipJson5WsAndComments(input, i);
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

    // EOF recovery: auto-close containers the input left open, exactly as
    // `preprocessAnnotated` has always done at its own end.
    //
    // ⛔ This entry point did NOT, and the asymmetry made the two disagree on
    // whether the result parses — the one thing `fuzzPreprocessAnnotated`'s
    // oracle exists to rule out. `preprocess("{a b")` emitted
    // `{"$err_trace_1": "a b --> missing colon after key at line 1"` with no
    // closing brace, so the recovery entry it had just gone to the trouble of
    // building was stranded in a document `std.json` cannot read, while
    // `preprocessAnnotated` on the same input produced valid JSON. `{a b` is
    // this module's OWN audit-F1 crash reproducer, quoted from the test below,
    // and the test only checked that `$err_trace` appears in the output — never
    // that the output parses. The oracle that would have caught it was written
    // during the W2 re-audit (`json5` F2) and had never executed on a single
    // input, because the harness's length draw collapsed to 0 (2026-09-07).
    //
    // ⛔ ...but ONLY when this run already recovered from something. Closing
    // whatever was open regardless turned a merely TRUNCATED document into a
    // complete one with no trace: `{"servers": [{"host": "a"}` came back as
    // the valid `{"servers": [{"host": "a"}]}`, a config cut off mid-write
    // read as one with fewer entries. The reference JSON5 refuses it, and so
    // does `std.json` now that it is left open (the reference JSON5 oracle,
    // 2026-10-05). `preprocessAnnotated` applies the same rule, so the two
    // still agree on whether the result parses.
    if (err_counter > 0) while (nest.items.len > 0) {
        removeTrailingComma(&out);
        try out.append(alloc, if (nest.items[nest.items.len - 1] == '{') @as(u8, '}') else @as(u8, ']'));
        _ = nest.pop();
    };

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

/// The most significant hex digits a `0x…` literal may have (leading zeros do
/// not count): 256 digits = 1024 bits, which is already beyond the largest
/// finite `f64` (2^1024 - 1 needs exactly 256). Bigger is refused rather than
/// converted, so the conversion stays a fixed-size stack computation and a
/// hostile 1 MB literal costs nothing.
pub const hex_digits_max = 256;

/// 16^256 = 2^1024 < 10^309, i.e. 35 limbs of nine decimal digits; one spare.
const hex_limbs_max = 36;

/// Byte length of one IdentifierName unit of an unquoted key at `i` (JSON5
/// §3, ECMAScript 5.1 §7.6), or 0: an ASCII letter, `_` or `$` (a digit too
/// when not `start`), a `\uXXXX` escape (kept as is -- it is a JSON escape
/// too), or one non-ASCII code point that is not JSON5 whitespace or a line
/// terminator. Copied into the quoted key unchanged, all three are valid JSON
/// string content.
///
/// Non-ASCII is NOT checked against Unicode ID_Start/ID_Continue (no tables
/// in this module): a superset -- the reference refuses an emoji key, this
/// module quotes it (SPEC Backlog). Until 2026-10-05 only ASCII was taken,
/// so `{é: 1}`, `{π: 1}`, `{a\u0062: 1}` and keys with ZWNJ/ZWJ or combining
/// marks went into `$err_trace` recovery (the reference JSON5 oracle).
fn identUnitLen(input: []const u8, i: usize, start: bool) usize {
    const c = input[i];
    if (std.ascii.isAlphabetic(c) or c == '_' or c == '$') return 1;
    if (std.ascii.isDigit(c)) return if (start) 0 else 1;
    if (c == '\\') {
        if (i + 6 > input.len or input[i + 1] != 'u') return 0;
        const cp = std.fmt.parseInt(u16, input[i + 2 .. i + 6], 16) catch return 0;
        if (cp < 0x80) {
            const b: u8 = @intCast(cp);
            const ok = std.ascii.isAlphabetic(b) or b == '_' or b == '$' or (!start and std.ascii.isDigit(b));
            return if (ok) 6 else 0;
        }
        // A surrogate half has no character of its own; JSON5 whitespace
        // and line terminators are never identifier parts.
        if (cp >= 0xD800 and cp <= 0xDFFF) return 0;
        if (cp == 0xA0 or cp == 0xFEFF or cp == 0x1680 or (cp >= 0x2000 and cp <= 0x200A) or
            cp == 0x2028 or cp == 0x2029 or cp == 0x202F or cp == 0x205F or cp == 0x3000) return 0;
        return 6;
    }
    if (c < 0x80) return 0;
    if (json5WsLen(input, i) > 0) return 0;
    const n = std.unicode.utf8ByteSequenceLength(c) catch return 0;
    if (i + n > input.len) return 0;
    _ = std.unicode.utf8Decode(input[i..][0..n]) catch return 0;
    return n;
}

fn isIdentByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '$';
}

/// True iff a numeric token that ended at `end` runs on into something that
/// cannot follow a number (`1.2.3`, `0x1.5`, `1abc`). JSON5 forbids an
/// identifier start or digit right after a numeric literal; rewriting the
/// prefix and letting the tail become a SECOND token would join two tokens into
/// a fabricated valid one (`0x1.5` -> `1` + `.5` -> `10.5`), the same failure
/// as a deleted comment gluing `[1/*c*/2]` into `[12]`.
fn numberContinues(input: []const u8, end: usize) bool {
    return end < input.len and (isIdentByte(input[end]) or input[end] == '.');
}

/// Copy a malformed numeric token through verbatim — for `std.json` to reject
/// — extended over the whole junk run after `from`, so no fragment of it is
/// re-scanned as a number of its own. Returns the end index (> `start`).
fn copyMalformedNumber(alloc: std.mem.Allocator, out: *std.ArrayList(u8), input: []const u8, start: usize, from: usize) !usize {
    var e = from;
    while (e < input.len and (isIdentByte(input[e]) or input[e] == '.')) : (e += 1) {}
    try out.appendSlice(alloc, input[start..e]);
    return e;
}

/// `word` (`Infinity` / `NaN`) at `i`, not glued to a longer identifier.
fn wordAt(input: []const u8, i: usize, comptime word: []const u8) bool {
    if (!std.mem.startsWith(u8, input[@min(i, input.len)..], word)) return false;
    return i + word.len >= input.len or !isIdentByte(input[i + word.len]);
}

/// Append `digits` (hex digits, no leading zeros, at most `hex_digits_max`) as
/// an exact decimal integer. Little-endian limbs in base 10^9 on the stack:
/// multiply by 16, add the digit, carry — no allocation, no float rounding.
fn appendHexAsDecimal(alloc: std.mem.Allocator, out: *std.ArrayList(u8), digits: []const u8) !void {
    if (digits.len == 0) return out.append(alloc, '0');
    const base: u64 = 1_000_000_000;
    var limbs: [hex_limbs_max]u32 = undefined;
    limbs[0] = 0;
    var n: usize = 1;
    for (digits) |h| {
        var carry: u64 = std.fmt.charToDigit(h, 16) catch unreachable; // caller scanned isHex
        for (limbs[0..n]) |*l| {
            const v = @as(u64, l.*) * 16 + carry;
            l.* = @intCast(v % base);
            carry = v / base;
        }
        if (carry > 0) {
            limbs[n] = @intCast(carry);
            n += 1;
        }
    }
    var buf: [9]u8 = undefined;
    try out.appendSlice(alloc, std.fmt.bufPrint(&buf, "{d}", .{limbs[n - 1]}) catch unreachable);
    var k = n - 1;
    while (k > 0) {
        k -= 1;
        try out.appendSlice(alloc, std.fmt.bufPrint(&buf, "{d:0>9}", .{limbs[k]}) catch unreachable);
    }
}

/// One JSON5 numeric literal starting at `start` (an optional sign, then a
/// digit, `.`, or `Infinity`/`NaN`), rewritten into JSON and appended to
/// `out`. Returns the end index just past the consumed source. Always
/// consumes at least one byte.
///
/// - `+1` -> `1`; `.5` -> `0.5`; `5.` -> `5`; `5.e2` -> `5e2`; `-.5e3` -> `-0.5e3`
///   (the exponent is copied verbatim, so every already-valid number comes out
///   byte-identical).
/// - `0x1A` / `-0xff` / `0X1a` -> the exact decimal integer, any length up to
///   `hex_digits_max` digits (`std.json` reads a big integer as a number
///   string or a float). More than that is `error.HexLiteralTooLarge` when
///   `strict`, else passed through verbatim.
/// - `Infinity` / `NaN` with an optional sign: per `options.non_finite`.
///   `strict` (`preprocess`) makes `.reject` an error; the annotated entry point
///   is not strict and copies the token through.
/// - Anything else that merely looks numeric (`01`, `1.2.3`, `0x`, `1e`) is
///   copied verbatim, whole, for `std.json` to reject; a leading zero is NOT
///   stripped, so `01` stays invalid exactly as in JSON5.
///
/// Called in value position only, and never from inside a string or comment,
/// so `.5` there is untouched by construction.
fn emitNumber(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
    start: usize,
    options: Options,
    strict: bool,
    lines: *LineCounter,
) !usize {
    var i = start;
    var negative = false;
    if (i < input.len and (input[i] == '+' or input[i] == '-')) {
        negative = input[i] == '-';
        // The `+` is dropped, but it was the only thing between this token
        // and the one before: `1+2` came out `12` and `1.+3` `13` -- two
        // values joined into one, the `[1/*c*/2]` failure again (the
        // reference JSON5 oracle, 2026-10-05). A space keeps them two, and
        // `std.json` refuses them as the reference does.
        if (input[i] == '+' and out.items.len > 0 and isIdentByte(out.items[out.items.len - 1]) and
            i + 1 < input.len and (std.ascii.isDigit(input[i + 1]) or input[i + 1] == '.'))
            try out.append(alloc, ' ');
        i += 1;
    }

    inline for (.{ "Infinity", "NaN" }) |word| {
        if (wordAt(input, i, word)) {
            const end = i + word.len;
            switch (options.non_finite) {
                .quoted => {
                    try out.append(alloc, '"');
                    if (negative and word[0] == 'I') try out.append(alloc, '-');
                    try out.appendSlice(alloc, word);
                    try out.append(alloc, '"');
                },
                .reject => {
                    if (strict) {
                        if (options.diagnostic) |d| d.* = .{
                            .line = lines.at(input, start),
                            .message = "non-finite number (Infinity/NaN) has no JSON form; " ++
                                "pass Options{ .non_finite = .quoted } to accept it as a string",
                        };
                        return error.NonFiniteNumber;
                    }
                    try out.appendSlice(alloc, input[start..end]);
                },
            }
            return end;
        }
    }

    // A lone sign, or a stray `I`/`N` that is no non-finite word: one byte
    // through, so the caller always makes progress and what follows is
    // scanned as itself (`-foo` keeps its bare-identifier handling).
    if (i >= input.len or !(std.ascii.isDigit(input[i]) or input[i] == '.')) {
        try out.append(alloc, input[start]);
        return start + 1;
    }

    if (i + 1 < input.len and input[i] == '0' and (input[i + 1] == 'x' or input[i + 1] == 'X')) {
        var j = i + 2;
        while (j < input.len and std.ascii.isHex(input[j])) : (j += 1) {}
        if (j == i + 2 or numberContinues(input, j)) return copyMalformedNumber(alloc, out, input, start, j);
        var z = i + 2;
        while (z < j and input[z] == '0') : (z += 1) {}
        const digits = input[z..j];
        if (digits.len > hex_digits_max) {
            if (!strict) {
                try out.appendSlice(alloc, input[start..j]);
                return j;
            }
            if (options.diagnostic) |d| d.* = .{
                .line = lines.at(input, start),
                .message = "hexadecimal literal has more than 256 significant digits (beyond any finite f64)",
            };
            return error.HexLiteralTooLarge;
        }
        if (negative) try out.append(alloc, '-');
        try appendHexAsDecimal(alloc, out, digits);
        return j;
    }

    var j = i;
    while (j < input.len and std.ascii.isDigit(input[j])) : (j += 1) {}
    const int = input[i..j];
    var frac: []const u8 = "";
    if (j < input.len and input[j] == '.') {
        j += 1;
        const f0 = j;
        while (j < input.len and std.ascii.isDigit(input[j])) : (j += 1) {}
        frac = input[f0..j];
    }
    var exp: []const u8 = "";
    if (j < input.len and (input[j] == 'e' or input[j] == 'E')) {
        var k = j + 1;
        if (k < input.len and (input[k] == '+' or input[k] == '-')) k += 1;
        // Only an exponent with at least one digit is part of the number; a
        // bare `e` is a bare identifier and must stay one.
        if (k < input.len and std.ascii.isDigit(input[k])) {
            while (k < input.len and std.ascii.isDigit(input[k])) : (k += 1) {}
            exp = input[j..k];
            j = k;
        }
    }
    // `.` alone, `.e5`: no digit anywhere in the mantissa.
    if ((int.len == 0 and frac.len == 0) or numberContinues(input, j)) {
        return copyMalformedNumber(alloc, out, input, start, j);
    }
    if (negative) try out.append(alloc, '-');
    if (int.len == 0) try out.append(alloc, '0') else try out.appendSlice(alloc, int);
    if (frac.len > 0) {
        try out.append(alloc, '.');
        try out.appendSlice(alloc, frac);
    }
    try out.appendSlice(alloc, exp);
    return j;
}

/// Byte length of the JSON5 whitespace character at `i` that is NOT JSON
/// whitespace, or 0: form feed, vertical tab, NBSP U+00A0, U+1680,
/// U+2000..U+200A, U+2028/U+2029 (also line terminators), U+202F, U+205F,
/// U+3000 (the Unicode Zs spaces) and the BOM U+FEFF. Plain space, tab, CR and
/// LF are not here — `std.json` already accepts them.
fn json5WsLen(input: []const u8, i: usize) usize {
    const c = input[i];
    if (c == 0x0B or c == 0x0C) return 1;
    if (c < 0x80) return 0;
    if (c == 0xC2) return if (i + 1 < input.len and input[i + 1] == 0xA0) 2 else 0;
    if (i + 2 >= input.len) return 0;
    const b1 = input[i + 1];
    const b2 = input[i + 2];
    const hit = switch (c) {
        0xE1 => b1 == 0x9A and b2 == 0x80, // U+1680
        0xE2 => (b1 == 0x80 and ((b2 >= 0x80 and b2 <= 0x8A) or b2 == 0xA8 or b2 == 0xA9 or b2 == 0xAF)) or
            (b1 == 0x81 and b2 == 0x9F), // U+2000..200A, 2028, 2029, 202F, 205F
        0xE3 => b1 == 0x80 and b2 == 0x80, // U+3000
        0xEF => b1 == 0xBB and b2 == 0xBF, // U+FEFF
        else => false,
    };
    return if (hit) 3 else 0;
}

/// U+2028 (LINE SEPARATOR) or U+2029 (PARAGRAPH SEPARATOR) at `i`.
fn isLsPs(input: []const u8, i: usize) bool {
    return i + 2 < input.len and input[i] == 0xE2 and input[i + 1] == 0x80 and (input[i + 2] == 0xA8 or input[i + 2] == 0xA9);
}

/// Byte length of the JSON5 line terminator at `i` (LF, CR, CRLF, U+2028,
/// U+2029), or 0. CRLF is ONE terminator.
fn lineTerminatorLen(input: []const u8, i: usize) usize {
    if (i >= input.len) return 0;
    return switch (input[i]) {
        '\n' => 1,
        '\r' => if (i + 1 < input.len and input[i + 1] == '\n') 2 else 1,
        0xE2 => if (isLsPs(input, i)) 3 else 0,
        else => 0,
    };
}

/// First index at or after `from` that is not JSON5 whitespace: space, tab,
/// CR, LF, and the JSON5-only kinds (U+2028/U+2029 among them).
/// `skipJson5Ws`, also past whole `//` and `/* */` comments: JSON5 §6 lets
/// a comment stand wherever whitespace may, so `{a /* c */: 1}` has its colon
/// after the comment. An unterminated `/*` stops the skip at its start (the
/// main loop then refuses it as before). Until 2026-10-05 the key peek
/// stopped at the comment and sent a valid key into `$err_trace` recovery
/// (the reference JSON5 oracle).
fn skipJson5WsAndComments(input: []const u8, from: usize) usize {
    var j = skipJson5Ws(input, from);
    while (j + 1 < input.len and input[j] == '/') {
        if (input[j + 1] == '/') {
            j += 2;
            while (j < input.len and lineTerminatorLen(input, j) == 0) j += 1;
        } else if (input[j + 1] == '*') {
            const end = std.mem.indexOfPos(u8, input, j + 2, "*/") orelse return j;
            j = end + 2;
        } else break;
        j = skipJson5Ws(input, j);
    }
    return j;
}

fn skipJson5Ws(input: []const u8, from: usize) usize {
    var j = from;
    while (j < input.len) {
        const c = input[j];
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
            j += 1;
            continue;
        }
        const w = json5WsLen(input, j);
        if (w == 0) break;
        j += w;
    }
    return j;
}

/// Append one content byte of a JSON5 string to the JSON output. A JSON5
/// string may hold any source character except its own quote, `\` and a line
/// terminator (JSON5 §5 Strings: `JSON5DoubleStringCharacter` /
/// `JSON5SingleStringCharacter`), so a raw TAB or U+0001 is valid content;
/// JSON requires every U+0000..U+001F to be escaped (RFC 8259 §7) and
/// `std.json` refuses them raw. LF and CR pass through raw: inside a string
/// they are not content but an unterminated string, which must stay a
/// rejection (the callers' line-continuation and recovery logic handles them).
fn appendStringByte(out: *std.ArrayList(u8), alloc: std.mem.Allocator, b: u8) !void {
    if (b >= 0x20 or b == '\n' or b == '\r') return out.append(alloc, b);
    switch (b) {
        '\t' => try out.appendSlice(alloc, "\\t"),
        0x08 => try out.appendSlice(alloc, "\\b"),
        0x0C => try out.appendSlice(alloc, "\\f"),
        else => {
            var buf: [6]u8 = undefined;
            try out.appendSlice(alloc, std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{b}) catch unreachable);
        },
    }
}

/// Append the JSON form of the JSON5 escape whose character is `input[at]`
/// (the byte after `\`; never a line terminator: the callers remove those as
/// line continuations first) and return how many bytes of `input` it used.
/// JSON5 §5 takes ECMAScript 5.1's escapes (§7.8.4), a superset of JSON's:
///  - `\b \f \n \r \t \" \\ \/` and `\uXXXX` are JSON already;
///  - `\v` is U+000B, `\0` (no digit after it) U+0000, `\xHH` U+00HH -- written
///    as `\u` escapes; `\'` is `'`;
///  - any other character after `\` is a NonEscapeCharacter: the character
///    itself (`\q` is `q`, `\é` is `é`, `\` + TAB a TAB, written as
///    `appendStringByte` writes it);
///  - `\1`..`\9`, `\0` before a digit and a `\x` without two hex digits are
///    not escapes in JSON5: they are copied as they were, and `std.json`
///    refuses them, as the reference does.
/// Until 2026-10-05 everything but a control character was copied as the two
/// bytes it was, so `\v`, `\0`, `\x41`, `\q`, `\é` and, in a double-quoted
/// string, `\'` made `std.json` refuse a valid document (the reference JSON5
/// oracle, `ref_oracle_test.zig`).
fn appendEscape(out: *std.ArrayList(u8), alloc: std.mem.Allocator, input: []const u8, at: usize) !usize {
    const esc = input[at];
    switch (esc) {
        'b', 'f', 'n', 'r', 't', '"', '\\', '/', 'u', '1'...'9' => {
            try out.append(alloc, '\\');
            try out.append(alloc, esc);
        },
        'v' => try out.appendSlice(alloc, "\\u000b"),
        '\'' => try out.append(alloc, '\''),
        '0' => if (at + 1 < input.len and std.ascii.isDigit(input[at + 1]))
            try out.appendSlice(alloc, "\\0")
        else
            try out.appendSlice(alloc, "\\u0000"),
        'x' => {
            if (at + 2 < input.len and std.ascii.isHex(input[at + 1]) and std.ascii.isHex(input[at + 2])) {
                try out.appendSlice(alloc, "\\u00");
                try out.append(alloc, std.ascii.toLower(input[at + 1]));
                try out.append(alloc, std.ascii.toLower(input[at + 2]));
                return 3;
            }
            try out.appendSlice(alloc, "\\x");
        },
        else => try appendStringByte(out, alloc, esc),
    }
    return 1;
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
/// produced when nest top is `{`; elsewhere nothing is recovered (the document stays refused).
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
    return preprocessAnnotatedWithOptions(alloc, input, .{});
}

/// `preprocessAnnotated` with `Options`. Only `non_finite` matters here:
/// this entry point never fails on the input, so under `.reject` a non-finite
/// number is passed through verbatim (`std.json` then rejects it — recovery
/// must not change whether the document parses) and `diagnostic` stays untouched.
pub fn preprocessAnnotatedWithOptions(alloc: std.mem.Allocator, input: []const u8, options: Options) !AnnotatedResult {
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
    // flushed at the next ',' or '}' boundary. Inside an array there is no
    // sibling key for one, so nothing is recovered there and nothing queued.
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
                if (sc == '\\' and i + 1 < input.len) {
                    const lt = lineTerminatorLen(input, i + 1);
                    if (lt > 0) { // line continuation: see `preprocessWithOptions`
                        i += 1 + lt;
                        continue;
                    }
                }
                i += 1;
                if (sc == '\\' and i < input.len) {
                    i += try appendEscape(&out, alloc, input, i);
                } else {
                    try appendStringByte(&out, alloc, sc);
                }
                if (sc == '"') {
                    closed = true;
                    break;
                }
            }
            if (!closed) {
                // ⛔ The closing quote used to be appended UNCONDITIONALLY, and
                // the `isInObject` guard only covered the diagnostic. Outside an
                // object that turned a must-reject document into a valid one
                // with nothing recorded: `"unterminated` came out as
                // `"unterminated"`, which `std.json` accepts, while `preprocess`
                // on the same input rejects — the two entry points disagreeing
                // on whether the document parses, which is the one thing
                // `fuzzPreprocessAnnotated`'s oracle exists to rule out.
                //
                // This is the identical shape as the newline branch above, and
                // the identical reasoning: with nowhere to put the diagnostic,
                // the honest move is not to recover (W2 re-audit 2026-09-02,
                // `json5` F2 — applied there and missed here; found 2026-09-07
                // by the first corpus that ever reached this harness).
                if (!isInObject(nest.items)) continue;
                try out.append(alloc, '"');
                const msg = try std.fmt.allocPrint(alloc, "unterminated string at end of input (line {d})", .{lines.at(input, str_start)});
                try pending_value_errs.append(alloc, msg);
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
                    // Not recovered outside an object, as in the double-quoted
                    // branch above. ⛔ This branch closed the string anyway and
                    // only guarded the diagnostic, so `'a\nb'` at the top level
                    // or in an array came out VALID with nothing reported --
                    // the reference json5 refuses it (`ref_oracle_test.zig`,
                    // annotated half, 2026-10-06).
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
                i += 1;
                if (sc == '\\' and i < input.len) {
                    const lt = lineTerminatorLen(input, i);
                    if (lt > 0) { // line continuation: see `preprocessWithOptions`
                        i += lt;
                        continue;
                    }
                    i += try appendEscape(&out, alloc, input, i);
                } else if (sc == '"') {
                    try out.appendSlice(alloc, "\\\"");
                } else if (sc == '\'') {
                    closed = true;
                    try out.append(alloc, '"');
                    break;
                } else {
                    try appendStringByte(&out, alloc, sc);
                }
            }
            if (!closed) {
                // ⛔ The closing quote used to be appended UNCONDITIONALLY, and
                // the `isInObject` guard only covered the diagnostic. Outside an
                // object that turned a must-reject document into a valid one
                // with nothing recorded: `"unterminated` came out as
                // `"unterminated"`, which `std.json` accepts, while `preprocess`
                // on the same input rejects — the two entry points disagreeing
                // on whether the document parses, which is the one thing
                // `fuzzPreprocessAnnotated`'s oracle exists to rule out.
                //
                // This is the identical shape as the newline branch above, and
                // the identical reasoning: with nowhere to put the diagnostic,
                // the honest move is not to recover (W2 re-audit 2026-09-02,
                // `json5` F2 — applied there and missed here; found 2026-09-07
                // by the first corpus that ever reached this harness).
                if (!isInObject(nest.items)) continue;
                try out.append(alloc, '"');
                const msg = try std.fmt.allocPrint(alloc, "unterminated string at end of input (line {d})", .{lines.at(input, str_start)});
                try pending_value_errs.append(alloc, msg);
            }
            continue;
        }

        // ── comments → strip silently ─────────────────────────────────────
        if (c == '/' and i + 1 < input.len) {
            if (input[i + 1] == '/') {
                i += 2;
                // See preprocess()'s identical fix: bare '\r' is also a line
                // terminator (old Mac-style line endings), not just '\n'.
                while (i < input.len and input[i] != '\n' and input[i] != '\r' and !isLsPs(input, i)) i += 1;
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

        // ── JSON5-only whitespace → one plain space (see `preprocessWithOptions`)
        if (c == 0x0B or c == 0x0C or c >= 0x80) {
            const wl = json5WsLen(input, i);
            if (wl > 0) {
                try out.append(alloc, ' ');
                i += wl;
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
                if (key_pos and identUnitLen(input, i, true) > 0) {
                    const key_start = i;
                    while (i < input.len) {
                        const n = identUnitLen(input, i, i == key_start);
                        if (n == 0) break;
                        i += n;
                    }
                    // Peek past ALL whitespace incl. \n/\r — catches keys
                    // split by a newline (`file_type_o\n  ut: ...`).
                    const j = skipJson5WsAndComments(input, i);
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
                    //
                    // The literal is also REWRITTEN here (hex, `.5`, `5.`, `+1`,
                    // signed non-finite) by the same helper `preprocess` uses, so
                    // the two entry points cannot disagree on a number.
                    i = try emitNumber(alloc, &out, input, i, options, false, &lines);
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
                        if (options.non_finite == .quoted and
                            (std.mem.eql(u8, ident, "Infinity") or std.mem.eql(u8, ident, "NaN")))
                        {
                            try out.append(alloc, '"');
                            try out.appendSlice(alloc, ident);
                            try out.append(alloc, '"');
                        } else if (std.mem.eql(u8, ident, "true") or
                            std.mem.eql(u8, ident, "false") or
                            std.mem.eql(u8, ident, "null") or
                            // `Infinity`/`NaN` are JSON5 NUMBERS. Under the
                            // default `.reject` they are passed through for
                            // `std.json` to refuse. Wrapping them in quotes
                            // there fabricated the string "Infinity" where a
                            // number belonged, and made a document parse that
                            // `preprocess` rejects (W2 re-audit 2026-09-02,
                            // `json5` F2). Under the explicit opt-in
                            // `.quoted` (above) the string IS the contract.
                            std.mem.eql(u8, ident, "Infinity") or
                            std.mem.eql(u8, ident, "NaN"))
                        {
                            try out.appendSlice(alloc, ident);
                        } else if (!isInObject(nest.items)) {
                            // Nowhere to report it, so not recovered: the word
                            // goes out bare and `std.json` refuses it. ⛔ It was
                            // wrapped as a string here too, so `nul` became the
                            // valid document `"nul"` and `[tru]` the array
                            // `["tru"]`, with no `$err` anywhere -- the reference
                            // json5 refuses both (`ref_oracle_test.zig`, annotated
                            // half, 2026-10-06).
                            try out.appendSlice(alloc, ident);
                        } else {
                            // Wrap the bare word as a string so the output is valid JSON,
                            // then queue an error to be emitted as a sibling entry.
                            try out.append(alloc, '"');
                            try out.appendSlice(alloc, ident);
                            try out.append(alloc, '"');
                            const err_line = lines.at(input, start);
                            const msg = try std.fmt.allocPrint(alloc, "'{s}' --> invalid literal in value position at line {d}", .{
                                ident, err_line,
                            });
                            try pending_value_errs.append(alloc, msg);
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
    // Only after a recovery, as in `preprocessWithOptions`: a document that
    // is merely truncated stays open and does not parse (2026-10-05).
    if (counter > 0) while (nest.items.len > 0) {
        const top = nest.items[nest.items.len - 1];
        removeTrailingComma(&out);
        try out.append(alloc, if (top == '{') @as(u8, '}') else @as(u8, ']'));
        _ = nest.pop();
    };

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
    // ⭐ And the output has to PARSE. This assertion is the one the test was
    // missing: the recovery entry above was being emitted into a document with
    // no closing brace, so `std.json` could not read it and the diagnostic the
    // recovery had just built was stranded. Checking only that `$err_trace`
    // appears in the output is checking that a string is present, not that the
    // recovery worked (found 2026-09-07).
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    parsed.deinit();
}

test "both entry points reject an unterminated string OUTSIDE an object" {
    // ⭐ `preprocessAnnotated` used to close the string unconditionally at EOF,
    // so `"unterminated` became the valid document `"unterminated"` — a
    // must-reject input turned silently into an accepted one, with no
    // diagnostic anywhere, because outside an object there is no sibling key to
    // put one in. That is exactly the failure the W2 F2 fix eliminated for the
    // NEWLINE branch; the EOF branch kept it. `preprocess` rejected the same
    // input all along, so the two disagreed.
    const alloc = std.testing.allocator;
    for ([_][]const u8{ "\"unterminated", "'unterminated" }) |src| {
        const plain = try preprocess(alloc, src);
        defer alloc.free(plain);
        const r = try preprocessAnnotated(alloc, src);
        defer alloc.free(r.out);
        try std.testing.expect(!jsonParses(alloc, plain));
        try std.testing.expect(!jsonParses(alloc, r.out));
    }
    // Inside an object the diagnostic HAS somewhere to go, so recovery is still
    // the right move and both sides still agree — the guard is about where the
    // error can be reported, not about EOF.
    const src = "{a: \"no closing";
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    try std.testing.expect(jsonParses(alloc, r.out));
}

// ── fuzz: both preprocessors are the untrusted-input decode surface ─────────
// (arbitrary UTF-8/bytes, not necessarily well-formed JSON5) — must never
// panic or read/write out of bounds, only return a slice or a typed error.

//
// ⚠ Both opened with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain — so `len` was 0 on every
// input a corpus can carry and both preprocessors were handed an empty
// document. Neither had a corpus, so outside `--fuzz` each ran that one empty
// input for ever. In `fuzzPreprocessAnnotated` that is worse than it looks: its
// whole point is the differential oracle below, and on the empty input both
// entry points trivially agree, so the oracle could never have disagreed.

/// `fuzzSeedLocal`, aliased so the corpus reads as the JSON5 it is. A
/// corpus entry is not the document: `Smith.slice` reads a little-endian `u32`
/// length first, so raw source would arrive minus its own first four octets.
const seed = fuzzSeedLocal;

/// JSON5 documents, in the format the length draw reads. Shared by both
/// harnesses, because the differential oracle only means something if both
/// entry points see the same input. Every construct the value tests pin, the
/// audit's own crash reproducer, and the two shapes that make the diagnostic
/// key collide with real input.
const preprocess_seeds = [_][]const u8{
    seed("{ // comment\n\"a\": 1 }"), // a line comment
    seed("{/* hi */\"a\":1}"), // a block comment
    seed("{foo: 1}"), // an unquoted key
    seed("{a: 1, b: 2, c: 3}"), // several unquoted keys
    seed("{a: {b: {c: 1}}}"), // nested objects, all unquoted
    seed("{\"a\": 1,}"), // a trailing comma in an object
    seed("[1, 2, 3,]"), // a trailing comma in an array
    seed("{'hello'}"), // single-quoted string
    seed("{\"a\": \"val // not a comment\"}"), // a comment marker inside a string
    seed("{a: true, b: false, c: null}"), // the three keywords must stay keywords
    seed("{a: 1.2e3, b: 2e-23}"), // exponents: part of the number, not bare identifiers
    seed("[0e0, -0E+0, 1e+2]"), // the exponent sign and zero edges
    seed("{a b"), // the audit F1 CRIT reproducer: unquoted key, no colon, EOF
    seed("{a /*c*/: 1, b: 2}"), // a comment between the key and its colon
    seed("{a\n: 1, b: 2}"), // a newline between the key and its colon
    seed("{x y: 1, \"$err_trace_1\": \"all fine\"}"), // input choosing a diagnostic key name
    seed("{x y: 1, \"$err_1\": \"a\", \"$err__1\": \"b\", \"$err___1\": \"c\"}"), // …and the shadowing escalation
    seed("// hi\n{a:1, /* inline */ b: 2\n// tail\n}"), // comments in every position
    seed("{"), // truncated at the opening brace
    seed("\"unterminated"), // an unterminated double-quoted string
    seed("'unterminated"), // …and the single-quoted one, which is a different branch
    seed("\xff\xfe not utf-8"), // bytes that are not text at all
};

test "fuzz: preprocess never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPreprocess, .{ .corpus = &preprocess_seeds });
}

fn fuzzPreprocess(_: void, smith: *std.testing.Smith) !void {
    const alloc = std.testing.allocator;
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const out = preprocess(alloc, buf[0..len]) catch return;
    alloc.free(out);
}

test "corpus: every seed reaches both entry points, and the rewriting they do is pinned" {
    // ⭐ Octets emitted is the second number, and acceptance would have been a
    // bad one: `preprocess("")` succeeds and returns an empty string, so an
    // "accepted > 0" guard reads 100% on a harness that sees nothing. Octets
    // out, and the count of documents the rewrite actually CHANGED, cannot be
    // produced by the empty input at all.
    //
    // The last number is the one the annotated harness exists for: how many
    // seeds carry a `$err` diagnostic. On the empty input that is zero, so the
    // differential oracle in `fuzzPreprocessAnnotated` had never once compared
    // two outputs that could differ.
    const alloc = std.testing.allocator;
    var nonempty: usize = 0;
    var octets: usize = 0;
    var rewritten: usize = 0;
    var with_diagnostic: usize = 0;
    for (preprocess_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const plain = preprocess(alloc, buf[0..len]) catch continue;
        defer alloc.free(plain);
        octets += plain.len;
        if (!std.mem.eql(u8, plain, buf[0..len])) rewritten += 1;
        const r = preprocessAnnotated(alloc, buf[0..len]) catch continue;
        defer alloc.free(r.out);
        if (std.mem.indexOf(u8, r.out, "$err") != null) with_diagnostic += 1;
        // The harness's own oracle, run over the corpus: the two entry points
        // must agree on whether the result is parseable JSON.
        try std.testing.expectEqual(jsonParses(alloc, plain), jsonParses(alloc, r.out));
    }
    try std.testing.expectEqual(preprocess_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw every seed arrived empty —
    // 0 octets out, 0 documents rewritten, 0 diagnostics. After: 22 seeds,
    // 646 octets, 18 rewritten, 4 carrying a diagnostic. 2026-10-04: 601 --
    // `preprocess` now reads the seed `{a\n: 1, b: 2}` as the valid JSON5 it
    // is, `{"a"\n: 1, "b": 2}` (18 octets), where it used to emit the 63-octet
    // `{"$err_trace_1": "a: '1' --> malformed key at line 1", "b": 2}`.
    // 2026-10-05: 551 -- the seed `{a /*c*/: 1, b: 2}` is valid JSON5 too (a
    // comment may stand where whitespace may), now `{"a" : 1, "b": 2}`
    // instead of a recovery entry 50 octets longer (the reference JSON5 oracle), so
    // it no longer carries a diagnostic either: 4 -> 3. 550 -- the truncated
    // seed `{` stays `{` (refused) instead of being closed into `{}` -- and
    // so is no longer rewritten at all: 18 -> 17.
    try std.testing.expectEqual(@as(usize, 550), octets);
    try std.testing.expectEqual(@as(usize, 17), rewritten);
    try std.testing.expectEqual(@as(usize, 3), with_diagnostic);
}

test "fuzz: preprocessAnnotated never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPreprocessAnnotated, .{ .corpus = &preprocess_seeds });
}

fn fuzzPreprocessAnnotated(_: void, smith: *std.testing.Smith) !void {
    const alloc = std.testing.allocator;
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
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
    _ = @import("ref_oracle_test.zig");
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

/// ⛔ A LOCAL COPY of `testkit.fuzz.seed`, and it has to be one. Enrolling this
/// module in `test_deps` puts it into `zig build check-testonly`, whose probe
/// imports the PUBLISHED module and references every declaration three levels
/// deep — and this module deliberately guards a test-only function with a
/// `@compileError` that fires outside a test build. The two gates contradict
/// each other: `check-testonly` proves the test dep is not needed by the
/// published module by touching decls that refuse to be touched.
///
/// So the nine lines below stay here rather than the module joining `test_deps`.
/// The anchor test underneath is what stops this copy drifting from
/// `modules/testkit/src/fuzz.zig`: it drives the real `std.testing.Smith` over
/// what this produces, exactly as testkit's own tests do.
fn fuzzSeedLocal(comptime frame: []const u8) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame[0..frame.len].*;
    }.bytes;
}

test "the local seed helper produces what Smith.slice reads back" {
    const s = fuzzSeedLocal("abcdef");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [32]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("abcdef", buf[0..n]);
}

// ── JSON5 numeric literals, line continuations, JSON5 whitespace ────────────

/// Both entry points, same options, same bytes out. The two share `emitNumber`
/// on purpose; asserting both keeps them from drifting apart.
fn expectRewriteOpts(src: []const u8, options: Options, want: []const u8) !void {
    const alloc = std.testing.allocator;
    const plain = try preprocessWithOptions(alloc, src, options);
    defer alloc.free(plain);
    try std.testing.expectEqualStrings(want, plain);
    const r = try preprocessAnnotatedWithOptions(alloc, src, options);
    defer alloc.free(r.out);
    try std.testing.expectEqualStrings(want, r.out);
}

fn expectRewrite(src: []const u8, want: []const u8) !void {
    return expectRewriteOpts(src, .{}, want);
}

test "strings: raw control characters are valid JSON5 content and come out escaped" {
    // JSON5 §5 Strings: a string character is any SourceCharacter except the
    // quote, `\` and a LineTerminator, so TAB, U+0001, BS, FF and VT may sit
    // in a string raw; JSON (RFC 8259 §7) requires all of U+0000..U+001F to
    // be escaped. A `\` before such a character is a NonEscapeCharacter, the
    // character itself (ECMAScript 5.1 §7.8.4). Before 2026-10-04 they were
    // copied raw and `std.json` refused the document. Both entry points.
    try expectRewrite("[\"a\tb\"]", "[\"a\\tb\"]");
    try expectRewrite("['a\x01b']", "[\"a\\u0001b\"]");
    try expectRewrite("[\"\x08\x0c\x0b\x1f\"]", "[\"\\b\\f\\u000b\\u001f\"]");
    try expectRewrite("['a\\\tb']", "[\"a\\tb\"]");
    try expectRewrite("{k: \"x\ty\"}", "{\"k\": \"x\\ty\"}");
    // And the value is the character: what JSON5 means is what std.json reads.
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "['a\tb', \"\x01\"]");
    defer alloc.free(out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("a\tb", parsed.value.array.items[0].string);
    try std.testing.expectEqualStrings("\x01", parsed.value.array.items[1].string);
    // A raw LF/CR is NOT content (it is a LineTerminator): still refused.
    const lf = try preprocess(alloc, "[\"a\nb\"]");
    defer alloc.free(lf);
    try std.testing.expect(!jsonParses(alloc, lf));
}

test "unquoted key: a line terminator before ':' is whitespace" {
    // JSON5 §6 (White Space): WhiteSpace and LineTerminator may appear
    // between any two tokens, so `{a\n: 1}` is valid and means `{"a": 1}`.
    // `preprocess` used to skip only horizontal space there and sent the key
    // into $err_trace recovery; `preprocessAnnotated` already accepted it.
    // LF, CRLF, U+2028 and U+2029, on both entry points.
    const alloc = std.testing.allocator;
    for ([_][]const u8{ "{a\n: 1}", "{a\r\n: 1}", "{a\u{2028}: 1}", "{a \u{2029} : 1}" }) |src| {
        const plain = try preprocess(alloc, src);
        defer alloc.free(plain);
        const ann = try preprocessAnnotated(alloc, src);
        defer alloc.free(ann.out);
        for ([_][]const u8{ plain, ann.out }) |out| {
            const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
            defer parsed.deinit();
            try std.testing.expectEqual(@as(usize, 1), parsed.value.object.count());
            try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("a").?.integer);
        }
    }
}

// ── mutation run 2026-10-04: one test per mutant the suite let through ─────

test "single-quoted string: an inner double quote is escaped" {
    // JSON5 'a"b' is the three characters a, ", b; in JSON the quote needs
    // `\"` (RFC 8259 §7). Mutation 2026-10-04: emitting it raw survived.
    try expectRewrite("['a\"b']", "[\"a\\\"b\"]");
}

test "hex literal: a limb below 10^8 keeps its leading zeros" {
    // 0x3B9ACA00 = 1_000_000_000 = 10^9: two base-10^9 limbs, the low one 0,
    // which must print as nine zeros. 0x3B9ACA01 likewise ends in ...000000001.
    // Mutation 2026-10-04: dropping the `{d:0>9}` padding survived.
    try expectRewrite("[0x3B9ACA00]", "[1000000000]");
    try expectRewrite("[0x3B9ACA01]", "[1000000001]");
}

/// Both entry points on `src`: the output must parse, and the top-level
/// object must still hold every `want` key with its integer value -- error
/// recovery may replace the malformed member, never its siblings.
fn expectSiblingsSurvive(src: []const u8, want: []const struct { []const u8, i64 }) !void {
    const alloc = std.testing.allocator;
    const plain = try preprocess(alloc, src);
    defer alloc.free(plain);
    const ann = try preprocessAnnotated(alloc, src);
    defer alloc.free(ann.out);
    for ([_][]const u8{ plain, ann.out }) |out| {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, out, .{}) catch |err| {
            std.debug.print("src: {s}\nout: {s}\n", .{ src, out });
            return err;
        };
        defer parsed.deinit();
        for (want) |kv| {
            const v = parsed.value.object.get(kv[0]) orelse {
                std.debug.print("src: {s}\nout: {s}\nmissing key {s}\n", .{ src, out, kv[0] });
                return error.TestUnexpectedResult;
            };
            try std.testing.expectEqual(kv[1], v.integer);
        }
    }
}

test "error recovery: the value scan respects strings, escapes and nesting, so siblings survive" {
    // `findKeyColon` doc: it "steps over string literals (honouring `\\`
    // escapes)" and stops at `,`/`}`/`]`; `skipValue` doc: it tracks the
    // quote that OPENED a string and the nesting depth, returning at the
    // first delimiter of the enclosing level. Each case breaks one of those
    // and would lose `c`. Mutation 2026-10-04: four such mutants survived
    // (the F5 apostrophe case among them -- its fix had no test that looked
    // at the keys after it).
    try expectSiblingsSurvive("{a b \"x\\\"y:z\", c: 1}", &.{.{ "c", 1 }});
    try expectSiblingsSurvive("{a b: \"don't\", c: 2, d: 3}", &.{ .{ "c", 2 }, .{ "d", 3 } });
    try expectSiblingsSurvive("{a b: {p: 1, q: 2}, c: 3}", &.{.{ "c", 3 }});
    try expectSiblingsSurvive("{x: {a b: 1}, c: 4}", &.{.{ "c", 4 }});
}

test "error recovery: a huge malformed key yields a capped message" {
    // `message_fragment_max` (30) caps every raw fragment quoted in a
    // diagnostic (W2 F10). Mutation 2026-10-04: an uncapped `trimForMessage`
    // survived. 200 `k`s in, at most 30 of them in the message.
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{" ++ "k" ** 200 ++ " x: 1}");
    defer alloc.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "k" ** (message_fragment_max + 1)) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "k" ** message_fragment_max) != null);
}

test "numeric literals: every JSON5 form becomes a plain JSON number" {
    const cases = [_][2][]const u8{
        .{ "[0x1A]", "[26]" },
        .{ "[-0xff]", "[-255]" },
        .{ "[0X1a]", "[26]" }, // upper-case X
        .{ "[+0x1]", "[1]" },
        .{ "[0x0]", "[0]" },
        .{ "[-0x0]", "[-0]" },
        .{ "[0x000ff]", "[255]" }, // leading zeros after the prefix carry no value
        .{ "[0xDEADbeef]", "[3735928559]" },
        .{ "[0xc8e4]", "[51428]" }, // `e` is a hex digit here, not an exponent
        .{ "[.5]", "[0.5]" },
        .{ "[5.]", "[5]" },
        .{ "[-.5]", "[-0.5]" },
        .{ "[+.5]", "[0.5]" },
        .{ "[+1]", "[1]" },
        .{ "[+0.0]", "[0.0]" },
        .{ "[.5e3]", "[0.5e3]" },
        .{ "[5.e2]", "[5e2]" }, // the JSON5 grammar allows `5.` before an exponent
        .{ "[-5.E-2]", "[-5E-2]" },
        .{ "[+1.5e+2]", "[1.5e+2]" },
        // already-valid numbers come out byte-identical
        .{ "[1, 2.5, -3, 0, -0, 1e10, 2E-3, 0.5]", "[1, 2.5, -3, 0, -0, 1e10, 2E-3, 0.5]" },
        .{ "5.", "5" }, // top level
        .{ "{a: .5, b: 0x10, c: +1}", "{\"a\": 0.5, \"b\": 16, \"c\": 1}" },
        .{ "{\"a\": [.5, {b: -.5}]}", "{\"a\": [0.5, {\"b\": -0.5}]}" },
    };
    for (cases) |c| try expectRewrite(c[0], c[1]);
}

test "numeric literals: a hex value of any length becomes its exact decimal integer" {
    const alloc = std.testing.allocator;
    // 2^64 - 1, 2^64 and 2^128 - 1 — past u64, still exact (not a rounded float).
    try expectRewrite("[0xFFFFFFFFFFFFFFFF]", "[18446744073709551615]");
    try expectRewrite("[0x10000000000000000]", "[18446744073709551616]");
    var buf: [64]u8 = undefined;
    const max128 = try std.fmt.bufPrint(&buf, "[{d}]", .{std.math.maxInt(u128)});
    try expectRewrite("[0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]", max128);

    // The largest accepted literal — 256 significant digits, 2^1024 - 1 — is
    // checked against an independent bignum rather than a typed-in constant.
    const digits = "F" ** hex_digits_max;
    const out = try preprocess(alloc, "[0x" ++ digits ++ "]");
    defer alloc.free(out);
    try std.testing.expectEqual(@as(u8, '['), out[0]);
    try std.testing.expectEqual(@as(u8, ']'), out[out.len - 1]);
    var got = try std.math.big.int.Managed.init(alloc);
    defer got.deinit();
    try got.setString(10, out[1 .. out.len - 1]);
    var want = try std.math.big.int.Managed.init(alloc);
    defer want.deinit();
    try want.setString(16, digits);
    try std.testing.expect(got.eql(want));
    // …and the same value with leading zeros in front of it.
    const padded = try preprocess(alloc, "[0x00000" ++ digits ++ "]");
    defer alloc.free(padded);
    try std.testing.expectEqualStrings(out, padded);
}

test "numeric literals: a hex value beyond 256 significant digits is an error, not a rounding" {
    const alloc = std.testing.allocator;
    const src = "[0x1" ++ "0" ** hex_digits_max ++ "]"; // 257 digits
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.HexLiteralTooLarge, preprocessWithOptions(alloc, src, .{ .diagnostic = &diag }));
    try std.testing.expectEqual(@as(usize, 1), diag.line);
    try std.testing.expect(diag.message.len > 0);
    // The annotated entry never fails: verbatim, and `std.json` refuses it.
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    try std.testing.expectEqualStrings(src, r.out);
    try std.testing.expect(!jsonParses(alloc, r.out));
}

test "numeric literals: a hostile megabyte-class hex literal is refused cheaply, output stays bounded" {
    const alloc = std.testing.allocator;
    const big = try alloc.alloc(u8, 200_000);
    defer alloc.free(big);
    @memset(big, 'F');
    const src = try std.mem.concat(alloc, u8, &.{ "[0x", big, "]" });
    defer alloc.free(src);
    try std.testing.expectError(error.HexLiteralTooLarge, preprocess(alloc, src));
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    try std.testing.expectEqual(src.len, r.out.len);
}

test "numeric literals: malformed ones pass through whole, for std.json to reject" {
    // Not a single fragment may be re-scanned as a number of its own:
    // `0x1.5` must not become `1` + `.5` -> `10.5`.
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{
        "[01]", // JSON5 forbids a leading zero, and so must the output
        "[-01]",
        "[0x]",
        "[0xG]",
        "[0x1.5]",
        "[1.2.3]",
        "[.]",
        "[1e]",
        "[1e+]",
        "[+]",
        "[-.e5]",
        "[1abc]",
        "[..5]",
        "[00.5]",
    };
    for (cases) |src| {
        try expectRewrite(src, src);
        try std.testing.expect(!jsonParses(alloc, src));
    }
}

test "numeric literals: a stray sign or word keeps its old handling" {
    // `-foo` is not a number: the `-` goes through alone and `foo` is a bare
    // identifier again (the annotated entry wraps and reports it).
    const alloc = std.testing.allocator;
    const plain = try preprocess(alloc, "[-foo]");
    defer alloc.free(plain);
    try std.testing.expectEqualStrings("[-foo]", plain);
    const r = try preprocessAnnotated(alloc, "{a: -foo}");
    defer alloc.free(r.out);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "$err_1") != null);
}

test "non-finite numbers: an error by default, with a line and a message" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{ "[Infinity]", "[-Infinity]", "[+Infinity]", "[NaN]", "[-NaN]", "[+NaN]", "NaN", "{a: Infinity}" };
    for (cases) |src| {
        var diag: Diagnostic = .{};
        try std.testing.expectError(error.NonFiniteNumber, preprocessWithOptions(alloc, src, .{ .diagnostic = &diag }));
        try std.testing.expectEqual(@as(usize, 1), diag.line);
        try std.testing.expect(std.mem.indexOf(u8, diag.message, ".quoted") != null);
        try std.testing.expectError(error.NonFiniteNumber, preprocess(alloc, src)); // no diagnostic asked for
    }
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.NonFiniteNumber, preprocessWithOptions(alloc, "{\n  a: 1,\n  b: NaN,\n}", .{ .diagnostic = &diag }));
    try std.testing.expectEqual(@as(usize, 3), diag.line);
}

test "non-finite numbers: the annotated entry passes them through, so recovery never changes the verdict" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{ "[NaN]", "[-Infinity]", "[+Infinity]", "{a: Infinity}", "{a: -NaN}" };
    for (cases) |src| {
        const r = try preprocessAnnotated(alloc, src);
        defer alloc.free(r.out);
        try std.testing.expect(std.mem.indexOf(u8, r.out, "$err") == null);
        try std.testing.expect(!jsonParses(alloc, r.out));
    }
    try std.testing.expectEqual(@as(u32, 1), (try annotatedNextId(alloc, "[NaN]")));
}

fn annotatedNextId(alloc: std.mem.Allocator, src: []const u8) !u32 {
    const r = try preprocessAnnotated(alloc, src);
    defer alloc.free(r.out);
    return r.next_id;
}

test "non_finite = .quoted: rewritten to the strings Infinity, -Infinity, NaN" {
    const q: Options = .{ .non_finite = .quoted };
    try expectRewriteOpts(
        "[Infinity, -Infinity, +Infinity, NaN, -NaN, +NaN]",
        q,
        "[\"Infinity\", \"-Infinity\", \"Infinity\", \"NaN\", \"NaN\", \"NaN\"]",
    );
    try expectRewriteOpts("{a: NaN, b: -Infinity}", q, "{\"a\": \"NaN\", \"b\": \"-Infinity\"}");
    try expectRewriteOpts("NaN", q, "\"NaN\"");
    // keys are identifiers, not numbers
    try expectRewriteOpts("{Infinity: 1, NaN: 2}", q, "{\"Infinity\": 1, \"NaN\": 2}");
    // glued to a longer identifier it is no non-finite word: left alone, still invalid
    const alloc = std.testing.allocator;
    const glued = try preprocessWithOptions(alloc, "[Infinityx]", q);
    defer alloc.free(glued);
    try std.testing.expectEqualStrings("[Infinityx]", glued);
    try std.testing.expect(!jsonParses(alloc, glued));
    // the other numeric rewrites are independent of the option
    try expectRewriteOpts("[.5, 0x10, +1]", q, "[0.5, 16, 1]");
}

test "the same bytes inside strings, comments and keys are never rewritten" {
    const alloc = std.testing.allocator;
    const src =
        "{\"a\": \".5 0x1A +1 5. Infinity -NaN\", 'b': '.5 0x1A +1 5. NaN',\n" ++
        "  // .5 0x1A +1 Infinity NaN\n" ++
        "  c: 1, /* .5 0x1A +1 Infinity NaN */ d: 2,\n" ++
        "  \"0x1A\": 3, '.5': 4, 'NaN': 5, e: [ 'Infinity', \".5\" ] }";
    inline for (.{ NonFinite.reject, NonFinite.quoted }) |mode| {
        inline for (.{ false, true }) |annotated| {
            const options: Options = .{ .non_finite = mode };
            const out = if (annotated) blk: {
                const r = try preprocessAnnotatedWithOptions(alloc, src, options);
                break :blk r.out;
            } else try preprocessWithOptions(alloc, src, options);
            defer alloc.free(out);
            const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
            defer parsed.deinit();
            const o = parsed.value.object;
            try std.testing.expectEqual(@as(usize, 8), o.count());
            try std.testing.expectEqualStrings(".5 0x1A +1 5. Infinity -NaN", o.get("a").?.string);
            try std.testing.expectEqualStrings(".5 0x1A +1 5. NaN", o.get("b").?.string);
            try std.testing.expectEqual(@as(i64, 1), o.get("c").?.integer);
            try std.testing.expectEqual(@as(i64, 2), o.get("d").?.integer);
            try std.testing.expectEqual(@as(i64, 3), o.get("0x1A").?.integer);
            try std.testing.expectEqual(@as(i64, 4), o.get(".5").?.integer);
            try std.testing.expectEqual(@as(i64, 5), o.get("NaN").?.integer);
            try std.testing.expectEqualStrings("Infinity", o.get("e").?.array.items[0].string);
            try std.testing.expectEqualStrings(".5", o.get("e").?.array.items[1].string);
        }
    }
}

const line_terminators = [_][]const u8{ "\n", "\r\n", "\r", "\u{2028}", "\u{2029}" };

test "line continuation: backslash + any line terminator disappears from a string" {
    const alloc = std.testing.allocator;
    inline for (line_terminators) |lt| {
        try expectRewrite("[\"ab\\" ++ lt ++ "cd\"]", "[\"abcd\"]");
        try expectRewrite("['ab\\" ++ lt ++ "cd']", "[\"abcd\"]");
        // two in a row, and one at the very start and end of the string
        try expectRewrite("[\"\\" ++ lt ++ "a\\" ++ lt ++ "\\" ++ lt ++ "b\\" ++ lt ++ "\"]", "[\"ab\"]");
        // as the value of a key, in the annotated entry's object branch too
        try expectRewrite("{k: 'x\\" ++ lt ++ "y'}", "{\"k\": \"xy\"}");
    }
    // CRLF is ONE terminator: nothing of it may survive as an escape or a raw byte.
    const out = try preprocess(alloc, "[\"a\\\r\nb\"]");
    defer alloc.free(out);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("ab", parsed.value.array.items[0].string);
}

test "line continuation: only a REAL backslash starts one, and only inside a string" {
    // `\\` is an escaped backslash, so the newline after it is a raw one:
    // untouched (and std.json rejects the raw control byte).
    const alloc = std.testing.allocator;
    const raw = "[\"a\\\\\nb\"]";
    const out = try preprocess(alloc, raw);
    defer alloc.free(out);
    try std.testing.expectEqualStrings(raw, out);
    try std.testing.expect(!jsonParses(alloc, out));
    // an ordinary escape stays an escape
    try expectRewrite("[\"a\\nb\"]", "[\"a\\nb\"]");
    // a comment has no continuation: the backslash-newline ends it like any newline
    inline for (line_terminators) |lt| {
        const o2 = try preprocess(alloc, "[1, // c \\" ++ lt ++ "2]");
        defer alloc.free(o2);
        const p = try std.json.parseFromSlice(std.json.Value, alloc, o2, .{});
        defer p.deinit();
        try std.testing.expectEqual(@as(usize, 2), p.value.array.items.len);
    }
    // a truncated backslash-terminator at end of input must not read out of bounds
    _ = try annotatedNextId(alloc, "\"ab\\\xE2\x80");
    const t = try preprocess(alloc, "['ab\\\xE2");
    alloc.free(t);
    const t2 = try preprocess(alloc, "\"ab\\");
    alloc.free(t2);
}

const ws_kinds = [_][]const u8{
    "\x0B", // vertical tab
    "\x0C", // form feed
    "\u{00A0}", // NBSP
    "\u{FEFF}", // BOM / ZWNBSP
    "\u{2028}", // LINE SEPARATOR
    "\u{2029}", // PARAGRAPH SEPARATOR
    "\u{1680}", // Ogham space mark (Zs)
    "\u{2000}", // en quad (Zs)
    "\u{2003}", // em space (Zs)
    "\u{200A}", // hair space (Zs)
    "\u{202F}", // narrow NBSP (Zs)
    "\u{205F}", // medium mathematical space (Zs)
    "\u{3000}", // ideographic space (Zs)
};

test "JSON5 whitespace between tokens becomes a plain space" {
    const alloc = std.testing.allocator;
    inline for (ws_kinds) |ws| {
        try expectRewrite("[1," ++ ws ++ "2]", "[1, 2]");
        try expectRewrite("[" ++ ws ++ "1" ++ ws ++ "]", "[ 1 ]");
        try expectRewrite("{" ++ ws ++ "a: 1}", "{ \"a\": 1}");
        // between an unquoted key and its colon the key must still be a key.
        // (U+2028/U+2029 are line terminators, and `preprocess` deliberately
        // ends an unquoted key at a newline — see its key peek.)
        if (comptime !(std.mem.eql(u8, ws, "\u{2028}") or std.mem.eql(u8, ws, "\u{2029}"))) {
            try expectRewrite("{a" ++ ws ++ ": 1}", "{\"a\" : 1}");
        }
        try expectRewrite("{\"a\":" ++ ws ++ "1," ++ ws ++ "}", "{\"a\": 1}");
        // and the result is a document std.json reads
        const out = try preprocess(alloc, ws ++ "{" ++ ws ++ "a:" ++ ws ++ "[" ++ ws ++ "1" ++ ws ++ "]" ++ ws ++ "}" ++ ws);
        defer alloc.free(out);
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("a").?.array.items[0].integer);
    }
}

test "JSON5 whitespace is left alone inside strings, and lookalikes are not whitespace" {
    const alloc = std.testing.allocator;
    const inside = "[\"a\u{00A0}b\u{FEFF}c\u{2028}d\u{3000}e\"]";
    try expectRewrite(inside, inside);
    try expectRewrite("['a\u{00A0}b']", "[\"a\u{00A0}b\"]");
    // U+200B (zero width space) and U+00A1 are NOT Zs: rewriting them would
    // accept a document JSON5 rejects.
    inline for (.{ "\u{200B}", "\u{00A1}", "\u{2027}", "\u{180E}", "\u{3001}" }) |odd| {
        try expectRewrite("[" ++ odd ++ "1]", "[" ++ odd ++ "1]");
        try std.testing.expect(!jsonParses(alloc, "[" ++ odd ++ "1]"));
    }
    // U+2028/U+2029 end a `//` comment (they are JSON5 line terminators)
    inline for (.{ "\u{2028}", "\u{2029}" }) |lt| {
        const out = try preprocess(alloc, "[1, // c" ++ lt ++ "2]");
        defer alloc.free(out);
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(@as(usize, 2), parsed.value.array.items.len);
    }
    // truncated multi-byte sequences at end of input: no panic, no rewrite
    inline for (ws_kinds) |ws| {
        inline for (0..ws.len) |k| {
            const src = "[1," ++ ws[0..k];
            const out = try preprocess(alloc, src);
            alloc.free(out);
            const r = try preprocessAnnotated(alloc, src);
            alloc.free(r.out);
        }
    }
}

test "std.json reads the rewritten output of a combined document into a typed struct" {
    const alloc = std.testing.allocator;
    const Cfg = struct {
        timeout: f64,
        retries: i32,
        mask: u64,
        neg: i64,
        half: f64,
        ratio: f64,
        big: f64,
        inf: f64,
        ninf: f64,
        pinf: f64,
        nan: f64,
        name: []const u8,
        tags: []const []const u8,
    };
    const src =
        "\u{FEFF}{ // a JSON5 config\n" ++
        "  timeout:\u{00A0}.5,\n" ++
        "  retries: +3,\x0C\n" ++
        "  mask: 0xDEADbeef,\n" ++
        "  neg: -0x10,\n" ++
        "  half: 5.,\n" ++
        "  ratio: -.25e1,\n" ++
        "  big: 0xFFFFFFFFFFFFFFFFFF, /* 2^72 - 1 */\n" ++
        "  inf: Infinity,\n" ++
        "  ninf: -Infinity,\n" ++
        "  pinf: +Infinity,\n" ++
        "  nan: NaN,\n" ++
        "  name: 'multi\\\r\nline',\u{2028}\n" ++
        "  tags: ['a', \"b\", 'c\\\u{2029}d',],\n" ++
        "}";
    // the default refuses, with the reason
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.NonFiniteNumber, preprocessWithOptions(alloc, src, .{ .diagnostic = &diag }));
    try std.testing.expectEqual(@as(usize, 9), diag.line);

    inline for (.{ false, true }) |annotated| {
        const options: Options = .{ .non_finite = .quoted };
        const out = if (annotated) blk: {
            const r = try preprocessAnnotatedWithOptions(alloc, src, options);
            break :blk r.out;
        } else try preprocessWithOptions(alloc, src, options);
        defer alloc.free(out);
        const parsed = try std.json.parseFromSlice(Cfg, alloc, out, .{});
        defer parsed.deinit();
        const v = parsed.value;
        try std.testing.expectEqual(@as(f64, 0.5), v.timeout);
        try std.testing.expectEqual(@as(i32, 3), v.retries);
        try std.testing.expectEqual(@as(u64, 0xDEADBEEF), v.mask);
        try std.testing.expectEqual(@as(i64, -16), v.neg);
        try std.testing.expectEqual(@as(f64, 5.0), v.half);
        try std.testing.expectEqual(@as(f64, -2.5), v.ratio);
        try std.testing.expectEqual(@as(f64, 0x1p72), v.big);
        try std.testing.expect(std.math.isInf(v.inf) and v.inf > 0);
        try std.testing.expect(std.math.isInf(v.ninf) and v.ninf < 0);
        try std.testing.expect(std.math.isInf(v.pinf) and v.pinf > 0);
        try std.testing.expect(std.math.isNan(v.nan));
        try std.testing.expectEqualStrings("multiline", v.name);
        try std.testing.expectEqual(@as(usize, 3), v.tags.len);
        try std.testing.expectEqualStrings("cd", v.tags[2]);
    }
}

test "the two entry points agree on whether the new forms parse" {
    const alloc = std.testing.allocator;
    const inputs = [_][]const u8{
        "[.5, 0x1A, +1, 5.]",   "[0x1.5]",     "[1.2.3]",    "[NaN]",
        "{a: Infinity, b: .5}", "['a\\\nb']",  "[1,\x0C2]",  "{a b: .5}",
        "[0x]",                 "[-Infinity]", "{a: -foo}",  "[+]",
        "{\"a\": 0xFF, }",      "[1/*c*/.5]",  "[.5/*c*/2]", "\u{FEFF}[1]",
    };
    inline for (.{ NonFinite.reject, NonFinite.quoted }) |mode| {
        for (inputs) |src| {
            const options: Options = .{ .non_finite = mode };
            const plain_ok = if (preprocessWithOptions(alloc, src, options)) |o| blk: {
                defer alloc.free(o);
                break :blk jsonParses(alloc, o);
            } else |_| false;
            const r = try preprocessAnnotatedWithOptions(alloc, src, options);
            defer alloc.free(r.out);
            try std.testing.expectEqual(plain_ok, jsonParses(alloc, r.out));
        }
    }
}

// ── found by the reference JSON5 oracle (ref_oracle_test.zig), 2026-10-05 ───

fn expectValue(input: []const u8, want_json: []const u8) !void {
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, input);
    defer alloc.free(out);
    const got = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer got.deinit();
    const want = try std.json.parseFromSlice(std.json.Value, alloc, want_json, .{});
    defer want.deinit();
    var a: std.Io.Writer.Allocating = .init(alloc);
    defer a.deinit();
    var b: std.Io.Writer.Allocating = .init(alloc);
    defer b.deinit();
    try std.json.Stringify.value(got.value, .{}, &a.writer);
    try std.json.Stringify.value(want.value, .{}, &b.writer);
    try std.testing.expectEqualStrings(b.written(), a.written());
}

fn expectRefusedByBoth(input: []const u8) !void {
    const alloc = std.testing.allocator;
    const plain = try preprocess(alloc, input);
    defer alloc.free(plain);
    try std.testing.expect(!jsonParses(alloc, plain));
    const r = try preprocessAnnotated(alloc, input);
    defer alloc.free(r.out);
    try std.testing.expect(!jsonParses(alloc, r.out));
}

test "strings: the JSON5 escapes JSON lacks become their characters" {
    // \v \0 \xHH were copied as the two bytes they were, and std.json refused
    // the valid document; so did \q (a NonEscapeCharacter, the character
    // itself), \é, and \' inside a double-quoted string.
    try expectValue("['\\v', '\\0', '\\x41\\xe9', '\\q\\é', \"\\'\", '\\/']", "[\"\\u000b\", \"\\u0000\", \"A\\u00e9\", \"q\\u00e9\", \"'\", \"/\"]");
    // Not escapes in JSON5, still refused: \1..\9, \0 before a digit, a short \x.
    try expectRefusedByBoth("['\\1']");
    try expectRefusedByBoth("['\\01']");
    try expectRefusedByBoth("['\\x4']");
}

test "unquoted keys: non-ASCII identifier characters and \\u escapes" {
    // Only ASCII was taken; these went into $err_trace recovery.
    try expectValue("{é: 1, π: 2, a\\u0062: 3, a\u{200C}: 4, Z\u{0300}: 5}", "{\"é\": 1, \"π\": 2, \"ab\": 3, \"a\u{200C}\": 4, \"Z\u{0300}\": 5}");
    // An escape that spells a non-identifier character is not an identifier.
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{\\u0020: 1}");
    defer alloc.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "$err_trace_") != null);
}

test "unquoted keys: a comment between the key and its colon" {
    try expectValue("{a /* c */: 1, b // c\n: 2}", "{\"a\": 1, \"b\": 2}");
    const alloc = std.testing.allocator;
    const r = try preprocessAnnotated(alloc, "{a /* c */: 1}");
    defer alloc.free(r.out);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "$err") == null);
}

test "a truncated document is refused, not completed" {
    // EOF auto-close closed whatever was open, so a config cut off mid-write
    // read as a complete one with fewer entries.
    try expectRefusedByBoth("{\"servers\": [{\"host\": \"a\"}");
    try expectRefusedByBoth("[1, 2");
    try expectRefusedByBoth("{");
    // ...while recovery that already happened still closes what it opened.
    const alloc = std.testing.allocator;
    const out = try preprocess(alloc, "{a b");
    defer alloc.free(out);
    try std.testing.expect(jsonParses(alloc, out));
}

test "numbers: a dropped + never joins two numbers into one" {
    // `1+2` came out `12`, `1.+3` `13`.
    try expectRefusedByBoth("[1+2]");
    try expectRefusedByBoth("1.+3");
    try expectValue("[+1, +.5]", "[1, 0.5]");
}
