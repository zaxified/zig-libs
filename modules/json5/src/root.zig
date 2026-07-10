// SPDX-License-Identifier: MIT
//! json5 — single-pass JSON5→JSON preprocessor (comments, unquoted keys,
//! trailing commas, single-quote strings) + a source-location annotated variant.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "JSON5 spec (json5.org) preprocessor to std.json",
    .deps = .{},
};

/// Preprocess JSON5 source and return a new slice owned by alloc.
pub fn preprocess(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
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
                while (i < input.len and input[i] != '\n') i += 1;
                continue;
            }
            if (input[i + 1] == '*') { // multi-line
                i += 2;
                while (i + 1 < input.len) {
                    if (input[i] == '*' and input[i + 1] == '/') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
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
                        var colon = j;
                        while (colon < input.len and input[colon] != ':') : (colon += 1) {}
                        const raw_key = std.mem.trim(u8, input[key_start..colon], " \t\r\n");
                        var vs = colon + 1;
                        while (vs < input.len and (input[vs] == ' ' or input[vs] == '\t')) : (vs += 1) {}
                        const val_end = skipValue(input, vs);
                        const raw_val_full = std.mem.trim(u8, input[vs..val_end], " \t\r\n");
                        // Truncate to 30 chars so the error message stays compact in the GUI.
                        const raw_val = if (raw_val_full.len > 30) raw_val_full[0..30] else raw_val_full;
                        const err_line = lineOf(input, key_start);
                        const msg = try std.fmt.allocPrint(alloc, "{s}: '{s}' --> malformed key at line {d}", .{
                            raw_key, raw_val, err_line,
                        });
                        defer alloc.free(msg);
                        err_counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"$err_trace_{d}\": ", .{err_counter});
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        try appendJsonStr(&out, alloc, msg);
                        key_pos = false;
                        i = val_end;
                    }
                } else {
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
                out.items.len = j;
                return;
            },
            else => return,
        }
    }
}

/// Return the 1-based line number of position `pos` in `input`.
fn lineOf(input: []const u8, pos: usize) usize {
    var line: usize = 1;
    for (input[0..@min(pos, input.len)]) |ch| {
        if (ch == '\n') line += 1;
    }
    return line;
}

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
    var in_str = false;
    while (i < input.len) : (i += 1) {
        const ch = input[i];
        if (in_str) {
            if (ch == '\\') {
                i += 1;
                continue;
            }
            if (ch == '"' or ch == '\'') in_str = false;
        } else switch (ch) {
            '"', '\'' => in_str = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                if (depth == 0) return i;
                depth -= 1;
            },
            ',' => if (depth == 0) return i,
            else => {},
        }
    }
    return i;
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
) !void {
    for (errs.items) |msg| {
        try out.appendSlice(alloc, ", ");
        counter.* += 1;
        const head = try std.fmt.allocPrint(alloc, "\"$err_{d}\": ", .{counter.*});
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
                    try out.append(alloc, '"');
                    closed = true;
                    if (isInObject(nest.items)) {
                        const msg = try std.fmt.allocPrint(alloc, "unterminated string at line {d}", .{lineOf(input, str_start)});
                        try pending_value_errs.append(alloc, msg);
                    }
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
                    const msg = try std.fmt.allocPrint(alloc, "unterminated string at end of input (line {d})", .{lineOf(input, str_start)});
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
                        const msg = try std.fmt.allocPrint(alloc, "unterminated string at line {d}", .{lineOf(input, str_start)});
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
                    const msg = try std.fmt.allocPrint(alloc, "unterminated string at end of input (line {d})", .{lineOf(input, str_start)});
                    try pending_value_errs.append(alloc, msg);
                }
            }
            continue;
        }

        // ── comments → strip silently ─────────────────────────────────────
        if (c == '/' and i + 1 < input.len) {
            if (input[i + 1] == '/') {
                i += 2;
                while (i < input.len and input[i] != '\n') i += 1;
                continue;
            }
            if (input[i + 1] == '*') {
                i += 2;
                while (i + 1 < input.len) {
                    if (input[i] == '*' and input[i + 1] == '/') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
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
                try flushValueErrs(&out, alloc, &pending_value_errs, &counter);
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
                try flushValueErrs(&out, alloc, &pending_value_errs, &counter);
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
                        // Scan for ':' but stop at the next ',' / '}' / ']' so
                        // we don't absorb a later key's colon. Skip over string
                        // literals so their bytes don't interfere.
                        var colon = j;
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
                        const has_colon = colon < input.len and input[colon] == ':';
                        const err_line = lineOf(input, key_start);
                        counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"$err_{d}\": ", .{counter});
                        defer alloc.free(head);
                        try out.appendSlice(alloc, head);
                        if (!has_colon) {
                            // Missing colon: skip up to next ',' or '}' so we
                            // don't lose subsequent keys in this object.
                            const skip_end = skipValue(input, j);
                            const after_full = std.mem.trim(u8, input[j..skip_end], " \t\r\n");
                            const after = if (after_full.len > 30) after_full[0..30] else after_full;
                            const msg = try std.fmt.allocPrint(alloc, "{s} {s} --> missing colon after key at line {d}", .{
                                input[key_start..i], after, err_line,
                            });
                            defer alloc.free(msg);
                            try appendJsonStr(&out, alloc, msg);
                            i = skip_end;
                        } else {
                            const raw_key = std.mem.trim(u8, input[key_start..colon], " \t\r\n");
                            var vs = colon + 1;
                            while (vs < input.len and (input[vs] == ' ' or input[vs] == '\t')) : (vs += 1) {}
                            const val_end = skipValue(input, vs);
                            const raw_val_full = std.mem.trim(u8, input[vs..val_end], " \t\r\n");
                            const raw_val = if (raw_val_full.len > 30) raw_val_full[0..30] else raw_val_full;
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
                        try flushValueErrs(&out, alloc, &pending_value_errs, &counter);
                        if (needsLeadingComma(out.items)) try out.appendSlice(alloc, ", ");
                        const err_line = lineOf(input, start);
                        const msg = try std.fmt.allocPrint(alloc, "missing comma before '{s}' at line {d}", .{ ident, err_line });
                        defer alloc.free(msg);
                        counter += 1;
                        const head = try std.fmt.allocPrint(alloc, "\"$err_{d}\": ", .{counter});
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
                            std.mem.eql(u8, ident, "null"))
                        {
                            try out.appendSlice(alloc, ident);
                        } else {
                            // Wrap the bare word as a string so the output is valid JSON,
                            // then queue an error to be emitted as a sibling entry.
                            try out.append(alloc, '"');
                            try out.appendSlice(alloc, ident);
                            try out.append(alloc, '"');
                            if (isInObject(nest.items)) {
                                const err_line = lineOf(input, start);
                                const msg = try std.fmt.allocPrint(alloc, "'{s}' --> invalid literal in value position at line {d}", .{
                                    ident, err_line,
                                });
                                try pending_value_errs.append(alloc, msg);
                            }
                        }
                    }
                } else {
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
        try flushValueErrs(&out, alloc, &pending_value_errs, &counter);
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
    const out = try preprocess(alloc, "{/* hi */\"a\":1}");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("{\"a\":1}", out);
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
