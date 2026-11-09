// SPDX-License-Identifier: MIT
//! Text functions that `exprfn.zig` does not have (dataframe S2 wave W4): whitespace-default
//! `split`, `rsplit`, `partition`/`rpartition`, `split_exact`/`splitn`, `wrap`,
//! `slice_replace`, hex and base64 `encode`/`decode`, several prefixes for `startswith`,
//! `replace(n=)`, and the two frame verbs `splitColumns` (pandas `str.split(expand=True)`,
//! polars `str.split_exact` + `unnest`) and `getDummies` (pandas `str.get_dummies`).
//!
//! Text is bytes; positions that the engines count in characters are counted in code points
//! here too (invalid UTF-8 counts bytes, as `exprfn.charStarts`). Original work of the
//! zig-libs authors (MIT); the engines' and Python's documentation was read, no source.

const std = @import("std");
const regex = @import("regex");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const sp = @import("spec.zig");
const lf = @import("listfn.zig");
const fnx = @import("exprfn.zig");
const Column = vm.Column;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Value = vm.Value;

/// What a cell function can fail with.
pub const Error = error{ OutOfMemory, TooLarge };

/// Errors of the two frame verbs. `BadArgument`: an empty separator, a pattern the `regex`
/// module refuses, a name given twice. `DuplicateColumn`: an output name equal to another
/// column's.
pub const StrError = sp.Error || error{ BadArgument, DuplicateColumn };

/// Most columns `splitColumns` or `getDummies` may make (the pieces / distinct tokens come
/// from the data).
pub const max_str_columns: usize = 1 << 12;

// ── whitespace ───────────────────────────────────────────────────────────────

const Cp = struct { cp: u21, len: usize };

fn cpAt(t: []const u8, i: usize) Cp {
    const n = std.unicode.utf8ByteSequenceLength(t[i]) catch return .{ .cp = 0xFFFD, .len = 1 };
    if (i + n > t.len) return .{ .cp = 0xFFFD, .len = 1 };
    const cp = std.unicode.utf8Decode(t[i..][0..n]) catch return .{ .cp = 0xFFFD, .len = 1 };
    return .{ .cp = cp, .len = n };
}

/// Python's `str.isspace` for one code point (`str.split()` splits on these).
fn isPySpace(cp: u21) bool {
    return switch (cp) {
        9...13, 28...32, 0x85, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000 => true,
        else => false,
    };
}

/// Python's `s.split(None, limit - 1)` as a list (pandas `str.split()` with no `pat`): runs
/// of whitespace separate, no empty pieces, leading and trailing whitespace ignored; with
/// `limit` pieces at most, the last is the rest of the text from its first non-space
/// character (trailing whitespace kept, as Python). `limit` 0 is the caller's to refuse.
pub fn splitWhitespace(a: std.mem.Allocator, t: []const u8, limit: ?usize) Error!Value {
    var pieces: std.ArrayList(Value) = .empty;
    defer pieces.deinit(a);
    try splitWsInto(a, &pieces, t, limit, std.math.maxInt(usize));
    return lf.makeList(a, pieces.items);
}

fn splitWsInto(a: std.mem.Allocator, out: *std.ArrayList(Value), t: []const u8, limit: ?usize, cap: usize) Error!void {
    const max = limit orelse std.math.maxInt(usize);
    var i: usize = 0;
    while (true) {
        while (i < t.len) {
            const c = cpAt(t, i);
            if (!isPySpace(c.cp)) break;
            i += c.len;
        }
        if (i >= t.len) return;
        if (out.items.len + 1 == max) {
            try out.append(a, .{ .text = t[i..] });
            if (out.items.len > cap) return error.TooLarge;
            return;
        }
        var j = i;
        while (j < t.len) {
            const c = cpAt(t, j);
            if (isPySpace(c.cp)) break;
            j += c.len;
        }
        try out.append(a, .{ .text = t[i..j] });
        if (out.items.len > cap) return error.TooLarge;
        i = j;
    }
}

// ── rsplit, partition, split_exact ───────────────────────────────────────────

/// Python's `s.rsplit(by, limit - 1)` (pandas `str.rsplit(pat, n)`): split from the right,
/// at most `limit` pieces, the first the rest of the text. `by` must not be empty (the
/// caller refuses it). Pieces are in text order.
pub fn rsplitLiteral(a: std.mem.Allocator, t: []const u8, by: []const u8, limit: ?usize) Error!Value {
    var pieces: std.ArrayList(Value) = .empty;
    defer pieces.deinit(a);
    const max = limit orelse std.math.maxInt(usize);
    var end = t.len;
    while (pieces.items.len + 1 < max) {
        const hit = std.mem.findLast(u8, t[0..end], by) orelse break;
        try pieces.append(a, .{ .text = t[hit + by.len .. end] });
        end = hit;
    }
    try pieces.append(a, .{ .text = t[0..end] });
    std.mem.reverse(Value, pieces.items);
    return lf.makeList(a, pieces.items);
}

/// The record field names of `partition`: pandas names the three columns 0, 1, 2.
pub const partition_names = [_][]const u8{ "0", "1", "2" };

/// Python's `partition` (`last` false) and `rpartition` (pandas `str.partition`): a record
/// of the text before the first (last) `sep`, the separator, and the rest; no separator:
/// the whole text, "", "" (`rpartition`: "", "", the whole text). `sep` is not empty.
pub fn partition(a: std.mem.Allocator, t: []const u8, sep: []const u8, last: bool) Error!Value {
    const hit = if (last) std.mem.findLast(u8, t, sep) else std.mem.find(u8, t, sep);
    var vals: [3]Value = undefined;
    if (hit) |h| {
        vals = .{ .{ .text = t[0..h] }, .{ .text = sep }, .{ .text = t[h + sep.len ..] } };
    } else if (last) {
        vals = .{ .{ .text = "" }, .{ .text = "" }, .{ .text = t } };
    } else {
        vals = .{ .{ .text = t }, .{ .text = "" }, .{ .text = "" } };
    }
    return lf.makeRecord(a, &partition_names, &vals);
}

/// The text split by the literal `by` at its first `n` occurrences and no more, as `n + 1`
/// fields `names` (polars `str.split_exact(by, n)`: a text with fewer pieces gives null
/// fields; pieces past the n+1st are dropped) or, `rest`, as `n` fields whose last is the
/// rest of the text (polars `str.splitn(by, n)`). `names.len` is the field count.
pub fn splitFields(a: std.mem.Allocator, t: []const u8, by: []const u8, names: []const []const u8, rest: bool) Error!Value {
    const vals = try a.alloc(Value, names.len);
    defer a.free(vals);
    @memset(vals, .null);
    var at: usize = 0;
    var k: usize = 0;
    while (k < names.len) : (k += 1) {
        if (rest and k + 1 == names.len) {
            vals[k] = .{ .text = t[at..] };
            break;
        }
        const hit = if (by.len == 0) null else std.mem.findPos(u8, t, at, by);
        if (hit) |h| {
            vals[k] = .{ .text = t[at..h] };
            at = h + by.len;
        } else {
            vals[k] = .{ .text = t[at..] };
            break;
        }
    }
    return lf.makeRecord(a, names, vals);
}

// ── slice_replace ────────────────────────────────────────────────────────────

fn pySliceIndex(i: i64, len: usize) usize {
    const n: i64 = @intCast(len);
    var j = i;
    if (j < 0) j = @max(0, j +| n);
    return @intCast(@min(j, n));
}

/// pandas `str.slice_replace(start, stop, repl)`: `x[:start] + repl + x[stop:]` in
/// characters, Python slice rules (negative from the end, clamped); a null `start` keeps
/// nothing before, a null `stop` nothing after; an empty slice (start at or past stop)
/// inserts `repl` at `start` and keeps the rest from there, as pandas does.
pub fn sliceReplace(a: std.mem.Allocator, t: []const u8, start: ?i64, stop: ?i64, repl: []const u8) Error![]const u8 {
    const starts = try fnx.charStarts(a, t);
    defer a.free(starts);
    const n = starts.len - 1;
    const s_idx: ?usize = if (start) |s| pySliceIndex(s, n) else null;
    const e_idx: ?usize = if (stop) |e| pySliceIndex(e, n) else null;
    // x[start:stop] == "" : the stop becomes the start.
    const lo = s_idx orelse 0;
    const hi = e_idx orelse n;
    const local_stop: ?usize = if (hi <= lo) s_idx else e_idx;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    if (s_idx) |s| try out.appendSlice(a, t[0..starts[s]]);
    try out.appendSlice(a, repl);
    if (e_idx != null) {
        const from = local_stop orelse 0;
        try out.appendSlice(a, t[starts[from]..]);
    }
    if (out.items.len > fnx.max_text_result) return error.TooLarge;
    return out.toOwnedSlice(a);
}

// ── encode / decode ──────────────────────────────────────────────────────────

pub const Encoding = enum { hex, base64 };

/// polars `str.encode("hex" | "base64")`: the text's UTF-8 bytes as lowercase hex, or as
/// standard base64 with `=` padding.
pub fn encode(a: std.mem.Allocator, t: []const u8, how: Encoding) Error![]const u8 {
    switch (how) {
        .hex => {
            if (t.len > fnx.max_text_result / 2) return error.TooLarge;
            const out = try a.alloc(u8, t.len * 2);
            const digits = "0123456789abcdef";
            for (t, 0..) |b, i| {
                out[2 * i] = digits[b >> 4];
                out[2 * i + 1] = digits[b & 15];
            }
            return out;
        },
        .base64 => {
            const enc = std.base64.standard.Encoder;
            const n = enc.calcSize(t.len);
            if (n > fnx.max_text_result) return error.TooLarge;
            const out = try a.alloc(u8, n);
            _ = enc.encode(out, t);
            return out;
        },
    }
}

/// polars `str.decode("hex" | "base64", strict=False)` / `bin.decode`: the bytes the text
/// spells, as text. Null when the text is not that encoding (hex: odd length or a non-hex
/// digit, either case; base64: standard alphabet, `=` padding, no whitespace) or when the
/// bytes are not valid UTF-8 (this module has no binary type; polars' strict mode raises).
pub fn decode(a: std.mem.Allocator, t: []const u8, how: Encoding) Error!?[]const u8 {
    switch (how) {
        .hex => {
            if (t.len % 2 != 0) return null;
            const out = try a.alloc(u8, t.len / 2);
            errdefer a.free(out);
            for (out, 0..) |*o, i| {
                const hi = std.fmt.charToDigit(t[2 * i], 16) catch {
                    a.free(out);
                    return null;
                };
                const lo = std.fmt.charToDigit(t[2 * i + 1], 16) catch {
                    a.free(out);
                    return null;
                };
                o.* = hi << 4 | lo;
            }
            if (!std.unicode.utf8ValidateSlice(out)) {
                a.free(out);
                return null;
            }
            return out;
        },
        .base64 => {
            const dec = std.base64.standard.Decoder;
            const n = dec.calcSizeForSlice(t) catch return null;
            const out = try a.alloc(u8, n);
            dec.decode(out, t) catch {
                a.free(out);
                return null;
            };
            if (!std.unicode.utf8ValidateSlice(out)) {
                a.free(out);
                return null;
            }
            return out;
        },
    }
}

// ── startswith / endswith with several affixes ───────────────────────────────

/// Python's `startswith(tuple)` / `endswith(tuple)` (pandas `str.startswith(("a", "b"))`):
/// whether the text starts (ends) with any of `affixes`; none: false.
pub fn hasAnyAffix(t: []const u8, affixes: []const []const u8, end: bool) bool {
    for (affixes) |p| {
        if (if (end) std.mem.endsWith(u8, t, p) else std.mem.startsWith(u8, t, p)) return true;
    }
    return false;
}

/// `std.mem.replaceOwned` of at most the first `n` occurrences (pandas `str.replace(n=)`
/// with `regex=False`). `from` is not empty.
pub fn replaceFirstN(a: std.mem.Allocator, t: []const u8, from: []const u8, to: []const u8, n: usize) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var at: usize = 0;
    var done: usize = 0;
    while (done < n) {
        const hit = std.mem.findPos(u8, t, at, from) orelse break;
        try out.appendSlice(a, t[at..hit]);
        try out.appendSlice(a, to);
        if (out.items.len > fnx.max_text_result) return error.TooLarge;
        at = hit + from.len;
        done += 1;
    }
    try out.appendSlice(a, t[at..]);
    if (out.items.len > fnx.max_text_result) return error.TooLarge;
    return out.toOwnedSlice(a);
}

// ── wrap ─────────────────────────────────────────────────────────────────────

/// Python's `textwrap.wrap(text, width, break_long_words=, break_on_hyphens=)` joined by
/// "\n" (pandas `str.wrap`). The other TextWrapper options keep Python's defaults:
/// `expand_tabs` (tab size 8), `replace_whitespace`, `drop_whitespace`,
/// `fix_sentence_endings` off, no indents, no `max_lines`. Lengths are code points. What
/// differs from Python: only the space is whitespace after the tab/newline replacement (a
/// no-break space is a letter), and bytes >= 0x80 count as letters for the hyphen rules
/// (Python's `\w` is Unicode-aware). `width` must be at least 1 (the caller refuses less).
pub fn wrap(a: std.mem.Allocator, t: []const u8, width: usize, break_long_words: bool, break_on_hyphens: bool) Error![]const u8 {
    // 1. expand tabs, replace whitespace by spaces.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    var col: usize = 0;
    for (t) |c| {
        switch (c) {
            '\t' => {
                const n = 8 - col % 8;
                if (buf.items.len + n > fnx.max_text_result) return error.TooLarge;
                try buf.appendNTimes(a, ' ', n);
                col += n;
            },
            '\n', '\r', 0x0b, 0x0c => {
                try buf.append(a, ' ');
                if (c == '\n' or c == '\r') col = 0 else col += 1;
            },
            else => {
                try buf.append(a, c);
                if (c & 0xC0 != 0x80) col += 1;
            },
        }
    }
    const s = buf.items;
    // 2. chunks.
    var chunks: std.ArrayList([]const u8) = .empty;
    defer chunks.deinit(a);
    var i: usize = 0;
    while (i < s.len) {
        const e = chunkEnd(s, i, break_on_hyphens);
        try chunks.append(a, s[i..e]);
        i = e;
    }
    // 3. fill lines.
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var cur: std.ArrayList([]const u8) = .empty;
    defer cur.deinit(a);
    var lines: usize = 0;
    var pos: usize = 0;
    var front: []const u8 = if (chunks.items.len > 0) chunks.items[0] else "";
    // UTF-8 validity of the chunk `front` was sliced from, decided once per chunk (not per
    // output line: that made a long word quadratic). A suffix of an invalid chunk stays "invalid".
    var fv = std.unicode.utf8ValidateSlice(front);
    while (pos < chunks.items.len) {
        cur.clearRetainingCapacity();
        var cur_len: usize = 0;
        if (lines > 0 and allSpaces(front)) {
            pos += 1;
            if (pos < chunks.items.len) {
                front = chunks.items[pos];
                fv = std.unicode.utf8ValidateSlice(front);
            }
            if (pos >= chunks.items.len) break;
        }
        while (pos < chunks.items.len) {
            const l = cpLenUpTo(front, fv, width - cur_len +| 1);
            if (l > width - cur_len) break;
            try cur.append(a, front);
            cur_len += l;
            pos += 1;
            if (pos < chunks.items.len) {
                front = chunks.items[pos];
                fv = std.unicode.utf8ValidateSlice(front);
            }
        }
        if (pos < chunks.items.len and cpLenUpTo(front, fv, width +| 1) > width) {
            // Python's _handle_long_word.
            const space_left: usize = if (width < 1) 1 else width - cur_len;
            if (break_long_words) {
                var end_chars = space_left;
                if (break_on_hyphens and cpLenUpTo(front, fv, space_left +| 1) > space_left) {
                    const lim = charToByte(front, fv, space_left);
                    if (std.mem.findScalarLast(u8, front[0..lim], '-')) |h| {
                        // chunk.rfind('-', 0, space_left), as a character index.
                        const hc = cpLenUpTo(front[0..h], fv, std.math.maxInt(usize));
                        if (hc > 0) {
                            var other = false;
                            for (front[0..h]) |ch| other = other or ch != '-';
                            if (other) end_chars = hc + 1;
                        }
                    }
                }
                const eb = charToByte(front, fv, end_chars);
                // Nothing fits (the line is full): nothing is added, so the whitespace chunk
                // that ended the line is the one dropped below (Python 3.14's output).
                if (eb > 0) try cur.append(a, front[0..eb]);
                front = front[eb..];
            } else if (cur.items.len == 0) {
                try cur.append(a, front);
                pos += 1;
                if (pos < chunks.items.len) {
                    front = chunks.items[pos];
                    fv = std.unicode.utf8ValidateSlice(front);
                }
            }
        }
        if (cur.items.len > 0 and allSpaces(cur.items[cur.items.len - 1])) _ = cur.pop();
        if (cur.items.len > 0) {
            if (lines > 0) try out.append(a, '\n');
            for (cur.items) |c| try out.appendSlice(a, c);
            lines += 1;
            if (out.items.len > fnx.max_text_result) return error.TooLarge;
        }
    }
    return out.toOwnedSlice(a);
}

fn allSpaces(c: []const u8) bool {
    for (c) |b| if (b != ' ') return false;
    return true;
}

/// Characters of `t` (`valid`: `t` is valid UTF-8, else bytes count), but counting stops at
/// `limit`: the result is exact when it is below `limit`, `limit` otherwise. O(min(len, limit)).
fn cpLenUpTo(t: []const u8, valid: bool, limit: usize) usize {
    if (!valid) return @min(t.len, limit);
    var i: usize = 0;
    var k: usize = 0;
    while (i < t.len and k < limit) : (k += 1) i += std.unicode.utf8ByteSequenceLength(t[i]) catch 1;
    return k;
}

/// Byte offset of character `n` of `t` (past the end: `t.len`); `valid` as in `cpLenUpTo`.
fn charToByte(t: []const u8, valid: bool, n: usize) usize {
    if (!valid) return @min(n, t.len);
    var i: usize = 0;
    var k: usize = 0;
    while (i < t.len and k < n) : (k += 1) i += std.unicode.utf8ByteSequenceLength(t[i]) catch 1;
    return i;
}

fn isWordCh(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c >= 0x80;
}

fn isLetterCh(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_' or c >= 0x80;
}

fn isWordPunct(c: u8) bool {
    return isWordCh(c) or std.mem.indexOfScalar(u8, "!\"'&.,?", c) != null;
}

/// `-{2,}\w` at `e`.
fn emDashAt(s: []const u8, e: usize) bool {
    var k = e;
    while (k < s.len and s[k] == '-') k += 1;
    return k - e >= 2 and k < s.len and isWordCh(s[k]);
}

/// The end of the chunk starting at `i` in Python's `TextWrapper.wordsep_re` (or, without
/// `hyphens`, `wordsep_simple_re`: runs of spaces and of non-spaces).
fn chunkEnd(s: []const u8, i: usize, hyphens: bool) usize {
    if (s[i] == ' ') {
        var k = i;
        while (k < s.len and s[k] == ' ') k += 1;
        return k;
    }
    if (!hyphens) {
        var k = i;
        while (k < s.len and s[k] != ' ') k += 1;
        return k;
    }
    // (?<=wp) -{2,} (?=\w)
    if (s[i] == '-' and i > 0 and isWordPunct(s[i - 1]) and emDashAt(s, i)) {
        var k = i;
        while (k < s.len and s[k] == '-') k += 1;
        return k;
    }
    var e = i + 1;
    while (true) : (e += 1) {
        if (e >= s.len or s[e] == ' ') return e; // end of word
        if (s[e] == '-') {
            // hyphenated word: the two characters before the hyphen are letters, or
            // letter-hyphen-letter; and a letter, an optional hyphen and a letter follow.
            const behind = (e >= 2 and isLetterCh(s[e - 2]) and isLetterCh(s[e - 1])) or
                (e >= 3 and isLetterCh(s[e - 3]) and s[e - 2] == '-' and isLetterCh(s[e - 1]));
            if (behind and e + 1 < s.len and isLetterCh(s[e + 1]) and
                ((e + 2 < s.len and isLetterCh(s[e + 2])) or
                    (e + 3 < s.len and s[e + 2] == '-' and isLetterCh(s[e + 3]))))
                return e + 1;
        }
        // em-dash: a word character before, `--x` after.
        if (isWordPunct(s[e - 1]) and emDashAt(s, e)) return e;
    }
}

// ── frame verbs ──────────────────────────────────────────────────────────────

/// `splitColumns`' spec.
pub const SplitSpec = struct {
    col: []const u8,
    /// The separator (a literal, or with `regex` a pattern of the `regex` module's Rust
    /// grammar); null splits on runs of whitespace like Python's `split()`.
    by: ?[]const u8 = null,
    regex: bool = false,
    /// Most pieces per cell (pandas `n` + 1, polars `splitn`): the last is the rest. Null:
    /// all. Zero is `error.BadArgument`.
    limit: ?usize = null,
    /// Output column names are `prefix` followed by the piece number from 0 (pandas names
    /// the columns 0, 1, ...; polars' `split_exact` names them `field_0`, ...).
    prefix: []const u8 = "",
    /// Keep the source column in front of the new ones (else it is replaced by them).
    keep_source: bool = false,
};

/// pandas `Series.str.split(pat, n, expand=True)` and polars `str.split_exact` + `unnest`:
/// one column per piece, as many as the cell with the most pieces has; a cell with fewer
/// (and a null or non-text cell) has nulls there. The new columns take the source
/// column's place. More than `max_str_columns` pieces, or `rows x columns` past
/// `sp.max_join_cells`, is `error.TooLarge`.
pub fn splitColumns(a: std.mem.Allocator, f: Frame, spec: SplitSpec) StrError!Frame {
    const ci = f.columnIndex(spec.col) orelse return error.NoSuchColumn;
    if (spec.limit != null and spec.limit.? == 0) return error.BadArgument;
    if (spec.by) |b| if (b.len == 0) return error.BadArgument;
    var matcher: ?*regex.Matcher = null;
    if (spec.regex) {
        const by = spec.by orelse return error.BadArgument;
        const re = try a.create(regex.Regex);
        re.* = regex.Regex.compileOptions(a, by, .{ .syntax = .rust }) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.BadArgument;
        const m = try a.create(regex.Matcher);
        m.* = try regex.Matcher.init(a, re);
        matcher = m;
    }
    const src = f.columnAt(ci);
    var pieces: std.ArrayList(Value) = .empty;
    defer pieces.deinit(a);
    // Pass 1: the widest cell.
    var width: usize = 0;
    for (0..f.len) |ri| {
        pieces.clearRetainingCapacity();
        try piecesOf(a, &pieces, src.get(ri), spec, matcher, max_str_columns);
        width = @max(width, pieces.items.len);
        if (width > max_str_columns) return error.TooLarge;
    }
    if (width != 0 and f.len > sp.max_join_cells / width) return error.TooLarge;
    const builders = try a.alloc(fm.ColBuilder, width);
    for (builders) |*b| b.* = .{ .a = a, .hint = f.len };
    for (0..f.len) |ri| {
        pieces.clearRetainingCapacity();
        try piecesOf(a, &pieces, src.get(ri), spec, matcher, max_str_columns);
        for (builders, 0..) |*b, k| try b.append(if (k < pieces.items.len) pieces.items[k] else .null);
    }
    const extra = width + @intFromBool(spec.keep_source);
    const cols = try a.alloc(Column, f.columns.len - 1 + extra);
    const data = try a.alloc(ColumnData, cols.len);
    var n: usize = 0;
    for (f.columns, 0..) |c, i| {
        if (i != ci) {
            cols[n] = c;
            data[n] = f.columnAt(i);
            n += 1;
            continue;
        }
        if (spec.keep_source) {
            cols[n] = c;
            data[n] = f.columnAt(i);
            n += 1;
        }
        for (builders, 0..) |*b, k| {
            cols[n] = .{ .name = try a.print("{s}{d}", .{ spec.prefix, k }), .type = .text };
            data[n] = b.finish();
            n += 1;
        }
    }
    try checkNames(a, cols);
    return .{ .columns = cols, .data = data, .len = f.len };
}

fn checkNames(a: std.mem.Allocator, cols: []const Column) StrError!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (cols) |c| if ((try seen.getOrPut(a, c.name)).found_existing) return error.DuplicateColumn;
}

fn piecesOf(a: std.mem.Allocator, out: *std.ArrayList(Value), v: Value, spec: SplitSpec, m: ?*regex.Matcher, cap: usize) Error!void {
    // `error.TooLarge` as soon as more than `cap` pieces exist: the pieces are never all built first.
    if (v != .text) return;
    const t = v.text;
    const by = spec.by orelse return splitWsInto(a, out, t, spec.limit, cap);
    const max = spec.limit orelse std.math.maxInt(usize);
    if (m) |mm| {
        var it = mm.split(t, spec.limit);
        while (it.next()) |p| {
            try out.append(a, .{ .text = p });
            if (out.items.len > cap) return error.TooLarge;
        }
        return;
    }
    var at: usize = 0;
    while (out.items.len + 1 < max) {
        const hit = std.mem.findPos(u8, t, at, by) orelse break;
        try out.append(a, .{ .text = t[at..hit] });
        if (out.items.len > cap) return error.TooLarge;
        at = hit + by.len;
    }
    try out.append(a, .{ .text = t[at..] });
    if (out.items.len > cap) return error.TooLarge;
}

/// `getDummies`' spec.
pub const DummiesSpec = struct {
    col: []const u8,
    /// Separates the tokens of a cell (pandas `sep`, default "|"). Not empty.
    sep: []const u8 = "|",
    /// Output names are `prefix` + `prefix_sep` + token when `prefix` is given, else the
    /// token (pandas `str.get_dummies` names by token; `pd.get_dummies(prefix=)` adds it).
    prefix: ?[]const u8 = null,
    prefix_sep: []const u8 = "_",
    keep_source: bool = false,
    /// Bool columns (`pd.get_dummies`' default since pandas 2) instead of int 0/1 columns
    /// (`Series.str.get_dummies`, which this follows by default).
    as_bool: bool = false,
};

/// pandas `Series.str.get_dummies(sep)`: an int 0/1 column (bool with `as_bool`) per distinct token, sorted by token
/// (byte order), true where the cell has the token. A null or non-text cell is false in
/// every column. More than `max_str_columns` tokens, or `rows x tokens` past
/// `sp.max_join_cells`, is `error.TooLarge`. An empty cell has the token "" (as pandas).
pub fn getDummies(a: std.mem.Allocator, f: Frame, spec: DummiesSpec) StrError!Frame {
    const ci = f.columnIndex(spec.col) orelse return error.NoSuchColumn;
    if (spec.sep.len == 0) return error.BadArgument;
    const src = f.columnAt(ci);
    var set: std.StringHashMapUnmanaged(void) = .empty;
    defer set.deinit(a);
    for (0..f.len) |ri| {
        const v = src.get(ri);
        if (v != .text) continue;
        var at: usize = 0;
        while (true) {
            const hit = std.mem.findPos(u8, v.text, at, spec.sep);
            const tok = v.text[at .. hit orelse v.text.len];
            if (!set.contains(tok)) {
                if (set.count() >= max_str_columns) return error.TooLarge;
                try set.put(a, tok, {});
            }
            at = (hit orelse break) + spec.sep.len;
        }
    }
    const toks = try a.alloc([]const u8, set.count());
    defer a.free(toks);
    var it = set.keyIterator();
    for (toks) |*o| o.* = it.next().?.*;
    std.mem.sort([]const u8, toks, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    const width = toks.len;
    if (width != 0 and f.len > sp.max_join_cells / width) return error.TooLarge;
    const flags = try a.alloc(bool, f.len * width);
    defer a.free(flags);
    @memset(flags, false);
    var index: std.StringHashMapUnmanaged(usize) = .empty;
    defer index.deinit(a);
    for (toks, 0..) |tk, k| try index.put(a, tk, k);
    for (0..f.len) |ri| {
        const v = src.get(ri);
        if (v != .text) continue;
        var at: usize = 0;
        while (true) {
            const hit = std.mem.findPos(u8, v.text, at, spec.sep);
            flags[ri * width + index.get(v.text[at .. hit orelse v.text.len]).?] = true;
            at = (hit orelse break) + spec.sep.len;
        }
    }
    const cols = try a.alloc(Column, f.columns.len - 1 + width + @intFromBool(spec.keep_source));
    const data = try a.alloc(ColumnData, cols.len);
    var n: usize = 0;
    for (f.columns, 0..) |c, i| {
        if (i != ci or spec.keep_source) {
            cols[n] = c;
            data[n] = f.columnAt(i);
            n += 1;
            if (i != ci) continue;
        }
        for (toks, 0..) |tk, k| {
            const name = if (spec.prefix) |p| try std.mem.concat(a, u8, &.{ p, spec.prefix_sep, tk }) else tk;
            if (spec.as_bool) {
                const vals = try a.alloc(bool, f.len);
                for (vals, 0..) |*o, ri| o.* = flags[ri * width + k];
                cols[n] = .{ .name = name, .type = .bool };
                data[n] = .{ .bool = .{ .values = vals } };
            } else {
                const vals = try a.alloc(i64, f.len);
                for (vals, 0..) |*o, ri| o.* = @intFromBool(flags[ri * width + k]);
                cols[n] = .{ .name = name, .type = .int };
                data[n] = .{ .int = .{ .values = vals } };
            }
            n += 1;
        }
    }
    try checkNames(a, cols);
    return .{ .columns = cols, .data = data, .len = f.len };
}
