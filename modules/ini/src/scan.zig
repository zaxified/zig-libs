// SPDX-License-Identifier: MIT

//! The one line classifier behind everything in this module, and the two
//! allocation-free pull readers on top of it (`Scanner` over a slice,
//! `StreamScanner` over a `std.Io.Reader`). `parse` and `Editor` consume the
//! same events, so the dialects cannot drift apart. SPEC.md § Grammar is the
//! specification of `Classifier.feed`.

const std = @import("std");
const root = @import("root.zig");
const Options = root.Options;
const ParseError = root.ParseError;

pub const Event = union(enum) {
    blank: struct { line: usize },
    /// `text` is the trimmed line, comment character included.
    comment: struct { text: []const u8, line: usize },
    section: struct { name: []const u8, line: usize },
    entry: EntryEvent,
    /// One more line of the last entry's value (`Options.continuation_lines`).
    continuation: struct {
        text: []const u8,
        /// Blank lines swallowed before this one (`Options.empty_lines_in_values`):
        /// the value gains that many empty lines first. Their `.blank` events
        /// have already been delivered.
        blanks_before: usize,
        line: usize,
    },
    /// A line that is not any of the above: a strict reader stops here, a
    /// lenient one carries on. The reader itself always carries on.
    invalid: struct { err: ParseError, text: []const u8, line: usize },
};

pub const EntryEvent = struct {
    key: []const u8,
    /// First line of the value; empty when `has_value` is false.
    value: []const u8,
    /// False for a bare key (`Options.no_value_keys`).
    has_value: bool,
    line: usize,
};

/// Classifies one line at a time. Keeps the little state continuation needs.
pub const Classifier = struct {
    opts: Options,
    line: usize = 0,
    in_section: bool = false,
    /// A last entry exists that a deeper-indented line would continue.
    cont_active: bool = false,
    cont_has_value: bool = true,
    cont_indent: usize = 0,
    pending_blanks: usize = 0,

    /// `raw` is one line without its `\n`. Slices in the event point into it.
    pub fn feed(self: *Classifier, raw: []const u8) Event {
        const opts = &self.opts;
        self.line += 1;
        const line_no = self.line;
        const line = if (raw.len != 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        var indent: usize = 0;
        while (indent < line.len and (line[indent] == ' ' or line[indent] == '\t')) indent += 1;
        var content = std.mem.trimEnd(u8, line[indent..], " \t");

        if (content.len == 0) {
            if (self.cont_active) {
                if (opts.empty_lines_in_values) {
                    if (self.cont_has_value) self.pending_blanks += 1;
                } else self.cont_active = false;
            }
            return .{ .blank = .{ .line = line_no } };
        }
        if (std.mem.findScalar(u8, opts.comment_chars, content[0]) != null) {
            if (!opts.empty_lines_in_values) self.cont_active = false;
            return .{ .comment = .{ .text = content, .line = line_no } };
        }
        var cut = false;
        if (opts.inline_comments) {
            if (inlineCommentAt(content, opts.comment_chars)) |at| {
                content = std.mem.trimEnd(u8, content[0..at], " \t");
                cut = true;
            }
        }
        if (self.cont_active and opts.continuation_lines and indent > self.cont_indent) {
            if (!self.cont_has_value) {
                // A bare key has no value to continue (configparser 3.14 refuses).
                self.cont_active = false;
                self.pending_blanks = 0;
                return .{ .invalid = .{ .err = error.MissingSeparator, .text = content, .line = line_no } };
            }
            const blanks = self.pending_blanks;
            self.pending_blanks = 0;
            return .{ .continuation = .{ .text = content, .blanks_before = blanks, .line = line_no } };
        }
        self.cont_active = false;
        self.pending_blanks = 0;

        if (headerName(content, opts)) |name| {
            self.in_section = true;
            return .{ .section = .{ .name = name, .line = line_no } };
        }

        const sep = std.mem.findAny(u8, content, opts.separators);
        if (sep == null and !opts.no_value_keys)
            return .{ .invalid = .{ .err = error.MissingSeparator, .text = content, .line = line_no } };
        const key = std.mem.trimEnd(u8, content[0 .. sep orelse content.len], " \t");
        if (key.len == 0)
            return .{ .invalid = .{ .err = error.EmptyKey, .text = content, .line = line_no } };
        if (opts.locale_keys and !isLocaleKey(key))
            return .{ .invalid = .{ .err = error.InvalidKey, .text = content, .line = line_no } };
        if (!self.in_section and !opts.global_entries)
            return .{ .invalid = .{ .err = error.EntryOutsideSection, .text = content, .line = line_no } };

        var value: []const u8 = "";
        if (sep) |s| {
            // The value runs to the end of the LINE, not of `content`: with
            // `trim_values = false` its trailing whitespace is kept. An inline
            // comment was cut from `content`, which is then the line.
            value = std.mem.trimStart(u8, if (cut) content[s + 1 ..] else line[indent + s + 1 ..], " \t");
            if (opts.trim_values) value = std.mem.trimEnd(u8, value, " \t");
        }
        self.cont_active = true;
        self.cont_has_value = sep != null;
        self.cont_indent = indent;
        return .{ .entry = .{ .key = key, .value = value, .has_value = sep != null, .line = line_no } };
    }
};

/// The section name if `content` (a line without its surrounding whitespace)
/// is a header, else null -- and then it is read as an entry, which is how
/// both references treat `[a` or `[a=b`.
fn headerName(content: []const u8, opts: *const Options) ?[]const u8 {
    if (content[0] != '[') return null;
    const close = std.mem.findScalarLast(u8, content, ']') orelse return null;
    if (close < 2) return null; // `[]`: no name
    const name = content[1..close];
    if (!opts.header_trailing_text) {
        if (close != content.len - 1) return null;
        if (std.mem.findAny(u8, name, "[]") != null) return null;
    }
    return name;
}

/// `name` or `name[locale]`: see `Options.locale_keys`.
fn isLocaleKey(key: []const u8) bool {
    const open = std.mem.findScalar(u8, key, '[') orelse
        return std.mem.findScalar(u8, key, ']') == null;
    if (open == 0 or key[key.len - 1] != ']') return false;
    return std.mem.findAny(u8, key[open + 1 .. key.len - 1], "[] \t") == null;
}

/// Where the first comment character that follows a blank is. `content[0]`
/// is known not to be a comment character.
fn inlineCommentAt(content: []const u8, comment_chars: []const u8) ?usize {
    var i: usize = 1;
    while (i < content.len) : (i += 1) {
        if ((content[i - 1] == ' ' or content[i - 1] == '\t') and
            std.mem.findScalar(u8, comment_chars, content[i]) != null) return i;
    }
    return null;
}

const bom = "\xEF\xBB\xBF";

/// A pull reader over a whole text: no allocation, every slice points into
/// `text`. `Options.strict` is not looked at: a bad line is an `.invalid`
/// event and the reader carries on. Continued values arrive as `.continuation`
/// events, line by line.
pub const Scanner = struct {
    rest: ?[]const u8,
    classifier: Classifier,

    pub fn init(text: []const u8, opts: Options) Scanner {
        // A UTF-8 byte-order mark is skipped (neither reference does; see SPEC).
        const body = if (std.mem.startsWith(u8, text, bom)) text[3..] else text;
        return .{ .rest = if (body.len == 0) null else body, .classifier = .{ .opts = opts } };
    }

    pub fn next(self: *Scanner) ?Event {
        const rest = self.rest orelse return null;
        if (std.mem.findScalar(u8, rest, '\n')) |nl| {
            // The empty piece after a final newline is not a line.
            self.rest = if (nl + 1 == rest.len) null else rest[nl + 1 ..];
            return self.classifier.feed(rest[0..nl]);
        }
        self.rest = null;
        return self.classifier.feed(rest);
    }
};

/// `Scanner` over a `std.Io.Reader`, so a file need not be in memory: holds
/// one line at a time, in the reader's own buffer. Every slice of an event is
/// valid until the next `next`. A line longer than the reader's buffer is
/// `error.LineTooLong`, so the buffer is the limit.
pub const StreamScanner = struct {
    reader: *std.Io.Reader,
    classifier: Classifier,
    first: bool = true,

    pub const Error = error{ ReadFailed, LineTooLong };

    pub fn init(reader: *std.Io.Reader, opts: Options) StreamScanner {
        return .{ .reader = reader, .classifier = .{ .opts = opts } };
    }

    pub fn next(self: *StreamScanner) Error!?Event {
        var line = (self.reader.takeDelimiter('\n') catch |e| switch (e) {
            error.ReadFailed => return error.ReadFailed,
            error.StreamTooLong => return error.LineTooLong,
        }) orelse return null;
        if (self.first) {
            self.first = false;
            if (std.mem.startsWith(u8, line, bom)) line = line[3..];
        }
        return self.classifier.feed(line);
    }
};
