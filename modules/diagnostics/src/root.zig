// SPDX-License-Identifier: MIT
//! diagnostics — LSP-style structured validation-finding collector.
//!
//! A `Diagnostics` collector accumulates `Diagnostic` findings (error /
//! warning / info) emitted while validating a config / json5 / expression
//! tree, each carrying a dot-separated tree path, optional 1-based source
//! line/col (and end position), an optional in-expression byte offset/length
//! for token highlighting, a machine-readable code, a human message, and an
//! optional did-you-mean suggestion.
//!
//! All strings referenced by a `Diagnostic` are expected to outlive the
//! `Diagnostics` collector — typically both live in the same arena, freed in
//! one shot at the validation boundary. Callers that need diagnostics to
//! outlive that arena should dupe the strings first.
//!
//! Provenance: original work of the zig-libs authors (MIT). See ../README.md.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "LSP-style structured validation-finding collector — severity, dot-path, position, code, suggestion.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "LSP Diagnostic / rustc diagnostics",
    .deps = .{},
};

/// Finding severity.
pub const Severity = enum { @"error", warning, info };

/// One validation finding. `path` is dot-separated and points at a node in
/// the validated tree (not necessarily the raw source). Source position
/// fields are 1-based and may be null when the emit site has no ready access
/// to scanner position (e.g. a cross-node invariant detected at end of load).
pub const Diagnostic = struct {
    path: []const u8,
    /// The file (or other source name) the finding is in, for `render` and
    /// `sortByPosition`. Null when the caller validates a single unnamed
    /// source.
    file: ?[]const u8 = null,
    line: ?u32 = null,
    col: ?u32 = null,
    end_line: ?u32 = null,
    end_col: ?u32 = null,
    /// Byte offset inside an expression string for expr-internal findings.
    /// Useful for token highlighting in a GUI's expression panel. Null for
    /// non-expr diagnostics.
    expr_off: ?u32 = null,
    expr_len: ?u32 = null,
    severity: Severity,
    /// Machine-readable code, e.g. "config.unknown_key",
    /// "expr.unknown_function", "json5.duplicate_key". Used for icon/route
    /// selection and for filtering.
    code: []const u8,
    message: []const u8,
    /// Optional suggestion ("did you mean 'COALESCE'?"). Owned by the same
    /// allocator as the rest of the strings.
    suggest: ?[]const u8 = null,
    /// Secondary spans, each with its own message — "first defined here"
    /// next to a duplicate key (codespan's secondary labels, LSP's
    /// `relatedInformation`). The diagnostic's own position is the primary
    /// span.
    labels: ?[]const Label = null,
    /// Extra `note:` / `help:` lines beyond `suggest` (rustc's notes).
    notes: ?[]const Note = null,
    /// Where the `code` is documented (miette's code URL, LSP's
    /// `codeDescription.href`).
    code_url: ?[]const u8 = null,
    /// A machine-applicable edit (LSP quick-fix `TextEdit`).
    fix: ?Fix = null,
};

/// A secondary span. Positions as in `Diagnostic` (1-based, `col` in bytes,
/// the end exclusive).
pub const Label = struct {
    /// Null means the diagnostic's own `file`.
    file: ?[]const u8 = null,
    line: u32,
    col: ?u32 = null,
    end_line: ?u32 = null,
    end_col: ?u32 = null,
    message: []const u8 = "",
};

pub const NoteKind = enum { note, help };

pub const Note = struct {
    kind: NoteKind = .note,
    message: []const u8,
};

/// Replace the span [`line`:`col`, `end_line`:`end_col`) with `replacement`
/// (an empty span inserts). `end_*` default to the start.
pub const Fix = struct {
    /// Null means the diagnostic's own `file`.
    file: ?[]const u8 = null,
    line: u32,
    col: u32,
    end_line: ?u32 = null,
    end_col: ?u32 = null,
    replacement: []const u8,
};

/// Owned collector. All strings referenced by appended `Diagnostic`s are
/// expected to live as long as this collector — typically a shared arena
/// freed in one shot when validation is done. Callers that need persistent
/// ownership across allocator boundaries should dupe before append.
pub const Diagnostics = struct {
    items: std.ArrayList(Diagnostic),
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Diagnostics {
        return .{ .items = .empty, .alloc = alloc };
    }

    pub fn deinit(self: *Diagnostics) void {
        self.items.deinit(self.alloc);
    }

    pub fn append(self: *Diagnostics, d: Diagnostic) !void {
        try self.items.append(self.alloc, d);
    }

    pub fn count(self: *const Diagnostics) usize {
        return self.items.items.len;
    }

    /// Number of diagnostics matching the given severity. Used e.g. by a
    /// pre-save guard (only `.@"error"` blocks save) and by a validation
    /// summary line.
    pub fn countBySeverity(self: *const Diagnostics, sev: Severity) usize {
        var n: usize = 0;
        for (self.items.items) |d| {
            if (d.severity == sev) n += 1;
        }
        return n;
    }

    /// Order the findings by position: `file` (byte order, findings with
    /// no file last), then `line`, then `col` (a missing line or column
    /// sorts after every present one). Stable -- findings at the same
    /// position keep the order they were appended in, which is usually the
    /// order the validator found them.
    pub fn sortByPosition(self: *Diagnostics) void {
        std.mem.sort(Diagnostic, self.items.items, {}, positionLessThan);
    }

    /// `render` every finding, in the current order.
    pub fn render(self: *const Diagnostics, w: *std.Io.Writer, opts: RenderOptions) std.Io.Writer.Error!void {
        for (self.items.items) |d| try renderOne(w, d, opts);
    }

    /// `writeJson` over every finding.
    pub fn writeJson(self: *const Diagnostics, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try writeJsonSlice(w, self.items.items);
    }
};

fn positionLessThan(_: void, a: Diagnostic, b: Diagnostic) bool {
    if (a.file == null or b.file == null) {
        if (a.file != null and b.file == null) return true;
        if (a.file == null and b.file != null) return false;
    } else switch (std.mem.order(u8, a.file.?, b.file.?)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    inline for (.{ "line", "col" }) |f| {
        const x = @field(a, f);
        const y = @field(b, f);
        if (x != null and y == null) return true;
        if (x == null and y != null) return false;
        if (x != null and x.? != y.?) return x.? < y.?;
    }
    return false;
}

// ── rendering ────────────────────────────────────────────────────────────────

pub const RenderStyle = enum {
    /// One line per finding, compiler style, for logs, grep and editors that
    /// jump to `file:line:col`:
    /// `conf.json5:12:5: warning[config.unknown_key]: unknown key 'x' (at a.x); did you mean 'y'?`
    short,
    /// rustc style: the header line, a `-->` location line, the source line
    /// with carets under the span (when the source text is in
    /// `RenderOptions.sources`), then the path and suggestion as notes.
    snippet,
};

/// The text of one source, for `RenderStyle.snippet`.
pub const Source = struct {
    /// Matched against `Diagnostic.file`; for a finding with no `file`, the
    /// single entry of a one-element `sources` is used whatever its name.
    file: []const u8,
    text: []const u8,
};

pub const RenderOptions = struct {
    style: RenderStyle = .short,
    sources: []const Source = &.{},
    /// ANSI colour (severity in red/yellow/cyan, locations and secondary
    /// carets in blue). Off by default; the caller decides from isatty and
    /// NO_COLOR. Only this module's own escape sequences are coloured — text
    /// from findings is escaped exactly as without colour.
    color: bool = false,
};

const Sgr = struct {
    on: bool,
    fn sev(self: Sgr, s: Severity) []const u8 {
        if (!self.on) return "";
        return switch (s) {
            .@"error" => "\x1b[1;31m",
            .warning => "\x1b[1;33m",
            .info => "\x1b[1;36m",
        };
    }
    fn blue(self: Sgr) []const u8 {
        return if (self.on) "\x1b[1;34m" else "";
    }
    fn bold(self: Sgr) []const u8 {
        return if (self.on) "\x1b[1m" else "";
    }
    fn reset(self: Sgr) []const u8 {
        return if (self.on) "\x1b[0m" else "";
    }
};

/// A span to quote: the primary one or a label.
const Span = struct {
    file: ?[]const u8,
    line: ?u32,
    col: ?u32,
    end_line: ?u32,
    end_col: ?u32,
};

fn primarySpan(d: Diagnostic) Span {
    return .{ .file = d.file, .line = d.line, .col = d.col, .end_line = d.end_line, .end_col = d.end_col };
}

fn labelSpan(d: Diagnostic, l: Label) Span {
    return .{ .file = l.file orelse d.file, .line = l.line, .col = l.col, .end_line = l.end_line, .end_col = l.end_col };
}

fn digits(n: u32) usize {
    var buf: [10]u8 = undefined;
    return (std.fmt.bufPrint(&buf, "{d}", .{n}) catch unreachable).len;
}

/// Write one finding as text. `line`/`col` are 1-based, `col` counted in
/// bytes; `end_line`/`end_col`, when present, end the span exclusively (as
/// in LSP). Every string from the finding (and the quoted source line) is
/// written with control characters escaped (`\n`, `\x1b`, ...; tab stays
/// a tab in the source line), because findings usually quote the input being
/// validated and are printed to a terminal: a key name carrying an escape
/// sequence must not reach it raw, and a `short` finding must stay one line.
/// Carets line up under the span for tabs and multi-byte UTF-8 (one column
/// per code point); double-width characters are not accounted for.
pub fn renderOne(w: *std.Io.Writer, d: Diagnostic, opts: RenderOptions) std.Io.Writer.Error!void {
    const c: Sgr = .{ .on = opts.color };
    switch (opts.style) {
        .short => {
            if (try writeLocation(w, primarySpan(d))) try w.writeAll(": ");
            try writeHeader(w, d, c);
            if (d.path.len > 0) {
                try w.writeAll(" (at ");
                try writeEscaped(w, d.path);
                try w.writeByte(')');
            }
            if (d.suggest) |s| {
                try w.writeAll("; ");
                try writeEscaped(w, s);
            }
            if (d.labels) |labels| for (labels) |l| {
                try w.writeAll("; ");
                if (try writeLocation(w, labelSpan(d, l))) try w.writeAll(": ");
                try writeEscaped(w, l.message);
            };
            if (d.notes) |notes| for (notes) |n| {
                try w.print("; {s}: ", .{@tagName(n.kind)});
                try writeEscaped(w, n.message);
            };
            if (d.fix) |f| {
                try w.writeAll("; fix: ");
                try writeFix(w, d, f);
            }
            if (d.code_url) |u| {
                try w.writeAll("; see ");
                try writeEscaped(w, u);
            }
            try w.writeByte('\n');
        },
        .snippet => {
            try writeHeader(w, d, c);
            try w.writeByte('\n');
            // One gutter width for every quoted line, so the bars align.
            const primary = primarySpan(d);
            var width: usize = 0;
            if (sourceLine(primary, opts.sources) != null) width = digits(primary.line.?);
            if (d.labels) |labels| for (labels) |l| {
                if (sourceLine(labelSpan(d, l), opts.sources) != null) width = @max(width, digits(l.line));
            };
            try writeSpanBlock(w, primary, "-->", '^', c.sev(d.severity), "", width, opts.sources, c);
            if (d.labels) |labels| for (labels) |l| {
                try writeSpanBlock(w, labelSpan(d, l), ":::", '-', c.blue(), l.message, width, opts.sources, c);
            };
            if (d.path.len > 0) try writeNote(w, width, c, "at", d.path);
            if (d.notes) |notes| for (notes) |n| try writeNote(w, width, c, @tagName(n.kind), n.message);
            if (d.suggest) |s| try writeNote(w, width, c, "help", s);
            if (d.fix) |f| {
                try w.splatByteAll(' ', width);
                try w.print(" {s}={s} {s}fix{s}: ", .{ c.blue(), c.reset(), c.bold(), c.reset() });
                try writeFix(w, d, f);
                try w.writeByte('\n');
            }
            if (d.code_url) |u| try writeNote(w, width, c, "see", u);
        },
    }
}

fn writeNote(w: *std.Io.Writer, width: usize, c: Sgr, kind: []const u8, text: []const u8) std.Io.Writer.Error!void {
    try w.splatByteAll(' ', width);
    try w.print(" {s}={s} {s}{s}{s}: ", .{ c.blue(), c.reset(), c.bold(), kind, c.reset() });
    try writeEscaped(w, text);
    try w.writeByte('\n');
}

/// `replace 3:5..3:9 with "x"` / `insert "x" at 3:5` (positions in the
/// diagnostic's file unless the fix names another).
fn writeFix(w: *std.Io.Writer, d: Diagnostic, f: Fix) std.Io.Writer.Error!void {
    const el = f.end_line orelse f.line;
    const ec = f.end_col orelse f.col;
    const empty = el == f.line and ec == f.col;
    if (empty) {
        try w.writeAll("insert \"");
        try writeEscaped(w, f.replacement);
        try w.writeAll("\" at ");
    } else try w.writeAll("replace ");
    if (f.file orelse d.file) |file| {
        try writeEscaped(w, file);
        try w.writeByte(':');
    }
    try w.print("{d}:{d}", .{ f.line, f.col });
    if (!empty) {
        try w.print("..{d}:{d} with \"", .{ el, ec });
        try writeEscaped(w, f.replacement);
        try w.writeByte('"');
    }
}

/// `--> location` (or `::: location` for a label), then the quoted line with
/// `mark` characters under the span and the label message after them. A span
/// with no quotable source line is just the location line (plus message).
fn writeSpanBlock(
    w: *std.Io.Writer,
    span: Span,
    arrow: []const u8,
    mark: u8,
    mark_color: []const u8,
    message: []const u8,
    width: usize,
    sources: []const Source,
    c: Sgr,
) std.Io.Writer.Error!void {
    if (span.file == null and span.line == null) return;
    const quoted = sourceLine(span, sources);
    try w.splatByteAll(' ', width);
    try w.print("{s}{s}{s} ", .{ c.blue(), arrow, c.reset() });
    _ = try writeLocation(w, span);
    if (quoted == null and message.len > 0) {
        try w.writeAll(": ");
        try writeEscaped(w, message);
    }
    try w.writeByte('\n');
    const text = quoted orelse return;
    try w.splatByteAll(' ', width);
    try w.print(" {s}|{s}\n", .{ c.blue(), c.reset() });
    try w.print("{s}", .{c.blue()});
    try w.splatByteAll(' ', width - digits(span.line.?));
    try w.print("{d} |{s} ", .{ span.line.?, c.reset() });
    try writeSourceLine(w, text);
    try w.writeByte('\n');
    try w.splatByteAll(' ', width);
    try w.print(" {s}|{s} ", .{ c.blue(), c.reset() });
    try writeCarets(w, span, text, mark, mark_color, c.reset());
    if (message.len > 0) {
        try w.writeByte(' ');
        try writeEscaped(w, message);
    }
    try w.writeByte('\n');
}

/// `severity[code]: message`.
fn writeHeader(w: *std.Io.Writer, d: Diagnostic, c: Sgr) std.Io.Writer.Error!void {
    try w.writeAll(c.sev(d.severity));
    try w.writeAll(@tagName(d.severity));
    if (d.code.len > 0) {
        try w.writeByte('[');
        try writeEscaped(w, d.code);
        try w.writeByte(']');
    }
    try w.writeAll(c.reset());
    try w.writeAll(c.bold());
    try w.writeAll(": ");
    try writeEscaped(w, d.message);
    try w.writeAll(c.reset());
}

/// `file:line:col`, as much of it as is known. Returns whether anything was
/// written.
fn writeLocation(w: *std.Io.Writer, d: Span) std.Io.Writer.Error!bool {
    var any = false;
    if (d.file) |f| {
        try writeEscaped(w, f);
        any = true;
    }
    if (d.line) |l| {
        if (any) try w.writeByte(':');
        try w.print("{d}", .{l});
        if (d.col) |c| try w.print(":{d}", .{c});
        any = true;
    }
    return any;
}

fn writeEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    var start: usize = 0;
    for (s, 0..) |c, i| {
        if (c >= 0x20 and c != 0x7f) continue;
        try w.writeAll(s[start..i]);
        switch (c) {
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.print("\\x{x:0>2}", .{c}),
        }
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

/// The quoted source line keeps tabs (so the carets, which copy them, stay
/// aligned) and shows every other control character as `?` -- one column,
/// like the byte it replaces.
fn writeSourceLine(w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    var start: usize = 0;
    for (text, 0..) |c, i| {
        if (c == '\t' or (c >= 0x20 and c != 0x7f)) continue;
        try w.writeAll(text[start..i]);
        try w.writeByte('?');
        start = i + 1;
    }
    try w.writeAll(text[start..]);
}

/// The text of line `d.line` (without its line break) from the matching
/// source, or null when there is nothing to quote.
fn sourceLine(d: Span, sources: []const Source) ?[]const u8 {
    const line = d.line orelse return null;
    if (line == 0) return null;
    const src = blk: {
        if (d.file) |f| {
            for (sources) |s| if (std.mem.eql(u8, s.file, f)) break :blk s.text;
            return null;
        }
        if (sources.len == 1) break :blk sources[0].text;
        return null;
    };
    var it = std.mem.splitScalar(u8, src, '\n');
    var n: u32 = 1;
    while (it.next()) |l| : (n += 1) {
        if (n == line) return std.mem.trimEnd(u8, l, "\r");
    }
    return null;
}

/// Display columns of `bytes`: one per code point (UTF-8 continuation
/// bytes take none).
fn columns(bytes: []const u8) usize {
    var n: usize = 0;
    for (bytes) |b| {
        if (b & 0xC0 != 0x80) n += 1;
    }
    return n;
}

fn writeCarets(w: *std.Io.Writer, d: Span, text: []const u8, mark: u8, on: []const u8, off: []const u8) std.Io.Writer.Error!void {
    const col: usize = @min(@as(usize, d.col orelse 1) -| 1, text.len);
    // Indent with the line's own bytes -- a tab where it had one, a space for
    // every other column -- so the caret sits under the span on any tab width.
    for (text[0..col]) |b| {
        if (b == '\t') {
            try w.writeByte('\t');
        } else if (b & 0xC0 != 0x80) {
            try w.writeByte(' ');
        }
    }
    const end: usize = blk: {
        const el = d.end_line orelse break :blk col + 1;
        if (el > d.line.?) break :blk text.len;
        if (el < d.line.?) break :blk col + 1;
        const ec = d.end_col orelse break :blk col + 1;
        break :blk @min(@as(usize, ec) -| 1, text.len);
    };
    const n = if (end > col) columns(text[col..@min(end, text.len)]) else 0;
    try w.writeAll(on);
    try w.splatByteAll(mark, @max(n, 1));
    try w.writeAll(off);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

/// Serialize findings as a JSON array of objects whose keys are
/// `Diagnostic`'s field names; absent (null) fields are omitted and
/// `severity` is a string (`"error"`, `"warning"`, `"info"`). Positions stay
/// as they are here, 1-based -- a caller emitting LSP converts to its
/// 0-based `range`.
pub fn writeJsonSlice(w: *std.Io.Writer, items: []const Diagnostic) std.Io.Writer.Error!void {
    std.json.Stringify.value(items, .{ .emit_null_optional_fields = false }, w) catch |e| switch (e) {
        error.WriteFailed => return error.WriteFailed,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Diagnostics: append + count + countBySeverity" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    try diag.append(.{
        .path = "conversion_templates.x.data_dir",
        .severity = .@"error",
        .code = "config.empty_required",
        .message = "data_dir must not be empty",
    });
    try diag.append(.{
        .path = "conversion_templates.x.unknown_key",
        .line = 12,
        .col = 5,
        .severity = .warning,
        .code = "config.unknown_key",
        .message = "unknown key 'unknown_key'",
        .suggest = "did you mean 'file_pattern_in'?",
    });
    try diag.append(.{
        .path = "conversion_templates.x.maps",
        .severity = .info,
        .code = "config.empty_optional",
        .message = "empty map; no remapping will occur",
    });

    try testing.expectEqual(@as(usize, 3), diag.count());
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.@"error"));
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.warning));
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.info));
}

test "Diagnostics: empty collector" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    try testing.expectEqual(@as(usize, 0), diag.count());
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.@"error"));
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.warning));
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.info));
}

test "Diagnostic: suggest field defaults to null and optional positions stay null" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    try diag.append(.{
        .path = "conversion_templates.x.data_dir",
        .severity = .@"error",
        .code = "config.empty_required",
        .message = "data_dir must not be empty",
    });

    const d = diag.items.items[0];
    try testing.expectEqual(@as(?[]const u8, null), d.suggest);
    try testing.expectEqual(@as(?u32, null), d.line);
    try testing.expectEqual(@as(?u32, null), d.col);
    try testing.expectEqual(@as(?u32, null), d.end_line);
    try testing.expectEqual(@as(?u32, null), d.end_col);
    try testing.expectEqual(@as(?u32, null), d.expr_off);
    try testing.expectEqual(@as(?u32, null), d.expr_len);
}

test "Diagnostics: countBySeverity across a mixed, unbalanced set" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    // Two errors, three warnings, one info — deliberately unbalanced to
    // catch an off-by-one or wrong-severity bug in the counting loop.
    const severities = [_]Severity{
        .@"error", .warning, .warning, .@"error", .warning, .info,
    };
    for (severities) |sev| {
        try diag.append(.{
            .path = "p",
            .severity = sev,
            .code = "c",
            .message = "m",
        });
    }

    try testing.expectEqual(@as(usize, 6), diag.count());
    try testing.expectEqual(@as(usize, 2), diag.countBySeverity(.@"error"));
    try testing.expectEqual(@as(usize, 3), diag.countBySeverity(.warning));
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.info));
}

fn renderToString(buf: []u8, d: Diagnostic, opts: RenderOptions) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try renderOne(&w, d, opts);
    return w.buffered();
}

const unknown_key: Diagnostic = .{
    .path = "templates.x.unknwn",
    .file = "conf.json5",
    .line = 2,
    .col = 3,
    .end_line = 2,
    .end_col = 9,
    .severity = .warning,
    .code = "config.unknown_key",
    .message = "unknown key 'unknwn'",
    .suggest = "did you mean 'unknown'?",
};

test "render short: one line, location, severity[code], path, suggestion" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "conf.json5:2:3: warning[config.unknown_key]: unknown key 'unknwn' (at templates.x.unknwn); did you mean 'unknown'?\n",
        try renderToString(&buf, unknown_key, .{}),
    );
    // Whatever is unknown is left out, never printed as "null" or "0".
    try testing.expectEqualStrings(
        "error: data_dir must not be empty\n",
        try renderToString(&buf, .{ .path = "", .severity = .@"error", .code = "", .message = "data_dir must not be empty" }, .{}),
    );
    try testing.expectEqualStrings(
        "7: info[c]: m (at p)\n",
        try renderToString(&buf, .{ .path = "p", .line = 7, .severity = .info, .code = "c", .message = "m" }, .{}),
    );
}

test "render snippet: source line with carets under the span" {
    var buf: [512]u8 = undefined;
    const src: Source = .{ .file = "conf.json5", .text = "{\n  unknwn: 1,\n}\n" };
    try testing.expectEqualStrings(
        \\warning[config.unknown_key]: unknown key 'unknwn'
        \\ --> conf.json5:2:3
        \\  |
        \\2 |   unknwn: 1,
        \\  |   ^^^^^^
        \\  = at: templates.x.unknwn
        \\  = help: did you mean 'unknown'?
        \\
    , try renderToString(&buf, unknown_key, .{ .style = .snippet, .sources = &.{src} }));
}

test "render snippet: without the source text, only the header, location and notes" {
    var buf: [512]u8 = undefined;
    const other: Source = .{ .file = "other.json5", .text = "{\n  unknwn: 1,\n}\n" };
    try testing.expectEqualStrings(
        \\warning[config.unknown_key]: unknown key 'unknwn'
        \\--> conf.json5:2:3
        \\ = at: templates.x.unknwn
        \\ = help: did you mean 'unknown'?
        \\
    , try renderToString(&buf, unknown_key, .{ .style = .snippet, .sources = &.{other} }));
    // A line past the end of the source quotes nothing either.
    var past = unknown_key;
    past.line = 40;
    const src: Source = .{ .file = "conf.json5", .text = "{}\n" };
    try testing.expect(std.mem.indexOf(u8, try renderToString(&buf, past, .{ .style = .snippet, .sources = &.{src} }), " | ") == null);
}

test "render snippet: carets align after tabs and multi-byte UTF-8, a span runs to the end of a multi-line range" {
    var buf: [512]u8 = undefined;
    // "\tné: x" -- tab, 'n', 'é' (2 bytes), ':' ... the key "x" is at byte col 7.
    const src: Source = .{ .file = "f", .text = "\tn\xC3\xA9: xyz" };
    const d: Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 7, .end_line = 1, .end_col = 10, .severity = .@"error", .code = "", .message = "bad" };
    try testing.expectEqualStrings(
        "error: bad\n --> f:1:7\n  |\n1 | \tn\xC3\xA9: xyz\n  | \t    ^^^\n",
        try renderToString(&buf, d, .{ .style = .snippet, .sources = &.{src} }),
    );
    // A span ending on a later line underlines to the end of this one; a
    // finding with no end gets one caret; a col past the end clamps.
    var multi = d;
    multi.end_line = 3;
    try testing.expect(std.mem.endsWith(u8, try renderToString(&buf, multi, .{ .style = .snippet, .sources = &.{src} }), "  | \t    ^^^\n"));
    var one = d;
    one.end_line = null;
    one.end_col = null;
    try testing.expect(std.mem.endsWith(u8, try renderToString(&buf, one, .{ .style = .snippet, .sources = &.{src} }), "  | \t    ^\n"));
    var far = one;
    far.col = 99;
    try testing.expect(std.mem.endsWith(u8, try renderToString(&buf, far, .{ .style = .snippet, .sources = &.{src} }), "  | \t       ^\n"));
}

test "render: a finding with no file uses the only source" {
    var buf: [512]u8 = undefined;
    const d: Diagnostic = .{ .path = "", .line = 1, .col = 1, .severity = .info, .code = "", .message = "m" };
    try testing.expectEqualStrings(
        "info: m\n --> 1:1\n  |\n1 | abc\n  | ^\n",
        try renderToString(&buf, d, .{ .style = .snippet, .sources = &.{.{ .file = "whatever", .text = "abc\r\ndef" }} }),
    );
}

test "render: control characters from the input never reach the terminal raw" {
    var buf: [512]u8 = undefined;
    // A key name carrying an ANSI escape and a newline, quoted into the
    // message, the path and the suggestion by a validator.
    const d: Diagnostic = .{
        .path = "a.\x1b[2Jb",
        .file = "f",
        .line = 1,
        .col = 1,
        .severity = .@"error",
        .code = "c",
        .message = "unknown key '\x1b[31mx\nfake: error'",
        .suggest = "did you mean '\x07'?",
    };
    const short = try renderToString(&buf, d, .{});
    try testing.expectEqualStrings(
        "f:1:1: error[c]: unknown key '\\x1b[31mx\\nfake: error' (at a.\\x1b[2Jb); did you mean '\\x07'?\n",
        short,
    );
    const snip = try renderToString(&buf, d, .{ .style = .snippet, .sources = &.{.{ .file = "f", .text = "\x1b]0;t\x07k: 1" }} });
    try testing.expect(std.mem.indexOfScalar(u8, snip, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, snip, 0x07) == null);
    try testing.expect(std.mem.indexOf(u8, snip, "1 | ?]0;t?k: 1\n") != null);
}

test "sortByPosition: file, line, col; unknowns last; stable for ties" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();
    const entries = [_]Diagnostic{
        .{ .path = "0", .severity = .info, .code = "", .message = "" }, // no file, no line
        .{ .path = "1", .file = "b", .line = 1, .severity = .info, .code = "", .message = "" },
        .{ .path = "2", .file = "a", .line = 3, .col = 2, .severity = .info, .code = "", .message = "" },
        .{ .path = "3", .file = "a", .line = 3, .severity = .info, .code = "", .message = "" }, // no col
        .{ .path = "4", .file = "a", .line = 3, .col = 1, .severity = .info, .code = "", .message = "" },
        .{ .path = "5", .file = "a", .severity = .info, .code = "", .message = "" }, // no line
        .{ .path = "6", .file = "a", .line = 3, .col = 2, .severity = .info, .code = "", .message = "" }, // tie with "2"
        .{ .path = "7", .line = 1, .severity = .info, .code = "", .message = "" }, // no file, a line
    };
    for (entries) |e| try diag.append(e);
    diag.sortByPosition();
    var order: [entries.len]u8 = undefined;
    for (diag.items.items, 0..) |d, i| order[i] = d.path[0];
    try testing.expectEqualStrings("42635170", &order);
}

test "writeJson: field names as keys, nulls omitted, severity as a string" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();
    try diag.append(unknown_key);
    try diag.append(.{ .path = "p", .severity = .@"error", .code = "c", .message = "say \"hi\"\n" });
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try diag.writeJson(&w);
    try testing.expectEqualStrings(
        \\[{"path":"templates.x.unknwn","file":"conf.json5","line":2,"col":3,"end_line":2,"end_col":9,"severity":"warning","code":"config.unknown_key","message":"unknown key 'unknwn'","suggest":"did you mean 'unknown'?"},{"path":"p","severity":"error","code":"c","message":"say \"hi\"\n"}]
    , w.buffered());
    // It is JSON: std's parser reads it back.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, w.buffered(), .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.value.array.items.len);
}

test "Diagnostics.render renders every finding in order" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();
    try diag.append(.{ .path = "", .line = 2, .severity = .info, .code = "", .message = "b" });
    try diag.append(.{ .path = "", .line = 1, .severity = .info, .code = "", .message = "a" });
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try diag.render(&w, .{});
    try testing.expectEqualStrings("2: info: b\n1: info: a\n", w.buffered());
}

// ── labels, notes, fix-its, code URL, colour (2026-10-04) ───────────────────

fn renderAlloc(d: Diagnostic, opts: RenderOptions) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try renderOne(&out.writer, d, opts);
    return out.toOwnedSlice();
}

const dup_src =
    \\{
    \\  a: 1,
    \\  b: 2,
    \\  a: 3,
    \\}
;

const dup: Diagnostic = .{
    .path = "a",
    .file = "c.json5",
    .line = 4,
    .col = 3,
    .end_line = 4,
    .end_col = 4,
    .severity = .@"error",
    .code = "json5.duplicate_key",
    .message = "duplicate key 'a'",
    .labels = &.{.{ .line = 2, .col = 3, .end_line = 2, .end_col = 4, .message = "first defined here" }},
    .notes = &.{.{ .message = "the later value would silently win" }},
    .fix = .{ .line = 4, .col = 3, .end_line = 4, .end_col = 4, .replacement = "c" },
    .code_url = "https://example.invalid/json5/duplicate_key",
    .suggest = "rename one of them",
};

test "snippet: a secondary label is quoted under ::: with '-' marks, then notes, help, fix, see" {
    // Layout derived by hand: both quoted lines are 1 digit, so the gutter is
    // one column; the primary span 4:3..4:4 is one '^' under 'a' (two spaces
    // in), the label 2:3..2:4 one '-' under the first 'a'.
    const got = try renderAlloc(dup, .{ .style = .snippet, .sources = &.{.{ .file = "c.json5", .text = dup_src }} });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\error[json5.duplicate_key]: duplicate key 'a'
        \\ --> c.json5:4:3
        \\  |
        \\4 |   a: 3,
        \\  |   ^
        \\ ::: c.json5:2:3
        \\  |
        \\2 |   a: 1,
        \\  |   - first defined here
        \\  = at: a
        \\  = note: the later value would silently win
        \\  = help: rename one of them
        \\  = fix: replace c.json5:4:3..4:4 with "c"
        \\  = see: https://example.invalid/json5/duplicate_key
        \\
    , got);
}

test "short: labels, notes, fix and URL stay on the one line" {
    const got = try renderAlloc(dup, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        "c.json5:4:3: error[json5.duplicate_key]: duplicate key 'a' (at a); rename one of them; " ++
            "c.json5:2:3: first defined here; note: the later value would silently win; " ++
            "fix: replace c.json5:4:3..4:4 with \"c\"; see https://example.invalid/json5/duplicate_key\n",
        got,
    );
}

test "snippet: gutter widens to the longest quoted line number; unquotable label is a location line" {
    // Line 10 needs two gutter columns, so line 2's number is padded.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (1..11) |i| try text.print(testing.allocator, "line{d}\n", .{i});
    const d: Diagnostic = .{
        .path = "",
        .file = "f",
        .line = 2,
        .col = 1,
        .severity = .warning,
        .code = "x",
        .message = "m",
        .labels = &.{
            // `end_col` counts only with `end_line` (as for the primary span).
            .{ .line = 10, .col = 1, .end_line = 10, .end_col = 7, .message = "here" },
            .{ .file = "other", .line = 1, .message = "elsewhere" }, // no source text
        },
    };
    const got = try renderAlloc(d, .{ .style = .snippet, .sources = &.{.{ .file = "f", .text = text.items }} });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\warning[x]: m
        \\  --> f:2:1
        \\   |
        \\ 2 | line2
        \\   | ^
        \\  ::: f:10:1
        \\   |
        \\10 | line10
        \\   | ------ here
        \\  ::: other:1: elsewhere
        \\
    , got);
}

test "fix: an empty span is an insertion; label and fix text is escaped" {
    const d: Diagnostic = .{
        .path = "",
        .line = 1,
        .col = 5,
        .severity = .info,
        .code = "",
        .message = "m",
        .labels = &.{.{ .line = 1, .message = "bad\x1b[31m" }},
        .fix = .{ .line = 1, .col = 5, .replacement = "\n;" },
    };
    const got = try renderAlloc(d, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("1:5: info: m; 1: bad\\x1b[31m; fix: insert \"\\n;\" at 1:5\n", got);
}

test "colour: SGR only around our own parts, finding text still escaped; off is byte-identical" {
    const src = [_]Source{.{ .file = "c.json5", .text = dup_src }};
    const plain = try renderAlloc(dup, .{ .style = .snippet, .sources = &src });
    defer testing.allocator.free(plain);
    const col = try renderAlloc(dup, .{ .style = .snippet, .sources = &src, .color = true });
    defer testing.allocator.free(col);
    // Stripping every SGR sequence from the coloured output gives the plain one.
    var stripped: std.ArrayList(u8) = .empty;
    defer stripped.deinit(testing.allocator);
    var i: usize = 0;
    while (i < col.len) {
        if (col[i] == 0x1b) {
            i = std.mem.indexOfScalarPos(u8, col, i, 'm').? + 1;
            continue;
        }
        try stripped.append(testing.allocator, col[i]);
        i += 1;
    }
    try testing.expectEqualStrings(plain, stripped.items);
    try testing.expect(std.mem.startsWith(u8, col, "\x1b[1;31merror[json5.duplicate_key]\x1b[0m"));
    try testing.expect(std.mem.indexOf(u8, col, "\x1b[1;34m-\x1b[0m first defined here") != null);
    // A finding carrying an escape sequence still cannot emit one.
    var hostile = dup;
    hostile.message = "\x1b[2J";
    const h = try renderAlloc(hostile, .{ .color = true });
    defer testing.allocator.free(h);
    try testing.expect(std.mem.indexOf(u8, h, "\x1b[2J") == null);
    try testing.expect(std.mem.indexOf(u8, h, "\\x1b[2J") != null);
}

test "JSON: new fields appear when set and are omitted when not" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeJsonSlice(&out.writer, &.{ dup, .{ .path = "p", .severity = .info, .code = "c", .message = "m" } });
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.written(), .{});
    defer parsed.deinit();
    const first = parsed.value.array.items[0].object;
    const lab = first.get("labels").?.array.items[0].object;
    try testing.expectEqual(@as(i64, 2), lab.get("line").?.integer);
    try testing.expectEqualStrings("first defined here", lab.get("message").?.string);
    try testing.expectEqualStrings("note", first.get("notes").?.array.items[0].object.get("kind").?.string);
    try testing.expectEqualStrings("c", first.get("fix").?.object.get("replacement").?.string);
    try testing.expectEqualStrings("https://example.invalid/json5/duplicate_key", first.get("code_url").?.string);
    const second = parsed.value.array.items[1].object;
    for ([_][]const u8{ "labels", "notes", "fix", "code_url" }) |k| try testing.expect(second.get(k) == null);
}

test "note kinds are named, and a hostile code URL is escaped in both styles" {
    // Mutation 2026-10-04: a `help` note rendered as `note`, and the URL
    // written raw, both survived the tests above.
    const d: Diagnostic = .{
        .path = "",
        .severity = .warning,
        .code = "c",
        .message = "m",
        .notes = &.{ .{ .kind = .help, .message = "try this" }, .{ .message = "fyi" } },
        .code_url = "https://x.invalid/\x1b]8;;evil\x07",
    };
    const snip = try renderAlloc(d, .{ .style = .snippet });
    defer testing.allocator.free(snip);
    try testing.expectEqualStrings(
        \\warning[c]: m
        \\ = help: try this
        \\ = note: fyi
        \\ = see: https://x.invalid/\x1b]8;;evil\x07
        \\
    , snip);
    const short = try renderAlloc(d, .{});
    defer testing.allocator.free(short);
    try testing.expectEqualStrings("warning[c]: m; help: try this; note: fyi; see https://x.invalid/\\x1b]8;;evil\\x07\n", short);
}
