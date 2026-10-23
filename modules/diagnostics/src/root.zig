// SPDX-License-Identifier: MIT
//! diagnostics — LSP-style structured validation-finding collector.
//!
//! A `Diagnostics` collector accumulates `Diagnostic` findings (error /
//! warning / info / hint) emitted while validating a config / json5 / expression
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
const width_table = @import("width_table.zig");

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

/// Finding severity. The four levels of LSP's `DiagnosticSeverity`
/// (`hint` is 4: the least important, "could be better" findings).
/// `hint` renders like `info` (the same colour), under its own word.
pub const Severity = enum { @"error", warning, info, hint };

/// LSP's `DiagnosticTag`: extra rendering hints for an editor. They are written
/// by `writeLsp`; the text renderers ignore them.
pub const Tag = enum { unnecessary, deprecated };

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
    /// non-expr diagnostics. Data for the consumer only: the offset is into the
    /// expression's own text, not into the source lines, so neither the text
    /// renderers nor `writeLsp` draw or convert it.
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
    /// The message printed next to the primary span (codespan's primary
    /// label message); `message` is the header. `snippet` only.
    span_message: ?[]const u8 = null,
    /// Extra `note:` / `help:` lines beyond `suggest` (rustc's notes).
    notes: ?[]const Note = null,
    /// Where the `code` is documented (miette's code URL, LSP's
    /// `codeDescription.href`).
    code_url: ?[]const u8 = null,
    /// A machine-applicable edit (LSP quick-fix `TextEdit`).
    fix: ?Fix = null,
    /// LSP `DiagnosticTag`s (`writeLsp` only).
    tags: ?[]const Tag = null,
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
    /// Draw as a primary span (`^` under the source, the severity colour)
    /// instead of a secondary one (`-`). Null is secondary.
    primary: ?bool = null,
};

/// `plain` is codespan's note: the bullet and the text, no `note:` prefix,
/// and a `\n` in the message starts an aligned continuation line.
pub const NoteKind = enum { note, help, plain };

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
    /// codespan-reporting's "rich" style (ASCII): the header line, a `-->`
    /// location line, the source lines with carets under the spans and the
    /// labels' messages (several labels of one line share it; a span over
    /// several lines is drawn with `/ |` markers), when the source text is in
    /// `RenderOptions.sources`; then the notes, the path, the suggestion, and
    /// an empty line. See "snippet layout" below for the bounds.
    snippet,
};

/// The text of one source, for `RenderStyle.snippet`.
pub const Source = struct {
    /// Matched against `Diagnostic.file`; for a finding with no `file`, the
    /// single entry of a one-element `sources` is used whatever its name.
    file: []const u8,
    text: []const u8,
    /// Optional: where each line of `text` starts (`indexLines`). With it a
    /// quoted line is found in O(1); without it every label scans `text` from
    /// the top (`memchr` per line), which is fine for one diagnostic and
    /// quadratic for thousands over a large file.
    line_starts: []const u32 = &.{},

    /// The byte offset of every line start of `text` (line 1 at index 0), for
    /// `line_starts`. Owned by the caller; one allocation, one pass.
    pub fn indexLines(gpa: std.mem.Allocator, text: []const u8) error{ OutOfMemory, SourceTooLarge }![]u32 {
        if (text.len > std.math.maxInt(u32)) return error.SourceTooLarge;
        const n = std.mem.count(u8, text, "\n") + 1;
        const starts = try gpa.alloc(u32, n);
        starts[0] = 0;
        var k: usize = 1;
        var pos: usize = 0;
        while (std.mem.findScalarPos(u8, text, pos, '\n')) |nl| : (k += 1) {
            starts[k] = @intCast(nl + 1);
            pos = nl + 1;
        }
        return starts;
    }
};

pub const RenderOptions = struct {
    style: RenderStyle = .short,
    sources: []const Source = &.{},
    /// ANSI colour (severity in red/yellow/cyan, locations and secondary
    /// carets in blue). Off by default; the caller decides from isatty and
    /// NO_COLOR. Only this module's own escape sequences are coloured — text
    /// from findings is escaped exactly as without colour.
    color: bool = false,
    /// Columns of a tab in the quoted source (tabs are shown as spaces).
    tab_width: u8 = 4,
    /// Of a multi-line span: lines quoted after its first / before its last
    /// line; the lines between are left out (codespan's `start_context_lines`
    /// and `end_context_lines`).
    start_context_lines: u32 = 3,
    end_context_lines: u32 = 1,
    /// Lines quoted before / after every span, whatever the span's size
    /// (codespan's `before_label_lines` and `after_label_lines`). They are
    /// clamped to the source, and do not widen the line-number gutter.
    before_label_lines: u32 = 0,
    after_label_lines: u32 = 0,
    /// The drawing characters: ASCII (`-->`, `|`, `/`) or Unicode box
    /// drawing (`┌─`, `│`, `╭`, `╰`, `·`), codespan's `Chars::ascii()` and
    /// `Chars::box_drawing()`.
    chars: CharSet = .ascii,
    /// Terminal width in columns. When set, a quoted line wider than what is
    /// left of it after the gutter is cut around the spans, `...` marking the
    /// cut ends and the carets staying under their characters (the
    /// annotate-snippets algorithm). Null: lines are never cut.
    term_width: ?u16 = null,
    /// The unit of the column in the `-->` line of `snippet`, when its source
    /// is known. `byte` prints the `col` given (a byte column); `char` prints
    /// the column of the character, as codespan and rustc do: the number of
    /// characters wholly before the byte, plus one (a leading BOM is not
    /// counted). `short` always prints the column as given.
    column: ColumnUnit = .byte,
};

pub const CharSet = enum { ascii, unicode };
pub const ColumnUnit = enum { byte, char };

const Sgr = struct {
    on: bool,
    fn sev(self: Sgr, s: Severity) []const u8 {
        if (!self.on) return "";
        return switch (s) {
            .@"error" => "\x1b[1;31m",
            .warning => "\x1b[1;33m",
            .info, .hint => "\x1b[1;36m",
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
    return (std.mem.print(&buf, "{d}", .{n}) catch unreachable).len;
}

/// Write one finding as text. `line`/`col` are 1-based, `col` counted in
/// bytes; `end_line`/`end_col`, when present, end the span exclusively (as
/// in LSP). Every string from the finding (and the quoted source line) is
/// written with control characters escaped (`\n`, `\x1b`, ...; tab stays
/// a tab in the source line), because findings usually quote the input being
/// validated and are printed to a terminal: a key name carrying an escape
/// sequence must not reach it raw, and a `short` finding must stay one line.
/// In `snippet` a tab is shown as spaces up to the next multiple of
/// `tab_width` and carets line up for multi-byte UTF-8 by display width
/// (`charWidth`: East Asian wide and emoji are two columns, combining marks and
/// zero-width characters none). Lines end at `\n`; every `\r` at the end of a
/// line (before its `\n` or at the end of the text) is part of the break, as
/// codespan's `trim_end_matches` has it; another `\r`, a C0/C1 control, U+2028/U+2029, a bidirectional
/// control and an invalid byte are shown as `?`; a U+FEFF is not written.
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
                if (n.kind == .plain) try w.writeAll("; ") else try w.print("; {s}: ", .{@tagName(n.kind)});
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
        .snippet => try renderSnippet(w, d, opts, c),
    }
}

// ── snippet layout ───────────────────────────────────────────────────────────
//
// ported from brendanzab/codespan codespan-reporting 0.13.1
// (Apache-2.0, commit decb0a0727e45bf2f04dcd3e4b4deb9517349fdc):
//   src/term/views.rs      RichDiagnostic::render -- which lines are shown, how
//                          single-line labels are sorted, multi-line columns,
//                          the locus, the gaps between shown lines
//   src/term/renderer.rs   Renderer::render_snippet_{source,empty,break,note},
//                          caret_pointers and the multi-line label pieces
//   src/term/config.rs     Chars::ascii()
//
// Also ported: `before_label_lines`/`after_label_lines`, `Chars::box_drawing()`,
// and unicode-width's per-character widths (width_table.zig, generated); the
// `term_width` cut is annotate-snippets 0.12.17's `Margin` (margin.rs) and the
// placeholder of its `draw_line` (graphics.rs).
//
// Not ported: colour themes (we colour the module's own parts only), codespan's
// `medium`/`short` display styles.
//
// Memory: no allocation. Everything lives in fixed arrays on the stack:
//   - at most `max_labels` (64) spans take part (the primary one and the first
//     63 labels); further labels are listed as `--> location: message` lines
//     after the snippets, in order, without a source quote;
//   - at most `max_multi` (16) multi-line spans per file (gutter columns); a
//     17th multi-line span of the same file is listed the same way.
// A label that cannot be quoted (no matching source, line past its end) is a
// location line too, as before.

const max_labels = 64;
const max_multi = 16;

const LabKind = enum { snippet, loose, dropped };

/// One span to draw. `sl`/`el` are 1-based lines, `sc`/`ec` byte offsets into
/// those lines (0-based, `ec` exclusive).
const Lab = struct {
    kind: LabKind,
    primary: bool,
    group: u8 = 0,
    msg: []const u8,
    span: Span,
    sl: u32 = 0,
    sc: usize = 0,
    el: u32 = 0,
    ec: usize = 0,
    mcol: u8 = 0,

    fn isMulti(l: Lab) bool {
        return l.el != l.sl;
    }
};

const Group = struct { src: *const Source, nmulti: u8 = 0 };
const Item = struct { is_group: bool, idx: u8 };

const Resolved = struct { src: *const Source, sl: u32, sc: usize, el: u32, ec: usize };

/// Where `span` lies in its source; null when there is nothing to quote.
fn resolveSpan(span: Span, sources: []const Source) ?Resolved {
    const line = span.line orelse return null;
    const src = findSource(span, sources) orelse return null;
    const text = lineIn(src, line) orelse return null;
    const sc = @min(@as(usize, span.col orelse 1) -| 1, text.len);
    var r: Resolved = .{ .src = src, .sl = line, .sc = sc, .el = line, .ec = sc + 1 };
    if (span.end_line) |e| {
        if (e == line) {
            if (span.end_col) |x| r.ec = @min(@as(usize, x) -| 1, text.len);
        } else if (e > line) {
            // Past the last line of the source: underline to the end of the first.
            if (lineIn(src, e)) |et| {
                r.el = e;
                r.ec = if (span.end_col) |x| @min(@as(usize, x) -| 1, et.len) else et.len;
            } else r.ec = text.len;
        }
    }
    return r;
}

const Single = struct { primary: bool, start: usize, end: usize, msg: []const u8 };

const MultiKind = enum { top, left, bottom };
const MultiEnt = struct { col: u8, primary: bool, kind: MultiKind, pos: usize, msg: []const u8 };

const Chr = struct { idx: usize, len: usize, width: usize, cp: u21, valid: bool };

// ported from unicode-rs/unicode-width 0.2.2 src/tables.rs (MIT OR Apache-2.0)
// via the generated width_table.zig: `UnicodeWidthChar::width`, ambiguous narrow.
/// Display columns of a printable code point: 0 for combining marks, variation
/// selectors, ZWJ and other zero-width characters, 2 for East Asian Wide /
/// Fullwidth and emoji presentation, 1 otherwise. (Controls have no width in
/// the crate; the renderer shows them as `?`, one column: see `cpWidth`.)
pub fn charWidth(cp: u21) u2 {
    if (cp < 0x7f) return if (cp >= 0x20) 1 else 0;
    if (cp < 0xa0) return 0;
    var lo: usize = 0;
    var hi: usize = width_table.ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const r = width_table.ranges[mid];
        if (cp < r.lo) {
            hi = mid;
        } else if (cp > r.hi) {
            lo = mid + 1;
        } else return r.w;
    }
    return 1;
}

/// Characters the quoted source shows as `?`: C0/C1 controls (a C1 control such
/// as U+009B is a terminal escape in some terminals), DEL, the line and
/// paragraph separators U+2028/U+2029, and the bidirectional embedding,
/// override and isolate controls U+202A–U+202E and U+2066–U+2069 ("Trojan
/// Source", CVE-2021-42574: they reorder what a terminal shows; rustc and
/// annotate-snippets replace the same set).
fn isShownAsQuestion(cp: u21) bool {
    return switch (cp) {
        0...0x1f, 0x7f...0x9f, 0x2028, 0x2029, 0x202a...0x202e, 0x2066...0x2069 => true,
        else => false,
    };
}

/// The columns a character takes in the quoted source (`?` for what
/// `isShownAsQuestion`, nothing for U+FEFF, else `charWidth`).
fn cpWidth(cp: u21) usize {
    if (isShownAsQuestion(cp)) return 1;
    return charWidth(cp);
}

/// UTF-8 characters of a line with the tab-aware display width
/// (codespan's `char_metrics`, widths from `charWidth`); an invalid byte is one
/// character of one column, shown as `?`.
const CharIter = struct {
    text: []const u8,
    tab: usize,
    i: usize = 0,
    col: usize = 0,

    fn next(self: *CharIter) ?Chr {
        if (self.i >= self.text.len) return null;
        const b = self.text[self.i];
        var len: usize = 1;
        var cp: u21 = b;
        var valid = b < 0x80;
        if (b >= 0x80) blk: {
            const n = std.unicode.utf8ByteSequenceLength(b) catch break :blk;
            if (self.i + n > self.text.len) break :blk;
            cp = std.unicode.utf8Decode(self.text[self.i..][0..n]) catch break :blk;
            len = n;
            valid = true;
        }
        const width: usize = if (b == '\t')
            (if (self.tab == 0) 0 else self.tab - self.col % self.tab)
        else if (valid) cpWidth(cp) else 1;
        const r: Chr = .{ .idx = self.i, .len = len, .width = width, .cp = cp, .valid = valid };
        self.i += len;
        self.col += width;
        return r;
    }
};

/// Display columns of `text` (tabs aligned from column 0).
fn lineWidth(text: []const u8, tab: usize) usize {
    var it: CharIter = .{ .text = text, .tab = tab };
    while (it.next()) |_| {}
    return it.col;
}

/// The 1-based character column of the 1-based byte column `byte_col`
/// (codespan's `column_index`: the characters wholly before the byte, so a
/// byte inside a character counts that character as not yet reached). A
/// BOM opening line 1 is not a character.
fn charColumn(text: []const u8, byte_col: u32, first_line: bool) u32 {
    const off = @min(@as(usize, byte_col) -| 1, text.len);
    var it: CharIter = .{ .text = text, .tab = 0 };
    var n: u32 = 0;
    while (it.next()) |ch| {
        if (ch.idx + ch.len > off) break;
        if (first_line and ch.idx == 0 and ch.cp == 0xFEFF and ch.valid) continue;
        n += 1;
    }
    return n + 1;
}

fn overlaps(a0: usize, a1: usize, b0: usize, b1: usize) bool {
    return @max(a0, b0) < @min(a1, b1);
}

/// Bytes of leading whitespace, as codespan's `str::trim_start` counts it:
/// the Unicode White_Space property (Rust's `char::is_whitespace`), so an
/// ideographic space U+3000 before a multi-line span's start still gives the
/// top-left corner form.
fn leadingSpace(text: []const u8) usize {
    var n: usize = 0;
    while (n < text.len) {
        const len = std.unicode.utf8ByteSequenceLength(text[n]) catch return n;
        if (n + len > text.len) return n;
        const cp = std.unicode.utf8Decode(text[n..][0..len]) catch return n;
        if (!isWhiteSpace(cp)) return n;
        n += len;
    }
    return n;
}

fn isWhiteSpace(cp: u21) bool {
    return switch (cp) {
        '\t'...'\r', ' ', 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

/// The primary style at `[a, b)` of the single-line labels, or null.
fn styleAt(singles: []const Single, a: usize, b: usize) ?bool {
    var r: ?bool = null;
    for (singles) |s| {
        if (!overlaps(s.start, s.end, a, b)) continue;
        if (s.primary) return true;
        r = false;
    }
    return r;
}

// ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/views.rs (RichDiagnostic::render, must_render)
/// The first line >= `from` of group `g` that is shown: the line of a
/// single-line span, the first and last line of a multi-line one, its
/// `start_context_lines` after the first and `end_context_lines` before the
/// last, and `before_label_lines` / `after_label_lines` around every span.
fn nextShown(labs: []const Lab, g: usize, src: *const Source, from: u32, o: RenderOptions) ?u32 {
    var best: ?u32 = null;
    for (labs) |l| {
        if (l.kind != .snippet or l.group != g) continue;
        considerLine(&best, from, l.sl, l.sl);
        // The context lines around the span (`before_label_lines`,
        // `after_label_lines`); a line past the end of the source is none.
        considerLine(&best, from, @max(1, l.sl -| o.before_label_lines), l.sl -| 1);
        const after_from = @max(l.el +| 1, from);
        if (after_from <= l.el +| o.after_label_lines and lineIn(src, after_from) != null) considerLine(&best, from, l.el +| 1, l.el +| o.after_label_lines);
        if (!l.isMulti()) continue;
        considerLine(&best, from, l.el, l.el);
        const a = l.sl + 1;
        const b = l.el - 1;
        considerLine(&best, from, a, @min(b, l.sl +| o.start_context_lines));
        considerLine(&best, from, @max(a, l.el -| o.end_context_lines), b);
    }
    return best;
}

/// Lower `best` to the first line of `[a, b]` that is >= `from`.
fn considerLine(best: *?u32, from: u32, a: u32, b: u32) void {
    if (a > b or b < from) return;
    const x = @max(a, from);
    if (best.* == null or x < best.*.?) best.* = x;
}

// ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/config.rs (Chars::ascii, Chars::box_drawing)
const Chars = struct {
    snippet_start: []const u8,
    border_left: []const u8,
    border_break: []const u8,
    multi_top_left: []const u8,
    multi_top: []const u8,
    multi_bottom_left: []const u8,
    multi_bottom: []const u8,
    multi_left: []const u8,
    pointer_left: []const u8,
};

const ascii_chars: Chars = .{
    .snippet_start = "-->",
    .border_left = "|",
    .border_break = ".",
    .multi_top_left = "/",
    .multi_top = "-",
    .multi_bottom_left = "\\",
    .multi_bottom = "-",
    .multi_left = "|",
    .pointer_left = "|",
};

const box_chars: Chars = .{
    .snippet_start = "\u{250c}\u{2500}",
    .border_left = "\u{2502}",
    .border_break = "\u{b7}",
    .multi_top_left = "\u{256d}",
    .multi_top = "\u{2500}",
    .multi_bottom_left = "\u{2570}",
    .multi_bottom = "\u{2500}",
    .multi_left = "\u{2502}",
    .pointer_left = "\u{2502}",
};

// ported from rust-lang/annotate-snippets-rs 0.12.17 (MIT OR Apache-2.0) src/renderer/margin.rs
/// Which columns of the quoted lines of one file are kept when they are wider
/// than the terminal: one window for all of them, chosen around the spans.
const Margin = struct {
    /// The whitespace before the left-most span that can be consumed.
    whitespace_left: usize,
    /// The column where the left-most span begins / the right-most ends.
    span_left: usize,
    span_right: usize,
    computed_left: usize = 0,
    computed_right: usize = 0,
    term_width: usize,
    /// The end column of the right-most label, its text included.
    label_right: usize,

    const ellipsis_passing = 6;
    const long_whitespace = 20;
    const long_whitespace_padding = 4;

    fn init(whitespace_left: usize, span_left: usize, span_right: usize, label_right: usize, term_width: usize, max_line_len: usize) Margin {
        // Whitespace before the left-most span only: an annotation of
        // whitespace is not trimmed away.
        const ws = @min(whitespace_left, span_left);
        // The 6 is room for the `...`.
        var m: Margin = .{
            .whitespace_left = ws -| ellipsis_passing,
            .span_left = span_left -| ellipsis_passing,
            .span_right = span_right + ellipsis_passing,
            .term_width = term_width,
            .label_right = label_right + ellipsis_passing,
        };
        m.compute(max_line_len);
        return m;
    }

    fn compute(m: *Margin, max_line_len: usize) void {
        // A lot of whitespace (> 20) is useless, trim it.
        m.computed_left = if (m.whitespace_left > long_whitespace) m.whitespace_left - (long_whitespace - long_whitespace_padding) else 0;
        m.computed_right = @max(max_line_len, m.computed_left);
        if (m.computed_right - m.computed_left > m.term_width) {
            if (m.label_right -| m.whitespace_left <= m.term_width and m.label_right >= m.whitespace_left) {
                // Trimming whitespace is enough.
                m.computed_left = m.whitespace_left;
                m.computed_right = m.computed_left + m.term_width;
            } else if (m.label_right -| m.span_left <= m.term_width) {
                // The spans and labels fit.
                const padding_left = (m.term_width - (m.label_right - m.span_left)) / 2;
                m.computed_left = m.span_left -| padding_left;
                m.computed_right = m.computed_left + m.term_width;
            } else if (m.span_right -| m.span_left <= m.term_width) {
                // The spans fit, with some padding.
                const padding_left = (m.term_width - (m.span_right - m.span_left)) / 5 * 2;
                m.computed_left = m.span_left -| padding_left;
                m.computed_right = m.computed_left + m.term_width;
            } else {
                // Give up, but still do not show the whole line.
                m.computed_left = m.span_left;
                m.computed_right = m.span_right;
            }
        }
    }

    fn wasCutLeft(m: Margin) bool {
        return m.computed_left > 0;
    }

    fn left(m: Margin, line_len: usize) usize {
        return @min(m.computed_left, line_len);
    }

    fn right(m: Margin, line_len: usize) usize {
        if (line_len -| m.computed_left <= m.term_width) return line_len;
        return @min(line_len, m.computed_right);
    }

    /// The bytes of `text` this margin keeps, ported from `draw_line`
    /// (the skipped columns are those before `left`, a wide character
    /// straddling it is skipped whole).
    fn window(m: Margin, text: []const u8, tab: usize) Window {
        const line_len = lineWidth(text, tab);
        const lft = m.left(line_len);
        const rgt = m.right(line_len);
        var w: Window = .{ .bs = text.len, .be = text.len, .cut_left = m.wasCutLeft(), .cut_right = line_len > rgt };
        var it: CharIter = .{ .text = text, .tab = tab };
        var skipped: usize = 0;
        var taken: usize = 0;
        var started = false;
        while (it.next()) |ch| {
            if (!started) {
                if (skipped < lft) {
                    skipped += ch.width;
                    continue;
                }
                started = true;
                w.bs = ch.idx;
            }
            taken += ch.width;
            if (taken > rgt -| lft) {
                w.be = ch.idx;
                break;
            }
        }
        return w;
    }
};

/// The part of a quoted line that is drawn when `term_width` cuts it: bytes
/// `[bs, be)`, and whether `...` replaces the first / last columns of it.
const Window = struct {
    bs: usize = 0,
    be: usize = std.math.maxInt(usize),
    cut_left: bool = false,
    cut_right: bool = false,
};

const Layout = struct {
    w: *std.Io.Writer,
    c: Sgr,
    sev: Severity,
    pad: usize,
    opts: RenderOptions,
    chars: *const Chars,
    nmulti: usize = 0,
    margin: ?Margin = null,

    const E = std.Io.Writer.Error;

    fn mark(l: *const Layout, primary: bool) []const u8 {
        return if (primary) l.c.sev(l.sev) else l.c.blue();
    }

    fn outerGutter(l: *Layout) E!void {
        try l.w.splatByteAll(' ', l.pad + 1);
    }

    fn border(l: *Layout, brk: bool) E!void {
        try l.w.print("{s}{s}{s}", .{ l.c.blue(), if (brk) l.chars.border_break else l.chars.border_left, l.c.reset() });
    }

    fn repeat(l: *Layout, s: []const u8, n: usize) E!void {
        try l.w.splatBytesAll(s, n);
    }

    fn innerGutter(l: *Layout, multis: []const MultiEnt) E!void {
        var mi: usize = 0;
        for (0..l.nmulti) |col| {
            if (mi < multis.len and multis[mi].col == col) {
                const m = multis[mi];
                if (m.kind == .top) try l.w.writeAll("  ") else try l.multiLeft(m.primary, null);
                mi += 1;
            } else try l.w.writeAll("  ");
        }
    }

    /// ` |` of a multi-line span, with an underline continued to its left.
    fn multiLeft(l: *Layout, primary: bool, underline: ?Underline) E!void {
        if (underline) |u| {
            try l.w.print("{s}{s}{s}", .{ l.mark(u.primary), l.chars.multi_top, l.c.reset() });
        } else try l.w.writeByte(' ');
        try l.w.print("{s}{s}{s}", .{ l.mark(primary), l.chars.multi_left, l.c.reset() });
    }

    fn multiCorner(l: *Layout, primary: bool, corner: []const u8) E!void {
        try l.w.print(" {s}{s}{s}", .{ l.mark(primary), corner, l.c.reset() });
    }

    fn innerGutterColumn(l: *Layout, underline: ?Underline) E!void {
        if (underline) |u| {
            try l.w.writeAll(l.mark(u.primary));
            try l.repeat(if (u.top) l.chars.multi_top else l.chars.multi_bottom, 2);
            try l.w.writeAll(l.c.reset());
        } else try l.w.writeAll("  ");
    }

    /// `   |` (or `   .`) and the inner gutter, no text.
    fn gutterRow(l: *Layout, brk: bool, multis: []const MultiEnt) E!void {
        try l.outerGutter();
        try l.border(brk);
        try l.innerGutter(multis);
    }

    fn emptyRow(l: *Layout) E!void {
        try l.gutterRow(false, &.{});
        try l.w.writeByte('\n');
    }

    /// The characters of `text` in the window; the ends cut by `term_width`
    /// are `...`.
    // ported from rust-lang/annotate-snippets-rs 0.12.17 src/renderer/graphics.rs (draw_line: the placeholder)
    fn writeSource(l: *Layout, text: []const u8, win: Window) E!void {
        // The first characters worth three columns, and the last ones, are
        // replaced by `...`; the columns the first ones took beyond three
        // stay blank so the carets keep their place.
        var lend = win.bs;
        if (win.cut_left) {
            try l.w.writeAll("...");
            var it: CharIter = .{ .text = text, .tab = l.opts.tab_width };
            var taken: usize = 0;
            while (it.next()) |ch| {
                if (ch.idx < win.bs) continue;
                if (ch.idx >= win.be or (taken >= 3 and ch.width != 0)) break;
                taken += ch.width;
                lend = ch.idx + ch.len;
            }
            try l.w.splatByteAll(' ', taken -| 3);
        }
        var rstart = win.be;
        if (win.cut_right) {
            var total: usize = 0;
            var it: CharIter = .{ .text = text, .tab = l.opts.tab_width };
            while (it.next()) |ch| {
                if (ch.idx >= lend and ch.idx < win.be) total += ch.width;
            }
            var before: usize = 0;
            rstart = @min(win.be, text.len);
            it = .{ .text = text, .tab = l.opts.tab_width };
            while (it.next()) |ch| {
                if (ch.idx < lend or ch.idx >= win.be) continue;
                // The last character that still leaves three columns after it.
                if (total - before >= 3 and total - before - ch.width < 3) {
                    rstart = ch.idx;
                    break;
                }
                before += ch.width;
            }
            if (total < 3) rstart = lend;
        }
        var it: CharIter = .{ .text = text, .tab = l.opts.tab_width };
        while (it.next()) |ch| {
            if (ch.idx < lend) continue;
            if (ch.idx >= rstart) break;
            if (text[ch.idx] == '\t') {
                try l.w.splatByteAll(' ', ch.width);
            } else if (!ch.valid or isShownAsQuestion(ch.cp)) {
                try l.w.writeByte('?');
            } else if (ch.cp == 0xFEFF) {
                // Zero columns and invisible: not written.
            } else try l.w.writeAll(text[ch.idx..][0..ch.len]);
        }
        if (win.cut_right) try l.w.writeAll("...");
    }

    // ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/renderer.rs (caret_pointers)
    /// The vertical lines under the carets that have a hanging message.
    fn caretPointers(l: *Layout, text: []const u8, singles: []const Single, trailing: ?usize, max_start: usize, limit: usize, win: Window) E!void {
        var it: CharIter = .{ .text = text, .tab = l.opts.tab_width };
        while (it.next()) |ch| {
            if (ch.idx >= limit or ch.idx >= win.be) break;
            if (ch.idx < win.bs) continue;
            var style: ?bool = null;
            for (singles, 0..) |s, k| {
                if (s.msg.len == 0 or trailing == k) continue;
                if (s.start < ch.idx or s.start >= ch.idx + ch.len) continue;
                if (s.primary) {
                    style = true;
                    break;
                }
                style = false;
            }
            var spaces = ch.width;
            if (style) |p| {
                try l.w.print("{s}{s}{s}", .{ l.mark(p), l.chars.pointer_left, l.c.reset() });
                spaces -|= 1;
            }
            if (ch.idx <= max_start) try l.w.splatByteAll(' ', spaces);
        }
    }

    // ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/renderer.rs (render_snippet_source, multi-line parts)
    fn sourceBlock(l: *Layout, number: u32, text: []const u8, singles: []const Single, multis: []const MultiEnt, win: Window) E!void {
        const w = l.w;
        const lead = leadingSpace(text);
        // The line.
        try w.splatByteAll(' ', l.pad -| digits(number));
        try w.print("{s}{d}{s} ", .{ l.c.blue(), number, l.c.reset() });
        try l.border(false);
        {
            var mi: usize = 0;
            for (0..l.nmulti) |col| {
                if (mi < multis.len and multis[mi].col == col) {
                    const m = multis[mi];
                    switch (m.kind) {
                        .top => if (m.pos <= lead) try l.multiCorner(m.primary, l.chars.multi_top_left) else try w.writeAll("  "),
                        .left, .bottom => try l.multiLeft(m.primary, null),
                    }
                    mi += 1;
                } else try w.writeAll("  ");
            }
        }
        try w.writeByte(' ');
        try l.writeSource(text, win);
        try w.writeByte('\n');

        if (singles.len > 0) try l.singleRows(text, singles, multis, win);

        // The top and bottom of multi-line spans.
        for (multis, 0..) |m, mk| {
            if (m.kind == .left) continue;
            if (m.kind == .top and m.pos <= lead) continue;
            try l.outerGutter();
            try l.border(false);
            var underline: ?Underline = null;
            var it: usize = 0;
            for (0..l.nmulti) |col| {
                if (it < multis.len and multis[it].col == col) {
                    const e = multis[it];
                    switch (e.kind) {
                        .left => try l.multiLeft(e.primary, underline),
                        .top => if (mk > it) {
                            try l.multiLeft(e.primary, underline);
                        } else if (mk == it) {
                            underline = .{ .primary = e.primary, .top = true };
                            try l.multiCorner(m.primary, l.chars.multi_top_left);
                        } else try l.innerGutterColumn(underline),
                        .bottom => if (mk < it) {
                            try l.multiLeft(e.primary, underline);
                        } else if (mk == it) {
                            underline = .{ .primary = e.primary, .top = false };
                            try l.multiCorner(m.primary, l.chars.multi_bottom_left);
                        } else try l.innerGutterColumn(underline),
                    }
                    it += 1;
                } else try l.innerGutterColumn(underline);
            }
            // Finish the top or bottom caret.
            const caret: u8 = if (m.primary) '^' else '\'';
            try w.writeAll(l.mark(m.primary));
            var ci: CharIter = .{ .text = text, .tab = l.opts.tab_width };
            while (ci.next()) |ch| {
                if (m.kind == .top) {
                    if (ch.idx >= m.pos + 1) break;
                } else if (ch.idx >= m.pos) break;
                if (ch.idx < win.bs) continue;
                try l.repeat(if (m.kind == .top) l.chars.multi_top else l.chars.multi_bottom, ch.width);
            }
            try w.writeByte(caret);
            try w.writeAll(l.c.reset());
            if (m.kind == .bottom and m.msg.len > 0) {
                try w.writeByte(' ');
                try writeEscaped(w, m.msg);
            }
            try w.writeByte('\n');
        }
    }

    // ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/renderer.rs (render_snippet_source, single-line labels)
    /// Carets of the single-line labels, a trailing message, and the hanging
    /// messages below.
    fn singleRows(l: *Layout, text: []const u8, singles: []const Single, multis: []const MultiEnt, win: Window) E!void {
        const w = l.w;
        var num_messages: usize = 0;
        var max_start: usize = 0;
        var max_end: usize = 0;
        var trailing: ?usize = null;
        for (singles, 0..) |s, i| {
            if (s.msg.len > 0) num_messages += 1;
            max_start = @max(max_start, s.start);
            max_end = @max(max_end, s.end);
            // A candidate for the trailing label: its message goes to the
            // right of the carets.
            if (s.end == max_end) trailing = if (s.msg.len == 0) null else i;
        }
        if (trailing) |t| {
            for (singles, 0..) |s, i| {
                if (i != t and overlaps(singles[t].start, singles[t].end, s.start, s.end)) {
                    trailing = null;
                    break;
                }
            }
        }

        // The carets.
        try l.gutterRow(false, multis);
        try w.writeByte(' ');
        var prev: ?bool = null;
        var it: CharIter = .{ .text = text, .tab = l.opts.tab_width };
        var placeholder = false;
        while (true) {
            // One extra column past the end, so a caret can sit at the end of
            // the line.
            const ch: Chr = it.next() orelse if (!placeholder and win.be >= text.len) blk: {
                placeholder = true;
                break :blk Chr{ .idx = text.len, .len = 1, .width = 1, .cp = 0, .valid = true };
            } else break;
            if (ch.idx >= win.be and ch.idx < text.len) break;
            if (ch.idx < win.bs) continue;
            const cur = styleAt(singles, ch.idx, ch.idx + ch.len);
            if (prev != cur) {
                if (cur) |p| try w.writeAll(l.mark(p)) else try w.writeAll(l.c.reset());
            }
            if (cur) |p| {
                try w.splatByteAll(if (p) '^' else '-', ch.width);
            } else if (ch.idx < max_end) try w.splatByteAll(' ', ch.width);
            prev = cur;
        }
        if (prev != null) try w.writeAll(l.c.reset());
        if (trailing) |t| {
            try w.writeByte(' ');
            try writeEscaped(w, singles[t].msg);
        }
        try w.writeByte('\n');

        const hanging = num_messages - @as(usize, @intFromBool(trailing != null));
        if (hanging == 0) return;
        // The pointers, then each hanging message under its caret, the last
        // label first.
        try l.gutterRow(false, multis);
        try w.writeByte(' ');
        try l.caretPointers(text, singles, trailing, max_start, std.math.maxInt(usize), win);
        try w.writeByte('\n');
        var k = singles.len;
        while (k > 0) {
            k -= 1;
            const s = singles[k];
            if (s.msg.len == 0 or trailing == k) continue;
            try l.gutterRow(false, multis);
            try w.writeByte(' ');
            try l.caretPointers(text, singles, trailing, max_start, s.start, win);
            try writeEscaped(w, s.msg);
            try w.writeByte('\n');
        }
    }

    fn looseLine(l: *Layout, span: Span, msg: []const u8) E!void {
        try l.outerGutter();
        try l.w.print("{s}{s}{s} ", .{ l.c.blue(), l.chars.snippet_start, l.c.reset() });
        _ = try writeLocation(l.w, span);
        if (msg.len > 0) {
            try l.w.writeAll(": ");
            try writeEscaped(l.w, msg);
        }
        try l.w.writeByte('\n');
    }

    // ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/views.rs (RichDiagnostic::render, single-line label sort)
    /// One shown line of group `g`: its source, with its single-line labels
    /// when `with_singles` (not for a line shown only to close a gap).
    fn showLine(l: *Layout, labs: []const Lab, g: usize, src: *const Source, ln: u32, with_singles: bool) E!void {
        const text = lineIn(src, ln) orelse return;
        var singles: [max_labels]Single = undefined;
        var ns: usize = 0;
        if (with_singles) for (labs) |lab| {
            if (lab.kind != .snippet or lab.group != g or lab.isMulti() or lab.sl != ln) continue;
            const s: Single = .{ .primary = lab.primary, .start = lab.sc, .end = @max(lab.ec, lab.sc + 1), .msg = lab.msg };
            // Sorted by the range they cover; equal ranges in the reverse of
            // the order given (the renderer prints the hanging ones backwards).
            var at: usize = 0;
            while (at < ns and (singles[at].start < s.start or (singles[at].start == s.start and singles[at].end < s.end))) at += 1;
            var j = ns;
            while (j > at) : (j -= 1) singles[j] = singles[j - 1];
            singles[at] = s;
            ns += 1;
        };
        var multis: [max_multi]MultiEnt = undefined;
        const nm = multisOf(labs, g, ln, &multis);
        const win: Window = if (l.margin) |m| m.window(text, l.opts.tab_width) else .{};
        try l.sourceBlock(ln, text, singles[0..ns], multis[0..nm], win);
    }

    fn breakRow(l: *Layout, multis: []const MultiEnt) E!void {
        try l.gutterRow(true, multis);
        try l.w.writeByte('\n');
    }
};

const Underline = struct { primary: bool, top: bool };

/// The multi-line spans of group `g` that touch line `ln`, by gutter column.
fn multisOf(labs: []const Lab, g: usize, ln: u32, out: *[max_multi]MultiEnt) usize {
    var n: usize = 0;
    for (labs) |l| {
        if (l.kind != .snippet or l.group != g or !l.isMulti()) continue;
        if (ln < l.sl or ln > l.el) continue;
        out[n] = if (ln == l.sl)
            .{ .col = l.mcol, .primary = l.primary, .kind = .top, .pos = l.sc, .msg = "" }
        else if (ln == l.el)
            .{ .col = l.mcol, .primary = l.primary, .kind = .bottom, .pos = l.ec, .msg = l.msg }
        else
            .{ .col = l.mcol, .primary = l.primary, .kind = .left, .pos = 0, .msg = "" };
        n += 1;
    }
    return n;
}

/// The display column of byte `byte` of `text`: of the character holding it
/// (`start`), or the end of the characters before it (`!start`, an exclusive end).
fn colOf(text: []const u8, byte: usize, tab: usize, start: bool) usize {
    var it: CharIter = .{ .text = text, .tab = tab };
    while (true) {
        const before = it.col;
        const ch = it.next() orelse return it.col;
        if (if (start) ch.idx + ch.len > byte else ch.idx >= byte) return before;
    }
}

// ported from rust-lang/annotate-snippets-rs 0.12.17 src/renderer/graphics.rs (the Margin::new call in draw_snippet)
/// The `term_width` window of group `g`: over all its shown lines, from the
/// columns of the spans and of the labels' text.
fn computeMargin(labs: []const Lab, g: usize, src: *const Source, o: RenderOptions, term_width: u16, code_offset: usize) Margin {
    const tab: usize = o.tab_width;
    var ws_left: usize = std.math.maxInt(usize);
    var span_left: usize = std.math.maxInt(usize);
    var span_right: usize = 0;
    var label_right: usize = 0;
    var max_line_len: usize = 0;
    var cur = nextShown(labs, g, src, 0, o);
    while (cur) |ln| : (cur = nextShown(labs, g, src, ln + 1, o)) {
        const text = lineIn(src, ln) orelse continue;
        max_line_len = @max(max_line_len, lineWidth(text, tab));
        var lead: usize = 0;
        while (lead < text.len and (text[lead] == ' ' or text[lead] == '\t')) lead += 1;
        if (lead < text.len) {
            var ws: usize = 0;
            for (text[0..lead]) |b| ws += if (b == '\t') 4 else 1;
            ws_left = @min(ws_left, ws);
        }
        for (labs) |l| {
            if (l.kind != .snippet or l.group != g) continue;
            if (l.sl != ln and l.el != ln) continue;
            // The span's columns on this line.
            const a = if (l.sl == ln) colOf(text, l.sc, tab, true) else 0;
            const b = if (l.el == ln) colOf(text, if (l.sl == ln) @max(l.ec, l.sc + 1) else l.ec, tab, false) else a;
            if (l.sl == l.el or l.el == ln) {
                span_left = @min(span_left, @min(a, b));
                span_right = @max(span_right, @max(a, b));
                label_right = @max(label_right, b + (if (l.msg.len > 0) lineWidth(l.msg, 4) + 1 else 0));
            } else {
                span_left = @min(span_left, a);
                span_right = @max(span_right, a);
                label_right = @max(label_right, a);
            }
        }
    }
    if (ws_left == std.math.maxInt(usize)) ws_left = 0;
    if (span_left == std.math.maxInt(usize)) span_left = 0;
    return Margin.init(ws_left, span_left, span_right, label_right, @as(usize, term_width) -| code_offset, max_line_len);
}

// ported from brendanzab/codespan codespan-reporting 0.13.1 src/term/views.rs (RichDiagnostic::render: files, locus, gaps, border, notes)
fn renderSnippet(w: *std.Io.Writer, d: Diagnostic, opts: RenderOptions, c: Sgr) std.Io.Writer.Error!void {
    try writeHeader(w, d, c);
    try w.writeByte('\n');

    var labs: [max_labels]Lab = undefined;
    var nl: usize = 0;
    var groups: [max_labels]Group = undefined;
    var ng: usize = 0;
    var items: [max_labels]Item = undefined;
    var ni: usize = 0;
    var pad: usize = 0;
    var overflow = false;
    const extra_labels: []const Label = d.labels orelse &.{};
    const nspans = 1 + extra_labels.len;

    var i: usize = 0;
    while (i < @min(nspans, max_labels)) : (i += 1) {
        const primary = i == 0;
        const span = if (primary) primarySpan(d) else labelSpan(d, extra_labels[i - 1]);
        if (span.file == null and span.line == null) continue;
        var lab: Lab = .{
            .kind = .loose,
            .primary = primary or (extra_labels[i -| 1].primary orelse false),
            .msg = if (primary) (d.span_message orelse "") else extra_labels[i - 1].message,
            .span = span,
        };
        if (resolveSpan(span, opts.sources)) |r| {
            var gi: usize = 0;
            while (gi < ng and groups[gi].src != r.src) gi += 1;
            const known = gi < ng;
            const nmulti: u8 = if (known) groups[gi].nmulti else 0;
            if (r.sl != r.el and nmulti >= max_multi) {
                lab.kind = .dropped;
                overflow = true;
            } else {
                if (!known) {
                    groups[gi] = .{ .src = r.src };
                    ng += 1;
                    items[ni] = .{ .is_group = true, .idx = @intCast(gi) };
                    ni += 1;
                }
                lab.kind = .snippet;
                lab.group = @intCast(gi);
                lab.sl = r.sl;
                lab.sc = r.sc;
                lab.el = r.el;
                lab.ec = r.ec;
                if (r.sl != r.el) {
                    lab.mcol = nmulti;
                    groups[gi].nmulti += 1;
                }
                pad = @max(pad, @max(digits(r.sl), digits(r.el)));
            }
        }
        if (lab.kind == .loose) {
            items[ni] = .{ .is_group = false, .idx = @intCast(nl) };
            ni += 1;
        }
        labs[nl] = lab;
        nl += 1;
    }
    if (nspans > max_labels) overflow = true;

    const notes: []const Note = d.notes orelse &.{};
    const has_after = notes.len > 0 or d.path.len > 0 or d.suggest != null or d.fix != null or d.code_url != null or overflow;
    var lay: Layout = .{ .w = w, .c = c, .sev = d.severity, .pad = pad, .opts = opts, .chars = if (opts.chars == .unicode) &box_chars else &ascii_chars };

    for (items[0..ni], 0..) |item, k| {
        if (!item.is_group) {
            const lab = labs[item.idx];
            try lay.looseLine(lab.span, lab.msg);
            continue;
        }
        const g: usize = item.idx;
        lay.nmulti = groups[g].nmulti;
        // The locus: the earliest primary span of the file (else the earliest).
        var best: ?usize = null;
        for (labs[0..nl], 0..) |l, j| {
            if (l.kind != .snippet or l.group != g) continue;
            const b = best orelse {
                best = j;
                continue;
            };
            const o = labs[b];
            if ((!o.primary and l.primary) or (o.primary == l.primary and (o.sl > l.sl or (o.sl == l.sl and o.sc > l.sc)))) best = j;
        }
        const src = groups[g].src;
        lay.margin = if (opts.term_width) |tw| computeMargin(labs[0..nl], g, src, opts, tw, pad + 3 + 2 * lay.nmulti) else null;
        try lay.outerGutter();
        try w.print("{s}{s}{s} ", .{ c.blue(), lay.chars.snippet_start, c.reset() });
        var locus = labs[best.?].span;
        if (opts.column == .char) if (locus.line) |ln| if (locus.col) |col| if (lineIn(src, ln)) |t| {
            locus.col = charColumn(t, col, ln == 1);
        };
        _ = try writeLocation(w, locus);
        try w.writeByte('\n');
        try lay.emptyRow();

        var cur = nextShown(labs[0..nl], g, src, 0, opts);
        while (cur) |ln| {
            try lay.showLine(labs[0..nl], g, src, ln, true);
            const nxt = nextShown(labs[0..nl], g, src, ln + 1, opts);
            if (nxt) |n| switch (n - ln) {
                1 => {},
                // One line between: show it, with the multi-line marks only.
                2 => try lay.showLine(labs[0..nl], g, src, ln + 1, false),
                else => {
                    var ms: [max_multi]MultiEnt = undefined;
                    const nm = multisOf(labs[0..nl], g, n, &ms);
                    try lay.breakRow(ms[0..nm]);
                },
            };
            cur = nxt;
        }
        // The closing border -- not when nothing follows (it would only add
        // an empty row above the final blank line).
        if (k + 1 < ni or has_after) try lay.emptyRow();
    }

    // Spans that could not be drawn.
    for (labs[0..nl]) |lab| if (lab.kind == .dropped) try lay.looseLine(lab.span, lab.msg);
    if (nspans > max_labels) for (max_labels..nspans) |j| {
        const l = extra_labels[j - 1];
        try lay.looseLine(labelSpan(d, l), l.message);
    };

    for (notes) |n| switch (n.kind) {
        .plain => try writePlainNote(&lay, n.message),
        else => try writeNote(&lay, @tagName(n.kind), n.message),
    };
    if (d.path.len > 0) try writeNote(&lay, "at", d.path);
    if (d.suggest) |s| try writeNote(&lay, "help", s);
    if (d.fix) |f| {
        try lay.outerGutter();
        try w.print("{s}={s} {s}fix{s}: ", .{ c.blue(), c.reset(), c.bold(), c.reset() });
        try writeFix(w, d, f);
        try w.writeByte('\n');
    }
    if (d.code_url) |u| try writeNote(&lay, "see", u);
    // codespan ends every diagnostic with an empty line.
    try w.writeByte('\n');
}

/// `= kind: text` (our own notes: escaped, one line).
fn writeNote(lay: *Layout, kind: []const u8, text: []const u8) std.Io.Writer.Error!void {
    const w = lay.w;
    const c = lay.c;
    try lay.outerGutter();
    try w.print("{s}={s} {s}{s}{s}: ", .{ c.blue(), c.reset(), c.bold(), kind, c.reset() });
    try writeEscaped(w, text);
    try w.writeByte('\n');
}

/// `= text` for a codespan-style note: one `=` and the text, the next lines
/// aligned under it. Control characters other than a tab are escaped.
/// ported from codespan-reporting 0.13.1 src/term/renderer.rs render_snippet_note
/// (`str::lines()` semantics: a final newline ends the last line, `\r\n` too).
fn writePlainNote(lay: *Layout, text: []const u8) std.Io.Writer.Error!void {
    const w = lay.w;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var first = true;
    while (lines.next()) |raw| {
        if (lines.peek() == null and raw.len == 0) break;
        try lay.outerGutter();
        if (first) {
            try w.print("{s}={s}", .{ lay.c.blue(), lay.c.reset() });
        } else try w.writeByte(' ');
        first = false;
        try w.writeByte(' ');
        try writeEscapedTabs(w, std.mem.trimEnd(u8, raw, "\r"));
        try w.writeByte('\n');
    }
}

/// `writeEscaped` that lets a tab through (a note quoted from source).
fn writeEscapedTabs(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    var parts = std.mem.splitScalar(u8, s, '\t');
    var first = true;
    while (parts.next()) |p| {
        if (!first) try w.writeByte('\t');
        first = false;
        try writeEscaped(w, p);
    }
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

/// Finding text with every character `isShownAsQuestion` written as an escape:
/// `\n` `\r` `\t`, `\xNN` for another C0 control, DEL and a byte that is not
/// valid UTF-8 (a lone 0x9B is an 8-bit CSI to a Latin-1 terminal), `\u{NNNN}`
/// for a C1 control, U+2028/U+2029 and a bidirectional control.
fn writeEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    var start: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c >= 0x20 and c < 0x7f) {
            i += 1;
            continue;
        }
        if (c >= 0x80) {
            const n = std.unicode.utf8ByteSequenceLength(c) catch 0;
            const cp: ?u21 = if (n != 0 and i + n <= s.len) std.unicode.utf8Decode(s[i..][0..n]) catch null else null;
            if (cp) |v| {
                if (!isShownAsQuestion(v)) {
                    i += n;
                    continue;
                }
                try w.writeAll(s[start..i]);
                try w.print("\\u{{{x:0>4}}}", .{v});
                i += n;
            } else {
                try w.writeAll(s[start..i]);
                try w.print("\\x{x:0>2}", .{c});
                i += 1;
            }
            start = i;
            continue;
        }
        try w.writeAll(s[start..i]);
        switch (c) {
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.print("\\x{x:0>2}", .{c}),
        }
        i += 1;
        start = i;
    }
    try w.writeAll(s[start..]);
}

/// The source `d.file` names (or the only one, for a span with no file), or
/// null when there is nothing to quote from.
fn findSource(d: Span, sources: []const Source) ?*const Source {
    if (d.file) |f| {
        for (sources) |*s| if (std.mem.eql(u8, s.file, f)) return s;
        return null;
    }
    if (sources.len == 1) return &sources[0];
    return null;
}

/// The text of 1-based `line` of `s`, without its line break, or null past
/// the end.
fn lineIn(s: *const Source, line: u32) ?[]const u8 {
    if (line == 0) return null;
    const src = s.text;
    var start: usize = 0;
    if (s.line_starts.len != 0) {
        if (line > s.line_starts.len) return null;
        start = s.line_starts[line - 1];
    } else {
        var n: u32 = 1;
        while (n < line) : (n += 1) {
            start = (std.mem.findScalarPos(u8, src, start, '\n') orelse return null) + 1;
        }
    }
    if (start > src.len) return null;
    const end = std.mem.findScalarPos(u8, src, start, '\n') orelse src.len;
    return std.mem.trimEnd(u8, src[start..end], "\r");
}

/// The text of line `d.line` (without its line break) from the matching
/// source, or null when there is nothing to quote.
fn sourceLine(d: Span, sources: []const Source) ?[]const u8 {
    const line = d.line orelse return null;
    const s = findSource(d, sources) orelse return null;
    return lineIn(s, line);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

/// Serialize findings as a JSON array of objects whose keys are
/// `Diagnostic`'s field names; absent (null) fields are omitted and
/// `severity` is a string (`"error"`, `"warning"`, `"info"`, `"hint"`). Positions
/// stay as they are here, 1-based; `writeLsp` emits the LSP form.
pub fn writeJsonSlice(w: *std.Io.Writer, items: []const Diagnostic) std.Io.Writer.Error!void {
    std.json.Stringify.value(items, .{ .emit_null_optional_fields = false }, w) catch |e| switch (e) {
        error.WriteFailed => return error.WriteFailed,
    };
}

// ── LSP 3.17 ─────────────────────────────────────────────────────────────────

/// How LSP counts the `character` of a `Position` (the negotiated
/// `PositionEncodingKind`): `utf8` bytes, `utf16` code units (an astral
/// character such as U+1F600 is 2), `utf32` code points. LSP's default, and
/// what every client supports, is `utf16`.
pub const PositionEncoding = enum { utf8, utf16, utf32 };

/// One decoded character of a line: its byte length and its size in `enc` units.
const CharUnits = struct { len: usize, units: u32 };

/// The character at byte `i` of `text`. A byte that does not start a valid
/// UTF-8 sequence (stray continuation byte, truncated, overlong or surrogate
/// encoding) is a character of its own, one unit in every encoding.
fn charUnits(text: []const u8, i: usize, enc: PositionEncoding) CharUnits {
    const b = text[i];
    if (b < 0x80) return .{ .len = 1, .units = 1 };
    const n = std.unicode.utf8ByteSequenceLength(b) catch return .{ .len = 1, .units = 1 };
    if (i + n > text.len) return .{ .len = 1, .units = 1 };
    const cp = std.unicode.utf8Decode(text[i..][0..n]) catch return .{ .len = 1, .units = 1 };
    return .{ .len = n, .units = switch (enc) {
        .utf8 => @intCast(n),
        .utf16 => if (cp >= 0x10000) 2 else 1,
        .utf32 => 1,
    } };
}

fn satU32(x: usize) u32 {
    return std.math.cast(u32, x) orelse std.math.maxInt(u32);
}

/// LSP's 0-based `character` for the 1-based byte column `byte_col_1based` of
/// `line_text` (the line without its line break). A column past the end of the
/// line is the line's length (LSP clamps the same way); a column inside a
/// multi-byte character counts as that character's start. Bytes that are not
/// valid UTF-8 count one unit each in every encoding. Column 0 is column 1.
pub fn lspCharacter(line_text: []const u8, byte_col_1based: u32, enc: PositionEncoding) u32 {
    const off = @min(@as(usize, byte_col_1based) -| 1, line_text.len);
    if (enc == .utf8) return satU32(off);
    var i: usize = 0;
    var units: usize = 0;
    while (i < off) {
        const c = charUnits(line_text, i, enc);
        if (i + c.len > off) break;
        i += c.len;
        units += c.units;
    }
    return satU32(units);
}

/// The inverse: the 1-based byte column of LSP `character` on `line_text`.
/// A `character` past the end of the line is the column just after the last
/// byte (LSP: "defaults back to the line length"). Null when it falls inside a
/// character: between the two halves of a UTF-16 surrogate pair. Bytes that
/// are not valid UTF-8 count as in `lspCharacter`.
pub fn byteColumn(line_text: []const u8, character: u32, enc: PositionEncoding) ?u32 {
    if (enc == .utf8) return satU32(@min(@as(usize, character), line_text.len) + 1);
    var i: usize = 0;
    var units: usize = 0;
    while (i < line_text.len) {
        if (units == character) break;
        const c = charUnits(line_text, i, enc);
        if (units + c.units > character) return null;
        units += c.units;
        i += c.len;
    }
    return satU32(i + 1);
}

pub const LspOptions = struct {
    /// LSP `Diagnostic.source`, "the source of this diagnostic" (the tool).
    /// Omitted when null.
    source: ?[]const u8 = null,
    /// Written before a `file` name to make a `DocumentUri`
    /// (`relatedInformation[].location.uri`). The file name is
    /// percent-encoded (everything but `A-Za-z0-9-._~/:@`), so an absolute path
    /// gives `file:///the/path` with the default, and a `file` that already is
    /// a URI passes through unchanged with an empty prefix. `fromLsp` strips
    /// the prefix and decodes the same way.
    uri_prefix: []const u8 = "file://",
};

const LspPos = struct { line: u32, character: u32 };
const LspRange = struct { start: LspPos, end: LspPos };

fn lspPosIn(text: ?[]const u8, line: u32, col: u32, enc: PositionEncoding) LspPos {
    return .{
        .line = line -| 1,
        .character = if (text) |t| lspCharacter(t, col, enc) else col -| 1,
    };
}

/// The LSP range of `span`. The source lines come from `sources` (found as
/// for rendering); without them `character` is `col - 1`, i.e. UTF-8 bytes
/// whatever `enc` says. Rules:
///   - no `line`: `0:0-0:0` (LSP requires a range);
///   - `line` but no `col`: the whole line (start of line to its end; without
///     the text a zero-width range at its start);
///   - `col` and no end: zero-width at `col`. A point, not "one character": we
///     do not know the width of what the finding is about, editors expand an
///     empty range to the word under it, and a one-character guess could
///     cover a line break or half of a UTF-16 pair;
///   - `end_col` without `end_line`: same line; `end_line` without `end_col`:
///     the end of that line;
///   - an end before the start is clamped to the start.
fn lspRangeOf(span: Span, sources: []const Source, enc: PositionEncoding) LspRange {
    const line = span.line orelse return .{ .start = .{ .line = 0, .character = 0 }, .end = .{ .line = 0, .character = 0 } };
    const src = findSource(span, sources);
    const text: ?[]const u8 = if (src) |s| lineIn(s, line) else null;
    const start = lspPosIn(text, line, span.col orelse 1, enc);
    var end = start;
    if (span.col == null) {
        if (text) |t| end.character = lspCharacter(t, satU32(t.len + 1), enc);
    } else if (span.end_line != null or span.end_col != null) {
        const el = span.end_line orelse line;
        const etext: ?[]const u8 = if (el == line) text else if (src) |s| lineIn(s, el) else null;
        if (span.end_col) |ec| {
            end = lspPosIn(etext, el, ec, enc);
        } else {
            end = .{ .line = el -| 1, .character = if (etext) |t| lspCharacter(t, satU32(t.len + 1), enc) else 0 };
        }
    }
    if (end.line < start.line or (end.line == start.line and end.character < start.character)) end = start;
    return .{ .start = start, .end = end };
}

fn severityNumber(s: Severity) u8 {
    return switch (s) {
        .@"error" => 1,
        .warning => 2,
        .info => 3,
        .hint => 4,
    };
}

fn tagNumber(t: Tag) u8 {
    return switch (t) {
        .unnecessary => 1,
        .deprecated => 2,
    };
}

fn isUriSafe(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '-', '.', '_', '~', '/', ':', '@' => true,
        else => false,
    };
}

/// A JSON string value: `uri_prefix` and the percent-encoded `file`.
fn writeUri(s: *std.json.Stringify, file: ?[]const u8, opts: LspOptions) std.Io.Writer.Error!void {
    const w = s.writer;
    try s.beginWriteRaw();
    defer s.endWriteRaw();
    try w.writeByte('"');
    try std.json.Stringify.encodeJsonStringChars(opts.uri_prefix, .{}, w);
    if (file) |f| for (f) |c| {
        if (isUriSafe(c)) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    };
    try w.writeByte('"');
}

fn writeLspValue(s: *std.json.Stringify, d: Diagnostic, sources: []const Source, enc: PositionEncoding, opts: LspOptions) std.Io.Writer.Error!void {
    try s.beginObject();
    try s.objectField("range");
    try s.write(lspRangeOf(primarySpan(d), sources, enc));
    try s.objectField("severity");
    try s.write(severityNumber(d.severity));
    if (d.code.len > 0) {
        try s.objectField("code");
        try s.write(d.code);
    }
    if (d.code_url) |u| {
        try s.objectField("codeDescription");
        try s.beginObject();
        try s.objectField("href");
        try s.write(u);
        try s.endObject();
    }
    if (opts.source) |src| {
        try s.objectField("source");
        try s.write(src);
    }
    try s.objectField("message");
    try s.write(d.message);
    if (d.tags) |tags| if (tags.len > 0) {
        try s.objectField("tags");
        try s.beginArray();
        for (tags) |t| try s.write(tagNumber(t));
        try s.endArray();
    };
    if (d.labels) |labels| if (labels.len > 0) {
        try s.objectField("relatedInformation");
        try s.beginArray();
        for (labels) |l| {
            const span = labelSpan(d, l);
            try s.beginObject();
            try s.objectField("location");
            try s.beginObject();
            try s.objectField("uri");
            try writeUri(s, span.file, opts);
            try s.objectField("range");
            try s.write(lspRangeOf(span, sources, enc));
            try s.endObject();
            try s.objectField("message");
            try s.write(l.message);
            try s.endObject();
        }
        try s.endArray();
    };
    try s.endObject();
}

/// Write `d` as one LSP 3.17 `Diagnostic` JSON object (compact):
/// `range` (see `lspRangeOf` rules above, `character` in `enc`), `severity`
/// (1..4), `code` (always a string; omitted when empty), `codeDescription.href`
/// from `code_url`, `source` from `opts.source`, `message` (verbatim, JSON
/// escaped: this is data, not terminal text), `tags`, and `relatedInformation`
/// from `labels` (`location.uri` from the label's file or the diagnostic's,
/// see `LspOptions.uri_prefix`). Not written: `path`, `suggest`, `notes`,
/// `fix`, `span_message`, `expr_*` (no LSP field; a fix is a code action, not
/// part of a diagnostic) and `data`.
pub fn writeLsp(w: *std.Io.Writer, d: Diagnostic, sources: []const Source, enc: PositionEncoding, opts: LspOptions) std.Io.Writer.Error!void {
    var s: std.json.Stringify = .{ .writer = w, .options = .{} };
    try writeLspValue(&s, d, sources, enc, opts);
}

/// `writeLsp` for each of `items`, as a JSON array: the `diagnostics` of a
/// `textDocument/publishDiagnostics` notification.
pub fn writeLspArray(w: *std.Io.Writer, items: []const Diagnostic, sources: []const Source, enc: PositionEncoding, opts: LspOptions) std.Io.Writer.Error!void {
    var s: std.json.Stringify = .{ .writer = w, .options = .{} };
    try s.beginArray();
    for (items) |d| try writeLspValue(&s, d, sources, enc, opts);
    try s.endArray();
}

pub const FromLspError = error{ OutOfMemory, InvalidDiagnostic };

fn jsonField(obj: std.json.ObjectMap, key: []const u8) ?std.json.Value {
    const v = obj.get(key) orelse return null;
    return if (v == .null) null else v;
}

fn jsonU32(v: ?std.json.Value) FromLspError!u32 {
    const x = v orelse return error.InvalidDiagnostic;
    if (x != .integer) return error.InvalidDiagnostic;
    return std.math.cast(u32, x.integer) orelse error.InvalidDiagnostic;
}

fn lspPosFrom(v: ?std.json.Value) FromLspError!LspPos {
    const p = v orelse return error.InvalidDiagnostic;
    if (p != .object) return error.InvalidDiagnostic;
    return .{ .line = try jsonU32(p.object.get("line")), .character = try jsonU32(p.object.get("character")) };
}

/// The 1-based byte column of `p` on its line (`line_text` null: unknown, so
/// `character + 1`). A position between the halves of a surrogate pair is
/// taken to be at the pair's start.
fn colFrom(line_text: ?[]const u8, p: LspPos, enc: PositionEncoding) u32 {
    const t = line_text orelse return p.character +| 1;
    return byteColumn(t, p.character, enc) orelse
        byteColumn(t, p.character -| 1, enc) orelse p.character +| 1;
}

const FromRange = struct { line: u32, col: u32, end_line: ?u32, end_col: ?u32 };

fn rangeFrom(v: ?std.json.Value, file: ?[]const u8, sources: []const Source, enc: PositionEncoding) FromLspError!FromRange {
    const r = v orelse return error.InvalidDiagnostic;
    if (r != .object) return error.InvalidDiagnostic;
    const a = try lspPosFrom(r.object.get("start"));
    const b = try lspPosFrom(r.object.get("end"));
    const line = std.math.add(u32, a.line, 1) catch return error.InvalidDiagnostic;
    const eline = std.math.add(u32, b.line, 1) catch return error.InvalidDiagnostic;
    const src = findSource(.{ .file = file, .line = line, .col = null, .end_line = null, .end_col = null }, sources);
    const atext: ?[]const u8 = if (src) |s| lineIn(s, line) else null;
    const col = colFrom(atext, a, enc);
    // A zero-width range is a point: no end (as `writeLsp` writes it).
    if (a.line == b.line and a.character == b.character) return .{ .line = line, .col = col, .end_line = null, .end_col = null };
    const btext: ?[]const u8 = if (eline == line) atext else if (src) |s| lineIn(s, eline) else null;
    return .{ .line = line, .col = col, .end_line = eline, .end_col = colFrom(btext, b, enc) };
}

/// The inverse of `writeUri`: `uri` without `prefix`, percent-decoded; the
/// whole decoded `uri` when it does not start with the prefix.
fn fileFromUri(arena: std.mem.Allocator, uri: []const u8, prefix: []const u8) std.mem.Allocator.Error![]const u8 {
    const rest = if (std.mem.startsWith(u8, uri, prefix)) uri[prefix.len..] else uri;
    const out = try arena.alloc(u8, rest.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < rest.len) : (n += 1) {
        // Two hex digits exactly: `parseInt` alone would take a sign (`%+f`).
        if (rest[i] == '%' and i + 2 < rest.len and std.ascii.isHex(rest[i + 1]) and std.ascii.isHex(rest[i + 2])) {
            out[n] = std.fmt.parseInt(u8, rest[i + 1 ..][0..2], 16) catch unreachable;
            i += 3;
            continue;
        }
        out[n] = rest[i];
        i += 1;
    }
    return out[0..n];
}

/// Read one LSP `Diagnostic` (a parsed JSON value) back. `file` is the document
/// the diagnostic was published for (`PublishDiagnosticsParams.uri`, turned
/// into a name by the caller), `sources` the texts to turn `character` back
/// into a byte column with `enc` (a line that is not there: `character + 1`).
/// Everything is allocated in `arena`, including the strings.
///   - `range` -> `line`/`col`/`end_line`/`end_col` (a zero-width range has no
///     end); `message` and `range` are required, else `error.InvalidDiagnostic`;
///   - `severity` 1..4 (absent or unknown: `error`, as most clients read it);
///   - `code` string or integer -> string; `codeDescription.href` -> `code_url`;
///   - `tags` 1/2 -> `tags` (others dropped);
///   - `relatedInformation` -> `labels`, `location.uri` -> `Label.file` via
///     `opts.uri_prefix` (null when it is `file` itself);
///   - dropped: `source` (a `Diagnostic` has none; it is the producing tool),
///     `data`. `path` is empty.
pub fn fromLsp(arena: std.mem.Allocator, v: std.json.Value, file: ?[]const u8, sources: []const Source, enc: PositionEncoding, opts: LspOptions) FromLspError!Diagnostic {
    if (v != .object) return error.InvalidDiagnostic;
    const o = v.object;
    const msg = jsonField(o, "message") orelse return error.InvalidDiagnostic;
    if (msg != .string) return error.InvalidDiagnostic;
    const r = try rangeFrom(o.get("range"), file, sources, enc);
    var d: Diagnostic = .{
        .path = "",
        .file = file,
        .line = r.line,
        .col = r.col,
        .end_line = r.end_line,
        .end_col = r.end_col,
        .severity = .@"error",
        .code = "",
        .message = try arena.dupe(u8, msg.string),
    };
    if (jsonField(o, "severity")) |sv| if (sv == .integer) {
        d.severity = switch (sv.integer) {
            2 => .warning,
            3 => .info,
            4 => .hint,
            else => .@"error",
        };
    };
    if (jsonField(o, "code")) |c| switch (c) {
        .string => |t| d.code = try arena.dupe(u8, t),
        .integer => |n| d.code = try std.fmt.allocPrint(arena, "{d}", .{n}),
        else => return error.InvalidDiagnostic,
    };
    if (jsonField(o, "codeDescription")) |cd| {
        if (cd != .object) return error.InvalidDiagnostic;
        const href = jsonField(cd.object, "href") orelse return error.InvalidDiagnostic;
        if (href != .string) return error.InvalidDiagnostic;
        d.code_url = try arena.dupe(u8, href.string);
    }
    if (jsonField(o, "tags")) |tv| {
        if (tv != .array) return error.InvalidDiagnostic;
        var tags: std.ArrayList(Tag) = .empty;
        for (tv.array.items) |t| {
            if (t != .integer) return error.InvalidDiagnostic;
            switch (t.integer) {
                1 => try tags.append(arena, .unnecessary),
                2 => try tags.append(arena, .deprecated),
                else => {},
            }
        }
        if (tags.items.len > 0) d.tags = tags.items;
    }
    if (jsonField(o, "relatedInformation")) |ri| {
        if (ri != .array) return error.InvalidDiagnostic;
        const labels = try arena.alloc(Label, ri.array.items.len);
        for (ri.array.items, labels) |item, *out| {
            if (item != .object) return error.InvalidDiagnostic;
            const loc = jsonField(item.object, "location") orelse return error.InvalidDiagnostic;
            if (loc != .object) return error.InvalidDiagnostic;
            const uri = jsonField(loc.object, "uri") orelse return error.InvalidDiagnostic;
            const m = jsonField(item.object, "message") orelse return error.InvalidDiagnostic;
            if (uri != .string or m != .string) return error.InvalidDiagnostic;
            const lfile = try fileFromUri(arena, uri.string, opts.uri_prefix);
            const same = file != null and std.mem.eql(u8, lfile, file.?);
            const lr = try rangeFrom(loc.object.get("range"), if (same) file else lfile, sources, enc);
            out.* = .{
                .file = if (same) null else lfile,
                .line = lr.line,
                .col = lr.col,
                .end_line = lr.end_line,
                .end_col = lr.end_col,
                .message = try arena.dupe(u8, m.string),
            };
        }
        if (labels.len > 0) d.labels = labels;
    }
    return d;
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
        \\  --> conf.json5:2:3
        \\  |
        \\2 |   unknwn: 1,
        \\  |   ^^^^^^
        \\  |
        \\  = at: templates.x.unknwn
        \\  = help: did you mean 'unknown'?
        \\
        \\
    , try renderToString(&buf, unknown_key, .{ .style = .snippet, .sources = &.{src} }));
}

test "render snippet: without the source text, only the header, location and notes" {
    var buf: [512]u8 = undefined;
    const other: Source = .{ .file = "other.json5", .text = "{\n  unknwn: 1,\n}\n" };
    try testing.expectEqualStrings(
        \\warning[config.unknown_key]: unknown key 'unknwn'
        \\ --> conf.json5:2:3
        \\ = at: templates.x.unknwn
        \\ = help: did you mean 'unknown'?
        \\
        \\
    , try renderToString(&buf, unknown_key, .{ .style = .snippet, .sources = &.{other} }));
    // A line past the end of the source quotes nothing either.
    var past = unknown_key;
    past.line = 40;
    const src: Source = .{ .file = "conf.json5", .text = "{}\n" };
    try testing.expect(std.mem.find(u8, try renderToString(&buf, past, .{ .style = .snippet, .sources = &.{src} }), " | ") == null);
}

test "render snippet: carets align after tabs and multi-byte UTF-8, a span runs to the end of a multi-line range" {
    var buf: [512]u8 = undefined;
    // "\tné: x" -- tab, 'n', 'é' (2 bytes), ':' ... the key "x" is at byte col 7.
    const src: Source = .{ .file = "f", .text = "\tn\xC3\xA9: xyz" };
    const d: Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 7, .end_line = 1, .end_col = 10, .severity = .@"error", .code = "", .message = "bad" };
    try testing.expectEqualStrings(
        "error: bad\n  --> f:1:7\n  |\n1 |     n\xC3\xA9: xyz\n  |         ^^^\n\n",
        try renderToString(&buf, d, .{ .style = .snippet, .sources = &.{src} }),
    );
    // A span ending on a later line underlines to the end of this one; a
    // finding with no end gets one caret; a col past the end clamps.
    var multi = d;
    multi.end_line = 3;
    try testing.expect(std.mem.endsWith(u8, try renderToString(&buf, multi, .{ .style = .snippet, .sources = &.{src} }), "  |         ^^^\n\n"));
    var one = d;
    one.end_line = null;
    one.end_col = null;
    try testing.expect(std.mem.endsWith(u8, try renderToString(&buf, one, .{ .style = .snippet, .sources = &.{src} }), "  |         ^\n\n"));
    var far = one;
    far.col = 99;
    try testing.expect(std.mem.endsWith(u8, try renderToString(&buf, far, .{ .style = .snippet, .sources = &.{src} }), "  |            ^\n\n"));
}

test "render: a finding with no file uses the only source" {
    var buf: [512]u8 = undefined;
    const d: Diagnostic = .{ .path = "", .line = 1, .col = 1, .severity = .info, .code = "", .message = "m" };
    try testing.expectEqualStrings(
        "info: m\n  --> 1:1\n  |\n1 | abc\n  | ^\n\n",
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
    try testing.expect(std.mem.findScalar(u8, snip, 0x1b) == null);
    try testing.expect(std.mem.findScalar(u8, snip, 0x07) == null);
    try testing.expect(std.mem.find(u8, snip, "1 | ?]0;t?k: 1\n") != null);
}

fn spanAt(line: u32) Span {
    return .{ .file = "f", .line = line, .col = null, .end_line = null, .end_col = null };
}

test "line index: the same quoted lines with and without Source.line_starts" {
    const text = "one\r\ntwo\n\nfour\nfive";
    const starts = try Source.indexLines(testing.allocator, text);
    defer testing.allocator.free(starts);
    try testing.expectEqualSlices(u32, &.{ 0, 5, 9, 10, 15 }, starts);
    const plain = [_]Source{.{ .file = "f", .text = text }};
    const indexed = [_]Source{.{ .file = "f", .text = text, .line_starts = starts }};
    for (1..7) |ln| {
        const span: Span = spanAt(@intCast(ln));
        const a = sourceLine(span, &plain);
        const b = sourceLine(span, &indexed);
        try testing.expectEqual(a == null, b == null);
        if (a) |x| try testing.expectEqualStrings(x, b.?);
    }
    try testing.expectEqualStrings("one", sourceLine(spanAt(1), &indexed).?);
    try testing.expectEqualStrings("", sourceLine(spanAt(3), &indexed).?);
    try testing.expectEqualStrings("five", sourceLine(spanAt(5), &plain).?);
    try testing.expect(sourceLine(spanAt(6), &plain) == null);
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

test "snippet: a secondary label shares the snippet; our notes follow codespan's, then help, fix, see" {
    // Layout derived by hand from codespan's rules: all quoted line numbers
    // are 1 digit, so the gutter is one column; the label 2:3..2:4 is one '-'
    // under the first 'a' and has its message after it, line 3 is shown
    // because only one line lies between the two, the primary span 4:3..4:4 is
    // one '^'. A border row separates the snippet from the notes, an empty
    // line ends the diagnostic.
    const got = try renderAlloc(dup, .{ .style = .snippet, .sources = &.{.{ .file = "c.json5", .text = dup_src }} });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\error[json5.duplicate_key]: duplicate key 'a'
        \\  --> c.json5:4:3
        \\  |
        \\2 |   a: 1,
        \\  |   - first defined here
        \\3 |   b: 2,
        \\4 |   a: 3,
        \\  |   ^
        \\  |
        \\  = note: the later value would silently win
        \\  = at: a
        \\  = help: rename one of them
        \\  = fix: replace c.json5:4:3..4:4 with "c"
        \\  = see: https://example.invalid/json5/duplicate_key
        \\
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

test "snippet: gutter widens to the longest quoted line number; a gap is a break row; an unquotable label is a location line" {
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
        \\   --> f:2:1
        \\   |
        \\ 2 | line2
        \\   | ^
        \\   .
        \\10 | line10
        \\   | ------ here
        \\   |
        \\   --> other:1: elsewhere
        \\
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
            i = std.mem.findScalarPos(u8, col, i, 'm').? + 1;
            continue;
        }
        try stripped.append(testing.allocator, col[i]);
        i += 1;
    }
    try testing.expectEqualStrings(plain, stripped.items);
    try testing.expect(std.mem.startsWith(u8, col, "\x1b[1;31merror[json5.duplicate_key]\x1b[0m"));
    try testing.expect(std.mem.find(u8, col, "\x1b[1;34m-\x1b[0m first defined here") != null);
    // A finding carrying an escape sequence still cannot emit one.
    var hostile = dup;
    hostile.message = "\x1b[2J";
    const h = try renderAlloc(hostile, .{ .color = true });
    defer testing.allocator.free(h);
    try testing.expect(std.mem.find(u8, h, "\x1b[2J") == null);
    try testing.expect(std.mem.find(u8, h, "\\x1b[2J") != null);
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
        \\
    , snip);
    const short = try renderAlloc(d, .{});
    defer testing.allocator.free(short);
    try testing.expectEqualStrings("warning[c]: m; help: try this; note: fyi; see https://x.invalid/\\x1b]8;;evil\\x07\n", short);
}

test {
    _ = @import("codespan_test.zig");
    _ = @import("lsp_test.zig");
    _ = @import("render_test.zig");
}

test "snippet: Unicode whitespace before a multi-line span's start gives the corner form" {
    // codespan's `str::trim_start` counts Unicode White_Space, so an ideographic
    // space (U+3000) is lead-in like ' ' and '\t' (found by interop-diagnostics;
    // expected text: codespan-reporting 0.13.1 on the same input).
    var buf: [256]u8 = undefined;
    const d: Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 4, .end_line = 2, .end_col = 3, .severity = .@"error", .code = "", .message = "m", .span_message = "here" };
    const out = try renderToString(&buf, d, .{ .style = .snippet, .sources = &.{.{ .file = "f", .text = "\u{3000}ab\ncd\n" }}, .column = .char });
    try testing.expectEqualStrings("error: m\n  --> f:1:2\n  |  \n1 | / \u{3000}ab\n2 | | cd\n  | \\--^ here\n\n", out);
}

test "escaping: bidi controls, C1 controls and invalid bytes never reach the terminal" {
    // Trojan Source (CVE-2021-42574): U+202E in a key name reorders what the
    // terminal shows. codespan-reporting 0.13.1 writes it, ESC and BEL raw
    // (tools/interop.zig's oracle on the same input); rustc/annotate-snippets
    // replace the bidi set; so do we, in finding text and in the quoted line.
    var buf: [1024]u8 = undefined;
    const hostile = "k\u{202e}ey\u{2066}\u{9b}2J\xff\u{2028}x";
    const d: Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 2, .end_line = 1, .end_col = 5, .severity = .@"error", .code = "", .message = hostile, .span_message = hostile, .notes = &.{.{ .message = hostile }} };
    for ([_]bool{ false, true }) |color| {
        for ([_]RenderStyle{ .short, .snippet }) |style| {
            const out = try renderToString(&buf, d, .{ .style = style, .color = color, .sources = &.{.{ .file = "f", .text = hostile ++ "\n" }} });
            for ([_][]const u8{ "\u{202e}", "\u{2066}", "\u{9b}", "\xff", "\u{2028}" }) |bad|
                try testing.expect(std.mem.find(u8, out, bad) == null);
            if (style == .short) {
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
                try testing.expect(std.mem.find(u8, out, "k\\u{202e}ey\\u{2066}\\u{009b}2J\\xff\\u{2028}x") != null);
            } else try testing.expect(std.mem.find(u8, out, "1 | k?ey?\u{9b}") == null);
        }
    }
    const snip = try renderToString(&buf, d, .{ .style = .snippet, .sources = &.{.{ .file = "f", .text = hostile ++ "\n" }} });
    try testing.expect(std.mem.find(u8, snip, "1 | k?ey??2J??x\n") != null);
}
