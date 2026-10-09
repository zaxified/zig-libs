// SPDX-License-Identifier: MIT

//! ini — an INI reader: `[section]` headers, `key = value` entries, comment
//! lines, in the dialects that matter in practice.
//!
//! `parse` reads the whole text into a `Document`: its sections in file order,
//! each with its entries in file order and the 1-based line every one came
//! from. Nothing is merged or dropped at parse time -- a repeated section or
//! key stays where it was -- and lookups (`get`, `entries`) apply the rule
//! every INI reader agrees on: a later value wins, and a section named twice
//! is one section. Values are returned RAW, as Python's `configparser` and
//! GLib's `GKeyFile.get_value` return them; quotes and escapes are the
//! caller's choice (`unquote`, `unescapeDesktop`), because which of them a
//! file means depends on who wrote it.
//!
//! INI has no standard, so the grammar is a handful of `Options`, with two
//! presets pinned against a real implementation each (see SPEC.md):
//!
//!   * `Options.python` -- `configparser.RawConfigParser` with its default
//!     delimiters (`=` and `:`), `#`/`;` comments, continuation lines by
//!     indentation, no entries before the first section.
//!   * `Options.desktop` -- freedesktop.org Desktop Entry / GLib key files
//!     (`.desktop`, mc skins, many GNOME/KDE settings): `#` comments, `=`
//!     only, a value keeps its trailing whitespace.
//!   * The default, `.{}`: `#`/`;` comments, `=`, entries before the first
//!     section allowed (in a section named ""), no continuation lines.
//!
//! Every preset is strict: a line that is not blank, a comment, a header or
//! `key = value` is `error.MissingSeparator` (or its sibling) with the line
//! in `ErrorInfo`. `.strict = false` skips such lines instead and lists them
//! in `Document.skipped`.
//!
//! Provenance: clean-room. The grammar is this module's; Python's
//! `configparser` (PSF licence) and GLib's `GKeyFile` (LGPL) were only RUN,
//! as black-box oracles, to produce the goldens in `src/testdata/` -- neither
//! implementation's source was read (`tools/README.md`).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "INI reader — sections, key = value, comments; Python configparser and Desktop Entry (GKeyFile) dialects.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Python configparser / GLib GKeyFile / Go gopkg.in/ini.v1",
    .deps = .{}, // std only
};

// ── options ──────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// A line whose first non-blank byte is one of these is a comment.
    comment_chars: []const u8 = "#;",
    /// Also end a value at a comment character that follows whitespace
    /// (`k = v ; note` -> `v`). Off by default: mc skins use `;` inside
    /// values, and neither reference implementation does this by default.
    /// Quotes are not looked at (Python's `inline_comment_prefixes` behaves
    /// the same way).
    inline_comments: bool = false,
    /// Each of these separates a key from its value; the first one on the
    /// line wins (`k = a:b` with `=:` is key `k`, value `a:b`).
    separators: []const u8 = "=",
    /// Strip trailing whitespace from values. GKeyFile keeps it (`k=v  `
    /// is `v  `), Python strips it. Leading whitespace is always stripped.
    trim_values: bool = true,
    /// An indented line after an entry, indented deeper than that entry's
    /// own line, continues its value on a new line (`\n` + the line,
    /// trimmed) -- Python's continuation rule. A blank or comment line ends
    /// the value.
    continuation_lines: bool = false,
    /// Entries before the first header go into a section named "" (at index
    /// 0 of `Document.sections`). When false they are
    /// `error.EntryOutsideSection`.
    global_entries: bool = true,
    /// A header's name ends at the LAST `]` on the line and whatever follows
    /// it is ignored (Python). When false the `]` must end the line (only
    /// whitespace after it) and the name may not contain `[` or `]`
    /// (GKeyFile). Either way the name is not trimmed: `[ a ]` is " a ",
    /// as in both references.
    header_trailing_text: bool = false,
    /// A key may contain `[` and `]` only as a trailing `[locale]` after a
    /// non-empty name, the locale without whitespace or brackets (`Name[cs]`,
    /// even `Name[]`); anything else is `error.InvalidKey`. GKeyFile's rule.
    locale_keys: bool = false,
    /// Match section names / keys ignoring ASCII case in `get`/`entries`.
    /// Parsing is unaffected: names are stored as written.
    case_insensitive_sections: bool = false,
    case_insensitive_keys: bool = false,
    /// false: a line that is not blank, a comment, a header or an entry is
    /// skipped and its number recorded in `Document.skipped`, instead of
    /// failing the parse.
    strict: bool = true,

    /// Python's `configparser.RawConfigParser` with default delimiters,
    /// `strict=False`, `empty_lines_in_values=False` and `optionxform=str`
    /// (keys keep their case) -- what the goldens were captured with.
    pub const python: Options = .{
        .comment_chars = "#;",
        .separators = "=:",
        .continuation_lines = true,
        .global_entries = false,
        .header_trailing_text = true,
    };

    /// Desktop Entry / GLib key-file syntax, as `GKeyFile` reads it.
    pub const desktop: Options = .{
        .comment_chars = "#",
        .separators = "=",
        .trim_values = false,
        .global_entries = false,
        .locale_keys = true,
    };
};

// ── document ─────────────────────────────────────────────────────────────────

pub const Entry = struct {
    key: []const u8,
    value: []const u8,
    /// 1-based line of the `key = value` line (a continued value's first line).
    line: usize,
};

pub const Section = struct {
    /// "" for the entries before the first header (`Options.global_entries`).
    name: []const u8,
    /// 1-based line of the header; 0 for the "" section.
    line: usize,
    entries: []const Entry,
};

/// A parsed file. Owns every string in it (nothing borrows the input text);
/// `deinit` frees it all.
pub const Document = struct {
    arena: std.heap.ArenaAllocator,
    /// In file order; a section named twice appears twice.
    sections: []const Section,
    /// Lines skipped by a non-strict parse (1-based). Empty when strict.
    skipped: []const usize,
    case_insensitive_sections: bool,
    case_insensitive_keys: bool,

    pub fn deinit(self: *Document) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// The value of `key` in `section`: the last one in the file, across
    /// every section of that name. `section` "" is the entries before the
    /// first header.
    pub fn get(self: *const Document, section: []const u8, key: []const u8) ?[]const u8 {
        var found: ?[]const u8 = null;
        var it = self.entries(section);
        while (it.next()) |e| {
            if (self.keyEql(e.key, key)) found = e.value;
        }
        return found;
    }

    /// `get`, read as a boolean the way Python's `getboolean` does:
    /// `1 yes true on` / `0 no false off`, any ASCII case. Null when the key
    /// is absent; `error.NotABool` for any other value.
    pub fn getBool(self: *const Document, section: []const u8, key: []const u8) error{NotABool}!?bool {
        const v = self.get(section, key) orelse return null;
        for ([_][]const u8{ "1", "yes", "true", "on" }) |t| if (std.ascii.eqlIgnoreCase(v, t)) return true;
        for ([_][]const u8{ "0", "no", "false", "off" }) |f| if (std.ascii.eqlIgnoreCase(v, f)) return false;
        return error.NotABool;
    }

    /// Whether any section is named `section`.
    pub fn hasSection(self: *const Document, section: []const u8) bool {
        for (self.sections) |s| if (self.sectionEql(s.name, section)) return true;
        return false;
    }

    /// Every entry of every section named `section`, in file order,
    /// repeated keys included (a list-valued key, or to see what `get`
    /// overrode).
    pub fn entries(self: *const Document, section: []const u8) EntryIterator {
        return .{ .doc = self, .section = section };
    }

    pub const EntryIterator = struct {
        doc: *const Document,
        section: []const u8,
        si: usize = 0,
        ei: usize = 0,

        pub fn next(it: *EntryIterator) ?Entry {
            while (it.si < it.doc.sections.len) {
                const s = it.doc.sections[it.si];
                if (it.doc.sectionEql(s.name, it.section) and it.ei < s.entries.len) {
                    it.ei += 1;
                    return s.entries[it.ei - 1];
                }
                it.si += 1;
                it.ei = 0;
            }
            return null;
        }
    };

    fn sectionEql(self: *const Document, a: []const u8, b: []const u8) bool {
        return if (self.case_insensitive_sections) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
    }

    fn keyEql(self: *const Document, a: []const u8, b: []const u8) bool {
        return if (self.case_insensitive_keys) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
    }
};

// ── parsing ──────────────────────────────────────────────────────────────────

pub const ParseError = error{
    /// A line that is not blank, a comment or a header has no separator.
    MissingSeparator,
    /// A `= value` line: the key is empty.
    EmptyKey,
    /// An entry before the first header with `global_entries = false`.
    EntryOutsideSection,
    /// A key with brackets other than a `[locale]` suffix, with
    /// `locale_keys = true`.
    InvalidKey,
};

/// Where a strict parse failed.
pub const ErrorInfo = struct {
    /// 1-based.
    line: usize = 0,
};

/// Parse `text`. The `Document` owns copies of everything it holds.
pub fn parse(gpa: Allocator, text: []const u8, opts: Options) (ParseError || Allocator.Error)!Document {
    var info: ErrorInfo = .{};
    return parseDiag(gpa, text, opts, &info);
}

/// `parse`, reporting the failing line of a strict parse in `info`.
pub fn parseDiag(gpa: Allocator, text: []const u8, opts: Options, info: *ErrorInfo) (ParseError || Allocator.Error)!Document {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();

    const SectionB = struct { name: []const u8, line: usize, entries: std.ArrayList(Entry) = .empty };
    var sections: std.ArrayList(SectionB) = .empty;
    var skipped: std.ArrayList(usize) = .empty;
    // The entry a deeper-indented line would continue, that entry's own
    // indentation, and its value as it grows: one buffer per entry, so a
    // value continued over N lines costs O(its length), not O(N * length).
    const Cont = struct { entry: *Entry, indent: usize, value: std.ArrayList(u8) = .empty };
    var cont: ?Cont = null;

    // A UTF-8 byte-order mark is skipped (neither reference does; see SPEC).
    const body_text = if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text[3..] else text;
    var it = std.mem.splitScalar(u8, body_text, '\n');
    var line_no: usize = 0;
    while (it.next()) |raw| {
        line_no += 1;
        const line = if (std.mem.endsWith(u8, raw, "\r")) raw[0 .. raw.len - 1] else raw;
        const indent = line.len - std.mem.trimStart(u8, line, " \t").len;
        const content = std.mem.trimEnd(u8, line[indent..], " \t");

        if (content.len == 0) {
            cont = null;
            continue;
        }
        if (std.mem.indexOfScalar(u8, opts.comment_chars, content[0]) != null) {
            cont = null;
            continue;
        }
        if (cont) |*c| {
            if (opts.continuation_lines and indent > c.indent) {
                if (c.value.items.len == 0) try c.value.appendSlice(a, c.entry.value);
                try c.value.append(a, '\n');
                try c.value.appendSlice(a, content);
                c.entry.value = c.value.items;
                continue;
            }
        }
        // `cont` points into the last section's entry list, so it must be
        // cleared before anything below appends to a list.
        cont = null;

        if (headerName(content, opts)) |name| {
            try sections.append(a, .{ .name = try a.dupe(u8, name), .line = line_no });
            continue;
        }

        const sep = std.mem.indexOfAny(u8, content, opts.separators) orelse {
            if (!opts.strict) {
                try skipped.append(a, line_no);
                continue;
            }
            info.line = line_no;
            return error.MissingSeparator;
        };
        const key = std.mem.trimEnd(u8, content[0..sep], " \t");
        const key_error: ?ParseError = if (key.len == 0)
            error.EmptyKey
        else if (opts.locale_keys and !isLocaleKey(key))
            error.InvalidKey
        else
            null;
        if (key_error) |e| {
            if (!opts.strict) {
                try skipped.append(a, line_no);
                continue;
            }
            info.line = line_no;
            return e;
        }
        // The value runs to the end of the LINE, not of `content`: with
        // `trim_values = false` its trailing whitespace is kept.
        const rest = line[indent + sep + 1 ..];
        var value = std.mem.trimStart(u8, rest, " \t");
        if (opts.inline_comments) value = cutInlineComment(value, opts.comment_chars);
        if (opts.trim_values) value = std.mem.trimEnd(u8, value, " \t");

        if (sections.items.len == 0) {
            if (!opts.global_entries) {
                if (!opts.strict) {
                    try skipped.append(a, line_no);
                    continue;
                }
                info.line = line_no;
                return error.EntryOutsideSection;
            }
            try sections.append(a, .{ .name = "", .line = 0 });
        }
        const cur = &sections.items[sections.items.len - 1];
        try cur.entries.append(a, .{ .key = try a.dupe(u8, key), .value = try a.dupe(u8, value), .line = line_no });
        cont = .{ .entry = &cur.entries.items[cur.entries.items.len - 1], .indent = indent };
    }

    const out = try a.alloc(Section, sections.items.len);
    for (sections.items, out) |s, *o| o.* = .{ .name = s.name, .line = s.line, .entries = s.entries.items };
    return .{
        .arena = arena_state,
        .sections = out,
        .skipped = skipped.items,
        .case_insensitive_sections = opts.case_insensitive_sections,
        .case_insensitive_keys = opts.case_insensitive_keys,
    };
}

/// The section name if `content` (a line without its surrounding
/// whitespace) is a header, else null -- and then it is read as an entry,
/// which is how both references treat `[a` or `[a=b`.
fn headerName(content: []const u8, opts: Options) ?[]const u8 {
    if (content[0] != '[') return null;
    const close = std.mem.lastIndexOfScalar(u8, content, ']') orelse return null;
    if (close < 2) return null; // `[]`: no name
    const name = content[1..close];
    if (!opts.header_trailing_text) {
        if (close != content.len - 1) return null;
        if (std.mem.indexOfAny(u8, name, "[]") != null) return null;
    }
    return name;
}

/// `name` or `name[locale]`: see `Options.locale_keys`.
fn isLocaleKey(key: []const u8) bool {
    const open = std.mem.indexOfScalar(u8, key, '[') orelse
        return std.mem.indexOfScalar(u8, key, ']') == null;
    if (open == 0 or key[key.len - 1] != ']') return false;
    return std.mem.indexOfAny(u8, key[open + 1 .. key.len - 1], "[] \t") == null;
}

fn cutInlineComment(value: []const u8, comment_chars: []const u8) []const u8 {
    var i: usize = 1;
    while (i < value.len) : (i += 1) {
        if (std.mem.indexOfScalar(u8, comment_chars, value[i]) != null and
            (value[i - 1] == ' ' or value[i - 1] == '\t'))
            return std.mem.trimEnd(u8, value[0..i], " \t");
    }
    return value;
}

// ── value helpers ────────────────────────────────────────────────────────────

/// A value in matching double or single quotes, without them: inside
/// double quotes `\\`, `\"`, `\n`, `\t`, `\r` are escapes (any other
/// backslash is kept as written); single quotes take no escapes. A value
/// that is not wholly quoted is returned as it is. Caller frees.
pub fn unquote(gpa: Allocator, raw: []const u8) Allocator.Error![]u8 {
    if (raw.len >= 2 and raw[0] == '\'' and raw[raw.len - 1] == '\'') return gpa.dupe(u8, raw[1 .. raw.len - 1]);
    if (!(raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"')) return gpa.dupe(u8, raw);
    const inner = raw[1 .. raw.len - 1];
    var out: std.ArrayList(u8) = try .initCapacity(gpa, inner.len);
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < inner.len) : (i += 1) {
        if (inner[i] == '\\' and i + 1 < inner.len) {
            const e: ?u8 = switch (inner[i + 1]) {
                '\\' => '\\',
                '"' => '"',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                else => null,
            };
            if (e) |c| {
                out.appendAssumeCapacity(c);
                i += 1;
                continue;
            }
        }
        out.appendAssumeCapacity(inner[i]);
    }
    return out.toOwnedSlice(gpa);
}

/// A Desktop Entry string value with its escapes resolved: `\s` space, `\n`
/// newline, `\t` tab, `\r` carriage return, `\\` backslash (Desktop Entry
/// Specification, "Possible value types"). Any other backslash sequence, or
/// a trailing backslash, is `error.InvalidEscape`. Caller frees.
pub fn unescapeDesktop(gpa: Allocator, raw: []const u8) (Allocator.Error || error{InvalidEscape})![]u8 {
    var out: std.ArrayList(u8) = try .initCapacity(gpa, raw.len);
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] != '\\') {
            out.appendAssumeCapacity(raw[i]);
            continue;
        }
        if (i + 1 == raw.len) return error.InvalidEscape;
        i += 1;
        out.appendAssumeCapacity(switch (raw[i]) {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            else => return error.InvalidEscape,
        });
    }
    return out.toOwnedSlice(gpa);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = @import("oracle_test.zig");
    _ = @import("fuzz_test.zig");
}

test "an mc skin: sections, later lines win, `;` inside values" {
    var doc = try parse(testing.allocator,
        \\[skin]
        \\    description = Default skin
        \\
        \\[core]
        \\    _default_ = lightgray;blue
        \\    selected = black;cyan
        \\# a comment
        \\[Core]
        \\    selected = white;red
    , .{ .case_insensitive_sections = true });
    defer doc.deinit();
    try testing.expectEqualStrings("Default skin", doc.get("skin", "description").?);
    try testing.expectEqualStrings("lightgray;blue", doc.get("core", "_default_").?);
    // [Core] is [core] under case-insensitive sections, and later wins.
    try testing.expectEqualStrings("white;red", doc.get("CORE", "selected").?);
    try testing.expectEqual(@as(?[]const u8, null), doc.get("core", "absent"));
    try testing.expectEqual(@as(usize, 3), doc.sections.len);
    try testing.expectEqual(@as(usize, 8), doc.sections[2].line);
    try testing.expectEqual(@as(usize, 9), doc.sections[2].entries[0].line);
}

test "a desktop entry: localized keys, trailing whitespace kept, escapes on request" {
    var doc = try parse(testing.allocator, "[Desktop Entry]\nName=Files\nName[cs]=Soubory\nComment=a\\sb\\nc  \n", .desktop);
    defer doc.deinit();
    try testing.expectEqualStrings("Soubory", doc.get("Desktop Entry", "Name[cs]").?);
    const raw = doc.get("Desktop Entry", "Comment").?;
    try testing.expectEqualStrings("a\\sb\\nc  ", raw);
    const s = try unescapeDesktop(testing.allocator, raw);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("a b\nc  ", s);
    try testing.expectError(error.InvalidEscape, unescapeDesktop(testing.allocator, "a\\q"));
    try testing.expectError(error.InvalidEscape, unescapeDesktop(testing.allocator, "a\\"));
    // Brackets in a key only as a `[locale]` suffix (GKeyFile).
    for ([_][]const u8{ "a[b", "a]b", "a[b]c", "[b]", "a[b][c]", "a[b c]" }) |k| {
        var line_buf: [32]u8 = undefined;
        const t = try std.fmt.bufPrint(&line_buf, "[g]\n{s}=v\n", .{k});
        try testing.expectError(error.InvalidKey, parse(testing.allocator, t, .desktop));
    }
    var ok = try parse(testing.allocator, "[g]\na[]=v\n", .desktop);
    ok.deinit();
}

test "python: continuation lines, `:` separator, comments end a value" {
    var doc = try parse(testing.allocator, "[a]\nk = first\n  second\n\tthird\nj: x=y\n", .python);
    defer doc.deinit();
    try testing.expectEqualStrings("first\nsecond\nthird", doc.get("a", "k").?);
    try testing.expectEqualStrings("x=y", doc.get("a", "j").?);
    try testing.expectError(error.MissingSeparator, parse(testing.allocator, "[a]\nk=v\n# c\n  more\n", .python));
}

test "a value continued over 100 000 lines is built in linear time" {
    // Each continuation line used to be `concat`ed onto the whole value so
    // far: quadratic, ~10^10 bytes copied for this input.
    const n = 100_000;
    const text = try testing.allocator.alloc(u8, "[a]\nk=x\n".len + n * "  x\n".len);
    defer testing.allocator.free(text);
    @memcpy(text[0..8], "[a]\nk=x\n");
    for (0..n) |i| @memcpy(text[8 + i * 4 ..][0..4], "  x\n");
    var doc = try parse(testing.allocator, text, .python);
    defer doc.deinit();
    const v = doc.get("a", "k").?;
    try testing.expectEqual(@as(usize, 1 + 2 * n), v.len);
    try testing.expectEqualStrings("x\nx\nx", v[0..5]);
}

test "strict errors carry the line; lenient skips and lists it" {
    var info: ErrorInfo = .{};
    try testing.expectError(error.MissingSeparator, parseDiag(testing.allocator, "[a]\nk=v\n\njunk\n", .{}, &info));
    try testing.expectEqual(@as(usize, 4), info.line);
    try testing.expectError(error.EmptyKey, parseDiag(testing.allocator, "[a]\n = v\n", .{}, &info));
    try testing.expectEqual(@as(usize, 2), info.line);
    try testing.expectError(error.EntryOutsideSection, parseDiag(testing.allocator, "k=v\n", .desktop, &info));
    try testing.expectEqual(@as(usize, 1), info.line);

    var doc = try parse(testing.allocator, "[a]\nk=v\njunk\n=x\nm=n\n", .{ .strict = false });
    defer doc.deinit();
    try testing.expectEqualSlices(usize, &.{ 3, 4 }, doc.skipped);
    try testing.expectEqualStrings("n", doc.get("a", "m").?);
}

test "global entries, empty values, BOM, CRLF" {
    var doc = try parse(testing.allocator, "\xEF\xBB\xBFtop=1\r\n[a]\r\nk=\r\n", .{});
    defer doc.deinit();
    try testing.expectEqualStrings("1", doc.get("", "top").?);
    try testing.expectEqualStrings("", doc.get("a", "k").?);
    try testing.expectEqualStrings("", doc.sections[0].name);
    try testing.expectEqual(@as(usize, 0), doc.sections[0].line);
}

test "headers: brackets, trailing text, what is not a header" {
    // Default: `]` ends the line, the name is not trimmed.
    var doc = try parse(testing.allocator, "[ a b ]  \nk=v\n", .{});
    defer doc.deinit();
    try testing.expectEqualStrings(" a b ", doc.sections[0].name);
    // `[a] x`, `[a]b]`, `[]` and `[a` are not headers there, so they are
    // read as entries -- and have no separator.
    for ([_][]const u8{ "[a] x\n", "[a]b]\n", "[]\n", "[a\n" }) |t|
        try testing.expectError(error.MissingSeparator, parse(testing.allocator, t, .{}));
    // Python: the name runs to the last `]`, the rest is ignored.
    var py = try parse(testing.allocator, "[a]b] x\nk=v\n", .python);
    defer py.deinit();
    try testing.expectEqualStrings("a]b", py.sections[0].name);
}

test "inline comments need whitespace before them" {
    var doc = try parse(testing.allocator, "[a]\nk = v ; note\nu = http://x#frag\nw = ;\n", .{ .inline_comments = true });
    defer doc.deinit();
    try testing.expectEqualStrings("v", doc.get("a", "k").?);
    try testing.expectEqualStrings("http://x#frag", doc.get("a", "u").?);
    try testing.expectEqualStrings(";", doc.get("a", "w").?); // a comment char at the very start is the value
}

test "getBool, entries across repeated sections, hasSection" {
    var doc = try parse(testing.allocator, "[a]\nx=Yes\ny=off\nz=maybe\nl=1\n[b]\n[a]\nl=2\n", .{});
    defer doc.deinit();
    try testing.expectEqual(@as(?bool, true), try doc.getBool("a", "x"));
    try testing.expectEqual(@as(?bool, false), try doc.getBool("a", "y"));
    try testing.expectError(error.NotABool, doc.getBool("a", "z"));
    try testing.expectEqual(@as(?bool, null), try doc.getBool("a", "absent"));
    var it = doc.entries("a");
    var ls: [2][]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |e| if (std.mem.eql(u8, e.key, "l")) {
        ls[n] = e.value;
        n += 1;
    };
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("1", ls[0]);
    try testing.expectEqualStrings("2", ls[1]);
    try testing.expect(doc.hasSection("b"));
    try testing.expect(!doc.hasSection("B"));
}

test "unquote: double quotes take escapes, single quotes none, anything else as is" {
    const cases = [_][2][]const u8{
        .{ "\"a \\\"b\\\" \\\\ \\n\\q\"", "a \"b\" \\ \n\\q" },
        .{ "'a \\n'", "a \\n" },
        .{ "\"unbalanced", "\"unbalanced" },
        .{ "\"", "\"" },
        .{ "plain", "plain" },
    };
    for (cases) |c| {
        const got = try unquote(testing.allocator, c[0]);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(c[1], got);
    }
}

test "locale keys: a blank, `[` or `]` inside the locale is an InvalidKey, each on its own" {
    for ([_][]const u8{ "a[b\tc]", "a[b c]", "a[b[c]", "a[b]c]" }) |k| {
        var line_buf: [32]u8 = undefined;
        const t = try std.fmt.bufPrint(&line_buf, "[g]\n{s}=v\n", .{k});
        try testing.expectError(error.InvalidKey, parse(testing.allocator, t, .desktop));
    }
    // lenient: the same lines are skipped, not fatal
    var lax = try parse(testing.allocator, "[g]\na[b[c]=v\na[b]c]=v\nok[cs]=v\n", .{ .locale_keys = true, .strict = false });
    defer lax.deinit();
    try testing.expectEqualSlices(usize, &.{ 2, 3 }, lax.skipped);
    try testing.expectEqualStrings("v", lax.get("g", "ok[cs]").?);
}

test "inline comments: a tab also precedes one, and the value is trimmed even without trim_values" {
    var doc = try parse(testing.allocator, "[a]\nk = v\t; note\nj = w  # note\n", .{ .inline_comments = true, .trim_values = false });
    defer doc.deinit();
    try testing.expectEqualStrings("v", doc.get("a", "k").?);
    try testing.expectEqualStrings("w", doc.get("a", "j").?);
    // no blank before the character: it is part of the value
    var doc2 = try parse(testing.allocator, "[a]\nk = a;b#c\n", .{ .inline_comments = true });
    defer doc2.deinit();
    try testing.expectEqualStrings("a;b#c", doc2.get("a", "k").?);
}

test "unquote: every escape, a trailing backslash, a lone quote" {
    const cases = [_][2][]const u8{
        .{ "\"a\\tb\\rc\"", "a\tb\rc" },
        .{ "\"a\\", "\"a\\" }, // not closed: as is
        .{ "\"ab\\\"", "ab\\" }, // a lone backslash before the closing quote is kept
        .{ "'", "'" },
        .{ "''", "" },
        .{ "\"\"", "" },
        .{ "'\"x\"'", "\"x\"" },
        .{ "\"'x'\"", "'x'" },
        .{ "", "" },
    };
    for (cases) |c| {
        const got = try unquote(testing.allocator, c[0]);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(c[1], got);
    }
}

test "unescapeDesktop: every escape of the specification, and the first bad one" {
    const got = try unescapeDesktop(testing.allocator, "a\\sb\\nc\\td\\re\\\\f");
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("a b\nc\td\re\\f", got);
    try testing.expectError(error.InvalidEscape, unescapeDesktop(testing.allocator, "\\;"));
    const plain = try unescapeDesktop(testing.allocator, "no escapes");
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("no escapes", plain);
}

test "getBool: every word of both lists, any case, and what is neither" {
    for ([_][]const u8{ "1", "yes", "true", "on", "YES", "True", "ON" }) |v| {
        var buf: [32]u8 = undefined;
        var doc = try parse(testing.allocator, try std.fmt.bufPrint(&buf, "[a]\nk={s}\n", .{v}), .{});
        defer doc.deinit();
        try testing.expectEqual(@as(?bool, true), try doc.getBool("a", "k"));
    }
    for ([_][]const u8{ "0", "no", "false", "off", "NO", "False", "OFF" }) |v| {
        var buf: [32]u8 = undefined;
        var doc = try parse(testing.allocator, try std.fmt.bufPrint(&buf, "[a]\nk={s}\n", .{v}), .{});
        defer doc.deinit();
        try testing.expectEqual(@as(?bool, false), try doc.getBool("a", "k"));
    }
    for ([_][]const u8{ "2", "", "y", "yess", "tru", "t", "of" }) |v| {
        var buf: [32]u8 = undefined;
        var doc = try parse(testing.allocator, try std.fmt.bufPrint(&buf, "[a]\nk={s}\n", .{v}), .{});
        defer doc.deinit();
        try testing.expectError(error.NotABool, doc.getBool("a", "k"));
    }
}

test "case_insensitive_keys: lookups fold case, the stored key keeps it; off by default" {
    var doc = try parse(testing.allocator, "[a]\nKey=1\nkey=2\nother=3\n", .{ .case_insensitive_keys = true });
    defer doc.deinit();
    try testing.expectEqualStrings("2", doc.get("a", "KEY").?);
    try testing.expectEqualStrings("3", doc.get("a", "OTHER").?);
    try testing.expectEqualStrings("Key", doc.sections[0].entries[0].key);
    // section names are a separate switch
    try testing.expectEqual(@as(?[]const u8, null), doc.get("A", "key"));
    var strict_case = try parse(testing.allocator, "[a]\nKey=1\n", .{});
    defer strict_case.deinit();
    try testing.expectEqual(@as(?[]const u8, null), strict_case.get("a", "key"));
    try testing.expectEqualStrings("1", strict_case.get("a", "Key").?);
}

fn parseThenFree(gpa: Allocator, text: []const u8, opts: Options) !void {
    var doc = try parse(gpa, text, opts);
    doc.deinit();
}

test "every allocation of a parse can fail without a leak" {
    const body = "[a]\nk = first\n  second\n  third\nj=v\n[b]\nx=y\n[a]\nz=1\n";
    try testing.checkAllAllocationFailures(testing.allocator, parseThenFree, .{ "top=1\n" ++ body, Options{ .continuation_lines = true } });
    try testing.checkAllAllocationFailures(testing.allocator, parseThenFree, .{ body, Options.python });
    try testing.checkAllAllocationFailures(testing.allocator, parseThenFree, .{ "junk\n" ++ body, Options{ .strict = false, .continuation_lines = true } });
}

// ── fuzz: parse never panics, lenient never fails, strict agrees with it ────

const seed = @import("testkit").fuzz.seed;

const parse_seeds = [_][]const u8{
    seed("[a]\nk=v\n"),
    seed("top=1\n[s]\n  k = v  \n; c\n# c\n"),
    seed("[a]\nk = first\n  second\n\n  third\n"), // continuation, then a blank ends it
    seed("[a] x\n[a]b]\n[]\n[a\n=v\nnovalue\n"), // every not-a-header and bad-entry shape
    seed("\xEF\xBB\xBF[a]\r\nk=\"q\\\" v\"\r\n"),
    seed("[Desktop Entry]\nName[cs]=A\\sB\n"),
    seed("[a]\nk=v ; c # d\n"),
    seed("\x00\xff[\n]\n=\n"),
    seed(""),
};

test "fuzz: parse never panics; a lenient parse never fails; strict agrees with lenient" {
    try testing.fuzz({}, fuzzParse, .{ .corpus = &parse_seeds });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var src: fz.ScriptSource = .{ .cur = .{ .bytes = buf[0..len] } };
    try fz.parseHarness(fz.ScriptSource, &src, testing.allocator);
}

const fz = @import("fuzz_test.zig");
fn checkAllPresets(text: []const u8) !usize {
    return fz.checkAllPresets(testing.allocator, text);
}

test "corpus: every seed reaches parse, and how many strict parses succeed is pinned" {
    var nonempty: usize = 0;
    var strict_ok: usize = 0;
    for (parse_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        strict_ok += try checkAllPresets(buf[0..len]);
    }
    try testing.expectEqual(parse_seeds.len - 1, nonempty);
    // Of 9 seeds x 4 presets: the seeds that are valid INI under some preset
    // parse strictly there, the rest reach the error paths. Measured.
    try testing.expectEqual(@as(usize, 22), strict_ok);
}

test "random INI-shaped text: the fuzz invariants over 3000 fixed-seed inputs" {
    // The deterministic half of the fuzz target: lines drawn from the shapes
    // the grammar distinguishes, so every branch is reached in the ordinary
    // test lane, not only under `--fuzz`.
    const shapes = [_][]const u8{
        "[a]",         "[b]",     "[ a ]",   "[a] x",      "[a]b]",      "[]",  "[a",   "  [b]",
        "k=v",         "k = v  ", "K=V",     "k=",         "=v",         "k",   "k: v", "k = a=b",
        "\tk\t=\tv\t", "k=v ; c", "k=v # c", "x y = z",    "Name[cs]=A", "# c", "; c",  "  # c",
        "",            "   ",     "  more",  "    deeper", "\tt",
    };
    var prng = std.Random.DefaultPrng.init(0x1111);
    const r = prng.random();
    var buf: [512]u8 = undefined;
    for (0..3000) |_| {
        var w: std.Io.Writer = .fixed(&buf);
        const n = r.uintLessThan(usize, 12);
        for (0..n) |_| {
            try w.writeAll(shapes[r.uintLessThan(usize, shapes.len)]);
            try w.writeAll(if (r.uintLessThan(u8, 8) == 0) "\r\n" else "\n");
        }
        _ = try checkAllPresets(w.buffered());
    }
}
