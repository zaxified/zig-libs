// SPDX-License-Identifier: MIT

//! ini — an INI reader and writer: `[section]` headers, `key = value` entries,
//! comment lines, in the dialects that matter in practice.
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
//! Beyond `parse` (all opt-in; see SPEC.md):
//!
//!   * `Scanner`, `StreamScanner` -- pull readers that allocate nothing.
//!   * `Editor` -- edits a file and writes it back: every line it was not asked
//!     to touch comes out byte for byte, comments and layout included.
//!   * `Document.write` -- serialises a document (order kept, comments gone).
//!   * `Document.getInt`, `getFloat`, `getList`, `getLocale`, `getInherited`,
//!     `mapSection`; `Options.default_section` (`[DEFAULT]`); and
//!     `Document.interpolated` (`%(name)s`, `${section:key}`), all layers over
//!     the raw values.
//!
//! Provenance: clean-room. The grammar is this module's; Python's
//! `configparser` (PSF licence) and GLib's `GKeyFile` (LGPL) were only RUN,
//! as black-box oracles, to produce the goldens in `src/testdata/` -- neither
//! implementation's source was read (`tools/README.md`). go-ini (Apache-2.0)
//! was read for the survey and the benchmark; none of its code is here.

const std = @import("std");
const Allocator = std.mem.Allocator;
const names = @import("names.zig");
const scan = @import("scan.zig");
const value_mod = @import("value.zig");
const write_mod = @import("write.zig");

pub const Scanner = scan.Scanner;
pub const StreamScanner = scan.StreamScanner;
pub const Event = scan.Event;
pub const EntryEvent = scan.EntryEvent;
pub const Editor = @import("editor.zig").Editor;
pub const EditError = @import("editor.zig").EditError;
pub const WriteOptions = write_mod.WriteOptions;
pub const WriteError = write_mod.WriteError;

pub const intValue = value_mod.intValue;
pub const floatValue = value_mod.floatValue;
pub const boolValue = value_mod.boolValue;
pub const IntError = value_mod.IntError;
pub const FloatError = value_mod.FloatError;
pub const List = value_mod.List;
pub const ListOptions = value_mod.ListOptions;
pub const ListError = value_mod.ListError;
pub const parseList = value_mod.parseList;
pub const InterpolateOptions = value_mod.InterpolateOptions;
pub const InterpolateError = value_mod.InterpolateError;
pub const MapError = value_mod.MapError;
pub const quote = value_mod.quote;
pub const escapeDesktop = value_mod.escapeDesktop;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "INI reader and layout-preserving writer — sections, key = value, comments, typed getters, [DEFAULT] and interpolation; Python configparser and Desktop Entry (GKeyFile) dialects.",
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
    /// Also end a line at a comment character that follows whitespace
    /// (`k = v ; note` -> `v`). Off by default: mc skins use `;` inside
    /// values, and neither reference implementation does this by default.
    /// The comment is cut before anything else looks at the line, so it holds
    /// for every kind of line (`x ; y = z` has no separator; a continuation
    /// line is cut too), as with Python's `inline_comment_prefixes`. Quotes
    /// are not looked at.
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
    /// With `continuation_lines`: a blank or comment line does NOT end a value;
    /// a later deeper-indented line continues it, each blank line kept as an
    /// empty line of the value (a comment line vanishes), trailing ones dropped.
    /// `configparser.ConfigParser`'s default (`empty_lines_in_values=True`).
    empty_lines_in_values: bool = false,
    /// A key with no separator is an entry with no value (`Entry.has_value`
    /// false, `get` answers ""): `my.cnf`, git-config booleans,
    /// `allow_no_value=True`. Such a key cannot be continued.
    no_value_keys: bool = false,
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
    /// A section of this name is `configparser`'s `[DEFAULT]`: `get` falls back
    /// to its keys from any existing section, and `merged` lists them. Raw
    /// access (`sections`, `entries`) is unaffected, and `sectionNames` leaves
    /// it out. Null: no such section.
    default_section: ?[]const u8 = null,
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

    /// `configparser.ConfigParser()`'s defaults with `optionxform=str`
    /// (keys keep their case; add `case_insensitive_keys` for the lowercasing
    /// behaviour): `.python` plus `[DEFAULT]` and blank lines inside values.
    /// Its `strict=True` refusal of duplicates is `Document.firstDuplicate`,
    /// its interpolation `Document.interpolated`.
    pub const configparser: Options = .{
        .comment_chars = "#;",
        .separators = "=:",
        .continuation_lines = true,
        .empty_lines_in_values = true,
        .global_entries = false,
        .header_trailing_text = true,
        .default_section = "DEFAULT",
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
    /// False for a bare key (`Options.no_value_keys`); `value` is then "".
    has_value: bool = true,
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
    /// Group id of `Options.default_section`, or `none_section`.
    default_group: u32,
    /// Lookup index built by `parse` (in `arena`). A "group" is all sections
    /// of one name; its id is the index of its first section. `sec_next[i]` is
    /// the next section of i's group (`none_section` at the end); `sec_set`
    /// finds a group by name; `key_set` finds the last entry of a key in a group.
    index_seed: u64,
    sec_next: []const u32,
    sec_set: SecSet,
    key_set: KeySet,

    pub fn deinit(self: *Document) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// The value of `key` in `section`: the last one in the file, across
    /// every section of that name. `section` "" is the entries before the
    /// first header. O(1) per call: `parse` indexes sections and keys once
    /// (a lookup used to scan the whole file, so a hostile skin of 1 MiB made
    /// each of a consumer's thousands of lookups cost milliseconds -- sweep IN-1).
    pub fn get(self: *const Document, section: []const u8, key: []const u8) ?[]const u8 {
        const g = self.group(section) orelse return null;
        const kc = self.keyCtx();
        if (self.key_set.getKeyAdapted(KeyQuery{ .group = g, .key = key }, kc)) |hit| return hit.entry.value;
        if (self.default_group == none_section or self.default_group == g) return null;
        const hit = self.key_set.getKeyAdapted(KeyQuery{ .group = self.default_group, .key = key }, kc) orelse return null;
        return hit.entry.value;
    }

    /// `get`, walking up a dotted section name: `a.b.c`, then `a.b`, then `a`
    /// (go-ini's parent-child sections). `delimiter` is usually `.`.
    pub fn getInherited(self: *const Document, section: []const u8, key: []const u8, delimiter: u8) ?[]const u8 {
        var s = section;
        while (true) {
            if (self.get(s, key)) |v| return v;
            s = s[0 .. std.mem.findScalarLast(u8, s, delimiter) orelse return null];
        }
    }

    /// `get`, for a Desktop Entry localized key: `key[locale]` with the most
    /// specific variant of `lang_COUNTRY.ENCODING@MODIFIER` first, ending at
    /// plain `key` (what `GKeyFile.get_locale_string` picks; golden-tested). A
    /// key and locale over 500 bytes together only get the plain key.
    pub fn getLocale(self: *const Document, section: []const u8, key: []const u8, locale: []const u8) ?[]const u8 {
        return value_mod.getLocale(self, section, key, locale);
    }

    /// `get`, read as a base-10 integer the way Python's `getint` does (see
    /// `intValue`). Null when the key is absent.
    pub fn getInt(self: *const Document, comptime T: type, section: []const u8, key: []const u8) IntError!?T {
        return try intValue(T, self.get(section, key) orelse return null);
    }

    /// `get`, read as a float the way Python's `getfloat` does (see
    /// `floatValue`). Null when the key is absent.
    pub fn getFloat(self: *const Document, comptime T: type, section: []const u8, key: []const u8) FloatError!?T {
        return try floatValue(T, self.get(section, key) orelse return null);
    }

    /// `get`, split into a list (`parseList`). Null when the key is absent;
    /// the caller calls `List.deinit`.
    pub fn getList(self: *const Document, gpa: Allocator, section: []const u8, key: []const u8, opts: ListOptions) ListError!?List {
        return try parseList(gpa, self.get(section, key) orelse return null, opts);
    }

    /// `get`, with references to other keys expanded (`%(name)s`, or
    /// `${name}` and `${section:name}`), `configparser`'s Basic and Extended
    /// interpolation. Null when the key is absent; the caller frees the result.
    pub fn interpolated(self: *const Document, gpa: Allocator, section: []const u8, key: []const u8, opts: InterpolateOptions) InterpolateError!?[]u8 {
        return value_mod.interpolated(self, gpa, section, key, opts);
    }

    /// A `T` whose fields are filled from `section`, field name = key (go-ini's
    /// `MapTo`). Every field of `T` needs a default, which stays when the key
    /// is absent. Field types: `[]const u8` (borrowed from the document), an
    /// integer, a float, `bool`, an enum (by tag name), or an optional of one.
    pub fn mapSection(self: *const Document, comptime T: type, section: []const u8) MapError!T {
        return value_mod.mapSection(self, T, section);
    }

    /// The text of this document (see `WriteOptions`). `gpa` is for one scratch
    /// line. Comments and layout are not in a `Document`: `Editor` keeps them.
    pub fn write(self: *const Document, gpa: Allocator, w: *std.Io.Writer, opts: WriteOptions) WriteError!void {
        return write_mod.writeDocument(self, gpa, w, opts);
    }

    /// The first thing a `configparser.ConfigParser(strict=True)` would refuse:
    /// a section or a key within a section named a second time. `parse` itself
    /// always accepts them (later wins); this is the check on top. O(entries).
    pub fn firstDuplicate(self: *const Document) ?Duplicate {
        const kc = self.keyCtx();
        for (self.sections, 0..) |s, i| {
            const g = self.group(s.name).?;
            // `[DEFAULT]` may be repeated, in configparser too.
            if (g != i and g != self.default_group) return .{ .kind = .section, .name = s.name, .line = s.line };
            for (s.entries) |*e| {
                const hit = self.key_set.getKeyAdapted(KeyQuery{ .group = g, .key = e.key }, kc).?;
                if (hit.first != e) return .{ .kind = .key, .name = e.key, .line = e.line };
            }
        }
        return null;
    }

    pub const Duplicate = struct { kind: enum { section, key }, name: []const u8, line: usize };

    /// The distinct section names in first-appearance order, without the
    /// `Options.default_section`: `configparser`'s `sections()`.
    pub fn sectionNames(self: *const Document) SectionNameIterator {
        return .{ .doc = self };
    }

    pub const SectionNameIterator = struct {
        doc: *const Document,
        i: usize = 0,

        pub fn next(it: *SectionNameIterator) ?[]const u8 {
            while (it.i < it.doc.sections.len) {
                const i = it.i;
                it.i += 1;
                if (it.doc.group(it.doc.sections[i].name).? == i and i != it.doc.default_group) return it.doc.sections[i].name;
            }
            return null;
        }
    };

    /// What `section` means under the lookup rule: each key once, in
    /// first-appearance order, with the value `get` answers, then the keys only
    /// `Options.default_section` has. `configparser`'s `options()` + `get()`.
    pub fn merged(self: *const Document, section: []const u8) MergedIterator {
        const g = self.group(section) orelse return .{ .doc = self, .g = none_section, .si = none_section };
        return .{ .doc = self, .g = g, .si = g };
    }

    pub const MergedIterator = struct {
        doc: *const Document,
        g: u32,
        si: u32,
        ei: usize = 0,
        /// Reading the default section's keys now.
        in_default: bool = false,

        pub fn next(it: *MergedIterator) ?Entry {
            const kc = it.doc.keyCtx();
            while (it.si != none_section) {
                const s = it.doc.sections[it.si];
                while (it.ei < s.entries.len) {
                    const e = &s.entries[it.ei];
                    it.ei += 1;
                    const scope = if (it.in_default) it.doc.default_group else it.g;
                    const hit = it.doc.key_set.getKeyAdapted(KeyQuery{ .group = scope, .key = e.key }, kc).?;
                    if (hit.first != e) continue;
                    if (it.in_default and it.doc.key_set.getKeyAdapted(KeyQuery{ .group = it.g, .key = e.key }, kc) != null) continue;
                    var out = hit.entry.*;
                    out.key = e.key;
                    return out;
                }
                it.ei = 0;
                it.si = it.doc.sec_next[it.si];
                if (it.si == none_section and !it.in_default and it.doc.default_group != none_section and it.doc.default_group != it.g) {
                    it.in_default = true;
                    it.si = it.doc.default_group;
                }
            }
            return null;
        }
    };

    /// `get`, read as a boolean the way Python's `getboolean` does:
    /// `1 yes true on` / `0 no false off`, any ASCII case. Null when the key
    /// is absent; `error.NotABool` for any other value.
    pub fn getBool(self: *const Document, section: []const u8, key: []const u8) error{NotABool}!?bool {
        const v = self.get(section, key) orelse return null;
        return try boolValue(v);
    }

    /// Whether any section is named `section`.
    pub fn hasSection(self: *const Document, section: []const u8) bool {
        return self.group(section) != null;
    }

    /// Every entry of every section named `section`, in file order,
    /// repeated keys included (a list-valued key, or to see what `get`
    /// overrode).
    pub fn entries(self: *const Document, section: []const u8) EntryIterator {
        return .{ .doc = self, .si = self.group(section) orelse none_section };
    }

    pub const EntryIterator = struct {
        doc: *const Document,
        /// Index into `doc.sections` of the section being read (`none_section`: done).
        si: u32,
        ei: usize = 0,

        pub fn next(it: *EntryIterator) ?Entry {
            while (it.si != none_section) {
                const s = it.doc.sections[it.si];
                if (it.ei < s.entries.len) {
                    it.ei += 1;
                    return s.entries[it.ei - 1];
                }
                it.si = it.doc.sec_next[it.si];
                it.ei = 0;
            }
            return null;
        }
    };

    /// Group id (index of the first section) of `section`, if any.
    fn group(self: *const Document, section: []const u8) ?u32 {
        return self.sec_set.getKeyAdapted(section, self.secCtx());
    }

    fn secCtx(self: *const Document) SecCtx {
        return .{ .sections = self.sections, .fold = self.case_insensitive_sections, .seed = self.index_seed };
    }

    fn keyCtx(self: *const Document) KeyCtx {
        return .{ .fold = self.case_insensitive_keys, .seed = self.index_seed };
    }
};

const none_section: u32 = std.math.maxInt(u32);

const nameHash = names.hash;
const nameEql = names.eql;

/// Context of `SecSet`: stored keys are section indices (the first section of
/// a group), lookups are by name.
const SecCtx = struct {
    sections: []const Section,
    fold: bool,
    seed: u64,

    fn nameOf(self: SecCtx, k: anytype) []const u8 {
        return if (@TypeOf(k) == u32) self.sections[k].name else k;
    }
    pub fn hash(self: SecCtx, k: anytype) u64 {
        return nameHash(self.seed, self.fold, self.nameOf(k));
    }
    pub fn eql(self: SecCtx, a: anytype, b: anytype) bool {
        return nameEql(self.fold, self.nameOf(a), self.nameOf(b));
    }
};

const SecSet = std.HashMapUnmanaged(u32, void, SecCtx, 80);

/// A stored key of `KeySet`: the last entry of a key inside a group, and the
/// first (`merged` and `firstDuplicate` need it).
const KeyRef = struct { group: u32, entry: *const Entry, first: *const Entry };
const KeyQuery = struct { group: u32, key: []const u8 };

const KeyCtx = struct {
    fold: bool,
    seed: u64,

    fn parts(k: anytype) struct { u32, []const u8 } {
        return if (@TypeOf(k) == KeyRef) .{ k.group, k.entry.key } else .{ k.group, k.key };
    }
    pub fn hash(self: KeyCtx, k: anytype) u64 {
        const g, const key = parts(k);
        return nameHash(self.seed +% @as(u64, g) *% 0x9E3779B97F4A7C15, self.fold, key);
    }
    pub fn eql(self: KeyCtx, a: anytype, b: anytype) bool {
        const ga, const ka = parts(a);
        const gb, const kb = parts(b);
        return ga == gb and nameEql(self.fold, ka, kb);
    }
};

const KeySet = std.HashMapUnmanaged(KeyRef, void, KeyCtx, 80);

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
    // The entry being continued and its value as it grows: one buffer per
    // entry, so a value continued over N lines costs O(its length), not
    // O(N * length). `cont_entry` points into the last section's entry list,
    // which only grows after it has been replaced.
    var cont_entry: ?*Entry = null;
    var cont_value: std.ArrayList(u8) = .empty;

    var scanner = Scanner.init(text, opts);
    while (scanner.next()) |ev| switch (ev) {
        .blank, .comment => {},
        .section => |h| try sections.append(a, .{ .name = try a.dupe(u8, h.name), .line = h.line }),
        .entry => |e| {
            if (sections.items.len == 0) try sections.append(a, .{ .name = "", .line = 0 });
            const cur = &sections.items[sections.items.len - 1];
            try cur.entries.append(a, .{ .key = try a.dupe(u8, e.key), .value = try a.dupe(u8, e.value), .line = e.line, .has_value = e.has_value });
            cont_entry = &cur.entries.items[cur.entries.items.len - 1];
            cont_value = .empty;
        },
        .continuation => |c| {
            // The classifier only continues an accepted entry.
            const entry = cont_entry.?;
            if (cont_value.items.len == 0) try cont_value.appendSlice(a, entry.value);
            try cont_value.appendNTimes(a, '\n', c.blanks_before + 1);
            try cont_value.appendSlice(a, c.text);
            entry.value = cont_value.items;
        },
        .invalid => |bad| {
            if (opts.strict) {
                info.line = bad.line;
                return bad.err;
            }
            try skipped.append(a, bad.line);
        },
    };

    const out = try a.alloc(Section, sections.items.len);
    for (sections.items, out) |s, *o| o.* = .{ .name = s.name, .line = s.line, .entries = s.entries.items };

    // The lookup index (see `Document.sec_next`), built once, O(sections +
    // entries) time and ~30 bytes per section/key of memory: pre-sized from
    // the counts, no per-group containers.
    var n_entries: usize = 0;
    for (out) |sc| n_entries += sc.entries.len;
    if (out.len >= none_section or n_entries >= none_section) return error.OutOfMemory;
    // Per-document hash seed: addresses (ASLR) and the text length, so the
    // table layout cannot be predicted from the file alone (sweep RV-IN-2).
    const info_addr: usize = @intFromPtr(info);
    const hseed = std.hash.Wyhash.hash(@intFromPtr(text.ptr) ^ (text.len *% 0x9E3779B97F4A7C15), std.mem.asBytes(&info_addr));
    const sec_ctx: SecCtx = .{ .sections = out, .fold = opts.case_insensitive_sections, .seed = hseed };
    const key_ctx: KeyCtx = .{ .fold = opts.case_insensitive_keys, .seed = hseed };
    const sec_next = try a.alloc(u32, out.len);
    const tail = try gpa.alloc(u32, out.len); // scratch: last section of a group, by group id
    defer gpa.free(tail);
    var sec_set: SecSet = .empty;
    try sec_set.ensureTotalCapacityContext(a, @intCast(out.len), sec_ctx);
    var key_set: KeySet = .empty;
    try key_set.ensureTotalCapacityContext(a, @intCast(n_entries), key_ctx);
    for (out, 0..) |sc, i| {
        const si: u32 = @intCast(i);
        const gop = try sec_set.getOrPutContextAdapted(a, sc.name, sec_ctx, sec_ctx);
        if (!gop.found_existing) gop.key_ptr.* = si;
        const group = gop.key_ptr.*;
        if (gop.found_existing) sec_next[tail[group]] = si;
        tail[group] = si;
        sec_next[si] = none_section;
        for (sc.entries) |*e| {
            const q: KeyQuery = .{ .group = group, .key = e.key };
            const kg = try key_set.getOrPutContextAdapted(a, q, key_ctx, key_ctx);
            // A later entry of the same key wins; the first stays known.
            kg.key_ptr.* = .{ .group = group, .entry = e, .first = if (kg.found_existing) kg.key_ptr.first else e };
        }
    }
    var default_group = none_section;
    if (opts.default_section) |ds| default_group = sec_set.getKeyAdapted(ds, sec_ctx) orelse none_section;
    return .{
        .arena = arena_state,
        .sections = out,
        .skipped = skipped.items,
        .case_insensitive_sections = opts.case_insensitive_sections,
        .case_insensitive_keys = opts.case_insensitive_keys,
        .default_group = default_group,
        .index_seed = hseed,
        .sec_next = sec_next,
        .sec_set = sec_set,
        .key_set = key_set,
    };
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
    _ = @import("sweep_test.zig");
    _ = @import("api_test.zig");
    _ = @import("edit_fail_test.zig");
    _ = @import("editor.zig");
    _ = @import("oracle_ext_test.zig");
    _ = @import("value.zig");
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
        const t = try std.mem.print(&line_buf, "[g]\n{s}=v\n", .{k});
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
    try testing.expectEqualStrings("", doc.get("a", "w").?); // a blank precedes it: a comment, as in configparser
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
        const t = try std.mem.print(&line_buf, "[g]\n{s}=v\n", .{k});
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
        var doc = try parse(testing.allocator, try std.mem.print(&buf, "[a]\nk={s}\n", .{v}), .{});
        defer doc.deinit();
        try testing.expectEqual(@as(?bool, true), try doc.getBool("a", "k"));
    }
    for ([_][]const u8{ "0", "no", "false", "off", "NO", "False", "OFF" }) |v| {
        var buf: [32]u8 = undefined;
        var doc = try parse(testing.allocator, try std.mem.print(&buf, "[a]\nk={s}\n", .{v}), .{});
        defer doc.deinit();
        try testing.expectEqual(@as(?bool, false), try doc.getBool("a", "k"));
    }
    for ([_][]const u8{ "2", "", "y", "yess", "tru", "t", "of" }) |v| {
        var buf: [32]u8 = undefined;
        var doc = try parse(testing.allocator, try std.mem.print(&buf, "[a]\nk={s}\n", .{v}), .{});
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

/// Every allocation of one parse failed in turn: each outcome is a Document
/// or `error.OutOfMemory`, and the testing allocator reports any leak. Not
/// `checkAllAllocationFailures`: over an arena it reports
/// NondeterministicMemoryUsage (the arena's growth depends on its history).
fn failEveryAllocation(text: []const u8, opts: Options) !void {
    var counter = testing.FailingAllocator.init(testing.allocator, .{});
    try parseThenFree(counter.allocator(), text, opts);
    var i: usize = 0;
    while (i <= counter.alloc_index) : (i += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        parseThenFree(fa.allocator(), text, opts) catch |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

test "every allocation of a parse can fail without a leak" {
    const body = "[a]\nk = first\n  second\n  third\nj=v\n[b]\nx=y\n[a]\nz=1\n";
    try failEveryAllocation("top=1\n" ++ body, Options{ .continuation_lines = true });
    try failEveryAllocation(body, Options.python);
    try failEveryAllocation("junk\n" ++ body, Options{ .strict = false, .continuation_lines = true });
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
