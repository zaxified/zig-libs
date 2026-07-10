// SPDX-License-Identifier: MIT

//! uci — parser + serializer + typed model for the OpenWRT UCI
//! (Unified Configuration Interface) file format.
//!
//! A UCI config file is a *package* (implicit — the file itself, optionally
//! restated by a `package` line) containing sections:
//!
//! ```
//! config <type> ['<name>']       # named or anonymous section
//!     option <key> '<value>'     # single value
//!     list   <key> '<value>'     # repeated -> list
//! ```
//!
//! `parse` builds a typed `Package` model (arena-backed — one `deinit` frees
//! everything); `serialize` writes it back as canonical UCI text. Round-trips
//! are stable: `parse(serialize(m))` equals `m`, and the second serialization
//! is byte-identical to the first.
//!
//! Quoting follows the documented format: single quotes take no escapes;
//! double quotes take `\"`, `\'`, `\\`, `\n`, `\t`, `\r` (a backslash before
//! any other character yields that character); bare words end at whitespace.
//! Adjacent segments of one token concatenate (`'a'"b"c` -> `abc`), quotes
//! may not span lines. `#` starts a comment at the start of a token; inside
//! a token or inside quotes it is literal.
//!
//! Malformed input yields a typed `ParseError` (never a panic); pass a
//! `Diagnostics` to `parseDiag` to learn the 1-based line number.
//!
//! Semantics on repeated keys within one section: a repeated `option` under
//! the same key overwrites (last wins, matching UCI CLI set semantics);
//! `list` entries under one key accumulate in order; mixing `option` and
//! `list` under the same key is rejected as `error.MixedOptionList`.
//!
//! Provenance: clean-room from the documented OpenWRT UCI file format;
//! libuci (LGPL-2.1) referenced for the format only, no source consulted
//! or copied.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "OpenWRT UCI file format / libuci",
    .deps = .{}, // std only
};

// ── limits ──────────────────────────────────────────────────────────────────

/// Largest accepted input, in bytes. Larger inputs fail with
/// `error.InputTooLarge` (diagnostic line 0).
pub const max_input_len: usize = 1 << 24; // 16 MiB

/// Longest accepted single line, in bytes (excluding the newline).
pub const max_line_len: usize = 1 << 14; // 16 KiB

// ── errors / diagnostics ────────────────────────────────────────────────────

pub const ParseError = error{
    /// Input exceeds `max_input_len`.
    InputTooLarge,
    /// A line exceeds `max_line_len`.
    LineTooLong,
    /// A single or double quote was not closed before end of line.
    UnterminatedQuote,
    /// Line starts with a token other than `config`/`option`/`list`/`package`.
    BadKeyword,
    /// A keyword is missing a required argument (e.g. bare `config`,
    /// `option key` with no value).
    MissingArgument,
    /// Extra tokens after a complete statement.
    TooManyArguments,
    /// `option`/`list` before any `config` section.
    OptionOutsideSection,
    /// `option` and `list` mixed under the same key in one section.
    MixedOptionList,
    OutOfMemory,
};

pub const SerializeError = error{
    /// A value contains a control character with no UCI escape
    /// (anything below 0x20 other than `\n`, `\t`, `\r`).
    UnserializableValue,
    OutOfMemory,
};

/// Filled in by `parseDiag` on failure. `line` is 1-based; 0 means the
/// failure was not tied to a line (`error.InputTooLarge`).
pub const Diagnostics = struct {
    line: usize = 0,
};

// ── model ───────────────────────────────────────────────────────────────────

pub const Option = struct {
    key: []const u8,
    kind: Kind,
    /// `.single` -> exactly one entry; `.list` -> one entry per `list` line.
    values: []const []const u8,

    pub const Kind = enum { single, list };

    pub fn eql(a: *const Option, b: *const Option) bool {
        if (!std.mem.eql(u8, a.key, b.key)) return false;
        if (a.kind != b.kind) return false;
        if (a.values.len != b.values.len) return false;
        for (a.values, b.values) |av, bv| {
            if (!std.mem.eql(u8, av, bv)) return false;
        }
        return true;
    }
};

pub const Section = struct {
    type: []const u8,
    /// Null for anonymous sections (`config rule` with no name).
    name: ?[]const u8,
    anonymous: bool,
    options: []const Option,

    /// Find an option (single or list) by key.
    pub fn option(self: *const Section, key: []const u8) ?*const Option {
        for (self.options) |*o| {
            if (std.mem.eql(u8, o.key, key)) return o;
        }
        return null;
    }

    /// First value under `key` (works for both single options and lists).
    pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
        const o = self.option(key) orelse return null;
        if (o.values.len == 0) return null;
        return o.values[0];
    }

    /// All values under `key`; empty slice if the key is absent. A single
    /// option yields a one-element slice.
    pub fn getList(self: *const Section, key: []const u8) []const []const u8 {
        const o = self.option(key) orelse return &.{};
        return o.values;
    }

    pub fn eql(a: *const Section, b: *const Section) bool {
        if (!std.mem.eql(u8, a.type, b.type)) return false;
        if (!optStrEql(a.name, b.name)) return false;
        if (a.anonymous != b.anonymous) return false;
        if (a.options.len != b.options.len) return false;
        for (a.options, b.options) |*ao, *bo| {
            if (!ao.eql(bo)) return false;
        }
        return true;
    }
};

pub const Package = struct {
    /// From an optional `package <name>` line; null when absent (the usual
    /// case — the package is implicitly the file).
    name: ?[]const u8 = null,
    sections: []const Section = &.{},
    arena_state: std.heap.ArenaAllocator.State = .{},

    /// Frees the whole model. `gpa` must be the allocator given to `parse`.
    pub fn deinit(self: *Package, gpa: Allocator) void {
        self.arena_state.promote(gpa).deinit();
        self.* = undefined;
    }

    /// Find a *named* section by type + name. Anonymous sections are never
    /// matched; use `iterate` for those.
    pub fn section(self: *const Package, section_type: []const u8, name: []const u8) ?*const Section {
        for (self.sections) |*s| {
            const n = s.name orelse continue;
            if (std.mem.eql(u8, s.type, section_type) and std.mem.eql(u8, n, name)) return s;
        }
        return null;
    }

    /// Iterate all sections of a given type, in file order.
    pub fn iterate(self: *const Package, section_type: []const u8) TypeIterator {
        return .{ .remaining = self.sections, .section_type = section_type };
    }

    pub fn eql(a: *const Package, b: *const Package) bool {
        if (!optStrEql(a.name, b.name)) return false;
        if (a.sections.len != b.sections.len) return false;
        for (a.sections, b.sections) |*as, *bs| {
            if (!as.eql(bs)) return false;
        }
        return true;
    }
};

pub const TypeIterator = struct {
    remaining: []const Section,
    section_type: []const u8,

    pub fn next(it: *TypeIterator) ?*const Section {
        while (it.remaining.len > 0) {
            const s = &it.remaining[0];
            it.remaining = it.remaining[1..];
            if (std.mem.eql(u8, s.type, it.section_type)) return s;
        }
        return null;
    }
};

fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    const av = a orelse return b == null;
    const bv = b orelse return false;
    return std.mem.eql(u8, av, bv);
}

// ── parser ──────────────────────────────────────────────────────────────────

/// Parse UCI text into a `Package`. All model memory comes from an internal
/// arena seeded from `gpa`; free it with `Package.deinit(gpa)`.
pub fn parse(gpa: Allocator, bytes: []const u8) ParseError!Package {
    return parseDiag(gpa, bytes, null);
}

/// Like `parse`, but on error fills `diag.line` with the offending 1-based
/// line number (0 when the error is not line-specific).
pub fn parseDiag(gpa: Allocator, bytes: []const u8, diag: ?*Diagnostics) ParseError!Package {
    if (bytes.len > max_input_len) {
        if (diag) |d| d.line = 0;
        return error.InputTooLarge;
    }

    var arena_impl = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_impl.deinit();

    var p: Parser = .{ .arena = arena_impl.allocator() };
    p.run(bytes) catch |err| {
        if (diag) |d| d.line = p.line_no;
        return err;
    };

    return .{
        .name = p.pkg_name,
        .sections = p.finished,
        .arena_state = arena_impl.state,
    };
}

const OptBuild = struct {
    key: []const u8,
    kind: Option.Kind,
    values: std.ArrayList([]const u8),
};

const SecBuild = struct {
    section_type: []const u8,
    name: ?[]const u8,
    options: std.ArrayList(OptBuild),
};

const Parser = struct {
    arena: Allocator,
    line_no: usize = 0,
    pkg_name: ?[]const u8 = null,
    sections: std.ArrayList(Section) = .empty,
    current: ?SecBuild = null,
    finished: []Section = &.{},

    fn run(p: *Parser, bytes: []const u8) ParseError!void {
        var it = std.mem.splitScalar(u8, bytes, '\n');
        while (it.next()) |raw_line| {
            p.line_no += 1;
            var line = raw_line;
            if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            if (line.len > max_line_len) return error.LineTooLong;
            try p.parseLine(line);
        }
        try p.flushSection();
        p.finished = try p.sections.toOwnedSlice(p.arena);
    }

    fn parseLine(p: *Parser, line: []const u8) ParseError!void {
        var pos: usize = 0;
        const kw = (try p.nextToken(line, &pos)) orelse return; // blank or comment line

        if (std.mem.eql(u8, kw, "config")) {
            const sec_type = (try p.nextToken(line, &pos)) orelse return error.MissingArgument;
            const name_tok = try p.nextToken(line, &pos);
            if (try p.nextToken(line, &pos) != null) return error.TooManyArguments;
            try p.flushSection();
            // An empty quoted name ('') is treated as anonymous.
            const name: ?[]const u8 = if (name_tok) |n| (if (n.len > 0) n else null) else null;
            p.current = .{ .section_type = sec_type, .name = name, .options = .empty };
        } else if (std.mem.eql(u8, kw, "option") or std.mem.eql(u8, kw, "list")) {
            if (p.current == null) return error.OptionOutsideSection;
            const key = (try p.nextToken(line, &pos)) orelse return error.MissingArgument;
            const value = (try p.nextToken(line, &pos)) orelse return error.MissingArgument;
            if (try p.nextToken(line, &pos) != null) return error.TooManyArguments;
            const kind: Option.Kind = if (kw[0] == 'o') .single else .list;
            try p.addOption(key, value, kind);
        } else if (std.mem.eql(u8, kw, "package")) {
            const name = (try p.nextToken(line, &pos)) orelse return error.MissingArgument;
            if (try p.nextToken(line, &pos) != null) return error.TooManyArguments;
            p.pkg_name = name; // last one wins
        } else {
            return error.BadKeyword;
        }
    }

    /// Read one whitespace-delimited token starting at `pos.*`, resolving
    /// quotes and escapes. Returns null at end of line or at a comment.
    fn nextToken(p: *Parser, line: []const u8, pos: *usize) ParseError!?[]const u8 {
        var i = pos.*;
        while (i < line.len and (line[i] == ' ' or line[i] == '\t')) i += 1;
        if (i >= line.len or line[i] == '#') {
            pos.* = line.len;
            return null;
        }

        var buf: std.ArrayList(u8) = .empty;
        while (i < line.len) {
            const c = line[i];
            if (c == ' ' or c == '\t') break;
            switch (c) {
                '\'' => {
                    // Single quotes: no escapes, everything literal.
                    i += 1;
                    const end = std.mem.indexOfScalarPos(u8, line, i, '\'') orelse
                        return error.UnterminatedQuote;
                    try buf.appendSlice(p.arena, line[i..end]);
                    i = end + 1;
                },
                '"' => {
                    i += 1;
                    var closed = false;
                    while (i < line.len) {
                        const d = line[i];
                        if (d == '"') {
                            closed = true;
                            i += 1;
                            break;
                        }
                        if (d == '\\') {
                            i += 1;
                            if (i >= line.len) return error.UnterminatedQuote;
                            try buf.append(p.arena, switch (line[i]) {
                                'n' => '\n',
                                't' => '\t',
                                'r' => '\r',
                                else => |e| e, // covers \" \' \\ and anything else
                            });
                            i += 1;
                        } else {
                            try buf.append(p.arena, d);
                            i += 1;
                        }
                    }
                    if (!closed) return error.UnterminatedQuote;
                },
                else => {
                    // Bare run: up to whitespace or a quote (concatenation).
                    // '#' inside a bare word is literal; it only starts a
                    // comment at the start of a token.
                    const start = i;
                    while (i < line.len) : (i += 1) {
                        const d = line[i];
                        if (d == ' ' or d == '\t' or d == '\'' or d == '"') break;
                    }
                    try buf.appendSlice(p.arena, line[start..i]);
                },
            }
        }
        pos.* = i;
        return try buf.toOwnedSlice(p.arena);
    }

    fn addOption(p: *Parser, key: []const u8, value: []const u8, kind: Option.Kind) ParseError!void {
        const cur = &p.current.?;
        for (cur.options.items) |*ob| {
            if (!std.mem.eql(u8, ob.key, key)) continue;
            if (ob.kind != kind) return error.MixedOptionList;
            switch (kind) {
                .single => {
                    // Repeated `option` under one key: last one wins.
                    ob.values.clearRetainingCapacity();
                    try ob.values.append(p.arena, value);
                },
                .list => try ob.values.append(p.arena, value),
            }
            return;
        }
        var values: std.ArrayList([]const u8) = .empty;
        try values.append(p.arena, value);
        try cur.options.append(p.arena, .{ .key = key, .kind = kind, .values = values });
    }

    fn flushSection(p: *Parser) ParseError!void {
        const sec = p.current orelse return;
        const options = try p.arena.alloc(Option, sec.options.items.len);
        for (sec.options.items, options) |*ob, *o| {
            o.* = .{
                .key = ob.key,
                .kind = ob.kind,
                .values = try ob.values.toOwnedSlice(p.arena),
            };
        }
        try p.sections.append(p.arena, .{
            .type = sec.section_type,
            .name = sec.name,
            .anonymous = sec.name == null,
            .options = options,
        });
        p.current = null;
    }
};

// ── serializer ──────────────────────────────────────────────────────────────

/// Serialize a `Package` to canonical UCI text (caller frees with `gpa`):
/// optional `package '<name>'` header, blank line between blocks, options
/// tab-indented, values quoted (single quotes by default, double quotes with
/// escapes when the value contains `'` or a control character).
pub fn serialize(gpa: Allocator, pkg: *const Package) SerializeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    if (pkg.name) |n| {
        try out.appendSlice(gpa, "package ");
        try writeValue(gpa, &out, n);
        try out.append(gpa, '\n');
    }
    for (pkg.sections, 0..) |*sec, i| {
        if (i != 0 or pkg.name != null) try out.append(gpa, '\n');
        try out.appendSlice(gpa, "config ");
        try writeWord(gpa, &out, sec.type);
        if (sec.name) |n| {
            try out.append(gpa, ' ');
            try writeValue(gpa, &out, n);
        }
        try out.append(gpa, '\n');
        for (sec.options) |*opt| {
            const kw: []const u8 = switch (opt.kind) {
                .single => "option",
                .list => "list",
            };
            for (opt.values) |v| {
                try out.append(gpa, '\t');
                try out.appendSlice(gpa, kw);
                try out.append(gpa, ' ');
                try writeWord(gpa, &out, opt.key);
                try out.append(gpa, ' ');
                try writeValue(gpa, &out, v);
                try out.append(gpa, '\n');
            }
        }
    }
    return out.toOwnedSlice(gpa);
}

fn isBareSafe(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

/// Section types and option keys: bare when identifier-like, quoted otherwise.
fn writeWord(gpa: Allocator, out: *std.ArrayList(u8), word: []const u8) SerializeError!void {
    if (word.len > 0) {
        for (word) |c| {
            if (!isBareSafe(c)) return writeValue(gpa, out, word);
        }
        return out.appendSlice(gpa, word);
    }
    return writeValue(gpa, out, word);
}

fn writeValue(gpa: Allocator, out: *std.ArrayList(u8), value: []const u8) SerializeError!void {
    var needs_double = false;
    for (value) |c| {
        if (c == '\'' or c < 0x20) {
            needs_double = true;
            break;
        }
    }
    if (!needs_double) {
        try out.append(gpa, '\'');
        try out.appendSlice(gpa, value);
        try out.append(gpa, '\'');
        return;
    }
    try out.append(gpa, '"');
    for (value) |c| switch (c) {
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '"' => try out.appendSlice(gpa, "\\\""),
        '\n' => try out.appendSlice(gpa, "\\n"),
        '\t' => try out.appendSlice(gpa, "\\t"),
        '\r' => try out.appendSlice(gpa, "\\r"),
        else => {
            if (c < 0x20) return error.UnserializableValue;
            try out.append(gpa, c);
        },
    };
    try out.append(gpa, '"');
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectRoundTrip(input: []const u8) !void {
    const gpa = testing.allocator;
    var p1 = try parse(gpa, input);
    defer p1.deinit(gpa);
    const s1 = try serialize(gpa, &p1);
    defer gpa.free(s1);
    var p2 = try parse(gpa, s1);
    defer p2.deinit(gpa);
    try testing.expect(p1.eql(&p2));
    const s2 = try serialize(gpa, &p2);
    defer gpa.free(s2);
    try testing.expectEqualStrings(s1, s2);
}

const golden_network =
    \\# /etc/config/network — golden KAT
    \\package 'network'
    \\
    \\config interface 'lan'
    \\    option proto 'static'
    \\    option ipaddr "192.168.1.1"   # trailing comment
    \\    option netmask 255.255.255.0
    \\    list ports 'lan1'
    \\    list ports 'lan2'
    \\    list ports "lan3"
    \\
    \\# anonymous rule
    \\config rule
    \\    option name 'Allow-DHCP # not a comment'
    \\    option enabled '1'
    \\
    \\config interface 'wan'
    \\    option proto 'dhcp'
    \\
;

test "golden: parse network config model" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, golden_network);
    defer pkg.deinit(gpa);

    try testing.expectEqualStrings("network", pkg.name.?);
    try testing.expectEqual(@as(usize, 3), pkg.sections.len);

    const lan = &pkg.sections[0];
    try testing.expectEqualStrings("interface", lan.type);
    try testing.expectEqualStrings("lan", lan.name.?);
    try testing.expect(!lan.anonymous);
    try testing.expectEqual(@as(usize, 4), lan.options.len);
    try testing.expectEqual(Option.Kind.single, lan.option("proto").?.kind);
    try testing.expectEqualStrings("static", lan.get("proto").?);
    try testing.expectEqualStrings("192.168.1.1", lan.get("ipaddr").?);
    try testing.expectEqualStrings("255.255.255.0", lan.get("netmask").?);
    const ports = lan.getList("ports");
    try testing.expectEqual(Option.Kind.list, lan.option("ports").?.kind);
    try testing.expectEqual(@as(usize, 3), ports.len);
    try testing.expectEqualStrings("lan1", ports[0]);
    try testing.expectEqualStrings("lan2", ports[1]);
    try testing.expectEqualStrings("lan3", ports[2]);

    const rule = &pkg.sections[1];
    try testing.expectEqualStrings("rule", rule.type);
    try testing.expect(rule.anonymous);
    try testing.expect(rule.name == null);
    try testing.expectEqualStrings("Allow-DHCP # not a comment", rule.get("name").?);
    try testing.expectEqualStrings("1", rule.get("enabled").?);

    const wan = &pkg.sections[2];
    try testing.expectEqualStrings("wan", wan.name.?);
    try testing.expectEqualStrings("dhcp", wan.get("proto").?);
}

test "golden: round-trip stable" {
    try expectRoundTrip(golden_network);
}

test "canonical serialization bytes" {
    const gpa = testing.allocator;
    const input = "# c\nconfig system\n option hostname  router1   # trailing\n list dns 8.8.8.8\n list dns '1.1.1.1'\n";
    var pkg = try parse(gpa, input);
    defer pkg.deinit(gpa);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "config system\n" ++
            "\toption hostname 'router1'\n" ++
            "\tlist dns '8.8.8.8'\n" ++
            "\tlist dns '1.1.1.1'\n",
        text,
    );
}

test "double-quote escapes" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption v \"a\\'b\\\"c\\\\d\\ne\\tf\\rg\"\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("a'b\"c\\d\ne\tf\rg", pkg.sections[0].get("v").?);
}

test "single quotes take no escapes" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption v 'a\\nb\"c\\\\d'\n");
    defer pkg.deinit(gpa);
    // Backslashes and double quotes are literal inside single quotes.
    try testing.expectEqualStrings("a\\nb\"c\\\\d", pkg.sections[0].get("v").?);
}

test "bare words and mid-word hash" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption a abc-def\n\toption b a#b\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("abc-def", pkg.sections[0].get("a").?);
    try testing.expectEqualStrings("a#b", pkg.sections[0].get("b").?);
    try expectRoundTrip("config t\n\toption a abc-def\n\toption b a#b\n");
}

test "token concatenation of quoted segments" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption v 'a'\"b\"c\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("abc", pkg.sections[0].get("v").?);
}

test "comments and blank lines" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa,
        \\# full-line comment
        \\
        \\   # indented comment
        \\config t 'n'
        \\    # comment between options
        \\    option a '1'   # after a value
        \\
    );
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections.len);
    try testing.expectEqual(@as(usize, 1), pkg.sections[0].options.len);
    try testing.expectEqualStrings("1", pkg.sections[0].get("a").?);
}

test "anonymous sections" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config rule\n\toption x '1'\nconfig rule\n\toption x '2'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), pkg.sections.len);
    try testing.expect(pkg.sections[0].anonymous);
    try testing.expect(pkg.sections[1].anonymous);
    // Named lookup never matches anonymous sections.
    try testing.expect(pkg.section("rule", "x") == null);
    try expectRoundTrip("config rule\n\toption x '1'\nconfig rule\n\toption x '2'\n");
}

test "empty section name is anonymous" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config rule ''\n");
    defer pkg.deinit(gpa);
    try testing.expect(pkg.sections[0].anonymous);
    try testing.expect(pkg.sections[0].name == null);
}

test "list accumulation" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\tlist l 'a'\n\toption o 'x'\n\tlist l 'b'\n\tlist l 'c'\n");
    defer pkg.deinit(gpa);
    const l = pkg.sections[0].getList("l");
    try testing.expectEqual(@as(usize, 3), l.len);
    try testing.expectEqualStrings("a", l[0]);
    try testing.expectEqualStrings("b", l[1]);
    try testing.expectEqualStrings("c", l[2]);
    // Only two Option entries: the list and the single.
    try testing.expectEqual(@as(usize, 2), pkg.sections[0].options.len);
    // get() on a list returns the first value; getList() on a single wraps it.
    try testing.expectEqualStrings("a", pkg.sections[0].get("l").?);
    try testing.expectEqual(@as(usize, 1), pkg.sections[0].getList("o").len);
}

test "duplicate option: last wins" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption k 'old'\n\toption k 'new'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections[0].options.len);
    try testing.expectEqualStrings("new", pkg.sections[0].get("k").?);
}

test "mixed option/list rejected" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.MixedOptionList,
        parseDiag(gpa, "config t\n\toption k 'v'\n\tlist k 'w'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
    try testing.expectError(
        error.MixedOptionList,
        parseDiag(gpa, "config t\n\tlist k 'v'\n\toption k 'w'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
}

test "empty file and comment-only file" {
    const gpa = testing.allocator;
    var empty = try parse(gpa, "");
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.sections.len);
    try testing.expect(empty.name == null);
    const text = try serialize(gpa, &empty);
    defer gpa.free(text);
    try testing.expectEqualStrings("", text);

    var comments = try parse(gpa, "\n\n# only comments\n   \n");
    defer comments.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), comments.sections.len);
}

test "empty quoted value" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption empty ''\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("", pkg.sections[0].get("empty").?);
    try expectRoundTrip("config t\n\toption empty ''\n");
}

test "serializer quoting choices" {
    const gpa = testing.allocator;
    var pkg = try parse(
        gpa,
        "config t\n" ++
            "\toption spaces 'hello world'\n" ++
            "\toption squote \"it's\"\n" ++
            "\toption bslash 'a\\b'\n" ++
            "\toption ctrl \"a\\nb\\tc\"\n" ++
            "\toption both \"a'\\\\b\"\n",
    );
    defer pkg.deinit(gpa);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "config t\n" ++
            "\toption spaces 'hello world'\n" ++
            "\toption squote \"it's\"\n" ++
            "\toption bslash 'a\\b'\n" ++
            "\toption ctrl \"a\\nb\\tc\"\n" ++
            "\toption both \"a'\\\\b\"\n",
        text,
    );
    try expectRoundTrip(text);
}

test "serializer rejects unescapable control chars" {
    const gpa = testing.allocator;
    const opts = [_]Option{.{ .key = "k", .kind = .single, .values = &.{"a\x01b"} }};
    const secs = [_]Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    const pkg: Package = .{ .sections = &secs };
    try testing.expectError(error.UnserializableValue, serialize(gpa, &pkg));
}

test "error: unterminated single quote with line number" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.UnterminatedQuote, parseDiag(gpa, "config foo 'bar\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(
        error.UnterminatedQuote,
        parseDiag(gpa, "# c\nconfig s\n\toption a 'b\n", &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
}

test "error: unterminated double quote with line number" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.UnterminatedQuote,
        parseDiag(gpa, "config s\n\toption a \"b\\\"\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
    // Trailing backslash inside a double quote is also unterminated.
    try testing.expectError(
        error.UnterminatedQuote,
        parseDiag(gpa, "config s\n\toption a \"b\\\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: option before any section" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.OptionOutsideSection,
        parseDiag(gpa, "option a 'b'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(
        error.OptionOutsideSection,
        parseDiag(gpa, "# c\nlist a 'b'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: bad keyword" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.BadKeyword, parseDiag(gpa, "config s\nfoo bar\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: missing argument" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.MissingArgument, parseDiag(gpa, "config\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(error.MissingArgument, parseDiag(gpa, "config s\n\toption k\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectError(error.MissingArgument, parseDiag(gpa, "package\n", &diag));
}

test "error: too many arguments" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.TooManyArguments, parseDiag(gpa, "config a b c\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(
        error.TooManyArguments,
        parseDiag(gpa, "config s\n\toption k v extra\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: line too long" {
    const gpa = testing.allocator;
    const line = try gpa.alloc(u8, max_line_len + 10);
    defer gpa.free(line);
    @memset(line, 'a');
    @memcpy(line[0..7], "config ");
    var diag: Diagnostics = .{};
    try testing.expectError(error.LineTooLong, parseDiag(gpa, line, &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
}

test "error: input too large" {
    const gpa = testing.allocator;
    const bytes = try gpa.alloc(u8, max_input_len + 1);
    defer gpa.free(bytes);
    @memset(bytes, '\n');
    var diag: Diagnostics = .{ .line = 99 };
    try testing.expectError(error.InputTooLarge, parseDiag(gpa, bytes, &diag));
    try testing.expectEqual(@as(usize, 0), diag.line);
}

test "accessors: section lookup and type iteration" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, golden_network);
    defer pkg.deinit(gpa);

    const lan = pkg.section("interface", "lan").?;
    try testing.expectEqualStrings("static", lan.get("proto").?);
    try testing.expect(pkg.section("interface", "nope") == null);
    try testing.expect(pkg.section("nope", "lan") == null);
    try testing.expect(lan.get("nope") == null);
    try testing.expectEqual(@as(usize, 0), lan.getList("nope").len);

    var it = pkg.iterate("interface");
    try testing.expectEqualStrings("lan", it.next().?.name.?);
    try testing.expectEqualStrings("wan", it.next().?.name.?);
    try testing.expect(it.next() == null);

    var none = pkg.iterate("nope");
    try testing.expect(none.next() == null);
}

test "crlf input" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config s 'n'\r\n\toption a 'b'\r\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("n", pkg.sections[0].name.?);
    try testing.expectEqualStrings("b", pkg.sections[0].get("a").?);
}

test "package keyword and header serialization" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "package dhcp\n\nconfig dnsmasq\n\toption domain 'lan'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("dhcp", pkg.name.?);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "package 'dhcp'\n\nconfig dnsmasq\n\toption domain 'lan'\n",
        text,
    );
    try expectRoundTrip(text);
}

test "quoted keys and types round-trip" {
    try expectRoundTrip("config 'weird type' 'n'\n\toption 'weird key' 'v'\n");
}

test "meta is well-formed" {
    try testing.expect(meta.role == .codec);
}
