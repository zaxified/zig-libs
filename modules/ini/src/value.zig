// SPDX-License-Identifier: MIT

//! What a raw value can mean: typed readings, lists, escaping, the references
//! of interpolation. All of it is a layer over raw values; nothing here is
//! applied unless asked for (see SPEC.md).

const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const Document = root.Document;

// ── typed readings ───────────────────────────────────────────────────────────

pub const IntError = error{ NotAnInt, Overflow };
pub const FloatError = error{NotAFloat};

/// Digits with single `_` between them: Python's rule for `int` and `float`.
fn digitRun(s: []const u8, from: usize) usize {
    var i = from;
    while (i < s.len) {
        if (std.ascii.isDigit(s[i])) {
            i += 1;
        } else if (s[i] == '_' and i > from and i + 1 < s.len and std.ascii.isDigit(s[i + 1]) and s[i - 1] != '_') {
            i += 1;
        } else break;
    }
    return i;
}

/// A base-10 integer as Python's `int()` reads a config value: surrounding
/// blanks, a sign, digits with single `_` between them. Not hexadecimal (go-ini
/// reads `0x10`; `configparser` and `GKeyFile` refuse it). Only ASCII digits.
pub fn intValue(comptime T: type, raw: []const u8) IntError!T {
    const s = std.mem.trim(u8, raw, " \t");
    const start: usize = if (s.len != 0 and (s[0] == '+' or s[0] == '-')) 1 else 0;
    if (s.len == start or digitRun(s, start) != s.len) return error.NotAnInt;
    return std.fmt.parseInt(T, s, 10) catch |e| switch (e) {
        error.Overflow => error.Overflow,
        error.InvalidCharacter => error.NotAnInt, // a negative for an unsigned T is Overflow above
    };
}

/// A float as Python's `float()` reads a config value: surrounding blanks, a
/// sign, `1`, `1.`, `.5`, `1e5`, `1_000.5`, or `inf`, `infinity`, `nan` in any
/// case. Not hexadecimal floats. Out-of-range magnitudes become inf or 0.
pub fn floatValue(comptime T: type, raw: []const u8) FloatError!T {
    const s = std.mem.trim(u8, raw, " \t");
    var i: usize = 0;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) i += 1;
    const body = s[i..];
    const neg = s.len != 0 and s[0] == '-';
    if (std.ascii.eqlIgnoreCase(body, "inf") or std.ascii.eqlIgnoreCase(body, "infinity"))
        return if (neg) -std.math.inf(T) else std.math.inf(T);
    if (std.ascii.eqlIgnoreCase(body, "nan")) return std.math.nan(T);
    const int_end = digitRun(s, i);
    var digits = int_end != i;
    i = int_end;
    if (i < s.len and s[i] == '.') {
        i += 1;
        const frac_end = digitRun(s, i);
        digits = digits or frac_end != i;
        i = frac_end;
    }
    if (!digits) return error.NotAFloat;
    if (i < s.len and (s[i] == 'e' or s[i] == 'E')) {
        i += 1;
        if (i < s.len and (s[i] == '+' or s[i] == '-')) i += 1;
        const exp_end = digitRun(s, i);
        if (exp_end == i) return error.NotAFloat;
        i = exp_end;
    }
    if (i != s.len) return error.NotAFloat;
    return std.fmt.parseFloat(T, s) catch error.NotAFloat;
}

/// `1 yes true on` / `0 no false off`, any ASCII case: Python's `getboolean`.
pub fn boolValue(raw: []const u8) error{NotABool}!bool {
    for ([_][]const u8{ "1", "yes", "true", "on" }) |t| if (std.ascii.eqlIgnoreCase(raw, t)) return true;
    for ([_][]const u8{ "0", "no", "false", "off" }) |f| if (std.ascii.eqlIgnoreCase(raw, f)) return false;
    return error.NotABool;
}

// ── lists ────────────────────────────────────────────────────────────────────

pub const ListOptions = struct {
    separator: u8 = ',',
    /// Trim blanks around each element.
    trim: bool = true,
    /// Keep empty elements (a trailing separator still ends the list and adds
    /// none, in go-ini's `Strings` and in `GKeyFile`).
    keep_empty: bool = true,
    /// How a backslash reads: `.none` it is text; `.separator` a backslash
    /// before the separator or a backslash is an escape, before anything else
    /// it is text, and a lone final one is dropped (go-ini's `Strings`);
    /// `.desktop` the separator and the Desktop Entry escapes, anything else
    /// `error.InvalidEscape`.
    escapes: enum { none, separator, desktop } = .separator,

    /// `GKeyFile.get_string_list`: `;`, kept empties, Desktop Entry escapes.
    pub const desktop: ListOptions = .{ .separator = ';', .trim = false, .keep_empty = true, .escapes = .desktop };
};

pub const ListError = Allocator.Error || error{InvalidEscape};

/// The elements of a list value; `deinit` frees them all at once.
pub const List = struct {
    items: []const []const u8,
    /// The bytes `items` point into.
    storage: []const u8,

    pub fn deinit(self: *List, gpa: Allocator) void {
        gpa.free(self.items);
        gpa.free(self.storage);
        self.* = undefined;
    }
};

/// Split a raw value into a list. Elements can only shrink, so one buffer of
/// the value's size holds them all.
pub fn parseList(gpa: Allocator, raw: []const u8, opts: ListOptions) ListError!List {
    const buf = try gpa.alloc(u8, raw.len);
    errdefer gpa.free(buf);
    var starts: std.ArrayList([2]usize) = .empty;
    defer starts.deinit(gpa);
    var o: usize = 0;
    var el_start: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c == '\\' and opts.escapes != .none) {
            const has_next = i + 1 < raw.len;
            if (has_next and raw[i + 1] == opts.separator) {
                buf[o] = opts.separator;
                o += 1;
                i += 1;
                continue;
            }
            if (opts.escapes == .separator) {
                if (!has_next) continue;
                if (raw[i + 1] == '\\') {
                    buf[o] = '\\';
                    o += 1;
                    i += 1;
                    continue;
                }
            }
            if (opts.escapes == .desktop) {
                if (!has_next) return error.InvalidEscape;
                i += 1;
                buf[o] = switch (raw[i]) {
                    's' => ' ',
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '\\' => '\\',
                    else => return error.InvalidEscape,
                };
                o += 1;
                continue;
            }
        }
        if (c == opts.separator) {
            try pushElement(gpa, &starts, buf, el_start, o, opts);
            el_start = o;
            continue;
        }
        buf[o] = c;
        o += 1;
    }
    // The piece after the last separator, unless it is empty (a trailing
    // separator ends the list; the empty text is an empty list).
    if (o != el_start) try pushElement(gpa, &starts, buf, el_start, o, opts);
    const items = try gpa.alloc([]const u8, starts.items.len);
    for (starts.items, items) |r, *it| it.* = buf[r[0]..r[1]];
    return .{ .items = items, .storage = buf };
}

fn pushElement(gpa: Allocator, starts: *std.ArrayList([2]usize), buf: []const u8, from: usize, to: usize, opts: ListOptions) Allocator.Error!void {
    var a = from;
    var b = to;
    if (opts.trim) {
        while (a < b and (buf[a] == ' ' or buf[a] == '\t')) a += 1;
        while (b > a and (buf[b - 1] == ' ' or buf[b - 1] == '\t')) b -= 1;
    }
    if (a == b and !opts.keep_empty) return;
    try starts.append(gpa, .{ a, b });
}

// ── escaping, the inverse of unquote and unescapeDesktop ─────────────────────

/// `raw` in double quotes with `\\`, `\"`, `\n`, `\t`, `\r` escaped:
/// `unquote(quote(x)) == x`. Caller frees.
pub fn quote(gpa: Allocator, raw: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = try .initCapacity(gpa, raw.len + 2);
    errdefer out.deinit(gpa);
    try out.append(gpa, '"');
    for (raw) |c| {
        const e: ?u8 = switch (c) {
            '\\' => '\\',
            '"' => '"',
            '\n' => 'n',
            '\t' => 't',
            '\r' => 'r',
            else => null,
        };
        if (e) |x| {
            try out.appendSlice(gpa, &.{ '\\', x });
        } else try out.append(gpa, c);
    }
    try out.append(gpa, '"');
    return out.toOwnedSlice(gpa);
}

/// A string with the Desktop Entry escapes applied, so it survives a
/// key-file line: `unescapeDesktop(escapeDesktop(x)) == x`. As
/// `GKeyFile.set_string` writes it: blanks are escaped only in the leading run
/// (a reader trims those). Caller frees.
pub fn escapeDesktop(gpa: Allocator, raw: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = try .initCapacity(gpa, raw.len);
    errdefer out.deinit(gpa);
    var leading = true;
    for (raw) |c| {
        leading = leading and (c == ' ' or c == '\t');
        const e: ?u8 = switch (c) {
            '\\' => '\\',
            '\n' => 'n',
            '\r' => 'r',
            '\t' => if (leading) 't' else null,
            ' ' => if (leading) 's' else null,
            else => null,
        };
        if (e) |x| {
            try out.appendSlice(gpa, &.{ '\\', x });
        } else try out.append(gpa, c);
    }
    return out.toOwnedSlice(gpa);
}

// ── locale keys ──────────────────────────────────────────────────────────────

pub fn getLocale(doc: *const Document, section: []const u8, key: []const u8, locale: []const u8) ?[]const u8 {
    var buf: [512]u8 = undefined;
    if (key.len + locale.len <= 500) {
        // lang[_TERRITORY][.CODESET][@MODIFIER]
        const at = std.mem.findScalar(u8, locale, '@');
        const without_mod = locale[0 .. at orelse locale.len];
        const dot = std.mem.findScalar(u8, without_mod, '.');
        const without_enc = without_mod[0 .. dot orelse without_mod.len];
        const us = std.mem.findScalar(u8, without_enc, '_');
        const lang = without_enc[0 .. us orelse without_enc.len];
        const parts = [3][]const u8{
            if (dot) |d| without_mod[d..] else "", // bit 0
            if (us) |u| without_enc[u..] else "", // bit 1
            if (at) |m| locale[m..] else "", // bit 2
        };
        const present: u3 = @as(u3, @intFromBool(parts[0].len != 0)) |
            (@as(u3, @intFromBool(parts[1].len != 0)) << 1) |
            (@as(u3, @intFromBool(parts[2].len != 0)) << 2);
        var j: u4 = 8;
        while (j != 0) {
            j -= 1;
            const mask: u3 = @intCast(j);
            if (mask & ~present != 0) continue;
            var w: std.Io.Writer = .fixed(&buf);
            // Cannot fail: everything written is under the length checked above.
            w.print("{s}[{s}{s}{s}{s}]", .{
                key,
                lang,
                if (mask & 2 != 0) parts[1] else "",
                if (mask & 1 != 0) parts[0] else "",
                if (mask & 4 != 0) parts[2] else "",
            }) catch break;
            if (doc.get(section, w.buffered())) |v| return v;
        }
    }
    return doc.get(section, key);
}

// ── interpolation ────────────────────────────────────────────────────────────

pub const InterpolateOptions = struct {
    /// `.basic`: `%(name)s` and `%%`. `.extended`: `${name}`, `${section:name}`
    /// and `$$`.
    style: enum { basic, extended } = .basic,
    /// References nested deeper than this are `error.InterpolationDepth`.
    /// `configparser`'s `MAX_INTERPOLATION_DEPTH`; at most 64 is honoured, as
    /// this recurses.
    max_depth: u8 = 10,
    /// The longest result. Beyond it `error.InterpolationTooLarge`: ten levels
    /// of doubling references are a thousand-fold expansion per level of text.
    max_bytes: usize = 1 << 20,
    /// The most references followed, for the same reason: references that
    /// expand to nothing cost time without producing output.
    max_steps: usize = 1 << 20,
};

pub const InterpolateError = Allocator.Error || error{
    /// A marker not followed by what the style allows.
    InterpolationSyntax,
    /// A reference to a key or section that does not exist.
    InterpolationMissing,
    /// `InterpolateOptions.max_depth`: usually a cycle.
    InterpolationDepth,
    InterpolationTooLarge,
};

const Expansion = struct {
    doc: *const Document,
    gpa: Allocator,
    opts: InterpolateOptions,
    out: std.ArrayList(u8) = .empty,
    steps: usize = 0,

    fn append(self: *Expansion, s: []const u8) InterpolateError!void {
        if (s.len > self.opts.max_bytes -| self.out.items.len) return error.InterpolationTooLarge;
        try self.out.appendSlice(self.gpa, s);
    }

    fn expand(self: *Expansion, section: []const u8, text: []const u8, depth: u32) InterpolateError!void {
        if (depth > @min(self.opts.max_depth, 64)) return error.InterpolationDepth;
        const marker: u8, const open: u8, const close: []const u8 = switch (self.opts.style) {
            .basic => .{ '%', '(', ")s" },
            .extended => .{ '$', '{', "}" },
        };
        var rest = text;
        while (true) {
            const p = std.mem.findScalar(u8, rest, marker) orelse return self.append(rest);
            try self.append(rest[0..p]);
            rest = rest[p..];
            const c: u8 = if (rest.len > 1) rest[1] else 0;
            if (c == marker) {
                try self.append(rest[0..1]);
                rest = rest[2..];
                continue;
            }
            if (c != open) return error.InterpolationSyntax;
            // The name is at least one byte, without the closing character.
            const end = std.mem.find(u8, rest[2..], close) orelse return error.InterpolationSyntax;
            const name = rest[2..][0..end];
            if (name.len == 0 or std.mem.findScalar(u8, name, close[0]) != null) return error.InterpolationSyntax;
            rest = rest[2 + end + close.len ..];
            self.steps += 1;
            if (self.steps > self.opts.max_steps) return error.InterpolationTooLarge;
            var target_section = section;
            var target_key = name;
            if (self.opts.style == .extended) {
                if (std.mem.findScalar(u8, name, ':')) |colon| {
                    target_section = name[0..colon];
                    target_key = name[colon + 1 ..];
                    if (std.mem.findScalar(u8, target_key, ':') != null) return error.InterpolationSyntax;
                }
            }
            const v = self.doc.get(target_section, target_key) orelse return error.InterpolationMissing;
            if (std.mem.findScalar(u8, v, marker) != null) {
                try self.expand(target_section, v, depth + 1);
            } else try self.append(v);
        }
    }
};

pub fn interpolated(doc: *const Document, gpa: Allocator, section: []const u8, key: []const u8, opts: InterpolateOptions) InterpolateError!?[]u8 {
    const raw = doc.get(section, key) orelse return null;
    var e: Expansion = .{ .doc = doc, .gpa = gpa, .opts = opts };
    errdefer e.out.deinit(gpa);
    try e.expand(section, raw, 1);
    return try e.out.toOwnedSlice(gpa);
}

// ── struct mapping ───────────────────────────────────────────────────────────

pub const MapError = IntError || FloatError || error{ NotABool, NotAnEnumTag };

fn readField(comptime F: type, raw: []const u8) MapError!F {
    switch (@typeInfo(F)) {
        .int => return intValue(F, raw),
        .float => return floatValue(F, raw),
        .bool => return boolValue(raw),
        .@"enum" => return std.meta.stringToEnum(F, raw) orelse error.NotAnEnumTag,
        .optional => |o| return try readField(o.child, raw),
        else => {
            if (F == []const u8) return raw;
            @compileError("ini.Document.mapSection: unsupported field type " ++ @typeName(F));
        },
    }
}

pub fn mapSection(doc: *const Document, comptime T: type, section: []const u8) MapError!T {
    var out: T = .{};
    const info = @typeInfo(T).@"struct";
    inline for (info.field_names, info.field_types) |name, F| {
        if (doc.get(section, name)) |raw| @field(out, name) = try readField(F, raw);
    }
    return out;
}

test "getLocale picks the most specific variant" {
    const testing = std.testing;
    var doc = try root.parse(testing.allocator, "[g]\nN=plain\nN[de]=de\nN[de_DE]=de_DE\nN[de@euro]=de@euro\n", .desktop);
    defer doc.deinit();
    try testing.expectEqualStrings("de_DE", doc.getLocale("g", "N", "de_DE.UTF-8").?);
    try testing.expectEqualStrings("de@euro", doc.getLocale("g", "N", "de_AT@euro").?);
    try testing.expectEqualStrings("de", doc.getLocale("g", "N", "de_AT").?);
    try testing.expectEqualStrings("plain", doc.getLocale("g", "N", "fr").?);
    try testing.expect(doc.getLocale("g", "X", "fr") == null);
    const long: [600]u8 = @splat('x');
    try testing.expectEqualStrings("plain", doc.getLocale("g", "N", &long).?);
}
