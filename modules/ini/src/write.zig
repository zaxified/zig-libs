// SPDX-License-Identifier: MIT

//! Rendering sections and entries, and proving each one reads back. Nothing is
//! written that the same `Options` would read differently: every line goes
//! through the parser's own classifier first (`verifyEntry`, `verifyHeader`),
//! so what a dialect cannot express is `error.NotRepresentable`, not a file
//! that silently means something else.

const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const Options = root.Options;
const Classifier = @import("scan.zig").Classifier;

pub const WriteOptions = struct {
    /// The dialect the text must read back under. Use the document's own.
    options: Options = .{},
    /// Between a key and its value. Null: `" = "` with the first of
    /// `Options.separators`, or without spaces when `trim_values` is false
    /// (a key file, `Name=Value`).
    separator: ?[]const u8 = null,
    /// Each key of each section once, with the section's own last value; the
    /// entries before any header first (they have no header, so anything else
    /// first would claim them), then the document's `[DEFAULT]`, then the sections
    /// merged: what `configparser.write` produces. False:
    /// everything in file order, repeated sections and keys included.
    merged: bool = false,
    /// A blank line after each section. `configparser.write` does.
    blank_after_section: bool = true,
    /// Before each continuation line of a value.
    continuation_indent: []const u8 = "\t",
    /// `"\n"` or `"\r\n"`; anything else is `error.NotRepresentable`.
    eol: []const u8 = "\n",
};

pub const WriteError = std.Io.Writer.Error || Allocator.Error || error{
    /// Under these options the text would not read back as this name or value:
    /// a newline where continuation lines are off, a leading blank, a key with
    /// a separator in it, a value that an inline comment would cut, an `eol` that
    /// is not a line ending, ...
    NotRepresentable,
};

pub fn defaultSeparator(opts: *const Options, buf: *[3]u8) error{NotRepresentable}![]const u8 {
    if (opts.separators.len == 0) return error.NotRepresentable;
    if (!opts.trim_values) {
        buf[0] = opts.separators[0];
        return buf[0..1];
    }
    buf.* = .{ ' ', opts.separators[0], ' ' };
    return buf;
}

/// Whether `block`, read by a fresh classifier in a section, is one entry with
/// exactly this key and value (`Editor` and `writeDocument` both end here).
/// `block` may span lines; a `\r` before each `\n` is dropped, as on reading.
pub fn verifyEntry(block: []const u8, key: []const u8, value: []const u8, has_value: bool, opts: *const Options) bool {
    var c: Classifier = .{ .opts = opts.*, .in_section = true };
    var lines = std.mem.splitScalar(u8, block, '\n');
    const head = switch (c.feed(lines.next().?)) {
        .entry => |e| e,
        else => return false,
    };
    if (!std.mem.eql(u8, head.key, key) or head.has_value != has_value) return false;
    if (!std.mem.startsWith(u8, value, head.value)) return false;
    var at = head.value.len;
    while (lines.next()) |raw| switch (c.feed(raw)) {
        .blank, .comment => {},
        .continuation => |t| {
            if (value.len - at < t.blanks_before + 1 + t.text.len) return false;
            for (value[at..][0 .. t.blanks_before + 1]) |ch| if (ch != '\n') return false;
            at += t.blanks_before + 1;
            if (!std.mem.eql(u8, value[at..][0..t.text.len], t.text)) return false;
            at += t.text.len;
        },
        else => return false,
    };
    return at == value.len;
}

pub fn verifyHeader(line: []const u8, name: []const u8, opts: *const Options) bool {
    if (std.mem.findScalar(u8, line, '\n') != null) return false;
    var c: Classifier = .{ .opts = opts.* };
    return switch (c.feed(line)) {
        .section => |s| std.mem.eql(u8, s.name, name),
        else => false,
    };
}

/// Appends `value` as its first line plus continuation lines to `out`.
pub fn appendValue(gpa: Allocator, out: *std.ArrayList(u8), value: []const u8, indent: []const u8, eol: []const u8) Allocator.Error!void {
    var parts = std.mem.splitScalar(u8, value, '\n');
    try out.appendSlice(gpa, parts.next().?);
    while (parts.next()) |p| {
        try out.appendSlice(gpa, eol);
        // Even an empty line gets the indent: `configparser.write` does, and
        // it reads as blank.
        try out.appendSlice(gpa, indent);
        try out.appendSlice(gpa, p);
    }
}

/// A byte-class shortcut for the common entry: one line, a plain key and a
/// plain value. It accepts an entry only when the classifier provably would
/// (so it never replaces the proof, only skips copying the line and reading it
/// back); anything else, and every bare key under a dialect that refuses them,
/// goes the long way through `verifyEntry`. `write_fast_test` below holds it to
/// "accepts implies the classifier accepts" over generated entries.
pub const Plain = struct {
    ok: bool,
    /// Not allowed anywhere in a key: a separator, a comment character, a
    /// bracket, a line end.
    key_bad: [256]bool = @splat(false),
    /// Not allowed anywhere in a value: a line end and, when inline comments are
    /// on, a comment character.
    val_bad: [256]bool = @splat(false),

    pub fn init(opts: *const Options, separator: []const u8) Plain {
        var p: Plain = .{ .ok = !opts.locale_keys };
        // The separator must be blanks around one of `separators`, which is no
        // comment character: the first separator on the line is then ours.
        const mid = std.mem.trim(u8, separator, " \t");
        if (mid.len != 1 or std.mem.findScalar(u8, opts.separators, mid[0]) == null or
            std.mem.findScalar(u8, opts.comment_chars, mid[0]) != null) p.ok = false;
        for (separator) |c| if (c != ' ' and c != '\t' and c != mid[0]) {
            p.ok = false;
        };
        for (opts.separators) |c| p.key_bad[c] = true;
        for (opts.comment_chars) |c| {
            p.key_bad[c] = true;
            if (opts.inline_comments) p.val_bad[c] = true;
        }
        for ("[]\r\n") |c| p.key_bad[c] = true;
        p.val_bad['\r'] = true;
        p.val_bad['\n'] = true;
        return p;
    }

    /// True: the line `key` + separator + `value` (or `key` alone when not
    /// `has_value`) reads as exactly this entry under the options given to `init`.
    pub fn entry(self: *const Plain, opts: *const Options, key: []const u8, value: []const u8, has_value: bool) bool {
        if (!self.ok or key.len == 0) return false;
        if (!has_value and !opts.no_value_keys) return false;
        if (isBlank(key[0]) or isBlank(key[key.len - 1])) return false;
        for (key) |c| if (self.key_bad[c]) return false;
        if (!has_value) return true;
        if (value.len == 0) return true;
        if (isBlank(value[0]) or isBlank(value[value.len - 1])) return false;
        for (value) |c| if (self.val_bad[c]) return false;
        return true;
    }

    fn isBlank(c: u8) bool {
        return c == ' ' or c == '\t';
    }
};

const Scratch = struct {
    gpa: Allocator,
    w: *std.Io.Writer,
    o: *const WriteOptions,
    separator: []const u8,
    plain: Plain,
    line: std.ArrayList(u8) = .empty,

    fn header(self: *Scratch, name: []const u8) WriteError!void {
        // Section "" is the entries before any header. It only comes first.
        if (name.len == 0) {
            if (!self.o.options.global_entries) return error.NotRepresentable;
            return;
        }
        self.line.clearRetainingCapacity();
        try self.line.append(self.gpa, '[');
        try self.line.appendSlice(self.gpa, name);
        try self.line.append(self.gpa, ']');
        if (!verifyHeader(self.line.items, name, &self.o.options)) return error.NotRepresentable;
        try self.w.writeAll(self.line.items);
        try self.w.writeAll(self.o.eol);
    }

    fn entry(self: *Scratch, key: []const u8, value: []const u8, has_value: bool) WriteError!void {
        if (self.plain.entry(&self.o.options, key, value, has_value)) {
            try self.w.writeAll(key);
            if (has_value) {
                try self.w.writeAll(self.separator);
                try self.w.writeAll(value);
            }
            return self.w.writeAll(self.o.eol);
        }
        self.line.clearRetainingCapacity();
        try self.line.appendSlice(self.gpa, key);
        if (has_value) {
            try self.line.appendSlice(self.gpa, self.separator);
            try appendValue(self.gpa, &self.line, value, self.o.continuation_indent, self.o.eol);
        }
        if (!verifyEntry(self.line.items, key, value, has_value, &self.o.options)) return error.NotRepresentable;
        try self.w.writeAll(self.line.items);
        try self.w.writeAll(self.o.eol);
    }
};

pub fn writeDocument(doc: *const root.Document, gpa: Allocator, w: *std.Io.Writer, o: WriteOptions) WriteError!void {
    if (!std.mem.eql(u8, o.eol, "\n") and !std.mem.eql(u8, o.eol, "\r\n")) return error.NotRepresentable;
    var sep_buf: [3]u8 = undefined;
    const separator = o.separator orelse try defaultSeparator(&o.options, &sep_buf);
    var s: Scratch = .{
        .gpa = gpa,
        .w = w,
        .o = &o,
        .separator = separator,
        .plain = .init(&o.options, separator),
    };
    defer s.line.deinit(gpa);

    if (!o.merged) {
        for (doc.sections) |sec| {
            try s.header(if (sec.line != 0) sec.name else "");
            for (sec.entries) |e| try s.entry(e.key, e.value, e.has_value);
            if (o.blank_after_section) try w.writeAll(o.eol);
        }
        return;
    }
    // Merged. Section "" first: headerless text belongs to whatever precedes it.
    if (doc.hasSection("")) try writeMergedSection(doc, &s, "");
    // The default section next, and only when it has keys.
    if (doc.default_group != std.math.maxInt(u32)) {
        const dn = doc.sections[doc.default_group].name;
        var it = doc.entries(dn);
        if (dn.len != 0 and it.next() != null) try writeMergedSection(doc, &s, dn);
    }
    var names = doc.sectionNames();
    while (names.next()) |name| {
        if (name.len != 0) try writeMergedSection(doc, &s, name);
    }
}

fn writeMergedSection(doc: *const root.Document, s: *Scratch, name: []const u8) WriteError!void {
    try s.header(name);
    // Only this section's own keys: `merged` lists the inherited ones last.
    var it = doc.merged(name);
    while (it.next()) |e| {
        if (it.in_default) break;
        try s.entry(e.key, e.value, e.has_value);
    }
    if (s.o.blank_after_section) try s.w.writeAll(s.o.eol);
}

test "Plain accepts only entries the classifier accepts" {
    const testing = std.testing;
    const optsets = [_]Options{
        .{},
        .python,
        .{ .separators = "=:", .comment_chars = "#;", .inline_comments = true },
        .{ .trim_values = false, .no_value_keys = true },
        .{ .separators = ":", .comment_chars = "#", .inline_comments = true, .no_value_keys = true },
        .{ .separators = "=", .comment_chars = "=", .inline_comments = true },
        .{ .locale_keys = true },
        .{ .header_trailing_text = true, .continuation_lines = true, .no_value_keys = true },
    };
    const alphabet = "ab =:;#[]\t\r\n.";
    var prng: std.Random.DefaultPrng = .init(0x1417);
    const rnd = prng.random();
    var kbuf: [8]u8 = undefined;
    var vbuf: [8]u8 = undefined;
    var accepted: usize = 0;
    for (optsets) |opts| {
        var sepb: [3]u8 = undefined;
        const sep = defaultSeparator(&opts, &sepb) catch continue;
        const plain = Plain.init(&opts, sep);
        var i: usize = 0;
        while (i < 40000) : (i += 1) {
            const kl = rnd.uintLessThan(usize, kbuf.len + 1);
            const vl = rnd.uintLessThan(usize, vbuf.len + 1);
            for (kbuf[0..kl]) |*c| c.* = alphabet[rnd.uintLessThan(usize, alphabet.len)];
            for (vbuf[0..vl]) |*c| c.* = alphabet[rnd.uintLessThan(usize, alphabet.len)];
            const has_value = rnd.boolean();
            if (!plain.entry(&opts, kbuf[0..kl], vbuf[0..vl], has_value)) continue;
            accepted += 1;
            var line: [32]u8 = undefined;
            var n: usize = 0;
            @memcpy(line[0..kl], kbuf[0..kl]);
            n = kl;
            if (has_value) {
                @memcpy(line[n..][0..sep.len], sep);
                n += sep.len;
                @memcpy(line[n..][0..vl], vbuf[0..vl]);
                n += vl;
            }
            try testing.expect(verifyEntry(line[0..n], kbuf[0..kl], if (has_value) vbuf[0..vl] else "", has_value, &opts));
        }
    }
    // The shortcut is not vacuous.
    try testing.expect(accepted > 5000);
}
