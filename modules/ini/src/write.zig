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

const Scratch = struct {
    gpa: Allocator,
    w: *std.Io.Writer,
    o: *const WriteOptions,
    separator: []const u8,
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
    var s: Scratch = .{
        .gpa = gpa,
        .w = w,
        .o = &o,
        .separator = o.separator orelse try defaultSeparator(&o.options, &sep_buf),
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
