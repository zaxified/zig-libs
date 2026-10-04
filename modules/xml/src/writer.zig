// SPDX-License-Identifier: MIT
//! XML 1.0 writer: a push API (`Writer`) for building documents, and
//! `writeDocument` / `writeElement` for serializing a parsed tree.
//!
//! Output is UTF-8 XML 1.0 that this module's own parser — and any
//! conforming one — reads back to the same infoset. What makes that hold:
//!
//!   - **Escaping.** Text: `&` `<` `>` as entity references, CR as `&#xD;`
//!     (a literal CR would be normalized away, XML §2.11). Attribute values,
//!     always double-quoted: `&` `<` `"` as references, and TAB / LF / CR as
//!     `&#x9;` `&#xA;` `&#xD;` (literal ones would become spaces, §3.3.3).
//!   - **Refusal instead of silent damage.** A code point XML 1.0 cannot carry
//!     at all (C0 controls other than TAB/LF/CR, U+FFFE, U+FFFF, invalid
//!     UTF-8) is `InvalidCharacter`; a name that is not a QName is
//!     `InvalidName`; a comment with `--` or a trailing `-` is
//!     `InvalidComment`; a PI whose target is `xml` (any case) or whose data
//!     holds `?>` is `InvalidPi`. CDATA content holding `]]>` is split into
//!     two sections, which reads back as the same text.
//!   - **Balance.** `Writer` keeps the open element names (allocator-backed)
//!     and writes the matching end tag itself; `end` fails `Unbalanced` while
//!     an element is open.
//!
//! Namespaces are the caller's: `namespace(prefix, uri)` writes the
//! declaration where it is asked for; the writer does not invent prefixes.
//! `writeDocument` reproduces a parsed tree's own prefixes and declarations,
//! so `parse(write(parse(x)))` has the same infoset as `parse(x)` (checked
//! against libxml2's canonical form in the module's oracle run, SPEC.md).

const std = @import("std");
const root = @import("root.zig");
const Io = std.Io;

pub const Error = Io.Writer.Error || std.mem.Allocator.Error || error{
    InvalidName,
    InvalidCharacter,
    InvalidComment,
    InvalidPi,
    /// `attribute`/`namespace` outside a start tag, or a second root.
    NotInStartTag,
    /// `endElement` with nothing open, or `end` with something open.
    Unbalanced,
};

pub const Writer = struct {
    w: *Io.Writer,
    gpa: std.mem.Allocator,
    open: std.ArrayList([]const u8) = .empty,
    /// A start tag is open: attributes may still follow.
    in_start_tag: bool = false,
    wrote_root: bool = false,

    pub fn init(gpa: std.mem.Allocator, w: *Io.Writer) Writer {
        return .{ .w = w, .gpa = gpa };
    }

    pub fn deinit(self: *Writer) void {
        for (self.open.items) |n| self.gpa.free(n);
        self.open.deinit(self.gpa);
    }

    /// `<?xml version="1.0" encoding="UTF-8"?>`. Optional; first if used.
    pub fn xmlDecl(self: *Writer) Error!void {
        try self.w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    }

    fn closeStartTag(self: *Writer) Error!void {
        if (self.in_start_tag) {
            try self.w.writeByte('>');
            self.in_start_tag = false;
        }
    }

    /// Open an element named `qname` (`local` or `prefix:local`).
    pub fn startElement(self: *Writer, qname: []const u8) Error!void {
        try checkQName(qname);
        if (self.open.items.len == 0) {
            if (self.wrote_root) return error.NotInStartTag;
            self.wrote_root = true;
        }
        try self.closeStartTag();
        const copy = try self.gpa.dupe(u8, qname);
        errdefer self.gpa.free(copy);
        try self.open.append(self.gpa, copy);
        try self.w.writeByte('<');
        try self.w.writeAll(qname);
        self.in_start_tag = true;
    }

    /// An attribute on the element just opened.
    pub fn attribute(self: *Writer, qname: []const u8, value: []const u8) Error!void {
        if (!self.in_start_tag) return error.NotInStartTag;
        try checkQName(qname);
        try self.w.writeByte(' ');
        try self.w.writeAll(qname);
        try self.w.writeAll("=\"");
        try escapeAttr(self.w, value);
        try self.w.writeByte('"');
    }

    /// A namespace declaration on the element just opened: `xmlns="uri"`
    /// for `prefix == ""`, else `xmlns:prefix="uri"`.
    pub fn namespace(self: *Writer, prefix: []const u8, uri: []const u8) Error!void {
        if (!self.in_start_tag) return error.NotInStartTag;
        if (prefix.len != 0) try checkNcName(prefix);
        try self.w.writeAll(if (prefix.len == 0) " xmlns" else " xmlns:");
        try self.w.writeAll(prefix);
        try self.w.writeAll("=\"");
        try escapeAttr(self.w, uri);
        try self.w.writeByte('"');
    }

    pub fn text(self: *Writer, s: []const u8) Error!void {
        if (self.open.items.len == 0) return error.NotInStartTag;
        try self.closeStartTag();
        try escapeText(self.w, s);
    }

    /// A CDATA section (split in two around any `]]>`).
    pub fn cdata(self: *Writer, s: []const u8) Error!void {
        if (self.open.items.len == 0) return error.NotInStartTag;
        try self.closeStartTag();
        try writeCData(self.w, s);
    }

    pub fn comment(self: *Writer, s: []const u8) Error!void {
        try self.closeStartTag();
        try writeComment(self.w, s);
    }

    pub fn pi(self: *Writer, target: []const u8, data: []const u8) Error!void {
        try self.closeStartTag();
        try writePi(self.w, target, data);
    }

    /// Close the innermost open element (`<a/>` if it has no content).
    pub fn endElement(self: *Writer) Error!void {
        const name = self.open.pop() orelse return error.Unbalanced;
        defer self.gpa.free(name);
        if (self.in_start_tag) {
            try self.w.writeAll("/>");
            self.in_start_tag = false;
        } else {
            try self.w.writeAll("</");
            try self.w.writeAll(name);
            try self.w.writeByte('>');
        }
    }

    /// Check the document is complete: one root, every element closed.
    pub fn end(self: *Writer) Error!void {
        if (self.open.items.len != 0 or !self.wrote_root) return error.Unbalanced;
    }
};

// ── checks and escaping ────────────────────────────────────────────────────

fn checkNcName(s: []const u8) Error!void {
    var view = std.unicode.Utf8View.init(s) catch return error.InvalidName;
    var it = view.iterator();
    const first = it.nextCodepoint() orelse return error.InvalidName;
    if (first == ':' or !root.isNameStartChar(first)) return error.InvalidName;
    while (it.nextCodepoint()) |cp| if (cp == ':' or !root.isNameChar(cp)) return error.InvalidName;
}

fn checkQName(s: []const u8) Error!void {
    if (std.mem.indexOfScalar(u8, s, ':')) |c| {
        try checkNcName(s[0..c]);
        try checkNcName(s[c + 1 ..]);
    } else try checkNcName(s);
}

/// Every code point of `s` is an XML `Char`.
fn checkChars(s: []const u8) Error!void {
    var view = std.unicode.Utf8View.init(s) catch return error.InvalidCharacter;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| if (!root.isXmlChar(cp)) return error.InvalidCharacter;
}

fn escapeText(w: *Io.Writer, s: []const u8) Error!void {
    try checkChars(s);
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const rep: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '\r' => "&#xD;",
            else => continue,
        };
        try w.writeAll(s[start..i]);
        try w.writeAll(rep);
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

fn escapeAttr(w: *Io.Writer, s: []const u8) Error!void {
    try checkChars(s);
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const rep: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '"' => "&quot;",
            '\t' => "&#x9;",
            '\n' => "&#xA;",
            '\r' => "&#xD;",
            else => continue,
        };
        try w.writeAll(s[start..i]);
        try w.writeAll(rep);
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

fn writeCData(w: *Io.Writer, s: []const u8) Error!void {
    try checkChars(s);
    var rest = s;
    try w.writeAll("<![CDATA[");
    while (std.mem.indexOf(u8, rest, "]]>")) |at| {
        // "]]" ends this section, ">" starts the next: same characters.
        try w.writeAll(rest[0 .. at + 2]);
        try w.writeAll("]]><![CDATA[");
        rest = rest[at + 2 ..];
    }
    try w.writeAll(rest);
    try w.writeAll("]]>");
}

fn writeComment(w: *Io.Writer, s: []const u8) Error!void {
    try checkChars(s);
    if (std.mem.indexOf(u8, s, "--") != null or std.mem.endsWith(u8, s, "-")) return error.InvalidComment;
    try w.writeAll("<!--");
    try w.writeAll(s);
    try w.writeAll("-->");
}

fn writePi(w: *Io.Writer, target: []const u8, data: []const u8) Error!void {
    checkNcName(target) catch return error.InvalidPi;
    if (std.ascii.eqlIgnoreCase(target, "xml")) return error.InvalidPi;
    try checkChars(data);
    if (std.mem.indexOf(u8, data, "?>") != null) return error.InvalidPi;
    try w.writeAll("<?");
    try w.writeAll(target);
    if (data.len != 0) {
        try w.writeByte(' ');
        try w.writeAll(data);
    }
    try w.writeAll("?>");
}

// ── tree serialization ─────────────────────────────────────────────────────

fn writeMisc(w: *Io.Writer, c: root.Child) Error!void {
    switch (c.content) {
        .comment => |s| try writeComment(w, s),
        .pi => |p| try writePi(w, p.target, p.data),
        else => {},
    }
}

fn writeStartTag(w: *Io.Writer, el: *const root.Element) Error!void {
    try w.writeByte('<');
    try writeQName(w, el.prefix, el.local);
    for (el.ns_decls) |d| {
        try w.writeAll(if (d.prefix.len == 0) " xmlns" else " xmlns:");
        try w.writeAll(d.prefix);
        try w.writeAll("=\"");
        try escapeAttr(w, d.uri);
        try w.writeByte('"');
    }
    for (el.attributes) |at| {
        try w.writeByte(' ');
        try writeQName(w, at.prefix, at.local);
        try w.writeAll("=\"");
        try escapeAttr(w, at.value);
        try w.writeByte('"');
    }
}

fn writeQName(w: *Io.Writer, prefix: []const u8, local: []const u8) Error!void {
    if (prefix.len != 0) {
        try w.writeAll(prefix);
        try w.writeByte(':');
    }
    try w.writeAll(local);
}

/// Serialize `el` and its subtree. Iterative (an explicit stack from `gpa`),
/// so a tree as deep as `Options.max_depth` allows does not recurse on the
/// machine stack.
pub fn writeElement(gpa: std.mem.Allocator, w: *Io.Writer, el: *const root.Element) Error!void {
    const Frame = struct { el: *const root.Element, next: usize };
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(gpa);
    try writeStartTag(w, el);
    if (el.children.len == 0) {
        try w.writeAll("/>");
        return;
    }
    try w.writeByte('>');
    try stack.append(gpa, .{ .el = el, .next = 0 });
    while (stack.items.len > 0) {
        const top = &stack.items[stack.items.len - 1];
        if (top.next == top.el.children.len) {
            try w.writeAll("</");
            try writeQName(w, top.el.prefix, top.el.local);
            try w.writeByte('>');
            _ = stack.pop();
            continue;
        }
        const c = top.el.children[top.next];
        top.next += 1;
        switch (c.content) {
            .element => |child| {
                try writeStartTag(w, child);
                if (child.children.len == 0) {
                    try w.writeAll("/>");
                } else {
                    try w.writeByte('>');
                    try stack.append(gpa, .{ .el = child, .next = 0 });
                }
            },
            .text => |t| try escapeText(w, t),
            .cdata => |t| try writeCData(w, t),
            .comment, .pi => try writeMisc(w, c),
        }
    }
}

/// Serialize a parsed document: an XML declaration (UTF-8, whatever the
/// input's encoding was), the prolog's comments and PIs, the root element,
/// the epilog's. A DOCTYPE is not reproduced (entities were expanded).
pub fn writeDocument(gpa: std.mem.Allocator, w: *Io.Writer, doc: *const root.Document) Error!void {
    try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    for (doc.prolog) |c| try writeMisc(w, c);
    try writeElement(gpa, w, doc.root);
    for (doc.epilog) |c| try writeMisc(w, c);
}
