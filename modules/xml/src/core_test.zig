// SPDX-License-Identifier: MIT
//! Tests for the 2026-10-04 additions: non-UTF-8 input, internal DTD
//! entities (opt-in) and the writer.
//!
//! The oracle is libxml2 (through lxml), driven as a black box by
//! `tools/gen_core_vectors.py` and frozen in `core_vectors.zig` as a DUMP of
//! its view of each document; `dump` below re-implements that format (it is
//! defined in the recipe). Writer escapes are derived by hand from XML 1.0
//! §2.4, §2.11 and §3.3.3, as each test says.

const std = @import("std");
const testing = std.testing;
const xml = @import("root.zig");
const cv = @import("core_vectors.zig");
const xmlconf = @import("xmlconf_vectors.zig");

/// The recipe's dump format (see `tools/gen_core_vectors.py`).
pub fn dump(a: std.mem.Allocator, out: *std.ArrayList(u8), el: *const xml.Element) !void {
    try out.print(a, "<{{{s}}}{s}", .{ el.uri, el.local });
    const attrs = try a.dupe(xml.Attribute, el.attributes);
    defer a.free(attrs);
    std.mem.sort(xml.Attribute, attrs, {}, struct {
        fn lt(_: void, x: xml.Attribute, y: xml.Attribute) bool {
            return switch (std.mem.order(u8, x.uri, y.uri)) {
                .lt => true,
                .gt => false,
                .eq => std.mem.order(u8, x.local, y.local) == .lt,
            };
        }
    }.lt);
    for (attrs) |at| try out.print(a, " {{{s}}}{s}={x}", .{ at.uri, at.local, at.value });
    try out.append(a, '>');
    var in_text = false;
    for (el.children) |c| {
        switch (c.content) {
            .text, .cdata => |t| {
                if (t.len == 0) continue;
                if (!in_text) try out.appendSlice(a, "T[");
                in_text = true;
                try out.print(a, "{x}", .{t});
                continue;
            },
            else => {},
        }
        if (in_text) try out.append(a, ']');
        in_text = false;
        switch (c.content) {
            .element => |e| try dump(a, out, e),
            .comment => |t| try out.print(a, "C[{x}]", .{t}),
            .pi => |p| try out.print(a, "P[{s} {x}]", .{ p.target, p.data }),
            else => unreachable,
        }
    }
    if (in_text) try out.append(a, ']');
    try out.appendSlice(a, "</>");
}

pub fn dumpDoc(a: std.mem.Allocator, doc: *const xml.Document) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try dump(a, &out, doc.root);
    return out.toOwnedSlice(a);
}

fn serialize(a: std.mem.Allocator, doc: *const xml.Document) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    try xml.writeDocument(a, &aw.writer, doc);
    return aw.toOwnedSlice();
}

test "libxml2 verdicts: encodings and internal entities, then the writer round trip" {
    const a = testing.allocator;
    var compared: usize = 0;
    for (cv.cases) |c| {
        const input = try a.alloc(u8, c.input.len / 2);
        defer a.free(input);
        _ = try std.fmt.hexToBytes(input, c.input);
        const opts: xml.Options = .{ .doctype = if (c.entities) .internal_entities else .ignore };
        if (c.ours) |want_err| {
            if (xml.parse(a, input, opts)) |d| {
                var doc = d;
                doc.deinit();
                std.debug.print("case '{s}': accepted, want {s}\n", .{ c.name, want_err });
                return error.TestUnexpectedResult;
            } else |e| {
                testing.expectEqualStrings(want_err, @errorName(e)) catch |err| {
                    std.debug.print("case '{s}'\n", .{c.name});
                    return err;
                };
            }
            continue;
        }
        const want = c.lxml orelse unreachable; // every accepted case has an oracle
        var doc = xml.parse(a, input, opts) catch |e| {
            std.debug.print("case '{s}': {t}\n", .{ c.name, e });
            return e;
        };
        defer doc.deinit();
        const got = try dumpDoc(a, &doc);
        defer a.free(got);
        testing.expectEqualStrings(want, got) catch |e| {
            std.debug.print("case '{s}'\n", .{c.name});
            return e;
        };
        // Write it out (UTF-8, entities expanded) and read it back.
        const text = try serialize(a, &doc);
        defer a.free(text);
        var again = try xml.parse(a, text, .{});
        defer again.deinit();
        const got2 = try dumpDoc(a, &again);
        defer a.free(got2);
        try testing.expectEqualStrings(want, got2);
        compared += 1;
    }
    // 7 encoding cases + 7 entity cases are accepted by both sides.
    try testing.expectEqual(@as(usize, 14), compared);
}

test "encodings: the document says what it was read from, spans index the UTF-8 text" {
    const a = testing.allocator;
    // "<r>é</r>" in ISO-8859-1: 0xE9 becomes C3 A9; the text node's span
    // covers the 2 UTF-8 bytes in `doc.source`, not the 1 input byte.
    const input = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>\xe9</r>";
    var doc = try xml.parse(a, input, .{});
    defer doc.deinit();
    try testing.expectEqual(xml.SourceEncoding.latin1, doc.source_encoding);
    const t = doc.root.children[0];
    try testing.expectEqualStrings("\xc3\xa9", t.span.slice(doc.source));
    // UTF-8 input is not copied: `source` is the caller's slice.
    var d8 = try xml.parse(a, "<r/>", .{});
    defer d8.deinit();
    try testing.expectEqual(xml.SourceEncoding.utf8, d8.source_encoding);
}

test "entities: limits are exact (depth and total bytes, derived by hand)" {
    const a = testing.allocator;
    // a -> b -> c: depth 3 is fine under max_entity_depth = 3, refused at 2.
    const chain = "<!DOCTYPE r [<!ENTITY c \"z\"><!ENTITY b \"&c;\"><!ENTITY a \"&b;\">]><r>&a;</r>";
    var ok = try xml.parse(a, chain, .{ .doctype = .internal_entities, .max_entity_depth = 3 });
    ok.deinit();
    try testing.expectError(error.EntityLimit, xml.parse(a, chain, .{ .doctype = .internal_entities, .max_entity_depth = 2 }));
    // "abcd" used three times = 12 expanded bytes + 3 references = 15
    // units: cap 15 passes, 14 fails.
    const three = "<!DOCTYPE r [<!ENTITY e \"abcd\">]><r>&e;&e;&e;</r>";
    var ok2 = try xml.parse(a, three, .{ .doctype = .internal_entities, .max_entity_expansion = 15 });
    ok2.deinit();
    try testing.expectError(error.EntityLimit, xml.parse(a, three, .{ .doctype = .internal_entities, .max_entity_expansion = 14 }));
    // Default policy is unchanged: a DOCTYPE is refused outright.
    try testing.expectError(error.DoctypeForbidden, xml.parse(a, three, .{}));
}

test "entities: the xmlconf accept vectors under .internal_entities" {
    // Every W3C accept vector parses, or fails ONLY with the documented
    // text-only limitation (markup in a replacement text). Counts pinned.
    const a = testing.allocator;
    var parsed: usize = 0;
    var markup: usize = 0;
    for (xmlconf.accept_vectors) |v| {
        if (xml.parse(a, v.content, .{ .doctype = .internal_entities })) |d| {
            var doc = d;
            doc.deinit();
            parsed += 1;
        } else |e| {
            if (e != error.UnsupportedEntity) {
                std.debug.print("{s}: {t}\n", .{ v.id, e });
                return e;
            }
            markup += 1;
        }
    }
    try testing.expectEqual(xmlconf.accept_vectors.len, parsed + markup);
    // Three vectors put markup in an entity's replacement text — the
    // documented text-only limit; the rest (102) expand and parse.
    try testing.expectEqual(@as(usize, 3), markup);
}

test "writer round trip: every xmlconf accept vector reads back to the same infoset" {
    const a = testing.allocator;
    for (xmlconf.accept_vectors) |v| {
        var doc = xml.parse(a, v.content, .{ .doctype = .ignore }) catch continue;
        defer doc.deinit();
        const before = try dumpDoc(a, &doc);
        defer a.free(before);
        const text = try serialize(a, &doc);
        defer a.free(text);
        var again = xml.parse(a, text, .{}) catch |e| {
            std.debug.print("{s}: {t}\n{s}\n", .{ v.id, e, text });
            return e;
        };
        defer again.deinit();
        const after = try dumpDoc(a, &again);
        defer a.free(after);
        testing.expectEqualStrings(before, after) catch |e| {
            std.debug.print("{s}\n", .{v.id});
            return e;
        };
    }
}

fn written(a: std.mem.Allocator, comptime f: fn (*xml.Writer) anyerror!void) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var w: xml.Writer = .init(a, &aw.writer);
    defer w.deinit();
    try f(&w);
    try w.end();
    return aw.toOwnedSlice();
}

test "writer: escapes, empty elements, namespaces (bytes derived by hand)" {
    const a = testing.allocator;
    const out = try written(a, struct {
        fn f(w: *xml.Writer) anyerror!void {
            try w.xmlDecl();
            try w.startElement("p:r");
            try w.namespace("p", "urn:x&y");
            try w.namespace("", "urn:d");
            // §3.3.3: literal TAB/LF/CR would read back as spaces.
            try w.attribute("a", "<\"&\t\n\r>'");
            try w.startElement("e");
            try w.endElement();
            // §2.11: a literal CR would read back as LF.
            try w.text("1 < 2 && 3 > 2\r]]>");
            try w.cdata("x]]>y");
            try w.comment(" c ");
            try w.pi("tgt", "data");
            try w.endElement();
        }
    }.f);
    defer a.free(out);
    try testing.expectEqualStrings(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
            "<p:r xmlns:p=\"urn:x&amp;y\" xmlns=\"urn:d\" a=\"&lt;&quot;&amp;&#x9;&#xA;&#xD;>'\">" ++
            "<e/>1 &lt; 2 &amp;&amp; 3 &gt; 2&#xD;]]&gt;" ++
            "<![CDATA[x]]]]><![CDATA[>y]]>" ++
            "<!-- c --><?tgt data?></p:r>",
        out,
    );
    // And it reads back to exactly what was written.
    var doc = try xml.parse(a, out, .{});
    defer doc.deinit();
    try testing.expectEqualStrings("urn:x&y", doc.root.uri);
    try testing.expectEqualStrings("<\"&\t\n\r>'", doc.root.attr("", "a").?);
    const tc = try doc.root.textContent(a);
    defer a.free(tc);
    try testing.expectEqualStrings("1 < 2 && 3 > 2\r]]>x]]>y", tc);
}

test "writer: every refusal" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var w: xml.Writer = .init(a, &aw.writer);
    defer w.deinit();
    try testing.expectError(error.InvalidName, w.startElement("1a"));
    try testing.expectError(error.InvalidName, w.startElement("a:b:c"));
    try testing.expectError(error.InvalidName, w.startElement(":a"));
    try testing.expectError(error.NotInStartTag, w.attribute("a", "v"));
    try testing.expectError(error.NotInStartTag, w.text("t"));
    try testing.expectError(error.Unbalanced, w.endElement());
    try testing.expectError(error.Unbalanced, w.end());
    try w.startElement("r");
    try testing.expectError(error.InvalidCharacter, w.attribute("a", "\x01"));
    try testing.expectError(error.InvalidName, w.namespace("a:b", "u"));
    try testing.expectError(error.InvalidCharacter, w.text("\xef\xbf\xbe")); // U+FFFE
    try testing.expectError(error.InvalidCharacter, w.text("\xff")); // not UTF-8
    try testing.expectError(error.InvalidComment, w.comment("a--b"));
    try testing.expectError(error.InvalidComment, w.comment("ends-"));
    try testing.expectError(error.InvalidPi, w.pi("XmL", "x"));
    try testing.expectError(error.InvalidPi, w.pi("t", "a?>b"));
    try w.text("ok");
    try testing.expectError(error.NotInStartTag, w.attribute("late", "v"));
    try testing.expectError(error.Unbalanced, w.end());
    try w.endElement();
    try w.end();
    // A second root is refused.
    try testing.expectError(error.NotInStartTag, w.startElement("again"));
}

test "writer: a deep tree is written without recursion" {
    const a = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    const depth = 250;
    for (0..depth) |_| try src.appendSlice(a, "<a>");
    for (0..depth) |_| try src.appendSlice(a, "</a>");
    var doc = try xml.parse(a, src.items, .{});
    defer doc.deinit();
    const out = try serialize(a, &doc);
    defer a.free(out);
    // <a>…<a/>…</a>: the innermost element is empty.
    try testing.expectEqual(@as(usize, 38 + (depth - 1) * 7 + 4), out.len);
}

// ── tests asked for by the 2026-10-04 mutation run ─────────────────────────

test "encodings: US-ASCII refuses any byte >= 0x80, even one that is valid UTF-8" {
    // US-ASCII is 7-bit: "é" as UTF-8 (C3 A9) is two bytes outside it.
    try testing.expectError(error.InvalidCharacter, xml.parse(testing.allocator, "<?xml version=\"1.0\" encoding=\"US-ASCII\"?><r>\xc3\xa9</r>", .{}));
}

test "writer: a name may not START with ':' either (namespace prefix, PI target)" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var w: xml.Writer = .init(a, &aw.writer);
    defer w.deinit();
    try w.startElement("r");
    try testing.expectError(error.InvalidName, w.namespace(":x", "u"));
    try testing.expectError(error.InvalidPi, w.pi(":t", ""));
}

test "entities: references to EMPTY text still spend the budget (no free fan-out)" {
    // z is "", y is ten z, x ten y, … : 10^6 references, zero bytes. Each
    // reference charges one unit, so the default 1 MiB budget is spent long
    // before the expansion finishes.
    var buf: [1024]u8 = undefined;
    var n: usize = 0;
    const head = "<!DOCTYPE r [<!ENTITY z \"\">";
    @memcpy(buf[0..head.len], head);
    n = head.len;
    const levels = "zyxwvut";
    for (1..levels.len) |i| {
        n += (try std.fmt.bufPrint(buf[n..], "<!ENTITY {c} \"", .{levels[i]})).len;
        for (0..10) |_| n += (try std.fmt.bufPrint(buf[n..], "&{c};", .{levels[i - 1]})).len;
        n += (try std.fmt.bufPrint(buf[n..], "\">", .{})).len;
    }
    n += (try std.fmt.bufPrint(buf[n..], "]><r>&t;</r>", .{})).len;
    try testing.expectError(error.EntityLimit, xml.parse(testing.allocator, buf[0..n], .{ .doctype = .internal_entities }));
    // Two levels (10 + 100 + 1 references, all empty) pass.
    const small = "<!DOCTYPE r [<!ENTITY z \"\"><!ENTITY y \"&z;&z;\">]><r>&y;</r>";
    var d = try xml.parse(testing.allocator, small, .{ .doctype = .internal_entities, .max_entity_expansion = 3 });
    d.deinit();
    try testing.expectError(error.EntityLimit, xml.parse(testing.allocator, small, .{ .doctype = .internal_entities, .max_entity_expansion = 2 }));
}

test "encodings: utf8_only refuses everything else" {
    const a = testing.allocator;
    try testing.expectError(error.UnsupportedEncoding, xml.parse(a, "\xff\xfe<\x00r\x00/\x00>\x00", .{ .utf8_only = true }));
    try testing.expectError(error.UnsupportedEncoding, xml.parse(a, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r/>", .{ .utf8_only = true }));
    var d = try xml.parse(a, "\xff\xfe<\x00r\x00/\x00>\x00", .{});
    d.deinit();
}
