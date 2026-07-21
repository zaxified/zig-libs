// SPDX-License-Identifier: MIT
//! c14n — XML Canonicalization over the `xml` infoset tree.
//!
//! Implements the two canonicalization families XML-Signature relies on, in
//! both the comment-stripping and comment-preserving variants:
//!
//!   * Exclusive XML Canonicalization 1.0 (W3C `xml-exc-c14n`) — the algorithm
//!     SAML uses. Namespace declarations are emitted only when *visibly
//!     utilized* by the element or one of its attributes and not already output
//!     by an ancestor with the same value. Supports the InclusiveNamespaces
//!     `PrefixList` parameter (listed prefixes are handled inclusively).
//!   * Canonical XML 1.0 (inclusive, W3C `xml-c14n` / RFC 3076) — the apex
//!     element receives the full in-scope namespace axis and inherited `xml:*`
//!     attributes; descendants drop superfluous namespace declarations.
//!
//! The node-set model is "the subtree rooted at an element, optionally with one
//! descendant element (and its subtree) omitted". That single omission is
//! exactly what the enveloped-signature transform needs (remove the enveloping
//! `ds:Signature`), and it keeps us clear of arbitrary XPath node-sets (an
//! attack surface we deliberately do not implement).
//!
//! Reference: W3C "Exclusive XML Canonicalization Version 1.0" and "Canonical
//! XML Version 1.0". The serialization rules (document order; namespaces sorted
//! by prefix and rendered before attributes; attributes sorted by
//! namespace-URI then local-name; the text/attribute escaping tables; empty
//! elements as explicit start+end tag pairs) are shared by both families.

const std = @import("std");
const xml = @import("xml");

pub const xml_ns = xml.xml_ns;

/// Which canonicalization algorithm to run.
pub const Mode = enum {
    /// Exclusive XML C14N 1.0 (`http://www.w3.org/2001/10/xml-exc-c14n#`).
    exclusive,
    /// Exclusive with comments (`…xml-exc-c14n#WithComments`).
    exclusive_with_comments,
    /// Canonical XML 1.0 (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`).
    inclusive,
    /// Canonical XML 1.0 with comments (`…-20010315#WithComments`).
    inclusive_with_comments,

    pub fn withComments(self: Mode) bool {
        return self == .exclusive_with_comments or self == .inclusive_with_comments;
    }
    pub fn isExclusive(self: Mode) bool {
        return self == .exclusive or self == .exclusive_with_comments;
    }
};

pub const Options = struct {
    mode: Mode,
    /// Exclusive-only: prefixes that must be handled inclusively (the
    /// InclusiveNamespaces `PrefixList`). A token of "" or "#default" forces the
    /// default namespace. Ignored by the inclusive modes.
    inclusive_prefixes: []const []const u8 = &.{},
    /// A descendant element to omit from the node-set together with its whole
    /// subtree (the enveloped-signature transform). `null` = canonicalize the
    /// entire subtree.
    omit: ?*const xml.Element = null,
};

pub const Error = std.mem.Allocator.Error;

/// Canonicalize the subtree rooted at `root` and return freshly-allocated
/// UTF-8 bytes owned by the caller (`alloc`).
pub fn canonicalize(alloc: std.mem.Allocator, root: *const xml.Element, options: Options) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var rendered: RenderedNs = .{};
    defer rendered.entries.deinit(alloc);

    var w: Writer = .{
        .alloc = alloc,
        .out = &out,
        .rendered = &rendered,
        .options = options,
    };
    try w.writeElement(root, 0, true);
    return out.toOwnedSlice(alloc);
}

// ── rendered-namespace stack ────────────────────────────────────────────────
// Tracks the namespace declarations already emitted along the current OUTPUT
// path, so both the exclusive novelty rule and the inclusive superfluous-drop
// rule can ask "what value (if any) is currently rendered for this prefix?".

const RenderedNs = struct {
    const Entry = struct { prefix: []const u8, uri: []const u8, depth: usize };
    entries: std.ArrayList(Entry) = .empty,

    /// Nearest currently-rendered URI for `prefix`, or null if none is in force.
    fn lookup(self: *const RenderedNs, prefix: []const u8) ?[]const u8 {
        var i = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.entries.items[i].prefix, prefix)) {
                return self.entries.items[i].uri;
            }
        }
        return null;
    }

    fn push(self: *RenderedNs, alloc: std.mem.Allocator, prefix: []const u8, uri: []const u8, depth: usize) !void {
        try self.entries.append(alloc, .{ .prefix = prefix, .uri = uri, .depth = depth });
    }

    /// Drop every entry pushed at `depth` or deeper (called when leaving a node).
    fn popDepth(self: *RenderedNs, depth: usize) void {
        while (self.entries.items.len > 0 and
            self.entries.items[self.entries.items.len - 1].depth >= depth)
        {
            _ = self.entries.pop();
        }
    }
};

// A namespace declaration queued for output at the current element.
const NsOut = struct { prefix: []const u8, uri: []const u8 };
// An attribute queued for output at the current element.
const AttrOut = struct { prefix: []const u8, local: []const u8, uri: []const u8, value: []const u8 };

const Writer = struct {
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    rendered: *RenderedNs,
    options: Options,

    fn raw(self: *Writer, s: []const u8) Error!void {
        try self.out.appendSlice(self.alloc, s);
    }

    fn writeQName(self: *Writer, prefix: []const u8, local: []const u8) Error!void {
        if (prefix.len != 0) {
            try self.raw(prefix);
            try self.raw(":");
        }
        try self.raw(local);
    }

    fn writeElement(self: *Writer, el: *const xml.Element, depth: usize, is_apex: bool) Error!void {
        // 1. Decide which namespace declarations to emit at this element.
        var ns_out: std.ArrayList(NsOut) = .empty;
        defer ns_out.deinit(self.alloc);
        if (self.options.mode.isExclusive()) {
            try self.gatherNsExclusive(el, depth, &ns_out);
        } else {
            try self.gatherNsInclusive(el, depth, is_apex, &ns_out);
        }
        sortNs(ns_out.items);

        // 2. Collect the attributes to emit (with inherited xml:* on the apex
        //    for inclusive canonicalization).
        var attrs: std.ArrayList(AttrOut) = .empty;
        defer attrs.deinit(self.alloc);
        for (el.attributes) |a| {
            try attrs.append(self.alloc, .{ .prefix = a.prefix, .local = a.local, .uri = a.uri, .value = a.value });
        }
        if (is_apex and !self.options.mode.isExclusive()) {
            try self.gatherInheritedXmlAttrs(el, &attrs);
        }
        sortAttrs(attrs.items);

        // 3. Start tag.
        try self.raw("<");
        try self.writeQName(el.prefix, el.local);
        for (ns_out.items) |n| {
            if (n.prefix.len == 0) {
                try self.raw(" xmlns=\"");
            } else {
                try self.raw(" xmlns:");
                try self.raw(n.prefix);
                try self.raw("=\"");
            }
            try self.writeEscapedAttr(n.uri);
            try self.raw("\"");
            try self.rendered.push(self.alloc, n.prefix, n.uri, depth);
        }
        for (attrs.items) |a| {
            try self.raw(" ");
            try self.writeQName(a.prefix, a.local);
            try self.raw("=\"");
            try self.writeEscapedAttr(a.value);
            try self.raw("\"");
        }
        try self.raw(">");

        // 4. Children in document order.
        for (el.children) |c| switch (c.content) {
            .element => |child| {
                if (self.options.omit) |om| {
                    if (child == om) continue; // enveloped-signature omission
                }
                try self.writeElement(child, depth + 1, false);
            },
            .text => |t| try self.writeEscapedText(t),
            .cdata => |t| try self.writeCData(t),
            .comment => |cm| if (self.options.mode.withComments()) {
                try self.raw("<!--");
                try self.raw(cm);
                try self.raw("-->");
            },
            .pi => |pi| {
                try self.raw("<?");
                try self.raw(pi.target);
                if (pi.data.len != 0) {
                    try self.raw(" ");
                    try self.raw(pi.data);
                }
                try self.raw("?>");
            },
        };

        // 5. Explicit end tag (empty elements are start+end, never self-closing).
        try self.raw("</");
        try self.writeQName(el.prefix, el.local);
        try self.raw(">");

        // 6. Leave scope: discard the namespaces we rendered here.
        self.rendered.popDepth(depth);
    }

    // ── exclusive namespace rendering ───────────────────────────────────────
    fn gatherNsExclusive(self: *Writer, el: *const xml.Element, depth: usize, ns_out: *std.ArrayList(NsOut)) Error!void {
        _ = depth;
        // Default namespace: visibly utilized iff the element itself has no
        // prefix. Attributes never utilize the default namespace.
        var default_handled = false;
        if (el.prefix.len == 0) {
            try self.considerExclusiveDefault(el, ns_out);
            default_handled = true;
        }

        // Prefixed visibly-utilized namespaces: the element's own prefix plus
        // every prefixed attribute's prefix (excluding the reserved `xml`,
        // which is never declared).
        try self.considerExclusivePrefix(el, el.prefix, ns_out);
        for (el.attributes) |a| {
            try self.considerExclusivePrefix(el, a.prefix, ns_out);
        }

        // InclusiveNamespaces PrefixList: listed prefixes are handled
        // inclusively — rendered whenever in scope and novel, even if not
        // visibly utilized here.
        for (self.options.inclusive_prefixes) |p| {
            if (p.len == 0 or std.mem.eql(u8, p, "#default")) {
                if (!default_handled) {
                    try self.considerExclusiveDefault(el, ns_out);
                    default_handled = true;
                }
            } else {
                try self.considerExclusivePrefix(el, p, ns_out);
            }
        }
    }

    fn considerExclusivePrefix(self: *Writer, el: *const xml.Element, prefix: []const u8, ns_out: *std.ArrayList(NsOut)) Error!void {
        if (prefix.len == 0) return; // default handled separately
        if (std.mem.eql(u8, prefix, "xml")) return; // reserved, never declared
        if (containsNs(ns_out.items, prefix)) return; // already queued here
        const uri = el.resolveNs(prefix) orelse return;
        if (self.rendered.lookup(prefix)) |prev| {
            if (std.mem.eql(u8, prev, uri)) return; // already rendered, same value
        }
        try ns_out.append(self.alloc, .{ .prefix = prefix, .uri = uri });
    }

    fn considerExclusiveDefault(self: *Writer, el: *const xml.Element, ns_out: *std.ArrayList(NsOut)) Error!void {
        if (containsNs(ns_out.items, "")) return;
        const uri = el.resolveNs("") orelse "";
        const prev = self.rendered.lookup("");
        if (uri.len == 0) {
            // Element is in no namespace: only emit xmlns="" to *undeclare* a
            // non-empty default that an output ancestor rendered.
            if (prev) |p| {
                if (p.len != 0) try ns_out.append(self.alloc, .{ .prefix = "", .uri = "" });
            }
        } else {
            if (prev) |p| {
                if (std.mem.eql(u8, p, uri)) return;
            }
            try ns_out.append(self.alloc, .{ .prefix = "", .uri = uri });
        }
    }

    // ── inclusive namespace rendering ───────────────────────────────────────
    fn gatherNsInclusive(self: *Writer, el: *const xml.Element, depth: usize, is_apex: bool, ns_out: *std.ArrayList(NsOut)) Error!void {
        _ = depth;
        if (is_apex) {
            // Apex renders the full in-scope namespace axis (nearest wins;
            // undeclared default omitted).
            const axis = try el.inScopeNamespaces(self.alloc);
            defer self.alloc.free(axis);
            for (axis) |d| try ns_out.append(self.alloc, .{ .prefix = d.prefix, .uri = d.uri });
            return;
        }
        // Descendants: only the declarations made ON this element can change the
        // rendered context; emit each unless it repeats the inherited value.
        for (el.ns_decls) |d| {
            if (d.prefix.len == 0 and d.uri.len == 0) {
                // Default undeclaration: emit only if a non-empty default is in
                // force in the output.
                if (self.rendered.lookup("")) |prev| {
                    if (prev.len != 0) try ns_out.append(self.alloc, .{ .prefix = "", .uri = "" });
                }
                continue;
            }
            if (self.rendered.lookup(d.prefix)) |prev| {
                if (std.mem.eql(u8, prev, d.uri)) continue; // superfluous
            }
            try ns_out.append(self.alloc, .{ .prefix = d.prefix, .uri = d.uri });
        }
    }

    /// Inclusive C14N copies in-scope `xml:*` attributes (from ancestors above
    /// the apex) onto the apex element, unless the apex overrides them.
    fn gatherInheritedXmlAttrs(self: *Writer, apex: *const xml.Element, attrs: *std.ArrayList(AttrOut)) Error!void {
        const names = [_][]const u8{ "base", "lang", "space" };
        for (names) |nm| {
            // Skip if the apex already carries this xml:* attribute.
            var on_apex = false;
            for (apex.attributes) |a| {
                if (std.mem.eql(u8, a.uri, xml_ns) and std.mem.eql(u8, a.local, nm)) {
                    on_apex = true;
                    break;
                }
            }
            if (on_apex) continue;
            // Nearest ancestor value wins.
            var cur = apex.parent;
            while (cur) |anc| : (cur = anc.parent) {
                var found: ?[]const u8 = null;
                for (anc.attributes) |a| {
                    if (std.mem.eql(u8, a.uri, xml_ns) and std.mem.eql(u8, a.local, nm)) {
                        found = a.value;
                        break;
                    }
                }
                if (found) |v| {
                    try attrs.append(self.alloc, .{ .prefix = "xml", .local = nm, .uri = xml_ns, .value = v });
                    break;
                }
            }
        }
    }

    // ── escaping ────────────────────────────────────────────────────────────
    /// Text node escaping: `&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;`, CR→`&#xD;`.
    fn writeEscapedText(self: *Writer, s: []const u8) Error!void {
        for (s) |c| switch (c) {
            '&' => try self.raw("&amp;"),
            '<' => try self.raw("&lt;"),
            '>' => try self.raw("&gt;"),
            '\r' => try self.raw("&#xD;"),
            else => try self.out.append(self.alloc, c),
        };
    }

    /// A CDATA section is replaced by its (line-ending-normalized) content and
    /// then escaped exactly like a text node.
    fn writeCData(self: *Writer, s: []const u8) Error!void {
        var i: usize = 0;
        while (i < s.len) : (i += 1) {
            const c = s[i];
            if (c == '\r') {
                // \r\n and lone \r → \n (XML §2.11 line-ending normalization).
                try self.out.append(self.alloc, '\n');
                if (i + 1 < s.len and s[i + 1] == '\n') i += 1;
                continue;
            }
            switch (c) {
                '&' => try self.raw("&amp;"),
                '<' => try self.raw("&lt;"),
                '>' => try self.raw("&gt;"),
                else => try self.out.append(self.alloc, c),
            }
        }
    }

    /// Attribute value escaping: `&`→`&amp;`, `<`→`&lt;`, `"`→`&quot;`,
    /// TAB→`&#x9;`, LF→`&#xA;`, CR→`&#xD;`. (`>` is NOT escaped in attributes.)
    fn writeEscapedAttr(self: *Writer, s: []const u8) Error!void {
        for (s) |c| switch (c) {
            '&' => try self.raw("&amp;"),
            '<' => try self.raw("&lt;"),
            '"' => try self.raw("&quot;"),
            '\t' => try self.raw("&#x9;"),
            '\n' => try self.raw("&#xA;"),
            '\r' => try self.raw("&#xD;"),
            else => try self.out.append(self.alloc, c),
        };
    }
};

fn containsNs(items: []const NsOut, prefix: []const u8) bool {
    for (items) |n| if (std.mem.eql(u8, n.prefix, prefix)) return true;
    return false;
}

/// Namespaces sort by prefix; the default declaration (empty prefix) sorts
/// first, then prefixes in ascending byte order.
fn sortNs(items: []NsOut) void {
    std.mem.sort(NsOut, items, {}, struct {
        fn lt(_: void, a: NsOut, b: NsOut) bool {
            return std.mem.lessThan(u8, a.prefix, b.prefix);
        }
    }.lt);
}

/// Attributes sort by namespace URI, then by local name. Unprefixed (no
/// namespace) attributes carry URI "" and therefore sort first.
fn sortAttrs(items: []AttrOut) void {
    std.mem.sort(AttrOut, items, {}, struct {
        fn lt(_: void, a: AttrOut, b: AttrOut) bool {
            if (!std.mem.eql(u8, a.uri, b.uri)) return std.mem.lessThan(u8, a.uri, b.uri);
            return std.mem.lessThan(u8, a.local, b.local);
        }
    }.lt);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Parse `src`, find the element with local name `local`, canonicalize its
/// subtree and assert the exact bytes.
fn expectC14n(src: []const u8, local: []const u8, opts: Options, expected: []const u8) !void {
    var doc = try xml.parse(testing.allocator, src, .{});
    defer doc.deinit();
    const el = findLocal(doc.root, local) orelse return error.NotFound;
    const got = try canonicalize(testing.allocator, el, opts);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

fn findLocal(el: *xml.Element, local: []const u8) ?*xml.Element {
    if (std.mem.eql(u8, el.local, local)) return el;
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (findLocal(child, local)) |f| return f;
        },
        else => {},
    };
    return null;
}

// Exclusive C14N spec (§2.3, Example 1): the ancestor n0 namespace is NOT
// visibly utilized by elem1, so it is pruned.  [W3C xml-exc-c14n]
test "exc-c14n W3C example 1: visibly-utilized pruning" {
    const src =
        "<n0:pdu xmlns:n0=\"http://a.example\">\n" ++
        "   <n1:elem1 xmlns:n1=\"http://b.example\">\n" ++
        "       content\n" ++
        "   </n1:elem1>\n" ++
        "</n0:pdu>";
    const expected =
        "<n1:elem1 xmlns:n1=\"http://b.example\">\n" ++
        "       content\n" ++
        "   </n1:elem1>";
    try expectC14n(src, "elem1", .{ .mode = .exclusive }, expected);
}

// Inclusive C14N over the SAME subtree DOES pull in the ancestor n0 namespace
// (full in-scope axis at the apex).  [W3C xml-c14n / xml-exc-c14n example 1]
test "c14n W3C example 1 (inclusive): ancestor namespace retained" {
    const src =
        "<n0:pdu xmlns:n0=\"http://a.example\">\n" ++
        "   <n1:elem1 xmlns:n1=\"http://b.example\">\n" ++
        "       content\n" ++
        "   </n1:elem1>\n" ++
        "</n0:pdu>";
    const expected =
        "<n1:elem1 xmlns:n0=\"http://a.example\" xmlns:n1=\"http://b.example\">\n" ++
        "       content\n" ++
        "   </n1:elem1>";
    try expectC14n(src, "elem1", .{ .mode = .inclusive }, expected);
}

// Exclusive C14N spec (§2.3, Example 2): elem2 renders only n1 (utilized) and
// keeps its own xml:lang; the ancestor n2 / xml:lang="fr" are dropped; n3:stuff
// renders n3 (utilized).  [W3C xml-exc-c14n]
test "exc-c14n W3C example 2: utilized-only, xml:lang not inherited" {
    const src =
        "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\"" ++
        " xml:lang=\"fr\" xml:space=\"retain\">\n" ++
        "   <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n" ++
        "       <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n" ++
        "   </n1:elem2>\n" ++
        "</n2:pdu>";
    const expected =
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n" ++
        "       <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n" ++
        "   </n1:elem2>";
    try expectC14n(src, "elem2", .{ .mode = .exclusive }, expected);
}

// Inclusive C14N spec example 2 (first context): the apex gets the full axis
// (n0,n1,n3) and xml:lang; the redundant n3 declaration on n3:stuff is dropped
// as superfluous.  [W3C xml-exc-c14n example 2, "Canonical XML" column]
test "c14n example 2 (inclusive): full axis + superfluous namespace drop" {
    const src =
        "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">\n" ++
        "   <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n" ++
        "       <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n" ++
        "   </n1:elem2>\n" ++
        "</n0:local>";
    const expected =
        "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" xml:lang=\"en\">\n" ++
        "       <n3:stuff></n3:stuff>\n" ++
        "   </n1:elem2>";
    try expectC14n(src, "elem2", .{ .mode = .inclusive }, expected);
}

// Canonical XML 1.0 spec §3.3: namespace declarations sorted before attributes
// (default first, then by prefix); attributes sorted by (URI, local); empty
// element becomes an explicit start+end tag.  [W3C xml-c14n §3.3]
test "c14n §3.3: attribute and namespace ordering" {
    const src =
        "<e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"" ++
        " xmlns:b=\"http://www.ietf.org\"" ++
        " xmlns:a=\"http://www.w3.org\"" ++
        " xmlns=\"http://example.org\"/>";
    const expected =
        "<e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\"" ++
        " attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>";
    try expectC14n(src, "e5", .{ .mode = .inclusive }, expected);
}

// Canonical XML 1.0 spec §3.3: nested default-namespace (re)declaration and
// superfluous-declaration removal.  [W3C xml-c14n §3.3, elements e6-e8]
test "c14n §3.3: nested default namespace redeclaration" {
    const src =
        "<e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n" ++
        "   <e7 xmlns=\"http://www.ietf.org\">\n" ++
        "      <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">x</e8>\n" ++
        "   </e7>\n" ++
        "</e6>";
    const expected =
        "<e6 xmlns:a=\"http://www.w3.org\">\n" ++
        "   <e7 xmlns=\"http://www.ietf.org\">\n" ++
        "      <e8 xmlns=\"\">x</e8>\n" ++
        "   </e7>\n" ++
        "</e6>";
    try expectC14n(src, "e6", .{ .mode = .inclusive }, expected);
}

// Canonical XML 1.0 spec §3.2: content whitespace is preserved verbatim.
// [W3C xml-c14n §3.2]
test "c14n §3.2: whitespace in document content preserved" {
    const src =
        "<doc>\n" ++
        "      <clean>   </clean>\n" ++
        "      <dirty>   A   B   </dirty>\n" ++
        "      <mixed>\n" ++
        "         A\n" ++
        "         <clean>   </clean>\n" ++
        "         B\n" ++
        "         <dirty>   A   B   </dirty>\n" ++
        "         C\n" ++
        "      </mixed>\n" ++
        "   </doc>";
    // Canonical form is identical to the input body (no namespaces present).
    try expectC14n(src, "doc", .{ .mode = .inclusive }, src);
}

// Canonical XML 1.0 spec §3.4: text escaping (& < > and CR→&#xD;), numeric
// character references, CDATA→text, and attribute-value escaping including the
// TAB/LF/CR control references. (DTD-typed normalization is out of scope, so
// the DTD-dependent normNames/normId rows of the spec example are omitted.)
// [W3C xml-c14n §3.4]
test "c14n §3.4: character modifications and references" {
    const src =
        "<doc>\n" ++
        "      <text>First line&#x0d;&#10;Second line</text>\n" ++
        "      <value>&#x32;</value>\n" ++
        "      <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n" ++
        "      <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n" ++
        "      <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n" ++
        "   </doc>";
    const expected =
        "<doc>\n" ++
        "      <text>First line&#xD;\nSecond line</text>\n" ++
        "      <value>2</value>\n" ++
        "      <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n" ++
        "      <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n" ++
        "      <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n" ++
        "   </doc>";
    try expectC14n(src, "doc", .{ .mode = .inclusive }, expected);
}

test "exc-c14n InclusiveNamespaces: listed prefix forced inclusively" {
    // n0 is not visibly utilized by elem1, but naming it in the PrefixList
    // forces it to be rendered (inclusive handling).
    const src =
        "<n0:pdu xmlns:n0=\"http://a.example\">" ++
        "<n1:elem1 xmlns:n1=\"http://b.example\">x</n1:elem1>" ++
        "</n0:pdu>";
    const expected =
        "<n1:elem1 xmlns:n0=\"http://a.example\" xmlns:n1=\"http://b.example\">x</n1:elem1>";
    try expectC14n(src, "elem1", .{ .mode = .exclusive, .inclusive_prefixes = &.{"n0"} }, expected);
}

test "with-comments vs default: comment inclusion toggles" {
    const src = "<a><!-- keep me -->text</a>";
    try expectC14n(src, "a", .{ .mode = .inclusive }, "<a>text</a>");
    try expectC14n(src, "a", .{ .mode = .inclusive_with_comments }, "<a><!-- keep me -->text</a>");
}

test "processing instruction serialization" {
    const src = "<a><?target some data?><?bare?></a>";
    try expectC14n(src, "a", .{ .mode = .exclusive }, "<a><?target some data?><?bare?></a>");
}

test "omit subtree: enveloped-signature-style removal" {
    const src = "<a xmlns=\"urn:x\"><b/><sig>SIG</sig><c/></a>";
    var doc = try xml.parse(testing.allocator, src, .{});
    defer doc.deinit();
    const sig = findLocal(doc.root, "sig").?;
    const got = try canonicalize(testing.allocator, doc.root, .{ .mode = .exclusive, .omit = sig });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        "<a xmlns=\"urn:x\"><b></b><c></c></a>",
        got,
    );
}

test "exclusive default-namespace undeclaration across output ancestor" {
    // Child leaves the default namespace; exclusive C14N must emit xmlns="" to
    // undeclare the parent's default that IS rendered in the output.
    const src = "<p xmlns=\"urn:p\"><c xmlns=\"\">t</c></p>";
    try expectC14n(src, "p", .{ .mode = .exclusive }, "<p xmlns=\"urn:p\"><c xmlns=\"\">t</c></p>");
}

test "inclusive apex inherits xml:lang from ancestor outside subtree" {
    const src = "<r xml:lang=\"en\"><child>t</child></r>";
    // Canonicalizing <child> alone (inclusive) copies the ancestor xml:lang.
    try expectC14n(src, "child", .{ .mode = .inclusive }, "<child xml:lang=\"en\">t</child>");
}
