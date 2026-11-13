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
    /// Deepest element nesting this will descend.
    ///
    /// `writeElement` recurses once per level on the machine stack, so the only
    /// thing that bounded it was the `xml.Options.max_depth` the DOCUMENT was
    /// parsed with -- and that is an explicitly supported knob, while `xml`'s
    /// own parser keeps its stack on the heap. Raising it is therefore safe for
    /// `xml` and fatal here. Measured in ReleaseFast on an 8 MiB stack: depth
    /// 32 000 canonicalizes, depth 36 000 is a SIGSEGV; in Debug the crash
    /// arrives between 4 000 and 8 000. `SPEC.md`'s "no input path panics" was
    /// false for any caller that raised the parser's limit.
    ///
    /// 256 matches `xml`'s own default, and is far past any real signature.
    max_depth: usize = 256,
    /// Largest canonical form this will produce, in bytes.
    ///
    /// Exclusive C14N re-renders a namespace declaration on EVERY element that
    /// utilizes the prefix when no output ancestor rendered it, so the output is
    /// not bounded by the input: one 100 KB `xmlns:p` URI on an element that
    /// does not use `p`, plus 8000 `<p:c/>` children (160 KB of input), is ~800 MB
    /// of canonical form. `max_elements` and `max_depth` bound the tree, not
    /// what it serializes to. Checked after every element, so the overshoot is
    /// one element's worth.
    max_output_len: usize = 64 << 20,
};

pub const Error = std.mem.Allocator.Error || error{ MaxDepthExceeded, OutputTooLarge };

/// Deterministic work counters (test seam, like `xml`'s `resolveNsCounted`):
/// a regression test pins the COMPLEXITY of the namespace bookkeeping with a
/// number instead of a stopwatch.
pub const Stats = struct {
    /// Entries inspected by `RenderedNs.lookup` (1 per call on the hashed path).
    lookup_probes: usize = 0,
    /// Calls of `considerExclusivePrefix`.
    prefix_considered: usize = 0,
    /// Test oracle: make every element walk the whole PrefixList, as the
    /// implementation did before 2026-11-13 (see `gatherNsExclusive`).
    full_list_scan: bool = false,
};

/// Canonicalize the subtree rooted at `root` and return freshly-allocated
/// UTF-8 bytes owned by the caller (`alloc`).
pub fn canonicalize(alloc: std.mem.Allocator, root: *const xml.Element, options: Options) Error![]u8 {
    return canonicalizeCounted(alloc, root, options, null);
}

fn canonicalizeCounted(alloc: std.mem.Allocator, root: *const xml.Element, options: Options, stats: ?*Stats) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var rendered: RenderedNs = .{ .stats = stats };
    defer rendered.deinit(alloc);

    // The PrefixList as a set: below the apex only a prefix DECLARED on the
    // element can be novel (see `gatherNsExclusive`), so the per-element cost is
    // the element's own declarations, not the list length.
    var prefix_set: std.StringHashMapUnmanaged(void) = .empty;
    defer prefix_set.deinit(alloc);
    var default_listed = false;
    if (options.mode.isExclusive()) {
        for (options.inclusive_prefixes) |p| {
            if (p.len == 0 or std.mem.eql(u8, p, "#default")) {
                default_listed = true;
            } else {
                try prefix_set.put(alloc, p, {});
            }
        }
    }

    var w: Writer = .{
        .alloc = alloc,
        .out = &out,
        .rendered = &rendered,
        .options = options,
        .prefix_set = &prefix_set,
        .default_listed = default_listed,
        .stats = stats,
    };
    try w.writeElement(root, 0, true);
    return out.toOwnedSlice(alloc);
}

// ── rendered-namespace stack ────────────────────────────────────────────────
// Tracks the namespace declarations already emitted along the current OUTPUT
// path, so both the exclusive novelty rule and the inclusive superfluous-drop
// rule can ask "what value (if any) is currently rendered for this prefix?".

const RenderedNs = struct {
    const Entry = struct {
        prefix: []const u8,
        uri: []const u8,
        depth: usize,
        /// The entry this one shadows (same prefix, nearer the root), if any.
        prev: ?usize,
    };
    entries: std.ArrayList(Entry) = .empty,
    /// prefix -> index of its topmost entry. A linear scan from the top made
    /// every lookup O(entries on the output path) = O(depth x declarations),
    /// and exclusive C14N does one lookup per attribute and per listed prefix.
    top: std.StringHashMapUnmanaged(usize) = .empty,
    stats: ?*Stats = null,

    fn deinit(self: *RenderedNs, alloc: std.mem.Allocator) void {
        self.entries.deinit(alloc);
        self.top.deinit(alloc);
    }

    /// Nearest currently-rendered URI for `prefix`, or null if none is in force.
    fn lookup(self: *const RenderedNs, prefix: []const u8) ?[]const u8 {
        if (self.stats) |st| st.lookup_probes += 1;
        const i = self.top.get(prefix) orelse return null;
        return self.entries.items[i].uri;
    }

    fn push(self: *RenderedNs, alloc: std.mem.Allocator, prefix: []const u8, uri: []const u8, depth: usize) !void {
        // Reserve first: an append that succeeds followed by a failing map put
        // would leave an entry the map does not know about.
        try self.top.ensureUnusedCapacity(alloc, 1);
        const idx = self.entries.items.len;
        try self.entries.append(alloc, .{ .prefix = prefix, .uri = uri, .depth = depth, .prev = self.top.get(prefix) });
        self.top.putAssumeCapacity(prefix, idx);
    }

    /// Drop every entry pushed at `depth` or deeper (called when leaving a node).
    fn popDepth(self: *RenderedNs, depth: usize) void {
        while (self.entries.items.len > 0 and
            self.entries.items[self.entries.items.len - 1].depth >= depth)
        {
            const e = self.entries.pop().?; // loop condition: non-empty
            if (e.prev) |pi| {
                self.top.putAssumeCapacity(e.prefix, pi); // key present: it was this entry's
            } else {
                _ = self.top.remove(e.prefix);
            }
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
    prefix_set: *const std.StringHashMapUnmanaged(void),
    default_listed: bool,
    stats: ?*Stats = null,

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
        // Bound the machine-stack recursion before descending, not after.
        if (depth > self.options.max_depth) return error.MaxDepthExceeded;
        // 1. Decide which namespace declarations to emit at this element.
        var ns_out: std.ArrayList(NsOut) = .empty;
        defer ns_out.deinit(self.alloc);
        if (self.options.mode.isExclusive()) {
            try self.gatherNsExclusive(el, is_apex, &ns_out);
        } else {
            try self.gatherNsInclusive(el, depth, is_apex, &ns_out);
        }
        // Sorted, then de-duplicated: the same prefix can be queued twice at one
        // element (several attributes using it), always with the same URI. A
        // membership test per queueing was O(queued) each, O(attributes^2) per
        // element.
        const n_ns = sortNs(ns_out.items);
        ns_out.shrinkRetainingCapacity(n_ns);

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
        if (self.out.items.len > self.options.max_output_len) return error.OutputTooLarge;

        // 4. Children in document order.
        for (el.children) |c| switch (c.content) {
            .element => |child| {
                if (self.options.omit) |om| {
                    if (child == om) continue; // enveloped-signature omission
                }
                try self.writeElement(child, depth + 1, false);
            },
            .text => |t| {
                try self.writeEscapedText(t);
                if (self.out.items.len > self.options.max_output_len) return error.OutputTooLarge;
            },
            .cdata => |t| {
                try self.writeCData(t);
                if (self.out.items.len > self.options.max_output_len) return error.OutputTooLarge;
            },
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
        if (self.out.items.len > self.options.max_output_len) return error.OutputTooLarge;

        // 6. Leave scope: discard the namespaces we rendered here.
        self.rendered.popDepth(depth);
    }

    // ── exclusive namespace rendering ───────────────────────────────────────
    fn gatherNsExclusive(self: *Writer, el: *const xml.Element, is_apex: bool, ns_out: *std.ArrayList(NsOut)) Error!void {
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
        //
        // Only the apex has to look at the whole list. Below it the parent (an
        // output element) already considered every listed prefix, so a listed
        // prefix this element does not DECLARE resolves exactly as it did there
        // and is already rendered with that value (or is unbound): it cannot be
        // novel. Walking the whole list per element made the cost
        // O(elements x list length), and the list is attacker-supplied.
        const scan_all = is_apex or (if (self.stats) |st| st.full_list_scan else false);
        if (scan_all) {
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
        } else {
            for (el.ns_decls) |d| {
                if (d.prefix.len == 0) {
                    if (self.default_listed and !default_handled) {
                        try self.considerExclusiveDefault(el, ns_out);
                        default_handled = true;
                    }
                } else if (self.prefix_set.contains(d.prefix)) {
                    try self.considerExclusivePrefix(el, d.prefix, ns_out);
                }
            }
        }
    }

    fn considerExclusivePrefix(self: *Writer, el: *const xml.Element, prefix: []const u8, ns_out: *std.ArrayList(NsOut)) Error!void {
        if (self.stats) |st| st.prefix_considered += 1;
        if (prefix.len == 0) return; // default handled separately
        if (std.mem.eql(u8, prefix, "xml")) return; // reserved, never declared
        const uri = el.resolveNs(prefix) orelse return;
        if (self.rendered.lookup(prefix)) |prev| {
            if (std.mem.eql(u8, prev, uri)) return; // already rendered, same value
        }
        try ns_out.append(self.alloc, .{ .prefix = prefix, .uri = uri });
    }

    fn considerExclusiveDefault(self: *Writer, el: *const xml.Element, ns_out: *std.ArrayList(NsOut)) Error!void {
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

/// Namespaces sort by prefix; the default declaration (empty prefix) sorts
/// first, then prefixes in ascending byte order. Returns the length after
/// dropping repeats of one prefix (always the same URI at one element).
fn sortNs(items: []NsOut) usize {
    std.mem.sort(NsOut, items, {}, struct {
        fn lt(_: void, a: NsOut, b: NsOut) bool {
            return std.mem.lessThan(u8, a.prefix, b.prefix);
        }
    }.lt);
    var n: usize = 0;
    for (items) |it| {
        if (n > 0 and std.mem.eql(u8, items[n - 1].prefix, it.prefix)) continue;
        items[n] = it;
        n += 1;
    }
    return n;
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
test "canonicalize: nesting past max_depth is a typed error, not a stack overflow" {
    // `writeElement` recurses on the machine stack. The only bound was the
    // `xml.Options.max_depth` the DOCUMENT was parsed with -- an explicitly
    // supported knob, and `xml`'s own parser keeps its stack on the heap, so
    // raising it is safe for `xml` and fatal here. Measured in ReleaseFast on
    // an 8 MiB stack before this bound: depth 32 000 canonicalized, depth
    // 36 000 was a SIGSEGV (exit 139); in Debug the crash arrived between
    // 4 000 and 8 000.
    //
    // Both directions are asserted: a document at the limit must still
    // canonicalize, or a bound of zero would pass the refusal half alone.
    const a = std.testing.allocator;
    const deep = 40;

    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    for (0..deep) |_| try src.appendSlice(a, "<a>");
    for (0..deep) |_| try src.appendSlice(a, "</a>");

    var doc = try xml.parse(a, src.items, .{ .max_depth = deep + 8 });
    defer doc.deinit();

    // At the limit: fine.
    const ok = try canonicalize(a, doc.root, .{ .mode = .exclusive, .max_depth = deep });
    defer a.free(ok);
    try std.testing.expect(ok.len > 0);

    // One level short of it: refused by name rather than by crashing.
    try std.testing.expectError(
        error.MaxDepthExceeded,
        canonicalize(a, doc.root, .{ .mode = .exclusive, .max_depth = deep - 2 }),
    );
}

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

// ── sweep 2026-11-13 (XDS) ──────────────────────────────────────────────────

fn parseOk(src: []const u8) !xml.Document {
    return xml.parse(testing.allocator, src, .{ .max_elements = 1 << 20 });
}

test "canonicalize: exclusive re-rendering of a big namespace URI is capped, not an OOM (sweep XDS-1)" {
    // One 100 KB xmlns:p URI on a root that does not use `p`, 8000 `<p:c/>`
    // children (~160 KB of input). Each child re-renders the declaration:
    // ~800 MB of canonical form without the cap.
    const a = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    try src.appendSlice(a, "<r xmlns:p=\"urn:");
    try src.appendNTimes(a, 'u', 100_000);
    try src.appendSlice(a, "\">");
    for (0..8000) |_| try src.appendSlice(a, "<p:c/>");
    try src.appendSlice(a, "</r>");
    var doc = try parseOk(src.items);
    defer doc.deinit();

    try testing.expectError(error.OutputTooLarge, canonicalize(a, doc.root, .{ .mode = .exclusive }));
    // The limit is the caller's: a small one trips early, a big one lets a
    // legitimate document through.
    try testing.expectError(error.OutputTooLarge, canonicalize(a, doc.root, .{ .mode = .exclusive, .max_output_len = 1 << 20 }));
    var small = try parseOk("<r xmlns:p=\"urn:x\"><p:c/><p:c/></r>");
    defer small.deinit();
    const ok = try canonicalize(a, small.root, .{ .mode = .exclusive, .max_output_len = 80 });
    defer a.free(ok);
    try testing.expectEqualStrings("<r><p:c xmlns:p=\"urn:x\"></p:c><p:c xmlns:p=\"urn:x\"></p:c></r>", ok);
    try testing.expectError(error.OutputTooLarge, canonicalize(a, small.root, .{ .mode = .exclusive, .max_output_len = ok.len - 1 }));
}

test "canonicalize: a long text run is counted against max_output_len (sweep XDS-1)" {
    const a = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    try src.appendSlice(a, "<r>");
    try src.appendNTimes(a, '\r', 1000); // CR -> &#xD;, 5x
    try src.appendSlice(a, "</r>");
    var doc = try parseOk(src.items);
    defer doc.deinit();
    const out = try canonicalize(a, doc.root, .{ .mode = .exclusive });
    defer a.free(out);
    try testing.expect(out.len > 1000);
    try testing.expectError(error.OutputTooLarge, canonicalize(a, doc.root, .{ .mode = .exclusive, .max_output_len = out.len - 1 }));
}

test "canonicalize: rendered-namespace lookups are O(1), not a scan of the output path (sweep XDS-2)" {
    // 40 nested ancestors, each rendering 25 junk prefixes (visibly utilized by
    // an attribute): ~1000 entries on the output path. The leaf then carries
    // 400 attributes in a prefix the root already rendered, one lookup each.
    // A scan from the top walks the junk for every one of them.
    const a = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    try src.appendSlice(a, "<p:r xmlns:p=\"urn:p\">");
    for (0..40) |i| {
        try src.print(a, "<a", .{});
        for (0..25) |j| try src.print(a, " xmlns:q{d}_{d}=\"urn:{d}_{d}\" q{d}_{d}:x=\"1\"", .{ i, j, i, j, i, j });
        try src.appendSlice(a, ">");
    }
    try src.appendSlice(a, "<leaf");
    for (0..400) |k| try src.print(a, " p:a{d}=\"1\"", .{k});
    try src.appendSlice(a, "/>");
    for (0..40) |_| try src.appendSlice(a, "</a>");
    try src.appendSlice(a, "</p:r>");
    var doc = try parseOk(src.items);
    defer doc.deinit();

    var st: Stats = .{};
    const out = try canonicalizeCounted(a, doc.root, .{ .mode = .exclusive }, &st);
    defer a.free(out);
    // One lookup per considered prefix; a scan would be ~400 x 1000 = 400 000.
    try testing.expect(st.lookup_probes < 4 * (400 + 40 * 26 * 2 + 10));
}

test "canonicalize: the PrefixList costs per apex and per declaration, not per element (sweep XDS-3)" {
    const a = testing.allocator;
    const p_n = 2000;
    const e_n = 2000;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    try src.appendSlice(a, "<r>");
    for (0..e_n) |_| try src.appendSlice(a, "<c/>");
    try src.appendSlice(a, "</r>");
    var doc = try parseOk(src.items);
    defer doc.deinit();
    var toks: std.ArrayList([]const u8) = .empty;
    defer toks.deinit(a);
    var names: std.ArrayList(u8) = .empty;
    defer names.deinit(a);
    for (0..p_n) |i| try names.print(a, "p{d} ", .{i});
    var it = std.mem.tokenizeScalar(u8, names.items, ' ');
    while (it.next()) |t| try toks.append(a, t);

    var st: Stats = .{};
    const out = try canonicalizeCounted(a, doc.root, .{ .mode = .exclusive, .inclusive_prefixes = toks.items }, &st);
    defer a.free(out);
    try testing.expect(st.prefix_considered <= p_n + 4 * e_n); // was p_n x e_n = 4 000 000
}

test "canonicalize: PrefixList below the apex only reacts to declarations on the element (sweep XDS-3)" {
    const src = "<p:r xmlns:p=\"urn:p\" xmlns:a=\"1\"><p:x xmlns:a=\"2\"><p:y xmlns:a=\"2\"/></p:x></p:r>";
    try expectC14n(src, "r", .{ .mode = .exclusive, .inclusive_prefixes = &.{"a"} }, "<p:r xmlns:a=\"1\" xmlns:p=\"urn:p\"><p:x xmlns:a=\"2\"><p:y></p:y></p:x></p:r>");
}

test "canonicalize: several attributes in one prefix declare it once (sweep XDS-2)" {
    try expectC14n("<e xmlns:p=\"urn:p\" p:a=\"1\" p:b=\"2\" p:c=\"3\"/>", "e", .{ .mode = .exclusive }, "<e xmlns:p=\"urn:p\" p:a=\"1\" p:b=\"2\" p:c=\"3\"></e>");
}

test "canonicalize: whole-list scan and per-declaration PrefixList agree on random documents (sweep XDS-3)" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC14_0001);
    const rnd = prng.random();
    const pf = [_][]const u8{ "a", "b", "c", "d" };
    var checked: usize = 0;
    for (0..600) |_| {
        var src: std.ArrayList(u8) = .empty;
        defer src.deinit(a);
        try src.appendSlice(a, "<a:r xmlns:a=\"u0\" xmlns:b=\"u1\" xmlns:c=\"u2\" xmlns:d=\"u3\" xmlns=\"ud\">");
        // A random tree, depth-first, as an explicit open stack.
        var open: usize = 0;
        var n: usize = 0;
        while (n < 30) : (n += 1) {
            const act = rnd.uintLessThan(u8, 4);
            if (act == 0 and open > 0) {
                try src.appendSlice(a, "</e>");
                open -= 1;
                continue;
            }
            try src.appendSlice(a, "<e");
            var used: [5]bool = @splat(false);
            // Declarations: a few of a-d and the default, values from a small pool.
            for (0..rnd.uintLessThan(usize, 4)) |_| {
                const k = rnd.uintLessThan(usize, 5);
                if (used[k]) continue;
                used[k] = true;
                if (k == 4) {
                    const v = rnd.uintLessThan(u8, 3);
                    if (v == 0) try src.appendSlice(a, " xmlns=\"\"") else try src.print(a, " xmlns=\"ud{d}\"", .{v});
                } else try src.print(a, " xmlns:{s}=\"u{d}\"", .{ pf[k], rnd.uintLessThan(u8, 3) });
            }
            for (0..rnd.uintLessThan(usize, 3)) |i| {
                try src.print(a, " {s}:t{d}=\"v\"", .{ pf[rnd.uintLessThan(usize, 4)], i });
            }
            if (rnd.boolean()) {
                try src.appendSlice(a, "/>");
            } else {
                try src.appendSlice(a, ">");
                open += 1;
            }
        }
        while (open > 0) : (open -= 1) try src.appendSlice(a, "</e>");
        try src.appendSlice(a, "</a:r>");

        var doc = xml.parse(a, src.items, .{}) catch continue;
        defer doc.deinit();
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(a);
        for ([_][]const u8{ "a", "b", "c", "d", "#default", "zz" }) |t| {
            if (rnd.boolean()) try list.append(a, t);
        }
        // The apex: the root, or a random first-level element.
        var apex: *const xml.Element = doc.root;
        if (rnd.boolean()) {
            for (doc.root.children) |c| switch (c.content) {
                .element => |e| {
                    apex = e;
                    break;
                },
                else => {},
            };
        }
        var fast: Stats = .{};
        var slow: Stats = .{ .full_list_scan = true };
        const o1 = try canonicalizeCounted(a, apex, .{ .mode = .exclusive, .inclusive_prefixes = list.items }, &fast);
        defer a.free(o1);
        const o2 = try canonicalizeCounted(a, apex, .{ .mode = .exclusive, .inclusive_prefixes = list.items }, &slow);
        defer a.free(o2);
        try testing.expectEqualStrings(o2, o1);
        checked += 1;
    }
    try testing.expect(checked > 300);
}
