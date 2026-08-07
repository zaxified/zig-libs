// SPDX-License-Identifier: MIT
//! xml — namespace-aware, security-hardened XML 1.0 parser producing a
//! canonicalization-ready infoset tree.
//!
//! This module is the foundation of a SAML / XML-DSig cluster: the tree it
//! produces preserves exactly the information that Canonical XML (C14N /
//! exclusive C14N) and XML-Signature reference resolution need — qualified
//! names with resolved namespace URIs, the ORIGINAL namespace prefixes, raw
//! attribute order, comments, PIs, document order, and per-node byte spans.
//!
//! Threat model: input comes from an untrusted external IdP. Hardening is a
//! primary requirement, not optional — see SPEC.md. In one line: no external
//! entities / no external DTD fetch (XXE-proof), no user-defined general
//! entities (billion-laughs-proof), DOCTYPE rejected by default, bounded
//! nesting depth, bounded attribute counts, typed errors, never panics.
//!
//! Reference: W3C "Extensible Markup Language (XML) 1.0 (Fifth Edition)" +
//! "Namespaces in XML 1.0 (Third Edition)". NOT a validating parser (no DTD
//! content-model validation); no XML 1.1; no XPath; UTF-8 only.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "W3C XML 1.0 (5th ed.) + Namespaces in XML 1.0; hardened per OWASP XXE guidance",
    .deps = .{},
};

// ── namespace constants ─────────────────────────────────────────────────────

/// The reserved `xml` prefix is implicitly bound to this URI (Namespaces §3).
pub const xml_ns = "http://www.w3.org/XML/1998/namespace";
/// The reserved `xmlns` prefix is implicitly bound to this URI.
pub const xmlns_ns = "http://www.w3.org/2000/xmlns/";

// ── tree types ──────────────────────────────────────────────────────────────

/// Byte range `[start, end)` of a node in the ORIGINAL source document.
/// For an element this spans from its opening `<` to just past the `>` that
/// closes it (the `/>` of an empty element, or the `>` of its end-tag). Lets
/// the xmldsig layer locate / raw-slice a specific subtree.
pub const Span = struct {
    start: usize,
    end: usize,

    pub fn slice(self: Span, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

/// A namespace declaration (`xmlns=...` or `xmlns:prefix=...`) that appears
/// literally ON an element. `prefix` is "" for the default-namespace
/// declaration (`xmlns=...`). `uri` may be "" only for the default declaration
/// `xmlns=""` (undeclaring the default namespace).
pub const NsDecl = struct {
    prefix: []const u8,
    uri: []const u8,
};

/// A non-namespace attribute. `prefix`/`local` are the original lexical parts;
/// `uri` is the resolved namespace ("" = no namespace — unprefixed attributes
/// are NEVER in the default namespace, per Namespaces §6.2). `value` is the
/// entity-expanded, XML-attribute-normalized value. `span` covers the whole
/// `name="value"` in the source.
pub const Attribute = struct {
    prefix: []const u8,
    local: []const u8,
    uri: []const u8,
    value: []const u8,
    span: Span,
};

/// A processing instruction `<?target data?>`.
pub const Pi = struct {
    target: []const u8,
    data: []const u8,
};

/// One child node, tagged by kind, in document order. Text nodes carry the
/// entity-expanded, line-ending-normalized character content; CDATA carries
/// verbatim content (no entity expansion) but is otherwise a text node for
/// C14N purposes. Comments and PIs are preserved so both with-comments and
/// without-comments C14N modes are expressible.
pub const Child = struct {
    content: Content,
    span: Span,

    pub const Content = union(enum) {
        element: *Element,
        text: []const u8,
        cdata: []const u8,
        comment: []const u8,
        pi: Pi,
    };
};

/// The namespace bindings in force at an element, as a chain that skips every
/// ancestor which declares nothing. The parser links one of these onto each
/// element so `resolveNs` — a PUBLIC entry point that `c14n`/`xmldsig` call
/// once per attribute — does not have to rescan the parent axis element by
/// element and declaration by declaration.
///
/// Two things make the chain cheap:
///  - an element that declares no namespace SHARES its parent's scope, so a
///    subtree nested 4000 deep under a root that declares `p` is one hop from
///    the binding, not 4000;
///  - an element carrying more than `dup_scan_threshold` declarations gets a
///    prefix index, so the per-level scan is a probe rather than a walk.
///
/// It answers exactly what the parent-axis walk answers, in the same
/// nearest-declaration-wins order: a prefix declared twice on one element is
/// rejected at parse, so each level holds at most one binding per prefix.
pub const NsScope = struct {
    /// Declarations made literally on the element that introduced this scope.
    decls: []const NsDecl,
    /// prefix → uri over `decls`, built only when `decls` is long enough that
    /// scanning it would dominate. Null means "scan `decls`".
    index: ?*const PrefixIndex = null,
    /// Scope of the nearest ancestor that declares any namespace.
    outer: ?*const NsScope = null,

    pub const PrefixIndex = std.StringHashMapUnmanaged([]const u8);
};

/// The scope of an element that declares nothing and has no declaring
/// ancestor. Shared, so "no namespaces anywhere" costs no allocation — and so
/// `Element.ns_scope == null` means unambiguously "not computed".
const empty_ns_scope: NsScope = .{ .decls = &.{} };

/// An element node. Preserves the original prefix, the resolved namespace URI,
/// the namespace declarations made on this element, all attributes in original
/// order, and children in document order. `parent` enables the inherited
/// namespace axis needed by inclusive C14N and prefix resolution.
pub const Element = struct {
    prefix: []const u8,
    local: []const u8,
    uri: []const u8,
    ns_decls: []const NsDecl,
    attributes: []const Attribute,
    children: []const Child,
    parent: ?*Element,
    span: Span,
    /// Accelerator for `resolveNs`, owned by the Document's arena. The parser
    /// sets it on every element it builds. `null` means "not computed" — a
    /// hand-assembled tree keeps working, on the plain parent-axis walk.
    ns_scope: ?*const NsScope = null,

    /// Resolve a namespace prefix to a URI using the in-scope namespaces at
    /// this element (nearest declaration wins).
    /// - `"xml"` and `"xmlns"` resolve to their reserved URIs.
    /// - The default prefix `""` resolves to the in-scope default namespace, or
    ///   "" (no namespace) when none is in scope. So a "" result for `""` means
    ///   "no namespace", never "unresolved".
    /// - Any other prefix returns null when not declared anywhere in scope.
    pub fn resolveNs(self: *const Element, prefix: []const u8) ?[]const u8 {
        var probes: usize = 0;
        return self.resolveNsCounted(prefix, &probes);
    }

    /// `resolveNs`, with a work counter. Test-only seam, exactly like
    /// `parseCounted`: it lets a regression test pin the *complexity* of
    /// prefix resolution with a deterministic number instead of a stopwatch.
    /// One probe = one prefix comparison on the scan path, or one hash lookup
    /// on the indexed path.
    fn resolveNsCounted(self: *const Element, prefix: []const u8, probes: *usize) ?[]const u8 {
        if (std.mem.eql(u8, prefix, "xml")) return xml_ns;
        if (std.mem.eql(u8, prefix, "xmlns")) return xmlns_ns;
        if (self.ns_scope) |scope| {
            var cur: ?*const NsScope = scope;
            while (cur) |s| : (cur = s.outer) {
                probes.* += 1;
                if (s.index) |ix| {
                    // "" uri for a prefixed decl can't happen (rejected at
                    // parse). For the default prefix, "" means undeclared.
                    if (ix.get(prefix)) |uri| return uri;
                } else {
                    for (s.decls) |d| {
                        probes.* += 1;
                        if (std.mem.eql(u8, d.prefix, prefix)) return d.uri;
                    }
                }
            }
        } else {
            var cur: ?*const Element = self;
            while (cur) |el| : (cur = el.parent) {
                probes.* += 1;
                for (el.ns_decls) |d| {
                    probes.* += 1;
                    if (std.mem.eql(u8, d.prefix, prefix)) return d.uri;
                }
            }
        }
        if (prefix.len == 0) return ""; // default namespace absent = no namespace
        return null;
    }

    /// Collect every namespace binding in scope at this element (the inherited
    /// namespace axis for inclusive C14N), nearest-declaration-wins. The
    /// default namespace is included only when it is actually in force (a
    /// `xmlns=""` that undeclares it is not emitted). Result is owned by the
    /// caller-supplied allocator. Order is arbitrary; C14N sorts by prefix
    /// itself.
    pub fn inScopeNamespaces(self: *const Element, alloc: std.mem.Allocator) ![]NsDecl {
        var out: std.ArrayList(NsDecl) = .empty;
        errdefer out.deinit(alloc);
        var cur: ?*const Element = self;
        while (cur) |el| : (cur = el.parent) {
            for (el.ns_decls) |d| {
                var seen = false;
                for (out.items) |o| {
                    if (std.mem.eql(u8, o.prefix, d.prefix)) {
                        seen = true;
                        break;
                    }
                }
                if (seen) continue; // a nearer declaration already won
                if (d.prefix.len == 0 and d.uri.len == 0) continue; // undeclared default
                try out.append(alloc, d);
            }
        }
        return out.toOwnedSlice(alloc);
    }

    /// Value of the attribute with the given namespace URI and local name, or
    /// null. Use `uri == ""` for a no-namespace (unprefixed) attribute.
    pub fn attr(self: *const Element, uri: []const u8, local: []const u8) ?[]const u8 {
        for (self.attributes) |a| {
            if (std.mem.eql(u8, a.uri, uri) and std.mem.eql(u8, a.local, local)) return a.value;
        }
        return null;
    }

    /// Iterator over child elements only (skips text/comment/PI), in order.
    pub fn elementIterator(self: *const Element) ElementIterator {
        return .{ .children = self.children };
    }

    /// First child element, or null.
    pub fn firstElementChild(self: *const Element) ?*Element {
        var it = self.elementIterator();
        return it.next();
    }

    /// Concatenated text content of this element's subtree (text + CDATA of all
    /// descendants, in document order). Result owned by the caller allocator.
    pub fn textContent(self: *const Element, alloc: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        try appendTextContent(self, alloc, &out);
        return out.toOwnedSlice(alloc);
    }

    fn appendTextContent(self: *const Element, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        for (self.children) |c| switch (c.content) {
            .text => |t| try out.appendSlice(alloc, t),
            .cdata => |t| try out.appendSlice(alloc, t),
            .element => |e| try appendTextContent(e, alloc, out),
            .comment, .pi => {},
        };
    }
};

pub const ElementIterator = struct {
    children: []const Child,
    idx: usize = 0,

    pub fn next(self: *ElementIterator) ?*Element {
        while (self.idx < self.children.len) {
            const c = self.children[self.idx];
            self.idx += 1;
            switch (c.content) {
                .element => |e| return e,
                else => {},
            }
        }
        return null;
    }
};

/// A parsed document. Owns all node memory via an internal arena; `deinit`
/// frees the whole tree at once (arena-per-document — subtrees stay valid for
/// the life of the Document, which is exactly what a C14N pass over a subtree
/// needs).
pub const Document = struct {
    arena: std.heap.ArenaAllocator,
    source: []const u8,
    root: *Element,
    /// Comments/PIs before the root element (document prolog misc), in order.
    prolog: []const Child,
    /// Comments/PIs after the root element (document epilog misc), in order.
    epilog: []const Child,
    /// From the XML declaration, if present. `encoding` is "" when unspecified.
    version: []const u8,
    encoding: []const u8,
    standalone: ?bool,
    ids: std.StringHashMapUnmanaged(*Element),

    pub fn deinit(self: *Document) void {
        self.arena.deinit();
    }

    /// Look up an element by its ID value. An attribute is treated as an ID if
    /// it is `xml:id` (the xml-namespace `id`) or its unqualified local name is
    /// one of `Options.id_attr_names` (default `ID`/`Id`/`id`). First match in
    /// document order wins. The xmldsig layer resolving `URI="#foo"` uses this;
    /// for signature-wrapping-safe lookup it may prefer `findByAttr` with the
    /// exact ID attribute name it expects.
    pub fn getElementById(self: *const Document, id: []const u8) ?*Element {
        return self.ids.get(id);
    }

    /// Depth-first search for the first element carrying an attribute
    /// (`uri`,`local`) equal to `value`. `uri == ""` matches an unprefixed
    /// attribute. Gives the dsig layer full control over which attribute is the
    /// ID, independent of the ID heuristic.
    pub fn findByAttr(self: *const Document, uri: []const u8, local: []const u8, value: []const u8) ?*Element {
        return findByAttrRec(self.root, uri, local, value);
    }

    fn findByAttrRec(el: *Element, uri: []const u8, local: []const u8, value: []const u8) ?*Element {
        if (el.attr(uri, local)) |v| {
            if (std.mem.eql(u8, v, value)) return el;
        }
        for (el.children) |c| switch (c.content) {
            .element => |child| {
                if (findByAttrRec(child, uri, local, value)) |found| return found;
            },
            else => {},
        };
        return null;
    }
};

// ── options & errors ────────────────────────────────────────────────────────

pub const DoctypePolicy = enum {
    /// Reject any `<!DOCTYPE ...>` with error.DoctypeForbidden (default, safest
    /// — an external subset can never even be looked at).
    reject,
    /// Skip the DOCTYPE (including any internal subset) WITHOUT parsing it: no
    /// entity declarations are honored, no external subset is fetched. Any
    /// later reference to a non-predefined entity therefore fails with
    /// error.UndefinedEntity. Still XXE- and billion-laughs-proof.
    ignore,
};

pub const Options = struct {
    /// Maximum element nesting depth (root = depth 1). Guards against stack /
    /// resource exhaustion from adversarial nesting.
    max_depth: usize = 256,
    /// Maximum number of attributes on a single element.
    max_attributes: usize = 4096,
    /// Maximum length in bytes of any single Name (element/attr/PI target).
    max_name_len: usize = 1 << 20,
    /// DOCTYPE handling. See DoctypePolicy.
    doctype: DoctypePolicy = .reject,
    /// Unqualified attribute local names treated as ID-typed for
    /// `getElementById`. `xml:id` is ALWAYS treated as an ID regardless.
    id_attr_names: []const []const u8 = &.{ "ID", "Id", "id" },
};

pub const ParseError = error{
    UnexpectedEof,
    UnexpectedChar,
    InvalidName,
    NameTooLong,
    MismatchedTag,
    UnclosedElement,
    DuplicateAttribute,
    TooManyAttributes,
    UndefinedEntity,
    InvalidCharRef,
    InvalidCharacter,
    UndeclaredNamespacePrefix,
    NamespaceError,
    DoctypeForbidden,
    UnsupportedEncoding,
    UnsupportedVersion,
    MaxDepthExceeded,
    MalformedComment,
    MalformedPI,
    MalformedCData,
    NoRootElement,
    MultipleRootElements,
    TrailingContent,
    DuplicateId,
} || std.mem.Allocator.Error;

// ── entry point ─────────────────────────────────────────────────────────────

/// Parse a UTF-8 XML document. On success the returned Document owns all
/// memory (backed by an arena whose child allocator is `gpa`); call
/// `Document.deinit`. On error nothing is leaked.
pub fn parse(gpa: std.mem.Allocator, source: []const u8, options: Options) ParseError!Document {
    return parseCounted(gpa, source, options, null);
}

/// `parse`, with an optional work counter. Test-only seam: it lets a regression
/// test pin the *complexity* of duplicate detection with a deterministic number
/// instead of a stopwatch. `stats == null` is the production path.
fn parseCounted(gpa: std.mem.Allocator, source: []const u8, options: Options, stats: ?*Stats) ParseError!Document {
    if (!std.unicode.utf8ValidateSlice(source)) return error.InvalidCharacter;

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var p: Parser = .{
        .src = source,
        .i = 0,
        .a = a,
        .opts = options,
        .ids = .empty,
        .stats = stats,
    };

    // Optional UTF-8 BOM.
    if (std.mem.startsWith(u8, source, "\xEF\xBB\xBF")) p.i = 3;

    var version: []const u8 = "1.0";
    var encoding: []const u8 = "";
    var standalone: ?bool = null;
    try p.parseXmlDecl(&version, &encoding, &standalone);

    var prolog: std.ArrayList(Child) = .empty;
    var epilog: std.ArrayList(Child) = .empty;
    var root: ?*Element = null;

    try p.parseDocument(&prolog, &epilog, &root);

    const r = root orelse return error.NoRootElement;

    return .{
        .arena = arena,
        .source = source,
        .root = r,
        .prolog = try prolog.toOwnedSlice(a),
        .epilog = try epilog.toOwnedSlice(a),
        .version = version,
        .encoding = encoding,
        .standalone = standalone,
        .ids = p.ids,
    };
}

// ── parser ──────────────────────────────────────────────────────────────────

const Open = struct {
    el: *Element,
    children: std.ArrayList(Child),
};

const Name = struct {
    prefix: []const u8,
    local: []const u8,
};

/// Deterministic work counters. `dup_compares` counts the units of work spent
/// on per-element duplicate detection: one per name comparison on the direct
/// scan, one per hash-set probe on the hashed path. A regression test asserts a
/// linear bound on it, which pins the complexity class without a stopwatch.
const Stats = struct {
    dup_compares: usize = 0,
};

/// Duplicate detection rescans the list it is building, which is O(k²) in the
/// number of attributes (or namespace declarations) on one element — and
/// `Options.max_attributes` caps that count, not the CPU it costs. Above this
/// many entries the scan runs through a hash set instead, which is O(k); below
/// it the direct scan wins, because a hash set costs an allocation and the
/// overwhelming majority of real elements carry a handful of attributes.
const dup_scan_threshold = 16;

/// An attribute's expanded name (namespace URI + local name), hashed as a unit
/// so the duplicate check needs no concatenated key and so no allocation.
const ExpandedName = struct {
    uri: []const u8,
    local: []const u8,

    const Context = struct {
        pub fn hash(_: Context, k: ExpandedName) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(k.uri);
            h.update(&[_]u8{0}); // separator: ("a","bc") must not hash as ("ab","c")
            h.update(k.local);
            return h.final();
        }
        pub fn eql(_: Context, a: ExpandedName, b: ExpandedName) bool {
            return std.mem.eql(u8, a.uri, b.uri) and std.mem.eql(u8, a.local, b.local);
        }
    };

    const Set = std.HashMapUnmanaged(ExpandedName, void, Context, std.hash_map.default_max_load_percentage);
};

const Parser = struct {
    src: []const u8,
    i: usize,
    a: std.mem.Allocator,
    opts: Options,
    ids: std.StringHashMapUnmanaged(*Element),
    stack: std.ArrayList(Open) = .empty,
    stats: ?*Stats = null,

    fn countCompares(self: *Parser, n: usize) void {
        if (self.stats) |s| s.dup_compares += n;
    }

    fn countCompare(self: *Parser) void {
        self.countCompares(1);
    }

    /// Has `pfx` already been declared on this element? `use_hash` selects the
    /// O(1) set over the O(d) rescan; both answer identically.
    fn nsAlreadyDeclared(
        self: *Parser,
        seen: *std.StringHashMapUnmanaged(void),
        use_hash: bool,
        decls: []const NsDecl,
        pfx: []const u8,
    ) ParseError!bool {
        self.countCompare();
        if (use_hash) return (try seen.getOrPut(self.a, pfx)).found_existing;
        for (decls) |d| {
            self.countCompare();
            if (std.mem.eql(u8, d.prefix, pfx)) return true;
        }
        return false;
    }

    fn eof(self: *Parser) bool {
        return self.i >= self.src.len;
    }

    fn peek(self: *Parser) ?u8 {
        return if (self.i < self.src.len) self.src[self.i] else null;
    }

    fn starts(self: *Parser, s: []const u8) bool {
        return std.mem.startsWith(u8, self.src[self.i..], s);
    }

    fn skipWs(self: *Parser) void {
        while (self.i < self.src.len) : (self.i += 1) {
            switch (self.src[self.i]) {
                ' ', '\t', '\r', '\n' => {},
                else => return,
            }
        }
    }

    fn requireWs(self: *Parser) ParseError!void {
        const before = self.i;
        self.skipWs();
        if (self.i == before) return error.UnexpectedChar;
    }

    // ── XML declaration ─────────────────────────────────────────────────────
    // Only valid at byte 0 (after BOM): `<?xml version="1.0" ...?>`.
    fn parseXmlDecl(self: *Parser, version: *[]const u8, encoding: *[]const u8, standalone: *?bool) ParseError!void {
        if (!self.starts("<?xml")) return;
        // Must be followed by whitespace to be the declaration (vs a PI target
        // like "xmlfoo"). A real "<?xml" PI target is reserved anyway.
        const after = self.i + 5;
        if (after >= self.src.len or !isWs(self.src[after])) return error.MalformedPI;
        self.i = after;
        self.skipWs();

        // version (required, must be 1.0)
        if (!self.starts("version")) return error.UnsupportedVersion;
        const ver = try self.parsePseudoAttr("version");
        if (!std.mem.eql(u8, ver, "1.0")) return error.UnsupportedVersion;
        version.* = ver;

        // Grammar: XMLDecl ::= '<?xml' VersionInfo (S EncodingDecl)?
        // (S SDDecl)? S? '?>' -- S is REQUIRED immediately before EncodingDecl
        // or SDDecl when either is present, but only OPTIONAL before the
        // final '?>' when neither follows. skipWs() alone can't tell those
        // apart, so track whether whitespace was actually consumed and
        // require it retroactively once we know what comes next (xmlconf
        // not-wf-sa-096: `version="1.0"encoding="UTF-8"` must be rejected).
        var had_ws = blk: {
            const before = self.i;
            self.skipWs();
            break :blk self.i != before;
        };
        if (self.starts("encoding")) {
            if (!had_ws) return error.MalformedPI;
            const enc = try self.parsePseudoAttr("encoding");
            if (!asciiEqualIgnoreCase(enc, "utf-8")) return error.UnsupportedEncoding;
            encoding.* = enc;
            const before = self.i;
            self.skipWs();
            had_ws = self.i != before;
        }
        if (self.starts("standalone")) {
            if (!had_ws) return error.MalformedPI;
            const sa = try self.parsePseudoAttr("standalone");
            if (std.mem.eql(u8, sa, "yes")) {
                standalone.* = true;
            } else if (std.mem.eql(u8, sa, "no")) {
                standalone.* = false;
            } else return error.MalformedPI;
            self.skipWs();
        }
        if (!self.starts("?>")) return error.MalformedPI;
        self.i += 2;
    }

    fn parsePseudoAttr(self: *Parser, key: []const u8) ParseError![]const u8 {
        if (!self.starts(key)) return error.MalformedPI;
        self.i += key.len;
        self.skipWs();
        if (self.peek() != '=') return error.MalformedPI;
        self.i += 1;
        self.skipWs();
        const q = self.peek() orelse return error.UnexpectedEof;
        if (q != '"' and q != '\'') return error.MalformedPI;
        self.i += 1;
        const start = self.i;
        while (self.i < self.src.len and self.src[self.i] != q) self.i += 1;
        if (self.eof()) return error.UnexpectedEof;
        const val = self.src[start..self.i];
        self.i += 1; // closing quote
        return val;
    }

    // ── document level ──────────────────────────────────────────────────────
    fn parseDocument(self: *Parser, prolog: *std.ArrayList(Child), epilog: *std.ArrayList(Child), root: *?*Element) ParseError!void {
        while (!self.eof()) {
            const c = self.src[self.i];
            if (c == '<') {
                try self.parseMarkup(prolog, epilog, root);
            } else if (self.stack.items.len == 0) {
                // Outside any element: only inter-element whitespace is allowed
                // (and ignored — it is not part of any canonicalized subtree).
                // Any other character data at the document level is an error.
                if (isWs(c)) {
                    self.i += 1;
                } else {
                    return error.TrailingContent;
                }
            } else {
                // Inside an element ALL character data — including leading /
                // whitespace-only runs — is significant content and must be
                // preserved verbatim (C14N is whitespace-sensitive here).
                try self.parseText();
            }
        }
        if (self.stack.items.len != 0) return error.UnclosedElement;
        if (root.* == null) return error.NoRootElement;
    }

    // Dispatch on what follows '<'.
    fn parseMarkup(self: *Parser, prolog: *std.ArrayList(Child), epilog: *std.ArrayList(Child), root: *?*Element) ParseError!void {
        std.debug.assert(self.src[self.i] == '<');
        const next = if (self.i + 1 < self.src.len) self.src[self.i + 1] else return error.UnexpectedEof;
        switch (next) {
            '?' => {
                const child = try self.parsePi();
                try self.addMisc(child, prolog, epilog, root.*);
            },
            '!' => {
                if (self.starts("<!--")) {
                    const child = try self.parseComment();
                    try self.addMisc(child, prolog, epilog, root.*);
                } else if (self.starts("<![CDATA[")) {
                    if (self.stack.items.len == 0) return error.TrailingContent;
                    try self.parseCData();
                } else if (self.starts("<!DOCTYPE")) {
                    try self.parseDoctype();
                } else return error.UnexpectedChar;
            },
            '/' => try self.parseEndTag(root),
            else => try self.parseStartTag(root),
        }
    }

    fn addMisc(self: *Parser, child: Child, prolog: *std.ArrayList(Child), epilog: *std.ArrayList(Child), root: ?*Element) ParseError!void {
        if (self.stack.items.len != 0) {
            var top = &self.stack.items[self.stack.items.len - 1];
            try top.children.append(self.a, child);
        } else if (root == null) {
            try prolog.append(self.a, child);
        } else {
            try epilog.append(self.a, child);
        }
    }

    // ── DOCTYPE ─────────────────────────────────────────────────────────────
    fn parseDoctype(self: *Parser) ParseError!void {
        if (self.opts.doctype == .reject) return error.DoctypeForbidden;
        // .ignore: skip the whole declaration without ever parsing entity decls
        // or touching an external subset. Balances a `[ internal subset ]`.
        self.i += "<!DOCTYPE".len;
        while (!self.eof()) {
            const c = self.src[self.i];
            if (c == '[') {
                self.i += 1;
                // A `]` inside a quoted literal (EntityValue/AttValue/
                // ExternalID literal, e.g. `<!ENTITY rsqb "]">`) or inside a
                // `<!-- comment -->` is NOT the internal subset's closing
                // bracket -- naively stopping at the first raw `]` byte
                // truncates the subset early and misparses everything after
                // it as document content (xmlconf valid-sa-114/117/118: an
                // entity value literally containing "]" or "]]"). Track
                // quote state and skip comments wholesale so only an
                // unquoted, uncommented `]` ends the subset.
                var quote: ?u8 = null;
                while (!self.eof()) {
                    const cc = self.src[self.i];
                    if (quote) |q| {
                        if (cc == q) quote = null;
                        self.i += 1;
                    } else if (cc == '"' or cc == '\'') {
                        quote = cc;
                        self.i += 1;
                    } else if (cc == '<' and self.starts("<!--")) {
                        self.i += "<!--".len;
                        while (!self.eof() and !self.starts("-->")) self.i += 1;
                        if (self.eof()) return error.UnexpectedEof;
                        self.i += "-->".len;
                    } else if (cc == ']') {
                        break;
                    } else {
                        self.i += 1;
                    }
                }
                if (self.eof()) return error.UnexpectedEof;
                self.i += 1; // ']'
            } else if (c == '>') {
                self.i += 1;
                return;
            } else {
                self.i += 1;
            }
        }
        return error.UnexpectedEof;
    }

    // ── comment / PI / CDATA ────────────────────────────────────────────────
    fn parseComment(self: *Parser) ParseError!Child {
        const start = self.i;
        self.i += "<!--".len;
        const body_start = self.i;
        while (self.i + 2 < self.src.len) : (self.i += 1) {
            if (self.src[self.i] == '-' and self.src[self.i + 1] == '-') {
                // "--" may only appear as the closing "-->".
                if (self.src[self.i + 2] != '>') return error.MalformedComment;
                const body = self.src[body_start..self.i];
                try self.validateChars(body);
                self.i += 3; // -->
                return .{ .content = .{ .comment = body }, .span = .{ .start = start, .end = self.i } };
            }
        }
        return error.MalformedComment;
    }

    fn parsePi(self: *Parser) ParseError!Child {
        const start = self.i;
        self.i += 1; // '?'  (we entered at '<', so consume '<?')
        self.i += 1;
        const target = try self.parseNameRaw();
        if (asciiEqualIgnoreCase(target, "xml")) return error.MalformedPI; // reserved
        // Namespaces in XML 1.0 §7 "Conformance of Documents", verbatim:
        // "It follows that in a namespace-well-formed document: ... No entity
        // names, processing instruction targets, or notation names contain any
        // colons." (Audit BD-26: cited as "Section 8 (Namespace Constraints)"
        // before — §8 is "Conformance of Processors", and the rule is a
        // consequence stated in §7, not a named Namespace Constraint.)
        // This module always applies namespace
        // processing, so this NSC is enforced unconditionally (xmlconf
        // rmt-ns10-042, errata NE08).
        if (std.mem.indexOfScalar(u8, target, ':') != null) return error.NamespaceError;
        var data: []const u8 = "";
        if (!self.starts("?>")) {
            try self.requireWs();
            const ds = self.i;
            while (self.i + 1 < self.src.len and !(self.src[self.i] == '?' and self.src[self.i + 1] == '>')) self.i += 1;
            if (self.i + 1 >= self.src.len) return error.MalformedPI;
            data = self.src[ds..self.i];
            try self.validateChars(data);
        }
        if (!self.starts("?>")) return error.MalformedPI;
        self.i += 2;
        return .{ .content = .{ .pi = .{ .target = target, .data = data } }, .span = .{ .start = start, .end = self.i } };
    }

    fn parseCData(self: *Parser) ParseError!void {
        const start = self.i;
        self.i += "<![CDATA[".len;
        const body_start = self.i;
        while (self.i + 2 < self.src.len + 1) : (self.i += 1) {
            if (self.i + 2 < self.src.len + 1 and self.i + 2 <= self.src.len and
                self.i + 3 <= self.src.len and std.mem.eql(u8, self.src[self.i .. self.i + 3], "]]>"))
            {
                const body = self.src[body_start..self.i];
                try self.validateChars(body);
                self.i += 3;
                var top = &self.stack.items[self.stack.items.len - 1];
                try top.children.append(self.a, .{ .content = .{ .cdata = body }, .span = .{ .start = start, .end = self.i } });
                return;
            }
            if (self.i + 3 > self.src.len) break;
        }
        return error.MalformedCData;
    }

    // ── text / character data ───────────────────────────────────────────────
    fn parseText(self: *Parser) ParseError!void {
        const start = self.i;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.a);
        while (self.i < self.src.len and self.src[self.i] != '<') {
            const c = self.src[self.i];
            if (c == '&') {
                try self.decodeReference(&out);
            } else if (c == ']' and self.starts("]]>")) {
                // Literal "]]>" is forbidden in character data (XML §2.4).
                return error.MalformedCData;
            } else if (c == '\r') {
                // Line-ending normalization: \r\n and \r → \n.
                try out.append(self.a, '\n');
                self.i += 1;
                if (self.i < self.src.len and self.src[self.i] == '\n') self.i += 1;
            } else if (c < 0x80) {
                if (c < 0x20 and c != '\t' and c != '\n') return error.InvalidCharacter;
                try out.append(self.a, c);
                self.i += 1;
            } else {
                // Multi-byte UTF-8: the whole source was already validated as
                // well-formed UTF-8 (parse()'s utf8ValidateSlice), but that
                // says nothing about the XML Char production itself, which
                // additionally excludes the Unicode noncharacters #xFFFE and
                // #xFFFF (xmlconf not-wf-sa-166/167/171-174: a LITERAL
                // (non-charref) #xFFFF/#xFFFE in content must still be
                // rejected, same as the already-enforced numeric-charref
                // path in decodeReference/isXmlChar).
                const len = std.unicode.utf8ByteSequenceLength(c) catch return error.InvalidCharacter;
                if (self.i + len > self.src.len) return error.InvalidCharacter;
                const seq = self.src[self.i .. self.i + len];
                const cp = std.unicode.utf8Decode(seq) catch return error.InvalidCharacter;
                if (!isXmlChar(cp)) return error.InvalidCharacter;
                try out.appendSlice(self.a, seq);
                self.i += len;
            }
        }
        const text = try out.toOwnedSlice(self.a);
        var top = &self.stack.items[self.stack.items.len - 1];
        try top.children.append(self.a, .{ .content = .{ .text = text }, .span = .{ .start = start, .end = self.i } });
    }

    /// Decode `&...;` at self.i into `out`. Only the 5 predefined entities and
    /// numeric character references are supported — any other name fails with
    /// error.UndefinedEntity (this is what makes user-defined entities, and
    /// therefore billion-laughs and external-entity XXE, impossible).
    fn decodeReference(self: *Parser, out: *std.ArrayList(u8)) ParseError!void {
        std.debug.assert(self.src[self.i] == '&');
        const semi = std.mem.indexOfScalarPos(u8, self.src, self.i + 1, ';') orelse return error.UndefinedEntity;
        const name = self.src[self.i + 1 .. semi];
        if (name.len == 0) return error.UndefinedEntity;
        if (name[0] == '#') {
            var cp: u32 = 0;
            // CharRef ::= '&#' [0-9]+ ';' | '&#x' [0-9a-fA-F]+ ';' -- the 'x'
            // introducing a hex reference is fixed lowercase in the grammar
            // (hex digits themselves may be upper/lower); '&#X41;' is not-wf
            // (xmlconf not-wf-sa-093).
            if (name.len >= 2 and name[1] == 'x') {
                if (name.len == 2) return error.InvalidCharRef;
                for (name[2..]) |d| {
                    const v = hexVal(d) orelse return error.InvalidCharRef;
                    cp = std.math.mul(u32, cp, 16) catch return error.InvalidCharRef;
                    cp = std.math.add(u32, cp, v) catch return error.InvalidCharRef;
                    if (cp > 0x10FFFF) return error.InvalidCharRef;
                }
            } else {
                for (name[1..]) |d| {
                    if (d < '0' or d > '9') return error.InvalidCharRef;
                    cp = std.math.mul(u32, cp, 10) catch return error.InvalidCharRef;
                    cp = std.math.add(u32, cp, @as(u32, d - '0')) catch return error.InvalidCharRef;
                    if (cp > 0x10FFFF) return error.InvalidCharRef;
                }
            }
            if (!isXmlChar(cp)) return error.InvalidCharRef;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(@intCast(cp), &buf) catch return error.InvalidCharRef;
            try out.appendSlice(self.a, buf[0..n]);
        } else if (std.mem.eql(u8, name, "lt")) {
            try out.append(self.a, '<');
        } else if (std.mem.eql(u8, name, "gt")) {
            try out.append(self.a, '>');
        } else if (std.mem.eql(u8, name, "amp")) {
            try out.append(self.a, '&');
        } else if (std.mem.eql(u8, name, "apos")) {
            try out.append(self.a, '\'');
        } else if (std.mem.eql(u8, name, "quot")) {
            try out.append(self.a, '"');
        } else {
            return error.UndefinedEntity;
        }
        self.i = semi + 1;
    }

    // ── start tag ───────────────────────────────────────────────────────────
    fn parseStartTag(self: *Parser, root: *?*Element) ParseError!void {
        const start = self.i;
        self.i += 1; // '<'
        const name = try self.parseName();

        // depth guard (root = depth 1)
        if (self.stack.items.len + 1 > self.opts.max_depth) return error.MaxDepthExceeded;

        // Parse raw attributes (including xmlns:* declarations).
        var raw: std.ArrayList(RawAttr) = .empty;
        defer raw.deinit(self.a);
        while (true) {
            self.skipWs();
            const c = self.peek() orelse return error.UnexpectedEof;
            if (c == '>' or c == '/') break;
            if (raw.items.len >= self.opts.max_attributes) return error.TooManyAttributes;
            // Require whitespace before each attribute (already consumed above;
            // enforce that at least one ws separated us from the name/prev val).
            const attr_start = self.i;
            const an = try self.parseName();
            self.skipWs();
            if (self.peek() != '=') return error.UnexpectedChar;
            self.i += 1;
            self.skipWs();
            const value = try self.parseAttrValue();
            try raw.append(self.a, .{ .name = an, .value = value, .span = .{ .start = attr_start, .end = self.i } });
        }

        const el = try self.a.create(Element);

        // Split raw attributes into namespace declarations and real attributes.
        var ns_decls: std.ArrayList(NsDecl) = .empty;
        var attrs: std.ArrayList(Attribute) = .empty;
        var seen_ns: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_ns.deinit(self.a);
        const hash_ns = raw.items.len > dup_scan_threshold;
        for (raw.items) |ra| {
            if (ra.name.prefix.len == 0 and std.mem.eql(u8, ra.name.local, "xmlns")) {
                // default namespace declaration
                if (try self.nsAlreadyDeclared(&seen_ns, hash_ns, ns_decls.items, "")) return error.NamespaceError;
                // xmlns="..." — value may be "" (undeclare). May not be the
                // reserved xmlns URI.
                if (std.mem.eql(u8, ra.value, xmlns_ns)) return error.NamespaceError;
                try ns_decls.append(self.a, .{ .prefix = "", .uri = ra.value });
            } else if (std.mem.eql(u8, ra.name.prefix, "xmlns")) {
                // prefixed namespace declaration
                const pfx = ra.name.local;
                if (std.mem.eql(u8, pfx, "xmlns")) return error.NamespaceError;
                if (ra.value.len == 0) return error.NamespaceError; // cannot undeclare a prefix in 1.0
                if (std.mem.eql(u8, pfx, "xml")) {
                    if (!std.mem.eql(u8, ra.value, xml_ns)) return error.NamespaceError;
                } else {
                    if (std.mem.eql(u8, ra.value, xml_ns)) return error.NamespaceError; // xml URI reserved
                    if (std.mem.eql(u8, ra.value, xmlns_ns)) return error.NamespaceError;
                }
                if (try self.nsAlreadyDeclared(&seen_ns, hash_ns, ns_decls.items, pfx)) return error.NamespaceError;
                try ns_decls.append(self.a, .{ .prefix = pfx, .uri = ra.value });
            } else {
                try attrs.append(self.a, .{
                    .prefix = ra.name.prefix,
                    .local = ra.name.local,
                    .uri = "", // resolved below
                    .value = ra.value,
                    .span = ra.span,
                });
            }
        }

        el.* = .{
            .prefix = name.prefix,
            .local = name.local,
            .uri = "",
            .ns_decls = try ns_decls.toOwnedSlice(self.a),
            .attributes = &.{},
            .children = &.{},
            .parent = if (self.stack.items.len != 0) self.stack.items[self.stack.items.len - 1].el else null,
            .span = .{ .start = start, .end = 0 },
        };

        // Link this element into the namespace scope chain BEFORE resolving
        // anything: `resolveNs` reads it, and both the parser and every
        // downstream consumer (`c14n` calls it once per attribute) then pay
        // O(declaring ancestors) instead of O(decls × depth). See `NsScope`.
        try self.linkNsScope(el);

        // Resolve element namespace.
        if (std.mem.eql(u8, name.prefix, "xmlns")) return error.NamespaceError;
        var probes: usize = 0;
        el.uri = el.resolveNsCounted(name.prefix, &probes) orelse return error.UndeclaredNamespacePrefix;
        self.countCompares(probes);

        // Resolve attribute namespaces; unprefixed attr → no namespace. With
        // the scope chain in place this is O(attrs), not the O(attrs × decls)
        // it used to be — the indexing lives in `resolveNs` now, so there is
        // one implementation of the precedence rules rather than two.
        //
        // The real probe count is folded into `dup_compares` rather than a
        // flat 1 per attribute: this loop is one of the three sites that
        // test's linear bound is written about, and charging it a constant
        // would make the bound blind to exactly the regression it exists to
        // catch.
        for (attrs.items) |*at| {
            if (at.prefix.len == 0) {
                at.uri = "";
            } else if (std.mem.eql(u8, at.prefix, "xmlns")) {
                return error.NamespaceError;
            } else {
                probes = 0;
                at.uri = el.resolveNsCounted(at.prefix, &probes) orelse return error.UndeclaredNamespacePrefix;
                self.countCompares(probes);
            }
        }
        // Duplicate check by expanded name (uri, local). O(k) above
        // `dup_scan_threshold`, direct scan below it — see that constant.
        if (attrs.items.len > dup_scan_threshold) {
            var seen: ExpandedName.Set = .empty;
            defer seen.deinit(self.a);
            try seen.ensureTotalCapacity(self.a, @intCast(attrs.items.len));
            for (attrs.items) |at| {
                self.countCompare();
                const gop = seen.getOrPutAssumeCapacity(.{ .uri = at.uri, .local = at.local });
                if (gop.found_existing) return error.DuplicateAttribute;
            }
        } else {
            for (attrs.items, 0..) |a1, idx| {
                for (attrs.items[idx + 1 ..]) |a2| {
                    self.countCompare();
                    if (std.mem.eql(u8, a1.uri, a2.uri) and std.mem.eql(u8, a1.local, a2.local)) {
                        return error.DuplicateAttribute;
                    }
                }
            }
        }
        el.attributes = try attrs.toOwnedSlice(self.a);

        // Register ID-typed attributes for getElementById.
        try self.registerIds(el);

        // Self-closing or open?
        const c = self.peek() orelse return error.UnexpectedEof;
        if (c == '/') {
            self.i += 1;
            if (self.peek() != '>') return error.UnexpectedChar;
            self.i += 1;
            el.span.end = self.i;
            try self.attachFinished(el, root);
        } else {
            std.debug.assert(c == '>');
            self.i += 1;
            try self.stack.append(self.a, .{ .el = el, .children = .empty });
        }
    }

    /// Attach the namespace scope in force at `el`. An element that declares
    /// nothing shares its parent's scope — no allocation, and the parent-axis
    /// walk in `resolveNs` skips it entirely.
    fn linkNsScope(self: *Parser, el: *Element) ParseError!void {
        const outer: ?*const NsScope = if (el.parent) |p| p.ns_scope else null;
        if (el.ns_decls.len == 0) {
            el.ns_scope = outer orelse &empty_ns_scope;
            return;
        }
        const s = try self.a.create(NsScope);
        s.* = .{ .decls = el.ns_decls, .index = null, .outer = outer };
        if (el.ns_decls.len > dup_scan_threshold) {
            const ix = try self.a.create(NsScope.PrefixIndex);
            ix.* = .empty;
            try ix.ensureTotalCapacity(self.a, @intCast(el.ns_decls.len));
            // A prefix declared twice on one element was rejected above, so
            // there is exactly one entry per prefix and no first-wins tie.
            for (el.ns_decls) |d| ix.putAssumeCapacity(d.prefix, d.uri);
            s.index = ix;
        }
        el.ns_scope = s;
    }

    fn registerIds(self: *Parser, el: *Element) ParseError!void {
        for (el.attributes) |at| {
            var is_id = false;
            if (std.mem.eql(u8, at.uri, xml_ns) and std.mem.eql(u8, at.local, "id")) {
                is_id = true;
            } else if (at.uri.len == 0) {
                for (self.opts.id_attr_names) |nm| {
                    if (std.mem.eql(u8, at.local, nm)) {
                        is_id = true;
                        break;
                    }
                }
            }
            if (!is_id) continue;
            const gop = try self.ids.getOrPut(self.a, at.value);
            if (gop.found_existing) return error.DuplicateId;
            gop.value_ptr.* = el;
        }
    }

    // ── end tag ─────────────────────────────────────────────────────────────
    fn parseEndTag(self: *Parser, root: *?*Element) ParseError!void {
        self.i += 2; // '</'
        const name = try self.parseName();
        self.skipWs();
        if (self.peek() != '>') return error.UnexpectedChar;
        self.i += 1;
        if (self.stack.items.len == 0) return error.MismatchedTag;
        var top = self.stack.items[self.stack.items.len - 1];
        if (!std.mem.eql(u8, top.el.prefix, name.prefix) or !std.mem.eql(u8, top.el.local, name.local)) {
            return error.MismatchedTag;
        }
        _ = self.stack.pop();
        top.el.children = try top.children.toOwnedSlice(self.a);
        top.el.span.end = self.i;
        try self.attachFinished(top.el, root);
    }

    // Attach a finished element to its parent (or record it as the root).
    fn attachFinished(self: *Parser, el: *Element, root: *?*Element) ParseError!void {
        if (self.stack.items.len == 0) {
            if (root.* != null) return error.MultipleRootElements;
            root.* = el;
        } else {
            var top = &self.stack.items[self.stack.items.len - 1];
            try top.children.append(self.a, .{ .content = .{ .element = el }, .span = el.span });
        }
    }

    // ── names & attribute values ────────────────────────────────────────────
    const RawAttr = struct { name: Name, value: []const u8, span: Span };

    fn parseName(self: *Parser) ParseError!Name {
        const raw = try self.parseNameRaw();
        // Split on a single colon (QName). Zero or one colon allowed; both
        // parts must be non-empty when a colon is present.
        if (std.mem.indexOfScalar(u8, raw, ':')) |ci| {
            const prefix = raw[0..ci];
            const local = raw[ci + 1 ..];
            if (prefix.len == 0 or local.len == 0) return error.InvalidName;
            if (std.mem.indexOfScalar(u8, local, ':') != null) return error.InvalidName;
            return .{ .prefix = prefix, .local = local };
        }
        return .{ .prefix = "", .local = raw };
    }

    fn parseNameRaw(self: *Parser) ParseError![]const u8 {
        const start = self.i;
        const first = self.peek() orelse return error.UnexpectedEof;
        if (!isNameStartByte(first)) return error.InvalidName;
        self.i += 1;
        while (self.i < self.src.len and isNameByte(self.src[self.i])) self.i += 1;
        const name = self.src[start..self.i];
        if (name.len > self.opts.max_name_len) return error.NameTooLong;
        return name;
    }

    fn parseAttrValue(self: *Parser) ParseError![]const u8 {
        const q = self.peek() orelse return error.UnexpectedEof;
        if (q != '"' and q != '\'') return error.UnexpectedChar;
        self.i += 1;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.a);
        while (self.i < self.src.len and self.src[self.i] != q) {
            const c = self.src[self.i];
            if (c == '<') return error.UnexpectedChar; // '<' illegal in attr value
            if (c == '&') {
                try self.decodeReference(&out);
            } else if (c == '\t' or c == '\n') {
                // Attribute-value normalization: literal whitespace → space.
                try out.append(self.a, ' ');
                self.i += 1;
            } else if (c == '\r') {
                // \r and \r\n normalize to a single space (line-ending then ws
                // normalization; the ref-introduced case is handled above).
                try out.append(self.a, ' ');
                self.i += 1;
                if (self.i < self.src.len and self.src[self.i] == '\n') self.i += 1;
            } else if (c < 0x80) {
                if (c < 0x20) return error.InvalidCharacter;
                try out.append(self.a, c);
                self.i += 1;
            } else {
                // See parseText's identical branch: a well-formed-UTF-8 byte
                // sequence can still decode to a codepoint the XML Char
                // production forbids (#xFFFE, #xFFFF).
                const len = std.unicode.utf8ByteSequenceLength(c) catch return error.InvalidCharacter;
                if (self.i + len > self.src.len) return error.InvalidCharacter;
                const seq = self.src[self.i .. self.i + len];
                const cp = std.unicode.utf8Decode(seq) catch return error.InvalidCharacter;
                if (!isXmlChar(cp)) return error.InvalidCharacter;
                try out.appendSlice(self.a, seq);
                self.i += len;
            }
        }
        if (self.eof()) return error.UnexpectedEof;
        self.i += 1; // closing quote
        return out.toOwnedSlice(self.a);
    }

    fn validateChars(self: *Parser, s: []const u8) ParseError!void {
        _ = self;
        // Reject control chars other than tab/LF/CR, and Unicode
        // noncharacters #xFFFE/#xFFFF, in comment/PI/CDATA bodies (XML Char
        // production, XML §2.2).
        var idx: usize = 0;
        while (idx < s.len) {
            const c = s[idx];
            if (c < 0x80) {
                if (c < 0x20 and c != '\t' and c != '\n' and c != '\r') return error.InvalidCharacter;
                idx += 1;
            } else {
                const len = std.unicode.utf8ByteSequenceLength(c) catch return error.InvalidCharacter;
                if (idx + len > s.len) return error.InvalidCharacter;
                const cp = std.unicode.utf8Decode(s[idx .. idx + len]) catch return error.InvalidCharacter;
                if (!isXmlChar(cp)) return error.InvalidCharacter;
                idx += len;
            }
        }
    }
};

// ── byte helpers ────────────────────────────────────────────────────────────

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

fn isNameStartByte(c: u8) bool {
    // ASCII NameStartChar plus any UTF-8 lead/continuation byte (>= 0x80). This
    // accepts the full non-ASCII Name range leniently; ASCII rules are exact.
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or c == '_' or c == ':' or c >= 0x80;
}

fn isNameByte(c: u8) bool {
    return isNameStartByte(c) or (c >= '0' and c <= '9') or c == '-' or c == '.';
}

fn hexVal(c: u8) ?u32 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn isXmlChar(cp: u32) bool {
    return cp == 0x9 or cp == 0xA or cp == 0xD or
        (cp >= 0x20 and cp <= 0xD7FF) or
        (cp >= 0xE000 and cp <= 0xFFFD) or
        (cp >= 0x10000 and cp <= 0x10FFFF);
}

fn asciiEqualIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "smoke: minimal document" {
    var doc = try parse(testing.allocator, "<root/>", .{});
    defer doc.deinit();
    try testing.expectEqualStrings("root", doc.root.local);
    try testing.expectEqual(@as(usize, 0), doc.root.children.len);
}

test "W3C valid: nested elements, attributes, document order" {
    const src =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<catalog><book id="b1"><title>Zig</title><price>0</price></book></catalog>
    ;
    var doc = try parse(testing.allocator, src, .{});
    defer doc.deinit();
    try testing.expectEqualStrings("catalog", doc.root.local);
    const book = doc.root.firstElementChild().?;
    try testing.expectEqualStrings("book", book.local);
    try testing.expectEqualStrings("b1", book.attr("", "id").?);
    // document order preserved: title then price
    var it = book.elementIterator();
    try testing.expectEqualStrings("title", it.next().?.local);
    try testing.expectEqualStrings("price", it.next().?.local);
    try testing.expect(it.next() == null);
    const title = book.firstElementChild().?;
    const txt = try title.textContent(testing.allocator);
    defer testing.allocator.free(txt);
    try testing.expectEqualStrings("Zig", txt);
}

test "namespaces: default, prefixed, scoping, shadowing, resolution" {
    const src =
        \\<a xmlns="urn:d" xmlns:x="urn:x">
        \\  <x:b attr="v" x:attr="w"/>
        \\  <c xmlns="urn:d2"><d/></c>
        \\</a>
    ;
    var doc = try parse(testing.allocator, src, .{});
    defer doc.deinit();
    const a = doc.root;
    try testing.expectEqualStrings("urn:d", a.uri);
    try testing.expectEqualStrings("", a.prefix);

    var it = a.elementIterator();
    const b = it.next().?;
    try testing.expectEqualStrings("x", b.prefix);
    try testing.expectEqualStrings("b", b.local);
    try testing.expectEqualStrings("urn:x", b.uri);
    // unprefixed attribute → NO namespace (not the default)
    try testing.expectEqualStrings("v", b.attr("", "attr").?);
    // prefixed attribute → x namespace
    try testing.expectEqualStrings("w", b.attr("urn:x", "attr").?);

    const c = it.next().?;
    // default namespace shadowed on <c>
    try testing.expectEqualStrings("urn:d2", c.uri);
    const d = c.firstElementChild().?;
    try testing.expectEqualStrings("urn:d2", d.uri);
    // prefix x still in scope inside <c> via inheritance
    try testing.expectEqualStrings("urn:x", d.resolveNs("x").?);
    // default at <d> is d2
    try testing.expectEqualStrings("urn:d2", d.resolveNs("").?);
}

test "infoset fidelity: prefixes, comments, PIs, CDATA, mixed content" {
    const src =
        \\<?pi-before yes?>
        \\<doc xmlns:h="urn:h"><!-- c1 -->text<h:e/>more<![CDATA[<raw> & ]]><?pi inside?></doc>
        \\<?pi-after no?>
    ;
    var doc = try parse(testing.allocator, src, .{});
    defer doc.deinit();
    // prolog & epilog PIs preserved
    try testing.expectEqual(@as(usize, 1), doc.prolog.len);
    try testing.expectEqualStrings("pi-before", doc.prolog[0].content.pi.target);
    try testing.expectEqual(@as(usize, 1), doc.epilog.len);
    try testing.expectEqualStrings("pi-after", doc.epilog[0].content.pi.target);

    // children in document order with kinds preserved
    const kids = doc.root.children;
    try testing.expectEqualStrings(" c1 ", kids[0].content.comment);
    try testing.expectEqualStrings("text", kids[1].content.text);
    try testing.expectEqualStrings("e", kids[2].content.element.local);
    try testing.expectEqualStrings("urn:h", kids[2].content.element.uri);
    try testing.expectEqualStrings("h", kids[2].content.element.prefix); // ORIGINAL prefix kept
    try testing.expectEqualStrings("more", kids[3].content.text);
    try testing.expectEqualStrings("<raw> & ", kids[4].content.cdata); // CDATA verbatim
    try testing.expectEqualStrings("pi", kids[5].content.pi.target);

    // byte span of <h:e/> round-trips to the source
    try testing.expectEqualStrings("<h:e/>", kids[2].span.slice(src));
}

test "entities: predefined + numeric char refs, decimal and hex" {
    var doc = try parse(testing.allocator, "<t>&lt;&amp;&gt;&#65;&#x42;&apos;&quot;</t>", .{});
    defer doc.deinit();
    const txt = try doc.root.textContent(testing.allocator);
    defer testing.allocator.free(txt);
    try testing.expectEqualStrings("<&>AB'\"", txt);
}

test "attribute value normalization: whitespace and refs" {
    var doc = try parse(testing.allocator, "<t a=\"x\ty\nz\" b=\"&#9;\"/>", .{});
    defer doc.deinit();
    // literal tab/newline → space; but a char-ref tab stays a tab
    try testing.expectEqualStrings("x y z", doc.root.attr("", "a").?);
    try testing.expectEqualStrings("\t", doc.root.attr("", "b").?);
}

test "content whitespace preserved: leading + whitespace-only runs (C14N-critical regression)" {
    // Regression: leading/whitespace-only character data INSIDE an element is
    // significant content and must survive verbatim — dropping it breaks XML-DSig
    // canonicalization (the signer's whitespace is part of the signed octets).
    // Document-level inter-element whitespace stays ignored.
    var doc = try parse(testing.allocator, "  <e>\n   text\n</e>  ", .{});
    defer doc.deinit();
    const txt = try doc.root.textContent(testing.allocator);
    defer testing.allocator.free(txt);
    try testing.expectEqualStrings("\n   text\n", txt);
}

test "getElementById + findByAttr" {
    const src =
        \\<r xmlns:xml="http://www.w3.org/XML/1998/namespace">
        \\  <a ID="assertion-1"><b xml:id="inner"/></a>
        \\</r>
    ;
    var doc = try parse(testing.allocator, src, .{});
    defer doc.deinit();
    try testing.expectEqualStrings("a", doc.getElementById("assertion-1").?.local);
    try testing.expectEqualStrings("b", doc.getElementById("inner").?.local); // xml:id
    try testing.expectEqualStrings("a", doc.findByAttr("", "ID", "assertion-1").?.local);
    try testing.expect(doc.getElementById("nope") == null);
}

test "inScopeNamespaces returns inherited axis" {
    const src = "<a xmlns:p=\"urn:p\"><b xmlns:q=\"urn:q\"><c/></b></a>";
    var doc = try parse(testing.allocator, src, .{});
    defer doc.deinit();
    const c = doc.root.firstElementChild().?.firstElementChild().?;
    const ns = try c.inScopeNamespaces(testing.allocator);
    defer testing.allocator.free(ns);
    // both p and q are in scope at <c>
    try testing.expectEqual(@as(usize, 2), ns.len);
    var have_p = false;
    var have_q = false;
    for (ns) |d| {
        if (std.mem.eql(u8, d.prefix, "p")) have_p = std.mem.eql(u8, d.uri, "urn:p");
        if (std.mem.eql(u8, d.prefix, "q")) have_q = std.mem.eql(u8, d.uri, "urn:q");
    }
    try testing.expect(have_p and have_q);
}

// ── W3C-pattern not-well-formed vectors (modeled on xmlconf not-wf/sa) ────────

test "not-wf: mismatched end tag" {
    try testing.expectError(error.MismatchedTag, parse(testing.allocator, "<a></b>", .{}));
}

test "not-wf: unclosed element" {
    try testing.expectError(error.UnclosedElement, parse(testing.allocator, "<a><b></b>", .{}));
}

test "not-wf: bad nesting overlap" {
    try testing.expectError(error.MismatchedTag, parse(testing.allocator, "<a><b></a></b>", .{}));
}

test "not-wf: duplicate attribute" {
    try testing.expectError(error.DuplicateAttribute, parse(testing.allocator, "<a x=\"1\" x=\"2\"/>", .{}));
}

test "not-wf: undeclared entity" {
    try testing.expectError(error.UndefinedEntity, parse(testing.allocator, "<a>&undefined;</a>", .{}));
}

test "not-wf: raw < in text" {
    // A bare '<' in content starts a tag; the following space is not a valid
    // name start, so the document is rejected (well-formedness violated).
    try testing.expectError(error.InvalidName, parse(testing.allocator, "<a>a < b</a>", .{}));
}

test "not-wf: no root element" {
    try testing.expectError(error.NoRootElement, parse(testing.allocator, "<!-- only a comment -->", .{}));
}

test "not-wf: multiple root elements" {
    try testing.expectError(error.MultipleRootElements, parse(testing.allocator, "<a/><b/>", .{}));
}

test "not-wf: text at top level" {
    try testing.expectError(error.TrailingContent, parse(testing.allocator, "<a/>garbage", .{}));
}

test "not-wf: bad comment with double hyphen" {
    try testing.expectError(error.MalformedComment, parse(testing.allocator, "<a><!-- a--b --></a>", .{}));
}

test "not-wf: undeclared namespace prefix" {
    try testing.expectError(error.UndeclaredNamespacePrefix, parse(testing.allocator, "<x:a/>", .{}));
}

test "not-wf: cannot undeclare prefix (Namespaces 1.0)" {
    try testing.expectError(error.NamespaceError, parse(testing.allocator, "<a xmlns:p=\"\"/>", .{}));
}

test "not-wf: invalid name start" {
    try testing.expectError(error.InvalidName, parse(testing.allocator, "<1a/>", .{}));
}

test "not-wf: char ref out of Unicode range" {
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#x110000;</a>", .{}));
}

test "not-wf: char ref onto a lone UTF-16 surrogate is rejected" {
    // D800..DFFF is carved out of XML 1.0's Char production (a lone surrogate
    // is not a valid Unicode scalar value) — the gap between isXmlChar's two
    // adjoining ranges (0x20..D7FF, E000..FFFD) exists precisely for this.
    // NOTE: `std.unicode.utf8Encode` also independently rejects a surrogate
    // half, so a mutation that widened isXmlChar's ranges to cover D800..DFFF
    // is an equivalent mutant for THIS call site today — the encode step
    // catches it regardless. The assertion is kept anyway: it pins the
    // documented spec contract (isXmlChar's own job, not an accident of
    // which stdlib helper happens to run after it), and it stops being
    // redundant the moment either check changes.
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#xD800;</a>", .{})); // low end
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#xDFFF;</a>", .{})); // high end
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#55296;</a>", .{})); // decimal 0xD800
    // The adjoining valid boundaries must still be accepted.
    var lo = try parse(testing.allocator, "<a>&#xD7FF;</a>", .{});
    defer lo.deinit();
    var hi = try parse(testing.allocator, "<a>&#xE000;</a>", .{});
    defer hi.deinit();
}

test "not-wf: char ref onto a forbidden control character is rejected" {
    // XML 1.0's Char production excludes every C0 control code except TAB
    // (x9), LF (xA) and CR (xD) — unlike the surrogate case above, nothing
    // downstream (`std.unicode.utf8Encode` happily encodes a NUL byte) backs
    // this up, so isXmlChar's low bound (`cp >= 0x20`) is the ONLY guard.
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#x0;</a>", .{})); // NUL
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#x1;</a>", .{}));
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#xB;</a>", .{})); // vertical tab
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#x1F;</a>", .{})); // last forbidden C0
    // The explicitly-whitelisted C0 controls and the adjoining valid boundary
    // must still be accepted.
    var tab = try parse(testing.allocator, "<a>&#x9;</a>", .{});
    defer tab.deinit();
    var space = try parse(testing.allocator, "<a>&#x20;</a>", .{});
    defer space.deinit();
}

// The four regressions below were each found by running the vendored xmlconf
// corpus (xmlconf_test.zig) during that corpus's own validation. The specific
// xmlconf cases that caught them (xmltest not-wf-sa-093/096/166-174,
// valid-sa-114/117/118) live in the James Clark `xmltest` sub-suite, which was
// later excluded from vendoring entirely on license grounds (see NOTICE) — so
// these hand-written regressions are what now pins each fix against silent
// regression, in place of the xmlconf case that originally caught it.

test "not-wf: hex char ref must use lowercase 'x' (uppercase 'X' rejected)" {
    // CharRef ::= '&#' [0-9]+ ';' | '&#x' [0-9a-fA-F]+ ';' — the 'x' itself is
    // fixed lowercase in the grammar; only the hex digits may vary case.
    try testing.expectError(error.InvalidCharRef, parse(testing.allocator, "<a>&#X41;</a>", .{}));
    var ok = try parse(testing.allocator, "<a>&#x41;</a>", .{});
    defer ok.deinit();
}

test "not-wf: XMLDecl requires whitespace before encoding/standalone" {
    // XMLDecl ::= '<?xml' VersionInfo (S EncodingDecl)? (S SDDecl)? S? '?>' —
    // S is required immediately before EncodingDecl/SDDecl when present, but
    // only optional before the final '?>' when neither follows.
    try testing.expectError(error.MalformedPI, parse(testing.allocator, "<?xml version=\"1.0\"encoding=\"UTF-8\"?><a/>", .{}));
    try testing.expectError(error.MalformedPI, parse(testing.allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"standalone=\"no\"?><a/>", .{}));
    // No encoding/standalone at all: no whitespace required before '?>'.
    var ok = try parse(testing.allocator, "<?xml version=\"1.0\"?><a/>", .{});
    defer ok.deinit();
}

test "not-wf: literal noncharacter U+FFFE/U+FFFF rejected in text, attr value, comment, PI" {
    // isXmlChar already excluded #xFFFE/#xFFFF for numeric character
    // references (decodeReference), but plain text/attribute/comment/PI
    // parsing only checked raw bytes < 0x20 and let any well-formed-UTF-8
    // multi-byte sequence through unchecked — so a LITERAL (non-charref)
    // U+FFFF in content slipped past every existing guard.
    try testing.expectError(error.InvalidCharacter, parse(testing.allocator, "<a>\u{FFFF}</a>", .{}));
    try testing.expectError(error.InvalidCharacter, parse(testing.allocator, "<a>\u{FFFE}</a>", .{}));
    try testing.expectError(error.InvalidCharacter, parse(testing.allocator, "<a x=\"\u{FFFF}\"/>", .{}));
    try testing.expectError(error.InvalidCharacter, parse(testing.allocator, "<a><!--\u{FFFF}--></a>", .{}));
    try testing.expectError(error.InvalidCharacter, parse(testing.allocator, "<a><?pi \u{FFFF}?></a>", .{}));
    // The adjoining valid boundary must still be accepted.
    var ok = try parse(testing.allocator, "<a>\u{FFFD}</a>", .{});
    defer ok.deinit();
}

test "doctype=.ignore: internal subset skip is quote- and comment-aware" {
    // parseDoctype's `[ ... ]` skip used to stop at the FIRST raw ']' byte,
    // even inside a quoted literal or a comment — so an internal subset
    // containing e.g. `<!ENTITY rsqb "]">` truncated the subset early and
    // misparsed everything after it as document content (TrailingContent),
    // instead of skipping the whole subset and reaching &rsqb; as an
    // (expected, unsupported) UndefinedEntity.
    const quoted = "<!DOCTYPE doc [<!ELEMENT doc (#PCDATA)><!ENTITY rsqb \"]\">]><doc>&rsqb;</doc>";
    try testing.expectError(error.UndefinedEntity, parse(testing.allocator, quoted, .{ .doctype = .ignore }));
    const double_bracket = "<!DOCTYPE doc [<!ELEMENT doc (#PCDATA)><!ENTITY rsqb \"]]\">]><doc>&rsqb;</doc>";
    try testing.expectError(error.UndefinedEntity, parse(testing.allocator, double_bracket, .{ .doctype = .ignore }));
    const bracket_in_comment = "<!DOCTYPE doc [<!-- ] --><!ELEMENT doc (#PCDATA)>]><doc/>";
    var ok = try parse(testing.allocator, bracket_in_comment, .{ .doctype = .ignore });
    defer ok.deinit();
}

test "wf control: default-namespace undeclaration IS allowed" {
    var doc = try parse(testing.allocator, "<a xmlns=\"urn:d\"><b xmlns=\"\"/></a>", .{});
    defer doc.deinit();
    const b = doc.root.firstElementChild().?;
    try testing.expectEqualStrings("", b.uri); // back to no namespace
}

// ── security tests (with positive controls) ──────────────────────────────────

test "security XXE: DOCTYPE rejected by default (no file access possible)" {
    const payload =
        "<?xml version=\"1.0\"?>" ++
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" ++
        "<foo>&xxe;</foo>";
    // Default policy: the DOCTYPE itself is refused before any entity is seen.
    try testing.expectError(error.DoctypeForbidden, parse(testing.allocator, payload, .{}));
}

test "security XXE: with doctype=ignore, external entity is inert (undefined)" {
    const payload =
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" ++
        "<foo>&xxe;</foo>";
    // The DTD is skipped without parsing entity decls; the reference is thus
    // undefined — no file is ever opened (the parser has no filesystem access
    // path at all). Rejected, not expanded.
    try testing.expectError(error.UndefinedEntity, parse(testing.allocator, payload, .{ .doctype = .ignore }));
}

test "security XXE positive control: same doc without DOCTYPE parses" {
    var doc = try parse(testing.allocator, "<foo>plain</foo>", .{});
    defer doc.deinit();
    const t = try doc.root.textContent(testing.allocator);
    defer testing.allocator.free(t);
    try testing.expectEqualStrings("plain", t);
}

test "security billion-laughs: rejected without blowup (default reject DOCTYPE)" {
    const bomb =
        "<?xml version=\"1.0\"?>" ++
        "<!DOCTYPE lolz [" ++
        "<!ENTITY lol \"lol\">" ++
        "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">" ++
        "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">" ++
        "]>" ++
        "<lolz>&lol3;</lolz>";
    try testing.expectError(error.DoctypeForbidden, parse(testing.allocator, bomb, .{}));
}

test "security billion-laughs: also inert under doctype=ignore" {
    const bomb =
        "<!DOCTYPE lolz [" ++
        "<!ENTITY lol \"lol\">" ++
        "<!ENTITY lol2 \"&lol;&lol;\">" ++
        "]>" ++
        "<lolz>&lol2;</lolz>";
    // Custom entities are never defined → the reference is undefined; no
    // expansion, no memory growth.
    try testing.expectError(error.UndefinedEntity, parse(testing.allocator, bomb, .{ .doctype = .ignore }));
}

test "security depth: nesting past the cap is rejected" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const n = 300;
    var k: usize = 0;
    while (k < n) : (k += 1) try buf.appendSlice(testing.allocator, "<a>");
    while (k > 0) : (k -= 1) try buf.appendSlice(testing.allocator, "</a>");
    try testing.expectError(error.MaxDepthExceeded, parse(testing.allocator, buf.items, .{ .max_depth = 256 }));
}

test "security depth positive control: at-limit nesting is accepted" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const n = 200;
    var k: usize = 0;
    while (k < n) : (k += 1) try buf.appendSlice(testing.allocator, "<a>");
    while (k > 0) : (k -= 1) try buf.appendSlice(testing.allocator, "</a>");
    var doc = try parse(testing.allocator, buf.items, .{ .max_depth = 256 });
    defer doc.deinit();
    try testing.expectEqualStrings("a", doc.root.local);
}

test "security depth: exact boundary — max_depth levels accepted, max_depth+1 rejected" {
    // The existing "positive control" test checks depth 200 against a cap of
    // 256 — nowhere near the boundary, so an off-by-one in the depth guard
    // (rejecting one level early, or accepting one level too many) would not
    // be caught there. Pin the boundary itself, at a small cap so the
    // buffers stay readable.
    const gpa = testing.allocator;
    const cap = 5;

    var at_cap: std.ArrayList(u8) = .empty;
    defer at_cap.deinit(gpa);
    var k: usize = 0;
    while (k < cap) : (k += 1) try at_cap.appendSlice(gpa, "<a>");
    while (k > 0) : (k -= 1) try at_cap.appendSlice(gpa, "</a>");
    var doc = try parse(gpa, at_cap.items, .{ .max_depth = cap });
    defer doc.deinit();
    try testing.expectEqualStrings("a", doc.root.local);

    var over_cap: std.ArrayList(u8) = .empty;
    defer over_cap.deinit(gpa);
    k = 0;
    while (k < cap + 1) : (k += 1) try over_cap.appendSlice(gpa, "<a>");
    while (k > 0) : (k -= 1) try over_cap.appendSlice(gpa, "</a>");
    try testing.expectError(error.MaxDepthExceeded, parse(gpa, over_cap.items, .{ .max_depth = cap }));
}

test "security bounds: too many attributes rejected" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, "<a");
    var k: usize = 0;
    while (k < 20) : (k += 1) {
        try buf.print(testing.allocator, " a{d}=\"v\"", .{k});
    }
    try buf.appendSlice(testing.allocator, "/>");
    try testing.expectError(error.TooManyAttributes, parse(testing.allocator, buf.items, .{ .max_attributes = 8 }));
}

test "security bounds: exact boundary — max_attributes accepted, max_attributes+1 rejected" {
    // The existing test checks 20 attributes against a cap of 8 — nowhere
    // near the boundary, so an off-by-one (allowing one attribute too many,
    // or rejecting one too few) would not be caught there.
    const gpa = testing.allocator;
    const cap = 4;

    var at_cap: std.ArrayList(u8) = .empty;
    defer at_cap.deinit(gpa);
    try at_cap.appendSlice(gpa, "<a");
    var k: usize = 0;
    while (k < cap) : (k += 1) try at_cap.print(gpa, " a{d}=\"v\"", .{k});
    try at_cap.appendSlice(gpa, "/>");
    var doc = try parse(gpa, at_cap.items, .{ .max_attributes = cap });
    defer doc.deinit();
    try testing.expectEqual(@as(usize, cap), doc.root.attributes.len);

    var over_cap: std.ArrayList(u8) = .empty;
    defer over_cap.deinit(gpa);
    try over_cap.appendSlice(gpa, "<a");
    k = 0;
    while (k < cap + 1) : (k += 1) try over_cap.print(gpa, " a{d}=\"v\"", .{k});
    try over_cap.appendSlice(gpa, "/>");
    try testing.expectError(error.TooManyAttributes, parse(gpa, over_cap.items, .{ .max_attributes = cap }));
}

test "security bounds: per-element duplicate detection is linear in k, not quadratic" {
    // `max_attributes` caps how many attributes an element may carry; it does
    // not cap what they cost. Every duplicate check here used to rescan the
    // list it was building, so one element at the default cap of 4096 spent
    // k(k-1)/2 ≈ 8.4 M name comparisons — measured at 89 ms of CPU for a
    // single 127 KB element, on a parser that runs *before* authentication and
    // that xmldsig/xmlenc/saml all sit on top of.
    //
    // Assert the complexity, not the wall clock: `Stats.dup_compares` counts
    // the comparisons/probes the three duplicate-detection sites perform, so
    // this pins O(k) deterministically instead of flaking on a loaded CI box.
    const gpa = testing.allocator;
    const k = 2048;

    // (a) plain attributes — the expanded-name duplicate check.
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r");
        for (0..k) |i| try buf.print(gpa, " a{d}=\"v\"", .{i});
        try buf.appendSlice(gpa, "/>");

        var st: Stats = .{};
        var doc = try parseCounted(gpa, buf.items, .{}, &st);
        defer doc.deinit();
        try testing.expectEqual(@as(usize, k), doc.root.attributes.len);
        try testing.expect(st.dup_compares <= 6 * k);
    }

    // (b) namespace declarations, plus the per-attribute prefix resolution
    //     that scans them — same quadratic shape, reached by a document that
    //     declares k prefixes and then uses each of them once.
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r");
        for (0..k) |i| try buf.print(gpa, " xmlns:p{d}=\"urn:x{d}\"", .{ i, i });
        for (0..k) |i| try buf.print(gpa, " p{d}:a=\"v\"", .{i});
        try buf.appendSlice(gpa, "/>");

        var st: Stats = .{};
        var doc = try parseCounted(gpa, buf.items, .{}, &st);
        defer doc.deinit();
        try testing.expectEqual(@as(usize, k), doc.root.ns_decls.len);
        try testing.expectEqualStrings("urn:x7", doc.root.attributes[7].uri);
        try testing.expect(st.dup_compares <= 6 * k);
    }

    // The behaviour these fast paths replace must be unchanged: duplicates are
    // still rejected, on both sides of `dup_scan_threshold`, and both by
    // expanded name rather than by spelling.
    try testing.expectError(error.DuplicateAttribute, parse(gpa, "<r a=\"1\" a=\"2\"/>", .{}));
    try testing.expectError(error.NamespaceError, parse(gpa, "<r xmlns:p=\"urn:a\" xmlns:p=\"urn:b\"/>", .{}));
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r xmlns:p=\"urn:x\" xmlns:q=\"urn:x\"");
        for (0..k) |i| try buf.print(gpa, " a{d}=\"v\"", .{i});
        // Distinct spellings, one expanded name — must still be a duplicate.
        try buf.appendSlice(gpa, " p:dup=\"1\" q:dup=\"2\"/>");
        try testing.expectError(error.DuplicateAttribute, parse(gpa, buf.items, .{}));
    }
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r");
        for (0..k) |i| try buf.print(gpa, " xmlns:p{d}=\"urn:x{d}\"", .{ i, i });
        try buf.appendSlice(gpa, " xmlns:p0=\"urn:again\"/>");
        try testing.expectError(error.NamespaceError, parse(gpa, buf.items, .{}));
    }
    {
        // Above the threshold, a prefix declared on an *ancestor* must still
        // resolve, and an undeclared one must still be refused.
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r xmlns:up=\"urn:up\"><c");
        for (0..k) |i| try buf.print(gpa, " xmlns:p{d}=\"urn:x{d}\"", .{ i, i });
        try buf.appendSlice(gpa, " up:a=\"1\" xml:lang=\"en\"/></r>");
        var doc = try parse(gpa, buf.items, .{});
        defer doc.deinit();
        const c = doc.root.children[0].content.element;
        try testing.expectEqualStrings("urn:up", c.attributes[0].uri);
        try testing.expectEqualStrings(xml_ns, c.attributes[1].uri);

        var bad: std.ArrayList(u8) = .empty;
        defer bad.deinit(gpa);
        try bad.appendSlice(gpa, "<r><c");
        for (0..k) |i| try bad.print(gpa, " xmlns:p{d}=\"urn:x{d}\"", .{ i, i });
        try bad.appendSlice(gpa, " nope:a=\"1\"/></r>");
        try testing.expectError(error.UndeclaredNamespacePrefix, parse(gpa, bad.items, .{}));
    }
}

/// The parent-axis walk `resolveNs` used to be, kept as a differential oracle:
/// the scope chain must answer identically, including precedence and the
/// null/"" distinction. Deliberately NOT written in terms of `NsScope`.
fn resolveNsReference(el: *const Element, prefix: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, prefix, "xml")) return xml_ns;
    if (std.mem.eql(u8, prefix, "xmlns")) return xmlns_ns;
    var cur: ?*const Element = el;
    while (cur) |e| : (cur = e.parent) {
        for (e.ns_decls) |d| {
            if (std.mem.eql(u8, d.prefix, prefix)) return d.uri;
        }
    }
    if (prefix.len == 0) return "";
    return null;
}

fn checkResolveAgreesEverywhere(el: *const Element, prefixes: []const []const u8) !void {
    for (prefixes) |p| {
        const got = el.resolveNs(p);
        const want = resolveNsReference(el, p);
        if (want == null or got == null) {
            try testing.expect((want == null) == (got == null));
        } else {
            try testing.expectEqualStrings(want.?, got.?);
        }
    }
    for (el.children) |c| switch (c.content) {
        .element => |e| try checkResolveAgreesEverywhere(e, prefixes),
        else => {},
    };
}

test "complexity: Element.resolveNs is O(1) in depth and in declaration count" {
    // `resolveNs` is a PUBLIC entry point, and `c14n`/`xmldsig` call it once
    // per attribute per element. The parser's own duplicate/namespace paths
    // were indexed earlier; `resolveNs` itself stayed a linear walk of every
    // declaration on every ancestor, so a consumer calling it per attribute
    // kept exactly the O(decls × depth) shape the parser had shed — reachable
    // pre-authentication through SAML/xmldsig, like every other bound here.
    //
    // Assert the complexity, not the wall clock: `resolveNsCounted` reports
    // prefix probes, so this pins the class deterministically. (Measured for
    // the record: a 4000-deep document costs 51.4 ms of consumer-side
    // resolution before this change and 0.13 ms after; exclusive C14N over
    // the same document, 31.6 ms -> 1.1 ms.)
    const gpa = testing.allocator;

    // (a) Depth. The prefix is declared once at the root and used far below.
    // Every element in between declares nothing, so the answer is one hop
    // away no matter how deep the use site is.
    {
        const depth = 2048;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r xmlns:p=\"urn:p\">");
        for (0..depth) |_| try buf.appendSlice(gpa, "<e>");
        try buf.appendSlice(gpa, "<leaf p:a=\"1\"/>");
        for (0..depth) |_| try buf.appendSlice(gpa, "</e>");
        try buf.appendSlice(gpa, "</r>");

        var doc = try parse(gpa, buf.items, .{ .max_depth = depth + 4 });
        defer doc.deinit();

        var leaf: *const Element = doc.root;
        while (leaf.firstElementChild()) |c| leaf = c;
        try testing.expectEqualStrings("leaf", leaf.local);
        try testing.expectEqualStrings("urn:p", leaf.attributes[0].uri);

        var probes: usize = 0;
        try testing.expectEqualStrings("urn:p", leaf.resolveNsCounted("p", &probes).?);
        try testing.expect(probes <= 8);

        // A prefix that is nowhere in scope must also cost O(1): it is the
        // miss, not the hit, that walks the whole axis.
        probes = 0;
        try testing.expect(leaf.resolveNsCounted("nope", &probes) == null);
        try testing.expect(probes <= 8);
    }

    // (b) Width. k declarations on one element, each prefix resolved once —
    // O(k) in total, not O(k²).
    {
        const k = 2048;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<r");
        for (0..k) |i| try buf.print(gpa, " xmlns:p{d}=\"urn:x{d}\"", .{ i, i });
        try buf.appendSlice(gpa, "/>");

        var doc = try parse(gpa, buf.items, .{});
        defer doc.deinit();

        var name: [32]u8 = undefined;
        var total: usize = 0;
        for (0..k) |i| {
            const pfx = try std.fmt.bufPrint(&name, "p{d}", .{i});
            var probes: usize = 0;
            const uri = doc.root.resolveNsCounted(pfx, &probes) orelse return error.TestUnexpectedResult;
            var want: [32]u8 = undefined;
            try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "urn:x{d}", .{i}), uri);
            total += probes;
        }
        try testing.expect(total <= 6 * k);
    }
}

test "behaviour: resolveNs answers exactly what the parent-axis walk answers" {
    // The accelerator must not move a single answer: nearest declaration wins,
    // `xml`/`xmlns` outrank any declaration, `xmlns=""` undeclares the default,
    // an unknown prefix is null while an absent default is "".
    const gpa = testing.allocator;
    const src =
        \\<r xmlns="urn:d" xmlns:a="urn:a1" xmlns:b="urn:b">
        \\  <m xmlns:a="urn:a2"><deep a:x="1" b:y="2"/></m>
        \\  <n xmlns=""><plain/></n>
        \\  <o><p xmlns:c="urn:c"><q/></p></o>
        \\</r>
    ;
    var doc = try parse(gpa, src, .{});
    defer doc.deinit();

    const prefixes = [_][]const u8{ "", "a", "b", "c", "xml", "xmlns", "zz" };
    try checkResolveAgreesEverywhere(doc.root, &prefixes);

    // Spot-check the specific rules rather than trusting the differential
    // alone (a reference that is wrong in the same way proves nothing).
    const m = doc.root.children[1].content.element;
    try testing.expectEqualStrings("m", m.local);
    const deep = m.firstElementChild().?;
    try testing.expectEqualStrings("urn:a2", deep.resolveNs("a").?); // shadowed
    try testing.expectEqualStrings("urn:b", deep.resolveNs("b").?); // inherited
    try testing.expectEqualStrings("urn:d", deep.resolveNs("").?);
    try testing.expectEqualStrings(xml_ns, deep.resolveNs("xml").?);
    try testing.expect(deep.resolveNs("c") == null); // declared on a sibling axis

    const n = doc.root.children[3].content.element;
    try testing.expectEqualStrings("n", n.local);
    try testing.expectEqualStrings("", n.firstElementChild().?.resolveNs("").?); // undeclared default

    // A hand-assembled tree carries no scope chain; it must still resolve.
    var root: Element = .{
        .prefix = "",
        .local = "r",
        .uri = "",
        .ns_decls = &.{.{ .prefix = "h", .uri = "urn:h" }},
        .attributes = &.{},
        .children = &.{},
        .parent = null,
        .span = .{ .start = 0, .end = 0 },
    };
    var child: Element = root;
    child.local = "c";
    child.ns_decls = &.{};
    child.parent = &root;
    try testing.expect(child.ns_scope == null);
    try testing.expectEqualStrings("urn:h", child.resolveNs("h").?);
    try testing.expect(child.resolveNs("zz") == null);
}

test "security: duplicate ID rejected (signature-wrapping guard)" {
    try testing.expectError(error.DuplicateId, parse(testing.allocator, "<r><a ID=\"x\"/><b ID=\"x\"/></r>", .{}));
}

test "security: invalid UTF-8 rejected" {
    try testing.expectError(error.InvalidCharacter, parse(testing.allocator, "<a>\xFF\xFE</a>", .{}));
}

test "unsupported: non-UTF-8 encoding declaration rejected" {
    try testing.expectError(error.UnsupportedEncoding, parse(testing.allocator, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>", .{}));
}

test "unsupported: XML 1.1 version rejected" {
    try testing.expectError(error.UnsupportedVersion, parse(testing.allocator, "<?xml version=\"1.1\"?><a/>", .{}));
}

// ── fuzz: document parse off arbitrary bytes, never panics ─────────────────
//
// `parse` is the canonical XML fuzz target: this collection's own
// `xmldsig`/`saml`/`xmlenc` all sit on top of it, so a crash here is a
// crash in every one of them too. Bias the byte pool toward XML's own
// syntax characters (`<>/="'&;`) so the fuzzer reaches the tag/attribute/
// entity state machines instead of bouncing off "doesn't even start with
// `<`" on the first byte.

test "fuzz: parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "<>/=\"'&;! ?abcCDATA0123\n\t";
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 3)) c.* = alphabet[c.* % alphabet.len];
    }

    var doc = parse(testing.allocator, buf[0..len], .{}) catch return;
    doc.deinit();
}

// ── vendored W3C XML Conformance Test Suite (xmlconf) ────────────────────────
// See xmlconf_test.zig / xmlconf_vectors.zig / NOTICE.
test {
    _ = @import("xmlconf_test.zig");
}
