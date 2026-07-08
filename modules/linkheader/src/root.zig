// SPDX-License-Identifier: MIT
//! linkheader — Web Linking (RFC 8288) `Link` header builder + parser.
//!
//! Serialises a `[]const Link` into a `Link:` header *value* and parses one
//! back, both allocation-free: the builder writes into a caller buffer (or any
//! `*std.Io.Writer`), and the parser is an iterator whose yielded `Link`s
//! borrow the input header. This is the little codec every REST client needs
//! for RFC 5988/8288 pagination — `<…?page=2>; rel="next", <…?page=1>;
//! rel="prev"`.
//!
//! Scope, and its edges:
//!   - Params modelled: `rel`, `title`, `type`, `hreflang` (the common set).
//!     Unknown params are tolerated on parse (skipped) — the grammar is still
//!     honoured so they never desync the scanner.
//!   - Percent-encoding of the URI is the caller's job; URIs pass through the
//!     builder verbatim between the `<>` delimiters.
//!   - The builder quotes every param value and backslash-escapes any `"`/`\`.
//!     The parser tracks those escapes while scanning (so a quoted `,`/`;`/`>`
//!     never ends a link early) but returns the quoted content **verbatim**,
//!     escapes included — it borrows the input and never allocates to unescape.
//!     For plain ASCII values (the overwhelming case) that is byte-identical.
//!   - Malformed links are skipped, never a panic: a segment with no `<…>`, an
//!     unterminated `<`, or a stray separator advances the iterator to the next
//!     top-level comma and parsing continues. A link with no `rel` is dropped
//!     (RFC 8288 requires `rel`).
//!
//! Clean-room from RFC 8288 (Web Linking); no third-party code.

const std = @import("std");
const ascii = std.ascii;

pub const meta = .{
    .status = .gap, // no Web-Linking codec in std; build it
    .platform = .any, // pure byte logic, no OS calls
    .role = .codec, // pure wire format, no I/O of its own
    .concurrency = .reentrant, // no shared state, no allocation
    .model_after = "RFC 8288 (Web Linking)",
    .deps = .{}, // std only
};

// ── model ────────────────────────────────────────────────────────────────────

/// One web link: a target URI plus its relation and the common descriptive
/// params. Fields other than `uri`/`rel` are optional. On parse the string
/// fields borrow the header buffer.
pub const Link = struct {
    /// Target URI, written between `<` and `>`. Caller owns percent-encoding.
    uri: []const u8,
    /// Link relation type (RFC 8288 `rel`), e.g. `"next"`; may be a
    /// whitespace-separated list of relations. Required.
    rel: []const u8,
    /// Human-readable label for the destination (`title`).
    title: ?[]const u8 = null,
    /// Media type hint for the destination (`type`), e.g. `"application/json"`.
    type: ?[]const u8 = null,
    /// Language of the destination (`hreflang`), e.g. `"en"`.
    hreflang: ?[]const u8 = null,
};

// ── build (serialise) ────────────────────────────────────────────────────────

/// Serialise `links` into a `Link` header value on `w`. Links are joined with
/// `", "`; each is `<uri>; rel="…"` followed by the present optional params.
/// Param values are quoted and `"`/`\` are backslash-escaped.
pub fn write(w: *std.Io.Writer, links: []const Link) std.Io.Writer.Error!void {
    for (links, 0..) |link, i| {
        if (i != 0) try w.writeAll(", ");
        try writeOne(w, link);
    }
}

/// Serialise `links` into `buf`, returning the used prefix. `error.NoSpaceLeft`
/// if `buf` is too small.
pub fn bufPrint(buf: []u8, links: []const Link) error{NoSpaceLeft}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    write(&w, links) catch return error.NoSpaceLeft;
    return w.buffered();
}

fn writeOne(w: *std.Io.Writer, link: Link) std.Io.Writer.Error!void {
    try w.writeByte('<');
    try w.writeAll(link.uri);
    try w.writeAll(">; rel=");
    try writeQuoted(w, link.rel);
    if (link.title) |v| {
        try w.writeAll("; title=");
        try writeQuoted(w, v);
    }
    if (link.type) |v| {
        try w.writeAll("; type=");
        try writeQuoted(w, v);
    }
    if (link.hreflang) |v| {
        try w.writeAll("; hreflang=");
        try writeQuoted(w, v);
    }
}

fn writeQuoted(w: *std.Io.Writer, v: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (v) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

// ── parse ────────────────────────────────────────────────────────────────────

/// Begin iterating over the links in a `Link` header value. Yielded `Link`s
/// borrow `header`; do not free `header` while a yielded link is in use.
pub fn parse(header: []const u8) Iterator {
    return .{ .s = header };
}

/// Forward-only, allocation-free iterator over a `Link` header value.
pub const Iterator = struct {
    s: []const u8,
    i: usize = 0,

    /// The next well-formed link, or null at end. Malformed segments are
    /// skipped (never a panic); a link with no `rel` is dropped.
    pub fn next(self: *Iterator) ?Link {
        while (self.i < self.s.len) {
            self.skipWs();
            if (self.i < self.s.len and self.s[self.i] == ',') {
                self.i += 1; // stray/empty segment
                continue;
            }
            if (self.i >= self.s.len) return null;
            if (self.s[self.i] != '<') {
                self.skipToNextLink();
                continue;
            }
            self.i += 1; // consume '<'
            const uri_start = self.i;
            const gt = std.mem.indexOfScalarPos(u8, self.s, self.i, '>') orelse {
                self.i = self.s.len; // unterminated '<' — give up
                return null;
            };
            var link: Link = .{ .uri = self.s[uri_start..gt], .rel = "" };
            self.i = gt + 1;
            self.parseParams(&link);
            if (link.rel.len == 0) continue; // RFC 8288: rel is required
            return link;
        }
        return null;
    }

    fn parseParams(self: *Iterator, link: *Link) void {
        while (true) {
            self.skipWs();
            if (self.i >= self.s.len) return;
            const c = self.s[self.i];
            if (c == ',') {
                self.i += 1; // end of this link
                return;
            }
            if (c != ';') {
                self.skipToNextLink(); // unexpected byte — resync
                return;
            }
            self.i += 1; // consume ';'
            self.skipWs();
            const name_start = self.i;
            while (self.i < self.s.len and !isNameEnd(self.s[self.i])) self.i += 1;
            const name = self.s[name_start..self.i];
            self.skipWs();
            var value: []const u8 = "";
            if (self.i < self.s.len and self.s[self.i] == '=') {
                self.i += 1;
                self.skipWs();
                value = self.readValue();
            }
            if (name.len == 0) continue;
            assign(link, name, value);
        }
    }

    /// Read a param value: a quoted-string (returned without the surrounding
    /// quotes, escapes left intact) or a bare token.
    fn readValue(self: *Iterator) []const u8 {
        if (self.i < self.s.len and self.s[self.i] == '"') {
            self.i += 1;
            const start = self.i;
            while (self.i < self.s.len) {
                const c = self.s[self.i];
                if (c == '\\') {
                    self.i += 2; // skip escaped byte
                    continue;
                }
                if (c == '"') {
                    const v = self.s[start..self.i];
                    self.i += 1;
                    return v;
                }
                self.i += 1;
            }
            return self.s[start..self.s.len]; // unterminated quote
        }
        const start = self.i;
        while (self.i < self.s.len and !isTokenEnd(self.s[self.i])) self.i += 1;
        return self.s[start..self.i];
    }

    /// Advance to just past the next top-level comma (quotes respected), or to
    /// end — guarantees forward progress out of a malformed segment.
    fn skipToNextLink(self: *Iterator) void {
        var in_quotes = false;
        while (self.i < self.s.len) {
            const c = self.s[self.i];
            if (in_quotes) {
                if (c == '\\') {
                    self.i += 2;
                    continue;
                }
                if (c == '"') in_quotes = false;
                self.i += 1;
            } else if (c == '"') {
                in_quotes = true;
                self.i += 1;
            } else if (c == ',') {
                self.i += 1;
                return;
            } else {
                self.i += 1;
            }
        }
    }

    fn skipWs(self: *Iterator) void {
        while (self.i < self.s.len and isWs(self.s[self.i])) self.i += 1;
    }
};

fn assign(link: *Link, name: []const u8, value: []const u8) void {
    // First occurrence of each param wins (RFC 8288 §3.3, §3.4).
    if (ascii.eqlIgnoreCase(name, "rel")) {
        if (link.rel.len == 0) link.rel = value;
    } else if (ascii.eqlIgnoreCase(name, "title")) {
        if (link.title == null) link.title = value;
    } else if (ascii.eqlIgnoreCase(name, "type")) {
        if (link.type == null) link.type = value;
    } else if (ascii.eqlIgnoreCase(name, "hreflang")) {
        if (link.hreflang == null) link.hreflang = value;
    }
}

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

fn isNameEnd(c: u8) bool {
    return c == '=' or c == ';' or c == ',' or isWs(c);
}

fn isTokenEnd(c: u8) bool {
    return c == ';' or c == ',' or c == '"' or isWs(c);
}

// ── convenience ──────────────────────────────────────────────────────────────

/// URIs for the four standard pagination relations. Any subset may be set.
pub const PaginationOpts = struct {
    first: ?[]const u8 = null,
    prev: ?[]const u8 = null,
    next: ?[]const u8 = null,
    last: ?[]const u8 = null,
};

/// Fill `out` with a `Link` (rel = first/prev/next/last) for each URI present
/// in `opts`, in that order, and return the used prefix — hand it to `write`
/// or `bufPrint`. Allocation-free (the URIs are borrowed from `opts`).
pub fn pagination(out: *[4]Link, opts: PaginationOpts) []const Link {
    var n: usize = 0;
    if (opts.first) |u| {
        out[n] = .{ .uri = u, .rel = "first" };
        n += 1;
    }
    if (opts.prev) |u| {
        out[n] = .{ .uri = u, .rel = "prev" };
        n += 1;
    }
    if (opts.next) |u| {
        out[n] = .{ .uri = u, .rel = "next" };
        n += 1;
    }
    if (opts.last) |u| {
        out[n] = .{ .uri = u, .rel = "last" };
        n += 1;
    }
    return out[0..n];
}

/// The first link in `header` whose `rel` matches `rel` (ASCII case-insensitive;
/// matches any token of a whitespace-separated `rel` list). Null if none.
pub fn find(header: []const u8, rel: []const u8) ?Link {
    var it = parse(header);
    while (it.next()) |link| {
        if (relMatches(link.rel, rel)) return link;
    }
    return null;
}

fn relMatches(field: []const u8, want: []const u8) bool {
    var toks = std.mem.tokenizeAny(u8, field, " \t\r\n");
    while (toks.next()) |t| {
        if (ascii.eqlIgnoreCase(t, want)) return true;
    }
    return false;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "build: single link" {
    var buf: [128]u8 = undefined;
    const out = try bufPrint(&buf, &.{
        .{ .uri = "https://api/x?page=2", .rel = "next" },
    });
    try testing.expectEqualStrings("<https://api/x?page=2>; rel=\"next\"", out);
}

test "build: multiple links joined with comma-space" {
    var buf: [256]u8 = undefined;
    const out = try bufPrint(&buf, &.{
        .{ .uri = "https://api/x?page=2", .rel = "next" },
        .{ .uri = "https://api/x?page=1", .rel = "prev" },
    });
    try testing.expectEqualStrings(
        "<https://api/x?page=2>; rel=\"next\", <https://api/x?page=1>; rel=\"prev\"",
        out,
    );
}

test "build: optional params emitted in order" {
    var buf: [256]u8 = undefined;
    const out = try bufPrint(&buf, &.{
        .{ .uri = "/a", .rel = "alternate", .title = "Home", .type = "text/html", .hreflang = "en" },
    });
    try testing.expectEqualStrings(
        "</a>; rel=\"alternate\"; title=\"Home\"; type=\"text/html\"; hreflang=\"en\"",
        out,
    );
}

test "build: quotes and backslashes escaped" {
    var buf: [128]u8 = undefined;
    const out = try bufPrint(&buf, &.{
        .{ .uri = "/a", .rel = "x", .title = "a\"b\\c" },
    });
    try testing.expectEqualStrings("</a>; rel=\"x\"; title=\"a\\\"b\\\\c\"", out);
}

test "build: NoSpaceLeft on tiny buffer" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, bufPrint(&buf, &.{
        .{ .uri = "https://example.com/very/long", .rel = "next" },
    }));
}

test "build: to a growable writer via Allocating" {
    var w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer w.deinit();
    try write(&w.writer, &.{.{ .uri = "/a", .rel = "self" }});
    try testing.expectEqualStrings("</a>; rel=\"self\"", w.written());
}

test "parse: single link" {
    var it = parse("<https://api/x?page=2>; rel=\"next\"");
    const l = it.next().?;
    try testing.expectEqualStrings("https://api/x?page=2", l.uri);
    try testing.expectEqualStrings("next", l.rel);
    try testing.expect(l.title == null);
    try testing.expect(it.next() == null);
}

test "parse: multiple links and all params" {
    var it = parse(
        "<u1>; rel=\"next\"; title=\"Page 2\"; type=\"application/json\", " ++
            "<u2>; rel=\"prev\"; hreflang=\"en\"",
    );
    const a = it.next().?;
    try testing.expectEqualStrings("u1", a.uri);
    try testing.expectEqualStrings("next", a.rel);
    try testing.expectEqualStrings("Page 2", a.title.?);
    try testing.expectEqualStrings("application/json", a.type.?);
    const b = it.next().?;
    try testing.expectEqualStrings("u2", b.uri);
    try testing.expectEqualStrings("prev", b.rel);
    try testing.expectEqualStrings("en", b.hreflang.?);
    try testing.expect(it.next() == null);
}

test "parse: token (unquoted) param value" {
    var it = parse("<u>; rel=next; type=text/html");
    const l = it.next().?;
    try testing.expectEqualStrings("next", l.rel);
    try testing.expectEqualStrings("text/html", l.type.?);
}

test "parse: surrounding and inter-token whitespace tolerated" {
    var it = parse("  <u>  ;  rel = \"next\" ,  <v> ; rel=\"prev\"  ");
    const a = it.next().?;
    try testing.expectEqualStrings("u", a.uri);
    try testing.expectEqualStrings("next", a.rel);
    const b = it.next().?;
    try testing.expectEqualStrings("v", b.uri);
    try testing.expectEqualStrings("prev", b.rel);
    try testing.expect(it.next() == null);
}

test "parse: comma inside the URI does not split the link" {
    var it = parse("<https://api/x?ids=1,2,3>; rel=\"next\"");
    const l = it.next().?;
    try testing.expectEqualStrings("https://api/x?ids=1,2,3", l.uri);
    try testing.expectEqualStrings("next", l.rel);
    try testing.expect(it.next() == null);
}

test "parse: comma and semicolon inside a quoted value" {
    var it = parse("<u>; rel=\"next\"; title=\"a, b; c\", <v>; rel=\"prev\"");
    const a = it.next().?;
    try testing.expectEqualStrings("a, b; c", a.title.?);
    const b = it.next().?;
    try testing.expectEqualStrings("prev", b.rel);
}

test "parse: unknown params ignored without desync" {
    var it = parse("<u>; foo=bar; rel=\"next\"; baz=\"x, y\"; media=screen");
    const l = it.next().?;
    try testing.expectEqualStrings("next", l.rel);
    try testing.expect(it.next() == null);
}

test "parse: first occurrence of a param wins" {
    var it = parse("<u>; rel=\"next\"; rel=\"prev\"; title=\"A\"; title=\"B\"");
    const l = it.next().?;
    try testing.expectEqualStrings("next", l.rel);
    try testing.expectEqualStrings("A", l.title.?);
}

test "parse: case-insensitive param names" {
    var it = parse("<u>; REL=\"next\"; Title=\"T\"");
    const l = it.next().?;
    try testing.expectEqualStrings("next", l.rel);
    try testing.expectEqualStrings("T", l.title.?);
}

test "parse: malformed segments skipped, valid ones survive" {
    // no angle brackets, then a link with no rel, then a good one
    var it = parse("garbage, <u>; title=\"no rel\", <v>; rel=\"next\"");
    const l = it.next().?;
    try testing.expectEqualStrings("v", l.uri);
    try testing.expectEqualStrings("next", l.rel);
    try testing.expect(it.next() == null);
}

test "parse: empty and whitespace-only input" {
    for ([_][]const u8{ "", "   \t ", ",,," }) |s| {
        var it = parse(s);
        try testing.expect(it.next() == null);
    }
}

test "parse: unterminated angle bracket is not a panic" {
    var it = parse("<https://api/x; rel=\"next\"");
    try testing.expect(it.next() == null);
}

test "roundtrip: build then parse" {
    const links = [_]Link{
        .{ .uri = "/a", .rel = "next", .title = "Next page" },
        .{ .uri = "/b", .rel = "prev", .type = "application/json" },
    };
    var buf: [256]u8 = undefined;
    const s = try bufPrint(&buf, &links);
    var it = parse(s);
    const a = it.next().?;
    try testing.expectEqualStrings("/a", a.uri);
    try testing.expectEqualStrings("next", a.rel);
    try testing.expectEqualStrings("Next page", a.title.?);
    const b = it.next().?;
    try testing.expectEqualStrings("/b", b.uri);
    try testing.expectEqualStrings("prev", b.rel);
    try testing.expectEqualStrings("application/json", b.type.?);
    try testing.expect(it.next() == null);
}

test "find: by rel, including a token within a rel list" {
    const h = "<u1>; rel=\"next\", <u2>; rel=\"prev start\", <u3>; rel=\"last\"";
    try testing.expectEqualStrings("u1", find(h, "next").?.uri);
    try testing.expectEqualStrings("u3", find(h, "last").?.uri);
    // "start" is one token of u2's whitespace-separated rel list
    try testing.expectEqualStrings("u2", find(h, "start").?.uri);
    // case-insensitive
    try testing.expectEqualStrings("u1", find(h, "NEXT").?.uri);
    try testing.expect(find(h, "first") == null);
}

test "pagination: builds present rels in order" {
    var slots: [4]Link = undefined;
    const links = pagination(&slots, .{
        .first = "/p/1",
        .next = "/p/3",
        .last = "/p/9",
    });
    try testing.expectEqual(@as(usize, 3), links.len);
    var buf: [256]u8 = undefined;
    const s = try bufPrint(&buf, links);
    try testing.expectEqualStrings(
        "</p/1>; rel=\"first\", </p/3>; rel=\"next\", </p/9>; rel=\"last\"",
        s,
    );
}

test "pagination: empty opts yields no links" {
    var slots: [4]Link = undefined;
    try testing.expectEqual(@as(usize, 0), pagination(&slots, .{}).len);
}
