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
//!   - Params modelled as fields: `rel`, `anchor`, `title`, `title*`, `type`,
//!     `hreflang`, `media`. EVERY param of a parsed link — modelled or not,
//!     repeated or not — is reachable through `Link.params()` / `Link.param()`,
//!     borrowed from the header. The builder writes extension params from
//!     `Link.extra`.
//!   - `title*` and other `*`-params use RFC 8187 extended notation:
//!     `decodeExtValue` / `encodeExtValue` translate it, `Link.preferredTitle`
//!     applies RFC 8288 §3.4.1's "prefer `title*`".
//!   - The builder quotes every ordinary param value and backslash-escapes any
//!     `"`/`\`. The parser tracks those escapes while scanning (so a quoted
//!     `,`/`;`/`>` never ends a link early) but returns the quoted content
//!     **verbatim**, escapes included; `unquote` removes them into a caller
//!     buffer.
//!   - The builder refuses (`error.InvalidLink`, before writing any byte of
//!     that link) what cannot be serialised faithfully: a URI holding a control
//!     byte, space, `<`, `>` or `"`; a quoted value holding a control byte; a
//!     `*`-param that is not a well-formed ext-value; an empty `rel`; an
//!     extension param name that is not a token. So a header value it writes
//!     can neither smuggle a line break nor parse back differently.
//!   - URIs are passed through verbatim (percent-encoding is the caller's);
//!     `resolve` turns a relative target or `anchor` into an absolute URI
//!     against a base (RFC 3986 §5.2, via `std.Uri`).
//!   - Malformed links are skipped, never a panic: a segment with no `<…>`, an
//!     unterminated `<`, or a stray separator advances the iterator to the next
//!     top-level comma and parsing continues. A link with no `rel` is dropped
//!     (RFC 8288 requires `rel`).
//!
//! Clean-room from RFC 8288 (Web Linking), RFC 8187 and RFC 3986; no
//! third-party code.

const std = @import("std");
const ascii = std.ascii;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Web Linking (RFC 8288) `Link` header build + parse: every param (anchor/media/title*/extensions), RFC 8187 ext-values, unquote, RFC 3986 target resolution, `pagination` + `find(rel)`; zero-alloc, injection-safe builder.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure byte logic, no OS calls
    .role = .codec, // pure wire format, no I/O of its own
    .concurrency = .reentrant, // no shared state, no allocation
    .model_after = "RFC 8288 (Web Linking)",
    .deps = .{}, // std only
};

// ── model ────────────────────────────────────────────────────────────────────

/// One link-param, `name[=value]`.
///
/// On parse both slices borrow the header and `quoted` says whether the value
/// was a quoted-string (its `\` escapes are then still in `value`; `unquote`
/// removes them). On build `quoted` is ignored: a name ending in `*` is
/// written bare as an RFC 8187 ext-value, every other value is quoted.
pub const Param = struct {
    name: []const u8,
    value: []const u8 = "",
    quoted: bool = false,
};

/// One web link: a target URI plus its relation and the descriptive params.
/// Fields other than `uri`/`rel` are optional. On parse the string fields
/// borrow the header buffer, and quoted values keep their `\` escapes.
pub const Link = struct {
    /// Target URI, written between `<` and `>`. Caller owns percent-encoding.
    /// May be a relative reference — see `resolve`.
    uri: []const u8,
    /// Link relation type (RFC 8288 `rel`), e.g. `"next"`; may be a
    /// whitespace-separated list of relations. Required.
    rel: []const u8,
    /// Context override (`anchor`, RFC 8288 §3.2): the link is about this URI
    /// instead of the resource that carried the header. May be relative.
    anchor: ?[]const u8 = null,
    /// Human-readable label for the destination (`title`).
    title: ?[]const u8 = null,
    /// The same label in RFC 8187 extended notation (`title*`), raw, e.g.
    /// `UTF-8'de'letztes%20Kapitel`. `decodeExtValue` reads it,
    /// `encodeExtValue` makes one; `preferredTitle` picks between the two.
    title_star: ?[]const u8 = null,
    /// Media type hint for the destination (`type`), e.g. `"application/json"`.
    type: ?[]const u8 = null,
    /// Language of the destination (`hreflang`), e.g. `"en"`. RFC 8288 lets it
    /// repeat; this is the first, `params()` yields all of them.
    hreflang: ?[]const u8 = null,
    /// Media query the destination is for (`media`), e.g. `"screen"`.
    media: ?[]const u8 = null,
    /// Build only: further params, written after the modelled ones in order
    /// (preload's `as`/`crossorigin`, API-specific ones). Ignored by parse.
    extra: []const Param = &.{},
    /// Parse only: the link's whole param region — every `; name=value` after
    /// the `>` — borrowed from the header. Ignored by the builder.
    raw_params: []const u8 = "",

    /// Every param of a parsed link in header order, including the modelled
    /// ones, unknown ones and repeats.
    pub fn params(self: Link) ParamIterator {
        return .{ .s = self.raw_params };
    }

    /// The first param of a parsed link named `name` (ASCII case-insensitive),
    /// or null.
    pub fn param(self: Link, name: []const u8) ?Param {
        var it = self.params();
        while (it.next()) |p| {
            if (ascii.eqlIgnoreCase(p.name, name)) return p;
        }
        return null;
    }

    /// The title an application should show, into `out`: the decoded
    /// `title*` when it is present and decodes, else the unquoted `title`,
    /// else null (RFC 8288 §3.4.1: "applications SHOULD use the title*
    /// link-param's value"). A `title*` that does not decode falls back to
    /// `title` rather than failing — a damaged label is no reason to lose the
    /// plain one.
    pub fn preferredTitle(self: Link, out: []u8) error{NoSpaceLeft}!?[]const u8 {
        if (self.title_star) |raw| {
            if (decodeExtValue(out, raw)) |ev| return ev.text else |e| switch (e) {
                error.NoSpaceLeft => return error.NoSpaceLeft,
                else => {},
            }
        }
        if (self.title) |t| return try unquote(out, t);
        return null;
    }
};

// ── build (serialise) ────────────────────────────────────────────────────────

pub const WriteError = std.Io.Writer.Error || error{InvalidLink};

/// Serialise `links` into a `Link` header value on `w`. Links are joined with
/// `", "`; each is `<uri>; rel="…"` followed by the present params in field
/// order and then `extra`. Ordinary values are quoted with `"`/`\`
/// backslash-escaped; `*`-params are written bare. `error.InvalidLink` (see
/// `validate`) is returned before any byte of the offending link is written.
pub fn write(w: *std.Io.Writer, links: []const Link) WriteError!void {
    for (links, 0..) |link, i| {
        try validate(link);
        if (i != 0) try w.writeAll(", ");
        try writeOne(w, link);
    }
}

/// Serialise `links` into `buf`, returning the used prefix. `error.NoSpaceLeft`
/// if `buf` is too small, `error.InvalidLink` as for `write`.
pub fn bufPrint(buf: []u8, links: []const Link) error{ NoSpaceLeft, InvalidLink }![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    write(&w, links) catch |e| return switch (e) {
        error.InvalidLink => error.InvalidLink,
        error.WriteFailed => error.NoSpaceLeft,
    };
    return w.buffered();
}

/// Whether the builder can write `link` faithfully: a non-empty `rel`; a URI
/// with no control byte, space, DEL, `<`, `>` or `"` (none is legal in a
/// URI-Reference, and `>` would end it early); quoted values with no control
/// byte other than HTAB (RFC 9110 `qdtext`/`quoted-pair`: a CR or LF would
/// split the header); `title*` and every `*`-param a well-formed RFC 8187
/// ext-value; every `extra` name a non-empty token.
pub fn validate(link: Link) error{InvalidLink}!void {
    if (link.rel.len == 0) return error.InvalidLink;
    for (link.uri) |c| {
        if (c <= ' ' or c == 0x7f or c == '<' or c == '>' or c == '"') return error.InvalidLink;
    }
    const quoted_fields = [_]?[]const u8{ link.rel, link.anchor, link.title, link.type, link.hreflang, link.media };
    for (quoted_fields) |f| if (f) |v| try checkQuotable(v);
    if (link.title_star) |v| if (!isExtValue(v)) return error.InvalidLink;
    for (link.extra) |p| {
        if (p.name.len == 0) return error.InvalidLink;
        // `*` is a tchar, so `title*`-style names are tokens too.
        for (p.name) |c| if (!isTchar(c)) return error.InvalidLink;
        if (isExtName(p.name)) {
            if (!isExtValue(p.value)) return error.InvalidLink;
        } else try checkQuotable(p.value);
    }
}

fn checkQuotable(v: []const u8) error{InvalidLink}!void {
    for (v) |c| {
        if ((c < ' ' and c != '\t') or c == 0x7f) return error.InvalidLink;
    }
}

fn writeOne(w: *std.Io.Writer, link: Link) std.Io.Writer.Error!void {
    try w.writeByte('<');
    try w.writeAll(link.uri);
    try w.writeAll(">; rel=");
    try writeQuoted(w, link.rel);
    if (link.anchor) |v| try writeParam(w, "anchor", v);
    if (link.title) |v| try writeParam(w, "title", v);
    if (link.title_star) |v| try writeParam(w, "title*", v);
    if (link.type) |v| try writeParam(w, "type", v);
    if (link.hreflang) |v| try writeParam(w, "hreflang", v);
    if (link.media) |v| try writeParam(w, "media", v);
    for (link.extra) |p| try writeParam(w, p.name, p.value);
}

fn writeParam(w: *std.Io.Writer, name: []const u8, value: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("; ");
    try w.writeAll(name);
    try w.writeByte('=');
    if (isExtName(name)) try w.writeAll(value) else try writeQuoted(w, value);
}

fn writeQuoted(w: *std.Io.Writer, v: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (v) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

fn isExtName(name: []const u8) bool {
    return name.len > 1 and name[name.len - 1] == '*';
}

/// RFC 9110 `tchar`.
fn isTchar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
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
            const rest = self.s[gt + 1 ..];
            var ps: ParamIterator = .{ .s = rest };
            while (ps.next()) |p| assign(&link, p);
            // `ps` stopped at the end, at the `,` that ends this link, or at
            // a byte the grammar does not allow here.
            const stop = ps.i;
            var end = stop;
            while (end > 0 and isWs(rest[end - 1])) end -= 1;
            link.raw_params = rest[0..end];
            // At the link's own `,` this consumes exactly that comma; at a
            // byte the grammar does not allow it resyncs past the next
            // top-level comma.
            self.i = gt + 1 + stop;
            self.skipToNextLink();
            if (link.rel.len == 0) continue; // RFC 8288: rel is required
            return link;
        }
        return null;
    }

    /// Advance to just past the next top-level comma (quotes respected), or to
    /// end — guarantees forward progress out of a malformed segment.
    fn skipToNextLink(self: *Iterator) void {
        var in_quotes = false;
        while (self.i < self.s.len) {
            const c = self.s[self.i];
            if (in_quotes) {
                if (c == '\\') {
                    self.i = @min(self.i + 2, self.s.len);
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

/// Forward-only iterator over `; name[=value]` params (`Link.params()`).
/// Stops at the end, at a top-level `,`, or at any byte that cannot start a
/// param (`i` is then left on that byte). A param with an empty name is
/// skipped.
pub const ParamIterator = struct {
    s: []const u8,
    i: usize = 0,

    pub fn next(self: *ParamIterator) ?Param {
        while (true) {
            self.skipWs();
            if (self.i >= self.s.len or self.s[self.i] != ';') return null;
            self.i += 1; // consume ';'
            self.skipWs();
            const name_start = self.i;
            while (self.i < self.s.len and !isNameEnd(self.s[self.i])) self.i += 1;
            const name = self.s[name_start..self.i];
            self.skipWs();
            var p: Param = .{ .name = name };
            if (self.i < self.s.len and self.s[self.i] == '=') {
                self.i += 1;
                self.skipWs();
                self.readValue(&p);
            }
            if (name.len == 0) continue;
            return p;
        }
    }

    /// Read a param value: a quoted-string (returned without the surrounding
    /// quotes, escapes left intact) or a bare token.
    fn readValue(self: *ParamIterator, p: *Param) void {
        if (self.i < self.s.len and self.s[self.i] == '"') {
            p.quoted = true;
            self.i += 1;
            const start = self.i;
            while (self.i < self.s.len) {
                const c = self.s[self.i];
                if (c == '\\') {
                    self.i = @min(self.i + 2, self.s.len); // skip escaped byte
                    continue;
                }
                if (c == '"') {
                    p.value = self.s[start..self.i];
                    self.i += 1;
                    return;
                }
                self.i += 1;
            }
            p.value = self.s[start..self.s.len]; // unterminated quote
            return;
        }
        const start = self.i;
        while (self.i < self.s.len and !isTokenEnd(self.s[self.i])) self.i += 1;
        p.value = self.s[start..self.i];
    }

    fn skipWs(self: *ParamIterator) void {
        while (self.i < self.s.len and isWs(self.s[self.i])) self.i += 1;
    }
};

fn assign(link: *Link, p: Param) void {
    // First occurrence of each param wins (RFC 8288 §3.3, §3.4).
    const n = p.name;
    if (ascii.eqlIgnoreCase(n, "rel")) {
        if (link.rel.len == 0) link.rel = p.value;
    } else if (ascii.eqlIgnoreCase(n, "anchor")) {
        if (link.anchor == null) link.anchor = p.value;
    } else if (ascii.eqlIgnoreCase(n, "title")) {
        if (link.title == null) link.title = p.value;
    } else if (ascii.eqlIgnoreCase(n, "title*")) {
        if (link.title_star == null) link.title_star = p.value;
    } else if (ascii.eqlIgnoreCase(n, "type")) {
        if (link.type == null) link.type = p.value;
    } else if (ascii.eqlIgnoreCase(n, "hreflang")) {
        if (link.hreflang == null) link.hreflang = p.value;
    } else if (ascii.eqlIgnoreCase(n, "media")) {
        if (link.media == null) link.media = p.value;
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

// ── quoted values ────────────────────────────────────────────────────────────

/// Remove the backslash escapes of a quoted-string's content (as `Param.value`
/// / `Link.title` hold it) into `out`. A lone trailing `\` (only a truncated
/// header leaves one) is dropped. The result is never longer than `value`,
/// and `out` may alias `value` (in place): the write index never passes the
/// read index.
pub fn unquote(out: []u8, value: []const u8) error{NoSpaceLeft}![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        var c = value[i];
        if (c == '\\') {
            i += 1;
            if (i == value.len) break;
            c = value[i];
        }
        if (n == out.len) return error.NoSpaceLeft;
        out[n] = c;
        n += 1;
    }
    return out[0..n];
}

// ── RFC 8187 extended notation (`title*`) ────────────────────────────────────

/// A decoded RFC 8187 ext-value. `charset` and `language` borrow the raw
/// value; `text` is in the caller's buffer.
pub const ExtValue = struct {
    /// As written (`UTF-8`, `utf-8`); always UTF-8 once decoded.
    charset: []const u8,
    /// RFC 5646 Language-Tag, possibly empty.
    language: []const u8,
    /// The decoded text, valid UTF-8.
    text: []const u8,
};

pub const ExtValueError = error{
    /// Not `charset'[language]'value-chars`, a bad `%XX`, or a byte outside
    /// `attr-char`.
    InvalidExtValue,
    /// A charset other than UTF-8: RFC 8187 §3.2.1 reserves the others "for
    /// future use" and requires recipients to support only UTF-8.
    UnsupportedCharset,
    /// The percent-decoded bytes are not valid UTF-8.
    InvalidUtf8,
    NoSpaceLeft,
};

/// Decode an RFC 8187 ext-value (`UTF-8'de'n%c3%a4chstes%20Kapitel`) into
/// `out` (at most `raw.len` bytes are needed).
pub fn decodeExtValue(out: []u8, raw: []const u8) ExtValueError!ExtValue {
    const parts = splitExt(raw) orelse return error.InvalidExtValue;
    if (!ascii.eqlIgnoreCase(parts.charset, "UTF-8")) return error.UnsupportedCharset;
    const chars = parts.chars;
    var n: usize = 0;
    var i: usize = 0;
    while (i < chars.len) : (i += 1) {
        var b = chars[i];
        if (b == '%') {
            if (chars.len - i < 3) return error.InvalidExtValue;
            const hi = std.fmt.charToDigit(chars[i + 1], 16) catch return error.InvalidExtValue;
            const lo = std.fmt.charToDigit(chars[i + 2], 16) catch return error.InvalidExtValue;
            b = hi * 16 + lo;
            i += 2;
        } else if (!isAttrChar(b)) return error.InvalidExtValue;
        if (n == out.len) return error.NoSpaceLeft;
        out[n] = b;
        n += 1;
    }
    if (!std.unicode.utf8ValidateSlice(out[0..n])) return error.InvalidUtf8;
    return .{ .charset = parts.charset, .language = parts.language, .text = out[0..n] };
}

/// Encode `text` (valid UTF-8) as an RFC 8187 ext-value `UTF-8'<language>'…`
/// into `out` — what `Link.title_star` or a `*`-param in `extra` carries.
/// Every byte outside `attr-char` is `%XX` (upper-case hex, RFC 3986 §2.1).
pub fn encodeExtValue(out: []u8, language: []const u8, text: []const u8) error{ NoSpaceLeft, InvalidExtValue, InvalidUtf8 }![]const u8 {
    for (language) |c| if (!(ascii.isAlphanumeric(c) or c == '-')) return error.InvalidExtValue;
    if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
    var w: std.Io.Writer = .fixed(out);
    w.print("UTF-8'{s}'", .{language}) catch return error.NoSpaceLeft;
    const hex = "0123456789ABCDEF";
    for (text) |c| {
        if (isAttrChar(c)) {
            w.writeByte(c) catch return error.NoSpaceLeft;
        } else {
            w.writeAll(&.{ '%', hex[c >> 4], hex[c & 15] }) catch return error.NoSpaceLeft;
        }
    }
    return w.buffered();
}

const ExtParts = struct { charset: []const u8, language: []const u8, chars: []const u8 };

/// `charset'language'value-chars`, the charset a non-empty `mime-charset`
/// and the language `ALPHA`/`DIGIT`/`-` only (the Language-Tag alphabet; its
/// finer structure is not checked). `chars` is not checked here.
fn splitExt(raw: []const u8) ?ExtParts {
    const q1 = std.mem.indexOfScalar(u8, raw, '\'') orelse return null;
    const q2 = std.mem.indexOfScalarPos(u8, raw, q1 + 1, '\'') orelse return null;
    const charset = raw[0..q1];
    const language = raw[q1 + 1 .. q2];
    if (charset.len == 0) return null;
    for (charset) |c| if (!isMimeCharsetc(c)) return null;
    for (language) |c| if (!(ascii.isAlphanumeric(c) or c == '-')) return null;
    return .{ .charset = charset, .language = language, .chars = raw[q2 + 1 ..] };
}

/// What the builder accepts as a `*`-param value: a UTF-8 ext-value whose
/// value-chars are well formed (RFC 8187 §3.2.1: producers MUST use UTF-8).
/// Every accepted byte is an `attr-char`, `%`, a hex digit or `'`, so the
/// value cannot end the param or the header line.
fn isExtValue(raw: []const u8) bool {
    const parts = splitExt(raw) orelse return false;
    if (!ascii.eqlIgnoreCase(parts.charset, "UTF-8")) return false;
    const chars = parts.chars;
    var i: usize = 0;
    while (i < chars.len) : (i += 1) {
        if (chars[i] == '%') {
            if (chars.len - i < 3) return false;
            if (!ascii.isHex(chars[i + 1]) or !ascii.isHex(chars[i + 2])) return false;
            i += 2;
        } else if (!isAttrChar(chars[i])) return false;
    }
    return true;
}

/// RFC 8187 `attr-char`.
fn isAttrChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '!', '#', '$', '&', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// RFC 8187 `mime-charsetc`.
fn isMimeCharsetc(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '+', '-', '^', '_', '`', '{', '}', '~' => true,
        else => false,
    };
}

// ── target resolution (RFC 3986 §5.2) ────────────────────────────────────────

pub const ResolveError = error{
    /// `base` has no scheme or does not parse as a URI.
    InvalidBase,
    /// `ref` does not parse as a URI-Reference.
    InvalidReference,
    NoSpaceLeft,
};

/// Resolve `ref` (a link's `uri` or `anchor`, possibly relative) against the
/// absolute URI `base` (the request URI, or the resolved anchor — RFC 8288
/// §3.1/§3.2) per RFC 3986 §5.2, into `out`. `out` doubles as the scratch the
/// in-place merge needs, so it must hold about `3 × (base.len + ref.len)`
/// bytes; a 2 KiB stack buffer serves any ordinary URL. Strict parser: a
/// reference with a scheme is taken as absolute (`http:g` stays `http:g`,
/// RFC 3986 §5.4.2).
pub fn resolve(out: []u8, base: []const u8, ref: []const u8) ResolveError![]const u8 {
    const base_uri = std.Uri.parse(base) catch return error.InvalidBase;
    // Tail of `out`: the copy of `ref` that `resolveInPlace` parses and the
    // merged path it builds. Head: the formatted result. The result is at
    // most base.len + ref.len + 3 bytes (scheme/authority from one side,
    // a path no longer than both, `?`/`#`), so the two never overlap.
    const aux_len = 2 * ref.len + base.len + 2;
    const head_len = base.len + ref.len + 4;
    if (out.len < aux_len + head_len) return error.NoSpaceLeft;
    var aux: []u8 = out[out.len - aux_len ..];
    @memcpy(aux[0..ref.len], ref);
    const r = std.Uri.resolveInPlace(base_uri, ref.len, &aux) catch |e| return switch (e) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        else => error.InvalidReference,
    };
    // Recomposed per RFC 3986 §5.3 by hand: `std.Uri.writeToStream` turns an
    // empty path under an authority into "/" (`//g` would come out as
    // `http://g/`, not §5.4.1's `http://g`), and drops the port unless asked.
    var w: std.Io.Writer = .fixed(out[0 .. out.len - aux_len]);
    recompose(&w, r) catch return error.NoSpaceLeft;
    return w.buffered();
}

fn recompose(w: *std.Io.Writer, r: std.Uri) std.Io.Writer.Error!void {
    if (r.scheme.len != 0) try w.print("{s}:", .{r.scheme});
    if (r.host) |host| {
        try w.writeAll("//");
        if (r.user) |u| {
            try w.writeAll(componentText(u));
            if (r.password) |p| try w.print(":{s}", .{componentText(p)});
            try w.writeByte('@');
        }
        try w.writeAll(componentText(host));
        if (r.port) |port| try w.print(":{d}", .{port});
    }
    try w.writeAll(componentText(r.path));
    if (r.query) |q| try w.print("?{s}", .{componentText(q)});
    if (r.fragment) |f| try w.print("#{s}", .{componentText(f)});
}

/// Every component here came out of `std.Uri.parse` (or the in-place merge),
/// so it is the text as written; no re-encoding.
fn componentText(c: std.Uri.Component) []const u8 {
    return switch (c) {
        .raw, .percent_encoded => |t| t,
    };
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

test "parse: backslash-escaped quote inside a quoted value is not mistaken for the closing quote" {
    // Raw bytes of the title param value: a \ " b  (backslash-escaped quote,
    // per RFC 8288 quoted-string escaping). The parser must skip the escaped
    // byte and keep scanning, returning the value verbatim (escape included).
    var it = parse("<u>; rel=\"next\"; title=\"a\\\"b\"");
    const l = it.next().?;
    try testing.expectEqualStrings("next", l.rel);
    try testing.expectEqualStrings("a\\\"b", l.title.?);
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

test "parse: stray empty param name (double semicolon) does not stop later params" {
    var it = parse("<u>;;rel=\"next\";title=\"T\"");
    const l = it.next().?;
    try testing.expectEqualStrings("next", l.rel);
    try testing.expectEqualStrings("T", l.title.?);
    try testing.expect(it.next() == null);
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

// ── RFC 8288 §3.5 worked examples (external anchor) ─────────────────────────
//
// The header values below are reconstructed byte-for-byte from RFC 8288
// §3.5's own "Link:" examples (fetched from rfc-editor.org, not recalled from
// memory) — only the document's print line-wrapping is undone (each was one
// logical field value, wrapped for page width). The expected `rel`/`title`
// readings are the RFC's own stated interpretation of each example, not this
// module's. The errata list for RFC 8288 was checked: the two verified errata
// (5319: §1.1 LOALPHA cross-reference; 5878: §B.2 var-name typo) and the two
// reported-not-verified ones (5168/5169: capitalization in §B.3/§B.4) all
// concern grammar/pseudocode prose elsewhere in the document, not §3.5's
// examples or the Link-header grammar itself, so none of them touch these
// fixtures.
//
// One further §3.5 example is deliberately NOT used: the `title*=UTF-8'de'...`
// RFC 8187 extended-notation title. This module does not implement extended
// (`*`-suffixed) parameter notation — see SPEC.md's "Threat model / out of
// scope" — so `title*` is correctly treated as an unrecognized param name
// distinct from `title` and dropped; that's already covered generically by
// the "unknown params ignored" test below and isn't a *-notation anchor.

test "RFC 8288 §3.5: chapter2 previous-chapter example" {
    var it = parse("<http://example.com/TheBook/chapter2>; rel=\"previous\"; title=\"previous chapter\"");
    const l = it.next().?;
    try testing.expectEqualStrings("http://example.com/TheBook/chapter2", l.uri);
    try testing.expectEqualStrings("previous", l.rel);
    try testing.expectEqualStrings("previous chapter", l.title.?);
    try testing.expect(it.next() == null);
}

test "RFC 8288 §3.5: extension relation type expressed as a full URI" {
    var it = parse("</>; rel=\"http://example.net/foo\"");
    const l = it.next().?;
    try testing.expectEqualStrings("/", l.uri);
    try testing.expectEqualStrings("http://example.net/foo", l.rel);
    try testing.expect(it.next() == null);
}

test "RFC 8288 §3.5: an unmodeled param (anchor) is tolerated without desync" {
    // `anchor` is not in this module's modeled param set (rel/title/type/
    // hreflang; see SPEC.md) — it must be skipped harmlessly and `rel` must
    // still come through, exactly the RFC's own copyright-terms example.
    var it = parse("</terms>; rel=\"copyright\"; anchor=\"#foo\"");
    const l = it.next().?;
    try testing.expectEqualStrings("/terms", l.uri);
    try testing.expectEqualStrings("copyright", l.rel);
    try testing.expect(it.next() == null);
}

test "RFC 8288 §3.5: one link value can carry multiple relation types" {
    var it = parse("<http://example.org/>; rel=\"start http://example.net/relation/other\"");
    const l = it.next().?;
    try testing.expectEqualStrings("http://example.org/", l.uri);
    try testing.expectEqualStrings("start http://example.net/relation/other", l.rel);
    try testing.expect(it.next() == null);
}

test "RFC 8288 §3.5: a comma-joined value carries two links, same as two header lines" {
    var it = parse("<https://example.org/>; rel=\"start\", <https://example.org/index>; rel=\"index\"");
    const a = it.next().?;
    try testing.expectEqualStrings("https://example.org/", a.uri);
    try testing.expectEqualStrings("start", a.rel);
    const b = it.next().?;
    try testing.expectEqualStrings("https://example.org/index", b.uri);
    try testing.expectEqualStrings("index", b.rel);
    try testing.expect(it.next() == null);
}

// ── fuzz: untrusted `Link` header parsing never panics ──────────────────────
//
// ⚠ This harness used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain — so `len` was 0 for every
// input a corpus can carry, and `parse` was handed an empty slice while the
// header sat unread in `buf`. It also had no corpus at all, so outside `--fuzz`
// it ran exactly one input for ever: the empty one. One `slice` draw closes the
// first half, the corpus below the second.

/// `testkit.fuzz.seed`, aliased so the corpus reads as the header values it is.
/// A corpus entry is not the frame: `Smith.slice` reads a little-endian `u32`
/// length first, so a raw header would arrive minus its own first four octets.
const seed = @import("testkit").fuzz.seed;

/// `Link` header values, in the format the length draw reads. Every shape the
/// value tests above pin: the quoting edges (a `,` and a `;` inside a quoted
/// param, a `\`-escaped quote), the desync candidates (unknown params carrying
/// separators, a stray empty param name, a repeated param), and the three ways
/// a segment is malformed (no brackets, no rel, an unterminated bracket — which
/// makes the URI scan run to the end of the header, the loop this bounds).
const parse_seeds = [_][]const u8{
    seed("<https://api/x?page=2>; rel=\"next\""), // the smallest complete link
    seed("<u1>; rel=\"next\"; title=\"Page 2\"; type=\"application/json\", <u2>; rel=\"prev\"; hreflang=\"en\""), // two links, all four modeled params
    seed("<u>; rel=next; type=text/html"), // token (unquoted) param values
    seed("  <u>  ;  rel = \"next\" ,  <v> ; rel=\"prev\"  "), // OWS everywhere the grammar allows it
    seed("<https://api/x?ids=1,2,3>; rel=\"next\""), // a ',' inside the URI must not split the value
    seed("<u>; rel=\"next\"; title=\"a\\\"b\""), // a '\'-escaped quote inside a quoted value
    seed("<u>; rel=\"next\"; title=\"a, b; c\", <v>; rel=\"prev\""), // ',' and ';' inside a quoted value
    seed("<u>; foo=bar; rel=\"next\"; baz=\"x, y\"; media=screen"), // unknown params carrying separators
    seed("<u>;;rel=\"next\";title=\"T\""), // a stray empty param name between the URI and the params
    seed("<u>; REL=\"next\"; Title=\"T\""), // param names are case-insensitive
    seed("<u>; rel=\"next\"; rel=\"prev\"; title=\"A\"; title=\"B\""), // first occurrence wins
    seed("garbage, <u>; title=\"no rel\", <v>; rel=\"next\""), // two malformed segments before a good one
    seed("<https://api/x; rel=\"next\""), // unterminated '<': the URI scan runs to the end
    seed("   \t ,,,"), // whitespace and empty segments only — yields nothing
    seed("<http://example.com/TheBook/chapter2>; rel=\"previous\"; title=\"previous chapter\""), // RFC 8288 §3.5
    seed("</terms>; rel=\"copyright\"; anchor=\"#foo\""), // RFC 8288 §3.5, an unmodeled param
};

const fz = @import("fuzz_test.zig");

test {
    _ = fz;
}
const ParseMark = fz.Marker(enum { empty, links, title, params });

fn fuzzParse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &parse_seeds);
    var it = parse(buf[0..len]);
    var n: usize = 0;
    while (it.next()) |l| {
        n += 1;
        if (l.title != null) ParseMark.mark(.title);
        var ps = l.params();
        while (ps.next()) |_| ParseMark.mark(.params);
    }
    if (n == 0) ParseMark.mark(.empty) else ParseMark.mark(.links);
}

fn fuzzParseSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParse(std.testing.Smith, smith, testing.allocator);
}

test "fuzz parse never panics" {
    try testing.fuzz({}, fuzzParseSmith, .{ .corpus = &parse_seeds });
}

test "fuzz driver: LINKHEADER_FUZZ (parse)" {
    try fz.fuzz_driver.run(fuzzParse, .{ .prefix = "LINKHEADER_FUZZ", .name = "linkheader-parse" });
}

test "fuzz harness: parse, 500 seeds, reaches every outcome" {
    try ParseMark.reach(fuzzParse, "linkheader-parse", 500);
}

test "corpus: every seed reaches the parser, and the links yielded are pinned" {
    // Links yielded is the second number, and it is the one that matters here:
    // `parse("")` is legal — it yields nothing and returns cleanly — so there is
    // no error path a guard could count, and "it did not crash" was already true
    // when the harness was seeing nothing at all. An empty input yields exactly
    // zero links, so this count is what falls if the draw ever collapses again.
    var nonempty: usize = 0;
    var links: usize = 0;
    var with_title: usize = 0;
    for (parse_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var it = parse(buf[0..len]);
        while (it.next()) |l| {
            links += 1;
            if (l.title != null) with_title += 1;
        }
    }
    try testing.expectEqual(parse_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 of 16 seeds arrived
    // non-empty and 0 links were yielded. After: 16 / 17 / 7.
    try testing.expectEqual(@as(usize, 17), links);
    try testing.expectEqual(@as(usize, 7), with_title);
}

// ── every param (RFC 8288 §3, the gap the 2026-09-30 survey named) ──────────

test "params: every param of a link, in header order, with repeats and unknowns" {
    // Expected values read off the header by hand: name, raw value, quoted?
    var it = parse("</style.css>; rel=preload; as=style; crossorigin; hreflang=en; hreflang=\"de\"; x-api=\"a\\\"b\"");
    const l = it.next().?;
    try testing.expectEqualStrings("preload", l.rel);
    try testing.expectEqualStrings("en", l.hreflang.?); // first wins in the field
    const want = [_]Param{
        .{ .name = "rel", .value = "preload" },
        .{ .name = "as", .value = "style" },
        .{ .name = "crossorigin" },
        .{ .name = "hreflang", .value = "en" },
        .{ .name = "hreflang", .value = "de", .quoted = true },
        .{ .name = "x-api", .value = "a\\\"b", .quoted = true },
    };
    var ps = l.params();
    for (want) |w| {
        const p = ps.next().?;
        try testing.expectEqualStrings(w.name, p.name);
        try testing.expectEqualStrings(w.value, p.value);
        try testing.expectEqual(w.quoted, p.quoted);
    }
    try testing.expect(ps.next() == null);
    try testing.expectEqualStrings("style", l.param("AS").?.value);
    try testing.expect(l.param("crossorigin") != null);
    try testing.expect(l.param("media") == null);
    try testing.expect(it.next() == null);
}

test "params: the raw region stops at the link's own comma" {
    var it = parse("<a>; rel=next; media=\"screen, print\" , <b>; rel=prev; anchor=\"#x\"");
    const a = it.next().?;
    try testing.expectEqualStrings("; rel=next; media=\"screen, print\"", a.raw_params);
    try testing.expectEqualStrings("screen, print", a.media.?);
    try testing.expect(a.anchor == null);
    const b = it.next().?;
    try testing.expectEqualStrings("#x", b.anchor.?);
    var n: usize = 0;
    var ps = b.params();
    while (ps.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 2), n);
}

test "params: a link that resyncs past garbage keeps the params before it" {
    // `junk` is not `;`: the scan stops there, the link keeps rel, the next
    // link is still found.
    var it = parse("<a>; rel=next junk; title=lost, <b>; rel=prev");
    const a = it.next().?;
    try testing.expectEqualStrings("next", a.rel);
    try testing.expect(a.title == null);
    try testing.expectEqualStrings("; rel=next", a.raw_params);
    try testing.expectEqualStrings("b", it.next().?.uri);
    try testing.expect(it.next() == null);
}

test "build: anchor, title*, media and extra params, in field order" {
    var buf: [256]u8 = undefined;
    const out = try bufPrint(&buf, &.{.{
        .uri = "/s.css",
        .rel = "preload",
        .anchor = "#top",
        .title_star = "UTF-8'en'%C2%A3%20rates",
        .media = "screen",
        .extra = &.{ .{ .name = "as", .value = "style" }, .{ .name = "x*", .value = "UTF-8''a" } },
    }});
    try testing.expectEqualStrings(
        "</s.css>; rel=\"preload\"; anchor=\"#top\"; title*=UTF-8'en'%C2%A3%20rates; media=\"screen\"; as=\"style\"; x*=UTF-8''a",
        out,
    );
    var it = parse(out);
    const l = it.next().?;
    try testing.expectEqualStrings("#top", l.anchor.?);
    try testing.expectEqualStrings("UTF-8'en'%C2%A3%20rates", l.title_star.?);
    try testing.expectEqualStrings("screen", l.media.?);
    try testing.expectEqualStrings("style", l.param("as").?.value);
    try testing.expectEqualStrings("UTF-8''a", l.param("x*").?.value);
}

// ── the builder refuses what it cannot write faithfully ─────────────────────
//
// Each refused class is a header-injection or desync vector: a CR/LF splits
// the header into two, `>` ends the URI early so the rest of it parses as
// params, a control byte is not legal field content. The positive control
// is the same link without the bad byte.

test "build: refused byte classes, each with error.InvalidLink and nothing written" {
    const bad = [_]Link{
        .{ .uri = "/a>b", .rel = "next" }, // '>' in the URI
        .{ .uri = "/a\rb", .rel = "next" }, // CR in the URI
        .{ .uri = "/a\nb", .rel = "next" }, // LF in the URI
        .{ .uri = "/a\"b", .rel = "next" }, // '"' in the URI (not a URI-Reference byte)
        .{ .uri = "/a b", .rel = "next" }, // SP in the URI
        .{ .uri = "/a<b", .rel = "next" }, // '<' in the URI
        .{ .uri = "/a", .rel = "next", .title = "x\r\nSet-Cookie: s=1" }, // CRLF in a quoted value
        .{ .uri = "/a", .rel = "next", .title = "x\nb" }, // LF in a quoted value
        .{ .uri = "/a", .rel = "next", .type = "x\x00b" }, // NUL (CTL) in a quoted value
        .{ .uri = "/a", .rel = "next", .media = "x\x7fb" }, // DEL in a quoted value
        .{ .uri = "/a", .rel = "next", .anchor = "\x1b" }, // ESC (CTL)
        .{ .uri = "/a", .rel = "" }, // rel is required
        .{ .uri = "/a", .rel = "ne\rxt" }, // CR in rel
        .{ .uri = "/a", .rel = "next", .title_star = "UTF-8'en'a b" }, // SP in an ext-value
        .{ .uri = "/a", .rel = "next", .title_star = "UTF-8'en'a\"" }, // quote in an ext-value
        .{ .uri = "/a", .rel = "next", .title_star = "ISO-8859-1'en'%A3" }, // producers MUST use UTF-8
        .{ .uri = "/a", .rel = "next", .title_star = "UTF-8'en'%4" }, // truncated %XX
        .{ .uri = "/a", .rel = "next", .title_star = "UTF-8'en'%zz" }, // not pct-encoded: decodeExtValue refuses it, so must the builder
        .{ .uri = "/a", .rel = "next", .extra = &.{.{ .name = "a b", .value = "v" }} }, // name not a token
        .{ .uri = "/a", .rel = "next", .extra = &.{.{ .name = "", .value = "v" }} }, // empty name
        .{ .uri = "/a", .rel = "next", .extra = &.{.{ .name = "x\"", .value = "v" }} }, // '"' is not a tchar
        .{ .uri = "/a", .rel = "next", .extra = &.{.{ .name = "x", .value = "a\rb" }} }, // CR in an extra value
        .{ .uri = "/a", .rel = "next", .extra = &.{.{ .name = "x*", .value = "a,b" }} }, // ext-param, not an ext-value
    };
    for (bad) |l| {
        var buf: [256]u8 = undefined;
        try testing.expectError(error.InvalidLink, bufPrint(&buf, &.{l}));
        // Nothing of the refused link reaches the writer — not even the ", "
        // after a good one.
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidLink, write(&w, &.{ .{ .uri = "/ok", .rel = "self" }, l }));
        try testing.expectEqualStrings("</ok>; rel=\"self\"", w.buffered());
    }
}

test "build: positive controls — the same links without the bad byte write and parse back" {
    const good = [_]Link{
        .{ .uri = "/ab", .rel = "next" },
        .{ .uri = "/a%3Eb", .rel = "next" }, // '>' percent-encoded is fine
        .{ .uri = "/a", .rel = "next", .title = "x Set-Cookie: s=1" },
        .{ .uri = "/a", .rel = "next", .title = "tab\there" }, // HTAB is qdtext
        .{ .uri = "/a", .rel = "next", .title = "a\"b\\c" }, // '"' and '\' are escaped, not refused
        .{ .uri = "/a", .rel = "next", .title_star = "UTF-8'en'a%20b" },
        .{ .uri = "/a", .rel = "next", .extra = &.{.{ .name = "x*", .value = "utf-8''a" }} },
    };
    for (good) |l| {
        var buf: [256]u8 = undefined;
        const out = try bufPrint(&buf, &.{l});
        var it = parse(out);
        const p = it.next().?;
        try testing.expectEqualStrings(l.uri, p.uri);
        try testing.expectEqualStrings(l.rel, p.rel);
        var ub: [64]u8 = undefined;
        if (l.title) |t| try testing.expectEqualStrings(t, try unquote(&ub, p.title.?));
        if (l.title_star) |t| try testing.expectEqualStrings(t, p.title_star.?);
        try testing.expect(it.next() == null);
    }
}

// ── unquote ──────────────────────────────────────────────────────────────────

test "unquote: escapes removed, hand-derived" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("a\"b\\c", try unquote(&b, "a\\\"b\\\\c"));
    try testing.expectEqualStrings("xy", try unquote(&b, "\\x\\y")); // any escaped byte is itself
    try testing.expectEqualStrings("ab", try unquote(&b, "ab\\")); // lone trailing '\' dropped
    try testing.expectEqualStrings("", try unquote(&b, ""));
    var small: [2]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, unquote(&small, "abc"));
    try testing.expectEqualStrings("ab", try unquote(&small, "a\\b")); // escapes do not count
}

// ── RFC 8187 ext-values (vectors from RFC 8187 §3.2.3 and RFC 8288 §3.5) ────
//
// The raw values are transcribed from the RFCs (fetched from rfc-editor.org
// 2026-10-04); the decoded text is the RFCs' own reading ("£ rates",
// "£ and € rates", "€ exchange rates", "letztes Kapitel",
// "nächstes Kapitel"), cross-checked through Python's
// `email.utils.decode_rfc2231` + `urllib.parse.unquote` as a black box.

test "RFC 8187 §3.2.3: the three extended-notation examples decode" {
    var b: [64]u8 = undefined;
    const a = try decodeExtValue(&b, "utf-8'en'%C2%A3%20rates");
    try testing.expectEqualStrings("utf-8", a.charset);
    try testing.expectEqualStrings("en", a.language);
    try testing.expectEqualStrings("\u{a3} rates", a.text);
    const c = try decodeExtValue(&b, "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates");
    try testing.expectEqualStrings("", c.language);
    try testing.expectEqualStrings("\u{a3} and \u{20ac} rates", c.text);
    try testing.expectEqualStrings("\u{20ac} exchange rates", (try decodeExtValue(&b, "utf-8''%e2%82%ac%20exchange%20rates")).text);
}

test "RFC 8288 §3.5 title* example: parsed and preferred over nothing" {
    // RFC 8288 §3.5, its print line-wrapping undone.
    const h = "</TheBook/chapter2>; rel=\"previous\"; title*=UTF-8'de'letztes%20Kapitel, " ++
        "</TheBook/chapter4>; rel=\"next\"; title*=UTF-8'de'n%c3%a4chstes%20Kapitel";
    var it = parse(h);
    var b: [64]u8 = undefined;
    const a = it.next().?;
    try testing.expectEqualStrings("/TheBook/chapter2", a.uri);
    try testing.expectEqualStrings("previous", a.rel);
    try testing.expectEqualStrings("UTF-8'de'letztes%20Kapitel", a.title_star.?);
    try testing.expectEqualStrings("letztes Kapitel", (try a.preferredTitle(&b)).?);
    const n = it.next().?;
    try testing.expectEqualStrings("next", n.rel);
    const ev = try decodeExtValue(&b, n.title_star.?);
    try testing.expectEqualStrings("de", ev.language);
    try testing.expectEqualStrings("n\u{e4}chstes Kapitel", ev.text);
    try testing.expect(it.next() == null);
}

test "RFC 8187 §3.2.3 backward-compatible pair: title* preferred, title the fallback" {
    var it = parse("<x>; rel=a; title=\"EURO exchange rates\"; title*=utf-8''%e2%82%ac%20exchange%20rates");
    const l = it.next().?;
    var b: [64]u8 = undefined;
    try testing.expectEqualStrings("\u{20ac} exchange rates", (try l.preferredTitle(&b)).?);
    // A title* that does not decode falls back to the (unquoted) title.
    var it2 = parse("<x>; rel=a; title=\"say \\\"hi\\\"\"; title*=latin1''%A3");
    try testing.expectEqualStrings("say \"hi\"", (try it2.next().?.preferredTitle(&b)).?);
    var it3 = parse("<x>; rel=a");
    try testing.expect((try it3.next().?.preferredTitle(&b)) == null);
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, l.preferredTitle(&tiny));
}

test "decodeExtValue: refusals" {
    var b: [32]u8 = undefined;
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8"));
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8'en"));
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "''abc")); // empty charset
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF 8''abc")); // SP in charset
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8'e n'abc")); // SP in language
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8''a b")); // SP is not attr-char
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8''a'b")); // nor is '\''
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8''%")); // truncated
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8''%4")); // truncated
    try testing.expectError(error.InvalidExtValue, decodeExtValue(&b, "UTF-8''%4g")); // not hex
    try testing.expectError(error.UnsupportedCharset, decodeExtValue(&b, "iso-8859-1'en'%A3%20rates"));
    try testing.expectError(error.InvalidUtf8, decodeExtValue(&b, "UTF-8''%C2")); // a lone lead byte
    try testing.expectError(error.InvalidUtf8, decodeExtValue(&b, "UTF-8''%ff"));
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, decodeExtValue(&tiny, "UTF-8''abc"));
    // The empty value is legal (value-chars is `*( … )`).
    try testing.expectEqualStrings("", (try decodeExtValue(&b, "UTF-8''")).text);
    // `%41` is 'A' and every attr-char passes through unchanged.
    try testing.expectEqualStrings("A!#$&+-.^_`|~z9", (try decodeExtValue(&b, "UTF-8''%41!#$&+-.^_`|~z9")).text);
}

test "encodeExtValue: RFC 8187's own encodings come back (upper-case hex)" {
    var b: [64]u8 = undefined;
    try testing.expectEqualStrings("UTF-8'en'%C2%A3%20rates", try encodeExtValue(&b, "en", "\u{a3} rates"));
    try testing.expectEqualStrings("UTF-8''%E2%82%AC%20exchange%20rates", try encodeExtValue(&b, "", "\u{20ac} exchange rates"));
    try testing.expectEqualStrings("UTF-8'de'n%C3%A4chstes%20Kapitel", try encodeExtValue(&b, "de", "n\u{e4}chstes Kapitel"));
    // '%', '\'', '*', '"' are not attr-char, so they are escaped.
    try testing.expectEqualStrings("UTF-8''%25%27%2A%22", try encodeExtValue(&b, "", "%'*\""));
    try testing.expectError(error.InvalidUtf8, encodeExtValue(&b, "", "\xff"));
    try testing.expectError(error.InvalidExtValue, encodeExtValue(&b, "e'n", "x"));
    var tiny: [7]u8 = undefined; // "UTF-8''x" is 8 bytes
    try testing.expectError(error.NoSpaceLeft, encodeExtValue(&tiny, "", "x"));
    try testing.expectError(error.NoSpaceLeft, encodeExtValue(&tiny, "", "\u{a3}"));
}

// ── RFC 3986 §5.4 reference resolution ──────────────────────────────────────
//
// The table is RFC 3986 §5.4.1 (normal) and §5.4.2 (abnormal), verbatim,
// base `http://a/b/c/d;p?q`. Python's `urllib.parse.urljoin`, driven as a
// black box over the same table, agrees on all 42 rows but the last, where it
// takes the non-strict reading (`http:g` → `http://a/b/c/g`) that §5.4.2
// allows only "for backward compatibility"; the strict reading is the RFC's.

test "RFC 3986 §5.4: resolve every normal and abnormal example" {
    const base = "http://a/b/c/d;p?q";
    const tab = [_][2][]const u8{
        .{ "g:h", "g:h" },                        .{ "g", "http://a/b/c/g" },
        .{ "./g", "http://a/b/c/g" },             .{ "g/", "http://a/b/c/g/" },
        .{ "/g", "http://a/g" },                  .{ "//g", "http://g" },
        .{ "?y", "http://a/b/c/d;p?y" },          .{ "g?y", "http://a/b/c/g?y" },
        .{ "#s", "http://a/b/c/d;p?q#s" },        .{ "g#s", "http://a/b/c/g#s" },
        .{ "g?y#s", "http://a/b/c/g?y#s" },       .{ ";x", "http://a/b/c/;x" },
        .{ "g;x", "http://a/b/c/g;x" },           .{ "g;x?y#s", "http://a/b/c/g;x?y#s" },
        .{ "", "http://a/b/c/d;p?q" },            .{ ".", "http://a/b/c/" },
        .{ "./", "http://a/b/c/" },               .{ "..", "http://a/b/" },
        .{ "../", "http://a/b/" },                .{ "../g", "http://a/b/g" },
        .{ "../..", "http://a/" },                .{ "../../", "http://a/" },
        .{ "../../g", "http://a/g" },             .{ "../../../g", "http://a/g" },
        .{ "../../../../g", "http://a/g" },       .{ "/./g", "http://a/g" },
        .{ "/../g", "http://a/g" },               .{ "g.", "http://a/b/c/g." },
        .{ ".g", "http://a/b/c/.g" },             .{ "g..", "http://a/b/c/g.." },
        .{ "..g", "http://a/b/c/..g" },           .{ "./../g", "http://a/b/g" },
        .{ "./g/.", "http://a/b/c/g/" },          .{ "g/./h", "http://a/b/c/g/h" },
        .{ "g/../h", "http://a/b/c/h" },          .{ "g;x=1/./y", "http://a/b/c/g;x=1/y" },
        .{ "g;x=1/../y", "http://a/b/c/y" },      .{ "g?y/./x", "http://a/b/c/g?y/./x" },
        .{ "g?y/../x", "http://a/b/c/g?y/../x" }, .{ "g#s/./x", "http://a/b/c/g#s/./x" },
        .{ "g#s/../x", "http://a/b/c/g#s/../x" }, .{ "http:g", "http:g" },
    };
    for (tab) |row| {
        var out: [256]u8 = undefined;
        const got = resolve(&out, base, row[0]) catch |e| {
            std.debug.print("ref {s}: {s}\n", .{ row[0], @errorName(e) });
            return e;
        };
        testing.expectEqualStrings(row[1], got) catch |e| {
            std.debug.print("ref {s}\n", .{row[0]});
            return e;
        };
    }
}

test "resolve: a next link against the request URI; refusals" {
    var out: [256]u8 = undefined;
    const l = find("<?page=3>; rel=next", "next").?;
    try testing.expectEqualStrings("https://api.example/items?page=3", try resolve(&out, "https://api.example/items?page=2", l.uri));
    // An authority with an empty path merges as "/" ++ ref (RFC 3986 §5.2.3).
    try testing.expectEqualStrings("https://h/g", try resolve(&out, "https://h", "g"));
    // Userinfo and port of the base survive a relative reference; a
    // network-path reference replaces them.
    try testing.expectEqualStrings("http://u:p@a:8080/b/g?x#f", try resolve(&out, "http://u:p@a:8080/b/c", "g?x#f"));
    try testing.expectEqualStrings("http://h:81", try resolve(&out, "http://u:p@a:8080/b/c", "//h:81"));
    try testing.expectError(error.InvalidBase, resolve(&out, "/relative/base", "g"));
    try testing.expectError(error.InvalidBase, resolve(&out, "", "g"));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, resolve(&tiny, "http://a/b", "c"));
}

// ── seeded corrupt-input sweep (deterministic, never `zig build --fuzz`) ─────
//
// Headers are generated from an alphabet weighted towards the bytes the
// grammar turns on (`<>;,="\` and whitespace), so most inputs reach the
// param scanner with quotes and escapes in play rather than dying at the
// first byte. Every yielded link must borrow from the input, the iterator
// must terminate within `len + 1` steps, and every param and ext-value must
// be readable without a panic. The round-trip half is an oracle, not a
// crash check: random VALID links, built and parsed back, must come back
// equal field for field (quoted values through `unquote`).

const SweepReach = struct {
    links: usize = 0,
    params: usize = 0,
    quoted: usize = 0,
    escapes: usize = 0,
    ext_ok: usize = 0,
    ext_err: usize = 0,
    roundtrips: usize = 0,
    refused: usize = 0,
};

fn genHeader(r: std.Random, buf: []u8) []u8 {
    // A well-formed header of one to four links assembled from grammar
    // pieces, then damaged in a few places: the damage lands on separators,
    // quotes and escapes often enough to test resync, while most links stay
    // whole enough to reach the param scanner.
    const uris = [_][]const u8{ "<u>", "</a,b;c>", "<?page=2>", "<>", "<http://h/x>" };
    const params = [_][]const u8{
        "; rel=next",         ";rel=\"prev start\"",                       "; REL=last",                "; title=\"a, b; c\"",
        "; title=\"q\\\"x\"", "; title*=UTF-8'de'n%c3%a4chstes%20Kapitel", "; title*=utf-8''%e2%82%ac", "; anchor=\"#x\"",
        "; media=screen",     "; hreflang=en",                             "; crossorigin",             "; x-k=\"a\\\\b\"",
        "; as=style",         ";;",                                        " ; type = text/html",
    };
    var w: std.Io.Writer = .fixed(buf);
    const links = r.intRangeAtMost(usize, 1, 4);
    for (0..links) |i| {
        if (i != 0) w.writeAll(if (r.boolean()) ", " else ",") catch break;
        w.writeAll(uris[r.uintLessThan(usize, uris.len)]) catch break;
        for (0..r.intRangeAtMost(usize, 0, 4)) |_|
            w.writeAll(params[r.uintLessThan(usize, params.len)]) catch break;
    }
    const out = w.buffered();
    if (out.len == 0) return out;
    const special = "<>;,=\"\\ '%*\r\n";
    for (0..r.uintAtMost(usize, 4)) |_| {
        const at = r.uintLessThan(usize, out.len);
        out[at] = switch (r.uintLessThan(u8, 3)) {
            0 => r.int(u8),
            else => special[r.uintLessThan(usize, special.len)],
        };
    }
    // Sometimes cut it short, mid-quote or mid-escape.
    return if (r.uintLessThan(u8, 4) == 0) out[0..r.uintAtMost(usize, out.len)] else out;
}

fn within(outer: []const u8, inner: []const u8) bool {
    if (inner.len == 0) return true;
    const o = @intFromPtr(outer.ptr);
    const i = @intFromPtr(inner.ptr);
    return i >= o and i + inner.len <= o + outer.len;
}

fn sweepParse(seeds: u64, reach: *SweepReach) !void {
    var buf: [400]u8 = undefined;
    var k: u64 = 0;
    while (k < seeds) : (k += 1) {
        var prng = std.Random.DefaultPrng.init(k);
        const h = genHeader(prng.random(), &buf);
        var it = parse(h);
        var steps: usize = 0;
        while (it.next()) |l| {
            steps += 1;
            if (steps > h.len + 1) return error.IteratorDidNotTerminate;
            reach.links += 1;
            if (!within(h, l.uri) or !within(h, l.rel) or !within(h, l.raw_params)) return error.NotBorrowed;
            var ps = l.params();
            while (ps.next()) |p| {
                reach.params += 1;
                if (!within(h, p.name) or !within(h, p.value)) return error.NotBorrowed;
                if (p.quoted) {
                    reach.quoted += 1;
                    if (std.mem.indexOfScalar(u8, p.value, '\\') != null) reach.escapes += 1;
                    var ub: [400]u8 = undefined;
                    const u = try unquote(&ub, p.value);
                    if (u.len > p.value.len) return error.UnquoteGrew;
                }
            }
            var tb: [400]u8 = undefined;
            if (l.title_star) |ts| {
                if (decodeExtValue(&tb, ts)) |_| reach.ext_ok += 1 else |_| reach.ext_err += 1;
            }
            _ = l.preferredTitle(&tb) catch {};
            var rb: [1024]u8 = undefined;
            _ = resolve(&rb, "http://a/b/c/d;p?q", l.uri) catch {};
        }
        // Raw ext-value decoding on the bare bytes, too.
        var eb: [400]u8 = undefined;
        if (decodeExtValue(&eb, h)) |_| reach.ext_ok += 1 else |_| reach.ext_err += 1;
    }
}

fn genValue(r: std.Random, buf: []u8) []u8 {
    // Printable ASCII plus HTAB and some UTF-8, incl. the separators the
    // quoting must protect.
    const alpha = " \t\"\\,;<>=abcXYZ09#%'*";
    const n = r.uintAtMost(usize, buf.len);
    for (buf[0..n]) |*c| c.* = alpha[r.uintLessThan(usize, alpha.len)];
    return buf[0..n];
}

fn sweepRoundtrip(seeds: u64, reach: *SweepReach) !void {
    var k: u64 = 0;
    while (k < seeds) : (k += 1) {
        var prng = std.Random.DefaultPrng.init(k ^ 0x9e37_79b9);
        const r = prng.random();
        var vb: [4][24]u8 = undefined;
        var eb: [128]u8 = undefined;
        const uri_alpha = "abc/?=&%#:.-_~";
        var ub: [16]u8 = undefined;
        const ulen = r.uintAtMost(usize, ub.len);
        for (ub[0..ulen]) |*c| c.* = uri_alpha[r.uintLessThan(usize, uri_alpha.len)];
        var rel = genValue(r, &vb[0]);
        if (rel.len == 0 or r.boolean()) rel = @constCast("next");
        const title = genValue(r, &vb[1]);
        const anchor = genValue(r, &vb[2]);
        const text = genValue(r, &vb[3]);
        const ts = try encodeExtValue(&eb, "en", text);
        const link: Link = .{
            .uri = ub[0..ulen],
            .rel = rel,
            .title = if (r.boolean()) title else null,
            .anchor = if (r.boolean()) anchor else null,
            .title_star = if (r.boolean()) ts else null,
            .extra = &.{.{ .name = "x-k", .value = anchor }},
        };
        var out: [512]u8 = undefined;
        const s = bufPrint(&out, &.{ link, link }) catch |e| {
            reach.refused += 1;
            return e; // every generated link is valid
        };
        var it = parse(s);
        for (0..2) |_| {
            const p = it.next() orelse return error.LinkLost;
            var t: [64]u8 = undefined;
            try testing.expectEqualStrings(link.uri, p.uri);
            try testing.expectEqualStrings(link.rel, try unquote(&t, p.rel));
            if (link.title) |v| try testing.expectEqualStrings(v, try unquote(&t, p.title.?)) else try testing.expect(p.title == null);
            if (link.anchor) |v| try testing.expectEqualStrings(v, try unquote(&t, p.anchor.?)) else try testing.expect(p.anchor == null);
            if (link.title_star) |_| {
                try testing.expectEqualStrings(text, (try decodeExtValue(&t, p.title_star.?)).text);
            } else try testing.expect(p.title_star == null);
            try testing.expectEqualStrings(anchor, try unquote(&t, p.param("x-k").?.value));
            reach.roundtrips += 1;
        }
        try testing.expect(it.next() == null);
    }
}

test "sweep: seeded corrupt headers never panic, borrow, terminate; valid links round-trip" {
    var reach: SweepReach = .{};
    try sweepParse(20_000, &reach);
    try sweepRoundtrip(3_000, &reach);
    // Reach floors. Measured 2026-10-04: links 11414, params 30732, quoted
    // 10580, with escapes 2886, ext-values decoded 1900 / refused 20585. A
    // generator that stopped producing links, quotes, escapes or decodable
    // ext-values would fall below these long before it stopped "passing".
    try testing.expect(reach.links > 9000);
    try testing.expect(reach.params > 25000);
    try testing.expect(reach.quoted > 8000);
    try testing.expect(reach.escapes > 2000);
    try testing.expect(reach.ext_ok > 1500);
    try testing.expect(reach.ext_err > 15000);
    try testing.expectEqual(@as(usize, 6000), reach.roundtrips);
}

// ── tests added for mutation survivors (2026-10-04) ─────────────────────────

test "build: a lone `*` is an ordinary token name, not extended notation" {
    // RFC 9110 tchar includes `*`, so `*` alone is a plain param name and its
    // value is quoted; only `name*` with a non-empty `name` is an ext-param.
    var buf: [64]u8 = undefined;
    const out = try bufPrint(&buf, &.{.{ .uri = "/a", .rel = "r", .extra = &.{.{ .name = "*", .value = "v w" }} }});
    try testing.expectEqualStrings("</a>; rel=\"r\"; *=\"v w\"", out);
}

test "parse: a repeated anchor keeps the first, as every modelled param does" {
    // The module's stated rule (first occurrence wins, RFC 8288 §3.3's rule
    // for rel applied to all): `anchor` must agree with `param("anchor")`,
    // which returns the first.
    var it = parse("<u>; rel=a; anchor=\"#1\"; anchor=\"#2\"; media=x; media=y");
    const l = it.next().?;
    try testing.expectEqualStrings("#1", l.anchor.?);
    try testing.expectEqualStrings(l.param("anchor").?.value, l.anchor.?);
    try testing.expectEqualStrings("x", l.media.?);
}

test "preferredTitle: a buffer too small for title* is an error, not a silent fallback" {
    // Falling back to `title` here would show the less-preferred label only
    // because the caller's buffer was short; the caller must learn to grow it.
    var it = parse("<u>; rel=a; title=E; title*=utf-8''%e2%82%ac%20rates");
    const l = it.next().?;
    var b: [2]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, l.preferredTitle(&b));
    var big: [16]u8 = undefined;
    try testing.expectEqualStrings("\u{20ac} rates", (try l.preferredTitle(&big)).?);
}

test "parse: an escaped quote inside a skipped malformed segment does not end the quote" {
    // In `junk "x\", <evil>; rel=evil, y"` the `\"` is escaped, so the quoted
    // string runs to the last `"` and `<evil>` is inside it: never a link.
    var it = parse("junk \"x\\\", <evil>; rel=evil, y\", <v>; rel=next");
    const l = it.next().?;
    try testing.expectEqualStrings("v", l.uri);
    try testing.expect(it.next() == null);
}

test "params: an empty name is not a param" {
    // link-param = token …, and a token is 1*tchar: `;=x` and `; ;` carry no
    // param, so `params()` yields only `rel`.
    var it = parse("<u>; ;=x; rel=a;");
    const l = it.next().?;
    var ps = l.params();
    try testing.expectEqualStrings("rel", ps.next().?.name);
    try testing.expect(ps.next() == null);
}
