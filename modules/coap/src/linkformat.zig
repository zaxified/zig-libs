// SPDX-License-Identifier: MIT

//! coap link-format (RFC 6690) — the `application/link-format` (Content-Format
//! 40) document that `/.well-known/core` serves: a comma-separated list of
//! `<uri>;attr=value;attr` links.
//!
//! * `Writer` builds a document into a caller buffer, link by link; a link that
//!   does not fit leaves the document as it was (`error.BufferTooSmall`).
//! * `Parser` iterates the links of a document and `Link.attrs()` its
//!   attributes, borrowing the input. A link is validated as a whole by
//!   `Parser.next`, so the attribute iterator cannot fail afterwards.
//! * `Filter` is the §4.1 discovery query (`?rt=temp*`, `?href=/a`, …).
//!
//! Grammar (RFC 6690 §2, over RFC 5988/8288 link-values): `link-value = "<"
//! URI-Reference ">" *( ";" link-param )`, `link-param = parmname [ "=" ( ptoken
//! / quoted-string ) ]`. The parser also accepts optional blanks around `,`, `;`
//! and `=` (RFC 8288 allows them; CoAP servers rarely emit them). Names compare
//! case-insensitively. Zero allocation; every scan is a bounded forward pass.

const std = @import("std");

pub const Error = error{
    /// The output buffer cannot hold the link; nothing was written for it.
    BufferTooSmall,
    /// A URI-Reference containing `>` or a control/blank octet.
    BadUri,
    /// An attribute name with a character outside `attr-char`, or empty.
    BadAttribute,
    /// A value with a control octet (cannot be a `ptoken` or a quoted-string).
    BadValue,
};

pub const ParseError = error{
    /// The text is not a well-formed link-format document.
    Malformed,
};

/// One attribute to write: `name`, `name=value` or `name="value"`.
pub const Attr = struct {
    name: []const u8,
    /// Null writes a flag attribute (`;obs`).
    value: ?[]const u8 = null,
    /// Force the quoted-string form. Values that are not a plain `ptoken`
    /// (empty, blanks, `,` `;` `"` …) are quoted regardless.
    quoted: bool = false,
};

/// The typed attributes RFC 6690 / RFC 7252 §7.2 define, in the order the
/// RFC examples print them.
pub const Params = struct {
    /// `rt` Resource Type (§3.1), possibly several space-separated values.
    rt: ?[]const u8 = null,
    /// `if` Interface Description (§3.2).
    if_: ?[]const u8 = null,
    /// `ct` Content-Format identifiers (RFC 7252 §7.2.1): one is written
    /// bare (`ct=40`), several as a quoted list (`ct="40 41"`).
    ct: []const u16 = &.{},
    /// `sz` maximum size estimate (§3.3).
    sz: ?u64 = null,
    /// `obs` observable flag (RFC 7641 §6).
    obs: bool = false,
    /// `title` (RFC 8288), written as a quoted-string.
    title: ?[]const u8 = null,
    /// Any further attributes, written after the typed ones.
    extra: []const Attr = &.{},
};

/// Link-format document builder over a caller buffer.
pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    /// The document written so far.
    pub fn written(w: *const Writer) []const u8 {
        return w.buf[0..w.len];
    }

    /// Append `<uri>` followed by `attrs`. On error the document is unchanged.
    pub fn link(w: *Writer, uri: []const u8, attrs: []const Attr) Error!void {
        const saved = w.len;
        errdefer w.len = saved;
        try w.begin(uri);
        for (attrs) |a| try w.attr(a);
    }

    /// Append `<uri>` with the typed `Params`. On error the document is unchanged.
    pub fn resource(w: *Writer, uri: []const u8, p: Params) Error!void {
        const saved = w.len;
        errdefer w.len = saved;
        try w.begin(uri);
        if (p.rt) |v| try w.attr(.{ .name = "rt", .value = v, .quoted = true });
        if (p.if_) |v| try w.attr(.{ .name = "if", .value = v, .quoted = true });
        if (p.ct.len == 1) {
            try w.put(";ct=");
            try w.putUint(p.ct[0]);
        } else if (p.ct.len > 1) {
            try w.put(";ct=\"");
            for (p.ct, 0..) |c, i| {
                if (i != 0) try w.put(" ");
                try w.putUint(c);
            }
            try w.put("\"");
        }
        if (p.sz) |v| {
            try w.put(";sz=");
            try w.putUint(v);
        }
        if (p.obs) try w.put(";obs");
        if (p.title) |v| try w.attr(.{ .name = "title", .value = v, .quoted = true });
        for (p.extra) |a| try w.attr(a);
    }

    fn begin(w: *Writer, uri: []const u8) Error!void {
        for (uri) |c| if (c <= 0x20 or c == 0x7f or c == '>') return error.BadUri;
        if (w.len != 0) try w.put(",");
        try w.put("<");
        try w.put(uri);
        try w.put(">");
    }

    fn attr(w: *Writer, a: Attr) Error!void {
        if (a.name.len == 0) return error.BadAttribute;
        for (a.name) |c| if (!isAttrChar(c)) return error.BadAttribute;
        try w.put(";");
        try w.put(a.name);
        const v = a.value orelse return;
        try w.put("=");
        for (v) |c| if (c < 0x20 and c != '\t' or c == 0x7f) return error.BadValue;
        var plain = v.len != 0 and !a.quoted;
        if (plain) for (v) |c| if (!isTokenChar(c)) {
            plain = false;
            break;
        };
        if (plain) return w.put(v);
        try w.put("\"");
        var start: usize = 0;
        for (v, 0..) |c, i| if (c == '"' or c == '\\') {
            try w.put(v[start..i]);
            try w.put("\\");
            start = i;
        };
        try w.put(v[start..]);
        try w.put("\"");
    }

    fn put(w: *Writer, s: []const u8) Error!void {
        if (w.buf.len - w.len < s.len) return error.BufferTooSmall;
        @memcpy(w.buf[w.len..][0..s.len], s);
        w.len += s.len;
    }

    fn putUint(w: *Writer, v: u64) Error!void {
        var tmp: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable; // u64 is at most 20 digits
        try w.put(s);
    }
};

/// RFC 8288 `attr-char` (a link-param name character), plus `*` so the
/// extension form `title*` parses.
fn isAttrChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '!', '#', '$', '&', '+', '-', '.', '^', '_', '`', '|', '~', '*' => true,
        else => false,
    };
}

/// RFC 5988 `ptokenchar`.
fn isTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '!', '#', '$', '%', '&', '\'', '(', ')', '*', '+', '-', '.', '/', ':', '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

fn isBlank(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn skipBlanks(s: []const u8, pos: *usize) void {
    while (pos.* < s.len and isBlank(s[pos.*])) pos.* += 1;
}

/// One attribute of a link: `value` is the text as written (without the
/// surrounding quotes; backslash escapes are still in it, see the helpers
/// `eql`/`hasToken`/`unescape`).
pub const ParsedAttr = struct {
    name: []const u8,
    /// Null for a flag attribute.
    value: ?[]const u8,
    quoted: bool,

    /// Whether the unescaped value equals `s`.
    pub fn eql(a: ParsedAttr, s: []const u8) bool {
        const v = a.value orelse return false;
        return cmpUnescaped(v, a.quoted, s, false);
    }

    /// Copy the unescaped value into `buf`; null when it does not fit or the
    /// attribute is a flag.
    pub fn unescape(a: ParsedAttr, buf: []u8) ?[]u8 {
        const v = a.value orelse return null;
        var n: usize = 0;
        var i: usize = 0;
        while (i < v.len) : (i += 1) {
            if (a.quoted and v[i] == '\\' and i + 1 < v.len) i += 1;
            if (n == buf.len) return null;
            buf[n] = v[i];
            n += 1;
        }
        return buf[0..n];
    }

    /// Iterates the blank-separated values of a multi-valued attribute
    /// (`rt="a b"`), as written (escapes not removed).
    pub fn tokens(a: ParsedAttr) std.mem.TokenIterator(u8, .scalar) {
        return std.mem.tokenizeScalar(u8, a.value orelse "", ' ');
    }

    /// Whether the attribute, or any one of its blank-separated values, equals
    /// the unescaped `s` (RFC 6690 §4.1: relation-type values match one by one).
    pub fn hasToken(a: ParsedAttr, s: []const u8) bool {
        return a.anyToken(s, false);
    }

    fn anyToken(a: ParsedAttr, pat: []const u8, prefix: bool) bool {
        var it = a.tokens();
        while (it.next()) |t| if (cmpUnescaped(t, a.quoted, pat, prefix)) return true;
        return false;
    }
};

/// Compare `raw` (quoted-string content when `quoted`, so `\x` stands for `x`)
/// with `pat`: equal, or with `prefix` just starting with it.
fn cmpUnescaped(raw: []const u8, quoted: bool, pat: []const u8, prefix: bool) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (j < pat.len) : (j += 1) {
        if (i >= raw.len) return false;
        if (quoted and raw[i] == '\\' and i + 1 < raw.len) i += 1;
        if (raw[i] != pat[j]) return false;
        i += 1;
    }
    return prefix or i == raw.len;
}

/// Scan one `;name[=value]` at `pos`. Null when the next non-blank octet is not
/// `;` (end of this link's attributes); `pos` then sits after the blanks.
fn scanAttr(s: []const u8, pos: *usize) ParseError!?ParsedAttr {
    skipBlanks(s, pos);
    if (pos.* >= s.len or s[pos.*] != ';') return null;
    pos.* += 1;
    skipBlanks(s, pos);
    const name_start = pos.*;
    while (pos.* < s.len and isAttrChar(s[pos.*])) pos.* += 1;
    if (pos.* == name_start) return error.Malformed;
    const name = s[name_start..pos.*];
    const after_name = pos.*;
    skipBlanks(s, pos);
    if (pos.* >= s.len or s[pos.*] != '=') {
        pos.* = after_name; // blanks belong to the separator scan
        return .{ .name = name, .value = null, .quoted = false };
    }
    pos.* += 1;
    skipBlanks(s, pos);
    if (pos.* >= s.len) return error.Malformed;
    if (s[pos.*] == '"') {
        pos.* += 1;
        const v_start = pos.*;
        while (true) {
            if (pos.* >= s.len) return error.Malformed;
            const c = s[pos.*];
            if (c == '\\') {
                if (pos.* + 1 >= s.len) return error.Malformed;
                pos.* += 2;
                continue;
            }
            if (c == '"') break;
            if (c < 0x20 and c != '\t' or c == 0x7f) return error.Malformed;
            pos.* += 1;
        }
        const v = s[v_start..pos.*];
        pos.* += 1; // closing quote
        return .{ .name = name, .value = v, .quoted = true };
    }
    const v_start = pos.*;
    while (pos.* < s.len and isTokenChar(s[pos.*])) pos.* += 1;
    if (pos.* == v_start) return error.Malformed;
    return .{ .name = name, .value = s[v_start..pos.*], .quoted = false };
}

/// One link of a document.
pub const Link = struct {
    /// The target URI-Reference between `<` and `>`.
    uri: []const u8,
    /// The text of all attributes, from the first `;`.
    params: []const u8,

    pub fn attrs(l: Link) AttrIterator {
        return .{ .s = l.params };
    }

    /// The first attribute called `name` (case-insensitive), if any.
    pub fn attr(l: Link, name: []const u8) ?ParsedAttr {
        var it = l.attrs();
        while (it.next()) |a| if (std.ascii.eqlIgnoreCase(a.name, name)) return a;
        return null;
    }
};

pub const AttrIterator = struct {
    s: []const u8,
    pos: usize = 0,

    pub fn next(it: *AttrIterator) ?ParsedAttr {
        // `Parser.next` validated the text with the same scanner.
        return (scanAttr(it.s, &it.pos) catch return null) orelse null;
    }
};

/// Iterates the links of a document.
pub const Parser = struct {
    s: []const u8,
    pos: usize = 0,

    pub fn init(text: []const u8) Parser {
        return .{ .s = text };
    }

    /// The next link; null at the end of the document, `error.Malformed` on bad
    /// text (after which `next` keeps failing at the same place).
    pub fn next(p: *Parser) ParseError!?Link {
        const s = p.s;
        // Skip blanks and empty list elements.
        while (p.pos < s.len and (isBlank(s[p.pos]) or s[p.pos] == ',')) p.pos += 1;
        if (p.pos >= s.len) return null;
        if (s[p.pos] != '<') return error.Malformed;
        const uri_start = p.pos + 1;
        const close = std.mem.findScalarPos(u8, s, uri_start, '>') orelse return error.Malformed;
        const uri = s[uri_start..close];
        for (uri) |c| if (c <= 0x20 or c == 0x7f) return error.Malformed;
        var pos = close + 1;
        const params_start = pos;
        var params_end = pos;
        while (try scanAttr(s, &pos)) |_| params_end = pos;
        // After the attributes: end, or a comma (blanks tolerated).
        skipBlanks(s, &pos);
        if (pos < s.len and s[pos] != ',') return error.Malformed;
        p.pos = pos;
        return .{ .uri = uri, .params = s[params_start..params_end] };
    }
};

/// The §4.1 query filter: one `name=value` pair, where `value` is a complete
/// string, or a prefix followed by `*` (an empty prefix matches any link that
/// has the attribute).
pub const Filter = struct {
    name: []const u8,
    value: []const u8,
    /// `value` had a trailing `*` (stripped).
    prefix: bool,

    /// Parse a Uri-Query parameter (`rt=temp*`); null when it has no `=` or an
    /// empty name (not a filter: RFC 6690 §4.1 defines only `name=value`).
    pub fn parse(param: []const u8) ?Filter {
        const eq = std.mem.findScalar(u8, param, '=') orelse return null;
        if (eq == 0) return null;
        var value = param[eq + 1 ..];
        const prefix = value.len > 0 and value[value.len - 1] == '*';
        if (prefix) value = value[0 .. value.len - 1];
        return .{ .name = param[0..eq], .value = value, .prefix = prefix };
    }

    /// Whether `l` matches. `href` filters the target URI; any other name
    /// filters the attribute of that name — a multi-valued attribute matches
    /// when one of its values does. A link without the attribute never matches.
    /// Matching is bitwise on the unescaped value (no percent-decoding: CoAP
    /// Uri-Query options already carry decoded octets).
    pub fn matches(f: Filter, l: Link) bool {
        if (std.ascii.eqlIgnoreCase(f.name, "href")) return cmpUnescaped(l.uri, false, f.value, f.prefix);
        var it = l.attrs();
        while (it.next()) |a| {
            if (!std.ascii.eqlIgnoreCase(a.name, f.name)) continue;
            if (f.prefix and f.value.len == 0) return true; // `foo=*`: the attribute exists
            if (a.value == null) continue;
            if (a.anyToken(f.value, f.prefix)) return true;
        }
        return false;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "RFC 6690 §5: writer reproduces the example documents" {
    var buf: [256]u8 = undefined;
    // "</sensors>;ct=40;title="Sensor Index","
    var w = Writer.init(&buf);
    try w.resource("/sensors", .{ .ct = &.{40}, .title = "Sensor Index" });
    try w.resource("/sensors/temp", .{ .rt = "temperature-c", .if_ = "sensor" });
    try w.resource("/firmware/v2.1", .{ .rt = "firmware", .sz = 262144 });
    try testing.expectEqualStrings(
        "</sensors>;ct=40;title=\"Sensor Index\"," ++
            "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\"," ++
            "</firmware/v2.1>;rt=\"firmware\";sz=262144",
        w.written(),
    );
}

test "writer: ct list, obs flag, extra attrs, quoting and escapes" {
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    try w.resource("/a", .{ .ct = &.{ 40, 41 }, .obs = true });
    try w.link("/b", &.{
        .{ .name = "x", .value = "plain" },
        .{ .name = "y", .value = "has space" },
        .{ .name = "z", .value = "q\"b\\s" },
        .{ .name = "e", .value = "" },
        .{ .name = "flag" },
    });
    try testing.expectEqualStrings("</a>;ct=\"40 41\";obs,</b>;x=plain;y=\"has space\";z=\"q\\\"b\\\\s\";e=\"\";flag", w.written());
}

test "writer: errors leave the document unchanged" {
    var small: [12]u8 = undefined;
    var w = Writer.init(&small);
    try w.link("/a", &.{});
    try testing.expectError(error.BufferTooSmall, w.link("/bbbbbbbbbbbb", &.{}));
    try testing.expectEqualStrings("</a>", w.written());
    var buf: [64]u8 = undefined;
    var w2 = Writer.init(&buf);
    try w2.link("/a", &.{});
    try testing.expectError(error.BadUri, w2.link("/a b", &.{}));
    try testing.expectError(error.BadUri, w2.link("/a>b", &.{}));
    try testing.expectError(error.BadAttribute, w2.link("/c", &.{.{ .name = "a=b" }}));
    try testing.expectError(error.BadAttribute, w2.link("/c", &.{.{ .name = "" }}));
    try testing.expectError(error.BadValue, w2.link("/c", &.{.{ .name = "a", .value = "x\ny" }}));
    try testing.expectEqualStrings("</a>", w2.written());
}

test "RFC 6690 §5: parser reads the example documents" {
    const doc = "</sensors>;ct=40;title=\"Sensor Index\",</sensors/temp>;rt=\"temperature-c\";if=\"sensor\"," ++
        "</sensors/light>;ct=41;rt=\"light-lux\";if=\"sensor\",</firmware/v2.1>;rt=\"firmware\";sz=262144";
    var p = Parser.init(doc);
    const l1 = (try p.next()).?;
    try testing.expectEqualStrings("/sensors", l1.uri);
    try testing.expect(l1.attr("ct").?.eql("40"));
    try testing.expect(!l1.attr("ct").?.quoted);
    try testing.expect(l1.attr("title").?.quoted);
    try testing.expect(l1.attr("title").?.eql("Sensor Index"));
    const l2 = (try p.next()).?;
    try testing.expectEqualStrings("/sensors/temp", l2.uri);
    try testing.expect(l2.attr("RT").?.eql("temperature-c")); // names are case-insensitive
    try testing.expect(l2.attr("if").?.eql("sensor"));
    try testing.expect(l2.attr("sz") == null);
    const l3 = (try p.next()).?;
    try testing.expect(l3.attr("ct").?.eql("41"));
    const l4 = (try p.next()).?;
    try testing.expect(l4.attr("sz").?.eql("262144"));
    try testing.expect((try p.next()) == null);
    try testing.expect((try p.next()) == null);
}

test "parser: flags, blanks, escapes, empty elements, comma inside a quoted value" {
    var p = Parser.init(" </a> ; obs ; rt = \"x\\\"y z\" ,, </b,c>;t=\"p,q;r\" , </d> ");
    const a = (try p.next()).?;
    try testing.expectEqualStrings("/a", a.uri);
    const obs = a.attr("obs").?;
    try testing.expect(obs.value == null and !obs.quoted);
    const rt = a.attr("rt").?;
    try testing.expect(rt.eql("x\"y z"));
    try testing.expect(rt.hasToken("x\"y") and rt.hasToken("z") and !rt.hasToken("y"));
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("x\"y z", rt.unescape(&buf).?);
    try testing.expect(rt.unescape(buf[0..3]) == null);
    const b = (try p.next()).?;
    try testing.expectEqualStrings("/b,c", b.uri);
    try testing.expect(b.attr("t").?.eql("p,q;r"));
    try testing.expectEqualStrings("/d", (try p.next()).?.uri);
    try testing.expect((try p.next()) == null);
    // The attribute iterator visits every attribute once, in order.
    var it = a.attrs();
    try testing.expectEqualStrings("obs", it.next().?.name);
    try testing.expectEqualStrings("rt", it.next().?.name);
    try testing.expect(it.next() == null);
}

test "parser: malformed documents are errors, not panics" {
    const bad = [_][]const u8{
        "a",
        "</a",
        "</a>x",
        "</a>;",
        "</a>;=1",
        "</a>;rt=",
        "</a>;rt=\"x",
        "</a>;rt=\"x\\",
        "</a>;rt=a\"b\"",
        "</a>;rt=\"a\x01b\"",
        "</a b>",
        "</a>;;rt=x",
        "</a> </b>",
    };
    for (bad) |doc| {
        var p = Parser.init(doc);
        const r = p.next() catch |e| {
            try testing.expectEqual(error.Malformed, e);
            continue;
        };
        // A prefix may parse; the document as a whole must not.
        if (r != null) try testing.expectError(error.Malformed, p.next());
    }
}

test "writer then parser: round trip of hostile attribute values" {
    var buf: [256]u8 = undefined;
    const vals = [_][]const u8{ "", "a", "a b", "q\"", "\\", "x,y;z", "<>", "\tt", "a\\\"b" };
    for (vals) |v| {
        var w = Writer.init(&buf);
        try w.link("/r", &.{ .{ .name = "k", .value = v }, .{ .name = "after", .value = "1" } });
        var p = Parser.init(w.written());
        const l = (try p.next()).?;
        try testing.expect(l.attr("k").?.eql(v));
        try testing.expect(l.attr("after").?.eql("1"));
        try testing.expect((try p.next()) == null);
    }
}

fn expectFilter(param: []const u8, doc: []const u8, want: []const []const u8) !void {
    const f = Filter.parse(param).?;
    var p = Parser.init(doc);
    var got: usize = 0;
    while (try p.next()) |l| {
        if (!f.matches(l)) continue;
        try testing.expect(got < want.len);
        try testing.expectEqualStrings(want[got], l.uri);
        got += 1;
    }
    try testing.expectEqual(want.len, got);
}

test "RFC 6690 §4.1: query filter examples (href, complete, prefix, empty prefix)" {
    const doc = "</foo>;rt=\"light-lux core.sen-light\";foo=bar,</foo/bar>;rt=temp;foo=baz,</x>;obs";
    try expectFilter("href=/foo", doc, &.{"/foo"});
    try expectFilter("href=/foo*", doc, &.{ "/foo", "/foo/bar" });
    try expectFilter("foo=bar", doc, &.{"/foo"});
    try expectFilter("foo=ba*", doc, &.{ "/foo", "/foo/bar" });
    try expectFilter("foo=*", doc, &.{ "/foo", "/foo/bar" });
    try expectFilter("obs=*", doc, &.{"/x"}); // a flag attribute exists
    try expectFilter("obs=a", doc, &.{});
    // §4.1: relation-type values match one by one.
    try expectFilter("rt=light-lux", doc, &.{"/foo"});
    try expectFilter("rt=core.sen-light", doc, &.{"/foo"});
    try expectFilter("rt=core.sen*", doc, &.{"/foo"});
    try expectFilter("rt=light", doc, &.{}); // complete value, not a prefix
    try expectFilter("rt=temp*", doc, &.{"/foo/bar"});
    try expectFilter("nope=*", doc, &.{});
}

test "filter: parse refuses non name=value parameters" {
    try testing.expect(Filter.parse("rt") == null);
    try testing.expect(Filter.parse("=x") == null);
    const f = Filter.parse("rt=").?;
    try testing.expect(!f.prefix and f.value.len == 0);
    const g = Filter.parse("rt=*").?;
    try testing.expect(g.prefix and g.value.len == 0);
}

// ── fuzz: arbitrary text through Parser + Filter, writer ↔ parser model ─────

const testkit = @import("testkit");
const fz = @import("fuzz_test.zig");
const seed = testkit.fuzz.seed;

const link_seeds = [_][]const u8{
    seed("</sensors>;ct=40;title=\"Sensor Index\",</sensors/temp>;rt=\"temperature-c\";if=\"sensor\""),
    seed("</firmware/v2.1>;rt=\"firmware\";sz=262144"),
    seed(" </a> ; obs ; rt = \"x\\\"y z\" ,, </b,c>;t=\"p,q;r\" "),
    seed("</a>;rt=\"x"),
    seed("</a>;=1,<"),
};

const fuzzMark = fz.Marker(enum { ran, parsed_link, with_attr, malformed, filtered_hit, roundtrip });

fn fuzzLinkFormat(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &link_seeds);
    fuzzMark.mark(.ran);
    const text = buf[0..len];

    const filters = [_][]const u8{ "rt=*", "href=/a*", "ct=40", "x=y" };
    var p = Parser.init(text);
    var links: usize = 0;
    while (true) {
        const l = (p.next() catch {
            fuzzMark.mark(.malformed);
            break;
        }) orelse break;
        links += 1;
        fuzzMark.mark(.parsed_link);
        // Termination bound: every link consumes at least `<>`.
        try testing.expect(links <= text.len);
        var it = l.attrs();
        var n: usize = 0;
        while (it.next()) |a| {
            n += 1;
            fuzzMark.mark(.with_attr);
            // Matching an attribute against its own value never fails.
            if (a.value) |v| if (!a.quoted) try testing.expect(a.eql(v));
        }
        try testing.expect(n <= l.params.len);
        for (filters) |q| if (Filter.parse(q).?.matches(l)) fuzzMark.mark(.filtered_hit);

        // Model: re-writing what was parsed and parsing that again agrees.
        var out: [512]u8 = undefined;
        var w = Writer.init(&out);
        var attrs: [16]Attr = undefined;
        var unesc: [256]u8 = undefined;
        var na: usize = 0;
        var used: usize = 0;
        var again = l.attrs();
        while (again.next()) |a| {
            if (na == attrs.len) break;
            var value: ?[]const u8 = null;
            if (a.value != null) {
                const u = a.unescape(unesc[used..]) orelse break;
                value = u;
                used += u.len;
            }
            attrs[na] = .{ .name = a.name, .value = value };
            na += 1;
        }
        if (na != 0 and used <= unesc.len) {
            w.link(l.uri, attrs[0..na]) catch continue;
            var q = Parser.init(w.written());
            const back = (try q.next()).?;
            try testing.expectEqualStrings(l.uri, back.uri);
            var i: usize = 0;
            var bit = back.attrs();
            while (bit.next()) |b| : (i += 1) {
                try testing.expect(i < na);
                try testing.expectEqualStrings(attrs[i].name, b.name);
                if (attrs[i].value) |v| try testing.expect(b.eql(v));
            }
            try testing.expectEqual(na, i);
            fuzzMark.mark(.roundtrip);
        }
    }
}

test "fuzz: link-format parser never panics" {
    try testing.fuzz({}, fuzzLinkFormatSmith, .{ .corpus = &link_seeds });
}

fn fuzzLinkFormatSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzLinkFormat(std.testing.Smith, smith, std.testing.allocator);
}

test "fuzz driver: COAP_FUZZ (fuzzLinkFormat)" {
    try fz.fuzz_driver.run(fuzzLinkFormat, .{ .prefix = "COAP_FUZZ", .name = "coap-linkformat-parse" });
}

test "fuzz harness: fuzzLinkFormat, 600 seeds, reaches every outcome" {
    try fuzzMark.reach(fuzzLinkFormat, "coap-linkformat-parse", 600);
}
