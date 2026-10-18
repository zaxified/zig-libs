// SPDX-License-Identifier: MIT

//! Request-body helpers: the `Content-Type` media-type + parameter parser
//! (RFC 9110 §5.6.6 / RFC 2045 §5.1) and an `application/x-www-form-urlencoded`
//! decoder (WHATWG URL §application/x-www-form-urlencoded). The streaming
//! `multipart/form-data` parser is a sibling (`http.multipart`) built on the
//! `ContentType` parser here.
//!
//! ## Content-Type
//!
//! ```zig
//! const ct = http.body.ContentType.parse(req.header("content-type") orelse "") orelse return;
//! if (ct.isType("multipart/form-data")) {
//!     const boundary = ct.param("boundary") orelse return; // RFC 2046 §5.1.1
//!     …
//! } else if (ct.isType("application/x-www-form-urlencoded")) {
//!     …
//! }
//! ```
//!
//! Parameter splitting is quoted-string aware: a `;` inside a quoted value
//! (`boundary="a;b"`) does not end the parameter (RFC 9110 §5.6.6 lets a
//! parameter value be a token *or* a quoted-string). Returned values are
//! slices into the header with surrounding quotes stripped; `\`-escapes inside
//! a quoted-string are NOT unescaped (media-type parameters in practice —
//! boundary, charset, name — never use them, and staying escape-literal keeps
//! this allocation-free). Match media types and parameter names
//! case-insensitively (both are case-insensitive per the RFCs); parameter
//! *values* are returned verbatim (case-sensitive — a boundary is).
//!
//! ## x-www-form-urlencoded
//!
//! ```zig
//! // The handler has read the (small) body into a mutable buffer.
//! var it = http.body.urlencoded(body_buf);
//! while (it.next()) |pair| {
//!     // pair.name / pair.value are decoded in place inside body_buf
//! }
//! ```
//!
//! Decoding is done **in place** inside the caller's buffer (percent-decode
//! only ever shrinks, so each field is decoded within its own region) and
//! applies the two form rules: `+` → SPACE, then `%XX` → byte. Keep the
//! multipart path for large/binary uploads — urlencoded buffers the whole
//! body, so bound it with a request body-size limit upstream.

const std = @import("std");

/// A parsed `Content-Type` (or any media-type-valued header, e.g. a multipart
/// part's own `Content-Type` / `Content-Disposition`). `media_type` and
/// `params` are slices into the input header, which must outlive this value.
pub const ContentType = struct {
    /// The `type/subtype` text, trimmed, as it appeared (compare with
    /// `isType`, which is case-insensitive). Never empty for a parse success.
    media_type: []const u8,
    /// The raw parameter section after the first `;` (empty when there are no
    /// parameters); iterate it with `params`.
    params_section: []const u8,

    /// Parse a media-type header value. Returns null when there is no non-empty
    /// media type before the first `;`. Malformed parameters are tolerated (a
    /// best-effort parse — an API server should not 400 purely on a weird
    /// parameter it will not read).
    pub fn parse(header: []const u8) ?ContentType {
        const semi = indexOfUnquoted(header, ';') orelse header.len;
        const mt = std.mem.trim(u8, header[0..semi], " \t");
        if (mt.len == 0) return null;
        const params_sec = if (semi < header.len) header[semi + 1 ..] else "";
        return .{ .media_type = mt, .params_section = params_sec };
    }

    /// Case-insensitive media-type equality (`"multipart/form-data"`).
    pub fn isType(ct: ContentType, media_type: []const u8) bool {
        return std.ascii.eqlIgnoreCase(ct.media_type, media_type);
    }

    /// Iterate the parameters as `{ name, value }` (name trimmed; value
    /// unquoted). Quoted-string aware.
    pub fn params(ct: ContentType) ParamIterator {
        return .{ .rest = ct.params_section };
    }

    /// The value of parameter `name` (case-insensitive), or null. Value is a
    /// slice into the header (quotes stripped, escapes NOT processed — see
    /// `paramUnescaped`). A parameter given twice yields the first.
    pub fn param(ct: ContentType, name: []const u8) ?[]const u8 {
        var it = ct.params();
        while (it.next()) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) return p.value;
        }
        return null;
    }

    /// `param` with a quoted value's quoted-pairs unescaped into `out`
    /// (`name="a\"b"` → `a"b`), as Go's `mime.ParseMediaType` returns it. An
    /// unquoted value is copied as is. `error.NoSpaceLeft` when `out` is
    /// shorter than the result; `value.len` always suffices.
    pub fn paramUnescaped(ct: ContentType, name: []const u8, out: []u8) error{NoSpaceLeft}!?[]const u8 {
        const v = ct.param(name) orelse return null;
        if (v.len > out.len) return error.NoSpaceLeft;
        @memcpy(out[0..v.len], v);
        return if (isQuotedValue(ct.params_section, v)) unescapeQuoted(out[0..v.len]) else out[0..v.len];
    }
};

/// Whether `value` — a slice of `section` handed out by `ParamIterator` — was
/// a quoted-string on the wire (the iterator strips the quotes).
pub fn isQuotedValue(section: []const u8, value: []const u8) bool {
    const off = @intFromPtr(value.ptr) -% @intFromPtr(section.ptr);
    return off > 0 and off <= section.len and section[off - 1] == '"';
}

/// Unescape a quoted-string's quoted-pairs in place and return the shortened
/// slice. Only a backslash before a tspecial (RFC 2045 §5.1) is an escape;
/// any other backslash stays, as Go's `mime.ParseMediaType` keeps it
/// (`"a\xb"` → `a\xb`, Go oracle `name-escaped-letter`).
pub fn unescapeQuoted(v: []u8) []u8 {
    var w: usize = 0;
    var i: usize = 0;
    while (i < v.len) : (i += 1) {
        if (v[i] == '\\' and i + 1 < v.len and isTspecial(v[i + 1])) i += 1;
        v[w] = v[i];
        w += 1;
    }
    return v[0..w];
}

/// RFC 2045 §5.1 tspecials.
fn isTspecial(c: u8) bool {
    return std.mem.indexOfScalar(u8, "()<>@,;:\\\"/[]?=", c) != null;
}

/// RFC 2045 §5.1 token octet: visible ASCII that is not a tspecial.
fn isTokenChar(c: u8) bool {
    return c > 0x20 and c < 0x7f and !isTspecial(c);
}

fn tokenLen(s: []const u8) usize {
    for (s, 0..) |c, i| if (!isTokenChar(c)) return i;
    return s.len;
}

/// What Go's `mime.ParseMediaType` concludes about a media-type header
/// value, without building its parameter map. `ContentType.parse` is the
/// lenient reader; this is the strict verdict, for the places where Go's
/// answer decides what is read at all (a request form's `Content-Type`, a
/// form part's `Content-Disposition`).
pub const MediaTypeCheck = struct {
    /// The media type (trimmed, case as sent), or "" when Go refuses the
    /// header outright: no type, a malformed type, or a parameter given twice
    /// with two different values.
    media_type: []const u8,
    /// No error at all: a well-formed type and every parameter
    /// `token "=" (token / quoted-string)`. Go still returns the type when
    /// only a parameter is malformed (`ErrInvalidMediaParameter`), so
    /// `media_type` can be set while this is false.
    clean: bool,
};

/// Go's `mime.ParseMediaType` verdict on `header` (see `MediaTypeCheck`).
/// Its rules, taken from the Go 1.26 source and pinned by the Go oracle:
/// the type is `token ["/" token]`; a parameter value is a token or a
/// quoted-string (a quoted CR or LF, or a missing closing quote, is
/// malformed); one trailing `;` is tolerated; a repeated parameter name is
/// an error only when the values differ (compared unescaped); RFC 2231
/// `name*` parameters are checked as names of their own. More than
/// `max_checked_params` parameters are reported malformed, which keeps the
/// duplicate check linear (Go has no cap; no sender comes close).
pub fn checkMediaType(header: []const u8) MediaTypeCheck {
    const ws = &std.ascii.whitespace;
    const semi = std.mem.indexOfScalar(u8, header, ';') orelse header.len;
    const mt = std.mem.trim(u8, header[0..semi], ws);
    if (!validMediaType(mt)) return .{ .media_type = "", .clean = false };
    const bad_param: MediaTypeCheck = .{ .media_type = mt, .clean = false };

    var seen: [max_checked_params]StrictParam = undefined;
    var n: usize = 0;
    var rest = header[semi..];
    while (true) {
        rest = std.mem.trimStart(u8, rest, ws);
        if (rest.len == 0) break;
        const p = StrictParam.consume(rest) orelse {
            if (std.mem.eql(u8, std.mem.trim(u8, rest, ws), ";")) break;
            return bad_param;
        };
        for (seen[0..n]) |s| {
            if (std.ascii.eqlIgnoreCase(s.name, p.name) and !s.valueEql(p))
                return .{ .media_type = "", .clean = false };
        }
        if (n == seen.len) return bad_param;
        seen[n] = p;
        n += 1;
        rest = p.rest;
    }
    return .{ .media_type = mt, .clean = true };
}

/// Parameters `checkMediaType` compares for duplicates before it gives up.
pub const max_checked_params = 32;

/// Go's `checkMediaTypeDisposition`: `token ["/" token]`, nothing else.
fn validMediaType(mt: []const u8) bool {
    const t = tokenLen(mt);
    if (t == 0) return false;
    if (t == mt.len) return true;
    if (mt[t] != '/') return false;
    const sub = tokenLen(mt[t + 1 ..]);
    return sub != 0 and t + 1 + sub == mt.len;
}

/// One `; name=value` as Go's `consumeMediaParam` reads it.
const StrictParam = struct {
    name: []const u8,
    /// The value as sent, without the quotes of a quoted-string (escapes kept).
    value: []const u8,
    quoted: bool,
    rest: []const u8,

    fn consume(in: []const u8) ?StrictParam {
        const ws = &std.ascii.whitespace;
        if (in.len == 0 or in[0] != ';') return null;
        var r = std.mem.trimStart(u8, in[1..], ws);
        const name_len = tokenLen(r);
        if (name_len == 0) return null;
        const name = r[0..name_len];
        r = std.mem.trimStart(u8, r[name_len..], ws);
        if (r.len == 0 or r[0] != '=') return null;
        r = std.mem.trimStart(u8, r[1..], ws);
        if (r.len != 0 and r[0] == '"') {
            var i: usize = 1;
            while (i < r.len) : (i += 1) switch (r[i]) {
                '"' => return .{ .name = name, .value = r[1..i], .quoted = true, .rest = r[i + 1 ..] },
                '\\' => if (i + 1 < r.len and isTspecial(r[i + 1])) {
                    i += 1;
                },
                '\r', '\n' => return null,
                else => {},
            };
            return null; // no closing quote
        }
        const len = tokenLen(r);
        if (len == 0) return null;
        return .{ .name = name, .value = r[0..len], .quoted = false, .rest = r[len..] };
    }

    /// Equal values once a quoted-string's quoted-pairs are unescaped.
    fn valueEql(a: StrictParam, b: StrictParam) bool {
        var x: Unescaped = .{ .s = a.value, .quoted = a.quoted };
        var y: Unescaped = .{ .s = b.value, .quoted = b.quoted };
        while (true) {
            const cx = x.next();
            const cy = y.next();
            if (cx == null or cy == null) return cx == null and cy == null;
            if (cx.? != cy.?) return false;
        }
    }
};

/// The octets of a parameter value with `unescapeQuoted`'s rule applied.
const Unescaped = struct {
    s: []const u8,
    quoted: bool,
    i: usize = 0,

    fn next(u: *Unescaped) ?u8 {
        if (u.i == u.s.len) return null;
        if (u.quoted and u.s[u.i] == '\\' and u.i + 1 < u.s.len and isTspecial(u.s[u.i + 1])) u.i += 1;
        u.i += 1;
        return u.s[u.i - 1];
    }
};

pub const Param = struct { name: []const u8, value: []const u8 };

/// Iterates `;`-separated `name=value` parameters, quoted-string aware.
pub const ParamIterator = struct {
    rest: []const u8,

    pub fn next(it: *ParamIterator) ?Param {
        while (true) {
            // Trim leading separators/whitespace.
            it.rest = std.mem.trimStart(u8, it.rest, " \t;");
            if (it.rest.len == 0) return null;
            const end = indexOfUnquoted(it.rest, ';') orelse it.rest.len;
            const seg = it.rest[0..end];
            it.rest = it.rest[end..];
            const eq = std.mem.indexOfScalar(u8, seg, '=') orelse {
                // Valueless parameter (rare) — return with an empty value.
                const name = std.mem.trim(u8, seg, " \t");
                if (name.len == 0) continue;
                return .{ .name = name, .value = "" };
            };
            const name = std.mem.trim(u8, seg[0..eq], " \t");
            if (name.len == 0) continue;
            var value = std.mem.trim(u8, seg[eq + 1 ..], " \t");
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }
            return .{ .name = name, .value = value };
        }
    }
};

/// Index of the first `needle` byte in `s` that is NOT inside a quoted-string
/// (`"…"`, with `\` escaping the next byte), or null. Used to split media-type
/// parameters without being fooled by a `;` inside `boundary="a;b"`.
pub fn indexOfUnquoted(s: []const u8, needle: u8) ?usize {
    var i: usize = 0;
    var in_quote = false;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (in_quote) {
            if (c == '\\' and i + 1 < s.len) {
                i += 1; // skip the escaped byte
            } else if (c == '"') {
                in_quote = false;
            }
        } else if (c == '"') {
            in_quote = true;
        } else if (c == needle) {
            return i;
        }
    }
    return null;
}

/// One decoded `name=value` pair from an urlencoded body. Slices point into
/// the caller's (now-mutated) buffer.
pub const FormPair = struct { name: []const u8, value: []const u8 };

/// Iterates `application/x-www-form-urlencoded` pairs, decoding each field in
/// place inside the backing buffer (`+`→SPACE then `%XX`). The buffer is
/// mutated as iteration proceeds; a returned slice stays valid (each field is
/// decoded within its own region and never overwritten by a later field).
pub const UrlEncodedIterator = struct {
    /// Not-yet-consumed tail of the original buffer (still encoded).
    rest: []u8,

    pub fn next(it: *UrlEncodedIterator) ?FormPair {
        while (true) {
            if (it.rest.len == 0) return null;
            const amp = std.mem.indexOfScalar(u8, it.rest, '&') orelse it.rest.len;
            var field = it.rest[0..amp];
            it.rest = if (amp < it.rest.len) it.rest[amp + 1 ..] else it.rest[it.rest.len..];
            if (field.len == 0) continue; // skip empty pairs ("a=1&&b=2")
            const eq = std.mem.indexOfScalar(u8, field, '=');
            if (eq) |e| {
                const name = decodeInPlace(field[0..e]);
                const value = decodeInPlace(field[e + 1 ..]);
                return .{ .name = name, .value = value };
            }
            return .{ .name = decodeInPlace(field), .value = "" };
        }
    }
};

/// Start an urlencoded pair iterator over `buf` (the request body, read into a
/// caller-owned mutable buffer). `buf` is decoded in place during iteration.
pub fn urlencoded(buf: []u8) UrlEncodedIterator {
    return .{ .rest = buf };
}

/// `+`→SPACE then percent-decode, in place; returns the (shorter-or-equal)
/// decoded slice.
fn decodeInPlace(field: []u8) []u8 {
    for (field) |*c| {
        if (c.* == '+') c.* = ' ';
    }
    return std.Uri.percentDecodeInPlace(field);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "ContentType.parse: media type + isType, no params" {
    const ct = ContentType.parse("application/json").?;
    try testing.expectEqualStrings("application/json", ct.media_type);
    try testing.expect(ct.isType("application/JSON")); // case-insensitive
    try testing.expect(!ct.isType("text/plain"));
    try testing.expectEqual(@as(?[]const u8, null), ct.param("charset"));

    // Trimming + trailing ';' with no params.
    const ct2 = ContentType.parse("  text/html ; ").?;
    try testing.expectEqualStrings("text/html", ct2.media_type);

    // Empty / no media type → null.
    try testing.expectEqual(@as(?ContentType, null), ContentType.parse(""));
    try testing.expectEqual(@as(?ContentType, null), ContentType.parse("  ; charset=utf-8"));
}

test "ContentType.param: token and quoted values, case-insensitive names" {
    const ct = ContentType.parse("text/plain; charset=utf-8; format=Flowed").?;
    try testing.expectEqualStrings("utf-8", ct.param("charset").?);
    try testing.expectEqualStrings("utf-8", ct.param("CharSet").?); // name CI
    try testing.expectEqualStrings("Flowed", ct.param("format").?); // value CS
    try testing.expectEqual(@as(?[]const u8, null), ct.param("boundary"));

    // Quoted boundary containing a ';' must NOT be split.
    const mp = ContentType.parse("multipart/form-data; boundary=\"a;b=c\"").?;
    try testing.expect(mp.isType("multipart/form-data"));
    try testing.expectEqualStrings("a;b=c", mp.param("boundary").?);

    // Ordinary token boundary.
    const mp2 = ContentType.parse("multipart/form-data; boundary=----XYZ").?;
    try testing.expectEqualStrings("----XYZ", mp2.param("boundary").?);
}

test "ContentType.params: iteration incl. a valueless parameter" {
    const ct = ContentType.parse("a/b; x=1; flag; y=\"two\"").?;
    var it = ct.params();
    const p1 = it.next().?;
    try testing.expectEqualStrings("x", p1.name);
    try testing.expectEqualStrings("1", p1.value);
    const p2 = it.next().?;
    try testing.expectEqualStrings("flag", p2.name);
    try testing.expectEqualStrings("", p2.value);
    const p3 = it.next().?;
    try testing.expectEqualStrings("y", p3.name);
    try testing.expectEqualStrings("two", p3.value);
    try testing.expectEqual(@as(?Param, null), it.next());
}

test "urlencoded: decode pairs, '+' and percent, empty and valueless" {
    var buf = "name=John+Doe&city=New%20York&flag&empty=".*;
    var it = urlencoded(&buf);
    const p1 = it.next().?;
    try testing.expectEqualStrings("name", p1.name);
    try testing.expectEqualStrings("John Doe", p1.value);
    const p2 = it.next().?;
    try testing.expectEqualStrings("city", p2.name);
    try testing.expectEqualStrings("New York", p2.value);
    const p3 = it.next().?;
    try testing.expectEqualStrings("flag", p3.name);
    try testing.expectEqualStrings("", p3.value);
    const p4 = it.next().?;
    try testing.expectEqualStrings("empty", p4.name);
    try testing.expectEqualStrings("", p4.value);
    try testing.expectEqual(@as(?FormPair, null), it.next());
}

test "urlencoded: percent-decoded key, literal '+' as %2B, skips empty fields" {
    var buf = "a%2Bb=1%2B1&&x=%41".*;
    var it = urlencoded(&buf);
    const p1 = it.next().?;
    try testing.expectEqualStrings("a+b", p1.name); // %2B in key
    try testing.expectEqualStrings("1+1", p1.value); // %2B in value, not '+'
    const p2 = it.next().?; // the empty field between && is skipped
    try testing.expectEqualStrings("x", p2.name);
    try testing.expectEqualStrings("A", p2.value); // %41 = 'A'
    try testing.expectEqual(@as(?FormPair, null), it.next());
}

test "urlencoded: empty buffer yields nothing" {
    var buf = "".*;
    var it = urlencoded(&buf);
    try testing.expectEqual(@as(?FormPair, null), it.next());
}

// ── fuzz: Content-Type and urlencoded body parse, never panic ──────────────
//
// `ContentType.parse`/`params` reads the request's `Content-Type` header
// directly (and, via `multipart.zig`, each part's `Content-Disposition` —
// both attacker-controlled); `urlencoded` decodes an
// `application/x-www-form-urlencoded` body in place. Both are untrusted-
// wire parsers with no existing fuzz coverage.
//
// ⚠ Both harnesses used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and a ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain — so the length was 0 on
// every input a corpus can carry, and both parsers were handed an empty slice
// while the header sat unread in `buf`. One `slice` draw fixes both halves:
// it reads the corpus entry's own length header and hands the bytes over
// intact.

/// `testkit.fuzz.seed`, aliased so the corpora below read as the header values
/// and bodies they are. A corpus entry is not the frame: the draw reads a
/// little-endian `u32` length first, so a raw header would arrive minus its own
/// first four octets. `testkit/src/fuzz.zig` carries the other two hazards.
const seed = @import("testkit").fuzz.seed;

/// Media-type header values, in the format the length draw reads.
///
/// Every shape the value tests above pin, plus the quoting edges `multipart`
/// depends on: a `;` inside a quoted boundary, a `\`-escape inside one, and an
/// unterminated quote (which makes `indexOfUnquoted` run to the end of the
/// header — the loop this harness exists to bound).
const content_type_seeds = [_][]const u8{
    seed("application/json"), // no parameters at all
    seed("  text/html ; "), // leading/trailing space and a trailing empty parameter section
    seed("  ; charset=utf-8"), // no media type before the ';' → parse returns null
    seed("text/plain; charset=utf-8; format=Flowed"), // two token parameters
    seed("multipart/form-data; boundary=\"a;b=c\""), // a ';' inside a quoted value must not split
    seed("multipart/form-data; boundary=----XYZ"), // an ordinary token boundary
    seed("a/b; x=1; flag; y=\"two\""), // a valueless parameter between two valued ones
    seed("multipart/form-data; boundary=\"a\\\"b\""), // a '\'-escaped quote inside the value
    seed("text/plain; charset=\"utf-8"), // unterminated quote: the scan runs to the end
    seed("application/x-www-form-urlencoded"), // the sibling body type
    seed("text/plain;;;=1;  ;name="), // empty names and an empty value, all skipped or empty
    seed("application/json\t; charset=\tUTF-8\t"), // tabs are the other OWS byte
};

const fz = @import("fuzz_test.zig");
const CtMark = fz.Marker(enum { rejected, parsed, with_params });
const UrlMark = fz.Marker(enum { empty, pairs });

test "fuzz: ContentType.parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzContentTypeSmith, .{ .corpus = &content_type_seeds });
}

test "fuzz driver: HTTP_FUZZ (content-type)" {
    try fz.fuzz_driver.run(fuzzContentType, .{ .prefix = "HTTP_FUZZ", .name = "http-content-type" });
}

test "fuzz harness: content-type, 300 seeds, reaches every outcome" {
    try CtMark.reach(fuzzContentType, "http-content-type", 300);
}

fn fuzzContentTypeSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzContentType, smith, script[0..n]);
}

fn fuzzContentType(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &content_type_seeds);

    const ct = ContentType.parse(buf[0..len]) orelse return CtMark.mark(.rejected);
    CtMark.mark(.parsed);
    var it = ct.params();
    var any = false;
    while (it.next()) |_| any = true;
    if (any) CtMark.mark(.with_params);
}

test "corpus: every media-type seed reaches the parser, and the parameters walked are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. It draws
    // exactly the way the harness does, because a guard measuring a different
    // draw from the one the harness gets is not a guard — and the defect was in
    // the draw.
    //
    // `params` is the second number, and it is the one that matters:
    // `ContentType.parse("")` returns null, so a "parsed > 0" guard would have
    // been satisfied by any seed carrying a single letter. Parameters walked
    // cannot be produced by an empty input at all.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var params_walked: usize = 0;
    for (content_type_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const ct = ContentType.parse(buf[0..len]) orelse continue;
        parsed += 1;
        var it = ct.params();
        while (it.next()) |_| params_walked += 1;
    }
    try testing.expectEqual(content_type_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 12 seeds non-empty, 0 parsed and 0 parameters
    // walked before the draw was fixed; 12 / 11 / 11 after.
    try testing.expectEqual(@as(usize, 11), parsed); // the ";  charset" seed is the one legal refusal
    try testing.expectEqual(@as(usize, 11), params_walked);
}

/// `application/x-www-form-urlencoded` bodies, in the format the length draw
/// reads. Percent-decoding is done IN PLACE, so the interesting seeds are the
/// ones where the decoded field is shorter than the encoded one, and the ones
/// where a `%` escape is truncated at the very end of the buffer.
const urlencoded_seeds = [_][]const u8{
    seed("name=John+Doe&city=New%20York&flag&empty="), // the four pair shapes the value tests pin
    seed("a%2Bb=1%2B1&&x=%41"), // %2B is a literal '+', and the empty field between && is skipped
    seed("q=hello"), // the smallest real pair
    seed("%"), // a percent escape truncated by the end of the body
    seed("a=%2"), // a percent escape one octet short
    seed("a=%zz&b=%2G"), // percent escapes whose digits are not hex
    seed("&&&&"), // nothing but separators
    seed("=value"), // an empty name
    seed("a=1&a=2&a=3"), // a repeated key
    seed("k=%00%01%ff"), // NUL and high bytes decoded in place
    seed("+++=+++"), // '+' on both sides of the '='
    seed("a"), // a valueless field with no '=' at all
};

test "fuzz: urlencoded never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzUrlencodedSmith, .{ .corpus = &urlencoded_seeds });
}

test "fuzz driver: HTTP_FUZZ (urlencoded)" {
    try fz.fuzz_driver.run(fuzzUrlencoded, .{ .prefix = "HTTP_FUZZ", .name = "http-urlencoded" });
}

test "fuzz harness: urlencoded, 300 seeds, reaches every outcome" {
    try UrlMark.reach(fuzzUrlencoded, "http-urlencoded", 300);
}

fn fuzzUrlencodedSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzUrlencoded, smith, script[0..n]);
}

fn fuzzUrlencoded(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &urlencoded_seeds);

    var it = urlencoded(buf[0..len]);
    var pairs = false;
    while (it.next()) |_| pairs = true;
    if (pairs) UrlMark.mark(.pairs) else UrlMark.mark(.empty);
}

test "corpus: every urlencoded seed reaches the decoder, and the pairs yielded are pinned" {
    // Pairs yielded rather than "it did not crash": `urlencoded("")` yields
    // nothing and returns cleanly, so there is no error path a guard could
    // count. The empty input yields exactly zero pairs, which is why this
    // number is the one that falls if the draw ever collapses again.
    var nonempty: usize = 0;
    var pairs: usize = 0;
    var decoded_octets: usize = 0;
    for (urlencoded_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var it = urlencoded(buf[0..len]);
        while (it.next()) |p| {
            pairs += 1;
            // The in-place decode is the part carrying a memory-safety
            // argument, so count what it actually produced, not just calls.
            decoded_octets += p.name.len + p.value.len;
        }
    }
    try testing.expectEqual(urlencoded_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 12 seeds non-empty, 0 pairs and 0 decoded
    // octets before the draw was fixed; 12 / 18 / 81 after.
    try testing.expectEqual(@as(usize, 18), pairs);
    try testing.expectEqual(@as(usize, 81), decoded_octets);
}

test "checkMediaType: Go's verdicts on type, parameter and duplicate shapes" {
    const Case = struct { in: []const u8, mt: []const u8, clean: bool };
    const cases = [_]Case{
        .{ .in = "application/x-www-form-urlencoded", .mt = "application/x-www-form-urlencoded", .clean = true },
        .{ .in = "  Text/Plain ;charset = \"utf-8\" ", .mt = "Text/Plain", .clean = true },
        .{ .in = "application", .mt = "application", .clean = true }, // no subtype is fine
        .{ .in = "text/plain;", .mt = "text/plain", .clean = true }, // one trailing ';'
        .{ .in = "text/plain;;", .mt = "text/plain", .clean = false },
        .{ .in = "", .mt = "", .clean = false },
        .{ .in = "; charset=x", .mt = "", .clean = false },
        .{ .in = "text/", .mt = "", .clean = false },
        .{ .in = "text/plain x", .mt = "", .clean = false },
        .{ .in = "text/plain/x", .mt = "", .clean = false },
        .{ .in = "text/plain; charset", .mt = "text/plain", .clean = false }, // valueless
        .{ .in = "text/plain; charset=", .mt = "text/plain", .clean = false }, // empty token
        .{ .in = "text/plain; charset=\"\"", .mt = "text/plain", .clean = true }, // empty quoted is a value
        .{ .in = "text/plain; a=b/c", .mt = "text/plain", .clean = false }, // '/' ends the token, then junk
        .{ .in = "text/plain; a=\"b", .mt = "text/plain", .clean = false }, // unterminated
        .{ .in = "text/plain; a=\"b\\\"", .mt = "text/plain", .clean = false }, // the quote is escaped
        .{ .in = "text/plain; a=\"b\\x\"", .mt = "text/plain", .clean = true }, // \x is literal
        .{ .in = "text/plain; a=1; A=2", .mt = "", .clean = false }, // duplicate, values differ
        .{ .in = "text/plain; a=1; A=\"1\"", .mt = "text/plain", .clean = true }, // equal once unquoted
        .{ .in = "text/plain; a=\"\\;\"; a=\";\"", .mt = "text/plain", .clean = true }, // equal once unescaped
        .{ .in = "text/plain; a=1; a*=2", .mt = "text/plain", .clean = true }, // `a*` is its own name
    };
    for (cases) |c| {
        const got = checkMediaType(c.in);
        testing.expectEqualStrings(c.mt, got.media_type) catch |e| {
            std.debug.print("case {f}\n", .{std.zig.fmtString(c.in)});
            return e;
        };
        testing.expectEqual(c.clean, got.clean) catch |e| {
            std.debug.print("case {f}\n", .{std.zig.fmtString(c.in)});
            return e;
        };
    }
    // Past the parameter cap: malformed, the type kept.
    const many = "a/b" ++ (strRepeat("; p=1", max_checked_params + 1));
    const got = checkMediaType(many);
    try testing.expectEqualStrings("a/b", got.media_type);
    try testing.expect(!got.clean);
}

test "ContentType.paramUnescaped: quoted-pairs before tspecials only, unquoted copied, short out refused" {
    const ct = ContentType.parse("form-data; name=\"a\\\"b\\\\c\\x\"; plain=x\\y").?;
    var out: [32]u8 = undefined;
    try std.testing.expectEqualStrings("a\"b\\c\\x", (try ct.paramUnescaped("name", &out)).?);
    // Unquoted: no unescaping (a backslash is not legal in a token anyway).
    try std.testing.expectEqualStrings("x\\y", (try ct.paramUnescaped("plain", &out)).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try ct.paramUnescaped("missing", &out));
    var tiny: [3]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, ct.paramUnescaped("name", &tiny));
    // A trailing lone backslash stays.
    var v = "a\\".*;
    try std.testing.expectEqualStrings("a\\", unescapeQuoted(&v));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * 2 + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
