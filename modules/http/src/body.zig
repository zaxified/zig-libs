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
    /// slice into the header (quotes stripped, escapes NOT processed).
    pub fn param(ct: ContentType, name: []const u8) ?[]const u8 {
        var it = ct.params();
        while (it.next()) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) return p.value;
        }
        return null;
    }
};

pub const Param = struct { name: []const u8, value: []const u8 };

/// Iterates `;`-separated `name=value` parameters, quoted-string aware.
pub const ParamIterator = struct {
    rest: []const u8,

    pub fn next(it: *ParamIterator) ?Param {
        while (true) {
            // Trim leading separators/whitespace.
            it.rest = std.mem.trimLeft(u8, it.rest, " \t;");
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
fn indexOfUnquoted(s: []const u8, needle: u8) ?usize {
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
