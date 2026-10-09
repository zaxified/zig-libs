// SPDX-License-Identifier: MIT
//! Query-string parameters and path percent-decoding, over the raw `path`
//! and `query` slices `Server.Request` carries.
//!
//!     var buf: [256]u8 = undefined;
//!     const page = try http.url.param(req.query, "page", &buf); // ?[]const u8
//!     const path = try http.url.decodePath(&buf, req.path);
//!
//! Everything decodes into a buffer the caller names; nothing allocates.
//!
//! ⛔ Decoding is strict, for two different reasons:
//!   * A path that decodes a `/` (`%2F`) or a NUL (`%00`) is refused, not
//!     decoded: `/a%2Fb` and `/a/b` must never reach the same handler, and
//!     the rule that decides what a path segment is has to live in one place.
//!   * A malformed escape (`%zz`, a truncated `%4`) is refused in a path AND
//!     in a query component. A lenient decoder that passes it through
//!     verbatim invites a second decoder somewhere else to read the same
//!     bytes differently. Go's `url.ParseQuery` refuses it too. (The body
//!     decoder, `body.urlencoded`, follows the WHATWG form parser and is
//!     lenient; a form body is not routed on.)
//!
//! Parameter keys are compared after decoding, so `?user%5Fid=1` answers
//! `user_id`. The first match wins; `a=1&a=2` answers "1" — iterate with
//! `QueryIterator` for every value.

const std = @import("std");

pub const DecodeError = error{
    /// A `%` not followed by two hex digits.
    MalformedEscape,
    /// A path decodes a `/` or a NUL: refuse it, do not route it.
    EncodedSeparator,
    /// `out` is shorter than the decoded value.
    NoSpaceLeft,
};

const Mode = enum { path, query };

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// One decoded byte of `in` at `i.*`, advancing `i`. `+` is a space only in
/// a query component; in a path it is a literal.
fn nextByte(comptime mode: Mode, in: []const u8, i: *usize) DecodeError!u8 {
    const c = in[i.*];
    if (c == '%') {
        if (in.len - i.* < 3) return error.MalformedEscape;
        const hi = hexVal(in[i.* + 1]) orelse return error.MalformedEscape;
        const lo = hexVal(in[i.* + 2]) orelse return error.MalformedEscape;
        const b = hi << 4 | lo;
        if (mode == .path and (b == '/' or b == 0)) return error.EncodedSeparator;
        i.* += 3;
        return b;
    }
    i.* += 1;
    return if (mode == .query and c == '+') ' ' else c;
}

fn decode(comptime mode: Mode, out: []u8, in: []const u8) DecodeError![]const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < in.len) : (o += 1) {
        const b = try nextByte(mode, in, &i);
        if (o == out.len) return error.NoSpaceLeft;
        out[o] = b;
    }
    return out[0..o];
}

/// `path` percent-decoded into `out`. `+` stays a `+`. Refuses a decoded
/// `/` or NUL (`error.EncodedSeparator`) and a malformed escape. A decoded
/// value is never longer than its input, so `out.len >= path.len` always
/// suffices.
pub fn decodePath(out: []u8, path: []const u8) DecodeError![]const u8 {
    return decode(.path, out, path);
}

/// One query component (a key or a value) decoded into `out`: `+` is a
/// space, `%XX` a byte, a malformed escape `error.MalformedEscape`.
pub fn decodeComponent(out: []u8, raw: []const u8) DecodeError![]const u8 {
    return decode(.query, out, raw);
}

/// One `key=value` pair, both still encoded. A pair with no `=` has the
/// value "".
pub const RawPair = struct { key: []const u8, value: []const u8 };

/// Every pair of a raw query string, in order, empty pairs (`a=1&&b=2`)
/// skipped. Nothing is decoded or mutated; decode with `decodeComponent`.
pub const QueryIterator = struct {
    rest: []const u8,

    pub fn init(raw_query: []const u8) QueryIterator {
        return .{ .rest = raw_query };
    }

    pub fn next(it: *QueryIterator) ?RawPair {
        while (it.rest.len != 0) {
            const amp = std.mem.indexOfScalar(u8, it.rest, '&') orelse it.rest.len;
            const pair = it.rest[0..amp];
            it.rest = it.rest[@min(amp + 1, it.rest.len)..];
            if (pair.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, pair, '=');
            return .{
                .key = pair[0 .. eq orelse pair.len],
                .value = if (eq) |e| pair[e + 1 ..] else "",
            };
        }
        return null;
    }
};

/// Whether the encoded `raw_key` decodes to exactly `name`. Streams the
/// decode, so a key of any length compares without a buffer; a key with a
/// malformed escape never matches.
// secret-api-ok: `raw_key` is a URL query-parameter name, not a secret
pub fn keyEquals(raw_key: []const u8, name: []const u8) bool {
    var i: usize = 0;
    var n: usize = 0;
    while (i < raw_key.len) : (n += 1) {
        const b = nextByte(.query, raw_key, &i) catch return false;
        if (n == name.len or b != name[n]) return false;
    }
    return n == name.len;
}

/// The value of the first `name` parameter, still encoded, or null when
/// absent.
pub fn paramRaw(raw_query: []const u8, name: []const u8) ?[]const u8 {
    var it = QueryIterator.init(raw_query);
    while (it.next()) |p| if (keyEquals(p.key, name)) return p.value;
    return null;
}

/// The value of the first `name` parameter, decoded into `out`, or null when
/// absent.
pub fn param(raw_query: []const u8, name: []const u8, out: []u8) DecodeError!?[]const u8 {
    const raw = paramRaw(raw_query, name) orelse return null;
    return try decodeComponent(out, raw);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "decodePath: plain, escapes, and the refusals" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("/users/42", try decodePath(&buf, "/users/42"));
    try testing.expectEqualStrings("/a b/č", try decodePath(&buf, "/a%20b/%C4%8D"));
    try testing.expectEqualStrings("/a+b", try decodePath(&buf, "/a+b")); // `+` is literal in a path
    try testing.expectError(error.EncodedSeparator, decodePath(&buf, "/a%2Fb"));
    try testing.expectError(error.EncodedSeparator, decodePath(&buf, "/a%2fb"));
    try testing.expectError(error.EncodedSeparator, decodePath(&buf, "/a%00"));
    try testing.expectError(error.MalformedEscape, decodePath(&buf, "/a%zz"));
    try testing.expectError(error.MalformedEscape, decodePath(&buf, "/a%2"));
    try testing.expectError(error.MalformedEscape, decodePath(&buf, "/a%"));
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, decodePath(&small, "/abcd"));
    try testing.expectEqualStrings("/ab", try decodePath(&small, "/ab"));
    try testing.expectEqualStrings("é", try decodePath(&small, "%C3%A9")); // 6 in, 2 out
}

test "param: first match, decoded keys and values, absent and valueless" {
    var buf: [64]u8 = undefined;
    const q = "a=1&b=x+y%21&a=2&flag&user%5Fid=7&&e=";
    try testing.expectEqualStrings("1", (try param(q, "a", &buf)).?);
    try testing.expectEqualStrings("x y!", (try param(q, "b", &buf)).?);
    try testing.expectEqualStrings("", (try param(q, "flag", &buf)).?);
    try testing.expectEqualStrings("7", (try param(q, "user_id", &buf)).?);
    try testing.expectEqualStrings("", (try param(q, "e", &buf)).?);
    try testing.expectEqual(@as(?[]const u8, null), try param(q, "missing", &buf));
    try testing.expectEqual(@as(?[]const u8, null), try param("", "a", &buf));
    try testing.expectEqualStrings("x+y%21", paramRaw(q, "b").?);
    // A value may carry an encoded `/`: only a path refuses it.
    try testing.expectEqualStrings("a/b", (try param("p=a%2Fb", "p", &buf)).?);
    try testing.expectError(error.MalformedEscape, param("p=%G0", "p", &buf));
    // `+` in a key is a space too; a malformed key never matches.
    try testing.expectEqualStrings("1", (try param("first+name=1", "first name", &buf)).?);
    try testing.expectEqual(@as(?[]const u8, null), paramRaw("a%zz=1", "a%zz"));
}

test "keyEquals: prefixes, longer keys, and keys past any fixed buffer" {
    try testing.expect(!keyEquals("ab", "a"));
    try testing.expect(!keyEquals("a", "ab"));
    try testing.expect(keyEquals("", ""));
    var long_key: [600]u8 = undefined;
    @memset(&long_key, 'k');
    var enc: [602]u8 = undefined;
    @memcpy(enc[0..600], &long_key);
    @memcpy(enc[599..602], "%6B"); // the last `k`, encoded
    try testing.expect(keyEquals(&enc, &long_key));
}

test "QueryIterator: every pair in order, empty pairs skipped, nothing decoded" {
    var it = QueryIterator.init("a=1&&b&c=%20=x&");
    const p1 = it.next().?;
    try testing.expectEqualStrings("a", p1.key);
    try testing.expectEqualStrings("1", p1.value);
    const p2 = it.next().?;
    try testing.expectEqualStrings("b", p2.key);
    try testing.expectEqualStrings("", p2.value);
    const p3 = it.next().?;
    try testing.expectEqualStrings("c", p3.key);
    try testing.expectEqualStrings("%20=x", p3.value); // only the first `=` splits
    try testing.expectEqual(@as(?RawPair, null), it.next());
}
