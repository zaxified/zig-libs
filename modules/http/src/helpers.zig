// SPDX-License-Identifier: MIT

//! The pure halves of the handler helpers Go users reach for — `http.Redirect`'s
//! location rewriting, `Request.BasicAuth` and `SetBasicAuth`. The response-side
//! halves are `Server.ResponseWriter.redirect` / `writeError` / `notFound`,
//! which call into here. Every behaviour below is held to Go 1.26's answers on
//! this module's own case tables (`go_oracle.zig`, area helpers); where it is
//! stricter, the oracle's divergence table says so and why.

const std = @import("std");

pub const LocationError = error{
    /// The rewritten location does not fit `out`.
    LocationTooLong,
    /// The location resolves to a path starting `/\`, which browsers read as
    /// `//` — another host. Go writes it as is; refused here (open redirect).
    InvalidLocation,
};

/// `http.Redirect`'s rewrite of `location` for a request whose path is
/// `req_path`. `buf` is the working storage (`redirect_buf_len` bytes); the
/// result's `header` is the `Location` value, `href` the pre-escape form the
/// HTML body links to (Go percent-encodes non-ASCII in the header only).
///
/// A location Go's `url.Parse` reads as absolute (a scheme, or `//` and a
/// host) or cannot parse at all passes unchanged. Anything else is a path,
/// possibly relative: it is joined to the directory of `req_path`, cleaned as
/// Go's `path.Clean` does (a trailing `/` kept), and its query and fragment
/// carried over. Non-ASCII bytes are then percent-encoded with lowercase hex,
/// existing escapes untouched.
pub fn redirectLocation(req_path: []const u8, location: []const u8, buf: *[redirect_buf_len]u8) LocationError!struct { header: []const u8, href: []const u8 } {
    const lower = buf[0..max_location];
    const upper = buf[max_location..];
    const resolved = if (isRelativePath(location))
        try resolvePath(req_path, location, lower, upper)
    else
        location;
    if (std.mem.startsWith(u8, resolved, "/\\")) return error.InvalidLocation;
    // `resolved` is the caller's string or lives in `lower`; the escaped form
    // goes to `upper`, which the join no longer needs.
    var w: usize = 0;
    for (resolved) |c| {
        if (c < 0x80) {
            if (w == upper.len) return error.LocationTooLong;
            upper[w] = c;
            w += 1;
        } else {
            if (w + 3 > upper.len) return error.LocationTooLong;
            upper[w] = '%';
            upper[w + 1] = hex_lower[c >> 4];
            upper[w + 2] = hex_lower[c & 0xf];
            w += 3;
        }
    }
    return .{ .header = upper[0..w], .href = resolved };
}

/// Longest location `redirectLocation` handles, joined or escaped; the
/// response's header storage caps it lower in practice.
pub const max_location = 2048;
pub const redirect_buf_len = 2 * max_location;

const hex_lower = "0123456789abcdef";

/// Whether Go's `url.Parse` gives `s` no scheme and no host and no error —
/// the case `http.Redirect` rewrites.
fn isRelativePath(s: []const u8) bool {
    for (s) |c| if (c < 0x20 or c == 0x7f) return false; // "invalid control character"
    // A scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":" (RFC 3986 §3.1).
    for (s, 0..) |c, i| {
        if (c == ':') {
            if (i == 0) return false; // "missing protocol scheme"
            if (std.ascii.isAlphabetic(s[0])) return false; // scheme → absolute
            break;
        }
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.')) break;
    }
    // `//host`: an authority (Go: not for `///`, and an empty host is no host).
    if (std.mem.startsWith(u8, s, "//") and !std.mem.startsWith(u8, s, "///") and s.len > 2) {
        const host_end = std.mem.indexOfAny(u8, s[2..], "/?#") orelse s.len - 2;
        if (host_end != 0) return false;
    }
    const path_end = std.mem.indexOfAny(u8, s, "?#") orelse s.len;
    // "first path segment in URL cannot contain colon".
    if (s.len == 0 or s[0] != '/') {
        const seg_end = std.mem.indexOfScalar(u8, s[0..path_end], '/') orelse path_end;
        if (std.mem.indexOfScalar(u8, s[0..seg_end], ':') != null) return false;
    }
    // Invalid percent-escapes in the path or the fragment fail the parse.
    if (!validEscapes(s[0..path_end])) return false;
    if (std.mem.indexOfScalar(u8, s, '#')) |h| if (!validEscapes(s[h + 1 ..])) return false;
    return true;
}

fn validEscapes(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] != '%') continue;
        if (i + 2 >= s.len or !std.ascii.isHex(s[i + 1]) or !std.ascii.isHex(s[i + 2])) return false;
        i += 2;
    }
    return true;
}

/// Join a relative `location` to `req_path`'s directory in `scratch`, then
/// clean the path part into `out` as Go's `path.Clean`, keeping a trailing
/// slash and the `?` tail (Go splits on the first `?` only; a `#` before it
/// stays in the path).
fn resolvePath(req_path: []const u8, location: []const u8, out: []u8, scratch: []u8) LocationError![]const u8 {
    var n: usize = 0;
    if (location.len == 0 or location[0] != '/') {
        const old = if (req_path.len == 0) "/" else req_path;
        // `*` (OPTIONS) has no directory; Go's path.Split gives "" there.
        const dir = if (std.mem.lastIndexOfScalar(u8, old, '/')) |i| old[0 .. i + 1] else "";
        if (dir.len > scratch.len) return error.LocationTooLong;
        @memcpy(scratch[0..dir.len], dir);
        n = dir.len;
    }
    // One byte of room for `cleanPath`'s "." and the kept trailing slash.
    if (n + location.len + 1 > scratch.len) return error.LocationTooLong;
    @memcpy(scratch[n..][0..location.len], location);
    n += location.len;

    const q = std.mem.indexOfScalar(u8, scratch[0..n], '?') orelse n;
    const path = scratch[0..q];
    const tail = scratch[q..n];
    const trailing = path.len > 0 and path[path.len - 1] == '/';
    var clean = cleanPath(path, out);
    if (trailing and clean[clean.len - 1] != '/') {
        out[clean.len] = '/';
        clean = out[0 .. clean.len + 1];
    }
    // clean ≤ path.len + 1 and out.len == scratch.len ≥ n + 1, so it fits.
    @memcpy(out[clean.len..][0..tail.len], tail);
    return out[0 .. clean.len + tail.len];
}

/// Go's `path.Clean` (Pike, "Lexical File Names in Plan 9"): collapse
/// repeated slashes, drop `.` elements, drop each inner `..` with the element
/// before it, drop `..` at the start of a rooted path; `.` for an empty
/// result. `out` must hold `in.len + 1` bytes.
pub fn cleanPath(in: []const u8, out: []u8) []u8 {
    if (in.len == 0) {
        out[0] = '.';
        return out[0..1];
    }
    const rooted = in[0] == '/';
    var w: usize = 0;
    var r: usize = 0;
    var dotdot: usize = 0; // `..` may not back up past here
    if (rooted) {
        out[0] = '/';
        w = 1;
        r = 1;
        dotdot = 1;
    }
    while (r < in.len) {
        if (in[r] == '/') {
            r += 1;
        } else if (in[r] == '.' and (r + 1 == in.len or in[r + 1] == '/')) {
            r += 1;
        } else if (in[r] == '.' and r + 1 < in.len and in[r + 1] == '.' and (r + 2 == in.len or in[r + 2] == '/')) {
            r += 2;
            if (w > dotdot) {
                w -= 1;
                while (w > dotdot and out[w] != '/') w -= 1;
            } else if (!rooted) {
                if (w > 0) {
                    out[w] = '/';
                    w += 1;
                }
                out[w] = '.';
                out[w + 1] = '.';
                w += 2;
                dotdot = w;
            }
        } else {
            if ((rooted and w != 1) or (!rooted and w != 0)) {
                out[w] = '/';
                w += 1;
            }
            while (r < in.len and in[r] != '/') : (r += 1) {
                out[w] = in[r];
                w += 1;
            }
        }
    }
    if (w == 0) {
        out[0] = '.';
        return out[0..1];
    }
    return out[0..w];
}

/// Write `s` HTML-escaped as Go's `htmlEscape` in `http.Redirect` does:
/// `&` `<` `>` `"` `'` → `&amp;` `&lt;` `&gt;` `&#34;` `&#39;`.
pub fn writeHtmlEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const rep: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&#34;",
            '\'' => "&#39;",
            else => continue,
        };
        try w.writeAll(s[start..i]);
        try w.writeAll(rep);
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

pub const BasicCredentials = struct { user: []const u8, password: []const u8 };

/// HTTP Basic credentials (RFC 7617) out of an `Authorization` value, as Go's
/// `Request.BasicAuth`: the scheme `Basic` in any case, exactly one space,
/// standard base64 with its padding, split at the first `:`. `out` receives
/// the decoded `user:password` (`value.len` bytes always suffice). Null for
/// anything else, including a decoded form with no `:`. The bytes are not
/// checked for UTF-8, as Go does not.
pub fn basicAuth(value: []const u8, out: []u8) ?BasicCredentials {
    const prefix = "Basic ";
    if (value.len < prefix.len or !std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix)) return null;
    const enc = value[prefix.len..];
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(enc) catch return null;
    if (n > out.len) return null;
    dec.decode(out[0..n], enc) catch return null;
    const colon = std.mem.indexOfScalar(u8, out[0..n], ':') orelse return null;
    return .{ .user = out[0..colon], .password = out[colon + 1 .. n] };
}

/// The `Authorization` value for HTTP Basic credentials (Go's
/// `Request.SetBasicAuth`): `Basic base64(user ":" password)`. `user` must
/// not contain `:` (RFC 7617 §2) — `error.InvalidUser`, since the server
/// would split there.
// secret-api-ok: the password is the caller's slice and leaves in `out` as the header's base64 by design; the plain copy staged in `out` is overwritten by that encoding, and no intermediate is held on the stack
pub fn basicAuthHeader(out: []u8, user: []const u8, password: []const u8) error{ NoSpaceLeft, InvalidUser }![]const u8 {
    if (std.mem.indexOfScalar(u8, user, ':') != null) return error.InvalidUser;
    const plain_len = user.len + 1 + password.len;
    const enc = std.base64.standard.Encoder;
    const total = "Basic ".len + enc.calcSize(plain_len);
    if (total > out.len) return error.NoSpaceLeft;
    @memcpy(out[0.."Basic ".len], "Basic ");
    // Encode the three pieces as one stream: join them in the tail of `out`
    // first (base64 output is longer than its input, so it never overtakes it).
    const tail = out[total - plain_len .. total];
    @memcpy(tail[0..user.len], user);
    tail[user.len] = ':';
    @memcpy(tail[user.len + 1 ..], password);
    _ = enc.encode(out["Basic ".len..total], tail);
    return out[0..total];
}

const testing = std.testing;

test "cleanPath: Go's path.Clean on the documented rules" {
    const cases = [_][2][]const u8{
        .{ "", "." },              .{ "/", "/" },                 .{ "//", "/" },          .{ "/a//b", "/a/b" },
        .{ "/a/./b", "/a/b" },     .{ "/a/../b", "/b" },          .{ "/../a", "/a" },      .{ "/a/b/..", "/a" },
        .{ "a/../..", ".." },      .{ "../a", "../a" },           .{ "a/./", "a" },        .{ ".", "." },
        .{ "/a/b/../../..", "/" }, .{ "a/b/../../../c", "../c" }, .{ "/.../x", "/.../x" }, .{ "/a/..b", "/a/..b" },
    };
    for (cases) |c| {
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings(c[1], cleanPath(c[0], &buf));
    }
}

test "basicAuthHeader round-trips through basicAuth; a colon in the user is refused" {
    var hdr: [64]u8 = undefined;
    const v = try basicAuthHeader(&hdr, "Aladdin", "open sesame");
    try testing.expectEqualStrings("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", v); // RFC 7617 §2
    var out: [64]u8 = undefined;
    const c = basicAuth(v, &out).?;
    try testing.expectEqualStrings("Aladdin", c.user);
    try testing.expectEqualStrings("open sesame", c.password);
    try testing.expectError(error.InvalidUser, basicAuthHeader(&hdr, "a:b", "p"));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, basicAuthHeader(&tiny, "user", "pass"));
    // A short `out` is "no credentials", never a partial decode.
    try testing.expectEqual(@as(?BasicCredentials, null), basicAuth(v, out[0..4]));
}

test "redirectLocation: the open-redirect `/\\` form is refused, a long location reports so" {
    var buf: [redirect_buf_len]u8 = undefined;
    try testing.expectError(error.InvalidLocation, redirectLocation("/a", "/\\evil.example", &buf));
    try testing.expectError(error.InvalidLocation, redirectLocation("/a", "\\evil.example", &buf));
    try testing.expectError(error.LocationTooLong, redirectLocation("/a", "/" ++ "x" ** max_location, &buf));
    // Non-ASCII triples in the header: a location that fits joined but not escaped.
    try testing.expectError(error.LocationTooLong, redirectLocation("/a", "/" ++ "\xc4" ** (max_location / 2), &buf));
    // `*` has no directory: the location is cleaned as a relative path.
    const star = try redirectLocation("*", "x/../y", &buf);
    try testing.expectEqualStrings("y", star.header);
}

// ── fuzz: basicAuth and redirectLocation ─────────────────────────────────

const fz = @import("fuzz_test.zig");
const seed = @import("testkit").fuzz.seed;

const helper_seeds = [_][]const u8{
    seed("Basic dXNlcjpwYXNz"), // user:pass
    seed("basic dTpwOnE="), // scheme case, a colon in the password
    seed("Basic dXNlcg=="), // no colon: refused
    seed("Basic dXNlcjpwYXN"), // missing padding: refused
    seed("/a/b\x00c"), // redirect: a path joined and cleaned
    seed("../../x?y=../z#f"), // relative with query and fragment
    seed("https://example.com/\xc4\x8d"), // absolute, non-ASCII escaped
    seed("/\\evil.example"), // the refused open-redirect form
};

const HelperMark = fz.Marker(enum { auth_ok, auth_refused, redirect_ok, redirect_refused });

test "fuzz: basicAuth and redirectLocation never panic, and keep their output invariants" {
    try testing.fuzz({}, fuzzHelpersSmith, .{ .corpus = &helper_seeds });
}

test "fuzz driver: HTTP_FUZZ (helpers)" {
    try fz.fuzz_driver.run(fuzzHelpers, .{ .prefix = "HTTP_FUZZ", .name = "http-helpers" });
}

test "fuzz harness: helpers, 300 seeds, reaches every outcome" {
    try HelperMark.reach(fuzzHelpers, "http-helpers", 300);
}

fn fuzzHelpersSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzHelpers, smith, script[0..n]);
}

fn fuzzHelpers(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &helper_seeds);
    const in = buf[0..len];

    var out: [256]u8 = undefined;
    if (basicAuth(in, &out)) |c| {
        HelperMark.mark(.auth_ok);
        // Both halves are the decoded bytes around the first colon.
        try testing.expect(c.user.len + 1 + c.password.len <= out.len);
        try testing.expect(std.mem.indexOfScalar(u8, c.user, ':') == null);
        // What a client builds from them is accepted back as the same pair.
        var hdr: [512]u8 = undefined;
        const v = try basicAuthHeader(&hdr, c.user, c.password);
        var out2: [256]u8 = undefined;
        const back = basicAuth(v, &out2).?;
        try testing.expectEqualStrings(c.user, back.user);
        try testing.expectEqualStrings(c.password, back.password);
    } else HelperMark.mark(.auth_refused);

    var rbuf: [redirect_buf_len]u8 = undefined;
    const req_path = if (len > 0 and in[0] == '/') in[0 .. len / 2] else "/a/b";
    if (redirectLocation(req_path, in, &rbuf)) |loc| {
        HelperMark.mark(.redirect_ok);
        for (loc.header) |c| try testing.expect(c < 0x80);
        try testing.expect(!std.mem.startsWith(u8, loc.href, "/\\"));
        // A rewritten path is clean: no `.`/`..` segment and no `//` before the query.
        if (loc.href.len > 0 and loc.href[0] == '/' and !std.mem.startsWith(u8, loc.href, "//") and
            isRelativePath(in))
        {
            const p = loc.href[0 .. std.mem.indexOfScalar(u8, loc.href, '?') orelse loc.href.len];
            try testing.expect(std.mem.indexOf(u8, p, "//") == null);
            try testing.expect(std.mem.indexOf(u8, p, "/./") == null and std.mem.indexOf(u8, p, "/../") == null);
        }
    } else |_| HelperMark.mark(.redirect_refused);
}
