//! http — HTTP/1.1 client over TCP + TLS (`std.crypto.tls`), pure Zig.
//!
//! Phase 1 (this code): `Client` — HTTP/1.1 over TCP and TLS, streaming
//! bodies both ways, chunked + Content-Length framing, RFC-conformant
//! redirect following. Phase 2 will add the `Server` codec; Phase 3 HTTP/2
//! (framing + HPACK, h2spec-verified). Deliberately NOT built on
//! `std.http.Client` (API churn is the reason this module exists); TLS is
//! strictly `std.crypto.tls`.
//!
//! Layout: this file owns the shared vocabulary (methods, URL parsing,
//! redirect rules); `h1.zig` is the pure HTTP/1.1 wire codec (offline
//! testable, reused by the future server); `Client.zig` is the transport.

const std = @import("std");
const netaddr = @import("netaddr");

pub const meta = .{
    .status = .extract, // client shape seeded in axp-core/src/httpclient.zig
    .platform = .any,
    .role = .client, // becomes .both when the Phase 2 server codec lands
    .concurrency = .single_owner, // one thread owns a Client and its responses
    .model_after = "lalinsky/dusty (1.1 client shape) + Go net/http (redirect semantics); nghttp2 later for h2",
    .deps = .{ "netaddr", "std.crypto.tls", "std.Io.net" },
};

/// Pure HTTP/1.1 wire framing (head parse, chunked codec) — shared with the
/// future Phase 2 server codec.
pub const h1 = @import("h1.zig");

/// The HTTP/1.1 client. See `Client.init` / `Client.request`.
pub const Client = @import("Client.zig");

// ── request vocabulary ──────────────────────────────────────────────────────

pub const Method = enum {
    get,
    head,
    post,
    put,
    delete,
    patch,
    options,

    /// The on-wire token, e.g. `.get` → "GET".
    pub fn token(m: Method) []const u8 {
        return switch (m) {
            .get => "GET",
            .head => "HEAD",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
            .patch => "PATCH",
            .options => "OPTIONS",
        };
    }
};

pub const Header = struct { name: []const u8, value: []const u8 };

// ── URL parsing ─────────────────────────────────────────────────────────────

/// A parsed `http(s)` URL. All slices point into the parsed text.
pub const Url = struct {
    scheme: Scheme,
    /// Hostname or IP literal; IPv6 brackets already stripped.
    host: []const u8,
    /// Explicit port, or the scheme default.
    port: u16,
    /// Path component, always at least "/". Percent-encoding is passed
    /// through untouched.
    path: []const u8,
    /// Query without the leading '?', or "".
    query: []const u8,

    pub const Scheme = enum {
        http,
        https,

        pub fn defaultPort(s: Scheme) u16 {
            return switch (s) {
                .http => 80,
                .https => 443,
            };
        }
    };

    pub const ParseError = error{ UnsupportedScheme, BadUrl };

    /// Parse `http[s]://host[:port][/path][?query][#fragment]`. The fragment
    /// is discarded; userinfo (`user@host`) is rejected.
    pub fn parse(text: []const u8) ParseError!Url {
        var scheme: Scheme = undefined;
        var rest: []const u8 = undefined;
        if (std.ascii.startsWithIgnoreCase(text, "http://")) {
            scheme = .http;
            rest = text["http://".len..];
        } else if (std.ascii.startsWithIgnoreCase(text, "https://")) {
            scheme = .https;
            rest = text["https://".len..];
        } else return error.UnsupportedScheme;

        const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
        const authority = rest[0..authority_end];
        if (authority.len == 0) return error.BadUrl;
        if (std.mem.indexOfScalar(u8, authority, '@') != null) return error.BadUrl; // userinfo unsupported

        var host: []const u8 = undefined;
        var port: ?u16 = null;
        if (authority[0] == '[') {
            const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.BadUrl;
            host = authority[1..close];
            if (netaddr.parseIp6(host) == null) return error.BadUrl;
            if (close + 1 < authority.len) {
                if (authority[close + 1] != ':') return error.BadUrl;
                port = parsePort(authority[close + 2 ..]) orelse return error.BadUrl;
            }
        } else if (std.mem.indexOfScalar(u8, authority, ':') != null) {
            const hp = netaddr.parseHostPort(authority) orelse return error.BadUrl;
            host = hp.host;
            port = hp.port;
        } else {
            host = authority;
        }
        if (host.len == 0) return error.BadUrl;

        var target = rest[authority_end..];
        if (std.mem.indexOfScalar(u8, target, '#')) |i| target = target[0..i];
        var path: []const u8 = target;
        var query: []const u8 = "";
        if (std.mem.indexOfScalar(u8, target, '?')) |i| {
            path = target[0..i];
            query = target[i + 1 ..];
        }
        if (path.len == 0) path = "/";

        return .{
            .scheme = scheme,
            .host = host,
            .port = port orelse scheme.defaultPort(),
            .path = path,
            .query = query,
        };
    }

    pub fn portIsDefault(u: Url) bool {
        return u.port == u.scheme.defaultPort();
    }

    /// True when `host` is an IPv6 literal (needs brackets on the wire).
    pub fn hostIsV6(u: Url) bool {
        return netaddr.parseIp6(u.host) != null;
    }

    /// Write the wire form of the authority for a Host header:
    /// `host` / `[v6]` plus `:port` when non-default.
    pub fn writeHostHeaderValue(u: Url, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (u.hostIsV6()) {
            try w.print("[{s}]", .{u.host});
        } else {
            try w.writeAll(u.host);
        }
        if (!u.portIsDefault()) try w.print(":{d}", .{u.port});
    }
};

fn parsePort(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > 5) return null;
    var v: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return if (v <= std.math.maxInt(u16)) @intCast(v) else null;
}

// ── redirect rules (Go net/http semantics) ──────────────────────────────────

/// Which method a redirect should be retried with, or null when `status` is
/// not an auto-followed redirect. Mirrors Go's `redirectBehavior`: 301/302/303
/// rewrite everything except GET/HEAD to GET (dropping the body); 307/308
/// preserve method and body.
pub fn redirectMethodFor(status: u16, method: Method) ?Method {
    return switch (status) {
        301, 302, 303 => if (method == .get or method == .head) method else .get,
        307, 308 => method,
        else => null,
    };
}

pub const ResolveError = error{ BadRedirect, RedirectTooLong };

/// Resolve a Location header value against the request URL (RFC 3986 §5.2),
/// producing an absolute http(s) URL in `out`. Handles absolute URLs,
/// scheme-relative (`//host/…`), absolute-path and relative-path references
/// (with dot-segment removal).
pub fn resolveLocation(base: Url, location: []const u8, out: []u8) ResolveError![]const u8 {
    if (location.len == 0) return error.BadRedirect;
    if (std.ascii.startsWithIgnoreCase(location, "http://") or
        std.ascii.startsWithIgnoreCase(location, "https://"))
    {
        if (location.len > out.len) return error.RedirectTooLong;
        @memcpy(out[0..location.len], location);
        return out[0..location.len];
    }

    var w: std.Io.Writer = .fixed(out);
    if (std.mem.startsWith(u8, location, "//")) {
        w.print("{t}:{s}", .{ base.scheme, location }) catch return error.RedirectTooLong;
        return w.buffered();
    }

    w.print("{t}://", .{base.scheme}) catch return error.RedirectTooLong;
    base.writeHostHeaderValue(&w) catch return error.RedirectTooLong;

    if (std.mem.startsWith(u8, location, "/")) {
        w.writeAll(location) catch return error.RedirectTooLong;
        return w.buffered();
    }

    // Relative path: merge with the base path's directory, then clean.
    const loc_path_end = std.mem.indexOfAny(u8, location, "?#") orelse location.len;
    const dir_len = if (std.mem.lastIndexOfScalar(u8, base.path, '/')) |i| i + 1 else 0;
    var merged: [max_merged_path]u8 = undefined;
    const total = dir_len + loc_path_end;
    if (total > merged.len) return error.RedirectTooLong;
    @memcpy(merged[0..dir_len], base.path[0..dir_len]);
    @memcpy(merged[dir_len..][0..loc_path_end], location[0..loc_path_end]);
    const cleaned = merged[0..removeDotSegments(merged[0..total])];
    w.writeAll(cleaned) catch return error.RedirectTooLong;
    w.writeAll(location[loc_path_end..]) catch return error.RedirectTooLong;
    return w.buffered();
}

/// Scratch bound for relative-redirect path merging.
pub const max_merged_path = 4096;

/// RFC 3986 §5.2.4 remove_dot_segments, in place; returns the new length.
pub fn removeDotSegments(path: []u8) usize {
    var r: usize = 0;
    var w: usize = 0;
    while (r < path.len) {
        const rest = path[r..];
        if (std.mem.startsWith(u8, rest, "../")) {
            r += 3;
        } else if (std.mem.startsWith(u8, rest, "./")) {
            r += 2;
        } else if (std.mem.eql(u8, rest, ".")) {
            r += 1;
        } else if (std.mem.startsWith(u8, rest, "/./")) {
            r += 2; // keep the leading '/'
        } else if (std.mem.eql(u8, rest, "/.")) {
            path[w] = '/';
            w += 1;
            break;
        } else if (std.mem.startsWith(u8, rest, "/../") or std.mem.eql(u8, rest, "/..")) {
            while (w > 0) {
                w -= 1;
                if (path[w] == '/') break;
            }
            if (std.mem.eql(u8, rest, "/..")) {
                path[w] = '/';
                w += 1;
                break;
            }
            r += 3;
        } else if (std.mem.eql(u8, rest, "..")) {
            r += 2;
        } else {
            const start = r;
            var e = if (path[r] == '/') r + 1 else r;
            while (e < path.len and path[e] != '/') e += 1;
            std.mem.copyForwards(u8, path[w..], path[start..e]);
            w += e - start;
            r = e;
        }
    }
    return w;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = h1;
    _ = Client;
}

test "Url.parse: happy paths" {
    const a = try Url.parse("http://example.com/x/y?q=1#frag");
    try testing.expectEqual(Url.Scheme.http, a.scheme);
    try testing.expectEqualStrings("example.com", a.host);
    try testing.expectEqual(@as(u16, 80), a.port);
    try testing.expectEqualStrings("/x/y", a.path);
    try testing.expectEqualStrings("q=1", a.query);

    const b = try Url.parse("HTTPS://Example.com:8443");
    try testing.expectEqual(Url.Scheme.https, b.scheme);
    try testing.expectEqual(@as(u16, 8443), b.port);
    try testing.expectEqualStrings("/", b.path);
    try testing.expectEqualStrings("", b.query);

    const c = try Url.parse("https://example.com?x=1"); // query, no path
    try testing.expectEqualStrings("/", c.path);
    try testing.expectEqualStrings("x=1", c.query);

    const v6 = try Url.parse("http://[2001:db8::1]:8080/api");
    try testing.expectEqualStrings("2001:db8::1", v6.host);
    try testing.expectEqual(@as(u16, 8080), v6.port);
    try testing.expect(v6.hostIsV6());

    const v6np = try Url.parse("https://[::1]/");
    try testing.expectEqual(@as(u16, 443), v6np.port);

    const v4 = try Url.parse("http://127.0.0.1:9070/v1/data");
    try testing.expectEqualStrings("127.0.0.1", v4.host);
    try testing.expect(!v4.hostIsV6());
}

test "Url.parse: rejects malformed input" {
    try testing.expectError(error.UnsupportedScheme, Url.parse("ftp://x/"));
    try testing.expectError(error.UnsupportedScheme, Url.parse("example.com/x"));
    try testing.expectError(error.BadUrl, Url.parse("http:///x"));
    try testing.expectError(error.BadUrl, Url.parse("http://user@host/"));
    try testing.expectError(error.BadUrl, Url.parse("http://host:99999/"));
    try testing.expectError(error.BadUrl, Url.parse("http://host:/"));
    try testing.expectError(error.BadUrl, Url.parse("http://[not-v6]/"));
    try testing.expectError(error.BadUrl, Url.parse("http://[::1]8080/"));
    try testing.expectError(error.BadUrl, Url.parse("http://2001:db8::1/")); // v6 needs brackets
}

test "Url host header form" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (try Url.parse("https://example.com/")).writeHostHeaderValue(&w);
    try testing.expectEqualStrings("example.com", w.buffered());

    w = .fixed(&buf);
    try (try Url.parse("http://example.com:8080/")).writeHostHeaderValue(&w);
    try testing.expectEqualStrings("example.com:8080", w.buffered());

    w = .fixed(&buf);
    try (try Url.parse("http://[::1]:81/")).writeHostHeaderValue(&w);
    try testing.expectEqualStrings("[::1]:81", w.buffered());

    w = .fixed(&buf);
    try (try Url.parse("http://[::1]/")).writeHostHeaderValue(&w);
    try testing.expectEqualStrings("[::1]", w.buffered());
}

test "redirectMethodFor mirrors Go" {
    try testing.expectEqual(@as(?Method, .get), redirectMethodFor(301, .post));
    try testing.expectEqual(@as(?Method, .get), redirectMethodFor(302, .put));
    try testing.expectEqual(@as(?Method, .get), redirectMethodFor(303, .post));
    try testing.expectEqual(@as(?Method, .get), redirectMethodFor(301, .get));
    try testing.expectEqual(@as(?Method, .head), redirectMethodFor(302, .head));
    try testing.expectEqual(@as(?Method, .post), redirectMethodFor(307, .post));
    try testing.expectEqual(@as(?Method, .delete), redirectMethodFor(308, .delete));
    try testing.expectEqual(@as(?Method, null), redirectMethodFor(200, .get));
    try testing.expectEqual(@as(?Method, null), redirectMethodFor(304, .get));
    try testing.expectEqual(@as(?Method, null), redirectMethodFor(300, .get));
    try testing.expectEqual(@as(?Method, null), redirectMethodFor(404, .get));
}

fn expectResolved(base_url: []const u8, location: []const u8, expected: []const u8) !void {
    const base = try Url.parse(base_url);
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(expected, try resolveLocation(base, location, &buf));
}

test "resolveLocation" {
    // Absolute — taken verbatim (scheme change allowed, e.g. http→https).
    try expectResolved("http://a.example/x", "https://b.example/y", "https://b.example/y");
    // Scheme-relative.
    try expectResolved("https://a.example/x", "//b.example/z?k=1", "https://b.example/z?k=1");
    // Absolute path keeps host and non-default port.
    try expectResolved("http://a.example:8080/x/y", "/new", "http://a.example:8080/new");
    // Relative path merges with the base directory.
    try expectResolved("http://a.example/dir/page", "other", "http://a.example/dir/other");
    try expectResolved("http://a.example/dir/page", "sub/other", "http://a.example/dir/sub/other");
    // Dot segments per RFC 3986.
    try expectResolved("http://a.example/a/b/c", "./../g", "http://a.example/a/g");
    try expectResolved("http://a.example/a/b/c", "../../../g", "http://a.example/g");
    // Query carried through on relative locations.
    try expectResolved("http://a.example/p/q", "r?s=1", "http://a.example/p/r?s=1");
    // IPv6 host round-trips with brackets.
    try expectResolved("http://[2001:db8::1]:81/x/y", "/z", "http://[2001:db8::1]:81/z");

    // Errors.
    const base = try Url.parse("http://a.example/");
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.RedirectTooLong, resolveLocation(base, "http://very-long-host.example/path", &tiny));
    var buf: [512]u8 = undefined;
    try testing.expectError(error.BadRedirect, resolveLocation(base, "", &buf));
}

test "removeDotSegments" {
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "/a/b/c/./../../g", .out = "/a/g" },
        .{ .in = "/../x", .out = "/x" },
        .{ .in = "/a/../../", .out = "/" },
        .{ .in = "/a/b/..", .out = "/a/" },
        .{ .in = "/a/b/.", .out = "/a/b/" },
        .{ .in = "/a/./b", .out = "/a/b" },
        .{ .in = "/", .out = "/" },
        .{ .in = "/..", .out = "/" },
        .{ .in = "mid/content=5/../6", .out = "mid/6" },
    };
    for (cases) |case| {
        var buf: [64]u8 = undefined;
        @memcpy(buf[0..case.in.len], case.in);
        try testing.expectEqualStrings(case.out, buf[0..removeDotSegments(buf[0..case.in.len])]);
    }
}
