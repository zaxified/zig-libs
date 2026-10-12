// SPDX-License-Identifier: MIT

//! Cross-origin request forgery protection without tokens — Go 1.25's
//! `http.CrossOriginProtection`. A browser marks every request it makes with
//! `Sec-Fetch-Site` (Fetch Metadata) and, on a non-GET from older browsers,
//! `Origin`; a state-changing request that came from another site is refused.
//!
//! The decision, in Go's order: a safe method (GET, HEAD, OPTIONS) passes;
//! `Sec-Fetch-Site: same-origin` or `none` passes, any other value is
//! cross-origin; without it, no `Origin` passes (not a browser) and an
//! `Origin` whose host equals the request's `Host` passes. A request that
//! would be refused still passes when its `Origin` is a trusted origin or the
//! bypass predicate accepts it (Go's `AddInsecureBypassPattern`, which takes
//! `ServeMux` patterns; routing lives in the sibling `router` module, so here
//! it is a predicate over the request).
//!
//! Held to Go 1.26 by `go_oracle.zig` (area crossorigin): `check`'s verdict,
//! the trusted-origin validation and the default denial response.

const std = @import("std");
const Server = @import("Server.zig");

pub const CrossOriginProtection = struct {
    /// Origins (`scheme://host[:port]`, exactly as a browser sends them)
    /// allowed to make cross-origin requests. Validate each with
    /// `validateOrigin` (Go's `AddTrustedOrigin` refuses what it refuses);
    /// `init` does it for the whole list.
    trusted_origins: []const []const u8 = &.{},
    /// Requests this returns true for are never refused — Go's
    /// `AddInsecureBypassPattern` (for example a webhook path that other
    /// sites post to on purpose). Null = none.
    bypass: ?*const fn (ctx: ?*anyopaque, req: *const Server.Request) bool = null,
    bypass_ctx: ?*anyopaque = null,

    pub const CheckError = error{
        /// `Sec-Fetch-Site` said the request came from another origin.
        CrossOriginRequest,
        /// No `Sec-Fetch-Site`, and `Origin` names another host.
        CrossOriginRequestFromOldBrowser,
    };

    /// `.{ .trusted_origins = origins, … }` after `validateOrigin` on each.
    pub fn init(c: CrossOriginProtection) error{InvalidOrigin}!CrossOriginProtection {
        for (c.trusted_origins) |o| try validateOrigin(o);
        return c;
    }

    /// Go's `Check`: null when `req` may proceed.
    pub fn check(c: *const CrossOriginProtection, req: *const Server.Request) CheckError!void {
        switch (req.method) {
            .get, .head, .options => return,
            else => {},
        }
        if (req.header("sec-fetch-site")) |site| {
            if (std.mem.eql(u8, site, "same-origin") or std.mem.eql(u8, site, "none")) return;
            if (site.len != 0) {
                if (c.exempt(req)) return;
                return error.CrossOriginRequest;
            }
        }
        const origin = req.header("origin") orelse return;
        if (origin.len == 0) return;
        var buf: [max_host]u8 = undefined;
        if (originHost(origin, &buf)) |h| {
            if (std.mem.eql(u8, h, req.header("host") orelse "")) return;
        }
        if (c.exempt(req)) return;
        return error.CrossOriginRequestFromOldBrowser;
    }

    fn exempt(c: *const CrossOriginProtection, req: *const Server.Request) bool {
        if (c.bypass) |f| if (f(c.bypass_ctx, req)) return true;
        const origin = req.header("origin") orelse return false;
        for (c.trusted_origins) |t| if (std.mem.eql(u8, t, origin)) return true;
        return false;
    }

    /// Go's default denial: 403 with the reason as plain text (`http.Error`).
    pub fn deny(rw: *Server.ResponseWriter, err: CheckError) (Server.ResponseWriter.SetHeaderError || std.Io.Writer.Error)!void {
        try rw.writeError(403, message(err));
    }

    /// The reason text Go's errors carry.
    pub fn message(err: CheckError) []const u8 {
        return switch (err) {
            error.CrossOriginRequest => "cross-origin request detected from Sec-Fetch-Site header",
            error.CrossOriginRequestFromOldBrowser => "cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host",
        };
    }
};

/// Go's `AddTrustedOrigin` validation: a URL with a scheme and a host, and
/// no path, query or fragment (user info passes, as in Go; a browser never
/// sends it, so such an entry simply never matches).
pub fn validateOrigin(origin: []const u8) error{InvalidOrigin}!void {
    const p = parseOrigin(origin) orelse return error.InvalidOrigin;
    if (p.scheme.len == 0 or p.host.len == 0) return error.InvalidOrigin;
    if (p.path.len != 0 or p.query.len != 0 or p.fragment.len != 0) return error.InvalidOrigin;
    var buf: [max_host]u8 = undefined;
    _ = decodeHost(p.host, &buf) orelse return error.InvalidOrigin;
}

const max_host = 256;

/// The host (and port) an `Origin` value names, as Go's `url.Parse(origin).Host`
/// gives it — percent-escapes decoded — or null when Go's parse fails or
/// finds no host.
fn originHost(origin: []const u8, buf: *[max_host]u8) ?[]const u8 {
    const p = parseOrigin(origin) orelse return null;
    if (p.host.len == 0) return null;
    return decodeHost(p.host, buf);
}

const Parsed = struct {
    scheme: []const u8,
    /// The raw authority minus user info; "" when there is none.
    host: []const u8,
    path: []const u8,
    query: []const u8,
    fragment: []const u8,
};

/// RFC 3986's split as Go's `url.Parse` makes it: fragment, scheme, query,
/// then the authority after `//`. Null where Go reports a parse error that
/// this split can see (a control byte, an empty scheme before `:`).
fn parseOrigin(s: []const u8) ?Parsed {
    for (s) |b| if (b < 0x20 or b == 0x7f) return null;
    var rest = s;
    var fragment: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '#')) |i| {
        fragment = rest[i + 1 ..];
        rest = rest[0..i];
    }
    var scheme: []const u8 = "";
    if (rest.len != 0 and std.ascii.isAlphabetic(rest[0])) {
        for (rest, 0..) |b, i| {
            if (b == ':') {
                scheme = rest[0..i];
                rest = rest[i + 1 ..];
                break;
            }
            if (!std.ascii.isAlphanumeric(b) and b != '+' and b != '-' and b != '.') break;
        }
    } else if (rest.len != 0 and rest[0] == ':') return null; // missing protocol scheme
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |i| {
        query = rest[i + 1 ..];
        rest = rest[0..i];
    }
    var host: []const u8 = "";
    if ((scheme.len != 0 or !std.mem.startsWith(u8, rest, "///")) and std.mem.startsWith(u8, rest, "//")) {
        const auth_end = std.mem.indexOfScalarPos(u8, rest, 2, '/') orelse rest.len;
        var auth = rest[2..auth_end];
        rest = rest[auth_end..];
        if (std.mem.lastIndexOfScalar(u8, auth, '@')) |at| auth = auth[at + 1 ..];
        host = auth;
    } else if (scheme.len == 0) {
        // A relative reference whose first segment holds a colon is an
        // error in Go ("first path segment in URL cannot contain colon").
        const seg_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        if (std.mem.indexOfScalar(u8, rest[0..seg_end], ':') != null) return null;
    }
    return .{
        .scheme = scheme,
        .host = host,
        .path = rest,
        .query = query,
        .fragment = fragment,
    };
}

/// Go's host check: a bracketed IP literal, or a name whose port (after the
/// last colon) is digits only; percent-escapes (non-ASCII only) decoded;
/// bytes Go escapes in a host refused. Null when Go refuses the host.
fn decodeHost(host: []const u8, buf: *[max_host]u8) ?[]const u8 {
    if (host.len > max_host) return null;
    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return null;
        if (!validPort(host[close + 1 ..])) return null;
    } else if (std.mem.lastIndexOfScalar(u8, host, ':')) |colon| {
        if (!validPort(host[colon..])) return null;
    }
    var n: usize = 0;
    var i: usize = 0;
    while (i < host.len) : (i += 1) {
        var b = host[i];
        if (b == '%') {
            if (i + 2 >= host.len) return null;
            const hi = std.fmt.charToDigit(host[i + 1], 16) catch return null;
            const lo = std.fmt.charToDigit(host[i + 2], 16) catch return null;
            b = hi << 4 | lo;
            // RFC 3986 §3.2.2 as Go reads it: an escape in a host is for a
            // non-ASCII byte only.
            if (b < 0x80) return null;
            i += 2;
        } else if (b < 0x80 and !hostByte(b)) return null;
        buf[n] = b;
        n += 1;
    }
    return buf[0..n];
}

/// `:` followed by digits only, or empty (Go's `validOptionalPort`).
fn validPort(p: []const u8) bool {
    if (p.len == 0) return true;
    if (p[0] != ':') return false;
    for (p[1..]) |b| if (!std.ascii.isDigit(b)) return false;
    return true;
}

/// The ASCII bytes Go leaves unescaped in a host.
fn hostByte(b: u8) bool {
    if (std.ascii.isAlphanumeric(b)) return true;
    return std.mem.indexOfScalar(u8, "-_.~!$&'()*+,;=:[]<>\"", b) != null;
}

const testing = std.testing;

fn runCheck(c: *const CrossOriginProtection, wire: []const u8) !?CrossOriginProtection.CheckError {
    const Ctx = struct {
        var prot: *const CrossOriginProtection = undefined;
        var verdict: ?CrossOriginProtection.CheckError = null;
        fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
            _ = rw;
            verdict = null;
            prot.check(req) catch |err| {
                verdict = err;
            };
        }
    };
    Ctx.prot = c;
    var in: std.Io.Reader = .fixed(wire);
    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var head: [2048]u8 = undefined;
    var req_body: [64]u8 = undefined;
    var resp_body: [256]u8 = undefined;
    var chunk: [64]u8 = undefined;
    Server.serveStream(.{ .handler = Ctx.handler, .server_name = null }, &in, &out, .{
        .head = &head,
        .request_body = &req_body,
        .response_body = &resp_body,
        .chunk = &chunk,
    });
    return Ctx.verdict;
}

test "check: safe methods, Sec-Fetch-Site, Origin against Host, trusted origins, bypass" {
    const Bypass = struct {
        fn f(_: ?*anyopaque, req: *const Server.Request) bool {
            return std.mem.startsWith(u8, req.path, "/hook/");
        }
    };
    const c = try CrossOriginProtection.init(.{ .trusted_origins = &.{"https://partner.example"}, .bypass = Bypass.f });
    const E = CrossOriginProtection.CheckError;
    const cases = [_]struct { []const u8, ?E }{
        .{ "GET / HTTP/1.1\r\nHost: a\r\nSec-Fetch-Site: cross-site\r\n\r\n", null },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nSec-Fetch-Site: same-origin\r\nContent-Length: 0\r\n\r\n", null },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nSec-Fetch-Site: none\r\nContent-Length: 0\r\n\r\n", null },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nSec-Fetch-Site: same-site\r\nContent-Length: 0\r\n\r\n", error.CrossOriginRequest },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nSec-Fetch-Site: cross-site\r\nOrigin: https://partner.example\r\nContent-Length: 0\r\n\r\n", null },
        .{ "POST /hook/x HTTP/1.1\r\nHost: a\r\nSec-Fetch-Site: cross-site\r\nContent-Length: 0\r\n\r\n", null },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", null },
        .{ "POST / HTTP/1.1\r\nHost: a:8080\r\nOrigin: https://a:8080\r\nContent-Length: 0\r\n\r\n", null },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nOrigin: https://b\r\nContent-Length: 0\r\n\r\n", error.CrossOriginRequestFromOldBrowser },
        .{ "POST / HTTP/1.1\r\nHost: a\r\nOrigin: null\r\nContent-Length: 0\r\n\r\n", error.CrossOriginRequestFromOldBrowser },
    };
    for (cases) |tc| try testing.expectEqual(tc[1], try runCheck(&c, tc[0]));
}

test "validateOrigin: scheme and host only" {
    try validateOrigin("https://example.com");
    try validateOrigin("http://example.com:8080");
    for ([_][]const u8{ "example.com", "https://", "https://example.com/", "https://example.com?x", "https://example.com#f", "https://example.com:x", "null", "https://ex%41mple.com" }) |bad|
        try testing.expectError(error.InvalidOrigin, validateOrigin(bad));
    try testing.expectError(error.InvalidOrigin, CrossOriginProtection.init(.{ .trusted_origins = &.{ "https://ok.example", "bad" } }));
}
