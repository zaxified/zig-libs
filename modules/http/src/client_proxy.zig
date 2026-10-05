// SPDX-License-Identifier: MIT

//! Outbound proxy selection for `Client` (`Client.Options.proxy`): which
//! proxy, if any, a request URL goes through. The rules are Go's
//! `http.ProxyFromEnvironment` (its `httpproxy` package), and the oracle
//! holds this file to them (`go_oracle.zig`, area `proxy`):
//!
//!   * `http://` URLs use `http`, `https://` URLs use `https`; unset or ""
//!     means direct.
//!   * `localhost` and every loopback address always go direct.
//!   * `no_proxy` is a comma-separated list. `*` turns the proxy off. A
//!     CIDR (`10.0.0.0/8`) or an IP (`192.0.2.1`, `[2001:db8::1]:8080`)
//!     matches that address. A name matches itself and every subdomain
//!     (`example.com` matches `a.example.com`); a leading `.` or `*.`
//!     matches subdomains only. `:port` after an entry narrows it to that
//!     port.
//!   * Under CGI (`REQUEST_METHOD` set) `HTTP_PROXY` may have come from a
//!     request's `Proxy:` header ("httpoxy"), so an `http://` request with an
//!     `http` proxy configured is refused.
//!
//! Where it differs from Go, on purpose: a proxy setting that does not parse
//! is `error.BadProxy` (Go silently goes direct -- a request the operator
//! meant to route through a proxy must not leak past it), and only `http://`
//! proxies are supported (an `https://` or `socks5://` proxy is BadProxy).

const std = @import("std");
const netaddr = @import("netaddr");
const http = @import("root.zig");

pub const Proxy = struct {
    /// The proxy for `http://` requests: `[http://][user[:password]@]host[:port]`,
    /// port 80 when absent; a path is ignored. Borrowed: must outlive the
    /// `Client`. null or "" = direct.
    http: ?[]const u8 = null,
    /// The proxy for `https://` requests, same syntax; reached with
    /// `CONNECT`, the TLS session runs end to end through it.
    https: ?[]const u8 = null,
    /// Hosts that bypass the proxy (see the file doc). Borrowed.
    no_proxy: []const u8 = "",
    /// Refuse `http` for `http://` requests (see the file doc, "httpoxy").
    cgi: bool = false,

    pub const Error = error{BadProxy};

    /// The proxy settings a process was started with, as Go reads them:
    /// `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, each falling back to its
    /// lowercase name when unset or empty; `cgi` when `REQUEST_METHOD` is set.
    /// The values are borrowed from `env`, which must outlive the `Client`.
    pub fn fromEnviron(env: *const std.process.Environ.Map) Proxy {
        return .{
            .http = envAny(env, "HTTP_PROXY", "http_proxy"),
            .https = envAny(env, "HTTPS_PROXY", "https_proxy"),
            .no_proxy = envAny(env, "NO_PROXY", "no_proxy") orelse "",
            .cgi = if (env.get("REQUEST_METHOD")) |m| m.len != 0 else false,
        };
    }

    /// Where a request to `url` connects: a proxy, or null for direct.
    pub fn forUrl(p: Proxy, url: http.Url) Error!?Endpoint {
        const raw = switch (url.scheme) {
            .http => p.http,
            .https => p.https,
        } orelse return null;
        if (raw.len == 0) return null;
        const endpoint = try Endpoint.parse(raw);
        if (url.scheme == .http and p.cgi) return error.BadProxy;
        if (!useProxy(p.no_proxy, url.host, url.port)) return null;
        return endpoint;
    }
};

fn envAny(env: *const std.process.Environ.Map, upper: []const u8, lower: []const u8) ?[]const u8 {
    if (env.get(upper)) |v| if (v.len != 0) return v;
    if (env.get(lower)) |v| if (v.len != 0) return v;
    return null;
}

/// Decoded credentials never exceed this; longer ones are `BadProxy`.
const max_credentials = 512;

/// A proxy to connect to. Slices point into the configured proxy text.
pub const Endpoint = struct {
    host: []const u8,
    port: u16,
    /// `user[:password]`, still percent-encoded; null = no credentials.
    userinfo: ?[]const u8 = null,

    /// `[http://][userinfo@]host[:port][/...]`.
    pub fn parse(raw: []const u8) Proxy.Error!Endpoint {
        for (raw) |c| if (c <= ' ' or c >= 0x7f) return error.BadProxy;
        var rest = raw;
        if (std.mem.indexOf(u8, raw, "://")) |sep| {
            if (!std.ascii.eqlIgnoreCase(raw[0..sep], "http")) return error.BadProxy;
            rest = raw[sep + 3 ..];
        }
        const authority = rest[0 .. std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len];
        var ep: Endpoint = .{ .host = undefined, .port = 80 };
        var hostport = authority;
        if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
            ep.userinfo = authority[0..at];
            hostport = authority[at + 1 ..];
            var scratch: [max_credentials]u8 = undefined;
            _ = try decodeCredentials(ep.userinfo.?, &scratch);
        }
        if (hostport.len == 0) return error.BadProxy;
        if (hostport[0] == '[') {
            const close = std.mem.indexOfScalar(u8, hostport, ']') orelse return error.BadProxy;
            ep.host = hostport[1..close];
            if (netaddr.parseIp6(ep.host) == null) return error.BadProxy;
            const after = hostport[close + 1 ..];
            if (after.len != 0) {
                if (after[0] != ':') return error.BadProxy;
                if (after.len > 1) ep.port = parsePort(after[1..]) orelse return error.BadProxy;
            }
        } else if (std.mem.indexOfScalar(u8, hostport, ':')) |colon| {
            if (std.mem.indexOfScalarPos(u8, hostport, colon + 1, ':') != null) return error.BadProxy;
            ep.host = hostport[0..colon];
            if (colon + 1 < hostport.len) ep.port = parsePort(hostport[colon + 1 ..]) orelse return error.BadProxy;
        } else {
            ep.host = hostport;
        }
        if (ep.host.len == 0) return error.BadProxy;
        return ep;
    }

    /// The `Proxy-Authorization` field line, CRLF included, or nothing
    /// without credentials. Go's form: `Basic base64(user ":" password)`,
    /// both percent-decoded, the colon there even with no password.
    pub fn writeAuthorization(ep: Endpoint, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const userinfo = ep.userinfo orelse return;
        var plain: [max_credentials + 1]u8 = undefined;
        const decoded = decodeCredentials(userinfo, plain[0..max_credentials]) catch unreachable; // checked by `parse`
        var n = decoded.len;
        if (std.mem.indexOfScalar(u8, userinfo, ':') == null) {
            plain[n] = ':';
            n += 1;
        }
        var b64: [std.base64.standard.Encoder.calcSize(max_credentials + 1)]u8 = undefined;
        try w.print("Proxy-Authorization: Basic {s}\r\n", .{std.base64.standard.Encoder.encode(&b64, plain[0..n])});
    }
};

/// `user[:password]` percent-decoded into `out`. The first `:` is the
/// separator and is kept; an encoded `%3A` in the user name decodes to a
/// colon too, as in Go (the server cannot tell them apart either).
fn decodeCredentials(userinfo: []const u8, out: []u8) Proxy.Error![]const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < userinfo.len) : (o += 1) {
        if (o == out.len) return error.BadProxy;
        if (userinfo[i] == '%') {
            if (userinfo.len - i < 3) return error.BadProxy;
            const hi = std.fmt.charToDigit(userinfo[i + 1], 16) catch return error.BadProxy;
            const lo = std.fmt.charToDigit(userinfo[i + 2], 16) catch return error.BadProxy;
            out[o] = hi << 4 | lo;
            i += 3;
        } else {
            out[o] = userinfo[i];
            i += 1;
        }
    }
    return out[0..o];
}

fn parsePort(text: []const u8) ?u16 {
    return std.fmt.parseInt(u16, text, 10) catch null;
}

/// Go's `useProxy`: false when `host:port` goes direct.
fn useProxy(no_proxy: []const u8, host: []const u8, port: u16) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return false;
    const ip: ?netaddr.Ip = if (netaddr.parseIp(host)) |a| a.unmap() else null;
    if (ip) |a| if (a.isLoopback()) return false;

    var entries = std.mem.splitScalar(u8, no_proxy, ',');
    while (entries.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t\r\n\x0b\x0c");
        if (entry.len == 0) continue;
        if (std.mem.eql(u8, entry, "*")) return false;

        if (std.mem.indexOfScalar(u8, entry, '/') != null) {
            if (netaddr.parsePrefix(entry)) |prefix| {
                if (ip) |a| if (prefix.contains(a)) return false;
                continue;
            }
        }

        var phost = entry;
        var pport: ?u16 = null;
        if (netaddr.parseHostPort(entry)) |hp| {
            phost = hp.host;
            pport = hp.port;
        } else if (std.mem.endsWith(u8, entry, ":")) {
            // `name:` -- an empty port, which Go reads as "any port".
            phost = entry[0 .. entry.len - 1];
        }
        if (netaddr.parseIp(phost)) |entry_ip| {
            if (ip) |a| if (a.eql(entry_ip.unmap()) and (pport == null or pport.? == port)) return false;
            continue;
        }
        if (phost.len == 0) continue;

        // A name: `a.com` matches itself and its subdomains; `.a.com` and
        // `*.a.com` only the subdomains.
        if (std.mem.startsWith(u8, phost, "*.")) phost = phost[1..];
        const subdomains_only = phost[0] == '.';
        const bare = if (subdomains_only) phost[1..] else phost;
        const matched = (host.len > bare.len and
            std.ascii.endsWithIgnoreCase(host, bare) and host[host.len - bare.len - 1] == '.') or
            (!subdomains_only and std.ascii.eqlIgnoreCase(host, bare));
        if (matched and (pport == null or pport.? == port)) return false;
    }
    return true;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn parseUrl(text: []const u8) http.Url {
    return http.Url.parse(text) catch unreachable;
}

test "forUrl: scheme picks the proxy; unset or empty is direct" {
    const p: Proxy = .{ .http = "proxy:3128", .https = "http://sproxy:8443" };
    const a = (try p.forUrl(parseUrl("http://example.com/"))).?;
    try testing.expectEqualStrings("proxy", a.host);
    try testing.expectEqual(@as(u16, 3128), a.port);
    const b = (try p.forUrl(parseUrl("https://example.com/"))).?;
    try testing.expectEqualStrings("sproxy", b.host);
    try testing.expectEqual(@as(u16, 8443), b.port);
    try testing.expectEqual(@as(?Endpoint, null), try (Proxy{ .https = "x:1" }).forUrl(parseUrl("http://example.com/")));
    try testing.expectEqual(@as(?Endpoint, null), try (Proxy{ .http = "" }).forUrl(parseUrl("http://example.com/")));
}

test "forUrl: localhost and loopback always go direct" {
    const p: Proxy = .{ .http = "proxy:3128" };
    for ([_][]const u8{ "http://localhost/", "http://LOCALHOST:8080/", "http://127.0.0.1/", "http://127.9.9.9/", "http://[::1]/", "http://[::ffff:127.0.0.1]/" }) |u| {
        try testing.expectEqual(@as(?Endpoint, null), try p.forUrl(parseUrl(u)));
    }
    try testing.expect((try p.forUrl(parseUrl("http://128.0.0.1/"))) != null);
    try testing.expect((try p.forUrl(parseUrl("http://localhost.example/"))) != null);
}

test "forUrl: no_proxy names, subdomains, ports, IPs, CIDRs, star" {
    const direct = struct {
        fn check(no_proxy: []const u8, u: []const u8) !bool {
            const p: Proxy = .{ .http = "proxy:3128", .https = "proxy:3128", .no_proxy = no_proxy };
            return (try p.forUrl(parseUrl(u))) == null;
        }
    }.check;
    try testing.expect(try direct("example.com", "http://example.com/"));
    try testing.expect(try direct("example.com", "http://a.b.example.com/"));
    try testing.expect(!try direct("example.com", "http://notexample.com/"));
    try testing.expect(!try direct(".example.com", "http://example.com/"));
    try testing.expect(try direct(".example.com", "http://a.example.com/"));
    try testing.expect(try direct("*.example.com", "http://a.example.com/"));
    try testing.expect(!try direct("*.example.com", "http://example.com/"));
    try testing.expect(try direct("EXAMPLE.com", "http://Example.COM/"));
    try testing.expect(try direct("example.com:8080", "http://example.com:8080/"));
    try testing.expect(!try direct("example.com:8080", "http://example.com/"));
    try testing.expect(try direct("example.com:443", "https://example.com/"));
    try testing.expect(try direct(" a.org , example.com ", "http://example.com/"));
    try testing.expect(try direct("*", "http://anything/"));
    try testing.expect(try direct("192.0.2.1", "http://192.0.2.1/"));
    try testing.expect(!try direct("192.0.2.1", "http://192.0.2.2/"));
    try testing.expect(try direct("192.0.2.1:80", "http://192.0.2.1/"));
    try testing.expect(!try direct("192.0.2.1:81", "http://192.0.2.1/"));
    try testing.expect(try direct("192.0.2.0/24", "http://192.0.2.77/"));
    try testing.expect(!try direct("192.0.2.0/24", "http://192.0.3.1/"));
    try testing.expect(try direct("2001:db8::/32", "http://[2001:db8::5]/"));
    try testing.expect(try direct("[2001:db8::1]:80", "http://[2001:db8::1]/"));
    try testing.expect(try direct("2001:db8::1", "http://[2001:db8::1]/"));
    try testing.expect(try direct("192.0.2.1", "http://[::ffff:192.0.2.1]/"));
    try testing.expect(!try direct("", "http://example.com/"));
    try testing.expect(!try direct(",,", "http://example.com/"));
    try testing.expect(try direct("example.com:", "http://example.com:8080/")); // empty port = any
}

test "forUrl: httpoxy -- under CGI an http:// request refuses the http proxy" {
    const p: Proxy = .{ .http = "proxy:3128", .https = "proxy:3128", .cgi = true };
    try testing.expectError(error.BadProxy, p.forUrl(parseUrl("http://example.com/")));
    try testing.expect((try p.forUrl(parseUrl("https://example.com/"))) != null);
}

test "Endpoint.parse: forms, defaults, refusals" {
    const e = try Endpoint.parse("http://u%40x:p%3Ass@[2001:db8::1]:8080/ignored");
    try testing.expectEqualStrings("2001:db8::1", e.host);
    try testing.expectEqual(@as(u16, 8080), e.port);
    try testing.expectEqualStrings("u%40x:p%3Ass", e.userinfo.?);
    try testing.expectEqual(@as(u16, 80), (try Endpoint.parse("proxy")).port);
    try testing.expectEqual(@as(u16, 80), (try Endpoint.parse("HTTP://proxy:")).port);
    for ([_][]const u8{ "", "https://proxy:443", "socks5://proxy:1080", "http://", "http://u@", "proxy:99999", "proxy:x", "a b:1", "http://[::1", "http://[nope]:1", "u%zz@proxy", "a:1:2" }) |bad| {
        try testing.expectError(error.BadProxy, Endpoint.parse(bad));
    }
}

test "Endpoint.writeAuthorization: Basic over the decoded user and password" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (try Endpoint.parse("http://Aladdin:open%20sesame@p:1")).writeAuthorization(&w);
    // RFC 7617 §2's example credentials.
    try testing.expectEqualStrings("Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n", w.buffered());
    w = .fixed(&buf);
    try (try Endpoint.parse("user@p")).writeAuthorization(&w);
    try testing.expectEqualStrings("Proxy-Authorization: Basic dXNlcjo=\r\n", w.buffered()); // "user:"
    w = .fixed(&buf);
    try (try Endpoint.parse("p:1")).writeAuthorization(&w);
    try testing.expectEqualStrings("", w.buffered());
}

test "fromEnviron: uppercase first, lowercase when unset or empty, REQUEST_METHOD = cgi" {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("HTTP_PROXY", "");
    try env.put("http_proxy", "lower:1");
    try env.put("HTTPS_PROXY", "upper:2");
    try env.put("https_proxy", "lower:2");
    try env.put("no_proxy", "a.org");
    const p = Proxy.fromEnviron(&env);
    try testing.expectEqualStrings("lower:1", p.http.?);
    try testing.expectEqualStrings("upper:2", p.https.?);
    try testing.expectEqualStrings("a.org", p.no_proxy);
    try testing.expect(!p.cgi);
    try env.put("REQUEST_METHOD", "GET");
    try testing.expect(Proxy.fromEnviron(&env).cgi);
}
