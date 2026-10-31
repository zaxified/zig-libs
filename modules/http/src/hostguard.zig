// SPDX-License-Identifier: MIT

//! A `Host` header allowlist — the DNS-rebinding guard (Django
//! `ALLOWED_HOSTS`). A local admin UI on 127.0.0.1 can be driven by any web
//! page that points a name of its own at 127.0.0.1: to the browser the
//! requests are same-origin, so `CrossOriginProtection` lets them through;
//! only `Host` still carries the attacker's name. A request whose host is
//! not allowed is answered 421 (Misdirected Request) and never handled.
//!
//! Matching: the port and one trailing dot are dropped, names compare
//! case-insensitively. An entry with a leading dot (`.example.org`) matches
//! that name and every subdomain of it, as in Django. IP literals
//! (`192.0.2.7`, `[::1]`) and `localhost` pass by default: nothing can
//! rebind an address, and a browser resolves `localhost` itself. A `Host`
//! that is missing or not host[:port] fails.
//!
//! On HTTP/2 the server builds `Host` from `:authority`, so the same check
//! covers both.

const std = @import("std");
const netaddr = @import("netaddr");
const Server = @import("Server.zig");

pub const HostGuard = struct {
    /// Allowed names, without port; `.example.org` also allows subdomains.
    allowed: []const []const u8 = &.{},
    /// IPv4 and bracketed IPv6 literals pass.
    allow_ip_literals: bool = true,
    /// `localhost` passes.
    allow_localhost: bool = true,

    /// Whether `req` may be handled: its `Host` header is allowed.
    pub fn check(g: *const HostGuard, req: *const Server.Request) bool {
        return g.allows(req.header("host") orelse return false);
    }

    /// Whether a `Host` header value is allowed.
    pub fn allows(g: *const HostGuard, host: []const u8) bool {
        const h = splitHost(host) orelse return false;
        if (h.literal) return g.allow_ip_literals;
        if (g.allow_localhost and std.ascii.eqlIgnoreCase(h.name, "localhost")) return true;
        for (g.allowed) |a| {
            if (a.len > 1 and a[0] == '.') {
                const base = a[1..];
                if (std.ascii.eqlIgnoreCase(h.name, base)) return true;
                if (h.name.len > a.len and std.ascii.endsWithIgnoreCase(h.name, a)) return true;
            } else if (std.ascii.eqlIgnoreCase(h.name, a)) return true;
        }
        return false;
    }

    /// The 421 a refused request gets.
    pub fn deny(rw: *Server.ResponseWriter) (Server.ResponseWriter.SetHeaderError || std.Io.Writer.Error)!void {
        try rw.writeError(421, "misdirected request: unknown host name");
    }
};

const Host = struct { name: []const u8, literal: bool };

/// `host[:port]` → the name without port or trailing dot; null when the
/// value is not of that shape.
fn splitHost(value: []const u8) ?Host {
    var v = value;
    if (v.len == 0) return null;
    if (v[0] == '[') {
        const close = std.mem.findScalar(u8, v, ']') orelse return null;
        if (!portOk(v[close + 1 ..])) return null;
        const inner = v[1..close];
        const ip = netaddr.parseIp(inner) orelse return null;
        if (ip != .v6) return null;
        return .{ .name = inner, .literal = true };
    }
    if (std.mem.findScalar(u8, v, ':')) |c| {
        if (!portOk(v[c..])) return null;
        v = v[0..c];
    }
    if (v.len != 0 and v[v.len - 1] == '.') v = v[0 .. v.len - 1];
    if (v.len == 0) return null;
    if (netaddr.parseIp(v)) |ip| {
        if (ip == .v4) return .{ .name = v, .literal = true };
    }
    return .{ .name = v, .literal = false };
}

/// Empty, or `:` and 1–5 digits.
fn portOk(rest: []const u8) bool {
    if (rest.len == 0) return true;
    if (rest[0] != ':' or rest.len < 2 or rest.len > 6) return false;
    for (rest[1..]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

const testing = std.testing;

test "HostGuard: literals, localhost and listed names pass; rebinding names fail" {
    const g: HostGuard = .{ .allowed = &.{"ping.example.org"} };
    for ([_][]const u8{ "127.0.0.1", "127.0.0.1:8080", "[::1]", "[::1]:8080", "192.0.2.7", "localhost:8080", "LOCALHOST.", "ping.example.org", "Ping.Example.Org:443", "ping.example.org." }) |h| {
        testing.expect(g.allows(h)) catch |e| {
            std.debug.print("refused {s}\n", .{h});
            return e;
        };
    }
    for ([_][]const u8{ "", ":80", ".", "evil.example", "evil.example:8080", "localhost.evil.example", "127.0.0.1.evil.example", "ping.example.org.evil.example", "xping.example.org", "[::1", "[127.0.0.1]", "::1", "a:b:c", "ping.example.org:", "ping.example.org:http", "ping.example.org:1234567" }) |h| {
        testing.expect(!g.allows(h)) catch |e| {
            std.debug.print("allowed {s}\n", .{h});
            return e;
        };
    }
}

test "HostGuard: a leading-dot entry allows the name and its subdomains only; switches turn literals and localhost off" {
    const sub: HostGuard = .{ .allowed = &.{".example.org"} };
    try testing.expect(sub.allows("example.org"));
    try testing.expect(sub.allows("a.b.example.org:443"));
    try testing.expect(!sub.allows("badexample.org"));
    try testing.expect(!sub.allows("example.org.evil"));

    const strict: HostGuard = .{ .allowed = &.{"app.test"}, .allow_ip_literals = false, .allow_localhost = false };
    try testing.expect(strict.allows("app.test"));
    try testing.expect(!strict.allows("127.0.0.1"));
    try testing.expect(!strict.allows("[::1]:80"));
    try testing.expect(!strict.allows("localhost"));
    // A one-character `.` entry is not "every name".
    const dot: HostGuard = .{ .allowed = &.{"."}, .allow_localhost = false };
    try testing.expect(!dot.allows("anything.example"));
}
