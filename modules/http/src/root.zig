// SPDX-License-Identifier: MIT

//! http — HTTP/1.1 client + server, pure Zig (TLS via `std.crypto.tls`).
//!
//! Phase 1: `Client` — HTTP/1.1 over TCP and TLS, streaming bodies both
//! ways, chunked + Content-Length framing, RFC-conformant redirect
//! following. Phase 2 (this code): `Server` — request codec, response
//! writer and a thread-per-connection serving loop; Phase 2.1 hardened it
//! for **direct internet exposure** (peer address on requests, accept
//! hook + connection accounting, 431/414/413 size limits, stall +
//! whole-request + write timeouts — see `Server`); TLS termination is a
//! separate later task (a reverse proxy also works). Phase 2.2 adds
//! negotiated gzip response compression (`Server.Options.compression`,
//! off by default; `std.compress.flate` streaming into the chunked
//! framing). Phase 3 adds HTTP/2: `hpack` (RFC 7541) + `h2` (RFC 9113
//! framing/state machine/flow control), and Phase 3.1 wires them into
//! the server as opt-in cleartext h2c via prior knowledge
//! (`Server.Options.enable_h2c`, RFC 9113 §3.3) — the same handler
//! serves both protocols. Phase 3.2 adds the client side and makes the
//! h2 stack bidirectional: `h2_client.Session` multiplexes requests
//! over one connection, and `Client.connectH2c` binds it to a TCP
//! stream (h2c prior knowledge). Phase 3.3 closes the loop with the
//! **TLS-adapter seam**: bring your own TLS (a reverse proxy, an
//! external Zig TLS library, a future std TLS server) and run the h2
//! stack over the established stream — `alpn_offer`/`protocolFromAlpn`
//! consume the ALPN result (RFC 7301; over TLS h2 is selected only via
//! ALPN, RFC 9113 §3.3), then `h2_server.serveStream` serves it and
//! `Client.connectH2Over` drives the client side; `Server.serveStream`
//! is the matching h1-over-provided-stream path.
//! Deliberately NOT built on `std.http` (API
//! churn is the reason this module exists); client TLS is strictly
//! `std.crypto.tls`.
//!
//! Layout: this file owns the shared vocabulary (methods, URL parsing,
//! redirect rules); `h1.zig` is the pure HTTP/1.1 wire codec (offline
//! testable, shared by both sides); `Client.zig` / `Server.zig` are the
//! transports.

const std = @import("std");
const netaddr = @import("netaddr");

pub const meta = .{
    .status = .extract, // client shape seeded in axp-core/src/httpclient.zig
    .platform = .any,
    .role = .both, // Client + Server submodules
    // One thread owns a Client (and its responses) or drives a Server;
    // the Server runs its own connection threads internally — handlers
    // must be thread-safe if they share state.
    .concurrency = .single_owner,
    .model_after = "lalinsky/dusty (1.1 client shape) + Go net/http (redirect semantics, Server shape, gzip handler); nghttp2 later for h2",
    .deps = .{ "netaddr", "std.crypto.tls", "std.Io.net", "std.compress.flate" },
};

/// Pure HTTP/1.1 wire framing (request/response head parse, chunked codec,
/// Content-Length reader) — shared by the client and the server.
pub const h1 = @import("h1.zig");

/// HPACK header compression for HTTP/2 (RFC 7541): `hpack.Encoder` /
/// `hpack.Decoder`. Pure codec, verified against the RFC Appendix C
/// vectors; the HTTP/2 framing layer (Phase 3) will build on it.
pub const hpack = @import("hpack.zig");

/// HTTP/2 framing + connection/stream state machine (RFC 9113): the §4/§6
/// frame codec, §5 stream lifecycle, §5.2 flow control and the
/// HEADERS+CONTINUATION assembler over `hpack` — see `h2.Connection`.
/// Pure wire layer; the server integrates it as opt-in cleartext h2c
/// (`Server.Options.enable_h2c`, prior knowledge per RFC 9113 §3.3).
pub const h2 = @import("h2.zig");

/// HTTP/2 client engine (Phase 3.2): `h2_client.Session` drives
/// `h2.Connection` in client role over any byte transport, multiplexing
/// requests (demux by stream id) with §5.2/§6.9 flow control and typed
/// GOAWAY/RST_STREAM handling. `Client.connectH2c` binds it to a TCP
/// stream for cleartext h2c via prior knowledge (RFC 9113 §3.3);
/// `Client.connectH2Over` binds it to a caller-provided (e.g. TLS)
/// stream after ALPN selected `alpn_h2`.
pub const h2_client = @import("h2_client.zig");

/// HTTP/2 server integration: the h2c serve loop behind
/// `Server.Options.enable_h2c`, and `h2_server.serveStream` — the
/// BYO-TLS entry point that serves HTTP/2 on one already-established
/// (e.g. TLS) connection when ALPN selected `alpn_h2`.
pub const h2_server = @import("h2_server.zig");

/// The HTTP/1.1 client (plus opt-in HTTP/2 h2c via `Client.connectH2c`).
/// See `Client.init` / `Client.request`.
pub const Client = @import("Client.zig");

/// The HTTP/1.1 server: `Server.Request`, `Server.ResponseWriter`, the
/// socket-free `Server.serveStream` codec loop, and the TCP serving loop.
pub const Server = @import("Server.zig");

/// Conditional requests (RFC 9110 §8.8/§13): ETag / Last-Modified validators
/// with `If-Match` / `If-None-Match` / `If-Modified-Since` /
/// `If-Unmodified-Since` → 304 Not Modified / 412 Precondition Failed.
pub const conditional = @import("conditional.zig");

/// Request-body helpers: the `Content-Type` media-type + parameter parser and
/// an `application/x-www-form-urlencoded` decoder. The `multipart/form-data`
/// parser lives in `multipart`.
pub const body = @import("body.zig");

/// `multipart/form-data` body parser (RFC 7578): iterate a form's parts —
/// field `name`, optional `filename`, `Content-Type`, and raw (binary-safe)
/// value — from a size-bounded in-memory body.
pub const multipart = @import("multipart.zig");

/// Server-Sent Events (`text/event-stream`) encoder over a streaming
/// `ResponseWriter` — the push half of a live HTTP endpoint (SSE / MCP).
pub const sse = @import("sse.zig");

/// Range requests (RFC 7233): the `Range` request-header parser (R1) —
/// `bytes=` byte-range-set into validated `ByteRangeSpec`s (range/from/suffix).
pub const range = @import("range.zig");

/// Proactive content negotiation (RFC 9110 §12): the `Accept` media-range +
/// q-value parser (N1) — media-ranges with integer milli-unit weights.
pub const conneg = @import("conneg.zig");

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

// ── ALPN (RFC 7301) — the bring-your-own-TLS seam ───────────────────────────
//
// This module ships no TLS server: TLS termination is the caller's (a
// reverse proxy in front of the h1/h2c `Server`, an external Zig TLS
// library, a future std TLS server). ALPN itself is negotiated inside the
// caller's TLS handshake (RFC 7301) — the vocabulary below is for *feeding*
// that handshake (`alpn_offer`) and *consuming* its result
// (`protocolFromAlpn`). Over TLS, HTTP/2 is selected exclusively via the
// ALPN id "h2" (RFC 9113 §3.3 — there is no request-based upgrade), so the
// intended deployment flow is:
//
//     terminate TLS with your library, offering `http.alpn_offer`
//     switch (http.protocolFromAlpn(negotiated)) {
//         .h2     => h2_server.serveStream(gpa, in, out, peer, .{ .handler = h });
//         .http11 => Server.serveStream(opts, in, out, bufs);   // or unknown:
//         .unknown => Server.serveStream(opts, in, out, bufs),  // h1 default
//     }
//
// where `in`/`out` are the TLS connection's plaintext reader/writer. The
// client side mirrors it: offer `alpn_offer`, and when "h2" comes back call
// `Client.connectH2Over` on the TLS stream (RFC 7301 §3.2: an empty or
// absent ALPN result means the server chose nothing — HTTP/1.1 is the safe
// default, hence `.unknown` maps to the h1 path above).

/// ALPN protocol id selecting HTTP/2 over TLS (RFC 9113 §3.3).
pub const alpn_h2 = "h2";

/// ALPN protocol id selecting HTTP/1.1 (RFC 7301 §6 IANA registry).
pub const alpn_http11 = "http/1.1";

/// The protocol list to offer in a TLS handshake, most-preferred first
/// (RFC 7301 §3.1): clients send it in the ClientHello, servers use it as
/// their preference order when picking against the client's list.
pub const alpn_offer = [_][]const u8{ alpn_h2, alpn_http11 };

/// Dispatch verdict for a negotiated ALPN protocol id — see `protocolFromAlpn`.
pub const AlpnProtocol = enum { http11, h2, unknown };

/// Map the ALPN protocol id the caller's TLS layer negotiated to the module
/// entry point to use: `.h2` → `h2_server.serveStream` /
/// `Client.connectH2Over`, `.http11` → `Server.serveStream` / the h1
/// `Client`. `.unknown` (anything else, including "" when ALPN was not
/// used) should be treated as HTTP/1.1 per RFC 7301 §3.2 fallback custom.
/// Comparison is exact and case-sensitive — ALPN ids are opaque bytes.
pub fn protocolFromAlpn(selected: []const u8) AlpnProtocol {
    if (std.mem.eql(u8, selected, alpn_h2)) return .h2;
    if (std.mem.eql(u8, selected, alpn_http11)) return .http11;
    return .unknown;
}

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
    _ = hpack;
    _ = h2;
    _ = h2_client;
    _ = h2_server;
    _ = Client;
    _ = Server;
    _ = conditional;
    _ = body;
    _ = multipart;
    _ = sse;
    _ = range;
    _ = conneg;
}

test "protocolFromAlpn: exact ALPN ids dispatch, anything else is unknown" {
    try testing.expectEqual(AlpnProtocol.h2, protocolFromAlpn("h2"));
    try testing.expectEqual(AlpnProtocol.http11, protocolFromAlpn("http/1.1"));
    // Not negotiated / ALPN absent → the caller falls back to HTTP/1.1.
    try testing.expectEqual(AlpnProtocol.unknown, protocolFromAlpn(""));
    // Unsupported protocols we never offer.
    try testing.expectEqual(AlpnProtocol.unknown, protocolFromAlpn("h3"));
    try testing.expectEqual(AlpnProtocol.unknown, protocolFromAlpn("http/1.0"));
    // ALPN ids are opaque bytes — no case folding, no prefix matching.
    try testing.expectEqual(AlpnProtocol.unknown, protocolFromAlpn("H2"));
    try testing.expectEqual(AlpnProtocol.unknown, protocolFromAlpn("h2c"));
}

test "alpn_offer: h2 preferred, http/1.1 fallback, nothing else" {
    try testing.expectEqual(@as(usize, 2), alpn_offer.len);
    try testing.expectEqualStrings(alpn_h2, alpn_offer[0]);
    try testing.expectEqualStrings(alpn_http11, alpn_offer[1]);
    // Every offered id round-trips through the dispatcher.
    try testing.expectEqual(AlpnProtocol.h2, protocolFromAlpn(alpn_offer[0]));
    try testing.expectEqual(AlpnProtocol.http11, protocolFromAlpn(alpn_offer[1]));
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
