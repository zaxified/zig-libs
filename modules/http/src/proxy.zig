// SPDX-License-Identifier: MIT

//! proxy — an HTTP/1.1 reverse-proxy handler: the forwarding half of an API
//! gateway. It composes the pieces this module already ships — the `Server`
//! request codec + `ResponseWriter` on the front side, the streaming
//! `Client` on the back side — into a `Server.Handler` that receives a
//! request, forwards it to a backend, and streams the response back.
//!
//! What it does per request (Go `httputil.ReverseProxy` / nginx
//! `proxy_pass` shape):
//! - **Backend selection** through the `Selector` seam (or a fixed
//!   `backend`). The seam is a plain `ctx + fn` so an upstream pool (the
//!   `upstream` module's load-balanced, health-checked `Pool`) or a route
//!   match (the `router` module) plugs in from *above* — see "Layering".
//! - **Hop-by-hop header stripping** (RFC 9110 §7.6.1): `Connection`,
//!   `Keep-Alive`, `TE`, `Trailer`/`Trailers`, `Transfer-Encoding`,
//!   `Upgrade`, every `Proxy-*`, and every field named in the request's
//!   `Connection` token list — dropped in both directions so per-hop
//!   framing never leaks end-to-end.
//! - **Forwarding headers:** appends the socket peer to `X-Forwarded-For`
//!   (RFC 7239 de-facto), sets `X-Forwarded-Proto` / `X-Forwarded-Host`,
//!   and injects `Via: 1.1 <pseudonym>` (RFC 9110 §7.6.3) on request and
//!   response, appending to any existing `Via`.
//! - **Host rewrite:** the forwarded `Host` becomes the backend authority
//!   (default; `rewrite_host = false` preserves the client's Host — nginx
//!   `proxy_set_header Host $http_host`).
//! - **Streaming both ways, no full buffering:** the request body streams
//!   client → backend through `Client.requestStreaming` (Content-Length or
//!   chunked, matching the inbound framing); the response body streams
//!   backend → client through the `ResponseWriter` (which re-frames it —
//!   exact Content-Length when the backend declared one, else chunked).
//! - **Error mapping:** an unreachable/refused/reset backend → `502 Bad
//!   Gateway`, a backend timeout → `504 Gateway Timeout`, no selectable
//!   backend → `503 Service Unavailable`. Once response bytes are already on
//!   the wire a mid-stream backend failure can only close the connection
//!   (nothing else is truthful).
//!
//! ## Layering — why the seam, not a hard `upstream`/`router` import
//!
//! `http` is the foundational module; `router` and `upstream` sit *on top of
//! it* (`router` imports `http`; `upstream` imports `resilience`/`probe`).
//! For this handler to import them back would be a dependency cycle
//! (`router`) or would drag the whole resilience/probe stack into every
//! `http` consumer (`upstream`). So the composition is inverted: the proxy
//! exposes a `Selector` seam and those modules drive it. Wiring an
//! `upstream.Pool` is a three-line adapter (pick → forward → report) the
//! caller writes; a `router` route simply calls this handler. `resilience`
//! composes the same way — wrap the caller's forward-through-the-pool
//! operation in `resilience.run` / `Pool.call` above this handler.
//!
//! ## Known gaps (this pass)
//!
//! - **HTTP/1.1 backends only.** The forward path uses the h1 `Client`;
//!   h2/h2c upstreaming is not wired here.
//! - **No response buffer pool** — the `ResponseWriter`'s per-connection
//!   buffer is reused across keep-alive requests but not shared across
//!   connections.
//!
//! Backend connection pooling is **not** a gap: `Client` keeps a keyed idle
//! `Pool` (on by default, `Client.Options.pool`) and every backend
//! connection this handler opens through `Client.request`/
//! `Client.requestStreaming` is checked out of and returned to that pool
//! transparently — nothing here has to ask for it. Set
//! `.pool.enabled = false` on the `Client` passed into `Config` to fall
//! back to one-connection-per-forwarded-request (e.g. for a backend that
//! cannot be trusted to frame keep-alive correctly).
//!
//! ## Thread-safety
//!
//! One `ProxyHandler` (and its `*Client`) is shared by all of the server's
//! connection threads — safe: `forward` owns no mutable shared state, and
//! `Client`'s pool is internally synchronized (see `Client`'s module doc).
//! As always with a shared `Client`, the allocator must be thread-safe (the
//! server already requires that for its per-connection slabs).

const std = @import("std");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const Server = @import("Server.zig");
const Client = @import("Client.zig");
const netaddr = @import("netaddr");

/// One backend origin to forward to.
pub const Backend = struct {
    scheme: http.Url.Scheme = .http,
    /// Hostname or IP literal (IPv6 without brackets — added on the wire).
    host: []const u8,
    port: u16,
};

/// Backend-selection seam. Return null to refuse the request with the
/// configured no-backend status (503) — e.g. an `upstream.Pool` whose
/// `pick()` found nothing healthy. `ctx` is your pool/router state.
pub const Selector = struct {
    ctx: ?*anyopaque = null,
    selectFn: *const fn (ctx: ?*anyopaque, req: *Server.Request) ?Backend,

    pub fn select(s: Selector, req: *Server.Request) ?Backend {
        return s.selectFn(s.ctx, req);
    }
};

pub const Config = struct {
    /// The back-side client. Shared across connection threads; give it a
    /// thread-safe allocator (the server already needs one).
    client: *Client,
    /// Fixed single backend — the simplest deployment. Ignored when
    /// `selector` is set. Exactly one of `backend`/`selector` must be set.
    backend: ?Backend = null,
    /// Dynamic backend selection (an `upstream.Pool`, a `router` match, …).
    selector: ?Selector = null,
    /// Token placed in the injected `Via` header (`Via: 1.1 <pseudonym>`).
    via_pseudonym: []const u8 = "zig-libs",
    /// Value for the injected `X-Forwarded-Proto` — the scheme the *client*
    /// reached this proxy on. Default "http" (this module terminates plain
    /// HTTP; set "https" when a TLS terminator sits in front of it).
    forwarded_proto: []const u8 = "http",
    /// Rewrite the forwarded `Host` to the backend authority (default). When
    /// false the client's original `Host` is forwarded unchanged.
    rewrite_host: bool = true,
};

/// The proxy handler. Construct one, then point a `Server` at it:
///
/// ```zig
/// var ph = proxy.ProxyHandler.init(.{ .client = &client,
///     .backend = .{ .host = "10.0.0.1", .port = 8080 } });
/// var server = http.Server.init(io, gpa, .{
///     .handler = proxy.ProxyHandler.handler,
///     .context = &ph,
/// });
/// ```
pub const ProxyHandler = struct {
    config: Config,

    pub fn init(config: Config) ProxyHandler {
        std.debug.assert((config.backend != null) != (config.selector != null));
        return .{ .config = config };
    }

    /// `Server.Handler` entry point — recovers the `*ProxyHandler` from
    /// `Request.context` (set `Server.Options.context` to `&handler`).
    pub fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const self: *ProxyHandler = @ptrCast(@alignCast(req.context.?));
        return self.forward(req, rw);
    }

    /// Forward `req` to the selected backend and stream the response into
    /// `rw`. Callable directly (e.g. from a `router` route handler that
    /// already resolved `req.context` itself).
    pub fn forward(self: *ProxyHandler, req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const backend = self.pickBackend(req) orelse
            return gatewayError(rw, 503, self.config.via_pseudonym);

        // ── build the forwarded target URL ──────────────────────────────
        var url_buf: [max_url_len]u8 = undefined;
        const url = buildUrl(&url_buf, backend, req.path, req.query) catch
            return gatewayError(rw, 502, self.config.via_pseudonym);

        // ── build the forwarded request headers ─────────────────────────
        var hdr_store: [max_fwd_headers]http.Header = undefined;
        var xff_buf: [max_xff_len]u8 = undefined;
        var via_buf: [max_via_len]u8 = undefined;
        const fwd = self.buildRequestHeaders(req, &hdr_store, &xff_buf, &via_buf) catch
            return gatewayError(rw, 502, self.config.via_pseudonym);

        const c = self.config.client;
        const has_body = req.head.chunked or (req.head.content_length orelse 0) != 0;

        var res: Client.Response = if (has_body) blk: {
            // Stream the request body through with the same framing shape.
            const content_length: ?u64 = if (req.head.chunked) null else req.head.content_length;
            var up = c.requestStreaming(req.method, url, .{ .headers = fwd }, content_length) catch |err|
                return self.onBackendError(rw, err);
            _ = req.reader().streamRemaining(up.writer()) catch {
                up.abort();
                return gatewayError(rw, 502, self.config.via_pseudonym);
            };
            break :blk up.finish() catch |err| return self.onBackendError(rw, err);
        } else c.request(req.method, url, .{
            .headers = fwd,
            .follow_redirects = false, // a proxy relays 3xx, never chases them
        }) catch |err| return self.onBackendError(rw, err);
        defer res.deinit();

        // ── relay status + response headers ─────────────────────────────
        rw.setStatus(res.status);
        const resp_conn = res.header("connection");
        var it = res.head.iterate();
        while (it.next()) |entry| {
            if (isHopByHop(entry.name, resp_conn)) continue;
            // `Transfer-Encoding` is hop-by-hop (above); `Content-Length` is
            // copied so `rw` re-frames identity with the exact length. The
            // writer manages `Connection`/`Date`/`Server` itself.
            if (std.ascii.eqlIgnoreCase(entry.name, "connection") or
                std.ascii.eqlIgnoreCase(entry.name, "via")) continue;
            rw.setHeader(entry.name, entry.value) catch {};
        }
        // Response-side Via (append to the backend's own, if any).
        const via = buildVia(&via_buf, res.header("via"), self.config.via_pseudonym) catch null;
        if (via) |v| rw.setHeader("Via", v) catch {};

        // ── stream the response body back (no full buffering) ───────────
        _ = res.reader().streamRemaining(rw.writer()) catch {
            // Head may already be on the wire (large body outgrew the
            // buffer) — then the only honest move is to close the
            // connection; the serving loop does that when we return an
            // error. If nothing was sent yet, a 502 still fits.
            if (rw.headSent()) return error.ProxyBackendStreamAborted;
            return gatewayError(rw, 502, self.config.via_pseudonym);
        };
        // Finalize the response *before* the deferred `res.deinit()` frees
        // the backend head buffer: the relayed header slices point into it,
        // and `ResponseWriter.writeHead` (fully-buffered path) reads them at
        // `end()`. `end()` is idempotent, so the serving loop's own call is
        // then a no-op.
        try rw.end();
    }

    fn pickBackend(self: *ProxyHandler, req: *Server.Request) ?Backend {
        if (self.config.selector) |sel| return sel.select(req);
        return self.config.backend;
    }

    /// Map a `Client` error to a gateway status, or surface a genuine
    /// out-of-memory as a plain error (→ the server's 500).
    fn onBackendError(self: *ProxyHandler, rw: *Server.ResponseWriter, err: Client.Error) anyerror!void {
        if (err == error.OutOfMemory) return err;
        return gatewayError(rw, statusForBackendError(err), self.config.via_pseudonym);
    }

    /// Assemble the forwarded header set: pass-through end-to-end headers,
    /// drop hop-by-hop + client-managed framing, add the forwarding headers.
    fn buildRequestHeaders(
        self: *ProxyHandler,
        req: *Server.Request,
        store: []http.Header,
        xff_buf: []u8,
        via_buf: []u8,
    ) error{TooManyHeaders}![]http.Header {
        var n: usize = 0;
        const req_conn = req.header("connection");
        var it = req.head.iterate();
        while (it.next()) |entry| {
            const name = entry.name;
            // Host is set below (rewrite) or preserved explicitly; framing
            // headers are the client's job.
            if (std.ascii.eqlIgnoreCase(name, "host")) continue;
            if (std.ascii.eqlIgnoreCase(name, "content-length")) continue;
            if (std.ascii.eqlIgnoreCase(name, "via")) continue; // re-injected below
            if (isHopByHop(name, req_conn)) continue;
            if (n == store.len) return error.TooManyHeaders;
            store[n] = .{ .name = entry.name, .value = entry.value };
            n += 1;
        }

        // Host: preserve the client's when not rewriting (rewrite = let the
        // client default it to the backend authority, so nothing is added).
        if (!self.config.rewrite_host) {
            if (req.header("host")) |h| {
                if (n == store.len) return error.TooManyHeaders;
                store[n] = .{ .name = "Host", .value = h };
                n += 1;
            }
        }
        // X-Forwarded-For: append this hop's socket peer.
        if (buildForwardedFor(xff_buf, req)) |xff| {
            if (n == store.len) return error.TooManyHeaders;
            store[n] = .{ .name = "X-Forwarded-For", .value = xff };
            n += 1;
        }
        // X-Forwarded-Proto.
        if (n == store.len) return error.TooManyHeaders;
        store[n] = .{ .name = "X-Forwarded-Proto", .value = self.config.forwarded_proto };
        n += 1;
        // X-Forwarded-Host: the original Host the client asked for.
        if (req.header("host")) |h| {
            if (n == store.len) return error.TooManyHeaders;
            store[n] = .{ .name = "X-Forwarded-Host", .value = h };
            n += 1;
        }
        // Via (request side): append to the client's own, if any.
        if (buildVia(via_buf, req.header("via"), self.config.via_pseudonym) catch null) |v| {
            if (n == store.len) return error.TooManyHeaders;
            store[n] = .{ .name = "Via", .value = v };
            n += 1;
        }
        return store[0..n];
    }
};

// ── pure helpers (offline-testable) ─────────────────────────────────────────

/// RFC 9110 §7.6.1 hop-by-hop set, plus every `Proxy-*` field and every
/// field named in the message's own `Connection` token list. Case-insensitive.
pub fn isHopByHop(name: []const u8, connection_value: ?[]const u8) bool {
    const fixed = [_][]const u8{
        "connection", "keep-alive",        "te",      "trailer",
        "trailers",   "transfer-encoding", "upgrade",
    };
    for (fixed) |h| if (std.ascii.eqlIgnoreCase(name, h)) return true;
    if (std.ascii.startsWithIgnoreCase(name, "proxy-")) return true;
    if (connection_value) |cv| if (h1.tokenListContains(cv, name)) return true;
    return false;
}

/// Map a back-side `Client` error to the gateway status a client should see.
pub fn statusForBackendError(err: Client.Error) u16 {
    return switch (err) {
        error.Timeout => 504, // Gateway Timeout
        else => 502, // Bad Gateway (unreachable/refused/reset/malformed/…)
    };
}

/// `X-Forwarded-For` value: the existing chain (if any) with this hop's
/// socket peer appended. Null when there is no peer (socket-free serving).
fn buildForwardedFor(buf: []u8, req: *Server.Request) ?[]const u8 {
    const peer = req.peerAddress() orelse return null;
    const ip: netaddr.Ip = switch (peer) {
        .ip4 => |a| .{ .v4 = a.bytes },
        .ip6 => |a| .{ .v6 = a.bytes },
    };
    var ip_buf: [64]u8 = undefined;
    const ip_text = netaddr.formatIp(ip.unmap(), &ip_buf);

    var w: std.Io.Writer = .fixed(buf);
    if (req.header("x-forwarded-for")) |existing| {
        w.print("{s}, {s}", .{ existing, ip_text }) catch return ip_shortcut(buf, ip_text);
    } else {
        w.writeAll(ip_text) catch return null;
    }
    return w.buffered();
}

/// Fallback when the combined XFF chain would overflow `buf`: forward just
/// this hop's peer (never drop the header entirely — the backend still needs
/// a client identity).
fn ip_shortcut(buf: []u8, ip_text: []const u8) ?[]const u8 {
    if (ip_text.len > buf.len) return null;
    @memcpy(buf[0..ip_text.len], ip_text);
    return buf[0..ip_text.len];
}

/// `Via` value: the existing `Via` (if any) with `", 1.1 <pseudonym>"`
/// appended (RFC 9110 §7.6.3 — received-protocol + pseudonym).
fn buildVia(buf: []u8, existing: ?[]const u8, pseudonym: []const u8) error{Overflow}!?[]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (existing) |e| {
        w.print("{s}, 1.1 {s}", .{ e, pseudonym }) catch return error.Overflow;
    } else {
        w.print("1.1 {s}", .{pseudonym}) catch return error.Overflow;
    }
    return w.buffered();
}

/// Build `scheme://authority{path}{?query}` for the backend into `buf`.
fn buildUrl(buf: []u8, backend: Backend, path: []const u8, query: []const u8) error{Overflow}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const scheme = switch (backend.scheme) {
        .http => "http",
        .https => "https",
    };
    w.print("{s}://", .{scheme}) catch return error.Overflow;
    // IPv6 literals need brackets in the authority.
    if (std.mem.indexOfScalar(u8, backend.host, ':') != null) {
        w.print("[{s}]", .{backend.host}) catch return error.Overflow;
    } else {
        w.writeAll(backend.host) catch return error.Overflow;
    }
    w.print(":{d}", .{backend.port}) catch return error.Overflow;
    const p = if (path.len == 0) "/" else path;
    w.writeAll(p) catch return error.Overflow;
    if (query.len != 0) w.print("?{s}", .{query}) catch return error.Overflow;
    return w.buffered();
}

/// Write a small gateway error response (only possible before any response
/// byte is on the wire; the caller guarantees that).
fn gatewayError(rw: *Server.ResponseWriter, status: u16, pseudonym: []const u8) anyerror!void {
    if (rw.headSent()) return error.ProxyBackendStreamAborted;
    rw.setStatus(status);
    rw.setHeader("Content-Type", "text/plain") catch {};
    var via_buf: [max_via_len]u8 = undefined;
    if (buildVia(&via_buf, null, pseudonym) catch null) |v| rw.setHeader("Via", v) catch {};
    const msg = switch (status) {
        502 => "Bad Gateway\n",
        503 => "Service Unavailable\n",
        504 => "Gateway Timeout\n",
        else => "Proxy Error\n",
    };
    try rw.writeAll(msg);
}

// Sizing: generous fixed scratch, no per-request allocation of our own.
const max_url_len = 16 * 1024; // covers the server's 8 KiB request-line cap + authority
const max_fwd_headers = 96;
const max_xff_len = 4 * 1024;
const max_via_len = 512;

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "isHopByHop: fixed set, Proxy-*, and Connection-listed tokens" {
    // Fixed hop-by-hop set (case-insensitive).
    try testing.expect(isHopByHop("Connection", null));
    try testing.expect(isHopByHop("keep-alive", null));
    try testing.expect(isHopByHop("TE", null));
    try testing.expect(isHopByHop("Trailer", null));
    try testing.expect(isHopByHop("Transfer-Encoding", null));
    try testing.expect(isHopByHop("Upgrade", null));
    // Every Proxy-* field.
    try testing.expect(isHopByHop("Proxy-Authorization", null));
    try testing.expect(isHopByHop("Proxy-Connection", null));
    // End-to-end headers pass through.
    try testing.expect(!isHopByHop("Content-Type", null));
    try testing.expect(!isHopByHop("Authorization", null));
    try testing.expect(!isHopByHop("X-Custom", null));
    // A field named in the Connection token list is hop-by-hop for this hop.
    try testing.expect(isHopByHop("X-Custom", "keep-alive, X-Custom"));
    try testing.expect(!isHopByHop("X-Other", "keep-alive, X-Custom"));
}

test "statusForBackendError: timeout → 504, everything else → 502" {
    try testing.expectEqual(@as(u16, 504), statusForBackendError(error.Timeout));
    try testing.expectEqual(@as(u16, 502), statusForBackendError(error.ConnectFailed));
    try testing.expectEqual(@as(u16, 502), statusForBackendError(error.UnknownHostName));
    try testing.expectEqual(@as(u16, 502), statusForBackendError(error.ConnectionClosed));
    try testing.expectEqual(@as(u16, 502), statusForBackendError(error.MalformedResponse));
    try testing.expectEqual(@as(u16, 502), statusForBackendError(error.TlsFailed));
}

test "buildVia: fresh and appended" {
    var buf: [max_via_len]u8 = undefined;
    try testing.expectEqualStrings("1.1 zig-libs", (try buildVia(&buf, null, "zig-libs")).?);
    try testing.expectEqualStrings(
        "1.0 edge, 1.1 gw",
        (try buildVia(&buf, "1.0 edge", "gw")).?,
    );
}

test "buildUrl: authority, path, query, IPv6 brackets, default path" {
    var buf: [max_url_len]u8 = undefined;
    try testing.expectEqualStrings(
        "http://10.0.0.1:8080/api?x=1",
        try buildUrl(&buf, .{ .host = "10.0.0.1", .port = 8080 }, "/api", "x=1"),
    );
    try testing.expectEqualStrings(
        "http://10.0.0.1:8080/",
        try buildUrl(&buf, .{ .host = "10.0.0.1", .port = 8080 }, "", ""),
    );
    try testing.expectEqualStrings(
        "https://[2001:db8::1]:443/v1",
        try buildUrl(&buf, .{ .scheme = .https, .host = "2001:db8::1", .port = 443 }, "/v1", ""),
    );
}

// ── integration: a real proxy in front of a real origin, over loopback ──────

/// Origin handler: reflects the forwarding headers it received into the
/// response (so the client, through the proxy, can assert them), and echoes
/// any request body back.
fn originHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/reflect")) {
        try rw.setHeader("X-Saw-XFF", req.header("x-forwarded-for") orelse "none");
        try rw.setHeader("X-Saw-Proto", req.header("x-forwarded-proto") orelse "none");
        try rw.setHeader("X-Saw-Host", req.header("x-forwarded-host") orelse "none");
        try rw.setHeader("X-Saw-Via", req.header("via") orelse "none");
        try rw.setHeader("X-Saw-Upgrade", req.header("upgrade") orelse "none");
        try rw.setHeader("X-Saw-ProxyAuth", req.header("proxy-authorization") orelse "none");
        try rw.setHeader("X-Saw-Keep", req.header("x-keep") orelse "none");
        try rw.setHeader("X-Saw-ReqHost", req.header("host") orelse "none");
        // A hop-by-hop response header the proxy must strip on the way back
        // (Keep-Alive is in the fixed set and, unlike Connection, is not
        // managed away by the ResponseWriter — so it really hits the wire).
        try rw.setHeader("Keep-Alive", "timeout=5");
        try rw.writeAll("reflected");
    } else if (std.mem.eql(u8, req.path, "/echo")) {
        var buf: [1 << 20]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
    } else {
        rw.setStatus(404);
        try rw.writeAll("origin: not found\n");
    }
}

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

test "integration: reverse proxy forwards, injects headers, strips hop-by-hop, 502 on dead upstream" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Origin server.
    var origin = Server.init(io, testing.allocator, .{ .handler = originHandler });
    defer origin.deinit();
    origin.bind() catch |err| {
        std.debug.print("origin bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const origin_thread = try std.Thread.spawn(.{}, serveWrap, .{&origin});
    defer origin_thread.join();
    defer origin.shutdown();
    const origin_port = origin.boundAddress().getPort();

    // Proxy server: forwards everything to the origin, on its own multicore
    // accept engine (exercise Part 1 and Part 2 together).
    var proxy_client = Client.init(io, testing.allocator, .{});
    defer proxy_client.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = origin_port },
    });
    var proxy = Server.init(io, testing.allocator, .{
        .handler = ProxyHandler.handler,
        .context = &ph,
        .accept_threads = 2,
    });
    defer proxy.deinit();
    proxy.bind() catch |err| {
        std.debug.print("proxy bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const proxy_thread = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer proxy_thread.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // Forwarding + header injection + hop-by-hop stripping.
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/reflect", .{proxy_port});
        var res = try client.request(.get, url, .{
            .headers = &.{
                .{ .name = "X-Keep", .value = "kept" }, // end-to-end → forwarded
                .{ .name = "Upgrade", .value = "websocket" }, // hop-by-hop → stripped
                .{ .name = "Proxy-Authorization", .value = "secret" }, // Proxy-* → stripped
            },
        });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 256);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("reflected", body);

        // Forwarding headers the origin saw:
        try testing.expectEqualStrings("127.0.0.1", res.header("x-saw-xff").?);
        try testing.expectEqualStrings("http", res.header("x-saw-proto").?);
        try testing.expect(std.mem.indexOf(u8, res.header("x-saw-via").?, "1.1 zig-libs") != null);
        try testing.expectEqualStrings("kept", res.header("x-saw-keep").?);
        // Host rewritten to the backend authority (default rewrite_host).
        var host_buf: [32]u8 = undefined;
        const want_host = try std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{origin_port});
        try testing.expectEqualStrings(want_host, res.header("x-saw-reqhost").?);
        // Hop-by-hop request headers were stripped before the origin.
        try testing.expectEqualStrings("none", res.header("x-saw-upgrade").?);
        try testing.expectEqualStrings("none", res.header("x-saw-proxyauth").?);
        // The origin's hop-by-hop response header (Keep-Alive) was stripped
        // by the proxy and never reached the client.
        try testing.expectEqual(@as(?[]const u8, null), res.header("keep-alive"));
        // The proxy injected a response-side Via too.
        try testing.expect(std.mem.indexOf(u8, res.header("via").?, "1.1 zig-libs") != null);
    }

    { // Streaming request + response body (large, outgrows every buffer).
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/echo", .{proxy_port});
        const payload = "STREAM" ** 20_000; // 120 KB
        var res = try client.request(.post, url, .{ .body = payload });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, payload.len + 16);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(payload, body);
    }

    { // Dead upstream → 502 Bad Gateway.
        var dead_client = Client.init(io, testing.allocator, .{});
        defer dead_client.deinit();
        var dead_ph = ProxyHandler.init(.{
            .client = &dead_client,
            // Port 1 is reserved/unbindable — connect refuses fast.
            .backend = .{ .host = "127.0.0.1", .port = 1 },
        });
        var dead_proxy = Server.init(io, testing.allocator, .{
            .handler = ProxyHandler.handler,
            .context = &dead_ph,
        });
        defer dead_proxy.deinit();
        dead_proxy.bind() catch return error.SkipZigTest;
        const dt = try std.Thread.spawn(.{}, serveWrap, .{&dead_proxy});
        defer dt.join();
        defer dead_proxy.shutdown();
        const dp = dead_proxy.boundAddress().getPort();

        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/anything", .{dp});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 502), res.status);
        try testing.expect(std.mem.indexOf(u8, res.header("via").?, "zig-libs") != null);
    }
}
