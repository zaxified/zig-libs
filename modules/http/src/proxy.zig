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
//! ## HTTP/2 (h2/h2c) upstreaming
//!
//! The forward path is **protocol-selectable per backend**
//! (`Backend.protocol`): `.http1` (the default) forwards over the h1
//! `Client` exactly as before — byte-for-byte unchanged — while `.h2c`
//! (cleartext prior-knowledge) and `.h2` (over TLS, via the BYO-TLS dial
//! seam) forward over HTTP/2. h2 forwarding composes an `h2_upstream.Pool`
//! (wired through `Config.h2_upstream`): the pool keeps ONE multiplexed h2
//! connection per backend origin and runs each proxied request as a fresh
//! stream on it, so many proxied requests share one upstream connection
//! (the whole point of h2 upstreaming). This module still owns the
//! translation — hop-by-hop stripping, `X-Forwarded-*` / `Via`, status +
//! header + body relay are shared with the h1 path; the pool owns
//! connection multiplexing, reuse and failure recovery. See `h2_upstream`
//! for the concurrency bound (per-connection response collection is
//! serialized) and the body-buffering caveat (the reused h2 client
//! assembles bodies in memory, bounded by `Config.h2_max_body_bytes`,
//! where the h1 path streams them). Trailers are not forwarded over h2
//! (the h2 client does not surface them — consistent with the module's
//! read-only-trailer posture).
//!
//! ## Known gaps (this pass)
//!
//! - **h2 upstream bodies are buffered** (bounded), not streamed like the
//!   h1 path — a limitation of reusing the existing multiplexing h2 client
//!   rather than forking a streaming one. Flow control is still exercised
//!   (WINDOW_UPDATE on bodies past the initial window).
//! - **No response buffer pool** for the *server*-side `ResponseWriter`
//!   (its per-connection buffer is reused across keep-alive requests but
//!   not shared across connections). The *client*-side shared buffer pool
//!   for pooled connections now exists (`Client.Options.buffer_pool`,
//!   backing h2 upstream dials).
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
const h2_upstream = @import("h2_upstream.zig");
const netaddr = @import("netaddr");

/// Which protocol the proxy forwards to a backend over. `.http1` (the
/// default) is the streaming h1 `Client` path, unchanged. `.h2c` and `.h2`
/// forward over the multiplexing HTTP/2 client through `Config.h2_upstream`
/// (which must be set when any backend selects them).
pub const UpstreamProtocol = enum {
    /// HTTP/1.1 over the h1 `Client` (the original path).
    http1,
    /// Cleartext HTTP/2 via prior knowledge (RFC 9113 §3.3) — `:scheme`
    /// "http". Requires an `h2_upstream.Pool` on the built-in h2c dialer.
    h2c,
    /// HTTP/2 over TLS — `:scheme` "https". Requires an `h2_upstream.Pool`
    /// configured with a custom TLS dialer (BYO-TLS + ALPN "h2").
    h2,
};

/// One backend origin to forward to.
pub const Backend = struct {
    scheme: http.Url.Scheme = .http,
    /// Hostname or IP literal (IPv6 without brackets — added on the wire).
    host: []const u8,
    port: u16,
    /// Forward protocol (see `UpstreamProtocol`). Default `.http1` keeps the
    /// original h1 forward path.
    protocol: UpstreamProtocol = .http1,
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
    /// HTTP/2 upstream pool — required when any backend's `protocol` is
    /// `.h2c`/`.h2` (a request routed to such a backend with this null
    /// answers 502). Keeps one multiplexed h2 connection per backend and
    /// runs each proxied request as a stream on it (see `h2_upstream`). The
    /// `.http1` path never touches it. Shared across the server's connection
    /// threads, like `client`.
    h2_upstream: ?*h2_upstream.Pool = null,
    /// Upper bound (bytes) on a request/response body proxied over h2: the
    /// reused multiplexing h2 client assembles bodies in memory (unlike the
    /// streaming h1 path), so both directions are capped. A larger body
    /// answers 502. Ignored by the `.http1` path (which streams).
    h2_max_body_bytes: usize = 8 * 1024 * 1024,
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

        // Protocol split: h2/h2c forward over the multiplexing HTTP/2 client
        // (a shared upstream connection per backend); h1 takes the streaming
        // path below, byte-for-byte unchanged.
        if (backend.protocol != .http1) return self.forwardH2(backend, req, rw);

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
            rw.setHeader(entry.name, entry.value) catch return self.relayFailed(rw);
        }
        // Response-side Via (append to the backend's own, if any).
        const via = buildVia(&via_buf, res.header("via"), self.config.via_pseudonym) catch
            return self.relayFailed(rw);
        rw.setHeader("Via", via) catch return self.relayFailed(rw);

        // ── stream the response body back (no full buffering) ───────────
        _ = res.reader().streamRemaining(rw.writer()) catch {
            // Head may already be on the wire (large body outgrew the
            // buffer) — then the only honest move is to close the
            // connection; the serving loop does that when we return an
            // error. If nothing was sent yet, a 502 still fits.
            if (rw.headSent()) return error.ProxyBackendStreamAborted;
            return gatewayError(rw, 502, self.config.via_pseudonym);
        };
        // No early `end()`. It used to be forced here so `writeHead` read the
        // relayed header slices before the deferred `res.deinit()` freed the
        // backend head buffer they pointed into; `setHeader` copies those
        // bytes now, and the body is likewise in the writer's own buffer or
        // already framed onto the wire. The serving loop ends the response.
    }

    /// Forward `req` to an HTTP/2 (h2/h2c) backend through the shared
    /// `h2_upstream.Pool`: translate the request into a stream on the
    /// backend's one multiplexed connection, collect the response, relay it
    /// back. Header translation (hop-by-hop, `X-Forwarded-*`, `Via`) is
    /// shared with the h1 path; the h2 body is buffered (bounded — see
    /// `Config.h2_max_body_bytes`).
    fn forwardH2(self: *ProxyHandler, backend: Backend, req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const pool = self.config.h2_upstream orelse
            return gatewayError(rw, 502, self.config.via_pseudonym);
        const gpa = self.config.client.gpa;

        // Forwarded request headers (shared with the h1 path). Host is not
        // among them (dropped there) — `:authority` carries it below.
        var hdr_store: [max_fwd_headers]http.Header = undefined;
        var xff_buf: [max_xff_len]u8 = undefined;
        var via_buf: [max_via_len]u8 = undefined;
        const fwd = self.buildRequestHeaders(req, &hdr_store, &xff_buf, &via_buf) catch
            return gatewayError(rw, 502, self.config.via_pseudonym);

        // `:authority` — backend authority when rewriting Host (default),
        // else the client's original Host.
        var auth_buf: [max_authority_len]u8 = undefined;
        const authority = blk: {
            if (!self.config.rewrite_host) {
                if (req.header("host")) |h| break :blk h;
            }
            break :blk buildAuthority(&auth_buf, backend) catch
                return gatewayError(rw, 502, self.config.via_pseudonym);
        };

        // Read the request body into memory (bounded); the h2 client streams
        // it out under §5.2 flow control (WINDOW_UPDATE past the window).
        const has_body = req.head.chunked or (req.head.content_length orelse 0) != 0;
        var body_buf: ?[]u8 = null;
        defer if (body_buf) |b| gpa.free(b);
        if (has_body) {
            body_buf = req.reader().allocRemaining(gpa, .limited(self.config.h2_max_body_bytes)) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Over the cap or a read failure — nothing is on the wire yet.
                else => return gatewayError(rw, 502, self.config.via_pseudonym),
            };
        }

        const be: h2_upstream.Backend = .{
            .host = backend.host,
            .port = backend.port,
            .secure = backend.protocol == .h2,
        };
        var res = pool.roundtrip(be, .{
            .method = req.method,
            .path = if (req.target.len == 0) "/" else req.target, // origin-form, query included
            .authority = authority,
            .scheme = if (backend.protocol == .h2) "https" else "http",
            .headers = fwd,
            .body = body_buf,
        }) catch |err| return self.onH2Error(rw, err);
        defer res.deinit(gpa);

        // ── relay status + response headers ─────────────────────────────
        rw.setStatus(res.status);
        const resp_conn = res.header("connection");
        for (res.headers.fields) |f| {
            if (f.name.len != 0 and f.name[0] == ':') continue; // pseudo-headers (:status)
            if (isHopByHop(f.name, resp_conn)) continue;
            if (std.ascii.eqlIgnoreCase(f.name, "connection") or
                std.ascii.eqlIgnoreCase(f.name, "via")) continue;
            rw.setHeader(f.name, f.value) catch return self.relayFailed(rw);
        }
        const via = buildVia(&via_buf, res.header("via"), self.config.via_pseudonym) catch
            return self.relayFailed(rw);
        rw.setHeader("Via", via) catch return self.relayFailed(rw);

        // ── relay the (buffered) response body ──────────────────────────
        // `res.body` is copied into the writer, so — as on the h1 path — the
        // deferred `res.deinit(gpa)` is no longer racing an early `end()`.
        rw.writeAll(res.body) catch {
            if (rw.headSent()) return error.ProxyBackendStreamAborted;
            return gatewayError(rw, 502, self.config.via_pseudonym);
        };
    }

    /// Map an `h2_upstream` forward error to a gateway status (or surface a
    /// genuine OOM as the server's 500).
    fn onH2Error(self: *ProxyHandler, rw: *Server.ResponseWriter, err: anyerror) anyerror!void {
        if (err == error.OutOfMemory) return err;
        const status: u16 = switch (err) {
            error.Timeout => 504, // Gateway Timeout
            else => 502, // Bad Gateway (dial/protocol/reset/goaway/…)
        };
        return gatewayError(rw, status, self.config.via_pseudonym);
    }

    fn pickBackend(self: *ProxyHandler, req: *Server.Request) ?Backend {
        if (self.config.selector) |sel| return sel.select(req);
        return self.config.backend;
    }

    /// A backend response header would not go onto our response — the
    /// writer's copied-header byte budget or its field table ran out, the
    /// `Via` chain outgrew `max_via_len`, or the backend sent a field we
    /// refuse (an unparseable `Content-Length`, a CR/LF in a value).
    ///
    /// This was `catch {}` until 2026-08-13, and a silent drop is the worst
    /// of the available answers: the client gets a 200 that *looks* complete
    /// while missing the `Location` of a redirect, the `WWW-Authenticate` of
    /// a 401, the `Set-Cookie` of a login, or the `Content-Encoding` of a
    /// compressed body — which it will then decode as plaintext. Neither end
    /// can tell, so nobody ever finds out.
    ///
    /// The alternatives, and why not:
    ///   * **Propagate the error.** The serving loop turns it into a bare 500
    ///     and closes the connection, which names neither the hop nor the
    ///     cause — and on the h1 path costs a connection per occurrence.
    ///   * **Truncate with a marker header.** There is no marker a client is
    ///     obliged to read, so the mutilated response still gets consumed as
    ///     if whole; and the marker wants budget in the one moment there is
    ///     none.
    ///   * **Reject up front**, as `security-headers` does for its static
    ///     configuration. A proxy cannot: it learns the backend's header set
    ///     only once the backend has answered, and re-deriving "will this
    ///     fit" here would duplicate the writer's own accounting — the copy
    ///     store's append-only budget, replace-by-name, the managed headers —
    ///     which is a second constant to get wrong.
    ///
    /// So the proxy reports what happened: it could not faithfully relay the
    /// backend's answer, which is a gateway failure. Nothing is on the wire
    /// yet (the head is written when the body starts, and no body byte has
    /// been relayed), so `reset` discards the half-relayed set and the 502
    /// goes out clean, carrying `Via` so the failing hop is identifiable.
    fn relayFailed(self: *ProxyHandler, rw: *Server.ResponseWriter) anyerror!void {
        if (rw.headSent()) return error.ProxyBackendStreamAborted;
        rw.reset(); // a partly-relayed header set must not ride the 502
        return gatewayErrorReason(
            rw,
            502,
            self.config.via_pseudonym,
            "Bad Gateway: backend response headers could not be relayed\n",
        );
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
        // Via (request side): append to the client's own, if any. A chain
        // too long for `via_buf` omits it rather than failing the forward —
        // the *response* side is where a header the peer never sees changes
        // what the client believes, and that one answers 502 (`relayFailed`).
        if (buildVia(via_buf, req.header("via"), self.config.via_pseudonym)) |v| {
            if (n == store.len) return error.TooManyHeaders;
            store[n] = .{ .name = "Via", .value = v };
            n += 1;
        } else |_| {}
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
fn buildVia(buf: []u8, existing: ?[]const u8, pseudonym: []const u8) error{Overflow}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (existing) |e| {
        w.print("{s}, 1.1 {s}", .{ e, pseudonym }) catch return error.Overflow;
    } else {
        w.print("1.1 {s}", .{pseudonym}) catch return error.Overflow;
    }
    return w.buffered();
}

/// Build the `:authority` value (backend host + `:port` when non-default for
/// the forward protocol) for an h2/h2c request into `buf`. IPv6 literals get
/// brackets (RFC 9113 §8.3.1 / §3.3, same authority shape as h1's Host).
fn buildAuthority(buf: []u8, backend: Backend) error{Overflow}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (std.mem.indexOfScalar(u8, backend.host, ':') != null) {
        w.print("[{s}]", .{backend.host}) catch return error.Overflow;
    } else {
        w.writeAll(backend.host) catch return error.Overflow;
    }
    const default_port: u16 = if (backend.protocol == .h2) 443 else 80;
    if (backend.port != default_port) w.print(":{d}", .{backend.port}) catch return error.Overflow;
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
    return gatewayErrorReason(rw, status, pseudonym, switch (status) {
        502 => "Bad Gateway\n",
        503 => "Service Unavailable\n",
        504 => "Gateway Timeout\n",
        else => "Proxy Error\n",
    });
}

/// `gatewayError` with the reason spelled out in the body — for a failure
/// whose cause is *this hop*, where a bare "Bad Gateway" would send an
/// operator hunting an unreachable backend that is in fact answering fine.
///
/// The two `catch {}` here are on the error page's own decoration and are
/// deliberate: the status line and the body already carry the failure, and a
/// second failure while reporting the first has nowhere left to go.
fn gatewayErrorReason(
    rw: *Server.ResponseWriter,
    status: u16,
    pseudonym: []const u8,
    msg: []const u8,
) anyerror!void {
    if (rw.headSent()) return error.ProxyBackendStreamAborted;
    rw.setStatus(status);
    rw.setHeader("Content-Type", "text/plain") catch {};
    var via_buf: [max_via_len]u8 = undefined;
    if (buildVia(&via_buf, null, pseudonym)) |v| rw.setHeader("Via", v) catch {} else |_| {}
    try rw.writeAll(msg);
}

// Sizing: generous fixed scratch, no per-request allocation of our own.
const max_url_len = 16 * 1024; // covers the server's 8 KiB request-line cap + authority
const max_fwd_headers = 96;
const max_xff_len = 4 * 1024;
const max_via_len = 512;
const max_authority_len = 300; // host (≤253) + brackets + ":port"

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const net = std.Io.net;

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
    try testing.expectEqualStrings("1.1 zig-libs", try buildVia(&buf, null, "zig-libs"));
    try testing.expectEqualStrings("1.0 edge, 1.1 gw", try buildVia(&buf, "1.0 edge", "gw"));
    // The chain that does not fit reports it — the response-side caller turns
    // that into a 502 rather than quietly forwarding an unmarked hop.
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.Overflow, buildVia(&tiny, null, "zig-libs"));
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

// ── integration: a backend answer the proxy cannot relay ────────────────────

/// One response header block a `FatHeaderOrigin` answers with.
const HeaderShape = struct {
    /// How many `X-Fat-NNN` response headers.
    count: usize,
    /// Bytes in each of their values.
    value_len: usize,
};

/// An origin that answers with a header block of the caller's choosing —
/// including blocks past what `ResponseWriter` can hold. Faked at the socket
/// level (the same `net.Stream` + `h1.readHead` plumbing `Client` and
/// `Server` are built on) because a real `http.Server` origin *cannot*
/// produce one: its response writer has the very limits under test, so an
/// origin able to send these bytes is precisely what an `http.Server` is not.
///
/// The schedule is fixed up front and the thread returns when it runs out, so
/// the origin can never be left parked in `accept` waiting for a request the
/// test is not going to make.
const FatHeaderOrigin = struct {
    io: std.Io,
    listener: *net.Server,
    /// One shape per request, in order. Read only by this thread.
    shapes: []const HeaderShape,

    fn run(o: *FatHeaderOrigin) void {
        for (o.shapes) |shape| {
            const s = o.listener.accept(o.io) catch return;
            defer s.close(o.io);
            var rbuf: [4096]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = s.reader(o.io, &rbuf);
            var sw = s.writer(o.io, &wbuf);
            var head_buf: [4096]u8 = undefined;
            _ = h1.readHead(&sr.interface, &head_buf) catch return;

            var value: [1024]u8 = undefined;
            @memset(&value, 'v');
            const w = &sw.interface;
            // `Connection: close` so every request gets a fresh connection and
            // the accept count matches the request count exactly.
            w.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n") catch return;
            for (0..shape.count) |i|
                w.print("X-Fat-{d:0>3}: {s}\r\n", .{ i, value[0..shape.value_len] }) catch return;
            w.writeAll("\r\nok") catch return;
            w.flush() catch return;
        }
    }
};

/// What one round trip through the proxy left behind, copied out before the
/// response is released.
///
/// All three round trips are captured BEFORE anything is asserted, on
/// purpose: a `try` that fired in the middle of the sequence would leave the
/// origin thread blocked in `accept` for a request that never comes, and the
/// deferred `join` would hang the suite instead of failing it.
const Relayed = struct {
    status: u16 = 0,
    body_buf: [160]u8 = undefined,
    body_len: usize = 0,
    /// Value length of the backend's first/last `X-Fat` header, null = the
    /// header did not reach the client.
    fat_first: ?usize = null,
    fat_last: ?usize = null,
    via_buf: [128]u8 = undefined,
    via_len: usize = 0,

    fn body(r: *const Relayed) []const u8 {
        return r.body_buf[0..r.body_len];
    }
    fn via(r: *const Relayed) []const u8 {
        return r.via_buf[0..r.via_len];
    }

    /// A failed request leaves `status` 0 rather than propagating — see the
    /// type doc.
    fn get(client: *Client, url: []const u8) Relayed {
        var r: Relayed = .{};
        var res = client.request(.get, url, .{}) catch return r;
        defer res.deinit();
        r.status = res.status;
        if (res.header("x-fat-000")) |v| r.fat_first = v.len;
        if (res.header("x-fat-007")) |v| r.fat_last = v.len;
        if (res.header("via")) |v| {
            r.via_len = @min(v.len, r.via_buf.len);
            @memcpy(r.via_buf[0..r.via_len], v[0..r.via_len]);
        }
        var w: std.Io.Writer = .fixed(&r.body_buf);
        _ = res.reader().streamRemaining(&w) catch {};
        r.body_len = w.buffered().len;
        return r;
    }
};

test "integration: a backend header set the proxy cannot relay answers 502, not a mutilated 200" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("fat-header origin listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const origin_port = listener.socket.address.getPort();

    var origin: FatHeaderOrigin = .{
        .io = io,
        .listener = &listener,
        .shapes = &.{
            // 1. Past the copied-header BYTE budget: 8 × (9 + 600) ≈ 4.9 KB
            //    of name+value against `header_copy_bytes` (4 KiB), while the
            //    field COUNT stays well inside `max_response_headers`.
            .{ .count = 8, .value_len = 600 },
            // 2. The mirror image: 40 fields, ~0.5 KB of bytes — over the
            //    count limit, nowhere near the byte one.
            .{ .count = 40, .value_len = 4 },
            // 3. Control: fat but relayable, inside both limits.
            .{ .count = 8, .value_len = 100 },
        },
    };
    const origin_thread = try std.Thread.spawn(.{}, FatHeaderOrigin.run, .{&origin});
    defer origin_thread.join();

    var proxy_client = Client.init(io, testing.allocator, .{});
    defer proxy_client.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = origin_port },
    });
    var proxy = Server.init(io, testing.allocator, .{ .handler = ProxyHandler.handler, .context = &ph });
    defer proxy.deinit();
    proxy.bind() catch return error.SkipZigTest;
    const proxy_thread = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer proxy_thread.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{proxy_port});

    const over_bytes = Relayed.get(&client, url);
    const over_count = Relayed.get(&client, url);
    const fits = Relayed.get(&client, url);

    // The item this pins: a backend header that will not fit is NOT dropped
    // behind the client's back. The old `catch {}` produced a 200 that looked
    // perfectly normal and was missing `X-Fat-005` onward.
    try testing.expectEqual(@as(u16, 502), over_bytes.status);
    try testing.expect(std.mem.indexOf(u8, over_bytes.body(), "could not be relayed") != null);
    // Not even the fields that DID fit before the budget ran out ride along
    // on the 502 — `reset` drops the half-relayed set.
    try testing.expectEqual(@as(?usize, null), over_bytes.fat_first);
    try testing.expectEqual(@as(?usize, null), over_bytes.fat_last);
    // …and the hop that failed names itself.
    try testing.expect(std.mem.indexOf(u8, over_bytes.via(), "zig-libs") != null);

    // Same answer when it is the field count rather than the byte budget.
    try testing.expectEqual(@as(u16, 502), over_count.status);
    try testing.expectEqual(@as(?usize, null), over_count.fat_first);

    // Control: a fat-but-relayable answer still goes through whole, so the
    // two 502s above are the limits talking and not the scaffold.
    try testing.expectEqual(@as(u16, 200), fits.status);
    try testing.expectEqual(@as(?usize, 100), fits.fat_first);
    try testing.expectEqual(@as(?usize, 100), fits.fat_last);
    try testing.expectEqualStrings("ok", fits.body());
}

// ── integration: h1 proxy forwarding over h2c to an HTTP/2 backend ──────────

/// One concurrent client hitting the proxy — used to prove many clients
/// share the ONE upstream h2 connection.
const H2Worker = struct {
    io: std.Io,
    port: u16,
    ok: bool = false,

    fn run(w: *H2Worker) void {
        var client = Client.init(w.io, testing.allocator, .{});
        defer client.deinit();
        var url_buf: [64]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/reflect", .{w.port}) catch return;
        var res = client.request(.get, url, .{}) catch return;
        defer res.deinit();
        if (res.status != 200) return;
        const body = res.readAllAlloc(testing.allocator, 64) catch return;
        defer testing.allocator.free(body);
        w.ok = std.mem.eql(u8, body, "reflected");
    }
};

test "integration: reverse proxy forwards over h2c to an HTTP/2 backend (multiplex + reuse)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // h2c backend — the SAME `originHandler` serves h1 and h2 (proof the
    // translation is protocol-agnostic).
    var backend = Server.init(io, gpa, .{ .handler = originHandler, .enable_h2c = true });
    defer backend.deinit();
    backend.bind() catch |err| {
        std.debug.print("h2 backend bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const bt = try std.Thread.spawn(.{}, serveWrap, .{&backend});
    defer bt.join();
    defer backend.shutdown();
    const backend_port = backend.boundAddress().getPort();

    // h2 upstream pool + an h1 proxy that forwards to the backend over h2c.
    var proxy_client = Client.init(io, gpa, .{});
    defer proxy_client.deinit();
    var up = http.h2_upstream.Pool.init(gpa, .{ .client = &proxy_client });
    defer up.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .h2_upstream = &up,
        .backend = .{ .host = "127.0.0.1", .port = backend_port, .protocol = .h2c },
    });
    var proxy = Server.init(io, gpa, .{ .handler = ProxyHandler.handler, .context = &ph });
    defer proxy.deinit();
    proxy.bind() catch |err| {
        std.debug.print("proxy bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const pt = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer pt.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // GET /reflect: forwarding headers injected, hop-by-hop stripped — over h2.
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/reflect", .{proxy_port});
        var res = try client.request(.get, url, .{
            .headers = &.{
                .{ .name = "X-Keep", .value = "kept" }, // end-to-end → forwarded
                .{ .name = "Proxy-Authorization", .value = "secret" }, // Proxy-* → stripped
            },
        });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(gpa, 64);
        defer gpa.free(body);
        try testing.expectEqualStrings("reflected", body);
        // Forwarding headers the h2 backend saw:
        try testing.expectEqualStrings("127.0.0.1", res.header("x-saw-xff").?);
        try testing.expectEqualStrings("http", res.header("x-saw-proto").?);
        try testing.expect(std.mem.indexOf(u8, res.header("x-saw-via").?, "1.1 zig-libs") != null);
        try testing.expectEqualStrings("kept", res.header("x-saw-keep").?);
        // Hop-by-hop request header stripped before the backend.
        try testing.expectEqualStrings("none", res.header("x-saw-proxyauth").?);
        // Response-side Via injected; backend's hop-by-hop Keep-Alive stripped.
        try testing.expect(std.mem.indexOf(u8, res.header("via").?, "1.1 zig-libs") != null);
        try testing.expectEqual(@as(?[]const u8, null), res.header("keep-alive"));
    }

    { // POST /echo, large body → exercises h2 send-side flow control.
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/echo", .{proxy_port});
        const payload = "H2PROXY" ** 20_000; // ~140 KB, past the 64 KiB window
        var res = try client.request(.post, url, .{ .body = payload });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(gpa, payload.len + 16);
        defer gpa.free(body);
        try testing.expectEqualStrings(payload, body);
    }

    // Every request so far went over the ONE shared upstream connection.
    try testing.expectEqual(@as(usize, 1), up.dialCount());

    { // Concurrent clients → still one shared upstream connection.
        var workers: [3]H2Worker = undefined;
        var threads: [3]std.Thread = undefined;
        for (&workers) |*w| w.* = .{ .io = io, .port = proxy_port };
        for (&threads, &workers) |*t, *w| t.* = try std.Thread.spawn(.{}, H2Worker.run, .{w});
        for (&threads) |t| t.join();
        for (workers) |w| try testing.expect(w.ok);
    }
    try testing.expectEqual(@as(usize, 1), up.dialCount());
}

test "integration: h2c backend unreachable → 502 Bad Gateway" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var proxy_client = Client.init(io, gpa, .{});
    defer proxy_client.deinit();
    var up = http.h2_upstream.Pool.init(gpa, .{ .client = &proxy_client });
    defer up.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .h2_upstream = &up,
        // Port 1 is unbindable — the h2c dial refuses fast.
        .backend = .{ .host = "127.0.0.1", .port = 1, .protocol = .h2c },
    });
    var proxy = Server.init(io, gpa, .{ .handler = ProxyHandler.handler, .context = &ph });
    defer proxy.deinit();
    proxy.bind() catch return error.SkipZigTest;
    const pt = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer pt.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/x", .{proxy_port});
    var res = try client.request(.get, url, .{});
    defer res.deinit();
    try testing.expectEqual(@as(u16, 502), res.status);
    try testing.expect(std.mem.indexOf(u8, res.header("via").?, "zig-libs") != null);
}
