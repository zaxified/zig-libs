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
//!   `Upgrade`, every `Proxy-*`, and every field named in any of the
//!   message's `Connection` lines — dropped in both directions so per-hop
//!   framing never leaks end-to-end. A repeated response field is relayed
//!   whole: `Set-Cookie` line by line, any other joined with commas.
//! - **Upgrade passthrough** (WebSocket and any other `Upgrade`, Go's
//!   `handleUpgradeResponse`): a request whose `Connection` lists `upgrade`
//!   keeps `Connection: Upgrade` + its one `Upgrade` protocol on the way to
//!   an h1 backend; a backend `101` naming the same protocol is relayed and
//!   the two connections are spliced, bytes copied both ways (two tasks of
//!   the client's `Io`) until either side stops. A `101` for another
//!   protocol, or one nobody asked for, answers 502. The upgraded client
//!   connection is out of the HTTP timeouts (`Request.upgraded`).
//! - **Forwarding headers:** appends the socket peer to `X-Forwarded-For`
//!   (de-facto; every inbound line joins the chain, which is dropped when the
//!   client lists the field in `Connection`), sets `X-Forwarded-Proto` /
//!   `X-Forwarded-Host` (replacing a client's own claim), and injects
//!   `Via: 1.1 <pseudonym>` (RFC 9110 §7.6.3) on request and response,
//!   appending to any existing `Via`.
//! - **Hooks** (Go `ReverseProxy`): `Config.rewrite` edits the outbound
//!   request (`ProxyRequest`: backend, path, query, headers,
//!   `setXForwarded`), `Config.modify_response` the backend's answer
//!   (`ProxyResponse`: status, headers, body), `Config.error_handler`
//!   answers every failure before the response head is sent.
//! - **Streaming responses flushed as they arrive** (`Config.flush`, Go's
//!   `FlushInterval` default): SSE and responses of undeclared length are
//!   pushed to the client after every backend read.
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
//! - **Upgrade over HTTP/2** either way is not carried: an h2 client
//!   cannot ask (RFC 9113 §8.6 removed Upgrade; RFC 8441 extended CONNECT
//!   is not implemented), and to an `.h2c`/`.h2` backend the request goes
//!   on as a plain one.
//! - **Go's timed `FlushInterval`** (flush at most every N ms) has no
//!   counterpart: `Flush` is per read or by buffer.
//! - **A `Rewrite` hook sees the raw query.** Go re-encodes a query with a
//!   `;` or a malformed escape before the hook (`cleanQueryParams`); the
//!   query here goes on as the client sent it, as `url` treats `;` as a byte.
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
const testkit = @import("testkit");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2 = @import("h2.zig");
const Server = @import("Server.zig");
const Client = @import("Client.zig");
const h2_upstream = @import("h2_upstream.zig");
const hpack = @import("hpack.zig");
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
    /// When the relayed response body is pushed to the client (Go's
    /// `FlushInterval`). See `Flush`.
    flush: Flush = .auto,
    /// Go's `Rewrite`: edit the outbound request — backend, path, query,
    /// headers — before it is sent. Setting it switches the forwarding
    /// headers to Go's `Rewrite` rules: the client's `Forwarded` and
    /// `X-Forwarded-For/-Host/-Proto` are removed and nothing is added
    /// unless the hook calls `ProxyRequest.setXForwarded` (a hook that
    /// forgets it no longer passes a client-supplied chain on as if this
    /// proxy had vouched for it). `Via` is still added after the hook.
    rewrite: ?Rewrite = null,
    /// Go's `ModifyResponse`: edit the backend's answer — status, headers,
    /// body — before any of it is sent. An error discards the answer and
    /// goes to `error_handler`.
    modify_response: ?ModifyResponse = null,
    /// Go's `ErrorHandler`: answer a failure that happens before the
    /// response head is on the wire (no backend, backend unreachable or
    /// timed out, a hook error, an answer that cannot be relayed). Null
    /// answers the default 502/503/504 with `Via`. After the head is sent a
    /// failure can only close the connection, with or without a hook.
    error_handler: ?ErrorHandler = null,
};

pub const Rewrite = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, pr: *ProxyRequest) anyerror!void,
};

pub const ModifyResponse = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, pr: *ProxyResponse) anyerror!void,
};

pub const ErrorHandler = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, rw: *Server.ResponseWriter, req: *Server.Request, failure: Failure) anyerror!void,
};

/// What went wrong, for an `ErrorHandler`.
pub const Failure = struct {
    /// The cause: a `Client`/`h2_upstream` error, a hook's own error, or
    /// one of `ForwardError`.
    err: anyerror,
    /// What the default handler answers for it (501, 502, 503 or 504).
    status: u16,
};

/// Failures this module names itself.
pub const ForwardError = error{
    /// No backend: the `Selector` returned null.
    NoBackend,
    /// The outbound request could not be built: too many header lines, a
    /// target past the URL buffer, a rewritten path or query that is not
    /// origin-form (must start with `/`, no control octets, SP or `#`).
    BadOutboundRequest,
    /// The client's request body could not be read or sent on.
    RequestBodyFailed,
    /// The backend's answer cannot go onto our response (see `relayFailed`).
    ResponseNotRelayable,
    /// An HTTP/2 backend was selected and `Config.h2_upstream` is null.
    NoH2Upstream,
    /// The backend answered `101` to a request that asked for no upgrade,
    /// or switched to another protocol than the one asked for.
    UpgradeMismatch,
    /// A CONNECT reached the proxy: it asks for a tunnel, not a request to
    /// relay (501).
    MethodNotSupported,
};

/// The outbound request, as a `Rewrite` hook sees and edits it (Go's
/// `ProxyRequest`: `In`, `Out`, `SetURL`, `SetXForwarded`).
pub const ProxyRequest = struct {
    /// The inbound request (Go `In`). Read only.
    in: *Server.Request,
    /// Where the request goes (Go `SetURL`).
    backend: Backend,
    /// The outbound path and raw query, encoded as sent (Go `Out.URL.Path`
    /// / `RawQuery`). A replacement must outlive the forward (a literal, or
    /// storage in the hook's `ctx`) and stay origin-form, else
    /// `error.BadOutboundRequest`.
    path: []const u8,
    query: []const u8,
    /// The outbound header lines, hop-by-hop already removed (Go
    /// `Out.Header`). A `Host` line here is sent as the `Host` (h1) /
    /// `:authority` (h2); without one the backend authority is used.
    headers: Headers,
    forwarded_proto: []const u8,
    xff_buf: []u8,

    /// Go's `SetXForwarded`: `X-Forwarded-For` becomes the outbound value
    /// (if any) with the client's address appended (removed when serving
    /// socket-free), `X-Forwarded-Host` the inbound `Host`,
    /// `X-Forwarded-Proto` `Config.forwarded_proto`.
    pub fn setXForwarded(pr: *ProxyRequest) error{TooManyHeaders}!void {
        if (pr.in.peerAddress() == null) {
            pr.headers.del("X-Forwarded-For");
        } else {
            var w: std.Io.Writer = .fixed(pr.xff_buf);
            const fits = blk: {
                for (pr.headers.slice()) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-for")) {
                    w.print("{s}, ", .{h.value}) catch break :blk false;
                };
                var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
                w.writeAll(peerText(pr.in, &ip_buf).?) catch break :blk false;
                break :blk true;
            };
            if (fits) {
                try pr.headers.set("X-Forwarded-For", w.buffered());
            } else {
                // Past the buffer: this hop's peer alone, as the default path does.
                var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
                const ip = peerText(pr.in, &ip_buf).?;
                @memcpy(pr.xff_buf[0..ip.len], ip);
                try pr.headers.set("X-Forwarded-For", pr.xff_buf[0..ip.len]);
            }
        }
        if (pr.in.header("host")) |h| try pr.headers.set("X-Forwarded-Host", h) else pr.headers.del("X-Forwarded-Host");
        try pr.headers.set("X-Forwarded-Proto", pr.forwarded_proto);
    }
};

/// The backend's answer, as a `ModifyResponse` hook sees and edits it (Go's
/// `*http.Response` handed to `ModifyResponse`).
pub const ProxyResponse = struct {
    /// The inbound request.
    in: *Server.Request,
    /// The status that will be sent; starts as the backend's.
    status: u16,
    /// The response being built, its headers already relayed (hop-by-hop
    /// removed, `Via` added): edit them with `setHeader`/`addHeader`/
    /// `delHeader`/`getHeader`. Do not write the body here.
    rw: *Server.ResponseWriter,
    /// The body to relay; starts as the backend's. A replacement must
    /// outlive the forward (the hook's `ctx`), and the hook adjusts or
    /// removes `Content-Length` to match it (Go: `ContentLength`).
    body: *std.Io.Reader,
};

/// An editable list of header lines over caller storage.
pub const Headers = struct {
    store: []http.Header,
    len: usize = 0,

    pub fn slice(h: *const Headers) []const http.Header {
        return h.store[0..h.len];
    }

    /// The first value of `name` (case-insensitive), or null.
    pub fn get(h: *const Headers, name: []const u8) ?[]const u8 {
        for (h.slice()) |x| if (std.ascii.eqlIgnoreCase(x.name, name)) return x.value;
        return null;
    }

    /// Append a line.
    pub fn add(h: *Headers, name: []const u8, value: []const u8) error{TooManyHeaders}!void {
        if (h.len == h.store.len) return error.TooManyHeaders;
        h.store[h.len] = .{ .name = name, .value = value };
        h.len += 1;
    }

    /// Replace every line of `name` with one.
    pub fn set(h: *Headers, name: []const u8, value: []const u8) error{TooManyHeaders}!void {
        h.del(name);
        return h.add(name, value);
    }

    /// Remove every line of `name`.
    pub fn del(h: *Headers, name: []const u8) void {
        var w: usize = 0;
        for (h.store[0..h.len]) |x| {
            if (std.ascii.eqlIgnoreCase(x.name, name)) continue;
            h.store[w] = x;
            w += 1;
        }
        h.len = w;
    }
};

/// When the proxy flushes a relayed response body (h1 backends; an h2
/// backend's body arrives whole, see "Known gaps").
pub const Flush = enum {
    /// Go's default: after every read for a `text/event-stream` response and
    /// for one whose length the backend did not declare (chunked or
    /// close-delimited — a stream of unknown length is a stream); otherwise
    /// only as the writer's buffer fills.
    auto,
    /// After every read, whatever the response (Go's negative
    /// `FlushInterval`). Go's positive interval — a timed flush — has no
    /// counterpart.
    immediate,
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
        // CONNECT asks for a tunnel to the authority it names, which is a
        // forward proxy's job; a reverse proxy has no request to relay.
        if (req.method == .connect) return self.fail(rw, req, error.MethodNotSupported, 501);
        const picked = self.pickBackend(req) orelse return self.fail(rw, req, error.NoBackend, 503);

        // ── build the outbound request, then let the hook edit it ───────
        var hdr_store: [max_fwd_headers]http.Header = undefined;
        var xff_buf: [max_xff_len]u8 = undefined;
        var via_buf: [max_via_len]u8 = undefined;
        var pr: ProxyRequest = .{
            .in = req,
            .backend = picked,
            .path = req.path,
            .query = req.query,
            .headers = .{ .store = &hdr_store },
            .forwarded_proto = self.config.forwarded_proto,
            .xff_buf = &xff_buf,
        };
        self.buildRequestHeaders(&pr) catch return self.fail(rw, req, error.BadOutboundRequest, 502);
        // An upgrade (WebSocket, …) asked for: the two hop-by-hop fields
        // that carry it go on again (RFC 9110 §7.8; Go does the same).
        const upgrade = upgradeRequested(req, rw);
        if (upgrade) |protocol| {
            pr.headers.add("Connection", "Upgrade") catch return self.fail(rw, req, error.BadOutboundRequest, 502);
            pr.headers.add("Upgrade", protocol) catch return self.fail(rw, req, error.BadOutboundRequest, 502);
        }
        if (self.config.rewrite) |hook| {
            hook.func(hook.ctx, &pr) catch |e| return self.fail(rw, req, e, 502);
            if (!originForm(pr.path, pr.query)) return self.fail(rw, req, error.BadOutboundRequest, 502);
        }
        // Via (request side): append to the client's own, if any. A chain
        // too long for `via_buf` omits it rather than failing the forward —
        // the *response* side is where a header the peer never sees changes
        // what the client believes, and that one answers 502 (`relayFailed`).
        if (buildVia(&via_buf, req.header("via"), self.config.via_pseudonym)) |v| {
            pr.headers.set("Via", v) catch return self.fail(rw, req, error.BadOutboundRequest, 502);
        } else |_| {}

        // Protocol split: h2/h2c forward over the multiplexing HTTP/2 client
        // (a shared upstream connection per backend); h1 takes the streaming
        // path below.
        if (pr.backend.protocol != .http1) return self.forwardH2(&pr, rw);

        var url_buf: [max_url_len]u8 = undefined;
        const url = buildUrl(&url_buf, pr.backend, pr.path, pr.query) catch
            return self.fail(rw, req, error.BadOutboundRequest, 502);

        const c = self.config.client;
        // An extension method travels as its token (Go relays any method).
        const method_token = if (req.method == .other) req.methodName() else "";
        const has_body = req.head.chunked or (req.head.content_length orelse 0) != 0;

        var res: Client.Response = if (has_body) blk: {
            // Stream the request body through with the same framing shape.
            const content_length: ?u64 = if (req.head.chunked) null else req.head.content_length;
            var up = c.requestStreaming(req.method, url, .{ .headers = pr.headers.slice(), .method_token = method_token }, content_length) catch |err|
                return self.onBackendError(rw, req, err);
            _ = req.reader().streamRemaining(up.writer()) catch {
                up.abort();
                return self.fail(rw, req, error.RequestBodyFailed, 502);
            };
            break :blk up.finish() catch |err| return self.onBackendError(rw, req, err);
        } else c.request(req.method, url, .{
            .headers = pr.headers.slice(),
            .method_token = method_token,
            .follow_redirects = false, // a proxy relays 3xx, never chases them
        }) catch |err| return self.onBackendError(rw, req, err);
        defer res.deinit();

        // ── relay status + response headers ─────────────────────────────
        rw.setStatus(res.status);
        relayHead(rw, res.head) catch return self.relayFailed(rw, req);
        if (res.status == 101) return self.relayUpgrade(rw, req, &res, upgrade, &via_buf);
        return self.finishResponse(rw, req, res.status, res.header("via"), res.reader(), &via_buf);
    }

    /// The backend switched protocols: answer the client's upgrade with the
    /// backend's 101 (its end-to-end fields, `Via`, the `ModifyResponse`
    /// hook), then copy bytes both ways until either side stops — Go's
    /// `handleUpgradeResponse`.
    fn relayUpgrade(
        self: *ProxyHandler,
        rw: *Server.ResponseWriter,
        req: *Server.Request,
        res: *Client.Response,
        asked: ?[]const u8,
        via_buf: []u8,
    ) anyerror!void {
        const want = asked orelse return self.fail(rw, req, error.UpgradeMismatch, 502);
        const got = (if (connectionLists(res.head.iterate(), "upgrade")) res.header("upgrade") else null) orelse
            return self.fail(rw, req, error.UpgradeMismatch, 502);
        if (!std.ascii.eqlIgnoreCase(got, want)) return self.fail(rw, req, error.UpgradeMismatch, 502);

        const via = buildVia(via_buf, res.header("via"), self.config.via_pseudonym) catch
            return self.relayFailed(rw, req);
        rw.setHeader("Via", via) catch return self.relayFailed(rw, req);
        if (self.config.modify_response) |hook| {
            // A 101 has no body; the hook edits the head only.
            var none: std.Io.Reader = .fixed("");
            var presp: ProxyResponse = .{ .in = req, .status = 101, .rw = rw, .body = &none };
            hook.func(hook.ctx, &presp) catch |e| return self.fail(rw, req, e, 502);
        }
        rw.upgrade(got) catch |e| return self.fail(rw, req, e, 502);
        // `upgradeRequested` checked both ends can be handed over.
        const front = req.upgraded(rw).?;
        const back = res.upgraded().?;
        splice(self.config.client.io, front, back);
    }

    /// The shared tail of both forward paths, once the backend's headers are
    /// on `rw`: response-side `Via`, the `ModifyResponse` hook, the body.
    fn finishResponse(
        self: *ProxyHandler,
        rw: *Server.ResponseWriter,
        req: *Server.Request,
        status: u16,
        backend_via: ?[]const u8,
        body: *std.Io.Reader,
        via_buf: []u8,
    ) anyerror!void {
        // Response-side Via (append to the backend's own, if any).
        const via = buildVia(via_buf, backend_via, self.config.via_pseudonym) catch
            return self.relayFailed(rw, req);
        rw.setHeader("Via", via) catch return self.relayFailed(rw, req);

        var presp: ProxyResponse = .{ .in = req, .status = status, .rw = rw, .body = body };
        if (self.config.modify_response) |hook| {
            hook.func(hook.ctx, &presp) catch |e| return self.fail(rw, req, e, 502);
            rw.setStatus(presp.status);
        }

        // ── stream the response body back (no full buffering) ───────────
        const flush_each = switch (self.config.flush) {
            .immediate => true,
            .auto => rw.declared_len == null or isEventStream(rw.getHeader("content-type")),
        };
        relayBody(presp.body, rw, flush_each) catch {
            // Head may already be on the wire (large body outgrew the
            // buffer) — then the only honest move is to close the
            // connection; the serving loop does that when we return an
            // error. If nothing was sent yet, a 502 still fits.
            if (rw.headSent()) return error.ProxyBackendStreamAborted;
            return self.fail(rw, req, error.ResponseNotRelayable, 502);
        };
        // No early `end()`. It used to be forced here so `writeHead` read the
        // relayed header slices before the deferred `res.deinit()` freed the
        // backend head buffer they pointed into; `setHeader` copies those
        // bytes now, and the body is likewise in the writer's own buffer or
        // already framed onto the wire. The serving loop ends the response.
    }

    /// Forward to an HTTP/2 (h2/h2c) backend through the shared
    /// `h2_upstream.Pool`: translate the request into a stream on the
    /// backend's one multiplexed connection, collect the response, relay it
    /// back. Header translation and the hooks are shared with the h1 path;
    /// the h2 body is buffered (bounded — see `Config.h2_max_body_bytes`).
    fn forwardH2(self: *ProxyHandler, pr: *ProxyRequest, rw: *Server.ResponseWriter) anyerror!void {
        const req = pr.in;
        const pool = self.config.h2_upstream orelse return self.fail(rw, req, error.NoH2Upstream, 502);
        const gpa = self.config.client.gpa;
        const backend = pr.backend;

        // `:authority` — a `Host` line in the outbound set (the client's,
        // kept by `rewrite_host = false`, or a hook's), else the backend
        // authority. Not sent as a field as well.
        var auth_buf: [max_authority_len]u8 = undefined;
        const authority = pr.headers.get("host") orelse
            (buildAuthority(&auth_buf, backend) catch return self.fail(rw, req, error.BadOutboundRequest, 502));
        pr.headers.del("host");
        // HTTP/2 has no Upgrade (RFC 9113 §8.6): an upgrade request goes on
        // as a plain one.
        pr.headers.del("connection");
        pr.headers.del("upgrade");

        // Origin-form target: the raw inbound target unless a hook rewrote it.
        var target_buf: [max_url_len]u8 = undefined;
        const target = if (self.config.rewrite == null)
            (if (req.target.len == 0) "/" else req.target)
        else
            buildTarget(&target_buf, pr.path, pr.query) catch return self.fail(rw, req, error.BadOutboundRequest, 502);

        // Read the request body into memory (bounded); the h2 client streams
        // it out under §5.2 flow control (WINDOW_UPDATE past the window).
        const has_body = req.head.chunked or (req.head.content_length orelse 0) != 0;
        var body_buf: ?[]u8 = null;
        defer if (body_buf) |b| gpa.free(b);
        if (has_body) {
            body_buf = req.reader().allocRemaining(gpa, .limited(self.config.h2_max_body_bytes)) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Over the cap or a read failure — nothing is on the wire yet.
                else => return self.fail(rw, req, error.RequestBodyFailed, 502),
            };
        }

        const be: h2_upstream.Backend = .{
            .host = backend.host,
            .port = backend.port,
            .secure = backend.protocol == .h2,
        };
        var res = pool.roundtrip(be, .{
            .method = req.method,
            .method_token = if (req.method == .other) req.methodName() else "",
            .path = target,
            .authority = authority,
            .scheme = if (backend.protocol == .h2) "https" else "http",
            .headers = pr.headers.slice(),
            .body = body_buf,
        }) catch |err| return self.onH2Error(rw, req, err);
        defer res.deinit(gpa);

        // ── relay status + response headers ─────────────────────────────
        rw.setStatus(res.status);
        for (res.headers.fields, 0..) |f, at| {
            if (f.name.len != 0 and f.name[0] == ':') continue; // pseudo-headers (:status)
            if (isHopByHop(f.name, null) or connectionLists(FieldIter{ .fields = res.headers.fields }, f.name)) continue;
            if (std.ascii.eqlIgnoreCase(f.name, "connection") or
                std.ascii.eqlIgnoreCase(f.name, "via")) continue;
            relayField(rw, FieldIter{ .fields = res.headers.fields }, at, f.name, f.value) catch return self.relayFailed(rw, req);
        }
        // The (buffered) body is copied into the writer, so — as on the h1
        // path — the deferred `res.deinit(gpa)` is not racing an `end()`.
        var body: std.Io.Reader = .fixed(res.body);
        var via_buf: [max_via_len]u8 = undefined;
        return self.finishResponse(rw, req, res.status, res.header("via"), &body, &via_buf);
    }

    /// Map an `h2_upstream` forward error to a gateway status (or surface a
    /// genuine OOM as the server's 500).
    fn onH2Error(self: *ProxyHandler, rw: *Server.ResponseWriter, req: *Server.Request, err: anyerror) anyerror!void {
        if (err == error.OutOfMemory) return err;
        const status: u16 = switch (err) {
            error.Timeout => 504, // Gateway Timeout
            else => 502, // Bad Gateway (dial/protocol/reset/goaway/…)
        };
        return self.fail(rw, req, err, status);
    }

    fn pickBackend(self: *ProxyHandler, req: *Server.Request) ?Backend {
        if (self.config.selector) |sel| return sel.select(req);
        return self.config.backend;
    }

    /// Every failure before the response head is on the wire ends here: the
    /// half-built response is discarded and `error_handler` (or the default
    /// gateway page) answers.
    fn fail(self: *ProxyHandler, rw: *Server.ResponseWriter, req: *Server.Request, err: anyerror, status: u16) anyerror!void {
        if (rw.headSent()) return error.ProxyBackendStreamAborted;
        // `headSent` was checked on the line above, so the error path is
        // unreachable here — `try` rather than an assert so it stays that
        // way in ReleaseFast.
        try rw.reset();
        if (self.config.error_handler) |hook| return hook.func(hook.ctx, rw, req, .{ .err = err, .status = status });
        if (err == error.ResponseNotRelayable)
            return gatewayErrorReason(rw, status, self.config.via_pseudonym, "Bad Gateway: backend response headers could not be relayed\n");
        return gatewayError(rw, status, self.config.via_pseudonym);
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
    /// been relayed), so `fail` discards the half-relayed set and the 502
    /// goes out clean, carrying `Via` so the failing hop is identifiable.
    fn relayFailed(self: *ProxyHandler, rw: *Server.ResponseWriter, req: *Server.Request) anyerror!void {
        return self.fail(rw, req, error.ResponseNotRelayable, 502);
    }

    /// Map a `Client` error to a gateway status, or surface a genuine
    /// out-of-memory as a plain error (→ the server's 500).
    fn onBackendError(self: *ProxyHandler, rw: *Server.ResponseWriter, req: *Server.Request, err: Client.Error) anyerror!void {
        if (err == error.OutOfMemory) return err;
        return self.fail(rw, req, err, statusForBackendError(err));
    }

    /// Assemble the forwarded header set: pass-through end-to-end headers,
    /// drop hop-by-hop + client-managed framing, add the forwarding headers
    /// (Go's `Director` shape; with a `Rewrite` hook, Go's `Rewrite` shape —
    /// see `Config.rewrite`). `Via` is added by the caller, after the hook.
    fn buildRequestHeaders(self: *ProxyHandler, pr: *ProxyRequest) error{TooManyHeaders}!void {
        const req = pr.in;
        const h = &pr.headers;
        const rewriting = self.config.rewrite != null;
        var it = req.head.iterate();
        while (it.next()) |entry| {
            const name = entry.name;
            // Host is set below (rewrite) or preserved explicitly; framing
            // headers are the client's job.
            if (std.ascii.eqlIgnoreCase(name, "host")) continue;
            if (std.ascii.eqlIgnoreCase(name, "content-length")) continue;
            if (std.ascii.eqlIgnoreCase(name, "via")) continue; // re-injected after the hook
            // Folded into the one chain built below, every line of it.
            if (std.ascii.eqlIgnoreCase(name, "x-forwarded-for")) continue;
            // Set below (or by the hook): a client's own claim must not ride
            // in front of ours — a backend reading the first line would take
            // `X-Forwarded-Proto: https` from a plain-HTTP client.
            if (std.ascii.eqlIgnoreCase(name, "x-forwarded-host") or
                std.ascii.eqlIgnoreCase(name, "x-forwarded-proto")) continue;
            if (isHopByHop(name, null) or connectionLists(req.head.iterate(), name)) continue;
            // Go's `Rewrite`: the client's `Forwarded` does not pass either.
            if (rewriting and std.ascii.eqlIgnoreCase(name, "forwarded")) continue;
            try h.add(entry.name, entry.value);
        }

        // Host: preserve the client's when not rewriting (rewrite = let the
        // client default it to the backend authority, so nothing is added).
        if (!self.config.rewrite_host) {
            if (req.header("host")) |host| try h.add("Host", host);
        }
        if (rewriting) return;
        // X-Forwarded-For: append this hop's socket peer.
        if (buildForwardedFor(pr.xff_buf, req)) |xff| try h.add("X-Forwarded-For", xff);
        try h.add("X-Forwarded-Proto", self.config.forwarded_proto);
        // X-Forwarded-Host: the original Host the client asked for.
        if (req.header("host")) |host| try h.add("X-Forwarded-Host", host);
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

/// Copy a backend body into `rw`; with `flush_each`, push every read to the
/// client at once (an event must not wait for the next one to fill a
/// buffer).
fn relayBody(r: *std.Io.Reader, rw: *Server.ResponseWriter, flush_each: bool) !void {
    if (!flush_each) {
        _ = try r.streamRemaining(rw.writer());
        return;
    }
    while (true) {
        _ = r.stream(rw.writer(), .unlimited) catch |e| switch (e) {
            error.EndOfStream => return,
            else => |x| return x,
        };
        try rw.flush();
    }
}

/// Whether a response `Content-Type` is Server-Sent Events, as Go's
/// `flushInterval` reads it (`mime.ParseMediaType`'s type).
fn isEventStream(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.ascii.eqlIgnoreCase(http.body.checkMediaType(ct).media_type, "text/event-stream");
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
    var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
    const ip_text = peerText(req, &ip_buf) orelse return null;

    // The existing chain is every `X-Forwarded-For` line, in order (RFC 9110
    // §5.3: repeated lines are one comma-separated list) — unless the client
    // named the field in `Connection`, which makes its value this hop's only.
    var w: std.Io.Writer = .fixed(buf);
    if (!connectionLists(req.head.iterate(), "x-forwarded-for")) {
        var it = req.head.iterate();
        while (it.next()) |e| {
            if (!std.ascii.eqlIgnoreCase(e.name, "x-forwarded-for")) continue;
            w.print("{s}, ", .{e.value}) catch return ip_shortcut(buf, ip_text);
        }
    }
    w.writeAll(ip_text) catch return ip_shortcut(buf, ip_text);
    return w.buffered();
}

/// The socket peer's address as text (IPv4-mapped IPv6 unmapped), or null
/// when serving socket-free.
fn peerText(req: *Server.Request, buf: *[netaddr.max_ip_text_len]u8) ?[]const u8 {
    const peer = req.peerAddress() orelse return null;
    const ip: netaddr.Ip = switch (peer) {
        .ip4 => |a| .{ .v4 = a.bytes },
        .ip6 => |a| .{ .v6 = a.bytes },
    };
    return netaddr.formatIp(ip.unmap(), buf);
}

/// The protocol `req` asks to switch to, when this proxy can carry the
/// switch: `Connection` lists `upgrade`, `Upgrade` names one protocol
/// (`name[/version]`, both tokens — a list could never match the backend's
/// single answer), and the request is an HTTP/1.1 one without a body served
/// over a socket (`ResponseWriter.upgrade` and `Request.upgraded` can hand
/// the connection over). Otherwise null, and the two fields are dropped as
/// hop-by-hop.
fn upgradeRequested(req: *Server.Request, rw: *const Server.ResponseWriter) ?[]const u8 {
    if (!rw.upgradable or rw.upgrade_in == null or req.control == null) return null;
    if (!connectionLists(req.head.iterate(), "upgrade")) return null;
    const protocol = req.header("upgrade") orelse return null;
    const slash = std.mem.findScalar(u8, protocol, '/');
    if (!h1.isToken(protocol[0 .. slash orelse protocol.len])) return null;
    if (slash) |i| if (!h1.isToken(protocol[i + 1 ..])) return null;
    return protocol;
}

/// Copy bytes both ways between an upgraded client connection and an
/// upgraded backend connection until either direction ends, then shut both
/// down (Go: the first copier to finish ends the exchange). The client to
/// backend direction runs in a task of its own.
fn splice(io: std.Io, front: Server.Upgraded, back: Client.Upgraded) void {
    var group: std.Io.Group = .init;
    group.concurrent(io, pipeToBackend, .{ front, back }) catch {
        front.shutdown();
        back.shutdown();
        return;
    };
    pipeToClient(front, back);
    group.await(io) catch {};
}

fn pipeToBackend(front: Server.Upgraded, back: Client.Upgraded) void {
    defer endSplice(front, back);
    while (true) {
        _ = front.reader.stream(back.writer(), .unlimited) catch return;
        back.flush() catch return;
    }
}

fn pipeToClient(front: Server.Upgraded, back: Client.Upgraded) void {
    defer endSplice(front, back);
    while (true) {
        _ = back.reader().stream(front.writer, .unlimited) catch return;
        front.writer.flush() catch return;
    }
}

fn endSplice(front: Server.Upgraded, back: Client.Upgraded) void {
    front.shutdown();
    back.shutdown();
}

/// Whether a (rewritten) path and query can go on a request line as
/// origin-form: the path starts with `/`, and neither holds a control octet,
/// SP, DEL or `#` — anything else would split the request line or be cut
/// off as a fragment.
fn originForm(path: []const u8, query: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    for ([_][]const u8{ path, query }) |part| for (part) |c| {
        if (c <= 0x20 or c == 0x7f or c == '#') return false;
    };
    return true;
}

/// `path` + `?query` (when non-empty) into `buf`.
fn buildTarget(buf: []u8, path: []const u8, query: []const u8) error{Overflow}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(path) catch return error.Overflow;
    if (query.len != 0) w.print("?{s}", .{query}) catch return error.Overflow;
    return w.buffered();
}

/// Whether any `Connection` field line in `fields` (an iterator yielding
/// `.name`/`.value`) lists `name` (RFC 9110 §7.6.1). Every line counts:
/// `Connection: a` + `Connection: b` is the one list `a, b` (§5.3).
fn connectionLists(fields: anytype, name: []const u8) bool {
    var it = fields;
    while (it.next()) |e| {
        if (std.ascii.eqlIgnoreCase(e.name, "connection") and h1.tokenListContains(e.value, name)) return true;
    }
    return false;
}

/// Put an h1 backend response's end-to-end fields on `rw`: hop-by-hop ones
/// (the fixed set, `Proxy-*`, every field a `Connection` line names) and
/// `Via` (re-built by the caller) dropped, repeated ones relayed whole.
/// `Transfer-Encoding` is hop-by-hop; `Content-Length` is copied so `rw`
/// re-frames identity with the exact length. The writer manages
/// `Connection`/`Date`/`Server` itself.
fn relayHead(rw: *Server.ResponseWriter, head: h1.ResponseHead) !void {
    var it = head.iterate();
    var at: usize = 0;
    while (it.next()) |entry| : (at += 1) {
        if (isHopByHop(entry.name, null) or connectionLists(head.iterate(), entry.name)) continue;
        if (std.ascii.eqlIgnoreCase(entry.name, "via")) continue;
        try relayField(rw, head.iterate(), at, entry.name, entry.value);
    }
}

/// `connectionLists`/`relayField` over an h2 response's field slice.
const FieldIter = struct {
    fields: []const hpack.Field,
    i: usize = 0,

    fn next(it: *FieldIter) ?hpack.Field {
        if (it.i == it.fields.len) return null;
        defer it.i += 1;
        return it.fields[it.i];
    }
};

/// Relay one backend response field, the `at`-th of `fields`, keeping every
/// line: `Set-Cookie` lines each stay a line of their own (RFC 6265 §3; they
/// cannot be joined); any other repeated field is sent once, at its first
/// line, as the comma-joined list of all of them (RFC 9110 §5.3) —
/// `setHeader` replaces by name, so relaying line by line kept only the last.
fn relayField(rw: *Server.ResponseWriter, fields: anytype, at: usize, name: []const u8, value: []const u8) !void {
    if (std.ascii.eqlIgnoreCase(name, "set-cookie")) return rw.addSetCookie(value);
    var joined: [max_joined_field_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&joined);
    var it = fields;
    var i: usize = 0;
    var count: usize = 0;
    while (it.next()) |e| : (i += 1) {
        if (!std.ascii.eqlIgnoreCase(e.name, name)) continue;
        if (i < at) return; // not the first line: already sent, joined
        try w.writeAll(if (count == 0) "" else ", ");
        try w.writeAll(e.value);
        count += 1;
    }
    try rw.setHeader(name, if (count <= 1) value else w.buffered());
}

/// Longest comma-joined value `relayField` builds from repeated lines; a
/// longer one fails the relay (502), as a header too big for the writer does.
const max_joined_field_len = 8 * 1024;

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
    if (std.mem.findScalar(u8, backend.host, ':') != null) {
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
    if (std.mem.findScalar(u8, backend.host, ':') != null) {
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
        try rw.setHeader("X-Saw-Method", req.methodName());
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
        return testkit.loopbackSkip("origin bind failed ({t})", .{err});
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
        return testkit.loopbackSkip("proxy bind failed ({t})", .{err});
    };
    const proxy_thread = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer proxy_thread.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // Forwarding + header injection + hop-by-hop stripping.
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/reflect", .{proxy_port});
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
        try testing.expect(std.mem.find(u8, res.header("x-saw-via").?, "1.1 zig-libs") != null);
        try testing.expectEqualStrings("kept", res.header("x-saw-keep").?);
        // Host rewritten to the backend authority (default rewrite_host).
        var host_buf: [32]u8 = undefined;
        const want_host = try std.mem.print(&host_buf, "127.0.0.1:{d}", .{origin_port});
        try testing.expectEqualStrings(want_host, res.header("x-saw-reqhost").?);
        // Hop-by-hop request headers were stripped before the origin.
        try testing.expectEqualStrings("none", res.header("x-saw-upgrade").?);
        try testing.expectEqualStrings("none", res.header("x-saw-proxyauth").?);
        // The origin's hop-by-hop response header (Keep-Alive) was stripped
        // by the proxy and never reached the client.
        try testing.expectEqual(@as(?[]const u8, null), res.header("keep-alive"));
        // The proxy injected a response-side Via too.
        try testing.expect(std.mem.find(u8, res.header("via").?, "1.1 zig-libs") != null);
    }

    { // Streaming request + response body (large, outgrows every buffer).
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/echo", .{proxy_port});
        const payload = strRepeat("STREAM", 20_000); // 120 KB
        var res = try client.request(.post, url, .{ .body = payload });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, payload.len + 16);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(payload, body);
    }

    { // An extension method is relayed as its token, body and all (Go).
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/echo", .{proxy_port});
        for ([_]?[]const u8{ "<propfind/>", null }) |payload| {
            var res = try client.request(.other, url, .{ .method_token = "PROPFIND", .body = payload });
            defer res.deinit();
            try testing.expectEqual(@as(u16, 200), res.status);
            try testing.expectEqualStrings("PROPFIND", res.header("x-saw-method").?);
            const body = try res.readAllAlloc(testing.allocator, 64);
            defer testing.allocator.free(body);
            try testing.expectEqualStrings(payload orelse "", body);
        }
    }

    { // CONNECT asks a reverse proxy for a tunnel: 501, nothing dialed.
        const addr = try net.IpAddress.parse("127.0.0.1", proxy_port);
        const s = try addr.connect(io, .{ .mode = .stream });
        defer s.close(io);
        var wbuf: [128]u8 = undefined;
        var sw = s.writer(io, &wbuf);
        try sw.interface.writeAll("CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n");
        try sw.interface.flush();
        var rbuf: [1024]u8 = undefined;
        var sr = s.reader(io, &rbuf);
        const line = try sr.interface.takeDelimiterExclusive('\n');
        try testing.expectEqualStrings("HTTP/1.1 501 Not Implemented\r", line);
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
        dead_proxy.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        const dt = try std.Thread.spawn(.{}, serveWrap, .{&dead_proxy});
        defer dt.join();
        defer dead_proxy.shutdown();
        const dp = dead_proxy.boundAddress().getPort();

        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/anything", .{dp});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 502), res.status);
        try testing.expect(std.mem.find(u8, res.header("via").?, "zig-libs") != null);
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
        return testkit.loopbackSkip("fat-header origin listen failed ({t})", .{err});
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
    proxy.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    const proxy_thread = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer proxy_thread.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/", .{proxy_port});

    const over_bytes = Relayed.get(&client, url);
    const over_count = Relayed.get(&client, url);
    const fits = Relayed.get(&client, url);

    // The item this pins: a backend header that will not fit is NOT dropped
    // behind the client's back. The old `catch {}` produced a 200 that looked
    // perfectly normal and was missing `X-Fat-005` onward.
    try testing.expectEqual(@as(u16, 502), over_bytes.status);
    try testing.expect(std.mem.find(u8, over_bytes.body(), "could not be relayed") != null);
    // Not even the fields that DID fit before the budget ran out ride along
    // on the 502 — `reset` drops the half-relayed set.
    try testing.expectEqual(@as(?usize, null), over_bytes.fat_first);
    try testing.expectEqual(@as(?usize, null), over_bytes.fat_last);
    // …and the hop that failed names itself.
    try testing.expect(std.mem.find(u8, over_bytes.via(), "zig-libs") != null);

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

// ── integration: a streaming response reaches the client as it is produced ──

/// An origin that answers each request with a chunked body in two halves and
/// holds the second back until the client behind the proxy has the first —
/// or until `wait_ms` runs out, which it records as "the first half was
/// stuck in the proxy". Faked at the socket level so the origin itself
/// flushes each half for certain.
const StreamingOrigin = struct {
    io: std.Io,
    listener: *net.Server,
    /// One response `Content-Type` per request, in order.
    content_types: []const []const u8,
    /// Set by the client once it has read the first half.
    got_first: std.atomic.Value(bool) = .init(false),
    /// Per request: did the client see the first half before the origin
    /// sent the second?
    in_time: [4]bool = @splat(false),
    const wait_ms = 2000;

    fn run(o: *StreamingOrigin) void {
        for (o.content_types, 0..) |ct, i| {
            const s = o.listener.accept(o.io) catch return;
            defer s.close(o.io);
            var rbuf: [4096]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var sr = s.reader(o.io, &rbuf);
            var sw = s.writer(o.io, &wbuf);
            var head_buf: [4096]u8 = undefined;
            _ = h1.readHead(&sr.interface, &head_buf) catch return;
            const w = &sw.interface;
            o.got_first.store(false, .release);
            w.print("HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
                "b\r\ndata: one\n\n\r\n", .{ct}) catch return;
            w.flush() catch return;
            var waited: usize = 0;
            while (!o.got_first.load(.acquire) and waited < wait_ms) : (waited += 5)
                o.io.sleep(.fromMilliseconds(5), .awake) catch return;
            o.in_time[i] = o.got_first.load(.acquire);
            w.writeAll("b\r\ndata: two\n\n\r\n0\r\n\r\n") catch return;
            w.flush() catch return;
        }
    }
};

/// One request through the proxy, signalling the origin once the first half
/// is in. Never fails the test itself (see `Relayed`): the origin thread
/// must always get its requests.
fn readStreamed(client: *Client, url: []const u8, origin: *StreamingOrigin, out: []u8) []const u8 {
    var res = client.request(.get, url, .{}) catch return "";
    defer res.deinit();
    // One `stream` per read: `readSliceShort` waits for a full buffer.
    var w: std.Io.Writer = .fixed(out);
    const r = res.reader();
    while (true) {
        _ = r.stream(&w, .unlimited) catch break;
        if (std.mem.find(u8, w.buffered(), "data: one\n\n") != null) origin.got_first.store(true, .release);
    }
    return w.buffered();
}

test "integration: a streaming response (SSE, or no declared length) is flushed through as it arrives" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("origin listen failed ({t})", .{err});
    defer listener.deinit(io);
    var origin: StreamingOrigin = .{
        .io = io,
        .listener = &listener,
        // Go's `flushInterval`: SSE by media type, anything of unknown length.
        .content_types = &.{ "text/event-stream; charset=utf-8", "application/x-ndjson" },
    };
    const origin_thread = try std.Thread.spawn(.{}, StreamingOrigin.run, .{&origin});
    defer origin_thread.join();

    var proxy_client = Client.init(io, testing.allocator, .{});
    defer proxy_client.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = listener.socket.address.getPort() },
    });
    var proxy = Server.init(io, testing.allocator, .{ .handler = ProxyHandler.handler, .context = &ph });
    defer proxy.deinit();
    proxy.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    const proxy_thread = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer proxy_thread.join();
    defer proxy.shutdown();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/", .{proxy.boundAddress().getPort()});
    var bufs: [2][64]u8 = undefined;
    const sse = readStreamed(&client, url, &origin, &bufs[0]);
    const ndjson = readStreamed(&client, url, &origin, &bufs[1]);

    try testing.expectEqualStrings("data: one\n\ndata: two\n\n", sse);
    try testing.expectEqualStrings("data: one\n\ndata: two\n\n", ndjson);
    try testing.expect(origin.in_time[0]);
    try testing.expect(origin.in_time[1]);
}

// ── integration: an upgrade (WebSocket-style) passes through ───────────────

/// A backend that switches to a toy `echo` protocol — or, on `/mismatch`, to
/// one nobody asked for — and echoes until the peer closes. Records the
/// request head it saw.
const EchoBackend = struct {
    io: std.Io,
    listener: *net.Server,
    n: usize,
    saw_upgrade: [2]bool = @splat(false),
    accepted: std.atomic.Value(usize) = .init(0),

    fn run(b: *EchoBackend) void {
        for (0..b.n) |i| b.one(i) catch {};
    }

    /// Dial whatever connections the test did not get to, so a failed
    /// assertion fails the test instead of hanging its `join`.
    fn release(b: *EchoBackend) void {
        const port = b.listener.socket.address.getPort();
        for (b.accepted.load(.acquire)..b.n) |_| {
            const addr = net.IpAddress.parse("127.0.0.1", port) catch return;
            const s = addr.connect(b.io, .{ .mode = .stream }) catch return;
            s.close(b.io);
        }
    }

    fn one(b: *EchoBackend, i: usize) !void {
        const s = try b.listener.accept(b.io);
        _ = b.accepted.fetchAdd(1, .release);
        defer s.close(b.io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s.reader(b.io, &rbuf);
        var sw = s.writer(b.io, &wbuf);
        var head_buf: [2048]u8 = undefined;
        const block = try h1.readHead(&sr.interface, &head_buf);
        const head = try h1.RequestHead.parse(block);
        b.saw_upgrade[i] = std.ascii.eqlIgnoreCase(head.header("upgrade") orelse "", "echo") and
            h1.tokenListContains(head.header("connection") orelse "", "upgrade");
        const w = &sw.interface;
        if (std.mem.startsWith(u8, block, "GET /mismatch")) {
            try w.writeAll("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n");
            return w.flush();
        }
        try w.writeAll("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\nX-Up: 1\r\nKeep-Alive: timeout=1\r\n\r\n");
        try w.flush();
        while (true) {
            _ = sr.interface.stream(w, .unlimited) catch return;
            try w.flush();
        }
    }
};

test "integration: an upgrade passes through — 101 relayed, bytes both ways, idle past the read timeout, ends when a side closes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("echo backend listen failed ({t})", .{err});
    defer listener.deinit(io);
    var backend: EchoBackend = .{ .io = io, .listener = &listener, .n = 2 };
    const backend_thread = try std.Thread.spawn(.{}, EchoBackend.run, .{&backend});
    defer backend_thread.join();
    defer backend.release();

    var proxy_client = Client.init(io, testing.allocator, .{});
    defer proxy_client.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = listener.socket.address.getPort() },
    });
    // A short per-read stall timeout: the upgraded connection must outlive it.
    var proxy = Server.init(io, testing.allocator, .{ .handler = ProxyHandler.handler, .context = &ph, .read_timeout_ms = 200 });
    defer proxy.deinit();
    proxy.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    const proxy_thread = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer proxy_thread.join();
    defer proxy.shutdown();
    const front = try net.IpAddress.parse("127.0.0.1", proxy.boundAddress().getPort());

    { // The switch, and an echo both ways.
        const s = try front.connect(io, .{ .mode = .stream });
        defer s.close(io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var sr = s.reader(io, &rbuf);
        var sw = s.writer(io, &wbuf);
        // "hello" rides right behind the request head.
        try sw.interface.writeAll("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nhello");
        try sw.interface.flush();
        var head_buf: [1024]u8 = undefined;
        const head = try h1.readHead(&sr.interface, &head_buf);
        try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 101 "));
        const parsed = try h1.ResponseHead.parse(head);
        try testing.expectEqualStrings("echo", parsed.header("upgrade").?);
        try testing.expect(h1.tokenListContains(parsed.header("connection").?, "upgrade"));
        try testing.expectEqualStrings("1", parsed.header("x-up").?); // end-to-end field relayed
        try testing.expectEqual(@as(?[]const u8, null), parsed.header("keep-alive")); // hop-by-hop dropped
        try testing.expect(std.mem.find(u8, parsed.header("via").?, "zig-libs") != null);
        var got: [5]u8 = undefined;
        try sr.interface.readSliceAll(&got);
        try testing.expectEqualStrings("hello", &got);
        // Idle for twice the proxy's read timeout: HTTP timeouts no longer apply.
        try io.sleep(.fromMilliseconds(400), .awake);
        try sw.interface.writeAll("world");
        try sw.interface.flush();
        try sr.interface.readSliceAll(&got);
        try testing.expectEqualStrings("world", &got);
        // Our half-close reaches the backend, which closes; so does the proxy.
        try s.shutdown(io, .send);
        try testing.expectError(error.EndOfStream, sr.interface.takeByte());
    }
    { // The backend switches to a protocol nobody asked for: 502.
        var client = Client.init(io, testing.allocator, .{});
        defer client.deinit();
        var url_buf: [64]u8 = undefined;
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/mismatch", .{proxy.boundAddress().getPort()});
        var res = try client.request(.get, url, .{ .headers = &.{
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Upgrade", .value = "echo" },
        } });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 502), res.status);
    }
    try testing.expect(backend.saw_upgrade[0]);
    try testing.expect(backend.saw_upgrade[1]);
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
        const url = std.mem.print(&url_buf, "http://127.0.0.1:{d}/reflect", .{w.port}) catch return;
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
        return testkit.loopbackSkip("h2 backend bind failed ({t})", .{err});
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
        return testkit.loopbackSkip("proxy bind failed ({t})", .{err});
    };
    const pt = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer pt.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // GET /reflect: forwarding headers injected, hop-by-hop stripped — over h2.
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/reflect", .{proxy_port});
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
        try testing.expect(std.mem.find(u8, res.header("x-saw-via").?, "1.1 zig-libs") != null);
        try testing.expectEqualStrings("kept", res.header("x-saw-keep").?);
        // Hop-by-hop request header stripped before the backend.
        try testing.expectEqualStrings("none", res.header("x-saw-proxyauth").?);
        // Response-side Via injected; backend's hop-by-hop Keep-Alive stripped.
        try testing.expect(std.mem.find(u8, res.header("via").?, "1.1 zig-libs") != null);
        try testing.expectEqual(@as(?[]const u8, null), res.header("keep-alive"));
    }

    { // POST /echo, large body → exercises h2 send-side flow control.
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/echo", .{proxy_port});
        const payload = strRepeat("H2PROXY", 20_000); // ~140 KB, past the 64 KiB window
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

/// h2c backend for the `relayFailed` test below: answers with `count`
/// response headers of `value_len` bytes each, both taken from the request
/// path (`/fat/{count}/{value_len}`).
///
/// Unlike the h1 side, this is a REAL `http.Server` rather than a socket-level
/// fake. `FatHeaderOrigin` had to be a fake because an `http.Server` cannot
/// overrun the byte budget under test — but it can overrun the FIELD COUNT
/// one, because the proxy's table is strictly larger than the backend's: the
/// backend's `Date`/`Server`/`Content-Length` are managed fields that never
/// occupy a slot in ITS table, yet arrive at the proxy as ordinary response
/// headers that do occupy one — and the proxy adds its own `Via` on top. So a
/// backend answering with a table it can just hold produces one the proxy
/// cannot, and that is the door into the h2 arm of `relayFailed`.
fn fatH2OriginHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    var it = std.mem.tokenizeScalar(u8, req.path, '/');
    _ = it.next(); // "fat"
    const count = try std.fmt.parseInt(usize, it.next() orelse "0", 10);
    const value_len = try std.fmt.parseInt(usize, it.next() orelse "0", 10);
    var value: [256]u8 = undefined;
    @memset(&value, 'v');
    var name_buf: [16]u8 = undefined;
    for (0..count) |i| {
        const name = try std.mem.print(&name_buf, "X-Fat-{d:0>3}", .{i});
        try rw.setHeader(name, value[0..value_len]);
    }
    try rw.writeAll("ok");
}

test "integration: an h2 backend header set the proxy cannot relay answers 502, not a mutilated 200" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var backend = Server.init(io, gpa, .{ .handler = fatH2OriginHandler, .enable_h2c = true });
    defer backend.deinit();
    backend.bind() catch |err| {
        return testkit.loopbackSkip("h2 fat backend bind failed ({t})", .{err});
    };
    const bt = try std.Thread.spawn(.{}, serveWrap, .{&backend});
    defer bt.join();
    defer backend.shutdown();
    const backend_port = backend.boundAddress().getPort();

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
    proxy.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    const pt = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer pt.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    // 32 fields is exactly what the backend's own table holds; the proxy needs
    // those 32 plus `Via` (plus the backend's now-ordinary `Date`/`Server`),
    // so `max_response_headers` is overrun no matter how those two are handled.
    const over_url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/fat/32/4", .{proxy_port});
    const over_count = Relayed.get(&client, over_url);
    var url_buf2: [64]u8 = undefined;
    const fits_url = try std.mem.print(&url_buf2, "http://127.0.0.1:{d}/fat/8/100", .{proxy_port});
    const fits = Relayed.get(&client, fits_url);

    // The h1 arm of this claim is pinned by the `FatHeaderOrigin` test above.
    // This is the second instance, and it is a separate function body
    // (`forwardH2`) with its own relay loop and its own `relayFailed` calls
    // (`:347`, `:350`, `:351`) — code-identical in shape is not evidence.
    try testing.expectEqual(@as(u16, 502), over_count.status);
    try testing.expect(std.mem.find(u8, over_count.body(), "could not be relayed") != null);
    // `reset` ran on the h2 path too: not even the fields that fit ride along.
    try testing.expectEqual(@as(?usize, null), over_count.fat_first);
    try testing.expectEqual(@as(?usize, null), over_count.fat_last);
    try testing.expect(std.mem.find(u8, over_count.via(), "zig-libs") != null);

    // Control: a fat-but-relayable h2 answer goes through whole, so the 502 is
    // the limit talking and not the h2 scaffold failing for its own reasons.
    try testing.expectEqual(@as(u16, 200), fits.status);
    try testing.expectEqual(@as(?usize, 100), fits.fat_first);
    try testing.expectEqual(@as(?usize, 100), fits.fat_last);
    try testing.expectEqualStrings("ok", fits.body());
}

// ── integration: the h2c → h1 request-smuggling seam (A1 G1) ────────────────

/// A backend that is not an `http.Server` on purpose: it records the raw
/// bytes the proxy puts on its wire — the only place the smuggled second
/// request could be observed — and answers 200 to whatever it got. One
/// accept per entry in `expected`, so the thread can never be left parked
/// in `accept` for a connection the proxy was right not to make.
const RawBackend = struct {
    io: std.Io,
    listener: *net.Server,
    /// Everything received, across all accepted connections, in order.
    buf: [8192]u8 = undefined,
    len: usize = 0,
    accepts: usize,

    fn run(b: *RawBackend) void {
        for (0..b.accepts) |_| {
            const s = b.listener.accept(b.io) catch return;
            defer s.close(b.io);
            var rbuf: [8192]u8 = undefined;
            var wbuf: [256]u8 = undefined;
            var sr = s.reader(b.io, &rbuf);
            var sw = s.writer(b.io, &wbuf);
            const start = b.len;
            while (b.len < b.buf.len) {
                const avail = sr.interface.peekGreedy(1) catch break;
                const take = @min(avail.len, b.buf.len - b.len);
                @memcpy(b.buf[b.len..][0..take], avail[0..take]);
                b.len += take;
                sr.interface.toss(take);
                if (std.mem.find(u8, b.buf[start..b.len], "\r\n\r\n") != null) break;
            }
            sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok") catch {};
            sw.interface.flush() catch {};
        }
    }
};

/// The attacker's side: a bare `h2.Connection` driven over a socket, so the
/// request head can carry bytes `Client.connectH2c` now refuses to frame.
const RawH2Peer = struct {
    gpa: std.mem.Allocator,
    conn: h2.Connection,
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,
    /// Per stream: the reset code, or the `:status`, whichever arrived.
    rst: std.AutoArrayHashMapUnmanaged(u31, h2.ErrorCode) = .empty,
    status: std.AutoArrayHashMapUnmanaged(u31, u16) = .empty,
    ended: std.AutoArrayHashMapUnmanaged(u31, void) = .empty,

    fn deinit(p: *RawH2Peer) void {
        p.ended.deinit(p.gpa);
        p.status.deinit(p.gpa);
        p.rst.deinit(p.gpa);
        p.events.deinit(p.gpa);
        p.wire.deinit(p.gpa);
        p.conn.deinit();
    }

    fn flush(p: *RawH2Peer, w: *std.Io.Writer) !void {
        if (p.wire.items.len == 0) return;
        try w.writeAll(p.wire.items);
        try w.flush();
        p.wire.clearRetainingCapacity();
    }

    fn pump(p: *RawH2Peer, r: *std.Io.Reader) !void {
        _ = try r.peekGreedy(1);
        const bytes = r.buffered();
        try p.conn.recv(bytes, &p.wire, &p.events);
        r.toss(bytes.len);
        for (p.events.items) |*ev| {
            switch (ev.*) {
                .headers => |*hd| {
                    for (hd.headers.fields) |f| {
                        if (std.mem.eql(u8, f.name, ":status"))
                            try p.status.put(p.gpa, hd.stream_id, std.fmt.parseInt(u16, f.value, 10) catch 0);
                    }
                    if (hd.end_stream) try p.ended.put(p.gpa, hd.stream_id, {});
                },
                .data => |d| if (d.end_stream) try p.ended.put(p.gpa, d.stream_id, {}),
                .stream_reset => |rs| {
                    try p.rst.put(p.gpa, rs.stream_id, rs.code);
                    try p.ended.put(p.gpa, rs.stream_id, {});
                },
                else => {},
            }
            ev.deinit(p.gpa);
        }
        p.events.clearRetainingCapacity();
    }
};

test "integration: an h2c :path/:authority carrying CR/LF or SP never becomes a second request on the h1 backend's wire (A1 G1)" {
    // Measured 2026-09-04 (`A1/repro/http/client/probe3.zig`): with
    // `enable_h2c`, a `:path` of
    // `/a\r\nX-Path-Injected: yes\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n`
    // reached the backend as exactly that — a complete second request —
    // and the unauthenticated h2c client got 200 for it. Three guards were
    // missing (h2 §8.2.1 field validity, the h2 `:path` guard, and the
    // client's own line discipline); this test stands on the composition,
    // at the one place the attack is observable: the backend's wire.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("raw backend listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    // Exactly ONE backend connection is expected: the control request. If a
    // malformed request were forwarded the count would be higher — and the
    // extra bytes would be in `backend.buf` — so the backend accepts once
    // and the assertions below read what that one connection carried.
    var backend: RawBackend = .{ .io = io, .listener = &listener, .accepts = 1 };
    const backend_port = listener.socket.address.getPort();
    const bt = try std.Thread.spawn(.{}, RawBackend.run, .{&backend});

    var proxy_client = Client.init(io, gpa, .{ .pool = .{ .enabled = false } });
    defer proxy_client.deinit();
    var ph = ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = backend_port },
    });
    var proxy = Server.init(io, gpa, .{
        .handler = ProxyHandler.handler,
        .context = &ph,
        .enable_h2c = true,
    });
    defer proxy.deinit();
    proxy.bind() catch |err| {
        bt.join();
        return testkit.loopbackSkip("proxy bind failed ({t})", .{err});
    };
    const pt = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer pt.join();
    defer proxy.shutdown();

    const stream = proxy.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        bt.join();
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    defer stream.close(io);
    var rbuf: [8192]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var peer: RawH2Peer = .{ .gpa = gpa, .conn = .init(gpa, .client, .{}) };
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const smuggle = "/a\r\nX-Path-Injected: yes\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
    const attacks = [_][2][]const u8{
        .{ smuggle, "front.example" }, // A: CRLF in :path — the full second request
        .{ "/front", "front.example\r\nX-Authority-Injected: yes" }, // B: CRLF in :authority
        .{ "/a HTTP/1.1", "front.example" }, // C: SP in :path — request-line confusion
    };
    var attack_sids: [attacks.len]u31 = undefined;
    for (attacks, 0..) |a, i| {
        attack_sids[i] = try peer.conn.startStream(&peer.wire, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = a[0] },
            .{ .name = ":authority", .value = a[1] },
        }, true);
    }
    // Control: the benign neighbour, forwarded and answered normally.
    const sid_control = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/front" },
        .{ .name = ":authority", .value = "front.example" },
    }, true);
    try peer.flush(&sw.interface);

    var all_ended = false;
    while (!all_ended) {
        try peer.pump(&sr.interface);
        try peer.flush(&sw.interface); // SETTINGS ACKs, window updates
        all_ended = peer.ended.contains(sid_control);
        for (attack_sids) |sid| all_ended = all_ended and peer.ended.contains(sid);
    }
    bt.join();

    for (attack_sids) |sid| {
        try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.rst.get(sid));
        try testing.expectEqual(@as(?u16, null), peer.status.get(sid));
    }
    try testing.expectEqual(@as(?u16, 200), peer.status.get(sid_control));

    const seen = backend.buf[0..backend.len];
    try testing.expect(std.mem.startsWith(u8, seen, "GET /front HTTP/1.1\r\n"));
    // One request line on the backend's wire, and none of the injected bytes.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, seen, "HTTP/1.1\r\n"));
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, seen, "GET /admin"));
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, seen, "X-Path-Injected"));
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, seen, "X-Authority-Injected"));
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
    proxy.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    const pt = try std.Thread.spawn(.{}, serveWrap, .{&proxy});
    defer pt.join();
    defer proxy.shutdown();
    const proxy_port = proxy.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/x", .{proxy_port});
    var res = try client.request(.get, url, .{});
    defer res.deinit();
    try testing.expectEqual(@as(u16, 502), res.status);
    try testing.expect(std.mem.find(u8, res.header("via").?, "zig-libs") != null);
}

// ── fuzz: a backend response head through the relay ─────────────────────────
//
// `relayHead` is where a backend's header section becomes ours: hop-by-hop
// stripping over arbitrary `Connection` token lists, repeated fields joined.
// The harness checks the property that matters on top of "no panic": no
// field the backend made hop-by-hop reaches the client.

const seed = testkit.fuzz.seed;
const fz = @import("fuzz_test.zig");
const RelayMark = fz.Marker(enum { rejected, relayed, refused, dropped, joined });

/// Header lines (CRLF-separated, no status line, no final blank line).
const relay_seeds = [_][]const u8{
    seed("Content-Type: text/plain\r\nX-A: 1\r\nX-A: 2"),
    seed("Connection: X-Secret, keep-alive\r\nX-Secret: 1\r\nKeep-Alive: timeout=5"),
    seed("connection: x-a\r\nConnection: X-B\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3"),
    seed("Proxy-Authenticate: Basic\r\nProxy-Foo: x\r\nTE: trailers\r\nUpgrade: h2c"),
    seed("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nVia: 1.1 other"),
    seed("Connection: ,,Content-Type,\r\nContent-Type: text/html\r\nContent-Length: 2"),
    seed("Transfer-Encoding: chunked\r\nTrailer: X-T\r\nX-T: 1"),
    seed("Connection: X-A\r\nX-A: 1\r\nX-a: 2\r\nx-A: 3"),
    seed(many_fields), // more fields than the writer holds: the relay refuses
};

const many_fields = blk: {
    var s: []const u8 = "";
    for (0..40) |i| s = s ++ std.fmt.comptimePrint("X{d}: 1\r\n", .{i});
    break :blk s[0 .. s.len - 2];
};

test "fuzz: relayHead never panics, never relays a hop-by-hop field" {
    try testing.fuzz({}, fuzzRelaySmith, .{ .corpus = &relay_seeds });
}

test "fuzz driver: HTTP_FUZZ (proxy relay)" {
    try fz.fuzz_driver.run(fuzzRelay, .{ .prefix = "HTTP_FUZZ", .name = "http-proxy-relay" });
}

test "fuzz harness: proxy relay, 300 seeds, reaches every outcome" {
    try RelayMark.reach(fuzzRelay, "http-proxy-relay", 300);
}

fn fuzzRelaySmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzRelay, smith, script[0..n]);
}

fn fuzzRelay(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var lines: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &lines, &relay_seeds);
    var raw: [600]u8 = undefined;
    const block = std.mem.print(&raw, "HTTP/1.1 200 OK\r\n{s}\r\n\r\n", .{lines[0..len]}) catch unreachable;
    const head = h1.ResponseHead.parse(block) catch return RelayMark.mark(.rejected);

    var out_buf: [2048]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    relayHead(&rw, head) catch return RelayMark.mark(.refused);
    RelayMark.mark(.relayed);

    // No field the backend made hop-by-hop is on our response.
    var it = head.iterate();
    while (it.next()) |e| {
        const hop = isHopByHop(e.name, null) or connectionLists(head.iterate(), e.name) or
            std.ascii.eqlIgnoreCase(e.name, "via");
        const got = rw.getHeader(e.name);
        if (hop) {
            // Managed names (`Connection`, framing) never read back anyway.
            if (got != null) return error.HopByHopRelayed;
            RelayMark.mark(.dropped);
        }
    }
    // Only `Set-Cookie` may repeat: any other repeated field is one joined line.
    for (rw.headers[0..rw.headers_len], 0..) |a, i| for (rw.headers[0..i]) |b| {
        if (std.ascii.eqlIgnoreCase(a.name, b.name) and !std.ascii.eqlIgnoreCase(a.name, "set-cookie"))
            return error.FieldNotJoined;
    };
    var repeated = false;
    var names = head.iterate();
    while (names.next()) |e| {
        var count: usize = 0;
        var again = head.iterate();
        while (again.next()) |f| count += @intFromBool(std.ascii.eqlIgnoreCase(e.name, f.name));
        if (count > 1 and rw.getHeader(e.name) != null) repeated = true;
    }
    if (repeated) RelayMark.mark(.joined);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
