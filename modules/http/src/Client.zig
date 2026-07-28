// SPDX-License-Identifier: MIT

//! HTTP/1.1 client over TCP + TLS.
//!
//! One `Client` is a lightweight config + lazily-loaded CA bundle + a
//! keyed idle-connection `Pool` (`Options.pool`, on by default). A request
//! first asks the pool for a warm connection to the target origin
//! (`scheme`/`host`/`port`); on a miss it dials fresh. A connection returns
//! to the pool on `Response.deinit`/`Upload.finish` *only* when the
//! response left it in a clean, fully-drained, keep-alive-eligible state
//! (see `Conn.keep_alive_eligible` / `isBodyDrained`) — anything else
//! (`Connection: close`, an HTTP/1.0 response without an explicit
//! `keep-alive`, a `101` upgrade, a body that was not read to completion, or
//! any read/write error) is closed instead, never pooled. Set
//! `Options.pool.enabled = false` for the old one-shot-per-request
//! behavior (`Connection: close` on every request, exactly as before).
//! Streaming both directions: response bodies are exposed as a
//! `std.Io.Reader` (chunked and Content-Length framing decoded on the fly),
//! request bodies can be streamed via `requestStreaming` (fixed length or
//! chunked), so bodies larger than memory never get buffered.
//!
//! Implementation notes: TLS via `std.crypto.tls` (never `std.http.Client`),
//! hostname resolution via `std.Io.net.HostName` (to be swapped for the
//! `dns` module when it lands), URL/host splitting via `netaddr`.
//!
//! Timeout model (Phase 1): the connect timeout is enforced natively by the
//! Io implementation; the total timeout is checked between phases (connect,
//! head read, redirect hops). TODO: enforce deadlines inside body reads via
//! async races once needed.
//!
//! HTTP/2 (Phase 3.2, opt-in): `connectH2c` opens a **cleartext h2c**
//! connection via prior knowledge (RFC 9113 §3.3) and returns an
//! `H2Session` that multiplexes any number of requests over that one
//! connection (the `h2_client` engine over this client's socket plumbing).
//! The h1 `request` path is byte-for-byte unchanged — h2 is strictly
//! opt-in. For h2 over TLS, `connectH2Over` (Phase 3.3) is the
//! bring-your-own-TLS seam: establish the TLS connection with your own
//! library offering `http.alpn_offer`, and when ALPN negotiated "h2"
//! (`http.protocolFromAlpn`, RFC 7301; RFC 9113 §3.3) hand the plaintext
//! reader/writer over — the same `H2Session` drives it, transport owned by
//! the caller.
//!
//! h2 pooling seam: an `H2Session` already multiplexes every request over
//! its ONE connection — that IS h2's pooling, so the h1 idle `Pool` below
//! does not apply to it and never touches `H2Session`/`connectH2c`/
//! `connectH2Over` (checking an h2 connection in/out exclusively per
//! request the way h1 does would defeat multiplexing). What is missing is
//! *reuse across calls to `connectH2c`* (each call dials a fresh h2c
//! connection); a caller that wants that today just keeps its own
//! `*H2Session` around and issues many `request`s on it — which is the
//! natural h2 usage pattern anyway. Pooling *many* h2 sessions per origin
//! (for parallelism beyond one connection's flow-control window) is a
//! documented non-goal of this pass, not a half-implementation: it would
//! need its own checkout policy (least-loaded session, not idle/warm), which
//! is different enough from the h1 `Pool` to deserve its own design rather
//! than a bolt-on.

const std = @import("std");
const netaddr = @import("netaddr");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2_client = @import("h2_client.zig");
const bufpool = @import("bufpool.zig");
const net = std.Io.net;
const tls = std.crypto.tls;

/// Shared, bounded slab pool for client connection buffers (see
/// `bufpool.BufferPool` and `Options.buffer_pool`).
pub const BufferPool = bufpool.BufferPool;

const Client = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
ca_bundle: std.crypto.Certificate.Bundle,
ca_lock: std.Io.RwLock,
ca_scanned: bool,
pool: Pool,
/// Lifetime count of fresh dials (pool misses + pooling disabled +
/// stale-connection retries). Diagnostics/metrics and the main reuse proof
/// in tests — a steady count across repeated same-origin requests means
/// the pool is doing its job.
dial_count: std.atomic.Value(usize) = .init(0),

pub const Options = struct {
    /// Per-connection connect timeout; 0 = none. NOTE: currently NOT
    /// enforced natively — std 0.16.0's `Io.Threaded` panics ("TODO
    /// implement netConnectIpPosix with timeout") when a connect timeout is
    /// passed, so the client falls back to the OS default until std lands
    /// the implementation (see `connectTimeout`).
    connect_timeout_ms: u32 = 5000,
    /// Whole-request budget (all redirect hops); 0 = none. Checked between
    /// phases, not inside a blocking body read.
    total_timeout_ms: u32 = 30000,
    /// Redirect-following cap (`error.TooManyRedirects` beyond it).
    max_redirects: u8 = 10,
    tls: TlsOptions = .{},
    /// Plaintext read buffer; also bounds a single response head line.
    read_buffer_size: usize = 16 * 1024,
    /// Plaintext write buffer.
    write_buffer_size: usize = 4 * 1024,
    /// Upper bound for a whole response head (status line + headers).
    max_head_bytes: usize = 16 * 1024,
    user_agent: []const u8 = "zig-libs-http/0.1",
    /// h1 keep-alive connection pooling (see the module doc). Defaults on;
    /// set `.enabled = false` for the old one-connection-per-request
    /// behavior (every request explicitly sends `Connection: close`).
    pool: PoolOptions = .{},
    /// Optional shared slab pool backing the **h2 client** read/write
    /// buffers (`connectH2c`). Null (the default) = each h2c dial
    /// `gpa.alloc`s its own `read_buffer_size + write_buffer_size` slab and
    /// frees it on `H2Session.close`, exactly as before. When set, that slab
    /// is checked out of / returned to the pool instead, so a gateway that
    /// churns h2 upstream connections reuses a bounded set of slabs rather
    /// than allocating one per dial. **The pool's `slab_size` MUST equal
    /// `read_buffer_size + write_buffer_size`** (asserted in `connectH2c`) —
    /// it serves exactly that one size class. The h1 path deliberately does
    /// NOT use it: h1's idle `Pool` already recycles whole warm connections
    /// (buffers included), so h1 never churns per-request buffers the way a
    /// fresh h2c dial does. Shared across threads (the pool is internally
    /// synchronized); the allocator behind it must be thread-safe.
    buffer_pool: ?*BufferPool = null,
};

/// Tunables for the idle-connection pool (`Options.pool`).
pub const PoolOptions = struct {
    /// Master switch. When false, `Client` behaves exactly as a
    /// non-pooling client always has: every request dials fresh and sends
    /// `Connection: close`.
    enabled: bool = true,
    /// Idle connections kept per `(scheme, host, port)` origin. Default 4:
    /// a reverse proxy typically fans a modest number of concurrent
    /// requests out to any one backend, so 4 warm sockets absorbs normal
    /// burst concurrency without pinning FDs a backend never asked for;
    /// callers fronting a hotter single backend can raise it.
    max_idle_per_host: u16 = 4,
    /// Idle connections kept across ALL origins combined. Default 64:
    /// bounds the client's total idle-FD/memory footprint when it talks to
    /// many distinct backends (a gateway in front of a large fleet), while
    /// still comfortably covering the common "few backends" case.
    max_idle_total: u16 = 64,
    /// An idle connection older than this is reaped — checked
    /// opportunistically whenever `acquire` scans the pool, and fully via
    /// an explicit `Client.poolSweep` call (no background thread anywhere
    /// in this module). Default 30s: comfortably under most reverse-proxy
    /// and origin-server default keep-alive timeouts (nginx/Apache
    /// commonly default to 60-75s), so a pooled connection is usually
    /// reaped by *us* before the peer would have closed it — the
    /// transparent one-shot retry (see the module doc / `request`) is the
    /// backstop for the remainder.
    idle_timeout_ms: u32 = 30_000,
};

pub const TlsOptions = struct {
    verify: Verify = .strict,

    pub const Verify = enum {
        /// Verify the certificate chain against the system CA bundle and the
        /// request host (loaded lazily, once per Client).
        strict,
        /// No certificate or host verification. Testing/diagnostics only.
        insecure_no_verify,
    };
};

pub const RequestOptions = struct {
    /// Extra request headers. `Host`, `User-Agent` and `Accept-Encoding`
    /// override the defaults; `Connection`, `Content-Length` and
    /// `Transfer-Encoding` are managed by the client and ignored here.
    headers: []const http.Header = &.{},
    /// In-memory request body (sent with Content-Length; replayed on 307/308
    /// redirects). For streaming uploads use `requestStreaming`.
    body: ?[]const u8 = null,
    follow_redirects: bool = true,
};

pub const Error = error{
    UnsupportedScheme,
    BadUrl,
    UnknownHostName,
    ConnectFailed,
    TlsFailed,
    CertificateBundleLoadFailure,
    WriteFailed,
    ReadFailed,
    ConnectionClosed,
    MalformedResponse,
    UnsupportedHttpVersion,
    HeadTooLarge,
    TooManyRedirects,
    BadRedirect,
    RedirectTooLong,
    BodyTooLarge,
    UnexpectedStatus,
    Timeout,
    Canceled,
    OutOfMemory,
};

/// `io` must support the net + async vtable operations (e.g.
/// `std.Io.Threaded`). The allocator is used for per-request connection
/// buffers and the CA bundle.
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Client {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .ca_bundle = .empty,
        .ca_lock = .init,
        .ca_scanned = false,
        .pool = Pool.init(gpa, options.pool),
    };
}

pub fn deinit(c: *Client) void {
    c.pool.deinit();
    c.ca_bundle.deinit(c.gpa);
    c.* = undefined;
}

/// Lifetime count of fresh dials (see `dial_count`'s doc). Mainly for tests
/// and metrics.
pub fn dialCount(c: *Client) usize {
    return c.dial_count.load(.monotonic);
}

/// Total idle pooled connections currently held (all origins). Mainly for
/// tests and metrics.
pub fn poolIdleCount(c: *Client) usize {
    return c.pool.idleCount();
}

/// Reap idle connections older than `Options.pool.idle_timeout_ms` right
/// now (this also happens opportunistically whenever `acquire` scans the
/// pool). There is no background thread anywhere in this module — call
/// this from your own timer/loop if you want proactive housekeeping instead
/// of relying on next-acquire reaping.
pub fn poolSweep(c: *Client) void {
    c.pool.sweep(c.nowMs());
}

// ── the request/response exchange ───────────────────────────────────────────

/// Perform a request, following redirects per `RequestOptions`. The returned
/// `Response` owns a connection — read the body via `Response.reader` and
/// always call `Response.deinit`.
pub fn request(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions) Error!Response {
    const deadline = c.totalDeadline();

    var url = try http.Url.parse(url_text);
    // Slices in `original_url` point into `url_text` (caller-owned, valid for
    // the whole call), so keeping this copy around stays valid even after
    // `url` itself gets reassigned to a redirect target below.
    const original_url = url;
    var current_method = method;
    var current_body = options.body;
    var url_owned: ?[]u8 = null;
    defer if (url_owned) |s| c.gpa.free(s);

    var redirects: u8 = 0;
    while (true) {
        try c.checkDeadline(deadline);

        // Strip credential-bearing headers unless this hop's target is the
        // *exact same origin* (scheme + host + port) as the original request
        // — a host-only check would keep sending Authorization/Cookie across
        // a same-host https→http downgrade or a same-host port change
        // (CVE-2018-18074 class: cleartext credential / cross-service leak).
        const strip_sensitive = crossOrigin(original_url, url);
        const plan: BodyPlan = if (current_body) |b| .{ .content_length = b.len } else .none;

        var reused = false;
        var conn = try c.acquireConn(url, &reused);
        errdefer conn.destroy();

        const head = c.sendAndReadHead(conn, current_method, url, options.headers, plan, current_body, strip_sensitive) catch |err| retry: {
            // Retry exactly once, and only when BOTH hold: (1) `conn` came
            // from the pool (`reused`), so it might have gone stale while
            // parked — a freshly dialed connection failing this way is a
            // real, non-retryable backend problem; (2) `isStaleConnError`
            // says the failure means nothing of this exchange reached the
            // peer as a live request (see its doc for the exact boundary).
            // We still hold the full request (method/url/headers and, on
            // this in-memory-body path, `current_body` itself) and can
            // resend it byte-for-byte on a fresh connection.
            //
            // `requestStreaming`/`Upload` deliberately get a narrower version
            // of this (only before any caller body byte is touched) — see
            // its doc comment for why a blanket retry is not safe there.
            if (!reused or !isStaleConnError(err)) return err;
            conn.destroy();
            conn = try c.dialConn(url);
            break :retry try c.sendAndReadHead(conn, current_method, url, options.headers, plan, current_body, strip_sensitive);
        };

        redirect: {
            if (!options.follow_redirects) break :redirect;
            const next_method = http.redirectMethodFor(head.status, current_method) orelse break :redirect;
            const location = head.header("location") orelse {
                // Like Go: 307/308 without Location is returned to the
                // caller; on 301–303 it is a protocol error.
                if (head.status == 307 or head.status == 308) break :redirect;
                return error.BadRedirect;
            };
            if (redirects >= c.options.max_redirects) return error.TooManyRedirects;
            redirects += 1;

            const cap = "https://".len + url.host.len + ":65535[]".len +
                url.path.len + location.len + http.max_merged_path;
            const buf = try c.gpa.alloc(u8, cap);
            errdefer c.gpa.free(buf);
            const resolved = try http.resolveLocation(url, location, buf);

            conn.destroy();
            if (url_owned) |s| c.gpa.free(s);
            url_owned = buf;
            url = http.Url.parse(resolved) catch return error.BadRedirect;
            if (head.status != 307 and head.status != 308) current_body = null;
            current_method = next_method;
            continue;
        }

        setupBody(conn, current_method, head);
        return .{ .status = head.status, .reason = head.reason, .head = head, .conn = conn };
    }
}

/// A response with its (single-use) connection. Slices in `head`/`reason`
/// stay valid until `deinit`.
pub const Response = struct {
    status: u16,
    reason: []const u8,
    head: h1.ResponseHead,
    conn: *Conn,

    /// First value of a response header (case-insensitive), or null.
    pub fn header(res: *const Response, name: []const u8) ?[]const u8 {
        return res.head.header(name);
    }

    /// Streaming body reader (chunked / Content-Length framing already
    /// decoded; reads to end-of-body). Valid until `deinit`.
    pub fn reader(res: *Response) *std.Io.Reader {
        return switch (res.conn.body) {
            .none => |*r| r,
            .chunked => |*cr| &cr.reader,
            .limited => |*lr| &lr.reader,
            .until_close => res.conn.plainReader(),
            .unset => unreachable,
        };
    }

    /// Read the whole remaining body into an allocated buffer
    /// (`error.BodyTooLarge` beyond `max_len`).
    pub fn readAllAlloc(res: *Response, gpa: std.mem.Allocator, max_len: usize) Error![]u8 {
        return res.reader().allocRemaining(gpa, .limited(max_len)) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => error.BodyTooLarge,
            else => error.ReadFailed,
        };
    }

    /// Return the connection to the pool when it left the exchange in a
    /// clean, fully-drained, keep-alive-eligible state (see
    /// `Conn.keep_alive_eligible` / `isBodyDrained`); otherwise close it.
    /// Either way, frees this response's per-request buffers.
    pub fn deinit(res: *Response) void {
        const conn = res.conn;
        const c = conn.client;
        if (c.options.pool.enabled and conn.keep_alive_eligible and isBodyDrained(conn)) {
            c.pool.release(conn, c.nowMs());
        } else {
            conn.destroy();
        }
        res.* = undefined;
    }
};

// ── streaming uploads ───────────────────────────────────────────────────────

/// An in-flight streaming request body. Write via `writer`, then call
/// `finish` (or `abort`). Do not copy after calling `writer`.
pub const Upload = struct {
    conn: *Conn,
    method: http.Method,
    chunked: ?h1.ChunkedWriter,

    /// The request-body writer: plaintext bytes in, wire framing out.
    pub fn writer(u: *Upload) *std.Io.Writer {
        if (u.chunked) |*cw| return &cw.writer;
        return u.conn.plainWriter();
    }

    /// Terminate the body (0-chunk when chunked), flush, and read the
    /// response. Consumes the Upload — on error the connection is closed.
    pub fn finish(u: *Upload) Error!Response {
        errdefer u.conn.destroy();
        if (u.chunked) |*cw| cw.finish() catch return error.WriteFailed;
        try u.conn.flushAll();
        const head = try readResponseHead(u.conn);
        setupBody(u.conn, u.method, head);
        return .{ .status = head.status, .reason = head.reason, .head = head, .conn = u.conn };
    }

    /// Drop the request without reading a response.
    pub fn abort(u: *Upload) void {
        u.conn.destroy();
        u.* = undefined;
    }
};

/// Open a request whose body is streamed by the caller. `content_length`
/// null selects chunked transfer-encoding. Redirects are NOT followed
/// (a streamed body cannot be replayed); `options.body` must be null.
pub fn requestStreaming(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions, content_length: ?u64) Error!Upload {
    std.debug.assert(options.body == null);
    const url = try http.Url.parse(url_text);
    const plan: BodyPlan = if (content_length) |n| .{ .content_length = n } else .chunked;

    var reused = false;
    var conn = try c.acquireConn(url, &reused);
    errdefer conn.destroy();

    writeRequestHead(conn.plainWriter(), method, url, options.headers, c.options.user_agent, plan, false, !c.options.pool.enabled) catch |err| {
        // Narrower than `request`'s retry: safe here ONLY because nothing
        // of the caller-driven body has been touched yet — just the fixed
        // request head, which we can regenerate byte-for-byte on a fresh
        // connection. Once this function returns the `Upload` and the
        // caller starts writing/streaming the body through it, no further
        // retry is attempted anywhere in `Upload` (`writer`/`finish`): that
        // body may come from a non-seekable source (a pipe, a generator)
        // that cannot be replayed, so a stale connection discovered mid- or
        // post-body surfaces as a normal request failure instead — the
        // same class of failure any other backend outage already produces.
        if (!reused or !isStaleConnError(err)) return err;
        conn.destroy();
        conn = try c.dialConn(url);
        try writeRequestHead(conn.plainWriter(), method, url, options.headers, c.options.user_agent, plan, false, !c.options.pool.enabled);
    };
    return .{
        .conn = conn,
        .method = method,
        .chunked = if (content_length == null) h1.ChunkedWriter.init(conn.plainWriter(), conn.body_buf) else null,
    };
}

// ── convenience helpers ─────────────────────────────────────────────────────

/// GET `url` and return the body (caller owns), requiring a 2xx status
/// (`error.UnexpectedStatus` otherwise).
pub fn getAlloc(c: *Client, gpa: std.mem.Allocator, url: []const u8, max_len: usize) Error![]u8 {
    var res = try c.request(.get, url, .{});
    defer res.deinit();
    if (res.status < 200 or res.status >= 300) return error.UnexpectedStatus;
    return res.readAllAlloc(gpa, max_len);
}

/// GET `url` streaming the body straight to `dir/sub_path` (no full-body
/// buffering). Returns bytes written; requires a 2xx status. File-system
/// failures map to `error.WriteFailed`.
pub fn getToFile(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8) Error!u64 {
    var res = try c.request(.get, url, .{});
    defer res.deinit();
    if (res.status < 200 or res.status >= 300) return error.UnexpectedStatus;

    var file = dir.createFile(c.io, sub_path, .{ .truncate = true }) catch return error.WriteFailed;
    defer file.close(c.io);
    var fbuf: [64 * 1024]u8 = undefined;
    var fw = file.writer(c.io, &fbuf);
    const n = res.reader().streamRemaining(&fw.interface) catch |err| switch (err) {
        error.WriteFailed => return error.WriteFailed,
        else => return error.ReadFailed,
    };
    fw.interface.flush() catch return error.WriteFailed;
    return n;
}

/// PUT the contents of `dir/sub_path` to `url`, streamed with a
/// Content-Length (never buffered whole). Returns the response status; the
/// response body is discarded. File-system failures map to
/// `error.ReadFailed`.
pub fn putFile(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8, options: RequestOptions) Error!u16 {
    var file = dir.openFile(c.io, sub_path, .{}) catch return error.ReadFailed;
    defer file.close(c.io);
    const size = (file.stat(c.io) catch return error.ReadFailed).size;

    var up = try c.requestStreaming(.put, url, options, size);
    var fbuf: [64 * 1024]u8 = undefined;
    var fr = file.reader(c.io, &fbuf);
    fr.interface.streamExact64(up.writer(), size) catch |err| {
        up.abort();
        return switch (err) {
            error.WriteFailed => error.WriteFailed,
            else => error.ReadFailed,
        };
    };
    var res = try up.finish();
    defer res.deinit();
    return res.status;
}

// ── HTTP/2 cleartext (h2c, prior knowledge) ─────────────────────────────────

/// One HTTP/2 connection, multiplexing any number of requests: call
/// `request` N times, then `awaitResponse` each returned stream id in any
/// order. Created by `connectH2c` (cleartext h2c over an owned TCP socket,
/// RFC 9113 §3.3 prior knowledge — the peer must speak h2c, e.g. `Server`
/// with `enable_h2c`) or `connectH2Over` (caller-provided stream, e.g.
/// after a TLS handshake negotiated ALPN "h2"); released with `close`.
/// Single-owner like the h1 client: one task drives a session.
pub const H2Session = struct {
    gpa: std.mem.Allocator,
    /// The socket transport when this client opened it (`connectH2c`);
    /// null when the session runs over a caller-provided stream
    /// (`connectH2Over`) — then the caller owns the transport and closes
    /// it after `close`.
    owned: ?Owned,
    session: h2_client.Session,
    authority: []u8,

    const Owned = struct {
        client: *Client,
        stream: net.Stream,
        sr: net.Stream.Reader,
        sw: net.Stream.Writer,
        slab: []u8,
        /// When set, `slab` was checked out of this pool and is returned to
        /// it on `close` instead of freed (`Options.buffer_pool`).
        buffer_pool: ?*BufferPool,
    };

    /// Start a request on its own stream (many may be in flight at once).
    /// `:authority` defaults to the connected host[:port].
    pub fn request(
        hs: *H2Session,
        method: http.Method,
        path: []const u8,
        options: h2_client.RequestOptions,
    ) h2_client.Error!u31 {
        var opts = options;
        if (opts.authority == null) opts.authority = hs.authority;
        return hs.session.request(method, path, opts);
    }

    /// Block until the response for `stream_id` is complete (pumping the
    /// connection, which advances every in-flight stream) and hand it over.
    pub fn awaitResponse(hs: *H2Session, stream_id: u31) h2_client.Error!h2_client.Response {
        return hs.session.awaitResponse(stream_id);
    }

    /// Graceful GOAWAY (best effort), close the socket when this client
    /// owns it (`connectH2c`), free everything. Over a caller-provided
    /// stream (`connectH2Over`) the transport is left open — close it
    /// yourself afterwards (e.g. the TLS close_notify + socket close).
    pub fn close(hs: *H2Session) void {
        hs.session.shutdown();
        hs.session.deinit();
        const gpa = hs.gpa;
        if (hs.owned) |*o| {
            o.stream.close(o.client.io);
            if (o.buffer_pool) |bp| bp.release(o.slab) else gpa.free(o.slab);
        }
        gpa.free(hs.authority);
        gpa.destroy(hs);
    }
};

/// Open an HTTP/2 cleartext connection to `host:port` via prior knowledge
/// (RFC 9113 §3.3): the client preface + SETTINGS are sent immediately.
/// Reuses the client's connect plumbing (`connect_timeout_ms`, buffer
/// sizing); the returned session multiplexes requests until `close`.
pub fn connectH2c(c: *Client, host: []const u8, port: u16, options: h2_client.Options) Error!*H2Session {
    const url: http.Url = .{ .scheme = .http, .host = host, .port = port, .path = "/", .query = "" };

    // Default `:authority` — the wire form of the authority, brackets and
    // non-default port included (same shape as the h1 Host header).
    var auth_buf: [280]u8 = undefined;
    var auth_w: std.Io.Writer = .fixed(&auth_buf);
    url.writeHostHeaderValue(&auth_w) catch return error.BadUrl;

    const slab_len = c.options.read_buffer_size + c.options.write_buffer_size;
    const hs = try c.gpa.create(H2Session);
    errdefer c.gpa.destroy(hs);
    // Slab from the shared pool when one is configured (its size class must
    // match this layout), else a fresh allocation freed on close.
    if (c.options.buffer_pool) |bp| std.debug.assert(bp.slab_size == slab_len);
    const slab = if (c.options.buffer_pool) |bp| try bp.acquire() else try c.gpa.alloc(u8, slab_len);
    errdefer if (c.options.buffer_pool) |bp| bp.release(slab) else c.gpa.free(slab);
    const authority = try c.gpa.dupe(u8, auth_w.buffered());
    errdefer c.gpa.free(authority);

    const stream = try c.connectStream(url);
    errdefer stream.close(c.io);

    hs.* = .{
        .gpa = c.gpa,
        .owned = .{
            .client = c,
            .stream = stream,
            .sr = undefined,
            .sw = undefined,
            .slab = slab,
            .buffer_pool = c.options.buffer_pool,
        },
        .session = undefined,
        .authority = authority,
    };
    // Reader/writer (and the session pointing at them) must be initialized
    // at the connection's final heap address.
    const o = &hs.owned.?;
    o.sr = stream.reader(c.io, slab[0..c.options.read_buffer_size]);
    o.sw = stream.writer(c.io, slab[c.options.read_buffer_size..]);
    hs.session = h2_client.Session.init(c.gpa, &o.sr.interface, &o.sw.interface, options) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.WriteFailed,
        };
    return hs;
}

/// BYO-TLS entry point: run the multiplexing HTTP/2 client over an
/// **already-established** byte stream the caller owns — typically a TLS
/// connection whose handshake (offering `http.alpn_offer`) negotiated the
/// ALPN protocol "h2" (`http.protocolFromAlpn`; RFC 7301, RFC 9113 §3.3 —
/// over TLS h2 is selected only via ALPN, never an upgrade). The client
/// connection preface + SETTINGS are sent immediately (RFC 9113 §3.4),
/// exactly as on h2c — the wire is identical from here on.
///
/// `in`/`out` must outlive the session and stay untouched by the caller
/// while it lives; `close` releases the session but leaves the transport
/// open (closing it — TLS close_notify, socket — stays the caller's job).
/// `authority` is copied and becomes the default `:authority` pseudo-header
/// (host[:port] — what was presented as the TLS server name). Over TLS,
/// pass `.scheme = "https"` in each request's `RequestOptions`
/// (RFC 9113 §8.3.1).
///
/// Intended flow (no TLS library required or referenced here):
///
///     // caller's TLS layer: connect, handshake offering http.alpn_offer
///     // negotiated = the ALPN protocol the handshake selected
///     if (http.protocolFromAlpn(negotiated) == .h2) {
///         const hs = try Client.connectH2Over(gpa, tls_reader, tls_writer,
///             "example.com", .{});
///         defer hs.close();
///         const sid = try hs.request(.get, "/", .{ .scheme = "https" });
///         ...
///     } // else: the HTTP/1.1 client path over the same stream
pub fn connectH2Over(
    gpa: std.mem.Allocator,
    in: *std.Io.Reader,
    out: *std.Io.Writer,
    authority: []const u8,
    options: h2_client.Options,
) Error!*H2Session {
    const hs = try gpa.create(H2Session);
    errdefer gpa.destroy(hs);
    const auth = try gpa.dupe(u8, authority);
    errdefer gpa.free(auth);
    hs.* = .{
        .gpa = gpa,
        .owned = null,
        .session = undefined,
        .authority = auth,
    };
    hs.session = h2_client.Session.init(gpa, in, out, options) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.WriteFailed,
    };
    return hs;
}

// ── connection internals ────────────────────────────────────────────────────

/// Extra interface buffer for the body-framing readers / chunked writer.
const body_scratch_len = 4096;

const Conn = struct {
    client: *Client,
    stream: net.Stream,
    sr: net.Stream.Reader,
    sw: net.Stream.Writer,
    tls_client: ?tls.Client,
    slab: []u8,
    head_buf: []u8,
    body_buf: []u8,
    body: BodyState,
    /// The origin this connection is dialed to — set once at dial time,
    /// read back when a completed response decides whether to return the
    /// connection to the pool (`Pool.release`'s key).
    origin: Origin,
    /// Whether the last response read on this connection left it eligible
    /// for reuse (no `Connection: close`, not an HTTP/1.0 response without
    /// explicit `keep-alive`, not a `101` upgrade) — set by `setupBody`.
    /// Still requires `isBodyDrained` before actually pooling: an eligible
    /// framing with an only-partially-read body cannot be reused either.
    keep_alive_eligible: bool = false,

    const BodyState = union(enum) {
        unset,
        none: std.Io.Reader,
        chunked: h1.ChunkedReader,
        limited: h1.ContentLengthReader,
        until_close,
    };

    /// Decrypted (or plain) byte stream from the server.
    fn plainReader(conn: *Conn) *std.Io.Reader {
        if (conn.tls_client) |*t| return &t.reader;
        return &conn.sr.interface;
    }

    /// Plaintext writer towards the server (encrypting when TLS).
    fn plainWriter(conn: *Conn) *std.Io.Writer {
        if (conn.tls_client) |*t| return &t.writer;
        return &conn.sw.interface;
    }

    fn flushAll(conn: *Conn) Error!void {
        conn.plainWriter().flush() catch return error.WriteFailed;
        // The TLS writer drains ciphertext into the socket writer — flush
        // that too.
        if (conn.tls_client != null)
            conn.sw.interface.flush() catch return error.WriteFailed;
    }

    fn destroy(conn: *Conn) void {
        const gpa = conn.client.gpa;
        conn.stream.close(conn.client.io);
        gpa.free(conn.slab);
        gpa.destroy(conn);
    }
};

/// A connection's origin (`scheme`, `host`, `port`) — the pool's key.
/// `host` is copied into a fixed inline buffer at dial time: the URL text
/// it was parsed from is caller-owned and, for a redirect hop, sometimes
/// freed before the connection this key describes is ever released back to
/// the pool (see `request`'s `url_owned`), so the key cannot merely borrow
/// it.
const Origin = struct {
    scheme: http.Url.Scheme,
    port: u16,
    host_buf: [max_origin_host]u8 = undefined,
    host_len: u8 = 0,

    /// DNS names top out at 253 octets; IP literals (with brackets) are
    /// shorter still. A host longer than this (never in practice) is
    /// truncated — worst case two such hosts sharing a 255-byte prefix
    /// collide in the pool key, which only costs a redial, never a
    /// correctness problem.
    const max_origin_host = 255;

    fn set(o: *Origin, scheme: http.Url.Scheme, port: u16, host_text: []const u8) void {
        const n: u8 = @intCast(@min(host_text.len, max_origin_host));
        o.* = .{ .scheme = scheme, .port = port, .host_len = n };
        @memcpy(o.host_buf[0..n], host_text[0..n]);
    }

    fn host(o: *const Origin) []const u8 {
        return o.host_buf[0..o.host_len];
    }

    fn eql(a: *const Origin, scheme: http.Url.Scheme, host_text: []const u8, port: u16) bool {
        return a.scheme == scheme and a.port == port and std.ascii.eqlIgnoreCase(a.host(), host_text);
    }
};

/// Keyed idle-connection pool (h1 only — see the module doc for the h2
/// seam). Bounded (`max_idle_per_host`/`max_idle_total`), reaps entries
/// older than `idle_timeout_ms`, internally synchronized (a tight
/// `std.atomic.Mutex` spinlock — this repo's era of `std` has no
/// `std.Thread.Mutex`/`Condition`; see `lockSpin`, the same idiom
/// `sessions`/`abuseguard`/`acme` already use for shared state touched from
/// every `http.Server` connection thread). No I/O ever happens while the
/// lock is held: `acquire`/`release`/`sweep` only mutate the idle list
/// under the lock, collecting anything to close into a stack buffer, and
/// only call `Conn.destroy` (a socket close + a free) after unlocking.
/// Takes `now_ms` as a plain parameter everywhere — it never reads a clock
/// itself (`Client` is the one real clock reader, via `nowMs`), so the pool
/// alone is fully deterministic to test.
const Pool = struct {
    gpa: std.mem.Allocator,
    options: PoolOptions,
    mutex: std.atomic.Mutex = .unlocked,
    idle: std.ArrayList(Idle) = .empty,

    const Idle = struct {
        conn: *Conn,
        idle_since_ms: i64,
    };

    /// Hard upper bound on how many connections one call closes in a
    /// single pass — sized to cover any sane `max_idle_total` without
    /// needing an allocation on the reap path. `init` asserts the
    /// configured cap actually fits.
    const max_reap_batch = 4096;

    fn init(gpa: std.mem.Allocator, options: PoolOptions) Pool {
        std.debug.assert(options.max_idle_total <= max_reap_batch);
        return .{ .gpa = gpa, .options = options };
    }

    /// Close every idle connection and free the pool's own bookkeeping.
    /// Not synchronized — call only once nothing else can touch the pool
    /// (this mirrors `Client.deinit`'s own contract).
    fn deinit(p: *Pool) void {
        for (p.idle.items) |it| it.conn.destroy();
        p.idle.deinit(p.gpa);
    }

    fn idleCount(p: *Pool) usize {
        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        return p.idle.items.len;
    }

    /// Pop a warm idle connection matching `(scheme, host, port)`, or null
    /// (dial fresh). Opportunistically reaps any idle connection already
    /// older than `idle_timeout_ms` encountered along the way. When several
    /// idle connections match the key, the most recently released one wins
    /// (keeps the warmest socket in play; older same-key idle connections
    /// simply age out via the timeout or a later cap eviction).
    fn acquire(p: *Pool, scheme: http.Url.Scheme, host: []const u8, port: u16, now_ms: i64) ?*Conn {
        var reap_buf: [max_reap_batch]*Conn = undefined;
        var reap_n: usize = 0;
        var found: ?*Conn = null;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();

            var i: usize = 0;
            while (i < p.idle.items.len) {
                if (now_ms -| p.idle.items[i].idle_since_ms > p.options.idle_timeout_ms and reap_n < max_reap_batch) {
                    reap_buf[reap_n] = p.idle.swapRemove(i).conn;
                    reap_n += 1;
                    continue; // swapRemove moved the tail into i — recheck it
                }
                i += 1;
            }
            var match_idx: ?usize = null;
            for (p.idle.items, 0..) |it, idx| {
                if (it.conn.origin.eql(scheme, host, port)) match_idx = idx;
            }
            if (match_idx) |idx| found = p.idle.orderedRemove(idx).conn;
        }
        for (reap_buf[0..reap_n]) |c| c.destroy();
        return found;
    }

    /// Return `conn` to the idle pool, evicting the oldest same-origin
    /// entry if `max_idle_per_host` would be exceeded and the oldest entry
    /// overall if `max_idle_total` would be exceeded (both closed after the
    /// lock is released). Fails closed under allocation pressure: if the
    /// pool's own bookkeeping cannot grow, `conn` is simply closed instead
    /// of pooled — a missed reuse opportunity, never a leak or a
    /// correctness problem (mirrors `ramcache.put`'s silent-no-op-on-OOM
    /// shape).
    fn release(p: *Pool, conn: *Conn, now_ms: i64) void {
        var evict_buf: [2]*Conn = undefined;
        var evict_n: usize = 0;
        var kept = true;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();

            var per_host: usize = 0;
            var oldest_host_idx: ?usize = null;
            var oldest_host_ms: i64 = std.math.maxInt(i64);
            for (p.idle.items, 0..) |it, idx| {
                if (!it.conn.origin.eql(conn.origin.scheme, conn.origin.host(), conn.origin.port)) continue;
                per_host += 1;
                if (it.idle_since_ms < oldest_host_ms) {
                    oldest_host_ms = it.idle_since_ms;
                    oldest_host_idx = idx;
                }
            }
            if (per_host >= p.options.max_idle_per_host) {
                if (oldest_host_idx) |idx| {
                    evict_buf[evict_n] = p.idle.orderedRemove(idx).conn;
                    evict_n += 1;
                }
            }
            if (p.idle.items.len >= p.options.max_idle_total) {
                var oldest_idx: ?usize = null;
                var oldest_ms: i64 = std.math.maxInt(i64);
                for (p.idle.items, 0..) |it, idx| {
                    if (it.idle_since_ms < oldest_ms) {
                        oldest_ms = it.idle_since_ms;
                        oldest_idx = idx;
                    }
                }
                if (oldest_idx) |idx| {
                    evict_buf[evict_n] = p.idle.orderedRemove(idx).conn;
                    evict_n += 1;
                }
            }
            p.idle.append(p.gpa, .{ .conn = conn, .idle_since_ms = now_ms }) catch {
                kept = false;
            };
        }
        for (evict_buf[0..evict_n]) |c| c.destroy();
        if (!kept) conn.destroy();
    }

    /// Reap every idle connection older than `idle_timeout_ms` right now
    /// (closed after the lock is released). `acquire` also reaps
    /// opportunistically, but only entries it happens to scan past —
    /// `sweep` is the thorough, explicit version for a caller-driven
    /// housekeeping tick (see `Client.poolSweep`).
    fn sweep(p: *Pool, now_ms: i64) void {
        var reap_buf: [max_reap_batch]*Conn = undefined;
        var reap_n: usize = 0;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();
            var i: usize = 0;
            while (i < p.idle.items.len) {
                if (now_ms -| p.idle.items[i].idle_since_ms > p.options.idle_timeout_ms and reap_n < max_reap_batch) {
                    reap_buf[reap_n] = p.idle.swapRemove(i).conn;
                    reap_n += 1;
                    continue;
                }
                i += 1;
            }
        }
        for (reap_buf[0..reap_n]) |c| c.destroy();
    }
};

/// Spin until `m` is acquired (this repo's era of `std` has no
/// `std.Thread.Mutex`; see the `Pool` doc comment).
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

/// Acquire a connection to `url`'s origin: a warm pooled one when pooling is
/// enabled and one is idle for that exact `(scheme, host, port)`, else a
/// freshly dialed one. `reused.*` reports which — callers use it to decide
/// whether a subsequent write/read failure is eligible for the transparent
/// one-shot retry (see `request`'s doc comment on that retry's safety
/// boundary).
fn acquireConn(c: *Client, url: http.Url, reused: *bool) Error!*Conn {
    if (c.options.pool.enabled) {
        if (c.pool.acquire(url.scheme, url.host, url.port, c.nowMs())) |conn| {
            reused.* = true;
            return conn;
        }
    }
    reused.* = false;
    return c.dialConn(url);
}

/// Write the request head + optional in-memory body, flush, and read back
/// the response head — one full h1 exchange on an already-acquired `conn`.
/// Factored out of `request`'s hop loop so the stale-pooled-connection retry
/// there can attempt it twice against two different connections without
/// duplicating the write/flush/read sequence.
fn sendAndReadHead(
    c: *Client,
    conn: *Conn,
    method: http.Method,
    url: http.Url,
    headers: []const http.Header,
    plan: BodyPlan,
    body: ?[]const u8,
    strip_sensitive: bool,
) Error!h1.ResponseHead {
    try writeRequestHead(conn.plainWriter(), method, url, headers, c.options.user_agent, plan, strip_sensitive, !c.options.pool.enabled);
    if (body) |b| conn.plainWriter().writeAll(b) catch return error.WriteFailed;
    try conn.flushAll();
    return readResponseHead(conn);
}

/// The narrow set of failures that mean *this* connection was already dead
/// before the exchange even produced a usable response — never bytes a live
/// peer actually sent back. See `request`'s retry-site doc comment for the
/// full reasoning. All three are purely transport-level and can only occur
/// while `sendAndReadHead` is still writing the request or waiting for the
/// response head:
///   * `error.WriteFailed` — the write/flush itself bounced off an
///     already-dead socket (e.g. `ECONNRESET`/`EPIPE` from a peer that
///     already tore the connection down).
///   * `error.ConnectionClosed` — the peer's FIN arrived with zero response
///     bytes behind it (a clean idle-timeout close raced our checkout).
///   * `error.ReadFailed` — the response-head read syscall itself failed
///     (most commonly `ECONNRESET`: on a fast loopback the peer's reset can
///     arrive *after* our write already succeeded locally, so the failure
///     surfaces on the read instead of the write — same dead-connection
///     cause, just discovered one step later).
/// `error.HeadTooLarge`/`MalformedResponse`/`UnsupportedHttpVersion` are
/// deliberately NOT included: those mean the peer *did* send real response
/// bytes back (just broken/oversized ones) — a live peer misbehaving, not a
/// stale connection, and redialing would not fix it.
fn isStaleConnError(err: anyerror) bool {
    return switch (err) {
        error.WriteFailed, error.ConnectionClosed, error.ReadFailed => true,
        else => false,
    };
}

/// Milliseconds on the `awake` (monotonic) clock — the pool's only time
/// source. Never called by `Pool` itself (it takes `now_ms` as a plain
/// parameter, per this repo's no-hidden-clock rule), only by `Client` at the
/// call sites that hand the pool its clock.
fn nowMs(c: *Client) i64 {
    const ts = std.Io.Clock.Timestamp.now(c.io, .awake);
    return @intCast(@divTrunc(ts.raw.nanoseconds, std.time.ns_per_ms));
}

fn dialConn(c: *Client, url: http.Url) Error!*Conn {
    const o = &c.options;
    const io = c.io;
    const tls_needed = url.scheme == .https;
    if (tls_needed and o.tls.verify == .strict) try c.ensureCaBundle();

    // Buffer slab layout. For TLS the socket-facing buffers must hold a full
    // ciphertext record; the plaintext read buffer additionally holds the
    // decoded response head (mirrors std.http.Client's sizing).
    const record_len = tls.Client.min_buffer_len;
    const sock_r_len = if (tls_needed) record_len else o.read_buffer_size;
    const sock_w_len = if (tls_needed) record_len else o.write_buffer_size;
    const tls_r_len = if (tls_needed) record_len + o.read_buffer_size else 0;
    const tls_w_len = if (tls_needed) o.write_buffer_size else 0;
    const total = sock_r_len + sock_w_len + tls_r_len + tls_w_len + o.max_head_bytes + body_scratch_len;

    const conn = try c.gpa.create(Conn);
    errdefer c.gpa.destroy(conn);
    const slab = try c.gpa.alloc(u8, total);
    errdefer c.gpa.free(slab);

    var off: usize = 0;
    const sock_r = slab[off..][0..sock_r_len];
    off += sock_r_len;
    const sock_w = slab[off..][0..sock_w_len];
    off += sock_w_len;
    const tls_r = slab[off..][0..tls_r_len];
    off += tls_r_len;
    const tls_w = slab[off..][0..tls_w_len];
    off += tls_w_len;
    const head_buf = slab[off..][0..o.max_head_bytes];
    off += o.max_head_bytes;
    const body_buf = slab[off..][0..body_scratch_len];

    const stream = try c.connectStream(url);
    errdefer stream.close(io);
    _ = c.dial_count.fetchAdd(1, .monotonic);

    conn.* = .{
        .client = c,
        .stream = stream,
        .sr = undefined,
        .sw = undefined,
        .tls_client = null,
        .slab = slab,
        .head_buf = head_buf,
        .body_buf = body_buf,
        .body = .unset,
        .origin = undefined,
        .keep_alive_eligible = false,
    };
    conn.origin.set(url.scheme, url.port, url.host);
    // The stream reader/writer (and the TLS client pointing at them) must be
    // initialized at the connection's final heap address.
    conn.sr = stream.reader(io, sock_r);
    conn.sw = stream.writer(io, sock_w);

    if (tls_needed) {
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        conn.tls_client = tls.Client.init(&conn.sr.interface, &conn.sw.interface, .{
            .host = switch (o.tls.verify) {
                .strict => .{ .explicit = url.host },
                .insecure_no_verify => .no_verification,
            },
            .ca = switch (o.tls.verify) {
                .strict => .{ .bundle = .{
                    .gpa = c.gpa,
                    .io = io,
                    .lock = &c.ca_lock,
                    .bundle = &c.ca_bundle,
                } },
                .insecure_no_verify => .no_verification,
            },
            .read_buffer = tls_r,
            .write_buffer = tls_w,
            .entropy = &entropy,
            .realtime_now = std.Io.Clock.real.now(io),
            // Fine for HTTP: framing (Content-Length/chunked) detects
            // truncation at the layer above.
            .allow_truncation_attacks = true,
        }) catch |err| switch (err) {
            error.ReadFailed, error.WriteFailed => return error.ConnectFailed,
            error.Canceled => return error.Canceled,
            else => return error.TlsFailed,
        };
    }
    return conn;
}

fn connectStream(c: *Client, url: http.Url) Error!net.Stream {
    const copts: net.IpAddress.ConnectOptions = .{
        .mode = .stream,
        .timeout = c.connectTimeout(),
    };
    if (netaddr.parseIp(url.host) != null) {
        const addr = net.IpAddress.parse(url.host, url.port) catch return error.BadUrl;
        return addr.connect(c.io, copts) catch |err| mapConnectError(err);
    }
    const host_name = net.HostName.init(url.host) catch return error.BadUrl;
    return host_name.connect(c.io, url.port, copts) catch |err| mapConnectError(err);
}

fn mapConnectError(err: anyerror) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.Timeout => error.Timeout,
        error.UnknownHostName, error.NoAddressReturned => error.UnknownHostName,
        error.OutOfMemory => error.OutOfMemory,
        else => error.ConnectFailed,
    };
}

/// Load the system CA bundle once (lazily, like std.http.Client).
fn ensureCaBundle(c: *Client) Error!void {
    const io = c.io;
    {
        c.ca_lock.lockShared(io) catch return error.Canceled;
        defer c.ca_lock.unlockShared(io);
        if (c.ca_scanned) return;
    }
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(c.gpa);
    bundle.rescan(c.gpa, io, std.Io.Clock.real.now(io)) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.CertificateBundleLoadFailure,
    };
    c.ca_lock.lock(io) catch return error.Canceled;
    defer c.ca_lock.unlock(io);
    if (!c.ca_scanned) {
        c.ca_scanned = true;
        std.mem.swap(std.crypto.Certificate.Bundle, &c.ca_bundle, &bundle);
    }
}

// ── timeouts ────────────────────────────────────────────────────────────────

fn connectTimeout(c: *Client) std.Io.Timeout {
    // TODO(zig-0.16.0): std.Io.Threaded panics with "TODO implement
    // netConnectIpPosix with timeout" when ConnectOptions.timeout != .none.
    // Until std implements it, rely on the OS connect timeout plus the
    // between-phases total-deadline checks; re-enable the code below then.
    _ = c;
    return .none;
    // const ms = c.options.connect_timeout_ms;
    // if (ms == 0) return .none;
    // return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

fn totalDeadline(c: *Client) ?std.Io.Clock.Timestamp {
    const ms = c.options.total_timeout_ms;
    if (ms == 0) return null;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toTimestamp(c.io);
}

fn checkDeadline(c: *Client, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const d = deadline orelse return;
    if (d.durationFromNow(c.io).raw.nanoseconds <= 0) return error.Timeout;
}

// ── wire helpers (pure, offline-testable) ───────────────────────────────────

const BodyPlan = union(enum) {
    none,
    content_length: u64,
    chunked,
};

/// True when `a` and `b` are different origins (RFC 6454): scheme, host
/// (case-insensitive — DNS names) and port must ALL match. `Url.parse`
/// already fills in the scheme's default port when the URL omits one, so a
/// bare port comparison here correctly treats an explicit `:443` and an
/// implicit `https://` origin as the same. Used to decide whether a redirect
/// hop must strip credential-bearing headers (`Authorization`, `Cookie`) —
/// a host-only check would keep sending them across a same-host scheme
/// downgrade (https→http) or a same-host port change.
fn crossOrigin(a: http.Url, b: http.Url) bool {
    return !(a.scheme == b.scheme and a.port == b.port and std.ascii.eqlIgnoreCase(a.host, b.host));
}

/// Emit a full request head. Pure writer logic so tests can assert exact
/// bytes. Managed headers: `Connection: close` when `send_close` (else
/// omitted — HTTP/1.1 defaults to persistent, which is what makes the
/// connection eligible for the pool afterwards); `Content-Length` /
/// `Transfer-Encoding` from `plan`; `Host`, `User-Agent`, `Accept-Encoding`
/// defaulted unless the caller supplies them; `Authorization` and `Cookie`
/// both dropped when `strip_sensitive` (cross-origin redirect — see
/// `crossOrigin`) since either can carry credentials that must not leak to a
/// different scheme/host/port.
fn writeRequestHead(
    w: *std.Io.Writer,
    method: http.Method,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_sensitive: bool,
    send_close: bool,
) error{WriteFailed}!void {
    var custom_host: ?[]const u8 = null;
    var custom_ua = false;
    var custom_ae = false;
    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "host")) custom_host = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, "user-agent")) custom_ua = true;
        if (std.ascii.eqlIgnoreCase(hd.name, "accept-encoding")) custom_ae = true;
    }

    writeHead(w, method, url, headers, user_agent, plan, strip_sensitive, send_close, custom_host, custom_ua, custom_ae) catch
        return error.WriteFailed;
}

fn writeHead(
    w: *std.Io.Writer,
    method: http.Method,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_sensitive: bool,
    send_close: bool,
    custom_host: ?[]const u8,
    custom_ua: bool,
    custom_ae: bool,
) std.Io.Writer.Error!void {
    try w.print("{s} {s}", .{ method.token(), url.path });
    if (url.query.len != 0) try w.print("?{s}", .{url.query});
    try w.writeAll(" HTTP/1.1\r\nHost: ");
    if (custom_host) |hv| {
        try w.writeAll(hv);
    } else {
        try url.writeHostHeaderValue(w);
    }
    try w.writeAll("\r\n");

    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "host") or
            std.ascii.eqlIgnoreCase(hd.name, "connection") or
            std.ascii.eqlIgnoreCase(hd.name, "content-length") or
            std.ascii.eqlIgnoreCase(hd.name, "transfer-encoding")) continue;
        if (strip_sensitive and (std.ascii.eqlIgnoreCase(hd.name, "authorization") or
            std.ascii.eqlIgnoreCase(hd.name, "cookie"))) continue;
        try w.print("{s}: {s}\r\n", .{ hd.name, hd.value });
    }

    if (!custom_ua) try w.print("User-Agent: {s}\r\n", .{user_agent});
    if (!custom_ae) try w.writeAll("Accept-Encoding: identity\r\n");
    if (send_close) try w.writeAll("Connection: close\r\n");
    switch (plan) {
        .none => {},
        .content_length => |n| try w.print("Content-Length: {d}\r\n", .{n}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    try w.writeAll("\r\n");
}

/// Read + parse the response head, skipping interim 1xx responses
/// (100-continue etc.; 101 is returned as-is).
fn readResponseHead(conn: *Conn) Error!h1.ResponseHead {
    while (true) {
        const block = h1.readHead(conn.plainReader(), conn.head_buf) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.ConnectionClosed => return error.ConnectionClosed,
            error.HeadTooLarge => return error.HeadTooLarge,
        };
        const head = h1.ResponseHead.parse(block) catch |err| switch (err) {
            error.MalformedHead => return error.MalformedResponse,
            error.UnsupportedVersion => return error.UnsupportedHttpVersion,
        };
        if (head.status >= 100 and head.status < 200 and head.status != 101) continue;
        return head;
    }
}

/// Select the body framing per RFC 7230 §3.3.3 (client side), and latch
/// whether this exchange leaves the connection eligible for the pool
/// (`conn.keep_alive_eligible`) — still gated on `isBodyDrained` once the
/// caller has actually read the body (or not) before it decides.
fn setupBody(conn: *Conn, method: http.Method, head: h1.ResponseHead) void {
    if (method == .head or head.status == 204 or head.status == 304) {
        conn.body = .{ .none = .fixed("") };
    } else if (head.chunked) {
        conn.body = .{ .chunked = h1.ChunkedReader.init(conn.plainReader(), conn.body_buf) };
    } else if (head.content_length) |n| {
        conn.body = .{ .limited = h1.ContentLengthReader.init(conn.plainReader(), n, conn.body_buf) };
    } else {
        conn.body = .until_close; // read to connection close
    }
    conn.keep_alive_eligible = keepAliveEligible(head) and conn.body != .until_close;
}

/// Header-level poolability (RFC 7230 §6.3 client side): never on an
/// explicit `Connection: close`, never on a `101` (the connection's
/// semantics changed entirely — e.g. WebSocket upgrade — so h1 request/
/// response framing no longer applies), never on an HTTP/1.0 response
/// unless it opted into `keep-alive` (1.0 defaults to closing). Body-length
/// framing (`until_close` can never be pooled — see the caller) is handled
/// separately since it depends on the body union, not just the head.
fn keepAliveEligible(head: h1.ResponseHead) bool {
    if (head.status == 101) return false;
    if (head.connection_close) return false;
    if (head.http1_0 and !head.connection_keep_alive) return false;
    return true;
}

/// Whether `conn`'s response body was read to completion with no framing
/// error — the other half (with `Conn.keep_alive_eligible`) of "may this
/// connection go back to the pool". A caller that `deinit`s a `Response`
/// without reading the whole body (or that hit a body read error) leaves
/// the connection in an indeterminate wire state, so it is closed instead,
/// never pooled — silently draining the rest for them here would be
/// surprise I/O in a `deinit` call, so this module does not attempt it.
fn isBodyDrained(conn: *const Conn) bool {
    return switch (conn.body) {
        .none => true,
        .limited => |r| r.remaining == 0 and !r.truncated,
        .chunked => |r| r.state == .done and r.fail_reason == null,
        .until_close, .unset => false,
    };
}

// ── tests (offline) ─────────────────────────────────────────────────────────

const testing = std.testing;

test "writeRequestHead: defaults" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const url = try http.Url.parse("http://example.com/x/y?q=1");
    try writeRequestHead(&w, .get, url, &.{}, "test-agent/1.0", .none, false, true);
    try testing.expectEqualStrings(
        "GET /x/y?q=1 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "User-Agent: test-agent/1.0\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
        w.buffered(),
    );
}

test "writeRequestHead: body plans, custom + managed headers" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const url = try http.Url.parse("https://[2001:db8::1]:8443/upload");
    try writeRequestHead(&w, .post, url, &.{
        .{ .name = "User-Agent", .value = "custom/2" },
        .{ .name = "X-Extra", .value = "1" },
        .{ .name = "Connection", .value = "keep-alive" }, // managed → ignored
        .{ .name = "Content-Length", .value = "999" }, // managed → ignored
    }, "default-agent", .{ .content_length = 11 }, false, true);
    try testing.expectEqualStrings(
        "POST /upload HTTP/1.1\r\n" ++
            "Host: [2001:db8::1]:8443\r\n" ++
            "User-Agent: custom/2\r\n" ++
            "X-Extra: 1\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 11\r\n" ++
            "\r\n",
        w.buffered(),
    );

    w = .fixed(&buf);
    try writeRequestHead(&w, .put, url, &.{}, "a", .chunked, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Content-Length") == null);
}

test "writeRequestHead: Authorization stripped on cross-host redirect" {
    var buf: [512]u8 = undefined;
    const url = try http.Url.parse("http://other.example/");
    const hdrs = [_]http.Header{.{ .name = "Authorization", .value = "Bearer secret" }};

    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);

    w = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, true, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
}

test "crossOrigin: scheme, host and port must ALL match (CVE-2018-18074 class)" {
    const base = try http.Url.parse("https://example.com/a");

    // Same origin, different path/query — not cross-origin.
    try testing.expect(!crossOrigin(base, try http.Url.parse("https://example.com/b?x=1")));
    // Host comparison is case-insensitive (DNS names).
    try testing.expect(!crossOrigin(base, try http.Url.parse("https://EXAMPLE.com/a")));
    // Explicit default port == implicit default port (both normalized by Url.parse).
    try testing.expect(!crossOrigin(base, try http.Url.parse("https://example.com:443/a")));

    // Same host, scheme downgrade https→http — cross-origin (must strip).
    try testing.expect(crossOrigin(base, try http.Url.parse("http://example.com/a")));
    // Same host+scheme, different (non-default) port — cross-origin.
    try testing.expect(crossOrigin(base, try http.Url.parse("https://example.com:8443/a")));
    // Different host entirely — cross-origin.
    try testing.expect(crossOrigin(base, try http.Url.parse("https://other.example/a")));
}

test "writeRequestHead: Authorization and Cookie both stripped on cross-origin redirect, both kept on same-origin" {
    var buf: [512]u8 = undefined;
    const url = try http.Url.parse("http://other.example/");
    const hdrs = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer secret" },
        .{ .name = "Cookie", .value = "session=abc123" },
    };

    // Same-origin hop: both credential headers are forwarded.
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie: session=abc123") != null);

    // Cross-origin hop: both are dropped (session-cookie / API-key leak
    // otherwise — Cookie is just as sensitive as Authorization here).
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, true, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);
}

test "request(): same-host scheme downgrade and same-host port change both strip Authorization+Cookie" {
    // Exercises the same origin computation `request()` uses
    // (`crossOrigin(original_url, url)`), offline: no network needed since
    // the decision only depends on the two parsed URLs.
    const original = try http.Url.parse("https://api.example/v1");
    const hdrs = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer secret" },
        .{ .name = "Cookie", .value = "session=abc123" },
    };
    var buf: [512]u8 = undefined;

    // Same host, https → http downgrade: must strip.
    const downgraded = try http.Url.parse("http://api.example/v1");
    try testing.expect(crossOrigin(original, downgraded));
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, downgraded, &hdrs, "a", .none, crossOrigin(original, downgraded), true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);

    // Same host+scheme, different port: must strip.
    const reported = try http.Url.parse("https://api.example:8443/v1");
    try testing.expect(crossOrigin(original, reported));
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, reported, &hdrs, "a", .none, crossOrigin(original, reported), true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);

    // Truly same-origin hop (path-only change): both preserved.
    const same_origin = try http.Url.parse("https://api.example/v2");
    try testing.expect(!crossOrigin(original, same_origin));
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, same_origin, &hdrs, "a", .none, crossOrigin(original, same_origin), true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie: session=abc123") != null);
}

test "redirect chain on fabricated responses" {
    // Hop 1: parse a fabricated 301 and compute the follow-up request.
    var hop1: std.Io.Reader = .fixed("HTTP/1.1 301 Moved Permanently\r\n" ++
        "Location: /v2/data\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    var head_buf: [1024]u8 = undefined;
    const head1 = try h1.ResponseHead.parse(try h1.readHead(&hop1, &head_buf));
    try testing.expectEqual(@as(u16, 301), head1.status);

    const base = try http.Url.parse("http://api.example:8080/v1/data?x=1");
    const method1 = http.redirectMethodFor(head1.status, .post).?;
    try testing.expectEqual(http.Method.get, method1); // POST → GET on 301

    var url_buf: [256]u8 = undefined;
    const next_url = try http.resolveLocation(base, head1.header("location").?, &url_buf);
    try testing.expectEqualStrings("http://api.example:8080/v2/data", next_url);

    // Hop 2: cross-host 307 — method preserved, host changes.
    var hop2: std.Io.Reader = .fixed("HTTP/1.1 307 Temporary Redirect\r\n" ++
        "Location: https://elsewhere.example/final\r\n" ++
        "\r\n");
    const head2 = try h1.ResponseHead.parse(try h1.readHead(&hop2, &head_buf));
    const method2 = http.redirectMethodFor(head2.status, .post).?;
    try testing.expectEqual(http.Method.post, method2);
    const hop2_url = try http.Url.parse(try http.resolveLocation(
        try http.Url.parse(next_url),
        head2.header("location").?,
        &url_buf,
    ));
    try testing.expectEqual(http.Url.Scheme.https, hop2_url.scheme);
    try testing.expectEqualStrings("elsewhere.example", hop2_url.host);

    // Hop 3: a 200 terminates the chain.
    var hop3: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    const head3 = try h1.ResponseHead.parse(try h1.readHead(&hop3, &head_buf));
    try testing.expectEqual(@as(?http.Method, null), http.redirectMethodFor(head3.status, method2));
}

test "setupBody framing decisions on fabricated heads" {
    // Fabricate a Conn without a socket — only the fields setupBody and the
    // body readers touch.
    var src: std.Io.Reader = .fixed("5\r\nhello\r\n0\r\n\r\n");
    var body_buf: [64]u8 = undefined;
    var conn: Conn = undefined;
    conn.tls_client = null;
    conn.body_buf = &body_buf;
    // plainReader() would hand out conn.sr; give it a fixed reader instead.
    conn.sr = undefined;

    const chunked_head = try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n");
    // Control: setupBody must SELECT chunked framing for this head. Without
    // this call the chunked branch of setupBody is never exercised here — the
    // body below was hand-built, so the decision under test was skipped.
    // The reader it installs points at conn.sr (not streamable in this
    // socket-free fixture), so only the selection is asserted.
    setupBody(&conn, .get, chunked_head);
    try testing.expect(conn.body == .chunked);
    // Re-point at a fixed reader to exercise the decode itself.
    conn.body = .{ .chunked = h1.ChunkedReader.init(&src, conn.body_buf) };
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    _ = try conn.body.chunked.reader.streamRemaining(&w);
    try testing.expectEqualStrings("hello", w.buffered());

    // HEAD → empty body regardless of headers.
    const cl_head = try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n");
    setupBody(&conn, .head, cl_head);
    try testing.expect(conn.body == .none);
    setupBody(&conn, .get, try h1.ResponseHead.parse("HTTP/1.1 204 No Content\r\n"));
    try testing.expect(conn.body == .none);
    // Content-Length → limited.
    setupBody(&conn, .get, cl_head);
    try testing.expect(conn.body == .limited);
    // Neither → read-until-close.
    setupBody(&conn, .get, try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\n"));
    try testing.expect(conn.body == .until_close);
}

// ── tests (h2c dogfood: our h2 client against our h2c server, loopback) ─────

const Server = @import("Server.zig");
const h2 = @import("h2.zig");

/// 200 KiB — far past the 65 535-octet initial flow-control window, so the
/// response only completes if the client keeps granting WINDOW_UPDATEs.
const huge_blocks = 200;

fn h2LoopbackHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        try rw.writeAll("hello h2");
    } else if (std.mem.eql(u8, req.path, "/echo")) {
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/huge")) {
        var block: [1024]u8 = undefined;
        for (0..huge_blocks) |i| {
            @memset(&block, 'A' + @as(u8, @intCast(i % 26)));
            try rw.writeAll(&block);
        }
    } else {
        rw.setStatus(404);
        try rw.writeAll("nope");
    }
}

fn h2ServeWrap(s: *Server) void {
    s.serve() catch {};
}

fn h2LoopbackServer(io: std.Io) !*Server {
    const server = try testing.allocator.create(Server);
    errdefer testing.allocator.destroy(server);
    server.* = Server.init(io, testing.allocator, .{
        .handler = h2LoopbackHandler,
        .enable_h2c = true,
    });
    server.bind() catch |err| {
        server.deinit();
        testing.allocator.destroy(server);
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    return server;
}

test "h2c dogfood: GET, POST and multiplexed requests on one connection (loopback)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try h2LoopbackServer(io);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    const hs = client.connectH2c("127.0.0.1", port, .{}) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer hs.close();

    { // GET: status + headers + body.
        const sid = try hs.request(.get, "/hello", .{});
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        try testing.expectEqualStrings("hello h2", res.body);
    }
    { // POST: the body crosses and comes back through the shared handler.
        const sid = try hs.request(.post, "/echo", .{ .body = "h2 upload body" });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("h2 upload body", res.body);
    }
    { // Multiplexing: two requests in flight on the same connection before
        // either response is read; collected in reverse order, each response
        // must match its own request.
        const sid_a = try hs.request(.post, "/echo", .{ .body = "first stream" });
        const sid_b = try hs.request(.post, "/echo", .{ .body = "second stream" });
        var res_b = try hs.awaitResponse(sid_b);
        defer res_b.deinit(gpa);
        var res_a = try hs.awaitResponse(sid_a);
        defer res_a.deinit(gpa);
        try testing.expectEqualStrings("second stream", res_b.body);
        try testing.expectEqualStrings("first stream", res_a.body);
    }
    { // 404 still carries a full response (not an error).
        const sid = try hs.request(.get, "/missing", .{});
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 404), res.status);
    }
}

test "h2c dogfood: large response streams past the initial window (flow control, loopback)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try h2LoopbackServer(io);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    const hs = client.connectH2c("127.0.0.1", port, .{}) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer hs.close();

    const sid = try hs.request(.get, "/huge", .{});
    var res = try hs.awaitResponse(sid);
    defer res.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqual(@as(usize, huge_blocks * 1024), res.body.len);
    for (0..huge_blocks) |i| {
        const expected: u8 = 'A' + @as(u8, @intCast(i % 26));
        try testing.expectEqual(expected, res.body[i * 1024]);
        try testing.expectEqual(expected, res.body[i * 1024 + 1023]);
    }
    // §6.9 reconciliation: every received octet was granted back, so the
    // connection receive window is back at its initial value — proof the
    // WINDOW_UPDATE path actually ran (the server could not have finished
    // a 200 KiB body inside a 64 KiB window otherwise).
    try testing.expectEqual(
        @as(i64, h2.default_initial_window_size),
        hs.session.conn.conn_recv_window,
    );
}

// ── tests (BYO-TLS seam dogfood: in-memory duplex pipe, no TLS, no sockets) ──

const h2s = @import("h2_server.zig");

/// One direction of the in-memory duplex "TLS stream" stand-in: a blocking
/// byte queue with a `Reader` and a `Writer` endpoint — exactly the
/// plaintext reader/writer shape a TLS library hands out after its
/// handshake. One reader task + one writer task; `shutdown` is the
/// writer-side close (readers drain what is buffered, then EOF). Not
/// movable after the endpoints have been handed out.
const TestPipe = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    data: std.array_list.Managed(u8),
    closed: bool = false,
    reader: std.Io.Reader,
    writer: std.Io.Writer,

    fn init(io: std.Io, rbuf: []u8, wbuf: []u8) TestPipe {
        return .{
            .io = io,
            .data = .init(testing.allocator),
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = rbuf,
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &.{ .drain = drainFn },
                .buffer = wbuf,
            },
        };
    }

    fn deinit(p: *TestPipe) void {
        p.data.deinit();
    }

    /// Writer side done: pending and future reads see EOF once drained.
    fn shutdown(p: *TestPipe) void {
        p.mutex.lockUncancelable(p.io);
        p.closed = true;
        p.cond.broadcast(p.io);
        p.mutex.unlock(p.io);
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const p: *TestPipe = @alignCast(@fieldParentPtr("reader", r));
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        while (p.data.items.len == 0) {
            if (p.closed) return error.EndOfStream;
            p.cond.waitUncancelable(p.io, &p.mutex);
        }
        const n = limit.minInt(p.data.items.len);
        const sent = w.write(p.data.items[0..n]) catch return error.WriteFailed;
        const remaining = p.data.items.len - sent;
        std.mem.copyForwards(u8, p.data.items[0..remaining], p.data.items[sent..]);
        p.data.shrinkRetainingCapacity(remaining);
        return sent;
    }

    fn drainFn(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const p: *TestPipe = @alignCast(@fieldParentPtr("writer", w));
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.data.appendSlice(w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            p.data.appendSlice(d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| p.data.appendSlice(last) catch return error.WriteFailed;
        consumed += last.len * splat;
        p.cond.signal(p.io);
        return consumed;
    }
};

/// The server side of the seam: HTTP/2 on one already-established stream,
/// exactly what a TLS accept loop calls when ALPN selected "h2".
fn tlsStandInServe(c2s: *TestPipe, s2c: *TestPipe) void {
    h2s.serveStream(testing.allocator, &c2s.reader, &s2c.writer, null, .{
        .handler = h2LoopbackHandler,
        .server_name = "h2tls",
    });
    s2c.shutdown(); // transport close after the h2 connection ended
}

test "BYO-TLS dogfood: connectH2Over ↔ serveStream over an in-memory duplex pipe" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The "TLS connection": one blocking in-memory byte queue per direction.
    // No TLS and no sockets anywhere — the seam only ever sees the plaintext
    // reader/writer pair, which is all a real TLS stream would present.
    var c2s_rbuf: [4096]u8 = undefined;
    var c2s_wbuf: [4096]u8 = undefined;
    var s2c_rbuf: [4096]u8 = undefined;
    var s2c_wbuf: [4096]u8 = undefined;
    var c2s: TestPipe = .init(io, &c2s_rbuf, &c2s_wbuf); // client → server
    defer c2s.deinit();
    var s2c: TestPipe = .init(io, &s2c_rbuf, &s2c_wbuf); // server → client
    defer s2c.deinit();

    // The caller's TLS layer negotiated ALPN (RFC 7301); dispatch on it.
    const negotiated = "h2"; // ← what the handshake would hand back
    try testing.expectEqual(http.AlpnProtocol.h2, http.protocolFromAlpn(negotiated));

    const thread = try std.Thread.spawn(.{}, tlsStandInServe, .{ &c2s, &s2c });
    defer thread.join();
    defer c2s.shutdown(); // client-side transport close (unblocks the server)

    const hs = try connectH2Over(gpa, &s2c.reader, &c2s.writer, "tls.test", .{});
    defer hs.close();

    { // GET round-trip.
        const sid = try hs.request(.get, "/hello", .{ .scheme = "https" });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        try testing.expectEqualStrings("hello h2", res.body);
        try testing.expectEqualStrings("h2tls", res.header("server").?);
    }
    { // POST round-trip: the request body crosses the pipe and comes back.
        const sid = try hs.request(.post, "/echo", .{
            .scheme = "https",
            .body = "over the TLS stand-in",
        });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("over the TLS stand-in", res.body);
    }
    { // Two concurrent streams in flight before either response is read;
        // collected in reverse order — demux by stream id must hold.
        const sid_a = try hs.request(.post, "/echo", .{ .scheme = "https", .body = "stream A" });
        const sid_b = try hs.request(.post, "/echo", .{ .scheme = "https", .body = "stream B" });
        var res_b = try hs.awaitResponse(sid_b);
        defer res_b.deinit(gpa);
        var res_a = try hs.awaitResponse(sid_a);
        defer res_a.deinit(gpa);
        try testing.expectEqualStrings("stream B", res_b.body);
        try testing.expectEqualStrings("stream A", res_a.body);
    }
}

// ── tests (live network — skipped when unavailable) ─────────────────────────

test "live: GET https://example.com round-trip" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = Client.init(io, testing.allocator, .{
        .connect_timeout_ms = 4000,
        .total_timeout_ms = 15000,
    });
    defer client.deinit();

    const body = client.getAlloc(testing.allocator, "https://example.com/", 1 << 20) catch |err| {
        std.debug.print("live network test skipped: {s}\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer testing.allocator.free(body);
    try testing.expect(body.len > 0);
    try testing.expect(std.mem.indexOf(u8, body, "Example") != null);
}

test "live: redirect follow (http → https)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = Client.init(io, testing.allocator, .{
        .connect_timeout_ms = 4000,
        .total_timeout_ms = 15000,
    });
    defer client.deinit();

    // www.example.com used to 3xx; if the world changed, accept any 2xx/3xx
    // completion — this test is about the transport, the redirect state
    // machine is unit-tested offline.
    var res = client.request(.get, "http://example.com/", .{}) catch |err| {
        std.debug.print("live network test skipped: {s}\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer res.deinit();
    try testing.expect(res.status >= 200 and res.status < 400);
}

// ── tests (connection pool: loopback + white-box) ────────────────────────────

/// GET → "ok"; POST → echoes the body. Used by every pool loopback test
/// below (a real `http.Server`, unmodified — it already supports h1
/// keep-alive, which is exactly what these tests exercise from the client
/// side).
fn poolTestHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (req.method == .post) {
        var buf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
        return;
    }
    try rw.writeAll("ok");
}

fn poolTestServeWrap(s: *Server) void {
    s.serve() catch {};
}

/// Read the whole body to completion, then `deinit` — a `Response` is only
/// pool-eligible once its body has actually been drained (see
/// `isBodyDrained`); these loopback tests care about *pooling*, not body
/// content, so they always fully drain before releasing.
fn drainAndDeinit(res: *Response) void {
    var sink: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&sink);
    _ = res.reader().streamRemaining(&w) catch {};
    res.deinit();
}

/// Bind a loopback `poolTestHandler` server (`max_requests_per_conn` 0 =
/// `Server`'s own effectively-unlimited default for these short tests).
/// Caller must spawn `poolTestServeWrap` on it and `defer server.shutdown()`
/// / `defer server.deinit()` / `defer testing.allocator.destroy(server)`,
/// same shape as the existing h2c-dogfood / proxy-integration loopback
/// helpers in this module.
fn poolTestLoopback(io: std.Io, max_requests_per_conn: u32) !*Server {
    const server = try testing.allocator.create(Server);
    errdefer testing.allocator.destroy(server);
    server.* = Server.init(io, testing.allocator, .{
        .handler = poolTestHandler,
        .max_requests_per_conn = if (max_requests_per_conn == 0) 1000 else max_requests_per_conn,
    });
    server.bind() catch |err| {
        server.deinit();
        testing.allocator.destroy(server);
        std.debug.print("pool test loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    return server;
}

test "pool: two sequential requests to the same origin reuse one connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    // Second request to the exact same origin: no re-dial — proof the pool
    // handed back the warm connection instead of opening a new one.
    var res2 = try client.request(.get, url, .{});
    drainAndDeinit(&res2);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
}

test "pool: requestStreaming also reuses pooled connections" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    {
        var up = try client.requestStreaming(.post, url, .{}, 5);
        try up.writer().writeAll("hello");
        var res = try up.finish();
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 64);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());

    {
        var up = try client.requestStreaming(.post, url, .{}, 5);
        try up.writer().writeAll("world");
        var res = try up.finish();
        defer res.deinit();
        const body = try res.readAllAlloc(testing.allocator, 64);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("world", body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount()); // reused, no re-dial
}

test "pool: distinct origins do not cross-pollinate" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_a = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server_a);
    defer server_a.deinit();
    const thread_a = try std.Thread.spawn(.{}, poolTestServeWrap, .{server_a});
    defer thread_a.join();
    defer server_a.shutdown();
    const port_a = server_a.boundAddress().getPort();

    const server_b = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server_b);
    defer server_b.deinit();
    const thread_b = try std.Thread.spawn(.{}, poolTestServeWrap, .{server_b});
    defer thread_b.join();
    defer server_b.shutdown();
    const port_b = server_b.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    const url_a = try std.fmt.bufPrint(&buf_a, "http://127.0.0.1:{d}/", .{port_a});
    const url_b = try std.fmt.bufPrint(&buf_b, "http://127.0.0.1:{d}/", .{port_b});

    var r1 = try client.request(.get, url_a, .{});
    drainAndDeinit(&r1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());

    var r2 = try client.request(.get, url_b, .{});
    drainAndDeinit(&r2);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    try testing.expectEqual(@as(usize, 2), client.poolIdleCount());

    // Re-requesting either origin reuses its own warm connection — no
    // re-dial, and never the other origin's connection.
    var r3 = try client.request(.get, url_a, .{});
    drainAndDeinit(&r3);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    var r4 = try client.request(.get, url_b, .{});
    drainAndDeinit(&r4);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
}

test "pool: a Connection: close response is not pooled" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // `max_requests_per_conn = 1` is an existing, unmodified `Server`
    // feature: it makes the server send `Connection: close` on the very
    // first response and end the connection — exactly the "server declined
    // to keep this alive" case the pool must respect.
    const server = try poolTestLoopback(io, 1);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    try testing.expect(res1.head.connection_close);
    res1.deinit();
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount()); // NOT pooled

    // A second request to the same origin has nothing to reuse — it must
    // dial again.
    var res2 = try client.request(.get, url, .{});
    res2.deinit();
    try testing.expectEqual(@as(usize, 2), client.dialCount());
}

/// One canned HTTP/1.1 200 response (Content-Length framed, no explicit
/// `Connection: close` — keep-alive-eligible per the client's own framing
/// rules), served over a raw accepted `net.Stream` and then hung up on —
/// exactly a peer that idle-timed-out a connection it had otherwise agreed
/// to keep alive. Used by the stale-connection-retry test below: a real
/// `http.Server` cannot be made to behave this uncooperatively (it always
/// advertises `Connection: close` before ending a connection), so this
/// fakes the origin at the raw-socket level instead, the same plumbing
/// (`net.Stream.reader`/`.writer`, `h1.readHead`) `Client`/`Server` both
/// build on.
fn staleConnOrigin(io: std.Io, listener: *net.Server, hung_up: *std.atomic.Value(bool)) void {
    const s1 = listener.accept(io) catch return;
    {
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s1.reader(io, &rbuf);
        var sw = s1.writer(io, &wbuf);
        var head_buf: [1024]u8 = undefined;
        _ = h1.readHead(&sr.interface, &head_buf) catch {};
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
        sw.interface.flush() catch {};
    }
    s1.close(io); // hang up — the client has no idea yet, it is not reading right now
    hung_up.store(true, .release);

    // The client's redial after it notices the first connection went stale.
    const s2 = listener.accept(io) catch return;
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = s2.reader(io, &rbuf);
    var sw = s2.writer(io, &wbuf);
    var head_buf: [1024]u8 = undefined;
    _ = h1.readHead(&sr.interface, &head_buf) catch {};
    sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
    sw.interface.flush() catch {};
    s2.close(io);
}

test "pool: a stale reused connection (peer already closed it) is retried once transparently" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("stale-conn test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var hung_up = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, staleConnOrigin, .{ io, &listener, &hung_up });
    defer thread.join();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    // Wait until the origin has actually hung up on connection #1 — avoids
    // a timing race against the assertions below (the pool doesn't need to
    // be told; it still believes the connection is good, exactly the
    // scenario the retry exists for).
    while (!hung_up.load(.acquire)) std.atomic.spinLoopHint();

    // The pool hands back the now-dead connection; the write and/or
    // response-head read against it fails in a way `isStaleConnError`
    // recognizes, and `request` transparently redials and resends against
    // the origin's second accepted connection — the caller never sees an
    // error.
    var res2 = try client.request(.get, url, .{});
    defer res2.deinit();
    try testing.expectEqual(@as(u16, 200), res2.status);
    const body = try res2.readAllAlloc(testing.allocator, 64);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("ok", body);
    try testing.expectEqual(@as(usize, 2), client.dialCount()); // original dial + the retry's redial
}

test "pool: max_idle_per_host and max_idle_total cap eviction (oldest first)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A bare listener is enough: `dialConn` only needs the TCP handshake to
    // complete, which the kernel does from its accept backlog even before
    // `accept()` is ever called — no need for a serving loop at all for
    // this bookkeeping-only test.
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("pool cap test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var url_buf: [64]u8 = undefined;
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port}));

    // Per-host cap: releasing a 3rd idle connection for the same origin
    // evicts the oldest (lowest `idle_since_ms`) of the first two.
    {
        var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_idle_per_host = 2, .max_idle_total = 100 } });
        defer client.deinit();
        const c0 = try client.dialConn(url);
        const c1 = try client.dialConn(url);
        const c2 = try client.dialConn(url);
        client.pool.release(c0, 100);
        client.pool.release(c1, 200);
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
        client.pool.release(c2, 300); // 3rd for this origin, cap = 2
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
    }

    // Total cap: same shape, but the cap that binds is the pool-wide one.
    {
        var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_idle_per_host = 100, .max_idle_total = 2 } });
        defer client.deinit();
        const c0 = try client.dialConn(url);
        const c1 = try client.dialConn(url);
        const c2 = try client.dialConn(url);
        client.pool.release(c0, 100);
        client.pool.release(c1, 200);
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
        client.pool.release(c2, 300);
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
    }
}

test "pool: idle_timeout_ms reaping via sweep" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("pool sweep test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var url_buf: [64]u8 = undefined;
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port}));

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .idle_timeout_ms = 100 } });
    defer client.deinit();

    const conn = try client.dialConn(url);
    client.pool.release(conn, 0); // idle_since_ms = 0
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    client.pool.sweep(50); // age 50ms <= 100ms: not stale yet
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    client.pool.sweep(150); // age 150ms > 100ms: reaped
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount());
}

test "pool: concurrent acquire/release from many threads is leak-free and race-free" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("pool concurrency test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_idle_per_host = 8, .max_idle_total = 8 } });
    defer client.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port}));

    const n_threads = 8;
    const iters = 200;

    const Worker = struct {
        fn run(c: *Client, u: http.Url, tid: usize) void {
            // Each thread only ever holds ONE connection object at a time —
            // exclusively either checked out (this thread's local `conn`)
            // or parked in the pool between `release` and the next
            // `acquire` — so there is never a concurrent touch of the same
            // `*Conn` from two threads; only the pool's own bookkeeping is
            // contended, which is exactly what this test exercises.
            var conn = c.dialConn(u) catch return;
            var now: i64 = @intCast(tid * 1_000_000);
            for (0..iters) |_| {
                c.pool.release(conn, now);
                now += 1;
                conn = c.pool.acquire(u.scheme, u.host, u.port, now) orelse (c.dialConn(u) catch return);
            }
            conn.destroy();
        }
    };

    var threads: [n_threads]std.Thread = undefined;
    for (0..n_threads) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ &client, url, i });
    for (threads) |t| t.join();

    // Whatever is left idle is freed by `client.deinit()` (deferred above);
    // `testing.allocator` catches any leak or double-free across the whole
    // run.
    try testing.expect(client.poolIdleCount() <= 8);
}
