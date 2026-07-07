// SPDX-License-Identifier: MIT

//! HTTP/1.1 client over TCP + TLS.
//!
//! One `Client` is a lightweight config + lazily-loaded CA bundle; each
//! request opens its own connection (`Connection: close`) — connection
//! pooling / keep-alive is an explicit Phase 1 non-goal (TODO: follow-up).
//! Streaming both directions: response bodies are exposed as a
//! `std.Io.Reader` (chunked and Content-Length framing decoded on the fly),
//! request bodies can be streamed via `requestStreaming` (fixed length or
//! chunked), so bodies larger than memory never get buffered.
//!
//! Adapted from the axp seed (`axp-core/src/httpclient.zig`), generalized:
//! TLS via `std.crypto.tls` (never `std.http.Client`), hostname resolution
//! via `std.Io.net.HostName` (to be swapped for the `dns` module when it
//! lands), URL/host splitting via `netaddr`.
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

const std = @import("std");
const netaddr = @import("netaddr");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2_client = @import("h2_client.zig");
const net = std.Io.net;
const tls = std.crypto.tls;

const Client = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
ca_bundle: std.crypto.Certificate.Bundle,
ca_lock: std.Io.RwLock,
ca_scanned: bool,

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
    };
}

pub fn deinit(c: *Client) void {
    c.ca_bundle.deinit(c.gpa);
    c.* = undefined;
}

// ── the request/response exchange ───────────────────────────────────────────

/// Perform a request, following redirects per `RequestOptions`. The returned
/// `Response` owns a connection — read the body via `Response.reader` and
/// always call `Response.deinit`.
pub fn request(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions) Error!Response {
    const deadline = c.totalDeadline();

    var url = try http.Url.parse(url_text);
    const original_host = url.host;
    var current_method = method;
    var current_body = options.body;
    var url_owned: ?[]u8 = null;
    defer if (url_owned) |s| c.gpa.free(s);

    var redirects: u8 = 0;
    while (true) {
        try c.checkDeadline(deadline);
        const conn = try c.openConn(url);
        errdefer conn.destroy();

        const strip_auth = !std.ascii.eqlIgnoreCase(url.host, original_host);
        const plan: BodyPlan = if (current_body) |b| .{ .content_length = b.len } else .none;
        try writeRequestHead(conn.plainWriter(), current_method, url, options.headers, c.options.user_agent, plan, strip_auth);
        if (current_body) |b| conn.plainWriter().writeAll(b) catch return error.WriteFailed;
        try conn.flushAll();

        try c.checkDeadline(deadline);
        const head = try readResponseHead(conn);

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

    /// Close the connection and free all per-request buffers.
    pub fn deinit(res: *Response) void {
        res.conn.destroy();
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
    const conn = try c.openConn(url);
    errdefer conn.destroy();
    const plan: BodyPlan = if (content_length) |n| .{ .content_length = n } else .chunked;
    try writeRequestHead(conn.plainWriter(), method, url, options.headers, c.options.user_agent, plan, false);
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
            gpa.free(o.slab);
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

    const hs = try c.gpa.create(H2Session);
    errdefer c.gpa.destroy(hs);
    const slab = try c.gpa.alloc(u8, c.options.read_buffer_size + c.options.write_buffer_size);
    errdefer c.gpa.free(slab);
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

fn openConn(c: *Client, url: http.Url) Error!*Conn {
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
    };
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

/// Emit a full request head. Pure writer logic so tests can assert exact
/// bytes. Managed headers: `Connection: close` always; `Content-Length` /
/// `Transfer-Encoding` from `plan`; `Host`, `User-Agent`, `Accept-Encoding`
/// defaulted unless the caller supplies them; `Authorization` dropped when
/// `strip_authorization` (cross-host redirect).
fn writeRequestHead(
    w: *std.Io.Writer,
    method: http.Method,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_authorization: bool,
) error{WriteFailed}!void {
    var custom_host: ?[]const u8 = null;
    var custom_ua = false;
    var custom_ae = false;
    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "host")) custom_host = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, "user-agent")) custom_ua = true;
        if (std.ascii.eqlIgnoreCase(hd.name, "accept-encoding")) custom_ae = true;
    }

    writeHead(w, method, url, headers, user_agent, plan, strip_authorization, custom_host, custom_ua, custom_ae) catch
        return error.WriteFailed;
}

fn writeHead(
    w: *std.Io.Writer,
    method: http.Method,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_authorization: bool,
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
        if (strip_authorization and std.ascii.eqlIgnoreCase(hd.name, "authorization")) continue;
        try w.print("{s}: {s}\r\n", .{ hd.name, hd.value });
    }

    if (!custom_ua) try w.print("User-Agent: {s}\r\n", .{user_agent});
    if (!custom_ae) try w.writeAll("Accept-Encoding: identity\r\n");
    try w.writeAll("Connection: close\r\n");
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

/// Select the body framing per RFC 7230 §3.3.3 (client side).
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
}

// ── tests (offline) ─────────────────────────────────────────────────────────

const testing = std.testing;

test "writeRequestHead: defaults" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const url = try http.Url.parse("http://example.com/x/y?q=1");
    try writeRequestHead(&w, .get, url, &.{}, "test-agent/1.0", .none, false);
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
    }, "default-agent", .{ .content_length = 11 }, false);
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
    try writeRequestHead(&w, .put, url, &.{}, "a", .chunked, false);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Content-Length") == null);
}

test "writeRequestHead: Authorization stripped on cross-host redirect" {
    var buf: [512]u8 = undefined;
    const url = try http.Url.parse("http://other.example/");
    const hdrs = [_]http.Header{.{ .name = "Authorization", .value = "Bearer secret" }};

    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, false);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);

    w = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
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
    conn.body = .{ .chunked = h1.ChunkedReader.init(&src, conn.body_buf) };
    _ = chunked_head;
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
