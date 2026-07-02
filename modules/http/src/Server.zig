//! HTTP/1.1 server: request codec + serving loop (Phase 2), modeled after
//! Go `net/http`'s Server (minimal subset). No TLS — Caddy (or any reverse
//! proxy) terminates TLS and forwards plain HTTP/1.1.
//!
//! Layering mirrors the client: `h1.zig` stays the pure wire codec (request
//! head parse, chunked/Content-Length framing); `serveStream` is the
//! per-connection HTTP state machine over any `std.Io.Reader`/`Writer` pair —
//! fully socket-free, which is what the offline tests (and the future
//! `router`) use; `Server` adds the TCP listener, accept loop and threads.
//!
//! Concurrency model: **task-per-connection** (Go's thread-per-connection
//! shape, expressed with `std.Io`). `serve` accepts on the caller's thread
//! and spawns one concurrent task per connection into an `Io.Group` — with
//! `std.Io.Threaded` that is one OS thread per connection; if the Io cannot
//! run the task concurrently the connection is served inline. The group is
//! awaited before `serve` returns, so no connection outlives it. The
//! handler runs on those connection tasks — it must be thread-safe if it
//! shares state. Concurrency *limiting* is deliberately out of scope (the
//! later `throttle` module); the kernel backlog is the only cap.
//!
//! Timeout model: a poll(2)-based read timeout bounds every read *stall*
//! (request head, body, keep-alive idle) at `read_timeout_ms`. A dribbling
//! client can extend the total head time — slowloris hardening belongs to
//! the later `abuseguard` module. On platforms without poll(2) the timeout
//! is compile-time disabled.

const std = @import("std");
const builtin = @import("builtin");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const net = std.Io.net;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const Server = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
listener: ?net.Server,
/// Tracks the per-connection tasks; awaited before `serve` returns.
group: std.Io.Group,

/// Called once per request, from the connection's thread. Errors turn into
/// a 500 when nothing was sent yet, otherwise the connection is closed.
pub const Handler = *const fn (*Request, *ResponseWriter) anyerror!void;

pub const Options = struct {
    handler: Handler,
    /// Opaque pointer handed to the handler as `Request.context`.
    context: ?*anyopaque = null,
    /// Listen address, an IP literal (this module does no name resolution).
    addr: []const u8 = "127.0.0.1",
    /// TCP port; 0 picks an ephemeral port (see `boundAddress`).
    port: u16 = 0,
    /// Max time a single read may stall (head wait, body wait, keep-alive
    /// idle) before the connection is dropped; 0 = no timeout.
    read_timeout_ms: u32 = 10_000,
    /// Per-connection read buffer; also bounds a single request head line.
    read_buffer_size: usize = 16 * 1024,
    /// Socket write buffer.
    write_buffer_size: usize = 4 * 1024,
    /// Upper bound for a whole request head (431 beyond it).
    max_head_bytes: usize = 16 * 1024,
    /// Response body buffering: bodies fully written within this get an
    /// exact Content-Length, larger ones stream chunked.
    response_buffer_size: usize = 4 * 1024,
    /// Auto `Server` response header, overridable per response.
    server_name: []const u8 = "zig-libs-http/0.1",
    kernel_backlog: u31 = 128,
    reuse_address: bool = false,
};

/// `io` must support the net + concurrency vtable operations (e.g.
/// `std.Io.Threaded`). The allocator provides per-connection buffers.
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Server {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .listener = null,
        .group = .init,
    };
}

/// Closes the listener if still open. Only call after `serve` returned.
pub fn deinit(s: *Server) void {
    if (s.listener) |*l| l.deinit(s.io);
    s.* = undefined;
}

pub const BindError = error{ BadAddress, ListenFailed, Canceled };

/// Bind + listen on `options.addr:port`. `boundAddress` is valid afterwards
/// (an ephemeral port is resolved). Split from `serve` so callers can learn
/// the port before serving; `listen` does both.
pub fn bind(s: *Server) BindError!void {
    std.debug.assert(s.listener == null);
    const addr = net.IpAddress.parse(s.options.addr, s.options.port) catch
        return error.BadAddress;
    s.listener = addr.listen(s.io, .{
        .kernel_backlog = s.options.kernel_backlog,
        .reuse_address = s.options.reuse_address,
    }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.ListenFailed,
    };
}

/// The address actually bound, with the resolved port — for ephemeral-port
/// (port 0) setups. Valid after `bind`.
pub fn boundAddress(s: *const Server) net.IpAddress {
    return s.listener.?.socket.address;
}

pub const ServeError = error{ AcceptFailed, Canceled };

/// Accept loop: dispatches connections until `shutdown` is called from
/// another thread (or accepting fails fatally), then waits for all
/// connection tasks to finish before returning. Call `bind` first.
pub fn serve(s: *Server) ServeError!void {
    defer s.group.await(s.io) catch {};
    const listener = &s.listener.?;
    while (true) {
        const stream = listener.accept(s.io) catch |err| switch (err) {
            error.SocketNotListening => return, // shutdown()
            error.Canceled => return error.Canceled,
            // Per-connection failures: keep accepting.
            error.ConnectionAborted,
            error.ProtocolFailure,
            error.BlockedByFirewall,
            => continue,
            // Resource exhaustion: back off briefly, keep accepting.
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            => {
                sleepMs(s.io, 50) catch return error.Canceled;
                continue;
            },
            else => return error.AcceptFailed,
        };
        s.group.concurrent(s.io, connMain, .{ s, stream }) catch {
            // No concurrency available: serve the connection inline rather
            // than drop it.
            connMain(s, stream);
        };
    }
}

/// Convenience: `bind` + `serve`.
pub fn listen(s: *Server) (BindError || ServeError)!void {
    try s.bind();
    try s.serve();
}

/// Stop accepting: wakes a blocked `serve`, which then drains connection
/// threads and returns. Safe to call from another thread while `serve` runs.
pub fn shutdown(s: *Server) void {
    const l = s.listener orelse return;
    const stream: net.Stream = .{ .socket = l.socket };
    stream.shutdown(s.io, .both) catch {};
}

fn sleepMs(io: std.Io, ms: u32) error{Canceled}!void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake };
    d.sleep(io) catch return error.Canceled;
}

// ── per-connection plumbing (socket side) ───────────────────────────────────

/// Interface buffer for the request-body decoders (mirrors the client).
const body_scratch_len = 4096;
/// Chunked-encoder scratch; only aggregates small writes, large writes pass
/// through as single chunks.
const chunk_scratch_len = 512;
/// How much unread request body to drain after the handler before giving up
/// on keep-alive (Go's maxPostHandlerReadBytes).
const max_unread_body_drain = 256 * 1024;

fn connMain(s: *Server, stream: net.Stream) void {
    defer stream.close(s.io);

    const o = &s.options;
    const total = o.read_buffer_size + o.write_buffer_size + o.max_head_bytes +
        o.response_buffer_size + body_scratch_len + chunk_scratch_len;
    const slab = s.gpa.alloc(u8, total) catch return; // overloaded: drop the connection
    defer s.gpa.free(slab);

    var off: usize = 0;
    const read_buf = slab[off..][0..o.read_buffer_size];
    off += o.read_buffer_size;
    const write_buf = slab[off..][0..o.write_buffer_size];
    off += o.write_buffer_size;
    const bufs: StreamBuffers = .{
        .head = slab[off..][0..o.max_head_bytes],
        .response_body = slab[off + o.max_head_bytes ..][0..o.response_buffer_size],
        .request_body = slab[off + o.max_head_bytes + o.response_buffer_size ..][0..body_scratch_len],
        .chunk = slab[off + o.max_head_bytes + o.response_buffer_size + body_scratch_len ..][0..chunk_scratch_len],
    };

    // All read buffering lives in the TimeoutReader (bounds head lines and
    // lets the timeout check see leftover bytes); the stream reader itself
    // is unbuffered.
    var sr = stream.reader(s.io, read_buf[0..0]);
    var tr: TimeoutReader = .init(&sr.interface, stream.socket.handle, o.read_timeout_ms, read_buf);
    var sw = stream.writer(s.io, write_buf);

    serveStream(.{
        .handler = o.handler,
        .context = o.context,
        .server_name = o.server_name,
        .now = .{ .ctx = @ptrCast(&s.io), .epochSeconds = ioEpochSeconds },
    }, &tr.reader, &sw.interface, bufs);
}

fn ioEpochSeconds(ctx: ?*anyopaque) i64 {
    const io: *const std.Io = @ptrCast(@alignCast(ctx.?));
    const ts = std.Io.Clock.real.now(io.*);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

const have_read_timeout = builtin.os.tag != .windows and std.posix.pollfd != void;

/// Wraps the connection reader: whenever a refill would block, first polls
/// the socket with the configured timeout; a stalled peer becomes
/// `error.ReadFailed` with `timed_out` set and the connection is dropped.
///
/// Not movable after `reader` has been handed out.
const TimeoutReader = struct {
    in: *Reader,
    handle: net.Socket.Handle,
    timeout_ms: u32,
    reader: Reader,
    timed_out: bool = false,

    fn init(in: *Reader, handle: net.Socket.Handle, timeout_ms: u32, buffer: []u8) TimeoutReader {
        return .{
            .in = in,
            .handle = handle,
            .timeout_ms = timeout_ms,
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const t: *TimeoutReader = @alignCast(@fieldParentPtr("reader", r));
        if (have_read_timeout and t.timeout_ms != 0 and t.in.bufferedLen() == 0) {
            var fds = [_]std.posix.pollfd{.{
                .fd = t.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const timeout: i32 = std.math.cast(i32, t.timeout_ms) orelse std.math.maxInt(i32);
            const ready = std.posix.poll(&fds, timeout) catch return error.ReadFailed;
            if (ready == 0) {
                t.timed_out = true;
                return error.ReadFailed;
            }
        }
        return t.in.stream(w, limit);
    }
};

// ── the socket-free per-connection state machine ────────────────────────────

/// Everything `serveStream` needs besides the byte streams — socket-free so
/// the whole codec is drivable from fixed buffers (offline tests, `router`).
pub const StreamOptions = struct {
    handler: Handler,
    context: ?*anyopaque = null,
    /// Auto `Server` response header; null = omit.
    server_name: ?[]const u8 = "zig-libs-http/0.1",
    /// Wall-clock source for the auto `Date` header; null = omit Date.
    now: ?Now = null,

    pub const Now = struct {
        ctx: ?*anyopaque = null,
        epochSeconds: *const fn (?*anyopaque) i64,
    };
};

/// Caller-supplied working memory for one connection.
pub const StreamBuffers = struct {
    /// Bounds a whole request head (431 beyond it).
    head: []u8,
    /// Request-body decoder interface buffer.
    request_body: []u8,
    /// Response body buffering; also the auto-Content-Length threshold.
    response_body: []u8,
    /// Chunked-encoder scratch (small, must be non-empty).
    chunk: []u8,
};

/// Serve HTTP/1.1 requests from `in`, responding on `out`, until the
/// connection is done (Connection: close, protocol error, read failure or a
/// clean client close). `out` is flushed after every response. Pure
/// Reader/Writer logic: the serving loop wraps it around a socket, tests
/// drive it with fixed buffers.
pub fn serveStream(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers) void {
    while (serveOne(opts, in, out, bufs) == .keep_alive) {}
}

const ConnDisposition = enum { keep_alive, close };

fn serveOne(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers) ConnDisposition {
    // Wait for the next request (keep-alive idle); any failure here — client
    // hung up between requests, idle timeout — is a quiet close.
    _ = in.peekByte() catch return .close;

    var date_buf: [http_date_len]u8 = undefined;
    const date: ?[]const u8 = if (opts.now) |n| formatHttpDate(n.epochSeconds(n.ctx), &date_buf) else null;

    const block = h1.readHead(in, bufs.head) catch |err| switch (err) {
        error.HeadTooLarge => return respondError(opts, out, date, 431),
        error.ReadFailed, error.ConnectionClosed => return .close,
    };
    const head = h1.RequestHead.parse(block) catch |err| return respondError(opts, out, date, switch (err) {
        error.UnsupportedVersion => 505,
        error.MalformedHead => 400,
    });

    // Semantic rejections (mirrors Go net/http): HTTP/1.1 requires Host; a
    // Transfer-Encoding without chunked leaves the body unframeable; only
    // methods in the shared vocabulary are dispatched.
    if (!head.http1_0 and head.host == null) return respondError(opts, out, date, 400);
    if (head.has_transfer_encoding and !head.chunked) return respondError(opts, out, date, 400);
    const method = methodFromToken(head.method) orelse return respondError(opts, out, date, 501);

    // Origin-form ("/path?query") and asterisk-form only — absolute-form is
    // a proxy concern and never appears behind a reverse proxy.
    if (head.target[0] != '/' and !std.mem.eql(u8, head.target, "*"))
        return respondError(opts, out, date, 400);
    var path: []const u8 = head.target;
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, head.target, '?')) |i| {
        path = head.target[0..i];
        query = head.target[i + 1 ..];
    }

    // Persistence: HTTP/1.1 defaults to keep-alive unless the client asked
    // to close; HTTP/1.0 always closes (keep-alive opt-in not implemented).
    const keep_alive = !head.http1_0 and !head.connection_close;

    const has_body = head.chunked or (head.content_length orelse 0) != 0;
    if (head.expect_continue and has_body) {
        out.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return .close;
        out.flush() catch return .close;
    }

    var body: RequestBody = .init(&head, in, bufs.request_body);
    var req: Request = .{
        .method = method,
        .target = head.target,
        .path = path,
        .query = query,
        .head = head,
        .body = &body,
        .context = opts.context,
    };
    var rw: ResponseWriter = .init(out, bufs.response_body, bufs.chunk, .{
        .head_request = method == .head,
        .http1_0 = head.http1_0,
        .date = date,
        .server_name = opts.server_name,
        .close_connection = !keep_alive,
    });

    opts.handler(&req, &rw) catch {
        // Nothing on the wire yet → a clean 500; otherwise the response
        // framing is broken and the connection must die.
        if (rw.sent_head) return .close;
        rw.reset();
        rw.setStatus(500);
        rw.setHeader("Content-Type", "text/plain") catch return .close;
        rw.writeAll("Internal Server Error\n") catch return .close;
    };
    rw.end() catch {
        // Framing failed. When nothing hit the wire yet (e.g. the body did
        // not match a declared Content-Length), a 500 still fits; either
        // way the connection is done.
        if (!rw.sent_head) _ = respondError(opts, out, date, 500);
        return .close;
    };
    out.flush() catch return .close;
    if (rw.connectionMustClose() or !keep_alive) return .close;

    // Drain what the handler left of the request body so the next head
    // parses; beyond a sanity cap just close (Go behavior).
    var drained: u64 = 0;
    const r = body.reader();
    while (true) {
        const n = r.discard(.limited(16 * 1024)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return .close,
        };
        drained += n;
        if (drained > max_unread_body_drain) return .close;
    }
    return .keep_alive;
}

fn respondError(opts: StreamOptions, out: *Writer, date: ?[]const u8, status: u16) ConnDisposition {
    writeErrorResponse(opts, out, date, status) catch {};
    out.flush() catch {};
    return .close;
}

fn writeErrorResponse(opts: StreamOptions, out: *Writer, date: ?[]const u8, status: u16) Writer.Error!void {
    const reason = reasonPhrase(status);
    try out.print("HTTP/1.1 {d} {s}\r\n", .{ status, reason });
    if (date) |d| try out.print("Date: {s}\r\n", .{d});
    if (opts.server_name) |sn| try out.print("Server: {s}\r\n", .{sn});
    try out.print("Content-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{reason.len + 1});
    try out.print("{s}\n", .{reason});
}

fn methodFromToken(token: []const u8) ?http.Method {
    inline for (@typeInfo(http.Method).@"enum".fields) |f| {
        const m: http.Method = @enumFromInt(f.value);
        if (std.mem.eql(u8, token, comptime m.token())) return m;
    }
    return null;
}

// ── the request ─────────────────────────────────────────────────────────────

/// One parsed request. All slices point into per-connection buffers — valid
/// for the duration of the handler call only.
pub const Request = struct {
    method: http.Method,
    /// Raw request-target as sent ("/path?q=1" or "*").
    target: []const u8,
    /// Target up to the '?' (the whole target when there is none).
    path: []const u8,
    /// Target after the '?', or "".
    query: []const u8,
    /// The parsed head, for framing fields beyond `header`/`iterateHeaders`.
    head: h1.RequestHead,
    body: *RequestBody,
    /// `Options.context` passthrough for stateful handlers.
    context: ?*anyopaque,

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(req: *const Request, name: []const u8) ?[]const u8 {
        return req.head.header(name);
    }

    /// Iterate all header name/value pairs in wire order.
    pub fn iterateHeaders(req: *const Request) h1.HeaderIterator {
        return req.head.iterate();
    }

    /// Streaming request-body reader — Content-Length / chunked framing
    /// already decoded; end-of-stream at the end of the body (immediately
    /// for bodyless requests).
    pub fn reader(req: *Request) *Reader {
        return req.body.reader();
    }
};

/// Framing-decoded request body (RFC 7230 §3.3.3, server side: chunked wins,
/// then Content-Length, else no body). Keep at a stable address once
/// `reader` has been handed out.
pub const RequestBody = union(enum) {
    none: Reader,
    limited: h1.ContentLengthReader,
    chunked: h1.ChunkedReader,

    pub fn init(head: *const h1.RequestHead, in: *Reader, scratch: []u8) RequestBody {
        if (head.chunked) return .{ .chunked = .init(in, scratch) };
        const n = head.content_length orelse 0;
        if (n != 0) return .{ .limited = .init(in, n, scratch) };
        return .{ .none = .fixed("") };
    }

    pub fn reader(b: *RequestBody) *Reader {
        return switch (b.*) {
            .none => |*r| r,
            .limited => |*lr| &lr.reader,
            .chunked => |*cr| &cr.reader,
        };
    }
};

// ── the response writer ─────────────────────────────────────────────────────

const max_response_headers = 32;

/// Response builder + body writer for one request. Buffers the body up to
/// its buffer's capacity: a handler that finishes within it gets an exact
/// automatic `Content-Length`; larger bodies switch to chunked streaming
/// transparently (Go net/http behavior). Works against any `*Writer` — no
/// socket required.
///
/// Managed headers: `Content-Length` (when set, selects identity framing
/// and the written byte count is enforced), `Connection` (only "close" is
/// honored), `Transfer-Encoding` (ignored — framing is the writer's job);
/// `Date` and `Server` are added automatically unless set. Header
/// name/value slices must outlive the response. HEAD/204/304 responses
/// discard body writes and frame correctly.
///
/// Not movable once `writer` has been handed out.
pub const ResponseWriter = struct {
    out: *Writer,
    chunk_buf: []u8,
    date: ?[]const u8,
    server_name: ?[]const u8,
    head_request: bool,
    http1_0: bool,
    close_connection: bool,
    status: u16 = 200,
    headers: [max_response_headers]http.Header = undefined,
    headers_len: usize = 0,
    /// Explicit Content-Length set via `setHeader`.
    declared_len: ?u64 = null,
    sent_head: bool = false,
    ended: bool = false,
    failed: bool = false,
    body: BodySink = .buffering,
    interface: Writer,

    const BodySink = union(enum) {
        /// Head unsent; body accumulates in the interface buffer.
        buffering,
        /// Streaming with `Transfer-Encoding: chunked`.
        chunked: h1.ChunkedWriter,
        /// Streaming against an explicit Content-Length; payload = bytes
        /// still owed.
        identity: u64,
        /// HTTP/1.0 fallback: identity body delimited by connection close.
        until_close,
        /// HEAD / 204 / 304: body writes are dropped.
        discard,
    };

    pub const InitOptions = struct {
        /// Response to a HEAD request: correct framing, no body bytes.
        head_request: bool = false,
        /// HTTP/1.0 peer: never emit chunked framing.
        http1_0: bool = false,
        /// Preformatted IMF-fixdate for the auto Date header; null = omit.
        date: ?[]const u8 = null,
        /// Auto Server header; null = omit.
        server_name: ?[]const u8 = null,
        /// Emit `Connection: close` (the connection won't be reused).
        close_connection: bool = false,
    };

    /// `body_buf` is the buffering/auto-Content-Length threshold;
    /// `chunk_buf` is small scratch for the chunked encoder (non-empty).
    pub fn init(out: *Writer, body_buf: []u8, chunk_buf: []u8, opts: InitOptions) ResponseWriter {
        return .{
            .out = out,
            .chunk_buf = chunk_buf,
            .date = opts.date,
            .server_name = opts.server_name,
            .head_request = opts.head_request,
            .http1_0 = opts.http1_0,
            .close_connection = opts.close_connection,
            .interface = .{
                .vtable = &.{ .drain = drainFn },
                .buffer = body_buf,
            },
        };
    }

    /// Set the response status (default 200). Ignored once the head is on
    /// the wire (mirrors Go's "superfluous WriteHeader").
    pub fn setStatus(rw: *ResponseWriter, status: u16) void {
        if (!rw.sent_head) rw.status = status;
    }

    pub const SetHeaderError = error{ HeadersSent, TooManyHeaders, InvalidHeader };

    /// Set a header, replacing an existing one of the same name
    /// (case-insensitive). See the managed-header rules in the type doc.
    pub fn setHeader(rw: *ResponseWriter, name: []const u8, value: []const u8) SetHeaderError!void {
        if (rw.sent_head) return error.HeadersSent;
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            rw.declared_len = std.fmt.parseInt(u64, value, 10) catch return error.InvalidHeader;
            return;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return; // managed
        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (h1.tokenListContains(value, "close")) rw.close_connection = true;
            return;
        }
        for (rw.headers[0..rw.headers_len]) |*hd| {
            if (std.ascii.eqlIgnoreCase(hd.name, name)) {
                hd.* = .{ .name = name, .value = value };
                return;
            }
        }
        if (rw.headers_len == max_response_headers) return error.TooManyHeaders;
        rw.headers[rw.headers_len] = .{ .name = name, .value = value };
        rw.headers_len += 1;
    }

    /// The response-body writer. First use beyond the buffer capacity (or a
    /// flush) puts the head on the wire and locks status + headers.
    pub fn writer(rw: *ResponseWriter) *Writer {
        return &rw.interface;
    }

    /// Convenience full-body write (same as `writer().writeAll`).
    pub fn writeAll(rw: *ResponseWriter, bytes: []const u8) Writer.Error!void {
        return rw.interface.writeAll(bytes);
    }

    /// True once the response head is on the wire.
    pub fn headSent(rw: *const ResponseWriter) bool {
        return rw.sent_head;
    }

    /// Whether the connection must close after this response (explicit
    /// Connection: close, HTTP/1.0 until-close body, or broken framing).
    pub fn connectionMustClose(rw: *const ResponseWriter) bool {
        return rw.failed or rw.close_connection;
    }

    /// Finish the response: emits the head with an exact Content-Length when
    /// the whole body fit the buffer, otherwise terminates the chunked
    /// stream / validates the declared length. Idempotent; the serving loop
    /// calls it after the handler, so handlers may omit it. Does not flush
    /// `out`.
    pub fn end(rw: *ResponseWriter) Writer.Error!void {
        if (rw.ended) return;
        rw.ended = true;
        switch (rw.body) {
            .buffering => {
                const body_bytes = rw.interface.buffered();
                defer rw.interface.end = 0;
                if (rw.noBody()) {
                    // HEAD mirrors GET framing when the length is known.
                    const framing: Framing = if (rw.declared_len) |n|
                        .{ .content_length = n }
                    else if (rw.head_request and body_bytes.len != 0)
                        .{ .content_length = body_bytes.len }
                    else
                        .none;
                    try rw.writeHead(framing);
                } else {
                    const n = rw.declared_len orelse body_bytes.len;
                    if (n != body_bytes.len) {
                        rw.failed = true; // body ≠ declared Content-Length
                        return error.WriteFailed;
                    }
                    try rw.writeHead(.{ .content_length = n });
                    try rw.out.writeAll(body_bytes);
                }
            },
            .chunked => {
                try rw.interface.flush();
                try rw.body.chunked.finish();
            },
            .identity => {
                try rw.interface.flush();
                if (rw.body.identity != 0) {
                    rw.failed = true; // under-delivered declared length
                    return error.WriteFailed;
                }
            },
            .until_close, .discard => try rw.interface.flush(),
        }
    }

    /// Revert to a fresh response — only while nothing is on the wire
    /// (used for the automatic 500 on handler errors).
    fn reset(rw: *ResponseWriter) void {
        std.debug.assert(!rw.sent_head);
        rw.status = 200;
        rw.headers_len = 0;
        rw.declared_len = null;
        rw.ended = false;
        rw.failed = false;
        rw.body = .buffering;
        rw.interface.end = 0;
    }

    fn noBody(rw: *const ResponseWriter) bool {
        return rw.head_request or rw.status == 204 or rw.status == 304 or
            (rw.status >= 100 and rw.status < 200);
    }

    const Framing = union(enum) { none, content_length: u64, chunked };

    /// Emit the status line + headers. Header order: user headers (set
    /// order), then auto Date/Server, Connection, framing.
    fn writeHead(rw: *ResponseWriter, framing: Framing) Writer.Error!void {
        const out = rw.out;
        try out.print("HTTP/1.1 {d} {s}\r\n", .{ rw.status, reasonPhrase(rw.status) });

        var saw_date = false;
        var saw_server = false;
        for (rw.headers[0..rw.headers_len]) |hd| {
            if (std.ascii.eqlIgnoreCase(hd.name, "date")) saw_date = true;
            if (std.ascii.eqlIgnoreCase(hd.name, "server")) saw_server = true;
            try out.print("{s}: {s}\r\n", .{ hd.name, hd.value });
        }
        if (!saw_date) if (rw.date) |d| try out.print("Date: {s}\r\n", .{d});
        if (!saw_server) if (rw.server_name) |sn| try out.print("Server: {s}\r\n", .{sn});
        if (rw.close_connection) try out.writeAll("Connection: close\r\n");
        switch (framing) {
            .none => {},
            .content_length => |n| try out.print("Content-Length: {d}\r\n", .{n}),
            .chunked => try out.writeAll("Transfer-Encoding: chunked\r\n"),
        }
        try out.writeAll("\r\n");
        rw.sent_head = true;
    }

    /// Put the head on the wire and pick the streaming framing. Called on
    /// the first drain (body outgrew the buffer, or the handler flushed).
    fn beginStreaming(rw: *ResponseWriter) Writer.Error!void {
        std.debug.assert(!rw.sent_head);
        if (rw.noBody()) {
            const framing: Framing = if (rw.declared_len) |n| .{ .content_length = n } else .none;
            try rw.writeHead(framing);
            rw.body = .discard;
        } else if (rw.declared_len) |n| {
            try rw.writeHead(.{ .content_length = n });
            rw.body = .{ .identity = n };
        } else if (rw.http1_0) {
            // HTTP/1.0 peers do not understand chunked: identity body
            // delimited by connection close.
            rw.close_connection = true;
            try rw.writeHead(.none);
            rw.body = .until_close;
        } else {
            try rw.writeHead(.chunked);
            rw.body = .{ .chunked = .init(rw.out, rw.chunk_buf) };
        }
    }

    fn drainFn(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const rw: *ResponseWriter = @alignCast(@fieldParentPtr("interface", w));
        if (rw.body == .buffering) try rw.beginStreaming();
        switch (rw.body) {
            .buffering => unreachable,
            .chunked => |*cw| return forwardDrain(w, &cw.writer, data, splat),
            .until_close => return forwardDrain(w, rw.out, data, splat),
            .identity => {
                var total: u64 = w.end;
                for (data[0 .. data.len - 1]) |d| total += d.len;
                total += data[data.len - 1].len * splat;
                if (total > rw.body.identity) {
                    rw.failed = true; // more body than the declared Content-Length
                    return error.WriteFailed;
                }
                const consumed = try forwardDrain(w, rw.out, data, splat);
                rw.body.identity -= total;
                return consumed;
            },
            .discard => {
                var consumed: usize = 0;
                for (data[0 .. data.len - 1]) |d| consumed += d.len;
                consumed += data[data.len - 1].len * splat;
                w.end = 0;
                return consumed;
            },
        }
    }

    /// Forward the interface buffer plus `data`/`splat` into `inner`,
    /// honoring the drain contract (returns bytes consumed from `data`).
    fn forwardDrain(w: *Writer, inner: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        try inner.writeAll(w.buffered());
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try inner.writeAll(d);
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try inner.writeAll(last);
        consumed += last.len * splat;
        return consumed;
    }
};

/// Canonical reason phrase for common status codes; "" when unknown (the
/// status line stays valid: "HTTP/1.1 599 \r\n").
pub fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        else => "",
    };
}

/// Length of an IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT").
pub const http_date_len = 29;

/// Format epoch seconds as an RFC 9110 IMF-fixdate for Date headers.
pub fn formatHttpDate(epoch_seconds: i64, buf: *[http_date_len]u8) []const u8 {
    const day_names = [7][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const month_names = [12][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(0, epoch_seconds)) };
    const day = es.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const secs = es.getDaySeconds();
    var w: Writer = .fixed(buf);
    w.print("{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[day.day % 7], // 1970-01-01 was a Thursday
        month_day.day_index + 1,
        month_names[month_day.month.numeric() - 1],
        year_day.year,
        secs.getHoursIntoDay(),
        secs.getMinutesIntoHour(),
        secs.getSecondsIntoMinute(),
    }) catch unreachable;
    return w.buffered();
}

// ── tests (offline — the codec without a socket) ────────────────────────────

const testing = std.testing;

const Hits = std.atomic.Value(u32);

fn bumpHits(req: *Request) void {
    if (req.context) |ctx| {
        const hits: *Hits = @ptrCast(@alignCast(ctx));
        _ = hits.fetchAdd(1, .monotonic);
    }
}

/// 87 bytes (0x57) — longer than the offline response buffer (64) so it
/// forces chunked streaming there.
const big_body = ("0123456789" ** 8) ++ "ABCDEFG";

fn testHandler(req: *Request, rw: *ResponseWriter) anyerror!void {
    bumpHits(req);
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        if (req.query.len != 0) try rw.setHeader("X-Query", req.query);
        try rw.writeAll("hello");
    } else if (std.mem.eql(u8, req.path, "/echo")) {
        var buf: [512]u8 = undefined;
        var w: Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/big")) {
        try rw.writeAll(big_body);
    } else if (std.mem.eql(u8, req.path, "/nocontent")) {
        rw.setStatus(204);
    } else if (std.mem.eql(u8, req.path, "/declared")) {
        try rw.setHeader("Content-Length", "5");
        try rw.writeAll("12345");
    } else if (std.mem.eql(u8, req.path, "/short")) {
        try rw.setHeader("Content-Length", "10");
        try rw.writeAll("only5"); // deliberately under-delivers
    } else if (std.mem.eql(u8, req.path, "/identbig")) {
        var len_buf: [8]u8 = undefined;
        try rw.setHeader("Content-Length", try std.fmt.bufPrint(&len_buf, "{d}", .{big_body.len}));
        try rw.writeAll(big_body);
    } else if (std.mem.eql(u8, req.path, "/overrun")) {
        try rw.setHeader("Content-Length", "5");
        try rw.writeAll(big_body); // deliberately over-delivers
    } else if (std.mem.eql(u8, req.path, "/fail")) {
        try rw.setHeader("X-Dropped", "yes");
        try rw.writeAll("partial");
        return error.Boom;
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

fn fixedEpoch(_: ?*anyopaque) i64 {
    return 784111777; // Sun, 06 Nov 1994 08:49:37 GMT (RFC 9110's example)
}

const test_date = "Sun, 06 Nov 1994 08:49:37 GMT";

/// Run `serveStream` over canned wire bytes with small test buffers
/// (response buffer 64 → bodies beyond it stream chunked).
fn runStream(ctx: ?*anyopaque, wire: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(wire);
    var out: Writer = .fixed(out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [64]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    serveStream(.{
        .handler = testHandler,
        .context = ctx,
        .server_name = "test",
        .now = .{ .epochSeconds = fixedEpoch },
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "serveStream: golden fixed-length response" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello", got);
}

test "serveStream: golden chunked response when the body outgrows the buffer" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /big HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "57\r\n" ++ big_body ++ "\r\n0\r\n\r\n", got);
}

test "serveStream: golden HEAD framing without a body" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "HEAD /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n", got);
}

test "serveStream: golden 204 — no Content-Length, no body" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /nocontent HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 204 No Content\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "\r\n", got);
}

test "serveStream: keep-alive serves two requests from one buffer" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    const got = runStream(&hits, "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "\r\n\r\nhello"));
    // Only the second response announces the close.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "Connection: close\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "Connection: close").? > std.mem.indexOf(u8, got, "hello").?);
}

test "serveStream: Content-Length request body reaches the handler" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length: 5\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nhello"));
}

test "serveStream: chunked request body is decoded for the handler" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "POST /echo HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length: 9\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nWikipedia"));
}

test "serveStream: unread request body is drained before the next request" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    const got = runStream(&hits, "POST /hello HTTP/1.1\r\nHost: t\r\nContent-Length: 6\r\n\r\nignore" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "HTTP/1.1 200 OK\r\n"));
}

test "serveStream: Expect: 100-continue is acknowledged before the body read" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello", &out_buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nhello"));
}

test "serveStream: malformed request line → golden 400, connection closes" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    const got = runStream(&hits, "BOGUS\r\n\r\nGET /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 400 Bad Request\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 12\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "Bad Request\n", got);
    // The pipelined request after the garbage was never served.
    try testing.expectEqual(@as(u32, 0), hits.load(.monotonic));
}

test "serveStream: protocol rejections (505, 501, 400s, 431)" {
    var out_buf: [4096]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET / HTTP/2.0\r\n\r\n", &out_buf), "HTTP/1.1 505 HTTP Version Not Supported\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "BREW /pot HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 501 Not Implemented\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET / HTTP/1.1\r\n\r\n", &out_buf), // missing Host
        "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: gzip\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET http://x/ HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), // absolute-form
        "HTTP/1.1 400 Bad Request\r\n"));
    const long_head = "GET / HTTP/1.1\r\nHost: t\r\nX-Big: " ++ ("a" ** 2000) ++ "\r\n\r\n";
    try testing.expect(std.mem.startsWith(u8, runStream(null, long_head, &out_buf), "HTTP/1.1 431 Request Header Fields Too Large\r\n"));
}

test "serveStream: handler error → clean 500, keep-alive survives" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    const got = runStream(&hits, "GET /fail HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 500 Internal Server Error\r\n"));
    // The partial body and headers staged before the error were dropped.
    try testing.expect(std.mem.indexOf(u8, got, "partial") == null);
    try testing.expect(std.mem.indexOf(u8, got, "X-Dropped") == null);
    try testing.expect(std.mem.indexOf(u8, got, "Internal Server Error\n") != null);
    // The connection stayed usable for the next request.
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nhello"));
}

test "serveStream: explicit Content-Length responses" {
    var out_buf: [4096]u8 = undefined;
    // Declared and delivered within the buffer.
    try testing.expect(std.mem.endsWith(u8, runStream(null, "GET /declared HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "Content-Length: 5\r\n\r\n12345"));
    // Declared and streamed past the buffer (identity framing, no chunking).
    const ident = runStream(null, "GET /identbig HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, ident, "Content-Length: 87\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, ident, "Transfer-Encoding") == null);
    try testing.expect(std.mem.endsWith(u8, ident, "\r\n\r\n" ++ big_body));
}

test "serveStream: broken declared Content-Length closes the connection" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    // Under-delivery is caught before the head is sent → 500 + close.
    const short = runStream(&hits, "GET /short HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, short, "HTTP/1.1 500 Internal Server Error\r\n"));
    try testing.expectEqual(@as(u32, 1), hits.load(.monotonic)); // pipelined request dropped

    // Over-delivery mid-stream: head already sent → connection just dies.
    hits = .init(0);
    const over = runStream(&hits, "GET /overrun HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, over, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.endsWith(u8, over, "Content-Length: 5\r\n\r\n")); // no body followed
    try testing.expectEqual(@as(u32, 1), hits.load(.monotonic));
}

test "serveStream: HTTP/1.0 gets identity-until-close instead of chunked" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /big HTTP/1.0\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "Connection: close\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Transfer-Encoding") == null);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length") == null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\n" ++ big_body));
}

test "ResponseWriter: standalone against any writer (no socket, no loop)" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    rw.setStatus(201);
    try rw.setHeader("X-Id", "42");
    try rw.setHeader("X-Id", "43"); // replaces
    try rw.writeAll("created");
    try rw.end();
    try rw.end(); // idempotent
    try testing.expectEqualStrings("HTTP/1.1 201 Created\r\n" ++
        "X-Id: 43\r\n" ++
        "Content-Length: 7\r\n" ++
        "\r\n" ++
        "created", out.buffered());
}

test "ResponseWriter: header validation and managed headers" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    try testing.expectError(error.InvalidHeader, rw.setHeader("Content-Length", "12x"));
    try rw.setHeader("Transfer-Encoding", "chunked"); // managed → dropped
    try rw.setHeader("Connection", "close"); // managed → close flag
    try testing.expect(rw.connectionMustClose());
    try rw.end();
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", out.buffered());
    try testing.expectError(error.HeadersSent, rw.setHeader("X-Late", "1"));
}

test "request codec: standalone parse + body decode from fixed bytes" {
    var in: Reader = .fixed("POST /up?k=v HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "3\r\nabc\r\n0\r\n\r\n");
    var head_buf: [256]u8 = undefined;
    const head = try h1.RequestHead.parse(try h1.readHead(&in, &head_buf));
    try testing.expectEqualStrings("POST", head.method);
    try testing.expectEqualStrings("/up?k=v", head.target);
    try testing.expect(head.chunked);

    var scratch: [64]u8 = undefined;
    var body: RequestBody = .init(&head, &in, &scratch);
    var plain: [64]u8 = undefined;
    var w: Writer = .fixed(&plain);
    _ = try body.reader().streamRemaining(&w);
    try testing.expectEqualStrings("abc", w.buffered());
}

test "formatHttpDate" {
    var buf: [http_date_len]u8 = undefined;
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(0, &buf));
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", formatHttpDate(784111777, &buf));
    try testing.expectEqualStrings("Thu, 29 Feb 2024 00:00:00 GMT", formatHttpDate(1709164800, &buf));
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(-5, &buf)); // clamped
}

test "methodFromToken" {
    try testing.expectEqual(@as(?http.Method, .get), methodFromToken("GET"));
    try testing.expectEqual(@as(?http.Method, .delete), methodFromToken("DELETE"));
    try testing.expectEqual(@as(?http.Method, null), methodFromToken("get")); // case-sensitive
    try testing.expectEqual(@as(?http.Method, null), methodFromToken("BREW"));
}

// ── tests (in-process integration — Phase-1 client vs this server) ──────────

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

test "integration: Phase-1 client drives the server over loopback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var hits: Hits = .init(0);
    var server = init(io, testing.allocator, .{
        .handler = testHandler,
        .context = &hits,
        .server_name = "zl-test",
        // Small response buffer so /big streams chunked over the real wire.
        .response_buffer_size = 32,
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // GET with a query string
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello?x=1", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        try testing.expectEqualStrings("x=1", res.header("x-query").?);
        try testing.expectEqualStrings("zl-test", res.header("server").?);
        try testing.expect(std.mem.endsWith(u8, res.header("date").?, "GMT"));
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }

    { // POST with a body → echoed back
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/echo", .{port});
        var res = try client.request(.post, url, .{ .body = "ping pong data" });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("ping pong data", body);
    }

    { // Client reuse: server streams chunked, client decodes it
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/big", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(res.head.chunked);
        const body = try res.readAllAlloc(testing.allocator, 4096);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(big_body, body);
    }

    try testing.expectEqual(@as(u32, 3), hits.load(.monotonic));
}

test "integration: keep-alive — two requests on one TCP connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var hits: Hits = .init(0);
    var server = init(io, testing.allocator, .{ .handler = testHandler, .context = &hits });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const addr = server.boundAddress();
    const stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [8192]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var head_buf: [2048]u8 = undefined;

    // Request 1 — server must keep the connection open.
    try sw.interface.writeAll("GET /hello HTTP/1.1\r\nHost: t\r\n\r\n");
    try sw.interface.flush();
    const res1 = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
    try testing.expectEqual(@as(u16, 200), res1.status);
    try testing.expect(!res1.connection_close);
    try testing.expectEqual(@as(?u64, 5), res1.content_length);
    try testing.expectEqualStrings("hello", try sr.interface.take(5));

    // Request 2 on the same connection — asks for close, server honors it.
    try sw.interface.writeAll("GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try sw.interface.flush();
    const res2 = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
    try testing.expectEqual(@as(u16, 200), res2.status);
    try testing.expect(res2.connection_close);
    try testing.expectEqualStrings("hello", try sr.interface.take(5));

    // …and the server actually closes.
    try testing.expectError(error.EndOfStream, sr.interface.take(1));
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
}

test "integration: stalled client is dropped after the read timeout" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = init(io, testing.allocator, .{ .handler = testHandler, .read_timeout_ms = 150 });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [256]u8 = undefined;
    var wbuf: [256]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // Send half a request head, then stall — the server must drop us.
    try sw.interface.writeAll("GET /hel");
    try sw.interface.flush();
    try testing.expectError(error.EndOfStream, sr.interface.take(1));
}
