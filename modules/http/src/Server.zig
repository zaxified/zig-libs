// SPDX-License-Identifier: MIT

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
//! Timeout model (poll(2)-based; compile-time disabled where poll is
//! unavailable): `read_timeout_ms` bounds every read *stall* (request head,
//! body, keep-alive idle); `request_timeout_ms` is a whole-request read
//! deadline (Go ReadTimeout shape: keep-alive idle + head + body share one
//! budget, so a dribbling client cannot stretch a request forever);
//! `write_timeout_ms` bounds every write stall (a peer that stops reading).
//!
//! Hardening (Phase 2.1, SPEC-http-hardening.md) — built to face the
//! internet without a reverse proxy: the handler sees the socket peer
//! address and a per-connection request index (`Request.peerAddress` /
//! `Request.connRequestIndex`); `Options.on_connect` accepts or rejects a
//! connection right after accept (the mechanism for `abuseguard`'s per-IP
//! caps + bans; a reject closes the socket silently, see the option doc);
//! `Server.activeConnections()` exposes a thread-safe connection count;
//! size limits answer 431 (`max_header_bytes`), 414
//! (`max_request_line_bytes`) and 413 (`max_body_bytes` — an oversized
//! declared Content-Length is refused before the handler runs, a chunked
//! body is capped while streaming; a request body is never buffered). An
//! optional Go-ConnState-style `on_conn_state` callback observes
//! new/active/idle/closed transitions for metrics.
//!
//! Compression (Phase 2.2, SPEC-http-gzip.md): `Options.compression`
//! (null = off) enables negotiated gzip response compression. Eligible
//! responses — the request's Accept-Encoding admits gzip, the
//! content-type is on the allowlist, the body is worth it — are
//! compressed transparently (handler code unchanged), **streaming**:
//! handler bytes → `std.compress.flate` gzip encoder → the existing
//! chunked framing (an explicit Content-Length is dropped from the wire,
//! like Go's gzip middleware / nginx — the byte count is still
//! enforced). `Vary: Accept-Encoding` goes on every response while
//! enabled. Negotiation/eligibility helpers live in `gzip.zig`.
//!
//! HTTP/2 (Phase 3.1, opt-in): with `Options.enable_h2c` a connection
//! that opens with the HTTP/2 client preface (RFC 9113 §3.3 prior
//! knowledge — the only cleartext path; RFC 9113 removed `Upgrade: h2c`)
//! is served by `h2_server.zig` through the same `Options.handler`;
//! everything else takes the HTTP/1.1 loop below unchanged.
//!
//! Bring-your-own-TLS (Phase 3.3): `serveStream` doubles as the
//! h1-over-provided-stream entry — a caller that terminates TLS itself
//! dispatches on the negotiated ALPN protocol (`http.protocolFromAlpn`,
//! RFC 7301) and hands the TLS connection's plaintext reader/writer either
//! here (`.http11`/`.unknown`) or to `h2_server.serveStream` (`.h2`); pass
//! the socket peer via `StreamOptions.peer` so `Request.peerAddress` keeps
//! working. The accept loop and `enable_h2c` detection are untouched by
//! this — they remain the cleartext path.

const std = @import("std");
const builtin = @import("builtin");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2 = @import("h2.zig");
const h2s = @import("h2_server.zig");
const gzip = @import("gzip.zig");
const flate = std.compress.flate;
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
/// Connections currently admitted and being served (see
/// `activeConnections`). Atomic: touched by the accept loop and every
/// connection task.
active_conns: std.atomic.Value(usize),

/// Called once per request, from the connection's thread. Errors turn into
/// a 500 when nothing was sent yet, otherwise the connection is closed.
pub const Handler = *const fn (*Request, *ResponseWriter) anyerror!void;

/// Verdict of an `on_connect` hook.
pub const ConnDecision = enum { accept, reject };

/// Accept hook — see `Options.on_connect`.
pub const OnConnectFn = *const fn (?*anyopaque, peer: net.IpAddress) ConnDecision;

/// Connection lifecycle phases, mirroring Go net/http's `ConnState`:
/// `.new` when serving starts (right after admission), `.active` once a
/// request head has arrived, `.idle` between keep-alive requests, `.closed`
/// when the connection is done. Rejected connections fire nothing.
pub const ConnState = enum { new, active, idle, closed };

/// Lifecycle observer — see `Options.on_conn_state`. `peer` is null only
/// when driven socket-free (`serveStream` without `StreamOptions.peer`).
pub const ConnStateFn = *const fn (?*anyopaque, peer: ?net.IpAddress, state: ConnState) void;

/// Gzip response-compression config — see `Options.compression` and
/// `gzip.zig` (min_size 1 KiB / level 6 / text+JSON+XML+JS defaults).
pub const Compression = gzip.Compression;

/// Working memory for the gzip encoder (deflate state + 64 KiB window,
/// ~290 KiB): one per connection while compression is enabled; the
/// serving loop allocates it, `serveStream` callers pass it via
/// `StreamBuffers.gzip`. Re-initialized per response — provide the
/// memory, nothing else.
pub const GzipScratch = gzip.Scratch;

/// Working memory for the inbound gzip request-body decoder (Task 1): the
/// flate decoder + its 64 KiB history window (~68 KiB). One per connection
/// while `Options.max_decompressed_request_bytes` is nonzero; the serving
/// loop allocates it and passes it via `StreamBuffers.gunzip`. Re-initialized
/// per request — provide the memory, nothing else.
pub const GunzipScratch = gzip.DecodeScratch;

pub const Options = struct {
    handler: Handler,
    /// Opaque pointer handed to the handler as `Request.context`.
    context: ?*anyopaque = null,
    /// Listen address, an IP literal (this module does no name resolution).
    addr: []const u8 = "127.0.0.1",
    /// TCP port; 0 picks an ephemeral port (see `boundAddress`).
    port: u16 = 0,
    /// Called on the accept-loop thread right after `accept`, with the
    /// socket peer address, before the connection is admitted (before any
    /// allocation, read or task spawn) — the plug-in point for per-IP
    /// connection caps, bans and global load shedding (`abuseguard` /
    /// `throttle`). `.reject` closes the socket immediately and **writes
    /// nothing** — no 429/503 (nginx `limit_conn` answers 503; we drop at
    /// the TCP level instead so abusive peers cost no response bytes; a
    /// polite 503 can always be layered as middleware since it needs the
    /// request anyway). Must be fast and thread-safe: it runs inline in the
    /// accept loop, stalling all other incoming connections while it runs.
    on_connect: ?OnConnectFn = null,
    /// Opaque pointer passed to `on_connect`.
    on_connect_ctx: ?*anyopaque = null,
    /// Optional Go-ConnState-style lifecycle observer (metrics/debugging);
    /// runs on the connection's task. See `ConnState`.
    on_conn_state: ?ConnStateFn = null,
    /// Opaque pointer passed to `on_conn_state`.
    on_conn_state_ctx: ?*anyopaque = null,
    /// Max time a single read may stall (head wait, body wait, keep-alive
    /// idle) before the connection is dropped; 0 = no timeout.
    read_timeout_ms: u32 = 10_000,
    /// Whole-request read deadline (Go `ReadTimeout` semantics): keep-alive
    /// idle + request head + request body must all complete within this
    /// budget, dribble included — the hard slowloris bound that
    /// `read_timeout_ms` alone cannot give. Response writing and handler
    /// compute time are not counted. 0 = no deadline.
    request_timeout_ms: u32 = 60_000,
    /// Max time a single write may stall because the peer stopped reading
    /// (slow-read attack): the socket is polled for writability before
    /// every write; 0 = no timeout.
    write_timeout_ms: u32 = 10_000,
    /// Per-connection read buffer; also bounds a single request head line.
    read_buffer_size: usize = 16 * 1024,
    /// Socket write buffer.
    write_buffer_size: usize = 4 * 1024,
    /// Upper bound for a whole request head (Go `MaxHeaderBytes`) → 431.
    max_header_bytes: usize = 16 * 1024,
    /// Upper bound for the request line (method + target + version) → 414.
    /// Applies to lines within `max_header_bytes`; a request line so long
    /// it blows the whole head budget gets the 431. null = no extra bound.
    max_request_line_bytes: ?usize = 8 * 1024,
    /// Upper bound for a request body → 413 (nginx `client_max_body_size`
    /// shape): an over-limit declared Content-Length is refused before the
    /// handler runs; a chunked body is capped while streaming — the
    /// handler's body reader fails once decoded bytes cross the limit, and
    /// the connection closes. Bodies are never buffered either way; this
    /// cap protects handlers that buffer and bounds bandwidth, not server
    /// memory. null = unlimited.
    max_body_bytes: ?u64 = 1 << 20,
    /// Response body buffering: bodies fully written within this get an
    /// exact Content-Length, larger ones stream chunked.
    response_buffer_size: usize = 4 * 1024,
    /// Max requests served on a single keep-alive connection before it is
    /// closed gracefully: the response to the last permitted request carries
    /// `Connection: close` and the connection ends (Go `Server` /
    /// nginx `keepalive_requests` shape — bounds a connection that pipelines
    /// forever inside the timeouts). 0 = unlimited.
    max_requests_per_conn: u32 = 1000,
    /// Negotiated gzip response compression (SPEC-http-gzip.md). null =
    /// off (the default — zero behavior change); `.{}` = on with safe
    /// defaults (compress bodies ≥ 1 KiB of text/JSON/XML/JS at level 6
    /// when the request's Accept-Encoding admits gzip — see
    /// `Compression`). Compressed responses always stream chunked; while
    /// enabled every response carries `Vary: Accept-Encoding`, and each
    /// connection costs an extra ~290 KiB of encoder state.
    compression: ?Compression = null,
    /// Transparent inbound gzip request-body decoding (Task 1): when a
    /// request carries `Content-Encoding: gzip`, the body the handler reads
    /// via `req.reader()` is decompressed on the fly, capped at this many
    /// **decompressed** bytes (a zip-bomb bound — a small compressed body
    /// can inflate enormously). 0 = off: a `Content-Encoding: gzip` request
    /// is then refused with 415 rather than handing the handler compressed
    /// bytes. Any other non-identity `Content-Encoding` answers 415
    /// regardless of this knob. Costs an extra ~68 KiB (decoder window) per
    /// connection while enabled.
    max_decompressed_request_bytes: u64 = 0,
    /// Auto `Server` response header, overridable per response.
    server_name: []const u8 = "zig-libs-http/0.1",
    kernel_backlog: u31 = 128,
    reuse_address: bool = false,
    /// Opt-in cleartext HTTP/2 (h2c via **prior knowledge**, RFC 9113
    /// §3.3 — RFC 9113 removed the `Upgrade: h2c` mechanism): when a
    /// connection opens with the HTTP/2 client preface it is served as
    /// HTTP/2 through the same `handler` (see `h2_server.zig`); anything
    /// else takes the HTTP/1.1 path unchanged. Off (the default) the
    /// server never even peeks — behavior is byte-for-byte the h1 server.
    /// Detection needs `read_buffer_size` ≥ 24 (the preface length).
    enable_h2c: bool = false,
    /// HTTP/2 DoS-hardening limits (rapid reset CVE-2023-44487,
    /// CONTINUATION flood CVE-2024-27316, SETTINGS_MAX_CONCURRENT_STREAMS,
    /// control-frame floods, total streams per connection). Only meaningful
    /// with `enable_h2c`; the defaults harden an h2c server out of the box.
    /// See `h2_server.Limits`.
    h2_limits: H2Limits = .{},
};

/// Re-export of `h2_server.Limits` for `Options.h2_limits`.
pub const H2Limits = h2s.Limits;

/// `io` must support the net + concurrency vtable operations (e.g.
/// `std.Io.Threaded`). The allocator provides per-connection buffers.
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Server {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .listener = null,
        .group = .init,
        .active_conns = .init(0),
    };
}

/// Number of connections currently admitted and being served (accepted,
/// past `on_connect`, not yet closed). Thread-safe; callable from any
/// thread while `serve` runs — the enforcement point for a global
/// connection cap (`throttle`) inside an `on_connect` hook.
pub fn activeConnections(s: *const Server) usize {
    return s.active_conns.load(.monotonic);
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
        // Admission control, before anything is spent on the connection.
        // A reject closes the socket without writing a byte (documented on
        // `Options.on_connect`) and never counts as active.
        if (s.options.on_connect) |hook| {
            if (hook(s.options.on_connect_ctx, stream.socket.address) == .reject) {
                stream.close(s.io);
                continue;
            }
        }
        _ = s.active_conns.fetchAdd(1, .monotonic); // connMain decrements
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
/// Capture buffer for an incoming chunked request's trailer section (Task 3);
/// a trailer block larger than this is truncated (excess still drained).
const trailer_scratch_len = 1024;
/// How much unread request body to drain after the handler before giving up
/// on keep-alive (Go's maxPostHandlerReadBytes).
const max_unread_body_drain = 256 * 1024;
/// Scratch bound for request-path normalization (a private copy so the raw
/// `Request.target` is preserved). Covers the default `max_request_line_bytes`
/// (8 KiB) — a longer origin-form path answers 414 rather than routing raw.
const max_normalized_path = 8 * 1024;

fn connMain(s: *Server, stream: net.Stream) void {
    defer stream.close(s.io);
    defer _ = s.active_conns.fetchSub(1, .monotonic); // paired with serve()

    const o = &s.options;
    const total = o.read_buffer_size + o.write_buffer_size + o.max_header_bytes +
        o.response_buffer_size + body_scratch_len + chunk_scratch_len + trailer_scratch_len;
    const slab = s.gpa.alloc(u8, total) catch return; // overloaded: drop the connection
    defer s.gpa.free(slab);

    // Compression working memory (deflate state + window), only when the
    // feature is on. Same overload policy as the slab.
    const gz: ?*GzipScratch = if (o.compression != null)
        s.gpa.create(GzipScratch) catch return
    else
        null;
    defer if (gz) |p| s.gpa.destroy(p);

    // Inbound gzip request-body decoder working memory (Task 1), only when
    // request decoding is enabled. Same overload policy as the slab.
    const gunzip: ?*GunzipScratch = if (o.max_decompressed_request_bytes != 0)
        s.gpa.create(GunzipScratch) catch return
    else
        null;
    defer if (gunzip) |p| s.gpa.destroy(p);

    var off: usize = 0;
    const read_buf = slab[off..][0..o.read_buffer_size];
    off += o.read_buffer_size;
    const write_buf = slab[off..][0..o.write_buffer_size];
    off += o.write_buffer_size;
    const bufs: StreamBuffers = .{
        .head = slab[off..][0..o.max_header_bytes],
        .response_body = slab[off + o.max_header_bytes ..][0..o.response_buffer_size],
        .request_body = slab[off + o.max_header_bytes + o.response_buffer_size ..][0..body_scratch_len],
        .chunk = slab[off + o.max_header_bytes + o.response_buffer_size + body_scratch_len ..][0..chunk_scratch_len],
        .trailers = slab[off + o.max_header_bytes + o.response_buffer_size + body_scratch_len + chunk_scratch_len ..][0..trailer_scratch_len],
        .gzip = gz,
        .gunzip = gunzip,
    };

    // All read buffering lives in the TimeoutReader (bounds head lines and
    // lets the timeout check see leftover bytes); the stream reader itself
    // is unbuffered. Same shape on the write side: the TimeoutWriter owns
    // the buffer so every socket write passes its writability poll.
    var sr = stream.reader(s.io, read_buf[0..0]);
    var tr: TimeoutReader = .init(&sr.interface, stream.socket.handle, o.read_timeout_ms, o.request_timeout_ms, read_buf);
    var sw = stream.writer(s.io, write_buf[0..0]);
    var tw: TimeoutWriter = .init(&sw.interface, stream.socket.handle, o.write_timeout_ms, write_buf);

    // h2c (opt-in): a connection that opens with the HTTP/2 client preface
    // is served as HTTP/2 with the same handler; anything else falls
    // through to the HTTP/1.1 loop below with nothing consumed. The stall
    // timeout guards the peek; the whole-request deadline stays h1-only
    // (it has no natural shape on a multiplexed connection).
    if (o.enable_h2c) {
        const is_h2 = detectH2Preface(&tr.reader) catch return; // stalled/reset: drop
        if (is_h2) {
            h2s.serve(s.gpa, .{
                .handler = o.handler,
                .context = o.context,
                .server_name = o.server_name,
                .now = .{ .ctx = @ptrCast(&s.io), .epochSeconds = ioEpochSeconds },
                .peer = stream.socket.address,
                .max_header_bytes = o.max_header_bytes,
                .max_body_bytes = o.max_body_bytes,
                .response_buffer_size = o.response_buffer_size,
                .compression = o.compression,
                .gzip_scratch = gz,
                .on_conn_state = o.on_conn_state,
                .on_conn_state_ctx = o.on_conn_state_ctx,
                .limits = o.h2_limits,
            }, &tr.reader, &tw.writer);
            return;
        }
    }

    serveLoop(.{
        .handler = o.handler,
        .context = o.context,
        .server_name = o.server_name,
        .now = .{ .ctx = @ptrCast(&s.io), .epochSeconds = ioEpochSeconds },
        .peer = stream.socket.address,
        .max_request_line_bytes = o.max_request_line_bytes,
        .max_body_bytes = o.max_body_bytes,
        .on_conn_state = o.on_conn_state,
        .on_conn_state_ctx = o.on_conn_state_ctx,
        .compression = o.compression,
        .max_decompressed_request_bytes = o.max_decompressed_request_bytes,
        .max_requests_per_conn = o.max_requests_per_conn,
    }, &tr.reader, &tw.writer, bufs, &tr);
}

/// Peek (never consume) whether the connection opens with the HTTP/2
/// client preface (RFC 9113 §3.3 prior knowledge). Compares incrementally
/// against whatever has arrived, so a short HTTP/1.1 request never blocks
/// waiting for 24 bytes — any real h1 method token diverges from
/// "PRI * HTTP/2.0" within its first bytes.
fn detectH2Preface(in: *Reader) error{ReadFailed}!bool {
    if (in.buffer.len < h2.preface.len) return false; // cannot peek that far
    var need: usize = 1;
    while (true) {
        const got = in.peekGreedy(need) catch |err| switch (err) {
            // Closed before 24 bytes: not a preface — the h1 path answers
            // (or quietly closes), exactly as without detection.
            error.EndOfStream => return false,
            error.ReadFailed => return error.ReadFailed,
        };
        const n = @min(got.len, h2.preface.len);
        if (!std.mem.eql(u8, got[0..n], h2.preface[0..n])) return false;
        if (got.len >= h2.preface.len) return true;
        need = got.len + 1;
    }
}

fn ioEpochSeconds(ctx: ?*anyopaque) i64 {
    const io: *const std.Io = @ptrCast(@alignCast(ctx.?));
    const ts = std.Io.Clock.real.now(io.*);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

const have_poll_timeouts = builtin.os.tag != .windows and std.posix.pollfd != void;

/// Monotonic now in nanoseconds for the whole-request deadline (only
/// compiled where `have_poll_timeouts`). A clock failure returns 0 —
/// deadlines then degrade to per-refill budgets instead of failing hard.
fn monotonicNowNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS)
        return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Wraps the connection reader: whenever a refill would block, first polls
/// the socket with the configured stall timeout, clamped to the remaining
/// whole-request deadline (armed per request by the serving loop); a
/// stalled peer or an expired deadline becomes `error.ReadFailed` with
/// `timed_out` set and the connection is dropped. Because the deadline is
/// re-checked on every refill, a dribbling client (one byte per poll
/// window) is bounded too — the stall timeout alone cannot do that.
///
/// Not movable after `reader` has been handed out.
const TimeoutReader = struct {
    in: *Reader,
    handle: net.Socket.Handle,
    timeout_ms: u32,
    request_timeout_ms: u32,
    /// Monotonic whole-request deadline; 0 = unarmed.
    deadline_ns: u64 = 0,
    reader: Reader,
    timed_out: bool = false,

    fn init(in: *Reader, handle: net.Socket.Handle, timeout_ms: u32, request_timeout_ms: u32, buffer: []u8) TimeoutReader {
        return .{
            .in = in,
            .handle = handle,
            .timeout_ms = timeout_ms,
            .request_timeout_ms = request_timeout_ms,
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Start the whole-request read budget (Go ReadTimeout shape): from
    /// here, keep-alive idle + head + body reads share one deadline.
    fn armRequest(t: *TimeoutReader) void {
        if (!have_poll_timeouts or t.request_timeout_ms == 0) return;
        t.deadline_ns = monotonicNowNs() + @as(u64, t.request_timeout_ms) * std.time.ns_per_ms;
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const t: *TimeoutReader = @alignCast(@fieldParentPtr("reader", r));
        if (have_poll_timeouts and t.in.bufferedLen() == 0 and
            (t.timeout_ms != 0 or t.deadline_ns != 0))
        {
            var wait_ms: u64 = if (t.timeout_ms != 0) t.timeout_ms else std.math.maxInt(i32);
            if (t.deadline_ns != 0) {
                const now = monotonicNowNs();
                if (now >= t.deadline_ns) {
                    t.timed_out = true;
                    return error.ReadFailed;
                }
                // Round up so we never poll(0)-spin just before the deadline.
                wait_ms = @min(wait_ms, (t.deadline_ns - now + std.time.ns_per_ms - 1) / std.time.ns_per_ms);
            }
            var fds = [_]std.posix.pollfd{.{
                .fd = t.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const timeout: i32 = std.math.cast(i32, wait_ms) orelse std.math.maxInt(i32);
            const ready = std.posix.poll(&fds, timeout) catch return error.ReadFailed;
            if (ready == 0) {
                t.timed_out = true;
                return error.ReadFailed;
            }
        }
        return t.in.stream(w, limit);
    }
};

/// Wraps the connection writer: polls the socket for writability (bounded
/// by `write_timeout_ms`) before every socket write, so a peer that stops
/// reading while a response streams (slow-read attack) becomes
/// `error.WriteFailed` with `timed_out` set instead of pinning the
/// connection task. Caveat (mirror of the read side): a peer that drains a
/// trickle restarts the window per write — only full stalls are bounded.
///
/// Not movable after `writer` has been handed out.
const TimeoutWriter = struct {
    out: *Writer,
    handle: net.Socket.Handle,
    timeout_ms: u32,
    writer: Writer,
    timed_out: bool = false,

    fn init(out: *Writer, handle: net.Socket.Handle, timeout_ms: u32, buffer: []u8) TimeoutWriter {
        return .{
            .out = out,
            .handle = handle,
            .timeout_ms = timeout_ms,
            .writer = .{
                .vtable = &.{ .drain = drainFn },
                .buffer = buffer,
            },
        };
    }

    fn pollOut(t: *TimeoutWriter) Writer.Error!void {
        if (!have_poll_timeouts or t.timeout_ms == 0) return;
        var fds = [_]std.posix.pollfd{.{
            .fd = t.handle,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const timeout: i32 = std.math.cast(i32, t.timeout_ms) orelse std.math.maxInt(i32);
        const ready = std.posix.poll(&fds, timeout) catch return error.WriteFailed;
        if (ready == 0) {
            t.timed_out = true;
            return error.WriteFailed;
        }
    }

    /// Write all of `bytes` to the (unbuffered) socket writer, polling
    /// before each partial write.
    fn sendAll(t: *TimeoutWriter, bytes: []const u8) Writer.Error!void {
        var rem = bytes;
        while (rem.len != 0) {
            try t.pollOut();
            const n = try t.out.write(rem);
            rem = rem[n..];
        }
    }

    fn drainFn(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const t: *TimeoutWriter = @alignCast(@fieldParentPtr("writer", w));
        try t.sendAll(w.buffered());
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try t.sendAll(d);
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try t.sendAll(last);
        consumed += last.len * splat;
        return consumed;
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
    /// The socket peer address, surfaced on every `Request` of this
    /// connection (`Request.peerAddress`); null = unknown (socket-free).
    /// The serving loop always fills it from the accepted socket.
    peer: ?net.IpAddress = null,
    /// Request line longer than this → 414 (see `Options`). null = no
    /// extra bound (the head buffer still applies).
    max_request_line_bytes: ?usize = null,
    /// Request body cap → 413 (see `Options`); enforced up front for a
    /// declared Content-Length, while streaming for chunked. null =
    /// unlimited (default here so plain codec runs stay permissive; the
    /// socket serving loop passes the hardened `Options` default).
    max_body_bytes: ?u64 = null,
    /// Optional lifecycle observer — see `ConnState`. Driven socket-free,
    /// the whole stream counts as one connection.
    on_conn_state: ?ConnStateFn = null,
    on_conn_state_ctx: ?*anyopaque = null,
    /// Negotiated gzip response compression (see `Options.compression`);
    /// active only when `StreamBuffers.gzip` is also provided. null = off.
    compression: ?Compression = null,
    /// Transparent inbound gzip request-body decoding (see
    /// `Options.max_decompressed_request_bytes`); active only when
    /// `StreamBuffers.gunzip` is also provided. 0 = off (a gzip-encoded
    /// request is then refused with 415).
    max_decompressed_request_bytes: u64 = 0,
    /// Max requests served on this connection before it closes gracefully
    /// (see `Options.max_requests_per_conn`). 0 = unlimited (the default
    /// here, so the plain codec stays permissive; the socket serving loop
    /// passes the hardened `Options` default).
    max_requests_per_conn: u32 = 0,

    pub const Now = struct {
        ctx: ?*anyopaque = null,
        epochSeconds: *const fn (?*anyopaque) i64,
    };
};

fn fireConnState(opts: *const StreamOptions, state: ConnState) void {
    if (opts.on_conn_state) |hook| hook(opts.on_conn_state_ctx, opts.peer, state);
}

/// Caller-supplied working memory for one connection.
pub const StreamBuffers = struct {
    /// Bounds a whole request head (431 beyond it).
    head: []u8,
    /// Request-body decoder interface buffer.
    request_body: []u8,
    /// Response body buffering; also the auto-Content-Length threshold.
    response_body: []u8,
    /// Chunked-encoder scratch (small, must be non-empty; with
    /// compression enabled it must be at least 9 bytes — the gzip
    /// encoder's output-buffer floor).
    chunk: []u8,
    /// Capture buffer for an incoming chunked request's trailer fields
    /// (Task 3), surfaced via `Request.trailer` / `iterateTrailers`. Empty
    /// (the default) = trailers are consumed and discarded, as before.
    trailers: []u8 = &.{},
    /// Gzip-encoder working memory; required for
    /// `StreamOptions.compression` to take effect (compression stays off
    /// without it). The serving loop allocates one per connection.
    gzip: ?*GzipScratch = null,
    /// Inbound gzip request-body decoder working memory; required for
    /// `StreamOptions.max_decompressed_request_bytes` to take effect
    /// (request decoding stays off without it). The serving loop allocates
    /// one per connection.
    gunzip: ?*GunzipScratch = null,
};

/// Serve HTTP/1.1 requests from `in`, responding on `out`, until the
/// connection is done (Connection: close, protocol error, read failure or a
/// clean client close). `out` is flushed after every response. Pure
/// Reader/Writer logic: the serving loop wraps it around a socket, tests
/// drive it with fixed buffers. This is also the BYO-TLS h1 entry point:
/// when a caller-terminated TLS handshake negotiated ALPN "http/1.1" (or
/// nothing — `http.protocolFromAlpn` returns `.unknown`), hand the TLS
/// connection's plaintext reader/writer here (`h2_server.serveStream` is
/// the "h2" counterpart).
pub fn serveStream(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers) void {
    serveLoop(opts, in, out, bufs, null);
}

/// The per-connection loop behind `serveStream`; the socket serving loop
/// additionally passes its TimeoutReader so the whole-request deadline is
/// re-armed at every request boundary.
fn serveLoop(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers, tr: ?*TimeoutReader) void {
    fireConnState(&opts, .new);
    var req_index: u32 = 0;
    while (true) {
        if (tr) |t| t.armRequest();
        // Per-connection request cap: when this request reaches the limit
        // its response is forced to `Connection: close` and the loop ends.
        const cap = opts.max_requests_per_conn;
        const force_close = cap != 0 and req_index + 1 >= cap;
        if (serveOne(opts, in, out, bufs, req_index, force_close) == .close) break;
        req_index += 1;
        fireConnState(&opts, .idle);
    }
    fireConnState(&opts, .closed);
}

const ConnDisposition = enum { keep_alive, close };

fn serveOne(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers, req_index: u32, force_close: bool) ConnDisposition {
    // Wait for the next request (keep-alive idle); any failure here — client
    // hung up between requests, idle timeout — is a quiet close.
    _ = in.peekByte() catch return .close;

    var date_buf: [http_date_len]u8 = undefined;
    const date: ?[]const u8 = if (opts.now) |n| formatHttpDate(n.epochSeconds(n.ctx), &date_buf) else null;

    const block = h1.readHead(in, bufs.head) catch |err| switch (err) {
        error.HeadTooLarge => return respondError(opts, out, date, 431),
        error.ReadFailed, error.ConnectionClosed => return .close,
    };
    fireConnState(&opts, .active);

    // Request-line bound (Go checks its URI length the same way, after the
    // line is in memory — the head buffer already bounds the read itself).
    if (opts.max_request_line_bytes) |max| {
        const eol = std.mem.indexOfScalar(u8, block, '\n') orelse block.len;
        if (std.mem.trimEnd(u8, block[0..eol], "\r").len > max)
            return respondError(opts, out, date, 414);
    }

    const head = h1.RequestHead.parse(block) catch |err| return respondError(opts, out, date, switch (err) {
        error.UnsupportedVersion => 505,
        error.MalformedHead => 400,
    });

    // Semantic rejections (mirrors Go net/http): HTTP/1.1 requires Host; a
    // Transfer-Encoding without chunked leaves the body unframeable; only
    // methods in the shared vocabulary are dispatched.
    if (!head.http1_0 and head.host == null) return respondError(opts, out, date, 400);
    if (head.has_transfer_encoding and !head.chunked) return respondError(opts, out, date, 400);
    // Request smuggling (RFC 9112 §6.1): a message carrying BOTH a
    // Content-Length and a Transfer-Encoding is ambiguous. The parser lets
    // TE override CL (smuggling-safe for us), but a fronting proxy that
    // instead trusts CL yields a classic CL.TE desync — so reject outright
    // and close, before the handler ever runs.
    if (head.has_transfer_encoding and head.has_content_length)
        return respondError(opts, out, date, 400);
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

    // Path normalization + traversal protection (RFC 3986 §5.2.4): collapse
    // `.`/`..` segments before routing so a `..` cannot walk a route prefix,
    // and reject an embedded NUL / `%00` (path-truncation tricks). The raw
    // `req.target` is preserved (normalization runs on a private copy);
    // percent-encoding is NOT decoded, so `%2F`/`%2E` can never turn into a
    // routing separator or dot-segment. `removeDotSegments` clamps at root
    // (a leading `..` is dropped, never escapes). Origin-form only — the
    // asterisk-form target ("*") is left untouched.
    var norm_buf: [max_normalized_path]u8 = undefined;
    if (path.len != 0 and path[0] == '/') {
        if (path.len > norm_buf.len) return respondError(opts, out, date, 414);
        if (std.mem.indexOfScalar(u8, path, 0) != null or
            std.ascii.indexOfIgnoreCase(path, "%00") != null)
            return respondError(opts, out, date, 400);
        @memcpy(norm_buf[0..path.len], path);
        path = norm_buf[0..http.removeDotSegments(norm_buf[0..path.len])];
    }

    // Persistence: HTTP/1.1 defaults to keep-alive unless the client asked
    // to close; HTTP/1.0 always closes (keep-alive opt-in not implemented).
    // `force_close` (per-connection request cap reached) also ends it.
    const keep_alive = !head.http1_0 and !head.connection_close and !force_close;

    // Body cap, declared-length half: refuse before the handler runs (and
    // before any 100-continue invites the body onto the wire) — the nginx
    // `client_max_body_size` behavior. Chunked bodies (length unknown) are
    // capped while streaming, below.
    if (opts.max_body_bytes) |max| {
        if ((head.content_length orelse 0) > max)
            return respondError(opts, out, date, 413);
    }

    // Inbound Content-Encoding (Task 1): a body we cannot decode must never
    // reach the handler as opaque bytes. `gzip` is decoded transparently
    // when enabled; anything else non-identity — and `gzip` while decoding
    // is off — answers 415 before the handler (and before 100-continue
    // invites the body onto the wire).
    const req_encoding = gzip.requestContentEncoding(head.header("content-encoding"));
    const decode_gzip = req_encoding == .gzip and
        opts.max_decompressed_request_bytes != 0 and bufs.gunzip != null;
    if (req_encoding == .unsupported or (req_encoding == .gzip and !decode_gzip))
        return respondError(opts, out, date, 415);

    const has_body = head.chunked or (head.content_length orelse 0) != 0;
    if (head.expect_continue and has_body) {
        out.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return .close;
        out.flush() catch return .close;
    }

    var body: RequestBody = if (opts.max_body_bytes) |max|
        .initCappedWithTrailers(&head, in, bufs.request_body, max, bufs.trailers)
    else
        .initWithTrailers(&head, in, bufs.request_body, bufs.trailers);
    var req: Request = .{
        .method = method,
        .target = head.target,
        .path = path,
        .query = query,
        .head = head,
        .body = &body,
        .context = opts.context,
        .peer = opts.peer,
        .conn_request_index = req_index,
    };
    // Inbound gzip decoding (Task 1): route the handler's `req.reader()`
    // through the flate decoder wrapped in a decompressed-byte cap. The
    // framing body (`body`) stays the raw source — it is what the
    // post-handler drain consumes — while `req.decoded` overrides the
    // handler-facing reader with the plaintext stream.
    var gunzip_body: GunzipBody = undefined;
    if (decode_gzip) {
        const sc = bufs.gunzip.?;
        sc.decompress = .init(body.reader(), .gzip, &sc.window);
        gunzip_body = .init(&sc.decompress.reader, opts.max_decompressed_request_bytes, &sc.out);
        req.decoded = &gunzip_body.reader;
    }
    // Compression is considered only when configured AND the working
    // memory is there; the Accept-Encoding negotiation is per request.
    const compression_on = opts.compression != null and bufs.gzip != null;
    var rw: ResponseWriter = .init(out, bufs.response_body, bufs.chunk, .{
        .head_request = method == .head,
        .http1_0 = head.http1_0,
        .date = date,
        .server_name = opts.server_name,
        .close_connection = !keep_alive,
        .compression = if (compression_on) opts.compression else null,
        .gzip_scratch = if (compression_on) bufs.gzip else null,
        .accept_gzip = compression_on and gzip.acceptsGzip(head.header("accept-encoding")),
    });

    opts.handler(&req, &rw) catch {
        // Nothing on the wire yet → a clean 500; otherwise the response
        // framing is broken and the connection must die.
        if (rw.sent_head) return .close;
        // A body that crossed max_body_bytes failed the handler's reads —
        // that is the request's fault, not the handler's: answer 413 and
        // close (the remaining body is unbounded, never drain it). Same for
        // a gzip body that inflated past the decompressed cap (zip bomb).
        if (body == .capped and body.capped.exceeded)
            return respondError(opts, out, date, 413);
        if (decode_gzip and gunzip_body.exceeded)
            return respondError(opts, out, date, 413);
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

/// Method-token lookup against the shared vocabulary (case-sensitive, as
/// the wire demands); also used by the h2 path to map `:method`.
pub fn methodFromToken(token: []const u8) ?http.Method {
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
    /// Transparent inbound-decoding override (Task 1): when set, `reader`
    /// returns this decoded (e.g. gunzipped) stream instead of `body`'s raw
    /// framing reader. The framing `body` remains the drain source.
    decoded: ?*Reader = null,
    /// `Options.context` passthrough for stateful handlers.
    context: ?*anyopaque,
    /// Socket peer address — see `peerAddress`.
    peer: ?net.IpAddress = null,
    /// 0-based request ordinal on this connection — see `connRequestIndex`.
    conn_request_index: u32 = 0,

    /// The socket peer address (the direct client — meaningful as a client
    /// identity only when no trusted proxy sits in front; `ratelimit` /
    /// `abuseguard` key on it when no forwarded header is present). Null
    /// only when the request was served socket-free (`serveStream` without
    /// `StreamOptions.peer`).
    pub fn peerAddress(req: *const Request) ?net.IpAddress {
        return req.peer;
    }

    /// 0-based index of this request on its keep-alive connection (Nth
    /// request served over the same socket).
    pub fn connRequestIndex(req: *const Request) u32 {
        return req.conn_request_index;
    }

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(req: *const Request, name: []const u8) ?[]const u8 {
        return req.head.header(name);
    }

    /// Iterate all header name/value pairs in wire order.
    pub fn iterateHeaders(req: *const Request) h1.HeaderIterator {
        return req.head.iterate();
    }

    /// Streaming request-body reader — Content-Length / chunked framing
    /// already decoded, and (when `Options.max_decompressed_request_bytes`
    /// is enabled) a `Content-Encoding: gzip` body transparently
    /// decompressed; end-of-stream at the end of the body (immediately for
    /// bodyless requests).
    pub fn reader(req: *Request) *Reader {
        return req.decoded orelse req.body.reader();
    }

    /// Incoming chunked **trailer** fields (RFC 7230 §4.1.2), captured when
    /// trailer support is enabled (`StreamBuffers.trailers` non-empty; the
    /// socket serving loop provides a buffer by default). Valid only **after
    /// the request body has been fully read** — trailers arrive on the wire
    /// after the last chunk, so a handler must drain `reader()` to
    /// end-of-stream first. Empty for non-chunked bodies or when capture is
    /// off. `trailer` looks one up (case-insensitive); `iterateTrailers`
    /// walks them in wire order; `trailers` returns the raw block.
    pub fn trailer(req: *const Request, name: []const u8) ?[]const u8 {
        return h1.blockHeader(req.body.trailerBlock(), name);
    }

    /// Iterate captured incoming chunked trailers in wire order (see
    /// `trailer`).
    pub fn iterateTrailers(req: *const Request) h1.HeaderIterator {
        return h1.blockIterator(req.body.trailerBlock());
    }

    /// The raw captured incoming chunked trailer block (see `trailer`).
    pub fn trailers(req: *const Request) []const u8 {
        return req.body.trailerBlock();
    }
};

/// Framing-decoded request body (RFC 7230 §3.3.3, server side: chunked wins,
/// then Content-Length, else no body). Keep at a stable address once
/// `reader` has been handed out.
pub const RequestBody = union(enum) {
    none: Reader,
    limited: h1.ContentLengthReader,
    chunked: h1.ChunkedReader,
    /// Chunked body under a `max_body_bytes` cap.
    capped: Capped,

    pub fn init(head: *const h1.RequestHead, in: *Reader, scratch: []u8) RequestBody {
        return initWithTrailers(head, in, scratch, &.{});
    }

    /// Like `init`, additionally capturing an incoming chunked body's
    /// trailer section (RFC 7230 §4.1.2) into `trailer_buf` — readable via
    /// `trailerBlock` once the body is fully consumed. An empty `trailer_buf`
    /// disables capture (identical to `init`).
    pub fn initWithTrailers(head: *const h1.RequestHead, in: *Reader, scratch: []u8, trailer_buf: []u8) RequestBody {
        if (head.chunked) return .{ .chunked = .initCapturingTrailers(in, scratch, trailer_buf) };
        const n = head.content_length orelse 0;
        if (n != 0) return .{ .limited = .init(in, n, scratch) };
        return .{ .none = .fixed("") };
    }

    /// Like `init`, additionally capping bodies whose size is not known up
    /// front (chunked) at `max_body` decoded bytes. Content-Length bodies
    /// are inherently bounded by their declared length — the caller must
    /// reject declared lengths above the cap (the serving loop answers 413
    /// before the handler runs).
    pub fn initCapped(head: *const h1.RequestHead, in: *Reader, scratch: []u8, max_body: u64) RequestBody {
        return initCappedWithTrailers(head, in, scratch, max_body, &.{});
    }

    /// `initCapped` + chunked trailer capture into `trailer_buf` (see
    /// `initWithTrailers`).
    pub fn initCappedWithTrailers(head: *const h1.RequestHead, in: *Reader, scratch: []u8, max_body: u64, trailer_buf: []u8) RequestBody {
        if (head.chunked) return .{ .capped = .initCapturingTrailers(in, max_body, scratch, trailer_buf) };
        return initWithTrailers(head, in, scratch, trailer_buf);
    }

    pub fn reader(b: *RequestBody) *Reader {
        return switch (b.*) {
            .none => |*r| r,
            .limited => |*lr| &lr.reader,
            .chunked => |*cr| &cr.reader,
            .capped => |*cc| &cc.reader,
        };
    }

    /// The captured incoming chunked trailer section as a raw header block
    /// (empty unless the body was chunked, trailer capture was enabled, and
    /// the body has been fully read). Parse with `h1.blockHeader` /
    /// `h1.blockIterator` — or use `Request.trailer` / `iterateTrailers`.
    pub fn trailerBlock(b: *const RequestBody) []const u8 {
        return switch (b.*) {
            .chunked => |*cr| cr.trailers(),
            .capped => |*cc| cc.inner.trailers(),
            .none, .limited => "",
        };
    }

    /// `max_body_bytes` enforcement for chunked request bodies: streams
    /// decoded bytes through until the cap, then fails the read with
    /// `exceeded` set (the serving loop turns that into a 413 when nothing
    /// was sent yet, and closes the connection either way). Memory use is
    /// the caller's `scratch` — nothing is buffered beyond it.
    ///
    /// Not movable after `reader` has been handed out.
    pub const Capped = struct {
        /// The framing decoder underneath; its interface stays unbuffered
        /// (all its reads write straight through), the consumer-facing
        /// buffer lives on `reader`.
        inner: h1.ChunkedReader,
        /// Decoded bytes still allowed.
        remaining: u64,
        exceeded: bool = false,
        reader: Reader,

        pub fn init(in: *Reader, max_body: u64, scratch: []u8) Capped {
            return .{
                .inner = .init(in, scratch[0..0]),
                .remaining = max_body,
                .reader = .{
                    .vtable = &.{ .stream = streamFn },
                    .buffer = scratch,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        /// `init` + chunked trailer capture into `trailer_buf` (see
        /// `ChunkedReader.initCapturingTrailers`).
        pub fn initCapturingTrailers(in: *Reader, max_body: u64, scratch: []u8, trailer_buf: []u8) Capped {
            var c = Capped.init(in, max_body, scratch);
            c.inner.trailer_buf = trailer_buf;
            return c;
        }

        fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
            const c: *Capped = @alignCast(@fieldParentPtr("reader", r));
            if (c.remaining == 0) {
                // At the cap: the body must end exactly here. Probe one
                // byte — a clean end-of-body passes, anything more is over
                // the limit.
                while (true) {
                    const n = c.inner.reader.discard(.limited(1)) catch |err| switch (err) {
                        error.EndOfStream => return error.EndOfStream,
                        error.ReadFailed => return error.ReadFailed,
                    };
                    if (n != 0) {
                        c.exceeded = true;
                        return error.ReadFailed;
                    }
                }
            }
            const n = try c.inner.reader.stream(w, limit.min(.limited64(c.remaining)));
            c.remaining -= n;
            return n;
        }
    };
};

/// Decompressed-size cap for a transparently-decoded gzip request body
/// (Task 1). Streams plaintext out of the `std.compress.flate` gzip decoder
/// under a decompressed-byte budget; once the budget is spent it probes for
/// a clean end of body — anything beyond it is a zip bomb, so the read fails
/// with `exceeded` set (the serving loop maps that to 413 when nothing was
/// sent yet, and closes the connection either way). Mirrors
/// `RequestBody.Capped`, but the bounded quantity is *decompressed* bytes.
///
/// Not movable after `reader` has been handed out.
pub const GunzipBody = struct {
    /// The flate gzip decoder's reader (its window lives in `GunzipScratch`).
    inner: *Reader,
    /// Decompressed bytes still allowed.
    remaining: u64,
    exceeded: bool = false,
    reader: Reader,

    pub fn init(inner: *Reader, max_body: u64, buffer: []u8) GunzipBody {
        return .{
            .inner = inner,
            .remaining = max_body,
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const c: *GunzipBody = @alignCast(@fieldParentPtr("reader", r));
        if (c.remaining == 0) {
            // At the cap: the decompressed body must end exactly here. Probe
            // one byte — a clean end passes, anything more is a zip bomb.
            while (true) {
                const n = c.inner.discard(.limited(1)) catch |err| switch (err) {
                    error.EndOfStream => return error.EndOfStream,
                    error.ReadFailed => return error.ReadFailed,
                };
                if (n != 0) {
                    c.exceeded = true;
                    return error.ReadFailed;
                }
            }
        }
        const n = c.inner.stream(w, limit.min(.limited64(c.remaining))) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed, error.WriteFailed => |e| return e,
        };
        c.remaining -= n;
        return n;
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
/// Compression (when `InitOptions.compression` is set): eligible bodies
/// are routed through a gzip encoder into the chunked framing —
/// transparent to the handler; a handler-declared `Content-Length` is
/// then dropped from the wire (the written byte count stays enforced),
/// a handler-set `Content-Encoding` disables it (never double-compress),
/// and `Vary: Accept-Encoding` is added to every response unless the
/// handler's own `Vary` already covers it.
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
    /// Compression config; null = this response never compresses.
    compression: ?Compression = null,
    /// Gzip working memory; present whenever `compression` is set.
    gzip_scratch: ?*GzipScratch = null,
    /// The request's Accept-Encoding admits gzip (negotiation input).
    accept_gzip: bool = false,
    /// Compression engaged: emit `Content-Encoding: gzip` with the head.
    content_encoding_gzip: bool = false,
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
        /// Compressed streaming: plain handler bytes → gzip encoder →
        /// chunked framing (Phase 2.2).
        gzip: GzipBody,
    };

    const GzipBody = struct {
        /// Chunked encoder the compressed bytes feed (owns `chunk_buf`).
        chunked: h1.ChunkedWriter,
        /// The flate gzip encoder; its state lives in `gzip_scratch`.
        compress: *flate.Compress,
        /// Plain-body bytes still owed against a declared Content-Length
        /// (enforced exactly like the identity sink, though the length
        /// itself never reaches the wire); null = no declared length.
        plain_remaining: ?u64,
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
        /// Negotiated gzip response compression (Phase 2.2); null = off.
        /// Requires `gzip_scratch`, and `chunk_buf` of at least 9 bytes.
        /// While set, every response carries `Vary: Accept-Encoding`.
        compression: ?Compression = null,
        /// Working memory for the gzip encoder (usually per-connection).
        gzip_scratch: ?*GzipScratch = null,
        /// The request's Accept-Encoding admits gzip (`gzip.acceptsGzip`)
        /// — evaluated by the serving loop, the negotiation input here.
        accept_gzip: bool = false,
    };

    /// `body_buf` is the buffering/auto-Content-Length threshold;
    /// `chunk_buf` is small scratch for the chunked encoder (non-empty).
    pub fn init(out: *Writer, body_buf: []u8, chunk_buf: []u8, opts: InitOptions) ResponseWriter {
        std.debug.assert(opts.compression == null or opts.gzip_scratch != null);
        return .{
            .out = out,
            .chunk_buf = chunk_buf,
            .date = opts.date,
            .server_name = opts.server_name,
            .head_request = opts.head_request,
            .http1_0 = opts.http1_0,
            .close_connection = opts.close_connection,
            .compression = opts.compression,
            .gzip_scratch = opts.gzip_scratch,
            .accept_gzip = opts.accept_gzip,
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
    ///
    /// Response-splitting guard (RFC 9110 §5.1 / §5.5): the mechanism is
    /// **reject at set time** (fail fast) — the single mutation path for the
    /// header table, so a rejected header can never reach `writeHead` and
    /// thus never the wire; no separate write-time scrub is needed. The
    /// `name` must be a non-empty RFC 9110 token (tchar only); the `value`
    /// must not contain CR, LF or NUL (the bytes that would inject a header
    /// or split the response when a handler reflects user input into a
    /// Location/Set-Cookie/filename header). Both fail with `InvalidHeader`.
    pub fn setHeader(rw: *ResponseWriter, name: []const u8, value: []const u8) SetHeaderError!void {
        if (rw.sent_head) return error.HeadersSent;
        if (!validHeaderName(name) or !validHeaderValue(value)) return error.InvalidHeader;
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

    /// Append a `Set-Cookie` response header (RFC 6265) — the one response
    /// header that is legitimately repeatable, which `setHeader`'s
    /// replace-by-name semantics cannot express (only the last would
    /// survive). Each call adds another line; `writeHead` emits every one on
    /// its own `Set-Cookie:` line, in call order. The value gets the same
    /// response-splitting validation `setHeader` applies (no CR/LF/NUL —
    /// `error.InvalidHeader` otherwise); the name is fixed, so it is always a
    /// valid token. Counts against the same `max_response_headers` budget
    /// (`error.TooManyHeaders`) and is likewise rejected once the head is on
    /// the wire (`error.HeadersSent`).
    pub fn addSetCookie(rw: *ResponseWriter, value: []const u8) SetHeaderError!void {
        if (rw.sent_head) return error.HeadersSent;
        if (!validHeaderValue(value)) return error.InvalidHeader;
        if (rw.headers_len == max_response_headers) return error.TooManyHeaders;
        // Appended straight to the header table (no replace scan), so
        // multiple Set-Cookie entries coexist and each is serialized by
        // `writeHead` like any other header.
        rw.headers[rw.headers_len] = .{ .name = "Set-Cookie", .value = value };
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

    /// Push everything written so far all the way to the socket — the head (on
    /// the first call) plus the buffered body, through the chunked framing and
    /// the connection writer. This is what makes **streaming responses**
    /// (Server-Sent Events, long-poll, progressive output) actually reach the
    /// client incrementally instead of at `end()`: write an event, `flush()`,
    /// repeat. The first flush commits the framing as chunked (no
    /// Content-Length was declared) and writes the head, so set the status and
    /// headers before it. A flush with nothing buffered is a no-op (the head
    /// is not forced out until there is a byte to send). Does nothing useful on
    /// HTTP/1.0 peers, which get an until-close identity body.
    pub fn flush(rw: *ResponseWriter) Writer.Error!void {
        try rw.interface.flush(); // interface buffer → sink (begins streaming)
        switch (rw.body) {
            .chunked => |*cw| try cw.writer.flush(), // chunk buffer → rw.out
            .gzip => |*g| try g.chunked.writer.flush(),
            else => {},
        }
        try rw.out.flush(); // connection writer → socket
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
        if (rw.body == .buffering and rw.shouldCompress(rw.interface.buffered().len)) {
            // Fully buffered body, eligible: compress it through the
            // streaming pipeline (single encoding path — see beginGzip).
            const body_bytes = rw.interface.buffered();
            defer rw.interface.end = 0;
            const n = rw.declared_len orelse body_bytes.len;
            if (n != body_bytes.len) {
                rw.failed = true; // body ≠ declared Content-Length
                return error.WriteFailed;
            }
            try rw.beginGzip(null); // length already validated above
            try rw.body.gzip.compress.writer.writeAll(body_bytes);
            return rw.finishGzip();
        }
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
            .gzip => {
                try rw.interface.flush();
                try rw.finishGzip();
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
        rw.content_encoding_gzip = false;
        rw.body = .buffering;
        rw.interface.end = 0;
    }

    fn noBody(rw: *const ResponseWriter) bool {
        return rw.head_request or rw.status == 204 or rw.status == 304 or
            (rw.status >= 100 and rw.status < 200);
    }

    /// The Phase 2.2 eligibility gate: negotiated (Accept-Encoding admits
    /// gzip), a body exists (not HEAD/1xx/204/304), HTTP/1.1 (chunked
    /// framing is how compressed bodies stream; nginx also requires
    /// ≥ 1.1), not already Content-Encoding'd (never double-compress),
    /// compressible content-type, and worth it: `known_len` is the plain
    /// body size when known (fully buffered, or declared) and must reach
    /// `min_size`; null = size unknown at streaming time → compress
    /// (nginx's behavior for unknown-length responses).
    fn shouldCompress(rw: *const ResponseWriter, known_len: ?u64) bool {
        const cfg = rw.compression orelse return false;
        if (!rw.accept_gzip) return false;
        if (rw.http1_0) return false;
        if (rw.noBody()) return false;
        if (known_len) |n| {
            if (n < cfg.min_size) return false;
        }
        var content_type: ?[]const u8 = null;
        for (rw.headers[0..rw.headers_len]) |hd| {
            if (std.ascii.eqlIgnoreCase(hd.name, "content-encoding")) return false;
            if (std.ascii.eqlIgnoreCase(hd.name, "content-type")) content_type = hd.value;
        }
        const ct = content_type orelse return false;
        return gzip.contentTypeCompressible(ct, cfg.content_types);
    }

    /// Put the head on the wire (`Content-Encoding: gzip` + chunked
    /// framing) and stand up the compression pipeline: handler bytes →
    /// gzip encoder (state + window in `gzip_scratch`) → chunked encoder
    /// → `out`. A declared Content-Length is dropped from the wire but
    /// still enforced via `plain_remaining` (pass null when the byte
    /// count was already validated).
    fn beginGzip(rw: *ResponseWriter, plain_remaining: ?u64) Writer.Error!void {
        std.debug.assert(!rw.sent_head);
        const scratch = rw.gzip_scratch.?;
        rw.content_encoding_gzip = true;
        try rw.writeHead(.chunked);
        rw.body = .{ .gzip = .{
            .chunked = .init(rw.out, rw.chunk_buf),
            .compress = &scratch.compress,
            .plain_remaining = plain_remaining,
        } };
        // Emits the 10-byte gzip container header — it lands in the
        // chunked encoder's buffer, safely after the response head. The
        // chunked writer must be at its final address by now (the
        // encoder keeps a pointer to it).
        scratch.compress = try flate.Compress.init(
            &rw.body.gzip.chunked.writer,
            &scratch.window,
            .gzip,
            gzip.levelOptions(rw.compression.?.level),
        );
    }

    /// Terminate a compressed body: enforce a declared length, flush the
    /// deflate tail + gzip footer, then the chunked 0-terminator.
    fn finishGzip(rw: *ResponseWriter) Writer.Error!void {
        const g = &rw.body.gzip;
        if (g.plain_remaining) |rem| {
            if (rem != 0) {
                rw.failed = true; // under-delivered declared length
                return error.WriteFailed;
            }
        }
        try g.compress.finish();
        try g.chunked.finish();
    }

    const Framing = union(enum) { none, content_length: u64, chunked };

    /// Emit the status line + headers. Header order: user headers (set
    /// order), then auto Date/Server, Vary/Content-Encoding (compression),
    /// Connection, framing.
    fn writeHead(rw: *ResponseWriter, framing: Framing) Writer.Error!void {
        const out = rw.out;
        try out.print("HTTP/1.1 {d} {s}\r\n", .{ rw.status, reasonPhrase(rw.status) });

        var saw_date = false;
        var saw_server = false;
        var vary_covered = false;
        for (rw.headers[0..rw.headers_len]) |hd| {
            if (std.ascii.eqlIgnoreCase(hd.name, "date")) saw_date = true;
            if (std.ascii.eqlIgnoreCase(hd.name, "server")) saw_server = true;
            if (std.ascii.eqlIgnoreCase(hd.name, "vary") and
                (h1.tokenListContains(hd.value, "accept-encoding") or
                    h1.tokenListContains(hd.value, "*"))) vary_covered = true;
            try out.print("{s}: {s}\r\n", .{ hd.name, hd.value });
        }
        if (!saw_date) if (rw.date) |d| try out.print("Date: {s}\r\n", .{d});
        if (!saw_server) if (rw.server_name) |sn| try out.print("Server: {s}\r\n", .{sn});
        // Cache safety: while compression is enabled, every response
        // could differ by Accept-Encoding — tell caches so, whether or
        // not this particular response is compressed (Go gzip-handler
        // behavior; an additional Vary line is legal next to a
        // handler-set one covering other headers).
        if (rw.compression != null and !vary_covered)
            try out.writeAll("Vary: Accept-Encoding\r\n");
        if (rw.content_encoding_gzip) try out.writeAll("Content-Encoding: gzip\r\n");
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
        } else if (rw.shouldCompress(rw.declared_len)) {
            // Streaming body: the size is the declared length when there
            // is one, else unknown (already outgrew the buffer).
            try rw.beginGzip(rw.declared_len);
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
            .gzip => |*g| {
                if (g.plain_remaining) |rem| {
                    // Same over-delivery guard as the identity sink —
                    // counted in plain bytes, pre-compression.
                    var total: u64 = w.end;
                    for (data[0 .. data.len - 1]) |d| total += d.len;
                    total += data[data.len - 1].len * splat;
                    if (total > rem) {
                        rw.failed = true;
                        return error.WriteFailed;
                    }
                    const consumed = try forwardDrain(w, &g.compress.writer, data, splat);
                    g.plain_remaining = rem - total;
                    return consumed;
                }
                return forwardDrain(w, &g.compress.writer, data, splat);
            },
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

/// A valid response header name: a non-empty RFC 9110 §5.1 token (tchar
/// only). Rejects the space/`:`/control bytes that would break the
/// `name: value` framing.
fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| if (!h1.isTchar(c)) return false;
    return true;
}

/// A safe response header value: no CR, LF or NUL (RFC 9110 §5.5 — the
/// bytes a reflected value would use to inject headers or split the
/// response). Everything else (including obs-text) is passed through.
fn validHeaderValue(value: []const u8) bool {
    for (value) |c| if (c == '\r' or c == '\n' or c == 0) return false;
    return true;
}

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
        416 => "Range Not Satisfiable",
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

/// 32 bytes of JSON — fits the offline response buffer (64), so it takes
/// the fully-buffered path; above the tests' min_size 16, below the 1 KiB
/// default.
const small_json = "{\"k\":\"" ++ ("v" ** 24) ++ "\"}";

/// ~1.8 KiB of repetitive JSON — above the default 1 KiB compression
/// min_size and every offline serving buffer, so it always streams.
const json_body = "{\"data\":[" ++ ("\"abcdefgh\"," ** 160) ++ "\"end\"]}";

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
    } else if (std.mem.eql(u8, req.path, "/connmeta")) {
        // Report what the hardening surfaced: peer address + request index.
        var buf: [96]u8 = undefined;
        var w: Writer = .fixed(&buf);
        if (req.peerAddress()) |p| try w.print("{f}", .{p}) else try w.writeAll("none");
        try w.print(" #{d}", .{req.connRequestIndex()});
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/json")) {
        try rw.setHeader("Content-Type", "application/json");
        try rw.writeAll(small_json);
    } else if (std.mem.eql(u8, req.path, "/jsonbig")) {
        try rw.setHeader("Content-Type", "application/json; charset=utf-8");
        try rw.writeAll(json_body);
    } else if (std.mem.eql(u8, req.path, "/declgz")) {
        // Declared Content-Length on a compressible body.
        try rw.setHeader("Content-Type", "application/json");
        var len_buf: [8]u8 = undefined;
        try rw.setHeader("Content-Length", try std.fmt.bufPrint(&len_buf, "{d}", .{json_body.len}));
        try rw.writeAll(json_body);
    } else if (std.mem.eql(u8, req.path, "/bin")) {
        // Big but not a compressible type.
        try rw.setHeader("Content-Type", "application/octet-stream");
        try rw.writeAll(json_body);
    } else if (std.mem.eql(u8, req.path, "/pregz")) {
        // Pretend pre-compressed content: must pass through untouched.
        try rw.setHeader("Content-Type", "application/json");
        try rw.setHeader("Content-Encoding", "gzip");
        try rw.writeAll("FAKE-GZIP-BYTES-FAKE-GZIP-BYTES");
    } else if (std.mem.eql(u8, req.path, "/drain")) {
        // Stream-discard the whole body (bounded memory by construction).
        var total: u64 = 0;
        const r = req.reader();
        while (true) {
            const n = r.discard(.limited(4096)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return error.BodyReadFailed,
            };
            total += n;
        }
        var buf: [32]u8 = undefined;
        try rw.writeAll(try std.fmt.bufPrint(&buf, "drained {d}", .{total}));
    } else if (std.mem.eql(u8, req.path, "/trailers")) {
        // Drain the body to end-of-stream (trailers arrive after the last
        // chunk), then echo a captured trailer field.
        const r = req.reader();
        while (true) {
            _ = r.discard(.limited(4096)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return error.BodyReadFailed,
            };
        }
        const cs = req.trailer("X-Checksum") orelse "none";
        var buf: [96]u8 = undefined;
        try rw.writeAll(try std.fmt.bufPrint(&buf, "trailer={s}", .{cs}));
    } else if (std.mem.eql(u8, req.path, "/stream")) {
        // Incremental streaming: each write+flush becomes its own chunk on the
        // wire (proves flush() reaches the socket mid-handler — the SSE path).
        try rw.setHeader("Content-Type", "text/event-stream");
        try rw.writeAll("A");
        try rw.flush();
        try rw.writeAll("B");
        try rw.flush();
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

fn fixedEpoch(_: ?*anyopaque) i64 {
    return 784111777; // Sun, 06 Nov 1994 08:49:37 GMT (RFC 9110's example)
}

const test_date = "Sun, 06 Nov 1994 08:49:37 GMT";

/// Hardening knobs for `runStreamWith` (defaults = the permissive
/// `StreamOptions` defaults, so `runStream` behaves as before).
const StreamTweaks = struct {
    peer: ?net.IpAddress = null,
    max_request_line_bytes: ?usize = null,
    max_body_bytes: ?u64 = null,
    on_conn_state: ?ConnStateFn = null,
    on_conn_state_ctx: ?*anyopaque = null,
    compression: ?Compression = null,
    max_decompressed_request_bytes: u64 = 0,
    max_requests_per_conn: u32 = 0,
};

/// Run `serveStream` over canned wire bytes with small test buffers
/// (response buffer 64 → bodies beyond it stream chunked). The buffers
/// dwarf nothing: any body larger than ~1.5 KiB total proves streaming.
fn runStreamWith(tweaks: StreamTweaks, ctx: ?*anyopaque, wire: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(wire);
    var out: Writer = .fixed(out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [64]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    var trailer_buf: [256]u8 = undefined;
    var gz: ?*GzipScratch = null;
    defer if (gz) |p| testing.allocator.destroy(p);
    if (tweaks.compression != null)
        gz = testing.allocator.create(GzipScratch) catch @panic("OOM");
    var gunzip: ?*GunzipScratch = null;
    defer if (gunzip) |p| testing.allocator.destroy(p);
    if (tweaks.max_decompressed_request_bytes != 0)
        gunzip = testing.allocator.create(GunzipScratch) catch @panic("OOM");
    serveStream(.{
        .handler = testHandler,
        .context = ctx,
        .server_name = "test",
        .now = .{ .epochSeconds = fixedEpoch },
        .peer = tweaks.peer,
        .max_request_line_bytes = tweaks.max_request_line_bytes,
        .max_body_bytes = tweaks.max_body_bytes,
        .on_conn_state = tweaks.on_conn_state,
        .on_conn_state_ctx = tweaks.on_conn_state_ctx,
        .compression = tweaks.compression,
        .max_decompressed_request_bytes = tweaks.max_decompressed_request_bytes,
        .max_requests_per_conn = tweaks.max_requests_per_conn,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
        .trailers = &trailer_buf,
        .gzip = gz,
        .gunzip = gunzip,
    });
    return out.buffered();
}

fn runStream(ctx: ?*anyopaque, wire: []const u8, out_buf: []u8) []const u8 {
    return runStreamWith(.{}, ctx, wire, out_buf);
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

test "serveStream: flush() streams each write as its own chunk (SSE path)" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /stream HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    // Chunked framing, event-stream content type, and — the point — "A" and
    // "B" arrive as two separate 1-byte chunks (flush emitted each), not one.
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/event-stream\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "1\r\nA\r\n" ++
        "1\r\nB\r\n" ++
        "0\r\n\r\n", got);
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

test "serveStream: bare-LF in the request head → 400, connection closes (smuggling guard)" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    // Bare LF terminating the request line (RFC 9112 §2.2: a recipient MUST
    // NOT treat it as a line terminator) — answered 400 like any malformed
    // head, and the pipelined request behind it is never served.
    const req_line = runStream(&hits, "GET /hello HTTP/1.1\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, req_line, "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(std.mem.endsWith(u8, req_line, "Connection: close\r\n\r\nBad Request\n"));
    try testing.expectEqual(@as(u32, 0), hits.load(.monotonic));
    // Bare LF between two header lines is rejected the same way.
    const between = runStream(null, "GET /hello HTTP/1.1\r\nHost: t\nAccept: */*\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, between, "HTTP/1.1 400 Bad Request\r\n"));
    // The all-CRLF control still succeeds.
    const ok = runStream(null, "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200 OK\r\n"));
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

test "ResponseWriter: header CR/LF/NUL + invalid name rejected (response-splitting guard)" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // Values that would inject a header / split the response (reflected
    // Location redirect, echoed input, smuggled Set-Cookie).
    try testing.expectError(error.InvalidHeader, rw.setHeader("Location", "/next\r\nSet-Cookie: pwned=1"));
    try testing.expectError(error.InvalidHeader, rw.setHeader("X-Echo", "a\nb"));
    try testing.expectError(error.InvalidHeader, rw.setHeader("X-Echo", "a\rb"));
    try testing.expectError(error.InvalidHeader, rw.setHeader("X-Echo", "a\x00b"));
    // Names that are not RFC 9110 tokens.
    try testing.expectError(error.InvalidHeader, rw.setHeader("Bad Name", "x"));
    try testing.expectError(error.InvalidHeader, rw.setHeader("X:Y", "x"));
    try testing.expectError(error.InvalidHeader, rw.setHeader("X\r", "x"));
    try testing.expectError(error.InvalidHeader, rw.setHeader("", "x"));

    // A well-formed header still works — and the serialized bytes prove the
    // injected header/value never reached the wire.
    try rw.setHeader("X-Ok", "clean");
    try rw.writeAll("body");
    try rw.end();
    const wire = out.buffered();
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie") == null);
    try testing.expect(std.mem.indexOf(u8, wire, "pwned") == null);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "X-Ok: clean\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n" ++
        "body", wire);
}

test "ResponseWriter: addSetCookie emits multiple Set-Cookie lines (Task 2)" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    // A plain header alongside two cookies — all three survive; the cookies
    // are NOT collapsed into one the way setHeader-replace would.
    try rw.setHeader("Content-Type", "text/plain");
    try rw.addSetCookie("sid=abc; HttpOnly");
    try rw.addSetCookie("theme=dark; Path=/");
    try rw.writeAll("ok");
    try rw.end();
    const wire = out.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, wire, "Set-Cookie: "));
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie: sid=abc; HttpOnly\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie: theme=dark; Path=/\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Type: text/plain\r\n") != null);
    // setHeader for a non-cookie header still replaces (semantics unchanged).
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "Content-Type: "));
}

test "ResponseWriter: addSetCookie validates the value + head-sent guard (Task 2)" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    // Same response-splitting guard as setHeader: an injected CRLF (or bare
    // CR/LF/NUL) is refused, so a second Set-Cookie can never be smuggled in.
    try testing.expectError(error.InvalidHeader, rw.addSetCookie("x=1\r\nSet-Cookie: pwned=1"));
    try testing.expectError(error.InvalidHeader, rw.addSetCookie("x=1\n"));
    try testing.expectError(error.InvalidHeader, rw.addSetCookie("x=1\r"));
    try testing.expectError(error.InvalidHeader, rw.addSetCookie("x=1\x00"));
    // A clean cookie still works, and none of the rejected bytes reached the wire.
    try rw.addSetCookie("ok=1");
    try rw.end();
    const wire = out.buffered();
    try testing.expect(std.mem.indexOf(u8, wire, "pwned") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "Set-Cookie: "));
    // Once the head is on the wire it is too late.
    try testing.expectError(error.HeadersSent, rw.addSetCookie("late=1"));
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

// ── tests (offline — Phase 2.1 hardening) ───────────────────────────────────

test "serveStream: over-long request line → 414; limit is configurable" {
    var out_buf: [4096]u8 = undefined;
    const wire_bytes = "GET /" ++ ("a" ** 100) ++ " HTTP/1.1\r\nHost: t\r\n\r\n";
    try testing.expect(std.mem.startsWith(
        u8,
        runStreamWith(.{ .max_request_line_bytes = 64 }, null, wire_bytes, &out_buf),
        "HTTP/1.1 414 URI Too Long\r\n",
    ));
    // The same wire under a permissive limit routes normally (404 path).
    try testing.expect(std.mem.startsWith(
        u8,
        runStreamWith(.{ .max_request_line_bytes = 512 }, null, wire_bytes, &out_buf),
        "HTTP/1.1 404 Not Found\r\n",
    ));
}

test "serveStream: declared Content-Length over max_body_bytes → golden 413 before the handler" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .max_body_bytes = 16 }, &hits, "POST /drain HTTP/1.1\r\nHost: t\r\nContent-Length: 17\r\n\r\n" ++ ("b" ** 17), &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 413 Content Too Large\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 18\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "Content Too Large\n", got);
    try testing.expectEqual(@as(u32, 0), hits.load(.monotonic)); // handler never ran

    // Exactly at the limit passes.
    const ok = runStreamWith(.{ .max_body_bytes = 16 }, &hits, "POST /drain HTTP/1.1\r\nHost: t\r\nContent-Length: 16\r\n\r\n" ++ ("b" ** 16), &out_buf);
    try testing.expect(std.mem.endsWith(u8, ok, "drained 16"));
    try testing.expectEqual(@as(u32, 1), hits.load(.monotonic));
}

test "serveStream: chunked body over max_body_bytes → 413 while streaming, memory bounded" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    // 4 KiB of decoded body in 64-byte chunks — more than every serving
    // buffer combined (head 1 KiB + request-body 256 + response 64 + chunk
    // 128), so it can only be handled streaming; the cap fires long before
    // the wire ends and nothing is ever buffered whole.
    const chunk = "40\r\n" ++ ("x" ** 0x40) ++ "\r\n";
    const wire_bytes = "POST /drain HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        (chunk ** 64) ++ "0\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n";
    const got = runStreamWith(.{ .max_body_bytes = 1024 }, &hits, wire_bytes, &out_buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 413 Content Too Large\r\n"));
    // One response only — the connection closed, the pipelined request died.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "HTTP/1.1"));
    try testing.expectEqual(@as(u32, 1), hits.load(.monotonic)); // handler ran; its read failed
}

test "serveStream: chunked body exactly at max_body_bytes passes; unread overrun closes" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    const chunk = "40\r\n" ++ ("x" ** 0x40) ++ "\r\n";
    const exact = "POST /drain HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        (chunk ** 16) ++ "0\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    const got = runStreamWith(.{ .max_body_bytes = 1024 }, &hits, exact, &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "drained 1024") != null);
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic)); // keep-alive survived

    // A handler that ignores an over-cap body still responds, but the
    // post-handler drain hits the cap → the connection closes.
    hits = .init(0);
    const unread = "POST /hello HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        (chunk ** 64) ++ "0\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n";
    const got2 = runStreamWith(.{ .max_body_bytes = 1024 }, &hits, unread, &out_buf);
    try testing.expect(std.mem.startsWith(u8, got2, "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqual(@as(u32, 1), hits.load(.monotonic)); // pipelined request dropped
}

test "serveStream: peer address and request index reach the handler" {
    var out_buf: [4096]u8 = undefined;
    const wire_bytes = "GET /connmeta HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /connmeta HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

    // Socket-free without a peer: null surfaces, the index still counts.
    const bare = runStream(null, wire_bytes, &out_buf);
    try testing.expect(std.mem.indexOf(u8, bare, "none #0") != null);
    try testing.expect(std.mem.indexOf(u8, bare, "none #1") != null);

    // With `StreamOptions.peer` the handler sees the address on every
    // request of the connection.
    const peer = net.IpAddress.parseIp4("192.0.2.7", 4242) catch unreachable;
    const with_peer = runStreamWith(.{ .peer = peer }, null, wire_bytes, &out_buf);
    try testing.expect(std.mem.indexOf(u8, with_peer, "192.0.2.7:4242 #0") != null);
    try testing.expect(std.mem.indexOf(u8, with_peer, "192.0.2.7:4242 #1") != null);
}

const StateLog = struct {
    saw: [8]ConnState = undefined,
    len: usize = 0,

    fn record(ctx: ?*anyopaque, peer: ?net.IpAddress, state: ConnState) void {
        _ = peer;
        const log: *StateLog = @ptrCast(@alignCast(ctx.?));
        if (log.len < log.saw.len) {
            log.saw[log.len] = state;
            log.len += 1;
        }
    }
};

test "serveStream: ConnState callback sees new→active→idle→active→closed" {
    var log: StateLog = .{};
    var out_buf: [4096]u8 = undefined;
    _ = runStreamWith(.{ .on_conn_state = StateLog.record, .on_conn_state_ctx = &log }, null, "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualSlices(ConnState, &.{ .new, .active, .idle, .active, .closed }, log.saw[0..log.len]);
}

test "serveStream: Content-Length + Transfer-Encoding together → 400 (CL.TE smuggling guard)" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    // Both framings present → rejected before the handler, connection closes.
    const got = runStream(&hits, "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "Connection: close\r\n") != null);
    try testing.expectEqual(@as(u32, 0), hits.load(.monotonic)); // handler never ran
    // Header order reversed is rejected identically.
    const got2 = runStream(null, "POST /echo HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", &out_buf);
    try testing.expect(std.mem.startsWith(u8, got2, "HTTP/1.1 400 Bad Request\r\n"));
}

test "serveStream: request path normalized + traversal-clamped before routing" {
    var out_buf: [4096]u8 = undefined;
    // `..` and `.` segments collapse; the normalized path routes to /hello.
    try testing.expect(std.mem.endsWith(u8, runStream(null, "GET /x/../hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf), "\r\n\r\nhello"));
    try testing.expect(std.mem.endsWith(u8, runStream(null, "GET /./hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf), "\r\n\r\nhello"));
    // A leading `..` is clamped at root (never escapes): `/../hello` → `/hello`.
    try testing.expect(std.mem.endsWith(u8, runStream(null, "GET /../hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf), "\r\n\r\nhello"));
    // Query survives normalization of the path half.
    const q = runStream(null, "GET /a/../hello?x=1 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, q, "X-Query: x=1\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, q, "\r\n\r\nhello"));
    // Already-normal routes are byte-for-byte unaffected (404 path).
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET /nope HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 404 Not Found\r\n"));
}

test "serveStream: NUL / encoded-NUL in the path → 400" {
    var out_buf: [4096]u8 = undefined;
    // Percent-encoded NUL: the parser passes it, normalization rejects it.
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET /a%00b HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    // A raw NUL never even parses (control byte in the target) → 400.
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET /a\x00b HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
}

test "serveStream: per-connection request cap closes the connection" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    // Cap = 2 over three pipelined requests: two are served, the second
    // carries Connection: close, and the third is never read.
    const three = "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ** 3;
    const got = runStreamWith(.{ .max_requests_per_conn = 2 }, &hits, three, &out_buf);
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "Connection: close\r\n"));

    // Cap = 0 (unlimited): all three are served, none forced closed.
    hits = .init(0);
    const all = runStreamWith(.{ .max_requests_per_conn = 0 }, &hits, three, &out_buf);
    try testing.expectEqual(@as(u32, 3), hits.load(.monotonic));
    try testing.expect(std.mem.indexOf(u8, all, "Connection: close") == null);
}

// ── tests (offline — Phase 2.2 gzip response compression) ───────────────────

test {
    _ = gzip; // pull in gzip.zig's negotiation/eligibility unit tests
    _ = h2s; // pull in the h2c serving-loop tests (Phase 3.1)
}

/// min_size below `small_json.len` so both the buffered and the streaming
/// paths engage with the tiny offline buffers.
const gz_on: Compression = .{ .min_size = 16 };

/// Parse a raw compressed response: expect 200 + `Content-Encoding: gzip`
/// + `Vary: Accept-Encoding` + chunked framing (no Content-Length), then
/// decode both layers and compare against the plain body.
fn expectGzipResponse(raw: []const u8, expected_body: []const u8) !void {
    var r: Reader = .fixed(raw);
    var head_buf: [1024]u8 = undefined;
    const res = try h1.ResponseHead.parse(try h1.readHead(&r, &head_buf));
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("gzip", res.header("content-encoding").?);
    try testing.expectEqualStrings("Accept-Encoding", res.header("vary").?);
    try testing.expect(res.chunked); // streaming framing…
    try testing.expectEqual(@as(?u64, null), res.content_length); // …never a length

    // Chunked-decode to the compressed bytes…
    var cbuf: [128]u8 = undefined;
    var cr: h1.ChunkedReader = .init(&r, &cbuf);
    var compressed_buf: [4096]u8 = undefined;
    var cw: Writer = .fixed(&compressed_buf);
    _ = try cr.reader.streamRemaining(&cw);

    // …then gunzip and compare: exactly what the handler wrote.
    var zin: Reader = .fixed(cw.buffered());
    var dc: flate.Decompress = .init(&zin, .gzip, &.{});
    var plain_buf: [4096]u8 = undefined;
    var pw: Writer = .fixed(&plain_buf);
    _ = try dc.reader.streamRemaining(&pw);
    try testing.expectEqualStrings(expected_body, pw.buffered());
}

test "serveStream gzip: negotiated response compresses and round-trips (streaming path)" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, null, "GET /jsonbig HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    try expectGzipResponse(got, json_body);
    // Actually smaller on the wire — headers included — than the body alone.
    try testing.expect(got.len < json_body.len);
}

test "serveStream gzip: fully buffered body compresses too" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, null, "GET /json HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    try expectGzipResponse(got, small_json);
}

test "serveStream gzip: no Accept-Encoding → identity, Vary still set" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, null, "GET /json HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    var r: Reader = .fixed(got);
    var head_buf: [1024]u8 = undefined;
    const res = try h1.ResponseHead.parse(try h1.readHead(&r, &head_buf));
    try testing.expect(res.header("content-encoding") == null);
    try testing.expectEqualStrings("Accept-Encoding", res.header("vary").?);
    try testing.expectEqual(@as(?u64, small_json.len), res.content_length);
    try testing.expect(std.mem.endsWith(u8, got, small_json));
}

test "serveStream gzip: q=0 refusal and HTTP/1.0 stay identity" {
    var out_buf: [4096]u8 = undefined;
    const refused = runStreamWith(.{ .compression = gz_on }, null, "GET /json HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip;q=0\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, refused, "Content-Encoding") == null);
    try testing.expect(std.mem.endsWith(u8, refused, small_json));

    // HTTP/1.0 cannot take chunked framing → never compressed (nginx
    // `gzip_http_version 1.1` behavior).
    var out_buf2: [4096]u8 = undefined;
    const old = runStreamWith(.{ .compression = gz_on }, null, "GET /jsonbig HTTP/1.0\r\nAccept-Encoding: gzip\r\n\r\n", &out_buf2);
    try testing.expect(std.mem.indexOf(u8, old, "Content-Encoding") == null);
    try testing.expect(std.mem.endsWith(u8, old, json_body));
}

test "serveStream gzip: below min_size stays identity" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = .{ .min_size = 1024 } }, null, "GET /json HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Encoding") == null);
    try testing.expect(std.mem.indexOf(u8, got, "Vary: Accept-Encoding\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, small_json));
}

test "serveStream gzip: content-type outside the allowlist stays identity" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, null, "GET /bin HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Encoding") == null);
    // Big identity body → a *plain* chunked stream; decode and compare.
    var r: Reader = .fixed(got);
    var head_buf: [1024]u8 = undefined;
    const res = try h1.ResponseHead.parse(try h1.readHead(&r, &head_buf));
    try testing.expect(res.chunked);
    var cbuf: [128]u8 = undefined;
    var cr: h1.ChunkedReader = .init(&r, &cbuf);
    var plain_buf: [4096]u8 = undefined;
    var pw: Writer = .fixed(&plain_buf);
    _ = try cr.reader.streamRemaining(&pw);
    try testing.expectEqualStrings(json_body, pw.buffered());
}

test "serveStream gzip: pre-encoded response is never re-compressed" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, null, "GET /pregz HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    // The handler's own Content-Encoding header + bytes pass through verbatim.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "Content-Encoding"));
    try testing.expect(std.mem.endsWith(u8, got, "FAKE-GZIP-BYTES-FAKE-GZIP-BYTES"));
}

test "serveStream gzip: HEAD and 204 are never compressed (Vary still set)" {
    var out_buf: [4096]u8 = undefined;
    const head_res = runStreamWith(.{ .compression = gz_on }, null, "HEAD /json HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, head_res, "Content-Encoding") == null);
    try testing.expect(std.mem.indexOf(u8, head_res, "Vary: Accept-Encoding\r\n") != null);
    // HEAD mirrors the identity variant's length.
    try testing.expect(std.mem.indexOf(u8, head_res, "Content-Length: 32\r\n") != null);

    var out_buf2: [4096]u8 = undefined;
    const nocontent = runStreamWith(.{ .compression = gz_on }, null, "GET /nocontent HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf2);
    try testing.expect(std.mem.startsWith(u8, nocontent, "HTTP/1.1 204 No Content\r\n"));
    try testing.expect(std.mem.indexOf(u8, nocontent, "Content-Encoding") == null);
    try testing.expect(std.mem.indexOf(u8, nocontent, "Vary: Accept-Encoding\r\n") != null);
}

test "serveStream gzip: declared Content-Length is dropped when compressing" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, null, "GET /declgz HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length") == null);
    try expectGzipResponse(got, json_body);
}

test "serveStream gzip: keep-alive survives a compressed response" {
    var hits: Hits = .init(0);
    var out_buf: [8192]u8 = undefined;
    const got = runStreamWith(.{ .compression = gz_on }, &hits, "GET /jsonbig HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
    // The compressed chunked stream terminated cleanly right before the
    // second (identity) response.
    try testing.expect(std.mem.indexOf(u8, got, "0\r\n\r\nHTTP/1.1 200 OK\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "hello"));
}

// ── tests (offline — Task 3: incoming chunked trailers) ─────────────────────

test "serveStream: chunked request trailers reach the handler (Task 3)" {
    var out_buf: [4096]u8 = undefined;
    const wire = "POST /trailers HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: deadbeef\r\nX-Rows: 2\r\n\r\n";
    // Default path (no body cap): trailers captured, handler reads them.
    const got = runStream(null, wire, &out_buf);
    try testing.expect(std.mem.endsWith(u8, got, "trailer=deadbeef"));
    // Capped chunked path (max_body_bytes set) captures trailers too.
    const capped = runStreamWith(.{ .max_body_bytes = 1024 }, null, wire, &out_buf);
    try testing.expect(std.mem.endsWith(u8, capped, "trailer=deadbeef"));
}

test "serveStream: a body with no trailers reports none (Task 3)" {
    var out_buf: [4096]u8 = undefined;
    // Chunked but no trailer fields.
    const chunked = runStream(null, "POST /trailers HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "3\r\nabc\r\n0\r\n\r\n", &out_buf);
    try testing.expect(std.mem.endsWith(u8, chunked, "trailer=none"));
    // Content-Length body: no trailer concept at all → none.
    const cl = runStream(null, "POST /trailers HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc", &out_buf);
    try testing.expect(std.mem.endsWith(u8, cl, "trailer=none"));
}

// ── tests (offline — Task 1: inbound gzip request-body decoding) ────────────

/// gzip-compress `plain` into a freshly allocated buffer (caller frees).
fn gzipAlloc(plain: []const u8) ![]u8 {
    const scratch = try testing.allocator.create(GzipScratch);
    defer testing.allocator.destroy(scratch);
    var aw: Writer.Allocating = try .initCapacity(testing.allocator, 64);
    defer aw.deinit();
    scratch.compress = try flate.Compress.init(&aw.writer, &scratch.window, .gzip, gzip.levelOptions(6));
    try scratch.compress.writer.writeAll(plain);
    try scratch.compress.finish();
    return testing.allocator.dupe(u8, aw.written());
}

/// Build a `POST /echo` request whose body is `compressed` under the given
/// `Content-Encoding` (caller frees).
fn gzipRequest(content_encoding: []const u8, compressed: []const u8) ![]u8 {
    return std.fmt.allocPrint(testing.allocator, "POST /echo HTTP/1.1\r\nHost: t\r\n" ++
        "Content-Encoding: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        content_encoding, compressed.len, compressed,
    });
}

test "serveStream: gzip request body is decompressed for the handler" {
    // 52 decompressed bytes: fits /echo's response buffer (64) so the reply
    // is exact-Content-Length — endsWith(plain) proves the decoded plaintext.
    const plain = "gzipped-body!" ** 4;
    const compressed = try gzipAlloc(plain);
    defer testing.allocator.free(compressed);
    try testing.expect(compressed.len < plain.len); // repetitive → shrinks
    const wire = try gzipRequest("gzip", compressed);
    defer testing.allocator.free(wire);

    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .max_decompressed_request_bytes = 1 << 20 }, null, wire, &out_buf);
    var lenbuf: [32]u8 = undefined;
    const cl = try std.fmt.bufPrint(&lenbuf, "Content-Length: {d}\r\n", .{plain.len});
    try testing.expect(std.mem.indexOf(u8, got, cl) != null);
    try testing.expect(std.mem.endsWith(u8, got, plain));
    // The x-gzip alias decodes identically.
    const wire2 = try gzipRequest("x-gzip", compressed);
    defer testing.allocator.free(wire2);
    const got2 = runStreamWith(.{ .max_decompressed_request_bytes = 1 << 20 }, null, wire2, &out_buf);
    try testing.expect(std.mem.endsWith(u8, got2, plain));
}

test "serveStream: gzip request body over the decompressed cap → 413 (zip-bomb guard)" {
    const plain = "gzipped-body!" ** 4; // 52 decompressed bytes
    const compressed = try gzipAlloc(plain);
    defer testing.allocator.free(compressed);
    const wire = try gzipRequest("gzip", compressed);
    defer testing.allocator.free(wire);

    var out_buf: [4096]u8 = undefined;
    // Cap of 16 < 52 decoded → the handler's read fails, mapped to 413
    // before the head is sent.
    const got = runStreamWith(.{ .max_decompressed_request_bytes = 16 }, null, wire, &out_buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 413 Content Too Large\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "Connection: close\r\n") != null);
}

test "serveStream: identity request body unchanged while gzip decoding is enabled" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .max_decompressed_request_bytes = 1 << 20 }, null, "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length: 5\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nhello"));
}

test "serveStream: unsupported / disabled Content-Encoding → 415" {
    var hits: Hits = .init(0);
    var out_buf: [4096]u8 = undefined;
    // An unknown coding is refused even with decoding enabled.
    const br = runStreamWith(.{ .max_decompressed_request_bytes = 1 << 20 }, &hits, "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: br\r\nContent-Length: 3\r\n\r\nabc", &out_buf);
    try testing.expect(std.mem.startsWith(u8, br, "HTTP/1.1 415 Unsupported Media Type\r\n"));
    // gzip while decoding is OFF (the default) is refused too — never hand
    // the handler compressed bytes.
    const off = runStream(&hits, "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc", &out_buf);
    try testing.expect(std.mem.startsWith(u8, off, "HTTP/1.1 415 Unsupported Media Type\r\n"));
    // A coding list is not unwrapped → 415.
    const list = runStreamWith(.{ .max_decompressed_request_bytes = 1 << 20 }, &hits, "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: gzip, br\r\nContent-Length: 3\r\n\r\nabc", &out_buf);
    try testing.expect(std.mem.startsWith(u8, list, "HTTP/1.1 415 Unsupported Media Type\r\n"));
    try testing.expectEqual(@as(u32, 0), hits.load(.monotonic)); // handler never ran
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

// ── tests (in-process integration — Phase 2.1 hardening) ────────────────────

/// Poll `activeConnections` until it reaches `want` (bounded ≈ 10 s).
fn waitForActive(server: *Server, io: std.Io, want: usize) !void {
    var tries: usize = 0;
    while (server.activeConnections() != want) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }
}

fn acceptCounting(ctx: ?*anyopaque, peer: net.IpAddress) ConnDecision {
    _ = peer;
    const n: *Hits = @ptrCast(@alignCast(ctx.?));
    _ = n.fetchAdd(1, .monotonic);
    return .accept;
}

fn rejectLoopback(_: ?*anyopaque, peer: net.IpAddress) ConnDecision {
    return switch (peer) {
        .ip4 => |a| if (std.mem.eql(u8, &a.bytes, &.{ 127, 0, 0, 1 })) .reject else .accept,
        .ip6 => .accept,
    };
}

test "integration: handler sees the loopback peer + rising request index; on_connect fires per connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var conns: Hits = .init(0);
    var server = init(io, testing.allocator, .{
        .handler = testHandler,
        .on_connect = acceptCounting,
        .on_connect_ctx = &conns,
    });
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
    var rbuf: [4096]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var head_buf: [2048]u8 = undefined;

    // Request 1: peer = loopback, index 0.
    try sw.interface.writeAll("GET /connmeta HTTP/1.1\r\nHost: t\r\n\r\n");
    try sw.interface.flush();
    const res1 = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
    try testing.expectEqual(@as(u16, 200), res1.status);
    const body1 = try sr.interface.take(res1.content_length.?);
    try testing.expect(std.mem.startsWith(u8, body1, "127.0.0.1:"));
    try testing.expect(std.mem.endsWith(u8, body1, " #0"));

    // Request 2 on the same connection: index rose to 1.
    try sw.interface.writeAll("GET /connmeta HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try sw.interface.flush();
    const res2 = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
    try testing.expectEqual(@as(u16, 200), res2.status);
    const body2 = try sr.interface.take(res2.content_length.?);
    try testing.expect(std.mem.startsWith(u8, body2, "127.0.0.1:"));
    try testing.expect(std.mem.endsWith(u8, body2, " #1"));

    // One connection, two requests → the accept hook fired exactly once.
    try testing.expectEqual(@as(u32, 1), conns.load(.monotonic));
}

test "integration: on_connect rejecting the peer refuses the connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = init(io, testing.allocator, .{
        .handler = testHandler,
        .on_connect = rejectLoopback, // we connect from 127.0.0.1 → rejected
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    // The TCP handshake completes (kernel backlog), then the server closes
    // without writing a byte: the first read fails.
    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [64]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    if (sr.interface.take(1)) |_| {
        return error.TestUnexpectedResult; // the server must not serve us
    } else |err| {
        try testing.expect(err == error.EndOfStream or err == error.ReadFailed);
    }
    // A rejected connection is never admitted.
    try testing.expectEqual(@as(usize, 0), server.activeConnections());
}

test "integration: activeConnections reflects an in-flight request" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = init(io, testing.allocator, .{ .handler = testHandler });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    try testing.expectEqual(@as(usize, 0), server.activeConnections());

    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var head_buf: [2048]u8 = undefined;

    // Head only — the handler blocks reading the body, keeping the
    // connection in flight while we observe the counter.
    try sw.interface.writeAll("POST /echo HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 4\r\n\r\n");
    try sw.interface.flush();
    try waitForActive(&server, io, 1);

    // Release the request; the response completes and the connection ends.
    try sw.interface.writeAll("ping");
    try sw.interface.flush();
    const res = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("ping", try sr.interface.take(4));
    try waitForActive(&server, io, 0);
}

// ── tests (in-process integration — Phase 2.2 gzip compression) ─────────────

test "integration: negotiated gzip compression over loopback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = init(io, testing.allocator, .{
        .handler = testHandler,
        .compression = .{}, // defaults: min 1 KiB, level 6, text/JSON/XML/JS
        // Small response buffer so /jsonbig (~1.8 KiB) exercises the real
        // streaming (chunked) gzip encoder over the wire.
        .response_buffer_size = 256,
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

    { // Accept-Encoding: gzip → compressed; decompresses to the exact JSON.
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/jsonbig", .{port});
        var res = try client.request(.get, url, .{
            .headers = &.{.{ .name = "Accept-Encoding", .value = "gzip" }},
        });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("gzip", res.header("content-encoding").?);
        try testing.expectEqualStrings("Accept-Encoding", res.header("vary").?);
        try testing.expect(res.head.chunked); // compressed = streamed, no length

        // The Phase-1 client leaves gzip decode to the caller — do it here.
        const compressed = try res.readAllAlloc(testing.allocator, 1 << 16);
        defer testing.allocator.free(compressed);
        try testing.expect(compressed.len < json_body.len);
        var zin: Reader = .fixed(compressed);
        var dc: flate.Decompress = .init(&zin, .gzip, &.{});
        var plain: Writer.Allocating = .init(testing.allocator);
        defer plain.deinit();
        _ = try dc.reader.streamRemaining(&plain.writer);
        try testing.expectEqualStrings(json_body, plain.written());
    }

    { // No gzip opt-in (client default = identity) → plain body, no
        // Content-Encoding, but Vary still marks the negotiation point.
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/jsonbig", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(res.header("content-encoding") == null);
        try testing.expectEqualStrings("Accept-Encoding", res.header("vary").?);
        const body = try res.readAllAlloc(testing.allocator, 1 << 16);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(json_body, body);
    }

    { // Tiny body under min_size → identity even though gzip was accepted.
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.get, url, .{
            .headers = &.{.{ .name = "Accept-Encoding", .value = "gzip" }},
        });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(res.header("content-encoding") == null);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }
}
