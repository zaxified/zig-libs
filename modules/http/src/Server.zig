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
//! Multicore accept engine (opt-in, `Options.accept_threads` > 1): bind N
//! listener sockets on the same address — each with SO_REUSEPORT
//! (`reuse_address`, forced on in this mode) — and run N independent accept
//! loops, each on its own OS thread pinned to a distinct core (Linux
//! `sched_setaffinity`; a best-effort no-op elsewhere). The kernel
//! load-balances incoming connections across the listeners
//! (nginx/glommio model), so there is zero cross-core accept contention and
//! no thundering herd on one listen queue — the shape an API gateway wants.
//! Each accept loop owns its own `Io.Group` (no shared-group contention);
//! `shutdown` drains all N. `accept_threads == 1` (the default) is the
//! classic single accept loop on the caller's thread, byte-for-byte
//! unchanged. io_uring is deliberately not used: its net vtable is
//! `Unavailable` in std 0.16.
//!
//! Timeout model (poll(2)-based; compile-time disabled where poll is
//! unavailable): `read_timeout_ms` bounds every read *stall* (request head,
//! body, keep-alive idle); `request_timeout_ms` is a whole-request read
//! deadline (Go ReadTimeout shape: keep-alive idle + head + body share one
//! budget, so a dribbling client cannot stretch a request forever);
//! `write_timeout_ms` bounds every write stall (a peer that stops reading).
//!
//! Hardening (Phase 2.1, ../SPEC.md) — built to face the
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
//! Compression (Phase 2.2, ../SPEC.md): `Options.compression`
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
const bufpool = @import("bufpool.zig");
// The branchless civil-from-days calendar, for the `Date` header. std has one
// too, and it walks a year at a time from 1970 -- see `formatHttpDate`.
const datefmt = @import("datefmt");
const flate = std.compress.flate;
const net = std.Io.net;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const Server = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
/// Listener #0 — bound in both modes; `boundAddress` reports its address.
listener: ?net.Server,
/// Additional SO_REUSEPORT listeners #1..N-1 for the multicore accept
/// engine (`Options.accept_threads` > 1); empty in the single-listener
/// default. Heap-owned, freed in `deinit`.
aux_listeners: []net.Server,
/// Tracks the per-connection tasks of the single-listener path; awaited
/// before `serve` returns. In the multicore path each accept thread owns
/// its own group instead.
group: std.Io.Group,
/// Connections currently admitted and being served (see
/// `activeConnections`). Atomic: touched by the accept loop and every
/// connection task.
active_conns: std.atomic.Value(usize),
/// The Zig error name behind the most recent `BadAddress`/`ListenFailed`
/// from `bind` — see `bindErrorName`. Same shape as `probe.ConnectOutcome.
/// err_name`: `std.Io.net` reports an `anyerror`, not an errno, so there is
/// no numeric code to carry, only `@errorName`'s static string. Null before
/// the first failing `bind` call and after a successful one.
last_bind_error: ?[]const u8,

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

/// Where a connection's per-request working memory comes from, when the
/// caller would rather **lend** it than own it.
///
/// ## Why this exists
///
/// `StreamBuffers` is otherwise the caller's for the whole connection, and
/// for a server holding many connections open that is most of what it costs.
/// Measured on this repo's own bench box, a TLS connection parked between
/// requests held 28 KiB of buffer containing nothing, of which 16 KiB was the
/// codec's `head`, `response_body` and `chunk` — memory that is scratch by
/// construction, rewritten before it is read, and dead every moment the
/// connection is waiting.
///
/// A provider makes that memory belong to a **request** instead of a
/// connection, so the steady-state cost is `set_size * in-flight requests`
/// rather than `set_size * open connections`. `bufpool.BufferPool` is the
/// obvious backing and `PooledBuffers` wires the two together in three lines.
///
/// ⭐ **Release has to be cheap.** The naive version of this idea hands the
/// pages back to the kernel at each request boundary; measured, that is a
/// syscall per request and it cost **57% of throughput** (79,099 req/s
/// against 34,216). A pool release is a push onto a list, and the kernel only
/// hears about it when the pool overflows. That difference is the whole
/// design.
///
/// `acquire` returning null is **backpressure**, not an error: the connection
/// is answered 503 and closed. A server that would rather queue should block
/// inside `acquire` instead.
/// A `BuffersProvider` backed by `bufpool.BufferPool`: one slab per in-flight
/// request, carved into the buffers the codec asks for.
///
/// The three lines a caller writes:
///
/// ```zig
/// var pool: http.bufpool.BufferPool = .init(gpa, layout.slabSize(), 64);
/// var layout: http.Server.PooledBuffers = .{ .pool = &pool, .head_len = 8192, ... };
/// opts.buffers_provider = layout.provider();
/// ```
///
/// The pool's `max_idle_slabs` is the memory ceiling this buys: a server
/// holding ten thousand connections that are mostly waiting keeps
/// `slab_size * max_idle_slabs`, not `slab_size * 10,000`.
///
/// Sub-buffers are carved in a fixed order from one slab, so a released slab
/// is recovered from the head buffer's pointer. Handing `release` anything
/// this did not produce is a bug in the caller and is asserted in safe
/// builds.
pub const PooledBuffers = struct {
    pool: *bufpool.BufferPool,
    head_len: usize,
    request_body_len: usize,
    response_body_len: usize,
    chunk_len: usize,
    trailers_len: usize = 0,

    /// What to construct the pool with. A pool whose slabs are a different
    /// size cannot serve this layout.
    ///
    /// ⚠ Deliberately NOT in the slab: the serving loop's own per-request
    /// state (the response writer, the path-normalization buffer). It was
    /// tried -- measured at 200-connection saturation, in-flight borrows
    /// approach the connection count (responses park on full sockets), so a
    /// bigger slab is paid per CONNECTION exactly when memory is scarcest:
    /// +14 KiB of slab cost +18 KiB/conn of RSS. A caller who parks its
    /// keep-alive wait outside `serveStep` gets those frame pages back for
    /// free between requests; a slab carries them forever.
    pub fn slabSize(l: PooledBuffers) usize {
        return l.head_len + l.request_body_len + l.response_body_len + l.chunk_len + l.trailers_len;
    }

    pub fn provider(self: *PooledBuffers) BuffersProvider {
        return .{ .ctx = self, .acquire = acquireFn, .release = releaseFn };
    }

    fn acquireFn(ctx: ?*anyopaque) ?StreamBuffers {
        const self: *PooledBuffers = @ptrCast(@alignCast(ctx.?));
        const slab = self.pool.acquire() catch return null;
        var at: usize = 0;
        const head = slab[at..][0..self.head_len];
        at += self.head_len;
        const request_body = slab[at..][0..self.request_body_len];
        at += self.request_body_len;
        const response_body = slab[at..][0..self.response_body_len];
        at += self.response_body_len;
        const chunk = slab[at..][0..self.chunk_len];
        at += self.chunk_len;
        const trailers = slab[at..][0..self.trailers_len];
        return .{
            .head = head,
            .request_body = request_body,
            .response_body = response_body,
            .chunk = chunk,
            .trailers = trailers,
        };
    }

    fn releaseFn(ctx: ?*anyopaque, b: StreamBuffers) void {
        const self: *PooledBuffers = @ptrCast(@alignCast(ctx.?));
        const slab = b.head.ptr[0..self.slabSize()];
        self.pool.release(slab);
    }
};

pub const BuffersProvider = struct {
    ctx: ?*anyopaque = null,
    /// Called before each request on the connection.
    acquire: *const fn (?*anyopaque) ?StreamBuffers,
    /// Called after each request, with exactly what `acquire` returned.
    release: *const fn (?*anyopaque, StreamBuffers) void,
};

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
    /// Lend a connection its working memory one request at a time instead of
    /// taking the caller's for the whole connection. Null keeps the buffers
    /// the serving loop allocates per connection, which is what every caller
    /// did before this existed.
    ///
    /// ⚠ **HTTP/1.1 only.** The h2 codec's working memory is per stream
    /// rather than per request and lending it is a different change; an h2
    /// connection ignores this. See `BuffersProvider`.
    buffers_provider: ?BuffersProvider = null,
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
    /// Disable Nagle's algorithm (`TCP_NODELAY`) on every accepted
    /// connection. Default **on**: an API/RPC server writes a complete
    /// response and then waits for the next request, so Nagle buffering the
    /// last small segment until an ACK — which delayed-ACK holds for up to
    /// ~40 ms — adds a flat per-response latency floor that request/response
    /// traffic never benefits from (measured ~41 ms p50 with it off). Set
    /// false only for a connection that streams many tiny writes it wants
    /// coalesced. Applies to the built-in accept loop; a bring-your-own-TLS
    /// caller that owns the socket sets it via `setTcpNoDelay` on its fd.
    tcp_nodelay: bool = true,
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
    /// memory. **null = unlimited — set this for any route that accepts
    /// real uploads**, or every body over 1 MiB gets a 413 (see README
    /// "Direct-internet posture"). Applies to `enable_h2c` requests too:
    /// `connMain` forwards this exact value into `h2_server.Options` when
    /// dispatching an h2 connection, so a `Server`-based consumer is
    /// hardened identically on both protocols by default — the lower-level
    /// `h2_server.Options.max_body_bytes` (like `StreamOptions.max_body_bytes`)
    /// defaults to null only because that struct is the permissive
    /// composable-codec layer this one wraps, not because h2 is
    /// intentionally left uncapped when served through `Server`.
    max_body_bytes: ?u64 = 1 << 20,
    /// Response body buffering: bodies fully written within this get an
    /// exact Content-Length, larger ones stream chunked. **A response
    /// larger than this switches to chunked framing silently** — a peer
    /// whose HTTP client does not decode chunked transfer coding (a minimal
    /// hand-rolled client is the common case) needs an explicit
    /// `rw.setHeader("Content-Length", …)` on every such response instead
    /// of relying on the auto framing.
    response_buffer_size: usize = 4 * 1024,
    /// Max requests served on a single keep-alive connection before it is
    /// closed gracefully: the response to the last permitted request carries
    /// `Connection: close` and the connection ends (Go `Server` /
    /// nginx `keepalive_requests` shape — bounds a connection that pipelines
    /// forever inside the timeouts). 0 = unlimited.
    max_requests_per_conn: u32 = 1000,
    /// Negotiated gzip response compression (../SPEC.md). null =
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
    /// Auto `Server` response header, overridable per response. null =
    /// omit the header entirely (matches `StreamOptions.server_name`'s
    /// null-means-omit shape — see `emit_date` for why the socket path
    /// needed this and did not have it).
    server_name: ?[]const u8 = "zig-libs-http/0.1",
    /// Auto `Date` header (IMF-fixdate) on every response. true (default)
    /// installs the server's own wall clock, exactly as before this field
    /// existed; false omits the header. This mirrors
    /// `StreamOptions.now`/`h2_server.Options.now` being `?Now` with
    /// null = omit, but stays a plain bool here — `Server.Options` only
    /// ever wants "the server's clock or nothing", never a caller-supplied
    /// `Now`, so there is no reason to spend the `Now` type on this surface.
    /// Before this field existed, the socket path (`connMain`) always built
    /// a non-null `Now`, so a consumer moving from a header-free bespoke
    /// server onto this one saw a new `Date` on every response with no way
    /// to turn it off — this field, and `server_name` becoming optional
    /// above, close that gap.
    emit_date: bool = true,
    kernel_backlog: u31 = 128,
    reuse_address: bool = false,
    /// Multicore accept engine (SO_REUSEPORT thread-per-core). 1 (the
    /// default) = the classic single accept loop on the caller's thread. N >
    /// 1 = bind N listener sockets on the same address (each SO_REUSEPORT —
    /// `reuse_address` is forced on) and run N independent accept loops, each
    /// on its own OS thread pinned to a distinct core; the kernel
    /// load-balances accepts across them. `serve` returns only after every
    /// listener's accept loop has drained its connections. `shutdown` stops
    /// all N. Pass `Server.cpuCount()` for one listener per core. 0 is
    /// treated as 1. See the module-level "Multicore accept engine" note.
    accept_threads: u32 = 1,
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
    /// Per-request opt-in to HTTP/2's **incremental request body** (only
    /// meaningful with `enable_h2c`, or via `h2_server.serveStream`).
    ///
    /// On HTTP/1.1 a handler always reads the request body straight off the
    /// socket as it arrives. HTTP/2 cannot do that by default and stay
    /// compatible: the answers this server gives *before* a handler runs —
    /// 413 for a body over `max_body_bytes`, 400 for a `content-length`
    /// disagreeing with the DATA total (RFC 9113 §8.1.1) — need the whole
    /// body first. Returning true from this predicate trades those two
    /// pre-dispatch answers for h1's behavior on the routes that want it:
    /// the handler starts at HEADERS and reads DATA as it lands (the two
    /// checks still happen, but as read failures — 413 and a failed stream
    /// respectively). Null (the default) keeps every request buffered.
    ///
    /// See `h2_server.Options.stream_request`.
    h2_stream_request: ?H2StreamRequestFn = null,
    /// Run HTTP/2 handlers on a caller-supplied bounded worker pool instead
    /// of on the connection's own task (only meaningful with `enable_h2c`,
    /// or via `h2_server.serveStream`). Null (the default) keeps the
    /// historical sequential behavior. See `h2_server.Dispatcher` and the
    /// "Concurrent handlers" section of that module's doc — in particular
    /// the obligation that `gpa` and `on_conn_state` be thread-safe once a
    /// dispatcher is installed. This does NOT affect HTTP/1.1, which is
    /// already one connection per thread.
    h2_dispatcher: ?H2Dispatcher = null,
};

/// Re-export of `h2_server.Limits` for `Options.h2_limits`.
pub const H2Limits = h2s.Limits;

/// Re-export of `h2_server.StreamRequestFn` for `Options.h2_stream_request`.
pub const H2StreamRequestFn = h2s.StreamRequestFn;

/// Re-export of `h2_server.RequestPreview` — what `h2_stream_request` sees.
pub const H2RequestPreview = h2s.RequestPreview;

/// Re-export of `h2_server.Dispatcher` for `Options.h2_dispatcher`.
pub const H2Dispatcher = h2s.Dispatcher;

/// Re-export of `h2_server.Task` — the unit `H2Dispatcher.spawn` receives.
pub const H2Task = h2s.Task;

/// `io` must support the net + concurrency vtable operations (e.g.
/// `std.Io.Threaded`). The allocator provides per-connection buffers.
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Server {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .listener = null,
        .aux_listeners = &.{},
        .group = .init,
        .active_conns = .init(0),
        .last_bind_error = null,
    };
}

/// One listener/accept-thread per online CPU — the usual argument for
/// `Options.accept_threads` in the multicore engine. Falls back to 1 when
/// the count is unavailable.
pub fn cpuCount() u32 {
    return @intCast(std.Thread.getCpuCount() catch 1);
}

/// Number of connections currently admitted and being served (accepted,
/// past `on_connect`, not yet closed). Thread-safe; callable from any
/// thread while `serve` runs — the enforcement point for a global
/// connection cap (`throttle`) inside an `on_connect` hook.
pub fn activeConnections(s: *const Server) usize {
    return s.active_conns.load(.monotonic);
}

/// Closes every listener if still open. Only call after `serve` returned.
pub fn deinit(s: *Server) void {
    if (s.listener) |*l| l.deinit(s.io);
    for (s.aux_listeners) |*l| l.deinit(s.io);
    if (s.aux_listeners.len != 0) s.gpa.free(s.aux_listeners);
    s.* = undefined;
}

pub const BindError = error{ BadAddress, ListenFailed, Canceled };

/// Bind + listen on `options.addr:port`. `boundAddress` is valid afterwards
/// (an ephemeral port is resolved). Split from `serve` so callers can learn
/// the port before serving; `listen` does both.
///
/// `BadAddress`/`ListenFailed` collapse `std.Io.net`'s real error (a parse
/// failure or a `ListenError` tag like `AddressInUse`/`AddressUnavailable`)
/// into one of two tags — the underlying name is not lost, it lands in
/// `last_bind_error`/`bindErrorName()` (set right before each such return,
/// cleared at the top of `bind`), the same "classified tag + `@errorName`
/// alongside it" shape `probe.ConnectOutcome.err_name` uses for the same
/// reason: `std.Io.net` reports an `anyerror` here, not an errno, so there
/// is no numeric code to carry.
pub fn bind(s: *Server) BindError!void {
    std.debug.assert(s.listener == null);
    s.last_bind_error = null;
    const n = @max(1, s.options.accept_threads);
    // The multicore engine needs SO_REUSEPORT on every listener; the kernel
    // refuses a second bind on the same address otherwise.
    const reuse = s.options.reuse_address or n > 1;

    const addr0 = net.IpAddress.parse(s.options.addr, s.options.port) catch |err| {
        s.last_bind_error = @errorName(err);
        return error.BadAddress;
    };
    s.listener = addr0.listen(s.io, .{
        .kernel_backlog = s.options.kernel_backlog,
        .reuse_address = reuse,
    }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            s.last_bind_error = @errorName(err);
            return error.ListenFailed;
        },
    };
    if (n == 1) return;

    // Bind the remaining N-1 listeners on the *resolved* port: with port 0
    // each listener would otherwise be handed a different ephemeral port and
    // the SO_REUSEPORT group would never form.
    const resolved_port = s.listener.?.socket.address.getPort();
    const addr = net.IpAddress.parse(s.options.addr, resolved_port) catch |err| {
        s.last_bind_error = @errorName(err);
        return error.BadAddress;
    };
    const aux = s.gpa.alloc(net.Server, n - 1) catch |err| {
        s.last_bind_error = @errorName(err);
        return error.ListenFailed;
    };
    errdefer s.gpa.free(aux);
    var bound: usize = 0;
    errdefer for (aux[0..bound]) |*l| l.deinit(s.io);
    while (bound < aux.len) : (bound += 1) {
        aux[bound] = addr.listen(s.io, .{
            .kernel_backlog = s.options.kernel_backlog,
            .reuse_address = true,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                s.last_bind_error = @errorName(err);
                return error.ListenFailed;
            },
        };
    }
    s.aux_listeners = aux;
}

/// The Zig error name behind the most recent failing `bind()` call (e.g.
/// `"AddressInUse"`, `"AddressFamilyUnsupported"`, an `IpAddress.parse`
/// error like `"InvalidCharacter"`, or `"OutOfMemory"` from the multicore
/// listener array). Null before any `bind` call, after a successful one, or
/// after a `Canceled` `bind` (cancellation is not itself a diagnostic — the
/// error tag already says what happened). An `@errorName` result: a static
/// string, never allocated or freed.
pub fn bindErrorName(s: *const Server) ?[]const u8 {
    return s.last_bind_error;
}

test "bind: ListenFailed carries the underlying AddressInUse error name" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Bind #1 on an ephemeral port, so the exact port is known but held.
    var first = init(io, testing.allocator, .{ .handler = testHandler });
    defer first.deinit();
    first.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    try testing.expectEqual(@as(?[]const u8, null), first.bindErrorName());
    const held_port = first.boundAddress().getPort();

    // Bind #2 on the exact same address:port, without SO_REUSEADDR — the
    // kernel refuses it, and the old two-error-tag `bind` discarded exactly
    // which failure that was (the SPEC report this fixes).
    var second = init(io, testing.allocator, .{ .handler = testHandler, .port = held_port });
    defer second.deinit();
    try testing.expectError(error.ListenFailed, second.bind());
    try testing.expectEqualStrings("AddressInUse", second.bindErrorName().?);
}

test "bind: BadAddress carries the underlying parse-error name" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = init(io, testing.allocator, .{ .handler = testHandler, .addr = "not-an-ip" });
    defer server.deinit();
    try testing.expectEqual(@as(?[]const u8, null), server.bindErrorName());
    try testing.expectError(error.BadAddress, server.bind());
    // Not pinned to a specific std parse-error tag (IPv4 vs IPv6 parsers
    // may change which one std picks) — the load-bearing assertion is that
    // *some* real error name survived instead of being discarded.
    const name = server.bindErrorName() orelse return error.TestExpectedNonNull;
    try testing.expect(name.len > 0);
}

/// The address actually bound, with the resolved port — for ephemeral-port
/// (port 0) setups. Valid after `bind`.
pub fn boundAddress(s: *const Server) net.IpAddress {
    return s.listener.?.socket.address;
}

pub const ServeError = error{ AcceptFailed, Canceled };

/// Accept loop: dispatches connections until `shutdown` is called from
/// another thread (or accepting fails fatally), then waits for all
/// connection tasks to finish before returning. Call `bind` first. With
/// `Options.accept_threads` > 1 this fans the accept work out across N
/// core-pinned threads (see `serveMulti`).
pub fn serve(s: *Server) ServeError!void {
    if (s.aux_listeners.len == 0) {
        defer s.group.await(s.io) catch {};
        return s.acceptLoop(&s.listener.?, &s.group);
    }
    return s.serveMulti();
}

/// One accept loop over `listener`, dispatching each admitted connection as
/// a concurrent task into `group`. Returns on `shutdown` (the listener
/// stops listening) or a fatal accept error; the caller awaits `group`.
fn acceptLoop(s: *Server, listener: *net.Server, group: *std.Io.Group) ServeError!void {
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
        if (s.options.tcp_nodelay) setTcpNoDelay(stream.socket.handle);
        _ = s.active_conns.fetchAdd(1, .monotonic); // connMain decrements
        group.concurrent(s.io, connMain, .{ s, stream }) catch {
            // No concurrency available: serve the connection inline rather
            // than drop it.
            connMain(s, stream);
        };
    }
}

/// Per-listener accept thread: pin to a core, run the accept loop, then
/// drain this thread's connection tasks before it exits.
const AcceptThread = struct {
    s: *Server,
    listener: *net.Server,
    group: std.Io.Group = .init,
    cpu: usize,
    result: ServeError!void = {},

    fn main(t: *AcceptThread) void {
        pinToCpu(t.cpu);
        defer t.group.await(t.s.io) catch {};
        t.result = t.s.acceptLoop(t.listener, &t.group);
    }
};

/// Multicore accept engine: one core-pinned OS thread per listener, each
/// with its own accept loop and connection group. Joins them all (drains
/// every connection) before returning; reports the first fatal accept error.
fn serveMulti(s: *Server) ServeError!void {
    const n = s.aux_listeners.len + 1;
    const gpa = s.gpa;

    const threads = gpa.alloc(AcceptThread, n) catch return error.AcceptFailed;
    defer gpa.free(threads);
    const handles = gpa.alloc(?std.Thread, n) catch return error.AcceptFailed;
    defer gpa.free(handles);

    for (threads, 0..) |*t, i| {
        t.* = .{
            .s = s,
            .listener = if (i == 0) &s.listener.? else &s.aux_listeners[i - 1],
            .cpu = i,
        };
    }

    var spawn_failed = false;
    for (threads, handles) |*t, *h| {
        h.* = std.Thread.spawn(.{}, AcceptThread.main, .{t}) catch blk: {
            spawn_failed = true;
            break :blk null;
        };
    }
    // A spawn failure leaves some loops running; stop them all so the join
    // below cannot hang, then report the failure.
    if (spawn_failed) s.shutdown();

    var first_err: ?ServeError = null;
    for (threads, handles) |*t, h| {
        if (h) |handle| {
            handle.join();
            if (t.result) |_| {} else |e| first_err = first_err orelse e;
        }
    }
    if (spawn_failed) return error.AcceptFailed;
    if (first_err) |e| return e;
}

/// Best-effort core pinning (Linux `sched_setaffinity`; a no-op elsewhere).
/// `cpu` is taken modulo the online CPU count so more listeners than cores
/// still spread deterministically instead of failing.
fn pinToCpu(cpu: usize) void {
    if (builtin.os.tag != .linux) return;
    const ncpu = std.Thread.getCpuCount() catch return;
    if (ncpu == 0) return;
    const target = cpu % ncpu;
    var set = std.mem.zeroes(std.os.linux.cpu_set_t);
    const bits = @bitSizeOf(usize);
    set[target / bits] |= @as(usize, 1) << @intCast(target % bits);
    std.os.linux.sched_setaffinity(0, &set) catch {};
}

/// Best-effort `TCP_NODELAY` on a socket fd — disables Nagle so a completed
/// small response is not held back waiting for the peer's delayed ACK (see
/// `Options.tcp_nodelay` for the latency rationale). Failure is ignored: a
/// missing NODELAY only costs latency, never correctness, and a non-TCP fd
/// (e.g. a Unix socket) simply rejects the option. Public so a
/// bring-your-own-TLS server — which accepts the socket itself and hands the
/// decrypted stream to `serveStream`, bypassing this module's accept loop —
/// can apply the same tuning on the fd it owns.
pub fn setTcpNoDelay(handle: std.posix.socket_t) void {
    std.posix.setsockopt(
        handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        &std.mem.toBytes(@as(c_int, 1)),
    ) catch {};
}

/// Convenience: `bind` + `serve`.
pub fn listen(s: *Server) (BindError || ServeError)!void {
    try s.bind();
    try s.serve();
}

/// Stop accepting: wakes every blocked accept loop (all N listeners in the
/// multicore engine), which then drain their connections and return. Safe to
/// call from another thread while `serve` runs.
pub fn shutdown(s: *Server) void {
    if (s.listener) |l| {
        const stream: net.Stream = .{ .socket = l.socket };
        stream.shutdown(s.io, .both) catch {};
    }
    for (s.aux_listeners) |l| {
        const stream: net.Stream = .{ .socket = l.socket };
        stream.shutdown(s.io, .both) catch {};
    }
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
/// `Request.target` is preserved): the longest request PATH this server will
/// normalize, and so the longest it will serve -- above it the answer is 414
/// rather than routing raw. The query string is not counted; `path` is the
/// target up to the '?'.
///
/// ⚠ This is NOT `max_request_line_bytes`, which still defaults to 8 KiB: a
/// request line may carry that much, and a query string may use all of it,
/// but the path half of it stops here.
///
/// ⭐⭐ 8 KiB until 2026-08-29, and the number is not free: this buffer sits on
/// the serving frame, and that frame is the per-connection memory of any server
/// that gives a connection its own stack (see `frame_probe`). Measured against
/// a live server -- 256 TLS connections at saturation, io_uring, ReleaseFast --
/// dropping it to 2 KiB took anonymous memory from 41.4-42.5 KiB per connection
/// to 38.1 and the serving frame from 18,640 B to 12,496. Dropping it further,
/// to 512 B, bought nothing measurable (37.7 KiB): residency is counted in
/// pages and the rest of the frame is already dense.
///
/// ⚠ And it has to be the DECLARED size that shrinks. Not writing to the
/// buffer does nothing at all -- the frame is one contiguous allocation whose
/// every page carries something live -- which is why the dot-segment skip
/// above this saves work but not a byte of memory.
const max_normalized_path = 2 * 1024;

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
    // The wrappers take the concrete socket reader/writer, not just their
    // interfaces: `err` — the only place a cancelation survives — lives on
    // the concrete type.
    var sr = stream.reader(s.io, read_buf[0..0]);
    var tr: TimeoutReader = .init(&sr, s.io, o.read_timeout_ms, o.request_timeout_ms, read_buf);
    var sw = stream.writer(s.io, write_buf[0..0]);
    var tw: TimeoutWriter = .init(&sw, s.io, o.write_timeout_ms, write_buf);

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
                .now = if (o.emit_date) .{ .ctx = @ptrCast(&s.io), .epochSeconds = ioEpochSeconds } else null,
                .peer = stream.socket.address,
                .max_header_bytes = o.max_header_bytes,
                .max_body_bytes = o.max_body_bytes,
                .response_buffer_size = o.response_buffer_size,
                .compression = o.compression,
                .gzip_scratch = gz,
                .on_conn_state = o.on_conn_state,
                .on_conn_state_ctx = o.on_conn_state_ctx,
                // Deliberately not forwarded: the h2 codec's working memory
                // has a different shape (per-stream, not per-request) and
                // lending it is a separate change. `Options.buffers_provider`
                // is documented as h1-only for that reason.
                .limits = o.h2_limits,
                .stream_request = o.h2_stream_request,
                .dispatcher = o.h2_dispatcher,
            }, &tr.reader, &tw.writer);
            return;
        }
    }

    serveLoop(.{
        .handler = o.handler,
        .context = o.context,
        .server_name = o.server_name,
        .now = if (o.emit_date) .{ .ctx = @ptrCast(&s.io), .epochSeconds = ioEpochSeconds } else null,
        .peer = stream.socket.address,
        .max_request_line_bytes = o.max_request_line_bytes,
        .max_body_bytes = o.max_body_bytes,
        .on_conn_state = o.on_conn_state,
        .on_conn_state_ctx = o.on_conn_state_ctx,
        .buffers_provider = o.buffers_provider,
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
/// Cancelation is recorded out of band, in `canceled`, for the same reason
/// std records it out of band on the socket reader: `Reader.StreamError`
/// cannot carry `error.Canceled`, so a vtable implementation has nowhere to
/// *return* it however well it knows. Two separate blind spots feed that
/// field. The `poll` below is not a `std.Io` cancelation point at all — it
/// restarts itself on `EINTR`, and a thread parked in a syscall `std.Io`
/// never registered is not signalled in the first place, so the wait runs
/// its full timeout and the abandoned connection reports itself as a
/// stalled peer; `checkCanceled` after the wait is what closes that. And
/// once the read does reach the socket, the reason it failed survives only
/// on `src.err`, which `readFailure` consults before flattening.
///
/// `timed_out` and `canceled` stay separate deliberately: a peer that
/// stopped talking and a connection its own server gave up on are different
/// events, and folding either into the other is how a shutdown comes to
/// look like a slowloris.
///
/// Not movable after `reader` has been handed out.
const TimeoutReader = struct {
    io: std.Io,
    /// The socket reader itself, not just its interface — the concrete type
    /// is what carries `err`, and that is where a cancelation lives.
    src: *net.Stream.Reader,
    handle: net.Socket.Handle,
    timeout_ms: u32,
    request_timeout_ms: u32,
    /// Monotonic whole-request deadline; 0 = unarmed.
    deadline_ns: u64 = 0,
    reader: Reader,
    timed_out: bool = false,
    canceled: bool = false,

    fn init(src: *net.Stream.Reader, io: std.Io, timeout_ms: u32, request_timeout_ms: u32, buffer: []u8) TimeoutReader {
        return .{
            .io = io,
            .src = src,
            .handle = src.stream.socket.handle,
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

    /// `Io.checkCancel` *acknowledges* the request — it reports a pending
    /// cancelation exactly once and returns void ever after — so the answer
    /// is banked here and never asked for a second time. True means "this
    /// wait ended because the connection was canceled".
    fn checkCanceled(t: *TimeoutReader) bool {
        t.io.checkCancel() catch {
            t.canceled = true;
            return true;
        };
        return false;
    }

    /// A read that reached the socket and failed: recover the real cause
    /// from the concrete reader before it is flattened into an anonymous
    /// `ReadFailed`. Only one distinction is load-bearing here — a canceled
    /// wait must not be filed as a dead or stalled peer.
    fn readFailure(t: *TimeoutReader) Reader.Error {
        if (t.src.err) |err| {
            if (err == error.Canceled) t.canceled = true;
        }
        return error.ReadFailed;
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const t: *TimeoutReader = @alignCast(@fieldParentPtr("reader", r));
        const in = &t.src.interface;
        if (have_poll_timeouts and in.bufferedLen() == 0 and
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
            // Both ways out of the wait have to ask, and neither can be
            // skipped: a `poll` that failed outright swallowed the
            // cancelation's signal exactly as one that ran to term did.
            const ready = std.posix.poll(&fds, timeout) catch {
                _ = t.checkCanceled();
                return error.ReadFailed;
            };
            if (ready == 0) {
                if (t.checkCanceled()) return error.ReadFailed;
                t.timed_out = true;
                return error.ReadFailed;
            }
        }
        return in.stream(w, limit) catch |err| switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.WriteFailed => error.WriteFailed,
            error.ReadFailed => t.readFailure(),
        };
    }
};

/// Wraps the connection writer: polls the socket for writability (bounded
/// by `write_timeout_ms`) before every socket write, so a peer that stops
/// reading while a response streams (slow-read attack) becomes
/// `error.WriteFailed` with `timed_out` set instead of pinning the
/// connection task. Caveat (mirror of the read side): a peer that drains a
/// trickle restarts the window per write — only full stalls are bounded.
///
/// `canceled` is the writer half of `TimeoutReader.canceled`, there for the
/// same two reasons: `Writer.Error` is exactly `{WriteFailed}` and cannot
/// carry a cancelation, and the writability `poll` below is no more a
/// `std.Io` cancelation point than the readability one is.
///
/// Not movable after `writer` has been handed out.
const TimeoutWriter = struct {
    io: std.Io,
    /// The socket writer itself — `err` is the writer-side equivalent of
    /// `net.Stream.Reader.err`.
    dst: *net.Stream.Writer,
    handle: net.Socket.Handle,
    timeout_ms: u32,
    writer: Writer,
    timed_out: bool = false,
    canceled: bool = false,

    fn init(dst: *net.Stream.Writer, io: std.Io, timeout_ms: u32, buffer: []u8) TimeoutWriter {
        return .{
            .io = io,
            .dst = dst,
            .handle = dst.stream.socket.handle,
            .timeout_ms = timeout_ms,
            .writer = .{
                .vtable = &.{ .drain = drainFn },
                .buffer = buffer,
            },
        };
    }

    /// See `TimeoutReader.checkCanceled` — the acknowledgement is one-shot,
    /// so it is banked, not re-asked.
    fn checkCanceled(t: *TimeoutWriter) bool {
        t.io.checkCancel() catch {
            t.canceled = true;
            return true;
        };
        return false;
    }

    /// The writer side of `TimeoutReader.readFailure`.
    fn writeFailure(t: *TimeoutWriter) Writer.Error {
        if (t.dst.err) |err| {
            if (err == error.Canceled) t.canceled = true;
        }
        return error.WriteFailed;
    }

    fn pollOut(t: *TimeoutWriter) Writer.Error!void {
        if (!have_poll_timeouts or t.timeout_ms == 0) return;
        var fds = [_]std.posix.pollfd{.{
            .fd = t.handle,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const timeout: i32 = std.math.cast(i32, t.timeout_ms) orelse std.math.maxInt(i32);
        const ready = std.posix.poll(&fds, timeout) catch {
            _ = t.checkCanceled();
            return error.WriteFailed;
        };
        if (ready == 0) {
            if (t.checkCanceled()) return error.WriteFailed;
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
            // Spelled out rather than caught bare: if `Writer.Error` ever
            // grows a second tag, this becomes a compile error instead of a
            // silent mis-map.
            const n = t.dst.interface.write(rem) catch |err| switch (err) {
                error.WriteFailed => return t.writeFailure(),
            };
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
    /// Lend this connection its working memory one request at a time instead
    /// of taking the caller's for the whole connection. Null keeps the
    /// buffers passed to `serveStream`, which is what every caller did before
    /// this existed. See `BuffersProvider`.
    buffers_provider: ?BuffersProvider = null,
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
///
/// Cancelation is the caller's to recover here, unlike on the socket path.
/// A `std.Io` cancelation of a blocking read on `in` arrives as plain
/// `error.ReadFailed` — `std.Io.Reader.Error` is only
/// `{ReadFailed, EndOfStream}` and has nowhere to put `Canceled` — and this
/// function owns no fd, so it has no concrete reader to ask. The real cause
/// survives in the out-of-band `err` field of the reader/writer the caller
/// built (`std.Io.net.Stream.Reader.err`, `std.Io.File.Reader.err`); a
/// caller that must tell a canceled connection from a dead peer inspects
/// that field. `connMain`'s own wrappers do exactly this on the socket it
/// owns — see `TimeoutReader`.
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

        // ⭐⭐⭐ Wait for the next request BEFORE borrowing anything.
        //
        // The wait is the whole point. A keep-alive connection spends most of
        // its life here, and if the borrow window covers the wait then a
        // borrowed set is held exactly as long as a per-connection one and
        // the mechanism buys nothing -- it costs, because now there is an
        // allocator in the path too. The first version of this did that: the
        // acquire sat above `serveOne`, whose first act is this same wait,
        // and a pool measured under 1024 connections at one request a second
        // grew to 896 slabs with an idle list that was empty every time it
        // was asked. Per-connection memory went UP by 4 KiB.
        //
        // Any failure here -- client hung up between requests, idle timeout
        // -- is a quiet close, as it was when `serveOne` owned this line.
        _ = in.peekByte() catch break;

        if (serveStep(opts, in, out, bufs, req_index) == .close) break;
        req_index += 1;
        fireConnState(&opts, .idle);
    }
    fireConnState(&opts, .closed);
}

/// Serve exactly one request that is already known to be arriving -- the
/// borrow-serve-release slice of `serveLoop`, without the wait and without
/// the loop.
///
/// This exists for callers whose *frame layout* is the resource: the serving
/// loop's frame is tens of kilobytes (the per-request state below lives in
/// it), and a caller that parks INSIDE `serveStream`'s wait keeps that whole
/// frame on its stack for as long as the connection idles. A
/// fiber-per-connection engine that instead does the wait itself, in its own
/// small frame, and calls this only when bytes are there, holds the big
/// frame only while a request is actually in flight:
///
/// ```zig
/// var req_index: u32 = 0;
/// while (true) {
///     _ = reader.peekByte() catch break;       // park HERE, shallow
///     if (http.Server.serveStep(opts, reader, writer, bufs, req_index) == .close) break;
///     req_index += 1;
/// }
/// ```
///
/// Semantics match one turn of `serveStream`'s loop exactly, including the
/// `buffers_provider` borrow bracketing the request and the
/// `max_requests_per_conn` cap (derived from `req_index`, which the caller
/// increments per served request). What the caller owns instead: the wait
/// for the first byte, and the connection-lifecycle `ConnState` hooks other
/// than `.active` (`.new`/`.idle`/`.closed` fire only in `serveStream`,
/// which owns the connection's life).
pub fn serveStep(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers, req_index: u32) ConnDisposition {
    // Per-connection request cap: when this request reaches the limit its
    // response is forced to `Connection: close` and the connection ends.
    const cap = opts.max_requests_per_conn;
    const force_close = cap != 0 and req_index + 1 >= cap;

    // Borrowed for this request and given back after it. The pair brackets
    // exactly the time a request is being served.
    var lent: ?StreamBuffers = null;
    const use = if (opts.buffers_provider) |p| blk: {
        lent = p.acquire(p.ctx);
        break :blk lent orelse {
            // Nothing to lend: this is backpressure, and it is answered
            // rather than dropped. A connection closed without a word
            // looks like a crash from the other end.
            _ = respondError(opts, out, null, 503);
            return .close;
        };
    } else bufs;
    defer if (opts.buffers_provider) |p| {
        if (lent) |l| p.release(p.ctx, l);
    };

    return serveOne(opts, in, out, use, req_index, force_close);
}

pub const ConnDisposition = enum { keep_alive, close };

/// How much stack one in-flight request costs, measured rather than reasoned
/// about.
///
/// ⭐⭐⭐ WHY THIS EXISTS. Measured against a live server (256 TLS connections
/// at saturation, io_uring, ReleaseFast): 36 KiB of every connection's stack
/// was resident, and every resident page of it lay between the codec's entry
/// and the handler's frame. Nothing else on that stack mattered -- the two
/// 16 KiB TLS record buffers a connection also holds had ZERO resident pages,
/// and nothing was left dead below the frame. On a server that gives every
/// connection its own stack, this frame IS the per-connection memory, and it
/// had no test.
///
/// ⚠ Two things make it unmeasurable if either is missed:
///
///   * ReleaseFast merges every inlined callee into ONE allocation taken in
///     the entry prologue, so two probes INSIDE the codec are ~200 B apart
///     however large that allocation is. The probe has to straddle a real
///     call boundary -- the caller's frame against the handler's.
///   * A `var` function pointer nothing ever stores to is proved constant and
///     inlined through, which collapses that boundary again. The harness loads
///     it through a `volatile` pointer, the way a server reaching the codec
///     through a vtable does by construction.
const frame_probe = struct {
    var caller: usize = 0;
    var measured: usize = 0;

    noinline fn here() usize {
        var x: usize = undefined;
        return @intFromPtr(&x);
    }

    fn markCaller() void {
        caller = here();
        measured = 0;
    }

    /// Called from the serving frame, just before the handler runs: the
    /// deepest point the codec reaches on its own.
    noinline fn record() void {
        if (caller == 0 or measured != 0) return;
        measured = caller -% here();
    }
};

fn serveOne(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers, req_index: u32, force_close: bool) ConnDisposition {
    // The wait for this request already happened in `serveLoop`, above the
    // point where working memory is borrowed. See the comment there.

    var date_buf: [http_date_len]u8 = undefined;
    const date: ?[]const u8 = if (opts.now) |n| httpDateInto(n, &date_buf) else null;

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

    // The request-target, reduced to what routing needs. Origin-form
    // ("/path?query") is what every client sends to an origin; asterisk-form
    // ("*") belongs to OPTIONS alone (RFC 9112 §3.2.4); absolute-form
    // ("http://host/path") is what a client sends to a proxy -- and a server
    // MUST accept it anyway (§3.2.2), using the authority in the target and
    // ignoring Host (§3.3). It used to be refused here as "a proxy concern";
    // a MUST is not a concern to weigh.
    var target: []const u8 = head.target;
    var query_of_empty_path: []const u8 = "";
    if (target[0] != '/' and !std.mem.eql(u8, target, "*")) {
        const scheme_end = std.mem.indexOf(u8, target, "://") orelse return respondError(opts, out, date, 400);
        const scheme = target[0..scheme_end];
        if (!std.ascii.eqlIgnoreCase(scheme, "http") and !std.ascii.eqlIgnoreCase(scheme, "https"))
            return respondError(opts, out, date, 400);
        const rest = target[scheme_end + 3 ..];
        // The authority ends at the first '/' or '?'; a target with neither
        // ("http://host") names an empty path, which is "/" (§3.2.2).
        const end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
        if (end == 0 or !h1.isValidHost(rest[0..end])) return respondError(opts, out, date, 400);
        target = if (end == rest.len) "/" else if (rest[end] == '?') "/" else rest[end..];
        if (end != rest.len and rest[end] == '?') {
            // "http://host?q": an empty path with a query.
            query_of_empty_path = rest[end + 1 ..];
        }
    }
    if (std.mem.eql(u8, target, "*") and method != .options) return respondError(opts, out, date, 400);
    var path: []const u8 = target;
    var query: []const u8 = query_of_empty_path;
    if (std.mem.indexOfScalar(u8, target, '?')) |i| {
        path = target[0..i];
        query = target[i + 1 ..];
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
        // ⭐⭐ The copy exists so that normalization -- which rewrites in
        // place -- cannot touch the raw target. Where there is nothing to
        // normalize there is nothing to protect: every branch of
        // `removeDotSegments` that moves a byte needs a "/." to fire, and a
        // path without one comes back byte for byte at the same length. So
        // the copy is skipped, and `path` keeps pointing into the head buffer
        // it already pointed into.
        //
        // ⭐ Not a micro-optimization. `norm_buf` is 8 KiB of the serving
        // frame, and on a server that gives every connection its own stack
        // that frame IS the per-connection memory (see `frame_probe`): the
        // `@memcpy` makes its pages resident for every connection on the box,
        // and a static-asset path like `/app.js` -- a dot, but not a dot
        // SEGMENT -- was paying it. `/foo/./bar` and `/foo/../bar` still take
        // the copy, which is the only case that ever needed it.
        if (std.mem.indexOf(u8, path, "/.") != null) {
            @memcpy(norm_buf[0..path.len], path);
            path = norm_buf[0..http.removeDotSegments(norm_buf[0..path.len])];
        }
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
    // RFC 9110 §10.1.1: an HTTP/1.0 client never sent the expectation on
    // purpose -- 1.0 has no 1xx -- and a 100 it does not understand is read
    // as the response.
    if (head.expect_continue and has_body and !head.http1_0) {
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

    // Compiled out entirely outside the test build; see `frame_probe`.
    if (builtin.is_test) frame_probe.record();
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
        // `sent_head` was checked above, so this cannot fail; handled rather
        // than asserted so the guard survives ReleaseFast.
        rw.reset() catch return .close;
        rw.setStatus(500);
        rw.setHeader("Content-Type", "text/plain") catch return .close;
        rw.writeAll("Internal Server Error\n") catch return .close;
    };
    // A detached response stays OPEN: no `end`, no chunked terminator, no
    // keep-alive — the loop stops (`.close`) and the embedder that knows
    // about the detach keeps writing the body (an SSE pump, say) before it
    // closes the socket. An embedder that does not know simply closes, which
    // is the h1 behavior `ResponseWriter.detach` documents.
    if (rw.detached) {
        rw.flush() catch return .close;
        return .close;
    }
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
    /// Trailer-source override: when set, `trailer`/`iterateTrailers`/
    /// `trailers` read this raw CRLF field block instead of the chunked
    /// body's captured one. The h2 path uses it — there is no chunked
    /// framing there, the trailer section is a HEADERS frame, so the
    /// decoded fields are re-serialized into a block and pointed at here.
    /// That keeps ONE trailer surface for handlers across both protocols.
    trailer_block: ?[]const u8 = null,
    /// `Options.context` passthrough for stateful handlers.
    context: ?*anyopaque,
    /// Socket peer address — see `peerAddress`.
    peer: ?net.IpAddress = null,
    /// 0-based request ordinal on this connection — see `connRequestIndex`.
    conn_request_index: u32 = 0,
    /// HTTP/2 only: the request's stream id, so a handler that detaches its
    /// response (`ResponseWriter.detach`) can name the stream to
    /// `h2_server.Detached.push` later. Null on HTTP/1.1.
    stream_id: ?u32 = null,

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
    ///
    /// On HTTP/2 the same three functions surface the request's trailer
    /// HEADERS frame (RFC 9113 §8.1) via `trailer_block`, with the same
    /// "drain the body first" rule — so a handler reads trailers one way on
    /// both protocols. h2 field names are lowercase on the wire; the
    /// lookups are case-insensitive, so that difference does not leak.
    pub fn trailer(req: *const Request, name: []const u8) ?[]const u8 {
        return h1.blockHeader(req.trailers(), name);
    }

    /// Iterate captured incoming chunked trailers in wire order (see
    /// `trailer`).
    pub fn iterateTrailers(req: *const Request) h1.HeaderIterator {
        return h1.blockIterator(req.trailers());
    }

    /// The raw captured incoming chunked trailer block (see `trailer`).
    pub fn trailers(req: *const Request) []const u8 {
        return req.trailer_block orelse req.body.trailerBlock();
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
    /// A body whose framing lives **outside** this union, handed over as a
    /// ready-made reader. HTTP/2 uses it: DATA frames are not an h1 framing
    /// at all, so the h2 serve loop decodes them itself and passes the
    /// handler-facing stream in here (`h2_server`'s incremental request
    /// surface). The trailer section travels via `Request.trailer_block`,
    /// which is why `trailerBlock` is empty for this variant.
    external: *Reader,

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
            .external => |r| r,
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
            .none, .limited, .external => "",
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

/// Response **trailer** fields a handler may declare and emit
/// (`ResponseWriter.declareTrailers` / `setTrailer`). Small on purpose: a
/// trailer section is for a handful of computed-at-the-end facts (checksum,
/// row count, server timing), not a second header table.
pub const max_response_trailers = 8;

/// Stable storage for the generated `Trailer` header value ("A, B, C").
const trailer_decl_bytes = 256;

/// Backing store for COPIED response header and trailer bytes — see
/// `ResponseWriter.header_buf`. Sized so that a full table of 32 headers plus 8
/// trailers has ~100 bytes each with room to spare for the handful of headers
/// that are legitimately long (a `Content-Security-Policy` runs to a kilobyte,
/// a `Set-Cookie` with attributes to a few hundred bytes).
///
/// **Public because it is a cross-module contract, not an internal buffer
/// size.** `cookies.max_set_cookie_bytes` is bounded by it — that coupling
/// used to be a duplicated literal held together by a comment in each file,
/// which no mutation can test; `cookies` now imports this and asserts the
/// relation at comptime. It also decides, since `proxy.relayFailed`, whether
/// a proxied backend response relays or answers 502.
///
/// Pinned BY VALUE below (`test "header_copy_bytes …"`). The bounds test
/// spends `header_copy_bytes / 4`, which follows this number wherever it
/// goes and therefore cannot see it move: halving this to 2048 was measured
/// to leave the whole http + cookies suite green, 451/451, exit 0.
pub const header_copy_bytes = 4096;

/// Response builder + body writer for one request. Buffers the body up to
/// its buffer's capacity: a handler that finishes within it gets an exact
/// automatic `Content-Length`; larger bodies switch to chunked streaming
/// transparently (Go net/http behavior). Works against any `*Writer` — no
/// socket required.
///
/// Managed headers: `Content-Length` (when set, selects identity framing
/// and the written byte count is enforced), `Connection` (only "close" is
/// honored), `Transfer-Encoding` (ignored — framing is the writer's job);
/// `Date` and `Server` are added automatically unless set. Header and trailer
/// name/value bytes are COPIED into the writer, so a handler may build them in
/// a stack buffer that dies when it returns — see `header_buf` for why that is
/// a correctness requirement rather than a convenience. HEAD/204/304 responses
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
/// Response trailers (RFC 9112 §7.1.2 / RFC 9113 §8.1): `declareTrailers`
/// before the head goes out, `setTrailer` any time before `end` — see those
/// two functions for the rules and the security policy. Declaring trailers
/// **commits the response to chunked framing**, so `Trailer` and
/// `Content-Length` can never appear on the same response.
///
/// Not movable once `writer` has been handed out — nor once trailers are
/// declared: the emitted `Trailer` header value points into
/// `trailer_decl_buf`, i.e. into the writer itself.
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
    /// Trailer field names advertised in the `Trailer` header, as slices
    /// into `trailer_decl_buf`. Non-empty ⇒ the response is committed to
    /// chunked framing (a trailer section has nowhere else to live).
    declared_trailers: [max_response_trailers][]const u8 = undefined,
    declared_trailers_len: usize = 0,
    /// Stable backing store for the `Trailer` header value; the header
    /// table entry and every `declared_trailers` slice point into it.
    trailer_decl_buf: [trailer_decl_bytes]u8 = undefined,
    trailer_decl_len: usize = 0,
    /// Trailer fields to emit after the body (`setTrailer`); like `headers`,
    /// the name/value bytes live in `header_buf`.
    trailers: [max_response_trailers]http.Header = undefined,
    trailers_len: usize = 0,
    /// Stable backing store for every header and trailer name/value byte.
    ///
    /// WHY THIS EXISTS. `headers` and `trailers` used to hold the CALLER's
    /// slices. That is only sound if those slices outlive the response, and no
    /// realistic handler can promise it: `writeHead` runs inside `end()`, and
    /// both servers call `end()` AFTER the handler returns (`Server.zig`'s h1
    /// loop and `h2_server.zig`'s `serveJob`). A handler that formats a value
    /// into a stack buffer — the obvious way to write one — therefore had its
    /// bytes read after its frame was gone. It was documented ("slices must
    /// outlive the response") and still wrong in practice: two unrelated
    /// modules, `tracecontext` and `idempotency`, had already been pushed into
    /// `threadlocal var` buffers to satisfy it, which is the shape a contract
    /// takes when it cannot be met honestly.
    ///
    /// It hid because it is undefined behaviour, not a check: Debug and
    /// ReleaseFast happened to still find the original bytes in the dead frame
    /// and passed. Only ReleaseSafe reused the stack soon enough to expose it,
    /// which is why twelve green full-gate runs never saw it.
    ///
    /// A bump allocator, not a heap: replacing a header by name appends new
    /// bytes and abandons the old ones rather than compacting, so a handler
    /// that rewrites the same header in a loop spends budget each time. With
    /// `header_copy_bytes` against 32 headers that is deliberate — the code is
    /// simpler and the slices already handed out stay valid, which compaction
    /// would break.
    header_buf: [header_copy_bytes]u8 = undefined,
    header_buf_len: usize = 0,
    sent_head: bool = false,
    ended: bool = false,
    failed: bool = false,
    /// See `detach`. Only the single-task h2 serve loop reads it.
    detached: bool = false,
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

    pub const SetHeaderError = error{ HeadersSent, TooManyHeaders, InvalidHeader, HeaderBytesExhausted };

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
            // Content-Length and a trailer section are mutually exclusive:
            // trailers exist only in chunked framing (RFC 9112 §7.1.2), so
            // a response that already advertised `Trailer` cannot take one.
            // Rejecting here closes the other half of the ordering — the
            // Content-Length-first order is caught by `declareTrailer`.
            if (rw.declared_trailers_len != 0) return error.InvalidHeader;
            rw.declared_len = std.fmt.parseInt(u64, value, 10) catch return error.InvalidHeader;
            return;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return; // managed
        if (std.ascii.eqlIgnoreCase(name, "trailer")) {
            // One mutation path for the advert: a hand-written `Trailer`
            // header is parsed as the RFC 9110 §6.6.2 field-name list and
            // pushed through `declareTrailer`, so the advertised set and
            // the set `setTrailer` will accept can never disagree — and a
            // forbidden name cannot be smuggled in by writing the header
            // directly instead of calling `declareTrailers`. The precise
            // reasons (`ForbiddenTrailer`, `TrailersUnsupported`, …) are
            // flattened into this function's narrower error set; call
            // `declareTrailers` to see them.
            //
            // All-or-nothing: `Trailer: X-Ok, Content-Length` must declare
            // NOTHING, not quietly keep `X-Ok`. A partially applied advert
            // would put field names on the wire the handler never asked
            // for, and would widen the `setTrailer` allow-list as a side
            // effect of a call that reported failure.
            const saved_names = rw.declared_trailers_len;
            const saved_bytes = rw.trailer_decl_len;
            const saved_headers = rw.headers_len;
            var it = std.mem.splitScalar(u8, value, ',');
            while (it.next()) |raw| {
                const tok = std.mem.trim(u8, raw, " \t");
                if (tok.len == 0) continue;
                rw.declareTrailer(tok) catch |err| {
                    rw.declared_trailers_len = saved_names;
                    rw.trailer_decl_len = saved_bytes;
                    if (saved_names == 0) {
                        // The advert entry was appended by the first
                        // `declareTrailer` above and nothing else has
                        // touched the table since — drop it again.
                        rw.headers_len = saved_headers;
                    } else {
                        rw.putHeader("Trailer", rw.trailer_decl_buf[0..saved_bytes]) catch {};
                    }
                    return switch (err) {
                        error.HeadersSent => error.HeadersSent,
                        error.TooManyTrailers => error.TooManyHeaders,
                        else => error.InvalidHeader,
                    };
                };
            }
            return;
        }
        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (h1.tokenListContains(value, "close")) rw.close_connection = true;
            return;
        }
        return rw.putHeader(name, value);
    }

    /// Raw header-table insert (replace by name, else append) — the single
    /// place the table grows, bypassing the managed-header interception in
    /// `setHeader` (which is how `declareTrailer` maintains its `Trailer`
    /// entry without recursing).
    fn putHeader(rw: *ResponseWriter, name: []const u8, value: []const u8) PutHeaderError!void {
        // Copy BEFORE touching the table: a `HeaderBytesExhausted` must leave
        // the response exactly as it was, not with a half-replaced entry whose
        // name is new and whose value is stale.
        const replacing = for (rw.headers[0..rw.headers_len]) |*hd| {
            if (std.ascii.eqlIgnoreCase(hd.name, name)) break hd;
        } else null;
        if (replacing == null and rw.headers_len == max_response_headers) return error.TooManyHeaders;

        // Rewind the copy store if the pair does not fit as a WHOLE. `dupe`
        // is a bump allocator, so without this the name of a rejected header
        // stays spent forever: a handler that retries with a shorter value
        // has strictly less room than before it asked, and since
        // `proxy.relayFailed` the same budget decides relay-versus-502.
        const mark = rw.header_buf_len;
        errdefer rw.header_buf_len = mark;
        const n = try rw.dupe(name);
        const v = try rw.dupe(value);
        if (replacing) |hd| {
            hd.* = .{ .name = n, .value = v };
            return;
        }
        rw.headers[rw.headers_len] = .{ .name = n, .value = v };
        rw.headers_len += 1;
    }

    const PutHeaderError = error{ TooManyHeaders, HeaderBytesExhausted };

    /// Copy `bytes` into `header_buf` and return a slice of the copy, stable
    /// for the life of the response. The one place header/trailer bytes enter
    /// the writer.
    fn dupe(rw: *ResponseWriter, bytes: []const u8) error{HeaderBytesExhausted}!([]const u8) {
        if (bytes.len > rw.header_buf.len - rw.header_buf_len) return error.HeaderBytesExhausted;
        const at = rw.header_buf_len;
        @memcpy(rw.header_buf[at..][0..bytes.len], bytes);
        rw.header_buf_len += bytes.len;
        return rw.header_buf[at..][0..bytes.len];
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
        // The name is a literal and needs no copy; the value is the caller's
        // and gets the same stable storage every other header value gets.
        rw.headers[rw.headers_len] = .{ .name = "Set-Cookie", .value = try rw.dupe(value) };
        rw.headers_len += 1;
    }

    pub const TrailerError = error{
        /// The head is already on the wire, so the `Trailer` advert can no
        /// longer be added (`declareTrailers` only).
        HeadersSent,
        /// Not a valid field name (RFC 9110 token), or the value carries
        /// CR/LF/NUL.
        InvalidHeader,
        /// The field is never legal in a trailer section — see
        /// `forbiddenTrailerName` for the list and the reasoning.
        ForbiddenTrailer,
        /// `setTrailer` for a name that no `Trailer` header advertised.
        TrailerNotDeclared,
        /// The response's copied-header storage is full — see
        /// `ResponseWriter.header_buf`. Distinct from `TooManyTrailers`,
        /// which is about the field COUNT: this is about total bytes.
        HeaderBytesExhausted,
        /// This response cannot carry a trailer section at all — see
        /// `trailersSupported`.
        TrailersUnsupported,
        /// More than `max_response_trailers` fields, or the advertised
        /// names outgrew `trailer_decl_bytes`.
        TooManyTrailers,
    };

    /// Whether a trailer section is possible on this response at all.
    /// False when the peer is HTTP/1.0 (no chunked transfer coding exists
    /// there, so there is no place to put trailers — and an HTTP/1.0
    /// response has no h2 equivalent either), when the response carries no
    /// body (HEAD / 1xx / 204 / 304 — no body means no trailer section),
    /// or when the handler declared a `Content-Length` (identity framing
    /// ends at the last body byte).
    ///
    /// Handlers that must serve HTTP/1.0 clients too should branch on this
    /// instead of eating `error.TrailersUnsupported`.
    pub fn trailersSupported(rw: *const ResponseWriter) bool {
        return !rw.http1_0 and !rw.noBody() and rw.declared_len == null;
    }

    /// Advertise the trailer fields this response will end with (the
    /// `Trailer` header, RFC 9110 §6.6.2) — repeatable and idempotent;
    /// each accepted name is appended to the emitted header value.
    ///
    /// Two things happen here, and both matter:
    ///
    ///  1. **It is the allow-list.** `setTrailer` refuses any name that was
    ///     not declared first (`error.TrailerNotDeclared`). See the policy
    ///     note on `setTrailer`.
    ///  2. **It commits the response to chunked framing.** Once anything is
    ///     declared, `setHeader("Content-Length", …)` is refused and `end`
    ///     emits a chunked body even for a payload that fit the buffer,
    ///     because a `Content-Length` response has nowhere to put a trailer
    ///     section. So `Trailer` and `Content-Length` can never both reach
    ///     the wire.
    ///
    /// Must be called before the head goes out (the advert rides in the
    /// head): before the first `flush`, and before the body outgrows the
    /// response buffer.
    ///
    /// The names are **copied** into the writer (unlike `setHeader`
    /// values), so a computed name does not need caller-stable memory.
    pub fn declareTrailers(rw: *ResponseWriter, names: []const []const u8) TrailerError!void {
        for (names) |n| try rw.declareTrailer(n);
    }

    /// `declareTrailers` for a single name.
    pub fn declareTrailer(rw: *ResponseWriter, name: []const u8) TrailerError!void {
        if (rw.sent_head) return error.HeadersSent;
        // Deny-list before the token check: a `:status` pseudo-header must
        // report as forbidden, not merely as a malformed name, so the
        // predicate keeps its meaning independent of the name validator.
        if (forbiddenTrailerName(name)) return error.ForbiddenTrailer;
        if (!validHeaderName(name)) return error.InvalidHeader;
        if (!rw.trailersSupported()) return error.TrailersUnsupported;
        if (rw.declaredTrailer(name)) return; // idempotent
        if (rw.declared_trailers_len == max_response_trailers) return error.TooManyTrailers;
        const sep: usize = if (rw.trailer_decl_len == 0) 0 else 2;
        if (rw.trailer_decl_len + sep + name.len > rw.trailer_decl_buf.len)
            return error.TooManyTrailers;
        // From here on the writer is mutated before the advert is
        // re-registered, and that re-registration (`putHeader` below) can
        // still fail on the copy-store budget. Rewind both counters on that
        // path — `setHeader`'s `Trailer` branch already does exactly this
        // (`:1730-1739`) and the two must not disagree about what a refused
        // declaration costs.
        //
        // The cost of not rewinding is not counter hygiene. `declared_trailers`
        // IS `setTrailer`'s allow-list, so a refused name stays emittable; the
        // caller's retry short-circuits as "already declared" (`:1903`) and
        // never re-advertises it; and the field then reaches the wire with no
        // `Trailer` header naming it (RFC 9110 §6.6.2) — after a call that
        // reported failure. `trailer_decl_len` is the second half: the refused
        // name stays in the generated advert text, so it reappears in, and
        // inflates the budget cost of, every later declaration.
        //
        // The header table needs no rewind: `putHeader` appends or replaces
        // only after both copies succeed, so a failure leaves either no
        // `Trailer` entry (first declaration) or the previous one (later
        // declaration) — in both cases the entry these counters now describe.
        const decl_mark = rw.trailer_decl_len;
        const names_mark = rw.declared_trailers_len;
        errdefer {
            rw.trailer_decl_len = decl_mark;
            rw.declared_trailers_len = names_mark;
        }
        if (sep != 0) {
            @memcpy(rw.trailer_decl_buf[rw.trailer_decl_len..][0..2], ", ");
            rw.trailer_decl_len += sep;
        }
        const at = rw.trailer_decl_len;
        @memcpy(rw.trailer_decl_buf[at..][0..name.len], name);
        rw.trailer_decl_len += name.len;
        rw.declared_trailers[rw.declared_trailers_len] = rw.trailer_decl_buf[at..][0..name.len];
        rw.declared_trailers_len += 1;
        // Re-register the advert every time: the value slice just grew, so
        // the header table's entry has to be replaced, not appended to.
        // Report what actually happened: `TrailerError` carries a distinct
        // `HeaderBytesExhausted` precisely so a byte-budget failure can be
        // told apart from a count-limit one, and flattening both into
        // `TooManyTrailers` tells a caller it declared too many trailers when
        // it declared too many BYTES. `setTrailer` already keeps them apart.
        rw.putHeader("Trailer", rw.trailer_decl_buf[0..rw.trailer_decl_len]) catch |err| switch (err) {
            error.TooManyHeaders => return error.TooManyTrailers,
            error.HeaderBytesExhausted => return error.HeaderBytesExhausted,
        };
    }

    /// Whether `name` was advertised in the `Trailer` header.
    pub fn declaredTrailer(rw: *const ResponseWriter, name: []const u8) bool {
        for (rw.declared_trailers[0..rw.declared_trailers_len]) |d|
            if (std.ascii.eqlIgnoreCase(d, name)) return true;
        return false;
    }

    /// Set a trailer field, replacing an existing one of the same name.
    /// Legal **after** the head and body have gone out — that is the whole
    /// point of a trailer: a value only known once the body is finished
    /// (payload checksum, row count, generation time). Emitted by `end`
    /// after the terminating chunk (h1) or as a final HEADERS frame (h2).
    ///
    /// Name and value bytes are COPIED into the writer, exactly like
    /// `setHeader` — the caller's slices only have to outlive this call.
    /// (They were borrowed until 2026-08-12, which made this the *most*
    /// exposed of the three setters: a trailer is read after the whole body,
    /// so the frame it was formatted in is longest dead by then.)
    ///
    /// ## Which fields are allowed, and why both gates exist
    ///
    /// A trailer is the single most inconsistently-handled part of an HTTP
    /// message: some intermediaries merge trailers into the header set,
    /// some forward them, some drop them, and caches disagree about what a
    /// trailer may modify. That makes a handler-controlled trailer a
    /// request-smuggling and cache-poisoning primitive unless it is
    /// constrained, so this implementation applies **both** available
    /// constraints rather than choosing between them:
    ///
    ///  * **Deny-list** (`forbiddenTrailerName`) — the RFC 9110 §6.5.1 set
    ///    of fields that must never appear in a trailer section: message
    ///    framing, routing, request modifiers, authentication, response
    ///    control data, payload-processing fields, plus h2/h3
    ///    pseudo-headers. Checked FIRST and unconditionally, so it holds
    ///    even for a name that somehow got advertised.
    ///  * **Allow-list** — the field must appear in the response's
    ///    `Trailer` header (`declareTrailers`). Recipients are only
    ///    entitled to act on trailers they were told to expect, and
    ///    forcing the advert means the sender decided the field set up
    ///    front, in the head, rather than at the end of a body whose
    ///    content may be attacker-influenced.
    ///
    /// Neither is sufficient alone. A deny-list alone cannot be exhaustive
    /// — it does not know about fields defined after this code was written,
    /// nor about the application's own routing/auth headers — and it leaves
    /// recipients with no advert. An allow-list alone puts the whole policy
    /// in handler code, so one `declareTrailers(&.{userSuppliedName})` or
    /// one careless `Content-Length` re-export reopens the vector. The
    /// intersection is what is safe to put on the wire.
    pub fn setTrailer(rw: *ResponseWriter, name: []const u8, value: []const u8) TrailerError!void {
        // Deny-list first: a forbidden field must report as forbidden even
        // if it somehow reached the advert, so this check never depends on
        // the declaration bookkeeping being correct — nor on the name
        // validator (`:status` is caught here, not as a bad token).
        if (forbiddenTrailerName(name)) return error.ForbiddenTrailer;
        if (!validHeaderName(name) or !validHeaderValue(value)) return error.InvalidHeader;
        if (!rw.declaredTrailer(name)) return error.TrailerNotDeclared;
        if (!rw.trailersSupported()) return error.TrailersUnsupported;
        const replacing = for (rw.trailers[0..rw.trailers_len]) |*t| {
            if (std.ascii.eqlIgnoreCase(t.name, name)) break t;
        } else null;
        if (replacing == null and rw.trailers_len == max_response_trailers) return error.TooManyTrailers;

        // Trailers are read even later than headers — after the body — so the
        // caller's slices are even less likely to be alive. Same storage, and
        // the same all-or-nothing rewind as `putHeader`.
        const mark = rw.header_buf_len;
        errdefer rw.header_buf_len = mark;
        const n = try rw.dupe(name);
        const v = try rw.dupe(value);
        if (replacing) |t| {
            t.* = .{ .name = n, .value = v };
            return;
        }
        rw.trailers[rw.trailers_len] = .{ .name = n, .value = v };
        rw.trailers_len += 1;
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

    /// Hand the response back to the embedder with its framing left OPEN —
    /// the handler returns, and the response is not ended.
    ///
    /// On h2 (single task): the stream stays open past the handler and the
    /// embedder pushes DATA on it through `h2_server.Detached` (no
    /// END_STREAM until it closes the stream). On h1: the serve loop stops
    /// without writing the chunked terminator and reports `.close`; an
    /// embedder that detached on purpose keeps writing body bytes — framed
    /// as the response was (chunked, unless the handler declared otherwise)
    /// — and then closes the socket, while one that did not simply closes,
    /// so a stray detach degrades to a truncated-looking close rather than
    /// a corrupted next response. The h2 dispatcher path ignores the flag
    /// and finishes normally.
    pub fn detach(rw: *ResponseWriter) void {
        rw.detached = true;
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
        // Trailers with no trailer section to put them in. `declareTrailer`
        // and `setTrailer` reject every framing that cannot carry one, so
        // the only way to get here is to declare trailers and *then* make
        // the response bodiless — `setStatus(204)` / `setStatus(304)`,
        // which returns void and so cannot report it. Fail the response:
        // silently dropping declared trailer fields is exactly the
        // "the client never learns the checksum" bug this API exists to
        // prevent, and `Trailer:` is already in the head by now.
        if (rw.declared_trailers_len != 0 and !rw.trailersSupported()) {
            rw.failed = true;
            return error.WriteFailed;
        }
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
                } else if (rw.declared_trailers_len != 0) {
                    // Declared trailers commit the response to chunked
                    // framing even though the whole body fit the buffer and
                    // an exact Content-Length was available: a
                    // Content-Length response has no trailer section.
                    try rw.writeHead(.chunked);
                    rw.body = .{ .chunked = .init(rw.out, rw.chunk_buf) };
                    try rw.body.chunked.writer.writeAll(body_bytes);
                    try rw.finishChunked(&rw.body.chunked);
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
                try rw.finishChunked(&rw.body.chunked);
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

    pub const ResetError = error{HeadersSent};

    /// Discard everything composed so far and start the response over —
    /// status, header table, copied-header bytes, declared trailers and the
    /// buffered body. Legal only while nothing is on the wire; returns
    /// `error.HeadersSent` otherwise (check `headSent` first to avoid the
    /// error path entirely).
    ///
    /// The serving loop uses it for the automatic 500 on a handler error.
    /// Public because a handler needs the same move for the same reason: one
    /// that composes a response and only then discovers it cannot finish it
    /// — `proxy` relaying a backend's headers until the budget runs out —
    /// otherwise has no way to stop the half-built answer from riding along
    /// with the error status it replaces it with.
    ///
    /// The precondition is a returned error and NOT `std.debug.assert`,
    /// which is the whole point of this signature. `reset` clears `ended`
    /// and sets `body = .buffering` while leaving `sent_head` **true** — it
    /// is the one field `reset` does not touch — so a post-head call makes
    /// the next `end()` take the `.buffering` arm and call `writeHead` a
    /// second time: a second status line and header block on the same
    /// connection, with the first body left unterminated. That is a
    /// response-splitting shape reachable by ordinary API misuse, and an
    /// assert is compiled out in exactly the modes people deploy
    /// (ReleaseFast/ReleaseSmall) — a fail-open guard on a public API.
    /// Measured before this signature: ReleaseFast put two complete heads on
    /// the wire, while `setHeader` still returned `HeadersSent`, so a caller
    /// checking its return values saw nothing wrong.
    pub fn reset(rw: *ResponseWriter) ResetError!void {
        if (rw.sent_head) return error.HeadersSent;
        rw.status = 200;
        rw.headers_len = 0;
        rw.header_buf_len = 0;
        rw.declared_len = null;
        rw.declared_trailers_len = 0;
        rw.trailer_decl_len = 0;
        rw.trailers_len = 0;
        rw.ended = false;
        rw.failed = false;
        rw.content_encoding_gzip = false;
        rw.body = .buffering;
        rw.interface.end = 0;
    }

    /// Terminate a chunked body, appending the trailer section when the
    /// handler set one. Every chunked-termination path goes through here so
    /// there is exactly one place that knows trailers come after the
    /// 0-chunk — the plain streaming body, the buffered-body-forced-chunked
    /// body, and the gzip pipeline.
    fn finishChunked(rw: *ResponseWriter, cw: *h1.ChunkedWriter) Writer.Error!void {
        if (rw.trailers_len == 0) return cw.finish();
        var fields: [max_response_trailers]h1.HeaderEntry = undefined;
        for (rw.trailers[0..rw.trailers_len], 0..) |t, i|
            fields[i] = .{ .name = t.name, .value = t.value };
        return cw.finishWithTrailers(fields[0..rw.trailers_len]);
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
        try rw.finishChunked(&g.chunked);
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

/// Fields that must never appear in a **trailer section** (RFC 9110 §6.5.1,
/// which keeps RFC 7230 §4.1.2's list). The reason a deny-list is needed at
/// all: intermediaries handle trailers inconsistently — some merge them into
/// the header set, some forward them, some drop them — so a field that
/// changes how a message is framed, routed, cached or authorized is a
/// request-smuggling / cache-poisoning primitive when it arrives *after* the
/// recipient has already acted on the head.
///
/// The RFC's categories, in order:
///   * message framing — a `Content-Length`/`Transfer-Encoding` that
///     contradicts the head is the classic desync;
///   * routing — `Host` after the request was already routed;
///   * request modifiers (controls and conditionals) — `Cache-Control` &
///     friends arriving too late to be honored consistently;
///   * authentication — credentials/challenges a proxy may or may not see;
///   * response control data — `Date`/`Location`/`Vary`/`Expires`… , the
///     fields a cache keys and validates on;
///   * payload processing — `Content-Type`/`Content-Encoding`/
///     `Content-Range`, plus `Trailer` itself (no recursion).
///
/// Beyond the RFC list this also rejects connection-specific fields (RFC
/// 9112 §9.1 / RFC 9113 §8.2.2 — they must not cross the h1↔h2 boundary at
/// all), `Cookie`/`Set-Cookie` (state-management fields whose late arrival
/// browsers and proxies treat differently), and anything starting with `:`
/// — an h2/h3 pseudo-header in a trailer block is malformed per RFC 9113
/// §8.1 and would be a direct `:status`/`:path` override primitive. The
/// pseudo-header test is kept even though `validHeaderName` already rejects
/// `:` (not a tchar): this predicate must stand on its own if the name
/// validator is ever relaxed.
///
/// Case-insensitive. Deliberately over-broad — a handler that needs one of
/// these has a design problem, not a missing feature.
pub fn forbiddenTrailerName(name: []const u8) bool {
    if (name.len == 0) return true;
    if (name[0] == ':') return true; // h2/h3 pseudo-header
    const forbidden = [_][]const u8{
        // message framing
        "content-length",
        "transfer-encoding",
        // routing
        "host",
        // request modifiers: controls and conditionals
        "cache-control",
        "expect",
        "max-forwards",
        "pragma",
        "range",
        "te",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
        // authentication / state management
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "proxy-authenticate",
        "cookie",
        "set-cookie",
        // response control data
        "age",
        "date",
        "expires",
        "location",
        "retry-after",
        "vary",
        "warning",
        // payload processing (incl. the advert itself)
        "content-encoding",
        "content-type",
        "content-range",
        "trailer",
        // connection-specific
        "connection",
        "keep-alive",
        "proxy-connection",
        "upgrade",
    };
    for (forbidden) |f| if (std.ascii.eqlIgnoreCase(name, f)) return true;
    return false;
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

/// The last stamp this thread formatted, and the second it is for.
///
/// A server answering the rate this codec is built for serves thousands of
/// responses inside one second, and every one of them carries the same 29
/// bytes. Formatting them separately is the single most expensive thing about
/// the `Date` header: measured in a consumer over TLS/h2, turning `Date` on
/// cost **+6,433 instructions per request**, of which the clock read was ~900
/// and the rest was almost entirely this call. nginx, ntex and hyper all keep
/// a stamp per second for the same reason.
///
/// Per thread rather than per process: it is written on every tick of the
/// clock, and a shared one would be a contended write on the response path to
/// save 29 bytes.
threadlocal var date_cache: [http_date_len]u8 = undefined;
threadlocal var date_cache_second: i64 = std.math.minInt(i64);

/// `formatHttpDate` for a caller that asks once per response, reusing the
/// stamp while the second lasts. The result is written into `buf` and is the
/// caller's, with exactly the lifetime `formatHttpDate` gave it.
///
/// ⭐ **The copy into `buf` is what makes this safe, and it is not a
/// leftover.** Returning `&date_cache` directly would hand out a pointer to
/// storage that the next tick rewrites, and a caller that yields between
/// taking the stamp and writing it — which a fibre-per-connection server does
/// whenever the response head does not fit the socket buffer — could then emit
/// a head half in one second and half in the next. Copying 29 bytes costs a
/// couple of instructions against the thousands this saves, and it cannot be
/// interrupted: nothing between here and the return can yield.
pub fn httpDateInto(now: StreamOptions.Now, buf: *[http_date_len]u8) []const u8 {
    const second = now.epochSeconds(now.ctx);
    if (second != date_cache_second) {
        _ = formatHttpDate(second, &date_cache);
        date_cache_second = second;
    }
    buf.* = date_cache;
    return buf;
}

/// Format epoch seconds as an RFC 9110 IMF-fixdate for Date headers.
///
/// The calendar conversion is `datefmt`'s `unixToParts` -- the branchless
/// civil-from-days core -- and the digits are written by hand rather than
/// through `Writer.print`. Both halves are the point: `std.time.epoch`'s
/// `calculateYearDay` walks **one iteration per year since 1970** (56 of them
/// in 2026, and one more every New Year) and `calculateMonthDay` then walks
/// the months, while `Writer.print` re-parses `{d:0>2}` at run time for each
/// of the six padded fields. Measured over 10M calls, ReleaseFast, `perf stat`:
/// **3,043 instructions before, 141 after -- 21x.**
///
/// That mattered because a server calls this once per response. It is now
/// called once a second (`httpDateInto`), so this is no longer on anyone's hot
/// path here -- but it is a public function, every other caller pays the full
/// price, and the cheap calendar was already in the next module along.
pub fn formatHttpDate(epoch_seconds: i64, buf: *[http_date_len]u8) []const u8 {
    const day_names = "ThuFriSatSunMonTueWed"; // 1970-01-01 was a Thursday
    const month_names = "JanFebMarAprMayJunJulAugSepOctNovDec";

    // Clamped on the way IN, and both ends are load-bearing. The field is four
    // digits wide and a caller may hand over any `i64`: before this the year
    // went out through `{d}`, so a five-digit year made the string longer than
    // the buffer and `catch unreachable` turned it into a panic. The upper
    // bound also keeps `datefmt` in range -- its `DateParts.year` is an `i32`,
    // and an unclamped `maxInt(i64)` of seconds overflows it.
    const max_secs = 253402300799; // 9999-12-31T23:59:59Z
    const secs = std.math.clamp(epoch_seconds, 0, max_secs);
    const p = datefmt.unixToParts(secs);
    const epoch_day = @divFloor(secs, std.time.s_per_day);
    const weekday: usize = @intCast(@mod(epoch_day, 7));
    const year: u32 = @intCast(p.year);

    @memcpy(buf[0..3], day_names[weekday * 3 ..][0..3]);
    buf[3] = ',';
    buf[4] = ' ';
    twoDigits(buf[5..7], p.day);
    buf[7] = ' ';
    @memcpy(buf[8..11], month_names[(p.month - 1) * 3 ..][0..3]);
    buf[11] = ' ';
    twoDigits(buf[12..14], year / 100);
    twoDigits(buf[14..16], year % 100);
    buf[16] = ' ';
    twoDigits(buf[17..19], p.hour);
    buf[19] = ':';
    twoDigits(buf[20..22], p.minute);
    buf[22] = ':';
    twoDigits(buf[23..25], p.second);
    @memcpy(buf[25..29], " GMT");
    return buf;
}

/// One zero-padded two-digit field. `v` is always in range here (0-99 for
/// every field, and the year is clamped to four digits before it is split), so
/// a value beyond it would be a bug in the caller rather than in the input.
fn twoDigits(out: *[2]u8, v: u32) void {
    std.debug.assert(v < 100);
    out[0] = '0' + @as(u8, @intCast(v / 10));
    out[1] = '0' + @as(u8, @intCast(v % 10));
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
    } else if (std.mem.eql(u8, req.path, "/outtrailers")) {
        // Response trailers on a body that FITS the response buffer: the
        // declaration alone must force chunked framing (an exact
        // Content-Length was available and must not be used).
        try rw.setHeader("Content-Type", "text/plain");
        try rw.declareTrailers(&.{ "X-Checksum", "X-Rows" });
        try rw.writeAll("hello");
        try rw.setTrailer("X-Checksum", "deadbeef");
        try rw.setTrailer("X-Rows", "3");
    } else if (std.mem.eql(u8, req.path, "/outtrailers-stream")) {
        // Same, on a body that outgrows the buffer (already chunked) and is
        // flushed mid-handler, i.e. the head is long gone when the trailer
        // value is computed — the case trailers exist for.
        try rw.setHeader("Content-Type", "text/plain");
        try rw.declareTrailer("X-Checksum");
        try rw.writeAll(big_body);
        try rw.flush();
        try rw.setTrailer("X-Checksum", "deadbeef");
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
    /// Matches `runStream`'s historical fixed value; override to null to
    /// prove the `Server` auto-header can be suppressed.
    server_name: ?[]const u8 = "test",
    /// Matches `runStream`'s historical fixed clock; override to null to
    /// prove the `Date` auto-header can be suppressed.
    now: ?StreamOptions.Now = .{ .epochSeconds = fixedEpoch },
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
    serveIndirect(.{
        .handler = testHandler,
        .context = ctx,
        .server_name = tweaks.server_name,
        .now = tweaks.now,
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

/// A real call boundary, for `frame_probe`. See its doc comment for why a
/// direct call cannot measure the frame and why this pointer is loaded
/// through `volatile`.
var serve_indirect: *const fn (StreamOptions, *Reader, *Writer, StreamBuffers) void = &serveStream;

fn serveIndirect(opts: StreamOptions, in: *Reader, out: *Writer, bufs: StreamBuffers) void {
    // ⚠ A plain global pointer is not enough: nothing ever stores to it, so
    // LLVM proves it constant and inlines through it anyway -- the probe then
    // reads 208 B whatever the frame holds. A volatile load cannot be folded.
    const p: *volatile *const fn (StreamOptions, *Reader, *Writer, StreamBuffers) void = &serve_indirect;
    p.*(opts, in, out, bufs);
}

fn runStream(ctx: ?*anyopaque, wire: []const u8, out_buf: []u8) []const u8 {
    frame_probe.markCaller();
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

test "serveStream: server_name = null omits Server, Date stays" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .server_name = null }, null, "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello", got);
}

test "serveStream: now = null omits Date, Server stays" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .now = null }, null, "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello", got);
}

/// The exact head `/hello` produces with both auto-headers suppressed —
/// reused by the live-socket agreement test below to prove `Server.Options`
/// (`server_name = null`, `emit_date = false`) and `StreamOptions`
/// (`server_name = null`, `now = null`) now emit byte-identical wire output
/// for the same request. That agreement — not either suppression alone — is
/// the finding: before `Options` gained these fields, the socket path could
/// not produce this string at all.
/// Head only (no blank-line terminator, no body) — the shape
/// `h1.readHead` returns, for the live-socket comparison.
const both_suppressed_head_only = "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/plain\r\n" ++
    "Connection: close\r\n" ++
    "Content-Length: 5\r\n";
const both_suppressed_head = both_suppressed_head_only ++ "\r\n" ++ "hello";

test "serveStream: server_name = null and now = null omit both auto-headers" {
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(.{ .server_name = null, .now = null }, null, "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings(both_suppressed_head, got);
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
    // Bare LF terminating the request line (RFC 9112 §2.2 permits, but does
    // not require, a recipient to accept a bare LF as a line terminator —
    // this server deliberately declines that leniency for request-smuggling
    // hardening; see h1.zig's `stripCrlf` and `h11_interop.zig`) — answered
    // 400 like any malformed head, and the pipelined request behind it is
    // never served.
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
    // Chunked present but not the sole/final coding is a TE.TE
    // request-smuggling primitive (RFC 9112 §6.1) — reject, don't frame.
    try testing.expect(std.mem.startsWith(u8, runStream(null, "POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    // Absolute-form is accepted, and its authority wins over Host (RFC 9112
    // §3.2.2, §3.3); a scheme this server does not speak, or no authority,
    // is still 400.
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET http://x/hello HTTP/1.1\r\nHost: other\r\n\r\n", &out_buf), "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET ftp://x/hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET http:///hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    // "*" is for OPTIONS alone (§3.2.4).
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET * HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 400 Bad Request\r\n"));
    // A 1.0 client gets no 100 Continue (RFC 9110 §10.1.1).
    try testing.expect(std.mem.indexOf(u8, runStream(null, "POST /echo HTTP/1.0\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi", &out_buf), "100 Continue") == null);
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

/// The handler half of the dead-frame test below: build a header name, a
/// header value, a `Set-Cookie` and a trailer in buffers that die with THIS
/// frame — the obvious way to write a handler — and return.
///
/// A separate `noinline` function, not a block inside the test, and that is
/// the whole point. A block scope does not free anything: Zig gives each
/// local its own slot for the enclosing function's entire body in Debug, so a
/// later local never lands on the "dead" buffer and the borrowed-slice bug
/// stays invisible. Only a returned frame is really reusable.
noinline fn setFromDeadFrame(rw: *ResponseWriter) !void {
    var scratch: [128]u8 = undefined;
    @memset(&scratch, 'v');
    const name = try std.fmt.bufPrint(scratch[0..16], "X-Doomed-{d}", .{7});
    try rw.setHeader(name, scratch[16..64]);

    var cookie_buf: [64]u8 = undefined;
    try rw.addSetCookie(try std.fmt.bufPrint(&cookie_buf, "sid={d}; Path=/", .{4242}));

    var tname_buf: [32]u8 = undefined;
    var tval_buf: [32]u8 = undefined;
    const tname = try std.fmt.bufPrint(&tname_buf, "X-Rows-{d}", .{2});
    try rw.declareTrailers(&.{tname});
    try rw.setTrailer(tname, try std.fmt.bufPrint(&tval_buf, "{d}", .{987654}));
}

/// Reuse the frame `setFromDeadFrame` just left, the way the next call down
/// the stack would have. Bigger than that frame so it covers every slot in
/// it, and `noinline` + `doNotOptimizeAway` so neither the call nor the
/// stores can be optimized out.
noinline fn clobberDeadFrame() void {
    var scratch: [2048]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "ResponseWriter: header, cookie and trailer bytes survive the caller's dead frame" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // The bug this guards: `writeHead` runs inside `end()`, and both servers
    // call `end()` AFTER the handler returns — so a value formatted into the
    // handler's stack frame was read once that frame was gone. Reproduced
    // here with no server at all: `setFromDeadFrame` IS the handler, and the
    // clobber is what the next stack user would have written over it.
    try setFromDeadFrame(&rw);
    clobberDeadFrame();

    try rw.writeAll("body");
    try rw.end();
    const wire = out.buffered();

    // Header name AND value, the cookie, and the trailer — every byte that
    // went through the copy store, read back off the wire after its source
    // was overwritten.
    try testing.expect(std.mem.indexOf(u8, wire, "X-Doomed-7: " ++ "v" ** 48 ++ "\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie: sid=4242; Path=/\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Trailer: X-Rows-2\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "X-Rows-2: 987654\r\n") != null);
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.indexOf(u8, wire, "#") == null);
}

/// Spend the copy store down to exactly `leave` free bytes, in one header, so
/// the arithmetic in the tests below is exact rather than approximate.
fn spendCopyStore(rw: *ResponseWriter, leave: usize) !void {
    var pad: [header_copy_bytes]u8 = undefined;
    @memset(&pad, 'x');
    const name = "X-Pad";
    try rw.setHeader(name, pad[0 .. header_copy_bytes - name.len - leave]);
}

test "ResponseWriter: a REJECTED header returns its name's bytes to the budget" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try spendCopyStore(&rw, 50);

    // `putHeader` dupes the name and THEN the value. This pair does not fit
    // (8 + 60 > 50), so it is refused — but the 8 bytes of name were already
    // committed to a bump allocator that never rewinds, and stayed spent.
    var value: [60]u8 = undefined;
    @memset(&value, 'v');
    try testing.expectError(error.HeaderBytesExhausted, rw.setHeader("X-Reject", &value));

    // The budget must be exactly as it was: a header costing all 50 remaining
    // bytes still fits. Before the rewind only 42 were left and this failed —
    // asking for a header and being refused made the response smaller.
    var v2: [47]u8 = undefined;
    @memset(&v2, 'w');
    try rw.setHeader("X-Y", &v2);
}

test "declareTrailers: byte exhaustion is reported as such, not as TooManyTrailers" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // Five free bytes: far below the count limit (8 trailers), far below the
    // 10 bytes `Trailer: X-T` needs in the copy store. The caller declared
    // ONE trailer, so `TooManyTrailers` would be a lie about which limit it
    // hit — and `TrailerError` carries `HeaderBytesExhausted` to say so.
    try spendCopyStore(&rw, 5);
    try testing.expectError(error.HeaderBytesExhausted, rw.declareTrailers(&.{"X-T"}));
}

test "declareTrailers: a REJECTED declaration does not widen the setTrailer allow-list" {
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // `declareTrailer` advances `trailer_decl_len` and `declared_trailers_len`
    // BEFORE it re-registers the `Trailer` advert through `putHeader`, and that
    // call can fail on the copy-store budget. Without a rewind the counters
    // keep the name the call reported it had refused, and the damage is not
    // counter hygiene: `declaredTrailer` is what `setTrailer` uses as its
    // allow-list, so a trailer the response never advertised becomes emittable.
    // A trailer field sent without a `Trailer` advert is an RFC 9110 §6.6.2
    // violation, produced by a call that told the caller it had failed.
    try spendCopyStore(&rw, 5);
    try testing.expectError(error.HeaderBytesExhausted, rw.declareTrailers(&.{"X-T"}));

    try testing.expect(!rw.declaredTrailer("X-T"));
    try testing.expectError(error.TrailerNotDeclared, rw.setTrailer("X-T", "1"));

    // …and the response is not silently committed to chunked framing by a
    // declaration that failed: `end` picks chunked purely off
    // `declared_trailers_len` (`:2097`), so a stuck counter changes the wire
    // framing of a response with no trailers at all.
    try rw.writeAll("body");
    try rw.end();
    const wire = out.buffered();
    try testing.expect(std.mem.indexOf(u8, wire, "X-T") == null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 4\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Transfer-Encoding: chunked") == null);
}

test "declareTrailers: a REJECTED declaration does not poison the advert of a later one" {
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // The other counter, pinned separately. `trailer_decl_buf` holds the
    // generated advert text and every `declareTrailer` re-registers the WHOLE
    // string, so a name left in it by a failed call reappears in — and inflates
    // the cost of — every later advert.
    //
    // Budget: 40 free. "X-A" costs `Trailer`(7) + `X-A`(3) = 10, leaving 30.
    // The 24-char name then needs 7 + len("X-A, " ++ name) = 36 > 30 and is
    // refused. "X-C" afterwards needs 7 + len("X-A, X-C") = 15 ≤ 30 and must
    // succeed — with the refused name still in the buffer it would need
    // 7 + len("X-A, X-0123456789012345678901, X-C") = 41 and fail too. The
    // remaining 15 bytes cover both `setTrailer` pairs (4 each).
    try spendCopyStore(&rw, 40);
    try rw.declareTrailer("X-A");
    try testing.expectError(
        error.HeaderBytesExhausted,
        rw.declareTrailer("X-0123456789012345678901"),
    );
    try rw.declareTrailer("X-C");

    try rw.setTrailer("X-A", "1");
    try rw.setTrailer("X-C", "3");
    try rw.writeAll("body");
    try rw.end();
    const wire = out.buffered();
    try testing.expect(std.mem.indexOf(u8, wire, "Trailer: X-A, X-C\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "X-01234567890123456") == null);
}

test "header_copy_bytes: pinned by value, in both directions" {
    // The one existing test that spends this budget is written in terms of
    // `header_copy_bytes / 4` — it verifies the MECHANISM (a rejection
    // happens, the table survives it) and is blind to the VALUE. Measured:
    // 4096 → 2048 left http + cookies at 451/451, exit 0. Only 4096 → 16384
    // went red. So the constant was pinned upward by accident and not at all
    // downward, while it decides proxy-502-versus-relay and bounds
    // `cookies.max_set_cookie_bytes`.
    //
    // WHERE 4096 COMES FROM: RFC 6265 §6.1 obliges a user agent to accept at
    // least 4096 bytes per cookie, "as measured by the sum of the length of
    // the cookie's name, value, and attributes" — i.e. the length of a
    // `Set-Cookie` header VALUE. That is the largest single header value the
    // response builder must be able to carry, so the copy store is sized to
    // it. Note it is sized to the value ALONE: emitting a maximal conforming
    // cookie also costs the 10 bytes of the `Set-Cookie` header name, so a
    // 4096-byte cookie does not in fact fit in a 4096-byte store — which is
    // exactly what `cookies`' "an over-long cookie is refused, not truncated"
    // test observes at `max_set_cookie_bytes - 8`. Recorded, not silently
    // rounded up: growing this is a per-response memory decision.
    try testing.expectEqual(@as(usize, 4096), header_copy_bytes);
}

test "ResponseWriter: reset after the head is on the wire is refused, not asserted" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [16]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // Outgrow the body buffer so the writer switches to chunked streaming and
    // puts the head on the wire from INSIDE the handler — the state a
    // consumer reaches by accident, not by hostile input.
    try rw.setHeader("X-First", "1");
    try rw.writeAll("a" ** 26);
    try testing.expect(rw.headSent());

    // The precondition must hold in every optimize mode. When it was
    // `std.debug.assert(!rw.sent_head)` this call was a no-op in ReleaseFast:
    // `reset` cleared `ended` and set `body = .buffering` but left
    // `sent_head` true, so the `end()` below called `writeHead` a SECOND
    // time and put a second complete status line + header block on the same
    // connection, leaving the chunked body above unterminated.
    // Deliberately captured rather than asserted here: the wire is checked
    // FIRST below, so that a regression is reported as the response-splitting
    // defect it is rather than as a missing error code.
    const reset_result = rw.reset();

    try rw.writeAll("bb");
    try rw.end();
    const wire = out.buffered();

    // The response-splitting property, asserted directly: exactly one status
    // line on this connection. This is the assertion that failed in
    // ReleaseFast before the signature change (it counted 2).
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "HTTP/1.1 200 OK\r\n"));
    // And the framing is intact: the chunked body is terminated exactly once.
    try testing.expect(std.mem.endsWith(u8, wire, "0\r\n\r\n"));
    // Only then the contract itself.
    try testing.expectError(error.HeadersSent, reset_result);
}

test "ResponseWriter: the copy store is bounded, and says so instead of truncating" {
    var out_buf: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // Copying bought a byte budget that storing slices did not have. A budget
    // nothing exercises is where a wrong constant hides, so spend it: values
    // just under a quarter of the store, four of which cannot fit alongside
    // their names.
    var big: [header_copy_bytes / 4]u8 = undefined;
    @memset(&big, 'x');
    try rw.setHeader("X-A", &big);
    try rw.setHeader("X-B", &big);
    try rw.setHeader("X-C", &big);
    try testing.expectError(error.HeaderBytesExhausted, rw.setHeader("X-D", &big));

    // Refused cleanly: the table is unchanged and the response still works.
    try testing.expectEqual(@as(usize, 3), rw.headers_len);
    try rw.setHeader("X-Small", "ok");
    try testing.expectEqual(@as(usize, 4), rw.headers_len);
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
    // ⭐ A dot that is not a dot SEGMENT does not make a path need
    // normalizing, and one that is still does even when the other is present.
    // This pins the predicate that decides whether the 8 KiB copy happens at
    // all: "/." appears in the second target and not the first.
    try testing.expect(std.mem.startsWith(u8, runStream(null, "GET /app.js HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf), "HTTP/1.1 404 Not Found\r\n"));
    try testing.expect(std.mem.endsWith(u8, runStream(null, "GET /app.js/../hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf), "\r\n\r\nhello"));
}

test "serveStream: a path past max_normalized_path is 414, one under it serves" {
    // The limit is the buffer the path is normalized in, and that buffer is
    // per-connection memory on any server that gives a connection its own
    // stack -- so the number is worth pinning rather than left to whoever next
    // reads the constant. `max_request_line_bytes` is a different and larger
    // limit; this one is the path half alone.
    //
    // Its own buffers, not `runStream`'s: that harness lends a 1 KiB head
    // buffer, so a 2 KiB path is refused as 431 before the path limit is ever
    // reached -- which is a true answer to a different question.
    const Case = struct {
        fn run(path_len: usize, out_buf: []u8) []const u8 {
            var wire: [max_normalized_path + 512]u8 = undefined;
            var w: Writer = .fixed(&wire);
            w.writeAll("GET /") catch unreachable;
            w.splatByteAll('a', path_len - 1) catch unreachable;
            w.writeAll(" HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n") catch unreachable;

            var in: Reader = .fixed(w.buffered());
            var out: Writer = .fixed(out_buf);
            var head_buf: [max_normalized_path + 512]u8 = undefined;
            var request_body_buf: [256]u8 = undefined;
            var response_body_buf: [64]u8 = undefined;
            var chunk_buf: [128]u8 = undefined;
            serveStream(.{
                .handler = testHandler,
                .server_name = "test",
                .now = .{ .epochSeconds = fixedEpoch },
                .max_request_line_bytes = null,
            }, &in, &out, .{
                .head = &head_buf,
                .request_body = &request_body_buf,
                .response_body = &response_body_buf,
                .chunk = &chunk_buf,
            });
            return out.buffered();
        }
    };
    var out_buf: [4096]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, Case.run(max_normalized_path + 1, &out_buf), "HTTP/1.1 414 "));
    // One inside the limit routes normally -- a 404 here, because the test
    // handler serves /hello and the point is that it ROUTED at all.
    try testing.expect(std.mem.startsWith(u8, Case.run(max_normalized_path, &out_buf), "HTTP/1.1 404 "));
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

// ── tests (offline — response trailer WRITE side) ───────────────────────────

test "serveStream: response trailers land AFTER the terminating chunk (RFC 9112 §7.1.2)" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /outtrailers HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    // Byte golden. Two things it pins that nothing else would:
    //   * `Trailer: X-Checksum, X-Rows` is in the HEAD (RFC 9110 §6.6.2) —
    //     drop the advert and this string vanishes;
    //   * the fields come after `0\r\n`, not before it — swap the order and
    //     the two lines move above the last-chunk line.
    // The body ("hello", 5 bytes) fits the 64-byte response buffer, so the
    // chunked framing here is purely the trailer commitment at work.
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Trailer: X-Checksum, X-Rows\r\n" ++
        "Date: " ++ test_date ++ "\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n" ++
        "0\r\n" ++
        "X-Checksum: deadbeef\r\n" ++
        "X-Rows: 3\r\n" ++
        "\r\n", got);
    // No Content-Length anywhere: declaring trailers commits to chunked.
    try testing.expect(std.mem.indexOf(u8, got, "Content-Length") == null);
}

test "serveStream: trailers on a streamed body arrive after the last chunk" {
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /outtrailers-stream HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(std.mem.indexOf(u8, got, "Trailer: X-Checksum\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\nX-Checksum: deadbeef\r\n\r\n"));
    // The body really did stream (multiple chunks), so the head was on the
    // wire well before `setTrailer` ran.
    try testing.expect(std.mem.count(u8, got, "\r\n") > 8);
}

test "ResponseWriter: our own chunked reader recovers the written trailers" {
    // Writer ↔ reader round trip. On its own this proves little — a shared
    // misreading of the framing survives it, which is why the live-curl
    // tests in curl_interop.zig exist — but it does pin that the emitted
    // block is parseable as a trailer section at all.
    var out_buf: [4096]u8 = undefined;
    const got = runStream(null, "GET /outtrailers HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    var rr: Reader = .fixed(got);
    var head_buf: [1024]u8 = undefined;
    const res = try h1.ResponseHead.parse(try h1.readHead(&rr, &head_buf));
    try testing.expect(res.chunked);
    try testing.expectEqualStrings("X-Checksum, X-Rows", res.header("trailer").?);
    var scratch: [256]u8 = undefined;
    var tbuf: [256]u8 = undefined;
    var cr: h1.ChunkedReader = .initCapturingTrailers(&rr, &scratch, &tbuf);
    var body: [64]u8 = undefined;
    var bw: Writer = .fixed(&body);
    _ = try cr.reader.streamRemaining(&bw);
    try testing.expectEqualStrings("hello", bw.buffered());
    try testing.expectEqualStrings("deadbeef", cr.trailer("x-checksum").?);
    try testing.expectEqualStrings("3", cr.trailer("X-Rows").?);
}

/// A `ResponseWriter` over `out_buf` with the usual small test buffers.
fn trailerWriter(out: *Writer, body_buf: []u8, chunk_buf: []u8, opts: ResponseWriter.InitOptions) ResponseWriter {
    return .init(out, body_buf, chunk_buf, opts);
}

test "ResponseWriter: forbidden trailer fields are rejected, both ways in" {
    var out_buf: [512]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{});

    // RFC 9110 §6.5.1, one per category — the fields that make a trailer a
    // smuggling / cache-poisoning primitive.
    const forbidden = [_][]const u8{
        "Content-Length",   "Transfer-Encoding", "Host",
        "Cache-Control",    "TE",                "Authorization",
        "WWW-Authenticate", "Set-Cookie",        "Date",
        "Location",         "Vary",              "Expires",
        "Content-Type",     "Content-Encoding",  "Content-Range",
        "Trailer",          "Connection",        "Upgrade",
        "Keep-Alive",       "If-None-Match",     "Range",
    };
    for (forbidden) |name| {
        // Gate 1: the advert refuses them…
        try testing.expectError(error.ForbiddenTrailer, rw.declareTrailer(name));
        // …and gate 2 refuses them independently of the advert, so the
        // deny-list never relies on the declaration bookkeeping.
        try testing.expectError(error.ForbiddenTrailer, rw.setTrailer(name, "x"));
    }
    // h2/h3 pseudo-headers: a `:status` trailer would be a direct response
    // override. Rejected as forbidden even before the token check.
    try testing.expectError(error.ForbiddenTrailer, rw.declareTrailer(":status"));
    try testing.expectError(error.ForbiddenTrailer, rw.setTrailer(":status", "500"));
    // Case-insensitive: the deny-list is not a spelling test.
    try testing.expectError(error.ForbiddenTrailer, rw.declareTrailer("cOnTeNt-LeNgTh"));
    // …and neither is writing the advert by hand instead of declaring it —
    // setHeader routes `Trailer` through the same gate (flattened error).
    try testing.expectError(error.InvalidHeader, rw.setHeader("Trailer", "X-Ok, Content-Length"));
    // …all-or-nothing: the good name in that list was NOT kept, so a
    // rejected advert cannot widen the allow-list as a side effect.
    try testing.expect(!rw.declaredTrailer("X-Ok"));
    try testing.expectError(error.TrailerNotDeclared, rw.setTrailer("X-Ok", "1"));

    // Nothing above stuck: a legitimate trailer still works, and the wire
    // carries no trace of the rejected names.
    try rw.declareTrailer("X-Checksum");
    try rw.writeAll("hi");
    try rw.setTrailer("X-Checksum", "deadbeef");
    try rw.end();
    const wire = out.buffered();
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Trailer: X-Checksum\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n2\r\nhi\r\n0\r\nX-Checksum: deadbeef\r\n\r\n", wire);
}

test "ResponseWriter: an undeclared trailer is refused (the Trailer advert is the allow-list)" {
    var out_buf: [512]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{});
    try testing.expectError(error.TrailerNotDeclared, rw.setTrailer("X-Checksum", "deadbeef"));
    // Declaring by hand-writing the header works too, and enables it.
    try rw.setHeader("Trailer", "X-Checksum ,  X-Rows");
    try testing.expect(rw.declaredTrailer("x-checksum"));
    try testing.expect(rw.declaredTrailer("X-ROWS"));
    try rw.setTrailer("X-Checksum", "deadbeef");
    // Still refused for a sibling name that was never advertised.
    try testing.expectError(error.TrailerNotDeclared, rw.setTrailer("X-Other", "1"));
    // Malformed names/values never get that far.
    try testing.expectError(error.InvalidHeader, rw.setTrailer("Bad Name", "x"));
    try testing.expectError(error.InvalidHeader, rw.setTrailer("X-Checksum", "a\r\nX-Evil: 1"));
    try rw.end();
    const wire = out.buffered();
    try testing.expect(std.mem.indexOf(u8, wire, "X-Evil") == null);
    try testing.expect(std.mem.indexOf(u8, wire, "X-Other") == null);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Trailer: X-Checksum, X-Rows\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n0\r\nX-Checksum: deadbeef\r\n\r\n", wire);
}

test "ResponseWriter: trailers are refused on framings that cannot carry them" {
    var out_buf: [512]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;

    { // Declared Content-Length → identity framing, no trailer section.
        var out: Writer = .fixed(&out_buf);
        var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{});
        try rw.setHeader("Content-Length", "2");
        try testing.expect(!rw.trailersSupported());
        try testing.expectError(error.TrailersUnsupported, rw.declareTrailer("X-Checksum"));
    }
    { // …and the other order: Content-Length after the advert is refused,
        // so `Trailer` + `Content-Length` can never both reach the wire.
        var out: Writer = .fixed(&out_buf);
        var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{});
        try rw.declareTrailer("X-Checksum");
        try testing.expectError(error.InvalidHeader, rw.setHeader("Content-Length", "2"));
    }
    { // HTTP/1.0 peer: no chunked transfer coding exists there.
        var out: Writer = .fixed(&out_buf);
        var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{ .http1_0 = true });
        try testing.expect(!rw.trailersSupported());
        try testing.expectError(error.TrailersUnsupported, rw.declareTrailer("X-Checksum"));
    }
    { // HEAD / 204 / 304: no body ⇒ no trailer section.
        var out: Writer = .fixed(&out_buf);
        var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{ .head_request = true });
        try testing.expectError(error.TrailersUnsupported, rw.declareTrailer("X-Checksum"));
        var out2: Writer = .fixed(&out_buf);
        var rw2 = trailerWriter(&out2, &body_buf, &chunk_buf, .{});
        rw2.setStatus(204);
        try testing.expectError(error.TrailersUnsupported, rw2.declareTrailer("X-Checksum"));
    }
    { // The one case the setters cannot catch: declare first, THEN make the
        // response bodiless. `setStatus` returns void, so `end` must fail
        // the response instead of quietly dropping the advertised fields.
        var out: Writer = .fixed(&out_buf);
        var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{});
        try rw.declareTrailer("X-Checksum");
        try rw.setTrailer("X-Checksum", "deadbeef");
        rw.setStatus(204);
        try testing.expectError(error.WriteFailed, rw.end());
        try testing.expect(rw.connectionMustClose());
    }
}

test "ResponseWriter: trailer capacity is bounded" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw = trailerWriter(&out, &body_buf, &chunk_buf, .{});
    const names = [_][]const u8{ "X-A", "X-B", "X-C", "X-D", "X-E", "X-F", "X-G", "X-H" };
    try rw.declareTrailers(&names); // exactly max_response_trailers
    try testing.expectError(error.TooManyTrailers, rw.declareTrailer("X-I"));
    // Re-declaring an existing name is idempotent, not a capacity charge.
    try rw.declareTrailer("x-a");
    try testing.expectEqualStrings("X-A, X-B, X-C, X-D, X-E, X-F, X-G, X-H", rw.headers[0].value);
    // A name list longer than `trailer_decl_bytes` is refused too.
    var out2: Writer = .fixed(&out_buf);
    var rw2 = trailerWriter(&out2, &body_buf, &chunk_buf, .{});
    const long = "X-" ++ ("a" ** 200);
    try rw2.declareTrailer(long);
    try testing.expectError(error.TooManyTrailers, rw2.declareTrailer(long ++ "b"));
}

test "ResponseWriter: a gzip-compressed body still carries its trailers" {
    // The compressed pipeline terminates its own chunked stream; the
    // trailer section has to survive that path too, not just the plain one.
    var out_buf: [4096]u8 = undefined;
    const got = runStreamWith(
        .{ .compression = .{ .min_size = 1 } },
        null,
        "GET /outtrailers HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
        &out_buf,
    );
    try testing.expect(std.mem.indexOf(u8, got, "Content-Encoding: gzip\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Trailer: X-Checksum, X-Rows\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\nX-Checksum: deadbeef\r\nX-Rows: 3\r\n\r\n"));
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

test "integration: multicore accept engine (SO_REUSEPORT) serves across N listeners" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const n_listeners = 4;
    var hits: Hits = .init(0);
    var server = init(io, testing.allocator, .{
        .handler = testHandler,
        .context = &hits,
        .accept_threads = n_listeners, // bind 4 SO_REUSEPORT listeners
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("multicore bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    // All N listeners bound the same resolved port (SO_REUSEPORT group).
    try testing.expectEqual(@as(usize, n_listeners - 1), server.aux_listeners.len);
    const port = server.boundAddress().getPort();
    for (server.aux_listeners) |l|
        try testing.expectEqual(port, l.socket.address.getPort());

    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    // The kernel spreads these fresh connections across the N listen queues;
    // every one must be served regardless of which listener accepted it.
    const requests = 24;
    for (0..requests) |_| {
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 64);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }
    try testing.expectEqual(@as(u32, requests), hits.load(.monotonic));
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

test "integration: Server.Options defaults emit Server and Date on the wire" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Default `Options` — no `server_name`/`emit_date` override.
    var server = init(io, testing.allocator, .{ .handler = testHandler });
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

    try sw.interface.writeAll("GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try sw.interface.flush();
    const head = try h1.readHead(&sr.interface, &head_buf);

    // Byte-level: the literal default `Server` line is on the wire …
    try testing.expect(std.mem.indexOf(u8, head, "\r\nServer: zig-libs-http/0.1\r\n") != null);
    // … and so is a `Date:` line (value is real wall-clock, so only the
    // literal field name + colon-space is asserted, not the timestamp).
    try testing.expect(std.mem.indexOf(u8, head, "\r\nDate: ") != null);
}

test "integration: Server.Options suppression agrees byte-for-byte with StreamOptions suppression" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The socket path expressing the same suppression `serveStream` already
    // could — this is the finding: before `server_name`/`emit_date`
    // existed on `Options`, `connMain` always built a non-null `Now` and a
    // non-optional name, so the socket path could NOT reach this string no
    // matter what a caller passed.
    var server = init(io, testing.allocator, .{
        .handler = testHandler,
        .server_name = null,
        .emit_date = false,
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

    try sw.interface.writeAll("GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try sw.interface.flush();
    const head = try h1.readHead(&sr.interface, &head_buf);

    // Byte-identical to `both_suppressed_head_only`, produced offline by
    // `serveStream` with `server_name = null, now = null` — the two entry
    // points now agree exactly rather than one being structurally unable
    // to omit what the other always could.
    try testing.expectEqualStrings(both_suppressed_head_only, head);
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
    // `content_length` is `?u64` (RFC 9110 allows values past `usize` on a
    // 32-bit host; `ContentLengthReader` streams it rather than materializing
    // the whole thing). This test reads a tiny literal body straight into
    // memory via `take`, which is inherently `usize`-bounded, so casting down
    // here -- not narrowing the wire-protocol field -- is the safe direction.
    const body1 = try sr.interface.take(@intCast(res1.content_length.?));
    try testing.expect(std.mem.startsWith(u8, body1, "127.0.0.1:"));
    try testing.expect(std.mem.endsWith(u8, body1, " #0"));

    // Request 2 on the same connection: index rose to 1.
    try sw.interface.writeAll("GET /connmeta HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try sw.interface.flush();
    const res2 = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
    try testing.expectEqual(@as(u16, 200), res2.status);
    const body2 = try sr.interface.take(@intCast(res2.content_length.?)); // see body1 above
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

// ── tests (cancelation) ─────────────────────────────────────────────────────
//
// `Future.cancel` does release a thread parked in a socket read, but nothing
// in `std.Io.Reader`/`Writer`'s error sets can carry the reason out — so the
// four tests below assert on `TimeoutReader`/`TimeoutWriter`'s out-of-band
// `canceled`, which is where std's own `Stream.Reader.err` idiom is
// continued. Each covers one blind spot, and each was proven by reverting
// its fix and watching it go red:
//
//   * parked in the stall-timeout `poll` — the raw `poll` is not a `std.Io`
//     cancelation point at all, and without `checkCanceled` the abandoned
//     connection files itself as `timed_out`, a stalled peer;
//   * parked in the socket read itself — the cancelation is on `src.err`
//     and is otherwise flattened into an anonymous `ReadFailed`;
//   * and the two writer-side mirrors of both.
//
// The peer accepts and then neither reads nor writes, so the operation under
// test really is parked when the cancelation arrives.

fn acceptOne(server: *net.Server, io: std.Io) net.Server.AcceptError!net.Stream {
    return server.accept(io);
}

/// A loopback listener on an ephemeral port — a fixed one collides as soon
/// as several modules' tests run at the same time.
fn cancelListener(io: std.Io) !net.Server {
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    return addr.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("loopback listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
}

/// A connected pair whose accepted end never reads and never writes: `conn`
/// is the side the wrapper under test owns.
const SilentPeer = struct {
    conn: net.Stream,
    peer: net.Stream,

    /// `error.SkipZigTest` when loopback is unusable, which is how the rest
    /// of this file's socket tests behave on a sandboxed runner.
    fn open(io: std.Io, server: *net.Server) !SilentPeer {
        var accept_fut = try io.concurrent(acceptOne, .{ server, io });
        const conn = server.socket.address.connect(io, .{ .mode = .stream }) catch |err| {
            if (accept_fut.cancel(io)) |s| s.close(io) else |_| {}
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        return .{ .conn = conn, .peer = try accept_fut.await(io) };
    }

    fn close(self: *SilentPeer, io: std.Io) void {
        self.peer.close(io);
        self.conn.close(io);
    }

    /// Shrink both halves of the pipe, best effort. A write only parks once
    /// our send buffer AND the peer's receive buffer are full; at loopback
    /// defaults that is megabytes of pointless memcpy before the writer
    /// tests reach the state they are about.
    fn shrink(self: *SilentPeer) void {
        const small = std.mem.toBytes(@as(c_int, 2048));
        std.posix.setsockopt(self.conn.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, &small) catch {};
        std.posix.setsockopt(self.peer.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &small) catch {};
    }
};

/// The blocking read under test, on its own task so it can be canceled.
fn cancelReadOnce(t: *TimeoutReader) Reader.Error!u8 {
    return t.reader.takeByte();
}

/// Push until the write parks. Bounded, so a kernel that somehow never
/// blocks cannot spin the suite instead of failing it.
fn cancelWriteUntilBlocked(t: *TimeoutWriter) Writer.Error!void {
    const chunk: [4096]u8 = @splat('x');
    var left: usize = 8 << 20;
    while (left != 0) : (left -= chunk.len) try t.writer.writeAll(&chunk);
}

test "cancel: a cancelation during the read stall poll is not filed as a stalled peer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try cancelListener(io);
    defer server.deinit(io);
    var pair = try SilentPeer.open(io, &server);
    defer pair.close(io);

    var buf: [64]u8 = undefined;
    var sr = pair.conn.reader(io, buf[0..0]);
    // 600 ms: `poll` restarts on the cancelation's signal, so the task can
    // only return once the stall timeout genuinely elapses — long enough to
    // be unambiguous, short enough not to weigh on the module's suite.
    var tr: TimeoutReader = .init(&sr, io, 600, 0, &buf);

    var fut = try io.concurrent(cancelReadOnce, .{&tr});
    try io.sleep(.fromMilliseconds(100), .awake);
    // `Reader.Error` cannot say more than this — which is the whole problem.
    try testing.expectError(error.ReadFailed, fut.cancel(io));
    try testing.expect(tr.canceled);
    try testing.expect(!tr.timed_out);
}

test "cancel: a canceled socket read is recovered from the reader's err field" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try cancelListener(io);
    defer server.deinit(io);
    var pair = try SilentPeer.open(io, &server);
    defer pair.close(io);

    var buf: [64]u8 = undefined;
    var sr = pair.conn.reader(io, buf[0..0]);
    // No stall timeout and no request deadline: the read skips `poll`
    // entirely and parks inside `std.Io`, where the cancelation lands on
    // `sr.err` instead.
    var tr: TimeoutReader = .init(&sr, io, 0, 0, &buf);

    var fut = try io.concurrent(cancelReadOnce, .{&tr});
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.ReadFailed, fut.cancel(io));
    try testing.expect(tr.canceled);
    try testing.expect(!tr.timed_out);
}

test "cancel: a cancelation during the write stall poll is not filed as a stalled peer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try cancelListener(io);
    defer server.deinit(io);
    var pair = try SilentPeer.open(io, &server);
    defer pair.close(io);
    pair.shrink();

    var buf: [1024]u8 = undefined;
    var sw = pair.conn.writer(io, buf[0..0]);
    var tw: TimeoutWriter = .init(&sw, io, 600, &buf);

    var fut = try io.concurrent(cancelWriteUntilBlocked, .{&tw});
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.WriteFailed, fut.cancel(io));
    try testing.expect(tw.canceled);
    try testing.expect(!tw.timed_out);
}

test "cancel: a canceled socket write is recovered from the writer's err field" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try cancelListener(io);
    defer server.deinit(io);
    var pair = try SilentPeer.open(io, &server);
    defer pair.close(io);
    pair.shrink();

    var buf: [1024]u8 = undefined;
    var sw = pair.conn.writer(io, buf[0..0]);
    // No write stall timeout: `pollOut` is skipped and the write parks in
    // `std.Io`, where the cancelation lands on `sw.err`.
    var tw: TimeoutWriter = .init(&sw, io, 0, &buf);

    var fut = try io.concurrent(cancelWriteUntilBlocked, .{&tw});
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.WriteFailed, fut.cancel(io));
    try testing.expect(tw.canceled);
    try testing.expect(!tw.timed_out);
}

// ── buffers_provider ────────────────────────────────────────────────────────

/// A provider that counts, so a test can say *when* the codec borrows rather
/// than only that it works.
const CountingProvider = struct {
    acquires: usize = 0,
    releases: usize = 0,
    fail_at: usize = 0, // acquire number that returns null; 0 = never
    head: [1024]u8 = undefined,
    request_body: [256]u8 = undefined,
    response_body: [64]u8 = undefined,
    chunk: [128]u8 = undefined,

    fn provider(self: *CountingProvider) BuffersProvider {
        return .{ .ctx = self, .acquire = acq, .release = rel };
    }
    fn acq(ctx: ?*anyopaque) ?StreamBuffers {
        const self: *CountingProvider = @ptrCast(@alignCast(ctx.?));
        self.acquires += 1;
        if (self.fail_at != 0 and self.acquires == self.fail_at) return null;
        return .{
            .head = &self.head,
            .request_body = &self.request_body,
            .response_body = &self.response_body,
            .chunk = &self.chunk,
        };
    }
    fn rel(ctx: ?*anyopaque, _: StreamBuffers) void {
        const self: *CountingProvider = @ptrCast(@alignCast(ctx.?));
        self.releases += 1;
    }
};

fn runWithProvider(p: BuffersProvider, wire: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(wire);
    var out: Writer = .fixed(out_buf);
    // Deliberately unusable: a provider that is consulted leaves these
    // untouched, so a zero-length fallback proves the borrow happened rather
    // than merely permitting it.
    var none: [0]u8 = undefined;
    serveStream(.{
        .handler = testHandler,
        .server_name = "test",
        .now = null,
        .buffers_provider = p,
    }, &in, &out, .{
        .head = &none,
        .request_body = &none,
        .response_body = &none,
        .chunk = &none,
    });
    return out.buffered();
}

test "buffers_provider: borrowed once per request and given back each time" {
    var cp: CountingProvider = .{};
    var out_buf: [4096]u8 = undefined;
    const got = runWithProvider(cp.provider(), "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);

    // Two requests answered from buffers the caller never owned: the fallback
    // passed to `serveStream` is zero length and could not have served either.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "hello"));
    try testing.expectEqual(@as(usize, 2), cp.acquires);
    // Balanced -- a leak here is a pool that drains under load, which is the
    // failure this whole mechanism would otherwise introduce.
    try testing.expectEqual(cp.acquires, cp.releases);
}

test "buffers_provider: nothing to lend is 503 and a closed connection, not a dropped one" {
    var cp: CountingProvider = .{ .fail_at = 2 };
    var out_buf: [4096]u8 = undefined;
    const got = runWithProvider(cp.provider(), "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "hello"));
    try testing.expect(std.mem.indexOf(u8, got, "503") != null);
    // The one that was lent came back; the one that was refused was never
    // handed out, so it must not be released either.
    try testing.expectEqual(@as(usize, 1), cp.releases);
}

test "PooledBuffers: successive requests reuse one slab" {
    var layout: PooledBuffers = .{
        .pool = undefined,
        .head_len = 1024,
        .request_body_len = 256,
        .response_body_len = 64,
        .chunk_len = 128,
    };
    var pool: bufpool.BufferPool = .init(testing.allocator, layout.slabSize(), 4);
    defer pool.deinit();
    layout.pool = &pool;

    var out_buf: [4096]u8 = undefined;
    const got = runWithProvider(layout.provider(), "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);

    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, got, "hello"));
    // ⭐ The point of the exercise: three requests, ONE slab. Without the
    // return half of the contract this would be three.
    try testing.expectEqual(@as(usize, 1), pool.allocCount());
    try testing.expectEqual(@as(usize, 2), pool.reuseCount());
    try testing.expectEqual(@as(usize, 1), pool.idleCount());
}

test "serveStep: one turn of the loop, wait owned by the caller" {
    // The contract a fiber-per-connection engine relies on: the caller does
    // the wait in ITS frame, `serveStep` serves exactly one request that is
    // already arriving, and the request cap still binds through `req_index`.
    var in: Reader = .fixed("GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n");
    var out_buf: [4096]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [64]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    const bufs: StreamBuffers = .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    };
    const opts: StreamOptions = .{ .handler = testHandler, .server_name = "test", .now = null };

    var served: u32 = 0;
    while (true) {
        _ = in.peekByte() catch break;
        if (serveStep(opts, &in, &out, bufs, served) == .close) break;
        served += 1;
    }
    try testing.expectEqual(@as(u32, 2), served);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, out.buffered(), "hello"));

    // And the cap: with max_requests_per_conn = 1, the first step already
    // answers `Connection: close`.
    var in2: Reader = .fixed("GET /hello HTTP/1.1\r\nHost: t\r\n\r\n");
    var out2_buf: [4096]u8 = undefined;
    var out2: Writer = .fixed(&out2_buf);
    var capped = opts;
    capped.max_requests_per_conn = 1;
    try testing.expectEqual(ConnDisposition.close, serveStep(capped, &in2, &out2, bufs, 0));
    try testing.expect(std.mem.indexOf(u8, out2.buffered(), "connection: close") != null or
        std.mem.indexOf(u8, out2.buffered(), "Connection: close") != null);
}

test "buffers_provider: nothing is borrowed while the connection waits" {
    // ⭐ The regression this pins is the one that made the whole mechanism
    // pointless: if the borrow window covers the wait for the next request,
    // a set is held for as long as a per-connection one would be. The wire
    // here ends after two requests with no `Connection: close`, so the loop
    // takes a third turn and finds end-of-stream. Borrowing before the wait
    // costs a third acquire; borrowing after it does not.
    var cp: CountingProvider = .{};
    var out_buf: [4096]u8 = undefined;
    const got = runWithProvider(cp.provider(), "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n", &out_buf);

    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "hello"));
    try testing.expectEqual(@as(usize, 2), cp.acquires);
    try testing.expectEqual(@as(usize, 2), cp.releases);
}

// ── the Date stamp is formatted once a second, not once a response ──────────

/// A clock the test drives, counting how often it was asked.
const CountingClock = struct {
    second: i64 = 1_756_468_938, // 2026-08-29T13:22:18Z
    reads: usize = 0,

    fn epochSeconds(ctx: ?*anyopaque) i64 {
        const self: *CountingClock = @ptrCast(@alignCast(ctx.?));
        self.reads += 1;
        return self.second;
    }

    fn now(self: *CountingClock) StreamOptions.Now {
        return .{ .ctx = self, .epochSeconds = CountingClock.epochSeconds };
    }
};

test "the stamp is reformatted only when the second changes" {
    // The whole point of the cache. A server answering thousands of responses
    // per second formats the same 29 bytes for all of them, and in a consumer
    // measurement that formatting was most of what the `Date` header cost.
    var clock: CountingClock = .{};
    date_cache_second = std.math.minInt(i64); // this thread may have served already

    var buf: [http_date_len]u8 = undefined;
    var expected: [http_date_len]u8 = undefined;
    const want = formatHttpDate(clock.second, &expected);

    try testing.expectEqualStrings(want, httpDateInto(clock.now(), &buf));

    // ⭐ Asserted by poisoning the cache rather than by counting calls: a
    // version that reformatted every time returns the right answer too, so a
    // test that only compares stamps passes with the cache deleted. Overwrite
    // what the first call stored, ask again inside the same second, and the
    // poison has to come back -- which it can only do if nothing reformatted.
    @memset(&date_cache, 'X');
    try testing.expectEqualStrings("X" ** http_date_len, httpDateInto(clock.now(), &buf));

    // The clock is still read every time -- what is saved is the formatting,
    // and a cache that stopped reading the clock could not notice the second
    // turning over.
    try testing.expectEqual(@as(usize, 2), clock.reads);

    // And the turnover itself: a new second reformats, poison and all.
    clock.second += 1;
    var next: [http_date_len]u8 = undefined;
    const got = httpDateInto(clock.now(), &buf);
    try testing.expectEqualStrings(formatHttpDate(clock.second, &next), got);
}

test "the stamp lands in the caller's buffer, not in the cache" {
    // ⭐ The safety property, and the reason this returns into a buffer rather
    // than handing back `&date_cache`: a caller may yield between taking the
    // stamp and writing it out, and the next tick of the clock must not edit a
    // head that is half on the wire.
    var clock: CountingClock = .{};
    date_cache_second = std.math.minInt(i64);

    var buf: [http_date_len]u8 = undefined;
    const got = httpDateInto(clock.now(), &buf);
    try testing.expectEqual(@as([*]const u8, &buf), got.ptr);

    // Prove it by doing exactly what a second connection on this thread would:
    // move the clock on, take another stamp, and check the first one did not
    // change under it.
    var held: [http_date_len]u8 = undefined;
    @memcpy(&held, got);
    clock.second += 60;
    var other: [http_date_len]u8 = undefined;
    _ = httpDateInto(clock.now(), &other);
    try testing.expectEqualStrings(&held, got);
}

test "formatHttpDate: the calendar, and the year that used to panic" {
    var buf: [http_date_len]u8 = undefined;

    // RFC 9110 §5.6.7's own example, and the epoch.
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", formatHttpDate(784111777, &buf));
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(0, &buf));

    // A leap day and the two year boundaries around it -- where a hand-written
    // calendar goes wrong, and where the leading zeroes are load-bearing.
    try testing.expectEqualStrings("Thu, 29 Feb 2024 00:00:00 GMT", formatHttpDate(1709164800, &buf));
    try testing.expectEqualStrings("Wed, 01 Jan 2025 00:00:00 GMT", formatHttpDate(1735689600, &buf));
    try testing.expectEqualStrings("Wed, 31 Dec 2025 23:59:59 GMT", formatHttpDate(1767225599, &buf));

    // Every weekday name, seven consecutive days from a known Sunday.
    const sunday = 784111777 - 8 * 3600; // same day, safely inside it
    for ([_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" }, 0..) |name, i| {
        const out = formatHttpDate(sunday + @as(i64, @intCast(i)) * std.time.s_per_day, &buf);
        try testing.expectEqualStrings(name, out[0..3]);
    }

    // ⚠ Before the rewrite the year went out through `{d}`, so a five-digit
    // year overran the 29-byte buffer and `catch unreachable` turned it into a
    // panic. A caller cannot be trusted not to hand over a wild `i64`.
    try testing.expectEqualStrings("Fri, 31 Dec 9999 23:59:59 GMT", formatHttpDate(253402300799, &buf));
    // Both ends saturate rather than wrapping or faulting.
    try testing.expectEqualStrings("Fri, 31 Dec 9999 23:59:59 GMT", formatHttpDate(std.math.maxInt(i64), &buf));
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(std.math.minInt(i64), &buf));

    // Negative seconds are floored to the epoch rather than wrapping into a
    // plausible-looking wrong date.
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(-1, &buf));
}

/// ⛔ The per-connection memory of any server that gives a connection its own
/// stack -- a thread, a fiber, a coroutine -- is this number, and it is paid
/// once per IN-FLIGHT REQUEST. It grows silently: a local added to the serving
/// path costs every connection on the box, and no other test in this file
/// would move.
///
/// The ceiling is deliberately loose. It is here to catch a frame that
/// DOUBLES, not to police a hundred bytes, and a change that needs more room
/// should raise it in the same commit that spends it -- with the number it
/// measured. Measured 2026-08-30: 12,496 B at ReleaseFast, down from 18,640
/// when `max_normalized_path` was 8 KiB.
const codec_frame_budget = 16 * 1024;

test "the serving frame stays inside its budget" {
    var out_buf: [4096]u8 = undefined;
    _ = runStream(null, "GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expect(frame_probe.measured != 0);

    // ⚠ Debug allocates a slot per temporary and reaches ~35 KiB where
    // ReleaseFast reaches 16.5; asserting one number against both would either
    // pass everything or fail honestly-built code. The optimized modes are the
    // ones a server ships, and they are the ones held to the budget.
    const optimized = builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe or
        builtin.mode == .ReleaseSmall;
    if (!optimized) return;
    if (frame_probe.measured > codec_frame_budget) {
        std.debug.print(
            "the serving frame is {d} B, over the {d} B budget -- see `frame_probe`\n",
            .{ frame_probe.measured, codec_frame_budget },
        );
        return error.ServingFrameTooLarge;
    }
}
