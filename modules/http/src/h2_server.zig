// SPDX-License-Identifier: MIT

//! h2 server integration (Phase 3.1): serves HTTP/2 over cleartext TCP via
//! **prior knowledge** (RFC 9113 §3.3 — the client just opens with the
//! HTTP/2 connection preface; RFC 9113 removed the HTTP/1.1 `Upgrade: h2c`
//! mechanism, so this is *the* cleartext path). `Server.zig` peeks for the
//! preface after accept (`Options.enable_h2c`) and hands the connection
//! here; everything handler-facing is shared with the HTTP/1.1 path — the
//! same `Server.Request` / `Server.ResponseWriter` / `Options.handler`.
//!
//! **Bring-your-own-TLS (Phase 3.3):** over TLS, HTTP/2 is selected via the
//! ALPN id "h2" (RFC 7301; RFC 9113 §3.3 — no upgrade mechanism exists).
//! This module deliberately ships no TLS server; instead `serveStream` is
//! the seam: terminate TLS yourself (an external Zig TLS library, or a
//! future std TLS server — today a reverse proxy in front of the cleartext
//! `Server` fills the same role), offer `http.alpn_offer` in the handshake,
//! and when the negotiated protocol maps to `.h2`
//! (`http.protocolFromAlpn`), call `serveStream` with the TLS connection's
//! plaintext reader/writer. The engine is byte-identical from there — the
//! client connection preface (§3.4) still opens the stream, exactly as on
//! h2c, so the serve loop is shared, not duplicated. When ALPN selected
//! "http/1.1" (or nothing), hand the same reader/writer to
//! `Server.serveStream` — both protocols serve one already-established
//! connection through the same `Options.handler`.
//!
//! Model (correct over fancy): frames are demultiplexed as they arrive —
//! per-stream request state (decoded header list + the DATA bytes)
//! accumulates in a map, so interleaved streams are all collected — and
//! requests are handled either **sequentially** on the connection's task
//! (the default: no `Options.dispatcher`, byte-for-byte the behavior this
//! module has always had) or **concurrently** on a caller-supplied bounded
//! worker pool (`Options.dispatcher`, see `Dispatcher` and the
//! "Concurrent handlers" section below). The handler writes an ordinary
//! HTTP/1.1 response through the stock `ResponseWriter`, which is re-framed
//! as h2 HEADERS + DATA (+ a trailing HEADERS frame when the handler set
//! response trailers — §8.1, which also moves END_STREAM off the last DATA
//! frame): connection-specific headers are stripped (§8.2.2), names
//! lowercased (§8.2.1), the peer's SETTINGS_MAX_FRAME_SIZE honored
//! (`h2.Connection` splits DATA/CONTINUATION), and both flow-control
//! windows respected — when the response body outruns the peer's window the
//! loop keeps reading (WINDOW_UPDATE, and anything else the peer sends)
//! until room opens (§5.2).
//!
//! **Streaming, both directions.** Neither side has to fit in memory, and
//! both can be live on one stream at once.
//!
//! *Responses* stream always, with no opt-in and no second code path: the
//! re-framing above happens **as the response is written** rather than after
//! it (`Framer`, which is a `std.Io.Writer` `ResponseWriter` drains into).
//! An HTTP/1.1 response is self-describing, so re-framing it as a pipe needs
//! nothing that re-framing it from a finished buffer needed — which is why
//! there is one engine here and not two. Everything `ResponseWriter` gives
//! an h1 handler (gzip, ranges, conditional requests, content negotiation,
//! the response-trailer surface) therefore works on h2 unchanged, because
//! none of it knows the difference; and a response that fits the
//! `ResponseWriter` buffer is still framed byte-identically to the old
//! stage-then-re-frame path. `Framer`'s doc comment argues the choice
//! against the two alternatives.
//!
//! *Request bodies* are buffered until END_STREAM by default and stream
//! per-route on opt-in (`Options.stream_request`). The default is not
//! laziness: the two answers this server gives *before* a handler runs —
//! 413 over `max_body_bytes`, 400 for a `content-length` disagreeing with
//! the DATA total (§8.1.1) — both need the whole body, and h1 has the same
//! answers only because it knows the length up front. Opting in trades them
//! for h1's actual behavior (the handler starts at HEADERS and reads DATA as
//! it lands; both checks survive as read failures) on the routes that want
//! it. `StreamBody` implements it; `Session.onData` documents why the
//! §6.9 window credit is returned on ARRIVAL for buffered bodies and on
//! CONSUMPTION for streaming ones, and why either policy on the other
//! surface is a bug.
//!
//! Errors mirror §5.4: a connection-scoped violation answers GOAWAY with
//! the code the h2 layer reports and closes; a stream-scoped violation
//! answers RST_STREAM and the connection lives on
//! (`h2.Connection.recoverStreamError`). Peer bytes never panic.
//!
//! Denial-of-service hardening (`Options.limits`, safe defaults — an
//! `enable_h2c` server is hardened out of the box):
//! - **Rapid reset (CVE-2023-44487)** and **CONTINUATION flood
//!   (CVE-2024-27316)** guards plus a control-frame flood budget live in
//!   `h2.Connection` (see its module doc); breaches surface here as
//!   connection violations answered with GOAWAY(ENHANCE_YOUR_CALM). The
//!   rapid-reset defence is a **budget**, not a consequence of running one
//!   handler at a time — see "Concurrent handlers" for why that distinction
//!   had to be made explicit and what now carries it.
//! - **SETTINGS_MAX_CONCURRENT_STREAMS** (`max_concurrent_streams`) is
//!   advertised in the server preface and enforced: request streams above
//!   the limit are refused with RST_STREAM(REFUSED_STREAM) — safely
//!   retryable per §8.7 — and the connection keeps serving the rest.
//! - **`max_streams_per_connection`** bounds total streams on one
//!   connection; once reached, ready requests finish and the connection
//!   closes with a graceful GOAWAY(NO_ERROR) so the client reconnects.
//!
//! ## Concurrent handlers (`Options.dispatcher`)
//!
//! Without a dispatcher every handler runs to completion on the connection's
//! own task. That is not merely slow, it is a *liveness* bug on a
//! multiplexed protocol: `pump` — the only thing that reads the socket — has
//! three call sites, all of them inside the response path, so a handler
//! blocked on anything that is **not** h2 read/write (a database, a lock, an
//! application queue a gRPC bidi handler is waiting on) stops the connection
//! from reading at all. PING, SETTINGS and WINDOW_UPDATE stop being
//! processed for every other stream on that connection.
//!
//! `Options.dispatcher` is the seam that fixes it: a two-function interface
//! whose implementation the **caller** supplies, so `http` keeps depending
//! on nothing but `netaddr` and no consumer of `http` pulls in threads it
//! did not ask for (`modules/workerpool` is the intended implementation; a
//! worked one is in this file's tests). With a dispatcher installed, a
//! stream is handed to a worker thread and the connection task goes straight
//! back to reading.
//!
//! **What is dispatched, and when.** Only after a *complete* HEADERS block
//! has been decoded and admitted into the jobs map — the same instant
//! `takeReady` already used. Rubbish (a truncated header sequence, a stream
//! over `max_concurrent_streams`, a CONTINUATION flood) is refused before it
//! can occupy a thread.
//!
//! **Two caps, both enforced, and they are not interchangeable.**
//!   * per connection: `Dispatcher.max_concurrent_handlers` (default 8).
//!     Over it, a ready stream simply waits in the jobs map — which
//!     `max_concurrent_streams` already bounds — exactly as *every* stream
//!     waits today; no new unbounded state exists, so there is nothing to
//!     refuse.
//!   * globally: the dispatcher's own admission control. `spawn` returning
//!     false means "the pool is full", and that IS refused —
//!     RST_STREAM(REFUSED_STREAM), retryable per §8.7 — never queued, so a
//!     fleet of connections cannot accumulate work behind a saturated pool.
//!
//! **Rapid reset, re-derived.** The old justification was structural: one
//! handler at a time meant a cancelled stream could never fan out concurrent
//! server work. A dispatch pool deletes that property by construction, so
//! the defence is now stated as three independent facts:
//!   1. cancellation is *charged*: a peer RST_STREAM on a stream that has
//!      not completed counts against `max_reset_streams` whether or not it
//!      was dispatched (`h2.Connection`, §rst_stream — a dispatched request
//!      stream is `half_closed_remote`, never `closed`, so "cancel after the
//!      thread is handed out" costs the attacker exactly as much as "cancel
//!      before"). Over budget ⇒ GOAWAY(ENHANCE_YOUR_CALM);
//!   2. the fan-out is *bounded* by the two caps above, so the work a
//!      cancelled stream can have started is bounded by the pool, not by the
//!      number of streams the attacker opened;
//!   3. a cancelled stream stops paying: `Job.rst` is polled by the response
//!      framer and the request-body reader, so a handler on a reset stream
//!      is aborted at its next write or read rather than running to
//!      completion.
//!
//! **Five invariants that used to hold for free.** One thread made them
//! true; `Session.mu` makes them true now, and each is stated where it is
//! enforced: stateful HPACK (`Framer.sendHead`, `Session.respondError`) ·
//! one shared `wire` (every `flushWire` caller) · flow control's
//! check-then-act (`Framer.emit`) · job lifetime (`Session.dropJob`) · the
//! rehashing jobs map (`Session.jobs`). `Session.lock` documents the whole
//! scheme, including what deliberately runs *outside* the lock.
//!
//! **Caller obligations with a dispatcher installed:** the `gpa` and the
//! `on_conn_state` hook must be thread-safe, and `Dispatcher.spawn` must run
//! the task on a *different* thread (running it inline self-deadlocks) — or,
//! with `Dispatcher.io` set, on a different fiber of the same thread.
//!
//! **Fibers (`Dispatcher.io`).** Without it the session lock and the waits
//! yield-spin, which is right for OS threads and a deadlock for fibers that
//! share one: a spinning fiber never hands the thread back to the fiber it is
//! waiting for. With it they park through that `Io` (`std.Io.Mutex` +
//! `std.Io.Condition`), so an io_uring engine can dispatch each stream to a
//! fiber of the connection's own thread.
//!
//! **Not here: per-user connection rate limiting.** The other half of the
//! DoS answer (max N new connections/s per user, identified by source IP +
//! a configured user-ip-list) cannot live in this file — by the time
//! `serve` is called the connection is already accepted and the preface is
//! being read. Its seam is `Server.Options.on_connect`
//! (`Server.ConnDecision.reject`), which runs on the accept loop with the
//! peer address and before a single byte is read; `modules/ratelimit`
//! already has the token bucket it needs.
//!
//! Provenance: clean-room from RFC 9113 (prior knowledge §3.3, malformed
//! requests §8.1.1, header validity §8.2.1/§8.2.2, request pseudo-headers
//! §8.3.1, flow control §5.2/§6.9, CONTINUATION/DoS considerations §10.5),
//! RFC 7301 (ALPN — consumed, not implemented, see `serveStream`) and the
//! public CVE-2023-44487 / CVE-2024-27316 advisories (behavior
//! descriptions only); no HTTP/2 server implementation was consulted or
//! copied.

const std = @import("std");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2 = @import("h2.zig");
const hpack = @import("hpack.zig");
const zeroize = @import("zeroize.zig");
const gzip = @import("gzip.zig");
const Server = @import("Server.zig");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Everything the h2 serving loop needs besides the byte streams —
/// socket-free (mirrors `Server.StreamOptions`), so tests can drive it from
/// fixed buffers. `Server.connMain` fills it from `Server.Options`.
pub const Options = struct {
    handler: Server.Handler,
    context: ?*anyopaque = null,
    /// Auto `server` response header; null = omit.
    server_name: ?[]const u8 = null,
    /// Wall-clock source for the auto `date` header; null = omit.
    now: ?Server.StreamOptions.Now = null,
    /// Socket peer address, surfaced on every `Request` (`peerAddress`).
    peer: ?std.Io.net.IpAddress = null,
    /// Bounds one decoded request header list — advertised as
    /// SETTINGS_MAX_HEADER_LIST_SIZE and enforced by the HPACK decoder
    /// (an over-limit block is a connection COMPRESSION_ERROR → GOAWAY;
    /// the h2 shape of the h1 431).
    max_header_bytes: usize = 16 * 1024,
    /// Request body cap (h1 `max_body_bytes` parity): a body crossing it
    /// answers 413 and its stream closes. **Enforced CONNECTION-WIDE, not
    /// per stream** (A1 http F2 — a body that is buffered at all, i.e. not
    /// `stream_request`, counts against `s.totalBufferedBodyBytes()` for
    /// the whole connection, not just its own stream): with h2
    /// multiplexing, `Limits.max_concurrent_streams` bodies can be buffered
    /// at once, and a per-stream-only cap let one connection hold that many
    /// times `max_body_bytes` at once (150 MB at the shipped defaults of
    /// 100 streams × 1 MiB) — the connection-wide total is what actually
    /// matches an h1 connection's single-body-at-a-time memory shape for
    /// the SAME configured number. null = unlimited — this struct is the
    /// low-level, socket-free codec layer (parity with
    /// `Server.StreamOptions`, which defaults the same field to null for
    /// the same reason: a plain-codec/BYO-TLS caller composing this
    /// directly should not be silently capped). A `Server`-owned h2c
    /// connection (`Options.enable_h2c`) does NOT get this default — see
    /// `Server.Options.max_body_bytes`'s doc: `connMain` forwards the
    /// hardened `1 << 20` (or whatever the caller set) into this field, so
    /// h1 and h2 are capped identically when driven through `Server`. Only
    /// a caller invoking `serve`/`serveStream` here directly (BYO-TLS) sees
    /// this null default.
    max_body_bytes: ?u64 = null,
    /// `ResponseWriter` body-buffer size (h1 parity; framing is re-derived
    /// here so it only affects gzip's buffered-vs-streaming decision).
    response_buffer_size: usize = 4 * 1024,
    /// Negotiated gzip response compression; requires `gzip_scratch`.
    compression: ?gzip.Compression = null,
    gzip_scratch: ?*gzip.Scratch = null,
    /// A second coding next to gzip; see `Server.EncoderProvider`. Active
    /// only while compression is. Acquired per stream, so with streams
    /// served concurrently (`dispatcher`, h2 fibers) the provider must be
    /// safe for that.
    encoder_provider: ?Server.EncoderProvider = null,
    /// Lifecycle observer (see `Server.ConnState`): .new/.closed per
    /// connection, .active/.idle around each request stream served.
    on_conn_state: ?Server.ConnStateFn = null,
    on_conn_state_ctx: ?*anyopaque = null,
    /// DoS-hardening limits; the defaults are safe for exposure.
    limits: Limits = .{},
    /// Per-request opt-in to the **incremental request body** (see the
    /// "Streaming" section of the module doc). Called once per request
    /// stream the moment its HEADERS block is decoded — before a single
    /// DATA octet — with `Options.context` and a `RequestPreview` of the
    /// decoded fields; returning true dispatches the handler right away
    /// and lets it read the body as it lands, false (and null, the
    /// default) keeps the buffer-then-dispatch behavior.
    ///
    /// This is a route-level switch by design: it is the one decision that
    /// cannot be made from inside the handler, because by the time a
    /// handler runs the choice has already been acted on.
    stream_request: ?StreamRequestFn = null,
    /// Run handlers on a caller-supplied bounded worker pool instead of on
    /// the connection's own task. Null (the default) is the historical
    /// sequential behavior, byte-for-byte — the locking below is compiled
    /// in but never taken. See the module doc's "Concurrent handlers".
    dispatcher: ?Dispatcher = null,
    /// Detached-stream idle hook (single-task mode only; see
    /// `ResponseWriter.detach` and `Detached`). Called by the serve loop
    /// right before it would block reading the connection, whenever at least
    /// one detached stream is live (or a detached stream's reset is waiting
    /// to be reported). The embedder owns the wait: push bytes through the
    /// `Detached` handle, `Detached.flush`, and return `.proceed` once the
    /// socket is (or may be) readable — the loop then does its blocking
    /// read exactly as always. Return `.close` to end the connection with a
    /// graceful GOAWAY. Without a hook, detached streams still work but new
    /// bytes for them can only be pushed from inside other streams'
    /// handlers, which is almost never what a detaching embedder wants.
    on_detached_idle: ?*const fn (?*anyopaque, Detached) IdleVerdict = null,
    /// Passed to `on_detached_idle`. Separate from `context`, which belongs
    /// to the handler.
    on_detached_idle_ctx: ?*anyopaque = null,
};

/// What `Options.on_detached_idle` tells the serve loop to do next.
pub const IdleVerdict = enum { proceed, close };

/// The embedder's handle over one connection's detached streams, valid only
/// inside `Options.on_detached_idle` (single-task mode: nothing else runs on
/// the connection while the hook does).
///
/// The push model is deliberately all-or-nothing and never queues: an event
/// that does not fit the stream's send window right now answers
/// `error.WouldBlock` and stages nothing, so backpressure lives with the
/// embedder's own event source rather than growing a buffer here. Credit
/// arrives as WINDOW_UPDATE frames — which is bytes on the socket, which is
/// exactly the "return `.proceed` and let the loop read" case.
pub const Detached = struct {
    s: *Session,

    pub const PushError = error{ WouldBlock, StreamGone, Overloaded };

    /// Live detached stream count.
    pub fn count(d: Detached) usize {
        return d.s.detached.items.len;
    }

    /// One stream the peer reset since the last call, or null. Drain this
    /// each hook invocation: a reset detached stream is already gone from
    /// `count` and can take no more pushes.
    pub fn takeClosed(d: Detached) ?u31 {
        return d.s.detached_closed.pop();
    }

    /// How many DATA octets `push` could send on `id` right now: the
    /// smaller of the connection and stream send windows, zero when the
    /// stream is gone.
    pub fn writable(d: Detached, id: u31) usize {
        const st = d.s.conn.stream(id) orelse return 0;
        switch (st.state) {
            .open, .half_closed_remote => {},
            else => return 0,
        }
        const win = @min(d.s.conn.conn_send_window, st.send_window);
        return if (win > 0) @intCast(win) else 0;
    }

    /// Stage `bytes` as DATA on detached stream `id` — all of it or none of
    /// it (`error.WouldBlock`). Staged, not flushed: call `flush` once the
    /// round of pushes is done. `error.StreamGone` means the stream is dead;
    /// call `close(id)` to retire it.
    pub fn push(d: Detached, id: u31, bytes: []const u8) PushError!void {
        const s = d.s;
        if (d.writable(id) < bytes.len) {
            if (s.conn.stream(id) == null) return error.StreamGone;
            return error.WouldBlock;
        }
        s.conn.sendData(&s.wire, id, bytes, false) catch |err| switch (err) {
            error.OutOfMemory => return error.Overloaded,
            error.WindowExhausted => return error.WouldBlock,
            else => return error.StreamGone,
        };
        s.stageWire() catch return error.Overloaded;
    }

    /// End detached stream `id` gracefully (an empty DATA frame carrying
    /// END_STREAM) and forget it. Safe on a stream that is already dead —
    /// the frame is simply not sent — so this is also the cleanup call
    /// after `error.StreamGone`.
    pub fn close(d: Detached, id: u31) void {
        const s = d.s;
        blk: {
            const st = s.conn.stream(id) orelse break :blk;
            switch (st.state) {
                .open, .half_closed_remote => {},
                else => break :blk,
            }
            s.conn.sendData(&s.wire, id, "", true) catch break :blk;
            s.stageWire() catch {};
        }
        for (s.detached.items, 0..) |sid, i| {
            if (sid == id) {
                _ = s.detached.swapRemove(i);
                break;
            }
        }
    }

    /// Put everything staged on the wire. Call before parking on the
    /// socket: the peer never learns of bytes sitting in the staging
    /// buffer.
    pub fn flush(d: Detached) error{Closed}!void {
        d.s.flushWire() catch return error.Closed;
    }
};

/// One unit of handler work, shaped exactly like `workerpool.Job` so a
/// `workerpool.WorkerPool` can carry it without an adapter struct.
pub const Task = struct {
    func: *const fn (ctx: *anyopaque) void,
    ctx: *anyopaque,
};

/// The injectable handler-execution seam (`Options.dispatcher`).
///
/// `http` deliberately does not implement this: it depends on `netaddr` and
/// nothing else, and `websocket`/`accesslog`/`grpc`/`mcp-http` all depend on
/// `http` — none of them should acquire a thread pool by transitive
/// accident. The intended implementation is `modules/workerpool` in ~30
/// lines of caller code (this file's tests contain a worked one, which is
/// also what the concurrency tests run against).
pub const Dispatcher = struct {
    /// Passed back to `spawn`.
    ctx: ?*anyopaque = null,
    /// Run `task.func(task.ctx)` exactly once on a task **other than the
    /// caller's**, and return true. Without `io` that task must be another
    /// OS thread; with `io` it may be a fiber of the caller's own thread
    /// (queued, or even switched to before `spawn` returns — it parks on
    /// the session lock the caller holds, which `io` makes a parking lock).
    ///
    /// Return **false** to refuse: the stream is answered with
    /// RST_STREAM(REFUSED_STREAM) (retryable, §8.7) and nothing is queued.
    /// That is the global-capacity answer — the owner ruling is "refuse, do
    /// not queue", so a saturated pool sheds load instead of growing a
    /// backlog behind it.
    ///
    /// ⚠ Calling `task.func` inline, on the caller's own stack, self-deadlocks
    /// in either mode: the caller holds the session lock, which the task needs.
    spawn: *const fn (ctx: ?*anyopaque, task: Task) bool,
    /// How the session's waits block. Null (the default) is the historical
    /// mode for tasks that are OS threads: the session lock and the two
    /// "wait for the connection to move" loops yield-spin.
    ///
    /// Set it when the tasks `spawn` starts are **fibers sharing a thread**
    /// (an io_uring engine, `std.Io.Evented`): a spinning fiber never gives
    /// the thread back, so a stream fiber parked in a socket write while
    /// holding the session lock would leave the reading fiber spinning on
    /// that lock forever — a deadlock, not a slowdown. With `io` the lock is
    /// a `std.Io.Mutex` and the waits are a `std.Io.Condition`, both of
    /// which park through `io.futexWait` — on a fiber engine, the fiber.
    /// A handler's waits -- for flow-control credit, for more of its request
    /// body -- are cancelation points of `io`: canceled, a response already
    /// started is ended by `RST_STREAM(CANCEL)` and the handler's write fails;
    /// a body read fails (`error.ReadFailed`). The connection stays up. The
    /// session lock and the connection task's own waits stay uncancelable.
    ///
    /// Must be the `Io` the tasks and the connection's own reader/writer
    /// run on.
    io: ?std.Io = null,
    /// Handlers allowed to run concurrently on **one** connection.
    ///
    /// Deliberately NOT `Limits.max_concurrent_streams`, which bounds
    /// in-flight *state* (the jobs map) and defaults to 100: using it as a
    /// thread count would manufacture a 100-way fan-out per connection, i.e.
    /// a new DoS surface rather than a closed one. A ready stream over this
    /// cap waits in the (already bounded) jobs map and is dispatched the
    /// moment a slot frees — the same wait every stream does today.
    max_concurrent_handlers: u32 = 8,
};

/// Predicate selecting the incremental request-body surface for one stream
/// (`Options.stream_request`). Gets `Options.context`.
pub const StreamRequestFn = *const fn (?*anyopaque, RequestPreview) bool;

/// What `Options.stream_request` sees: the decoded HEADERS block, exactly
/// as it came off the wire, before any body octet has arrived.
///
/// Deliberately the **raw** field list rather than a pre-validated request:
/// the authoritative §8.3/§8.2 validation still runs when the handler is
/// dispatched, and duplicating it here would be a second copy of the rules
/// to keep in step. A routing predicate needs `:method` and `:path`, which
/// need no validation to read.
pub const RequestPreview = struct {
    /// Decoded fields in wire order; h2 names are lowercase (§8.2.1) and
    /// pseudo-headers come first (§8.3).
    fields: []const hpack.Field,

    /// First value of `name` (exact match — h2 field names are lowercase
    /// on the wire, so pass them that way), or null.
    pub fn get(p: RequestPreview, name: []const u8) ?[]const u8 {
        for (p.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    /// `:method` mapped onto the shared vocabulary, or null when absent or
    /// not a method this server speaks.
    pub fn method(p: RequestPreview) ?http.Method {
        return Server.methodFromToken(p.get(":method") orelse return null);
    }

    /// `:path` up to the '?' ("" when absent).
    pub fn path(p: RequestPreview) []const u8 {
        const target = p.get(":path") orelse return "";
        const i = std.mem.indexOfScalar(u8, target, '?') orelse return target;
        return target[0..i];
    }
};

/// Per-connection DoS-hardening limits for the h2 serve loop (see the
/// module doc). Every breach ends in a clean GOAWAY or RST_STREAM — never
/// a panic and never unbounded work.
pub const Limits = struct {
    /// SETTINGS_MAX_CONCURRENT_STREAMS advertised to the peer and enforced:
    /// request streams above it are refused with RST_STREAM(REFUSED_STREAM)
    /// (retryable, §8.7) while the connection keeps serving.
    ///
    /// **This is a cap on STATE, not a concurrency limit.** What it bounds is
    /// the size of the in-flight jobs map (`s.jobs.count()`); it says nothing
    /// about how many handlers run at once. Do not reach for it as a worker
    /// or thread count — at the default 100 that manufactures a 100-way
    /// fan-out per connection, i.e. it OPENS a DoS surface rather than
    /// closing one. The handler-parallelism knob is
    /// `Dispatcher.max_concurrent_handlers` (default 8); see its doc comment.
    max_concurrent_streams: u32 = 100,
    /// F11 (`~/CML/20260901-zig-libs-audit/A1/http.md`): when the jobs map
    /// is at `max_concurrent_streams` and a NEW stream arrives, evict the
    /// oldest job that has made no progress at all (no body bytes received,
    /// handler never dispatched) to make room instead of refusing the new
    /// stream outright. Default `false` reproduces today's exact behavior —
    /// a peer that opens `max_concurrent_streams` HEADERS and never sends
    /// another byte occupies every slot on the connection until it closes.
    /// `true` bounds that: a parked, contentless stream is the cheapest
    /// thing on the connection to give up, and RST_STREAM(REFUSED_STREAM)
    /// is exactly the retryable signal §8.7 reserves for streams nothing
    /// was processed on. Streams that have received ANY body byte, or are
    /// already dispatched to a handler, are never evicted by this — they
    /// made progress and freeing them would be strictly more disruptive
    /// than the exhaustion this closes.
    evict_idle_streams_on_capacity: bool = false,
    /// Total request streams allowed on one connection; once reached the
    /// server finishes what is ready and closes with GOAWAY(NO_ERROR).
    max_streams_per_connection: u32 = 10_000,
    /// CVE-2023-44487 (rapid reset): streams reset before completion
    /// (peer RST_STREAMs + server-side error resets) allowed before
    /// GOAWAY(ENHANCE_YOUR_CALM).
    max_reset_streams: u32 = 100,
    /// CVE-2024-27316 (CONTINUATION flood): CONTINUATION frames allowed in
    /// one header sequence before GOAWAY(ENHANCE_YOUR_CALM).
    max_continuation_frames: u32 = 32,
    /// One reassembled HEADERS+CONTINUATION block, total octets; over →
    /// GOAWAY(ENHANCE_YOUR_CALM). (The HPACK decoder's decompression-bomb
    /// guard, `max_header_bytes`, bounds the *decoded* list separately.)
    max_header_block: usize = 1 << 20,
    /// Budget of consecutive no-progress frames (PING/SETTINGS/PRIORITY/
    /// empty DATA/unknown) before GOAWAY(ENHANCE_YOUR_CALM); any new
    /// request stream or productive DATA resets it.
    max_unproductive_frames: u32 = 1024,
};

/// Serve HTTP/2 requests from `in`, responding on `out`, until the peer
/// hangs up, sends GOAWAY (and all its streams finish), or a connection
/// error occurs. The client preface has NOT been consumed — the whole
/// stream from byte 0 (preface + frames) is read here. `out` is flushed
/// after every batch of frames. Never fails: all errors end the connection.
///
/// `in`/`out` are the caller's and this function opens no socket, so a
/// `std.Io` cancelation of a blocking read is *not* recovered here: it
/// arrives as plain `error.ReadFailed` (`std.Io.Reader.Error` is only
/// `{ReadFailed, EndOfStream}` and cannot carry `Canceled`) and simply ends
/// the connection like any other read failure. The real cause survives in
/// the out-of-band `err` field of the concrete reader the caller supplied
/// (`std.Io.net.Stream.Reader.err` / `std.Io.File.Reader.err`), and that is
/// where a caller who must tell a cancelation from a dead peer looks.
/// Reached through `Server.connMain` (`enable_h2c`) the readers handed in
/// are that server's own `TimeoutReader`/`TimeoutWriter`, which do the
/// recovery on the fd they own — nothing extra is needed there.
/// The `Limits` -> `h2.Connection.Options` wiring, factored out of `serve`
/// so a test can assert what the SHIPPED defaults actually become on the
/// protocol core — a limit that never reaches `h2.Connection` bounds
/// nothing, however good its value looks in `Limits`.
fn connOptions(opts: Options) h2.Connection.Options {
    return .{
        .settings = .{
            .enable_push = false, // §8.4: we never push
            .max_concurrent_streams = opts.limits.max_concurrent_streams,
            .max_header_list_size = std.math.cast(u32, opts.max_header_bytes) orelse
                std.math.maxInt(u32),
        },
        .max_header_block = opts.limits.max_header_block,
        .max_continuation_frames = opts.limits.max_continuation_frames,
        .max_reset_streams = opts.limits.max_reset_streams,
        .max_unproductive_frames = opts.limits.max_unproductive_frames,
    };
}

/// Everything in a response head is held to RFC 9113 §8.2.1, and almost all of
/// it is guaranteed before it gets here: header names and values reach the
/// framer through `setHeader`, which rejects CR/LF/NUL at set time and is the
/// only way into the table, and the rest are literals or generated (the date,
/// the content-length digits).
///
/// `server_name` is the exception -- it comes straight from the caller -- so it
/// is checked ONCE, here, where a connection begins, instead of on every field
/// of every response. A value that cannot go on the wire is dropped rather than
/// refused: the header is optional, and a server that will not start because
/// its own banner is malformed helps nobody.
fn checkedOptions(opts: Options) Options {
    var out = opts;
    if (opts.server_name) |name| {
        if (!h1.isValidFieldValue(name)) out.server_name = null;
    }
    return out;
}

pub fn serve(gpa: Allocator, opts: Options, in: *Reader, out: *Writer) void {
    var s: Session = .{
        .gpa = gpa,
        .opts = checkedOptions(opts),
        .in = in,
        .out = out,
        .threaded = opts.dispatcher != null,
        .io = if (opts.dispatcher) |d| d.io else null,
        .conn = .init(gpa, .server, connOptions(opts)),
    };
    defer s.deinit();
    s.run();
}

/// BYO-TLS entry point: serve HTTP/2 on one **already-established**
/// connection — the caller owns the transport (typically a TLS connection
/// whose handshake negotiated ALPN "h2", see `http.protocolFromAlpn`) and
/// hands in its plaintext reader/writer plus the socket peer address.
/// Identical to `serve` with `Options.peer` folded in: the client
/// connection preface (RFC 9113 §3.4) is read from byte 0 — the same wire
/// shape over TLS and h2c — and the function returns when the connection
/// is done (peer hang-up, GOAWAY completed, or a connection error). It
/// never fails; closing the underlying transport afterwards is the
/// caller's job.
///
/// Intended flow (no TLS library required or referenced here):
///
///     // caller's TLS layer: accept, handshake offering http.alpn_offer
///     // negotiated = the ALPN protocol the handshake selected
///     switch (http.protocolFromAlpn(negotiated)) {
///         .h2 => h2_server.serveStream(gpa, tls_reader, tls_writer, peer, .{
///             .handler = my_handler,
///         }),
///         .http11, .unknown => // Server.serveStream — the h1 equivalent
///     }
///
/// See `serve` on why a canceled read reaches here as `error.ReadFailed`
/// and where its real cause is recoverable: the transport is yours.
pub fn serveStream(
    gpa: Allocator,
    in: *Reader,
    out: *Writer,
    peer: ?std.Io.net.IpAddress,
    options: Options,
) void {
    var opts = options;
    opts.peer = peer;
    serve(gpa, opts, in, out);
}

/// One request stream being assembled: HEADERS (+ CONTINUATION) decoded,
/// DATA possibly still streaming in. Owns its header list and body copy.
/// Capture budget for the staged response's trailer section on its way to
/// an h2 trailer HEADERS frame. Generous next to `ResponseWriter`'s own
/// limits (`max_response_trailers` fields, `trailer_decl_bytes` of names),
/// so the writer's caps are what actually bound this, not the buffer.
const trailer_capture_bytes = 4096;

const Job = struct {
    id: u31,
    headers: hpack.HeaderList,
    /// Request trailer section (§8.1): the fields of a second HEADERS frame
    /// on this stream, surfaced to the handler as `Request.trailer`.
    trailers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    /// Consumption cursor into `body` — only the streaming surface moves it
    /// (the buffered one hands the whole slice to the handler at once).
    read_pos: usize = 0,
    /// Received DATA octets whose §6.9 window credit has NOT been returned
    /// yet. Exactly one place decrements it (`grantJob`), so credit can be
    /// returned neither twice nor never, whichever policy applies.
    owed: usize = 0,
    /// END_STREAM seen — the request is complete (body *and* trailers).
    complete: bool = false,
    /// Body crossed `max_body_bytes` (or memory ran out) → 413 + close.
    /// Buffered surface only; the streaming one enforces the cap as it reads.
    over_cap: bool = false,
    /// `Options.stream_request` said yes: dispatch at HEADERS, hand the
    /// handler an incremental body reader, replenish on consumption.
    streaming: bool = false,
    /// The handler is running against this job right now.
    dispatched: bool = false,
    /// The stream died under us while it was being served (peer RST_STREAM,
    /// or a stream-scoped violation we recovered from). The job survives
    /// until the handler returns — `serveJob` holds slices into it — so the
    /// reader and the response framer poll this instead.
    rst: bool = false,

    fn deinit(job: *Job, gpa: Allocator) void {
        job.headers.deinit(gpa);
        if (job.trailers) |*hl| hl.deinit(gpa);
        // The body is the caller's data -- credentials, payloads -- and this
        // block goes back to an allocator the next connection draws from.
        // The whole allocation, not just `items`: a streaming body that was
        // drained (`clearRetainingCapacity`) still has its bytes past `len`.
        // `zeroize`, not `std.crypto.secureZero` -- see `zeroize.zig`.
        zeroize.zeroize(job.body.allocatedSlice());
        job.body.deinit(gpa);
    }

    /// Received but not yet handed to the handler.
    fn unread(job: *const Job) []const u8 {
        return job.body.items[job.read_pos..];
    }
};

const Disposition = enum { keep, close };

const Session = struct {
    gpa: Allocator,
    opts: Options,
    in: *Reader,
    out: *Writer,
    conn: h2.Connection,
    /// Outgoing wire bytes staged by the h2 layer; flushed to `out`.
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,
    /// Request streams in flight, in arrival order (served in that order).
    ///
    /// A job STAYS here while its handler runs — the streaming surfaces need
    /// to keep folding DATA and trailer HEADERS into it, and `pump` runs
    /// re-entrantly from inside the handler. Nothing may therefore hold a
    /// `*Job` across a pump: the map rehashes when a new stream is admitted.
    /// Look up by id, every time.
    jobs: std.AutoArrayHashMapUnmanaged(u31, Job) = .empty,
    req_index: u32 = 0,
    peer_goaway: bool = false,
    /// Streams a handler detached (`ResponseWriter.detach`): response open,
    /// request state already freed, DATA pushed through `Detached` between
    /// pumps. Single-task mode only; the dispatcher path never fills it.
    detached: std.ArrayList(u31) = .empty,
    /// Detached streams the peer has reset, waiting for the embedder to
    /// collect them (`Detached.takeClosed`).
    detached_closed: std.ArrayList(u31) = .empty,

    // ── concurrency (all four are inert without `Options.dispatcher`) ────

    /// **Invariants 1–5.** The one lock over everything reachable from a
    /// worker thread: `conn` (HPACK encoder *and* decoder, both flow-control
    /// windows, the stream table), `wire`, `out`, `events`, `jobs` (the map
    /// *and* every `Job` in it), `req_index`, `peer_goaway`, `inflight`,
    /// `closing`.
    ///
    /// `std.atomic.Mutex` + yield-spin rather than a blocking mutex: Zig
    /// 0.16 std has no `std.Thread.Mutex`/`Condition`/`Futex`, and the
    /// io-less lock that may be held across blocking I/O is already this
    /// module's idiom (`h2_upstream.lockBlocking`, `Client.lockSpin`). No
    /// new synchronisation primitive is invented here.
    ///
    /// **Held across a socket write** (`flushWire`), on purpose: staging a
    /// frame and putting it on the wire in one section is what keeps the
    /// HPACK dynamic table in step with the bytes the peer actually sees
    /// (invariant 1), and it makes `wire` FIFO for every producer
    /// (invariant 2). A write that blocks on TCP backpressure therefore
    /// stalls the connection — which it would anyway, since every reply we
    /// could compute meanwhile would still be unsendable.
    ///
    /// **Deliberately outside the lock:** the handler body (the entire
    /// point), `in.peekGreedy` in `pump` (so a running handler never blocks
    /// the reading side), and `Writer.writeAll` out of `StreamBody`
    /// (it re-enters `Framer`, which locks for itself).
    mu: std.atomic.Mutex = .unlocked,
    /// `opts.dispatcher != null`, hoisted: when false every `lock`/`unlock`
    /// is a no-op and the sequential path is exactly what it always was.
    threaded: bool = false,
    /// Handlers dispatched and not yet retired on THIS connection.
    inflight: u32 = 0,
    /// A worker returned `.close`: stop dispatching and end the connection
    /// once the last handler is off it.
    closing: bool = false,
    /// The connection task has left `run` and is waiting for handlers to
    /// drain. Read without the lock by the two wait loops, which must not
    /// keep waiting for a peer nobody is reading from any more.
    gone: std.atomic.Value(bool) = .init(false),

    // ── the parking variant (`Dispatcher.io` set; inert otherwise) ───────
    //
    // Same scheme as above with blocking primitives in place of the spins:
    // `io_mu` stands in for `mu` (the same invariants 1–5, the same holders),
    // and `moved` is broadcast whenever something a waiter may be waiting
    // for has happened — `pump` processed a batch of frames, a handler
    // retired, the connection task left. Its counter `progress` is what makes
    // a wait immune to the lost wakeup: a waiter samples it under the lock
    // when it decides to wait, and sleeps only while it is unchanged.

    /// `Dispatcher.io`, hoisted.
    io: ?std.Io = null,
    io_mu: std.Io.Mutex = .init,
    moved: std.Io.Condition = .init,
    /// Bumped (under the lock) together with every `moved` broadcast.
    progress: u32 = 0,

    /// Take `mu` (no-op on the sequential path). Yield-spin: this lock is
    /// held across blocking writes, so a plain `spinLoopHint` spin could
    /// starve the holder on a busy core — same reasoning, same shape as
    /// `h2_upstream.lockBlocking`. With `Dispatcher.io` a contended lock
    /// parks instead (`io_mu`), which is what fibers of one thread need.
    fn lock(s: *Session) void {
        if (!s.threaded) return;
        if (s.io) |io| return s.io_mu.lockUncancelable(io);
        while (!s.mu.tryLock()) std.Thread.yield() catch std.atomic.spinLoopHint();
    }

    fn unlock(s: *Session) void {
        if (!s.threaded) return;
        if (s.io) |io| return s.io_mu.unlock(io);
        s.mu.unlock();
    }

    /// Tell every parked waiter that the connection moved. **Caller holds
    /// the lock.** No-op unless `Dispatcher.io` is set.
    fn announce(s: *Session) void {
        const io = s.io orelse return;
        s.progress +%= 1;
        s.moved.broadcast(io);
    }

    /// Wait for the connection task to make progress (a WINDOW_UPDATE, more
    /// DATA). **Must not be called holding `mu`.** `seen` is `s.progress` as
    /// the caller read it under the lock when it found it had to wait.
    ///
    /// Sequential: there is no other task, so the caller pumps the
    /// connection itself — unchanged behavior. Threaded: only the connection
    /// task may touch `in`, so a worker yields and re-checks; `gone` is what
    /// stops it waiting forever once nobody is reading any more. With
    /// `Dispatcher.io` it parks until `progress` moves past `seen` — if it
    /// already has, it returns at once, so a WINDOW_UPDATE processed between
    /// the caller's unlock and this call is not slept through.
    ///
    /// Only a handler waits here, and with `Dispatcher.io` the park is a
    /// cancelation point of that handler's `Io`: `error.Canceled` when the
    /// embedder cancels it (a handler deadline), so a handler stuck on a peer
    /// that never grants credit or never sends the body is released. The
    /// lock itself stays uncancelable -- it is only ever held briefly.
    fn waitForPeer(s: *Session, seen: u32) error{ Closed, Canceled }!void {
        if (!s.threaded) return s.pump();
        if (s.io) |io| {
            s.io_mu.lockUncancelable(io);
            defer s.io_mu.unlock(io);
            while (s.progress == seen and !s.gone.load(.acquire))
                try s.moved.wait(io, &s.io_mu);
        }
        if (s.gone.load(.acquire)) return error.Closed;
        if (s.io == null) std.Thread.yield() catch std.atomic.spinLoopHint();
    }

    fn deinit(s: *Session) void {
        for (s.jobs.values()) |*job| job.deinit(s.gpa);
        s.jobs.deinit(s.gpa);
        s.events.deinit(s.gpa); // always drained by processEvents
        s.wire.deinit(s.gpa);
        s.detached.deinit(s.gpa);
        s.detached_closed.deinit(s.gpa);
        s.conn.deinit();
    }

    fn fireConnState(s: *Session, state: Server.ConnState) void {
        if (s.opts.on_conn_state) |hook| hook(s.opts.on_conn_state_ctx, s.opts.peer, state);
    }

    fn run(s: *Session) void {
        s.fireConnState(.new);
        defer s.fireConnState(.closed);
        // Declared before the worker-drain defer so it runs AFTER it (LIFO):
        // by then nothing can still be staging, and a response staged by the
        // last round must not die with the session.
        defer {
            s.lock();
            s.flushWire() catch {};
            s.unlock();
        }
        // Threaded: no worker may still be holding a `*Job`, the `wire` or
        // the socket writer when `deinit` frees them. `gone` first, so a
        // worker parked in `waitForPeer` stops waiting for a connection task
        // that has left.
        defer if (s.threaded) {
            s.gone.store(true, .release);
            if (s.io) |io| {
                s.io_mu.lockUncancelable(io);
                defer s.io_mu.unlock(io);
                s.announce(); // wakes workers parked in `waitForPeer`
                while (s.inflight != 0) s.moved.waitUncancelable(io, &s.io_mu);
            } else while (true) {
                s.lock();
                const busy = s.inflight != 0;
                s.unlock();
                if (!busy) break;
                std.Thread.yield() catch std.atomic.spinLoopHint();
            }
        };
        // §3.4 server preface: our SETTINGS, before anything else.
        s.conn.sendPreface(&s.wire) catch return;
        s.flushWire() catch return;
        while (true) {
            if (s.threaded) {
                s.lock();
                s.dispatchReady();
                const done = s.closing and s.inflight == 0;
                s.unlock();
                if (done) return;
            } else while (s.takeReady()) |id| {
                s.fireConnState(.active);
                const disp = s.serveJob(id, s.req_index);
                s.finishJob(id, disp);
                s.req_index += 1;
                s.fireConnState(.idle);
                if (disp == .close) return;
            }
            s.lock();
            // Total-streams cap: enough streams for one connection — what
            // was ready has been served; close gracefully (NO_ERROR) so a
            // legitimate client just reconnects.
            const over_total =
                s.conn.remote_streams_total >= s.opts.limits.max_streams_per_connection and
                s.inflight == 0;
            if (over_total) {
                s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
                s.flushWire() catch {};
            }
            // Graceful shutdown: the peer said GOAWAY and nothing is left.
            // A GOAWAY forbids NEW streams; a live detached stream is an
            // existing one and keeps the connection open (§6.8).
            const drained = s.peer_goaway and s.jobs.count() == 0 and
                s.detached.items.len == 0;
            s.unlock();
            if (over_total or drained) return;
            // The embedder's turn, before the loop blocks on the peer: with
            // detached streams live (or their resets unreported) the next
            // bytes may have to ORIGINATE here rather than answer anything.
            if (!s.threaded and
                s.detached.items.len + s.detached_closed.items.len != 0)
            {
                if (s.opts.on_detached_idle) |hook| {
                    switch (hook(s.opts.on_detached_idle_ctx, .{ .s = s })) {
                        .proceed => {},
                        .close => {
                            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
                            s.flushWire() catch {};
                            return;
                        },
                    }
                }
            }
            s.pump() catch return;
        }
    }

    /// Hand every ready-and-undispatched stream to `Options.dispatcher`, up
    /// to the per-connection cap. **Caller holds `mu`.**
    ///
    /// Called from two places, and it needs both: the connection task's loop
    /// (a stream became ready because bytes arrived) and the tail of every
    /// worker task (a slot freed). Without the second, a stream held back by
    /// the cap would wait for the *next wire event* to be dispatched, which
    /// on an idle connection never comes.
    fn dispatchReady(s: *Session) void {
        const d = s.opts.dispatcher orelse return;
        // ⚠ Why the per-connection cap DEFERS while a full pool REFUSES, and
        // why that is not an inconsistency to "fix".
        //
        // The owner ruling is "when the pool is full, refuse — do not queue".
        // What that rules out is **unbounded** queueing: work piling up behind
        // a saturated pool across every connection in the fleet, which is the
        // shape that turns a load spike into an outage. `spawn` returning
        // false is exactly that case, and `refuse` answers it below.
        //
        // A stream held back by THIS loop's condition is a different thing. It
        // is not queued anywhere new — it stays in `jobs`, which
        // `Limits.max_concurrent_streams` already bounds (100 by default), and
        // it waits precisely as every stream waits on today's sequential
        // engine. Refusing at the cap instead would cut a client's usable
        // parallelism on one connection from the 100 we advertise in our own
        // SETTINGS to 8, i.e. it would answer a DoS question by breaking
        // ordinary multiplexed traffic. So: bounded wait here, refusal there.
        while (!s.closing and s.inflight < d.max_concurrent_handlers) {
            // Ruling #1: only a stream whose HEADERS block is complete and
            // admitted is here at all — nothing half-decoded reaches a thread.
            const id = s.takeReadyUndispatched() orelse return;
            const job = s.jobs.getPtr(id).?;
            job.dispatched = true;
            const h = s.gpa.create(Handoff) catch {
                // Cannot even describe the work: shed the stream, keep the
                // connection (same policy as `onHeaders`' allocation failure).
                s.refuse(id);
                continue;
            };
            h.* = .{ .s = s, .id = id, .req_index = s.req_index };
            s.req_index += 1;
            s.inflight += 1;
            if (d.spawn(d.ctx, .{ .func = Handoff.entry, .ctx = h })) continue;
            // Ruling #4: the pool is full ⇒ refuse, never queue.
            s.inflight -= 1;
            s.gpa.destroy(h);
            s.refuse(id);
        }
    }

    /// RST_STREAM(REFUSED_STREAM) + drop the state. **Caller holds `mu`.**
    fn refuse(s: *Session, id: u31) void {
        // Marked dispatched by `dispatchReady` a moment ago and never handed
        // to a thread, so nothing holds it (see `removeJob`'s assertion).
        if (s.jobs.getPtr(id)) |job| job.dispatched = false;
        s.conn.sendRstStream(&s.wire, id, .refused_stream) catch {};
        s.removeJob(id);
        s.flushWire() catch {};
    }

    /// One dispatched stream's ticket. Heap-allocated because it outlives
    /// `dispatchReady`'s frame; freed by the worker that runs it.
    const Handoff = struct {
        s: *Session,
        id: u31,
        req_index: u32,

        fn entry(ctx: *anyopaque) void {
            const h: *Handoff = @ptrCast(@alignCast(ctx));
            const s = h.s;
            const id = h.id;
            s.fireConnState(.active);
            const disp = s.serveJob(id, h.req_index);
            // Everything that touches `s` outside the lock happens BEFORE
            // `inflight` drops: the connection task's drain in `run` treats
            // `inflight == 0` as "the Session may now be destroyed", and it
            // can only observe that after the `unlock` below.
            s.gpa.destroy(h);
            s.fireConnState(.idle);
            s.lock();
            s.finishJob(id, disp);
            if (disp == .close) s.closing = true;
            s.inflight -= 1;
            s.announce(); // the drain in `run` waits for `inflight == 0`
            // A slot just freed: pull the next ready stream in now rather
            // than at the next wire event (see `dispatchReady`).
            s.dispatchReady();
            s.unlock();
        }
    };

    /// How much may sit staged in `wire` before `stageWire` spills it into
    /// the socket writer's buffer. A whole round of small responses fits,
    /// which is the point; the cap exists so a large one cannot grow the
    /// staging buffer without bound.
    const wire_flush_threshold = 8 * 1024;

    /// Hot-path counterpart to `flushWire`: stage the frames and let them
    /// leave together.
    ///
    /// A multiplexed protocol whose responses each take their own socket
    /// write throws away most of what multiplexing is for. Measured against
    /// `hyper` on the same box, one 112-byte answer per stream: it wrote 0.16
    /// times per request where this server wrote 2.04 -- a 13-byte HEADERS
    /// frame and a 26-byte DATA frame, each its own `sendmsg`, per response,
    /// with nothing coalesced across the eight streams in flight. Two
    /// microseconds of kernel transition to move thirteen bytes.
    ///
    /// **Who flushes, and why it differs by mode.** Without a dispatcher the
    /// task that stages a response is the task that will next reach `pump`,
    /// and `pump` flushes before it blocks, so staging is safe and the whole
    /// ready round leaves in one write. With one, a worker may finish a
    /// response while the connection task is *already* blocked in that read;
    /// nothing would then push the bytes out until the peer sent something
    /// unprompted, which for a peer waiting on this very response is never.
    /// So a worker flushes immediately and only the single-task path
    /// accumulates.
    fn stageWire(s: *Session) Writer.Error!void {
        if (s.threaded) return s.flushWire();
        if (s.wire.items.len >= wire_flush_threshold) return s.spillWire();
    }

    /// Move staged wire bytes into the socket writer's own buffering without
    /// forcing them onto the wire. Bounding `wire` needs only the move --
    /// `out` is a buffered writer (over TLS, one that builds whole records in
    /// the connection's ciphertext buffer), and bytes that are waiting for
    /// more company belong in it, not on the network. Flushing the socket
    /// here as well is what `stageWire` used to do, and it put a response
    /// larger than the threshold on the wire one threshold-sized piece per
    /// send -- each send a full pass through the TCP stack -- while the
    /// single-task pump was going to flush before blocking anyway.
    fn spillWire(s: *Session) Writer.Error!void {
        if (s.wire.items.len == 0) return;
        try s.out.writeAll(s.wire.items);
        s.wire.clearRetainingCapacity();
    }

    /// Flush staged wire bytes through the (timeout-guarded) socket writer.
    /// `out` is flushed even with nothing staged: `stageWire` spills without
    /// flushing, so bytes can sit in `out`'s buffer while `wire` is empty --
    /// and every caller of this function is about to block on (or hand the
    /// connection back to) a peer who may be waiting on exactly those bytes.
    /// On an empty buffer the flush is a no-op, not a syscall.
    fn flushWire(s: *Session) Writer.Error!void {
        try s.spillWire();
        try s.out.flush();
    }

    /// Block for at least one byte, feed everything buffered to the h2
    /// state machine, dispatch events and flush auto-replies (SETTINGS/PING
    /// ACKs, WINDOW_UPDATEs). Stream-scoped violations answer RST_STREAM
    /// and processing continues (§5.4.2); connection-scoped ones answer
    /// GOAWAY with the layer's code and close (§5.4.1).
    /// Threaded: called **only** by the connection task (a worker waits in
    /// `waitForPeer` instead), and the blocking read deliberately happens
    /// with `mu` released — that is what keeps PING/SETTINGS/WINDOW_UPDATE
    /// flowing while handlers run.
    fn pump(s: *Session) error{Closed}!void {
        // Anything `stageWire` left staged goes out BEFORE the blocking read.
        // This is the half that makes staging safe: the peer never waits on
        // bytes that are sitting in `wire` while we wait on the peer.
        {
            s.lock();
            defer s.unlock();
            s.flushWire() catch return error.Closed;
        }
        _ = s.in.peekGreedy(1) catch return error.Closed; // EOF/timeout/reset
        s.lock();
        defer s.unlock();
        // Runs before the unlock: whatever this batch carried (credit, DATA,
        // a reset) is visible to a woken worker the moment it holds the lock.
        defer s.announce();
        const bytes = s.in.buffered();
        var chunk: []const u8 = bytes;
        s.in.toss(bytes.len);
        while (true) {
            const res = s.conn.recv(chunk, &s.wire, &s.events);
            chunk = ""; // continuation rounds only drain the internal buffer
            s.processEvents();
            s.flushWire() catch return error.Closed;
            if (res) |_| {
                return;
            } else |_| {
                if (s.conn.recoverStreamError()) |v| {
                    h2.encodeRstStream(s.gpa, &s.wire, v.stream_id, v.code) catch
                        return error.Closed;
                    s.dropJob(v.stream_id);
                    s.flushWire() catch return error.Closed;
                    continue; // drain frames buffered behind the bad one
                }
                if (s.conn.violation) |v| {
                    s.conn.sendGoaway(&s.wire, v.code, "") catch {};
                    s.flushWire() catch {};
                }
                return error.Closed; // connection error (or OOM): done
            }
        }
    }

    fn processEvents(s: *Session) void {
        for (s.events.items) |*ev| switch (ev.*) {
            .headers => |*hd| s.onHeaders(hd),
            .data => |d| s.onData(d),
            .stream_reset => |r| {
                s.dropJob(r.stream_id);
                s.detachedReset(r.stream_id);
            },
            .goaway => s.peer_goaway = true,
            // SETTINGS/PING are acknowledged by the layer; WINDOW_UPDATE
            // already raised the send windows; PRIORITY is advisory.
            else => {},
        };
        s.events.clearRetainingCapacity();
    }

    fn onHeaders(s: *Session, hd: *@FieldType(h2.Event, "headers")) void {
        if (s.jobs.getPtr(hd.stream_id)) |job| {
            // A second HEADERS on a live stream is the request trailer
            // section (§8.1); END_STREAM completes the request either way.
            //
            // A trailer block carrying pseudo-header fields is malformed by
            // that same section — and `:method`/`:path`/`:authority`
            // arriving *after* the handler-visible request was built is a
            // routing-override primitive — so it is dropped rather than
            // surfaced. (Dropping, not resetting: it stays byte-compatible
            // with the previous behavior and cannot be used to kill a
            // stream the handler is already working on.)
            //
            // The same drop covers a trailer field that fails §8.2.1: the
            // block is re-serialized into `Request.trailer`'s CRLF form
            // exactly as the request headers are, so a CR/LF in a trailer
            // value is the same injection primitive one stage later.
            if (job.trailers == null and trailerBlockIsValid(hd.headers)) {
                job.trailers = hd.headers; // ownership moves into the job
            } else hd.headers.deinit(s.gpa);
            if (hd.end_stream) job.complete = true;
            return;
        }
        // Enforce our advertised SETTINGS_MAX_CONCURRENT_STREAMS (§5.1.2):
        // excess streams are refused — REFUSED_STREAM is safely retryable
        // (§8.7) — and the connection keeps serving the admitted ones. This
        // also caps in-flight request state (the jobs map): a peer cannot
        // force unbounded buffered streams awaiting the handler.
        if (s.jobs.count() >= s.opts.limits.max_concurrent_streams) {
            // F11: try to evict an idle, no-progress job to make room before
            // refusing the new stream outright (opt-in, see the field doc).
            if (!s.opts.limits.evict_idle_streams_on_capacity or !s.evictIdleJob()) {
                hd.headers.deinit(s.gpa);
                s.conn.sendRstStream(&s.wire, hd.stream_id, .refused_stream) catch {};
                return;
            }
        }
        // The incremental-request opt-in is decided HERE and only here —
        // the one moment at which "buffer the body first" and "run the
        // handler now" are still both possible.
        const streaming = if (s.opts.stream_request) |pred|
            pred(s.opts.context, .{ .fields = hd.headers.fields })
        else
            false;
        s.jobs.put(s.gpa, hd.stream_id, .{
            .id = hd.stream_id,
            .headers = hd.headers, // ownership moves into the job
            .complete = hd.end_stream,
            .streaming = streaming,
        }) catch {
            // Overloaded: shed the stream, keep the connection (same
            // policy as the h1 loop's allocation failures).
            hd.headers.deinit(s.gpa);
            s.conn.sendRstStream(&s.wire, hd.stream_id, .refused_stream) catch {};
        };
    }

    /// ## Where the receive window is replenished, and why it is two answers
    ///
    /// One principle: **credit goes back when the octet stops constraining
    /// us**. What that means depends on which surface the stream is on, and
    /// the two answers are not a drift — either one applied to the other
    /// surface is a bug.
    ///
    /// *Buffered* (the default): the handler cannot start until END_STREAM,
    /// so nobody can consume an octet before the last one arrives. Waiting
    /// for consumption would deadlock every upload larger than the 64 KiB
    /// initial window — we would be withholding the credit the peer needs
    /// to send the END_STREAM we are waiting for. The credit is therefore
    /// returned on ARRIVAL, which is honest here precisely because a
    /// separate, explicit bound already governs the memory: `max_body_bytes`
    /// (over it → 413), not the window.
    ///
    /// *Streaming* (`Options.stream_request`): the handler is already
    /// running and reading, so there is no such deadlock — and there is
    /// also no `max_body_bytes`-shaped memory bound, because the whole point
    /// is not to hold the body. The window becomes the bound, so credit is
    /// owed on CONSUMPTION (`grantConsumed`, from the body reader). This is
    /// the identical conclusion `h2_client.readBody` argues at length and
    /// for the identical reason: an octet sitting unread in our buffer is
    /// still occupying us, and re-advertising it on arrival makes the buffer
    /// rather than the window the only limit. Unread octets therefore cannot
    /// exceed the advertised window — 64 KiB per stream by default — no
    /// matter how slowly the handler reads.
    ///
    /// Two corollaries, both shared with the client: octets we DISCARD
    /// (unknown, reset or finished stream) are credited immediately, or the
    /// connection window leaks shut permanently (§6.9.1); and the
    /// stream-level grant is skipped once the stream has ended, where more
    /// credit would be dead weight.
    fn onData(s: *Session, d: @FieldType(h2.Event, "data")) void {
        const job = s.jobs.getPtr(d.stream_id) orelse {
            // Not ours to hold — a stream we reset, refused or already
            // finished. §6.9.1: account for it now or the shared window
            // shrinks by that much for the rest of the connection.
            s.grant(0, d.data.len);
            s.flushWire() catch {};
            return;
        };
        job.owed += d.data.len;
        if (d.end_stream) job.complete = true;
        if (job.streaming) {
            // Consumption-driven: `grantConsumed` returns this credit when
            // the handler actually takes the octets.
            job.body.appendSlice(s.gpa, d.data) catch {
                // Overloaded. The window has not been re-advertised, so
                // dropping is safe accounting-wise; fail the read instead of
                // silently truncating the body.
                job.rst = true;
            };
            return;
        }
        // Arrival-driven (see above). Padding octets are charged by the
        // layer but not visible here; padded uploads shrink the window
        // slightly.
        s.grantJob(d.stream_id, d.data.len);
        if (job.over_cap or job.dispatched) return; // shedding / already handed over
        if (s.opts.max_body_bytes) |max| {
            // A1 http F2: this used to compare only `job`'s OWN bytes to
            // `max`, so the cap was per-STREAM — with
            // `Limits.max_concurrent_streams` buffered bodies live on one
            // connection at once, a single h2c connection could hold
            // `max_concurrent_streams * max_body_bytes` (150 MB at the
            // shipped defaults of 100 streams × 1 MiB), against an h1
            // connection's single ~46 KiB slab for the SAME `max_body_bytes`
            // value. Checking the CONNECTION-WIDE total instead restores
            // the doc's claim that this one number bounds memory the same
            // way on both protocols. Subsumes the old per-job comparison
            // (the total can only be >= any one job's own bytes), so that
            // check is gone rather than kept alongside a stricter one.
            if (s.totalBufferedBodyBytes() + d.data.len > max) {
                job.over_cap = true;
                return;
            }
        }
        job.body.appendSlice(s.gpa, d.data) catch {
            job.over_cap = true; // overloaded: shed like an over-limit body
        };
    }

    /// Sum of buffered (non-streaming) request-body bytes across every job
    /// on this connection right now (A1 http F2) — computed fresh rather
    /// than kept as a running counter, because a `Job` leaves `s.jobs`
    /// through several paths (served to completion, evicted for capacity,
    /// reset-and-reaped) and a counter would need every one of them to
    /// remember to decrement it by exactly the right amount; summing the
    /// buffers themselves cannot drift. `Limits.max_concurrent_streams`
    /// bounds how many jobs there ever are (100 by default), so this is
    /// cheap relative to the DATA frame that triggers it.
    fn totalBufferedBodyBytes(s: *const Session) usize {
        var total: usize = 0;
        for (s.jobs.values()) |*job| {
            if (!job.streaming) total += job.body.items.len;
        }
        return total;
    }

    /// Return `n` octets of `id`'s outstanding credit (§6.9): the connection
    /// window always, the stream window only while the stream can still
    /// receive. The single place `Job.owed` shrinks.
    fn grantJob(s: *Session, id: u31, n: usize) void {
        if (n == 0) return;
        const job = s.jobs.getPtr(id) orelse {
            s.grant(0, n);
            s.flushWire() catch {};
            return;
        };
        const take = @min(n, job.owed);
        if (take == 0) return;
        job.owed -= take;
        const stream_open = !job.complete and !job.rst;
        s.grant(0, take);
        if (stream_open) s.grant(id, take);
        s.stageWire() catch {};
    }

    /// Stage WINDOW_UPDATE(s) worth `n` octets for `id` (0 = connection).
    /// Split so a single grant larger than 2^31-1 cannot be mis-encoded.
    fn grant(s: *Session, id: u31, n: usize) void {
        var left = n;
        while (left != 0) {
            const inc: u31 = @intCast(@min(left, @as(usize, h2.max_window_size)));
            s.conn.sendWindowUpdate(&s.wire, id, inc) catch return;
            left -= inc;
        }
    }

    /// Next request ready for the handler, in stream-arrival order. Over-cap
    /// streams are "ready" too — they answer 413 immediately — and a
    /// streaming stream is ready the moment its headers are in, which is the
    /// whole difference between the two surfaces.
    fn takeReady(s: *Session) ?u31 {
        for (s.jobs.keys()) |id| {
            const job = s.jobs.getPtr(id).?;
            if (job.streaming or job.complete or job.over_cap) return id;
        }
        return null;
    }

    /// `takeReady`, skipping streams already handed to a worker — the
    /// threaded path's selector. **Caller holds `mu`.**
    fn takeReadyUndispatched(s: *Session) ?u31 {
        for (s.jobs.keys()) |id| {
            const job = s.jobs.getPtr(id).?;
            if (job.dispatched) continue;
            if (job.streaming or job.complete or job.over_cap) return id;
        }
        return null;
    }

    /// The stream is gone (peer RST_STREAM, or our own stream-scoped
    /// recovery). Frees the job — unless its handler is running, in which
    /// case `serveJob` holds slices into it and only a flag may be set.
    ///
    /// **Invariant 4.** This used to hang on a single `serving` slot, which
    /// is the shape of "one handler at a time" written into the data model:
    /// with N handlers in flight there is no single current stream, so the
    /// question "may I free this job?" is answered by the job itself.
    /// `dispatched` is set under `mu` before the worker is spawned, so there
    /// is no window in which a job is on its way to a thread and still
    /// looks free.
    fn dropJob(s: *Session, id: u31) void {
        if (s.jobs.getPtr(id)) |job| {
            if (job.dispatched) {
                job.rst = true;
                return;
            }
        }
        s.removeJob(id);
    }

    /// A peer reset landed on a detached stream: retire it and queue the id
    /// for the embedder (`Detached.takeClosed`). No-op for everything else.
    fn detachedReset(s: *Session, id: u31) void {
        for (s.detached.items, 0..) |sid, i| {
            if (sid != id) continue;
            _ = s.detached.swapRemove(i);
            // Report best-effort: if the append fails the embedder still
            // finds out at its next push (`error.StreamGone`).
            s.detached_closed.append(s.gpa, id) catch {};
            return;
        }
    }

    /// Take stream `id` out of the request lifecycle with its response left
    /// open — the second half of `ResponseWriter.detach`. Returns false when
    /// the stream cannot be detached (request not fully arrived, response
    /// head never flushed, stream already dead), in which case the caller
    /// finishes the response normally.
    fn detachJob(s: *Session, f: *Framer, rw: *Server.ResponseWriter, id: u31) bool {
        // Only a fully-arrived request can leave its stream open: h2 has no
        // half-close of the peer's sending direction short of RST_STREAM,
        // which would kill the response with it.
        {
            const job = s.jobs.getPtr(id) orelse return false;
            if (!job.complete or job.rst) return false;
        }
        // Everything the handler wrote — head included — must reach the
        // wire now: nothing may stay held for an END_STREAM that is not
        // coming, and the framer's memory dies with `serveJob`'s frame.
        rw.flush() catch return false;
        if (f.dead) return false;
        // A response that never produced a byte never produced a head
        // either; there is nothing on the wire to keep open.
        if (!f.headers_sent) return false;
        s.detached.append(s.gpa, id) catch return false;
        if (s.jobs.getPtr(id)) |job| job.dispatched = false;
        s.removeJob(id);
        return true;
    }

    /// **Invariant 4, enforced rather than assumed.** `serveJob` keeps
    /// slices into the job (`Request.path`/`.target`, the decoded field
    /// list, the buffered body) alive for the whole handler call, so freeing
    /// a job whose handler is still running is a use-after-free whose
    /// symptom is *silence* — measured: with `dropJob`'s guard deleted the
    /// entire `http` suite still passed. The assertion is what makes that
    /// mistake loud. Callers legitimately retiring a dispatched job clear
    /// the flag first (`finishJob`, `refuse`).
    fn removeJob(s: *Session, id: u31) void {
        if (s.jobs.fetchOrderedRemove(id)) |kv| {
            var job = kv.value;
            std.debug.assert(!job.dispatched);
            // Everything received and never credited back is being thrown
            // away now; the connection window is owed it (§6.9.1). The
            // stream window is moot — the stream is gone.
            //
            // The guard is load-bearing, not tidiness. This flushed
            // unconditionally, and retiring a job is the last thing that
            // happens to every response — so a GET, which owes nothing and
            // stages nothing here, still had its response written out on its
            // own. It was 400 of the 416 socket writes on a 400-request run,
            // i.e. the entire reason responses never coalesced with each
            // other. With nothing owed there is nothing to say, and what IS
            // owed can travel with the rest: `pump` flushes before it blocks.
            if (job.owed != 0) {
                s.grant(0, job.owed);
                s.stageWire() catch {};
            }
            job.deinit(s.gpa);
        }
    }

    /// F11 (`~/CML/20260901-zig-libs-audit/A1/http.md`, opt-in via
    /// `Limits.evict_idle_streams_on_capacity`): find the OLDEST job that
    /// has made no progress at all — no body bytes received, handler never
    /// dispatched, not yet complete — and evict it: RST_STREAM
    /// (REFUSED_STREAM), safe to retry because nothing was processed
    /// (§8.7), then `removeJob` to free the slot and return its receive
    /// window credit. `s.jobs` is an `AutoArrayHashMapUnmanaged`, so
    /// `.keys()` is admission order: the first match is the longest-parked
    /// one. Returns whether a slot was freed.
    fn evictIdleJob(s: *Session) bool {
        for (s.jobs.keys()) |id| {
            const job = s.jobs.getPtr(id).?;
            if (job.dispatched or job.complete or job.body.items.len != 0) continue;
            s.conn.sendRstStream(&s.wire, id, .refused_stream) catch {};
            s.removeJob(id);
            return true;
        }
        return false;
    }

    /// Retire a served stream. A streaming handler may well have answered
    /// without reading the request to its end; §8.1 says to tell the peer so
    /// with RST_STREAM(NO_ERROR) — explicitly *not* an error — rather than
    /// leaving it uploading into a stream nobody is listening to. That, plus
    /// `removeJob` handing the unread octets' credit back, is what keeps a
    /// handler which never reads the body from wedging the connection.
    fn finishJob(s: *Session, id: u31, disp: Disposition) void {
        if (s.jobs.getPtr(id)) |job| {
            if (disp != .close and !job.complete and !job.rst and !job.over_cap) {
                s.conn.sendRstStream(&s.wire, id, .no_error) catch {};
                s.flushWire() catch {};
            }
            // The handler has returned: nothing points into the job any more.
            job.dispatched = false;
        }
        s.removeJob(id);
    }

    /// Map one request stream onto the shared handler types, run the
    /// handler, and re-frame its HTTP/1.1 response as h2 frames.
    ///
    /// `id` rather than a `*Job`: the job stays in `s.jobs` for the whole
    /// call (see the field's doc) and every pump can rehash the map, so the
    /// pointer is re-derived at each use and never held.
    /// Threaded: this whole function runs on a **worker** thread. It holds
    /// `mu` only in the short sections that touch the session; the handler
    /// call itself is the point of the exercise and runs without it.
    fn serveJob(s: *Session, id: u31, req_index: u32) Disposition {
        s.lock();
        const job = s.jobs.getPtr(id).?;
        job.dispatched = true;
        const streaming = job.streaming;
        // The decoded header list is a heap slice: rehashing moves the `Job`
        // struct and never these bytes, and the job outlives this call
        // (`dropJob` may only flag a dispatched job, never free it) — so it
        // survives the unlock below. **Invariant 5**: the `*Job` itself does
        // not, and is re-derived under `mu` at every later use.
        const req_headers = job.headers;
        const over_cap = job.over_cap;
        // Buffered surface only: the whole body is already in, and nothing
        // appends to a dispatched buffered job (`onData` guards on it), so
        // this slice is stable for the handler's lifetime.
        const buffered_body: []const u8 = if (streaming) "" else job.body.items;
        s.unlock();

        if (over_cap) {
            // h1 parity: over-limit body → 413, connection closes (the
            // rest of the body is unbounded — never drain it).
            _ = s.respondError(id, 413);
            s.lock();
            defer s.unlock();
            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
            s.flushWire() catch {};
            return .close;
        }

        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // ── §8.3 pseudo-headers + §8.2 header validity ──────────────────
        //
        // Every field is held to §8.2.1 HERE, before anything below reads
        // it, because of what happens below: the decoded fields are
        // re-serialized into a CRLF block for `Request.header`/
        // `iterateHeaders`, and `:path` becomes `req.path` for the handler
        // and for whatever the handler forwards it to. A value with a CR/LF
        // in it would come out of that block as a header the peer never
        // legally sent; a `:path` with one would come out of a reverse
        // proxy's request line as a SECOND request (measured end to end
        // through `proxy.ProxyHandler`, 2026-09-04). HPACK frames each
        // field by length, so nothing on the h2 wire stops those bytes —
        // the check is the whole defence, and it is the same predicate set
        // the h1 parser applies to its own wire (`h1.isToken`,
        // `h1.isValidFieldValue`, `h1.isValidRequestTarget`, `h1.isValidHost`).
        var method_tok: ?[]const u8 = null;
        var path_full: ?[]const u8 = null;
        var scheme: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var content_length: ?u64 = null;
        var pseudo_done = false;
        var malformed = false;
        for (req_headers.fields) |f| {
            if (f.name.len == 0) {
                malformed = true;
                break;
            }
            if (f.name[0] == ':') {
                if (pseudo_done) {
                    malformed = true; // §8.3: pseudo-header after a regular one
                    break;
                }
                const put: *?[]const u8 = if (std.mem.eql(u8, f.name, ":method"))
                    &method_tok
                else if (std.mem.eql(u8, f.name, ":path"))
                    &path_full
                else if (std.mem.eql(u8, f.name, ":scheme"))
                    &scheme
                else if (std.mem.eql(u8, f.name, ":authority"))
                    &authority
                else {
                    malformed = true; // unknown/response pseudo-header (§8.3)
                    break;
                };
                if (put.* != null) { // §8.3: no duplicates
                    malformed = true;
                    break;
                }
                put.* = f.value;
            } else {
                pseudo_done = true;
                // §8.2.1: a regular field name is a lowercase token, its
                // value carries no CR/LF/NUL/control byte and does not
                // start or end with whitespace.
                if (!regularFieldIsValid(f)) malformed = true;
                // §8.2.2: connection-specific headers are malformed;
                // `te` is allowed only as exactly "trailers".
                if (isConnectionSpecific(f.name)) malformed = true;
                if (std.mem.eql(u8, f.name, "te") and
                    !std.mem.eql(u8, f.value, "trailers")) malformed = true;
                // §8.3.1: `host` beside `:authority` must name the same
                // thing; alone, it plays `:authority`'s part (it is what an
                // h1→h2 intermediary forwards). Either way it is checked as
                // a Host (h1 answers a bad one 400) and written into the
                // synthesized block exactly once, from `authority`.
                if (std.mem.eql(u8, f.name, "host")) {
                    if (!h1.isValidHost(f.value)) {
                        malformed = true;
                    } else if (authority) |a| {
                        if (!std.ascii.eqlIgnoreCase(a, f.value)) malformed = true;
                    } else authority = f.value;
                }
                if (std.mem.eql(u8, f.name, "content-length")) {
                    // Strict 1*DIGIT, matching the h1 parser: `parseInt`
                    // would accept `+5` and `1_0`, and §8.1.1 makes a
                    // duplicate with a different value malformed too.
                    if (h1.parseContentLengthStrict(f.value)) |n| {
                        if (content_length) |prev| {
                            if (prev != n) malformed = true;
                        } else content_length = n;
                    } else |_| malformed = true;
                }
                if (malformed) break;
            }
        }
        if (method_tok == null) malformed = true;
        // The pseudo-header VALUES, to the rule the h1 request line applies
        // to the same things: the method is a token, the target is a URI
        // (ASCII, no whitespace, no control byte), the authority is a Host.
        // `:scheme` is checked as a token — a superset of RFC 3986's scheme
        // grammar that still excludes every byte that could split a line.
        if (method_tok) |m| if (!h1.isToken(m)) {
            malformed = true;
        };
        if (path_full) |p| if (!h1.isValidRequestTarget(p)) {
            malformed = true;
        };
        if (scheme) |sc| if (!h1.isToken(sc)) {
            malformed = true;
        };
        if (authority) |a| if (!h1.isValidHost(a)) {
            malformed = true;
        };
        // §8.1.1: a malformed request is a STREAM ERROR of type
        // PROTOCOL_ERROR -- RST_STREAM, not a 400. This used to answer 400
        // with a body, which a client reads as a response to a request it
        // never fully made; every h2 conformance suite (h2spec 8.1.2.x)
        // expects the reset, and so does every peer.
        if (malformed) return s.protocolError(id);
        const method = Server.methodFromToken(method_tok.?) orelse
            return s.respondError(id, 501);
        // §8.3.1: GET-family requests need :scheme and a non-empty :path.
        if (scheme == null or path_full == null or path_full.?.len == 0)
            return s.protocolError(id);
        // §8.1.1: a content-length must match the actual DATA total. On the
        // streaming surface the total is not known yet — nothing has been
        // received — so `StreamBody` enforces the same rule as it reads,
        // which is also how the h1 `ContentLengthReader` does it.
        if (content_length) |n| {
            if (!streaming and n != buffered_body.len) return s.protocolError(id);
        }

        // `:path` is origin-form or "*" (§8.3.1); anything else is malformed.
        // "*" belongs to OPTIONS alone (RFC 9112 §3.2.4 — h1 parity).
        const target = path_full.?;
        if (target[0] != '/' and !std.mem.eql(u8, target, "*"))
            return s.protocolError(id);
        if (std.mem.eql(u8, target, "*") and method != .options)
            return s.respondError(id, 400);
        var path: []const u8 = target;
        var query: []const u8 = "";
        if (std.mem.indexOfScalar(u8, target, '?')) |i| {
            path = target[0..i];
            query = target[i + 1 ..];
        }
        // The h1 path guard and normalization, verbatim (`Server.
        // checkOriginPath` / `normalizePathInto`): 414 over the length
        // cap, 400 on NUL/`%00`, and `.`/`..` segments collapsed so a `..`
        // cannot walk a route prefix. The h1 loop does this on its serving
        // frame; here the copy is one arena allocation, taken only when a
        // dot-segment is actually present.
        if (path[0] == '/') {
            Server.checkOriginPath(path) catch |err| return s.respondError(id, switch (err) {
                error.PathTooLong => 414,
                error.PathForbidden => 400,
            });
            if (Server.pathHasDotSegments(path)) {
                const norm_buf = arena.alloc(u8, path.len) catch return .close;
                path = Server.normalizePathInto(norm_buf, path);
            }
        }

        // ── synthesize the h1-shaped request the handler expects ────────
        // `Request.header`/`iterateHeaders` read a raw header block, so one
        // is rebuilt from the decoded fields (:authority becomes `host`,
        // matching its §8.3.1 role as the h1 Host; a `host` field the peer
        // sent has already been folded into `authority` above, so it is not
        // written a second time). Every name and value here passed
        // `regularFieldIsValid`, which is what makes a `print` of them into
        // CRLF framing sound.
        // The size is known before the first byte is written, so the block is
        // allocated once at exactly that size instead of growing from zero:
        // an `Allocating` that starts empty rebases (allocate, copy, free)
        // several times per response, and every one of those copies is of a
        // header block this function throws away at the end of the request.
        var block_len: usize = 0;
        if (authority) |a| block_len += "host: \r\n".len + a.len;
        for (req_headers.fields) |f| {
            if (f.name[0] == ':' or std.mem.eql(u8, f.name, "host")) continue;
            block_len += f.name.len + ": \r\n".len + f.value.len;
        }
        var block: Writer.Allocating = Writer.Allocating.initCapacity(arena, block_len) catch
            return .close;
        if (authority) |a| block.writer.print("host: {s}\r\n", .{a}) catch return .close;
        for (req_headers.fields) |f| {
            if (f.name[0] == ':' or std.mem.eql(u8, f.name, "host")) continue;
            block.writer.print("{s}: {s}\r\n", .{ f.name, f.value }) catch return .close;
        }
        const head: h1.RequestHead = .{
            .method = method_tok.?,
            .target = target,
            .http1_0 = false,
            .header_block = block.written(),
            .host = authority,
            // Buffered: the exact total, already known. Streaming: whatever
            // the peer declared (null when it declared nothing — legal in
            // h2, where DATA framing carries the length instead).
            .content_length = if (streaming)
                content_length
            else if (buffered_body.len != 0) buffered_body.len else null,
        };
        // The body reader mirrors the h1 shape exactly: a ContentLength
        // decoder (write-through, empty interface buffer) over the collected
        // bytes — a bare `.fixed` Reader would lose its buffered tail on the
        // `discard` path (std drops partial counts under EndOfStream).
        var body_inner: Reader = .fixed(buffered_body);
        // ── one arena block for every request-scoped buffer ──────────────
        // Body scratch, the response buffer and the framer's interface buffer
        // are all fixed sizes known right here, so they are cut from a single
        // allocation. As four separate `arena.alloc` calls they also made the
        // arena take a second chunk from the gpa, so the saving is both the
        // arena's own bookkeeping and one malloc/free pair per request.
        const scratch_len = 4096;
        const framer_buf_len = 256;
        const slab = arena.alloc(
            u8,
            scratch_len * @as(usize, if (streaming) 2 else 1) +
                s.opts.response_buffer_size + framer_buf_len,
        ) catch return .close;
        const body_scratch = slab[0..scratch_len];
        var cut: usize = scratch_len;
        // Only one of the two body surfaces is ever wired into `body`, so
        // they share `body_scratch`; the streaming one needs a second buffer
        // (see `StreamBody.scratch`) and only takes its slice when it is live.
        var stream_scratch: []u8 = &.{};
        if (streaming) {
            stream_scratch = slab[cut..][0..scratch_len];
            cut += scratch_len;
        }
        // The body passes through these on its way to the handler; zero them
        // before the arena hands the slab back (defers run in reverse, so
        // this runs first). See `Job.deinit`. `zeroize`, not
        // `std.crypto.secureZero` -- this runs on every h2 stream, GET
        // included, and secureZero's byte-at-a-time store showed up as a
        // measured regression on the no-body path (see `zeroize.zig`).
        defer zeroize.zeroize(body_scratch);
        defer zeroize.zeroize(stream_scratch);
        const body_buf = slab[cut..][0..s.opts.response_buffer_size];
        cut += s.opts.response_buffer_size;
        const framer_buf = slab[cut..][0..framer_buf_len];
        var sb: StreamBody = .init(s, id, arena, .{
            .content_length = content_length,
            .budget = s.opts.max_body_bytes,
            .buffer = body_scratch,
            .scratch = stream_scratch,
        });
        var body: Server.RequestBody = if (streaming)
            .{ .external = &sb.reader }
        else if (buffered_body.len != 0)
            .{ .limited = .init(&body_inner, buffered_body.len, body_scratch) }
        else
            .{ .none = .fixed("") };
        // Request trailers (§8.1) → the stock `Request.trailer` surface:
        // the decoded fields are re-serialized as a raw CRLF block, which is
        // the shape `Request` already reads on the h1 chunked path. On the
        // streaming surface the trailer HEADERS frame has not arrived yet —
        // it comes after the last DATA — so `StreamBody` fills the very same
        // field in when the body ends. ONE trailer surface either way.
        var trailer_block: ?[]const u8 = null;
        if (!streaming) {
            s.lock();
            const hl_opt = s.jobs.getPtr(id).?.trailers;
            s.unlock();
            if (hl_opt) |hl| {
                // The field bytes are heap slices owned by the job, which
                // outlives this call; only the `*Job` needed the lock.
                var tb: Writer.Allocating = .init(arena);
                for (hl.fields) |f|
                    tb.writer.print("{s}: {s}\r\n", .{ f.name, f.value }) catch return .close;
                trailer_block = tb.written();
            }
        }
        var req: Server.Request = .{
            .method = method,
            .target = target,
            .path = path,
            .query = query,
            .head = head,
            .body = &body,
            .trailer_block = trailer_block,
            .context = s.opts.context,
            .peer = s.opts.peer,
            .conn_request_index = req_index,
            .stream_id = id,
        };

        // ── run the handler against the stock ResponseWriter ────────────
        var date_buf: [Server.http_date_len]u8 = undefined;
        const date: ?[]const u8 = if (s.opts.now) |n|
            Server.httpDateInto(n, &date_buf)
        else
            null;
        var chunk_buf: [64]u8 = undefined;
        const compression_on = s.opts.compression != null and s.opts.gzip_scratch != null;
        // The handler writes an ordinary HTTP/1.1 response, as it always
        // has — into the re-framer instead of into memory. Everything
        // `ResponseWriter` gives an h1 handler (gzip, ranges, conditional
        // requests, content negotiation, the trailer surface) therefore
        // works on h2 unchanged, because none of it knows the difference.
        var framer: Framer = .init(s, id, arena, .{
            .hold_cap = @max(s.opts.response_buffer_size, 1),
            .buffer = framer_buf,
        });
        // §8.1.2.1 wants the pseudo-header first and the sink sees the status
        // last, so its slot is reserved now and filled in `sinkHeadDone`.
        framer.fields.append(arena, .{ .name = ":status", .value = "" }) catch return .close;
        var rw: Server.ResponseWriter = .init(&framer.interface, body_buf, &chunk_buf, .{
            .head_request = method == .head,
            .date = date,
            .server_name = s.opts.server_name,
            .compression = if (compression_on) s.opts.compression else null,
            .gzip_scratch = if (compression_on) s.opts.gzip_scratch else null,
            .accept_gzip = compression_on and
                gzip.acceptsGzip(head.header("accept-encoding")),
            .encoder_provider = if (compression_on and s.opts.encoder_provider != null) &s.opts.encoder_provider.? else null,
            .accept_encoding = head.header("accept-encoding"),
            // The head crosses as fields: it never becomes HTTP/1.1 text, and
            // nothing parses it back (worth 6,354 instructions per response).
            .field_sink = framer.sink(),
        });
        // Every return below, a detached stream's included: the writer is
        // this frame's, and `Detached` pushes raw DATA, never through it.
        defer rw.releaseEncoder();
        sb.req = &req;
        var failed = false;
        s.opts.handler(&req, &rw) catch {
            failed = true;
        };
        // A detach intercepts BEFORE `rw.end`, which would terminate the
        // response the handler is asking to keep open. Single-task mode
        // only: on the dispatcher path the connection task cannot push for
        // a worker's stream, so the flag is ignored and the response ends
        // normally — as `ResponseWriter.detach` documents.
        if (!failed and rw.detached and !s.threaded) {
            if (s.detachJob(&framer, &rw, id)) return .keep;
        }
        if (!failed) rw.end() catch {
            failed = true; // e.g. body ≠ declared Content-Length
        };
        // Flush what `ResponseWriter` still holds in the framer's own buffer
        // — `end` deliberately does not touch `out`. NOT `framer.interface
        // .flush()`, which is the handler-facing "get it out now" and would
        // release the held DATA frame that END_STREAM has to ride.
        if (!failed) Writer.defaultFlush(&framer.interface) catch {
            failed = true;
        };

        if (framer.dead) return framer.disp; // stream or connection gone
        if (failed) {
            if (!framer.headers_sent) {
                // Nothing has touched the wire yet, so the staged response is
                // simply discarded and a clean status takes its place —
                // exactly the old behavior, which held for every response
                // because every response was staged whole.
                return s.respondError(id, if (sb.exceeded) 413 else 500);
            }
            // Part of the response IS on the wire and cannot be retracted.
            // h1 closes the connection here; h2 can do better and kill just
            // this stream (§5.4.2) — the client sees a failed stream instead
            // of a truncated body silently passed off as complete.
            s.lock();
            defer s.unlock();
            s.conn.sendRstStream(&s.wire, id, .internal_error) catch {};
            s.flushWire() catch return .close;
            return .keep;
        }
        if (framer.finish() == .close) return .close;
        if (rw.connectionMustClose()) {
            // The handler asked for `Connection: close` — h2 has no such
            // header, the equivalent is a graceful GOAWAY (§6.8).
            s.lock();
            defer s.unlock();
            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
            s.flushWire() catch {};
            return .close;
        }
        return .keep;
    }

    /// Minimal error response on one stream (h1 `respondError` parity:
    /// status + text/plain reason body, END_STREAM), leaving the connection
    /// alive. Always returns `.keep` so callers can `return s.respondError(...)`.
    ///
    /// **Invariant 1** (the other HPACK encode site besides `Framer
    /// .sendHead`): the whole response — encode, stage, flush — is one
    /// critical section. Callers must NOT hold `mu`.
    /// RST_STREAM(PROTOCOL_ERROR): the answer to a malformed request
    /// (§8.1.1). No response head goes out first -- the RFC permits one, but
    /// a peer that sees HEADERS on a stream it is about to have reset has to
    /// guess which of the two is the answer, and the conformance suites
    /// read the first frame.
    fn protocolError(s: *Session, id: u31) Disposition {
        s.lock();
        defer s.unlock();
        s.conn.sendRstStream(&s.wire, id, .protocol_error) catch return .keep;
        s.flushWire() catch return .close;
        return .keep;
    }

    fn respondError(s: *Session, id: u31, status: u16) Disposition {
        s.lock();
        defer s.unlock();
        const reason = Server.reasonPhrase(status);
        var status_buf: [8]u8 = undefined;
        var len_buf: [8]u8 = undefined;
        var body_buf: [64]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch unreachable;
        const body_text = std.fmt.bufPrint(&body_buf, "{s}\n", .{reason}) catch unreachable;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body_text.len}) catch unreachable;
        // h1 parity (`Server.writeErrorResponse`): `date` and `server` on the
        // codec's own answers too. RFC 9110 §6.6.1 wants `Date` on a 4xx from
        // a server with a clock, and these are the answers no handler ever
        // saw to add one.
        var date_buf: [Server.http_date_len]u8 = undefined;
        var fields: [5]hpack.Field = undefined;
        var n: usize = 0;
        fields[n] = .{ .name = ":status", .value = status_str };
        n += 1;
        if (s.opts.now) |now| {
            fields[n] = .{ .name = "date", .value = Server.httpDateInto(now, &date_buf) };
            n += 1;
        }
        if (s.opts.server_name) |sn| {
            fields[n] = .{ .name = "server", .value = sn };
            n += 1;
        }
        fields[n] = .{ .name = "content-type", .value = "text/plain" };
        n += 1;
        fields[n] = .{ .name = "content-length", .value = len_str };
        n += 1;
        s.conn.sendHeaders(&s.wire, id, fields[0..n], false) catch return .keep; // stream gone (reset) or overloaded
        s.conn.sendData(&s.wire, id, body_text, true) catch {
            // No window even for the reason text: abort the stream instead.
            s.conn.sendRstStream(&s.wire, id, .internal_error) catch {};
        };
        s.flushWire() catch return .close;
        return .keep;
    }
};

/// Cap on one line of the staged chunked framing (a chunk-size line or a
/// trailer field): the cap is here so that a framing bug cannot become
/// unbounded growth. (Its companion `max_staged_head` went away with the
/// staged head itself -- the response head now crosses as fields, bounded by
/// `ResponseWriter`'s own `max_response_headers`.)
const max_staged_line = 4096;

// ── the response side: one engine, streaming ────────────────────────────────

/// Re-frames the HTTP/1.1 response `ResponseWriter` produces into HTTP/2
/// frames **while it is being produced** — a `std.Io.Writer` the response
/// writer drains into, instead of the `Writer.Allocating` it used to fill.
///
/// ## Why this shape, and what the alternatives would have cost
///
/// The old path staged the whole HTTP/1.1 response in memory, waited for the
/// handler to return, and re-framed it. That staging is what buys h2 every
/// h1 response feature for free — gzip, ranges, conditional requests,
/// content negotiation, the response-trailer surface are each written once,
/// against `ResponseWriter`, and none of them knows which protocol it is on.
/// What it costs is that no byte can leave before the last byte is written,
/// so an unbounded response has to fit in memory first.
///
/// The transformation here is the SAME one, moved from "after" to "during":
/// an HTTP/1.1 response is self-describing, so re-framing it as a pipe needs
/// nothing that re-framing it from a buffer did not already need. That is
/// the entire argument for this design — there is exactly ONE response path,
/// not a streaming one beside a buffered one, so no `ResponseWriter` feature
/// can quietly work on one and not the other, and neither can rot.
///
/// The two alternatives, and their price:
///   * **A streaming-only second handler type** taking an h2-native writer.
///     It never has to parse anything, which is genuinely simpler — but
///     every `ResponseWriter` feature would then be either reimplemented
///     against it or missing from it, and the two would drift on exactly the
///     details (framing, END_STREAM placement, trailer rules) where drift is
///     silent rather than loud.
///   * **Teaching `ResponseWriter` an h2 framing mode**, so no HTTP/1.1
///     bytes are generated at all. Less work at runtime, and no parser — but
///     it puts a protocol branch through the one type every h1 handler and
///     all 373 tests already run through, and it inverts the module's
///     layering: `Server.zig` would have to know about HPACK.
///
/// ## Framing: one frame of lookahead, in two places
///
/// So that a response fitting the `ResponseWriter` buffer is framed
/// BYTE-IDENTICALLY to the old staging path — HEADERS, then one DATA frame
/// carrying END_STREAM — while a longer one streams:
///   * the response HEADERS frame is withheld until either the first body
///     octet (it then goes out **without** END_STREAM) or `finish` (it then
///     carries END_STREAM, when there is neither body nor trailer section);
///   * up to `hold_cap` body octets are withheld, so END_STREAM can ride the
///     final DATA frame rather than needing an empty one behind it (§8.1).
///
/// `interface.flush` — what a handler calls to push an SSE event out — is
/// the deliberate exception: it releases the held octets, and pays for it
/// with one empty END_STREAM DATA frame at the end of the response.
const Framer = struct {
    s: *Session,
    id: u31,
    /// Request-scoped; holds the HPACK field names/values until they are
    /// encoded, the framer's own interface buffer, and every list below --
    /// nothing in a framer outlives its request, so nothing needs an
    /// allocator that does.
    arena: Allocator,
    hold_cap: usize,
    /// Backs the `:status` field's value until `sendHead` encodes it.
    status_buf: [5]u8 = undefined,
    /// Backs the `content-length` value until `sendHead` encodes it.
    clen_buf: [20]u8 = undefined,

    /// Set once the head has crossed as fields; body octets may follow.
    head_done: bool = false,
    /// Parsed response fields, waiting for `sendHead`.
    fields: std.ArrayList(hpack.Field) = .empty,
    headers_sent: bool = false,
    /// The staged response uses chunked framing (declared trailers, gzip, or
    /// a body that outgrew the `ResponseWriter` buffer).
    chunked: bool = false,
    /// Body octets withheld so END_STREAM can ride the last DATA frame.
    held: std.ArrayList(u8) = .empty,
    data_sent: bool = false,
    /// The staged trailer section, as h2 fields (§8.1).
    trailers: std.ArrayList(hpack.Field) = .empty,

    // Chunked-decoder state (push mode: the pull-mode `h1.ChunkedReader`
    // needs a reader to pull from, and the whole point here is that there is
    // no complete buffer to give it).
    cstate: enum { size, data, data_crlf, trailer, done } = .size,
    cleft: usize = 0,
    crlf_seen: u8 = 0,
    line: std.ArrayList(u8) = .empty,

    /// Sticky: nothing more may be sent on this stream. `disp` is what
    /// `serveJob` should return.
    dead: bool = false,
    disp: Disposition = .keep,
    interface: Writer,

    const InitOptions = struct { hold_cap: usize, buffer: []u8 };

    fn init(s: *Session, id: u31, arena: Allocator, opts: InitOptions) Framer {
        return .{
            .s = s,
            .id = id,
            .arena = arena,
            .hold_cap = opts.hold_cap,
            .interface = .{
                .vtable = &.{ .drain = drainFn, .flush = flushFn },
                .buffer = opts.buffer,
            },
        };
    }

    /// The response head reaches the framer as fields: the handler's writer
    /// calls `sinkPut` per field and `sinkHeadDone` at the end, and no HTTP/1.1
    /// text is produced or parsed anywhere on the way.
    fn sink(f: *Framer) Server.ResponseWriter.FieldSink {
        return .{ .ctx = f, .put = sinkPut, .head_done = sinkHeadDone };
    }

    fn sinkPut(ctx: *anyopaque, name: []const u8, value: []const u8) Writer.Error!void {
        const f: *Framer = @ptrCast(@alignCast(ctx));
        // §8.2.2: connection-specific headers never cross into h2.
        if (isConnectionSpecific(name)) return;
        // §8.2.1 is settled before a field reaches here, by construction rather
        // than by re-walking every octet of every field of every response (a
        // check here measured 600 instructions per response -- 4% of the whole
        // h2 path -- to re-answer a question with two known answers):
        //
        //   * names: `setHeader` is the only way into the header table and
        //     rejects anything that is not a token; `ResponseWriter.lowerName`
        //     lowercases what it hands over. The rest are literals in this file.
        //   * values: `setHeader` rejects CR/LF/NUL at set time, `checkedOptions`
        //     holds `server_name` once per connection, and the others are
        //     generated here (the date, the content-length digits).
        //
        // The assert is what keeps that a fact rather than a belief: it runs in
        // Debug and ReleaseSafe, which is what the test suite and the gate build,
        // so a new path that forwards a field from somewhere else trips it there
        // instead of putting it on the wire.
        // The assert is what keeps that a fact rather than a belief: it runs in
        // Debug and ReleaseSafe, which is what the test suite and the gate build,
        // so a new path that forwards a field from somewhere else trips it there
        // instead of putting it on the wire. In ReleaseFast the whole block is
        // gone -- measured at 15 instructions per response, inside the
        // instrument's own noise.
        if (std.debug.runtime_safety) {
            for (name) |c| std.debug.assert(!std.ascii.isUpper(c) and h1.isTchar(c));
            std.debug.assert(h1.isValidFieldValue(value));
        }
        f.fields.append(f.arena, .{ .name = name, .value = value }) catch
            return f.die(.close);
    }

    fn sinkHeadDone(
        ctx: *anyopaque,
        status: u16,
        chunked: bool,
        content_length: ?u64,
    ) Writer.Error!void {
        const f: *Framer = @ptrCast(@alignCast(ctx));
        if (f.dead) return error.WriteFailed;
        f.chunked = chunked;
        f.fields.items[0].value = std.fmt.bufPrint(&f.status_buf, "{d}", .{status}) catch
            return f.die(.close);
        if (content_length) |n| {
            const text = std.fmt.bufPrint(&f.clen_buf, "{d}", .{n}) catch
                return f.die(.close);
            f.fields.append(f.arena, .{ .name = "content-length", .value = text }) catch
                return f.die(.close);
        }
        f.head_done = true;
    }

    fn drainFn(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const f: *Framer = @alignCast(@fieldParentPtr("interface", w));
        const buffered = w.buffer[0..w.end];
        w.end = 0;
        try f.feed(buffered);
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try f.feed(d);
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try f.feed(last);
        consumed += last.len * splat;
        return consumed;
    }

    /// A handler-driven flush (`ResponseWriter.flush`: SSE, long poll,
    /// progressive output) means "these bytes must reach the client now", so
    /// the held DATA frame goes out too — the one case where END_STREAM
    /// cannot ride the last body frame and gets an empty one of its own.
    fn flushFn(w: *Writer) Writer.Error!void {
        const f: *Framer = @alignCast(@fieldParentPtr("interface", w));
        try Writer.defaultFlush(w);
        if (f.held.items.len != 0) {
            try f.emit(f.held.items, false);
            f.held.clearRetainingCapacity();
        }
    }

    /// Mark the stream unusable and report it to `ResponseWriter` as a write
    /// failure, which is how the handler learns to stop.
    fn die(f: *Framer, disp: Disposition) Writer.Error {
        if (!f.dead) {
            f.dead = true;
            f.disp = disp;
        }
        return error.WriteFailed;
    }

    /// Body octets only. The head never comes through here: the writer hands it
    /// over as fields (`sinkPut`/`sinkHeadDone`) before any body byte drains, so
    /// what arrives is either the body itself or, when the response is chunked,
    /// the body inside chunked framing that this strips back off.
    fn feed(f: *Framer, bytes: []const u8) Writer.Error!void {
        if (f.dead) return error.WriteFailed;
        // A body before a head would mean a `ResponseWriter` that drained
        // without calling `writeHead`, which it does not do.
        std.debug.assert(f.head_done);
        var rest = bytes;
        while (rest.len != 0) {
            if (!f.chunked) {
                try f.push(rest);
                return;
            }
            rest = try f.feedChunked(rest);
        }
    }

    /// One step of the push-mode chunked decoder; returns the unconsumed
    /// tail. Chunk payload becomes DATA, the trailer section becomes h2
    /// trailer fields (§8.1).
    fn feedChunked(f: *Framer, bytes: []const u8) Writer.Error![]const u8 {
        switch (f.cstate) {
            .size, .trailer => {
                const nl = std.mem.indexOfScalar(u8, bytes, '\n') orelse {
                    try f.appendLine(bytes);
                    return "";
                };
                try f.appendLine(bytes[0 .. nl + 1]);
                const rest = bytes[nl + 1 ..];
                const line = std.mem.trimEnd(u8, f.line.items, "\r\n");
                defer f.line.clearRetainingCapacity();
                if (f.cstate == .size) {
                    if (line.len == 0) return rest; // tolerate a stray CRLF
                    const end = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
                    const n = std.fmt.parseInt(usize, line[0..end], 16) catch
                        return f.die(.close);
                    if (n == 0) {
                        f.cstate = .trailer; // the last-chunk line
                    } else {
                        f.cleft = n;
                        f.cstate = .data;
                    }
                } else if (line.len == 0) {
                    f.cstate = .done; // blank line: end of the trailer section
                } else {
                    const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                        return f.die(.close);
                    // The names were already vetted by `ResponseWriter`'s
                    // trailer filter (RFC 9110 §6.5.1 + the `Trailer`
                    // advert), which is also what keeps a pseudo-header out
                    // of this block — `:`-prefixed names never make it into
                    // the staged response at all.
                    const name = std.ascii.allocLowerString(
                        f.arena,
                        std.mem.trim(u8, line[0..colon], " \t"),
                    ) catch return f.die(.close);
                    const value = f.arena.dupe(
                        u8,
                        std.mem.trim(u8, line[colon + 1 ..], " \t"),
                    ) catch return f.die(.close);
                    f.trailers.append(f.arena, .{ .name = name, .value = value }) catch
                        return f.die(.close);
                }
                return rest;
            },
            .data => {
                const n = @min(f.cleft, bytes.len);
                try f.push(bytes[0..n]);
                f.cleft -= n;
                if (f.cleft == 0) f.cstate = .data_crlf;
                return bytes[n..];
            },
            .data_crlf => {
                const n = @min(@as(usize, 2 - f.crlf_seen), bytes.len);
                f.crlf_seen += @intCast(n);
                if (f.crlf_seen == 2) {
                    f.crlf_seen = 0;
                    f.cstate = .size;
                }
                return bytes[n..];
            },
            .done => return "", // nothing follows the trailer section
        }
    }

    fn appendLine(f: *Framer, bytes: []const u8) Writer.Error!void {
        f.line.appendSlice(f.arena, bytes) catch return f.die(.close);
        if (f.line.items.len > max_staged_line) return f.die(.close);
    }

    /// Body octets, framing already stripped: everything above `hold_cap`
    /// goes to the wire now, the tail waits for END_STREAM.
    fn push(f: *Framer, bytes: []const u8) Writer.Error!void {
        if (bytes.len == 0) return;
        if (!f.headers_sent) try f.sendHead(false); // a body exists: no END_STREAM
        if (f.held.items.len + bytes.len <= f.hold_cap) {
            f.held.appendSlice(f.arena, bytes) catch return f.die(.close);
            return;
        }
        if (f.held.items.len != 0) {
            try f.emit(f.held.items, false);
            f.held.clearRetainingCapacity();
        }
        if (bytes.len > f.hold_cap) {
            const n = bytes.len - f.hold_cap;
            try f.emit(bytes[0..n], false);
            f.held.appendSlice(f.arena, bytes[n..]) catch return f.die(.close);
        } else {
            f.held.appendSlice(f.arena, bytes) catch return f.die(.close);
        }
    }

    /// **Invariant 1 — stateful HPACK.** The encoder's dynamic table is
    /// connection-global and every emitted block is an *edit* to it, so the
    /// encode, the append to `wire` and the flush are ONE critical section.
    /// Split them across two threads and each block is still individually
    /// well-formed while referring to a table state the peer never reached:
    /// silent corruption of somebody else's headers, not a crash. (Splitting
    /// only the flush out would be safe — `wire` stays FIFO — but is not
    /// The flush belongs in the same section for a second, independent
    /// reason (**invariant 2**): `flushWire` is itself a read-then-clear of
    /// the shared `wire`, so two unlocked flushers can both observe the same
    /// staged bytes and write them twice. ⚠ Measured: moving *only* the
    /// flush out of this section did NOT fail the suite in a full run — the
    /// window is a memcpy wide. Treat that as a known blind spot, not as
    /// evidence the split is safe.
    fn sendHead(f: *Framer, end_stream: bool) Writer.Error!void {
        f.s.lock();
        defer f.s.unlock();
        f.s.conn.sendHeaders(&f.s.wire, f.id, f.fields.items, end_stream) catch |err|
            switch (err) {
                error.OutOfMemory => return f.die(.close),
                else => return f.die(.keep), // stream reset by the peer meanwhile
            };
        f.headers_sent = true;
        f.s.stageWire() catch return f.die(.close);
    }

    /// Put `body` on the wire as DATA under §5.2 flow control: send what the
    /// connection + stream windows allow (the layer splits frames per the
    /// peer's SETTINGS_MAX_FRAME_SIZE), and when both are shut keep reading
    /// the connection until a WINDOW_UPDATE opens room.
    ///
    /// The pump is what makes bidirectional streaming work: a handler
    /// blocked writing its response keeps the receive side live, so the
    /// request body it is also reading continues to arrive.
    /// **Invariant 3 — flow control is check-then-act.** The two windows are
    /// signed and §6.9.1 forbids them going negative; if they do, it is the
    /// **peer** that GOAWAYs us. Reading the window and consuming it are one
    /// critical section here, so two handlers cannot both observe the same
    /// room and both spend it. What is deliberately outside the section is
    /// the *wait*: yielding while holding `mu` would keep the connection task
    /// from ever delivering the WINDOW_UPDATE being waited for.
    ///
    /// ⚠ `conn_send_window` — the term two workers actually share, since a
    /// stream window belongs to one handler — must stay in the minimum below.
    /// Dropping it does not corrupt anything, because `h2.sendData` re-checks
    /// `len > conn_send_window` itself; it turns a correct chop into a
    /// **livelock**, where `emit` keeps asking for a chunk the connection
    /// window cannot fund and waits for credit that only arrives if it makes
    /// progress. That failure is invisible until one `emit` call carries more
    /// than the connection window, which needs `response_buffer_size` above
    /// the body size — see the test "the connection window bounds two
    /// concurrent senders", which is built specifically to reach it.
    const Step = enum { sent, wait, dead_keep, dead_close };

    fn emit(f: *Framer, body: []const u8, end_stream: bool) Writer.Error!void {
        const s = f.s;
        var off: usize = 0;
        while (off < body.len) {
            var n: usize = 0;
            var seen: u32 = undefined;
            const step: Step = blk: {
                s.lock();
                defer s.unlock();
                seen = s.progress;
                if (s.jobs.getPtr(f.id)) |job| {
                    if (job.rst) break :blk .dead_keep;
                }
                const st = s.conn.stream(f.id) orelse break :blk .dead_keep;
                switch (st.state) {
                    .open, .half_closed_remote => {},
                    else => break :blk .dead_keep, // peer reset the stream: abandon
                }
                const win = @min(s.conn.conn_send_window, st.send_window);
                if (win <= 0) break :blk .wait;
                n = @min(body.len - off, @as(usize, @intCast(win)));
                const last = end_stream and off + n == body.len;
                s.conn.sendData(&s.wire, f.id, body[off..][0..n], last) catch |err|
                    switch (err) {
                        error.OutOfMemory => break :blk .dead_close,
                        // Raced a SETTINGS window shrink applied meanwhile.
                        error.WindowExhausted => break :blk .wait,
                        else => break :blk .dead_keep, // stream reset: abandon
                    };
                s.stageWire() catch break :blk .dead_close;
                break :blk .sent;
            };
            switch (step) {
                .sent => {
                    off += n;
                    f.data_sent = true;
                },
                .wait => s.waitForPeer(seen) catch |err| switch (err) {
                    error.Closed => return f.die(.close),
                    // The handler was canceled waiting for credit. Part of
                    // the response is on the wire: end just this stream
                    // (§5.4.2), the connection stays.
                    error.Canceled => {
                        s.lock();
                        defer s.unlock();
                        s.conn.sendRstStream(&s.wire, f.id, .cancel) catch {};
                        s.stageWire() catch return f.die(.close);
                        return f.die(.keep);
                    },
                },
                .dead_keep => return f.die(.keep),
                .dead_close => return f.die(.close),
            }
        }
        if (end_stream and body.len == 0) {
            // Post-flush: the last real DATA frame is long gone, so
            // END_STREAM needs a frame of its own.
            s.lock();
            defer s.unlock();
            s.conn.sendData(&s.wire, f.id, "", true) catch return f.die(.keep);
            s.stageWire() catch return f.die(.close);
        }
    }

    /// The handler is done and `ResponseWriter.end` has run: release the
    /// held frames with END_STREAM in the one place §8.1 allows it.
    ///
    /// §8.1: END_STREAM belongs on the LAST thing sent. With a trailer
    /// section that is the trailing HEADERS frame — never the response
    /// HEADERS, and never the final DATA frame. Getting this wrong loses the
    /// trailers *silently*: measured against curl 8.18/nghttp2 1.68, a peer
    /// that already saw END_STREAM discards the later HEADERS frame and
    /// still reports the transfer as successful, so nothing but an explicit
    /// "were the trailers surfaced?" check catches it.
    fn finish(f: *Framer) Disposition {
        if (f.dead) return f.disp;
        // `ResponseWriter.end` always terminates a chunked body (0-chunk +
        // the blank line), so by now the decoder must have reached the end
        // of the staged message. If it has not, the staged framing and this
        // decoder disagree and the body would be silently truncated — kill
        // the stream instead of shipping a short body as a complete one.
        if (f.chunked and f.cstate != .done) {
            if (f.headers_sent) {
                f.s.lock();
                defer f.s.unlock();
                f.s.conn.sendRstStream(&f.s.wire, f.id, .internal_error) catch {};
                f.s.flushWire() catch return .close;
                return .keep;
            }
            return f.s.respondError(f.id, 500);
        }
        const has_trailers = f.trailers.items.len != 0;
        if (!f.headers_sent) {
            f.sendHead(f.held.items.len == 0 and !has_trailers) catch return f.disp;
        }
        if (f.held.items.len != 0) {
            f.emit(f.held.items, !has_trailers) catch return f.disp;
            f.held.clearRetainingCapacity();
        } else if (!has_trailers and f.data_sent) {
            f.emit("", true) catch return f.disp;
        }
        if (has_trailers) {
            // **Invariant 1** again: the trailer block is a second edit to
            // the same dynamic table.
            f.s.lock();
            defer f.s.unlock();
            f.s.conn.sendHeaders(&f.s.wire, f.id, f.trailers.items, true) catch |err|
                switch (err) {
                    error.OutOfMemory => return .close,
                    else => return .keep, // stream reset by the peer meanwhile
                };
            f.s.stageWire() catch return .close;
        }
        return .keep;
    }
};

// ── the request side: the incremental body ──────────────────────────────────

/// The handler-facing request body on the streaming surface (§8.1 read
/// side): DATA frames as they land, rather than after the last one.
///
/// Reads block only while nothing has arrived — pumping the connection,
/// which advances every other stream and keeps the response side live —
/// and end at END_STREAM, never at a lull in the DATA frames. Taking octets
/// is what returns their §6.9 window credit (`Session.grantJob`), so unread
/// octets cannot outgrow the advertised receive window however slowly the
/// handler reads. `Options.max_body_bytes` still bounds the whole body, the
/// way `RequestBody.Capped` does it on the h1 chunked path: the read fails
/// once it is crossed, and `serveJob` turns that into a 413 when nothing has
/// been sent yet.
const StreamBody = struct {
    s: *Session,
    id: u31,
    arena: Allocator,
    /// Set by `serveJob` before the handler runs: where the trailer section
    /// is deposited once the body ends, so `Request.trailer` /
    /// `iterateTrailers` are the same surface on both protocols.
    req: ?*Server.Request = null,
    trailers_done: bool = false,
    /// Declared `content-length` still owed (§8.1.1); null = none declared.
    remaining: ?u64,
    /// `max_body_bytes` still allowed; null = unlimited.
    budget: ?u64,
    /// The cap was crossed — `serveJob` answers 413 rather than 500.
    exceeded: bool = false,
    /// A staging copy of the octets handed over. The handler's sink can
    /// re-enter `pump` (an echo handler writes into the response framer,
    /// which pumps when the send window shuts), and a slice into the job's
    /// body would not survive that: `onData` may append to — and therefore
    /// reallocate — the very buffer we would be copying out of.
    scratch: []u8,
    reader: Reader,

    const InitOptions = struct {
        content_length: ?u64,
        budget: ?u64,
        buffer: []u8,
        scratch: []u8,
    };

    fn init(s: *Session, id: u31, arena: Allocator, opts: InitOptions) StreamBody {
        return .{
            .s = s,
            .id = id,
            .arena = arena,
            .remaining = opts.content_length,
            .budget = opts.budget,
            .scratch = opts.scratch,
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = opts.buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    const Step = enum { copied, wait, eof, fail, exceeded };

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const b: *StreamBody = @alignCast(@fieldParentPtr("reader", r));
        while (true) {
            var n: usize = 0;
            var seen: u32 = undefined;
            // **Invariants 4+5**: the `*Job` is re-derived under `mu` and
            // never leaves this section — `onData` may append to (and so
            // reallocate) `job.body` from the connection task at any moment,
            // and the map rehashes when a new stream is admitted.
            const step: Step = blk: {
                b.s.lock();
                defer b.s.unlock();
                seen = b.s.progress;
                const job = b.s.jobs.getPtr(b.id) orelse break :blk .fail;
                if (job.rst) break :blk .fail;
                const src = limit.sliceConst(job.unread());
                if (src.len != 0) {
                    n = @min(src.len, b.scratch.len);
                    if (b.budget) |left| {
                        if (n > left) break :blk .exceeded;
                        b.budget = left - n;
                    }
                    if (b.remaining) |rem| {
                        // §8.1.1: more DATA than the declared content-length.
                        if (n > rem) break :blk .fail;
                        b.remaining = rem - n;
                    }
                    @memcpy(b.scratch[0..n], src[0..n]);
                    break :blk .copied;
                }
                // Only END_STREAM ends the body — a lull in the DATA frames
                // does not, and neither does a trailer section that has not
                // landed.
                if (job.complete) {
                    b.materializeTrailers();
                    if (b.remaining) |rem| {
                        // §8.1.1: fewer DATA octets than the declared length.
                        if (rem != 0) break :blk .fail;
                    }
                    break :blk .eof;
                }
                break :blk .wait;
            };
            switch (step) {
                .fail => return error.ReadFailed,
                .exceeded => {
                    b.exceeded = true;
                    return error.ReadFailed;
                },
                .eof => return error.EndOfStream,
                // Canceled too: `Reader.Error` cannot carry it. The job's
                // body is then unread, and `finishJob` resets the stream.
                .wait => b.s.waitForPeer(seen) catch return error.ReadFailed,
                .copied => {
                    // Outside the lock on purpose: this write can re-enter
                    // the connection through `Framer` (see `scratch`), which
                    // takes `mu` for itself.
                    try w.writeAll(b.scratch[0..n]);
                    b.s.lock();
                    defer b.s.unlock();
                    const jp = b.s.jobs.getPtr(b.id) orelse return error.ReadFailed;
                    jp.read_pos += n;
                    if (jp.read_pos == jp.body.items.len) {
                        // Fully drained: reclaim the buffer instead of
                        // letting a long upload accumulate behind the cursor.
                        // `zeroize`, not `std.crypto.secureZero` -- see
                        // `zeroize.zig`.
                        zeroize.zeroize(jp.body.items);
                        jp.body.clearRetainingCapacity();
                        jp.read_pos = 0;
                    }
                    b.s.grantJob(b.id, n);
                    return n;
                },
            }
        }
    }

    /// Re-serialize the request's trailer HEADERS frame as the raw CRLF
    /// block `Request.trailer` reads — the same representation the buffered
    /// surface builds, just built at the moment the trailers are known.
    fn materializeTrailers(b: *StreamBody) void {
        if (b.trailers_done) return;
        b.trailers_done = true;
        const req = b.req orelse return;
        const job = b.s.jobs.getPtr(b.id) orelse return;
        const hl = job.trailers orelse return;
        var tb: Writer.Allocating = .init(b.arena);
        for (hl.fields) |f|
            tb.writer.print("{s}: {s}\r\n", .{ f.name, f.value }) catch return;
        req.trailer_block = tb.written();
    }
};

/// RFC 9113 §8.2.1 for one regular (non-pseudo) field: the name is a
/// lowercase token — no byte in 0x00–0x20, 0x41–0x5A or 0x7F–0xFF, and no
/// `:` — and the value carries no NUL, LF or CR (nor any other control
/// byte; `h1.isValidFieldValue` is the h1 wire rule and is applied
/// unchanged) and neither starts nor ends with SP/HTAB. A field failing
/// this makes the request malformed (§8.1.1).
fn regularFieldIsValid(f: hpack.Field) bool {
    if (!h1.isToken(f.name)) return false;
    for (f.name) |c| if (c >= 'A' and c <= 'Z') return false;
    if (!h1.isValidFieldValue(f.value)) return false;
    if (f.value.len != 0) {
        const first = f.value[0];
        const last = f.value[f.value.len - 1];
        if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return false;
    }
    return true;
}

/// Whether a decoded trailer block may be surfaced: no pseudo-header field
/// (never legal in a trailer section, RFC 9113 §8.1) and every field
/// §8.2.1-valid. A block is admitted whole or dropped whole.
fn trailerBlockIsValid(list: hpack.HeaderList) bool {
    for (list.fields) |f| {
        if (f.name.len != 0 and f.name[0] == ':') return false;
        if (!regularFieldIsValid(f)) return false;
    }
    return true;
}

/// Connection-specific headers that must not cross the h1↔h2 boundary
/// (RFC 9113 §8.2.2).
fn isConnectionSpecific(name: []const u8) bool {
    const names = [_][]const u8{
        "connection", "transfer-encoding", "keep-alive", "proxy-connection", "upgrade",
    };
    for (names) |n| {
        if (std.ascii.eqlIgnoreCase(name, n)) return true;
    }
    return false;
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Offline tests drive `serve` from fixed buffers, playing the client with
// `h2.Connection` in client role; loopback tests stand up the real
// `Server` with `enable_h2c` and prove the SAME handler answers over both
// HTTP/1.1 and HTTP/2.

const testing = std.testing;
const net = std.Io.net;

/// 256 bytes — larger than the small client windows the flow-control tests
/// advertise, so the response body must be window-throttled.
const big_body = "abcdefgh" ** 32;

/// 8 KiB — larger than the default 4 KiB `response_buffer_size`, so a
/// handler writing it forces `ResponseWriter` into streaming (chunked)
/// framing and the response reaches the wire *before* the handler returns.
const long_body = "0123456789abcdef" ** 512;

/// Scratch the `/stream-count` route drains into. File scope, not a stack
/// array: it is 16 KiB and the handler runs on the connection's task.
var stream_sink_buf: [16 * 1024]u8 = undefined;

/// `Options.stream_request` for the tests: the `/stream-*` routes take the
/// incremental request body, everything else keeps the buffered surface —
/// which is the point of the predicate being per-request.
fn streamRoutes(ctx: ?*anyopaque, preview: RequestPreview) bool {
    _ = ctx;
    return std.mem.startsWith(u8, preview.path(), "/stream-");
}

/// The one handler every test (h1 and h2 alike) is served by.
fn testHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        if (req.query.len != 0) try rw.setHeader("X-Query", req.query);
        try rw.writeAll("hello");
    } else if (std.mem.eql(u8, req.path, "/echo")) {
        var buf: [512]u8 = undefined;
        var w: Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/meta")) {
        var buf: [128]u8 = undefined;
        var w: Writer = .fixed(&buf);
        if (req.peerAddress()) |p| try w.print("{f}", .{p}) else try w.writeAll("none");
        try w.print(" #{d} host={s}", .{ req.connRequestIndex(), req.header("host") orelse "-" });
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/static-name")) {
        // A comptime name: `setHeaderStatic` stores the literal itself, so
        // the h2 head cannot lower it where it lies.
        rw.setStatus(405);
        try rw.setHeaderStatic("Allow", "GET, HEAD");
    } else if (std.mem.eql(u8, req.path, "/big")) {
        try rw.writeAll(big_body);
    } else if (std.mem.eql(u8, req.path, "/drain")) {
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
    } else if (std.mem.eql(u8, req.path, "/outtrailers")) {
        try rw.setHeader("Content-Type", "text/plain");
        try rw.declareTrailers(&.{ "X-Checksum", "X-Rows" });
        try rw.writeAll("hello");
        try rw.setTrailer("X-Checksum", "deadbeef");
        try rw.setTrailer("X-Rows", "3");
    } else if (std.mem.eql(u8, req.path, "/outtrailers-empty")) {
        // Trailers with no body at all: the response HEADERS must not carry
        // END_STREAM either, and no DATA frame may be sent.
        try rw.declareTrailer("X-Checksum");
        try rw.setTrailer("X-Checksum", "deadbeef");
    } else if (std.mem.eql(u8, req.path, "/reqtrailers")) {
        // Drain the body first — a trailer section arrives after it on both
        // protocols — then echo what came through.
        const r = req.reader();
        while (true) {
            _ = r.discard(.limited(4096)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return error.BodyReadFailed,
            };
        }
        var buf: [128]u8 = undefined;
        var w: Writer = .fixed(&buf);
        try w.print("trailer={s}", .{req.trailer("X-Checksum") orelse "none"});
        var it = req.iterateTrailers();
        var n: usize = 0;
        while (it.next()) |_| n += 1;
        try w.print(" count={d}", .{n});
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/headers")) {
        // Every header the handler can see, in wire order, plus the routed
        // path and query — what the §8.2.1 tests read to prove that no
        // field reached the handler that the peer did not legally send.
        var buf: [1024]u8 = undefined;
        var w: Writer = .fixed(&buf);
        try w.print("path={s} query={s}", .{ req.path, req.query });
        var it = req.iterateHeaders();
        while (it.next()) |e| try w.print(" [{s}={s}]", .{ e.name, e.value });
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/fail")) {
        try rw.writeAll("partial");
        return error.Boom;
    } else if (std.mem.eql(u8, req.path, "/bigfail")) {
        // Writes past `response_buffer_size` and *then* fails: with a
        // streaming response the head and part of the body are already gone
        // and cannot be retracted, so the stream is killed instead of being
        // rewritten into a 500.
        try rw.writeAll(long_body);
        return error.Boom;
    } else if (std.mem.eql(u8, req.path, "/stream-partial")) {
        // Reads exactly 10 octets of a body that has not ended and answers.
        // `stream(..., .limited(10))` rather than `take(10)` on purpose: a
        // buffer-filling read would pull far more than it consumes and make
        // "credit follows consumption" indistinguishable from "credit
        // follows arrival".
        var buf: [16]u8 = undefined;
        var w: Writer = .fixed(&buf);
        const n = req.reader().stream(&w, .limited(10)) catch |err| switch (err) {
            error.EndOfStream => 0,
            else => return error.BodyReadFailed,
        };
        var out: [48]u8 = undefined;
        try rw.writeAll(try std.fmt.bufPrint(&out, "took {d}", .{n}));
    } else if (std.mem.eql(u8, req.path, "/stream-ignore")) {
        // Never touches the body at all.
        try rw.writeAll("ignored");
    } else if (std.mem.eql(u8, req.path, "/stream-count")) {
        // Drains incrementally to END_STREAM, reporting both the byte total
        // and how many separate reads it took — a body delivered in one
        // piece would report reads=1.
        const r = req.reader();
        var total: u64 = 0;
        var reads: u64 = 0;
        var sink: Writer = .fixed(&stream_sink_buf);
        while (true) {
            sink = .fixed(&stream_sink_buf);
            const n = r.stream(&sink, .limited(stream_sink_buf.len)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return error.BodyReadFailed,
            };
            if (n == 0) continue;
            total += n;
            reads += 1;
        }
        var out: [96]u8 = undefined;
        try rw.writeAll(try std.fmt.bufPrint(
            &out,
            "streamed {d} in {d} reads trailer={s}",
            .{ total, reads, req.trailer("X-Checksum") orelse "none" },
        ));
    } else if (std.mem.eql(u8, req.path, "/stream-echo")) {
        // Both directions live on one stream: every chunk read is written
        // back and flushed before the next one is read.
        const r = req.reader();
        var buf: [256]u8 = undefined;
        while (true) {
            var w: Writer = .fixed(&buf);
            const n = r.stream(&w, .limited(buf.len)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return error.BodyReadFailed,
            };
            if (n == 0) continue;
            try rw.writeAll(w.buffered());
            try rw.flush();
        }
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

/// One response stream as seen by the test client.
const Collected = struct {
    status: u16 = 0,
    /// The response header list (moved out of the event).
    headers: ?hpack.HeaderList = null,
    /// A SECOND HEADERS frame on the stream = the trailer section (§8.1).
    trailers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    data_frames: u32 = 0,
    /// Whether the response HEADERS carried END_STREAM.
    headers_end_stream: bool = false,
    /// Whether ANY DATA frame carried END_STREAM. Must be false when a
    /// trailer HEADERS frame follows — that is the h2 framing rule a
    /// self-consistent implementation would otherwise never notice.
    data_end_stream: bool = false,
    trailers_end_stream: bool = false,
    /// DATA frames seen before the trailer HEADERS arrived (ordering).
    data_frames_before_trailers: u32 = 0,
    end: bool = false,
    rst: ?h2.ErrorCode = null,

    fn header(c: *const Collected, name: []const u8) ?[]const u8 {
        const hl = c.headers orelse return null;
        for (hl.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    fn trailer(c: *const Collected, name: []const u8) ?[]const u8 {
        const hl = c.trailers orelse return null;
        for (hl.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    fn deinit(c: *Collected, gpa: Allocator) void {
        if (c.headers) |*hl| hl.deinit(gpa);
        if (c.trailers) |*hl| hl.deinit(gpa);
        c.body.deinit(gpa);
    }
};

/// Test client: an `h2.Connection` in client role plus event folding into
/// per-stream `Collected` responses.
const TestPeer = struct {
    gpa: Allocator,
    conn: h2.Connection,
    /// Outgoing bytes (requests, ACKs, window updates) awaiting a flush.
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,
    resps: std.AutoArrayHashMapUnmanaged(u31, Collected) = .empty,
    goaway: ?h2.ErrorCode = null,
    /// §6.9 credit the server handed us back, split by window. These are
    /// observations about the frames actually on the wire — the only thing
    /// that can tell an arrival-driven WINDOW_UPDATE policy from a
    /// consumption-driven one, since both end up crediting the same total.
    wu_conn: u64 = 0,
    wu_stream: std.AutoArrayHashMapUnmanaged(u31, u64) = .empty,
    /// Frames seen since the last `mark`, in arrival order (kind only) —
    /// for asserting that a grant came *after* a response, not before it.
    log: std.ArrayList(Frame) = .empty,

    const Frame = union(enum) {
        headers: u31,
        data: u31,
        window_update: struct { stream_id: u31, increment: u31 },
        rst: u31,
    };

    /// Total stream-level credit the server returned on `sid`.
    fn streamCredit(p: *const TestPeer, sid: u31) u64 {
        return p.wu_stream.get(sid) orelse 0;
    }

    fn indexOfFirstHeaders(p: *const TestPeer, sid: u31) ?usize {
        for (p.log.items, 0..) |fr, i| switch (fr) {
            .headers => |id| if (id == sid) return i,
            else => {},
        };
        return null;
    }

    fn indexOfFirstConnWindowUpdate(p: *const TestPeer) ?usize {
        for (p.log.items, 0..) |fr, i| switch (fr) {
            .window_update => |wu| if (wu.stream_id == 0) return i,
            else => {},
        };
        return null;
    }

    fn init(gpa: Allocator, settings: h2.Settings) TestPeer {
        return .{ .gpa = gpa, .conn = .init(gpa, .client, .{ .settings = settings }) };
    }

    fn deinit(p: *TestPeer) void {
        for (p.resps.values()) |*c| c.deinit(p.gpa);
        p.resps.deinit(p.gpa);
        p.wu_stream.deinit(p.gpa);
        p.log.deinit(p.gpa);
        p.events.deinit(p.gpa);
        p.wire.deinit(p.gpa);
        p.conn.deinit();
    }

    /// Feed server→client bytes and fold the resulting events.
    fn feed(p: *TestPeer, bytes: []const u8) !void {
        try p.conn.recv(bytes, &p.wire, &p.events);
        try p.fold();
    }

    fn fold(p: *TestPeer) !void {
        for (p.events.items) |*ev| switch (ev.*) {
            .headers => |*hd| {
                const g = try p.resps.getOrPut(p.gpa, hd.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                if (g.value_ptr.headers == null) {
                    g.value_ptr.headers = hd.headers; // take ownership
                    g.value_ptr.headers_end_stream = hd.end_stream;
                    if (g.value_ptr.header(":status")) |v|
                        g.value_ptr.status = std.fmt.parseInt(u16, v, 10) catch 0;
                } else if (g.value_ptr.trailers == null) {
                    g.value_ptr.trailers = hd.headers; // the trailer section
                    g.value_ptr.trailers_end_stream = hd.end_stream;
                    g.value_ptr.data_frames_before_trailers = g.value_ptr.data_frames;
                } else hd.headers.deinit(p.gpa);
                if (hd.end_stream) g.value_ptr.end = true;
                try p.log.append(p.gpa, .{ .headers = hd.stream_id });
            },
            .data => |d| {
                const g = try p.resps.getOrPut(p.gpa, d.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                try g.value_ptr.body.appendSlice(p.gpa, d.data);
                g.value_ptr.data_frames += 1;
                if (d.end_stream) {
                    g.value_ptr.data_end_stream = true;
                    g.value_ptr.end = true;
                }
                try p.log.append(p.gpa, .{ .data = d.stream_id });
            },
            .stream_reset => |r| {
                const g = try p.resps.getOrPut(p.gpa, r.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                g.value_ptr.rst = r.code;
                g.value_ptr.end = true;
                try p.log.append(p.gpa, .{ .rst = r.stream_id });
            },
            .goaway => |g| p.goaway = g.code,
            .window_update => |wu| {
                if (wu.stream_id == 0) {
                    p.wu_conn += wu.increment;
                } else {
                    const g = try p.wu_stream.getOrPut(p.gpa, wu.stream_id);
                    if (!g.found_existing) g.value_ptr.* = 0;
                    g.value_ptr.* += wu.increment;
                }
                try p.log.append(p.gpa, .{ .window_update = .{
                    .stream_id = wu.stream_id,
                    .increment = wu.increment,
                } });
            },
            else => {},
        };
        p.events.clearRetainingCapacity();
    }

    fn resp(p: *TestPeer, sid: u31) *Collected {
        return p.resps.getPtr(sid).?;
    }

    /// Loopback plumbing: flush staged bytes / read+feed one batch.
    fn sendWire(p: *TestPeer, w: *Writer) !void {
        if (p.wire.items.len == 0) return;
        try w.writeAll(p.wire.items);
        try w.flush();
        p.wire.clearRetainingCapacity();
    }

    fn pumpSocket(p: *TestPeer, r: *Reader) !void {
        _ = try r.peekGreedy(1);
        const bytes = r.buffered();
        try p.conn.recv(bytes, &p.wire, &p.events);
        r.toss(bytes.len);
        try p.fold();
    }
};

const get_fields = [_]hpack.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/hello?x=1" },
    .{ .name = ":authority", .value = "t" },
};

fn fieldsFor(method: []const u8, path: []const u8) [4]hpack.Field {
    return .{
        .{ .name = ":method", .value = method },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "t" },
    };
}

/// Run `serve` offline over the client bytes staged in `peer.wire`, then
/// feed the server's output back to the peer. Returns nothing — assertions
/// read `peer.resps`/`peer.goaway`.
fn runOffline(peer: *TestPeer, opts: Options, out_buf: []u8) !void {
    var in: Reader = .fixed(peer.wire.items);
    var out: Writer = .fixed(out_buf);
    serve(testing.allocator, opts, &in, &out);
    peer.wire.clearRetainingCapacity();
    try peer.feed(out.buffered());
}

test "h2 DoS limits: the SHIPPED default values, written out as literals" {
    // Every h2 DoS test overrides the limit it exercises with its own tiny
    // value (`max_reset_streams = 4`, `max_header_block = 256`, ...), so the
    // suite pins the MECHANISM and nothing pinned the VALUE: all six
    // defaults could be weakened by 4-20 orders of magnitude with
    // `zig build test-http` fully green. These are the exposed product
    // surface — `Server.Options.h2_limits` hands them to every `enable_h2c`
    // consumer, and SPEC.md sells them as "safe by default".
    //
    // Each literal below is the delivered value, with where it comes from.
    const d: Limits = .{};

    // 100 concurrent streams: the SETTINGS_MAX_CONCURRENT_STREAMS value RFC
    // 9113 §6.5.2 recommends as a floor ("no smaller than 100") for peers
    // that impose a limit at all. NOT a worker bound — that is
    // `Dispatcher.max_concurrent_handlers` (8).
    try testing.expectEqual(@as(u32, 100), d.max_concurrent_streams);

    // 10 000 request streams per connection, then GOAWAY(NO_ERROR): stream
    // ids are 31-bit and never reused, so a connection must eventually be
    // retired; this is a graceful-recycle bound, not an attack bound.
    try testing.expectEqual(@as(u32, 10_000), d.max_streams_per_connection);

    // 100 rapid resets (CVE-2023-44487): one per concurrent stream we would
    // have admitted anyway, so a well-behaved client that cancels every
    // in-flight request still fits, while the "cancel and immediately
    // re-open, forever" pattern the CVE describes does not.
    try testing.expectEqual(@as(u32, 100), d.max_reset_streams);

    // 32 CONTINUATION frames per header sequence (CVE-2024-27316): with the
    // default 16 KiB SETTINGS_MAX_FRAME_SIZE that is ~512 KiB of frames for
    // one header block, far above any real request and far below "unbounded".
    try testing.expectEqual(@as(u32, 32), d.max_continuation_frames);

    // 1 MiB reassembled header block — the total-octets twin of the frame
    // count above, so zero-length CONTINUATIONs cannot dodge the size cap.
    try testing.expectEqual(@as(usize, 1 << 20), d.max_header_block);
    try testing.expectEqual(@as(usize, 1_048_576), d.max_header_block);

    // 1024 consecutive no-progress frames (PING/SETTINGS/PRIORITY/empty
    // DATA/unknown/unspent WINDOW_UPDATE) before GOAWAY(ENHANCE_YOUR_CALM);
    // any real progress resets it, so this is a burst allowance, not a rate.
    try testing.expectEqual(@as(u32, 1024), d.max_unproductive_frames);
}

test "h2 DoS limits: the shipped defaults are the values that actually reach the protocol core" {
    // A default is only a bound if it arrives at `h2.Connection`. This pins
    // the wiring `serve` uses, so a limit that quietly stops being passed
    // through fails here rather than in production.
    const co = connOptions(.{ .handler = testHandler });
    try testing.expectEqual(@as(u32, 100), co.settings.max_concurrent_streams.?);
    try testing.expectEqual(@as(usize, 1 << 20), co.max_header_block);
    try testing.expectEqual(@as(u32, 32), co.max_continuation_frames);
    try testing.expectEqual(@as(u32, 100), co.max_reset_streams);
    try testing.expectEqual(@as(u32, 1024), co.max_unproductive_frames);
    // ...and the h2 core's own defaults agree with what this layer ships,
    // so the two cannot drift apart unnoticed.
    const core: h2.Connection.Options = .{};
    try testing.expectEqual(@as(usize, 1 << 20), core.max_header_block);
    try testing.expectEqual(@as(u32, 32), core.max_continuation_frames);
    try testing.expectEqual(@as(u32, 100), core.max_reset_streams);
    try testing.expectEqual(@as(u32, 1024), core.max_unproductive_frames);

    // The re-export consumers actually configure (`Server.Options.h2_limits`)
    // must be the same struct with the same defaults — that field is how
    // every `enable_h2c` caller inherits all of the above.
    const via_server: Server.Options = .{ .handler = testHandler };
    try testing.expectEqual(@as(u32, 100), via_server.h2_limits.max_concurrent_streams);
    try testing.expectEqual(@as(u32, 10_000), via_server.h2_limits.max_streams_per_connection);
    try testing.expectEqual(@as(u32, 100), via_server.h2_limits.max_reset_streams);
    try testing.expectEqual(@as(u32, 32), via_server.h2_limits.max_continuation_frames);
    try testing.expectEqual(@as(usize, 1 << 20), via_server.h2_limits.max_header_block);
    try testing.expectEqual(@as(u32, 1024), via_server.h2_limits.max_unproductive_frames);
}

test "h2c serve: GET and POST round-trip through the shared handler (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid_get = try peer.conn.startStream(&peer.wire, &get_fields, true);
    const sid_post = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    try peer.conn.sendData(&peer.wire, sid_post, "ping pong h2", true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler, .server_name = "h2test" }, &out_buf);

    const get = peer.resp(sid_get);
    try testing.expectEqual(@as(u16, 200), get.status);
    try testing.expect(get.end);
    try testing.expectEqualStrings("hello", get.body.items);
    try testing.expectEqualStrings("text/plain", get.header("content-type").?);
    try testing.expectEqualStrings("x=1", get.header("x-query").?);
    try testing.expectEqualStrings("h2test", get.header("server").?);
    try testing.expectEqualStrings("5", get.header("content-length").?);
    // §8.2.2: no connection-specific headers cross into h2.
    try testing.expectEqual(@as(?[]const u8, null), get.header("connection"));
    try testing.expectEqual(@as(?[]const u8, null), get.header("transfer-encoding"));

    const post = peer.resp(sid_post);
    try testing.expectEqual(@as(u16, 200), post.status);
    try testing.expect(post.end);
    try testing.expectEqualStrings("ping pong h2", post.body.items);

    // Streams closed on both ends; no GOAWAY; client windows reconciled
    // (nothing left owed: all DATA was consumed and both bodies were tiny).
    try testing.expectEqual(h2.StreamState.closed, peer.conn.stream(sid_get).?.state);
    try testing.expectEqual(h2.StreamState.closed, peer.conn.stream(sid_post).?.state);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: an EncoderProvider's coding is negotiated per stream and given back (offline)" {
    // A pass-through coding: what is under test is the negotiation and the
    // loan, not a codec -- `Server.zig`'s tests cover the pipeline itself.
    const Pass = struct {
        acquired: u32 = 0,
        released: u32 = 0,
        finished: u32 = 0,
        fn begin(_: *anyopaque, dst: *Writer, _: ?u64) Writer.Error!*Writer {
            return dst;
        }
        fn finish(ctx: *anyopaque) Writer.Error!void {
            const p: *@This() = @ptrCast(@alignCast(ctx));
            p.finished += 1;
        }
        fn acquire(ctx: *anyopaque) ?Server.Encoder {
            const p: *@This() = @ptrCast(@alignCast(ctx));
            p.acquired += 1;
            return .{ .name = "x-pass", .ctx = ctx, .begin = begin, .finish = finish };
        }
        fn release(ctx: *anyopaque, _: Server.Encoder) void {
            const p: *@This() = @ptrCast(@alignCast(ctx));
            p.released += 1;
        }
    };
    const gpa = testing.allocator;
    var pass: Pass = .{};
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const base = fieldsFor("GET", "/hello");
    const wants = base ++ [_]hpack.Field{.{ .name = "accept-encoding", .value = "gzip, x-pass" }};
    const prefers_gzip = base ++ [_]hpack.Field{.{ .name = "accept-encoding", .value = "gzip, x-pass;q=0.1" }};
    const sid_pass = try peer.conn.startStream(&peer.wire, &wants, true);
    const sid_gzip = try peer.conn.startStream(&peer.wire, &prefers_gzip, true);
    const sid_none = try peer.conn.startStream(&peer.wire, &base, true);

    const scratch = try gpa.create(gzip.Scratch);
    defer gpa.destroy(scratch);
    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .compression = .{ .min_size = 1 },
        .gzip_scratch = scratch,
        .encoder_provider = .init("x-pass", &pass, Pass.acquire, Pass.release),
    }, &out_buf);

    const r = peer.resp(sid_pass);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expectEqualStrings("x-pass", r.header("content-encoding").?);
    try testing.expectEqualStrings("hello", r.body.items);
    try testing.expectEqualStrings("gzip", peer.resp(sid_gzip).header("content-encoding").?);
    try testing.expectEqual(@as(?[]const u8, null), peer.resp(sid_none).header("content-encoding"));
    try testing.expectEqual(@as(u32, 1), pass.acquired);
    try testing.expectEqual(@as(u32, 1), pass.released);
    try testing.expectEqual(@as(u32, 1), pass.finished);
}

test "h2c serve: handler error → 500; 404 and HEAD framing (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid_fail = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/fail"), true);
    const sid_404 = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/nope"), true);
    const sid_head = try peer.conn.startStream(&peer.wire, &fieldsFor("HEAD", "/hello"), true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    // Handler error: clean 500, the staged partial body is dropped.
    const fail = peer.resp(sid_fail);
    try testing.expectEqual(@as(u16, 500), fail.status);
    try testing.expect(fail.end);
    try testing.expectEqualStrings("Internal Server Error\n", fail.body.items);

    const missing = peer.resp(sid_404);
    try testing.expectEqual(@as(u16, 404), missing.status);
    try testing.expectEqualStrings("not found\n", missing.body.items);

    // HEAD: headers only (Content-Length included), END_STREAM, no DATA.
    const head = peer.resp(sid_head);
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expect(head.end);
    try testing.expectEqualStrings("5", head.header("content-length").?);
    try testing.expectEqual(@as(usize, 0), head.body.items.len);
    try testing.expectEqual(@as(u32, 0), head.data_frames);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: malformed requests → RST_STREAM(PROTOCOL_ERROR)/501, connection survives (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    // No :path (§8.3.1) → malformed → RST_STREAM(PROTOCOL_ERROR) (§8.1.1).
    const sid_nopath = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "t" },
    }, true);
    // Connection-specific header (§8.2.2) → malformed → reset.
    const sid_connhdr = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/hello" },
        .{ .name = "connection", .value = "keep-alive" },
    }, true);
    // content-length disagreeing with the DATA total (§8.1.1) → reset.
    const sid_badlen = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "content-length", .value = "99" },
    }, false);
    try peer.conn.sendData(&peer.wire, sid_badlen, "four", true);
    // Method outside the vocabulary → 501 (h1 parity).
    const sid_brew = try peer.conn.startStream(&peer.wire, &fieldsFor("BREW", "/pot"), true);
    // …and a valid request after all of them still gets served.
    const sid_ok = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    // A malformed request gets no response head at all -- the peer would
    // have to guess whether the HEADERS or the RST_STREAM is the answer.
    try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid_nopath).rst);
    try testing.expectEqual(@as(u16, 0), peer.resp(sid_nopath).status);
    try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid_connhdr).rst);
    try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid_badlen).rst);
    try testing.expectEqual(@as(u16, 501), peer.resp(sid_brew).status);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_ok).status);
    try testing.expectEqualStrings("hello", peer.resp(sid_ok).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

/// The four pseudo-headers of a GET plus one regular field — the shape every
/// §8.2.1 case below varies one byte of.
fn fieldsWith(path: []const u8, authority: []const u8, name: []const u8, value: []const u8) [5]hpack.Field {
    return .{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = authority },
        .{ .name = name, .value = value },
    };
}

test "h2c serve: RFC 9113 §8.2.1 — a CR/LF/NUL/control byte in a field, or a name that is not a lowercase token, is RST_STREAM(PROTOCOL_ERROR)" {
    // HPACK frames each field by length, so every one of these arrives
    // intact — and each used to be re-serialized into the handler's CRLF
    // header block byte for byte, where `"v\r\nx-injected: PWNED"` became a
    // real `x-injected` header and a CR in a NAME made the original field
    // vanish (measured 2026-09-04, A1 F1). The §8.2.1 rule is now enforced
    // before anything is rebuilt, and the request is malformed (§8.1.1).
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);

    const bad = [_][2][]const u8{
        .{ "x-benign", "v\r\nx-injected: PWNED" }, // CRLF in a value
        .{ "x-benign", "v\nx-injected: PWNED" }, // bare LF in a value
        .{ "x-benign", "v\rx" }, // bare CR in a value
        .{ "x-benign", "v\x00x" }, // NUL in a value
        .{ "x-benign", "v\x7fx" }, // DEL in a value
        .{ "x-benign", " v" }, // leading SP
        .{ "x-benign", "v\t" }, // trailing HTAB
        .{ "a\r\nx-injected2", "PWNED2" }, // CRLF in a name
        .{ "x benign", "v" }, // SP in a name
        .{ "x:benign", "v" }, // ':' in a name
        .{ "X-Benign", "v" }, // uppercase (was the only check, and unguarded)
        .{ "x-b\x80", "v" }, // non-ASCII in a name
    };
    var sids: [bad.len]u31 = undefined;
    for (bad, 0..) |case, i| {
        sids[i] = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", case[0], case[1]), true);
    }
    // The legal shapes right at the edge of the rule still serve: an
    // interior tab, obs-text, an empty value, and every tchar in a name.
    const sid_ok = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "x-ok!#$%&'*+.^_`|~", "a\tb \xc3\xa9"), true);
    const sid_empty = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "x-empty", ""), true);

    var out_buf: [16384]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    for (sids, 0..) |sid, i| {
        testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid).rst) catch |err| {
            std.debug.print("case {d} ({s}={s}) was not reset\n", .{ i, bad[i][0], bad[i][1] });
            return err;
        };
        try testing.expectEqual(@as(u16, 0), peer.resp(sid).status);
    }
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_ok).status);
    try testing.expectEqualStrings("path=/headers query= [host=t] [x-ok!#$%&'*+.^_`|~=a\tb \xc3\xa9]", peer.resp(sid_ok).body.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_empty).status);
    try testing.expectEqualStrings("path=/headers query= [host=t] [x-empty=]", peer.resp(sid_empty).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: pseudo-header values are held to the h1 request-line rules — :path/:authority/:method/:scheme with CR/LF/SP/NUL → RST_STREAM(PROTOCOL_ERROR)" {
    // `:path` used to be checked for `target[0] == '/'` and nothing else, so
    // `"/a\r\nX: y\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"`
    // reached the handler as `req.path` byte for byte — and through
    // `proxy.ProxyHandler`'s request line, the backend as a SECOND request
    // (A1 G1, CRITICAL). The same target on the h1 request line has always
    // been `MalformedHead`; the two paths now share the predicate.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);

    const smuggle = "/a\r\nX-Path-Injected: yes\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
    const sid_path_crlf = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", smuggle), true);
    const sid_path_lf = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/a\nx"), true);
    const sid_path_sp = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/a HTTP/1.1"), true);
    const sid_path_nul = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/a\x00b"), true);
    const sid_path_hi = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/caf\xc3\xa9"), true);
    const sid_auth_crlf = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/headers" },
        .{ .name = ":authority", .value = "front.example\r\nX-Authority-Injected: yes" },
    }, true);
    const sid_auth_sp = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/headers" },
        .{ .name = ":authority", .value = "a b" },
    }, true);
    const sid_auth_empty = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/headers" },
        .{ .name = ":authority", .value = "" },
    }, true);
    const sid_method = try peer.conn.startStream(&peer.wire, &fieldsFor("GE\r\nT", "/headers"), true);
    const sid_scheme = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "ht tp" },
        .{ .name = ":path", .value = "/headers" },
        .{ .name = ":authority", .value = "t" },
    }, true);
    // Control: the innocent neighbour of every case above still serves.
    const sid_ok = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/headers?q=1"), true);

    var out_buf: [16384]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    for ([_]u31{ sid_path_crlf, sid_path_lf, sid_path_sp, sid_path_nul, sid_path_hi, sid_auth_crlf, sid_auth_sp, sid_auth_empty, sid_method, sid_scheme }) |sid| {
        try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid).rst);
        try testing.expectEqual(@as(u16, 0), peer.resp(sid).status);
    }
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_ok).status);
    try testing.expectEqualStrings("path=/headers query=q=1 [host=t]", peer.resp(sid_ok).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: :path gets the h1 path guard — dot segments collapsed, %00 → 400, over the cap → 414, '*' outside OPTIONS → 400" {
    // On h1 these four have been enforced in `serveOne` since the router
    // existed; the h2 `:path` skipped all of them (A1 F13), so
    // `/public/../admin` routed on `..` and `%00` reached the handler.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);

    const sid_dotdot = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/public/../headers?a=1"), true);
    const sid_dot = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/./headers"), true);
    const sid_root_escape = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/../../headers"), true);
    // Percent-encoding is NOT decoded: `%2e%2e` stays a literal segment and
    // must NOT be walked as `..`.
    const sid_pct = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/x/%2e%2e/headers"), true);
    const sid_nul_pct = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/headers%00.txt"), true);
    const sid_nul_pct_uc = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/headers%00"), true);
    var long_path: [2 * 1024 + 1]u8 = undefined;
    @memset(&long_path, 'a');
    long_path[0] = '/';
    const sid_long = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", &long_path), true);
    const sid_star_get = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "*"), true);
    const sid_star_options = try peer.conn.startStream(&peer.wire, &fieldsFor("OPTIONS", "*"), true);

    var out_buf: [16384]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    try testing.expectEqual(@as(u16, 200), peer.resp(sid_dotdot).status);
    try testing.expectEqualStrings("path=/headers query=a=1 [host=t]", peer.resp(sid_dotdot).body.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_dot).status);
    try testing.expectEqualStrings("path=/headers query= [host=t]", peer.resp(sid_dot).body.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_root_escape).status); // clamped at root
    try testing.expectEqual(@as(u16, 404), peer.resp(sid_pct).status); // `/x/%2e%2e/headers`, literally
    try testing.expectEqual(@as(u16, 400), peer.resp(sid_nul_pct).status);
    try testing.expectEqual(@as(u16, 400), peer.resp(sid_nul_pct_uc).status);
    try testing.expectEqual(@as(u16, 414), peer.resp(sid_long).status);
    try testing.expectEqual(@as(u16, 400), peer.resp(sid_star_get).status);
    try testing.expectEqual(@as(u16, 404), peer.resp(sid_star_options).status); // reached the handler
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: a `host` field beside :authority must agree (§8.3.1), is written into the handler's block once, and stands in for a missing :authority" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);

    const sid_agree = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "T.example", "host", "t.example"), true);
    const sid_disagree = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t.example", "host", "other.example"), true);
    const sid_bad_host = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t.example", "host", "a b"), true);
    const sid_host_only = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/headers" },
        .{ .name = "host", .value = "alone.example" },
    }, true);

    var out_buf: [16384]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    try testing.expectEqual(@as(u16, 200), peer.resp(sid_agree).status);
    // One `host` line, spelled as `:authority` sent it — not two.
    try testing.expectEqualStrings("path=/headers query= [host=T.example]", peer.resp(sid_agree).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid_disagree).rst);
    try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid_bad_host).rst);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_host_only).status);
    try testing.expectEqualStrings("path=/headers query= [host=alone.example]", peer.resp(sid_host_only).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: h2 content-length is strict 1*DIGIT like h1's (F10) — leading `+`/`-`, embedded `_`, leading zero all rejected" {
    // `h1.parseContentLengthStrict` is called here (h2_server.zig) but had
    // no test on this path — only h1's own parser had one (A1 audit F10,
    // 2026-09-04). Regression M18 (swap it back for `std.fmt.parseInt`)
    // would let all four bad shapes through; this pins the strict parse.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);

    const sid_plus = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "content-length", "+5"), true);
    const sid_underscore = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "content-length", "1_0"), true);
    const sid_minus_zero = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "content-length", "-0"), true);
    const sid_hex = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "content-length", "0x5"), true);
    const sid_space = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "content-length", " 5"), true);
    // Positive control: a plain digit string, on an actually-empty body.
    const sid_ok = try peer.conn.startStream(&peer.wire, &fieldsWith("/headers", "t", "content-length", "0"), true);

    var out_buf: [16384]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    for ([_]u31{ sid_plus, sid_underscore, sid_minus_zero, sid_hex, sid_space }) |sid| {
        try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid).rst);
    }
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_ok).status);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: garbage after the preface → GOAWAY (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    // A correct preface magic followed by junk that is not a SETTINGS
    // frame ("GAR…" decodes as an absurd 24-bit length → FRAME_SIZE_ERROR).
    try peer.wire.appendSlice(gpa, h2.preface);
    try peer.wire.appendSlice(gpa, "GARBAGE-GARBAGE-GARBAGE");

    var out_buf: [1024]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.frame_size_error), peer.goaway);
    try testing.expectEqual(@as(usize, 0), peer.resps.count()); // nothing served
}

fn epochForErrorTest(_: ?*anyopaque) i64 {
    return 784111777; // RFC 9110 §5.6.7's example instant
}

test "h2c serve: the codec's own error answers carry date and server, as h1's do (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/drain"), false);
    try peer.conn.sendData(&peer.wire, sid, "x" ** 32, true);

    var out_buf: [2048]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .max_body_bytes = 8,
        .now = .{ .epochSeconds = epochForErrorTest },
        .server_name = "t/1",
    }, &out_buf);
    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 413), r.status);
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", r.header("date").?);
    try testing.expectEqualStrings("t/1", r.header("server").?);
    try testing.expectEqualStrings("text/plain", r.header("content-type").?);
}

test "h2c serve: request body over max_body_bytes → 413, connection closes (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/drain"), false);
    try peer.conn.sendData(&peer.wire, sid, "x" ** 32, true);

    var out_buf: [2048]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler, .max_body_bytes = 8 }, &out_buf);

    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 413), r.status);
    try testing.expect(r.end);
    try testing.expectEqualStrings("Content Too Large\n", r.body.items);
    // h1 parity: over-limit body ends the connection (graceful GOAWAY).
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.no_error), peer.goaway);

    // Exactly at the cap passes (fresh connection).
    var peer2: TestPeer = .init(gpa, .{});
    defer peer2.deinit();
    try peer2.conn.sendPreface(&peer2.wire);
    const sid2 = try peer2.conn.startStream(&peer2.wire, &fieldsFor("POST", "/drain"), false);
    try peer2.conn.sendData(&peer2.wire, sid2, "x" ** 8, true);
    try runOffline(&peer2, .{ .handler = testHandler, .max_body_bytes = 8 }, &out_buf);
    try testing.expectEqual(@as(u16, 200), peer2.resp(sid2).status);
    try testing.expectEqualStrings("drained 8", peer2.resp(sid2).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer2.goaway);
}

test "h2c serve: max_body_bytes is enforced CONNECTION-WIDE, not per stream (A1 http F2)" {
    // Before this fix, `onData` compared only the RECEIVING job's own bytes
    // to `max_body_bytes`, so with `Limits.max_concurrent_streams` streams
    // each individually under the cap, a connection could buffer that many
    // TIMES the cap at once. Two streams, 5 bytes each, cap 8: neither
    // stream's own total ever crosses 8, but the connection-wide total
    // (10) does the moment the second stream's chunk arrives.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/drain"), false);
    try peer.conn.sendData(&peer.wire, sid1, "x" ** 5, false); // 5 bytes, not yet complete
    const sid2 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/drain"), false);
    try peer.conn.sendData(&peer.wire, sid2, "y" ** 5, true); // 5 alone, but 5+5 > 8 connection-wide
    try peer.conn.sendData(&peer.wire, sid1, "", true); // complete stream 1 at exactly its own 5 bytes

    var out_buf: [2048]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler, .max_body_bytes = 8 }, &out_buf);

    try testing.expectEqual(@as(u16, 200), peer.resp(sid1).status);
    try testing.expectEqualStrings("drained 5", peer.resp(sid1).body.items);
    try testing.expectEqual(@as(u16, 413), peer.resp(sid2).status);
    try testing.expect(peer.resp(sid2).end);
}

test "h2c serve: stream error → RST_STREAM, connection keeps serving (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &get_fields, true);
    // Crafted DATA on the half-closed stream (the client API refuses to
    // send this, so encode it raw): a stream-scoped STREAM_CLOSED.
    try h2.encodeData(gpa, &peer.wire, sid1, "late", .{});
    // A later request behind the bad frame must still be served.
    const sid3 = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/hello"), true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    // The poisoned stream was reset with the layer's code…
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.stream_closed), peer.resp(sid1).rst);
    // …and the connection lived on to answer the next stream.
    try testing.expectEqual(@as(u16, 200), peer.resp(sid3).status);
    try testing.expectEqualStrings("hello", peer.resp(sid3).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

// ── DoS-hardening attack simulations (offline) ──────────────────────────────

/// Counts invocations through `Request.context` — proves handlers did (not)
/// run under attack, independent of what reached the wire.
fn countingHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    const runs: *usize = @ptrCast(@alignCast(req.context.?));
    runs.* += 1;
    try rw.writeAll("ok");
}

test "h2c serve: rapid reset (CVE-2023-44487) → GOAWAY(ENHANCE_YOUR_CALM), no handler ran" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    // Open-and-immediately-cancel, more times than the budget allows. None
    // of the streams ever completes, so no handler run is legitimate.
    try peer.conn.sendPreface(&peer.wire);
    for (0..6) |_| {
        const sid = try peer.conn.startStream(&peer.wire, &get_fields, false);
        try peer.conn.sendRstStream(&peer.wire, sid, .cancel);
    }

    var handler_runs: usize = 0;
    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{
        .handler = countingHandler,
        .context = &handler_runs,
        .limits = .{ .max_reset_streams = 4 },
    }, &out_buf);

    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.enhance_your_calm), peer.goaway);
    try testing.expectEqual(@as(usize, 0), handler_runs); // no unbounded work
}

test "h2c serve: CONTINUATION flood (CVE-2024-27316) → GOAWAY(ENHANCE_YOUR_CALM)" {
    const gpa = testing.allocator;
    { // Frame-count flood: endless zero-length CONTINUATIONs, no END_HEADERS.
        var peer: TestPeer = .init(gpa, .{});
        defer peer.deinit();
        try peer.conn.sendPreface(&peer.wire);
        try h2.encodeHeaders(gpa, &peer.wire, 1, &.{}, .{ .end_headers = false });
        for (0..10) |_| try h2.encodeContinuation(gpa, &peer.wire, 1, &.{}, false);
        var out_buf: [1024]u8 = undefined;
        try runOffline(&peer, .{
            .handler = testHandler,
            .limits = .{ .max_continuation_frames = 8 },
        }, &out_buf);
        try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.enhance_your_calm), peer.goaway);
        try testing.expectEqual(@as(usize, 0), peer.resps.count());
    }
    { // Size flood: the reassembled block crosses max_header_block.
        var peer: TestPeer = .init(gpa, .{});
        defer peer.deinit();
        try peer.conn.sendPreface(&peer.wire);
        try h2.encodeHeaders(gpa, &peer.wire, 1, &(.{0} ** 200), .{ .end_headers = false });
        try h2.encodeContinuation(gpa, &peer.wire, 1, &(.{0} ** 200), false);
        var out_buf: [1024]u8 = undefined;
        try runOffline(&peer, .{
            .handler = testHandler,
            .limits = .{ .max_header_block = 256 },
        }, &out_buf);
        try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.enhance_your_calm), peer.goaway);
    }
}

test "h2c serve: streams over SETTINGS_MAX_CONCURRENT_STREAMS → RST_STREAM(REFUSED_STREAM)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    // Three streams concurrently open against an advertised limit of 2:
    // the third must be refused, the two admitted ones served.
    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    const sid2 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    const sid3 = try peer.conn.startStream(&peer.wire, &get_fields, true);
    try peer.conn.sendData(&peer.wire, sid1, "one", true);
    try peer.conn.sendData(&peer.wire, sid2, "two", true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .limits = .{ .max_concurrent_streams = 2 },
    }, &out_buf);

    // The server advertised the limit in its SETTINGS…
    try testing.expectEqual(@as(?u32, 2), peer.conn.remote_settings.max_concurrent_streams);
    // …the excess stream was refused (retryable), the connection survived…
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.refused_stream), peer.resp(sid3).rst);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
    // …and the admitted streams were served normally.
    try testing.expectEqual(@as(u16, 200), peer.resp(sid1).status);
    try testing.expectEqualStrings("one", peer.resp(sid1).body.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid2).status);
    try testing.expectEqualStrings("two", peer.resp(sid2).body.items);
}

test "h2c serve: evict_idle_streams_on_capacity=false (default) still refuses — no behavior change" {
    // Pins that the F11 opt-in defaults to today's exact behavior: two
    // streams parked with HEADERS only (no DATA, no END_STREAM) at a limit
    // of 2, then a third arrives — refused, same as the
    // SETTINGS_MAX_CONCURRENT_STREAMS test above, WITHOUT setting the new
    // field at all (its default is what is under test here).
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    _ = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    const sid3 = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .limits = .{ .max_concurrent_streams = 2 },
    }, &out_buf);

    // sid1 is untouched (still parked, no response at all)...
    try testing.expect(!peer.resps.contains(sid1));
    // ...and sid3, the new stream, was refused rather than admitted.
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.refused_stream), peer.resp(sid3).rst);
}

test "h2c serve: evict_idle_streams_on_capacity=true evicts the oldest idle, no-progress stream" {
    // F11 (`~/CML/20260901-zig-libs-audit/A1/http.md`): "100 parked HEADERS
    // with no END_STREAM occupy every slot on the connection forever." Two
    // streams open HEADERS only (no DATA, no END_STREAM) against a limit of
    // 2 -- exactly that shape. A third, COMPLETE stream must evict the
    // OLDEST parked one (sid1) rather than being refused.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    const sid2 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    const sid3 = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .limits = .{ .max_concurrent_streams = 2, .evict_idle_streams_on_capacity = true },
    }, &out_buf);

    // sid1 (the oldest, still-parked stream) was evicted, retryable...
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.refused_stream), peer.resp(sid1).rst);
    // ...sid2 is untouched -- it never got DATA/END_STREAM either, so it is
    // STILL parked and got no response at all. This is what pins "oldest",
    // not just any idle job: if eviction picked sid2 instead, this would
    // fail.
    try testing.expect(!peer.resps.contains(sid2));
    // ...and sid3 was admitted into the freed slot and served normally.
    try testing.expectEqual(@as(u16, 200), peer.resp(sid3).status);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c serve: evict_idle_streams_on_capacity=true never evicts a stream that received body bytes" {
    // The eviction candidate set is "no progress at all" -- a stream that
    // has received even one DATA byte is excluded, even though it is not
    // yet complete/dispatched. Two streams at the limit: sid1 got a DATA
    // frame (no END_STREAM yet), sid2 is fully parked (HEADERS only). A
    // third stream should evict sid2 (the genuinely idle one), not sid1.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    try peer.conn.sendData(&peer.wire, sid1, "partial", false); // progress, not complete
    const sid2 = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    const sid3 = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .limits = .{ .max_concurrent_streams = 2, .evict_idle_streams_on_capacity = true },
    }, &out_buf);

    // sid1 (has body bytes, not idle) is untouched -- no response at all...
    try testing.expect(!peer.resps.contains(sid1));
    // ...sid2 (genuinely idle) was evicted instead...
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.refused_stream), peer.resp(sid2).rst);
    // ...and sid3 was admitted.
    try testing.expectEqual(@as(u16, 200), peer.resp(sid3).status);
}

test "h2c serve: PING flood → GOAWAY(ENHANCE_YOUR_CALM)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    for (0..20) |_| try peer.conn.sendPing(&peer.wire, .{0xaa} ** 8);

    var out_buf: [2048]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .limits = .{ .max_unproductive_frames = 8 },
    }, &out_buf);
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.enhance_your_calm), peer.goaway);
}

test "h2c serve: total-streams cap → graceful GOAWAY(NO_ERROR) after serving" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid1 = try peer.conn.startStream(&peer.wire, &get_fields, true);
    const sid2 = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .limits = .{ .max_streams_per_connection = 2 },
    }, &out_buf);

    // Both requests were answered, then the connection retired NO_ERROR —
    // a well-behaved client simply reconnects.
    try testing.expectEqual(@as(u16, 200), peer.resp(sid1).status);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid2).status);
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.no_error), peer.goaway);
}

test "h2c serve: legit request with CONTINUATIONs under the limit succeeds" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    // Force the client to fragment its header block into CONTINUATIONs
    // (test-only: a real peer could never advertise a max_frame_size < 16384).
    peer.conn.remote_settings.max_frame_size = 16;
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf); // default limits

    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
    try testing.expectEqualStrings("hello", peer.resp(sid).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

// ── response trailers (RFC 9113 §8.1) ───────────────────────────────────────

test "h2: a server_name that cannot go on the wire is dropped once, not sent and not fatal" {
    // `setHeader` rejects CR/LF/NUL at set time and is the only way into the
    // header table, so nothing a HANDLER sets can arrive malformed.
    // `server_name` comes straight from the caller and never goes through it --
    // and it used to be checked anyway, by accident, because the head was
    // serialised and parsed back. It is not serialised any more, so `serve`
    // checks it once per connection: the banner is dropped, the response is
    // served, and no second field appears out of the CRLF.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .server_name = "qap\r\nx-injected: yes",
    }, &out_buf);

    const c = peer.resps.getPtr(sid) orelse return error.NoResponse;
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expectEqualStrings("hello", c.body.items);
    // Neither the banner nor anything the CRLF could have framed out of it.
    try testing.expect(c.header("server") == null);
    try testing.expect(c.header("x-injected") == null);
}

test "h2: an uppercase field name from the handler reaches the wire lowercased (§8.2.1)" {
    // The handler sets `Content-Type`; h2 forbids uppercase in a field name.
    // The lowering happens in the response writer's own header storage, which
    // is the only memory it is allowed to write to -- hence a test that reads
    // the name off the wire rather than trusting the call.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resps.getPtr(sid) orelse return error.NoResponse;
    const hl = c.headers orelse return error.NoHeaders;
    var saw = false;
    for (hl.fields) |f| {
        for (f.name) |ch| try testing.expect(!std.ascii.isUpper(ch));
        if (std.mem.eql(u8, f.name, "content-type")) saw = true;
    }
    try testing.expect(saw);
}

test "h2: a mixed-case name set with setHeaderStatic reaches the wire lowercased, and the literal is untouched" {
    // The head lowers names in the writer's own storage. A static name is NOT
    // in that storage -- it is a string literal, read-only memory -- and the
    // first version asserted it never would be: one POST to a GET-only server
    // (whose 405 sets `Allow` this way) took a qap process down, an assert in
    // Debug and a write into .rodata in ReleaseFast.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/static-name"), true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 405), c.status);
    try testing.expectEqualStrings("GET, HEAD", c.header("allow").?);
    const hl = c.headers orelse return error.NoHeaders;
    for (hl.fields) |f| for (f.name) |ch| try testing.expect(!std.ascii.isUpper(ch));
}

test "h2: response trailers are a HEADERS frame AFTER the DATA frames (§8.1)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/outtrailers"), true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expectEqualStrings("hello", c.body.items);
    // The h1 chunked framing does NOT cross over: only the frame layer
    // delimits an h2 body.
    try testing.expectEqual(@as(?[]const u8, null), c.header("transfer-encoding"));
    // The advert does cross over (lowercased, §8.2.1).
    try testing.expectEqualStrings("X-Checksum, X-Rows", c.header("trailer").?);

    // The three END_STREAM placements, which is the whole framing rule:
    // not on the response HEADERS, not on the last DATA frame, only on the
    // trailer HEADERS. Leave it on DATA and a real peer (nghttp2) drops the
    // trailer frame without complaining — a failure mode that produces no
    // error anywhere, which is exactly why it is asserted explicitly.
    try testing.expect(!c.headers_end_stream);
    try testing.expect(!c.data_end_stream);
    try testing.expect(c.trailers_end_stream);

    try testing.expect(c.trailers != null);
    try testing.expect(c.data_frames_before_trailers > 0); // after the body, not before
    try testing.expectEqualStrings("deadbeef", c.trailer("x-checksum").?);
    try testing.expectEqualStrings("3", c.trailer("x-rows").?);
    // Lowercase on the wire, so the mixed-case handler spelling is gone.
    try testing.expectEqual(@as(?[]const u8, null), c.trailer("X-Checksum"));
    try testing.expect(c.end);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2: trailers on an empty body send no DATA frame at all" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/outtrailers-empty"), true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expectEqual(@as(u32, 0), c.data_frames);
    // Without trailers this response would have been a single HEADERS with
    // END_STREAM; the trailer section moves the flag one frame later.
    try testing.expect(!c.headers_end_stream);
    try testing.expect(c.trailers_end_stream);
    try testing.expectEqualStrings("deadbeef", c.trailer("x-checksum").?);
    try testing.expect(c.end);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2: a response without trailers is byte-framed exactly as before" {
    // Regression guard for the END_STREAM plumbing: the no-trailer path must
    // still put END_STREAM on the last DATA frame.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expect(c.trailers == null);
    try testing.expect(c.data_end_stream);
    try testing.expect(c.end);
}

test "h2: incoming request trailers reach the handler (§8.1 read side)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/reqtrailers"), false);
    try peer.conn.sendData(&peer.wire, sid, "Wikipedia", false);
    // The trailer section: a second HEADERS frame carrying END_STREAM.
    try peer.conn.sendHeaders(&peer.wire, sid, &.{
        .{ .name = "x-checksum", .value = "deadbeef" },
        .{ .name = "x-rows", .value = "2" },
    }, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    // Same `Request.trailer` surface the h1 chunked path uses, and the
    // case-insensitive lookup hides h2's lowercase wire names.
    try testing.expectEqualStrings("trailer=deadbeef count=2", c.body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2: a request trailer block with pseudo-headers is dropped, not surfaced" {
    // §8.1 forbids pseudo-headers in a trailer section, and a late
    // `:path`/`:method` would be a routing-override primitive — the whole
    // block is refused rather than filtered field by field.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/reqtrailers"), false);
    try peer.conn.sendData(&peer.wire, sid, "Wikipedia", false);
    try peer.conn.sendHeaders(&peer.wire, sid, &.{
        .{ .name = "x-checksum", .value = "deadbeef" },
        .{ .name = ":path", .value = "/admin" },
    }, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    // Nothing from that block reached the handler — not even the innocent
    // field that shared it.
    try testing.expectEqualStrings("trailer=none count=0", c.body.items);
    // …and the stream still completed normally (END_STREAM was honored).
    try testing.expect(c.end);
}

test "h2: a request trailer block with a §8.2.1-invalid field is dropped whole, like one with a pseudo-header" {
    // The trailer block is re-serialized into `Request.trailer`'s CRLF form
    // exactly as the header block is, so a CR/LF in a trailer value is the
    // same injection one stage later — and an uppercase or non-token name
    // is malformed by the same section.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid_crlf = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/reqtrailers"), false);
    try peer.conn.sendData(&peer.wire, sid_crlf, "Wikipedia", false);
    try peer.conn.sendHeaders(&peer.wire, sid_crlf, &.{
        .{ .name = "x-checksum", .value = "deadbeef\r\nx-injected: yes" },
    }, true);
    const sid_name = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/reqtrailers"), false);
    try peer.conn.sendData(&peer.wire, sid_name, "Wikipedia", false);
    try peer.conn.sendHeaders(&peer.wire, sid_name, &.{
        .{ .name = "X-Checksum", .value = "deadbeef" },
    }, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    for ([_]u31{ sid_crlf, sid_name }) |sid| {
        const c = peer.resp(sid);
        try testing.expectEqual(@as(u16, 200), c.status);
        try testing.expectEqualStrings("trailer=none count=0", c.body.items);
        try testing.expect(c.end);
    }
}

// ── incremental request body (Options.stream_request) ───────────────────────

/// The offline harness plus the streaming opt-in.
fn streamOpts() Options {
    return .{ .handler = testHandler, .stream_request = streamRoutes };
}

test "h2 streaming request: the handler runs at HEADERS, before END_STREAM" {
    // The decisive observation, and the one a "dispatch at END_STREAM after
    // all" mutation cannot survive: END_STREAM is NEVER sent on this stream,
    // so a request that has to be complete before the handler sees it can
    // never be answered at all.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-partial"), false);
    try peer.conn.sendData(&peer.wire, sid, "0123456789abcdef", false); // no END_STREAM

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, streamOpts(), &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expectEqualStrings("took 10", c.body.items);
    // …and the same request on the buffered surface is answered by nothing,
    // which is what makes the assertion above about *timing* rather than
    // about the route existing.
    var peer2: TestPeer = .init(gpa, .{});
    defer peer2.deinit();
    try peer2.conn.sendPreface(&peer2.wire);
    const sid2 = try peer2.conn.startStream(&peer2.wire, &fieldsFor("POST", "/echo"), false);
    try peer2.conn.sendData(&peer2.wire, sid2, "0123456789abcdef", false);
    try runOffline(&peer2, .{ .handler = testHandler }, &out_buf);
    try testing.expectEqual(@as(usize, 0), peer2.resps.count());
}

test "h2 streaming request: WINDOW_UPDATE follows consumption, not arrival" {
    // The mutation this exists for is the one the client work found: crediting
    // on ARRIVAL is consistent with everything our own loopback can see, and
    // even the *totals* agree (what the handler leaves unread is credited back
    // when the stream is released either way). Only the split between the two
    // windows, computed from the frames actually on the wire, tells them apart.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-partial"), false);
    try peer.conn.sendData(&peer.wire, sid, "x" ** 100, false);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, streamOpts(), &out_buf);

    try testing.expectEqualStrings("took 10", peer.resp(sid).body.items);
    // 100 octets arrived; the handler took 10. Stream-level credit is what
    // says "send me 10 more on THIS stream", and only 10 were freed:
    // arrival-driven crediting would say 100 here.
    try testing.expectEqual(@as(u64, 10), peer.streamCredit(sid));
    // The connection window gets all 100 back — 10 by consumption and the
    // other 90 as discarded octets when the stream was released (§6.9.1:
    // account for what you throw away, or the shared window leaks shut).
    try testing.expectEqual(@as(u64, 100), peer.wu_conn);
    // §8.1: the response was complete while the request body was not, so the
    // peer is told to stop — with NO_ERROR, which is not a failure.
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.no_error), peer.resp(sid).rst);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2 streaming request: a handler that never reads does not wedge the connection" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-ignore"), false);
    try peer.conn.sendData(&peer.wire, sid, "y" ** 500, false); // never ended
    // A second stream behind it must still be served.
    const sid2 = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, streamOpts(), &out_buf);

    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
    try testing.expectEqualStrings("ignored", peer.resp(sid).body.items);
    // Not one octet was consumed, so not one octet of STREAM credit was
    // returned — the peer is not invited to send more into a body nobody is
    // reading. The connection window, which every other stream shares, is
    // made whole instead.
    try testing.expectEqual(@as(u64, 0), peer.streamCredit(sid));
    try testing.expectEqual(@as(u64, 500), peer.wu_conn);
    // …and that connection credit was returned AFTER the response, when the
    // octets were actually discarded. Arrival-driven crediting would have
    // put it before the response HEADERS.
    const wu_at = peer.indexOfFirstConnWindowUpdate().?;
    const resp_at = peer.indexOfFirstHeaders(sid).?;
    try testing.expect(wu_at > resp_at);
    // The connection lived on and answered the next request.
    try testing.expectEqual(@as(u16, 200), peer.resp(sid2).status);
    try testing.expectEqualStrings("hello", peer.resp(sid2).body.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2 streaming request: trailers reach the same Request.trailer surface" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-count"), false);
    try peer.conn.sendData(&peer.wire, sid, "Wikipedia", false);
    // The trailer section arrives *after* the body, which on this surface
    // means after the handler has already started reading (§8.1).
    try peer.conn.sendHeaders(&peer.wire, sid, &.{
        .{ .name = "x-checksum", .value = "deadbeef" },
    }, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, streamOpts(), &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expectEqualStrings("streamed 9 in 1 reads trailer=deadbeef", c.body.items);
    // All 9 octets were consumed, so all 9 were credited back — connection
    // window only: the trailer HEADERS carried END_STREAM, and stream-level
    // credit on a stream that can never receive again is dead weight (the
    // same corollary `h2_client.readBody` states).
    try testing.expectEqual(@as(u64, 9), peer.wu_conn);
    try testing.expectEqual(@as(u64, 0), peer.streamCredit(sid));
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2 streaming request: max_body_bytes → 413, the connection survives" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-count"), false);
    try peer.conn.sendData(&peer.wire, sid, "z" ** 32, true);
    const sid2 = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    var opts = streamOpts();
    opts.max_body_bytes = 8;
    try runOffline(&peer, opts, &out_buf);

    // Same status as the buffered surface, reached the other way round: the
    // read fails at the cap instead of the body being weighed before dispatch.
    try testing.expectEqual(@as(u16, 413), peer.resp(sid).status);
    try testing.expectEqualStrings("Content Too Large\n", peer.resp(sid).body.items);
    // Unlike the buffered surface this does NOT have to end the connection:
    // the rest of the body is bounded by the window we are no longer
    // replenishing, so the stream can simply be abandoned.
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid2).status);
}

test "h2 streaming request: content-length disagreeing with the DATA total fails the stream" {
    // §8.1.1. The buffered surface answers 400 before the handler runs; the
    // streaming surface cannot know the total up front, so the rule is
    // enforced by the body reader — exactly where h1's ContentLengthReader
    // enforces it.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/stream-count" },
        .{ .name = "content-length", .value = "99" },
    }, false);
    try peer.conn.sendData(&peer.wire, sid, "four", true);

    var out_buf: [4096]u8 = undefined;
    try runOffline(&peer, streamOpts(), &out_buf);

    // The read failed and nothing had been sent, so it surfaces as a status
    // rather than a reset. (500, not 400: the handler is what failed, and by
    // then the choice of status is no longer the framing layer's to make.)
    try testing.expectEqual(@as(u16, 500), peer.resp(sid).status);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2 streaming request: opting one route in leaves every other route buffered" {
    // Requirement: the buffered surface must be preserved *exactly* for
    // anything that did not opt in, on a server where the opt-in is enabled.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    // `/echo` is not a `/stream-*` route: it must still get the
    // RST_STREAM(PROTOCOL_ERROR) that only a fully collected body can
    // produce (§8.1.1) -- the content-length check needs the whole body.
    const sid_bad = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "content-length", .value = "99" },
    }, false);
    try peer.conn.sendData(&peer.wire, sid_bad, "four", true);
    const sid_ok = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/echo"), false);
    // Two frames, so the credit for the first is observable while the body
    // is still open.
    try peer.conn.sendData(&peer.wire, sid_ok, "buffered", false);
    try peer.conn.sendData(&peer.wire, sid_ok, " still", true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, streamOpts(), &out_buf);

    try testing.expectEqual(@as(?h2.ErrorCode, .protocol_error), peer.resp(sid_bad).rst);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_ok).status);
    try testing.expectEqualStrings("buffered still", peer.resp(sid_ok).body.items);
    // A buffered body is still credited on ARRIVAL: 8 octets of stream
    // credit were handed back while the request was still incomplete and
    // no handler had run, so nothing had consumed them. It has to work this
    // way — consumption-driven crediting here would withhold exactly the
    // credit the peer needs to send the END_STREAM the dispatch waits for,
    // and deadlock every upload above the initial window.
    try testing.expectEqual(@as(u64, 8), peer.streamCredit(sid_ok));
    // Every octet either stream got is back on the connection window: 14
    // here plus the 4 the malformed stream sent before its reset.
    try testing.expectEqual(@as(u64, 18), peer.wu_conn);
}

// ── incremental response body ───────────────────────────────────────────────

test "h2 streaming response: body reaches the wire before the handler returns" {
    // `/bigfail` writes 8 KiB (past `response_buffer_size`) and only then
    // fails. If the response were staged whole, nothing would have been sent
    // and the failure would be rewritten into a clean 500 — which is exactly
    // what `/fail` (7 bytes, still inside the buffer) still gets. Here the
    // head and part of the body are already gone, so the only honest answer
    // left is to kill the stream.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/bigfail"), true);

    var out_buf: [32768]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status); // the head went out as 200
    try testing.expect(c.body.items.len != 0);
    try testing.expect(std.mem.startsWith(u8, long_body, c.body.items));
    try testing.expectEqual(@as(?h2.ErrorCode, h2.ErrorCode.internal_error), c.rst);
    // Just this stream died; the connection is fine.
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2 streaming response: a body inside the buffer is framed exactly as before" {
    // The lookahead in `Framer` exists for this: a response that fits
    // `response_buffer_size` must still be HEADERS + ONE DATA frame carrying
    // END_STREAM, byte for byte what the stage-then-re-frame path produced.
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &get_fields, true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{ .handler = testHandler }, &out_buf);

    const c = peer.resp(sid);
    try testing.expectEqualStrings("hello", c.body.items);
    try testing.expectEqual(@as(u32, 1), c.data_frames);
    try testing.expect(!c.headers_end_stream);
    try testing.expect(c.data_end_stream);
    try testing.expectEqualStrings("5", c.header("content-length").?);
}

// ── loopback integration (Server.enable_h2c end to end) ─────────────────────

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

fn bindOrSkip(server: *Server) !void {
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
}

test "detach: the handler returns, the hook pushes and ends the stream cleanly" {
    const gpa = testing.allocator;
    const T = struct {
        var sid_g: ?u32 = null;
        var hook_calls: u32 = 0;

        fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
            sid_g = req.stream_id;
            rw.setStatus(200);
            try rw.setHeader("Content-Type", "text/event-stream");
            try rw.writer().writeAll("retry: 1000\n\n");
            try rw.flush();
            rw.detach();
        }

        fn idle(_: ?*anyopaque, d: Detached) IdleVerdict {
            hook_calls += 1;
            const id: u31 = @intCast(sid_g.?);
            d.push(id, "data: 1\n\n") catch unreachable;
            d.push(id, "data: 2\n\n") catch unreachable;
            d.close(id);
            d.flush() catch {};
            return .proceed;
        }
    };
    T.sid_g = null;
    T.hook_calls = 0;

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/sse"), true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{
        .handler = T.handler,
        .on_detached_idle = T.idle,
    }, &out_buf);

    // The handler's flush reached the wire before it returned; the hook's
    // pushes followed on the SAME stream, and `close` ended it with a clean
    // END_STREAM rather than a reset.
    try testing.expectEqual(@as(?u32, sid), T.sid_g);
    try testing.expectEqual(@as(u32, 1), T.hook_calls);
    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expectEqualStrings("text/event-stream", r.header("content-type").?);
    try testing.expectEqualStrings("retry: 1000\n\ndata: 1\n\ndata: 2\n\n", r.body.items);
    try testing.expect(r.end);
    try testing.expect(r.data_end_stream);
    try testing.expectEqual(@as(?h2.ErrorCode, null), r.rst);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "detach: an exhausted stream window answers WouldBlock, never queues" {
    const gpa = testing.allocator;
    const T = struct {
        var sid_g: ?u32 = null;
        var would_block: bool = false;

        fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
            sid_g = req.stream_id;
            rw.setStatus(200);
            // Exactly the client's whole 13-octet stream window, so the
            // hook finds it at zero.
            try rw.writer().writeAll("retry: 1000\n\n");
            try rw.flush();
            rw.detach();
        }

        fn idle(_: ?*anyopaque, d: Detached) IdleVerdict {
            const id: u31 = @intCast(sid_g.?);
            // The hook cannot return an error, so the window observation is
            // folded into the flag the test asserts on.
            if (d.writable(id) != 0) return .close;
            d.push(id, "data: x\n\n") catch |err| {
                would_block = err == error.WouldBlock;
            };
            // END_STREAM on an empty DATA frame needs no window credit.
            d.close(id);
            d.flush() catch {};
            return .proceed;
        }
    };
    T.sid_g = null;
    T.would_block = false;

    var peer: TestPeer = .init(gpa, .{ .initial_window_size = 13 });
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/sse"), true);

    var out_buf: [8192]u8 = undefined;
    try runOffline(&peer, .{
        .handler = T.handler,
        .on_detached_idle = T.idle,
    }, &out_buf);

    try testing.expect(T.would_block);
    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expectEqualStrings("retry: 1000\n\n", r.body.items);
    try testing.expect(r.end); // the close still landed
}

test "detach integration: a peer reset is reported through takeClosed" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const T = struct {
        var sid_g: ?u32 = null;
        var closed_seen: ?u31 = null;

        fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
            sid_g = req.stream_id;
            rw.setStatus(200);
            try rw.writer().writeAll("retry: 1000\n\n");
            try rw.flush();
            rw.detach();
        }

        fn idle(_: ?*anyopaque, d: Detached) IdleVerdict {
            if (d.takeClosed()) |id| {
                closed_seen = id;
                return .close; // nothing left to serve: end the connection
            }
            // Nothing to push: hand the loop back to the socket and wait
            // for the peer (this test: for its RST_STREAM).
            return .proceed;
        }

        fn serveConn(server: *std.Io.net.Server, sio: std.Io) void {
            const stream = server.accept(sio) catch return;
            defer stream.close(sio);
            var rbuf: [8192]u8 = undefined;
            var wbuf: [8192]u8 = undefined;
            var sr = stream.reader(sio, &rbuf);
            var sw = stream.writer(sio, &wbuf);
            serveStream(testing.allocator, &sr.interface, &sw.interface, null, .{
                .handler = handler,
                .on_detached_idle = idle,
            });
        }
    };
    T.sid_g = null;
    T.closed_seen = null;

    const addr = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    var listener = addr.listen(io, .{ .mode = .stream, .reuse_address = true }) catch |err| {
        std.debug.print("loopback listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const thread = try std.Thread.spawn(.{}, T.serveConn, .{ &listener, io });
    defer thread.join();

    const stream = listener.socket.address.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [8192]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/sse"), true);
    try peer.sendWire(&sw.interface);

    // Wait for the detached response's first bytes, so the reset lands on a
    // stream the server has already detached.
    while (peer.resps.getPtr(sid) == null or peer.resp(sid).body.items.len == 0) {
        try peer.pumpSocket(&sr.interface);
    }
    try peer.conn.sendRstStream(&peer.wire, sid, .cancel);
    try peer.sendWire(&sw.interface);

    // The server notices the reset, reports it to the hook, and the hook's
    // `.close` verdict ends the connection with a graceful GOAWAY.
    while (peer.goaway == null) {
        peer.pumpSocket(&sr.interface) catch break; // EOF after GOAWAY is fine
    }
    try testing.expectEqual(@as(?h2.ErrorCode, .no_error), peer.goaway);
    try testing.expectEqual(@as(?u31, @intCast(sid)), T.closed_seen);
}

test "h2c integration: the same handler serves HTTP/1.1 and HTTP/2 over loopback" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.init(io, gpa, .{ .handler = testHandler, .enable_h2c = true });
    defer server.deinit();
    try bindOrSkip(&server);
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const addr = server.boundAddress();

    var h1_body_buf: [64]u8 = undefined;
    var h1_body: []const u8 = undefined;
    { // HTTP/1.1 — detection must fall through untouched.
        const stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        defer stream.close(io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        try sw.interface.writeAll("GET /hello?x=1 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        try sw.interface.flush();
        var head_buf: [2048]u8 = undefined;
        const res = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        // `content_length` is `?u64` at the protocol layer; this test reads a
        // short literal body straight into `h1_body_buf` (`[64]u8`), so
        // narrowing to `usize` here -- both for the array slice bound and
        // for `Reader.take`'s argument -- is safe by construction.
        const n: usize = @intCast(res.content_length.?);
        @memcpy(h1_body_buf[0..n], try sr.interface.take(n));
        h1_body = h1_body_buf[0..n];
    }

    { // HTTP/2 via prior knowledge on a fresh connection — same handler.
        const stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        defer stream.close(io);
        var rbuf: [8192]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);

        var peer: TestPeer = .init(gpa, .{});
        defer peer.deinit();
        try peer.conn.sendPreface(&peer.wire);
        const sid_hello = try peer.conn.startStream(&peer.wire, &get_fields, true);
        const sid_meta = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/meta"), true);
        try peer.sendWire(&sw.interface);

        while (peer.resps.getPtr(sid_meta) == null or !peer.resp(sid_meta).end or
            !peer.resp(sid_hello).end)
        {
            try peer.pumpSocket(&sr.interface);
            try peer.sendWire(&sw.interface); // ACKs
        }

        const hello = peer.resp(sid_hello);
        try testing.expectEqual(@as(u16, 200), hello.status);
        try testing.expectEqualStrings("text/plain", hello.header("content-type").?);
        try testing.expectEqualStrings("x=1", hello.header("x-query").?);
        // The exact same handler produced the exact same body on both protocols.
        try testing.expectEqualStrings(h1_body, hello.body.items);

        // Hardening plumbing carried over: peer address, per-connection
        // request index (second stream on this connection → #1), and the
        // :authority → host mapping.
        const meta = peer.resp(sid_meta);
        try testing.expectEqual(@as(u16, 200), meta.status);
        try testing.expect(std.mem.startsWith(u8, meta.body.items, "127.0.0.1:"));
        try testing.expect(std.mem.endsWith(u8, meta.body.items, " #1 host=t"));
    }
}

test "h2c integration: response body honors the client's flow-control window" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.init(io, gpa, .{ .handler = testHandler, .enable_h2c = true });
    defer server.deinit();
    try bindOrSkip(&server);
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [8192]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // Advertise a 64-octet stream window: the 256-byte body can only cross
    // after WINDOW_UPDATE grants — the server must wait, not overrun.
    var peer: TestPeer = .init(gpa, .{ .initial_window_size = 64 });
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("GET", "/big"), true);
    try peer.sendWire(&sw.interface);

    var granted: usize = 0;
    while (peer.resps.getPtr(sid) == null or !peer.resp(sid).end) {
        try peer.pumpSocket(&sr.interface);
        if (peer.resps.getPtr(sid)) |c| {
            const got = c.body.items.len;
            if (got > granted) {
                const inc: u31 = @intCast(got - granted);
                // Replenish the connection window always, the stream window
                // only while the stream is still open for receiving.
                try peer.conn.sendWindowUpdate(&peer.wire, 0, inc);
                if (!c.end) try peer.conn.sendWindowUpdate(&peer.wire, sid, inc);
                granted = got;
            }
        }
        try peer.sendWire(&sw.interface);
    }

    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expectEqualStrings(big_body, r.body.items);
    // The 64-octet window forced the body into several DATA frames.
    try testing.expect(r.data_frames >= 4);
    // Windows reconcile: everything received was granted back, so the
    // connection receive window is back at its initial value.
    try testing.expectEqual(
        @as(i64, h2.default_initial_window_size),
        peer.conn.conn_recv_window,
    );
}

test "h2c integration: large POST body streams past the 64 KiB initial window" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.init(io, gpa, .{
        .handler = testHandler,
        .enable_h2c = true,
        .max_body_bytes = 1 << 20,
    });
    defer server.deinit();
    try bindOrSkip(&server);
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/drain"), false);
    try peer.sendWire(&sw.interface);

    // 100 000 bytes — more than the 65 535-octet initial window, so the
    // upload stalls until the server replenishes via WINDOW_UPDATE.
    const req_body = try gpa.alloc(u8, 100_000);
    defer gpa.free(req_body);
    @memset(req_body, 'b');
    var off: usize = 0;
    while (off < req_body.len) {
        const st = peer.conn.stream(sid).?;
        const win = @min(peer.conn.conn_send_window, st.send_window);
        if (win <= 0) {
            try peer.pumpSocket(&sr.interface); // wait for the server's grants
            continue;
        }
        const n = @min(req_body.len - off, @as(usize, @intCast(win)));
        try peer.conn.sendData(&peer.wire, sid, req_body[off..][0..n], off + n == req_body.len);
        try peer.sendWire(&sw.interface);
        off += n;
    }

    while (peer.resps.getPtr(sid) == null or !peer.resp(sid).end) {
        try peer.pumpSocket(&sr.interface);
        try peer.sendWire(&sw.interface);
    }
    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
    try testing.expectEqualStrings("drained 100000", peer.resp(sid).body.items);
}

test "h2c integration: request and response stream on ONE stream at the same time" {
    // Requirement: both directions live at once. The client sends a chunk
    // and then WAITS for its echo before sending the next one — which can
    // only complete if the handler is reading request DATA and writing
    // response DATA on the same still-open stream, interleaved.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.init(io, gpa, .{
        .handler = testHandler,
        .enable_h2c = true,
        .h2_stream_request = streamRoutes,
    });
    defer server.deinit();
    try bindOrSkip(&server);
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [8192]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-echo"), false);
    try peer.sendWire(&sw.interface);

    const chunks = [_][]const u8{ "alpha", "bravo", "charlie" };
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(gpa);
    for (chunks) |chunk| {
        try peer.conn.sendData(&peer.wire, sid, chunk, false);
        try peer.sendWire(&sw.interface);
        try expected.appendSlice(gpa, chunk);
        // Block until THIS chunk has come back, before the next goes out.
        while (peer.resps.getPtr(sid) == null or
            peer.resp(sid).body.items.len < expected.items.len)
        {
            try peer.pumpSocket(&sr.interface);
            try peer.sendWire(&sw.interface);
        }
        try testing.expectEqualStrings(expected.items, peer.resp(sid).body.items);
        // The request stream is still open in both directions: the response
        // has not ended, and we have not finished sending.
        try testing.expect(!peer.resp(sid).end);
    }

    // Now end the request body; the response ends behind it.
    try peer.conn.sendData(&peer.wire, sid, "", true);
    try peer.sendWire(&sw.interface);
    while (!peer.resp(sid).end) {
        try peer.pumpSocket(&sr.interface);
        try peer.sendWire(&sw.interface);
    }
    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
    try testing.expectEqualStrings("alphabravocharlie", peer.resp(sid).body.items);
    // Three flushes ⇒ at least three DATA frames: the response was NOT
    // coalesced into one frame at the end.
    try testing.expect(peer.resp(sid).data_frames >= 3);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
}

test "h2c integration: a streaming upload past the initial window, read as it lands" {
    // The consumption-driven WINDOW_UPDATE policy has to actually work: with
    // no replenishment at all this upload stalls at 65 535 octets forever.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.init(io, gpa, .{
        .handler = testHandler,
        .enable_h2c = true,
        .max_body_bytes = 1 << 20,
        .h2_stream_request = streamRoutes,
    });
    defer server.deinit();
    try bindOrSkip(&server);
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer stream.close(io);
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/stream-count"), false);
    try peer.sendWire(&sw.interface);

    const total = 200_000; // ≫ the 65 535-octet initial window
    const req_body = try gpa.alloc(u8, total);
    defer gpa.free(req_body);
    @memset(req_body, 'q');
    var off: usize = 0;
    while (off < req_body.len) {
        const st = peer.conn.stream(sid).?;
        const win = @min(peer.conn.conn_send_window, st.send_window);
        if (win <= 0) {
            try peer.pumpSocket(&sr.interface); // wait for the handler's grants
            continue;
        }
        const n = @min(req_body.len - off, @as(usize, @intCast(win)));
        try peer.conn.sendData(&peer.wire, sid, req_body[off..][0..n], off + n == req_body.len);
        try peer.sendWire(&sw.interface);
        off += n;
    }
    while (peer.resps.getPtr(sid) == null or !peer.resp(sid).end) {
        try peer.pumpSocket(&sr.interface);
        try peer.sendWire(&sw.interface);
    }
    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
    // Byte-exact, and delivered in many reads — the handler saw it arrive
    // rather than receiving it in one piece at the end.
    const body = peer.resp(sid).body.items;
    try testing.expect(std.mem.startsWith(u8, body, "streamed 200000 in "));
    const reads_at = "streamed 200000 in ".len;
    const reads_end = std.mem.indexOfScalarPos(u8, body, reads_at, ' ').?;
    const reads = try std.fmt.parseInt(u32, body[reads_at..reads_end], 10);
    try testing.expect(reads > 1);
}

test "h2c integration: detection — near-miss preface and disabled h2c take the h1 path" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // enable_h2c on: bytes that diverge from the preface mid-way go h1
    // (the h1 parser answers 505 to "PRI * HTTP/2.0").
    {
        var server = Server.init(io, gpa, .{ .handler = testHandler, .enable_h2c = true });
        defer server.deinit();
        try bindOrSkip(&server);
        const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
        defer thread.join();
        defer server.shutdown();
        const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        defer stream.close(io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        try sw.interface.writeAll("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n"); // not "SM"
        try sw.interface.flush();
        var head_buf: [1024]u8 = undefined;
        const res = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
        try testing.expectEqual(@as(u16, 505), res.status);
    }

    // enable_h2c off (the default): even a perfect preface is plain h1
    // bytes — current behavior byte-for-byte (505, no h2 anywhere).
    {
        var server = Server.init(io, gpa, .{ .handler = testHandler });
        defer server.deinit();
        try bindOrSkip(&server);
        const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
        defer thread.join();
        defer server.shutdown();
        const stream = server.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        defer stream.close(io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        try sw.interface.writeAll(h2.preface);
        try sw.interface.flush();
        var head_buf: [1024]u8 = undefined;
        const res = try h1.ResponseHead.parse(try h1.readHead(&sr.interface, &head_buf));
        try testing.expectEqual(@as(u16, 505), res.status);
    }
}

// ── concurrent handlers (`Options.dispatcher`) ──────────────────────────────
//
// Real threads throughout: the five invariants the module doc lists exist
// only because two handlers can be inside the session at once, so nothing
// short of a real pool exercises them. `workerpool` is a TEST-only dependency
// of `http` (see build.zig) — the published module implements no pool, only
// the seam.
//
// ⚠ Timing discipline. Every rendezvous here is a *gate*: a thread waits for
// a fact another thread publishes (an atomic flag), never for a duration. The
// only wall-clock numbers are (a) `gate_timeout_ms`, which exists so that a
// regression fails the suite instead of hanging it — it is never reached by a
// passing run — and (b) the 300 ms sleep in the overlap measurement, which
// reproduces the original F3 measurement and whose assertion has that whole
// 300 ms as its margin.

const workerpool = @import("workerpool");

/// How long a gate waits before declaring the run deadlocked. Only the
/// FAILURE path ever observes this, so it is deliberately enormous.
const gate_timeout_ms: u64 = 30_000;

fn nowNs(io: std.Io) i96 {
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}

/// Block until `flag` is set. Returns `error.GateTimeout` rather than
/// spinning forever, so a broken run fails loudly instead of wedging CI.
fn awaitFlag(io: std.Io, flag: *std.atomic.Value(bool)) error{GateTimeout}!void {
    const deadline = nowNs(io) + @as(i96, gate_timeout_ms) * std.time.ns_per_ms;
    while (!flag.load(.acquire)) {
        if (nowNs(io) >= deadline) return error.GateTimeout;
        std.Thread.yield() catch std.atomic.spinLoopHint();
    }
}

// `c`/`n` are `usize`, not `u64`: the only counter ever passed here is
// `FrameWatcher.data_bytes`, a private test-harness tally of bytes written
// into an in-memory `std.ArrayList(u8)` -- inherently `usize`-bounded, since
// you cannot buffer more than `usize` bytes in the first place. A `u64` here
// would also hit wasm32-baseline's lack of 64-bit atomic RMW/load support
// (`@atomicLoad`/`@atomicRmw` cap out at the target's register width); the
// widest real use is `2 * fc_body_len` (192 KiB), nowhere near overflowing
// even a 32-bit `usize`.
fn awaitAtLeast(io: std.Io, c: *std.atomic.Value(usize), n: usize) error{GateTimeout}!void {
    const deadline = nowNs(io) + @as(i96, gate_timeout_ms) * std.time.ns_per_ms;
    while (c.load(.acquire) < n) {
        if (nowNs(io) >= deadline) return error.GateTimeout;
        std.Thread.yield() catch std.atomic.spinLoopHint();
    }
}

fn awaitCount(io: std.Io, c: *std.atomic.Value(u32), n: u32) error{GateTimeout}!void {
    const deadline = nowNs(io) + @as(i96, gate_timeout_ms) * std.time.ns_per_ms;
    while (c.load(.acquire) < n) {
        if (nowNs(io) >= deadline) return error.GateTimeout;
        std.Thread.yield() catch std.atomic.spinLoopHint();
    }
}

/// The reference `Dispatcher` implementation — `modules/workerpool` plus the
/// **global** admission cap. The split is deliberate and is the owner ruling:
/// the per-connection cap is `Dispatcher.max_concurrent_handlers` and the
/// server enforces it (a stream over it waits in the already-bounded jobs
/// map); the global cap belongs to whoever owns the pool, because it is the
/// only place that can see every connection at once. Defaults from the
/// ruling: per-connection 8, global 4 × CPU count.
const PoolDispatcher = struct {
    gpa: Allocator,
    pool: *workerpool.WorkerPool,
    global_cap: u32,
    live: std.atomic.Value(u32) = .init(0),

    /// One dispatched handler: the caller's task plus the back-pointer that
    /// releases its global slot when it finishes.
    const Slot = struct { d: *PoolDispatcher, task: Task };

    fn defaultGlobalCap() u32 {
        const cpus = std.Thread.getCpuCount() catch 1;
        return @intCast(@max(1, cpus * 4));
    }

    fn init(gpa: Allocator, io: std.Io, workers: usize, cap: u32) !PoolDispatcher {
        return .{
            .gpa = gpa,
            .pool = try workerpool.WorkerPool.init(gpa, .{ .io = io, .n_workers = workers }),
            .global_cap = cap,
        };
    }

    fn deinit(d: *PoolDispatcher) void {
        d.pool.drain();
        d.pool.deinit();
    }

    fn iface(d: *PoolDispatcher, per_conn: u32) Dispatcher {
        return .{ .ctx = d, .spawn = spawn, .max_concurrent_handlers = per_conn };
    }

    fn spawn(ctx: ?*anyopaque, task: Task) bool {
        const d: *PoolDispatcher = @ptrCast(@alignCast(ctx.?));
        // Reserve the global slot BEFORE enqueueing, so "the pool is full"
        // is answered by refusing (false → RST_STREAM(REFUSED_STREAM)) and
        // never by growing a queue behind a saturated pool.
        while (true) {
            const cur = d.live.load(.monotonic);
            if (cur >= d.global_cap) return false;
            if (d.live.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) break;
        }
        const slot = d.gpa.create(Slot) catch {
            _ = d.live.fetchSub(1, .acq_rel);
            return false;
        };
        slot.* = .{ .d = d, .task = task };
        d.pool.submit(.{ .func = runSlot, .ctx = slot }) catch {
            d.gpa.destroy(slot);
            _ = d.live.fetchSub(1, .acq_rel);
            return false;
        };
        return true;
    }

    fn runSlot(ctx: *anyopaque) void {
        const slot: *Slot = @ptrCast(@alignCast(ctx));
        const d = slot.d;
        const task = slot.task;
        d.gpa.destroy(slot);
        task.func(task.ctx);
        _ = d.live.fetchSub(1, .acq_rel);
    }
};

/// A `Reader` that releases the client's bytes in *stages*, each gated on a
/// fact the server must publish first. This is what makes "the reading side
/// keeps working while a handler is blocked" testable without a socket and
/// without a sleep: stage N+1 simply does not exist on the wire until the
/// server has demonstrably reached the state stage N was supposed to cause.
const StagedReader = struct {
    io: std.Io,
    stages: []const Stage,
    idx: usize = 0,
    off: usize = 0,
    reader: Reader,

    const Stage = struct {
        /// Withhold these bytes until the flag is set (null = no flag gate).
        gate: ?*std.atomic.Value(bool) = null,
        /// Withhold them until `counter` reaches `at_least` — the shape a
        /// flow-control test needs, where the fact being waited for is "the
        /// server has spent N octets of window", not a boolean. A stage with
        /// empty `bytes` is then a pure barrier (useful as the last stage, to
        /// keep EOF from racing the workers).
        counter: ?*std.atomic.Value(usize) = null, // see awaitAtLeast's comment
        at_least: usize = 0,
        /// Withhold them until this event is set — the gate the fiber tests
        /// use: waiting on it parks the reading fiber, where the two gates
        /// above would spin the one thread every fiber shares.
        event: ?*std.Io.Event = null,
        bytes: []const u8,
    };

    fn init(io: std.Io, stages: []const Stage, buffer: []u8) StagedReader {
        return .{
            .io = io,
            .stages = stages,
            .reader = .{ .vtable = &.{ .stream = streamFn }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const sr: *StagedReader = @alignCast(@fieldParentPtr("reader", r));
        while (true) {
            if (sr.idx >= sr.stages.len) return error.EndOfStream;
            const st = sr.stages[sr.idx];
            if (sr.off == 0) {
                if (st.gate) |g| awaitFlag(sr.io, g) catch return error.ReadFailed;
                if (st.counter) |c|
                    awaitAtLeast(sr.io, c, st.at_least) catch return error.ReadFailed;
                if (st.event) |e| e.waitUncancelable(sr.io);
            }
            const src = limit.sliceConst(st.bytes[sr.off..]);
            if (src.len == 0) {
                sr.idx += 1;
                sr.off = 0;
                continue;
            }
            try w.writeAll(src);
            sr.off += src.len;
            if (sr.off == st.bytes.len) {
                sr.idx += 1;
                sr.off = 0;
            }
            return src.len;
        }
    }
};

/// A `Writer` that collects the server's output AND classifies the frames as
/// they are written, publishing what it saw through atomics. Classification
/// has to happen here rather than in the test body: the server writes from
/// several threads under `Session.mu`, so the accumulated buffer is only safe
/// to read once `serve` has returned — but the gates need to fire *during*
/// the run.
const FrameWatcher = struct {
    gpa: Allocator,
    buf: std.ArrayList(u8) = .empty,
    scan: usize = 0,
    ping_ack: std.atomic.Value(bool) = .init(false),
    goaway: std.atomic.Value(bool) = .init(false),
    refused: std.atomic.Value(u32) = .init(0),
    /// Total DATA payload octets written — i.e. exactly the send-window
    /// credit the server has spent. `usize`, not `u64`: this only ever counts
    /// bytes already sitting in `buf` (an in-memory `ArrayList`), so it can
    /// never need to represent more than `usize` can hold — see
    /// `awaitAtLeast`'s comment for the rest of the reasoning.
    data_bytes: std.atomic.Value(usize) = .init(0),
    /// Fiber tests only: the same facts as events a fiber can park on, and
    /// a write that parks. `park` is what a socket write on an io_uring
    /// engine does — the writing fiber, still holding the session lock,
    /// hands the thread to whoever is ready — and it is that hand-over a
    /// spinning lock turns into a deadlock.
    fiber: ?struct {
        io: std.Io,
        park: bool = true,
        ping_ack: ?*std.Io.Event = null,
        data: []const DataGate = &.{},
    } = null,
    writer: Writer,

    const DataGate = struct { at_least: usize, ev: *std.Io.Event };

    fn init(gpa: Allocator, buffer: []u8) FrameWatcher {
        return .{
            .gpa = gpa,
            .writer = .{ .vtable = &.{ .drain = drainFn }, .buffer = buffer },
        };
    }

    fn deinit(fw: *FrameWatcher) void {
        fw.buf.deinit(fw.gpa);
    }

    fn drainFn(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const fw: *FrameWatcher = @alignCast(@fieldParentPtr("writer", w));
        const buffered = w.buffer[0..w.end];
        w.end = 0;
        fw.buf.appendSlice(fw.gpa, buffered) catch return error.WriteFailed;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            fw.buf.appendSlice(fw.gpa, d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| fw.buf.appendSlice(fw.gpa, last) catch return error.WriteFailed;
        consumed += last.len * splat;
        fw.classify();
        if (fw.fiber) |f| {
            if (f.ping_ack) |e| if (fw.ping_ack.load(.acquire)) e.set(f.io);
            for (f.data) |g| if (fw.data_bytes.load(.acquire) >= g.at_least) g.ev.set(f.io);
            // The connection's socket, not the handler's `Io`: a real engine
            // writes it uncancelably, so a canceled handler that happens to
            // be the one flushing must not see its cancelation here -- that
            // would fail a write whose bytes are already out.
            if (f.park) {
                const was = f.io.swapCancelProtection(.blocked);
                defer _ = f.io.swapCancelProtection(was);
                f.io.sleep(.fromMilliseconds(1), .awake) catch unreachable;
            }
        }
        return consumed;
    }

    /// Walk whole frames off the accumulated output (§4.1: 3-octet length,
    /// type, flags, 4-octet stream id) and publish the three facts the gates
    /// wait on.
    fn classify(fw: *FrameWatcher) void {
        while (fw.buf.items.len - fw.scan >= 9) {
            const h = fw.buf.items[fw.scan..][0..9];
            const len = (@as(usize, h[0]) << 16) | (@as(usize, h[1]) << 8) | h[2];
            if (fw.buf.items.len - fw.scan < 9 + len) return;
            const payload = fw.buf.items[fw.scan + 9 ..][0..len];
            switch (h[3]) {
                0x0 => _ = fw.data_bytes.fetchAdd(len, .acq_rel), // DATA
                0x3 => if (len >= 4) { // RST_STREAM
                    const code = std.mem.readInt(u32, payload[0..4], .big);
                    if (code == 7) _ = fw.refused.fetchAdd(1, .acq_rel); // REFUSED_STREAM
                },
                0x6 => if (h[4] & 0x1 != 0) fw.ping_ack.store(true, .release), // PING ACK
                0x7 => fw.goaway.store(true, .release), // GOAWAY
                else => {},
            }
            fw.scan += 9 + len;
        }
    }
};

/// Client bytes for one complete GET stream, staged into `peer.wire`.
fn stageGet(peer: *TestPeer, path: []const u8) !u31 {
    return peer.conn.startStream(&peer.wire, &fieldsFor("GET", path), true);
}

// ── the F3 measurement, before and after ────────────────────────────────────

const OverlapProbe = struct {
    io: std.Io,
    t0: i96 = 0,
    slow_enter: i96 = 0,
    slow_exit: i96 = 0,
    fast_enter: i96 = 0,
    fast_exit: i96 = 0,

    fn ms(p: *const OverlapProbe, t: i96) i64 {
        return @intCast(@divTrunc(t - p.t0, std.time.ns_per_ms));
    }

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *OverlapProbe = @ptrCast(@alignCast(req.context.?));
        if (std.mem.eql(u8, req.path, "/slow")) {
            p.slow_enter = nowNs(p.io);
            const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(300), .clock = .awake };
            d.sleep(p.io) catch {};
            p.slow_exit = nowNs(p.io);
        } else {
            p.fast_enter = nowNs(p.io);
            p.fast_exit = nowNs(p.io);
        }
        try rw.writeAll("ok");
    }
};

test "dispatcher: /fast completes while /slow is still sleeping (F3 measurement)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Both streams are complete on the wire before the server reads a byte —
    // the exact shape of the original measurement.
    var out_buf: [16 * 1024]u8 = undefined;

    // BEFORE: no dispatcher. Handlers run on the connection's own task.
    var seq: OverlapProbe = .{ .io = io };
    {
        var peer: TestPeer = .init(gpa, .{});
        defer peer.deinit();
        try peer.conn.sendPreface(&peer.wire);
        const slow = try stageGet(&peer, "/slow");
        const fast = try stageGet(&peer, "/fast");
        seq.t0 = nowNs(io);
        try runOffline(&peer, .{
            .handler = OverlapProbe.handler,
            .context = &seq,
        }, &out_buf);
        try testing.expectEqual(@as(u16, 200), peer.resp(slow).status);
        try testing.expectEqual(@as(u16, 200), peer.resp(fast).status);
    }
    // Sequential by construction: /fast cannot even start until /slow is out.
    try testing.expect(seq.fast_enter >= seq.slow_exit);

    // AFTER: the same bytes, the same handler, a bounded pool underneath.
    var pd = try PoolDispatcher.init(gpa, io, 4, PoolDispatcher.defaultGlobalCap());
    defer pd.deinit();
    var par: OverlapProbe = .{ .io = io };
    {
        var peer: TestPeer = .init(gpa, .{});
        defer peer.deinit();
        try peer.conn.sendPreface(&peer.wire);
        const slow = try stageGet(&peer, "/slow");
        const fast = try stageGet(&peer, "/fast");
        par.t0 = nowNs(io);
        try runOffline(&peer, .{
            .handler = OverlapProbe.handler,
            .context = &par,
            .dispatcher = pd.iface(8),
        }, &out_buf);
        try testing.expectEqual(@as(u16, 200), peer.resp(slow).status);
        try testing.expectEqual(@as(u16, 200), peer.resp(fast).status);
    }
    // Overlap: /fast entered AND returned while /slow was still inside its
    // 300 ms sleep. Timing-dependent only in that /fast must not itself take
    // 300 ms — the whole sleep is the margin.
    // Measured on this machine, both halves of this very test:
    //   sequential: slow enter +0 ms / exit +300 ms . fast enter +301 ms / exit +301 ms
    //   pooled:     slow enter +1 ms / exit +301 ms . fast enter   +0 ms / exit   +0 ms
    // The first line is, to the millisecond, the audit's original F3
    // measurement — which is the point: the same bytes, the same handler,
    // and only `Options.dispatcher` differs.
    try testing.expect(par.fast_enter < par.slow_exit);
    try testing.expect(par.fast_exit < par.slow_exit);
    // And the connection as a whole no longer costs 2 × the slow handler.
    try testing.expect(par.ms(par.fast_exit) < 300);
}

// ── the reading side keeps working ──────────────────────────────────────────

const PingProbe = struct {
    io: std.Io,
    /// Published by the handler once it is inside and blocked.
    entered: std.atomic.Value(bool) = .init(false),
    /// The server's PING ACK, observed by `FrameWatcher`.
    ack: *std.atomic.Value(bool),

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *PingProbe = @ptrCast(@alignCast(req.context.?));
        p.entered.store(true, .release);
        // Blocked on something that is NOT h2 I/O — a gRPC bidi handler
        // waiting on application state does exactly this. The old engine
        // stopped reading the socket right here.
        try awaitFlag(p.io, p.ack);
        try rw.writeAll("ok");
    }
};

test "dispatcher: a PING is answered while a handler is blocked on non-h2 work" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    // Stage 0: preface + one request. Stage 1: a PING, withheld until the
    // handler is demonstrably inside and blocked — so an ACK can only mean
    // the connection kept reading with a handler stuck in it.
    try peer.conn.sendPreface(&peer.wire);
    const sid = try stageGet(&peer, "/block");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();
    try peer.conn.sendPing(&peer.wire, .{ 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef });
    const stage1 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage1);
    peer.wire.clearRetainingCapacity();

    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();

    var probe: PingProbe = .{ .io = io, .ack = &fw.ping_ack };

    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{
        .{ .bytes = stage0 },
        .{ .gate = &probe.entered, .bytes = stage1 },
    }, &rbuf);

    var pd = try PoolDispatcher.init(gpa, io, 2, 8);
    defer pd.deinit();

    serve(gpa, .{
        .handler = PingProbe.handler,
        .context = &probe,
        .dispatcher = pd.iface(8),
    }, &sr.reader, &fw.writer);

    // Reaching here at all is the result: the handler could only return
    // because the ACK it was waiting for was produced by the connection task
    // while it blocked. Sequentially this deadlocks (and `gate_timeout_ms`
    // would fail the run instead).
    try testing.expect(fw.ping_ack.load(.acquire));
    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
}

// ── a full pool refuses, it does not queue ──────────────────────────────────

const RefuseProbe = struct {
    io: std.Io,
    refused: *std.atomic.Value(u32),

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *RefuseProbe = @ptrCast(@alignCast(req.context.?));
        // Hold the pool's single slot until the second stream has been
        // answered — by a refusal, if the pool really refuses rather than
        // queueing behind us.
        const deadline = nowNs(p.io) + @as(i96, gate_timeout_ms) * std.time.ns_per_ms;
        while (p.refused.load(.acquire) == 0) {
            if (nowNs(p.io) >= deadline) return error.GateTimeout;
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
        try rw.writeAll("ok");
    }
};

test "dispatcher: a full pool answers RST_STREAM(REFUSED_STREAM), never a queue" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const first = try stageGet(&peer, "/a");
    const second = try stageGet(&peer, "/b");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();

    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();
    var probe: RefuseProbe = .{ .io = io, .refused = &fw.refused };

    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{.{ .bytes = stage0 }}, &rbuf);

    // Global capacity ONE. The per-connection cap is deliberately left at 8
    // so the refusal can only come from the global admission control.
    var pd = try PoolDispatcher.init(gpa, io, 2, 1);
    defer pd.deinit();

    serve(gpa, .{
        .handler = RefuseProbe.handler,
        .context = &probe,
        .dispatcher = pd.iface(8),
    }, &sr.reader, &fw.writer);

    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(first).status);
    // Refused, not queued and not hung: retryable per §8.7.
    try testing.expectEqual(@as(?h2.ErrorCode, .refused_stream), peer.resp(second).rst);
    try testing.expectEqual(@as(?[]const u8, null), peer.resp(second).header(":status"));
}

// ── rapid reset still costs the attacker after dispatch ─────────────────────

const CancelProbe = struct {
    io: std.Io,
    entered: std.atomic.Value(u32) = .init(0),
    goaway: *std.atomic.Value(bool),

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *CancelProbe = @ptrCast(@alignCast(req.context.?));
        _ = p.entered.fetchAdd(1, .acq_rel);
        // Still running when the cancellation arrives — the situation the
        // old structural argument ("handlers run sequentially, so cancelled
        // streams never fan out concurrent work") no longer covers.
        awaitFlag(p.io, p.goaway) catch {};
        rw.writeAll("ok") catch {};
    }
};

test "dispatcher: streams cancelled AFTER dispatch are charged to the rapid-reset budget" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    var sids: [3]u31 = undefined;
    for (&sids) |*sid| sid.* = try stageGet(&peer, "/hold");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();
    // The cancellations, withheld until all three handlers are running.
    for (sids) |sid| try peer.conn.sendRstStream(&peer.wire, sid, .cancel);
    const stage1 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage1);
    peer.wire.clearRetainingCapacity();

    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();
    var probe: CancelProbe = .{ .io = io, .goaway = &fw.goaway };

    // A gate on a counter needs a bool for `StagedReader`; publish one.
    var all_in: std.atomic.Value(bool) = .init(false);
    const Waiter = struct {
        fn run(p: *CancelProbe, flag: *std.atomic.Value(bool), i: std.Io) void {
            awaitCount(i, &p.entered, 3) catch {};
            flag.store(true, .release);
        }
    };
    const waiter = try std.Thread.spawn(.{}, Waiter.run, .{ &probe, &all_in, io });
    defer waiter.join();

    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{
        .{ .bytes = stage0 },
        .{ .gate = &all_in, .bytes = stage1 },
    }, &rbuf);

    var pd = try PoolDispatcher.init(gpa, io, 4, 8);
    defer pd.deinit();

    serve(gpa, .{
        .handler = CancelProbe.handler,
        .context = &probe,
        // Budget 2: the third post-dispatch cancellation must break it.
        .limits = .{ .max_reset_streams = 2 },
        .dispatcher = pd.iface(8),
    }, &sr.reader, &fw.writer);

    try testing.expectEqual(@as(u32, 3), probe.entered.load(.acquire));
    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(?h2.ErrorCode, .enhance_your_calm), peer.goaway);
}

// ── invariant 1: the HPACK dynamic table under concurrent encoders ──────────

const table_streams = 8;

const HpackProbe = struct {
    io: std.Io,
    arrived: std.atomic.Value(u32) = .init(0),

    /// Each stream answers with a header whose NAME and VALUE are unique to
    /// it and long enough to be inserted into the connection's single HPACK
    /// dynamic table. Every response is therefore an edit to shared encoder
    /// state, and the peer's decoder replays those edits in wire order: if
    /// two encoders interleave, the table the peer builds is not the table
    /// the server thinks it built, and the values come back wrong (or the
    /// block fails to decode at all).
    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *HpackProbe = @ptrCast(@alignCast(req.context.?));
        const n = req.path[req.path.len - 1];
        _ = p.arrived.fetchAdd(1, .acq_rel);
        // All encoders enter `sendHead` at once: the collision is scheduled,
        // not hoped for.
        try awaitCount(p.io, &p.arrived, table_streams);
        var name_buf: [32]u8 = undefined;
        var val_buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "x-table-{c}", .{n});
        @memset(&val_buf, n);
        const val: []const u8 = &val_buf;
        try rw.setHeader(name, val);
        try rw.writeAll(val[0..8]);
    }
};

test "dispatcher: concurrent responses keep the HPACK dynamic table coherent" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    var sids: [table_streams]u31 = undefined;
    var paths: [table_streams][8]u8 = undefined;
    for (&sids, &paths, 0..) |*sid, *path, i| {
        path.* = .{ '/', 't', 'a', 'b', '/', 'x', 'x', @intCast('a' + i) };
        sid.* = try stageGet(&peer, path);
    }

    var probe: HpackProbe = .{ .io = io };
    var pd = try PoolDispatcher.init(gpa, io, table_streams, table_streams);
    defer pd.deinit();

    var out_buf: [64 * 1024]u8 = undefined;
    try runOffline(&peer, .{
        .handler = HpackProbe.handler,
        .context = &probe,
        .dispatcher = pd.iface(table_streams),
    }, &out_buf);

    for (sids, 0..) |sid, i| {
        const c = peer.resp(sid);
        try testing.expectEqual(@as(u16, 200), c.status);
        var name_buf: [32]u8 = undefined;
        var val_buf: [64]u8 = undefined;
        const ch: u8 = @intCast('a' + i);
        const name = try std.fmt.bufPrint(&name_buf, "x-table-{c}", .{ch});
        @memset(&val_buf, ch);
        const val: []const u8 = &val_buf;
        try testing.expectEqualStrings(val, c.header(name) orelse return error.HeaderLost);
        try testing.expectEqualStrings(val[0..8], c.body.items);
    }
}

// ── the per-connection cap holds work back without losing it ────────────────

test "dispatcher: streams over the per-connection cap wait, and are all served" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    var sids: [6]u31 = undefined;
    for (&sids) |*sid| sid.* = try stageGet(&peer, "/hello");

    // Cap of 2 with 6 ready streams: the other four are NOT refused — they
    // wait in the (already bounded) jobs map and are dispatched by the tail
    // of each finishing worker, which is the only thing that can do it on a
    // connection with no further wire events.
    var pd = try PoolDispatcher.init(gpa, io, 4, 64);
    defer pd.deinit();

    var out_buf: [32 * 1024]u8 = undefined;
    try runOffline(&peer, .{
        .handler = testHandler,
        .dispatcher = pd.iface(2),
    }, &out_buf);

    for (sids) |sid| {
        const c = peer.resp(sid);
        try testing.expectEqual(@as(u16, 200), c.status);
        try testing.expect(c.end);
        try testing.expectEqual(@as(?h2.ErrorCode, null), c.rst);
        try testing.expectEqualStrings("hello", c.body.items);
    }
}

// ── invariant 3: the CONNECTION window as the binding constraint ────────────
//
// The connection send window (§6.9.1) is the one piece of flow-control state
// two workers genuinely share — a stream window belongs to one handler, the
// connection window belongs to all of them — and it is the one whose breach
// gets us GOAWAYed by the *peer* rather than caught locally.
//
// Making it the binding constraint takes three deliberate settings, and
// without all three the test is a no-op that passes for the wrong reason:
//   * the peer advertises a LARGE SETTINGS_INITIAL_WINDOW_SIZE, so per-stream
//     windows are not what limits anything (the connection window is fixed at
//     65535 and no SETTINGS can raise it — only WINDOW_UPDATE can);
//   * `response_buffer_size` is larger than the response body, so the whole
//     body reaches `Framer.emit` as ONE slice. With the default 4 KiB buffer
//     every `emit` call is a 4 KiB chunk that fits the connection window
//     trivially, and `h2.sendData`'s own `len > conn_send_window` check masks
//     any mistake `emit` makes — which is exactly why an earlier version of
//     this file could drop `conn_send_window` from the minimum and stay green;
//   * the credit is replenished in instalments, each gated on octets actually
//     sent, so a server that waits for the *whole* remaining body to fit at
//     once never reaches the next instalment and deadlocks instead of
//     completing slowly.
//
// Two streams, so the pooled path is the one under test: both workers sit in
// `emit` spending the same connection window, and both park in the
// outside-the-lock wait while the connection task applies the WINDOW_UPDATE
// that frees them — the replenishment half of the liveness argument.

const fc_body_len = 96 * 1024;
const fc_stream_window = 1 << 20;
const fc_grant: u31 = 65535;

const FlowProbe = struct {
    body_a: [fc_body_len]u8 = @splat('a'),
    body_b: [fc_body_len]u8 = @splat('b'),

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *FlowProbe = @ptrCast(@alignCast(req.context.?));
        const body: []const u8 = if (std.mem.endsWith(u8, req.path, "a"))
            &p.body_a
        else
            &p.body_b;
        try rw.writeAll(body);
    }
};

test "dispatcher: the connection window bounds two concurrent senders (§6.9.1)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Stream windows wide open; the connection window is the only limit.
    var peer: TestPeer = .init(gpa, .{ .initial_window_size = fc_stream_window });
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid_a = try stageGet(&peer, "/big/a");
    const sid_b = try stageGet(&peer, "/big/b");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();

    // Three connection-level instalments. `sendWindowUpdate` also raises the
    // peer's own receive window, which is what lets it decode 192 KiB later.
    var grants: [3][]u8 = undefined;
    for (&grants) |*g| {
        try peer.conn.sendWindowUpdate(&peer.wire, 0, fc_grant);
        g.* = try gpa.dupe(u8, peer.wire.items);
        peer.wire.clearRetainingCapacity();
    }
    defer for (grants) |g| gpa.free(g);

    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();

    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{
        .{ .bytes = stage0 },
        // Each gate is below the credit outstanding at that point, so a
        // correct server always reaches it; a server that demands the whole
        // remainder in one window never sends a byte and hangs at the first.
        .{ .counter = &fw.data_bytes, .at_least = 60_000, .bytes = grants[0] },
        .{ .counter = &fw.data_bytes, .at_least = 125_000, .bytes = grants[1] },
        .{ .counter = &fw.data_bytes, .at_least = 190_000, .bytes = grants[2] },
        // Pure barrier: hold EOF back until both bodies are out, so tearing
        // the connection down cannot race the workers.
        .{ .counter = &fw.data_bytes, .at_least = 2 * fc_body_len, .bytes = "" },
    }, &rbuf);

    var probe: FlowProbe = .{};
    var pd = try PoolDispatcher.init(gpa, io, 4, 8);
    defer pd.deinit();

    serve(gpa, .{
        .handler = FlowProbe.handler,
        .context = &probe,
        // > body length: the whole response reaches `emit` as one slice.
        .response_buffer_size = 128 * 1024,
        .dispatcher = pd.iface(8),
    }, &sr.reader, &fw.writer);

    try peer.feed(fw.buf.items);
    // Never GOAWAYed: had either sender overspent the shared window, §6.9.1
    // says the peer is the one that ends the connection.
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
    for ([_]u31{ sid_a, sid_b }, [_]u8{ 'a', 'b' }) |sid, ch| {
        const c = peer.resp(sid);
        try testing.expectEqual(@as(u16, 200), c.status);
        try testing.expect(c.end);
        try testing.expectEqual(@as(usize, fc_body_len), c.body.items.len);
        for (c.body.items) |b| try testing.expectEqual(ch, b);
    }
    // The connection window really was the binding constraint: more octets
    // were delivered than it ever held at once.
    try testing.expect(fw.data_bytes.load(.acquire) > fc_grant);
}

// ── concurrent handlers as fibers of ONE thread (`Dispatcher.io`) ───────────
//
// The same scenarios as above under the scheduling rule of fibers sharing a
// thread: exactly one task runs at a time, and a task gives the thread up
// only when it blocks through `Io`. Zig 0.16's own fiber engine cannot serve
// here — `std.Io.Evented` does not compile in 0.16.0 (`Io/Uring.zig` returns
// `error.ReadOnlyFileSystem` outside its declared error sets) — so `BatonIo`
// models the rule with OS threads and one baton: a task runs only while it
// holds the baton, and releases it only inside a blocking `Io` call (futex
// wait, sleep). A task that spins with `std.Thread.yield` keeps the baton,
// exactly as a spinning fiber keeps its thread.
//
// What makes these tests bite: the writer PARKS (`FrameWatcher.fiber.park`),
// so a stream task regularly holds the session lock across a hand-over, and
// every gate is an `std.Io.Event`, never a spin. Without `Dispatcher.io` (the
// yield-spin lock) they hang on the first contended lock — measured on the
// first of them before `Dispatcher.io` existed.

/// `std.Io.Threaded` with the one-runner-at-a-time rule of a fiber engine.
/// Every task must hold `baton` to run: the test thread from `init` to
/// `deinit`, a dispatched task from start to end (`BatonDispatcher.run`).
const BatonIo = struct {
    threaded: std.Io.Threaded,
    baton: std.Io.Mutex = .init,
    vtable: std.Io.VTable,

    /// The overrides are called with `Threaded`'s own userdata (every other
    /// vtable entry is Threaded's and needs it), so they find the baton here.
    /// Test-only and one at a time: the test runner runs tests sequentially.
    var active: ?*BatonIo = null;

    fn init(b: *BatonIo, gpa: Allocator) void {
        b.* = .{ .threaded = .init(gpa, .{}), .vtable = undefined };
        b.vtable = b.inner().vtable.*;
        b.vtable.futexWait = futexWait;
        b.vtable.futexWaitUncancelable = futexWaitUncancelable;
        b.vtable.sleep = sleep;
        std.debug.assert(active == null);
        active = b;
        b.enter();
    }

    fn deinit(b: *BatonIo) void {
        b.leave();
        active = null;
        b.threaded.deinit();
    }

    /// The `Io` the code under test gets: blocking hands the baton over.
    fn io(b: *BatonIo) std.Io {
        return .{ .userdata = b.inner().userdata, .vtable = &b.vtable };
    }

    /// The plain `Threaded` underneath, for the harness's own plumbing.
    fn inner(b: *BatonIo) std.Io {
        return b.threaded.io();
    }

    fn enter(b: *BatonIo) void {
        b.baton.lockUncancelable(b.inner());
    }

    fn leave(b: *BatonIo) void {
        b.baton.unlock(b.inner());
    }

    fn futexWait(ud: ?*anyopaque, ptr: *const u32, expected: u32, t: std.Io.Timeout) std.Io.Cancelable!void {
        const b = active.?;
        b.leave();
        defer b.enter();
        return b.inner().vtable.futexWait(ud, ptr, expected, t);
    }

    fn futexWaitUncancelable(ud: ?*anyopaque, ptr: *const u32, expected: u32) void {
        const b = active.?;
        b.leave();
        defer b.enter();
        b.inner().vtable.futexWaitUncancelable(ud, ptr, expected);
    }

    fn sleep(ud: ?*anyopaque, t: std.Io.Timeout) std.Io.Cancelable!void {
        const b = active.?;
        b.leave();
        defer b.enter();
        return b.inner().vtable.sleep(ud, t);
    }
};

/// A `Dispatcher` whose tasks obey `BatonIo`'s rule — the shape of a fiber
/// engine dispatching each stream to a fiber of the connection's thread.
const BatonDispatcher = struct {
    b: *BatonIo,
    group: std.Io.Group = .init,

    fn iface(d: *BatonDispatcher, per_conn: u32) Dispatcher {
        return .{ .ctx = d, .spawn = spawn, .max_concurrent_handlers = per_conn, .io = d.b.io() };
    }

    fn spawn(ctx: ?*anyopaque, task: Task) bool {
        const d: *BatonDispatcher = @ptrCast(@alignCast(ctx.?));
        d.group.concurrent(d.b.inner(), run, .{ d.b, task }) catch return false;
        return true;
    }

    fn run(b: *BatonIo, task: Task) void {
        b.enter();
        defer b.leave();
        task.func(task.ctx);
    }

    /// Wait for every task to have returned (the session only guarantees
    /// they are off it); blocking, so the baton goes.
    fn join(d: *BatonDispatcher) void {
        d.b.leave();
        defer d.b.enter();
        d.group.await(d.b.inner()) catch {};
    }
};

const FiberOverlapProbe = struct {
    io: std.Io,
    t0: i96 = 0,
    slow_exit: i96 = 0,
    fast_enter: i96 = 0,
    fast_exit: i96 = 0,

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *FiberOverlapProbe = @ptrCast(@alignCast(req.context.?));
        if (std.mem.eql(u8, req.path, "/slow")) {
            try p.io.sleep(.fromMilliseconds(300), .awake);
            // A body bigger than the writer's buffer: several parking
            // writes, each under the session lock.
            var chunk: [1024]u8 = @splat('s');
            for (0..16) |_| try rw.writeAll(&chunk);
            p.slow_exit = nowNs(p.io);
        } else {
            p.fast_enter = nowNs(p.io);
            try rw.writeAll("ok");
            p.fast_exit = nowNs(p.io);
        }
    }
};

test "dispatcher (fibers): /fast completes while /slow sleeps, one runner" {
    const gpa = testing.allocator;
    var bio: BatonIo = undefined;
    bio.init(gpa);
    defer bio.deinit();
    const io = bio.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const slow = try stageGet(&peer, "/slow");
    const fast = try stageGet(&peer, "/fast");

    var wbuf: [512]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();
    fw.fiber = .{ .io = io };
    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{.{ .bytes = peer.wire.items }}, &rbuf);

    var fd: BatonDispatcher = .{ .b = &bio };
    var probe: FiberOverlapProbe = .{ .io = io };
    probe.t0 = nowNs(io);
    serve(gpa, .{
        .handler = FiberOverlapProbe.handler,
        .context = &probe,
        .dispatcher = fd.iface(8),
    }, &sr.reader, &fw.writer);
    fd.join();

    peer.wire.clearRetainingCapacity();
    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(slow).status);
    try testing.expectEqual(@as(usize, 16 * 1024), peer.resp(slow).body.items.len);
    try testing.expectEqual(@as(u16, 200), peer.resp(fast).status);
    // Overlap with one runner at a time: /fast ran to completion inside /slow's sleep.
    try testing.expect(probe.fast_exit < probe.slow_exit);
    try testing.expect(probe.fast_exit - probe.t0 < 300 * std.time.ns_per_ms);
}

const FiberPingProbe = struct {
    io: std.Io,
    entered: std.Io.Event = .unset,
    ack: std.Io.Event = .unset,

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *FiberPingProbe = @ptrCast(@alignCast(req.context.?));
        p.entered.set(p.io);
        // Parked on application state the connection itself must produce.
        p.ack.waitUncancelable(p.io);
        try rw.writeAll("ok");
    }
};

test "dispatcher (fibers): a PING is answered while a handler is parked" {
    const gpa = testing.allocator;
    var bio: BatonIo = undefined;
    bio.init(gpa);
    defer bio.deinit();
    const io = bio.io();

    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try stageGet(&peer, "/block");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();
    try peer.conn.sendPing(&peer.wire, .{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const stage1 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage1);
    peer.wire.clearRetainingCapacity();

    var probe: FiberPingProbe = .{ .io = io };
    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();
    fw.fiber = .{ .io = io, .ping_ack = &probe.ack };
    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{
        .{ .bytes = stage0 },
        .{ .event = &probe.entered, .bytes = stage1 },
    }, &rbuf);

    var fd: BatonDispatcher = .{ .b = &bio };
    serve(gpa, .{
        .handler = FiberPingProbe.handler,
        .context = &probe,
        .dispatcher = fd.iface(8),
    }, &sr.reader, &fw.writer);
    fd.join();

    try testing.expect(fw.ping_ack.load(.acquire));
    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
}

test "dispatcher (fibers): flow-control waits park, and the connection window bounds two senders" {
    const gpa = testing.allocator;
    var bio: BatonIo = undefined;
    bio.init(gpa);
    defer bio.deinit();
    const io = bio.io();

    var peer: TestPeer = .init(gpa, .{ .initial_window_size = fc_stream_window });
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid_a = try stageGet(&peer, "/big/a");
    const sid_b = try stageGet(&peer, "/big/b");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();
    var grants: [3][]u8 = undefined;
    for (&grants) |*g| {
        try peer.conn.sendWindowUpdate(&peer.wire, 0, fc_grant);
        g.* = try gpa.dupe(u8, peer.wire.items);
        peer.wire.clearRetainingCapacity();
    }
    defer for (grants) |g| gpa.free(g);

    // Same thresholds as the threaded test, as events: each is below the
    // credit outstanding when it is due, so a correct server reaches it.
    var evs: [4]std.Io.Event = @splat(.unset);
    const gates = [_]FrameWatcher.DataGate{
        .{ .at_least = 60_000, .ev = &evs[0] },
        .{ .at_least = 125_000, .ev = &evs[1] },
        .{ .at_least = 190_000, .ev = &evs[2] },
        .{ .at_least = 2 * fc_body_len, .ev = &evs[3] },
    };
    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();
    fw.fiber = .{ .io = io, .data = &gates };
    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{
        .{ .bytes = stage0 },
        .{ .event = &evs[0], .bytes = grants[0] },
        .{ .event = &evs[1], .bytes = grants[1] },
        .{ .event = &evs[2], .bytes = grants[2] },
        .{ .event = &evs[3], .bytes = "" },
    }, &rbuf);

    var probe: FlowProbe = .{};
    var fd: BatonDispatcher = .{ .b = &bio };
    serve(gpa, .{
        .handler = FlowProbe.handler,
        .context = &probe,
        .response_buffer_size = 128 * 1024,
        .dispatcher = fd.iface(8),
    }, &sr.reader, &fw.writer);
    fd.join();

    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
    for ([_]u31{ sid_a, sid_b }, [_]u8{ 'a', 'b' }) |sid, ch| {
        const c = peer.resp(sid);
        try testing.expectEqual(@as(u16, 200), c.status);
        try testing.expect(c.end);
        try testing.expectEqual(@as(usize, fc_body_len), c.body.items.len);
        for (c.body.items) |b| try testing.expectEqual(ch, b);
    }
    try testing.expect(fw.data_bytes.load(.acquire) > fc_grant);
}

test "dispatcher (fibers): a handler canceled while waiting for credit resets only its stream" {
    const gpa = testing.allocator;
    var bio: BatonIo = undefined;
    bio.init(gpa);
    defer bio.deinit();
    const io = bio.io();

    // One stream, a body past the connection window (65 535), and no
    // WINDOW_UPDATE ever: the handler parks in `waitForPeer` for good.
    var peer: TestPeer = .init(gpa, .{ .initial_window_size = fc_stream_window });
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try stageGet(&peer, "/big/a");
    const stage0 = try gpa.dupe(u8, peer.wire.items);
    defer gpa.free(stage0);
    peer.wire.clearRetainingCapacity();

    // `window_spent` fires once the server has used the whole window; the
    // canceller then cancels the stream's task and only after that lets the
    // connection end (`done`), so the reset cannot be the connection's exit.
    var window_spent: std.Io.Event = .unset;
    var done: std.Io.Event = .unset;
    const gates = [_]FrameWatcher.DataGate{.{ .at_least = 65_535, .ev = &window_spent }};
    var wbuf: [4096]u8 = undefined;
    var fw: FrameWatcher = .init(gpa, &wbuf);
    defer fw.deinit();
    fw.fiber = .{ .io = io, .data = &gates };
    var rbuf: [4096]u8 = undefined;
    var sr: StagedReader = .init(io, &.{
        .{ .bytes = stage0 },
        .{ .event = &done, .bytes = "" },
    }, &rbuf);

    var probe: FlowProbe = .{};
    var fd: BatonDispatcher = .{ .b = &bio };
    const Canceller = struct {
        fn run(d: *BatonDispatcher, spent: *std.Io.Event, end: *std.Io.Event) void {
            const inner = d.b.inner();
            spent.waitUncancelable(inner);
            d.group.cancel(inner);
            end.set(inner);
        }
    };
    const canceller = try std.Thread.spawn(.{}, Canceller.run, .{ &fd, &window_spent, &done });
    serve(gpa, .{
        .handler = FlowProbe.handler,
        .context = &probe,
        .response_buffer_size = 128 * 1024,
        .dispatcher = fd.iface(8),
    }, &sr.reader, &fw.writer);
    canceller.join();
    fd.join();

    try peer.feed(fw.buf.items);
    try testing.expectEqual(@as(?h2.ErrorCode, null), peer.goaway);
    const c = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), c.status);
    try testing.expect(!c.data_end_stream and !c.headers_end_stream); // ended by the reset, not END_STREAM
    try testing.expectEqual(@as(?h2.ErrorCode, .cancel), c.rst);
    try testing.expect(c.body.items.len < fc_body_len);
}

/// Counts frees whose block still holds `marker` -- request-body bytes the
/// codec handed back to the allocator without zeroing them first.
const ScrubWatch = struct {
    inner: Allocator,
    marker: []const u8,
    dirty_frees: usize = 0,

    fn allocator(w: *ScrubWatch) Allocator {
        return .{ .ptr = w, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const w: *ScrubWatch = @ptrCast(@alignCast(ctx));
        return w.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const w: *ScrubWatch = @ptrCast(@alignCast(ctx));
        return w.inner.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const w: *ScrubWatch = @ptrCast(@alignCast(ctx));
        // A remap that moves copies the block and drops the old one: that
        // old one is a free too, and nothing zeroed it. Refuse, so growth
        // goes through alloc + copy + free, where `free` sees it.
        _ = w;
        _ = m;
        _ = a;
        _ = n;
        _ = ra;
        return null;
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const w: *ScrubWatch = @ptrCast(@alignCast(ctx));
        if (std.mem.indexOf(u8, m, w.marker) != null) w.dirty_frees += 1;
        w.inner.rawFree(m, a, ra);
    }
};

test "h2: a buffered request body is zeroed before the codec frees it" {
    // A request body is the caller's data -- credentials, payloads -- and the
    // heap block that held it goes back to an allocator the next connection
    // draws from. The body is read and discarded by the handler here, so any
    // freed block still holding it is the codec's own copy. Three were found:
    // the job's buffered body, the request arena's body scratch, and the
    // connection's raw frame buffer.
    //
    // ⚠ Meaningful in ReleaseFast. A safe build's `Allocator.free` clobbers
    // the block itself (`@memset(undefined)`), so in Debug two of the three
    // copies are invisible here -- measured: removing either fix passes in
    // Debug and fails in ReleaseFast.
    const marker = "BODY-SECRET-7f3a";
    var watch: ScrubWatch = .{ .inner = testing.allocator, .marker = marker };
    const gpa = watch.allocator();

    var peer: TestPeer = .init(testing.allocator, .{});
    defer peer.deinit();
    try peer.conn.sendPreface(&peer.wire);
    const sid = try peer.conn.startStream(&peer.wire, &fieldsFor("POST", "/drain"), false);
    try peer.conn.sendData(&peer.wire, sid, marker, true);

    var out_buf: [8192]u8 = undefined;
    var in: Reader = .fixed(peer.wire.items);
    var out: Writer = .fixed(&out_buf);
    serve(gpa, .{ .handler = testHandler }, &in, &out);
    peer.wire.clearRetainingCapacity();
    try peer.feed(out.buffered());

    try testing.expectEqual(@as(u16, 200), peer.resp(sid).status);
    try testing.expectEqual(@as(usize, 0), watch.dirty_frees);
}
