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
//! accumulates in a map, so interleaved streams are all collected — but
//! requests are handled **sequentially** on the connection's task (no
//! concurrent-stream scheduling yet). The handler writes an ordinary
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
//!   connection violations answered with GOAWAY(ENHANCE_YOUR_CALM).
//!   Handlers run sequentially on the connection's task, so cancelled
//!   streams never fan out concurrent server-side work.
//! - **SETTINGS_MAX_CONCURRENT_STREAMS** (`max_concurrent_streams`) is
//!   advertised in the server preface and enforced: request streams above
//!   the limit are refused with RST_STREAM(REFUSED_STREAM) — safely
//!   retryable per §8.7 — and the connection keeps serving the rest.
//! - **`max_streams_per_connection`** bounds total streams on one
//!   connection; once reached, ready requests finish and the connection
//!   closes with a graceful GOAWAY(NO_ERROR) so the client reconnects.
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
    /// answers 413 and the connection closes. null = unlimited.
    max_body_bytes: ?u64 = null,
    /// `ResponseWriter` body-buffer size (h1 parity; framing is re-derived
    /// here so it only affects gzip's buffered-vs-streaming decision).
    response_buffer_size: usize = 4 * 1024,
    /// Negotiated gzip response compression; requires `gzip_scratch`.
    compression: ?gzip.Compression = null,
    gzip_scratch: ?*gzip.Scratch = null,
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
    max_concurrent_streams: u32 = 100,
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
pub fn serve(gpa: Allocator, opts: Options, in: *Reader, out: *Writer) void {
    var s: Session = .{
        .gpa = gpa,
        .opts = opts,
        .in = in,
        .out = out,
        .conn = .init(gpa, .server, .{
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
        }),
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
    /// Stream id currently being served, if any — the one job `dropJob` must
    /// mark instead of freeing (see `Job.rst`).
    serving: ?u31 = null,
    req_index: u32 = 0,
    peer_goaway: bool = false,

    fn deinit(s: *Session) void {
        for (s.jobs.values()) |*job| job.deinit(s.gpa);
        s.jobs.deinit(s.gpa);
        s.events.deinit(s.gpa); // always drained by processEvents
        s.wire.deinit(s.gpa);
        s.conn.deinit();
    }

    fn fireConnState(s: *Session, state: Server.ConnState) void {
        if (s.opts.on_conn_state) |hook| hook(s.opts.on_conn_state_ctx, s.opts.peer, state);
    }

    fn run(s: *Session) void {
        s.fireConnState(.new);
        defer s.fireConnState(.closed);
        // §3.4 server preface: our SETTINGS, before anything else.
        s.conn.sendPreface(&s.wire) catch return;
        s.flushWire() catch return;
        while (true) {
            while (s.takeReady()) |id| {
                s.fireConnState(.active);
                s.serving = id;
                const disp = s.serveJob(id);
                s.serving = null;
                s.finishJob(id, disp);
                s.req_index += 1;
                s.fireConnState(.idle);
                if (disp == .close) return;
            }
            // Total-streams cap: enough streams for one connection — what
            // was ready has been served; close gracefully (NO_ERROR) so a
            // legitimate client just reconnects.
            if (s.conn.remote_streams_total >= s.opts.limits.max_streams_per_connection) {
                s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
                s.flushWire() catch {};
                return;
            }
            // Graceful shutdown: the peer said GOAWAY and nothing is left.
            if (s.peer_goaway and s.jobs.count() == 0) return;
            s.pump() catch return;
        }
    }

    /// Flush staged wire bytes through the (timeout-guarded) socket writer.
    fn flushWire(s: *Session) Writer.Error!void {
        if (s.wire.items.len == 0) return;
        try s.out.writeAll(s.wire.items);
        try s.out.flush();
        s.wire.clearRetainingCapacity();
    }

    /// Block for at least one byte, feed everything buffered to the h2
    /// state machine, dispatch events and flush auto-replies (SETTINGS/PING
    /// ACKs, WINDOW_UPDATEs). Stream-scoped violations answer RST_STREAM
    /// and processing continues (§5.4.2); connection-scoped ones answer
    /// GOAWAY with the layer's code and close (§5.4.1).
    fn pump(s: *Session) error{Closed}!void {
        _ = s.in.peekGreedy(1) catch return error.Closed; // EOF/timeout/reset
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
            .stream_reset => |r| s.dropJob(r.stream_id),
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
            if (job.trailers == null and !containsPseudoHeader(hd.headers)) {
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
            hd.headers.deinit(s.gpa);
            s.conn.sendRstStream(&s.wire, hd.stream_id, .refused_stream) catch {};
            return;
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
            if (job.body.items.len + d.data.len > max) {
                job.over_cap = true;
                return;
            }
        }
        job.body.appendSlice(s.gpa, d.data) catch {
            job.over_cap = true; // overloaded: shed like an over-limit body
        };
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
        s.flushWire() catch {};
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

    /// The stream is gone (peer RST_STREAM, or our own stream-scoped
    /// recovery). Frees the job — unless its handler is running, in which
    /// case `serveJob` holds slices into it and only a flag may be set.
    fn dropJob(s: *Session, id: u31) void {
        if (s.serving) |cur| {
            if (cur == id) {
                if (s.jobs.getPtr(id)) |job| job.rst = true;
                return;
            }
        }
        s.removeJob(id);
    }

    fn removeJob(s: *Session, id: u31) void {
        if (s.jobs.fetchOrderedRemove(id)) |kv| {
            var job = kv.value;
            // Everything received and never credited back is being thrown
            // away now; the connection window is owed it (§6.9.1). The
            // stream window is moot — the stream is gone.
            s.grant(0, job.owed);
            s.flushWire() catch {};
            job.deinit(s.gpa);
        }
    }

    /// Retire a served stream. A streaming handler may well have answered
    /// without reading the request to its end; §8.1 says to tell the peer so
    /// with RST_STREAM(NO_ERROR) — explicitly *not* an error — rather than
    /// leaving it uploading into a stream nobody is listening to. That, plus
    /// `removeJob` handing the unread octets' credit back, is what keeps a
    /// handler which never reads the body from wedging the connection.
    fn finishJob(s: *Session, id: u31, disp: Disposition) void {
        if (disp != .close) {
            if (s.jobs.getPtr(id)) |job| {
                if (!job.complete and !job.rst and !job.over_cap) {
                    s.conn.sendRstStream(&s.wire, id, .no_error) catch {};
                    s.flushWire() catch {};
                }
            }
        }
        s.removeJob(id);
    }

    /// Map one request stream onto the shared handler types, run the
    /// handler, and re-frame its HTTP/1.1 response as h2 frames.
    ///
    /// `id` rather than a `*Job`: the job stays in `s.jobs` for the whole
    /// call (see the field's doc) and every pump can rehash the map, so the
    /// pointer is re-derived at each use and never held.
    fn serveJob(s: *Session, id: u31) Disposition {
        const job = s.jobs.getPtr(id).?;
        job.dispatched = true;
        const streaming = job.streaming;
        // The decoded header list is a heap slice: rehashing moves the `Job`
        // struct and never these bytes, and the job outlives this call.
        const req_headers = job.headers;
        if (job.over_cap) {
            // h1 parity: over-limit body → 413, connection closes (the
            // rest of the body is unbounded — never drain it).
            _ = s.respondError(id, 413);
            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
            s.flushWire() catch {};
            return .close;
        }
        // Buffered surface only: the whole body is already in, and nothing
        // appends to a dispatched buffered job (`onData` guards on it), so
        // this slice is stable for the handler's lifetime.
        const buffered_body: []const u8 = if (streaming) "" else job.body.items;

        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // ── §8.3 pseudo-headers + §8.2 header validity ──────────────────
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
                // §8.2.1: field names must be lowercase.
                for (f.name) |c| {
                    if (c >= 'A' and c <= 'Z') malformed = true;
                }
                // §8.2.2: connection-specific headers are malformed;
                // `te` is allowed only as exactly "trailers".
                if (isConnectionSpecific(f.name)) malformed = true;
                if (std.ascii.eqlIgnoreCase(f.name, "te") and
                    !std.mem.eql(u8, f.value, "trailers")) malformed = true;
                if (std.ascii.eqlIgnoreCase(f.name, "content-length")) {
                    content_length = std.fmt.parseInt(u64, f.value, 10) catch blk: {
                        malformed = true;
                        break :blk null;
                    };
                }
                if (malformed) break;
            }
        }
        if (method_tok == null) malformed = true;
        if (malformed) return s.respondError(id, 400);
        const method = Server.methodFromToken(method_tok.?) orelse
            return s.respondError(id, 501);
        // §8.3.1: GET-family requests need :scheme and a non-empty :path.
        if (scheme == null or path_full == null or path_full.?.len == 0)
            return s.respondError(id, 400);
        // §8.1.1: a content-length must match the actual DATA total. On the
        // streaming surface the total is not known yet — nothing has been
        // received — so `StreamBody` enforces the same rule as it reads,
        // which is also how the h1 `ContentLengthReader` does it.
        if (content_length) |n| {
            if (!streaming and n != buffered_body.len) return s.respondError(id, 400);
        }

        // Origin-form / asterisk-form only, same rule as the h1 loop.
        const target = path_full.?;
        if (target[0] != '/' and !std.mem.eql(u8, target, "*"))
            return s.respondError(id, 400);
        var path: []const u8 = target;
        var query: []const u8 = "";
        if (std.mem.indexOfScalar(u8, target, '?')) |i| {
            path = target[0..i];
            query = target[i + 1 ..];
        }

        // ── synthesize the h1-shaped request the handler expects ────────
        // `Request.header`/`iterateHeaders` read a raw header block, so one
        // is rebuilt from the decoded fields (:authority becomes `host`,
        // matching its §8.3.1 role as the h1 Host).
        var block: Writer.Allocating = .init(arena);
        if (authority) |a| block.writer.print("host: {s}\r\n", .{a}) catch return .close;
        for (req_headers.fields) |f| {
            if (f.name[0] == ':') continue;
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
        const body_scratch = arena.alloc(u8, 4096) catch return .close;
        // Only one of the two body surfaces is ever wired into `body`, so
        // they share `body_scratch`; the streaming one needs a second buffer
        // (see `StreamBody.scratch`) and only allocates it when it is live.
        var stream_scratch: []u8 = &.{};
        if (streaming) stream_scratch = arena.alloc(u8, 4096) catch return .close;
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
            if (s.jobs.getPtr(id).?.trailers) |hl| {
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
            .conn_request_index = s.req_index,
        };

        // ── run the handler against the stock ResponseWriter ────────────
        var date_buf: [Server.http_date_len]u8 = undefined;
        const date: ?[]const u8 = if (s.opts.now) |n|
            Server.formatHttpDate(n.epochSeconds(n.ctx), &date_buf)
        else
            null;
        const body_buf = arena.alloc(u8, s.opts.response_buffer_size) catch return .close;
        var chunk_buf: [64]u8 = undefined;
        const compression_on = s.opts.compression != null and s.opts.gzip_scratch != null;
        // The handler writes an ordinary HTTP/1.1 response, as it always
        // has — into the re-framer instead of into memory. Everything
        // `ResponseWriter` gives an h1 handler (gzip, ranges, conditional
        // requests, content negotiation, the trailer surface) therefore
        // works on h2 unchanged, because none of it knows the difference.
        var framer: Framer = .init(s, id, arena, .{
            .gpa = s.gpa,
            .hold_cap = @max(s.opts.response_buffer_size, 1),
            .buffer = arena.alloc(u8, 256) catch return .close,
        });
        defer framer.deinit();
        var rw: Server.ResponseWriter = .init(&framer.interface, body_buf, &chunk_buf, .{
            .head_request = method == .head,
            .date = date,
            .server_name = s.opts.server_name,
            .compression = if (compression_on) s.opts.compression else null,
            .gzip_scratch = if (compression_on) s.opts.gzip_scratch else null,
            .accept_gzip = compression_on and
                gzip.acceptsGzip(head.header("accept-encoding")),
        });
        sb.req = &req;
        var failed = false;
        s.opts.handler(&req, &rw) catch {
            failed = true;
        };
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
            s.conn.sendRstStream(&s.wire, id, .internal_error) catch {};
            s.flushWire() catch return .close;
            return .keep;
        }
        if (framer.finish() == .close) return .close;
        if (rw.connectionMustClose()) {
            // The handler asked for `Connection: close` — h2 has no such
            // header, the equivalent is a graceful GOAWAY (§6.8).
            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
            s.flushWire() catch {};
            return .close;
        }
        return .keep;
    }

    /// Minimal error response on one stream (h1 `respondError` parity:
    /// status + text/plain reason body, END_STREAM), leaving the connection
    /// alive. Always returns `.keep` so callers can `return s.respondError(...)`.
    fn respondError(s: *Session, id: u31, status: u16) Disposition {
        const reason = Server.reasonPhrase(status);
        var status_buf: [8]u8 = undefined;
        var len_buf: [8]u8 = undefined;
        var body_buf: [64]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch unreachable;
        const body_text = std.fmt.bufPrint(&body_buf, "{s}\n", .{reason}) catch unreachable;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body_text.len}) catch unreachable;
        s.conn.sendHeaders(&s.wire, id, &.{
            .{ .name = ":status", .value = status_str },
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "content-length", .value = len_str },
        }, false) catch return .keep; // stream gone (reset) or overloaded
        s.conn.sendData(&s.wire, id, body_text, true) catch {
            // No window even for the reason text: abort the stream instead.
            s.conn.sendRstStream(&s.wire, id, .internal_error) catch {};
        };
        s.flushWire() catch return .close;
        return .keep;
    }
};

/// Cap on the staged HTTP/1.1 response head the framer will accumulate.
/// `ResponseWriter`'s own `max_response_headers` bounds it far below this;
/// the cap is here so that a framing bug cannot become unbounded growth.
const max_staged_head = 64 * 1024;

/// Cap on one line of the staged chunked framing (a chunk-size line or a
/// trailer field). Same reasoning as `max_staged_head`.
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
    /// encoded, and the framer's own interface buffer.
    arena: Allocator,
    gpa: Allocator,
    hold_cap: usize,

    /// Staged response head, until CRLFCRLF.
    head: std.ArrayList(u8) = .empty,
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

    const InitOptions = struct { gpa: Allocator, hold_cap: usize, buffer: []u8 };

    fn init(s: *Session, id: u31, arena: Allocator, opts: InitOptions) Framer {
        return .{
            .s = s,
            .id = id,
            .arena = arena,
            .gpa = opts.gpa,
            .hold_cap = opts.hold_cap,
            .interface = .{
                .vtable = &.{ .drain = drainFn, .flush = flushFn },
                .buffer = opts.buffer,
            },
        };
    }

    fn deinit(f: *Framer) void {
        f.head.deinit(f.gpa);
        f.held.deinit(f.gpa);
        f.line.deinit(f.gpa);
        f.trailers.deinit(f.gpa);
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

    fn feed(f: *Framer, bytes: []const u8) Writer.Error!void {
        if (f.dead) return error.WriteFailed;
        var rest = bytes;
        while (rest.len != 0) {
            if (!f.head_done) {
                rest = try f.feedHead(rest);
                continue;
            }
            if (!f.chunked) {
                try f.push(rest);
                return;
            }
            rest = try f.feedChunked(rest);
        }
    }

    /// Accumulate the staged response head; once CRLFCRLF lands, parse it
    /// into h2 fields and return whatever followed it.
    fn feedHead(f: *Framer, bytes: []const u8) Writer.Error![]const u8 {
        const start = f.head.items.len;
        f.head.appendSlice(f.gpa, bytes) catch return f.die(.close);
        if (f.head.items.len > max_staged_head) return f.die(.close);
        // The terminator can straddle two writes: rescan the last 3 octets.
        const from = start -| 3;
        const idx = std.mem.indexOfPos(u8, f.head.items, from, "\r\n\r\n") orelse return "";
        // `h1.readHead`'s shape: the field lines, without the blank line.
        const res = h1.ResponseHead.parse(f.head.items[0 .. idx + 2]) catch
            return f.die(.close);
        f.chunked = res.chunked;
        const status_str = std.fmt.allocPrint(f.arena, "{d}", .{res.status}) catch
            return f.die(.close);
        f.fields.append(f.arena, .{ .name = ":status", .value = status_str }) catch
            return f.die(.close);
        var it = res.iterate();
        while (it.next()) |hd| {
            // §8.2.2: connection-specific headers never cross into h2
            // (framing is the frame layer's job now).
            if (isConnectionSpecific(hd.name)) continue;
            // §8.2.1: lowercase on the wire. Copied out of `head`, which is
            // an ArrayList that must be allowed to keep growing.
            const name = std.ascii.allocLowerString(f.arena, hd.name) catch
                return f.die(.close);
            const value = f.arena.dupe(u8, hd.value) catch return f.die(.close);
            f.fields.append(f.arena, .{ .name = name, .value = value }) catch
                return f.die(.close);
        }
        f.head_done = true;
        return bytes[idx + 4 - start ..];
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
                    f.trailers.append(f.gpa, .{ .name = name, .value = value }) catch
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
        f.line.appendSlice(f.gpa, bytes) catch return f.die(.close);
        if (f.line.items.len > max_staged_line) return f.die(.close);
    }

    /// Body octets, framing already stripped: everything above `hold_cap`
    /// goes to the wire now, the tail waits for END_STREAM.
    fn push(f: *Framer, bytes: []const u8) Writer.Error!void {
        if (bytes.len == 0) return;
        if (!f.headers_sent) try f.sendHead(false); // a body exists: no END_STREAM
        if (f.held.items.len + bytes.len <= f.hold_cap) {
            f.held.appendSlice(f.gpa, bytes) catch return f.die(.close);
            return;
        }
        if (f.held.items.len != 0) {
            try f.emit(f.held.items, false);
            f.held.clearRetainingCapacity();
        }
        if (bytes.len > f.hold_cap) {
            const n = bytes.len - f.hold_cap;
            try f.emit(bytes[0..n], false);
            f.held.appendSlice(f.gpa, bytes[n..]) catch return f.die(.close);
        } else {
            f.held.appendSlice(f.gpa, bytes) catch return f.die(.close);
        }
    }

    fn sendHead(f: *Framer, end_stream: bool) Writer.Error!void {
        f.s.conn.sendHeaders(&f.s.wire, f.id, f.fields.items, end_stream) catch |err|
            switch (err) {
                error.OutOfMemory => return f.die(.close),
                else => return f.die(.keep), // stream reset by the peer meanwhile
            };
        f.headers_sent = true;
        f.s.flushWire() catch return f.die(.close);
    }

    /// Put `body` on the wire as DATA under §5.2 flow control: send what the
    /// connection + stream windows allow (the layer splits frames per the
    /// peer's SETTINGS_MAX_FRAME_SIZE), and when both are shut keep reading
    /// the connection until a WINDOW_UPDATE opens room.
    ///
    /// The pump is what makes bidirectional streaming work: a handler
    /// blocked writing its response keeps the receive side live, so the
    /// request body it is also reading continues to arrive.
    fn emit(f: *Framer, body: []const u8, end_stream: bool) Writer.Error!void {
        const s = f.s;
        var off: usize = 0;
        while (off < body.len) {
            if (s.jobs.getPtr(f.id)) |job| {
                if (job.rst) return f.die(.keep);
            }
            const st = s.conn.stream(f.id) orelse return f.die(.keep);
            switch (st.state) {
                .open, .half_closed_remote => {},
                else => return f.die(.keep), // peer reset the stream: abandon
            }
            const win = @min(s.conn.conn_send_window, st.send_window);
            if (win <= 0) {
                s.pump() catch return f.die(.close);
                continue;
            }
            const n = @min(body.len - off, @as(usize, @intCast(win)));
            const last = end_stream and off + n == body.len;
            s.conn.sendData(&s.wire, f.id, body[off..][0..n], last) catch |err| switch (err) {
                error.OutOfMemory => return f.die(.close),
                // Raced a SETTINGS window shrink applied by a pump above.
                error.WindowExhausted => {
                    s.pump() catch return f.die(.close);
                    continue;
                },
                else => return f.die(.keep), // stream reset: abandon
            };
            off += n;
            f.data_sent = true;
            s.flushWire() catch return f.die(.close);
        }
        if (end_stream and body.len == 0) {
            // Post-flush: the last real DATA frame is long gone, so
            // END_STREAM needs a frame of its own.
            s.conn.sendData(&s.wire, f.id, "", true) catch return f.die(.keep);
            s.flushWire() catch return f.die(.close);
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
            f.s.conn.sendHeaders(&f.s.wire, f.id, f.trailers.items, true) catch |err|
                switch (err) {
                    error.OutOfMemory => return .close,
                    else => return .keep, // stream reset by the peer meanwhile
                };
            f.s.flushWire() catch return .close;
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

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const b: *StreamBody = @alignCast(@fieldParentPtr("reader", r));
        while (true) {
            const job = b.s.jobs.getPtr(b.id) orelse return error.ReadFailed;
            if (job.rst) return error.ReadFailed;
            const src = limit.sliceConst(job.unread());
            if (src.len != 0) {
                const n = @min(src.len, b.scratch.len);
                if (b.budget) |left| {
                    if (n > left) {
                        b.exceeded = true;
                        return error.ReadFailed;
                    }
                    b.budget = left - n;
                }
                if (b.remaining) |rem| {
                    // §8.1.1: more DATA than the declared content-length.
                    if (n > rem) return error.ReadFailed;
                    b.remaining = rem - n;
                }
                @memcpy(b.scratch[0..n], src[0..n]);
                // From here on nothing may touch `job` again: this write can
                // re-enter the connection (see `scratch`).
                try w.writeAll(b.scratch[0..n]);
                const jp = b.s.jobs.getPtr(b.id) orelse return error.ReadFailed;
                jp.read_pos += n;
                if (jp.read_pos == jp.body.items.len) {
                    // Fully drained: reclaim the buffer instead of letting a
                    // long upload accumulate behind the cursor.
                    jp.body.clearRetainingCapacity();
                    jp.read_pos = 0;
                }
                b.s.grantJob(b.id, n);
                return n;
            }
            // Only END_STREAM ends the body — a lull in the DATA frames does
            // not, and neither does a trailer section that has not landed.
            if (job.complete) {
                b.materializeTrailers();
                if (b.remaining) |rem| {
                    // §8.1.1: fewer DATA octets than the declared length.
                    if (rem != 0) return error.ReadFailed;
                }
                return error.EndOfStream;
            }
            b.s.pump() catch return error.ReadFailed;
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

/// Whether a decoded field block contains any pseudo-header field — never
/// legal in a trailer section (RFC 9113 §8.1).
fn containsPseudoHeader(list: hpack.HeaderList) bool {
    for (list.fields) |f| {
        if (f.name.len != 0 and f.name[0] == ':') return true;
    }
    return false;
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

test "h2c serve: malformed requests → 400/501, connection survives (offline)" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa, .{});
    defer peer.deinit();

    try peer.conn.sendPreface(&peer.wire);
    // No :path (§8.3.1) → 400.
    const sid_nopath = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "t" },
    }, true);
    // Connection-specific header (§8.2.2) → 400.
    const sid_connhdr = try peer.conn.startStream(&peer.wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/hello" },
        .{ .name = "connection", .value = "keep-alive" },
    }, true);
    // content-length disagreeing with the DATA total (§8.1.1) → 400.
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

    try testing.expectEqual(@as(u16, 400), peer.resp(sid_nopath).status);
    try testing.expectEqualStrings("Bad Request\n", peer.resp(sid_nopath).body.items);
    try testing.expectEqual(@as(u16, 400), peer.resp(sid_connhdr).status);
    try testing.expectEqual(@as(u16, 400), peer.resp(sid_badlen).status);
    try testing.expectEqual(@as(u16, 501), peer.resp(sid_brew).status);
    try testing.expectEqual(@as(u16, 200), peer.resp(sid_ok).status);
    try testing.expectEqualStrings("hello", peer.resp(sid_ok).body.items);
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
    // `/echo` is not a `/stream-*` route: it must still see the 400 that only
    // a fully collected body can produce (§8.1.1).
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

    try testing.expectEqual(@as(u16, 400), peer.resp(sid_bad).status);
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
    // here plus the 4 the malformed stream sent before its 400.
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
        const n = res.content_length.?;
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
