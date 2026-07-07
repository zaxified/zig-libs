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
//! per-stream request state (decoded header list + a copy of the DATA
//! bytes) accumulates in a map, so interleaved streams are all collected —
//! but completed requests are handled **sequentially** on the connection's
//! task (no concurrent-stream scheduling yet). The handler writes an
//! ordinary HTTP/1.1 response into memory through the stock
//! `ResponseWriter`; that response is then re-framed as h2 HEADERS + DATA:
//! connection-specific headers are stripped (§8.2.2), names lowercased
//! (§8.2.1), the peer's SETTINGS_MAX_FRAME_SIZE honored (`h2.Connection`
//! splits DATA/CONTINUATION), and both flow-control windows respected —
//! when the response body outruns the peer's window the loop keeps reading
//! (WINDOW_UPDATE, and anything else the peer sends) until room opens
//! (§5.2). Request-body flow control is replenished as DATA arrives so
//! uploads above the initial 64 KiB window stream freely up to
//! `max_body_bytes` (h1 parity: over the cap → 413, connection closes).
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
const Job = struct {
    id: u31,
    headers: hpack.HeaderList,
    body: std.ArrayList(u8) = .empty,
    /// END_STREAM seen — ready for the handler.
    complete: bool = false,
    /// Body crossed `max_body_bytes` (or memory ran out) → 413 + close.
    over_cap: bool = false,

    fn deinit(job: *Job, gpa: Allocator) void {
        job.headers.deinit(gpa);
        job.body.deinit(gpa);
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
    jobs: std.AutoArrayHashMapUnmanaged(u31, Job) = .empty,
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
            while (s.takeReady()) |taken| {
                var job = taken;
                defer job.deinit(s.gpa);
                s.fireConnState(.active);
                const disp = s.serveJob(&job);
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
            // Trailers (§8.1): the handler API has no trailer surface, so
            // the fields are dropped; END_STREAM completes the request.
            hd.headers.deinit(s.gpa);
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
        s.jobs.put(s.gpa, hd.stream_id, .{
            .id = hd.stream_id,
            .headers = hd.headers, // ownership moves into the job
            .complete = hd.end_stream,
        }) catch {
            // Overloaded: shed the stream, keep the connection (same
            // policy as the h1 loop's allocation failures).
            hd.headers.deinit(s.gpa);
            s.conn.sendRstStream(&s.wire, hd.stream_id, .refused_stream) catch {};
        };
    }

    fn onData(s: *Session, d: @FieldType(h2.Event, "data")) void {
        const job = s.jobs.getPtr(d.stream_id) orelse return; // reset: ignore
        if (d.end_stream) job.complete = true;
        // Replenish what the peer consumed (§6.9) so request bodies are
        // never window-throttled — the cap is `max_body_bytes`, not the
        // 64 KiB initial window. (Padding octets are charged by the layer
        // but not visible here; padded uploads shrink the window slightly.)
        if (d.data.len != 0) {
            const inc: u31 = @intCast(d.data.len);
            s.conn.sendWindowUpdate(&s.wire, 0, inc) catch {};
            if (!d.end_stream) s.conn.sendWindowUpdate(&s.wire, d.stream_id, inc) catch {};
        }
        if (job.over_cap) return; // already shedding: drop the bytes
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

    /// Next request ready for the handler, in stream-arrival order.
    /// Over-cap streams are "ready" too — they answer 413 immediately.
    fn takeReady(s: *Session) ?Job {
        for (s.jobs.keys()) |id| {
            const job = s.jobs.getPtr(id).?;
            if (job.complete or job.over_cap)
                return s.jobs.fetchOrderedRemove(id).?.value;
        }
        return null;
    }

    fn dropJob(s: *Session, id: u31) void {
        if (s.jobs.fetchOrderedRemove(id)) |kv| {
            var job = kv.value;
            job.deinit(s.gpa);
        }
    }

    /// Map one complete request stream onto the shared handler types, run
    /// the handler, and re-frame its HTTP/1.1 response as h2 frames.
    fn serveJob(s: *Session, job: *Job) Disposition {
        if (job.over_cap) {
            // h1 parity: over-limit body → 413, connection closes (the
            // rest of the body is unbounded — never drain it).
            _ = s.respondError(job.id, 413);
            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
            s.flushWire() catch {};
            return .close;
        }

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
        for (job.headers.fields) |f| {
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
        if (malformed) return s.respondError(job.id, 400);
        const method = Server.methodFromToken(method_tok.?) orelse
            return s.respondError(job.id, 501);
        // §8.3.1: GET-family requests need :scheme and a non-empty :path.
        if (scheme == null or path_full == null or path_full.?.len == 0)
            return s.respondError(job.id, 400);
        // §8.1.1: a content-length must match the actual DATA total.
        if (content_length) |n| {
            if (n != job.body.items.len) return s.respondError(job.id, 400);
        }

        // Origin-form / asterisk-form only, same rule as the h1 loop.
        const target = path_full.?;
        if (target[0] != '/' and !std.mem.eql(u8, target, "*"))
            return s.respondError(job.id, 400);
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
        for (job.headers.fields) |f| {
            if (f.name[0] == ':') continue;
            block.writer.print("{s}: {s}\r\n", .{ f.name, f.value }) catch return .close;
        }
        const head: h1.RequestHead = .{
            .method = method_tok.?,
            .target = target,
            .http1_0 = false,
            .header_block = block.written(),
            .host = authority,
            .content_length = if (job.body.items.len != 0) job.body.items.len else null,
        };
        // The body reader mirrors the h1 shape exactly: a ContentLength
        // decoder (write-through, empty interface buffer) over the collected
        // bytes — a bare `.fixed` Reader would lose its buffered tail on the
        // `discard` path (std drops partial counts under EndOfStream).
        var body_inner: Reader = .fixed(job.body.items);
        const body_scratch = arena.alloc(u8, 4096) catch return .close;
        var body: Server.RequestBody = if (job.body.items.len != 0)
            .{ .limited = .init(&body_inner, job.body.items.len, body_scratch) }
        else
            .{ .none = .fixed("") };
        var req: Server.Request = .{
            .method = method,
            .target = target,
            .path = path,
            .query = query,
            .head = head,
            .body = &body,
            .context = s.opts.context,
            .peer = s.opts.peer,
            .conn_request_index = s.req_index,
        };

        // ── run the handler against the stock ResponseWriter, in memory ──
        var date_buf: [Server.http_date_len]u8 = undefined;
        const date: ?[]const u8 = if (s.opts.now) |n|
            Server.formatHttpDate(n.epochSeconds(n.ctx), &date_buf)
        else
            null;
        const body_buf = arena.alloc(u8, s.opts.response_buffer_size) catch return .close;
        var chunk_buf: [64]u8 = undefined;
        const compression_on = s.opts.compression != null and s.opts.gzip_scratch != null;
        var acc: Writer.Allocating = .init(arena);
        var rw: Server.ResponseWriter = .init(&acc.writer, body_buf, &chunk_buf, .{
            .head_request = method == .head,
            .date = date,
            .server_name = s.opts.server_name,
            .compression = if (compression_on) s.opts.compression else null,
            .gzip_scratch = if (compression_on) s.opts.gzip_scratch else null,
            .accept_gzip = compression_on and
                gzip.acceptsGzip(head.header("accept-encoding")),
        });
        var failed = false;
        s.opts.handler(&req, &rw) catch {
            failed = true;
        };
        if (!failed) rw.end() catch {
            failed = true; // e.g. body ≠ declared Content-Length
        };
        // Handler errors always get a clean 500 here: unlike h1, nothing
        // has touched the real wire yet, so the staged bytes are discarded.
        if (failed) return s.respondError(job.id, 500);

        // ── re-frame the staged HTTP/1.1 response as h2 ──────────────────
        var rr: Reader = .fixed(acc.written());
        const head_buf = arena.alloc(u8, 16 * 1024) catch return .close;
        const res_block = h1.readHead(&rr, head_buf) catch return .close;
        const res = h1.ResponseHead.parse(res_block) catch return .close;
        var payload: Writer.Allocating = .init(arena);
        if (res.chunked) {
            var scratch: [256]u8 = undefined;
            var cr: h1.ChunkedReader = .init(&rr, &scratch);
            _ = cr.reader.streamRemaining(&payload.writer) catch return .close;
        } else {
            _ = rr.streamRemaining(&payload.writer) catch return .close;
        }
        const body_bytes = payload.written();

        var fields: std.ArrayList(hpack.Field) = .empty;
        const status_str = std.fmt.allocPrint(arena, "{d}", .{res.status}) catch return .close;
        fields.append(arena, .{ .name = ":status", .value = status_str }) catch return .close;
        var it = res.iterate();
        while (it.next()) |hd| {
            // §8.2.2: connection-specific headers never cross into h2
            // (framing is the frame layer's job now).
            if (isConnectionSpecific(hd.name)) continue;
            const name = std.ascii.allocLowerString(arena, hd.name) catch return .close;
            fields.append(arena, .{ .name = name, .value = hd.value }) catch return .close;
        }

        s.conn.sendHeaders(&s.wire, job.id, fields.items, body_bytes.len == 0) catch |err|
            switch (err) {
                error.OutOfMemory => return .close,
                else => return .keep, // stream reset by the peer meanwhile
            };
        s.flushWire() catch return .close;
        if (body_bytes.len != 0) {
            if (s.sendBody(job.id, body_bytes) == .close) return .close;
        }
        if (rw.connectionMustClose()) {
            // The handler asked for `Connection: close` — h2 has no such
            // header, the equivalent is a graceful GOAWAY (§6.8).
            s.conn.sendGoaway(&s.wire, .no_error, "") catch {};
            s.flushWire() catch {};
            return .close;
        }
        return .keep;
    }

    /// Stream the response body as DATA frames under §5.2 flow control:
    /// send what the connection + stream windows allow (the layer splits
    /// frames per the peer's SETTINGS_MAX_FRAME_SIZE), and when both are
    /// exhausted keep reading the connection until WINDOW_UPDATE opens room.
    fn sendBody(s: *Session, id: u31, body: []const u8) Disposition {
        var off: usize = 0;
        while (off < body.len) {
            const st = s.conn.stream(id) orelse return .keep;
            switch (st.state) {
                .open, .half_closed_remote => {},
                else => return .keep, // peer reset the stream: abandon
            }
            const win = @min(s.conn.conn_send_window, st.send_window);
            if (win <= 0) {
                s.pump() catch return .close;
                continue;
            }
            const n = @min(body.len - off, @as(usize, @intCast(win)));
            const last = off + n == body.len;
            s.conn.sendData(&s.wire, id, body[off..][0..n], last) catch |err| switch (err) {
                error.OutOfMemory => return .close,
                // Raced a SETTINGS window shrink applied by a pump above.
                error.WindowExhausted => {
                    s.pump() catch return .close;
                    continue;
                },
                else => return .keep, // stream reset: abandon
            };
            off += n;
            s.flushWire() catch return .close;
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
    } else if (std.mem.eql(u8, req.path, "/fail")) {
        try rw.writeAll("partial");
        return error.Boom;
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

/// One response stream as seen by the test client.
const Collected = struct {
    status: u16 = 0,
    /// The response header list (moved out of the event; trailers dropped).
    headers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    data_frames: u32 = 0,
    end: bool = false,
    rst: ?h2.ErrorCode = null,

    fn header(c: *const Collected, name: []const u8) ?[]const u8 {
        const hl = c.headers orelse return null;
        for (hl.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    fn deinit(c: *Collected, gpa: Allocator) void {
        if (c.headers) |*hl| hl.deinit(gpa);
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

    fn init(gpa: Allocator, settings: h2.Settings) TestPeer {
        return .{ .gpa = gpa, .conn = .init(gpa, .client, .{ .settings = settings }) };
    }

    fn deinit(p: *TestPeer) void {
        for (p.resps.values()) |*c| c.deinit(p.gpa);
        p.resps.deinit(p.gpa);
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
                    if (g.value_ptr.header(":status")) |v|
                        g.value_ptr.status = std.fmt.parseInt(u16, v, 10) catch 0;
                } else hd.headers.deinit(p.gpa);
                if (hd.end_stream) g.value_ptr.end = true;
            },
            .data => |d| {
                const g = try p.resps.getOrPut(p.gpa, d.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                try g.value_ptr.body.appendSlice(p.gpa, d.data);
                g.value_ptr.data_frames += 1;
                if (d.end_stream) g.value_ptr.end = true;
            },
            .stream_reset => |r| {
                const g = try p.resps.getOrPut(p.gpa, r.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                g.value_ptr.rst = r.code;
                g.value_ptr.end = true;
            },
            .goaway => |g| p.goaway = g.code,
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
