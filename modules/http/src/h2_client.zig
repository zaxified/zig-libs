// SPDX-License-Identifier: MIT

//! h2 client engine (Phase 3.2): drives `h2.Connection` in **client** role
//! over a byte transport (`std.Io.Reader`/`std.Io.Writer` — socket-free, so
//! tests run from fixed buffers). `Client.connectH2c` binds it to a TCP
//! stream for cleartext HTTP/2 via **prior knowledge** (RFC 9113 §3.3 —
//! the client just opens with the connection preface). For h2-over-TLS the
//! seam is `Session.init` itself (Phase 3.3, bring-your-own-TLS): do the
//! TLS handshake with your own library offering `http.alpn_offer`, and
//! when the negotiated ALPN protocol is "h2" (`http.protocolFromAlpn`,
//! RFC 7301; over TLS h2 is selected only via ALPN, RFC 9113 §3.3) hand
//! the TLS connection's plaintext reader/writer to `Session.init` — or use
//! `Client.connectH2Over`, the convenience wrapper that also carries the
//! default `:authority`. The wire shape is identical to h2c from the
//! preface onward; remember `:scheme` should be "https" on requests over
//! TLS (`RequestOptions.scheme`, RFC 9113 §8.3.1).
//!
//! Model: one `Session` **multiplexes** any number of requests over one
//! connection. `request` opens a stream (§5.1.1: odd, monotonic ids) and
//! sends the §8.3 pseudo-header request form (`:method`/`:scheme`/`:path`/
//! `:authority` + lowercased regular headers, §8.2.1, with
//! connection-specific headers stripped, §8.2.2) plus an optional DATA body
//! under §5.2 flow control. Frames read back are demultiplexed by stream id
//! into per-stream response state, so many requests can be in flight before
//! `awaitResponse` collects each one — interleaved server frames land on
//! the right response regardless of order.
//!
//! ## Two surfaces, one engine
//!
//! `request` + `awaitResponse` is the **buffered** surface: an in-memory
//! request body goes out, a fully assembled `Response` comes back. It is
//! all most callers want and it is unchanged.
//!
//! Underneath it — and usable directly — is the **incremental** surface,
//! for the transfers a buffered call cannot express: a body you do not have
//! yet, a response you must process as it arrives, or both at once on one
//! stream (a long download, an upload of unknown length, an event stream
//! over h2, a bidirectional RPC):
//!
//!     const sid = try s.openStream(.post, "/rpc", .{ .authority = "h" });
//!     try s.sendData(sid, first_chunk, false);   // more may follow
//!     const head = try s.awaitHead(sid);         // status/headers, early
//!     try s.sendData(sid, last_chunk, true);     // END_STREAM: body done
//!     var buf: [4096]u8 = undefined;
//!     while (try s.readBody(sid, &buf)) |...| …  // 0 = body complete
//!     const tr = s.trailers(sid);                // distinct from the end
//!     s.release(sid);
//!
//! Both directions stay live throughout: every blocking call pumps the one
//! connection, so `sendData` waiting on a flow-control grant keeps folding
//! arriving response frames into the demux table, and `readBody` waiting on
//! DATA does not stop the upload from being resumable on the next call.
//! `awaitResponse` is written *on top of* this surface (open → await head →
//! drain → take trailers), so there is a single flow-control engine rather
//! than a buffered one and a streaming one that can drift apart.
//!
//! ## Flow control, in one line each
//!
//! Send: `sendData` blocks until every octet has been handed to the
//! transport, reading the connection for WINDOW_UPDATE grants when the
//! peer's window is shut; `sendDataPartial` is the one-shot variant that
//! never blocks and *returns the count it accepted*. Receive: window credit
//! is returned when the **caller consumes** bytes, never when they arrive —
//! see `readBody` for why that is the only defensible answer for a
//! streaming reader.
//!
//! Errors mirror §5.4 + §6.8, and peer bytes never panic (all typed via
//! `h2.Connection`): a connection-scoped violation answers GOAWAY with the
//! layer's §7 code and poisons the session (`error.ProtocolError`
//! thereafter); a server RST_STREAM fails only that request
//! (`error.StreamReset`, code in `Session.last_reset_code`) while other
//! streams continue; a server GOAWAY lets in-flight streams at or below
//! `last_stream_id` finish, fails those above it (`error.StreamRefused` —
//! safely retryable elsewhere, §6.8) and refuses new `request` calls
//! (`error.GoawayReceived`).
//!
//! Provenance: clean-room from RFC 9113 (client preface §3.4, streams
//! §5.1, flow control §5.2/§6.9, GOAWAY §6.8, HTTP semantics §8.1–§8.3)
//! and RFC 7301 (ALPN — consumed, not implemented); no HTTP/2 client
//! implementation source was consulted or copied.

const std = @import("std");
const http = @import("root.zig");
const h2 = @import("h2.zig");
const hpack = @import("hpack.zig");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Everything a `Session` call can fail with. Stream-scoped failures
/// (`StreamReset`, `StreamRefused`) leave the session usable; the rest of
/// the connection-scoped ones latch (`Session.broken`) and repeat.
pub const Error = error{
    /// Connection-scoped protocol violation (either side); a GOAWAY with
    /// the §7 code was sent and the session is dead.
    ProtocolError,
    /// The server reset this stream (RST_STREAM, §6.4); the code is in
    /// `Session.last_reset_code`. Other streams are unaffected.
    StreamReset,
    /// A server GOAWAY marked this stream unprocessed (§6.8) — it is safe
    /// to retry on a fresh connection. Other in-flight streams finish.
    StreamRefused,
    /// GOAWAY already received — no new streams may be started (§6.8).
    GoawayReceived,
    /// The stream id was never issued by `request`/`openStream` (or has
    /// already been collected/released).
    UnknownStream,
    /// The request body was already ended — END_STREAM has been sent on
    /// this stream, so no further `sendData` is possible. A caller bug,
    /// deliberately distinct from `StreamReset` (a peer action).
    SendClosed,
    /// Transport EOF/failure before the stream completed.
    ConnectionClosed,
    /// The response is missing a valid `:status` pseudo-header (§8.3.2).
    MalformedResponse,
    WriteFailed,
    OutOfMemory,
};

pub const Options = struct {
    /// SETTINGS we advertise (§6.5). Push stays disabled by default; a
    /// promised stream is refused with RST_STREAM(REFUSED_STREAM) if it is
    /// enabled and the server pushes anyway.
    settings: h2.Settings = .{ .enable_push = false },
    /// DoS-hardening pass-throughs to `h2.Connection` (see its module doc).
    max_header_block: usize = 1 << 20,
    max_continuation_frames: u32 = 32,
    max_reset_streams: u32 = 100,
    max_unproductive_frames: u32 = 1024,
};

/// The request *head* — everything `openStream` needs. `RequestOptions`
/// is this plus a complete in-memory body; they are kept as two types so
/// that "open a stream and feed it over time" cannot be confused with
/// "send this whole body now".
pub const StreamOptions = struct {
    /// `:scheme` pseudo-header (§8.3.1). h2c is cleartext, hence "http".
    scheme: []const u8 = "http",
    /// `:authority` pseudo-header; null = omit (callers going through
    /// `Client.connectH2c` get the connected host[:port] by default).
    authority: ?[]const u8 = null,
    /// Extra request headers. Names are lowercased on the wire (§8.2.1);
    /// connection-specific headers and `Host` are dropped (§8.2.2 — the
    /// authority pseudo-header carries the host).
    headers: []const http.Header = &.{},
};

pub const RequestOptions = struct {
    /// `:scheme` pseudo-header (§8.3.1). h2c is cleartext, hence "http".
    scheme: []const u8 = "http",
    /// `:authority` pseudo-header; null = omit (callers going through
    /// `Client.connectH2c` get the connected host[:port] by default).
    authority: ?[]const u8 = null,
    /// Extra request headers. Names are lowercased on the wire (§8.2.1);
    /// connection-specific headers and `Host` are dropped (§8.2.2 — the
    /// authority pseudo-header carries the host).
    headers: []const http.Header = &.{},
    /// In-memory request body; empty/null sends END_STREAM on HEADERS.
    body: ?[]const u8 = null,

    fn head(o: RequestOptions) StreamOptions {
        return .{ .scheme = o.scheme, .authority = o.authority, .headers = o.headers };
    }
};

/// A complete, owned response: final status + header list + assembled body.
/// Release with `deinit`.
pub const Response = struct {
    status: u16,
    headers: hpack.HeaderList,
    body: []u8,
    /// The **trailer section** (RFC 9113 §8.1) — the fields of the HEADERS
    /// frame that followed the DATA frames, or null when the response had
    /// none. Field names are lowercase, as on the wire.
    trailers: ?hpack.HeaderList = null,

    /// First value of a response header (case-insensitive), or null.
    pub fn header(res: *const Response, name: []const u8) ?[]const u8 {
        for (res.headers.fields) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        }
        return null;
    }

    /// First value of a response **trailer** field (case-insensitive), or
    /// null. Kept separate from `header` on purpose: a trailer arrives
    /// after the caller may already have acted on the head, so merging the
    /// two namespaces would let a late field masquerade as an early one.
    pub fn trailer(res: *const Response, name: []const u8) ?[]const u8 {
        const hl = res.trailers orelse return null;
        for (hl.fields) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        }
        return null;
    }

    pub fn deinit(res: *Response, gpa: Allocator) void {
        res.headers.deinit(gpa);
        if (res.trailers) |*hl| hl.deinit(gpa);
        gpa.free(res.body);
        res.* = undefined;
    }
};

/// The response **head** as seen by a streaming caller: the status and the
/// final header section, available as soon as the HEADERS frame arrives —
/// typically long before the body is complete, sometimes long before any of
/// it exists.
///
/// The header list is **borrowed** from the session's per-stream state: it
/// stays valid until that stream is released (`release`, `cancel`,
/// `awaitResponse`) or the session is deinitialized. Do not `deinit` it.
/// (Borrowing is safe across other session calls even though the demux
/// table may rehash: `hpack.HeaderList` is a heap slice, so only the
/// `Pending` struct moves, never the field bytes.)
pub const Head = struct {
    status: u16,
    headers: hpack.HeaderList,

    /// First value of a response header (case-insensitive), or null.
    pub fn header(h: *const Head, name: []const u8) ?[]const u8 {
        for (h.headers.fields) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        }
        return null;
    }
};

/// One response stream being assembled from demultiplexed frames.
const Pending = struct {
    /// Final response header list (interim 1xx responses are skipped).
    headers: ?hpack.HeaderList = null,
    /// Trailer section: a second HEADERS frame after the DATA frames.
    trailers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    /// Read cursor into `body`: everything before it has been handed to the
    /// caller and its receive-window credit already returned (§6.9). The
    /// octets from here to `body.items.len` are the ones we are still
    /// holding — the exact quantity we must NOT re-advertise.
    read_pos: usize = 0,
    /// END_STREAM seen — the response is complete (body *and* trailers).
    end: bool = false,
    /// We sent END_STREAM: the request body is finished.
    send_end: bool = false,
    /// Server RST_STREAM (or a local stream-scoped recovery) code.
    rst: ?h2.ErrorCode = null,
    /// Marked unprocessed by a server GOAWAY (§6.8).
    refused: bool = false,

    /// Received but not yet consumed by the caller.
    fn unread(p: *const Pending) []const u8 {
        return p.body.items[p.read_pos..];
    }

    fn deinit(p: *Pending, gpa: Allocator) void {
        if (p.headers) |*hl| hl.deinit(gpa);
        if (p.trailers) |*hl| hl.deinit(gpa);
        p.body.deinit(gpa);
    }
};

/// An HTTP/2 client connection: issue `request` any number of times (the
/// streams run concurrently on the wire), then `awaitResponse` each stream
/// id. Single-owner, like the rest of the module: one task drives a
/// Session. `deinit` releases everything; call `shutdown` first for a
/// graceful GOAWAY.
pub const Session = struct {
    gpa: Allocator,
    /// Server → client bytes.
    in: *Reader,
    /// Client → server bytes; flushed after every staged batch.
    out: *Writer,
    conn: h2.Connection,
    /// Outgoing wire bytes staged by the h2 layer; flushed to `out`.
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,
    /// Demux table: in-flight response state keyed by stream id.
    streams: std.AutoArrayHashMapUnmanaged(u31, Pending) = .empty,
    /// Set once the server sends GOAWAY (§6.8).
    goaway: ?Goaway = null,
    /// Connection-scoped failure, latched: every later call repeats it.
    broken: ?Error = null,
    /// §7 code of the most recent `error.StreamReset`.
    last_reset_code: ?h2.ErrorCode = null,

    pub const Goaway = struct { last_stream_id: u31, code: h2.ErrorCode };

    /// Send the §3.4 client connection preface (magic + our SETTINGS) and
    /// hand back a ready session. `in`/`out` must outlive it.
    pub fn init(gpa: Allocator, in: *Reader, out: *Writer, options: Options) Error!Session {
        var s: Session = .{
            .gpa = gpa,
            .in = in,
            .out = out,
            .conn = .init(gpa, .client, .{
                .settings = options.settings,
                .max_header_block = options.max_header_block,
                .max_continuation_frames = options.max_continuation_frames,
                .max_reset_streams = options.max_reset_streams,
                .max_unproductive_frames = options.max_unproductive_frames,
            }),
        };
        errdefer s.deinit();
        try s.conn.sendPreface(&s.wire);
        s.flushWire() catch return error.WriteFailed;
        return s;
    }

    pub fn deinit(s: *Session) void {
        for (s.streams.values()) |*p| p.deinit(s.gpa);
        s.streams.deinit(s.gpa);
        s.events.deinit(s.gpa); // always drained by processEvents
        s.wire.deinit(s.gpa);
        s.conn.deinit();
        s.* = undefined;
    }

    /// Graceful close: GOAWAY(NO_ERROR), best effort. Call before `deinit`
    /// when the peer deserves notice (§6.8).
    pub fn shutdown(s: *Session) void {
        if (s.broken != null) return;
        s.conn.sendGoaway(&s.wire, .no_error, "") catch return;
        s.flushWire() catch {};
    }

    /// Open a stream and send the request (HEADERS, then DATA under §5.2
    /// flow control when `options.body` is non-empty — blocking for
    /// WINDOW_UPDATE grants as needed). Returns the stream id to pass to
    /// `awaitResponse`; any number of requests may be in flight at once.
    ///
    /// This is the buffered surface, and it is exactly `openStream` +
    /// `sendData(…, true)` — see `openStream` when the body is not all in
    /// memory yet.
    pub fn request(
        s: *Session,
        method: http.Method,
        path: []const u8,
        options: RequestOptions,
    ) Error!u31 {
        const body = options.body orelse "";
        const sid = try s.open(method, path, options.head(), body.len == 0);
        if (body.len != 0) try s.sendData(sid, body, true);
        return sid;
    }

    /// Open a stream, send only the request **head** (HEADERS without
    /// END_STREAM) and return its id: the request body follows over time
    /// via `sendData`/`sendDataPartial` and ends with `closeSend` (or
    /// `sendData(…, true)`).
    ///
    /// The response side is live from this moment: `awaitHead`/`readBody`
    /// may be interleaved with the sending, on this stream or any other.
    /// For a request whose body is already in memory, use `request`.
    pub fn openStream(
        s: *Session,
        method: http.Method,
        path: []const u8,
        options: StreamOptions,
    ) Error!u31 {
        return s.open(method, path, options, false);
    }

    /// Shared by both: build the §8.3 request form and start the stream.
    fn open(
        s: *Session,
        method: http.Method,
        path: []const u8,
        options: StreamOptions,
        end_stream: bool,
    ) Error!u31 {
        if (s.broken) |e| return e;
        if (s.goaway != null) return error.GoawayReceived;

        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // §8.3.1 pseudo-headers first, then the regular headers, names
        // lowercased (§8.2.1) and connection-specific ones dropped (§8.2.2).
        var fields: std.ArrayList(hpack.Field) = .empty;
        try fields.append(arena, .{ .name = ":method", .value = method.token() });
        try fields.append(arena, .{ .name = ":scheme", .value = options.scheme });
        try fields.append(arena, .{ .name = ":path", .value = path });
        if (options.authority) |a| {
            if (a.len != 0) try fields.append(arena, .{ .name = ":authority", .value = a });
        }
        for (options.headers) |hd| {
            if (isConnectionSpecific(hd.name) or std.ascii.eqlIgnoreCase(hd.name, "host"))
                continue;
            if (std.ascii.eqlIgnoreCase(hd.name, "te") and
                !std.mem.eql(u8, hd.value, "trailers")) continue;
            try fields.append(arena, .{
                .name = try std.ascii.allocLowerString(arena, hd.name),
                .value = hd.value,
            });
        }

        const sid = s.conn.startStream(&s.wire, fields.items, end_stream) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // A freshly opened client stream is always writable.
                else => return s.fail(error.ProtocolError),
            };
        s.streams.put(s.gpa, sid, .{ .send_end = end_stream }) catch return error.OutOfMemory;
        s.flushWire() catch return s.fail(error.WriteFailed);
        return sid;
    }

    // ── incremental send ────────────────────────────────────────────────────

    /// Send `bytes` as DATA on `sid`, **blocking until all of them are away**
    /// under §5.2 flow control: what the peer's connection/stream windows
    /// allow goes out at once, and when they are shut this reads the
    /// connection (advancing every other stream meanwhile) until a
    /// WINDOW_UPDATE opens room. `end_stream` closes the request body
    /// (END_STREAM rides the last DATA frame, so no extra frame is spent).
    ///
    /// Blocking, rather than a partial send, is the default on purpose: this
    /// engine is single-owner and blocking throughout, and a partial-send
    /// default would put the same retry loop in every caller — where a
    /// caller who ignored the count would silently truncate the body.
    /// `sendDataPartial` is there for callers that must not block; it hands
    /// back the count, and Zig's unused-result rule makes discarding it an
    /// explicit act.
    pub fn sendData(s: *Session, sid: u31, bytes: []const u8, end_stream: bool) Error!void {
        var off: usize = 0;
        var end_sent = false;
        while (off < bytes.len) {
            const n = try s.sendSome(sid, bytes[off..], end_stream);
            if (n == 0) {
                try s.pump(); // window shut: wait for a §6.9 grant
                continue;
            }
            off += n;
            // `sendSome` puts END_STREAM on the frame that carries the last
            // octet, so no extra frame is spent on it.
            end_sent = end_stream and off == bytes.len;
        }
        // An empty body still needs its END_STREAM (an empty DATA frame) —
        // and this is also the path that must REFUSE a second close rather
        // than quietly succeeding, hence going through `sendSome`.
        if (end_stream and !end_sent) _ = try s.sendSome(sid, "", true);
    }

    /// One non-blocking attempt: send as much of `bytes` as the §5.2 windows
    /// currently allow and return how many octets that was — possibly 0 when
    /// the peer's window is shut. Never ends the stream; call `closeSend`
    /// for that. The remainder is the caller's to retry (nothing is queued
    /// internally, so nothing can be silently dropped).
    pub fn sendDataPartial(s: *Session, sid: u31, bytes: []const u8) Error!usize {
        return s.sendSome(sid, bytes, false);
    }

    /// End the request body: END_STREAM with no further payload (§8.1).
    /// The response side stays fully open.
    pub fn closeSend(s: *Session, sid: u31) Error!void {
        return s.sendData(sid, "", true);
    }

    /// Whether END_STREAM has been sent on `sid` (false for unknown ids).
    pub fn sendEnded(s: *const Session, sid: u31) bool {
        const p = s.streams.getPtr(sid) orelse return false;
        return p.send_end;
    }

    /// The single send attempt both public forms are built from: emits at
    /// most one flow-control-bounded batch and returns the octets accepted.
    fn sendSome(s: *Session, sid: u31, bytes: []const u8, end_stream: bool) Error!usize {
        if (s.broken) |e| return e;
        const p = s.streams.getPtr(sid) orelse return error.UnknownStream;
        if (p.rst) |code| {
            s.last_reset_code = code;
            return error.StreamReset;
        }
        if (p.send_end) return error.SendClosed;
        const st = s.conn.stream(sid) orelse return error.StreamReset;
        switch (st.state) {
            // half_closed_remote = the peer already finished its response
            // (END_STREAM received) while we are still uploading — legal,
            // and the case that makes this more than a refactor.
            .open, .half_closed_remote => {},
            else => return error.StreamReset, // peer reset mid-upload
        }
        const win = @min(s.conn.conn_send_window, st.send_window);
        if (win <= 0 and bytes.len != 0) return 0;
        const n = @min(bytes.len, @as(usize, @intCast(@max(win, 0))));
        const last = end_stream and n == bytes.len;
        s.conn.sendData(&s.wire, sid, bytes[0..n], last) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Raced a SETTINGS window shrink applied by a pump above.
            error.WindowExhausted => return 0,
            else => return error.StreamReset,
        };
        if (last) p.send_end = true;
        s.flushWire() catch return s.fail(error.WriteFailed);
        return n;
    }

    // ── incremental receive ─────────────────────────────────────────────────

    /// Block until the response **head** for `sid` arrives (interim 1xx
    /// responses are skipped, §8.1) and return it — status and headers,
    /// without waiting for a single body octet. Idempotent: the head is
    /// borrowed from the session, not moved out of it (see `Head`).
    pub fn awaitHead(s: *Session, sid: u31) Error!Head {
        try s.waitHead(sid);
        const p = s.streams.getPtr(sid) orelse return error.UnknownStream;
        const headers = p.headers orelse return error.MalformedResponse;
        const status = statusOf(headers) orelse return error.MalformedResponse;
        return .{ .status = status, .headers = headers };
    }

    /// Copy up to `buf.len` octets of the response body into `buf` and
    /// return how many; **0 means the body is complete** (END_STREAM seen —
    /// so any trailer section has already arrived and `trailers` is final).
    /// Blocks only when nothing has arrived yet, so a slow producer is
    /// observed chunk by chunk rather than at the end.
    ///
    /// ## Why the WINDOW_UPDATE is owed here, on consumption
    ///
    /// The receive window is the *only* backpressure this client has. An
    /// octet that has arrived but has not been read is still sitting in our
    /// memory, so re-advertising its credit the moment it lands (which is
    /// what a whole-body buffering client can get away with) would claim
    /// capacity we are still using: the peer would keep sending as fast as
    /// it likes and our buffer, not the window, would become the only
    /// limit — an unbounded one. Replenishing as the caller *consumes*
    /// makes "credit outstanding" mean "buffer space actually free", which
    /// is the property §5.2 exists to give.
    ///
    /// The price is that a caller who stops reading eventually stalls the
    /// shared connection window and with it the other streams (§6.9
    /// head-of-line blocking). That is not a bug to be engineered away by
    /// granting the connection window early — early grants would only move
    /// the unbounded growth from one window to the other. It is the
    /// peer-visible consequence of not reading, which is what backpressure
    /// is.
    ///
    /// Two corollaries this implementation honours: octets we *discard*
    /// (data for a reset or already-released stream) are credited back
    /// immediately, because we are not holding those (§6.9.1 — a receiver
    /// must account for data it discards, or the connection window leaks);
    /// and the stream-level grant is skipped once the stream has ended,
    /// where more credit would be pointless.
    ///
    /// `readBody` hands the bytes to the caller and drops them from the
    /// session, so it and `awaitResponse` are alternatives on one stream,
    /// not a pair: an `awaitResponse` after a partial `readBody` returns
    /// only what was left.
    pub fn readBody(s: *Session, sid: u31, buf: []u8) Error!usize {
        // 0 is reserved for "the body is complete", so an empty sink is a
        // caller bug rather than a very short read (same convention as
        // `h2.Connection.sendWindowUpdate`'s non-zero increment).
        std.debug.assert(buf.len != 0);
        // A response is HEADERS-then-DATA (§8.1), so body octets are never
        // handed over before the head they belong to. That is free against a
        // conforming peer and load-bearing against one that is not: this
        // layer accepts a DATA frame that arrives before any HEADERS, and
        // without this a streaming caller would be processing a payload
        // whose status it has never seen. (The buffered surface was always
        // immune — it demands the head at collection time.) Nothing is lost:
        // the octets stay buffered until the head arrives, or the read fails
        // with the transport when it never does.
        try s.waitHead(sid);
        const head_seen = s.streams.getPtr(sid) orelse return error.UnknownStream;
        if (head_seen.headers == null) return error.MalformedResponse;
        if (!try s.waitBody(sid)) return 0;
        const p = s.streams.getPtr(sid).?;
        const src = p.unread();
        const n = @min(buf.len, src.len);
        @memcpy(buf[0..n], src[0..n]);
        p.read_pos += n;
        // Fully drained: reclaim the buffer instead of letting a long
        // download accumulate behind the cursor.
        if (p.read_pos == p.body.items.len) {
            p.body.clearRetainingCapacity();
            p.read_pos = 0;
        }
        s.grantConsumed(sid, n);
        return n;
    }

    /// The response **trailer section** (§8.1) once the stream has ended,
    /// else null — borrowed from the session like `Head.headers`. Kept
    /// distinct from `readBody` returning 0: "the body is done" and "there
    /// were trailers" are two different observations, and only the first
    /// tells you the stream is over.
    pub fn trailers(s: *const Session, sid: u31) ?hpack.HeaderList {
        const p = s.streams.getPtr(sid) orelse return null;
        return p.trailers;
    }

    /// Whether END_STREAM has been received on `sid` (false for unknown ids).
    pub fn ended(s: *const Session, sid: u31) bool {
        const p = s.streams.getPtr(sid) orelse return false;
        return p.end;
    }

    /// Abort `sid` with RST_STREAM (§6.4) and release its state — for a
    /// download the caller no longer wants, or an upload it is giving up
    /// on. Other streams are untouched. Best effort: a dead session just
    /// drops the state.
    pub fn cancel(s: *Session, sid: u31, code: h2.ErrorCode) void {
        if (s.streams.getPtr(sid) == null) return;
        if (s.broken == null) s.conn.sendRstStream(&s.wire, sid, code) catch {};
        s.dropStream(sid); // also returns the unread octets' §6.9 credit
    }

    /// Release a finished stream's state. Idempotent; unknown ids are a
    /// no-op. `awaitResponse` does this for you — a streaming caller must
    /// do it once `readBody` has returned 0 and the trailers were read.
    pub fn release(s: *Session, sid: u31) void {
        s.dropStream(sid);
    }

    /// Block (pumping the connection — which advances *all* streams) until
    /// the response for `stream_id` is complete, then hand it over. Each
    /// stream id can be collected once; order is the caller's choice.
    ///
    /// The buffered surface, written on the incremental one: await the head,
    /// consume the body as it arrives (so the §6.9 replenishment is the very
    /// same consumption-driven path `readBody` uses — a whole-body caller
    /// simply consumes everything), then take ownership of the accumulated
    /// bytes and the trailers.
    pub fn awaitResponse(s: *Session, stream_id: u31) Error!Response {
        const head = try s.awaitHead(stream_id);
        const status = head.status;
        // Consume in place: the per-stream buffer *is* the accumulator, so
        // this costs no copy — only the read cursor advances, which is what
        // grants the window credit back.
        while (try s.waitBody(stream_id)) {
            const p = s.streams.getPtr(stream_id).?;
            const n = p.unread().len;
            p.read_pos += n;
            s.grantConsumed(stream_id, n);
        }
        var pending = s.streams.fetchOrderedRemove(stream_id).?.value;
        errdefer pending.deinit(s.gpa);
        const headers = pending.headers.?;
        const body = try pending.body.toOwnedSlice(s.gpa);
        return .{
            .status = status,
            .headers = headers,
            .body = body,
            .trailers = pending.trailers,
        };
    }

    // ── internals ───────────────────────────────────────────────────────────

    /// Block until `sid` has a response head, or fails. Shared by
    /// `awaitHead` and `awaitResponse`.
    fn waitHead(s: *Session, sid: u31) Error!void {
        while (true) {
            const p = s.streams.getPtr(sid) orelse return error.UnknownStream;
            if (p.rst) |code| {
                s.last_reset_code = code;
                s.dropStream(sid);
                return error.StreamReset;
            }
            if (p.refused) {
                s.dropStream(sid);
                return error.StreamRefused;
            }
            // `end` without headers is a headerless response: let the caller
            // surface it as MalformedResponse rather than block forever.
            if (p.headers != null or p.end) return;
            if (s.broken) |e| return e;
            try s.pump();
        }
    }

    /// Block until `sid` has unread body octets (→ true) or the response has
    /// ended (→ false). The single place where "more body" and "stream over"
    /// are decided, so both surfaces agree.
    fn waitBody(s: *Session, sid: u31) Error!bool {
        while (true) {
            const p = s.streams.getPtr(sid) orelse return error.UnknownStream;
            if (p.rst) |code| {
                s.last_reset_code = code;
                s.dropStream(sid);
                return error.StreamReset;
            }
            if (p.refused) {
                s.dropStream(sid);
                return error.StreamRefused;
            }
            if (p.read_pos < p.body.items.len) return true;
            // Only END_STREAM ends the body — a lull in the DATA frames does
            // not, and neither does a trailer section that has not landed
            // yet. Reporting "done" any earlier would let a caller act on a
            // truncated body and miss the trailers entirely.
            if (p.end) return false;
            if (s.broken) |e| return e;
            try s.pump();
        }
    }

    /// Return `n` octets of receive-window credit for `sid` after the caller
    /// has taken them (§6.9). See `readBody` for why this is on consumption.
    fn grantConsumed(s: *Session, sid: u31, n: usize) void {
        if (n == 0) return;
        const stream_open = if (s.streams.getPtr(sid)) |p| !p.end else false;
        s.grant(0, n);
        // A stream that already ended will never be sent more DATA; credit
        // on it would be dead weight (and the peer may have closed it).
        if (stream_open) s.grant(sid, n);
        s.flushWire() catch {};
    }

    /// Stage WINDOW_UPDATE(s) worth `n` octets for `id` (0 = connection).
    /// Split so that a single consumption larger than 2^31-1 is impossible
    /// to mis-encode.
    fn grant(s: *Session, id: u31, n: usize) void {
        var left = n;
        while (left != 0) {
            const inc: u31 = @intCast(@min(left, @as(usize, h2.max_window_size)));
            s.conn.sendWindowUpdate(&s.wire, id, inc) catch return;
            left -= inc;
        }
    }

    /// Block for at least one byte, feed everything buffered to the h2
    /// state machine, fold events into the demux table and flush replies
    /// (SETTINGS/PING ACKs, WINDOW_UPDATEs). Stream-scoped violations
    /// answer RST_STREAM and only fail that stream (§5.4.2);
    /// connection-scoped ones answer GOAWAY and latch `broken` (§5.4.1).
    fn pump(s: *Session) Error!void {
        if (s.broken) |e| return e;
        _ = s.in.peekGreedy(1) catch return s.fail(error.ConnectionClosed);
        const bytes = s.in.buffered();
        var chunk: []const u8 = bytes;
        s.in.toss(bytes.len);
        while (true) {
            const res = s.conn.recv(chunk, &s.wire, &s.events);
            chunk = ""; // continuation rounds only drain the internal buffer
            s.processEvents() catch return s.fail(error.OutOfMemory);
            s.flushWire() catch return s.fail(error.WriteFailed);
            if (res) |_| {
                return;
            } else |err| {
                if (err == error.OutOfMemory) return s.fail(error.OutOfMemory);
                if (s.conn.recoverStreamError()) |v| {
                    h2.encodeRstStream(s.gpa, &s.wire, v.stream_id, v.code) catch
                        return s.fail(error.OutOfMemory);
                    if (s.streams.getPtr(v.stream_id)) |p| {
                        if (!p.end) p.rst = v.code;
                    }
                    s.flushWire() catch return s.fail(error.WriteFailed);
                    continue; // drain frames buffered behind the bad one
                }
                if (s.conn.violation) |v| {
                    s.conn.sendGoaway(&s.wire, v.code, "") catch {};
                    s.flushWire() catch {};
                }
                return s.fail(error.ProtocolError);
            }
        }
    }

    fn processEvents(s: *Session) Allocator.Error!void {
        defer s.events.clearRetainingCapacity();
        var i: usize = 0;
        errdefer for (s.events.items[i..]) |*ev| ev.deinit(s.gpa);
        while (i < s.events.items.len) : (i += 1) {
            switch (s.events.items[i]) {
                .headers => |*hd| {
                    const p = s.streams.getPtr(hd.stream_id) orelse {
                        hd.headers.deinit(s.gpa); // collected/dropped stream
                        continue;
                    };
                    if (p.headers == null) {
                        const st = statusOf(hd.headers) orelse 0;
                        if (st >= 100 and st < 200 and !hd.end_stream) {
                            hd.headers.deinit(s.gpa); // interim 1xx (§8.1): skip
                        } else {
                            p.headers = hd.headers; // ownership moves
                        }
                    } else if (p.trailers == null and !containsPseudoHeader(hd.headers)) {
                        // The trailer section (§8.1). A trailer block that
                        // carries pseudo-header fields is malformed by the
                        // same section, and a `:status` arriving after the
                        // real one is a response-override primitive — such
                        // a block is dropped rather than surfaced.
                        p.trailers = hd.headers; // ownership moves
                    } else {
                        hd.headers.deinit(s.gpa); // malformed or a third block
                    }
                    if (hd.end_stream) p.end = true;
                },
                .data => |d| {
                    // NO window replenishment here: arrival is not
                    // consumption. These octets are now in our buffer, and
                    // the credit for them is returned when the caller takes
                    // them (`grantConsumed`, called from `readBody` /
                    // `awaitResponse`) — see `readBody`'s doc comment.
                    const held = held: {
                        const p = s.streams.getPtr(d.stream_id) orelse break :held false;
                        if (p.rst != null) break :held false; // stream already dead
                        try p.body.appendSlice(s.gpa, d.data);
                        if (d.end_stream) p.end = true;
                        break :held true;
                    };
                    // …with one exception: octets we do NOT hold (unknown,
                    // collected or reset stream) are discarded right here,
                    // so their connection-level credit is free immediately.
                    // §6.9.1 — a receiver must account for data it discards
                    // or the connection window leaks shut.
                    if (!held) s.grant(0, d.data.len);
                },
                .stream_reset => |r| {
                    if (s.streams.getPtr(r.stream_id)) |p| {
                        if (!p.end) p.rst = r.code;
                    }
                },
                .goaway => |g| {
                    s.goaway = .{ .last_stream_id = g.last_stream_id, .code = g.code };
                    // §6.8: streams above last_stream_id were not processed
                    // — fail them as retryable; the rest keep going.
                    for (s.streams.keys()) |id| {
                        if (id > g.last_stream_id) {
                            const p = s.streams.getPtr(id).?;
                            if (!p.end) p.refused = true;
                        }
                    }
                },
                .push_promise => |*pp| {
                    // We do not surface pushes; refuse the promised stream
                    // (only reachable when Options enabled push, §6.6).
                    pp.headers.deinit(s.gpa);
                    s.conn.sendRstStream(&s.wire, pp.promised_id, .refused_stream) catch {};
                },
                // SETTINGS/PING are acknowledged by the layer; WINDOW_UPDATE
                // already raised the send windows; PRIORITY is advisory.
                else => {},
            }
        }
    }

    /// Latch a connection-scoped failure; every later call repeats it.
    fn fail(s: *Session, e: Error) Error {
        if (s.broken == null) s.broken = e;
        return e;
    }

    fn flushWire(s: *Session) Writer.Error!void {
        if (s.wire.items.len == 0) return;
        try s.out.writeAll(s.wire.items);
        try s.out.flush();
        s.wire.clearRetainingCapacity();
    }

    fn dropStream(s: *Session, id: u31) void {
        if (s.streams.fetchOrderedRemove(id)) |kv| {
            var p = kv.value;
            // Octets received but never consumed are being thrown away now;
            // their connection-window credit is owed back or the shared
            // window shrinks by that much for the rest of the connection
            // (§6.9.1). Stream-level credit is moot — the stream is gone.
            s.grant(0, p.unread().len);
            s.flushWire() catch {};
            p.deinit(s.gpa);
        }
    }
};

/// The `:status` pseudo-header value (§8.3.2), or null when absent/invalid.
fn statusOf(list: hpack.HeaderList) ?u16 {
    for (list.fields) |f| {
        if (std.mem.eql(u8, f.name, ":status"))
            return std.fmt.parseInt(u16, f.value, 10) catch null;
    }
    return null;
}

/// Whether a decoded field block contains any pseudo-header field. RFC 9113
/// §8.1 forbids them in a trailer section — a `:status` (or `:path`) turning
/// up after the response head is exactly the kind of late override an
/// intermediary might act on, so such a block is refused wholesale rather
/// than filtered field by field.
fn containsPseudoHeader(list: hpack.HeaderList) bool {
    for (list.fields) |f| {
        if (f.name.len != 0 and f.name[0] == ':') return true;
    }
    return false;
}

/// Connection-specific headers that must not cross into h2 (RFC 9113 §8.2.2).
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
// Offline: the session runs over fixed buffers. The happy paths dogfood the
// real h2c server engine (`h2_server.serve`) as the peer; the negative
// paths fabricate server bytes with an `h2.Connection` in server role (or
// raw frames) so RST_STREAM/GOAWAY/garbage arrive exactly as scripted.
// Socket loopback integration (via `Client.connectH2c`) lives in
// `Client.zig`.

const testing = std.testing;
const h2_server = @import("h2_server.zig");
const Server = @import("Server.zig");

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
    } else if (std.mem.eql(u8, req.path, "/hdr")) {
        try rw.writeAll(req.header("x-custom") orelse "-");
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

/// Run the h2c server engine over the client bytes staged in `out`, then
/// point the session's reader at the server's reply.
fn serveStaged(in: *Reader, out: *const Writer, srv_out: []u8, opts: h2_server.Options) void {
    var srv_in: Reader = .fixed(out.buffered());
    var srv_w: Writer = .fixed(srv_out);
    h2_server.serve(testing.allocator, opts, &srv_in, &srv_w);
    in.* = .fixed(srv_w.buffered());
}

test "h2 client: GET and POST round-trip against the h2c server engine (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid_get = try s.request(.get, "/hello?x=1", .{ .authority = "t" });
    const sid_post = try s.request(.post, "/echo", .{
        .authority = "t",
        .body = "ping pong h2",
    });
    // Header names are lowercased; connection-specific ones stripped —
    // the server 400s any request where they leak through (§8.2).
    const sid_hdr = try s.request(.get, "/hdr", .{
        .authority = "t",
        .headers = &.{
            .{ .name = "X-Custom", .value = "Val-1" },
            .{ .name = "Connection", .value = "keep-alive" },
        },
    });
    try testing.expectEqual(@as(u31, 1), sid_get); // §5.1.1: odd, monotonic
    try testing.expectEqual(@as(u31, 3), sid_post);
    try testing.expectEqual(@as(u31, 5), sid_hdr);

    var srv_out: [16384]u8 = undefined;
    serveStaged(&in, &out, &srv_out, .{ .handler = testHandler, .server_name = "h2test" });

    // Collect out of order — frames were already demuxed per stream.
    var post = try s.awaitResponse(sid_post);
    defer post.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), post.status);
    try testing.expectEqualStrings("ping pong h2", post.body);

    var get = try s.awaitResponse(sid_get);
    defer get.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), get.status);
    try testing.expectEqualStrings("hello", get.body);
    try testing.expectEqualStrings("text/plain", get.header("Content-Type").?);
    try testing.expectEqualStrings("x=1", get.header("x-query").?);
    try testing.expectEqualStrings("h2test", get.header("server").?);

    var hdr = try s.awaitResponse(sid_hdr);
    defer hdr.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), hdr.status);
    try testing.expectEqualStrings("Val-1", hdr.body);

    // Collected streams are gone; unknown ids answer typed errors.
    try testing.expectError(error.UnknownStream, s.awaitResponse(sid_get));
    try testing.expectError(error.UnknownStream, s.awaitResponse(99));
}

/// Fabricated peer: an `h2.Connection` in server role whose handshake with
/// the session's staged bytes is already done, ready to script responses.
const ScriptedServer = struct {
    conn: h2.Connection,
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,

    fn init(client_bytes: []const u8) !ScriptedServer {
        const gpa = testing.allocator;
        var srv: ScriptedServer = .{ .conn = .init(gpa, .server, .{}) };
        errdefer srv.deinit();
        try srv.conn.sendPreface(&srv.wire);
        try srv.conn.recv(client_bytes, &srv.wire, &srv.events);
        return srv;
    }

    fn deinit(srv: *ScriptedServer) void {
        const gpa = testing.allocator;
        for (srv.events.items) |*ev| ev.deinit(gpa);
        srv.events.deinit(gpa);
        srv.wire.deinit(gpa);
        srv.conn.deinit();
    }
};

const ok_fields = [_]hpack.Field{.{ .name = ":status", .value = "200" }};

test "h2 client: multiplexing — interleaved DATA frames demux by stream id (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid_a = try s.request(.get, "/a", .{ .authority = "t" });
    const sid_b = try s.request(.get, "/b", .{ .authority = "t" });

    // The scripted server interleaves the two response streams frame by
    // frame — HEADERS b/a, DATA b/a/b/a — so only per-stream-id demux can
    // reassemble them correctly.
    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendHeaders(&srv.wire, sid_b, &ok_fields, false);
    try srv.conn.sendHeaders(&srv.wire, sid_a, &ok_fields, false);
    try srv.conn.sendData(&srv.wire, sid_b, "BB-1 ", false);
    try srv.conn.sendData(&srv.wire, sid_a, "AA-1 ", false);
    try srv.conn.sendData(&srv.wire, sid_b, "BB-2", true);
    try srv.conn.sendData(&srv.wire, sid_a, "AA-2", true);
    in = .fixed(srv.wire.items);

    var res_a = try s.awaitResponse(sid_a);
    defer res_a.deinit(gpa);
    var res_b = try s.awaitResponse(sid_b);
    defer res_b.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), res_a.status);
    try testing.expectEqualStrings("AA-1 AA-2", res_a.body);
    try testing.expectEqual(@as(u16, 200), res_b.status);
    try testing.expectEqualStrings("BB-1 BB-2", res_b.body);
}

test "h2 client: response trailers are surfaced separately from the headers (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/t", .{ .authority = "t" });
    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendHeaders(&srv.wire, sid, &ok_fields, false);
    try srv.conn.sendData(&srv.wire, sid, "hello", false); // no END_STREAM: trailers follow
    try srv.conn.sendHeaders(&srv.wire, sid, &.{
        .{ .name = "x-checksum", .value = "deadbeef" },
        .{ .name = "x-rows", .value = "3" },
    }, true);
    in = .fixed(srv.wire.items);

    var res = try s.awaitResponse(sid);
    defer res.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("hello", res.body);
    try testing.expectEqualStrings("deadbeef", res.trailer("X-Checksum").?); // case-insensitive
    try testing.expectEqualStrings("3", res.trailer("x-rows").?);
    // Two namespaces, deliberately: a field that only arrived in the trailer
    // section must never answer a `header` lookup, or a late value could
    // masquerade as one the caller already validated.
    try testing.expectEqual(@as(?[]const u8, null), res.header("x-checksum"));
    try testing.expectEqual(@as(?[]const u8, null), res.trailer("nope"));
}

test "h2 client: a response without trailers reports none (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/t", .{ .authority = "t" });
    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendHeaders(&srv.wire, sid, &ok_fields, false);
    try srv.conn.sendData(&srv.wire, sid, "hello", true);
    in = .fixed(srv.wire.items);

    var res = try s.awaitResponse(sid);
    defer res.deinit(gpa);
    try testing.expect(res.trailers == null);
    try testing.expectEqual(@as(?[]const u8, null), res.trailer("x-checksum"));
}

test "h2 client: a trailer block carrying pseudo-headers is dropped (§8.1)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/t", .{ .authority = "t" });
    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendHeaders(&srv.wire, sid, &ok_fields, false);
    try srv.conn.sendData(&srv.wire, sid, "hello", false);
    // A second `:status` after the real one — the override this guard is for.
    try srv.conn.sendHeaders(&srv.wire, sid, &.{
        .{ .name = ":status", .value = "500" },
        .{ .name = "x-checksum", .value = "deadbeef" },
    }, true);
    in = .fixed(srv.wire.items);

    var res = try s.awaitResponse(sid);
    defer res.deinit(gpa);
    // The real status stands and the whole malformed block is gone.
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expect(res.trailers == null);
    try testing.expectEqualStrings("hello", res.body);
}

test "h2 client: server RST_STREAM fails that request; other streams continue (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid_dead = try s.request(.get, "/dead", .{ .authority = "t" });
    const sid_live = try s.request(.get, "/live", .{ .authority = "t" });

    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendRstStream(&srv.wire, sid_dead, .cancel);
    try srv.conn.sendHeaders(&srv.wire, sid_live, &ok_fields, false);
    try srv.conn.sendData(&srv.wire, sid_live, "still here", true);
    in = .fixed(srv.wire.items);

    try testing.expectError(error.StreamReset, s.awaitResponse(sid_dead));
    try testing.expectEqual(@as(?h2.ErrorCode, .cancel), s.last_reset_code);
    // The reset touched exactly one stream — the session and its other
    // streams behave per §5.4.2.
    var live = try s.awaitResponse(sid_live);
    defer live.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), live.status);
    try testing.expectEqualStrings("still here", live.body);
    try testing.expectEqual(@as(?Error, null), s.broken);
}

test "h2 client: GOAWAY — in-flight ≤ last finish, above are refused, new blocked (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid_done = try s.request(.get, "/done", .{ .authority = "t" });
    const sid_lost = try s.request(.get, "/lost", .{ .authority = "t" });

    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendHeaders(&srv.wire, sid_done, &ok_fields, false);
    try srv.conn.sendData(&srv.wire, sid_done, "made it", true);
    // GOAWAY(last_stream_id = sid_done): sid_lost was never processed.
    try h2.encodeGoaway(gpa, &srv.wire, sid_done, .no_error, "");
    in = .fixed(srv.wire.items);

    var done = try s.awaitResponse(sid_done);
    defer done.deinit(gpa);
    try testing.expectEqualStrings("made it", done.body);

    try testing.expectError(error.StreamRefused, s.awaitResponse(sid_lost));
    try testing.expectEqual(@as(u31, sid_done), s.goaway.?.last_stream_id);
    try testing.expectEqual(h2.ErrorCode.no_error, s.goaway.?.code);
    // §6.8: no new streams after GOAWAY.
    try testing.expectError(error.GoawayReceived, s.request(.get, "/new", .{}));
}

test "h2 client: malformed server bytes → typed error and a latched session, no panic (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/x", .{ .authority = "t" });
    in = .fixed("this is definitely not an HTTP/2 frame stream");

    try testing.expectError(error.ProtocolError, s.awaitResponse(sid));
    // The violation latched: everything after repeats the typed error.
    try testing.expectEqual(@as(?Error, error.ProtocolError), s.broken);
    try testing.expectError(error.ProtocolError, s.request(.get, "/y", .{}));
    try testing.expectError(error.ProtocolError, s.awaitResponse(sid));
}

test "h2 client: response spanning many DATA frames replenishes flow control (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/big", .{ .authority = "t" });

    // 48 KiB in 1 KiB DATA frames — most of the 64 KiB initial window; the
    // client must grant it back via WINDOW_UPDATE or a real server would
    // stall on the next response (asserted below via window reconciliation).
    const chunk = "0123456789abcdef" ** 64; // 1024 B
    var srv: ScriptedServer = try .init(out.buffered());
    defer srv.deinit();
    try srv.conn.sendHeaders(&srv.wire, sid, &ok_fields, false);
    for (0..48) |i| try srv.conn.sendData(&srv.wire, sid, chunk, i == 47);
    in = .fixed(srv.wire.items);

    var res = try s.awaitResponse(sid);
    defer res.deinit(gpa);
    try testing.expectEqual(@as(usize, 48 * 1024), res.body.len);
    try testing.expectEqualStrings(chunk, res.body[47 * 1024 ..]);
    // Every received octet was granted back: the connection receive window
    // is back at its initial value (§6.9 reconciliation).
    try testing.expectEqual(
        @as(i64, h2.default_initial_window_size),
        s.conn.conn_recv_window,
    );
    // …and the staged WINDOW_UPDATEs landed in the transport.
    try testing.expect(out.buffered().len > 0);
}

// ── the incremental surface ─────────────────────────────────────────────────
//
// A note on anchoring, because it decides how these tests are written. This
// module's external anchor (`curl_interop.zig`) drives our *server* with a
// real curl + nghttp2 — and curl, like every h2 tool present on this host,
// is a client only. Anchoring the h2 *client* the same way would need a live
// third-party h2 *server* (`nghttpd --no-tls` from the uninstalled
// `nghttp2-server` package); there is none, so none of the cases below can
// honestly claim an external oracle.
//
// What they do instead is the next-strongest thing: assert on the frames
// that actually LEFT the client, and let an INDEPENDENT `h2.Connection` in
// server role be the judge. Its §5.2 send-window accounting is driven purely
// by the WINDOW_UPDATE frames we really emitted, so "the peer may now send
// exactly N more octets" is a statement about our wire output, not about our
// intentions — which is precisely the class of mutation that survives a
// loopback where both sides share the same misunderstanding.

/// Steps a `ScriptedServer` and a `Session` against each other in both
/// directions, so a test can interleave "the peer sends", "the caller
/// consumes" and "what did the client actually put on the wire".
const Peer = struct {
    srv: ScriptedServer,
    /// How much of the client's output the server has already read.
    seen: usize,
    /// Stable staging buffer behind the client's reader: `srv.wire` moves as
    /// it grows and a `Reader.fixed` over it would dangle.
    stage: std.ArrayList(u8) = .empty,
    /// Every request-body octet the server has received.
    got: std.ArrayList(u8) = .empty,

    fn init(out: *const Writer) !Peer {
        return .{ .srv = try .init(out.buffered()), .seen = out.buffered().len };
    }

    fn deinit(p: *Peer) void {
        p.stage.deinit(testing.allocator);
        p.got.deinit(testing.allocator);
        p.srv.deinit();
    }

    /// Hand everything the server has staged to the client's reader,
    /// preserving anything the client has not read yet.
    fn toClient(p: *Peer, in: *Reader) !void {
        const gpa = testing.allocator;
        var fresh: std.ArrayList(u8) = .empty;
        errdefer fresh.deinit(gpa);
        try fresh.appendSlice(gpa, in.buffered()); // copy before the free below
        try fresh.appendSlice(gpa, p.srv.wire.items);
        p.srv.wire.clearRetainingCapacity();
        p.stage.deinit(gpa);
        p.stage = fresh;
        in.* = .fixed(p.stage.items);
    }

    /// Feed the client's new output to the server's own state machine —
    /// this is what makes its flow-control windows an independent judge.
    fn fromClient(p: *Peer, out: *const Writer) !void {
        const gpa = testing.allocator;
        const all = out.buffered();
        const chunk = all[p.seen..];
        p.seen = all.len;
        const first = p.srv.events.items.len;
        try p.srv.conn.recv(chunk, &p.srv.wire, &p.srv.events);
        // `data.data` borrows the receive buffer only until the next recv.
        for (p.srv.events.items[first..]) |ev| {
            if (ev == .data) try p.got.appendSlice(gpa, ev.data.data);
        }
    }

    /// Whether the server saw an RST_STREAM for `sid` with `code`.
    fn sawReset(p: *const Peer, sid: u31, code: h2.ErrorCode) bool {
        for (p.srv.events.items) |ev| {
            if (ev == .stream_reset and ev.stream_reset.stream_id == sid and
                ev.stream_reset.code == code) return true;
        }
        return false;
    }
};

fn trailerValue(list: hpack.HeaderList, name: []const u8) ?[]const u8 {
    for (list.fields) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
    }
    return null;
}

test "h2 client: both directions live on one stream — send and receive interleaved (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    // HEADERS without END_STREAM: the request body does not exist yet.
    const sid = try s.openStream(.post, "/bidi", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();

    try s.sendData(sid, "req-1;", false);
    try peer.fromClient(&out);
    try testing.expectEqualStrings("req-1;", peer.got.items);

    // The peer answers while the request body is still open — the case a
    // request/response API cannot express at all.
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid, "res-1;", false);
    try peer.toClient(&in);

    const head = try s.awaitHead(sid);
    try testing.expectEqual(@as(u16, 200), head.status);
    var rbuf: [64]u8 = undefined;
    try testing.expectEqualStrings("res-1;", rbuf[0..try s.readBody(sid, &rbuf)]);
    try testing.expect(!s.ended(sid));

    // …and the caller keeps sending, having already acted on the head.
    try s.sendData(sid, "req-2", true);
    try testing.expect(s.sendEnded(sid));
    try peer.fromClient(&out);
    try testing.expectEqualStrings("req-1;req-2", peer.got.items);

    // The peer's half closes last, with a trailer section.
    try peer.srv.conn.sendData(&peer.srv.wire, sid, "res-2", false);
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &.{
        .{ .name = "x-rows", .value = "2" },
    }, true);
    try peer.toClient(&in);

    try testing.expectEqualStrings("res-2", rbuf[0..try s.readBody(sid, &rbuf)]);
    // 0 = the body is complete, and only then are the trailers final.
    try testing.expectEqual(@as(usize, 0), try s.readBody(sid, &rbuf));
    try testing.expect(s.ended(sid));
    try testing.expectEqualStrings("2", trailerValue(s.trailers(sid).?, "X-Rows").?);
    // The trailer field is not a header field (two namespaces, as in the
    // buffered surface).
    try testing.expectEqual(@as(?[]const u8, null), head.header("x-rows"));

    s.release(sid);
    try testing.expectError(error.UnknownStream, s.readBody(sid, &rbuf));
    try testing.expectEqual(@as(?hpack.HeaderList, null), s.trailers(sid));
}

test "h2 client: the response head is delivered long before any DATA (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/events", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();

    // Head only — the shape of an event stream or a slow generator.
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/event-stream" },
    }, false);
    try peer.toClient(&in);

    const head = try s.awaitHead(sid);
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqualStrings("text/event-stream", head.header("Content-Type").?);
    try testing.expect(!s.ended(sid));

    // The body then arrives in instalments, each observable on its own.
    var rbuf: [64]u8 = undefined;
    try peer.srv.conn.sendData(&peer.srv.wire, sid, "tick-1", false);
    try peer.toClient(&in);
    try testing.expectEqualStrings("tick-1", rbuf[0..try s.readBody(sid, &rbuf)]);

    try peer.srv.conn.sendData(&peer.srv.wire, sid, "tick-2", true);
    try peer.toClient(&in);
    try testing.expectEqualStrings("tick-2", rbuf[0..try s.readBody(sid, &rbuf)]);
    try testing.expectEqual(@as(usize, 0), try s.readBody(sid, &rbuf));
    try testing.expect(s.ended(sid));
    try testing.expectEqual(@as(?hpack.HeaderList, null), s.trailers(sid));
    s.release(sid);
}

test "h2 client: a lull in the DATA frames is not the end of the body (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/lull", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid, "hello", false); // no END_STREAM
    try peer.toClient(&in);

    var rbuf: [64]u8 = undefined;
    _ = try s.awaitHead(sid);
    try testing.expectEqualStrings("hello", rbuf[0..try s.readBody(sid, &rbuf)]);
    try testing.expect(!s.ended(sid));
    try testing.expectEqual(@as(?hpack.HeaderList, null), s.trailers(sid));

    // Nothing more is staged. "0" would mean the body is complete AND any
    // trailer section is final — neither is true here, so `readBody` must
    // block for more instead, and blocking on a drained offline transport
    // surfaces as the transport EOF. A reader that reported end-of-body the
    // moment its buffer ran dry would return 0 here and lose every trailer
    // the peer had not sent yet.
    try testing.expectError(error.ConnectionClosed, s.readBody(sid, &rbuf));
}

test "h2 client: WINDOW_UPDATE is owed on consumption, not on arrival (§5.2/§6.9, offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/big", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();

    // The peer fills its whole 64 KiB send window and stops, as it must.
    const w: usize = h2.default_initial_window_size;
    const filler = try gpa.alloc(u8, w);
    defer gpa.free(filler);
    @memset(filler, 'x');
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid, filler, false);
    try peer.toClient(&in);

    // The head is available; not one body octet has been consumed.
    try testing.expectEqual(@as(u16, 200), (try s.awaitHead(sid)).status);

    // So not one octet of credit may have been returned. The judge is the
    // peer's own accounting, fed with the bytes we really emitted: both of
    // its send windows must still be shut. Granting on ARRIVAL — which a
    // whole-body buffering client can get away with — fails right here.
    try peer.fromClient(&out);
    try testing.expectEqual(@as(i64, 0), peer.srv.conn.conn_send_window);
    try testing.expectEqual(@as(i64, 0), peer.srv.conn.stream(sid).?.send_window);
    try testing.expectError(
        error.WindowExhausted,
        peer.srv.conn.sendData(&peer.srv.wire, sid, "x", false),
    );

    // Consume exactly 16 KiB…
    var rbuf: [16384]u8 = undefined;
    try testing.expectEqual(rbuf.len, try s.readBody(sid, &rbuf));
    try peer.fromClient(&out);

    // …and exactly 16 KiB of credit appears, on both windows (§6.9: the
    // connection window and the stream window are replenished separately).
    try testing.expectEqual(@as(i64, rbuf.len), peer.srv.conn.conn_send_window);
    try testing.expectEqual(@as(i64, rbuf.len), peer.srv.conn.stream(sid).?.send_window);
    // Not one octet more than we freed: over-granting would advertise
    // capacity we are still holding.
    try testing.expectError(
        error.WindowExhausted,
        peer.srv.conn.sendData(&peer.srv.wire, sid, filler[0 .. rbuf.len + 1], false),
    );
    try peer.srv.conn.sendData(&peer.srv.wire, sid, filler[0..rbuf.len], false);

    // The rest of the transfer drains normally through the same path.
    try peer.toClient(&in);
    var total: usize = rbuf.len;
    while (true) {
        const n = try s.readBody(sid, &rbuf);
        if (n == 0) break;
        total += n;
        if (total == w + rbuf.len) {
            try peer.srv.conn.sendData(&peer.srv.wire, sid, "", true);
            try peer.toClient(&in);
        }
    }
    try testing.expectEqual(w + rbuf.len, total);
    s.release(sid);
}

test "h2 client: a peer that shuts the send window mid-body, then reopens it (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    const out_buf = try gpa.alloc(u8, 160 * 1024);
    defer gpa.free(out_buf);
    var out: Writer = .fixed(out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const w: usize = h2.default_initial_window_size; // what the peer allows
    const body = try gpa.alloc(u8, w + 4_465);
    defer gpa.free(body);
    for (body, 0..) |*b, i| b.* = @intCast('a' + i % 26);

    const sid = try s.openStream(.post, "/upload", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();

    // The one-shot form takes exactly what fits and SAYS SO — the count is
    // the whole contract, and Zig will not let a caller drop it by accident.
    try testing.expectEqual(w, try s.sendDataPartial(sid, body));
    // Window shut: a second attempt takes nothing rather than pretending.
    try testing.expectEqual(@as(usize, 0), try s.sendDataPartial(sid, body[w..]));
    try testing.expect(!s.sendEnded(sid));

    // Exactly the accepted prefix reached the peer — no more, no less.
    try peer.fromClient(&out);
    try testing.expectEqualSlices(u8, body[0..w], peer.got.items);
    try testing.expectEqual(@as(i64, 0), s.conn.conn_send_window);

    // The peer reopens both windows…
    try peer.srv.conn.sendWindowUpdate(&peer.srv.wire, 0, @intCast(w));
    try peer.srv.conn.sendWindowUpdate(&peer.srv.wire, sid, @intCast(w));
    try peer.toClient(&in);

    // …and the blocking form finishes the body on its own, reading the
    // connection for the grant instead of returning short.
    try s.sendData(sid, body[w..], true);
    try testing.expect(s.sendEnded(sid));
    try peer.fromClient(&out);
    try testing.expectEqualSlices(u8, body, peer.got.items);

    // END_STREAM sent: further sends are a caller bug, not a peer event.
    try testing.expectError(error.SendClosed, s.sendData(sid, "more", false));
    try testing.expectError(error.SendClosed, s.closeSend(sid));
}

test "h2 client: the peer finishes its response while the caller is still sending (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.openStream(.post, "/early", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();
    try s.sendData(sid, "part-1;", false);
    try peer.fromClient(&out);

    // A complete response, END_STREAM and all, long before the request body
    // is done (a 4xx on the first chunk of an upload looks exactly like it).
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid, "done", true);
    try peer.toClient(&in);

    var rbuf: [64]u8 = undefined;
    try testing.expectEqual(@as(u16, 200), (try s.awaitHead(sid)).status);
    try testing.expectEqualStrings("done", rbuf[0..try s.readBody(sid, &rbuf)]);
    try testing.expectEqual(@as(usize, 0), try s.readBody(sid, &rbuf));
    try testing.expect(s.ended(sid));

    // half-closed (remote) is not half-closed (local), §5.1: our half is
    // still open and the upload continues to completion.
    try testing.expect(!s.sendEnded(sid));
    try s.sendData(sid, "part-2", true);
    try peer.fromClient(&out);
    try testing.expectEqualStrings("part-1;part-2", peer.got.items);

    s.release(sid);
    try testing.expectError(error.UnknownStream, s.sendData(sid, "x", false));
}

test "h2 client: peer RST_STREAM mid-body — buffered octets first, then the error (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/half", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();
    var chunk: [2048]u8 = undefined;
    @memset(&chunk, 'z');
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid, &chunk, false);
    try peer.toClient(&in);

    var rbuf: [1024]u8 = undefined;
    _ = try s.awaitHead(sid);
    try testing.expectEqual(rbuf.len, try s.readBody(sid, &rbuf));

    // The peer gives up mid-stream.
    try peer.srv.conn.sendRstStream(&peer.srv.wire, sid, .internal_error);
    try peer.toClient(&in);

    // What legitimately arrived before the reset is still delivered — the
    // reset surfaces once the reader would otherwise have to wait for more.
    try testing.expectEqual(rbuf.len, try s.readBody(sid, &rbuf));
    try testing.expectError(error.StreamReset, s.readBody(sid, &rbuf));
    try testing.expectEqual(@as(?h2.ErrorCode, .internal_error), s.last_reset_code);
    // The stream is gone, the session is not (§5.4.2).
    try testing.expectError(error.UnknownStream, s.readBody(sid, &rbuf));
    try testing.expectEqual(@as(?Error, null), s.broken);
}

test "h2 client: cancel resets the stream and returns the unread octets' credit (§6.9.1, offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/abandon", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();
    var chunk: [4096]u8 = undefined;
    @memset(&chunk, 'q');
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid, &chunk, false);
    try peer.toClient(&in);

    var rbuf: [1024]u8 = undefined;
    _ = try s.awaitHead(sid);
    try testing.expectEqual(rbuf.len, try s.readBody(sid, &rbuf));

    // The caller walks away with 3 KiB still buffered.
    s.cancel(sid, .cancel);
    try testing.expectError(error.UnknownStream, s.readBody(sid, &rbuf));

    try peer.fromClient(&out);
    try testing.expect(peer.sawReset(sid, .cancel));
    // §6.9.1: octets we discard must still be credited back on the
    // CONNECTION window, or every abandoned download shrinks the shared
    // window permanently and the connection eventually stalls for good. All
    // 4 KiB are accounted for — 1 KiB by consumption, 3 KiB by the drop —
    // so the peer's connection window is whole again.
    const w: i64 = h2.default_initial_window_size;
    try testing.expectEqual(w, peer.srv.conn.conn_send_window);
    // Not on the stream window — that stream is dead; only what the caller
    // actually read was ever granted there.
    try testing.expectEqual(
        w - @as(i64, chunk.len) + @as(i64, rbuf.len),
        peer.srv.conn.stream(sid).?.send_window,
    );
}

test "h2 client: DATA for a stream we no longer hold is credited immediately (offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [16384]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid_a = try s.request(.get, "/a", .{ .authority = "t" });
    const sid_b = try s.request(.get, "/b", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();

    // Collect A, then let a late DATA frame for it arrive: we hold nothing,
    // so its connection credit is free at once rather than leaking.
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid_a, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid_a, "done", true);
    try peer.toClient(&in);
    var res = try s.awaitResponse(sid_a);
    defer res.deinit(gpa);

    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid_b, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid_b, "stray", true);
    try peer.toClient(&in);
    // Drop B without ever collecting it, then pump the frames in.
    s.release(sid_b);
    const sid_c = try s.request(.get, "/c", .{ .authority = "t" });
    try peer.fromClient(&out); // the peer must see C's HEADERS first
    try peer.srv.conn.sendHeaders(&peer.srv.wire, sid_c, &ok_fields, false);
    try peer.srv.conn.sendData(&peer.srv.wire, sid_c, "ok", true);
    try peer.toClient(&in);
    var res_c = try s.awaitResponse(sid_c);
    defer res_c.deinit(gpa);
    try testing.expectEqualStrings("ok", res_c.body);

    // Every octet the peer sent is back in its connection window.
    try peer.fromClient(&out);
    try testing.expectEqual(
        @as(i64, h2.default_initial_window_size),
        peer.srv.conn.conn_send_window,
    );
}

test "h2 client: DATA arriving before any HEADERS is not handed to the reader (§8.1, offline)" {
    const gpa = testing.allocator;
    var in: Reader = .fixed("");
    var out_buf: [8192]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var s: Session = try .init(gpa, &in, &out, .{});
    defer s.deinit();

    const sid = try s.request(.get, "/ooo", .{ .authority = "t" });
    var peer: Peer = try .init(&out);
    defer peer.deinit();
    // A peer that puts DATA on the wire before the response head. This
    // layer accepts the frame (it is the stream state machine, not the
    // HTTP semantics), so the guard has to live in the reader.
    try peer.srv.conn.sendData(&peer.srv.wire, sid, "leak", false);
    try peer.toClient(&in);

    // Those four octets must NOT reach a caller that has no status to
    // interpret them with: the read waits for the head instead, which on a
    // drained offline transport surfaces as the transport EOF. Without the
    // guard this returns "leak".
    var rbuf: [64]u8 = undefined;
    try testing.expectError(error.ConnectionClosed, s.readBody(sid, &rbuf));
}
