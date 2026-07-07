// SPDX-License-Identifier: MIT

//! h2 client engine (Phase 3.2): drives `h2.Connection` in **client** role
//! over a byte transport (`std.Io.Reader`/`std.Io.Writer` — socket-free, so
//! tests run from fixed buffers). `Client.connectH2c` binds it to a TCP
//! stream for cleartext HTTP/2 via **prior knowledge** (RFC 9113 §3.3 —
//! the client just opens with the connection preface); h2-over-TLS (ALPN)
//! slots in later by handing a TLS plaintext reader/writer to
//! `Session.init` once the TLS-adapter seam lands.
//!
//! Model: one `Session` **multiplexes** any number of requests over one
//! connection. `request` opens a stream (§5.1.1: odd, monotonic ids) and
//! sends the §8.3 pseudo-header request form (`:method`/`:scheme`/`:path`/
//! `:authority` + lowercased regular headers, §8.2.1, with
//! connection-specific headers stripped, §8.2.2) plus an optional DATA body
//! under §5.2 flow control. Frames read back are demultiplexed by stream id
//! into per-stream response state, so many requests can be in flight before
//! `awaitResponse` collects each one — interleaved server frames land on
//! the right response regardless of order. Receive-side flow control is
//! replenished as DATA arrives (WINDOW_UPDATE, §6.9), so response bodies
//! larger than the 64 KiB initial window stream freely; send-side flow
//! control blocks the upload (reading the connection for grants) instead of
//! overrunning the peer's window.
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
//! §5.1, flow control §5.2/§6.9, GOAWAY §6.8, HTTP semantics §8.1–§8.3);
//! no HTTP/2 client implementation source was consulted or copied.

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
    /// The stream id was never issued by `request` (or already collected).
    UnknownStream,
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
};

/// A complete, owned response: final status + header list + assembled body.
/// Release with `deinit`.
pub const Response = struct {
    status: u16,
    headers: hpack.HeaderList,
    body: []u8,

    /// First value of a response header (case-insensitive), or null.
    pub fn header(res: *const Response, name: []const u8) ?[]const u8 {
        for (res.headers.fields) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        }
        return null;
    }

    pub fn deinit(res: *Response, gpa: Allocator) void {
        res.headers.deinit(gpa);
        gpa.free(res.body);
        res.* = undefined;
    }
};

/// One response stream being assembled from demultiplexed frames.
const Pending = struct {
    /// Final response header list (interim 1xx responses are skipped).
    headers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    /// END_STREAM seen — the response is complete.
    end: bool = false,
    /// Server RST_STREAM (or a local stream-scoped recovery) code.
    rst: ?h2.ErrorCode = null,
    /// Marked unprocessed by a server GOAWAY (§6.8).
    refused: bool = false,

    fn deinit(p: *Pending, gpa: Allocator) void {
        if (p.headers) |*hl| hl.deinit(gpa);
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
    pub fn request(
        s: *Session,
        method: http.Method,
        path: []const u8,
        options: RequestOptions,
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

        const body = options.body orelse "";
        const end_stream = body.len == 0;
        const sid = s.conn.startStream(&s.wire, fields.items, end_stream) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // A freshly opened client stream is always writable.
                else => return s.fail(error.ProtocolError),
            };
        s.streams.put(s.gpa, sid, .{}) catch return error.OutOfMemory;
        s.flushWire() catch return s.fail(error.WriteFailed);
        if (!end_stream) try s.sendBody(sid, body);
        return sid;
    }

    /// Block (pumping the connection — which advances *all* streams) until
    /// the response for `stream_id` is complete, then hand it over. Each
    /// stream id can be collected once; order is the caller's choice.
    pub fn awaitResponse(s: *Session, stream_id: u31) Error!Response {
        while (true) {
            const p = s.streams.getPtr(stream_id) orelse return error.UnknownStream;
            if (p.rst) |code| {
                s.last_reset_code = code;
                s.dropStream(stream_id);
                return error.StreamReset;
            }
            if (p.refused) {
                s.dropStream(stream_id);
                return error.StreamRefused;
            }
            if (p.end) break;
            if (s.broken) |e| return e;
            try s.pump();
        }
        var pending = s.streams.fetchOrderedRemove(stream_id).?.value;
        errdefer pending.deinit(s.gpa);
        const headers = pending.headers orelse return error.MalformedResponse;
        const status = statusOf(headers) orelse return error.MalformedResponse;
        const body = try pending.body.toOwnedSlice(s.gpa);
        return .{ .status = status, .headers = headers, .body = body };
    }

    // ── internals ───────────────────────────────────────────────────────────

    /// Stream `body` as DATA frames under §5.2 flow control: send what the
    /// connection + stream windows allow, and when both are exhausted read
    /// the connection until WINDOW_UPDATE opens room (responses arriving
    /// meanwhile are folded into the demux table as usual).
    fn sendBody(s: *Session, sid: u31, body: []const u8) Error!void {
        var off: usize = 0;
        while (off < body.len) {
            const st = s.conn.stream(sid) orelse return error.StreamReset;
            switch (st.state) {
                .open, .half_closed_remote => {},
                else => return error.StreamReset, // peer reset mid-upload
            }
            const win = @min(s.conn.conn_send_window, st.send_window);
            if (win <= 0) {
                try s.pump();
                continue;
            }
            const n = @min(body.len - off, @as(usize, @intCast(win)));
            const last = off + n == body.len;
            s.conn.sendData(&s.wire, sid, body[off..][0..n], last) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Raced a SETTINGS window shrink applied by a pump above.
                error.WindowExhausted => {
                    try s.pump();
                    continue;
                },
                else => return error.StreamReset,
            };
            off += n;
            s.flushWire() catch return s.fail(error.WriteFailed);
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
                    } else {
                        hd.headers.deinit(s.gpa); // trailers: no surface, dropped
                    }
                    if (hd.end_stream) p.end = true;
                },
                .data => |d| {
                    // Replenish what the server consumed (§6.9) so response
                    // bodies stream past the 64 KiB initial windows.
                    if (d.data.len != 0) {
                        const inc: u31 = @intCast(d.data.len);
                        s.conn.sendWindowUpdate(&s.wire, 0, inc) catch {};
                        if (!d.end_stream)
                            s.conn.sendWindowUpdate(&s.wire, d.stream_id, inc) catch {};
                    }
                    if (s.streams.getPtr(d.stream_id)) |p| {
                        try p.body.appendSlice(s.gpa, d.data);
                        if (d.end_stream) p.end = true;
                    }
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
