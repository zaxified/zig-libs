// SPDX-License-Identifier: MIT

//! Server-Sent Events (WHATWG HTML "server-sent events" / the `text/event-stream`
//! wire format) over an `http.Server.ResponseWriter`. A thin, correct encoder
//! for the push half of a streaming HTTP endpoint — the transport the MCP
//! HTTP/SSE server and any other live-push API build on.
//!
//! An `EventStream` takes over a response: it sets the streaming headers, then
//! each `send`/`data`/`comment` formats one event and **flushes it to the
//! socket** (via `ResponseWriter.flush`) so the client's `EventSource` receives
//! it immediately. The connection stays open (chunked framing) until the
//! handler returns.
//!
//! ## Usage
//!
//! ```zig
//! var es = try http.sse.EventStream.start(rw);
//! try es.send(.{ .event = "tick", .id = "1", .data = "hello" });
//! try es.comment("keep-alive");            // heartbeat, ignored by clients
//! try es.data("{\"n\":42}");               // a default-type ("message") event
//! // returning from the handler ends the stream
//! ```
//!
//! ## Wire format (WHATWG §9.2)
//!
//! Each event is a group of `field: value` lines ended by a blank line:
//!
//! ```
//! event: tick\n     (optional type; default is "message")
//! id: 1\n           (optional; the client echoes it as Last-Event-ID on reconnect)
//! retry: 3000\n     (optional reconnection time, ms)
//! data: hello\n     (payload; an embedded LF becomes another data: line)
//! \n                (blank line dispatches the event)
//! ```
//!
//! A line beginning `:` is a comment (a `comment`/heartbeat) — clients ignore
//! it, but it keeps the connection and any intermediary from timing out.

const std = @import("std");
const Server = @import("Server.zig");

const Writer = std.Io.Writer;

/// One SSE event. All fields optional; a bare `.{ .data = "…" }` is the common
/// case (a default-type "message" event).
pub const Event = struct {
    /// The `event:` type. Null ⇒ the client's default "message". Must not
    /// contain CR or LF (a single line).
    event: ?[]const u8 = null,
    /// The `id:` (becomes the client's Last-Event-ID for resumption). Must not
    /// contain CR, LF or NUL.
    id: ?[]const u8 = null,
    /// The `data:` payload. An embedded LF (`\n`) is emitted as an additional
    /// `data:` line per the spec; CR is normalized so it cannot desync framing.
    data: []const u8 = "",
    /// The `retry:` reconnection time in milliseconds; null ⇒ omit.
    retry: ?u32 = null,
};

/// Rejected when a single-line field (`event`/`id`) contains a CR or LF that
/// would break the event framing.
pub const FieldError = error{InvalidField};

/// Errors from starting a stream (setting the streaming headers).
pub const StartError = Server.ResponseWriter.SetHeaderError;

/// Errors from sending an event: a bad field or a transport write failure.
pub const SendError = FieldError || Writer.Error;

/// A live `text/event-stream` response. Create with `start`; the underlying
/// `ResponseWriter` must outlive it (it is borrowed).
pub const EventStream = struct {
    rw: *Server.ResponseWriter,

    /// Take over `rw` as an event stream: status 200, `Content-Type:
    /// text/event-stream`, `Cache-Control: no-store` (SSE must not be cached),
    /// and `X-Accel-Buffering: no` (defeat proxy buffering that would defeat
    /// streaming). Does not write the head yet — the first `send` does. Sets no
    /// Content-Length; the body streams chunked. To prime the client's
    /// reconnection time, set `Event.retry` on the first event you send.
    pub fn start(rw: *Server.ResponseWriter) StartError!EventStream {
        rw.setStatus(200);
        try rw.setHeader("Content-Type", "text/event-stream");
        try rw.setHeader("Cache-Control", "no-store");
        try rw.setHeader("X-Accel-Buffering", "no");
        return .{ .rw = rw };
    }

    /// Format one event and flush it to the socket. Field order: `event`,
    /// `id`, `retry`, then `data` line(s), then the terminating blank line.
    pub fn send(es: *EventStream, ev: Event) SendError!void {
        // Validate the single-line fields before writing anything, so a bad
        // event never leaves a half-written frame on the wire.
        if (ev.event) |name| {
            if (std.mem.indexOfAny(u8, name, "\r\n") != null) return error.InvalidField;
        }
        if (ev.id) |id| {
            if (std.mem.indexOfAny(u8, id, "\r\n\x00") != null) return error.InvalidField;
        }

        const w = es.rw.writer();
        if (ev.event) |name| {
            try w.writeAll("event: ");
            try w.writeAll(name);
            try w.writeByte('\n');
        }
        if (ev.id) |id| {
            try w.writeAll("id: ");
            try w.writeAll(id);
            try w.writeByte('\n');
        }
        if (ev.retry) |ms| try w.print("retry: {d}\n", .{ms});

        // Data lines (WHATWG §9.2.6): cut at each '\n' or '\r' (a '\r'
        // followed by '\n' counts as one break) and emit one data: line per
        // segment — including a trailing empty segment when the data ends
        // with a newline, and exactly one "data:\n" for empty data.
        var rest = ev.data;
        while (true) {
            if (std.mem.indexOfAny(u8, rest, "\r\n")) |i| {
                try writeDataLine(w, rest[0..i]);
                var next = i + 1;
                if (rest[i] == '\r' and next < rest.len and rest[next] == '\n') next += 1;
                rest = rest[next..];
            } else {
                try writeDataLine(w, rest);
                break;
            }
        }

        try w.writeByte('\n'); // blank line dispatches the event
        try es.rw.flush();
    }

    fn writeDataLine(w: *Writer, line: []const u8) Writer.Error!void {
        if (line.len == 0) return w.writeAll("data:\n");
        try w.writeAll("data: ");
        try w.writeAll(line);
        try w.writeByte('\n');
    }

    /// Convenience: a default-type ("message") event carrying `payload`.
    pub fn data(es: *EventStream, payload: []const u8) SendError!void {
        return es.send(.{ .data = payload });
    }

    /// Write an SSE comment line (`: text\n\n`) and flush — a heartbeat that
    /// keeps the connection and intermediaries alive without dispatching a
    /// client event. `text` must not contain CR or LF.
    pub fn comment(es: *EventStream, text: []const u8) SendError!void {
        if (std.mem.indexOfAny(u8, text, "\r\n") != null) return error.InvalidField;
        const w = es.rw.writer();
        try w.writeAll(": ");
        try w.writeAll(text);
        try w.writeAll("\n\n");
        try es.rw.flush();
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testEpoch(_: ?*anyopaque) i64 {
    return 784111777; // Sun, 06 Nov 1994 08:49:37 GMT
}

/// Drive one GET request through `Server.serveStream` with `handler` and
/// return the raw wire bytes (head + chunked body).
fn runSse(handler: Server.Handler, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed("GET /sse HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [64]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    Server.serveStream(.{
        .handler = handler,
        .server_name = "test",
        .now = .{ .epochSeconds = testEpoch },
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

/// Concatenate the chunk payloads of a chunked response body — each `send`
/// flushes, so events arrive as separate chunks; this recovers the clean
/// event bytes to assert on.
fn dechunk(raw: []const u8, out: []u8) []const u8 {
    const body_start = (std.mem.indexOf(u8, raw, "\r\n\r\n") orelse @panic("no head/body split")) + 4;
    var rest = raw[body_start..];
    var w: std.Io.Writer = .fixed(out);
    while (true) {
        const nl = std.mem.indexOf(u8, rest, "\r\n") orelse @panic("missing chunk-size line");
        const size = std.fmt.parseInt(usize, rest[0..nl], 16) catch @panic("bad chunk size");
        if (size == 0) break;
        w.writeAll(rest[nl + 2 ..][0..size]) catch @panic("dechunk buffer too small");
        rest = rest[nl + 2 + size + 2 ..];
    }
    return w.buffered();
}

fn eventsHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = req;
    var es = try EventStream.start(rw);
    try es.send(.{ .data = "hello" }); // simple default-type event
    try es.send(.{ .event = "tick", .id = "1", .retry = 3000, .data = "x" });
    try es.send(.{ .data = "a\nb" }); // multi-line data
    try es.send(.{ .data = "a\r\nb" }); // CRLF break normalized
    try es.send(.{ .data = "a\rb" }); // lone CR break normalized
    try es.send(.{ .data = "a\n" }); // trailing newline → trailing empty line
    try es.send(.{ .data = "" }); // empty data
    try es.comment("hi");
}

test "sse: headers and event wire bytes over serveStream" {
    var out_buf: [4096]u8 = undefined;
    const raw = runSse(eventsHandler, &out_buf);

    // Streaming head: SSE content type, no caching, chunked framing.
    try testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, raw, "Content-Type: text/event-stream\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Cache-Control: no-store\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "X-Accel-Buffering: no\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Transfer-Encoding: chunked\r\n") != null);

    var body_buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("data: hello\n\n" ++
        "event: tick\nid: 1\nretry: 3000\ndata: x\n\n" ++
        "data: a\ndata: b\n\n" ++
        "data: a\ndata: b\n\n" ++
        "data: a\ndata: b\n\n" ++
        "data: a\ndata:\n\n" ++
        "data:\n\n" ++
        ": hi\n\n", dechunk(raw, &body_buf));
}

fn invalidFieldsHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = req;
    var es = try EventStream.start(rw);
    try testing.expectError(error.InvalidField, es.send(.{ .event = "a\nb" }));
    try testing.expectError(error.InvalidField, es.send(.{ .event = "a\rb" }));
    try testing.expectError(error.InvalidField, es.send(.{ .id = "1\n2" }));
    try testing.expectError(error.InvalidField, es.send(.{ .id = "1\r2" }));
    try testing.expectError(error.InvalidField, es.send(.{ .id = "1\x002" }));
    try testing.expectError(error.InvalidField, es.comment("a\nb"));
    try testing.expectError(error.InvalidField, es.comment("a\rb"));
    // Rejection happens before any bytes are written — a clean event still
    // goes out as the only body content.
    try es.send(.{ .data = "ok" });
}

test "sse: invalid event/id/comment fields are rejected before writing" {
    var out_buf: [4096]u8 = undefined;
    const raw = runSse(invalidFieldsHandler, &out_buf);
    try testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 200 OK\r\n"));
    var body_buf: [256]u8 = undefined;
    try testing.expectEqualStrings("data: ok\n\n", dechunk(raw, &body_buf));
}
