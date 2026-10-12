// SPDX-License-Identifier: MIT

//! Go's `httptest.ResponseRecorder`, socket-free: run a handler over canned
//! request bytes through `Server.serveStream` — the same codec the serving
//! loop runs, so framing, auto-headers, refusals and keep-alive are the real
//! ones — and get the responses back parsed, one per request.
//!
//! ```zig
//! var rec = try http.httptest.record(gpa, .{ .handler = h, .server_name = null },
//!     "GET /x HTTP/1.1\r\nHost: t\r\n\r\n", .{});
//! defer rec.deinit();
//! const res = try rec.only();
//! try testing.expectEqual(200, res.status);
//! try testing.expectEqualStrings("hi", res.body);
//! ```
//!
//! Differences from Go: the request is wire bytes, not a `NewRequest`
//! struct (several pipelined requests give several responses); the body is
//! the decoded payload (chunked framing undone, trailers split off), while
//! `raw` keeps every byte the server wrote; `StreamOptions` passes through
//! unchanged, so pass `.server_name = null` (and leave `.now` null) for
//! goldens free of `Server`/`Date`. HTTP/1.1 only — an h2 recorder would
//! need a client-side h2 codec here.

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const h1 = @import("h1.zig");
const Server = @import("Server.zig");

/// Working memory for one recorded connection (`StreamBuffers`). The
/// defaults match the socket serving loop's, so a head or body that fits
/// there fits here.
pub const Config = struct {
    head_bytes: usize = 16 * 1024,
    request_body_bytes: usize = 4096,
    response_body_bytes: usize = 4 * 1024,
    chunk_bytes: usize = 512,
    trailer_bytes: usize = 1024,
    /// Bound on everything the server writes; reaching it is
    /// `error.OutputTooLarge`, never a silently cut recording.
    max_output_bytes: usize = 1024 * 1024,
};

/// One response as the client saw it.
pub const Response = struct {
    status: u16,
    reason: []const u8,
    /// The parsed head (`head.header(name)`, `head.iterate()`, framing flags).
    head: h1.ResponseHead,
    /// The payload: Content-Length bytes, or the chunks joined. Empty for a
    /// 1xx, 204, 304 and any answer to HEAD.
    body: []const u8,
    /// A chunked body's trailer section as a raw header block (`trailer`).
    trailers: []const u8 = "",
    /// The bytes of this response on the wire, head through framing.
    raw: []const u8,
    /// False when the output ended before the framing did: a handler that
    /// failed after the head (the server then closes the connection).
    complete: bool = true,

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(r: *const Response, name: []const u8) ?[]const u8 {
        return r.head.header(name);
    }

    /// First trailer field `name` (case-insensitive), or null.
    pub fn trailer(r: *const Response, name: []const u8) ?[]const u8 {
        return h1.blockHeader(r.trailers, name);
    }
};

/// Everything one `record` saw; owns all its slices.
pub const Recording = struct {
    arena: std.heap.ArenaAllocator,
    /// Every byte the server wrote.
    raw: []const u8,
    /// In wire order, interim (1xx other than 101) responses included.
    responses: []const Response,
    /// The bytes after a 101 or a 2xx to CONNECT: the connection's new
    /// protocol, written by the handler through `Request.upgraded`.
    tunnel: []const u8 = "",

    pub fn deinit(r: *Recording) void {
        r.arena.deinit();
        r.* = undefined;
    }

    pub const OnlyError = error{NotOneResponse};

    /// The one final response, for the common one-request case; interim
    /// 1xx responses before it are skipped.
    pub fn only(r: *const Recording) OnlyError!*const Response {
        var found: ?*const Response = null;
        for (r.responses) |*res| {
            if (isInterim(res.status)) continue;
            if (found != null) return error.NotOneResponse;
            found = res;
        }
        return found orelse error.NotOneResponse;
    }
};

pub const RecordError = std.mem.Allocator.Error || error{
    /// The server wrote `Config.max_output_bytes` or more.
    OutputTooLarge,
    /// The server wrote something that does not parse as an HTTP/1.x
    /// response head, or a chunked body that does not decode.
    MalformedResponse,
};

/// Serve `wire` (one or more pipelined requests, as a client would send
/// them) with `opts` and parse what the server wrote. The working memory
/// comes from `gpa`, including the gzip scratch when `opts.compression` /
/// `opts.max_decompressed_request_bytes` ask for it, so `opts` behaves as
/// it does on a socket.
pub fn record(gpa: std.mem.Allocator, opts: Server.StreamOptions, wire: []const u8, cfg: Config) RecordError!Recording {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const head = try a.alloc(u8, cfg.head_bytes);
    const request_body = try a.alloc(u8, cfg.request_body_bytes);
    const response_body = try a.alloc(u8, cfg.response_body_bytes);
    const chunk = try a.alloc(u8, cfg.chunk_bytes);
    const trailers = try a.alloc(u8, cfg.trailer_bytes);
    const gz: ?*Server.GzipScratch = if (opts.compression != null) try a.create(Server.GzipScratch) else null;
    const gunzip: ?*Server.GunzipScratch = if (opts.max_decompressed_request_bytes != 0)
        try a.create(Server.GunzipScratch)
    else
        null;

    const out_buf = try a.alloc(u8, cfg.max_output_bytes);
    var out: Writer = .fixed(out_buf);
    var in: Reader = .fixed(wire);
    Server.serveStream(opts, &in, &out, .{
        .head = head,
        .request_body = request_body,
        .response_body = response_body,
        .chunk = chunk,
        .trailers = trailers,
        .gzip = gz,
        .gunzip = gunzip,
    });
    // A full buffer is the only way a fixed writer fails, and the server
    // cannot report it (it just stops): a full buffer is the verdict.
    const raw = out.buffered();
    if (raw.len == out_buf.len) return error.OutputTooLarge;

    const methods = try requestMethods(a, wire, cfg.head_bytes);
    var rec: Recording = .{ .arena = undefined, .raw = raw, .responses = &.{} };
    rec.responses = try parseResponses(a, raw, methods, &rec.tunnel);
    rec.arena = arena;
    return rec;
}

const RequestKind = enum { head, connect, other };

/// The method of each request on `wire`, read the way the server frames
/// them. It only decides which responses carry a body (HEAD) and which open
/// a tunnel (CONNECT); a request it cannot frame ends the list — the server
/// refuses it and closes, so no response after it needs a method.
fn requestMethods(a: std.mem.Allocator, wire: []const u8, head_bytes: usize) std.mem.Allocator.Error![]const RequestKind {
    var list: std.ArrayList(RequestKind) = .empty;
    const buf = try a.alloc(u8, head_bytes);
    var in: Reader = .fixed(wire);
    while (true) {
        const block = h1.readHead(&in, buf) catch break;
        const req = h1.RequestHead.parse(block) catch break;
        const kind: RequestKind = if (std.mem.eql(u8, req.method, "HEAD"))
            .head
        else if (std.mem.eql(u8, req.method, "CONNECT"))
            .connect
        else
            .other;
        try list.append(a, kind);
        if (kind == .connect) break; // what follows is the tunnel's
        if (req.chunked) {
            var scratch: [256]u8 = undefined;
            var cr: h1.ChunkedReader = .init(&in, &scratch);
            _ = cr.reader.discardRemaining() catch break;
        } else if (req.content_length) |n| {
            _ = in.discard(.limited64(n)) catch break;
        }
    }
    return list.items;
}

fn isInterim(status: u16) bool {
    return status >= 100 and status < 200 and status != 101;
}

fn parseResponses(
    a: std.mem.Allocator,
    raw: []const u8,
    methods: []const RequestKind,
    tunnel: *[]const u8,
) RecordError![]const Response {
    var list: std.ArrayList(Response) = .empty;
    var in: Reader = .fixed(raw);
    // A head can be as long as the whole output, never longer.
    const head_buf = try a.alloc(u8, raw.len);
    var head_off: usize = 0;
    var req_index: usize = 0;
    while (in.seek < raw.len) {
        const start = in.seek;
        const block = h1.readHead(&in, head_buf[head_off..]) catch return error.MalformedResponse;
        head_off += block.len;
        const head = h1.ResponseHead.parse(block) catch return error.MalformedResponse;
        var res: Response = .{
            .status = head.status,
            .reason = head.reason,
            .head = head,
            .body = "",
            .raw = undefined,
        };
        if (isInterim(head.status)) {
            res.raw = raw[start..in.seek];
            try list.append(a, res);
            continue;
        }
        const kind: RequestKind = if (req_index < methods.len) methods[req_index] else .other;
        req_index += 1;

        const switched = head.status == 101 or (kind == .connect and head.status / 100 == 2);
        const bodiless = switched or kind == .head or head.status == 204 or head.status == 304;
        var last = switched;
        if (bodiless) {
            // no payload
        } else if (head.chunked) {
            var scratch: [256]u8 = undefined;
            const trailer_buf = try a.alloc(u8, raw.len - in.seek);
            var cr: h1.ChunkedReader = .initCapturingTrailers(&in, &scratch, trailer_buf);
            var body: Writer.Allocating = .init(a);
            _ = cr.reader.streamRemaining(&body.writer) catch |err| switch (err) {
                error.WriteFailed => return error.OutOfMemory,
                error.ReadFailed => if (cr.fail_reason == .truncated_body) {
                    res.complete = false;
                } else return error.MalformedResponse,
            };
            res.body = body.written();
            res.trailers = cr.trailers();
        } else if (head.content_length) |n| {
            const have = raw.len - in.seek;
            res.body = raw[in.seek..][0..@min(have, n)];
            in.seek += res.body.len;
            res.complete = have >= n;
        } else {
            // Neither framing: the body runs to the end of the connection.
            res.body = raw[in.seek..];
            in.seek = raw.len;
            last = true;
        }
        res.raw = raw[start..in.seek];
        try list.append(a, res);
        if (switched) tunnel.* = raw[in.seek..];
        if (last or !res.complete) break;
    }
    return list.items;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hello(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/big")) {
        // Past the 64-byte response buffer below: streams chunked.
        try rw.setHeader("Content-Type", "text/plain");
        try rw.declareTrailer("X-Sum");
        for (0..10) |i| try rw.writer().print("line {d} of a body bigger than the buffer\n", .{i});
        try rw.setTrailer("X-Sum", "ok");
        return;
    }
    if (std.mem.eql(u8, req.path, "/empty")) {
        rw.setStatus(204);
        return;
    }
    if (std.mem.eql(u8, req.path, "/fail")) {
        try rw.writer().writeAll("partial ");
        try rw.flush(); // the head is out: the failure can only cut the body
        return error.Boom;
    }
    try rw.setHeader("Content-Type", "text/plain");
    try rw.writer().print("{s} {s}", .{ req.methodName(), req.target });
}

const quiet: Server.StreamOptions = .{ .handler = hello, .server_name = null };

test "record: one request, one response, parsed" {
    var rec = try record(testing.allocator, quiet, "GET /a?b=1 HTTP/1.1\r\nHost: t\r\n\r\n", .{});
    defer rec.deinit();
    const res = try rec.only();
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("OK", res.reason);
    try testing.expectEqualStrings("text/plain", res.header("content-type").?);
    try testing.expectEqualStrings("GET /a?b=1", res.body);
    try testing.expect(res.complete);
    try testing.expectEqualStrings(rec.raw, res.raw);
    try testing.expect(res.header("Server") == null);
    try testing.expect(res.header("Date") == null);
}

test "record: pipelined requests, HEAD bodiless, chunked decoded with trailers" {
    var rec = try record(testing.allocator, quiet, "HEAD /h HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /big HTTP/1.1\r\nHost: t\r\nTE: trailers\r\n\r\n" ++
        "POST /p HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc" ++
        "GET /empty HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ .response_body_bytes = 64 });
    defer rec.deinit();
    try testing.expectEqual(@as(usize, 4), rec.responses.len);
    try testing.expectError(error.NotOneResponse, rec.only());

    const head = rec.responses[0];
    try testing.expectEqualStrings("", head.body);
    try testing.expectEqualStrings("7", head.header("Content-Length").?); // "HEAD /h", not sent

    const big = rec.responses[1];
    try testing.expect(big.head.chunked);
    try testing.expect(std.mem.startsWith(u8, big.body, "line 0 of a body"));
    try testing.expect(std.mem.endsWith(u8, big.body, "line 9 of a body bigger than the buffer\n"));
    try testing.expectEqualStrings("ok", big.trailer("x-sum").?);

    try testing.expectEqualStrings("POST /p", rec.responses[2].body);
    try testing.expectEqual(@as(u16, 204), rec.responses[3].status);
    try testing.expectEqualStrings("", rec.responses[3].body);

    // The pieces tile the output exactly.
    var len: usize = 0;
    for (rec.responses) |r| len += r.raw.len;
    try testing.expectEqual(rec.raw.len, len);
}

test "record: server refusal ends the connection; later requests get nothing" {
    var rec = try record(testing.allocator, quiet, "GET /a HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /b HTTP/1.1\r\n\r\n" ++ // no Host: 400, close
        "GET /c HTTP/1.1\r\nHost: t\r\n\r\n", .{});
    defer rec.deinit();
    try testing.expectEqual(@as(usize, 2), rec.responses.len);
    try testing.expectEqual(@as(u16, 200), rec.responses[0].status);
    try testing.expectEqual(@as(u16, 400), rec.responses[1].status);
}

test "record: a handler failing after the head leaves an incomplete body" {
    var rec = try record(testing.allocator, quiet, "GET /fail HTTP/1.1\r\nHost: t\r\n\r\nGET /a HTTP/1.1\r\nHost: t\r\n\r\n", .{});
    defer rec.deinit();
    const res = try rec.only();
    try testing.expect(!res.complete);
    try testing.expectEqualStrings("partial ", res.body);
}

test "record: interim 100 Continue is listed but not counted" {
    var rec = try record(testing.allocator, quiet, "PUT /u HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n" ++
        "Expect: 100-continue\r\nConnection: close\r\n\r\nhi", .{});
    defer rec.deinit();
    // The server sends 100 only when the handler reads the body, which
    // `hello` does not; either way `only` finds the final answer.
    const res = try rec.only();
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("PUT /u", res.body);
}

fn echoUpload(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    var buf: [64]u8 = undefined;
    const n = try req.reader().readSliceShort(&buf);
    try rw.writeAll(buf[0..n]);
}

test "record: 100 Continue before the final response" {
    var rec = try record(testing.allocator, .{ .handler = echoUpload, .server_name = null }, "PUT /u HTTP/1.1\r\nHost: t\r\n" ++
        "Content-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nhi", .{});
    defer rec.deinit();
    try testing.expectEqual(@as(usize, 2), rec.responses.len);
    try testing.expectEqual(@as(u16, 100), rec.responses[0].status);
    const res = try rec.only();
    try testing.expectEqualStrings("hi", res.body);
}

fn tunnelEcho(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    try rw.tunnel(200);
    const up = req.upgraded(rw).?;
    var buf: [16]u8 = undefined;
    const n = try up.reader.readSliceShort(&buf);
    try up.writer.print("echo:{s}", .{buf[0..n]});
    try up.writer.flush();
}

test "record: CONNECT 2xx opens a tunnel; its bytes are not a body" {
    var rec = try record(testing.allocator, .{ .handler = tunnelEcho, .server_name = null }, "CONNECT x.test:443 HTTP/1.1\r\n\r\nping", .{});
    defer rec.deinit();
    const res = try rec.only();
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("", res.body);
    try testing.expectEqualStrings("echo:ping", rec.tunnel);
}

test "record: compression gets its scratch from the recorder" {
    var rec = try record(testing.allocator, .{
        .handler = hello,
        .server_name = null,
        .compression = .{ .min_size = 0 },
    }, "GET /big HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", .{});
    defer rec.deinit();
    const res = try rec.only();
    try testing.expectEqualStrings("gzip", res.header("Content-Encoding").?);
    var in: Reader = .fixed(res.body);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var d: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var plain: Writer.Allocating = .init(testing.allocator);
    defer plain.deinit();
    _ = try d.reader.streamRemaining(&plain.writer);
    try testing.expect(std.mem.startsWith(u8, plain.written(), "line 0 of a body"));
}

test "record: output past max_output_bytes is an error" {
    try testing.expectError(error.OutputTooLarge, record(testing.allocator, quiet, "GET /big HTTP/1.1\r\nHost: t\r\n\r\n", .{
        .response_body_bytes = 64,
        .max_output_bytes = 100,
    }));
}

test "record: allocation failures are reported, never leaked" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(gpa: std.mem.Allocator) !void {
            var rec = record(gpa, quiet, "GET /a HTTP/1.1\r\nHost: t\r\n\r\n", .{}) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return err,
            };
            rec.deinit();
        }
    }.run, .{});
}
