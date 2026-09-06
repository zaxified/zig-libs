// SPDX-License-Identifier: MIT

//! `Client` — the Anthropic Messages API surface over the sibling
//! `http.Client`: `create` for a buffered `POST /v1/messages`, `stream`
//! for the Server-Sent-Events variant (`stream: true`), pulling one
//! `StreamEvent` at a time via `EventIterator`.
//!
//! `http.Client` handles real HTTPS (the h1 stack's TLS is
//! `std.crypto.tls`, not a BYO-TLS stub — that caveat only applies to the
//! h2 stack), so `client.request(.post, "https://api.anthropic.com/...",
//! ...)` works as-is; no gzip/chunked handling is needed here beyond what
//! `http.Client.Response.reader()` already decodes.

const std = @import("std");
const http = @import("http");
const types = @import("types.zig");
const response = @import("response.zig");
const sse_parse = @import("sse_parse.zig");

const Client = @This();

pub const MessageRequest = types.MessageRequest;
pub const Message = response.Message;
pub const StreamEvent = response.StreamEvent;

/// Caller-owned transport (share it with other subsystems freely).
http_client: *http.Client,
/// `x-api-key` header value.
api_key: []const u8,
/// `anthropic-version` header value.
anthropic_version: []const u8 = "2023-06-01",
/// API base URL (no trailing slash) — override for a proxy or test double.
/// This is the ONLY host the key is ever sent to: a 3xx from it is
/// `error.UnexpectedStatus`, never followed (see `create`).
base_url: []const u8 = "https://api.anthropic.com",
/// Upper bound on a buffered (non-streaming) response body — bytes ON THE
/// WIRE. What a response costs is `max_parsed_bytes`.
max_response_bytes: usize = 10 << 20,
/// Upper bound on the memory one response (`create`) or one stream event
/// (`EventIterator.next`) may allocate while being parsed into
/// `Message`/`StreamEvent` — the quantity that actually costs. A body of
/// 7.8 MB, under the 10 MiB wire cap, parsed into 310 MiB of `std.json`
/// nodes and returned `OK` before this existed (2026-09-06); past this
/// bound the call is `error.ResponseTooLarge` and the arena is released.
max_parsed_bytes: usize = 64 << 20,
/// Upper bound on one SSE dispatch group's joined `data:` payload
/// (`sse_parse.Parser.max_data_bytes`); past it `EventIterator.next` is
/// `error.ResponseTooLarge`. One API event is one ~4 KiB line; the default
/// is headroom, not a limit anyone legitimate reaches.
max_event_bytes: usize = sse_parse.Parser.default_max_data_bytes,
/// Deadline, in milliseconds, on reading the response body: the whole
/// body for `create`, each `next()` for a stream. `http.Client`'s
/// `total_timeout_ms` bounds connect + request + response HEAD and,
/// deliberately, not the body (its own doc says to wrap the read); before
/// this existed a peer trickling one byte a second held `create` for as
/// long as it cared to (measured: 30 s against a 2 s total timeout, ended
/// by the peer). `0` = unbounded. Enforced by racing the read against the
/// deadline on a concurrent task; when the `std.Io` cannot spare one the
/// read runs unbounded, as `http.Client` does in the same situation.
read_timeout_ms: u32 = 60_000,

error_scratch: [error_scratch_len]u8 = undefined,
error_len: usize = 0,

pub const Error = error{
    OutOfMemory,
    /// Transport failure (connect/TLS/read/write) from `http.Client`.
    HttpFailed,
    Timeout,
    Canceled,
    /// The API responded outside 2xx — see `lastErrorBody`.
    UnexpectedStatus,
    /// The response was not the expected Anthropic Messages API JSON shape.
    MalformedResponse,
    /// The response (or one stream event) is over a size bound: the wire
    /// body over `max_response_bytes`, its parse over `max_parsed_bytes`,
    /// or an SSE group over `max_event_bytes`. Distinct from `HttpFailed`
    /// so a caller can tell "the peer sent too much" from "the connection
    /// died".
    ResponseTooLarge,
};

pub fn init(http_client: *http.Client, api_key: []const u8) Client {
    return .{ .http_client = http_client, .api_key = api_key };
}

/// The body of the most recent non-2xx response (truncated to 512 bytes),
/// for diagnostics after `error.UnexpectedStatus`. Borrowed — valid until
/// the next request through this client.
pub fn lastErrorBody(c: *const Client) ?[]const u8 {
    if (c.error_len == 0) return null;
    return c.error_scratch[0..c.error_len];
}

fn noteError(c: *Client, body: []const u8) void {
    const n = @min(body.len, c.error_scratch.len);
    @memcpy(c.error_scratch[0..n], body[0..n]);
    c.error_len = n;
}

fn requestHeaders(c: *const Client) [3]http.Header {
    return .{
        .{ .name = "x-api-key", .value = c.api_key },
        .{ .name = "anthropic-version", .value = c.anthropic_version },
        .{ .name = "content-type", .value = "application/json" },
    };
}

fn messagesUrl(base_url: []const u8, buf: []u8) error{MalformedResponse}![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/v1/messages", .{base_url}) catch return error.MalformedResponse;
}

fn mapHttpError(err: http.Client.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Timeout => error.Timeout,
        error.BodyTooLarge => error.ResponseTooLarge,
        else => error.HttpFailed,
    };
}

/// `http.RequestOptions` for both entry points: the key rides on every
/// request, so a redirect is never followed (A1 F1). `http.Client` strips
/// `Authorization`/`Cookie` on a cross-origin hop but not `x-api-key` —
/// it cannot know the name — and even a same-origin hop would resend the
/// whole prompt. The API never answers 3xx; a 3xx is treated like any
/// other non-2xx: `error.UnexpectedStatus` with the body in
/// `lastErrorBody`.
fn requestOptions(hdrs: []const http.Header, body: []const u8) http.Client.RequestOptions {
    return .{ .headers = hdrs, .body = body, .follow_redirects = false };
}

fn readDeadline(c: *const Client) ?std.Io.Clock.Timestamp {
    if (c.read_timeout_ms == 0) return null;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(c.read_timeout_ms), .clock = .awake } };
    return t.toTimestamp(c.http_client.io);
}

/// `readAllAlloc` as a plain function, so `runBounded` can race it.
fn readBody(res: *http.Client.Response, a: std.mem.Allocator, max: usize) http.Client.Error![]u8 {
    return res.readAllAlloc(a, max);
}

/// `sse_parse.Parser.next` as a plain function, for the same reason.
fn parserNext(p: *sse_parse.Parser) sse_parse.Error!?sse_parse.Event {
    return p.next();
}

// ── a deadline for one blocking read ────────────────────────────────────────
//
// The same shape `http.Client` uses for its own total timeout, kept private
// there; a copy is the price of not widening `http`'s API for one consumer.
// Contract: finished in time → `func`'s own result; deadline hit → the task
// is canceled and joined, then `error.Timeout` (a success that landed in
// the cancelation window is still returned); this task canceled while
// waiting → `error.Canceled`; no unit of concurrency → the caller runs
// `func` unbounded (`error.ConcurrencyUnavailable`).

fn BoundedResult(comptime func: anytype) type {
    const Result = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    const Payload = @typeInfo(Result).error_union.payload;
    const Errs = @typeInfo(Result).error_union.error_set;
    return (Errs || error{ Timeout, Canceled, ConcurrencyUnavailable })!Payload;
}

fn runBounded(
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
) BoundedResult(func) {
    const Result = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    const Ctx = struct {
        io: std.Io,
        args: std.meta.ArgsTuple(@TypeOf(func)),
        result: Result = undefined,
        state: std.atomic.Value(u32) = .init(0),

        fn run(ctx: *@This()) void {
            ctx.result = @call(.auto, func, ctx.args);
            ctx.state.store(1, .release);
            ctx.io.futexWake(u32, &ctx.state.raw, 1);
        }
    };

    var ctx: Ctx = .{ .io = io, .args = args };
    var future = io.concurrent(Ctx.run, .{&ctx}) catch return error.ConcurrencyUnavailable;

    var canceled = false;
    var expired = false;
    while (ctx.state.load(.acquire) == 0) {
        const timeout: std.Io.Timeout = if (deadline) |d| t: {
            if (d.durationFromNow(io).raw.nanoseconds <= 0) {
                expired = true;
                break;
            }
            break :t .{ .deadline = d };
        } else .none;
        io.futexWaitTimeout(u32, &ctx.state.raw, 0, timeout) catch {
            canceled = true;
            break;
        };
    }
    if (!expired and !canceled) {
        future.await(io);
        return ctx.result;
    }
    future.cancel(io);
    if (ctx.result) |value| return value else |_| {}
    return if (expired) error.Timeout else error.Canceled;
}

// ── a memory bound on the parse ─────────────────────────────────────────────

/// An allocator that refuses past `limit` bytes of live requests — the
/// gate `max_parsed_bytes` is enforced through. Wraps the parse arena, so
/// a `std.json` tree that would cost more than the bound fails as
/// `OutOfMemory` inside the parser and is reported as
/// `error.ResponseTooLarge` here (`exceeded` says which it was). Frees
/// are credited back (an arena never issues any, but the wrapper does
/// not assume that).
const BoundedAllocator = struct {
    child: std.mem.Allocator,
    limit: usize,
    used: usize = 0,
    exceeded: bool = false,

    fn allocator(self: *BoundedAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn charge(self: *BoundedAllocator, extra: usize) bool {
        if (extra > self.limit - self.used) {
            self.exceeded = true;
            return false;
        }
        self.used += extra;
        return true;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (!self.charge(len)) return null;
        const p = self.child.rawAlloc(len, alignment, ret_addr) orelse {
            self.used -= len;
            return null;
        };
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and !self.charge(new_len - memory.len)) return false;
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) {
            if (new_len > memory.len) self.used -= new_len - memory.len;
            return false;
        }
        if (new_len < memory.len) self.used -= memory.len - new_len;
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and !self.charge(new_len - memory.len)) return null;
        const p = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse {
            if (new_len > memory.len) self.used -= new_len - memory.len;
            return null;
        };
        if (new_len < memory.len) self.used -= memory.len - new_len;
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ret_addr);
        self.used -|= memory.len;
    }
};

/// `POST /v1/messages` (non-streaming; `req.stream` is forced false).
/// The returned `Parsed(Message)` owns an arena backing every string in
/// the result — call `.deinit()`.
pub fn create(c: *Client, gpa: std.mem.Allocator, req: MessageRequest) Error!std.json.Parsed(Message) {
    var non_stream = req;
    non_stream.stream = false;

    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const body = types.stringifyAlloc(a, non_stream) catch return error.OutOfMemory;

    var url_buf: [256]u8 = undefined;
    const url = try messagesUrl(c.base_url, &url_buf);
    const hdrs = c.requestHeaders();

    var res = c.http_client.request(.post, url, requestOptions(&hdrs, body)) catch |err|
        return mapHttpError(err);
    defer res.deinit();

    // The body read, under `read_timeout_ms` (A1 F4). A 3xx body is read
    // too — it is what `lastErrorBody` shows for the redirect that is not
    // followed.
    const resp_body = runBounded(c.http_client.io, c.readDeadline(), readBody, .{ &res, a, c.max_response_bytes }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => readBody(&res, a, c.max_response_bytes) catch |e| return mapHttpError(e),
        error.Timeout => return error.Timeout,
        error.Canceled => return error.Canceled,
        else => |e| return mapHttpError(e),
    };

    if (res.status < 200 or res.status >= 300) {
        c.noteError(resp_body);
        return error.UnexpectedStatus;
    }

    // The parse, under `max_parsed_bytes` (A1 F5): the wire cap above
    // bounds bytes, this bounds what they turn into.
    var bounded: BoundedAllocator = .{ .child = a, .limit = c.max_parsed_bytes };
    const msg = response.parseMessage(bounded.allocator(), resp_body) catch |err| switch (err) {
        error.OutOfMemory => return if (bounded.exceeded) error.ResponseTooLarge else error.OutOfMemory,
        error.MalformedResponse => return error.MalformedResponse,
    };
    return .{ .arena = arena, .value = msg };
}

/// `POST /v1/messages` with `stream: true` forced; returns an
/// `EventIterator` that pulls one `StreamEvent` per SSE dispatch group.
/// Owns the connection — call `EventIterator.deinit`.
pub fn stream(c: *Client, gpa: std.mem.Allocator, req: MessageRequest) Error!EventIterator {
    var streaming = req;
    streaming.stream = true;

    var build_arena = std.heap.ArenaAllocator.init(gpa);
    defer build_arena.deinit();
    const body = types.stringifyAlloc(build_arena.allocator(), streaming) catch return error.OutOfMemory;

    var url_buf: [256]u8 = undefined;
    const url = try messagesUrl(c.base_url, &url_buf);
    const hdrs = c.requestHeaders();

    var res = c.http_client.request(.post, url, requestOptions(&hdrs, body)) catch |err|
        return mapHttpError(err);
    errdefer res.deinit();

    if (res.status < 200 or res.status >= 300) {
        // Bounded like `create`'s body read (A1 F4); and read into the
        // scratch `lastErrorBody` shows, truncated rather than dropped
        // when the body is longer than it (A1 F10 — `readAllAlloc` into a
        // 512-byte arena used to return `""` for any longer body).
        var err_buf: [error_scratch_len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&err_buf);
        _ = runBounded(c.http_client.io, c.readDeadline(), streamErrorBody, .{ &res, &w }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => streamErrorBody(&res, &w) catch {},
            else => {},
        };
        c.noteError(w.buffered());
        return error.UnexpectedStatus;
    }

    var it = EventIterator.init(gpa, res, c.http_client.io);
    it.parser.max_data_bytes = c.max_event_bytes;
    it.max_parsed_bytes = c.max_parsed_bytes;
    it.read_deadline_ms = c.read_timeout_ms;
    return it;
}

/// Copy as much of a non-2xx stream response body as `w` holds; the rest
/// is discarded (it is diagnostics, not data).
fn streamErrorBody(res: *http.Client.Response, w: *std.Io.Writer) http.Client.Error!void {
    const r = res.reader();
    while (true) {
        const n = r.stream(w, .limited(256)) catch |err| switch (err) {
            error.EndOfStream => return,
            error.WriteFailed => {
                // `w` is full: drain the remainder so the connection ends
                // cleanly, without keeping any of it.
                _ = r.discardRemaining() catch return res.readFailure();
                return;
            },
            error.ReadFailed => return res.readFailure(),
        };
        if (n == 0) return;
    }
}

const error_scratch_len = 512;

/// Pulls one `StreamEvent` at a time off an open streaming response.
pub const EventIterator = struct {
    res: http.Client.Response,
    parser: sse_parse.Parser,
    arena: std.heap.ArenaAllocator,
    /// Copied from `Client.max_parsed_bytes` / `read_timeout_ms` at
    /// `stream` time, so the iterator outlives any later change to the
    /// client's knobs.
    max_parsed_bytes: usize = 64 << 20,
    read_deadline_ms: u32 = 0,
    /// The transport's `std.Io`, for the per-`next()` deadline race.
    io: std.Io,

    fn init(gpa: std.mem.Allocator, res: http.Client.Response, io: std.Io) EventIterator {
        var it: EventIterator = .{
            .res = res,
            .parser = undefined,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .io = io,
        };
        it.parser = sse_parse.Parser.init(it.res.reader(), gpa);
        return it;
    }

    pub fn deinit(it: *EventIterator) void {
        it.parser.deinit();
        it.arena.deinit();
        it.res.deinit();
        it.* = undefined;
    }

    /// The next parsed stream event, or null at a clean end of stream.
    /// The event's memory is valid until the next `next()` call or
    /// `deinit()` — copy anything you need to keep.
    ///
    /// A `std.Io` cancellation of the blocked body read surfaces as
    /// `error.Canceled`, not `error.HttpFailed`. `it.res.reader()` (from
    /// `http.Client.Response`) is a plain `*std.Io.Reader` and still cannot
    /// carry `Canceled` itself, but `http.Client.Response.readFailure()`
    /// now exists precisely to answer this from outside `http` — see its
    /// doc comment. This mirrors what `create`/`stream`'s `mapHttpError`
    /// already does for the connect phase.
    ///
    /// Each call is bounded by `Client.read_timeout_ms` (`error.Timeout`)
    /// and by `max_event_bytes`/`max_parsed_bytes` (`error.ResponseTooLarge`);
    /// on either the connection is no longer usable and `deinit` is the
    /// only thing left to call.
    pub fn next(it: *EventIterator) Error!?StreamEvent {
        _ = it.arena.reset(.retain_capacity);
        while (true) {
            const deadline: ?std.Io.Clock.Timestamp = if (it.read_deadline_ms == 0) null else blk: {
                const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(it.read_deadline_ms), .clock = .awake } };
                break :blk t.toTimestamp(it.io);
            };
            const raw = runBounded(it.io, deadline, parserNext, .{&it.parser}) catch |err| switch (err) {
                error.ConcurrencyUnavailable => it.parser.next() catch |e| return it.mapParserError(e),
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Canceled,
                else => |e| return it.mapParserError(e),
            };
            const ev = raw orelse return null;
            if (ev.data.len == 0) continue;
            // The parse, under `max_parsed_bytes` (A1 F5), on this event's
            // slice of the arena; the arena's own capacity is what
            // `reset(.retain_capacity)` keeps, and it is bounded by the same
            // number. On a bound hit the arena is released as well, so a
            // caller that keeps the iterator around after the error does
            // not keep the peer's bytes with it (A1 F15).
            const a = it.arena.allocator();
            var bounded: BoundedAllocator = .{ .child = a, .limit = it.max_parsed_bytes };
            return response.parseStreamEvent(bounded.allocator(), ev.data) catch |err| switch (err) {
                error.OutOfMemory => {
                    if (!bounded.exceeded) return error.OutOfMemory;
                    _ = it.arena.reset(.free_all);
                    it.parser.releaseBuffers();
                    return error.ResponseTooLarge;
                },
                error.MalformedResponse => return error.MalformedResponse,
            };
        }
    }

    fn mapParserError(it: *EventIterator, err: sse_parse.Error) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.EndOfStream, error.LineTooLong => error.HttpFailed,
            error.DataTooLarge => blk: {
                _ = it.arena.reset(.free_all);
                break :blk error.ResponseTooLarge;
            },
            error.ReadFailed => mapHttpError(it.res.readFailure()),
        };
    }
};

// ── tests (offline where possible; one gated live test) ─────────────────────

const testing = std.testing;

test "Client.create: golden request body, headers, and non-2xx surfaces UnexpectedStatus + lastErrorBody" {
    // Exercise the pure pieces `create`/`stream` are built from without a
    // live network: header construction and URL building are pure/offline
    // testable (mirrors `http.Client.writeRequestHead`'s golden tests).
    var c: Client = .init(undefined, "sk-test-key");
    const hdrs = c.requestHeaders();
    try testing.expectEqualStrings("x-api-key", hdrs[0].name);
    try testing.expectEqualStrings("sk-test-key", hdrs[0].value);
    try testing.expectEqualStrings("anthropic-version", hdrs[1].name);
    try testing.expectEqualStrings("2023-06-01", hdrs[1].value);
    try testing.expectEqualStrings("content-type", hdrs[2].name);
    try testing.expectEqualStrings("application/json", hdrs[2].value);

    var url_buf: [256]u8 = undefined;
    const url = try messagesUrl(c.base_url, &url_buf);
    try testing.expectEqualStrings("https://api.anthropic.com/v1/messages", url);

    c.noteError("{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}");
    try testing.expectEqualStrings("{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}", c.lastErrorBody().?);
}

test "Client: request/response types are re-exported flatly" {
    const req: MessageRequest = .{
        .max_tokens = 16,
        .messages = &.{types.MessageParam.user(&.{types.textBlock("hi")})},
    };
    try testing.expectEqualStrings("claude-opus-4-8", req.model);
}

// ── tests (cancellation, loopback) ──────────────────────────────────────────
//
// `create`'s body read goes through `http.Client.Response.readAllAlloc`, and
// `mapHttpError` already names `error.Canceled` explicitly (see above) — so
// once `http` itself stopped laundering a canceled body read into
// `error.ReadFailed` (its `Client.zig:552`, this campaign's root fix), this
// path is fixed for free, with no change needed in this file. Proven here
// rather than assumed: the fake peer answers a `Content-Length: 5` head and
// sends none of the body, so the read is genuinely parked in the kernel when
// the test cancels it.

const CreateCancelPeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    stop: std.atomic.Value(u32) = .init(0),

    fn run(p: *CreateCancelPeer) void {
        const s = p.listener.accept(p.io) catch return;
        defer s.close(p.io);
        var wbuf: [256]u8 = undefined;
        var sw = s.writer(p.io, &wbuf);
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") catch {};
        sw.interface.flush() catch {};
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }
};

fn createOnce(c: *Client, gpa: std.mem.Allocator, req: MessageRequest) Error!std.json.Parsed(Message) {
    return c.create(gpa, req);
}

test "Client.create: a canceled body read surfaces error.Canceled, not error.HttpFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("llmclient cancel test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: CreateCancelPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, CreateCancelPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.stop.store(1, .release);

    var http_client = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer http_client.deinit();

    var url_buf: [64]u8 = undefined;
    const base_url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{port});

    var c: Client = .init(&http_client, "sk-test-key");
    c.base_url = base_url;

    const req: MessageRequest = .{
        .max_tokens = 16,
        .messages = &.{types.MessageParam.user(&.{types.textBlock("hi")})},
    };

    var fut = try io.concurrent(createOnce, .{ &c, testing.allocator, req });
    // Long enough that the head has arrived and the body read is the one
    // parked in the kernel.
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

/// `stream` returns as soon as the head arrives; the SSE body read that
/// this test cancels only happens inside `next()`, so both live in one
/// task — `it.deinit()` (closing the connection) runs as this function's
/// own defer, exactly like `create`'s internal `defer res.deinit()`.
fn streamNextOnce(c: *Client, gpa: std.mem.Allocator, req: MessageRequest) Error!?StreamEvent {
    var it = try c.stream(gpa, req);
    defer it.deinit();
    return it.next();
}

test "EventIterator.next: a canceled body read surfaces error.Canceled, not error.HttpFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("llmclient stream cancel test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    // Same peer shape as `create`'s cancel test: answers a `Content-Length: 5`
    // head and then sends none of the declared bytes, so `EventIterator.next`'s
    // first SSE line read is genuinely parked in the kernel when the cancel
    // arrives.
    var peer: CreateCancelPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, CreateCancelPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.stop.store(1, .release);

    var http_client = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer http_client.deinit();

    var url_buf: [64]u8 = undefined;
    const base_url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{port});

    var c: Client = .init(&http_client, "sk-test-key");
    c.base_url = base_url;

    const req: MessageRequest = .{
        .max_tokens = 16,
        .stream = true,
        .messages = &.{types.MessageParam.user(&.{types.textBlock("hi")})},
    };

    var fut = try io.concurrent(streamNextOnce, .{ &c, testing.allocator, req });
    // Long enough that the head has arrived and the body read is the one
    // parked in the kernel.
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

// ── tests (loopback stand-ins for the A1 findings) ──────────────────────────
//
// One scripted peer per shape the audit measured: a redirect (F1), a body
// that arrives one byte at a time (F4), a body far cheaper on the wire than
// in memory (F5), an SSE group with no end (F3), and a long error body
// (F10). Each accepts exactly the connections its test makes, so a `try`
// that fails mid-test cannot leave the thread parked in `accept`.

const Script = union(enum) {
    /// A 307 to `port`, with a small body.
    redirect: u16,
    /// A 200 head declaring a long body, then one byte every `ms` for 40 ticks or until `stop`.
    drip: u32,
    /// A 200 JSON body of `n` one-character text blocks.
    many_blocks: usize,
    /// A 200 `text/event-stream` body: ONE dispatch group of `lines` data lines
    /// of `width` bytes each, then a blank line.
    big_group: struct { lines: usize, width: usize },
    /// A 500 with a body of `n` bytes.
    long_error: usize,
};

const FakePeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    scripts: []const Script,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: usize = 0,

    fn run(p: *FakePeer) void {
        for (p.scripts) |script| {
            const s = p.listener.accept(p.io) catch return;
            defer s.close(p.io);
            p.accepted += 1;
            var rbuf: [8192]u8 = undefined;
            var wbuf: [4096]u8 = undefined;
            var sr = s.reader(p.io, &rbuf);
            var sw = s.writer(p.io, &wbuf);
            var head_buf: [8192]u8 = undefined;
            if (p.stop.load(.acquire) != 0) continue; // `finish` unparking us
            const head = http.h1.readHead(&sr.interface, &head_buf) catch continue;
            const req = http.h1.RequestHead.parse(head) catch continue;
            // Drain the request body so the client's write never blocks.
            if (req.content_length) |n| sr.interface.discardAll(@intCast(n)) catch continue;
            const w = &sw.interface;
            // A failed write ends THIS script (the client hung up), not the
            // peer: the next script's accept must still happen.
            script: switch (script) {
                .redirect => |port| {
                    w.print("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{d}/v1/messages\r\nContent-Length: 8\r\nConnection: close\r\n\r\nredirect", .{port}) catch break :script;
                    w.flush() catch break :script;
                },
                .drip => |ms| {
                    w.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000000\r\n\r\n") catch break :script;
                    w.flush() catch break :script;
                    // Bounded, so a client that gave up (and closed) does not
                    // keep this connection's turn forever: the next script
                    // must get its accept within the transport's total timeout.
                    var ticks: usize = 0;
                    while (p.stop.load(.acquire) == 0 and ticks < 40) : (ticks += 1) {
                        w.writeAll("d") catch break :script;
                        w.flush() catch break :script;
                        p.io.sleep(.fromMilliseconds(ms), .awake) catch break :script;
                    }
                },
                .many_blocks => |n| {
                    const prefix = "{\"id\":\"msg_big\",\"model\":\"m\",\"role\":\"assistant\",\"content\":[";
                    const block = "{\"type\":\"text\",\"text\":\"x\"}";
                    const suffix = "],\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
                    const len = prefix.len + n * block.len + (n - 1) + suffix.len;
                    w.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{len}) catch break :script;
                    w.writeAll(prefix) catch break :script;
                    for (0..n) |i| {
                        if (i != 0) w.writeAll(",") catch break :script;
                        w.writeAll(block) catch break :script;
                    }
                    w.writeAll(suffix) catch break :script;
                    w.flush() catch break :script;
                },
                .big_group => |g| {
                    const len = g.lines * ("data: ".len + g.width + 1) + 1;
                    w.print("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{len}) catch break :script;
                    for (0..g.lines) |_| {
                        w.writeAll("data: ") catch break :script;
                        w.splatByteAll('[', g.width) catch break :script;
                        w.writeAll("\n") catch break :script;
                    }
                    w.writeAll("\n") catch break :script;
                    w.flush() catch break :script;
                },
                .long_error => |n| {
                    w.print("HTTP/1.1 500 Internal Server Error\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{n}) catch break :script;
                    w.splatByteAll('e', n) catch break :script;
                    w.flush() catch break :script;
                },
            }
        }
    }
};

const Loopback = struct {
    threaded: std.Io.Threaded,
    listener: std.Io.net.Server,
    peer: FakePeer,
    thread: std.Thread,
    http_client: http.Client,
    url_buf: [64]u8 = undefined,

    fn start(self: *Loopback, scripts: []const Script) !void {
        self.threaded = std.Io.Threaded.init(testing.allocator, .{});
        errdefer self.threaded.deinit();
        const io = self.threaded.io();
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        self.listener = addr.listen(io, .{}) catch return error.SkipZigTest;
        errdefer self.listener.deinit(io);
        self.peer = .{ .io = io, .listener = &self.listener, .scripts = scripts };
        self.thread = try std.Thread.spawn(.{}, FakePeer.run, .{&self.peer});
        self.http_client = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 5000 });
    }

    fn client(self: *Loopback) !Client {
        const port = self.listener.socket.address.getPort();
        const base_url = try std.fmt.bufPrint(&self.url_buf, "http://127.0.0.1:{d}", .{port});
        var c: Client = .init(&self.http_client, "sk-ant-api03-TEST-CANARY");
        c.base_url = base_url;
        return c;
    }

    fn finish(self: *Loopback) void {
        self.peer.stop.store(1, .release);
        // A test that failed before making every connection its scripts
        // expect leaves the peer parked in `accept`; a failed test must
        // report, not hang the suite in `join`. Dial once per script so
        // every remaining `accept` returns (the script's `readHead` then
        // sees EOF and moves on).
        const io = self.threaded.io();
        for (self.peer.scripts) |_| {
            const s = self.listener.socket.address.connect(io, .{ .mode = .stream }) catch break;
            s.close(io);
        }
        self.thread.join();
        self.http_client.deinit();
        self.listener.deinit(self.threaded.io());
        self.threaded.deinit();
    }
};

const canned_request: MessageRequest = .{
    .max_tokens = 16,
    .messages = &.{types.MessageParam.user(&.{types.textBlock("audit canary prompt")})},
};

test "Client.create/stream: a 3xx is UnexpectedStatus and is never followed — the key goes to base_url and nowhere else (A1 F1)" {
    // Measured before the fix: a 307 from `base_url` sent `x-api-key` and
    // the whole prompt to the host in `Location:` and `create` returned OK.
    // `http.Client` strips `Authorization`/`Cookie` across origins, not
    // `x-api-key` (it cannot know the name). Now no hop is made at all:
    // one dial, the 3xx body in `lastErrorBody`.
    var lb: Loopback = undefined;
    // Port 1 is unbindable: had the redirect been followed, the dial would
    // fail loudly (ConnectFailed → HttpFailed), not silently succeed.
    try lb.start(&.{ .{ .redirect = 1 }, .{ .redirect = 1 } });
    defer lb.finish();
    var c = try lb.client();

    try testing.expectError(error.UnexpectedStatus, c.create(testing.allocator, canned_request));
    try testing.expectEqualStrings("redirect", c.lastErrorBody().?);
    try testing.expectEqual(@as(usize, 1), lb.http_client.dialCount());

    try testing.expectError(error.UnexpectedStatus, c.stream(testing.allocator, canned_request));
    try testing.expectEqualStrings("redirect", c.lastErrorBody().?);
    try testing.expectEqual(@as(usize, 2), lb.http_client.dialCount());
}

test "Client.create / EventIterator.next: a body that trickles in is Timeout after read_timeout_ms, not whenever the peer feels like it (A1 F4)" {
    // Measured before the fix with total_timeout_ms = 2000: 30 007 ms on
    // `create`, 60 013 ms on a stream, both ended by the peer.
    var lb: Loopback = undefined;
    try lb.start(&.{ .{ .drip = 50 }, .{ .drip = 50 } });
    defer lb.finish();
    var c = try lb.client();
    c.read_timeout_ms = 300;

    const t0 = std.Io.Clock.Timestamp.now(lb.threaded.io(), .awake);
    try testing.expectError(error.Timeout, c.create(testing.allocator, canned_request));
    const create_ms = @divTrunc(t0.durationFromNow(lb.threaded.io()).raw.nanoseconds, -std.time.ns_per_ms);
    try testing.expect(create_ms < 3000);

    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    const t1 = std.Io.Clock.Timestamp.now(lb.threaded.io(), .awake);
    try testing.expectError(error.Timeout, it.next());
    const next_ms = @divTrunc(t1.durationFromNow(lb.threaded.io()).raw.nanoseconds, -std.time.ns_per_ms);
    try testing.expect(next_ms < 3000);
}

test "Client.create: a body cheap on the wire and expensive in memory is ResponseTooLarge past max_parsed_bytes (A1 F5)" {
    // 100 000 one-character blocks: ~2.5 MB on the wire, well under the
    // 10 MiB wire cap, and tens of MB as `std.json` nodes. Before the fix a
    // 7.8 MB body of this shape parsed into 310 MiB and returned OK.
    var lb: Loopback = undefined;
    try lb.start(&.{ .{ .many_blocks = 100_000 }, .{ .many_blocks = 100_000 } });
    defer lb.finish();
    var c = try lb.client();

    c.max_parsed_bytes = 4 << 20;
    try testing.expectError(error.ResponseTooLarge, c.create(testing.allocator, canned_request));

    // Positive control: the same body under the default bound is a normal
    // response with every block in it — the peer's shape is well-formed and
    // the refusal above was the bound, not a parse failure.
    c.max_parsed_bytes = 64 << 20;
    var parsed = try c.create(testing.allocator, canned_request);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 100_000), parsed.value.content.len);
}

test "EventIterator.next: an SSE group that never ends is ResponseTooLarge past max_event_bytes, and nothing stays pinned (A1 F3)" {
    // 2000 legal 4000-byte `data:` lines in one group (8 MB) — the shape
    // that turned 10 MB of wire into 2.4 GB live and kept it after the
    // error.
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .big_group = .{ .lines = 2000, .width = 4000 } }});
    defer lb.finish();
    var c = try lb.client();
    c.max_event_bytes = 64 << 10;

    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expectError(error.ResponseTooLarge, it.next());
    try testing.expectEqual(@as(usize, 0), it.parser.data_buf.capacity);
}

test "Client.stream: a non-2xx body longer than the scratch is kept truncated in lastErrorBody, not dropped (A1 F10)" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .long_error = 2000 }});
    defer lb.finish();
    var c = try lb.client();
    try testing.expectError(error.UnexpectedStatus, c.stream(testing.allocator, canned_request));
    const body = c.lastErrorBody().?;
    try testing.expectEqual(@as(usize, error_scratch_len), body.len);
    try testing.expect(std.mem.allEqual(u8, body, 'e'));
}

test "BoundedAllocator: refuses past the limit, credits frees back, and flags the refusal" {
    var b: BoundedAllocator = .{ .child = testing.allocator, .limit = 100 };
    const a = b.allocator();
    const x = try a.alloc(u8, 60);
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 41));
    try testing.expect(b.exceeded);
    b.exceeded = false;
    const y = try a.alloc(u8, 40);
    try testing.expectEqual(@as(usize, 100), b.used);
    a.free(x);
    try testing.expectEqual(@as(usize, 40), b.used);
    a.free(y);
    try testing.expectEqual(@as(usize, 0), b.used);
    try testing.expect(!b.exceeded);
}

// Real network call against the live API — skipped unconditionally.
//
// This module is pure Zig (no libc), and 0.16's `std.process.Environ`
// (the only way to read `ANTHROPIC_API_KEY` from the environment) is
// only reachable through `main`'s `Init` parameter, not from inside a
// plain `test` block — unlike `http.Client`'s gated "live:" tests, which
// need no credentials and so don't hit this problem. Exercise this path
// manually via a real `main`/CLI wired up with a key from `Init`, using
// the exact shape below.
test "live: create a minimal message (manual only — see doc comment)" {
    // `if (false)` still type-checks `liveCreateExample` (so a real API
    // change here would fail `zig build test-llmclient`), but never
    // actually runs it.
    if (false) try liveCreateExample(testing.allocator, undefined, "");
    return error.SkipZigTest;
}

/// The real shape a caller with an `Init`-sourced API key would use —
/// referenced (compiled + type-checked) only from the dead branch above.
fn liveCreateExample(gpa: std.mem.Allocator, io: std.Io, api_key: []const u8) !void {
    var transport = http.Client.init(io, gpa, .{
        .connect_timeout_ms = 4000,
        .total_timeout_ms = 20000,
    });
    defer transport.deinit();
    var client: Client = .init(&transport, api_key);

    var parsed = try client.create(gpa, .{
        .max_tokens = 16,
        .messages = &.{types.MessageParam.user(&.{types.textBlock("Reply with exactly: ok")})},
    });
    defer parsed.deinit();
}
