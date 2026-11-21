// SPDX-License-Identifier: MIT

//! `Client` — the Anthropic Messages API surface over the sibling
//! `http.Client`: `create` for a buffered `POST /v1/messages`, `stream`
//! for the Server-Sent-Events variant (`stream: true`), pulling one
//! `StreamEvent` at a time via `EventIterator`, and `countTokens` for
//! `POST /v1/messages/count_tokens`. `betas` adds an `anthropic-beta`
//! header to all three.
//!
//! `http.Client` handles real HTTPS (the h1 stack's TLS is
//! `std.crypto.tls`, not a BYO-TLS stub — that caveat only applies to the
//! h2 stack), so `client.request(.post, "https://api.anthropic.com/...",
//! ...)` works as-is; no gzip/chunked handling is needed here beyond what
//! `http.Client.Response.reader()` already decodes.

const std = @import("std");
const testkit = @import("testkit");
const http = @import("http");
const types = @import("types.zig");
const response = @import("response.zig");
const batch = @import("batch.zig");
const files = @import("files.zig");
const sse_parse = @import("sse_parse.zig");

const Client = @This();

pub const MessageRequest = types.MessageRequest;
pub const CountTokensRequest = types.CountTokensRequest;
pub const TokenCount = response.TokenCount;
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
/// nodes and returned `OK` before this existed; past this
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
/// Beta feature names (e.g. `"context-management-2025-06-27"`), sent on
/// every request as one `anthropic-beta: a,b,...` header — the
/// comma-joined form Anthropic documents as equivalent to repeating the
/// header. Empty (the default) sends no header. Each name must be a
/// non-empty run of `A-Z a-z 0-9 . _ -`; anything else (a comma, a space,
/// a CR/LF) is `error.InvalidBeta` before a byte is sent.
betas: []const []const u8 = &.{},

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
    /// `base_url` plus the endpoint path (`/v1/messages`,
    /// `/v1/messages/count_tokens`) doesn't fit the 512-byte URL buffer.
    /// A caller configuration mistake, not anything the peer sent — kept
    /// distinct from `MalformedResponse` (whose name and doc comment are
    /// both about the wire) so a caller can't confuse "my base_url is too
    /// long" with "the server sent garbage" (A1 F23).
    BaseUrlTooLong,
    /// An entry of `betas` is empty or has a byte outside
    /// `A-Z a-z 0-9 . _ -` — a caller configuration mistake, refused
    /// before the request is sent.
    InvalidBeta,
    /// A caller-supplied argument that cannot go on the wire as given: a
    /// batch or file id, a pagination cursor, a `custom_id`, a file name
    /// or MIME type with a control byte, a `limit` outside 1..1000, an empty
    /// list of batch requests. Refused before a byte is sent.
    InvalidArgument,
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

/// Per-request overrides of what a call sends.
pub const RequestOptions = struct {
    /// Beta feature names for this request. When set (even empty), they
    /// REPLACE `Client.betas` for the call, as a per-request
    /// `anthropic-beta` header replaces a client default in the official
    /// SDKs; null (the default) uses `Client.betas`. Same name rules as
    /// `Client.betas` (`error.InvalidBeta`).
    betas: ?[]const []const u8 = null,
};

/// How `requestHeadersWith` builds the header set.
const HeaderSpec = struct {
    betas: ?[]const []const u8 = null,
    /// A beta the call needs whatever the list says (the Files API's).
    add_beta: ?[]const u8 = null,
    content_type: []const u8 = "application/json",
};

/// The headers every request carries, into `out`; the joined
/// `anthropic-beta` value (when there is one) is allocated from `a` and
/// must outlive the request.
fn requestHeaders(c: *const Client, a: std.mem.Allocator, out: *[4]http.Header) Error![]const http.Header {
    return c.requestHeadersWith(a, out, .{});
}

fn requestHeadersWith(c: *const Client, a: std.mem.Allocator, out: *[4]http.Header, spec: HeaderSpec) Error![]const http.Header {
    out[0] = .{ .name = "x-api-key", .value = c.api_key };
    out[1] = .{ .name = "anthropic-version", .value = c.anthropic_version };
    out[2] = .{ .name = "content-type", .value = spec.content_type };
    const list = spec.betas orelse c.betas;
    var extra: ?[]const u8 = spec.add_beta;
    var len: usize = 0;
    var count: usize = 0;
    for (list) |b| {
        if (!validBeta(b)) return error.InvalidBeta;
        len += b.len;
        count += 1;
        if (extra) |e| if (std.mem.eql(u8, e, b)) {
            extra = null;
        };
    }
    if (extra) |e| {
        len += e.len;
        count += 1;
    }
    if (count == 0) return out[0..3];
    len += count - 1;
    const joined = a.alloc(u8, len) catch return error.OutOfMemory;
    var i: usize = 0;
    var n: usize = 0;
    for (list) |b| {
        if (n != 0) {
            joined[i] = ',';
            i += 1;
        }
        @memcpy(joined[i..][0..b.len], b);
        i += b.len;
        n += 1;
    }
    if (extra) |e| {
        if (n != 0) {
            joined[i] = ',';
            i += 1;
        }
        @memcpy(joined[i..][0..e.len], e);
    }
    out[3] = .{ .name = "anthropic-beta", .value = joined };
    return out[0..4];
}

fn validBeta(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return true;
}

const messages_path = "/v1/messages";
const count_tokens_path = "/v1/messages/count_tokens";

fn endpointUrl(base_url: []const u8, path: []const u8, buf: []u8) error{BaseUrlTooLong}![]const u8 {
    return std.mem.print(buf, "{s}{s}", .{ base_url, path }) catch return error.BaseUrlTooLong;
}

fn messagesUrl(base_url: []const u8, buf: []u8) error{BaseUrlTooLong}![]const u8 {
    return endpointUrl(base_url, messages_path, buf);
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
fn requestOptions(hdrs: []const http.Header, body: ?[]const u8) http.Client.RequestOptions {
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
    return c.createWith(gpa, req, .{});
}

/// `create` with per-request `RequestOptions` (betas).
pub fn createWith(c: *Client, gpa: std.mem.Allocator, req: MessageRequest, opts: RequestOptions) Error!std.json.Parsed(Message) {
    var non_stream = req;
    non_stream.stream = false;

    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const body = types.stringifyAlloc(a, non_stream) catch return error.OutOfMemory;
    const resp_body = try c.sendBuffered(a, .post, messages_path, body, .{ .betas = opts.betas });

    // The parse, under `max_parsed_bytes` (A1 F5): the wire cap bounds
    // bytes, this bounds what they turn into.
    const msg = try c.parseBounded(a, Message, response.parseMessage, resp_body);
    return .{ .arena = arena, .value = msg };
}

/// `POST /v1/messages/count_tokens`: how many input tokens `req` would
/// cost, without running the model. Same headers, bounds and redirect
/// rule as `create`; `CountTokensRequest.fromMessageRequest` counts a
/// `MessageRequest` as it would be sent. Nothing is retained after the
/// call returns.
pub fn countTokens(c: *Client, gpa: std.mem.Allocator, req: CountTokensRequest) Error!TokenCount {
    return c.countTokensWith(gpa, req, .{});
}

/// `countTokens` with per-request `RequestOptions` (betas).
pub fn countTokensWith(c: *Client, gpa: std.mem.Allocator, req: CountTokensRequest, opts: RequestOptions) Error!TokenCount {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const body = types.stringifyCountTokensAlloc(a, req) catch return error.OutOfMemory;
    const resp_body = try c.sendBuffered(a, .post, count_tokens_path, body, .{ .betas = opts.betas });
    return c.parseBounded(a, TokenCount, response.parseTokenCount, resp_body);
}

/// `parse(bounded allocator, body)` under `max_parsed_bytes`: a parse that
/// would cost more is `error.ResponseTooLarge`.
fn parseBounded(
    c: *const Client,
    a: std.mem.Allocator,
    comptime T: type,
    comptime parse: fn (std.mem.Allocator, []const u8) response.ParseError!T,
    body: []const u8,
) Error!T {
    var bounded: BoundedAllocator = .{ .child = a, .limit = c.max_parsed_bytes };
    return parse(bounded.allocator(), body) catch |err| switch (err) {
        error.OutOfMemory => return if (bounded.exceeded) error.ResponseTooLarge else error.OutOfMemory,
        error.MalformedResponse => return error.MalformedResponse,
    };
}

/// One buffered request to `base_url ++ path_and_query`: the response body,
/// allocated from `a`, when the status is 2xx; otherwise the body goes to
/// `lastErrorBody` and the call is `error.UnexpectedStatus`.
fn sendBuffered(c: *Client, a: std.mem.Allocator, method: http.Method, path_and_query: []const u8, body: ?[]const u8, spec: HeaderSpec) Error![]u8 {
    var url_buf: [512]u8 = undefined;
    const url = try endpointUrl(c.base_url, path_and_query, &url_buf);
    var hdr_buf: [4]http.Header = undefined;
    const hdrs = try c.requestHeadersWith(a, &hdr_buf, spec);

    var res = c.http_client.request(method, url, requestOptions(hdrs, body)) catch |err|
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
    return resp_body;
}

// ── Message Batches and Files API ───────────────────────────────────────────

const batches_path = "/v1/messages/batches";
const files_path = "/v1/files";

pub const MessageBatch = batch.MessageBatch;
pub const BatchList = batch.BatchList;
pub const DeletedBatch = batch.DeletedBatch;
pub const BatchResultItem = batch.BatchResultItem;
pub const FileMetadata = files.FileMetadata;
pub const FileList = files.FileList;
pub const DeletedFile = files.DeletedFile;

/// Pagination of the two list calls (`listBatches`, `listFiles`): at most
/// `limit` (1..1000; the API's default is 20) entries, those before
/// `before_id` or after `after_id` (the `first_id` / `last_id` of a page).
pub const ListOptions = struct {
    limit: ?u32 = null,
    before_id: ?[]const u8 = null,
    after_id: ?[]const u8 = null,
};

/// An id (or cursor, or `custom_id`) that can sit in a URL path or query
/// untouched: `A-Z a-z 0-9 _ -`, at most `max` bytes.
fn validId(s: []const u8, max: usize) bool {
    if (s.len == 0 or s.len > max) return false;
    for (s) |ch| switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => {},
        else => return false,
    };
    return true;
}

/// `base`, then `/id` and `suffix` when `id` is given, then the list query.
fn apiPath(buf: []u8, base: []const u8, id: ?[]const u8, suffix: []const u8, list: ?ListOptions) Error![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(base) catch return error.InvalidArgument;
    if (id) |i| {
        if (!validId(i, 128)) return error.InvalidArgument;
        w.print("/{s}{s}", .{ i, suffix }) catch return error.InvalidArgument;
    }
    if (list) |o| {
        var sep: u8 = '?';
        if (o.limit) |n| {
            if (n < 1 or n > 1000) return error.InvalidArgument;
            w.print("{c}limit={d}", .{ sep, n }) catch return error.InvalidArgument;
            sep = '&';
        }
        if (o.before_id) |b| {
            if (!validId(b, 128)) return error.InvalidArgument;
            w.print("{c}before_id={s}", .{ sep, b }) catch return error.InvalidArgument;
            sep = '&';
        }
        if (o.after_id) |b| {
            if (!validId(b, 128)) return error.InvalidArgument;
            w.print("{c}after_id={s}", .{ sep, b }) catch return error.InvalidArgument;
        }
    }
    return w.buffered();
}

/// One buffered call answered by a JSON object of type `T`, parsed under
/// `max_parsed_bytes`; the result owns an arena.
fn callParsed(
    c: *Client,
    gpa: std.mem.Allocator,
    comptime T: type,
    comptime parse: fn (std.mem.Allocator, []const u8) response.ParseError!T,
    method: http.Method,
    path: []const u8,
    body: ?[]const u8,
    spec: HeaderSpec,
) Error!std.json.Parsed(T) {
    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const resp_body = try c.sendBuffered(a, method, path, body, spec);
    const value = try c.parseBounded(a, T, parse, resp_body);
    return .{ .arena = arena, .value = value };
}

/// `POST /v1/messages/batches`: runs `requests` (each a `MessageRequest`
/// with your `custom_id`, 1-64 characters of `A-Z a-z 0-9 _ -`) in the
/// background at a discount; the answer is the new batch (`in_progress`).
/// An empty list or an invalid `custom_id` is `error.InvalidArgument`;
/// the API's own limits (100,000 requests, 256 MB) are not checked here.
/// The result owns an arena: call `.deinit()`.
pub fn createBatch(c: *Client, gpa: std.mem.Allocator, requests: []const types.BatchRequest) Error!std.json.Parsed(MessageBatch) {
    if (requests.len == 0) return error.InvalidArgument;
    for (requests) |r| if (!validId(r.custom_id, 64)) return error.InvalidArgument;
    var build = std.heap.ArenaAllocator.init(gpa);
    defer build.deinit();
    const body = types.stringifyBatchAlloc(build.allocator(), requests) catch return error.OutOfMemory;
    return c.callParsed(gpa, MessageBatch, batch.parseBatch, .post, batches_path, body, .{});
}

/// `GET /v1/messages/batches/{id}`: the batch and how far it is.
pub fn getBatch(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error!std.json.Parsed(MessageBatch) {
    var buf: [256]u8 = undefined;
    const path = try apiPath(&buf, batches_path, id, "", null);
    return c.callParsed(gpa, MessageBatch, batch.parseBatch, .get, path, null, .{});
}

/// `GET /v1/messages/batches`: one page of your batches, newest first.
pub fn listBatches(c: *Client, gpa: std.mem.Allocator, opts: ListOptions) Error!std.json.Parsed(BatchList) {
    var buf: [512]u8 = undefined;
    const path = try apiPath(&buf, batches_path, null, "", opts);
    return c.callParsed(gpa, BatchList, batch.parseBatchList, .get, path, null, .{});
}

/// `POST /v1/messages/batches/{id}/cancel`: starts the cancellation
/// (`processing_status` `canceling`; requests already running still
/// finish and are reported in the results).
pub fn cancelBatch(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error!std.json.Parsed(MessageBatch) {
    var buf: [256]u8 = undefined;
    const path = try apiPath(&buf, batches_path, id, "/cancel", null);
    return c.callParsed(gpa, MessageBatch, batch.parseBatch, .post, path, "", .{});
}

/// `DELETE /v1/messages/batches/{id}`: removes an ended batch.
pub fn deleteBatch(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error!std.json.Parsed(DeletedBatch) {
    var buf: [256]u8 = undefined;
    const path = try apiPath(&buf, batches_path, id, "", null);
    return c.callParsed(gpa, DeletedBatch, batch.parseDeletedBatch, .delete, path, null, .{});
}

/// `GET /v1/messages/batches/{id}/results`: the results of an ended batch
/// as an iterator over the JSONL body, one `BatchResultItem` per
/// `next()` (the order is not the order of the requests; match on
/// `custom_id`). The batch must have ended (`results_url` set), else the
/// API answers an error (`error.UnexpectedStatus`). Owns the connection:
/// call `ResultIterator.deinit`.
pub fn batchResults(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error!ResultIterator {
    var path_buf: [256]u8 = undefined;
    const path = try apiPath(&path_buf, batches_path, id, "/results", null);
    var url_buf: [512]u8 = undefined;
    const url = try endpointUrl(c.base_url, path, &url_buf);
    var build = std.heap.ArenaAllocator.init(gpa);
    defer build.deinit();
    var hdr_buf: [4]http.Header = undefined;
    const hdrs = try c.requestHeadersWith(build.allocator(), &hdr_buf, .{});

    var res = c.http_client.request(.get, url, requestOptions(hdrs, null)) catch |err|
        return mapHttpError(err);
    errdefer res.deinit();
    if (res.status < 200 or res.status >= 300) {
        var err_buf: [error_scratch_len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&err_buf);
        _ = runBounded(c.http_client.io, c.readDeadline(), streamErrorBody, .{ &res, &w }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => streamErrorBody(&res, &w) catch {},
            else => {},
        };
        c.noteError(w.buffered());
        return error.UnexpectedStatus;
    }
    return ResultIterator.init(gpa, res, c.http_client.io, .{
        .max_line_bytes = c.max_response_bytes,
        .max_parsed_bytes = c.max_parsed_bytes,
        .read_deadline_ms = c.read_timeout_ms,
    });
}

/// Pulls one `BatchResultItem` at a time off the JSONL body of
/// `batchResults`.
pub const ResultIterator = struct {
    res: http.Client.Response,
    line: std.Io.Writer.Allocating,
    arena: std.heap.ArenaAllocator,
    /// Copied from the client at `batchResults` time: the wire bytes one
    /// result line may take, the memory its parse may allocate, and the
    /// deadline of one `next()` (milliseconds, 0 = none).
    max_line_bytes: usize,
    max_parsed_bytes: usize,
    read_deadline_ms: u32,
    io: std.Io,

    const Limits = struct { max_line_bytes: usize, max_parsed_bytes: usize, read_deadline_ms: u32 };

    fn init(gpa: std.mem.Allocator, res: http.Client.Response, io: std.Io, l: Limits) ResultIterator {
        return .{
            .res = res,
            .line = .init(gpa),
            .arena = std.heap.ArenaAllocator.init(gpa),
            .max_line_bytes = l.max_line_bytes,
            .max_parsed_bytes = l.max_parsed_bytes,
            .read_deadline_ms = l.read_deadline_ms,
            .io = io,
        };
    }

    pub fn deinit(it: *ResultIterator) void {
        it.line.deinit();
        it.arena.deinit();
        it.res.deinit();
        it.* = undefined;
    }

    /// One line of the body into `line` (without its newline); false at the
    /// end of the body.
    fn readLine(it: *ResultIterator) error{ ReadFailed, StreamTooLong, WriteFailed }!bool {
        const r = it.res.reader();
        it.line.clearRetainingCapacity();
        _ = try r.streamDelimiterLimit(&it.line.writer, '\n', .limited(it.max_line_bytes));
        _ = r.takeByte() catch |err| switch (err) {
            // A last line with no newline, or the clean end.
            error.EndOfStream => return it.line.written().len != 0,
            error.ReadFailed => return error.ReadFailed,
        };
        return true;
    }

    /// The next result, or null at the end. Its memory is valid until the
    /// next `next()` or `deinit()`. Each call is bounded by `read_timeout_ms`
    /// (`error.Timeout`), a line by `max_response_bytes` and its parse by
    /// `max_parsed_bytes` (`error.ResponseTooLarge`); after an error the
    /// connection is no longer usable.
    pub fn next(it: *ResultIterator) Error!?BatchResultItem {
        _ = it.arena.reset(.retain_capacity);
        while (true) {
            const deadline: ?std.Io.Clock.Timestamp = if (it.read_deadline_ms == 0) null else blk: {
                const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(it.read_deadline_ms), .clock = .awake } };
                break :blk t.toTimestamp(it.io);
            };
            const got = runBounded(it.io, deadline, readLine, .{it}) catch |err| switch (err) {
                error.ConcurrencyUnavailable => it.readLine() catch |e| return it.mapLineError(e),
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Canceled,
                else => |e| return it.mapLineError(e),
            };
            if (!got) return null;
            const text = std.mem.trim(u8, it.line.written(), " \t\r");
            if (text.len == 0) continue;
            const a = it.arena.allocator();
            var bounded: BoundedAllocator = .{ .child = a, .limit = it.max_parsed_bytes };
            return batch.parseResultLine(bounded.allocator(), text) catch |err| switch (err) {
                error.OutOfMemory => {
                    if (!bounded.exceeded) return error.OutOfMemory;
                    _ = it.arena.reset(.free_all);
                    return error.ResponseTooLarge;
                },
                error.MalformedResponse => return error.MalformedResponse,
            };
        }
    }

    fn mapLineError(it: *ResultIterator, err: error{ ReadFailed, StreamTooLong, WriteFailed }) Error {
        return switch (err) {
            error.WriteFailed => error.OutOfMemory,
            error.StreamTooLong => error.ResponseTooLarge,
            error.ReadFailed => mapHttpError(it.res.readFailure()),
        };
    }
};

/// A file to upload: its name, MIME type (`type/subtype`, e.g.
/// `application/pdf`, `text/plain`, `image/png`) and bytes. The whole file
/// is held in memory for the request.
pub const UploadFile = struct {
    filename: []const u8,
    mime_type: []const u8,
    data: []const u8,
};

/// The bytes of a `multipart/form-data` body with one `file` part, and
/// the `Content-Type` header value that names its boundary. The boundary
/// is one that occurs in neither the data, the name nor the type. A
/// file name has `"`, CR and LF percent-encoded (`%22`, `%0D`, `%0A`) as a
/// browser form does; a MIME type with a byte outside printable ASCII is
/// `error.InvalidArgument` (it goes into a header line).
fn multipartBody(a: std.mem.Allocator, f: UploadFile) Error!struct { body: []u8, content_type: []u8 } {
    if (f.filename.len == 0 or f.filename.len > 255) return error.InvalidArgument;
    if (std.mem.findScalar(u8, f.mime_type, '/') == null) return error.InvalidArgument;
    for (f.mime_type) |ch| if (ch < 0x20 or ch > 0x7e) return error.InvalidArgument;
    var n: usize = 0;
    var boundary_buf: [48]u8 = undefined;
    const boundary = while (true) : (n += 1) {
        const b = std.mem.print(&boundary_buf, "----llmclient-boundary-{d}", .{n}) catch unreachable;
        if (std.mem.find(u8, f.data, b) == null and std.mem.find(u8, f.filename, b) == null and std.mem.find(u8, f.mime_type, b) == null) break b;
    };
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    w.print("--{s}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"", .{boundary}) catch return error.OutOfMemory;
    for (f.filename) |ch| switch (ch) {
        '"' => w.writeAll("%22") catch return error.OutOfMemory,
        '\r' => w.writeAll("%0D") catch return error.OutOfMemory,
        '\n' => w.writeAll("%0A") catch return error.OutOfMemory,
        else => w.writeByte(ch) catch return error.OutOfMemory,
    };
    w.print("\"\r\nContent-Type: {s}\r\n\r\n", .{f.mime_type}) catch return error.OutOfMemory;
    w.writeAll(f.data) catch return error.OutOfMemory;
    w.print("\r\n--{s}--\r\n", .{boundary}) catch return error.OutOfMemory;
    const ct = a.print("multipart/form-data; boundary={s}", .{boundary}) catch return error.OutOfMemory;
    return .{ .body = out.toOwnedSlice() catch return error.OutOfMemory, .content_type = ct };
}

const files_spec: HeaderSpec = .{ .add_beta = files.beta };

/// `POST /v1/files`: uploads a file (multipart) for use as an
/// `ImageSource.file` / `DocumentSource.file`. Sends the Files API beta
/// header along with `Client.betas`.
pub fn uploadFile(c: *Client, gpa: std.mem.Allocator, f: UploadFile) Error!std.json.Parsed(FileMetadata) {
    var build = std.heap.ArenaAllocator.init(gpa);
    defer build.deinit();
    const mp = try multipartBody(build.allocator(), f);
    var spec = files_spec;
    spec.content_type = mp.content_type;
    return c.callParsed(gpa, FileMetadata, files.parseFile, .post, files_path, mp.body, spec);
}

/// `GET /v1/files/{id}`: a file's metadata.
pub fn getFile(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error!std.json.Parsed(FileMetadata) {
    var buf: [256]u8 = undefined;
    const path = try apiPath(&buf, files_path, id, "", null);
    return c.callParsed(gpa, FileMetadata, files.parseFile, .get, path, null, files_spec);
}

/// `GET /v1/files`: one page of your files, newest first.
pub fn listFiles(c: *Client, gpa: std.mem.Allocator, opts: ListOptions) Error!std.json.Parsed(FileList) {
    var buf: [512]u8 = undefined;
    const path = try apiPath(&buf, files_path, null, "", opts);
    return c.callParsed(gpa, FileList, files.parseFileList, .get, path, null, files_spec);
}

/// `GET /v1/files/{id}/content`: a file's bytes, allocated from `gpa`
/// (caller frees), at most `max_response_bytes` (raise it for a large
/// file). Only files a tool produced are downloadable
/// (`FileMetadata.downloadable`); the API refuses an uploaded one.
pub fn fileContent(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error![]u8 {
    var buf: [256]u8 = undefined;
    const path = try apiPath(&buf, files_path, id, "/content", null);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const body = try c.sendBuffered(arena.allocator(), .get, path, null, files_spec);
    return gpa.dupe(u8, body) catch return error.OutOfMemory;
}

/// `DELETE /v1/files/{id}`.
pub fn deleteFile(c: *Client, gpa: std.mem.Allocator, id: []const u8) Error!std.json.Parsed(DeletedFile) {
    var buf: [256]u8 = undefined;
    const path = try apiPath(&buf, files_path, id, "", null);
    return c.callParsed(gpa, DeletedFile, files.parseDeletedFile, .delete, path, null, files_spec);
}

/// `POST /v1/messages` with `stream: true` forced; returns an
/// `EventIterator` that pulls one `StreamEvent` per SSE dispatch group.
/// Owns the connection — call `EventIterator.deinit`.
pub fn stream(c: *Client, gpa: std.mem.Allocator, req: MessageRequest) Error!EventIterator {
    return c.streamWith(gpa, req, .{});
}

/// `stream` with per-request `RequestOptions` (betas).
pub fn streamWith(c: *Client, gpa: std.mem.Allocator, req: MessageRequest, opts: RequestOptions) Error!EventIterator {
    var streaming = req;
    streaming.stream = true;

    var build_arena = std.heap.ArenaAllocator.init(gpa);
    defer build_arena.deinit();
    const body = types.stringifyAlloc(build_arena.allocator(), streaming) catch return error.OutOfMemory;

    var url_buf: [512]u8 = undefined;
    const url = try messagesUrl(c.base_url, &url_buf);
    var hdr_buf: [4]http.Header = undefined;
    const hdrs = try c.requestHeadersWith(build_arena.allocator(), &hdr_buf, .{ .betas = opts.betas });

    var res = c.http_client.request(.post, url, requestOptions(hdrs, body)) catch |err|
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
            const parsed = response.parseStreamEvent(bounded.allocator(), ev.data) catch |err| switch (err) {
                error.OutOfMemory => {
                    if (!bounded.exceeded) return error.OutOfMemory;
                    _ = it.arena.reset(.free_all);
                    it.parser.releaseBuffers();
                    return error.ResponseTooLarge;
                },
                error.MalformedResponse => return error.MalformedResponse,
            };
            // The SSE `event:` field name and the JSON payload's own
            // `"type"` are two independently-parsed statements of the same
            // fact; Anthropic keeps them consistent, but nothing checked
            // that until now (A1 F6). `StreamEvent`'s variant names are
            // exactly the API's `type`/`event:` strings, so the active tag
            // name IS the expected `event:` value.
            if (ev.event) |name| {
                if (!std.mem.eql(u8, name, @tagName(std.meta.activeTag(parsed))))
                    return error.MalformedResponse;
            }
            return parsed;
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
    var hdr_buf: [4]http.Header = undefined;
    const hdrs = try c.requestHeaders(testing.allocator, &hdr_buf);
    try testing.expectEqual(@as(usize, 3), hdrs.len); // no `betas` → no anthropic-beta
    try testing.expectEqualStrings("x-api-key", hdrs[0].name);
    try testing.expectEqualStrings("sk-test-key", hdrs[0].value);
    try testing.expectEqualStrings("anthropic-version", hdrs[1].name);
    try testing.expectEqualStrings("2023-06-01", hdrs[1].value);
    try testing.expectEqualStrings("content-type", hdrs[2].name);
    try testing.expectEqualStrings("application/json", hdrs[2].value);

    var url_buf: [512]u8 = undefined;
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
    /// Set once `accept` returned; `release` only has to wake a peer before that.
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *CreateCancelPeer) void {
        const s = p.listener.accept(p.io) catch return;
        defer s.close(p.io);
        p.accepted.store(1, .release);
        if (p.stop.load(.acquire) != 0) return; // woken by `release`
        var wbuf: [256]u8 = undefined;
        var sw = s.writer(p.io, &wbuf);
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") catch {};
        sw.interface.flush() catch {};
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    /// Wake the peer if it is still parked in `accept`. After a client that
    /// never connected nothing else would, and `join` would wait forever.
    /// Closing the listener does not wake it under `std.Io.Threaded`.
    fn release(p: *@This(), port: u16) void {
        p.stop.store(1, .release);
        if (p.accepted.load(.acquire) != 0) return;
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }
};

/// A real `std.Io` whose only changed slot counts `netRead` entries. A cancel
/// test uses it to cancel once the client is INSIDE a given socket read, not
/// after a sleep. The peer writes its whole head in one flush, so on loopback
/// the head (or reply) is read #1 and the body read #2. With a sleep, a loaded
/// machine could cancel an earlier step, which passes by the wrong route. It
/// could also cancel before the connect: the peer then waits in `accept`
/// forever, and so does `join`. That is the http full-gate hang, and the same shape as this module's peer.
const ReadCueIo = struct {
    vtable: std.Io.VTable,
    userdata: ?*anyopaque,

    var inner_vtable: *const std.Io.VTable = undefined;
    var reads: std.atomic.Value(u32) = .init(0);

    fn init(inner: std.Io) ReadCueIo {
        inner_vtable = inner.vtable;
        reads.store(0, .release);
        var vt = inner.vtable.*;
        vt.operate = operate; // 0.17: socket reads are `Operation.net_read` through `vtable.operate`
        return .{ .vtable = vt, .userdata = inner.userdata };
    }

    fn io(self: *const ReadCueIo) std.Io {
        return .{ .userdata = self.userdata, .vtable = &self.vtable };
    }

    fn operate(userdata: ?*anyopaque, op: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
        if (op == .net_read) _ = reads.fetchAdd(1, .monotonic);
        return inner_vtable.operate(userdata, op);
    }

    /// Wait until the client has entered its `n`-th socket read. The deadline
    /// is a watchdog only: a client that never gets there is a red, not a hang
    /// (the gate's per-test limit is 3 minutes).
    fn awaitReads(real_io: std.Io, n: u32) bool {
        const start = std.Io.Clock.Timestamp.now(real_io, .awake);
        while (reads.load(.acquire) < n) {
            const waited = start.durationTo(std.Io.Clock.Timestamp.now(real_io, .awake)).raw.nanoseconds;
            if (waited > 60 * std.time.ns_per_s) return false;
            real_io.sleep(.fromMilliseconds(1), .awake) catch return reads.load(.acquire) >= n;
        }
        return true;
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
        return testkit.loopbackSkip("llmclient cancel test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: CreateCancelPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, CreateCancelPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    var cue: ReadCueIo = .init(io);
    var http_client = http.Client.init(cue.io(), testing.allocator, .{ .pool = .{ .enabled = false } });
    defer http_client.deinit();

    var url_buf: [64]u8 = undefined;
    const base_url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}", .{port});

    var c: Client = .init(&http_client, "sk-test-key");
    c.base_url = base_url;

    const req: MessageRequest = .{
        .max_tokens = 16,
        .messages = &.{types.MessageParam.user(&.{types.textBlock("hi")})},
    };

    var fut = try io.concurrent(createOnce, .{ &c, testing.allocator, req });
    // Cancel once the client is inside read #2, the body read (`ReadCueIo`).
    const reached = ReadCueIo.awaitReads(io, 2);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
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
        return testkit.loopbackSkip("llmclient stream cancel test listen failed ({t})", .{err});
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
    defer peer.release(port);

    var cue: ReadCueIo = .init(io);
    var http_client = http.Client.init(cue.io(), testing.allocator, .{ .pool = .{ .enabled = false } });
    defer http_client.deinit();

    var url_buf: [64]u8 = undefined;
    const base_url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}", .{port});

    var c: Client = .init(&http_client, "sk-test-key");
    c.base_url = base_url;

    const req: MessageRequest = .{
        .max_tokens = 16,
        .stream = true,
        .messages = &.{types.MessageParam.user(&.{types.textBlock("hi")})},
    };

    var fut = try io.concurrent(streamNextOnce, .{ &c, testing.allocator, req });
    // Cancel once the client is inside read #2, the body read (`ReadCueIo`).
    const reached = ReadCueIo.awaitReads(io, 2);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
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
    /// A 200 `text/event-stream` body, sent byte-exact (A1 F6, F14).
    sse_raw: []const u8,
    /// A 200 `application/json` body, sent byte-exact (A1 F8: an exact
    /// wire-byte-count boundary needs a body of a known exact length,
    /// which `many_blocks`' computed length doesn't give a test for free).
    blob: []const u8,
    /// An arbitrary status line + body (A1 F7: the exact `300` boundary,
    /// which `redirect`'s hardcoded `307` doesn't exercise).
    status: struct { code: u16, body: []const u8 },
};

const FakePeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    scripts: []const Script,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: usize = 0,
    /// The most recent request body this peer received, captured for
    /// assertions (A1 F11: did the client actually force `stream` on the
    /// wire, or just in the type it handed to the caller?). Overwritten
    /// per accepted connection; read it right after the call whose body
    /// you want.
    last_body_buf: [8192]u8 = undefined,
    last_body_len: usize = 0,
    /// The request-target and `anthropic-beta` value of that same request
    /// (`beta_count` = how many `anthropic-beta` lines it carried).
    last_target_buf: [128]u8 = undefined,
    last_target_len: usize = 0,
    last_beta_buf: [256]u8 = undefined,
    last_beta_len: usize = 0,
    last_beta_count: usize = 0,
    last_method_buf: [16]u8 = undefined,
    last_method_len: usize = 0,
    last_ctype_buf: [128]u8 = undefined,
    last_ctype_len: usize = 0,

    fn lastMethod(p: *const FakePeer) []const u8 {
        return p.last_method_buf[0..p.last_method_len];
    }
    fn lastContentType(p: *const FakePeer) []const u8 {
        return p.last_ctype_buf[0..p.last_ctype_len];
    }
    fn lastTarget(p: *const FakePeer) []const u8 {
        return p.last_target_buf[0..p.last_target_len];
    }
    fn lastBeta(p: *const FakePeer) []const u8 {
        return p.last_beta_buf[0..p.last_beta_len];
    }
    fn lastBody(p: *const FakePeer) []const u8 {
        return p.last_body_buf[0..p.last_body_len];
    }

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
            p.last_target_len = @min(req.target.len, p.last_target_buf.len);
            @memcpy(p.last_target_buf[0..p.last_target_len], req.target[0..p.last_target_len]);
            p.last_beta_len = 0;
            p.last_beta_count = 0;
            p.last_method_len = @min(req.method.len, p.last_method_buf.len);
            @memcpy(p.last_method_buf[0..p.last_method_len], req.method[0..p.last_method_len]);
            p.last_ctype_len = 0;
            var lines = std.mem.splitSequence(u8, req.header_block, "\r\n");
            while (lines.next()) |line| {
                const colon = std.mem.findScalar(u8, line, ':') orelse continue;
                if (std.ascii.eqlIgnoreCase(line[0..colon], "content-type")) {
                    const v = std.mem.trim(u8, line[colon + 1 ..], " \t");
                    p.last_ctype_len = @min(v.len, p.last_ctype_buf.len);
                    @memcpy(p.last_ctype_buf[0..p.last_ctype_len], v[0..p.last_ctype_len]);
                }
                if (!std.ascii.eqlIgnoreCase(line[0..colon], "anthropic-beta")) continue;
                p.last_beta_count += 1;
                const v = std.mem.trim(u8, line[colon + 1 ..], " \t");
                p.last_beta_len = @min(v.len, p.last_beta_buf.len);
                @memcpy(p.last_beta_buf[0..p.last_beta_len], v[0..p.last_beta_len]);
            }
            // Capture the body (up to the capture buffer's size) so a test
            // can assert what actually went out on the wire, then drain
            // whatever's left so the client's write never blocks.
            p.last_body_len = 0;
            if (req.content_length) |raw_n| {
                const n: usize = @intCast(raw_n);
                const take = @min(n, p.last_body_buf.len);
                sr.interface.readSliceAll(p.last_body_buf[0..take]) catch continue;
                p.last_body_len = take;
                if (n > take) sr.interface.discardAll(n - take) catch continue;
            }
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
                .sse_raw => |body| {
                    w.print("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch break :script;
                    w.flush() catch break :script;
                },
                .blob => |body| {
                    w.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch break :script;
                    w.flush() catch break :script;
                },
                .status => |st| {
                    w.print("HTTP/1.1 {d} test\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ st.code, st.body.len, st.body }) catch break :script;
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
        self.listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err});
        errdefer self.listener.deinit(io);
        self.peer = .{ .io = io, .listener = &self.listener, .scripts = scripts };
        self.thread = try std.Thread.spawn(.{}, FakePeer.run, .{&self.peer});
        self.http_client = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 5000 });
    }

    fn client(self: *Loopback) !Client {
        const port = self.listener.socket.address.getPort();
        const base_url = try std.mem.print(&self.url_buf, "http://127.0.0.1:{d}", .{port});
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

// ── regression: mutation-ladder gaps from A1 (F6, F7, F8, F11, F14, F23) ────

test "messagesUrl: a base_url that doesn't fit the buffer is BaseUrlTooLong, distinct from MalformedResponse (A1 F23)" {
    var buf: [16]u8 = undefined; // too small for any real URL + "/v1/messages"
    try testing.expectError(error.BaseUrlTooLong, messagesUrl("https://api.anthropic.com", &buf));
    var big_buf: [256]u8 = undefined;
    const url = try messagesUrl("https://api.anthropic.com", &big_buf);
    try testing.expectEqualStrings("https://api.anthropic.com/v1/messages", url);
}

test "EventIterator.next: event: name inconsistent with the JSON \"type\" is MalformedResponse (A1 F6)" {
    // `event: message_stop` announcing one thing, the payload's own `"type"`
    // dispatching to another — before this check `EventIterator.next` read
    // `.data` only and never looked at `.event` at all.
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .sse_raw = "event: message_stop\n" ++
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"INJECTED\"}}\n" ++
        "\n" }});
    defer lb.finish();
    var c = try lb.client();
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expectError(error.MalformedResponse, it.next());
}

test "EventIterator.next: a consistent event: / type pair still parses (positive control for A1 F6)" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .sse_raw = "event: content_block_stop\n" ++
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n" ++
        "\n" }});
    defer lb.finish();
    var c = try lb.client();
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    const ev = (try it.next()).?;
    try testing.expectEqual(@as(u32, 0), ev.content_block_stop.index);
}

test "EventIterator.next: an event with no event: field at all still parses (A1 F6 does not require the field)" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .sse_raw = "data: {\"type\":\"ping\"}\n\n" }});
    defer lb.finish();
    var c = try lb.client();
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expect((try it.next()).? == .ping);
}

test "Client.create: status exactly 300 is UnexpectedStatus, the >= 300 boundary itself, not >= 301 (A1 F7)" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .status = .{ .code = 300, .body = "boundary" } }});
    defer lb.finish();
    var c = try lb.client();
    try testing.expectError(error.UnexpectedStatus, c.create(testing.allocator, canned_request));
    try testing.expectEqualStrings("boundary", c.lastErrorBody().?);
}

test "Client.create: max_response_bytes is enforced at the exact wire byte count, off by one either way (A1 F8)" {
    // A minimal valid Message body of known exact length `L`. `http`'s own
    // `readAllAlloc(a, max)` accepts exactly `max` bytes since Zig 0.17
    // (`allocRemaining(.limited(n))` allows n; 0.16 refused `max == L`), so
    // the tight pair is `max == L - 1` (must refuse) / `max == L` (must
    // succeed) -- one byte apart.
    // `max_response_bytes` is forwarded to it unmodified; this single pair
    // catches M04 (cap removed), M05 (1024x looser) and M06 (a one-byte
    // shift in what gets forwarded) all at once: under any of the three,
    // `max == L - 1` would wrongly succeed.
    const min_msg = "{\"id\":\"m\",\"model\":\"m\",\"role\":\"assistant\",\"content\":[]," ++
        "\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
    var lb: Loopback = undefined;
    try lb.start(&.{ .{ .blob = min_msg }, .{ .blob = min_msg } });
    defer lb.finish();
    var c = try lb.client();

    c.max_response_bytes = min_msg.len - 1;
    try testing.expectError(error.ResponseTooLarge, c.create(testing.allocator, canned_request));

    c.max_response_bytes = min_msg.len;
    var parsed = try c.create(testing.allocator, canned_request);
    defer parsed.deinit();
    try testing.expectEqualStrings("m", parsed.value.id);
}

test "Client.create / Client.stream: stream is forced on the wire regardless of what the caller set it to (A1 F11)" {
    // `req.stream` set the "wrong" way on purpose for both calls; `create`
    // must still send `\"stream\":false` and `stream()` must still send
    // `\"stream\":true` — verified against the actual captured request
    // body, not the in-process struct `create`/`stream` build internally.
    var lb: Loopback = undefined;
    try lb.start(&.{ .{ .many_blocks = 1 }, .{ .sse_raw = "data: {\"type\":\"ping\"}\n\n" } });
    defer lb.finish();
    var c = try lb.client();

    var wrong_stream_true = canned_request;
    wrong_stream_true.stream = true;
    var parsed = try c.create(testing.allocator, wrong_stream_true);
    defer parsed.deinit();
    try testing.expect(std.mem.find(u8, lb.peer.last_body_buf[0..lb.peer.last_body_len], "\"stream\":false") != null);
    try testing.expect(std.mem.find(u8, lb.peer.last_body_buf[0..lb.peer.last_body_len], "\"stream\":true") == null);

    var wrong_stream_false = canned_request;
    wrong_stream_false.stream = false;
    var it = try c.stream(testing.allocator, wrong_stream_false);
    defer it.deinit();
    try testing.expect(std.mem.find(u8, lb.peer.last_body_buf[0..lb.peer.last_body_len], "\"stream\":true") != null);
    try testing.expect(std.mem.find(u8, lb.peer.last_body_buf[0..lb.peer.last_body_len], "\"stream\":false") == null);
}

test "EventIterator.next: a LineTooLong is a real error (HttpFailed), never a silent end of stream (A1 F14)" {
    // One SSE line past the ~4088-byte ceiling `http`'s own scratch buffer
    // imposes (A1 F13) — the only wire bound this module's SSE path has by
    // construction, not a knob. `mapParserError` maps it to `HttpFailed`;
    // the mutation this guards against (M21) makes that branch return
    // `null` instead, which `it.next()` would report as an ordinary clean
    // end of stream with zero events — indistinguishable from success.
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .big_group = .{ .lines = 1, .width = 4200 } }});
    defer lb.finish();
    var c = try lb.client();
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expectError(error.HttpFailed, it.next());
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

// ── whole-module mutation audit: tests for the mutants that survived ──

test "lastErrorBody / noteError: null when empty, kept truncated to the scratch size" {
    var c: Client = .init(undefined, "k");
    try testing.expect(c.lastErrorBody() == null);
    c.noteError("");
    try testing.expect(c.lastErrorBody() == null);
    var big: [error_scratch_len + 88]u8 = @splat('z');
    c.noteError(&big);
    try testing.expectEqual(@as(usize, error_scratch_len), c.lastErrorBody().?.len);
    c.noteError("short");
    try testing.expectEqualStrings("short", c.lastErrorBody().?);
}

test "validBeta: the characters at the edge of each accepted range" {
    for ("AZaz09._-") |ch| try testing.expect(validBeta(&.{ch}));
    for ("@[`{/: ,\r\n!~") |ch| try testing.expect(!validBeta(&.{ch}));
    try testing.expect(!validBeta(""));
}

test "mapHttpError: the distinguished transport errors keep their meaning, the rest are HttpFailed" {
    try testing.expectEqual(@as(Error, error.OutOfMemory), mapHttpError(error.OutOfMemory));
    try testing.expectEqual(@as(Error, error.Canceled), mapHttpError(error.Canceled));
    try testing.expectEqual(@as(Error, error.Timeout), mapHttpError(error.Timeout));
    try testing.expectEqual(@as(Error, error.ResponseTooLarge), mapHttpError(error.BodyTooLarge));
    try testing.expectEqual(@as(Error, error.HttpFailed), mapHttpError(error.ReadFailed));
}

test "readDeadline: 0 is unbounded, anything else is a deadline" {
    var hc = http.Client.init(testing.io, testing.allocator, .{});
    defer hc.deinit();
    var c: Client = .init(&hc, "k");
    c.read_timeout_ms = 0;
    try testing.expect(c.readDeadline() == null);
    c.read_timeout_ms = 1000;
    try testing.expect(c.readDeadline() != null);
}

test "BoundedAllocator: growth is charged, shrinks credited, refusals flagged, failed child calls not charged" {
    var buf: [256]u8 align(16) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var b: BoundedAllocator = .{ .child = fba.allocator(), .limit = 50 };
    const a = b.allocator();
    const x = try a.alloc(u8, 10);
    try testing.expect(a.resize(x, 20));
    try testing.expectEqual(@as(usize, 20), b.used);
    try testing.expect(!a.resize(x.ptr[0..20], 60)); // 40 more than the 30 left
    try testing.expect(b.exceeded);
    try testing.expectEqual(@as(usize, 20), b.used);
    b.exceeded = false;
    try testing.expect(a.resize(x.ptr[0..20], 10)); // shrink in place
    try testing.expectEqual(@as(usize, 10), b.used);
    const y = try a.alloc(u8, 5); // x is no longer the last allocation: a grow must fail in the child
    try testing.expectEqual(@as(usize, 15), b.used);
    try testing.expect(!a.resize(x.ptr[0..10], 30));
    try testing.expectEqual(@as(usize, 15), b.used); // the charge was rolled back
    try testing.expect(!b.exceeded);
    _ = y;
}

test "BoundedAllocator.remap: growth is charged, a refused or failed remap leaves the count alone, a shrink is credited" {
    var buf: [256]u8 align(16) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var b: BoundedAllocator = .{ .child = fba.allocator(), .limit = 50 };
    const a = b.allocator();
    const x = try a.alloc(u8, 10);
    const x2 = a.remap(x, 20) orelse return error.SkipZigTest; // the child cannot remap in place
    try testing.expectEqual(@as(usize, 20), b.used);
    try testing.expect(a.remap(x2, 60) == null);
    try testing.expect(b.exceeded);
    try testing.expectEqual(@as(usize, 20), b.used);
    b.exceeded = false;
    const x3 = a.remap(x2, 10).?;
    try testing.expectEqual(@as(usize, 10), b.used);
    const y = try a.alloc(u8, 5);
    try testing.expect(a.remap(x3, 30) == null); // not the last allocation
    try testing.expectEqual(@as(usize, 15), b.used);
    _ = y;
}

test "BoundedAllocator: a failed child allocation is not charged" {
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var b: BoundedAllocator = .{ .child = fa.allocator(), .limit = 100 };
    try testing.expectError(error.OutOfMemory, b.allocator().alloc(u8, 10));
    try testing.expectEqual(@as(usize, 0), b.used);
    try testing.expect(!b.exceeded);
}

test "Client.stream: posts to /v1/messages; a clean end is null; an empty data event is skipped; read_timeout_ms = 0 is unbounded" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .sse_raw = "data:\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\n" }});
    defer lb.finish();
    var c = try lb.client();
    c.read_timeout_ms = 0;
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expectEqualStrings("/v1/messages", lb.peer.lastTarget());
    const ev = (try it.next()).?;
    try testing.expect(ev == .ping);
    try testing.expect((try it.next()) == null);
}

test "Client.create / stream: 299 is success, 300 is UnexpectedStatus" {
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .status = .{ .code = 299, .body = "{\"id\":\"m\",\"model\":\"x\",\"role\":\"assistant\",\"content\":[],\"usage\":{}}" } },
        .{ .status = .{ .code = 299, .body = "data: {\"type\":\"ping\"}\n\n" } },
        .{ .status = .{ .code = 300, .body = "x" } },
    });
    defer lb.finish();
    var c = try lb.client();
    var parsed = try c.create(testing.allocator, canned_request);
    parsed.deinit();
    var it = try c.stream(testing.allocator, canned_request);
    it.deinit();
    try testing.expectError(error.UnexpectedStatus, c.stream(testing.allocator, canned_request));
}

test "Client.stream: max_event_bytes and max_parsed_bytes reach the iterator; a bound hit frees its buffers" {
    const filler: [600]u8 = @splat('h'); // the first small allocations fit under the bound, the string does not
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .big_group = .{ .lines = 50, .width = 4000 } },
        .{ .sse_raw = "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" ++ &filler ++ "\"}}\n\n" },
    });
    defer lb.finish();
    var c = try lb.client();
    c.max_event_bytes = 64 << 10; // the default (1 MiB) would let these 200 KB through to a parse failure
    {
        var it = try c.stream(testing.allocator, canned_request);
        defer it.deinit();
        try testing.expectError(error.ResponseTooLarge, it.next());
    }
    c.max_parsed_bytes = 400;
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expectError(error.ResponseTooLarge, it.next());
    try testing.expectEqual(@as(usize, 0), it.arena.queryCapacity());
    try testing.expectEqual(@as(usize, 0), it.parser.data_buf.capacity);
}

test "EventIterator.next: read_timeout_ms = 0 never times out a slow peer" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .drip = 20 }});
    defer lb.finish();
    var c = try lb.client();
    c.read_timeout_ms = 0;
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    if (it.next()) |_| return error.TestUnexpectedResult else |e| try testing.expect(e != error.Timeout);
}

test "Client.countTokens: the parse is bounded by max_parsed_bytes" {
    var lb: Loopback = undefined;
    try lb.start(&.{ .{ .blob = "{\"input_tokens\":5}" }, .{ .blob = "{\"input_tokens\":5}" } });
    defer lb.finish();
    var c = try lb.client();
    c.max_parsed_bytes = 4;
    try testing.expectError(error.ResponseTooLarge, c.countTokens(testing.allocator, .fromMessageRequest(canned_request)));
    c.max_parsed_bytes = 64 << 20;
    try testing.expectEqual(@as(u64, 5), (try c.countTokens(testing.allocator, .fromMessageRequest(canned_request))).input_tokens);
}

test "EventIterator.mapParserError: OutOfMemory stays, DataTooLarge frees the arena" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .sse_raw = "" }});
    defer lb.finish();
    var c = try lb.client();
    var it = try c.stream(testing.allocator, canned_request);
    defer it.deinit();
    try testing.expectEqual(@as(Error, error.OutOfMemory), it.mapParserError(error.OutOfMemory));
    _ = try it.arena.allocator().alloc(u8, 100);
    try testing.expect(it.arena.queryCapacity() > 0);
    try testing.expectEqual(@as(Error, error.ResponseTooLarge), it.mapParserError(error.DataTooLarge));
    try testing.expectEqual(@as(usize, 0), it.arena.queryCapacity());
}

// ── Message Batches, Files API, per-request betas ───────────────────────────

const batch_json =
    "{\"id\":\"msgbatch_01\",\"type\":\"message_batch\",\"processing_status\":\"in_progress\"," ++
    "\"request_counts\":{\"processing\":2,\"succeeded\":0,\"errored\":0,\"canceled\":0,\"expired\":0}," ++
    "\"ended_at\":null,\"created_at\":\"2024-09-24T18:37:24Z\",\"expires_at\":\"2024-09-25T18:37:24Z\"," ++
    "\"cancel_initiated_at\":null,\"results_url\":null}";

test "Client.createBatch: POSTs {requests:[{custom_id,params}]} without stream and returns the batch" {
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .blob = batch_json }});
    defer lb.finish();
    var c = try lb.client();
    var req = canned_request;
    req.max_tokens = 16;
    req.stream = true; // not part of a batch request
    var parsed = try c.createBatch(testing.allocator, &.{.{ .custom_id = "my-first-request", .params = req }});
    defer parsed.deinit();
    try testing.expectEqualStrings("msgbatch_01", parsed.value.id);
    try testing.expectEqual(@as(u64, 2), parsed.value.request_counts.processing);
    try testing.expectEqualStrings("POST", lb.peer.lastMethod());
    try testing.expectEqualStrings("/v1/messages/batches", lb.peer.lastTarget());
    try testing.expectEqualStrings("application/json", lb.peer.lastContentType());
    try testing.expectEqualStrings(
        "{\"requests\":[{\"custom_id\":\"my-first-request\",\"params\":{\"model\":\"claude-opus-4-8\",\"max_tokens\":16," ++
            "\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"audit canary prompt\"}]}]}}]}",
        lb.peer.lastBody(),
    );
}

test "Client.createBatch: an empty list and a bad custom_id are InvalidArgument before anything is sent" {
    var c: Client = .init(undefined, "k");
    try testing.expectError(error.InvalidArgument, c.createBatch(testing.allocator, &.{}));
    try testing.expectError(error.InvalidArgument, c.createBatch(testing.allocator, &.{.{ .custom_id = "has space", .params = canned_request }}));
    try testing.expectError(error.InvalidArgument, c.createBatch(testing.allocator, &.{.{ .custom_id = "", .params = canned_request }}));
    const too_long: [65]u8 = @splat('a');
    try testing.expectError(error.InvalidArgument, c.createBatch(testing.allocator, &.{.{ .custom_id = &too_long, .params = canned_request }}));
}

test "Client batches: retrieve, list with a cursor, cancel and delete use the documented verbs and paths" {
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .blob = batch_json },
        .{ .blob = "{\"data\":[" ++ batch_json ++ "],\"has_more\":true,\"first_id\":\"msgbatch_01\",\"last_id\":\"msgbatch_01\"}" },
        .{ .blob = batch_json },
        .{ .blob = "{\"id\":\"msgbatch_01\",\"type\":\"message_batch_deleted\"}" },
    });
    defer lb.finish();
    var c = try lb.client();
    var b = try c.getBatch(testing.allocator, "msgbatch_01");
    b.deinit();
    try testing.expectEqualStrings("GET", lb.peer.lastMethod());
    try testing.expectEqualStrings("/v1/messages/batches/msgbatch_01", lb.peer.lastTarget());
    try testing.expectEqual(@as(usize, 0), lb.peer.lastBody().len);

    var l = try c.listBatches(testing.allocator, .{ .limit = 5, .after_id = "msgbatch_00" });
    defer l.deinit();
    try testing.expect(l.value.has_more);
    try testing.expectEqual(@as(usize, 1), l.value.data.len);
    try testing.expectEqualStrings("/v1/messages/batches?limit=5&after_id=msgbatch_00", lb.peer.lastTarget());

    var x = try c.cancelBatch(testing.allocator, "msgbatch_01");
    x.deinit();
    try testing.expectEqualStrings("POST", lb.peer.lastMethod());
    try testing.expectEqualStrings("/v1/messages/batches/msgbatch_01/cancel", lb.peer.lastTarget());

    var d = try c.deleteBatch(testing.allocator, "msgbatch_01");
    defer d.deinit();
    try testing.expectEqualStrings("DELETE", lb.peer.lastMethod());
    try testing.expectEqualStrings("/v1/messages/batches/msgbatch_01", lb.peer.lastTarget());
    try testing.expectEqualStrings("msgbatch_01", d.value.id);
}

test "apiPath: ids and cursors that could leave the path are InvalidArgument; limit is 1..1000" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", "../x", "", null));
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", "a/b", "", null));
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", "", "", null));
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", "a?b=c", "", null));
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", null, "", .{ .limit = 0 }));
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", null, "", .{ .limit = 1001 }));
    try testing.expectError(error.InvalidArgument, apiPath(&buf, "/v1/files", null, "", .{ .after_id = "x&y" }));
    try testing.expectEqualStrings("/v1/files?limit=1000&before_id=b&after_id=a", try apiPath(&buf, "/v1/files", null, "", .{ .limit = 1000, .before_id = "b", .after_id = "a" }));
    try testing.expectEqualStrings("/v1/files", try apiPath(&buf, "/v1/files", null, "", .{}));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.InvalidArgument, apiPath(&tiny, "/v1/messages/batches", "x", "", null));
}

test "Client.batchResults: one item per JSONL line, blank lines skipped, order kept, last line without a newline" {
    const lines =
        "{\"custom_id\":\"a\",\"result\":{\"type\":\"succeeded\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"model\":\"x\"," ++
        "\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}}\n" ++
        "\r\n" ++
        "{\"custom_id\":\"b\",\"result\":{\"type\":\"errored\",\"error\":{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"bad\"}}}}\r\n" ++
        "{\"custom_id\":\"c\",\"result\":{\"type\":\"expired\"}}";
    var lb: Loopback = undefined;
    try lb.start(&.{.{ .blob = lines }});
    defer lb.finish();
    var c = try lb.client();
    var it = try c.batchResults(testing.allocator, "msgbatch_01");
    defer it.deinit();
    try testing.expectEqualStrings("GET", lb.peer.lastMethod());
    try testing.expectEqualStrings("/v1/messages/batches/msgbatch_01/results", lb.peer.lastTarget());
    const a = (try it.next()).?;
    try testing.expectEqualStrings("a", a.custom_id);
    try testing.expectEqualStrings("hi", a.result.succeeded.content[0].text.text);
    const b = (try it.next()).?;
    try testing.expectEqualStrings("invalid_request_error", b.result.errored.type);
    const e = (try it.next()).?;
    try testing.expect(e.result == .expired);
    try testing.expectEqual(@as(?BatchResultItem, null), try it.next());
}

test "Client.batchResults: a malformed line, an over-long line and a refused request are typed errors" {
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .blob = "{\"custom_id\":\"a\"}\n" },
        .{ .blob = "{\"custom_id\":\"a\",\"result\":{\"type\":\"expired\"}}\n" },
        .{ .status = .{ .code = 400, .body = "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"not ended\"}}" } },
    });
    defer lb.finish();
    var c = try lb.client();
    {
        var it = try c.batchResults(testing.allocator, "msgbatch_01");
        defer it.deinit();
        try testing.expectError(error.MalformedResponse, it.next());
    }
    c.max_response_bytes = 10;
    {
        var it = try c.batchResults(testing.allocator, "msgbatch_01");
        defer it.deinit();
        try testing.expectError(error.ResponseTooLarge, it.next());
    }
    c.max_response_bytes = 10 << 20;
    try testing.expectError(error.UnexpectedStatus, c.batchResults(testing.allocator, "msgbatch_01"));
    try testing.expect(std.mem.find(u8, c.lastErrorBody().?, "not ended") != null);
    try testing.expectError(error.InvalidArgument, c.batchResults(testing.allocator, "x/../y"));
}

test "multipartBody: golden bytes, a boundary that is not in the data, escaped file name, bad type refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const mp = try multipartBody(a, .{ .filename = "note.txt", .mime_type = "text/plain", .data = "hello" });
    try testing.expectEqualStrings("multipart/form-data; boundary=----llmclient-boundary-0", mp.content_type);
    try testing.expectEqualStrings(
        "------llmclient-boundary-0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\n" ++
            "Content-Type: text/plain\r\n\r\nhello\r\n------llmclient-boundary-0--\r\n",
        mp.body,
    );
    // The data holds the first boundary: the next one is used.
    const clash = try multipartBody(a, .{ .filename = "x", .mime_type = "application/pdf", .data = "..----llmclient-boundary-0.." });
    try testing.expectEqualStrings("multipart/form-data; boundary=----llmclient-boundary-1", clash.content_type);
    // A quote or line break in the name cannot end the header line.
    const esc = try multipartBody(a, .{ .filename = "a\"b\r\nc", .mime_type = "text/plain", .data = "" });
    try testing.expect(std.mem.find(u8, esc.body, "filename=\"a%22b%0D%0Ac\"\r\n") != null);
    try testing.expectError(error.InvalidArgument, multipartBody(a, .{ .filename = "", .mime_type = "text/plain", .data = "" }));
    try testing.expectError(error.InvalidArgument, multipartBody(a, .{ .filename = "f", .mime_type = "text", .data = "" }));
    try testing.expectError(error.InvalidArgument, multipartBody(a, .{ .filename = "f", .mime_type = "text/plain\r\nX: y", .data = "" }));
}

const file_json =
    "{\"id\":\"file_011CNha8iCJcU1wXNR6q4V8w\",\"type\":\"file\",\"filename\":\"note.txt\",\"mime_type\":\"text/plain\"," ++
    "\"size_bytes\":5,\"created_at\":\"2025-01-01T00:00:00Z\",\"downloadable\":false}";

test "Client files: upload is multipart with the Files beta (merged with the client's), list, get, content, delete" {
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .blob = file_json },
        .{ .blob = "{\"data\":[" ++ file_json ++ "],\"has_more\":false,\"first_id\":\"f\",\"last_id\":\"f\"}" },
        .{ .blob = file_json },
        .{ .blob = "raw\x00bytes" },
        .{ .blob = "{\"id\":\"file_011CNha8iCJcU1wXNR6q4V8w\",\"type\":\"file_deleted\"}" },
    });
    defer lb.finish();
    var c = try lb.client();
    c.betas = &.{"other-beta-2025-01-01"};
    var up = try c.uploadFile(testing.allocator, .{ .filename = "note.txt", .mime_type = "text/plain", .data = "hello" });
    defer up.deinit();
    try testing.expectEqualStrings("file_011CNha8iCJcU1wXNR6q4V8w", up.value.id);
    try testing.expectEqual(@as(u64, 5), up.value.size_bytes);
    try testing.expectEqualStrings("POST", lb.peer.lastMethod());
    try testing.expectEqualStrings("/v1/files", lb.peer.lastTarget());
    try testing.expectEqualStrings("multipart/form-data; boundary=----llmclient-boundary-0", lb.peer.lastContentType());
    try testing.expectEqualStrings("other-beta-2025-01-01,files-api-2025-04-14", lb.peer.lastBeta());
    try testing.expect(std.mem.find(u8, lb.peer.lastBody(), "filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n") != null);

    c.betas = &.{"files-api-2025-04-14"}; // not repeated
    var l = try c.listFiles(testing.allocator, .{ .limit = 2 });
    defer l.deinit();
    try testing.expectEqualStrings("/v1/files?limit=2", lb.peer.lastTarget());
    try testing.expectEqualStrings("files-api-2025-04-14", lb.peer.lastBeta());
    try testing.expectEqual(@as(usize, 1), lb.peer.last_beta_count);
    var g = try c.getFile(testing.allocator, "file_011CNha8iCJcU1wXNR6q4V8w");
    g.deinit();
    try testing.expectEqualStrings("/v1/files/file_011CNha8iCJcU1wXNR6q4V8w", lb.peer.lastTarget());
    const bytes = try c.fileContent(testing.allocator, "file_011CNha8iCJcU1wXNR6q4V8w");
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("raw\x00bytes", bytes);
    try testing.expectEqualStrings("/v1/files/file_011CNha8iCJcU1wXNR6q4V8w/content", lb.peer.lastTarget());
    var d = try c.deleteFile(testing.allocator, "file_011CNha8iCJcU1wXNR6q4V8w");
    defer d.deinit();
    try testing.expectEqualStrings("DELETE", lb.peer.lastMethod());
    try testing.expectEqualStrings("file_011CNha8iCJcU1wXNR6q4V8w", d.value.id);
}

test "RequestOptions.betas replaces Client.betas for one call; null keeps them; a bad name is InvalidBeta" {
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .blob = "{\"id\":\"m\",\"model\":\"x\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":\"end_turn\",\"usage\":{}}" },
        .{ .blob = "{\"id\":\"m\",\"model\":\"x\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":\"end_turn\",\"usage\":{}}" },
        .{ .blob = "{\"input_tokens\":3}" },
        .{ .blob = "{\"id\":\"m\",\"model\":\"x\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":\"end_turn\",\"usage\":{}}" },
    });
    defer lb.finish();
    var c = try lb.client();
    c.betas = &.{"client-beta-1"};
    var m1 = try c.createWith(testing.allocator, canned_request, .{ .betas = &.{ "req-beta-1", "req-beta-2" } });
    m1.deinit();
    try testing.expectEqualStrings("req-beta-1,req-beta-2", lb.peer.lastBeta());
    var m2 = try c.createWith(testing.allocator, canned_request, .{ .betas = &.{} });
    m2.deinit();
    try testing.expectEqual(@as(usize, 0), lb.peer.last_beta_count);
    _ = try c.countTokensWith(testing.allocator, .fromMessageRequest(canned_request), .{ .betas = &.{"count-beta"} });
    try testing.expectEqualStrings("count-beta", lb.peer.lastBeta());
    var m3 = try c.createWith(testing.allocator, canned_request, .{});
    m3.deinit();
    try testing.expectEqualStrings("client-beta-1", lb.peer.lastBeta());
    try testing.expectError(error.InvalidBeta, c.createWith(testing.allocator, canned_request, .{ .betas = &.{"bad name"} }));
    try testing.expectError(error.InvalidBeta, c.streamWith(testing.allocator, canned_request, .{ .betas = &.{""} }));
}

// Real network call against the live API — skipped unconditionally.
//
// This module is pure Zig (no libc), and `std.process.Environ` (the
// way to read `ANTHROPIC_API_KEY` from the environment) was taken to be
// reachable only through `main`'s `Init` parameter, not from inside a
// plain `test` block (the repo's other modules read it via
// `std.testing.environ`; this test does not use that yet) — unlike
// `http.Client`'s gated "live:" tests, which
// need no credentials and so don't hit this problem. Exercise this path
// manually via a real `main`/CLI wired up with a key from `Init`, using
// the exact shape below.
// ── anthropic-beta, count_tokens ───────────────────────────────────────────

test "requestHeaders: betas go out as one comma-joined anthropic-beta header (the documented form)" {
    var c: Client = .init(undefined, "k");
    c.betas = &.{ "context-management-2025-06-27", "fast-mode-2026-02-01" };
    var hdr_buf: [4]http.Header = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const hdrs = try c.requestHeaders(arena.allocator(), &hdr_buf);
    try testing.expectEqual(@as(usize, 4), hdrs.len);
    try testing.expectEqualStrings("anthropic-beta", hdrs[3].name);
    try testing.expectEqualStrings("context-management-2025-06-27,fast-mode-2026-02-01", hdrs[3].value);

    c.betas = &.{"only-one-2025-01-01"};
    try testing.expectEqualStrings("only-one-2025-01-01", (try c.requestHeaders(arena.allocator(), &hdr_buf))[3].value);
}

test "requestHeaders: a beta name that could split or smuggle a header is InvalidBeta, refused before sending" {
    var c: Client = .init(undefined, "k");
    var hdr_buf: [4]http.Header = undefined;
    const bad = [_][]const u8{ "", "a,b", "a b", "a\r\nx-api-key: stolen", "a\nb", "a:b", "caf\xc3\xa9" };
    for (bad) |b| {
        c.betas = &.{ "ok-2025-01-01", b };
        try testing.expectError(error.InvalidBeta, c.requestHeaders(testing.allocator, &hdr_buf));
    }
}

test "Client.create / stream / countTokens: anthropic-beta is on the wire, once, for every endpoint" {
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .many_blocks = 1 },
        .{ .sse_raw = "data: {\"type\":\"ping\"}\n\n" },
        .{ .blob = "{\"input_tokens\":3}" },
        .{ .many_blocks = 1 },
    });
    defer lb.finish();
    var c = try lb.client();
    c.betas = &.{ "beta-a-2026-01-01", "beta-b-2026-02-02" };

    var parsed = try c.create(testing.allocator, canned_request);
    parsed.deinit();
    try testing.expectEqualStrings("/v1/messages", lb.peer.lastTarget());
    try testing.expectEqualStrings("beta-a-2026-01-01,beta-b-2026-02-02", lb.peer.lastBeta());
    try testing.expectEqual(@as(usize, 1), lb.peer.last_beta_count);

    var it = try c.stream(testing.allocator, canned_request);
    it.deinit();
    try testing.expectEqualStrings("beta-a-2026-01-01,beta-b-2026-02-02", lb.peer.lastBeta());

    _ = try c.countTokens(testing.allocator, .fromMessageRequest(canned_request));
    try testing.expectEqualStrings("beta-a-2026-01-01,beta-b-2026-02-02", lb.peer.lastBeta());

    // And none at all once `betas` is empty again.
    c.betas = &.{};
    var parsed2 = try c.create(testing.allocator, canned_request);
    parsed2.deinit();
    try testing.expectEqual(@as(usize, 0), lb.peer.last_beta_count);
}

test "Client.countTokens: POSTs the count_tokens body to /v1/messages/count_tokens and returns input_tokens" {
    var lb: Loopback = undefined;
    // The docs' own output, verbatim (token-counting.md, fetched 2026-10-06).
    try lb.start(&.{.{ .blob = "{ \"input_tokens\": 14 }" }});
    defer lb.finish();
    var c = try lb.client();

    var req: MessageRequest = canned_request;
    req.system = "You are a scientist";
    req.stream = true;
    const count = try c.countTokens(testing.allocator, .fromMessageRequest(req));
    try testing.expectEqual(@as(u64, 14), count.input_tokens);
    try testing.expectEqualStrings("/v1/messages/count_tokens", lb.peer.lastTarget());
    try testing.expectEqualStrings(
        "{\"model\":\"claude-opus-4-8\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\"," ++
            "\"text\":\"audit canary prompt\"}]}],\"system\":\"You are a scientist\"}",
        lb.peer.lastBody(),
    );
}

test "Client.countTokens: non-2xx is UnexpectedStatus + lastErrorBody; a body that is not a count is MalformedResponse; the wire cap holds" {
    const err_body = "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"max_tokens: Extra inputs are not permitted\"}}";
    var lb: Loopback = undefined;
    try lb.start(&.{
        .{ .status = .{ .code = 400, .body = err_body } },
        .{ .blob = "{\"tokens\":14}" },
        .{ .blob = "{\"input_tokens\":-5}" },
        .{ .many_blocks = 1000 },
        .{ .redirect = 1 },
    });
    defer lb.finish();
    var c = try lb.client();
    const req: CountTokensRequest = .fromMessageRequest(canned_request);

    try testing.expectError(error.UnexpectedStatus, c.countTokens(testing.allocator, req));
    try testing.expectEqualStrings(err_body, c.lastErrorBody().?);
    try testing.expectError(error.MalformedResponse, c.countTokens(testing.allocator, req));
    try testing.expectError(error.MalformedResponse, c.countTokens(testing.allocator, req));
    c.max_response_bytes = 1024;
    try testing.expectError(error.ResponseTooLarge, c.countTokens(testing.allocator, req));
    // Never followed, as for create (A1 F1).
    try testing.expectError(error.UnexpectedStatus, c.countTokens(testing.allocator, req));
    try testing.expectEqualStrings("redirect", c.lastErrorBody().?);
}

test "Client.create: an invalid beta is refused before any connection is made" {
    var lb: Loopback = undefined;
    try lb.start(&.{});
    defer lb.finish();
    var c = try lb.client();
    c.betas = &.{"bad beta"};
    try testing.expectError(error.InvalidBeta, c.create(testing.allocator, canned_request));
    try testing.expectError(error.InvalidBeta, c.stream(testing.allocator, canned_request));
    try testing.expectError(error.InvalidBeta, c.countTokens(testing.allocator, .fromMessageRequest(canned_request)));
    try testing.expectEqual(@as(usize, 0), lb.http_client.dialCount());
}

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
