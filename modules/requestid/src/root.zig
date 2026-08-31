// SPDX-License-Identifier: MIT

//! requestid — request / correlation ID as a `router` middleware.
//!
//! Every request gets a stable ID for log correlation and cross-service
//! tracing. The middleware, per request:
//!
//! 1. If the incoming request carries the correlation header (`X-Request-Id`
//!    by default) and `trust_incoming` is set, **adopts** that value (the
//!    edge/ingress already assigned it — keep the chain intact). A malformed
//!    or over-long incoming value is not trusted; a fresh one is generated.
//! 2. Otherwise **generates** one.
//! 3. Echoes the ID back on the response under the same header, and makes it
//!    available to handlers and the access log via `requestid.current()`.
//!
//! It deliberately does NOT use `Ctx.data` (that single slot belongs to an
//! auth middleware like `aaa-gate`/`jwt`) — the ID is exposed through
//! `current()` instead, so request-ID composes with authentication on the
//! same routes. Register it **first** (outermost) so every response, including
//! 401/404 short-circuits, carries the ID.
//!
//! ## Generated IDs
//!
//! The default generator produces a unique-per-request 32-hex-char token from
//! the monotonic clock, a per-connection-thread nonce and a per-thread
//! counter — no allocation and no OS entropy call, fully portable. It is a
//! **correlation** ID (unique for tracing), NOT an unpredictable security
//! token: do not use it where unguessability matters. If you need CSPRNG IDs,
//! adopt an edge-assigned header (`trust_incoming`) or set the header yourself.
//!
//! ## Memory / concurrency
//!
//! An adopted ID borrows the request head (stable for the response). A
//! generated ID lives in thread-local storage (the server is
//! task-per-connection: one request at a time per thread, so the buffer is
//! valid until the response is flushed and only reused by the *next* request
//! on that thread). `current()` reads that thread-local, so it is meaningful
//! only from the connection thread handling the request the middleware ran on.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Request/correlation-ID middleware — adopts incoming `X-Request-Id` or generates one, echoes on response, exposed via `current()`",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // Per-request state lives in thread-local storage owned by the connection
    // task; the immutable config is only read.
    .concurrency = .threadsafe,
    .model_after = "X-Request-Id / correlation-id middleware (nginx request_id, Envoy x-request-id)",
    .deps = .{ "router", "http" },
};

/// Default correlation header (case-insensitive on read; emitted verbatim).
pub const default_header = "X-Request-Id";

/// Length of a generated ID (hex characters).
pub const generated_len = 32;

/// Longest incoming value that will be adopted; a longer one is regenerated.
pub const max_adopt_len = 200;

pub const Options = struct {
    /// The correlation header read and written. Default `X-Request-Id`.
    header_name: []const u8 = default_header,
    /// Adopt a valid incoming header value instead of always generating.
    trust_incoming: bool = true,
    /// Echo the ID back on the response. Off ⇒ the ID is only exposed via
    /// `current()` (e.g. for logging) and not sent to the client.
    echo: bool = true,
};

/// Config + the middleware over it. Immutable; share one across threads.
pub const RequestId = struct {
    options: Options = .{},

    pub fn middleware(ri: *const RequestId) router.Middleware {
        return .{ .state = @constCast(ri), .run = middlewareRun };
    }
};

// Per-connection-thread request-scoped storage (see the module doc).
threadlocal var id_buf: [generated_len]u8 = undefined;
threadlocal var current_id: []const u8 = &.{};
threadlocal var counter: u64 = 0;

/// The current request's ID, or null if no `RequestId` middleware has run on
/// this thread yet. Call it from the connection thread during the request.
pub fn current() ?[]const u8 {
    return if (current_id.len == 0) null else current_id;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const ri: *const RequestId = @ptrCast(@alignCast(state.?));

    const id: []const u8 = blk: {
        if (ri.options.trust_incoming) {
            if (ctx.req.header(ri.options.header_name)) |incoming| {
                if (isAdoptable(incoming)) break :blk incoming; // stable: request head
            }
        }
        break :blk generateInto(&id_buf);
    };
    current_id = id;

    if (ri.options.echo) try ctx.res.setHeader(ri.options.header_name, id);
    return next.run(ctx);
}

/// An incoming ID is adopted only when it is non-empty, within
/// `max_adopt_len`, and every byte is a token-safe character.
///
/// `pub`, with `generateInto`, for servers that pass request state
/// explicitly instead of running the middleware — an engine whose
/// connections are fibers that migrate between threads cannot use
/// `current()`'s thread-local, but the adopt-or-generate policy is the
/// same. Continued:
/// `[A-Za-z0-9._-]`, the same charset nginx's own `$request_id` (hex) and
/// most upstream correlation-id conventions produce. This is narrower than
/// "printable ASCII, no space": the wider set still let a crafted
/// `X-Request-Id` carry `"`, `\`, `,`, `{`, `}` and other structured-log
/// metacharacters straight through to `current()` — no header/log-*line*
/// injection (CR/LF/NUL were always rejected), but a caller that reflects
/// `current()` into an unescaped JSON/logfmt sink could still get a malformed
/// record from an adopted ID (wave-2 audit `requestid` F1). Otherwise a fresh
/// ID is generated.
pub fn isAdoptable(v: []const u8) bool {
    if (v.len == 0 or v.len > max_adopt_len) return false;
    for (v) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }
    return true;
}

/// Write a unique 32-hex-char ID into `buf` and return it. Composition:
/// 16 hex of monotonic ns · 4 hex of a per-thread nonce · 12 hex of a
/// per-thread counter — unique without any OS-entropy call (see module doc).
///
/// `pub` for explicit-state servers (see `isAdoptable`); safe from a fiber,
/// unlike `current()`: the thread-locals here are the generator's own
/// counter and nonce, consumed within this call — nothing request-scoped
/// survives it, so a task that later resumes on another thread keeps only
/// the caller-owned `buf`.
pub fn generateInto(buf: *[generated_len]u8) []const u8 {
    counter +%= 1;
    const ns = monoNs();
    // The address of a thread-local distinguishes threads (each has its own
    // TLS block). It does NOT make a collision impossible, which this
    // comment used to claim: TLS blocks are laid out at a fixed stride, so
    // bits 4..19 of their addresses form an arithmetic progression with a
    // short period — measured at 128 distinct nonces across 300 live
    // threads on x86-64 Linux. `monoNs` is not a tiebreak either (two
    // threads read the same nanosecond in ~2.6% of concurrent samples), and
    // `counter` starts at 1 on every thread, so under
    // one-thread-per-connection the first request of two connections can
    // match on all three. Duplicate ids merge two traces; that is the cost,
    // and it is a correlation-quality cost only — the module already
    // disclaims security use, and nothing here is a uniqueness guarantee.
    const nonce: u16 = @truncate(@intFromPtr(&counter) >> 4);
    const printed = std.fmt.bufPrint(buf, "{x:0>16}{x:0>4}{x:0>12}", .{
        ns, nonce, counter & 0xffffffffffff,
    }) catch unreachable; // exactly 32 chars fit
    return printed;
}

fn monoNs() u64 {
    switch (builtin.os.tag) {
        .windows => {
            var qpf: std.os.windows.LARGE_INTEGER = undefined;
            var qpc: std.os.windows.LARGE_INTEGER = undefined;
            if (!std.os.windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!std.os.windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
            const freq: u64 = @bitCast(qpf);
            const count: u64 = @bitCast(qpc);
            return @intCast(@as(u128, count) * std.time.ns_per_s / freq);
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
        },
    }
}

// ── tests (offline — through http.Server.serveStream) ───────────────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

/// Header value of `name` (case-insensitive) from a raw response, or null.
fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

/// Handler that echoes `current()` into the body so tests can assert it
/// matches the response header (proving handler-visible correlation).
fn hEchoCurrent(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll(current() orelse "<none>");
}

test "generates an ID, echoes it, and current() matches" {
    var ri = RequestId{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    const hdr = headerValue(got, "X-Request-Id").?;
    try testing.expectEqual(@as(usize, generated_len), hdr.len);
    for (hdr) |c| try testing.expect(std.ascii.isHex(c));
    // The handler saw the same ID via current().
    try testing.expectEqualStrings(hdr, bodyOf(got));
}

test "two requests get different generated IDs" {
    var ri = RequestId{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var b1: [1024]u8 = undefined;
    var b2: [1024]u8 = undefined;
    const id1 = headerValue(runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &b1), "X-Request-Id").?;
    const id2 = headerValue(runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &b2), "X-Request-Id").?;
    try testing.expect(!std.mem.eql(u8, id1, id2));
}

test "adopts a valid incoming ID" {
    var ri = RequestId{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "X-Request-Id: edge-abc-123\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("edge-abc-123", headerValue(got, "X-Request-Id").?);
    try testing.expectEqualStrings("edge-abc-123", bodyOf(got));
}

test "isAdoptable: DEL (0x7f) and high-bit bytes are rejected" {
    try testing.expect(!isAdoptable("abc\x7fdef"));
    try testing.expect(!isAdoptable("abc\xffdef"));
    try testing.expect(!isAdoptable("")); // empty is never adoptable
}

test "isAdoptable: only the token-safe charset is adopted (F1 regression)" {
    // Regression for the wave-2 audit's F1: the old guard was "printable
    // ASCII, no space", which let `"`, `\`, `,`, `{`, `}` and other
    // structured-log metacharacters through an incoming X-Request-Id and out
    // through `current()` unescaped. The charset is now `[A-Za-z0-9._-]`,
    // matching nginx's own $request_id output.
    try testing.expect(isAdoptable("edge-abc_123.456")); // hyphen/underscore/dot: fine
    try testing.expect(isAdoptable("0123456789abcdef0123456789abcdef")); // hex, nginx's shape
    try testing.expect(!isAdoptable("abc\x7edef")); // '~' is printable ASCII but not token-safe
    try testing.expect(!isAdoptable("id,injected"));
    try testing.expect(!isAdoptable("id\"injected\""));
    try testing.expect(!isAdoptable("id\\injected"));
    try testing.expect(!isAdoptable("id{injected}"));
    try testing.expect(!isAdoptable("id injected")); // space, already rejected before the fix
}

test "adopt length boundary: exactly max_adopt_len is adopted, one over is regenerated" {
    var ri = RequestId{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var req_buf: [1024]u8 = undefined;
    var resp_buf: [1024]u8 = undefined;

    // Exactly max_adopt_len ('a' * 200): must be adopted verbatim.
    {
        const val: [max_adopt_len]u8 = @splat('a');
        const req = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{val}) catch unreachable;
        const got = runWire(&r, req, &resp_buf);
        try testing.expectEqualStrings(&val, headerValue(got, "X-Request-Id").?);
    }
    // One byte over max_adopt_len: rejected, a fresh generated ID is used instead.
    {
        const val: [max_adopt_len + 1]u8 = @splat('a');
        const req = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{val}) catch unreachable;
        const got = runWire(&r, req, &resp_buf);
        const hdr = headerValue(got, "X-Request-Id").?;
        try testing.expectEqual(@as(usize, generated_len), hdr.len);
        try testing.expect(!std.mem.eql(u8, &val, hdr));
    }
}

test "regenerates when the incoming ID is malformed (spaces) or trust is off" {
    // Malformed incoming (contains a space) → not adopted, a fresh one is used.
    {
        var ri = RequestId{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(ri.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "X-Request-Id: has spaces\r\nConnection: close\r\n\r\n", &buf);
        const hdr = headerValue(got, "X-Request-Id").?;
        try testing.expectEqual(@as(usize, generated_len), hdr.len);
    }
    // trust_incoming = false → the incoming value is ignored even if valid.
    {
        var ri = RequestId{ .options = .{ .trust_incoming = false } };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(ri.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "X-Request-Id: edge-xyz\r\nConnection: close\r\n\r\n", &buf);
        try testing.expect(!std.mem.eql(u8, "edge-xyz", headerValue(got, "X-Request-Id").?));
    }
}

test "echo=false omits the response header but keeps current()" {
    var ri = RequestId{ .options = .{ .echo = false } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "X-Request-Id"));
    try testing.expectEqual(@as(usize, generated_len), bodyOf(got).len); // current() still set
}

test "custom header name" {
    var ri = RequestId{ .options = .{ .header_name = "X-Correlation-Id" } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "X-Correlation-Id: trace-42\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("trace-42", headerValue(got, "X-Correlation-Id").?);
}
