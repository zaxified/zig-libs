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
//! The default generator produces a 32-hex-char token: a per-process prefix
//! and a process-wide atomic sequence number — unique within the process
//! across all threads, no allocation and no OS entropy call. It is a
//! **correlation** ID (unique for tracing), NOT an unpredictable security
//! token: do not use it where unguessability matters. For another scheme
//! (UUID, ULID, CSPRNG) plug in `Options.generator`, or adopt an
//! edge-assigned header (`trust_incoming`).
//!
//! ## Memory / concurrency
//!
//! An adopted ID is copied, and a generated one written, into thread-local
//! storage (the server is
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
    /// Must be an RFC 9110 token and not a framing header (`Content-Length`,
    /// `Transfer-Encoding`) — `middleware()` panics otherwise, because every
    /// echo would fail and every request with it.
    header_name: []const u8 = default_header,
    /// Adopt a valid incoming header value instead of always generating.
    trust_incoming: bool = true,
    /// Echo the ID back on the response. Off ⇒ the ID is only exposed via
    /// `current()` (e.g. for logging) and not sent to the client.
    echo: bool = true,
    /// Produces an ID when none is adopted. Null ⇒ the built-in 32-hex
    /// generator (`generateInto`). See `Generator` for the contract.
    generator: ?Generator = null,
};

/// A caller-supplied ID scheme (UUIDv4/v7, ULID, a team's own format) —
/// echo's `Generator` and tower-http's `MakeRequestId` offer the same.
///
/// `run` writes into `buf` (thread-local, reused by the next request on the
/// thread) and returns the ID as a sub-slice of it. The result must pass
/// `isAdoptable` — the same shape an incoming ID needs, so `current()` stays
/// safe for an unescaped log sink and the echo never fails on the value
/// (`http` refuses a header value with CR/LF, which would fail the request;
/// a response header table an outer middleware already filled still fails it,
/// like any other header). A result that
/// does not (empty, bad byte, not inside `buf`) is discarded and the
/// built-in generator is used instead.
pub const Generator = struct {
    /// Passed back to `run` verbatim (an `Io`, a PRNG, a prefix…).
    context: ?*anyopaque = null,
    run: *const fn (context: ?*anyopaque, buf: *[max_adopt_len]u8) []const u8,
};

/// Config + the middleware over it. Immutable; share one across threads.
pub const RequestId = struct {
    options: Options = .{},

    /// `ri` must outlive the router. Panics (in every build mode) on a
    /// `header_name` the echo could never set — see `Options.header_name`.
    pub fn middleware(ri: *const RequestId) router.Middleware {
        if (!isUsableHeaderName(ri.options.header_name)) @panic("requestid: Options.header_name is not a usable header name");
        return .{ .state = @constCast(ri), .run = middlewareRun };
    }
};

// Per-connection-thread request-scoped storage (see the module doc). Sized
// for a custom generator's output; the built-in one fills the first 32.
threadlocal var id_buf: [max_adopt_len]u8 = undefined;
threadlocal var current_id: []const u8 = &.{};

/// The ID the `RequestId` middleware last assigned on this thread, or null if
/// it has not run on this thread yet. It stays set after the request (an
/// access log registered *outside* the middleware reads it once the chain
/// returns) until the next request the middleware runs for, so a request
/// that bypasses the middleware sees the previous one's ID: register it
/// first. The bytes are always this thread's own copy — before 2026-10-24 an
/// adopted ID pointed into the request head, which the next request on the
/// connection overwrites.
pub fn current() ?[]const u8 {
    return if (current_id.len == 0) null else current_id;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const ri: *const RequestId = @ptrCast(@alignCast(state.?));

    const id: []const u8 = blk: {
        if (ri.options.trust_incoming) {
            if (ctx.req.header(ri.options.header_name)) |incoming| {
                if (isAdoptable(incoming)) { // ≤ max_adopt_len = id_buf.len
                    @memcpy(id_buf[0..incoming.len], incoming);
                    break :blk id_buf[0..incoming.len];
                }
            }
        }
        if (ri.options.generator) |g| {
            if (customId(g, &id_buf)) |custom| break :blk custom;
        }
        break :blk generateInto(id_buf[0..generated_len]);
    };
    current_id = id;

    if (ri.options.echo) try ctx.res.setHeader(ri.options.header_name, id);
    return next.run(ctx);
}

/// An RFC 9110 `token` that `http` will set as an ordinary header: the
/// framing headers it treats specially (Content-Length is parsed as a number,
/// Transfer-Encoding is dropped) would make every echo fail or vanish.
fn isUsableHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
        else => return false,
    };
    return !std.ascii.eqlIgnoreCase(name, "content-length") and
        !std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

/// The generator's ID when it honours the `Generator` contract, else null.
fn customId(g: Generator, buf: *[max_adopt_len]u8) ?[]const u8 {
    const id = g.run(g.context, buf);
    const start = @intFromPtr(id.ptr);
    const inside = start >= @intFromPtr(buf) and
        start + id.len <= @intFromPtr(buf) + buf.len;
    return if (inside and isAdoptable(id)) id else null;
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

/// Write a 32-hex-char ID into `buf` and return it. Composition: 16 hex of a
/// per-process prefix · 16 hex of a process-wide sequence number. Unique
/// within the process for 2^64 calls, from any number of threads; across
/// processes (restarts, replicas) the prefix makes a clash improbable, not
/// impossible. A `fork()` child inherits the prefix AND the counter if the
/// parent generated an ID before forking, so parent and child then repeat
/// each other's IDs — a pre-fork server must not generate before it forks. No allocation and no OS-entropy call (see module doc).
///
/// `pub` for explicit-state servers (see `isAdoptable`); safe from a fiber,
/// unlike `current()`: it touches only process-wide atomics and the
/// caller-owned `buf`, nothing request-scoped.
pub fn generateInto(buf: *[generated_len]u8) []const u8 {
    // A process-wide counter, as chi's RequestID keeps. The 2026-10-04
    // design (monotonic ns + a thread-address nonce + a per-thread counter)
    // could repeat across connection threads: TLS blocks sit at a fixed
    // stride (128 distinct nonces over 300 threads), two threads read the
    // same nanosecond in ~2.6% of concurrent samples, and every thread's
    // counter started at 1.
    const seq = next_seq.fetchAdd(1, .monotonic);
    const printed = std.mem.print(buf, "{x:0>16}{x:0>16}", .{ processPrefix(), seq }) catch unreachable; // exactly 32 chars fit
    return printed;
}

var next_seq: std.atomic.Value(u64) = .init(0);
var prefix_cache: std.atomic.Value(u64) = .init(0);

/// The per-process half of a generated ID, computed on first use. It mixes
/// the wall clock, the monotonic clock, the process ID (Linux) and the
/// address of a static (ASLR), so two processes started in the same
/// nanosecond still differ. Racing first callers compute the same kind of
/// value and the first store wins; 0 is the "not yet" sentinel, so a mix
/// that lands on 0 is bumped to 1.
fn processPrefix() u64 {
    const cached = prefix_cache.load(.monotonic);
    if (cached != 0) return cached;
    var h = std.hash.Wyhash.init(0x7265_7169_6470_7265);
    std.hash.autoHash(&h, wallNs());
    std.hash.autoHash(&h, monoNs());
    std.hash.autoHash(&h, @intFromPtr(&prefix_cache));
    if (builtin.os.tag == .linux) std.hash.autoHash(&h, std.os.linux.getpid());
    const fresh = @max(h.final(), 1);
    return prefix_cache.cmpxchgStrong(0, fresh, .monotonic, .monotonic) orelse fresh;
}

fn wallNs() u64 {
    if (builtin.os.tag == .windows) return 0; // the monotonic reading and ASLR still vary
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @bitCast(@as(i64, ts.sec))) *% std.time.ns_per_s +% @as(u64, @intCast(ts.nsec));
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

test "current() is null on a thread no middleware has run on" {
    // `current` doc: "or null if no `RequestId` middleware has run on this
    // thread yet". A fresh thread has fresh thread-locals. Mutation
    // 2026-10-04: returning the empty slice instead of null survived.
    const T = struct {
        fn run(out: *bool) void {
            out.* = current() == null;
        }
    };
    var was_null = false;
    const th = try std.Thread.spawn(.{}, T.run, .{&was_null});
    th.join();
    try testing.expect(was_null);
}

test "generateInto: same prefix, the last 16 hex digits are a sequence that steps by one" {
    // `generateInto` doc: "16 hex of a per-process prefix · 16 hex of a
    // process-wide sequence number". Mutation 2026-10-04: a frozen counter
    // survived the first test set. Test blocks run one at a time, so no
    // other caller takes a number between the two calls.
    var a: [generated_len]u8 = undefined;
    var b: [generated_len]u8 = undefined;
    const ia = generateInto(&a);
    const ib = generateInto(&b);
    try testing.expectEqualStrings(ia[0..16], ib[0..16]);
    try testing.expect(!std.mem.eql(u8, ia[0..16], "0000000000000000")); // 0 = "not yet"
    const ca = try std.fmt.parseInt(u64, ia[16..32], 16);
    const cb = try std.fmt.parseInt(u64, ib[16..32], 16);
    try testing.expectEqual(ca +% 1, cb);
}

test "generateInto: no duplicate across many threads (the 2026-09-30 survey gap)" {
    // The old id (ns · thread-address nonce · per-thread counter starting at
    // 1) repeated across connection threads. Every thread takes ids at once
    // after a shared start flag, the case that collided. Negative control
    // 2026-10-11: a threadlocal sequence instead of the process-wide one
    // made this fail (same prefix, same sequence 0 on every thread).
    const n_threads = 32;
    const per_thread = 200;
    const T = struct {
        fn run(go: *std.atomic.Value(bool), out: *[per_thread][generated_len]u8) void {
            while (!go.load(.acquire)) std.atomic.spinLoopHint();
            for (out) |*slot| _ = generateInto(slot);
        }
    };
    const ids = try testing.allocator.alloc([per_thread][generated_len]u8, n_threads);
    defer testing.allocator.free(ids);
    var go: std.atomic.Value(bool) = .init(false);
    var threads: [n_threads]std.Thread = undefined;
    // Every thread races the FIRST prefix computation too (mutation
    // 2026-10-24: a cmpxchg loser returning its own value survived, the
    // prefix having been cached by an earlier test).
    prefix_cache.store(0, .monotonic);
    for (&threads, ids) |*th, *out| th.* = try std.Thread.spawn(.{}, T.run, .{ &go, out });
    go.store(true, .release);
    for (threads) |th| th.join();
    for (ids) |*per| for (per) |*id| try testing.expectEqualStrings(ids[0][0][0..16], id[0..16]);

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(testing.allocator);
    for (ids) |*per| for (per) |*id| {
        const gop = try seen.getOrPut(testing.allocator, id);
        if (gop.found_existing) {
            std.debug.print("duplicate generated id {s}\n", .{id});
            return error.TestUnexpectedResult;
        }
    };
    try testing.expectEqual(@as(usize, n_threads * per_thread), seen.count());
}

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
    const i = std.mem.find(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

/// Header value of `name` (case-insensitive) from a raw response, or null.
fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
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
        const req = std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{val}) catch unreachable;
        const got = runWire(&r, req, &resp_buf);
        try testing.expectEqualStrings(&val, headerValue(got, "X-Request-Id").?);
    }
    // One byte over max_adopt_len: rejected, a fresh generated ID is used instead.
    {
        const val: [max_adopt_len + 1]u8 = @splat('a');
        const req = std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{val}) catch unreachable;
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
        const hdr = headerValue(got, "X-Request-Id").?;
        try testing.expectEqual(@as(usize, generated_len), hdr.len); // a generated one, not just "not edge-xyz"
        for (hdr) |c| try testing.expect(std.ascii.isHex(c));
        try testing.expectEqualStrings(hdr, bodyOf(got));
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
    try testing.expectEqualStrings("trace-42", bodyOf(got)); // adopted through the custom name
    try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "X-Request-Id"));
}

test "header_name: tokens only, framing headers refused (middleware() panics on them)" {
    // Review 2026-10-24: a non-token name or Content-Length made every echo
    // fail (http parses Content-Length as a number), Transfer-Encoding was
    // dropped silently.
    try testing.expect(isUsableHeaderName(default_header));
    try testing.expect(isUsableHeaderName("x-correlation-id"));
    try testing.expect(isUsableHeaderName("X!#$%&'*+-.^_`|~9"));
    try testing.expect(!isUsableHeaderName(""));
    try testing.expect(!isUsableHeaderName("X Request"));
    try testing.expect(!isUsableHeaderName("X-Id:"));
    try testing.expect(!isUsableHeaderName("X-Id\r\n"));
    try testing.expect(!isUsableHeaderName("Content-Length"));
    try testing.expect(!isUsableHeaderName("transfer-ENCODING"));
}

test "an adopted ID is this thread's copy, still current() for an outer middleware after the chain" {
    // Review 2026-10-24: `current()` returned a slice of the request head,
    // which the next request on the connection overwrites. An access log
    // registered outside the middleware reads it after `next.run`.
    const Outer = struct {
        var seen: [max_adopt_len]u8 = undefined;
        var seen_len: usize = 0;
        fn run(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
            try next.run(ctx);
            const id = current().?;
            @memcpy(seen[0..id.len], id);
            seen_len = id.len;
        }
    };
    var ri = RequestId{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .state = null, .run = Outer.run });
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);
    var buf: [1024]u8 = undefined;
    _ = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: edge-abc\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("edge-abc", Outer.seen[0..Outer.seen_len]);
    const id = current().?; // runWire's head buffer is gone; this must not point into it
    try testing.expectEqual(@intFromPtr(&id_buf), @intFromPtr(id.ptr));
    try testing.expectEqualStrings("edge-abc", id);
}

/// Test generator: "<prefix>-<n>" with a per-instance counter in `context`.
const PrefixGen = struct {
    prefix: []const u8,
    n: u32 = 0,
    /// When set, returns this instead (to exercise the contract checks):
    /// copied into `buf` when `copy`, else the literal itself (outside `buf`).
    bad: ?[]const u8 = null,
    copy: bool = false,

    fn run(context: ?*anyopaque, buf: *[max_adopt_len]u8) []const u8 {
        const self: *PrefixGen = @ptrCast(@alignCast(context.?));
        self.n += 1;
        const b = self.bad orelse
            return std.mem.print(buf, "{s}-{d}", .{ self.prefix, self.n }) catch unreachable;
        if (!self.copy) return b;
        @memcpy(buf[0..b.len], b);
        return buf[0..b.len];
    }

    fn generator(self: *PrefixGen) Generator {
        return .{ .context = self, .run = run };
    }
};

test "generator: a custom scheme is used, echoed and seen by current(); incoming still wins" {
    var gen: PrefixGen = .{ .prefix = "svc" };
    var ri = RequestId{ .options = .{ .generator = gen.generator() } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ri.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    var got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("svc-1", headerValue(got, "X-Request-Id").?);
    try testing.expectEqualStrings("svc-1", bodyOf(got));
    got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("svc-2", headerValue(got, "X-Request-Id").?);

    // A valid incoming ID is adopted; the generator is not called.
    got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: edge-7\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("edge-7", headerValue(got, "X-Request-Id").?);
    try testing.expectEqual(@as(u32, 2), gen.n);
}

test "customId: a result must lie inside buf at both ends (the whole of buf is fine)" {
    // Mutation 2026-10-24: `<` for `<=` on the end bound and dropping the end
    // bound survived -- no generator filled buf or ran past it. `big` holds
    // `buf` in its middle so the overrunning results are real memory.
    var big: [3 * max_adopt_len]u8 = @splat('a');
    const buf: *[max_adopt_len]u8 = big[max_adopt_len..][0..max_adopt_len];
    const Ret = struct {
        fn run(context: ?*anyopaque, _: *[max_adopt_len]u8) []const u8 {
            return @as(*const []const u8, @ptrCast(@alignCast(context.?))).*;
        }
    };
    var whole: []const u8 = buf;
    var past_end: []const u8 = big[max_adopt_len + 100 ..][0..max_adopt_len];
    var before_start: []const u8 = big[max_adopt_len - 1 ..][0..10];
    try testing.expectEqual(@intFromPtr(buf), @intFromPtr(customId(.{ .context = @ptrCast(&whole), .run = Ret.run }, buf).?.ptr));
    try testing.expectEqual(@as(?[]const u8, null), customId(.{ .context = @ptrCast(&past_end), .run = Ret.run }, buf));
    try testing.expectEqual(@as(?[]const u8, null), customId(.{ .context = @ptrCast(&before_start), .run = Ret.run }, buf));
}

test "generator: a result breaking the contract falls back to the built-in id" {
    // Each case: (bad output, copy it into buf first?). Copied cases fail on
    // shape (isAdoptable); the literal case fails on "not inside buf".
    // Negative control 2026-10-11: dropping the `isAdoptable` call in
    // `customId` failed this test (an empty id went out as the header).
    const cases = [_]struct { bad: []const u8, copy: bool }{
        .{ .bad = "", .copy = true },
        .{ .bad = "a\r\nX-Evil: 1", .copy = true },
        .{ .bad = "id,with,commas", .copy = true },
        .{ .bad = "static-literal", .copy = false },
    };
    for (cases) |c| {
        var gen: PrefixGen = .{ .prefix = "", .bad = c.bad, .copy = c.copy };
        var ri = RequestId{ .options = .{ .generator = gen.generator() } };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(ri.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
        const hdr = headerValue(got, "X-Request-Id").?;
        errdefer std.debug.print("generator fallback case bad={s} got header {s}\n", .{ c.bad, hdr });
        try testing.expectEqual(@as(u32, 1), gen.n);
        try testing.expect(modelIsGenerated(hdr));
        try testing.expectEqualStrings(hdr, bodyOf(got));
        try testing.expect(std.mem.find(u8, got, "X-Evil") == null);
    }
}

// ── model-fuzz: seeded random requests vs. a naive reference model ──────────
//
// The model is a restatement of the documented policy (module doc + SPEC
// "Design & invariants"), written with its own logic: an explicit allowed
// character string, no call into `isAdoptable`.

const model_allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";

fn modelAdoptable(v: []const u8) bool {
    if (v.len < 1) return false;
    if (v.len > 200) return false;
    var i: usize = 0;
    while (i < v.len) : (i += 1) {
        if (std.mem.findScalar(u8, model_allowed, v[i]) == null) return false;
    }
    return true;
}

fn modelIsGenerated(v: []const u8) bool {
    if (v.len != 32) return false;
    for (v) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

test "model-fuzz: isAdoptable matches the documented charset/length rule on random bytes" {
    var prng = std.Random.DefaultPrng.init(0x7265716964303031);
    const rnd = prng.random();
    var buf: [260]u8 = undefined;
    var adoptable: usize = 0;
    var rejected_len: usize = 0;
    var rejected_char: usize = 0;
    var case: usize = 0;
    while (case < 4000) : (case += 1) {
        // Length hits 0, 1, the 200/201 boundary and beyond.
        const len: usize = switch (rnd.uintLessThan(u8, 6)) {
            0 => 0,
            1 => 200,
            2 => 201,
            3 => rnd.uintLessThan(usize, 260),
            else => 1 + rnd.uintLessThan(usize, 40),
        };
        const style = rnd.uintLessThan(u8, 3);
        for (buf[0..len]) |*b| {
            b.* = switch (style) {
                0 => model_allowed[rnd.uintLessThan(usize, model_allowed.len)],
                1 => rnd.int(u8),
                else => if (rnd.uintLessThan(u8, 20) == 0) rnd.int(u8) else model_allowed[rnd.uintLessThan(usize, model_allowed.len)],
            };
        }
        const v = buf[0..len];
        const want = modelAdoptable(v);
        if (isAdoptable(v) != want) {
            std.debug.print("requestid model-fuzz mismatch: seed=0x7265716964303031 case={d} len={d} want={}\n", .{ case, len, want });
            return error.TestUnexpectedResult;
        }
        if (want) adoptable += 1 else if (len > 200) rejected_len += 1 else rejected_char += 1;
    }
    try testing.expect(adoptable > 0 and rejected_len > 0 and rejected_char > 0);
}

test "model-fuzz: middleware adopt-or-generate vs. model over random options and headers" {
    const seed: u64 = 0x7265716964303032;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    const names = [_][]const u8{ "X-Request-Id", "X-Correlation-Id", "Trace" };
    const req_spellings = [_][]const u8{ "X-Request-Id", "x-request-id", "X-REQUEST-ID", "X-Correlation-Id", "x-correlation-id", "Trace", "trace" };
    const wire_chars = model_allowed ++ "!#$%&'()*+,/:;<=>?@[]^`{|}~\"\\ ";

    var reach_adopted: usize = 0;
    var reach_regen_malformed: usize = 0;
    var reach_regen_long: usize = 0;
    var reach_regen_untrusted: usize = 0;
    var reach_absent: usize = 0;
    var reach_no_echo: usize = 0;
    var reach_boundary_adopted: usize = 0;
    var seen_generated: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var it = seen_generated.keyIterator();
        while (it.next()) |k| testing.allocator.free(k.*);
        seen_generated.deinit(testing.allocator);
    }

    var step: usize = 0;
    while (step < 400) : (step += 1) {
        const name = names[rnd.uintLessThan(usize, names.len)];
        const trust = rnd.boolean();
        const echo = rnd.uintLessThan(u8, 4) != 0;

        // Incoming header: absent, or a value. It travels on the wire, so no
        // CR/LF/NUL/high bytes and no leading/trailing blanks (the HTTP parser
        // trims those; the raw-byte charset is covered by the test above).
        var val_buf: [260]u8 = undefined;
        var present = rnd.uintLessThan(u8, 8) != 0;
        var len: usize = 0;
        if (present) {
            len = switch (rnd.uintLessThan(u8, 8)) {
                0 => 1,
                1 => 200,
                2 => 201,
                3 => 150 + rnd.uintLessThan(usize, 60),
                else => 1 + rnd.uintLessThan(usize, 40),
            };
            const dirty = rnd.uintLessThan(u8, 3) == 0;
            for (val_buf[0..len], 0..) |*b, i| {
                const dirty_here = dirty and rnd.uintLessThan(u8, 12) == 0;
                const pool: []const u8 = if (dirty_here) wire_chars else model_allowed;
                b.* = pool[rnd.uintLessThan(usize, pool.len)];
                if ((i == 0 or i == len - 1) and b.* == ' ') b.* = 'x';
            }
        } else {
            present = false;
        }
        const val = val_buf[0..len];

        // The request names the header with a random spelling, but it is only
        // the configured header when it matches case-insensitively.
        const spelling = if (present and rnd.boolean())
            req_spellings[rnd.uintLessThan(usize, req_spellings.len)]
        else
            name;
        const header_applies = present and std.ascii.eqlIgnoreCase(spelling, name);

        var req_buf: [1024]u8 = undefined;
        const req = if (present)
            std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\n{s}: {s}\r\nConnection: close\r\n\r\n", .{ spelling, val }) catch unreachable
        else
            std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{}) catch unreachable;

        var ri = RequestId{ .options = .{ .header_name = name, .trust_incoming = trust, .echo = echo } };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(ri.middleware());
        try r.get("/", hEchoCurrent);
        var out: [2048]u8 = undefined;
        const got = runWire(&r, req, &out);

        const body = bodyOf(got);
        const hdr = headerValue(got, name);
        const should_adopt = trust and header_applies and modelAdoptable(val);

        errdefer std.debug.print("requestid model-fuzz mismatch: seed=0x{x} step={d} name={s} trust={} echo={} present={} applies={} len={d}\n", .{ seed, step, name, trust, echo, present, header_applies, len });

        if (should_adopt) {
            try testing.expectEqualStrings(val, body);
            if (echo) try testing.expectEqualStrings(val, hdr.?) else try testing.expect(hdr == null);
            reach_adopted += 1;
            if (len == 200) reach_boundary_adopted += 1;
        } else {
            try testing.expect(modelIsGenerated(body));
            if (echo) try testing.expectEqualStrings(body, hdr.?) else try testing.expect(hdr == null);
            // Generated ids are unique within one thread's run.
            const gop = try seen_generated.getOrPut(testing.allocator, body);
            if (gop.found_existing) return error.TestUnexpectedResult;
            gop.key_ptr.* = try testing.allocator.dupe(u8, body);
            if (!present or !header_applies) {
                reach_absent += 1;
            } else if (!trust) {
                reach_regen_untrusted += 1;
            } else if (len > 200) {
                reach_regen_long += 1;
            } else {
                reach_regen_malformed += 1;
            }
        }
        if (!echo) reach_no_echo += 1;
    }
    try testing.expect(reach_adopted > 0);
    try testing.expect(reach_boundary_adopted > 0);
    try testing.expect(reach_regen_malformed > 0);
    try testing.expect(reach_regen_long > 0);
    try testing.expect(reach_regen_untrusted > 0);
    try testing.expect(reach_absent > 0);
    try testing.expect(reach_no_echo > 0);
}
