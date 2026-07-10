// SPDX-License-Identifier: MIT

//! tracecontext — W3C Trace Context propagation as a `router` middleware.
//!
//! Implements W3C Trace Context Level 1: parsing, generating and forwarding
//! the `traceparent` header (plus opaque `tracestate` passthrough) so a request
//! keeps a single distributed-trace identity as it crosses services.
//!
//! A `traceparent` value is `version-traceid-parentid-flags`, e.g.
//! `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`:
//!
//! - `version`   two lowercase hex — only `00` (Level 1) is accepted.
//! - `trace-id`  16 bytes / 32 lowercase hex — the whole-trace identity, kept
//!               end to end. The all-zero value is invalid.
//! - `parent-id` (a.k.a. span-id) 8 bytes / 16 lowercase hex — the caller's
//!               span. The all-zero value is invalid.
//! - `flags`     one byte / 2 lowercase hex — bit 0 (`01`) = sampled.
//!
//! The middleware, per request:
//!
//! 1. Parses the incoming `traceparent`. If valid (and `trust_incoming`),
//!    **keeps its trace-id and flags** and mints a **fresh span-id** for this
//!    hop — the child context of the incoming one.
//! 2. If absent or malformed, **starts a new trace** (fresh trace-id + span-id,
//!    flags from `sampled`).
//! 3. Carries the opaque `tracestate` along unchanged (light validation only).
//! 4. Exposes the current hop's context via `tracecontext.current()` (a
//!    thread-local, like `requestid.current()`) and, when `echo` is set, writes
//!    the outgoing `traceparent`/`tracestate` back on the response.
//!
//! Register it **first** (outermost) so every response carries the context.
//!
//! ## Generated IDs
//!
//! trace-ids and span-ids are derived from the monotonic clock, a
//! per-connection-thread nonce and a per-thread counter — no allocation and no
//! OS entropy call, fully portable. They are **correlation** identifiers
//! (unique for tracing), NOT unpredictable security tokens: do not rely on them
//! being unguessable. W3C does not require randomness of trace-ids, only
//! uniqueness; if you need CSPRNG ids, mint them yourself and set `traceparent`.
//!
//! ## Memory / concurrency
//!
//! The current context is a value in thread-local storage owned by the
//! connection task (the server is task-per-connection: one request at a time
//! per thread). The outgoing header is formatted into a thread-local buffer,
//! valid until the response is flushed. An adopted `tracestate` borrows the
//! request head (stable for the response). `current()` is meaningful only from
//! the connection thread handling the request the middleware ran on.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .platform = .any,
    .role = .util,
    // Per-request state lives in thread-local storage owned by the connection
    // task; the immutable config is only read.
    .concurrency = .threadsafe,
    .model_after = "W3C Trace Context Level 1 (traceparent/tracestate)",
    .deps = .{ "router", "http" },
};

/// Default header names (case-insensitive on read; emitted lowercase per spec).
pub const default_traceparent_header = "traceparent";
pub const default_tracestate_header = "tracestate";

/// traceparent flag: the trace is sampled (recorded).
pub const flag_sampled: u8 = 0x01;

/// Longest `tracestate` value carried along; a longer one is dropped (RFC caps
/// the combined list at 512 bytes).
pub const max_state_len = 512;

/// A parsed / mintable `traceparent` (version `00`). `trace_id` and
/// `parent_id` are raw bytes; `write` renders them back to the header string.
pub const TraceParent = struct {
    trace_id: [16]u8,
    parent_id: [8]u8,
    flags: u8,

    /// Length of a rendered `00` traceparent: `00` `-` 32 `-` 16 `-` 2 = 55.
    pub const header_len = 2 + 1 + 32 + 1 + 16 + 1 + 2;

    pub const ParseError = error{
        BadLength,
        BadVersion,
        BadFormat,
        BadHex,
        ZeroTraceId,
        ZeroParentId,
    };

    /// Parse a Level 1 (`version 00`) traceparent. Rejects a wrong length, a
    /// non-`00` version, misplaced delimiters, any non-lowercase-hex digit and
    /// the all-zero trace-id / parent-id (both invalid per spec).
    pub fn parse(v: []const u8) ParseError!TraceParent {
        if (v.len != header_len) return error.BadLength;
        if (v[0] != '0' or v[1] != '0') return error.BadVersion;
        if (v[2] != '-' or v[35] != '-' or v[52] != '-') return error.BadFormat;

        var tp: TraceParent = undefined;
        var flags_byte: [1]u8 = undefined;
        if (!decodeHex(&tp.trace_id, v[3..35])) return error.BadHex;
        if (!decodeHex(&tp.parent_id, v[36..52])) return error.BadHex;
        if (!decodeHex(&flags_byte, v[53..55])) return error.BadHex;
        tp.flags = flags_byte[0];

        if (isZero(&tp.trace_id)) return error.ZeroTraceId;
        if (isZero(&tp.parent_id)) return error.ZeroParentId;
        return tp;
    }

    /// Render this context into `buf` (exactly `header_len` bytes) and return
    /// the slice. Always version `00`, lowercase hex.
    pub fn write(tp: TraceParent, buf: *[header_len]u8) []const u8 {
        buf[0] = '0';
        buf[1] = '0';
        buf[2] = '-';
        encodeHex(buf[3..35], &tp.trace_id);
        buf[35] = '-';
        encodeHex(buf[36..52], &tp.parent_id);
        buf[52] = '-';
        encodeHex(buf[53..55], &[_]u8{tp.flags});
        return buf[0..];
    }

    /// True when the sampled flag (bit 0) is set.
    pub fn sampled(tp: TraceParent) bool {
        return tp.flags & flag_sampled != 0;
    }
};

/// The child of `parent` for this hop: same trace-id and flags, a fresh
/// span-id (`parent_id`) identifying the current span.
pub fn childOf(parent: TraceParent, span_id: [8]u8) TraceParent {
    return .{ .trace_id = parent.trace_id, .parent_id = span_id, .flags = parent.flags };
}

/// A brand-new root context (fresh trace-id + span-id).
pub fn newTrace(flags: u8) TraceParent {
    return .{ .trace_id = newTraceId(), .parent_id = newSpanId(), .flags = flags };
}

pub const Options = struct {
    /// Header carrying the trace-id chain. Default `traceparent`.
    traceparent_header: []const u8 = default_traceparent_header,
    /// Opaque vendor state header carried along. Default `tracestate`.
    tracestate_header: []const u8 = default_tracestate_header,
    /// Continue a valid incoming trace instead of always starting a new one.
    trust_incoming: bool = true,
    /// Sampled flag for a newly *started* trace (ignored when continuing).
    sampled: bool = true,
    /// Echo the outgoing `traceparent` (and passed-through `tracestate`) on the
    /// response. Off ⇒ the context is only exposed via `current()`.
    echo: bool = true,
};

/// Config + the middleware over it. Immutable; share one across threads.
pub const TraceContext = struct {
    options: Options = .{},

    pub fn middleware(tc: *const TraceContext) router.Middleware {
        return .{ .state = @constCast(tc), .run = middlewareRun };
    }
};

// Per-connection-thread request-scoped storage (see the module doc).
threadlocal var current_ctx: ?TraceParent = null;
threadlocal var current_state: ?[]const u8 = null;
threadlocal var out_buf: [TraceParent.header_len]u8 = undefined;
threadlocal var counter: u64 = 0;

/// The current hop's trace context, or null if no `TraceContext` middleware has
/// run on this thread yet. Call it from the connection thread during the
/// request. The trace-id is the whole-trace identity; the parent-id is this
/// hop's span-id.
pub fn current() ?TraceParent {
    return current_ctx;
}

/// The opaque `tracestate` carried on this request, if any and valid.
pub fn currentState() ?[]const u8 {
    return current_state;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const tc: *const TraceContext = @ptrCast(@alignCast(state.?));
    const opt = tc.options;

    const incoming: ?TraceParent = blk: {
        if (!opt.trust_incoming) break :blk null;
        const raw = ctx.req.header(opt.traceparent_header) orelse break :blk null;
        break :blk TraceParent.parse(raw) catch null;
    };

    const hop: TraceParent = if (incoming) |p|
        childOf(p, newSpanId())
    else
        newTrace(if (opt.sampled) flag_sampled else 0);
    current_ctx = hop;

    // tracestate passthrough: carry a valid value along unchanged (borrows the
    // request head, stable for the response), else drop it.
    current_state = blk: {
        const ts = ctx.req.header(opt.tracestate_header) orelse break :blk null;
        break :blk if (isValidState(ts)) ts else null;
    };

    if (opt.echo) {
        try ctx.res.setHeader(opt.traceparent_header, hop.write(&out_buf));
        if (current_state) |ts| try ctx.res.setHeader(opt.tracestate_header, ts);
    }
    return next.run(ctx);
}

/// A `tracestate` is carried unchanged when non-empty, within `max_state_len`,
/// and every byte is printable non-control ASCII (a light guard — full grammar
/// validation is intentionally left to the tracing backend).
fn isValidState(v: []const u8) bool {
    if (v.len == 0 or v.len > max_state_len) return false;
    for (v) |c| {
        if (c < 0x20 or c >= 0x7f) return false;
    }
    return true;
}

// ── id generation (portable, no OS entropy — see module doc) ─────────────────

/// A fresh 8-byte span-id (never all-zero).
pub fn newSpanId() [8]u8 {
    var id: [8]u8 = undefined;
    fillId(&id);
    return id;
}

/// A fresh 16-byte trace-id (never all-zero).
pub fn newTraceId() [16]u8 {
    var id: [16]u8 = undefined;
    fillId(&id);
    return id;
}

/// Fill `dst` with a unique-per-call value mixed from the monotonic clock, a
/// per-thread nonce and a per-thread counter, then guarantee it is not the
/// all-zero (invalid) id. Not a CSPRNG — a correlation id, not a secret.
fn fillId(dst: []u8) void {
    counter +%= 1;
    const ns = monoNs();
    // The address of a thread-local distinguishes threads (each has its own TLS
    // block), so two threads never collide even within one ns tick.
    const nonce: u64 = @intFromPtr(&counter);
    var acc: u64 = ns ^ (nonce *% 0x9E3779B97F4A7C15) ^ (counter *% 0xD1B54A32D192ED03);
    for (dst, 0..) |*b, i| {
        acc ^= acc >> 12;
        acc ^= acc << 25;
        acc ^= acc >> 27;
        acc +%= counter +% @as(u64, i);
        b.* = @truncate((acc *% 0x2545F4914F6CDD1D) >> 24);
    }
    if (isZero(dst)) dst[dst.len - 1] = 1; // never the invalid all-zero id
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

// ── hex helpers (lowercase only, per spec) ───────────────────────────────────

const hex_digits = "0123456789abcdef";

fn encodeHex(dst: []u8, src: []const u8) void {
    for (src, 0..) |byte, i| {
        dst[i * 2] = hex_digits[byte >> 4];
        dst[i * 2 + 1] = hex_digits[byte & 0x0f];
    }
}

/// Decode `src` (lowercase hex, `dst.len * 2` chars) into `dst`; false on any
/// non-lowercase-hex digit. Uppercase is rejected — the spec mandates lowercase.
fn decodeHex(dst: []u8, src: []const u8) bool {
    for (dst, 0..) |*d, i| {
        const hi = hexNibble(src[i * 2]) orelse return false;
        const lo = hexNibble(src[i * 2 + 1]) orelse return false;
        d.* = (@as(u8, hi) << 4) | lo;
    }
    return true;
}

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        else => null,
    };
}

fn isZero(s: []const u8) bool {
    for (s) |b| {
        if (b != 0) return false;
    }
    return true;
}

// ── tests (offline — through http.Server.serveStream) ───────────────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// A canonical W3C example traceparent (from the spec).
const sample = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const sample_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
const sample_span = "00f067aa0ba902b7";

fn runWire(r: *router.Router, bytes: []const u8, out_buf_wire: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf_wire);
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

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

/// Handler that renders `current()` into the body so tests can assert it
/// matches the outgoing response header.
fn hEchoCurrent(ctx: *router.Ctx) anyerror!void {
    if (current()) |tp| {
        var b: [TraceParent.header_len]u8 = undefined;
        try ctx.res.writeAll(tp.write(&b));
    } else try ctx.res.writeAll("<none>");
}

test "valid incoming traceparent: trace-id carried, fresh span-id, current() matches" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\nConnection: close\r\n\r\n", &buf);

    const hdr = headerValue(got, "traceparent").?;
    try testing.expectEqual(@as(usize, TraceParent.header_len), hdr.len);
    // Trace-id and flags carried from the incoming header …
    try testing.expectEqualStrings("00", hdr[0..2]);
    try testing.expectEqualStrings(sample_trace, hdr[3..35]);
    try testing.expectEqualStrings("01", hdr[53..55]);
    // … but a fresh span-id was minted for this hop.
    try testing.expect(!std.mem.eql(u8, sample_span, hdr[36..52]));
    // The outgoing header re-parses and is sampled.
    const parsed = try TraceParent.parse(hdr);
    try testing.expect(parsed.sampled());
    // Handler saw the same context via current().
    try testing.expectEqualStrings(hdr, bodyOf(got));
}

test "absent traceparent starts a fresh valid trace" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    const hdr = headerValue(got, "traceparent").?;
    const parsed = try TraceParent.parse(hdr); // valid, non-zero ids
    try testing.expect(parsed.sampled()); // default sampled=true
}

test "malformed incoming traceparent starts a fresh trace" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: not-a-valid-traceparent\r\nConnection: close\r\n\r\n", &buf);
    const hdr = headerValue(got, "traceparent").?;
    _ = try TraceParent.parse(hdr); // still emits a valid fresh context
}

test "echo=false omits the header but keeps current()" {
    var tc = TraceContext{ .options = .{ .echo = false } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "traceparent"));
    try testing.expectEqual(@as(usize, TraceParent.header_len), bodyOf(got).len); // current() set
}

test "tracestate is carried through unchanged" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\ntracestate: rojo=00f067aa0ba902b7,congo=t61rcWkgMzE\r\n" ++
        "Connection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings(
        "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        headerValue(got, "tracestate").?,
    );
}

test "parse / write round-trip" {
    const tp = try TraceParent.parse(sample);
    try testing.expect(tp.sampled());
    var b: [TraceParent.header_len]u8 = undefined;
    try testing.expectEqualStrings(sample, tp.write(&b));
}

test "invalid traceparents are rejected" {
    const E = TraceParent.ParseError;
    // Wrong length.
    try testing.expectError(E.BadLength, TraceParent.parse("00-abcd"));
    // Non-00 version.
    try testing.expectError(
        E.BadVersion,
        TraceParent.parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // Misplaced delimiter.
    try testing.expectError(
        E.BadFormat,
        TraceParent.parse("00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // Uppercase hex (spec mandates lowercase).
    try testing.expectError(
        E.BadHex,
        TraceParent.parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"),
    );
    // All-zero trace-id.
    try testing.expectError(
        E.ZeroTraceId,
        TraceParent.parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
    );
    // All-zero parent-id.
    try testing.expectError(
        E.ZeroParentId,
        TraceParent.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
    );
}

test "childOf keeps the trace and generated ids are unique / non-zero" {
    const parent = try TraceParent.parse(sample);
    const span = newSpanId();
    const child = childOf(parent, span);
    try testing.expectEqualSlices(u8, &parent.trace_id, &child.trace_id);
    try testing.expectEqualSlices(u8, &span, &child.parent_id);
    try testing.expectEqual(parent.flags, child.flags);

    // Successive generated ids differ and are never the invalid all-zero id.
    const a = newTraceId();
    const b = newTraceId();
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!isZero(&a));
    try testing.expect(!isZero(&newSpanId()));
}
