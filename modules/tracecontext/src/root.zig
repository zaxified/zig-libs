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
//! - `version`   two lowercase hex. `00` (Level 1) is what we emit; a higher
//!               version is read forward-compatibly as its Level 1 prefix
//!               (W3C §3.2.2.3), and `ff` is reserved as invalid.
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
//! 3. When (and only when) a trusted `traceparent` was continued in step 1,
//!    carries the opaque `tracestate` along (light validation only; multiple
//!    header instances are combined per RFC 9110 §5.3). A `tracestate`
//!    arriving without a valid incoming `traceparent` is dropped outright —
//!    per spec, a vendor that fails to parse `traceparent` MUST NOT attempt
//!    to parse `tracestate`.
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "W3C Trace Context — `traceparent`/`tracestate` parse + generate + propagation middleware (child span per hop) for distributed tracing",
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

    /// Parse a traceparent. Rejects a wrong length, misplaced delimiters, any
    /// non-lowercase-hex digit and the all-zero trace-id / parent-id (both
    /// invalid per spec).
    ///
    /// Future versions are parsed forward-compatibly, as W3C §3.2.2.3
    /// requires: every version keeps the Level 1 `version-traceid-parentid-
    /// flags` prefix and may append `-<extra>`, so a header we do not know is
    /// read as its Level 1 prefix and the remainder is ignored rather than
    /// restarting the trace. Version `ff` is reserved as invalid, and `00`
    /// itself is exactly `header_len` — trailing bytes there are malformed,
    /// not an extension.
    pub fn parse(v: []const u8) ParseError!TraceParent {
        if (v.len < header_len) return error.BadLength;
        var version_byte: [1]u8 = undefined;
        if (!decodeHex(&version_byte, v[0..2])) return error.BadVersion;
        if (version_byte[0] == 0xff) return error.BadVersion;
        if (version_byte[0] == 0x00) {
            if (v.len != header_len) return error.BadLength;
        } else if (v.len > header_len and v[header_len] != '-') {
            return error.BadFormat;
        }
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
// Scratch for combining multiple `tracestate` header instances (RFC 9110
// §5.3 field order — see `combinedHeader`) before validation. Sized to
// `max_state_len` since anything that would overflow it is dropped anyway
// under the existing coarse length gate.
threadlocal var state_buf: [max_state_len]u8 = undefined;
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
        // A duplicated traceparent is ambiguous (which of the two is the real
        // parent?), so it is discarded exactly like an absent/malformed one —
        // per the W3C conformance suite's `test_traceparent_duplicated`, NOT a
        // normative sentence in the spec's traceparent section itself.
        const raw = singleHeader(ctx.req, opt.traceparent_header) orelse break :blk null;
        break :blk TraceParent.parse(raw) catch null;
    };

    const hop: TraceParent = if (incoming) |p|
        childOf(p, newSpanId())
    else
        newTrace(if (opt.sampled) flag_sampled else 0);
    current_ctx = hop;

    // tracestate passthrough: the spec is explicit — "If the vendor failed to
    // parse traceparent, it MUST NOT attempt to parse tracestate" (spec
    // `20-http_request_header_format.md`, "Tracestate Header"; the W3C
    // conformance suite's `test_tracestate_included_traceparent_missing`
    // exercises exactly this). So without a trusted, successfully-parsed
    // incoming traceparent, tracestate is dropped outright — there is no
    // parent to correlate it with — regardless of how well-formed it looks.
    // Otherwise: RFC 9110 §5.3 requires multiple same-name header instances
    // to be combined (comma-joined, in wire order) before use — the spec's
    // own "tracestate MAY be split into multiple header fields" text depends
    // on this. Carry the combined value along unchanged when valid, else
    // drop it.
    current_state = blk: {
        if (incoming == null) break :blk null;
        const ts = combinedHeader(ctx.req, opt.tracestate_header, &state_buf) orelse break :blk null;
        break :blk if (isValidState(ts)) ts else null;
    };

    if (opt.echo) {
        // Plain local: `setHeader` copies the bytes (`ResponseWriter.header_buf`),
        // so this buffer only has to outlive the call, not the response. It was
        // a `threadlocal` until 2026-08-12 for the latter reason.
        var out_buf: [TraceParent.header_len]u8 = undefined;
        try ctx.res.setHeader(opt.traceparent_header, hop.write(&out_buf));
        if (current_state) |ts| try ctx.res.setHeader(opt.tracestate_header, ts);
    }
    return next.run(ctx);
}

/// A `tracestate` is carried unchanged when non-empty, within `max_state_len`,
/// and every byte is either printable non-control ASCII or horizontal tab
/// (`\t`, part of the spec's `OWS` — optional whitespace legally surrounds
/// list-members) — a light guard, full grammar validation is intentionally
/// left to the tracing backend.
fn isValidState(v: []const u8) bool {
    if (v.len == 0 or v.len > max_state_len) return false;
    for (v) |c| {
        if (c == '\t') continue;
        if (c < 0x20 or c >= 0x7f) return false;
    }
    return true;
}

/// The value of header `name` only when it occurs EXACTLY once; null if
/// absent OR duplicated. A single-valued header (`traceparent`) sent twice is
/// ambiguous — neither occurrence can be trusted over the other — so it is
/// treated the same as absent/malformed (see `middlewareRun`).
fn singleHeader(req: *const http.Server.Request, name: []const u8) ?[]const u8 {
    var it = req.iterateHeaders();
    var found: ?[]const u8 = null;
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.name, name)) continue;
        if (found != null) return null; // duplicate — ambiguous, discard both
        found = entry.value;
    }
    return found;
}

/// Every occurrence of header `name`, comma-joined in wire order into `buf`
/// (RFC 9110 §5.3 field-order combining — `tracestate` MAY legally arrive as
/// several header instances that must be combined before use). Returns null
/// when absent, or when combining would overflow `buf` (the existing coarse
/// `max_state_len` gate then drops it entirely, same as an over-long single
/// header already did).
fn combinedHeader(req: *const http.Server.Request, name: []const u8, buf: []u8) ?[]const u8 {
    var it = req.iterateHeaders();
    var len: usize = 0;
    var any = false;
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.name, name)) continue;
        const piece = entry.value;
        const sep_len: usize = if (any) 1 else 0;
        if (len + sep_len + piece.len > buf.len) return null;
        if (any) {
            buf[len] = ',';
            len += 1;
        }
        @memcpy(buf[len..][0..piece.len], piece);
        len += piece.len;
        any = true;
    }
    return if (any) buf[0..len] else null;
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

// `runWire`/`headerValue` are `pub` (not just file-local) so the vendored
// W3C-corpus runner (`w3c_conformance_test.zig`) can drive the same offline
// wire harness instead of duplicating it.
pub fn runWire(r: *router.Router, bytes: []const u8, out_buf_wire: []u8) []const u8 {
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

pub fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
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

test "trust_incoming=false always starts a fresh trace, even with a valid incoming traceparent" {
    var tc = TraceContext{ .options = .{ .trust_incoming = false } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\nConnection: close\r\n\r\n", &buf);

    const hdr = headerValue(got, "traceparent").?;
    const parsed = try TraceParent.parse(hdr); // still a valid fresh context
    // The incoming trace-id must NOT have been kept: a fresh trace-id was minted.
    try testing.expect(!std.mem.eql(u8, sample_trace, hdr[3..35]));
    _ = parsed;
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

test "tracestate: invalid values (empty, too long, control char) are dropped, not passed through" {
    // Empty value: dropped.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: \r\n" ++
            "Connection: close\r\n\r\n", &buf);
        try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "tracestate"));
    }
    // Longer than max_state_len (512): dropped, at the exact boundary + 1.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);

        var req_buf: [4096]u8 = undefined;
        const too_long = [_]u8{'a'} ** (max_state_len + 1);
        const req = try std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: {s}\r\n" ++
            "Connection: close\r\n\r\n", .{too_long});
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, req, &buf);
        try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "tracestate"));
    }
    // A control character (below 0x20): dropped.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: rojo=\x01bad\r\n" ++
            "Connection: close\r\n\r\n", &buf);
        try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "tracestate"));
    }
    // Exactly at the boundary (max_state_len): kept.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);

        var req_buf: [4096]u8 = undefined;
        const at_boundary = [_]u8{'a'} ** max_state_len;
        const req = try std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: {s}\r\n" ++
            "Connection: close\r\n\r\n", .{at_boundary});
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, req, &buf);
        try testing.expectEqualStrings(&at_boundary, headerValue(got, "tracestate").?);
    }
}

test "parse / write round-trip" {
    const tp = try TraceParent.parse(sample);
    try testing.expect(tp.sampled());
    var b: [TraceParent.header_len]u8 = undefined;
    try testing.expectEqualStrings(sample, tp.write(&b));
}

test "a future traceparent version is parsed as its Level 1 prefix" {
    // W3C §3.2.2.3: an unknown *higher* version keeps the version-traceid-
    // parentid-flags prefix and may append `-<extra>`. Rejecting it would
    // restart the trace and break the very forward compatibility the field
    // exists for. We re-emit as `00` because that is all we understand.
    const future = "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const tp = try TraceParent.parse(future);
    try testing.expect(tp.sampled());
    var b: [TraceParent.header_len]u8 = undefined;
    try testing.expectEqualStrings(sample, tp.write(&b));

    // Same, with a future field appended after the Level 1 prefix.
    const extended = future ++ "-somethingnew";
    const tp2 = try TraceParent.parse(extended);
    try testing.expectEqualStrings(sample, tp2.write(&b));

    // The Level 1 validity rules still apply to the prefix of a future version.
    try testing.expectError(
        TraceParent.ParseError.ZeroTraceId,
        TraceParent.parse("cc-00000000000000000000000000000000-00f067aa0ba902b7-01"),
    );
}

test "invalid traceparents are rejected" {
    const E = TraceParent.ParseError;
    // Wrong length.
    try testing.expectError(E.BadLength, TraceParent.parse("00-abcd"));
    // Version `ff` is reserved as invalid (W3C §3.2.2.3).
    try testing.expectError(
        E.BadVersion,
        TraceParent.parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // A version that is not lowercase hex at all.
    try testing.expectError(
        E.BadVersion,
        TraceParent.parse("0X-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // Version `00` is exactly 55 chars: trailing bytes are malformed, not an
    // extension — only a *higher* version may carry one.
    try testing.expectError(
        E.BadLength,
        TraceParent.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-xyz"),
    );
    // A future version whose 56th char is not `-` cannot be trusted to keep
    // the Level 1 prefix.
    try testing.expectError(
        E.BadFormat,
        TraceParent.parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x"),
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

/// The handler half of the dead-frame test below: format the outgoing
/// traceparent into a buffer that dies with THIS frame — exactly what
/// `middlewareRun`'s echo block does — and hand it to `setHeader`. Mirrors
/// `http`'s and `cookies`' own `setFromDeadFrame`.
///
/// A separate `noinline` function, not a block inside the test: Zig gives
/// each local its own slot for the enclosing function's entire body in
/// Debug, so a block scope frees nothing and the bug this guards would stay
/// invisible. Only a returned frame is really reusable.
noinline fn setFromDeadFrame(res: *http.Server.ResponseWriter) !void {
    var out_buf: [TraceParent.header_len]u8 = undefined;
    const tp = try TraceParent.parse(sample);
    try res.setHeader(default_traceparent_header, tp.write(&out_buf));
}

/// Reuse the frame `setFromDeadFrame` just left, the way the next call down
/// the stack would have. `noinline` + `doNotOptimizeAway` so neither the
/// call nor the stores can be optimized out.
noinline fn clobberDeadFrame() void {
    var scratch: [2048]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "TraceContext echo: traceparent header survives the caller's dead frame" {
    // What this pins: `middlewareRun`'s echo block formats the outgoing
    // traceparent into `out_buf`, a plain local that dies once
    // `middlewareRun` returns -- well before `end()` runs (`writeHead` runs
    // inside `end()`, which both servers call only after the whole handler
    // chain has returned). `out_buf` was `threadlocal` until 2026-08-12
    // specifically so it would outlive the response regardless of copying;
    // now that it is a plain local (see the module doc's "Memory /
    // concurrency" section), this module leans entirely on `http`'s
    // `ResponseWriter.dupe` copying header bytes into its own storage rather
    // than borrowing the caller's.
    //
    // Nothing else in this module's suite pins that on purpose -- `runWire`
    // drives `middlewareRun` through the full router/server dispatch with no
    // seam between the echo block returning and `end()` running in which to
    // clobber the stack deliberately (a mutation removing the copy can
    // *happen* to corrupt the header there today by accident, depending on
    // what the dispatch path's own stack traffic leaves behind, but that is
    // not a reliable anchor). So the writer is built and driven by hand
    // here, mirroring `http`'s and `cookies`' own dead-frame tests.
    var out_buf: [512]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try setFromDeadFrame(&rw);
    clobberDeadFrame();

    try rw.writeAll("ok");
    try rw.end();
    const wire = out.buffered();

    // The traceparent header, read back off the wire after every byte of its
    // source was overwritten.
    try testing.expect(std.mem.indexOf(u8, wire, "traceparent: " ++ sample ++ "\r\n") != null);
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.indexOf(u8, wire, "#") == null);
}

// See w3c_conformance_test.zig / w3c_vectors.zig / NOTICE.
test {
    _ = @import("w3c_vectors.zig");
    _ = @import("w3c_conformance_test.zig");
}

// ── fuzz: TraceParent.parse never panics on arbitrary or shaped bytes ──────
//
// `TraceParent.parse` is the decode entry point for a `traceparent` header —
// attacker-controlled bytes off the wire. It is allocation-free (the result
// is a fixed-size value), so there is no leak oracle to run here; the
// property under test is "never panics or reads out of bounds" across pure
// garbage, plus input shaped like `version-traceid-parentid-flags` with each
// field's length, hex-ness and delimiter independently perturbed — arbitrary
// bytes essentially never land on `header_len` (55) with dashes in the right
// three places, so without shaping this harness would only ever exercise the
// very first length check.
const traceparent_corpus = [_][]const u8{
    sample,
    "00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace-id
    "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // all-zero parent-id
    "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // reserved version
    "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-somethingnew", // future ext
};

test "fuzz: TraceParent.parse never panics, arbitrary or traceparent-shaped bytes" {
    try std.testing.fuzz({}, fuzzParseNeverPanics, .{ .corpus = &traceparent_corpus });
}

fn fuzzParseNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    const input = buildTraceparent(smith, &buf);
    _ = TraceParent.parse(input) catch return;
}

/// One draw in eight is pure arbitrary bytes; the rest assemble
/// `version-traceid-parentid-flags` field by field, each field independently
/// its nominal length / off by one, and each delimiter usually `-` but
/// sometimes not.
fn buildTraceparent(smith: *std.testing.Smith, buf: []u8) []const u8 {
    if (smith.valueRangeAtMost(u8, 0, 7) == 0) {
        var raw: [128]u8 = undefined;
        smith.bytes(&raw);
        const len = smith.valueRangeAtMost(u8, 0, @intCast(raw.len));
        @memcpy(buf[0..len], raw[0..len]);
        return buf[0..len];
    }
    var w: std.Io.Writer = .fixed(buf);
    writeField(smith, &w, 2); // version
    writeDelim(smith, &w);
    writeField(smith, &w, 32); // trace-id
    writeDelim(smith, &w);
    writeField(smith, &w, 16); // parent-id
    writeDelim(smith, &w);
    writeField(smith, &w, 2); // flags
    // Occasionally a trailing extension, as a future version may carry.
    if (smith.value(bool)) {
        w.writeByte('-') catch return w.buffered();
        writeField(smith, &w, smith.valueRangeAtMost(u8, 0, 12));
    }
    return w.buffered();
}

fn writeDelim(smith: *std.testing.Smith, w: *std.Io.Writer) void {
    const c: u8 = if (smith.valueRangeAtMost(u8, 0, 9) == 0) '_' else '-';
    w.writeByte(c) catch {};
}

fn writeField(smith: *std.testing.Smith, w: *std.Io.Writer, nominal_len: u8) void {
    const delta: i16 = switch (smith.valueRangeAtMost(u8, 0, 9)) {
        0 => -1,
        1 => 1,
        else => 0,
    };
    const len: u8 = @intCast(std.math.clamp(@as(i16, nominal_len) + delta, 0, 48));
    var i: u8 = 0;
    while (i < len) : (i += 1) {
        w.writeByte(fieldByte(smith)) catch return;
    }
}

/// Mostly a valid lowercase hex digit; sometimes uppercase hex (invalid per
/// spec — lowercase is mandated) or a fully arbitrary byte.
fn fieldByte(smith: *std.testing.Smith) u8 {
    return switch (smith.valueRangeAtMost(u8, 0, 9)) {
        0...6 => hex_digits[smith.index(hex_digits.len)],
        7 => std.ascii.toUpper(hex_digits[smith.index(hex_digits.len)]),
        else => smith.value(u8),
    };
}
