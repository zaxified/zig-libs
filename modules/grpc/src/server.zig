// SPDX-License-Identifier: MIT

//! The gRPC **server**: a routing table, one call object, and the response
//! contract — over the `http` module's HTTP/2 server.
//!
//! The client in `call.zig` argues that all four call shapes are one engine
//! used differently, because on the wire they are the same thing. The same
//! is true here, so this file has one `Call` and four *typed wrappers*, not
//! four engines.
//!
//! ## The response contract, and the trap in it
//!
//! A gRPC response has exactly two legal shapes, and they are not variants of
//! each other:
//!
//! ```text
//! normal        HEADERS(:status 200, content-type, Trailer)
//!               DATA…                      (length-prefixed messages)
//!               HEADERS(grpc-status, …)    END_STREAM   ← a TRAILER section
//!
//! Trailers-Only HEADERS(:status 200, content-type, grpc-status, …) END_STREAM
//! ```
//!
//! In the second one `grpc-status` is a **header**, not a trailer, and there
//! is no DATA frame and no trailer section at all — the spec's grammar says
//! so outright (`Trailers-Only → HTTP-Status Content-Type Trailers`, a single
//! field block). A client that waits for a trailer section after a
//! Trailers-Only response waits forever, and a server that emits an empty
//! DATA frame or a second field block on that path is not sending
//! Trailers-Only however similar the field values look.
//!
//! **How the two are kept apart here.** There is exactly one predicate:
//! `Call.head_committed`. It flips in exactly one place, `Call.commitHead`,
//! which is reached only from `Call.send` and `Call.sendInitialMetadata` —
//! i.e. only when something has irrevocably gone out ahead of the status.
//! `Call.finish` then branches on it once:
//!
//!   * not committed → the status pair and all metadata are set with
//!     `setHeader`, nothing is written to the body, and `declareTrailers` is
//!     never called. `ResponseWriter` therefore keeps identity framing and
//!     the h2 framer puts END_STREAM on the response HEADERS: one field
//!     block, no DATA, no trailer section.
//!   * committed → `commitHead` already called `declareTrailers`, so the
//!     status pair is set with `setTrailer` and travels in the trailing
//!     HEADERS frame, which is where END_STREAM lives instead.
//!
//! That is the same rule the reference implementation uses ("no headers sent
//! yet ⇒ trailers-only"), which is why a *successful* call that produced no
//! messages is Trailers-Only too, not an empty body with a trailer section.
//!
//! ## The security-critical part
//!
//! Inbound message lengths come off the wire, and the property `frame.zig`
//! guarantees — *the declared length never sizes an allocation* — is the
//! server's property here just as it is the client's, because it is the same
//! `Deframer`. `Options.max_recv_message_size` is checked the instant a
//! 5-byte header completes, so a request frame claiming 4 GiB fails the call
//! with `RESOURCE_EXHAUSTED` having buffered five bytes. `adversarial.zig`
//! drives that against the server path specifically.
//!
//! ## What is deliberately not here
//!
//! *Preemptive deadlines.* `grpc-timeout` is parsed, surfaced to the handler
//! (`Call.deadline`, `Call.remaining`, `Call.expired`) and enforced at every
//! engine boundary — before dispatch, around each `receive`, before each
//! `send`. It cannot be enforced *during* a blocking body read: handlers run
//! on the connection's task and the h2 request-body reader has no deadline
//! hook, so a handler that blocks forever on a peer that never sends blocks
//! the connection — unless the application installs
//! `Server.Options.h2_dispatcher`, which moves handlers onto a bounded pool
//! and keeps the connection's read side live (it still does not *cancel* the
//! blocked handler). `http`'s own `read_timeout_ms` / `request_timeout_ms` are
//! the backstop for that, and they are transport-level, not per-call. The
//! clock is injected (`Options.clock`) so none of the above needs a real one
//! under test.
//!
//! *HTTP/1.1 rejection.* gRPC requires HTTP/2; the reference implementations
//! answer 505 for a gRPC request that arrives over HTTP/1.1. `http`'s
//! handler-facing `Request` exposes no protocol discriminator (the h2 loop
//! synthesizes an h1-shaped head on purpose, which is what lets one handler
//! serve both), so that answer is not available from here without changing
//! `http`. Wire the router with `httpOptions`/`h2ServerOptions` and the
//! question does not arise.
//!
//! Provenance: clean-room from the published `grpc-over-http2` protocol
//! specification and `doc/compression.md` (both public specifications —
//! CONVENTIONS.md §5); no gRPC implementation source was ported or studied.
//! The Python `grpcio` package is run as a black-box test oracle only.

const std = @import("std");
const http = @import("http");
const pb = @import("protobuf");

const frame = @import("frame.zig");
const status_mod = @import("status.zig");
const metadata = @import("metadata.zig");
const call_mod = @import("call.zig");

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Status = status_mod.Status;
const Timeout = call_mod.Timeout;
const Entry = metadata.Entry;

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source for `grpc-timeout` enforcement, injected so a
/// deadline test never has to sleep. Implementations must be non-decreasing;
/// only differences are used.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// CLOCK_MONOTONIC via the posix `clock_gettime` errno form — the
    /// production default and the only place this file touches the OS.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS)
        return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ── options ─────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Hard ceiling on a single **received** message, enforced against the
    /// length declared on the wire before any of its payload is accepted.
    /// gRPC's own default, and ours, is 4 MiB. This is a *message* bound;
    /// `http.Server.Options.max_body_bytes` separately bounds the whole
    /// request, and both apply.
    max_recv_message_size: u32 = frame.default_max_recv_message_size,
    /// Ceiling on a single **sent** message; null = no local limit.
    max_send_message_size: ?u32 = null,
    /// Bytes read from the HTTP/2 body per read before deframing. Not a
    /// message limit: a larger message is simply reassembled over reads.
    read_chunk: usize = 16 * 1024,
    /// Monotonic clock for `grpc-timeout`.
    clock: Clock = .monotonic,
    /// Whether an expired deadline fails the call (`DEADLINE_EXCEEDED`) at
    /// the engine boundaries. Off, `grpc-timeout` is still parsed and
    /// surfaced — the handler decides.
    enforce_deadline: bool = true,
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const CallError = status_mod.StatusError || metadata.DecodeError || error{
    /// The request body could not be read: the peer reset the stream, the
    /// connection died, or `max_body_bytes` was crossed.
    RequestFailed,
    /// The response could not be written (peer reset, connection gone).
    ResponseFailed,
    /// The request stream ended in the middle of a length-prefixed message.
    TruncatedRequest,
    /// A declared request-message length exceeded `max_recv_message_size`.
    MessageTooLarge,
    /// A request message carried the compressed flag; this build negotiated
    /// identity only, so it is refused rather than handed to a decoder.
    CompressedUnsupported,
    /// A response message exceeds `Options.max_send_message_size`.
    SendMessageTooLarge,
    /// A handler-supplied metadata entry collides with a field this layer
    /// owns (`grpc-status`, `content-type`, …).
    ReservedMetadata,
    /// More trailing-metadata names than the response can advertise, or an
    /// invalid field name/value.
    BadMetadata,
    /// `setTrailingMetadata` for a name that was never declared (see
    /// `declareTrailingMetadata`).
    TrailerNotDeclared,
    OutOfMemory,
};

// ── the routing table ───────────────────────────────────────────────────────

/// One method: a name, and the untyped engine-level implementation. Build
/// these with `Methods(Req, Rep)` for a protobuf schema, or `Method.raw` for
/// another codec.
pub const Method = struct {
    /// The bare method name — the part after the last `/` in `:path`.
    name: []const u8,
    run: *const fn (*Call) anyerror!void,

    /// A method whose messages are opaque byte slices: `Call.receive` hands
    /// them over and `Call.send` takes them. The escape hatch for a codec
    /// other than protobuf, and what the typed wrappers are built on.
    pub fn raw(name: []const u8, comptime f: fn (*Call) anyerror!void) Method {
        return .{ .name = name, .run = f };
    }
};

/// One service: the `{Service}` half of `/{Service}/{Method}`, fully
/// qualified exactly as the `.proto` package spells it (e.g. `echo.Echo`).
pub const Service = struct {
    name: []const u8,
    methods: []const Method,
};

/// The gRPC server: a table of services plus policy, wired into
/// `http.Server` (or `http.h2_server`) with `httpOptions`/`h2ServerOptions`.
///
/// ## Why registration is a data table and not comptime reflection
///
/// The obvious Zig move is `Service(MyImpl)` — reflect over a struct's decls
/// and derive the table. It was rejected for one concrete reason: **the call
/// shape cannot be read off a Zig signature without guessing.** A `.proto`
/// service says `rpc M(stream Req) returns (Rep)`; a Zig function says
/// `fn(*Stream) !Rep`, and inferring "client-streaming" from that means an
/// accidental signature change silently rewrites the wire contract of a
/// published method. Here each shape is named at the call site
/// (`Methods(Req, Rep).clientStreaming(...)`), so the contract is written
/// down and a mismatched implementation is a compile error rather than a
/// different RPC.
///
/// Two smaller reasons: a service definition is *data* in every other gRPC
/// stack (it comes from a `.proto`), so a table maps onto it one-to-one and
/// is what a code generator would emit; and a table can be assembled at
/// runtime — a server that mounts services from configuration cannot express
/// that as a type. Nothing is lost: the methods themselves are still
/// comptime-typed, with the schema derived from the Zig structs exactly as
/// the client does it.
///
/// Concurrency: a `Router` is **immutable while serving** and every field is
/// read-only on the serving path, so one may back any number of connections
/// — including `http.Server`'s multicore accept engine — provided `gpa` is
/// thread-safe and the handlers are. Mutating `services` or `options` while
/// `serve` is running is not supported.
pub const Router = struct {
    /// Backs each call's arena and the deframer's reassembly buffer. Must be
    /// thread-safe if more than one connection is served at a time.
    gpa: Allocator,
    services: []const Service,
    options: Options = .{},
    /// Passed to every handler as `Call.context` — the seam for server
    /// state, since a `Method` is a plain function pointer.
    context: ?*anyopaque = null,

    /// `http.Server.Options` wired for gRPC: the handler, the context and
    /// the streaming predicate all have to agree about which router they
    /// mean, and this is the one place that can guarantee it. `base` carries
    /// everything else (address, timeouts, limits).
    ///
    /// `enable_h2c` is forced on: gRPC is HTTP/2 only, and prior-knowledge
    /// h2c is how the built-in accept loop speaks it. For gRPC over TLS,
    /// terminate TLS yourself and call `h2_server.serveStream` with
    /// `h2ServerOptions` instead.
    pub fn httpOptions(r: *Router, base: http.Server.Options) http.Server.Options {
        var o = base;
        o.handler = handleHttp;
        o.context = r;
        o.h2_stream_request = streamRequest;
        o.enable_h2c = true;
        return o;
    }

    /// `h2_server.Options` wired for gRPC — the bring-your-own-TLS seam
    /// (`h2_server.serveStream`), same guarantee as `httpOptions`.
    pub fn h2ServerOptions(r: *Router, base: http.h2_server.Options) http.h2_server.Options {
        var o = base;
        o.handler = handleHttp;
        o.context = r;
        o.stream_request = streamRequest;
        return o;
    }

    /// `Options.h2_stream_request`: every `application/grpc*` request takes
    /// the incremental body, because buffering one would make
    /// client-streaming and bidirectional calls impossible (the handler
    /// could not see message #1 until the client had sent its last). A
    /// non-gRPC request keeps the buffered surface, so a server that also
    /// serves ordinary HTTP through a different handler is unaffected.
    pub fn streamRequest(ctx: ?*anyopaque, preview: http.Server.H2RequestPreview) bool {
        _ = ctx;
        const m = preview.method() orelse return false;
        if (m != .post) return false;
        const ct = preview.get("content-type") orelse return false;
        return grpcContentType(ct) != null;
    }

    fn find(r: *const Router, service: []const u8, method: []const u8) ?*const Method {
        for (r.services) |*s| {
            if (!std.mem.eql(u8, s.name, service)) continue;
            for (s.methods) |*m| {
                if (std.mem.eql(u8, m.name, method)) return m;
            }
            return null;
        }
        return null;
    }

    fn hasService(r: *const Router, service: []const u8) bool {
        for (r.services) |s| {
            if (std.mem.eql(u8, s.name, service)) return true;
        }
        return false;
    }
};

/// `http.Server.Handler` — the entry point `httpOptions` installs.
pub fn handleHttp(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const ctx = req.context orelse return error.NoGrpcRouter;
    const r: *const Router = @ptrCast(@alignCast(ctx));
    return serve(r, req, rw);
}

/// Serve one request against `r`. Public so a caller who routes gRPC and
/// plain HTTP through one handler can delegate the gRPC paths here.
pub fn serve(
    r: *const Router,
    req: *http.Server.Request,
    rw: *http.Server.ResponseWriter,
) anyerror!void {
    // ── the two answers that are HTTP-level, not gRPC-level ─────────────
    // Both are given *before* a `Call` exists, and neither carries a
    // `grpc-status`: a gRPC error response is HTTP 200, so a peer that got
    // this far without speaking gRPC must be told in HTTP's own vocabulary
    // or it would read a failure as a success.
    if (req.method != .post) {
        // Call-Definition: `Method → ":method POST"`. 405 + Allow is the
        // HTTP answer for a method a resource does not support.
        rw.setStatus(405);
        try rw.setHeader("Allow", "POST");
        try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
        try rw.writeAll("gRPC requires POST\n");
        return;
    }
    const ct = grpcContentType(req.header("content-type") orelse "") orelse {
        // Spec: "If Content-Type does not begin with 'application/grpc',
        // gRPC servers SHOULD respond with HTTP status of 415 (Unsupported
        // Media Type)." — precisely so a non-gRPC HTTP/2 client does not
        // read our 200-with-an-error as success.
        rw.setStatus(415);
        try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
        try rw.writeAll("unsupported content-type: gRPC requires application/grpc\n");
        return;
    };

    var arena_state: std.heap.ArenaAllocator = .init(r.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var call: Call = .{
        .router = r,
        .gpa = r.gpa,
        .arena = arena,
        .req = req,
        .rw = rw,
        .content_type = ct,
        .de = .{ .max_recv_message_size = r.options.max_recv_message_size },
        .read_buf = try arena.alloc(u8, @max(frame.header_len, r.options.read_chunk)),
    };
    defer call.deinit();

    dispatch(r, &call) catch |err| call.adoptError(err);
    call.finish();
    // No `ResponseWriter.end` here. It used to run ahead of the serving
    // loop's, purely so it beat `arena_state.deinit()` (the `defer` above) to
    // the metadata `finish` had just handed `setHeader`/`setTrailer` — the
    // status digits, the percent-encoded message, the trailing metadata.
    // Those two copy their bytes into the writer now, so the arena dying with
    // this frame no longer reaches anything already set, and gRPC gains
    // nothing from committing the head early: the response body is in the
    // writer's own buffer (or already framed onto the wire), and every
    // trailer this module cares about is set above, not after.
}

fn dispatch(r: *const Router, c: *Call) anyerror!void {
    // Message-Encoding: this build negotiated identity only. A message
    // compressed with anything else is UNIMPLEMENTED, and the answer must
    // carry `grpc-accept-encoding` so the peer learns what would work
    // (doc/compression.md).
    if (c.req.header("grpc-encoding")) |enc| {
        if (!std.ascii.eqlIgnoreCase(enc, "identity")) {
            c.accept_encoding_in_status = true;
            return c.failFmt(
                .unimplemented,
                "grpc: no decompressor available for grpc-encoding \"{s}\"",
                .{enc},
            );
        }
    }

    // Timeout → deadline. A malformed value is not ignorable: silently
    // dropping it would run a call the client believes is bounded.
    if (c.req.header("grpc-timeout")) |raw| {
        const t = Timeout.parse(raw) orelse
            return c.failFmt(.internal, "malformed grpc-timeout: \"{s}\"", .{raw});
        c.timeout = t;
        c.deadline_ns = r.options.clock.now() +| timeoutNanos(t);
    }

    const split = splitPath(c.req.path) orelse
        return c.failFmt(.unimplemented, "malformed method name: \"{s}\"", .{c.req.path});
    c.service = split.service;
    c.method = split.method;

    const m = r.find(split.service, split.method) orelse {
        if (r.hasService(split.service))
            return c.failFmt(
                .unimplemented,
                "unknown method {s} for service {s}",
                .{ split.method, split.service },
            );
        return c.failFmt(.unimplemented, "unknown service {s}", .{split.service});
    };

    // Already past the deadline before a byte of work: answer rather than
    // run the handler and discard its result.
    try c.checkDeadline();
    return m.run(c);
}

// ── one call ────────────────────────────────────────────────────────────────

/// One RPC, server side. Receive with `receive` until it returns null, send
/// with `send`, fail with `fail`/`failFmt`. All four call shapes are this
/// object used differently — see `Methods` for the typed wrappers.
pub const Call = struct {
    router: *const Router,
    gpa: Allocator,
    /// Request-scoped: message buffers, formatted status/trailer text and
    /// similar per-call scratch live here. `setHeader`/`setTrailer` copy
    /// their bytes into the `ResponseWriter`'s own storage at call time, so
    /// values handed to them don't strictly need to live past that call —
    /// this arena is sized for the call's other allocations regardless.
    arena: Allocator,
    req: *http.Server.Request,
    rw: *http.Server.ResponseWriter,
    /// The response `content-type`, echoing the request's grpc flavour.
    content_type: []const u8,

    /// `{Service}` and `{Method}` from `:path`, once routed.
    service: []const u8 = "",
    method: []const u8 = "",

    de: frame.Deframer,
    read_buf: []u8,
    recv_done: bool = false,

    /// **The Trailers-Only predicate.** False ⇒ nothing has gone out ahead
    /// of the status, so the whole response is one field block. True ⇒ the
    /// response HEADERS are on the wire and the status must travel in a
    /// trailer section. Flipped only by `commitHead`.
    head_committed: bool = false,
    /// The response side is broken; nothing more may be written.
    write_failed: bool = false,

    initial_md: std.ArrayList(Entry) = .empty,
    trailing_md: std.ArrayList(Entry) = .empty,
    /// Extra trailer field names advertised at `commitHead`.
    declared_md: std.ArrayList([]const u8) = .empty,

    status: Status = .ok,
    status_message: []const u8 = "",
    /// The status was chosen deliberately (`fail`), so a later error must
    /// not overwrite it.
    status_set: bool = false,
    /// Emit `grpc-accept-encoding` with the status (the compression spec
    /// requires it on the UNIMPLEMENTED answer to an unknown encoding).
    accept_encoding_in_status: bool = false,

    timeout: ?Timeout = null,
    deadline_ns: ?u64 = null,

    messages_received: usize = 0,
    messages_sent: usize = 0,

    fn deinit(c: *Call) void {
        c.de.deinit(c.gpa);
        // Everything else lives in the request arena.
    }

    // ── what the handler is given ───────────────────────────────────────

    /// `Router.context`.
    pub fn context(c: *const Call) ?*anyopaque {
        return c.router.context;
    }

    /// First value of a request metadata field, in its **wire** form (still
    /// base64 for a `-bin` key — `metadataValueDecoded` undoes that).
    pub fn metadataValue(c: *const Call, name: []const u8) ?[]const u8 {
        return c.req.header(name);
    }

    /// `metadataValue`, base64-decoded for a `-bin` key. `Decoded.owned`
    /// says whether the result must be released.
    pub fn metadataValueDecoded(c: *const Call, name: []const u8) CallError!?metadata.Decoded {
        const raw = c.metadataValue(name) orelse return null;
        return try metadata.decodeValue(c.gpa, name, raw);
    }

    /// The parsed `grpc-timeout`, or null when the client set no deadline.
    pub fn callTimeout(c: *const Call) ?Timeout {
        return c.timeout;
    }

    /// Nanoseconds left before the deadline, or null when there is none.
    /// Zero once it has passed.
    pub fn remaining(c: *const Call) ?u64 {
        const dl = c.deadline_ns orelse return null;
        const now = c.router.options.clock.now();
        return if (now >= dl) 0 else dl - now;
    }

    /// Whether the deadline has passed (false when there is none).
    pub fn expired(c: *const Call) bool {
        const left = c.remaining() orelse return false;
        return left == 0;
    }

    // ── receive ─────────────────────────────────────────────────────────

    /// The next request message, or null once the request side is complete.
    ///
    /// The slice is **borrowed** from the call's reassembly buffer and is
    /// valid until the next `receive` — decode or copy it first.
    pub fn receive(c: *Call) CallError!?[]const u8 {
        if (c.recv_done) return null;
        while (true) {
            if (c.de.next() catch |e| return mapFrameError(e)) |msg| {
                c.messages_received += 1;
                return msg;
            }
            try c.checkDeadline();
            var w: Writer = .fixed(c.read_buf);
            const n = c.req.reader().stream(&w, .limited(c.read_buf.len)) catch |err| switch (err) {
                error.EndOfStream => {
                    // A stream that stops mid-message is a truncated
                    // request, not an empty one.
                    c.de.endOfStream() catch |e| return mapFrameError(e);
                    c.recv_done = true;
                    return null;
                },
                else => return error.RequestFailed,
            };
            if (n == 0) continue;
            c.de.push(c.gpa, w.buffered()) catch |e| return mapFrameError(e);
        }
    }

    // ── send ────────────────────────────────────────────────────────────

    /// Frame and send one response message. The first call commits the
    /// response head, which is what takes the Trailers-Only shape off the
    /// table for the rest of this call.
    pub fn send(c: *Call, message: []const u8) CallError!void {
        if (c.router.options.max_send_message_size) |limit| {
            if (message.len > limit) return error.SendMessageTooLarge;
        }
        if (message.len > std.math.maxInt(u32)) return error.SendMessageTooLarge;
        try c.checkDeadline();
        try c.commitHead();
        var hdr: [frame.header_len]u8 = undefined;
        frame.writeHeader(&hdr, false, @intCast(message.len));
        c.rw.writeAll(&hdr) catch return c.writeDied();
        c.rw.writeAll(message) catch return c.writeDied();
        // Each message is pushed all the way out: a server-streaming reply
        // that sits in the response buffer until the handler returns is not
        // a stream. With a trailer section coming, this costs nothing on
        // the wire — END_STREAM rides the trailing HEADERS either way.
        c.rw.flush() catch return c.writeDied();
        c.messages_sent += 1;
    }

    /// Stage an initial-metadata field. Must precede the first `send` /
    /// `sendInitialMetadata`; reserved names are refused so a handler
    /// cannot forge `grpc-status` or the framing fields.
    pub fn addInitialMetadata(c: *Call, entry: Entry) CallError!void {
        if (c.head_committed) return error.ResponseFailed;
        if (metadata.isReserved(entry.name)) return error.ReservedMetadata;
        try c.initial_md.append(c.arena, try c.encodeEntry(entry));
    }

    /// Send the response head now, with whatever initial metadata is
    /// staged. Optional — `send` does it. Calling it commits the response
    /// to the normal (non-Trailers-Only) shape even if no message ever
    /// follows, which is the point: a handler that wants the client to see
    /// initial metadata before the first message has to say so.
    pub fn sendInitialMetadata(c: *Call) CallError!void {
        return c.commitHead();
    }

    /// Advertise trailing-metadata field names. Must precede the first
    /// `send`: the advert rides in the response head (RFC 9110 §6.6.2), and
    /// `ResponseWriter` refuses a trailer that was never advertised. The
    /// *values* are still set at the end — that is what a trailer is for.
    ///
    /// Not needed on the Trailers-Only path, where every field is a header;
    /// declaring names costs nothing there.
    pub fn declareTrailingMetadata(c: *Call, names: []const []const u8) CallError!void {
        if (c.head_committed) return error.ResponseFailed;
        for (names) |n| {
            if (metadata.isReserved(n)) return error.ReservedMetadata;
            try c.declared_md.append(c.arena, n);
        }
    }

    /// Set a trailing-metadata field. Legal at any point before the handler
    /// returns. On the normal path the name must have been advertised with
    /// `declareTrailingMetadata`; on the Trailers-Only path it becomes a
    /// header, exactly as the reference implementation merges them.
    pub fn setTrailingMetadata(c: *Call, entry: Entry) CallError!void {
        if (metadata.isReserved(entry.name)) return error.ReservedMetadata;
        if (c.head_committed and !c.rw.declaredTrailer(entry.name))
            return error.TrailerNotDeclared;
        try c.trailing_md.append(c.arena, try c.encodeEntry(entry));
    }

    // ── failing ─────────────────────────────────────────────────────────

    /// Fail the call with `s` and a human-readable `message`. Returns the
    /// matching error so the handler body reads `return call.fail(…)`.
    ///
    /// `message` is **copied** into the call's arena. That is not politeness:
    /// the natural thing to fail with is a string from the decoded request,
    /// and the decoded request is released when the handler returns —
    /// i.e. before the status reaches the wire. Storing the slice would be a
    /// use-after-free in the most obvious usage there is.
    pub fn fail(c: *Call, s: Status, message: []const u8) status_mod.StatusError {
        std.debug.assert(s != .ok);
        c.status = s;
        c.status_message = c.arena.dupe(u8, message) catch "";
        c.status_set = true;
        return status_mod.toError(s);
    }

    /// `fail` with a message formatted into the call's arena.
    pub fn failFmt(
        c: *Call,
        s: Status,
        comptime fmt: []const u8,
        args: anytype,
    ) status_mod.StatusError {
        const msg = std.fmt.allocPrint(c.arena, fmt, args) catch "";
        return c.fail(s, msg);
    }

    // ── internals ───────────────────────────────────────────────────────

    fn checkDeadline(c: *Call) CallError!void {
        if (!c.router.options.enforce_deadline) return;
        if (c.deadline_ns == null) return;
        if (!c.expired()) return;
        return c.fail(.deadline_exceeded, "context deadline exceeded");
    }

    fn writeDied(c: *Call) CallError {
        c.write_failed = true;
        return error.ResponseFailed;
    }

    fn encodeEntry(c: *Call, entry: Entry) CallError!Entry {
        const buf = try c.arena.alloc(u8, metadata.encodedValueLen(entry));
        return .{ .name = entry.name, .value = metadata.encodeValue(entry, buf) };
    }

    /// Put the response head on the wire. **The one place `head_committed`
    /// becomes true**, and the one place `declareTrailers` is called — so a
    /// response either has a trailer section and got here, or it does not
    /// and never did.
    fn commitHead(c: *Call) CallError!void {
        if (c.head_committed) return;
        if (c.write_failed) return error.ResponseFailed;
        c.rw.setStatus(200);
        c.rw.setHeader("content-type", c.content_type) catch return c.writeDied();
        c.rw.setHeader("grpc-accept-encoding", "identity") catch return c.writeDied();
        for (c.initial_md.items) |e|
            c.rw.setHeader(e.name, e.value) catch return error.BadMetadata;
        // From here the status has nowhere to live but the trailer section,
        // so it is advertised before the head can escape.
        c.rw.declareTrailers(&.{ "grpc-status", "grpc-message" }) catch
            return c.writeDied();
        for (c.declared_md.items) |n|
            c.rw.declareTrailer(n) catch return error.BadMetadata;
        c.head_committed = true;
    }

    /// Adopt the status a handler's error stands for, unless it already
    /// chose one with `fail`.
    fn adoptError(c: *Call, err: anyerror) void {
        if (err == error.ResponseFailed) c.write_failed = true;
        if (c.status_set) return;
        c.status = statusForError(err);
        c.status_message = @errorName(err);
        c.status_set = true;
    }

    /// What the client is told when response metadata could not be written.
    ///
    /// `finish` returns `void` — it is the last exit — so the status is the
    /// only channel left, and an RPC that silently threw away the metadata it
    /// promised must not read as OK. `commitHead` already takes this line on
    /// the *same* `initial_md` writes (`catch return error.BadMetadata`);
    /// before this, `finish` swallowed them, so which of two identical
    /// failures the client heard about depended only on whether the head had
    /// been committed yet. Derived from the enum rather than written as "13"
    /// so a renumbering cannot desync it.
    const md_lost_code = std.fmt.comptimePrint("{d}", .{@intFromEnum(status_mod.Status.internal)});
    /// Pure ASCII in 0x20-0x7E with no `%`, so `encodeMessage` is the
    /// identity on it and it needs no arena allocation to emit.
    const md_lost_message = "response metadata could not be written";

    /// Emit the status — the single exit through which every response,
    /// successful or not, leaves this module.
    fn finish(c: *Call) void {
        if (c.write_failed) return; // the stream is gone; nothing can be said
        const code = std.fmt.allocPrint(c.arena, "{d}", .{@intFromEnum(c.status)}) catch return;
        const message: ?[]const u8 = if (c.status_message.len == 0) null else blk: {
            const buf = c.arena.alloc(u8, status_mod.encodedMessageLen(c.status_message)) catch
                break :blk null;
            break :blk status_mod.encodeMessage(c.status_message, buf);
        };

        if (!c.head_committed) {
            // ── Trailers-Only ──
            // One field block, END_STREAM on it, no DATA frame and no
            // trailer section. Every field here is a HEADER: `setHeader`,
            // never `setTrailer`, and `declareTrailers` is not called — the
            // moment it were, `ResponseWriter` would switch to chunked
            // framing and this would stop being Trailers-Only.
            c.rw.setStatus(200);
            c.rw.setHeader("content-type", c.content_type) catch return;
            if (c.accept_encoding_in_status)
                c.rw.setHeader("grpc-accept-encoding", "identity") catch return;
            var head_md_lost = false;
            for (c.initial_md.items) |e|
                c.rw.setHeader(e.name, e.value) catch {
                    head_md_lost = true;
                };
            for (c.trailing_md.items) |e|
                c.rw.setHeader(e.name, e.value) catch {
                    head_md_lost = true;
                };
            c.rw.setHeader("grpc-status", if (head_md_lost) md_lost_code else code) catch return;
            // `grpc-message` is optional (gRPC over HTTP/2: the machine-
            // readable half is `grpc-status`, which is already on the head by
            // now). Best-effort DELIBERATELY, and the client still learns
            // something went wrong from the status itself.
            const head_msg: ?[]const u8 = if (head_md_lost) md_lost_message else message;
            if (head_msg) |m| c.rw.setHeader("grpc-message", m) catch {};
            return; // no body: `ResponseWriter.end` frames it bodiless
        }

        // ── the normal shape: the status is a TRAILER ──
        var trailer_md_lost = false;
        for (c.trailing_md.items) |e|
            c.rw.setTrailer(e.name, e.value) catch {
                trailer_md_lost = true;
            };
        c.rw.setTrailer("grpc-status", if (trailer_md_lost) md_lost_code else code) catch return;
        const trailer_msg: ?[]const u8 = if (trailer_md_lost) md_lost_message else message;
        if (trailer_msg) |m| c.rw.setTrailer("grpc-message", m) catch {};
    }
};

// ── the typed surface ───────────────────────────────────────────────────────

/// Typed methods over a protobuf request/reply pair — the server mirror of
/// the client's `Stream(Req, Rep)`. `Req` and `Rep` are ordinary Zig structs
/// with a `pb_fields` descriptor; the schema is derived at compile time.
///
/// ```zig
/// const M = grpc.Methods(EchoRequest, EchoReply);
/// const echo: grpc.Service = .{ .name = "echo.Echo", .methods = &.{
///     M.unary("Unary", unaryImpl),
///     M.serverStreaming("ServerStream", serverStreamImpl),
///     M.clientStreaming("ClientStream", clientStreamImpl),
///     M.bidiStreaming("Bidi", bidiImpl),
/// } };
/// ```
pub fn Methods(comptime Req: type, comptime Rep: type) type {
    return struct {
        /// The typed view of a call handed to a streaming method.
        pub const Stream = struct {
            call: *Call,
            /// Decode options for received messages (nesting cap, unknown
            /// fields). The default already refuses a hostile nesting depth.
            decode_options: pb.DecodeOptions = .{},

            /// The next request message, or null at the end of the request
            /// side. The result owns an arena; `deinit` it.
            pub fn receive(s: *Stream) !?pb.Decoded(Req) {
                const bytes = try s.call.receive() orelse return null;
                return try pb.decode(Req, s.call.gpa, bytes, s.decode_options);
            }

            /// Encode and send one reply. The encoding buffer is released
            /// immediately, so a stream of a million replies costs one of
            /// them — the call arena would otherwise hold every byte until
            /// the RPC ended.
            pub fn send(s: *Stream, value: Rep) !void {
                const bytes = try pb.encodeAlloc(s.call.gpa, value, .{});
                defer s.call.gpa.free(bytes);
                return s.call.send(bytes);
            }
        };

        /// One request, one reply. "Exactly one request" is enforced: a
        /// client that sends none or two has broken the unary contract, and
        /// acting on the first of two is how a server answers the wrong
        /// question.
        pub fn unary(name: []const u8, comptime f: fn (*Call, Req) anyerror!Rep) Method {
            const Impl = struct {
                fn run(c: *Call) anyerror!void {
                    var s: Stream = .{ .call = c };
                    var got = try s.receive() orelse
                        return c.fail(.internal, "unary request carried no message");
                    defer got.deinit();
                    if (try s.receive()) |extra| {
                        var e = extra;
                        e.deinit();
                        return c.fail(.internal, "unary request carried more than one message");
                    }
                    return s.send(try f(c, got.value));
                }
            };
            return .{ .name = name, .run = Impl.run };
        }

        /// One request, a stream of replies.
        pub fn serverStreaming(
            name: []const u8,
            comptime f: fn (*Stream, Req) anyerror!void,
        ) Method {
            const Impl = struct {
                fn run(c: *Call) anyerror!void {
                    var s: Stream = .{ .call = c };
                    var got = try s.receive() orelse
                        return c.fail(.internal, "server-streaming request carried no message");
                    defer got.deinit();
                    if (try s.receive()) |extra| {
                        var e = extra;
                        e.deinit();
                        return c.fail(.internal, "server-streaming request carried more than one message");
                    }
                    return f(&s, got.value);
                }
            };
            return .{ .name = name, .run = Impl.run };
        }

        /// A stream of requests, one reply. The handler drains `receive`
        /// to null and returns the reply, which the engine sends.
        pub fn clientStreaming(name: []const u8, comptime f: fn (*Stream) anyerror!Rep) Method {
            const Impl = struct {
                fn run(c: *Call) anyerror!void {
                    var s: Stream = .{ .call = c };
                    return s.send(try f(&s));
                }
            };
            return .{ .name = name, .run = Impl.run };
        }

        /// Streams both ways, interleaved as the handler pleases.
        pub fn bidiStreaming(name: []const u8, comptime f: fn (*Stream) anyerror!void) Method {
            const Impl = struct {
                fn run(c: *Call) anyerror!void {
                    var s: Stream = .{ .call = c };
                    return f(&s);
                }
            };
            return .{ .name = name, .run = Impl.run };
        }
    };
}

// ── small helpers ───────────────────────────────────────────────────────────

/// `application/grpc`, optionally `+subtype` and/or `;parameters`. Returns
/// the canonical value to echo in the response (base + subtype, parameters
/// dropped), or null when this is not a gRPC request at all.
pub fn grpcContentType(ct: []const u8) ?[]const u8 {
    const base = "application/grpc";
    if (ct.len < base.len) return null;
    if (!std.ascii.eqlIgnoreCase(ct[0..base.len], base)) return null;
    if (ct.len == base.len) return ct;
    return switch (ct[base.len]) {
        // `+subtype` runs until a parameter starts.
        '+' => blk: {
            const end = std.mem.indexOfAny(u8, ct, "; ") orelse ct.len;
            break :blk ct[0..end];
        },
        ';', ' ' => ct[0..base.len],
        else => null,
    };
}

pub const PathSplit = struct { service: []const u8, method: []const u8 };

/// `/{Service}/{Method}` → its two halves. The leading slash and the single
/// separator are the whole grammar; anything else is a malformed method
/// name, which is UNIMPLEMENTED rather than a 404 — the call reached a gRPC
/// server, it just named nothing.
pub fn splitPath(path: []const u8) ?PathSplit {
    if (path.len < 2 or path[0] != '/') return null;
    const rest = path[1..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const service = rest[0..slash];
    const method = rest[slash + 1 ..];
    if (service.len == 0 or method.len == 0) return null;
    // A name containing another separator is not a name.
    if (std.mem.indexOfScalar(u8, method, '/') != null) return null;
    return .{ .service = service, .method = method };
}

/// The `grpc-timeout` value in nanoseconds, saturating.
pub fn timeoutNanos(t: Timeout) u64 {
    const scale: u64 = switch (t.unit) {
        .hours => 3600 * std.time.ns_per_s,
        .minutes => 60 * std.time.ns_per_s,
        .seconds => std.time.ns_per_s,
        .milliseconds => std.time.ns_per_ms,
        .microseconds => std.time.ns_per_us,
        .nanoseconds => 1,
    };
    return t.value *| scale;
}

fn mapFrameError(e: frame.Error) CallError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MessageTooLarge => error.MessageTooLarge,
        error.CompressedUnsupported => error.CompressedUnsupported,
        error.TruncatedMessage => error.TruncatedRequest,
    };
}

/// The status an escaping handler error stands for. A `StatusError` keeps
/// its own code; the engine's own faults map to what other implementations
/// return for them; anything else is UNKNOWN, which is what the code is for.
pub fn statusForError(err: anyerror) Status {
    return switch (err) {
        error.Cancelled => .cancelled,
        error.Unknown => .unknown,
        error.InvalidArgument => .invalid_argument,
        error.DeadlineExceeded => .deadline_exceeded,
        error.NotFound => .not_found,
        error.AlreadyExists => .already_exists,
        error.PermissionDenied => .permission_denied,
        error.ResourceExhausted => .resource_exhausted,
        error.FailedPrecondition => .failed_precondition,
        error.Aborted => .aborted,
        error.OutOfRange => .out_of_range,
        error.Unimplemented => .unimplemented,
        error.Internal => .internal,
        error.Unavailable => .unavailable,
        error.DataLoss => .data_loss,
        error.Unauthenticated => .unauthenticated,

        // Over the receive limit is what every implementation calls
        // RESOURCE_EXHAUSTED; so is running out of memory serving the call.
        error.MessageTooLarge, error.OutOfMemory => .resource_exhausted,
        error.SendMessageTooLarge => .resource_exhausted,
        // A compressed request we never advertised support for.
        error.CompressedUnsupported => .unimplemented,
        // Framing faults on the request side: the peer sent something this
        // side cannot make sense of.
        error.TruncatedRequest, error.InvalidBinaryValue => .internal,
        error.RequestFailed => .internal,
        error.ReservedMetadata, error.BadMetadata, error.TrailerNotDeclared => .internal,
        else => .unknown,
    };
}

test {
    _ = @import("server_test.zig");
}
