// SPDX-License-Identifier: MIT

//! The gRPC call engine: one RPC on one HTTP/2 stream.
//!
//! A `Channel` is a thin policy layer over an `http.h2_client.Session` (the
//! multiplexing HTTP/2 client). A `Call` is one stream on it, and *all four*
//! gRPC call shapes are the same object used differently — because on the
//! wire they are the same thing:
//!
//! | shape | request messages | response messages |
//! |---|---|---|
//! | unary | 1, then close | 1, then trailers |
//! | server-streaming | 1, then close | 0..n, then trailers |
//! | client-streaming | 0..n, then close | 1, then trailers |
//! | bidirectional | 0..n, interleaved | 0..n, interleaved |
//!
//! Nothing in the framing distinguishes them; only the service contract
//! does. So there is one engine here, not four, and the typed wrappers in
//! `root.zig` differ only in which calls they make on it.
//!
//! ## The response shape, and the trap in it
//!
//! A normal response is HEADERS → DATA… → TRAILERS, and `grpc-status` is in
//! the **trailers**. But an error usually arrives as **Trailers-Only**: a
//! single HEADERS frame with END_STREAM that carries the status and no body
//! at all. It is the common case, not the rare one — every `abort()` on the
//! server side produces it. A client that waits for a trailer section after
//! a body will wait forever for a response that has neither, so `readHead`
//! checks for `grpc-status` in the *initial* header block first and treats
//! its presence as the whole response.
//!
//! ## Errors
//!
//! A non-OK status is a Zig error, one per code (`status.StatusError`), so
//! it cannot be ignored the way a returned enum can. The human-readable
//! `grpc-message` cannot ride in an error value, so it stays on the call
//! (`statusMessage`) and can be copied out through `CallOptions.failure`.
//!
//! Provenance: clean-room from the published `grpc-over-http2` protocol
//! specification; no gRPC implementation source was consulted or copied.

const std = @import("std");
const http = @import("http");
const status_mod = @import("status.zig");
const frame = @import("frame.zig");
const metadata = @import("metadata.zig");

const Allocator = std.mem.Allocator;
const h2c = http.h2_client;
const hpack = http.hpack;
const Status = status_mod.Status;

/// Everything a call can fail with: the HTTP/2 transport's errors, one error
/// per non-OK gRPC status, and the small set of gRPC-specific framing and
/// protocol faults.
pub const Error = h2c.Error || status_mod.StatusError || metadata.DecodeError || error{
    /// The response ended without a `grpc-status` anywhere — neither in the
    /// trailers nor in an initial Trailers-Only block. The peer is broken;
    /// this is deliberately not silently promoted to OK.
    MissingStatus,
    /// `grpc-status` was present but not a bare decimal number.
    MalformedStatus,
    /// The response `content-type` is not an `application/grpc` flavour.
    NotGrpc,
    /// A unary response carried no message, or a second one where the
    /// contract allows exactly one.
    MissingMessage,
    UnexpectedMessage,
    /// An outgoing message exceeds `Options.max_send_message_size`.
    SendMessageTooLarge,
    /// A caller-supplied metadata entry collides with a header this layer
    /// owns (`grpc-timeout`, `content-type`, `:path`, …).
    ReservedMetadata,
};

/// Channel-wide policy. The receive limit is the security-critical one — see
/// `frame.zig`.
pub const Options = struct {
    /// Hard ceiling on a single **received** message, enforced against the
    /// length declared on the wire before any of its payload is accepted.
    /// gRPC's own default, and ours, is 4 MiB.
    max_recv_message_size: u32 = frame.default_max_recv_message_size,
    /// Ceiling on a single **sent** message; null = no local limit.
    max_send_message_size: ?u32 = null,
    /// The `application/grpc+{subtype}` we advertise and require.
    content_subtype: []const u8 = "proto",
    /// `user-agent`; null omits it.
    user_agent: ?[]const u8 = "grpc-zig-libs/0.1",
    /// `grpc-accept-encoding`. This build can only undo `identity`, so
    /// advertising anything else would invite a body it cannot read.
    accept_encoding: []const u8 = "identity",
    /// `:scheme` — "https" when the session runs over TLS.
    scheme: []const u8 = "http",
    /// Size of the buffer each call reads HTTP/2 body bytes into before
    /// deframing. Not a message limit: a message larger than this is simply
    /// reassembled over several reads.
    read_chunk: usize = 16 * 1024,
};

/// Where a caller can have the failure detail copied to, since a Zig error
/// cannot carry the `grpc-message` string.
pub const Failure = struct {
    status: Status = .ok,
    /// Decoded `grpc-message`, allocated with the channel's allocator when
    /// non-empty. Release with `deinit`.
    message: []const u8 = "",

    pub fn deinit(f: *Failure, gpa: Allocator) void {
        if (f.message.len != 0) gpa.free(@constCast(f.message));
        f.* = .{};
    }
};

/// `grpc-timeout`: a positive integer of **at most 8 digits** plus a unit.
/// The digit cap is in the spec, so a duration is converted to the finest
/// unit that still fits — and always rounded **up**, because rounding a
/// deadline down would cancel a call the caller still wanted.
pub const Timeout = struct {
    value: u64,
    unit: Unit,

    pub const Unit = enum(u8) {
        hours = 'H',
        minutes = 'M',
        seconds = 'S',
        milliseconds = 'm',
        microseconds = 'u',
        nanoseconds = 'n',
    };

    pub const max_value: u64 = 99_999_999;

    /// Longest wire form: 8 digits + unit.
    pub const max_len = 9;

    pub fn fromNanos(ns: u64) Timeout {
        const ladder = [_]struct { u64, Unit }{
            .{ 1, .nanoseconds },
            .{ 1_000, .microseconds },
            .{ 1_000_000, .milliseconds },
            .{ 1_000_000_000, .seconds },
            .{ 60 * 1_000_000_000, .minutes },
            .{ 3600 * 1_000_000_000, .hours },
        };
        for (ladder) |step| {
            const scale, const unit = step;
            const v = (ns + scale - 1) / scale; // round up: never shorten
            if (v <= max_value) return .{ .value = v, .unit = unit };
        }
        return .{ .value = max_value, .unit = .hours };
    }

    pub fn fromMillis(ms: u64) Timeout {
        return fromNanos(ms *| 1_000_000);
    }

    /// Render into `out` (`out.len >= max_len`).
    pub fn write(t: Timeout, out: []u8) []const u8 {
        std.debug.assert(t.value <= max_value);
        const digits = std.fmt.bufPrint(out, "{d}", .{t.value}) catch unreachable;
        out[digits.len] = @intFromEnum(t.unit);
        return out[0 .. digits.len + 1];
    }

    /// Parse a wire value; null when malformed. Present so a test can prove
    /// the round trip, and for anyone proxying the header onward.
    pub fn parse(s: []const u8) ?Timeout {
        if (s.len < 2 or s.len > max_len) return null;
        const unit: Unit = switch (s[s.len - 1]) {
            'H' => .hours,
            'M' => .minutes,
            'S' => .seconds,
            'm' => .milliseconds,
            'u' => .microseconds,
            'n' => .nanoseconds,
            else => return null,
        };
        const digits = s[0 .. s.len - 1];
        for (digits) |c| {
            if (c < '0' or c > '9') return null;
        }
        const v = std.fmt.parseInt(u64, digits, 10) catch return null;
        if (v > max_value) return null;
        return .{ .value = v, .unit = unit };
    }
};

/// Per-call knobs.
pub const CallOptions = struct {
    /// `grpc-timeout`; null omits it (no deadline).
    timeout: ?Timeout = null,
    /// Extra request metadata. `-bin` keys are base64-encoded here, so
    /// `value` is always the raw form.
    metadata: []const metadata.Entry = &.{},
    /// When set and the call ends non-OK, receives the status and an owned
    /// copy of the decoded `grpc-message`.
    failure: ?*Failure = null,
};

/// Build `/{Service}/{Method}` into `out`. The leading slash and the single
/// separator are the whole of the gRPC path grammar — nothing is escaped,
/// because a service or method name containing `/` is not a name.
pub fn methodPath(out: []u8, service: []const u8, method: []const u8) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(out, "/{s}/{s}", .{ service, method });
}

/// A gRPC channel: policy plus the HTTP/2 session every call runs on. The
/// session is borrowed, not owned — the caller connects it (`connectH2c`,
/// or `connectH2Over` after a TLS handshake) and closes it.
pub const Channel = struct {
    gpa: Allocator,
    session: *h2c.Session,
    /// `:authority`; null lets the session's own default stand.
    authority: ?[]const u8 = null,
    options: Options = .{},

    pub fn init(gpa: Allocator, session: *h2c.Session, options: Options) Channel {
        return .{ .gpa = gpa, .session = session, .options = options };
    }

    /// Convenience over `http.Client`'s h2 session wrapper: borrows its
    /// `h2_client.Session` and its default `:authority`.
    pub fn overH2Session(hs: *http.Client.H2Session, options: Options) Channel {
        return .{
            .gpa = hs.gpa,
            .session = &hs.session,
            .authority = hs.authority,
            .options = options,
        };
    }

    /// Open a stream and send the request head. Nothing else goes out yet:
    /// the messages follow via `Call.sendMessage`.
    pub fn start(ch: *Channel, path: []const u8, opts: CallOptions) Error!Call {
        var arena_state: std.heap.ArenaAllocator = .init(ch.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var fields: std.ArrayList(http.Header) = .empty;
        // `te: trailers` is mandatory (it is what says "I can read a trailer
        // section", and the status lives there); `content-type` selects the
        // gRPC framing and its subtype the message codec.
        try fields.append(arena, .{ .name = "te", .value = "trailers" });
        try fields.append(arena, .{
            .name = "content-type",
            .value = try std.fmt.allocPrint(arena, "application/grpc+{s}", .{ch.options.content_subtype}),
        });
        if (ch.options.user_agent) |ua| try fields.append(arena, .{ .name = "user-agent", .value = ua });
        if (opts.timeout) |t| {
            const buf = try arena.alloc(u8, Timeout.max_len);
            try fields.append(arena, .{ .name = "grpc-timeout", .value = t.write(buf) });
        }
        // We only ever produce identity-encoded messages, so `grpc-encoding`
        // is omitted (identity is the default) and only the accept list is
        // advertised.
        try fields.append(arena, .{ .name = "grpc-accept-encoding", .value = ch.options.accept_encoding });

        for (opts.metadata) |e| {
            if (metadata.isReserved(e.name)) return error.ReservedMetadata;
            const buf = try arena.alloc(u8, metadata.encodedValueLen(e));
            try fields.append(arena, .{ .name = e.name, .value = metadata.encodeValue(e, buf) });
        }

        const sid = try ch.session.openStream(.post, path, .{
            .scheme = ch.options.scheme,
            .authority = ch.authority,
            .headers = fields.items,
        });
        errdefer ch.session.cancel(sid, .cancel);

        const read_buf = try ch.gpa.alloc(u8, ch.options.read_chunk);
        errdefer ch.gpa.free(read_buf);
        return .{
            .ch = ch,
            .sid = sid,
            .read_buf = read_buf,
            .de = .{ .max_recv_message_size = ch.options.max_recv_message_size },
            .failure_out = opts.failure,
        };
    }
};

/// One RPC. Send with `sendMessage`/`closeSend`, receive with `receive`
/// until it returns null, then `finish` for the status. `deinit` always.
pub const Call = struct {
    ch: *Channel,
    sid: u31,
    read_buf: []u8,
    de: frame.Deframer,
    failure_out: ?*Failure,

    /// Borrowed from the session; valid until this call is released.
    head: ?h2c.Head = null,
    /// The whole response was one HEADERS frame with END_STREAM.
    trailers_only: bool = false,
    /// END_STREAM seen on the receive side and the status resolved.
    recv_done: bool = false,
    /// Final status, once known.
    status: ?Status = null,
    status_message: []const u8 = "",
    status_message_owned: bool = false,

    /// Release the call. The underlying HTTP/2 stream is released **here**,
    /// not in `finish` — the response header and trailer lists are borrowed
    /// from the session, so releasing the stream earlier would leave
    /// `initialMetadata`/`trailingMetadata` pointing at freed memory for any
    /// caller that reads metadata after checking the status, which is the
    /// natural order to do it in.
    pub fn deinit(c: *Call) void {
        const gpa = c.ch.gpa;
        if (c.status_message_owned) gpa.free(@constCast(c.status_message));
        c.de.deinit(gpa);
        gpa.free(c.read_buf);
        // A call abandoned before its stream ended is a cancellation — the
        // peer is told, rather than left producing into a void.
        if (c.ch.session.ended(c.sid)) c.ch.session.release(c.sid) else c.ch.session.cancel(c.sid, .cancel);
        c.* = undefined;
    }

    // ── send ────────────────────────────────────────────────────────────────

    /// Frame and send one message. `end` closes the request side with it.
    ///
    /// Alloc-free: the 5-byte gRPC length-prefix header goes out as its own
    /// `sendData` call from a stack buffer, then `message` itself — mirroring
    /// `Stream(Rep).send`'s server-side path (`server.zig`), which never had
    /// to allocate+memcpy the whole framed message just to hand it to the
    /// transport. The two writes land as separate HTTP/2 DATA frames on the
    /// wire, which is immaterial to the receiver: the deframer reassembles
    /// by the declared length prefix, not by DATA-frame boundaries.
    pub fn sendMessage(c: *Call, message: []const u8, end: bool) Error!void {
        if (c.ch.options.max_send_message_size) |limit| {
            if (message.len > limit) return error.SendMessageTooLarge;
        }
        if (message.len > std.math.maxInt(u32)) return error.SendMessageTooLarge;
        var hdr: [frame.header_len]u8 = undefined;
        frame.writeHeader(&hdr, false, @intCast(message.len));
        try c.ch.session.sendData(c.sid, &hdr, false);
        try c.ch.session.sendData(c.sid, message, end);
    }

    /// Half-close the request side with no further message.
    pub fn closeSend(c: *Call) Error!void {
        if (c.ch.session.sendEnded(c.sid)) return;
        return c.ch.session.closeSend(c.sid);
    }

    // ── receive ─────────────────────────────────────────────────────────────

    /// Block for the response head and validate it. Idempotent. After this,
    /// `initialMetadata` is available — and for a Trailers-Only response the
    /// call is already over.
    pub fn readHead(c: *Call) Error!void {
        if (c.head != null) return;
        const head = try c.ch.session.awaitHead(c.sid);
        c.head = head;

        if (head.status != 200) {
            // No gRPC layer to ask: the spec's HTTP-status table is the only
            // information available.
            return c.failLocal(status_mod.fromHttpStatus(head.status), "http status is not 200");
        }
        const ct = head.header("content-type") orelse return c.failLocal(.internal, "response has no content-type");
        if (!isGrpcContentType(ct)) return c.failLocal(.internal, "response content-type is not application/grpc");

        // ── Trailers-Only ──
        // `grpc-status` in the *initial* header block means the whole
        // response is this one frame. Detecting it here is what keeps an
        // error response from hanging a client that waits for trailers.
        if (head.header("grpc-status")) |v| {
            c.trailers_only = true;
            c.recv_done = true;
            try c.adoptStatus(v, head.header("grpc-message"));
            return;
        }
        // A body is coming, so the peer must not have compressed it with
        // something we cannot undo.
        if (head.header("grpc-encoding")) |enc| {
            if (!std.ascii.eqlIgnoreCase(enc, "identity"))
                return c.failLocal(.internal, "response uses a message encoding this client did not accept");
        }
    }

    /// The next response message, or null when the response is complete (at
    /// which point the status is resolved and `finish` will report it).
    ///
    /// The returned slice is **borrowed** from the call's reassembly buffer
    /// and is valid until the next `receive`. Decode or copy it first.
    pub fn receive(c: *Call) Error!?[]const u8 {
        try c.readHead();
        if (c.recv_done) return null;
        while (true) {
            if (c.de.next() catch |e| return c.mapFrameError(e)) |msg| return msg;
            const n = try c.ch.session.readBody(c.sid, c.read_buf);
            if (n == 0) {
                c.de.endOfStream() catch |e| return c.mapFrameError(e);
                c.recv_done = true;
                try c.readTrailers();
                return null;
            }
            c.de.push(c.ch.gpa, c.read_buf[0..n]) catch |e| return c.mapFrameError(e);
        }
    }

    /// Drain to the end of the response and return the status as an error
    /// when it is not OK. Any message still unread is **discarded** — call
    /// this once `receive` has returned null, or deliberately to abandon the
    /// rest of a server stream.
    pub fn finish(c: *Call) Error!void {
        while (!c.recv_done) _ = try c.receive();
        const s = c.status orelse return error.MissingStatus;
        if (s != .ok) {
            c.exportFailure(s);
            return status_mod.toError(s);
        }
    }

    // ── metadata ────────────────────────────────────────────────────────────

    /// Response header section (initial metadata); null before `readHead`.
    pub fn initialMetadata(c: *const Call) ?hpack.HeaderList {
        const h = c.head orelse return null;
        return h.headers;
    }

    /// Response trailer section; null for a Trailers-Only response (whose
    /// fields are in `initialMetadata`) and before the stream ends.
    pub fn trailingMetadata(c: *const Call) ?hpack.HeaderList {
        return c.ch.session.trailers(c.sid);
    }

    /// First value of `name` in the response metadata, still in its wire
    /// form — initial section first, then the trailing one, which is the
    /// order in which a peer may legitimately place a field.
    pub fn metadataValue(c: *const Call, name: []const u8) ?[]const u8 {
        if (c.initialMetadata()) |hl| {
            if (findField(hl, name)) |v| return v;
        }
        if (c.trailingMetadata()) |hl| {
            if (findField(hl, name)) |v| return v;
        }
        return null;
    }

    /// `metadataValue`, base64-decoded when `name` is a `-bin` key. The
    /// result is owned by the caller for a binary key and borrowed for an
    /// ASCII one — `Decoded.owned` says which.
    pub fn metadataValueDecoded(c: *const Call, name: []const u8) Error!?metadata.Decoded {
        const raw = c.metadataValue(name) orelse return null;
        return try metadata.decodeValue(c.ch.gpa, name, raw);
    }

    /// Decoded `grpc-message`, or "" — valid until `deinit`.
    pub fn statusMessage(c: *const Call) []const u8 {
        return c.status_message;
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn readTrailers(c: *Call) Error!void {
        if (c.status != null) return; // Trailers-Only already resolved it
        const hl = c.ch.session.trailers(c.sid) orelse return error.MissingStatus;
        const v = findField(hl, "grpc-status") orelse return error.MissingStatus;
        try c.adoptStatus(v, findField(hl, "grpc-message"));
    }

    fn adoptStatus(c: *Call, raw_status: []const u8, raw_message: ?[]const u8) Error!void {
        const s = status_mod.parse(raw_status) orelse return error.MalformedStatus;
        c.status = s;
        if (raw_message) |m| {
            if (m.len != 0) {
                c.status_message = try status_mod.decodeMessageAlloc(c.ch.gpa, m);
                c.status_message_owned = true;
            }
        }
    }

    /// A failure this client decided on locally (bad head, oversized
    /// message, truncated stream): give the call the same shape a
    /// server-sent status would, so callers see one model.
    fn failLocal(c: *Call, s: Status, message: []const u8) Error {
        c.recv_done = true;
        if (c.status == null) {
            c.status = s;
            c.status_message = message;
            c.status_message_owned = false;
        }
        c.exportFailure(s);
        return status_mod.toError(s);
    }

    fn mapFrameError(c: *Call, e: frame.Error) Error {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            // What every other gRPC implementation returns for a message
            // over the receive limit.
            error.MessageTooLarge => c.failLocal(.resource_exhausted, "received message larger than the maximum receive size"),
            error.CompressedUnsupported => c.failLocal(.internal, "received a compressed message but no compression was negotiated"),
            error.TruncatedMessage => c.failLocal(.internal, "stream ended in the middle of a length-prefixed message"),
        };
    }

    fn exportFailure(c: *Call, s: Status) void {
        const out = c.failure_out orelse return;
        out.status = s;
        if (c.status_message.len != 0) {
            out.message = c.ch.gpa.dupe(u8, c.status_message) catch "";
        }
    }
};

fn findField(hl: hpack.HeaderList, name: []const u8) ?[]const u8 {
    for (hl.fields) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
    }
    return null;
}

/// `application/grpc`, optionally `+proto`/`;charset=…`. Anything else means
/// something other than a gRPC server answered, and its body must not be
/// deframed as if it were gRPC.
fn isGrpcContentType(ct: []const u8) bool {
    const base = "application/grpc";
    if (ct.len < base.len) return false;
    if (!std.ascii.eqlIgnoreCase(ct[0..base.len], base)) return false;
    if (ct.len == base.len) return true;
    return switch (ct[base.len]) {
        '+', ';', ' ' => true,
        else => false,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "path: /Service/Method, nothing else" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("/echo.Echo/Unary", try methodPath(&buf, "echo.Echo", "Unary"));
    try testing.expectError(error.NoSpaceLeft, methodPath(buf[0..4], "echo.Echo", "Unary"));
}

test "timeout: unit ladder picks the finest unit that fits 8 digits" {
    var buf: [Timeout.max_len]u8 = undefined;
    try testing.expectEqualStrings("100n", Timeout.fromNanos(100).write(&buf));
    try testing.expectEqualStrings("99999999n", Timeout.fromNanos(99_999_999).write(&buf));
    // One nanosecond more no longer fits in 8 digits of nanoseconds.
    try testing.expectEqualStrings("100000u", Timeout.fromNanos(100_000_000).write(&buf));
    // 500 ms does not fit 8 digits of nanoseconds, so it goes out as
    // microseconds — the finest unit that does, which is what grpc's own
    // clients emit.
    try testing.expectEqualStrings("500000u", Timeout.fromMillis(500).write(&buf));
    try testing.expectEqualStrings("100000m", Timeout.fromMillis(100_000).write(&buf));
}

test "timeout: conversion rounds up, never shortening the deadline" {
    // 100000001 ns does not fit in nanoseconds; as microseconds it is
    // 100000.001, which must become 100001u — rounding down would expire the
    // call a microsecond early.
    var buf: [Timeout.max_len]u8 = undefined;
    try testing.expectEqualStrings("100001u", Timeout.fromNanos(100_000_001).write(&buf));
    // …and the same one unit up: 100000001us → 100001ms, not 100000ms.
    try testing.expectEqualStrings("100001m", Timeout.fromNanos(100_000_001_000).write(&buf));
}

test "timeout: wire form round trips" {
    const cases = [_]Timeout{
        .{ .value = 1, .unit = .nanoseconds },
        .{ .value = 250, .unit = .milliseconds },
        .{ .value = 30, .unit = .seconds },
        .{ .value = 99_999_999, .unit = .hours },
    };
    var buf: [Timeout.max_len]u8 = undefined;
    for (cases) |t| {
        const parsed = Timeout.parse(t.write(&buf)).?;
        try testing.expectEqual(t.value, parsed.value);
        try testing.expectEqual(t.unit, parsed.unit);
    }
    try testing.expectEqual(@as(?Timeout, null), Timeout.parse(""));
    try testing.expectEqual(@as(?Timeout, null), Timeout.parse("100"));
    try testing.expectEqual(@as(?Timeout, null), Timeout.parse("100x"));
    try testing.expectEqual(@as(?Timeout, null), Timeout.parse("1000000000S")); // 10 digits
}

test "content-type: only application/grpc flavours are accepted" {
    try testing.expect(isGrpcContentType("application/grpc"));
    try testing.expect(isGrpcContentType("application/grpc+proto"));
    try testing.expect(isGrpcContentType("application/grpc+json"));
    try testing.expect(isGrpcContentType("application/grpc; charset=utf-8"));
    try testing.expect(isGrpcContentType("APPLICATION/GRPC+PROTO"));
    try testing.expect(!isGrpcContentType("application/grpcweb"));
    try testing.expect(!isGrpcContentType("text/html"));
    try testing.expect(!isGrpcContentType(""));
}
