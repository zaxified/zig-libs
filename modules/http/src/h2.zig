// SPDX-License-Identifier: MIT

//! h2 — HTTP/2 framing and the connection/stream state machine (RFC 9113).
//! Pure wire layer: no sockets, no I/O — bytes in, bytes out, allocator
//! based, and it never panics on malformed peer input (typed errors only,
//! each mapped to an RFC 9113 §7 error code via `errorCode` so a caller
//! can emit the right GOAWAY/RST_STREAM).
//!
//! Contents: the §4 9-octet frame header codec (`FrameHeader`), full
//! encode/decode + validation for every §6 frame type (`parseFrame`,
//! `encode*`), the §3.4 connection preface, §6.5 SETTINGS handling, and
//! `Connection` — the §5.1 stream state machine, §5.1.1 stream-identifier
//! rules, §5.2/§6.9 flow-control accounting and the HEADERS+CONTINUATION
//! header-block assembler/emitter running through `hpack` (RFC 7541).
//! Transport integration (TLS/ALPN, sockets, the h1 upgrade) is the next
//! layer up: feed received bytes to `Connection.recv` and write out the
//! bytes it and the `send*` calls append to `out`.
//!
//! Denial-of-service hardening (all limits configurable via
//! `Connection.Options`, breaches surface as `error.EnhanceYourCalm` so
//! the caller answers GOAWAY(ENHANCE_YOUR_CALM) and closes, §5.4.1):
//! - **Rapid reset (CVE-2023-44487)**: streams reset before completing —
//!   RST_STREAM received on a non-closed stream, or reset by us after a
//!   stream-scoped violation — are counted; over `max_reset_streams` the
//!   connection dies instead of doing unbounded setup/teardown work.
//! - **CONTINUATION flood (CVE-2024-27316)**: one header sequence may use
//!   at most `max_continuation_frames` CONTINUATION frames (so a stream of
//!   zero-length CONTINUATIONs that never sets END_HEADERS dies) *and* at
//!   most `max_header_block` reassembled octets. Connection-scoped, since
//!   the header block is part of the shared HPACK compression context. The
//!   HPACK decoder's own `max_header_list_size` decompression-bomb guard
//!   (RFC 7541) applies after reassembly, independently.
//! - **Control-frame floods**: frames that make no progress (PING,
//!   SETTINGS after the handshake, PRIORITY, zero-length DATA without
//!   END_STREAM, repeated HEADERS on an existing stream, unknown types)
//!   consume a shared budget of `max_unproductive_frames` consecutive
//!   frames; progress (a new request stream, DATA that carries bytes or
//!   END_STREAM) resets it. PINGs are still answered while under budget.
//!
//! Provenance: clean-room implementation from RFC 9113 (with RFC 7540
//! consulted only where it clarifies the same rules, e.g. §5.1/§6.9.2)
//! plus, for the hardening, RFC 9113 §10.5 and the public CVE-2023-44487 /
//! CVE-2024-27316 advisories (behavior descriptions only); no HTTP/2
//! implementation source was consulted or copied.

const std = @import("std");
const hpack = @import("hpack.zig");
const Allocator = std.mem.Allocator;

// ── constants (§3.4, §4.1, §4.2, §6.5.2, §6.9.1) ────────────────────────────

/// The client connection preface magic (§3.4).
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Size of the fixed frame header (§4.1).
pub const frame_header_len = 9;

/// Initial and minimum SETTINGS_MAX_FRAME_SIZE (§6.5.2).
pub const default_max_frame_size: u32 = 1 << 14;

/// Largest value SETTINGS_MAX_FRAME_SIZE may take, 2^24-1 (§6.5.2).
pub const max_allowed_frame_size: u32 = (1 << 24) - 1;

/// Initial flow-control window, connection and per-stream (§6.9.2).
pub const default_initial_window_size: u32 = 65_535;

/// Flow-control window ceiling, 2^31-1 (§6.9.1).
pub const max_window_size: u32 = (1 << 31) - 1;

// ── §7 error codes ──────────────────────────────────────────────────────────

/// RFC 9113 §7 error codes as they appear in RST_STREAM/GOAWAY. Unknown
/// codes are representable (non-exhaustive) and must be treated as
/// INTERNAL_ERROR by callers that need to act on them (§7).
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

/// Every RFC 9113 protocol violation this layer can detect. Each member
/// maps 1:1 to a §7 code via `errorCode`; `Connection` additionally records
/// scope + stream id in `Connection.violation` so the caller knows whether
/// to answer with GOAWAY (connection scope) or RST_STREAM (stream scope).
pub const Error = error{
    ProtocolError,
    InternalError,
    FlowControlError,
    SettingsTimeout,
    StreamClosed,
    FrameSizeError,
    RefusedStream,
    Cancel,
    CompressionError,
    ConnectError,
    EnhanceYourCalm,
    InadequateSecurity,
    Http11Required,
};

/// The §7 wire code for a detected violation.
pub fn errorCode(e: Error) ErrorCode {
    return switch (e) {
        error.ProtocolError => .protocol_error,
        error.InternalError => .internal_error,
        error.FlowControlError => .flow_control_error,
        error.SettingsTimeout => .settings_timeout,
        error.StreamClosed => .stream_closed,
        error.FrameSizeError => .frame_size_error,
        error.RefusedStream => .refused_stream,
        error.Cancel => .cancel,
        error.CompressionError => .compression_error,
        error.ConnectError => .connect_error,
        error.EnhanceYourCalm => .enhance_your_calm,
        error.InadequateSecurity => .inadequate_security,
        error.Http11Required => .http_1_1_required,
    };
}

/// Details of the violation behind the last error `Connection.recv`
/// returned: what to send before closing (GOAWAY for `.connection` scope,
/// RST_STREAM on `stream_id` for `.stream` scope — §5.4).
pub const Violation = struct {
    scope: enum { connection, stream },
    stream_id: u31,
    code: ErrorCode,
};

// ── §4.1 frame header ───────────────────────────────────────────────────────

/// Frame types (§6). Non-exhaustive: frames of unknown type must be
/// ignored (§4.1), so unknown values stay representable.
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

/// Frame flag bits (§6). ACK shares the END_STREAM bit position but
/// applies only to SETTINGS/PING.
pub const Flags = struct {
    pub const end_stream: u8 = 0x01;
    pub const ack: u8 = 0x01;
    pub const end_headers: u8 = 0x04;
    pub const padded: u8 = 0x08;
    pub const priority: u8 = 0x20;
};

/// The 9-octet frame header (§4.1): 24-bit length, type, flags, R bit +
/// 31-bit stream identifier. The reserved bit is written as 0 and ignored
/// on receipt (masked off by `decode`), as §4.1 requires.
pub const FrameHeader = struct {
    /// Payload length; the wire field is 24 bits.
    length: u32,
    frame_type: FrameType,
    flags: u8,
    stream_id: u31,

    pub fn encode(h: FrameHeader) [frame_header_len]u8 {
        std.debug.assert(h.length <= max_allowed_frame_size);
        var out: [frame_header_len]u8 = undefined;
        out[0] = @intCast(h.length >> 16);
        out[1] = @intCast((h.length >> 8) & 0xff);
        out[2] = @intCast(h.length & 0xff);
        out[3] = @intFromEnum(h.frame_type);
        out[4] = h.flags;
        std.mem.writeInt(u32, out[5..9], h.stream_id, .big);
        return out;
    }

    pub fn decode(bytes: *const [frame_header_len]u8) FrameHeader {
        return .{
            .length = (@as(u32, bytes[0]) << 16) | (@as(u32, bytes[1]) << 8) | bytes[2],
            .frame_type = @enumFromInt(bytes[3]),
            .flags = bytes[4],
            // High bit is the reserved bit — ignored on receipt (§4.1).
            .stream_id = @intCast(std.mem.readInt(u32, bytes[5..9], .big) & max_window_size),
        };
    }
};

/// The §6.3 PRIORITY payload (also embedded in HEADERS when the PRIORITY
/// flag is set). Deprecated by RFC 9113 §5.3 but still parsed/carried.
pub const Priority = struct {
    exclusive: bool,
    /// Stream this one depends on (0 = the root).
    dependency: u31,
    /// Wire weight 0..255, representing 1..256 (§6.3 of RFC 7540).
    weight: u8,
};

// ── §6.5 SETTINGS ───────────────────────────────────────────────────────────

/// The defined SETTINGS parameters (§6.5.2) with their initial values.
/// Unknown parameters received from a peer are ignored (§6.5.2).
pub const Settings = struct {
    header_table_size: u32 = hpack.default_max_table_size,
    enable_push: bool = true,
    /// null = unlimited (no advertised limit).
    max_concurrent_streams: ?u32 = null,
    initial_window_size: u32 = default_initial_window_size,
    max_frame_size: u32 = default_max_frame_size,
    /// null = unlimited (advisory, §6.5.2).
    max_header_list_size: ?u32 = null,

    pub const Id = enum(u16) {
        header_table_size = 0x1,
        enable_push = 0x2,
        max_concurrent_streams = 0x3,
        initial_window_size = 0x4,
        max_frame_size = 0x5,
        max_header_list_size = 0x6,
        _,
    };
};

/// Iterates the 6-octet (identifier, value) pairs of a SETTINGS payload
/// whose length was already validated to be a multiple of 6.
pub const SettingsIterator = struct {
    payload: []const u8,
    pos: usize = 0,

    pub const Entry = struct { id: Settings.Id, value: u32 };

    pub fn next(it: *SettingsIterator) ?Entry {
        if (it.pos >= it.payload.len) return null;
        const chunk = it.payload[it.pos..][0..6];
        it.pos += 6;
        return .{
            .id = @enumFromInt(std.mem.readInt(u16, chunk[0..2], .big)),
            .value = std.mem.readInt(u32, chunk[2..6], .big),
        };
    }
};

// ── §6 frame payload decode ─────────────────────────────────────────────────

/// A structurally decoded and validated frame (§6). Slices borrow from the
/// payload passed to `parseFrame`.
pub const Frame = union(enum) {
    data: struct { stream_id: u31, data: []const u8, end_stream: bool },
    headers: struct {
        stream_id: u31,
        fragment: []const u8,
        end_stream: bool,
        end_headers: bool,
        priority: ?Priority,
    },
    priority: struct { stream_id: u31, priority: Priority },
    rst_stream: struct { stream_id: u31, code: ErrorCode },
    settings: struct { ack: bool, payload: []const u8 },
    push_promise: struct {
        stream_id: u31,
        promised_id: u31,
        fragment: []const u8,
        end_headers: bool,
    },
    ping: struct { ack: bool, data: [8]u8 },
    goaway: struct { last_stream_id: u31, code: ErrorCode, debug: []const u8 },
    window_update: struct { stream_id: u31, increment: u31 },
    continuation: struct { stream_id: u31, fragment: []const u8, end_headers: bool },
    /// Unknown frame type — must be ignored (§4.1).
    unknown: struct { frame_type: u8, stream_id: u31 },
};

/// Errors `parseFrame` itself can produce; `Connection` maps them to the
/// right connection-vs-stream scope.
pub const ParseError = error{ ProtocolError, FrameSizeError };

/// Structurally decode + validate one frame payload against its header.
/// `payload.len` must equal `h.length` (the caller has already framed it).
/// Enforces the per-type §6 rules: stream-id zero/nonzero, fixed payload
/// sizes (FRAME_SIZE_ERROR), padding bounds (PROTOCOL_ERROR), SETTINGS
/// ACK emptiness, reserved-bit masking in PUSH_PROMISE/GOAWAY/WINDOW_UPDATE.
pub fn parseFrame(h: FrameHeader, payload: []const u8) ParseError!Frame {
    std.debug.assert(payload.len == h.length);
    switch (h.frame_type) {
        .data => {
            if (h.stream_id == 0) return error.ProtocolError;
            const data = try stripPadding(payload, h.flags, 0);
            return .{ .data = .{
                .stream_id = h.stream_id,
                .data = data,
                .end_stream = h.flags & Flags.end_stream != 0,
            } };
        },
        .headers => {
            if (h.stream_id == 0) return error.ProtocolError;
            const body = try stripPadding(payload, h.flags, if (h.flags & Flags.priority != 0) 5 else 0);
            var prio: ?Priority = null;
            var fragment = body;
            if (h.flags & Flags.priority != 0) {
                prio = readPriority(body[0..5]);
                fragment = body[5..];
            }
            return .{ .headers = .{
                .stream_id = h.stream_id,
                .fragment = fragment,
                .end_stream = h.flags & Flags.end_stream != 0,
                .end_headers = h.flags & Flags.end_headers != 0,
                .priority = prio,
            } };
        },
        .priority => {
            if (h.stream_id == 0) return error.ProtocolError;
            if (payload.len != 5) return error.FrameSizeError;
            return .{ .priority = .{
                .stream_id = h.stream_id,
                .priority = readPriority(payload[0..5]),
            } };
        },
        .rst_stream => {
            if (h.stream_id == 0) return error.ProtocolError;
            if (payload.len != 4) return error.FrameSizeError;
            return .{ .rst_stream = .{
                .stream_id = h.stream_id,
                .code = @enumFromInt(std.mem.readInt(u32, payload[0..4], .big)),
            } };
        },
        .settings => {
            if (h.stream_id != 0) return error.ProtocolError;
            const ack = h.flags & Flags.ack != 0;
            if (ack and payload.len != 0) return error.FrameSizeError;
            if (payload.len % 6 != 0) return error.FrameSizeError;
            return .{ .settings = .{ .ack = ack, .payload = payload } };
        },
        .push_promise => {
            if (h.stream_id == 0) return error.ProtocolError;
            const body = try stripPadding(payload, h.flags, 4);
            const promised = std.mem.readInt(u32, body[0..4], .big) & max_window_size;
            if (promised == 0) return error.ProtocolError;
            return .{ .push_promise = .{
                .stream_id = h.stream_id,
                .promised_id = @intCast(promised),
                .fragment = body[4..],
                .end_headers = h.flags & Flags.end_headers != 0,
            } };
        },
        .ping => {
            if (h.stream_id != 0) return error.ProtocolError;
            if (payload.len != 8) return error.FrameSizeError;
            return .{ .ping = .{
                .ack = h.flags & Flags.ack != 0,
                .data = payload[0..8].*,
            } };
        },
        .goaway => {
            if (h.stream_id != 0) return error.ProtocolError;
            if (payload.len < 8) return error.FrameSizeError;
            return .{ .goaway = .{
                .last_stream_id = @intCast(std.mem.readInt(u32, payload[0..4], .big) & max_window_size),
                .code = @enumFromInt(std.mem.readInt(u32, payload[4..8], .big)),
                .debug = payload[8..],
            } };
        },
        .window_update => {
            if (payload.len != 4) return error.FrameSizeError;
            const inc = std.mem.readInt(u32, payload[0..4], .big) & max_window_size;
            // A zero increment is a PROTOCOL_ERROR (§6.9).
            if (inc == 0) return error.ProtocolError;
            return .{ .window_update = .{
                .stream_id = h.stream_id,
                .increment = @intCast(inc),
            } };
        },
        .continuation => {
            if (h.stream_id == 0) return error.ProtocolError;
            return .{ .continuation = .{
                .stream_id = h.stream_id,
                .fragment = payload,
                .end_headers = h.flags & Flags.end_headers != 0,
            } };
        },
        _ => return .{ .unknown = .{
            .frame_type = @intFromEnum(h.frame_type),
            .stream_id = h.stream_id,
        } },
    }
}

/// Remove the §6.1/§6.2 Pad Length octet + trailing padding when the
/// PADDED flag is set. `fixed_prefix` is the size of any fields that must
/// still fit after the pad-length octet (HEADERS priority = 5,
/// PUSH_PROMISE promised id = 4). Padding that does not fit inside the
/// payload is a PROTOCOL_ERROR (§6.1).
fn stripPadding(payload: []const u8, flags: u8, fixed_prefix: usize) ParseError![]const u8 {
    if (flags & Flags.padded == 0) {
        if (payload.len < fixed_prefix) return error.FrameSizeError;
        return payload;
    }
    if (payload.len < 1) return error.FrameSizeError;
    const pad: usize = payload[0];
    const rest = payload[1..];
    if (rest.len < fixed_prefix or pad > rest.len - fixed_prefix) return error.ProtocolError;
    return rest[0 .. rest.len - pad];
}

fn readPriority(bytes: *const [5]u8) Priority {
    const word = std.mem.readInt(u32, bytes[0..4], .big);
    return .{
        .exclusive = word & 0x8000_0000 != 0,
        .dependency = @intCast(word & max_window_size),
        .weight = bytes[4],
    };
}

// ── §6 frame encode ─────────────────────────────────────────────────────────
//
// All encoders append one complete frame (header + payload) to `out`.
// They are pure — no connection state; `Connection.send*` wraps them with
// state-machine + flow-control bookkeeping.

/// Append a frame with an arbitrary type/flags/payload — the shared
/// primitive under every `encode*`, public so tests and future layers can
/// craft frames (including intentionally invalid ones).
pub fn encodeRawFrame(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    frame_type: FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) Allocator.Error!void {
    const h: FrameHeader = .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    };
    try out.appendSlice(gpa, &h.encode());
    try out.appendSlice(gpa, payload);
}

pub const PadOptions = struct {
    /// null = no PADDED flag; 0 = PADDED flag with zero pad octets.
    pad: ?u8 = null,
};

pub const DataOptions = struct {
    end_stream: bool = false,
    pad: ?u8 = null,
};

/// DATA (§6.1).
pub fn encodeData(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    data: []const u8,
    options: DataOptions,
) Allocator.Error!void {
    var flags: u8 = 0;
    if (options.end_stream) flags |= Flags.end_stream;
    if (options.pad == null) {
        try encodeRawFrame(gpa, out, .data, flags, stream_id, data);
        return;
    }
    try encodePadded(gpa, out, .data, flags, stream_id, &.{}, data, options.pad.?);
}

pub const HeadersOptions = struct {
    end_stream: bool = false,
    end_headers: bool = true,
    priority: ?Priority = null,
    pad: ?u8 = null,
};

/// HEADERS (§6.2) carrying one already-encoded header-block fragment.
/// For whole header lists use `Connection.sendHeaders`, which HPACK-encodes
/// and fragments across CONTINUATION frames.
pub fn encodeHeaders(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    fragment: []const u8,
    options: HeadersOptions,
) Allocator.Error!void {
    var flags: u8 = 0;
    if (options.end_stream) flags |= Flags.end_stream;
    if (options.end_headers) flags |= Flags.end_headers;
    var prefix: [5]u8 = undefined;
    var prefix_len: usize = 0;
    if (options.priority) |p| {
        flags |= Flags.priority;
        writePriorityBytes(prefix[0..5], p);
        prefix_len = 5;
    }
    if (options.pad == null and prefix_len == 0) {
        try encodeRawFrame(gpa, out, .headers, flags, stream_id, fragment);
        return;
    }
    if (options.pad) |pad| {
        try encodePadded(gpa, out, .headers, flags, stream_id, prefix[0..prefix_len], fragment, pad);
        return;
    }
    const h: FrameHeader = .{
        .length = @intCast(prefix_len + fragment.len),
        .frame_type = .headers,
        .flags = flags,
        .stream_id = stream_id,
    };
    try out.appendSlice(gpa, &h.encode());
    try out.appendSlice(gpa, prefix[0..prefix_len]);
    try out.appendSlice(gpa, fragment);
}

/// PRIORITY (§6.3).
pub fn encodePriority(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    priority: Priority,
) Allocator.Error!void {
    var payload: [5]u8 = undefined;
    writePriorityBytes(&payload, priority);
    try encodeRawFrame(gpa, out, .priority, 0, stream_id, &payload);
}

/// RST_STREAM (§6.4).
pub fn encodeRstStream(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    code: ErrorCode,
) Allocator.Error!void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @intFromEnum(code), .big);
    try encodeRawFrame(gpa, out, .rst_stream, 0, stream_id, &payload);
}

/// SETTINGS (§6.5) advertising `settings`. The four always-meaningful
/// parameters are emitted unconditionally; the two optional ones only when
/// set (absent = unlimited, their initial value).
pub fn encodeSettings(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    settings: Settings,
) Allocator.Error!void {
    var payload: [6 * 6]u8 = undefined;
    var n: usize = 0;
    putSetting(&payload, &n, .header_table_size, settings.header_table_size);
    putSetting(&payload, &n, .enable_push, @intFromBool(settings.enable_push));
    putSetting(&payload, &n, .initial_window_size, settings.initial_window_size);
    putSetting(&payload, &n, .max_frame_size, settings.max_frame_size);
    if (settings.max_concurrent_streams) |v| putSetting(&payload, &n, .max_concurrent_streams, v);
    if (settings.max_header_list_size) |v| putSetting(&payload, &n, .max_header_list_size, v);
    try encodeRawFrame(gpa, out, .settings, 0, 0, payload[0..n]);
}

/// SETTINGS acknowledgement (§6.5.3).
pub fn encodeSettingsAck(gpa: Allocator, out: *std.ArrayList(u8)) Allocator.Error!void {
    try encodeRawFrame(gpa, out, .settings, Flags.ack, 0, &.{});
}

/// PUSH_PROMISE (§6.6) carrying an already-encoded fragment. Decoded and
/// validated on receipt; this encoder exists for completeness/tests — this
/// implementation never promises pushes itself.
pub fn encodePushPromise(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    promised_id: u31,
    fragment: []const u8,
    end_headers: bool,
) Allocator.Error!void {
    const h: FrameHeader = .{
        .length = @intCast(4 + fragment.len),
        .frame_type = .push_promise,
        .flags = if (end_headers) Flags.end_headers else 0,
        .stream_id = stream_id,
    };
    try out.appendSlice(gpa, &h.encode());
    var id_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &id_bytes, promised_id, .big);
    try out.appendSlice(gpa, &id_bytes);
    try out.appendSlice(gpa, fragment);
}

/// PING (§6.7).
pub fn encodePing(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    data: [8]u8,
    ack: bool,
) Allocator.Error!void {
    try encodeRawFrame(gpa, out, .ping, if (ack) Flags.ack else 0, 0, &data);
}

/// GOAWAY (§6.8).
pub fn encodeGoaway(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    last_stream_id: u31,
    code: ErrorCode,
    debug: []const u8,
) Allocator.Error!void {
    const h: FrameHeader = .{
        .length = @intCast(8 + debug.len),
        .frame_type = .goaway,
        .flags = 0,
        .stream_id = 0,
    };
    try out.appendSlice(gpa, &h.encode());
    var fixed: [8]u8 = undefined;
    std.mem.writeInt(u32, fixed[0..4], last_stream_id, .big);
    std.mem.writeInt(u32, fixed[4..8], @intFromEnum(code), .big);
    try out.appendSlice(gpa, &fixed);
    try out.appendSlice(gpa, debug);
}

/// WINDOW_UPDATE (§6.9). `stream_id` 0 = the connection window.
pub fn encodeWindowUpdate(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    increment: u31,
) Allocator.Error!void {
    std.debug.assert(increment > 0);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);
    try encodeRawFrame(gpa, out, .window_update, 0, stream_id, &payload);
}

/// CONTINUATION (§6.10).
pub fn encodeContinuation(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    stream_id: u31,
    fragment: []const u8,
    end_headers: bool,
) Allocator.Error!void {
    const flags: u8 = if (end_headers) Flags.end_headers else 0;
    try encodeRawFrame(gpa, out, .continuation, flags, stream_id, fragment);
}

fn writePriorityBytes(bytes: *[5]u8, p: Priority) void {
    var word: u32 = p.dependency;
    if (p.exclusive) word |= 0x8000_0000;
    std.mem.writeInt(u32, bytes[0..4], word, .big);
    bytes[4] = p.weight;
}

fn putSetting(buf: *[36]u8, n: *usize, id: Settings.Id, value: u32) void {
    std.mem.writeInt(u16, buf[n.*..][0..2], @intFromEnum(id), .big);
    std.mem.writeInt(u32, buf[n.* + 2 ..][0..4], value, .big);
    n.* += 6;
}

/// Padded frame: Pad Length octet + fixed prefix + body + pad zero octets.
fn encodePadded(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    frame_type: FrameType,
    flags: u8,
    stream_id: u31,
    prefix: []const u8,
    body: []const u8,
    pad: u8,
) Allocator.Error!void {
    const h: FrameHeader = .{
        .length = @intCast(1 + prefix.len + body.len + pad),
        .frame_type = frame_type,
        .flags = flags | Flags.padded,
        .stream_id = stream_id,
    };
    try out.appendSlice(gpa, &h.encode());
    try out.append(gpa, pad);
    try out.appendSlice(gpa, prefix);
    try out.appendSlice(gpa, body);
    try out.appendNTimes(gpa, 0, pad);
}

// ── §5 streams + connection ─────────────────────────────────────────────────

/// §5.1 stream states. `reserved_local` is unused by this implementation
/// (we never send PUSH_PROMISE) but kept for the complete state space.
pub const StreamState = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Per-stream bookkeeping. Windows are i64: §6.9.2 SETTINGS changes can
/// legally drive a window negative, and the wide type keeps the 2^31-1
/// overflow check (§6.9.1) trivially exact.
pub const Stream = struct {
    id: u31,
    state: StreamState,
    /// What we may still send them on this stream (peer-controlled).
    send_window: i64,
    /// What they may still send us (we control via WINDOW_UPDATE).
    recv_window: i64,
};

/// Which endpoint of the connection this is (decides stream-id parity,
/// preface direction and PUSH_PROMISE legality).
pub const Role = enum { client, server };

/// A semantic event produced by `Connection.recv`. `headers`/`push_promise`
/// own their decoded `hpack.HeaderList` — release with `Event.deinit`.
/// `data.data`, `goaway.debug` borrow the connection's receive buffer and
/// are valid only until the next `recv` call.
pub const Event = union(enum) {
    /// Peer SETTINGS applied to `remote_settings`; the ACK was queued.
    settings,
    /// Peer acknowledged our SETTINGS.
    settings_ack,
    headers: struct { stream_id: u31, headers: hpack.HeaderList, end_stream: bool },
    push_promise: struct { stream_id: u31, promised_id: u31, headers: hpack.HeaderList },
    data: struct { stream_id: u31, data: []const u8, end_stream: bool },
    stream_reset: struct { stream_id: u31, code: ErrorCode },
    /// stream_id 0 = the connection window.
    window_update: struct { stream_id: u31, increment: u31 },
    /// Peer PING; the ACK was queued.
    ping: struct { data: [8]u8 },
    ping_ack: struct { data: [8]u8 },
    goaway: struct { last_stream_id: u31, code: ErrorCode, debug: []const u8 },
    priority: struct { stream_id: u31, priority: Priority },

    pub fn deinit(ev: *Event, gpa: Allocator) void {
        switch (ev.*) {
            .headers => |*h| h.headers.deinit(gpa),
            .push_promise => |*p| p.headers.deinit(gpa),
            else => {},
        }
        ev.* = undefined;
    }
};

/// The RFC 9113 connection + stream state machine, transport-free.
///
/// Receiving: feed raw bytes (any chunking) to `recv`; it buffers partial
/// frames, validates everything, auto-queues SETTINGS/PING ACKs into `out`
/// and appends semantic `Event`s. On a violation it returns an `Error`
/// (see `violation` for GOAWAY-vs-RST_STREAM scope) and the connection
/// must not be used further except to emit that GOAWAY/RST_STREAM.
///
/// Sending: `sendPreface` first, then `startStream`/`sendHeaders`/
/// `sendData`/... — each appends wire bytes to the caller's `out` list and
/// keeps stream states + flow-control windows in step.
pub const Connection = struct {
    gpa: Allocator,
    role: Role,
    /// Our settings, advertised in `sendPreface` and enforced on receipt.
    local_settings: Settings,
    /// Peer settings; §6.5.2 initial values until its SETTINGS arrives.
    remote_settings: Settings = .{},
    hpack_enc: hpack.Encoder,
    hpack_dec: hpack.Decoder,
    /// All streams ever created, keyed by id; closed streams stay so that
    /// closed-vs-idle can be told apart (§5.1). Bounded in practice by
    /// SETTINGS_MAX_CONCURRENT_STREAMS enforcement in the server layer.
    streams: std.AutoHashMapUnmanaged(u32, Stream) = .empty,
    conn_send_window: i64 = default_initial_window_size,
    conn_recv_window: i64,
    next_local_stream_id: u31,
    highest_remote_stream_id: u31 = 0,
    recv_buf: std.ArrayList(u8) = .empty,
    recv_pos: usize = 0,
    /// Server side: the client preface magic is still expected.
    preface_pending: bool,
    /// The first frame from the peer must be SETTINGS (§3.4).
    first_settings_pending: bool = true,
    assembling: ?Assembly = null,
    /// last_stream_id from a received / sent GOAWAY.
    goaway_recv: ?u31 = null,
    goaway_sent: ?u31 = null,
    /// Set when `recv` returns an `Error`: what to answer before closing.
    violation: ?Violation = null,
    max_header_block: usize,
    max_continuation_frames: u32,
    max_reset_streams: u32,
    max_unproductive_frames: u32,
    /// Streams reset before completing useful work (RST_STREAM received on
    /// a non-closed stream + local `recoverStreamError` resets) —
    /// CVE-2023-44487 rapid-reset accounting.
    reset_streams: u32 = 0,
    /// Consecutive no-progress frames (see the module doc); reset by
    /// productive frames.
    unproductive_frames: u32 = 0,
    /// Total peer-initiated streams ever opened on this connection; the
    /// serve layer's `max_streams_per_connection` cap reads this.
    remote_streams_total: u32 = 0,

    const Assembly = struct {
        kind: enum { headers, push_promise },
        stream_id: u31,
        promised_id: u31 = 0,
        end_stream: bool = false,
        buf: std.ArrayList(u8) = .empty,
        /// CONTINUATION frames consumed by this sequence (CVE-2024-27316).
        frames: u32 = 0,
    };

    pub const Options = struct {
        /// Settings we advertise. `header_table_size`/`max_header_list_size`
        /// also configure the HPACK decoder; `initial_window_size` seeds
        /// per-stream receive windows; `max_frame_size` bounds inbound frames.
        settings: Settings = .{},
        /// Cap on one reassembled HEADERS+CONTINUATION block; a peer
        /// exceeding it gets `error.EnhanceYourCalm` (connection scope —
        /// the block is part of the shared HPACK context, §4.3).
        max_header_block: usize = 1 << 20,
        /// CONTINUATION frames allowed in one header sequence
        /// (CVE-2024-27316 flood guard — catches zero-length CONTINUATION
        /// streams the size cap cannot); over → `error.EnhanceYourCalm`.
        max_continuation_frames: u32 = 32,
        /// Streams the peer may reset before completion (CVE-2023-44487
        /// rapid-reset guard); over → `error.EnhanceYourCalm`.
        max_reset_streams: u32 = 100,
        /// Budget of consecutive no-progress frames (PING/SETTINGS/
        /// PRIORITY/empty DATA/unknown/…); over → `error.EnhanceYourCalm`.
        max_unproductive_frames: u32 = 1024,
        hpack_huffman: hpack.Encoder.HuffmanMode = .auto,
    };

    pub fn init(gpa: Allocator, role: Role, options: Options) Connection {
        return .{
            .gpa = gpa,
            .role = role,
            .local_settings = options.settings,
            .hpack_enc = .init(gpa, .{
                // Bounded by the peer default (4096) until its SETTINGS
                // raises/lowers it — see applySettings.
                .max_table_size = hpack.default_max_table_size,
                .huffman = options.hpack_huffman,
            }),
            .hpack_dec = .init(gpa, .{
                .max_table_size = options.settings.header_table_size,
                .max_header_list_size = options.settings.max_header_list_size orelse
                    hpack.default_max_header_list_size,
            }),
            .conn_recv_window = default_initial_window_size,
            .next_local_stream_id = if (role == .client) 1 else 2,
            .preface_pending = role == .server,
            .max_header_block = options.max_header_block,
            .max_continuation_frames = options.max_continuation_frames,
            .max_reset_streams = options.max_reset_streams,
            .max_unproductive_frames = options.max_unproductive_frames,
        };
    }

    pub fn deinit(c: *Connection) void {
        c.hpack_enc.deinit();
        c.hpack_dec.deinit();
        c.streams.deinit(c.gpa);
        c.recv_buf.deinit(c.gpa);
        if (c.assembling) |*a| a.buf.deinit(c.gpa);
        c.* = undefined;
    }

    /// Look up a stream (introspection; e.g. for asserting states in tests
    /// and for the server layer's scheduling decisions).
    pub fn stream(c: *const Connection, id: u31) ?Stream {
        return c.streams.get(id);
    }

    // ── send side ───────────────────────────────────────────────────────────

    /// Errors from local send calls. These are caller bugs or local limits
    /// (e.g. flow-control exhaustion needing backpressure), not peer
    /// protocol violations.
    pub const SendError = error{
        /// No such stream (never created, or peer/state unknown).
        InvalidStream,
        /// Stream state does not permit sending this (§5.1).
        StreamNotWritable,
        /// Connection or stream send window has no room; wait for
        /// WINDOW_UPDATE and retry (§5.2).
        WindowExhausted,
    } || Allocator.Error;

    /// §3.4 connection preface: client magic (client role) + our SETTINGS.
    /// Call once, before anything else is sent.
    pub fn sendPreface(c: *Connection, out: *std.ArrayList(u8)) Allocator.Error!void {
        if (c.role == .client) try out.appendSlice(c.gpa, preface);
        try encodeSettings(c.gpa, out, c.local_settings);
    }

    /// Open a new locally-initiated stream (client request) and send its
    /// header block. Returns the stream id (§5.1.1: odd, monotonic).
    pub fn startStream(
        c: *Connection,
        out: *std.ArrayList(u8),
        fields: []const hpack.Field,
        end_stream: bool,
    ) SendError!u31 {
        std.debug.assert(c.role == .client); // servers respond on peer streams
        const id = c.next_local_stream_id;
        c.next_local_stream_id += 2;
        try c.streams.put(c.gpa, id, .{
            .id = id,
            .state = .open,
            .send_window = c.remote_settings.initial_window_size,
            .recv_window = c.local_settings.initial_window_size,
        });
        try c.sendHeaders(out, id, fields, end_stream);
        return id;
    }

    /// HPACK-encode `fields` and emit HEADERS (+ CONTINUATIONs when the
    /// block exceeds the peer's SETTINGS_MAX_FRAME_SIZE, §4.3/§6.10) on an
    /// existing stream. Servers use this for responses and trailers.
    pub fn sendHeaders(
        c: *Connection,
        out: *std.ArrayList(u8),
        stream_id: u31,
        fields: []const hpack.Field,
        end_stream: bool,
    ) SendError!void {
        const st = c.streams.getPtr(stream_id) orelse return error.InvalidStream;
        switch (st.state) {
            .open, .half_closed_remote => {},
            else => return error.StreamNotWritable,
        }
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(c.gpa);
        try c.hpack_enc.encodeBlock(fields, &block);

        const max_frag: usize = c.remote_settings.max_frame_size;
        var off: usize = 0;
        var first = true;
        while (true) {
            const n = @min(block.items.len - off, max_frag);
            const frag = block.items[off..][0..n];
            off += n;
            const last = off == block.items.len;
            if (first) {
                try encodeHeaders(c.gpa, out, stream_id, frag, .{
                    .end_stream = end_stream,
                    .end_headers = last,
                });
                first = false;
            } else {
                try encodeContinuation(c.gpa, out, stream_id, frag, last);
            }
            if (last) break;
        }
        if (end_stream) sendEndStream(st);
    }

    /// Send DATA, split across frames per the peer's SETTINGS_MAX_FRAME_SIZE
    /// and charged against both flow-control windows (§5.2). Fails with
    /// `WindowExhausted` (nothing is sent) when `data` does not fit — the
    /// caller implements backpressure/queueing on top.
    pub fn sendData(
        c: *Connection,
        out: *std.ArrayList(u8),
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
    ) SendError!void {
        const st = c.streams.getPtr(stream_id) orelse return error.InvalidStream;
        switch (st.state) {
            .open, .half_closed_remote => {},
            else => return error.StreamNotWritable,
        }
        const len: i64 = @intCast(data.len);
        if (len > c.conn_send_window or len > st.send_window) return error.WindowExhausted;

        const max_frag: usize = c.remote_settings.max_frame_size;
        var off: usize = 0;
        while (true) {
            const n = @min(data.len - off, max_frag);
            const chunk = data[off..][0..n];
            off += n;
            const last = off == data.len;
            try encodeData(c.gpa, out, stream_id, chunk, .{ .end_stream = end_stream and last });
            if (last) break;
        }
        c.conn_send_window -= len;
        st.send_window -= len;
        if (end_stream) sendEndStream(st);
    }

    /// Grant the peer `increment` more octets (§6.9); stream_id 0 = the
    /// connection window. Updates our receive accounting to match.
    pub fn sendWindowUpdate(
        c: *Connection,
        out: *std.ArrayList(u8),
        stream_id: u31,
        increment: u31,
    ) SendError!void {
        std.debug.assert(increment > 0);
        if (stream_id == 0) {
            c.conn_recv_window += increment;
            std.debug.assert(c.conn_recv_window <= max_window_size);
        } else {
            const st = c.streams.getPtr(stream_id) orelse return error.InvalidStream;
            st.recv_window += increment;
            std.debug.assert(st.recv_window <= max_window_size);
        }
        try encodeWindowUpdate(c.gpa, out, stream_id, increment);
    }

    /// PING (§6.7); expect a `ping_ack` event with the same payload.
    pub fn sendPing(c: *Connection, out: *std.ArrayList(u8), data: [8]u8) Allocator.Error!void {
        try encodePing(c.gpa, out, data, false);
    }

    /// RST_STREAM (§6.4): abort a stream; it transitions to closed.
    pub fn sendRstStream(
        c: *Connection,
        out: *std.ArrayList(u8),
        stream_id: u31,
        code: ErrorCode,
    ) SendError!void {
        const st = c.streams.getPtr(stream_id) orelse return error.InvalidStream;
        st.state = .closed;
        try encodeRstStream(c.gpa, out, stream_id, code);
    }

    /// GOAWAY (§6.8). `last_stream_id` defaults to the highest
    /// peer-initiated stream we processed.
    pub fn sendGoaway(
        c: *Connection,
        out: *std.ArrayList(u8),
        code: ErrorCode,
        debug: []const u8,
    ) Allocator.Error!void {
        const last = c.highest_remote_stream_id;
        c.goaway_sent = last;
        try encodeGoaway(c.gpa, out, last, code, debug);
    }

    /// §5.4.2 stream-error recovery: when the last `recv` failure was
    /// stream-scoped, close the offending stream, clear the violation and
    /// return it — the caller answers with RST_STREAM (carrying the
    /// returned code) and may keep using the connection, including calling
    /// `recv` again to drain frames already buffered behind the bad one.
    /// Returns null (and changes nothing) for connection-scoped violations,
    /// which stay fatal (§5.4.1: GOAWAY and close).
    pub fn recoverStreamError(c: *Connection) ?Violation {
        const v = c.violation orelse return null;
        if (v.scope != .stream) return null;
        if (c.streams.getPtr(v.stream_id)) |st| st.state = .closed;
        // CVE-2023-44487: a stream we must reset counts against the same
        // budget as peer resets — a peer forcing us to reset stream after
        // stream is doing the rapid-reset dance in reverse. The next
        // `recv` call fails with `error.EnhanceYourCalm` once exceeded.
        c.reset_streams += 1;
        c.violation = null;
        return v;
    }

    // ── receive side ────────────────────────────────────────────────────────

    pub const RecvError = Error || Allocator.Error;

    /// Consume raw connection bytes (any chunking — partial frames are
    /// buffered). Appends semantic events to `events` and auto-queues
    /// protocol replies (SETTINGS ACK, PING ACK) into `out`. On a protocol
    /// violation returns the typed error, with scope/stream/code detail in
    /// `violation`; the connection is then dead — send the matching
    /// GOAWAY/RST_STREAM and close.
    pub fn recv(
        c: *Connection,
        bytes: []const u8,
        out: *std.ArrayList(u8),
        events: *std.ArrayList(Event),
    ) RecvError!void {
        if (c.violation) |v| {
            // Dead connection; repeat the original violation class.
            _ = v;
            return error.ProtocolError;
        }
        // CVE-2023-44487 rapid reset: too many streams reset before
        // completion (peer RST_STREAMs and/or our own error recoveries).
        if (c.reset_streams > c.max_reset_streams)
            return c.fail(.connection, 0, error.EnhanceYourCalm);
        // Compact the consumed prefix, then buffer the new bytes. Event
        // slices handed out by the previous recv() die here — documented.
        if (c.recv_pos > 0) {
            const remaining = c.recv_buf.items.len - c.recv_pos;
            std.mem.copyForwards(
                u8,
                c.recv_buf.items[0..remaining],
                c.recv_buf.items[c.recv_pos..],
            );
            c.recv_buf.shrinkRetainingCapacity(remaining);
            c.recv_pos = 0;
        }
        try c.recv_buf.appendSlice(c.gpa, bytes);

        if (c.preface_pending) {
            if (c.recv_buf.items.len < preface.len) return;
            if (!std.mem.eql(u8, c.recv_buf.items[0..preface.len], preface))
                return c.fail(.connection, 0, error.ProtocolError);
            c.recv_pos = preface.len;
            c.preface_pending = false;
        }

        while (c.recv_buf.items.len - c.recv_pos >= frame_header_len) {
            const head = FrameHeader.decode(c.recv_buf.items[c.recv_pos..][0..frame_header_len]);
            if (head.length > c.local_settings.max_frame_size)
                return c.fail(.connection, head.stream_id, error.FrameSizeError);
            if (c.recv_buf.items.len - c.recv_pos < frame_header_len + head.length) return;
            const payload = c.recv_buf.items[c.recv_pos + frame_header_len ..][0..head.length];
            c.recv_pos += frame_header_len + head.length;
            try c.handleFrame(head, payload, out, events);
        }
    }

    fn handleFrame(
        c: *Connection,
        h: FrameHeader,
        payload: []const u8,
        out: *std.ArrayList(u8),
        events: *std.ArrayList(Event),
    ) RecvError!void {
        // §6.10/§4.3: an unfinished header block admits nothing but its own
        // CONTINUATION — any other frame is a connection PROTOCOL_ERROR.
        if (c.assembling) |a| {
            if (h.frame_type != .continuation or h.stream_id != a.stream_id)
                return c.fail(.connection, h.stream_id, error.ProtocolError);
        }
        // §3.4: the peer's first frame must be its SETTINGS.
        var handshake_settings = false;
        if (c.first_settings_pending) {
            if (h.frame_type != .settings or h.flags & Flags.ack != 0)
                return c.fail(.connection, h.stream_id, error.ProtocolError);
            c.first_settings_pending = false;
            handshake_settings = true;
        }

        const frame = parseFrame(h, payload) catch |err| {
            // Scope per §6.3 (PRIORITY length: stream error) and §6.9 (zero
            // increment on a stream: stream error); everything else is a
            // connection error.
            const scope: @FieldType(Violation, "scope") = switch (h.frame_type) {
                .priority => .stream,
                .window_update => if (h.stream_id != 0 and err == error.ProtocolError)
                    .stream
                else
                    .connection,
                else => .connection,
            };
            return c.fail(scope, h.stream_id, err);
        };

        switch (frame) {
            .data => |d| {
                const st = c.streams.getPtr(d.stream_id) orelse
                    return c.fail(.connection, d.stream_id, error.ProtocolError); // idle (§6.1)
                // Flow control charges the whole payload incl. padding (§6.1).
                if (h.length > c.conn_recv_window)
                    return c.fail(.connection, 0, error.FlowControlError);
                if (h.length > st.recv_window)
                    return c.fail(.stream, d.stream_id, error.FlowControlError);
                c.conn_recv_window -= h.length;
                st.recv_window -= h.length;
                switch (st.state) {
                    .open, .half_closed_local => {},
                    else => return c.fail(.stream, d.stream_id, error.StreamClosed),
                }
                // Zero-length DATA without END_STREAM makes no progress —
                // an empty-frame flood burns the unproductive budget.
                if (d.data.len == 0 and !d.end_stream)
                    try c.noteUnproductive()
                else
                    c.unproductive_frames = 0;
                if (d.end_stream) recvEndStream(st);
                try events.append(c.gpa, .{ .data = .{
                    .stream_id = d.stream_id,
                    .data = d.data,
                    .end_stream = d.end_stream,
                } });
            },
            .headers => |hd| {
                if (c.streams.getPtr(hd.stream_id)) |st| {
                    switch (st.state) {
                        .open, .half_closed_local => {},
                        .reserved_remote => st.state = .half_closed_local,
                        else => return c.fail(.stream, hd.stream_id, error.StreamClosed),
                    }
                    // Repeat HEADERS on an existing stream (trailers at
                    // best) are not new work — a trailer flood on one
                    // stream burns the unproductive budget.
                    try c.noteUnproductive();
                } else {
                    // New peer-initiated stream: §5.1.1 — clients initiate
                    // odd ids toward a server, monotonically, never reused;
                    // a server may open streams only via PUSH_PROMISE.
                    if (c.role == .client)
                        return c.fail(.connection, hd.stream_id, error.ProtocolError);
                    if (hd.stream_id % 2 == 0 or hd.stream_id <= c.highest_remote_stream_id)
                        return c.fail(.connection, hd.stream_id, error.ProtocolError);
                    c.highest_remote_stream_id = hd.stream_id;
                    c.remote_streams_total +|= 1;
                    c.unproductive_frames = 0; // a new request stream is progress
                    try c.streams.put(c.gpa, hd.stream_id, .{
                        .id = hd.stream_id,
                        .state = .open,
                        .send_window = c.remote_settings.initial_window_size,
                        .recv_window = c.local_settings.initial_window_size,
                    });
                }
                if (hd.priority) |p| try events.append(c.gpa, .{ .priority = .{
                    .stream_id = hd.stream_id,
                    .priority = p,
                } });
                if (hd.end_headers) {
                    try c.finishHeaderBlock(hd.stream_id, hd.fragment, hd.end_stream, events);
                } else {
                    try c.beginAssembly(.{
                        .kind = .headers,
                        .stream_id = hd.stream_id,
                        .end_stream = hd.end_stream,
                    }, hd.fragment);
                }
            },
            .priority => |p| {
                // Legal in any state, including idle (§6.3 / RFC 7540 §5.1)
                // — but advisory only, so it burns the unproductive budget.
                try c.noteUnproductive();
                try events.append(c.gpa, .{ .priority = .{
                    .stream_id = p.stream_id,
                    .priority = p.priority,
                } });
            },
            .rst_stream => |r| {
                const st = c.streams.getPtr(r.stream_id) orelse
                    return c.fail(.connection, r.stream_id, error.ProtocolError); // idle (§6.4)
                // CVE-2023-44487 rapid reset: a reset of a stream that had
                // not completed (both sides closed) is cancelled work.
                const was_done = st.state == .closed;
                st.state = .closed;
                if (!was_done) {
                    c.reset_streams += 1;
                    if (c.reset_streams > c.max_reset_streams)
                        return c.fail(.connection, r.stream_id, error.EnhanceYourCalm);
                }
                try events.append(c.gpa, .{ .stream_reset = .{
                    .stream_id = r.stream_id,
                    .code = r.code,
                } });
            },
            .settings => |s| {
                // SETTINGS beyond the §3.4 handshake one (and every ACK)
                // burn the unproductive budget — a SETTINGS flood makes us
                // re-apply state and emit an ACK per frame.
                if (!handshake_settings) try c.noteUnproductive();
                if (s.ack) {
                    try events.append(c.gpa, .settings_ack);
                } else {
                    try c.applySettings(s.payload);
                    try encodeSettingsAck(c.gpa, out);
                    try events.append(c.gpa, .settings);
                }
            },
            .push_promise => |pp| {
                // §8.4: only servers push; §6.6: recipient must have push
                // enabled and the associated stream must be peer-writable.
                if (c.role == .server or !c.local_settings.enable_push)
                    return c.fail(.connection, pp.stream_id, error.ProtocolError);
                const st = c.streams.getPtr(pp.stream_id) orelse
                    return c.fail(.connection, pp.stream_id, error.ProtocolError);
                switch (st.state) {
                    .open, .half_closed_local => {},
                    else => return c.fail(.connection, pp.stream_id, error.ProtocolError),
                }
                // §5.1.1: server-promised ids are even and monotonic.
                if (pp.promised_id % 2 != 0 or pp.promised_id <= c.highest_remote_stream_id)
                    return c.fail(.connection, pp.promised_id, error.ProtocolError);
                c.highest_remote_stream_id = pp.promised_id;
                try c.streams.put(c.gpa, pp.promised_id, .{
                    .id = pp.promised_id,
                    .state = .reserved_remote,
                    .send_window = c.remote_settings.initial_window_size,
                    .recv_window = c.local_settings.initial_window_size,
                });
                if (pp.end_headers) {
                    try c.finishPushPromise(pp.stream_id, pp.promised_id, pp.fragment, events);
                } else {
                    try c.beginAssembly(.{
                        .kind = .push_promise,
                        .stream_id = pp.stream_id,
                        .promised_id = pp.promised_id,
                    }, pp.fragment);
                }
            },
            .ping => |p| {
                // PING flood guard: still answered while under budget, but
                // a peer pinging faster than it does real work gets CALM
                // before we amplify its bytes any further.
                try c.noteUnproductive();
                if (p.ack) {
                    try events.append(c.gpa, .{ .ping_ack = .{ .data = p.data } });
                } else {
                    try encodePing(c.gpa, out, p.data, true);
                    try events.append(c.gpa, .{ .ping = .{ .data = p.data } });
                }
            },
            .goaway => |g| {
                c.goaway_recv = g.last_stream_id;
                try events.append(c.gpa, .{ .goaway = .{
                    .last_stream_id = g.last_stream_id,
                    .code = g.code,
                    .debug = g.debug,
                } });
            },
            .window_update => |wu| {
                if (wu.stream_id == 0) {
                    c.conn_send_window += wu.increment;
                    if (c.conn_send_window > max_window_size)
                        return c.fail(.connection, 0, error.FlowControlError); // §6.9.1
                } else if (c.streams.getPtr(wu.stream_id)) |st| {
                    if (st.state != .closed) {
                        st.send_window += wu.increment;
                        if (st.send_window > max_window_size)
                            return c.fail(.stream, wu.stream_id, error.FlowControlError);
                    } // closed: ignore (§5.1 short-lived-frame grace)
                } else {
                    return c.fail(.connection, wu.stream_id, error.ProtocolError); // idle
                }
                try events.append(c.gpa, .{ .window_update = .{
                    .stream_id = wu.stream_id,
                    .increment = wu.increment,
                } });
            },
            .continuation => |ct| {
                // CONTINUATION with no block in progress (§6.10).
                if (c.assembling == null)
                    return c.fail(.connection, ct.stream_id, error.ProtocolError);
                const a = &c.assembling.?;
                // CVE-2024-27316 CONTINUATION flood: bound the frame count
                // (zero-length frames dodge the size cap below) and the
                // reassembled size. Connection-scoped — §4.3: the header
                // block is part of the shared HPACK compression context.
                a.frames += 1;
                if (a.frames > c.max_continuation_frames)
                    return c.fail(.connection, ct.stream_id, error.EnhanceYourCalm);
                if (a.buf.items.len + ct.fragment.len > c.max_header_block)
                    return c.fail(.connection, ct.stream_id, error.EnhanceYourCalm);
                try a.buf.appendSlice(c.gpa, ct.fragment);
                if (ct.end_headers) {
                    var done = c.assembling.?;
                    c.assembling = null;
                    defer done.buf.deinit(c.gpa);
                    switch (done.kind) {
                        .headers => try c.finishHeaderBlock(
                            done.stream_id,
                            done.buf.items,
                            done.end_stream,
                            events,
                        ),
                        .push_promise => try c.finishPushPromise(
                            done.stream_id,
                            done.promised_id,
                            done.buf.items,
                            events,
                        ),
                    }
                }
            },
            // §4.1: ignore frames of unknown type — but an ignored frame is
            // still parse work, so a flood of them burns the budget.
            .unknown => try c.noteUnproductive(),
        }
    }

    // ── internals ───────────────────────────────────────────────────────────

    /// Charge one no-progress frame against the flood budget; breach it and
    /// the connection dies with `error.EnhanceYourCalm` (§5.4.1 GOAWAY).
    fn noteUnproductive(c: *Connection) Error!void {
        c.unproductive_frames += 1;
        if (c.unproductive_frames > c.max_unproductive_frames)
            return c.fail(.connection, 0, error.EnhanceYourCalm);
    }

    /// Record the violation detail and hand back the typed error.
    fn fail(
        c: *Connection,
        scope: @FieldType(Violation, "scope"),
        stream_id: u31,
        err: Error,
    ) Error {
        c.violation = .{ .scope = scope, .stream_id = stream_id, .code = errorCode(err) };
        return err;
    }

    fn beginAssembly(c: *Connection, a: Assembly, first_fragment: []const u8) RecvError!void {
        std.debug.assert(c.assembling == null);
        if (first_fragment.len > c.max_header_block)
            return c.fail(.connection, a.stream_id, error.EnhanceYourCalm);
        var started = a;
        try started.buf.appendSlice(c.gpa, first_fragment);
        c.assembling = started;
    }

    /// Run a complete header block through HPACK, apply END_STREAM, emit
    /// the event. HPACK failures are connection errors: COMPRESSION_ERROR
    /// (§4.3).
    fn finishHeaderBlock(
        c: *Connection,
        stream_id: u31,
        block: []const u8,
        end_stream: bool,
        events: *std.ArrayList(Event),
    ) RecvError!void {
        var list = c.hpack_dec.decodeBlock(block) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return c.fail(.connection, stream_id, error.CompressionError),
        };
        errdefer list.deinit(c.gpa);
        if (end_stream) recvEndStream(c.streams.getPtr(stream_id).?);
        try events.append(c.gpa, .{ .headers = .{
            .stream_id = stream_id,
            .headers = list,
            .end_stream = end_stream,
        } });
    }

    fn finishPushPromise(
        c: *Connection,
        stream_id: u31,
        promised_id: u31,
        block: []const u8,
        events: *std.ArrayList(Event),
    ) RecvError!void {
        var list = c.hpack_dec.decodeBlock(block) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return c.fail(.connection, stream_id, error.CompressionError),
        };
        errdefer list.deinit(c.gpa);
        try events.append(c.gpa, .{ .push_promise = .{
            .stream_id = stream_id,
            .promised_id = promised_id,
            .headers = list,
        } });
    }

    /// Validate + apply a peer SETTINGS payload (§6.5.2/§6.5.3).
    fn applySettings(c: *Connection, payload: []const u8) RecvError!void {
        var it: SettingsIterator = .{ .payload = payload };
        while (it.next()) |kv| switch (kv.id) {
            .header_table_size => {
                c.remote_settings.header_table_size = kv.value;
                // Our encoder must fit the peer's table; cap our own memory
                // at the default even if the peer allows more.
                c.hpack_enc.setMaxTableSize(@min(kv.value, hpack.default_max_table_size));
            },
            .enable_push => {
                if (kv.value > 1) return c.fail(.connection, 0, error.ProtocolError);
                c.remote_settings.enable_push = kv.value == 1;
            },
            .max_concurrent_streams => c.remote_settings.max_concurrent_streams = kv.value,
            .initial_window_size => {
                if (kv.value > max_window_size)
                    return c.fail(.connection, 0, error.FlowControlError); // §6.5.2
                // §6.9.2: adjust every stream send window by the delta (may
                // go negative); overflow is a FLOW_CONTROL_ERROR.
                const delta = @as(i64, kv.value) - c.remote_settings.initial_window_size;
                c.remote_settings.initial_window_size = kv.value;
                var streams_it = c.streams.valueIterator();
                while (streams_it.next()) |st| {
                    st.send_window += delta;
                    if (st.send_window > max_window_size)
                        return c.fail(.connection, 0, error.FlowControlError);
                }
            },
            .max_frame_size => {
                if (kv.value < default_max_frame_size or kv.value > max_allowed_frame_size)
                    return c.fail(.connection, 0, error.ProtocolError); // §6.5.2
                c.remote_settings.max_frame_size = kv.value;
            },
            .max_header_list_size => c.remote_settings.max_header_list_size = kv.value,
            _ => {}, // §6.5.2: ignore unknown parameters
        };
    }

    /// §5.1 transitions on receiving END_STREAM.
    fn recvEndStream(st: *Stream) void {
        st.state = switch (st.state) {
            .open => .half_closed_remote,
            .half_closed_local => .closed,
            else => st.state,
        };
    }

    /// §5.1 transitions on sending END_STREAM.
    fn sendEndStream(st: *Stream) void {
        st.state = switch (st.state) {
            .open => .half_closed_local,
            .half_closed_remote => .closed,
            else => st.state,
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Decode the single frame in `bytes` (header + payload).
fn parseOne(bytes: []const u8) !Frame {
    const h = FrameHeader.decode(bytes[0..frame_header_len]);
    try testing.expectEqual(bytes.len - frame_header_len, h.length);
    return parseFrame(h, bytes[frame_header_len..]);
}

test "frame header: encode/decode round-trip, reserved bit ignored" {
    const h: FrameHeader = .{
        .length = 0x00abcdef,
        .frame_type = .headers,
        .flags = Flags.end_headers | Flags.end_stream,
        .stream_id = 0x7fff_ffff,
    };
    var wire = h.encode();
    try testing.expectEqual(h, FrameHeader.decode(&wire));
    // Set the reserved bit on the wire — §4.1: must be ignored on receipt.
    wire[5] |= 0x80;
    try testing.expectEqual(h, FrameHeader.decode(&wire));

    const zero: FrameHeader = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 0 };
    try testing.expectEqual(zero, FrameHeader.decode(&zero.encode()));
}

test "DATA: round-trip plain, END_STREAM, padded (0 and max-fit)" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodeData(gpa, &out, 3, "hello", .{});
    const plain = try parseOne(out.items);
    try testing.expectEqual(@as(u31, 3), plain.data.stream_id);
    try testing.expectEqualStrings("hello", plain.data.data);
    try testing.expect(!plain.data.end_stream);

    out.clearRetainingCapacity();
    try encodeData(gpa, &out, 5, "", .{ .end_stream = true });
    const fin = try parseOne(out.items);
    try testing.expect(fin.data.end_stream);
    try testing.expectEqual(@as(usize, 0), fin.data.data.len);

    out.clearRetainingCapacity();
    try encodeData(gpa, &out, 7, "padded!", .{ .pad = 0 });
    const pad0 = try parseOne(out.items);
    try testing.expectEqualStrings("padded!", pad0.data.data);
    // On the wire: 9 header + 1 pad-length + 7 data + 0 padding.
    try testing.expectEqual(@as(usize, 17), out.items.len);

    out.clearRetainingCapacity();
    try encodeData(gpa, &out, 7, "x", .{ .pad = 255 });
    const padmax = try parseOne(out.items);
    try testing.expectEqualStrings("x", padmax.data.data);
    try testing.expectEqual(@as(usize, 9 + 1 + 1 + 255), out.items.len);
}

test "DATA: padding >= payload and stream 0 rejected" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    // Pad length 4 but only 3 octets follow the pad-length field.
    try encodeRawFrame(gpa, &out, .data, Flags.padded, 1, &.{ 4, 'a', 'b', 'c' });
    try testing.expectError(error.ProtocolError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .data, Flags.padded, 1, &.{}); // PADDED, empty
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .data, 0, 0, "x"); // stream 0
    try testing.expectError(error.ProtocolError, parseOne(out.items));
}

test "HEADERS: round-trip flags, priority fields, priority+padding" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodeHeaders(gpa, &out, 9, "frag", .{ .end_stream = true });
    const plain = try parseOne(out.items);
    try testing.expectEqualStrings("frag", plain.headers.fragment);
    try testing.expect(plain.headers.end_stream);
    try testing.expect(plain.headers.end_headers);
    try testing.expectEqual(@as(?Priority, null), plain.headers.priority);

    out.clearRetainingCapacity();
    const prio: Priority = .{ .exclusive = true, .dependency = 11, .weight = 200 };
    try encodeHeaders(gpa, &out, 9, "frag", .{ .end_headers = false, .priority = prio });
    const withprio = try parseOne(out.items);
    try testing.expect(!withprio.headers.end_headers);
    try testing.expectEqual(prio, withprio.headers.priority.?);
    try testing.expectEqualStrings("frag", withprio.headers.fragment);

    out.clearRetainingCapacity();
    try encodeHeaders(gpa, &out, 9, "frag", .{ .priority = prio, .pad = 6 });
    const both = try parseOne(out.items);
    try testing.expectEqual(prio, both.headers.priority.?);
    try testing.expectEqualStrings("frag", both.headers.fragment);

    // Padding that swallows the priority fields → PROTOCOL_ERROR.
    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .headers, Flags.padded | Flags.priority, 9, &.{ 9, 0, 0, 0, 1, 42, 'x', 'y', 'z' });
    try testing.expectError(error.ProtocolError, parseOne(out.items));
}

test "PRIORITY: round-trip and length check" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    const prio: Priority = .{ .exclusive = false, .dependency = max_window_size, .weight = 0 };
    try encodePriority(gpa, &out, 15, prio);
    const p = try parseOne(out.items);
    try testing.expectEqual(@as(u31, 15), p.priority.stream_id);
    try testing.expectEqual(prio, p.priority.priority);

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .priority, 0, 15, &.{ 0, 0, 0, 1 }); // 4 bytes
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .priority, 0, 0, &.{ 0, 0, 0, 1, 5 }); // stream 0
    try testing.expectError(error.ProtocolError, parseOne(out.items));
}

test "RST_STREAM: round-trip incl. unknown code; length check" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodeRstStream(gpa, &out, 5, .cancel);
    const r = try parseOne(out.items);
    try testing.expectEqual(ErrorCode.cancel, r.rst_stream.code);

    out.clearRetainingCapacity();
    try encodeRstStream(gpa, &out, 5, @enumFromInt(0xdeadbeef)); // unknown code survives
    const unk = try parseOne(out.items);
    try testing.expectEqual(@as(u32, 0xdeadbeef), @intFromEnum(unk.rst_stream.code));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .rst_stream, 0, 5, &.{ 0, 0, 8 }); // 3 bytes
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .rst_stream, 0, 0, &.{ 0, 0, 0, 8 }); // stream 0
    try testing.expectError(error.ProtocolError, parseOne(out.items));
}

test "SETTINGS: round-trip via iterator; ACK; malformed lengths" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodeSettings(gpa, &out, .{
        .header_table_size = 8192,
        .enable_push = false,
        .initial_window_size = 100_000,
        .max_frame_size = 32_768,
        .max_concurrent_streams = 128,
        .max_header_list_size = 16_384,
    });
    const s = try parseOne(out.items);
    try testing.expect(!s.settings.ack);
    var got: Settings = .{};
    var it: SettingsIterator = .{ .payload = s.settings.payload };
    var n: usize = 0;
    while (it.next()) |kv| : (n += 1) switch (kv.id) {
        .header_table_size => got.header_table_size = kv.value,
        .enable_push => got.enable_push = kv.value == 1,
        .max_concurrent_streams => got.max_concurrent_streams = kv.value,
        .initial_window_size => got.initial_window_size = kv.value,
        .max_frame_size => got.max_frame_size = kv.value,
        .max_header_list_size => got.max_header_list_size = kv.value,
        _ => {},
    };
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqual(@as(u32, 8192), got.header_table_size);
    try testing.expect(!got.enable_push);
    try testing.expectEqual(@as(?u32, 128), got.max_concurrent_streams);
    try testing.expectEqual(@as(u32, 100_000), got.initial_window_size);
    try testing.expectEqual(@as(u32, 32_768), got.max_frame_size);
    try testing.expectEqual(@as(?u32, 16_384), got.max_header_list_size);

    out.clearRetainingCapacity();
    try encodeSettingsAck(gpa, &out);
    const ack = try parseOne(out.items);
    try testing.expect(ack.settings.ack);
    try testing.expectEqual(@as(usize, 0), ack.settings.payload.len);

    // ACK with payload → FRAME_SIZE_ERROR (§6.5).
    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .settings, Flags.ack, 0, &(.{0} ** 6));
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    // Length not a multiple of 6 → FRAME_SIZE_ERROR (§6.5).
    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .settings, 0, 0, &.{ 0, 1, 0 });
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    // SETTINGS on a stream → PROTOCOL_ERROR (§6.5).
    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .settings, 0, 1, &.{});
    try testing.expectError(error.ProtocolError, parseOne(out.items));
}

test "PUSH_PROMISE / PING / GOAWAY / WINDOW_UPDATE / CONTINUATION round-trips" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodePushPromise(gpa, &out, 1, 2, "frag", true);
    const pp = try parseOne(out.items);
    try testing.expectEqual(@as(u31, 1), pp.push_promise.stream_id);
    try testing.expectEqual(@as(u31, 2), pp.push_promise.promised_id);
    try testing.expectEqualStrings("frag", pp.push_promise.fragment);
    try testing.expect(pp.push_promise.end_headers);

    out.clearRetainingCapacity();
    const opaque_data: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try encodePing(gpa, &out, opaque_data, false);
    const ping = try parseOne(out.items);
    try testing.expect(!ping.ping.ack);
    try testing.expectEqual(opaque_data, ping.ping.data);
    out.clearRetainingCapacity();
    try encodePing(gpa, &out, opaque_data, true);
    try testing.expect((try parseOne(out.items)).ping.ack);

    out.clearRetainingCapacity();
    try encodeGoaway(gpa, &out, 41, .enhance_your_calm, "debug data");
    const ga = try parseOne(out.items);
    try testing.expectEqual(@as(u31, 41), ga.goaway.last_stream_id);
    try testing.expectEqual(ErrorCode.enhance_your_calm, ga.goaway.code);
    try testing.expectEqualStrings("debug data", ga.goaway.debug);

    out.clearRetainingCapacity();
    try encodeGoaway(gpa, &out, 0, .no_error, ""); // minimal: 8-octet payload
    const ga0 = try parseOne(out.items);
    try testing.expectEqual(@as(usize, 0), ga0.goaway.debug.len);

    out.clearRetainingCapacity();
    try encodeWindowUpdate(gpa, &out, 0, max_window_size);
    const wu = try parseOne(out.items);
    try testing.expectEqual(@as(u31, 0), wu.window_update.stream_id);
    try testing.expectEqual(@as(u31, max_window_size), wu.window_update.increment);

    out.clearRetainingCapacity();
    try encodeContinuation(gpa, &out, 5, "more", false);
    const cont = try parseOne(out.items);
    try testing.expectEqualStrings("more", cont.continuation.fragment);
    try testing.expect(!cont.continuation.end_headers);
}

test "PING/GOAWAY/WINDOW_UPDATE/CONTINUATION: malformed rejected" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodeRawFrame(gpa, &out, .ping, 0, 0, &.{ 1, 2, 3, 4, 5, 6, 7 }); // 7 bytes
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .ping, 0, 3, &(.{0} ** 8)); // stream != 0
    try testing.expectError(error.ProtocolError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .goaway, 0, 0, &.{ 0, 0, 0, 1 }); // < 8 bytes
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .goaway, 0, 1, &(.{0} ** 8)); // stream != 0
    try testing.expectError(error.ProtocolError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .window_update, 0, 1, &.{ 0, 0, 1 }); // 3 bytes
    try testing.expectError(error.FrameSizeError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .window_update, 0, 1, &.{ 0, 0, 0, 0 }); // zero increment
    try testing.expectError(error.ProtocolError, parseOne(out.items));

    out.clearRetainingCapacity();
    try encodeRawFrame(gpa, &out, .continuation, 0, 0, "frag"); // stream 0
    try testing.expectError(error.ProtocolError, parseOne(out.items));
}

test "unknown frame type parses as .unknown; boundary-length payload" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try encodeRawFrame(gpa, &out, @enumFromInt(0xbe), 0xff, 21, "whatever");
    const u = try parseOne(out.items);
    try testing.expectEqual(@as(u8, 0xbe), u.unknown.frame_type);
    try testing.expectEqual(@as(u31, 21), u.unknown.stream_id);

    // A payload of exactly the default SETTINGS_MAX_FRAME_SIZE.
    out.clearRetainingCapacity();
    const big = try gpa.alloc(u8, default_max_frame_size);
    defer gpa.free(big);
    @memset(big, 0xaa);
    try encodeData(gpa, &out, 1, big, .{});
    const d = try parseOne(out.items);
    try testing.expectEqual(@as(usize, default_max_frame_size), d.data.data.len);
}

// ── connection-level test helpers ───────────────────────────────────────────

fn clearEvents(events: *std.ArrayList(Event)) void {
    for (events.items) |*ev| ev.deinit(testing.allocator);
    events.clearRetainingCapacity();
}

fn freeEvents(events: *std.ArrayList(Event)) void {
    clearEvents(events);
    events.deinit(testing.allocator);
}

/// A server `Connection` that already consumed the client preface + an
/// empty-default SETTINGS frame (handshake done, no events pending).
fn testServer() !Connection {
    const gpa = testing.allocator;
    var conn: Connection = .init(gpa, .server, .{});
    errdefer conn.deinit();
    var handshake: std.ArrayList(u8) = .empty;
    defer handshake.deinit(gpa);
    try handshake.appendSlice(gpa, preface);
    try encodeSettings(gpa, &handshake, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try conn.recv(handshake.items, &out, &events);
    return conn;
}

/// Feed `bytes` and expect the typed violation with its §7 code + scope.
fn expectViolation(
    conn: *Connection,
    bytes: []const u8,
    expected: Error,
    scope: @FieldType(Violation, "scope"),
) !void {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try testing.expectError(expected, conn.recv(bytes, &out, &events));
    const v = conn.violation.?;
    try testing.expectEqual(errorCode(expected), v.code);
    try testing.expectEqual(scope, v.scope);
}

test "connection: bad client preface → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn: Connection = .init(gpa, .server, .{});
    defer conn.deinit();
    try expectViolation(&conn, "GET / HTTP/1.1\r\nHost: x\r\n", error.ProtocolError, .connection);
}

test "connection: first frame not SETTINGS → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn: Connection = .init(gpa, .server, .{});
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try bytes.appendSlice(gpa, preface);
    try encodePing(gpa, &bytes, .{0} ** 8, false);
    try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
}

test "connection: oversized frame → FRAME_SIZE_ERROR" {
    var conn = try testServer();
    defer conn.deinit();
    // Only the 9-octet header is needed — the length field alone convicts.
    const h: FrameHeader = .{
        .length = default_max_frame_size + 1,
        .frame_type = .data,
        .flags = 0,
        .stream_id = 1,
    };
    try expectViolation(&conn, &h.encode(), error.FrameSizeError, .connection);
}

test "connection: DATA on idle stream → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeData(gpa, &bytes, 1, "boo", .{});
    try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
}

test "connection: RST_STREAM on idle stream → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeRstStream(gpa, &bytes, 1, .cancel);
    try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
}

test "connection: HEADERS without END_HEADERS then another frame → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeHeaders(gpa, &bytes, 1, &.{0x82}, .{ .end_headers = false });
    try encodePing(gpa, &bytes, .{0} ** 8, false); // must have been CONTINUATION
    try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
}

test "connection: CONTINUATION on the wrong stream → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeHeaders(gpa, &bytes, 1, &.{0x82}, .{ .end_headers = false });
    try encodeContinuation(gpa, &bytes, 3, &.{0x87}, true);
    try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
}

test "connection: CONTINUATION without preceding HEADERS → PROTOCOL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeContinuation(gpa, &bytes, 1, &.{0x82}, true);
    try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
}

test "connection: SETTINGS ACK with payload → FRAME_SIZE_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeRawFrame(gpa, &bytes, .settings, Flags.ack, 0, &(.{0} ** 6));
    try expectViolation(&conn, bytes.items, error.FrameSizeError, .connection);
}

test "connection: connection window overflow → FLOW_CONTROL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    // 65535 (initial) + 2^31-1 exceeds the §6.9.1 cap.
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeWindowUpdate(gpa, &bytes, 0, max_window_size);
    try expectViolation(&conn, bytes.items, error.FlowControlError, .connection);
}

test "connection: bad SETTINGS values rejected with the right codes" {
    const gpa = testing.allocator;
    {
        var conn = try testServer();
        defer conn.deinit();
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(gpa);
        var payload: [6]u8 = undefined;
        var n: usize = 0;
        putSetting(@ptrCast(&payload), &n, .enable_push, 2); // must be 0/1
        try encodeRawFrame(gpa, &bytes, .settings, 0, 0, &payload);
        try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
    }
    {
        var conn = try testServer();
        defer conn.deinit();
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(gpa);
        var payload: [6]u8 = undefined;
        var n: usize = 0;
        putSetting(@ptrCast(&payload), &n, .initial_window_size, max_window_size + 1);
        try encodeRawFrame(gpa, &bytes, .settings, 0, 0, &payload);
        try expectViolation(&conn, bytes.items, error.FlowControlError, .connection);
    }
    {
        var conn = try testServer();
        defer conn.deinit();
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(gpa);
        var payload: [6]u8 = undefined;
        var n: usize = 0;
        putSetting(@ptrCast(&payload), &n, .max_frame_size, 1000); // < 16384
        try encodeRawFrame(gpa, &bytes, .settings, 0, 0, &payload);
        try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
    }
}

test "connection: stream id rules — even id and reuse rejected" {
    const gpa = testing.allocator;
    {
        var conn = try testServer();
        defer conn.deinit();
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(gpa);
        try encodeHeaders(gpa, &bytes, 2, &.{0x82}, .{}); // client ids are odd
        try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
    }
    {
        var conn = try testServer();
        defer conn.deinit();
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var events: std.ArrayList(Event) = .empty;
        defer freeEvents(&events);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(gpa);
        try encodeHeaders(gpa, &bytes, 5, &.{0x82}, .{});
        try conn.recv(bytes.items, &out, &events);
        bytes.clearRetainingCapacity();
        try encodeHeaders(gpa, &bytes, 3, &.{0x82}, .{}); // §5.1.1: not monotonic
        try expectViolation(&conn, bytes.items, error.ProtocolError, .connection);
    }
}

test "connection: garbage HPACK block → COMPRESSION_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    try encodeHeaders(gpa, &bytes, 1, &.{ 0x40, 0x7f }, .{}); // truncated literal
    try expectViolation(&conn, bytes.items, error.CompressionError, .connection);
}

/// "Pipe" hop: feed everything `src` accumulated into `dst`, letting `dst`
/// append its automatic replies to `reply`; `src` is drained.
fn deliver(
    src: *std.ArrayList(u8),
    dst: *Connection,
    reply: *std.ArrayList(u8),
    events: *std.ArrayList(Event),
) !void {
    try dst.recv(src.items, reply, events);
    src.clearRetainingCapacity();
}

test "connection: full client/server exchange over an in-memory pipe" {
    const gpa = testing.allocator;
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit();
    var server: Connection = .init(gpa, .server, .{});
    defer server.deinit();
    var c2s: std.ArrayList(u8) = .empty; // client → server wire
    defer c2s.deinit(gpa);
    var s2c: std.ArrayList(u8) = .empty; // server → client wire
    defer s2c.deinit(gpa);
    var c_events: std.ArrayList(Event) = .empty;
    defer freeEvents(&c_events);
    var s_events: std.ArrayList(Event) = .empty;
    defer freeEvents(&s_events);

    // §3.4 handshake: prefaces + SETTINGS, then the auto-ACKs cross.
    try client.sendPreface(&c2s);
    try server.sendPreface(&s2c);
    try deliver(&c2s, &server, &s2c, &s_events); // magic + SETTINGS; ACK queued
    try deliver(&s2c, &client, &c2s, &c_events); // SETTINGS + ACK; ACK queued
    try deliver(&c2s, &server, &s2c, &s_events); // client's ACK
    try testing.expectEqual(@as(usize, 2), s_events.items.len);
    try testing.expectEqual(Event.settings, s_events.items[0]);
    try testing.expectEqual(Event.settings_ack, s_events.items[1]);
    try testing.expectEqual(@as(usize, 2), c_events.items.len);
    try testing.expectEqual(Event.settings, c_events.items[0]);
    try testing.expectEqual(Event.settings_ack, c_events.items[1]);
    clearEvents(&s_events);
    clearEvents(&c_events);

    // Request: HEADERS then DATA with END_STREAM.
    const sid = try client.startStream(&c2s, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/submit" },
        .{ .name = ":authority", .value = "example.com" },
    }, false);
    try testing.expectEqual(@as(u31, 1), sid);
    const request_body = "hello h2";
    try client.sendData(&c2s, sid, request_body, true);
    try testing.expectEqual(StreamState.half_closed_local, client.stream(sid).?.state);
    try deliver(&c2s, &server, &s2c, &s_events);

    try testing.expectEqual(@as(usize, 2), s_events.items.len);
    const req = s_events.items[0].headers;
    try testing.expectEqual(sid, req.stream_id);
    try testing.expect(!req.end_stream);
    try testing.expectEqual(@as(usize, 4), req.headers.fields.len);
    try testing.expectEqualStrings(":method", req.headers.fields[0].name);
    try testing.expectEqualStrings("POST", req.headers.fields[0].value);
    try testing.expectEqualStrings("/submit", req.headers.fields[2].value);
    const req_data = s_events.items[1].data;
    try testing.expectEqualStrings(request_body, req_data.data);
    try testing.expect(req_data.end_stream);
    try testing.expectEqual(StreamState.half_closed_remote, server.stream(sid).?.state);
    clearEvents(&s_events);

    // Both sides charged the request body against their windows.
    const w: i64 = default_initial_window_size;
    try testing.expectEqual(w - request_body.len, client.conn_send_window);
    try testing.expectEqual(w - request_body.len, server.conn_recv_window);
    try testing.expectEqual(w - request_body.len, server.stream(sid).?.recv_window);

    // Response: HEADERS then DATA with END_STREAM → stream fully closed.
    try server.sendHeaders(&s2c, sid, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    }, false);
    const response_body = "response body!";
    try server.sendData(&s2c, sid, response_body, true);
    try testing.expectEqual(StreamState.closed, server.stream(sid).?.state);
    try deliver(&s2c, &client, &c2s, &c_events);

    try testing.expectEqual(@as(usize, 2), c_events.items.len);
    const resp = c_events.items[0].headers;
    try testing.expectEqualStrings(":status", resp.headers.fields[0].name);
    try testing.expectEqualStrings("200", resp.headers.fields[0].value);
    try testing.expectEqualStrings(response_body, c_events.items[1].data.data);
    try testing.expect(c_events.items[1].data.end_stream);
    try testing.expectEqual(StreamState.closed, client.stream(sid).?.state);
    clearEvents(&c_events);

    // WINDOW_UPDATE round: each side replenishes what it consumed.
    try server.sendWindowUpdate(&s2c, 0, request_body.len);
    try client.sendWindowUpdate(&c2s, 0, response_body.len);
    try deliver(&s2c, &client, &c2s, &c_events);
    try deliver(&c2s, &server, &s2c, &s_events);
    try testing.expectEqual(
        @as(u31, request_body.len),
        c_events.items[0].window_update.increment,
    );
    clearEvents(&c_events);
    clearEvents(&s_events);
    // Windows reconcile back to the initial values on both sides.
    try testing.expectEqual(w, client.conn_send_window);
    try testing.expectEqual(w, server.conn_recv_window);
    try testing.expectEqual(w, server.conn_send_window);
    try testing.expectEqual(w, client.conn_recv_window);

    // PING / PING-ACK.
    const ping_data: [8]u8 = "ping-pot".*;
    try client.sendPing(&c2s, ping_data);
    try deliver(&c2s, &server, &s2c, &s_events);
    try testing.expectEqual(ping_data, s_events.items[0].ping.data);
    clearEvents(&s_events);
    try deliver(&s2c, &client, &c2s, &c_events); // the auto-ACK
    try testing.expectEqual(ping_data, c_events.items[0].ping_ack.data);
    clearEvents(&c_events);

    // GOAWAY.
    try server.sendGoaway(&s2c, .no_error, "done");
    try deliver(&s2c, &client, &c2s, &c_events);
    const ga = c_events.items[0].goaway;
    try testing.expectEqual(sid, ga.last_stream_id);
    try testing.expectEqual(ErrorCode.no_error, ga.code);
    try testing.expectEqualStrings("done", ga.debug);
    try testing.expectEqual(@as(?u31, sid), client.goaway_recv);
    try testing.expectEqual(@as(?u31, sid), server.goaway_sent);
    clearEvents(&c_events);

    // No violations anywhere; wires drained.
    try testing.expectEqual(@as(?Violation, null), client.violation);
    try testing.expectEqual(@as(?Violation, null), server.violation);
    try testing.expectEqual(@as(usize, 0), c2s.items.len);
    try testing.expectEqual(@as(usize, 0), s2c.items.len);
}

test "connection: header block spans HEADERS + CONTINUATION both directions" {
    const gpa = testing.allocator;
    var server = try testServer();
    defer server.deinit();
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit();
    // Force tiny outgoing frames so the block must fragment (test-only:
    // a real peer could never advertise < 16384).
    client.remote_settings.max_frame_size = 16;

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    const long_value = "0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ" ** 3;
    const sid = try client.startStream(&wire, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-long", .value = long_value },
    }, true);

    // Inspect the emitted frame sequence: HEADERS then CONTINUATIONs, with
    // END_HEADERS only on the last.
    var off: usize = 0;
    var count: usize = 0;
    while (off < wire.items.len) : (count += 1) {
        const h = FrameHeader.decode(wire.items[off..][0..frame_header_len]);
        try testing.expect(h.length <= 16);
        if (count == 0) {
            try testing.expectEqual(FrameType.headers, h.frame_type);
        } else {
            try testing.expectEqual(FrameType.continuation, h.frame_type);
        }
        off += frame_header_len + h.length;
        const is_last = off == wire.items.len;
        try testing.expectEqual(is_last, h.flags & Flags.end_headers != 0);
    }
    try testing.expect(count >= 3);

    // The server reassembles and HPACK-decodes the block.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try server.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    const hd = events.items[0].headers;
    try testing.expectEqual(sid, hd.stream_id);
    try testing.expect(hd.end_stream);
    try testing.expectEqualStrings("x-long", hd.headers.fields[1].name);
    try testing.expectEqualStrings(long_value, hd.headers.fields[1].value);
    try testing.expectEqual(StreamState.half_closed_remote, server.stream(sid).?.state);
}

test "connection: arbitrary chunking — one byte at a time" {
    const gpa = testing.allocator;
    var conn: Connection = .init(gpa, .server, .{});
    defer conn.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try wire.appendSlice(gpa, preface);
    try encodeSettings(gpa, &wire, .{});
    try encodeHeaders(gpa, &wire, 1, &.{0x82}, .{ .end_stream = true });
    try encodePing(gpa, &wire, "dribbled".*, false);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    for (wire.items) |b| try conn.recv(&.{b}, &out, &events);
    try testing.expectEqual(@as(usize, 3), events.items.len);
    try testing.expectEqual(Event.settings, events.items[0]);
    try testing.expectEqualStrings(":method", events.items[1].headers.headers.fields[0].name);
    try testing.expectEqual(@as([8]u8, "dribbled".*), events.items[2].ping.data);
}

test "connection: PUSH_PROMISE — client accepts, server rejects" {
    const gpa = testing.allocator;
    // Client side: promised stream is reserved, then its HEADERS arrive.
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    const sid = try client.startStream(&out, &.{.{ .name = ":method", .value = "GET" }}, true);
    try encodeSettings(gpa, &wire, .{}); // server preface SETTINGS
    try encodePushPromise(gpa, &wire, sid, 2, &.{0x82}, true);
    try encodeHeaders(gpa, &wire, 2, &.{0x88}, .{ .end_stream = true }); // :status 200
    try client.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(usize, 3), events.items.len);
    const pp = events.items[1].push_promise;
    try testing.expectEqual(sid, pp.stream_id);
    try testing.expectEqual(@as(u31, 2), pp.promised_id);
    try testing.expectEqualStrings(":method", pp.headers.fields[0].name);
    try testing.expectEqualStrings(":status", events.items[2].headers.headers.fields[0].name);
    // reserved_remote → half_closed_local → (END_STREAM) closed (§5.1).
    try testing.expectEqual(StreamState.closed, client.stream(2).?.state);

    // Server side: a client must never promise (§8.4).
    var server = try testServer();
    defer server.deinit();
    wire.clearRetainingCapacity();
    try encodePushPromise(gpa, &wire, 1, 2, &.{0x82}, true);
    try expectViolation(&server, wire.items, error.ProtocolError, .connection);
}

test "connection: SETTINGS_INITIAL_WINDOW_SIZE delta adjusts open streams" {
    const gpa = testing.allocator;
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    const sid = try client.startStream(&out, &.{.{ .name = ":method", .value = "GET" }}, false);
    try testing.expectEqual(
        @as(i64, default_initial_window_size),
        client.stream(sid).?.send_window,
    );

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    var payload: [6]u8 = undefined;
    var n: usize = 0;
    putSetting(@ptrCast(&payload), &n, .initial_window_size, 70_000);
    try encodeRawFrame(gpa, &wire, .settings, 0, 0, &payload);
    try client.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(i64, 70_000), client.stream(sid).?.send_window); // §6.9.2
    // The connection window is NOT adjusted by SETTINGS (§6.9.2).
    try testing.expectEqual(@as(i64, default_initial_window_size), client.conn_send_window);

    wire.clearRetainingCapacity();
    n = 0;
    putSetting(@ptrCast(&payload), &n, .initial_window_size, 100);
    try encodeRawFrame(gpa, &wire, .settings, 0, 0, &payload);
    try client.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(i64, 100), client.stream(sid).?.send_window);
}

test "connection: DATA past the receive window → FLOW_CONTROL_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeHeaders(gpa, &wire, 1, &.{0x82}, .{});
    const chunk = [_]u8{0xaa} ** 16_000;
    // 5 × 16000 = 80000 > 65535: the fifth frame overdraws the window.
    for (0..5) |_| try encodeData(gpa, &wire, 1, &chunk, .{});
    try expectViolation(&conn, wire.items, error.FlowControlError, .connection);
}

test "connection: frames on a half-closed(remote) stream → STREAM_CLOSED" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeHeaders(gpa, &wire, 1, &.{0x82}, .{ .end_stream = true });
    try encodeData(gpa, &wire, 1, "late", .{});
    try expectViolation(&conn, wire.items, error.StreamClosed, .stream);
    try testing.expectEqual(@as(u31, 1), conn.violation.?.stream_id);
}

test "connection: recoverStreamError clears a stream violation; connection error stays fatal" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeHeaders(gpa, &wire, 1, &.{0x82}, .{ .end_stream = true });
    try encodeData(gpa, &wire, 1, "late", .{}); // → stream-scope STREAM_CLOSED
    try expectViolation(&conn, wire.items, error.StreamClosed, .stream);

    // Recover: violation reported + cleared, stream closed, connection lives.
    const v = conn.recoverStreamError().?;
    try testing.expectEqual(@as(u31, 1), v.stream_id);
    try testing.expectEqual(ErrorCode.stream_closed, v.code);
    try testing.expectEqual(@as(?Violation, null), conn.violation);
    try testing.expectEqual(StreamState.closed, conn.stream(1).?.state);

    // The connection accepts further traffic (a new stream works).
    wire.clearRetainingCapacity();
    try encodeHeaders(gpa, &wire, 3, &.{0x82}, .{ .end_stream = true });
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try conn.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u31, 3), events.items[0].headers.stream_id);

    // Connection-scoped violations are not recoverable.
    wire.clearRetainingCapacity();
    try encodeRawFrame(gpa, &wire, .settings, 0, 1, &.{}); // SETTINGS on a stream
    try expectViolation(&conn, wire.items, error.ProtocolError, .connection);
    try testing.expectEqual(@as(?Violation, null), conn.recoverStreamError());
    try testing.expect(conn.violation != null);
}

test "connection: PRIORITY with bad length is a stream-scope FRAME_SIZE_ERROR" {
    const gpa = testing.allocator;
    var conn = try testServer();
    defer conn.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeRawFrame(gpa, &wire, .priority, 0, 1, &.{ 0, 0, 0, 1 });
    try expectViolation(&conn, wire.items, error.FrameSizeError, .stream);
}

test "connection: send-side guards — windows, states, stream ids" {
    const gpa = testing.allocator;
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    const sid = try client.startStream(&out, &.{.{ .name = ":method", .value = "GET" }}, false);
    try testing.expectEqual(@as(u31, 1), sid);

    // More than the 65535-octet initial window: refused locally, unsent.
    const big = try gpa.alloc(u8, default_initial_window_size + 1);
    defer gpa.free(big);
    @memset(big, 0);
    try testing.expectError(error.WindowExhausted, client.sendData(&out, sid, big, false));

    try testing.expectError(error.InvalidStream, client.sendData(&out, 99, "x", false));

    try client.sendData(&out, sid, "fin", true); // open → half_closed_local
    try testing.expectError(error.StreamNotWritable, client.sendData(&out, sid, "x", false));
    try testing.expectError(error.StreamNotWritable, client.sendHeaders(&out, sid, &.{}, true));

    // §5.1.1: locally-initiated ids stay odd and monotonic.
    const sid2 = try client.startStream(&out, &.{.{ .name = ":method", .value = "GET" }}, true);
    try testing.expectEqual(@as(u31, 3), sid2);
    try testing.expectEqual(StreamState.half_closed_local, client.stream(sid2).?.state);
}

// ── DoS-hardening tests (CVE-2023-44487, CVE-2024-27316, flood guards) ──────

/// A server `Connection` with custom options, handshake already consumed.
fn testServerWith(options: Connection.Options) !Connection {
    const gpa = testing.allocator;
    var conn: Connection = .init(gpa, .server, options);
    errdefer conn.deinit();
    var handshake: std.ArrayList(u8) = .empty;
    defer handshake.deinit(gpa);
    try handshake.appendSlice(gpa, preface);
    try encodeSettings(gpa, &handshake, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try conn.recv(handshake.items, &out, &events);
    return conn;
}

test "connection: rapid reset (CVE-2023-44487) → ENHANCE_YOUR_CALM" {
    const gpa = testing.allocator;
    var conn = try testServerWith(.{ .max_reset_streams = 3 });
    defer conn.deinit();

    // Three open-then-cancel rounds stay within the budget…
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    var sid: u31 = 1;
    for (0..3) |_| {
        try encodeHeaders(gpa, &wire, sid, &.{0x82}, .{});
        try encodeRstStream(gpa, &wire, sid, .cancel);
        sid += 2;
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try conn.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(u32, 3), conn.reset_streams);
    clearEvents(&events);

    // …the fourth breaches: connection-scoped ENHANCE_YOUR_CALM.
    wire.clearRetainingCapacity();
    try encodeHeaders(gpa, &wire, sid, &.{0x82}, .{});
    try encodeRstStream(gpa, &wire, sid, .cancel);
    try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
}

test "connection: repeated forced stream errors count as resets (rapid reset, server side)" {
    const gpa = testing.allocator;
    var conn = try testServerWith(.{ .max_reset_streams = 2 });
    defer conn.deinit();

    // Each round: a valid request stream, then DATA on the now half-closed
    // stream → stream-scoped STREAM_CLOSED that we recover (= we RST it).
    var sid: u31 = 1;
    for (0..2) |_| {
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try encodeHeaders(gpa, &wire, sid, &.{0x82}, .{ .end_stream = true });
        try encodeData(gpa, &wire, sid, "late", .{});
        try expectViolation(&conn, wire.items, error.StreamClosed, .stream);
        try testing.expect(conn.recoverStreamError() != null);
        sid += 2;
    }
    try testing.expectEqual(@as(u32, 2), conn.reset_streams);

    // Budget exhausted: the next recv round convicts the connection.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeHeaders(gpa, &wire, sid, &.{0x82}, .{ .end_stream = true });
    try encodeData(gpa, &wire, sid, "late", .{});
    try expectViolation(&conn, wire.items, error.StreamClosed, .stream);
    try testing.expect(conn.recoverStreamError() != null);
    try expectViolation(&conn, "", error.EnhanceYourCalm, .connection);
}

test "connection: CONTINUATION frame flood (CVE-2024-27316) → ENHANCE_YOUR_CALM" {
    const gpa = testing.allocator;
    var conn = try testServerWith(.{ .max_continuation_frames = 8 });
    defer conn.deinit();

    // Zero-length CONTINUATIONs never trip the size cap — the frame-count
    // cap has to convict. END_HEADERS is never set.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeHeaders(gpa, &wire, 1, &.{}, .{ .end_headers = false });
    for (0..9) |_| try encodeContinuation(gpa, &wire, 1, &.{}, false);
    try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
}

test "connection: CONTINUATIONs under the limit still assemble" {
    const gpa = testing.allocator;
    var conn = try testServerWith(.{ .max_continuation_frames = 8 });
    defer conn.deinit();

    // :method GET (0x82) split into one-octet nothing-burgers: HEADERS with
    // an empty fragment + 2 CONTINUATIONs — well under the limit of 8.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try encodeHeaders(gpa, &wire, 1, &.{}, .{ .end_headers = false, .end_stream = true });
    try encodeContinuation(gpa, &wire, 1, &.{}, false);
    try encodeContinuation(gpa, &wire, 1, &.{0x82}, true);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(Event) = .empty;
    defer freeEvents(&events);
    try conn.recv(wire.items, &out, &events);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqualStrings(":method", events.items[0].headers.headers.fields[0].name);
    try testing.expectEqual(@as(?Violation, null), conn.violation);
}

test "connection: header block over max_header_block → ENHANCE_YOUR_CALM" {
    const gpa = testing.allocator;
    // (a) The first fragment alone blows the cap.
    {
        var conn = try testServerWith(.{ .max_header_block = 64 });
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try encodeHeaders(gpa, &wire, 1, &(.{0} ** 65), .{ .end_headers = false });
        try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
    }
    // (b) CONTINUATION growth crosses the cap.
    {
        var conn = try testServerWith(.{ .max_header_block = 64 });
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try encodeHeaders(gpa, &wire, 1, &(.{0} ** 40), .{ .end_headers = false });
        try encodeContinuation(gpa, &wire, 1, &(.{0} ** 40), false);
        try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
    }
}

test "connection: PING flood → ENHANCE_YOUR_CALM; productive frames reset the budget" {
    const gpa = testing.allocator;
    {
        var conn = try testServerWith(.{ .max_unproductive_frames = 4 });
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        for (0..8) |_| try encodePing(gpa, &wire, .{0} ** 8, false);
        try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
    }
    // The same number of PINGs interleaved with real requests is fine —
    // each new request stream resets the budget.
    {
        var conn = try testServerWith(.{ .max_unproductive_frames = 4 });
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        var sid: u31 = 1;
        for (0..4) |_| {
            try encodePing(gpa, &wire, .{0} ** 8, false);
            try encodePing(gpa, &wire, .{0} ** 8, false);
            try encodeHeaders(gpa, &wire, sid, &.{0x82}, .{ .end_stream = true });
            sid += 2;
        }
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var events: std.ArrayList(Event) = .empty;
        defer freeEvents(&events);
        try conn.recv(wire.items, &out, &events);
        try testing.expectEqual(@as(?Violation, null), conn.violation);
        try testing.expectEqual(@as(u32, 4), conn.remote_streams_total);
    }
}

test "connection: SETTINGS and empty-DATA floods → ENHANCE_YOUR_CALM" {
    const gpa = testing.allocator;
    { // SETTINGS spam (each also costs us an ACK).
        var conn = try testServerWith(.{ .max_unproductive_frames = 4 });
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        for (0..8) |_| try encodeSettings(gpa, &wire, .{});
        try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
    }
    { // Zero-length DATA without END_STREAM on a live stream.
        var conn = try testServerWith(.{ .max_unproductive_frames = 4 });
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try encodeHeaders(gpa, &wire, 1, &.{0x82}, .{});
        for (0..8) |_| try encodeData(gpa, &wire, 1, "", .{});
        try expectViolation(&conn, wire.items, error.EnhanceYourCalm, .connection);
    }
}
