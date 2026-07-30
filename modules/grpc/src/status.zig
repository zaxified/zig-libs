// SPDX-License-Identifier: MIT

//! gRPC status codes, the `grpc-status`/`grpc-message` trailer pair, and the
//! HTTP-status fallback mapping.
//!
//! Two things live here that are easy to get subtly wrong:
//!
//!   1. **A status is a trailer, not a header.** `grpc-status` arrives in the
//!      TRAILERS frame after the messages — except in the Trailers-Only case,
//!      where the whole response is one HEADERS frame. Both spellings are the
//!      *same* field name, so a parser that looks in only one place is right
//!      half the time. `call.zig` looks in both, in the right order.
//!   2. **`grpc-message` is percent-encoded.** The header ABNF forbids the
//!      bytes a human-readable error message is most likely to contain
//!      (newlines, UTF-8), so it is transported percent-encoded and must be
//!      decoded before it is shown to anyone.

const std = @import("std");

/// The canonical gRPC status codes (0–16). Non-exhaustive on purpose: the
/// code is read off the wire, and a peer from a newer spec revision may send
/// a number this build has never heard of — that must be representable, not
/// undefined behaviour.
pub const Status = enum(u32) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,
    _,

    /// The spec's SCREAMING_SNAKE name, or "UNRECOGNIZED" for a code this
    /// build does not know.
    pub fn name(s: Status) []const u8 {
        return switch (s) {
            .ok => "OK",
            .cancelled => "CANCELLED",
            .unknown => "UNKNOWN",
            .invalid_argument => "INVALID_ARGUMENT",
            .deadline_exceeded => "DEADLINE_EXCEEDED",
            .not_found => "NOT_FOUND",
            .already_exists => "ALREADY_EXISTS",
            .permission_denied => "PERMISSION_DENIED",
            .resource_exhausted => "RESOURCE_EXHAUSTED",
            .failed_precondition => "FAILED_PRECONDITION",
            .aborted => "ABORTED",
            .out_of_range => "OUT_OF_RANGE",
            .unimplemented => "UNIMPLEMENTED",
            .internal => "INTERNAL",
            .unavailable => "UNAVAILABLE",
            .data_loss => "DATA_LOSS",
            .unauthenticated => "UNAUTHENTICATED",
            _ => "UNRECOGNIZED",
        };
    }
};

/// One Zig error per non-OK status, so a failed RPC is an ordinary `try`
/// failure whose *code* survives in the type system rather than being
/// flattened into a single `error.RpcFailed`. The human-readable
/// `grpc-message` cannot ride in a Zig error value, so it stays on the call
/// (`Call.statusMessage`) / in a caller-supplied `Failure`.
pub const StatusError = error{
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
};

/// The error for a non-OK status. `.ok` has no error and is a caller bug —
/// asserted rather than silently turned into `Unknown`. A code outside 0–16
/// maps to `Unknown`, matching what other implementations do with a status
/// they cannot name.
pub fn toError(s: Status) StatusError {
    return switch (s) {
        .ok => unreachable,
        .cancelled => error.Cancelled,
        .unknown => error.Unknown,
        .invalid_argument => error.InvalidArgument,
        .deadline_exceeded => error.DeadlineExceeded,
        .not_found => error.NotFound,
        .already_exists => error.AlreadyExists,
        .permission_denied => error.PermissionDenied,
        .resource_exhausted => error.ResourceExhausted,
        .failed_precondition => error.FailedPrecondition,
        .aborted => error.Aborted,
        .out_of_range => error.OutOfRange,
        .unimplemented => error.Unimplemented,
        .internal => error.Internal,
        .unavailable => error.Unavailable,
        .data_loss => error.DataLoss,
        .unauthenticated => error.Unauthenticated,
        _ => error.Unknown,
    };
}

/// Inverse of `toError` — the status a `StatusError` stands for.
pub fn fromError(e: StatusError) Status {
    return switch (e) {
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
    };
}

/// Parse a `grpc-status` field value: an unsigned decimal integer, nothing
/// else. Leading `+`, whitespace, a sign or any trailing junk is a malformed
/// status, not a zero — returning `.ok` for garbage would turn a broken peer
/// into a silently successful call, which is the single worst failure this
/// module could have.
pub fn parse(value: []const u8) ?Status {
    if (value.len == 0) return null;
    for (value) |c| {
        if (c < '0' or c > '9') return null;
    }
    const n = std.fmt.parseInt(u32, value, 10) catch return null;
    return @enumFromInt(n);
}

/// The status a **non-200** HTTP response maps to, per the gRPC-over-HTTP2
/// spec's table. Reached when the server (or an intermediary that has never
/// heard of gRPC) answers with an HTTP-level failure and therefore has no
/// `grpc-status` to offer.
pub fn fromHttpStatus(http_status: u16) Status {
    return switch (http_status) {
        400 => .internal,
        401 => .unauthenticated,
        403 => .permission_denied,
        404 => .unimplemented,
        429, 502, 503, 504 => .unavailable,
        else => .unknown,
    };
}

// ── grpc-message percent-coding ─────────────────────────────────────────────
//
// Percent-Encoded → 1*(Percent-Byte-Unencoded / Percent-Byte-Encoded)
// Percent-Byte-Unencoded → %x20-24 / %x26-7E   (printable ASCII minus '%')
// Percent-Byte-Encoded   → "%" 2HEXDIGIT

fn unencoded(c: u8) bool {
    return (c >= 0x20 and c <= 0x24) or (c >= 0x26 and c <= 0x7e);
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Decode a percent-encoded `grpc-message` into `out`, returning the used
/// prefix. `out.len >= value.len` always suffices (decoding only shrinks).
///
/// A `%` that is not followed by two hex digits is **passed through
/// verbatim**, as the spec directs: the field carries a human-readable
/// message that may legitimately contain a stray percent sign, and a peer
/// that under-encodes must not cost us the rest of the string.
pub fn decodeMessage(value: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= value.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < value.len) {
        if (value[i] == '%' and i + 2 < value.len) {
            if (hexVal(value[i + 1])) |hi| {
                if (hexVal(value[i + 2])) |lo| {
                    out[n] = (hi << 4) | lo;
                    n += 1;
                    i += 3;
                    continue;
                }
            }
        }
        out[n] = value[i];
        n += 1;
        i += 1;
    }
    return out[0..n];
}

/// Allocating form of `decodeMessage`.
pub fn decodeMessageAlloc(gpa: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    const buf = try gpa.alloc(u8, value.len);
    errdefer gpa.free(buf);
    const used = decodeMessage(value, buf);
    return gpa.realloc(buf, used.len) catch buf[0..used.len];
}

/// Encoded length of `message` — what `encodeMessage` will write.
pub fn encodedMessageLen(message: []const u8) usize {
    var n: usize = 0;
    for (message) |c| n += if (unencoded(c)) 1 else 3;
    return n;
}

/// Percent-encode `message` into `out` (`out.len >= encodedMessageLen`).
/// Present for symmetry and for tests that must produce a wire value; the
/// client itself never sends `grpc-message`.
pub fn encodeMessage(message: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedMessageLen(message));
    const hex = "0123456789ABCDEF";
    var n: usize = 0;
    for (message) |c| {
        if (unencoded(c)) {
            out[n] = c;
            n += 1;
        } else {
            out[n] = '%';
            out[n + 1] = hex[c >> 4];
            out[n + 2] = hex[c & 0xf];
            n += 3;
        }
    }
    return out[0..n];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "status: codes, names and the error mapping round trip" {
    try testing.expectEqual(@as(u32, 0), @intFromEnum(Status.ok));
    try testing.expectEqual(@as(u32, 16), @intFromEnum(Status.unauthenticated));
    try testing.expectEqualStrings("RESOURCE_EXHAUSTED", Status.resource_exhausted.name());

    inline for (@typeInfo(Status).@"enum".fields) |f| {
        const s: Status = @enumFromInt(f.value);
        if (s == .ok) continue;
        try testing.expectEqual(s, fromError(toError(s)));
    }
}

test "status: an unrecognized code is representable and reads as UNKNOWN" {
    const s: Status = @enumFromInt(99);
    try testing.expectEqualStrings("UNRECOGNIZED", s.name());
    try testing.expectEqual(error.Unknown, toError(s));
}

test "status: parsing rejects everything that is not a bare decimal" {
    try testing.expectEqual(Status.ok, parse("0").?);
    try testing.expectEqual(Status.unimplemented, parse("12").?);
    try testing.expectEqual(@as(?Status, null), parse(""));
    try testing.expectEqual(@as(?Status, null), parse(" 0"));
    try testing.expectEqual(@as(?Status, null), parse("0 "));
    try testing.expectEqual(@as(?Status, null), parse("+0"));
    try testing.expectEqual(@as(?Status, null), parse("-1"));
    try testing.expectEqual(@as(?Status, null), parse("0x0"));
    try testing.expectEqual(@as(?Status, null), parse("ok"));
    try testing.expectEqual(@as(?Status, null), parse("99999999999999999999"));
}

test "status: http fallback mapping" {
    try testing.expectEqual(Status.internal, fromHttpStatus(400));
    try testing.expectEqual(Status.unauthenticated, fromHttpStatus(401));
    try testing.expectEqual(Status.permission_denied, fromHttpStatus(403));
    try testing.expectEqual(Status.unimplemented, fromHttpStatus(404));
    try testing.expectEqual(Status.unavailable, fromHttpStatus(503));
    try testing.expectEqual(Status.unknown, fromHttpStatus(418));
}

test "grpc-message: percent round trip, including bytes the ABNF forbids" {
    const cases = [_][]const u8{
        "",
        "plain message",
        "100% sure",
        "line\nbreak\ttab",
        "non-ascii \xe2\x98\x83 snowman",
        "\x00\x01\x7f",
    };
    var enc_buf: [256]u8 = undefined;
    var dec_buf: [256]u8 = undefined;
    for (cases) |c| {
        const enc = encodeMessage(c, &enc_buf);
        for (enc) |b| try testing.expect(unencoded(b) or b == '%');
        try testing.expectEqualStrings(c, decodeMessage(enc, &dec_buf));
    }
}

test "grpc-message: a malformed escape survives verbatim" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("100% sure", decodeMessage("100% sure", &buf));
    try testing.expectEqualStrings("trailing %", decodeMessage("trailing %", &buf));
    try testing.expectEqualStrings("%zz here", decodeMessage("%zz here", &buf));
    // …but a well-formed one is still decoded next to it.
    try testing.expectEqualStrings("% and \n", decodeMessage("% and %0A", &buf));
}
