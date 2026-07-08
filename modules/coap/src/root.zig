// SPDX-License-Identifier: MIT

//! coap — CoAP (RFC 7252) message codec: the binary wire format for the
//! Constrained Application Protocol, the REST-over-UDP protocol of
//! constrained/IoT devices. This is the message layer (C1): parse and
//! serialize a CoAP message — header, token, delta-encoded options and
//! payload. The typed option registry (Uri-Path/Content-Format/…), the
//! CON/ACK reliability layer, and the client/server sit on top (later parts).
//!
//! Zero-allocation and transport-agnostic: `parse` fills a caller-provided
//! option array from a datagram; `serialize` writes a message into a caller
//! buffer. Wire it to any UDP/DTLS transport.
//!
//! ## Message format (RFC 7252 §3)
//!
//! ```
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver| T |  TKL  |      Code     |          Message ID           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Token (0..8 bytes) ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Options (delta-encoded TLV) ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |1 1 1 1 1 1 1 1|   Payload (if any) ...   (0xFF marker, then bytes)
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Ver = 1. T = message type. TKL = token length (0..8; 9..15 is a format
//! error). Code = 3-bit class · 5-bit detail (e.g. 0.01 GET, 2.05 Content,
//! 4.04 Not Found). Message ID is big-endian.

const std = @import("std");

pub const meta = .{
    .status = .gap,
    .platform = .any, // pure codec over a caller-provided datagram
    .role = .util,
    .concurrency = .reentrant, // no shared state; slices borrow the caller's buffers
    .model_after = "RFC 7252 (CoAP) message format §3 — delta-encoded options",
    .deps = .{},
};

/// The typed option layer (C2): the RFC 7252 §5.10 option registry + class
/// bits, the CoAP uint value format, typed accessors (Content-Format / Accept /
/// Max-Age / Uri-Path / Uri-Query), and the §6 URI ↔ options mapping.
pub const options = @import("options.zig");

/// The message/reliability layer (C3): Confirmable retransmission with
/// exponential backoff (§4.2), message-ID deduplication (§4.5), and the
/// empty-ACK / Reset helpers — transport- and clock-agnostic.
pub const reliability = @import("reliability.zig");

/// CoAP version in the 2-bit Ver field (always 1 for RFC 7252).
pub const version = 1;

/// Maximum token length (TKL 0..8; 9..15 are reserved → format error).
pub const max_token_len = 8;

/// Message type (the 2-bit T field, RFC 7252 §3).
pub const Type = enum(u2) {
    /// Confirmable — retransmitted until ACKed.
    confirmable = 0,
    /// Non-confirmable — fire-and-forget.
    non_confirmable = 1,
    /// Acknowledgement of a Confirmable message.
    ack = 2,
    /// Reset — the recipient could not process the message (or is not
    /// interested, for a NON).
    reset = 3,
};

/// Request/response code: 3-bit class (`c`) · 5-bit detail (`dd`), written as
/// `c.dd`. Non-exhaustive — only the common codes are named; build any other
/// with `init`. `0.00` is the Empty message.
pub const Code = enum(u8) {
    empty = 0,

    // 0.xx — request methods (RFC 7252 §12.1.1).
    get = (0 << 5) | 1,
    post = (0 << 5) | 2,
    put = (0 << 5) | 3,
    delete = (0 << 5) | 4,

    // 2.xx — success (RFC 7252 §12.1.2).
    created = (2 << 5) | 1,
    deleted = (2 << 5) | 2,
    valid = (2 << 5) | 3,
    changed = (2 << 5) | 4,
    content = (2 << 5) | 5,

    // 4.xx — client error.
    bad_request = (4 << 5) | 0,
    unauthorized = (4 << 5) | 1,
    bad_option = (4 << 5) | 2,
    forbidden = (4 << 5) | 3,
    not_found = (4 << 5) | 4,
    method_not_allowed = (4 << 5) | 5,
    not_acceptable = (4 << 5) | 6,
    request_entity_too_large = (4 << 5) | 13,
    unsupported_content_format = (4 << 5) | 15,

    // 5.xx — server error.
    internal_server_error = (5 << 5) | 0,
    not_implemented = (5 << 5) | 1,
    bad_gateway = (5 << 5) | 2,
    service_unavailable = (5 << 5) | 3,
    gateway_timeout = (5 << 5) | 4,
    proxying_not_supported = (5 << 5) | 5,

    _,

    /// The 3-bit class (0, 2, 4, 5).
    pub fn class(c: Code) u3 {
        return @intCast(@intFromEnum(c) >> 5);
    }

    /// The 5-bit detail (0..31).
    pub fn detail(c: Code) u5 {
        return @intCast(@intFromEnum(c) & 0x1f);
    }

    /// Build a code from class + detail (e.g. `Code.init(2, 5)` == `.content`).
    pub fn init(cls: u3, det: u5) Code {
        return @enumFromInt((@as(u8, cls) << 5) | det);
    }

    /// A request code (class 0, and not the Empty message).
    pub fn isRequest(c: Code) bool {
        return c.class() == 0 and c != .empty;
    }
};

/// One CoAP option as a number + raw value. The value borrows the source
/// datagram (on `parse`) or the caller's memory (on `serialize`). The typed
/// meaning of `number` (Uri-Path = 11, Content-Format = 12, …) is the next
/// part's registry; the codec is value-agnostic.
pub const Option = struct {
    number: u16,
    value: []const u8,
};

/// A decoded CoAP message. All slices borrow the parsed datagram (for `parse`)
/// — copy anything you keep past the buffer's life.
pub const Message = struct {
    type: Type,
    code: Code,
    message_id: u16,
    /// 0..8 bytes.
    token: []const u8 = &.{},
    /// Options in ascending `number` order (guaranteed by `parse`; **required**
    /// by `serialize` — the delta encoding cannot represent an out-of-order
    /// option). Repeated numbers are allowed and kept in order.
    options: []const Option = &.{},
    /// Empty when the message carries no payload.
    payload: []const u8 = &.{},
};

pub const ParseError = error{
    /// Fewer than the 4 header bytes.
    TooShort,
    /// Version field is not 1.
    BadVersion,
    /// Token length 9..15 (reserved).
    BadTokenLength,
    /// A malformed option (reserved nibble 15, or a truncated header/value).
    BadOption,
    /// More options than `options_buf` can hold.
    TooManyOptions,
    /// A 0xFF payload marker with no payload bytes after it (RFC 7252 §3).
    EmptyPayload,
    /// The datagram ended mid-field.
    Truncated,
};

pub const SerializeError = error{
    /// `out` is smaller than the encoded message.
    BufferTooSmall,
    /// `token` longer than 8 bytes.
    BadTokenLength,
    /// `options` are not in ascending `number` order.
    OptionsNotSorted,
};

/// Parse a CoAP datagram. Options are written into `options_buf` (borrowing
/// their values from `bytes`); the returned `Message.options` is the filled
/// prefix. No allocation; everything borrows `bytes`.
pub fn parse(bytes: []const u8, options_buf: []Option) ParseError!Message {
    if (bytes.len < 4) return error.TooShort;
    const b0 = bytes[0];
    if (b0 >> 6 != version) return error.BadVersion;
    const typ: Type = @enumFromInt(@as(u2, @truncate(b0 >> 4)));
    const tkl: u4 = @truncate(b0);
    if (tkl > max_token_len) return error.BadTokenLength;
    const code: Code = @enumFromInt(bytes[1]);
    const message_id = std.mem.readInt(u16, bytes[2..4], .big);

    var pos: usize = 4;
    if (bytes.len < pos + tkl) return error.Truncated;
    const token = bytes[pos .. pos + tkl];
    pos += tkl;

    var n_opts: usize = 0;
    var number: u32 = 0;
    var payload: []const u8 = &.{};
    while (pos < bytes.len) {
        const b = bytes[pos];
        pos += 1;
        if (b == 0xff) {
            if (pos == bytes.len) return error.EmptyPayload;
            payload = bytes[pos..];
            break;
        }
        const delta = try decodeExtended(@truncate(b >> 4), bytes, &pos);
        const len = try decodeExtended(@truncate(b), bytes, &pos);
        number += delta;
        if (number > std.math.maxInt(u16)) return error.BadOption;
        if (bytes.len - pos < len) return error.Truncated;
        if (n_opts == options_buf.len) return error.TooManyOptions;
        options_buf[n_opts] = .{ .number = @intCast(number), .value = bytes[pos .. pos + len] };
        n_opts += 1;
        pos += len;
    }

    return .{
        .type = typ,
        .code = code,
        .message_id = message_id,
        .token = token,
        .options = options_buf[0..n_opts],
        .payload = payload,
    };
}

/// Resolve one option nibble (delta or length) to its value, consuming any
/// extended bytes at `pos` (RFC 7252 §3.1): 0..12 → the nibble; 13 → 1 ext
/// byte + 13; 14 → 2 ext bytes (big-endian) + 269; 15 → reserved.
fn decodeExtended(nibble: u4, bytes: []const u8, pos: *usize) ParseError!u32 {
    switch (nibble) {
        0...12 => return nibble,
        13 => {
            if (pos.* >= bytes.len) return error.Truncated;
            const ext = bytes[pos.*];
            pos.* += 1;
            return @as(u32, ext) + 13;
        },
        14 => {
            if (bytes.len - pos.* < 2) return error.Truncated;
            const ext = std.mem.readInt(u16, bytes[pos.*..][0..2], .big);
            pos.* += 2;
            return @as(u32, ext) + 269;
        },
        15 => return error.BadOption,
    }
}

/// Number of extended bytes the nibble encoding of `value` needs:
/// 0 for ≤ 12, 1 for 13..268, 2 otherwise. Shared by parse/serialize/
/// encodedLen so the three always agree.
fn extBytesFor(value: usize) usize {
    if (value <= 12) return 0;
    if (value <= 268) return 1;
    return 2;
}

/// The nibble for `value` under the extension rule (0..12, 13, or 14).
fn nibbleFor(value: u32) u4 {
    if (value <= 12) return @intCast(value);
    if (value <= 268) return 13;
    return 14;
}

/// Write the extended bytes for `value` (none, 1, or 2 big-endian) at `pos`.
fn writeExtended(value: u32, out: []u8, pos: *usize) SerializeError!void {
    switch (extBytesFor(value)) {
        0 => {},
        1 => {
            if (pos.* >= out.len) return error.BufferTooSmall;
            out[pos.*] = @intCast(value - 13);
            pos.* += 1;
        },
        else => {
            if (out.len - pos.* < 2) return error.BufferTooSmall;
            std.mem.writeInt(u16, out[pos.*..][0..2], @intCast(value - 269), .big);
            pos.* += 2;
        },
    }
}

/// Serialize `msg` into `out`; returns the number of bytes written. `out`
/// should be at least `encodedLen(msg)` bytes. Options must be sorted ascending
/// by `number`.
pub fn serialize(msg: Message, out: []u8) SerializeError!usize {
    if (msg.token.len > max_token_len) return error.BadTokenLength;
    if (out.len < 4 + msg.token.len) return error.BufferTooSmall;
    out[0] = (@as(u8, version) << 6) |
        (@as(u8, @intFromEnum(msg.type)) << 4) |
        @as(u8, @intCast(msg.token.len));
    out[1] = @intFromEnum(msg.code);
    std.mem.writeInt(u16, out[2..4], msg.message_id, .big);
    var pos: usize = 4;
    @memcpy(out[pos..][0..msg.token.len], msg.token);
    pos += msg.token.len;

    var last_number: u16 = 0;
    for (msg.options) |opt| {
        if (opt.number < last_number) return error.OptionsNotSorted;
        const delta: u32 = opt.number - last_number;
        last_number = opt.number;
        const len: u32 = @intCast(opt.value.len);
        if (pos >= out.len) return error.BufferTooSmall;
        out[pos] = (@as(u8, nibbleFor(delta)) << 4) | nibbleFor(len);
        pos += 1;
        try writeExtended(delta, out, &pos);
        try writeExtended(len, out, &pos);
        if (out.len - pos < opt.value.len) return error.BufferTooSmall;
        @memcpy(out[pos..][0..opt.value.len], opt.value);
        pos += opt.value.len;
    }

    if (msg.payload.len != 0) {
        if (out.len - pos < 1 + msg.payload.len) return error.BufferTooSmall;
        out[pos] = 0xff;
        pos += 1;
        @memcpy(out[pos..][0..msg.payload.len], msg.payload);
        pos += msg.payload.len;
    }
    return pos;
}

/// The exact serialized length of `msg` in bytes (header + token + options +
/// optional payload marker + payload). Handy for sizing the `serialize` buffer.
pub fn encodedLen(msg: Message) usize {
    var total: usize = 4 + msg.token.len;
    var last_number: u16 = 0;
    for (msg.options) |opt| {
        const delta = opt.number -| last_number;
        last_number = opt.number;
        total += 1 + extBytesFor(delta) + extBytesFor(opt.value.len) + opt.value.len;
    }
    if (msg.payload.len != 0) total += 1 + msg.payload.len;
    return total;
}

// ── tests ──

const testing = std.testing;

fn expectMessageEqual(expected: Message, actual: Message) !void {
    try testing.expectEqual(expected.type, actual.type);
    try testing.expectEqual(expected.code, actual.code);
    try testing.expectEqual(expected.message_id, actual.message_id);
    try testing.expectEqualSlices(u8, expected.token, actual.token);
    try testing.expectEqual(expected.options.len, actual.options.len);
    for (expected.options, actual.options) |e, a| {
        try testing.expectEqual(e.number, a.number);
        try testing.expectEqualSlices(u8, e.value, a.value);
    }
    try testing.expectEqualSlices(u8, expected.payload, actual.payload);
}

/// serialize → parse → compare with the original; also checks encodedLen.
fn expectRoundTrip(msg: Message) !void {
    var out: [512]u8 = undefined;
    const n = try serialize(msg, &out);
    try testing.expectEqual(encodedLen(msg), n);
    var opts: [16]Option = undefined;
    const back = try parse(out[0..n], &opts);
    try expectMessageEqual(msg, back);
}

test "hand-built datagram: CON GET, token, repeated Uri-Path, no payload" {
    // Ver=1 T=CON TKL=2 | GET | mid 0x3039 | token | 11:"temp" | delta 0:"temp"
    const wire = [_]u8{
        0x42, 0x01, 0x30, 0x39, // header
        0xab, 0xcd, // token
        0xb4, 't', 'e', 'm', 'p', // option 11, len 4
        0x04, 't', 'e', 'm', 'p', // option 11 again (delta 0)
    };
    var opts: [4]Option = undefined;
    const msg = try parse(&wire, &opts);
    try testing.expectEqual(Type.confirmable, msg.type);
    try testing.expectEqual(Code.get, msg.code);
    try testing.expectEqual(@as(u16, 0x3039), msg.message_id);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, msg.token);
    try testing.expectEqual(@as(usize, 2), msg.options.len);
    try testing.expectEqual(@as(u16, 11), msg.options[0].number);
    try testing.expectEqualSlices(u8, "temp", msg.options[0].value);
    try testing.expectEqual(@as(u16, 11), msg.options[1].number);
    try testing.expectEqualSlices(u8, "temp", msg.options[1].value);
    try testing.expectEqual(@as(usize, 0), msg.payload.len);

    // Serializing the parsed message reproduces the exact wire bytes.
    var out: [64]u8 = undefined;
    const n = try serialize(msg, &out);
    try testing.expectEqualSlices(u8, &wire, out[0..n]);
    try testing.expectEqual(wire.len, encodedLen(msg));
}

test "extended nibble forms round-trip across the 13 and 269 boundaries" {
    const long20 = "abcdefghijklmnopqrst"; // length 20 → length nibble 13
    const long300 = "x" ** 300; // length 300 → length nibble 14
    try expectRoundTrip(.{
        .type = .non_confirmable,
        .code = .content,
        .message_id = 7,
        .options = &.{
            .{ .number = 12, .value = "a" }, // delta 12 → plain nibble
            .{ .number = 25, .value = long20 }, // delta 13 → nibble 13, ext 0
            .{ .number = 293, .value = "b" }, // delta 268 → nibble 13, ext 255
            .{ .number = 562, .value = long300 }, // delta 269 → nibble 14, ext 0
        },
    });
    // Option number 300 straight from zero → delta nibble 14.
    const one = [_]Option{.{ .number = 300, .value = "v" }};
    const msg: Message = .{ .type = .ack, .code = .changed, .message_id = 1, .options = &one };
    var out: [16]u8 = undefined;
    const n = try serialize(msg, &out);
    try testing.expectEqual(@as(u8, 0xe1), out[4]); // delta nibble 14, len 1
    try testing.expectEqual(@as(u8, 0x00), out[5]); // ext = 300 - 269 = 31
    try testing.expectEqual(@as(u8, 0x1f), out[6]);
    try testing.expectEqual(encodedLen(msg), n);
    try expectRoundTrip(msg);
}

test "payload: marker parses, serialize re-emits it, lone 0xFF errors" {
    const wire = [_]u8{ 0x40, 0x45, 0x00, 0x01, 0xff, 'h', 'i' };
    var opts: [1]Option = undefined;
    const msg = try parse(&wire, &opts);
    try testing.expectEqualSlices(u8, "hi", msg.payload);

    var out: [16]u8 = undefined;
    const n = try serialize(msg, &out);
    try testing.expectEqualSlices(u8, &wire, out[0..n]);

    try expectRoundTrip(.{
        .type = .confirmable,
        .code = .post,
        .message_id = 0xffff,
        .token = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .options = &.{.{ .number = 11, .value = "p" }},
        .payload = "body",
    });

    const lone_marker = [_]u8{ 0x40, 0x45, 0x00, 0x01, 0xff };
    try testing.expectError(error.EmptyPayload, parse(&lone_marker, &opts));
}

test "parse errors" {
    var opts: [1]Option = undefined;
    // 3-byte buffer.
    try testing.expectError(error.TooShort, parse(&.{ 0x40, 0x01, 0x00 }, &opts));
    // Ver = 0.
    try testing.expectError(error.BadVersion, parse(&.{ 0x00, 0x01, 0x00, 0x01 }, &opts));
    // TKL = 9.
    try testing.expectError(error.BadTokenLength, parse(&.{ 0x49, 0x01, 0x00, 0x01 }, &opts));
    // Token shorter than TKL.
    try testing.expectError(error.Truncated, parse(&.{ 0x42, 0x01, 0x00, 0x01, 0xab }, &opts));
    // Option value shorter than its length nibble.
    try testing.expectError(error.Truncated, parse(&.{ 0x40, 0x01, 0x00, 0x01, 0x03, 'a' }, &opts));
    // Truncated 1-byte delta extension.
    try testing.expectError(error.Truncated, parse(&.{ 0x40, 0x01, 0x00, 0x01, 0xd0 }, &opts));
    // Truncated 2-byte length extension.
    try testing.expectError(error.Truncated, parse(&.{ 0x40, 0x01, 0x00, 0x01, 0x0e, 0x01 }, &opts));
    // Reserved delta nibble 15 (byte != 0xFF, so not the payload marker).
    try testing.expectError(error.BadOption, parse(&.{ 0x40, 0x01, 0x00, 0x01, 0xf0 }, &opts));
    // Reserved length nibble 15.
    try testing.expectError(error.BadOption, parse(&.{ 0x40, 0x01, 0x00, 0x01, 0x0f }, &opts));
    // More options than options_buf holds.
    try testing.expectError(error.TooManyOptions, parse(&.{ 0x40, 0x01, 0x00, 0x01, 0x10, 0x10 }, &opts));
}

test "serialize errors" {
    var out: [64]u8 = undefined;
    // Unsorted options.
    const unsorted = [_]Option{
        .{ .number = 11, .value = "a" },
        .{ .number = 4, .value = "b" },
    };
    try testing.expectError(error.OptionsNotSorted, serialize(.{
        .type = .confirmable,
        .code = .get,
        .message_id = 1,
        .options = &unsorted,
    }, &out));
    // Token longer than 8 bytes.
    try testing.expectError(error.BadTokenLength, serialize(.{
        .type = .confirmable,
        .code = .get,
        .message_id = 1,
        .token = &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 },
    }, &out));
    // Output buffers too small for the header, an option, and a payload.
    const msg: Message = .{
        .type = .confirmable,
        .code = .get,
        .message_id = 1,
        .options = &.{.{ .number = 11, .value = "abc" }},
        .payload = "body",
    };
    try testing.expectError(error.BufferTooSmall, serialize(msg, out[0..2]));
    try testing.expectError(error.BufferTooSmall, serialize(msg, out[0..6]));
    try testing.expectError(error.BufferTooSmall, serialize(msg, out[0..10]));
    // Exactly encodedLen bytes succeeds.
    try testing.expectEqual(encodedLen(msg), try serialize(msg, out[0..encodedLen(msg)]));
}

test "encodedLen matches serialize across shapes" {
    const shapes = [_]Message{
        .{ .type = .reset, .code = .empty, .message_id = 0 },
        .{ .type = .ack, .code = .not_found, .message_id = 2, .token = &.{0x01} },
        .{
            .type = .confirmable,
            .code = .put,
            .message_id = 3,
            .options = &.{
                .{ .number = 1, .value = "" },
                .{ .number = 270, .value = "y" ** 269 },
            },
            .payload = "z",
        },
    };
    var out: [512]u8 = undefined;
    for (shapes) |msg| {
        try testing.expectEqual(encodedLen(msg), try serialize(msg, &out));
        try expectRoundTrip(msg);
    }
}

test "Code helpers" {
    try testing.expectEqual(@as(u3, 2), Code.content.class());
    try testing.expectEqual(@as(u5, 5), Code.content.detail());
    try testing.expectEqual(Code.not_found, Code.init(4, 4));
    try testing.expect(Code.get.isRequest());
    try testing.expect(!Code.content.isRequest());
    try testing.expect(!Code.empty.isRequest());
}
