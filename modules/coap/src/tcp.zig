// SPDX-License-Identifier: MIT

//! coap over reliable transports (RFC 8323): the TCP / TLS / WebSocket-less
//! message framing of §3 and the signaling messages of §5 (CSM, Ping/Pong,
//! Release, Abort). The TLS seam is the caller's, as everywhere in this module:
//! hand this code the plaintext byte stream of an already-secured connection.
//!
//! A message on a stream has no Version, Type or Message ID (the transport
//! gives reliability and ordering); its header is
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |  Len  |  TKL  |   Len 0..12: the number of octets after the token
//! +-+-+-+-+-+-+-+-+   (options, payload marker, payload); 13: one extension
//! | Extended Length|  octet (+13); 14: two octets (+269); 15: four octets
//! +-+-+-+-+-+-+-+-+  (+65805). Then Code, Token (TKL octets, 0..8), Options
//! |      Code      |  and Payload exactly as in RFC 7252 §3.1.
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! `decode` reads one message from the front of a byte stream and says how many
//! octets it used, or that more are needed; `frameLen` answers the latter
//! without parsing so a socket adapter can read exactly one frame.
//!
//! `Session` is the connection state machine of §5: each side sends a CSM
//! first, nothing else is accepted before the peer's CSM, Ping is answered with
//! a Pong echoing the token, Release and Abort end the use of the connection.
//! It decides; the caller does the I/O and builds the answers with
//! `pongFor`, `encodeAbort` and `Csm.message`.

const std = @import("std");
const coap = @import("root.zig");

/// A message of the reliable-transport framing: no Type, no Message ID.
pub const Message = struct {
    code: coap.Code,
    /// 0..8 octets.
    token: []const u8 = &.{},
    /// Ascending by number, as for the datagram codec.
    options: []const coap.Option = &.{},
    payload: []const u8 = &.{},
};

pub const DecodeError = error{
    /// More octets are needed; nothing was consumed.
    Incomplete,
    /// TKL 9..15 (reserved; RFC 8974's extended token length is not used here).
    BadTokenLength,
    /// The announced length does not fit this implementation's limit.
    TooLarge,
} || coap.ParseError;

pub const EncodeError = coap.SerializeError;

/// The largest message (octets after the token) `decode`/`frameLen` accept by
/// default: the 4-octet length form could announce 4 GiB, and a stream
/// decoder must not wait for what it cannot buffer. Pass a limit to override.
pub const default_max_body: usize = 1 << 20;

const ext_1: usize = 13;
const ext_2: usize = 269;
const ext_4: usize = 65805;

fn lenNibble(body: usize) u4 {
    if (body < ext_1) return @intCast(body);
    if (body < ext_2) return 13;
    if (body < ext_4) return 14;
    return 15;
}

fn extBytes(nibble: u4) usize {
    return switch (nibble) {
        13 => 1,
        14 => 2,
        15 => 4,
        else => 0,
    };
}

/// Octets of the fixed part in front of the options for `body` octets of
/// options and payload: Len/TKL, extended length, Code, token.
fn headerLen(body: usize, token_len: usize) usize {
    return 1 + extBytes(lenNibble(body)) + 1 + token_len;
}

/// The serialized length of `msg`.
pub fn encodedLen(msg: Message) usize {
    const body = coap.bodyLen(msg.options, msg.payload);
    return headerLen(body, msg.token.len) + body;
}

/// Serializes `msg` into `out`; returns the number of octets written.
pub fn serialize(msg: Message, out: []u8) EncodeError!usize {
    if (msg.token.len > coap.max_token_len) return error.BadTokenLength;
    const body = coap.bodyLen(msg.options, msg.payload);
    // A body needing the 4-octet form must fit its 32 bits.
    if (body - @min(body, ext_4) > std.math.maxInt(u32)) return error.BufferTooSmall;
    const total = headerLen(body, msg.token.len) + body;
    if (out.len < total) return error.BufferTooSmall;
    const nib = lenNibble(body);
    out[0] = (@as(u8, nib) << 4) | @as(u8, @intCast(msg.token.len));
    var pos: usize = 1;
    switch (nib) {
        13 => out[pos] = @intCast(body - ext_1),
        14 => std.mem.writeInt(u16, out[pos..][0..2], @intCast(body - ext_2), .big),
        15 => std.mem.writeInt(u32, out[pos..][0..4], @intCast(body - ext_4), .big),
        else => {},
    }
    pos += extBytes(nib);
    out[pos] = @backingInt(msg.code);
    pos += 1;
    @memcpy(out[pos..][0..msg.token.len], msg.token);
    pos += msg.token.len;
    const end = try coap.serializeBody(msg.options, msg.payload, out, pos);
    std.debug.assert(end == total);
    return end;
}

/// The total length of the frame at the front of `bytes`: the header and the
/// announced body. `error.Incomplete` while the length field itself is not
/// complete; `error.TooLarge` when the body exceeds `max_body`; a reserved TKL
/// is `error.BadTokenLength` (the stream cannot be resynchronised after it).
pub fn frameLen(bytes: []const u8, max_body: usize) DecodeError!usize {
    if (bytes.len < 1) return error.Incomplete;
    const nib: u4 = @truncate(bytes[0] >> 4);
    const tkl: usize = bytes[0] & 0x0F;
    if (tkl > coap.max_token_len) return error.BadTokenLength;
    const ext = extBytes(nib);
    if (bytes.len < 1 + ext) return error.Incomplete;
    const body: usize = switch (nib) {
        13 => @as(usize, bytes[1]) + ext_1,
        14 => @as(usize, std.mem.readInt(u16, bytes[1..][0..2], .big)) + ext_2,
        15 => @as(usize, std.mem.readInt(u32, bytes[1..][0..4], .big)) + ext_4,
        else => nib,
    };
    if (body > max_body) return error.TooLarge;
    return 1 + ext + 1 + tkl + body;
}

/// One decoded message and the number of octets it occupied.
pub const Decoded = struct { message: Message, len: usize };

/// Decodes the message at the front of `bytes`; options are written into
/// `options_buf` and everything borrows `bytes`. `error.Incomplete` leaves the
/// caller to read more and call again; any other error means the stream is
/// broken (a frame boundary is lost) and the connection should be aborted.
pub fn decode(bytes: []const u8, options_buf: []coap.Option, max_body: usize) DecodeError!Decoded {
    const total = try frameLen(bytes, max_body);
    if (bytes.len < total) return error.Incomplete;
    const nib: u4 = @truncate(bytes[0] >> 4);
    const tkl: usize = bytes[0] & 0x0F;
    const pos = 1 + extBytes(nib);
    const msg_code: coap.Code = @fromBackingInt(@intCast(bytes[pos]));
    const token = bytes[pos + 1 ..][0..tkl];
    const body = try coap.parseBody(bytes[pos + 1 + tkl .. total], options_buf);
    return .{
        .message = .{ .code = msg_code, .token = token, .options = body.options, .payload = body.payload },
        .len = total,
    };
}

// ── signaling (RFC 8323 §5) ────────────────────────────────────────────────

/// Signaling codes (class 7, RFC 8323 §5).
pub const code = struct {
    pub const csm: coap.Code = @fromBackingInt((7 << 5) | 1);
    pub const ping: coap.Code = @fromBackingInt((7 << 5) | 2);
    pub const pong: coap.Code = @fromBackingInt((7 << 5) | 3);
    pub const release: coap.Code = @fromBackingInt((7 << 5) | 4);
    pub const abort: coap.Code = @fromBackingInt((7 << 5) | 5);
};

/// Signaling option numbers. Their numbering is per signaling code (§5.2), and
/// they follow the odd = critical rule of RFC 7252 §5.4.6.
pub const option = struct {
    // CSM
    pub const max_message_size: u16 = 2;
    pub const block_wise_transfer: u16 = 4;
    /// RFC 8974 §3: the peer accepts extended token lengths.
    pub const extended_token_length: u16 = 6;
    // Ping / Pong
    pub const custody: u16 = 2;
    // Release
    pub const alternative_address: u16 = 2;
    pub const hold_off: u16 = 4;
    // Abort
    pub const bad_csm_option: u16 = 2;
};

/// The Max-Message-Size a peer is assumed to have until its CSM says otherwise
/// (RFC 8323 §5.3.1; also the datagram default 1152).
pub const default_max_message_size: u32 = 1152;

/// A capabilities-and-settings message (RFC 8323 §5.3).
pub const Csm = struct {
    /// Largest message the sender will accept (the whole frame, §5.3.1). Sent
    /// only when it differs from the default.
    max_message_size: u32 = default_max_message_size,
    /// The sender supports block-wise transfer (§5.3.2). Messages longer than
    /// the peer's maximum can only be sent block-wise.
    block_wise: bool = false,
    /// RFC 8974: the sender accepts extended token lengths.
    extended_token_length: bool = false,

    pub const FromError = error{
        /// Not a CSM (wrong code).
        NotCsm,
        /// A critical option this implementation does not know (§5.3: the
        /// receiver aborts with Bad-CSM-Option naming it), or a known one with
        /// a value that is not valid; `bad_option` is the option number.
        BadCsmOption,
    };

    /// The options of `message` as a CSM; `bad_option` is set on `BadCsmOption`.
    pub fn from(msg: Message, bad_option: *u16) FromError!Csm {
        if (msg.code != code.csm) return error.NotCsm;
        var c: Csm = .{};
        for (msg.options) |o| {
            switch (o.number) {
                option.max_message_size => {
                    if (o.value.len > 4) {
                        bad_option.* = o.number;
                        return error.BadCsmOption;
                    }
                    c.max_message_size = @intCast(coap.options.decodeUint(o.value));
                },
                option.block_wise_transfer => {
                    if (o.value.len != 0) {
                        bad_option.* = o.number;
                        return error.BadCsmOption;
                    }
                    c.block_wise = true;
                },
                option.extended_token_length => {
                    if (o.value.len != 0) {
                        bad_option.* = o.number;
                        return error.BadCsmOption;
                    }
                    c.extended_token_length = true;
                },
                else => if (coap.options.isCritical(o.number)) {
                    bad_option.* = o.number;
                    return error.BadCsmOption;
                },
            }
        }
        return c;
    }

    /// Storage for the option values `message` points into.
    pub const Storage = struct {
        opts: [3]coap.Option = undefined,
        size: [8]u8 = undefined,
    };

    /// This CSM as a message (no token). The options live in `storage`.
    pub fn message(c: Csm, storage: *Storage) Message {
        var n: usize = 0;
        if (c.max_message_size != default_max_message_size) {
            storage.opts[n] = .{ .number = option.max_message_size, .value = coap.options.encodeUint(c.max_message_size, &storage.size) };
            n += 1;
        }
        if (c.block_wise) {
            storage.opts[n] = .{ .number = option.block_wise_transfer, .value = &.{} };
            n += 1;
        }
        if (c.extended_token_length) {
            storage.opts[n] = .{ .number = option.extended_token_length, .value = &.{} };
            n += 1;
        }
        return .{ .code = code.csm, .options = storage.opts[0..n] };
    }
};

/// The Pong answering `ping`: the same token, and the Custody option when the
/// Ping carried it (§5.4: the sender asked for the Pong only once earlier
/// messages are processed, which is the caller's to honour before sending).
pub fn pongFor(ping: Message) Message {
    return .{ .code = code.pong, .token = ping.token, .options = custodyOnly(ping) };
}

fn custodyOnly(ping: Message) []const coap.Option {
    for (ping.options, 0..) |o, i| if (o.number == option.custody) return ping.options[i .. i + 1];
    return &.{};
}

/// An Abort message (§5.6) with the diagnostic text as payload (UTF-8, may be
/// empty) and, when the abort answers a bad CSM option, that option's number.
pub const AbortStorage = struct {
    opts: [1]coap.Option = undefined,
    num: [8]u8 = undefined,
};

pub fn abortMessage(storage: *AbortStorage, bad_csm_option: ?u16, diagnostic: []const u8) Message {
    var n: usize = 0;
    if (bad_csm_option) |b| {
        storage.opts[0] = .{ .number = option.bad_csm_option, .value = coap.options.encodeUint(b, &storage.num) };
        n = 1;
    }
    return .{ .code = code.abort, .options = storage.opts[0..n], .payload = diagnostic };
}

/// What the caller should do about one received message.
pub const Action = union(enum) {
    /// A request or response for the application.
    deliver,
    /// The peer's CSM was accepted; `Session.peer` holds it.
    csm,
    /// Answer with `pongFor(message)`.
    send_pong,
    /// A Pong; match its token against the Ping that was sent.
    pong,
    /// The peer will close after outstanding exchanges: stop starting new
    /// ones. `alternative_address` and `hold_off_s` are its optional Release
    /// options (§5.5), borrowed from the message.
    release: struct { alternative_address: ?[]const u8, hold_off_s: ?u32 },
    /// The peer aborted; close the connection. `bad_csm_option` is the option
    /// number it names, `diagnostic` its text.
    peer_abort: struct { bad_csm_option: ?u16, diagnostic: []const u8 },
    /// The message breaks the protocol: send `abortMessage` with `diagnostic`
    /// (and `bad_csm_option` when set) and close.
    abort: struct { bad_csm_option: ?u16, diagnostic: []const u8 },
};

/// The signaling state of one connection (RFC 8323 §5).
pub const Session = struct {
    /// What this side sent in its own CSM: `peer_limit` of the other side is
    /// checked against it, and `canSend` against the peer's.
    local: Csm,
    /// The peer's CSM, the default until it arrived.
    peer: Csm = .{},
    state: State = .awaiting_csm,

    pub const State = enum {
        /// Nothing but the peer's CSM is acceptable yet.
        awaiting_csm,
        established,
        /// The peer sent Release: no new exchanges.
        released,
        /// Either side aborted.
        closed,
    };

    pub fn init(local: Csm) Session {
        return .{ .local = local };
    }

    /// Feeds one received message through the state machine.
    pub fn onMessage(self: *Session, message: Message) Action {
        if (self.state == .closed) return .{ .abort = .{ .bad_csm_option = null, .diagnostic = "connection closed" } };
        const c = message.code;
        if (self.state == .awaiting_csm) {
            // §5.3: the CSM is the first message each side sends; anything
            // else first is a protocol error.
            if (c != code.csm) return self.fail("expected CSM first", null);
            var bad: u16 = 0;
            self.peer = Csm.from(message, &bad) catch |err| switch (err) {
                error.BadCsmOption => return self.fail("bad CSM option", bad),
                error.NotCsm => unreachable,
            };
            self.state = .established;
            return .csm;
        }
        if (c == code.csm) return self.fail("CSM sent twice", null);
        if (c == code.ping) return .send_pong;
        if (c == code.pong) return .pong;
        if (c == code.release) {
            self.state = .released;
            var alt: ?[]const u8 = null;
            var hold: ?u32 = null;
            for (message.options) |o| switch (o.number) {
                option.alternative_address => alt = o.value,
                option.hold_off => hold = @intCast(@min(coap.options.decodeUint(o.value), std.math.maxInt(u32))),
                else => {},
            };
            return .{ .release = .{ .alternative_address = alt, .hold_off_s = hold } };
        }
        if (c == code.abort) {
            self.state = .closed;
            var bad: ?u16 = null;
            for (message.options) |o| if (o.number == option.bad_csm_option and o.value.len <= 2) {
                bad = @intCast(coap.options.decodeUint(o.value));
            };
            return .{ .peer_abort = .{ .bad_csm_option = bad, .diagnostic = message.payload } };
        }
        // 0.00 Empty is not used on reliable transports (§3), and an unknown
        // signaling code is a protocol error too.
        if (c == .empty or c.class() == 7) return self.fail("unexpected code", null);
        return .deliver;
    }

    fn fail(self: *Session, diagnostic: []const u8, bad: ?u16) Action {
        self.state = .closed;
        return .{ .abort = .{ .bad_csm_option = bad, .diagnostic = diagnostic } };
    }

    /// Whether a message of `len` octets (the whole frame) may be sent: the
    /// peer's Max-Message-Size bounds it (§5.3.1); a larger payload has to go
    /// block-wise, which needs `peer.block_wise` (§5.3.2).
    pub fn canSend(self: *const Session, len: usize) bool {
        return len <= self.peer.max_message_size;
    }

    /// Whether a received frame of `len` octets is within what this side
    /// announced; an over-long one is answered with 4.13 or an Abort (§5.3.1).
    pub fn withinLocalLimit(self: *const Session, len: usize) bool {
        return len <= self.local.max_message_size;
    }

    /// New exchanges may be started (the peer has not released the connection).
    pub fn mayStartExchange(self: *const Session) bool {
        return self.state == .established;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "framing: header forms, hand-derived bytes" {
    var out: [64]u8 = undefined;
    // GET, token 0x01, Uri-Path "x": options B1 78 -> body 2.
    var n = try serialize(.{ .code = .get, .token = &.{0x01}, .options = &.{.{ .number = 11, .value = "x" }} }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x21, 0x01, 0x01, 0xB1, 0x78 }, out[0..n]);
    // Empty-ish request: 0 body, TKL 0.
    n = try serialize(.{ .code = .get }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, out[0..n]);
    // With a payload: marker + payload count in Len.
    n = try serialize(.{ .code = .content, .token = &.{ 0xAA, 0xBB }, .payload = "hi" }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x32, 0x45, 0xAA, 0xBB, 0xFF, 'h', 'i' }, out[0..n]);
    // Body of exactly 12 octets stays in the nibble, 13 needs the extension octet.
    var p12: [11]u8 = @splat('p'); // marker + 11 = 12
    n = try serialize(.{ .code = .content, .payload = &p12 }, &out);
    try testing.expectEqual(@as(u8, 0xC0), out[0]);
    try testing.expectEqual(@as(usize, 2 + 12), n);
    var p13: [12]u8 = @splat('p');
    n = try serialize(.{ .code = .content, .payload = &p13 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0xD0, 0x00, 0x45, 0xFF }, out[0..4]);
    try testing.expectEqual(@as(usize, 3 + 13), n);
}

test "framing: the extended length forms at their boundaries round-trip" {
    var gpa_buf: [70000]u8 = undefined;
    var payload: [70000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 3 +% 1);
    var opts: [4]coap.Option = undefined;
    // payload length p -> body p + 1 (marker): 12 -> p 11; 13 -> 12; 268 -> 267; 269 -> 268;
    // 65804 -> 65803; 65805 -> 65804.
    for ([_]usize{ 11, 12, 267, 268, 65803, 65804 }) |p| {
        const msg: Message = .{ .code = .content, .token = &.{ 1, 2, 3 }, .payload = payload[0..p] };
        const n = try serialize(msg, &gpa_buf);
        try testing.expectEqual(encodedLen(msg), n);
        try testing.expectEqual(n, try frameLen(gpa_buf[0..n], default_max_body));
        const d = try decode(gpa_buf[0..n], &opts, default_max_body);
        try testing.expectEqual(n, d.len);
        try testing.expectEqual(msg.code, d.message.code);
        try testing.expectEqualSlices(u8, msg.token, d.message.token);
        try testing.expectEqualSlices(u8, msg.payload, d.message.payload);
        // The Len nibble per the boundary.
        const body = p + 1;
        const want: u8 = if (body < 13) @intCast(body) else if (body < 269) 13 else if (body < 65805) 14 else 15;
        try testing.expectEqual(want, gpa_buf[0] >> 4);
    }
}

test "framing: stream decoding — incomplete input consumes nothing, two frames back to back" {
    var buf: [64]u8 = undefined;
    var n = try serialize(.{ .code = .get, .token = &.{7}, .options = &.{.{ .number = 11, .value = "temp" }} }, &buf);
    n += try serialize(.{ .code = .content, .token = &.{7}, .payload = "21.5" }, buf[n..]);
    var opts: [4]coap.Option = undefined;
    // Every proper prefix of the first frame is `Incomplete`.
    const first_len = try frameLen(buf[0..n], default_max_body);
    for (0..first_len) |cut| try testing.expectError(error.Incomplete, decode(buf[0..cut], &opts, default_max_body));
    const a = try decode(buf[0..n], &opts, default_max_body);
    try testing.expectEqual(first_len, a.len);
    try testing.expectEqual(coap.Code.get, a.message.code);
    try testing.expectEqualStrings("temp", a.message.options[0].value);
    var opts2: [4]coap.Option = undefined;
    const b = try decode(buf[a.len..n], &opts2, default_max_body);
    try testing.expectEqual(n - a.len, b.len);
    try testing.expectEqualStrings("21.5", b.message.payload);
}

test "framing: malformed and oversized input is a typed error" {
    var opts: [4]coap.Option = undefined;
    // TKL 9 (and 15) is reserved.
    try testing.expectError(error.BadTokenLength, decode(&.{ 0x09, 0x01 }, &opts, default_max_body));
    try testing.expectError(error.BadTokenLength, frameLen(&.{0x0F}, default_max_body));
    // A 4-octet length announcing more than the limit is refused before buffering.
    try testing.expectError(error.TooLarge, frameLen(&.{ 0xF0, 0x00, 0x10, 0x00, 0x00 }, 1 << 20));
    try testing.expectError(error.Incomplete, frameLen(&.{ 0xF0, 0x00, 0x10 }, 1 << 20));
    try testing.expectEqual(@as(usize, 1 + 4 + 1 + 65805 + 0x1000), try frameLen(&.{ 0xF0, 0x00, 0x00, 0x10, 0x00 }, 1 << 20));
    // A reserved option nibble inside a complete frame; a payload marker with no payload.
    try testing.expectError(error.BadOption, decode(&.{ 0x10, 0x01, 0xF0 }, &opts, default_max_body));
    try testing.expectError(error.EmptyPayload, decode(&.{ 0x10, 0x45, 0xFF }, &opts, default_max_body));
    // The option array bounds the count.
    var one: [1]coap.Option = undefined;
    try testing.expectError(error.TooManyOptions, decode(&.{ 0x40, 0x01, 0xB1, 'a', 0x01, 'b' }, &one, default_max_body));
    // Encoding: unsorted options, an over-long token, a small buffer.
    var out: [16]u8 = undefined;
    try testing.expectError(error.OptionsNotSorted, serialize(.{ .code = .get, .options = &.{ .{ .number = 11, .value = "" }, .{ .number = 3, .value = "" } } }, &out));
    try testing.expectError(error.BadTokenLength, serialize(.{ .code = .get, .token = "123456789" }, &out));
    try testing.expectError(error.BufferTooSmall, serialize(.{ .code = .get, .token = "1234" }, out[0..5]));
}

test "CSM: defaults are not sent, options round-trip, unknown critical options are refused" {
    var st: Csm.Storage = undefined;
    var buf: [32]u8 = undefined;
    // Default CSM: no options.
    var n = try serialize((Csm{}).message(&st), &buf);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xE1 }, buf[0..n]);
    // Max-Message-Size 8192 (2 octets) + Block-Wise-Transfer + Extended-Token-Length:
    // option 2 len 2 -> 0x22 20 00; option 4 (delta 2) len 0 -> 0x20; option 6 (delta 2) len 0 -> 0x20.
    const full: Csm = .{ .max_message_size = 8192, .block_wise = true, .extended_token_length = true };
    n = try serialize(full.message(&st), &buf);
    try testing.expectEqualSlices(u8, &.{ 0x50, 0xE1, 0x22, 0x20, 0x00, 0x20, 0x20 }, buf[0..n]);
    var opts: [4]coap.Option = undefined;
    const d = try decode(buf[0..n], &opts, default_max_body);
    var bad: u16 = 0;
    try testing.expectEqual(full, try Csm.from(d.message, &bad));
    // A value on the Block-Wise-Transfer option is invalid; a 5-octet Max-Message-Size too.
    try testing.expectError(error.BadCsmOption, Csm.from(.{ .code = code.csm, .options = &.{.{ .number = option.block_wise_transfer, .value = &.{1} }} }, &bad));
    try testing.expectEqual(option.block_wise_transfer, bad);
    try testing.expectError(error.BadCsmOption, Csm.from(.{ .code = code.csm, .options = &.{.{ .number = option.max_message_size, .value = &.{ 1, 2, 3, 4, 5 } }} }, &bad));
    // An unknown elective option (even number) is ignored, an unknown critical one (odd) refused.
    _ = try Csm.from(.{ .code = code.csm, .options = &.{.{ .number = 8, .value = "x" }} }, &bad);
    try testing.expectError(error.BadCsmOption, Csm.from(.{ .code = code.csm, .options = &.{.{ .number = 9, .value = "x" }} }, &bad));
    try testing.expectEqual(@as(u16, 9), bad);
    try testing.expectError(error.NotCsm, Csm.from(.{ .code = .get }, &bad));
}

test "Session: CSM first, Ping/Pong, Release, Abort" {
    var s = Session.init(.{ .max_message_size = 4096, .block_wise = true });
    try testing.expect(!s.mayStartExchange());
    // Anything but a CSM first aborts.
    var t = s;
    try testing.expect(t.onMessage(.{ .code = .get }) == .abort);
    try testing.expectEqual(Session.State.closed, t.state);
    // A CSM with a bad critical option aborts naming it.
    t = s;
    const bad_csm: Message = .{ .code = code.csm, .options = &.{.{ .number = 9, .value = "" }} };
    const bad_action = t.onMessage(bad_csm);
    try testing.expectEqual(@as(?u16, 9), bad_action.abort.bad_csm_option);

    // A good CSM establishes; its limits apply to sending.
    var st: Csm.Storage = undefined;
    const peer: Csm = .{ .max_message_size = 2000, .block_wise = true };
    try testing.expect(s.onMessage(peer.message(&st)) == .csm);
    try testing.expect(s.mayStartExchange());
    try testing.expect(s.peer.block_wise);
    try testing.expect(s.canSend(2000) and !s.canSend(2001));
    try testing.expect(s.withinLocalLimit(4096) and !s.withinLocalLimit(4097));

    // Requests and responses are delivered; Empty and a second CSM are protocol errors.
    try testing.expect(s.onMessage(.{ .code = .get, .token = &.{1} }) == .deliver);
    try testing.expect(s.onMessage(.{ .code = .content }) == .deliver);
    var e = s;
    try testing.expect(e.onMessage(.{ .code = .empty }) == .abort);
    e = s;
    try testing.expect(e.onMessage(peer.message(&st)) == .abort);
    e = s;
    try testing.expect(e.onMessage(.{ .code = @fromBackingInt((7 << 5) | 9) }) == .abort);

    // Ping is answered by a Pong with the token (and Custody when present).
    const ping: Message = .{ .code = code.ping, .token = &.{ 9, 9 }, .options = &.{.{ .number = option.custody, .value = &.{} }} };
    try testing.expect(s.onMessage(ping) == .send_pong);
    const pong = pongFor(ping);
    try testing.expectEqual(code.pong, pong.code);
    try testing.expectEqualSlices(u8, &.{ 9, 9 }, pong.token);
    try testing.expectEqual(@as(usize, 1), pong.options.len);
    try testing.expectEqual(@as(usize, 0), pongFor(.{ .code = code.ping, .token = &.{1} }).options.len);
    try testing.expect(s.onMessage(.{ .code = code.pong, .token = &.{ 9, 9 } }) == .pong);

    // Release: no new exchanges; its options are reported.
    var hold: [8]u8 = undefined;
    const rel = s.onMessage(.{ .code = code.release, .options = &.{
        .{ .number = option.alternative_address, .value = "tcp://other:5683" },
        .{ .number = option.hold_off, .value = coap.options.encodeUint(30, &hold) },
    } });
    try testing.expectEqualStrings("tcp://other:5683", rel.release.alternative_address.?);
    try testing.expectEqual(@as(?u32, 30), rel.release.hold_off_s);
    try testing.expect(!s.mayStartExchange());
    try testing.expectEqual(Session.State.released, s.state);
    // Requests still arrive while released (exchanges in flight finish).
    try testing.expect(s.onMessage(.{ .code = .get }) == .deliver);

    // Abort closes, and carries the Bad-CSM-Option number and the text.
    var ast: AbortStorage = undefined;
    const am = abortMessage(&ast, 9, "no");
    var buf: [32]u8 = undefined;
    const n = try serialize(am, &buf);
    var opts: [2]coap.Option = undefined;
    const back = (try decode(buf[0..n], &opts, default_max_body)).message;
    const act = s.onMessage(back);
    try testing.expectEqual(@as(?u16, 9), act.peer_abort.bad_csm_option);
    try testing.expectEqualStrings("no", act.peer_abort.diagnostic);
    try testing.expectEqual(Session.State.closed, s.state);
    try testing.expect(s.onMessage(.{ .code = .get }) == .abort);
    // No bad option: none reported.
    const plain = abortMessage(&ast, null, "");
    try testing.expectEqual(@as(usize, 0), plain.options.len);
}
