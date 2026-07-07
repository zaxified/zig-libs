// SPDX-License-Identifier: MIT

//! MQTT 3.1.1 control-packet codec: encode + decode for all 14 packet types
//! (CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE,
//! SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT).
//!
//! Pure wire logic — no I/O, no allocation. Decoding is zero-copy: string
//! and payload fields of a decoded `Packet` are slices into the input
//! buffer. `decode` returns `null` while the buffer does not yet hold a
//! complete packet (stream framing) and a typed error for malformed bytes —
//! it never panics on hostile input. All lengths are bounded: UTF-8 strings
//! by their 2-byte length prefix, the packet body by the remaining-length
//! varint (1–4 bytes, max 268 435 455, overlong encodings rejected).
//!
//! Provenance: clean-room from the OASIS MQTT Version 3.1.1 specification.

const std = @import("std");

/// Protocol name carried in the CONNECT variable header (spec 3.1.2.1).
pub const protocol_name = "MQTT";
/// Protocol level for MQTT 3.1.1 (spec 3.1.2.2).
pub const protocol_level: u8 = 4;

/// Largest value the remaining-length varint can carry (spec 2.2.3).
pub const max_remaining_length: u32 = 268_435_455;

/// Largest UTF-8 string / binary field (2-byte length prefix, spec 1.5.3).
pub const max_string_len: usize = 65_535;

/// SUBACK per-filter return code for "subscription refused" (spec 3.9.3).
pub const suback_failure: u8 = 0x80;

/// Control-packet type, the high nibble of the fixed header (spec 2.2.1).
pub const PacketType = enum(u4) {
    connect = 1,
    connack = 2,
    publish = 3,
    puback = 4,
    pubrec = 5,
    pubrel = 6,
    pubcomp = 7,
    subscribe = 8,
    suback = 9,
    unsubscribe = 10,
    unsuback = 11,
    pingreq = 12,
    pingresp = 13,
    disconnect = 14,
};

/// Quality-of-service level (spec 4.3).
pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,
};

/// CONNACK return code (spec 3.2.2.3): 0 accepted, 1–5 refused.
pub const ConnectReturnCode = enum(u8) {
    accepted = 0,
    unacceptable_protocol_version = 1,
    identifier_rejected = 2,
    server_unavailable = 3,
    bad_username_or_password = 4,
    not_authorized = 5,
};

// ── error sets ──────────────────────────────────────────────────────────────

/// Failures while building a packet (all detected locally, before I/O).
pub const EncodeError = error{
    /// Destination buffer too small for the encoded packet.
    BufferTooSmall,
    /// A string / binary field exceeds the 65 535-byte length prefix.
    StringTooLong,
    /// Remaining length would exceed 268 435 455 bytes.
    PacketTooLarge,
    /// A UTF-8 string field is not well-formed UTF-8 (or contains U+0000).
    InvalidUtf8,
    /// CONNECT carries a password without a username (spec 3.1.2.9).
    PasswordWithoutUsername,
    /// Packet identifier 0 where a nonzero one is required (spec 2.3.1).
    InvalidPacketId,
    /// Empty client id without clean session (spec 3.1.3-7).
    InvalidClientId,
    /// SUBSCRIBE / UNSUBSCRIBE / SUBACK with an empty topic/code list.
    EmptyTopicList,
    /// SUBACK code other than 0, 1, 2 or 0x80.
    InvalidSubackCode,
};

/// Failures while decoding server bytes. Typed, never a panic.
pub const DecodeError = error{
    /// Remaining-length varint is longer than 4 bytes or overlong-encoded.
    MalformedRemainingLength,
    /// Fixed-header type nibble is 0 or 15 (reserved).
    UnknownPacketType,
    /// Fixed-header flag bits differ from the value the spec mandates.
    InvalidFlags,
    /// A QoS field holds the reserved value 3.
    InvalidQos,
    /// Body disagrees with the announced lengths / reserved bits set / etc.
    MalformedPacket,
    /// A UTF-8 string field is not well-formed UTF-8 (or contains U+0000).
    InvalidUtf8,
    /// CONNECT protocol name is not "MQTT" or level is not 4.
    UnsupportedProtocol,
    /// Well-formed bytes that violate the protocol (e.g. wildcard in a
    /// PUBLISH topic name, spec 3.3.2.1).
    ProtocolViolation,
};

// ── packet payload types ────────────────────────────────────────────────────

/// Will message registered at connect time (spec 3.1.2.5–3.1.2.7).
pub const Will = struct {
    topic: []const u8,
    /// Application payload of the will; opaque bytes, not validated UTF-8.
    message: []const u8,
    qos: QoS = .at_most_once,
    retain: bool = false,
};

/// CONNECT fields (spec 3.1). Used both to encode and as decode output.
pub const Connect = struct {
    /// May be empty only together with `clean_session` (spec 3.1.3.1).
    client_id: []const u8,
    clean_session: bool = true,
    /// Keep-alive interval in seconds; 0 disables the mechanism.
    keep_alive_s: u16 = 0,
    will: ?Will = null,
    username: ?[]const u8 = null,
    /// Opaque binary data (spec 3.1.3.5), not validated as UTF-8.
    password: ?[]const u8 = null,
};

/// CONNACK fields (spec 3.2).
pub const Connack = struct {
    session_present: bool,
    return_code: ConnectReturnCode,
};

/// PUBLISH fields (spec 3.3). `packet_id` is meaningful only for QoS > 0.
pub const Publish = struct {
    topic: []const u8,
    payload: []const u8 = &.{},
    qos: QoS = .at_most_once,
    retain: bool = false,
    dup: bool = false,
    packet_id: u16 = 0,
};

/// One SUBSCRIBE entry: topic filter + requested QoS (spec 3.8.3).
pub const Subscription = struct {
    filter: []const u8,
    qos: QoS = .at_most_once,
};

/// Decoded SUBSCRIBE (spec 3.8). The payload is validated during decode;
/// walk the filter/QoS pairs with `iterator`.
pub const Subscribe = struct {
    packet_id: u16,
    /// Raw validated payload bytes (filter/QoS pairs).
    payload: []const u8,

    pub fn iterator(s: Subscribe) Iterator {
        return .{ .rest = s.payload };
    }

    pub const Iterator = struct {
        rest: []const u8,

        /// Defensive even on hand-built payloads: truncation ends iteration.
        pub fn next(it: *Iterator) ?Subscription {
            if (it.rest.len < 2) return null;
            const len = std.mem.readInt(u16, it.rest[0..2], .big);
            if (it.rest.len < 3 + @as(usize, len)) {
                it.rest = &.{};
                return null;
            }
            const filter = it.rest[2 .. 2 + @as(usize, len)];
            const qos_raw = it.rest[2 + @as(usize, len)];
            it.rest = it.rest[3 + @as(usize, len) ..];
            if (qos_raw > 2) return null;
            return .{ .filter = filter, .qos = @enumFromInt(@as(u2, @intCast(qos_raw))) };
        }
    };
};

/// Decoded SUBACK (spec 3.9): one code per requested filter — 0/1/2 granted
/// QoS or `suback_failure` (0x80). Codes are validated during decode.
pub const Suback = struct {
    packet_id: u16,
    codes: []const u8,
};

/// Decoded UNSUBSCRIBE (spec 3.10); walk the filters with `iterator`.
pub const Unsubscribe = struct {
    packet_id: u16,
    /// Raw validated payload bytes (length-prefixed topic filters).
    payload: []const u8,

    pub fn iterator(u: Unsubscribe) Iterator {
        return .{ .rest = u.payload };
    }

    pub const Iterator = struct {
        rest: []const u8,

        pub fn next(it: *Iterator) ?[]const u8 {
            if (it.rest.len < 2) return null;
            const len = std.mem.readInt(u16, it.rest[0..2], .big);
            if (it.rest.len < 2 + @as(usize, len)) {
                it.rest = &.{};
                return null;
            }
            const filter = it.rest[2 .. 2 + @as(usize, len)];
            it.rest = it.rest[2 + @as(usize, len) ..];
            return filter;
        }
    };
};

/// A decoded control packet. Slice fields point into the decode input.
pub const Packet = union(PacketType) {
    connect: Connect,
    connack: Connack,
    publish: Publish,
    puback: u16,
    pubrec: u16,
    pubrel: u16,
    pubcomp: u16,
    subscribe: Subscribe,
    suback: Suback,
    unsubscribe: Unsubscribe,
    unsuback: u16,
    pingreq,
    pingresp,
    disconnect,
};

// ── remaining-length varint (spec 2.2.3) ────────────────────────────────────

pub const RemainingLength = struct {
    value: u32,
    /// Number of varint bytes consumed (1–4).
    len: usize,
};

/// Encode `value` as a remaining-length varint; returns the byte count (1–4).
pub fn encodeRemainingLength(buf: *[4]u8, value: u32) error{PacketTooLarge}!usize {
    if (value > max_remaining_length) return error.PacketTooLarge;
    var v = value;
    var i: usize = 0;
    while (true) {
        var b: u8 = @intCast(v & 0x7F);
        v >>= 7;
        if (v != 0) b |= 0x80;
        buf[i] = b;
        i += 1;
        if (v == 0) return i;
    }
}

/// Decode a remaining-length varint. Returns `null` if `bytes` ends before
/// the varint does (need more data). Rejects encodings longer than 4 bytes
/// and overlong encodings (a trailing 0x00 continuation byte).
pub fn decodeRemainingLength(bytes: []const u8) DecodeError!?RemainingLength {
    var value: u32 = 0;
    var i: usize = 0;
    while (i < bytes.len and i < 4) : (i += 1) {
        const b = bytes[i];
        value |= @as(u32, b & 0x7F) << @intCast(7 * i);
        if (b & 0x80 == 0) {
            // Overlong guard: only a 1-byte encoding may end in 0x00.
            if (i > 0 and b == 0) return error.MalformedRemainingLength;
            return .{ .value = value, .len = i + 1 };
        }
    }
    if (i == 4) return error.MalformedRemainingLength;
    return null;
}

// ── shared field validation ─────────────────────────────────────────────────

/// MQTT UTF-8 string rules (spec 1.5.3): well-formed UTF-8 (which excludes
/// surrogate code points) and no U+0000.
pub fn wellFormedString(s: []const u8) bool {
    if (std.mem.indexOfScalar(u8, s, 0) != null) return false;
    return std.unicode.utf8ValidateSlice(s);
}

// ── encoding ────────────────────────────────────────────────────────────────

/// Bounds-checked byte cursor over the caller's output buffer.
const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn byte(c: *Cursor, b: u8) EncodeError!void {
        if (c.pos >= c.buf.len) return error.BufferTooSmall;
        c.buf[c.pos] = b;
        c.pos += 1;
    }

    fn u16be(c: *Cursor, v: u16) EncodeError!void {
        if (c.buf.len - c.pos < 2) return error.BufferTooSmall;
        std.mem.writeInt(u16, c.buf[c.pos..][0..2], v, .big);
        c.pos += 2;
    }

    fn bytes(c: *Cursor, s: []const u8) EncodeError!void {
        if (c.buf.len - c.pos < s.len) return error.BufferTooSmall;
        @memcpy(c.buf[c.pos..][0..s.len], s);
        c.pos += s.len;
    }

    /// 2-byte length prefix + raw bytes (binary data, spec 1.5.3 framing).
    fn lenPrefixed(c: *Cursor, s: []const u8) EncodeError!void {
        if (s.len > max_string_len) return error.StringTooLong;
        try c.u16be(@intCast(s.len));
        try c.bytes(s);
    }

    /// Length-prefixed field that must also be a valid MQTT UTF-8 string.
    fn utf8String(c: *Cursor, s: []const u8) EncodeError!void {
        if (!wellFormedString(s)) return error.InvalidUtf8;
        try c.lenPrefixed(s);
    }

    fn fixedHeader(c: *Cursor, t: PacketType, flags: u4, remaining: u32) EncodeError!void {
        try c.byte(@as(u8, @intFromEnum(t)) << 4 | flags);
        var tmp: [4]u8 = undefined;
        const n = try encodeRemainingLength(&tmp, remaining);
        try c.bytes(tmp[0..n]);
    }

    fn done(c: *const Cursor) []const u8 {
        return c.buf[0..c.pos];
    }
};

fn checkedRemaining(remaining: u64) EncodeError!u32 {
    if (remaining > max_remaining_length) return error.PacketTooLarge;
    return @intCast(remaining);
}

/// Encode CONNECT (spec 3.1). Password without username is rejected
/// (spec 3.1.2.22); an empty client id requires `clean_session`.
pub fn encodeConnect(buf: []u8, c: Connect) EncodeError![]const u8 {
    if (c.password != null and c.username == null) return error.PasswordWithoutUsername;
    if (c.client_id.len == 0 and !c.clean_session) return error.InvalidClientId;

    var remaining: u64 = 10 + 2 + c.client_id.len; // variable header + client id
    if (c.will) |w| remaining += 2 + w.topic.len + 2 + w.message.len;
    if (c.username) |u| remaining += 2 + u.len;
    if (c.password) |p| remaining += 2 + p.len;

    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(.connect, 0, try checkedRemaining(remaining));
    try cur.lenPrefixed(protocol_name);
    try cur.byte(protocol_level);

    var flags: u8 = 0;
    if (c.clean_session) flags |= 0x02;
    if (c.will) |w| {
        flags |= 0x04 | @as(u8, @intFromEnum(w.qos)) << 3;
        if (w.retain) flags |= 0x20;
    }
    if (c.username != null) flags |= 0x80;
    if (c.password != null) flags |= 0x40;
    try cur.byte(flags);

    try cur.u16be(c.keep_alive_s);
    try cur.utf8String(c.client_id);
    if (c.will) |w| {
        try cur.utf8String(w.topic);
        try cur.lenPrefixed(w.message);
    }
    if (c.username) |u| try cur.utf8String(u);
    if (c.password) |p| try cur.lenPrefixed(p);
    return cur.done();
}

/// Encode CONNACK (spec 3.2) — mostly useful for test fakes and servers.
pub fn encodeConnack(buf: []u8, c: Connack) EncodeError![]const u8 {
    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(.connack, 0, 2);
    try cur.byte(if (c.session_present) 1 else 0);
    try cur.byte(@intFromEnum(c.return_code));
    return cur.done();
}

/// Encode PUBLISH (spec 3.3). QoS > 0 requires a nonzero `packet_id`;
/// the DUP flag is cleared for QoS 0 (spec 3.3.1.1).
pub fn encodePublish(buf: []u8, p: Publish) EncodeError![]const u8 {
    if (p.qos != .at_most_once and p.packet_id == 0) return error.InvalidPacketId;
    var remaining: u64 = 2 + @as(u64, p.topic.len) + p.payload.len;
    if (p.qos != .at_most_once) remaining += 2;

    var flags: u4 = @as(u4, @intFromEnum(p.qos)) << 1;
    if (p.dup and p.qos != .at_most_once) flags |= 0x8;
    if (p.retain) flags |= 0x1;

    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(.publish, flags, try checkedRemaining(remaining));
    try cur.utf8String(p.topic);
    if (p.qos != .at_most_once) try cur.u16be(p.packet_id);
    try cur.bytes(p.payload);
    return cur.done();
}

fn encodeIdOnly(buf: []u8, t: PacketType, flags: u4, packet_id: u16) EncodeError![]const u8 {
    if (packet_id == 0) return error.InvalidPacketId;
    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(t, flags, 2);
    try cur.u16be(packet_id);
    return cur.done();
}

/// Encode PUBACK (spec 3.4).
pub fn encodePuback(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodeIdOnly(buf, .puback, 0, packet_id);
}

/// Encode PUBREC (spec 3.5).
pub fn encodePubrec(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodeIdOnly(buf, .pubrec, 0, packet_id);
}

/// Encode PUBREL (spec 3.6) — fixed-header flags are mandatorily 0b0010.
pub fn encodePubrel(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodeIdOnly(buf, .pubrel, 0x2, packet_id);
}

/// Encode PUBCOMP (spec 3.7).
pub fn encodePubcomp(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodeIdOnly(buf, .pubcomp, 0, packet_id);
}

/// Encode UNSUBACK (spec 3.11) — for test fakes and servers.
pub fn encodeUnsuback(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodeIdOnly(buf, .unsuback, 0, packet_id);
}

/// Encode SUBSCRIBE (spec 3.8) — at least one filter is required.
pub fn encodeSubscribe(buf: []u8, packet_id: u16, filters: []const Subscription) EncodeError![]const u8 {
    if (packet_id == 0) return error.InvalidPacketId;
    if (filters.len == 0) return error.EmptyTopicList;
    var remaining: u64 = 2;
    for (filters) |f| remaining += 2 + @as(u64, f.filter.len) + 1;

    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(.subscribe, 0x2, try checkedRemaining(remaining));
    try cur.u16be(packet_id);
    for (filters) |f| {
        try cur.utf8String(f.filter);
        try cur.byte(@intFromEnum(f.qos));
    }
    return cur.done();
}

/// Encode SUBACK (spec 3.9) — for test fakes and servers. Codes must be
/// 0, 1, 2 or `suback_failure` (0x80).
pub fn encodeSuback(buf: []u8, packet_id: u16, codes: []const u8) EncodeError![]const u8 {
    if (packet_id == 0) return error.InvalidPacketId;
    if (codes.len == 0) return error.EmptyTopicList;
    for (codes) |code| {
        if (code > 2 and code != suback_failure) return error.InvalidSubackCode;
    }
    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(.suback, 0, try checkedRemaining(2 + @as(u64, codes.len)));
    try cur.u16be(packet_id);
    try cur.bytes(codes);
    return cur.done();
}

/// Encode UNSUBSCRIBE (spec 3.10) — at least one filter is required.
pub fn encodeUnsubscribe(buf: []u8, packet_id: u16, filters: []const []const u8) EncodeError![]const u8 {
    if (packet_id == 0) return error.InvalidPacketId;
    if (filters.len == 0) return error.EmptyTopicList;
    var remaining: u64 = 2;
    for (filters) |f| remaining += 2 + @as(u64, f.len);

    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(.unsubscribe, 0x2, try checkedRemaining(remaining));
    try cur.u16be(packet_id);
    for (filters) |f| try cur.utf8String(f);
    return cur.done();
}

fn encodeEmpty(buf: []u8, t: PacketType) EncodeError![]const u8 {
    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(t, 0, 0);
    return cur.done();
}

/// Encode PINGREQ (spec 3.12).
pub fn encodePingreq(buf: []u8) EncodeError![]const u8 {
    return encodeEmpty(buf, .pingreq);
}

/// Encode PINGRESP (spec 3.13) — for test fakes and servers.
pub fn encodePingresp(buf: []u8) EncodeError![]const u8 {
    return encodeEmpty(buf, .pingresp);
}

/// Encode DISCONNECT (spec 3.14).
pub fn encodeDisconnect(buf: []u8) EncodeError![]const u8 {
    return encodeEmpty(buf, .disconnect);
}

// ── decoding ────────────────────────────────────────────────────────────────

pub const Decoded = struct {
    packet: Packet,
    /// Total bytes consumed from the input (fixed header + body).
    consumed: usize,
};

/// Bounds-checked reader over a packet body.
const BodyReader = struct {
    rest: []const u8,

    fn byte(r: *BodyReader) DecodeError!u8 {
        if (r.rest.len < 1) return error.MalformedPacket;
        const b = r.rest[0];
        r.rest = r.rest[1..];
        return b;
    }

    fn u16be(r: *BodyReader) DecodeError!u16 {
        if (r.rest.len < 2) return error.MalformedPacket;
        const v = std.mem.readInt(u16, r.rest[0..2], .big);
        r.rest = r.rest[2..];
        return v;
    }

    fn lenPrefixed(r: *BodyReader) DecodeError![]const u8 {
        const len = try r.u16be();
        if (r.rest.len < len) return error.MalformedPacket;
        const s = r.rest[0..len];
        r.rest = r.rest[len..];
        return s;
    }

    fn utf8String(r: *BodyReader) DecodeError![]const u8 {
        const s = try r.lenPrefixed();
        if (!wellFormedString(s)) return error.InvalidUtf8;
        return s;
    }

    fn takeRest(r: *BodyReader) []const u8 {
        const s = r.rest;
        r.rest = &.{};
        return s;
    }

    fn expectEmpty(r: *const BodyReader) DecodeError!void {
        if (r.rest.len != 0) return error.MalformedPacket;
    }
};

fn nonzeroId(id: u16) DecodeError!u16 {
    if (id == 0) return error.MalformedPacket;
    return id;
}

/// Decode one control packet from the front of `bytes`.
///
/// Returns `null` when `bytes` does not yet hold a complete packet (read
/// more from the stream and retry). On success `consumed` is the packet's
/// total wire size; slice fields of the packet point into `bytes`.
pub fn decode(bytes: []const u8) DecodeError!?Decoded {
    if (bytes.len < 1) return null;
    const b0 = bytes[0];
    const type_raw: u8 = b0 >> 4;
    if (type_raw < 1 or type_raw > 14) return error.UnknownPacketType;
    const ptype: PacketType = @enumFromInt(type_raw);
    const flags: u4 = @truncate(b0);

    const rl = try decodeRemainingLength(bytes[1..]) orelse return null;
    const total: usize = 1 + rl.len + @as(usize, rl.value);
    if (bytes.len < total) return null;
    const body = bytes[1 + rl.len ..][0..rl.value];

    return .{ .packet = try decodeBody(ptype, flags, body), .consumed = total };
}

fn decodeBody(ptype: PacketType, flags: u4, body: []const u8) DecodeError!Packet {
    // Fixed-header flag bits are mandated per type (spec 2.2.2, table 2.2).
    switch (ptype) {
        .publish => {},
        .pubrel, .subscribe, .unsubscribe => if (flags != 0x2) return error.InvalidFlags,
        else => if (flags != 0) return error.InvalidFlags,
    }

    var r = BodyReader{ .rest = body };
    switch (ptype) {
        .connect => return .{ .connect = try decodeConnect(&r) },
        .connack => {
            const ack_flags = try r.byte();
            if (ack_flags & 0xFE != 0) return error.MalformedPacket;
            const rc = try r.byte();
            if (rc > 5) return error.MalformedPacket;
            try r.expectEmpty();
            return .{ .connack = .{
                .session_present = ack_flags & 0x1 != 0,
                .return_code = @enumFromInt(rc),
            } };
        },
        .publish => return .{ .publish = try decodePublish(&r, flags) },
        .puback => return .{ .puback = try decodeIdOnly(&r) },
        .pubrec => return .{ .pubrec = try decodeIdOnly(&r) },
        .pubrel => return .{ .pubrel = try decodeIdOnly(&r) },
        .pubcomp => return .{ .pubcomp = try decodeIdOnly(&r) },
        .subscribe => {
            const id = try nonzeroId(try r.u16be());
            const payload = r.takeRest();
            if (payload.len == 0) return error.ProtocolViolation; // spec 3.8.3-3
            var v = BodyReader{ .rest = payload };
            while (v.rest.len > 0) {
                const f = try v.utf8String();
                if (f.len == 0) return error.MalformedPacket;
                const q = try v.byte();
                if (q > 2) return error.InvalidQos;
            }
            return .{ .subscribe = .{ .packet_id = id, .payload = payload } };
        },
        .suback => {
            const id = try nonzeroId(try r.u16be());
            const codes = r.takeRest();
            if (codes.len == 0) return error.MalformedPacket;
            for (codes) |code| {
                if (code > 2 and code != suback_failure) return error.MalformedPacket;
            }
            return .{ .suback = .{ .packet_id = id, .codes = codes } };
        },
        .unsubscribe => {
            const id = try nonzeroId(try r.u16be());
            const payload = r.takeRest();
            if (payload.len == 0) return error.ProtocolViolation; // spec 3.10.3-2
            var v = BodyReader{ .rest = payload };
            while (v.rest.len > 0) {
                const f = try v.utf8String();
                if (f.len == 0) return error.MalformedPacket;
            }
            return .{ .unsubscribe = .{ .packet_id = id, .payload = payload } };
        },
        .unsuback => return .{ .unsuback = try decodeIdOnly(&r) },
        .pingreq => {
            try r.expectEmpty();
            return .pingreq;
        },
        .pingresp => {
            try r.expectEmpty();
            return .pingresp;
        },
        .disconnect => {
            try r.expectEmpty();
            return .disconnect;
        },
    }
}

fn decodeIdOnly(r: *BodyReader) DecodeError!u16 {
    const id = try nonzeroId(try r.u16be());
    try r.expectEmpty();
    return id;
}

fn decodeConnect(r: *BodyReader) DecodeError!Connect {
    const name = try r.lenPrefixed();
    if (!std.mem.eql(u8, name, protocol_name)) return error.UnsupportedProtocol;
    const level = try r.byte();
    if (level != protocol_level) return error.UnsupportedProtocol;

    const flags = try r.byte();
    if (flags & 0x01 != 0) return error.MalformedPacket; // reserved bit
    const clean_session = flags & 0x02 != 0;
    const will_flag = flags & 0x04 != 0;
    const will_qos_raw: u8 = (flags >> 3) & 0x3;
    const will_retain = flags & 0x20 != 0;
    const password_flag = flags & 0x40 != 0;
    const username_flag = flags & 0x80 != 0;
    if (will_qos_raw == 3) return error.InvalidQos;
    if (!will_flag and (will_qos_raw != 0 or will_retain)) return error.MalformedPacket;
    if (password_flag and !username_flag) return error.MalformedPacket; // spec 3.1.2-22

    const keep_alive_s = try r.u16be();
    const client_id = try r.utf8String();
    if (client_id.len == 0 and !clean_session) return error.MalformedPacket; // spec 3.1.3-7

    var will: ?Will = null;
    if (will_flag) {
        const topic = try r.utf8String();
        if (topic.len == 0) return error.MalformedPacket;
        will = .{
            .topic = topic,
            .message = try r.lenPrefixed(),
            .qos = @enumFromInt(@as(u2, @intCast(will_qos_raw))),
            .retain = will_retain,
        };
    }
    const username = if (username_flag) try r.utf8String() else null;
    const password = if (password_flag) try r.lenPrefixed() else null;
    try r.expectEmpty();

    return .{
        .client_id = client_id,
        .clean_session = clean_session,
        .keep_alive_s = keep_alive_s,
        .will = will,
        .username = username,
        .password = password,
    };
}

fn decodePublish(r: *BodyReader, flags: u4) DecodeError!Publish {
    const qos_raw: u8 = (@as(u8, flags) >> 1) & 0x3;
    if (qos_raw == 3) return error.InvalidQos;
    const qos: QoS = @enumFromInt(@as(u2, @intCast(qos_raw)));
    const dup = flags & 0x8 != 0;
    const retain = flags & 0x1 != 0;
    if (dup and qos == .at_most_once) return error.MalformedPacket; // spec 3.3.1-2

    const topic = try r.utf8String();
    if (topic.len == 0) return error.MalformedPacket;
    if (std.mem.indexOfAny(u8, topic, "+#") != null) return error.ProtocolViolation; // spec 3.3.2-2

    const packet_id = if (qos != .at_most_once) try nonzeroId(try r.u16be()) else 0;
    return .{
        .topic = topic,
        .payload = r.takeRest(),
        .qos = qos,
        .retain = retain,
        .dup = dup,
        .packet_id = packet_id,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "remaining length: boundary values encode/decode exactly" {
    const cases = [_]struct { value: u32, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 127, .bytes = &.{0x7F} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 16_383, .bytes = &.{ 0xFF, 0x7F } },
        .{ .value = 16_384, .bytes = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 2_097_151, .bytes = &.{ 0xFF, 0xFF, 0x7F } },
        .{ .value = 2_097_152, .bytes = &.{ 0x80, 0x80, 0x80, 0x01 } },
        .{ .value = 268_435_455, .bytes = &.{ 0xFF, 0xFF, 0xFF, 0x7F } },
    };
    for (cases) |case| {
        var buf: [4]u8 = undefined;
        const n = try encodeRemainingLength(&buf, case.value);
        try testing.expectEqualSlices(u8, case.bytes, buf[0..n]);
        const dec = (try decodeRemainingLength(case.bytes)).?;
        try testing.expectEqual(case.value, dec.value);
        try testing.expectEqual(case.bytes.len, dec.len);
    }
}

test "remaining length: malformed and incomplete" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.PacketTooLarge, encodeRemainingLength(&buf, 268_435_456));

    // 5-byte / 4-continuation-byte encodings are malformed.
    try testing.expectError(
        error.MalformedRemainingLength,
        decodeRemainingLength(&.{ 0x80, 0x80, 0x80, 0x80, 0x01 }),
    );
    try testing.expectError(
        error.MalformedRemainingLength,
        decodeRemainingLength(&.{ 0xFF, 0xFF, 0xFF, 0xFF }),
    );
    // Overlong encodings of small values are malformed.
    try testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0x80, 0x00 }));
    try testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0xFF, 0x80, 0x00 }));
    // Truncated varint: need more bytes.
    try testing.expectEqual(null, try decodeRemainingLength(&.{0x80}));
    try testing.expectEqual(null, try decodeRemainingLength(&.{ 0x80, 0x80, 0x80 }));
}

test "CONNECT: golden bytes with will + credentials (KAT)" {
    var buf: [64]u8 = undefined;
    const got = try encodeConnect(&buf, .{
        .client_id = "zl",
        .clean_session = true,
        .keep_alive_s = 60,
        .will = .{ .topic = "w/t", .message = "gone", .qos = .at_least_once, .retain = true },
        .username = "user",
        .password = "pass",
    });
    const expected = [_]u8{
        0x10, 0x25, // CONNECT, remaining length 37
        0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
        0x04, // protocol level 4
        0xEE, // user+pass+will retain+will qos1+will flag+clean session
        0x00, 0x3C, // keep-alive 60
        0x00, 0x02, 'z', 'l', // client id
        0x00, 0x03, 'w', '/', 't', // will topic
        0x00, 0x04, 'g', 'o', 'n', 'e', // will message
        0x00, 0x04, 'u', 's', 'e', 'r', // username
        0x00, 0x04, 'p', 'a', 's', 's', // password
    };
    try testing.expectEqualSlices(u8, &expected, got);

    // Round-trip: decode gives back every field.
    const dec = (try decode(got)).?;
    try testing.expectEqual(got.len, dec.consumed);
    const c = dec.packet.connect;
    try testing.expectEqualStrings("zl", c.client_id);
    try testing.expect(c.clean_session);
    try testing.expectEqual(@as(u16, 60), c.keep_alive_s);
    try testing.expectEqualStrings("w/t", c.will.?.topic);
    try testing.expectEqualStrings("gone", c.will.?.message);
    try testing.expectEqual(QoS.at_least_once, c.will.?.qos);
    try testing.expect(c.will.?.retain);
    try testing.expectEqualStrings("user", c.username.?);
    try testing.expectEqualSlices(u8, "pass", c.password.?);
}

test "CONNECT: validation" {
    var buf: [64]u8 = undefined;
    try testing.expectError(
        error.PasswordWithoutUsername,
        encodeConnect(&buf, .{ .client_id = "x", .password = "p" }),
    );
    try testing.expectError(
        error.InvalidClientId,
        encodeConnect(&buf, .{ .client_id = "", .clean_session = false }),
    );
    try testing.expectError(
        error.InvalidUtf8,
        encodeConnect(&buf, .{ .client_id = &.{ 0xFF, 0xFE } }),
    );
    try testing.expectError(error.BufferTooSmall, encodeConnect(buf[0..4], .{ .client_id = "x" }));

    // Decoding: wrong protocol name / level.
    var ok_buf: [32]u8 = undefined;
    const ok = try encodeConnect(&ok_buf, .{ .client_id = "x" });
    var bad: [32]u8 = undefined;
    @memcpy(bad[0..ok.len], ok);
    bad[4] = 'X'; // corrupt protocol name
    try testing.expectError(error.UnsupportedProtocol, decode(bad[0..ok.len]));
    @memcpy(bad[0..ok.len], ok);
    bad[8] = 3; // protocol level 3
    try testing.expectError(error.UnsupportedProtocol, decode(bad[0..ok.len]));
    @memcpy(bad[0..ok.len], ok);
    bad[9] |= 0x01; // reserved connect flag set
    try testing.expectError(error.MalformedPacket, decode(bad[0..ok.len]));
}

test "CONNACK: decode golden bytes and all return codes" {
    const dec = (try decode(&.{ 0x20, 0x02, 0x01, 0x00 })).?;
    try testing.expectEqual(@as(usize, 4), dec.consumed);
    try testing.expect(dec.packet.connack.session_present);
    try testing.expectEqual(ConnectReturnCode.accepted, dec.packet.connack.return_code);

    const codes = [_]ConnectReturnCode{
        .accepted,           .unacceptable_protocol_version, .identifier_rejected,
        .server_unavailable, .bad_username_or_password,      .not_authorized,
    };
    for (codes, 0..) |rc, i| {
        const d = (try decode(&.{ 0x20, 0x02, 0x00, @intCast(i) })).?;
        try testing.expectEqual(rc, d.packet.connack.return_code);
        try testing.expect(!d.packet.connack.session_present);
    }

    // rc > 5, reserved ack bits, bad fixed flags, wrong length → typed errors.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x20, 0x02, 0x00, 0x06 }));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x20, 0x02, 0x02, 0x00 }));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x21, 0x02, 0x00, 0x00 }));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x20, 0x03, 0x00, 0x00, 0x00 }));

    // encodeConnack round-trips.
    var buf: [4]u8 = undefined;
    const enc = try encodeConnack(&buf, .{ .session_present = true, .return_code = .not_authorized });
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x02, 0x01, 0x05 }, enc);
}

test "PUBLISH: QoS 1 golden bytes + round-trip preserves packet id" {
    var buf: [32]u8 = undefined;
    const original = Publish{
        .topic = "a/b",
        .payload = "hi",
        .qos = .at_least_once,
        .packet_id = 10,
    };
    const got = try encodePublish(&buf, original);
    const expected = [_]u8{
        0x32, 0x09, // PUBLISH qos1, remaining length 9
        0x00, 0x03, 'a', '/', 'b', // topic
        0x00, 0x0A, // packet id 10
        'h', 'i', // payload
    };
    try testing.expectEqualSlices(u8, &expected, got);

    const dec = (try decode(got)).?;
    try testing.expectEqual(got.len, dec.consumed);
    const p = dec.packet.publish;
    try testing.expectEqualStrings(original.topic, p.topic);
    try testing.expectEqualSlices(u8, original.payload, p.payload);
    try testing.expectEqual(original.qos, p.qos);
    try testing.expectEqual(original.packet_id, p.packet_id);
    try testing.expectEqual(original.retain, p.retain);
    try testing.expectEqual(original.dup, p.dup);
}

test "PUBLISH: flags and malformed forms" {
    var buf: [32]u8 = undefined;
    // QoS 0: no packet id on the wire; DUP is normalized away.
    const q0 = try encodePublish(&buf, .{ .topic = "t", .payload = "x", .dup = true, .retain = true });
    try testing.expectEqualSlices(u8, &.{ 0x31, 0x04, 0x00, 0x01, 't', 'x' }, q0);

    // QoS > 0 requires a nonzero id.
    try testing.expectError(
        error.InvalidPacketId,
        encodePublish(&buf, .{ .topic = "t", .qos = .at_least_once }),
    );

    // Decode: QoS 3 is reserved.
    try testing.expectError(error.InvalidQos, decode(&.{ 0x36, 0x03, 0x00, 0x01, 't' }));
    // Decode: DUP with QoS 0 is malformed.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x38, 0x03, 0x00, 0x01, 't' }));
    // Decode: wildcard in a PUBLISH topic name is a protocol violation.
    try testing.expectError(error.ProtocolViolation, decode(&.{ 0x30, 0x03, 0x00, 0x01, '#' }));
    // Decode: zero packet id with QoS 1 is malformed.
    try testing.expectError(
        error.MalformedPacket,
        decode(&.{ 0x32, 0x05, 0x00, 0x01, 't', 0x00, 0x00 }),
    );
    // Decode: topic longer than the body.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x30, 0x02, 0x00, 0x09 }));
    // Decode: invalid UTF-8 topic.
    try testing.expectError(error.InvalidUtf8, decode(&.{ 0x30, 0x03, 0x00, 0x01, 0xFF }));
    // Decode: embedded U+0000 in topic.
    try testing.expectError(error.InvalidUtf8, decode(&.{ 0x30, 0x03, 0x00, 0x01, 0x00 }));
}

test "SUBSCRIBE: golden bytes + iterator round-trip" {
    var buf: [64]u8 = undefined;
    const got = try encodeSubscribe(&buf, 10, &.{
        .{ .filter = "a/b", .qos = .at_least_once },
        .{ .filter = "sport/#", .qos = .exactly_once },
    });
    const expected = [_]u8{
        0x82, 0x12, // SUBSCRIBE (flags 0b0010), remaining length 18
        0x00, 0x0A, // packet id 10
        0x00, 0x03, 'a', '/', 'b', 0x01, // "a/b" qos 1
        0x00, 0x07, 's', 'p', 'o', 'r', 't', '/', '#', 0x02, // "sport/#" qos 2
    };
    try testing.expectEqualSlices(u8, &expected, got);

    const dec = (try decode(got)).?;
    const s = dec.packet.subscribe;
    try testing.expectEqual(@as(u16, 10), s.packet_id);
    var it = s.iterator();
    const first = it.next().?;
    try testing.expectEqualStrings("a/b", first.filter);
    try testing.expectEqual(QoS.at_least_once, first.qos);
    const second = it.next().?;
    try testing.expectEqualStrings("sport/#", second.filter);
    try testing.expectEqual(QoS.exactly_once, second.qos);
    try testing.expectEqual(null, it.next());

    // Empty filter list / bad fixed flags / empty payload → typed errors.
    try testing.expectError(error.EmptyTopicList, encodeSubscribe(&buf, 10, &.{}));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x80, 0x02, 0x00, 0x0A }));
    try testing.expectError(error.ProtocolViolation, decode(&.{ 0x82, 0x02, 0x00, 0x0A }));
    // Requested QoS 3 in the payload.
    try testing.expectError(
        error.InvalidQos,
        decode(&.{ 0x82, 0x06, 0x00, 0x0A, 0x00, 0x01, 'a', 0x03 }),
    );
}

test "SUBACK: mixed granted QoS including 0x80 failure" {
    var buf: [16]u8 = undefined;
    const got = try encodeSuback(&buf, 10, &.{ 0x00, 0x01, 0x02, 0x80 });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x90, 0x06, 0x00, 0x0A, 0x00, 0x01, 0x02, 0x80 },
        got,
    );

    const dec = (try decode(got)).?;
    try testing.expectEqual(@as(u16, 10), dec.packet.suback.packet_id);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x80 }, dec.packet.suback.codes);

    // Invalid code on either side.
    try testing.expectError(error.InvalidSubackCode, encodeSuback(&buf, 10, &.{0x03}));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x90, 0x03, 0x00, 0x0A, 0x03 }));
    // No codes at all.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x90, 0x02, 0x00, 0x0A }));
}

test "UNSUBSCRIBE / UNSUBACK: round-trip" {
    var buf: [32]u8 = undefined;
    const got = try encodeUnsubscribe(&buf, 7, &.{ "a/b", "c" });
    try testing.expectEqualSlices(
        u8,
        &.{ 0xA2, 0x0A, 0x00, 0x07, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x01, 'c' },
        got,
    );
    const dec = (try decode(got)).?;
    var it = dec.packet.unsubscribe.iterator();
    try testing.expectEqualStrings("a/b", it.next().?);
    try testing.expectEqualStrings("c", it.next().?);
    try testing.expectEqual(null, it.next());

    var ubuf: [4]u8 = undefined;
    const ua = try encodeUnsuback(&ubuf, 7);
    try testing.expectEqualSlices(u8, &.{ 0xB0, 0x02, 0x00, 0x07 }, ua);
    try testing.expectEqual(@as(u16, 7), (try decode(ua)).?.packet.unsuback);
}

test "PUBACK/PUBREC/PUBREL/PUBCOMP: golden bytes, flags, round-trip" {
    var buf: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x02, 0x00, 0x0A }, try encodePuback(&buf, 10));
    try testing.expectEqualSlices(u8, &.{ 0x50, 0x02, 0x00, 0x0A }, try encodePubrec(&buf, 10));
    try testing.expectEqualSlices(u8, &.{ 0x62, 0x02, 0x00, 0x0A }, try encodePubrel(&buf, 10));
    try testing.expectEqualSlices(u8, &.{ 0x70, 0x02, 0x00, 0x0A }, try encodePubcomp(&buf, 10));

    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x40, 0x02, 0x00, 0x0A })).?.packet.puback);
    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x50, 0x02, 0x00, 0x0A })).?.packet.pubrec);
    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x62, 0x02, 0x00, 0x0A })).?.packet.pubrel);
    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x70, 0x02, 0x00, 0x0A })).?.packet.pubcomp);

    // PUBREL must carry flags 0b0010; PUBACK must carry 0.
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x60, 0x02, 0x00, 0x0A }));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x42, 0x02, 0x00, 0x0A }));
    // Zero packet id / wrong body length.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x40, 0x02, 0x00, 0x00 }));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x40, 0x03, 0x00, 0x0A, 0x00 }));
    try testing.expectError(error.InvalidPacketId, encodePuback(&buf, 0));
}

test "PINGREQ / PINGRESP / DISCONNECT: empty-body packets" {
    var buf: [2]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0x00 }, try encodePingreq(&buf));
    try testing.expectEqualSlices(u8, &.{ 0xD0, 0x00 }, try encodePingresp(&buf));
    try testing.expectEqualSlices(u8, &.{ 0xE0, 0x00 }, try encodeDisconnect(&buf));

    try testing.expect((try decode(&.{ 0xC0, 0x00 })).?.packet == .pingreq);
    try testing.expect((try decode(&.{ 0xD0, 0x00 })).?.packet == .pingresp);
    try testing.expect((try decode(&.{ 0xE0, 0x00 })).?.packet == .disconnect);

    // Non-empty body / nonzero flags are malformed.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0xD0, 0x01, 0x00 }));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0xC1, 0x00 }));
}

test "decode: unknown packet types and stream framing (null = need more)" {
    try testing.expectError(error.UnknownPacketType, decode(&.{ 0x00, 0x00 }));
    try testing.expectError(error.UnknownPacketType, decode(&.{ 0xF0, 0x00 }));

    try testing.expectEqual(null, try decode(&.{}));
    try testing.expectEqual(null, try decode(&.{0x20}));

    // Every strict prefix of a valid packet decodes to null, never an error.
    var buf: [64]u8 = undefined;
    const full = try encodeConnect(&buf, .{
        .client_id = "abc",
        .will = .{ .topic = "t", .message = "m" },
        .username = "u",
        .password = "p",
    });
    for (0..full.len) |cut| {
        try testing.expectEqual(null, try decode(full[0..cut]));
    }

    // Announced length longer than provided bytes: need more, not an error.
    try testing.expectEqual(null, try decode(&.{ 0x30, 0x7F, 0x00, 0x01 }));
}

test "decode: two packets back to back consume exactly one each" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += (try encodePuback(buf[pos..], 1)).len;
    pos += (try encodePingresp(buf[pos..])).len;
    const first = (try decode(buf[0..pos])).?;
    try testing.expectEqual(@as(u16, 1), first.packet.puback);
    try testing.expectEqual(@as(usize, 4), first.consumed);
    const second = (try decode(buf[first.consumed..pos])).?;
    try testing.expect(second.packet == .pingresp);
}

test "decode: 1000-iteration garbage sweep never panics" {
    var prng = std.Random.DefaultPrng.init(0x6d717474); // "mqtt"
    const random = prng.random();
    var buf: [96]u8 = undefined;
    for (0..1000) |_| {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        // Any outcome (packet, null, typed error) is fine — just no panic.
        _ = decode(buf[0..len]) catch continue;
    }
    // Same sweep with a plausible fixed header in front.
    for (0..1000) |i| {
        const len = random.uintAtMost(usize, buf.len - 2);
        buf[0] = @as(u8, @intCast((i % 14) + 1)) << 4 | @as(u8, @intCast(i % 16));
        buf[1] = @intCast(len);
        random.bytes(buf[2..][0..len]);
        _ = decode(buf[0 .. 2 + len]) catch continue;
    }
}
