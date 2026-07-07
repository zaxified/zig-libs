// SPDX-License-Identifier: MIT

//! BER (ITU-T X.690 Basic Encoding Rules) — exactly the subset SNMP uses.
//!
//! Definite-length tag-length-value only (short + long length form; the
//! indefinite form is rejected), single-byte tags (SNMP never uses
//! multi-byte/high tag numbers), and the SNMP type universe: INTEGER,
//! OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE, the RFC 2578
//! application types (IpAddress, Counter32, Gauge32/Unsigned32, TimeTicks,
//! Opaque, Counter64) and the RFC 3416 varbind exceptions (noSuchObject,
//! noSuchInstance, endOfMibView).
//!
//! Decoding is fully bounds-checked and never panics on malformed input —
//! every failure is a typed `DecodeError`. Encoding writes **backwards**
//! into a caller buffer (`Encoder`), which makes nested definite lengths
//! trivial: children are emitted first, then wrapped (`wrap`).

const std = @import("std");
const oid_mod = @import("oid.zig");

pub const Oid = oid_mod.Oid;

// ── tags ────────────────────────────────────────────────────────────────────

/// Tag bytes (class | constructed-bit | number) used by SNMP.
pub const tag = struct {
    // Universal class.
    pub const integer: u8 = 0x02;
    pub const octet_string: u8 = 0x04;
    pub const @"null": u8 = 0x05;
    pub const object_identifier: u8 = 0x06;
    pub const sequence: u8 = 0x30; // constructed

    // Application class — SMI types (RFC 2578).
    pub const ip_address: u8 = 0x40; // [APPLICATION 0]
    pub const counter32: u8 = 0x41; // [APPLICATION 1]
    pub const gauge32: u8 = 0x42; // [APPLICATION 2], also Unsigned32
    pub const time_ticks: u8 = 0x43; // [APPLICATION 3]
    pub const @"opaque": u8 = 0x44; // [APPLICATION 4]
    pub const counter64: u8 = 0x46; // [APPLICATION 6]

    // Context class, primitive — v2c varbind exceptions (RFC 3416).
    pub const no_such_object: u8 = 0x80;
    pub const no_such_instance: u8 = 0x81;
    pub const end_of_mib_view: u8 = 0x82;
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const DecodeError = error{
    /// A tag, length, or content ran past the end of the input.
    Truncated,
    /// Multi-byte (high) tag number — never used by SNMP.
    InvalidTag,
    /// Indefinite length (0x80) or otherwise malformed length octets.
    InvalidLength,
    /// Long-form length wider than 4 bytes.
    LengthOverflow,
    /// The element's tag is not the one required here (or is unknown).
    UnexpectedTag,
    /// Zero-length INTEGER content.
    InvalidInteger,
    /// INTEGER content wider than the target type.
    IntegerTooLarge,
    /// Negative INTEGER where an unsigned SNMP type was required.
    NegativeUnsigned,
    /// Malformed OBJECT IDENTIFIER content (empty, overlong 0x80 padding,
    /// or a subidentifier with the continuation bit running off the end).
    InvalidOid,
    /// More arcs than `oid.max_arcs`.
    OidTooLong,
    /// A subidentifier exceeds 32 bits.
    ArcTooLarge,
    /// Content octets malformed for the type (e.g. IpAddress not 4 bytes,
    /// non-empty NULL or exception value).
    InvalidValue,
    /// Extra bytes after a complete element where none are allowed.
    TrailingData,
};

pub const EncodeError = error{BufferTooSmall};

// ── decoding ────────────────────────────────────────────────────────────────

pub const Tlv = struct {
    tag: u8,
    content: []const u8,
};

/// Sequential TLV reader over a byte slice. All reads are bounds-checked.
pub const Decoder = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Decoder {
        return .{ .data = data };
    }

    pub fn done(d: *const Decoder) bool {
        return d.pos >= d.data.len;
    }

    /// Read the next TLV whatever its tag.
    pub fn any(d: *Decoder) DecodeError!Tlv {
        var i = d.pos;
        if (i >= d.data.len) return error.Truncated;
        const t = d.data[i];
        if (t & 0x1f == 0x1f) return error.InvalidTag;
        i += 1;

        if (i >= d.data.len) return error.Truncated;
        const l0 = d.data[i];
        i += 1;
        var content_len: usize = undefined;
        if (l0 < 0x80) {
            content_len = l0;
        } else if (l0 == 0x80) {
            return error.InvalidLength; // indefinite form
        } else {
            const n: usize = l0 & 0x7f;
            if (n > 4) return error.LengthOverflow;
            if (n > d.data.len - i) return error.Truncated;
            var v: u32 = 0;
            for (d.data[i..][0..n]) |b| v = (v << 8) | b;
            i += n;
            content_len = v;
        }
        if (content_len > d.data.len - i) return error.Truncated;
        const content = d.data[i..][0..content_len];
        d.pos = i + content_len;
        return .{ .tag = t, .content = content };
    }

    /// Read the next TLV and require its tag; returns the content octets.
    pub fn expect(d: *Decoder, required_tag: u8) DecodeError![]const u8 {
        const tlv = try d.any();
        if (tlv.tag != required_tag) return error.UnexpectedTag;
        return tlv.content;
    }
};

/// Two's-complement INTEGER content → i64. Redundant leading sign octets
/// (BER, unlike DER, permits them) are tolerated.
pub fn parseInteger(content: []const u8) DecodeError!i64 {
    if (content.len == 0) return error.InvalidInteger;
    var c = content;
    while (c.len > 1 and
        ((c[0] == 0x00 and c[1] & 0x80 == 0) or (c[0] == 0xff and c[1] & 0x80 != 0)))
    {
        c = c[1..];
    }
    if (c.len > 8) return error.IntegerTooLarge;
    var acc: u64 = if (c[0] & 0x80 != 0) std.math.maxInt(u64) else 0;
    for (c) |b| acc = (acc << 8) | b;
    return @bitCast(acc);
}

/// Non-negative INTEGER content → u64 (Counter64 & friends: up to 9 content
/// bytes when the leading octet is a 0x00 sign pad).
pub fn parseUnsigned(content: []const u8) DecodeError!u64 {
    if (content.len == 0) return error.InvalidInteger;
    if (content[0] & 0x80 != 0) return error.NegativeUnsigned;
    var c = content;
    while (c.len > 1 and c[0] == 0) c = c[1..];
    if (c.len > 8) return error.IntegerTooLarge;
    var acc: u64 = 0;
    for (c) |b| acc = (acc << 8) | b;
    return acc;
}

/// Non-negative INTEGER content → u32 (Counter32 / Gauge32 / TimeTicks).
pub fn parseUnsigned32(content: []const u8) DecodeError!u32 {
    const v = try parseUnsigned(content);
    return std.math.cast(u32, v) orelse error.IntegerTooLarge;
}

/// OBJECT IDENTIFIER content octets → `Oid`. The first octet unpacks to two
/// arcs (40*x + y); subsequent arcs are base-128 with the high bit as the
/// continuation flag. Overlong (leading 0x80) padding is rejected, arcs are
/// bounded to u32, and the arc count is bounded by `oid.max_arcs`.
pub fn parseOid(content: []const u8) DecodeError!Oid {
    if (content.len == 0) return error.InvalidOid;
    var o: Oid = .empty;
    var i: usize = 0;
    var first = true;
    while (i < content.len) {
        if (content[i] == 0x80) return error.InvalidOid; // overlong padding
        var arc: u32 = 0;
        while (true) {
            if (i >= content.len) return error.InvalidOid; // dangling continuation
            const b = content[i];
            i += 1;
            if (arc & 0xfe00_0000 != 0) return error.ArcTooLarge;
            arc = (arc << 7) | (b & 0x7f);
            if (b & 0x80 == 0) break;
        }
        if (first) {
            first = false;
            const x: u32 = if (arc < 40) 0 else if (arc < 80) 1 else 2;
            o.append(x) catch return error.OidTooLong;
            o.append(arc - 40 * x) catch return error.OidTooLong;
        } else {
            o.append(arc) catch return error.OidTooLong;
        }
    }
    return o;
}

// ── the SNMP value universe ─────────────────────────────────────────────────

/// A decoded SNMP varbind value. Slice payloads (`octet_string`, `opaque`)
/// borrow from the decoded message buffer.
pub const Value = union(enum) {
    integer: i64,
    octet_string: []const u8,
    null,
    oid: Oid,
    ip_address: [4]u8,
    counter32: u32,
    /// Gauge32 and Unsigned32 share this wire type ([APPLICATION 2]).
    gauge32: u32,
    time_ticks: u32,
    @"opaque": []const u8,
    counter64: u64,
    // v2c varbind exceptions (RFC 3416 §4.2).
    no_such_object,
    no_such_instance,
    end_of_mib_view,
};

fn expectEmpty(content: []const u8, comptime v: Value) DecodeError!Value {
    if (content.len != 0) return error.InvalidValue;
    return v;
}

/// Decode one TLV into a typed `Value`. Unknown tags are a typed error.
pub fn parseValue(tlv: Tlv) DecodeError!Value {
    return switch (tlv.tag) {
        tag.integer => .{ .integer = try parseInteger(tlv.content) },
        tag.octet_string => .{ .octet_string = tlv.content },
        tag.null => try expectEmpty(tlv.content, .null),
        tag.object_identifier => .{ .oid = try parseOid(tlv.content) },
        tag.ip_address => blk: {
            if (tlv.content.len != 4) break :blk error.InvalidValue;
            break :blk .{ .ip_address = tlv.content[0..4].* };
        },
        tag.counter32 => .{ .counter32 = try parseUnsigned32(tlv.content) },
        tag.gauge32 => .{ .gauge32 = try parseUnsigned32(tlv.content) },
        tag.time_ticks => .{ .time_ticks = try parseUnsigned32(tlv.content) },
        tag.@"opaque" => .{ .@"opaque" = tlv.content },
        tag.counter64 => .{ .counter64 = try parseUnsigned(tlv.content) },
        tag.no_such_object => try expectEmpty(tlv.content, .no_such_object),
        tag.no_such_instance => try expectEmpty(tlv.content, .no_such_instance),
        tag.end_of_mib_view => try expectEmpty(tlv.content, .end_of_mib_view),
        else => error.UnexpectedTag,
    };
}

// ── encoding ────────────────────────────────────────────────────────────────

/// Backwards BER writer. `init` starts at the end of `buf`; every `prepend*`
/// grows the encoding towards the front; `encoded()` is the finished slice.
/// For constructed types capture `mark = e.len()` before the children, emit
/// them, then `wrap(tag, mark)`.
pub const Encoder = struct {
    buf: []u8,
    pos: usize,

    pub fn init(buf: []u8) Encoder {
        return .{ .buf = buf, .pos = buf.len };
    }

    pub fn encoded(e: *const Encoder) []const u8 {
        return e.buf[e.pos..];
    }

    /// Number of bytes emitted so far.
    pub fn len(e: *const Encoder) usize {
        return e.buf.len - e.pos;
    }

    pub fn prependByte(e: *Encoder, b: u8) EncodeError!void {
        if (e.pos == 0) return error.BufferTooSmall;
        e.pos -= 1;
        e.buf[e.pos] = b;
    }

    pub fn prependBytes(e: *Encoder, bytes: []const u8) EncodeError!void {
        if (bytes.len > e.pos) return error.BufferTooSmall;
        e.pos -= bytes.len;
        @memcpy(e.buf[e.pos..][0..bytes.len], bytes);
    }

    /// Definite-length octets: short form below 128, else minimal long form.
    pub fn prependLength(e: *Encoder, content_len: usize) EncodeError!void {
        if (content_len < 0x80) return e.prependByte(@intCast(content_len));
        var n: u8 = 0;
        var x = content_len;
        while (x > 0) : (x >>= 8) {
            try e.prependByte(@truncate(x));
            n += 1;
        }
        try e.prependByte(0x80 | n);
    }

    /// Length octets, then the tag byte (call after the content is in).
    pub fn prependHeader(e: *Encoder, t: u8, content_len: usize) EncodeError!void {
        try e.prependLength(content_len);
        try e.prependByte(t);
    }

    /// A complete primitive TLV from raw content octets.
    pub fn prependTlv(e: *Encoder, t: u8, content: []const u8) EncodeError!void {
        try e.prependBytes(content);
        try e.prependHeader(t, content.len);
    }

    /// Close a constructed element whose children were emitted after `mark`
    /// (`mark` = the value of `len()` before the first child).
    pub fn wrap(e: *Encoder, t: u8, mark: usize) EncodeError!void {
        try e.prependHeader(t, e.len() - mark);
    }

    /// Minimal two's-complement INTEGER.
    pub fn prependInteger(e: *Encoder, t: u8, value: i64) EncodeError!void {
        var n: usize = 1;
        {
            var x = value;
            while (x < -128 or x > 127) : (x >>= 8) n += 1;
        }
        var x: u64 = @bitCast(value);
        for (0..n) |_| {
            try e.prependByte(@truncate(x));
            x >>= 8;
        }
        try e.prependHeader(t, n);
    }

    /// Minimal non-negative INTEGER-style content (Counter32, Gauge32,
    /// TimeTicks, Counter64): a 0x00 pad octet is prepended when the top
    /// content bit would read as a sign.
    pub fn prependUnsigned(e: *Encoder, t: u8, value: u64) EncodeError!void {
        var n: usize = 1;
        {
            var x = value;
            while (x > 0xff) : (x >>= 8) n += 1;
        }
        var x = value;
        for (0..n) |_| {
            try e.prependByte(@truncate(x));
            x >>= 8;
        }
        if (value >> @intCast(8 * (n - 1)) >= 0x80) {
            try e.prependByte(0x00);
            n += 1;
        }
        try e.prependHeader(t, n);
    }

    /// NULL-shaped TLV (also used for the v2c exception values).
    pub fn prependNull(e: *Encoder, t: u8) EncodeError!void {
        try e.prependByte(0x00);
        try e.prependByte(t);
    }

    /// OBJECT IDENTIFIER TLV. Requires at least two arcs with the X.660
    /// root constraints (already guaranteed for `Oid.parse` results).
    pub fn prependOid(e: *Encoder, o: *const Oid) (EncodeError || error{InvalidOid})!void {
        const arcs = o.slice();
        if (arcs.len < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40))
            return error.InvalidOid;
        const first = @as(u64, arcs[0]) * 40 + arcs[1];
        if (first > std.math.maxInt(u32)) return error.InvalidOid;
        const mark = e.len();
        var i = arcs.len;
        while (i > 2) {
            i -= 1;
            try e.prependArc(arcs[i]);
        }
        try e.prependArc(@intCast(first));
        try e.prependHeader(tag.object_identifier, e.len() - mark);
    }

    fn prependArc(e: *Encoder, arc: u32) EncodeError!void {
        try e.prependByte(@truncate(arc & 0x7f));
        var x = arc >> 7;
        while (x != 0) : (x >>= 7) {
            try e.prependByte(@intCast(0x80 | (x & 0x7f)));
        }
    }

    /// One typed varbind value as a TLV.
    pub fn prependValue(e: *Encoder, v: *const Value) (EncodeError || error{InvalidOid})!void {
        switch (v.*) {
            .integer => |x| try e.prependInteger(tag.integer, x),
            .octet_string => |s| try e.prependTlv(tag.octet_string, s),
            .null => try e.prependNull(tag.null),
            .oid => |*o| try e.prependOid(o),
            .ip_address => |a| try e.prependTlv(tag.ip_address, &a),
            .counter32 => |x| try e.prependUnsigned(tag.counter32, x),
            .gauge32 => |x| try e.prependUnsigned(tag.gauge32, x),
            .time_ticks => |x| try e.prependUnsigned(tag.time_ticks, x),
            .@"opaque" => |s| try e.prependTlv(tag.@"opaque", s),
            .counter64 => |x| try e.prependUnsigned(tag.counter64, x),
            .no_such_object => try e.prependNull(tag.no_such_object),
            .no_such_instance => try e.prependNull(tag.no_such_instance),
            .end_of_mib_view => try e.prependNull(tag.end_of_mib_view),
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn encodeValue(buf: []u8, v: Value) ![]const u8 {
    var e = Encoder.init(buf);
    try e.prependValue(&v);
    return e.encoded();
}

fn expectValueBytes(expected: []const u8, v: Value) !void {
    var buf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, expected, try encodeValue(&buf, v));
}

fn decodeOne(bytes: []const u8) !Value {
    var d = Decoder.init(bytes);
    const tlv = try d.any();
    if (!d.done()) return error.TrailingData;
    return parseValue(tlv);
}

test "INTEGER golden KATs" {
    try expectValueBytes(&.{ 0x02, 0x01, 0x05 }, .{ .integer = 5 });
    try expectValueBytes(&.{ 0x02, 0x01, 0x00 }, .{ .integer = 0 });
    try expectValueBytes(&.{ 0x02, 0x01, 0x7f }, .{ .integer = 127 });
    try expectValueBytes(&.{ 0x02, 0x02, 0x00, 0x80 }, .{ .integer = 128 });
    try expectValueBytes(&.{ 0x02, 0x02, 0x01, 0x00 }, .{ .integer = 256 });
    try expectValueBytes(&.{ 0x02, 0x01, 0xff }, .{ .integer = -1 });
    try expectValueBytes(&.{ 0x02, 0x01, 0x80 }, .{ .integer = -128 });
    try expectValueBytes(&.{ 0x02, 0x02, 0xff, 0x7f }, .{ .integer = -129 });
    try expectValueBytes(
        &.{ 0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        .{ .integer = std.math.maxInt(i64) },
    );
    try expectValueBytes(
        &.{ 0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .{ .integer = std.math.minInt(i64) },
    );

    // Decode side, including tolerated redundant sign padding.
    try testing.expectEqual(@as(i64, 5), (try decodeOne(&.{ 0x02, 0x01, 0x05 })).integer);
    try testing.expectEqual(@as(i64, -129), (try decodeOne(&.{ 0x02, 0x02, 0xff, 0x7f })).integer);
    try testing.expectEqual(@as(i64, 5), try parseInteger(&.{ 0x00, 0x00, 0x05 }));
    try testing.expectEqual(@as(i64, -1), try parseInteger(&.{ 0xff, 0xff, 0xff }));
    try testing.expectError(error.InvalidInteger, parseInteger(&.{}));
    try testing.expectError(
        error.IntegerTooLarge,
        parseInteger(&.{ 0x01, 0, 0, 0, 0, 0, 0, 0, 0 }),
    );
}

test "application types golden KATs" {
    try expectValueBytes(
        &.{ 0x40, 0x04, 0xc0, 0xa8, 0x01, 0x01 },
        .{ .ip_address = .{ 192, 168, 1, 1 } },
    );
    try expectValueBytes(&.{ 0x41, 0x01, 0x00 }, .{ .counter32 = 0 });
    try expectValueBytes(
        &.{ 0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff },
        .{ .counter32 = std.math.maxInt(u32) },
    );
    try expectValueBytes(&.{ 0x42, 0x02, 0x30, 0x39 }, .{ .gauge32 = 12345 });
    // TimeTicks 100494 (16 min 44.94 s) = 0x01888E.
    try expectValueBytes(&.{ 0x43, 0x03, 0x01, 0x88, 0x8e }, .{ .time_ticks = 100494 });
    try expectValueBytes(&.{ 0x44, 0x02, 0xde, 0xad }, .{ .@"opaque" = &.{ 0xde, 0xad } });
    try expectValueBytes(
        &.{ 0x46, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        .{ .counter64 = std.math.maxInt(u64) },
    );
    try expectValueBytes(&.{ 0x46, 0x01, 0x2a }, .{ .counter64 = 42 });

    try testing.expectEqual(
        @as(u64, std.math.maxInt(u64)),
        (try decodeOne(&.{ 0x46, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })).counter64,
    );
    try testing.expectEqual(
        @as(u32, 100494),
        (try decodeOne(&.{ 0x43, 0x03, 0x01, 0x88, 0x8e })).time_ticks,
    );
    try testing.expectEqual(
        [4]u8{ 192, 168, 1, 1 },
        (try decodeOne(&.{ 0x40, 0x04, 0xc0, 0xa8, 0x01, 0x01 })).ip_address,
    );
    try testing.expectError(error.InvalidValue, decodeOne(&.{ 0x40, 0x03, 1, 2, 3 }));
    try testing.expectError(error.NegativeUnsigned, decodeOne(&.{ 0x41, 0x01, 0x80 }));
    try testing.expectError(
        error.IntegerTooLarge,
        decodeOne(&.{ 0x41, 0x05, 0x01, 0, 0, 0, 0 }),
    );
}

test "OCTET STRING, NULL, and v2c exceptions" {
    try expectValueBytes(
        &.{ 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c' },
        .{ .octet_string = "public" },
    );
    try expectValueBytes(&.{ 0x04, 0x00 }, .{ .octet_string = "" });
    try expectValueBytes(&.{ 0x05, 0x00 }, .null);
    try expectValueBytes(&.{ 0x80, 0x00 }, .no_such_object);
    try expectValueBytes(&.{ 0x81, 0x00 }, .no_such_instance);
    try expectValueBytes(&.{ 0x82, 0x00 }, .end_of_mib_view);

    try testing.expectEqualStrings("public", (try decodeOne(&.{ 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c' })).octet_string);
    try testing.expectEqual(Value.no_such_object, try decodeOne(&.{ 0x80, 0x00 }));
    try testing.expectEqual(Value.end_of_mib_view, try decodeOne(&.{ 0x82, 0x00 }));
    try testing.expectError(error.InvalidValue, decodeOne(&.{ 0x05, 0x01, 0x00 }));
    try testing.expectError(error.InvalidValue, decodeOne(&.{ 0x80, 0x01, 0x00 }));
    try testing.expectError(error.UnexpectedTag, decodeOne(&.{ 0x83, 0x00 })); // unknown context tag
}

test "OID golden KATs" {
    // The canonical sysDescr.0 example.
    var buf: [64]u8 = undefined;
    const sys_descr = try Oid.parse("1.3.6.1.2.1.1.1.0");
    var e = Encoder.init(&buf);
    try e.prependOid(&sys_descr);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 },
        e.encoded(),
    );
    const back = try parseOid(e.encoded()[2..]);
    try testing.expect(back.eql(&sys_descr));

    // Multi-byte subidentifier: 8072 = 63*128 + 8 -> BF 08.
    const nsnmp = try Oid.parse("1.3.6.1.4.1.8072");
    e = Encoder.init(&buf);
    try e.prependOid(&nsnmp);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08 },
        e.encoded(),
    );
    try testing.expect((try parseOid(e.encoded()[2..])).eql(&nsnmp));

    // First subidentifier above 80: 2.999 -> 1079 -> 88 37 (X.690 example).
    const joint = try Oid.parse("2.999");
    e = Encoder.init(&buf);
    try e.prependOid(&joint);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x02, 0x88, 0x37 }, e.encoded());
    try testing.expect((try parseOid(&.{ 0x88, 0x37 })).eql(&joint));

    // Max u32 arc round-trips.
    const wide = try Oid.fromSlice(&.{ 1, 3, std.math.maxInt(u32) });
    e = Encoder.init(&buf);
    try e.prependOid(&wide);
    try testing.expect((try parseOid(e.encoded()[2..])).eql(&wide));
}

test "OID decode rejects hostile content" {
    try testing.expectError(error.InvalidOid, parseOid(&.{}));
    try testing.expectError(error.InvalidOid, parseOid(&.{ 0x2b, 0x86 })); // dangling continuation
    try testing.expectError(error.InvalidOid, parseOid(&.{ 0x2b, 0x80, 0x01 })); // overlong padding
    // Subidentifier > u32: six continuation bytes.
    try testing.expectError(
        error.ArcTooLarge,
        parseOid(&.{ 0x2b, 0x90, 0x80, 0x80, 0x80, 0x80, 0x00 }),
    );
    // Arc-count bound: max_arcs+ single-byte arcs.
    const many = [_]u8{0x01} ** (oid_mod.max_arcs + 1);
    try testing.expectError(error.OidTooLong, parseOid(&many));
    // Encoding a non-encodable Oid is a typed error.
    var buf: [16]u8 = undefined;
    var e = Encoder.init(&buf);
    const bad = try Oid.fromSlice(&.{5});
    try testing.expectError(error.InvalidOid, e.prependOid(&bad));
}

test "length forms: 127/128/255/256 boundary" {
    var content: [256]u8 = @splat(0xaa);
    var buf: [300]u8 = undefined;

    const cases = [_]struct { n: usize, header: []const u8 }{
        .{ .n = 127, .header = &.{ 0x04, 0x7f } },
        .{ .n = 128, .header = &.{ 0x04, 0x81, 0x80 } },
        .{ .n = 255, .header = &.{ 0x04, 0x81, 0xff } },
        .{ .n = 256, .header = &.{ 0x04, 0x82, 0x01, 0x00 } },
    };
    for (cases) |case| {
        var e = Encoder.init(&buf);
        try e.prependTlv(tag.octet_string, content[0..case.n]);
        const out = e.encoded();
        try testing.expectEqualSlices(u8, case.header, out[0..case.header.len]);
        try testing.expectEqual(case.header.len + case.n, out.len);

        var d = Decoder.init(out);
        const got = try d.expect(tag.octet_string);
        try testing.expectEqualSlices(u8, content[0..case.n], got);
        try testing.expect(d.done());
    }
}

test "malformed TLVs are typed errors, never panics" {
    var d = Decoder.init(&.{});
    try testing.expectError(error.Truncated, d.any());

    d = Decoder.init(&.{0x02}); // tag without length
    try testing.expectError(error.Truncated, d.any());

    d = Decoder.init(&.{ 0x02, 0x05, 0x01 }); // length overruns buffer
    try testing.expectError(error.Truncated, d.any());

    d = Decoder.init(&.{ 0x30, 0x80, 0x02, 0x01, 0x05 }); // indefinite length
    try testing.expectError(error.InvalidLength, d.any());

    d = Decoder.init(&.{ 0x02, 0x85, 0x01, 0x01, 0x01, 0x01, 0x01 }); // 5-byte length
    try testing.expectError(error.LengthOverflow, d.any());

    d = Decoder.init(&.{ 0x02, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00 }); // 4 GiB claimed
    try testing.expectError(error.Truncated, d.any());

    d = Decoder.init(&.{ 0x02, 0x82, 0x01 }); // truncated long-form length
    try testing.expectError(error.Truncated, d.any());

    d = Decoder.init(&.{ 0x1f, 0x01, 0x00 }); // multi-byte tag
    try testing.expectError(error.InvalidTag, d.any());

    d = Decoder.init(&.{ 0x04, 0x01, 0x41 });
    try testing.expectError(error.UnexpectedTag, d.expect(tag.integer));
}

test "full varbind SEQUENCE golden KAT" {
    // SEQUENCE { OID 1.3.6.1.2.1.1.3.0, TimeTicks 100494 }
    const expected = [_]u8{
        0x30, 0x0f,
        0x06, 0x08,
        0x2b, 0x06,
        0x01, 0x02,
        0x01, 0x01,
        0x03, 0x00,
        0x43, 0x03,
        0x01, 0x88,
        0x8e,
    };
    var buf: [32]u8 = undefined;
    var e = Encoder.init(&buf);
    const mark = e.len();
    const name = try Oid.parse("1.3.6.1.2.1.1.3.0");
    try e.prependValue(&.{ .time_ticks = 100494 });
    try e.prependOid(&name);
    try e.wrap(tag.sequence, mark);
    try testing.expectEqualSlices(u8, &expected, e.encoded());
}

test "encode into too-small buffer -> BufferTooSmall" {
    var buf: [4]u8 = undefined;
    var e = Encoder.init(&buf);
    try testing.expectError(
        error.BufferTooSmall,
        e.prependTlv(tag.octet_string, "this does not fit"),
    );
    var none: [0]u8 = undefined;
    e = Encoder.init(&none);
    try testing.expectError(error.BufferTooSmall, e.prependNull(tag.null));
}
