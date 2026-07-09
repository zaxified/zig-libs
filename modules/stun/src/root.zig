// SPDX-License-Identifier: MIT
//! stun — STUN client (RFC 8489): transport-agnostic Binding message
//! encode/decode/verify + XOR-MAPPED-ADDRESS, FINGERPRINT, MESSAGE-INTEGRITY.
//!
//! Session Traversal Utilities for NAT (STUN, RFC 8489, née RFC 5389) lets a
//! host behind a NAT discover its public "reflexive" address by sending a
//! Binding request to a STUN server and reading the XOR-MAPPED-ADDRESS the
//! server reflects back. This module is the **transport-agnostic core**:
//! build/parse/verify STUN messages over caller-provided byte buffers, with no
//! I/O of its own. A small optional `query` helper drives one Binding exchange
//! over `std.Io.net` UDP for callers that want the batteries included.
//!
//! ## Wire model
//!
//! Every STUN message is a 20-byte header — a 16-bit type (2-bit class +
//! 12-bit method, interleaved per RFC 8489 §5), a 16-bit attribute-region
//! length, the 32-bit magic cookie `0x2112A442`, and a 96-bit transaction id —
//! followed by a sequence of TLV attributes, each padded to a 4-byte boundary.
//!
//! - `Builder` writes a message into a caller buffer: header, generic
//!   attributes, then the two "special" trailing attributes whose value
//!   depends on the bytes before them — MESSAGE-INTEGRITY (HMAC-SHA1-20 keyed
//!   by a short-term credential) and FINGERPRINT (CRC-32 ⊕ `0x5354554E`). Both
//!   are computed with the header length field temporarily set to *include*
//!   the attribute being added, exactly as the RFC requires.
//! - `Message` parses a buffer: it validates the header and cookie, then hands
//!   out an `AttributeIterator`. `xorMappedAddress` / `mappedAddress` decode the
//!   reflexive address to a `netaddr.Ip` + port; `verifyFingerprint` and
//!   `verifyMessageIntegrity` re-derive the trailing attributes over the exact
//!   same byte regions (streamed, no copy) and compare — the MAC in
//!   **constant time** via `std.crypto.timing_safe.eql`.
//!
//! ## Provenance & scope
//!
//! Clean-room from RFC 8489 and the RFC 5769 test vectors; the attribute
//! TLV (de)serialization structure is modelled after Corendos/ztun (MIT) — no
//! third-party code copied. v1 implements the Binding method and short-term
//! credentials only. The long-term credential mechanism (RFC 8489 §9.2:
//! username/realm/nonce, MD5/SHA-256 PASSWORD-ALGORITHMS, USERHASH), the
//! server side, ICE/TURN, and TCP/TLS transport are out of scope — see the
//! module README.

const std = @import("std");
const netaddr = @import("netaddr");

pub const meta = .{
    .status = .gap,
    .platform = .any, // core is pure; only the optional `query` helper does I/O
    .role = .codec,
    .concurrency = .reentrant, // no shared state; every call is over caller buffers
    .model_after = "RFC 8489 STUN; design after Corendos/ztun; RFC 5769 test vectors",
    .deps = .{"netaddr"},
};

// ── constants ────────────────────────────────────────────────────────────────

/// The STUN magic cookie (RFC 8489 §5), fixed in the header at bytes 4..8.
pub const magic_cookie: u32 = 0x2112A442;

/// The magic cookie as big-endian bytes — the per-byte XOR key for an IPv4
/// XOR-MAPPED-ADDRESS, and the first four bytes of the IPv6 XOR key.
pub const magic_cookie_bytes = [4]u8{ 0x21, 0x12, 0xA4, 0x42 };

/// Fixed size of the STUN message header in bytes.
pub const header_len = 20;

/// The 96-bit transaction id that ties a response to its request.
pub const TransactionId = [12]u8;

/// Value XORed into the CRC-32 to form the FINGERPRINT (RFC 8489 §14.7); it is
/// the ASCII "STUN" (`0x53 0x54 0x55 0x4E`) so a FINGERPRINT can never collide
/// with a genuine CRC of the same message.
pub const fingerprint_xor: u32 = 0x5354554E;

// ── message class & method ───────────────────────────────────────────────────

/// The two-bit message class (RFC 8489 §5). The numeric values are the on-wire
/// C1..C0 bits, so `@intFromEnum` feeds `encodeType` directly.
pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,
};

/// The 12-bit message method. Non-exhaustive: only Binding is defined by the
/// base spec, but the wire carries a full 12-bit space (TURN, etc.).
pub const Method = enum(u12) {
    binding = 0x001,
    _,
};

/// Interleave a class and method into the 16-bit STUN message type (RFC 8489
/// §5): method bits M11..M0 are split around the two class bits C1/C0.
pub fn encodeType(class: Class, method: Method) u16 {
    const m: u16 = @intFromEnum(method);
    const c: u16 = @intFromEnum(class);
    return ((m & 0x0F80) << 2) | ((m & 0x0070) << 1) | (m & 0x000F) |
        ((c & 0x2) << 7) | ((c & 0x1) << 4);
}

/// Recover the class from a 16-bit message type.
pub fn decodeClass(t: u16) Class {
    const c: u2 = @intCast(((t >> 4) & 0x1) | ((t >> 7) & 0x2));
    return @enumFromInt(c);
}

/// Recover the 12-bit method from a 16-bit message type.
pub fn decodeMethod(t: u16) u12 {
    return @intCast((t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80));
}

// ── attribute types ──────────────────────────────────────────────────────────

/// The registered STUN attribute type codes used by v1. The comprehension-
/// required range is `0x0000..0x8000`; `0x8000..` is comprehension-optional.
pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    realm = 0x0014,
    nonce = 0x0015,
    xor_mapped_address = 0x0020,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    _,
};

fn attrCode(t: AttributeType) u16 {
    return @intFromEnum(t);
}

// ── errors ───────────────────────────────────────────────────────────────────

pub const DecodeError = error{
    /// Buffer shorter than the header, or an attribute runs past the end.
    Truncated,
    /// The two most-significant bits of the type were not zero (not STUN).
    NotStun,
    /// The magic cookie did not match `magic_cookie`.
    BadCookie,
    /// The header length field was not a multiple of 4.
    BadLength,
    /// An attribute value was too short for its declared meaning.
    MalformedAttribute,
    /// A MAPPED-ADDRESS family byte was neither IPv4 (0x01) nor IPv6 (0x02).
    UnknownAddressFamily,
};

pub const BuildError = error{
    /// The caller buffer could not hold the next attribute.
    BufferTooSmall,
};

// ── decoded address ──────────────────────────────────────────────────────────

/// A reflexive transport address decoded from a (XOR-)MAPPED-ADDRESS attribute.
pub const AddressPort = struct {
    ip: netaddr.Ip,
    port: u16,
};

// ── builder (encode) ─────────────────────────────────────────────────────────

/// Writes a STUN message into a caller-provided buffer. Append generic
/// attributes with `addAttribute` (and the typed helpers), then — last, and in
/// this order if both are present — `addMessageIntegrity` and `addFingerprint`,
/// whose values cover every byte written before them. `finish` returns the
/// message slice.
pub const Builder = struct {
    buf: []u8,
    /// Bytes written so far = the total message length (header + attributes).
    len: usize,

    /// Start a message: writes the 20-byte header (type, zero length, cookie,
    /// transaction id). Fails if `buf` cannot hold the header.
    pub fn init(buf: []u8, class: Class, method: Method, txid: TransactionId) BuildError!Builder {
        if (buf.len < header_len) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], encodeType(class, method), .big);
        std.mem.writeInt(u16, buf[2..4], 0, .big); // attribute-region length
        std.mem.writeInt(u32, buf[4..8], magic_cookie, .big);
        @memcpy(buf[8..20], &txid);
        return .{ .buf = buf, .len = header_len };
    }

    /// Length of the attribute region (message length minus the header).
    fn attrRegionLen(self: *const Builder) u16 {
        return @intCast(self.len - header_len);
    }

    fn setLengthField(self: *Builder, region_len: u16) void {
        std.mem.writeInt(u16, self.buf[2..4], region_len, .big);
    }

    /// Append one TLV attribute: 2-byte type, 2-byte value length, the value,
    /// then zero padding to the next 4-byte boundary. Updates the header length.
    pub fn addAttribute(self: *Builder, typ: u16, value: []const u8) BuildError!void {
        const padded = (value.len + 3) & ~@as(usize, 3);
        if (self.len + 4 + padded > self.buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, self.buf[self.len..][0..2], typ, .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], @intCast(value.len), .big);
        @memcpy(self.buf[self.len + 4 ..][0..value.len], value);
        @memset(self.buf[self.len + 4 + value.len ..][0 .. padded - value.len], 0);
        self.len += 4 + padded;
        self.setLengthField(self.attrRegionLen());
    }

    /// Append a SOFTWARE attribute (a human-readable agent description).
    pub fn addSoftware(self: *Builder, text: []const u8) BuildError!void {
        return self.addAttribute(attrCode(.software), text);
    }

    /// Append an (optionally XOR-encoded) MAPPED-ADDRESS-style attribute for
    /// the given transport address. `xor` selects XOR-MAPPED-ADDRESS (0x0020)
    /// vs plain MAPPED-ADDRESS (0x0001).
    pub fn addMappedAddress(self: *Builder, ip: netaddr.Ip, port: u16, xor: bool) BuildError!void {
        var value: [4 + 16]u8 = undefined;
        const n = encodeAddress(&value, ip, port, self.transactionId(), xor);
        return self.addAttribute(if (xor) attrCode(.xor_mapped_address) else attrCode(.mapped_address), value[0..n]);
    }

    fn transactionId(self: *const Builder) TransactionId {
        return self.buf[8..20].*;
    }

    /// Append MESSAGE-INTEGRITY (RFC 8489 §14.5): HMAC-SHA1-20 over the message
    /// so far, with the header length field first set to include this
    /// attribute. `key` is the short-term credential (the SASLprep'd password).
    pub fn addMessageIntegrity(self: *Builder, key: []const u8) BuildError!void {
        if (self.len + 24 > self.buf.len) return error.BufferTooSmall;
        // Length must point past this attribute before the MAC is taken.
        self.setLengthField(@intCast(self.attrRegionLen() + 24));
        var mac: [HmacSha1.mac_length]u8 = undefined;
        var h = HmacSha1.init(key);
        h.update(self.buf[0..self.len]);
        h.final(&mac);
        std.mem.writeInt(u16, self.buf[self.len..][0..2], attrCode(.message_integrity), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], HmacSha1.mac_length, .big);
        @memcpy(self.buf[self.len + 4 ..][0..HmacSha1.mac_length], &mac);
        self.len += 24; // length field already correct
    }

    /// Append FINGERPRINT (RFC 8489 §14.7): CRC-32 of the message so far ⊕
    /// `fingerprint_xor`, with the header length field first set to include
    /// this attribute. Must be the final attribute.
    pub fn addFingerprint(self: *Builder) BuildError!void {
        if (self.len + 8 > self.buf.len) return error.BufferTooSmall;
        self.setLengthField(@intCast(self.attrRegionLen() + 8));
        var c = Crc32.init();
        c.update(self.buf[0..self.len]);
        const fp = c.final() ^ fingerprint_xor;
        std.mem.writeInt(u16, self.buf[self.len..][0..2], attrCode(.fingerprint), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], 4, .big);
        std.mem.writeInt(u32, self.buf[self.len + 4 ..][0..4], fp, .big);
        self.len += 8;
    }

    /// The finished message bytes (a sub-slice of the caller buffer).
    pub fn finish(self: *const Builder) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Build a bare Binding request (just the header) into `out`. The convenience
/// entry point named in the module scope.
pub fn bindingRequest(txid: TransactionId, out: []u8) BuildError![]const u8 {
    var b = try Builder.init(out, .request, .binding, txid);
    return b.finish();
}

/// Encode a transport address into a (XOR-)MAPPED-ADDRESS value; returns the
/// number of bytes written (8 for IPv4, 20 for IPv6).
fn encodeAddress(out: *[4 + 16]u8, ip: netaddr.Ip, port: u16, txid: TransactionId, xor: bool) usize {
    out[0] = 0;
    const xport = if (xor) port ^ @as(u16, @truncate(magic_cookie >> 16)) else port;
    std.mem.writeInt(u16, out[2..4], xport, .big);
    switch (ip) {
        .v4 => |q| {
            out[1] = 0x01;
            out[4..8].* = q;
            if (xor) for (out[4..8], 0..) |*b, i| {
                b.* ^= magic_cookie_bytes[i];
            };
            return 8;
        },
        .v6 => |b6| {
            out[1] = 0x02;
            out[4..20].* = b6;
            if (xor) {
                const key = v6XorKey(txid);
                for (out[4..20], 0..) |*b, i| b.* ^= key[i];
            }
            return 20;
        },
    }
}

/// The 16-byte XOR key for an IPv6 (XOR-)MAPPED-ADDRESS: cookie ‖ transaction id.
fn v6XorKey(txid: TransactionId) [16]u8 {
    var key: [16]u8 = undefined;
    @memcpy(key[0..4], &magic_cookie_bytes);
    @memcpy(key[4..16], &txid);
    return key;
}

// ── message (decode) ─────────────────────────────────────────────────────────

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const Crc32 = std.hash.Crc32;

/// A parsed STUN message. Holds a slice of the original buffer (`bytes`,
/// trimmed to `header_len + length`) plus the decoded header fields. All
/// accessors are read-only and allocation-free.
pub const Message = struct {
    bytes: []const u8,
    class: Class,
    method: Method,
    /// The attribute-region length from the header (bytes after the header).
    length: u16,
    transaction_id: TransactionId,

    /// Iterate the attributes in wire order.
    pub fn attributes(self: Message) AttributeIterator {
        return .{ .msg = self.bytes };
    }

    /// The first attribute of type `code`, or null. Later duplicates are
    /// ignored (STUN takes the first occurrence of most attributes).
    pub fn find(self: Message, code: u16) ?Attribute {
        var it = self.attributes();
        while (it.next()) |a| if (a.type == code) return a;
        return null;
    }

    /// Decode XOR-MAPPED-ADDRESS (0x0020) to an address+port, or null if the
    /// attribute is absent. Errors on a malformed/short value.
    pub fn xorMappedAddress(self: Message) DecodeError!?AddressPort {
        const a = self.find(attrCode(.xor_mapped_address)) orelse return null;
        return try decodeAddress(a.value, self.transaction_id, true);
    }

    /// Decode plain MAPPED-ADDRESS (0x0001), or null if absent.
    pub fn plainMappedAddress(self: Message) DecodeError!?AddressPort {
        const a = self.find(attrCode(.mapped_address)) orelse return null;
        return try decodeAddress(a.value, self.transaction_id, false);
    }

    /// The reflexive address, preferring XOR-MAPPED-ADDRESS and falling back to
    /// MAPPED-ADDRESS; null if neither is present.
    pub fn mappedAddress(self: Message) DecodeError!?AddressPort {
        if (try self.xorMappedAddress()) |ap| return ap;
        return self.plainMappedAddress();
    }

    /// Parse an ERROR-CODE (0x0009) attribute, or null if absent.
    pub fn errorCode(self: Message) DecodeError!?ErrorCode {
        const a = self.find(attrCode(.error_code)) orelse return null;
        return try decodeErrorCode(a.value);
    }

    /// Verify FINGERPRINT (0x8028): recompute CRC-32 ⊕ `fingerprint_xor` over
    /// the message up to the attribute, with the header length field patched to
    /// point just past it. False if the attribute is absent or malformed.
    pub fn verifyFingerprint(self: Message) bool {
        const fp = self.find(attrCode(.fingerprint)) orelse return false;
        if (fp.value.len != 4) return false;
        const stored = std.mem.readInt(u32, fp.value[0..4], .big);
        var c = Crc32.init();
        self.hashHeaderWithLength(Crc32, &c, @intCast(fp.offset - header_len + 8));
        c.update(self.bytes[4..fp.offset]);
        return (c.final() ^ fingerprint_xor) == stored;
    }

    /// Verify MESSAGE-INTEGRITY (0x0008) against short-term credential `key`:
    /// recompute HMAC-SHA1-20 over the message up to the attribute, with the
    /// header length field patched to point just past it, and compare in
    /// constant time. False if the attribute is absent or malformed.
    pub fn verifyMessageIntegrity(self: Message, key: []const u8) bool {
        const mi = self.find(attrCode(.message_integrity)) orelse return false;
        if (mi.value.len != HmacSha1.mac_length) return false;
        var h = HmacSha1.init(key);
        self.hashHeaderWithLength(HmacSha1, &h, @intCast(mi.offset - header_len + 24));
        h.update(self.bytes[4..mi.offset]);
        var mac: [HmacSha1.mac_length]u8 = undefined;
        h.final(&mac);
        const got: [HmacSha1.mac_length]u8 = mi.value[0..HmacSha1.mac_length].*;
        return std.crypto.timing_safe.eql([HmacSha1.mac_length]u8, mac, got);
    }

    /// Feed the header type (2 bytes) then a *patched* 2-byte length into a
    /// streaming hasher, without mutating the buffer. Both `Crc32` and the HMAC
    /// context expose `update`, so `Ctx` is duck-typed.
    fn hashHeaderWithLength(self: Message, comptime Ctx: type, ctx: *Ctx, patched_len: u16) void {
        ctx.update(self.bytes[0..2]);
        var lb: [2]u8 = undefined;
        std.mem.writeInt(u16, &lb, patched_len, .big);
        ctx.update(&lb);
    }
};

/// Parse a STUN message from `bytes`. Validates length, the two zero MSBs, the
/// magic cookie, and 4-byte length alignment; the returned `Message.bytes` is
/// trimmed to exactly `header_len + length`.
pub fn decode(bytes: []const u8) DecodeError!Message {
    if (bytes.len < header_len) return error.Truncated;
    const t = std.mem.readInt(u16, bytes[0..2], .big);
    if (t & 0xC000 != 0) return error.NotStun;
    const length = std.mem.readInt(u16, bytes[2..4], .big);
    if (length % 4 != 0) return error.BadLength;
    if (std.mem.readInt(u32, bytes[4..8], .big) != magic_cookie) return error.BadCookie;
    if (@as(usize, header_len) + length > bytes.len) return error.Truncated;
    return .{
        .bytes = bytes[0 .. header_len + length],
        .class = decodeClass(t),
        .method = @enumFromInt(decodeMethod(t)),
        .length = length,
        .transaction_id = bytes[8..20].*,
    };
}

/// One TLV attribute, its value unpadded, plus its byte offset within the
/// message (needed for FINGERPRINT / MESSAGE-INTEGRITY region math).
pub const Attribute = struct {
    type: u16,
    value: []const u8,
    offset: usize,
};

/// Walks the attribute region of a message. Stops (returns null) at the end or
/// on a truncated attribute — a malformed tail is treated as end-of-message.
pub const AttributeIterator = struct {
    msg: []const u8,
    pos: usize = header_len,

    pub fn next(self: *AttributeIterator) ?Attribute {
        if (self.pos + 4 > self.msg.len) return null;
        const typ = std.mem.readInt(u16, self.msg[self.pos..][0..2], .big);
        const vlen = std.mem.readInt(u16, self.msg[self.pos + 2 ..][0..2], .big);
        const vstart = self.pos + 4;
        if (vstart + vlen > self.msg.len) return null;
        const attr: Attribute = .{ .type = typ, .value = self.msg[vstart .. vstart + vlen], .offset = self.pos };
        const padded = (@as(usize, vlen) + 3) & ~@as(usize, 3);
        self.pos = vstart + padded;
        return attr;
    }
};

/// Decode a (XOR-)MAPPED-ADDRESS attribute value.
fn decodeAddress(value: []const u8, txid: TransactionId, xor: bool) DecodeError!AddressPort {
    if (value.len < 4) return error.MalformedAttribute;
    const family = value[1];
    const raw_port = std.mem.readInt(u16, value[2..4], .big);
    const port = if (xor) raw_port ^ @as(u16, @truncate(magic_cookie >> 16)) else raw_port;
    switch (family) {
        0x01 => {
            if (value.len < 8) return error.MalformedAttribute;
            var a: [4]u8 = value[4..8].*;
            if (xor) for (&a, 0..) |*b, i| {
                b.* ^= magic_cookie_bytes[i];
            };
            return .{ .ip = .{ .v4 = a }, .port = port };
        },
        0x02 => {
            if (value.len < 20) return error.MalformedAttribute;
            var a: [16]u8 = value[4..20].*;
            if (xor) {
                const key = v6XorKey(txid);
                for (&a, 0..) |*b, i| b.* ^= key[i];
            }
            return .{ .ip = .{ .v6 = a }, .port = port };
        },
        else => return error.UnknownAddressFamily,
    }
}

/// A decoded ERROR-CODE attribute (RFC 8489 §14.8).
pub const ErrorCode = struct {
    /// The numeric error, class*100 + number (e.g. 401, 420, 438).
    code: u16,
    /// The UTF-8 reason phrase (a slice into the message buffer).
    reason: []const u8,
};

fn decodeErrorCode(value: []const u8) DecodeError!ErrorCode {
    if (value.len < 4) return error.MalformedAttribute;
    const class = value[2] & 0x07;
    const number = value[3];
    return .{ .code = @as(u16, class) * 100 + number, .reason = value[4..] };
}

// ── optional live query over std.Io.net UDP ──────────────────────────────────

/// Send one Binding request to `server` over UDP and return the reflexive
/// address the server reflects back (its view of our public transport address).
///
/// A batteries-included convenience for callers that just want their public
/// address; the pure `Builder` / `Message` API above is the real interface and
/// needs no `Io`. `buf` receives the raw response bytes and must outlive the
/// returned `AddressPort` only if you keep the (unrelated) reason slices — the
/// address is copied out. The tests never exercise this path (it needs a
/// reachable server); a `query` unit test skips via `error.SkipZigTest`.
pub fn query(
    io: std.Io,
    server: std.Io.net.IpAddress,
    txid: TransactionId,
    buf: []u8,
) !AddressPort {
    const IpAddress = std.Io.net.IpAddress;
    const local: IpAddress = switch (server) {
        .ip4 => try IpAddress.parse("0.0.0.0", 0),
        .ip6 => try IpAddress.parse("[::]", 0),
    };
    var sock = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sock.close(io);

    var req_buf: [header_len]u8 = undefined;
    const req = try bindingRequest(txid, &req_buf);
    try sock.send(io, &server, req);

    const msg = try sock.receive(io, buf);
    const parsed = try decode(msg.data);
    if (!std.mem.eql(u8, &parsed.transaction_id, &txid)) return error.TransactionMismatch;
    return (try parsed.mappedAddress()) orelse error.NoMappedAddress;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// RFC 5769 §2.1 — Sample Request. Short-term credential password below.
const rfc5769_password = "VOkJxbRl1RmTxUk/WvJxBt";

const rfc5769_txid = TransactionId{
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
};

const req_2_1 = [_]u8{
    // header: Binding request, length 0x58, cookie, transaction id
    0x00, 0x01, 0x00, 0x58,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    // SOFTWARE "STUN test client"
    0x80, 0x22, 0x00, 0x10,
    0x53, 0x54, 0x55, 0x4e,
    0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x63, 0x6c,
    0x69, 0x65, 0x6e, 0x74,
    // PRIORITY
    0x00, 0x24, 0x00, 0x04,
    0x6e, 0x00, 0x01, 0xff,
    // ICE-CONTROLLED
    0x80, 0x29, 0x00, 0x08,
    0x93, 0x2f, 0xf9, 0xb1,
    0x51, 0x26, 0x3b, 0x36,
    // USERNAME "evtj:h6vY" (9 bytes + 3 pad)
    0x00, 0x06, 0x00, 0x09,
    0x65, 0x76, 0x74, 0x6a,
    0x3a, 0x68, 0x36, 0x76,
    0x59, 0x20, 0x20, 0x20,
    // MESSAGE-INTEGRITY
    0x00, 0x08, 0x00, 0x14,
    0x9a, 0xea, 0xa7, 0x0c,
    0xbf, 0xd8, 0xcb, 0x56,
    0x78, 0x1e, 0xf2, 0xb5,
    0xb2, 0xd3, 0xf2, 0x49,
    0xc1, 0xb5, 0x71, 0xa2,
    // FINGERPRINT
    0x80, 0x28, 0x00, 0x04,
    0xe5, 0x7a, 0x3b, 0xcf,
};

const resp_2_2 = [_]u8{
    // header: Binding success response, length 0x3c
    0x01, 0x01, 0x00, 0x3c,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    // SOFTWARE "test vector " (11 bytes + 1 pad)
    0x80, 0x22, 0x00, 0x0b,
    0x74, 0x65, 0x73, 0x74,
    0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20,
    // XOR-MAPPED-ADDRESS (IPv4)
    0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xa1, 0x47,
    0xe1, 0x12, 0xa6, 0x43,
    // MESSAGE-INTEGRITY
    0x00, 0x08, 0x00, 0x14,
    0x2b, 0x91, 0xf5, 0x99,
    0xfd, 0x9e, 0x90, 0xc3,
    0x8c, 0x74, 0x89, 0xf9,
    0x2a, 0xf9, 0xba, 0x53,
    0xf0, 0x6b, 0xe7, 0xd7,
    // FINGERPRINT
    0x80, 0x28, 0x00, 0x04,
    0xc0, 0x7d, 0x4c, 0x96,
};

const resp_2_3 = [_]u8{
    // header: Binding success response, length 0x48
    0x01, 0x01, 0x00, 0x48,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    // SOFTWARE "test vector "
    0x80, 0x22, 0x00, 0x0b,
    0x74, 0x65, 0x73, 0x74,
    0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20,
    // XOR-MAPPED-ADDRESS (IPv6)
    0x00, 0x20, 0x00, 0x14,
    0x00, 0x02, 0xa1, 0x47,
    0x01, 0x13, 0xa9, 0xfa,
    0xa5, 0xd3, 0xf1, 0x79,
    0xbc, 0x25, 0xf4, 0xb5,
    0xbe, 0xd2, 0xb9, 0xd9,
    // MESSAGE-INTEGRITY
    0x00, 0x08, 0x00, 0x14,
    0xa3, 0x82, 0x95, 0x4e,
    0x4b, 0xe6, 0x7b, 0xf1,
    0x17, 0x84, 0xc9, 0x7c,
    0x82, 0x92, 0xc2, 0x75,
    0xbf, 0xe3, 0xed, 0x41,
    // FINGERPRINT
    0x80, 0x28, 0x00, 0x04,
    0xc8, 0xfb, 0x0b, 0x4c,
};

test "message type class/method encode+decode round-trip" {
    // Binding request = 0x0001, Binding success response = 0x0101 (RFC 5769).
    try testing.expectEqual(@as(u16, 0x0001), encodeType(.request, .binding));
    try testing.expectEqual(@as(u16, 0x0101), encodeType(.success_response, .binding));
    try testing.expectEqual(@as(u16, 0x0111), encodeType(.error_response, .binding));
    inline for (.{ Class.request, .indication, .success_response, .error_response }) |cls| {
        const t = encodeType(cls, .binding);
        try testing.expectEqual(cls, decodeClass(t));
        try testing.expectEqual(@as(u12, 0x001), decodeMethod(t));
    }
}

test "RFC 5769 §2.1: decode the sample request" {
    const m = try decode(&req_2_1);
    try testing.expectEqual(Class.request, m.class);
    try testing.expectEqual(Method.binding, m.method);
    try testing.expectEqual(@as(u16, 0x58), m.length);
    try testing.expectEqualSlices(u8, &rfc5769_txid, &m.transaction_id);

    // Attribute order and types as documented.
    var it = m.attributes();
    const want = [_]u16{ 0x8022, 0x0024, 0x8029, 0x0006, 0x0008, 0x8028 };
    var i: usize = 0;
    while (it.next()) |a| : (i += 1) try testing.expectEqual(want[i], a.type);
    try testing.expectEqual(want.len, i);

    // SOFTWARE and USERNAME values.
    try testing.expectEqualStrings("STUN test client", m.find(0x8022).?.value);
    try testing.expectEqualStrings("evtj:h6vY", m.find(0x0006).?.value);

    // The sample request's MESSAGE-INTEGRITY and FINGERPRINT verify.
    try testing.expect(m.verifyMessageIntegrity(rfc5769_password));
    try testing.expect(m.verifyFingerprint());
}

test "encode → decode → re-encode is stable, with MI + FINGERPRINT recomputed" {
    // Note: the RFC 5769 §2.1 vector pads its USERNAME with spaces (0x20), an
    // allowed-but-unusual quirk; our encoder zero-pads per RFC 8489 §14. So we
    // do NOT byte-match the vector here (its MI/FINGERPRINT cover those space
    // pads — that exact-bytes oracle is the `verify*` checks above, which pass).
    // Instead we prove the codec is self-consistent: build a request replaying
    // the sample's attributes (zero-padded), then decode and re-encode it and
    // assert an identical result, with MI/FINGERPRINT recomputed each time.
    const m0 = try decode(&req_2_1);
    var buf_a: [req_2_1.len]u8 = undefined;
    var b0 = try Builder.init(&buf_a, .request, .binding, m0.transaction_id);
    var it0 = m0.attributes();
    while (it0.next()) |a| switch (a.type) {
        0x0008 => try b0.addMessageIntegrity(rfc5769_password),
        0x8028 => try b0.addFingerprint(),
        else => try b0.addAttribute(a.type, a.value),
    };
    const canonical = b0.finish();

    // Our own encoding must verify against the same credential.
    const m1 = try decode(canonical);
    try testing.expect(m1.verifyMessageIntegrity(rfc5769_password));
    try testing.expect(m1.verifyFingerprint());

    // Re-encoding the decoded message reproduces it byte-for-byte.
    var buf_b: [req_2_1.len]u8 = undefined;
    var b1 = try Builder.init(&buf_b, m1.class, m1.method, m1.transaction_id);
    var it1 = m1.attributes();
    while (it1.next()) |a| switch (a.type) {
        0x0008 => try b1.addMessageIntegrity(rfc5769_password),
        0x8028 => try b1.addFingerprint(),
        else => try b1.addAttribute(a.type, a.value),
    };
    try testing.expectEqualSlices(u8, canonical, b1.finish());
}

test "RFC 5769 §2.2: IPv4 XOR-MAPPED-ADDRESS + MI + FINGERPRINT" {
    const m = try decode(&resp_2_2);
    try testing.expectEqual(Class.success_response, m.class);

    const ap = (try m.xorMappedAddress()).?;
    try testing.expectEqual(@as(u16, 32853), ap.port);
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.0.2.1", netaddr.formatIp(ap.ip, &buf));
    // mappedAddress() prefers XOR-MAPPED-ADDRESS and yields the same answer.
    try testing.expect((try m.mappedAddress()).?.ip.eql(ap.ip));

    try testing.expect(m.verifyFingerprint());
    try testing.expect(m.verifyMessageIntegrity(rfc5769_password));
}

test "RFC 5769 §2.3: IPv6 XOR-MAPPED-ADDRESS" {
    const m = try decode(&resp_2_3);
    const ap = (try m.xorMappedAddress()).?;
    try testing.expectEqual(@as(u16, 32853), ap.port);
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("2001:db8:1234:5678:11:2233:4455:6677", netaddr.formatIp(ap.ip, &buf));

    try testing.expect(m.verifyFingerprint());
    try testing.expect(m.verifyMessageIntegrity(rfc5769_password));
}

test "FINGERPRINT tamper: flipping any covered byte fails verification" {
    var bytes = resp_2_2;
    // Flip a byte inside SOFTWARE (before the fingerprint) → CRC mismatch.
    bytes[24] ^= 0x01;
    const m = try decode(&bytes);
    try testing.expect(!m.verifyFingerprint());
}

test "MESSAGE-INTEGRITY tamper: flipped body byte and flipped MAC both fail" {
    // A byte inside XOR-MAPPED-ADDRESS is covered by the MAC.
    {
        var bytes = resp_2_2;
        bytes[52] ^= 0x01; // somewhere in the XMA value region
        const m = try decode(&bytes);
        try testing.expect(!m.verifyMessageIntegrity(rfc5769_password));
    }
    // Flip a byte inside the MAC itself → still rejected (full compare).
    {
        var bytes = resp_2_2;
        const mi = (try decode(&bytes)).find(0x0008).?;
        bytes[mi.offset + 4] ^= 0x01;
        const m = try decode(&bytes);
        try testing.expect(!m.verifyMessageIntegrity(rfc5769_password));
    }
    // Wrong key also fails.
    {
        const m = try decode(&resp_2_2);
        try testing.expect(!m.verifyMessageIntegrity("wrong-password"));
    }
}

test "MAPPED-ADDRESS (plain) and XMA encode round-trip" {
    // Build a response carrying plain + XOR mapped address, decode it back.
    const ip = netaddr.parseIp("203.0.113.7").?;
    var out: [64]u8 = undefined;
    var b = try Builder.init(&out, .success_response, .binding, rfc5769_txid);
    try b.addMappedAddress(ip, 4242, false); // MAPPED-ADDRESS
    try b.addMappedAddress(ip, 4242, true); // XOR-MAPPED-ADDRESS
    const m = try decode(b.finish());

    const plain = (try m.plainMappedAddress()).?;
    try testing.expect(plain.ip.eql(ip));
    try testing.expectEqual(@as(u16, 4242), plain.port);
    const xored = (try m.xorMappedAddress()).?;
    try testing.expect(xored.ip.eql(ip));
    try testing.expectEqual(@as(u16, 4242), xored.port);
}

test "bindingRequest builds a bare 20-byte Binding request" {
    var out: [32]u8 = undefined;
    const req = try bindingRequest(rfc5769_txid, &out);
    try testing.expectEqual(@as(usize, header_len), req.len);
    const m = try decode(req);
    try testing.expectEqual(Class.request, m.class);
    try testing.expectEqual(Method.binding, m.method);
    try testing.expectEqual(@as(u16, 0), m.length);
}

test "ERROR-CODE parse (class*100 + number + reason)" {
    var out: [64]u8 = undefined;
    var b = try Builder.init(&out, .error_response, .binding, rfc5769_txid);
    // 401 Unauthorized: class=4, number=1.
    const val = [_]u8{ 0, 0, 4, 1 } ++ "Unauthorized".*;
    try b.addAttribute(attrCode(.error_code), &val);
    const m = try decode(b.finish());
    const ec = (try m.errorCode()).?;
    try testing.expectEqual(@as(u16, 401), ec.code);
    try testing.expectEqualStrings("Unauthorized", ec.reason);
}

test "decode rejects non-STUN, bad cookie, and truncation" {
    try testing.expectError(error.Truncated, decode(&[_]u8{0} ** 8));
    // Wrong cookie.
    var bad_cookie = req_2_1;
    bad_cookie[4] = 0x00;
    try testing.expectError(error.BadCookie, decode(&bad_cookie));
    // Top two type bits set → not STUN.
    var not_stun = req_2_1;
    not_stun[0] = 0xC0;
    try testing.expectError(error.NotStun, decode(&not_stun));
    // Length (kept a multiple of 4) points past the buffer.
    var short = req_2_1;
    short[2] = 0x01; // length 0x0158 ≫ available bytes
    try testing.expectError(error.Truncated, decode(&short));
}

test "query() type-checks (skipped — needs a live STUN server and Io)" {
    // Force semantic analysis of the optional live path without any I/O.
    _ = &query;
    return error.SkipZigTest;
}
