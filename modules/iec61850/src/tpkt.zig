// SPDX-License-Identifier: MIT

//! TPKT (RFC 1006 §6) — the four-octet shim that carries an ISO transport
//! service over TCP. MMS rides on it exactly as S7comm does.
//!
//! ```text
//! 0        1        2        3        4
//! +--------+--------+--------+--------+
//! |version |reserved|      length     |   length counts THIS header too
//! +--------+--------+--------+--------+
//! ```
//!
//! `length` is the length of the **whole** packet, header included. A decoder
//! that reads it as a payload length desynchronises the stream by four octets
//! and never recovers, and since TPKT is the only framing MMS has, every packet
//! after the first mis-framed one is garbage.
//!
//! Re-derived from RFC 1006 rather than shared with the sibling `s7comm`
//! module: this module takes no dependencies, so the wire layers it needs live
//! here even where another module has an equivalent.

const std = @import("std");

pub const version: u8 = 3;
pub const header_len: usize = 4;
/// A packet must carry at least a COTP length-indicator octet.
pub const min_length: usize = header_len + 1;
pub const max_length: usize = 65535;

pub const Error = error{
    ShortPacket,
    BadVersion,
    ReservedNotZero,
    LengthTooSmall,
    TruncatedPacket,
    PayloadTooLong,
    BufferTooSmall,
};

pub const Packet = struct {
    payload: []const u8,
    /// Octets a stream reader must consume — **not** `payload.len`.
    total_len: usize,
};

pub fn header(payload_len: usize) Error![header_len]u8 {
    if (payload_len == 0) return error.LengthTooSmall;
    const total = payload_len + header_len;
    if (total > max_length) return error.PayloadTooLong;
    return .{ version, 0, @intCast((total >> 8) & 0xFF), @intCast(total & 0xFF) };
}

pub fn encode(payload: []const u8, out: []u8) Error![]u8 {
    const h = try header(payload.len);
    if (out.len < header_len + payload.len) return error.BufferTooSmall;
    @memcpy(out[0..header_len], &h);
    @memcpy(out[header_len..][0..payload.len], payload);
    return out[0 .. header_len + payload.len];
}

pub fn decode(bytes: []const u8) Error!Packet {
    if (bytes.len < header_len) return error.ShortPacket;
    if (bytes[0] != version) return error.BadVersion;
    if (bytes[1] != 0) return error.ReservedNotZero;
    const total: usize = (@as(usize, bytes[2]) << 8) | bytes[3];
    if (total < min_length) return error.LengthTooSmall;
    if (bytes.len < total) return error.TruncatedPacket;
    return .{ .payload = bytes[header_len..total], .total_len = total };
}

/// The announced total length, without needing the whole packet present.
pub fn peekLength(bytes: []const u8) Error!usize {
    if (bytes.len < header_len) return error.ShortPacket;
    if (bytes[0] != version) return error.BadVersion;
    if (bytes[1] != 0) return error.ReservedNotZero;
    const total: usize = (@as(usize, bytes[2]) << 8) | bytes[3];
    if (total < min_length) return error.LengthTooSmall;
    return total;
}

/// Splits a TCP byte stream into TPKTs over caller-supplied storage: the
/// ceiling on one packet is explicit and there is no allocation.
pub const Framer = struct {
    buf: []u8,
    len: usize = 0,
    pos: usize = 0,

    pub fn init(storage: []u8) Framer {
        return .{ .buf = storage };
    }

    pub fn pending(self: *const Framer) usize {
        return self.len - self.pos;
    }

    pub fn reset(self: *Framer) void {
        self.len = 0;
        self.pos = 0;
    }

    pub fn feed(self: *Framer, bytes: []const u8) error{Overflow}!void {
        if (self.pos > 0) {
            std.mem.copyForwards(u8, self.buf[0..self.pending()], self.buf[self.pos..self.len]);
            self.len -= self.pos;
            self.pos = 0;
        }
        if (self.len + bytes.len > self.buf.len) return error.Overflow;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// The next whole packet, or null when more octets are needed. The payload
    /// points into the framer's storage and is invalidated by the next `feed`.
    pub fn next(self: *Framer) Error!?Packet {
        const avail = self.buf[self.pos..self.len];
        if (avail.len < header_len) return null;
        const total = try peekLength(avail);
        // Refuse a packet that can never fit rather than waiting forever for
        // octets there is no room for.
        if (total > self.buf.len) return error.PayloadTooLong;
        if (avail.len < total) return null;
        const pkt = try decode(avail);
        self.pos += pkt.total_len;
        return pkt;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "header counts itself" {
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x00, 0x00, 0x17 }, &try header(19));
}

test "round trip against a captured MMS packet header" {
    // The captured COTP connect request is a 22-octet TPKT.
    const payload = [_]u8{ 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0D, 0xC2, 0x02, 0x00, 0x01, 0xC1, 0x02, 0x00, 0x01 };
    var buf: [64]u8 = undefined;
    const frame = try encode(&payload, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x00, 0x00, 0x16 }, frame[0..4]);
    const pkt = try decode(frame);
    try testing.expectEqualSlices(u8, &payload, pkt.payload);
    try testing.expectEqual(@as(usize, 22), pkt.total_len);
}

test "decode rejects malformed headers" {
    try testing.expectError(error.ShortPacket, decode(&[_]u8{ 0x03, 0x00, 0x00 }));
    try testing.expectError(error.BadVersion, decode(&[_]u8{ 0x04, 0x00, 0x00, 0x05, 0x00 }));
    try testing.expectError(error.ReservedNotZero, decode(&[_]u8{ 0x03, 0x01, 0x00, 0x05, 0x00 }));
    try testing.expectError(error.LengthTooSmall, decode(&[_]u8{ 0x03, 0x00, 0x00, 0x04 }));
    try testing.expectError(error.TruncatedPacket, decode(&[_]u8{ 0x03, 0x00, 0x00, 0x20, 0x00 }));
}

test "a length that disagrees with the payload never reads past the buffer" {
    var bytes = [_]u8{ 0x03, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };
    try testing.expectError(error.TruncatedPacket, decode(&bytes));
    bytes[2] = 0x00;
    bytes[3] = 0x06;
    const pkt = try decode(&bytes);
    try testing.expectEqual(@as(usize, 6), pkt.total_len);
}

test "framer reassembles split packets" {
    var storage: [256]u8 = undefined;
    var f = Framer.init(&storage);
    const a = [_]u8{ 0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80 };
    try f.feed(a[0..2]);
    try testing.expect((try f.next()) == null);
    try f.feed(a[2..]);
    try testing.expectEqualSlices(u8, a[4..], (try f.next()).?.payload);
    try testing.expect((try f.next()) == null);
    try testing.expectEqual(@as(usize, 0), f.pending());
}

test "framer refuses a packet larger than its storage instead of blocking forever" {
    var storage: [16]u8 = undefined;
    var f = Framer.init(&storage);
    try f.feed(&[_]u8{ 0x03, 0x00, 0x10, 0x00 });
    try testing.expectError(error.PayloadTooLong, f.next());
}

test "fuzz: tpkt decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const pkt = decode(buf[0..len]) catch return;
    try testing.expect(pkt.total_len <= len);
    try testing.expectEqual(pkt.total_len, pkt.payload.len + header_len);
    var round: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, buf[0..pkt.total_len], try encode(pkt.payload, &round));
}

test "fuzz: framer never panics or hangs" {
    try std.testing.fuzz({}, fuzzFramer, .{});
}

fn fuzzFramer(_: void, smith: *std.testing.Smith) !void {
    var input: [512]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u16, 0, input.len);
    var storage: [1024]u8 = undefined;
    var f = Framer.init(&storage);
    var off: usize = 0;
    while (off < len) {
        const chunk = @min(len - off, @as(usize, 64));
        f.feed(input[off..][0..chunk]) catch return;
        off += chunk;
        var guard: usize = 0;
        while (true) {
            guard += 1;
            try testing.expect(guard <= storage.len);
            const got = f.next() catch return;
            if (got == null) break;
        }
    }
}
