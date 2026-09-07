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

/// `testkit.fuzz.seedHex`, aliased so the corpora below read as the frames they
/// are. A corpus entry is not the frame: `Smith.slice` reads a little-endian
/// u32 length first, so a raw frame would arrive minus its own first four
/// octets. See `testkit/src/fuzz.zig` for the two other hazards.
const seed = @import("testkit").fuzz.seedHex;

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

/// TPKT packets, in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// Lifted from the value tests above, plus the four refusals `decode` names.
/// Uniform random octets clear a `03 00` version/reserved pair and a
/// self-consistent 16-bit length with probability ~2^-16 per draw, so without
/// these the harness proves only that the version check rejects noise.
const decode_seeds = [_][]const u8{
    seed("03000016" ++ "11E00000000100C0010DC2020001C1020001"), // the CR TPDU from the value test
    seed("0300000702F080"), // a Data TPDU
    seed("03000003"), // ShortPacket: three octets
    seed("03000004"), // LengthTooSmall: a length that cannot hold its own header
    seed("0300002000"), // TruncatedPacket: declares 32, delivers 5
    seed("03000100AABBCCDD"), // a length of 256 over an 8-octet frame
    seed("04000007" ++ "02F080"), // a wrong version octet on an otherwise valid frame
    seed("0300FFFF" ++ "02F080"), // the largest length TPKT can express
    seed("03000006" ++ "AABB"), // the shortest frame that carries a payload
};

test "fuzz: tpkt decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{ .corpus = &decode_seeds });
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every seed and `decode` was called with `buf[0..0]`
    // every single time, with the seed sitting unread in `buf`. Measured
    // 2026-09-07 over the corpus above: **0 of 9 non-empty and 0 decoded
    // before, 9 of 9 non-empty and 3 decoded after.**
    const len: usize = smith.slice(&buf);
    const pkt = decode(buf[0..len]) catch return;
    try testing.expect(pkt.total_len <= len);
    try testing.expectEqual(pkt.total_len, pkt.payload.len + header_len);
    var round: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, buf[0..pkt.total_len], try encode(pkt.payload, &round));
}

/// Streams for the framer: frames back to back, a frame split across the
/// 64-octet feed chunk, and streams that stop mid-header and mid-payload.
const framer_seeds = [_][]const u8{
    seed("0300000702F080" ++ "0300000702F080"), // two DT TPDUs in one feed
    seed("0300000702F0"), // stops one octet into the payload
    seed("0300"), // stops inside the header
    seed("03000050" ++ ("AA" ** 76)), // 80 octets: a payload split across two chunks
    seed("03001000"), // declares 4096 with nothing behind it
    seed("0300000702F080" ++ "0300"), // one whole frame, then a partial header
};

test "fuzz: framer never panics or hangs" {
    try std.testing.fuzz({}, fuzzFramer, .{ .corpus = &framer_seeds });
}

fn fuzzFramer(_: void, smith: *std.testing.Smith) !void {
    var input: [512]u8 = undefined;
    // ⚠ Same defect as `fuzzDecode` above, and for two months `check-fuzz-reach`
    // did NOT see it: its R2 rule looked for the drawn buffer being sliced
    // literally as `buf[0..len]`, and here `len` never touches the buffer at
    // all — it is the bound of the loop that feeds it. `len` was 0, so
    // `while (off < len)` never ran and this harness fed the framer NOTHING,
    // while its name promised a framer that never hangs. The rule was widened
    // on 2026-09-07 (form (b)); four other modules were hiding behind the same
    // gap. Measured over the corpus above: **0 of 6 seeds reached `feed` before,
    // 6 of 6 after.**
    const len: usize = smith.slice(&input);
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
