// SPDX-License-Identifier: MIT

//! TPKT (RFC 1006 §6) — the four-octet shim that carries an ISO transport
//! service over TCP.
//!
//! ```text
//! 0        1        2        3        4
//! +--------+--------+--------+--------+
//! |version |reserved|      length     |   length counts THIS header too
//! +--------+--------+--------+--------+
//! ```
//!
//! Two facts are worth stating loudly because both are common bugs:
//!
//! * **`length` is the length of the whole packet**, header included — not of
//!   the payload. A decoder that treats it as a payload length desynchronises
//!   the stream by four octets and then never recovers.
//! * A TPKT is the *only* framing S7 has. TCP delivers no message boundaries,
//!   so everything above this file depends on `Framer` splitting the stream
//!   correctly; a single mis-framed packet corrupts every packet after it.

const std = @import("std");

/// RFC 1006 fixes the version octet at 3.
pub const version: u8 = 3;
/// Octets in the TPKT header.
pub const header_len: usize = 4;
/// A packet must carry at least a COTP header length octet, so the smallest
/// legal `length` is the header plus one octet.
pub const min_length: usize = header_len + 1;
/// The length field is 16 bits, so this is the hard ceiling. Real S7 peers
/// negotiate far smaller PDUs (240/480/960) — see `s7.Setup`.
pub const max_length: usize = 65535;

pub const Error = error{
    /// Fewer octets than the four-octet header.
    ShortPacket,
    /// Version octet is not 3.
    BadVersion,
    /// The reserved octet is not zero.
    ReservedNotZero,
    /// `length` is below the header size (a self-inconsistent packet).
    LengthTooSmall,
    /// `length` announces more octets than the caller supplied.
    TruncatedPacket,
    /// The caller's payload does not fit a 16-bit length.
    PayloadTooLong,
    /// The caller's output buffer is too small.
    BufferTooSmall,
};

/// A decoded TPKT: the payload plus how many octets the whole packet occupied.
/// `total_len` is what a stream reader must consume, and is *not* the same as
/// `payload.len`.
pub const Packet = struct {
    payload: []const u8,
    total_len: usize,
};

/// Builds the four header octets for a payload of `payload_len`.
pub fn header(payload_len: usize) Error![header_len]u8 {
    if (payload_len == 0) return error.LengthTooSmall;
    const total = payload_len + header_len;
    if (total > max_length) return error.PayloadTooLong;
    return .{
        version,
        0,
        @intCast((total >> 8) & 0xFF),
        @intCast(total & 0xFF),
    };
}

/// Writes header + payload into `out` and returns the written slice.
pub fn encode(payload: []const u8, out: []u8) Error![]u8 {
    const h = try header(payload.len);
    if (out.len < header_len + payload.len) return error.BufferTooSmall;
    @memcpy(out[0..header_len], &h);
    @memcpy(out[header_len..][0..payload.len], payload);
    return out[0 .. header_len + payload.len];
}

/// Reads one TPKT from the front of `bytes`. Trailing octets are ignored —
/// `total_len` says where the next packet begins.
pub fn decode(bytes: []const u8) Error!Packet {
    if (bytes.len < header_len) return error.ShortPacket;
    if (bytes[0] != version) return error.BadVersion;
    if (bytes[1] != 0) return error.ReservedNotZero;
    const total: usize = (@as(usize, bytes[2]) << 8) | bytes[3];
    if (total < min_length) return error.LengthTooSmall;
    if (bytes.len < total) return error.TruncatedPacket;
    return .{ .payload = bytes[header_len..total], .total_len = total };
}

/// Peeks the announced total length without requiring the whole packet to be
/// present. Used by the stream framer and by socket adapters that want to read
/// exactly one packet.
pub fn peekLength(bytes: []const u8) Error!usize {
    if (bytes.len < header_len) return error.ShortPacket;
    if (bytes[0] != version) return error.BadVersion;
    if (bytes[1] != 0) return error.ReservedNotZero;
    const total: usize = (@as(usize, bytes[2]) << 8) | bytes[3];
    if (total < min_length) return error.LengthTooSmall;
    return total;
}

/// Splits a TCP byte stream into TPKTs. The caller supplies the storage, so
/// the ceiling on a single packet is explicit and there is no allocation.
///
/// `feed` appends, `next` yields whole packets until the buffer holds only a
/// partial one. Storage is compacted on `feed`, never grown.
pub const Framer = struct {
    buf: []u8,
    len: usize = 0,
    pos: usize = 0,

    pub fn init(storage: []u8) Framer {
        return .{ .buf = storage };
    }

    /// Octets held but not yet yielded.
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

    /// The next whole packet, or null when more octets are needed. The
    /// returned payload points into the framer's storage and is invalidated by
    /// the next `feed`.
    pub fn next(self: *Framer) Error!?Packet {
        const avail = self.buf[self.pos..self.len];
        if (avail.len < header_len) return null;
        const total = try peekLength(avail);
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
    // 19 payload octets -> total 23 = 0x0017.
    const h = try header(19);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x00, 0x00, 0x17 }, &h);
}

test "round trip" {
    const payload = [_]u8{ 0x02, 0xF0, 0x80, 0x32, 0x01 };
    var buf: [64]u8 = undefined;
    const frame = try encode(&payload, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x00, 0x00, 0x09 }, frame[0..4]);
    const pkt = try decode(frame);
    try testing.expectEqualSlices(u8, &payload, pkt.payload);
    try testing.expectEqual(@as(usize, 9), pkt.total_len);
}

test "decode rejects malformed headers" {
    try testing.expectError(error.ShortPacket, decode(&[_]u8{ 0x03, 0x00, 0x00 }));
    try testing.expectError(error.BadVersion, decode(&[_]u8{ 0x04, 0x00, 0x00, 0x05, 0x00 }));
    try testing.expectError(error.ReservedNotZero, decode(&[_]u8{ 0x03, 0x01, 0x00, 0x05, 0x00 }));
    try testing.expectError(error.LengthTooSmall, decode(&[_]u8{ 0x03, 0x00, 0x00, 0x04 }));
    try testing.expectError(error.LengthTooSmall, decode(&[_]u8{ 0x03, 0x00, 0x00, 0x00 }));
    // Length says 32 octets; only 5 are present.
    try testing.expectError(error.TruncatedPacket, decode(&[_]u8{ 0x03, 0x00, 0x00, 0x20, 0x00 }));
}

test "a length that disagrees with the payload never reads past the buffer" {
    // Announced 0x0100 (256) with 8 octets present.
    var bytes = [_]u8{ 0x03, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };
    try testing.expectError(error.TruncatedPacket, decode(&bytes));
    // The other direction: more octets than announced is fine, the surplus is
    // the next packet and total_len says so.
    bytes[2] = 0x00;
    bytes[3] = 0x06;
    const pkt = try decode(&bytes);
    try testing.expectEqual(@as(usize, 6), pkt.total_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, pkt.payload);
}

test "encode refuses an empty payload and a too-small buffer" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.LengthTooSmall, encode(&[_]u8{}, &buf));
    try testing.expectError(error.BufferTooSmall, encode(&[_]u8{ 1, 2 }, &buf));
}

test "framer reassembles split packets and yields several per feed" {
    var storage: [256]u8 = undefined;
    var f = Framer.init(&storage);
    const a = [_]u8{ 0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80 };
    const b = [_]u8{ 0x03, 0x00, 0x00, 0x06, 0x01, 0xE0 };

    try f.feed(a[0..2]);
    try testing.expect((try f.next()) == null);
    try f.feed(a[2..5]);
    try testing.expect((try f.next()) == null);
    try f.feed(a[5..]);
    const first = (try f.next()).?;
    try testing.expectEqualSlices(u8, a[4..], first.payload);
    try testing.expect((try f.next()) == null);

    var both: [13]u8 = undefined;
    @memcpy(both[0..7], &a);
    @memcpy(both[7..13], &b);
    try f.feed(&both);
    try testing.expectEqualSlices(u8, a[4..], (try f.next()).?.payload);
    try testing.expectEqualSlices(u8, b[4..], (try f.next()).?.payload);
    try testing.expect((try f.next()) == null);
    try testing.expectEqual(@as(usize, 0), f.pending());
}

test "framer refuses a packet larger than its storage instead of blocking forever" {
    var storage: [16]u8 = undefined;
    var f = Framer.init(&storage);
    try f.feed(&[_]u8{ 0x03, 0x00, 0x10, 0x00 }); // announces 4096
    try testing.expectError(error.PayloadTooLong, f.next());
}

test "framer surfaces a bad version rather than resynchronising" {
    var storage: [64]u8 = undefined;
    var f = Framer.init(&storage);
    try f.feed(&[_]u8{ 0x00, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80 });
    try testing.expectError(error.BadVersion, f.next());
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it -- 33 across 12
/// modules in three shapes -- each with its own note about the same trap (the
/// array has to be container-level or the returned slice dangles with the RIGHT
/// length and garbage behind it). It lives in `testkit.fuzz` now, with tests
/// that drive the real `std.testing.Smith` over what it produces.
const fuzzSeed = @import("testkit").fuzz.seedHex;

/// Real TPKT packets: a COTP-DT carrying an S7 header, a full Read Var job, and
/// every rejection `decode` has an error for.
const tpkt_seeds = [_][]const u8{
    fuzzSeed("0300000702f080"), // COTP-DT, empty S7 payload
    fuzzSeed("0300000902f0803201"), // the first two S7 octets
    fuzzSeed("0300001f02f080320100000001000e00000401120a10010000000184000200"), // a Read Var job
    fuzzSeed("03000100aabbccdd"), // declares 256 octets, delivers 8
    fuzzSeed("0300000702f08032"), // one octet past the declared length
    fuzzSeed("030000"), // shorter than the header
    fuzzSeed("0400000500"), // version is not 3
    fuzzSeed("0301000500"), // the reserved octet is not zero
    fuzzSeed("03000004"), // length below the header
    fuzzSeed("03000000"), // length zero
    fuzzSeed("0300002000"), // length past the end
};

test "fuzz: tpkt decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{ .corpus = &tpkt_seeds });
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    // `Smith.bytes` consumes the whole remaining seed, and the ranged draw then
    // finds fewer than eight octets left and returns the range MINIMUM — so the
    // length was 0 for every seed and this harness only ever saw the empty
    // input. Measured on 2026-09-06 over the corpus above: **0 of 11
    // non-empty and 0 decoded before, 11 of 11 non-empty and 4 decoded after.**
    const len: usize = smith.slice(&buf);
    const pkt = decode(buf[0..len]) catch return;
    try testing.expect(pkt.total_len <= len);
    try testing.expectEqual(pkt.total_len, pkt.payload.len + header_len);
    var round: [512]u8 = undefined;
    const again = try encode(pkt.payload, &round);
    try testing.expectEqualSlices(u8, buf[0..pkt.total_len], again);
}

/// Streams for the framer: two whole packets back to back, a packet split so
/// the 64-octet feed chunk lands inside the header, and a stream that never
/// completes its declared length.
const framer_seeds = [_][]const u8{
    fuzzSeed("0300000702f0800300000702f080"), // two complete packets
    fuzzSeed("0300001f02f080320100000001000e00000401120a100100000001840002000300000702f080"),
    fuzzSeed("03000100aabbccdd"), // declares 256 and stops
    fuzzSeed("03"), // one octet, then end of stream
    fuzzSeed("04000005000300000702f080"), // a bad version ahead of a good packet
};

test "fuzz: framer never panics or hangs" {
    try std.testing.fuzz({}, fuzzFramer, .{ .corpus = &framer_seeds });
}

fn fuzzFramer(_: void, smith: *std.testing.Smith) !void {
    var input: [512]u8 = undefined;
    // ⚠ Same defect as `fuzzDecode` above, and NOT flagged by
    // `check-fuzz-reach`: the gate's R2 rule looks for the drawn buffer being
    // sliced directly by the ranged length, and here `len` reaches the buffer
    // one level down, through `input[off..][0..chunk]`. The collapse was
    // identical — `len` was 0, the `while (off < len)` loop never ran, and this
    // harness fed the framer nothing at all. Measured on 2026-09-06 over the
    // corpus above: **0 of 5 seeds fed the framer a single octet, and 0 packets
    // came out, before; 5 of 5 fed, 4 packets out, after.**
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
            // A framer that yields without consuming would spin forever.
            try testing.expect(guard <= storage.len);
            const got = f.next() catch return;
            if (got == null) break;
        }
    }
}
