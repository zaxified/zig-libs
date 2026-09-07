// SPDX-License-Identifier: MIT

//! APCI — the IEC 60870-5-104 Application Protocol Control Information
//! (IEC 60870-5-104 §5.1), i.e. the fixed six-octet header that prefixes every
//! APDU on the wire:
//!
//! ```text
//!   +------+--------+------+------+------+------+ - - - - - - - - +
//!   | 0x68 | length | ctl1 | ctl2 | ctl3 | ctl4 |  ASDU (0..249)  |
//!   +------+--------+------+------+------+------+ - - - - - - - - +
//! ```
//!
//! `length` counts **the octets after itself** — the four control octets plus
//! the ASDU — and is capped at 253, so an APDU is at most 255 octets and an
//! ASDU at most 249.
//!
//! Three frame formats are distinguished by the low bits of the first control
//! octet:
//!
//! * **I-format** (information transfer, ctl1 bit0 = 0): carries an ASDU and
//!   both 15-bit sequence numbers, N(S) in ctl1/ctl2 and N(R) in ctl3/ctl4,
//!   each shifted left by one so the low bit stays a format marker.
//! * **S-format** (supervisory, ctl1 bits1..0 = 0b01): acknowledge-only, no
//!   ASDU, carries N(R) only.
//! * **U-format** (unnumbered, ctl1 bits1..0 = 0b11): STARTDT/STOPDT/TESTFR,
//!   act or con, no ASDU and no sequence numbers.
//!
//! Everything here is a pure function over byte slices — no allocation, no
//! I/O, no clock. Hostile bytes resolve to typed errors.

const std = @import("std");

/// APDU start octet (§5.1). Every frame begins with it.
pub const start_byte: u8 = 0x68;

/// The APCI is always exactly six octets: start + length + four control.
pub const apci_len: usize = 6;

/// Maximum value of the length octet (§5.1) — it counts everything after
/// itself, so an APDU never exceeds `2 + 253 = 255` octets.
pub const max_length: u8 = 253;

/// Longest legal APDU (start + length octet + `max_length` octets).
pub const max_apdu_len: usize = 2 + @as(usize, max_length);

/// Longest ASDU that still fits inside an APDU (`max_length` minus the four
/// control octets).
pub const max_asdu_len: usize = @as(usize, max_length) - 4;

/// Smallest legal length octet: the four control octets, no ASDU (an S- or
/// U-format frame).
pub const min_length: u8 = 4;

/// Sequence numbers are 15 bits and wrap at 32768 (§5.5). `+%` on this type is
/// exactly the modulo-32768 arithmetic the standard prescribes, which is why
/// the sequence counters are declared `Seq` and never widened to `u16`.
pub const Seq = u15;

/// Number of distinct sequence numbers, 2^15.
pub const seq_modulus: u32 = 1 << 15;

/// Sequence-number distance `to - from`, taken modulo 2^15. Because `Seq` is
/// exactly 15 bits this is just wrapping subtraction; the helper exists so
/// call sites read as protocol logic rather than integer trickery.
pub fn seqDistance(from: Seq, to: Seq) u15 {
    return to -% from;
}

pub const Format = enum { i, s, u };

/// U-format function, encoded in the upper six bits of the first control
/// octet. Exactly one bit may be set (§5.3); `0x03` (bits 1..0) marks the
/// format itself and is not part of the value stored here.
pub const UFunction = enum(u8) {
    startdt_act = 0x04,
    startdt_con = 0x08,
    stopdt_act = 0x10,
    stopdt_con = 0x20,
    testfr_act = 0x40,
    testfr_con = 0x80,

    /// True for the three `act` requests (each of which expects a `con`).
    pub fn isAct(self: UFunction) bool {
        return switch (self) {
            .startdt_act, .stopdt_act, .testfr_act => true,
            else => false,
        };
    }

    /// The confirmation that answers this `act`, or null for a `con`.
    pub fn confirmation(self: UFunction) ?UFunction {
        return switch (self) {
            .startdt_act => .startdt_con,
            .stopdt_act => .stopdt_con,
            .testfr_act => .testfr_con,
            else => null,
        };
    }
};

/// A decoded control field.
pub const Control = union(Format) {
    i: struct { send_seq: Seq, recv_seq: Seq },
    s: struct { recv_seq: Seq },
    u: UFunction,
};

/// A fully decoded APDU: its control field plus the ASDU body (empty for S-
/// and U-format). The ASDU slice aliases the caller's input buffer.
pub const Apdu = struct {
    control: Control,
    asdu: []const u8,
    /// Total octets consumed from the input, i.e. `2 + length`.
    len: usize,
};

pub const DecodeError = error{
    /// First octet was not 0x68.
    BadStartByte,
    /// Fewer than the six APCI octets are present.
    ShortApdu,
    /// Length octet < 4 (there must be at least the four control octets).
    LengthTooSmall,
    /// Length octet > 253 (§5.1 hard cap).
    LengthTooLarge,
    /// The buffer holds fewer octets than the length field promises.
    TruncatedApdu,
    /// U-format with zero or more than one function bit set.
    BadUFunction,
    /// S-format whose second control octet is not zero, or U-format with a
    /// non-zero control octet 2/3/4.
    ReservedBitsSet,
};

pub const EncodeError = error{
    /// The output buffer cannot hold the frame.
    BufferTooSmall,
    /// The ASDU is longer than `max_asdu_len`.
    AsduTooLong,
};

/// Decodes exactly one APDU from the front of `bytes`.
///
/// The returned `asdu` aliases `bytes`; `len` says how many octets were
/// consumed, so a caller walking a stream advances by `result.len`.
pub fn decode(bytes: []const u8) DecodeError!Apdu {
    if (bytes.len < 2) return error.ShortApdu;
    if (bytes[0] != start_byte) return error.BadStartByte;
    const length = bytes[1];
    if (length < min_length) return error.LengthTooSmall;
    if (length > max_length) return error.LengthTooLarge;
    const total = 2 + @as(usize, length);
    if (bytes.len < total) return error.TruncatedApdu;

    const c1 = bytes[2];
    const c2 = bytes[3];
    const c3 = bytes[4];
    const c4 = bytes[5];
    const body = bytes[apci_len..total];

    if (c1 & 0x01 == 0) {
        // I-format: both sequence numbers present, ASDU follows.
        if (c3 & 0x01 != 0) return error.ReservedBitsSet;
        // §5.1 gives the I-format an ASDU by definition. An empty one used to
        // be accepted here and rejected downstream as `ShortAsdu` — but only
        // after `state.onFrame` had counted it and advanced `recv_seq`, and
        // the cost is the connection. The other two formats already reject a
        // body they do not expect; this makes the third symmetric
        // (W2 re-audit 2026-09-02, `iec104` F7).
        if (body.len == 0) return error.ReservedBitsSet;
        const ns: Seq = @intCast((@as(u16, c1) | (@as(u16, c2) << 8)) >> 1);
        const nr: Seq = @intCast((@as(u16, c3) | (@as(u16, c4) << 8)) >> 1);
        return .{
            .control = .{ .i = .{ .send_seq = ns, .recv_seq = nr } },
            .asdu = body,
            .len = total,
        };
    }

    if (c1 & 0x03 == 0x01) {
        // S-format: acknowledge only. ctl1 must be exactly 0x01, ctl2 zero.
        if (c1 != 0x01 or c2 != 0x00) return error.ReservedBitsSet;
        if (c3 & 0x01 != 0) return error.ReservedBitsSet;
        if (body.len != 0) return error.ReservedBitsSet;
        const nr: Seq = @intCast((@as(u16, c3) | (@as(u16, c4) << 8)) >> 1);
        return .{ .control = .{ .s = .{ .recv_seq = nr } }, .asdu = body, .len = total };
    }

    // U-format (ctl1 bits 1..0 == 0b11).
    if (c2 != 0 or c3 != 0 or c4 != 0) return error.ReservedBitsSet;
    if (body.len != 0) return error.ReservedBitsSet;
    const fn_bits = c1 & 0xFC;
    if (fn_bits == 0 or @popCount(fn_bits) != 1) return error.BadUFunction;
    const func: UFunction = switch (fn_bits) {
        0x04 => .startdt_act,
        0x08 => .startdt_con,
        0x10 => .stopdt_act,
        0x20 => .stopdt_con,
        0x40 => .testfr_act,
        0x80 => .testfr_con,
        else => return error.BadUFunction,
    };
    return .{ .control = .{ .u = func }, .asdu = body, .len = total };
}

/// Encodes one APDU into `out`, returning the written slice.
/// `asdu` must be empty for S- and U-format frames.
pub fn encode(control: Control, asdu: []const u8, out: []u8) EncodeError![]u8 {
    if (asdu.len > max_asdu_len) return error.AsduTooLong;
    const total = apci_len + asdu.len;
    if (out.len < total) return error.BufferTooSmall;

    out[0] = start_byte;
    out[1] = @intCast(4 + asdu.len);
    switch (control) {
        .i => |f| {
            const ns = @as(u16, f.send_seq) << 1;
            const nr = @as(u16, f.recv_seq) << 1;
            out[2] = @truncate(ns);
            out[3] = @truncate(ns >> 8);
            out[4] = @truncate(nr);
            out[5] = @truncate(nr >> 8);
            @memcpy(out[apci_len..total], asdu);
        },
        .s => |f| {
            if (asdu.len != 0) return error.AsduTooLong;
            const nr = @as(u16, f.recv_seq) << 1;
            out[2] = 0x01;
            out[3] = 0x00;
            out[4] = @truncate(nr);
            out[5] = @truncate(nr >> 8);
        },
        .u => |func| {
            if (asdu.len != 0) return error.AsduTooLong;
            out[2] = @intFromEnum(func) | 0x03;
            out[3] = 0;
            out[4] = 0;
            out[5] = 0;
        },
    }
    return out[0..total];
}

/// Convenience: encode a U-format frame into a fixed six-octet array.
pub fn encodeU(func: UFunction) [apci_len]u8 {
    var buf: [apci_len]u8 = undefined;
    _ = encode(.{ .u = func }, &.{}, &buf) catch unreachable;
    return buf;
}

/// Convenience: encode an S-format acknowledgement into a fixed six-octet
/// array.
pub fn encodeS(recv_seq: Seq) [apci_len]u8 {
    var buf: [apci_len]u8 = undefined;
    _ = encode(.{ .s = .{ .recv_seq = recv_seq } }, &.{}, &buf) catch unreachable;
    return buf;
}

// ── stream framer ───────────────────────────────────────────────────────────

pub const FramerError = DecodeError || error{
    /// A frame arrived that is longer than the framer's buffer, or a partial
    /// frame plus the bytes just fed exceed it.
    ///
    /// ⚠ This used to read "since the buffer is sized for `max_apdu_len` this
    /// can only happen if the caller supplied a smaller one". Not so: with a
    /// buffer at exactly `max_apdu_len` — the documented minimum — an ordinary
    /// TCP segmentation (200 octets of a 255-octet frame, then the rest with a
    /// second frame coalesced behind it) overflows it. `Client.poll` and
    /// `Server.poll` now cap each read at `capacity() - pending()`
    /// (W2 re-audit 2026-09-02, `iec104` F5).
    BufferTooSmall,
};

/// Splits a TCP byte stream into APDUs. TCP gives no message boundaries, so a
/// read may deliver half a frame, three frames, or a frame split across two
/// reads; `feed` absorbs whatever arrives and `next` yields whole APDUs.
///
/// The framer owns a caller-supplied buffer of at least `max_apdu_len` octets
/// and never allocates. It is a pure state machine — no clock, no socket.
pub const Framer = struct {
    buf: []u8,
    len: usize = 0,
    /// Offset of the next unconsumed octet inside `buf[0..len]`.
    pos: usize = 0,

    pub fn init(buf: []u8) Framer {
        return .{ .buf = buf };
    }

    /// Bytes still buffered but not yet consumed.
    pub fn pending(self: *const Framer) usize {
        return self.len - self.pos;
    }

    /// Total octets this framer's buffer can hold. A caller reading into it
    /// must cap its read at `capacity() - pending()`, or a partial frame plus
    /// a full chunk overflows a buffer sized at the documented minimum (F5).
    pub fn capacity(self: *const Framer) usize {
        return self.buf.len;
    }

    /// Appends freshly-read stream bytes. Compacts first, so a caller may feed
    /// repeatedly without draining every frame in between.
    pub fn feed(self: *Framer, bytes: []const u8) FramerError!void {
        if (self.pos > 0) {
            std.mem.copyForwards(u8, self.buf[0 .. self.len - self.pos], self.buf[self.pos..self.len]);
            self.len -= self.pos;
            self.pos = 0;
        }
        if (bytes.len > self.buf.len - self.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Returns the next complete APDU, or null when more bytes are needed.
    /// The returned `asdu` aliases the framer's buffer and stays valid only
    /// until the next `feed`/`next`.
    pub fn next(self: *Framer) FramerError!?Apdu {
        const avail = self.buf[self.pos..self.len];
        if (avail.len < 2) return null;
        if (avail[0] != start_byte) return error.BadStartByte;
        const length = avail[1];
        if (length < min_length) return error.LengthTooSmall;
        if (length > max_length) return error.LengthTooLarge;
        if (avail.len < 2 + @as(usize, length)) return null;
        const apdu = try decode(avail);
        self.pos += apdu.len;
        return apdu;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// `testkit.fuzz.seedHex`, aliased so the corpora below read as the APDUs they
/// are. A corpus entry is not the frame: `Smith.slice` reads a little-endian
/// u32 length first, so a raw frame would arrive minus its own first four
/// octets. See `testkit/src/fuzz.zig` for the two other hazards.
const seed = @import("testkit").fuzz.seedHex;

test "U-format round-trip for all six functions" {
    const cases = [_]struct { f: UFunction, hex: []const u8 }{
        .{ .f = .startdt_act, .hex = "680407000000" },
        .{ .f = .startdt_con, .hex = "68040b000000" },
        .{ .f = .stopdt_act, .hex = "680413000000" },
        .{ .f = .stopdt_con, .hex = "680423000000" },
        .{ .f = .testfr_act, .hex = "680443000000" },
        .{ .f = .testfr_con, .hex = "680483000000" },
    };
    for (cases) |c| {
        var want: [6]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, c.hex);
        const got = encodeU(c.f);
        try testing.expectEqualSlices(u8, &want, &got);
        const dec = try decode(&want);
        try testing.expectEqual(Format.u, @as(Format, dec.control));
        try testing.expectEqual(c.f, dec.control.u);
        try testing.expectEqual(@as(usize, 6), dec.len);
    }
}

test "S-format carries N(R) shifted left by one" {
    const s = encodeS(9);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x68, 0x04, 0x01, 0x00, 0x12, 0x00 }, &s);
    const dec = try decode(&s);
    try testing.expectEqual(@as(Seq, 9), dec.control.s.recv_seq);

    // A large N(R) spills into the fourth control octet.
    const big = encodeS(32767);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x68, 0x04, 0x01, 0x00, 0xFE, 0xFF }, &big);
    try testing.expectEqual(@as(Seq, 32767), (try decode(&big)).control.s.recv_seq);
}

test "I-format round-trip carries both sequence numbers and the ASDU" {
    const asdu = [_]u8{ 0x64, 0x01, 0x06, 0x00, 0x2F, 0x00, 0, 0, 0, 0x14 };
    var buf: [max_apdu_len]u8 = undefined;
    const frame = try encode(.{ .i = .{ .send_seq = 1, .recv_seq = 2 } }, &asdu, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x68, 0x0E, 0x02, 0x00, 0x04, 0x00 }, frame[0..6]);
    const dec = try decode(frame);
    try testing.expectEqual(@as(Seq, 1), dec.control.i.send_seq);
    try testing.expectEqual(@as(Seq, 2), dec.control.i.recv_seq);
    try testing.expectEqualSlices(u8, &asdu, dec.asdu);
}

test "sequence numbers wrap at 32768, not 65536" {
    var buf: [max_apdu_len]u8 = undefined;
    const asdu = [_]u8{0xAA};
    // 32767 is the largest N(S); the next one is 0.
    const frame = try encode(.{ .i = .{ .send_seq = 32767, .recv_seq = 32767 } }, &asdu, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x68, 0x05, 0xFE, 0xFF, 0xFE, 0xFF }, frame[0..6]);
    const dec = try decode(frame);
    try testing.expectEqual(@as(Seq, 32767), dec.control.i.send_seq);
    const wrapped: Seq = dec.control.i.send_seq +% 1;
    try testing.expectEqual(@as(Seq, 0), wrapped);
    try testing.expectEqual(@as(u15, 1), seqDistance(32767, 0));
    try testing.expectEqual(@as(u15, 32767), seqDistance(1, 0));
}

test "length octet boundary: 253 accepted, 254 rejected" {
    var buf: [max_apdu_len]u8 = undefined;
    const asdu = [_]u8{0x5A} ** max_asdu_len; // 249 -> length 253
    const frame = try encode(.{ .i = .{ .send_seq = 0, .recv_seq = 0 } }, &asdu, &buf);
    try testing.expectEqual(@as(u8, 253), frame[1]);
    try testing.expectEqual(max_apdu_len, frame.len);
    _ = try decode(frame);

    // One octet more must be refused at the encoder.
    const too_long = [_]u8{0x5A} ** (max_asdu_len + 1);
    try testing.expectError(error.AsduTooLong, encode(.{ .i = .{ .send_seq = 0, .recv_seq = 0 } }, &too_long, &buf));

    // ... and a length octet above the cap must be refused at the decoder,
    // even when that many bytes really are present.
    var hostile: [2 + 254]u8 = undefined;
    hostile[0] = start_byte;
    hostile[1] = 254;
    @memset(hostile[2..], 0);
    try testing.expectError(error.LengthTooLarge, decode(&hostile));
}

test "decode rejects malformed APCI" {
    try testing.expectError(error.ShortApdu, decode(&[_]u8{}));
    try testing.expectError(error.ShortApdu, decode(&[_]u8{0x68}));
    try testing.expectError(error.BadStartByte, decode(&[_]u8{ 0x69, 0x04, 0x07, 0, 0, 0 }));
    try testing.expectError(error.LengthTooSmall, decode(&[_]u8{ 0x68, 0x03, 0x07, 0, 0, 0 }));
    try testing.expectError(error.TruncatedApdu, decode(&[_]u8{ 0x68, 0x04, 0x07, 0, 0 }));
    // U-format with two function bits set.
    try testing.expectError(error.BadUFunction, decode(&[_]u8{ 0x68, 0x04, 0x07 | 0x08, 0, 0, 0 }));
    // U-format with only the format bits.
    try testing.expectError(error.BadUFunction, decode(&[_]u8{ 0x68, 0x04, 0x03, 0, 0, 0 }));
    // U-format with a non-zero control octet 2.
    try testing.expectError(error.ReservedBitsSet, decode(&[_]u8{ 0x68, 0x04, 0x07, 0x01, 0, 0 }));
    // U-format carrying a body.
    try testing.expectError(error.ReservedBitsSet, decode(&[_]u8{ 0x68, 0x05, 0x07, 0, 0, 0, 0xFF }));
    // S-format carrying a body.
    try testing.expectError(error.ReservedBitsSet, decode(&[_]u8{ 0x68, 0x05, 0x01, 0, 0, 0, 0xFF }));
    // S-format with a dirty second control octet.
    try testing.expectError(error.ReservedBitsSet, decode(&[_]u8{ 0x68, 0x04, 0x01, 0x02, 0, 0 }));
    // I-format with the N(R) marker bit set.
    try testing.expectError(error.ReservedBitsSet, decode(&[_]u8{ 0x68, 0x05, 0x00, 0, 0x01, 0, 0xFF }));
}

test "framer reassembles APDUs split across reads and yields several per read" {
    var storage: [max_apdu_len * 2]u8 = undefined;
    var f = Framer.init(&storage);

    const start = encodeU(.startdt_act);
    // Half a frame first: nothing to yield yet.
    try f.feed(start[0..3]);
    try testing.expect((try f.next()) == null);
    try f.feed(start[3..]);
    const one = (try f.next()).?;
    try testing.expectEqual(UFunction.startdt_act, one.control.u);
    try testing.expect((try f.next()) == null);

    // Two frames in a single read.
    const con = encodeU(.startdt_con);
    const s = encodeS(3);
    var both: [12]u8 = undefined;
    @memcpy(both[0..6], &con);
    @memcpy(both[6..12], &s);
    try f.feed(&both);
    try testing.expectEqual(UFunction.startdt_con, (try f.next()).?.control.u);
    try testing.expectEqual(@as(Seq, 3), (try f.next()).?.control.s.recv_seq);
    try testing.expect((try f.next()) == null);
    try testing.expectEqual(@as(usize, 0), f.pending());
}

test "framer rejects a bad start byte and an over-long length octet" {
    var storage: [max_apdu_len]u8 = undefined;
    var f = Framer.init(&storage);
    try f.feed(&[_]u8{ 0x00, 0x04, 0x07, 0, 0, 0 });
    try testing.expectError(error.BadStartByte, f.next());

    var g = Framer.init(&storage);
    try g.feed(&[_]u8{ 0x68, 0xFF, 0x07, 0, 0, 0 });
    try testing.expectError(error.LengthTooLarge, g.next());
}

/// APDUs, in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// Lifted from the value tests above plus every refusal `decode` names.
/// Uniform random octets clear a `0x68` start byte and a self-consistent
/// length octet with probability ~2^-9 per draw, and the I/S/U discrimination
/// then sits behind three more reserved-octet checks — so without these the
/// harness proves only that the start-byte check rejects noise.
const decode_seeds = [_][]const u8{
    seed("680407000000"), // U-format STARTDT act
    seed("680483000000"), // U-format TESTFR con
    seed("680401001200"), // S-format, N(R) = 9
    seed("680E02000400" ++ "640106002F0000000014"), // I-format with the value test's ASDU
    seed("68FD00000000" ++ ("5A" ** 249)), // the longest legal APDU: length octet 253
    seed("680407000000" ++ "680483000000"), // two frames: the tail must be left alone
    seed("68"), // ShortApdu
    seed("690407000000"), // BadStartByte
    seed("680307000000"), // LengthTooSmall: length octet 3
    seed("6804070000"), // TruncatedApdu: five octets of a six-octet frame
    seed("68040F000000"), // BadUFunction: two function bits set
    seed("680403000000"), // BadUFunction: the format bits and nothing else
    seed("680407010000"), // ReservedBitsSet: U-format with a dirty control octet 2
    seed("680507000000FF"), // ReservedBitsSet: U-format carrying a body
    seed("680501000000FF"), // ReservedBitsSet: S-format carrying a body
    seed("680401020000"), // ReservedBitsSet: S-format with a dirty control octet 2
    seed("680500000100FF"), // ReservedBitsSet: I-format with the N(R) marker bit set
    seed("680400000000"), // ReservedBitsSet: I-format with no ASDU (F7)
    seed("68FE" ++ ("00" ** 254)), // LengthTooLarge, with the octets really present
};

test "fuzz: apci decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{ .corpus = &decode_seeds });
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [max_apdu_len + 8]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every seed and `decode` was handed `buf[0..0]` every
    // time, with the frame sitting unread in `buf`. Measured 2026-09-07 over
    // the corpus above: **0 of 19 non-empty and 0 decoded before, 19 of 19
    // non-empty and 6 decoded after.**
    const len: usize = smith.slice(&buf);
    const apdu = decode(buf[0..len]) catch return;
    // Anything that decodes must re-encode to the very same octets.
    var round: [max_apdu_len]u8 = undefined;
    const again = encode(apdu.control, apdu.asdu, &round) catch return;
    try testing.expectEqualSlices(u8, buf[0..apdu.len], again);
}

test "corpus: every APDU seed reaches the decoder, and the accepted count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer — `Smith.slice`
    // reads that back as the EMPTY seed, silently. `accepted` is pinned rather
    // than asserted `> 0`: a corpus of refusals only exercises the refusal
    // path, and a later edit that quietly stops a frame decoding shows up here.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [max_apdu_len + 8]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (decode(buf[0..len])) |_| accepted += 1 else |_| {}
    }
    try testing.expectEqual(decode_seeds.len, nonempty);
    // 6 = two U-format, one S-format, the value test's I-format, the 253-octet
    // I-format, and the first of the two back-to-back frames.
    try testing.expectEqual(@as(usize, 6), accepted);
}

/// Streams for the framer: frames back to back, a frame split across the
/// 255-octet feed chunk, streams that stop mid-header, and the two refusals
/// `next` can raise before a whole frame is present.
const framer_seeds = [_][]const u8{
    seed("680407000000" ++ "680483000000" ++ "680401001200"), // three frames in one feed
    seed("68040700"), // stops four octets into the header
    seed("68"), // one octet
    // 30 octets of U-format frames, then the 253-length I-format APDU: 285
    // octets in all, so the 255-octet chunk cuts the last frame in half.
    seed(("680407000000" ** 5) ++ "68FD00000000" ++ ("5A" ** 249)),
    seed("68FF07000000"), // LengthTooLarge, raised before the frame completes
    seed("000407000000"), // BadStartByte
    seed("680407000000" ++ "6804"), // one whole frame, then a partial header
    seed("68" ** 400), // self-consistent by accident: 0x68 is also a legal length
};

test "fuzz: framer never panics or hangs on arbitrary stream bytes" {
    try std.testing.fuzz({}, fuzzFramer, .{ .corpus = &framer_seeds });
}

fn fuzzFramer(_: void, smith: *std.testing.Smith) !void {
    var input: [512]u8 = undefined;
    // ⚠ Same defect as `fuzzDecode` above, and worse: `len` never touched the
    // buffer at all — it was the bound of the loop that feeds it. `len` was 0,
    // so `while (off < len)` never ran and this harness fed the framer
    // NOTHING, while its name promised a framer that never hangs.
    // `check-fuzz-reach` only learned to see that shape on 2026-09-07.
    // Measured over the corpus above: **0 of 8 seeds reached `feed` and 0
    // frames were yielded before, 8 of 8 and 13 frames after.**
    const len: usize = smith.slice(&input);
    var storage: [max_apdu_len * 2]u8 = undefined;
    var f = Framer.init(&storage);
    var off: usize = 0;
    while (off < len) {
        const chunk = @min(len - off, max_apdu_len);
        f.feed(input[off..][0..chunk]) catch return;
        off += chunk;
        var guard: usize = 0;
        while (true) {
            guard += 1;
            // A framer that ever returns frames without consuming input would
            // spin forever; cap the loop so the bug shows as a failure.
            try testing.expect(guard <= max_apdu_len * 2);
            const got = f.next() catch return;
            if (got == null) break;
        }
    }
}

test "corpus: every stream seed reaches feed, and the frames yielded are pinned" {
    // ⭐ Same shape as the decode guard, with the second number chosen for what
    // the collapse hid: `nonempty` alone would have been satisfied by a stream
    // that `feed` accepts and `next` never completes, and that is exactly what
    // this harness did for its whole life — it fed nothing at all. `frames` is
    // the number an empty input cannot produce.
    var nonempty: usize = 0;
    var frames: usize = 0;
    for (framer_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var input: [512]u8 = undefined;
        const len: usize = smith.slice(&input);
        if (len != 0) nonempty += 1;
        var storage: [max_apdu_len * 2]u8 = undefined;
        var f = Framer.init(&storage);
        var off: usize = 0;
        stream: while (off < len) {
            const chunk = @min(len - off, max_apdu_len);
            f.feed(input[off..][0..chunk]) catch break :stream;
            off += chunk;
            while (true) {
                const got = f.next() catch break :stream;
                if (got == null) break;
                frames += 1;
            }
        }
    }
    try testing.expectEqual(framer_seeds.len, nonempty);
    // 3 + 0 + 0 + 6 + 0 + 0 + 1 + 3: the last one is the accidental stream of
    // 0x68 octets, where the start byte doubles as a legal length octet (106),
    // so three whole I-format APDUs come out of 400 octets of it.
    try testing.expectEqual(@as(usize, 13), frames);
}

test "an I-format APDU with no ASDU is refused by the framer, not by the state machine" {
    // §5.1 gives the I-format an ASDU by definition. An empty one was accepted
    // here and rejected downstream — but only after `state.onFrame` had
    // counted it and advanced `recv_seq`, and the cost is the connection. The
    // other two formats already reject a body they do not expect
    // (W2 re-audit 2026-09-02, `iec104` F7).
    const empty_i = [_]u8{ 0x68, 0x04, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.ReservedBitsSet, decode(&empty_i));

    // One octet of ASDU is still refused later (it is a short ASDU), but the
    // frame itself decodes — the bound is on "no body", not on "small body".
    const one_octet = [_]u8{ 0x68, 0x05, 0x00, 0x00, 0x00, 0x00, 0x2d };
    const f = try decode(&one_octet);
    try std.testing.expectEqual(@as(usize, 1), f.asdu.len);
}
