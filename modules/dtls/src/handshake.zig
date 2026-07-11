// SPDX-License-Identifier: MIT

//! dtls.handshake — RFC 9147 §5.2 handshake message framing: the 12-byte
//! header (`msg_type`, `length`, `message_seq`, `fragment_offset`,
//! `fragment_length`) that wraps every DTLS handshake message, plus
//! `Fragmenter`/`Reassembler` to split an oversized message into
//! MTU-fitting fragments and reassemble them — including OUT-OF-ORDER and
//! DUPLICATE fragments, since DTLS runs over UDP and has no transport-level
//! ordering guarantee (unlike TCP-backed TLS, which never needs this at
//! all). Pure, allocation-free, operates on caller-supplied buffers only.

const std = @import("std");

pub const FrameError = error{
    BufferTooShort,
    FragmentOutOfRange,
};

pub const ReassembleError = error{
    /// Caller's reassembly buffer/bitmap is smaller than the message's
    /// declared total length.
    BufferTooSmall,
    /// A later fragment's `length` field disagrees with the first
    /// fragment's for the same `message_seq` — the peer is lying about the
    /// message's total size mid-stream.
    InconsistentLength,
    /// `fragment_offset + fragment_length` exceeds the declared `length`.
    FragmentOutOfRange,
};

pub const header_len = 12;

/// RFC 9147 §5.2's handshake header. `msg_type` is an opaque `u8` here
/// (interpret it against `messages.HandshakeType` if you need the name);
/// this file only cares about the framing fields.
pub const HandshakeHeader = struct {
    msg_type: u8,
    /// Total length of the *reassembled* handshake message body (constant
    /// across every fragment sharing this `message_seq`).
    length: u24,
    /// Monotonically increasing per logical handshake message (RFC 9147
    /// §5.2) — NOT the same counter as the record layer's sequence number.
    message_seq: u16,
    fragment_offset: u24,
    fragment_length: u24,
};

fn writeU24(out: *[3]u8, v: u24) void {
    out[0] = @truncate(v >> 16);
    out[1] = @truncate(v >> 8);
    out[2] = @truncate(v);
}

fn readU24(buf: *const [3]u8) u24 {
    return (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | buf[2];
}

pub fn encodeHeader(hdr: HandshakeHeader, out: *[header_len]u8) void {
    out[0] = hdr.msg_type;
    writeU24(out[1..4], hdr.length);
    std.mem.writeInt(u16, out[4..6], hdr.message_seq, .big);
    writeU24(out[6..9], hdr.fragment_offset);
    writeU24(out[9..12], hdr.fragment_length);
}

pub fn decodeHeader(buf: []const u8) (FrameError)!HandshakeHeader {
    if (buf.len < header_len) return error.BufferTooShort;
    const length = readU24(buf[1..4]);
    const fragment_offset = readU24(buf[6..9]);
    const fragment_length = readU24(buf[9..12]);
    if (@as(u32, fragment_offset) + @as(u32, fragment_length) > @as(u32, length))
        return error.FragmentOutOfRange;
    return .{
        .msg_type = buf[0],
        .length = length,
        .message_seq = std.mem.readInt(u16, buf[4..6], .big),
        .fragment_offset = fragment_offset,
        .fragment_length = fragment_length,
    };
}

// ── fragmentation (outgoing) ─────────────────────────────────────────────

/// Splits `body` into a sequence of handshake fragments (12-byte header +
/// up to `max_fragment_len` bytes each), one `next()` call at a time. A
/// zero-length body still produces exactly one (offset 0, length 0)
/// fragment, matching the header semantics where `length == 0` is a
/// complete, legal message.
pub const Fragmenter = struct {
    msg_type: u8,
    message_seq: u16,
    body: []const u8,
    pos: u24 = 0,
    emitted_any: bool = false,

    pub fn init(msg_type: u8, message_seq: u16, body: []const u8) Fragmenter {
        std.debug.assert(body.len <= std.math.maxInt(u24));
        return .{ .msg_type = msg_type, .message_seq = message_seq, .body = body };
    }

    /// Writes the next fragment into `out` (must be >= `header_len +
    /// max_fragment_len`) and returns the slice of `out` used, or `null`
    /// once every fragment has been produced.
    pub fn next(self: *Fragmenter, max_fragment_len: usize, out: []u8) ?[]const u8 {
        std.debug.assert(out.len >= header_len + max_fragment_len);
        if (self.emitted_any and self.pos >= self.body.len) return null;

        const remaining = self.body.len - self.pos;
        const n = @min(remaining, max_fragment_len);
        const hdr = HandshakeHeader{
            .msg_type = self.msg_type,
            .length = @intCast(self.body.len),
            .message_seq = self.message_seq,
            .fragment_offset = self.pos,
            .fragment_length = @intCast(n),
        };
        encodeHeader(hdr, out[0..header_len]);
        @memcpy(out[header_len..][0..n], self.body[self.pos..][0..n]);

        self.pos += @intCast(n);
        self.emitted_any = true;
        return out[0 .. header_len + n];
    }
};

// ── reassembly (incoming, out-of-order + duplicate tolerant) ────────────

/// Feeds handshake fragments (in arbitrary arrival order, duplicates
/// allowed) and reassembles them into a caller-supplied buffer.
/// Completion is detected by having received every byte in
/// `[0, total_len)`, not by fragment arrival order — required because DTLS
/// has no transport-level ordering (RFC 9147 §5.2).
pub const Reassembler = struct {
    buf: []u8,
    /// Byte-granularity "have I received this offset yet" bitmap, same
    /// length as `buf`.
    received: []bool,
    total_len: ?u24 = null,
    message_seq: ?u16 = null,
    msg_type: u8 = 0,

    pub fn init(buf: []u8, received: []bool) Reassembler {
        std.debug.assert(buf.len == received.len);
        return .{ .buf = buf, .received = received };
    }

    /// Discards any in-progress reassembly, ready for a new message.
    pub fn reset(self: *Reassembler) void {
        self.total_len = null;
        self.message_seq = null;
        @memset(self.received, false);
    }

    /// Feeds one fragment. `hdr` must already be `decodeHeader`'d and
    /// `fragment_body` must be exactly `hdr.fragment_length` bytes (the
    /// slice of the datagram immediately following the 12-byte header). A
    /// fragment whose `message_seq` differs from the one already in
    /// progress restarts reassembly for the new message (RFC 9147 §5.2:
    /// only one handshake message is reassembled at a time). Returns the
    /// complete message body once every byte has arrived, `null` if more
    /// fragments are still needed.
    pub fn feed(self: *Reassembler, hdr: HandshakeHeader, fragment_body: []const u8) ReassembleError!?[]const u8 {
        if (fragment_body.len != hdr.fragment_length) return error.FragmentOutOfRange;

        if (self.message_seq == null or self.message_seq.? != hdr.message_seq) {
            self.reset();
            self.message_seq = hdr.message_seq;
            self.total_len = hdr.length;
            self.msg_type = hdr.msg_type;
        } else if (self.total_len.? != hdr.length) {
            return error.InconsistentLength;
        }

        const total: usize = self.total_len.?;
        if (total > self.buf.len) return error.BufferTooSmall;

        const end = @as(usize, hdr.fragment_offset) + @as(usize, hdr.fragment_length);
        if (end > total) return error.FragmentOutOfRange;

        if (fragment_body.len > 0) {
            @memcpy(self.buf[hdr.fragment_offset..][0..fragment_body.len], fragment_body);
            @memset(self.received[hdr.fragment_offset..][0..fragment_body.len], true);
        }

        if (total == 0) return self.buf[0..0];

        for (self.received[0..total]) |r| {
            if (!r) return null;
        }
        return self.buf[0..total];
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "handshake header round-trip" {
    const hdr = HandshakeHeader{ .msg_type = 1, .length = 500, .message_seq = 3, .fragment_offset = 100, .fragment_length = 200 };
    var buf: [header_len]u8 = undefined;
    encodeHeader(hdr, &buf);
    const dec = try decodeHeader(&buf);
    try testing.expectEqual(hdr.msg_type, dec.msg_type);
    try testing.expectEqual(hdr.length, dec.length);
    try testing.expectEqual(hdr.message_seq, dec.message_seq);
    try testing.expectEqual(hdr.fragment_offset, dec.fragment_offset);
    try testing.expectEqual(hdr.fragment_length, dec.fragment_length);
}

test "handshake header: hand-built golden bytes" {
    // msg_type=1, length=0x000102, message_seq=0x0304,
    // fragment_offset=0x000000, fragment_length=0x000102 (whole message).
    const hdr = HandshakeHeader{ .msg_type = 1, .length = 0x0102, .message_seq = 0x0304, .fragment_offset = 0, .fragment_length = 0x0102 };
    var buf: [header_len]u8 = undefined;
    encodeHeader(hdr, &buf);
    try testing.expectEqualSlices(u8, &.{ 1, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02 }, &buf);
}

test "handshake header: fragment out of range is a typed error" {
    var buf: [header_len]u8 = undefined;
    encodeHeader(.{ .msg_type = 1, .length = 10, .message_seq = 0, .fragment_offset = 5, .fragment_length = 10 }, &buf);
    try testing.expectError(error.FragmentOutOfRange, decodeHeader(&buf));
}

test "handshake header: buffer too short is a typed error" {
    var buf: [header_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooShort, decodeHeader(&buf));
}

test "fragmenter: zero-length body yields one empty fragment" {
    var frag = Fragmenter.init(1, 0, &.{});
    var out: [header_len + 16]u8 = undefined;
    const f = frag.next(16, &out).?;
    try testing.expectEqual(@as(usize, header_len), f.len);
    const hdr = try decodeHeader(f);
    try testing.expectEqual(@as(u24, 0), hdr.length);
    try testing.expectEqual(@as(u24, 0), hdr.fragment_length);
    try testing.expectEqual(@as(?[]const u8, null), frag.next(16, &out));
}

test "fragmenter+reassembler: multi-fragment message, in-order" {
    var data: [50]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);

    var frag = Fragmenter.init(1, 7, &data);
    var reasm_buf: [50]u8 = undefined;
    var received: [50]bool = undefined;
    var reasm = Reassembler.init(&reasm_buf, &received);

    var out: [header_len + 20]u8 = undefined;
    var result: ?[]const u8 = null;
    var n_fragments: usize = 0;
    while (frag.next(20, &out)) |f| {
        n_fragments += 1;
        const hdr = try decodeHeader(f);
        result = try reasm.feed(hdr, f[header_len..]);
    }
    try testing.expectEqual(@as(usize, 3), n_fragments); // 20 + 20 + 10
    try testing.expectEqualSlices(u8, &data, result.?);
}

test "fragmenter+reassembler: out-of-order and duplicate fragments" {
    var data: [30]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(100 + i);

    var frag = Fragmenter.init(2, 1, &data);
    var out: [header_len + 10]u8 = undefined;
    var fragments = std.ArrayList([]u8).empty;
    defer fragments.deinit(testing.allocator);
    while (frag.next(10, &out)) |f| {
        const copy = try testing.allocator.dupe(u8, f);
        try fragments.append(testing.allocator, copy);
    }
    defer for (fragments.items) |f| testing.allocator.free(f);
    try testing.expectEqual(@as(usize, 3), fragments.items.len);

    var reasm_buf: [30]u8 = undefined;
    var received: [30]bool = undefined;
    var reasm = Reassembler.init(&reasm_buf, &received);

    // Feed out of order: 2, 0, then 1 again (duplicate) then 1.
    const order = [_]usize{ 2, 0, 1, 1 };
    var result: ?[]const u8 = null;
    for (order) |idx| {
        const f = fragments.items[idx];
        const hdr = try decodeHeader(f);
        result = try reasm.feed(hdr, f[header_len..]);
    }
    try testing.expectEqualSlices(u8, &data, result.?);
}

test "reassembler: new message_seq restarts reassembly" {
    var buf: [16]u8 = undefined;
    var received: [16]bool = undefined;
    var reasm = Reassembler.init(&buf, &received);

    const hdr_a = HandshakeHeader{ .msg_type = 1, .length = 16, .message_seq = 0, .fragment_offset = 0, .fragment_length = 4 };
    _ = try reasm.feed(hdr_a, "AAAA");

    // A fresh message_seq arrives before the previous one finished.
    const hdr_b = HandshakeHeader{ .msg_type = 1, .length = 4, .message_seq = 1, .fragment_offset = 0, .fragment_length = 4 };
    const result = try reasm.feed(hdr_b, "BBBB");
    try testing.expectEqualSlices(u8, "BBBB", result.?);
}

test "reassembler: inconsistent length is a typed error" {
    var buf: [16]u8 = undefined;
    var received: [16]bool = undefined;
    var reasm = Reassembler.init(&buf, &received);

    const hdr_a = HandshakeHeader{ .msg_type = 1, .length = 16, .message_seq = 0, .fragment_offset = 0, .fragment_length = 4 };
    _ = try reasm.feed(hdr_a, "AAAA");

    const hdr_b = HandshakeHeader{ .msg_type = 1, .length = 12, .message_seq = 0, .fragment_offset = 4, .fragment_length = 4 };
    try testing.expectError(error.InconsistentLength, reasm.feed(hdr_b, "BBBB"));
}

test "reassembler: fragment out of range is a typed error" {
    var buf: [8]u8 = undefined;
    var received: [8]bool = undefined;
    var reasm = Reassembler.init(&buf, &received);

    const hdr = HandshakeHeader{ .msg_type = 1, .length = 8, .message_seq = 0, .fragment_offset = 6, .fragment_length = 4 };
    try testing.expectError(error.FragmentOutOfRange, reasm.feed(hdr, "XXXX"));
}

test "reassembler: buffer too small for declared total length" {
    var buf: [4]u8 = undefined;
    var received: [4]bool = undefined;
    var reasm = Reassembler.init(&buf, &received);

    const hdr = HandshakeHeader{ .msg_type = 1, .length = 8, .message_seq = 0, .fragment_offset = 0, .fragment_length = 4 };
    try testing.expectError(error.BufferTooSmall, reasm.feed(hdr, "AAAA"));
}
