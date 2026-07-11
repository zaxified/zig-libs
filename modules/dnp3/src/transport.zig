// SPDX-License-Identifier: MIT

//! dnp3.transport — the Transport Function (IEEE 1815-2012 §8): a single
//! transport octet (FIN/FIR + a 6-bit sequence number) prepended to each
//! chunk of an application-layer fragment, so it can be segmented across
//! multiple data-link frames and reassembled on the other end.
//!
//! Transport octet layout: bit 0x80 = FIN (final segment of this fragment),
//! bit 0x40 = FIR (first segment of this fragment), bits 0x3F = a 6-bit
//! sequence number that starts at whatever the first (FIR) segment carries
//! and increments by 1 (mod 64) on every following segment of the same
//! fragment (§8.2.3). A single-segment fragment has both FIR and FIN set.
//!
//! `Segmenter`/`Reassembler` are pure, allocation-free, and operate on
//! caller-supplied buffers only — no I/O.

const std = @import("std");
const link = @import("link.zig");

/// Max application-fragment bytes per transport segment: the link layer's
/// max user data (`link.max_user_data_len`) minus the 1-byte transport header.
pub const max_segment_payload: usize = link.max_user_data_len - 1;

// ── transport octet ──────────────────────────────────────────────────────────

pub const TransportHeader = struct {
    fin: bool,
    fir: bool,
    seq: u6,

    pub fn toByte(self: TransportHeader) u8 {
        var b: u8 = @as(u8, self.seq);
        if (self.fin) b |= 0x80;
        if (self.fir) b |= 0x40;
        return b;
    }

    pub fn fromByte(b: u8) TransportHeader {
        return .{
            .fin = (b & 0x80) != 0,
            .fir = (b & 0x40) != 0,
            .seq = @truncate(b & 0x3F),
        };
    }
};

// ── segmentation ─────────────────────────────────────────────────────────────

/// Splits an application fragment into a sequence of transport segments
/// (1-byte header + up to `max_segment_payload` bytes each), one `next()`
/// call at a time. A zero-length fragment still produces exactly one
/// (FIR+FIN, empty-payload) segment.
pub const Segmenter = struct {
    data: []const u8,
    pos: usize = 0,
    seq: u6 = 0,
    done: bool = false,

    pub fn init(data: []const u8) Segmenter {
        return .{ .data = data };
    }

    /// Writes the next segment into `out` (must be >= 1 + max_segment_payload)
    /// and returns the slice of `out` used, or `null` once every segment of
    /// the fragment has been produced.
    pub fn next(self: *Segmenter, out: []u8) ?[]const u8 {
        if (self.done) return null;
        std.debug.assert(out.len >= 1 + max_segment_payload);

        const remaining = self.data.len - self.pos;
        const n = @min(remaining, max_segment_payload);
        const fir = self.pos == 0;
        const at_end = self.pos + n >= self.data.len;

        const hdr = TransportHeader{ .fin = at_end, .fir = fir, .seq = self.seq };
        out[0] = hdr.toByte();
        @memcpy(out[1..][0..n], self.data[self.pos..][0..n]);

        self.pos += n;
        self.seq +%= 1;
        if (at_end) self.done = true;
        return out[0 .. n + 1];
    }
};

// ── reassembly ───────────────────────────────────────────────────────────────

pub const ReassembleError = error{
    /// A segment arrived with FIR unset before any FIR segment started a
    /// fragment (or after the previous fragment already completed).
    UnexpectedContinuation,
    /// A non-FIR segment's sequence number isn't the previous one + 1 (mod 64).
    SequenceMismatch,
    /// The reassembly buffer is too small for the fragment so far.
    BufferTooSmall,
    /// A segment carried zero bytes (not even the transport header octet).
    EmptySegment,
};

/// Feeds transport segments (in link-frame arrival order) and reassembles
/// them into a caller-supplied buffer. A new FIR segment always restarts
/// reassembly (matching §8.2.3: a FIR segment begins a new fragment,
/// discarding any partially-received previous one).
pub const Reassembler = struct {
    buf: []u8,
    len: usize = 0,
    expected_seq: u6 = 0,
    have_first: bool = false,

    pub fn init(buf: []u8) Reassembler {
        return .{ .buf = buf };
    }

    /// Feeds one segment (1-byte transport header + payload, exactly what a
    /// decoded link frame's user data holds). Returns the complete
    /// reassembled fragment once a FIN segment is fed, `null` if more
    /// segments are still expected.
    pub fn feed(self: *Reassembler, segment: []const u8) ReassembleError!?[]const u8 {
        if (segment.len == 0) return error.EmptySegment;
        const hdr = TransportHeader.fromByte(segment[0]);
        const payload = segment[1..];

        if (hdr.fir) {
            self.len = 0;
            self.have_first = true;
            self.expected_seq = hdr.seq;
        } else {
            if (!self.have_first) return error.UnexpectedContinuation;
            self.expected_seq +%= 1;
        }
        if (hdr.seq != self.expected_seq) return error.SequenceMismatch;
        if (self.len + payload.len > self.buf.len) return error.BufferTooSmall;

        @memcpy(self.buf[self.len..][0..payload.len], payload);
        self.len += payload.len;

        if (hdr.fin) {
            self.have_first = false; // ready for the next fragment
            return self.buf[0..self.len];
        }
        return null;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "transport octet round-trip" {
    const h = TransportHeader{ .fin = true, .fir = true, .seq = 17 };
    const b = h.toByte();
    try testing.expectEqual(@as(u8, 0xC0 | 17), b);
    const back = TransportHeader.fromByte(b);
    try testing.expectEqual(h.fin, back.fin);
    try testing.expectEqual(h.fir, back.fir);
    try testing.expectEqual(h.seq, back.seq);
}

test "segmenter: empty fragment yields one FIR+FIN empty segment" {
    var seg = Segmenter.init(&.{});
    var buf: [1 + max_segment_payload]u8 = undefined;
    const s = seg.next(&buf).?;
    try testing.expectEqual(@as(usize, 1), s.len);
    const h = TransportHeader.fromByte(s[0]);
    try testing.expect(h.fir and h.fin);
    try testing.expectEqual(@as(?[]const u8, null), seg.next(&buf));
}

test "segmenter: single small fragment (one segment)" {
    var seg = Segmenter.init("hello");
    var buf: [1 + max_segment_payload]u8 = undefined;
    const s = seg.next(&buf).?;
    const h = TransportHeader.fromByte(s[0]);
    try testing.expect(h.fir and h.fin);
    try testing.expectEqual(@as(u6, 0), h.seq);
    try testing.expectEqualSlices(u8, "hello", s[1..]);
    try testing.expectEqual(@as(?[]const u8, null), seg.next(&buf));
}

test "segmenter+reassembler: multi-segment fragment round-trip" {
    var data: [max_segment_payload * 3 + 10]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    var seg = Segmenter.init(&data);
    var reasm_buf: [data.len]u8 = undefined;
    var reasm = Reassembler.init(&reasm_buf);

    var seg_buf: [1 + max_segment_payload]u8 = undefined;
    var result: ?[]const u8 = null;
    var segments: usize = 0;
    while (seg.next(&seg_buf)) |s| {
        segments += 1;
        result = try reasm.feed(s);
    }
    try testing.expectEqual(@as(usize, 4), segments); // 3 full + 1 partial
    try testing.expect(result != null);
    try testing.expectEqualSlices(u8, &data, result.?);
}

test "reassembler: sequence mismatch is a typed error, not a panic" {
    var buf: [64]u8 = undefined;
    var reasm = Reassembler.init(&buf);
    const first = TransportHeader{ .fin = false, .fir = true, .seq = 5 };
    var seg1: [3]u8 = .{ first.toByte(), 'a', 'b' };
    _ = try reasm.feed(&seg1);

    // Should be seq 6, feed seq 8 instead.
    const bad = TransportHeader{ .fin = true, .fir = false, .seq = 8 };
    var seg2: [2]u8 = .{ bad.toByte(), 'c' };
    try testing.expectError(error.SequenceMismatch, reasm.feed(&seg2));
}

test "reassembler: continuation before FIR is a typed error" {
    var buf: [64]u8 = undefined;
    var reasm = Reassembler.init(&buf);
    const cont = TransportHeader{ .fin = true, .fir = false, .seq = 3 };
    var seg: [2]u8 = .{ cont.toByte(), 'x' };
    try testing.expectError(error.UnexpectedContinuation, reasm.feed(&seg));
}

test "reassembler: new FIR restarts reassembly" {
    var buf: [64]u8 = undefined;
    var reasm = Reassembler.init(&buf);
    const first_a = TransportHeader{ .fin = false, .fir = true, .seq = 0 };
    var seg_a: [4]u8 = .{ first_a.toByte(), 'X', 'X', 'X' };
    try testing.expectEqual(@as(?[]const u8, null), try reasm.feed(&seg_a));

    // A fresh FIR arrives before the previous fragment finished -- discard it.
    const first_b = TransportHeader{ .fin = true, .fir = true, .seq = 9 };
    var seg_b: [3]u8 = .{ first_b.toByte(), 'o', 'k' };
    const result = try reasm.feed(&seg_b);
    try testing.expectEqualSlices(u8, "ok", result.?);
}

test "reassembler: buffer too small" {
    var buf: [2]u8 = undefined;
    var reasm = Reassembler.init(&buf);
    const first = TransportHeader{ .fin = true, .fir = true, .seq = 0 };
    var seg: [4]u8 = .{ first.toByte(), 'a', 'b', 'c' };
    try testing.expectError(error.BufferTooSmall, reasm.feed(&seg));
}

test "reassembler: empty segment is a typed error" {
    var buf: [8]u8 = undefined;
    var reasm = Reassembler.init(&buf);
    try testing.expectError(error.EmptySegment, reasm.feed(&.{}));
}
