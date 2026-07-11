// SPDX-License-Identifier: MIT

//! dtls.record — RFC 9147 §4 record layer framing: the DTLSCiphertext
//! "unified header" (epoch bits, variable-length sequence number, optional
//! connection ID, optional length) and the legacy DTLSPlaintext header used
//! for epoch-0 unencrypted records (ClientHello / HelloRetryRequest, before
//! any cipher suite is negotiated — RFC 9147 §4, reusing RFC 6347 §4.1's
//! wire format for that one case).
//!
//! Pure framing: every function here operates on caller-supplied byte
//! slices and never touches key material. The unified header's
//! sequence-number bytes are treated as OPAQUE by this file — RFC 9147
//! §4.2.3 requires implementations to encrypt them, so by the time
//! `decodeUnified` sees a record they may already be a masked value;
//! masking/unmasking is `aead.zig`'s job. Full 48-bit sequence-number
//! reconstruction from the on-wire low bits (`reconstructSequenceNumber`)
//! IS implemented here, since it is pure windowing arithmetic (analogous to
//! QUIC's packet-number decoding, RFC 9000 §A.3, which RFC 9147 §4.3 points
//! to as the technique to use) — no cryptography involved.

const std = @import("std");

pub const RecordError = error{
    BufferTooShort,
    InvalidHeader,
    UnsupportedCidLength,
};

// ── unified header (RFC 9147 §4) ────────────────────────────────────────
//
// Wire layout of byte 0, MSB first:
//   bit 7 6 5 4 3 2 1 0
//       0 0 1 C S L E E
// C = connection ID present, S = sequence-number length (0=1 byte,
// 1=2 bytes), L = explicit length field present, E E = low 2 bits of the
// epoch (the full epoch is tracked out-of-band per RFC 9147 §4.1 — an
// endpoint only ever has a handful of live epochs, so 2 bits + local state
// disambiguates which one a record belongs to).

const fixed_mask: u8 = 0b1110_0000;
const fixed_value: u8 = 0b0010_0000;
const cid_bit: u8 = 0b0001_0000;
const seq_len_bit: u8 = 0b0000_1000;
const length_bit: u8 = 0b0000_0100;
const epoch_mask: u8 = 0b0000_0011;

pub const SeqNumLen = enum(u1) {
    short = 0, // 1 byte on the wire
    long = 1, // 2 bytes on the wire
};

pub const UnifiedHeader = struct {
    /// Low-order 2 bits of the epoch (see wire-layout note above).
    epoch_low: u2,
    seq_len: SeqNumLen,
    /// The on-wire sequence-number value (1 or 2 bytes per `seq_len`), a
    /// plaintext low-order value OR an AEAD-masked one (RFC 9147 §4.2.3) —
    /// this file doesn't know or care which; unmasking is `aead.zig`'s job.
    seq_wire: u16,
    /// Connection-ID bytes, present iff the C bit was set. `null` means no
    /// CID on this record.
    cid: ?[]const u8,
    /// Explicit record length, present iff the L bit was set. `null` means
    /// "the rest of the datagram" (RFC 9147 §4 permits omitting it for the
    /// last, or only, record in a UDP datagram).
    length: ?u16,
};

/// Encodes `hdr` into `out`, returning the slice of `out` actually used.
pub fn encodeUnified(hdr: UnifiedHeader, out: []u8) RecordError![]u8 {
    var needed: usize = 1;
    if (hdr.cid) |c| needed += c.len;
    needed += if (hdr.seq_len == .short) @as(usize, 1) else 2;
    if (hdr.length != null) needed += 2;
    if (out.len < needed) return error.BufferTooShort;

    var b: u8 = fixed_value;
    if (hdr.cid != null) b |= cid_bit;
    if (hdr.seq_len == .long) b |= seq_len_bit;
    if (hdr.length != null) b |= length_bit;
    b |= @as(u8, hdr.epoch_low);
    out[0] = b;

    var i: usize = 1;
    if (hdr.cid) |c| {
        @memcpy(out[i..][0..c.len], c);
        i += c.len;
    }
    switch (hdr.seq_len) {
        .short => {
            out[i] = @truncate(hdr.seq_wire);
            i += 1;
        },
        .long => {
            std.mem.writeInt(u16, out[i..][0..2], hdr.seq_wire, .big);
            i += 2;
        },
    }
    if (hdr.length) |len| {
        std.mem.writeInt(u16, out[i..][0..2], len, .big);
        i += 2;
    }
    return out[0..i];
}

pub const DecodedUnified = struct {
    hdr: UnifiedHeader,
    /// Bytes of `buf` consumed by the header (start of the remaining
    /// ciphertext, if `hdr.length` is `null` — otherwise the ciphertext is
    /// exactly `hdr.length` bytes starting here).
    consumed: usize,
};

/// Decodes a unified header from the front of `buf`. `negotiated_cid_len`
/// must be the CID length agreed out-of-band for this connection (0 if no
/// CID was negotiated); a record with the C bit set when none was
/// negotiated (or vice versa expected elsewhere) is `error.UnsupportedCidLength`.
pub fn decodeUnified(buf: []const u8, negotiated_cid_len: usize) RecordError!DecodedUnified {
    if (buf.len < 1) return error.BufferTooShort;
    const b = buf[0];
    if (b & fixed_mask != fixed_value) return error.InvalidHeader;
    const has_cid = (b & cid_bit) != 0;
    const seq_len: SeqNumLen = if ((b & seq_len_bit) != 0) .long else .short;
    const has_length = (b & length_bit) != 0;
    const epoch_low: u2 = @truncate(b & epoch_mask);

    var i: usize = 1;
    var cid: ?[]const u8 = null;
    if (has_cid) {
        if (negotiated_cid_len == 0) return error.UnsupportedCidLength;
        if (buf.len < i + negotiated_cid_len) return error.BufferTooShort;
        cid = buf[i..][0..negotiated_cid_len];
        i += negotiated_cid_len;
    }

    const seq_bytes: usize = if (seq_len == .short) 1 else 2;
    if (buf.len < i + seq_bytes) return error.BufferTooShort;
    const seq_wire: u16 = if (seq_len == .short) buf[i] else std.mem.readInt(u16, buf[i..][0..2], .big);
    i += seq_bytes;

    var length: ?u16 = null;
    if (has_length) {
        if (buf.len < i + 2) return error.BufferTooShort;
        length = std.mem.readInt(u16, buf[i..][0..2], .big);
        i += 2;
    }

    return .{
        .hdr = .{
            .epoch_low = epoch_low,
            .seq_len = seq_len,
            .seq_wire = seq_wire,
            .cid = cid,
            .length = length,
        },
        .consumed = i,
    };
}

// ── legacy plaintext header (epoch 0 only — RFC 9147 §4 / RFC 6347 §4.1) ─

pub const plaintext_header_len = 13; // 1 + 2 + 2 + 6 + 2

/// RFC 9147 §5.3: DTLS 1.3's ClientHello.legacy_version stays {254, 253}
/// ("DTLS 1.2") on the wire for backward/middlebox compatibility — actual
/// version negotiation happens via the `supported_versions` extension
/// (mirrors TLS 1.3's ClientHello.legacy_version = {3, 3}, RFC 8446 §4.1.2).
pub const legacy_version_dtls12 = [2]u8{ 0xFE, 0xFD };

pub const PlaintextHeader = struct {
    content_type: u8,
    legacy_version: [2]u8 = legacy_version_dtls12,
    epoch: u16,
    sequence_number: u48,
    length: u16,
};

pub fn encodePlaintext(hdr: PlaintextHeader, out: []u8) RecordError![]u8 {
    if (out.len < plaintext_header_len) return error.BufferTooShort;
    out[0] = hdr.content_type;
    out[1..3].* = hdr.legacy_version;
    std.mem.writeInt(u16, out[3..5], hdr.epoch, .big);
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, hdr.sequence_number, .big);
    @memcpy(out[5..11], seq_bytes[2..8]);
    std.mem.writeInt(u16, out[11..13], hdr.length, .big);
    return out[0..plaintext_header_len];
}

pub fn decodePlaintext(buf: []const u8) RecordError!PlaintextHeader {
    if (buf.len < plaintext_header_len) return error.BufferTooShort;
    var seq_bytes: [8]u8 = .{0} ** 8;
    @memcpy(seq_bytes[2..8], buf[5..11]);
    return .{
        .content_type = buf[0],
        .legacy_version = buf[1..3].*,
        .epoch = std.mem.readInt(u16, buf[3..5], .big),
        .sequence_number = @truncate(std.mem.readInt(u64, &seq_bytes, .big)),
        .length = std.mem.readInt(u16, buf[11..13], .big),
    };
}

// ── sequence-number reconstruction (RFC 9147 §4.3) ──────────────────────

/// Reconstructs the full 48-bit sequence number from the on-wire low-order
/// bits (`wire_low_bits`, already unmasked by `aead.zig` if the record used
/// sequence-number encryption), given the largest sequence number this
/// epoch has processed so far (`largest_seen`). Pure arithmetic — the
/// "closest candidate to `largest_seen + 1`" reconstruction technique RFC
/// 9147 §4.3 describes, structurally the same algorithm as QUIC's packet
/// number decoding (RFC 9000 Appendix A.3). No cryptography.
pub fn reconstructSequenceNumber(largest_seen: u48, seq_len: SeqNumLen, wire_low_bits: u16) u48 {
    const nbits: u6 = if (seq_len == .short) 8 else 16;
    const expected: u64 = @as(u64, largest_seen) + 1;
    const win: u64 = @as(u64, 1) << nbits;
    const hwin: u64 = win / 2;
    const mask: u64 = win - 1;
    const truncated: u64 = wire_low_bits;
    const max_seq: u64 = (1 << 48) - 1;

    const base = expected & ~mask;
    var candidate: u64 = base | truncated;

    if (candidate + hwin <= expected and candidate + win <= max_seq) {
        candidate += win;
    } else if (candidate > expected + hwin and candidate >= win) {
        candidate -= win;
    }
    return @intCast(@min(candidate, max_seq));
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "unified header: hand-built golden bytes, no CID, short seq, with length" {
    // epoch_low=1, seq_len=.short (S=0), length present (L=1), no CID (C=0):
    // byte0 = 0b001_0_0_1_01 = 0x20 | 0x04 | 0x01 = 0x25.
    const hdr = UnifiedHeader{ .epoch_low = 1, .seq_len = .short, .seq_wire = 0x2A, .cid = null, .length = 0x0010 };
    var buf: [8]u8 = undefined;
    const enc = try encodeUnified(hdr, &buf);
    try testing.expectEqualSlices(u8, &.{ 0x25, 0x2A, 0x00, 0x10 }, enc);

    const dec = try decodeUnified(enc, 0);
    try testing.expectEqual(@as(usize, 4), dec.consumed);
    try testing.expectEqual(@as(u2, 1), dec.hdr.epoch_low);
    try testing.expectEqual(SeqNumLen.short, dec.hdr.seq_len);
    try testing.expectEqual(@as(u16, 0x2A), dec.hdr.seq_wire);
    try testing.expectEqual(@as(?[]const u8, null), dec.hdr.cid);
    try testing.expectEqual(@as(?u16, 0x0010), dec.hdr.length);
}

test "unified header: hand-built golden bytes, with CID, long seq, no length" {
    // epoch_low=2 (0b10), seq_len=.long (S=1), CID present (C=1), no length (L=0):
    // byte0 = 0b001_1_1_0_10 = 0x20 | 0x10 | 0x08 | 0x02 = 0x3A.
    const cid = [_]u8{ 0xAA, 0xBB };
    const hdr = UnifiedHeader{ .epoch_low = 2, .seq_len = .long, .seq_wire = 0x1234, .cid = &cid, .length = null };
    var buf: [8]u8 = undefined;
    const enc = try encodeUnified(hdr, &buf);
    try testing.expectEqualSlices(u8, &.{ 0x3A, 0xAA, 0xBB, 0x12, 0x34 }, enc);

    const dec = try decodeUnified(enc, 2);
    try testing.expectEqual(@as(usize, 5), dec.consumed);
    try testing.expectEqual(@as(u2, 2), dec.hdr.epoch_low);
    try testing.expectEqual(SeqNumLen.long, dec.hdr.seq_len);
    try testing.expectEqual(@as(u16, 0x1234), dec.hdr.seq_wire);
    try testing.expectEqualSlices(u8, &cid, dec.hdr.cid.?);
    try testing.expectEqual(@as(?u16, null), dec.hdr.length);
}

test "unified header: rejects the wrong fixed bit pattern" {
    const buf = [_]u8{0x00};
    try testing.expectError(error.InvalidHeader, decodeUnified(&buf, 0));
}

test "unified header: CID bit set but no CID negotiated is a typed error" {
    const buf = [_]u8{ 0x30, 0xAA, 0x00 }; // C=1, S=0, L=0, epoch=0
    try testing.expectError(error.UnsupportedCidLength, decodeUnified(&buf, 0));
}

test "unified header: buffer too short is a typed error, not a panic" {
    const buf = [_]u8{0x24}; // L bit set, needs 2 more length bytes
    try testing.expectError(error.BufferTooShort, decodeUnified(&buf, 0));
}

test "unified header: encode buffer too small" {
    const hdr = UnifiedHeader{ .epoch_low = 0, .seq_len = .long, .seq_wire = 1, .cid = null, .length = 5 };
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.BufferTooShort, encodeUnified(hdr, &tiny));
}

test "plaintext header: hand-built golden bytes round-trip" {
    const hdr = PlaintextHeader{ .content_type = 22, .epoch = 0, .sequence_number = 1, .length = 42 };
    var buf: [plaintext_header_len]u8 = undefined;
    const enc = try encodePlaintext(hdr, &buf);
    // content_type=22, legacy_version={0xFE,0xFD}, epoch=0x0000,
    // seq=0x000000000001, length=0x002A.
    try testing.expectEqualSlices(u8, &.{ 22, 0xFE, 0xFD, 0x00, 0x00, 0, 0, 0, 0, 0, 1, 0x00, 0x2A }, enc);

    const dec = try decodePlaintext(enc);
    try testing.expectEqual(hdr.content_type, dec.content_type);
    try testing.expectEqual(hdr.legacy_version, dec.legacy_version);
    try testing.expectEqual(hdr.epoch, dec.epoch);
    try testing.expectEqual(hdr.sequence_number, dec.sequence_number);
    try testing.expectEqual(hdr.length, dec.length);
}

test "plaintext header: buffer too short" {
    var buf: [plaintext_header_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooShort, decodePlaintext(&buf));
}

test "reconstructSequenceNumber: no wraparound, exact low bits" {
    try testing.expectEqual(@as(u48, 300), reconstructSequenceNumber(299, .long, 300));
}

test "reconstructSequenceNumber: short (1-byte) window wraps forward" {
    // largest_seen=250, wire says low byte 5 -> the nearest candidate to
    // 251 with low byte 5 is 261 (250's own window rolled over), not 5.
    try testing.expectEqual(@as(u48, 261), reconstructSequenceNumber(250, .short, 5));
}

test "reconstructSequenceNumber: long (2-byte) window, same window as largest" {
    try testing.expectEqual(@as(u48, 0x10005), reconstructSequenceNumber(0x10000, .long, 5));
}

test "reconstructSequenceNumber: clamps at the 48-bit ceiling" {
    const max_seq: u48 = (1 << 48) - 1;
    const got = reconstructSequenceNumber(max_seq, .short, 0);
    try testing.expect(got <= max_seq);
}
