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
    /// Bytes of `buf` consumed by the header — where the ciphertext starts.
    ///
    /// ⚠ `hdr.length`, when present, is the peer's DECLARED body length and
    /// is NOT reconciled against `buf` here: this decodes a header and is
    /// called on header-only buffers (see this file's round-trip tests), so
    /// it cannot require the body. **A caller slicing
    /// `buf[consumed..][0..hdr.length]` must first check
    /// `buf.len >= consumed + hdr.length`** — unchecked, the 4-byte datagram
    /// `25 2A FF FF` yields `consumed = 4, length = 65535` and the slice runs
    /// 64 KiB past the receive buffer, which in ReleaseFast is not a bounds
    /// panic but heap fed to the AEAD, whose pass/fail is then an oracle on
    /// it. Every caller in this module does check (`Connection.zig`'s
    /// `recv`/`unprotectRecord`, `recordLen`); this note is here so the next
    /// one does too.
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
const fuzz_corpus = @import("fuzz_corpus.zig");

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

// ── fuzz: record headers off the wire, never panic ──────────────────────────
//
// `decodeUnified`/`decodePlaintext` are the very first bytes this module (or
// any DTLS implementation) touches on a received UDP datagram — from an
// unauthenticated, potentially hostile peer, before any handshake state
// exists. `decodeUnified` is gated by a 3-bit fixed pattern in byte 0, so
// pure random bytes fail that check almost every time.
//
// ⛔ Both harnesses used to open with
//
//     smith.bytes(&buf);
//     const len = smith.valueRangeAtMost(u8, 0, buf.len);
//
// and `bytes` takes `@min(buf.len, in.len)` octets, leaving the ranged draw
// with fewer than the eight it reads as a little-endian `u64` — so it returned
// the range MINIMUM and `len` was 0 on every input. Both decoders were handed
// an empty slice, for ever, and outside `--fuzz` the runner replays only the
// declared corpus plus one empty input, so "for ever" was literally one call
// each. Measured 2026-09-07 over the corpora below: **0 of 30 / 0 of 15 seeds
// non-empty and 0 headers decoded before; 30 of 30 and 15 of 15 non-empty, 30
// and 15 decoded after.**
//
// The knobs went the same way. `boolWeighted(1, 6)` (bias byte 0 into the
// fixed pattern) and `valueRangeAtMost(u8, 0, 4)` (the negotiated CID length)
// are both drawn AFTER the byte draw, which has consumed the input, so the
// bias branch had never executed once and `cid_len` was 0 on every call — the
// CID arm of `decodeUnified`, and with it `error.UnsupportedCidLength`, was
// unreachable from this harness. They now come out of one full-width
// `smith.value(u64)`, which is faithful (`Smith` splits a 64-bit scalar into
// one chunk whose weights span the whole range), carried in the seed's tail.

/// Recorded datagrams, in the format `Smith.slice` reads, with the knob word
/// the draws after the slice read out of the tail.
///
/// ⭐ Built from `testdata/wolfssl_transcript.txt` rather than hand-written:
/// these are the octets a real wolfSSL 5.9.1 put on a socket, and the module
/// already fails loudly (`wolfssl_replay.zig`) if they stop being what it
/// speaks. A hand-edited header would have been refused by the fixed-bit gate
/// or the length check and the corpus would have measured the refusal path.
const RecordCorpus = struct {
    unified: fuzz_corpus.Store(8192, 128) = .{},
    plaintext: fuzz_corpus.Store(8192, 128) = .{},

    /// `knobs`: the low octet is the negotiated CID length, bit 8 forces byte 0
    /// into the fixed pattern. A seed with no tail reads 0 for both, which is
    /// the right default for a recorded record — it already carries the
    /// pattern, and the connection it came from negotiated no CID.
    const cid_len_2 = 0x02;
    const force_pattern = 0x100;

    fn build(self: *RecordCorpus) []const []const u8 {
        var dg: [fuzz_corpus.max_datagram]u8 = undefined;
        var it: fuzz_corpus.DatagramIterator = .{};
        while (it.next(&dg)) |d| {
            if (d.len == 0) continue;
            // One record's worth of leading octets is all a header decoder
            // reads; the rest of the datagram is a body neither function looks
            // at. 24 octets covers the longest header (1 + 2 CID + 2 seq + 2
            // length) with room to spare.
            const head = d[0..@min(d.len, 24)];
            if (head[0] & fixed_mask == fixed_value) {
                self.unified.pushUnique(head, null);
            } else {
                self.plaintext.pushUnique(head, null);
            }
        }

        // ⭐ The CID arm, which no recording can supply: this module has never
        // negotiated a connection ID with wolfSSL, so every recorded record has
        // C=0 and the whole `has_cid` branch — including
        // `error.UnsupportedCidLength` — was outside the corpus. These come
        // from the file's OWN encoder, so they track `encodeUnified` instead of
        // freezing a paste of its output.
        var enc: [16]u8 = undefined;
        const cid = [_]u8{ 0xAA, 0xBB };
        for ([_]SeqNumLen{ .short, .long }) |sl| {
            for ([_]?u16{ null, 0x0010 }) |len| {
                const h = encodeUnified(.{
                    .epoch_low = 3,
                    .seq_len = sl,
                    .seq_wire = 0x1234,
                    .cid = &cid,
                    .length = len,
                }, &enc) catch continue;
                self.unified.push(h, cid_len_2);
                // The same header with NO CID negotiated: the refusal.
                self.unified.push(h, null);
            }
        }

        // The shapes neither a recording nor the encoder produces.
        self.unified.push(&.{0x00}, null); // wrong fixed pattern
        self.unified.push(&.{0x24}, null); // L=1, the two length octets missing
        self.unified.push(&.{ 0x30, 0xAA }, cid_len_2); // C=1, CID truncated
        self.unified.push(&.{ 0x2F, 0xFF, 0xFF, 0xFF, 0xFF }, force_pattern | cid_len_2);
        self.plaintext.push(&.{ 22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0x00 }, null); // 12 octets: one short
        return self.unified.corpus();
    }
};

test "fuzz: decodeUnified never panics on arbitrary bytes" {
    var corpus: RecordCorpus = .{};
    try testing.fuzz({}, fuzzDecodeUnified, .{ .corpus = corpus.build() });
}

fn fuzzDecodeUnified(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length — see the note above this section for the measurement.
    var buf: [64]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const knobs = smith.value(u64); // full width: faithful, unlike a ranged draw
    if (len > 0 and knobs & RecordCorpus.force_pattern != 0) {
        buf[0] = (buf[0] & ~fixed_mask) | fixed_value;
    }
    _ = decodeUnified(buf[0..len], @as(usize, @truncate(knobs)) % 5) catch return;
}

test "fuzz: decodePlaintext never panics on arbitrary bytes" {
    var corpus: RecordCorpus = .{};
    _ = corpus.build();
    try testing.fuzz({}, fuzzDecodePlaintext, .{ .corpus = corpus.plaintext.corpus() });
}

fn fuzzDecodePlaintext(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    const len: usize = smith.slice(&buf);
    _ = decodePlaintext(buf[0..len]) catch return;
}

test "corpus: every record seed reaches its decoder, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpora the harnesses get. `nonempty` is the reach claim and the
    // only check that notices a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently.
    //
    // The second numbers are what the first cannot say. `decodeUnified`
    // ACCEPTS the single octet 0x20 — a one-byte datagram is a legal
    // "epoch 0, 1-octet sequence number, no CID, no length" header — so a
    // "decoded" count alone would score a harness that walks nothing as a
    // success. `consumed` is the octets the header walk actually crossed, and
    // `with_cid` is the arm the collapsed `cid_len` draw made unreachable.
    var corpus: RecordCorpus = .{};
    const unified = corpus.build();

    var nonempty: usize = 0;
    var decoded: usize = 0;
    var consumed: usize = 0;
    var with_cid: usize = 0;
    var with_length: usize = 0;
    for (unified) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const knobs = smith.value(u64);
        if (len > 0 and knobs & RecordCorpus.force_pattern != 0) {
            buf[0] = (buf[0] & ~fixed_mask) | fixed_value;
        }
        const d = decodeUnified(buf[0..len], @as(usize, @truncate(knobs)) % 5) catch continue;
        decoded += 1;
        consumed += d.consumed;
        if (d.hdr.cid != null) with_cid += 1;
        if (d.hdr.length != null) with_length += 1;
    }
    try testing.expectEqual(unified.len, nonempty);
    try testing.expectEqual(@as(usize, 85), decoded);
    try testing.expectEqual(@as(usize, 399), consumed);
    try testing.expectEqual(@as(usize, 4), with_cid);
    try testing.expectEqual(@as(usize, 83), with_length);

    var p_nonempty: usize = 0;
    var p_decoded: usize = 0;
    var handshake_records: usize = 0;
    var declared: usize = 0;
    for (corpus.plaintext.corpus()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) p_nonempty += 1;
        const h = decodePlaintext(buf[0..len]) catch continue;
        p_decoded += 1;
        if (h.content_type == 22) handshake_records += 1;
        declared += h.length;
    }
    try testing.expectEqual(corpus.plaintext.n, p_nonempty);
    try testing.expectEqual(@as(usize, 21), p_decoded);
    try testing.expectEqual(@as(usize, 21), handshake_records);
    try testing.expectEqual(@as(usize, 9783), declared);

    // Nothing was dropped for capacity: a dropped frame is a corpus entry that
    // silently does not exist.
    try testing.expectEqual(@as(usize, 0), corpus.unified.dropped);
    try testing.expectEqual(@as(usize, 0), corpus.plaintext.dropped);
}
