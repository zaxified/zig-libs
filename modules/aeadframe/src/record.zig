// SPDX-License-Identifier: MIT

//! Record wire format + nonce derivation for `aeadframe`.
//!
//! A sealed record is `header ‖ ciphertext ‖ tag`, laid out big-endian:
//!
//! ```
//!   offset  size  field
//!   0       1     version   (currently 1)
//!   1       4     epoch     (u32, big-endian)
//!   5       8     seq       (u64, big-endian)
//!   13      N     ciphertext (N = plaintext length; may be 0)
//!   13+N    16    tag       (AEAD authentication tag)
//! ```
//!
//! **Padded records (version 2, opt-in on both ends).** A record sealed with
//! `Sealer.sealPadded` carries `version = 2` and its encrypted body is
//! `plaintext ‖ 0x00 × pad ‖ pad (u16, big-endian)`: the zero padding and the
//! two-byte pad length sit INSIDE the AEAD, so a traffic observer sees only the
//! padded size (TLS 1.3 / DTLS 1.3 record padding, with ESP's explicit Pad
//! Length trailer to delimit it, since this format has no content-type byte).
//! Header, nonce and tag are exactly as for version 1; `parse` keeps refusing
//! version 2 and only `parseWith(…, true)` (`Opener.allow_padding`) reads it.
//!
//! There is deliberately **no explicit ciphertext-length field**: the
//! ciphertext length is recovered as `record.len - overhead`, so a
//! length-field-vs-actual-length mismatch is not a reachable state. `parse`
//! is total over arbitrary bytes — a short or wrong-version record yields a
//! typed error, never an out-of-bounds read.

const std = @import("std");

/// Current wire version. A record whose first byte differs is rejected.
pub const version: u8 = 1;

/// Wire version of a padded record (see the module comment). Never produced
/// unless the caller asks for padding with `Sealer.sealPadded`.
pub const version_padded: u8 = 2;

/// Bytes the pad-length trailer of a padded record occupies inside the body.
pub const pad_trailer_len: usize = 2;

/// Fixed header size: version(1) + epoch(4) + seq(8).
pub const header_len: usize = 13;

/// AEAD tag size (both instantiations use a 16-byte tag).
pub const tag_len: usize = 16;

/// Bytes a record carries beyond its plaintext: header + tag.
pub const overhead: usize = header_len + tag_len;

pub const ParseError = error{
    /// Fewer bytes than the minimum record (`overhead`), i.e. truncated.
    Truncated,
    /// First byte is not `version`.
    UnsupportedVersion,
};

/// The two counters that pin a record to a unique nonce under one key.
pub const Header = struct {
    epoch: u32,
    seq: u64,

    /// Serialize the 13-byte header into `out`.
    pub fn encode(h: Header, out: *[header_len]u8) void {
        h.encodeVersion(out, version);
    }

    /// As `encode`, for a padded record (`version_padded`).
    pub fn encodePadded(h: Header, out: *[header_len]u8) void {
        h.encodeVersion(out, version_padded);
    }

    fn encodeVersion(h: Header, out: *[header_len]u8, v: u8) void {
        out[0] = v;
        std.mem.writeInt(u32, out[1..5], h.epoch, .big);
        std.mem.writeInt(u64, out[5..13], h.seq, .big);
    }
};

/// Result of parsing an untrusted record: the validated header plus the byte
/// spans of the ciphertext and tag within the original slice.
pub const Parsed = struct {
    header: Header,
    ct_off: usize,
    ct_len: usize,
    tag_off: usize,
    /// True for a version-2 record: the body is `plaintext ‖ zeros ‖ pad(u16)`.
    padded: bool = false,
};

/// Parse and bounds-check the header of an untrusted record. Validates the
/// version and the minimum length; does NOT touch the AEAD (auth happens in
/// the channel layer). Total: any byte slice either parses to a `Parsed` or
/// returns a typed error.
pub fn parse(record: []const u8) ParseError!Parsed {
    return parseWith(record, false);
}

/// `parse`, additionally accepting `version_padded` when `allow_padded`. A
/// padded record must hold at least its two-byte pad-length trailer
/// (`Truncated` otherwise). With `allow_padded = false` this is `parse`.
pub fn parseWith(record: []const u8, allow_padded: bool) ParseError!Parsed {
    if (record.len < overhead) return error.Truncated;
    const padded = allow_padded and record[0] == version_padded;
    if (record[0] != version and !padded) return error.UnsupportedVersion;
    if (padded and record.len < overhead + pad_trailer_len) return error.Truncated;
    const epoch = std.mem.readInt(u32, record[1..5], .big);
    const seq = std.mem.readInt(u64, record[5..13], .big);
    const ct_len = record.len - overhead;
    return .{
        .header = .{ .epoch = epoch, .seq = seq },
        .ct_off = header_len,
        .ct_len = ct_len,
        .tag_off = header_len + ct_len,
        .padded = padded,
    };
}

/// The pad length that rounds a padded body (`pt_len` plus the pad-length
/// trailer) up to a multiple of `block` bytes, the smallest one (OpenSSL's
/// `SSL_CTX_set_block_padding` shape: a record's inner plaintext is rounded to
/// a block). `block <= 1` gives 0. The result is below `block`, so it fits
/// `Sealer.sealPadded`'s `u16` whenever `block <= 65535`; a larger block is
/// clamped to the `u16` ceiling.
pub fn padForBlock(pt_len: usize, block: usize) u16 {
    if (block <= 1) return 0;
    const used = (pt_len + pad_trailer_len) % block;
    const pad = if (used == 0) 0 else block - used;
    return @intCast(@min(pad, std.math.maxInt(u16)));
}

/// Deterministic 12-byte AEAD nonce for `(epoch, seq)`:
/// `epoch` big-endian in the high 4 bytes, `seq` big-endian in the low 8.
///
/// This map from `(u32, u64)` to `[12]u8` is **injective**: distinct
/// `(epoch, seq)` pairs always produce distinct nonces (the two fields occupy
/// disjoint, fixed byte ranges). That injectivity is the whole nonce-safety
/// argument — see SPEC.md.
pub fn deriveNonce(epoch: u32, seq: u64) [12]u8 {
    var n: [12]u8 = undefined;
    std.mem.writeInt(u32, n[0..4], epoch, .big);
    std.mem.writeInt(u64, n[4..12], seq, .big);
    return n;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "nonce layout KAT (pure, hand-verifiable): epoch high, seq low, big-endian" {
    const n = deriveNonce(0x01020304, 0x05060708_090A0B0C);
    const expect = [12]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    try testing.expectEqualSlices(u8, &expect, &n);
}

test "nonce derivation is injective over (epoch, seq)" {
    // Same seq, different epoch -> different nonce (epoch is in the nonce).
    try testing.expect(!std.mem.eql(u8, &deriveNonce(0, 5), &deriveNonce(1, 5)));
    // Same epoch, different seq -> different nonce.
    try testing.expect(!std.mem.eql(u8, &deriveNonce(7, 5), &deriveNonce(7, 6)));
    // A small exhaustive sweep: all pairs distinct.
    var seen = std.AutoHashMap([12]u8, void).init(testing.allocator);
    defer seen.deinit();
    for (0..8) |e| {
        for (0..64) |s| {
            const n = deriveNonce(@intCast(e), s);
            try testing.expect(seen.get(n) == null);
            try seen.put(n, {});
        }
    }
}

test "header encode round-trips through parse" {
    var buf: [overhead]u8 = undefined; // empty-plaintext record
    const h = Header{ .epoch = 0xDEADBEEF, .seq = 0x0102030405060708 };
    h.encode(buf[0..header_len]);
    @memset(buf[header_len..], 0); // tag bytes irrelevant to parse
    const p = try parse(&buf);
    try testing.expectEqual(h.epoch, p.header.epoch);
    try testing.expectEqual(h.seq, p.header.seq);
    try testing.expectEqual(@as(usize, 0), p.ct_len);
}

test "parse rejects truncated and wrong-version records" {
    var buf: [overhead]u8 = undefined;
    @memset(&buf, 0);
    buf[0] = version;
    try testing.expectError(error.Truncated, parse(buf[0 .. overhead - 1]));
    try testing.expectError(error.Truncated, parse(buf[0..0]));
    buf[0] = version +% 1;
    try testing.expectError(error.UnsupportedVersion, parse(&buf));
}
