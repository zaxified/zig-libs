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
//! There is deliberately **no explicit ciphertext-length field**: the
//! ciphertext length is recovered as `record.len - overhead`, so a
//! length-field-vs-actual-length mismatch is not a reachable state. `parse`
//! is total over arbitrary bytes — a short or wrong-version record yields a
//! typed error, never an out-of-bounds read.

const std = @import("std");

/// Current wire version. A record whose first byte differs is rejected.
pub const version: u8 = 1;

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
        out[0] = version;
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
};

/// Parse and bounds-check the header of an untrusted record. Validates the
/// version and the minimum length; does NOT touch the AEAD (auth happens in
/// the channel layer). Total: any byte slice either parses to a `Parsed` or
/// returns a typed error.
pub fn parse(record: []const u8) ParseError!Parsed {
    if (record.len < overhead) return error.Truncated;
    if (record[0] != version) return error.UnsupportedVersion;
    const epoch = std.mem.readInt(u32, record[1..5], .big);
    const seq = std.mem.readInt(u64, record[5..13], .big);
    const ct_len = record.len - overhead;
    return .{
        .header = .{ .epoch = epoch, .seq = seq },
        .ct_off = header_len,
        .ct_len = ct_len,
        .tag_off = header_len + ct_len,
    };
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
