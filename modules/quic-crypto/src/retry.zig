// SPDX-License-Identifier: MIT

//! quic-crypto.retry — the Retry Integrity Tag: RFC 9001 §5.8 (QUIC v1) and
//! RFC 9369 §3.3.3 (QUIC v2). The tag is AEAD_AES_128_GCM over an EMPTY
//! plaintext with a fixed per-version key and nonce; the associated data is
//! the Retry Pseudo-Packet, i.e. `ODCID Length (1) || ODCID || Retry packet
//! without its 16-byte tag`. A server appends the tag to the Retry it sends;
//! a client verifies it before acting on the Retry's token / SCID.
//!
//! Engine-agnostic like the rest of the module: the caller supplies the
//! Original Destination Connection ID (the DCID of the Initial this Retry
//! answers) and the Retry packet bytes; nothing is parsed here. The pseudo
//! packet is assembled in a fixed stack buffer (`max_pseudo_packet_len`), so
//! there is no allocator.
//!
//! RFC 9369 §4.1 requires a server to send Retry with the ORIGINAL version and
//! a client to ignore Retry in any other; choosing the version is the
//! transport's job — pass the version of the Retry packet's long header.

const std = @import("std");
const version = @import("version.zig");

pub const Version = version.Version;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// The Retry Integrity Tag is 128 bits (RFC 9001 §5.8).
pub const tag_length = Aes128Gcm.tag_length;

/// Capacity of the internal pseudo-packet buffer: 1 (ODCID length) + ODCID
/// (<= 255 by its 8-bit length) + Retry-without-tag. 2048 covers a 1-byte
/// ODCID length, any ODCID and a Retry that fits a 1500-byte datagram.
pub const max_pseudo_packet_len = 2048;

pub const RetryError = error{
    /// The packet handed to `verifyRetryTag` is shorter than the tag.
    PacketTooShort,
    /// ODCID + Retry packet do not fit `max_pseudo_packet_len`, or the ODCID
    /// is longer than the 8-bit length field can express (255).
    PacketTooLong,
    /// The Retry Integrity Tag does not verify (corrupted, wrong ODCID, wrong
    /// version, or forged) — drop the Retry.
    IntegrityFailed,
};

/// Build the Retry Pseudo-Packet (RFC 9001 Figure 8) into `buf`; returns the
/// used prefix.
fn pseudoPacket(buf: *[max_pseudo_packet_len]u8, odcid: []const u8, retry_no_tag: []const u8) RetryError![]const u8 {
    if (odcid.len > 255) return error.PacketTooLong;
    const n = 1 + odcid.len + retry_no_tag.len;
    if (n > buf.len) return error.PacketTooLong;
    buf[0] = @intCast(odcid.len);
    @memcpy(buf[1..][0..odcid.len], odcid);
    @memcpy(buf[1 + odcid.len ..][0..retry_no_tag.len], retry_no_tag);
    return buf[0..n];
}

/// RFC 9001 §5.8: compute the Retry Integrity Tag. `odcid` is the
/// Destination Connection ID of the client Initial this Retry responds to;
/// `retry_no_tag` is the whole Retry packet WITHOUT the tag (first byte
/// through the end of the Retry Token). The server appends the returned 16
/// bytes to `retry_no_tag`.
pub fn computeRetryTag(
    ver: Version,
    odcid: []const u8,
    retry_no_tag: []const u8,
) RetryError![tag_length]u8 {
    var buf: [max_pseudo_packet_len]u8 = undefined;
    const ad = try pseudoPacket(&buf, odcid, retry_no_tag);
    var tag: [tag_length]u8 = undefined;
    var no_ciphertext: [0]u8 = .{};
    Aes128Gcm.encrypt(&no_ciphertext, &tag, "", ad, ver.retryNonce().*, ver.retryKey().*);
    return tag;
}

/// RFC 9001 §5.8: verify a received Retry packet. `retry_packet` is the
/// complete packet INCLUDING its trailing 16-byte tag; `odcid` is the DCID of
/// the first Initial this client sent. Returns `error.IntegrityFailed` (never
/// a panic) on any mismatch; the tag comparison is constant-time (std AEAD).
pub fn verifyRetryTag(
    ver: Version,
    odcid: []const u8,
    retry_packet: []const u8,
) RetryError!void {
    if (retry_packet.len < tag_length) return error.PacketTooShort;
    const body_len = retry_packet.len - tag_length;
    var buf: [max_pseudo_packet_len]u8 = undefined;
    const ad = try pseudoPacket(&buf, odcid, retry_packet[0..body_len]);
    const tag: [tag_length]u8 = retry_packet[body_len..][0..tag_length].*;
    var no_plaintext: [0]u8 = .{};
    Aes128Gcm.decrypt(&no_plaintext, "", tag, ad, ver.retryNonce().*, ver.retryKey().*) catch
        return error.IntegrityFailed;
}

// ── tests ────────────────────────────────────────────────────────────────
//
// The Retry packets of RFC 9001 Appendix A.4 (v1) and RFC 9369 Appendix A.4
// (v2), byte-exact, both answering the client Initial of App. A.2 whose
// Destination Connection ID is 0x8394c8f03e515708. Hex copied from
// https://www.rfc-editor.org/rfc/rfc9001.txt / rfc9369.txt (the plain-text
// copies carry no page breaks, so sections are cited instead of pages).

const testing = std.testing;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const rfc_odcid = hexTo(8, "8394c8f03e515708");

// RFC 9001 Appendix A.4 "Retry" — full Retry packet incl. the 16-byte tag.
const rfc9001_a4_retry = hexTo(36, "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
// RFC 9369 Appendix A.4 "Retry" — full Retry packet incl. the 16-byte tag.
const rfc9369_a4_retry = hexTo(36, "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d9555436" ++ "65dcc7b6");

test "RFC 9001 App. A.4: v1 Retry tag is recomputed byte-exact" {
    const body = rfc9001_a4_retry[0 .. rfc9001_a4_retry.len - tag_length];
    const tag = try computeRetryTag(.v1, &rfc_odcid, body);
    try testing.expectEqualSlices(u8, rfc9001_a4_retry[body.len..], &tag);
    try testing.expectEqualSlices(u8, &hexTo(16, "04a265ba2eff4d829058fb3f0f2496ba"), &tag);
}

test "RFC 9001 App. A.4: the published v1 Retry packet verifies" {
    try verifyRetryTag(.v1, &rfc_odcid, &rfc9001_a4_retry);
}

test "RFC 9369 App. A.4: v2 Retry tag is recomputed byte-exact" {
    const body = rfc9369_a4_retry[0 .. rfc9369_a4_retry.len - tag_length];
    const tag = try computeRetryTag(.v2, &rfc_odcid, body);
    try testing.expectEqualSlices(u8, rfc9369_a4_retry[body.len..], &tag);
    try testing.expectEqualSlices(u8, &hexTo(16, "c8646ce8bfe33952d955543665dcc7b6"), &tag);
}

test "RFC 9369 App. A.4: the published v2 Retry packet verifies" {
    try verifyRetryTag(.v2, &rfc_odcid, &rfc9369_a4_retry);
}

test "Retry tag: a v1 tag fails under v2 and vice versa" {
    try testing.expectError(error.IntegrityFailed, verifyRetryTag(.v2, &rfc_odcid, &rfc9001_a4_retry));
    try testing.expectError(error.IntegrityFailed, verifyRetryTag(.v1, &rfc_odcid, &rfc9369_a4_retry));
}

test "Retry tag: any flipped bit of ODCID, packet body or tag fails" {
    for ([_]struct { v: Version, pkt: [36]u8 }{
        .{ .v = .v1, .pkt = rfc9001_a4_retry },
        .{ .v = .v2, .pkt = rfc9369_a4_retry },
    }) |c| {
        // ODCID: every bit.
        for (0..rfc_odcid.len) |i| for (0..8) |b| {
            var o = rfc_odcid;
            o[i] ^= @as(u8, 1) << @intCast(b);
            try testing.expectError(error.IntegrityFailed, verifyRetryTag(c.v, &o, &c.pkt));
        };
        // Packet (body and tag): every bit.
        for (0..c.pkt.len) |i| for (0..8) |b| {
            var p = c.pkt;
            p[i] ^= @as(u8, 1) << @intCast(b);
            try testing.expectError(error.IntegrityFailed, verifyRetryTag(c.v, &rfc_odcid, &p));
        };
        // ODCID of the wrong length (truncated / extended) also fails.
        try testing.expectError(error.IntegrityFailed, verifyRetryTag(c.v, rfc_odcid[0..7], &c.pkt));
        try testing.expectError(error.IntegrityFailed, verifyRetryTag(c.v, &(rfc_odcid ++ [_]u8{0}), &c.pkt));
    }
}

test "Retry tag: length limits are typed errors, not panics" {
    try testing.expectError(error.PacketTooShort, verifyRetryTag(.v1, &rfc_odcid, rfc9001_a4_retry[0..15]));
    var big: [max_pseudo_packet_len]u8 = undefined;
    @memset(&big, 0);
    try testing.expectError(error.PacketTooLong, computeRetryTag(.v1, &rfc_odcid, &big));
    var long_odcid: [256]u8 = undefined;
    @memset(&long_odcid, 0);
    try testing.expectError(error.PacketTooLong, computeRetryTag(.v1, &long_odcid, ""));
    // Boundary: exactly max_pseudo_packet_len is accepted, one octet more is
    // not (mutation run 2026-10-05: the 2057-octet case above could not tell
    // `>` from an off-by-one, which overruns the stack buffer).
    _ = try computeRetryTag(.v1, &rfc_odcid, big[0 .. max_pseudo_packet_len - 1 - rfc_odcid.len]);
    try testing.expectError(error.PacketTooLong, computeRetryTag(.v1, &rfc_odcid, big[0 .. max_pseudo_packet_len - rfc_odcid.len]));
}

test "Retry tag: empty ODCID and empty token round-trip (compute then verify)" {
    // Fresh (non-RFC) input: zero-length ODCID (valid, RFC 9000 §7.2).
    const body = hexTo(7, "ff000000010000"); // no dcid, no scid, no token
    var pkt: [7 + tag_length]u8 = undefined;
    @memcpy(pkt[0..7], &body);
    const tag = try computeRetryTag(.v1, "", &body);
    @memcpy(pkt[7..], &tag);
    try verifyRetryTag(.v1, "", &pkt);
}
