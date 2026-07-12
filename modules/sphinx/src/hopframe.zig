// SPDX-License-Identifier: MIT
//! BOLT#4 "Packet Structure" / "Packet Construction": the per-hop framing
//! inside the 1300-byte `hop_payloads` field — `bigsize(length) ‖ payload
//! ‖ hmac(32)`, repeated per hop, plus the "right-shift by shift_size" /
//! "left-shift" mechanics `construct`/`process` drive. This is REAL,
//! keyless wire-shape logic: it never touches a shared secret, a
//! ChaCha20 keystream, or an HMAC computation — those are `core.zig`'s
//! job. What lives here is purely "where do the bytes go in the
//! 1300-byte buffer."
//!
//! From BOLT#4 "Packet Construction": "`shift_size` is defined as the
//! length of the `hop_payload` plus the bigsize encoding of the length and
//! the length of that HMAC. Thus if the payload length is `l` then the
//! `shift_size` is `1 + l + 32` for `l < 253`, otherwise `3 + l + 32` due
//! to the bigsize encoding of `l`." (253 == BOLT#1 bigsize's `0xfd`
//! threshold — see `bigsize.zig`.)

const std = @import("std");
const bigsize = @import("bigsize.zig");

pub const hop_payloads_len: usize = 1300;
pub const hmac_len: usize = 32;

/// `bigsize(payload_len) ++ payload ++ hmac(32)`'s total on-wire size for a
/// hop whose TLV `payload` is `payload_len` bytes — i.e. the number of
/// bytes `hop_payloads` is right-shifted by by `construct` (or left-shifted
/// by `process`) for this one hop. BOLT#4 reserves payload lengths 0 and 1
/// (a real `payload` TLV stream is never shorter than 2 bytes: "Since no
/// `payload` TLV value can ever be shorter than 2 bytes, `length` values of
/// 0 and 1 are reserved"), enforced by `writeHopFrame`/`readHopFrame` below,
/// not by this pure arithmetic helper.
pub fn shiftSize(payload_len: usize) usize {
    return bigsize.encodedLength(@as(u64, payload_len)) + payload_len + hmac_len;
}

pub const FrameError = error{
    /// A `payload` of length 0 or 1 (BOLT#4: reserved, "0 indicated a
    /// legacy format no longer supported, and 1 is reserved for future
    /// use").
    ReservedPayloadLength,
    /// The frame (`bigsize(len) ++ payload ++ hmac`) does not fit in the
    /// destination buffer.
    BufferTooSmall,
};

/// Write one hop's frame — `bigsize(payload.len) ++ payload ++ hmac` — into
/// the FRONT of `dest`, returning the number of bytes written
/// (`shiftSize(payload.len)`). Pure byte-shape assembly: `dest` is normally
/// the front of a 1300-byte `hop_payloads` buffer that has already been
/// right-shifted by this same amount (that shift is the caller's job, e.g.
/// `rightShift` below, executed BEFORE calling this so the freed space at
/// the front is exactly this frame's size) — this function only ever
/// writes to `dest[0..shiftSize(payload.len)]`.
pub fn writeHopFrame(dest: []u8, payload: []const u8, hmac: [hmac_len]u8) FrameError![]u8 {
    if (payload.len < 2) return error.ReservedPayloadLength;
    const total = shiftSize(payload.len);
    if (dest.len < total) return error.BufferTooSmall;
    const len_bytes = bigsize.write(@as(u64, payload.len), dest);
    const after_len = dest[len_bytes.len..];
    @memcpy(after_len[0..payload.len], payload);
    after_len[payload.len..][0..hmac_len].* = hmac;
    return dest[0..total];
}

/// One hop's parsed frame: the `payload` (a borrowed slice into the input
/// buffer) and the following 32-byte `hmac` field (BOLT#4 calls this
/// `next_hmac` on the reader's side — it names either the NEXT hop's HMAC,
/// or all-zero if this was the final hop).
pub const ParsedFrame = struct {
    payload: []const u8,
    hmac: [hmac_len]u8,
    /// Total bytes consumed from the front of the input (`bigsize(len)
    /// + len + 32`), i.e. `shiftSize(payload.len)`.
    consumed: usize,
};

/// Parse one hop's frame off the FRONT of `unwrapped`, mirroring BOLT#4
/// "Onion Decryption"'s per-field extraction from the (already
/// XOR-deobfuscated) buffer: a bigsize `payload_length`, that many payload
/// bytes, then a 32-byte `next_hmac`. Enforces the same requirements the
/// spec lists at this step: a malformed bigsize, a reserved length (`< 2`),
/// or too few remaining bytes for either field all fail closed rather than
/// read out-of-bounds/garbage data.
pub fn readHopFrame(unwrapped: []const u8) (bigsize.DecodeError || FrameError)!ParsedFrame {
    const len_field = try bigsize.read(unwrapped);
    if (len_field.value < 2) return error.ReservedPayloadLength;
    // Fits in `usize` on every platform this repo targets (payload lengths
    // are bounded by hop_payloads_len, 1300, far below any usize/u64 gap).
    const payload_len: usize = @intCast(len_field.value);
    const after_len = unwrapped[len_field.len..];
    if (after_len.len < payload_len + hmac_len) return error.BufferTooSmall;
    const payload = after_len[0..payload_len];
    const hmac = after_len[payload_len..][0..hmac_len].*;
    return .{
        .payload = payload,
        .hmac = hmac,
        .consumed = len_field.len + payload_len + hmac_len,
    };
}

/// Right-shift `buf` in place by `shift` bytes: `buf[shift..]` becomes the
/// old `buf[0 .. buf.len - shift]`, and `buf[0..shift]` is left UNDEFINED
/// (the caller — `construct` — immediately overwrites it via
/// `writeHopFrame`). The trailing `shift` bytes that fall off the end
/// are simply discarded, matching BOLT#4's "the `hop_payloads` field is
/// right-shifted by `shift_size` bytes, discarding the last `shift_size`
/// bytes that exceed its 1300-byte size." Asserts `shift <= buf.len`
/// (a `shift_size` that would discard the ENTIRE buffer indicates the
/// route doesn't fit in 1300 bytes — `construct`-level `error.
/// RouteTooLong` territory, not this primitive's job).
pub fn rightShift(buf: []u8, shift: usize) void {
    std.debug.assert(shift <= buf.len);
    // std.mem.copyBackwards handles the overlapping src/dst safely (a plain
    // forward @memcpy would corrupt overlapping ranges here).
    std.mem.copyBackwards(u8, buf[shift..], buf[0 .. buf.len - shift]);
}

/// Left-shift `buf` in place by `shift` bytes (the inverse of `rightShift`,
/// used by `process` when reconstructing the outgoing `hop_payloads` for
/// the next hop): `buf[0 .. buf.len - shift]` becomes the old
/// `buf[shift..]`, and the last `shift` bytes are left UNDEFINED (the
/// caller fills them with the tail of the caller's twice-length
/// deobfuscated scratch buffer — BOLT#4 "Onion Decryption": "`hop_payloads`
/// set to the `unwrapped_payloads`, truncated to the incoming
/// `hop_payloads` size" is really "shift left" once padded to 2x length).
pub fn leftShift(buf: []u8, shift: usize) void {
    std.debug.assert(shift <= buf.len);
    std.mem.copyForwards(u8, buf[0 .. buf.len - shift], buf[shift..]);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "shiftSize: 1-byte bigsize (l < 253) is 1 + l + 32" {
    try testing.expectEqual(@as(usize, 1 + 18 + 32), shiftSize(18));
    try testing.expectEqual(@as(usize, 1 + 252 + 32), shiftSize(252));
}

test "shiftSize: 3-byte bigsize (l >= 253) is 3 + l + 32" {
    try testing.expectEqual(@as(usize, 3 + 253 + 32), shiftSize(253));
    try testing.expectEqual(@as(usize, 3 + 272 + 32), shiftSize(272));
}

test "writeHopFrame/readHopFrame round-trip" {
    var dest: [512]u8 = undefined;
    const payload = [_]u8{0xaa} ** 40;
    const hmac = [_]u8{0xbb} ** hmac_len;
    const written = try writeHopFrame(&dest, &payload, hmac);
    try testing.expectEqual(shiftSize(40), written.len);

    const parsed = try readHopFrame(&dest);
    try testing.expectEqualSlices(u8, &payload, parsed.payload);
    try testing.expectEqualSlices(u8, &hmac, &parsed.hmac);
    try testing.expectEqual(written.len, parsed.consumed);
}

test "writeHopFrame/readHopFrame: 272-byte payload forces the 3-byte bigsize form" {
    var dest: [400]u8 = undefined;
    var payload: [272]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    const hmac = [_]u8{0xcc} ** hmac_len;
    const written = try writeHopFrame(&dest, &payload, hmac);
    try testing.expectEqualSlices(u8, &.{ 0xfd, 0x01, 0x10 }, written[0..3]);

    const parsed = try readHopFrame(&dest);
    try testing.expectEqualSlices(u8, &payload, parsed.payload);
}

test "writeHopFrame rejects reserved payload lengths (0, 1)" {
    var dest: [64]u8 = undefined;
    try testing.expectError(error.ReservedPayloadLength, writeHopFrame(&dest, &.{}, [_]u8{0} ** hmac_len));
    try testing.expectError(error.ReservedPayloadLength, writeHopFrame(&dest, &.{0x01}, [_]u8{0} ** hmac_len));
}

test "readHopFrame rejects a truncated buffer" {
    // bigsize says 40 bytes of payload + 32-byte hmac follow, but only 10
    // bytes actually remain.
    var buf = [_]u8{0} ** 11;
    buf[0] = 40;
    try testing.expectError(error.BufferTooSmall, readHopFrame(&buf));
}

test "rightShift/leftShift are inverses on a distinguishable buffer" {
    var buf: [16]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @intCast(i);
    var shifted = buf;
    rightShift(&shifted, 4);
    try testing.expectEqualSlices(u8, buf[0 .. buf.len - 4], shifted[4..]);

    leftShift(&shifted, 4);
    // The last 4 bytes are undefined after leftShift; compare only the
    // portion rightShift then leftShift should restore.
    try testing.expectEqualSlices(u8, buf[0 .. buf.len - 4], shifted[0 .. buf.len - 4]);
}

test "known BOLT#4 KAT shift sizes: hop 0/2/3 (51 bytes), hop 1 (115 bytes), hop 4 (307 bytes)" {
    // Payload TLV lengths from the official onion-test.json vector (see
    // kat_vectors.zig): 18, 82, 18, 18, 272 bytes.
    try testing.expectEqual(@as(usize, 51), shiftSize(18));
    try testing.expectEqual(@as(usize, 115), shiftSize(82));
    try testing.expectEqual(@as(usize, 307), shiftSize(272));
}
