// SPDX-License-Identifier: MIT
//! 5-bit-quintet <-> byte / integer conversions — BOLT#11's tagged-field
//! values are a bitstring packed MSB-first into the invoice's 5-bit bech32
//! symbols (BIP173's `convertbits`, applied to arbitrary-length values
//! rather than just witness programs), and BOLT#12's whole TLV payload is
//! the same MSB-first bit-packing of its raw bytes. This file is the one
//! place that bit-packing lives, shared by `bolt11.zig` and `bolt12.zig`.
//!
//! Two families:
//!   * byte-string fields (`p`/`s`/`d`/`h`/`m`/`n`/`9`/`f`/`r`, and BOLT#12's
//!     whole TLV payload) — `quintetsToBytesStrict` (decode: any bits left
//!     over after the last full byte MUST be zero, i.e. exactly the padding
//!     an encoder would have appended, never smuggled real data) and
//!     `bytesToQuintets` (encode: zero-pad the final quintet).
//!   * plain big-endian integer fields (`timestamp`, `x`, `c`) — the quintet
//!     stream read straight as a base-32 (== 5-bit-group-concatenated)
//!     integer, no byte alignment at all: `quintetsToUint`/`uintToQuintets`.
//!
//! `quintetsToBytesPadded` is a third, deliberately lenient form used only
//! to reconstruct the exact preimage BOLT#11 signs: "0 bits appended to pad
//! to a byte boundary" — appending fresh zero bits to whatever data-part
//! quintets remain (after the signature is stripped), never rejecting.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const PaddingError = error{ NonZeroPadding, PaddingTooLong };

/// Strict byte-string decode (BIP173 `convertbits(5, 8, pad=false)`): packs
/// `quintets` MSB-first into bytes; any leftover bits after the last full
/// byte (0..7 of them) MUST be zero, matching what a compliant encoder would
/// have zero-padded — a nonzero remainder means the input was tampered with
/// or malformed, and is rejected rather than silently truncated.
///
/// Deliberately does NOT enforce "leftover < 5 bits": that stronger rule
/// only holds when `quintets` is an entire bech32 DATA PART with no other
/// length signal (BOLT#12's whole-stream conversion — see
/// `quintetsToBytesMinimal` below, which adds it for exactly that case).
/// Here, `quintets` is routinely a BOLT#11 tagged field's OWN `data_length`
/// slice, whose quintet count BOLT#11 never requires to be minimal for the
/// byte string it holds — a real, valid invoice's field can carry more
/// quintets than the tightest possible encoding and still be legitimate, as
/// long as the extra bits are zero. Conflating the two lost real BOLT#11
/// vectors during development (see `quintetsToBytesMinimal`'s doc comment).
pub fn quintetsToBytesStrict(allocator: Allocator, quintets: []const u5) (PaddingError || Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var acc: u32 = 0;
    var bits: u8 = 0;
    for (quintets) |q| {
        acc = (acc << 5) | q;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            try out.append(allocator, @intCast((acc >> @intCast(bits)) & 0xff));
        }
    }
    if (bits > 0) {
        const mask: u32 = (@as(u32, 1) << @intCast(bits)) - 1;
        if ((acc & mask) != 0) return error.NonZeroPadding;
    }
    return out.toOwnedSlice(allocator);
}

/// `quintetsToBytesStrict` PLUS the "leftover < 5 bits" invariant that only
/// holds for a bech32-style string's WHOLE data part (BOLT#12's
/// `decodeOffer`/`decodeInvoiceRequest`/`decodeInvoice`, none of which carry
/// a separate length field the way a BOLT#11 tagged field does — the
/// quintet count itself is the only signal of how many bytes were meant).
///
/// **`error.PaddingTooLong` (added 2026-08-02, external anchor: BOLT#12
/// `bolt12/offers-test.json` "Bech32 padding exceeds 4-bit limit")** —
/// reference `convertbits(5, 8, pad=false)` (the same algorithm
/// `quintetsToBytesStrict` implements) rejects whenever `bits >= frombits`
/// (`frombits` = 5): five-plus leftover bits can never be genuine
/// zero-padding (padding exists only to round the last partial byte up to 8
/// bits, and a partial byte can never need a whole extra quintet's worth of
/// filler) — a leftover of 5+ bits means the quintet count itself is wrong
/// (one extra all-zero quintet appended beyond the minimal encoding), which
/// is exactly the vector this catches: it is `offers-test.json`'s "Minimal
/// bolt12 offer" string with one extra trailing zero-value bech32 char
/// (`q`) appended. `bolt12.zig` used to call `quintetsToBytesStrict`
/// directly for this and missed the case; this wrapper is now the one it
/// calls instead, so BOLT#11's field-level decode (which must NOT apply
/// this extra rule) stays untouched.
pub fn quintetsToBytesMinimal(allocator: Allocator, quintets: []const u5) (PaddingError || Allocator.Error)![]u8 {
    const leftover_bits = (quintets.len * 5) % 8;
    if (leftover_bits >= 5) return error.PaddingTooLong;
    return quintetsToBytesStrict(allocator, quintets);
}

/// Lenient byte-string decode (BIP173 `convertbits(5, 8, pad=true)`-style,
/// but taking whatever bits are already there and simply extending with
/// fresh zero bits to the next byte boundary) — used ONLY to rebuild
/// BOLT#11's signed preimage from its own already-parsed data-part quintets
/// ("the human-readable part ... concatenated with the data part (excluding
/// the signature), with 0 bits appended to pad to a byte boundary"). Never
/// fails: there is nothing to reject, the padding bits are ours to add.
pub fn quintetsToBytesPadded(allocator: Allocator, quintets: []const u5) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var acc: u32 = 0;
    var bits: u8 = 0;
    for (quintets) |q| {
        acc = (acc << 5) | q;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            try out.append(allocator, @intCast((acc >> @intCast(bits)) & 0xff));
        }
    }
    if (bits > 0) {
        const pad: u8 = 8 - bits;
        try out.append(allocator, @intCast((acc << @intCast(pad)) & 0xff));
    }
    return out.toOwnedSlice(allocator);
}

/// Byte-string encode: zero-pads the final quintet (the `encode` side of
/// `quintetsToBytesStrict`).
pub fn bytesToQuintets(allocator: Allocator, bytes: []const u8) Allocator.Error![]u5 {
    var out: std.ArrayList(u5) = .empty;
    errdefer out.deinit(allocator);
    var acc: u32 = 0;
    var bits: u8 = 0;
    for (bytes) |b| {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            try out.append(allocator, @intCast((acc >> @intCast(bits)) & 0x1f));
        }
    }
    if (bits > 0) {
        const pad: u3 = @intCast(5 - bits);
        try out.append(allocator, @intCast((acc << pad) & 0x1f));
    }
    return out.toOwnedSlice(allocator);
}

pub const IntError = error{TooManyQuintets};

/// Reads `quintets` as a plain big-endian base-32 integer (BOLT#11
/// `timestamp`/`x`/`c`: "35 bits, big-endian" etc — no byte alignment). Caps
/// at 12 quintets (60 bits, comfortably covering every real BOLT#11 use —
/// `timestamp` is fixed at 7, `x`/`c` are seconds/block-deltas) so the
/// accumulator can never silently truncate a hostile oversized field.
pub fn quintetsToUint(quintets: []const u5) IntError!u64 {
    if (quintets.len > 12) return error.TooManyQuintets;
    var v: u64 = 0;
    for (quintets) |q| v = (v << 5) | q;
    return v;
}

/// Minimal big-endian base-32 encoding of `v` (no leading zero quintets;
/// `v == 0` encodes as zero quintets, per BOLT#11 "MUST use the minimum
/// `data_length` possible, i.e. no leading 0 field-elements").
pub fn uintToQuintets(v: u64, buf: *[13]u5) []u5 {
    if (v == 0) return buf[0..0];
    var tmp: [13]u5 = undefined;
    var n: usize = 0;
    var x = v;
    while (x != 0) : (x >>= 5) {
        tmp[n] = @intCast(x & 0x1f);
        n += 1;
    }
    for (0..n) |i| buf[i] = tmp[n - 1 - i];
    return buf[0..n];
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "quintetsToBytesStrict / bytesToQuintets round-trip a 32-byte hash (52 quintets, 4 pad bits)" {
    const allocator = testing.allocator;
    var hash: [32]u8 = undefined;
    for (&hash, 0..) |*b, i| b.* = @intCast(i * 7 + 1);

    const q = try bytesToQuintets(allocator, &hash);
    defer allocator.free(q);
    try testing.expectEqual(@as(usize, 52), q.len); // ceil(256/5)

    const back = try quintetsToBytesStrict(allocator, q);
    defer allocator.free(back);
    try testing.expectEqualSlices(u8, &hash, back);
}

test "quintetsToBytesStrict rejects nonzero padding (tamper detection)" {
    const allocator = testing.allocator;
    var hash: [32]u8 = undefined;
    @memset(&hash, 0xff);
    const q = try bytesToQuintets(allocator, &hash);
    defer allocator.free(q);
    var tampered = try allocator.dupe(u5, q);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] |= 1; // flip a low padding bit
    try testing.expectError(error.NonZeroPadding, quintetsToBytesStrict(allocator, tampered));
}

test "quintetsToBytesPadded never fails and matches strict decode when padding is already zero" {
    const allocator = testing.allocator;
    const q = [_]u5{ 1, 2, 3 }; // 15 bits -> 1 byte + 7 leftover bits
    const padded = try quintetsToBytesPadded(allocator, &q);
    defer allocator.free(padded);
    try testing.expectEqual(@as(usize, 2), padded.len);
    // 1,2,3 -> bits 00001 00010 00011 -> byte0 = 00001000 = 0x08,
    // remaining 7 bits 1000011 + 1 zero pad bit -> byte1 = 10000110 = 0x86
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x86 }, padded);
}

test "quintetsToUint / uintToQuintets: timestamp round-trip + minimal encoding" {
    // 'pvjluez' quintet values (bech32 charset "qpzry9x8gf2tvdw0s3jn54khce6mua7l") from the
    // BOLT#11 donation example, which documents this exact string decoding to timestamp 1496314658.
    const q = [_]u5{ 1, 12, 18, 31, 28, 25, 2 };
    const v = try quintetsToUint(&q);
    try testing.expectEqual(@as(u64, 1496314658), v);

    var buf: [13]u5 = undefined;
    const enc = uintToQuintets(v, &buf);
    try testing.expectEqualSlices(u5, &q, enc);

    // Zero encodes as zero quintets (minimal -- no leading-zero elements).
    var buf2: [13]u5 = undefined;
    try testing.expectEqual(@as(usize, 0), uintToQuintets(0, &buf2).len);
}
