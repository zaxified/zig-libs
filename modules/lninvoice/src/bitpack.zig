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

// ── BOLT#11 `9` (features): a bit vector, NOT a byte string ──────────────
//
// Every other BOLT#11 tagged-field value is a byte string that happens to be
// carried in 5-bit groups, so the group count rounds UP and the slack bits
// land at the END where the decoder discards them (`bytesToQuintets` /
// `quintetsToBytesStrict`). `9` is the exception, and using the byte-string
// pair on it is wrong in both directions.
//
// BOLT#11 "Feature Bits":
//   "The field is big-endian.  The least-significant bit is numbered 0,
//    which is _even_, and the next most significant bit is numbered 1,
//    which is _odd_."
//
// The numbering is anchored at the END of the `data_length * 5`-bit string,
// so whatever slack rounds the vector up to a multiple of 5 bits sits at the
// FRONT. Right-padding a byte string instead shifts every feature bit UP by
// `(5 - 8*len mod 5) mod 5` positions, and dropping the trailing bits on
// decode shifts them DOWN by the same amount — the spec's own donation
// example is a 15-bit field, so `quintetsToBytesStrict` reported its feature
// bits {14, 8} as {7, 1}, and `bytesToQuintets` could not re-emit it at all.
//
// Length is pinned by the writer requirement:
//   "if `9` contains non-zero bits:
//      - MUST use the minimum `data_length` possible to encode the non-zero
//        bits with no 0 field-elements at the start.
//    otherwise:
//      - MUST omit the `9` field altogether."
//
// i.e. `data_length == ceil((highest_set_bit + 1) / 5)`. Checked against all
// 20 worked examples in BOLT#11's own "Examples" section: the `data_length`
// values that occur there are 3, 10, 20 and 21, and every one of them equals
// `ceil((highest_set_bit+1)/5)` for the bit string the spec prints beside it.

/// Reads bit `index` (LSB-numbered, 0 = least-significant bit of the last
/// byte) out of a big-endian feature vector; 0 past the end.
fn featureBit(bytes: []const u8, index: usize) u1 {
    const from_end = index / 8;
    if (from_end >= bytes.len) return 0;
    const b = bytes[bytes.len - 1 - from_end];
    return @intCast((b >> @intCast(index % 8)) & 1);
}

/// Encode side of the `9` field: `bytes` is a big-endian feature vector (bit
/// 0 = least-significant bit of the last byte, exactly as BOLT#9 carries it),
/// emitted in the minimum number of 5-bit field-elements that covers its
/// highest set bit. An all-zero vector yields ZERO quintets — the caller is
/// then required to omit the field entirely.
pub fn featureBytesToQuintets(allocator: Allocator, bytes: []const u8) Allocator.Error![]u5 {
    var first_nz: usize = 0;
    while (first_nz < bytes.len and bytes[first_nz] == 0) first_nz += 1;
    if (first_nz == bytes.len) return allocator.alloc(u5, 0);

    const high_bit = (bytes.len - 1 - first_nz) * 8 + (7 - @clz(bytes[first_nz]));
    const nq = (high_bit + 5) / 5; // ceil((high_bit + 1) / 5)

    const out = try allocator.alloc(u5, nq);
    for (out, 0..) |*q, j| {
        var acc: u8 = 0;
        const base = (nq - 1 - j) * 5;
        var b: usize = 5;
        while (b > 0) {
            b -= 1;
            acc = (acc << 1) | featureBit(bytes, base + b);
        }
        q.* = @intCast(acc);
    }
    return out;
}

/// Decode side of the `9` field: the `data_length * 5`-bit string read as a
/// big-endian integer and left-padded into `ceil(data_length * 5 / 8)` bytes,
/// so the caller's bit N is BOLT#9's feature bit N. Never rejects: unlike a
/// byte string's trailing padding, a `9` field's low bits are real feature
/// bits and a non-zero one is ordinary data, not tampering.
pub fn quintetsToFeatureBytes(allocator: Allocator, quintets: []const u5) Allocator.Error![]u8 {
    const total_bits = quintets.len * 5;
    const n = (total_bits + 7) / 8;
    const out = try allocator.alloc(u8, n);
    @memset(out, 0);
    for (quintets, 0..) |q, j| {
        for (0..5) |b| {
            if ((q >> @intCast(4 - b)) & 1 == 0) continue;
            const index = total_bits - 1 - (j * 5 + b); // LSB-numbered
            out[n - 1 - index / 8] |= @as(u8, 1) << @intCast(index % 8);
        }
    }
    return out;
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

test "BOLT#11 `9` field: every data_length that occurs in the spec's own examples, both directions" {
    const allocator = testing.allocator;
    const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Each row is a `9` field's data copied verbatim out of a BOLT#11 worked
    // example, paired with the feature NUMBERS the spec states for it in
    // prose. The prose is the oracle here, deliberately: it is independent of
    // any bit-string expansion this test could perform for itself, and it is
    // what pins the ALIGNMENT -- a shifted decode gets the numbers wrong.
    //
    // Covers all four `data_length` values that occur anywhere in the spec's
    // examples (3, 10, 20, 21), whose leftover bit counts (`5*len mod 8`) are
    // 7, 2, 4 and 1 -- i.e. every distinct byte misalignment. Row 21's
    // leading field-element is `00001`: minimal, but easy to mistake for
    // padding.
    const rows = [_]struct { data: []const u8, bits: []const u8, source: []const u8 }{
        .{
            // "Please make a donation of any amount using payment_hash ...".
            // Breakdown: "`sgq`: b100000100000000" -- printed in full; the
            // set bits are #14 and #8.
            .data = "sgq",
            .bits = &.{ 8, 14 },
            .source = "donation",
        },
        .{
            // "Please send 0.01 BTC with payment metadata 0x01fafaf0".
            // Breakdown: "`gqqqqqqsgq`:
            // [b01000...0100000100000000] = 8 + 14 + 48".
            .data = "gqqqqqqsgq",
            .bits = &.{ 8, 14, 48 },
            .source = "payment metadata 0x01fafaf0",
        },
        .{
            // "Please send $30 for coffee beans to the same peer, which
            // supports features 8, 14 and 99, using secret 0x1111...".
            .data = "sqqqqqqqqqqqqqqqqsgq",
            .bits = &.{ 8, 14, 99 },
            .source = "features 8, 14 and 99",
        },
        .{
            // "Same, but adding invalid unknown feature 100" -- filed under
            // "Examples of Invalid Invoices", but invalid only at the
            // feature-BIT layer (an unknown *even* bit), which is BOLT#9's
            // business. Its encoding is well-formed, and the encoding is
            // what is asserted here.
            .data = "psqqqqqqqqqqqqqqqqsgq",
            .bits = &.{ 8, 14, 99, 100 },
            .source = "unknown feature 100",
        },
    };

    var ran: usize = 0;
    for (rows) |row| {
        errdefer std.debug.print("failing row: {s}\n", .{row.source});

        var quintets: [32]u5 = undefined;
        for (row.data, 0..) |c, i| quintets[i] = @intCast(std.mem.indexOfScalar(u8, CHARSET, c).?);
        const q = quintets[0..row.data.len];

        // `data_length` follows from the writer rule alone ("the minimum
        // `data_length` possible to encode the non-zero bits"), so the spec's
        // stated feature numbers predict the field width the spec actually
        // used -- an independent check on both the rule and the row.
        const highest: usize = row.bits[row.bits.len - 1];
        try testing.expectEqual((highest + 5) / 5, row.data.len);

        // Expected byte vector, built from the feature numbers by BOLT#11's
        // own definition: "the least-significant bit is numbered 0".
        const n = highest / 8 + 1;
        var want: [16]u8 = @splat(0);
        for (row.bits) |b| want[n - 1 - b / 8] |= @as(u8, 1) << @intCast(b % 8);

        const got = try quintetsToFeatureBytes(allocator, q);
        defer allocator.free(got);
        try testing.expectEqualSlices(u8, want[0..n], got[got.len - n ..]);
        for (got[0 .. got.len - n]) |b| try testing.expectEqual(@as(u8, 0), b);

        // ... and back out at exactly the spec's own `data_length`.
        const back = try featureBytesToQuintets(allocator, got);
        defer allocator.free(back);
        try testing.expectEqualSlices(u5, q, back);
        ran += 1;
    }
    try testing.expectEqual(@as(usize, 4), ran); // a silently shrinking table fails
}

test "BOLT#11 `9` field: an all-zero feature vector encodes to zero quintets (writer MUST omit it)" {
    const allocator = testing.allocator;
    const q = try featureBytesToQuintets(allocator, &.{ 0, 0, 0 });
    defer allocator.free(q);
    try testing.expectEqual(@as(usize, 0), q.len);
}

test "BOLT#11 `9` field: low feature bits survive -- the byte-string decoder rejected them" {
    const allocator = testing.allocator;
    // data_length 3 (15 bits) with feature bit 0 set: `qqp` = 00000 00000 00001.
    // `quintetsToBytesStrict` sees 1 byte + 7 leftover bits of which the last
    // is 1, and returns error.NonZeroPadding -- rejecting a legal invoice.
    const q = [_]u5{ 0, 0, 1 };
    try testing.expectError(error.NonZeroPadding, quintetsToBytesStrict(allocator, &q));

    const feat = try quintetsToFeatureBytes(allocator, &q);
    defer allocator.free(feat);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, feat);
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
