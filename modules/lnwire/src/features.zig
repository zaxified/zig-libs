// SPDX-License-Identifier: MIT
//! BOLT#9 feature bit vectors — the `features` byte arrays in `init`,
//! `node_announcement`, `channel_announcement` and the `channel_type` TLV.
//!
//! Layout (BOLT#9: "Flags are numbered from the least-significant bit, at
//! bit 0"; BOLT#1: every field is big-endian): bit `n` lives in octet
//! `len - 1 - n / 8`, mask `1 << (n % 8)`. Features come in pairs —
//! even = compulsory, odd = optional — and BOLT#1's "it's ok to be odd"
//! rule means only an unknown EVEN bit makes a peer incompatible.
//!
//! No feature-name table: BOLT#9's assignments change faster than this
//! codec, so callers pass the bit numbers they understand. Every function
//! is a pure read over (or write into) a caller-owned slice; out-of-range
//! bits read as unset.

const std = @import("std");

/// Whether `bit` is set. A bit beyond the vector's length is unset.
pub fn isSet(features: []const u8, bit: usize) bool {
    const octet = bit / 8;
    if (octet >= features.len) return false;
    return features[features.len - 1 - octet] & (@as(u8, 1) << @intCast(bit % 8)) != 0;
}

/// Whether either bit of `bit`'s pair (compulsory or optional) is set — the
/// usual "does the peer support this feature" question.
pub fn supports(features: []const u8, bit: usize) bool {
    const even = bit & ~@as(usize, 1);
    return isSet(features, even) or isSet(features, even + 1);
}

/// The octet count a vector needs to hold `bit`.
pub fn byteLenFor(bit: usize) usize {
    return bit / 8 + 1;
}

/// Sets `bit` in `buf` (same layout). Refuses a buffer too short to hold it
/// rather than dropping the bit.
pub fn set(buf: []u8, bit: usize) error{BufferTooSmall}!void {
    const octet = bit / 8;
    if (octet >= buf.len) return error.BufferTooSmall;
    buf[buf.len - 1 - octet] |= @as(u8, 1) << @intCast(bit % 8);
}

/// The lowest EVEN (compulsory) bit set whose pair is not in `known` — the
/// bit that makes the peer incompatible (BOLT#1 `init`: "if the feature
/// vector sets required features unknown to it: MUST close the
/// connection"). `known` lists either bit of each understood pair. An
/// unknown ODD bit is never returned.
pub fn firstUnknownEvenBit(features: []const u8, known: []const u16) ?usize {
    var bit: usize = 0;
    const total = features.len * 8;
    while (bit < total) : (bit += 2) {
        if (!isSet(features, bit)) continue;
        const understood = for (known) |k| {
            if (@as(usize, k) & ~@as(usize, 1) == bit) break true;
        } else false;
        if (!understood) return bit;
    }
    return null;
}

/// `features` with leading all-zero octets removed — the minimal `flen`
/// BOLT#7 asks an origin to send ("SHOULD set `flen` to the minimum length
/// required to hold the `features` bits it sets"). Borrows the input.
pub fn minimal(features: []const u8) []const u8 {
    var i: usize = 0;
    while (i < features.len and features[i] == 0) i += 1;
    return features[i..];
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const au_kat = @import("bolt7_announcement_update_kat_vectors.zig");

test "EXTERNAL: rust-lightning's node_announcement features (`2 | 1 << 5` and 0xFFFF) read as those bits" {
    // rust-lightning builds the baseline vector's features as
    // `NodeFeatures::from_le_bytes(vec![2 | 1 << 5])` — bits 1
    // (option_data_loss_protect, optional) and 5 (option_upfront_shutdown_script,
    // optional) — and its wire hex for them is "22".
    var buf: [2]u8 = undefined;
    const base = au_kat.node_announcement_vectors[1];
    try testing.expectEqualStrings("22", base.features_hex);
    const f = try std.fmt.hexToBytes(&buf, base.features_hex);
    for (0..16) |b| try testing.expectEqual(b == 1 or b == 5, isSet(f, b));
    try testing.expect(supports(f, 0) and supports(f, 4) and !supports(f, 2));
    try testing.expectEqual(@as(?usize, null), firstUnknownEvenBit(f, &.{}));

    // `from_le_bytes(vec![0xFF, 0xFF])`: bits 0..15 all set, so with nothing
    // known the first incompatibility is bit 0, and with 0..13 known it is 14.
    const all = au_kat.node_announcement_vectors[0];
    try testing.expectEqualStrings("ffff", all.features_hex);
    const g = try std.fmt.hexToBytes(&buf, all.features_hex);
    for (0..16) |b| try testing.expect(isSet(g, b));
    try testing.expect(!isSet(g, 16));
    try testing.expectEqual(@as(?usize, 0), firstUnknownEvenBit(g, &.{}));
    try testing.expectEqual(@as(?usize, 14), firstUnknownEvenBit(g, &.{ 0, 3, 4, 7, 8, 10, 13, 12 }));
}

test "SELF-DERIVED (BOLT#9 text): bit numbering runs from the LAST octet" {
    // Byte order is not distinguishable in any vendored vector (all are one
    // octet or all-0xFF), so this is from BOLT#9/BOLT#1's wording alone.
    var buf: [3]u8 = @splat(0);
    try set(&buf, 0);
    try set(&buf, 9);
    try set(&buf, 23);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x02, 0x01 }, &buf);
    try testing.expect(isSet(&buf, 9) and !isSet(&buf, 8) and !isSet(&buf, 1));
    try testing.expectError(error.BufferTooSmall, set(&buf, 24));
    try testing.expectEqual(@as(usize, 4), byteLenFor(24));
    try testing.expect(!isSet(&buf, 1000));
    try testing.expect(!isSet(&.{}, 0));
    // An odd unknown bit is fine; the even one is not.
    try testing.expectEqual(@as(?usize, null), firstUnknownEvenBit(&.{ 0x00, 0x02 }, &.{}));
    try testing.expectEqual(@as(?usize, 8), firstUnknownEvenBit(&.{ 0x01, 0x02 }, &.{}));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, minimal(&.{ 0x00, 0x00, 0x01, 0x00 }));
    try testing.expectEqual(@as(usize, 0), minimal(&.{ 0, 0 }).len);
}
