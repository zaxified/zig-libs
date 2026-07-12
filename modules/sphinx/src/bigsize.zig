// SPDX-License-Identifier: MIT
//! BOLT#1's `bigsize` variable-length integer encoding — a compact,
//! canonically-minimal `u64` codec used throughout the Lightning wire
//! protocol for TLV lengths/types. BOLT#4's `hop_payload` framing (see
//! `hopframe.zig`) uses it for the per-hop `length` field, which is why it
//! lives in this module rather than being invented ad hoc there.
//!
//! Encoding (BOLT#1 "A Simple Serialization Format", `bigsize`):
//!
//!   - `value < 0xfd`               -> 1 byte:  `value`
//!   - `0xfd <= value <= 0xffff`    -> 3 bytes: `0xfd ++ be16(value)`
//!   - `0x10000 <= value <= 0xffffffff` -> 5 bytes: `0xfe ++ be32(value)`
//!   - otherwise                    -> 9 bytes: `0xff ++ be64(value)`
//!
//! Decoding MUST reject a non-minimal encoding (e.g. `0xfd 0x00 0x05` for the
//! value 5, which fits in 1 byte) — BOLT#1 requires the minimal form and
//! implementations that skip this check accept malleable reencodings of the
//! same logical value, which would let an attacker vary a message's bytes
//! (and thus its wire hash) without changing its meaning.

const std = @import("std");

pub const DecodeError = error{
    /// Fewer bytes remain than the leading byte's form requires.
    Truncated,
    /// A `0xfd`/`0xfe`/`0xff`-prefixed form was used for a value that fits
    /// in a shorter encoding (BOLT#1's minimality requirement).
    NonCanonical,
};

/// The exact number of bytes `encode`/`write` will produce for `value`.
pub fn encodedLength(value: u64) usize {
    if (value < 0xfd) return 1;
    if (value <= 0xffff) return 3;
    if (value <= 0xffffffff) return 5;
    return 9;
}

/// Write `value`'s canonical bigsize encoding into `out` (which must be at
/// least `encodedLength(value)` bytes) and return the written subslice.
pub fn write(value: u64, out: []u8) []u8 {
    const n = encodedLength(value);
    switch (n) {
        1 => out[0] = @intCast(value),
        3 => {
            out[0] = 0xfd;
            std.mem.writeInt(u16, out[1..3], @intCast(value), .big);
        },
        5 => {
            out[0] = 0xfe;
            std.mem.writeInt(u32, out[1..5], @intCast(value), .big);
        },
        9 => {
            out[0] = 0xff;
            std.mem.writeInt(u64, out[1..9], value, .big);
        },
        else => unreachable,
    }
    return out[0..n];
}

/// A decoded bigsize: its value plus how many leading bytes of the input it
/// consumed (1, 3, 5, or 9).
pub const Decoded = struct {
    value: u64,
    len: usize,
};

/// Parse a bigsize off the front of `buf`. Rejects truncated input and any
/// non-minimal (non-canonical) encoding — see the module doc comment.
pub fn read(buf: []const u8) DecodeError!Decoded {
    if (buf.len == 0) return error.Truncated;
    return switch (buf[0]) {
        0xff => blk: {
            if (buf.len < 9) return error.Truncated;
            const v = std.mem.readInt(u64, buf[1..9], .big);
            if (v <= 0xffffffff) return error.NonCanonical;
            break :blk .{ .value = v, .len = 9 };
        },
        0xfe => blk: {
            if (buf.len < 5) return error.Truncated;
            const v = std.mem.readInt(u32, buf[1..5], .big);
            if (v <= 0xffff) return error.NonCanonical;
            break :blk .{ .value = v, .len = 5 };
        },
        0xfd => blk: {
            if (buf.len < 3) return error.Truncated;
            const v = std.mem.readInt(u16, buf[1..3], .big);
            if (v < 0xfd) return error.NonCanonical;
            break :blk .{ .value = v, .len = 3 };
        },
        else => |b| .{ .value = b, .len = 1 },
    };
}

// ── tests ────────────────────────────────────────────────────────────────

test "encodedLength: the four size classes" {
    try std.testing.expectEqual(@as(usize, 1), encodedLength(0));
    try std.testing.expectEqual(@as(usize, 1), encodedLength(0xfc));
    try std.testing.expectEqual(@as(usize, 3), encodedLength(0xfd));
    try std.testing.expectEqual(@as(usize, 3), encodedLength(0xffff));
    try std.testing.expectEqual(@as(usize, 5), encodedLength(0x10000));
    try std.testing.expectEqual(@as(usize, 5), encodedLength(0xffffffff));
    try std.testing.expectEqual(@as(usize, 9), encodedLength(0x100000000));
}

test "write/read round-trip across every size class" {
    const values = [_]u64{ 0, 1, 0xfc, 0xfd, 0x100, 0xffff, 0x10000, 0x12345678, 0xffffffff, 0x100000000, std.math.maxInt(u64) };
    for (values) |v| {
        var buf: [9]u8 = undefined;
        const written = write(v, &buf);
        try std.testing.expectEqual(encodedLength(v), written.len);
        const decoded = try read(written);
        try std.testing.expectEqual(v, decoded.value);
        try std.testing.expectEqual(written.len, decoded.len);
    }
}

test "read rejects non-canonical (non-minimal) encodings" {
    // 0xfd-prefixed but value < 0xfd: value 5 does not need 3 bytes.
    try std.testing.expectError(error.NonCanonical, read(&.{ 0xfd, 0x00, 0x05 }));
    // 0xfe-prefixed but value <= 0xffff.
    try std.testing.expectError(error.NonCanonical, read(&.{ 0xfe, 0x00, 0x00, 0xff, 0xff }));
    // 0xff-prefixed but value <= 0xffffffff.
    try std.testing.expectError(error.NonCanonical, read(&.{ 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff }));
}

test "read rejects truncated input" {
    try std.testing.expectError(error.Truncated, read(&.{}));
    try std.testing.expectError(error.Truncated, read(&.{ 0xfd, 0x01 }));
    try std.testing.expectError(error.Truncated, read(&.{ 0xfe, 0x01, 0x02, 0x03 }));
    try std.testing.expectError(error.Truncated, read(&.{ 0xff, 1, 2, 3, 4, 5, 6, 7 }));
}

test "known BOLT#4 KAT prefixes: hop 0/2/3 (18-byte payload) and hop 4 (272-byte payload)" {
    // hop_payload lengths from the official onion-test.json vector (see
    // kat_vectors.zig): payload lengths 18 (1-byte bigsize) and 272
    // (3-byte bigsize, 0xfd prefix).
    var buf18: [1]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{0x12}, write(18, &buf18));
    var buf272: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 0xfd, 0x01, 0x10 }, write(272, &buf272));
}
