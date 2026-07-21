// SPDX-License-Identifier: MIT
//! `CScriptNum` — Bitcoin Script's little-endian, sign-magnitude integer
//! encoding (Bitcoin Core `script/script.h` `CScriptNum`). Every arithmetic
//! opcode (`OP_ADD`, `OP_1ADD`, `OP_WITHIN`, the locktime opcodes, …) reads
//! and writes stack elements in this format, NOT plain two's-complement.
//!
//! ## Encoding
//!
//! A number is stored as the fewest bytes needed, little-endian, with the
//! **high bit of the last byte** as the sign flag (so `0x81` last-byte-alone
//! encodes `-1`, not `129`). An extra `0x00`/`0x80` padding byte is appended
//! only when the natural encoding's last byte would already have its high
//! bit set (to disambiguate magnitude from sign). Empty bytes encode `0`.
//!
//! ## Minimal-encoding enforcement
//!
//! `decode` rejects a redundant trailing zero/sign byte whenever
//! `require_minimal` is `true`. Bitcoin Core's interpreter derives this
//! from a single `fRequireMinimal` local — the `MINIMALDATA` script flag —
//! that gates BOTH push-opcode minimality (`interpreter.zig`'s
//! `checkMinimalPush`) AND every arithmetic/`CHECKLOCKTIMEVERIFY`/
//! `CHECKSEQUENCEVERIFY` operand's `CScriptNum` minimality; callers here
//! (`interpreter.zig`) pass `flags.minimaldata` through unchanged to both.
//!
//! ## Overflow bound
//!
//! Bitcoin Core bounds every `CScriptNum` operand to `nMaxNumSize` bytes
//! (default `4`, i.e. values in `[-2^31+1, 2^31-1]`) to keep arithmetic
//! results bounded regardless of how many operations a script chains — this
//! module's `default_max_num_size` matches that. Results of arithmetic
//! (which can transiently need a 5th byte, e.g. `0x7fffffff + 1`) are
//! representable as `i64` internally but must themselves re-satisfy the
//! bound before being pushed back if consumed by a later numeric opcode
//! (mirroring `CScriptNum`'s own internal `int64_t` storage).

const std = @import("std");

pub const NumError = error{ Overflow, NonMinimalEncoding };

/// Consensus default: arithmetic operands/results are bounded to 4 bytes.
pub const default_max_num_size: usize = 4;
/// `OP_CHECKLOCKTIMEVERIFY`/`OP_CHECKSEQUENCEVERIFY` (BIP65/BIP112) read
/// their argument with a wider, 5-byte bound (locktimes exceed `i32`).
pub const locktime_max_num_size: usize = 5;

/// Decodes a `CScriptNum`-encoded stack element into an `i64`.
/// `require_minimal`: reject any non-minimal encoding (module doc comment).
/// `max_size`: reject encodings longer than this many bytes.
pub fn decode(bytes: []const u8, require_minimal: bool, max_size: usize) NumError!i64 {
    if (bytes.len > max_size) return error.Overflow;
    if (bytes.len == 0) return 0;
    if (require_minimal) {
        // The last byte, sign bit masked off, must be non-zero UNLESS a
        // non-zero byte immediately below it already has its own top bit
        // set (in which case the trailing 0x00/0x80 is the required
        // sign-disambiguation pad, not redundant).
        if ((bytes[bytes.len - 1] & 0x7f) == 0) {
            if (bytes.len <= 1 or (bytes[bytes.len - 2] & 0x80) == 0) {
                return error.NonMinimalEncoding;
            }
        }
    }
    var result: u64 = 0;
    for (bytes, 0..) |b, i| result |= @as(u64, b) << @intCast(8 * i);
    const sign_byte = bytes[bytes.len - 1];
    if ((sign_byte & 0x80) != 0) {
        // Clear the sign bit from the assembled magnitude, then negate.
        const clear_mask = @as(u64, 0x80) << @intCast(8 * (bytes.len - 1));
        result &= ~clear_mask;
        return -@as(i64, @intCast(result));
    }
    return @intCast(result);
}

/// Encodes `value` as a minimal `CScriptNum`, writing into `out` (9 bytes is
/// always enough for any `i64`) and returning the written prefix.
pub fn encode(value: i64, out: *[9]u8) []u8 {
    if (value == 0) return out[0..0];
    const negative = value < 0;
    var abs_val: u64 = if (negative) blk: {
        // Avoid overflow negating i64 min (not reachable for real script
        // values given the 4/5-byte bound, but keep this total).
        break :blk @as(u64, @bitCast(-value));
    } else @intCast(value);

    var n: usize = 0;
    while (abs_val != 0) {
        out[n] = @intCast(abs_val & 0xff);
        abs_val >>= 8;
        n += 1;
    }
    if (out[n - 1] & 0x80 != 0) {
        out[n] = if (negative) 0x80 else 0x00;
        n += 1;
    } else if (negative) {
        out[n - 1] |= 0x80;
    }
    return out[0..n];
}

/// Bitcoin Script truth-value cast (`CastToBool` in Bitcoin Core): non-zero
/// iff any byte is non-zero, EXCEPT a lone negative-zero encoding
/// (all-zero bytes except the sign bit set on the final byte) which is
/// still falsy.
pub fn castToBool(bytes: []const u8) bool {
    for (bytes, 0..) |b, i| {
        if (b != 0) {
            // Last byte, only its sign bit (0x80) set: still "negative zero".
            if (i == bytes.len - 1 and b == 0x80) return false;
            return true;
        }
    }
    return false;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "round-trip small values" {
    const cases = [_]i64{ 0, 1, -1, 127, 128, -128, 255, 256, -256, 32767, 32768, 2147483647, -2147483647 };
    for (cases) |v| {
        var buf: [9]u8 = undefined;
        const enc = encode(v, &buf);
        const dec = try decode(enc, true, 5);
        try testing.expectEqual(v, dec);
    }
}

test "zero encodes as empty bytes" {
    var buf: [9]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), encode(0, &buf).len);
    try testing.expectEqual(@as(i64, 0), try decode(&.{}, true, 4));
}

test "known encodings match Bitcoin Core CScriptNum byte-for-byte" {
    var buf: [9]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x01}, encode(1, &buf));
    try testing.expectEqualSlices(u8, &.{0x81}, encode(-1, &buf));
    try testing.expectEqualSlices(u8, &.{0x7f}, encode(127, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x00 }, encode(128, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x80 }, encode(-128, &buf));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0x00 }, encode(255, &buf));
}

test "rejects non-minimal encoding when required" {
    // 0x00 0x80 -- a redundant leading-magnitude zero byte before the sign byte.
    try testing.expectError(error.NonMinimalEncoding, decode(&.{ 0x00, 0x80 }, true, 4));
    // Same bytes accepted when minimality isn't required.
    _ = try decode(&.{ 0x00, 0x80 }, false, 4);
}

test "rejects overflow beyond max_size" {
    try testing.expectError(error.Overflow, decode(&.{ 1, 2, 3, 4, 5 }, true, 4));
    _ = try decode(&.{ 1, 2, 3, 4, 5 }, true, 5);
}

test "castToBool: negative zero is falsy, everything else with a set byte is truthy" {
    try testing.expect(!castToBool(&.{}));
    try testing.expect(!castToBool(&.{0x00}));
    try testing.expect(!castToBool(&.{0x80})); // negative zero
    try testing.expect(!castToBool(&.{ 0x00, 0x00, 0x80 }));
    try testing.expect(castToBool(&.{0x01}));
    try testing.expect(castToBool(&.{ 0x00, 0x01 }));
    try testing.expect(castToBool(&.{ 0x00, 0x00, 0x81 })); // -1: non-zero magnitude bit alongside sign
}
