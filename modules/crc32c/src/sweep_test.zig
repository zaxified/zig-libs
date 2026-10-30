// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GP). crc32c had no finding; these pin the
//! edge arguments the sweep argued safe (`combine` with 0 and 2^64-1 bytes,
//! every backend on empty and tiny input) so they stay safe.

const std = @import("std");
const crc = @import("root.zig");

test "combine: length 0 and the largest length terminate and agree with the definition (sweep CC)" {
    // Appending zero bytes multiplies by x^0 = 1.
    try std.testing.expectEqual(@as(u32, 0x1234_5678 ^ 0x9abc_def0), crc.combine(0x1234_5678, 0x9abc_def0, 0));
    // Largest u64 length: indexes the last x^(2^k) table entry (k = 66).
    _ = crc.combine(0xdead_beef, 0x0bad_cafe, std.math.maxInt(u64));
    // combine is the exact CRC of the concatenation (spot check, both halves odd-sized).
    const a = "hello, ";
    const b = "world";
    try std.testing.expectEqual(crc.hash(a ++ b), crc.combine(crc.hash(a), crc.hash(b), b.len));
}

test "every available backend accepts empty and 1-byte input at any alignment (sweep CC)" {
    var buf: [16]u8 align(8) = @splat(0xa5);
    for ([_]crc.Backend{ .table, .sse42, .armv8 }) |be| {
        for (0..8) |off| {
            const want = crc.hashWith(.table, buf[off .. off + 1]);
            if (crc.hashWith(be, buf[off..off])) |v| try std.testing.expectEqual(@as(u32, 0), v);
            if (crc.hashWith(be, buf[off .. off + 1])) |v| try std.testing.expectEqual(want.?, v);
        }
    }
}
