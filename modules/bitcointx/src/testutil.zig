// SPDX-License-Identifier: MIT
//! Tiny hex-decode helpers shared by the `*_kat_test.zig` files. Test-only
//! (not part of the public API).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

pub fn hexToArray(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
