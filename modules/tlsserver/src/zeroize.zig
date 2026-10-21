// SPDX-License-Identifier: MIT

//! Zero buffers on the per-connection path without paying for
//! `std.crypto.secureZero`'s byte-at-a-time store. Copied from
//! `http/src/zeroize.zig` (identical body).
//!
//! `std.crypto.secureZero` is a `@memset` over a `[]volatile u8`, which
//! never lowers to `memset`: every build emits a loop of single-byte stores
//! (~3 B/ns without libc). Wiping qap's 48 KiB output buffer that way on
//! every connection cost ~16 µs of a ~285 µs handshake (2026-10-21).
//! `zeroize` stores volatile 32-byte vectors over the aligned middle and
//! volatile bytes over the unaligned head and tail: nothing can be folded
//! into a call or dropped as dead. Heap and caller buffers only — the stack
//! burn is `burn.stack` (a 32-byte vector there realigns the frame).
const std = @import("std");
const testing = std.testing;

/// Zero every byte of `buf` in place, at any alignment and length.
pub fn zeroize(buf: []u8) void {
    const Vec32 = @Vector(32, u8);
    const zero_vec: Vec32 = @splat(0);

    // Bytes up to the first 32-byte-aligned address, clamped to `buf.len`.
    const addr = @intFromPtr(buf.ptr);
    const head_len = @min(buf.len, std.mem.alignForward(usize, addr, 32) - addr);

    var i: usize = 0;
    while (i < head_len) : (i += 1) {
        const p: *volatile u8 = &buf[i];
        p.* = 0;
    }
    while (i + 32 <= buf.len) : (i += 32) {
        const p: *volatile Vec32 = @ptrCast(@alignCast(buf[i..][0..32].ptr));
        p.* = zero_vec;
    }
    while (i < buf.len) : (i += 1) {
        const p: *volatile u8 = &buf[i];
        p.* = 0;
    }
}

test "zeroize: every length 0..100 at every offset 0..33, neighbours untouched" {
    var big: [160]u8 = undefined;
    for (0..34) |offset| {
        for (0..101) |len| {
            @memset(&big, 0x5a);
            zeroize(big[offset..][0..len]);
            for (big, 0..) |b, i| {
                const inside = i >= offset and i < offset + len;
                try testing.expectEqual(@as(u8, if (inside) 0 else 0x5a), b);
            }
        }
    }
}

test "zeroize: 48 KiB" {
    const buf = try testing.allocator.alloc(u8, 48 * 1024);
    defer testing.allocator.free(buf);
    @memset(buf, 0xff);
    zeroize(buf);
    for (buf) |b| try testing.expectEqual(@as(u8, 0), b);
}
