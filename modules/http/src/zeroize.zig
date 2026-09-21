// SPDX-License-Identifier: MIT

//! This module's `secureZero`: zero memory that must not survive a `free`
//! in ReleaseFast (request bodies, header blocks, credentials) without
//! paying for `std.crypto.secureZero`'s byte-at-a-time store.
//!
//! `std.crypto.secureZero(T, s)` is `@memset(s, zero)` over a `[]volatile
//! T` (`lib/std/crypto.zig`). `@memset` cannot lower a volatile destination
//! to the ordinary `memset` intrinsic -- doing so would let the optimizer
//! treat the write as droppable or reorderable, which is exactly what
//! `volatile` forbids -- so every build, including ReleaseFast, emits a
//! scalar loop that stores one `T` at a time. Measured (qap perf audit
//! 2026-09-21, finding F1): zeroing 4096 B this way costs 5657
//! instructions, 2048 B costs 2841. `h2_server.zig`'s per-stream
//! `body_scratch` zeroing (added in 60a08442) runs on *every* h2 stream,
//! GET included, and regressed a downstream server's h2 GET path by +13%
//! total instructions (+35% of the user-space part) for a request that has
//! no body to protect.
//!
//! `zeroize` instead does volatile stores of 32-byte vectors over the
//! aligned middle of the buffer, falling back to volatile byte stores only
//! for the unaligned head (up to 31 bytes) and tail (up to 31 bytes).
//! Measured: 169 instructions for the same 4096 B -- each store instruction
//! now moves 32 bytes instead of 1, and there are proportionally fewer of
//! them, but every one is still volatile: nothing here can be folded into a
//! call to the byte-at-a-time `compiler_rt.memset`, and nothing can be
//! dropped as dead because the buffer is never read again.
//!
//! Every `std.crypto.secureZero` call in `modules/http/src/` should be
//! `zeroize` instead; this is the module's only sanctioned way to scrub a
//! buffer before it goes back to an allocator.
const std = @import("std");
const testing = std.testing;

/// Zero every byte of `buf` in place. Handles `buf.len == 0`, lengths
/// below 32, and any starting alignment -- `buf.ptr` need not be aligned
/// to anything in particular.
pub fn zeroize(buf: []u8) void {
    const Vec32 = @Vector(32, u8);
    const zero_vec: Vec32 = @splat(0);

    // Bytes needed to bring `buf.ptr + i` up to a 32-byte-aligned address,
    // clamped to `buf.len` -- a short buffer never reaches alignment and
    // is handled entirely by the tail loop below.
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

fn expectAllZero(buf: []const u8) !void {
    for (buf, 0..) |b, idx| {
        if (b != 0) {
            std.debug.print("byte {d} of {d} was 0x{x}, not zero\n", .{ idx, buf.len, b });
            return error.TestExpectedZero;
        }
    }
}

test "zeroize: every byte is zero for lengths 0..100" {
    var len: usize = 0;
    while (len <= 100) : (len += 1) {
        var buf: [100]u8 = undefined;
        for (buf[0..len], 0..) |*b, idx| b.* = @truncate(0xaa +% idx);
        zeroize(buf[0..len]);
        try expectAllZero(buf[0..len]);
    }
}

test "zeroize: large buffers (2048, 4096, 65536 bytes)" {
    const sizes = [_]usize{ 2048, 4096, 65536 };
    for (sizes) |size| {
        const buf = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(buf);
        @memset(buf, 0xff);
        zeroize(buf);
        try expectAllZero(buf);
    }
}

test "zeroize: misaligned starts, offsets 0..33 into a bigger buffer" {
    // A slice starting at an arbitrary byte offset into a larger
    // allocation -- `buf.ptr` is then not necessarily aligned to
    // anything, which is the case this helper's head loop exists for.
    var big: [4096]u8 = undefined;
    var offset: usize = 0;
    while (offset <= 33) : (offset += 1) {
        @memset(&big, 0x5a);
        const slice = big[offset..];
        for (slice, 0..) |*b, idx| b.* = @truncate(0x5a +% idx);
        zeroize(slice);
        try expectAllZero(slice);
        // Bytes before the offset are untouched.
        for (big[0..offset]) |b| try testing.expectEqual(@as(u8, 0x5a), b);
    }
}

test "zeroize: len 0 is a no-op, not a crash" {
    var buf: [1]u8 = .{0x42};
    zeroize(buf[0..0]);
    try testing.expectEqual(@as(u8, 0x42), buf[0]);
}

test "zeroize: single byte and sub-vector lengths at various misalignments" {
    var big: [64]u8 = undefined;
    var offset: usize = 0;
    while (offset < 32) : (offset += 1) {
        var len: usize = 1;
        while (len <= 31) : (len += 1) {
            if (offset + len > big.len) break;
            @memset(&big, 0x77);
            const slice = big[offset..][0..len];
            zeroize(slice);
            try expectAllZero(slice);
        }
    }
}
