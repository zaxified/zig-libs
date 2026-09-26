// SPDX-License-Identifier: MIT
//! Filling memory without `compiler_rt.memset`.
//!
//! Zig 0.16 without libc lowers `@memset` (and a large zero initializer) to
//! `compiler_rt.memset`, which stores one byte at a time. The tables this
//! module clears for every block (Huffman nodes, histograms, rank tables)
//! and the RLE blocks the decoder expands made it 11 % of the cycles at
//! 4 KB per frame (Z21). Stores here go through `volatile` 32-byte vectors:
//! volatile so that LLVM neither drops them nor recognises the loop as a
//! memset idiom and turns it back into the same call.
//!
//! Delete with a Zig whose `compiler_rt.memset` is vectorised (upstream
//! `fastMemset`, after 0.16) and go back to `@memset`.

const std = @import("std");

const V = @Vector(32, u8);

/// `@memset(buf, value)` for bytes. The tail is one more store that
/// overlaps the last full one, not a byte loop.
pub fn bytes(buf: []u8, value: u8) void {
    const p: [*]volatile u8 = buf.ptr;
    const n = buf.len;
    if (n >= 32) {
        const v: V = @splat(value);
        var i: usize = 0;
        while (i + 32 <= n) : (i += 32) store(V, p + i, v);
        if (i < n) store(V, p + n - 32, v);
    } else if (n >= 8) {
        const w: u64 = @as(u64, value) * 0x0101010101010101;
        var i: usize = 0;
        while (i + 8 <= n) : (i += 8) store(u64, p + i, w);
        if (i < n) store(u64, p + n - 8, w);
    } else {
        for (0..n) |i| p[i] = value;
    }
}

/// `@memset(buf[pos..][0..n], value)` in 8-byte stores that may run up
/// to 7 bytes past `pos + n` (libzstd's FSE spread): `buf` needs that
/// slack, and a later run overwrites it. For many short runs, where a
/// call per run is the cost.
pub inline fn run(buf: []u8, pos: usize, n: usize, value: u8) void {
    std.debug.assert(pos + n + 7 <= buf.len or n == 0);
    const p: [*]volatile u8 = buf.ptr;
    const w: u64 = @as(u64, value) * 0x0101010101010101;
    var i: usize = 0;
    while (i < n) : (i += 8) store(u64, p + pos + i, w);
}

inline fn store(comptime T: type, at: [*]volatile u8, v: T) void {
    const w: *align(1) volatile T = @ptrCast(at);
    w.* = v;
}

/// `@memset(buf, 0)` for any element type whose zero is all zero bytes.
pub fn zero(comptime T: type, buf: []T) void {
    bytes(std.mem.sliceAsBytes(buf), 0);
}

test "bytes fills every length and alignment" {
    var buf: [200]u8 = undefined;
    for (0..8) |off| for (0..100) |len| {
        @memset(&buf, 0xAA);
        bytes(buf[off..][0..len], 0x5C);
        for (buf, 0..) |b, i| {
            const inside = i >= off and i < off + len;
            try std.testing.expectEqual(@as(u8, if (inside) 0x5C else 0xAA), b);
        }
    };
}

test "run fills its range and only spills into the slack" {
    var buf: [40]u8 = undefined;
    for (0..20) |n| {
        @memset(&buf, 0xAA);
        run(&buf, 3, n, 0x11);
        for (buf, 0..) |b, i| {
            if (i >= 3 and i < 3 + n) try std.testing.expectEqual(@as(u8, 0x11), b);
            if (i < 3 or i >= 3 + n + 7) try std.testing.expectEqual(@as(u8, 0xAA), b);
        }
    }
}

test "zero clears a typed slice" {
    const S = struct { a: u32 = 0, b: u16 = 0, c: u8 = 0, d: u8 = 0 };
    var s: [9]S = @splat(.{ .a = 7, .b = 7, .c = 7, .d = 7 });
    zero(S, s[1..8]);
    try std.testing.expectEqual(@as(u32, 7), s[0].a);
    for (s[1..8]) |e| try std.testing.expectEqual(S{}, e);
    try std.testing.expectEqual(@as(u8, 7), s[8].d);
}
