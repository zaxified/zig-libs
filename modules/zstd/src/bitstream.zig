// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Forward bit writer shared by the FSE, Huffman and sequence encoders.
//!
//! Port of libzstd's `BIT_CStream_t` (lib/common/bitstream.h, v1.5.7). Bits are
//! appended least-significant first into a 64-bit accumulator and flushed a
//! whole byte at a time. The container is always 64 bits wide, whatever the
//! target: libzstd uses `size_t`, and a narrower container changes only *when*
//! bytes are flushed, never which bits come out (the flush points are chosen so
//! that the accumulator never overflows, and every caller here mirrors the
//! 64-bit flush schedule).
//!
//! Overflow handling is libzstd's, not an error return: the write pointer
//! saturates at `end` (capacity minus one container), and `close` reports 0 —
//! "did not fit" — when it got there. Callers treat 0 as "not compressible into
//! this space", exactly as the reference does.

const std = @import("std");

pub const Error = error{DstSizeTooSmall};

pub const CStream = struct {
    container: u64 = 0,
    bit_pos: u32 = 0,
    buf: []u8,
    ptr: usize = 0,
    /// Last position a full 8-byte flush may start at.
    end: usize,

    pub fn init(buf: []u8) Error!CStream {
        if (buf.len <= 8) return error.DstSizeTooSmall;
        return .{ .buf = buf, .end = buf.len - 8 };
    }

    /// Append the low `nb_bits` bits of `value` (masked, as `BIT_addBits` does).
    pub inline fn addBits(s: *CStream, value: u64, nb_bits: u32) void {
        std.debug.assert(nb_bits < 32);
        std.debug.assert(nb_bits + s.bit_pos < 64);
        const mask: u64 = (@as(u64, 1) << @intCast(nb_bits)) - 1;
        s.container |= (value & mask) << @intCast(s.bit_pos);
        s.bit_pos += nb_bits;
    }

    /// `BIT_addBitsFast`: the caller guarantees `value` has no bits above `nb_bits`.
    pub inline fn addBitsFast(s: *CStream, value: u64, nb_bits: u32) void {
        std.debug.assert(value >> @intCast(nb_bits) == 0);
        s.container |= value << @intCast(s.bit_pos);
        s.bit_pos += nb_bits;
    }

    /// `BIT_flushBits`: write the whole bytes accumulated so far; saturate at `end`.
    pub inline fn flush(s: *CStream) void {
        const nb_bytes = s.bit_pos >> 3;
        std.debug.assert(s.ptr <= s.end);
        std.mem.writeInt(u64, s.buf[s.ptr..][0..8], s.container, .little);
        s.ptr += nb_bytes;
        if (s.ptr > s.end) s.ptr = s.end;
        s.bit_pos &= 7;
        // nb_bytes is at most 7 here (bit_pos < 64), so the shift stays in range.
        s.container = if (nb_bytes == 0) s.container else s.container >> @intCast(nb_bytes * 8);
    }

    /// `BIT_closeCStream`: end mark, final flush. Returns the stream size, or 0
    /// when the stream did not fit.
    pub fn close(s: *CStream) usize {
        s.addBitsFast(1, 1);
        s.flush();
        if (s.ptr >= s.end) return 0;
        return s.ptr + @intFromBool(s.bit_pos > 0);
    }
};

test "bit order is least-significant first, end mark closes the stream" {
    var buf: [16]u8 = undefined;
    var s = try CStream.init(&buf);
    s.addBits(0b101, 3);
    s.addBits(0b11, 2);
    const n = s.close();
    // 101 | 11<<3 | 1<<5 = 0b111101
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0b111101), buf[0]);
}

test "a stream that reaches the saturation point reports 0" {
    var buf: [10]u8 = undefined; // end = 2
    var s = try CStream.init(&buf);
    s.addBits(0xffff, 16);
    s.flush();
    try std.testing.expectEqual(@as(usize, 0), s.close());
}

test "capacity of one container or less is refused" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.DstSizeTooSmall, CStream.init(&buf));
}
