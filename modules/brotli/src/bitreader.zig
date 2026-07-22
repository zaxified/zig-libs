//! Least-significant-bit-first bit reader over an in-memory Brotli stream.

const std = @import("std");
const BrotliError = @import("errors.zig").BrotliError;
const huffman = @import("huffman.zig");

pub const BitReader = struct {
    data: []const u8,
    byte_pos: usize = 0,
    acc: u64 = 0,
    cnt: u32 = 0, // number of valid low bits in `acc`

    pub fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }

    fn refill(self: *BitReader) void {
        while (self.cnt <= 56 and self.byte_pos < self.data.len) {
            self.acc |= @as(u64, self.data[self.byte_pos]) << @intCast(self.cnt);
            self.byte_pos += 1;
            self.cnt += 8;
        }
    }

    pub fn availableBits(self: *const BitReader) usize {
        return self.cnt + (self.data.len - self.byte_pos) * 8;
    }

    fn mask(n: u32) u64 {
        if (n >= 64) return ~@as(u64, 0);
        return (@as(u64, 1) << @intCast(n)) - 1;
    }

    /// Read `n` (0..32) bits. Errors if fewer than `n` bits remain.
    pub fn takeBits(self: *BitReader, n: u32) BrotliError!u32 {
        if (n == 0) return 0;
        self.refill();
        if (self.cnt < n) return error.TruncatedInput;
        const v: u32 = @truncate(self.acc & mask(n));
        self.acc >>= @intCast(n);
        self.cnt -= n;
        return v;
    }

    /// Peek `n` bits without consuming; missing bits beyond EOF read as zero.
    pub fn peekBits(self: *BitReader, n: u32) u32 {
        self.refill();
        return @truncate(self.acc & mask(n));
    }

    fn dropBits(self: *BitReader, n: u32) void {
        self.acc >>= @intCast(n);
        self.cnt -= n;
    }

    /// Decode one symbol from a prefix-code table.
    pub fn readSymbol(self: *BitReader, table: *const huffman.Table) BrotliError!u16 {
        self.refill();
        const idx: usize = @truncate(self.acc & mask(table.bits));
        const e = table.entries[idx];
        if (e.len > self.cnt) return error.TruncatedInput;
        self.dropBits(e.len);
        return e.sym;
    }

    /// Discard bits up to the next byte boundary; they must all be zero.
    pub fn jumpToByteBoundary(self: *BitReader) BrotliError!void {
        const n = self.cnt & 7;
        if (n == 0) return;
        const pad = self.acc & mask(n);
        if (pad != 0) return error.InvalidPadding;
        self.dropBits(n);
    }

    /// Copy `dst.len` byte-aligned bytes into `dst`. Precondition: byte aligned.
    pub fn readAlignedBytes(self: *BitReader, dst: []u8) BrotliError!void {
        var i: usize = 0;
        while (i < dst.len and self.cnt >= 8) : (i += 1) {
            dst[i] = @truncate(self.acc & 0xff);
            self.dropBits(8);
        }
        const remaining = dst.len - i;
        if (remaining == 0) return;
        if (self.byte_pos + remaining > self.data.len) return error.TruncatedInput;
        @memcpy(dst[i..], self.data[self.byte_pos..][0..remaining]);
        self.byte_pos += remaining;
    }

    /// Skip `n` byte-aligned bytes. Precondition: byte aligned.
    pub fn skipAlignedBytes(self: *BitReader, n: usize) BrotliError!void {
        var rem = n;
        while (rem > 0 and self.cnt >= 8) : (rem -= 1) self.dropBits(8);
        if (rem == 0) return;
        if (self.byte_pos + rem > self.data.len) return error.TruncatedInput;
        self.byte_pos += rem;
    }
};
