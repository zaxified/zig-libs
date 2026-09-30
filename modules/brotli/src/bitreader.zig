// SPDX-License-Identifier: MIT
//! Least-significant-bit-first bit reader over a Brotli stream — an in-memory
//! slice, or a `std.Io.Reader` pulled from as bits are needed.

const std = @import("std");
const BrotliError = @import("errors.zig").BrotliError;
const huffman = @import("huffman.zig");

pub const BitReader = struct {
    /// The bytes at hand: the whole input for a slice, the reader's buffered
    /// bytes for a stream.
    data: []const u8,
    byte_pos: usize = 0,
    acc: u64 = 0,
    cnt: u32 = 0, // number of valid low bits in `acc`
    /// Streaming source; `data` is always a view of its buffer. Null for a
    /// slice, and once the source has ended or failed.
    source: ?*std.Io.Reader = null,
    /// The source reported `ReadFailed` (not an end of stream): the caller
    /// turns the resulting `TruncatedInput` back into that.
    read_failed: bool = false,
    /// Bytes consumed from `source` in earlier chunks.
    consumed_before: u64 = 0,

    pub fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }

    /// Pull from `r`. Its buffer must be non-empty. Up to 8 bytes past the
    /// end of the Brotli stream may be consumed from it (the accumulator reads
    /// ahead); `finish` gives back what `data` still holds.
    pub fn initStream(r: *std.Io.Reader) BitReader {
        return .{ .data = r.buffered(), .source = r };
    }

    /// Input bytes taken so far (into the accumulator or copied out).
    pub fn consumedBytes(self: *const BitReader) u64 {
        return self.consumed_before + self.byte_pos;
    }

    /// Hand the unread part of the current chunk back to the source.
    pub fn finish(self: *BitReader) void {
        const r = self.source orelse return;
        r.toss(self.byte_pos);
        self.consumed_before += self.byte_pos;
        self.byte_pos = 0;
        self.data = r.buffered();
    }

    /// `data` is used up: fetch the next chunk. False at the end of input
    /// (always, for a slice).
    fn nextChunk(self: *BitReader) bool {
        const r = self.source orelse return false;
        r.toss(self.byte_pos);
        self.consumed_before += self.byte_pos;
        self.byte_pos = 0;
        self.data = &.{};
        // `fillMore` may add nothing without it being the end of the stream
        // (its own doc); only `EndOfStream` is.
        while (true) {
            r.fillMore() catch |err| {
                if (err == error.ReadFailed) self.read_failed = true;
                self.source = null;
                return false;
            };
            self.data = r.buffered();
            if (self.data.len != 0) return true;
        }
    }

    fn refill(self: *BitReader) void {
        while (self.cnt <= 56) {
            if (self.byte_pos == self.data.len and !self.nextChunk()) return;
            self.acc |= @as(u64, self.data[self.byte_pos]) << @intCast(self.cnt);
            self.byte_pos += 1;
            self.cnt += 8;
        }
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
        while (i < dst.len) {
            if (self.byte_pos == self.data.len and !self.nextChunk()) return error.TruncatedInput;
            const n = @min(dst.len - i, self.data.len - self.byte_pos);
            @memcpy(dst[i..][0..n], self.data[self.byte_pos..][0..n]);
            self.byte_pos += n;
            i += n;
        }
    }

    /// Skip `n` byte-aligned bytes. Precondition: byte aligned.
    pub fn skipAlignedBytes(self: *BitReader, n: usize) BrotliError!void {
        var rem = n;
        while (rem > 0 and self.cnt >= 8) : (rem -= 1) self.dropBits(8);
        while (rem > 0) {
            if (self.byte_pos == self.data.len and !self.nextChunk()) return error.TruncatedInput;
            const k = @min(rem, self.data.len - self.byte_pos);
            self.byte_pos += k;
            rem -= k;
        }
    }
};
