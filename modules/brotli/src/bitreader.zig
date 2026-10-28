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
    /// slice.
    source: ?*std.Io.Reader = null,
    /// The source has ended or failed: no more is fetched.
    source_done: bool = false,
    /// The source reported `ReadFailed` (not an end of stream): the caller
    /// turns the resulting `TruncatedInput` back into that.
    read_failed: bool = false,
    /// Bytes consumed from `source` in earlier chunks.
    consumed_before: u64 = 0,

    pub fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }

    /// Pull from `r`. With an empty buffer nothing is pulled (the input ends
    /// at once — see `nextChunk`). Up to 8 bytes past the
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
        if (self.source_done) return false;
        // No buffer to refill through: the input ends here. `fillMore` would
        // rebase to a capacity of 1, which std asserts on for a streaming
        // reader — UB in ReleaseFast (no-panic sweep 2026-10-28, B-4).
        if (r.buffer.len == 0) {
            self.source_done = true;
            return false;
        }
        // The last eight bytes taken stay in the source's buffer (when it
        // has room for more besides): the accumulator may hold them unread,
        // and `unreadAhead` gives them back at the end of the stream.
        const keep: usize = if (r.buffer.len >= 16) @min(self.byte_pos, 8) else 0;
        r.toss(self.byte_pos - keep);
        self.consumed_before += self.byte_pos - keep;
        self.byte_pos = keep;
        self.data = r.buffered();
        // `fillMore` may add nothing without it being the end of the stream
        // (its own doc); only `EndOfStream` is.
        while (true) {
            r.fillMore() catch |err| {
                if (err == error.ReadFailed) self.read_failed = true;
                self.source_done = true;
                return false;
            };
            self.data = r.buffered();
            if (self.data.len > keep) return true;
        }
    }

    /// The stream ended at a byte boundary: give the whole bytes the
    /// accumulator read past it back to `data` (and so to the source, at
    /// `finish`), as far as `data` still holds them.
    pub fn unreadAhead(self: *BitReader) void {
        std.debug.assert(self.cnt % 8 == 0);
        self.byte_pos -= @min(self.cnt / 8, self.byte_pos);
        self.acc = 0;
        self.cnt = 0;
    }

    inline fn refill(self: *BitReader) void {
        if (self.cnt > 56) return;
        // Fast path, eight bytes at hand: one load fills the accumulator to
        // 57..64 bits. Only the whole bytes counted are kept: the bits above
        // `cnt` must stay zero, because the aligned-byte readers move
        // `byte_pos` past the accumulator.
        if (self.data.len - self.byte_pos >= 8) {
            const nbytes = (64 - self.cnt) >> 3;
            const v = std.mem.readInt(u64, self.data[self.byte_pos..][0..8], .little) & mask(nbytes * 8);
            self.acc |= v << @intCast(self.cnt);
            self.byte_pos += nbytes;
            self.cnt += nbytes * 8;
            return;
        }
        self.refillSlow();
    }

    /// The last bytes of a slice, or a stream chunk boundary: byte by byte.
    fn refillSlow(self: *BitReader) void {
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
    pub inline fn takeBits(self: *BitReader, n: u32) BrotliError!u32 {
        // Refill only when short: most reads after a refill find the bits
        // there (57..64 of them).
        if (self.cnt < n) {
            self.refill();
            if (self.cnt < n) return error.TruncatedInput;
        }
        const v: u32 = @truncate(self.acc & ((@as(u64, 1) << @intCast(n)) - 1)); // n ≤ 32
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
    pub inline fn readSymbol(self: *BitReader, table: *const huffman.Table) BrotliError!u16 {
        if (self.cnt < 15) self.refill(); // 15: the longest code (RFC 7932 §3.5)
        const idx: usize = @truncate(self.acc & mask(table.bits));
        var e = table.entries[idx];
        if (e.len & huffman.link_flag != 0) {
            const sub: usize = @truncate((self.acc >> table.bits) & mask(e.len & ~huffman.link_flag));
            e = table.entries[@as(usize, e.sym) + sub];
        }
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
