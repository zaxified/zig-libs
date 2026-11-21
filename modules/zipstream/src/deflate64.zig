// SPDX-License-Identifier: MIT
//! Deflate64 ("enhanced deflate", ZIP method 9) decoder, written from RFC 1951 and the
//! differences APPNOTE 4.4.5 / 5.8 name: a 64 KiB window (distances up to 65536: the
//! distance codes 30 and 31 are valid, 14 extra bits each), and length code 285, which
//! is "258" in Deflate, means a base of 3 with 16 extra bits (lengths 3..65538).
//! Everything else, the block types and the dynamic-table coding, is Deflate's.
//!
//! A pull decoder: `Inflate.reader` is a `std.Io.Reader` that decodes on demand into the
//! caller's destination, keeping a 64 KiB history ring; nothing is buffered beyond that and
//! the bit accumulator. Corrupt or truncated data ends the stream with `error.ReadFailed`
//! (`Inflate.err` says why). It stops at the end of the final block and reads no input past it
//! beyond the bytes already in its accumulator.

const std = @import("std");
const Io = std.Io;

pub const DecodeError = error{
    /// The input ended inside a block.
    Truncated,
    /// A block type of 3.
    BadBlockType,
    /// A stored block whose length and its complement disagree.
    BadStoredLength,
    /// A code-length set that is over-subscribed, or incomplete where that is not allowed.
    BadHuffman,
    /// Too many length or distance codes, a repeat with nothing before it, or a repeat past the table.
    BadTable,
    /// A literal/length or distance symbol that is not defined (286, 287; 30, 31 in plain Deflate).
    BadSymbol,
    /// A match that reaches before the start of the output.
    BadDistance,
    /// A dynamic block without an end-of-block code.
    NoEndCode,
};

const window_size = 1 << 16;
const fast_bits = 9;

const Huffman = struct {
    /// Codes of each length 1..15 (index 0 unused).
    count: [16]u16 = @splat(0),
    /// Symbols in canonical order.
    symbol: [288]u16 = @splat(0),
    /// `len << 12 | symbol` for codes up to `fast_bits` long, indexed by the next `fast_bits` input bits (0 = not here).
    fast: [1 << fast_bits]u16 = @splat(0),

    /// Build from code lengths; false when the set is over-subscribed, or incomplete and not the single-code case.
    fn build(h: *Huffman, lengths: []const u8) bool {
        h.count = @splat(0);
        h.fast = @splat(0);
        for (lengths) |l| h.count[l] += 1;
        const used = lengths.len - h.count[0];
        if (used == 0) return true; // no codes: a decoder that never meets one (all-literal blocks with no distances)
        var left: i32 = 1;
        for (1..16) |l| {
            left <<= 1;
            left -= h.count[l];
            if (left < 0) return false;
        }
        if (left > 0 and used != 1) return false;
        var offs: [16]u16 = undefined;
        offs[1] = 0;
        for (1..15) |l| offs[l + 1] = offs[l] + h.count[l];
        for (lengths, 0..) |l, sym| if (l != 0) {
            h.symbol[offs[l]] = @intCast(sym);
            offs[l] += 1;
        };
        // The fast table: each code of up to `fast_bits` bits, bit-reversed (the stream packs a
        // code's first bit lowest), repeated for every value of the bits after it.
        var code: u32 = 0;
        var index: usize = 0;
        for (1..fast_bits + 1) |l| {
            for (0..h.count[l]) |_| {
                const sym = h.symbol[index];
                index += 1;
                const rev = @bitReverse(@as(u16, @intCast(code))) >> @intCast(16 - l);
                var k: usize = rev;
                while (k < h.fast.len) : (k += @as(usize, 1) << @intCast(l)) h.fast[k] = @intCast(l << 12 | sym);
                code += 1;
            }
            code <<= 1;
        }
        return true;
    }
};

const len_base = [_]u16{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3 };
const len_extra = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16 };
const dist_base = [_]u32{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153 };
const dist_extra = [_]u8{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14 };
const clen_order = [_]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

pub const Inflate = struct {
    reader: Io.Reader,
    input: *Io.Reader,
    /// Why the stream ended with `error.ReadFailed`.
    err: ?DecodeError = null,
    bits: u64 = 0,
    nbits: u7 = 0,
    state: enum { header, stored, codes, done, failed } = .header,
    final: bool = false,
    stored_left: u32 = 0,
    /// A match being copied out: bytes left and its distance.
    match_len: u32 = 0,
    match_dist: u32 = 0,
    /// Bytes produced in all; the ring index is the low 16 bits.
    total: u64 = 0,
    ring: [window_size]u8 = undefined,
    lit: Huffman = .{},
    dist: Huffman = .{},

    /// Initialise in place (the ring is 64 KiB). Reading starts on the first `reader` call.
    pub fn init(self: *Inflate, input: *Io.Reader) void {
        self.* = .{
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
            .input = input,
        };
    }

    fn fail(self: *Inflate, e: DecodeError) void {
        self.err = e;
        self.state = .failed;
    }

    /// Top the accumulator up to at least 32 bits when the input has them.
    fn refill(self: *Inflate) void {
        while (self.nbits <= 56) {
            const b = self.input.takeByte() catch return;
            self.bits |= @as(u64, b) << @intCast(self.nbits);
            self.nbits += 8;
        }
    }

    fn need(self: *Inflate, n: u6) DecodeError!void {
        if (self.nbits >= n) return;
        self.refill();
        if (self.nbits < n) return error.Truncated;
    }

    fn take(self: *Inflate, n: u6) DecodeError!u32 {
        if (n == 0) return 0;
        try self.need(n);
        const v: u32 = @intCast(self.bits & ((@as(u64, 1) << n) - 1));
        self.bits >>= n;
        self.nbits -= n;
        return v;
    }

    fn symbolOf(self: *Inflate, h: *const Huffman) DecodeError!u16 {
        if (self.nbits < 15) self.refill();
        if (self.nbits >= fast_bits) {
            const e = h.fast[@intCast(self.bits & ((1 << fast_bits) - 1))];
            if (e != 0) {
                const l: u6 = @intCast(e >> 12);
                self.bits >>= l;
                self.nbits -= l;
                return e & 0xfff;
            }
        }
        // Canonical decoding one bit at a time (longer codes, or the last bits of the input).
        var code: i32 = 0;
        var first: i32 = 0;
        var index: i32 = 0;
        var len: u6 = 1;
        var bits = self.bits;
        var avail = self.nbits;
        while (len <= 15) : (len += 1) {
            if (avail == 0) return error.Truncated;
            code |= @intCast(bits & 1);
            bits >>= 1;
            avail -= 1;
            const count: i32 = h.count[len];
            if (code - count < first) {
                self.bits = bits;
                self.nbits = avail;
                return h.symbol[@intCast(index + (code - first))];
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        return error.BadSymbol;
    }

    fn readHeader(self: *Inflate) DecodeError!void {
        self.final = (try self.take(1)) == 1;
        switch (try self.take(2)) {
            0 => {
                // Stored: drop the bits up to the byte boundary, then LEN and NLEN.
                const drop: u6 = @intCast(self.nbits % 8);
                self.bits >>= drop;
                self.nbits -= drop;
                const len = try self.take(16);
                const nlen = try self.take(16);
                if (len != (~nlen & 0xffff)) return error.BadStoredLength;
                self.stored_left = len;
                self.state = .stored;
            },
            1 => {
                var l: [288]u8 = undefined;
                @memset(l[0..144], 8);
                @memset(l[144..256], 9);
                @memset(l[256..280], 7);
                @memset(l[280..288], 8);
                _ = self.lit.build(&l);
                var d: [32]u8 = @splat(5);
                _ = self.dist.build(&d);
                self.state = .codes;
            },
            2 => {
                try self.readDynamic();
                self.state = .codes;
            },
            else => return error.BadBlockType,
        }
    }

    fn readDynamic(self: *Inflate) DecodeError!void {
        const nlen: usize = (try self.take(5)) + 257;
        const ndist: usize = (try self.take(5)) + 1;
        const ncode: usize = (try self.take(4)) + 4;
        if (nlen > 286 or ndist > 32) return error.BadTable;
        var cl: [19]u8 = @splat(0);
        for (0..ncode) |i| cl[clen_order[i]] = @intCast(try self.take(3));
        var clh: Huffman = .{};
        if (!clh.build(&cl)) return error.BadHuffman;
        var lengths: [288 + 32]u8 = @splat(0);
        var i: usize = 0;
        while (i < nlen + ndist) {
            const sym = try self.symbolOf(&clh);
            if (sym < 16) {
                lengths[i] = @intCast(sym);
                i += 1;
                continue;
            }
            var rep: usize = undefined;
            var val: u8 = 0;
            switch (sym) {
                16 => {
                    if (i == 0) return error.BadTable;
                    val = lengths[i - 1];
                    rep = 3 + try self.take(2);
                },
                17 => rep = 3 + try self.take(3),
                else => rep = 11 + try self.take(7),
            }
            if (i + rep > nlen + ndist) return error.BadTable;
            @memset(lengths[i..][0..rep], val);
            i += rep;
        }
        if (lengths[256] == 0) return error.NoEndCode;
        if (!self.lit.build(lengths[0..nlen])) return error.BadHuffman;
        if (!self.dist.build(lengths[nlen..][0..ndist])) return error.BadHuffman;
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *Inflate = @alignCast(@fieldParentPtr("reader", r));
        const dst = limit.slice(try w.writableSliceGreedy(1));
        var n: usize = 0;
        // An error ends the loop and surfaces on the call after the bytes decoded so far were delivered.
        loop: while (n < dst.len) {
            if (self.match_len != 0) {
                const m = @min(self.match_len, dst.len - n);
                for (0..m) |_| {
                    const b = self.ring[(self.total -% self.match_dist) & (window_size - 1)];
                    self.ring[self.total & (window_size - 1)] = b;
                    self.total += 1;
                    dst[n] = b;
                    n += 1;
                }
                self.match_len -= @intCast(m);
                continue;
            }
            switch (self.state) {
                .done, .failed => break :loop,
                .header => self.readHeader() catch |e| {
                    self.fail(e);
                    break :loop;
                },
                .stored => {
                    if (self.stored_left == 0) {
                        self.state = if (self.final) .done else .header;
                        continue;
                    }
                    // The accumulator holds whole bytes now; they come first.
                    const b: u8 = if (self.nbits >= 8) blk: {
                        const v: u8 = @truncate(self.bits);
                        self.bits >>= 8;
                        self.nbits -= 8;
                        break :blk v;
                    } else self.input.takeByte() catch {
                        self.fail(error.Truncated);
                        break :loop;
                    };
                    self.ring[self.total & (window_size - 1)] = b;
                    self.total += 1;
                    dst[n] = b;
                    n += 1;
                    self.stored_left -= 1;
                },
                .codes => {
                    const sym = self.symbolOf(&self.lit) catch |e| {
                        self.fail(e);
                        break :loop;
                    };
                    if (sym < 256) {
                        const b: u8 = @intCast(sym);
                        self.ring[self.total & (window_size - 1)] = b;
                        self.total += 1;
                        dst[n] = b;
                        n += 1;
                    } else if (sym == 256) {
                        self.state = if (self.final) .done else .header;
                    } else {
                        self.startMatch(sym) catch |e| {
                            self.fail(e);
                            break :loop;
                        };
                    }
                },
            }
        }
        if (n == 0) return if (self.state == .done) error.EndOfStream else error.ReadFailed;
        w.advance(n);
        return n;
    }

    /// The length symbol `sym` (257..) is read: its extra bits, then the distance code and its extra bits.
    fn startMatch(self: *Inflate, sym: u16) DecodeError!void {
        const li = sym - 257;
        if (li >= len_base.len) return error.BadSymbol;
        const len = len_base[li] + try self.take(@intCast(len_extra[li]));
        const ds = try self.symbolOf(&self.dist);
        if (ds >= dist_base.len) return error.BadSymbol;
        const d = dist_base[ds] + try self.take(@intCast(dist_extra[ds]));
        if (d > self.total) return error.BadDistance;
        self.match_len = len;
        self.match_dist = d;
    }
};
