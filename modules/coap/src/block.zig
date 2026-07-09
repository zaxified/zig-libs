// SPDX-License-Identifier: MIT

//! coap block-wise transfer (C6) — RFC 7959: moving a payload larger than one
//! datagram in numbered blocks. A CoAP endpoint carries a **Block1** (option 27,
//! request body) or **Block2** (option 23, response body) option whose value
//! packs three fields — the block number, a "more" flag, and a size exponent:
//!
//! ```
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |  NUM  |M| SZX |   (last byte; NUM continues into any earlier bytes)
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! NUM is the 0..20-bit block index, M ("more") is set on every block but the
//! last, and SZX (0..6) gives the block size `2^(SZX+4)` — 16 … 1024 bytes. The
//! value is 0..3 bytes, minimally encoded like a CoAP uint (no leading zero
//! bytes; an all-zero descriptor is the empty value).
//!
//! This is the value codec + the byte-slicing arithmetic, transport- and
//! allocation-agnostic (the same caller-driven, borrow-the-buffer style as the
//! rest of the module): `Block.encode`/`decode` for the option value, `split`
//! to carve block N out of a full payload, and `Assembler` to gather arriving
//! blocks into a caller-provided buffer.
//!
//! ## Deferred (documented, not built)
//!
//! - **Combined Block1+Block2 in one exchange** (RFC 7959 §3.3) — a large
//!   request whose large response is itself blocked. Each direction works here
//!   in isolation; interleaving the two option streams is left to the caller.
//! - **SZX renegotiation mid-transfer** (a peer answering a smaller block size
//!   than requested). `Assembler` positions each block by its own SZX, so it
//!   tolerates a *constant* size only; a size change partway is not stitched.

const std = @import("std");
const coap = @import("root.zig");

/// The size of a block for size-exponent `szx`: `2^(SZX+4)`, i.e. 16 (SZX 0) …
/// 1024 (SZX 6). SZX 7 is reserved (see `Block.decode`).
pub fn sizeForSzx(szx: u3) usize {
    return @as(usize, 1) << (@as(u5, szx) + 4);
}

/// A decoded Block1/Block2 option value: block index, the "more" flag, and the
/// size exponent. Number-agnostic — the caller attaches it to option 23 (Block2)
/// or 27 (Block1); the wire codec is identical for both.
pub const Block = struct {
    /// Block index (0 … 2^20-1).
    num: u32,
    /// M — set when further blocks follow this one.
    more: bool = false,
    /// SZX — the size exponent (block size = `2^(SZX+4)`).
    szx: u3,

    /// The largest representable block number (20-bit NUM field).
    pub const max_num: u32 = (1 << 20) - 1;

    pub const DecodeError = error{
        /// A block option value is at most 3 bytes.
        TooLong,
        /// SZX 7 is reserved (RFC 7959 §2.2) — treat as a bad option.
        ReservedSzx,
    };

    pub const EncodeError = error{
        /// `num` exceeds the 20-bit NUM field.
        NumTooLarge,
    };

    /// This descriptor's block size in bytes.
    pub fn size(self: Block) usize {
        return sizeForSzx(self.szx);
    }

    /// The byte offset of this block within the whole payload (`num * size`).
    pub fn offset(self: Block) usize {
        return @as(usize, self.num) * self.size();
    }

    /// Decode a 0..3-byte Block option value (RFC 7959 §2.2).
    pub fn decode(bytes: []const u8) DecodeError!Block {
        if (bytes.len > 3) return error.TooLong;
        var v: u32 = 0;
        for (bytes) |b| v = (v << 8) | b;
        const szx: u3 = @truncate(v & 0x7);
        if (szx == 7) return error.ReservedSzx;
        return .{ .num = v >> 4, .more = (v & 0x8) != 0, .szx = szx };
    }

    /// Encode into `buf`, returning the minimal (0..3-byte, no leading zero
    /// bytes) prefix — an all-zero descriptor (NUM 0, M 0, SZX 0) is the empty
    /// value, exactly like the CoAP uint codec.
    pub fn encode(self: Block, buf: *[3]u8) EncodeError![]const u8 {
        if (self.num > max_num) return error.NumTooLarge;
        const v: u32 = (self.num << 4) |
            (@as(u32, @intFromBool(self.more)) << 3) |
            @as(u32, self.szx);
        buf.* = .{ @truncate(v >> 16), @truncate(v >> 8), @truncate(v) };
        var start: usize = 0;
        while (start < 3 and buf[start] == 0) start += 1;
        return buf[start..];
    }
};

/// One block carved out of a full payload by `split`: the block's bytes plus the
/// descriptor to put on the wire.
pub const Chunk = struct {
    /// The block's slice of the source payload (borrows it).
    data: []const u8,
    /// The matching Block1/Block2 descriptor for `data`.
    descriptor: Block,
};

/// Carve block `num` (of size `2^(szx+4)`) out of `payload`. The returned
/// `descriptor.more` is set when bytes remain past this block. `num` may address
/// the exact end (an empty final block); addressing past the end is
/// `error.OutOfRange`.
pub fn split(payload: []const u8, szx: u3, num: u32) error{OutOfRange}!Chunk {
    const bs = sizeForSzx(szx);
    const start = @as(usize, num) * bs;
    if (start > payload.len) return error.OutOfRange;
    const end = @min(start + bs, payload.len);
    return .{
        .data = payload[start..end],
        .descriptor = .{ .num = num, .more = end < payload.len, .szx = szx },
    };
}

/// Reassembles arriving blocks into a caller-provided buffer — the same
/// caller-storage, zero-allocation pattern as `reliability.Dedup`. Each accepted
/// block is written at `num * blockSize`; the transfer is complete once a block
/// with M unset (the last) has been seen **and** every byte from offset 0 up to
/// it has actually been written by an accepted block (never a gap of
/// never-written buffer contents).
pub const Assembler = struct {
    /// Caller storage for the reassembled payload.
    buf: []u8,
    /// Bytes written so far — also the *contiguous* coverage from offset 0
    /// (see `accept`'s gap check), so this doubles as the payload length.
    len: usize = 0,
    /// Set once the final (M==0) block has been accepted.
    done: bool = false,
    /// SZX of the first accepted block; a later block with a different SZX is
    /// a mid-transfer size renegotiation, which this assembler does not
    /// support (see the module doc comment) and rejects rather than silently
    /// mis-assembling.
    szx: ?u3 = null,

    pub const Error = error{
        /// A block would write past the end of `buf`.
        BufferTooSmall,
        /// The block offset/length overflows a `usize`.
        Overflow,
        /// The block's start offset is beyond the current contiguous coverage
        /// — accepting it would leave a never-written gap in `buf` between the
        /// existing coverage and this block (e.g. a lone high-`num` final
        /// block on a fresh assembler). Rejected so `payload()`/`isComplete()`
        /// can never expose never-written bytes.
        NonContiguousBlock,
        /// This block's SZX differs from the first accepted block's SZX.
        SzxChanged,
    };

    /// Initialize over caller storage.
    pub fn init(buf: []u8) Assembler {
        return .{ .buf = buf };
    }

    /// Write `data` (block `blk`'s bytes) at its offset and note completion when
    /// `blk.more` is false. `data` should be `blk.size()` bytes except on the
    /// final block; the assembler does not itself require full blocks.
    ///
    /// Rejects (rather than silently mis-assembling) a block whose start
    /// offset exceeds the current contiguous coverage (`error.NonContiguousBlock`
    /// — closes a gap that would otherwise let a single high-`num`, `more=false`
    /// block mark the transfer complete over never-written buffer bytes) and a
    /// block whose SZX differs from the first accepted block's (`error.SzxChanged`).
    pub fn accept(self: *Assembler, blk: Block, data: []const u8) Error!void {
        if (self.szx) |s| {
            if (blk.szx != s) return error.SzxChanged;
        } else {
            self.szx = blk.szx;
        }
        const start = std.math.mul(usize, blk.num, blk.size()) catch return error.Overflow;
        if (start > self.len) return error.NonContiguousBlock;
        const end = std.math.add(usize, start, data.len) catch return error.Overflow;
        if (end > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[start..end], data);
        if (end > self.len) self.len = end;
        if (!blk.more) self.done = true;
    }

    /// The reassembled payload so far (a prefix of `buf`).
    pub fn payload(self: *const Assembler) []const u8 {
        return self.buf[0..self.len];
    }

    /// Whether the final block has been accepted.
    pub fn isComplete(self: *const Assembler) bool {
        return self.done;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Block value codec: field packing, sizes, and minimal encoding" {
    // SZX → block size.
    try testing.expectEqual(@as(usize, 16), sizeForSzx(0));
    try testing.expectEqual(@as(usize, 1024), sizeForSzx(6));

    // Empty value ⇒ NUM 0, M 0, SZX 0.
    const zero = try Block.decode(&.{});
    try testing.expectEqual(@as(u32, 0), zero.num);
    try testing.expect(!zero.more);
    try testing.expectEqual(@as(u3, 0), zero.szx);

    var buf: [3]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{}, try (Block{ .num = 0, .szx = 0 }).encode(&buf));

    // 1-byte value: NUM in the high nibble. num=2, more, szx=6 → 0x2E.
    const one = Block{ .num = 2, .more = true, .szx = 6 };
    const enc1 = try one.encode(&buf);
    try testing.expectEqualSlices(u8, &.{0x2E}, enc1);
    const dec1 = try Block.decode(enc1);
    try testing.expectEqual(@as(u32, 2), dec1.num);
    try testing.expect(dec1.more);
    try testing.expectEqual(@as(u3, 6), dec1.szx);

    // Multi-byte NUM round-trips across the 1→2→3 byte boundaries.
    for ([_]u32{ 0, 1, 15, 16, 4095, 4096, Block.max_num }) |num| {
        const b = Block{ .num = num, .more = false, .szx = 4 };
        const enc = try b.encode(&buf);
        try testing.expect(enc.len <= 3);
        const dec = try Block.decode(enc);
        try testing.expectEqual(num, dec.num);
        try testing.expectEqual(@as(u3, 4), dec.szx);
        try testing.expect(!dec.more);
    }

    // Errors: reserved SZX 7, over-long value, over-large NUM.
    try testing.expectError(error.ReservedSzx, Block.decode(&.{0x07}));
    try testing.expectError(error.TooLong, Block.decode(&.{ 1, 2, 3, 4 }));
    try testing.expectError(error.NumTooLarge, (Block{ .num = Block.max_num + 1, .szx = 0 }).encode(&buf));
}

test "split: carves blocks and sets the more flag at the boundary" {
    const payload = "0123456789abcdefX"; // 17 bytes, szx 0 ⇒ 16-byte blocks
    const c0 = try split(payload, 0, 0);
    try testing.expectEqualStrings("0123456789abcdef", c0.data);
    try testing.expect(c0.descriptor.more);
    try testing.expectEqual(@as(u32, 0), c0.descriptor.num);

    const c1 = try split(payload, 0, 1);
    try testing.expectEqualStrings("X", c1.data);
    try testing.expect(!c1.descriptor.more); // last block

    // Addressing the exact end is an empty final block; past the end errors.
    const c2 = try split("0123456789abcdef", 0, 1); // 16 bytes → num 1 at end
    try testing.expectEqual(@as(usize, 0), c2.data.len);
    try testing.expect(!c2.descriptor.more);
    try testing.expectError(error.OutOfRange, split(payload, 0, 3));
}

test "Assembler: gather blocks then detect completion" {
    var store: [4096]u8 = undefined;
    var asm_ = Assembler.init(&store);

    const src = "z" ** 40; // szx 0 ⇒ blocks of 16, so 16+16+8
    var num: u32 = 0;
    while (true) : (num += 1) {
        const c = try split(src, 0, num);
        try asm_.accept(c.descriptor, c.data);
        if (!c.descriptor.more) break;
    }
    try testing.expect(asm_.isComplete());
    try testing.expectEqualStrings(src, asm_.payload());

    // A block past the buffer end is rejected (num=0 keeps it contiguous so
    // this isolates the BufferTooSmall check from the gap check below).
    var tiny = Assembler.init(store[0..8]);
    try testing.expectError(error.BufferTooSmall, tiny.accept(.{ .num = 0, .szx = 0 }, "0123456789abcdef"));
}

test "Assembler: a lone high-num final block is rejected, not reported complete" {
    // Attack: a single block with a high NUM and more=false, on a fresh
    // assembler. Without the gap check this would set done=true while
    // [0, offset) was never written (stale pooled-buffer disclosure).
    var store: [4096]u8 = undefined;
    var asm_ = Assembler.init(&store);
    const blk: Block = .{ .num = 10, .more = false, .szx = 0 }; // offset 160
    try testing.expectError(error.NonContiguousBlock, asm_.accept(blk, "tail"));
    try testing.expect(!asm_.isComplete());
    try testing.expectEqual(@as(usize, 0), asm_.payload().len);
}

test "Assembler: in-order 0..N assembly still works" {
    var store: [64]u8 = undefined;
    var asm_ = Assembler.init(&store);
    try asm_.accept(.{ .num = 0, .more = true, .szx = 0 }, "0123456789abcdef"); // [0,16)
    try asm_.accept(.{ .num = 1, .more = true, .szx = 0 }, "ghijklmnopqrstuv"); // [16,32)
    try asm_.accept(.{ .num = 2, .more = false, .szx = 0 }, "wxyz"); // [32,36)
    try testing.expect(asm_.isComplete());
    try testing.expectEqualStrings("0123456789abcdefghijklmnopqrstuvwxyz", asm_.payload());
}

test "Assembler: a gap between blocks is rejected" {
    var store: [4096]u8 = undefined;
    var asm_ = Assembler.init(&store);
    try asm_.accept(.{ .num = 0, .more = true, .szx = 0 }, "0123456789abcdef"); // covers [0,16)
    // Block 2 (offset 32) skips block 1's range [16,32): a gap.
    try testing.expectError(error.NonContiguousBlock, asm_.accept(.{ .num = 2, .more = false, .szx = 0 }, "tail"));
    try testing.expect(!asm_.isComplete());
    // The transfer can still be completed properly by filling the gap.
    try asm_.accept(.{ .num = 1, .more = true, .szx = 0 }, "ghijklmnopqrstuv");
    try asm_.accept(.{ .num = 2, .more = false, .szx = 0 }, "tail");
    try testing.expect(asm_.isComplete());
}

test "Assembler: rejects a mid-transfer SZX change instead of mis-assembling" {
    var store: [4096]u8 = undefined;
    var asm_ = Assembler.init(&store);
    try asm_.accept(.{ .num = 0, .more = true, .szx = 0 }, "0123456789abcdef"); // szx 0 ⇒ 16-byte blocks
    try testing.expectError(error.SzxChanged, asm_.accept(.{ .num = 1, .more = false, .szx = 1 }, "x"));
}

test "C6 end-to-end: Block2 GET transfers a 3000-byte body block by block" {
    const server = @import("server.zig");
    const num = coap.options.number;

    // The server-side resource: 3000 bytes → 1024 + 1024 + 952 at SZX 6.
    var body: [3000]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    const szx: u3 = 6;

    var store: [4096]u8 = undefined;
    var reasm = Assembler.init(&store);

    var n: u32 = 0;
    while (true) : (n += 1) {
        // ── client → server: GET /data with Block2(n, szx) ──
        var qbuf: [3]u8 = undefined;
        const req: coap.Message = .{
            .type = .confirmable,
            .code = .get,
            .message_id = @intCast(0x30 + n),
            .token = "\xA1\xA2",
            .options = &.{
                .{ .number = num.uri_path, .value = "data" },
                .{ .number = num.block2, .value = try (Block{ .num = n, .szx = szx }).encode(&qbuf) },
            },
        };
        var qwire: [64]u8 = undefined;
        const qlen = try coap.serialize(req, &qwire);

        // ── server: parse, read the requested Block2, carve, piggyback ──
        var sopts: [8]coap.Option = undefined;
        const sreq = try coap.parse(qwire[0..qlen], &sopts);
        var requested: Block = .{ .num = 0, .szx = szx };
        for (sreq.options) |o| {
            if (o.number == num.block2) requested = try Block.decode(o.value);
        }
        const chunk = try split(&body, requested.szx, requested.num);
        var rbuf: [3]u8 = undefined;
        const resp = server.piggyback(sreq, .content, &.{
            .{ .number = num.block2, .value = try chunk.descriptor.encode(&rbuf) },
        }, chunk.data);
        var rwire: [1152]u8 = undefined;
        const rlen = try coap.serialize(resp, &rwire);

        // ── client: parse response, decode Block2, assemble ──
        var copts: [8]coap.Option = undefined;
        const cresp = try coap.parse(rwire[0..rlen], &copts);
        var got: Block = undefined;
        for (cresp.options) |o| {
            if (o.number == num.block2) got = try Block.decode(o.value);
        }
        try reasm.accept(got, cresp.payload);
        if (!got.more) break;
    }
    try testing.expectEqual(@as(u32, 2), n); // three blocks: 0, 1, 2
    try testing.expect(reasm.isComplete());
    try testing.expectEqualSlices(u8, &body, reasm.payload());
}

test "C6 end-to-end: Block1 PUT — client splits, server assembles, 2.31 Continue" {
    const server = @import("server.zig");
    const num = coap.options.number;

    var body: [3000]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate(i *% 17 +% 3);
    const szx: u3 = 6;

    var store: [4096]u8 = undefined;
    var reasm = Assembler.init(&store);

    var n: u32 = 0;
    while (true) : (n += 1) {
        // ── client: split block n, PUT /data with Block1(n) + block payload ──
        const chunk = try split(&body, szx, n);
        var qbuf: [3]u8 = undefined;
        const qval = try chunk.descriptor.encode(&qbuf);
        const req: coap.Message = .{
            .type = .confirmable,
            .code = .put,
            .message_id = @intCast(0x50 + n),
            .token = "\xB1",
            .options = &.{
                .{ .number = num.uri_path, .value = "data" },
                .{ .number = num.block1, .value = qval },
            },
            .payload = chunk.data,
        };
        var qwire: [1152]u8 = undefined;
        const qlen = try coap.serialize(req, &qwire);

        // ── server: parse, assemble the block, answer ──
        var sopts: [8]coap.Option = undefined;
        const sreq = try coap.parse(qwire[0..qlen], &sopts);
        var got: Block = undefined;
        for (sreq.options) |o| {
            if (o.number == num.block1) got = try Block.decode(o.value);
        }
        try reasm.accept(got, sreq.payload);
        // 2.31 Continue on a non-final block; 2.04 Changed on the last.
        const code: coap.Code = if (got.more) .@"continue" else .changed;
        const resp = server.piggyback(sreq, code, &.{
            .{ .number = num.block1, .value = qval },
        }, "");
        var rwire: [64]u8 = undefined;
        const rlen = try coap.serialize(resp, &rwire);

        var copts: [8]coap.Option = undefined;
        const cresp = try coap.parse(rwire[0..rlen], &copts);
        if (got.more) {
            try testing.expectEqual(coap.Code.@"continue", cresp.code);
        } else {
            try testing.expectEqual(coap.Code.changed, cresp.code);
            break;
        }
    }
    try testing.expect(reasm.isComplete());
    try testing.expectEqualSlices(u8, &body, reasm.payload());
}
