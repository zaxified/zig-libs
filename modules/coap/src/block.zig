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
//! `Sender` is the sending half (carve the blocks of a payload, adopting a smaller
//! block size when the peer asks for one), and `Transfer` combines both for the
//! client side of one exchange whose request body is sent in Block1 blocks and
//! whose response body arrives in Block2 blocks (RFC 7959 §3.3).
//!
//! **SZX renegotiation (RFC 7959 §2.3).** A peer may answer with a block size
//! smaller than the one in use; the transfer continues at the smaller size with
//! NUM counted in the new size (`offset = NUM * size`). `Assembler` and `Sender`
//! take a *smaller* size at any block; a *larger* one mid-transfer is refused
//! (`error.SzxChanged` / `error.SzxIncrease`): only a decrease is negotiable.

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
    /// SZX in use: the first accepted block's, lowered by a later block that
    /// renegotiates a smaller size (RFC 7959 §2.3). A block with a *larger*
    /// SZX than the one in use is refused rather than silently mis-assembled.
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
        /// This block's SZX is larger than the one in use (only a decrease is a
        /// valid renegotiation).
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
    /// block whose SZX is larger than the one in use (`error.SzxChanged`). A smaller
    /// SZX is a renegotiation: the block is placed at `num * its own size` and
    /// the smaller size is used from then on.
    pub fn accept(self: *Assembler, blk: Block, data: []const u8) Error!void {
        if (self.szx) |s| {
            if (blk.szx > s) return error.SzxChanged;
        }
        const start = std.math.mul(usize, blk.num, blk.size()) catch return error.Overflow;
        if (start > self.len) return error.NonContiguousBlock;
        const end = std.math.add(usize, start, data.len) catch return error.Overflow;
        if (end > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[start..end], data);
        if (end > self.len) self.len = end;
        if (!blk.more) self.done = true;
        self.szx = blk.szx;
    }

    /// The Block2/Block1 NUM of the next block to ask for / expect, in the
    /// size now in use (`len / size`); 0 before the first block.
    pub fn nextNum(self: *const Assembler) u32 {
        const s = self.szx orelse return 0;
        return @intCast(self.len / sizeForSzx(s));
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

/// The sending half of a block-wise transfer: carves a payload into blocks, one
/// at a time, and follows the peer when it asks for a smaller block size
/// (RFC 7959 §2.3). `current` is the block to send now; `acknowledged` moves
/// past it once the peer confirmed it; `adopt` takes the size the peer's answer
/// names.
pub const Sender = struct {
    payload: []const u8,
    szx: u3,
    /// Bytes confirmed so far. Always a multiple of the block size in use: it
    /// only advances by whole blocks and the size only shrinks by powers of two.
    offset: usize = 0,

    pub const Error = error{
        /// The peer answered a larger block size than the one in use.
        SzxIncrease,
    };

    pub fn init(payload: []const u8, szx: u3) Sender {
        return .{ .payload = payload, .szx = szx };
    }

    /// The block to send now (an empty final block when the payload is empty).
    pub fn current(self: *const Sender) Chunk {
        const bs = sizeForSzx(self.szx);
        const end = @min(self.offset + bs, self.payload.len);
        return .{
            .data = self.payload[self.offset..end],
            .descriptor = .{ .num = @intCast(self.offset / bs), .more = end < self.payload.len, .szx = self.szx },
        };
    }

    /// The peer's answer to the block just sent named `peer` (its Block1
    /// option): continue at its size if that is smaller. A larger size is
    /// `error.SzxIncrease` and changes nothing.
    pub fn adopt(self: *Sender, peer: Block) Error!void {
        if (peer.szx > self.szx) return error.SzxIncrease;
        self.szx = peer.szx;
    }

    /// The block `sent` (what `current` returned, at the size it was sent in)
    /// is confirmed: move on to the next one. A no-op for the final block.
    pub fn acknowledged(self: *Sender, sent: Block) void {
        if (sent.more) self.offset += sent.size();
    }
};

/// One client exchange whose request body is sent in Block1 blocks and whose
/// response body arrives in Block2 blocks (RFC 7959 §3.3), over caller storage.
///
/// Drive it as `request` -> send -> receive -> `response`, until `response`
/// answers `.done`. The caller owns everything else: option assembly, the Token
/// and message ids, retransmission, and checking the response code (a 4.xx/5.xx
/// ends the exchange; this type only sees successful answers).
///
/// - While the request body is sent, every request carries the next Block1 block
///   (none at all when the body fits one block) and the server answers each with
///   2.31 Continue and the Block1 option, which `response` checks (NUM echoed)
///   and from which it adopts a smaller size if the server named one.
/// - The request that carries the last Block1 block also carries Block2 `0`
///   at the preferred size (when one was given): the answer to it is the first
///   block of the response (Block2 NUM 0), or the whole, unblocked, response.
/// - The remaining response blocks are fetched with requests carrying only a
///   Block2 option (NUM = next block in the size now in use) and no body, as RFC
///   7959 §3.3 allows; a server that answers a smaller size is followed.
pub const Transfer = struct {
    sender: Sender,
    assembler: Assembler,
    /// Preferred Block2 size for the response; null: no preference expressed.
    szx2: ?u3,
    phase: Phase = .sending,
    /// The Block1 descriptor of the request in flight, null when it carried none.
    in_flight: ?Block = null,

    pub const Phase = enum { sending, receiving, done };

    pub const Error = error{
        /// `response` after the exchange is done.
        UnexpectedPhase,
        /// The answer to a Block1 request lacks the Block1 option or echoes a
        /// different NUM.
        BadBlock1Ack,
        /// A Block2 option where none is acceptable (NUM other than 0 in the
        /// first answer, or none while the response is being fetched in blocks).
        UnexpectedBlock2,
        /// The peer named a larger Block1 size than the one in use.
        SzxIncrease,
    } || Assembler.Error;

    /// What the next request carries.
    pub const Request = struct {
        block1: ?Block,
        body: []const u8,
        block2: ?Block,
    };

    pub fn init(request_body: []const u8, szx1: u3, response_buf: []u8, szx2: ?u3) Transfer {
        return .{ .sender = Sender.init(request_body, szx1), .assembler = Assembler.init(response_buf), .szx2 = szx2 };
    }

    /// The options and body of the next request.
    pub fn request(self: *Transfer) Request {
        switch (self.phase) {
            .sending => {
                const chunk = self.sender.current();
                const single = chunk.descriptor.num == 0 and !chunk.descriptor.more;
                self.in_flight = if (single) null else chunk.descriptor;
                return .{
                    .block1 = self.in_flight,
                    .body = chunk.data,
                    .block2 = if (!chunk.descriptor.more) self.firstBlock2() else null,
                };
            },
            .receiving => {
                self.in_flight = null;
                const szx = self.assembler.szx orelse self.szx2 orelse 6;
                return .{ .block1 = null, .body = &.{}, .block2 = .{ .num = self.assembler.nextNum(), .szx = szx } };
            },
            .done => return .{ .block1 = null, .body = &.{}, .block2 = null },
        }
    }

    fn firstBlock2(self: *const Transfer) ?Block {
        const z = self.szx2 orelse return null;
        return .{ .num = 0, .szx = z };
    }

    /// Takes the answer to the request `request` returned: its Block1 and Block2
    /// options (null when absent) and payload. Returns the phase to continue in.
    pub fn response(self: *Transfer, block1: ?Block, block2: ?Block, payload: []const u8) Error!Phase {
        switch (self.phase) {
            .done => return error.UnexpectedPhase,
            .sending => {
                if (self.in_flight) |sent| {
                    const ack = block1 orelse return error.BadBlock1Ack;
                    if (ack.num != sent.num) return error.BadBlock1Ack;
                    self.sender.adopt(ack) catch return error.SzxIncrease;
                    if (sent.more) {
                        self.sender.acknowledged(sent);
                        return .sending;
                    }
                }
                // The request body is delivered: this is the first answer of the
                // response.
                if (block2) |b2| {
                    if (b2.num != 0) return error.UnexpectedBlock2;
                    try self.assembler.accept(b2, payload);
                    self.phase = if (b2.more) .receiving else .done;
                } else {
                    // Not blocked: the payload is the whole response.
                    try self.assembler.accept(.{ .num = 0, .more = false, .szx = 0 }, payload);
                    self.phase = .done;
                }
                return self.phase;
            },
            .receiving => {
                const b2 = block2 orelse return error.UnexpectedBlock2;
                try self.assembler.accept(b2, payload);
                if (!b2.more) self.phase = .done;
                return self.phase;
            },
        }
    }

    /// The response body assembled so far (complete once `.done`).
    pub fn responseBody(self: *const Transfer) []const u8 {
        return self.assembler.payload();
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

    const src = strRepeat("z", 40); // szx 0 ⇒ blocks of 16, so 16+16+8
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

test "TEETH: re-accepting an earlier block never SHRINKS the assembled coverage" {
    // `if (end > self.len) self.len = end;` — the guard is the monotonicity that
    // keeps a retransmitted or short duplicate block from truncating what is
    // already assembled. Reduced to a bare `self.len = end;` the whole suite
    // stayed green, because no test ever re-sent a block.
    var buf: [64]u8 = undefined;
    var asm_ = Assembler.init(&buf);
    try asm_.accept(.{ .num = 0, .more = true, .szx = 0 }, "0123456789ABCDEF");
    try asm_.accept(.{ .num = 1, .more = false, .szx = 0 }, "GHIJ");
    try testing.expectEqualStrings("0123456789ABCDEFGHIJ", asm_.payload());

    // A duplicate of block 0 — same offset, fewer bytes than are already
    // assembled beyond it. Coverage must not go backwards.
    try asm_.accept(.{ .num = 0, .more = true, .szx = 0 }, "0123456789ABCDEF");
    try testing.expectEqualStrings("0123456789ABCDEFGHIJ", asm_.payload());
    try testing.expectEqual(@as(usize, 20), asm_.payload().len);
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

test "Assembler: a smaller SZX mid-transfer is a renegotiation, a larger one is refused" {
    var store: [4096]u8 = undefined;
    var asm_ = Assembler.init(&store);
    const src = strRepeat("0123456789abcdefghijklmnopqrstuvwxyz", 3); // 108 bytes
    // Two blocks of 32 (szx 1), then the peer drops to 16 (szx 0): NUM counts in 16s.
    try asm_.accept(.{ .num = 0, .more = true, .szx = 1 }, src[0..32]);
    try testing.expectEqual(@as(u32, 1), asm_.nextNum());
    try asm_.accept(.{ .num = 1, .more = true, .szx = 1 }, src[32..64]);
    try testing.expectEqual(@as(u32, 2), asm_.nextNum());
    try asm_.accept(.{ .num = 4, .more = true, .szx = 0 }, src[64..80]); // offset 4 * 16
    try testing.expectEqual(@as(?u3, 0), asm_.szx);
    try testing.expectEqual(@as(u32, 5), asm_.nextNum());
    // Back to the larger size: refused, and nothing changes.
    try testing.expectError(error.SzxChanged, asm_.accept(.{ .num = 3, .more = true, .szx = 1 }, src[96..]));
    try testing.expectEqual(@as(usize, 80), asm_.payload().len);
    try testing.expectEqual(@as(?u3, 0), asm_.szx);
    // A block of the smaller size that leaves a gap is still a gap.
    try testing.expectError(error.NonContiguousBlock, asm_.accept(.{ .num = 6, .more = false, .szx = 0 }, src[96..]));
    try asm_.accept(.{ .num = 5, .more = true, .szx = 0 }, src[80..96]);
    try asm_.accept(.{ .num = 6, .more = false, .szx = 0 }, src[96..]);
    try testing.expect(asm_.isComplete());
    try testing.expectEqualStrings(src, asm_.payload());
    // A refused block does not even set the first size.
    var fresh = Assembler.init(&store);
    try testing.expectEqual(@as(u32, 0), fresh.nextNum());
}

test "Sender: blocks, acknowledgement, and following a smaller size" {
    const src = strRepeat("0123456789abcdefghijklmnopqrstuvwxyz", 3); // 108 bytes
    var tx = Sender.init(src, 1); // 32-byte blocks
    const b0 = tx.current();
    try testing.expectEqual(@as(u32, 0), b0.descriptor.num);
    try testing.expect(b0.descriptor.more);
    try testing.expectEqualStrings(src[0..32], b0.data);
    tx.acknowledged(b0.descriptor);
    const b1 = tx.current();
    try testing.expectEqual(@as(u32, 1), b1.descriptor.num);
    // The peer asks for 16 after block 1: the next block is NUM 4 of size 16.
    try tx.adopt(.{ .num = 1, .more = true, .szx = 0 });
    tx.acknowledged(b1.descriptor);
    const b2 = tx.current();
    try testing.expectEqual(@as(u32, 4), b2.descriptor.num);
    try testing.expectEqual(@as(u3, 0), b2.descriptor.szx);
    try testing.expectEqualStrings(src[64..80], b2.data);
    try testing.expectError(error.SzxIncrease, tx.adopt(.{ .num = 4, .more = true, .szx = 2 }));
    try testing.expectEqual(@as(u3, 0), tx.szx);
    tx.acknowledged(b2.descriptor);
    tx.acknowledged(tx.current().descriptor);
    const last = tx.current();
    try testing.expectEqual(@as(u32, 6), last.descriptor.num);
    try testing.expect(!last.descriptor.more);
    try testing.expectEqualStrings(src[96..], last.data);
    tx.acknowledged(last.descriptor); // a no-op
    try testing.expectEqual(@as(usize, 96), tx.offset);

    // An empty payload is one empty final block.
    const empty = Sender.init("", 2).current();
    try testing.expectEqual(@as(usize, 0), empty.data.len);
    try testing.expect(!empty.descriptor.more);
    try testing.expectEqual(@as(u32, 0), empty.descriptor.num);
}

/// A scripted server for the `Transfer` tests: assembles Block1 requests into
/// `got`, answers each with 2.31 and the Block1 option (lowering the size to
/// `lower_to` after the first block when set), and serves `response` in Block2
/// blocks (lowering to `lower2_to` from its second block on).
const MiniServer = struct {
    got: [512]u8 = undefined,
    asm_: Assembler = undefined,
    lower_to: ?u3 = null,
    lower2_to: ?u3 = null,
    response: []const u8,
    requests: usize = 0,

    const Answer = struct { block1: ?Block, block2: ?Block, payload: []const u8 };

    fn handle(self: *MiniServer, req: Transfer.Request) !Answer {
        if (self.requests == 0) self.asm_ = Assembler.init(&self.got);
        self.requests += 1;
        var ack: ?Block = null;
        if (req.block1) |b1| {
            try self.asm_.accept(b1, req.body);
            ack = b1;
            if (self.lower_to) |z| if (b1.more and b1.num == 0) {
                ack.?.szx = z;
            };
        } else if (req.body.len != 0) {
            try self.asm_.accept(.{ .num = 0, .more = false, .szx = 0 }, req.body);
        }
        const delivered = if (req.block1) |b1| !b1.more else true;
        if (!delivered) return .{ .block1 = ack, .block2 = null, .payload = "" };
        const want = req.block2 orelse return .{ .block1 = ack, .block2 = null, .payload = self.response };
        var szx = want.szx;
        if (self.lower2_to) |z| if (want.num > 0) {
            szx = @min(szx, z);
        };
        // NUM was counted in the size the client used; convert to bytes first.
        const start = want.offset();
        const bs = sizeForSzx(szx);
        const num: u32 = @intCast(start / bs);
        const chunk = try split(self.response, szx, num);
        return .{ .block1 = ack, .block2 = chunk.descriptor, .payload = chunk.data };
    }
};

test "Transfer: combined Block1+Block2 in one exchange (RFC 7959 §3.3)" {
    var body: [100]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate(i *% 5 +% 1);
    var resp_body: [200]u8 = undefined;
    for (&resp_body, 0..) |*b, i| b.* = @truncate(i *% 11 +% 9);
    var out: [256]u8 = undefined;

    var srv: MiniServer = .{ .response = &resp_body };
    var t = Transfer.init(&body, 1, &out, 2); // 32-byte request blocks, 64-byte response blocks
    var guard: usize = 0;
    while (t.phase != .done) : (guard += 1) {
        try testing.expect(guard < 20);
        const req = t.request();
        // Block2 rides only on the request with the last Block1 block, and on
        // the follow-up fetches (which carry no Block1 and no body).
        if (t.phase == .sending) try testing.expectEqual(req.block2 != null, !(req.block1.?.more));
        if (t.phase == .receiving) {
            try testing.expect(req.block1 == null);
            try testing.expectEqual(@as(usize, 0), req.body.len);
        }
        const a = try srv.handle(req);
        _ = try t.response(a.block1, a.block2, a.payload);
    }
    try testing.expectEqualSlices(u8, &body, srv.asm_.payload());
    try testing.expectEqualSlices(u8, &resp_body, t.responseBody());
    // 4 Block1 requests (32+32+32+4); the last carries Block2 0, then 200 = 64+64+64+8: 3 more.
    try testing.expectEqual(@as(usize, 7), srv.requests);
}

test "Transfer: both directions follow a renegotiated smaller size" {
    var body: [100]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate(i *% 7 +% 2);
    var resp_body: [200]u8 = undefined;
    for (&resp_body, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    var out: [256]u8 = undefined;

    // The server drops the request size to 16 after block 0 and the response
    // size to 32 from the second response block on.
    var srv: MiniServer = .{ .response = &resp_body, .lower_to = 0, .lower2_to = 1 };
    var t = Transfer.init(&body, 1, &out, 2);
    var guard: usize = 0;
    while (t.phase != .done) : (guard += 1) {
        try testing.expect(guard < 40);
        const a = try srv.handle(t.request());
        _ = try t.response(a.block1, a.block2, a.payload);
    }
    try testing.expectEqualSlices(u8, &body, srv.asm_.payload());
    try testing.expectEqualSlices(u8, &resp_body, t.responseBody());
    try testing.expectEqual(@as(u3, 0), t.sender.szx);
    try testing.expectEqual(@as(?u3, 1), t.assembler.szx);
}

test "Transfer: a body that fits one block sends no Block1; an unblocked response is the whole" {
    var out: [64]u8 = undefined;
    var t = Transfer.init("small", 2, &out, null);
    const req = t.request();
    try testing.expect(req.block1 == null);
    try testing.expect(req.block2 == null);
    try testing.expectEqualStrings("small", req.body);
    try testing.expectEqual(Transfer.Phase.done, try t.response(null, null, "all of it"));
    try testing.expectEqualStrings("all of it", t.responseBody());
    try testing.expectError(error.UnexpectedPhase, t.response(null, null, "x"));
}

test "Transfer: protocol violations are typed errors" {
    var out: [64]u8 = undefined;
    const body = strRepeat("x", 40);
    // The ack of a Block1 request must carry the Block1 option with the same NUM.
    var t = Transfer.init(body, 0, &out, null); // 16-byte blocks
    const r0 = t.request();
    try testing.expectError(error.BadBlock1Ack, t.response(null, null, ""));
    try testing.expectError(error.BadBlock1Ack, t.response(.{ .num = 1, .more = true, .szx = 0 }, null, ""));
    // A larger size than in use is refused.
    try testing.expectError(error.SzxIncrease, t.response(.{ .num = r0.block1.?.num, .more = true, .szx = 1 }, null, ""));
    // The first answer after the last Block1 block must start the response at 0.
    var t2 = Transfer.init("abc", 0, &out, 0);
    _ = t2.request();
    try testing.expectError(error.UnexpectedBlock2, t2.response(null, .{ .num = 2, .more = false, .szx = 0 }, "zz"));
    // While fetching in blocks, an answer without Block2 is refused.
    var t3 = Transfer.init("abc", 0, &out, 0);
    _ = t3.request();
    try testing.expectEqual(Transfer.Phase.receiving, try t3.response(null, .{ .num = 0, .more = true, .szx = 0 }, "0123456789abcdef"));
    const fetch = t3.request();
    try testing.expectEqual(@as(u32, 1), fetch.block2.?.num);
    try testing.expectError(error.UnexpectedBlock2, t3.response(null, null, "zz"));
    // The response buffer bounds the transfer.
    var tiny: [8]u8 = undefined;
    var t4 = Transfer.init("abc", 0, &tiny, 0);
    _ = t4.request();
    try testing.expectError(error.BufferTooSmall, t4.response(null, .{ .num = 0, .more = true, .szx = 0 }, "0123456789abcdef"));
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

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── whole-module mutation (2026-11-17): boundary tests ──────────────────────

test "Block.offset multiplies; split refuses start == len + 1; the assembler refuses a gap of one byte" {
    try testing.expectEqual(@as(usize, 192), (Block{ .num = 3, .szx = 2 }).offset());

    const p15: [15]u8 = @splat(1);
    try testing.expectError(error.OutOfRange, split(&p15, 0, 1)); // start 16 = len + 1
    const c0 = try split(&p15, 0, 0);
    try testing.expectEqual(@as(usize, 15), c0.data.len);
    try testing.expect(!c0.descriptor.more);

    var buf: [32]u8 = undefined;
    var a = Assembler.init(&buf);
    const short: [15]u8 = @splat(2);
    try a.accept(.{ .num = 0, .more = true, .szx = 0 }, &short);
    // Block 1 starts at 16, one byte beyond the 15 bytes written: a gap.
    try testing.expectError(error.NonContiguousBlock, a.accept(.{ .num = 1, .more = false, .szx = 0 }, &short));

    // A buffer of exactly two full blocks takes them both.
    var b = Assembler.init(&buf);
    const full: [16]u8 = @splat(3);
    try b.accept(.{ .num = 0, .more = true, .szx = 0 }, &full);
    try b.accept(.{ .num = 1, .more = false, .szx = 0 }, &full);
    try testing.expect(b.isComplete());
    try testing.expectEqual(@as(usize, 32), b.payload().len);
}
