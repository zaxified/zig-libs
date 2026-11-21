// SPDX-License-Identifier: MIT

//! Salvage of the intact blocks of a damaged .bz2 file, the way libbzip2 1.0.8's
//! `bzip2recover` does it (BSD-style licence, see ../NOTICE; altered: rewritten in
//! Zig over byte slices and a `std.Io.Writer` instead of files, and without
//! the file naming). Every block of a bzip2 stream starts with the 48-bit magic
//! 0x314159265359 and the stream ends with 0x177245385090, at any bit offset;
//! blocks are independent, so a block that is intact decodes on its own once it is
//! wrapped in a stream header and a trailer. Nothing is decoded or checked here: a
//! damaged block is recovered like any other and fails when it is decoded
//! (`bzip2 -t`, `decompress`) — that is how the tool finds out which ones survived.

const std = @import("std");
const Writer = std.Io.Writer;

const block_magic: u64 = 0x314159265359;
const end_magic: u64 = 0x177245385090;
const magic_mask: u64 = (1 << 48) - 1;

/// Fewer bits than this between two magics is not a block (a block is at least a
/// CRC, a header, tables and a symbol; bzip2recover's `>= 130`).
const min_block_bits: u64 = 130;

/// The bit range of one candidate block: the bits after its 48-bit header magic
/// (the block CRC first) up to and including the bit before the next magic, as bzip2recover
/// reports it ("block N runs from `first_bit` to `last_bit`"). Bit 0 is the most significant bit of byte 0.
pub const Block = struct {
    first_bit: u64,
    last_bit: u64,
};

pub const Options = struct {
    /// Refuse an input with more candidate blocks than this (`error.TooManyBlocks`):
    /// bzip2recover's `BZ_MAX_HANDLED_BLOCKS`. 50,000 blocks of level 9 are 40 GB of text.
    max_blocks: usize = 50_000,
};

pub const Error = error{
    /// More than `Options.max_blocks` candidate blocks.
    TooManyBlocks,
    OutOfMemory,
};

/// Every candidate block of `input`, in order. Caller owns the result. Empty when no
/// block boundary is found at all (bzip2recover: "couldn't find any block boundaries").
pub fn findBlocks(gpa: std.mem.Allocator, input: []const u8, opts: Options) Error![]Block {
    var out: std.ArrayList(Block) = .empty;
    errdefer out.deinit(gpa);

    var window: u64 = 0;
    var bits: u64 = 0; // bits read so far
    var start: u64 = 0; // first bit of the region being scanned
    var seen_magic = false;
    for (input) |byte| {
        var i: u4 = 8;
        while (i > 0) {
            i -= 1;
            window = ((window << 1) | ((byte >> @as(u3, @intCast(i))) & 1)) & magic_mask;
            bits += 1;
            if (window != block_magic and window != end_magic) continue;
            // The region before this magic ends 49 bits back (its first bit is `bits - 48`).
            const end: u64 = if (bits > 49) bits - 49 else 0;
            if (seen_magic and end >= start and end - start >= min_block_bits) {
                if (out.items.len >= opts.max_blocks) return error.TooManyBlocks;
                try out.append(gpa, .{ .first_bit = start, .last_bit = end });
            }
            seen_magic = true;
            start = bits;
        }
    }
    return out.toOwnedSlice(gpa);
}

/// Write `block` of `input` as a stream of its own: "BZh9", the block header magic, the block's
/// bits, the end-of-stream magic and a stream CRC (the block's own CRC: the combined CRC
/// of one block), zero-padded to a byte. Level 9 allows any block size. The result decodes
/// if, and only if, the block was intact.
pub fn writeBlockStream(input: []const u8, block: Block, w: *Writer) Writer.Error!void {
    var bw: BitWriter = .{ .w = w };
    try bw.put(0x425A6839, 32); // "BZh9"
    try bw.put(block_magic >> 16, 32);
    try bw.put(block_magic & 0xFFFF, 16);
    // The block CRC is its first 32 bits.
    var crc: u64 = 0;
    var pos = block.first_bit;
    while (pos <= block.last_bit) {
        const n: u6 = @intCast(@min(32, block.last_bit - pos + 1));
        const v = readBits(input, pos, n);
        if (pos == block.first_bit) crc = readBits(input, pos, 32);
        try bw.put(v, n);
        pos += n;
    }
    try bw.put(end_magic >> 16, 32);
    try bw.put(end_magic & 0xFFFF, 16);
    try bw.put(crc, 32);
    try bw.flush();
}

/// `n <= 32` bits of `input` from bit `pos`; bits past the end read as 0.
fn readBits(input: []const u8, pos: u64, n: u6) u64 {
    var acc: u64 = 0;
    var byte: usize = @intCast(pos / 8);
    const skip: u6 = @intCast(pos % 8);
    var have: u7 = 0;
    while (have < @as(u7, n) + skip) : (have += 8) {
        acc = (acc << 8) | (if (byte < input.len) input[byte] else 0);
        byte += 1;
    }
    const total: u7 = have;
    return (acc >> @as(u6, @intCast(total - skip - n))) & ((@as(u64, 1) << n) - 1);
}

const BitWriter = struct {
    w: *Writer,
    acc: u64 = 0,
    n: u7 = 0,

    fn put(self: *BitWriter, v: u64, bits: u6) Writer.Error!void {
        self.acc = (self.acc << bits) | (v & ((@as(u64, 1) << bits) - 1));
        self.n += bits;
        while (self.n >= 8) {
            self.n -= 8;
            try self.w.writeByte(@intCast((self.acc >> @as(u6, @intCast(self.n))) & 0xFF));
        }
        self.acc &= (@as(u64, 1) << @as(u6, @intCast(self.n))) - 1;
    }

    fn flush(self: *BitWriter) Writer.Error!void {
        if (self.n > 0) try self.put(0, @intCast(8 - self.n));
    }
};
