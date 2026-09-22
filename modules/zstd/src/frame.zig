// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Frame and block driver (port of the one-shot path of libzstd
//! lib/compress/zstd_compress.c, v1.5.7): `ZSTD_compress2` with the whole input
//! in one call, which libzstd routes through `ZSTD_compressEnd_public` ->
//! `ZSTD_compress_frameChunk` -> `ZSTD_compressBlock_internal`.

const std = @import("std");
const params = @import("params.zig");
const match = @import("match.zig");
const sequences = @import("sequences.zig");
const literals = @import("literals.zig");
const presplit = @import("presplit.zig");

pub const Error = error{
    /// `dst` is smaller than `compressBound(src.len)`.
    NoSpaceLeft,
    /// The input is too large for one frame of 32-bit indices (libzstd would
    /// start rescaling its tables, which this port does not carry).
    InputTooLarge,
    OutOfMemory,
};

/// `ZSTD_compressBound`.
pub fn compressBound(src_size: usize) usize {
    const margin: usize = if (src_size < 128 << 10) ((128 << 10) - src_size) >> 11 else 0;
    return src_size + (src_size >> 8) + margin;
}

/// Largest input one frame can take here: libzstd corrects index overflow
/// once `ZSTD_CURRENT_MAX` (3500 MB on 64-bit) is crossed.
pub const max_input_size: usize = 3500 * (1 << 20) - match.window_start;

const block_size_max_abs = 128 * 1024;
const block_header_size = 3;
const min_cblock_size = 2;
const magic = 0xFD2FB528;
const rle_max_length = 25;

const bt_raw = 0;
const bt_rle = 1;
const bt_compressed = 2;

/// What one block leaves behind for the next (`ZSTD_compressedBlockState_t`).
const BlockState = struct {
    huf: literals.HufState = .{},
    fse: sequences.FseTables = .{},
    rep: [3]u32 = .{ 1, 4, 8 },
};

const Ctx = struct {
    ms: match.MatchState,
    ss: sequences.SeqStore,
    prev: *BlockState,
    next: *BlockState,
    strategy: u32,
    disable_literal_compression: bool,
    is_first_block: bool = true,
};

fn writeFrameHeader(dst: []u8, cp: params.CParams, src_size: u64, checksum: bool) usize {
    const window_size: u64 = @as(u64, 1) << @intCast(cp.window_log);
    const single_segment = window_size >= src_size;
    const window_log_byte: u8 = @intCast((cp.window_log - 10) << 3);
    const fcs_code: u8 = @as(u8, @intFromBool(src_size >= 256)) +
        @intFromBool(src_size >= 65536 + 256) +
        @intFromBool(src_size >= 0xFFFFFFFF);
    const fhd: u8 = (@as(u8, @intFromBool(checksum)) << 2) + (@as(u8, @intFromBool(single_segment)) << 5) + (fcs_code << 6);
    std.mem.writeInt(u32, dst[0..4], magic, .little);
    var pos: usize = 4;
    dst[pos] = fhd;
    pos += 1;
    if (!single_segment) {
        dst[pos] = window_log_byte;
        pos += 1;
    }
    switch (fcs_code) {
        0 => if (single_segment) {
            dst[pos] = @truncate(src_size);
            pos += 1;
        },
        1 => {
            std.mem.writeInt(u16, dst[pos..][0..2], @intCast(src_size - 256), .little);
            pos += 2;
        },
        2 => {
            std.mem.writeInt(u32, dst[pos..][0..4], @intCast(src_size), .little);
            pos += 4;
        },
        else => {
            std.mem.writeInt(u64, dst[pos..][0..8], src_size, .little);
            pos += 8;
        },
    }
    return pos;
}

fn writeBlockHeader(dst: []u8, v: u32) void {
    dst[0] = @truncate(v);
    dst[1] = @truncate(v >> 8);
    dst[2] = @truncate(v >> 16);
}

/// `ZSTD_bitmix`: XXH3's rrmxmx.
fn bitmix(val_in: u64, len: u64) u64 {
    var val = val_in;
    val ^= std.math.rotr(u64, val, 49) ^ std.math.rotr(u64, val, 24);
    val *%= 0x9FB21C651E98DF25;
    val ^= (val >> 35) +% len;
    val *%= 0x9FB21C651E98DF25;
    return val ^ (val >> 28);
}

/// `ZSTD_isRLE`.
fn isRle(src: []const u8) bool {
    for (src[1..]) |b| if (b != src[0]) return false;
    return true;
}

const EntropyError = error{ DstSizeTooSmall, Generic };

/// `ZSTD_entropyCompressSeqStore_internal`.
fn entropyCompressInternal(c: *Ctx, dst: []u8) EntropyError!usize {
    const ss = &c.ss;
    const n_seq = ss.n_seq;
    var op: usize = 0;

    // Compress literals
    {
        const suspect_uncompressible = n_seq == 0 or ss.n_lit / n_seq >= 20;
        op += try literals.compress(dst, ss.lits[0..ss.n_lit], &c.prev.huf, &c.next.huf, c.strategy, c.disable_literal_compression, suspect_uncompressible);
    }

    // Sequences header
    if (dst.len - op < 3 + 1) return error.DstSizeTooSmall;
    if (n_seq < 128) {
        dst[op] = @intCast(n_seq);
        op += 1;
    } else if (n_seq < sequences.long_nb_seq) {
        dst[op] = @intCast((n_seq >> 8) + 0x80);
        dst[op + 1] = @truncate(n_seq);
        op += 2;
    } else {
        dst[op] = 0xFF;
        std.mem.writeInt(u16, dst[op + 1 ..][0..2], @intCast(n_seq - sequences.long_nb_seq), .little);
        op += 3;
    }
    if (n_seq == 0) {
        // Copy the old tables over as if we repeated them
        c.next.fse = c.prev.fse;
        return op;
    }

    const seq_head = op;
    op += 1;
    const stats = try sequences.buildStatistics(ss, &c.prev.fse, &c.next.fse, dst[op..], c.strategy);
    dst[seq_head] = (@as(u8, @intFromEnum(stats.ll_type)) << 6) + (@as(u8, @intFromEnum(stats.of_type)) << 4) + (@as(u8, @intFromEnum(stats.ml_type)) << 2);
    op += stats.size;

    const bitstream_size = try sequences.encode(dst[op..], ss, &c.next.fse.ml, &c.next.fse.of, &c.next.fse.ll);
    op += bitstream_size;
    // zstd <= 1.3.4 misreads a table header that ends within 4 bytes of the
    // block; libzstd emits the block uncompressed instead.
    if (stats.last_count_size != 0 and stats.last_count_size + bitstream_size < 4) return 0;
    return op;
}

/// `ZSTD_entropyCompressSeqStore_wExtLitBuffer`: 0 means "store raw".
fn entropyCompress(c: *Ctx, dst: []u8, block_size: usize) usize {
    const c_size = entropyCompressInternal(c, dst) catch |err| switch (err) {
        // Out of space with room for a raw block: the block is not compressible.
        error.DstSizeTooSmall => return 0,
        // libzstd surfaces an internal error here; none is reachable from the
        // inputs this port accepts, so a raw block is the conservative answer.
        error.Generic => return 0,
    };
    if (c_size == 0) return 0;
    const max_c_size = block_size - literals.minGain(block_size, c.strategy);
    if (c_size >= max_c_size) return 0; // block not compressed
    return c_size;
}

/// `ZSTD_compressBlock_internal` (frame mode). Returns 0 for "store raw", 1 for
/// "RLE" (`dst[0]` holds the byte), otherwise the compressed block size.
fn compressBlock(c: *Ctx, dst: []u8, block_start: usize, block_size: usize) usize {
    const src = c.ms.src;
    var c_size: usize = 0;
    // don't even attempt compression below a certain srcSize
    if (block_size >= min_cblock_size + block_header_size + 1 + 1) {
        c.ss.reset();
        const istart: u32 = @intCast(block_start + match.window_start);
        // limited update after a very long match
        if (istart > c.ms.next_to_update + 384)
            c.ms.next_to_update = istart - @min(192, istart - c.ms.next_to_update - 384);
        c.next.rep = c.prev.rep;
        const last_ll = match.compressBlock(&c.ms, &c.ss, &c.next.rep, istart, @intCast(block_size));
        c.ss.storeLastLiterals(src[block_start + block_size - last_ll .. block_start + block_size]);
        c_size = entropyCompress(c, dst, block_size);

        if (!c.is_first_block and c_size < rle_max_length and isRle(src[block_start..][0..block_size])) {
            c_size = 1;
            dst[0] = src[block_start];
        }
        if (c_size > 1) std.mem.swap(*BlockState, &c.prev, &c.next);
    }
    return c_size;
}

pub const Options = struct {
    level: i32,
    checksum: bool,
};

/// One-shot frame. `dst.len` must be at least `compressBound(src.len)`.
pub fn compress(gpa: std.mem.Allocator, dst: []u8, src: []const u8, opts: Options) Error!usize {
    if (src.len > max_input_size) return error.InputTooLarge;
    const bound = compressBound(src.len);
    if (dst.len < bound) return error.NoSpaceLeft;
    const out = dst[0..bound];

    const cp = params.get(opts.level, src.len);
    var op = writeFrameHeader(out, cp, src.len, opts.checksum);

    if (src.len == 0) {
        // empty frame: one last, empty raw block
        writeBlockHeader(out[op..], 1 + (bt_raw << 1));
        op += block_header_size;
    } else {
        const row = params.useRowMatchFinder(cp);
        const hash_table = try gpa.alloc(u32, @as(usize, 1) << @intCast(cp.hash_log));
        defer gpa.free(hash_table);
        @memset(hash_table, 0);
        // ZSTD_allocateChainTable: not for fast, not with the row match finder
        const chain_len: usize = if (cp.strategy != .fast and !row) @as(usize, 1) << @intCast(cp.chain_log) else 0;
        const chain_table = try gpa.alloc(u32, chain_len);
        defer gpa.free(chain_table);
        @memset(chain_table, 0);
        const tag_table = try gpa.alloc(u8, if (row) @as(usize, 1) << @intCast(cp.hash_log) else 0);
        defer gpa.free(tag_table);
        @memset(tag_table, 0);

        const window_size: usize = @as(usize, 1) << @intCast(cp.window_log);
        const block_size_max: usize = @min(block_size_max_abs, @max(1, @min(window_size, src.len)));
        // every sequence carries a match of at least 4 bytes (min_match >= 4)
        const max_n_seq = block_size_max / 4 + 1;
        const seqs = try gpa.alloc(sequences.SeqDef, max_n_seq);
        defer gpa.free(seqs);
        const codes = try gpa.alloc(u8, 3 * max_n_seq);
        defer gpa.free(codes);
        const lits = try gpa.alloc(u8, block_size_max);
        defer gpa.free(lits);
        const states = try gpa.create([2]BlockState);
        defer gpa.destroy(states);
        states.* = .{ .{}, .{} };
        const split_ws = try gpa.create(presplit.Workspace);
        defer gpa.destroy(split_ws);

        var c: Ctx = .{
            .ms = .{
                .src = src,
                .cp = cp,
                .hash_table = hash_table,
                .chain_table = chain_table,
                .tag_table = tag_table,
                .row_hash_log = if (row) cp.hash_log - params.rowLog(cp) else 0,
                // ZSTD_advanceHashSalt on a fresh context: salt and entropy 0
                .hash_salt = if (row) bitmix(0, 8) ^ bitmix(0, 4) else 0,
            },
            .ss = .{
                .seqs = seqs,
                .lits = lits,
                .ll_code = codes[0..max_n_seq],
                .ml_code = codes[max_n_seq .. 2 * max_n_seq],
                .of_code = codes[2 * max_n_seq ..],
            },
            .prev = &states[0],
            .next = &states[1],
            .strategy = @intFromEnum(cp.strategy),
            // ZSTD_literalsCompressionIsDisabled (auto): fast + acceleration
            .disable_literal_compression = cp.strategy == .fast and cp.target_length > 0,
        };

        var savings: i64 = 0;
        var ip: usize = 0;
        while (ip < src.len) {
            const remaining = src.len - ip;
            const block_size = presplit.optimalBlockSize(src[ip..], block_size_max, c.strategy, savings, split_ws);
            const last_block: u32 = @intFromBool(block_size == remaining);
            std.debug.assert(out.len - op >= block_header_size + min_cblock_size + 1);

            c.ms.enforceMaxDist(@intCast(ip + match.window_start));
            // Ensure hash/chain table insertion resumes no sooner than lowlimit
            if (c.ms.next_to_update < c.ms.low_limit) c.ms.next_to_update = c.ms.low_limit;

            const block_out = out[op + block_header_size ..];
            var c_size = compressBlock(&c, block_out, ip, block_size);
            const bs: u32 = @intCast(block_size);
            if (c_size == 0) { // block is not compressible
                writeBlockHeader(out[op..], last_block + (bt_raw << 1) + (bs << 3));
                @memcpy(out[op + block_header_size ..][0..block_size], src[ip..][0..block_size]);
                c_size = block_header_size + block_size;
            } else if (c_size == 1) {
                writeBlockHeader(out[op..], last_block + (bt_rle << 1) + (bs << 3));
                c_size += block_header_size;
            } else {
                writeBlockHeader(out[op..], last_block + (bt_compressed << 1) + (@as(u32, @intCast(c_size)) << 3));
                c_size += block_header_size;
            }
            savings += @as(i64, @intCast(block_size)) - @as(i64, @intCast(c_size));
            ip += block_size;
            op += c_size;
            c.is_first_block = false;
        }
    }

    if (opts.checksum) {
        const h: u32 = @truncate(std.hash.XxHash64.hash(0, src));
        std.mem.writeInt(u32, out[op..][0..4], h, .little);
        op += 4;
    }
    return op;
}
