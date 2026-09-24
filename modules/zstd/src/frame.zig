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
const opt = @import("opt.zig");
const blocksplit = @import("blocksplit.zig");
const ldm = @import("ldm.zig");
const superblock = @import("superblock.zig");

pub const Error = error{
    /// `dst` is smaller than `compressBound(src.len)`.
    NoSpaceLeft,
    OutOfMemory,
} || params.Advanced.CheckError;

/// `ZSTD_compressBound`.
pub fn compressBound(src_size: usize) usize {
    const margin: usize = if (src_size < 128 << 10) ((128 << 10) - src_size) >> 11 else 0;
    return src_size + (src_size >> 8) + margin;
}

const block_size_max_abs = params.block_size_max_abs;
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
    /// `ZSTD_c_blockSplitterLevel`.
    pre_split_level: u32,
    is_first_block: bool = true,
    /// `ZSTD_blockSplitterEnabled`.
    split_blocks: bool,
    /// `ZSTD_c_targetCBlockSize` (0: off), already raised to its minimum.
    target_c_block_size: u32 = 0,
    partitions: [blocksplit.partitions_len]u32 = undefined,
    /// Long-distance matching: the table, and room for one block's sequences.
    ldm: ?*ldm.State = null,
    ldm_seqs: []ldm.RawSeq = &.{},

    /// The match state's index of `block`, which lies in its prefix.
    fn index(c: *const Ctx, block: []const u8) u32 {
        return @intCast(c.ms.src_base + (@intFromPtr(block.ptr) - @intFromPtr(c.ms.src.ptr)));
    }
};

/// `ZSTD_writeFrameHeader`; `content_size` null leaves the size out
/// (`contentSizeFlag` 0, or a stream of unknown length).
fn writeFrameHeader(dst: []u8, cp: params.CParams, content_size: ?u64, checksum: bool, format: params.Format) usize {
    const window_size: u64 = @as(u64, 1) << @intCast(cp.window_log);
    const src_size = content_size orelse 0;
    const single_segment = content_size != null and window_size >= src_size;
    const window_log_byte: u8 = @intCast((cp.window_log - 10) << 3);
    const fcs_code: u8 = if (content_size == null) 0 else @as(u8, @intFromBool(src_size >= 256)) +
        @intFromBool(src_size >= 65536 + 256) +
        @intFromBool(src_size >= 0xFFFFFFFF);
    const fhd: u8 = (@as(u8, @intFromBool(checksum)) << 2) + (@as(u8, @intFromBool(single_segment)) << 5) + (fcs_code << 6);
    var pos: usize = 0;
    if (format == .zstd1) {
        std.mem.writeInt(u32, dst[0..4], magic, .little);
        pos = 4;
    }
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
fn entropyCompressInternal(c: *Ctx, ss: *sequences.SeqStore, dst: []u8) EntropyError!usize {
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
fn entropyCompress(c: *Ctx, ss: *sequences.SeqStore, dst: []u8, block_size: usize) usize {
    const c_size = entropyCompressInternal(c, ss, dst) catch |err| switch (err) {
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

/// `ZSTD_buildSeqStore`: run the match finder over the block. Returns false
/// for a block too small to try (`ZSTDbss_noCompress`).
fn buildSeqStore(c: *Ctx, block: []const u8) bool {
    // don't even attempt compression below a certain srcSize
    if (block.len < min_cblock_size + block_header_size + 1 + 1) return false;
    c.ss.reset();
    const istart = c.index(block);
    // limited update after a very long match
    if (istart > c.ms.next_to_update + 384)
        c.ms.next_to_update = istart - @min(192, istart - c.ms.next_to_update - 384);
    c.next.rep = c.prev.rep;
    const last_ll = if (c.ldm) |ls| blk: {
        var ldm_seq_store: ldm.RawSeqStore = .{ .seq = c.ldm_seqs };
        ls.generateSequences(&ldm_seq_store, block);
        const n = ldm.blockCompress(&ldm_seq_store, &c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
        std.debug.assert(ldm_seq_store.pos == ldm_seq_store.size);
        break :blk n;
    } else match.compressBlock(&c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
    c.ss.storeLastLiterals(block[block.len - last_ll ..]);
    return true;
}

/// `ZSTD_compressBlock_internal` (frame mode). Returns 0 for "store raw", 1 for
/// "RLE" (`dst[0]` holds the byte), otherwise the compressed block size.
fn compressBlock(c: *Ctx, dst: []u8, block: []const u8) usize {
    var c_size: usize = 0;
    if (buildSeqStore(c, block)) {
        c_size = entropyCompress(c, &c.ss, dst, block.len);
        if (!c.is_first_block and c_size < rle_max_length and isRle(block)) {
            c_size = 1;
            dst[0] = block[0];
        }
        if (c_size > 1) std.mem.swap(*BlockState, &c.prev, &c.next);
    }
    return c_size;
}

/// Write one block (header included) for the outcome `c_size` of a block
/// compression: 0 raw, 1 RLE, otherwise compressed and already in place
/// after the header. Returns the bytes written.
fn emitBlock(out: []u8, src: []const u8, c_size: usize, last_block: u32) usize {
    const bs: u32 = @intCast(src.len);
    if (c_size == 0) { // block is not compressible
        writeBlockHeader(out, last_block + (bt_raw << 1) + (bs << 3));
        @memcpy(out[block_header_size..][0..src.len], src);
        return block_header_size + src.len;
    } else if (c_size == 1) {
        writeBlockHeader(out, last_block + (bt_rle << 1) + (bs << 3));
        out[block_header_size] = src[0];
        return block_header_size + 1;
    } else {
        writeBlockHeader(out, last_block + (bt_compressed << 1) + (@as(u32, @intCast(c_size)) << 3));
        return block_header_size + c_size;
    }
}

/// `ZSTD_compressSeqStore_singleBlock`: one block from the sequences in `ss`
/// covering `src`. Returns the bytes written, header included.
fn compressSingleBlock(c: *Ctx, ss: *sequences.SeqStore, d_rep: *[3]u32, c_rep: *[3]u32, out: []u8, src: []const u8, last_block: u32, is_partition: bool) usize {
    const d_rep_original = d_rep.*;
    if (is_partition) blocksplit.resolveOffCodes(d_rep, c_rep, ss);
    var c_seqs_size = entropyCompress(c, ss, out[block_header_size..], src.len);
    if (!c.is_first_block and c_seqs_size < rle_max_length and isRle(src)) c_seqs_size = 1;
    if (c_seqs_size > 1) {
        std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
    } else {
        d_rep.* = d_rep_original;
    }
    return emitBlock(out, src, c_seqs_size, last_block);
}

/// `ZSTD_compressBlock_targetCBlockSize`: one block of input, emitted as
/// sub-blocks of about `targetCBlockSize` compressed bytes each
/// (`superblock.zig`), else as one raw block. Returns the bytes written.
fn compressBlockTargetCBlockSize(c: *Ctx, out: []u8, src: []const u8, last_block: u32) usize {
    if (buildSeqStore(c, src)) {
        // We don't want to emit our first block as a RLE even if it
        // qualifies because doing so will cause the decoder (cli only) to
        // throw a "should consume all input error." This is only an issue
        // for zstd <= v1.4.3
        if (!c.is_first_block and c.ss.n_seq < 4 and c.ss.n_lit < 10 and isRle(src)) // ZSTD_maybeRLE
            return emitBlock(out, src, 1, last_block);
        const prev: superblock.State = .{ .huf = &c.prev.huf, .fse = &c.prev.fse, .rep = &c.prev.rep };
        const next: superblock.State = .{ .huf = &c.next.huf, .fse = &c.next.fse, .rep = &c.next.rep };
        // A superblock is not bound by compressBound: a size of a raw block
        // or more, or no room, falls back to a raw block.
        if (superblock.compress(&c.ss, prev, next, c.strategy, c.disable_literal_compression, c.target_c_block_size, out, src, last_block)) |c_size| {
            const max_c_size = src.len - literals.minGain(src.len, c.strategy);
            if (c_size != 0 and c_size < max_c_size + block_header_size) {
                std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
                return c_size;
            }
        } else |err| switch (err) {
            error.DstSizeTooSmall => {},
        }
    }
    // Superblock compression failed, attempt to emit a single no compress
    // block. The decoder will be able to stream this block since it is
    // uncompressed.
    return emitBlock(out, src, 0, last_block);
}

/// `ZSTD_compressBlock_splitBlock`: one block of input, emitted as one or
/// more blocks. Returns the bytes written, headers included.
fn compressBlockSplit(c: *Ctx, out: []u8, src: []const u8, last_block: u32) usize {
    const block_size = src.len;
    if (!buildSeqStore(c, src)) return emitBlock(out, src, 0, last_block);

    const prev: blocksplit.Entropy = .{ .huf = &c.prev.huf, .fse = &c.prev.fse };
    const next: blocksplit.Entropy = .{ .huf = &c.next.huf, .fse = &c.next.fse };
    const partitions = &c.partitions;
    const num_splits = blocksplit.deriveSplits(partitions, &c.ss, prev, next, .{ .strategy = c.strategy, .disable_literal_compression = c.disable_literal_compression });
    var d_rep = c.prev.rep;
    var c_rep = c.prev.rep;
    if (num_splits == 0) return compressSingleBlock(c, &c.ss, &d_rep, &c_rep, out, src, last_block, false);

    var op: usize = 0;
    var ip: usize = 0;
    var src_bytes_total: usize = 0;
    var curr = blocksplit.deriveChunk(&c.ss, 0, partitions[0]);
    var i: usize = 0;
    while (i <= num_splits) : (i += 1) {
        const last_partition = i == num_splits;
        var last_block_entire_src: u32 = 0;
        var src_bytes = blocksplit.countLiteralsBytes(&curr) + blocksplit.countMatchBytes(&curr);
        src_bytes_total += src_bytes;
        var next_chunk: sequences.SeqStore = undefined;
        if (last_partition) {
            // This is the final partition, need to account for possible last literals
            src_bytes += block_size - src_bytes_total;
            last_block_entire_src = last_block;
        } else {
            next_chunk = blocksplit.deriveChunk(&c.ss, partitions[i], partitions[i + 1]);
        }
        op += compressSingleBlock(c, &curr, &d_rep, &c_rep, out[op..], src[ip..][0..src_bytes], last_block_entire_src, true);
        ip += src_bytes;
        curr = next_chunk;
    }
    // cRep and dRep may have diverged during the compression. If so, we use
    // the dRep repcodes for the next block.
    c.prev.rep = d_rep;
    return op;
}

pub const Options = struct {
    level: i32,
    checksum: bool,
    advanced: params.Advanced = .{},
    /// Test seam: libzstd built with `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`
    /// (its fuzzing mode), which corrects index overflow whenever it safely
    /// can instead of only past `ZSTD_CURRENT_MAX` (3500 MiB). The output
    /// changes; it is how inputs of kilobytes reach the correction.
    overflow_correct_frequently: bool = false,
    /// Test seam: receives how many corrections the match state and the LDM
    /// window made. The output does not show them -- a correction only drops
    /// indices outside the window -- so this is how a test knows they ran.
    overflow_corrections: ?*[2]u32 = null,
};

/// One-shot frame on a fresh context. `dst.len` must be at least
/// `compressBound(src.len)`.
pub fn compress(gpa: std.mem.Allocator, dst: []u8, src: []const u8, opts: Options) Error!usize {
    var comp: Compressor = .initEmpty(gpa);
    defer comp.deinit();
    return comp.compressFrame(dst, src, opts);
}

/// The workspace alignment: the tables start on a cache line, as libzstd's
/// do (`ZSTD_CWKSP_ALIGNMENT_BYTES`).
pub const workspace_alignment = 64;
pub const Workspace = []align(workspace_alignment) u8;

/// Where each part of a compression context lives in its workspace, for
/// one frame's parameters (libzstd's `ZSTD_cwksp` reservations in
/// `ZSTD_resetCCtx_internal`, not its byte layout). The match tables come
/// first, so that a reused workspace keeps them in place; `total` is what
/// the context needs (`ZSTD_estimateCCtxSize_usingCCtxParams`, for this
/// port).
const Layout = struct {
    total: usize = 0,
    hash_len: usize,
    chain_len: usize,
    hash3_len: usize,
    hash_log3: u32,
    row: bool,
    block_size_max: usize,
    window_size: usize,
    max_n_seq: usize,
    ldm_params: ?ldm.Params,
    tag: usize = 0,
    states: usize = 0,
    split_ws: usize = 0,
    opt_state: usize = 0,
    ldm_state: usize = 0,
    ldm_table: usize = 0,
    ldm_buckets: usize = 0,
    ldm_seqs: usize = 0,
    ldm_n_seqs: usize = 0,
    seqs: usize = 0,
    codes: usize = 0,
    lits: usize = 0,
    in_buff: usize = 0,
    in_buff_len: usize = 0,
    out_buff: usize = 0,
    out_buff_len: usize = 0,

    fn tablesBytes(l: *const Layout) usize {
        return (l.hash_len + l.chain_len + l.hash3_len) * @sizeOf(u32);
    }

    fn compute(cp: params.CParams, pledged: ?u64, opts: Options, buffered: bool) Layout {
        const adv = opts.advanced;
        const ldm_params: ?ldm.Params = if (ldm.resolve(adv.long_distance_matching, cp)) ldm.adjustParameters(cp, adv) else null;
        const window_size: usize = @intCast(@max(1, @min(@as(u64, 1) << @intCast(cp.window_log), pledged orelse std.math.maxInt(u64))));
        // ZSTD_resolveMaxBlockSize
        const block_size_max: usize = @min(adv.max_block_size orelse block_size_max_abs, window_size);
        const row = params.resolveRowMatchFinder(adv.row_match_finder, cp);
        const hash_len = @as(usize, 1) << @intCast(cp.hash_log);
        // ZSTD_reset_matchState: the 3-byte hash of the optimal parser
        const hash_log3: u32 = if (cp.min_match == 3) @min(opt.hash_log3_max, cp.window_log) else 0;
        var l: Layout = .{
            .hash_len = hash_len,
            // ZSTD_allocateChainTable: not for fast, not with the row match finder
            .chain_len = if (cp.strategy != .fast and !row) @as(usize, 1) << @intCast(cp.chain_log) else 0,
            .hash3_len = if (hash_log3 != 0) @as(usize, 1) << @intCast(hash_log3) else 0,
            .hash_log3 = hash_log3,
            .row = row,
            .block_size_max = block_size_max,
            .window_size = window_size,
            // ZSTD_maxNbSeq: every sequence carries a match of at least
            // min_match bytes
            .max_n_seq = block_size_max / @as(usize, if (cp.min_match == 3) 3 else 4) + 1,
            .ldm_params = ldm_params,
        };
        var off = l.tablesBytes();
        l.tag = place(&off, u8, if (row) hash_len else 0, workspace_alignment);
        l.states = place(&off, BlockState, 2, @alignOf(BlockState));
        l.split_ws = place(&off, presplit.Workspace, 1, @alignOf(presplit.Workspace));
        if (@intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.btopt))
            l.opt_state = place(&off, opt.State, 1, @alignOf(opt.State));
        if (ldm_params) |lp| {
            l.ldm_state = place(&off, ldm.State, 1, @alignOf(ldm.State));
            l.ldm_table = place(&off, ldm.Entry, @as(usize, 1) << @intCast(lp.hash_log), @alignOf(ldm.Entry));
            l.ldm_buckets = place(&off, u8, @as(usize, 1) << @intCast(lp.hash_log - lp.bucket_size_log), 1);
            // ZSTD_ldm_getMaxNbSeq over one block
            l.ldm_n_seqs = ldm.maxNbSeq(lp, block_size_max);
            l.ldm_seqs = place(&off, ldm.RawSeq, l.ldm_n_seqs, @alignOf(ldm.RawSeq));
        }
        l.seqs = place(&off, sequences.SeqDef, l.max_n_seq, @alignOf(sequences.SeqDef));
        l.codes = place(&off, u8, 3 * l.max_n_seq, 1);
        l.lits = place(&off, u8, block_size_max, 1);
        if (buffered) {
            // one window plus one block in, one compressed block out
            l.in_buff_len = window_size + block_size_max;
            l.in_buff = place(&off, u8, l.in_buff_len, 1);
            l.out_buff_len = compressBound(block_size_max) + 1;
            l.out_buff = place(&off, u8, l.out_buff_len, 1);
        }
        l.total = std.mem.alignForward(usize, off, workspace_alignment);
        return l;
    }

    fn place(off: *usize, comptime T: type, n: usize, alignment: usize) usize {
        off.* = std.mem.alignForward(usize, off.*, alignment);
        const at = off.*;
        off.* += n * @sizeOf(T);
        return at;
    }
};

/// The workspace a context needs for a frame with these parameters: the
/// same number `Compressor.begin` then asks for.
pub fn workspaceSize(cp: params.CParams, pledged: ?u64, opts: Options, buffered: bool) usize {
    return Layout.compute(cp, pledged, opts, buffered).total;
}

/// `ZSTD_INDEXOVERFLOW_MARGIN`.
const index_overflow_margin: u32 = 16 << 20;
/// `ZSTD_WORKSPACETOOLARGE_FACTOR`, `ZSTD_WORKSPACETOOLARGE_MAXDURATION`.
const workspace_too_large_factor = 3;
const workspace_too_large_max_duration = 128;

/// libzstd's compression context (`ZSTD_CCtx`): one workspace holding the
/// match tables, block states and buffers, set up for each frame by
/// `begin` (`ZSTD_resetCCtx_internal`) and fed one chunk of input at a time
/// (`ZSTD_compressContinue`, `ZSTD_compressEnd`). A chunk that follows the
/// previous one in memory extends the window's prefix; one that does not
/// turns the prefix into the extDict (`match.MatchState.windowUpdate`).
///
/// Reused for another frame, the context keeps its workspace when it is
/// big enough and not wastefully big, and, as libzstd does, its indices go
/// on from where the last frame ended: the match tables are not cleared
/// (whatever they hold lies below the new window), only the table space
/// the last frame did not use is. The frame's output is the same as from a
/// fresh context.
pub const Compressor = struct {
    /// Null for a caller's fixed workspace (`ZSTD_initStaticCCtx`), which
    /// is never resized.
    gpa: ?std.mem.Allocator,
    ws: Workspace = &.{},
    /// Bytes of `ws` the current frame's layout uses.
    ws_used: usize = 0,
    /// `workspaceOversizedDuration`.
    oversized_duration: u32 = 0,
    /// `zc->initialized`: the window has been set up once.
    initialized: bool = false,
    /// Leading bytes of `ws` whose values are table indices below the
    /// window (`tableValidEnd`): a table laid over them needs no clearing.
    tables_valid: usize = 0,
    /// Where the last frame's tag table was, if it had one: a tag table in
    /// the same place keeps its contents (libzstd's init-once space).
    tag_prev: ?[2]usize = null,
    /// Test seam: the index past which a new frame restarts indexing
    /// rather than going on (`ZSTD_CURRENT_MAX - ZSTD_INDEXOVERFLOW_MARGIN`).
    index_too_close: u32 = match.current_max - index_overflow_margin,
    /// Frames that restarted indexing, and workspaces allocated. Not
    /// libzstd's; tests read them.
    n_index_resets: u32 = 0,
    n_workspace_allocs: u32 = 0,

    // Set by `begin` for each frame.
    cp: params.CParams = undefined,
    checksum: bool = false,
    /// `pledgedSrcSize`; null for unknown, which also leaves it out of the
    /// frame header.
    pledged: ?u64 = null,
    /// `ZSTD_c_contentSizeFlag`.
    content_size_flag: bool = true,
    format: params.Format = .zstd1,
    /// `blockSizeMax`: `min(maxBlockSize, window size)` (128 KB unless
    /// `Advanced.max_block_size` says less), the window shrunk to a known
    /// size.
    block_size_max: usize = 0,
    stage: enum { init, ongoing, ending } = .init,
    consumed: u64 = 0,
    produced: u64 = 0,
    xxh: std.hash.XxHash64 = .init(0),
    overflow_correct_frequently: bool = false,
    c: Ctx = .{
        .ms = .{ .src = &.{}, .cp = undefined, .hash_table = &.{}, .chain_table = &.{} },
        .ss = undefined,
        .prev = undefined,
        .next = undefined,
        .strategy = 0,
        .disable_literal_compression = false,
        .pre_split_level = 0,
        .split_blocks = false,
    },
    split_ws: *presplit.Workspace = undefined,
    /// A buffered stream's input and output buffers (`begin` with
    /// `buffered`), in the workspace.
    in_buff: []u8 = &.{},
    out_buff: []u8 = &.{},

    pub const SizeError = error{
        /// More input than pledged, or less at the end (`srcSize_wrong`).
        SrcSizeWrong,
    };

    /// A context that allocates its workspace from `gpa` at the first
    /// `begin`.
    pub fn initEmpty(gpa: std.mem.Allocator) Compressor {
        return .{ .gpa = gpa };
    }

    /// A context in the caller's `ws`, which must hold what `begin` needs
    /// (`workspaceSize`); it is never freed or resized.
    pub fn initStatic(ws: Workspace) Compressor {
        return .{ .gpa = null, .ws = ws };
    }

    pub fn deinit(comp: *Compressor) void {
        if (comp.gpa) |gpa| gpa.free(comp.ws);
        comp.* = undefined;
    }

    /// One whole frame of `src` (`ZSTD_compress2`), on this context.
    pub fn compressFrame(comp: *Compressor, dst: []u8, src: []const u8, opts: Options) Error!usize {
        const bound = compressBound(src.len);
        if (dst.len < bound) return error.NoSpaceLeft;
        // libzstd is given exactly the bound (zref); the room a block may use
        // can decide whether it is stored compressed
        const out = dst[0..bound];
        try opts.advanced.check();
        const cp = params.getOverridden(opts.level, src.len, opts.advanced);
        try comp.begin(cp, src.len, opts, false);
        const n = comp.compressContinue(out, src, true) catch unreachable; // pledged is src.len
        const m = comp.writeEpilogue(out[n..]);
        if (opts.overflow_corrections) |oc| oc.* = .{ comp.c.ms.n_overflow_corrections, if (comp.c.ldm) |ls| ls.n_overflow_corrections else 0 };
        return n + m;
    }

    /// `ZSTD_resetCCtx_internal`: set the context up for a frame with
    /// parameters `cp` (the level's, sized for `pledged`), resizing the
    /// workspace if it is too small or has long been three times too big.
    /// `buffered` adds a stream's input and output buffers.
    pub fn begin(comp: *Compressor, cp: params.CParams, pledged: ?u64, opts: Options, buffered: bool) error{OutOfMemory}!void {
        const l = Layout.compute(cp, pledged, opts, buffered);

        const ms_old = comp.c.ms;
        var index_reset = !comp.initialized or ms_old.src_base + ms_old.src.len > comp.index_too_close;

        // ZSTD_cwksp_bump_oversized_duration, ZSTD_cwksp_check_wasteful
        const available = comp.ws.len - comp.ws_used;
        const too_large = available >= l.total * workspace_too_large_factor;
        if (comp.gpa != null) comp.oversized_duration = if (too_large) comp.oversized_duration + 1 else 0;
        const wasteful = too_large and comp.oversized_duration > workspace_too_large_max_duration;
        var fresh_ws = false;
        if (comp.ws.len < l.total or wasteful) {
            const gpa = comp.gpa orelse return error.OutOfMemory; // static: no resize
            const ws = try gpa.alignedAlloc(u8, .fromByteUnits(workspace_alignment), l.total);
            gpa.free(comp.ws);
            comp.ws = ws;
            comp.oversized_duration = 0;
            comp.tables_valid = 0;
            comp.tag_prev = null;
            comp.n_workspace_allocs += 1;
            index_reset = true;
            fresh_ws = true;
        }
        comp.ws_used = l.total;
        const ws = comp.ws;

        // The tables: cleared where their values are not known to be
        // indices, all of it when indexing restarts.
        const tables_bytes = l.tablesBytes();
        const tables = slice(u32, ws, 0, l.hash_len + l.chain_len + l.hash3_len);
        if (index_reset) comp.tables_valid = 0;
        if (comp.tables_valid < tables_bytes) @memset(ws[comp.tables_valid..tables_bytes], 0);
        comp.tables_valid = tables_bytes;
        const tag_table = slice(u8, ws, l.tag, if (l.row) l.hash_len else 0);
        if (l.row) {
            const here: [2]usize = .{ l.tag, l.hash_len };
            if (comp.tag_prev == null or !std.meta.eql(comp.tag_prev.?, here)) @memset(tag_table, 0);
            comp.tag_prev = here;
        } else comp.tag_prev = null;

        const adv = opts.advanced;
        const states = &slice(BlockState, ws, l.states, 2)[0..2].*;
        states.* = .{ .{}, .{} };
        const opt_state: ?*opt.State = if (@intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.btopt)) &slice(opt.State, ws, l.opt_state, 1)[0] else null;
        if (opt_state) |p| p.* = .{ .compressed_literals = adv.literal_compression != .disable };

        // ZSTD_resetCCtx_internal: the LDM hash table, bucket offsets and
        // sequence buffer, and its own window from scratch
        const ldm_state: ?*ldm.State = if (l.ldm_params) |lp| blk: {
            const ls = &slice(ldm.State, ws, l.ldm_state, 1)[0];
            const table = slice(ldm.Entry, ws, l.ldm_table, @as(usize, 1) << @intCast(lp.hash_log));
            @memset(table, .{});
            const buckets = slice(u8, ws, l.ldm_buckets, @as(usize, 1) << @intCast(lp.hash_log - lp.bucket_size_log));
            @memset(buckets, 0);
            ls.* = .{
                .p = lp,
                .hash_table = table,
                .bucket_offsets = buckets,
                .overflow_correct_frequently = opts.overflow_correct_frequently,
            };
            break :blk ls;
        } else null;

        const n = l.max_n_seq;
        const codes = slice(u8, ws, l.codes, 3 * n);
        comp.in_buff = slice(u8, ws, l.in_buff, l.in_buff_len);
        comp.out_buff = slice(u8, ws, l.out_buff, l.out_buff_len);
        // libzstd's workspace comes from the allocator unwritten; a stream
        // can read a few bytes past the end of the old window segment (see
        // SPEC.md), which a fresh large allocation holds as zeros, and a
        // reused one as whatever the last frame left there.
        if (fresh_ws) @memset(comp.in_buff, 0);

        comp.cp = cp;
        comp.checksum = opts.checksum;
        comp.pledged = pledged;
        comp.content_size_flag = adv.content_size;
        comp.format = adv.format;
        comp.block_size_max = l.block_size_max;
        comp.stage = .init;
        comp.consumed = 0;
        comp.produced = 0;
        comp.xxh = .init(0);
        comp.overflow_correct_frequently = opts.overflow_correct_frequently;
        comp.split_ws = &slice(presplit.Workspace, ws, l.split_ws, 1)[0];
        comp.c = .{
            .ms = .{
                .src = &.{},
                .cp = cp,
                .hash_table = tables[0..l.hash_len],
                .chain_table = tables[l.hash_len..][0..l.chain_len],
                .tag_table = tag_table,
                .buffer = comp.in_buff,
                .use_row = l.row,
                .row_hash_log = if (l.row) cp.hash_log - params.rowLog(cp) else 0,
                .hash_salt = ms_old.hash_salt,
                .hash_salt_entropy = ms_old.hash_salt_entropy,
                .hash_table3 = tables[l.hash_len + l.chain_len ..],
                .hash_log3 = l.hash_log3,
                .opt = opt_state,
            },
            .ss = .{
                .seqs = slice(sequences.SeqDef, ws, l.seqs, n),
                .lits = slice(u8, ws, l.lits, l.block_size_max),
                .ll_code = codes[0..n],
                .ml_code = codes[n .. 2 * n],
                .of_code = codes[2 * n ..],
            },
            .prev = &states[0],
            .next = &states[1],
            .strategy = @intFromEnum(cp.strategy),
            .disable_literal_compression = params.literalCompressionDisabled(adv.literal_compression, cp),
            .pre_split_level = adv.block_splitter_level,
            .split_blocks = params.resolveSplitAfterSequences(adv.split_after_sequences, cp),
            .target_c_block_size = if (params.nonZero(adv.target_c_block_size)) |v| @max(v, superblock.target_c_block_size_min) else 0,
            .ldm = ldm_state,
            .ldm_seqs = slice(ldm.RawSeq, ws, l.ldm_seqs, l.ldm_n_seqs),
        };
        if (ldm_state) |ls| ls.buffer = comp.in_buff;
        const ms = &comp.c.ms;
        // ZSTD_advanceHashSalt, for every frame that uses the row match
        // finder; a fresh context starts from salt and entropy 0
        if (l.row) ms.hash_salt = bitmix(ms.hash_salt, 8) ^ bitmix(ms.hash_salt_entropy, 4);
        if (index_reset) {
            // ZSTD_window_init
            comp.n_index_resets += 1;
        } else {
            // ZSTD_window_clear: indexing goes on past the last frame, whose
            // bytes are below the window from now on
            const end: u32 = @intCast(ms_old.src_base + ms_old.src.len);
            ms.src = ms_old.src[ms_old.src.len..];
            ms.src_base = end;
            ms.dict_base = end;
            ms.low_limit = end;
            ms.dict_limit = end;
            ms.next_to_update = end;
            ms.n_overflow_corrections = ms_old.n_overflow_corrections;
        }
        comp.initialized = true;
    }

    fn slice(comptime T: type, ws: Workspace, at: usize, n: usize) []T {
        const p: [*]T = @ptrCast(@alignCast(ws.ptr + at));
        return p[0..n];
    }

    /// `ZSTD_compressContinue_internal` in frame mode: the frame header on
    /// the first call, then `chunk` as one or more blocks, the last of them
    /// marked last when `last_chunk`. `dst.len` is the room libzstd would
    /// have (a block that does not fit is stored raw), at least
    /// `compressBound(chunk.len)` plus the header. Returns the bytes written.
    pub fn compressContinue(comp: *Compressor, dst: []u8, chunk: []const u8, last_chunk: bool) SizeError!usize {
        var fh_size: usize = 0;
        if (comp.stage == .init) {
            fh_size = writeFrameHeader(dst, comp.cp, comp.headerContentSize(comp.pledged), comp.checksum, comp.format);
            comp.stage = .ongoing;
        }
        if (chunk.len == 0) return fh_size; // do not generate an empty block if no input

        const ms = &comp.c.ms;
        if (!ms.windowUpdate(chunk)) ms.next_to_update = ms.dict_limit;
        if (comp.c.ldm) |ls| ls.windowUpdate(chunk);

        const c_size = comp.frameChunk(dst[fh_size..], chunk, last_chunk);
        comp.consumed += chunk.len;
        comp.produced += c_size + fh_size;
        if (comp.pledged) |p| if (comp.consumed > p) return error.SrcSizeWrong;
        return c_size + fh_size;
    }

    /// `ZSTD_compress_frameChunk`.
    fn frameChunk(comp: *Compressor, out: []u8, chunk: []const u8, last_chunk: bool) usize {
        const c = &comp.c;
        var savings: i64 = @as(i64, @intCast(comp.consumed)) - @as(i64, @intCast(comp.produced));
        if (comp.checksum) comp.xxh.update(chunk);
        var op: usize = 0;
        var ip: usize = 0;
        while (ip < chunk.len) {
            const remaining = chunk.len - ip;
            const block_size = presplit.optimalBlockSize(chunk[ip..], comp.block_size_max, c.pre_split_level, c.strategy, savings, comp.split_ws);
            const last_block: u32 = @intFromBool(last_chunk and block_size == remaining);
            std.debug.assert(out.len - op >= block_header_size + min_cblock_size + 1);
            const block = chunk[ip..][0..block_size];

            const bi = c.index(block);
            _ = c.ms.overflowCorrectIfNeeded(comp.overflow_correct_frequently, bi, @as(usize, bi) + block_size);
            c.ms.enforceMaxDist(c.index(block));
            // Ensure hash/chain table insertion resumes no sooner than lowlimit
            if (c.ms.next_to_update < c.ms.low_limit) c.ms.next_to_update = c.ms.low_limit;

            const c_size = if (c.target_c_block_size != 0)
                compressBlockTargetCBlockSize(c, out[op..], block, last_block)
            else if (c.split_blocks)
                compressBlockSplit(c, out[op..], block, last_block)
            else
                emitBlock(out[op..], block, compressBlock(c, out[op + block_header_size ..], block), last_block);
            savings += @as(i64, @intCast(block_size)) - @as(i64, @intCast(c_size));
            ip += block_size;
            op += c_size;
            c.is_first_block = false;
        }
        if (last_chunk and op > 0) comp.stage = .ending;
        return op;
    }

    /// The content size the frame header records: none without
    /// `contentSizeFlag`, which libzstd also clears for an unknown size.
    fn headerContentSize(comp: *const Compressor, size: ?u64) ?u64 {
        return if (comp.content_size_flag and comp.pledged != null) size else null;
    }

    /// `ZSTD_writeEpilogue`: a last empty block unless the last chunk ended
    /// the frame, then the checksum. `dst` has room for 7 bytes.
    pub fn writeEpilogue(comp: *Compressor, dst: []u8) usize {
        var op: usize = 0;
        if (comp.stage == .init) {
            // special case: empty frame
            op += writeFrameHeader(dst, comp.cp, comp.headerContentSize(0), comp.checksum, comp.format);
            comp.stage = .ongoing;
        }
        if (comp.stage != .ending) {
            // write one last empty block, make it the "last" block
            writeBlockHeader(dst[op..], 1 + (bt_raw << 1));
            op += block_header_size;
        }
        if (comp.checksum) {
            const h: u32 = @truncate(comp.xxh.final());
            std.mem.writeInt(u32, dst[op..][0..4], h, .little);
            op += 4;
        }
        return op;
    }
};
