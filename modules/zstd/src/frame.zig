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

pub const Error = error{
    /// `dst` is smaller than `compressBound(src.len)`.
    NoSpaceLeft,
    OutOfMemory,
};

/// `ZSTD_compressBound`.
pub fn compressBound(src_size: usize) usize {
    const margin: usize = if (src_size < 128 << 10) ((128 << 10) - src_size) >> 11 else 0;
    return src_size + (src_size >> 8) + margin;
}

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
    /// `ZSTD_blockSplitterEnabled`.
    split_blocks: bool,
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
/// (`contentSizeFlag` 0, a stream of unknown length).
fn writeFrameHeader(dst: []u8, cp: params.CParams, content_size: ?u64, checksum: bool) usize {
    const window_size: u64 = @as(u64, 1) << @intCast(cp.window_log);
    const src_size = content_size orelse 0;
    const single_segment = content_size != null and window_size >= src_size;
    const window_log_byte: u8 = @intCast((cp.window_log - 10) << 3);
    const fcs_code: u8 = if (content_size == null) 0 else @as(u8, @intFromBool(src_size >= 256)) +
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
    var last_ll: usize = undefined;
    if (c.ldm) |ls| {
        // ZSTD_ldm_blockCompress, strategy >= btopt: the long-distance
        // matches are candidates for the optimal parser, not sequences
        var ldm_seq_store: ldm.RawSeqStore = .{ .seq = c.ldm_seqs };
        ls.generateSequences(&ldm_seq_store, block);
        c.ms.ldm_seq_store = &ldm_seq_store;
        defer c.ms.ldm_seq_store = null;
        last_ll = match.compressBlock(&c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
    } else {
        last_ll = match.compressBlock(&c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
    }
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

/// `ZSTD_compressBlock_splitBlock`: one block of input, emitted as one or
/// more blocks. Returns the bytes written, headers included.
fn compressBlockSplit(c: *Ctx, out: []u8, src: []const u8, last_block: u32) usize {
    const block_size = src.len;
    if (!buildSeqStore(c, src)) return emitBlock(out, src, 0, last_block);

    const prev: blocksplit.Entropy = .{ .huf = &c.prev.huf, .fse = &c.prev.fse };
    const next: blocksplit.Entropy = .{ .huf = &c.next.huf, .fse = &c.next.fse };
    const partitions = &c.partitions;
    const num_splits = blocksplit.deriveSplits(partitions, &c.ss, prev, next, c.strategy);
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
    /// Test seam: override the level's strategy the way
    /// `ZSTD_c_strategy` does, to reach strategy/size pairs no level maps
    /// to. Not part of the public API.
    strategy: ?params.Strategy = null,
    /// Test seam: long-distance matching switched on by hand, as
    /// `ZSTD_c_enableLongDistanceMatching` = 1 does (window log reset to 27
    /// before the input shrinks it), to reach LDM on inputs far below the
    /// 64 MB where level 22 switches it on. Only for btopt and up.
    ldm: bool = false,
    /// Test seam: `ZSTD_c_windowLog`, a window smaller than the level's.
    window_log: ?u32 = null,
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

/// One-shot frame. `dst.len` must be at least `compressBound(src.len)`.
pub fn compress(gpa: std.mem.Allocator, dst: []u8, src: []const u8, opts: Options) Error!usize {
    const bound = compressBound(src.len);
    if (dst.len < bound) return error.NoSpaceLeft;
    // libzstd is given exactly the bound (zref); the room a block may use
    // can decide whether it is stored compressed
    const out = dst[0..bound];
    const cp = params.getOverridden(opts.level, src.len, opts.strategy, opts.ldm, opts.window_log);
    var comp = try Compressor.init(gpa, cp, src.len, opts);
    defer comp.deinit();
    const n = comp.compressContinue(out, src, true) catch unreachable; // pledged is src.len
    const m = comp.writeEpilogue(out[n..]);
    if (opts.overflow_corrections) |oc| oc.* = .{ comp.c.ms.n_overflow_corrections, if (comp.c.ldm) |ls| ls.n_overflow_corrections else 0 };
    return n + m;
}

/// libzstd's compression context between `ZSTD_compressBegin` and the end
/// of the frame: parameters, match state, block states and buffers
/// (`ZSTD_resetCCtx_internal`), fed one chunk of input at a time
/// (`ZSTD_compressContinue`, `ZSTD_compressEnd`). A chunk that follows the
/// previous one in memory extends the window's prefix; one that does not
/// turns the prefix into the extDict (`match.MatchState.windowUpdate`).
pub const Compressor = struct {
    gpa: std.mem.Allocator,
    cp: params.CParams,
    checksum: bool,
    /// `pledgedSrcSize`; null for unknown, which also leaves it out of the
    /// frame header.
    pledged: ?u64,
    /// `blockSizeMax`: `min(128 KB, window size)`, the window shrunk to a
    /// known size.
    block_size_max: usize,
    stage: enum { init, ongoing, ending } = .init,
    consumed: u64 = 0,
    produced: u64 = 0,
    xxh: std.hash.XxHash64 = .init(0),
    overflow_correct_frequently: bool,
    c: Ctx,
    states: *[2]BlockState,
    split_ws: *presplit.Workspace,
    tables: []u32,
    tag_table: []u8,
    codes: []u8,
    lits: []u8,
    seqs: []sequences.SeqDef,
    opt_state: ?*opt.State,
    ldm_table: []ldm.Entry,
    ldm_buckets: []u8,
    ldm_state: ?*ldm.State,

    pub const SizeError = error{
        /// More input than pledged, or less at the end (`srcSize_wrong`).
        SrcSizeWrong,
    };

    pub fn init(gpa: std.mem.Allocator, cp: params.CParams, pledged: ?u64, opts: Options) error{OutOfMemory}!Compressor {
        const ldm_params: ?ldm.Params = if (opts.ldm or ldm.enabledByDefault(cp)) ldm.adjustParameters(cp) else null;
        // LDM by hand below btopt splices LDM sequences between runs of the
        // block compressor (`ZSTD_ldm_blockCompress`), which is not ported.
        std.debug.assert(ldm_params == null or @intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.btopt));

        const window_size: u64 = @max(1, @min(@as(u64, 1) << @intCast(cp.window_log), pledged orelse std.math.maxInt(u64)));
        const block_size_max: usize = @intCast(@min(block_size_max_abs, window_size));
        const row = params.useRowMatchFinder(cp);
        const hash_len = @as(usize, 1) << @intCast(cp.hash_log);
        // ZSTD_allocateChainTable: not for fast, not with the row match finder
        const chain_len: usize = if (cp.strategy != .fast and !row) @as(usize, 1) << @intCast(cp.chain_log) else 0;
        // ZSTD_reset_matchState: the 3-byte hash of the optimal parser
        const hash_log3: u32 = if (cp.min_match == 3) @min(opt.hash_log3_max, cp.window_log) else 0;
        const hash3_len: usize = if (hash_log3 != 0) @as(usize, 1) << @intCast(hash_log3) else 0;
        const tables = try gpa.alloc(u32, hash_len + chain_len + hash3_len);
        errdefer gpa.free(tables);
        @memset(tables, 0);
        const tag_table = try gpa.alloc(u8, if (row) hash_len else 0);
        errdefer gpa.free(tag_table);
        @memset(tag_table, 0);
        const opt_state: ?*opt.State = if (@intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.btopt)) try gpa.create(opt.State) else null;
        errdefer if (opt_state) |p| gpa.destroy(p);
        if (opt_state) |p| p.* = .{};

        // ZSTD_maxNbSeq: every sequence carries a match of at least
        // min_match bytes
        const max_n_seq = block_size_max / @as(usize, if (cp.min_match == 3) 3 else 4) + 1;
        const seqs = try gpa.alloc(sequences.SeqDef, max_n_seq);
        errdefer gpa.free(seqs);
        const codes = try gpa.alloc(u8, 3 * max_n_seq);
        errdefer gpa.free(codes);
        const lits = try gpa.alloc(u8, block_size_max);
        errdefer gpa.free(lits);
        const states = try gpa.create([2]BlockState);
        errdefer gpa.destroy(states);
        states.* = .{ .{}, .{} };
        const split_ws = try gpa.create(presplit.Workspace);
        errdefer gpa.destroy(split_ws);

        // ZSTD_resetCCtx_internal: the LDM hash table, bucket offsets and
        // sequence buffer (`ZSTD_ldm_getMaxNbSeq` over one block)
        const lp: ldm.Params = ldm_params orelse std.mem.zeroes(ldm.Params);
        const ldm_on = ldm_params != null;
        const ldm_table = try gpa.alloc(ldm.Entry, if (ldm_on) @as(usize, 1) << @intCast(lp.hash_log) else 0);
        errdefer gpa.free(ldm_table);
        @memset(ldm_table, .{});
        const ldm_buckets = try gpa.alloc(u8, if (ldm_on) @as(usize, 1) << @intCast(lp.hash_log - lp.bucket_size_log) else 0);
        errdefer gpa.free(ldm_buckets);
        @memset(ldm_buckets, 0);
        const ldm_seqs = try gpa.alloc(ldm.RawSeq, if (ldm_on) ldm.maxNbSeq(lp, block_size_max) else 0);
        errdefer gpa.free(ldm_seqs);
        const ldm_state: ?*ldm.State = if (ldm_on) try gpa.create(ldm.State) else null;
        errdefer if (ldm_state) |p| gpa.destroy(p);
        if (ldm_state) |p| p.* = .{
            .p = lp,
            .hash_table = ldm_table,
            .bucket_offsets = ldm_buckets,
            .overflow_correct_frequently = opts.overflow_correct_frequently,
        };

        return .{
            .gpa = gpa,
            .cp = cp,
            .checksum = opts.checksum,
            .pledged = pledged,
            .block_size_max = block_size_max,
            .overflow_correct_frequently = opts.overflow_correct_frequently,
            .states = states,
            .split_ws = split_ws,
            .tables = tables,
            .tag_table = tag_table,
            .codes = codes,
            .lits = lits,
            .seqs = seqs,
            .opt_state = opt_state,
            .ldm_table = ldm_table,
            .ldm_buckets = ldm_buckets,
            .ldm_state = ldm_state,
            .c = .{
                .ms = .{
                    .src = &.{},
                    .cp = cp,
                    .hash_table = tables[0..hash_len],
                    .chain_table = tables[hash_len..][0..chain_len],
                    .tag_table = tag_table,
                    .row_hash_log = if (row) cp.hash_log - params.rowLog(cp) else 0,
                    // ZSTD_advanceHashSalt on a fresh context: salt and entropy 0
                    .hash_salt = if (row) bitmix(0, 8) ^ bitmix(0, 4) else 0,
                    .hash_table3 = tables[hash_len + chain_len ..],
                    .hash_log3 = hash_log3,
                    .opt = opt_state,
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
                // ZSTD_resolveBlockSplitterMode (auto)
                .split_blocks = @intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.btopt) and cp.window_log >= 17,
                .ldm = ldm_state,
                .ldm_seqs = ldm_seqs,
            },
        };
    }

    pub fn deinit(comp: *Compressor) void {
        const gpa = comp.gpa;
        if (comp.ldm_state) |p| gpa.destroy(p);
        gpa.free(comp.c.ldm_seqs);
        gpa.free(comp.ldm_buckets);
        gpa.free(comp.ldm_table);
        gpa.destroy(comp.split_ws);
        gpa.destroy(comp.states);
        gpa.free(comp.lits);
        gpa.free(comp.codes);
        gpa.free(comp.seqs);
        if (comp.opt_state) |p| gpa.destroy(p);
        gpa.free(comp.tag_table);
        gpa.free(comp.tables);
        comp.* = undefined;
    }

    /// `ZSTD_compressContinue_internal` in frame mode: the frame header on
    /// the first call, then `chunk` as one or more blocks, the last of them
    /// marked last when `last_chunk`. `dst.len` is the room libzstd would
    /// have (a block that does not fit is stored raw), at least
    /// `compressBound(chunk.len)` plus the header. Returns the bytes written.
    pub fn compressContinue(comp: *Compressor, dst: []u8, chunk: []const u8, last_chunk: bool) SizeError!usize {
        var fh_size: usize = 0;
        if (comp.stage == .init) {
            fh_size = writeFrameHeader(dst, comp.cp, comp.pledged, comp.checksum);
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
            const block_size = presplit.optimalBlockSize(chunk[ip..], comp.block_size_max, c.strategy, savings, comp.split_ws);
            const last_block: u32 = @intFromBool(last_chunk and block_size == remaining);
            std.debug.assert(out.len - op >= block_header_size + min_cblock_size + 1);
            const block = chunk[ip..][0..block_size];

            const bi = c.index(block);
            _ = c.ms.overflowCorrectIfNeeded(comp.overflow_correct_frequently, bi, @as(usize, bi) + block_size);
            c.ms.enforceMaxDist(c.index(block));
            // Ensure hash/chain table insertion resumes no sooner than lowlimit
            if (c.ms.next_to_update < c.ms.low_limit) c.ms.next_to_update = c.ms.low_limit;

            const c_size = if (c.split_blocks)
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

    /// `ZSTD_writeEpilogue`: a last empty block unless the last chunk ended
    /// the frame, then the checksum. `dst` has room for 7 bytes.
    pub fn writeEpilogue(comp: *Compressor, dst: []u8) usize {
        var op: usize = 0;
        if (comp.stage == .init) {
            // special case: empty frame
            op += writeFrameHeader(dst, comp.cp, 0, comp.checksum);
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
