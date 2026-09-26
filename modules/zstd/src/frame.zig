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
const cdict_mod = @import("cdict.zig");
const CDict = cdict_mod.CDict;
const seqapi = @import("seqapi.zig");
pub const SequenceProducer = seqapi.SequenceProducer;

pub const Error = error{
    /// `dst` is smaller than `compressBound(src.len)`.
    NoSpaceLeft,
} || BeginError || BlockError;

/// What compressing a block can fail with: only with an external sequence
/// producer (`Options.sequence_producer`) or while collecting sequences
/// (`Compressor.generateSequences`), see seqapi.zig.
pub const BlockError = seqapi.Error;

/// What setting a context up for a frame can fail with.
pub const BeginError = error{
    OutOfMemory,
    /// libzstd would attach the `CDict` (a small or unknown input size, or
    /// `Advanced.force_attach_dict = .attach`), searching its tables in
    /// place with the match finders' `dictMatchState` variants, which are
    /// not ported yet for its strategy. Copying instead would change the
    /// output, so the frame is refused. Temporary.
    DictAttachUnsupported,
    /// Level above `params.max_level` (for a context's own `CDict`).
    LevelUnsupported,
    /// `parameter_combination_unsupported`: a sequence producer with
    /// workers (`Advanced.nb_workers`), which libzstd refuses.
    ParameterCombinationUnsupported,
} || params.Advanced.CheckError || cdict_mod.Error;

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

/// What one block leaves behind for the next (`ZSTD_compressedBlockState_t`);
/// a full dictionary sets the first block's.
pub const BlockState = struct {
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
    /// `externSeqStore`: long-distance matches made elsewhere for the whole
    /// frame, consumed block by block (`ZSTD_referenceExternalSequences`;
    /// multithreaded compression generates them serially across jobs).
    extern_seqs: ldm.RawSeqStore = .{},
    /// External sequences (seqapi.zig): the settings, the producer's
    /// buffer (`extSeqBuf`) and `ZSTD_generateSequences`' collector.
    seq: seqapi.Params = .{},
    ext_seqs: []seqapi.Sequence = &.{},
    collector: ?*seqapi.Collector = null,

    /// The match state's index of `block`, which lies in its prefix.
    fn index(c: *const Ctx, block: []const u8) u32 {
        return @intCast(c.ms.src_base + (@intFromPtr(block.ptr) - @intFromPtr(c.ms.src.ptr)));
    }
};

/// `ZSTD_writeFrameHeader`; `content_size` null leaves the size out
/// (`contentSizeFlag` 0, or a stream of unknown length); `dict_id` 0 or
/// `no_dict_id` leaves the dictionary ID out.
fn writeFrameHeader(dst: []u8, cp: params.CParams, content_size: ?u64, checksum: bool, format: params.Format, dict_id: u32, no_dict_id: bool) usize {
    const window_size: u64 = @as(u64, 1) << @intCast(cp.window_log);
    const src_size = content_size orelse 0;
    const dict_id_size_code_length: u8 = @as(u8, @intFromBool(dict_id > 0)) + @intFromBool(dict_id >= 256) + @intFromBool(dict_id >= 65536); // 0-3
    const dict_id_size_code: u8 = if (no_dict_id) 0 else dict_id_size_code_length;
    const single_segment = content_size != null and window_size >= src_size;
    const window_log_byte: u8 = @intCast((cp.window_log - 10) << 3);
    const fcs_code: u8 = if (content_size == null) 0 else @as(u8, @intFromBool(src_size >= 256)) +
        @intFromBool(src_size >= 65536 + 256) +
        @intFromBool(src_size >= 0xFFFFFFFF);
    const fhd: u8 = dict_id_size_code + (@as(u8, @intFromBool(checksum)) << 2) + (@as(u8, @intFromBool(single_segment)) << 5) + (fcs_code << 6);
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
    switch (dict_id_size_code) {
        0 => {},
        1 => {
            dst[pos] = @truncate(dict_id);
            pos += 1;
        },
        2 => {
            std.mem.writeInt(u16, dst[pos..][0..2], @truncate(dict_id), .little);
            pos += 2;
        },
        else => {
            std.mem.writeInt(u32, dst[pos..][0..4], dict_id, .little);
            pos += 4;
        },
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

/// The offset table a dictionary gave was valid for the first block's
/// offsets only; from the next block on it must be checked (libzstd does
/// this after every block).
fn offcodeValidToCheck(c: *Ctx) void {
    if (c.prev.fse.of_repeat == .valid) c.prev.fse.of_repeat = .check;
}

/// `ZSTD_isRLE`.
fn isRle(src: []const u8) bool {
    for (src[1..]) |b| if (b != src[0]) return false;
    return true;
}

const EntropyError = error{ DstSizeTooSmall, Generic };

/// `ZSTD_entropyCompressSeqStore_internal`.
fn entropyCompressInternal(c: *Ctx, ss: *sequences.SeqStore, dst: []u8) EntropyError!usize {
    return entropyCompressLits(c, ss, ss.lits[0..ss.n_lit], dst);
}

/// `ZSTD_entropyCompressSeqStore_internal` with the literals given apart
/// from the store (`ZSTD_compressSequencesAndLiterals`).
fn entropyCompressLits(c: *Ctx, ss: *sequences.SeqStore, lits: []const u8, dst: []u8) EntropyError!usize {
    const n_seq = ss.n_seq;
    var op: usize = 0;

    // Compress literals
    {
        const suspect_uncompressible = n_seq == 0 or lits.len / n_seq >= 20;
        op += try literals.compress(dst, lits, &c.prev.huf, &c.next.huf, c.strategy, c.disable_literal_compression, suspect_uncompressible);
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

/// `ZSTD_buildSeqStore`: run the match finder (or the external sequence
/// producer) over the block. Returns false for a block too small to try
/// (`ZSTDbss_noCompress`).
fn buildSeqStore(c: *Ctx, block: []const u8) BlockError!bool {
    // don't even attempt compression below a certain srcSize
    if (block.len < min_cblock_size + block_header_size + 1 + 1) {
        if (c.strategy >= @intFromEnum(params.Strategy.btopt))
            c.extern_seqs.skipBytes(block.len)
        else
            c.extern_seqs.skipSequences(block.len, c.ms.cp.min_match);
        return false;
    }
    c.ss.reset();
    // required for optimal parser to read stats from dictionary
    if (c.ms.opt) |st| st.symbol_costs = .{ .huf = &c.prev.huf, .fse = &c.prev.fse };
    const istart = c.index(block);
    // limited update after a very long match
    if (istart > c.ms.next_to_update + 384)
        c.ms.next_to_update = istart - @min(192, istart - c.ms.next_to_update - 384);
    c.next.rep = c.prev.rep;
    const last_ll = if (c.extern_seqs.pos < c.extern_seqs.size) blk: {
        // External matchfinder + LDM is technically possible, just not
        // implemented yet (libzstd).
        if (c.seq.producer != null) return error.ParameterCombinationUnsupported;
        break :blk ldm.blockCompress(&c.extern_seqs, &c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
    } else if (c.ldm) |ls| blk: {
        if (c.seq.producer != null) return error.ParameterCombinationUnsupported;
        var ldm_seq_store: ldm.RawSeqStore = .{ .seq = c.ldm_seqs };
        ls.generateSequences(&ldm_seq_store, block);
        const n = ldm.blockCompress(&ldm_seq_store, &c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
        std.debug.assert(ldm_seq_store.pos == ldm_seq_store.size);
        break :blk n;
    } else if (c.seq.producer != null) blk: {
        if (try seqapi.produceBlock(&c.ss, .{ .prev = &c.prev.rep, .next = &c.next.rep }, &c.seq, c.ext_seqs, block)) return true;
        // Fallback to software matchfinder
        break :blk match.compressBlock(&c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
    } else match.compressBlock(&c.ms, &c.ss, &c.next.rep, istart, @intCast(block.len));
    c.ss.storeLastLiterals(block[block.len - last_ll ..]);
    return true;
}

/// `ZSTD_compressBlock_internal` (frame mode). Returns 0 for "store raw", 1 for
/// "RLE" (`dst[0]` holds the byte), otherwise the compressed block size.
fn compressBlock(c: *Ctx, dst: []u8, block: []const u8) BlockError!usize {
    return compressBlockMode(c, dst, block, true);
}

/// `ZSTD_compressBlock_internal`; outside a frame (`frame` 0,
/// `ZSTD_compressBlock_deprecated`) a block is never turned into RLE.
fn compressBlockMode(c: *Ctx, dst: []u8, block: []const u8, frame_mode: bool) BlockError!usize {
    var c_size: usize = 0;
    if (try buildSeqStore(c, block)) {
        if (c.collector) |col| {
            try col.copyBlockSequences(&c.ss, c.prev.rep);
            std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
            return 0;
        }
        c_size = entropyCompress(c, &c.ss, dst, block.len);
        if (frame_mode and !c.is_first_block and c_size < rle_max_length and isRle(block)) {
            c_size = 1;
            dst[0] = block[0];
        }
        if (c_size > 1) std.mem.swap(*BlockState, &c.prev, &c.next);
    } else if (c.collector != null) return error.SequenceProducerFailed; // Uncompressible block
    offcodeValidToCheck(c);
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
fn compressSingleBlock(c: *Ctx, ss: *sequences.SeqStore, d_rep: *[3]u32, c_rep: *[3]u32, out: []u8, src: []const u8, last_block: u32, is_partition: bool) BlockError!usize {
    const d_rep_original = d_rep.*;
    if (is_partition) blocksplit.resolveOffCodes(d_rep, c_rep, ss);
    var c_seqs_size = entropyCompress(c, ss, out[block_header_size..], src.len);
    if (!c.is_first_block and c_seqs_size < rle_max_length and isRle(src)) c_seqs_size = 1;
    // Sequence collection not supported when block splitting
    if (c.collector) |col| {
        try col.copyBlockSequences(ss, d_rep_original);
        std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
        return 0;
    }
    if (c_seqs_size > 1) {
        std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
    } else {
        d_rep.* = d_rep_original;
    }
    offcodeValidToCheck(c);
    return emitBlock(out, src, c_seqs_size, last_block);
}

/// `ZSTD_compressBlock_targetCBlockSize`: one block of input, emitted as
/// sub-blocks of about `targetCBlockSize` compressed bytes each
/// (`superblock.zig`), else as one raw block. Returns the bytes written.
fn compressBlockTargetCBlockSize(c: *Ctx, out: []u8, src: []const u8, last_block: u32) BlockError!usize {
    defer offcodeValidToCheck(c);
    if (try buildSeqStore(c, src)) {
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
fn compressBlockSplit(c: *Ctx, out: []u8, src: []const u8, last_block: u32) BlockError!usize {
    const block_size = src.len;
    if (!try buildSeqStore(c, src)) {
        offcodeValidToCheck(c);
        if (c.collector != null) return error.SequenceProducerFailed; // Uncompressible block
        return emitBlock(out, src, 0, last_block);
    }

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
        op += try compressSingleBlock(c, &curr, &d_rep, &c_rep, out[op..], src[ip..][0..src_bytes], last_block_entire_src, true);
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
    /// The dictionary, as libzstd has it set on the context before
    /// `ZSTD_compress2` / `ZSTD_compressStream2`.
    dict: Dict = .none,
    /// `ZSTD_registerSequenceProducer`: a block-level sequence producer
    /// run in place of the level's match finder (seqapi.zig).
    sequence_producer: ?seqapi.SequenceProducer = null,
    /// `ZSTD_generateSequences`' collector (`zc->seqCollector`): each
    /// block's sequences are copied there and the block is stored raw.
    collector: ?*seqapi.Collector = null,
};

/// A dictionary for a frame: libzstd's `ZSTD_CCtx_loadDictionary_advanced`,
/// `ZSTD_CCtx_refCDict` and `ZSTD_CCtx_refPrefix_advanced`.
pub const Dict = union(enum) {
    none,
    /// Copied (`ZSTD_dlm_byCopy`) and digested into a `CDict` of the
    /// context's own, with the frame's parameters (`ZSTD_initLocalDict`),
    /// then used as `cdict` is -- except that its level stays the frame's.
    /// Where the bytes lie does not matter: an input right after them in
    /// memory is not their continuation.
    raw: RawDict,
    /// A dictionary digested beforehand; its level, if it has one, replaces
    /// the frame's.
    cdict: *const CDict,
    /// Loaded into the context for this frame only, raw by default
    /// (`ZSTD_CCtx_refPrefix`): the input is compressed as its continuation.
    prefix: RawDict,
};

pub const RawDict = struct {
    bytes: []const u8,
    content_type: cdict_mod.ContentType = .auto,
};

/// `ZSTD_USE_CDICT_PARAMS_SRCSIZE_CUTOFF`, `ZSTD_USE_CDICT_PARAMS_DICTSIZE_MULTIPLIER`:
/// up to 128 KB of input, or six times the dictionary, a `CDict` is used
/// with its own tables (attached or copied); above, a CDict with a level is
/// loaded anew with the input's parameters.
const use_cdict_params_src_size_cutoff = 128 << 10;
const use_cdict_params_dict_size_multiplier = 6;

/// `attachDictSizeCutoffs`: per strategy, the input size up to which a
/// `CDict` is attached rather than copied.
const attach_dict_size_cutoffs = [10]u64{
    8 << 10, // unused
    8 << 10, // ZSTD_fast
    16 << 10, // ZSTD_dfast
    32 << 10, // ZSTD_greedy
    32 << 10, // ZSTD_lazy
    32 << 10, // ZSTD_lazy2
    32 << 10, // ZSTD_btlazy2
    32 << 10, // ZSTD_btopt
    8 << 10, // ZSTD_btultra
    8 << 10, // ZSTD_btultra2
};

/// `ZSTD_shouldAttachDict`: whether a frame of `pledged` bytes
/// (`unknown_size` when not known) searches `cdict` in place rather than a
/// copy of its tables. A dedicated-search CDict is always attached (its
/// table layout is for searching in place only), even with `.copy` or
/// `force_max_window`.
pub fn shouldAttachDict(cdict: *const CDict, adv: params.Advanced, pledged: u64) bool {
    const cutoff = attach_dict_size_cutoffs[@intFromEnum(cdict.ms.cp.strategy)];
    if (cdict.dedicated_dict_search) return true;
    return (pledged <= cutoff or pledged == params.unknown_size or adv.force_attach_dict == .attach) and
        adv.force_attach_dict != .copy and
        !adv.force_max_window; // dictMatchState isn't correctly handled in _enforceMaxDist
}

/// The frame parameters of `ZSTD_compress_usingCDict_advanced`.
pub const FrameParams = struct {
    content_size: bool = true,
    checksum: bool = false,
    dict_id: bool = true,
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
    ext_seqs: usize = 0,
    ext_n_seqs: usize = 0,
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
            // min_match bytes (3 from an external producer)
            .max_n_seq = block_size_max / seqDivider(cp, opts) + 1,
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
        // reserve space for block-level external sequences
        if (opts.sequence_producer != null) {
            l.ext_n_seqs = seqapi.sequenceBound(block_size_max);
            l.ext_seqs = place(&off, seqapi.Sequence, l.ext_n_seqs, @alignOf(seqapi.Sequence));
        }
        l.seqs = place(&off, sequences.SeqDef, l.max_n_seq, @alignOf(sequences.SeqDef));
        l.codes = place(&off, u8, 3 * l.max_n_seq, 1);
        l.lits = place(&off, u8, block_size_max, 1);
        // one window plus one block in, one compressed block out -- unless
        // the caller's buffers stand in (`stable_in_buffer`, `stable_out_buffer`)
        if (buffered and !opts.advanced.stable_in_buffer) {
            l.in_buff_len = window_size + block_size_max;
            l.in_buff = place(&off, u8, l.in_buff_len, 1);
        }
        if (buffered and !opts.advanced.stable_out_buffer) {
            l.out_buff_len = compressBound(block_size_max) + 1;
            l.out_buff = place(&off, u8, l.out_buff_len, 1);
        }
        l.total = std.mem.alignForward(usize, off, workspace_alignment);
        return l;
    }

    /// `ZSTD_maxNbSeq`'s divider.
    fn seqDivider(cp: params.CParams, opts: Options) usize {
        return if (cp.min_match == 3 or opts.sequence_producer != null) 3 else 4;
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
/// `ZSTD_CHUNKSIZE_MAX`.
const chunk_size_max: usize = std.math.maxInt(u32) - match.current_max;
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
    /// Frames that copied a `CDict`'s tables, and that loaded a dictionary
    /// into the context. Not libzstd's; tests read them.
    n_cdict_copies: u32 = 0,
    n_dict_loads: u32 = 0,

    // Set by `begin` for each frame.
    cp: params.CParams = undefined,
    checksum: bool = false,
    /// `pledgedSrcSize`; null for unknown, which also leaves it out of the
    /// frame header.
    pledged: ?u64 = null,
    /// `ZSTD_c_contentSizeFlag`.
    content_size_flag: bool = true,
    format: params.Format = .zstd1,
    /// `dictID` for the frame header, and `fParams.noDictIDFlag`.
    dict_id: u32 = 0,
    no_dict_id: bool = false,
    /// `dictContentSize`.
    dict_content_size: usize = 0,
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

    /// One whole frame of `src` (`ZSTD_compress2`, with `opts.dict` set on
    /// the context), on this context.
    pub fn compressFrame(comp: *Compressor, dst: []u8, src: []const u8, opts: Options) Error!usize {
        const bound = compressBound(src.len);
        if (dst.len < bound) return error.NoSpaceLeft;
        // libzstd is given exactly the bound (zref); the room a block may use
        // can decide whether it is stored compressed
        const out = dst[0..bound];
        try opts.advanced.check();
        var local: ?CDict = null;
        defer if (local) |*l| l.deinit();
        try comp.initStream2(opts, src.len, null, false, &local);
        return comp.finishFrame(out, src, opts);
    }

    fn finishFrame(comp: *Compressor, out: []u8, src: []const u8, opts: Options) BlockError!usize {
        const n = comp.compressContinue(out, src, true) catch |err| switch (err) {
            error.SrcSizeWrong => unreachable, // pledged is src.len
            else => |e| return e,
        };
        const m = comp.writeEpilogue(out[n..]);
        if (opts.overflow_corrections) |oc| oc.* = .{ comp.c.ms.n_overflow_corrections, if (comp.c.ldm) |ls| ls.n_overflow_corrections else 0 };
        return n + m;
    }

    /// `ZSTD_compress_usingDict`: one frame of `src` with `dict` (raw
    /// content, or a full dictionary by its magic number) loaded into the
    /// context, at `level` with every other parameter at its default, sized
    /// for the input and the dictionary together.
    pub fn compressUsingDict(comp: *Compressor, dst: []u8, src: []const u8, dict: []const u8, level: i32) Error!usize {
        const bound = compressBound(src.len);
        if (dst.len < bound) return error.NoSpaceLeft;
        const cp = params.getInternal(level, src.len, dict.len, .no_attach_dict);
        const opts: Options = .{ .level = if (level == 0) params.default_level else level, .checksum = false };
        try comp.beginInternal(.{ .bytes = dict }, null, cp, src.len, opts, false);
        return comp.finishFrame(dst[0..bound], src, opts);
    }

    /// `ZSTD_compress_usingCDict_advanced`: one frame of `src` with
    /// `cdict`, with its parameters (and the window widened to the input,
    /// up to 512 KB) for inputs up to 128 KB or six times the dictionary,
    /// else -- a CDict with a level -- the level's for the input size and
    /// the dictionary loaded anew. Every other parameter at its default.
    pub fn compressUsingCDict(comp: *Compressor, dst: []u8, src: []const u8, cdict: *const CDict, fp: FrameParams) Error!usize {
        const bound = compressBound(src.len);
        if (dst.len < bound) return error.NoSpaceLeft;
        const pledged: u64 = src.len;
        const dict_size: u64 = cdict.content.len;
        var cp = if (pledged < use_cdict_params_src_size_cutoff or pledged < dict_size * use_cdict_params_dict_size_multiplier or
            cdict.compression_level == 0)
            cdict.ms.cp
        else
            // ZSTD_getCParams: a size of 0 is unknown (not reachable here)
            params.getInternal(cdict.compression_level, pledged, dict_size, .unknown);
        // ZSTD_CCtxParams_init_internal resolves the switches on these
        // parameters, before the window grows below
        var adv: params.Advanced = .{ .content_size = fp.content_size, .dict_id_flag = fp.dict_id };
        adv.row_match_finder = resolved(params.resolveRowMatchFinder(.auto, cp));
        adv.split_after_sequences = resolved(params.resolveSplitAfterSequences(.auto, cp));
        adv.long_distance_matching = resolved(ldm.resolve(.auto, cp));
        // Increase window log to fit the entire dictionary and source if the
        // source size is known. Limit the increase to 19, which is the
        // window log for compression level 1 with the largest source size.
        {
            const limited_src_size: u32 = @intCast(@min(pledged, 1 << 19));
            const limited_src_log: u32 = if (limited_src_size > 1) std.math.log2_int(u32, limited_src_size - 1) + 1 else 1;
            cp.window_log = @max(cp.window_log, limited_src_log);
        }
        const opts: Options = .{ .level = cdict.compression_level, .checksum = fp.checksum, .advanced = adv };
        try comp.beginInternal(null, cdict, cp, src.len, opts, false);
        return comp.finishFrame(dst[0..bound], src, opts);
    }

    fn resolved(on: bool) params.Switch {
        return if (on) .enable else .disable;
    }

    /// `ZSTD_compressBegin_usingCDict_deprecated`: the context set up with
    /// `cdict` for input of unknown size (so `cdict` is attached, its
    /// parameters used as they are), no frame parameters, for
    /// `compressBlockOnly`. Dictionary training compresses its samples
    /// this way (`ZDICT_analyzeEntropy`).
    pub fn beginUsingCDict(comp: *Compressor, cdict: *const CDict) BeginError!void {
        const cp = cdict.ms.cp;
        // ZSTD_CCtxParams_init_internal resolves the switches on the
        // CDict's parameters; fParams are all 0
        var adv: params.Advanced = .{ .content_size = false };
        adv.row_match_finder = resolved(params.resolveRowMatchFinder(.auto, cp));
        adv.split_after_sequences = resolved(params.resolveSplitAfterSequences(.auto, cp));
        adv.long_distance_matching = resolved(ldm.resolve(.auto, cp));
        const opts: Options = .{ .level = cdict.compression_level, .checksum = false, .advanced = adv };
        try comp.beginInternal(null, cdict, cp, null, opts, false);
    }

    /// `ZSTD_compressBlock_deprecated`: `src` as one block without a
    /// block header or frame (`ZSTD_compressContinue_internal` in block
    /// mode), after `beginUsingCDict` or another `begin*`. Returns 0 when
    /// the block is not compressible (store it raw), else the compressed
    /// size; `seqStore` then holds its sequences. `src` above the
    /// context's block size is `error.SrcSizeWrong`. `dst` is the room
    /// the caller gives (libzstd's callers give `ZSTD_BLOCKSIZE_MAX`).
    pub fn compressBlockOnly(comp: *Compressor, dst: []u8, src: []const u8) (SizeError || BlockError)!usize {
        if (src.len > comp.block_size_max) return error.SrcSizeWrong; // input is larger than a block
        if (src.len == 0) return 0; // do not generate an empty block if no input
        const ms = &comp.c.ms;
        if (!ms.windowUpdate(src, ms.force_non_contiguous)) {
            ms.force_non_contiguous = false;
            ms.next_to_update = ms.dict_limit;
        }
        if (comp.c.ldm) |ls| ls.windowUpdate(src);
        // overflow check and correction for block mode
        const bi = comp.c.index(src);
        _ = ms.overflowCorrectIfNeeded(comp.overflow_correct_frequently, bi, @as(usize, bi) + src.len);
        const c_size = try compressBlockMode(&comp.c, dst, src, false);
        comp.consumed += src.len;
        comp.produced += c_size;
        return c_size;
    }

    /// `ZSTD_getSeqStore`: the sequences and literals of the last block.
    pub fn seqStore(comp: *Compressor) *sequences.SeqStore {
        return &comp.c.ss;
    }

    /// `ZSTD_CCtx_init_compressStream2` (single-threaded): the frame's
    /// parameters from its pledged size (else the size hint) and the
    /// dictionary's size, then `ZSTD_compressBegin_internal`. `local` holds
    /// the context's own `CDict` for a `.raw` dictionary, made on first use
    /// and kept by the caller for the frames after.
    pub fn initStream2(comp: *Compressor, opts: Options, pledged: ?u64, size_hint: ?u32, buffered: bool, local: *?CDict) BeginError!void {
        const s = try comp.setupStream2(opts, pledged, size_hint, local);
        try comp.beginInternal(s.prefix, s.cdict, s.cp, pledged, s.opts, buffered);
        // the external sequences' offsets may reach into a CDict's content
        // (a prefix is cleared before they are read: single usage)
        comp.c.seq.dict_size = if (s.cdict) |c| c.content.len else 0;
    }

    /// What `ZSTD_CCtx_init_compressStream2` settles before it begins a
    /// frame: the parameters, the level (a `CDict`'s replaces the
    /// options'), and the dictionary as a prefix or a `CDict`.
    pub const StreamSetup = struct {
        cp: params.CParams,
        opts: Options,
        prefix: ?RawDict,
        cdict: ?*const CDict,
    };

    /// The first half of `initStream2`, which multithreaded compression
    /// shares (it hands the frame to its jobs instead of beginning it here).
    pub fn setupStream2(comp: *Compressor, opts: Options, pledged: ?u64, size_hint: ?u32, local: *?CDict) BeginError!StreamSetup {
        const adv = opts.advanced;
        var level = opts.level;
        var cdict: ?*const CDict = null;
        var prefix: ?RawDict = null;
        switch (opts.dict) {
            .none => {},
            // 0 bytes are no dictionary (ZSTD_CCtx_loadDictionary, refPrefix)
            .raw => |r| if (r.bytes.len != 0) {
                if (local.* == null) {
                    const gpa = comp.gpa orelse return error.OutOfMemory;
                    // ZSTD_CCtx_loadDictionary copies the dictionary
                    // (ZSTD_dlm_byCopy) and ZSTD_initLocalDict digests that
                    // copy: the window must not end in the caller's memory,
                    // or an input placed right after the dictionary would
                    // continue it (one segment instead of an extDict).
                    local.* = try CDict.initAdvanced(gpa, r.bytes, .{ .level = level, .content_type = r.content_type, .advanced = adv, .src_size_hint = size_hint });
                }
                cdict = &local.*.?;
            },
            .cdict => |c| {
                // Let the cdict's compression level take priority over the
                // requested params (not the context's own CDict's).
                cdict = c;
                level = c.compression_level;
            },
            .prefix => |p| if (p.bytes.len != 0) {
                prefix = p;
            },
        }
        const dict_size: u64 = if (prefix) |p| p.bytes.len else if (cdict) |c| c.content.len else 0;
        const mode: params.CParamMode = if (cdict) |c| (if (shouldAttachDict(c, adv, pledged orelse params.unknown_size)) .attach_dict else .no_attach_dict) else .no_attach_dict;
        const size: u64 = pledged orelse if (size_hint) |h| h else params.unknown_size;
        const cp = params.getFromCCtxParams(level, size, dict_size, mode, adv);
        var o = opts;
        o.level = level;
        // If external matchfinder is enabled, make sure to fail before
        // checking job size (for consistency)
        if (opts.sequence_producer != null and adv.nb_workers >= 1) return error.ParameterCombinationUnsupported;
        return .{ .cp = cp, .opts = o, .prefix = prefix, .cdict = cdict };
    }

    /// `ZSTD_compressBegin_internal`: set the context up for a frame with
    /// the dictionary `dict` (loaded into it) or `cdict` (its tables
    /// attached or copied -- or, for a large input and a CDict with a
    /// level, its content loaded anew).
    pub fn beginInternal(comp: *Compressor, dict: ?RawDict, cdict: ?*const CDict, cp: params.CParams, pledged: ?u64, opts: Options, buffered: bool) BeginError!void {
        const adv = opts.advanced;
        const dict_content_size: usize = if (cdict) |c| c.content.len else if (dict) |d| d.bytes.len else 0;
        const p = pledged orelse params.unknown_size;
        if (cdict) |c| if (c.content.len > 0 and
            (p < use_cdict_params_src_size_cutoff or p < @as(u64, c.content.len) * use_cdict_params_dict_size_multiplier or
                p == params.unknown_size or c.compression_level == 0) and
            adv.force_attach_dict != .load)
        {
            // ZSTD_resetCCtx_usingCDict
            if (shouldAttachDict(c, adv, p)) return comp.resetByAttachingCDict(c, cp, pledged, opts, buffered);
            return comp.resetByCopyingCDict(c, cp, pledged, opts, buffered);
        };
        try comp.begin(cp, pledged, opts, buffered, .{ .loaded_dict_size = dict_content_size });
        const d: RawDict = if (cdict) |c| .{ .bytes = c.content, .content_type = c.content_type } else dict orelse .{ .bytes = &.{} };
        if (d.bytes.len >= 8 or d.content_type == .full) comp.n_dict_loads += 1;
        comp.dict_id = try cdict_mod.insertDictionary(comp.c.prev, &comp.c.ms, comp.c.ldm, d.bytes, d.content_type, .fast, .for_cctx, .{
            .no_dict_id = !adv.dict_id_flag,
            .force_window = adv.force_max_window,
            .deterministic_ref_prefix = adv.deterministic_ref_prefix,
            .overflow_correct_frequently = opts.overflow_correct_frequently,
        });
        comp.dict_content_size = dict_content_size;
    }

    /// The switches libzstd resolved on the frame's parameters `cp`, before
    /// a CDict's replaced them: `ZSTD_CCtx_init_compressStream2` resolves
    /// them first.
    fn resolvedOn(opts: Options, cp: params.CParams, use_row: bool) Options {
        var o = opts;
        o.advanced.split_after_sequences = resolved(params.resolveSplitAfterSequences(opts.advanced.split_after_sequences, cp));
        o.advanced.long_distance_matching = resolved(ldm.resolve(opts.advanced.long_distance_matching, cp));
        o.advanced.row_match_finder = resolved(use_row);
        return o;
    }

    /// `ZSTD_resetCCtx_byCopyingCDict`: the CDict's parameters but for the
    /// window log, and a copy of its tables (untagged), window, entropy
    /// tables and repcodes.
    fn resetByCopyingCDict(comp: *Compressor, cdict: *const CDict, cp_frame: params.CParams, pledged: ?u64, opts: Options, buffered: bool) BeginError!void {
        const cdict_cp = cdict.ms.cp;
        std.debug.assert(!cdict.dedicated_dict_search);
        // Copy only compression parameters related to tables.
        var cp = cdict_cp;
        cp.window_log = cp_frame.window_log;
        try comp.begin(cp, pledged, resolvedOn(opts, cp_frame, cdict.use_row), buffered, .{ .leave_dirty = true });
        const ms = &comp.c.ms;
        std.debug.assert(ms.use_row == cdict.use_row);
        // copy tables
        copyCDictTable(ms.hash_table, cdict.ms.hash_table, cdict_cp);
        // Do not copy cdict's chainTable if cctx has parameters such that it
        // would not use chainTable (it has the CDict's size when it does)
        std.debug.assert(ms.chain_table.len == cdict.ms.chain_table.len);
        copyCDictTable(ms.chain_table, cdict.ms.chain_table, cdict_cp);
        // copy tag table
        if (cdict.use_row) {
            @memcpy(ms.tag_table, cdict.ms.tag_table);
            ms.hash_salt = cdict.ms.hash_salt;
        }
        // Zero the hashTable3, since the cdict never fills it
        @memset(ms.hash_table3, 0);
        // copy dictionary offsets
        ms.src = cdict.ms.src;
        ms.src_base = cdict.ms.src_base;
        ms.dict = cdict.ms.dict;
        ms.dict_base = cdict.ms.dict_base;
        ms.low_limit = cdict.ms.low_limit;
        ms.dict_limit = cdict.ms.dict_limit;
        ms.n_overflow_corrections = cdict.ms.n_overflow_corrections;
        ms.next_to_update = cdict.ms.next_to_update;
        ms.loaded_dict_end = cdict.ms.loaded_dict_end;
        comp.dict_id = cdict.dict_id;
        comp.dict_content_size = cdict.content.len;
        // copy block state
        comp.c.prev.* = cdict.block_state;
        comp.n_cdict_copies += 1;
    }

    /// `ZSTD_copyCDictTableIntoCCtx`: a `fast`/`dfast` CDict's entries lose
    /// their tag.
    fn copyCDictTable(dst: []u32, src: []const u32, cdict_cp: params.CParams) void {
        if (params.cdictIndicesAreTagged(cdict_cp)) {
            for (dst, src) |*d, t| d.* = t >> params.short_cache_tag_bits;
        } else @memcpy(dst, src);
    }

    /// `ZSTD_resetCCtx_byAttachingCDict`: parameters for the input alone
    /// (the CDict keeps its own tables), and the CDict's match state
    /// attached below the window (`MatchState.dict_match_state`), which the
    /// match finders' `dictMatchState` variants search. Refused
    /// (`error.DictAttachUnsupported`) until the CDict's strategy has them
    /// (`match.hasDictMatchStateVariant`); the rest is libzstd's attach,
    /// ready for them.
    fn resetByAttachingCDict(comp: *Compressor, cdict: *const CDict, cp_frame: params.CParams, pledged: ?u64, opts: Options, buffered: bool) BeginError!void {
        if (!match.hasDictMatchStateVariant(cdict.ms.cp.strategy)) return error.DictAttachUnsupported;
        const use_row_frame = params.resolveRowMatchFinder(opts.advanced.row_match_finder, cp_frame);
        // Resize working context table params for input only, since the
        // dict has its own tables.
        var cdict_cp = cdict.ms.cp;
        if (cdict.dedicated_dict_search) cdict_mod.ddsRevertCParams(&cdict_cp);
        var cp = params.adjustInternal(cdict_cp, pledged orelse params.unknown_size, cdict.content.len, .attach_dict, resolved(use_row_frame));
        cp.window_log = cp_frame.window_log;
        try comp.begin(cp, pledged, resolvedOn(opts, cp_frame, cdict.use_row), buffered, .{});
        const ms = &comp.c.ms;
        const cdict_end: u32 = @intCast(cdict.ms.src_base + cdict.ms.src.len);
        const cdict_len = cdict_end - cdict.ms.dict_limit;
        if (cdict_len != 0) { // don't even attach dictionaries with no contents
            ms.dict_match_state = &cdict.ms;
            // prep working match state so dict matches never have negative
            // indices when they are translated to the working context's
            // index space: the window starts (empty) at the CDict's end
            if (ms.dict_limit < cdict_end) {
                ms.src = ms.src[ms.src.len..];
                ms.src_base = cdict_end;
                ms.low_limit = cdict_end; // ZSTD_window_clear
                ms.dict_limit = cdict_end;
            }
            // loadedDictEnd is expressed within the referential of the
            // active context
            ms.loaded_dict_end = ms.dict_limit;
        }
        comp.dict_id = cdict.dict_id;
        comp.dict_content_size = cdict.content.len;
        // copy block state
        comp.c.prev.* = cdict.block_state;
    }

    /// How `begin` treats the tables (`ZSTD_resetCCtx_internal`'s
    /// `loadedDictSize` and `ZSTD_compResetPolicy_e`).
    pub const Reset = struct {
        /// A dictionary about to be loaded; over `ZSTD_CHUNKSIZE_MAX` it
        /// restarts indexing.
        loaded_dict_size: usize = 0,
        /// `ZSTDcrp_leaveDirty`: the tables are about to be overwritten.
        leave_dirty: bool = false,
    };

    /// `ZSTD_resetCCtx_internal`: set the context up for a frame with
    /// parameters `cp` (the level's, sized for `pledged`), resizing the
    /// workspace if it is too small or has long been three times too big.
    /// `buffered` adds a stream's input and output buffers.
    pub fn begin(comp: *Compressor, cp: params.CParams, pledged: ?u64, opts: Options, buffered: bool, reset: Reset) error{OutOfMemory}!void {
        const l = Layout.compute(cp, pledged, opts, buffered);

        const ms_old = comp.c.ms;
        // ZSTD_dictTooBig: a dictionary larger than ZSTD_CHUNKSIZE_MAX is
        // loaded from index 0, as much of it as fits
        const dict_too_big = reset.loaded_dict_size > chunk_size_max;
        var index_reset = !comp.initialized or ms_old.src_base + ms_old.src.len > comp.index_too_close or dict_too_big;

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
        // (left dirty, they are overwritten whole right after)
        if (comp.tables_valid < tables_bytes and !reset.leave_dirty) @memset(ws[comp.tables_valid..tables_bytes], 0);
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
        comp.dict_id = 0;
        comp.no_dict_id = !adv.dict_id_flag;
        comp.dict_content_size = 0;
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
            .seq = .{
                .validate = adv.validate_sequences,
                .repcode_resolution = seqapi.resolveRepcodeResolution(adv.repcode_resolution, appliedLevel(opts.level)),
                .block_delimiters = adv.block_delimiters,
                .fallback = adv.enable_seq_producer_fallback,
                .producer = opts.sequence_producer,
                .min_match = cp.min_match,
                .window_log = cp.window_log,
                // ZSTD_maxNbSeq (without the port's spare slot)
                .max_nb_seq = l.block_size_max / Layout.seqDivider(cp, opts),
                .level = appliedLevel(opts.level),
            },
            .ext_seqs = slice(seqapi.Sequence, ws, l.ext_seqs, l.ext_n_seqs),
            .collector = opts.collector,
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
        // `forceNonContiguous` is libzstd's until the next chunk consumes it
        ms.force_non_contiguous = ms_old.force_non_contiguous;
        comp.initialized = true;
    }

    /// `appliedParams.compressionLevel`: 0 is the default level, and
    /// levels below the lowest are clamped (`ZSTD_CCtx_setParameter`).
    fn appliedLevel(level: i32) i32 {
        return if (level == 0) params.default_level else @max(level, params.min_level);
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
    pub fn compressContinue(comp: *Compressor, dst: []u8, chunk: []const u8, last_chunk: bool) (SizeError || BlockError)!usize {
        var fh_size: usize = 0;
        if (comp.stage == .init) {
            fh_size = writeFrameHeader(dst, comp.cp, comp.headerContentSize(comp.pledged), comp.checksum, comp.format, comp.dict_id, comp.no_dict_id);
            comp.stage = .ongoing;
        }
        if (chunk.len == 0) return fh_size; // do not generate an empty block if no input

        const ms = &comp.c.ms;
        if (!ms.windowUpdate(chunk, ms.force_non_contiguous)) {
            ms.force_non_contiguous = false;
            ms.next_to_update = ms.dict_limit;
        }
        if (comp.c.ldm) |ls| ls.windowUpdate(chunk);

        const c_size = try comp.frameChunk(dst[fh_size..], chunk, last_chunk);
        comp.consumed += chunk.len;
        comp.produced += c_size + fh_size;
        if (comp.pledged) |p| if (comp.consumed > p) return error.SrcSizeWrong;
        return c_size + fh_size;
    }

    /// `ZSTD_compress_frameChunk`.
    fn frameChunk(comp: *Compressor, out: []u8, chunk: []const u8, last_chunk: bool) BlockError!usize {
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
            c.ms.checkDictValidity(c.index(block) + @as(u32, @intCast(block_size)));
            c.ms.enforceMaxDist(c.index(block));
            // Ensure hash/chain table insertion resumes no sooner than lowlimit
            if (c.ms.next_to_update < c.ms.low_limit) c.ms.next_to_update = c.ms.low_limit;

            const c_size = if (c.target_c_block_size != 0)
                try compressBlockTargetCBlockSize(c, out[op..], block, last_block)
            else if (c.split_blocks)
                try compressBlockSplit(c, out[op..], block, last_block)
            else
                emitBlock(out[op..], block, try compressBlock(c, out[op + block_header_size ..], block), last_block);
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
            // special case: empty frame (libzstd passes dictID 0 here)
            op += writeFrameHeader(dst, comp.cp, comp.headerContentSize(0), comp.checksum, comp.format, 0, comp.no_dict_id);
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

    // ---- Sequence-level API (Z10; seqapi.zig) ----

    pub const SequenceError = Error || error{
        /// `dstSize_tooSmall`: `dst` too small for the frame (libzstd's
        /// capacity rules: the frame header needs 18 bytes of room).
        DstSizeTooSmall,
        /// `parameter_unsupported`: `generateSequences` with
        /// `target_c_block_size`; `compressSequencesAndLiterals` with
        /// validation.
        ParameterUnsupported,
        /// `frameParameter_unsupported`: `compressSequencesAndLiterals`
        /// without explicit block delimiters, or with a checksum.
        FrameParameterUnsupported,
        /// `cannotProduce_uncompressedBlock`: a block of
        /// `compressSequencesAndLiterals` does not compress, and without the
        /// input it cannot be stored raw.
        CannotProduceUncompressedBlock,
        /// `GENERIC`: the entropy stage failed on sequences no encoder
        /// produces.
        Generic,
    };

    /// `ZSTD_compressSequences`: one frame of `src` from the caller's
    /// sequences `seqs` (with or without block delimiters, as
    /// `opts.advanced.block_delimiters` says), with every parameter and
    /// the dictionary of `opts` as `compressFrame` takes them. No match
    /// finder runs. Unlike `compressFrame`, `dst` may have any size; too
    /// little room is `error.DstSizeTooSmall` where libzstd says so.
    pub fn compressSequences(comp: *Compressor, dst: []u8, seqs: []const seqapi.Sequence, src: []const u8, opts: Options) SequenceError!usize {
        try opts.advanced.check();
        var local: ?CDict = null;
        defer if (local) |*l| l.deinit();
        try comp.initStream2(opts, src.len, null, false, &local);
        const n = try comp.writeSeqFrameHeader(dst, src.len);
        var c_size = n;
        if (comp.checksum and src.len != 0) comp.xxh.update(src);
        // Now generate compressed blocks
        c_size += try comp.compressSequencesInternal(dst[n..], seqs, src);
        // Complete with frame checksum, if needed
        if (comp.checksum) {
            if (dst.len - c_size < 4) return error.DstSizeTooSmall; // no room for checksum
            std.mem.writeInt(u32, dst[c_size..][0..4], @truncate(comp.xxh.final()), .little);
            c_size += 4;
        }
        return c_size;
    }

    /// `ZSTD_writeFrameHeader` as the sequence API calls it: the header
    /// needs `ZSTD_FRAMEHEADERSIZE_MAX` bytes of room. (libzstd does not
    /// check the error it returns there and goes on at a wild position;
    /// here it is `error.DstSizeTooSmall`.)
    fn writeSeqFrameHeader(comp: *Compressor, dst: []u8, content_size: u64) error{DstSizeTooSmall}!usize {
        const frame_header_size_max = 18;
        if (dst.len < frame_header_size_max) return error.DstSizeTooSmall;
        return writeFrameHeader(dst, comp.cp, comp.headerContentSize(content_size), comp.checksum, comp.format, comp.dict_id, comp.no_dict_id);
    }

    /// `ZSTD_compressSequences_internal`: the blocks.
    fn compressSequencesInternal(comp: *Compressor, dst: []u8, seqs: []const seqapi.Sequence, src: []const u8) SequenceError!usize {
        const c = &comp.c;
        var c_size: usize = 0;
        var remaining = src.len;
        var pos: seqapi.Position = .{};
        var ip: usize = 0;
        var op: usize = 0;
        // Special case: empty frame
        if (remaining == 0) {
            // (libzstd writes the 24-bit header as 4 bytes)
            if (dst.len < 4) return error.DstSizeTooSmall; // No room for empty frame block header
            writeBlockHeader(dst, 1 + (bt_raw << 1));
            dst[3] = 0;
            op += block_header_size;
            c_size += block_header_size;
        }
        while (remaining != 0) {
            var block_size = try seqapi.determineBlockSize(c.seq.block_delimiters, comp.block_size_max, remaining, seqs, pos);
            const last_block: u32 = @intFromBool(block_size == remaining);
            c.ss.reset();
            const reps: seqapi.Reps = .{ .prev = &c.prev.rep, .next = &c.next.rep };
            const block = src[ip..][0..block_size];
            block_size = switch (c.seq.block_delimiters) {
                .explicit => try seqapi.transferWithBlockDelim(&c.ss, reps, &c.seq, &pos, seqs, block, c.seq.repcode_resolution),
                .none => try seqapi.transferNoDelim(&c.ss, reps, &c.seq, &pos, seqs, block),
            };
            const out = dst[op..];

            // If blocks are too small, emit as a nocompress block
            if (block_size < min_cblock_size + block_header_size + 1 + 1) {
                const n = try noCompressBlock(out, src[ip..][0..block_size], last_block);
                c_size += n;
                ip += block_size;
                op += n;
                remaining -= block_size;
                continue;
            }

            // not enough dstCapacity to write a new compressed block
            if (out.len < block_header_size) return error.DstSizeTooSmall;
            var c_seqs_size = try entropyCompressSeqStore(c, &c.ss, out[block_header_size..], block_size);
            // Note: don't emit the first block as RLE even if it qualifies
            // because doing so will cause the decoder (cli <= v1.4.3 only)
            // to throw an (invalid) error "should consume all input error."
            if (!c.is_first_block and seqapi.maybeRle(&c.ss) and isRle(src[ip..][0..block_size])) c_seqs_size = 1;

            var c_block_size: usize = undefined;
            if (c_seqs_size == 0) {
                c_block_size = try noCompressBlock(out, src[ip..][0..block_size], last_block);
            } else if (c_seqs_size == 1) {
                if (out.len < 4) return error.DstSizeTooSmall;
                c_block_size = emitBlock(out, src[ip..][0..block_size], 1, last_block);
            } else {
                // Error checking and repcodes update
                std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
                offcodeValidToCheck(c);
                c_block_size = emitBlock(out, src[ip..][0..block_size], c_seqs_size, last_block);
            }
            c_size += c_block_size;
            if (last_block != 0) break;
            ip += block_size;
            op += c_block_size;
            remaining -= block_size;
            c.is_first_block = false;
        }
        return c_size;
    }

    /// `ZSTD_noCompressBlock`.
    fn noCompressBlock(out: []u8, src: []const u8, last_block: u32) error{DstSizeTooSmall}!usize {
        // dst buf too small for uncompressed block
        if (src.len + block_header_size > out.len) return error.DstSizeTooSmall;
        return emitBlock(out, src, 0, last_block);
    }

    /// `ZSTD_entropyCompressSeqStore` with libzstd's capacity rule: out of
    /// room is "store raw" only when the raw block would fit.
    fn entropyCompressSeqStore(c: *Ctx, ss: *sequences.SeqStore, dst: []u8, block_size: usize) error{DstSizeTooSmall}!usize {
        const c_size = entropyCompressInternal(c, ss, dst) catch |err| switch (err) {
            error.DstSizeTooSmall => if (block_size <= dst.len) return 0 else return error.DstSizeTooSmall,
            // as in `entropyCompress`: not reachable from inputs libzstd encodes
            error.Generic => return 0,
        };
        if (c_size == 0) return 0;
        const max_c_size = block_size - literals.minGain(block_size, c.strategy);
        if (c_size >= max_c_size) return 0; // block not compressed
        return c_size;
    }

    /// `ZSTD_compressSequencesAndLiterals`: one frame of
    /// `decompressed_size` bytes from `seqs` (with explicit block
    /// delimiters) and `lits`, all their literals one after the other --
    /// without the input itself, so a block that does not compress is
    /// `error.CannotProduceUncompressedBlock`. Refuses validation and the
    /// checksum, as libzstd does. (libzstd also takes the literal buffer's
    /// capacity, only to refuse one smaller than the literals; a slice
    /// needs no such check.)
    pub fn compressSequencesAndLiterals(comp: *Compressor, dst: []u8, seqs: []const seqapi.Sequence, lits: []const u8, decompressed_size: usize, opts: Options) SequenceError!usize {
        try opts.advanced.check();
        var local: ?CDict = null;
        defer if (local) |*l| l.deinit();
        try comp.initStream2(opts, decompressed_size, null, false, &local);
        // This mode is only compatible with explicit delimiters
        if (comp.c.seq.block_delimiters == .none) return error.FrameParameterUnsupported;
        // This mode is not compatible with Sequence validation
        if (comp.c.seq.validate) return error.ParameterUnsupported;
        // this mode is not compatible with frame checksum
        if (comp.checksum) return error.FrameParameterUnsupported;
        const n = try comp.writeSeqFrameHeader(dst, decompressed_size);
        return n + try comp.compressSequencesAndLiteralsInternal(dst[n..], seqs, lits, decompressed_size);
    }

    /// `ZSTD_compressSequencesAndLiterals_internal`.
    fn compressSequencesAndLiteralsInternal(comp: *Compressor, dst: []u8, seqs_in: []const seqapi.Sequence, lits_in: []const u8, src_size: usize) SequenceError!usize {
        const c = &comp.c;
        var seqs = seqs_in;
        var lits = lits_in;
        var remaining: u64 = src_size;
        var c_size: usize = 0;
        var op: usize = 0;
        if (seqs.len == 0) return error.ExternalSequencesInvalid; // Requires at least 1 end-of-block
        // Special case: empty frame
        if (seqs.len == 1 and seqs[0].lit_length == 0) {
            if (dst.len < 3) return error.DstSizeTooSmall; // No room for empty frame block header
            writeBlockHeader(dst, 1 + (bt_raw << 1));
            op += block_header_size;
            c_size += block_header_size;
        }
        while (seqs.len != 0) {
            const block = try seqapi.get1BlockSummary(seqs);
            const last_block: u32 = @intFromBool(block.n_seq == seqs.len);
            // discrepancy: Sequences require more literals than present in buffer
            if (block.lit_size > lits.len) return error.ExternalSequencesInvalid;
            c.ss.reset();
            try seqapi.convertBlockSequences(&c.ss, .{ .prev = &c.prev.rep, .next = &c.next.rep }, &c.seq, seqs[0..block.n_seq], c.seq.repcode_resolution);
            seqs = seqs[block.n_seq..];
            remaining -%= block.block_size;

            // Note: when blockSize is very small, other variant send it
            // uncompressed. Here, we still send the sequences, because we
            // don't have the original source to send it uncompressed.
            const out = dst[op..];
            // not enough dstCapacity to write a new compressed block
            if (out.len < block_header_size) return error.DstSizeTooSmall;
            const block_lits = lits[0..@intCast(block.lit_size)];
            var c_seqs_size = entropyCompressLits(c, &c.ss, block_lits, out[block_header_size..]) catch |err| switch (err) {
                error.DstSizeTooSmall => return error.DstSizeTooSmall,
                error.Generic => return error.Generic,
            };
            // note: the spec forbids for any compressed block to be larger
            // than maximum block size
            if (c_seqs_size > comp.block_size_max) c_seqs_size = 0;
            lits = lits[block_lits.len..];
            // Sending uncompressed blocks is out of reach, because the
            // source is not provided.
            if (c_seqs_size == 0) return error.CannotProduceUncompressedBlock;
            // Error checking and repcodes update
            std.mem.swap(*BlockState, &c.prev, &c.next); // confirm repcodes and entropy tables
            offcodeValidToCheck(c);
            writeBlockHeader(out, last_block + (bt_compressed << 1) + (@as(u32, @intCast(c_seqs_size)) << 3));
            const c_block_size = block_header_size + c_seqs_size;
            c_size += c_block_size;
            op += c_block_size;
            c.is_first_block = false;
            if (last_block != 0) break;
        }
        // literals must be entirely and exactly consumed
        if (lits.len != 0) return error.ExternalSequencesInvalid;
        // Sequences must represent a total of exactly srcSize
        if (remaining != 0) return error.ExternalSequencesInvalid;
        return c_size;
    }

    /// `ZSTD_generateSequences`: the sequences `compressFrame` finds for
    /// `src` with `opts`, each block's followed by a delimiter holding its
    /// last literals, into `out` (`sequenceBound(src.len)` is always
    /// enough). Returns how many. libzstd marks it deprecated and "for
    /// debugging only": it fails (`error.SequenceProducerFailed`) on a
    /// block too small to compress, i.e. an input whose last block is
    /// under 7 bytes, and does not take `target_c_block_size`. It
    /// compresses into a scratch buffer from the context's allocator (a
    /// static context has none: `error.OutOfMemory`).
    pub fn generateSequences(comp: *Compressor, out: []seqapi.Sequence, src: []const u8, opts: Options) SequenceError!usize {
        if (params.nonZero(opts.advanced.target_c_block_size) != null) return error.ParameterUnsupported; // targetCBlockSize != 0
        if (opts.advanced.nb_workers != 0) return error.ParameterUnsupported; // nbWorkers != 0
        const gpa = comp.gpa orelse return error.OutOfMemory;
        const dst = try gpa.alloc(u8, compressBound(src.len));
        defer gpa.free(dst);
        var col: seqapi.Collector = .{ .seqs = out };
        var o = opts;
        o.collector = &col;
        _ = try comp.compressFrame(dst, src, o);
        return col.idx;
    }
};
