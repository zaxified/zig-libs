// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Superblocks: a block's sequences cut into several compressed blocks of
//! about `targetCBlockSize` bytes each (port of libzstd
//! lib/compress/zstd_compress_superblock.c, v1.5.7). The whole block's
//! entropy tables are built once; the first sub-block that writes literals
//! or sequences carries them, the later ones say `set_repeat`. A sub-block
//! that would not shrink is folded into the next; what the last one cannot
//! compress is stored raw.

const std = @import("std");
const huf = @import("huf.zig");
const hist = @import("hist.zig");
const literals = @import("literals.zig");
const sequences = @import("sequences.zig");
const blocksplit = @import("blocksplit.zig");
const SeqStore = sequences.SeqStore;

/// `ZSTD_TARGETCBLOCKSIZE_MIN`: suitable to fit into an ethernet / wifi / 4G
/// transport frame.
pub const target_c_block_size_min = 1340;
/// `ZSTD_TARGETCBLOCKSIZE_MAX`: `ZSTD_BLOCKSIZE_MAX`.
pub const target_c_block_size_max = 128 * 1024;

/// `BYTESCALE`: costs are in 1/256 bytes.
const bytescale = 256;
const block_header_size = 3;
const bt_raw = 0;
const bt_compressed = 2;
const set_repeat = 3;

pub const Error = error{
    /// libzstd's `dstSize_tooSmall`: the caller stores the block raw.
    DstSizeTooSmall,
};

/// One block's entropy state (`ZSTD_compressedBlockState_t`).
pub const State = struct {
    huf: *literals.HufState,
    fse: *sequences.FseTables,
    rep: *[3]u32,
};

/// `ZSTD_entropyCTablesMetadata_t`.
const Metadata = struct {
    huf: blocksplit.HufMetadata,
    huf_des: [blocksplit.max_huf_header_size]u8,
    ll_type: sequences.EncodingType,
    of_type: sequences.EncodingType,
    ml_type: sequences.EncodingType,
    fse_tables: [2048]u8, // ZSTD_MAX_FSE_HEADERS_SIZE is never approached
    fse_tables_size: usize,
    last_count_size: usize,
};

/// `ZSTD_compressSuperBlock`: the block `src`, whose sequences are in `ss`,
/// as sub-blocks into `dst`. Returns the bytes written, 0 when the block is
/// better stored raw, or `error.DstSizeTooSmall`.
pub fn compress(ss: *SeqStore, prev: State, next: State, strategy: u32, disable_literal_compression: bool, target_c_block_size: u32, dst: []u8, src: []const u8, last_block: u32) Error!usize {
    // ZSTD_buildBlockEntropyStats
    var meta: Metadata = undefined;
    const lits = ss.lits[0..ss.n_lit];
    meta.huf.des_size = blocksplit.buildLiteralsStats(lits, prev.huf, next.huf, disable_literal_compression, strategy >= 8, &meta.huf, &meta.huf_des);
    // (libzstd surfaces an internal error here; none is reachable from the
    // inputs this port accepts, so the block is stored raw)
    if (blocksplit.isError(meta.huf.des_size)) return 0;
    if (ss.n_seq != 0) {
        const stats = sequences.buildStatistics(ss, prev.fse, next.fse, &meta.fse_tables, strategy) catch return 0;
        meta.ll_type = stats.ll_type;
        meta.of_type = stats.of_type;
        meta.ml_type = stats.ml_type;
        meta.fse_tables_size = stats.size;
        meta.last_count_size = stats.last_count_size;
    } else {
        // ZSTD_buildDummySequencesStatistics
        next.fse.ll_repeat = .none;
        next.fse.of_repeat = .none;
        next.fse.ml_repeat = .none;
        meta.ll_type = .basic;
        meta.of_type = .basic;
        meta.ml_type = .basic;
        meta.fse_tables_size = 0;
        meta.last_count_size = 0;
    }
    return compressMulti(ss, prev, next, &meta, target_c_block_size, dst, src, last_block);
}

/// `ZSTD_getSequenceLength`: sequence `i` of `ss`, long lengths included.
fn sequenceLength(ss: *const SeqStore, i: usize) struct { lit: usize, match: usize } {
    const sq = ss.seqs[i];
    var lit: usize = sq.lit_length;
    var ml: usize = @as(usize, sq.ml_base) + sequences.min_match;
    if (ss.long_length_pos == i) {
        if (ss.long_length_type == .literal_length) lit += 0x10000;
        if (ss.long_length_type == .match_length) ml += 0x10000;
    }
    return .{ .lit = lit, .match = ml };
}

/// `countLiterals`.
fn countLiterals(ss: *const SeqStore, sp: usize, count: usize) usize {
    var total: usize = 0;
    for (sp..sp + count) |i| total += sequenceLength(ss, i).lit;
    return total;
}

/// `ZSTD_seqDecompressedSize`: the bytes sequences `sp..sp+count` and
/// `lit_size` literals decode to.
fn decompressedSize(ss: *const SeqStore, sp: usize, count: usize, lit_size: usize) usize {
    var match_sum: usize = 0;
    for (sp..sp + count) |i| match_sum += sequenceLength(ss, i).match;
    return match_sum + lit_size;
}

/// `sizeBlockSequences`: how many sequences from `sp` fit `target_budget`
/// (in 1/256 bytes). Reads the raw 16-bit lengths, as libzstd does.
fn sizeBlockSequences(seqs: []const sequences.SeqDef, target_budget: usize, avg_lit_cost: usize, avg_seq_cost: usize, first_sub_block: bool) usize {
    const header_size: usize = @as(usize, @intFromBool(first_sub_block)) * 120 * bytescale;
    var budget: usize = header_size;
    budget += @as(usize, seqs[0].lit_length) * avg_lit_cost + avg_seq_cost;
    if (budget > target_budget) return 1;
    var in_size: usize = @as(usize, seqs[0].lit_length) + seqs[0].ml_base + sequences.min_match;
    var n: usize = 1;
    while (n < seqs.len) : (n += 1) {
        const current_cost = @as(usize, seqs[n].lit_length) * avg_lit_cost + avg_seq_cost;
        budget += current_cost;
        in_size += @as(usize, seqs[n].lit_length) + seqs[n].ml_base + sequences.min_match;
        // stop when sub-block budget is reached
        if (budget > target_budget and budget < in_size * bytescale) break;
    }
    return n;
}

/// `ZSTD_estimateSubBlockSize_literal`.
fn estimateLiterals(lits: []const u8, table: *const huf.CTable, meta: blocksplit.HufMetadata, write_entropy: bool) usize {
    const literal_section_header_size = 3;
    switch (meta.h_type) {
        .basic => return lits.len,
        .rle => return 1,
        .compressed, .repeat => {
            var counts: [huf.symbol_value_max + 1]u32 = undefined;
            var max_symbol: u32 = huf.symbol_value_max;
            _ = hist.count(&counts, &max_symbol, lits);
            var estimate = huf.estimateCompressedSize(table, &counts, max_symbol);
            if (write_entropy) estimate += meta.des_size;
            return estimate + literal_section_header_size;
        },
    }
}

/// `ZSTD_estimateSubBlockSize_symbolType`.
fn estimateSymbolType(kind: sequences.EncodingType, codes: []const u8, max_code: u32, ct: *const @import("fse.zig").CTable, additional_bits: ?[]const u8, default_norm: []const i16, default_norm_log: u32, default_max: u32) usize {
    var counts: [sequences.max_ml + 1]u32 = undefined;
    var max = max_code;
    _ = hist.count(&counts, &max, codes);
    var bits: usize = switch (kind) {
        .basic => if (max <= default_max) sequences.crossEntropyCost(default_norm, default_norm_log, &counts, max) else sequences.cost_error,
        .rle => 0,
        .compressed, .repeat => sequences.fseBitCost(ct, &counts, max),
    };
    if (bits == sequences.cost_error) return codes.len * 10;
    for (codes) |c| bits += if (additional_bits) |ab| ab[c] else c;
    return bits / 8;
}

/// `ZSTD_estimateSubBlockSize`: the literals' size and the whole block's.
fn estimateSubBlockSize(lits: []const u8, ss: *const SeqStore, n_seq: usize, next: State, meta: *const Metadata, write_lit_entropy: bool, write_seq_entropy: bool) struct { lit: usize, block: usize } {
    const lit = estimateLiterals(lits, &next.huf.table, meta.huf, write_lit_entropy);
    // ZSTD_estimateSubBlockSize_sequences
    const sequences_section_header_size = 3;
    var seq: usize = 0;
    if (n_seq != 0) {
        seq += estimateSymbolType(meta.of_type, ss.of_code[0..n_seq], sequences.max_off, &next.fse.of, null, &sequences.of_default_norm, sequences.of_default_norm_log, sequences.default_max_off);
        seq += estimateSymbolType(meta.ll_type, ss.ll_code[0..n_seq], sequences.max_ll, &next.fse.ll, &sequences.ll_bits, &sequences.ll_default_norm, sequences.ll_default_norm_log, sequences.max_ll);
        seq += estimateSymbolType(meta.ml_type, ss.ml_code[0..n_seq], sequences.max_ml, &next.fse.ml, &sequences.ml_bits, &sequences.ml_default_norm, sequences.ml_default_norm_log, sequences.max_ml);
        if (write_seq_entropy) seq += meta.fse_tables_size;
    }
    seq += sequences_section_header_size;
    return .{ .lit = lit, .block = seq + lit + block_header_size };
}

/// `ZSTD_needSequenceEntropyTables`.
fn needSequenceEntropyTables(meta: *const Metadata) bool {
    for ([_]sequences.EncodingType{ meta.ll_type, meta.ml_type, meta.of_type }) |t|
        if (t == .compressed or t == .rle) return true;
    return false;
}

/// `ZSTD_compressSubBlock_literal`. Returns 0 when the literals do not
/// compress.
fn compressLiterals(table: *const huf.CTable, meta: *const Metadata, lits: []const u8, dst: []u8, write_entropy: bool, entropy_written: *bool) Error!usize {
    const header: usize = if (write_entropy) 200 else 0;
    const lh_size: usize = 3 + @as(usize, @intFromBool(lits.len >= 1024 -| header)) + @intFromBool(lits.len >= 16 * 1024 -| header);
    const single_stream = lh_size == 3;
    const h_type: u32 = if (write_entropy) @intFromEnum(meta.huf.h_type) else set_repeat;
    entropy_written.* = false;
    if (lits.len == 0 or meta.huf.h_type == .basic) {
        return literals.noCompress(dst, lits) catch error.DstSizeTooSmall;
    } else if (meta.huf.h_type == .rle) {
        return literals.rle(dst, lits);
    }
    var op = lh_size;
    var c_lit_size: usize = 0;
    if (write_entropy and meta.huf.h_type == .compressed) {
        @memcpy(dst[op..][0..meta.huf.des_size], meta.huf_des[0..meta.huf.des_size]);
        op += meta.huf.des_size;
        c_lit_size += meta.huf.des_size;
    }
    {
        const c_size = if (single_stream) huf.compress1X(dst[op..], lits, table) else huf.compress4X(dst[op..], lits, table);
        op += c_size;
        c_lit_size += c_size;
        if (c_size == 0) return 0;
        // If we are writing headers then allow expansion that doesn't
        // change our header size.
        if (!write_entropy and c_lit_size >= lits.len)
            return literals.noCompress(dst, lits) catch error.DstSizeTooSmall;
        if (lh_size < 3 + @as(usize, @intFromBool(c_lit_size >= 1024)) + @intFromBool(c_lit_size >= 16 * 1024))
            return literals.noCompress(dst, lits) catch error.DstSizeTooSmall;
    }
    const lit_size: u32 = @intCast(lits.len);
    const c_lit: u32 = @intCast(c_lit_size);
    switch (lh_size) {
        3 => { // 2 - 1 - 10 - 10
            const lhc: u32 = h_type + (@as(u32, @intFromBool(!single_stream)) << 2) + (lit_size << 4) + (c_lit << 14);
            dst[0] = @truncate(lhc);
            dst[1] = @truncate(lhc >> 8);
            dst[2] = @truncate(lhc >> 16);
        },
        4 => { // 2 - 2 - 14 - 14
            const lhc: u32 = h_type + (2 << 2) + (lit_size << 4) + (c_lit << 18);
            std.mem.writeInt(u32, dst[0..4], lhc, .little);
        },
        5 => { // 2 - 2 - 18 - 18
            const lhc: u32 = h_type + (3 << 2) + (lit_size << 4) +% (c_lit << 22);
            std.mem.writeInt(u32, dst[0..4], lhc, .little);
            dst[4] = @truncate(c_lit >> 10);
        },
        else => unreachable,
    }
    entropy_written.* = true;
    return op;
}

/// `ZSTD_compressSubBlock_sequences`: sequences of the view `ss`. Returns 0
/// when a decoder of zstd <= 1.4.0 would misread them.
fn compressSequences(fse_tables: *const sequences.FseTables, meta: *const Metadata, ss: *const SeqStore, dst: []u8, write_entropy: bool, entropy_written: *bool) Error!usize {
    const n_seq = ss.n_seq;
    var op: usize = 0;
    entropy_written.* = false;
    // Sequences Header
    if (dst.len < 3 + 1) return error.DstSizeTooSmall;
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
    if (n_seq == 0) return op;

    // seqHead : flags for FSE encoding type
    const seq_head = op;
    op += 1;
    if (write_entropy) {
        dst[seq_head] = (@as(u8, @intFromEnum(meta.ll_type)) << 6) + (@as(u8, @intFromEnum(meta.of_type)) << 4) + (@as(u8, @intFromEnum(meta.ml_type)) << 2);
        @memcpy(dst[op..][0..meta.fse_tables_size], meta.fse_tables[0..meta.fse_tables_size]);
        op += meta.fse_tables_size;
    } else {
        dst[seq_head] = (set_repeat << 6) + (set_repeat << 4) + (set_repeat << 2);
    }
    const bitstream_size = sequences.encode(dst[op..], ss, &fse_tables.ml, &fse_tables.of, &fse_tables.ll) catch |err| switch (err) {
        error.DstSizeTooSmall => return error.DstSizeTooSmall,
        else => unreachable,
    };
    op += bitstream_size;
    // zstd versions <= 1.3.4 mistakenly report corruption when
    // FSE_readNCount() receives a buffer < 4 bytes; emit an uncompressed
    // block instead.
    if (write_entropy and meta.last_count_size != 0 and meta.last_count_size + bitstream_size < 4) return 0;
    // zstd versions <= 1.4.0 mistakenly report error when sequences section
    // body size is less than 3 bytes.
    if (op - seq_head < 4) return 0;
    entropy_written.* = true;
    return op;
}

/// `ZSTD_compressSubBlock`: one compressed block of sequences `sp..` (the
/// store `sub`) and literals `lits`, header included. 0 when it does not
/// compress.
fn compressSubBlock(next: State, meta: *const Metadata, sub: *const SeqStore, lits: []const u8, dst: []u8, write_lit_entropy: bool, write_seq_entropy: bool, lit_entropy_written: *bool, seq_entropy_written: *bool, last_block: u32) Error!usize {
    var op: usize = block_header_size;
    {
        const c_lit_size = try compressLiterals(&next.huf.table, meta, lits, dst[op..], write_lit_entropy, lit_entropy_written);
        if (c_lit_size == 0) return 0;
        op += c_lit_size;
    }
    {
        const c_seq_size = try compressSequences(next.fse, meta, sub, dst[op..], write_seq_entropy, seq_entropy_written);
        if (c_seq_size == 0) return 0;
        op += c_seq_size;
    }
    // Write block header
    const c_size: u32 = @intCast(op - block_header_size);
    const header: u32 = last_block + (bt_compressed << 1) + (c_size << 3);
    dst[0] = @truncate(header);
    dst[1] = @truncate(header >> 8);
    dst[2] = @truncate(header >> 16);
    return op;
}

/// The sequences `sp..sp+count` of `ss` as a store of their own, sharing
/// its memory (the codes were computed for the whole block).
fn subStore(ss: *const SeqStore, sp: usize, count: usize) SeqStore {
    var r = ss.*;
    r.seqs = ss.seqs[sp..];
    r.ll_code = ss.ll_code[sp..];
    r.ml_code = ss.ml_code[sp..];
    r.of_code = ss.of_code[sp..];
    r.n_seq = count;
    return r;
}

/// `ZSTD_compressSubBlock_multi`.
fn compressMulti(ss: *const SeqStore, prev: State, next: State, meta: *const Metadata, target_c_block_size_in: u32, dst: []u8, src: []const u8, last_block: u32) Error!usize {
    const n_seqs = ss.n_seq;
    const n_literals = ss.n_lit;
    var sp: usize = 0;
    var lp: usize = 0;
    var ip: usize = 0;
    var op: usize = 0;
    const target_c_block_size: usize = @max(target_c_block_size_min, target_c_block_size_in);
    var write_lit_entropy = meta.huf.h_type == .compressed;
    var write_seq_entropy = true;

    if (n_seqs > 0) {
        const ebs = estimateSubBlockSize(ss.lits[0..n_literals], ss, n_seqs, next, meta, write_lit_entropy, write_seq_entropy);
        // quick estimation
        const avg_lit_cost: usize = if (n_literals != 0) (ebs.lit * bytescale) / n_literals else bytescale;
        const avg_seq_cost: usize = ((ebs.block - ebs.lit) * bytescale) / n_seqs;
        const nb_sub_blocks: usize = @max((ebs.block + (target_c_block_size / 2)) / target_c_block_size, 1);
        const avg_block_budget: usize = (ebs.block * bytescale) / nb_sub_blocks;
        const block_budget_supp: usize = 0;
        if (ebs.block > src.len) return 0;

        // compress and write sub-blocks
        var n: usize = 0;
        while (n < nb_sub_blocks - 1) : (n += 1) {
            // determine nb of sequences for current sub-block + nbLiterals from next sequence
            const seq_count = sizeBlockSequences(ss.seqs[sp..n_seqs], avg_block_budget + block_budget_supp, avg_lit_cost, avg_seq_cost, n == 0);
            // if reached last sequence : break to last sub-block (simplification)
            if (sp + seq_count == n_seqs) break;
            // compress sub-block
            var lit_entropy_written = false;
            var seq_entropy_written = false;
            const lit_size = countLiterals(ss, sp, seq_count);
            const dsize = decompressedSize(ss, sp, seq_count, lit_size);
            const v = subStore(ss, sp, seq_count);
            const c_size = try compressSubBlock(next, meta, &v, ss.lits[lp..][0..lit_size], dst[op..], write_lit_entropy, write_seq_entropy, &lit_entropy_written, &seq_entropy_written, 0);
            // check compressibility, update state components
            if (c_size > 0 and c_size < dsize) {
                ip += dsize;
                lp += lit_size;
                op += c_size;
                if (lit_entropy_written) write_lit_entropy = false;
                if (seq_entropy_written) write_seq_entropy = false;
                sp += seq_count;
            }
        }
    }

    // write last block
    {
        var lit_entropy_written = false;
        var seq_entropy_written = false;
        const lit_size = n_literals - lp;
        const seq_count = n_seqs - sp;
        const dsize = decompressedSize(ss, sp, seq_count, lit_size);
        const v = subStore(ss, sp, seq_count);
        const c_size = try compressSubBlock(next, meta, &v, ss.lits[lp..][0..lit_size], dst[op..], write_lit_entropy, write_seq_entropy, &lit_entropy_written, &seq_entropy_written, last_block);
        // update pointers, the nb of literals borrowed from next sequence must be preserved
        if (c_size > 0 and c_size < dsize) {
            ip += dsize;
            lp += lit_size;
            op += c_size;
            if (lit_entropy_written) write_lit_entropy = false;
            if (seq_entropy_written) write_seq_entropy = false;
            sp += seq_count;
        }
    }

    if (write_lit_entropy) {
        // Literals entropy tables were not emitted: the next block cannot
        // repeat them.
        next.huf.* = prev.huf.*;
    }
    if (write_seq_entropy and needSequenceEntropyTables(meta)) {
        // If we haven't written our entropy tables, then we've violated our
        // contract and must emit an uncompressed block.
        return 0;
    }

    if (ip < src.len) {
        // some data left: last part of the block sent uncompressed
        const r_size = src.len - ip;
        if (dst.len - op < block_header_size + r_size) return error.DstSizeTooSmall;
        const header: u32 = last_block + (bt_raw << 1) + (@as(u32, @intCast(r_size)) << 3);
        dst[op] = @truncate(header);
        dst[op + 1] = @truncate(header >> 8);
        dst[op + 2] = @truncate(header >> 16);
        @memcpy(dst[op + block_header_size ..][0..r_size], src[ip..]);
        op += block_header_size + r_size;
        if (sp < n_seqs) {
            // some sequences left: update repcodes and next block state for
            // the sequences that were emitted
            var rep = prev.rep.*;
            for (0..sp) |i| blocksplit.updateRep(&rep, ss.seqs[i].off_base, sequenceLength(ss, i).lit == 0);
            next.rep.* = rep;
        }
    }
    return op;
}
