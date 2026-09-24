// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Post-block splitter (port of libzstd lib/compress/zstd_compress.c,
//! v1.5.7: `ZSTD_deriveBlockSplits` and the size estimates behind it).
//!
//! libzstd enables it for `btopt` and up with a window of at least 128 KB.
//! After a block's sequences are found, it halves the sequence range while
//! the estimated sizes of the two halves, each with its own entropy tables,
//! beat the estimate of the whole; every half becomes a block of its own.
//! The estimates build real tables into the next block state, which is
//! scratch at that point: compressing a block overwrites all of it.

const std = @import("std");
const huf = @import("huf.zig");
const hist = @import("hist.zig");
const literals = @import("literals.zig");
const sequences = @import("sequences.zig");
const SeqStore = sequences.SeqStore;

/// `ZSTD_MAX_NB_BLOCK_SPLITS`.
pub const max_nb_block_splits = 196;
/// libzstd checks the split count only on entry to each halving, so nested
/// halvings still in flight can push it past 196 and write past its
/// `partitions[196]` (the terminator lands there too, and is read back).
/// The recursion is at most ~8 deep (43690 sequences / 300), so this slack
/// holds every index libzstd can write.
pub const partitions_len = max_nb_block_splits + 64;
/// `MIN_SEQUENCES_BLOCK_SPLITTING`.
const min_sequences_block_splitting = 300;
/// `COMPRESS_LITERALS_SIZE_MIN`.
const compress_literals_size_min = 63;
/// `ZSTD_MAX_HUF_HEADER_SIZE`.
pub const max_huf_header_size = 128;
const block_header_size = 3;

/// libzstd's error codes, which the literal estimate carries through
/// unsigned arithmetic before anyone checks them (`ZSTD_isError`).
const error_generic: usize = 0 -% @as(usize, 1);
const error_dst_size_too_small: usize = 0 -% @as(usize, 70);
pub fn isError(code: usize) bool {
    return code > 0 -% @as(usize, 120); // ZSTD_error_maxCode
}

/// `ZSTD_countSeqStoreLiteralsBytes`.
pub fn countLiteralsBytes(ss: *const SeqStore) usize {
    var n: usize = 0;
    for (ss.seqs[0..ss.n_seq], 0..) |sq, i| {
        n += sq.lit_length;
        if (i == ss.long_length_pos and ss.long_length_type == .literal_length) n += 0x10000;
    }
    return n;
}

/// `ZSTD_countSeqStoreMatchBytes`.
pub fn countMatchBytes(ss: *const SeqStore) usize {
    var n: usize = 0;
    for (ss.seqs[0..ss.n_seq], 0..) |sq, i| {
        n += @as(usize, sq.ml_base) + sequences.min_match;
        if (i == ss.long_length_pos and ss.long_length_type == .match_length) n += 0x10000;
    }
    return n;
}

/// `ZSTD_deriveSeqStoreChunk`: a view of sequences `start..end` of `orig`,
/// sharing its memory. The code slices run on past `end` as libzstd's
/// pointers do: a long length at exactly `end` is kept (`> endIdx`, not
/// `>=`) and its code lands on the next chunk's first slot, which that
/// chunk recomputes before reading.
pub fn deriveChunk(orig: *const SeqStore, start: usize, end: usize) SeqStore {
    var r = orig.*;
    var lit_start: usize = 0;
    if (start > 0) {
        r.n_seq = start;
        lit_start = countLiteralsBytes(&r);
    }
    if (orig.long_length_type != .none) {
        if (orig.long_length_pos < start or orig.long_length_pos > end) {
            r.long_length_type = .none;
        } else {
            r.long_length_pos -= @intCast(start);
        }
    }
    r.seqs = orig.seqs[start..];
    r.n_seq = end - start;
    r.lits = orig.lits[lit_start..];
    r.n_lit = if (end == orig.n_seq) orig.n_lit - lit_start else countLiteralsBytes(&r);
    r.ll_code = orig.ll_code[start..];
    r.ml_code = orig.ml_code[start..];
    r.of_code = orig.of_code[start..];
    return r;
}

/// `ZSTD_seqStore_resolveOffCodes`: when an earlier partition was emitted
/// raw or RLE, the decoder's offset history (`d_rep`) is not the one the
/// match finder assumed (`c_rep`); rewrite repcodes that now mean a
/// different offset as full offsets.
pub fn resolveOffCodes(d_rep: *[3]u32, c_rep: *[3]u32, ss: *SeqStore) void {
    const n: u32 = @intCast(ss.n_seq);
    const long_lit_len_idx: u32 = if (ss.long_length_type == .literal_length) ss.long_length_pos else n;
    for (ss.seqs[0..n], 0..) |*sq, idx| {
        const ll0 = sq.lit_length == 0 and idx != long_lit_len_idx;
        const off_base = sq.off_base;
        std.debug.assert(off_base > 0);
        if (off_base <= sequences.rep_num) {
            const d_raw = resolveRepcode(d_rep, off_base, ll0);
            const c_raw = resolveRepcode(c_rep, off_base, ll0);
            // Adjust simulated decompression repcode history if we come
            // across a mismatch. Replace the repcode with the offset it
            // actually references, determined by the compression repcode
            // history.
            if (d_raw != c_raw) sq.off_base = c_raw + sequences.rep_num;
        }
        // Compression repcode history is always updated with values
        // directly from the unmodified seqStore. Decompression repcode
        // history may use modified seq->offset value taken from
        // compression repcode history.
        updateRep(d_rep, sq.off_base, ll0);
        updateRep(c_rep, off_base, ll0);
    }
}

/// `ZSTD_resolveRepcodeToRawOffset`.
fn resolveRepcode(rep: *const [3]u32, off_base: u32, ll0: bool) u32 {
    const adjusted = off_base - 1 + @intFromBool(ll0);
    if (adjusted == sequences.rep_num) return rep[0] - 1;
    return rep[adjusted];
}

/// `ZSTD_updateRep`.
pub fn updateRep(rep: *[3]u32, off_base: u32, ll0: bool) void {
    if (off_base > sequences.rep_num) {
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - sequences.rep_num;
        return;
    }
    const rep_code = off_base - 1 + @intFromBool(ll0);
    if (rep_code > 0) {
        const current = if (rep_code == sequences.rep_num) rep[0] - 1 else rep[rep_code];
        if (rep_code >= 2) rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = current;
    }
}

/// Entropy state of one block, as the estimates see it.
pub const Entropy = struct {
    huf: *literals.HufState,
    fse: *sequences.FseTables,
};

pub const HType = enum { basic, rle, compressed, repeat };

pub const HufMetadata = struct { h_type: HType, des_size: usize };

/// `ZSTD_buildBlockEntropyStats_literals`: the serialised
/// table goes to `des_buffer` (`hufDesBuffer`). Returns libzstd's size_t,
/// error codes included.
pub fn buildLiteralsStats(src: []const u8, prev: *const literals.HufState, next: *literals.HufState, disabled: bool, optimal_depth: bool, meta: *HufMetadata, des_buffer: *[max_huf_header_size]u8) usize {
    var repeat = prev.repeat;
    next.* = prev.*;
    meta.des_size = 0;
    if (disabled) { // set_basic - disabled
        meta.h_type = .basic;
        return 0;
    }
    const min_lit_size: usize = if (prev.repeat == .valid) 6 else compress_literals_size_min;
    if (src.len <= min_lit_size) { // set_basic - too small
        meta.h_type = .basic;
        return 0;
    }
    // Scan input and build symbol stats
    var counts: [huf.symbol_value_max + 1]u32 = undefined;
    var max_symbol: u32 = huf.symbol_value_max;
    const largest = hist.count(&counts, &max_symbol, src);
    if (largest == src.len) {
        meta.h_type = .rle;
        return 0;
    }
    if (largest <= (src.len >> 7) + 4) { // set_basic - no gain
        meta.h_type = .basic;
        return 0;
    }
    // Validate the previous Huffman table
    if (repeat == .check and !huf.validateCTable(&prev.table, &counts, max_symbol)) repeat = .none;

    // Build Huffman Tree
    next.table = .{};
    var huff_log = huf.optimalTableLog(literals.lit_huf_log, src.len, max_symbol, &counts, optimal_depth);
    huff_log = huf.buildCTable(&next.table, &counts, max_symbol, huff_log) catch return error_generic;

    // Build and write the CTable
    const new_c_size = huf.estimateCompressedSize(&next.table, &counts, max_symbol);
    const h_size: usize = huf.writeCTable(des_buffer, &next.table, max_symbol, huff_log) catch |err| switch (err) {
        error.Generic => error_generic,
        error.DstSizeTooSmall => error_dst_size_too_small,
    };
    // Check against repeating the previous CTable
    if (repeat != .none) {
        const old_c_size = huf.estimateCompressedSize(&prev.table, &counts, max_symbol);
        if (old_c_size < src.len and (old_c_size <= h_size +% new_c_size or h_size +% 12 >= src.len)) {
            next.* = prev.*;
            meta.h_type = .repeat;
            return 0;
        }
    }
    if (new_c_size +% h_size >= src.len) { // set_basic - no gains
        next.* = prev.*;
        meta.h_type = .basic;
        return 0;
    }
    meta.h_type = .compressed;
    next.repeat = .check;
    meta.des_size = h_size;
    return h_size;
}

/// `ZSTD_estimateBlockSize_literal`.
fn estimateLiterals(lits: []const u8, table: *const huf.CTable, meta: HufMetadata, write_entropy: bool) usize {
    const header_size: usize = 3 + @as(usize, @intFromBool(lits.len >= 1024)) + @intFromBool(lits.len >= 16 * 1024);
    const single_stream = lits.len < 256;
    switch (meta.h_type) {
        .basic => return lits.len,
        .rle => return 1,
        .compressed, .repeat => {
            var counts: [huf.symbol_value_max + 1]u32 = undefined;
            var max_symbol: u32 = huf.symbol_value_max;
            _ = hist.count(&counts, &max_symbol, lits);
            var estimate = huf.estimateCompressedSize(table, &counts, max_symbol);
            if (write_entropy) estimate += meta.des_size;
            if (!single_stream) estimate += 6; // multi-stream huffman uses 6-byte jump table
            return estimate + header_size;
        },
    }
}

/// `ZSTD_estimateBlockSize_symbolType`.
fn estimateSymbolType(kind: sequences.EncodingType, codes: []const u8, max_code: u32, ct: *const @import("fse.zig").CTable, additional_bits: ?[]const u8, default_norm: []const i16, default_norm_log: u32) usize {
    var counts: [sequences.max_ml + 1]u32 = undefined;
    var max = max_code;
    _ = hist.count(&counts, &max, codes);
    var bits: usize = switch (kind) {
        .basic => sequences.crossEntropyCost(default_norm, default_norm_log, &counts, max),
        .rle => 0,
        .compressed, .repeat => sequences.fseBitCost(ct, &counts, max),
    };
    if (bits == sequences.cost_error) return codes.len * 10;
    for (codes) |c| bits += if (additional_bits) |ab| ab[c] else c;
    return bits >> 3;
}

/// `ZSTD_buildEntropyStatisticsAndEstimateSubBlockSize`: build the tables
/// `ss` would get as a block of its own (into `next`) and estimate that
/// block's size. Null when libzstd's estimate fails.
pub fn estimateSubBlockSize(ss: *SeqStore, prev: Entropy, next: Entropy, cfg: Config) ?usize {
    const strategy = cfg.strategy;
    const lits = ss.lits[0..ss.n_lit];
    var huf_meta: HufMetadata = undefined;
    var des_buffer: [max_huf_header_size]u8 = undefined;
    const huf_size = buildLiteralsStats(lits, prev.huf, next.huf, cfg.disable_literal_compression, strategy >= 8, &huf_meta, &des_buffer);
    if (isError(huf_size)) return null;

    const n_seq = ss.n_seq;
    var stats: sequences.Stats = .{ .ll_type = .basic, .of_type = .basic, .ml_type = .basic, .size = 0, .last_count_size = 0 };
    if (n_seq != 0) {
        var tables: [2048]u8 = undefined; // ZSTD_MAX_FSE_HEADERS_SIZE is never approached
        stats = sequences.buildStatistics(ss, prev.fse, next.fse, &tables, strategy) catch return null;
    } else {
        // ZSTD_buildDummySequencesStatistics
        next.fse.ll_repeat = .none;
        next.fse.of_repeat = .none;
        next.fse.ml_repeat = .none;
    }

    const lit_size = estimateLiterals(lits, &next.huf.table, huf_meta, huf_meta.h_type == .compressed);
    var seq_size: usize = 1 + 1 + @as(usize, @intFromBool(n_seq >= 128)) + @intFromBool(n_seq >= sequences.long_nb_seq);
    seq_size += estimateSymbolType(stats.of_type, ss.of_code[0..n_seq], sequences.max_off, &next.fse.of, null, &sequences.of_default_norm, sequences.of_default_norm_log);
    seq_size += estimateSymbolType(stats.ll_type, ss.ll_code[0..n_seq], sequences.max_ll, &next.fse.ll, &sequences.ll_bits, &sequences.ll_default_norm, sequences.ll_default_norm_log);
    seq_size += estimateSymbolType(stats.ml_type, ss.ml_code[0..n_seq], sequences.max_ml, &next.fse.ml, &sequences.ml_bits, &sequences.ml_default_norm, sequences.ml_default_norm_log);
    seq_size += stats.size; // writeSeqEntropy is always set
    return seq_size + lit_size + block_header_size;
}

/// What the estimates take from the compression parameters.
pub const Config = struct {
    /// libzstd's numeric strategy.
    strategy: u32,
    /// `ZSTD_literalsCompressionIsDisabled`.
    disable_literal_compression: bool,
};

const Splits = struct {
    locations: *[partitions_len]u32,
    idx: usize = 0,
};

/// `ZSTD_deriveBlockSplitsHelper`.
fn deriveHelper(splits: *Splits, start: usize, end: usize, orig: *const SeqStore, prev: Entropy, next: Entropy, cfg: Config) void {
    const mid = (start + end) / 2;
    std.debug.assert(end >= start);
    if (end - start < min_sequences_block_splitting or splits.idx >= max_nb_block_splits) return;
    var full = deriveChunk(orig, start, end);
    var first = deriveChunk(orig, start, mid);
    var second = deriveChunk(orig, mid, end);
    const est_full = estimateSubBlockSize(&full, prev, next, cfg) orelse return;
    const est_first = estimateSubBlockSize(&first, prev, next, cfg) orelse return;
    const est_second = estimateSubBlockSize(&second, prev, next, cfg) orelse return;
    if (est_first + est_second < est_full) {
        deriveHelper(splits, start, mid, orig, prev, next, cfg);
        splits.locations[splits.idx] = @intCast(mid);
        splits.idx += 1;
        deriveHelper(splits, mid, end, orig, prev, next, cfg);
    }
}

/// `ZSTD_deriveBlockSplits`: fill `partitions` with the sequence indices to
/// split at, terminated by `n_seq`, and return how many splits there are.
pub fn deriveSplits(partitions: *[partitions_len]u32, orig: *const SeqStore, prev: Entropy, next: Entropy, cfg: Config) usize {
    const n_seq = orig.n_seq;
    if (n_seq <= 4) return 0; // too few sequences to split
    var splits: Splits = .{ .locations = partitions };
    deriveHelper(&splits, 0, n_seq, orig, prev, next, cfg);
    splits.locations[splits.idx] = @intCast(n_seq);
    return splits.idx;
}

test "a chunk view counts its own literals and keeps the long length" {
    var seqs = [_]sequences.SeqDef{
        .{ .off_base = 5, .lit_length = 2, .ml_base = 1 },
        .{ .off_base = 1, .lit_length = 3, .ml_base = 0 },
        .{ .off_base = 9, .lit_length = 1, .ml_base = 4 },
    };
    var lits: [20]u8 = undefined;
    var codes: [9]u8 = undefined;
    const ss: SeqStore = .{
        .seqs = &seqs,
        .n_seq = 3,
        .lits = &lits,
        .n_lit = 2 + 3 + 1 + 4, // 4 trailing literals
        .ll_code = codes[0..3],
        .ml_code = codes[3..6],
        .of_code = codes[6..9],
    };
    const mid = deriveChunk(&ss, 1, 2);
    try std.testing.expectEqual(@as(usize, 1), mid.n_seq);
    try std.testing.expectEqual(@as(usize, 3), mid.n_lit);
    try std.testing.expectEqual(@as(usize, 18), mid.lits.len);
    const last = deriveChunk(&ss, 2, 3);
    try std.testing.expectEqual(@as(usize, 1 + 4), last.n_lit); // the trailing literals ride on the last chunk
    try std.testing.expectEqual(@as(usize, 7), countMatchBytes(&last));
}

test "a repcode whose offset the decoder no longer has becomes a full offset" {
    var seqs = [_]sequences.SeqDef{.{ .off_base = 1, .lit_length = 4, .ml_base = 1 }};
    var lits: [8]u8 = undefined;
    var codes: [3]u8 = undefined;
    var ss: SeqStore = .{ .seqs = &seqs, .n_seq = 1, .lits = &lits, .n_lit = 4, .ll_code = codes[0..1], .ml_code = codes[1..2], .of_code = codes[2..3] };
    var d_rep = [3]u32{ 1, 4, 8 };
    var c_rep = [3]u32{ 77, 1, 4 };
    resolveOffCodes(&d_rep, &c_rep, &ss);
    try std.testing.expectEqual(@as(u32, 77 + sequences.rep_num), seqs[0].off_base);
    try std.testing.expectEqual(d_rep, c_rep);
}
