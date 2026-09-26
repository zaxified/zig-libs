// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! The sequence-level API (port of lib/compress/zstd_compress.c, v1.5.7):
//! compressing a caller's sequences (`ZSTD_compressSequences`,
//! `ZSTD_compressSequencesAndLiterals`), collecting the sequences a
//! compression finds (`ZSTD_generateSequences`), and taking a block's
//! sequences from an external producer (`ZSTD_registerSequenceProducer`,
//! in `ZSTD_buildSeqStore`).
//!
//! libzstd's arithmetic on the caller's lengths and offsets is unsigned and
//! wraps; so does this port's, so that sequences libzstd accepts without
//! validation give the same bytes here even when they are not a valid
//! parse. Where libzstd's behaviour is undefined instead (a read outside
//! the input, an offset whose code is `highbit32(0)`), the sequences are
//! refused as `error.ExternalSequencesInvalid` (see SPEC.md, *Sequences*).

const std = @import("std");
const sequences = @import("sequences.zig");
const params = @import("params.zig");
const SeqStore = sequences.SeqStore;

/// `ZSTD_Sequence`: one match and the literals before it, as the sequence
/// API takes and returns them. A sequence with `offset` and `match_length`
/// 0 is a block delimiter, whose `lit_length` literals end the block.
/// Laid out as libzstd's (four `unsigned`), so a C caller's array can be
/// passed as it is.
pub const Sequence = extern struct {
    /// The match's distance back (not an offset code).
    offset: u32,
    lit_length: u32,
    match_length: u32,
    /// Which repeat offset `offset` is (1..3), 0 for none: set by
    /// `generateSequences`, ignored when compressing (as in libzstd 1.5.7).
    rep: u32 = 0,

    pub fn isDelimiter(s: Sequence) bool {
        return s.offset == 0 and s.match_length == 0;
    }
};

pub const BlockDelimiters = params.BlockDelimiters;

/// A block-level sequence producer (`ZSTD_sequenceProducer_F` and its
/// state, `ZSTD_registerSequenceProducer`): called for each block of 7
/// bytes or more in place of the level's match finder. It writes at most
/// `out.len` sequences describing `src` -- the block only, with offsets
/// within it; the last may be a delimiter holding the block's last literals
/// (one is appended when it is missing) -- and returns their number, or
/// fails. `dict` is always empty and `level` / `window_size` are the
/// frame's, as libzstd passes them. A function pointer and a context, as
/// in libzstd, rather than a comptime interface: the producer is chosen at
/// run time and the contexts (`Compressor`, `Stream`) are not generic.
pub const SequenceProducer = struct {
    context: ?*anyopaque,
    produce: *const fn (context: ?*anyopaque, out: []Sequence, src: []const u8, dict: []const u8, level: i32, window_size: usize) ProduceError!usize,

    /// `ZSTD_SEQUENCE_PRODUCER_ERROR`. A count above `out.len` counts as
    /// one too.
    pub const ProduceError = error{SequenceProducerFailed};
};

/// What taking external sequences into a block can fail with.
pub const Error = error{
    /// `externalSequences_invalid`: sequences that do not describe the
    /// input, do not fit the block, lack a delimiter, or fail validation.
    ExternalSequencesInvalid,
    /// `sequenceProducer_failed`: the producer failed and there is no
    /// fallback; or, collecting sequences, a block too small to compress.
    SequenceProducerFailed,
    /// `parameter_combination_unsupported`: a producer with long-distance
    /// matching (libzstd does not implement the combination).
    ParameterCombinationUnsupported,
    /// `dstSize_tooSmall`: no room for the collected sequences.
    DstSizeTooSmall,
};

/// `ZSTD_MINMATCH_MIN`, `ZSTD_BLOCKSIZE_MAX_MIN`.
const minmatch_min = 3;
const block_size_max_min = 1 << 10;
const rep_num = sequences.rep_num;
/// `MINMATCH`: the stored match length is relative to it.
const minmatch = 3;

/// `ZSTD_sequenceBound`: the most sequences, delimiters included, a
/// compression of `src_size` bytes can yield.
pub fn sequenceBound(src_size: usize) usize {
    const max_nb_seq = src_size / minmatch_min + 1;
    const max_nb_delims = src_size / block_size_max_min + 1;
    return max_nb_seq + max_nb_delims;
}

/// `ZSTD_mergeBlockDelimiters`: drop the delimiters, adding their literals
/// to the next sequence's (the last delimiter's are dropped: they are the
/// input's last literals), for `BlockDelimiters.none`. Returns how many
/// sequences are left at the front of `seqs`.
pub fn mergeBlockDelimiters(seqs: []Sequence) usize {
    var out: usize = 0;
    for (0..seqs.len) |in| {
        if (seqs[in].offset == 0 and seqs[in].match_length == 0) {
            if (in != seqs.len - 1) seqs[in + 1].lit_length +%= seqs[in].lit_length;
        } else {
            seqs[out] = seqs[in];
            out += 1;
        }
    }
    return out;
}

/// The context's settings for external sequences (`appliedParams`).
pub const Params = struct {
    /// `ZSTD_c_validateSequences`.
    validate: bool = false,
    /// `ZSTD_c_repcodeResolution`, resolved (`ZSTD_resolveExternalRepcodeSearch`).
    repcode_resolution: bool = false,
    /// `ZSTD_c_blockDelimiters`.
    block_delimiters: BlockDelimiters = .none,
    /// `ZSTD_c_enableSeqProducerFallback`.
    fallback: bool = false,
    /// `ZSTD_hasExtSeqProd`.
    producer: ?SequenceProducer = null,
    min_match: u32 = 3,
    window_log: u32 = 10,
    /// The dictionary content the offsets may reach into: a `CDict`'s
    /// (loaded or referenced), never a prefix's (libzstd clears the prefix
    /// before the sequences are read).
    dict_size: usize = 0,
    /// `seqStore.maxNbSeq` (`ZSTD_maxNbSeq`).
    max_nb_seq: usize = 0,
    /// The frame's level, for the producer (`appliedParams.compressionLevel`).
    level: i32 = 3,
};

/// `ZSTD_resolveExternalRepcodeSearch`: `.auto` searches from level 10 on.
pub fn resolveRepcodeResolution(on: params.Switch, level: i32) bool {
    return switch (on) {
        .enable => true,
        .disable => false,
        .auto => level >= 10,
    };
}

/// `ZSTD_SequencePosition`.
pub const Position = struct {
    /// Index in the sequences.
    idx: u32 = 0,
    /// Bytes of `seqs[idx]` already consumed (no-delimiter mode).
    pos_in_sequence: u32 = 0,
    /// Bytes of input consumed so far, for validation.
    pos_in_src: usize = 0,
};

/// `ZSTD_updateRep`, in libzstd's wrapping arithmetic.
fn updateRep(rep: *[3]u32, off_base: u32, ll0: bool) void {
    if (off_base > rep_num) { // OFFBASE_IS_OFFSET
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - rep_num;
    } else {
        const rep_code = off_base -% 1 +% @intFromBool(ll0);
        if (rep_code > 0) {
            const current = if (rep_code == rep_num) rep[0] -% 1 else rep[rep_code];
            if (rep_code >= 2) rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = current;
        }
    }
}

/// `ZSTD_finalizeOffBase`: the offset code for a raw offset, a repcode
/// where one of the history matches.
fn finalizeOffBase(raw: u32, rep: *const [3]u32, ll0: bool) u32 {
    var off_base = raw +% rep_num; // OFFSET_TO_OFFBASE
    if (!ll0 and raw == rep[0]) {
        off_base = 1; // REPCODE1_TO_OFFBASE
    } else if (raw == rep[1]) {
        off_base = 2 - @as(u32, @intFromBool(ll0));
    } else if (raw == rep[2]) {
        off_base = 3 - @as(u32, @intFromBool(ll0));
    } else if (ll0 and raw == rep[0] -% 1) {
        off_base = 3; // REPCODE3_TO_OFFBASE
    }
    return off_base;
}

/// `ZSTD_validateSequence`.
fn validateSequence(off_base: u32, match_length: u32, p: *const Params, pos_in_src: usize) Error!void {
    const window_size: usize = @as(usize, 1) << @intCast(p.window_log);
    // posInSrc represents the amount of data the decoder would decode up
    // to this point. As long as the amount of data decoded is less than or
    // equal to window size, offsets may be larger than the total length of
    // output decoded in order to reference the dict, even larger than
    // window size. After output surpasses windowSize, we're limited to
    // windowSize offsets again.
    const offset_bound: usize = if (pos_in_src > window_size) window_size else pos_in_src + p.dict_size;
    const lower_bound: u32 = if (p.min_match == 3 or p.producer != null) 3 else 4;
    if (off_base > offset_bound + rep_num) return error.ExternalSequencesInvalid; // Offset too large!
    if (match_length < lower_bound) return error.ExternalSequencesInvalid; // Matchlength too small for the minMatch
}

/// `ZSTD_storeSeqOnly` as libzstd's release build runs it: no assertion,
/// the length stored minus `MINMATCH` in wrapping arithmetic, and a second
/// long length replacing the first.
fn storeSeqOnly(ss: *SeqStore, lit_length: usize, off_base: u32, match_length: usize) Error!void {
    // offBase 0 has no offset code (ZSTD_highbit32(0) is undefined in libzstd)
    if (off_base == 0) return error.ExternalSequencesInvalid;
    if (lit_length > 0xFFFF) {
        ss.long_length_type = .literal_length;
        ss.long_length_pos = @intCast(ss.n_seq);
    }
    const ml_base = match_length -% minmatch;
    if (ml_base > 0xFFFF) {
        ss.long_length_type = .match_length;
        ss.long_length_pos = @intCast(ss.n_seq);
    }
    ss.seqs[ss.n_seq] = .{ .off_base = off_base, .lit_length = @truncate(lit_length), .ml_base = @truncate(ml_base) };
    ss.n_seq += 1;
}

/// `ZSTD_storeSeq`: the literals `lits`, then the sequence.
fn storeSeq(ss: *SeqStore, lits: []const u8, off_base: u32, match_length: usize) Error!void {
    try storeSeqOnly(ss, lits.len, off_base, match_length);
    @memcpy(ss.lits[ss.n_lit..][0..lits.len], lits);
    ss.n_lit += lits.len;
}

/// The part of the block state a sequence copier reads and writes.
pub const Reps = struct {
    prev: *const [3]u32,
    next: *[3]u32,
};

/// `ZSTD_transferSequences_wBlockDelim`: store `in[pos.idx..]` up to the
/// next block delimiter, which must end exactly at the end of `block`.
/// Returns `block.len`.
pub fn transferWithBlockDelim(ss: *SeqStore, reps: Reps, p: *const Params, pos: *Position, in: []const Sequence, block: []const u8, repcode_resolution: bool) Error!usize {
    var idx: usize = pos.idx;
    const start_idx = idx;
    var ip: usize = 0;
    var rep = reps.prev.*;
    while (idx < in.len and (in[idx].match_length != 0 or in[idx].offset != 0)) : (idx += 1) {
        const lit_length = in[idx].lit_length;
        const match_length = in[idx].match_length;
        var off_base: u32 = undefined;
        if (!repcode_resolution) {
            off_base = in[idx].offset +% rep_num; // OFFSET_TO_OFFBASE
        } else {
            const ll0 = lit_length == 0;
            off_base = finalizeOffBase(in[idx].offset, &rep, ll0);
            updateRep(&rep, off_base, ll0);
        }
        if (p.validate) {
            pos.pos_in_src += @as(usize, lit_length) + match_length;
            try validateSequence(off_base, match_length, p, pos.pos_in_src);
        }
        // Not enough memory allocated. Try adjusting ZSTD_c_minMatch.
        if (idx - pos.idx >= p.max_nb_seq) return error.ExternalSequencesInvalid;
        // (libzstd reads past the block here; the sum up to the delimiter
        // is the block size in every caller, so this does not fire)
        if (@as(u64, lit_length) + match_length > block.len - ip) return error.ExternalSequencesInvalid;
        try storeSeq(ss, block[ip..][0..lit_length], off_base, match_length);
        ip += @as(usize, match_length) + lit_length;
    }
    if (idx == in.len) return error.ExternalSequencesInvalid; // Block delimiter not found.

    // If we skipped repcode search while parsing, we need to update
    // repcodes now
    if (!repcode_resolution and idx != start_idx) {
        const last = idx - 1; // index of last non-block-delimiter sequence
        if (last >= start_idx + 2) {
            rep[2] = in[last - 2].offset;
            rep[1] = in[last - 1].offset;
            rep[0] = in[last].offset;
        } else if (last == start_idx + 1) {
            rep[2] = rep[0];
            rep[1] = in[last - 1].offset;
            rep[0] = in[last].offset;
        } else {
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = in[last].offset;
        }
    }
    reps.next.* = rep;

    const last_ll = in[idx].lit_length;
    if (last_ll != 0) {
        if (last_ll > block.len - ip) return error.ExternalSequencesInvalid; // (as above)
        ss.storeLastLiterals(block[ip..][0..last_ll]);
        ip += last_ll;
        pos.pos_in_src += last_ll;
    }
    if (ip != block.len) return error.ExternalSequencesInvalid; // Blocksize doesn't agree with block delimiter!
    pos.idx = @intCast(idx + 1);
    return block.len;
}

/// `ZSTD_transferSequences_noDelim`: store sequences from `pos` on
/// covering at most `block`, splitting the last one where the block ends
/// (a match only when it is longer than the block and both halves keep
/// `minMatch`; otherwise the block ends before it). Returns how many bytes
/// of `block` the stored sequences cover.
pub fn transferNoDelim(ss: *SeqStore, reps: Reps, p: *const Params, pos: *Position, in: []const Sequence, block: []const u8) Error!usize {
    var idx: usize = pos.idx;
    var start_pos: u32 = pos.pos_in_sequence;
    var end_pos: u32 = pos.pos_in_sequence +% @as(u32, @intCast(block.len));
    var ip: usize = 0;
    var iend: usize = block.len; // May be adjusted if we decide to process fewer than blockSize bytes
    var rep = reps.prev.*;
    var bytes_adjustment: u32 = 0;
    var final_match_split = false;
    const min_match = p.min_match;

    while (end_pos != 0 and idx < in.len and !final_match_split) {
        const curr = in[idx];
        var lit_length = curr.lit_length;
        var match_length = curr.match_length;
        const raw_offset = curr.offset;
        const curr_len = curr.lit_length +% curr.match_length;

        // Modify the sequence depending on where endPosInSequence lies
        if (end_pos >= curr_len) {
            if (start_pos >= lit_length) {
                start_pos -%= lit_length;
                lit_length = 0;
                match_length -%= start_pos;
            } else {
                lit_length -%= start_pos;
            }
            // Move to the next sequence
            end_pos -%= curr_len;
            start_pos = 0;
        } else {
            // This is the final (partial) sequence we're adding from inSeqs,
            // and endPosInSequence does not reach the end of the match. So,
            // we have to split the sequence
            if (end_pos > lit_length) {
                lit_length = if (start_pos >= lit_length) 0 else lit_length - start_pos;
                var first_half = end_pos -% start_pos -% lit_length;
                if (match_length > block.len and first_half >= min_match) {
                    // Only ever split the match if it is larger than the block size
                    const second_half = curr.match_length +% curr.lit_length -% end_pos;
                    if (second_half < min_match) {
                        // Move the endPosInSequence backward so that it
                        // creates match of minMatch length
                        end_pos -%= min_match - second_half;
                        bytes_adjustment = min_match - second_half;
                        first_half -%= bytes_adjustment;
                    }
                    match_length = first_half;
                    // Flag that we split the last match - after storing the
                    // sequence, exit the loop, but keep the value of
                    // endPosInSequence
                    final_match_split = true;
                } else {
                    // Move the position in sequence backwards so that we
                    // don't split match, and break to store the last
                    // literals.
                    bytes_adjustment = end_pos -% curr.lit_length;
                    end_pos = curr.lit_length;
                    break;
                }
            } else {
                // This sequence ends inside the literals, break to store the
                // last literals
                break;
            }
        }
        // Check if this offset can be represented with a repcode
        const ll0 = lit_length == 0;
        const off_base = finalizeOffBase(raw_offset, &rep, ll0);
        updateRep(&rep, off_base, ll0);

        if (p.validate) {
            pos.pos_in_src += @as(usize, lit_length) + match_length;
            try validateSequence(off_base, match_length, p, pos.pos_in_src);
        }
        // Not enough memory allocated. Try adjusting ZSTD_c_minMatch.
        if (idx - pos.idx >= p.max_nb_seq) return error.ExternalSequencesInvalid;
        // (libzstd reads past the block on lengths wrapped by the cuts
        // above; not reachable from lengths that sum within 2^32)
        if (@as(u64, lit_length) + match_length > block.len - ip) return error.ExternalSequencesInvalid;
        try storeSeq(ss, block[ip..][0..lit_length], off_base, match_length);
        ip += @as(usize, match_length) + lit_length;
        if (!final_match_split) idx += 1; // Next Sequence
    }
    pos.idx = @intCast(idx);
    pos.pos_in_sequence = end_pos;
    reps.next.* = rep;

    if (bytes_adjustment > iend - ip) return error.ExternalSequencesInvalid; // (libzstd: ip > iend, undefined)
    iend -= bytes_adjustment;
    if (ip != iend) {
        // Store any last literals
        ss.storeLastLiterals(block[ip..iend]);
        pos.pos_in_src += iend - ip;
    }
    return iend;
}

/// `blockSize_explicitDelimiter`: the size of the block the sequences at
/// `pos` describe, up to and including the next delimiter.
fn blockSizeExplicitDelimiter(in: []const Sequence, pos: Position) Error!usize {
    var end = false;
    var block_size: usize = 0;
    var spos: usize = pos.idx;
    while (spos < in.len) {
        end = in[spos].offset == 0;
        block_size += @as(usize, in[spos].lit_length) + in[spos].match_length;
        if (end) {
            // delimiter format error : both matchlength and offset must be == 0
            if (in[spos].match_length != 0) return error.ExternalSequencesInvalid;
            break;
        }
        spos += 1;
    }
    // Reached end of sequences without finding a block delimiter
    if (!end) return error.ExternalSequencesInvalid;
    return block_size;
}

/// `determine_blockSize`.
pub fn determineBlockSize(mode: BlockDelimiters, block_size_max: usize, remaining: usize, in: []const Sequence, pos: Position) Error!usize {
    if (mode == .none) return @min(remaining, block_size_max); // more a "target" block size
    const explicit = try blockSizeExplicitDelimiter(in, pos);
    if (explicit > block_size_max) return error.ExternalSequencesInvalid; // sequences incorrectly define a too large block
    if (explicit > remaining) return error.ExternalSequencesInvalid; // sequences define a frame longer than source
    return explicit;
}

/// `ZSTD_maybeRLE`: a block with this few sequences and literals may be
/// one repeated byte.
pub fn maybeRle(ss: *const SeqStore) bool {
    return ss.n_seq < 4 and ss.n_lit < 10;
}

/// `ZSTD_postProcessSequenceProducerResult`: the producer's count checked,
/// and a delimiter appended when the last sequence is not one. Returns the
/// number of sequences.
pub fn postProcessProducerResult(out: []Sequence, n_ext: usize, src_size: usize) Error!usize {
    // External sequence producer returned error code
    if (n_ext > out.len) return error.SequenceProducerFailed;
    // Got zero sequences from external sequence producer for a non-empty src buffer!
    if (n_ext == 0 and src_size > 0) return error.SequenceProducerFailed;
    if (src_size == 0) {
        out[0] = .{ .offset = 0, .lit_length = 0, .match_length = 0, .rep = 0 };
        return 1;
    }
    const last = out[n_ext - 1];
    // We can return early if lastSeq is already a block delimiter.
    if (last.offset == 0 and last.match_length == 0) return n_ext;
    // nbExternalSeqs == outSeqsCapacity but lastSeq is not a block delimiter!
    if (n_ext == out.len) return error.SequenceProducerFailed;
    // lastSeq is not a block delimiter, so we need to append one.
    out[n_ext] = .{ .offset = 0, .lit_length = 0, .match_length = 0, .rep = 0 };
    return n_ext + 1;
}

/// `ZSTD_fastSequenceLengthSum`: every literal and match length, past the
/// first delimiter too.
pub fn fastSequenceLengthSum(seqs: []const Sequence) usize {
    var lit_sum: usize = 0;
    var match_sum: usize = 0;
    for (seqs) |s| {
        lit_sum += s.lit_length;
        match_sum += s.match_length;
    }
    return lit_sum + match_sum;
}

/// The external-producer branch of `ZSTD_buildSeqStore`: the producer's
/// sequences for `block` stored, or -- when it fails and the fallback is
/// on -- false, for the level's match finder to run instead.
pub fn produceBlock(ss: *SeqStore, reps: Reps, p: *const Params, ext: []Sequence, block: []const u8) Error!bool {
    const prod = p.producer.?;
    const window_size: usize = @as(usize, 1) << @intCast(p.window_log);
    const produced: Error!usize = if (prod.produce(prod.context, ext, block, &.{}, p.level, window_size)) |n|
        postProcessProducerResult(ext, n, block.len)
    else |err| switch (err) {
        error.SequenceProducerFailed => error.SequenceProducerFailed,
    };
    // Return early if there is no error, since we don't need to worry
    // about last literals
    if (produced) |n| {
        var pos: Position = .{};
        // External sequences imply too large a block!
        if (fastSequenceLengthSum(ext[0..n]) > block.len) return error.ExternalSequencesInvalid;
        _ = try transferWithBlockDelim(ss, reps, p, &pos, ext[0..n], block, p.repcode_resolution);
        return true;
    } else |err| {
        // Propagate the error if fallback is disabled
        if (!p.fallback) return err;
        return false; // Fallback to software matchfinder
    }
}

/// `SeqCollector`: where `ZSTD_generateSequences` gathers each block's
/// sequences.
pub const Collector = struct {
    seqs: []Sequence,
    idx: usize = 0,

    /// `ZSTD_copyBlockSequences`: the block's sequences with raw offsets
    /// (repcodes resolved against `prev_rep`, the history before the
    /// block) and a delimiter holding its last literals. The delimiter's
    /// `rep` is left as the caller's buffer had it, as libzstd leaves it.
    pub fn copyBlockSequences(col: *Collector, ss: *const SeqStore, prev_rep: [3]u32) Error!void {
        const n_in = ss.n_seq;
        const n_out = n_in + 1;
        // Not enough space to copy sequences
        if (n_out > col.seqs.len - col.idx) return error.DstSizeTooSmall;
        const out = col.seqs[col.idx..];
        var rep = prev_rep;
        var n_out_lits: usize = 0;
        for (ss.seqs[0..n_in], 0..) |sq, i| {
            out[i].lit_length = sq.lit_length;
            out[i].match_length = @as(u32, sq.ml_base) + minmatch;
            out[i].rep = 0;
            // Handle the possible single length >= 64K. There can only be
            // one because we add MINMATCH to every match length, and blocks
            // are at most 128K.
            if (i == ss.long_length_pos) {
                switch (ss.long_length_type) {
                    .literal_length => out[i].lit_length += 0x10000,
                    .match_length => out[i].match_length += 0x10000,
                    .none => {},
                }
            }
            // Determine the raw offset given the offBase, which may be a
            // repcode.
            var raw: u32 = undefined;
            if (sq.off_base <= rep_num) { // OFFBASE_IS_REPCODE
                const repcode = sq.off_base;
                out[i].rep = repcode;
                if (out[i].lit_length != 0) {
                    raw = rep[repcode - 1];
                } else if (repcode == 3) {
                    raw = rep[0] -% 1;
                } else {
                    raw = rep[repcode];
                }
            } else raw = sq.off_base - rep_num;
            out[i].offset = raw;
            // Update repcode history for the sequence
            updateRep(&rep, sq.off_base, sq.lit_length == 0);
            n_out_lits += out[i].lit_length;
        }
        // Insert last literals (if any exist) in the block as a sequence
        // with ml == off == 0. If there are no last literals, then we'll
        // emit (of: 0, ml: 0, ll: 0), which is a marker for the block
        // boundary, according to the API.
        std.debug.assert(ss.n_lit >= n_out_lits);
        out[n_in].lit_length = @intCast(ss.n_lit - n_out_lits);
        out[n_in].match_length = 0;
        out[n_in].offset = 0;
        col.idx += n_out;
    }
};

/// `BlockSummary` / `ZSTD_get1BlockSummary`: the sequences of the next
/// block (up to a match length of 0, which ends it), its size and its
/// literals.
pub const BlockSummary = struct { n_seq: usize, block_size: u64, lit_size: u64 };

pub fn get1BlockSummary(seqs: []const Sequence) Error!BlockSummary {
    var total_match: u64 = 0;
    var lit_size: u64 = 0;
    for (seqs, 0..) |s, n| {
        total_match += s.match_length;
        lit_size += s.lit_length;
        if (s.match_length == 0) return .{ .n_seq = n + 1, .block_size = lit_size + total_match, .lit_size = lit_size };
    }
    return error.ExternalSequencesInvalid;
}

/// `ZSTD_convertBlockSequences`: one block's sequences (the last is its
/// delimiter) into the store, without their literals.
pub fn convertBlockSequences(ss: *SeqStore, reps: Reps, p: *const Params, in: []const Sequence, repcode_resolution: bool) Error!void {
    // Not enough memory allocated. Try adjusting ZSTD_c_minMatch.
    if (in.len >= p.max_nb_seq) return error.ExternalSequencesInvalid;
    var rep = reps.prev.*;
    const n = in.len - 1;
    // Convert Sequences from public format to internal format
    if (!repcode_resolution) {
        // convertSequences_noRepcodes: a second long length wins over the
        // first, as in a release build (an assertion in a debug one)
        var long_len: usize = 0;
        for (in[0..n], 0..) |s, i| {
            const off_base = s.offset +% rep_num;
            if (off_base == 0) return error.ExternalSequencesInvalid; // (see storeSeqOnly)
            ss.seqs[i] = .{ .off_base = off_base, .lit_length = @truncate(s.lit_length), .ml_base = @truncate(s.match_length -% minmatch) };
            // check for long length > 65535
            if (s.match_length > 65535 + minmatch) long_len = i + 1;
            if (s.lit_length > 65535) long_len = i + n + 1;
        }
        ss.n_seq = n;
        if (long_len != 0) {
            if (long_len <= n) {
                ss.long_length_type = .match_length;
                ss.long_length_pos = @intCast(long_len - 1);
            } else {
                ss.long_length_type = .literal_length;
                ss.long_length_pos = @intCast(long_len - n - 1);
            }
        }
    } else {
        for (in[0..n]) |s| {
            const ll0 = s.lit_length == 0;
            const off_base = finalizeOffBase(s.offset, &rep, ll0);
            try storeSeqOnly(ss, s.lit_length, off_base, s.match_length);
            updateRep(&rep, off_base, ll0);
        }
    }
    // If we skipped repcode search while parsing, we need to update
    // repcodes now
    if (!repcode_resolution and in.len > 1) {
        if (in.len >= 4) {
            const last = in.len - 2; // index of last full sequence
            rep[2] = in[last - 2].offset;
            rep[1] = in[last - 1].offset;
            rep[0] = in[last].offset;
        } else if (in.len == 3) {
            rep[2] = rep[0];
            rep[1] = in[0].offset;
            rep[0] = in[1].offset;
        } else {
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = in[0].offset;
        }
    }
    reps.next.* = rep;
}

test "sequenceBound and mergeBlockDelimiters follow libzstd" {
    try std.testing.expectEqual(@as(usize, 1 + 1), sequenceBound(0));
    try std.testing.expectEqual(@as(usize, (131072 / 3 + 1) + (131072 / 1024 + 1)), sequenceBound(131072));
    var s = [_]Sequence{
        .{ .offset = 5, .lit_length = 2, .match_length = 4 },
        .{ .offset = 0, .lit_length = 3, .match_length = 0 },
        .{ .offset = 7, .lit_length = 1, .match_length = 5 },
        .{ .offset = 0, .lit_length = 9, .match_length = 0 },
    };
    const n = mergeBlockDelimiters(&s);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u32, 4), s[1].lit_length);
}
