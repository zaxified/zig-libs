// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Long-distance matching (port of the no-dictionary paths of libzstd
//! lib/compress/zstd_ldm.c and zstd_ldm_geartab.h, v1.5.7).
//!
//! A gear rolling hash picks split points about every 2^hashRateLog bytes;
//! each split's `minMatchLength` preceding bytes are hashed with XXH64 into a
//! bucketed table of (index, checksum). A split whose checksum is found again
//! extends forwards and backwards into a long match, and the block's matches
//! become raw sequences. The optimal parsers take them as extra candidates
//! next to their own binary-tree matches; every other strategy takes each
//! of them as it comes, compressing only the literals between them with its
//! own match finder (`blockCompress`). libzstd turns LDM on by itself only
//! for `btopt` and up with a window log of 27 or more (`resolve`), which
//! only level 22 reaches (inputs over 64 MB); `Advanced.long_distance_matching`
//! turns it on for any level.
//!
//! A stream's window can be in two segments (extDict); the LDM state keeps
//! its own window, like the match state's, and counts matches across both.

const std = @import("std");
const params = @import("params.zig");
const match = @import("match.zig");
const sequences = @import("sequences.zig");

/// `LDM_BUCKET_SIZE_LOG`.
const bucket_size_log_default: u32 = 4;
/// `LDM_MIN_MATCH_LENGTH`.
const min_match_length_default: u32 = 64;
/// `LDM_BATCH_SIZE`: splits gathered before their buckets are searched.
const batch_size = 64;

/// `ldmParams_t` once `ZSTD_ldm_adjustParameters` has filled it in.
pub const Params = struct {
    window_log: u32,
    hash_log: u32,
    bucket_size_log: u32,
    min_match_length: u32,
    hash_rate_log: u32,
};

/// `ZSTD_resolveEnableLdm`: whether LDM runs with the frame's final
/// parameters `cp`.
pub fn resolve(mode: params.Switch, cp: params.CParams) bool {
    return switch (mode) {
        .enable => true,
        .disable => false,
        .auto => @intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.btopt) and cp.window_log >= 27,
    };
}

/// `ZSTD_ldm_adjustParameters`: the LDM parameters `adv` leaves unset
/// (null or 0), derived from the frame's parameters and the others.
pub fn adjustParameters(cp: params.CParams, adv: params.Advanced) Params {
    const strategy = @intFromEnum(cp.strategy);
    const window_log = cp.window_log;
    var hash_rate_log = params.nonZero(adv.ldm_hash_rate_log) orelse 0;
    var hash_log = params.nonZero(adv.ldm_hash_log) orelse 0;
    if (hash_rate_log == 0) {
        if (hash_log > 0) {
            // if params->hashLog is set, derive hashRateLog from it
            if (window_log > hash_log) hash_rate_log = window_log - hash_log;
        } else {
            // mapping from [fast, rate7] to [btultra2, rate4]
            hash_rate_log = 7 - strategy / 3;
        }
    }
    // (unsigned in libzstd: a rate above the window log wraps, and the
    // table takes the largest size)
    if (hash_log == 0) hash_log = std.math.clamp(window_log -% hash_rate_log, params.hash_log_min, params.hash_log_max);
    const min_match_length = params.nonZero(adv.ldm_min_match) orelse
        if (strategy >= @intFromEnum(params.Strategy.btultra)) min_match_length_default / 2 else min_match_length_default;
    const bucket_size_log = params.nonZero(adv.ldm_bucket_size_log) orelse
        std.math.clamp(strategy, bucket_size_log_default, params.ldm_bucket_size_log_max);
    return .{
        .window_log = window_log,
        .hash_log = hash_log,
        .bucket_size_log = @min(bucket_size_log, hash_log),
        .min_match_length = min_match_length,
        .hash_rate_log = hash_rate_log,
    };
}

/// `ZSTD_ldm_getMaxNbSeq`: every sequence holds a match of at least
/// `min_match_length` bytes, and the block holds them all.
pub fn maxNbSeq(p: Params, max_chunk_size: usize) usize {
    return max_chunk_size / p.min_match_length;
}

/// `rawSeq`: literals, then a match at `offset` (a real distance, not an offBase).
pub const RawSeq = struct {
    offset: u32,
    lit_length: u32,
    match_length: u32,
};

/// `RawSeqStore_t`; the default is `kNullRawSeqStore`.
pub const RawSeqStore = struct {
    seq: []RawSeq = &.{},
    /// next sequence to hand out
    pos: usize = 0,
    /// bytes of `seq[pos]` already consumed
    pos_in_sequence: usize = 0,
    size: usize = 0,

    /// `ZSTD_ldm_skipRawSeqStoreBytes` (and its copy in zstd_opt.c,
    /// `ZSTD_optLdm_skipRawSeqStoreBytes`): move `nb_bytes` forwards.
    pub fn skipBytes(s: *RawSeqStore, nb_bytes: usize) void {
        var curr_pos: u32 = @truncate(s.pos_in_sequence + nb_bytes);
        while (curr_pos != 0 and s.pos < s.size) {
            const curr = s.seq[s.pos];
            if (curr_pos >= curr.lit_length + curr.match_length) {
                curr_pos -= curr.lit_length + curr.match_length;
                s.pos += 1;
            } else {
                s.pos_in_sequence = curr_pos;
                break;
            }
        }
        if (curr_pos == 0 or s.pos == s.size) s.pos_in_sequence = 0;
    }

    /// `ZSTD_ldm_skipSequences`: consume `src_size` bytes of the sequences,
    /// shortening the one they end in; a match left shorter than
    /// `min_match` turns into literals of the next sequence.
    pub fn skipSequences(s: *RawSeqStore, src_size_in: usize, min_match: u32) void {
        var src_size = src_size_in;
        while (src_size > 0 and s.pos < s.size) {
            const seq = &s.seq[s.pos];
            if (src_size <= seq.lit_length) {
                // Skip past srcSize literals
                seq.lit_length -= @intCast(src_size);
                return;
            }
            src_size -= seq.lit_length;
            seq.lit_length = 0;
            if (src_size < seq.match_length) {
                // Skip past the first srcSize of the match
                seq.match_length -= @intCast(src_size);
                if (seq.match_length < min_match) {
                    // The match is too short, omit it
                    if (s.pos + 1 < s.size) s.seq[s.pos + 1].lit_length += seq.match_length;
                    s.pos += 1;
                }
                return;
            }
            src_size -= seq.match_length;
            seq.match_length = 0;
            s.pos += 1;
        }
    }

    /// `maybeSplitSequence`: the next sequence, cut short where it runs
    /// past the `remaining` bytes of the block (the rest goes to the next
    /// block). An `offset` of 0 means the rest of the block is literals.
    fn maybeSplitSequence(s: *RawSeqStore, remaining: u32, min_match: u32) RawSeq {
        var seq = s.seq[s.pos];
        std.debug.assert(seq.offset > 0);
        // Likely: No partial sequence
        if (remaining >= seq.lit_length + seq.match_length) {
            s.pos += 1;
            return seq;
        }
        // Cut the sequence short (offset == 0 ==> rest is literals).
        if (remaining <= seq.lit_length) {
            seq.offset = 0;
        } else if (remaining < seq.lit_length + seq.match_length) {
            seq.match_length = remaining - seq.lit_length;
            if (seq.match_length < min_match) seq.offset = 0;
        }
        // Skip past `remaining` bytes for the future sequences.
        s.skipSequences(remaining, min_match);
        return seq;
    }
};

/// `ZSTD_ldm_blockCompress`: the block at indices `istart`..`istart +
/// src_size` with its long-distance matches in `store`. The optimal
/// parsers weigh them against their own; every other strategy takes each
/// one, running its match finder over the literals before it. Returns the
/// trailing literals, as `match.compressBlock` does.
pub fn blockCompress(store: *RawSeqStore, ms: *match.MatchState, ss: *sequences.SeqStore, rep: *[3]u32, istart: u32, src_size: u32) usize {
    // If using opt parser, use LDMs only as candidates rather than always
    // accepting them
    if (@intFromEnum(ms.cp.strategy) >= @intFromEnum(params.Strategy.btopt)) {
        ms.ldm_seq_store = store;
        defer ms.ldm_seq_store = null;
        const last_ll = match.compressBlock(ms, ss, rep, istart, src_size);
        store.skipBytes(src_size);
        return last_ll;
    }

    const min_match = ms.cp.min_match;
    const iend: usize = @as(usize, istart) + src_size;
    var ip: usize = istart;
    // Loop through each sequence and apply the block compressor to the literals
    while (store.pos < store.size and ip < iend) {
        const seq = store.maybeSplitSequence(@intCast(iend - ip), min_match);
        // End signal
        if (seq.offset == 0) break;
        std.debug.assert(ip + seq.lit_length + seq.match_length <= iend);
        // Fill tables for block compressor
        limitTableUpdate(ms, ip);
        fillFastTables(ms, ip);
        // Run the block compressor
        const new_lit_length = match.compressBlock(ms, ss, rep, @intCast(ip), seq.lit_length);
        ip += seq.lit_length;
        // Update the repcodes
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = seq.offset;
        // Store the sequence
        ss.store(ms.bytes(ip - new_lit_length, ip), seq.offset + sequences.rep_num, seq.match_length);
        ip += seq.match_length;
    }
    // Fill the tables for the block compressor
    limitTableUpdate(ms, ip);
    fillFastTables(ms, ip);
    // Compress the last literals
    return match.compressBlock(ms, ss, rep, @intCast(ip), @intCast(iend - ip));
}

/// `ZSTD_ldm_limitTableUpdate`: after a long match, the match finder
/// inserts only the last positions before `anchor`.
fn limitTableUpdate(ms: *match.MatchState, anchor: usize) void {
    const curr: u32 = @intCast(anchor);
    if (curr > ms.next_to_update + 1024)
        ms.next_to_update = curr - @min(512, curr - ms.next_to_update - 1024);
}

/// `ZSTD_ldm_fillFastTables`: `fast` and `dfast` fill their tables here up
/// to `end` (the other strategies fill theirs while they search).
fn fillFastTables(ms: *match.MatchState, end: usize) void {
    switch (ms.cp.strategy) {
        .fast => match.fillHashTable(ms, end),
        .dfast => match.fillDoubleHashTable(ms, end),
        else => {},
    }
}

/// `ldmEntry_t`: offset 0 is an empty slot (indices start at 2).
pub const Entry = struct { offset: u32 = 0, checksum: u32 = 0 };

const Candidate = struct {
    split: u32,
    hash: u32,
    checksum: u32,
};

/// `ldmState_t`: the table and its own window, which trails the match
/// finder's (it is moved by the END of each block, the match state's by the
/// start).
pub const State = struct {
    /// The window, as in `match.MatchState`: the prefix `src` from index
    /// `src_base`, the extDict `dict` from `dict_base`, and a stream's input
    /// buffer (`match.updateWindow`).
    src: []const u8 = &.{},
    src_base: u32 = match.window_start,
    dict: []const u8 = &.{},
    dict_base: u32 = match.window_start,
    buffer: []const u8 = &.{},
    p: Params,
    /// `1 << hash_log` entries, `1 << bucket_size_log` per bucket
    hash_table: []Entry,
    /// per bucket, the slot the next insertion overwrites
    bucket_offsets: []u8,
    low_limit: u32 = match.window_start,
    dict_limit: u32 = match.window_start,
    /// `window.nbOverflowCorrections`.
    n_overflow_corrections: u32 = 0,
    /// `loadedDictEnd`: the index past a raw dictionary loaded into the
    /// table, until the input is a window past it (see `match.MatchState`).
    loaded_dict_end: u32 = 0,
    /// Chunks searched with the window in two segments. Not libzstd's;
    /// tests read it.
    n_ext_dict_chunks: u32 = 0,
    /// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY` (see `match.needOverflowCorrection`).
    overflow_correct_frequently: bool = false,
    split_indices: [batch_size]usize = undefined,
    candidates: [batch_size]Candidate = undefined,

    /// The index of the prefix byte at `ptr`.
    fn indexOf(ls: *const State, ptr: [*]const u8) usize {
        return ls.src_base + (@intFromPtr(ptr) - @intFromPtr(ls.src.ptr));
    }

    fn bytes(ls: *const State, idx: usize, len: usize) []const u8 {
        return ls.src[idx - ls.src_base ..][0..len];
    }

    /// The byte at `idx`, from the extDict below `dict_limit`.
    inline fn atSeg(ls: *const State, idx: usize) u8 {
        return if (idx < ls.dict_limit) ls.dict[idx - ls.dict_base] else ls.src[idx - ls.src_base];
    }

    /// Address of the byte at index `idx` in the segment `in_dict` names:
    /// libzstd compares segment bounds as pointers.
    fn addr(ls: *const State, idx: usize, in_dict: bool) usize {
        return if (in_dict) @intFromPtr(ls.dict.ptr) + idx - ls.dict_base else @intFromPtr(ls.src.ptr) + idx - ls.src_base;
    }

    /// `ZSTD_window_update` of the LDM window.
    pub fn windowUpdate(ls: *State, chunk: []const u8) void {
        _ = match.updateWindow(ls, chunk, false);
    }

    /// `ZSTD_ldm_insertEntry`.
    fn insertEntry(ls: *State, hash: u32, entry: Entry) void {
        const offset = ls.bucket_offsets[hash];
        ls.hash_table[(@as(usize, hash) << @intCast(ls.p.bucket_size_log)) + offset] = entry;
        ls.bucket_offsets[hash] = @truncate((@as(u32, offset) + 1) & ((@as(u32, 1) << @intCast(ls.p.bucket_size_log)) - 1));
    }

    /// `ZSTD_count`: common run at indices `p_in` and `p_match`, not reading
    /// at or past `p_limit` on the `p_in` side.
    fn count(ls: *const State, p_in: usize, p_match: usize, p_limit: usize) usize {
        const s = ls.src;
        var i = p_in - ls.src_base;
        var m = p_match - ls.src_base;
        const lim = p_limit - ls.src_base;
        const start = i;
        while (i + 8 <= lim) {
            const d = std.mem.readInt(u64, s[i..][0..8], .little) ^ std.mem.readInt(u64, s[m..][0..8], .little);
            if (d != 0) return i - start + (@ctz(d) >> 3);
            i += 8;
            m += 8;
        }
        while (i < lim and s[i] == s[m]) {
            i += 1;
            m += 1;
        }
        return i - start;
    }

    /// `ZSTD_ldm_countBackwardsMatch`: bytes that match backwards before
    /// `p_in` and `p_match`, with `p_in` above `p_anchor` and `p_match` above
    /// `p_match_base`.
    fn countBackwards(ls: *const State, p_in_start: usize, p_anchor: usize, p_match_start: usize, p_match_base: usize) usize {
        var p_in = p_in_start;
        var p_match = p_match_start;
        while (p_in > p_anchor and p_match > p_match_base and ls.atSeg(p_in - 1) == ls.atSeg(p_match - 1)) {
            p_in -= 1;
            p_match -= 1;
        }
        return p_in_start - p_in;
    }

    /// `ZSTD_window_enforceMaxDist(&ldmState->window, blockEnd, maxDist, &loadedDictEnd, NULL)`.
    fn enforceMaxDist(ls: *State, block_end_idx: u32) void {
        const max_dist: u32 = @as(u32, 1) << @intCast(ls.p.window_log);
        if (block_end_idx > max_dist +% ls.loaded_dict_end) {
            const new_low = block_end_idx - max_dist;
            if (ls.low_limit < new_low) ls.low_limit = new_low;
            if (ls.dict_limit < ls.low_limit) ls.dict_limit = ls.low_limit;
            // On reaching window size, dictionaries are invalidated
            ls.loaded_dict_end = 0;
        }
    }

    /// `ZSTD_count_2segments` for a candidate in the extDict (`m_end` its
    /// end); in the prefix (`m_end == i_end`) a plain count.
    fn count2Segments(ls: *const State, p_in: usize, p_match: usize, i_end: usize, m_end: usize, i_start: usize) usize {
        if (m_end == i_end) return ls.count(p_in, p_match, i_end);
        const v_end = if (p_match > m_end) p_in else @min(p_in + (m_end - p_match), i_end);
        var n: usize = 0;
        while (p_in + n < v_end and ls.src[p_in + n - ls.src_base] == ls.dict[p_match + n - ls.dict_base]) n += 1;
        if (p_match + n != m_end) return n;
        return n + ls.count(p_in + n, i_start, i_end);
    }

    /// `ZSTD_ldm_countBackwardsMatch_2segments`: on reaching the prefix's
    /// start, go on from the extDict's end — unless the match was in the
    /// extDict, or (a pointer comparison in libzstd) the two segments'
    /// starts are one address.
    fn countBackwards2Segments(ls: *const State, p_in: usize, p_anchor: usize, p_match: usize, p_match_base: usize, match_in_dict: bool) usize {
        var match_length = ls.countBackwards(p_in, p_anchor, p_match, p_match_base);
        const dict_start: usize = ls.low_limit;
        if (p_match - match_length != p_match_base or ls.addr(p_match_base, match_in_dict) == ls.addr(dict_start, true)) return match_length;
        match_length += ls.countBackwards(p_in - match_length, p_anchor, ls.dict_limit, dict_start);
        return match_length;
    }

    /// `ZSTD_ldm_reduceTable`.
    fn reduceTable(ls: *State, reducer: u32) void {
        for (ls.hash_table) |*e| e.offset = if (e.offset < reducer) 0 else e.offset - reducer;
    }

    /// `ZSTD_ldm_fillHashTable`: enter the split points of `content` (the
    /// window's prefix, a dictionary just loaded) into the table.
    pub fn fillHashTable(ls: *State, content: []const u8) void {
        const min_match_length = ls.p.min_match_length;
        const h_bits: u5 = @intCast(ls.p.hash_log - ls.p.bucket_size_log);
        const istart = ls.indexOf(content.ptr);
        const iend = istart + content.len;
        var hs: GearState = .init(ls.p);
        var ip = istart;
        while (ip < iend) {
            var num_splits: usize = 0;
            const hashed = hs.feed(ls.bytes(ip, iend - ip), &ls.split_indices, &num_splits);
            for (ls.split_indices[0..num_splits]) |sp| {
                if (ip + sp >= istart + min_match_length) {
                    const split = ip + sp - min_match_length;
                    const xxhash = std.hash.XxHash64.hash(0, ls.bytes(split, min_match_length));
                    const hash = @as(u32, @truncate(xxhash)) & ((@as(u32, 1) << h_bits) - 1);
                    ls.insertEntry(hash, .{ .offset = @intCast(split), .checksum = @truncate(xxhash >> 32) });
                }
            }
            ip += hashed;
        }
    }

    /// `ZSTD_ldm_generateSequences`: the raw sequences of `block`, which is
    /// in this window's prefix, into `out` (whose capacity is `maxNbSeq`).
    /// The table keeps what it learnt for later blocks. Indices are this
    /// window's own: they drift from the match state's once either is
    /// corrected for overflow.
    pub fn generateSequences(ls: *State, out: *RawSeqStore, block: []const u8) void {
        const src_size = block.len;
        const k_max_chunk_size: usize = 1 << 20;
        const max_dist: u32 = @as(u32, 1) << @intCast(ls.p.window_log);
        const nb_chunks = src_size / k_max_chunk_size + @intFromBool(src_size % k_max_chunk_size != 0);
        var leftover_size: usize = 0;
        std.debug.assert(out.pos <= out.size and out.size <= out.seq.len);
        var chunk: usize = 0;
        while (chunk < nb_chunks and out.size < out.seq.len) : (chunk += 1) {
            const chunk_ptr = block.ptr + chunk * k_max_chunk_size;
            const chunk_size = @min(src_size - chunk * k_max_chunk_size, k_max_chunk_size);
            const prev_size = out.size;
            // 1. Perform overflow correction if necessary.
            if (match.needOverflowCorrection(ls.overflow_correct_frequently, ls.n_overflow_corrections, 0, max_dist, ls.loaded_dict_end, ls.indexOf(chunk_ptr), ls.indexOf(chunk_ptr) + chunk_size)) {
                const correction = match.correctOverflow(&ls.low_limit, &ls.dict_limit, &ls.n_overflow_corrections, ls.overflow_correct_frequently, 0, max_dist, @intCast(ls.indexOf(chunk_ptr)));
                match.shiftSegment(&ls.src, &ls.src_base, correction);
                match.shiftSegment(&ls.dict, &ls.dict_base, correction);
                ls.reduceTable(correction);
                // invalidate dictionaries on overflow correction
                ls.loaded_dict_end = 0;
            }
            const chunk_start = ls.indexOf(chunk_ptr);
            const chunk_end = chunk_start + chunk_size;
            // 2. We enforce the maximum offset allowed.
            ls.enforceMaxDist(@intCast(chunk_end));
            // 3. Generate the sequences for the chunk, and get newLeftoverSize.
            const new_leftover_size = if (ls.low_limit < ls.dict_limit) blk: {
                ls.n_ext_dict_chunks += 1;
                break :blk ls.generateInternal(out, chunk_start, chunk_size, true);
            } else ls.generateInternal(out, chunk_start, chunk_size, false);
            // 4. Prepend the leftover literals from the last call.
            if (prev_size < out.size) {
                out.seq[prev_size].lit_length += @intCast(leftover_size);
                leftover_size = new_leftover_size;
            } else {
                std.debug.assert(new_leftover_size == chunk_size);
                leftover_size += chunk_size;
            }
        }
    }

    /// `ZSTD_ldm_generateSequences_internal` (extDict when `ext`). Returns
    /// the trailing literals of the chunk.
    fn generateInternal(ls: *State, out: *RawSeqStore, istart: usize, src_size: usize, comptime ext: bool) usize {
        const min_match_length = ls.p.min_match_length;
        const ents_per_bucket = @as(usize, 1) << @intCast(ls.p.bucket_size_log);
        const h_bits: u5 = @intCast(ls.p.hash_log - ls.p.bucket_size_log);
        const dict_limit = ls.dict_limit;
        const lowest_index = if (ext) ls.low_limit else dict_limit;
        const low_prefix: usize = dict_limit;
        const iend = istart + src_size;
        var anchor = istart;

        if (src_size < min_match_length) return iend - anchor;
        const ilimit = iend - match.hash_read_size;

        // Initialize the rolling hash state with the first minMatchLength bytes
        var hs: GearState = .init(ls.p);
        hs.reset(ls.bytes(istart, min_match_length));
        var ip = istart + min_match_length;

        while (ip < ilimit) {
            var num_splits: usize = 0;
            const hashed = hs.feed(ls.bytes(ip, ilimit - ip), &ls.split_indices, &num_splits);

            for (ls.split_indices[0..num_splits], ls.candidates[0..num_splits]) |s, *c| {
                const split = ip + s - min_match_length;
                const xxhash = std.hash.XxHash64.hash(0, ls.bytes(split, min_match_length));
                c.* = .{
                    .split = @intCast(split),
                    .hash = @as(u32, @truncate(xxhash)) & ((@as(u32, 1) << h_bits) - 1),
                    .checksum = @truncate(xxhash >> 32),
                };
            }

            for (ls.candidates[0..num_splits]) |c| {
                const split: usize = c.split;
                const new_entry: Entry = .{ .offset = c.split, .checksum = c.checksum };

                // If a split point would generate a sequence overlapping with
                // the previous one, we merely register it in the hash table
                // and move on
                if (split < anchor) {
                    ls.insertEntry(c.hash, new_entry);
                    continue;
                }

                var forward_match_length: usize = 0;
                var backward_match_length: usize = 0;
                var best_match_length: usize = 0;
                var best: ?Entry = null;
                const bucket = ls.hash_table[@as(usize, c.hash) << @intCast(ls.p.bucket_size_log) ..][0..ents_per_bucket];
                for (bucket) |cur| {
                    if (cur.checksum != c.checksum or cur.offset <= lowest_index) continue;
                    const p_match: usize = cur.offset;
                    var cur_forward: usize = undefined;
                    var cur_backward: usize = undefined;
                    if (ext) {
                        const in_dict = cur.offset < dict_limit;
                        const match_end: usize = if (in_dict) dict_limit else iend;
                        const low_match: usize = if (in_dict) ls.low_limit else low_prefix;
                        cur_forward = ls.count2Segments(split, p_match, iend, match_end, low_prefix);
                        if (cur_forward < min_match_length) continue;
                        cur_backward = ls.countBackwards2Segments(split, anchor, p_match, low_match, in_dict);
                    } else {
                        cur_forward = ls.count(split, p_match, iend);
                        if (cur_forward < min_match_length) continue;
                        cur_backward = ls.countBackwards(split, anchor, p_match, low_prefix);
                    }
                    const cur_total = cur_forward + cur_backward;
                    if (cur_total > best_match_length) {
                        best_match_length = cur_total;
                        forward_match_length = cur_forward;
                        backward_match_length = cur_backward;
                        best = cur;
                    }
                }

                // No match found -- insert an entry into the hash table and
                // process the next candidate match
                const best_entry = best orelse {
                    ls.insertEntry(c.hash, new_entry);
                    continue;
                };

                // Match found
                // (libzstd returns dstSize_tooSmall on a full store; every
                // sequence covers at least min_match_length bytes of the
                // chunk, so the capacity of maxNbSeq is never reached)
                std.debug.assert(out.size < out.seq.len);
                out.seq[out.size] = .{
                    .lit_length = @intCast(split - backward_match_length - anchor),
                    .match_length = @intCast(forward_match_length + backward_match_length),
                    .offset = c.split - best_entry.offset,
                };
                out.size += 1;

                // Insert the current entry into the hash table --- it must be
                // done after the previous block to avoid clobbering bestEntry
                ls.insertEntry(c.hash, new_entry);

                anchor = split + forward_match_length;

                // A match that ends after the data hashed so far is a
                // repeating, overlapping pattern (e.g. all zeros): skip over
                // it instead of inserting every repetition.
                if (anchor > ip + hashed) {
                    hs.reset(ls.bytes(anchor - min_match_length, min_match_length));
                    // Continue the outer loop at anchor (ip + hashed == anchor).
                    ip = anchor - hashed;
                    break;
                }
            }
            ip += hashed;
        }
        return iend - anchor;
    }
};

/// `ldmRollingHashState_t` with `ZSTD_ldm_gear_init/reset/feed`.
const GearState = struct {
    rolling: u64,
    stop_mask: u64,

    fn init(p: Params) GearState {
        const max_bits_in_mask = @min(p.min_match_length, 64);
        const hash_rate_log = p.hash_rate_log;
        // The mask has hashRateLog bits set, as high as a window of
        // minMatchLength bytes allows (bit n depends on the last n bytes).
        const stop_mask: u64 = if (hash_rate_log > 0 and hash_rate_log <= max_bits_in_mask)
            ((@as(u64, 1) << @intCast(hash_rate_log)) - 1) << @intCast(max_bits_in_mask - hash_rate_log)
        else
            // In this degenerate case we simply honor the hash rate.
            (@as(u64, 1) << @intCast(hash_rate_log)) - 1;
        return .{ .rolling = ~@as(u32, 0), .stop_mask = stop_mask };
    }

    /// `ZSTD_ldm_gear_reset` is meant to feed `data` into the hash without
    /// registering splits, but in 1.5.7 it rolls a local copy and never
    /// stores it: the state is left as it was. Output depends on that, so it
    /// is a no-op here too.
    fn reset(g: *GearState, data: []const u8) void {
        _ = g;
        _ = data;
    }

    /// Registers the split points in `data` (offsets just past each split)
    /// until `data` or the batch runs out. Returns the bytes consumed.
    fn feed(g: *GearState, data: []const u8, splits: *[batch_size]usize, num_splits: *usize) usize {
        var hash = g.rolling;
        const mask = g.stop_mask;
        var n: usize = 0;
        while (n < data.len) {
            hash = (hash << 1) +% gear_tab[data[n]];
            n += 1;
            if ((hash & mask) == 0) {
                splits[num_splits.*] = n;
                num_splits.* += 1;
                if (num_splits.* == batch_size) break;
            }
        }
        g.rolling = hash;
        return n;
    }
};

test "level 22 above 64 MB: the parameters libzstd derives" {
    // btultra2, windowLog 27: rate 7 - 9/3, table 2^(27-4), bucket
    // clamp(9, 4, 8), half of the default minimum match
    const p = adjustParameters(params.get(22, 100 << 20), .{});
    try std.testing.expectEqual(Params{ .window_log = 27, .hash_log = 23, .bucket_size_log = 8, .min_match_length = 32, .hash_rate_log = 4 }, p);
    try std.testing.expectEqual(@as(usize, 4096), maxNbSeq(p, 128 * 1024));
}

test "level 22 switches LDM on from one byte over 64 MB" {
    try std.testing.expect(!resolve(.auto, params.get(22, 1 << 26)));
    try std.testing.expect(resolve(.auto, params.get(22, (1 << 26) + 1)));
    try std.testing.expect(!resolve(.auto, params.get(21, 1 << 30)));
    try std.testing.expect(!resolve(.disable, params.get(22, (1 << 26) + 1)));
    try std.testing.expect(resolve(.enable, params.get(1, 1000)));
}

test "btopt keeps the default minimum match and a bucket of 2^strategy" {
    const cp: params.CParams = .{ .window_log = 20, .chain_log = 20, .hash_log = 20, .search_log = 5, .min_match = 4, .target_length = 64, .strategy = .btopt };
    try std.testing.expectEqual(Params{ .window_log = 20, .hash_log = 15, .bucket_size_log = 7, .min_match_length = 64, .hash_rate_log = 5 }, adjustParameters(cp, .{}));
}

test "LDM parameters set by hand, and the ones derived from them" {
    const cp: params.CParams = .{ .window_log = 20, .chain_log = 16, .hash_log = 17, .search_log = 1, .min_match = 5, .target_length = 0, .strategy = .fast };
    // a hash log sets the rate: one split per 2^(window - hash) bytes
    try std.testing.expectEqual(Params{ .window_log = 20, .hash_log = 12, .bucket_size_log = 4, .min_match_length = 64, .hash_rate_log = 8 }, adjustParameters(cp, .{ .ldm_hash_log = 12 }));
    // ... and none when the table is as large as the window
    try std.testing.expectEqual(@as(u32, 0), adjustParameters(cp, .{ .ldm_hash_log = 20 }).hash_rate_log);
    try std.testing.expectEqual(@as(u32, 1), adjustParameters(cp, .{ .ldm_hash_log = 19 }).hash_rate_log);
    // a rate sets the hash log; one past the window log wraps to the largest
    try std.testing.expectEqual(@as(u32, 15), adjustParameters(cp, .{ .ldm_hash_rate_log = 5 }).hash_log);
    try std.testing.expectEqual(@as(u32, params.hash_log_max), adjustParameters(cp, .{ .ldm_hash_rate_log = 21 }).hash_log);
    // the bucket never exceeds the table; 0 is "not set"
    try std.testing.expectEqual(@as(u32, 6), adjustParameters(cp, .{ .ldm_hash_log = 6, .ldm_bucket_size_log = 8 }).bucket_size_log);
    try std.testing.expectEqual(Params{ .window_log = 20, .hash_log = 13, .bucket_size_log = 4, .min_match_length = 64, .hash_rate_log = 7 }, adjustParameters(cp, .{ .ldm_hash_log = 0, .ldm_min_match = 0, .ldm_bucket_size_log = 0, .ldm_hash_rate_log = 0 }));
    try std.testing.expectEqual(@as(u32, 4096), adjustParameters(cp, .{ .ldm_min_match = 4096 }).min_match_length);
}

test "the stop mask takes the highest bits a match can depend on" {
    const g: GearState = .init(.{ .window_log = 27, .hash_log = 23, .bucket_size_log = 8, .min_match_length = 32, .hash_rate_log = 4 });
    try std.testing.expectEqual(@as(u64, 0xF) << 28, g.stop_mask);
    try std.testing.expectEqual(@as(u64, 0xFFFF_FFFF), g.rolling);
}

test "skipping raw sequences lands inside, between and past them" {
    var seqs = [_]RawSeq{ .{ .offset = 9, .lit_length = 10, .match_length = 40 }, .{ .offset = 9, .lit_length = 0, .match_length = 50 } };
    var s: RawSeqStore = .{ .seq = &seqs, .size = 2 };
    s.skipBytes(25);
    try std.testing.expectEqual(@as(usize, 0), s.pos);
    try std.testing.expectEqual(@as(usize, 25), s.pos_in_sequence);
    s.skipBytes(25); // exactly to the end of the first
    try std.testing.expectEqual(@as(usize, 1), s.pos);
    try std.testing.expectEqual(@as(usize, 0), s.pos_in_sequence);
    s.skipBytes(1000); // past everything: the position resets
    try std.testing.expectEqual(@as(usize, 2), s.pos);
    try std.testing.expectEqual(@as(usize, 0), s.pos_in_sequence);
}

/// `ZSTD_ldm_gearTab`.
const gear_tab = [256]u64{
    0xf5b8f72c5f77775c, 0x84935f266b7ac412, 0xb647ada9ca730ccc, 0xb065bb4b114fb1de,
    0x34584e7e8c3a9fd0, 0x4e97e17c6ae26b05, 0x3a03d743bc99a604, 0xcecd042422c4044f,
    0x76de76c58524259e, 0x9c8528f65badeaca, 0x86563706e2097529, 0x2902475fa375d889,
    0xafb32a9739a5ebe6, 0xce2714da3883e639, 0x21eaf821722e69e,  0x37b628620b628,
    0x49a8d455d88caf5,  0x8556d711e6958140, 0x4f7ae74fc605c1f,  0x829f0c3468bd3a20,
    0x4ffdc885c625179e, 0x8473de048a3daf1b, 0x51008822b05646b2, 0x69d75d12b2d1cc5f,
    0x8c9d4a19159154bc, 0xc3cc10f4abbd4003, 0xd06ddc1cecb97391, 0xbe48e6e7ed80302e,
    0x3481db31cee03547, 0xacc3f67cdaa1d210, 0x65cb771d8c7f96cc, 0x8eb27177055723dd,
    0xc789950d44cd94be, 0x934feadc3700b12b, 0x5e485f11edbdf182, 0x1e2e2a46fd64767a,
    0x2969ca71d82efa7c, 0x9d46e9935ebbba2e, 0xe056b67e05e6822b, 0x94d73f55739d03a0,
    0xcd7010bdb69b5a03, 0x455ef9fcd79b82f4, 0x869cb54a8749c161, 0x38d1a4fa6185d225,
    0xb475166f94bbe9bb, 0xa4143548720959f1, 0x7aed4780ba6b26ba, 0xd0ce264439e02312,
    0x84366d746078d508, 0xa8ce973c72ed17be, 0x21c323a29a430b01, 0x9962d617e3af80ee,
    0xab0ce91d9c8cf75b, 0x530e8ee6d19a4dbc, 0x2ef68c0cf53f5d72, 0xc03a681640a85506,
    0x496e4e9f9c310967, 0x78580472b59b14a0, 0x273824c23b388577, 0x66bf923ad45cb553,
    0x47ae1a5a2492ba86, 0x35e304569e229659, 0x4765182a46870b6f, 0x6cbab625e9099412,
    0xddac9a2e598522c1, 0x7172086e666624f2, 0xdf5003ca503b7837, 0x88c0c1db78563d09,
    0x58d51865acfc289d, 0x177671aec65224f1, 0xfb79d8a241e967d7, 0x2be1e101cad9a49a,
    0x6625682f6e29186b, 0x399553457ac06e50, 0x35dffb4c23abb74,  0x429db2591f54aade,
    0xc52802a8037d1009, 0x6acb27381f0b25f3, 0xf45e2551ee4f823b, 0x8b0ea2d99580c2f7,
    0x3bed519cbcb4e1e1, 0xff452823dbb010a,  0x9d42ed614f3dd267, 0x5b9313c06257c57b,
    0xa114b8008b5e1442, 0xc1fe311c11c13d4b, 0x66e8763ea34c5568, 0x8b982af1c262f05d,
    0xee8876faaa75fbb7, 0x8a62a4d0d172bb2a, 0xc13d94a3b7449a97, 0x6dbbba9dc15d037c,
    0xc786101f1d92e0f1, 0xd78681a907a0b79b, 0xf61aaf2962c9abb9, 0x2cfd16fcd3cb7ad9,
    0x868c5b6744624d21, 0x25e650899c74ddd7, 0xba042af4a7c37463, 0x4eb1a539465a3eca,
    0xbe09dbf03b05d5ca, 0x774e5a362b5472ba, 0x47a1221229d183cd, 0x504b0ca18ef5a2df,
    0xdffbdfbde2456eb9, 0x46cd2b2fbee34634, 0xf2aef8fe819d98c3, 0x357f5276d4599d61,
    0x24a5483879c453e3, 0x88026889192b4b9,  0x28da96671782dbec, 0x4ef37c40588e9aaa,
    0x8837b90651bc9fb3, 0xc164f741d3f0e5d6, 0xbc135a0a704b70ba, 0x69cd868f7622ada,
    0xbc37ba89e0b9c0ab, 0x47c14a01323552f6, 0x4f00794bacee98bb, 0x7107de7d637a69d5,
    0x88af793bb6f2255e, 0xf3c6466b8799b598, 0xc288c616aa7f3b59, 0x81ca63cf42fca3fd,
    0x88d85ace36a2674b, 0xd056bd3792389e7,  0xe55c396c4e9dd32d, 0xbefb504571e6c0a6,
    0x96ab32115e91e8cc, 0xbf8acb18de8f38d1, 0x66dae58801672606, 0x833b6017872317fb,
    0xb87c16f2d1c92864, 0xdb766a74e58b669c, 0x89659f85c61417be, 0xc8daad856011ea0c,
    0x76a4b565b6fe7eae, 0xa469d085f6237312, 0xaaf0365683a3e96c, 0x4dbb746f8424f7b8,
    0x638755af4e4acc1,  0x3d7807f5bde64486, 0x17be6d8f5bbb7639, 0x903f0cd44dc35dc,
    0x67b672eafdf1196c, 0xa676ff93ed4c82f1, 0x521d1004c5053d9d, 0x37ba9ad09ccc9202,
    0x84e54d297aacfb51, 0xa0b4b776a143445,  0x820d471e20b348e,  0x1874383cb83d46dc,
    0x97edeec7a1efe11c, 0xb330e50b1bdc42aa, 0x1dd91955ce70e032, 0xa514cdb88f2939d5,
    0x2791233fd90db9d3, 0x7b670a4cc50f7a9b, 0x77c07d2a05c6dfa5, 0xe3778b6646d0a6fa,
    0xb39c8eda47b56749, 0x933ed448addbef28, 0xaf846af6ab7d0bf4, 0xe5af208eb666e49,
    0x5e6622f73534cd6a, 0x297daeca42ef5b6e, 0x862daef3d35539a6, 0xe68722498f8e1ea9,
    0x981c53093dc0d572, 0xfa09b0bfbf86fbf5, 0x30b1e96166219f15, 0x70e7d466bdc4fb83,
    0x5a66736e35f2a8e9, 0xcddb59d2b7c1baef, 0xd6c7d247d26d8996, 0xea4e39eac8de1ba3,
    0x539c8bb19fa3aff2, 0x9f90e4c5fd508d8,  0xa34e5956fbaf3385, 0x2e2f8e151d3ef375,
    0x173691e9b83faec1, 0xb85a8d56bf016379, 0x8382381267408ae3, 0xb90f901bbdc0096d,
    0x7c6ad32933bcec65, 0x76bb5e2f2c8ad595, 0x390f851a6cf46d28, 0xc3e6064da1c2da72,
    0xc52a0c101cfa5389, 0xd78eaf84a3fbc530, 0x3781b9e2288b997e, 0x73c2f6dea83d05c4,
    0x4228e364c5b5ed7,  0x9d7a3edf0da43911, 0x8edcfeda24686756, 0x5e7667a7b7a9b3a1,
    0x4c4f389fa143791d, 0xb08bc1023da7cddc, 0x7ab4be3ae529b1cc, 0x754e6132dbe74ff9,
    0x71635442a839df45, 0x2f6fb1643fbe52de, 0x961e0a42cf7a8177, 0xf3b45d83d89ef2ea,
    0xee3de4cf4a6e3e9b, 0xcd6848542c3295e7, 0xe4cee1664c78662f, 0x9947548b474c68c4,
    0x25d73777a5ed8b0b, 0xc915b1d636b7fc,   0x21c2ba75d9b0d2da, 0x5f6b5dcf608a64a1,
    0xdcf333255ff9570c, 0x633b922418ced4ee, 0xc136dde0b004b34a, 0x58cc83b05d4b2f5a,
    0x5eb424dda28e42d2, 0x62df47369739cd98, 0xb4e0b42485e4ce17, 0x16e1f0c1f9a8d1e7,
    0x8ec3916707560ebf, 0x62ba6e2df2cc9db3, 0xcbf9f4ff77d83a16, 0x78d9d7d07d2bbcc4,
    0xef554ce1e02c41f4, 0x8d7581127eccf94d, 0xa9b53336cb3c8a05, 0x38c42c0bf45c4f91,
    0x640893cdf4488863, 0x80ec34bc575ea568, 0x39f324f5b48eaa40, 0xe9d9ed1f8eff527f,
    0x9224fc058cc5a214, 0xbaba00b04cfe7741, 0x309a9f120fcf52af, 0xa558f3ec65626212,
    0x424bec8b7adabe2f, 0x41622513a6aea433, 0xb88da2d5324ca798, 0xd287733b245528a4,
    0x9a44697e6d68aec3, 0x7b1093be2f49bb28, 0x50bbec632e3d8aad, 0x6cd90723e1ea8283,
    0x897b9e7431b02bf3, 0x219efdcb338a7047, 0x3b0311f0a27c0656, 0xdb17bf91c0db96e7,
    0x8cd4fd6b4e85a5b2, 0xfab071054ba6409d, 0x40d6fe831fa9dfd9, 0xaf358debad7d791e,
    0xeb8d0e25a65e3e58, 0xbbcbd3df14e08580, 0xcf751f27ecdab2b,  0x2b4da14f2613d8f4,
};
