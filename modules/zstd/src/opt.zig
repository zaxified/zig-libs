// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Optimal parser for the `btopt`, `btultra` and `btultra2` strategies.
//!
//! Port of the no-dictionary paths of libzstd lib/compress/zstd_opt.c
//! (v1.5.7): the binary tree that collects every match length at a position
//! (`ZSTD_insertBtAndGetAllMatches`, plus the 3-byte hash of `minMatch` 3),
//! the adaptive symbol statistics that price literals, lengths and offsets,
//! and the forward pass / backward trace of `ZSTD_compressBlock_opt_generic`.
//! Long-distance matches (`ldm.zig`) join the candidates at each position
//! (`ZSTD_optLdm_*`) when the frame has them.
//!
//! Prices are in 1/256 bit (`BITCOST_ACCURACY` 8). `opt_level` 0 is btopt
//! (whole-bit weights, early exits), 2 is btultra and btultra2 (fractional
//! weights, the "match + 1 literal" probe).

const std = @import("std");
const match = @import("match.zig");
const sequences = @import("sequences.zig");
const ldm = @import("ldm.zig");
const MatchState = match.MatchState;
const SeqStore = sequences.SeqStore;

/// `ZSTD_OPT_NUM`: longest look-ahead of one series.
pub const opt_num = 1 << 12;
/// `ZSTD_OPT_SIZE`.
pub const opt_size = opt_num + 3;
/// `ZSTD_HASHLOG3_MAX`.
pub const hash_log3_max = 17;

const lit_freq_add = 2;
const max_price: i32 = 1 << 30;
/// `ZSTD_PREDEF_THRESHOLD`: blocks this small start from fixed prices.
pub const predef_threshold = 8;
const bitcost_accuracy = 8;
const bitcost_multiplier = 1 << bitcost_accuracy;
/// `ZSTD_BLOCKSIZE_MAX`.
const block_size_max = 128 * 1024;

const max_lit = 255;
const max_ll = sequences.max_ll;
const max_ml = sequences.max_ml;
const max_off = sequences.max_off;

pub const Match = struct { off: u32, len: u32 };

/// `ZSTD_optimal_t`: the cheapest known way to reach one position.
pub const Optimal = struct {
    /// price from the beginning of the series to this position
    price: i32 = 0,
    /// offBase of the previous match
    off: u32 = 0,
    /// length of the previous match
    mlen: u32 = 0,
    /// literals since the previous match
    litlen: u32 = 0,
    /// offset history after the previous match
    rep: [3]u32 = .{ 0, 0, 0 },
};

const PriceType = enum { dynamic, predef };

/// `optState_t`: the statistics live for the whole frame; the tables are
/// scratch for one series.
pub const State = struct {
    lit_freq: [max_lit + 1]u32 = @splat(0),
    lit_length_freq: [max_ll + 1]u32 = @splat(0),
    match_length_freq: [max_ml + 1]u32 = @splat(0),
    off_code_freq: [max_off + 1]u32 = @splat(0),
    lit_sum: u32 = 0,
    lit_length_sum: u32 = 0,
    match_length_sum: u32 = 0,
    off_code_sum: u32 = 0,
    lit_sum_base_price: u32 = 0,
    lit_length_sum_base_price: u32 = 0,
    match_length_sum_base_price: u32 = 0,
    off_code_sum_base_price: u32 = 0,
    price_type: PriceType = .dynamic,
    price_table: [opt_size]Optimal = undefined,
    match_table: [opt_size]Match = undefined,
};

// ---------------------------------------------------------------------------
// Statistics and prices

inline fn highbit32(v: u32) u32 {
    return 31 - @as(u32, @clz(v));
}

fn bitWeight(stat: u32) u32 {
    return highbit32(stat + 1) * bitcost_multiplier;
}

/// `ZSTD_fracWeight`: log2 with a linear fraction, in 1/256 bit.
fn fracWeight(raw_stat: u32) u32 {
    const stat = raw_stat + 1;
    const hb = highbit32(stat);
    const b_weight = hb * bitcost_multiplier;
    const f_weight = (stat << bitcost_accuracy) >> @intCast(hb);
    return b_weight + f_weight;
}

inline fn weight(stat: u32, comptime opt_level: u32) u32 {
    return if (opt_level != 0) fracWeight(stat) else bitWeight(stat);
}

fn setBasePrices(st: *State, comptime opt_level: u32) void {
    st.lit_sum_base_price = weight(st.lit_sum, opt_level);
    st.lit_length_sum_base_price = weight(st.lit_length_sum, opt_level);
    st.match_length_sum_base_price = weight(st.match_length_sum, opt_level);
    st.off_code_sum_base_price = weight(st.off_code_sum, opt_level);
}

fn sum(table: []const u32) u32 {
    var total: u32 = 0;
    for (table) |v| total += v;
    return total;
}

/// `ZSTD_downscaleStats`.
fn downscaleStats(table: []u32, shift: u32, base_1guaranteed: bool) u32 {
    var total: u32 = 0;
    for (table) |*v| {
        const base: u32 = if (base_1guaranteed) 1 else @intFromBool(v.* > 0);
        const new_stat = base + (v.* >> @intCast(shift));
        total += new_stat;
        v.* = new_stat;
    }
    return total;
}

/// `ZSTD_scaleStats`: shrink the table's sum to about 2^log_target.
fn scaleStats(table: []u32, log_target: u32) u32 {
    const prev_sum = sum(table);
    const factor = prev_sum >> @intCast(log_target);
    if (factor <= 1) return prev_sum;
    return downscaleStats(table, highbit32(factor), true);
}

const base_ll_freqs = [max_ll + 1]u32{
    4, 2, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1,
};
const base_ofc_freqs = [max_off + 1]u32{
    6, 2, 1, 1, 2, 3, 4, 4,
    4, 3, 2, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
};

/// `ZSTD_rescaleFreqs` (no dictionary: the `HUF_repeat_valid` seeding from
/// dictionary tables does not arise). Literal compression is never disabled
/// for these strategies.
fn rescaleFreqs(st: *State, src: []const u8, comptime opt_level: u32) void {
    st.price_type = .dynamic;
    if (st.lit_length_sum == 0) { // no statistics yet: first block
        if (src.len <= predef_threshold) st.price_type = .predef;
        // literals: histogram of the block, downscaled
        @memset(&st.lit_freq, 0);
        for (src) |b| st.lit_freq[b] += 1;
        st.lit_sum = downscaleStats(&st.lit_freq, 8, false);
        st.lit_length_freq = base_ll_freqs;
        st.lit_length_sum = sum(&base_ll_freqs);
        @memset(&st.match_length_freq, 1);
        st.match_length_sum = max_ml + 1;
        st.off_code_freq = base_ofc_freqs;
        st.off_code_sum = sum(&base_ofc_freqs);
    } else {
        // new block: keep the previous statistics, scaled down
        st.lit_sum = scaleStats(&st.lit_freq, 12);
        st.lit_length_sum = scaleStats(&st.lit_length_freq, 11);
        st.match_length_sum = scaleStats(&st.match_length_freq, 11);
        st.off_code_sum = scaleStats(&st.off_code_freq, 11);
    }
    setBasePrices(st, opt_level);
}

/// `ZSTD_rawLiteralsCost` for one literal.
inline fn literalPrice(st: *const State, lit: u8, comptime opt_level: u32) i32 {
    if (st.price_type == .predef) return 6 * bitcost_multiplier;
    const lit_price_max = st.lit_sum_base_price - bitcost_multiplier;
    var lit_price = weight(st.lit_freq[lit], opt_level);
    if (lit_price > lit_price_max) lit_price = lit_price_max;
    return @intCast(st.lit_sum_base_price - lit_price);
}

/// `ZSTD_litLengthPrice`.
fn litLengthPrice(st: *const State, lit_length: u32, comptime opt_level: u32) i32 {
    if (st.price_type == .predef) return @intCast(weight(lit_length, opt_level));
    // ZSTD_BLOCKSIZE_MAX has no code of its own: price it as one bit more
    // than the longest length that has
    if (lit_length == block_size_max) return bitcost_multiplier + litLengthPrice(st, block_size_max - 1, opt_level);
    const ll_code = sequences.llCode(lit_length);
    return @intCast(@as(u32, sequences.ll_bits[ll_code]) * bitcost_multiplier + st.lit_length_sum_base_price - weight(st.lit_length_freq[ll_code], opt_level));
}

/// `LL_INCPRICE`: the cost of one more literal in the run.
inline fn litLengthIncPrice(st: *const State, lit_length: u32, comptime opt_level: u32) i32 {
    return litLengthPrice(st, lit_length, opt_level) - litLengthPrice(st, lit_length - 1, opt_level);
}

/// `ZSTD_getMatchPrice`: offset and match length, without the literal length.
inline fn matchPrice(st: *const State, off_base: u32, match_length: u32, comptime opt_level: u32) i32 {
    const off_code = highbit32(off_base);
    const ml_base = match_length - sequences.min_match;
    if (st.price_type == .predef)
        return @intCast(weight(ml_base, opt_level) + (16 + off_code) * bitcost_multiplier);
    // dynamic statistics
    var price: u32 = off_code * bitcost_multiplier + (st.off_code_sum_base_price - weight(st.off_code_freq[off_code], opt_level));
    // handicap for long distance offsets, favoring decompression speed
    if (opt_level < 2 and off_code >= 20) price += (off_code - 19) * 2 * bitcost_multiplier;
    const ml_code = sequences.mlCode(ml_base);
    price += @as(u32, sequences.ml_bits[ml_code]) * bitcost_multiplier + (st.match_length_sum_base_price - weight(st.match_length_freq[ml_code], opt_level));
    price += bitcost_multiplier / 5; // heuristic: make matchLength 3 more expensive
    return @intCast(price);
}

/// `ZSTD_updateStats`.
fn updateStats(st: *State, lits: []const u8, off_base: u32, match_length: u32) void {
    for (lits) |b| st.lit_freq[b] += lit_freq_add;
    st.lit_sum += @as(u32, @intCast(lits.len)) * lit_freq_add;
    st.lit_length_freq[sequences.llCode(@intCast(lits.len))] += 1;
    st.lit_length_sum += 1;
    st.off_code_freq[highbit32(off_base)] += 1;
    st.off_code_sum += 1;
    st.match_length_freq[sequences.mlCode(match_length - sequences.min_match)] += 1;
    st.match_length_sum += 1;
}

/// `ZSTD_updateRep`: the offset history after a sequence with `off_base`.
pub fn newRep(rep_in: [3]u32, off_base: u32, ll0: bool) [3]u32 {
    var rep = rep_in;
    if (off_base > sequences.rep_num) { // full offset
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - sequences.rep_num;
    } else { // repcode
        const rep_code = off_base - 1 + @intFromBool(ll0);
        if (rep_code > 0) { // note: if rep_code == 0, no change
            const current_offset = if (rep_code == sequences.rep_num) rep[0] - 1 else rep[rep_code];
            if (rep_code >= 2) rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = current_offset;
        }
    }
    return rep;
}

// ---------------------------------------------------------------------------
// Binary tree match finder

/// `ZSTD_getLowestMatchIndex` without a dictionary.
inline fn lowestMatchIndex(ms: *const MatchState, curr: u32) u32 {
    const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
    const lowest_valid = ms.low_limit;
    return if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
}

inline fn btMask(ms: *const MatchState) u32 {
    return (@as(u32, 1) << @intCast(ms.cp.chain_log - 1)) - 1;
}

/// `ZSTD_readMINMATCH(ip) == ZSTD_readMINMATCH(dictBase + rep_index)`.
inline fn readMinMatchDict(ms: *const MatchState, curr: usize, rep_index: usize, dict_limit: u32, comptime length: u32) bool {
    std.debug.assert(rep_index < dict_limit);
    const a = ms.read32(curr);
    const b = ms.read32Seg(rep_index, dict_limit);
    return if (length == 3) a << 8 == b << 8 else a == b;
}

/// `ZSTD_readMINMATCH`: the first 3 or 4 bytes, comparable as one number.
inline fn readMinMatch(ms: *const MatchState, idx: usize, comptime length: u32) u32 {
    return if (length == 3) ms.read32(idx) << 8 else ms.read32(idx);
}

/// `ZSTD_hash3Ptr`.
inline fn hash3(ms: *const MatchState, idx: usize, h_bits: u32) usize {
    const prime3bytes: u32 = 506832829;
    return ((ms.read32(idx) << (32 - 24)) *% prime3bytes) >> @intCast(32 - h_bits);
}

/// `ZSTD_insertAndFindFirstIndexHash3`.
fn insertAndFindFirstIndexHash3(ms: *MatchState, next_to_update3: *u32, ip: u32) u32 {
    const table3 = ms.hash_table3;
    const hash_log3 = ms.hash_log3;
    var idx = next_to_update3.*;
    while (idx < ip) : (idx += 1) table3[hash3(ms, idx, hash_log3)] = idx;
    next_to_update3.* = ip;
    return table3[hash3(ms, ip, hash_log3)];
}

/// The byte at index `idx`: from the extDict below `dict_limit` when `ext`.
inline fn byteAt(ms: *const MatchState, idx: usize, dict_limit: u32, comptime ext: bool) u8 {
    return if (ext) ms.atSeg(idx, dict_limit) else ms.at(idx);
}

/// `ZSTD_count` from `curr` against the candidate at `match_index` (both
/// `match_length` bytes in): with an extDict (`ext`) a candidate below its
/// end counts on into the prefix.
inline fn countFrom(ms: *const MatchState, curr: usize, match_index: usize, match_length: usize, iend: usize, dict_limit: u32, comptime ext: bool) usize {
    if (!ext or match_index + match_length >= dict_limit)
        return ms.count(curr + match_length, match_index + match_length, iend);
    return ms.count2Segments(curr + match_length, match_index + match_length, iend, dict_limit, dict_limit);
}

/// `ZSTD_insertBt1` (noDict, or extDict when `ext`): sort `curr`, which is
/// in the prefix, into the tree. Returns how many positions the caller may
/// skip (more than 1 inside long repetitions).
fn insertBt1(ms: *MatchState, curr: u32, iend: usize, target: u32, comptime mls: u32, comptime ext: bool) u32 {
    const dict_limit = ms.dict_limit;
    const hash_table = ms.hash_table;
    const h = ms.hash(curr, ms.cp.hash_log, mls);
    const bt = ms.chain_table;
    const bt_mask = btMask(ms);
    var match_index = hash_table[h];
    var common_length_smaller: usize = 0;
    var common_length_larger: usize = 0;
    const bt_low: u32 = if (bt_mask >= curr) 0 else curr - bt_mask;
    const slot = 2 * @as(usize, curr & bt_mask);
    var smaller_ptr: *u32 = &bt[slot];
    var larger_ptr: *u32 = &bt[slot + 1];
    var dummy32: u32 = undefined; // to be nullified at the end
    // windowLow is based on target because we only need positions that will
    // be in the window at the end of the tree update
    const window_low = lowestMatchIndex(ms, target);
    var match_end_idx: u32 = curr + 8 + 1;
    var best_length: usize = 8;
    var nb_compares: u32 = @as(u32, 1) << @intCast(ms.cp.search_log);

    std.debug.assert(curr <= target);
    hash_table[h] = curr; // Update Hash Table

    while (nb_compares > 0 and match_index >= window_low) : (nb_compares -= 1) {
        const next_slot = 2 * @as(usize, match_index & bt_mask);
        var match_length = @min(common_length_smaller, common_length_larger); // guaranteed minimum nb of common bytes
        std.debug.assert(match_index < curr);
        match_length += countFrom(ms, curr, match_index, match_length, iend, dict_limit, ext);

        if (match_length > best_length) {
            best_length = match_length;
            if (match_length > match_end_idx - match_index)
                match_end_idx = match_index + @as(u32, @intCast(match_length));
        }

        // equal: no way to know if inf or sup. Drop, to guarantee consistency;
        // miss a bit of compression, but other solutions can corrupt the tree.
        if (curr + match_length == iend) break;

        if (byteAt(ms, match_index + match_length, dict_limit, ext) < ms.at(curr + match_length)) {
            // match is smaller than current
            smaller_ptr.* = match_index; // update smaller idx
            common_length_smaller = match_length; // all smaller will now have at least this guaranteed common length
            if (match_index <= bt_low) { // beyond tree size, stop searching
                smaller_ptr = &dummy32;
                break;
            }
            smaller_ptr = &bt[next_slot + 1]; // new "candidate" => larger than match, which was smaller than target
            match_index = bt[next_slot + 1]; // new matchIndex, larger than previous and closer to current
        } else {
            // match is larger than current
            larger_ptr.* = match_index;
            common_length_larger = match_length;
            if (match_index <= bt_low) { // beyond tree size, stop searching
                larger_ptr = &dummy32;
                break;
            }
            larger_ptr = &bt[next_slot];
            match_index = bt[next_slot];
        }
    }
    smaller_ptr.* = 0;
    larger_ptr.* = 0;

    var positions: u32 = 0;
    if (best_length > 384) positions = @min(192, @as(u32, @intCast(best_length - 384))); // speed optimization
    std.debug.assert(match_end_idx > curr + 8);
    return @max(positions, match_end_idx - (curr + 8));
}

/// `ZSTD_updateTree_internal`: insert every position up to `ip`.
fn updateTree(ms: *MatchState, ip: u32, iend: usize, comptime mls: u32, comptime ext: bool) void {
    var idx = ms.next_to_update;
    while (idx < ip) idx += insertBt1(ms, idx, iend, ip, mls, ext);
    ms.next_to_update = ip;
}

/// `ZSTD_insertBtAndGetAllMatches` (noDict, or extDict when `ext`): insert
/// `curr` and list its matches, each longer than the one before, into
/// `matches`. Returns how many.
fn insertBtAndGetAllMatches(matches: []Match, ms: *MatchState, next_to_update3: *u32, curr: u32, i_limit: usize, rep: *const [3]u32, ll0: bool, length_to_beat: u32, comptime mls: u32, comptime ext: bool) u32 {
    const sufficient_len = @min(ms.cp.target_length, opt_num - 1);
    const min_match: u32 = if (mls == 3) 3 else 4;
    const hash_table = ms.hash_table;
    const h = ms.hash(curr, ms.cp.hash_log, mls);
    var match_index = hash_table[h];
    const bt = ms.chain_table;
    const bt_mask = btMask(ms);
    var common_length_smaller: usize = 0;
    var common_length_larger: usize = 0;
    const dict_limit = ms.dict_limit;
    const bt_low: u32 = if (bt_mask >= curr) 0 else curr - bt_mask;
    const window_low = lowestMatchIndex(ms, curr);
    const match_low = if (window_low != 0) window_low else 1;
    const slot = 2 * @as(usize, curr & bt_mask);
    var smaller_ptr: *u32 = &bt[slot];
    var larger_ptr: *u32 = &bt[slot + 1];
    var match_end_idx: u32 = curr + 8 + 1; // farthest referenced position of any match => detects repetitive patterns
    var dummy32: u32 = undefined; // to be nullified at the end
    var mnum: u32 = 0;
    var nb_compares: u32 = @as(u32, 1) << @intCast(ms.cp.search_log);
    var best_length: usize = length_to_beat - 1;

    // check repCode
    {
        const last_r = sequences.rep_num + @as(u32, @intFromBool(ll0));
        var rep_code: u32 = @intFromBool(ll0);
        while (rep_code < last_r) : (rep_code += 1) {
            const rep_offset = if (rep_code == sequences.rep_num) rep[0] -% 1 else rep[rep_code];
            const rep_index = curr -% rep_offset;
            var rep_len: u32 = 0;
            std.debug.assert(curr >= dict_limit);
            // equivalent to `curr > repIndex >= dictLimit`; intentional overflow
            if (rep_offset -% 1 < curr - dict_limit) {
                // We must validate the repcode offset because when we're using
                // a dictionary the valid offset range shrinks when the
                // dictionary goes out of bounds.
                if (rep_index >= window_low and readMinMatch(ms, curr, min_match) == readMinMatch(ms, curr - rep_offset, min_match)) {
                    rep_len = @intCast(ms.count(curr + min_match, curr + min_match - rep_offset, i_limit) + min_match);
                }
            } else if (ext) { // repIndex < dictLimit || repIndex >= curr
                std.debug.assert(curr >= window_low);
                // `curr > repIndex >= windowLow`, and the bytes do not
                // straddle the extDict's end
                if (rep_offset -% 1 < curr - window_low and match.indexOverlapCheck(dict_limit, rep_index) and
                    readMinMatchDict(ms, curr, rep_index, dict_limit, min_match))
                {
                    rep_len = @intCast(ms.count2Segments(@as(usize, curr) + min_match, @as(usize, rep_index) + min_match, i_limit, dict_limit, dict_limit) + min_match);
                }
            }
            if (rep_len > best_length) {
                best_length = rep_len;
                matches[mnum] = .{ .off = rep_code - @intFromBool(ll0) + 1, .len = rep_len }; // REPCODE_TO_OFFBASE
                mnum += 1;
                if (rep_len > sufficient_len or curr + rep_len == i_limit) { // best possible
                    return mnum;
                }
            }
        }
    }

    // HC3 match finder
    if (mls == 3 and best_length < mls) {
        const match_index3 = insertAndFindFirstIndexHash3(ms, next_to_update3, curr);
        // heuristic: longer distance likely too expensive
        if (match_index3 >= match_low and curr - match_index3 < (1 << 18)) {
            const mlen = if (!ext or match_index3 >= dict_limit)
                ms.count(curr, match_index3, i_limit)
            else
                ms.count2Segments(curr, match_index3, i_limit, dict_limit, dict_limit);
            if (mlen >= mls) {
                best_length = mlen;
                std.debug.assert(curr > match_index3);
                std.debug.assert(mnum == 0); // no prior solution
                matches[0] = .{ .off = curr - match_index3 + sequences.rep_num, .len = @intCast(mlen) };
                mnum = 1;
                if (mlen > sufficient_len or curr + mlen == i_limit) { // best possible length
                    ms.next_to_update = curr + 1; // skip insertion
                    return 1;
                }
            }
        }
        // no dictMatchState lookup: dicts don't have a table3
    }

    hash_table[h] = curr; // Update Hash Table

    while (nb_compares > 0 and match_index >= match_low) : (nb_compares -= 1) {
        const next_slot = 2 * @as(usize, match_index & bt_mask);
        var match_length = @min(common_length_smaller, common_length_larger); // guaranteed minimum nb of common bytes
        std.debug.assert(curr > match_index);
        match_length += countFrom(ms, curr, match_index, match_length, i_limit, dict_limit, ext);

        if (match_length > best_length) {
            std.debug.assert(match_end_idx > match_index);
            if (match_length > match_end_idx - match_index)
                match_end_idx = match_index + @as(u32, @intCast(match_length));
            best_length = match_length;
            matches[mnum] = .{ .off = curr - match_index + sequences.rep_num, .len = @intCast(match_length) };
            mnum += 1;
            // equal: no way to know if inf or sup; also prevents overflow
            if (match_length > opt_num or curr + match_length == i_limit) break; // drop, to preserve bt consistency (miss a little bit of compression)
        }

        if (byteAt(ms, match_index + match_length, dict_limit, ext) < ms.at(curr + match_length)) {
            // match smaller than current
            smaller_ptr.* = match_index; // update smaller idx
            common_length_smaller = match_length; // all smaller will now have at least this guaranteed common length
            if (match_index <= bt_low) { // beyond tree size, stop the search
                smaller_ptr = &dummy32;
                break;
            }
            smaller_ptr = &bt[next_slot + 1]; // new candidate => larger than match, which was smaller than current
            match_index = bt[next_slot + 1]; // new matchIndex, larger than previous, closer to current
        } else {
            larger_ptr.* = match_index;
            common_length_larger = match_length;
            if (match_index <= bt_low) { // beyond tree size, stop the search
                larger_ptr = &dummy32;
                break;
            }
            larger_ptr = &bt[next_slot];
            match_index = bt[next_slot];
        }
    }
    smaller_ptr.* = 0;
    larger_ptr.* = 0;

    std.debug.assert(match_end_idx > curr + 8);
    ms.next_to_update = match_end_idx - 8; // skip repetitive patterns
    return mnum;
}

/// `ZSTD_btGetAllMatches_internal`.
inline fn getAllMatches(matches: []Match, ms: *MatchState, next_to_update3: *u32, ip: u32, i_high_limit: usize, rep: *const [3]u32, ll0: bool, length_to_beat: u32, comptime mls: u32, comptime ext: bool) u32 {
    if (ip < ms.next_to_update) return 0; // skipped area
    updateTree(ms, ip, i_high_limit, mls, ext);
    return insertBtAndGetAllMatches(matches, ms, next_to_update3, ip, i_high_limit, rep, ll0, length_to_beat, mls, ext);
}

// ---------------------------------------------------------------------------
// Long-distance match candidates

/// `ZSTD_optLdm_t`: a private copy of the block's LDM sequences and the one
/// match candidate they currently offer, as block positions.
const OptLdm = struct {
    store: ldm.RawSeqStore,
    start_pos_in_block: u32 = 0,
    end_pos_in_block: u32 = 0,
    offset: u32 = 0,

    fn exhausted(o: *const OptLdm) bool {
        return o.store.size == 0 or o.store.pos >= o.store.size;
    }

    /// `ZSTD_opt_getNextMatchAndUpdateSeqStore`: the next candidate's start
    /// and end in the block, consuming it from the store.
    fn getNextMatch(o: *OptLdm, curr_pos_in_block: u32, block_bytes_remaining: u32) void {
        // Setting match end position to MAX to ensure we never use an LDM during this block
        if (o.exhausted()) {
            o.start_pos_in_block = std.math.maxInt(u32);
            o.end_pos_in_block = std.math.maxInt(u32);
            return;
        }
        const curr = o.store.seq[o.store.pos];
        std.debug.assert(o.store.pos_in_sequence <= curr.lit_length + curr.match_length);
        const pos_in_seq: u32 = @intCast(o.store.pos_in_sequence);
        const curr_block_end_pos = curr_pos_in_block + block_bytes_remaining;
        const literals_bytes_remaining = if (pos_in_seq < curr.lit_length) curr.lit_length - pos_in_seq else 0;
        const match_bytes_remaining = if (literals_bytes_remaining == 0) curr.match_length - (pos_in_seq - curr.lit_length) else curr.match_length;

        // If there are more literal bytes than bytes remaining in block, no ldm is possible
        if (literals_bytes_remaining >= block_bytes_remaining) {
            o.start_pos_in_block = std.math.maxInt(u32);
            o.end_pos_in_block = std.math.maxInt(u32);
            o.store.skipBytes(block_bytes_remaining);
            return;
        }

        // Matches may be < minMatch by this process. In that case, we will
        // reject them when we are deciding whether or not to add the ldm
        o.start_pos_in_block = curr_pos_in_block + literals_bytes_remaining;
        o.end_pos_in_block = o.start_pos_in_block + match_bytes_remaining;
        o.offset = curr.offset;

        if (o.end_pos_in_block > curr_block_end_pos) {
            // Match ends after the block ends, we can't use the whole match
            o.end_pos_in_block = curr_block_end_pos;
            o.store.skipBytes(curr_block_end_pos - curr_pos_in_block);
        } else {
            // Consume nb of bytes equal to size of sequence left
            o.store.skipBytes(literals_bytes_remaining + match_bytes_remaining);
        }
    }

    /// `ZSTD_optLdm_maybeAddMatch`: append the candidate if the position is
    /// inside it, it is long enough, and it is longer than every match found.
    fn maybeAddMatch(o: *const OptLdm, matches: []Match, nb_matches: *u32, curr_pos_in_block: u32, min_match: u32) void {
        const pos_diff = curr_pos_in_block -% o.start_pos_in_block;
        const candidate_match_length = o.end_pos_in_block -% o.start_pos_in_block -% pos_diff;
        // Ensure that current block position is not outside of the match
        if (curr_pos_in_block < o.start_pos_in_block or
            curr_pos_in_block >= o.end_pos_in_block or
            candidate_match_length < min_match) return;
        const n = nb_matches.*;
        if (n == 0 or (candidate_match_length > matches[n - 1].len and n < opt_num)) {
            matches[n] = .{ .len = candidate_match_length, .off = o.offset + sequences.rep_num };
            nb_matches.* = n + 1;
        }
    }

    /// `ZSTD_optLdm_processMatchCandidate`. Note that the candidate taken
    /// from the store's last sequence is never offered: consuming it leaves
    /// the store exhausted, and that returns early (as in libzstd).
    fn processMatchCandidate(o: *OptLdm, matches: []Match, nb_matches: *u32, curr_pos_in_block: u32, remaining_bytes: u32, min_match: u32) void {
        if (o.exhausted()) return;
        if (curr_pos_in_block >= o.end_pos_in_block) {
            if (curr_pos_in_block > o.end_pos_in_block) {
                // The parser is often some bytes past the candidate's end:
                // correct for the overshoot.
                o.store.skipBytes(curr_pos_in_block - o.end_pos_in_block);
            }
            o.getNextMatch(curr_pos_in_block, remaining_bytes);
        }
        o.maybeAddMatch(matches, nb_matches, curr_pos_in_block, min_match);
    }
};

// ---------------------------------------------------------------------------
// Parser

/// Compress one block with `btopt` (`opt_level` 0) or `btultra` (2).
pub fn compressBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime opt_level: u32) usize {
    if (ms.hasExtDict()) ms.n_ext_dict_blocks += 1;
    return switch (std.math.clamp(ms.cp.min_match, 3, 6)) {
        inline 3, 4, 5, 6 => |m| if (ms.hasExtDict())
            optGeneric(ms, ss, rep, istart, src_size, opt_level, m, true)
        else
            optGeneric(ms, ss, rep, istart, src_size, opt_level, m, false),
        else => unreachable,
    };
}

/// `ZSTD_compressBlock_btultra2`: on the first block of a frame, run the
/// parser once only to seed the statistics, then forget its matches.
pub fn compressBlockUltra2(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32) usize {
    const st = ms.opt.?;
    if (st.lit_length_sum == 0 and // first block
        ss.n_seq == 0 and // no ldm
        ms.dict_limit == ms.low_limit and // no dictionary
        istart == ms.dict_limit and // start of frame, nothing already loaded nor skipped
        src_size > predef_threshold)
    {
        initStatsUltra(ms, ss, rep, istart, src_size);
    }
    return compressBlock(ms, ss, rep, istart, src_size, 2);
}

/// `ZSTD_initStats_ultra`: a first pass whose sequences are thrown away but
/// whose statistics stay. libzstd then invalidates the whole block for match
/// finding by moving the window base back by `src_size`, so every index
/// already in a table falls below the new low limit. Every index comparison
/// the finders make is relative to the window limits, so emptying the tables
/// and restarting insertion at the block is the same.
fn initStatsUltra(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32) void {
    var tmp_rep = rep.*;
    std.debug.assert(ms.opt.?.lit_length_sum == 0);
    std.debug.assert(ss.n_seq == 0);
    std.debug.assert(ms.dict_limit == ms.low_limit);
    std.debug.assert(ms.dict_limit - ms.next_to_update <= 1);
    _ = compressBlock(ms, ss, &tmp_rep, istart, src_size, 2); // generate stats into ms.opt
    // invalidate first scan from history, only keep entropy stats
    ss.reset();
    @memset(ms.hash_table, 0);
    @memset(ms.chain_table, 0);
    @memset(ms.hash_table3, 0);
    ms.next_to_update = ms.dict_limit;
}

/// `ZSTD_compressBlock_opt_generic` (noDict).
fn optGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime opt_level: u32, comptime mls: u32, comptime ext: bool) usize {
    const st = ms.opt.?;
    var ip: u32 = istart;
    var anchor: u32 = istart;
    const iend: usize = @as(usize, istart) + src_size;
    // signed: a short block puts the limit before the block start
    const ilimit: i64 = @as(i64, @intCast(iend)) - 8;
    const prefix_start = ms.dict_limit;
    const sufficient_len: u32 = @min(ms.cp.target_length, opt_num - 1);
    const min_match: u32 = if (ms.cp.min_match == 3) 3 else 4;
    var next_to_update3 = ms.next_to_update;
    const opt = &st.price_table;
    const matches = &st.match_table;
    var last_stretch: Optimal = .{};
    var opt_ldm: OptLdm = .{ .store = if (ms.ldm_seq_store) |s| s.* else .{} };
    opt_ldm.getNextMatch(ip - istart, @intCast(iend - ip));

    rescaleFreqs(st, ms.bytes(istart, istart + src_size), opt_level);
    ip += @intFromBool(ip == prefix_start);

    // Match Loop
    while (@as(i64, ip) < ilimit) {
        var cur: u32 = 0;
        var last_pos: u32 = 0;

        shortest_path: {
            // find first match
            {
                const litlen = ip - anchor;
                const ll0 = litlen == 0;
                var nb_matches = getAllMatches(matches, ms, &next_to_update3, ip, iend, rep, ll0, min_match, mls, ext);
                opt_ldm.processMatchCandidate(matches, &nb_matches, ip - istart, @intCast(iend - ip), min_match);
                if (nb_matches == 0) {
                    ip += 1;
                    continue;
                }

                // Match found: let's store this solution, and eventually find more candidates.
                // During this forward pass, @opt is used to store stretches,
                // defined as "a match followed by N literals".
                opt[0].mlen = 0; // there are only literals so far
                opt[0].litlen = litlen;
                // No need to include the actual price of the literals before
                // the segment: it's the same for all paths, as long as it
                // includes the literal length price.
                opt[0].price = litLengthPrice(st, litlen, opt_level);
                opt[0].rep = rep.*;

                // large match -> immediate encoding
                {
                    const max_len = matches[nb_matches - 1].len;
                    const max_off_base = matches[nb_matches - 1].off;
                    if (max_len > sufficient_len) {
                        last_stretch.litlen = 0;
                        last_stretch.mlen = max_len;
                        last_stretch.off = max_off_base;
                        cur = 0;
                        last_pos = max_len;
                        break :shortest_path;
                    }
                }

                // set prices for first matches starting position == 0
                std.debug.assert(opt[0].price >= 0);
                var pos: u32 = 1;
                while (pos < min_match) : (pos += 1) {
                    opt[pos].price = max_price;
                    opt[pos].mlen = 0;
                    opt[pos].litlen = litlen + pos;
                }
                for (matches[0..nb_matches]) |m| {
                    const off_base = m.off;
                    const end = m.len;
                    while (pos <= end) : (pos += 1) {
                        const match_price = matchPrice(st, off_base, pos, opt_level);
                        const sequence_price = opt[0].price + match_price;
                        opt[pos].mlen = pos;
                        opt[pos].off = off_base;
                        opt[pos].litlen = 0; // end of match
                        opt[pos].price = sequence_price + litLengthPrice(st, 0, opt_level);
                    }
                }
                last_pos = pos - 1;
                opt[pos].price = max_price;
            }

            // check further positions
            cur = 1;
            while (cur <= last_pos) : (cur += 1) {
                const inr = ip + cur;
                std.debug.assert(cur <= opt_num);

                // Fix current position with one literal if cheaper
                {
                    const litlen = opt[cur - 1].litlen + 1;
                    const price = opt[cur - 1].price + literalPrice(st, ms.at(ip + cur - 1), opt_level) + litLengthIncPrice(st, litlen, opt_level);
                    std.debug.assert(price < 1000000000); // overflow check
                    if (price <= opt[cur].price) {
                        const prev_match = opt[cur];
                        opt[cur] = opt[cur - 1];
                        opt[cur].litlen = litlen;
                        opt[cur].price = price;
                        if (opt_level >= 1 and // only in btultra mode
                            prev_match.litlen == 0 and // replacing a match
                            litLengthIncPrice(st, 1, opt_level) < 0 and // ll1 is cheaper than ll0
                            ip + cur < iend)
                        {
                            // check next position, in case it would be cheaper
                            const with1literal = prev_match.price + literalPrice(st, ms.at(ip + cur), opt_level) + litLengthIncPrice(st, 1, opt_level);
                            const with_more_literals = price + literalPrice(st, ms.at(ip + cur), opt_level) + litLengthIncPrice(st, litlen + 1, opt_level);
                            if (with1literal < with_more_literals and with1literal < opt[cur + 1].price) {
                                // update offset history - before it disappears
                                const prev = cur - prev_match.mlen;
                                const new_reps = newRep(opt[prev].rep, prev_match.off, opt[prev].litlen == 0);
                                std.debug.assert(cur >= prev_match.mlen);
                                opt[cur + 1] = prev_match; // mlen & offbase
                                opt[cur + 1].rep = new_reps;
                                opt[cur + 1].litlen = 1;
                                opt[cur + 1].price = with1literal;
                                if (last_pos < cur + 1) last_pos = cur + 1;
                            }
                        }
                    }
                }

                // Offset history is not updated during match comparison.
                // Do it here, now that the match is selected and confirmed.
                std.debug.assert(cur >= opt[cur].mlen);
                if (opt[cur].litlen == 0) {
                    // just finished a match => alter offset history
                    const prev = cur - opt[cur].mlen;
                    opt[cur].rep = newRep(opt[prev].rep, opt[cur].off, opt[prev].litlen == 0);
                }

                // last match must start at a minimum distance of 8 from oend
                if (@as(i64, inr) > ilimit) continue;

                if (cur == last_pos) break;

                if (opt_level == 0 and opt[cur + 1].price <= opt[cur].price + (bitcost_multiplier / 2)) {
                    continue; // skip unpromising positions; about ~+6% speed, -0.01 ratio
                }

                std.debug.assert(opt[cur].price >= 0);
                {
                    const ll0 = opt[cur].litlen == 0;
                    const previous_price = opt[cur].price;
                    const base_price = previous_price + litLengthPrice(st, 0, opt_level);
                    var nb_matches = getAllMatches(matches, ms, &next_to_update3, inr, iend, &opt[cur].rep, ll0, min_match, mls, ext);
                    opt_ldm.processMatchCandidate(matches, &nb_matches, inr - istart, @intCast(iend - inr), min_match);
                    if (nb_matches == 0) continue;

                    {
                        const longest_ml = matches[nb_matches - 1].len;
                        if (longest_ml > sufficient_len or cur + longest_ml >= opt_num or ip + cur + longest_ml >= iend) {
                            last_stretch.mlen = longest_ml;
                            last_stretch.off = matches[nb_matches - 1].off;
                            last_stretch.litlen = 0;
                            last_pos = cur + longest_ml;
                            break :shortest_path;
                        }
                    }

                    // set prices using matches found at position == cur
                    for (matches[0..nb_matches], 0..) |m, match_nb| {
                        const offset = m.off;
                        const last_ml = m.len;
                        const start_ml = if (match_nb > 0) matches[match_nb - 1].len + 1 else min_match;
                        var mlen = last_ml;
                        while (mlen >= start_ml) : (mlen -= 1) { // scan downward
                            const pos = cur + mlen;
                            const price = base_price + matchPrice(st, offset, mlen, opt_level);
                            if (pos > last_pos or price < opt[pos].price) {
                                while (last_pos < pos) {
                                    // fill empty positions, for future comparisons
                                    last_pos += 1;
                                    opt[last_pos].price = max_price;
                                    opt[last_pos].litlen = 1; // just needs to be != 0, to mean "not an end of match"
                                }
                                opt[pos].mlen = mlen;
                                opt[pos].off = offset;
                                opt[pos].litlen = 0;
                                opt[pos].price = price;
                            } else {
                                if (opt_level == 0) break; // early update abort; gets ~+10% speed for about -0.01 ratio loss
                            }
                        }
                    }
                }
                opt[last_pos + 1].price = max_price;
            } // for (cur = 1; cur <= last_pos; cur++)

            last_stretch = opt[last_pos];
            std.debug.assert(cur >= last_stretch.mlen);
            cur = last_pos - last_stretch.mlen;
        }

        // _shortestPath: cur, last_pos, last_stretch have to be set
        std.debug.assert(opt[0].mlen == 0);
        std.debug.assert(last_pos >= last_stretch.mlen);
        std.debug.assert(cur == last_pos - last_stretch.mlen);

        if (last_stretch.mlen == 0) {
            // no solution: all matches have been converted into literals
            std.debug.assert(last_stretch.litlen == (ip - anchor) + last_pos);
            ip += last_pos;
            continue;
        }
        std.debug.assert(last_stretch.off > 0);

        // Update offset history
        if (last_stretch.litlen == 0) {
            // finishing on a match: update offset history
            rep.* = newRep(opt[cur].rep, last_stretch.off, opt[cur].litlen == 0);
        } else {
            rep.* = last_stretch.rep;
            std.debug.assert(cur >= last_stretch.litlen);
            cur -= last_stretch.litlen;
        }

        // Let's write the shortest path solution. It is stored in @opt in
        // reverse order, starting from @storeEnd (==cur+2), effectively
        // partially @opt overwriting. Content is changed too: each opt[pos]
        // now contains the match which *starts* at pos, followed by literals.
        {
            const store_end = cur + 2;
            var store_start = store_end;
            var stretch_pos = cur;
            std.debug.assert(store_end < opt_size);
            if (last_stretch.litlen > 0) {
                // last "sequence" is unfinished: just a bunch of literals
                opt[store_end].litlen = last_stretch.litlen;
                opt[store_end].mlen = 0;
                store_start = store_end - 1;
                opt[store_start] = last_stretch;
            }
            // (libzstd: a bare block, not an else -- it always runs)
            opt[store_end] = last_stretch; // note: litlen will be fixed
            store_start = store_end;
            while (true) {
                const next_stretch = opt[stretch_pos];
                opt[store_start].litlen = next_stretch.litlen;
                if (next_stretch.mlen == 0) break; // reaching beginning of segment
                store_start -= 1;
                opt[store_start] = next_stretch; // note: litlen will be fixed
                std.debug.assert(next_stretch.litlen + next_stretch.mlen <= stretch_pos);
                stretch_pos -= next_stretch.litlen + next_stretch.mlen;
            }

            // save sequences
            var store_pos = store_start;
            while (store_pos <= store_end) : (store_pos += 1) {
                const llen = opt[store_pos].litlen;
                const mlen = opt[store_pos].mlen;
                const off_base = opt[store_pos].off;
                const advance = llen + mlen;
                if (mlen == 0) { // only literals => must be last "sequence", actually starting a new stream of sequences
                    std.debug.assert(store_pos == store_end); // must be last sequence
                    ip = anchor + llen; // last "sequence" is a bunch of literals => don't progress anchor
                    continue; // will finish
                }
                const lits = ms.bytes(anchor, anchor + llen);
                updateStats(st, lits, off_base, mlen);
                ss.store(lits, off_base, mlen);
                anchor += advance;
                ip = anchor;
            }
            setBasePrices(st, opt_level);
        }
    } // while (ip < ilimit)

    // Return the last literals size
    return iend - anchor;
}

test "fractional weights grow with the count" {
    try std.testing.expectEqual(@as(u32, 256), fracWeight(0)); // stat 1: 0 bits + 1.0
    try std.testing.expectEqual(@as(u32, 256 + 256), fracWeight(1)); // stat 2: 1 bit + 1.0
    try std.testing.expectEqual(@as(u32, 256 + 384), fracWeight(2)); // stat 3: 1 bit + 1.5
    try std.testing.expectEqual(@as(u32, 256), bitWeight(1));
}

test "a repcode 1 after literals keeps the history, a full offset shifts it" {
    try std.testing.expectEqual([3]u32{ 1, 4, 8 }, newRep(.{ 1, 4, 8 }, 1, false));
    try std.testing.expectEqual([3]u32{ 100, 1, 4 }, newRep(.{ 1, 4, 8 }, 100 + sequences.rep_num, false));
    // with no literals, repcode 1 means rep[1]
    try std.testing.expectEqual([3]u32{ 4, 1, 8 }, newRep(.{ 1, 4, 8 }, 1, true));
    // repcode 3 with no literals means rep[0] - 1
    try std.testing.expectEqual([3]u32{ 9, 10, 4 }, newRep(.{ 10, 4, 8 }, 3, true));
}
