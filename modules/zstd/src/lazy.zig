// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Match finders for the `greedy`, `lazy`, `lazy2` and `btlazy2` strategies.
//!
//! Port of the no-dictionary paths of libzstd lib/compress/zstd_lazy.c
//! (v1.5.7): the hash-chain finder (`ZSTD_HcFindBestMatch`), the row-based
//! finder (`ZSTD_RowFindBestMatch`), the lazily sorted binary tree of
//! `btlazy2` (`ZSTD_BtFindBestMatch`, "DUBT") and the parser that all three
//! feed (`ZSTD_compressBlock_lazy_generic`). libzstd picks the row finder over
//! the hash chain whenever the window is larger than 16 KB, so both are needed
//! for every level of `greedy`..`lazy2`.
//!
//! The row finder's SIMD tag comparison is written as a plain vector compare;
//! only the set of matching slots matters, not how it is computed.

const std = @import("std");
const params = @import("params.zig");
const match = @import("match.zig");
const sequences = @import("sequences.zig");
const MatchState = match.MatchState;
const SeqStore = sequences.SeqStore;

const Method = enum { hash_chain, row, binary_tree };

/// `kLazySkippingStep`.
const lazy_skipping_step = 8;
const tag_bits = params.row_hash_tag_bits;
const tag_mask = (1 << tag_bits) - 1;
const cache_size = match.row_hash_cache_size;
const cache_mask = cache_size - 1;
/// `ZSTD_ROW_HASH_MAX_ENTRIES`.
const row_max_entries = 64;
/// Offset placeholder libzstd passes to a search that may find nothing.
const no_offset = 999999999;
/// `ZSTD_DUBT_UNSORTED_MARK`: below `window_start`, so never a real index.
const dubt_unsorted_mark = 1;

/// Compress one block with the strategy in `ms.cp` (greedy, lazy, lazy2 or
/// btlazy2).
pub fn compressBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32) usize {
    const mls = std.math.clamp(ms.cp.min_match, 4, 6);
    const depth: u32 = switch (ms.cp.strategy) {
        .greedy => 0,
        .lazy => 1,
        .lazy2 => 2,
        .btlazy2 => return switch (mls) {
            inline 4, 5, 6 => |m| lazyGeneric(ms, ss, rep, istart, src_size, .binary_tree, 2, m),
            else => unreachable,
        },
        else => unreachable,
    };
    const row = params.useRowMatchFinder(ms.cp);
    return switch (depth) {
        inline 0, 1, 2 => |d| if (row) switch (mls) {
            inline 4, 5, 6 => |m| lazyGeneric(ms, ss, rep, istart, src_size, .row, d, m),
            else => unreachable,
        } else switch (mls) {
            inline 4, 5, 6 => |m| lazyGeneric(ms, ss, rep, istart, src_size, .hash_chain, d, m),
            else => unreachable,
        },
        else => unreachable,
    };
}

// ---------------------------------------------------------------------------
// Hash chain

/// `ZSTD_insertAndFindFirstIndex_internal`: insert every position from
/// `next_to_update` up to `ip` (only one when lazily skipping) and return the
/// newest candidate for `ip`.
fn insertAndFindFirstIndex(ms: *MatchState, ip: u32, comptime mls: u32) u32 {
    const hash_table = ms.hash_table;
    const hash_log = ms.cp.hash_log;
    const chain_table = ms.chain_table;
    const chain_mask = (@as(u32, 1) << @intCast(ms.cp.chain_log)) - 1;
    var idx = ms.next_to_update;
    while (idx < ip) {
        const h = ms.hash(idx, hash_log, mls);
        chain_table[idx & chain_mask] = hash_table[h];
        hash_table[h] = idx;
        idx += 1;
        // Stop inserting every position when in the lazy skipping mode.
        if (ms.lazy_skipping) break;
    }
    ms.next_to_update = ip;
    return hash_table[ms.hash(ip, hash_log, mls)];
}

/// `ZSTD_HcFindBestMatch` (noDict). Returns the best length found (3 when
/// none reaches 4) and stores its offBase in `offset_ptr`.
fn hcFindBestMatch(ms: *MatchState, ip: u32, iend: usize, offset_ptr: *u32, comptime mls: u32) usize {
    const chain_table = ms.chain_table;
    const chain_size: u32 = @as(u32, 1) << @intCast(ms.cp.chain_log);
    const chain_mask = chain_size - 1;
    const curr = ip;
    const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
    const lowest_valid = ms.low_limit;
    const low_limit = if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    const min_chain: u32 = if (curr > chain_size) curr - chain_size else 0;
    var nb_attempts: u32 = @as(u32, 1) << @intCast(ms.cp.search_log);
    var ml: usize = 4 - 1;

    var match_index = insertAndFindFirstIndex(ms, ip, mls);
    while (match_index >= low_limit and nb_attempts > 0) : (nb_attempts -= 1) {
        var current_ml: usize = 0;
        // read 4B starting from (match + ml + 1 - sizeof(U32))
        if (ms.read32(match_index + ml - 3) == ms.read32(ip + ml - 3)) // potentially better
            current_ml = ms.count(ip, match_index, iend);
        // save best solution
        if (current_ml > ml) {
            ml = current_ml;
            offset_ptr.* = curr - match_index + sequences.rep_num;
            if (ip + current_ml == iend) break; // best possible, avoids read overflow on next attempt
        }
        if (match_index <= min_chain) break;
        match_index = chain_table[match_index & chain_mask];
    }
    return ml;
}

// ---------------------------------------------------------------------------
// Row-based match finder

/// `ZSTD_row_nextIndex`: the slot to overwrite next in a row, cycling
/// backwards through 1..rowEntries-1; slot 0 of the tag row holds the head.
inline fn rowNextIndex(tag_row: []u8, row_mask: u32) u32 {
    var next: u32 = (@as(u32, tag_row[0]) -% 1) & row_mask;
    if (next == 0) next += row_mask; // skip first position
    tag_row[0] = @intCast(next);
    return next;
}

inline fn rowHash(ms: *const MatchState, idx: usize, comptime mls: u32) u32 {
    return @intCast(ms.hashSalted(idx, ms.row_hash_log + tag_bits, mls, ms.hash_salt));
}

/// `ZSTD_row_fillHashCache`: hashes of up to 8 positions from `idx`, not
/// past `ilimit`.
fn fillHashCache(ms: *MatchState, comptime mls: u32, idx_in: u32, ilimit: i64) void {
    var idx = idx_in;
    const max_elems: u32 = if (@as(i64, idx) > ilimit) 0 else @intCast(ilimit - idx + 1);
    const lim = idx + @min(cache_size, max_elems);
    while (idx < lim) : (idx += 1) ms.hash_cache[idx & cache_mask] = rowHash(ms, idx, mls);
}

/// `ZSTD_row_nextCachedHash`: the hash of `idx`, replaced in the cache by the
/// hash of `idx + 8`.
inline fn nextCachedHash(ms: *MatchState, idx: u32, comptime mls: u32) u32 {
    const new_hash = rowHash(ms, idx + cache_size, mls);
    const h = ms.hash_cache[idx & cache_mask];
    ms.hash_cache[idx & cache_mask] = new_hash;
    return h;
}

/// `ZSTD_row_update_internalImpl` with the hash cache.
fn rowUpdateImpl(ms: *MatchState, start: u32, end: u32, comptime mls: u32, row_log: u32, row_mask: u32) void {
    var idx = start;
    while (idx < end) : (idx += 1) {
        const h = nextCachedHash(ms, idx, mls);
        const rel_row: usize = @as(usize, h >> tag_bits) << @intCast(row_log);
        const tag_row = ms.tag_table[rel_row..];
        const pos = rowNextIndex(tag_row, row_mask);
        tag_row[pos] = @truncate(h & tag_mask);
        ms.hash_table[rel_row + pos] = idx;
    }
}

/// `ZSTD_row_update_internal` (useCache): insert positions up to `ip`,
/// skipping the middle of long matches.
fn rowUpdate(ms: *MatchState, ip: u32, comptime mls: u32, row_log: u32, row_mask: u32) void {
    var idx = ms.next_to_update;
    const target = ip;
    const skip_threshold = 384;
    const max_match_start_positions_to_update = 96;
    const max_match_end_positions_to_update = 32;
    if (target -% idx > skip_threshold) {
        const bound = idx + max_match_start_positions_to_update;
        rowUpdateImpl(ms, idx, bound, mls, row_log, row_mask);
        idx = target - max_match_end_positions_to_update;
        fillHashCache(ms, mls, idx, @as(i64, ip) + 1);
    }
    rowUpdateImpl(ms, idx, target, mls, row_log, row_mask);
    ms.next_to_update = target;
}

/// Bit `i` set when slot `(head + i) % entries` of `tag_row` holds `tag`
/// (`ZSTD_row_getMatchMask`).
inline fn matchMask(comptime entries: u32, tag_row: []const u8, tag: u8, head: u32) u64 {
    const V = @Vector(entries, u8);
    const B = std.meta.Int(.unsigned, entries);
    const v: V = tag_row[0..entries].*;
    const eq: B = @bitCast(v == @as(V, @splat(tag)));
    return std.math.rotr(B, eq, head);
}

/// `ZSTD_RowFindBestMatch` (noDict).
fn rowFindBestMatch(ms: *MatchState, ip: u32, iend: usize, offset_ptr: *u32, comptime mls: u32, row_log: u32) usize {
    const curr = ip;
    const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
    const lowest_valid = ms.low_limit;
    const low_limit = if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    const row_entries: u32 = @as(u32, 1) << @intCast(row_log);
    const row_mask = row_entries - 1;
    const capped_search_log = @min(ms.cp.search_log, row_log); // nb of searches is capped at nb entries per row
    var nb_attempts: u32 = @as(u32, 1) << @intCast(capped_search_log);
    var ml: usize = 4 - 1;

    // Update the hashTable and tagTable up to (but not including) ip
    var h: u32 = undefined;
    if (!ms.lazy_skipping) {
        rowUpdate(ms, ip, mls, row_log, row_mask);
        h = nextCachedHash(ms, curr, mls);
    } else {
        // Stop inserting every position when in the lazy skipping mode. The
        // hash cache is also not kept up to date in this mode.
        h = rowHash(ms, ip, mls);
        ms.next_to_update = curr;
    }
    ms.hash_salt_entropy +%= h; // collect salt entropy

    const rel_row: usize = @as(usize, h >> tag_bits) << @intCast(row_log);
    const tag: u8 = @truncate(h & tag_mask);
    const row = ms.hash_table[rel_row..][0..row_entries];
    const tag_row = ms.tag_table[rel_row..][0..row_entries];
    const head = tag_row[0] & row_mask;
    var match_buffer: [row_max_entries]u32 = undefined;
    var num_matches: usize = 0;
    var matches: u64 = switch (row_log) {
        4 => matchMask(16, tag_row, tag, head),
        5 => matchMask(32, tag_row, tag, head),
        6 => matchMask(64, tag_row, tag, head),
        else => unreachable,
    };

    // Cycle through the matches
    while (matches > 0 and nb_attempts > 0) : (matches &= matches - 1) {
        const match_pos = (head + @as(u32, @ctz(matches))) & row_mask;
        const match_index = row[match_pos];
        if (match_pos == 0) continue;
        if (match_index < low_limit) break;
        match_buffer[num_matches] = match_index;
        num_matches += 1;
        nb_attempts -= 1;
    }

    // Insert the current position into the row as well, so the next search
    // skips one iteration of the update loop.
    {
        const pos = rowNextIndex(tag_row, row_mask);
        tag_row[pos] = tag;
        row[pos] = ms.next_to_update;
        ms.next_to_update += 1;
    }

    // Return the longest match
    for (match_buffer[0..num_matches]) |match_index| {
        var current_ml: usize = 0;
        if (ms.read32(match_index + ml - 3) == ms.read32(ip + ml - 3)) // potentially better
            current_ml = ms.count(ip, match_index, iend);
        if (current_ml > ml) {
            ml = current_ml;
            offset_ptr.* = curr - match_index + sequences.rep_num;
            if (ip + current_ml == iend) break; // best possible, avoids read overflow on next attempt
        }
    }
    return ml;
}

// ---------------------------------------------------------------------------
// Binary tree (DUBT: "delayed update binary tree")
//
// The chain table holds two entries per position: the smaller and the larger
// child. New positions are only chained (like a hash chain) and marked
// unsorted; a search first sorts the unsorted candidates it meets into the
// tree, then descends it.

/// `ZSTD_getLowestMatchIndex` without a dictionary.
inline fn lowestMatchIndex(ms: *const MatchState, curr: u32) u32 {
    const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
    const lowest_valid = ms.low_limit;
    return if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
}

inline fn btMask(ms: *const MatchState) u32 {
    return (@as(u32, 1) << @intCast(ms.cp.chain_log - 1)) - 1;
}

/// `ZSTD_updateDUBT`: chain every position from `next_to_update` up to `ip`
/// and mark it unsorted.
fn updateDubt(ms: *MatchState, ip: u32, comptime mls: u32) void {
    const bt = ms.chain_table;
    const bt_mask = btMask(ms);
    var idx = ms.next_to_update;
    while (idx < ip) : (idx += 1) {
        const h = ms.hash(idx, ms.cp.hash_log, mls);
        const match_index = ms.hash_table[h];
        const slot = 2 * @as(usize, idx & bt_mask);
        ms.hash_table[h] = idx; // Update Hash Table
        bt[slot] = match_index; // update BT like a chain
        bt[slot + 1] = dubt_unsorted_mark;
    }
    ms.next_to_update = ip;
}

/// `ZSTD_insertDUBT1` (noDict): sort one already inserted but unsorted
/// position `curr` into the tree, comparing at most `nb_compares` nodes and
/// not descending below `bt_low`.
fn insertDubt1(ms: *MatchState, curr: u32, iend: usize, nb_compares_in: u32, bt_low: u32) void {
    const bt = ms.chain_table;
    const bt_mask = btMask(ms);
    var common_length_smaller: usize = 0;
    var common_length_larger: usize = 0;
    const slot = 2 * @as(usize, curr & bt_mask);
    var smaller_ptr: *u32 = &bt[slot];
    var larger_ptr: *u32 = &bt[slot + 1];
    // this candidate is unsorted: the next sorted candidate is reached through
    // smaller_ptr, while larger_ptr holds the previous unsorted candidate
    // (already saved, can be overwritten)
    var match_index = smaller_ptr.*;
    var dummy32: u32 = undefined; // to be nullified at the end
    const window_low = lowestMatchIndex(ms, curr);
    var nb_compares = nb_compares_in;

    while (nb_compares > 0 and match_index > window_low) : (nb_compares -= 1) {
        const next_slot = 2 * @as(usize, match_index & bt_mask);
        var match_length = @min(common_length_smaller, common_length_larger); // guaranteed minimum nb of common bytes
        std.debug.assert(match_index < curr);
        match_length += ms.count(curr + match_length, match_index + match_length, iend);

        // equal: no way to know if inf or sup. Drop, to guarantee consistency;
        // miss a bit of compression, but other solutions can corrupt the tree.
        if (curr + match_length == iend) break;

        if (ms.at(match_index + match_length) < ms.at(curr + match_length)) {
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
}

/// `ZSTD_DUBT_findBestMatch` (noDict). Returns the best length (0 when none)
/// and stores its offBase in `off_base_ptr`, whose incoming value also
/// prices the first candidate.
fn dubtFindBestMatch(ms: *MatchState, ip: u32, iend: usize, off_base_ptr: *u32, comptime mls: u32) usize {
    const hash_table = ms.hash_table;
    const h = ms.hash(ip, ms.cp.hash_log, mls);
    var match_index = hash_table[h];
    const curr = ip;
    const window_low = lowestMatchIndex(ms, curr);
    const bt = ms.chain_table;
    const bt_mask = btMask(ms);
    const bt_low: u32 = if (bt_mask >= curr) 0 else curr - bt_mask;
    const unsort_limit = @max(bt_low, window_low);
    var nb_compares: u32 = @as(u32, 1) << @intCast(ms.cp.search_log);
    var nb_candidates = nb_compares;
    var previous_candidate: u32 = 0;

    // reach end of unsorted candidates list
    while (match_index > unsort_limit and bt[2 * @as(usize, match_index & bt_mask) + 1] == dubt_unsorted_mark and nb_candidates > 1) {
        const slot = 2 * @as(usize, match_index & bt_mask);
        // the unsorted mark becomes a reversed chain, to move up back to the original position
        bt[slot + 1] = previous_candidate;
        previous_candidate = match_index;
        match_index = bt[slot];
        nb_candidates -= 1;
    }

    // nullify last candidate if it's still unsorted: simplification,
    // detrimental to compression ratio, beneficial for speed
    if (match_index > unsort_limit and bt[2 * @as(usize, match_index & bt_mask) + 1] == dubt_unsorted_mark) {
        const slot = 2 * @as(usize, match_index & bt_mask);
        bt[slot] = 0;
        bt[slot + 1] = 0;
    }

    // batch sort stacked candidates
    match_index = previous_candidate;
    while (match_index != 0) { // will end on match_index == 0
        const next_candidate_idx = bt[2 * @as(usize, match_index & bt_mask) + 1];
        insertDubt1(ms, match_index, iend, nb_candidates, unsort_limit);
        match_index = next_candidate_idx;
        nb_candidates += 1;
    }

    // find longest match
    var common_length_smaller: usize = 0;
    var common_length_larger: usize = 0;
    const slot = 2 * @as(usize, curr & bt_mask);
    var smaller_ptr: *u32 = &bt[slot];
    var larger_ptr: *u32 = &bt[slot + 1];
    var match_end_idx: u32 = curr + 8 + 1;
    var dummy32: u32 = undefined; // to be nullified at the end
    var best_length: usize = 0;

    match_index = hash_table[h];
    hash_table[h] = curr; // Update Hash Table

    while (nb_compares > 0 and match_index > window_low) : (nb_compares -= 1) {
        const next_slot = 2 * @as(usize, match_index & bt_mask);
        var match_length = @min(common_length_smaller, common_length_larger); // guaranteed minimum nb of common bytes
        match_length += ms.count(curr + match_length, match_index + match_length, iend);

        if (match_length > best_length) {
            if (match_length > match_end_idx - match_index)
                match_end_idx = match_index + @as(u32, @intCast(match_length));
            const gain_len = 4 * @as(i64, @intCast(match_length - best_length));
            const gain_off = @as(i64, std.math.log2_int(u32, curr - match_index + 1)) - std.math.log2_int(u32, off_base_ptr.*);
            if (gain_len > gain_off) {
                best_length = match_length;
                off_base_ptr.* = curr - match_index + sequences.rep_num;
            }
            // equal: no way to know if inf or sup. Drop, to guarantee
            // consistency (miss a little bit of compression).
            if (curr + match_length == iend) break;
        }

        if (ms.at(match_index + match_length) < ms.at(curr + match_length)) {
            // match is smaller than current
            smaller_ptr.* = match_index; // update smaller idx
            common_length_smaller = match_length; // all smaller will now have at least this guaranteed common length
            if (match_index <= bt_low) { // beyond tree size, stop the search
                smaller_ptr = &dummy32;
                break;
            }
            smaller_ptr = &bt[next_slot + 1]; // new "smaller" => larger of match
            match_index = bt[next_slot + 1]; // new matchIndex larger than previous (closer to current)
        } else {
            // match is larger than current
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

    std.debug.assert(match_end_idx > curr + 8); // ensure next_to_update is increased
    ms.next_to_update = match_end_idx - 8; // skip repetitive patterns
    return best_length;
}

/// `ZSTD_BtFindBestMatch`: tree updater, providing the best match.
fn btFindBestMatch(ms: *MatchState, ip: u32, iend: usize, off_base_ptr: *u32, comptime mls: u32) usize {
    if (ip < ms.next_to_update) return 0; // skipped area
    updateDubt(ms, ip, mls);
    return dubtFindBestMatch(ms, ip, iend, off_base_ptr, mls);
}

// ---------------------------------------------------------------------------
// Parser

inline fn searchMax(ms: *MatchState, ip: usize, iend: usize, offset_ptr: *u32, comptime method: Method, comptime mls: u32, row_log: u32) usize {
    return switch (method) {
        .hash_chain => hcFindBestMatch(ms, @intCast(ip), iend, offset_ptr, mls),
        .row => rowFindBestMatch(ms, @intCast(ip), iend, offset_ptr, mls, row_log),
        .binary_tree => btFindBestMatch(ms, @intCast(ip), iend, offset_ptr, mls),
    };
}

inline fn gain(ml: usize, mult: i64, off_base: u32, bonus: i64) i64 {
    return @as(i64, @intCast(ml)) * mult - @as(i64, std.math.log2_int(u32, off_base)) + bonus;
}

/// `ZSTD_compressBlock_lazy_generic` (noDict). `depth` 0 is greedy, 1 lazy,
/// 2 lazy2 and btlazy2. Stores sequences into `ss`, updates `rep`, and returns the number
/// of trailing literals.
fn lazyGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime method: Method, comptime depth: u32, comptime mls: u32) usize {
    const iend: usize = istart + src_size;
    // Signed: a short block puts the limit before the block start.
    const ilimit: i64 = @as(i64, @intCast(iend)) - 8 - (if (method == .row) cache_size else 0);
    const prefix_lowest: usize = ms.dict_limit;
    const row_log = params.rowLog(ms.cp);
    var ip: usize = istart;
    var anchor: usize = istart;

    var offset_1: u32 = rep[0];
    var offset_2: u32 = rep[1];
    var offset_saved1: u32 = 0;
    var offset_saved2: u32 = 0;

    ip += @intFromBool(ip == prefix_lowest);
    {
        const curr: u32 = @intCast(ip);
        const window_low = ms.lowestPrefixIndex(curr);
        const max_rep = curr - window_low;
        if (offset_2 > max_rep) {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if (offset_1 > max_rep) {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    // Reset the lazy skipping state
    ms.lazy_skipping = false;
    if (method == .row) fillHashCache(ms, mls, ms.next_to_update, ilimit);

    while (@as(i64, @intCast(ip)) < ilimit) {
        var match_length: usize = 0;
        var off_base: u32 = 1; // REPCODE1_TO_OFFBASE
        var start: usize = ip + 1;

        store: {
            // check repCode
            if (offset_1 > 0 and ms.read32(ip + 1 - offset_1) == ms.read32(ip + 1)) {
                match_length = ms.count(ip + 1 + 4, ip + 1 + 4 - offset_1, iend) + 4;
                if (depth == 0) break :store;
            }

            // first search (depth 0)
            {
                var offbase_found: u32 = no_offset;
                const ml2 = searchMax(ms, ip, iend, &offbase_found, method, mls, row_log);
                if (ml2 > match_length) {
                    match_length = ml2;
                    start = ip;
                    off_base = offbase_found;
                }
            }

            if (match_length < 4) {
                const step = ((ip - anchor) >> match.search_strength) + 1; // jump faster over incompressible sections
                ip += step;
                // Enter the lazy skipping mode once we are skipping more than
                // 8 bytes at a time: only searched positions get inserted.
                ms.lazy_skipping = step > lazy_skipping_step;
                continue;
            }

            // let's try to find a better solution
            if (depth >= 1) while (@as(i64, @intCast(ip)) < ilimit) {
                ip += 1;
                if (off_base != 0 and offset_1 > 0 and ms.read32(ip) == ms.read32(ip - offset_1)) {
                    const ml_rep = ms.count(ip + 4, ip + 4 - offset_1, iend) + 4;
                    const gain2: i64 = @as(i64, @intCast(ml_rep)) * 3;
                    const gain1 = gain(match_length, 3, off_base, 1);
                    if (ml_rep >= 4 and gain2 > gain1) {
                        match_length = ml_rep;
                        off_base = 1;
                        start = ip;
                    }
                }
                {
                    var ofb_candidate: u32 = no_offset;
                    const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log);
                    const gain2 = gain(ml2, 4, ofb_candidate, 0); // raw approx
                    const gain1 = gain(match_length, 4, off_base, 4);
                    if (ml2 >= 4 and gain2 > gain1) {
                        match_length = ml2;
                        off_base = ofb_candidate;
                        start = ip;
                        continue; // search a better one
                    }
                }

                // let's find an even better one
                if (depth == 2 and @as(i64, @intCast(ip)) < ilimit) {
                    ip += 1;
                    if (off_base != 0 and offset_1 > 0 and ms.read32(ip) == ms.read32(ip - offset_1)) {
                        const ml_rep = ms.count(ip + 4, ip + 4 - offset_1, iend) + 4;
                        const gain2: i64 = @as(i64, @intCast(ml_rep)) * 4;
                        const gain1 = gain(match_length, 4, off_base, 1);
                        if (ml_rep >= 4 and gain2 > gain1) {
                            match_length = ml_rep;
                            off_base = 1;
                            start = ip;
                        }
                    }
                    {
                        var ofb_candidate: u32 = no_offset;
                        const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log);
                        const gain2 = gain(ml2, 4, ofb_candidate, 0); // raw approx
                        const gain1 = gain(match_length, 4, off_base, 7);
                        if (ml2 >= 4 and gain2 > gain1) {
                            match_length = ml2;
                            off_base = ofb_candidate;
                            start = ip;
                            continue;
                        }
                    }
                }
                break; // nothing found : store previous solution
            };

            // catch up
            if (off_base > sequences.rep_num) {
                const offset = off_base - sequences.rep_num;
                // only search for offset within prefix
                while (start > anchor and start - offset > prefix_lowest and ms.at(start - 1) == ms.at(start - offset - 1)) {
                    start -= 1;
                    match_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        // store sequence
        ss.store(ms.src[anchor - match.window_start .. start - match.window_start], off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if (ms.lazy_skipping) {
            // We've found a match, disable lazy skipping mode, and refill the hash cache.
            if (method == .row) fillHashCache(ms, mls, ms.next_to_update, ilimit);
            ms.lazy_skipping = false;
        }

        // check immediate repcode
        while (@as(i64, @intCast(ip)) <= ilimit and offset_2 > 0 and ms.read32(ip) == ms.read32(ip - offset_2)) {
            match_length = ms.count(ip + 4, ip + 4 - offset_2, iend) + 4;
            std.mem.swap(u32, &offset_1, &offset_2); // swap repcodes
            ss.store(&.{}, 1, match_length);
            ip += match_length;
            anchor = ip;
        }
    }

    // If offset_1 started invalid (offsetSaved1 != 0) and became valid
    // (offset_1 != 0), rotate saved offsets.
    offset_saved2 = if (offset_saved1 != 0 and offset_1 != 0) offset_saved1 else offset_saved2;
    // save reps for next block
    rep[0] = if (offset_1 != 0) offset_1 else offset_saved1;
    rep[1] = if (offset_2 != 0) offset_2 else offset_saved2;
    return iend - anchor;
}

test "the next row slot cycles backwards and skips the head" {
    var tag_row = [_]u8{0} ** 16;
    try std.testing.expectEqual(@as(u32, 15), rowNextIndex(&tag_row, 15));
    try std.testing.expectEqual(@as(u32, 14), rowNextIndex(&tag_row, 15));
    tag_row[0] = 1;
    try std.testing.expectEqual(@as(u32, 15), rowNextIndex(&tag_row, 15));
}

test "the match mask starts at the row head" {
    var tag_row = [_]u8{0} ** 16;
    tag_row[3] = 7;
    tag_row[9] = 7;
    // head 5: slot 9 is 4 steps from the head, slot 3 wraps around to 14
    try std.testing.expectEqual(@as(u64, (1 << 4) | (1 << 14)), matchMask(16, &tag_row, 7, 5));
}
