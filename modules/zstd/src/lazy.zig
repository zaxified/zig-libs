// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Match finders for the `greedy`, `lazy`, `lazy2` and `btlazy2` strategies.
//!
//! Port of libzstd lib/compress/zstd_lazy.c (v1.5.7): the hash-chain finder
//! (`ZSTD_HcFindBestMatch`), the row-based finder (`ZSTD_RowFindBestMatch`),
//! the lazily sorted binary tree of `btlazy2` (`ZSTD_BtFindBestMatch`,
//! "DUBT") and the parser that all three feed
//! (`ZSTD_compressBlock_lazy_generic`), each in libzstd's dictionary modes
//! (`DictMode`), and the dedicated dictionary search's table layout
//! (`ZSTD_dedicatedDictSearch_lazy_loadDictionary`) and search. libzstd
//! picks the row finder over the hash chain whenever the window is larger
//! than 16 KB, so both are needed for every level of `greedy`..`lazy2`.
//!
//! The row finder's SIMD tag comparison is written as a plain vector compare
//! (`matchMask`); the set of matching slots is what must match libzstd, and
//! it does -- but getting that set out of the vector is endianness-sensitive
//! (see `matchMask`'s own comment, SPEC.md *Portability*).

const std = @import("std");
const builtin = @import("builtin");
const params = @import("params.zig");
const match = @import("match.zig");
const sequences = @import("sequences.zig");
const MatchState = match.MatchState;
const SeqStore = sequences.SeqStore;
const Base = match.Base;

const Method = enum { hash_chain, row, binary_tree };

/// `ZSTD_dictMode_e`: the window in one segment (`no_dict`), in two
/// (`ext_dict`: a dictionary or an earlier buffer below the prefix), or one
/// segment with an attached `CDict` searched beside it
/// (`dict_match_state`, `MatchState.dict_match_state`) -- or one whose
/// tables are laid out for the dedicated dictionary search
/// (`dedicated_dict_search`, `MatchState.dedicated_dict_search`; hash
/// chain and rows only). Every function takes it at compile time, as
/// libzstd's templates do, so the dictionary branches cost the other modes
/// nothing.
const DictMode = enum { no_dict, ext_dict, dict_match_state, dedicated_dict_search };

/// `ZSTD_LAZY_DDSS_BUCKET_LOG`: a dedicated-dictionary-search CDict's hash
/// table has 2^2 entries per hash -- the three newest positions and a
/// pointer into its chain table -- so it is 4 times the size of a plain one.
pub const ddss_bucket_log = 2;

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
pub const dubt_unsorted_mark = 1;

/// Compress one block with the strategy in `ms.cp` (greedy, lazy, lazy2 or
/// btlazy2).
pub fn compressBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32) usize {
    // ZSTD_matchState_dictMode
    if (ms.hasExtDict()) return dispatch(ms, ss, rep, istart, src_size, .ext_dict);
    if (ms.dict_match_state) |dms| return if (dms.dedicated_dict_search)
        dispatch(ms, ss, rep, istart, src_size, .dedicated_dict_search)
    else
        dispatch(ms, ss, rep, istart, src_size, .dict_match_state);
    return dispatch(ms, ss, rep, istart, src_size, .no_dict);
}

fn dispatch(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime mode: DictMode) usize {
    const mls = std.math.clamp(ms.cp.min_match, 4, 6);
    const generic = switch (mode) {
        .ext_dict => lazyExtDictGeneric,
        .no_dict => lazyGeneric,
        .dict_match_state => lazyDictMatchStateGeneric,
        .dedicated_dict_search => lazyDedicatedDictSearchGeneric,
    };
    const depth: u32 = switch (ms.cp.strategy) {
        .greedy => 0,
        .lazy => 1,
        .lazy2 => 2,
        // libzstd has no binary-tree variant: a CDict for btlazy2 never
        // gets the dedicated layout (ZSTD_dedicatedDictSearch_isSupported)
        .btlazy2 => if (mode == .dedicated_dict_search) unreachable else return switch (mls) {
            inline 4, 5, 6 => |m| generic(ms, ss, rep, istart, src_size, .binary_tree, 2, m),
            else => unreachable,
        },
        else => unreachable,
    };
    const row = ms.use_row;
    return switch (depth) {
        inline 0, 1, 2 => |d| if (row) switch (mls) {
            inline 4, 5, 6 => |m| generic(ms, ss, rep, istart, src_size, .row, d, m),
            else => unreachable,
        } else switch (mls) {
            inline 4, 5, 6 => |m| generic(ms, ss, rep, istart, src_size, .hash_chain, d, m),
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
    const w: Base = .of(ms);
    const hash_table = ms.hash_table;
    const hash_log = ms.cp.hash_log;
    const chain_table = ms.chain_table;
    const chain_mask = (@as(u32, 1) << @intCast(ms.cp.chain_log)) - 1;
    var idx = ms.next_to_update;
    while (idx < ip) {
        const h = w.hash(idx, hash_log, mls);
        chain_table[idx & chain_mask] = hash_table[h];
        hash_table[h] = idx;
        idx += 1;
        // Stop inserting every position when in the lazy skipping mode.
        if (ms.lazy_skipping) break;
    }
    ms.next_to_update = ip;
    return hash_table[w.hash(ip, hash_log, mls)];
}

/// `ZSTD_HcFindBestMatch` (noDict, extDict or dictMatchState: `mode`). Returns the best
/// length found (3 when none reaches 4) and stores its offBase in
/// `offset_ptr`.
fn hcFindBestMatch(ms: *MatchState, ip: u32, iend: usize, offset_ptr: *u32, comptime mls: u32, comptime mode: DictMode) usize {
    const w: Base = .of(ms);
    const dict_limit = ms.dict_limit;
    const chain_table = ms.chain_table;
    const chain_size: u32 = @as(u32, 1) << @intCast(ms.cp.chain_log);
    const chain_mask = chain_size - 1;
    const curr = ip;
    const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
    const lowest_valid = ms.low_limit;
    const within_max_distance = if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    const is_dictionary = ms.loaded_dict_end != 0;
    const low_limit = if (is_dictionary) lowest_valid else within_max_distance;
    const min_chain: u32 = if (curr > chain_size) curr - chain_size else 0;
    var nb_attempts: u32 = @as(u32, 1) << @intCast(ms.cp.search_log);
    var ml: usize = 4 - 1;

    const dds_idx: usize = if (mode == .dedicated_dict_search) ddsBucket(w, ms.dict_match_state.?, ip, mls) else 0;

    var match_index = insertAndFindFirstIndex(ms, ip, mls);
    while (match_index >= low_limit and nb_attempts > 0) : (nb_attempts -= 1) {
        const current_ml = candidateLength(w, ip, match_index, iend, ml, dict_limit, mode);
        // save best solution
        if (current_ml > ml) {
            ml = current_ml;
            offset_ptr.* = curr - match_index + sequences.rep_num;
            if (ip + current_ml == iend) break; // best possible, avoids read overflow on next attempt
        }
        if (match_index <= min_chain) break;
        match_index = chain_table[match_index & chain_mask];
    }

    if (mode == .dedicated_dict_search)
        return ddsSearch(w, ms.dict_match_state.?, offset_ptr, ml, nb_attempts, ip, iend, dict_limit, dds_idx);
    if (mode == .dict_match_state) {
        // the attempts left go to the CDict's own hash chain
        const dm: Dms = .of(ms.dict_match_state.?);
        const dms_chain_size: u32 = @as(u32, 1) << @intCast(dm.ms.cp.chain_log);
        const dms_chain_mask = dms_chain_size - 1;
        const dms_index_delta = dict_limit -% dm.end;
        const dms_min_chain: u32 = if (dm.end > dms_chain_size) dm.end - dms_chain_size else 0;

        match_index = dm.ms.hash_table[w.hash(ip, dm.ms.cp.hash_log, mls)];
        while (match_index >= dm.lowest and nb_attempts > 0) : (nb_attempts -= 1) {
            var current_ml: usize = 0;
            // assumption: matchIndex <= dictLimit-4 (by table construction)
            if (dm.b.read32(match_index) == w.read32(ip))
                current_ml = countDms(w, dm.b, @as(usize, ip) + 4, @as(usize, match_index) + 4, iend, dm.end, dict_limit) + 4;
            // save best solution
            if (current_ml > ml) {
                ml = current_ml;
                std.debug.assert(curr > match_index +% dms_index_delta);
                offset_ptr.* = curr - (match_index +% dms_index_delta) + sequences.rep_num;
                if (ip + current_ml == iend) break; // best possible, avoids read overflow on next attempt
            }
            if (match_index <= dms_min_chain) break;
            match_index = dm.ms.chain_table[match_index & dms_chain_mask];
        }
    }
    return ml;
}

/// The length of the match at `match_index` if it can beat `ml`, else 0: the
/// candidate test of the hash-chain and row finders. In the prefix, the 4
/// bytes ending at `ml` must match; in the extDict (`.ext_dict`), the first 4,
/// and the count may run on into the prefix.
inline fn candidateLength(w: Base, ip: u32, match_index: u32, iend: usize, ml: usize, dict_limit: u32, comptime mode: DictMode) usize {
    if (mode != .ext_dict or match_index >= dict_limit) {
        // read 4B starting from (match + ml + 1 - sizeof(U32))
        if (w.read32(match_index + ml - 3) == w.read32(ip + ml - 3)) // potentially better
            return w.count(ip, match_index, iend);
        return 0;
    }
    // assumption: matchIndex <= dictLimit-4 (by table construction)
    if (w.read32Seg(match_index, dict_limit) == w.read32(ip))
        return w.count2Segments(@as(usize, ip) + 4, @as(usize, match_index) + 4, iend, dict_limit, dict_limit) + 4;
    return 0;
}

/// `ZSTD_insertAndFindFirstIndex` as dictionary loading calls it: every
/// position from `next_to_update` up to `ip` into the hash chains, hashed
/// with `minMatch` as it is (3 hashes as 4, 7 as 7), not with the search's
/// clamped length.
pub fn insertDictionary(ms: *MatchState, ip: u32) void {
    switch (ms.cp.min_match) {
        inline 5, 6, 7 => |m| _ = insertAndFindFirstIndex(ms, ip, m),
        else => _ = insertAndFindFirstIndex(ms, ip, 4),
    }
}

// ---------------------------------------------------------------------------
// Dedicated dictionary search
//
// A CDict made with `Advanced.enable_dedicated_dict_search` for greedy..lazy2
// gets a hash table of 2^(hashLog) entries where a plain one would have
// 2^(hashLog - 2): a bucket of 4 per hash, the three newest positions with
// that hash (newest first, 0 when fewer) and a packed pointer
// `(start << 8) | length` to the rest of its chain, laid out contiguously in
// the chain table. The search reads it without following links.

/// `ZSTD_dedicatedDictSearch_lazy_loadDictionary`: lay the positions from
/// `next_to_update` up to `target` out in `ms`'s buckets and chain table.
/// The positions are hashed with `minMatch` as it is (3 as 4, 7 as 7),
/// although the search clamps it to 6, as libzstd does.
pub fn ddsLoadDictionary(ms: *MatchState, target: u32) void {
    switch (ms.cp.min_match) {
        inline 5, 6, 7 => |m| ddsLoadDictionaryT(ms, target, m),
        else => ddsLoadDictionaryT(ms, target, 4),
    }
}

fn ddsLoadDictionaryT(ms: *MatchState, target: u32, comptime mls: u32) void {
    const w: Base = .of(ms);
    const hash_table = ms.hash_table;
    const chain_table = ms.chain_table;
    const chain_size: u32 = @as(u32, 1) << @intCast(ms.cp.chain_log);
    var idx = ms.next_to_update;
    const min_chain: u32 = if (chain_size < target -% idx) target - chain_size else idx;
    const bucket_size: u32 = 1 << ddss_bucket_log;
    const cache_sz: u32 = bucket_size - 1;
    // U32 in libzstd: a search log of 1 wraps, and then caps at 255
    const chain_attempts: u32 = (@as(u32, 1) << @intCast(ms.cp.search_log)) -% cache_sz;
    const chain_limit: u32 = if (chain_attempts > 255) 255 else chain_attempts;

    // We know the hashtable is oversized by a factor of `bucketSize`. We
    // are going to temporarily pretend `bucketSize == 1`, keeping only a
    // single entry. We will use the rest of the space to construct a
    // temporary chaintable.
    const hash_log: u32 = ms.cp.hash_log - ddss_bucket_log;
    const n_hashes: u32 = @as(u32, 1) << @intCast(hash_log);
    const tmp_hash_table = hash_table[0..n_hashes];
    const tmp_chain_table = hash_table[n_hashes..];
    const tmp_chain_size: u32 = @as(u32, (1 << ddss_bucket_log) - 1) << @intCast(hash_log);
    const tmp_min_chain: u32 = if (tmp_chain_size < target) target - tmp_chain_size else idx;

    std.debug.assert(ms.cp.chain_log <= 24);
    std.debug.assert(ms.cp.hash_log > ms.cp.chain_log);
    std.debug.assert(idx != 0);
    std.debug.assert(tmp_min_chain <= min_chain);

    // fill conventional hash table and conventional chain table
    while (idx < target) : (idx += 1) {
        const h = w.hash(idx, hash_log, mls);
        if (idx >= tmp_min_chain) tmp_chain_table[idx - tmp_min_chain] = hash_table[h];
        tmp_hash_table[h] = idx;
    }

    // sort chains into ddss chain table
    {
        var chain_pos: u32 = 0;
        for (tmp_hash_table) |*head| {
            var count: u32 = 0;
            var count_beyond_min_chain: u32 = 0;
            var i = head.*;
            while (i >= tmp_min_chain and count < cache_sz) : (count += 1) {
                // skip through the chain to the first position that won't be
                // in the hash cache bucket
                if (i < min_chain) count_beyond_min_chain += 1;
                i = tmp_chain_table[i - tmp_min_chain];
            }
            if (count == cache_sz) {
                count = 0;
                while (count < chain_limit) {
                    if (i < min_chain) {
                        // only allow pulling `cacheSize` number of entries
                        // into the cache or chainTable beyond `minChain`, to
                        // replace the entries pulled out of the chainTable
                        // into the cache. This lets us reach back further
                        // without increasing the total number of entries in
                        // the chainTable, guaranteeing the DDSS chain table
                        // will fit into the space allocated for the regular
                        // one.
                        if (i == 0) break;
                        count_beyond_min_chain += 1;
                        if (count_beyond_min_chain > cache_sz) break;
                    }
                    chain_table[chain_pos] = i;
                    chain_pos += 1;
                    count += 1;
                    if (i < tmp_min_chain) break;
                    i = tmp_chain_table[i - tmp_min_chain];
                }
            } else {
                count = 0;
            }
            head.* = if (count != 0) ((chain_pos - count) << 8) + count else 0;
        }
        std.debug.assert(chain_pos <= chain_size);
    }

    // move chain pointers into the last entry of each hash bucket (from the
    // top down: a bucket lies at or above the entry it is made from)
    var hash_idx: u32 = n_hashes;
    while (hash_idx != 0) {
        hash_idx -= 1;
        const bucket_idx = @as(usize, hash_idx) << ddss_bucket_log;
        const chain_packed_pointer = tmp_hash_table[hash_idx];
        @memset(hash_table[bucket_idx..][0..cache_sz], 0);
        hash_table[bucket_idx + bucket_size - 1] = chain_packed_pointer;
    }

    // fill the buckets of the hash table
    idx = ms.next_to_update;
    while (idx < target) : (idx += 1) {
        const h = w.hash(idx, hash_log, mls) << ddss_bucket_log;
        // Shift hash cache down 1.
        var k: usize = cache_sz - 1;
        while (k != 0) : (k -= 1) hash_table[h + k] = hash_table[h + k - 1];
        hash_table[h] = idx;
    }

    ms.next_to_update = target;
}

/// The first entry of `ip`'s bucket in the dedicated-search CDict `dms`
/// (hashed with its hash log less the bucket log, unsalted), prefetched.
inline fn ddsBucket(w: Base, dms: *const MatchState, ip: u32, comptime mls: u32) usize {
    const dds_hash_log = dms.cp.hash_log - ddss_bucket_log;
    const dds_idx = w.hash(ip, dds_hash_log, mls) << ddss_bucket_log;
    @prefetch(dms.hash_table.ptr + dds_idx, .{});
    return dds_idx;
}

/// `ZSTD_dedicatedDictSearch_lazy_search`: spend `nb_attempts` on the
/// CDict `dms`'s bucket `dds_idx` and then its chain, for a match longer
/// than `ml`. Returns the longest length found (`ml` if none is longer),
/// and its offBase in `offset_ptr`. (libzstd also prefetches the
/// candidates' bytes; that changes no decision and is left out.)
inline fn ddsSearch(w: Base, dms: *const MatchState, offset_ptr: *u32, ml_in: usize, nb_attempts: u32, ip: u32, iend: usize, dict_limit: u32, dds_idx: usize) usize {
    const dm: Dms = .of(dms);
    const curr = ip;
    const dds_index_delta = dict_limit -% dm.end;
    const bucket_size: u32 = 1 << ddss_bucket_log;
    const bucket_limit: u32 = @min(nb_attempts, bucket_size - 1);
    var ml = ml_in;

    const chain_packed_pointer = dms.hash_table[dds_idx + bucket_size - 1];
    @prefetch(dms.chain_table.ptr + (chain_packed_pointer >> 8), .{});

    var dds_attempt: u32 = 0;
    while (dds_attempt < bucket_limit) : (dds_attempt += 1) {
        const match_index = dms.hash_table[dds_idx + dds_attempt];
        if (match_index == 0) return ml;
        // guaranteed by table construction
        std.debug.assert(match_index >= dm.lowest);
        var current_ml: usize = 0;
        // assumption: matchIndex <= dictLimit-4 (by table construction)
        if (dm.b.read32(match_index) == w.read32(ip))
            current_ml = countDms(w, dm.b, @as(usize, ip) + 4, @as(usize, match_index) + 4, iend, dm.end, dict_limit) + 4;
        // save best solution
        if (current_ml > ml) {
            ml = current_ml;
            offset_ptr.* = curr - (match_index +% dds_index_delta) + sequences.rep_num;
            if (ip + current_ml == iend) return ml; // best possible, avoids read overflow on next attempt
        }
    }

    var chain_index = chain_packed_pointer >> 8;
    const chain_length = chain_packed_pointer & 0xFF;
    const chain_attempts = nb_attempts - dds_attempt;
    const chain_limit = @min(chain_attempts, chain_length);
    var chain_attempt: u32 = 0;
    while (chain_attempt < chain_limit) : ({
        chain_attempt += 1;
        chain_index += 1;
    }) {
        const match_index = dms.chain_table[chain_index];
        // guaranteed by table construction
        std.debug.assert(match_index >= dm.lowest);
        var current_ml: usize = 0;
        // assumption: matchIndex <= dictLimit-4 (by table construction)
        if (dm.b.read32(match_index) == w.read32(ip))
            current_ml = countDms(w, dm.b, @as(usize, ip) + 4, @as(usize, match_index) + 4, iend, dm.end, dict_limit) + 4;
        // save best solution
        if (current_ml > ml) {
            ml = current_ml;
            offset_ptr.* = curr - (match_index +% dds_index_delta) + sequences.rep_num;
            if (ip + current_ml == iend) break; // best possible, avoids read overflow on next attempt
        }
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

inline fn rowHash(ms: *const MatchState, w: Base, idx: usize, comptime mls: u32) u32 {
    return @intCast(w.hashSalted(idx, ms.row_hash_log + tag_bits, mls, ms.hash_salt));
}

/// `ZSTD_row_prefetch`: the hash-table and tag-table row of a hash the
/// cache will hand out 8 positions later. Changes no decision.
inline fn rowPrefetch(ms: *const MatchState, h: u32, row_log: u32) void {
    const rel_row: usize = @as(usize, h >> tag_bits) << @intCast(row_log);
    @prefetch(ms.hash_table.ptr + rel_row, .{});
    if (row_log >= 5) @prefetch(ms.hash_table.ptr + rel_row + 16, .{});
    @prefetch(ms.tag_table.ptr + rel_row, .{});
    if (row_log == 6) @prefetch(ms.tag_table.ptr + rel_row + 32, .{});
}

/// `ZSTD_row_fillHashCache`: hashes of up to 8 positions from `idx`, not
/// past `ilimit`.
fn fillHashCache(ms: *MatchState, comptime mls: u32, idx_in: u32, ilimit: i64, row_log: u32) void {
    const w: Base = .of(ms);
    var idx = idx_in;
    const max_elems: u32 = if (@as(i64, idx) > ilimit) 0 else @intCast(ilimit - idx + 1);
    const lim = idx + @min(cache_size, max_elems);
    while (idx < lim) : (idx += 1) {
        const h = rowHash(ms, w, idx, mls);
        rowPrefetch(ms, h, row_log);
        ms.hash_cache[idx & cache_mask] = h;
    }
}

/// `ZSTD_row_nextCachedHash`: the hash of `idx`, replaced in the cache by the
/// hash of `idx + 8`.
inline fn nextCachedHash(ms: *MatchState, w: Base, idx: u32, comptime mls: u32, comptime row_log: u32) u32 {
    const new_hash = rowHash(ms, w, idx + cache_size, mls);
    rowPrefetch(ms, new_hash, row_log);
    const h = ms.hash_cache[idx & cache_mask];
    ms.hash_cache[idx & cache_mask] = new_hash;
    return h;
}

/// `ZSTD_row_update_internalImpl` with the hash cache.
fn rowUpdateImpl(ms: *MatchState, start: u32, end: u32, comptime mls: u32, comptime row_log: u32, row_mask: u32) void {
    const w: Base = .of(ms);
    var idx = start;
    while (idx < end) : (idx += 1) {
        const h = nextCachedHash(ms, w, idx, mls, row_log);
        const rel_row: usize = @as(usize, h >> tag_bits) << @intCast(row_log);
        const tag_row = ms.tag_table[rel_row..];
        const pos = rowNextIndex(tag_row, row_mask);
        tag_row[pos] = @truncate(h & tag_mask);
        ms.hash_table[rel_row + pos] = idx;
    }
}

/// `ZSTD_row_update_internal` (useCache): insert positions up to `ip`,
/// skipping the middle of long matches.
fn rowUpdate(ms: *MatchState, ip: u32, comptime mls: u32, comptime row_log: u32, row_mask: u32) void {
    var idx = ms.next_to_update;
    const target = ip;
    const skip_threshold = 384;
    const max_match_start_positions_to_update = 96;
    const max_match_end_positions_to_update = 32;
    if (target -% idx > skip_threshold) {
        const bound = idx + max_match_start_positions_to_update;
        rowUpdateImpl(ms, idx, bound, mls, row_log, row_mask);
        idx = target - max_match_end_positions_to_update;
        fillHashCache(ms, mls, idx, @as(i64, ip) + 1, row_log);
    }
    rowUpdateImpl(ms, idx, target, mls, row_log, row_mask);
    ms.next_to_update = target;
}

/// `ZSTD_row_update`: insert every position from `next_to_update` up to
/// `ip`, without the hash cache and without skipping (dictionary loading).
pub fn rowUpdateDictionary(ms: *MatchState, ip: u32) void {
    const row_log = params.rowLog(ms.cp);
    const row_mask = (@as(u32, 1) << @intCast(row_log)) - 1;
    const w: Base = .of(ms);
    // mls caps out at 6; 3 hashes as 4
    switch (@min(ms.cp.min_match, 6)) {
        inline 5, 6 => |m| rowUpdateNoCache(ms, w, ip, m, row_log, row_mask),
        else => rowUpdateNoCache(ms, w, ip, 4, row_log, row_mask),
    }
    ms.next_to_update = ip;
}

/// `ZSTD_row_update_internalImpl` without the hash cache.
fn rowUpdateNoCache(ms: *MatchState, w: Base, end: u32, comptime mls: u32, row_log: u32, row_mask: u32) void {
    var idx = ms.next_to_update;
    while (idx < end) : (idx += 1) {
        const h = rowHash(ms, w, idx, mls);
        const rel_row: usize = @as(usize, h >> tag_bits) << @intCast(row_log);
        const tag_row = ms.tag_table[rel_row..];
        const pos = rowNextIndex(tag_row, row_mask);
        tag_row[pos] = @truncate(h & tag_mask);
        ms.hash_table[rel_row + pos] = idx;
    }
}

/// Bit `i` set when slot `(head + i) % entries` of `tag_row` holds `tag`
/// (`ZSTD_row_getMatchMask`).
inline fn matchMask(comptime entries: u32, tag_row: []const u8, tag: u8, head: u32) u64 {
    const V = @Vector(entries, u8);
    const B = std.meta.Int(.unsigned, entries);
    const v: V = tag_row[0..entries].*;
    // `@bitCast` of a `@Vector(entries, bool)` must give bit `i` == lane
    // `i` (`tag_row[i]`'s comparison), the convention libzstd's own SIMD
    // paths use and its portable SWAR fallback (`zstd_lazy.c`'s
    // `ZSTD_row_getMatchMask`) goes out of its way to preserve on a
    // big-endian host too ("reverse bits during extraction", its own
    // comment) -- `rotr` below, and every caller's `headGrouped +
    // ZSTD_VecMask_next(matches)`, depend on that mapping being
    // bit-for-bit the same regardless of target.
    //
    // Zig's `@bitCast` does not honour it: measured directly (a standalone
    // comparison of the same vector-of-bool bitcast on `x86_64-linux` vs.
    // `mips-linux-musl`, 32-bit big-endian -- `check-portable`'s
    // `.linux32`), the big-endian result is the little-endian one with
    // every bit reversed end to end, not merely a byte swap, at both the
    // 16- and 32-lane widths this function is instantiated at.
    // `@bitReverse` on a big-endian target only undoes exactly that, at
    // zero cost on every currently little-endian target (`.linux64`,
    // `.windows`) this collapses to a no-op branch.
    const raw: B = @bitCast(v == @as(V, @splat(tag)));
    const eq: B = if (comptime builtin.cpu.arch.endian() == .big) @bitReverse(raw) else raw;
    return std.math.rotr(B, eq, head);
}

/// `ZSTD_RowFindBestMatch` (noDict, extDict or dictMatchState: `mode`), specialised on
/// the row log as libzstd's templates are.
inline fn rowFindBestMatch(ms: *MatchState, ip: u32, iend: usize, offset_ptr: *u32, comptime mls: u32, row_log: u32, comptime mode: DictMode) usize {
    return switch (row_log) {
        inline 4, 5, 6 => |rl| rowFindBestMatchT(ms, ip, iend, offset_ptr, mls, rl, mode),
        else => unreachable,
    };
}

fn rowFindBestMatchT(ms: *MatchState, ip: u32, iend: usize, offset_ptr: *u32, comptime mls: u32, comptime row_log: u32, comptime mode: DictMode) usize {
    const w: Base = .of(ms);
    const dict_limit = ms.dict_limit;
    const curr = ip;
    const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
    const lowest_valid = ms.low_limit;
    const within_max_distance = if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    const is_dictionary = ms.loaded_dict_end != 0;
    const low_limit = if (is_dictionary) lowest_valid else within_max_distance;
    const row_entries: u32 = 1 << row_log;
    const row_mask = row_entries - 1;
    const capped_search_log = @min(ms.cp.search_log, row_log); // nb of searches is capped at nb entries per row
    var nb_attempts: u32 = @as(u32, 1) << @intCast(capped_search_log);
    var ml: usize = 4 - 1;

    // The dedicated search's bucket, and the extra attempts it gets: the
    // context's rows are capped in searches, the CDict's search is not.
    var dds_idx: usize = 0;
    var dds_extra_attempts: u32 = 0;
    if (mode == .dedicated_dict_search) {
        dds_idx = ddsBucket(w, ms.dict_match_state.?, ip, mls);
        dds_extra_attempts = if (ms.cp.search_log > row_log) @as(u32, 1) << @intCast(ms.cp.search_log - row_log) else 0;
    }

    // The CDict's row: hashed with its row hash log, unsalted, into its
    // own tables, prefetched before this window's update.
    const dm: Dms = if (mode == .dict_match_state) .of(ms.dict_match_state.?) else undefined;
    var dms_tag: u8 = undefined;
    var dms_rel_row: usize = undefined;
    if (mode == .dict_match_state) {
        const dms_hash: u32 = @intCast(w.hash(ip, dm.ms.row_hash_log + tag_bits, mls));
        dms_rel_row = @as(usize, dms_hash >> tag_bits) << @intCast(row_log);
        dms_tag = @truncate(dms_hash & tag_mask);
        rowPrefetch(dm.ms, dms_hash, row_log);
    }

    // Update the hashTable and tagTable up to (but not including) ip
    var h: u32 = undefined;
    if (!ms.lazy_skipping) {
        rowUpdate(ms, ip, mls, row_log, row_mask);
        h = nextCachedHash(ms, w, curr, mls, row_log);
    } else {
        // Stop inserting every position when in the lazy skipping mode. The
        // hash cache is also not kept up to date in this mode.
        h = rowHash(ms, w, ip, mls);
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
    var matches: u64 = matchMask(row_entries, tag_row, tag, head);

    // Cycle through the matches
    while (matches > 0 and nb_attempts > 0) : (matches &= matches - 1) {
        const match_pos = (head + @as(u32, @ctz(matches))) & row_mask;
        const match_index = row[match_pos];
        if (match_pos == 0) continue;
        if (match_index < low_limit) break;
        if (mode != .ext_dict or match_index >= dict_limit)
            @prefetch(ms.src.ptr + (match_index - ms.src_base), .{})
        else
            @prefetch(ms.dict.ptr + (match_index - ms.dict_base), .{});
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
        const current_ml = candidateLength(w, ip, match_index, iend, ml, dict_limit, mode);
        if (current_ml > ml) {
            ml = current_ml;
            offset_ptr.* = curr - match_index + sequences.rep_num;
            if (ip + current_ml == iend) break; // best possible, avoids read overflow on next attempt
        }
    }

    if (mode == .dedicated_dict_search)
        return ddsSearch(w, ms.dict_match_state.?, offset_ptr, ml, nb_attempts + dds_extra_attempts, ip, iend, dict_limit, dds_idx);
    if (mode == .dict_match_state) {
        // the attempts left go to the CDict's row
        const dms_index_delta = dict_limit -% dm.end;
        const dms_row = dm.ms.hash_table[dms_rel_row..][0..row_entries];
        const dms_tag_row = dm.ms.tag_table[dms_rel_row..][0..row_entries];
        const dms_head = dms_tag_row[0] & row_mask;
        num_matches = 0;
        matches = matchMask(row_entries, dms_tag_row, dms_tag, dms_head);
        while (matches > 0 and nb_attempts > 0) : (matches &= matches - 1) {
            const match_pos = (dms_head + @as(u32, @ctz(matches))) & row_mask;
            const match_index = dms_row[match_pos];
            if (match_pos == 0) continue;
            if (match_index < dm.lowest) break;
            @prefetch(dm.ms.src.ptr + (match_index - dm.ms.src_base), .{});
            match_buffer[num_matches] = match_index;
            num_matches += 1;
            nb_attempts -= 1;
        }

        // Return the longest match
        for (match_buffer[0..num_matches]) |match_index| {
            std.debug.assert(match_index >= dm.lowest);
            var current_ml: usize = 0;
            if (dm.b.read32(match_index) == w.read32(ip))
                current_ml = countDms(w, dm.b, @as(usize, ip) + 4, @as(usize, match_index) + 4, iend, dm.end, dict_limit) + 4;
            if (current_ml > ml) {
                ml = current_ml;
                std.debug.assert(curr > match_index +% dms_index_delta);
                offset_ptr.* = curr - (match_index +% dms_index_delta) + sequences.rep_num;
                if (ip + current_ml == iend) break;
            }
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

/// The window's low end as `ZSTD_insertDUBT1` computes it: a window back
/// from `curr`, even with a dictionary (unlike `ZSTD_getLowestMatchIndex`).
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
    const w: Base = .of(ms);
    const bt = ms.chain_table;
    const bt_mask = btMask(ms);
    var idx = ms.next_to_update;
    while (idx < ip) : (idx += 1) {
        const h = w.hash(idx, ms.cp.hash_log, mls);
        const match_index = ms.hash_table[h];
        const slot = 2 * @as(usize, idx & bt_mask);
        ms.hash_table[h] = idx; // Update Hash Table
        bt[slot] = match_index; // update BT like a chain
        bt[slot + 1] = dubt_unsorted_mark;
    }
    ms.next_to_update = ip;
}

/// `ZSTD_insertDUBT1` (noDict, extDict or dictMatchState: `mode`): sort one already
/// inserted but unsorted position `curr` into the tree, comparing at most
/// `nb_compares` nodes and not descending below `bt_low`. With an extDict,
/// `curr` itself may lie in it; its input then ends at the extDict's end.
fn insertDubt1(ms: *MatchState, curr: u32, input_end: usize, nb_compares_in: u32, bt_low: u32, comptime mode: DictMode) void {
    const w: Base = .of(ms);
    const dict_limit = ms.dict_limit;
    const iend: usize = if (mode != .ext_dict or curr >= dict_limit) input_end else dict_limit;
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
        if (mode != .ext_dict or match_index + match_length >= dict_limit) {
            match_length += w.count(curr + match_length, match_index + match_length, iend);
        } else if (curr < dict_limit) { // both in extDict
            match_length += w.countInDict(curr + match_length, match_index + match_length, iend);
        } else {
            match_length += w.count2Segments(curr + match_length, match_index + match_length, iend, dict_limit, dict_limit);
        }

        // equal: no way to know if inf or sup. Drop, to guarantee consistency;
        // miss a bit of compression, but other solutions can corrupt the tree.
        if (curr + match_length == iend) break;

        if (byteAt(w, match_index + match_length, dict_limit, mode) < byteAt(w, curr + match_length, dict_limit, mode)) {
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

/// The byte at index `idx`: from the extDict below `dict_limit` in `.ext_dict` mode.
inline fn byteAt(w: Base, idx: usize, dict_limit: u32, comptime mode: DictMode) u8 {
    return if (mode == .ext_dict) w.atSeg(idx, dict_limit) else w.at(idx);
}

/// `ZSTD_DUBT_findBestMatch` (noDict, extDict or dictMatchState: `mode`). Returns the
/// best length (0 when none) and stores its offBase in `off_base_ptr`, whose
/// incoming value also prices the first candidate.
fn dubtFindBestMatch(ms: *MatchState, ip: u32, iend: usize, off_base_ptr: *u32, comptime mls: u32, comptime mode: DictMode) usize {
    const w: Base = .of(ms);
    const dict_limit = ms.dict_limit;
    const hash_table = ms.hash_table;
    const h = w.hash(ip, ms.cp.hash_log, mls);
    var match_index = hash_table[h];
    const curr = ip;
    const window_low = ms.lowestMatchIndex(curr); // ZSTD_getLowestMatchIndex
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
        insertDubt1(ms, match_index, iend, nb_candidates, unsort_limit, mode);
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
        if (mode != .ext_dict or match_index + match_length >= dict_limit) {
            match_length += w.count(curr + match_length, match_index + match_length, iend);
        } else {
            match_length += w.count2Segments(curr + match_length, match_index + match_length, iend, dict_limit, dict_limit);
        }

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
            if (curr + match_length == iend) {
                // in addition to avoiding checking any further in this
                // loop, make sure we skip checking in the dictionary
                if (mode == .dict_match_state) nb_compares = 0;
                break;
            }
        }

        if (byteAt(w, match_index + match_length, dict_limit, mode) < w.at(curr + match_length)) {
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

    if (mode == .dict_match_state and nb_compares > 0)
        best_length = dubtFindBetterDictMatch(ms, ip, iend, off_base_ptr, best_length, nb_compares, mls);

    std.debug.assert(match_end_idx > curr + 8); // ensure next_to_update is increased
    ms.next_to_update = match_end_idx - 8; // skip repetitive patterns
    return best_length;
}

/// `ZSTD_DUBT_findBetterDictMatch`: go on with the `nb_compares` left down
/// the attached CDict's binary tree (fully sorted when it was made), for a
/// match that beats `best_length` at the cost of its offset. The CDict's
/// tree is only read. Returns the best length, and its offBase in
/// `off_base_ptr`.
fn dubtFindBetterDictMatch(ms: *const MatchState, ip: u32, iend: usize, off_base_ptr: *u32, best_length_in: usize, nb_compares_in: u32, comptime mls: u32) usize {
    const dm: Dms = .of(ms.dict_match_state.?);
    const w: Base = .of(ms);
    const h = w.hash(ip, dm.ms.cp.hash_log, mls);
    var dict_match_index = dm.ms.hash_table[h];
    const prefix_start = ms.dict_limit;
    const curr = ip;
    const dict_high_limit = dm.end;
    const dict_low_limit = dm.ms.low_limit;
    const dict_index_delta = ms.low_limit -% dict_high_limit;
    const dict_bt = dm.ms.chain_table;
    const bt_mask = btMask(dm.ms);
    const bt_low = if (bt_mask >= dict_high_limit - dict_low_limit) dict_low_limit else dict_high_limit - bt_mask;
    var common_length_smaller: usize = 0;
    var common_length_larger: usize = 0;
    var best_length = best_length_in;
    var nb_compares = nb_compares_in;

    while (nb_compares > 0 and dict_match_index > dict_low_limit) : (nb_compares -= 1) {
        const next_slot = 2 * @as(usize, dict_match_index & bt_mask);
        var match_length = @min(common_length_smaller, common_length_larger); // guaranteed minimum nb of common bytes
        match_length += countDms(w, dm.b, curr + match_length, dict_match_index + match_length, iend, dict_high_limit, prefix_start);

        if (match_length > best_length) {
            const match_index = dict_match_index +% dict_index_delta;
            const gain_len = 4 * @as(i64, @intCast(match_length - best_length));
            const gain_off = @as(i64, std.math.log2_int(u32, curr - match_index + 1)) - std.math.log2_int(u32, off_base_ptr.* + 1);
            if (gain_len > gain_off) {
                best_length = match_length;
                off_base_ptr.* = curr - match_index + sequences.rep_num;
            }
            // reached end of input: ip[matchLength] is not valid, no way to
            // know if it's larger or smaller than match. Drop, to guarantee
            // consistency (miss a little bit of compression).
            if (curr + match_length == iend) break;
        }

        // past the CDict's end, the match goes on in this window's prefix
        const match_byte = if (dict_match_index + match_length >= dict_high_limit)
            w.at(dict_match_index +% dict_index_delta + match_length)
        else
            dm.b.at(dict_match_index + match_length);
        if (match_byte < w.at(curr + match_length)) {
            if (dict_match_index <= bt_low) break; // beyond tree size, stop the search
            common_length_smaller = match_length; // all smaller will now have at least this guaranteed common length
            dict_match_index = dict_bt[next_slot + 1]; // new matchIndex larger than previous (closer to current)
        } else {
            // match is larger than current
            if (dict_match_index <= bt_low) break; // beyond tree size, stop the search
            common_length_larger = match_length;
            dict_match_index = dict_bt[next_slot];
        }
    }
    return best_length;
}

/// `ZSTD_BtFindBestMatch`: tree updater, providing the best match.
fn btFindBestMatch(ms: *MatchState, ip: u32, iend: usize, off_base_ptr: *u32, comptime mls: u32, comptime mode: DictMode) usize {
    if (ip < ms.next_to_update) return 0; // skipped area
    updateDubt(ms, ip, mls);
    return dubtFindBestMatch(ms, ip, iend, off_base_ptr, mls, mode);
}

// ---------------------------------------------------------------------------
// Parser

inline fn searchMax(ms: *MatchState, ip: usize, iend: usize, offset_ptr: *u32, comptime method: Method, comptime mls: u32, row_log: u32, comptime mode: DictMode) usize {
    return switch (method) {
        .hash_chain => hcFindBestMatch(ms, @intCast(ip), iend, offset_ptr, mls, mode),
        .row => rowFindBestMatch(ms, @intCast(ip), iend, offset_ptr, mls, row_log, mode),
        .binary_tree => btFindBestMatch(ms, @intCast(ip), iend, offset_ptr, mls, mode),
    };
}

inline fn gain(ml: usize, mult: i64, off_base: u32, bonus: i64) i64 {
    return @as(i64, @intCast(ml)) * mult - @as(i64, std.math.log2_int(u32, off_base)) + bonus;
}

/// `ZSTD_compressBlock_lazy_generic` (noDict). `depth` 0 is greedy, 1 lazy,
/// 2 lazy2 and btlazy2. Stores sequences into `ss`, updates `rep`, and returns the number
/// of trailing literals.
fn lazyGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime method: Method, comptime depth: u32, comptime mls: u32) usize {
    return lazyPrefixGeneric(ms, ss, rep, istart, src_size, method, depth, mls, .no_dict);
}

/// `ZSTD_compressBlock_lazy_generic` (dictMatchState): the prefix-only
/// parser that also searches the attached `CDict`, and takes repcodes into
/// it.
fn lazyDictMatchStateGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime method: Method, comptime depth: u32, comptime mls: u32) usize {
    return lazyPrefixGeneric(ms, ss, rep, istart, src_size, method, depth, mls, .dict_match_state);
}

/// `ZSTD_compressBlock_lazy_generic` (dedicatedDictSearch): the
/// dictMatchState parser, the attached `CDict` searched through its
/// bucketed table (`ddsSearch`).
fn lazyDedicatedDictSearchGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime method: Method, comptime depth: u32, comptime mls: u32) usize {
    return lazyPrefixGeneric(ms, ss, rep, istart, src_size, method, depth, mls, .dedicated_dict_search);
}

/// The attached `CDict` (`ms->dictMatchState`) as the dictMatchState
/// variants read it. Its content lies at its own indices `lowest`..`end`;
/// the context's window starts right above them in the context's index
/// space, and `index_delta` (libzstd's `dictIndexDelta`) takes a CDict index
/// there.
const Dms = struct {
    ms: *const MatchState,
    /// `dictBase`: reads at the CDict's own indices.
    b: Base,
    /// `dms->window.dictLimit`.
    lowest: u32,
    /// `dms->window.nextSrc - dms->window.base`.
    end: u32,

    inline fn of(dms: *const MatchState) Dms {
        return .{ .ms = dms, .b = .of(dms), .lowest = dms.dict_limit, .end = @intCast(dms.src_base + dms.src.len) };
    }
};

/// `ZSTD_count_2segments(ip, match, iEnd, mEnd, iStart)` with `match` in
/// the attached CDict at its index `p_match` and `m_end` its end: the
/// count runs to the CDict's end, then on from the context's prefix start
/// `i_start`. A match already past `m_end` counts nothing, as in libzstd.
inline fn countDms(w: Base, d: Base, p_in: usize, p_match: usize, i_end: usize, m_end: usize, i_start: usize) usize {
    const v_end = if (p_match > m_end) p_in else @min(p_in + (m_end - p_match), i_end);
    var n: usize = 0;
    if (v_end > p_in) {
        const len = v_end - p_in;
        n = std.mem.indexOfDiff(u8, w.bytes(p_in, v_end), d.bytes(p_match, p_match + len)) orelse len;
    }
    if (p_match + n != m_end) return n;
    return n + w.count(p_in + n, i_start, i_end);
}

/// The dictMatchState parser's repcode test at `ip` for `rep_index` (`ip`
/// less the offset, in the context's index space): below the prefix it
/// lies in the CDict, and its 4 bytes must not straddle the CDict's end.
/// The match length, or null.
inline fn dmsRepMatchLength(w: Base, dm: Dms, ip: usize, rep_index: u32, iend: usize, prefix_lowest_index: u32, dict_index_delta: u32) ?usize {
    if (!match.indexOverlapCheck(prefix_lowest_index, rep_index)) return null;
    if (rep_index < prefix_lowest_index) {
        const rep_match = rep_index -% dict_index_delta;
        if (dm.b.read32(rep_match) != w.read32(ip)) return null;
        return countDms(w, dm.b, ip + 4, @as(usize, rep_match) + 4, iend, dm.end, prefix_lowest_index) + 4;
    }
    if (w.read32(rep_index) != w.read32(ip)) return null;
    return w.count(ip + 4, @as(usize, rep_index) + 4, iend) + 4;
}

/// `ZSTD_compressBlock_lazy_generic` for a window in one segment:
/// `.no_dict`, or `.dict_match_state` with an attached CDict. `depth` 0 is
/// greedy, 1 lazy, 2 lazy2 and btlazy2. Stores sequences into `ss`,
/// updates `rep`, and returns the number of trailing literals.
inline fn lazyPrefixGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime method: Method, comptime depth: u32, comptime mls: u32, comptime mode: DictMode) usize {
    comptime std.debug.assert(mode != .ext_dict);
    // isDxS: the dedicated dictionary search parses as dictMatchState does
    const is_dms = mode == .dict_match_state or mode == .dedicated_dict_search;
    const w: Base = .of(ms);
    const iend: usize = istart + src_size;
    // Signed: a short block puts the limit before the block start.
    const ilimit: i64 = @as(i64, @intCast(iend)) - 8 - (if (method == .row) cache_size else 0);
    const prefix_lowest_index = ms.dict_limit;
    const prefix_lowest: usize = prefix_lowest_index;
    const row_log = params.rowLog(ms.cp);
    var ip: usize = istart;
    var anchor: usize = istart;

    var offset_1: u32 = rep[0];
    var offset_2: u32 = rep[1];
    var offset_saved1: u32 = 0;
    var offset_saved2: u32 = 0;

    const dm: Dms = if (is_dms) .of(ms.dict_match_state.?) else undefined;
    const dict_index_delta: u32 = if (is_dms) prefix_lowest_index -% dm.end else 0;
    const dict_and_prefix_length: usize = (ip - prefix_lowest) + (if (is_dms) dm.end - dm.lowest else 0);

    ip += @intFromBool(dict_and_prefix_length == 0);
    if (mode == .no_dict) {
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
    // dictMatchState repCode checks don't currently handle repCode == 0
    // disabling.
    if (is_dms) std.debug.assert(offset_1 <= dict_and_prefix_length and offset_2 <= dict_and_prefix_length);

    // Reset the lazy skipping state
    ms.lazy_skipping = false;
    if (method == .row) fillHashCache(ms, mls, ms.next_to_update, ilimit, row_log);

    while (@as(i64, @intCast(ip)) < ilimit) {
        var match_length: usize = 0;
        var off_base: u32 = 1; // REPCODE1_TO_OFFBASE
        var start: usize = ip + 1;

        store: {
            // check repCode
            if (is_dms) {
                if (dmsRepMatchLength(w, dm, ip + 1, @as(u32, @intCast(ip)) +% 1 -% offset_1, iend, prefix_lowest_index, dict_index_delta)) |len| {
                    match_length = len;
                    if (depth == 0) break :store;
                }
            }
            if (mode == .no_dict and offset_1 > 0 and w.read32(ip + 1 - offset_1) == w.read32(ip + 1)) {
                match_length = w.count(ip + 1 + 4, ip + 1 + 4 - offset_1, iend) + 4;
                if (depth == 0) break :store;
            }

            // first search (depth 0)
            {
                var offbase_found: u32 = no_offset;
                const ml2 = searchMax(ms, ip, iend, &offbase_found, method, mls, row_log, mode);
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
                if (mode == .no_dict and off_base != 0 and offset_1 > 0 and w.read32(ip) == w.read32(ip - offset_1)) {
                    const ml_rep = w.count(ip + 4, ip + 4 - offset_1, iend) + 4;
                    const gain2: i64 = @as(i64, @intCast(ml_rep)) * 3;
                    const gain1 = gain(match_length, 3, off_base, 1);
                    if (ml_rep >= 4 and gain2 > gain1) {
                        match_length = ml_rep;
                        off_base = 1;
                        start = ip;
                    }
                }
                if (is_dms) {
                    if (dmsRepMatchLength(w, dm, ip, @as(u32, @intCast(ip)) -% offset_1, iend, prefix_lowest_index, dict_index_delta)) |ml_rep| {
                        const gain2: i64 = @as(i64, @intCast(ml_rep)) * 3;
                        const gain1 = gain(match_length, 3, off_base, 1);
                        if (ml_rep >= 4 and gain2 > gain1) {
                            match_length = ml_rep;
                            off_base = 1;
                            start = ip;
                        }
                    }
                }
                {
                    var ofb_candidate: u32 = no_offset;
                    const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log, mode);
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
                    if (mode == .no_dict and off_base != 0 and offset_1 > 0 and w.read32(ip) == w.read32(ip - offset_1)) {
                        const ml_rep = w.count(ip + 4, ip + 4 - offset_1, iend) + 4;
                        const gain2: i64 = @as(i64, @intCast(ml_rep)) * 4;
                        const gain1 = gain(match_length, 4, off_base, 1);
                        if (ml_rep >= 4 and gain2 > gain1) {
                            match_length = ml_rep;
                            off_base = 1;
                            start = ip;
                        }
                    }
                    if (is_dms) {
                        if (dmsRepMatchLength(w, dm, ip, @as(u32, @intCast(ip)) -% offset_1, iend, prefix_lowest_index, dict_index_delta)) |ml_rep| {
                            const gain2: i64 = @as(i64, @intCast(ml_rep)) * 4;
                            const gain1 = gain(match_length, 4, off_base, 1);
                            if (ml_rep >= 4 and gain2 > gain1) {
                                match_length = ml_rep;
                                off_base = 1;
                                start = ip;
                            }
                        }
                    }
                    {
                        var ofb_candidate: u32 = no_offset;
                        const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log, mode);
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
                if (mode == .no_dict) {
                    // only search for offset within prefix
                    while (start > anchor and start - offset > prefix_lowest and w.at(start - 1) == w.at(start - offset - 1)) {
                        start -= 1;
                        match_length += 1;
                    }
                }
                if (is_dms) {
                    const match_index: u32 = @as(u32, @intCast(start)) -% offset;
                    if (match_index < prefix_lowest_index) {
                        var m: usize = match_index -% dict_index_delta;
                        while (start > anchor and m > dm.lowest and w.at(start - 1) == dm.b.at(m - 1)) {
                            start -= 1;
                            m -= 1;
                            match_length += 1;
                        }
                    } else {
                        var m: usize = match_index;
                        while (start > anchor and m > prefix_lowest and w.at(start - 1) == w.at(m - 1)) {
                            start -= 1;
                            m -= 1;
                            match_length += 1;
                        }
                    }
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        // store sequence
        ss.store(w.bytes(anchor, start), off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if (ms.lazy_skipping) {
            // We've found a match, disable lazy skipping mode, and refill the hash cache.
            if (method == .row) fillHashCache(ms, mls, ms.next_to_update, ilimit, row_log);
            ms.lazy_skipping = false;
        }

        // check immediate repcode
        if (is_dms) {
            while (@as(i64, @intCast(ip)) <= ilimit) {
                const len = dmsRepMatchLength(w, dm, ip, @as(u32, @intCast(ip)) -% offset_2, iend, prefix_lowest_index, dict_index_delta) orelse break;
                match_length = len;
                const tmp = offset_2; // swap offset_2 <=> offset_1
                offset_2 = offset_1;
                offset_1 = tmp;
                ss.store(&.{}, 1, match_length);
                ip += match_length;
                anchor = ip;
            }
        }
        if (mode == .no_dict) {
            while (@as(i64, @intCast(ip)) <= ilimit and offset_2 > 0 and w.read32(ip) == w.read32(ip - offset_2)) {
                match_length = w.count(ip + 4, ip + 4 - offset_2, iend) + 4;
                const tmp = offset_1; // swap repcodes
                offset_1 = offset_2;
                offset_2 = tmp;
                ss.store(&.{}, 1, match_length);
                ip += match_length;
                anchor = ip;
            }
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

/// `ZSTD_compressBlock_lazy_extDict_generic`: the parser over a window in
/// two segments. Unlike the prefix-only parser it never drops a repcode at
/// the block start; each repcode check tests the offset against the window
/// at that position and refuses one whose 4 bytes straddle the extDict's
/// end.
fn lazyExtDictGeneric(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime method: Method, comptime depth: u32, comptime mls: u32) usize {
    const w: Base = .of(ms);
    const iend: usize = istart + src_size;
    const ilimit: i64 = @as(i64, @intCast(iend)) - 8 - (if (method == .row) cache_size else 0);
    const dict_limit = ms.dict_limit;
    const prefix_start: usize = dict_limit;
    const dict_start: usize = ms.low_limit;
    const row_log = params.rowLog(ms.cp);
    var ip: usize = istart;
    var anchor: usize = istart;

    var offset_1: u32 = rep[0];
    var offset_2: u32 = rep[1];
    ms.n_ext_dict_blocks += 1;

    // Reset the lazy skipping state
    ms.lazy_skipping = false;

    // init
    ip += @intFromBool(ip == prefix_start);
    if (method == .row) fillHashCache(ms, mls, ms.next_to_update, ilimit, row_log);

    while (@as(i64, @intCast(ip)) < ilimit) {
        var match_length: usize = 0;
        var off_base: u32 = 1; // REPCODE1_TO_OFFBASE
        var start: usize = ip + 1;
        var curr: u32 = @intCast(ip);

        store: {
            // check repCode
            if (repMatchLength(ms, w, curr + 1, offset_1, iend, dict_limit)) |len| {
                match_length = len;
                if (depth == 0) break :store;
            }

            // first search (depth 0)
            {
                var ofb_candidate: u32 = no_offset;
                const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log, .ext_dict);
                if (ml2 > match_length) {
                    match_length = ml2;
                    start = ip;
                    off_base = ofb_candidate;
                }
            }

            if (match_length < 4) {
                const step = (ip - anchor) >> match.search_strength;
                ip += step + 1; // jump faster over incompressible sections
                ms.lazy_skipping = step > lazy_skipping_step;
                continue;
            }

            // let's try to find a better solution
            if (depth >= 1) while (@as(i64, @intCast(ip)) < ilimit) {
                ip += 1;
                curr += 1;
                // check repCode
                if (off_base != 0) if (repMatchLength(ms, w, curr, offset_1, iend, dict_limit)) |rep_length| {
                    const gain2: i64 = @as(i64, @intCast(rep_length)) * 3;
                    const gain1 = gain(match_length, 3, off_base, 1);
                    if (rep_length >= 4 and gain2 > gain1) {
                        match_length = rep_length;
                        off_base = 1;
                        start = ip;
                    }
                };

                // search match, depth 1
                {
                    var ofb_candidate: u32 = no_offset;
                    const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log, .ext_dict);
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
                    curr += 1;
                    // check repCode
                    if (off_base != 0) if (repMatchLength(ms, w, curr, offset_1, iend, dict_limit)) |rep_length| {
                        const gain2: i64 = @as(i64, @intCast(rep_length)) * 4;
                        const gain1 = gain(match_length, 4, off_base, 1);
                        if (rep_length >= 4 and gain2 > gain1) {
                            match_length = rep_length;
                            off_base = 1;
                            start = ip;
                        }
                    };

                    // search match, depth 2
                    {
                        var ofb_candidate: u32 = no_offset;
                        const ml2 = searchMax(ms, ip, iend, &ofb_candidate, method, mls, row_log, .ext_dict);
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
                var match_index: usize = start - offset;
                const m_start: usize = if (match_index < dict_limit) dict_start else prefix_start;
                while (start > anchor and match_index > m_start and w.at(start - 1) == w.atSeg(match_index - 1, dict_limit)) {
                    start -= 1;
                    match_index -= 1;
                    match_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        // store sequence
        ss.store(w.bytes(anchor, start), off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if (ms.lazy_skipping) {
            // We've found a match, disable lazy skipping mode, and refill the hash cache.
            if (method == .row) fillHashCache(ms, mls, ms.next_to_update, ilimit, row_log);
            ms.lazy_skipping = false;
        }

        // check immediate repcode
        while (@as(i64, @intCast(ip)) <= ilimit) {
            const len = repMatchLength(ms, w, @intCast(ip), offset_2, iend, dict_limit) orelse break;
            match_length = len;
            const tmp = offset_1; // swap offset history
            offset_1 = offset_2;
            offset_2 = tmp;
            ss.store(&.{}, 1, match_length);
            ip += match_length;
            anchor = ip;
        }
    }

    // Save reps for next block
    rep[0] = offset_1;
    rep[1] = offset_2;
    return iend - anchor;
}

/// The extDict parser's repcode test at index `curr` for `offset`: the
/// match length when the offset lies within the window, its 4 bytes do not
/// straddle the extDict's end, and they match; else null.
inline fn repMatchLength(ms: *const MatchState, w: Base, curr: u32, offset: u32, iend: usize, dict_limit: u32) ?usize {
    const window_low = ms.lowestMatchIndex(curr);
    const rep_index = curr -% offset;
    if (!(match.indexOverlapCheck(dict_limit, rep_index) and offset <= curr - window_low)) return null;
    if (w.read32(curr) != w.read32Seg(rep_index, dict_limit)) return null;
    const rep_end: usize = if (rep_index < dict_limit) dict_limit else iend;
    return w.count2Segments(@as(usize, curr) + 4, @as(usize, rep_index) + 4, iend, rep_end, dict_limit) + 4;
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
