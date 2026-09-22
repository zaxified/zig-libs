// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Match finders for the `fast` and `dfast` strategies, and the match state
//! every strategy shares (the lazy and binary-tree ones live in `lazy.zig`).
//!
//! Port of the no-dictionary paths of libzstd lib/compress/zstd_fast.c and
//! lib/compress/zstd_double_fast.c, with the window helpers and hashes of
//! lib/compress/zstd_compress_internal.h (v1.5.7).
//!
//! Positions are libzstd *indices*: the whole input is one contiguous prefix
//! and index `i` names `src[i - window_start]`. libzstd starts indexing at 2 so
//! that a zero in a hash table always means "empty"; keeping the same numbers
//! keeps every table comparison and every repeat-offset bound identical.

const std = @import("std");
const params = @import("params.zig");
const sequences = @import("sequences.zig");
const lazy = @import("lazy.zig");
const SeqStore = sequences.SeqStore;

/// `ZSTD_WINDOW_START_INDEX`.
pub const window_start = 2;
/// `HASH_READ_SIZE`.
pub const hash_read_size = 8;
/// `kSearchStrength`.
pub const search_strength = 8;
/// `ZSTD_ROW_HASH_CACHE_SIZE`.
pub const row_hash_cache_size = 8;

pub const MatchState = struct {
    src: []const u8,
    cp: params.CParams,
    hash_table: []u32,
    /// dfast: the short-hash table; greedy..lazy2 without the row match
    /// finder: the hash chains; btlazy2: the binary tree, two entries per
    /// position (`chainTable` in libzstd). Empty otherwise.
    chain_table: []u32,
    /// Row match finder only: one tag byte per `hash_table` slot; the first
    /// byte of each row holds the row's head (`tagTable`).
    tag_table: []u8 = &.{},
    /// `window.lowLimit` / `window.dictLimit`; equal here (no extDict ever).
    low_limit: u32 = window_start,
    dict_limit: u32 = window_start,
    /// First index the lazy match finders have not inserted yet.
    next_to_update: u32 = window_start,
    /// Row match finder: `rowHashLog` (hash_log - rowLog) and hash salt.
    row_hash_log: u32 = 0,
    hash_salt: u64 = 0,
    hash_salt_entropy: u32 = 0,
    hash_cache: [row_hash_cache_size]u32 = @splat(0),
    lazy_skipping: bool = false,

    pub inline fn at(ms: *const MatchState, idx: usize) u8 {
        return ms.src[idx - window_start];
    }
    pub inline fn read32(ms: *const MatchState, idx: usize) u32 {
        return std.mem.readInt(u32, ms.src[idx - window_start ..][0..4], .little);
    }
    pub inline fn read64(ms: *const MatchState, idx: usize) u64 {
        return std.mem.readInt(u64, ms.src[idx - window_start ..][0..8], .little);
    }

    /// `ZSTD_count`: length of the common run at `p_in` and `p_match`,
    /// not reading at or past `p_limit` on the `p_in` side.
    pub fn count(ms: *const MatchState, p_in: usize, p_match: usize, p_limit: usize) usize {
        const s = ms.src;
        var i = p_in - window_start;
        var m = p_match - window_start;
        const lim = p_limit - window_start;
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

    /// `ZSTD_hashPtr` for `mls` in 4..8.
    pub inline fn hash(ms: *const MatchState, idx: usize, h_bits: u32, mls: u32) usize {
        return ms.hashSalted(idx, h_bits, mls, 0);
    }

    /// `ZSTD_hashPtrSalted`: `h_bits` up to 32.
    pub inline fn hashSalted(ms: *const MatchState, idx: usize, h_bits: u32, mls: u32, salt: u64) usize {
        const sh: u6 = @intCast(64 - h_bits);
        return switch (mls) {
            5 => @intCast((((ms.read64(idx) << 24) *% prime5) ^ salt) >> sh),
            6 => @intCast((((ms.read64(idx) << 16) *% prime6) ^ salt) >> sh),
            7 => @intCast((((ms.read64(idx) << 8) *% prime7) ^ salt) >> sh),
            8 => @intCast(((ms.read64(idx) *% prime8) ^ salt) >> sh),
            else => @intCast(((ms.read32(idx) *% prime4) ^ @as(u32, @truncate(salt))) >> @intCast(32 - h_bits)),
        };
    }

    /// `ZSTD_window_enforceMaxDist(window, blockStart, maxDist, NULL, NULL)`.
    pub fn enforceMaxDist(ms: *MatchState, block_start_idx: u32) void {
        const max_dist: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
        if (block_start_idx > max_dist) {
            const new_low = block_start_idx - max_dist;
            if (ms.low_limit < new_low) ms.low_limit = new_low;
            if (ms.dict_limit < ms.low_limit) ms.dict_limit = ms.low_limit;
        }
    }

    /// `ZSTD_getLowestPrefixIndex` without a dictionary.
    pub fn lowestPrefixIndex(ms: *const MatchState, curr: u32) u32 {
        const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
        const lowest_valid = ms.dict_limit;
        return if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    }
};

const prime4: u32 = 2654435761;
const prime5: u64 = 889523592379;
const prime6: u64 = 227718039650203;
const prime7: u64 = 58295818150454627;
const prime8: u64 = 0xCF1BBCDCB7A56463;

/// Compress one block with the strategy in `ms.cp`. Stores sequences into
/// `ss`, updates `rep`, and returns the number of trailing literals.
pub fn compressBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32) usize {
    const mls = ms.cp.min_match;
    return switch (ms.cp.strategy) {
        .fast => switch (mls) {
            5 => fastBlock(ms, ss, rep, istart, src_size, 5),
            6 => fastBlock(ms, ss, rep, istart, src_size, 6),
            7 => fastBlock(ms, ss, rep, istart, src_size, 7),
            else => fastBlock(ms, ss, rep, istart, src_size, 4),
        },
        .dfast => switch (mls) {
            5 => dfastBlock(ms, ss, rep, istart, src_size, 5),
            6 => dfastBlock(ms, ss, rep, istart, src_size, 6),
            7 => dfastBlock(ms, ss, rep, istart, src_size, 7),
            else => dfastBlock(ms, ss, rep, istart, src_size, 4),
        },
        .greedy, .lazy, .lazy2, .btlazy2 => lazy.compressBlock(ms, ss, rep, istart, src_size),
        else => unreachable, // above params.max_level
    };
}

/// `ZSTD_compressBlock_fast_noDict_generic`. The cmov and branch variants of
/// libzstd's `matchFound` accept exactly the same candidates, so one serves.
fn fastBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime mls: u32) usize {
    const hash_table = ms.hash_table;
    const hlog = ms.cp.hash_log;
    const step_size: usize = ms.cp.target_length + @intFromBool(ms.cp.target_length == 0) + 1;
    const end_index: u32 = istart + src_size;
    const prefix_start_index = ms.lowestPrefixIndex(end_index);
    const prefix_start: usize = prefix_start_index;
    const iend: usize = end_index;
    const ilimit: usize = iend - hash_read_size;

    var anchor: usize = istart;
    var ip0: usize = istart;
    var ip1: usize = undefined;
    var ip2: usize = undefined;
    var ip3: usize = undefined;
    var current0: u32 = undefined;

    var rep_offset1: u32 = rep[0];
    var rep_offset2: u32 = rep[1];
    var offset_saved1: u32 = 0;
    var offset_saved2: u32 = 0;

    var hash0: usize = undefined;
    var hash1: usize = undefined;
    var match_idx: u32 = undefined;
    var offcode: u32 = undefined;
    var match0: usize = undefined;
    var m_length: usize = undefined;
    var step: usize = undefined;
    var next_step: usize = undefined;
    const step_incr: usize = 1 << (search_strength - 1);

    ip0 += @intFromBool(ip0 == prefix_start);
    {
        const curr: u32 = @intCast(ip0);
        const window_low = ms.lowestPrefixIndex(curr);
        const max_rep = curr - window_low;
        if (rep_offset2 > max_rep) {
            offset_saved2 = rep_offset2;
            rep_offset2 = 0;
        }
        if (rep_offset1 > max_rep) {
            offset_saved1 = rep_offset1;
            rep_offset1 = 0;
        }
    }

    outer: while (true) {
        // _start
        step = step_size;
        next_step = ip0 + step_incr;
        ip1 = ip0 + 1;
        ip2 = ip0 + step;
        ip3 = ip2 + 1;
        if (ip3 >= ilimit) break :outer;

        hash0 = ms.hash(ip0, hlog, mls);
        hash1 = ms.hash(ip1, hlog, mls);
        match_idx = hash_table[hash0];

        const found: enum { rep, offset } = search: while (true) {
            // check repcode at ip[2]
            const rval = ms.read32(ip2 - rep_offset1);
            current0 = @intCast(ip0);
            hash_table[hash0] = current0;
            if (ms.read32(ip2) == rval and rep_offset1 > 0) {
                ip0 = ip2;
                match0 = ip0 - rep_offset1;
                m_length = @intFromBool(ms.at(ip0 - 1) == ms.at(match0 - 1));
                ip0 -= m_length;
                match0 -= m_length;
                offcode = 1; // REPCODE1_TO_OFFBASE
                m_length += 4;
                // Write next hash table entry: it's already calculated.
                hash_table[hash1] = @intCast(ip1);
                break :search .rep;
            }
            if (match_idx >= prefix_start_index and ms.read32(ip0) == ms.read32(match_idx)) {
                hash_table[hash1] = @intCast(ip1);
                break :search .offset;
            }

            // lookup ip[1]
            match_idx = hash_table[hash1];
            hash0 = hash1;
            hash1 = ms.hash(ip2, hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;

            current0 = @intCast(ip0);
            hash_table[hash0] = current0;
            if (match_idx >= prefix_start_index and ms.read32(ip0) == ms.read32(match_idx)) {
                if (step <= 4) hash_table[hash1] = @intCast(ip1);
                break :search .offset;
            }

            // lookup ip[2]
            match_idx = hash_table[hash1];
            hash0 = hash1;
            hash1 = ms.hash(ip2, hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip0 + step;
            ip3 = ip1 + step;
            if (ip2 >= next_step) {
                step += 1;
                next_step += step_incr;
            }
            if (!(ip3 < ilimit)) break :outer;
        };

        if (found == .offset) {
            match0 = match_idx;
            rep_offset2 = rep_offset1;
            rep_offset1 = @intCast(ip0 - match0);
            offcode = rep_offset1 + sequences.rep_num;
            m_length = 4;
            // Count the backwards match length.
            while (ip0 > anchor and match0 > prefix_start and ms.at(ip0 - 1) == ms.at(match0 - 1)) {
                ip0 -= 1;
                match0 -= 1;
                m_length += 1;
            }
        }

        // _match: count the forward length
        m_length += ms.count(ip0 + m_length, match0 + m_length, iend);
        ss.store(ms.src[anchor - window_start .. ip0 - window_start], offcode, m_length);
        ip0 += m_length;
        anchor = ip0;

        // Fill table and check for immediate repcode.
        if (ip0 <= ilimit) {
            hash_table[ms.hash(current0 + 2, hlog, mls)] = current0 + 2;
            hash_table[ms.hash(ip0 - 2, hlog, mls)] = @intCast(ip0 - 2);
            if (rep_offset2 > 0) {
                while (ip0 <= ilimit and ms.read32(ip0) == ms.read32(ip0 - rep_offset2)) {
                    const r_length = ms.count(ip0 + 4, ip0 + 4 - rep_offset2, iend) + 4;
                    std.mem.swap(u32, &rep_offset1, &rep_offset2);
                    hash_table[ms.hash(ip0, hlog, mls)] = @intCast(ip0);
                    ip0 += r_length;
                    ss.store(&.{}, 1, r_length);
                    anchor = ip0;
                }
            }
        }
    }

    // _cleanup: save reps for next block
    offset_saved2 = if (offset_saved1 != 0 and rep_offset1 != 0) offset_saved1 else offset_saved2;
    rep[0] = if (rep_offset1 != 0) rep_offset1 else offset_saved1;
    rep[1] = if (rep_offset2 != 0) rep_offset2 else offset_saved2;
    return iend - anchor;
}

/// `ZSTD_compressBlock_doubleFast_noDict_generic`.
fn dfastBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime mls: u32) usize {
    const hash_long = ms.hash_table;
    const h_bits_l = ms.cp.hash_log;
    const hash_small = ms.chain_table;
    const h_bits_s = ms.cp.chain_log;
    var anchor: usize = istart;
    const end_index: u32 = istart + src_size;
    const prefix_lowest_index = ms.lowestPrefixIndex(end_index);
    const prefix_lowest: usize = prefix_lowest_index;
    const iend: usize = end_index;
    const ilimit: usize = iend - hash_read_size;
    var offset_1: u32 = rep[0];
    var offset_2: u32 = rep[1];
    var offset_saved1: u32 = 0;
    var offset_saved2: u32 = 0;

    var m_length: usize = undefined;
    var offset: u32 = undefined;
    var curr: u32 = undefined;
    const step_incr: usize = 1 << search_strength;
    var next_step: usize = undefined;
    var step: usize = undefined;
    var hl0: usize = undefined;
    var hl1: usize = undefined;
    var idxl0: u32 = undefined;
    var idxl1: u32 = undefined;
    var matchl0: usize = undefined;
    var matchs0: usize = undefined;
    var matchl1: usize = undefined;

    var ip: usize = istart;
    var ip1: usize = undefined;

    // init
    ip += @intFromBool(ip == prefix_lowest);
    {
        const current: u32 = @intCast(ip);
        const window_low = ms.lowestPrefixIndex(current);
        const max_rep = current - window_low;
        if (offset_2 > max_rep) {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if (offset_1 > max_rep) {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    outer: while (true) {
        step = 1;
        next_step = ip + step_incr;
        ip1 = ip + step;
        if (ip1 > ilimit) break :outer;

        hl0 = ms.hash(ip, h_bits_l, 8);
        idxl0 = hash_long[hl0];
        matchl0 = idxl0;

        const found: enum { stored, found, next_long } = search: while (true) {
            const hs0 = ms.hash(ip, h_bits_s, mls);
            const idxs0 = hash_small[hs0];
            curr = @intCast(ip);
            matchs0 = idxs0;

            hash_long[hl0] = curr;
            hash_small[hs0] = curr; // update hash tables

            // check noDict repcode
            if (offset_1 > 0 and ms.read32(ip + 1 - offset_1) == ms.read32(ip + 1)) {
                m_length = ms.count(ip + 1 + 4, ip + 1 + 4 - offset_1, iend) + 4;
                ip += 1;
                ss.store(ms.src[anchor - window_start .. ip - window_start], 1, m_length);
                break :search .stored;
            }

            hl1 = ms.hash(ip1, h_bits_l, 8);

            // idxl0 > 0 && idxl0 >= prefixLowestIndex
            if (idxl0 >= prefix_lowest_index and ms.read64(matchl0) == ms.read64(ip)) {
                m_length = ms.count(ip + 8, matchl0 + 8, iend) + 8;
                offset = @intCast(ip - matchl0);
                while (ip > anchor and matchl0 > prefix_lowest and ms.at(ip - 1) == ms.at(matchl0 - 1)) {
                    ip -= 1;
                    matchl0 -= 1;
                    m_length += 1;
                }
                break :search .found;
            }

            idxl1 = hash_long[hl1];
            matchl1 = idxl1;

            // Is there a short match at ip?
            if (idxs0 >= prefix_lowest_index and ms.read32(matchs0) == ms.read32(ip)) {
                break :search .next_long;
            }

            if (ip1 >= next_step) {
                step += 1;
                next_step += step_incr;
            }
            ip = ip1;
            ip1 += step;

            hl0 = hl1;
            idxl0 = idxl1;
            matchl0 = matchl1;
            if (!(ip1 <= ilimit)) break :outer;
        };

        if (found == .next_long) {
            // check prefix long +1 match
            m_length = ms.count(ip + 4, matchs0 + 4, iend) + 4;
            offset = @intCast(ip - matchs0);
            if (idxl1 > prefix_lowest_index and ms.read64(matchl1) == ms.read64(ip1)) {
                const l1len = ms.count(ip1 + 8, matchl1 + 8, iend) + 8;
                if (l1len > m_length) {
                    // use the long match found
                    ip = ip1;
                    m_length = l1len;
                    offset = @intCast(ip - matchl1);
                    matchs0 = matchl1;
                }
            }
            while (ip > anchor and matchs0 > prefix_lowest and ms.at(ip - 1) == ms.at(matchs0 - 1)) {
                ip -= 1;
                matchs0 -= 1;
                m_length += 1;
            }
        }

        if (found != .stored) {
            // _match_found
            offset_2 = offset_1;
            offset_1 = offset;
            if (step < 4) {
                // Write next hash table entry: it's already calculated.
                hash_long[hl1] = @intCast(ip1);
            }
            ss.store(ms.src[anchor - window_start .. ip - window_start], offset + sequences.rep_num, m_length);
        }

        // _match_stored
        ip += m_length;
        anchor = ip;

        if (ip <= ilimit) {
            // Complementary insertion
            const index_to_insert = curr + 2;
            hash_long[ms.hash(index_to_insert, h_bits_l, 8)] = index_to_insert;
            hash_long[ms.hash(ip - 2, h_bits_l, 8)] = @intCast(ip - 2);
            hash_small[ms.hash(index_to_insert, h_bits_s, mls)] = index_to_insert;
            hash_small[ms.hash(ip - 1, h_bits_s, mls)] = @intCast(ip - 1);

            // check immediate repcode
            while (ip <= ilimit and offset_2 > 0 and ms.read32(ip) == ms.read32(ip - offset_2)) {
                const r_length = ms.count(ip + 4, ip + 4 - offset_2, iend) + 4;
                std.mem.swap(u32, &offset_1, &offset_2);
                hash_small[ms.hash(ip, h_bits_s, mls)] = @intCast(ip);
                hash_long[ms.hash(ip, h_bits_l, 8)] = @intCast(ip);
                ss.store(&.{}, 1, r_length);
                ip += r_length;
                anchor = ip;
            }
        }
    }

    // _cleanup
    offset_saved2 = if (offset_saved1 != 0 and offset_1 != 0) offset_saved1 else offset_saved2;
    rep[0] = if (offset_1 != 0) offset_1 else offset_saved1;
    rep[1] = if (offset_2 != 0) offset_2 else offset_saved2;
    return iend - anchor;
}
