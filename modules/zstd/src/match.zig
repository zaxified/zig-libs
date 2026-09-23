// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Match finders for the `fast` and `dfast` strategies, and the match state
//! every strategy shares (the lazy and binary-tree ones live in `lazy.zig`,
//! the optimal parser in `opt.zig`).
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
const opt = @import("opt.zig");
const ldm = @import("ldm.zig");
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
    /// `src[0]` is index `src_base`: the prefix segment, libzstd's
    /// `window.base + src_base` up to `window.nextSrc`.
    src_base: u32 = window_start,
    /// The extDict segment (`window.dictBase`): `dict[0]` is index
    /// `dict_base`; only `low_limit`..`dict_limit` of it is valid. Empty
    /// until a stream's input stops being contiguous (see `windowUpdate`).
    dict: []const u8 = &.{},
    dict_base: u32 = window_start,
    /// A stream's input buffer. An extDict inside it stays readable up to
    /// the buffer's end: libzstd's 8-byte reads near the segment's end
    /// (dfast) run a byte past it, into whatever the buffer holds there.
    buffer: []const u8 = &.{},
    /// `window.lowLimit` / `window.dictLimit`: indices below `dict_limit`
    /// are in `dict`, and none below `low_limit` is valid.
    low_limit: u32 = window_start,
    dict_limit: u32 = window_start,
    /// `window.nbOverflowCorrections`.
    n_overflow_corrections: u32 = 0,
    /// Blocks the extDict variant of a match finder searched (not those it
    /// handed to the plain variant because the window had left the extDict
    /// behind). Not libzstd's; tests read it here.
    n_ext_dict_blocks: u32 = 0,
    /// First index the lazy match finders have not inserted yet.
    next_to_update: u32 = window_start,
    /// Row match finder: `rowHashLog` (hash_log - rowLog) and hash salt.
    row_hash_log: u32 = 0,
    hash_salt: u64 = 0,
    hash_salt_entropy: u32 = 0,
    hash_cache: [row_hash_cache_size]u32 = @splat(0),
    lazy_skipping: bool = false,
    /// `minMatch` 3 with the optimal parser: newest index per 3-byte hash
    /// (`hashTable3`, `hashLog3`).
    hash_table3: []u32 = &.{},
    hash_log3: u32 = 0,
    /// btopt and up: the parser's statistics and scratch tables.
    opt: ?*opt.State = null,
    /// The block's long-distance matches while the optimal parser runs on
    /// it (`ms->ldmSeqStore`); the parser reads a copy.
    ldm_seq_store: ?*const ldm.RawSeqStore = null,

    pub inline fn at(ms: *const MatchState, idx: usize) u8 {
        return ms.src[idx - ms.src_base];
    }
    pub inline fn read32(ms: *const MatchState, idx: usize) u32 {
        return std.mem.readInt(u32, ms.src[idx - ms.src_base ..][0..4], .little);
    }
    pub inline fn read64(ms: *const MatchState, idx: usize) u64 {
        return std.mem.readInt(u64, ms.src[idx - ms.src_base ..][0..8], .little);
    }
    /// The prefix bytes at indices `from`..`to`.
    pub inline fn bytes(ms: *const MatchState, from: usize, to: usize) []const u8 {
        return ms.src[from - ms.src_base .. to - ms.src_base];
    }

    /// The byte at `idx` of whichever segment holds it: libzstd's
    /// `(idx < prefixStart ? dictBase : base) + idx`.
    pub inline fn atSeg(ms: *const MatchState, idx: usize, prefix_start: usize) u8 {
        return if (idx < prefix_start) ms.dict[idx - ms.dict_base] else ms.src[idx - ms.src_base];
    }
    pub inline fn read32Seg(ms: *const MatchState, idx: usize, prefix_start: usize) u32 {
        const s = if (idx < prefix_start) ms.dict[idx - ms.dict_base ..] else ms.src[idx - ms.src_base ..];
        return std.mem.readInt(u32, s[0..4], .little);
    }
    pub inline fn read64Seg(ms: *const MatchState, idx: usize, prefix_start: usize) u64 {
        const s = if (idx < prefix_start) ms.dict[idx - ms.dict_base ..] else ms.src[idx - ms.src_base ..];
        return std.mem.readInt(u64, s[0..8], .little);
    }

    /// `ZSTD_window_hasExtDict`.
    pub inline fn hasExtDict(ms: *const MatchState) bool {
        return ms.low_limit < ms.dict_limit;
    }

    /// `ZSTD_window_update`: `chunk` is the next input to compress. Where
    /// it does not follow the prefix in memory (a stream's input buffer
    /// wrapped, or a new buffer), the prefix becomes the extDict and the
    /// chunk starts a new prefix at the next index. Input that overwrites
    /// the extDict's memory raises `low_limit` past it. Returns whether the
    /// chunk was contiguous.
    pub fn windowUpdate(ms: *MatchState, chunk: []const u8) bool {
        if (chunk.len == 0) return true;
        var contiguous = true;
        // A fresh window's `nextSrc` points at nothing, so the first chunk
        // takes this path too (and changes nothing but the base).
        if (ms.src.len == 0 or @intFromPtr(chunk.ptr) != @intFromPtr(ms.src.ptr) + ms.src.len) {
            const distance_from_base: u32 = @intCast(ms.src_base + ms.src.len);
            ms.low_limit = ms.dict_limit;
            ms.dict_limit = distance_from_base;
            ms.dict = ms.src;
            ms.dict_base = ms.src_base;
            const buf = @intFromPtr(ms.buffer.ptr);
            const old = @intFromPtr(ms.src.ptr);
            if (ms.src.len != 0 and old >= buf and old + ms.src.len <= buf + ms.buffer.len)
                ms.dict = ms.src.ptr[0 .. buf + ms.buffer.len - old];
            ms.src = chunk[0..0];
            ms.src_base = distance_from_base;
            // too small extDict
            if (ms.dict_limit - ms.low_limit < hash_read_size) ms.low_limit = ms.dict_limit;
            contiguous = false;
        }
        ms.src = ms.src.ptr[0 .. ms.src.len + chunk.len];
        // if input and dictionary overlap: reduce dictionary (area presumed
        // modified by input)
        if (ms.low_limit < ms.dict_limit) {
            const dict_origin: i128 = @as(i128, @intFromPtr(ms.dict.ptr)) - ms.dict_base; // dictBase
            const ip: i128 = @intFromPtr(chunk.ptr);
            const iend: i128 = ip + chunk.len;
            if (iend > dict_origin + ms.low_limit and ip < dict_origin + ms.dict_limit) {
                const high_input_idx = iend - dict_origin;
                ms.low_limit = if (high_input_idx > ms.dict_limit) ms.dict_limit else @intCast(high_input_idx);
            }
        }
        return contiguous;
    }

    /// `ZSTD_getLowestMatchIndex` without a dictionary.
    pub fn lowestMatchIndex(ms: *const MatchState, curr: u32) u32 {
        const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
        const lowest_valid = ms.low_limit;
        return if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    }

    /// `ZSTD_count_2segments` over indices: a match in the extDict
    /// (`m_end` is the extDict's end, the prefix start) may run into
    /// `m_end`, where libzstd goes on counting against `i_start` (the
    /// prefix's first byte). With `m_end == i_end` the match is in the
    /// prefix, which it cannot outrun, so it is a plain `count`.
    pub fn count2Segments(ms: *const MatchState, p_in: usize, p_match: usize, i_end: usize, m_end: usize, i_start: usize) usize {
        if (m_end == i_end) return ms.count(p_in, p_match, i_end);
        const v_end = if (p_match > m_end) p_in else @min(p_in + (m_end - p_match), i_end);
        const match_length = ms.countDict(p_in, p_match, v_end);
        if (p_match + match_length != m_end) return match_length;
        return match_length + ms.count(p_in + match_length, i_start, i_end);
    }

    /// `ZSTD_count` with both sides in the extDict (`binary tree insertion
    /// of a position that is itself in the extDict).
    pub fn countInDict(ms: *const MatchState, p_in: usize, p_match: usize, p_limit: usize) usize {
        if (p_limit <= p_in) return 0;
        const n = p_limit - p_in;
        const a = ms.dict[p_in - ms.dict_base ..][0..n];
        const b = ms.dict[p_match - ms.dict_base ..][0..n];
        return std.mem.indexOfDiff(u8, a, b) orelse n;
    }

    /// `ZSTD_count` with the match side in the extDict.
    fn countDict(ms: *const MatchState, p_in: usize, p_match: usize, p_limit: usize) usize {
        if (p_limit <= p_in) return 0;
        const n = p_limit - p_in;
        const a = ms.src[p_in - ms.src_base ..][0..n];
        const b = ms.dict[p_match - ms.dict_base ..][0..n];
        return std.mem.indexOfDiff(u8, a, b) orelse n;
    }

    /// `ZSTD_count`: length of the common run at `p_in` and `p_match`,
    /// not reading at or past `p_limit` on the `p_in` side.
    pub fn count(ms: *const MatchState, p_in: usize, p_match: usize, p_limit: usize) usize {
        const s = ms.src;
        var i = p_in - ms.src_base;
        var m = p_match - ms.src_base;
        const lim = p_limit - ms.src_base;
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

    /// `ZSTD_overflowCorrectIfNeeded` for the block at indices
    /// `ip`..`iend`. Returns the correction made (0 for none): every index
    /// drops by it, and `src` loses that many bytes at the front, which is
    /// libzstd's `window.base += correction`.
    pub fn overflowCorrectIfNeeded(ms: *MatchState, frequently: bool, ip: usize, iend: usize) u32 {
        const cycle_log = params.cycleLog(ms.cp);
        const max_dist: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
        if (!needOverflowCorrection(frequently, ms.n_overflow_corrections, cycle_log, max_dist, ip, iend)) return 0;
        const correction = correctOverflow(&ms.low_limit, &ms.dict_limit, &ms.n_overflow_corrections, frequently, cycle_log, max_dist, @intCast(ip));
        // `window.base` and `window.dictBase` move up by the correction: a
        // segment whose first index would drop below `window_start` loses
        // those bytes at the front (they are outside the window).
        shiftSegment(&ms.src, &ms.src_base, correction);
        shiftSegment(&ms.dict, &ms.dict_base, correction);
        // ZSTD_reduceIndex
        reduceTable(ms.hash_table, correction, false);
        reduceTable(ms.chain_table, correction, ms.cp.strategy == .btlazy2);
        reduceTable(ms.hash_table3, correction, false);
        ms.next_to_update = if (ms.next_to_update < correction) 0 else ms.next_to_update - correction;
        return correction;
    }

    /// `ZSTD_getLowestPrefixIndex` without a dictionary.
    pub fn lowestPrefixIndex(ms: *const MatchState, curr: u32) u32 {
        const max_distance: u32 = @as(u32, 1) << @intCast(ms.cp.window_log);
        const lowest_valid = ms.dict_limit;
        return if (curr - lowest_valid > max_distance) curr - max_distance else lowest_valid;
    }
};

/// Indices of `seg` (whose first byte is index `base.*`) drop by
/// `correction`.
fn shiftSegment(seg: *[]const u8, base: *u32, correction: u32) void {
    if (base.* >= correction + window_start) {
        base.* -= correction;
    } else {
        seg.* = seg.*[@min(seg.len, correction + window_start - base.*)..];
        base.* = window_start;
    }
}

/// `ZSTD_CURRENT_MAX` on 64-bit: past this index the indices are rescaled.
pub const current_max: u32 = 3500 << 20;

/// `ZSTD_window_canOverflowCorrect` (no dictionary: `loadedDictEnd` 0).
fn canOverflowCorrect(n_corrections: u32, cycle_log: u32, max_dist: u32, curr: u32) bool {
    const cycle_size = @as(u32, 1) << @intCast(cycle_log);
    const min_index_to_overflow_correct = cycle_size +% @max(max_dist, cycle_size) +% window_start;
    // Back off the correction frequency; if the product overflows it only
    // has to stay at least the minimum.
    const adjustment = n_corrections +% 1;
    const adjusted_index = @max(min_index_to_overflow_correct *% adjustment, min_index_to_overflow_correct);
    const index_large_enough = curr > adjusted_index;
    const dictionary_invalidated = curr > max_dist;
    return index_large_enough and dictionary_invalidated;
}

/// `ZSTD_window_needOverflowCorrection` for the chunk at indices
/// `ip`..`iend`. `frequently` is `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`,
/// libzstd's fuzzing switch: correct whenever it is safe, not only past
/// `current_max`, which is how the tests reach this code on small inputs.
pub fn needOverflowCorrection(frequently: bool, n_corrections: u32, cycle_log: u32, max_dist: u32, ip: usize, iend: usize) bool {
    if (frequently and canOverflowCorrect(n_corrections, cycle_log, max_dist, @intCast(ip))) return true;
    return iend > current_max;
}

/// `ZSTD_window_correctOverflow`: the correction that brings index `curr`
/// down to just above `max_dist` while keeping its low `cycle_log` bits
/// (the chains and trees index by them). Updates the window limits; the
/// caller moves its base and reduces its tables.
pub fn correctOverflow(low_limit: *u32, dict_limit: *u32, n_corrections: *u32, frequently: bool, cycle_log: u32, max_dist: u32, curr: u32) u32 {
    const cycle_size = @as(u32, 1) << @intCast(cycle_log);
    const cycle_mask = cycle_size - 1;
    const current_cycle = curr & cycle_mask;
    // Ensure newCurrent - maxDist >= ZSTD_WINDOW_START_INDEX.
    const current_cycle_correction: u32 = if (current_cycle < window_start) @max(cycle_size, window_start) else 0;
    const new_current = current_cycle + current_cycle_correction + @max(max_dist, cycle_size);
    const correction = curr - new_current;
    std.debug.assert(max_dist & (max_dist - 1) == 0);
    std.debug.assert(curr & cycle_mask == new_current & cycle_mask);
    std.debug.assert(curr > new_current);
    if (!frequently) std.debug.assert(correction > 1 << 28);

    low_limit.* = if (low_limit.* < correction + window_start) window_start else low_limit.* - correction;
    dict_limit.* = if (dict_limit.* < correction + window_start) window_start else dict_limit.* - correction;
    std.debug.assert(new_current >= max_dist and new_current - max_dist >= window_start);
    std.debug.assert(low_limit.* <= new_current and dict_limit.* <= new_current);
    n_corrections.* +%= 1;
    return correction;
}

/// `ZSTD_reduceTable` / `ZSTD_reduceTable_btlazy2`: indices drop by
/// `reducer`; those that would fall below `window_start` become 0 (empty).
/// `preserve_mark` keeps btlazy2's unsorted mark, which is below
/// `window_start` itself.
pub fn reduceTable(table: []u32, reducer: u32, preserve_mark: bool) void {
    const threshold = reducer + window_start;
    for (table) |*v| {
        if (preserve_mark and v.* == lazy.dubt_unsorted_mark) continue;
        v.* = if (v.* < threshold) 0 else v.* - reducer;
    }
}

const prime4: u32 = 2654435761;
const prime5: u64 = 889523592379;
const prime6: u64 = 227718039650203;
const prime7: u64 = 58295818150454627;
const prime8: u64 = 0xCF1BBCDCB7A56463;

/// Compress one block with the strategy in `ms.cp`. Stores sequences into
/// `ss`, updates `rep`, and returns the number of trailing literals.
pub fn compressBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32) usize {
    const mls = ms.cp.min_match;
    if (ms.hasExtDict()) switch (ms.cp.strategy) {
        .fast => return switch (mls) {
            5 => fastExtDictBlock(ms, ss, rep, istart, src_size, 5),
            6 => fastExtDictBlock(ms, ss, rep, istart, src_size, 6),
            7 => fastExtDictBlock(ms, ss, rep, istart, src_size, 7),
            else => fastExtDictBlock(ms, ss, rep, istart, src_size, 4),
        },
        .dfast => return switch (mls) {
            5 => dfastExtDictBlock(ms, ss, rep, istart, src_size, 5),
            6 => dfastExtDictBlock(ms, ss, rep, istart, src_size, 6),
            7 => dfastExtDictBlock(ms, ss, rep, istart, src_size, 7),
            else => dfastExtDictBlock(ms, ss, rep, istart, src_size, 4),
        },
        .greedy, .lazy, .lazy2, .btlazy2 => return lazy.compressBlock(ms, ss, rep, istart, src_size),
        // Only streams make an extDict, and they refuse the optimal
        // parsers for now (stream.zig).
        else => unreachable,
    };
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
        .btopt => opt.compressBlock(ms, ss, rep, istart, src_size, 0),
        .btultra => opt.compressBlock(ms, ss, rep, istart, src_size, 2),
        .btultra2 => opt.compressBlockUltra2(ms, ss, rep, istart, src_size),
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
        ss.store(ms.bytes(anchor, ip0), offcode, m_length);
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
                ss.store(ms.bytes(anchor, ip), 1, m_length);
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
            ss.store(ms.bytes(anchor, ip), offset + sequences.rep_num, m_length);
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

/// `ZSTD_index_overlap_check`: the four bytes at `rep_index` do not straddle
/// the extDict's end.
pub inline fn indexOverlapCheck(prefix_lowest_index: u32, rep_index: u32) bool {
    return (prefix_lowest_index -% 1) -% rep_index >= 3;
}

/// `ZSTD_compressBlock_fast_extDict_generic`: the window is two segments,
/// the extDict (indices `low_limit`..`dict_limit`) and the prefix.
fn fastExtDictBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime mls: u32) usize {
    const hash_table = ms.hash_table;
    const hlog = ms.cp.hash_log;
    const step_size: usize = ms.cp.target_length + @intFromBool(ms.cp.target_length == 0) + 1;
    const end_index: u32 = istart + src_size;
    const low_limit = ms.lowestMatchIndex(end_index);
    const dict_start_index = low_limit;
    const dict_limit = ms.dict_limit;
    const prefix_start_index: u32 = if (dict_limit < low_limit) low_limit else dict_limit;
    const prefix_start: usize = prefix_start_index;
    const dict_start: usize = dict_start_index;
    const dict_end: usize = prefix_start_index; // the extDict's end, as an index
    const iend: usize = end_index;
    const ilimit: usize = iend - 8;
    var offset_1: u32 = rep[0];
    var offset_2: u32 = rep[1];
    var offset_saved1: u32 = 0;
    var offset_saved2: u32 = 0;

    var anchor: usize = istart;
    var ip0: usize = istart;
    var ip1: usize = undefined;
    var ip2: usize = undefined;
    var ip3: usize = undefined;
    var current0: u32 = undefined;

    var hash0: usize = undefined;
    var hash1: usize = undefined;
    var idx: u32 = undefined;

    var offcode: u32 = undefined;
    var match0: usize = undefined;
    var m_length: usize = undefined;
    var match_end: usize = undefined;

    var step: usize = undefined;
    var next_step: usize = undefined;
    const step_incr: usize = 1 << (search_strength - 1);

    // switch to "regular" variant if extDict is invalidated due to maxDistance
    if (prefix_start_index == dict_start_index) return fastBlock(ms, ss, rep, istart, src_size, mls);
    ms.n_ext_dict_blocks += 1;

    {
        const curr: u32 = @intCast(ip0);
        const max_rep = curr - dict_start_index;
        if (offset_2 >= max_rep) {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if (offset_1 >= max_rep) {
            offset_saved1 = offset_1;
            offset_1 = 0;
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
        idx = hash_table[hash0];

        const found: enum { rep, offset } = search: while (true) {
            {
                // load repcode match for ip[2]
                const current2: u32 = @intCast(ip2);
                const rep_index = current2 -% offset_1;
                const in_dict = rep_index < prefix_start_index;
                const rval: u32 = if (prefix_start_index -% rep_index >= 4 and offset_1 > 0)
                    ms.read32Seg(rep_index, prefix_start)
                else
                    ms.read32(ip2) ^ 1; // guaranteed to not match
                // write back hash table entry
                current0 = @intCast(ip0);
                hash_table[hash0] = current0;
                // check repcode at ip[2]
                if (ms.read32(ip2) == rval) {
                    ip0 = ip2;
                    match0 = rep_index;
                    match_end = if (in_dict) dict_end else iend;
                    m_length = @intFromBool(ms.at(ip0 - 1) == ms.atSeg(match0 - 1, prefix_start));
                    ip0 -= m_length;
                    match0 -= m_length;
                    offcode = 1; // REPCODE1_TO_OFFBASE
                    m_length += 4;
                    break :search .rep;
                }
            }
            {
                // load match for ip[0]
                const mval: u32 = if (idx >= dict_start_index) ms.read32Seg(idx, prefix_start) else ms.read32(ip0) ^ 1;
                if (ms.read32(ip0) == mval) break :search .offset;
            }

            // lookup ip[1]
            idx = hash_table[hash1];
            hash0 = hash1;
            hash1 = ms.hash(ip2, hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;

            current0 = @intCast(ip0);
            hash_table[hash0] = current0;
            {
                const mval: u32 = if (idx >= dict_start_index) ms.read32Seg(idx, prefix_start) else ms.read32(ip0) ^ 1;
                if (ms.read32(ip0) == mval) break :search .offset;
            }

            // lookup ip[1]
            idx = hash_table[hash1];
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
            const offset = current0 - idx;
            const low_match: usize = if (idx < prefix_start_index) dict_start else prefix_start;
            match_end = if (idx < prefix_start_index) dict_end else iend;
            match0 = idx;
            offset_2 = offset_1;
            offset_1 = offset;
            offcode = offset + sequences.rep_num;
            m_length = 4;
            // Count the backwards match length.
            while (ip0 > anchor and match0 > low_match and ms.at(ip0 - 1) == ms.atSeg(match0 - 1, prefix_start)) {
                ip0 -= 1;
                match0 -= 1;
                m_length += 1;
            }
        }

        // _match: count the forward length
        m_length += ms.count2Segments(ip0 + m_length, match0 + m_length, iend, match_end, prefix_start);
        ss.store(ms.bytes(anchor, ip0), offcode, m_length);
        ip0 += m_length;
        anchor = ip0;

        // write next hash table entry
        if (ip1 < ip0) hash_table[hash1] = @intCast(ip1);

        // Fill table and check for immediate repcode.
        if (ip0 <= ilimit) {
            hash_table[ms.hash(current0 + 2, hlog, mls)] = current0 + 2;
            hash_table[ms.hash(ip0 - 2, hlog, mls)] = @intCast(ip0 - 2);
            while (ip0 <= ilimit) {
                const rep_index2: u32 = @as(u32, @intCast(ip0)) -% offset_2;
                if (indexOverlapCheck(prefix_start_index, rep_index2) and offset_2 > 0 and
                    ms.read32Seg(rep_index2, prefix_start) == ms.read32(ip0))
                {
                    const rep_end2: usize = if (rep_index2 < prefix_start_index) dict_end else iend;
                    const rep_length2 = ms.count2Segments(ip0 + 4, @as(usize, rep_index2) + 4, iend, rep_end2, prefix_start) + 4;
                    std.mem.swap(u32, &offset_1, &offset_2);
                    ss.store(&.{}, 1, rep_length2);
                    hash_table[ms.hash(ip0, hlog, mls)] = @intCast(ip0);
                    ip0 += rep_length2;
                    anchor = ip0;
                    continue;
                }
                break;
            }
        }
    }

    // _cleanup
    offset_saved2 = if (offset_saved1 != 0 and offset_1 != 0) offset_saved1 else offset_saved2;
    rep[0] = if (offset_1 != 0) offset_1 else offset_saved1;
    rep[1] = if (offset_2 != 0) offset_2 else offset_saved2;
    return iend - anchor;
}

/// `ZSTD_compressBlock_doubleFast_extDict_generic`.
fn dfastExtDictBlock(ms: *MatchState, ss: *SeqStore, rep: *[3]u32, istart: u32, src_size: u32, comptime mls: u32) usize {
    const hash_long = ms.hash_table;
    const h_bits_l = ms.cp.hash_log;
    const hash_small = ms.chain_table;
    const h_bits_s = ms.cp.chain_log;
    var ip: usize = istart;
    var anchor: usize = istart;
    const iend: usize = @as(usize, istart) + src_size;
    const ilimit: usize = iend - 8;
    const end_index: u32 = istart + src_size;
    const low_limit = ms.lowestMatchIndex(end_index);
    const dict_start_index = low_limit;
    const dict_limit = ms.dict_limit;
    const prefix_start_index: u32 = if (dict_limit > low_limit) dict_limit else low_limit;
    const prefix_start: usize = prefix_start_index;
    const dict_start: usize = dict_start_index;
    const dict_end: usize = prefix_start_index;
    var offset_1: u32 = rep[0];
    var offset_2: u32 = rep[1];

    // if extDict is invalidated due to maxDistance, switch to "regular" variant
    if (prefix_start_index == dict_start_index) return dfastBlock(ms, ss, rep, istart, src_size, mls);
    ms.n_ext_dict_blocks += 1;

    // Search Loop
    while (ip < ilimit) { // < instead of <=, because (ip+1)
        const h_small = ms.hash(ip, h_bits_s, mls);
        const match_index = hash_small[h_small];
        const h_long = ms.hash(ip, h_bits_l, 8);
        const match_long_index = hash_long[h_long];

        const curr: u32 = @intCast(ip);
        const rep_index = curr +% 1 -% offset_1; // offset_1 expected <= curr +1
        var m_length: usize = undefined;
        hash_small[h_small] = curr;
        hash_long[h_long] = curr; // update hash table

        if (indexOverlapCheck(prefix_start_index, rep_index) and offset_1 <= curr + 1 - dict_start_index and
            ms.read32Seg(rep_index, prefix_start) == ms.read32(ip + 1))
        {
            const rep_match_end: usize = if (rep_index < prefix_start_index) dict_end else iend;
            m_length = ms.count2Segments(ip + 1 + 4, @as(usize, rep_index) + 4, iend, rep_match_end, prefix_start) + 4;
            ip += 1;
            ss.store(ms.bytes(anchor, ip), 1, m_length);
        } else {
            if (match_long_index > dict_start_index and ms.read64Seg(match_long_index, prefix_start) == ms.read64(ip)) {
                const match_end: usize = if (match_long_index < prefix_start_index) dict_end else iend;
                const low_match: usize = if (match_long_index < prefix_start_index) dict_start else prefix_start;
                var match_long: usize = match_long_index;
                m_length = ms.count2Segments(ip + 8, match_long + 8, iend, match_end, prefix_start) + 8;
                const offset = curr - match_long_index;
                while (ip > anchor and match_long > low_match and ms.at(ip - 1) == ms.atSeg(match_long - 1, prefix_start)) { // catch up
                    ip -= 1;
                    match_long -= 1;
                    m_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
                ss.store(ms.bytes(anchor, ip), offset + sequences.rep_num, m_length);
            } else if (match_index > dict_start_index and ms.read32Seg(match_index, prefix_start) == ms.read32(ip)) {
                const h3 = ms.hash(ip + 1, h_bits_l, 8);
                const match_index3 = hash_long[h3];
                var offset: u32 = undefined;
                hash_long[h3] = curr + 1;
                if (match_index3 > dict_start_index and ms.read64Seg(match_index3, prefix_start) == ms.read64(ip + 1)) {
                    const match_end: usize = if (match_index3 < prefix_start_index) dict_end else iend;
                    const low_match: usize = if (match_index3 < prefix_start_index) dict_start else prefix_start;
                    var match3: usize = match_index3;
                    m_length = ms.count2Segments(ip + 9, match3 + 8, iend, match_end, prefix_start) + 8;
                    ip += 1;
                    offset = curr + 1 - match_index3;
                    while (ip > anchor and match3 > low_match and ms.at(ip - 1) == ms.atSeg(match3 - 1, prefix_start)) { // catch up
                        ip -= 1;
                        match3 -= 1;
                        m_length += 1;
                    }
                } else {
                    const match_end: usize = if (match_index < prefix_start_index) dict_end else iend;
                    const low_match: usize = if (match_index < prefix_start_index) dict_start else prefix_start;
                    var match: usize = match_index;
                    m_length = ms.count2Segments(ip + 4, match + 4, iend, match_end, prefix_start) + 4;
                    offset = curr - match_index;
                    while (ip > anchor and match > low_match and ms.at(ip - 1) == ms.atSeg(match - 1, prefix_start)) { // catch up
                        ip -= 1;
                        match -= 1;
                        m_length += 1;
                    }
                }
                offset_2 = offset_1;
                offset_1 = offset;
                ss.store(ms.bytes(anchor, ip), offset + sequences.rep_num, m_length);
            } else {
                ip += ((ip - anchor) >> search_strength) + 1;
                continue;
            }
        }

        // move to next sequence start
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
            while (ip <= ilimit) {
                const current2: u32 = @intCast(ip);
                const rep_index2 = current2 -% offset_2;
                if (indexOverlapCheck(prefix_start_index, rep_index2) and offset_2 <= current2 - dict_start_index and
                    ms.read32Seg(rep_index2, prefix_start) == ms.read32(ip))
                {
                    const rep_end2: usize = if (rep_index2 < prefix_start_index) dict_end else iend;
                    const rep_length2 = ms.count2Segments(ip + 4, @as(usize, rep_index2) + 4, iend, rep_end2, prefix_start) + 4;
                    std.mem.swap(u32, &offset_1, &offset_2);
                    ss.store(&.{}, 1, rep_length2);
                    hash_small[ms.hash(ip, h_bits_s, mls)] = current2;
                    hash_long[ms.hash(ip, h_bits_l, 8)] = current2;
                    ip += rep_length2;
                    anchor = ip;
                    continue;
                }
                break;
            }
        }
    }

    // save reps for next block
    rep[0] = offset_1;
    rep[1] = offset_2;
    return iend - anchor;
}

test "reduceTable squashes indices below the threshold and keeps btlazy2's mark" {
    var t = [_]u32{ 0, 1, 2, 1000, 1001, 1002, 1003, 5000 };
    var u = t;
    reduceTable(&t, 1000, false);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 0, 0, 0, 2, 3, 4000 }, &t);
    reduceTable(&u, 1000, true);
    try std.testing.expectEqualSlices(u32, &.{ 0, lazy.dubt_unsorted_mark, 0, 0, 0, 2, 3, 4000 }, &u);
}

test "past current_max the correction keeps the low cycle bits and the whole window" {
    // 3500 MiB is a multiple of 2^16, so the index's cycle position is 5.
    try std.testing.expect(!needOverflowCorrection(false, 0, 16, 1 << 19, current_max - 100, current_max));
    try std.testing.expect(needOverflowCorrection(false, 0, 16, 1 << 19, current_max - 100, current_max + 1));
    var low: u32 = current_max + 5 - (1 << 19);
    var dict: u32 = low;
    var n: u32 = 0;
    const corr = correctOverflow(&low, &dict, &n, false, 16, 1 << 19, current_max + 5);
    try std.testing.expectEqual(current_max + 5 - (5 + (1 << 19)), corr);
    try std.testing.expectEqual(@as(u32, 5), low);
    try std.testing.expectEqual(@as(u32, 5), dict);
    try std.testing.expectEqual(@as(u32, 1), n);
    // At cycle position 1 (below window_start) one more cycle is kept.
    low = 2;
    dict = 2;
    const corr1 = correctOverflow(&low, &dict, &n, false, 16, 1 << 19, current_max + 1);
    try std.testing.expectEqual(current_max + 1 - (1 + (1 << 16) + (1 << 19)), corr1);
    try std.testing.expectEqual(@as(u32, window_start), low);
    try std.testing.expectEqual(@as(u32, 2), n);
}

test "frequent correction backs off with each correction made" {
    // min index = 2^12 + 2^14 + 2 = 20482
    try std.testing.expect(!needOverflowCorrection(true, 0, 12, 1 << 14, 20482, 20483));
    try std.testing.expect(needOverflowCorrection(true, 0, 12, 1 << 14, 20483, 20484));
    try std.testing.expect(!needOverflowCorrection(true, 2, 12, 1 << 14, 3 * 20482, 3 * 20482 + 1));
    try std.testing.expect(needOverflowCorrection(true, 2, 12, 1 << 14, 3 * 20482 + 1, 3 * 20482 + 2));
}
