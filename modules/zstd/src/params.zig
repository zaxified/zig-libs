// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Compression parameters per level (port of libzstd lib/compress/clevels.h and
//! the parameter selection in lib/compress/zstd_compress.c, v1.5.7).
//!
//! The tables are libzstd's in full; `max_level` says how far this module
//! implements them. Selection is libzstd's exactly — table by source size,
//! then `ZSTD_adjustCParams_internal` shrinking window/hash/chain to the input
//! — because the resulting window log is written into the frame header and
//! the table sizes decide which matches are found.

const std = @import("std");

/// `ZSTD_strategy`, numbered as in libzstd: several decisions compare it
/// numerically (`strategy >= ZSTD_lazy`, `9 - strategy`, table indices).
pub const Strategy = enum(u32) { fast = 1, dfast = 2, greedy = 3, lazy = 4, lazy2 = 5, btlazy2 = 6, btopt = 7, btultra = 8, btultra2 = 9 };

pub const CParams = struct {
    window_log: u32,
    chain_log: u32,
    hash_log: u32,
    search_log: u32,
    min_match: u32,
    target_length: u32,
    strategy: Strategy,
};

/// Highest level: every row of libzstd's tables is implemented, including
/// level 22's 128 MB window on inputs over 64 MB, where libzstd switches on
/// long-distance matching (`ZSTD_resolveEnableLdm`, see `ldm.zig`).
pub const max_level = 22;
/// `ZSTD_MAX_CLEVEL`: rows in each table.
const table_levels = 22;
/// `ZSTD_minCLevel()`: -ZSTD_TARGETLENGTH_MAX.
pub const min_level = -(1 << 17);
/// `ZSTD_CLEVEL_DEFAULT`.
pub const default_level = 3;

const window_log_absolute_min = 10;
pub const hash_log_min = 6;
/// `ZSTD_WINDOWLOG_MAX` (64-bit).
pub const window_log_max = 31;
/// `ZSTD_ROW_HASH_TAG_BITS`.
pub const row_hash_tag_bits = 8;

fn row(w: u32, c: u32, h: u32, s: u32, l: u32, tl: u32, st: Strategy) CParams {
    return .{ .window_log = w, .chain_log = c, .hash_log = h, .search_log = s, .min_match = l, .target_length = tl, .strategy = st };
}

/// `ZSTD_defaultCParameters[tableID]`: row 0 is the base for negative levels.
const table = [4][table_levels + 1]CParams{
    .{ // srcSize > 256 KB
        row(19, 12, 13, 1, 6, 1, .fast), // base for negative levels
        row(19, 13, 14, 1, 7, 0, .fast), // level 1
        row(20, 15, 16, 1, 6, 0, .fast), // level 2
        row(21, 16, 17, 1, 5, 0, .dfast), // level 3
        row(21, 18, 18, 1, 5, 0, .dfast), // level 4
        row(21, 18, 19, 3, 5, 2, .greedy), // level 5
        row(21, 18, 19, 3, 5, 4, .lazy), // level 6
        row(21, 19, 20, 4, 5, 8, .lazy), // level 7
        row(21, 19, 20, 4, 5, 16, .lazy2), // level 8
        row(22, 20, 21, 4, 5, 16, .lazy2), // level 9
        row(22, 21, 22, 5, 5, 16, .lazy2), // level 10
        row(22, 21, 22, 6, 5, 16, .lazy2), // level 11
        row(22, 22, 23, 6, 5, 32, .lazy2), // level 12
        row(22, 22, 22, 4, 5, 32, .btlazy2), // level 13
        row(22, 22, 23, 5, 5, 32, .btlazy2), // level 14
        row(22, 23, 23, 6, 5, 32, .btlazy2), // level 15
        row(22, 22, 22, 5, 5, 48, .btopt), // level 16
        row(23, 23, 22, 5, 4, 64, .btopt), // level 17
        row(23, 23, 22, 6, 3, 64, .btultra), // level 18
        row(23, 24, 22, 7, 3, 256, .btultra2), // level 19
        row(25, 25, 23, 7, 3, 256, .btultra2), // level 20
        row(26, 26, 24, 7, 3, 512, .btultra2), // level 21
        row(27, 27, 25, 9, 3, 999, .btultra2), // level 22
    },
    .{ // srcSize <= 256 KB
        row(18, 12, 13, 1, 5, 1, .fast), // base for negative levels
        row(18, 13, 14, 1, 6, 0, .fast), // level 1
        row(18, 14, 14, 1, 5, 0, .dfast), // level 2
        row(18, 16, 16, 1, 4, 0, .dfast), // level 3
        row(18, 16, 17, 3, 5, 2, .greedy), // level 4
        row(18, 17, 18, 5, 5, 2, .greedy), // level 5
        row(18, 18, 19, 3, 5, 4, .lazy), // level 6
        row(18, 18, 19, 4, 4, 4, .lazy), // level 7
        row(18, 18, 19, 4, 4, 8, .lazy2), // level 8
        row(18, 18, 19, 5, 4, 8, .lazy2), // level 9
        row(18, 18, 19, 6, 4, 8, .lazy2), // level 10
        row(18, 18, 19, 5, 4, 12, .btlazy2), // level 11
        row(18, 19, 19, 7, 4, 12, .btlazy2), // level 12
        row(18, 18, 19, 4, 4, 16, .btopt), // level 13
        row(18, 18, 19, 4, 3, 32, .btopt), // level 14
        row(18, 18, 19, 6, 3, 128, .btopt), // level 15
        row(18, 19, 19, 6, 3, 128, .btultra), // level 16
        row(18, 19, 19, 8, 3, 256, .btultra), // level 17
        row(18, 19, 19, 6, 3, 128, .btultra2), // level 18
        row(18, 19, 19, 8, 3, 256, .btultra2), // level 19
        row(18, 19, 19, 10, 3, 512, .btultra2), // level 20
        row(18, 19, 19, 12, 3, 512, .btultra2), // level 21
        row(18, 19, 19, 13, 3, 999, .btultra2), // level 22
    },
    .{ // srcSize <= 128 KB
        row(17, 12, 12, 1, 5, 1, .fast), // base for negative levels
        row(17, 12, 13, 1, 6, 0, .fast), // level 1
        row(17, 13, 15, 1, 5, 0, .fast), // level 2
        row(17, 15, 16, 2, 5, 0, .dfast), // level 3
        row(17, 17, 17, 2, 4, 0, .dfast), // level 4
        row(17, 16, 17, 3, 4, 2, .greedy), // level 5
        row(17, 16, 17, 3, 4, 4, .lazy), // level 6
        row(17, 16, 17, 3, 4, 8, .lazy2), // level 7
        row(17, 16, 17, 4, 4, 8, .lazy2), // level 8
        row(17, 16, 17, 5, 4, 8, .lazy2), // level 9
        row(17, 16, 17, 6, 4, 8, .lazy2), // level 10
        row(17, 17, 17, 5, 4, 8, .btlazy2), // level 11
        row(17, 18, 17, 7, 4, 12, .btlazy2), // level 12
        row(17, 18, 17, 3, 4, 12, .btopt), // level 13
        row(17, 18, 17, 4, 3, 32, .btopt), // level 14
        row(17, 18, 17, 6, 3, 256, .btopt), // level 15
        row(17, 18, 17, 6, 3, 128, .btultra), // level 16
        row(17, 18, 17, 8, 3, 256, .btultra), // level 17
        row(17, 18, 17, 10, 3, 512, .btultra), // level 18
        row(17, 18, 17, 5, 3, 256, .btultra2), // level 19
        row(17, 18, 17, 7, 3, 512, .btultra2), // level 20
        row(17, 18, 17, 9, 3, 512, .btultra2), // level 21
        row(17, 18, 17, 11, 3, 999, .btultra2), // level 22
    },
    .{ // srcSize <= 16 KB
        row(14, 12, 13, 1, 5, 1, .fast), // base for negative levels
        row(14, 14, 15, 1, 5, 0, .fast), // level 1
        row(14, 14, 15, 1, 4, 0, .fast), // level 2
        row(14, 14, 15, 2, 4, 0, .dfast), // level 3
        row(14, 14, 14, 4, 4, 2, .greedy), // level 4
        row(14, 14, 14, 3, 4, 4, .lazy), // level 5
        row(14, 14, 14, 4, 4, 8, .lazy2), // level 6
        row(14, 14, 14, 6, 4, 8, .lazy2), // level 7
        row(14, 14, 14, 8, 4, 8, .lazy2), // level 8
        row(14, 15, 14, 5, 4, 8, .btlazy2), // level 9
        row(14, 15, 14, 9, 4, 8, .btlazy2), // level 10
        row(14, 15, 14, 3, 4, 12, .btopt), // level 11
        row(14, 15, 14, 4, 3, 24, .btopt), // level 12
        row(14, 15, 14, 5, 3, 32, .btultra), // level 13
        row(14, 15, 15, 6, 3, 64, .btultra), // level 14
        row(14, 15, 15, 7, 3, 256, .btultra), // level 15
        row(14, 15, 15, 5, 3, 48, .btultra2), // level 16
        row(14, 15, 15, 6, 3, 128, .btultra2), // level 17
        row(14, 15, 15, 7, 3, 256, .btultra2), // level 18
        row(14, 15, 15, 8, 3, 256, .btultra2), // level 19
        row(14, 15, 15, 8, 3, 512, .btultra2), // level 20
        row(14, 15, 15, 9, 3, 512, .btultra2), // level 21
        row(14, 15, 15, 10, 3, 999, .btultra2), // level 22
    },
};

fn highbit32(v: u32) u32 {
    return 31 - @as(u32, @clz(v));
}

/// `ZSTD_rowMatchFinderSupported`.
pub fn rowMatchFinderSupported(strategy: Strategy) bool {
    return @intFromEnum(strategy) >= @intFromEnum(Strategy.greedy) and @intFromEnum(strategy) <= @intFromEnum(Strategy.lazy2);
}

/// `ZSTD_resolveRowMatchFinderMode(ZSTD_ps_auto, cParams)`: whether the
/// row-based match finder replaces the hash chain.
pub fn useRowMatchFinder(cp: CParams) bool {
    return rowMatchFinderSupported(cp.strategy) and cp.window_log > 14;
}

/// `BOUNDED(4, searchLog, 6)`: log2 of the entries per row.
pub fn rowLog(cp: CParams) u32 {
    return std.math.clamp(cp.search_log, 4, 6);
}

/// `ZSTD_cycleLog`: the binary-tree strategies keep two entries per position.
pub fn cycleLog(cp: CParams) u32 {
    return cp.chain_log - @intFromBool(@intFromEnum(cp.strategy) >= @intFromEnum(Strategy.btlazy2));
}

/// `ZSTD_CONTENTSIZE_UNKNOWN`: a stream whose length is not pledged. It
/// selects the table for inputs over 256 KB and shrinks nothing.
pub const unknown_size: u64 = std.math.maxInt(u64);

/// `ZSTD_CParamMode_e`: how the dictionary size takes part in choosing the
/// parameters.
pub const CParamMode = enum {
    /// `ZSTD_cpm_unknown` (`ZSTD_getCParams`, `ZSTD_adjustCParams`).
    unknown,
    /// `ZSTD_cpm_noAttachDict`: the dictionary goes into the window (loaded,
    /// copied, or a prefix), so the window and tables must cover both.
    no_attach_dict,
    /// `ZSTD_cpm_attachDict`: the dictionary keeps its own tables; the
    /// parameters are for the input alone.
    attach_dict,
    /// `ZSTD_cpm_createCDict`: a CDict's own parameters; an unknown input
    /// size counts as small (513 bytes).
    create_cdict,
};

/// `ZSTD_dictAndWindowLog`: a window log covering the dictionary and the
/// window, for sizing the hash and chain tables (`src_size` is known).
fn dictAndWindowLog(window_log: u32, src_size: u64, dict_size: u64) u32 {
    if (dict_size == 0) return window_log; // No dictionary ==> No change
    const window_size: u64 = @as(u64, 1) << @intCast(window_log);
    const dict_and_window_size = dict_size +% window_size;
    // the window already fits both the source and the dictionary
    if (window_size >= dict_size +% src_size) return window_log;
    if (dict_and_window_size >= @as(u64, 1) << window_log_max) return window_log_max;
    return highbit32(@intCast(dict_and_window_size - 1)) + 1;
}

/// `ZSTD_CDictIndicesAreTagged`: a CDict for `fast` and `dfast` keeps an
/// 8-bit tag in the low bits of each table entry ("short cache").
pub fn cdictIndicesAreTagged(cp: CParams) bool {
    return cp.strategy == .fast or cp.strategy == .dfast;
}

/// `ZSTD_SHORT_CACHE_TAG_BITS`.
pub const short_cache_tag_bits = 8;

/// `ZSTD_adjustCParams_internal`: shrink `cp_in` to an input of `src_size`
/// bytes (`unknown_size` when not known) and a dictionary of `dict_size`
/// bytes. `row_mode` is the row match finder switch: only `.disable` lifts
/// its cap on the hash log, since libzstd assumes it may be used here.
pub fn adjustInternal(cp_in: CParams, src_size_in: u64, dict_size_in: u64, mode: CParamMode, row_mode: Switch) CParams {
    var cp = cp_in;
    var src_size = src_size_in;
    var dict_size = dict_size_in;
    const min_src_size: u64 = 513; // (1<<9) + 1
    const max_window_resize: u64 = @as(u64, 1) << (window_log_max - 1);
    switch (mode) {
        // If we don't know the source size, don't make any assumptions
        // about it: smaller parameters are already chosen for a dictionary.
        .unknown, .no_attach_dict => {},
        // Assume a small source size when creating a dictionary with an
        // unknown source size.
        .create_cdict => if (dict_size != 0 and src_size == unknown_size) {
            src_size = min_src_size;
        },
        // The dictionary has its own parameters, already chosen: these are
        // for the source only.
        .attach_dict => dict_size = 0,
    }
    // resize windowLog if input is small enough, to use less memory
    if (src_size <= max_window_resize and dict_size <= max_window_resize) {
        const t_size: u32 = @truncate(src_size + dict_size);
        const hash_size_min: u32 = 1 << hash_log_min;
        const src_log: u32 = if (t_size < hash_size_min) hash_log_min else highbit32(t_size - 1) + 1;
        if (cp.window_log > src_log) cp.window_log = src_log;
    }
    if (src_size != unknown_size) {
        const dict_and_window_log = dictAndWindowLog(cp.window_log, src_size, dict_size);
        const cycle_log = cycleLog(cp);
        if (cp.hash_log > dict_and_window_log + 1) cp.hash_log = dict_and_window_log + 1;
        if (cycle_log > dict_and_window_log) cp.chain_log -= (cycle_log - dict_and_window_log);
    }
    if (cp.window_log < window_log_absolute_min) cp.window_log = window_log_absolute_min;
    // A CDict's tagged tables keep 8 bits of each entry for the tag.
    if (mode == .create_cdict and cdictIndicesAreTagged(cp)) {
        const max_short_cache_hash_log = 32 - short_cache_tag_bits;
        if (cp.hash_log > max_short_cache_hash_log) cp.hash_log = max_short_cache_hash_log;
        if (cp.chain_log > max_short_cache_hash_log) cp.chain_log = max_short_cache_hash_log;
    }
    // The row match finder hashes hashLog - rowLog + 8 bits into 32. libzstd
    // assumes it is in use here, before the window size decides, unless it
    // is switched off.
    if (row_mode != .disable and rowMatchFinderSupported(cp.strategy)) {
        const max_hash_log = 32 - row_hash_tag_bits + rowLog(cp);
        if (cp.hash_log > max_hash_log) cp.hash_log = max_hash_log;
    }
    return cp;
}

fn adjust(cp_in: CParams, src_size: u64) CParams {
    return adjustInternal(cp_in, src_size, 0, .no_attach_dict, .auto);
}

/// The largest input of each of the parameter tables' size classes but
/// the last (`get`): within a class the parameters, and so the memory,
/// grow with the size.
pub const size_class_bounds = [_]u64{ 16 * 1024, 128 * 1024, 256 * 1024 };

/// `ZSTD_getCParamRowSize`: the size that picks the table.
fn rowSize(src_size_hint: u64, dict_size_in: u64, mode: CParamMode) u64 {
    const dict_size = if (mode == .attach_dict) 0 else dict_size_in;
    const unknown = src_size_hint == unknown_size;
    const added_size: u64 = if (unknown and dict_size > 0) 500 else 0;
    return if (unknown and dict_size == 0) unknown_size else src_size_hint +% dict_size +% added_size;
}

/// `ZSTD_getCParams_internal(level, srcSizeHint, dictSize, mode)`. `level`
/// must be at most `max_level`; 0 means the default level.
pub fn getInternal(level: i32, src_size_hint: u64, dict_size: u64, mode: CParamMode) CParams {
    std.debug.assert(level <= max_level);
    const r_size = rowSize(src_size_hint, dict_size, mode);
    const table_id: usize = @as(usize, @intFromBool(r_size <= 256 * 1024)) +
        @intFromBool(r_size <= 128 * 1024) +
        @intFromBool(r_size <= 16 * 1024);
    const r: usize = if (level == 0) default_level else if (level < 0) 0 else @intCast(level);
    var cp = table[table_id][r];
    if (level < 0) cp.target_length = @intCast(-@max(min_level, level)); // acceleration factor
    return adjustInternal(cp, src_size_hint, dict_size, mode, .auto);
}

/// `ZSTD_getCParams_internal(level, srcSize, 0, ZSTD_cpm_noAttachDict)` as used
/// by one-shot compression. `level` must be in `min_level..max_level`; 0 means
/// the default level.
pub fn get(level: i32, src_size: u64) CParams {
    return getInternal(level, src_size, 0, .no_attach_dict);
}

/// `ZSTD_getCParamsFromCCtxParams`: the level's parameters (already
/// adjusted for its own strategy); with long-distance matching switched on
/// (`.enable`, not `.auto`) the window log reset to 27,
/// `ZSTD_LDM_DEFAULT_WINDOW_LOG`; the explicit parameters of `adv` put over
/// them (`ZSTD_overrideCParams`); and the adjustment run again, this time
/// knowing whether the row match finder is ruled out. `adv` must have
/// passed `check`.
pub fn getOverridden(level: i32, src_size: u64, adv: Advanced) CParams {
    return getFromCCtxParams(level, src_size, 0, .no_attach_dict, adv);
}

/// `ZSTD_getCParamsFromCCtxParams` with a dictionary of `dict_size` bytes
/// used in `mode` (see `getOverridden`). The caller has already put a size
/// hint in place of an unknown `src_size`.
pub fn getFromCCtxParams(level: i32, src_size: u64, dict_size: u64, mode: CParamMode, adv: Advanced) CParams {
    var cp = getInternal(level, src_size, dict_size, mode);
    if (adv.long_distance_matching == .enable) cp.window_log = ldm_default_window_log;
    if (adv.window_log) |v| cp.window_log = v;
    if (adv.hash_log) |v| cp.hash_log = v;
    if (adv.chain_log) |v| cp.chain_log = v;
    if (adv.search_log) |v| cp.search_log = v;
    if (adv.min_match) |v| cp.min_match = v;
    // 0 is in bounds but, as in libzstd, means "not set"
    if (adv.target_length) |v| if (v != 0) {
        cp.target_length = v;
    };
    if (adv.strategy) |v| cp.strategy = v;
    return adjustInternal(cp, src_size, dict_size, mode, adv.row_match_finder);
}

/// `ZSTD_ParamSwitch_e`.
pub const Switch = enum {
    /// libzstd's own choice from the parameters.
    auto,
    enable,
    disable,
};

/// `ZSTD_format_e`.
pub const Format = enum {
    /// RFC 8878 frames, starting with the magic number.
    zstd1,
    /// The same frames without the 4-byte magic number
    /// (`ZSTD_f_zstd1_magicless`). A decoder must be told to expect them;
    /// they cannot be mixed with skippable frames.
    magicless,
};

/// libzstd's advanced compression parameters (`ZSTD_CCtx_setParameter`).
/// Null or `.auto` leaves each to the level. The bounds are libzstd's
/// (`ZSTD_cParam_getBounds`, 64-bit): a value outside them is
/// `error.ParameterOutOfBound`, where libzstd refuses to set it.
pub const Advanced = struct {
    /// `ZSTD_c_windowLog`, 10..31: the largest back-reference distance, and
    /// the window a decoder must hold. The input's size still shrinks it.
    window_log: ?u32 = null,
    /// `ZSTD_c_hashLog`, 6..30.
    hash_log: ?u32 = null,
    /// `ZSTD_c_chainLog`, 6..30.
    chain_log: ?u32 = null,
    /// `ZSTD_c_searchLog`, 1..30.
    search_log: ?u32 = null,
    /// `ZSTD_c_minMatch`, 3..7.
    min_match: ?u32 = null,
    /// `ZSTD_c_targetLength`, 0..131072; 0 keeps the level's, as in libzstd.
    target_length: ?u32 = null,
    /// `ZSTD_c_strategy`.
    strategy: ?Strategy = null,
    /// `ZSTD_c_contentSizeFlag`: record the content size in the frame header
    /// when it is known.
    content_size: bool = true,
    /// `ZSTD_c_format`.
    format: Format = .zstd1,
    /// `ZSTD_c_literalCompressionMode`: `.auto` compresses literals except
    /// at the negative levels (strategy `fast` with an acceleration).
    literal_compression: Switch = .auto,
    /// `ZSTD_c_useRowMatchFinder`, for `greedy`, `lazy` and `lazy2`: `.auto`
    /// uses it above a 16 KB window.
    row_match_finder: Switch = .auto,
    /// `ZSTD_c_splitAfterSequences`, the post-splitter: `.auto` runs it for
    /// `btopt` and up with a window of 128 KB or more.
    split_after_sequences: Switch = .auto,
    /// `ZSTD_c_blockSplitterLevel`, the pre-splitter, 0..6: 0 by strategy,
    /// 1 never splits, 2..6 in increasing cost.
    block_splitter_level: u32 = 0,
    /// `ZSTD_c_maxBlockSize`, 1024..131072: the largest block.
    max_block_size: ?u32 = null,
    /// `ZSTD_c_enableLongDistanceMatching` (`--long`): a second match finder
    /// over the whole window that finds long repeats far back. `.auto` runs
    /// it for `btopt` and up with a window log of 27 or more (level 22 on
    /// inputs over 64 MB); `.enable` also raises the window log to 27 unless
    /// `window_log` says otherwise (the input's size still shrinks it).
    long_distance_matching: Switch = .auto,
    /// `ZSTD_c_ldmHashLog`, 6..30: the LDM table's size; 0 or null derives
    /// it from the window and the hash rate.
    ldm_hash_log: ?u32 = null,
    /// `ZSTD_c_ldmMinMatch`, 4..4096: the shortest long-distance match; 0 or
    /// null is 64, or 32 for `btultra` and up.
    ldm_min_match: ?u32 = null,
    /// `ZSTD_c_ldmBucketSizeLog`, 1..8: entries per LDM hash bucket; 0 or
    /// null derives it from the strategy.
    ldm_bucket_size_log: ?u32 = null,
    /// `ZSTD_c_ldmHashRateLog`, 0..25: one position in 2^rate enters the LDM
    /// table; 0 or null derives it from the hash log, else the strategy.
    ldm_hash_rate_log: ?u32 = null,
    /// `ZSTD_c_targetCBlockSize`, up to 131072: cut each block into
    /// compressed blocks of about this many bytes (superblocks), so a
    /// streaming decoder can start sooner; values below 1340 count as 1340.
    /// 0 or null: off.
    target_c_block_size: ?u32 = null,
    /// `ZSTD_c_dictIDFlag`: write the dictionary's ID into the frame header
    /// (a full dictionary's; a raw one has none).
    dict_id_flag: bool = true,
    /// `ZSTD_c_forceAttachDict`: how a `CDict` gets into the context.
    force_attach_dict: DictAttachPref = .default,
    /// `ZSTD_c_deterministicRefPrefix`: always treat a prefix (or a
    /// dictionary loaded into the context) as a separate segment of the
    /// window, even when the input follows it in memory, so the output does
    /// not depend on where the buffers lie.
    deterministic_ref_prefix: bool = false,
    /// `ZSTD_c_forceMaxWindow`: a dictionary counts only as far as the
    /// window reaches (a byte of it no longer keeps all of it valid), and a
    /// `CDict` is never attached.
    force_max_window: bool = false,

    pub const CheckError = error{
        /// A parameter outside libzstd's bounds (`parameter_outOfBound`).
        ParameterOutOfBound,
    };

    /// `ZSTD_cParam_getBounds`, as `ZSTD_CCtx_setParameter` enforces it.
    pub fn check(adv: Advanced) CheckError!void {
        const B = struct {
            fn in(v: ?u32, lo: u32, hi: u32) bool {
                return if (v) |x| x >= lo and x <= hi else true;
            }
        };
        if (!B.in(adv.window_log, window_log_min, window_log_max) or
            !B.in(adv.hash_log, hash_log_min, hash_log_max) or
            !B.in(adv.chain_log, chain_log_min, chain_log_max) or
            !B.in(adv.search_log, search_log_min, search_log_max) or
            !B.in(adv.min_match, min_match_min, min_match_max) or
            !B.in(adv.target_length, 0, target_length_max) or
            !B.in(adv.block_splitter_level, 0, block_splitter_level_max) or
            !B.in(adv.max_block_size, block_size_max_min, block_size_max_abs) or
            // for the LDM parameters, as for libzstd, 0 is "not set"
            !B.in(nonZero(adv.ldm_hash_log), hash_log_min, hash_log_max) or
            !B.in(nonZero(adv.ldm_min_match), ldm_min_match_min, ldm_min_match_max) or
            !B.in(nonZero(adv.ldm_bucket_size_log), ldm_bucket_size_log_min, ldm_bucket_size_log_max) or
            !B.in(nonZero(adv.ldm_hash_rate_log), 0, ldm_hash_rate_log_max) or
            !B.in(adv.target_c_block_size, 0, block_size_max_abs))
            return error.ParameterOutOfBound;
    }
};

/// `ZSTD_dictAttachPref_e`: libzstd picks between attaching a `CDict`'s
/// tables (for small inputs) and copying them into the context by the
/// input size and strategy; this overrides the pick.
pub const DictAttachPref = enum {
    /// `ZSTD_dictDefaultAttach`: libzstd's choice.
    default,
    /// `ZSTD_dictForceAttach`: always attach.
    attach,
    /// `ZSTD_dictForceCopy`: always copy the tables.
    copy,
    /// `ZSTD_dictForceLoad`: always load the dictionary's content into the
    /// context anew, as if it were not digested.
    load,
};

/// Null for 0, which libzstd's LDM parameters take as "not set".
pub fn nonZero(v: ?u32) ?u32 {
    return if (v) |x| if (x == 0) null else x else null;
}

/// `ZSTD_WINDOWLOG_MIN`.
pub const window_log_min = 10;
/// `ZSTD_LDM_DEFAULT_WINDOW_LOG`: the window log long-distance matching
/// switched on starts from.
pub const ldm_default_window_log = 27;
/// `ZSTD_LDM_MINMATCH_MIN` / `_MAX`.
pub const ldm_min_match_min = 4;
pub const ldm_min_match_max = 4096;
/// `ZSTD_LDM_BUCKETSIZELOG_MIN` / `_MAX`.
pub const ldm_bucket_size_log_min = 1;
pub const ldm_bucket_size_log_max = 8;
/// `ZSTD_LDM_HASHRATELOG_MAX`: `ZSTD_WINDOWLOG_MAX - ZSTD_HASHLOG_MIN`.
pub const ldm_hash_rate_log_max = window_log_max - hash_log_min;
/// `ZSTD_HASHLOG_MAX`, `ZSTD_CHAINLOG_MAX` (64-bit).
pub const hash_log_max = 30;
pub const chain_log_min = 6;
pub const chain_log_max = 30;
pub const search_log_min = 1;
/// `ZSTD_SEARCHLOG_MAX`: `ZSTD_WINDOWLOG_MAX` - 1.
pub const search_log_max = window_log_max - 1;
pub const min_match_min = 3;
pub const min_match_max = 7;
/// `ZSTD_TARGETLENGTH_MAX`: `ZSTD_BLOCKSIZE_MAX`.
pub const target_length_max = block_size_max_abs;
/// `ZSTD_BLOCKSPLITTER_LEVEL_MAX`.
pub const block_splitter_level_max = 6;
/// `ZSTD_BLOCKSIZE_MAX_MIN`.
pub const block_size_max_min = 1 << 10;
/// `ZSTD_BLOCKSIZE_MAX`.
pub const block_size_max_abs = 128 * 1024;

/// `ZSTD_resolveRowMatchFinderMode`.
pub fn resolveRowMatchFinder(mode: Switch, cp: CParams) bool {
    return switch (mode) {
        .enable => rowMatchFinderSupported(cp.strategy),
        .disable => false,
        .auto => useRowMatchFinder(cp),
    };
}

/// `ZSTD_resolveBlockSplitterMode`: whether the post-splitter runs.
pub fn resolveSplitAfterSequences(mode: Switch, cp: CParams) bool {
    return switch (mode) {
        .enable => true,
        .disable => false,
        .auto => @intFromEnum(cp.strategy) >= @intFromEnum(Strategy.btopt) and cp.window_log >= 17,
    };
}

/// `ZSTD_literalsCompressionIsDisabled`.
pub fn literalCompressionDisabled(mode: Switch, cp: CParams) bool {
    return switch (mode) {
        .enable => false,
        .disable => true,
        .auto => cp.strategy == .fast and cp.target_length > 0,
    };
}

test "a 1000-byte input shrinks the window to 1 KB" {
    const cp = get(3, 1000);
    try std.testing.expectEqual(@as(u32, 10), cp.window_log);
    try std.testing.expectEqual(@as(u32, 11), cp.hash_log);
    try std.testing.expectEqual(@as(u32, 10), cp.chain_log);
    try std.testing.expectEqual(Strategy.dfast, cp.strategy);
}

test "large inputs keep the table row" {
    const cp = get(1, 10 << 20);
    try std.testing.expectEqual(@as(u32, 19), cp.window_log);
    try std.testing.expectEqual(@as(u32, 7), cp.min_match);
    try std.testing.expectEqual(Strategy.fast, cp.strategy);
}

test "negative levels set the acceleration factor" {
    const cp = get(-5, 1 << 20);
    try std.testing.expectEqual(@as(u32, 5), cp.target_length);
    try std.testing.expectEqual(Strategy.fast, cp.strategy);
}

test "only level 22 above 64 MB reaches long-distance matching" {
    // ZSTD_resolveEnableLdm: btopt and up with windowLog >= 27
    const ldm_on = struct {
        fn f(cp: CParams) bool {
            return @intFromEnum(cp.strategy) >= @intFromEnum(Strategy.btopt) and cp.window_log >= 27;
        }
    }.f;
    for ([_]u64{ 1000, 16 * 1024, 100_000, 200_000, 10 << 20, 1 << 26, (1 << 26) + 1, 1 << 30 }) |size| {
        var level: i32 = 1;
        while (level <= max_level) : (level += 1) {
            try std.testing.expectEqual(level == 22 and size > 1 << 26, ldm_on(get(level, size)));
        }
    }
    try std.testing.expectEqual(@as(u32, 26), get(22, 1 << 26).window_log);
    try std.testing.expectEqual(@as(u32, 27), get(22, (1 << 26) + 1).window_log);
    try std.testing.expectEqual(@as(u32, 27), get(22, 1 << 30).window_log);
}

test "LDM by hand widens the window before the input shrinks it" {
    // level 19 above 256 KB has windowLog 23; LDM by hand starts from 27
    try std.testing.expectEqual(@as(u32, 23), get(19, 20 << 20).window_log);
    try std.testing.expectEqual(@as(u32, 25), getOverridden(19, 20 << 20, .{ .long_distance_matching = .enable }).window_log);
    try std.testing.expectEqual(@as(u32, 27), getOverridden(19, 1 << 30, .{ .long_distance_matching = .enable }).window_log);
    // the hash and chain logs were already cut to the level's own window
    try std.testing.expectEqual(get(19, 20 << 20).chain_log, getOverridden(19, 20 << 20, .{ .long_distance_matching = .enable }).chain_log);
    // a small input shrinks both to the same window
    try std.testing.expectEqual(get(19, 5000), getOverridden(19, 5000, .{ .long_distance_matching = .enable }));
}

test "btlazy2 halves the chain log to the window (ZSTD_cycleLog)" {
    // level 10, 16 KB tier: row (14, 15, 14, 9, 4, 8); 1000 bytes -> window 10,
    // chain 15 - 1 = 14 > 10 cut to 11 (two entries per position)
    const cp = get(10, 1000);
    try std.testing.expectEqual(Strategy.btlazy2, cp.strategy);
    try std.testing.expectEqual(@as(u32, 10), cp.window_log);
    try std.testing.expectEqual(@as(u32, 11), cp.chain_log);
    try std.testing.expect(!useRowMatchFinder(cp));
}

test "the row match finder takes over above a 16 KB window" {
    const small = get(5, 16 * 1024);
    try std.testing.expectEqual(@as(u32, 14), small.window_log);
    try std.testing.expect(!useRowMatchFinder(small));
    const large = get(5, 16 * 1024 + 1);
    try std.testing.expect(useRowMatchFinder(large));
    try std.testing.expectEqual(Strategy.lazy, get(6, 1 << 20).strategy);
}
