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

/// Highest level implemented: every size tier resolves levels up to 10 to a
/// strategy between `fast` and `btlazy2`. Level 11 is `btopt` for inputs of
/// 16 KB or less, which this module does not have.
pub const max_level = 10;
/// `ZSTD_MAX_CLEVEL`: rows in each table.
const table_levels = 22;
/// `ZSTD_minCLevel()`: -ZSTD_TARGETLENGTH_MAX.
pub const min_level = -(1 << 17);
/// `ZSTD_CLEVEL_DEFAULT`.
pub const default_level = 3;

const window_log_absolute_min = 10;
const hash_log_min = 6;
const window_log_max = 31;
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

/// `ZSTD_adjustCParams_internal` for a known source size and no dictionary.
fn adjust(cp_in: CParams, src_size: u64) CParams {
    var cp = cp_in;
    const max_window_resize: u64 = @as(u64, 1) << (window_log_max - 1);
    // resize windowLog if input is small enough, to use less memory
    if (src_size <= max_window_resize) {
        const t_size: u32 = @intCast(src_size);
        const hash_size_min: u32 = 1 << hash_log_min;
        const src_log: u32 = if (t_size < hash_size_min) hash_log_min else highbit32(t_size - 1) + 1;
        if (cp.window_log > src_log) cp.window_log = src_log;
    }
    // no dictionary: dictAndWindowLog == windowLog
    const dict_and_window_log = cp.window_log;
    // ZSTD_cycleLog: the binary-tree strategies keep two entries per position
    const cycle_log = cp.chain_log - @intFromBool(@intFromEnum(cp.strategy) >= @intFromEnum(Strategy.btlazy2));
    if (cp.hash_log > dict_and_window_log + 1) cp.hash_log = dict_and_window_log + 1;
    if (cycle_log > dict_and_window_log) cp.chain_log -= (cycle_log - dict_and_window_log);
    if (cp.window_log < window_log_absolute_min) cp.window_log = window_log_absolute_min;
    // The row match finder hashes hashLog - rowLog + 8 bits into 32. libzstd
    // assumes it is in use here, before the window size decides.
    if (rowMatchFinderSupported(cp.strategy)) {
        const max_hash_log = 32 - row_hash_tag_bits + rowLog(cp);
        if (cp.hash_log > max_hash_log) cp.hash_log = max_hash_log;
    }
    return cp;
}

/// `ZSTD_getCParams_internal(level, srcSize, 0, ZSTD_cpm_noAttachDict)` as used
/// by one-shot compression. `level` must be in `min_level..max_level`; 0 means
/// the default level.
pub fn get(level: i32, src_size: u64) CParams {
    std.debug.assert(level <= max_level);
    const table_id: usize = @as(usize, @intFromBool(src_size <= 256 * 1024)) +
        @intFromBool(src_size <= 128 * 1024) +
        @intFromBool(src_size <= 16 * 1024);
    const r: usize = if (level == 0) default_level else if (level < 0) 0 else @intCast(level);
    var cp = table[table_id][r];
    if (level < 0) cp.target_length = @intCast(-@max(min_level, level)); // acceleration factor
    return adjust(cp, src_size);
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

test "every size tier stays at or below btlazy2 up to max_level" {
    for ([_]u64{ 1000, 16 * 1024, 100_000, 200_000, 10 << 20 }) |size| {
        var level: i32 = 1;
        while (level <= max_level) : (level += 1) {
            try std.testing.expect(@intFromEnum(get(level, size).strategy) <= @intFromEnum(Strategy.btlazy2));
        }
    }
    // the next level is btopt in the smallest tier
    try std.testing.expectEqual(Strategy.btopt, table[3][max_level + 1].strategy);
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
