// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Compression parameters per level (port of libzstd lib/compress/clevels.h and
//! the parameter selection in lib/compress/zstd_compress.c, v1.5.7).
//!
//! Only the rows this module implements are carried: levels 1-3 and the
//! negative ("fast") levels, all of which resolve to the `fast` or `dfast`
//! strategy. Selection is libzstd's exactly — table by source size, then
//! `ZSTD_adjustCParams_internal` shrinking window/hash/chain to the input —
//! because the resulting window log is written into the frame header and the
//! table sizes decide which matches are found.

const std = @import("std");

pub const Strategy = enum(u32) { fast = 1, dfast = 2 };

pub const CParams = struct {
    window_log: u32,
    chain_log: u32,
    hash_log: u32,
    search_log: u32,
    min_match: u32,
    target_length: u32,
    strategy: Strategy,
};

/// Highest level implemented. Levels above it use strategies (greedy, lazy,
/// btopt, ...) this module does not have.
pub const max_level = 3;
/// `ZSTD_minCLevel()`: -ZSTD_TARGETLENGTH_MAX.
pub const min_level = -(1 << 17);
/// `ZSTD_CLEVEL_DEFAULT`.
pub const default_level = 3;

const window_log_absolute_min = 10;
const hash_log_min = 6;
const window_log_max = 31;

fn row(w: u32, c: u32, h: u32, s: u32, l: u32, tl: u32, st: Strategy) CParams {
    return .{ .window_log = w, .chain_log = c, .hash_log = h, .search_log = s, .min_match = l, .target_length = tl, .strategy = st };
}

/// `ZSTD_defaultCParameters[tableID][0..3]`: row 0 is the base for negative levels.
const table = [4][max_level + 1]CParams{
    .{ // srcSize > 256 KB
        row(19, 12, 13, 1, 6, 1, .fast),
        row(19, 13, 14, 1, 7, 0, .fast),
        row(20, 15, 16, 1, 6, 0, .fast),
        row(21, 16, 17, 1, 5, 0, .dfast),
    },
    .{ // srcSize <= 256 KB
        row(18, 12, 13, 1, 5, 1, .fast),
        row(18, 13, 14, 1, 6, 0, .fast),
        row(18, 14, 14, 1, 5, 0, .dfast),
        row(18, 16, 16, 1, 4, 0, .dfast),
    },
    .{ // srcSize <= 128 KB
        row(17, 12, 12, 1, 5, 1, .fast),
        row(17, 12, 13, 1, 6, 0, .fast),
        row(17, 13, 15, 1, 5, 0, .fast),
        row(17, 15, 16, 2, 5, 0, .dfast),
    },
    .{ // srcSize <= 16 KB
        row(14, 12, 13, 1, 5, 1, .fast),
        row(14, 14, 15, 1, 5, 0, .fast),
        row(14, 14, 15, 1, 4, 0, .fast),
        row(14, 14, 15, 2, 4, 0, .dfast),
    },
};

fn highbit32(v: u32) u32 {
    return 31 - @as(u32, @clz(v));
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
    // no dictionary: dictAndWindowLog == windowLog; fast/dfast: cycleLog == chainLog
    const dict_and_window_log = cp.window_log;
    if (cp.hash_log > dict_and_window_log + 1) cp.hash_log = dict_and_window_log + 1;
    if (cp.chain_log > dict_and_window_log) cp.chain_log -= (cp.chain_log - dict_and_window_log);
    if (cp.window_log < window_log_absolute_min) cp.window_log = window_log_absolute_min;
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
