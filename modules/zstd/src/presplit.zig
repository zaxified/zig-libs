// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Block pre-splitting (port of libzstd lib/compress/zstd_preSplit.c, v1.5.7).
//!
//! Before a full 128 KB block is compressed, libzstd may cut it where the byte
//! statistics change. Since 1.5.7 this runs for every strategy once the frame
//! has shown some savings, including `fast` (split "from borders") and `dfast`
//! (split by 8 KB chunks, sampled every 43rd byte). It decides block
//! boundaries, so it decides the output.

const std = @import("std");
const hist = @import("hist.zig");

const threshold_penalty_rate = 16;
const threshold_base = threshold_penalty_rate - 2;
const threshold_penalty = 3;
const hash_length = 2;
const hashlog_max = 10;
const hashtable_size = 1 << hashlog_max;
const knuth: u32 = 0x9e3779b9;
const chunk_size = 8 << 10;
const segment_size = 512;

pub const full_block = 128 * 1024;

const Fingerprint = struct {
    events: [hashtable_size]u32 = [_]u32{0} ** hashtable_size,
    nb_events: usize = 0,
};

fn hash2(p: []const u8, hash_log: u32) u32 {
    std.debug.assert(hash_log >= 8);
    if (hash_log == 8) return p[0];
    std.debug.assert(hash_log <= hashlog_max);
    // libzstd reads these two bytes in native order; little-endian is what the
    // reference output on x86/arm64 corresponds to. (Only greedy and up use it.)
    const v: u32 = std.mem.readInt(u16, p[0..2], .little);
    return (v *% knuth) >> @intCast(32 - hash_log);
}

fn recordFingerprint(fp: *Fingerprint, src: []const u8, sampling_rate: usize, hash_log: u32) void {
    @memset(fp.events[0 .. @as(usize, 1) << @intCast(hash_log)], 0);
    fp.nb_events = 0;
    const limit = src.len - hash_length + 1;
    var n: usize = 0;
    while (n < limit) : (n += sampling_rate) fp.events[hash2(src[n..], hash_log)] += 1;
    fp.nb_events += limit / sampling_rate;
}

fn abs64(v: i64) u64 {
    return @intCast(if (v < 0) -v else v);
}

fn fpDistance(fp1: *const Fingerprint, fp2: *const Fingerprint, hash_log: u32) u64 {
    var distance: u64 = 0;
    const n1: i64 = @intCast(fp1.nb_events);
    const n2: i64 = @intCast(fp2.nb_events);
    for (0..@as(usize, 1) << @intCast(hash_log)) |n| {
        distance += abs64(@as(i64, fp1.events[n]) * n2 - @as(i64, fp2.events[n]) * n1);
    }
    return distance;
}

/// True when `newfp` is too far from `ref` to belong to the same block.
fn compareFingerprints(ref: *const Fingerprint, newfp: *const Fingerprint, penalty: u32, hash_log: u32) bool {
    const p50: u64 = @as(u64, ref.nb_events) * @as(u64, newfp.nb_events);
    const deviation = fpDistance(ref, newfp, hash_log);
    const threshold = p50 * (threshold_base + penalty) / threshold_penalty_rate;
    return deviation >= threshold;
}

fn mergeEvents(acc: *Fingerprint, newfp: *const Fingerprint) void {
    for (&acc.events, newfp.events) |*a, b| a.* += b;
    acc.nb_events += newfp.nb_events;
}

const Stats = struct {
    past: Fingerprint = .{},
    new: Fingerprint = .{},
};

fn splitByChunks(block: []const u8, level: u32, stats: *Stats) usize {
    const rates = [_]usize{ 43, 11, 5, 1 };
    const hash_params = [_]u32{ 8, 9, 10, 10 };
    std.debug.assert(block.len == full_block);
    const rate = rates[level];
    const hlog = hash_params[level];
    var penalty: u32 = threshold_penalty;
    stats.* = .{};
    recordFingerprint(&stats.past, block[0..chunk_size], rate, hlog);
    var pos: usize = chunk_size;
    while (pos <= block.len - chunk_size) : (pos += chunk_size) {
        recordFingerprint(&stats.new, block[pos..][0..chunk_size], rate, hlog);
        if (compareFingerprints(&stats.past, &stats.new, penalty, hlog)) return pos;
        mergeEvents(&stats.past, &stats.new);
        if (penalty > 0) penalty -= 1;
    }
    return block.len;
}

fn splitFromBorders(block: []const u8, stats: *Stats) usize {
    std.debug.assert(block.len == full_block);
    stats.* = .{};
    var middle: Fingerprint = .{};
    hist.add(&stats.past.events, block[0..segment_size]);
    hist.add(&stats.new.events, block[block.len - segment_size ..]);
    stats.past.nb_events = segment_size;
    stats.new.nb_events = segment_size;
    if (!compareFingerprints(&stats.past, &stats.new, 0, 8)) return block.len;

    hist.add(&middle.events, block[block.len / 2 - segment_size / 2 ..][0..segment_size]);
    middle.nb_events = segment_size;
    const dist_from_begin = fpDistance(&stats.past, &middle, 8);
    const dist_from_end = fpDistance(&stats.new, &middle, 8);
    const min_distance: u64 = segment_size * segment_size / 3;
    if (abs64(@as(i64, @intCast(dist_from_begin)) - @as(i64, @intCast(dist_from_end))) < min_distance) return 64 * 1024;
    return if (dist_from_begin > dist_from_end) 32 * 1024 else 96 * 1024;
}

/// `ZSTD_splitBlock`: where to end the block that starts `block` (a full 128 KB).
fn splitBlock(block: []const u8, level: u32, stats: *Stats) usize {
    std.debug.assert(level <= 4);
    if (level == 0) return splitFromBorders(block, stats);
    return splitByChunks(block, level - 1, stats);
}

/// `ZSTD_optimalBlockSize`. `strategy` is libzstd's numeric strategy
/// (1 = fast, 2 = dfast); `split_level` is `ZSTD_c_blockSplitterLevel`: 0
/// picks by strategy, 1 never splits, 2..6 are the splitter's levels 0..4.
pub fn optimalBlockSize(src: []const u8, block_size_max: usize, split_level: u32, strategy: u32, savings: i64, stats: *Stats) usize {
    // split level based on compression strategy, from `fast` to `btultra2`
    const split_levels = [_]u32{ 0, 0, 1, 2, 2, 3, 3, 4, 4, 4 };
    if (src.len < full_block or block_size_max < full_block) return @min(src.len, block_size_max);
    // do not split incompressible data: the first full block is never split
    if (savings < 3) return full_block;
    if (split_level == 1) return full_block;
    const level = if (split_level == 0) split_levels[strategy] else split_level - 2;
    return splitBlock(src[0..block_size_max], level, stats);
}

pub const Workspace = Stats;

test "a homogeneous block is not split" {
    var buf: [full_block]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 7);
    var ws: Workspace = .{};
    try std.testing.expectEqual(@as(usize, full_block), optimalBlockSize(&buf, full_block, 0, 1, 1000, &ws));
    try std.testing.expectEqual(@as(usize, full_block), optimalBlockSize(&buf, full_block, 0, 2, 1000, &ws));
}

test "a block whose halves differ is split from the borders" {
    var buf: [full_block]u8 = undefined;
    @memset(buf[0 .. full_block / 4], 'a');
    @memset(buf[full_block / 4 ..], 'z');
    var ws: Workspace = .{};
    try std.testing.expectEqual(@as(usize, 32 * 1024), optimalBlockSize(&buf, full_block, 0, 1, 1000, &ws));
}

test "no split before the frame has saved anything" {
    var buf: [full_block + 10]u8 = undefined;
    @memset(buf[0 .. full_block / 2], 'a');
    @memset(buf[full_block / 2 ..], 'z');
    var ws: Workspace = .{};
    try std.testing.expectEqual(@as(usize, full_block), optimalBlockSize(&buf, full_block, 0, 1, 0, &ws));
}
