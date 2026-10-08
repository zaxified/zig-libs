// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Byte histograms (port of libzstd lib/compress/hist.c, v1.5.7).
//!
//! libzstd has a "simple" and a 4-way "parallel" counter and picks one by input
//! size and alphabet (`HIST_count_wksp`); both return the same counts, the same
//! trimmed `max_symbol` and the same largest count, so the choice is speed only.

const std = @import("std");
const fill = @import("fill.zig");

/// `HIST_FAST_THRESHOLD`: below it a full byte alphabet is counted simply.
const parallel_threshold = 1500;

/// Count the bytes of `src` into `count[0..max_symbol.*+1]`, trim `max_symbol`
/// down to the largest symbol present, and return the largest count.
/// Every byte of `src` must be `<= max_symbol.*`. An empty `src` sets
/// `max_symbol` to 0 and returns 0 (`HIST_count_simple`).
pub fn count(counts: []u32, max_symbol: *u32, src: []const u8) u32 {
    const max_in = max_symbol.*;
    if (src.len == 0) {
        fill.zero(u32, counts[0 .. max_in + 1]);
        max_symbol.* = 0;
        return 0;
    }
    if (max_in < 255 or src.len >= parallel_threshold) return countParallel(counts, max_symbol, src);
    fill.zero(u32, counts[0 .. max_in + 1]);
    for (src) |b| {
        std.debug.assert(b <= max_in);
        counts[b] += 1;
    }
    var m = max_in;
    while (counts[m] == 0) m -= 1;
    max_symbol.* = m;
    var largest: u32 = 0;
    for (counts[0 .. m + 1]) |c| largest = @max(largest, c);
    return largest;
}

/// `HIST_count_parallel_wksp`: four tables, so that a run of one byte value
/// does not chain every increment on the previous one through memory.
fn countParallel(counts: []u32, max_symbol: *u32, src: []const u8) u32 {
    const max_in = max_symbol.*;
    var t: [4][256]u32 = undefined;
    fill.zero(u32, @as(*[4 * 256]u32, @ptrCast(&t)));
    var ip: usize = 0;
    while (ip + 16 <= src.len) : (ip += 16) {
        inline for (0..4) |k| {
            const c = std.mem.readInt(u32, src[ip + 4 * k ..][0..4], .little);
            t[0][@as(u8, @truncate(c))] += 1;
            t[1][@as(u8, @truncate(c >> 8))] += 1;
            t[2][@as(u8, @truncate(c >> 16))] += 1;
            t[3][c >> 24] += 1;
        }
    }
    for (src[ip..]) |b| t[0][b] += 1;
    var largest: u32 = 0;
    for (&t[0], t[1], t[2], t[3]) |*a, b, c, d| {
        a.* += b + c + d;
        largest = @max(largest, a.*);
    }
    var m: u32 = 255;
    while (t[0][m] == 0) m -= 1;
    std.debug.assert(m <= max_in);
    max_symbol.* = m;
    @memcpy(counts[0 .. max_in + 1], t[0][0 .. max_in + 1]);
    return largest;
}

/// `HIST_add`: accumulate without clearing.
pub fn add(counts: []u32, src: []const u8) void {
    for (src) |b| counts[b] += 1;
}

test "count trims the alphabet and reports the mode" {
    var c: [256]u32 = undefined;
    var max: u32 = 255;
    const largest = count(&c, &max, "abracadabra");
    try std.testing.expectEqual(@as(u32, 'r'), max);
    try std.testing.expectEqual(@as(u32, 5), largest);
    try std.testing.expectEqual(@as(u32, 2), c['b']);
}

test "the parallel counter agrees with a plain count at every length and alphabet" {
    var prng = std.Random.DefaultPrng.init(0x5eed_4157);
    const r = prng.random();
    var src: [4100]u8 = undefined;
    // Lengths around the 16-byte stripes and the 1500-byte threshold; skewed
    // and run-heavy inputs (the case the four tables exist for) as well as
    // uniform ones, and alphabets below 255 (always parallel in libzstd).
    const lens = [_]usize{ 1, 15, 16, 17, 31, 1499, 1500, 1501, 4096, 4100 };
    for (lens) |len| for ([_]u32{ 255, 52, 35, 1 }) |alpha| for (0..3) |shape| {
        for (src[0..len], 0..) |*b, i| b.* = switch (shape) {
            0 => r.uintAtMost(u8, @intCast(alpha)),
            1 => if (r.uintLessThan(u8, 8) == 0) r.uintAtMost(u8, @intCast(alpha)) else 0,
            else => @intCast((i / 37) % (alpha + 1)),
        };
        var want: [256]u32 = @splat(0);
        for (src[0..len]) |b| want[b] += 1;
        var want_max: u32 = alpha;
        while (want[want_max] == 0) want_max -= 1;
        var got: [256]u32 = @splat(0xdead);
        var max = alpha;
        const largest = count(&got, &max, src[0..len]);
        try std.testing.expectEqual(want_max, max);
        try std.testing.expectEqual(std.mem.max(u32, want[0 .. alpha + 1]), largest);
        try std.testing.expectEqualSlices(u32, want[0 .. alpha + 1], got[0 .. alpha + 1]);
        // Nothing past the caller's alphabet is touched.
        for (got[alpha + 1 ..]) |c| try std.testing.expectEqual(@as(u32, 0xdead), c);
    };
}

test "empty input" {
    var c: [4]u32 = .{ 9, 9, 9, 9 };
    var max: u32 = 3;
    try std.testing.expectEqual(@as(u32, 0), count(&c, &max, ""));
    try std.testing.expectEqual(@as(u32, 0), max);
}
