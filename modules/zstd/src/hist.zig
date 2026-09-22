// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Byte histograms (port of libzstd lib/compress/hist.c, v1.5.7).
//!
//! libzstd has a "simple" and a 4-way "parallel" counter and picks one by input
//! size; both return the same counts, the same trimmed `max_symbol` and the same
//! largest count, so one implementation serves every call site here.

const std = @import("std");

/// Count the bytes of `src` into `count[0..max_symbol.*+1]`, trim `max_symbol`
/// down to the largest symbol present, and return the largest count.
/// Every byte of `src` must be `<= max_symbol.*`. An empty `src` sets
/// `max_symbol` to 0 and returns 0 (`HIST_count_simple`).
pub fn count(counts: []u32, max_symbol: *u32, src: []const u8) u32 {
    const max_in = max_symbol.*;
    @memset(counts[0 .. max_in + 1], 0);
    if (src.len == 0) {
        max_symbol.* = 0;
        return 0;
    }
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

test "empty input" {
    var c: [4]u32 = .{ 9, 9, 9, 9 };
    var max: u32 = 3;
    try std.testing.expectEqual(@as(u32, 0), count(&c, &max, ""));
    try std.testing.expectEqual(@as(u32, 0), max);
}
