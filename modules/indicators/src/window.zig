// SPDX-License-Identifier: MIT
//! Rolling SUM, MAX and MIN over a window, ported from TA-Lib 0.8.3
//! (`ta_SUM.c`, `ta_MAX.c`, `ta_MIN.c`; BSD-3, see NOTICE). The window extreme
//! core is also what STOCH reads its highest high and lowest low from.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const Error = core.Error;
const pf = core.pf;
const th = @import("testhelp.zig");

pub const WindowParams = struct { period: usize = 30 };
pub const SumParams = WindowParams;
pub const MaxParams = WindowParams;
pub const MinParams = WindowParams;

// ── SUM ─────────────────────────────────────────────────────────────────────

pub const SumCore = struct {
    p: usize,
    n: usize = 0,
    sum: f64 = 0.0,

    pub fn validate(p: WindowParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: WindowParams) usize {
        return p.period;
    }
    pub fn lookback(p: WindowParams) usize {
        return p.period - 1;
    }
    pub fn init(p: WindowParams) Error!SumCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *SumCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        self.sum += x;
        if (n + 1 < self.p) return null;
        const t = self.sum;
        self.sum -= src.at(n + 1 - self.p);
        return t;
    }
};

pub fn sumLookback(p: SumParams) Error!usize {
    try SumCore.validate(p);
    return SumCore.lookback(p);
}
pub fn sum(comptime T: type, in: []const T, out: []T, p: SumParams) Error!usize {
    return smooth.batch1(T, SumCore, in, out, p);
}
pub fn SumStream(comptime T: type) type {
    return smooth.Stream1(T, SumParams, SumCore);
}

// ── MAX / MIN ───────────────────────────────────────────────────────────────

/// The extreme of the last `period` bars. Tracks the index of the current
/// extreme and rescans the window only when it leaves it (TA_MAX / TA_MIN's
/// classic algorithm; ties keep the newest bar).
pub fn ExtCore(comptime is_max: bool) type {
    return struct {
        const Self = @This();
        p: usize,
        n: usize = 0,
        idx: ?usize = null,
        val: f64 = 0.0,

        pub fn validate(p: WindowParams) Error!void {
            try core.checkPeriod(p.period, 2);
        }
        pub fn ringLen(p: WindowParams) usize {
            return p.period;
        }
        pub fn lookback(p: WindowParams) usize {
            return p.period - 1;
        }
        pub fn init(p: WindowParams) Error!Self {
            try validate(p);
            return .{ .p = p.period };
        }
        /// The window-extreme update shared with STOCH; `period >= 1`.
        pub fn initAny(period: usize) Self {
            return .{ .p = period };
        }
        inline fn better(a: f64, b: f64) bool {
            return if (is_max) a > b else a < b;
        }
        inline fn betterEq(a: f64, b: f64) bool {
            return if (is_max) a >= b else a <= b;
        }
        pub fn step(self: *Self, src: anytype, x: f64) ?f64 {
            const n = self.n;
            self.n += 1;
            if (n + 1 < self.p) return null;
            const trailing = n + 1 - self.p;
            if (self.idx == null or self.idx.? < trailing) {
                var idx = trailing;
                var val = src.at(trailing);
                var i = trailing;
                while (i < n) {
                    i += 1;
                    const t = src.at(i);
                    if (better(t, val)) {
                        idx = i;
                        val = t;
                    }
                }
                self.idx = idx;
                self.val = val;
            } else if (betterEq(x, self.val)) {
                self.idx = n;
                self.val = x;
            }
            return self.val;
        }
    };
}

pub const MaxCore = ExtCore(true);
pub const MinCore = ExtCore(false);

pub fn maxLookback(p: MaxParams) Error!usize {
    try MaxCore.validate(p);
    return MaxCore.lookback(p);
}
pub fn max(comptime T: type, in: []const T, out: []T, p: MaxParams) Error!usize {
    return smooth.batch1(T, MaxCore, in, out, p);
}
pub fn MaxStream(comptime T: type) type {
    return smooth.Stream1(T, MaxParams, MaxCore);
}
pub fn minLookback(p: MinParams) Error!usize {
    try MinCore.validate(p);
    return MinCore.lookback(p);
}
pub fn min(comptime T: type, in: []const T, out: []T, p: MinParams) Error!usize {
    return smooth.batch1(T, MinCore, in, out, p);
}
pub fn MinStream(comptime T: type) type {
    return smooth.Stream1(T, MinParams, MinCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "sum hand-checked vector" {
    // period 3 over 1 2 3 4 5: 6, 9, 12 (running sum 1,3,6 -> 6; 6-1+4 = 9; 9-2+5 = 12).
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var out: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try sum(f64, &in, &out, .{ .period = 3 }));
    try testing.expect(std.math.isNan(out[1]));
    try testing.expectEqual(@as(f64, 6), out[2]);
    try testing.expectEqual(@as(f64, 9), out[3]);
    try testing.expectEqual(@as(f64, 12), out[4]);
}

test "max and min hand-checked vector" {
    // period 3 over 5 1 4 2 8 3: windows (5,1,4) (1,4,2) (4,2,8) (2,8,3).
    // The max of the first window is 5 at bar 0; at bar 3 it has left, so the
    // window is rescanned: (1,4,2) -> 4; bar 4: 8 >= 4 -> 8; bar 5: 8 is still inside -> 8.
    const in = [_]f64{ 5, 1, 4, 2, 8, 3 };
    var hi: [6]f64 = undefined;
    var lo: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try max(f64, &in, &hi, .{ .period = 3 }));
    try testing.expectEqual(@as(usize, 2), try min(f64, &in, &lo, .{ .period = 3 }));
    try testing.expectEqualSlices(f64, &.{ 5, 4, 8, 8 }, hi[2..]);
    try testing.expectEqualSlices(f64, &.{ 1, 1, 2, 2 }, lo[2..]);
}

test "window: BadParam, period 2 minimum" {
    const in = [_]f64{ 1, 2, 3 };
    var out: [3]f64 = undefined;
    try testing.expectError(error.BadParam, sum(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, max(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, min(f64, &in, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, sumLookback(.{ .period = 0 }));
    try testing.expectError(error.BadParam, max(f64, &in, out[0..2], .{ .period = 2 }));
    try testing.expectEqual(@as(usize, 1), try maxLookback(.{ .period = 2 }));
}

test "window: batch == streaming, lookback == leading NaN, matches naive scan, f32" {
    var xs: [400]f64 = undefined;
    th.walk(&xs, 21);
    try th.checkOne(SumParams, SumStream, sum, sumLookback, &xs, .{ .period = 10 });
    try th.checkOne(MaxParams, MaxStream, max, maxLookback, &xs, .{ .period = 10 });
    try th.checkOne(MinParams, MinStream, min, minLookback, &xs, .{ .period = 10 });
    try th.checkOne(MaxParams, MaxStream, max, maxLookback, &xs, .{ .period = 2 });
    var hi: [400]f64 = undefined;
    var lo: [400]f64 = undefined;
    _ = try max(f64, &xs, &hi, .{ .period = 7 });
    _ = try min(f64, &xs, &lo, .{ .period = 7 });
    for (6..400) |i| {
        var h = xs[i];
        var l = xs[i];
        for (xs[i - 6 .. i + 1]) |v| {
            h = @max(h, v);
            l = @min(l, v);
        }
        try testing.expectEqual(h, hi[i]);
        try testing.expectEqual(l, lo[i]);
    }
    var f32s: [50]f32 = undefined;
    for (&f32s, xs[0..50]) |*d, s| d.* = @floatCast(s);
    var o32: [50]f32 = undefined;
    try testing.expectEqual(@as(usize, 4), try sum(f32, &f32s, &o32, .{ .period = 5 }));
    try testing.expectEqual(@as(usize, 4), try max(f32, &f32s, &o32, .{ .period = 5 }));
    try testing.expectEqual(@as(usize, 4), try min(f32, &f32s, &o32, .{ .period = 5 }));
}

test "sum: a NaN poisons the running sum" {
    const nan = std.math.nan(f64);
    const in = [_]f64{ 1, 2, nan, 4, 5, 6 };
    var out: [6]f64 = undefined;
    _ = try sum(f64, &in, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 3), out[1]);
    for (out[2..]) |v| try testing.expect(std.math.isNan(v));
}

test "max/min with NaN: a NaN never wins a comparison, so it only shows when it opens a rescan" {
    const nan = std.math.nan(f64);
    // max, period 3 over 1 2 NaN 0 0 0:
    //  bar 2 rescan (1,2,NaN): 1 -> 2, NaN > 2 false -> 2; bar 3: 0 >= 2 false -> 2;
    //  bar 4: the max (bar 1) left, rescan (NaN,0,0): starts at NaN, 0 > NaN false -> NaN;
    //  bar 5: NaN's index left, rescan (0,0,0) -> 0.
    const a = [_]f64{ 1, 2, nan, 0, 0, 0 };
    var out: [6]f64 = undefined;
    _ = try max(f64, &a, &out, .{ .period = 3 });
    try testing.expectEqual(@as(f64, 2), out[2]);
    try testing.expectEqual(@as(f64, 2), out[3]);
    try testing.expect(std.math.isNan(out[4]));
    try testing.expectEqual(@as(f64, 0), out[5]);
    // min, period 3 over 5 4 NaN 9 9 9: 4, 4, NaN, 9
    const b = [_]f64{ 5, 4, nan, 9, 9, 9 };
    _ = try min(f64, &b, &out, .{ .period = 3 });
    try testing.expectEqual(@as(f64, 4), out[2]);
    try testing.expectEqual(@as(f64, 4), out[3]);
    try testing.expect(std.math.isNan(out[4]));
    try testing.expectEqual(@as(f64, 9), out[5]);
}

test "max/min ties: a rescan keeps the OLDEST of equal values, an incremental update the NEWEST (0.0 vs -0.0)" {
    // The C code: rescan `tmp > highest` (strict, oldest stays); update `tmp >= highest` (newest wins).
    // max, period 3 over -2 -0 -1 0 -0:
    //  bar 2 rescan: -2 -> -0 (idx 1) -> stays; out -0.
    //  bar 3: idx 1 still in window, 0.0 >= -0.0 -> newest wins: +0.
    //  bar 4: -0.0 >= +0.0 -> newest wins: -0.
    const nz = -0.0;
    const a = [_]f64{ -2, nz, -1, 0.0, nz };
    var out: [5]f64 = undefined;
    _ = try max(f64, &a, &out, .{ .period = 3 });
    try testing.expect(std.math.signbit(out[2]) and out[2] == 0);
    try testing.expect(!std.math.signbit(out[3]) and out[3] == 0);
    try testing.expect(std.math.signbit(out[4]) and out[4] == 0);
    // min, period 3 over 2 +0 1 -0 +0: bar 2 -> +0; bar 3 (-0 <= +0) -> -0; bar 4 -> +0.
    const b = [_]f64{ 2, 0.0, 1, nz, 0.0 };
    _ = try min(f64, &b, &out, .{ .period = 3 });
    try testing.expect(!std.math.signbit(out[2]) and out[2] == 0);
    try testing.expect(std.math.signbit(out[3]) and out[3] == 0);
    try testing.expect(!std.math.signbit(out[4]) and out[4] == 0);
    // rescan: period 2 over -0 +0 -0: bar 1 window (-0,+0): oldest -0 stays; bar 2 rescan (+0,-0): +0 stays.
    const c = [_]f64{ nz, 0.0, nz };
    _ = try max(f64, &c, out[0..3], .{ .period = 2 });
    try testing.expect(std.math.signbit(out[1]));
    try testing.expect(!std.math.signbit(out[2]));
}
