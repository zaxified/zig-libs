// SPDX-License-Identifier: MIT
//! RSI, ported from TA-Lib 0.8.3 (`ta_RSI.c`; BSD-3, see NOTICE).

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const pf = core.pf;

pub const RsiParams = struct {
    period: usize = 14,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Wilder's RSI. Bar 0 only provides the first delta's reference; the next
/// `period` deltas are summed and divided by `period` (the seed), after that
/// avgGain/avgLoss are smoothed `(prev*(p-1) + today) / p`. The ratio is
/// `100 * gain / (gain + loss)`; a window with neither gain nor loss answers the
/// neutral 50 (TA-Lib 0.8.x, #480).
pub const RsiCore = struct {
    p: usize,
    u: usize,
    inv: f64,
    n: usize = 0,
    prev: f64 = 0.0,
    gain: f64 = 0.0,
    loss: f64 = 0.0,

    pub fn validate(p: RsiParams) Error!void {
        try core.checkPeriod(p.period, 2);
        try p.unstable.check();
    }
    pub fn unstableOf(p: RsiParams) usize {
        // auto4 = 10p, auto8 = 19p (period > 1 always holds here).
        return p.unstable.get(10 * p.period, 19 * p.period);
    }
    pub fn lookback(p: RsiParams) usize {
        return p.period + unstableOf(p);
    }
    pub fn init(p: RsiParams) Error!RsiCore {
        try validate(p);
        return .{ .p = p.period, .u = unstableOf(p), .inv = 1.0 / pf(p.period) };
    }
    fn answer(self: *const RsiCore) f64 {
        // Deliberate deviation: TA-Lib's `t > 0` test turns a NaN state into the
        // neutral 50; a NaN state answers NaN here.
        if (std.math.isNan(self.gain) or std.math.isNan(self.loss)) return std.math.nan(f64);
        const t = self.gain + self.loss;
        if (t > 0.0) return 100.0 * (self.gain / t);
        return 50.0;
    }
    pub fn step(self: *RsiCore, src: anytype, x: f64) ?f64 {
        _ = src;
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.prev = x;
            return null;
        }
        const d = x - self.prev;
        self.prev = x;
        const gd: f64 = if (d > 0.0) d else 0.0;
        if (n <= self.p) {
            self.gain += gd;
            self.loss += gd - d;
            if (n < self.p) return null;
            self.loss *= self.inv;
            self.gain *= self.inv;
            return if (self.u == 0) self.answer() else null;
        }
        self.loss *= pf(self.p - 1);
        self.gain *= pf(self.p - 1);
        self.gain += gd;
        self.loss += gd - d;
        self.loss *= self.inv;
        self.gain *= self.inv;
        return if (n >= self.p + self.u) self.answer() else null;
    }
};

pub fn rsiLookback(p: RsiParams) Error!usize {
    try RsiCore.validate(p);
    return RsiCore.lookback(p);
}
pub fn rsi(comptime T: type, in: []const T, out: []T, p: RsiParams) Error!usize {
    return smooth.batch1(T, RsiCore, in, out, p);
}
pub fn RsiStream(comptime T: type) type {
    return smooth.Rec1(T, RsiParams, RsiCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "rsi hand-checked vector" {
    // period 2 over 10 11 10 12 (TA-Lib's recursion, derived by hand):
    //  bar 1: d=+1: gain 1, loss 0;  bar 2: d=-1: gain 1, loss 1 -> seed /2: 0.5, 0.5
    //    RSI = 100 * 0.5 / 1.0 = 50.
    //  bar 3: d=+2: gain = 0.5*1 + 2 = 2.5, loss = 0.5*1 + 0 = 0.5, both /2: 1.25, 0.25
    //    RSI = 100 * 1.25 / 1.5 = 83.33...
    const in = [_]f64{ 10, 11, 10, 12 };
    var out: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try rsi(f64, &in, &out, .{ .period = 2 }));
    try testing.expect(std.math.isNan(out[1]));
    try testing.expectEqual(@as(f64, 50), out[2]);
    try testing.expectApproxEqRel(@as(f64, 100.0 * 1.25 / 1.5), out[3], 1e-14);
}

test "rsi: flat input answers 50, a monotone rise answers 100" {
    const flat = [_]f64{ 5, 5, 5, 5, 5, 5 };
    var out: [6]f64 = undefined;
    _ = try rsi(f64, &flat, &out, .{ .period = 3 });
    try testing.expectEqual(@as(f64, 50), out[3]);
    try testing.expectEqual(@as(f64, 50), out[5]);
    const up = [_]f64{ 1, 2, 3, 4, 5, 6 };
    _ = try rsi(f64, &up, &out, .{ .period = 3 });
    try testing.expectEqual(@as(f64, 100), out[3]);
    try testing.expectEqual(@as(f64, 100), out[5]);
}

test "rsi unstable period: lookback and AUTO constants" {
    try testing.expectEqual(@as(usize, 14), try rsiLookback(.{}));
    try testing.expectEqual(@as(usize, 14 + 5), try rsiLookback(.{ .unstable = .{ .bars = 5 } }));
    try testing.expectEqual(@as(usize, 14 + 140), try rsiLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 14 + 266), try rsiLookback(.{ .unstable = .auto8 }));
}

test "rsi: BadParam" {
    const in = [_]f64{ 1, 2, 3 };
    var out: [3]f64 = undefined;
    try testing.expectError(error.BadParam, rsi(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, rsi(f64, &in, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, rsi(f64, &in, out[0..1], .{ .period = 2 }));
}

test "rsi: NaN propagates or is skipped" {
    const nan = std.math.nan(f64);
    const in = [_]f64{ 10, 11, 10, nan, 12, 11 };
    var out: [6]f64 = undefined;
    _ = try rsi(f64, &in, &out, .{ .period = 2 });
    try testing.expect(std.math.isNan(out[4]) and std.math.isNan(out[5]));
    _ = try rsi(f64, &in, &out, .{ .period = 2, .nan = .skip });
    var clean: [5]f64 = undefined;
    _ = try rsi(f64, &[_]f64{ 10, 11, 10, 12, 11 }, &clean, .{ .period = 2 });
    try testing.expectEqual(clean[2], out[3]); // carries the previous output
    try testing.expectEqual(clean[3], out[4]);
    try testing.expectEqual(clean[4], out[5]);
}

test "rsi: batch == streaming, lookback == leading NaN, f32" {
    var xs: [300]f64 = undefined;
    th.walk(&xs, 31);
    try th.checkRec(RsiParams, RsiStream, rsi, rsiLookback, &xs, .{});
    try th.checkRec(RsiParams, RsiStream, rsi, rsiLookback, &xs, .{ .period = 5, .unstable = .{ .bars = 9 } });
    try th.checkRec(RsiParams, RsiStream, rsi, rsiLookback, &xs, .{ .period = 2, .unstable = .auto4 });
    var f32s: [100]f32 = undefined;
    for (&f32s, xs[0..100]) |*d, s| d.* = @floatCast(s);
    var o32: [100]f32 = undefined;
    try testing.expectEqual(@as(usize, 14), try rsi(f32, &f32s, &o32, .{}));
    try testing.expect(o32[14] >= 0 and o32[14] <= 100);
}

test "rsi: nan skip equals the series without the NaN bars, outputs carry over" {
    try th.checkSkip1(rsi, RsiParams{ .period = 5, .nan = .skip }, RsiParams{ .period = 5 });
}
