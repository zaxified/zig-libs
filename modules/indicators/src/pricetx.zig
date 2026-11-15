// SPDX-License-Identifier: MIT
//! Price transforms ported from TA-Lib 0.8.3 (`ta_AVGDEV.c`, `ta_AVGPRICE.c`,
//! `ta_HA.c`, `ta_MEDPRICE.c`, `ta_TYPPRICE.c`, `ta_WCLPRICE.c`; BSD-3, see
//! NOTICE). The operation order of every sum is the C's.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const K = @import("vs_kit.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const pf = core.pf;

// ── AVGDEV ──────────────────────────────────────────────────────────────────

pub const AvgdevParams = struct { period: usize = 14 };

/// Mean absolute deviation about the window's mean; the window is summed from
/// the newest bar back, exactly as the C does, and every bar's deviation uses
/// the freshly divided mean.
pub const AvgdevCore = struct {
    n: usize = 0,
    p: usize,
    pub fn validate(p: AvgdevParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: AvgdevParams) usize {
        return p.period;
    }
    pub fn lookback(p: AvgdevParams) usize {
        return p.period - 1;
    }
    pub fn init(p: AvgdevParams) Error!AvgdevCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *AvgdevCore, src: anytype, x: f64) ?f64 {
        _ = x;
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) return null;
        var sum: f64 = 0.0;
        var i: usize = 0;
        while (i < self.p) : (i += 1) sum += src.at(n - i);
        var dev: f64 = 0.0;
        i = 0;
        while (i < self.p) : (i += 1) dev += @abs(src.at(n - i) - sum / pf(self.p));
        return dev / pf(self.p);
    }
};
pub fn avgdevLookback(p: AvgdevParams) Error!usize {
    try AvgdevCore.validate(p);
    return AvgdevCore.lookback(p);
}
pub fn avgdev(comptime T: type, in: []const T, out: []T, p: AvgdevParams) Error!usize {
    return smooth.batch1(T, AvgdevCore, in, out, p);
}
pub fn AvgdevStream(comptime T: type) type {
    return smooth.Stream1(T, AvgdevParams, AvgdevCore);
}

// ── per-bar averages ────────────────────────────────────────────────────────

fn avgpriceFn(b: K.Ohlc(f64)) f64 {
    return (b.high + b.low + b.close + b.open) / 4.0;
}
fn medpriceFn(b: K.Hl(f64)) f64 {
    return (b.high + b.low) / 2.0;
}
fn typpriceFn(b: K.Hlc(f64)) f64 {
    return (b.high + b.low + b.close) / 3.0;
}
fn wclpriceFn(b: K.Hlc(f64)) f64 {
    return @mulAdd(f64, b.close, 2.0, b.high + b.low) / 4.0;
}
/// (high + low + close + open) / 4, summed in that order (HA sums open first).
pub const AvgpriceCore = K.PureCore(K.Ohlc, avgpriceFn);
/// (high + low) / 2
pub const MedpriceCore = K.PureCore(K.Hl, medpriceFn);
/// (high + low + close) / 3
pub const TyppriceCore = K.PureCore(K.Hlc, typpriceFn);
/// (high + low + 2 * close) / 4, the doubled close fused into the sum as TA-Lib's `fma`.
pub const WclpriceCore = K.PureCore(K.Hlc, wclpriceFn);

pub fn avgpriceLookback() usize {
    return 0;
}
pub fn avgprice(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return K.batch(T, AvgpriceCore, .{}, .{ .open = open, .high = high, .low = low, .close = close }, .{out});
}
pub fn AvgpriceStream(comptime T: type) type {
    return K.Stream(T, AvgpriceCore);
}
pub fn medpriceLookback() usize {
    return 0;
}
pub fn medprice(comptime T: type, high: []const T, low: []const T, out: []T) Error!usize {
    return K.batch(T, MedpriceCore, .{}, .{ .high = high, .low = low }, .{out});
}
pub fn MedpriceStream(comptime T: type) type {
    return K.Stream(T, MedpriceCore);
}
pub fn typpriceLookback() usize {
    return 0;
}
pub fn typprice(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return K.batch(T, TyppriceCore, .{}, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn TyppriceStream(comptime T: type) type {
    return K.Stream(T, TyppriceCore);
}
pub fn wclpriceLookback() usize {
    return 0;
}
pub fn wclprice(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return K.batch(T, WclpriceCore, .{}, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn WclpriceStream(comptime T: type) type {
    return K.Stream(T, WclpriceCore);
}

// ── HA ──────────────────────────────────────────────────────────────────────

pub const HaParams = struct {
    /// Extra bars dropped from the front (HA is a recursion on its own open;
    /// AUTO: 15 / 28 bars).
    unstable: Unstable = core.no_unstable,
};

pub fn HaOut(comptime T: type) type {
    return struct { open: T, high: T, low: T, close: T };
}

/// Heikin-Ashi candles: haClose = (O+H+L+C)/4, haOpen = (previous haOpen +
/// previous haClose)/2 (the first bar: (O+C)/2), haHigh/haLow the extremes of
/// the bar's own high/low and the two HA prices (plain comparisons).
pub const HaCore = struct {
    pub const In = K.Ohlc(f64);
    pub const Out = HaOut(f64);
    pub const Params = HaParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Ohlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return HaOut(T);
    }
    n: usize = 0,
    lb: usize,
    ho: f64 = 0.0,
    hc: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try p.unstable.check();
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(p: Params) usize {
        return p.unstable.get((13 * 10 + 8) / 9, (13 * 19 + 8) / 9);
    }
    pub fn init(p: Params) Error!HaCore {
        try validate(p);
        return .{ .lb = lookback(p) };
    }
    pub fn step(self: *HaCore, _: anytype, b: In) ?Out {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.ho = (b.open + b.close) / 2.0;
        } else {
            self.ho = (self.ho + self.hc) / 2.0;
        }
        self.hc = (b.open + b.high + b.low + b.close) / 4.0;
        if (n < self.lb) return null;
        var hh = b.high;
        if (self.ho > hh) hh = self.ho;
        if (self.hc > hh) hh = self.hc;
        var hl = b.low;
        if (self.ho < hl) hl = self.ho;
        if (self.hc < hl) hl = self.hc;
        return .{ .open = self.ho, .high = hh, .low = hl, .close = self.hc };
    }
};
pub fn haLookback(p: HaParams) Error!usize {
    try HaCore.validate(p);
    return HaCore.lookback(p);
}
pub fn ha(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out_open: []T, out_high: []T, out_low: []T, out_close: []T, p: HaParams) Error!usize {
    return K.batch(T, HaCore, p, .{ .open = open, .high = high, .low = low, .close = close }, .{ out_open, out_high, out_low, out_close });
}
pub fn HaStream(comptime T: type) type {
    return K.Stream(T, HaCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "price transforms: hand-checked values" {
    var out: [2]f64 = undefined;
    // bar (o=10, h=14, l=8, c=12): avg (14+8+12+10)/4 = 11, med 11, typ 34/3, wcl (14+8+24)/4 = 11.5
    _ = try avgprice(f64, &.{10}, &.{14}, &.{8}, &.{12}, out[0..1]);
    try testing.expectEqual(@as(f64, 11), out[0]);
    _ = try medprice(f64, &.{14}, &.{8}, out[0..1]);
    try testing.expectEqual(@as(f64, 11), out[0]);
    _ = try typprice(f64, &.{14}, &.{8}, &.{12}, out[0..1]);
    try testing.expectApproxEqRel(@as(f64, 34.0 / 3.0), out[0], 1e-15);
    _ = try wclprice(f64, &.{14}, &.{8}, &.{12}, out[0..1]);
    try testing.expectEqual(@as(f64, 11.5), out[0]);
}

test "avgdev hand-checked vector" {
    // window (1,2,6): mean 3, deviations 2 1 3 -> 2; window (2,6,4): mean 4, 2 2 0 -> 4/3.
    var out: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try avgdev(f64, &.{ 1, 2, 6, 4 }, &out, .{ .period = 3 }));
    try testing.expectEqual(@as(f64, 2), out[2]);
    try testing.expectApproxEqRel(@as(f64, 4.0 / 3.0), out[3], 1e-15);
}

test "ha hand-checked vector" {
    // bar 0 (o=10 h=12 l=8 c=11): haOpen (10+11)/2 = 10.5, haClose (10+12+8+11)/4 = 10.25,
    //   haHigh = max(12, 10.5, 10.25) = 12, haLow = min(8, ..) = 8.
    // bar 1 (o=11 h=13 l=9 c=12): haOpen (10.5+10.25)/2 = 10.375, haClose (11+13+9+12)/4 = 11.25.
    var o: [2]f64 = undefined;
    var h: [2]f64 = undefined;
    var l: [2]f64 = undefined;
    var c: [2]f64 = undefined;
    try testing.expectEqual(@as(usize, 0), try ha(f64, &.{ 10, 11 }, &.{ 12, 13 }, &.{ 8, 9 }, &.{ 11, 12 }, &o, &h, &l, &c, .{}));
    try testing.expectEqual(@as(f64, 10.5), o[0]);
    try testing.expectEqual(@as(f64, 10.25), c[0]);
    try testing.expectEqual(@as(f64, 12), h[0]);
    try testing.expectEqual(@as(f64, 8), l[0]);
    try testing.expectEqual(@as(f64, 10.375), o[1]);
    try testing.expectEqual(@as(f64, 11.25), c[1]);
    try testing.expectEqual(@as(usize, 15), try haLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 28), try haLookback(.{ .unstable = .auto8 }));
}

test "price transforms: BadParam, batch == streaming, f32" {
    var out: [8]f64 = undefined;
    const z = [_]f64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try testing.expectError(error.BadParam, avgdev(f64, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, avgprice(f64, &z, &z, &z, z[0..7], &out));
    try testing.expectError(error.BadParam, ha(f64, &z, &z, &z, &z, &out, &out, &out, &out, .{ .unstable = .{ .bars = 1 << 31 } }));
    var o: [200]f64 = undefined;
    var h: [200]f64 = undefined;
    var l: [200]f64 = undefined;
    var c: [200]f64 = undefined;
    var v: [200]f64 = undefined;
    K.fillBars(&o, &h, &l, &c, &v, 21);
    try th.checkOne(AvgdevParams, AvgdevStream, avgdev, avgdevLookback, &c, .{});
    try th.checkOne(AvgdevParams, AvgdevStream, avgdev, avgdevLookback, &c, .{ .period = 2 });
    try K.checkCore(AvgpriceCore, .{}, .{ .open = &o, .high = &h, .low = &l, .close = &c });
    try K.checkCore(MedpriceCore, .{}, .{ .high = &h, .low = &l });
    try K.checkCore(TyppriceCore, .{}, .{ .high = &h, .low = &l, .close = &c });
    try K.checkCore(WclpriceCore, .{}, .{ .high = &h, .low = &l, .close = &c });
    const ohlc = .{ .open = &o, .high = &h, .low = &l, .close = &c };
    try K.checkCore(HaCore, .{}, ohlc);
    try K.checkCore(HaCore, .{ .unstable = .{ .bars = 4 } }, ohlc);
    try K.checkCore(HaCore, .{ .unstable = .auto8 }, ohlc);
    var h32: [20]f32 = undefined;
    var l32: [20]f32 = undefined;
    for (&h32, &l32, h[0..20], l[0..20]) |*a, *b, x, y| {
        a.* = @floatCast(x);
        b.* = @floatCast(y);
    }
    var o32: [20]f32 = undefined;
    try testing.expectEqual(@as(usize, 0), try medprice(f32, &h32, &l32, &o32));
}
