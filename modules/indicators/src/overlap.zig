// SPDX-License-Identifier: MIT
//! MIDPOINT, MIDPRICE, FRAMA, VWMA and MAVP, ported from TA-Lib 0.8.3
//! (`ta_MIDPOINT.c`, `ta_MIDPRICE.c`, `ta_FRAMA.c`, `ta_VWMA.c`, `ta_MAVP.c`;
//! BSD-3, see NOTICE).

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const window = @import("window.zig");
const hist = @import("hist.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const MaType = core.MaType;
const pf = core.pf;
const MaxCore = window.MaxCore;
const MinCore = window.MinCore;

// ── MIDPOINT ────────────────────────────────────────────────────────────────

pub const MidParams = struct { period: usize = 14 };

/// `(highest + lowest) / 2` of the last `period` values.
pub const MidpointCore = struct {
    hi: MaxCore,
    lo: MinCore,
    n: usize = 0,

    pub fn validate(p: MidParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: MidParams) usize {
        return p.period;
    }
    pub fn lookback(p: MidParams) usize {
        return p.period - 1;
    }
    pub fn init(p: MidParams) Error!MidpointCore {
        try validate(p);
        return .{ .hi = MaxCore.initAny(p.period), .lo = MinCore.initAny(p.period) };
    }
    pub fn step(self: *MidpointCore, src: anytype, x: f64) ?f64 {
        self.n += 1;
        const h = self.hi.step(src, x);
        const l = self.lo.step(src, x);
        if (h == null or l == null) return null;
        return (h.? + l.?) / 2.0;
    }
    /// The steady path of `smooth.runCore`: from the first output on.
    pub fn steady(self: *const MidpointCore) bool {
        return self.n + 1 >= self.hi.p;
    }
    pub fn steadyRun(self: *MidpointCore, comptime T: type, in: []const T, out: []T, i: usize) void {
        var hr = MaxCore.Run.of(&self.hi);
        var lr = MinCore.Run.of(&self.lo);
        var n = i;
        while (n < in.len) : (n += 1) {
            const h = hr.bar(T, in, n);
            const l = lr.bar(T, in, n);
            out[n] = core.to(T, (h + l) / 2.0);
        }
        hr.store(&self.hi, in.len);
        lr.store(&self.lo, in.len);
        self.n = in.len;
    }
};

pub fn midpointLookback(p: MidParams) Error!usize {
    try MidpointCore.validate(p);
    return MidpointCore.lookback(p);
}
pub fn midpoint(comptime T: type, in: []const T, out: []T, p: MidParams) Error!usize {
    return smooth.batch1(T, MidpointCore, in, out, p);
}
pub fn MidpointStream(comptime T: type) type {
    return smooth.Stream1(T, MidParams, MidpointCore);
}

// ── MIDPRICE ────────────────────────────────────────────────────────────────

/// `(highest high + lowest low) / 2` of the last `period` bars.
pub const MidpriceCore = struct {
    pub const In = hist.Hl(f64);
    pub const Out = f64;
    pub fn InOf(comptime T: type) type {
        return hist.Hl(T);
    }
    pub fn OutOf(comptime T: type) type {
        return T;
    }
    hi: MaxCore,
    lo: MinCore,
    n: usize = 0,

    pub fn validate(p: MidParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: MidParams) usize {
        return p.period;
    }
    pub fn lookback(p: MidParams) usize {
        return p.period - 1;
    }
    pub fn init(p: MidParams) Error!MidpriceCore {
        try validate(p);
        return .{ .hi = MaxCore.initAny(p.period), .lo = MinCore.initAny(p.period) };
    }
    pub fn step(self: *MidpriceCore, h: anytype, x: In) ?f64 {
        self.n += 1;
        const hh = self.hi.step(hist.field(h, .high), x.high);
        const ll = self.lo.step(hist.field(h, .low), x.low);
        if (hh == null or ll == null) return null;
        return (hh.? + ll.?) / 2.0;
    }
};

pub fn midpriceLookback(p: MidParams) Error!usize {
    try MidpriceCore.validate(p);
    return MidpriceCore.lookback(p);
}
pub fn midprice(comptime T: type, high: []const T, low: []const T, out: []T, p: MidParams) Error!usize {
    return hist.batch(T, MidpriceCore, .{ high, low }, .{out}, p, &.{});
}
pub fn MidpriceStream(comptime T: type) type {
    return hist.Stream(T, MidParams, MidpriceCore);
}

// ── FRAMA ───────────────────────────────────────────────────────────────────

pub const FramaParams = struct {
    period: usize = 16,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

const frama_scale: f64 = blk: {
    const a: f64 = -4.6;
    const b: f64 = 0.6931471805599453;
    break :blk a / b;
};

/// Ehlers' fractal adaptive moving average over the bar midpoint: the fractal
/// dimension comes from the ranges of the two halves of the window and of the
/// whole window, `alpha = exp(-4.6 (D - 1))`; the period must be even.
pub const FramaCore = struct {
    pub const In = hist.Hl(f64);
    pub const Out = f64;
    pub fn InOf(comptime T: type) type {
        return hist.Hl(T);
    }
    pub fn OutOf(comptime T: type) type {
        return T;
    }
    p: usize,
    half: usize,
    lb: usize,
    hi1: MaxCore,
    lo1: MinCore,
    hi2: MaxCore,
    lo2: MinCore,
    n: usize = 0,
    prev: f64 = 0.0,

    pub fn validate(p: FramaParams) Error!void {
        try core.checkPeriod(p.period, 2);
        if (p.period % 2 != 0) return error.BadParam;
        try p.unstable.check();
    }
    pub fn unstableOf(p: FramaParams) usize {
        const root: usize = @intFromFloat(@sqrt(pf(p.period)));
        const c4 = @min(9 * (4 + 4) * (root + 2) / 2, 99 * 10);
        const c8 = @min(9 * (8 + 4) * (root + 2) / 2, 99 * 19);
        return p.unstable.get(c4, c8);
    }
    pub fn ringLen(p: FramaParams) usize {
        return p.period;
    }
    pub fn lookback(p: FramaParams) usize {
        return p.period + unstableOf(p);
    }
    pub fn init(p: FramaParams) Error!FramaCore {
        try validate(p);
        const half = p.period / 2;
        return .{
            .p = p.period,
            .half = half,
            .lb = lookback(p),
            .hi1 = MaxCore.initAny(half),
            .lo1 = MinCore.initAny(half),
            .hi2 = MaxCore.initAny(half),
            .lo2 = MinCore.initAny(half),
        };
    }
    pub fn step(self: *FramaCore, h: anytype, x: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const hs = hist.field(h, .high);
        const ls = hist.field(h, .low);
        // Newest half window, and the half window that ended `half` bars ago.
        const a = self.hi1.step(hs, x.high);
        const b = self.lo1.step(ls, x.low);
        var c: ?f64 = null;
        var d: ?f64 = null;
        if (n >= self.half) {
            const old = h.at(n - self.half);
            c = self.hi2.step(hs, old.high);
            d = self.lo2.step(ls, old.low);
        }
        const price = (x.high + x.low) / 2.0;
        if (n + 1 == self.p) {
            self.prev = price;
            return null;
        }
        if (n < self.p) return null;
        const hi1 = a.?;
        const lo1 = b.?;
        const hi2 = c.?;
        const lo2 = d.?;
        const r1 = hi1 - lo1;
        const r2 = hi2 - lo2;
        const r = (if (hi1 > hi2) hi1 else hi2) - (if (lo1 < lo2) lo1 else lo2);
        if (r1 > 0.0 and r2 > 0.0 and r1 + r2 > r) {
            const alpha = @exp(frama_scale * @log((r1 + r2) / r));
            self.prev = @mulAdd(f64, 1.0 - alpha, self.prev, alpha * price);
        } else {
            self.prev = price;
        }
        return if (n >= self.lb) self.prev else null;
    }
};

pub fn framaLookback(p: FramaParams) Error!usize {
    try FramaCore.validate(p);
    return FramaCore.lookback(p);
}
pub fn frama(comptime T: type, high: []const T, low: []const T, out: []T, p: FramaParams) Error!usize {
    return hist.batch(T, FramaCore, .{ high, low }, .{out}, p, &.{});
}
pub fn FramaStream(comptime T: type) type {
    return hist.Stream(T, FramaParams, FramaCore);
}

// ── VWMA ────────────────────────────────────────────────────────────────────

pub const VwmaParams = struct { period: usize = 30 };

/// Volume-weighted moving average `sum(price*volume) / sum(volume)`; a window of
/// all-zero volume answers NaN (0/0), as TA-Lib's exact zero-window reset does.
pub const VwmaCore = struct {
    pub const In = hist.Cv(f64);
    pub const Out = f64;
    pub fn InOf(comptime T: type) type {
        return hist.Cv(T);
    }
    pub fn OutOf(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    sum_pv: f64 = 0.0,
    sum_v: f64 = 0.0,
    zeros: usize = 0,

    pub fn validate(p: VwmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: VwmaParams) usize {
        return if (p.period == 1) 0 else p.period;
    }
    pub fn lookback(p: VwmaParams) usize {
        return p.period - 1;
    }
    pub fn init(p: VwmaParams) Error!VwmaCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *VwmaCore, h: anytype, x: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (self.p == 1) return x.close;
        self.sum_pv += x.close * x.volume;
        self.sum_v += x.volume;
        if (@abs(x.volume) <= 0.0) self.zeros += 1;
        if (n + 1 < self.p) return null;
        const t = h.at(n + 1 - self.p);
        const tr = t.close * t.volume;
        const per = pf(self.p);
        var out: f64 = undefined;
        if (self.zeros >= self.p) {
            const zero: f64 = 0.0;
            self.sum_pv = 0.0 - tr;
            self.sum_v = 0.0 - t.volume;
            out = zero / per / (zero / per);
        } else {
            const pv = self.sum_pv;
            const v = self.sum_v;
            self.sum_pv -= tr;
            self.sum_v -= t.volume;
            out = pv / per / (v / per);
        }
        if (@abs(t.volume) <= 0.0) self.zeros -= 1;
        return out;
    }
};

pub fn vwmaLookback(p: VwmaParams) Error!usize {
    try VwmaCore.validate(p);
    return VwmaCore.lookback(p);
}
pub fn vwma(comptime T: type, in: []const T, volume: []const T, out: []T, p: VwmaParams) Error!usize {
    return hist.batch(T, VwmaCore, .{ in, volume }, .{out}, p, &.{});
}
pub fn VwmaStream(comptime T: type) type {
    return hist.Stream(T, VwmaParams, VwmaCore);
}

// ── MAVP ────────────────────────────────────────────────────────────────────

pub const MavpParams = struct {
    min_period: usize = 2,
    max_period: usize = 30,
    kind: MaType = .sma,
    unstable: Unstable = core.no_unstable,
    seed: core.Seed = .sma,
};

const mavp_max = 10000;

fn mavpMa(p: MavpParams, period: usize) smooth.MaParams {
    return .{ .period = period, .kind = p.kind, .unstable = p.unstable, .seed = p.seed };
}

fn mavpCheck(p: MavpParams) Error!void {
    if (p.min_period < 1 or p.min_period > mavp_max) return error.BadParam;
    if (p.max_period < 1 or p.max_period > mavp_max) return error.BadParam;
    if (p.min_period > p.max_period) return error.BadParam;
    try smooth.MaCore.validate(mavpMa(p, p.max_period));
}

pub fn mavpLookback(p: MavpParams) Error!usize {
    try mavpCheck(p);
    return smooth.MaCore.lookback(mavpMa(p, p.max_period));
}

/// TA-Lib's per-bar period: clamped to the parameter range, truncated, NaN
/// answers `min_period`.
fn mavpPeriod(p: MavpParams, v: f64) usize {
    if (!(v >= pf(p.min_period))) return p.min_period;
    if (v > pf(p.max_period)) return p.max_period;
    const t: usize = @intFromFloat(v);
    return @max(t, 1);
}

/// Moving average with a period per bar: bar `i >= lookback` gets the moving
/// average of period `periods[i]` (clamped to the parameter range) at bar `i`,
/// each period's average run as TA_MA runs it from the common first output bar.
/// No allocation (a 10001-entry table of last uses lives on the stack).
pub fn mavp(comptime T: type, in: []const T, periods: []const T, out: []T, p: MavpParams) Error!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{ periods.len, out.len });
    try mavpCheck(p);
    const lb = smooth.MaCore.lookback(mavpMa(p, p.max_period));
    const n = in.len;
    core.fillNan(T, out[0..@min(lb, n)]);
    if (lb >= n) return lb;
    var last: [mavp_max + 1]usize = undefined;
    var used: [mavp_max + 1]bool = @splat(false);
    var lo: usize = p.max_period;
    var hi: usize = 1;
    for (lb..n) |i| {
        const k = mavpPeriod(p, periods[i]);
        used[k] = true;
        last[k] = i;
        lo = @min(lo, k);
        hi = @max(hi, k);
    }
    for (lo..hi + 1) |k| {
        if (!used[k]) continue;
        const mp = mavpMa(p, k);
        const skip = lb - smooth.MaCore.lookback(mp);
        var c = try smooth.MaCore.init(mp);
        const src = core.SliceSrc(T){ .xs = in, .off = skip };
        var i = skip;
        while (i <= last[k]) : (i += 1) {
            const r = c.step(src, in[i]);
            if (i >= lb and mavpPeriod(p, periods[i]) == k) {
                out[i] = if (r) |v| core.to(T, v) else std.math.nan(T);
            }
        }
    }
    return lb;
}
