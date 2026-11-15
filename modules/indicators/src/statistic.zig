// SPDX-License-Identifier: MIT
//! Statistic functions ported from TA-Lib 0.8.3 (`ta_BETA.c`, `ta_CORREL.c`,
//! `ta_KURTOSIS.c`, `ta_LINEARREG*.c`, `ta_MEDIAN.c`, `ta_PERCENTILE.c`,
//! `ta_PERCENTRANK.c`, `ta_STDDEV.c`, `ta_TSF.c`, `ta_VAR.c`; BSD-3, see NOTICE).
//! The running-sum functions carry the C's shifted sums, re-anchor triggers and
//! floors operation for operation. MEDIAN and PERCENTILE keep a sorted copy of
//! the window (a caller scratch array: `batch*` allocates it from `gpa`, the
//! stream takes it in its buffer).

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const bands = @import("bands.zig");
const K = @import("vs_kit.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const pf = core.pf;
const VarCore = bands.VarCore;

const real_min = -3e37;
const real_max = 3e37;
/// TA_EPSILON
const eps: f64 = 0.00000000000001;

// ── VAR / STDDEV ────────────────────────────────────────────────────────────

pub const VarianceParams = struct {
    period: usize = 5,
    /// Validated (TA-Lib range) but without effect, as in TA_VAR.
    nbdev: f64 = 1.0,
};
pub const StddevParams = struct {
    period: usize = 5,
    nbdev: f64 = 1.0,
};

fn nbdevOk(d: f64) bool {
    return d >= real_min and d <= real_max;
}

/// Population variance of the window: the shifted running sums with re-anchor of `ta_VAR.c`.
pub const VarianceCore = struct {
    n: usize = 0,
    v: VarCore,
    pub fn validate(p: VarianceParams) Error!void {
        try core.checkPeriod(p.period, 1);
        if (!nbdevOk(p.nbdev)) return error.BadParam;
    }
    pub fn ringLen(p: VarianceParams) usize {
        return p.period;
    }
    pub fn lookback(p: VarianceParams) usize {
        return p.period - 1;
    }
    pub fn init(p: VarianceParams) Error!VarianceCore {
        try validate(p);
        return .{ .v = VarCore.init(p.period) };
    }
    pub fn step(self: *VarianceCore, src: anytype, x: f64) ?f64 {
        self.n += 1;
        return self.v.step(src, x);
    }
};
pub fn varianceLookback(p: VarianceParams) Error!usize {
    try VarianceCore.validate(p);
    return VarianceCore.lookback(p);
}
pub fn variance(comptime T: type, in: []const T, out: []T, p: VarianceParams) Error!usize {
    return smooth.batch1(T, VarianceCore, in, out, p);
}
pub fn VarianceStream(comptime T: type) type {
    return smooth.Stream1(T, VarianceParams, VarianceCore);
}

/// `sqrt(variance) * nbdev` (`sqrt(variance)` when nbdev is exactly 1).
pub const StddevCore = struct {
    n: usize = 0,
    v: VarCore,
    nbdev: f64,
    pub fn validate(p: StddevParams) Error!void {
        try core.checkPeriod(p.period, 2);
        if (!nbdevOk(p.nbdev)) return error.BadParam;
    }
    pub fn ringLen(p: StddevParams) usize {
        return p.period;
    }
    pub fn lookback(p: StddevParams) usize {
        return p.period - 1;
    }
    pub fn init(p: StddevParams) Error!StddevCore {
        try validate(p);
        return .{ .v = VarCore.init(p.period), .nbdev = p.nbdev };
    }
    pub fn step(self: *StddevCore, src: anytype, x: f64) ?f64 {
        self.n += 1;
        const vr = self.v.step(src, x) orelse return null;
        if (self.nbdev != 1.0) return @sqrt(vr) * self.nbdev;
        return @sqrt(vr);
    }
};
pub fn stddevLookback(p: StddevParams) Error!usize {
    try StddevCore.validate(p);
    return StddevCore.lookback(p);
}
pub fn stddev(comptime T: type, in: []const T, out: []T, p: StddevParams) Error!usize {
    return smooth.batch1(T, StddevCore, in, out, p);
}
pub fn StddevStream(comptime T: type) type {
    return smooth.Stream1(T, StddevParams, StddevCore);
}

// ── LINEARREG family ────────────────────────────────────────────────────────

pub const LinearregParams = struct { period: usize = 14 };

pub const LrMode = enum { value, slope, angle, intercept, forecast };

/// Least-squares line through the last `period` bars (x = 0 at the oldest):
/// `value` = b + m(p-1) (LINEARREG), `slope` = m, `angle` = atan(m) in degrees,
/// `intercept` = b, `forecast` = b + m*p (TSF). The two sums are slid in O(1)
/// and rebuilt from the window every 32 periods and whenever the departing
/// value outweighs the whole window's magnitude 100 times.
pub fn LrCore(comptime mode: LrMode) type {
    return struct {
        const Self = @This();
        n: usize = 0,
        p: usize,
        sum_x: f64,
        divisor: f64,
        sum_xy: f64 = 0.0,
        sum_y: f64 = 0.0,
        sum_abs: f64 = 0.0,
        trailing: f64 = 0.0,
        since: usize,

        pub fn validate(p: LinearregParams) Error!void {
            try core.checkPeriod(p.period, 2);
        }
        pub fn ringLen(p: LinearregParams) usize {
            return p.period;
        }
        pub fn lookback(p: LinearregParams) usize {
            return p.period - 1;
        }
        pub fn init(p: LinearregParams) Error!Self {
            try validate(p);
            const pp = pf(p.period);
            const sum_x = pp * pf(p.period - 1) * 0.5;
            const sum_xsqr = pp * pf(p.period - 1) * pf(2 * p.period - 1) / 6.0;
            return .{ .p = p.period, .sum_x = sum_x, .divisor = sum_x * sum_x - pp * sum_xsqr, .since = 32 * p.period };
        }
        fn result(self: *const Self) f64 {
            const pp = pf(self.p);
            const m = (pp * self.sum_xy - self.sum_x * self.sum_y) / self.divisor;
            switch (mode) {
                .slope => return m,
                .angle => return std.math.atan(m) * (@as(f64, 180.0) / @as(f64, 3.141592653589793)),
                else => {},
            }
            const b = (self.sum_y - m * self.sum_x) / pp;
            return switch (mode) {
                .intercept => b,
                .value => @mulAdd(f64, m, pf(self.p - 1), b),
                .forecast => @mulAdd(f64, m, pp, b),
                else => unreachable,
            };
        }
        pub fn step(self: *Self, src: anytype, x: f64) ?f64 {
            const n = self.n;
            self.n += 1;
            if (n + 1 < self.p) return null;
            if (n + 1 == self.p) {
                var i: usize = self.p;
                while (i > 0) {
                    i -= 1;
                    const v = src.at(n - i);
                    self.sum_y += v;
                    self.sum_xy += pf(i) * v;
                    self.sum_abs += @abs(v);
                }
                self.since = 32 * self.p;
            } else {
                const weighted = pf(self.p) * self.trailing;
                self.sum_xy = self.sum_xy + self.sum_y - weighted;
                self.sum_y = self.sum_y - self.trailing + x;
                self.sum_abs = self.sum_abs - @abs(self.trailing) + @abs(x);
                self.since -= 1;
                if (self.since == 0 or @abs(weighted) > 100.0 * self.sum_abs) {
                    self.since = 32 * self.p;
                    self.sum_y = 0.0;
                    self.sum_xy = 0.0;
                    self.sum_abs = 0.0;
                    var w = pf(self.p - 1);
                    var j = n + 1 - self.p;
                    while (j <= n) : (j += 1) {
                        const v = src.at(j);
                        self.sum_y += v;
                        self.sum_xy += w * v;
                        self.sum_abs += @abs(v);
                        w -= 1.0;
                    }
                }
            }
            const out = self.result();
            self.trailing = src.at(n + 1 - self.p);
            return out;
        }
    };
}
pub const LinearregCore = LrCore(.value);
pub const LinearregSlopeCore = LrCore(.slope);
pub const LinearregAngleCore = LrCore(.angle);
pub const LinearregInterceptCore = LrCore(.intercept);
pub const TsfCore = LrCore(.forecast);

pub fn linearregLookback(p: LinearregParams) Error!usize {
    try LinearregCore.validate(p);
    return LinearregCore.lookback(p);
}
pub fn linearreg(comptime T: type, in: []const T, out: []T, p: LinearregParams) Error!usize {
    return smooth.batch1(T, LinearregCore, in, out, p);
}
pub fn LinearregStream(comptime T: type) type {
    return smooth.Stream1(T, LinearregParams, LinearregCore);
}
pub fn linearregSlopeLookback(p: LinearregParams) Error!usize {
    try LinearregSlopeCore.validate(p);
    return LinearregSlopeCore.lookback(p);
}
pub fn linearregSlope(comptime T: type, in: []const T, out: []T, p: LinearregParams) Error!usize {
    return smooth.batch1(T, LinearregSlopeCore, in, out, p);
}
pub fn LinearregSlopeStream(comptime T: type) type {
    return smooth.Stream1(T, LinearregParams, LinearregSlopeCore);
}
pub fn linearregAngleLookback(p: LinearregParams) Error!usize {
    try LinearregAngleCore.validate(p);
    return LinearregAngleCore.lookback(p);
}
pub fn linearregAngle(comptime T: type, in: []const T, out: []T, p: LinearregParams) Error!usize {
    return smooth.batch1(T, LinearregAngleCore, in, out, p);
}
pub fn LinearregAngleStream(comptime T: type) type {
    return smooth.Stream1(T, LinearregParams, LinearregAngleCore);
}
pub fn linearregInterceptLookback(p: LinearregParams) Error!usize {
    try LinearregInterceptCore.validate(p);
    return LinearregInterceptCore.lookback(p);
}
pub fn linearregIntercept(comptime T: type, in: []const T, out: []T, p: LinearregParams) Error!usize {
    return smooth.batch1(T, LinearregInterceptCore, in, out, p);
}
pub fn LinearregInterceptStream(comptime T: type) type {
    return smooth.Stream1(T, LinearregParams, LinearregInterceptCore);
}
pub fn tsfLookback(p: LinearregParams) Error!usize {
    try TsfCore.validate(p);
    return TsfCore.lookback(p);
}
pub fn tsf(comptime T: type, in: []const T, out: []T, p: LinearregParams) Error!usize {
    return smooth.batch1(T, TsfCore, in, out, p);
}
pub fn TsfStream(comptime T: type) type {
    return smooth.Stream1(T, LinearregParams, TsfCore);
}

// ── PERCENTRANK ─────────────────────────────────────────────────────────────

pub const PercentrankParams = struct { period: usize = 100 };

/// Share (percent) of the previous `period` bars strictly below the current
/// bar: `count / period * 100`.
pub const PercentrankCore = struct {
    n: usize = 0,
    p: usize,
    pub fn validate(p: PercentrankParams) Error!void {
        if (p.period < 2 or p.period > 10000) return error.BadParam;
    }
    pub fn ringLen(p: PercentrankParams) usize {
        return p.period + 1;
    }
    pub fn lookback(p: PercentrankParams) usize {
        return p.period;
    }
    pub fn init(p: PercentrankParams) Error!PercentrankCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *PercentrankCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n < self.p) return null;
        var count: usize = 0;
        var j = n - self.p;
        while (j < n) : (j += 1) {
            if (src.at(j) < x) count += 1;
        }
        return pf(count) / pf(self.p) * 100.0;
    }
};
pub fn percentrankLookback(p: PercentrankParams) Error!usize {
    try PercentrankCore.validate(p);
    return PercentrankCore.lookback(p);
}
pub fn percentrank(comptime T: type, in: []const T, out: []T, p: PercentrankParams) Error!usize {
    return smooth.batch1(T, PercentrankCore, in, out, p);
}
pub fn PercentrankStream(comptime T: type) type {
    return smooth.Stream1(T, PercentrankParams, PercentrankCore);
}

// ── KURTOSIS ────────────────────────────────────────────────────────────────

pub const KurtosisParams = struct { period: usize = 30 };

/// Sample-adjusted Fisher excess kurtosis (G2) of the window from shifted
/// power sums; a flat window answers NaN (0/0), as in the C.
pub const KurtosisCore = struct {
    n: usize = 0,
    p: usize,
    d_period: f64,
    coef_a: f64,
    coef_b: f64,
    inv: f64,
    shift: f64 = 0.0,
    t1: f64 = 0.0,
    t2: f64 = 0.0,
    t3: f64 = 0.0,
    t4: f64 = 0.0,
    peak2: f64 = 0.0,
    peak4: f64 = 0.0,
    since: usize,

    const Mom = struct { residue: f64, m2: f64, m4: f64 };

    pub fn validate(p: KurtosisParams) Error!void {
        if (p.period < 4 or p.period > 10000) return error.BadParam;
    }
    pub fn ringLen(p: KurtosisParams) usize {
        return p.period;
    }
    pub fn lookback(p: KurtosisParams) usize {
        return p.period - 1;
    }
    pub fn init(p: KurtosisParams) Error!KurtosisCore {
        try validate(p);
        const d = pf(p.period);
        return .{
            .p = p.period,
            .d_period = d,
            .coef_a = d * (d + 1.0) / ((d - 1.0) * (d - 2.0) * (d - 3.0)),
            .coef_b = 3.0 * (d - 1.0) * (d - 1.0) / ((d - 2.0) * (d - 3.0)),
            .inv = 1.0 / d,
            .since = 32 * p.period,
        };
    }
    fn add(self: *KurtosisCore, x: f64) void {
        const dev = x - self.shift;
        const dev2 = dev * dev;
        self.t1 += dev;
        self.t2 += dev2;
        self.t3 += dev2 * dev;
        self.t4 += dev2 * dev2;
    }
    fn moments(self: *const KurtosisCore) Mom {
        const residue = self.t1 * self.inv;
        const rs = residue * residue;
        const m2 = self.t2 - self.d_period * rs;
        const m4 = @mulAdd(f64, 6.0 * rs, self.t2, self.t4 - 4.0 * residue * self.t3) - 3.0 * self.d_period * rs * rs;
        return .{ .residue = residue, .m2 = m2, .m4 = m4 };
    }
    fn rebuild(self: *KurtosisCore, src: anytype, ws: usize, n: usize) void {
        self.t1 = 0.0;
        self.t2 = 0.0;
        self.t3 = 0.0;
        self.t4 = 0.0;
        var j = ws;
        while (j <= n) : (j += 1) self.add(src.at(j));
    }
    pub fn step(self: *KurtosisCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) self.shift = x;
        if (n + 1 < self.p) {
            self.add(x);
            return null;
        }
        if (n + 1 == self.p) {
            self.peak2 = self.t2;
            self.peak4 = self.t4;
        }
        self.add(x);
        if (self.t2 > self.peak2) self.peak2 = self.t2;
        if (self.t4 > self.peak4) self.peak4 = self.t4;
        var m = self.moments();
        self.since -= 1;
        if (m.m2 < 0.01 * self.peak2 or m.m4 < 0.01 * self.peak4 or self.since == 0) {
            self.since = 32 * self.p;
            const ws = n + 1 - self.p;
            var tmp: f64 = 0.0;
            var j = ws;
            while (j <= n) : (j += 1) tmp += src.at(j);
            self.shift = tmp * self.inv;
            self.rebuild(src, ws, n);
            m = self.moments();
            if (m.m2 < 0.01 * self.t2 or m.m4 < 0.01 * self.t4) {
                self.shift += m.residue;
                self.rebuild(src, ws, n);
                m = self.moments();
            }
            self.peak2 = self.t2;
            self.peak4 = self.t4;
        }
        const sample_var = m.m2 / (self.d_period - 1.0);
        const var_sq = sample_var * sample_var;
        const kurt = self.coef_a * (m.m4 / var_sq) - self.coef_b;
        const dev = src.at(n + 1 - self.p) - self.shift;
        const dev2 = dev * dev;
        self.t1 -= dev;
        self.t2 -= dev2;
        self.t3 -= dev2 * dev;
        self.t4 -= dev2 * dev2;
        return kurt;
    }
};
pub fn kurtosisLookback(p: KurtosisParams) Error!usize {
    try KurtosisCore.validate(p);
    return KurtosisCore.lookback(p);
}
pub fn kurtosis(comptime T: type, in: []const T, out: []T, p: KurtosisParams) Error!usize {
    return smooth.batch1(T, KurtosisCore, in, out, p);
}
pub fn KurtosisStream(comptime T: type) type {
    return smooth.Stream1(T, KurtosisParams, KurtosisCore);
}

// ── CORREL ──────────────────────────────────────────────────────────────────

pub const CorrelParams = struct { period: usize = 30 };

/// Pearson correlation of the last `period` bars of two series, from sums
/// shifted near the window (re-anchored when either sum of squares falls below
/// 1e-6 of its peak, and every 32 windows); clamped to [-1, 1], 0 when a side
/// has no spread.
pub const CorrelCore = struct {
    pub const In = K.Xy(f64);
    pub const Out = f64;
    pub const Params = CorrelParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Xy(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    inv: f64,
    shift_x: f64 = 0.0,
    shift_y: f64 = 0.0,
    sx: f64 = 0.0,
    sy: f64 = 0.0,
    sxx: f64 = 0.0,
    syy: f64 = 0.0,
    sxy: f64 = 0.0,
    peak_x: f64 = 0.0,
    peak_y: f64 = 0.0,
    since: usize,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params) Error!CorrelCore {
        try validate(p);
        return .{ .p = p.period, .inv = 1.0 / pf(p.period), .since = 32 * p.period };
    }
    fn add(self: *CorrelCore, bx: f64, by: f64) void {
        const x = bx - self.shift_x;
        self.sx += x;
        self.sxx += x * x;
        const y = by - self.shift_y;
        self.sxy += x * y;
        self.sy += y;
        self.syy += y * y;
    }
    fn zero(self: *CorrelCore) void {
        self.sx = 0.0;
        self.sxx = 0.0;
        self.sy = 0.0;
        self.syy = 0.0;
        self.sxy = 0.0;
    }
    pub fn step(self: *CorrelCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.shift_x = b.x;
            self.shift_y = b.y;
        }
        if (n + 1 < self.p) {
            self.add(b.x, b.y);
            return null;
        }
        if (n + 1 == self.p) {
            self.peak_x = self.sxx;
            self.peak_y = self.syy;
        }
        self.add(b.x, b.y);
        if (self.sxx > self.peak_x) self.peak_x = self.sxx;
        if (self.syy > self.peak_y) self.peak_y = self.syy;
        var ss_x = self.sxx - self.sx * self.sx * self.inv;
        var ss_y = self.syy - self.sy * self.sy * self.inv;
        var sp = self.sxy - self.sx * self.sy * self.inv;
        self.since -= 1;
        if (ss_x < 0.000001 * self.peak_x or ss_y < 0.000001 * self.peak_y or self.since == 0) {
            self.since = 32 * self.p;
            const ws = n + 1 - self.p;
            var tx: f64 = 0.0;
            var ty: f64 = 0.0;
            var j = ws;
            while (j <= n) : (j += 1) {
                const o = src.at(j);
                tx += o.x;
                ty += o.y;
            }
            self.shift_x = tx * self.inv;
            self.shift_y = ty * self.inv;
            self.zero();
            j = ws;
            while (j <= n) : (j += 1) {
                const o = src.at(j);
                self.add(o.x, o.y);
            }
            ss_x = self.sxx - self.sx * self.sx * self.inv;
            ss_y = self.syy - self.sy * self.sy * self.inv;
            sp = self.sxy - self.sx * self.sy * self.inv;
            if (ss_x < 0.000001 * self.sxx or ss_y < 0.000001 * self.syy) {
                if (ss_x < 0.000001 * self.sxx) self.shift_x = b.x;
                if (ss_y < 0.000001 * self.syy) self.shift_y = b.y;
                self.zero();
                j = ws;
                while (j <= n) : (j += 1) {
                    const o = src.at(j);
                    self.add(o.x, o.y);
                }
                ss_x = self.sxx - self.sx * self.sx * self.inv;
                ss_y = self.syy - self.sy * self.sy * self.inv;
                sp = self.sxy - self.sx * self.sy * self.inv;
            }
            self.peak_x = self.sxx;
            self.peak_y = self.syy;
            if (ss_x < 0.0) ss_x = 0.0;
            if (ss_y < 0.0) ss_y = 0.0;
        }
        const o = src.at(n + 1 - self.p);
        const trail_x = o.x - self.shift_x;
        const trail_y = o.y - self.shift_y;
        var out: f64 = 0.0;
        if (ss_x > eps * self.sxx and ss_y > eps * self.syy and ss_x * ss_y > 0.0) {
            var t = sp / @sqrt(ss_x * ss_y);
            if (t > 1.0) {
                t = 1.0;
            } else if (t < -1.0) {
                t = -1.0;
            }
            out = t;
        }
        self.sx -= trail_x;
        self.sxx -= trail_x * trail_x;
        self.sxy -= trail_x * trail_y;
        self.sy -= trail_y;
        self.syy -= trail_y * trail_y;
        return out;
    }
};
pub fn correlLookback(p: CorrelParams) Error!usize {
    try CorrelCore.validate(p);
    return CorrelCore.lookback(p);
}
pub fn correl(comptime T: type, x: []const T, y: []const T, out: []T, p: CorrelParams) Error!usize {
    return K.batch(T, CorrelCore, p, .{ .x = x, .y = y }, .{out});
}
pub fn CorrelStream(comptime T: type) type {
    return K.Stream(T, CorrelCore);
}

// ── BETA ────────────────────────────────────────────────────────────────────

pub const BetaParams = struct { period: usize = 5 };

/// Beta of series `y` (the security) against `x` (the market): the slope of
/// the regression of the `period` one-bar returns of `y` on those of `x`,
/// from sums of returns shifted near the window (re-anchored on cancellation,
/// on an outlier leaving the window, and every 32 windows). A return from a
/// zero price is 0 (`-shift`).
pub const BetaCore = struct {
    pub const In = K.Xy(f64);
    pub const Out = f64;
    pub const Params = BetaParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Xy(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    nn: f64,
    sxx: f64 = 0.0,
    sxy: f64 = 0.0,
    sx: f64 = 0.0,
    sy: f64 = 0.0,
    syy: f64 = 0.0,
    last_x: f64 = 0.0,
    last_y: f64 = 0.0,
    tlast_x: f64 = 0.0,
    tlast_y: f64 = 0.0,
    shift_x: f64 = 0.0,
    shift_y: f64 = 0.0,
    leaving_xx: f64 = 0.0,
    leaving_yy: f64 = 0.0,
    since: usize,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!BetaCore {
        try validate(p);
        return .{ .p = p.period, .nn = pf(p.period), .since = 32 * p.period };
    }
    fn ret(price: f64, last: f64, shift: f64) f64 {
        if (last != 0.0) return (price - last) / last - shift;
        return -shift;
    }
    fn addRet(self: *BetaCore, x: f64, y: f64) void {
        self.sxx += x * x;
        self.syy += y * y;
        self.sxy += x * y;
        self.sx += x;
        self.sy += y;
    }
    pub fn step(self: *BetaCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.tlast_x = b.x;
            self.last_x = b.x;
            self.tlast_y = b.y;
            self.last_y = b.y;
            return null;
        }
        if (n == 1) {
            if (self.last_x != 0.0) self.shift_x = (b.x - self.last_x) / self.last_x;
            if (self.last_y != 0.0) self.shift_y = (b.y - self.last_y) / self.last_y;
        }
        const x = ret(b.x, self.last_x, self.shift_x);
        self.last_x = b.x;
        const y = ret(b.y, self.last_y, self.shift_y);
        self.last_y = b.y;
        self.addRet(x, y);
        if (n < self.p) return null;
        var denom_scale = self.nn * self.sxx;
        var denom = denom_scale - self.sx * self.sx;
        self.since -= 1;
        const ws = n + 1 - self.p;
        if (denom < 0.000001 * denom_scale or self.leaving_xx > 1000.0 * self.sxx or self.leaving_yy > 1000.0 * self.syy or self.since == 0) {
            self.since = 32 * self.p;
            var prev_x = self.tlast_x;
            var prev_y = self.tlast_y;
            var tmp: f64 = 0.0;
            var sy_shift: f64 = 0.0;
            var j = ws;
            while (j <= n) : (j += 1) {
                const o = src.at(j);
                if (prev_x != 0.0) tmp += (o.x - prev_x) / prev_x;
                prev_x = o.x;
                if (prev_y != 0.0) sy_shift += (o.y - prev_y) / prev_y;
                prev_y = o.y;
            }
            self.shift_x = tmp / self.nn;
            self.shift_y = sy_shift / self.nn;
            prev_x = self.tlast_x;
            prev_y = self.tlast_y;
            self.sxx = 0.0;
            self.syy = 0.0;
            self.sxy = 0.0;
            self.sx = 0.0;
            self.sy = 0.0;
            j = ws;
            while (j <= n) : (j += 1) {
                const o = src.at(j);
                const rx = ret(o.x, prev_x, self.shift_x);
                prev_x = o.x;
                const ry = ret(o.y, prev_y, self.shift_y);
                prev_y = o.y;
                self.addRet(rx, ry);
            }
            denom_scale = self.nn * self.sxx;
            denom = denom_scale - self.sx * self.sx;
            if (denom < 0.0) denom = 0.0;
        }
        const o = src.at(ws);
        const tx = ret(o.x, self.tlast_x, self.shift_x);
        self.tlast_x = o.x;
        const ty = ret(o.y, self.tlast_y, self.shift_y);
        self.tlast_y = o.y;
        var out: f64 = 0.0;
        if (denom > eps * denom_scale) out = (self.nn * self.sxy - self.sx * self.sy) / denom;
        self.leaving_xx = tx * tx;
        self.leaving_yy = ty * ty;
        self.sxx -= tx * tx;
        self.syy -= ty * ty;
        self.sxy -= tx * ty;
        self.sx -= tx;
        self.sy -= ty;
        return out;
    }
};
pub fn betaLookback(p: BetaParams) Error!usize {
    try BetaCore.validate(p);
    return BetaCore.lookback(p);
}
pub fn beta(comptime T: type, x: []const T, y: []const T, out: []T, p: BetaParams) Error!usize {
    return K.batch(T, BetaCore, p, .{ .x = x, .y = y }, .{out});
}
pub fn BetaStream(comptime T: type) type {
    return K.Stream(T, BetaCore);
}

// ── MEDIAN / PERCENTILE ─────────────────────────────────────────────────────

/// Number of elements of the sorted `s` that are `<= x` (`x` goes after its equals).
fn upperBound(s: []const f64, x: f64) usize {
    var lo: usize = 0;
    var hi: usize = s.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (s[mid] <= x) lo = mid + 1 else hi = mid;
    }
    return lo;
}
/// Index of the first element of the sorted `s` that is `>= x`.
fn lowerBound(s: []const f64, x: f64) usize {
    var lo: usize = 0;
    var hi: usize = s.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (s[mid] < x) lo = mid + 1 else hi = mid;
    }
    return lo;
}
/// Insert `x` into the sorted prefix `s[0..len]` (after its equals).
fn sortedInsert(s: []f64, len: usize, x: f64) void {
    var j = upperBound(s[0..len], x);
    const pos = j;
    j = len;
    while (j > pos) : (j -= 1) s[j] = s[j - 1];
    s[pos] = x;
}
/// Replace `old` (the first of its run of equals, i.e. the oldest) by `new`
/// (after the equals of `new`) in the sorted `s` with one shift.
fn sortedReplace(s: []f64, old: f64, new: f64) void {
    const pos = upperBound(s, new);
    var j = lowerBound(s, old);
    if (j < pos) {
        while (j + 1 < pos) : (j += 1) s[j] = s[j + 1];
        s[pos - 1] = new;
    } else {
        while (j > pos) : (j -= 1) s[j] = s[j - 1];
        s[pos] = new;
    }
}

pub const MedianParams = struct { period: usize = 30 };

/// Rolling median: the window is carried twice, by age (the input ring) and by
/// value (`sorted`, equal values in age order, so a zero keeps its sign). An
/// even window averages the two central values. NaN inputs are not ordered
/// consistently (TA-Lib's behaviour there is unspecified too).
pub const MedianCore = struct {
    pub const In = K.X(f64);
    pub const Out = f64;
    pub const Params = MedianParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    sorted: []f64,

    pub fn validate(p: Params) Error!void {
        if (p.period < 2 or p.period > 10000) return error.BadParam;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn scratchLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params, scratch: []f64) Error!MedianCore {
        try validate(p);
        if (scratch.len < p.period) return error.BadParam;
        return .{ .p = p.period, .sorted = scratch[0..p.period] };
    }
    fn compute(self: *const MedianCore, x: f64) f64 {
        const retained = self.sorted[0 .. self.p - 1];
        const pos = upperBound(retained, x);
        const lo_idx = (self.p - 1) / 2;
        const hi_idx = self.p / 2;
        const lower = if (lo_idx < pos) retained[lo_idx] else if (lo_idx == pos) x else retained[lo_idx - 1];
        const upper = if (hi_idx < pos) retained[hi_idx] else if (hi_idx == pos) x else retained[hi_idx - 1];
        if (lo_idx == hi_idx) return lower;
        return (lower + upper) / 2.0;
    }
    pub fn peekStep(self: *const MedianCore, _: anytype, b: In) ?f64 {
        if (self.n + 1 < self.p) return null;
        return self.compute(b.x);
    }
    pub fn step(self: *MedianCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) {
            sortedInsert(self.sorted, n, b.x);
            return null;
        }
        const out = self.compute(b.x);
        sortedReplace(self.sorted[0 .. self.p - 1], src.at(n + 1 - self.p).x, b.x);
        return out;
    }
};
pub fn medianLookback(p: MedianParams) Error!usize {
    try MedianCore.validate(p);
    return MedianCore.lookback(p);
}
pub fn median(comptime T: type, gpa: std.mem.Allocator, in: []const T, out: []T, p: MedianParams) core.AllocError!usize {
    return K.batchScratch(T, MedianCore, gpa, p, .{ .x = in }, .{out});
}
pub fn MedianStream(comptime T: type) type {
    return K.SingleStream(T, MedianCore);
}

pub const PercentileParams = struct {
    period: usize = 100,
    /// 0 .. 100 (nearest rank: the `ceil(percentile * period / 100)`-th smallest of the window).
    percentile: f64 = 50.0,
};

pub const PercentileCore = struct {
    pub const In = K.X(f64);
    pub const Out = f64;
    pub const Params = PercentileParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    rank: usize,
    sorted: []f64,

    pub fn validate(p: Params) Error!void {
        if (p.period < 2 or p.period > 10000) return error.BadParam;
        if (!(p.percentile >= 0.0 and p.percentile <= 100.0)) return error.BadParam;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn scratchLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params, scratch: []f64) Error!PercentileCore {
        try validate(p);
        if (scratch.len < p.period) return error.BadParam;
        // the multiply stays left of the divide: (P*n)/100
        const r: usize = @intFromFloat(@ceil(p.percentile * pf(p.period) / 100.0));
        return .{ .p = p.period, .rank = std.math.clamp(r, 1, p.period), .sorted = scratch[0..p.period] };
    }
    fn compute(self: *const PercentileCore, x: f64) f64 {
        const retained = self.sorted[0 .. self.p - 1];
        const pos = upperBound(retained, x);
        const k = self.rank - 1;
        if (k < pos) return retained[k];
        if (k == pos) return x;
        return retained[k - 1];
    }
    pub fn peekStep(self: *const PercentileCore, _: anytype, b: In) ?f64 {
        if (self.n + 1 < self.p) return null;
        return self.compute(b.x);
    }
    pub fn step(self: *PercentileCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) {
            sortedInsert(self.sorted, n, b.x);
            return null;
        }
        const out = self.compute(b.x);
        sortedReplace(self.sorted[0 .. self.p - 1], src.at(n + 1 - self.p).x, b.x);
        return out;
    }
};
pub fn percentileLookback(p: PercentileParams) Error!usize {
    try PercentileCore.validate(p);
    return PercentileCore.lookback(p);
}
pub fn percentile(comptime T: type, gpa: std.mem.Allocator, in: []const T, out: []T, p: PercentileParams) core.AllocError!usize {
    return K.batchScratch(T, PercentileCore, gpa, p, .{ .x = in }, .{out});
}
pub fn PercentileStream(comptime T: type) type {
    return K.SingleStream(T, PercentileCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "var, stddev: hand-checked" {
    var out: [3]f64 = undefined;
    // window (1,3): population variance 1; (3,2): 0.25
    _ = try variance(f64, &.{ 1, 3, 2 }, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 1), out[1]);
    try testing.expectEqual(@as(f64, 0.25), out[2]);
    _ = try stddev(f64, &.{ 1, 3, 2 }, &out, .{ .period = 2, .nbdev = 2 });
    try testing.expectEqual(@as(f64, 2), out[1]);
    try testing.expectEqual(@as(f64, 1), out[2]);
    // VAR at period 1 is 0
    _ = try variance(f64, &.{ 4, 7, 9 }, &out, .{ .period = 1 });
    try testing.expectEqualSlices(f64, &.{ 0, 0, 0 }, &out);
}

test "linear regression family on an exact line" {
    // y = 2i + 1, period 5: at bar n the window starts at i0 = n-4: b = 2*i0+1, m = 2.
    var ys: [10]f64 = undefined;
    for (&ys, 0..) |*y, i| y.* = 2.0 * @as(f64, @floatFromInt(i)) + 1.0;
    var out: [10]f64 = undefined;
    try testing.expectEqual(@as(usize, 4), try linearreg(f64, &ys, &out, .{ .period = 5 }));
    try testing.expectApproxEqAbs(@as(f64, 2 * 7 + 1), out[7], 1e-9);
    _ = try linearregSlope(f64, &ys, &out, .{ .period = 5 });
    try testing.expectApproxEqAbs(@as(f64, 2), out[7], 1e-12);
    _ = try linearregIntercept(f64, &ys, &out, .{ .period = 5 });
    try testing.expectApproxEqAbs(@as(f64, 2 * 3 + 1), out[7], 1e-9);
    _ = try tsf(f64, &ys, &out, .{ .period = 5 });
    try testing.expectApproxEqAbs(@as(f64, 2 * 8 + 1), out[7], 1e-9);
    _ = try linearregAngle(f64, &ys, &out, .{ .period = 5 });
    try testing.expectApproxEqAbs(std.math.atan(@as(f64, 2)) * 180.0 / std.math.pi, out[7], 1e-9);
}

test "median, percentile, percentrank: hand-checked" {
    const gpa = testing.allocator;
    var out: [5]f64 = undefined;
    // period 3 over 5 1 4 2 8: (1,4,5) -> 4, (1,2,4) -> 2, (2,4,8) -> 4
    _ = try median(f64, gpa, &.{ 5, 1, 4, 2, 8 }, &out, .{ .period = 3 });
    try testing.expectEqualSlices(f64, &.{ 4, 2, 4 }, out[2..]);
    // period 4: sorted (1,2,4,5) -> (2+4)/2 = 3
    _ = try median(f64, gpa, &.{ 5, 1, 4, 2, 8 }, &out, .{ .period = 4 });
    try testing.expectEqual(@as(f64, 3), out[3]);
    // percentile period 4 over 5 1 4 2: sorted 1 2 4 5: 50 -> rank 2 -> 2, 100 -> 5, 0 -> 1, 75 -> rank 3 -> 4
    _ = try percentile(f64, gpa, &.{ 5, 1, 4, 2, 8 }, &out, .{ .period = 4, .percentile = 50 });
    try testing.expectEqual(@as(f64, 2), out[3]);
    _ = try percentile(f64, gpa, &.{ 5, 1, 4, 2, 8 }, &out, .{ .period = 4, .percentile = 100 });
    try testing.expectEqual(@as(f64, 5), out[3]);
    _ = try percentile(f64, gpa, &.{ 5, 1, 4, 2, 8 }, &out, .{ .period = 4, .percentile = 0 });
    try testing.expectEqual(@as(f64, 1), out[3]);
    _ = try percentile(f64, gpa, &.{ 5, 1, 4, 2, 8 }, &out, .{ .period = 4, .percentile = 75 });
    try testing.expectEqual(@as(f64, 4), out[3]);
    // percentrank period 3: bar 3 value 4 over (1,2,3): 3/3*100; bar 4 value 0 over (2,3,4): 0.
    _ = try percentrank(f64, &.{ 1, 2, 3, 4, 0 }, &out, .{ .period = 3 });
    try testing.expectEqual(@as(f64, 100), out[3]);
    try testing.expectEqual(@as(f64, 0), out[4]);
}

test "median keeps the sign of a zero (equal values stay in age order)" {
    const gpa = testing.allocator;
    var out: [5]f64 = undefined;
    const nz = -0.0;
    // period 3 over +0 -0 +0 -0 +0: all medians are the middle of three equal zeros: the age-ordered middle.
    _ = try median(f64, gpa, &.{ 0.0, nz, 0.0, nz, 0.0 }, &out, .{ .period = 3 });
    // window (+0,-0,+0): sorted in age order -> middle is -0; window (-0,+0,-0) -> +0; (+0,-0,+0) -> -0
    try testing.expect(std.math.signbit(out[2]));
    try testing.expect(!std.math.signbit(out[3]));
    try testing.expect(std.math.signbit(out[4]));
}

test "kurtosis and correl, beta: closed forms" {
    var out: [8]f64 = undefined;
    // uniform 1,2,3,4: G2 = -1.2
    try testing.expectEqual(@as(usize, 3), try kurtosis(f64, &.{ 1, 2, 3, 4, 3, 2, 1, 2 }, &out, .{ .period = 4 }));
    try testing.expectApproxEqAbs(@as(f64, -1.2), out[3], 1e-12);
    // y = 2x + 1 correlates perfectly, anti-correlated with -x
    const xs = [_]f64{ 1, 3, 2, 5, 4, 6, 8, 7 };
    var ys: [8]f64 = undefined;
    var ns: [8]f64 = undefined;
    for (xs, &ys, &ns) |x, *y, *m| {
        y.* = 2 * x + 1;
        m.* = -x;
    }
    try testing.expectEqual(@as(usize, 3), try correl(f64, &xs, &ys, &out, .{ .period = 4 }));
    try testing.expectApproxEqAbs(@as(f64, 1), out[5], 1e-12);
    _ = try correl(f64, &xs, &ns, &out, .{ .period = 4 });
    try testing.expectApproxEqAbs(@as(f64, -1), out[5], 1e-12);
    // beta of a series against itself is 1
    try testing.expectEqual(@as(usize, 4), try beta(f64, &xs, &xs, &out, .{ .period = 4 }));
    try testing.expectApproxEqAbs(@as(f64, 1), out[6], 1e-9);
}

test "statistic: BadParam edges" {
    const gpa = testing.allocator;
    var out: [8]f64 = undefined;
    const z = [_]f64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try testing.expectError(error.BadParam, variance(f64, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, variance(f64, &z, &out, .{ .nbdev = 4e37 }));
    try testing.expectError(error.BadParam, stddev(f64, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, linearreg(f64, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, tsf(f64, &z, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, percentrank(f64, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, percentrank(f64, &z, &out, .{ .period = 10001 }));
    try testing.expectError(error.BadParam, kurtosis(f64, &z, &out, .{ .period = 3 }));
    try testing.expectError(error.BadParam, kurtosis(f64, &z, &out, .{ .period = 10001 }));
    try testing.expectError(error.BadParam, correl(f64, &z, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, beta(f64, &z, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, beta(f64, &z, z[0..7], &out, .{}));
    try testing.expectError(error.BadParam, median(f64, gpa, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, median(f64, gpa, &z, &out, .{ .period = 10001 }));
    try testing.expectError(error.BadParam, percentile(f64, gpa, &z, &out, .{ .percentile = 101 }));
    try testing.expectError(error.BadParam, percentile(f64, gpa, &z, &out, .{ .percentile = -1 }));
    try testing.expectEqual(@as(usize, 5), try betaLookback(.{}));
    try testing.expectEqual(@as(usize, 29), try correlLookback(.{}));
    try testing.expectEqual(@as(usize, 100), try percentrankLookback(.{}));
    try testing.expectEqual(@as(usize, 99), try percentileLookback(.{}));
    try testing.expectEqual(@as(usize, 13), try tsfLookback(.{}));
}

test "statistic: batch == streaming, lookback == leading NaN" {
    var xs: [400]f64 = undefined;
    var ys: [400]f64 = undefined;
    th.walk(&xs, 31);
    th.walk(&ys, 32);
    inline for (.{ 2, 5, 14, 60 }) |per| {
        try th.checkOne(VarianceParams, VarianceStream, variance, varianceLookback, &xs, .{ .period = per });
        try th.checkOne(StddevParams, StddevStream, stddev, stddevLookback, &xs, .{ .period = per, .nbdev = 2 });
        try th.checkOne(LinearregParams, LinearregStream, linearreg, linearregLookback, &xs, .{ .period = per });
        try th.checkOne(LinearregParams, LinearregSlopeStream, linearregSlope, linearregSlopeLookback, &xs, .{ .period = per });
        try th.checkOne(LinearregParams, LinearregAngleStream, linearregAngle, linearregAngleLookback, &xs, .{ .period = per });
        try th.checkOne(LinearregParams, LinearregInterceptStream, linearregIntercept, linearregInterceptLookback, &xs, .{ .period = per });
        try th.checkOne(LinearregParams, TsfStream, tsf, tsfLookback, &xs, .{ .period = per });
        try th.checkOne(PercentrankParams, PercentrankStream, percentrank, percentrankLookback, &xs, .{ .period = per });
        try th.checkOne(KurtosisParams, KurtosisStream, kurtosis, kurtosisLookback, &xs, .{ .period = per + 3 });
        try K.checkCore(CorrelCore, .{ .period = per }, .{ .x = &xs, .y = &ys });
        try K.checkCore(BetaCore, .{ .period = per }, .{ .x = &xs, .y = &ys });
        try K.checkCore(MedianCore, .{ .period = per }, .{ .x = &xs });
        try K.checkCore(PercentileCore, .{ .period = per, .percentile = 30 }, .{ .x = &xs });
    }
    // a series that jumps by 1e5 (re-anchor triggers) and a long flat run
    var jag: [400]f64 = undefined;
    for (&jag, 0..) |*v, i| v.* = if (i % 37 == 0) 1.0e5 else 100.0 + @as(f64, @floatFromInt(i % 5));
    try K.checkCore(CorrelCore, .{ .period = 6 }, .{ .x = &jag, .y = &xs });
    try K.checkCore(BetaCore, .{ .period = 6 }, .{ .x = &jag, .y = &xs });
    try th.checkOne(LinearregParams, LinearregStream, linearreg, linearregLookback, &jag, .{ .period = 7 });
    try th.checkOne(KurtosisParams, KurtosisStream, kurtosis, kurtosisLookback, &jag, .{ .period = 9 });
    const flat: [100]f64 = @splat(42.0);
    try K.checkCore(CorrelCore, .{ .period = 5 }, .{ .x = &flat, .y = &flat });
}
