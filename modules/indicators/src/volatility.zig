// SPDX-License-Identifier: MIT
//! Volatility indicators ported from TA-Lib 0.8.3 (`ta_ADR.c`, `ta_BBW.c`,
//! `ta_CVI.c`, `ta_MASSI.c`, `ta_PERCENTB.c`, `ta_ROGERSSATCHELL.c`,
//! `ta_RVI.c`, `ta_RVIR.c`; BSD-3, see NOTICE). Tuple cores of `vs_kit.zig`.
//! Where the C keeps a ring of derived values (CVI's EMA, MASSI's ratio) the
//! value that leaves the window is recomputed by a second copy of the same
//! recursion running `lag` bars behind, which gives the identical double
//! without a scratch array.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const bands = @import("bands.zig");
const K = @import("vs_kit.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const pf = core.pf;
const EmaCore = smooth.EmaCore;
const VarCore = bands.VarCore;

fn emaLb(period: usize, un: Unstable) usize {
    return EmaCore.lookbackOf(period, un, .sma);
}

// ── ADR ─────────────────────────────────────────────────────────────────────

pub const AdrParams = struct { period: usize = 14 };

/// Average daily range: the simple moving average of `high - low`
/// (`ta_SMA.c`'s add / read / subtract order).
pub const AdrCore = struct {
    pub const In = K.Hl(f64);
    pub const Out = f64;
    pub const Params = AdrParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    total: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params) Error!AdrCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *AdrCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        self.total += b.high - b.low;
        if (n + 1 < self.p) return null;
        const t = self.total;
        const o = src.at(n + 1 - self.p);
        self.total -= o.high - o.low;
        return t / pf(self.p);
    }
};
pub fn adrLookback(p: AdrParams) Error!usize {
    try AdrCore.validate(p);
    return AdrCore.lookback(p);
}
pub fn adr(comptime T: type, high: []const T, low: []const T, out: []T, p: AdrParams) Error!usize {
    return K.batch(T, AdrCore, p, .{ .high = high, .low = low }, .{out});
}
pub fn AdrStream(comptime T: type) type {
    return K.Stream(T, AdrCore);
}

// ── BBW / PERCENTB ──────────────────────────────────────────────────────────

pub const BbwParams = bands.BbandsParams;
pub const PercentbParams = bands.BbandsParams;

const real_min = -3e37;
const real_max = 3e37;

const BandPlan = struct {
    ma: smooth.MaParams,
    lb: usize,
    skip_m: usize,
    skip_v: usize,

    fn make(p: bands.BbandsParams) Error!BandPlan {
        try core.checkPeriod(p.period, 2);
        if (!(p.dev_up >= real_min and p.dev_up <= real_max)) return error.BadParam;
        if (!(p.dev_dn >= real_min and p.dev_dn <= real_max)) return error.BadParam;
        const ma = smooth.MaParams{ .period = p.period, .kind = p.ma, .unstable = p.unstable, .seed = p.seed };
        try smooth.MaCore.validate(ma);
        const lb_ma = smooth.MaCore.lookback(ma);
        const lb_sd = p.period - 1;
        const lb = @max(lb_ma, lb_sd);
        return .{ .ma = ma, .lb = lb, .skip_m = lb - lb_ma, .skip_v = lb - lb_sd };
    }
};

/// Bollinger band width `(upper - lower) / middle * 100` (`percentb = false`)
/// or %B `(x - lower) / (upper - lower)` (`percentb = true`): the bands are
/// BBANDS' (moving average, population standard deviation of the window).
/// A zero middle band answers 0 (width); a zero-width band answers 0.5 (%B).
pub fn BandCore(comptime pct: bool) type {
    return struct {
        const Self = @This();
        pub const In = K.X(f64);
        pub const Out = f64;
        pub const Params = bands.BbandsParams;
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return K.X(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        n: usize = 0,
        cm: smooth.MaCore,
        cv: VarCore,
        skip_m: usize,
        skip_v: usize,
        up: f64,
        dn: f64,
        lb: usize,

        pub fn validate(p: Params) Error!void {
            _ = try BandPlan.make(p);
        }
        pub fn ringLen(p: Params) usize {
            return p.period;
        }
        pub fn lookback(p: Params) usize {
            return (BandPlan.make(p) catch return 0).lb;
        }
        pub fn init(p: Params) Error!Self {
            const plan = try BandPlan.make(p);
            return .{
                .cm = try smooth.MaCore.init(plan.ma),
                .cv = VarCore.init(p.period),
                .skip_m = plan.skip_m,
                .skip_v = plan.skip_v,
                .up = p.dev_up,
                .dn = p.dev_dn,
                .lb = plan.lb,
            };
        }
        pub fn step(self: *Self, src: anytype, b: In) ?f64 {
            const n = self.n;
            self.n += 1;
            const xs = K.field(src, "x");
            const mv = if (n >= self.skip_m) self.cm.step(K.offset(xs, self.skip_m), b.x) else null;
            const vv = if (n >= self.skip_v) self.cv.step(K.offset(xs, self.skip_v), b.x) else null;
            if (mv == null or vv == null) return null;
            const mid = mv.?;
            const sd = if (vv.? != 0.0) @sqrt(vv.?) else 0.0;
            var upper: f64 = undefined;
            var lower: f64 = undefined;
            if (self.up == self.dn) {
                const t = sd * self.up;
                upper = mid + t;
                lower = mid - t;
            } else {
                upper = @mulAdd(f64, sd, self.up, mid);
                lower = mid - sd * self.dn;
            }
            if (pct) {
                const den = upper - lower;
                if (den == 0.0) return 0.5;
                return (b.x - lower) / den;
            }
            if (mid == 0.0) return 0.0;
            return (upper - lower) / mid * 100.0;
        }
    };
}
pub const BbwCore = BandCore(false);
pub const PercentbCore = BandCore(true);

pub fn bbwLookback(p: BbwParams) Error!usize {
    try BbwCore.validate(p);
    return BbwCore.lookback(p);
}
pub fn bbw(comptime T: type, in: []const T, out: []T, p: BbwParams) Error!usize {
    return K.batch(T, BbwCore, p, .{ .x = in }, .{out});
}
pub fn BbwStream(comptime T: type) type {
    return K.Stream(T, BbwCore);
}
pub fn percentbLookback(p: PercentbParams) Error!usize {
    try PercentbCore.validate(p);
    return PercentbCore.lookback(p);
}
pub fn percentb(comptime T: type, in: []const T, out: []T, p: PercentbParams) Error!usize {
    return K.batch(T, PercentbCore, p, .{ .x = in }, .{out});
}
pub fn PercentbStream(comptime T: type) type {
    return K.Stream(T, PercentbCore);
}

// ── CVI ─────────────────────────────────────────────────────────────────────

pub const CviParams = struct {
    period: usize = 10,
    roc: usize = 10,
    unstable: Unstable = core.no_unstable,
};

/// Chaikin volatility: the rate of change over `roc` bars of the EMA of
/// `high - low`, `100 * (E[t] - E[t-roc]) / E[t-roc]` (0 when the lagged EMA is
/// exactly 0).
pub const CviCore = struct {
    pub const In = K.Hl(f64);
    pub const Out = f64;
    pub const Params = CviParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    roc: usize,
    lb: usize,
    cur: EmaCore,
    lag: EmaCore,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
        try core.checkPeriod(p.roc, 1);
        try p.unstable.check();
    }
    pub fn ringLen(p: Params) usize {
        return p.roc + 1;
    }
    pub fn lookback(p: Params) usize {
        return emaLb(p.period, p.unstable) + p.roc;
    }
    pub fn init(p: Params) Error!CviCore {
        try validate(p);
        const e = try EmaCore.init(.{ .period = p.period });
        return .{ .roc = p.roc, .lb = lookback(p), .cur = e, .lag = e };
    }
    pub fn step(self: *CviCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const cur = self.cur.step({}, b.high - b.low);
        var lagged: ?f64 = null;
        if (n >= self.roc) {
            const o = src.at(n - self.roc);
            lagged = self.lag.step({}, o.high - o.low);
        }
        if (n < self.lb) return null;
        const e = cur.?;
        const lg = lagged.?;
        if (lg != 0.0) return 100.0 * ((e - lg) / lg);
        return 0.0;
    }
};
pub fn cviLookback(p: CviParams) Error!usize {
    try CviCore.validate(p);
    return CviCore.lookback(p);
}
pub fn cvi(comptime T: type, high: []const T, low: []const T, out: []T, p: CviParams) Error!usize {
    return K.batch(T, CviCore, p, .{ .high = high, .low = low }, .{out});
}
pub fn CviStream(comptime T: type) type {
    return K.Stream(T, CviCore);
}

// ── MASSI ───────────────────────────────────────────────────────────────────

pub const MassiParams = struct {
    fast: usize = 9,
    slow: usize = 25,
    unstable: Unstable = core.no_unstable,
};

/// `high - low` -> EMA -> EMA of that -> ratio, one value per bar once both
/// EMAs are warm. Each stage seeds with the mean of its first `fast` inputs,
/// the second stage starting at the EMA lookback `lem` (unstable bars included).
const MassiPipe = struct {
    n: usize = 0,
    fast: usize,
    lem: usize,
    beta: f64,
    k: f64,
    sum1: f64 = 0.0,
    ema1: f64 = 0.0,
    sum2: f64 = 0.0,
    ema2: f64 = 0.0,

    fn step(self: *MassiPipe, hl: f64) ?f64 {
        const nb = self.n;
        self.n += 1;
        if (nb < self.fast) {
            self.sum1 = self.sum1 + hl;
            if (nb == self.fast - 1) self.ema1 = self.sum1 / pf(self.fast);
        } else {
            self.ema1 = @mulAdd(f64, self.beta, self.ema1, self.k * hl);
        }
        if (nb >= self.lem) {
            const n2 = nb - self.lem;
            if (n2 < self.fast) {
                self.sum2 = self.sum2 + self.ema1;
                if (n2 == self.fast - 1) self.ema2 = self.sum2 / pf(self.fast);
            } else {
                self.ema2 = @mulAdd(f64, self.beta, self.ema2, self.k * self.ema1);
            }
        }
        if (nb >= 2 * self.lem) {
            if (self.ema2 == 0.0) return 1.0;
            return self.ema1 / self.ema2;
        }
        return null;
    }
};

/// Mass index: the sum over `slow` bars of the single-to-double EMA ratio of the
/// high-low range (a flat market is the ratio 1).
pub const MassiCore = struct {
    pub const In = K.Hl(f64);
    pub const Out = f64;
    pub const Params = MassiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    slow: usize,
    lb: usize,
    cur: MassiPipe,
    lag: MassiPipe,
    total: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try p.unstable.check();
    }
    pub fn ringLen(p: Params) usize {
        return p.slow;
    }
    pub fn lookback(p: Params) usize {
        return emaLb(p.fast, p.unstable) * 2 + (p.slow - 1);
    }
    pub fn init(p: Params) Error!MassiCore {
        try validate(p);
        const bk = EmaCore.betaK(p.fast);
        const pipe = MassiPipe{ .fast = p.fast, .lem = emaLb(p.fast, p.unstable), .beta = bk[0], .k = bk[1] };
        return .{ .slow = p.slow, .lb = lookback(p), .cur = pipe, .lag = pipe };
    }
    pub fn step(self: *MassiCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (self.cur.step(b.high - b.low)) |r| self.total = self.total + r;
        var leaving: ?f64 = null;
        if (n + 1 >= self.slow) {
            const o = src.at(n + 1 - self.slow);
            leaving = self.lag.step(o.high - o.low);
        }
        if (n < self.lb) return null;
        const out = self.total;
        self.total = self.total - leaving.?;
        return out;
    }
};
pub fn massiLookback(p: MassiParams) Error!usize {
    try MassiCore.validate(p);
    return MassiCore.lookback(p);
}
pub fn massi(comptime T: type, high: []const T, low: []const T, out: []T, p: MassiParams) Error!usize {
    return K.batch(T, MassiCore, p, .{ .high = high, .low = low }, .{out});
}
pub fn MassiStream(comptime T: type) type {
    return K.Stream(T, MassiCore);
}

// ── ROGERSSATCHELL ──────────────────────────────────────────────────────────

pub const RogersSatchellParams = struct {
    period: usize = 10,
    /// Annualisation factor A, 0 .. 3e37: the result is `sqrt(A)` times the per-bar value.
    annualization: f64 = 252.0,
};

fn rsTerm(b: K.Ohlc(f64)) f64 {
    if (b.open > 0.0 and b.high > 0.0 and b.low > 0.0 and b.close > 0.0) {
        const p1 = @log(b.high / b.close) * @log(b.high / b.open);
        const p2 = @log(b.low / b.close) * @log(b.low / b.open);
        return p1 + p2;
    }
    return 0.0;
}

/// Rogers-Satchell volatility: sqrt(A) * sqrt(mean over the window of
/// `ln(H/C) ln(H/O) + ln(L/C) ln(L/O)`); a bar with a price at or below zero
/// contributes 0, a window sum at or below zero answers 0. The running sum is
/// rebuilt from the window when it falls below 1e-6 of its peak and at least
/// every 32 windows.
pub const RogersSatchellCore = struct {
    pub const In = K.Ohlc(f64);
    pub const Out = f64;
    pub const Params = RogersSatchellParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Ohlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    sqrt_a: f64,
    total: f64 = 0.0,
    peak: f64 = 0.0,
    since: usize,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
        if (!(p.annualization >= 0.0 and p.annualization <= real_max)) return error.BadParam;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params) Error!RogersSatchellCore {
        try validate(p);
        return .{ .p = p.period, .sqrt_a = @sqrt(p.annualization), .since = 32 * p.period };
    }
    pub fn step(self: *RogersSatchellCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const t = rsTerm(b);
        if (n + 1 < self.p) {
            self.total += t;
            return null;
        }
        if (n + 1 == self.p) self.peak = @abs(self.total);
        self.total += t;
        var window_total = self.total;
        const mag = @abs(window_total);
        self.peak = if (mag > self.peak) mag else self.peak;
        const ws = n + 1 - self.p;
        self.total -= rsTerm(src.at(ws));
        self.since -= 1;
        if (mag < 0.000001 * self.peak or self.since == 0) {
            self.since = 32 * self.p;
            window_total = 0.0;
            var j = ws;
            while (j <= n) : (j += 1) window_total += rsTerm(src.at(j));
            self.peak = @abs(window_total);
            self.total = window_total;
            self.total -= rsTerm(src.at(ws));
        }
        if (window_total > 0.0) return self.sqrt_a * @sqrt(window_total / pf(self.p));
        return 0.0;
    }
};
pub fn rogerssatchellLookback(p: RogersSatchellParams) Error!usize {
    try RogersSatchellCore.validate(p);
    return RogersSatchellCore.lookback(p);
}
pub fn rogerssatchell(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out: []T, p: RogersSatchellParams) Error!usize {
    return K.batch(T, RogersSatchellCore, p, .{ .open = open, .high = high, .low = low, .close = close }, .{out});
}
pub fn RogersSatchellStream(comptime T: type) type {
    return K.Stream(T, RogersSatchellCore);
}

// ── RVI / RVIR ──────────────────────────────────────────────────────────────

pub const RviParams = struct {
    period: usize = 14,
    stddev: usize = 10,
    unstable: Unstable = core.no_unstable,
};

/// Relative volatility index: the standard deviation of the last `stddev` bars
/// (the TA_VAR step, anchored at the series start) credited to the up or the
/// down side by the close change, each side smoothed by Wilder's RMA with a
/// mean seed; `100 * up / (up + down)`, 50 when both are 0.
pub const RviCore = struct {
    n: usize = 0,
    p: usize,
    sd: usize,
    u: usize,
    v: VarCore,
    prev_x: f64 = 0.0,
    up_total: f64 = 0.0,
    dn_total: f64 = 0.0,
    prev_up: f64 = 0.0,
    prev_dn: f64 = 0.0,
    w_beta: f64,
    w_alpha: f64,

    fn unstableOf(p: RviParams) usize {
        const c4: usize = if (p.period > 1) 10 * p.period else 0;
        const c8: usize = if (p.period > 1) 19 * p.period else 0;
        return p.unstable.get(c4, c8);
    }
    pub fn validate(p: RviParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try core.checkPeriod(p.stddev, 2);
        try p.unstable.check();
    }
    pub fn ringLen(p: RviParams) usize {
        return p.stddev;
    }
    pub fn lookback(p: RviParams) usize {
        return p.stddev - 1 + (p.period - 1) + unstableOf(p);
    }
    pub fn init(p: RviParams) Error!RviCore {
        try validate(p);
        const wb = pf(p.period - 1) / pf(p.period);
        return .{ .p = p.period, .sd = p.stddev, .u = unstableOf(p), .v = VarCore.init(p.stddev), .w_beta = wb, .w_alpha = 1.0 - wb };
    }
    pub fn step(self: *RviCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        const prev = self.prev_x;
        self.prev_x = x;
        const variance = self.v.step(src, x) orelse return null;
        const k = n - (self.sd - 1);
        const sigma = @sqrt(variance);
        const delta = x - prev;
        if (k < self.p) {
            if (delta > 0.0) {
                self.up_total += sigma;
            } else if (delta < 0.0) {
                self.dn_total += sigma;
            }
            if (k + 1 < self.p) return null;
            self.prev_up = self.up_total / pf(self.p);
            self.prev_dn = self.dn_total / pf(self.p);
        } else {
            var up_value: f64 = 0.0;
            var dn_value: f64 = 0.0;
            if (delta > 0.0) {
                up_value = sigma;
            } else if (delta < 0.0) {
                dn_value = sigma;
            }
            self.prev_up = @mulAdd(f64, self.w_beta, self.prev_up, self.w_alpha * up_value);
            self.prev_dn = @mulAdd(f64, self.w_beta, self.prev_dn, self.w_alpha * dn_value);
        }
        if (k < self.p - 1 + self.u) return null;
        const total = self.prev_up + self.prev_dn;
        return if (total == 0.0) 50.0 else 100.0 * (self.prev_up / total);
    }
};
pub fn rviLookback(p: RviParams) Error!usize {
    try RviCore.validate(p);
    return RviCore.lookback(p);
}
pub fn rvi(comptime T: type, in: []const T, out: []T, p: RviParams) Error!usize {
    return smooth.batch1(T, RviCore, in, out, p);
}
pub fn RviStream(comptime T: type) type {
    return smooth.Stream1(T, RviParams, RviCore);
}

/// RVI of the highs and of the lows, averaged: `0.5 * (rvi(high) + rvi(low))`.
pub const RvirCore = struct {
    pub const In = K.Hl(f64);
    pub const Out = f64;
    pub const Params = RviParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    ch: RviCore,
    cl: RviCore,
    pub fn validate(p: Params) Error!void {
        try RviCore.validate(p);
    }
    pub fn ringLen(p: Params) usize {
        return p.stddev;
    }
    pub fn lookback(p: Params) usize {
        return RviCore.lookback(p);
    }
    pub fn init(p: Params) Error!RvirCore {
        const c = try RviCore.init(p);
        return .{ .ch = c, .cl = c };
    }
    pub fn step(self: *RvirCore, src: anytype, b: In) ?f64 {
        self.n += 1;
        const h = self.ch.step(K.field(src, "high"), b.high);
        const l = self.cl.step(K.field(src, "low"), b.low);
        if (h == null or l == null) return null;
        return 0.5 * (h.? + l.?);
    }
};
pub fn rvirLookback(p: RviParams) Error!usize {
    try RvirCore.validate(p);
    return RvirCore.lookback(p);
}
pub fn rvir(comptime T: type, high: []const T, low: []const T, out: []T, p: RviParams) Error!usize {
    return K.batch(T, RvirCore, p, .{ .high = high, .low = low }, .{out});
}
pub fn RvirStream(comptime T: type) type {
    return K.Stream(T, RvirCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "adr hand-checked vector" {
    // ranges 2 2 4 2; period 2: (2+2)/2 = 2, (2+4)/2 = 3, (4+2)/2 = 3.
    var out: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 1), try adr(f64, &.{ 10, 11, 15, 13 }, &.{ 8, 9, 11, 11 }, &out, .{ .period = 2 }));
    try testing.expectEqualSlices(f64, &.{ 2, 3, 3 }, out[1..]);
}

test "bbw and percentb hand-checked vector (period 2, SMA)" {
    // input 1 3 2: window (1,3): mean 2, sd 1 -> upper 4, lower 0: width (4-0)/2*100 = 200, %B (3-0)/4 = 0.75.
    // window (3,2): mean 2.5, sd 0.5 -> 3.5 / 1.5: width 2/2.5*100 = 80, %B (2-1.5)/2 = 0.25.
    var out: [3]f64 = undefined;
    _ = try bbw(f64, &.{ 1, 3, 2 }, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 200), out[1]);
    try testing.expectApproxEqRel(@as(f64, 80), out[2], 1e-14);
    _ = try percentb(f64, &.{ 1, 3, 2 }, &out, .{ .period = 2 });
    try testing.expectEqualSlices(f64, &.{ 0.75, 0.25 }, out[1..]);
    // a flat window: zero-width bands answer 0.5 and a zero-width BBW is (0)/mid
    _ = try percentb(f64, &.{ 5, 5, 5 }, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0.5), out[2]);
    _ = try bbw(f64, &.{ 0, 0, 0 }, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0), out[2]);
}

test "rogerssatchell: a constant bar has no variance; hand value for one bar" {
    // o=1, h=e, l=1, c=e: ln(h/c) = 0 and ln(l/c) ln(l/o) = (-1)(0) = 0 -> term 0.
    const e = std.math.e;
    var out: [2]f64 = undefined;
    _ = try rogerssatchell(f64, &.{ 1, 1 }, &.{ e, e }, &.{ 1, 1 }, &.{ e, e }, &out, .{ .period = 1 });
    try testing.expectEqual(@as(f64, 0), out[0]);
    // o=1, h=e^2, l=1, c=e: ln(h/c) ln(h/o) = 1 * 2 = 2, ln(l/..) ln(l/o) = 0: sqrt(252) * sqrt(2).
    _ = try rogerssatchell(f64, &.{1}, &.{e * e}, &.{1}, &.{e}, out[0..1], .{ .period = 1 });
    try testing.expectApproxEqRel(@sqrt(@as(f64, 504)), out[0], 1e-12);
    // a non-positive price contributes 0
    _ = try rogerssatchell(f64, &.{0}, &.{e * e}, &.{1}, &.{e}, out[0..1], .{ .period = 1 });
    try testing.expectEqual(@as(f64, 0), out[0]);
}

test "rvi: a rising series puts all the deviation on the up side (100), a flat one answers 50" {
    var up: [30]f64 = undefined;
    for (&up, 0..) |*v, i| v.* = @as(f64, @floatFromInt(i * i)) + 1.0;
    var out: [30]f64 = undefined;
    const lb = try rvi(f64, &up, &out, .{ .period = 3, .stddev = 4 });
    try testing.expectEqual(@as(usize, 3 + 2), lb);
    try testing.expectEqual(@as(f64, 100), out[lb]);
    var flat: [30]f64 = @splat(7.0);
    _ = try rvi(f64, &flat, &out, .{ .period = 3, .stddev = 4 });
    try testing.expectEqual(@as(f64, 50), out[10]);
}

test "volatility: BadParam edges and lookbacks" {
    var out: [8]f64 = undefined;
    const z = [_]f64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try testing.expectError(error.BadParam, adr(f64, &z, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, bbw(f64, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, percentb(f64, &z, &out, .{ .dev_up = 4e37 }));
    try testing.expectError(error.BadParam, cvi(f64, &z, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, cvi(f64, &z, &z, &out, .{ .roc = 0 }));
    try testing.expectError(error.BadParam, massi(f64, &z, &z, &out, .{ .fast = 1 }));
    try testing.expectError(error.BadParam, rogerssatchell(f64, &z, &z, &z, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, rogerssatchell(f64, &z, &z, &z, &z, &out, .{ .annualization = -1 }));
    try testing.expectError(error.BadParam, rvi(f64, &z, &out, .{ .stddev = 1 }));
    try testing.expectError(error.BadParam, rvir(f64, &z, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, adr(f64, &z, z[0..7], &out, .{}));
    try testing.expectEqual(@as(usize, 13), try adrLookback(.{}));
    try testing.expectEqual(@as(usize, 19), try bbwLookback(.{}));
    try testing.expectEqual(@as(usize, 9 + 10), try cviLookback(.{}));
    try testing.expectEqual(@as(usize, 16 + 24), try massiLookback(.{}));
    try testing.expectEqual(@as(usize, 9), try rogerssatchellLookback(.{}));
    try testing.expectEqual(@as(usize, 9 + 13), try rviLookback(.{}));
    try testing.expectEqual(@as(usize, 9 + 13 + 140), try rviLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 9 + 13 + 266), try rvirLookback(.{ .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, 2 * (8 + 5) + 24), try massiLookback(.{ .unstable = .{ .bars = 5 } }));
}

test "volatility: batch == streaming, lookback == leading NaN" {
    var o: [300]f64 = undefined;
    var h: [300]f64 = undefined;
    var l: [300]f64 = undefined;
    var c: [300]f64 = undefined;
    var v: [300]f64 = undefined;
    K.fillBars(&o, &h, &l, &c, &v, 11);
    const hl = .{ .high = &h, .low = &l };
    try K.checkCore(AdrCore, .{}, hl);
    try K.checkCore(AdrCore, .{ .period = 1 }, hl);
    try K.checkCore(CviCore, .{}, hl);
    try K.checkCore(CviCore, .{ .period = 3, .roc = 1, .unstable = .{ .bars = 3 } }, hl);
    try K.checkCore(MassiCore, .{}, hl);
    try K.checkCore(MassiCore, .{ .fast = 2, .slow = 2, .unstable = .{ .bars = 2 } }, hl);
    try K.checkCore(MassiCore, .{ .fast = 4, .slow = 30, .unstable = .auto4 }, hl);
    try K.checkCore(RvirCore, .{}, hl);
    try K.checkCore(RvirCore, .{ .period = 1, .stddev = 2 }, hl);
    const x = .{ .x = &c };
    try K.checkCore(BbwCore, .{}, x);
    try K.checkCore(BbwCore, .{ .period = 5, .dev_up = 1.5, .dev_dn = 2.5, .ma = .wma }, x);
    try K.checkCore(BbwCore, .{ .period = 6, .ma = .ema }, x);
    try K.checkCore(PercentbCore, .{}, x);
    try K.checkCore(PercentbCore, .{ .period = 4, .ma = .ema, .dev_up = 1, .dev_dn = 3 }, x);
    try K.checkCore(PercentbCore, .{ .period = 7, .ma = .disabled }, x);
    const ohlc = .{ .open = &o, .high = &h, .low = &l, .close = &c };
    try K.checkCore(RogersSatchellCore, .{}, ohlc);
    try K.checkCore(RogersSatchellCore, .{ .period = 1 }, ohlc);
    try th.checkOne(RviParams, RviStream, rvi, rviLookback, &c, .{});
    try th.checkOne(RviParams, RviStream, rvi, rviLookback, &c, .{ .period = 1, .stddev = 2 });
    try th.checkOne(RviParams, RviStream, rvi, rviLookback, &c, .{ .period = 5, .stddev = 7, .unstable = .{ .bars = 6 } });
}

test "volatility: f32 inputs" {
    var xs: [80]f64 = undefined;
    th.walk(&xs, 3);
    var x32: [80]f32 = undefined;
    for (&x32, xs) |*d, s| d.* = @floatCast(s);
    var o32: [80]f32 = undefined;
    try testing.expectEqual(@as(usize, 19), try bbw(f32, &x32, &o32, .{}));
    try testing.expectEqual(@as(usize, 19), try percentb(f32, &x32, &o32, .{}));
    try testing.expectEqual(@as(usize, 22), try rvi(f32, &x32, &o32, .{}));
}
