// SPDX-License-Identifier: MIT
//! ACCBANDS, DONCHIAN, KC and ICHIMOKU, ported from TA-Lib 0.8.3
//! (`ta_ACCBANDS.c`, `ta_DONCHIAN.c`, `ta_KC.c`, `ta_ICHIMOKU.c`; BSD-3, see
//! NOTICE): price channels with several outputs over high / low (/ close) bars.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const range = @import("range.zig");
const window = @import("window.zig");
const bands = @import("bands.zig");
const hist = @import("hist.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const Bar = core.Bar;
const pf = core.pf;
const BbandsOut = bands.BbandsOut;
const MaxCore = window.MaxCore;
const MinCore = window.MinCore;

// ── ACCBANDS ────────────────────────────────────────────────────────────────

pub const AccbandsParams = struct { period: usize = 20 };

/// Headley's acceleration bands: simple averages of the high and low widened
/// by the bar's own relative range (`4 (h-l) / (h+l)`), and of the close.
pub const AccbandsCore = struct {
    pub const In = Bar(f64);
    pub const Out = BbandsOut(f64);
    pub fn InOf(comptime T: type) type {
        return Bar(T);
    }
    pub fn OutOf(comptime T: type) type {
        return BbandsOut(T);
    }
    p: usize,
    n: usize = 0,
    up: f64 = 0.0,
    mid: f64 = 0.0,
    lo: f64 = 0.0,

    pub fn validate(p: AccbandsParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: AccbandsParams) usize {
        return p.period;
    }
    pub fn lookback(p: AccbandsParams) usize {
        return p.period - 1;
    }
    pub fn init(p: AccbandsParams) Error!AccbandsCore {
        try validate(p);
        return .{ .p = p.period };
    }
    /// The (upper, lower) contribution of one bar.
    fn terms(b: Bar(f64)) [2]f64 {
        var t = b.high + b.low;
        if (!(@abs(t) <= 0.00000000000001 * (@abs(b.high) + @abs(b.low)))) {
            t = 4.0 * (b.high - b.low) / t;
            return .{ b.high * (1.0 + t), b.low * (1.0 - t) };
        }
        return .{ b.high, b.low };
    }
    pub fn step(self: *AccbandsCore, h: anytype, x: In) ?Out {
        const n = self.n;
        self.n += 1;
        const a = terms(x);
        self.up += a[0];
        self.lo += a[1];
        self.mid += x.close;
        if (n + 1 < self.p) return null;
        const tu = self.up;
        const tm = self.mid;
        const tl = self.lo;
        const old = h.at(n + 1 - self.p);
        const o = terms(old);
        self.up -= o[0];
        self.lo -= o[1];
        self.mid -= old.close;
        const per = pf(self.p);
        return .{ .upper = tu / per, .middle = tm / per, .lower = tl / per };
    }
};

pub fn accbandsLookback(p: AccbandsParams) Error!usize {
    try AccbandsCore.validate(p);
    return AccbandsCore.lookback(p);
}
pub fn accbands(comptime T: type, high: []const T, low: []const T, close: []const T, upper: []T, middle: []T, lower: []T, p: AccbandsParams) Error!usize {
    return hist.batch(T, AccbandsCore, .{ high, low, close }, .{ upper, middle, lower }, p, &.{});
}
pub fn AccbandsStream(comptime T: type) type {
    return hist.Stream(T, AccbandsParams, AccbandsCore);
}

// ── DONCHIAN ────────────────────────────────────────────────────────────────

pub const DonchianParams = struct { period: usize = 20 };

/// Highest high, lowest low and their midpoint over the last `period` bars.
pub const DonchianCore = struct {
    pub const In = hist.Hl(f64);
    pub const Out = BbandsOut(f64);
    pub fn InOf(comptime T: type) type {
        return hist.Hl(T);
    }
    pub fn OutOf(comptime T: type) type {
        return BbandsOut(T);
    }
    hi: MaxCore,
    lo: MinCore,
    n: usize = 0,

    pub fn validate(p: DonchianParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: DonchianParams) usize {
        return p.period;
    }
    pub fn lookback(p: DonchianParams) usize {
        return p.period - 1;
    }
    pub fn init(p: DonchianParams) Error!DonchianCore {
        try validate(p);
        return .{ .hi = MaxCore.initAny(p.period), .lo = MinCore.initAny(p.period) };
    }
    pub fn step(self: *DonchianCore, h: anytype, x: In) ?Out {
        self.n += 1;
        const hh = self.hi.step(hist.field(h, .high), x.high);
        const ll = self.lo.step(hist.field(h, .low), x.low);
        if (hh == null or ll == null) return null;
        return .{ .upper = hh.?, .middle = (hh.? + ll.?) / 2.0, .lower = ll.? };
    }
};

pub fn donchianLookback(p: DonchianParams) Error!usize {
    try DonchianCore.validate(p);
    return DonchianCore.lookback(p);
}
pub fn donchian(comptime T: type, high: []const T, low: []const T, upper: []T, middle: []T, lower: []T, p: DonchianParams) Error!usize {
    return hist.batch(T, DonchianCore, .{ high, low }, .{ upper, middle, lower }, p, &.{});
}
pub fn DonchianStream(comptime T: type) type {
    return hist.Stream(T, DonchianParams, DonchianCore);
}

// ── KC ──────────────────────────────────────────────────────────────────────

pub const KcParams = struct {
    period: usize = 20,
    atr_period: usize = 10,
    nb_dev: f64 = 2.0,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Keltner channel: EMA of the typical price `(h+l+c)/3` as the middle band,
/// `middle +/- ATR * nb_dev` as the others; the EMA and the ATR each start where
/// their own lookback ends exactly on the channel's first bar.
pub const KcCore = struct {
    pub const In = Bar(f64);
    pub const Out = BbandsOut(f64);
    pub fn InOf(comptime T: type) type {
        return Bar(T);
    }
    pub fn OutOf(comptime T: type) type {
        return BbandsOut(T);
    }
    ema: smooth.EmaCore,
    atr: range.AtrCoreT,
    skip_ema: usize,
    skip_atr: usize,
    dev: f64,
    n: usize = 0,

    pub fn validate(p: KcParams) Error!void {
        try core.checkPeriod(p.period, 2);
        try core.checkPeriod(p.atr_period, 1);
        if (!(p.nb_dev >= -3e37 and p.nb_dev <= 3e37)) return error.BadParam;
        try p.unstable.check();
    }
    fn emaParams(p: KcParams) smooth.EmaParams {
        return .{ .period = p.period, .unstable = p.unstable };
    }
    fn atrParams(p: KcParams) range.AtrParams {
        return .{ .period = p.atr_period, .unstable = p.unstable };
    }
    pub fn ringLen(_: KcParams) usize {
        return 0;
    }
    pub fn lookback(p: KcParams) usize {
        return @max(smooth.EmaCore.lookback(emaParams(p)), range.AtrCoreT.lookback(atrParams(p)));
    }
    pub fn init(p: KcParams) Error!KcCore {
        try validate(p);
        const lb = lookback(p);
        return .{
            .ema = try smooth.EmaCore.init(emaParams(p)),
            .atr = try range.AtrCoreT.init(atrParams(p)),
            .skip_ema = lb - smooth.EmaCore.lookback(emaParams(p)),
            .skip_atr = lb - range.AtrCoreT.lookback(atrParams(p)),
            .dev = p.nb_dev,
        };
    }
    pub fn step(self: *KcCore, h: anytype, x: In) ?Out {
        _ = h;
        const n = self.n;
        self.n += 1;
        const tp = (x.high + x.low + x.close) / 3.0;
        const m = if (n >= self.skip_ema) self.ema.step(smooth.NoSrc{}, tp) else null;
        const a = if (n >= self.skip_atr) self.atr.step(x) else null;
        if (m == null or a == null) return null;
        const t = a.? * self.dev;
        return .{ .upper = m.? + t, .middle = m.?, .lower = m.? - t };
    }
};

pub fn kcLookback(p: KcParams) Error!usize {
    try KcCore.validate(p);
    return KcCore.lookback(p);
}
pub fn kc(comptime T: type, high: []const T, low: []const T, close: []const T, upper: []T, middle: []T, lower: []T, p: KcParams) Error!usize {
    return hist.batch(T, KcCore, .{ high, low, close }, .{ upper, middle, lower }, p, &.{});
}
pub fn KcStream(comptime T: type) type {
    return hist.Stream(T, KcParams, KcCore);
}

// ── ICHIMOKU ────────────────────────────────────────────────────────────────

pub const IchimokuParams = struct {
    tenkan: usize = 9,
    kijun: usize = 26,
    senkou_b: usize = 52,
};

pub fn IchimokuOut(comptime T: type) type {
    return struct { tenkan: T, kijun: T, senkou_a: T, senkou_b: T };
}

/// Ichimoku lines at each bar, without the forward / backward displacement:
/// tenkan and kijun are midpoints of the highest high / lowest low over their
/// periods, senkou span B the same over its period, senkou span A the mean of
/// tenkan and kijun.
pub const IchimokuCore = struct {
    pub const In = hist.Hl(f64);
    pub const Out = IchimokuOut(f64);
    pub fn InOf(comptime T: type) type {
        return hist.Hl(T);
    }
    pub fn OutOf(comptime T: type) type {
        return IchimokuOut(T);
    }
    hi: [3]MaxCore,
    lo: [3]MinCore,
    n: usize = 0,

    pub fn validate(p: IchimokuParams) Error!void {
        try core.checkPeriod(p.tenkan, 2);
        try core.checkPeriod(p.kijun, 2);
        try core.checkPeriod(p.senkou_b, 2);
    }
    pub fn ringLen(p: IchimokuParams) usize {
        return @max(p.tenkan, @max(p.kijun, p.senkou_b));
    }
    pub fn lookback(p: IchimokuParams) usize {
        return ringLen(p) - 1;
    }
    pub fn init(p: IchimokuParams) Error!IchimokuCore {
        try validate(p);
        const ps = [3]usize{ p.tenkan, p.kijun, p.senkou_b };
        return .{
            .hi = .{ MaxCore.initAny(ps[0]), MaxCore.initAny(ps[1]), MaxCore.initAny(ps[2]) },
            .lo = .{ MinCore.initAny(ps[0]), MinCore.initAny(ps[1]), MinCore.initAny(ps[2]) },
        };
    }
    pub fn step(self: *IchimokuCore, h: anytype, x: In) ?Out {
        self.n += 1;
        var mid: [3]?f64 = undefined;
        inline for (0..3) |q| {
            const hh = self.hi[q].step(hist.field(h, .high), x.high);
            const ll = self.lo[q].step(hist.field(h, .low), x.low);
            mid[q] = if (hh != null and ll != null) (hh.? + ll.?) / 2.0 else null;
        }
        if (mid[0] == null or mid[1] == null or mid[2] == null) return null;
        return .{ .tenkan = mid[0].?, .kijun = mid[1].?, .senkou_a = (mid[0].? + mid[1].?) / 2.0, .senkou_b = mid[2].? };
    }
};

pub fn ichimokuLookback(p: IchimokuParams) Error!usize {
    try IchimokuCore.validate(p);
    return IchimokuCore.lookback(p);
}
pub fn ichimoku(comptime T: type, high: []const T, low: []const T, tenkan: []T, kijun: []T, senkou_a: []T, senkou_b: []T, p: IchimokuParams) Error!usize {
    return hist.batch(T, IchimokuCore, .{ high, low }, .{ tenkan, kijun, senkou_a, senkou_b }, p, &.{});
}
pub fn IchimokuStream(comptime T: type) type {
    return hist.Stream(T, IchimokuParams, IchimokuCore);
}
