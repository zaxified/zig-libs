// SPDX-License-Identifier: MIT
//! SAR, SAREXT, SUPERTREND, CKSP and ZIGZAG, ported from TA-Lib 0.8.3
//! (`ta_SAR.c`, `ta_SAREXT.c`, `ta_SUPERTREND.c`, `ta_CKSP.c`, `ta_ZIGZAG.c`;
//! BSD-3, see NOTICE). Trend-following state machines over high / low (/ close)
//! bars; integer outputs (trend direction, pivot index) are integer slices.

const std = @import("std");
const core = @import("core.zig");
const range = @import("range.zig");
const window = @import("window.zig");
const hist = @import("hist.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const Bar = core.Bar;
const pf = core.pf;
const real_max: f64 = 3e37;

fn inRange(v: f64, lo: f64, hi: f64) bool {
    return v >= lo and v <= hi;
}

// ── SAR / SAREXT ────────────────────────────────────────────────────────────

pub const SarParams = struct {
    acceleration: f64 = 0.02,
    maximum: f64 = 0.2,
};

pub const SarextParams = struct {
    start_value: f64 = 0.0,
    offset_on_reverse: f64 = 0.0,
    af_init_long: f64 = 0.02,
    af_long: f64 = 0.02,
    af_max_long: f64 = 0.2,
    af_init_short: f64 = 0.02,
    af_short: f64 = 0.02,
    af_max_short: f64 = 0.2,
};

const SarCfg = struct {
    start: f64,
    offset: f64,
    init_long: f64,
    inc_long: f64,
    max_long: f64,
    init_short: f64,
    inc_short: f64,
    max_short: f64,
};

fn cfgOf(p: SarParams) SarCfg {
    // TA_SAR clamps the acceleration to the maximum, then uses it for the
    // initial value and the increment of both directions.
    const acc = if (p.acceleration > p.maximum) p.maximum else p.acceleration;
    return .{ .start = 0.0, .offset = 0.0, .init_long = acc, .inc_long = acc, .max_long = p.maximum, .init_short = acc, .inc_short = acc, .max_short = p.maximum };
}

fn cfgOfExt(p: SarextParams) SarCfg {
    return .{
        .start = p.start_value,
        .offset = p.offset_on_reverse,
        .init_long = if (p.af_init_long > p.af_max_long) p.af_max_long else p.af_init_long,
        .inc_long = if (p.af_long > p.af_max_long) p.af_max_long else p.af_long,
        .max_long = p.af_max_long,
        .init_short = if (p.af_init_short > p.af_max_short) p.af_max_short else p.af_init_short,
        .inc_short = if (p.af_short > p.af_max_short) p.af_max_short else p.af_short,
        .max_short = p.af_max_short,
    };
}

/// Parabolic SAR. `ext`: SAREXT (separate parameters per direction, start
/// value, offset on reverse, short-side values reported negative).
pub fn SarCore(comptime ext: bool) type {
    const Params = if (ext) SarextParams else SarParams;
    return struct {
        const Self = @This();
        pub const In = hist.Hl(f64);
        pub const Out = f64;
        pub fn InOf(comptime T: type) type {
            return hist.Hl(T);
        }
        pub fn OutOf(comptime T: type) type {
            return T;
        }
        cfg: SarCfg,
        n: usize = 0,
        last_low: f64 = 0.0,
        last_high: f64 = 0.0,
        is_long: bool = false,
        ep: f64 = 0.0,
        sar: f64 = 0.0,
        af_long: f64 = 0.0,
        af_short: f64 = 0.0,

        pub fn validate(p: Params) Error!void {
            if (ext) {
                if (!inRange(p.start_value, -real_max, real_max)) return error.BadParam;
                if (!inRange(p.offset_on_reverse, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.af_init_long, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.af_long, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.af_max_long, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.af_init_short, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.af_short, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.af_max_short, 0.0, real_max)) return error.BadParam;
            } else {
                if (!inRange(p.acceleration, 0.0, real_max)) return error.BadParam;
                if (!inRange(p.maximum, 0.0, real_max)) return error.BadParam;
            }
        }
        pub fn ringLen(_: Params) usize {
            return 0;
        }
        pub fn lookback(_: Params) usize {
            return 1;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            const cfg = if (ext) cfgOfExt(p) else cfgOf(p);
            return .{ .cfg = cfg, .af_long = cfg.init_long, .af_short = cfg.init_short };
        }
        pub fn step(self: *Self, h: anytype, x: In) ?f64 {
            _ = h;
            const n = self.n;
            self.n += 1;
            const c = self.cfg;
            var prev_low: f64 = undefined;
            var prev_high: f64 = undefined;
            if (n == 0) {
                self.last_low = x.low;
                self.last_high = x.high;
                return null;
            }
            if (n == 1) {
                if (c.start == 0.0) {
                    // Direction of the first move: TA_MINUS_DM with period 1.
                    const diff_p = x.high - self.last_high;
                    const diff_m = self.last_low - x.low;
                    var m: f64 = if (diff_m > 0.0) diff_m else 0.0;
                    m = if (diff_p < diff_m) m else 0.0;
                    self.is_long = !(m > 0.0);
                    if (self.is_long) {
                        self.ep = x.high;
                        self.sar = self.last_low;
                    } else {
                        self.ep = x.low;
                        self.sar = self.last_high;
                    }
                } else if (c.start > 0.0) {
                    self.is_long = true;
                    self.ep = x.high;
                    self.sar = c.start;
                } else {
                    self.is_long = false;
                    self.ep = x.low;
                    self.sar = @abs(c.start);
                }
                // The first iteration treats this bar as its own predecessor.
                prev_low = x.low;
                prev_high = x.high;
            } else {
                prev_low = self.last_low;
                prev_high = self.last_high;
            }
            self.last_low = x.low;
            self.last_high = x.high;
            const new_low = x.low;
            const new_high = x.high;
            var out: f64 = undefined;
            if (self.is_long) {
                if (new_low <= self.sar) {
                    // Switch to short: the SAR becomes the extreme point.
                    self.is_long = false;
                    self.sar = self.ep;
                    if (self.sar < prev_high) self.sar = prev_high;
                    if (self.sar < new_high) self.sar = new_high;
                    if (c.offset != 0.0) self.sar += self.sar * c.offset;
                    out = if (ext) -self.sar else self.sar;
                    self.af_short = c.init_short;
                    self.ep = new_low;
                    self.sar = @mulAdd(f64, self.af_short, self.ep - self.sar, self.sar);
                    if (self.sar < prev_high) self.sar = prev_high;
                    if (self.sar < new_high) self.sar = new_high;
                } else {
                    out = self.sar;
                    if (new_high > self.ep) {
                        self.ep = new_high;
                        self.af_long += c.inc_long;
                        if (self.af_long > c.max_long) self.af_long = c.max_long;
                    }
                    self.sar = @mulAdd(f64, self.af_long, self.ep - self.sar, self.sar);
                    if (self.sar > prev_low) self.sar = prev_low;
                    if (self.sar > new_low) self.sar = new_low;
                }
            } else if (new_high >= self.sar) {
                // Switch to long.
                self.is_long = true;
                self.sar = self.ep;
                if (self.sar > prev_low) self.sar = prev_low;
                if (self.sar > new_low) self.sar = new_low;
                if (c.offset != 0.0) self.sar -= self.sar * c.offset;
                out = self.sar;
                self.af_long = c.init_long;
                self.ep = new_high;
                self.sar = @mulAdd(f64, self.af_long, self.ep - self.sar, self.sar);
                if (self.sar > prev_low) self.sar = prev_low;
                if (self.sar > new_low) self.sar = new_low;
            } else {
                out = if (ext) -self.sar else self.sar;
                if (new_low < self.ep) {
                    self.ep = new_low;
                    self.af_short += c.inc_short;
                    if (self.af_short > c.max_short) self.af_short = c.max_short;
                }
                self.sar = @mulAdd(f64, self.af_short, self.ep - self.sar, self.sar);
                if (self.sar < prev_high) self.sar = prev_high;
                if (self.sar < new_high) self.sar = new_high;
            }
            return out;
        }
    };
}

pub const SarCoreT = SarCore(false);
pub const SarextCoreT = SarCore(true);

pub fn sarLookback(p: SarParams) Error!usize {
    try SarCoreT.validate(p);
    return SarCoreT.lookback(p);
}
pub fn sar(comptime T: type, high: []const T, low: []const T, out: []T, p: SarParams) Error!usize {
    return hist.batch(T, SarCoreT, .{ high, low }, .{out}, p, &.{});
}
pub fn SarStream(comptime T: type) type {
    return hist.Stream(T, SarParams, SarCoreT);
}
pub fn sarextLookback(p: SarextParams) Error!usize {
    try SarextCoreT.validate(p);
    return SarextCoreT.lookback(p);
}
pub fn sarext(comptime T: type, high: []const T, low: []const T, out: []T, p: SarextParams) Error!usize {
    return hist.batch(T, SarextCoreT, .{ high, low }, .{out}, p, &.{});
}
pub fn SarextStream(comptime T: type) type {
    return hist.Stream(T, SarextParams, SarextCoreT);
}

// ── SUPERTREND ──────────────────────────────────────────────────────────────

pub const SupertrendParams = struct {
    period: usize = 10,
    multiplier: f64 = 3.0,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

pub fn SupertrendOut(comptime T: type) type {
    return struct { supertrend: T, trend: i8 };
}

/// ATR bands around the bar midpoint that only tighten while the trend holds;
/// `trend` is 1 (up, the lower band is reported) or -1 (down, the upper band).
pub const SupertrendCore = struct {
    pub const In = Bar(f64);
    pub const Out = SupertrendOut(f64);
    pub fn InOf(comptime T: type) type {
        return Bar(T);
    }
    pub fn OutOf(comptime T: type) type {
        return SupertrendOut(T);
    }
    atr: range.AtrCoreT,
    mult: f64,
    n: usize = 0,
    started: bool = false,
    up: bool = true,
    final_upper: f64 = 0.0,
    final_lower: f64 = 0.0,
    prev_close: f64 = 0.0,

    pub fn validate(p: SupertrendParams) Error!void {
        try core.checkPeriod(p.period, 2);
        if (!inRange(p.multiplier, 0.0, real_max)) return error.BadParam;
        try p.unstable.check();
    }
    fn atrParams(p: SupertrendParams) range.AtrParams {
        return .{ .period = p.period, .unstable = p.unstable };
    }
    pub fn ringLen(_: SupertrendParams) usize {
        return 0;
    }
    pub fn lookback(p: SupertrendParams) usize {
        return range.AtrCoreT.lookback(atrParams(p));
    }
    pub fn init(p: SupertrendParams) Error!SupertrendCore {
        try validate(p);
        return .{ .atr = try range.AtrCoreT.init(atrParams(p)), .mult = p.multiplier };
    }
    pub fn step(self: *SupertrendCore, h: anytype, x: In) ?Out {
        _ = h;
        self.n += 1;
        const a = self.atr.step(x) orelse return null;
        const median = (x.high + x.low) / 2.0;
        const band = self.mult * a;
        if (!self.started) {
            self.started = true;
            self.final_upper = median + band;
            self.final_lower = median - band;
            self.up = true;
            self.prev_close = x.close;
            return .{ .supertrend = self.final_lower, .trend = 1 };
        }
        const basic_upper = median + band;
        const basic_lower = median - band;
        if (basic_upper < self.final_upper or self.prev_close > self.final_upper) self.final_upper = basic_upper;
        if (basic_lower > self.final_lower or self.prev_close < self.final_lower) self.final_lower = basic_lower;
        if (self.up) {
            if (x.close < self.final_lower) self.up = false;
        } else if (x.close > self.final_upper) {
            self.up = true;
        }
        self.prev_close = x.close;
        return if (self.up)
            .{ .supertrend = self.final_lower, .trend = 1 }
        else
            .{ .supertrend = self.final_upper, .trend = -1 };
    }
};

pub fn supertrendLookback(p: SupertrendParams) Error!usize {
    try SupertrendCore.validate(p);
    return SupertrendCore.lookback(p);
}
/// `trend` is 0 in the lead (before the lookback).
pub fn supertrend(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, trend: []i8, p: SupertrendParams) Error!usize {
    return hist.batch(T, SupertrendCore, .{ high, low, close }, .{ out, trend }, p, &.{});
}
pub fn SupertrendStream(comptime T: type) type {
    return hist.Stream(T, SupertrendParams, SupertrendCore);
}

// ── CKSP ────────────────────────────────────────────────────────────────────

pub const CkspParams = struct {
    period: usize = 10,
    multiplier: f64 = 1.0,
    stop_period: usize = 9,
    unstable: Unstable = core.no_unstable,
};

pub fn CkspOut(comptime T: type) type {
    return struct { high_stop: T, low_stop: T };
}

/// Chande Kroll stop: first stops `highest high(period) - mult*ATR` and
/// `lowest low(period) + mult*ATR`, then the highest / lowest of the last
/// `stop_period` first stops. With an AUTO unstable level the first stops start
/// `stop_period - 1` bars later (so the stop window sits on converged ATRs).
pub const CkspCore = struct {
    pub const In = Bar(f64);
    pub const Out = CkspOut(f64);
    pub fn InOf(comptime T: type) type {
        return Bar(T);
    }
    pub fn OutOf(comptime T: type) type {
        return CkspOut(T);
    }
    atr: range.AtrCoreT,
    hi: window.MaxCore,
    lo: window.MinCore,
    hs_max: window.MaxCore,
    ls_min: window.MinCore,
    hs: hist.PRing = .{},
    ls: hist.PRing = .{},
    mult: f64,
    q: usize,
    first_stop: usize,
    n: usize = 0,

    pub fn validate(p: CkspParams) Error!void {
        try core.checkPeriod(p.period, 2);
        if (!inRange(p.multiplier, 0.0, real_max)) return error.BadParam;
        try core.checkPeriod(p.stop_period, 1);
        try p.unstable.check();
    }
    fn atrParams(p: CkspParams) range.AtrParams {
        return .{ .period = p.period, .unstable = p.unstable };
    }
    fn extra(p: CkspParams) usize {
        return switch (p.unstable) {
            .bars => 0,
            else => p.stop_period - 1,
        };
    }
    pub fn ringLen(p: CkspParams) usize {
        return p.period;
    }
    pub fn scratchLen(p: CkspParams) usize {
        return 2 * p.stop_period;
    }
    pub fn lookback(p: CkspParams) usize {
        return range.AtrCoreT.lookback(atrParams(p)) + p.stop_period - 1 + extra(p);
    }
    pub fn init(p: CkspParams) Error!CkspCore {
        try validate(p);
        return .{
            .atr = try range.AtrCoreT.init(atrParams(p)),
            .hi = window.MaxCore.initAny(p.period),
            .lo = window.MinCore.initAny(p.period),
            .hs_max = window.MaxCore.initAny(p.stop_period),
            .ls_min = window.MinCore.initAny(p.stop_period),
            .mult = p.multiplier,
            .q = p.stop_period,
            .first_stop = range.AtrCoreT.lookback(atrParams(p)) + extra(p),
        };
    }
    pub fn bind(self: *CkspCore, s: []f64) void {
        self.hs = .{ .buf = s[0..self.q] };
        self.ls = .{ .buf = s[self.q .. 2 * self.q] };
    }
    pub fn scratchSlice(self: *const CkspCore) []f64 {
        return self.hs.buf.ptr[0 .. 2 * self.q];
    }
    pub fn step(self: *CkspCore, h: anytype, x: In) ?Out {
        const dry = @TypeOf(h).dry;
        const n = self.n;
        self.n += 1;
        const hh = self.hi.step(hist.field(h, .high), x.high);
        const ll = self.lo.step(hist.field(h, .low), x.low);
        const a = self.atr.step(x) orelse return null;
        if (n < self.first_stop) return null;
        const band = self.mult * a;
        const high_stop = hh.? - band;
        const low_stop = ll.? + band;
        const m = n - self.first_stop;
        self.hs.put(dry, m, high_stop);
        self.ls.put(dry, m, low_stop);
        const hm = self.hs_max.step(self.hs.src(m, high_stop), high_stop);
        const lm = self.ls_min.step(self.ls.src(m, low_stop), low_stop);
        if (hm == null or lm == null) return null;
        return .{ .high_stop = hm.?, .low_stop = lm.? };
    }
};

pub fn ckspLookback(p: CkspParams) Error!usize {
    try CkspCore.validate(p);
    return CkspCore.lookback(p);
}
/// `gpa` provides `2 * stop_period` f64 of scratch.
pub fn cksp(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, high_stop: []T, low_stop: []T, p: CkspParams) core.AllocError!usize {
    return hist.batchAlloc(T, CkspCore, gpa, .{ high, low, close }, .{ high_stop, low_stop }, p);
}
pub fn CkspStream(comptime T: type) type {
    return hist.Stream(T, CkspParams, CkspCore);
}

// ── ZIGZAG ──────────────────────────────────────────────────────────────────

pub const ZigzagParams = struct {
    /// Reversal threshold in percent, 0..100.
    sensitivity: f64 = 5.0,
    min_trend_length: usize = 1,
};

pub fn ZigzagOut(comptime T: type) type {
    return struct { zigzag: T, trend: i8, pivot_idx: i32 };
}

/// Percentage zig-zag: `zigzag` is the current pivot (the extreme of the leg
/// in progress), `trend` the leg's direction (1 up, -1 down) and `pivot_idx`
/// the index of the pivot bar in the input. The first leg is down from bar 0's
/// low. The lookback equals `min_trend_length`.
pub const ZigzagCore = struct {
    pub const In = hist.Hl(f64);
    pub const Out = ZigzagOut(f64);
    pub fn InOf(comptime T: type) type {
        return hist.Hl(T);
    }
    pub fn OutOf(comptime T: type) type {
        return ZigzagOut(T);
    }
    up: f64,
    dn: f64,
    min_len: usize,
    n: usize = 0,
    trend: i8 = -1,
    pivot: f64 = 0.0,
    since: usize = 0,

    pub fn validate(p: ZigzagParams) Error!void {
        if (!inRange(p.sensitivity, 0.0, 100.0)) return error.BadParam;
        try core.checkPeriod(p.min_trend_length, 1);
    }
    pub fn ringLen(_: ZigzagParams) usize {
        return 0;
    }
    pub fn lookback(p: ZigzagParams) usize {
        return p.min_trend_length;
    }
    pub fn init(p: ZigzagParams) Error!ZigzagCore {
        try validate(p);
        const s = p.sensitivity / 100.0;
        return .{ .up = 1.0 + s, .dn = 1.0 - s, .min_len = p.min_trend_length };
    }
    pub fn step(self: *ZigzagCore, h: anytype, x: In) ?Out {
        _ = h;
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.pivot = x.low;
            self.since = 0;
            return null;
        }
        self.since += 1;
        if (self.trend == -1) {
            if (x.high >= self.pivot * self.up and self.since >= self.min_len) {
                self.trend = 1;
                self.pivot = x.high;
                self.since = 0;
            } else {
                if (x.low <= self.pivot) self.since = 0;
                self.pivot = if (x.low < self.pivot) x.low else self.pivot;
            }
        } else if (x.low <= self.pivot * self.dn and self.since >= self.min_len) {
            self.trend = -1;
            self.pivot = x.low;
            self.since = 0;
        } else {
            if (x.high >= self.pivot) self.since = 0;
            self.pivot = if (x.high > self.pivot) x.high else self.pivot;
        }
        if (n < self.min_len) return null;
        return .{ .zigzag = self.pivot, .trend = self.trend, .pivot_idx = std.math.cast(i32, n - self.since) orelse std.math.maxInt(i32) }; // saturates past 2^31 bars (TA-Lib's own int indices end there)
    }
};

pub fn zigzagLookback(p: ZigzagParams) Error!usize {
    try ZigzagCore.validate(p);
    return ZigzagCore.lookback(p);
}
/// `trend` and `pivot_idx` are 0 in the lead (before the lookback).
pub fn zigzag(comptime T: type, high: []const T, low: []const T, out: []T, trend: []i8, pivot_idx: []i32, p: ZigzagParams) Error!usize {
    return hist.batch(T, ZigzagCore, .{ high, low }, .{ out, trend, pivot_idx }, p, &.{});
}
pub fn ZigzagStream(comptime T: type) type {
    return hist.Stream(T, ZigzagParams, ZigzagCore);
}

test "zigzag: a bar index past 2^31 saturates the i32 pivot index instead of trapping (sweep IND-3)" {
    // A stream that has seen more than 2^31 bars (a tick feed, a few weeks) must keep answering.
    var c = try ZigzagCore.init(.{});
    c.n = std.math.maxInt(i32) + 1000;
    c.since = 3;
    c.trend = 1;
    c.pivot = 10.0;
    const r = c.step({}, .{ .high = 10.0, .low = 10.0 }) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), r.pivot_idx);
    // below the limit the index is the bar of the pivot, as before
    var d = try ZigzagCore.init(.{});
    d.n = 1000;
    d.since = 3;
    d.trend = 1;
    d.pivot = 10.0;
    const q = d.step({}, .{ .high = 10.0, .low = 10.0 }) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, 1000), q.pivot_idx);
}
