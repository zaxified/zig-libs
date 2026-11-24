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
    fn atrCore(p: CkspParams) Error!range.AtrCoreT {
        return range.AtrCoreT.init(atrParams(p));
    }
    fn firstStop(p: CkspParams) usize {
        return range.AtrCoreT.lookback(atrParams(p)) + extra(p);
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
/// A rolling extremum over `buf.len` values, one value per `push` (van Herk /
/// Gil-Werman, as TA-Lib's own CKSP does): the window ending in slot `j` is
/// the current block's prefix extremum joined with the previous block's suffix
/// extremum from slot `j + 1`. A slot holds the raw value while its block is
/// filling and becomes the suffix extremum, in place, when the block completes
/// (slot `j + 1` is always still the previous block's when slot `j` is
/// written). The answer of `push` is a full window from the `buf.len`-th push on.
fn BlockExt(comptime is_max: bool) type {
    return struct {
        buf: []f64,
        j: usize = 0,
        pre: f64 = 0.0,
        full: bool = false,

        /// The better of two finite values, without a branch (a data-dependent
        /// `if` here mispredicts about half the time on a random walk).
        inline fn best(a: f64, b: f64) f64 {
            // A plain compare-select is one `maxsd` / `minsd`; `@max` / `@min` add the NaN
            // fix-up (`cmpunordsd` + `blendvpd`) the finite input never needs.
            return if (is_max) (if (a > b) a else b) else (if (a < b) a else b);
        }
        fn push(s: *@This(), v: f64) f64 {
            const w = s.buf.len;
            const j = s.j;
            s.pre = if (j == 0) v else best(v, s.pre);
            s.buf[j] = v;
            const r = if (j + 1 == w or !s.full) s.pre else best(s.pre, s.buf[j + 1]);
            if (j + 1 == w) {
                var k = w - 1;
                while (k > 0) {
                    k -= 1;
                    s.buf[k] = best(s.buf[k], s.buf[k + 1]);
                }
                s.j = 0;
                s.full = true;
            } else {
                s.j = j + 1;
            }
            return r;
        }
    };
}

/// The batch CKSP as one pass of four block-wise extrema and the Wilder ATR
/// (`CkspCore`'s arithmetic, bit for bit), for inputs where an extremum's only
/// freedom is gone: every high and low finite and not zero (a tie between +0.0
/// and -0.0 would pick a sign by the window's shape), every close finite, and
/// every stop finite. Null when the inputs are not like that (the caller runs
/// `CkspCore`); the outputs are then unspecified.
fn ckspBlocks(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, high_stop: []T, low_stop: []T, p: CkspParams) ?usize {
    const n = high.len;
    if (low.len != n or close.len != n or high_stop.len != n or low_stop.len != n) return null;
    CkspCore.validate(p) catch return null;
    var bad = false;
    for (high, low, close) |h, l, c| {
        const hv: f64 = h;
        const lv: f64 = l;
        bad = bad or !std.math.isFinite(hv) or !std.math.isFinite(lv) or !std.math.isFinite(@as(f64, c)) or hv == 0.0 or lv == 0.0;
    }
    if (bad) return null;
    const lb = CkspCore.lookback(p);
    const nan = std.math.nan(T);
    @memset(high_stop[0..@min(lb, n)], nan);
    @memset(low_stop[0..@min(lb, n)], nan);
    if (lb >= n) return lb;

    const pp = p.period;
    const q = p.stop_period;
    // No room for the four buffers: the generic core, which needs `2 * q`, answers.
    const bufs = gpa.alloc(f64, 2 * (pp + q)) catch return null;
    defer gpa.free(bufs);
    var hh: BlockExt(true) = .{ .buf = bufs[0..pp] };
    var ll: BlockExt(false) = .{ .buf = bufs[pp .. 2 * pp] };
    var hs: BlockExt(true) = .{ .buf = bufs[2 * pp .. 2 * pp + q] };
    var ls: BlockExt(false) = .{ .buf = bufs[2 * pp + q ..] };
    var atr = CkspCore.atrCore(p) catch return null;
    const first_stop = CkspCore.firstStop(p);
    const Stage = struct {
        hh: *BlockExt(true),
        ll: *BlockExt(false),
        hs: *BlockExt(true),
        ls: *BlockExt(false),
        high_stop: []T,
        low_stop: []T,
        mult: f64,
        win_start: usize,
        first_stop: usize,
        lb: usize,
        finite: bool = true,

        /// Bar `i` with its ATR (null while the ATR has no output).
        inline fn feed(st: *@This(), i: usize, h: f64, l: f64, a: ?f64) void {
            if (i < st.win_start) return;
            const hv = st.hh.push(h);
            const lv = st.ll.push(l);
            if (i < st.first_stop) return;
            const band = st.mult * a.?;
            const hsv = hv - band;
            const lsv = lv + band;
            st.finite = st.finite and std.math.isFinite(hsv) and std.math.isFinite(lsv);
            const hm = st.hs.push(hsv);
            const lm = st.ls.push(lsv);
            if (i >= st.lb) {
                st.high_stop[i] = core.to(T, hm);
                st.low_stop[i] = core.to(T, lm);
            }
        }

        /// `feed` for a bar already known to be in phase `ph`: 0 before the extrema
        /// start, 1 extrema only, 2 first stops (no output yet), 3 outputs.
        inline fn feedPhase(st: *@This(), comptime ph: usize, i: usize, h: f64, l: f64, a: f64) void {
            if (ph == 0) return;
            const hv = st.hh.push(h);
            const lv = st.ll.push(l);
            if (ph == 1) return;
            const band = st.mult * a;
            const hsv = hv - band;
            const lsv = lv + band;
            st.finite = st.finite and std.math.isFinite(hsv) and std.math.isFinite(lsv);
            const hm = st.hs.push(hsv);
            const lm = st.ls.push(lsv);
            if (ph == 3) {
                st.high_stop[i] = core.to(T, hm);
                st.low_stop[i] = core.to(T, lm);
            }
        }
    };
    var st: Stage = .{ .hh = &hh, .ll = &ll, .hs = &hs, .ls = &ls, .high_stop = high_stop, .low_stop = low_stop, .mult = p.multiplier, .win_start = first_stop + 1 - pp, .first_stop = first_stop, .lb = lb };
    var i: usize = 0;
    // The ATR through its core until it is a bare recurrence, then the same
    // arithmetic inline (`AtrCore.steadyRun`'s), so no optional is carried per bar.
    while (i < n and !atr.steady()) : (i += 1) {
        const h: f64 = high[i];
        const l: f64 = low[i];
        st.feed(i, h, l, atr.step(.{ .high = h, .low = l, .close = close[i] }));
    }
    var prev = atr.prev;
    var cy = atr.tr.prev_close;
    const beta = atr.beta;
    const alpha = atr.alpha;
    // The steady loop in four phases (the extrema start, the first stops start, the stops
    // are written), each with its own branch-free body.
    inline for (0..4) |ph| {
        const end = switch (ph) {
            0 => @min(n, @max(i, st.win_start)),
            1 => @min(n, @max(i, st.first_stop)),
            2 => @min(n, @max(i, st.lb)),
            else => n,
        };
        while (i < end) : (i += 1) {
            const h: f64 = high[i];
            const l: f64 = low[i];
            const cl: f64 = close[i];
            var greatest = h - l;
            const v2 = @abs(cy - h);
            if (v2 > greatest) greatest = v2;
            const v3 = @abs(cy - l);
            if (v3 > greatest) greatest = v3;
            cy = cl;
            prev = @mulAdd(f64, beta, prev, alpha * greatest);
            st.feedPhase(ph, i, h, l, prev);
        }
    }
    const finite = st.finite;
    if (!finite) return null;
    return lb;
}

/// `gpa` provides scratch: `2 * (period + stop_period)` f64 for finite,
/// non-zero input (one pass of block-wise extrema; the generic core answers if
/// that cannot be had), `2 * stop_period` for any other input (the generic core).
pub fn cksp(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, high_stop: []T, low_stop: []T, p: CkspParams) core.AllocError!usize {
    if (ckspBlocks(T, gpa, high, low, close, high_stop, low_stop, p)) |lb| return lb;
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

test "cksp: the block-wise pass equals the generic core bit for bit (f64 and f32), and steps aside for zeros, NaN and overflow" {
    const gpa = std.testing.allocator;
    const n = 700;
    var h: [n]f64 = undefined;
    var l: [n]f64 = undefined;
    var c: [n]f64 = undefined;
    th.walkBars(&h, &l, &c, 7);
    var got: [2][n]f64 = undefined;
    var want: [2][n]f64 = undefined;
    const params = [_]CkspParams{
        .{},
        .{ .period = 2, .stop_period = 1 },
        .{ .period = 2, .multiplier = 0.0, .stop_period = 2 },
        .{ .period = 3, .multiplier = 2.5, .stop_period = 40 },
        .{ .period = 50, .multiplier = 1.5, .stop_period = 3 },
        .{ .period = 17, .stop_period = 17 },
        .{ .period = 10, .stop_period = 9, .unstable = .{ .bars = 25 } },
        .{ .period = 10, .stop_period = 9, .unstable = .auto4 },
        .{ .period = 300, .stop_period = 300 },
        .{ .period = 800, .stop_period = 5 },
    };
    for (params) |p| {
        const lb = try cksp(f64, gpa, &h, &l, &c, &got[0], &got[1], p);
        const lb_ref = try hist.batchAlloc(f64, CkspCore, gpa, .{ &h, &l, &c }, .{ &want[0], &want[1] }, p);
        try std.testing.expectEqual(lb_ref, lb);
        try th.expectSameBits(&want[0], &got[0]);
        try th.expectSameBits(&want[1], &got[1]);
        // the fast pass really ran (it answers, the fallback is for other input)
        try std.testing.expect(ckspBlocks(f64, gpa, &h, &l, &c, &got[0], &got[1], p) != null);
    }
    // f32 in and out: the f64 result rounded once, as the generic core does
    var h32: [n]f32 = undefined;
    var l32: [n]f32 = undefined;
    var c32: [n]f32 = undefined;
    for (&h32, &l32, &c32, h, l, c) |*a, *b, *d, x, y, z| {
        a.* = @floatCast(x);
        b.* = @floatCast(y);
        d.* = @floatCast(z);
    }
    var g32: [2][n]f32 = undefined;
    var w32: [2][n]f32 = undefined;
    const p32: CkspParams = .{ .period = 12, .stop_period = 7 };
    _ = try cksp(f32, gpa, &h32, &l32, &c32, &g32[0], &g32[1], p32);
    _ = try hist.batchAlloc(f32, CkspCore, gpa, .{ &h32, &l32, &c32 }, .{ &w32[0], &w32[1] }, p32);
    for (0..2) |k| for (g32[k], w32[k]) |a, b| try std.testing.expect(th.sameBits(a, b));
    // an allocator with no room for the four buffers: the generic core answers
    var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    try std.testing.expect(ckspBlocks(f64, fa.allocator(), &h, &l, &c, &got[0], &got[1], .{}) == null);
    // a zero, a NaN or an overflow: the generic core answers (null from the fast pass)
    var hz = h;
    hz[100] = 0.0;
    try std.testing.expect(ckspBlocks(f64, gpa, &hz, &l, &c, &got[0], &got[1], .{}) == null);
    var cn = c;
    cn[100] = std.math.nan(f64);
    try std.testing.expect(ckspBlocks(f64, gpa, &h, &l, &cn, &got[0], &got[1], .{}) == null);
    var hb = h;
    var lb2 = l;
    hb[300] = 1e308;
    lb2[300] = -1e308;
    try std.testing.expect(ckspBlocks(f64, gpa, &hb, &lb2, &c, &got[0], &got[1], .{ .multiplier = 1e30 }) == null);
    _ = try cksp(f64, gpa, &hb, &lb2, &c, &got[0], &got[1], .{ .multiplier = 1e30 });
}
