// SPDX-License-Identifier: MIT
//! Cycle indicators ported from TA-Lib 0.8.3 (`ta_HT_DCPERIOD.c`, `ta_HT_DCPHASE.c`,
//! `ta_HT_PHASOR.c`, `ta_HT_SINE.c`, `ta_HT_TRENDLINE.c`, `ta_HT_TRENDMODE.c`,
//! `ta_MAMA.c`, `ta_SWAK_BP.c`, `ta_SWAK_HP.c`, `ta_SWAK_2PHP.c`; BSD-3, see NOTICE).
//!
//! The six Hilbert-transform functions and MAMA share one core (`Hil`): the
//! 4-bar weighted price smoother, the even / odd detrender and quadrature stages
//! and the dominant-cycle period estimate, in the C's operation order (constants
//! as typed f64, the C's `fma` calls as `@mulAdd`). The functions differ only in
//! how many bars the C's initial smoother loop eats before the transform starts
//! (9 bars after the first three: DCPERIOD, PHASOR, MAMA; 34: the rest) and in
//! what they derive from the transform. The recursion is anchored at bar 0 (TA-Lib
//! starts every one of these at the first input and only withholds the output, the
//! lookback is a fixed count plus the unstable period), and the even / odd split
//! follows the absolute bar index, so streaming and batch agree to the bit.
//!
//! The transcendental calls (`sin`, `cos`, `atan`) go through `libm` below: `sin` and
//! `cos` are Zig's builtins, `atan` is `xmath.atan` (correctly rounded, which is what
//! a C library's `atan` is nearly always: the period estimate feeds back into the
//! filter, so a last-bit difference in `atan` would drift along the series).

const std = @import("std");
const core = @import("core.zig");
const xmath = @import("xmath.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const pf = core.pf;

// ── libm ────────────────────────────────────────────────────────────────────

/// The C library calls of the ported sources, in one place.
const libm = struct {
    fn sin(x: f64) f64 {
        return @sin(x);
    }
    fn cos(x: f64) f64 {
        return @cos(x);
    }
    fn atan(x: f64) f64 {
        return xmath.atan(x);
    }
};

// ── drivers ─────────────────────────────────────────────────────────────────

fn conv(comptime D: type, v: anytype) D {
    if (D == @TypeOf(v)) return v;
    return core.to(D, v);
}

fn OutAt(comptime R: type, comptime k: usize) type {
    if (@typeInfo(R) == .@"struct") return @typeInfo(R).@"struct".field_types[k];
    return R;
}
fn outAt(r: anytype, comptime k: usize) OutAt(@TypeOf(r), k) {
    if (@typeInfo(@TypeOf(r)) == .@"struct") return @field(r, @typeInfo(@TypeOf(r)).@"struct".field_names[k]);
    return r;
}
fn Child(comptime S: type) type {
    return @typeInfo(S).pointer.child;
}
/// What an output slot holds before the lookback is satisfied.
fn lead(comptime E: type) E {
    return if (@typeInfo(E) == .float) std.math.nan(E) else 0;
}

/// Batch driver of a single-input core: `outs` is a tuple of output slices. A
/// float slot is NaN in the lead, an integer slot 0; with `nan = .skip` a NaN bar
/// answers the previous output and does not enter the core.
fn batch(comptime T: type, comptime Core: type, p: Core.Params, in: []const T, outs: anytype) Error!usize {
    core.checkFloat(T);
    inline for (0..outs.len) |k| try core.checkLen(in.len, &.{outs[k].len});
    var c = try Core.init(p);
    const skip = p.nan == .skip;
    var last: ?Core.Out = null;
    for (in, 0..) |x, i| {
        const xv: f64 = x;
        var r: ?Core.Out = undefined;
        if (skip and core.isNan(xv)) {
            r = last;
        } else {
            r = c.step(xv);
            last = r;
        }
        inline for (0..outs.len) |k| {
            const E = Child(@TypeOf(outs[k]));
            outs[k][i] = if (r) |v| conv(E, outAt(v, k)) else lead(E);
        }
    }
    return Core.lookback(p);
}

/// Streaming wrapper of a single-input core without history buffer (copy by value).
fn Stream(comptime T: type, comptime Core: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        pub const Output = Core.Outputs(T);
        c: Core,
        skip: bool,
        last: ?Output = null,

        pub fn init(p: Core.Params) Error!Self {
            return .{ .c = try Core.init(p), .skip = p.nan == .skip };
        }
        /// Feed one bar; null until the lookback is satisfied.
        pub fn update(self: *Self, x: T) ?Output {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return self.last;
            const r = self.c.step(xv) orelse return null;
            self.last = conv(Output, r);
            return self.last;
        }
        /// What `update(x)` would answer, without changing the state.
        pub fn peek(self: *const Self, x: T) ?Output {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return self.last;
            var cc = self.c;
            const r = cc.step(xv) orelse return null;
            return conv(Output, r);
        }
        /// The last value `update` produced.
        pub fn value(self: *const Self) ?Output {
            return self.last;
        }
    };
}

// ── the Hilbert-transform core ──────────────────────────────────────────────

const a_coef: f64 = 0.0962;
const b_coef: f64 = 0.5769;
/// `atan(1)` of the C, i.e. pi/4 correctly rounded.
const atan1: f64 = std.math.pi / 4.0;
const rad2deg: f64 = 180.0 / (4.0 * atan1);
const deg2rad: f64 = 1.0 / rad2deg;
const two_pi: f64 = atan1 * 8.0;

/// One 3-slot circular delay of a Hilbert stage with its two scalar taps.
fn stage(arr: *[3]f64, prev: *f64, prev_in: *f64, idx: usize, input: f64, adj: f64) f64 {
    const t = a_coef * input;
    var r = -arr[idx];
    arr[idx] = t;
    r += t;
    r -= prev.*;
    prev.* = b_coef * prev_in.*;
    r += prev.*;
    prev_in.* = input;
    r *= adj;
    return r;
}

const Par = struct {
    det: [3]f64 = @splat(0.0),
    q1: [3]f64 = @splat(0.0),
    ji: [3]f64 = @splat(0.0),
    jq: [3]f64 = @splat(0.0),
    prev_det: f64 = 0.0,
    prev_det_in: f64 = 0.0,
    prev_q1: f64 = 0.0,
    prev_q1_in: f64 = 0.0,
    prev_ji: f64 = 0.0,
    prev_ji_in: f64 = 0.0,
    prev_jq: f64 = 0.0,
    prev_jq_in: f64 = 0.0,
};

/// What one bar of the transform leaves behind.
pub const HBar = struct {
    /// Index of the bar.
    n: usize,
    /// The bar's price.
    x: f64,
    /// The 4-bar weighted price smoother.
    smoothed: f64,
    /// Quadrature component.
    q1: f64,
    /// In-phase component (the detrender delayed by three bars of this parity).
    ip1: f64,
    /// Instantaneous period estimate (after this bar).
    period: f64,
    /// Smoothed period (after this bar).
    smooth_period: f64,
    /// Slot of the smoothed price in `Hil.sm`.
    sidx: usize,
};

const Hil = struct {
    /// First bar that runs the transform (3 + the C's initial smoother loop).
    start: usize,
    n: usize = 0,
    raw: [50]f64 = @splat(0.0),
    sm: [50]f64 = @splat(0.0),
    sidx: usize = 0,
    wsub: f64 = 0.0,
    wsum: f64 = 0.0,
    trailing: f64 = 0.0,
    hidx: usize = 0,
    par: [2]Par = .{ .{}, .{} },
    dl3: [2]f64 = .{ 0.0, 0.0 },
    dl2: [2]f64 = .{ 0.0, 0.0 },
    prev_q2: f64 = 0.0,
    prev_i2: f64 = 0.0,
    re: f64 = 0.0,
    im: f64 = 0.0,
    period: f64 = 0.0,
    smooth_period: f64 = 0.0,

    fn step(self: *Hil, x: f64) ?HBar {
        const n = self.n;
        self.n += 1;
        self.raw[n % 50] = x;
        // The price smoother, initialised like TA_WMA with the first three bars unrolled.
        if (n == 0) {
            self.wsub = x;
            self.wsum = x;
            return null;
        }
        if (n == 1) {
            self.wsub += x;
            self.wsum += x * 2.0;
            return null;
        }
        if (n == 2) {
            self.wsub += x;
            self.wsum += x * 3.0;
            return null;
        }
        self.wsub += x;
        self.wsub -= self.trailing;
        self.wsum += x * 4.0;
        self.trailing = self.raw[(n - 3) % 50];
        const smoothed = self.wsum * 0.1;
        self.wsum -= self.wsub;
        if (n < self.start) return null;

        const adj = @mulAdd(f64, 0.075, self.period, 0.54);
        const sidx = self.sidx;
        self.sm[sidx] = smoothed;
        const pi: usize = n % 2; // 0 even, 1 odd
        const po = &self.par[pi];
        const other = 1 - pi;
        const det = stage(&po.det, &po.prev_det, &po.prev_det_in, self.hidx, smoothed, adj);
        const q1 = stage(&po.q1, &po.prev_q1, &po.prev_q1_in, self.hidx, det, adj);
        const ip1 = self.dl3[pi];
        const ji = stage(&po.ji, &po.prev_ji, &po.prev_ji_in, self.hidx, ip1, adj);
        const jq = stage(&po.jq, &po.prev_jq, &po.prev_jq_in, self.hidx, q1, adj);
        if (pi == 0) {
            self.hidx += 1;
            if (self.hidx == 3) self.hidx = 0;
        }
        const q2 = @mulAdd(f64, 0.2, q1 + ji, 0.8 * self.prev_q2);
        const ip2 = @mulAdd(f64, 0.2, ip1 - jq, 0.8 * self.prev_i2);
        // I1 is the detrender delayed three bars; the other parity picks this bar's up later.
        self.dl3[other] = self.dl2[other];
        self.dl2[other] = det;

        // Adjust the period for the next bar.
        self.re = @mulAdd(f64, 0.8, self.re, 0.2 * @mulAdd(f64, ip2, self.prev_i2, q2 * self.prev_q2));
        self.im = @mulAdd(f64, 0.8, self.im, 0.2 * (ip2 * self.prev_q2 - q2 * self.prev_i2));
        self.prev_q2 = q2;
        self.prev_i2 = ip2;
        const old = self.period;
        var period = old;
        if (self.im != 0.0 and self.re != 0.0) {
            period = 360.0 / (libm.atan(self.im / self.re) * rad2deg);
        }
        var t = 1.5 * old;
        if (period > t) period = t;
        t = 0.67 * old;
        if (period < t) period = t;
        if (period < 6.0) {
            period = 6.0;
        } else if (period > 50.0) {
            period = 50.0;
        }
        period = @mulAdd(f64, 0.2, period, 0.8 * old);
        self.period = period;
        self.smooth_period = @mulAdd(f64, 0.67, self.smooth_period, 0.33 * period);
        self.sidx = if (sidx == 49) 0 else sidx + 1;
        return .{ .n = n, .x = x, .smoothed = smoothed, .q1 = q1, .ip1 = ip1, .period = period, .smooth_period = self.smooth_period, .sidx = sidx };
    }

    /// `(int)(smoothPeriod + 0.5)` of the C, 0 for a NaN.
    fn periodInt(b: HBar) usize {
        const d = b.smooth_period + 0.5;
        if (d >= 0.0) return @intFromFloat(@min(d, 1.0e9));
        return 0;
    }

    /// The dominant-cycle phase (degrees) of the bar, updating `phase` in place
    /// (some branches add to the previous phase).
    fn dcPhase(self: *const Hil, b: HBar, phase: f64) f64 {
        const dci = periodInt(b);
        var real: f64 = 0.0;
        var imag: f64 = 0.0;
        var idx = b.sidx;
        var i: usize = 0;
        const dcf: f64 = @floatFromInt(dci);
        while (i < dci) : (i += 1) {
            const t = @as(f64, @floatFromInt(i)) * two_pi / dcf;
            const v = self.sm[idx];
            real += libm.sin(t) * v;
            imag += libm.cos(t) * v;
            idx = if (idx == 0) 49 else idx - 1;
        }
        var ph = phase;
        const ai = @abs(imag);
        if (ai > 0.0) {
            ph = libm.atan(real / imag) * rad2deg;
        } else if (ai <= 0.01) {
            if (real < 0.0) {
                ph -= 90.0;
            } else if (real > 0.0) {
                ph += 90.0;
            }
        }
        ph += 90.0;
        // Compensate for one bar lag of the weighted moving average.
        ph += 360.0 / b.smooth_period;
        if (imag < 0.0) ph += 180.0;
        if (ph > 315.0) ph -= 360.0;
        return ph;
    }

    /// The raw-price average over the dominant cycle period.
    fn rawAverage(self: *const Hil, b: HBar) f64 {
        const dci = periodInt(b);
        var sum: f64 = 0.0;
        var i: usize = 0;
        while (i < 50) : (i += 1) {
            if (i < dci) sum += self.raw[(b.n + 50 - i) % 50];
        }
        if (dci > 0) sum = sum / @as(f64, @floatFromInt(dci));
        return sum;
    }
};

// ── HT_* ────────────────────────────────────────────────────────────────────

pub const HtParams = struct {
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

pub fn PhasorOut(comptime T: type) type {
    return struct { in_phase: T, quadrature: T };
}
pub fn SineOut(comptime T: type) type {
    return struct { sine: T, lead_sine: T };
}

pub const HtKind = enum { dcperiod, dcphase, phasor, sine, trendline, trendmode };

pub fn HtCore(comptime kind: HtKind) type {
    return struct {
        const Self = @This();
        pub const Params = HtParams;
        pub const Out = switch (kind) {
            .phasor => PhasorOut(f64),
            .sine => SineOut(f64),
            .trendmode => i8,
            else => f64,
        };
        pub fn Outputs(comptime T: type) type {
            return switch (kind) {
                .phasor => PhasorOut(T),
                .sine => SineOut(T),
                .trendmode => i8,
                else => T,
            };
        }
        h: Hil,
        lb: usize,
        n: usize = 0,
        dcphase: f64 = 0.0,
        prev_dcphase: f64 = 0.0,
        sine: f64 = 0.0,
        lead_sine: f64 = 0.0,
        it1: f64 = 0.0,
        it2: f64 = 0.0,
        it3: f64 = 0.0,
        days: i64 = 0,

        pub fn validate(p: HtParams) Error!void {
            try p.unstable.check();
        }
        pub fn lookback(p: HtParams) usize {
            return switch (kind) {
                .dcperiod, .phasor => 32 + p.unstable.get(80 + 50 * 4, 80 + 50 * 8),
                .dcphase, .sine => 63 + p.unstable.get(80 + 50 * 4, 80 + 50 * 8),
                .trendline, .trendmode => 63 + p.unstable.get(120 + 20 * 4, 120 + 20 * 8),
            };
        }
        pub fn init(p: HtParams) Error!Self {
            try validate(p);
            // 3 unrolled bars + the C's smoother loop (9 or 34 bars).
            const start: usize = switch (kind) {
                .dcperiod, .phasor => 12,
                else => 37,
            };
            return .{ .h = .{ .start = start }, .lb = lookback(p) };
        }
        pub fn step(self: *Self, x: f64) ?Out {
            const bar = self.h.step(x);
            self.n += 1;
            const b = bar orelse return null;
            const emit = b.n >= self.lb;
            switch (kind) {
                .dcperiod => return if (emit) b.smooth_period else null,
                .phasor => return if (emit) .{ .in_phase = b.ip1, .quadrature = b.q1 } else null,
                .dcphase => {
                    self.dcphase = self.h.dcPhase(b, self.dcphase);
                    return if (emit) self.dcphase else null;
                },
                .sine => {
                    self.dcphase = self.h.dcPhase(b, self.dcphase);
                    return if (emit) .{ .sine = libm.sin(self.dcphase * deg2rad), .lead_sine = libm.sin((self.dcphase + 45.0) * deg2rad) } else null;
                },
                .trendline => {
                    const avg = self.h.rawAverage(b);
                    const tl = (@mulAdd(f64, 2.0, self.it2, @mulAdd(f64, 4.0, avg, 3.0 * self.it1)) + self.it3) / 10.0;
                    self.it3 = self.it2;
                    self.it2 = self.it1;
                    self.it1 = avg;
                    return if (emit) tl else null;
                },
                .trendmode => {
                    self.prev_dcphase = self.dcphase;
                    self.dcphase = self.h.dcPhase(b, self.dcphase);
                    const prev_sine = self.sine;
                    const prev_lead = self.lead_sine;
                    self.sine = libm.sin(self.dcphase * deg2rad);
                    self.lead_sine = libm.sin((self.dcphase + 45.0) * deg2rad);
                    const avg = self.h.rawAverage(b);
                    const tl = (@mulAdd(f64, 2.0, self.it2, @mulAdd(f64, 4.0, avg, 3.0 * self.it1)) + self.it3) / 10.0;
                    self.it3 = self.it2;
                    self.it2 = self.it1;
                    self.it1 = avg;
                    var trend: i8 = 1;
                    if ((self.sine > self.lead_sine and prev_sine <= prev_lead) or (self.sine < self.lead_sine and prev_sine >= prev_lead)) {
                        self.days = 0;
                        trend = 0;
                    }
                    self.days += 1;
                    const sp = b.smooth_period;
                    if (@as(f64, @floatFromInt(self.days)) < 0.5 * sp) trend = 0;
                    const d = self.dcphase - self.prev_dcphase;
                    if (sp != 0.0 and (d > 0.67 * 360.0 / sp and d < 1.5 * 360.0 / sp)) trend = 0;
                    const price = self.h.sm[b.sidx];
                    if (tl != 0.0 and @abs((price - tl) / tl) >= 0.015) trend = 1;
                    return if (emit) trend else null;
                },
            }
        }
    };
}

pub const HtDcperiodCore = HtCore(.dcperiod);
pub const HtDcphaseCore = HtCore(.dcphase);
pub const HtPhasorCore = HtCore(.phasor);
pub const HtSineCore = HtCore(.sine);
pub const HtTrendlineCore = HtCore(.trendline);
pub const HtTrendmodeCore = HtCore(.trendmode);

pub fn htDcperiodLookback(p: HtParams) Error!usize {
    try HtDcperiodCore.validate(p);
    return HtDcperiodCore.lookback(p);
}
/// Smoothed dominant-cycle period (bars).
pub fn htDcperiod(comptime T: type, in: []const T, out: []T, p: HtParams) Error!usize {
    return batch(T, HtDcperiodCore, p, in, .{out});
}
pub fn HtDcperiodStream(comptime T: type) type {
    return Stream(T, HtDcperiodCore);
}

pub fn htDcphaseLookback(p: HtParams) Error!usize {
    try HtDcphaseCore.validate(p);
    return HtDcphaseCore.lookback(p);
}
/// Dominant-cycle phase in degrees.
pub fn htDcphase(comptime T: type, in: []const T, out: []T, p: HtParams) Error!usize {
    return batch(T, HtDcphaseCore, p, in, .{out});
}
pub fn HtDcphaseStream(comptime T: type) type {
    return Stream(T, HtDcphaseCore);
}

pub fn htPhasorLookback(p: HtParams) Error!usize {
    try HtPhasorCore.validate(p);
    return HtPhasorCore.lookback(p);
}
/// In-phase and quadrature components of the detrended price.
pub fn htPhasor(comptime T: type, in: []const T, in_phase: []T, quadrature: []T, p: HtParams) Error!usize {
    return batch(T, HtPhasorCore, p, in, .{ in_phase, quadrature });
}
pub fn HtPhasorStream(comptime T: type) type {
    return Stream(T, HtPhasorCore);
}

pub fn htSineLookback(p: HtParams) Error!usize {
    try HtSineCore.validate(p);
    return HtSineCore.lookback(p);
}
/// Sine wave and lead sine wave (45 degrees ahead) of the dominant-cycle phase.
pub fn htSine(comptime T: type, in: []const T, sine: []T, lead_sine: []T, p: HtParams) Error!usize {
    return batch(T, HtSineCore, p, in, .{ sine, lead_sine });
}
pub fn HtSineStream(comptime T: type) type {
    return Stream(T, HtSineCore);
}

pub fn htTrendlineLookback(p: HtParams) Error!usize {
    try HtTrendlineCore.validate(p);
    return HtTrendlineCore.lookback(p);
}
/// Instantaneous trendline.
pub fn htTrendline(comptime T: type, in: []const T, out: []T, p: HtParams) Error!usize {
    return batch(T, HtTrendlineCore, p, in, .{out});
}
pub fn HtTrendlineStream(comptime T: type) type {
    return Stream(T, HtTrendlineCore);
}

pub fn htTrendmodeLookback(p: HtParams) Error!usize {
    try HtTrendmodeCore.validate(p);
    return HtTrendmodeCore.lookback(p);
}
/// Trend (1) or cycle (0) mode; `out` is 0 in the lead.
pub fn htTrendmode(comptime T: type, in: []const T, out: []i8, p: HtParams) Error!usize {
    return batch(T, HtTrendmodeCore, p, in, .{out});
}
pub fn HtTrendmodeStream(comptime T: type) type {
    return Stream(T, HtTrendmodeCore);
}

// ── MAMA ────────────────────────────────────────────────────────────────────

pub const MamaParams = struct {
    fast_limit: f64 = 0.5,
    slow_limit: f64 = 0.05,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

pub fn MamaOut(comptime T: type) type {
    return struct { mama: T, fama: T };
}

fn limitOk(x: f64) bool {
    return x >= 1e-2 and x <= 9.9e-1;
}

/// MESA adaptive moving average and its following average (`ta_MAMA.c`).
pub const MamaCore = struct {
    pub const Params = MamaParams;
    pub const Out = MamaOut(f64);
    pub fn Outputs(comptime T: type) type {
        return MamaOut(T);
    }
    h: Hil,
    lb: usize,
    fast: f64,
    slow: f64,
    mama: f64 = 0.0,
    fama: f64 = 0.0,
    prev_phase: f64 = 0.0,

    pub fn validate(p: MamaParams) Error!void {
        if (!limitOk(p.fast_limit) or !limitOk(p.slow_limit)) return error.BadParam;
        try p.unstable.check();
    }
    /// The lookback for the given limits: 32 plus the unstable period, whose AUTO
    /// counts grow with `ceil(2K / max(fast, slow))`.
    pub fn lookbackOf(fast: f64, slow: f64, un: Unstable) usize {
        const limit = if (fast > slow) fast else slow;
        const c4: usize = @intFromFloat(@ceil(20.0 / limit));
        const c8: usize = @intFromFloat(@ceil(38.0 / limit));
        return 32 + un.get(80 + 50 * 4 + c4, 80 + 50 * 8 + c8);
    }
    pub fn lookback(p: MamaParams) usize {
        return lookbackOf(p.fast_limit, p.slow_limit, p.unstable);
    }
    pub fn init(p: MamaParams) Error!MamaCore {
        try validate(p);
        return .{ .h = .{ .start = 12 }, .lb = lookback(p), .fast = p.fast_limit, .slow = p.slow_limit };
    }
    pub fn step(self: *MamaCore, x: f64) ?Out {
        const b = self.h.step(x) orelse return null;
        // The phase of the in-phase / quadrature pair drives the adaptive alpha.
        var phase: f64 = 0.0;
        if (b.ip1 != 0.0) phase = libm.atan(b.q1 / b.ip1) * rad2deg;
        var alpha = self.prev_phase - phase;
        self.prev_phase = phase;
        if (alpha < 1.0) alpha = 1.0;
        if (alpha > 1.0) {
            alpha = self.fast / alpha;
            if (alpha < self.slow) alpha = self.slow;
        } else {
            alpha = self.fast;
        }
        self.mama = @mulAdd(f64, 1.0 - alpha, self.mama, alpha * b.x);
        alpha *= 0.5;
        self.fama = @mulAdd(f64, 1.0 - alpha, self.fama, alpha * self.mama);
        return if (b.n >= self.lb) .{ .mama = self.mama, .fama = self.fama } else null;
    }
};

/// MAMA in the moving-average slot of `ma` & co. (`TA_MA` with `TA_MAType_MAMA`:
/// the period is ignored, limits 0.5 / 0.05, the MAMA line is the output).
pub const MamaMaCore = struct {
    c: MamaCore,
    n: usize = 0,

    pub fn lookback(un: Unstable) usize {
        return MamaCore.lookbackOf(0.5, 0.05, un);
    }
    pub fn init(un: Unstable) Error!MamaMaCore {
        return .{ .c = try MamaCore.init(.{ .unstable = un }) };
    }
    pub fn step(self: *MamaMaCore, src: anytype, x: f64) ?f64 {
        _ = src;
        self.n += 1;
        const r = self.c.step(x) orelse return null;
        return r.mama;
    }
};

pub fn mamaLookback(p: MamaParams) Error!usize {
    try MamaCore.validate(p);
    return MamaCore.lookback(p);
}
pub fn mama(comptime T: type, in: []const T, out_mama: []T, out_fama: []T, p: MamaParams) Error!usize {
    return batch(T, MamaCore, p, in, .{ out_mama, out_fama });
}
pub fn MamaStream(comptime T: type) type {
    return Stream(T, MamaCore);
}

// ── SWAK_BP / SWAK_HP / SWAK_2PHP ───────────────────────────────────────────

const pi64: f64 = 3.141592653589793;

pub const SwakBpParams = struct {
    period: usize = 20,
    delta: f64 = 0.1,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Ehlers' band-pass row of the Swiss Army Knife (`ta_SWAK_BP.c`).
pub const SwakBpCore = struct {
    pub const Params = SwakBpParams;
    pub const Out = f64;
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    lb: usize,
    c0: f64,
    a1: f64,
    a2: f64,
    n: usize = 0,
    x1: f64 = 0.0,
    x2: f64 = 0.0,
    y1: f64 = 0.0,
    y2: f64 = 0.0,

    pub fn validate(p: SwakBpParams) Error!void {
        if (p.period < 5 or p.period > 2000) return error.BadParam;
        if (!(p.delta >= 5e-2 and p.delta <= 5e-1)) return error.BadParam;
        try p.unstable.check();
    }
    pub fn lookback(p: SwakBpParams) usize {
        const c4: usize = @intFromFloat(@ceil(pf(11 * p.period) / (6.0 * p.delta)));
        const c8: usize = @intFromFloat(@ceil(pf(20 * p.period) / (6.0 * p.delta)));
        return p.unstable.get(c4, c8);
    }
    pub fn init(p: SwakBpParams) Error!SwakBpCore {
        try validate(p);
        const w = 2.0 * pi64 / pf(p.period);
        const beta = libm.cos(w);
        const t = 4.0 * pi64 * p.delta / pf(p.period);
        // (1 - sin t) / cos t rather than the paper's gamma - sqrt(gamma^2 - 1): see the C.
        const abp = (1.0 - libm.sin(t)) / libm.cos(t);
        return .{ .lb = lookback(p), .c0 = (1.0 - abp) / 2.0, .a1 = beta * (1.0 + abp), .a2 = -abp };
    }
    pub fn step(self: *SwakBpCore, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.x1 = x;
            self.x2 = x;
        }
        const y = @mulAdd(f64, self.a1, self.y1, @mulAdd(f64, self.a2, self.y2, self.c0 * (x - self.x2)));
        self.x2 = self.x1;
        self.x1 = x;
        self.y2 = self.y1;
        self.y1 = y;
        return if (n >= self.lb) y else null;
    }
};

pub fn swakBpLookback(p: SwakBpParams) Error!usize {
    try SwakBpCore.validate(p);
    return SwakBpCore.lookback(p);
}
pub fn swakBp(comptime T: type, in: []const T, out: []T, p: SwakBpParams) Error!usize {
    return batch(T, SwakBpCore, p, in, .{out});
}
pub fn SwakBpStream(comptime T: type) type {
    return Stream(T, SwakBpCore);
}

pub const SwakHpParams = struct {
    period: usize = 20,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Ehlers' one-pole high-pass row (`ta_SWAK_HP.c`).
pub const SwakHpCore = struct {
    pub const Params = SwakHpParams;
    pub const Out = f64;
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    lb: usize,
    c0: f64,
    a1: f64,
    n: usize = 0,
    x1: f64 = 0.0,
    y1: f64 = 0.0,

    pub fn validate(p: SwakHpParams) Error!void {
        if (p.period < 5 or p.period > 100000) return error.BadParam;
        try p.unstable.check();
    }
    pub fn lookback(p: SwakHpParams) usize {
        return p.unstable.get((10 * p.period + 5) / 6, (19 * p.period + 5) / 6);
    }
    pub fn init(p: SwakHpParams) Error!SwakHpCore {
        try validate(p);
        const h = pi64 / pf(p.period);
        const sh = libm.sin(h);
        const ch = libm.cos(h);
        const a1p = 2.0 * sh * (ch - sh) / (1.0 - 2.0 * sh * sh);
        return .{ .lb = lookback(p), .c0 = 1.0 - a1p / 2.0, .a1 = 1.0 - a1p };
    }
    pub fn step(self: *SwakHpCore, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) self.x1 = x;
        const y = @mulAdd(f64, self.a1, self.y1, self.c0 * (x - self.x1));
        self.x1 = x;
        self.y1 = y;
        return if (n >= self.lb) y else null;
    }
};

pub fn swakHpLookback(p: SwakHpParams) Error!usize {
    try SwakHpCore.validate(p);
    return SwakHpCore.lookback(p);
}
pub fn swakHp(comptime T: type, in: []const T, out: []T, p: SwakHpParams) Error!usize {
    return batch(T, SwakHpCore, p, in, .{out});
}
pub fn SwakHpStream(comptime T: type) type {
    return Stream(T, SwakHpCore);
}

pub const Swak2phpParams = struct {
    period: usize = 20,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Ehlers' two-pole high-pass row (`ta_SWAK_2PHP.c`).
pub const Swak2phpCore = struct {
    pub const Params = Swak2phpParams;
    pub const Out = f64;
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    lb: usize,
    c0: f64,
    a1: f64,
    a2: f64,
    n: usize = 0,
    x1: f64 = 0.0,
    x2: f64 = 0.0,
    y1: f64 = 0.0,
    y2: f64 = 0.0,

    pub fn validate(p: Swak2phpParams) Error!void {
        if (p.period < 2 or p.period > 10000) return error.BadParam;
        try p.unstable.check();
    }
    pub fn lookback(p: Swak2phpParams) usize {
        return p.unstable.get(((10 + 3) * (p.period + 2) + 8) / 9, ((19 + 3) * (p.period + 2) + 8) / 9);
    }
    pub fn init(p: Swak2phpParams) Error!Swak2phpCore {
        try validate(p);
        const s = libm.sin(pi64 / pf(p.period));
        const b2p = 2.415 * (2.0 * s * s);
        const a2p = -b2p + @sqrt(@mulAdd(f64, b2p, b2p, 2.0 * b2p));
        const om = 1.0 - a2p;
        return .{ .lb = lookback(p), .c0 = (1.0 - a2p / 2.0) * (1.0 - a2p / 2.0), .a1 = 2.0 * om, .a2 = -(om * om) };
    }
    pub fn step(self: *Swak2phpCore, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.x1 = x;
            self.x2 = x;
        }
        const y = @mulAdd(f64, self.a1, self.y1, @mulAdd(f64, self.a2, self.y2, self.c0 * (x - 2.0 * self.x1 + self.x2)));
        self.x2 = self.x1;
        self.x1 = x;
        self.y2 = self.y1;
        self.y1 = y;
        return if (n >= self.lb) y else null;
    }
};

pub fn swak2phpLookback(p: Swak2phpParams) Error!usize {
    try Swak2phpCore.validate(p);
    return Swak2phpCore.lookback(p);
}
pub fn swak2php(comptime T: type, in: []const T, out: []T, p: Swak2phpParams) Error!usize {
    return batch(T, Swak2phpCore, p, in, .{out});
}
pub fn Swak2phpStream(comptime T: type) type {
    return Stream(T, Swak2phpCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const th = @import("testhelp.zig");

fn series(n: usize, seed: u64) [400]f64 {
    var xs: [400]f64 = undefined;
    th.walk(&xs, seed);
    _ = n;
    return xs;
}

/// Batch against stream and `peek` for a single float output.
fn checkSingle(comptime Core: type, comptime batchFn: anytype, p: Core.Params, xs: []const f64) !void {
    const gpa = testing.allocator;
    const out = try gpa.alloc(f64, xs.len);
    defer gpa.free(out);
    const lb = try batchFn(f64, xs, out, p);
    try testing.expectEqual(Core.lookback(p), lb);
    try testing.expectEqual(lb, th.leadingNan(out));
    var s = try Stream(f64, Core).init(p);
    for (xs, out) |x, want| {
        const pk = s.peek(x);
        const got = s.update(x);
        try testing.expect(th.sameOpt(got, want));
        try testing.expect((pk == null) == (got == null) and (pk == null or th.sameBits(pk.?, got.?)));
    }
}

test "ht dcperiod, dcphase, trendline: batch == stream, lookback == NaN lead" {
    const xs = series(400, 11);
    for ([_]Unstable{ .{ .bars = 0 }, .{ .bars = 7 }, .auto4 }) |u| {
        const p: HtParams = .{ .unstable = u };
        try checkSingle(HtDcperiodCore, htDcperiod, p, &xs);
        try checkSingle(HtDcphaseCore, htDcphase, p, &xs);
        try checkSingle(HtTrendlineCore, htTrendline, p, &xs);
    }
    try testing.expectEqual(@as(usize, 32), try htDcperiodLookback(.{}));
    try testing.expectEqual(@as(usize, 63), try htDcphaseLookback(.{}));
    try testing.expectEqual(@as(usize, 63), try htTrendlineLookback(.{}));
    try testing.expectEqual(@as(usize, 32 + 280), try htDcperiodLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 63 + 480), try htDcphaseLookback(.{ .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, 63 + 200), try htTrendlineLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 63 + 280), try htTrendmodeLookback(.{ .unstable = .auto8 }));
}

test "ht phasor, sine, mama and trendmode: batch == stream, lookback == lead" {
    const xs = series(400, 12);
    const gpa = testing.allocator;
    var o: [2][]f64 = undefined;
    for (&o) |*s| s.* = try gpa.alloc(f64, xs.len);
    defer for (o) |s| gpa.free(s);
    var tm = try gpa.alloc(i8, xs.len);
    defer gpa.free(tm);

    const lp = try htPhasor(f64, &xs, o[0], o[1], .{});
    try testing.expectEqual(@as(usize, 32), lp);
    try testing.expectEqual(lp, th.leadingNan(o[0]));
    try testing.expectEqual(lp, th.leadingNan(o[1]));
    var sp = try HtPhasorStream(f64).init(.{});
    for (xs, 0..) |x, i| {
        const pk = sp.peek(x);
        const got = sp.update(x);
        try testing.expect((got == null) == std.math.isNan(o[0][i]));
        if (got) |g| {
            try testing.expect(th.sameBits(g.in_phase, o[0][i]) and th.sameBits(g.quadrature, o[1][i]));
            try testing.expect(th.sameBits(pk.?.in_phase, g.in_phase));
        }
    }

    const ls = try htSine(f64, &xs, o[0], o[1], .{});
    try testing.expectEqual(@as(usize, 63), ls);
    try testing.expectEqual(ls, th.leadingNan(o[0]));
    var ss = try HtSineStream(f64).init(.{});
    for (xs, 0..) |x, i| {
        const got = ss.update(x);
        try testing.expect((got == null) == std.math.isNan(o[0][i]));
        if (got) |g| try testing.expect(th.sameBits(g.sine, o[0][i]) and th.sameBits(g.lead_sine, o[1][i]));
    }
    for (o[0][ls..], o[1][ls..]) |a, b| try testing.expect(@abs(a) <= 1.0 and @abs(b) <= 1.0);

    const lm = try mama(f64, &xs, o[0], o[1], .{});
    try testing.expectEqual(@as(usize, 32), lm);
    try testing.expectEqual(lm, th.leadingNan(o[1]));
    var sm = try MamaStream(f64).init(.{});
    for (xs, 0..) |x, i| {
        const pk = sm.peek(x);
        const got = sm.update(x);
        try testing.expect((got == null) == std.math.isNan(o[0][i]));
        if (got) |g| {
            try testing.expect(th.sameBits(g.mama, o[0][i]) and th.sameBits(g.fama, o[1][i]));
            try testing.expect(th.sameBits(pk.?.fama, g.fama));
        }
    }

    const lt = try htTrendmode(f64, &xs, tm, .{});
    try testing.expectEqual(@as(usize, 63), lt);
    for (tm[0..lt]) |v| try testing.expectEqual(@as(i8, 0), v);
    var st = try HtTrendmodeStream(f64).init(.{});
    var ones: usize = 0;
    for (xs, 0..) |x, i| {
        const pk = st.peek(x);
        const got = st.update(x);
        try testing.expect((got == null) == (i < lt));
        if (got) |g| {
            try testing.expectEqual(tm[i], g);
            try testing.expectEqual(g, pk.?);
            try testing.expect(g == 0 or g == 1);
            ones += @intCast(g);
        }
    }
    try testing.expect(ones > 0 and ones < xs.len - lt); // both modes occur on a random walk
}

test "swak bp, hp, 2php: batch == stream; a constant series has no band-pass or high-pass output" {
    var xs: [1000]f64 = undefined; // longer than the auto8 lookback (667)
    th.walk(&xs, 13);
    for ([_]Unstable{ .{ .bars = 0 }, .{ .bars = 9 }, .auto4, .auto8 }) |u| {
        try checkSingle(SwakBpCore, swakBp, .{ .unstable = u }, &xs);
        try checkSingle(SwakBpCore, swakBp, .{ .period = 7, .delta = 0.3, .unstable = u }, &xs);
        try checkSingle(SwakHpCore, swakHp, .{ .unstable = u }, &xs);
        try checkSingle(Swak2phpCore, swak2php, .{ .unstable = u }, &xs);
        try checkSingle(Swak2phpCore, swak2php, .{ .period = 2, .unstable = u }, &xs);
    }
    // A DC-gain-zero row answers 0 on a constant input (the C starts in that steady state).
    const flat: [60]f64 = @splat(42.5);
    var out: [60]f64 = undefined;
    _ = try swakBp(f64, &flat, &out, .{});
    for (out) |v| try testing.expectEqual(@as(f64, 0.0), v);
    _ = try swakHp(f64, &flat, &out, .{});
    for (out) |v| try testing.expectEqual(@as(f64, 0.0), v);
    _ = try swak2php(f64, &flat, &out, .{});
    for (out) |v| try testing.expectEqual(@as(f64, 0.0), v);
    // Lookbacks are the unstable count only: 0 by default.
    try testing.expectEqual(@as(usize, 0), try swakBpLookback(.{}));
    // ceil(11 * 20 / (6 * 0.1)) = ceil(366.67) = 367; ceil(20 * 20 / 0.6) = 667.
    try testing.expectEqual(@as(usize, 367), try swakBpLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 667), try swakBpLookback(.{ .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, (10 * 20 + 5) / 6), try swakHpLookback(.{ .unstable = .auto4 }));
}

test "mama: limits and the MA slot" {
    try testing.expectError(error.BadParam, mamaLookback(.{ .fast_limit = 0.005 }));
    try testing.expectError(error.BadParam, mamaLookback(.{ .slow_limit = 1.0 }));
    try testing.expectError(error.BadParam, mamaLookback(.{ .fast_limit = std.math.nan(f64) }));
    // limit 0.5: count4 = ceil(20 / 0.5) = 40, count8 = ceil(38 / 0.5) = 76.
    try testing.expectEqual(@as(usize, 32 + 280 + 40), try mamaLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 32 + 480 + 76), try mamaLookback(.{ .unstable = .auto8 }));
    // limit 0.01: ceil(2000) and ceil(3800).
    try testing.expectEqual(@as(usize, 32 + 280 + 2000), try mamaLookback(.{ .fast_limit = 0.01, .slow_limit = 0.01, .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 32 + 480 + 3800), try mamaLookback(.{ .fast_limit = 0.01, .slow_limit = 0.01, .unstable = .auto8 }));
}

test "ht functions: BadParam for a huge unstable, length mismatch; nan skip; f32" {
    const xs = series(400, 14);
    var out: [400]f64 = undefined;
    try testing.expectError(error.BadParam, htDcperiodLookback(.{ .unstable = .{ .bars = core.max_unstable + 1 } }));
    try testing.expectError(error.BadParam, htDcperiod(f64, xs[0..10], out[0..9], .{}));
    try testing.expectError(error.BadParam, swakBp(f64, &xs, &out, .{ .period = 4 }));
    try testing.expectError(error.BadParam, swakBp(f64, &xs, &out, .{ .period = 2001 }));
    try testing.expectError(error.BadParam, swakBp(f64, &xs, &out, .{ .delta = 0.04 }));
    try testing.expectError(error.BadParam, swakBp(f64, &xs, &out, .{ .delta = 0.51 }));
    try testing.expectError(error.BadParam, swakHp(f64, &xs, &out, .{ .period = 4 }));
    try testing.expectError(error.BadParam, swak2php(f64, &xs, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, swak2php(f64, &xs, &out, .{ .period = 10001 }));
    // too short for any output: all lead
    const lb = try htDcphase(f64, xs[0..30], out[0..30], .{});
    try testing.expectEqual(@as(usize, 63), lb);
    for (out[0..30]) |v| try testing.expect(std.math.isNan(v));
    // nan skip: the output at the NaN bar is the previous one, the others equal the run without it
    var ys = xs;
    ys[100] = std.math.nan(f64);
    var a: [400]f64 = undefined;
    var b: [399]f64 = undefined;
    _ = try htDcperiod(f64, &ys, &a, .{ .nan = .skip });
    var clean: [399]f64 = undefined;
    @memcpy(clean[0..100], xs[0..100]);
    @memcpy(clean[100..], xs[101..]);
    _ = try htDcperiod(f64, &clean, &b, .{});
    try testing.expect(th.sameBits(a[100], a[99]));
    try testing.expect(th.sameBits(a[101], b[100]));
    try testing.expect(th.sameBits(a[399], b[398]));
    // f32 input: the f64 math runs on the rounded input, the output is rounded once
    var x32: [400]f32 = undefined;
    var x64: [400]f64 = undefined;
    for (&x32, &x64, xs) |*d, *e, x| {
        d.* = @floatCast(x);
        e.* = d.*;
    }
    var o32: [400]f32 = undefined;
    var o64: [400]f64 = undefined;
    _ = try htDcperiod(f32, &x32, &o32, .{});
    _ = try htDcperiod(f64, &x64, &o64, .{});
    for (o32[32..], o64[32..]) |p, q| try testing.expectEqual(@as(f32, @floatCast(q)), p);
}
