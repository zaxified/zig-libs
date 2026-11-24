// SPDX-License-Identifier: MIT
//! MIDPOINT, MIDPRICE, FRAMA, VWMA and MAVP, ported from TA-Lib 0.8.3
//! (`ta_MIDPOINT.c`, `ta_MIDPRICE.c`, `ta_FRAMA.c`, `ta_VWMA.c`, `ta_MAVP.c`;
//! BSD-3, see NOTICE).

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const window = @import("window.zig");
const vmath = @import("vmath.zig");
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
/// The batch runs TA-Lib's block scan (`window.hiLoBlocks`) up to `window.block_cap` bars of period, the
/// streaming automaton above it; the two differ only where a NaN or a 0.0 / -0.0 tie is in the window.
pub fn midpoint(comptime T: type, in: []const T, out: []T, p: MidParams) Error!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{out.len});
    try MidpointCore.validate(p);
    const Sink = struct {
        out: []T,
        pub inline fn put(s: @This(), k: usize, h: f64, l: f64) void {
            s.out[k] = core.to(T, (h + l) / 2.0);
        }
    };
    if (!window.hiLoBlocks(T, in, in, p.period, Sink{ .out = out })) return smooth.batch1(T, MidpointCore, in, out, p);
    const lb = MidpointCore.lookback(p);
    for (out[0..@min(lb, out.len)]) |*o| o.* = std.math.nan(T);
    return lb;
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
/// The batch runs TA-Lib's block scan up to `window.block_cap` bars of period, as `midpoint` does.
pub fn midprice(comptime T: type, high: []const T, low: []const T, out: []T, p: MidParams) Error!usize {
    core.checkFloat(T);
    try core.checkLen(high.len, &.{ low.len, out.len });
    try MidpriceCore.validate(p);
    const Sink = struct {
        out: []T,
        pub inline fn put(s: @This(), k: usize, h: f64, l: f64) void {
            s.out[k] = core.to(T, (h + l) / 2.0);
        }
    };
    if (!window.hiLoBlocks(T, high, low, p.period, Sink{ .out = out }))
        return hist.batch(T, MidpriceCore, .{ high, low }, .{out}, p, &.{});
    const lb = MidpriceCore.lookback(p);
    for (out[0..@min(lb, out.len)]) |*o| o.* = std.math.nan(T);
    return lb;
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
    if (T == f64 and p.nan != .skip) {
        try FramaCore.validate(p);
        try core.checkLen(high.len, &.{ low.len, out.len });
        framaRun(high, low, out, p);
        return FramaCore.lookback(p);
    }
    return hist.batch(T, FramaCore, .{ high, low }, .{out}, p, &.{});
}

/// The f64 batch of `FramaCore.step`, bitwise. The core's older half-window extremes (`hi2`, `lo2`) are the same
/// automaton as the newer ones fed the same bars `half` bars later, so here all four run as `ExtCore.Run` over the
/// slices, the older pair at bar `n - half`; the state stays in registers, and the extremes of the whole window
/// are one two-lane vector select ({highest, -lowest}; negation is exact) instead of two ternaries LLVM turns into
/// branches.
fn framaRun(high: []const f64, low: []const f64, out: []f64, p: FramaParams) void {
    const n = high.len;
    const per = p.period;
    const half = per / 2;
    const lb = FramaCore.lookback(p);
    const V = @Vector(2, f64);
    var h1 = MaxCore.Run{ .p = half, .idx1 = 0, .val = 0.0 };
    var l1 = MinCore.Run{ .p = half, .idx1 = 0, .val = 0.0 };
    var h2 = MaxCore.Run{ .p = half, .idx1 = 0, .val = 0.0 };
    var l2 = MinCore.Run{ .p = half, .idx1 = 0, .val = 0.0 };
    var prev: f64 = 0.0;
    const warm = @min(n, per);
    for (0..warm) |i| {
        // The automatons answer from their window's last bar on; every bar after that must be stepped.
        if (i + 1 >= half) {
            _ = h1.bar(f64, high, i);
            _ = l1.bar(f64, low, i);
        }
        if (i + 1 >= per) {
            _ = h2.bar(f64, high, i - half);
            _ = l2.bar(f64, low, i - half);
            prev = (high[i] + low[i]) / 2.0;
        }
        out[i] = std.math.nan(f64);
    }
    // The ranges of a block of bars first (the automatons do not depend on the average), then the block's
    // `exp(scale * log(q))` four lanes at a time (`vmath.log4` / `exp4`, bit for bit `@log` / `@exp`), then the
    // recurrence of the average.
    const block = 64;
    var qs: [block]f64 = undefined;
    var prices: [block]f64 = undefined;
    var live: [block]bool = undefined;
    var alphas: [block]f64 = undefined;
    var i = warm;
    while (i < n) {
        const len = @min(block, n - i);
        for (0..len) |j| {
            const k = i + j;
            const hi1 = h1.bar(f64, high, k);
            const lo1 = l1.bar(f64, low, k);
            const hi2 = h2.bar(f64, high, k - half);
            const lo2 = l2.bar(f64, low, k - half);
            prices[j] = (high[k] + low[k]) / 2.0;
            const r1 = hi1 - lo1;
            const r2 = hi2 - lo2;
            const e1: V = .{ hi1, -lo1 };
            const e2: V = .{ hi2, -lo2 };
            const e = @select(f64, e1 > e2, e1, e2);
            const r = e[0] - (-e[1]);
            live[j] = r1 > 0.0 and r2 > 0.0 and r1 + r2 > r;
            qs[j] = if (live[j]) (r1 + r2) / r else 1.5;
        }
        @memset(qs[len..], 1.5);
        var q: usize = 0;
        while (q < block) : (q += 4) {
            const v: vmath.V = qs[q..][0..4].*;
            alphas[q..][0..4].* = vmath.exp4(vmath.log4(v) * @as(vmath.V, @splat(frama_scale)));
        }
        for (0..len) |j| {
            const k = i + j;
            if (live[j]) {
                const alpha = alphas[j];
                prev = @mulAdd(f64, 1.0 - alpha, prev, alpha * prices[j]);
            } else {
                prev = prices[j];
            }
            out[k] = if (k >= lb) prev else std.math.nan(f64);
        }
        i += len;
    }
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

/// A bar of MAVP's streaming input: the price and the period for this bar.
pub fn MavpIn(comptime T: type) type {
    return struct { close: T, period: T };
}

/// Streaming MAVP as TA-Lib 0.8's `TA_MAVP_Update` does it: a bank of one
/// moving average per period in `min_period..max_period`, each stepped on
/// every bar from the bar its own lookback allows (the start the batch gives
/// it), all reading one ring of the last bars; the bar's output is the average
/// of the period the bar asks for. The bank lives in the caller's buffer
/// (`scratchLen`), the ring in the stream's, so a stream of a wide range is
/// large (one `MaCore` per period) and costs one step per period per bar.
/// `peek` steps a copy of the one selected average.
pub const MavpCore = struct {
    pub const In = struct { close: f64, period: f64 };
    pub const Out = f64;
    pub fn InOf(comptime T: type) type {
        return MavpIn(T);
    }
    pub fn OutOf(comptime T: type) type {
        return T;
    }

    const Entry = struct { c: smooth.MaCore, skip: usize };

    p: MavpParams,
    lb: usize,
    n: usize = 0,
    bank: []Entry = &.{},
    raw: []f64 = &.{},

    pub fn validate(p: MavpParams) Error!void {
        try mavpCheck(p);
        // The batch starts the average of period `k` at bar `lookback(max) -
        // lookback(k)`; that has to be a bar.
        const lb = smooth.MaCore.lookback(mavpMa(p, p.max_period));
        for (p.min_period..p.max_period + 1) |k| {
            if (smooth.MaCore.lookback(mavpMa(p, k)) > lb) return error.BadParam;
        }
    }
    pub fn ringLen(p: MavpParams) usize {
        var r: usize = 0;
        for (p.min_period..p.max_period + 1) |k| r = @max(r, smooth.MaCore.ringLen(mavpMa(p, k)));
        return r;
    }
    pub fn lookback(p: MavpParams) usize {
        return smooth.MaCore.lookback(mavpMa(p, p.max_period));
    }
    /// f64 slots for the bank (`bind` takes this many).
    pub fn scratchLen(p: MavpParams) usize {
        const bytes = (p.max_period - p.min_period + 1) * @sizeOf(Entry);
        return (bytes + @sizeOf(f64) - 1) / @sizeOf(f64);
    }
    pub fn init(p: MavpParams) Error!MavpCore {
        try validate(p);
        return .{ .p = p, .lb = lookback(p) };
    }
    /// Hand the core its bank storage. A fresh core (`n == 0`) builds the
    /// averages; a clone's copy of the bank is only re-pointed.
    pub fn bind(self: *MavpCore, s: []f64) void {
        const cnt = self.p.max_period - self.p.min_period + 1;
        self.raw = s;
        const bytes = std.mem.sliceAsBytes(s)[0 .. cnt * @sizeOf(Entry)];
        const ptr: [*]Entry = @ptrCast(@alignCast(bytes.ptr));
        self.bank = ptr[0..cnt];
        if (self.n != 0) return;
        for (self.bank, self.p.min_period..) |*e, k| {
            const mp = mavpMa(self.p, k);
            // `validate` has run, so the period and the unstable count are in range.
            e.* = .{ .c = smooth.MaCore.init(mp) catch unreachable, .skip = self.lb - smooth.MaCore.lookback(mp) };
        }
    }
    pub fn scratchSlice(self: *const MavpCore) []f64 {
        return self.raw;
    }

    fn Src(comptime H: type) type {
        return struct {
            h: H,
            off: usize,
            pub fn at(self: @This(), i: usize) f64 {
                return self.h.at(i + self.off).close;
            }
        };
    }

    pub fn step(self: *MavpCore, h: anytype, x: In) ?f64 {
        const g = self.n;
        self.n += 1;
        const sel = mavpPeriod(self.p, x.period) - self.p.min_period;
        var res: ?f64 = null;
        if (@TypeOf(h).dry) {
            // A peek: only the selected average, as a copy, leaves the bank untouched.
            var e = self.bank[sel];
            if (g >= e.skip) res = e.c.step(Src(@TypeOf(h)){ .h = h, .off = e.skip }, x.close);
        } else {
            for (self.bank, 0..) |*e, j| {
                if (g < e.skip) continue;
                const r = e.c.step(Src(@TypeOf(h)){ .h = h, .off = e.skip }, x.close);
                if (j == sel) res = r;
            }
        }
        if (g < self.lb) return null;
        return res orelse std.math.nan(f64);
    }
};

pub fn MavpStream(comptime T: type) type {
    return hist.Stream(T, MavpParams, MavpCore);
}
