// SPDX-License-Identifier: MIT
//! BBANDS (Bollinger bands) and the rolling variance it is built on, ported from
//! TA-Lib 0.8.3 (`ta_BBANDS.c`, `ta_VAR.c`, `ta_STDDEV.c`; BSD-3, see NOTICE).
//!
//! The middle band is a moving average of any supported type, the deviation is
//! the population standard deviation of the same window (not of the average),
//! and the bands are `mid +/- dev * sd`. TA-Lib's variance is a shifted
//! running-sums form that re-anchors (from the window itself) whenever it
//! collapses below 1e-6 of the largest sum of squares seen since the last
//! anchor, and at least every 32 windows; the same steps are ported here.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const Seed = core.Seed;
const MaType = core.MaType;
const MaCore = smooth.MaCore;
const MaParams = smooth.MaParams;
const Stage = smooth.Stage;
const SliceSrc = core.SliceSrc;
const RingSrc = core.RingSrc;
const PeekSrc = core.PeekSrc;
const pf = core.pf;

/// Population variance of the last `p` bars (TA_VAR with nbdev 1).
pub const VarCore = struct {
    p: usize,
    inv: f64,
    n: usize = 0,
    shift: f64 = 0.0,
    t1: f64 = 0.0,
    t2: f64 = 0.0,
    peak: f64 = 0.0,
    since: usize,

    pub fn init(period: usize) VarCore {
        return .{ .p = period, .inv = 1.0 / pf(period), .since = 32 * period };
    }
    pub fn step(self: *VarCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) self.shift = x;
        if (n + 1 < self.p) {
            var d0 = x - self.shift;
            self.t1 += d0;
            d0 *= d0;
            self.t2 += d0;
            return null;
        }
        if (n + 1 == self.p) self.peak = self.t2;
        var d = x - self.shift;
        self.t1 += d;
        d *= d;
        self.t2 += d;
        self.peak = if (self.t2 > self.peak) self.t2 else self.peak;
        var mean = self.t1 * self.inv;
        var variance = self.t2 * self.inv - mean * mean;
        const ws = n + 1 - self.p;
        d = src.at(ws) - self.shift;
        self.t1 -= d;
        d *= d;
        self.t2 -= d;
        self.since -= 1;
        if (variance < 0.000001 * (self.peak * self.inv) or self.since == 0) {
            self.since = 32 * self.p;
            var sum: f64 = 0.0;
            var j = ws;
            while (j <= n) : (j += 1) sum += src.at(j);
            self.shift = sum * self.inv;
            self.t1 = 0.0;
            self.t2 = 0.0;
            j = ws;
            while (j <= n) : (j += 1) {
                d = src.at(j) - self.shift;
                self.t1 += d;
                d *= d;
                self.t2 += d;
            }
            mean = self.t1 * self.inv;
            variance = self.t2 * self.inv - mean * mean;
            // A window flat to within the rounding of its own mean: anchor on
            // one of its values so the trigger cannot fire on every bar.
            if (variance < 0.000001 * (self.t2 * self.inv)) {
                self.shift = x;
                self.t1 = 0.0;
                self.t2 = 0.0;
                j = ws;
                while (j <= n) : (j += 1) {
                    d = src.at(j) - self.shift;
                    self.t1 += d;
                    d *= d;
                    self.t2 += d;
                }
                mean = self.t1 * self.inv;
                variance = self.t2 * self.inv - mean * mean;
            }
            self.peak = self.t2;
            if (variance < 0.000000000001 * (self.t2 * self.inv)) variance = 0.0;
            d = src.at(ws) - self.shift;
            self.t1 -= d;
            d *= d;
            self.t2 -= d;
        }
        return variance;
    }
};

pub fn BbandsOut(comptime T: type) type {
    return struct { upper: T, middle: T, lower: T };
}

pub const BbandsParams = struct {
    period: usize = 20,
    dev_up: f64 = 2.0,
    dev_dn: f64 = 2.0,
    ma: MaType = .sma,
    unstable: Unstable = core.no_unstable,
    seed: Seed = .sma,
};

const real_min = -3e37;
const real_max = 3e37;

const Plan = struct {
    ma: MaParams,
    lb_ma: usize,
    lb_sd: usize,
    lb: usize,

    fn make(p: BbandsParams) Error!Plan {
        try core.checkPeriod(p.period, 2);
        if (!(p.dev_up >= real_min and p.dev_up <= real_max)) return error.BadParam;
        if (!(p.dev_dn >= real_min and p.dev_dn <= real_max)) return error.BadParam;
        const ma = MaParams{ .period = p.period, .kind = p.ma, .unstable = p.unstable, .seed = p.seed };
        try MaCore.validate(ma);
        const lb_ma = MaCore.lookback(ma);
        const lb_sd = p.period - 1;
        return .{ .ma = ma, .lb_ma = lb_ma, .lb_sd = lb_sd, .lb = @max(lb_ma, lb_sd) };
    }
};

fn bands(mid: f64, variance: f64, up: f64, dn: f64) BbandsOut(f64) {
    const sd = if (variance != 0.0) @sqrt(variance) else 0.0;
    if (up == dn) {
        const t = sd * up;
        return .{ .upper = mid + t, .middle = mid, .lower = mid - t };
    }
    return .{ .upper = @mulAdd(f64, sd, up, mid), .middle = mid, .lower = mid - sd * dn };
}

pub fn bbandsLookback(p: BbandsParams) Error!usize {
    return (try Plan.make(p)).lb;
}

pub fn bbands(comptime T: type, in: []const T, upper: []T, middle: []T, lower: []T, p: BbandsParams) Error!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{ upper.len, middle.len, lower.len });
    const plan = try Plan.make(p);
    const cm = try MaCore.init(plan.ma);
    // One dispatch per call: a monomorphic loop over the active MA variant
    // (a by-value copy the optimizer keeps in registers).
    switch (cm) {
        inline else => |v| {
            var local = v;
            bbLoop(T, &local, in, upper, middle, lower, p, plan);
        },
    }
    return plan.lb;
}

fn bbLoop(comptime T: type, cm: anytype, in: []const T, upper: []T, middle: []T, lower: []T, p: BbandsParams, plan: Plan) void {
    var cv = VarCore.init(p.period);
    // TA_BBANDS calls TA_MA from bar 0 (the average clamps to its own lookback and is
    // realigned); only the deviation is started late. Matters when the average's
    // lookback is below the deviation's (VIDYA, ALMA at small sizes, MAMA, DISABLED).
    const skip_m: usize = 0;
    const skip_v = plan.lb - plan.lb_sd;
    const sm = SliceSrc(T){ .xs = in, .off = skip_m };
    const sv = SliceSrc(T){ .xs = in, .off = skip_v };
    const nan = std.math.nan(T);
    for (in, upper, middle, lower, 0..) |x, *u, *m, *l, i| {
        const xv: f64 = x;
        const mv = if (i >= skip_m) cm.step(sm, xv) else null;
        const vv = if (i >= skip_v) cv.step(sv, xv) else null;
        if (mv == null or vv == null) {
            u.* = nan;
            m.* = nan;
            l.* = nan;
            continue;
        }
        const b = core.to(BbandsOut(T), bands(mv.?, vv.?, p.dev_up, p.dev_dn));
        u.* = b.upper;
        m.* = b.middle;
        l.* = b.lower;
    }
}

/// Streaming BBANDS: a moving-average stage plus the variance window, rings in
/// the caller's buffer (`bufLen`).
pub fn BbandsStream(comptime T: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        ma: Stage,
        cv: VarCore,
        vring: []f64,
        skip_m: usize,
        skip_v: usize,
        up: f64,
        dn: f64,
        n: usize = 0,
        last: ?BbandsOut(T) = null,

        pub fn bufLen(p: BbandsParams) Error!usize {
            const plan = try Plan.make(p);
            return MaCore.ringLen(plan.ma) + p.period;
        }
        pub fn init(p: BbandsParams, buf: []f64) Error!Self {
            const plan = try Plan.make(p);
            var rest = buf;
            const ma = try Stage.init(plan.ma, &rest);
            if (rest.len < p.period) return error.BadParam;
            return .{
                .ma = ma,
                .cv = VarCore.init(p.period),
                .vring = core.carve(&rest, p.period),
                .skip_m = 0, // see `bbands`: the average starts at bar 0
                .skip_v = plan.lb - plan.lb_sd,
                .up = p.dev_up,
                .dn = p.dev_dn,
            };
        }
        fn run(self: *Self, x: T, comptime dry: bool) ?BbandsOut(T) {
            const xv: f64 = x;
            const n = self.n;
            if (!dry) self.n += 1;
            const mv = if (n >= self.skip_m) self.ma.feed(xv, dry) else null;
            var vv: ?f64 = null;
            if (n >= self.skip_v) {
                if (dry) {
                    vv = self.cv.step(PeekSrc{ .buf = self.vring, .n = self.cv.n, .x = xv }, xv);
                } else {
                    self.vring[self.cv.n % self.vring.len] = xv;
                    vv = self.cv.step(RingSrc{ .buf = self.vring }, xv);
                }
            }
            if (mv == null or vv == null) return null;
            return core.to(BbandsOut(T), bands(mv.?, vv.?, self.up, self.dn));
        }
        pub fn update(self: *Self, x: T) ?BbandsOut(T) {
            const r = self.run(x, false) orelse return null;
            self.last = r;
            return r;
        }
        pub fn peek(self: *const Self, x: T) ?BbandsOut(T) {
            var cp = self.*;
            return cp.run(x, true);
        }
        pub fn value(self: *const Self) ?BbandsOut(T) {
            return self.last;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "bbands hand-checked vector (period 2, SMA)" {
    // input 1 3 2: window (1,3): mean 2, population variance ((1-2)^2+(3-2)^2)/2 = 1, sd 1
    //   -> upper 2+2*1 = 4, lower 0. window (3,2): mean 2.5, variance 0.25, sd 0.5 -> 3.5 / 1.5.
    const in = [_]f64{ 1, 3, 2 };
    var u: [3]f64 = undefined;
    var m: [3]f64 = undefined;
    var l: [3]f64 = undefined;
    try testing.expectEqual(@as(usize, 1), try bbands(f64, &in, &u, &m, &l, .{ .period = 2 }));
    try testing.expect(std.math.isNan(u[0]) and std.math.isNan(m[0]) and std.math.isNan(l[0]));
    try testing.expectEqual(@as(f64, 4), u[1]);
    try testing.expectEqual(@as(f64, 2), m[1]);
    try testing.expectEqual(@as(f64, 0), l[1]);
    try testing.expectEqual(@as(f64, 3.5), u[2]);
    try testing.expectEqual(@as(f64, 2.5), m[2]);
    try testing.expectEqual(@as(f64, 1.5), l[2]);
    // different deviations: upper = fma(sd, 1, mid) = 3, lower = mid - sd * 3 = -1
    _ = try bbands(f64, &in, &u, &m, &l, .{ .period = 2, .dev_up = 1, .dev_dn = 3 });
    try testing.expectEqual(@as(f64, 3), u[1]);
    try testing.expectEqual(@as(f64, -1), l[1]);
}

test "bbands: a flat series has zero-width bands" {
    const in = [_]f64{ 5, 5, 5, 5, 5, 5 };
    var u: [6]f64 = undefined;
    var m: [6]f64 = undefined;
    var l: [6]f64 = undefined;
    _ = try bbands(f64, &in, &u, &m, &l, .{ .period = 3 });
    for (2..6) |i| {
        try testing.expectEqual(@as(f64, 5), u[i]);
        try testing.expectEqual(@as(f64, 5), l[i]);
    }
}

test "bbands: the variance agrees with a two-pass definition over a long walk" {
    // 500 bars at period 5 force several re-anchors (every 160 windows) and flat-window checks.
    var xs: [500]f64 = undefined;
    th.walk(&xs, 91);
    var u: [500]f64 = undefined;
    var m: [500]f64 = undefined;
    var l: [500]f64 = undefined;
    _ = try bbands(f64, &xs, &u, &m, &l, .{ .period = 5, .dev_up = 1, .dev_dn = 1 });
    for (4..500) |i| {
        var mean: f64 = 0;
        for (xs[i - 4 .. i + 1]) |v| mean += v;
        mean /= 5.0;
        var ss: f64 = 0;
        for (xs[i - 4 .. i + 1]) |v| ss += (v - mean) * (v - mean);
        const sd = @sqrt(ss / 5.0);
        try testing.expectApproxEqAbs(mean + sd, u[i], 1e-9);
        try testing.expectApproxEqAbs(mean - sd, l[i], 1e-9);
    }
}

test "bbands: lookback follows the MA type, BadParam" {
    try testing.expectEqual(@as(usize, 19), try bbandsLookback(.{}));
    try testing.expectEqual(@as(usize, 19 + 4), try bbandsLookback(.{ .ma = .ema, .unstable = .{ .bars = 4 } }));
    try testing.expectEqual(@as(usize, 19), try bbandsLookback(.{ .ma = .disabled }));
    try testing.expectEqual(@as(usize, 32), try bbandsLookback(.{ .ma = .mama })); // MAMA's lookback is 32 at any period
    try testing.expectError(error.BadParam, bbandsLookback(.{ .period = 1 }));
    try testing.expectError(error.BadParam, bbandsLookback(.{ .period = 100001 }));
    try testing.expectError(error.BadParam, bbandsLookback(.{ .dev_up = 4e37 }));
    try testing.expectError(error.BadParam, bbandsLookback(.{ .dev_dn = std.math.nan(f64) }));
    const in = [_]f64{ 1, 2, 3 };
    var a: [3]f64 = undefined;
    var b: [3]f64 = undefined;
    var c: [2]f64 = undefined;
    try testing.expectError(error.BadParam, bbands(f64, &in, &a, &b, &c, .{ .period = 2 }));
}

fn checkBands(xs: []const f64, p: BbandsParams) !void {
    const n = xs.len;
    const u = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(u);
    const m = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(m);
    const l = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(l);
    const lb = try bbands(f64, xs, u, m, l, p);
    try testing.expectEqual(try bbandsLookback(p), lb);
    try testing.expectEqual(lb, th.leadingNan(u));
    try testing.expectEqual(lb, th.leadingNan(m));
    try testing.expectEqual(lb, th.leadingNan(l));
    const S = BbandsStream(f64);
    const buf = try testing.allocator.alloc(f64, try S.bufLen(p));
    defer testing.allocator.free(buf);
    var s = try S.init(p, buf);
    for (xs, u, m, l) |x, wu, wm, wl| {
        const pk = s.peek(x);
        const got = s.update(x);
        if (got) |g| {
            try testing.expect(th.sameBits(g.upper, wu) and th.sameBits(g.middle, wm) and th.sameBits(g.lower, wl));
            try testing.expect(pk != null and th.sameBits(pk.?.upper, g.upper));
        } else {
            try testing.expect(std.math.isNan(wu) and pk == null);
        }
    }
}

test "bbands: batch == streaming, lookback == leading NaN, f32" {
    var xs: [600]f64 = undefined;
    th.walk(&xs, 101);
    try checkBands(&xs, .{});
    try checkBands(&xs, .{ .period = 2 });
    try checkBands(&xs, .{ .period = 7, .dev_up = 2.5, .dev_dn = 1.5 });
    try checkBands(&xs, .{ .period = 9, .ma = .ema, .unstable = .{ .bars = 5 } });
    try checkBands(&xs, .{ .period = 9, .ma = .wma });
    try checkBands(&xs, .{ .period = 9, .ma = .disabled });
    // a flat stretch exercises the flat-window re-anchor
    var flat: [200]f64 = undefined;
    for (&flat, 0..) |*v, i| v.* = if (i < 100) 50.0 else 50.0 + @as(f64, @floatFromInt(i % 3)) * 1e-9;
    try checkBands(&flat, .{ .period = 6 });
    var f32s: [60]f32 = undefined;
    for (&f32s, xs[0..60]) |*d, s| d.* = @floatCast(s);
    var u: [60]f32 = undefined;
    var m: [60]f32 = undefined;
    var l: [60]f32 = undefined;
    try testing.expectEqual(@as(usize, 19), try bbands(f32, &f32s, &u, &m, &l, .{}));
    try testing.expect(u[30] > m[30] and m[30] > l[30]);
}

test "bbands: a NaN poisons the running sums and the variance (as in TA-Lib)" {
    const nan = std.math.nan(f64);
    const in = [_]f64{ 1, 2, nan, 4, 5, 6 };
    var u: [6]f64 = undefined;
    var m: [6]f64 = undefined;
    var l: [6]f64 = undefined;
    _ = try bbands(f64, &in, &u, &m, &l, .{ .period = 2 });
    try testing.expect(!std.math.isNan(u[1]));
    for (2..6) |i| try testing.expect(std.math.isNan(u[i]) and std.math.isNan(m[i]) and std.math.isNan(l[i]));
}
