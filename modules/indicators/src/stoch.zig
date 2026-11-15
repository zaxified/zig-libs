// SPDX-License-Identifier: MIT
//! STOCH (slow) and STOCHF (fast) stochastic oscillators, ported from TA-Lib
//! 0.8.3 (`ta_STOCH.c`, `ta_STOCHF.c`; BSD-3, see NOTICE).
//!
//! Fast %K = 100 * (close - lowest low) / (highest high - lowest low) over
//! `fastk` bars; a window flat to within 1e-14 of its own magnitude answers 0.
//! STOCHF returns %K and %D = MA(%K); STOCH returns slow %K = MA(%K) and
//! slow %D = MA(slow %K). The stages cascade: each is fed from the bar where
//! the previous one has its first output.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const window = @import("window.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const Seed = core.Seed;
const MaType = core.MaType;
const Bar = core.Bar;
const MaCore = smooth.MaCore;
const MaParams = smooth.MaParams;
const Stage = smooth.Stage;
const SliceSrc = core.SliceSrc;
const RingSrc = core.RingSrc;
const PeekSrc = core.PeekSrc;
const HiCore = window.ExtCore(true);
const LoCore = window.ExtCore(false);

pub fn StochOut(comptime T: type) type {
    return struct { k: T, d: T };
}

/// Raw %K of the last `p` bars.
pub const KCore = struct {
    hi: HiCore,
    lo: LoCore,

    pub fn init(period: usize) KCore {
        return .{ .hi = HiCore.initAny(period), .lo = LoCore.initAny(period) };
    }
    pub fn count(self: *const KCore) usize {
        return self.hi.n;
    }
    pub fn step(self: *KCore, hsrc: anytype, lsrc: anytype, b: Bar(f64)) ?f64 {
        const hh = self.hi.step(hsrc, b.high);
        const ll = self.lo.step(lsrc, b.low);
        if (hh == null or ll == null) return null;
        const range = hh.? - ll.?;
        // 1e-14 is TA_EPSILON; the band is scaled by the extremes' own magnitude.
        if (!(@abs(range) <= 0.00000000000001 * (@abs(hh.?) + @abs(ll.?)))) {
            return (b.close - ll.?) / range * 100.0;
        }
        return 0.0;
    }
};

/// A `KCore` with its two rings.
const KStage = struct {
    c: KCore,
    hr: []f64,
    lr: []f64,

    fn init(period: usize, buf: *[]f64) Error!KStage {
        if (buf.len < 2 * period) return error.BadParam;
        const hr = core.carve(buf, period);
        const lr = core.carve(buf, period);
        return .{ .c = KCore.init(period), .hr = hr, .lr = lr };
    }
    fn feed(self: *KStage, b: Bar(f64), comptime dry: bool) ?f64 {
        const n = self.c.count();
        if (dry) {
            return self.c.step(PeekSrc{ .buf = self.hr, .n = n, .x = b.high }, PeekSrc{ .buf = self.lr, .n = n, .x = b.low }, b);
        }
        self.hr[n % self.hr.len] = b.high;
        self.lr[n % self.lr.len] = b.low;
        return self.c.step(RingSrc{ .buf = self.hr }, RingSrc{ .buf = self.lr }, b);
    }
};

fn validK(period: usize) Error!void {
    try core.checkPeriod(period, 1);
}

/// Batch %K of every bar into the f64 series `out` (NaN before `period - 1`).
fn kSeries(comptime T: type, hs: []const T, ls: []const T, cs: []const T, out: []f64, period: usize) void {
    var k = KCore.init(period);
    const sh = SliceSrc(T){ .xs = hs };
    const sl = SliceSrc(T){ .xs = ls };
    for (hs, ls, cs, out) |h, l, c, *o| {
        const r = k.step(sh, sl, .{ .high = h, .low = l, .close = c });
        o.* = r orelse std.math.nan(f64);
    }
}

// ── STOCHF ──────────────────────────────────────────────────────────────────

pub const StochfParams = struct {
    fastk: usize = 5,
    fastd: usize = 3,
    fastd_ma: MaType = .sma,
    unstable: Unstable = core.no_unstable,
    seed: Seed = .sma,
};

const FPlan = struct {
    d: MaParams,
    lb_k: usize,
    lb_d: usize,

    fn make(p: StochfParams) Error!FPlan {
        try validK(p.fastk);
        try core.checkPeriod(p.fastd, 1);
        const d = MaParams{ .period = p.fastd, .kind = p.fastd_ma, .unstable = p.unstable, .seed = p.seed };
        try MaCore.validate(d);
        return .{ .d = d, .lb_k = p.fastk - 1, .lb_d = MaCore.lookback(d) };
    }
};

pub fn stochfLookback(p: StochfParams) Error!usize {
    const plan = try FPlan.make(p);
    return plan.lb_k + plan.lb_d;
}

/// STOCHF. Intermediate series are f64 whatever `T` is (see `macdext`); `gpa`
/// is used only for `T = f32`.
pub fn stochf(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, out_k: []T, out_d: []T, p: StochfParams) core.AllocError!usize {
    core.checkFloat(T);
    try core.checkLen(high.len, &.{ low.len, close.len, out_k.len, out_d.len });
    const plan = try FPlan.make(p);
    const total = plan.lb_k + plan.lb_d;
    const nan = std.math.nan(T);
    var owned: []f64 = &.{};
    defer if (T != f64) gpa.free(owned);
    const kb: []f64 = if (T == f64) out_k else blk: {
        owned = try gpa.alloc(f64, high.len);
        break :blk owned;
    };
    kSeries(T, high, low, close, kb, p.fastk);
    var cd = try MaCore.init(plan.d);
    const sd = SliceSrc(f64){ .xs = kb, .off = plan.lb_k };
    for (kb, out_d, 0..) |kv, *o, i| {
        const r = if (i >= plan.lb_k) cd.step(sd, kv) else null;
        o.* = if (r) |v| core.to(T, v) else nan;
    }
    // %K is reported only from the first %D bar.
    for (out_k, kb, 0..) |*o, kv, i| o.* = if (i < total) nan else core.to(T, kv);
    return total;
}

pub fn StochfStream(comptime T: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        k: KStage,
        d: Stage,
        n: usize = 0,
        last: ?StochOut(T) = null,

        pub fn bufLen(p: StochfParams) Error!usize {
            const plan = try FPlan.make(p);
            return 2 * p.fastk + MaCore.ringLen(plan.d);
        }
        pub fn init(p: StochfParams, buf: []f64) Error!Self {
            const plan = try FPlan.make(p);
            var rest = buf;
            const k = try KStage.init(p.fastk, &rest);
            return .{ .k = k, .d = try Stage.init(plan.d, &rest) };
        }
        fn run(self: *Self, bar: Bar(T), comptime dry: bool) ?StochOut(T) {
            const b = core.to(Bar(f64), bar);
            const kv = self.k.feed(b, dry) orelse return null;
            const dv = self.d.feed(kv, dry) orelse return null;
            return core.to(StochOut(T), StochOut(f64){ .k = kv, .d = dv });
        }
        pub fn update(self: *Self, bar: Bar(T)) ?StochOut(T) {
            const r = self.run(bar, false) orelse return null;
            self.last = r;
            return r;
        }
        pub fn peek(self: *const Self, bar: Bar(T)) ?StochOut(T) {
            var cp = self.*;
            return cp.run(bar, true);
        }
        pub fn value(self: *const Self) ?StochOut(T) {
            return self.last;
        }
    };
}

// ── STOCH ───────────────────────────────────────────────────────────────────

pub const StochParams = struct {
    fastk: usize = 5,
    slowk: usize = 3,
    slowk_ma: MaType = .sma,
    slowd: usize = 3,
    slowd_ma: MaType = .sma,
    unstable: Unstable = core.no_unstable,
    seed: Seed = .sma,
};

const SPlan = struct {
    sk: MaParams,
    sd: MaParams,
    lb_k: usize,
    lb_sk: usize,
    lb_sd: usize,

    fn make(p: StochParams) Error!SPlan {
        try validK(p.fastk);
        try core.checkPeriod(p.slowk, 1);
        try core.checkPeriod(p.slowd, 1);
        const sk = MaParams{ .period = p.slowk, .kind = p.slowk_ma, .unstable = p.unstable, .seed = p.seed };
        const sd = MaParams{ .period = p.slowd, .kind = p.slowd_ma, .unstable = p.unstable, .seed = p.seed };
        try MaCore.validate(sk);
        try MaCore.validate(sd);
        return .{ .sk = sk, .sd = sd, .lb_k = p.fastk - 1, .lb_sk = MaCore.lookback(sk), .lb_sd = MaCore.lookback(sd) };
    }
    fn total(self: SPlan) usize {
        return self.lb_k + self.lb_sk + self.lb_sd;
    }
};

pub fn stochLookback(p: StochParams) Error!usize {
    return (try SPlan.make(p)).total();
}

/// Outputs slow %K and slow %D. Intermediate series (raw %K, slow %K) are f64
/// whatever `T` is: with `f64` the two output slices double as that scratch, with
/// `f32` `2 * n` f64 are allocated from `gpa` and freed before returning.
pub fn stoch(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, out_k: []T, out_d: []T, p: StochParams) core.AllocError!usize {
    core.checkFloat(T);
    try core.checkLen(high.len, &.{ low.len, close.len, out_k.len, out_d.len });
    const plan = try SPlan.make(p);
    const total = plan.total();
    const nan = std.math.nan(T);
    const n = high.len;
    var owned: []f64 = &.{};
    defer if (T != f64) gpa.free(owned);
    const a, const b = if (T == f64) .{ out_k, out_d } else blk: {
        owned = try gpa.alloc(f64, 2 * n);
        break :blk .{ owned[0..n], owned[n..] };
    };
    // 1. raw %K -> a
    kSeries(T, high, low, close, a, p.fastk);
    // 2. slow %K = MA(raw %K) -> b
    var ck = try MaCore.init(plan.sk);
    const s1 = SliceSrc(f64){ .xs = a, .off = plan.lb_k };
    for (a, b, 0..) |kv, *o, i| {
        const r = if (i >= plan.lb_k) ck.step(s1, kv) else null;
        o.* = r orelse std.math.nan(f64);
    }
    // 3. slow %D = MA(slow %K) -> a (the raw %K is no longer needed)
    var cd = try MaCore.init(plan.sd);
    const start = plan.lb_k + plan.lb_sk;
    const s2 = SliceSrc(f64){ .xs = b, .off = start };
    for (a, b, 0..) |*o, sk, i| {
        const r = if (i >= start) cd.step(s2, sk) else null;
        o.* = r orelse std.math.nan(f64);
    }
    // 4. a now holds slow %D and b slow %K. Slow %K is reported only from the
    // first slow %D bar.
    for (out_k, out_d, a, b, 0..) |*ok, *od, dv, kv, i| {
        ok.* = if (i < total) nan else core.to(T, kv);
        od.* = core.to(T, dv);
    }
    return total;
}

pub fn StochStream(comptime T: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        k: KStage,
        sk: Stage,
        sd: Stage,
        last: ?StochOut(T) = null,

        pub fn bufLen(p: StochParams) Error!usize {
            const plan = try SPlan.make(p);
            return 2 * p.fastk + MaCore.ringLen(plan.sk) + MaCore.ringLen(plan.sd);
        }
        pub fn init(p: StochParams, buf: []f64) Error!Self {
            const plan = try SPlan.make(p);
            var rest = buf;
            const k = try KStage.init(p.fastk, &rest);
            const sk = try Stage.init(plan.sk, &rest);
            return .{ .k = k, .sk = sk, .sd = try Stage.init(plan.sd, &rest) };
        }
        fn run(self: *Self, bar: Bar(T), comptime dry: bool) ?StochOut(T) {
            const b = core.to(Bar(f64), bar);
            const kv = self.k.feed(b, dry) orelse return null;
            const skv = self.sk.feed(kv, dry) orelse return null;
            const sdv = self.sd.feed(skv, dry) orelse return null;
            return core.to(StochOut(T), StochOut(f64){ .k = skv, .d = sdv });
        }
        pub fn update(self: *Self, bar: Bar(T)) ?StochOut(T) {
            const r = self.run(bar, false) orelse return null;
            self.last = r;
            return r;
        }
        pub fn peek(self: *const Self, bar: Bar(T)) ?StochOut(T) {
            var cp = self.*;
            return cp.run(bar, true);
        }
        pub fn value(self: *const Self) ?StochOut(T) {
            return self.last;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// Bars (high, low, close). Raw %K over 3 bars, 100 * (C - LL) / (HH - LL):
//   bar 2: HH 15 (10,11,15), LL 8  (8,9,11),  C 14   -> 600/7  = 85.714285714
//   bar 3: HH 15 (11,15,13), LL 9  (9,11,12), C 12.5 -> 350/6  = 58.333333333
//   bar 4: HH 15 (15,13,14), LL 10 (11,12,10), C 13   -> 300/5  = 60
//   bar 5: HH 14 (13,14,12), LL 9  (12,10,9), C 11    -> 200/5  = 40
const t_h = [_]f64{ 10, 11, 15, 13, 14, 12 };
const t_l = [_]f64{ 8, 9, 11, 12, 10, 9 };
const t_c = [_]f64{ 9, 10, 14, 12.5, 13, 11 };

test "stochf hand-checked vector" {
    // fastk 3, fastd 2 (SMA): D at bar 3 = (85.714285714 + 58.333333333) / 2 = 72.023809524
    var k: [6]f64 = undefined;
    var d: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 3), try stochf(f64, testing.allocator, &t_h, &t_l, &t_c, &k, &d, .{ .fastk = 3, .fastd = 2 }));
    try testing.expect(std.math.isNan(k[2]) and std.math.isNan(d[2]));
    try testing.expectApproxEqAbs(@as(f64, 350.0 / 6.0), k[3], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, (600.0 / 7.0 + 350.0 / 6.0) / 2.0), d[3], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 60), k[4], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 40), k[5], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 50), d[5], 1e-12);
    // fastd 1 is a copy: %D == %K, lookback 2
    try testing.expectEqual(@as(usize, 2), try stochf(f64, testing.allocator, &t_h, &t_l, &t_c, &k, &d, .{ .fastk = 3, .fastd = 1 }));
    try testing.expectApproxEqAbs(@as(f64, 600.0 / 7.0), k[2], 1e-12);
    try testing.expectEqual(k[2], d[2]);
}

test "stoch hand-checked vector" {
    // fastk 3, slowk SMA 2, slowd SMA 2 -> lookback 2 + 1 + 1 = 4
    //   slow %K: bar 3 = (85.714 + 58.333)/2, bar 4 = (58.333 + 60)/2 = 59.1666..., bar 5 = (60 + 40)/2 = 50
    //   slow %D: bar 4 = (72.0238 + 59.1667)/2 = 65.5952381, bar 5 = (59.1667 + 50)/2 = 54.58333
    var k: [6]f64 = undefined;
    var d: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 4), try stoch(f64, testing.allocator, &t_h, &t_l, &t_c, &k, &d, .{ .fastk = 3, .slowk = 2, .slowd = 2 }));
    for (0..4) |i| try testing.expect(std.math.isNan(k[i]) and std.math.isNan(d[i]));
    try testing.expectApproxEqAbs(@as(f64, (350.0 / 6.0 + 60.0) / 2.0), k[4], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, ((600.0 / 7.0 + 350.0 / 6.0) / 2.0 + (350.0 / 6.0 + 60.0) / 2.0) / 2.0), d[4], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 50), k[5], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, ((350.0 / 6.0 + 60.0) / 2.0 + 50.0) / 2.0), d[5], 1e-12);
}

test "stoch: a flat window answers 0, a close at the high answers 100" {
    const h = [_]f64{ 5, 5, 5, 6 };
    const l = [_]f64{ 5, 5, 5, 4 };
    const c = [_]f64{ 5, 5, 5, 6 };
    var k: [4]f64 = undefined;
    var d: [4]f64 = undefined;
    _ = try stochf(f64, testing.allocator, &h, &l, &c, &k, &d, .{ .fastk = 2, .fastd = 1 });
    try testing.expectEqual(@as(f64, 0), k[1]);
    try testing.expectEqual(@as(f64, 0), k[2]);
    try testing.expectEqual(@as(f64, 100), k[3]); // window (5..5, 6 / 5, 4): HH 6, LL 4, C 6
}

test "stoch family: lookback and BadParam" {
    try testing.expectEqual(@as(usize, 4 + 2), try stochfLookback(.{}));
    try testing.expectEqual(@as(usize, 4 + 2 + 2), try stochLookback(.{}));
    // slowk EMA 3 with 5 unstable bars: lookback 2 + 5; slowd SMA 3: 2; fastk 5: 4
    try testing.expectEqual(@as(usize, 4 + 7 + 2), try stochLookback(.{ .slowk_ma = .ema, .unstable = .{ .bars = 5 } }));
    try testing.expectError(error.BadParam, stochfLookback(.{ .fastk = 0 }));
    try testing.expectError(error.BadParam, stochfLookback(.{ .fastd = 100001 }));
    try testing.expectError(error.BadParam, stochLookback(.{ .slowk = 0 }));
    try testing.expectError(error.BadParam, stochLookback(.{ .slowd = 0 }));
    try testing.expectError(error.Unsupported, stochLookback(.{ .slowd_ma = .mama }));
    var k: [6]f64 = undefined;
    var d: [5]f64 = undefined;
    try testing.expectError(error.BadParam, stoch(f64, testing.allocator, &t_h, &t_l, &t_c, &k, &d, .{}));
}

fn stochfT(comptime T: type, h: []const T, l: []const T, c: []const T, k: []T, d: []T, p: StochfParams) core.AllocError!usize {
    return stochf(T, testing.allocator, h, l, c, k, d, p);
}
fn stochT(comptime T: type, h: []const T, l: []const T, c: []const T, k: []T, d: []T, p: StochParams) core.AllocError!usize {
    return stoch(T, testing.allocator, h, l, c, k, d, p);
}

fn checkStoch(comptime Stream: anytype, comptime batch: anytype, comptime lbFn: anytype, h: []const f64, l: []const f64, c: []const f64, p: anytype) !void {
    const n = h.len;
    const k = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(k);
    const d = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(d);
    const lb = try batch(f64, h, l, c, k, d, p);
    try testing.expectEqual(try lbFn(p), lb);
    try testing.expectEqual(lb, th.leadingNan(k));
    try testing.expectEqual(lb, th.leadingNan(d));
    const S = Stream(f64);
    const buf = try testing.allocator.alloc(f64, try S.bufLen(p));
    defer testing.allocator.free(buf);
    var s = try S.init(p, buf);
    for (h, l, c, k, d) |hh, ll, cc, wk, wd| {
        const b = Bar(f64){ .high = hh, .low = ll, .close = cc };
        const pk = s.peek(b);
        const got = s.update(b);
        if (got) |g| {
            try testing.expect(th.sameBits(g.k, wk) and th.sameBits(g.d, wd));
            try testing.expect(pk != null and th.sameBits(pk.?.d, g.d));
        } else {
            try testing.expect(std.math.isNan(wk) and std.math.isNan(wd) and pk == null);
        }
    }
}

test "stoch family: batch == streaming, lookback == leading NaN, f32" {
    var h: [300]f64 = undefined;
    var l: [300]f64 = undefined;
    var c: [300]f64 = undefined;
    th.walkBars(&h, &l, &c, 111);
    try checkStoch(StochfStream, stochfT, stochfLookback, &h, &l, &c, StochfParams{});
    try checkStoch(StochfStream, stochfT, stochfLookback, &h, &l, &c, StochfParams{ .fastk = 1, .fastd = 1 });
    try checkStoch(StochfStream, stochfT, stochfLookback, &h, &l, &c, StochfParams{ .fastk = 9, .fastd = 4, .fastd_ma = .ema, .unstable = .{ .bars = 3 } });
    try checkStoch(StochfStream, stochfT, stochfLookback, &h, &l, &c, StochfParams{ .fastk = 4, .fastd = 5, .fastd_ma = .wma });
    try checkStoch(StochStream, stochT, stochLookback, &h, &l, &c, StochParams{});
    try checkStoch(StochStream, stochT, stochLookback, &h, &l, &c, StochParams{ .fastk = 6, .slowk = 4, .slowk_ma = .ema, .slowd = 5, .slowd_ma = .wma });
    try checkStoch(StochStream, stochT, stochLookback, &h, &l, &c, StochParams{ .fastk = 2, .slowk = 1, .slowd = 1 });
    var h32: [60]f32 = undefined;
    var l32: [60]f32 = undefined;
    var c32: [60]f32 = undefined;
    for (0..60) |i| {
        h32[i] = @floatCast(h[i]);
        l32[i] = @floatCast(l[i]);
        c32[i] = @floatCast(c[i]);
    }
    var k: [60]f32 = undefined;
    var d: [60]f32 = undefined;
    try testing.expectEqual(@as(usize, 8), try stoch(f32, testing.allocator, &h32, &l32, &c32, &k, &d, .{}));
    try testing.expectEqual(@as(usize, 6), try stochf(f32, testing.allocator, &h32, &l32, &c32, &k, &d, .{}));
    try testing.expect(k[20] >= 0 and k[20] <= 100);
}

test "stoch family: a NaN close poisons raw %K at its bar and the running-sum smoothing after it" {
    var h: [10]f64 = undefined;
    var l: [10]f64 = undefined;
    var c: [10]f64 = undefined;
    th.walkBars(&h, &l, &c, 5);
    c[5] = std.math.nan(f64);
    var k: [10]f64 = undefined;
    var d: [10]f64 = undefined;
    // fastk 3, fastd 1 (copy): only bar 5 is NaN
    _ = try stochf(f64, testing.allocator, &h, &l, &c, &k, &d, .{ .fastk = 3, .fastd = 1 });
    for (2..10) |i| try testing.expectEqual(i == 5, std.math.isNan(k[i]));
    // fastd 2 (SMA running sum): %D is NaN from bar 5 on
    _ = try stochf(f64, testing.allocator, &h, &l, &c, &k, &d, .{ .fastk = 3, .fastd = 2 });
    try testing.expect(!std.math.isNan(d[4]));
    for (5..10) |i| try testing.expect(std.math.isNan(d[i]));
    // slow: the slow %K (SMA 2) is NaN from bar 5 on
    _ = try stoch(f64, testing.allocator, &h, &l, &c, &k, &d, .{ .fastk = 3, .slowk = 2, .slowd = 2 });
    try testing.expect(!std.math.isNan(k[4]));
    for (5..10) |i| try testing.expect(std.math.isNan(k[i]) and std.math.isNan(d[i]));
}

test "stoch family: f32 output is the f64 result of the f32-rounded input, rounded once" {
    var h: [120]f64 = undefined;
    var l: [120]f64 = undefined;
    var c: [120]f64 = undefined;
    th.walkBars(&h, &l, &c, 77);
    var h32: [120]f32 = undefined;
    var l32: [120]f32 = undefined;
    var c32: [120]f32 = undefined;
    var h6: [120]f64 = undefined;
    var l6: [120]f64 = undefined;
    var c6: [120]f64 = undefined;
    for (0..120) |i| {
        h32[i] = @floatCast(h[i]);
        l32[i] = @floatCast(l[i]);
        c32[i] = @floatCast(c[i]);
        h6[i] = h32[i];
        l6[i] = l32[i];
        c6[i] = c32[i];
    }
    var k32: [120]f32 = undefined;
    var d32: [120]f32 = undefined;
    var k64: [120]f64 = undefined;
    var d64: [120]f64 = undefined;
    const ps = [_]StochParams{ .{}, .{ .fastk = 6, .slowk = 4, .slowk_ma = .ema, .slowd = 5, .slowd_ma = .wma } };
    for (ps) |p| {
        const lb = try stoch(f32, testing.allocator, &h32, &l32, &c32, &k32, &d32, p);
        _ = try stoch(f64, testing.allocator, &h6, &l6, &c6, &k64, &d64, p);
        for (0..120) |i| {
            try testing.expect(th.sameBits(@as(f64, k32[i]), if (i < lb) std.math.nan(f64) else @as(f64, @as(f32, @floatCast(k64[i])))));
            try testing.expect(th.sameBits(@as(f64, d32[i]), if (i < lb) std.math.nan(f64) else @as(f64, @as(f32, @floatCast(d64[i])))));
        }
    }
    const pf_ = [_]StochfParams{ .{}, .{ .fastk = 7, .fastd = 4, .fastd_ma = .ema } };
    for (pf_) |p| {
        const lb = try stochf(f32, testing.allocator, &h32, &l32, &c32, &k32, &d32, p);
        _ = try stochf(f64, testing.allocator, &h6, &l6, &c6, &k64, &d64, p);
        for (0..120) |i| {
            try testing.expect(th.sameBits(@as(f64, k32[i]), if (i < lb) std.math.nan(f64) else @as(f64, @as(f32, @floatCast(k64[i])))));
            try testing.expect(th.sameBits(@as(f64, d32[i]), if (i < lb) std.math.nan(f64) else @as(f64, @as(f32, @floatCast(d64[i])))));
        }
    }
}
