// SPDX-License-Identifier: MIT
//! More composites of the momentum group, ported from TA-Lib 0.8.3
//! (`ta_KST.c`, `ta_KSTEXT.c`, `ta_KDJ.c`, `ta_STOCHRSI.c`, `ta_CRSI.c`,
//! `ta_STC.c`, `ta_SQZMOM.c`; BSD-3, see NOTICE).
//!
//! KST / KSTEXT, STOCHRSI and KDJ are built from the seed cores (`MaCore`,
//! `RsiCore`, the stochastic `KCore`, `stoch`); CRSI, STC and SQZMOM have
//! their own cores. CRSI's percent rank is `statistic.PercentrankCore`; SQZMOM
//! composes `bands.VarCore` (the standard deviation), `overlap.MidpriceCore` and
//! `statistic.LinearregCore`.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const rsi_ = @import("rsi.zig");
const stoch_ = @import("stoch.zig");
const bands = @import("bands.zig");
const stat = @import("statistic.zig");
const overlap = @import("overlap.zig");
const comp = @import("mom_comp.zig");
const vs = @import("vs_kit.zig");
const mu = @import("mom_util.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const MaType = core.MaType;
const pf = core.pf;
const EmaCore = smooth.EmaCore;
const NoSrc = smooth.NoSrc;
const MaCore = smooth.MaCore;

// ── KST / KSTEXT ────────────────────────────────────────────────────────────

pub const KstParams = struct {
    roc1: usize = 10,
    roc2: usize = 15,
    roc3: usize = 20,
    roc4: usize = 30,
    sma1: usize = 10,
    sma2: usize = 10,
    sma3: usize = 10,
    sma4: usize = 15,
    signal: usize = 9,
};

pub const KstextParams = struct {
    roc1: usize = 10,
    roc2: usize = 15,
    roc3: usize = 20,
    roc4: usize = 30,
    ma1: usize = 10,
    ma2: usize = 10,
    ma3: usize = 10,
    ma4: usize = 15,
    signal: usize = 9,
    roc_ma: MaType = .sma,
    signal_ma: MaType = .sma,
};

const KstPlan = struct {
    roc: [4]usize,
    ma: [4]smooth.MaParams,
    sig: smooth.MaParams,
    lb_ma: [4]usize,
    leg_max: usize,

    fn make(roc: [4]usize, per: [4]usize, signal: usize, roc_ma: MaType, signal_ma: MaType) Error!KstPlan {
        var r: KstPlan = undefined;
        r.roc = roc;
        r.leg_max = 0;
        for (0..4) |i| {
            try core.checkPeriod(roc[i], 1);
            try core.checkPeriod(per[i], 1);
            r.ma[i] = .{ .period = per[i], .kind = roc_ma };
            try MaCore.validate(r.ma[i]);
            r.lb_ma[i] = MaCore.lookback(r.ma[i]);
            r.leg_max = @max(r.leg_max, roc[i] + r.lb_ma[i]);
        }
        try core.checkPeriod(signal, 1);
        r.sig = .{ .period = signal, .kind = signal_ma };
        try MaCore.validate(r.sig);
        return r;
    }
};

fn RocView(comptime S: type) type {
    return struct {
        s: S,
        off: usize,
        roc: usize,
        pub fn at(self: @This(), i: usize) f64 {
            return comp.rocPct(self.s, self.off + i, self.roc);
        }
    };
}

/// KST: four ROCs, each smoothed by a moving average, combined 1:2:3:4, plus a
/// signal MA. Every smoothing MA starts at the bar where its first output
/// coincides with the slowest leg's (TA-Lib feeds each from `legMax - its own
/// lookback`), so the running sums start fresh there.
pub fn KstCore(comptime ext: bool) type {
    return struct {
        const Self = @This();
        pub const In = vs.X(f64);
        pub const Out = struct { kst: f64, signal: f64 };
        pub const Params = if (ext) KstextParams else KstParams;
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return vs.X(T);
        }
        pub fn Outputs(comptime T: type) type {
            return struct { kst: T, signal: T };
        }
        legs: [4]MaCore,
        sig: MaCore,
        ring: mu.Ring,
        roc: [4]usize,
        start: [4]usize,
        leg_max: usize,
        n: usize = 0,

        fn plan(p: Params) Error!KstPlan {
            if (ext) return KstPlan.make(.{ p.roc1, p.roc2, p.roc3, p.roc4 }, .{ p.ma1, p.ma2, p.ma3, p.ma4 }, p.signal, p.roc_ma, p.signal_ma);
            return KstPlan.make(.{ p.roc1, p.roc2, p.roc3, p.roc4 }, .{ p.sma1, p.sma2, p.sma3, p.sma4 }, p.signal, .sma, .sma);
        }
        pub fn validate(p: Params) Error!void {
            _ = try plan(p);
        }
        pub fn lookback(p: Params) usize {
            const pl = plan(p) catch return 0;
            return pl.leg_max + MaCore.lookback(pl.sig);
        }
        pub fn ringLen(p: Params) usize {
            const pl = plan(p) catch return 0;
            var m: usize = 0;
            for (0..4) |i| m = @max(m, MaCore.ringLen(pl.ma[i]) + pl.roc[i]);
            return m + 1;
        }
        pub fn scratchLen(p: Params) usize {
            const pl = plan(p) catch return 0;
            return MaCore.ringLen(pl.sig);
        }
        pub fn init(p: Params, scratch: []f64) Error!Self {
            const pl = try plan(p);
            const sl = MaCore.ringLen(pl.sig);
            if (scratch.len < sl) return error.BadParam;
            var r: Self = undefined;
            for (0..4) |i| {
                r.legs[i] = try MaCore.init(pl.ma[i]);
                r.roc[i] = pl.roc[i];
                r.start[i] = pl.leg_max - pl.lb_ma[i];
            }
            r.sig = try MaCore.init(pl.sig);
            r.ring = mu.Ring.init(scratch[0..sl]);
            r.leg_max = pl.leg_max;
            r.n = 0;
            return r;
        }
        pub fn step(self: *Self, src: anytype, _: In) ?Out {
            const n = self.n;
            self.n += 1;
            var v: [4]f64 = undefined;
            var ok = true;
            inline for (0..4) |i| {
                if (n >= self.start[i]) {
                    const view = RocView(@TypeOf(src)){ .s = src, .off = self.start[i], .roc = self.roc[i] };
                    const x = comp.rocPct(src, n, self.roc[i]);
                    if (self.legs[i].step(view, x)) |r| v[i] = r else ok = false;
                } else ok = false;
            }
            if (!ok) return null;
            const kv = @mulAdd(f64, 4.0, v[3], @mulAdd(f64, 3.0, v[2], @mulAdd(f64, 2.0, v[1], v[0])));
            self.ring.push(kv);
            const s = self.sig.step(self.ring.view(), kv) orelse return null;
            return .{ .kst = kv, .signal = s };
        }
        pub fn peekStep(self: *const Self, src: anytype, b: In) ?Out {
            return mu.peekRings(Self, self, src, b);
        }
    };
}
pub const KST = KstCore(false);
pub const KSTEXT = KstCore(true);

pub fn kstLookback(p: KstParams) Error!usize {
    try KST.validate(p);
    return KST.lookback(p);
}
/// Outputs `kst` and its `signal`.
pub fn kst(comptime T: type, gpa: std.mem.Allocator, in: []const T, out_kst: []T, out_signal: []T, p: KstParams) core.AllocError!usize {
    return vs.batchScratch(T, KST, gpa, p, .{ .x = in }, .{ out_kst, out_signal });
}
pub fn KstStream(comptime T: type) type {
    return vs.SingleStream(T, KST);
}
pub fn kstextLookback(p: KstextParams) Error!usize {
    try KSTEXT.validate(p);
    return KSTEXT.lookback(p);
}
pub fn kstext(comptime T: type, gpa: std.mem.Allocator, in: []const T, out_kst: []T, out_signal: []T, p: KstextParams) core.AllocError!usize {
    return vs.batchScratch(T, KSTEXT, gpa, p, .{ .x = in }, .{ out_kst, out_signal });
}
pub fn KstextStream(comptime T: type) type {
    return vs.SingleStream(T, KSTEXT);
}

// ── KDJ ─────────────────────────────────────────────────────────────────────

/// KDJ = STOCH with J = 3K - 2D. The default moving average is TA-Lib's RMA
/// (type 13).
pub const KdjParams = struct {
    fastk: usize = 9,
    slowk: usize = 3,
    slowk_ma: MaType = .rma,
    slowd: usize = 3,
    slowd_ma: MaType = .rma,
    unstable: Unstable = core.no_unstable,
};

fn stochParams(p: KdjParams) stoch_.StochParams {
    return .{ .fastk = p.fastk, .slowk = p.slowk, .slowk_ma = p.slowk_ma, .slowd = p.slowd, .slowd_ma = p.slowd_ma, .unstable = p.unstable };
}

pub fn kdjLookback(p: KdjParams) Error!usize {
    return stoch_.stochLookback(stochParams(p));
}

fn jOf(k: f64, d: f64) f64 {
    return 3.0 * k - 2.0 * d;
}

/// Outputs K, D (the slow stochastic) and J. The math is f64; for `f32` input
/// the series are widened into `gpa` memory so that J is the f64 value rounded
/// once.
pub fn kdj(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, out_k: []T, out_d: []T, out_j: []T, p: KdjParams) core.AllocError!usize {
    core.checkFloat(T);
    try core.checkLen(high.len, &.{ low.len, close.len, out_k.len, out_d.len, out_j.len });
    const sp = stochParams(p);
    const n = high.len;
    if (T == f64) {
        const lb = try stoch_.stoch(f64, gpa, high, low, close, out_k, out_d, sp);
        for (out_j, out_k, out_d) |*j, k, d| j.* = jOf(k, d);
        return lb;
    }
    const buf = try gpa.alloc(f64, 6 * n);
    defer gpa.free(buf);
    for (buf[0..n], high) |*d, s| d.* = s;
    for (buf[n .. 2 * n], low) |*d, s| d.* = s;
    for (buf[2 * n .. 3 * n], close) |*d, s| d.* = s;
    const lb = try stoch_.stoch(f64, gpa, buf[0..n], buf[n .. 2 * n], buf[2 * n .. 3 * n], buf[3 * n .. 4 * n], buf[4 * n .. 5 * n], sp);
    for (0..n) |i| {
        out_k[i] = @floatCast(buf[3 * n + i]);
        out_d[i] = @floatCast(buf[4 * n + i]);
        out_j[i] = @floatCast(jOf(buf[3 * n + i], buf[4 * n + i]));
    }
    return lb;
}

pub fn KdjStream(comptime T: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        pub const Output = struct { k: T, d: T, j: T };
        s: stoch_.StochStream(f64),
        last: ?Output = null,

        pub fn bufLen(p: KdjParams) Error!usize {
            return stoch_.StochStream(f64).bufLen(stochParams(p));
        }
        pub fn init(p: KdjParams, buf: []f64) Error!Self {
            return .{ .s = try stoch_.StochStream(f64).init(stochParams(p), buf) };
        }
        fn conv(o: stoch_.StochOut(f64)) Output {
            return .{ .k = @floatCast(o.k), .d = @floatCast(o.d), .j = @floatCast(jOf(o.k, o.d)) };
        }
        pub fn update(self: *Self, bar: core.Bar(T)) ?Output {
            const r = self.s.update(core.to(core.Bar(f64), bar)) orelse return null;
            self.last = conv(r);
            return self.last;
        }
        pub fn peek(self: *const Self, bar: core.Bar(T)) ?Output {
            const r = self.s.peek(core.to(core.Bar(f64), bar)) orelse return null;
            return conv(r);
        }
        pub fn value(self: *const Self) ?Output {
            return self.last;
        }
    };
}

// ── STOCHRSI ────────────────────────────────────────────────────────────────

pub const StochrsiParams = struct {
    period: usize = 14,
    fastk: usize = 5,
    fastd: usize = 3,
    fastd_ma: MaType = .sma,
    unstable: Unstable = core.no_unstable,
};

pub const STOCHRSI = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = struct { fastk: f64, fastd: f64 };
    pub const Params = StochrsiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { fastk: T, fastd: T };
    }
    rsi: rsi_.RsiCore,
    k: stoch_.KCore,
    d: MaCore,
    r_ring: mu.Ring,
    k_ring: mu.Ring,
    n: usize = 0,

    fn dParams(p: Params) smooth.MaParams {
        return .{ .period = p.fastd, .kind = p.fastd_ma, .unstable = p.unstable };
    }
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
        try core.checkPeriod(p.fastk, 1);
        try core.checkPeriod(p.fastd, 1);
        try p.unstable.check();
        try MaCore.validate(dParams(p));
    }
    pub fn lookback(p: Params) usize {
        return rsi_.RsiCore.lookback(.{ .period = p.period, .unstable = p.unstable }) + p.fastk - 1 + MaCore.lookback(dParams(p));
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn scratchLen(p: Params) usize {
        return p.fastk + MaCore.ringLen(dParams(p));
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        const need = scratchLen(p);
        if (scratch.len < need) return error.BadParam;
        var rest = scratch;
        const rr = mu.carve(&rest, p.fastk);
        const kr = mu.carve(&rest, MaCore.ringLen(dParams(p)));
        return .{
            .rsi = try rsi_.RsiCore.init(.{ .period = p.period, .unstable = p.unstable }),
            .k = stoch_.KCore.init(p.fastk),
            .d = try MaCore.init(dParams(p)),
            .r_ring = rr,
            .k_ring = kr,
        };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?Out {
        self.n += 1;
        const r = self.rsi.step(NoSrc{}, b.x) orelse return null;
        self.r_ring.push(r);
        const v = self.r_ring.view();
        const kv = self.k.step(v, v, .{ .high = r, .low = r, .close = r }) orelse return null;
        self.k_ring.push(kv);
        const dv = self.d.step(self.k_ring.view(), kv) orelse return null;
        return .{ .fastk = kv, .fastd = dv };
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?Out {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn stochrsiLookback(p: StochrsiParams) Error!usize {
    try STOCHRSI.validate(p);
    return STOCHRSI.lookback(p);
}
/// Outputs fast %K and fast %D of the RSI.
pub fn stochrsi(comptime T: type, gpa: std.mem.Allocator, in: []const T, fastk: []T, fastd: []T, p: StochrsiParams) core.AllocError!usize {
    return vs.batchScratch(T, STOCHRSI, gpa, p, .{ .x = in }, .{ fastk, fastd });
}
pub fn StochrsiStream(comptime T: type) type {
    return vs.SingleStream(T, STOCHRSI);
}

// ── CRSI (connors RSI) ──────────────────────────────────────────────────────

pub const CrsiParams = struct {
    period: usize = 3,
    streak: usize = 2,
    rank: usize = 100,
    unstable: Unstable = core.no_unstable,
};

/// (RSI(close) + RSI(up/down streak length) + percent rank of the 1-bar ROC) / 3.
pub const CRSI = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = CrsiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    rsi: rsi_.RsiCore,
    srsi: rsi_.RsiCore,
    ring: mu.Ring,
    pr: stat.PercentrankCore,
    prev: f64 = 0.0,
    streak: f64 = 0.0,
    n: usize = 0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
        try core.checkPeriod(p.streak, 2);
        if (p.rank < 2 or p.rank > 10000) return error.BadParam;
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        const a = rsi_.RsiCore.lookback(.{ .period = p.period, .unstable = p.unstable });
        const b = rsi_.RsiCore.lookback(.{ .period = p.streak, .unstable = p.unstable }) + 1;
        return @max(a, @max(b, p.rank + 1));
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn scratchLen(p: Params) usize {
        return p.rank + 1;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < p.rank + 1) return error.BadParam;
        return .{
            .rsi = try rsi_.RsiCore.init(.{ .period = p.period, .unstable = p.unstable }),
            .srsi = try rsi_.RsiCore.init(.{ .period = p.streak, .unstable = p.unstable }),
            .ring = mu.Ring.init(scratch[0 .. p.rank + 1]),
            .pr = try stat.PercentrankCore.init(.{ .period = p.rank }),
        };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const x = b.x;
        const r = self.rsi.step(NoSrc{}, x);
        if (n == 0) {
            self.prev = x;
            return null;
        }
        const close = x;
        if (close > self.prev) {
            self.streak = if (self.streak > 0.0) self.streak + 1.0 else 1.0;
        } else if (close < self.prev) {
            self.streak = if (self.streak < 0.0) self.streak - 1.0 else -1.0;
        } else {
            self.streak = 0.0;
        }
        const rocp = if (self.prev != 0.0) (close - self.prev) / self.prev else 0.0;
        self.prev = close;
        const sr = self.srsi.step(NoSrc{}, self.streak);
        self.ring.push(rocp);
        // percent rank of the ROCP value among the previous `rank` ones (the ring holds rank + 1)
        const prank = self.pr.step(self.ring.view(), rocp) orelse return null;
        if (r == null or sr == null) return null;
        return (r.? + sr.? + prank) / 3.0;
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?f64 {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn crsiLookback(p: CrsiParams) Error!usize {
    try CRSI.validate(p);
    return CRSI.lookback(p);
}
pub fn crsi(comptime T: type, gpa: std.mem.Allocator, in: []const T, out: []T, p: CrsiParams) core.AllocError!usize {
    return vs.batchScratch(T, CRSI, gpa, p, .{ .x = in }, .{out});
}
pub fn CrsiStream(comptime T: type) type {
    return vs.SingleStream(T, CRSI);
}

// ── STC (Schaff trend cycle) ────────────────────────────────────────────────

pub const StcParams = struct {
    fast: usize = 23,
    slow: usize = 50,
    cycle: usize = 10,
    unstable: Unstable = core.no_unstable,
};

pub const STC = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = StcParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    fast: EmaCore,
    slow: EmaCore,
    skip_fast: usize,
    l_line: usize, // bar of the first line value (the slow EMA's lookback)
    l_total: usize,
    cycle: usize,
    lines: mu.Ring,
    pfs: mu.Ring,
    frac1: f64 = 0.0,
    frac2: f64 = 0.0,
    pf_v: f64 = 0.0,
    pff: f64 = 0.0,
    n: usize = 0,

    fn swapped(p: Params) [2]usize {
        return .{ @min(p.fast, p.slow), @max(p.fast, p.slow) };
    }
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try core.checkPeriod(p.cycle, 2);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        const sl = swapped(p)[1];
        const stc_u = p.unstable.get((5 * 10 + 1) / 2 + 3 * (sl + 1), (5 * 19 + 1) / 2 + 3 * (sl + 1));
        return EmaCore.lookbackOf(sl, p.unstable, .sma) + 2 * (p.cycle - 1) + stc_u;
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn scratchLen(p: Params) usize {
        return 2 * p.cycle;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < 2 * p.cycle) return error.BadParam;
        const sw = swapped(p);
        const lf = EmaCore.lookbackOf(sw[0], p.unstable, .sma);
        const ls = EmaCore.lookbackOf(sw[1], p.unstable, .sma);
        var rest = scratch;
        return .{
            .fast = try EmaCore.init(.{ .period = sw[0], .unstable = p.unstable }),
            .slow = try EmaCore.init(.{ .period = sw[1], .unstable = p.unstable }),
            .skip_fast = ls - lf,
            .l_line = ls,
            .l_total = lookback(p),
            .cycle = p.cycle,
            .lines = mu.carve(&rest, p.cycle),
            .pfs = mu.carve(&rest, p.cycle),
        };
    }
    /// frac = position of `v` inside the min..max of the ring's last `cycle` values
    fn windowFrac(r: mu.Ring, cycle: usize, v: f64, frac: f64) f64 {
        var hi = v;
        var lo = v;
        var i = r.n - cycle;
        while (i < r.n - 1) : (i += 1) {
            const t = r.at(i);
            if (t > hi) hi = t;
            if (t < lo) lo = t;
        }
        const range = hi - lo;
        return if (range > 0.0) (v - lo) / range * 100.0 else frac;
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const s = self.slow.step(NoSrc{}, b.x);
        const f = if (n >= self.skip_fast) self.fast.step(NoSrc{}, b.x) else null;
        if (s == null or f == null) return null;
        const line = f.? - s.?;
        self.lines.push(line);
        if (self.lines.n < self.cycle) return null;
        self.frac1 = windowFrac(self.lines, self.cycle, line, self.frac1);
        if (self.pfs.n == 0) {
            self.pf_v = self.frac1;
        } else {
            self.pf_v = @mulAdd(f64, 0.5, self.frac1 - self.pf_v, self.pf_v);
        }
        self.pfs.push(self.pf_v);
        if (self.pfs.n < self.cycle) return null;
        self.frac2 = windowFrac(self.pfs, self.cycle, self.pf_v, self.frac2);
        if (self.pfs.n == self.cycle) {
            self.pff = self.frac2;
        } else {
            self.pff = @mulAdd(f64, 0.5, self.frac2 - self.pff, self.pff);
        }
        return if (n >= self.l_total) self.pff else null;
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?f64 {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn stcLookback(p: StcParams) Error!usize {
    try STC.validate(p);
    return STC.lookback(p);
}
pub fn stc(comptime T: type, gpa: std.mem.Allocator, in: []const T, out: []T, p: StcParams) core.AllocError!usize {
    return vs.batchScratch(T, STC, gpa, p, .{ .x = in }, .{out});
}
pub fn StcStream(comptime T: type) type {
    return vs.SingleStream(T, STC);
}

// ── SQZMOM (squeeze momentum) ───────────────────────────────────────────────

fn closeFrom(s: anytype, off: usize) @TypeOf(vs.offset(vs.field(s, "close"), off)) {
    return vs.offset(vs.field(s, "close"), off);
}

fn sqzTr(src: anytype, g: usize) f64 {
    const t = src.at(g);
    const pc = src.at(g - 1).close;
    var tr = t.high - t.low;
    var d = @abs(pc - t.high);
    if (d > tr) tr = d;
    d = @abs(pc - t.low);
    if (d > tr) tr = d;
    return tr;
}

/// The true-range series from bar `off`, over the input ring.
fn TrView(comptime S: type) type {
    return struct {
        s: S,
        off: usize,
        pub fn at(self: @This(), i: usize) f64 {
            return sqzTr(self.s, self.off + i);
        }
    };
}

pub const SqzmomParams = struct {
    bb_period: usize = 20,
    nb_dev: f64 = 2.0,
    kc_period: usize = 20,
    factor_wide: f64 = 2.0,
    factor_normal: f64 = 1.5,
    factor_narrow: f64 = 1.0,
};

fn okFactor(x: f64) bool {
    return x >= 0.0 and x <= 3.0e37; // TA_REAL_MAX
}

/// Momentum (linear regression of close minus the average of the donchian
/// midline and the SMA) and squeeze state: 3 / 2 / 1 when the Bollinger bands
/// are inside the narrow / normal / wide Keltner channel, -1 when outside the
/// wide one, 0 otherwise.
pub const SQZMOM = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = struct { momentum: f64, squeeze: i8 };
    pub const Params = SqzmomParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { momentum: T, squeeze: i8 };
    }
    bb: usize,
    kc: usize,
    l: usize,
    nb_dev: f64,
    fw: f64,
    fnm: f64,
    fnr: f64,
    mid: smooth.SmaCore,
    sd: bands.VarCore,
    kcm: smooth.SmaCore,
    band: smooth.SmaCore,
    lr: stat.LinearregCore,
    mp: overlap.MidpriceCore,
    dev: mu.Ring,
    n: usize = 0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.bb_period, 2);
        try core.checkPeriod(p.kc_period, 2);
        if (!okFactor(p.nb_dev) or !okFactor(p.factor_wide) or !okFactor(p.factor_normal) or !okFactor(p.factor_narrow)) return error.BadParam;
        if (p.factor_normal > p.factor_wide or p.factor_narrow > p.factor_normal) return error.BadParam;
    }
    pub fn lookback(p: Params) usize {
        return @max(p.bb_period - 1, @max(p.kc_period, 2 * p.kc_period - 2));
    }
    pub fn ringLen(p: Params) usize {
        return @max(p.bb_period, p.kc_period + 1) + 1;
    }
    pub fn scratchLen(p: Params) usize {
        return p.kc_period;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < p.kc_period) return error.BadParam;
        return .{
            .bb = p.bb_period,
            .kc = p.kc_period,
            .l = lookback(p),
            .nb_dev = p.nb_dev,
            .fw = p.factor_wide,
            .fnm = p.factor_normal,
            .fnr = p.factor_narrow,
            .mid = try smooth.SmaCore.init(.{ .period = p.bb_period }),
            .sd = bands.VarCore.init(p.bb_period),
            .kcm = try smooth.SmaCore.init(.{ .period = p.kc_period }),
            .band = try smooth.SmaCore.init(.{ .period = p.kc_period }),
            .lr = try stat.LinearregCore.init(.{ .period = p.kc_period }),
            .mp = try overlap.MidpriceCore.init(.{ .period = p.kc_period }),
            .dev = mu.Ring.init(scratch[0..p.kc_period]),
        };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?Out {
        const n = self.n;
        self.n += 1;
        const l = self.l;
        const kc1 = self.kc - 1;
        const stage = l - kc1; // first bar of the keltner stage
        const close_at = closeFrom;
        var mid_v: ?f64 = null;
        var sd_v: ?f64 = null;
        if (n + self.bb > l) {
            const s = close_at(src, l + 1 - self.bb);
            mid_v = self.mid.step(s, b.close);
            sd_v = self.sd.step(s, b.close);
        }
        var kcm_v: ?f64 = null;
        if (n >= l - 2 * kc1) kcm_v = self.kcm.step(close_at(src, l - 2 * kc1), b.close);
        // midprice of the last kc bars (stepped on every bar: the extreme tracker keeps its own index)
        const mp_v = self.mp.step(src, .{ .high = b.high, .low = b.low });
        if (n < stage) return null;
        const mp = mp_v.?;
        const dev = b.close - (mp + kcm_v.?) / 2.0;
        self.dev.push(dev);
        const mom = self.lr.step(self.dev.view(), dev);
        const tr = sqzTr(src, n);
        const tv = TrView(@TypeOf(src)){ .s = src, .off = stage };
        const band = self.band.step(tv, tr);
        if (n < l) return null;
        const sdv = @sqrt(sd_v.?);
        const dv = sdv * self.nb_dev;
        const up = mid_v.? + dv;
        const lo = mid_v.? - dv;
        const centre = kcm_v.?;
        const bd = band.?;
        const sq: i8 = if (lo > centre - self.fnr * bd and up < centre + self.fnr * bd)
            3
        else if (lo > centre - self.fnm * bd and up < centre + self.fnm * bd)
            2
        else if (lo > centre - self.fw * bd and up < centre + self.fw * bd)
            1
        else if (lo < centre - self.fw * bd and up > centre + self.fw * bd)
            -1
        else
            0;
        return .{ .momentum = mom.?, .squeeze = sq };
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?Out {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn sqzmomLookback(p: SqzmomParams) Error!usize {
    try SQZMOM.validate(p);
    return SQZMOM.lookback(p);
}
/// Outputs the momentum and the squeeze state (`i8`, 0 in the lead).
pub fn sqzmom(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, momentum: []T, squeeze: []i8, p: SqzmomParams) core.AllocError!usize {
    return mu.batchLead0(T, SQZMOM, gpa, p, .{ .high = high, .low = low, .close = close }, .{ momentum, squeeze });
}
pub fn SqzmomStream(comptime T: type) type {
    return vs.Stream(T, SQZMOM);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "comp2: batch == streaming, lookback == NaN lead" {
    try mu.checkCore(KST, .{}, 300, 1);
    try mu.checkCore(KST, .{ .roc1 = 1, .roc2 = 2, .roc3 = 3, .roc4 = 4, .sma1 = 1, .sma2 = 2, .sma3 = 3, .sma4 = 1, .signal = 1 }, 60, 2);
    try mu.checkCore(KSTEXT, .{}, 300, 3);
    try mu.checkCore(KSTEXT, .{ .roc_ma = .ema, .signal_ma = .wma, .ma1 = 3, .ma2 = 5, .ma3 = 4, .ma4 = 6, .signal = 4, .roc1 = 2, .roc2 = 3, .roc3 = 5, .roc4 = 8 }, 100, 4);
    try mu.checkCore(STOCHRSI, .{}, 200, 5);
    try mu.checkCore(STOCHRSI, .{ .period = 3, .fastk = 1, .fastd = 2, .fastd_ma = .ema, .unstable = .{ .bars = 3 } }, 100, 6);
    try mu.checkCore(CRSI, .{}, 300, 7);
    try mu.checkCore(CRSI, .{ .period = 2, .streak = 3, .rank = 5, .unstable = .{ .bars = 2 } }, 100, 8);
    try mu.checkCore(STC, .{}, 300, 9);
    try mu.checkCore(STC, .{ .fast = 5, .slow = 3, .cycle = 2, .unstable = .{ .bars = 4 } }, 100, 10);
    try mu.checkCore(STC, .{ .unstable = .auto4 }, 600, 11);
}

test "comp2: f32 path" {
    try mu.checkF32(KST, .{}, 120, 21);
    try mu.checkF32(STOCHRSI, .{}, 100, 22);
    try mu.checkF32(CRSI, .{}, 150, 23);
    try mu.checkF32(STC, .{}, 150, 24);
}

test "comp2: BadParam" {
    var o: [4]f64 = undefined;
    const x = [_]f64{ 1, 2, 3, 4 };
    const gpa = testing.allocator;
    try testing.expectError(error.BadParam, kst(f64, gpa, &x, &o, &o, .{ .roc2 = 0 }));
    try testing.expectError(error.BadParam, kstext(f64, gpa, &x, &o, &o, .{ .signal = 100001 }));
    try testing.expectError(error.BadParam, stochrsi(f64, gpa, &x, &o, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, crsi(f64, gpa, &x, &o, .{ .rank = 10001 }));
    try testing.expectError(error.BadParam, stc(f64, gpa, &x, &o, .{ .cycle = 1 }));
    var sq: [4]i8 = undefined;
    try testing.expectError(error.BadParam, sqzmom(f64, gpa, &x, &x, &x, &o, &sq, .{ .factor_normal = 3.0 }));
    try testing.expectError(error.BadParam, sqzmom(f64, gpa, &x, &x, &x, &o, &sq, .{ .nb_dev = -1.0 }));
    // MAMA works in every MaType slot (cycle wave)
    try testing.expectEqual(try kstextLookback(.{ .roc_ma = .mama }), try kstext(f64, gpa, &x, &o, &o, .{ .roc_ma = .mama }));
}

test "kst: SMA legs equal kstext with SMA kinds, bitwise" {
    const gpa = testing.allocator;
    const b = try mu.Bars.make(gpa, 200, 77);
    defer b.free(gpa);
    var k1: [200]f64 = undefined;
    var s1: [200]f64 = undefined;
    var k2: [200]f64 = undefined;
    var s2: [200]f64 = undefined;
    const lb1 = try kst(f64, gpa, b.c, &k1, &s1, .{});
    const lb2 = try kstext(f64, gpa, b.c, &k2, &s2, .{});
    try testing.expectEqual(lb1, lb2);
    for (0..200) |i| {
        try testing.expect(@import("testhelp.zig").sameBits(k1[i], k2[i]));
        try testing.expect(@import("testhelp.zig").sameBits(s1[i], s2[i]));
    }
}

test "sqzmom: batch == streaming, shape, hand check of the lead" {
    const gpa = testing.allocator;
    const b = try mu.Bars.make(gpa, 150, 31);
    defer b.free(gpa);
    var mom: [150]f64 = undefined;
    var sq: [150]i8 = undefined;
    const p = SqzmomParams{};
    const lb = try sqzmom(f64, gpa, b.h, b.l, b.c, &mom, &sq, p);
    try testing.expectEqual(@as(usize, 38), lb);
    for (0..lb) |i| try testing.expect(std.math.isNan(mom[i]) and sq[i] == 0);
    const S = SqzmomStream(f64);
    const buf = try gpa.alloc(f64, try S.bufLen(p));
    defer gpa.free(buf);
    var s = try S.init(p, buf);
    for (0..150) |i| {
        const bar = S.Input{ .high = b.h[i], .low = b.l[i], .close = b.c[i] };
        const pk = s.peek(bar);
        const got = s.update(bar);
        if (i < lb) {
            try testing.expect(got == null and pk == null);
        } else {
            try testing.expect(@import("testhelp.zig").sameBits(mom[i], got.?.momentum));
            try testing.expectEqual(sq[i], got.?.squeeze);
            try testing.expectEqual(sq[i], pk.?.squeeze);
            try testing.expect(sq[i] >= -1 and sq[i] <= 3);
        }
    }
}

test "sqzmom: f32 equals the rounded f64 run" {
    const gpa = testing.allocator;
    const b = try mu.Bars.make(gpa, 90, 32);
    defer b.free(gpa);
    var h32: [90]f32 = undefined;
    var l32: [90]f32 = undefined;
    var c32: [90]f32 = undefined;
    var h64: [90]f64 = undefined;
    var l64: [90]f64 = undefined;
    var c64: [90]f64 = undefined;
    for (0..90) |i| {
        h32[i] = @floatCast(b.h[i]);
        l32[i] = @floatCast(b.l[i]);
        c32[i] = @floatCast(b.c[i]);
        h64[i] = h32[i];
        l64[i] = l32[i];
        c64[i] = c32[i];
    }
    var m32: [90]f32 = undefined;
    var m64: [90]f64 = undefined;
    var q32: [90]i8 = undefined;
    var q64: [90]i8 = undefined;
    _ = try sqzmom(f32, gpa, &h32, &l32, &c32, &m32, &q32, .{});
    _ = try sqzmom(f64, gpa, &h64, &l64, &c64, &m64, &q64, .{});
    for (0..90) |i| {
        try testing.expect((std.math.isNan(m32[i]) and std.math.isNan(m64[i])) or m32[i] == @as(f32, @floatCast(m64[i])));
        try testing.expectEqual(q64[i], q32[i]);
    }
}

test "kdj: J = 3K - 2D, batch == streaming" {
    const gpa = testing.allocator;
    const b = try mu.Bars.make(gpa, 100, 41);
    defer b.free(gpa);
    const p = KdjParams{ .slowk_ma = .sma, .slowd_ma = .ema };
    var k: [100]f64 = undefined;
    var d: [100]f64 = undefined;
    var j: [100]f64 = undefined;
    const lb = try kdj(f64, gpa, b.h, b.l, b.c, &k, &d, &j, p);
    try testing.expectEqual(try kdjLookback(p), lb);
    const S = KdjStream(f64);
    const buf = try gpa.alloc(f64, try S.bufLen(p));
    defer gpa.free(buf);
    var s = try S.init(p, buf);
    for (0..100) |i| {
        const bar = core.Bar(f64){ .high = b.h[i], .low = b.l[i], .close = b.c[i] };
        const pk = s.peek(bar);
        const got = s.update(bar);
        if (i < lb) {
            try testing.expect(std.math.isNan(j[i]) and got == null);
        } else {
            try testing.expectEqual(3.0 * k[i] - 2.0 * d[i], j[i]);
            try testing.expectEqual(j[i], got.?.j);
            try testing.expectEqual(k[i], pk.?.k);
        }
    }
    // f32: J is the f64 value rounded once
    var h32: [100]f32 = undefined;
    var l32: [100]f32 = undefined;
    var c32: [100]f32 = undefined;
    var k32: [100]f32 = undefined;
    var d32: [100]f32 = undefined;
    var j32: [100]f32 = undefined;
    for (0..100) |i| {
        h32[i] = @floatCast(b.h[i]);
        l32[i] = @floatCast(b.l[i]);
        c32[i] = @floatCast(b.c[i]);
    }
    _ = try kdj(f32, gpa, &h32, &l32, &c32, &k32, &d32, &j32, p);
    try testing.expect(!std.math.isNan(j32[99]));
}

test "kstext / stochrsi / kdj: every MaType in every slot, KDJ defaults to RMA" {
    inline for (comptime std.enums.values(core.MaType), 0..) |k, i| {
        try mu.checkCore(KSTEXT, .{ .roc_ma = k, .signal_ma = k, .ma1 = 3, .ma2 = 4, .ma3 = 3, .ma4 = 5, .signal = 3, .roc1 = 2, .roc2 = 3, .roc3 = 4, .roc4 = 6 }, 120, 300 + i);
        try mu.checkCore(STOCHRSI, .{ .period = 5, .fastk = 3, .fastd = 2, .fastd_ma = k }, 120, 400 + i);
        const p = KdjParams{ .slowk_ma = k, .slowd_ma = k };
        try testing.expectEqual(try stoch_.stochLookback(stochParams(p)), try kdjLookback(p));
    }
    const d = KdjParams{};
    try testing.expectEqual(core.MaType.rma, d.slowk_ma);
    try testing.expectEqual(core.MaType.rma, d.slowd_ma);
    const gpa = testing.allocator;
    const b = try mu.Bars.make(gpa, 80, 7);
    defer b.free(gpa);
    var k1: [80]f64 = undefined;
    var d1: [80]f64 = undefined;
    var j1: [80]f64 = undefined;
    var k2: [80]f64 = undefined;
    var d2: [80]f64 = undefined;
    const lb = try kdj(f64, gpa, b.h, b.l, b.c, &k1, &d1, &j1, .{});
    // the defaults are STOCH with RMA smoothing
    try testing.expectEqual(lb, try stoch_.stoch(f64, gpa, b.h, b.l, b.c, &k2, &d2, .{ .fastk = 9, .slowk = 3, .slowk_ma = .rma, .slowd = 3, .slowd_ma = .rma }));
    for (lb..80) |i| try testing.expectEqual(k2[i], k1[i]);
}
