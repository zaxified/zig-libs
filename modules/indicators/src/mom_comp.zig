// SPDX-License-Identifier: MIT
//! Composite oscillators of the momentum group, ported from TA-Lib 0.8.3
//! (`ta_TRIX.c`, `ta_APO.c`, `ta_PPO.c`, `ta_COPPOCK.c`, `ta_ERI.c`,
//! `ta_DOSC.c`, `ta_FISHER.c`, `ta_PSO.c`, `ta_SMI.c`, `ta_TSI.c`,
//! `ta_WAVETREND.c`; BSD-3, see NOTICE).
//!
//! The C writes each of them as one fused loop; the arithmetic is that of a
//! cascade of the seed cores (an SMA-seeded EMA fed from the previous stage's
//! first output, ...), so these are cascades of `EmaCore` / `SmaCore` /
//! `WmaCore` / `MaCore` with the extra per-bar formulas in between. The
//! `unstable` option of each function drives every EMA / RSI stage of it, which
//! is what TA-Lib's process-wide unstable period does.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const rsi_ = @import("rsi.zig");
const vs = @import("vs_kit.zig");
const mu = @import("mom_util.zig");
const xmath = @import("xmath.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const MaType = core.MaType;
const pf = core.pf;
const EmaCore = smooth.EmaCore;
const NoSrc = smooth.NoSrc;

const eps: f64 = 0.00000000000001; // TA_EPSILON
fn isZero(v: f64) bool {
    return (-eps < v) and (v < eps);
}
fn zeroScaled(v: f64, scale: f64) bool {
    return @abs(v) <= eps * scale;
}

fn ema(period: usize, un: Unstable) Error!EmaCore {
    return EmaCore.init(.{ .period = period, .unstable = un });
}
fn emaLb(period: usize, un: Unstable) usize {
    return EmaCore.lookbackOf(period, un, .sma);
}

// ── TRIX ────────────────────────────────────────────────────────────────────

pub const TrixParams = struct { period: usize = 30, unstable: Unstable = core.no_unstable };

/// 1-bar rate of change of a triple EMA, in percent.
pub const TRIX = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = TrixParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    e1: EmaCore,
    e2: EmaCore,
    e3: EmaCore,
    prev: ?f64 = null,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return 3 * emaLb(p.period, p.unstable) + 1;
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .e1 = try ema(p.period, p.unstable), .e2 = try ema(p.period, p.unstable), .e3 = try ema(p.period, p.unstable) };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        self.n += 1;
        const a = self.e1.step(NoSrc{}, b.x) orelse return null;
        const c = self.e2.step(NoSrc{}, a) orelse return null;
        const d = self.e3.step(NoSrc{}, c) orelse return null;
        const prev = self.prev;
        self.prev = d;
        const p = prev orelse return null;
        return if (p != 0.0) (d / p - 1.0) * 100.0 else 0.0;
    }
};
pub fn trixLookback(p: TrixParams) Error!usize {
    try TRIX.validate(p);
    return TRIX.lookback(p);
}
pub fn trix(comptime T: type, in: []const T, out: []T, p: TrixParams) Error!usize {
    return vs.batch(T, TRIX, p, .{ .x = in }, .{out});
}
pub fn TrixStream(comptime T: type) type {
    return vs.SingleStream(T, TRIX);
}

// ── APO / PPO ───────────────────────────────────────────────────────────────

pub const ApoParams = struct {
    fast: usize = 12,
    slow: usize = 26,
    /// TA-Lib 0.8.3's default is EMA.
    kind: MaType = .ema,
    unstable: Unstable = core.no_unstable,
};
pub const PpoParams = ApoParams;

fn windowedKind(k: MaType) bool {
    return k == .sma or k == .wma or k == .trima or k == .hma;
}

/// APO (`pct = false`): fast MA - slow MA. PPO (`pct = true`): that difference
/// over the slow MA, in percent, answering 0 when the slow MA is ~0 or (for the
/// windowed MA types) when the whole slow window is exactly zero.
pub fn ApoCore(comptime pct: bool) type {
    return struct {
        const Self = @This();
        pub const In = vs.X(f64);
        pub const Out = f64;
        pub const Params = ApoParams;
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return vs.X(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        fast: smooth.MaCore,
        slow: smooth.MaCore,
        win: bool,
        slow_lb: usize,
        zero_run: usize = 0,
        n: usize = 0,

        fn plans(p: Params) [2]smooth.MaParams {
            // TA-Lib swaps the periods so that the fast one is the shorter
            const lo = @min(p.fast, p.slow);
            const hi = @max(p.fast, p.slow);
            return .{
                .{ .period = lo, .kind = p.kind, .unstable = p.unstable },
                .{ .period = hi, .kind = p.kind, .unstable = p.unstable },
            };
        }
        pub fn validate(p: Params) Error!void {
            try core.checkPeriod(p.fast, 2);
            try core.checkPeriod(p.slow, 2);
            try p.unstable.check();
            const pl = plans(p);
            try smooth.MaCore.validate(pl[0]);
            try smooth.MaCore.validate(pl[1]);
        }
        pub fn lookback(p: Params) usize {
            return smooth.MaCore.lookback(plans(p)[1]);
        }
        pub fn ringLen(p: Params) usize {
            const pl = plans(p);
            return @max(smooth.MaCore.ringLen(pl[0]), smooth.MaCore.ringLen(pl[1]));
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            const pl = plans(p);
            return .{
                .fast = try smooth.MaCore.init(pl[0]),
                .slow = try smooth.MaCore.init(pl[1]),
                .win = windowedKind(p.kind),
                .slow_lb = smooth.MaCore.lookback(pl[1]),
            };
        }
        pub fn step(self: *Self, src: anytype, b: In) ?f64 {
            self.n += 1;
            const s = vs.field(src, "x");
            const f = self.fast.step(s, b.x);
            const sl = self.slow.step(s, b.x);
            self.zero_run = if (@abs(b.x) <= 0.0) @min(self.zero_run + 1, self.slow_lb + 1) else 0;
            if (f == null or sl == null) return null;
            if (!pct) return f.? - sl.?;
            if (self.win and self.zero_run > self.slow_lb) return 0.0;
            if (isZero(sl.?)) return 0.0;
            return (f.? - sl.?) / sl.? * 100.0;
        }
    };
}
pub const APO = ApoCore(false);
pub const PPO = ApoCore(true);

pub fn apoLookback(p: ApoParams) Error!usize {
    try APO.validate(p);
    return APO.lookback(p);
}
pub fn apo(comptime T: type, in: []const T, out: []T, p: ApoParams) Error!usize {
    return vs.batch(T, APO, p, .{ .x = in }, .{out});
}
pub fn ApoStream(comptime T: type) type {
    return vs.SingleStream(T, APO);
}
pub fn ppoLookback(p: PpoParams) Error!usize {
    try PPO.validate(p);
    return PPO.lookback(p);
}
pub fn ppo(comptime T: type, in: []const T, out: []T, p: PpoParams) Error!usize {
    return vs.batch(T, PPO, p, .{ .x = in }, .{out});
}
pub fn PpoStream(comptime T: type) type {
    return vs.SingleStream(T, PPO);
}

// ── COPPOCK ─────────────────────────────────────────────────────────────────

pub const CoppockParams = struct { wma: usize = 10, roc1: usize = 11, roc2: usize = 14 };

pub fn rocPct(src: anytype, g: usize, period: usize) f64 {
    const base = src.at(g - period).x;
    return if (base != 0.0) (src.at(g).x / base - 1.0) * 100.0 else 0.0;
}

fn RocSumView(comptime S: type) type {
    return struct {
        s: S,
        off: usize,
        r1: usize,
        r2: usize,
        pub fn at(self: @This(), i: usize) f64 {
            return rocPct(self.s, self.off + i, self.r1) + rocPct(self.s, self.off + i, self.r2);
        }
    };
}

/// WMA of (ROC1 + ROC2); the sum series is recomputed from the input ring.
pub const COPPOCK = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = CoppockParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    w: smooth.WmaCore,
    r1: usize,
    r2: usize,
    start: usize,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.wma, 1);
        try core.checkPeriod(p.roc1, 1);
        try core.checkPeriod(p.roc2, 1);
    }
    pub fn lookback(p: Params) usize {
        return @max(p.roc1, p.roc2) + p.wma - 1;
    }
    pub fn ringLen(p: Params) usize {
        return @max(p.roc1, p.roc2) + p.wma + 1;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .w = try smooth.WmaCore.init(.{ .period = p.wma }), .r1 = p.roc1, .r2 = p.roc2, .start = @max(p.roc1, p.roc2) };
    }
    pub fn step(self: *Self, src: anytype, _: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n < self.start) return null;
        const view = RocSumView(@TypeOf(src)){ .s = src, .off = self.start, .r1 = self.r1, .r2 = self.r2 };
        const v = rocPct(src, n, self.r1) + rocPct(src, n, self.r2);
        return self.w.step(view, v);
    }
};
pub fn coppockLookback(p: CoppockParams) Error!usize {
    try COPPOCK.validate(p);
    return COPPOCK.lookback(p);
}
pub fn coppock(comptime T: type, in: []const T, out: []T, p: CoppockParams) Error!usize {
    return vs.batch(T, COPPOCK, p, .{ .x = in }, .{out});
}
pub fn CoppockStream(comptime T: type) type {
    return vs.SingleStream(T, COPPOCK);
}

// ── ERI (Elder-ray) ─────────────────────────────────────────────────────────

pub const EriParams = struct { period: usize = 13, unstable: Unstable = core.no_unstable };

pub const ERI = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = struct { bull: f64, bear: f64 };
    pub const Params = EriParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { bull: T, bear: T };
    }
    e: EmaCore,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return emaLb(p.period, p.unstable);
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .e = try ema(p.period, p.unstable) };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?Out {
        self.n += 1;
        const m = self.e.step(NoSrc{}, b.close) orelse return null;
        return .{ .bull = b.high - m, .bear = b.low - m };
    }
};
pub fn eriLookback(p: EriParams) Error!usize {
    try ERI.validate(p);
    return ERI.lookback(p);
}
/// Outputs `bull` (high - EMA of close) and `bear` (low - EMA of close).
pub fn eri(comptime T: type, high: []const T, low: []const T, close: []const T, bull: []T, bear: []T, p: EriParams) Error!usize {
    return vs.batch(T, ERI, p, .{ .high = high, .low = low, .close = close }, .{ bull, bear });
}
pub fn EriStream(comptime T: type) type {
    return vs.Stream(T, ERI);
}

// ── DOSC (derivative oscillator) ────────────────────────────────────────────

pub const DoscParams = struct {
    period: usize = 14,
    first: usize = 5,
    second: usize = 3,
    signal: usize = 9,
    unstable: Unstable = core.no_unstable,
};

/// RSI, double-smoothed by two EMAs, minus its SMA(signal).
pub const DOSC = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = DoscParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    rsi: rsi_.RsiCore,
    e1: EmaCore,
    e2: EmaCore,
    sig: smooth.SmaCore,
    ring: mu.Ring,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
        try core.checkPeriod(p.first, 2);
        try core.checkPeriod(p.second, 2);
        try core.checkPeriod(p.signal, 2);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return rsi_.RsiCore.lookback(.{ .period = p.period, .unstable = p.unstable }) + emaLb(p.first, p.unstable) + emaLb(p.second, p.unstable) + p.signal - 1;
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn scratchLen(p: Params) usize {
        return p.signal;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < p.signal) return error.BadParam;
        return .{
            .rsi = try rsi_.RsiCore.init(.{ .period = p.period, .unstable = p.unstable }),
            .e1 = try ema(p.first, p.unstable),
            .e2 = try ema(p.second, p.unstable),
            .sig = try smooth.SmaCore.init(.{ .period = p.signal }),
            .ring = mu.Ring.init(scratch[0..p.signal]),
        };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        self.n += 1;
        const r = self.rsi.step(NoSrc{}, b.x) orelse return null;
        const a = self.e1.step(NoSrc{}, r) orelse return null;
        const c = self.e2.step(NoSrc{}, a) orelse return null;
        self.ring.push(c);
        const avg = self.sig.step(self.ring.view(), c) orelse return null;
        return c - avg;
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?f64 {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn doscLookback(p: DoscParams) Error!usize {
    try DOSC.validate(p);
    return DOSC.lookback(p);
}
pub fn dosc(comptime T: type, gpa: std.mem.Allocator, in: []const T, out: []T, p: DoscParams) core.AllocError!usize {
    return vs.batchScratch(T, DOSC, gpa, p, .{ .x = in }, .{out});
}
pub fn DoscStream(comptime T: type) type {
    return vs.SingleStream(T, DOSC);
}

// ── FISHER ──────────────────────────────────────────────────────────────────

pub const FisherParams = struct { period: usize = 10, unstable: Unstable = core.no_unstable };

pub const FISHER = struct {
    const Self = @This();
    pub const In = vs.Hl(f64);
    pub const Out = struct { fisher: f64, trigger: f64 };
    pub const Params = FisherParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { fisher: T, trigger: T };
    }
    p: usize,
    l: usize,
    n: usize = 0,
    smoothed: f64 = 0.0,
    prev_fish: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        // AUTO constants: (5 * (10 + 6) + 1) / 2 and (5 * (19 + 6) + 1) / 2
        return p.period - 1 + p.unstable.get(40, 63);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period, .l = lookback(p) };
    }
    fn mid(b: In) f64 {
        return (b.high + b.low) / 2.0;
    }
    pub fn step(self: *Self, src: anytype, b: In) ?Out {
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) return null;
        const price = mid(b);
        var highest = price;
        var lowest = price;
        var i = n + 1 - self.p;
        while (i < n) : (i += 1) {
            const t = mid(src.at(i));
            if (t > highest) highest = t;
            if (t < lowest) lowest = t;
        }
        const range = highest - lowest;
        const ratio = if (!zeroScaled(range, @abs(highest) + @abs(lowest))) (price - lowest) / range else 0.5;
        self.smoothed = @mulAdd(f64, 0.67, self.smoothed, @as(f64, 0.33) * 2.0 * (ratio - 0.5));
        if (self.smoothed > 0.99) self.smoothed = 0.999;
        if (self.smoothed < -0.99) self.smoothed = -0.999;
        const fish = @mulAdd(f64, 0.5, @log((1.0 + self.smoothed) / (1.0 - self.smoothed)), 0.5 * self.prev_fish);
        const trigger = self.prev_fish;
        self.prev_fish = fish;
        if (n < self.l) return null;
        return .{ .fisher = fish, .trigger = trigger };
    }
};
pub fn fisherLookback(p: FisherParams) Error!usize {
    try FISHER.validate(p);
    return FISHER.lookback(p);
}
/// Outputs `fisher` and `trigger` (the previous Fisher value).
pub fn fisher(comptime T: type, high: []const T, low: []const T, fish: []T, trigger: []T, p: FisherParams) Error!usize {
    return vs.batch(T, FISHER, p, .{ .high = high, .low = low }, .{ fish, trigger });
}
pub fn FisherStream(comptime T: type) type {
    return vs.Stream(T, FISHER);
}

// ── PSO (fast %K, smoothed twice by an EMA, squashed with tanh) ────────────

pub const PsoParams = struct { fastk: usize = 8, ema: usize = 5, unstable: Unstable = core.no_unstable };

pub const PSO = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = f64;
    pub const Params = PsoParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    k: usize,
    e1: EmaCore,
    e2: EmaCore,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.fastk, 1);
        try core.checkPeriod(p.ema, 1);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return p.fastk - 1 + 2 * emaLb(p.ema, p.unstable);
    }
    pub fn ringLen(p: Params) usize {
        return p.fastk;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .k = p.fastk, .e1 = try ema(p.ema, p.unstable), .e2 = try ema(p.ema, p.unstable) };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.k) return null;
        var highest = b.high;
        var lowest = b.low;
        var i = n + 1 - self.k;
        while (i < n) : (i += 1) {
            const t = src.at(i);
            if (t.high > highest) highest = t.high;
            if (t.low < lowest) lowest = t.low;
        }
        const range = highest - lowest;
        const fast_k = if (!zeroScaled(range, @abs(highest) + @abs(lowest))) (b.close - lowest) / range * 100.0 else 50.0;
        const nsk = 0.1 * (fast_k - 50.0);
        const a = self.e1.step(NoSrc{}, nsk) orelse return null;
        const c = self.e2.step(NoSrc{}, a) orelse return null;
        return xmath.tanh(0.5 * c);
    }
};
pub fn psoLookback(p: PsoParams) Error!usize {
    try PSO.validate(p);
    return PSO.lookback(p);
}
pub fn pso(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: PsoParams) Error!usize {
    return vs.batch(T, PSO, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn PsoStream(comptime T: type) type {
    return vs.Stream(T, PSO);
}

// ── SMI (stochastic momentum index) ─────────────────────────────────────────

pub const SmiParams = struct {
    period: usize = 13,
    fast: usize = 2,
    slow: usize = 25,
    signal: usize = 9,
    unstable: Unstable = core.no_unstable,
};

pub const SMI = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = struct { smi: f64, signal: f64 };
    pub const Params = SmiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { smi: T, signal: T };
    }
    p: usize,
    sn: EmaCore,
    sd: EmaCore,
    fnum: EmaCore,
    fden: EmaCore,
    sig: EmaCore,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try core.checkPeriod(p.signal, 2);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1 + emaLb(p.slow, p.unstable) + emaLb(p.fast, p.unstable) + emaLb(p.signal, p.unstable);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{
            .p = p.period,
            .sn = try ema(p.slow, p.unstable),
            .sd = try ema(p.slow, p.unstable),
            .fnum = try ema(p.fast, p.unstable),
            .fden = try ema(p.fast, p.unstable),
            .sig = try ema(p.signal, p.unstable),
        };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?Out {
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) return null;
        var highest = b.high;
        var lowest = b.low;
        var i = n + 1 - self.p;
        while (i < n) : (i += 1) {
            const t = src.at(i);
            if (t.high > highest) highest = t.high;
            if (t.low < lowest) lowest = t.low;
        }
        const den = highest - lowest;
        const num = b.close - (highest + lowest) * 0.5;
        // both members of a pair start together; step both before bailing out
        const a_n = self.sn.step(NoSrc{}, num);
        const a_d = self.sd.step(NoSrc{}, den);
        if (a_n == null or a_d == null) return null;
        const f_n = self.fnum.step(NoSrc{}, a_n.?);
        const f_d = self.fden.step(NoSrc{}, a_d.?);
        if (f_n == null or f_d == null) return null;
        const f = f_n.?;
        const half = 0.5 * f_d.?;
        const sv = if (half > 0.0) 100.0 * f / half else 0.0;
        const s = self.sig.step(NoSrc{}, sv) orelse return null;
        return .{ .smi = sv, .signal = s };
    }
};
pub fn smiLookback(p: SmiParams) Error!usize {
    try SMI.validate(p);
    return SMI.lookback(p);
}
/// Outputs `smi` and `signal`.
pub fn smi(comptime T: type, high: []const T, low: []const T, close: []const T, out_smi: []T, out_signal: []T, p: SmiParams) Error!usize {
    return vs.batch(T, SMI, p, .{ .high = high, .low = low, .close = close }, .{ out_smi, out_signal });
}
pub fn SmiStream(comptime T: type) type {
    return vs.Stream(T, SMI);
}

// ── TSI ─────────────────────────────────────────────────────────────────────

pub const TsiParams = struct { first: usize = 25, second: usize = 13, unstable: Unstable = core.no_unstable };

pub const TSI = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = TsiParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n1: EmaCore,
    d1: EmaCore,
    n2: EmaCore,
    d2: EmaCore,
    prev: f64 = 0.0,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.first, 2);
        try core.checkPeriod(p.second, 2);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return 1 + emaLb(p.first, p.unstable) + emaLb(p.second, p.unstable);
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{
            .n1 = try ema(p.first, p.unstable),
            .d1 = try ema(p.first, p.unstable),
            .n2 = try ema(p.second, p.unstable),
            .d2 = try ema(p.second, p.unstable),
        };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        const k = self.n;
        self.n += 1;
        if (k == 0) {
            self.prev = b.x;
            return null;
        }
        const mom = b.x - self.prev;
        self.prev = b.x;
        const a_n = self.n1.step(NoSrc{}, mom);
        const a_d = self.d1.step(NoSrc{}, @abs(mom));
        if (a_n == null or a_d == null) return null;
        const c_n = self.n2.step(NoSrc{}, a_n.?);
        const c_d = self.d2.step(NoSrc{}, a_d.?);
        if (c_n == null or c_d == null) return null;
        return if (c_d.? > 0.0) 100.0 * c_n.? / c_d.? else 0.0;
    }
};
pub fn tsiLookback(p: TsiParams) Error!usize {
    try TSI.validate(p);
    return TSI.lookback(p);
}
pub fn tsi(comptime T: type, in: []const T, out: []T, p: TsiParams) Error!usize {
    return vs.batch(T, TSI, p, .{ .x = in }, .{out});
}
pub fn TsiStream(comptime T: type) type {
    return vs.SingleStream(T, TSI);
}

// ── WAVETREND ───────────────────────────────────────────────────────────────

pub const WavetrendParams = struct {
    channel: usize = 10,
    average: usize = 21,
    signal: usize = 4,
    unstable: Unstable = core.no_unstable,
};

pub const WAVETREND = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = struct { wt1: f64, wt2: f64 };
    pub const Params = WavetrendParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { wt1: T, wt2: T };
    }
    ch: usize,
    esa: EmaCore,
    d: EmaCore,
    wt1: EmaCore,
    sig: smooth.SmaCore,
    ring: mu.Ring,
    prev_ap: f64 = 0.0,
    prev_esa: f64 = 0.0,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.channel, 2);
        try core.checkPeriod(p.average, 1);
        try core.checkPeriod(p.signal, 1);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return 2 * emaLb(p.channel, p.unstable) + emaLb(p.average, p.unstable) + p.signal - 1;
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn scratchLen(p: Params) usize {
        return p.signal;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < p.signal) return error.BadParam;
        return .{
            .ch = p.channel,
            .esa = try ema(p.channel, p.unstable),
            .d = try ema(p.channel, p.unstable),
            .wt1 = try ema(p.average, p.unstable),
            .sig = try smooth.SmaCore.init(.{ .period = p.signal }),
            .ring = mu.Ring.init(scratch[0..p.signal]),
        };
    }
    fn run(self: *Self, ap: f64, n_ap: usize) ?Out {
        const e = self.esa.step(NoSrc{}, ap) orelse return null;
        var num = ap - e;
        if (n_ap >= self.ch and ap == self.prev_ap and self.esa.prev == self.prev_esa) num = 0.0;
        const dv = self.d.step(NoSrc{}, @abs(num)) orelse return null;
        const scaled = 0.015 * dv;
        const ci = if (scaled > 0.0) num / scaled else 0.0;
        const w1 = self.wt1.step(NoSrc{}, ci) orelse return null;
        self.ring.push(w1);
        const w2 = self.sig.step(self.ring.view(), w1) orelse return null;
        return .{ .wt1 = w1, .wt2 = w2 };
    }
    pub fn step(self: *Self, _: anytype, b: In) ?Out {
        const n_ap = self.n;
        self.n += 1;
        const ap = (b.high + b.low + b.close) / 3.0;
        const r = self.run(ap, n_ap);
        self.prev_ap = ap;
        self.prev_esa = self.esa.prev;
        return r;
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?Out {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn wavetrendLookback(p: WavetrendParams) Error!usize {
    try WAVETREND.validate(p);
    return WAVETREND.lookback(p);
}
/// Outputs `wt1` and `wt2` (its SMA).
pub fn wavetrend(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, wt1: []T, wt2: []T, p: WavetrendParams) core.AllocError!usize {
    return vs.batchScratch(T, WAVETREND, gpa, p, .{ .high = high, .low = low, .close = close }, .{ wt1, wt2 });
}
pub fn WavetrendStream(comptime T: type) type {
    return vs.Stream(T, WAVETREND);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "comp group: batch == streaming, lookback == NaN lead" {
    try mu.checkCore(TRIX, .{}, 300, 1);
    try mu.checkCore(TRIX, .{ .period = 3, .unstable = .{ .bars = 2 } }, 100, 2);
    try mu.checkCore(APO, .{}, 100, 3);
    try mu.checkCore(APO, .{ .fast = 5, .slow = 3, .kind = .sma }, 100, 4);
    try mu.checkCore(APO, .{ .fast = 4, .slow = 9, .kind = .wma }, 100, 5);
    try mu.checkCore(PPO, .{}, 100, 6);
    try mu.checkCore(PPO, .{ .fast = 3, .slow = 6, .kind = .sma }, 100, 7);
    try mu.checkCore(COPPOCK, .{}, 100, 8);
    try mu.checkCore(COPPOCK, .{ .wma = 1, .roc1 = 2, .roc2 = 3 }, 60, 9);
    try mu.checkCore(ERI, .{}, 100, 10);
    try mu.checkCore(ERI, .{ .period = 1 }, 50, 11);
    try mu.checkCore(DOSC, .{}, 200, 12);
    try mu.checkCore(DOSC, .{ .period = 3, .first = 2, .second = 2, .signal = 2, .unstable = .{ .bars = 3 } }, 100, 13);
    try mu.checkCore(FISHER, .{}, 100, 14);
    try mu.checkCore(FISHER, .{ .period = 2, .unstable = .{ .bars = 5 } }, 100, 15);
    try mu.checkCore(PSO, .{}, 100, 16);
    try mu.checkCore(PSO, .{ .fastk = 1, .ema = 1 }, 50, 17);
    try mu.checkCore(SMI, .{}, 200, 18);
    try mu.checkCore(TSI, .{}, 200, 19);
    try mu.checkCore(TSI, .{ .first = 2, .second = 2, .unstable = .auto4 }, 200, 20);
    try mu.checkCore(WAVETREND, .{}, 200, 21);
    try mu.checkCore(WAVETREND, .{ .channel = 2, .average = 1, .signal = 1, .unstable = .{ .bars = 2 } }, 100, 22);
}

test "comp group: f32 path" {
    try mu.checkF32(TRIX, .{}, 200, 31);
    try mu.checkF32(PPO, .{}, 100, 32);
    try mu.checkF32(ERI, .{}, 100, 33);
    try mu.checkF32(SMI, .{}, 100, 34);
    try mu.checkF32(WAVETREND, .{}, 100, 35);
}

test "comp group: BadParam" {
    var o: [4]f64 = undefined;
    const x = [_]f64{ 1, 2, 3, 4 };
    try testing.expectError(error.BadParam, trix(f64, &x, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, apo(f64, &x, &o, .{ .fast = 1 }));
    try testing.expectError(error.BadParam, ppo(f64, &x, &o, .{ .slow = 100001 }));
    try testing.expectError(error.BadParam, coppock(f64, &x, &o, .{ .roc1 = 0 }));
    try testing.expectError(error.BadParam, eri(f64, &x, &x, &x, &o, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, fisher(f64, &x, &x, &o, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, tsi(f64, &x, &o, .{ .first = 1 }));
    try testing.expectError(error.BadParam, smi(f64, &x, &x, &x, &o, o[0..3], .{}));
    // MAMA works in every MaType slot (cycle wave): TA_MA's lookback of 32
    try testing.expectEqual(@as(usize, 32), try apo(f64, &x, &o, .{ .kind = .mama }));
}

test "apo / ppo hand vector" {
    // SMA(2) - SMA(3) of 1 2 4 8: bar 2: (3+... ) 6/... fast (2+4)/2 = 3, slow (1+2+4)/3 = 7/3
    const x = [_]f64{ 1, 2, 4, 8 };
    var o: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try apo(f64, &x, &o, .{ .fast = 2, .slow = 3, .kind = .sma }));
    try testing.expectApproxEqAbs(@as(f64, 3.0 - 7.0 / 3.0), o[2], 1e-15);
    _ = try ppo(f64, &x, &o, .{ .fast = 2, .slow = 3, .kind = .sma });
    try testing.expectApproxEqAbs(@as(f64, (3.0 - 7.0 / 3.0) / (7.0 / 3.0) * 100.0), o[2], 1e-12);
    // an all-zero window answers 0 for the windowed PPO
    const z = [_]f64{ 0, 0, 0, 0 };
    _ = try ppo(f64, &z, &o, .{ .fast = 2, .slow = 3, .kind = .sma });
    try testing.expectEqual(@as(f64, 0), o[3]);
}

test "trix on a ramp" {
    // EMA(2) triple of a ramp: all three EMAs lag by a constant, TRIX tends to the ramp's relative slope
    var x: [40]f64 = undefined;
    for (&x, 0..) |*v, i| v.* = 100.0 + @as(f64, @floatFromInt(i));
    var o: [40]f64 = undefined;
    const lb = try trix(f64, &x, &o, .{ .period = 2 });
    try testing.expectEqual(@as(usize, 4), lb);
    try testing.expect(o[39] > 0.5 and o[39] < 1.0);
}
