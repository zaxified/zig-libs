// SPDX-License-Identifier: MIT
//! The moving averages after SMA / EMA / WMA, ported from TA-Lib 0.8.3
//! (`ta_DEMA.c`, `ta_TEMA.c`, `ta_T3.c`, `ta_TRIMA.c`, `ta_KAMA.c`, `ta_ZLEMA.c`,
//! `ta_RMA.c`, `ta_VIDYA.c`, `ta_HMA.c`, `ta_ALMA.c`, `ta_MCGD.c`,
//! `ta_SWAK_BUTTER.c`, `ta_SWAK_GAUSS.c`; BSD-3, see NOTICE). Every one is a
//! by-value single-input core (`step(src, x) ?f64`, see `core.zig`); the
//! dispatcher `smooth.MaCore` embeds them so each works in every `MaType`
//! slot (MA, MACDEXT, BBANDS, STOCH, ...).

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const pf = core.pf;
const EmaCore = smooth.EmaCore;
const WmaCore = smooth.WmaCore;

/// `(int)sqrt((double)p)`.
fn isqrt(p: usize) usize {
    return @intFromFloat(@sqrt(pf(p)));
}

// ── DEMA / TEMA / T3: chains of EMAs ────────────────────────────────────────

pub const DemaParams = struct {
    period: usize = 30,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};
pub const TemaParams = DemaParams;
pub const T3Params = struct {
    period: usize = 5,
    vfactor: f64 = 0.7,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

const ChainKind = enum { dema, tema, t3 };

/// K EMAs in lockstep, each fed by the previous one. Stage j starts consuming at
/// bar `j * gap` and is seeded with the mean of its first `period` inputs; the
/// output starts at `lookback`. DEMA/TEMA: gap = EMA lookback (so the unstable
/// bars of every stage are skipped), T3: gap = period - 1 and the unstable bars
/// are added at the end (`ta_T3.c`).
pub fn ChainCore(comptime kind: ChainKind) type {
    const K: usize = switch (kind) {
        .dema => 2,
        .tema => 3,
        .t3 => 6,
    };
    const Params = if (kind == .t3) T3Params else DemaParams;
    return struct {
        const Self = @This();
        p: usize,
        beta: f64,
        k: f64,
        gap: usize,
        lb: usize,
        n: usize = 0,
        sum: [K]f64 = @splat(0.0),
        prev: [K]f64 = @splat(0.0),
        c1: f64 = 0.0,
        c2: f64 = 0.0,
        c3: f64 = 0.0,
        c4: f64 = 0.0,

        pub fn validate(p: Params) Error!void {
            try core.checkPeriod(p.period, 1);
            try p.unstable.check();
            if (kind == .t3 and !(p.vfactor >= 0.0 and p.vfactor <= 1.0)) return error.BadParam;
        }
        fn t3Unstable(p: Params) usize {
            const c4: usize = if (p.period > 1) (11 * (4 + 4) * p.period + 7) / 8 else 0;
            const c8: usize = if (p.period > 1) (11 * (8 + 4) * p.period + 7) / 8 else 0;
            return p.unstable.get(c4, c8);
        }
        pub fn lookback(p: Params) usize {
            if (kind == .t3) return 6 * (p.period - 1) + t3Unstable(p);
            return K * EmaCore.lookbackOf(p.period, p.unstable, .sma);
        }
        pub fn ringLen(_: Params) usize {
            return 0;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            var s: Self = .{ .p = p.period, .beta = 0, .k = 0, .gap = 0, .lb = lookback(p) };
            if (kind == .t3) {
                // k = 2/(p+1), 1-k as the other weight; no beta < 0.5 swap here.
                const one: f64 = 1.0;
                s.k = 2.0 / (pf(p.period) + one);
                s.beta = one - s.k;
                s.gap = p.period - 1;
                const v = p.vfactor;
                const t = v * v;
                s.c1 = -(t * v);
                s.c2 = 3.0 * (t - s.c1);
                s.c3 = -6.0 * t - 3.0 * (v - s.c1);
                s.c4 = @mulAdd(f64, 3.0, t, @mulAdd(f64, 3.0, v, 1.0) - s.c1);
            } else if (p.period > 1) {
                const bk = EmaCore.betaK(p.period);
                s.beta = bk[0];
                s.k = bk[1];
                s.gap = EmaCore.lookbackOf(p.period, p.unstable, .sma);
            }
            return s;
        }
        pub fn step(self: *Self, src: anytype, x: f64) ?f64 {
            _ = src;
            const n = self.n;
            self.n += 1;
            // No smoothing at period 1: an exact copy after the unstable bars.
            if (self.p == 1) return if (n >= self.lb) x else null;
            var v = x;
            inline for (0..K) |j| {
                const base = j * self.gap;
                if (n < base) return null;
                const m = n - base;
                if (m + 1 < self.p) {
                    self.sum[j] += v;
                    return null;
                }
                if (m + 1 == self.p) {
                    self.sum[j] += v;
                    self.prev[j] = self.sum[j] / pf(self.p);
                } else {
                    self.prev[j] = @mulAdd(f64, self.beta, self.prev[j], self.k * v);
                }
                v = self.prev[j];
            }
            if (n < self.lb) return null;
            return self.combine(self.prev);
        }
        inline fn combine(self: *const Self, e: [K]f64) f64 {
            return switch (kind) {
                .dema => 2.0 * e[0] - e[1],
                .tema => e[2] + (3.0 * e[0] - 3.0 * e[1]),
                .t3 => @mulAdd(f64, self.c4, e[2], @mulAdd(f64, self.c3, e[3], @mulAdd(f64, self.c1, e[5], self.c2 * e[4]))),
            };
        }
        /// True once every stage is past its seed and the output has started.
        pub fn steady(self: *const Self) bool {
            if (self.p == 1) return self.n >= self.lb;
            return self.n >= (K - 1) * self.gap + self.p and self.n >= self.lb;
        }
        /// The K recurrences as one tight loop (see `smooth.runCore`).
        pub fn steadyRun(self: *Self, comptime T: type, in: []const T, out: []T, i: usize) void {
            self.n += in.len - i;
            if (self.p == 1) {
                for (in[i..], out[i..]) |x, *o| o.* = core.to(T, @as(f64, x));
                return;
            }
            const beta = self.beta;
            const k = self.k;
            var e = self.prev;
            for (in[i..], out[i..]) |x, *o| {
                var v: f64 = x;
                inline for (0..K) |j| {
                    e[j] = @mulAdd(f64, beta, e[j], k * v);
                    v = e[j];
                }
                o.* = core.to(T, self.combine(e));
            }
            self.prev = e;
        }
    };
}

pub const DemaCore = ChainCore(.dema);
pub const TemaCore = ChainCore(.tema);
pub const T3Core = ChainCore(.t3);

pub fn demaLookback(p: DemaParams) Error!usize {
    try DemaCore.validate(p);
    return DemaCore.lookback(p);
}
pub fn dema(comptime T: type, in: []const T, out: []T, p: DemaParams) Error!usize {
    return smooth.batch1(T, DemaCore, in, out, p);
}
pub fn DemaStream(comptime T: type) type {
    return smooth.Rec1(T, DemaParams, DemaCore);
}
pub fn temaLookback(p: TemaParams) Error!usize {
    try TemaCore.validate(p);
    return TemaCore.lookback(p);
}
pub fn tema(comptime T: type, in: []const T, out: []T, p: TemaParams) Error!usize {
    return smooth.batch1(T, TemaCore, in, out, p);
}
pub fn TemaStream(comptime T: type) type {
    return smooth.Rec1(T, TemaParams, TemaCore);
}
pub fn t3Lookback(p: T3Params) Error!usize {
    try T3Core.validate(p);
    return T3Core.lookback(p);
}
pub fn t3(comptime T: type, in: []const T, out: []T, p: T3Params) Error!usize {
    return smooth.batch1(T, T3Core, in, out, p);
}
pub fn T3Stream(comptime T: type) type {
    return smooth.Rec1(T, T3Params, T3Core);
}

// ── TRIMA ───────────────────────────────────────────────────────────────────

pub const TrimaParams = struct { period: usize = 30 };

/// Triangular moving average: the weighted window is updated by four small
/// adjustments of a running numerator (`ta_TRIMA.c`), odd and even periods
/// differ in the middle weight.
pub const TrimaCore = struct {
    p: usize,
    h: usize,
    odd: bool,
    factor: f64,
    n: usize = 0,
    numerator: f64 = 0.0,
    sub: f64 = 0.0,
    add: f64 = 0.0,
    trail: f64 = 0.0,

    pub fn validate(p: TrimaParams) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: TrimaParams) usize {
        return p.period;
    }
    pub fn lookback(p: TrimaParams) usize {
        return p.period - 1;
    }
    pub fn init(p: TrimaParams) Error!TrimaCore {
        try validate(p);
        const h = p.period >> 1;
        const odd = p.period % 2 == 1;
        // Widened to double: (h+1)^2 overflows int32 near the maximum period.
        const f = if (odd) pf(h + 1) * pf(h + 1) else pf(h) * pf(h + 1);
        return .{ .p = p.period, .h = h, .odd = odd, .factor = 1.0 / f };
    }
    pub fn step(self: *TrimaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        const lb = self.p - 1;
        if (n < lb) return null;
        if (n == lb) {
            const mid0 = if (self.odd) self.h else self.h - 1;
            var i: usize = mid0 + 1;
            while (i > 0) {
                i -= 1;
                self.sub += src.at(i);
                self.numerator += self.sub;
            }
            var j = mid0 + 1;
            while (j <= lb) : (j += 1) {
                self.add += src.at(j);
                self.numerator += self.add;
            }
            self.trail = src.at(0);
            return self.numerator * self.factor;
        }
        // Step 1: drop the trailing bar and the middle weight.
        self.numerator -= self.sub;
        self.sub -= self.trail;
        var t = src.at(n - self.h);
        self.sub += t;
        // Step 2
        if (self.odd) {
            self.numerator += self.add;
            self.add -= t;
        } else {
            self.add -= t;
            self.numerator += self.add;
        }
        t = x;
        self.add += t;
        // Step 3
        self.numerator += t;
        // Step 4
        self.trail = src.at(n - lb);
        return self.numerator * self.factor;
    }
};

pub fn trimaLookback(p: TrimaParams) Error!usize {
    try TrimaCore.validate(p);
    return TrimaCore.lookback(p);
}
pub fn trima(comptime T: type, in: []const T, out: []T, p: TrimaParams) Error!usize {
    return smooth.batch1(T, TrimaCore, in, out, p);
}
pub fn TrimaStream(comptime T: type) type {
    return smooth.Stream1(T, TrimaParams, TrimaCore);
}

// ── KAMA ────────────────────────────────────────────────────────────────────

pub const KamaParams = struct {
    period: usize = 30,
    unstable: Unstable = core.no_unstable,
};

const kama_max: f64 = 2.0 / 31.0;
const kama_diff: f64 = blk: {
    const two_thirds: f64 = 2.0 / 3.0;
    break :blk two_thirds - kama_max;
};

/// Kaufman's adaptive moving average (`ta_KAMA.c`): efficiency ratio from a
/// running sum of absolute one-bar changes, exactly flat windows recognised by
/// a run counter (0.8.x), period 1 is a copy.
pub const KamaCore = struct {
    p: usize,
    u: usize,
    n: usize = 0,
    sum_roc: f64 = 0.0,
    null_run: usize = 0,
    prev: f64 = 0.0,
    trailing: f64 = 0.0,

    pub fn validate(p: KamaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn unstableOf(p: KamaParams) usize {
        if (p.period == 1) return p.unstable.get(0, 0);
        const root = isqrt(p.period);
        return p.unstable.get(25 * 4 * root, 25 * 8 * root);
    }
    pub fn ringLen(p: KamaParams) usize {
        return if (p.period == 1) 0 else p.period + 1;
    }
    pub fn lookback(p: KamaParams) usize {
        if (p.period == 1) return unstableOf(p);
        return p.period + unstableOf(p);
    }
    pub fn init(p: KamaParams) Error!KamaCore {
        try validate(p);
        return .{ .p = p.period, .u = unstableOf(p) };
    }
    fn ratio(sum_roc: f64, roc: f64) f64 {
        if (sum_roc <= 0.0 or sum_roc <= roc) return 1.0;
        const r = @abs(roc / sum_roc);
        return if (r > 1.0) 1.0 else r;
    }
    pub fn step(self: *KamaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        const p = self.p;
        if (p == 1) return if (n >= self.u) x else null;
        if (n < p) return null;
        if (n == p) {
            var j: usize = 0;
            while (j < p) : (j += 1) {
                const d = src.at(j) - src.at(j + 1);
                self.sum_roc += @abs(d);
                self.null_run = if (@abs(d) <= 0.0) self.null_run + 1 else 0;
            }
            const first = src.at(0);
            const roc = x - first;
            self.trailing = first;
            var sc = @mulAdd(f64, ratio(self.sum_roc, roc), kama_diff, kama_max);
            sc *= sc;
            const yesterday = src.at(p - 1);
            self.prev = @mulAdd(f64, x - yesterday, sc, yesterday);
        } else {
            const t2 = src.at(n - p);
            const roc = x - t2;
            const yesterday = src.at(n - 1);
            self.sum_roc -= @abs(self.trailing - t2);
            self.sum_roc += @abs(x - yesterday);
            self.null_run = if (@abs(x - yesterday) <= 0.0) self.null_run + 1 else 0;
            var er: f64 = undefined;
            if (self.null_run >= p) {
                self.null_run = p;
                self.sum_roc = 0.0;
                er = 1.0;
            } else {
                er = ratio(self.sum_roc, roc);
            }
            self.trailing = t2;
            var sc = @mulAdd(f64, er, kama_diff, kama_max);
            sc *= sc;
            self.prev = @mulAdd(f64, x - self.prev, sc, self.prev);
        }
        return if (n >= p + self.u) self.prev else null;
    }
    /// True once `step` is the sliding update with an output.
    pub fn steady(self: *const KamaCore) bool {
        if (self.p == 1) return self.n >= self.u;
        return self.n > self.p and self.n >= self.p + self.u;
    }
    /// The sliding update as a tight loop over the caller's slice (see `smooth.runCore`).
    pub fn steadyRun(self: *KamaCore, comptime T: type, in: []const T, out: []T, i: usize) void {
        self.n += in.len - i;
        const p = self.p;
        if (p == 1) {
            for (in[i..], out[i..]) |x, *o| o.* = core.to(T, @as(f64, x));
            return;
        }
        var sum_roc = self.sum_roc;
        var null_run = self.null_run;
        var prev = self.prev;
        var trailing = self.trailing;
        var j = i;
        while (j < in.len) : (j += 1) {
            const x: f64 = in[j];
            const t2: f64 = in[j - p];
            const roc = x - t2;
            const yesterday: f64 = in[j - 1];
            sum_roc -= @abs(trailing - t2);
            sum_roc += @abs(x - yesterday);
            null_run = if (@abs(x - yesterday) <= 0.0) null_run + 1 else 0;
            var er: f64 = undefined;
            if (null_run >= p) {
                null_run = p;
                sum_roc = 0.0;
                er = 1.0;
            } else {
                er = ratio(sum_roc, roc);
            }
            trailing = t2;
            var sc = @mulAdd(f64, er, kama_diff, kama_max);
            sc *= sc;
            prev = @mulAdd(f64, x - prev, sc, prev);
            out[j] = core.to(T, prev);
        }
        self.sum_roc = sum_roc;
        self.null_run = null_run;
        self.prev = prev;
        self.trailing = trailing;
    }
};

pub fn kamaLookback(p: KamaParams) Error!usize {
    try KamaCore.validate(p);
    return KamaCore.lookback(p);
}
pub fn kama(comptime T: type, in: []const T, out: []T, p: KamaParams) Error!usize {
    return smooth.batch1(T, KamaCore, in, out, p);
}
pub fn KamaStream(comptime T: type) type {
    return smooth.Stream1(T, KamaParams, KamaCore);
}

// ── ZLEMA ───────────────────────────────────────────────────────────────────

pub const ZlemaParams = struct {
    period: usize = 30,
    unstable: Unstable = core.no_unstable,
};

/// EMA of the de-lagged series `2 x[t] - x[t - lag]`, `lag = (period-1)/2`.
pub const ZlemaCore = struct {
    p: usize,
    lag: usize,
    lb: usize,
    beta: f64,
    k: f64,
    n: usize = 0,
    sum: f64 = 0.0,
    prev: f64 = 0.0,

    pub fn validate(p: ZlemaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn ringLen(p: ZlemaParams) usize {
        return (p.period - 1) / 2 + 1;
    }
    pub fn lookback(p: ZlemaParams) usize {
        return (p.period - 1) / 2 + EmaCore.lookbackOf(p.period, p.unstable, .sma);
    }
    pub fn init(p: ZlemaParams) Error!ZlemaCore {
        try validate(p);
        const bk = EmaCore.betaK(p.period);
        return .{ .p = p.period, .lag = (p.period - 1) / 2, .lb = lookback(p), .beta = bk[0], .k = bk[1] };
    }
    pub fn step(self: *ZlemaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (self.p == 1) return if (n >= self.lb) x else null;
        if (n < self.lag) return null;
        const d = 2.0 * x - src.at(n - self.lag);
        const m = n - self.lag;
        if (m + 1 < self.p) {
            self.sum += d;
            return null;
        }
        if (m + 1 == self.p) {
            self.sum += d;
            self.prev = self.sum / pf(self.p);
        } else {
            self.prev = @mulAdd(f64, self.beta, self.prev, self.k * d);
        }
        return if (n >= self.lb) self.prev else null;
    }
};

pub fn zlemaLookback(p: ZlemaParams) Error!usize {
    try ZlemaCore.validate(p);
    return ZlemaCore.lookback(p);
}
pub fn zlema(comptime T: type, in: []const T, out: []T, p: ZlemaParams) Error!usize {
    return smooth.batch1(T, ZlemaCore, in, out, p);
}
pub fn ZlemaStream(comptime T: type) type {
    return smooth.Stream1(T, ZlemaParams, ZlemaCore);
}

// ── RMA ─────────────────────────────────────────────────────────────────────

pub const RmaParams = struct {
    period: usize = 30,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Wilder's moving average: seed = mean of the first `period` bars, then
/// `fma(beta, prev, alpha * x)` with `beta = (p-1)/p`, `alpha = 1 - beta`.
pub const RmaCore = struct {
    p: usize,
    lb: usize,
    beta: f64,
    alpha: f64,
    n: usize = 0,
    sum: f64 = 0.0,
    prev: f64 = 0.0,

    pub fn validate(p: RmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn unstableOf(p: RmaParams) usize {
        const c4: usize = if (p.period > 1) (10 * (2 * p.period - 1) + 1) / 2 else 0;
        const c8: usize = if (p.period > 1) (19 * (2 * p.period - 1) + 1) / 2 else 0;
        return p.unstable.get(c4, c8);
    }
    pub fn ringLen(_: RmaParams) usize {
        return 0;
    }
    pub fn lookback(p: RmaParams) usize {
        return p.period - 1 + unstableOf(p);
    }
    pub fn init(p: RmaParams) Error!RmaCore {
        try validate(p);
        const beta = pf(p.period - 1) / pf(p.period);
        return .{ .p = p.period, .lb = lookback(p), .beta = beta, .alpha = 1.0 - beta };
    }
    pub fn step(self: *RmaCore, src: anytype, x: f64) ?f64 {
        _ = src;
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) {
            self.sum += x;
            return null;
        }
        if (n + 1 == self.p) {
            self.sum += x;
            self.prev = self.sum / pf(self.p);
        } else {
            self.prev = @mulAdd(f64, self.beta, self.prev, self.alpha * x);
        }
        return if (n >= self.lb) self.prev else null;
    }
};

pub fn rmaLookback(p: RmaParams) Error!usize {
    try RmaCore.validate(p);
    return RmaCore.lookback(p);
}
pub fn rma(comptime T: type, in: []const T, out: []T, p: RmaParams) Error!usize {
    return smooth.batch1(T, RmaCore, in, out, p);
}
pub fn RmaStream(comptime T: type) type {
    return smooth.Rec1(T, RmaParams, RmaCore);
}

// ── VIDYA ───────────────────────────────────────────────────────────────────

pub const VidyaParams = struct {
    period: usize = 12,
    cmo_period: usize = 9,
    unstable: Unstable = core.no_unstable,
};

/// Chande's variable index dynamic average: an EMA whose smoothing constant is
/// `alpha * |CMO|` over `cmo_period` changes (`ta_VIDYA.c`).
pub const VidyaCore = struct {
    p: usize,
    c: usize,
    lb: usize,
    alpha: f64,
    n: usize = 0,
    prev_value: f64 = 0.0,
    trailing: f64 = 0.0,
    prev: f64 = 0.0,
    up_sum: f64 = 0.0,
    down_sum: f64 = 0.0,
    null_run: usize = 0,

    pub fn validate(p: VidyaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try core.checkPeriod(p.cmo_period, 2);
        try p.unstable.check();
    }
    pub fn unstableOf(p: VidyaParams) usize {
        if (p.period == 1) return p.unstable.get(0, 0);
        const root = isqrt(p.cmo_period);
        const cap: usize = 100000000;
        const c4 = @min(2 * 4 * (p.period + 1) * root, cap);
        const c8 = @min(2 * 8 * (p.period + 1) * root, cap);
        return p.unstable.get(c4, c8);
    }
    pub fn ringLen(p: VidyaParams) usize {
        return if (p.period == 1) 0 else p.cmo_period;
    }
    pub fn lookback(p: VidyaParams) usize {
        if (p.period == 1) return unstableOf(p);
        return p.cmo_period + unstableOf(p);
    }
    pub fn init(p: VidyaParams) Error!VidyaCore {
        try validate(p);
        return .{ .p = p.period, .c = p.cmo_period, .lb = lookback(p), .alpha = 2.0 / pf(p.period + 1) };
    }
    pub fn step(self: *VidyaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (self.p == 1) return if (n >= self.lb) x else null;
        if (n == 0) {
            self.prev_value = x;
            self.trailing = x;
            self.prev = x;
            return null;
        }
        const diff = x - self.prev_value;
        self.prev_value = x;
        const up = (diff + @abs(diff)) * 0.5;
        self.up_sum += up;
        self.down_sum += up - diff;
        self.null_run = if (@abs(diff) <= 0.0) self.null_run + 1 else 0;
        var k: f64 = undefined;
        if (n > self.c and self.null_run >= self.c) {
            self.null_run = self.c;
            self.up_sum = 0.0;
            self.down_sum = 0.0;
            k = 0.0;
        } else {
            const s = self.up_sum + self.down_sum;
            k = if (s > 0.0) self.alpha * (@abs(100.0 * (self.up_sum - self.down_sum) / s) / 100.0) else 0.0;
        }
        self.prev = @mulAdd(f64, self.prev_value - self.prev, k, self.prev);
        if (n >= self.c) {
            // The change that leaves the window after this bar.
            const t = src.at(n - self.c + 1);
            const d2 = t - self.trailing;
            self.trailing = t;
            const up2 = (d2 + @abs(d2)) * 0.5;
            self.up_sum -= up2;
            self.down_sum -= up2 - d2;
        }
        return if (n >= self.lb) self.prev else null;
    }
};

pub fn vidyaLookback(p: VidyaParams) Error!usize {
    try VidyaCore.validate(p);
    return VidyaCore.lookback(p);
}
pub fn vidya(comptime T: type, in: []const T, out: []T, p: VidyaParams) Error!usize {
    return smooth.batch1(T, VidyaCore, in, out, p);
}
pub fn VidyaStream(comptime T: type) type {
    return smooth.Stream1(T, VidyaParams, VidyaCore);
}

// ── HMA ─────────────────────────────────────────────────────────────────────

pub const HmaParams = struct { period: usize = 20 };

/// `sqrt(100000)` rounded down: the longest ring of de-lagged values.
const hma_max_ring = 316;

fn ShiftSrc(comptime S: type) type {
    return struct {
        s: S,
        off: usize,
        pub fn at(self: @This(), i: usize) f64 {
            return self.s.at(i + self.off);
        }
    };
}

const DRingSrc = struct {
    buf: *const [hma_max_ring]f64,
    len: usize,
    pub fn at(self: DRingSrc, i: usize) f64 {
        return self.buf[i % self.len];
    }
};

/// Hull moving average: `WMA(2 WMA(x, p/2) - WMA(x, p), sqrt(p))` with the three
/// WMAs as TA_WMA runs them (re-anchors included), the de-lagged series kept in
/// a small ring inside the core.
pub const HmaCore = struct {
    p: usize,
    half: WmaCore,
    full: WmaCore,
    outer: WmaCore,
    s: usize,
    shift: usize,
    n: usize = 0,
    dring: [hma_max_ring]f64 = undefined,

    pub fn validate(p: HmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: HmaParams) usize {
        return p.period;
    }
    pub fn lookback(p: HmaParams) usize {
        if (p.period == 1) return 0;
        return (p.period - 1) + (isqrt(p.period) - 1);
    }
    pub fn init(p: HmaParams) Error!HmaCore {
        try validate(p);
        const per = p.period;
        const half = per / 2;
        const s = isqrt(per);
        return .{
            .p = per,
            .half = try WmaCore.init(.{ .period = @max(half, 1) }),
            .full = try WmaCore.init(.{ .period = per }),
            .outer = try WmaCore.init(.{ .period = s }),
            .s = s,
            .shift = per - @max(half, 1),
        };
    }
    pub fn step(self: *HmaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (self.p == 1) return x;
        const f = self.full.step(src, x);
        var h: ?f64 = null;
        if (n >= self.shift) h = self.half.step(ShiftSrc(@TypeOf(src)){ .s = src, .off = self.shift }, x);
        const fo = f orelse return null;
        const diff = 2.0 * h.? - fo;
        const m = n - (self.p - 1);
        self.dring[m % self.s] = diff;
        return self.outer.step(DRingSrc{ .buf = &self.dring, .len = self.s }, diff);
    }
};

pub fn hmaLookback(p: HmaParams) Error!usize {
    try HmaCore.validate(p);
    return HmaCore.lookback(p);
}
pub fn hma(comptime T: type, in: []const T, out: []T, p: HmaParams) Error!usize {
    return smooth.batch1(T, HmaCore, in, out, p);
}
pub fn HmaStream(comptime T: type) type {
    return smooth.Stream1(T, HmaParams, HmaCore);
}

// ── ALMA ────────────────────────────────────────────────────────────────────

pub const AlmaParams = struct {
    period: usize = 9,
    sigma: f64 = 6.0,
    offset: f64 = 0.85,
};

/// Arnaud Legoux moving average: a Gaussian-weighted window (weights
/// `exp(-(j-m)^2 / (2 s^2)) / norm`, `m = floor(offset (p-1))`, `s = p/sigma`).
/// `weights` is an optional precomputed table (`fillWeights`); without it every
/// weight is recomputed per bar (same bits, slower).
pub const AlmaCore = struct {
    p: usize,
    m: usize,
    two_ssq: f64,
    norm: f64,
    weights: []const f64 = &.{},
    n: usize = 0,

    pub fn validate(p: AlmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        if (!(p.sigma >= 1e-2 and p.sigma <= 3e37)) return error.BadParam;
        if (!(p.offset >= 0.0 and p.offset <= 1.0)) return error.BadParam;
    }
    pub fn ringLen(p: AlmaParams) usize {
        return p.period;
    }
    pub fn lookback(p: AlmaParams) usize {
        return p.period - 1;
    }
    fn raw(self: *const AlmaCore, j: usize) f64 {
        const d: f64 = @floatFromInt(@as(i64, @intCast(j)) - @as(i64, @intCast(self.m)));
        return @exp(-(d * d) / self.two_ssq);
    }
    pub fn init(p: AlmaParams) Error!AlmaCore {
        try validate(p);
        const lb = p.period - 1;
        const m: usize = @intFromFloat(@floor(p.offset * pf(lb)));
        const s = pf(p.period) / p.sigma;
        var c: AlmaCore = .{ .p = p.period, .m = m, .two_ssq = 2.0 * s * s, .norm = 0.0 };
        if (p.period > 1) {
            var norm: f64 = 0.0;
            for (0..p.period) |j| norm += c.raw(j);
            c.norm = norm;
        }
        return c;
    }
    /// Fill `w[0..p]` with the final weights.
    pub fn fillWeights(self: *const AlmaCore, w: []f64) void {
        for (w[0..self.p], 0..) |*o, j| o.* = self.raw(j) / self.norm;
    }
    pub fn step(self: *AlmaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        // A dot product seeded with 0.0 would turn a -0.0 input into +0.0.
        if (self.p == 1) return x;
        if (n + 1 < self.p) return null;
        const b = n + 1 - self.p;
        var sum: f64 = 0.0;
        if (self.weights.len == self.p) {
            for (self.weights, 0..) |w, j| sum += w * src.at(b + j);
        } else {
            for (0..self.p) |j| sum += (self.raw(j) / self.norm) * src.at(b + j);
        }
        return sum;
    }
};

pub fn almaLookback(p: AlmaParams) Error!usize {
    try AlmaCore.validate(p);
    return AlmaCore.lookback(p);
}
/// ALMA with the weight table built once; `gpa` is used for it when the period
/// exceeds 64 (smaller tables live on the stack).
pub fn alma(comptime T: type, gpa: std.mem.Allocator, in: []const T, out: []T, p: AlmaParams) core.AllocError!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{out.len});
    var c = try AlmaCore.init(p);
    var small: [64]f64 = undefined;
    var big: []f64 = &.{};
    defer gpa.free(big);
    var w: []f64 = &.{};
    if (p.period > 1) {
        if (p.period <= small.len) {
            w = small[0..p.period];
        } else {
            big = try gpa.alloc(f64, p.period);
            w = big;
        }
        c.fillWeights(w);
        c.weights = w;
    }
    const sl = core.SliceSrc(T){ .xs = in };
    for (in, out) |x, *o| {
        o.* = if (c.step(sl, x)) |r| core.to(T, r) else std.math.nan(T);
    }
    return AlmaCore.lookback(p);
}
pub fn AlmaStream(comptime T: type) type {
    return smooth.Stream1(T, AlmaParams, AlmaCore);
}

// ── MCGD ────────────────────────────────────────────────────────────────────

pub const McgdParams = struct {
    period: usize = 14,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// McGinley dynamic: `md += (x - md) / (period * (x/md)^4)`, an update that
/// would leave the finite numbers is dropped (`ta_MCGD.c`).
pub const McgdCore = struct {
    p: f64,
    lb: usize,
    n: usize = 0,
    prev: f64 = 0.0,

    pub fn validate(p: McgdParams) Error!void {
        try core.checkPeriod(p.period, 2);
        try p.unstable.check();
    }
    pub fn ringLen(_: McgdParams) usize {
        return 0;
    }
    pub fn lookback(p: McgdParams) usize {
        return p.period - 1 + p.unstable.get(5 * 4 * p.period, 5 * 8 * p.period);
    }
    pub fn init(p: McgdParams) Error!McgdCore {
        try validate(p);
        return .{ .p = pf(p.period), .lb = lookback(p) };
    }
    pub fn step(self: *McgdCore, src: anytype, x: f64) ?f64 {
        _ = src;
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.prev = x;
            return null;
        }
        const ratio = x / self.prev;
        const t = self.prev + (x - self.prev) / (self.p * (ratio * ratio * (ratio * ratio)));
        if (std.math.isFinite(t)) self.prev = t;
        return if (n >= self.lb) self.prev else null;
    }
};

pub fn mcgdLookback(p: McgdParams) Error!usize {
    try McgdCore.validate(p);
    return McgdCore.lookback(p);
}
pub fn mcgd(comptime T: type, in: []const T, out: []T, p: McgdParams) Error!usize {
    return smooth.batch1(T, McgdCore, in, out, p);
}
pub fn McgdStream(comptime T: type) type {
    return smooth.Rec1(T, McgdParams, McgdCore);
}

// ── SWAK_BUTTER / SWAK_GAUSS ────────────────────────────────────────────────

pub const SwakParams = struct {
    period: usize = 20,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};

/// Ehlers' two-pole filters (`ta_SWAK_BUTTER.c`, `ta_SWAK_GAUSS.c`); TA-Lib's
/// period range for both is 2..10000 and the lookback is the unstable count only.
pub fn SwakCore(comptime butter: bool) type {
    return struct {
        const Self = @This();
        lb: usize,
        a1: f64,
        a2: f64,
        c0: f64,
        n: usize = 0,
        x1: f64 = 0.0,
        x2: f64 = 0.0,
        y1: f64 = 0.0,
        y2: f64 = 0.0,

        pub fn validate(p: SwakParams) Error!void {
            if (p.period < 2 or p.period > 10000) return error.BadParam;
            try p.unstable.check();
        }
        pub fn ringLen(_: SwakParams) usize {
            return 0;
        }
        pub fn lookback(p: SwakParams) usize {
            return p.unstable.get(((10 + 3) * (p.period + 2) + 8) / 9, ((19 + 3) * (p.period + 2) + 8) / 9);
        }
        pub fn init(p: SwakParams) Error!Self {
            try validate(p);
            const pi: f64 = std.math.pi;
            const s = @sin(pi / pf(p.period));
            const b2p = 2.415 * (2.0 * s * s);
            const a2p = -b2p + @sqrt(@mulAdd(f64, b2p, b2p, 2.0 * b2p));
            const om = 1.0 - a2p;
            return .{
                .lb = lookback(p),
                .a1 = 2.0 * om,
                .a2 = -(om * om),
                .c0 = if (butter) a2p * a2p / 4.0 else a2p * a2p,
            };
        }
        pub fn step(self: *Self, src: anytype, x: f64) ?f64 {
            _ = src;
            const n = self.n;
            self.n += 1;
            if (n == 0) {
                self.x1 = x;
                self.x2 = x;
                self.y1 = x;
                self.y2 = x;
            }
            const y = if (butter)
                @mulAdd(f64, self.a1, self.y1, @mulAdd(f64, self.a2, self.y2, self.c0 * (@mulAdd(f64, 2.0, self.x1, x) + self.x2)))
            else
                @mulAdd(f64, self.a1, self.y1, @mulAdd(f64, self.a2, self.y2, self.c0 * x));
            self.x2 = self.x1;
            self.x1 = x;
            self.y2 = self.y1;
            self.y1 = y;
            return if (n >= self.lb) y else null;
        }
    };
}

pub const SwakButterCore = SwakCore(true);
pub const SwakGaussCore = SwakCore(false);

pub fn swakButterLookback(p: SwakParams) Error!usize {
    try SwakButterCore.validate(p);
    return SwakButterCore.lookback(p);
}
pub fn swakButter(comptime T: type, in: []const T, out: []T, p: SwakParams) Error!usize {
    return smooth.batch1(T, SwakButterCore, in, out, p);
}
pub fn SwakButterStream(comptime T: type) type {
    return smooth.Rec1(T, SwakParams, SwakButterCore);
}
pub fn swakGaussLookback(p: SwakParams) Error!usize {
    try SwakGaussCore.validate(p);
    return SwakGaussCore.lookback(p);
}
pub fn swakGauss(comptime T: type, in: []const T, out: []T, p: SwakParams) Error!usize {
    return smooth.batch1(T, SwakGaussCore, in, out, p);
}
pub fn SwakGaussStream(comptime T: type) type {
    return smooth.Rec1(T, SwakParams, SwakGaussCore);
}
