// SPDX-License-Identifier: MIT
//! Volume indicators ported from TA-Lib 0.8.3 (`ta_AD.c`, `ta_ADOSC.c`,
//! `ta_CMF.c`, `ta_EFI.c`, `ta_EMV.c`, `ta_KVO.c`, `ta_MARKETFI.c`,
//! `ta_NVI.c`, `ta_OBV.c`, `ta_PVI.c`, `ta_PVO.c`, `ta_PVT.c`, `ta_RVOL.c`,
//! `ta_VWAP.c`; BSD-3, see NOTICE). Inputs are parallel slices of one length.
//! Every function is a tuple core of `vs_kit.zig`: one `step` per bar, run by
//! the batch driver over the caller's slices and by the streaming type over a
//! ring, so both agree to the bit.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const K = @import("vs_kit.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const MaType = core.MaType;
const pf = core.pf;
const EmaCore = smooth.EmaCore;

fn emaLb(period: usize, un: Unstable) usize {
    return EmaCore.lookbackOf(period, un, .sma);
}

/// Accumulation / distribution step shared by AD, ADOSC (and the money flow
/// volume of CMF): `(close-low - (high-close)) / (high-low) * volume`.
fn mfv(h: f64, l: f64, c: f64, v: f64) f64 {
    const tmp = h - l;
    if (tmp > 0.0) return (c - l - (h - c)) / tmp * v;
    return 0.0;
}

// ── AD ──────────────────────────────────────────────────────────────────────

pub const AdCore = struct {
    pub const In = K.Hlcv(f64);
    pub const Out = f64;
    pub const Params = struct {};
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Hlcv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    ad: f64 = 0.0,
    pub fn validate(_: Params) Error!void {}
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(_: Params) usize {
        return 0;
    }
    pub fn init(_: Params) Error!AdCore {
        return .{};
    }
    pub fn step(self: *AdCore, _: anytype, b: In) ?f64 {
        self.n += 1;
        const tmp = b.high - b.low;
        if (tmp > 0.0) self.ad += (b.close - b.low - (b.high - b.close)) / tmp * b.volume;
        return self.ad;
    }
};

pub fn adLookback() usize {
    return 0;
}
pub fn ad(comptime T: type, high: []const T, low: []const T, close: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, AdCore, .{}, .{ .high = high, .low = low, .close = close, .volume = volume }, .{out});
}
pub fn AdStream(comptime T: type) type {
    return K.Stream(T, AdCore);
}

// ── ADOSC ───────────────────────────────────────────────────────────────────

pub const AdoscParams = struct {
    fast: usize = 3,
    slow: usize = 10,
    unstable: Unstable = core.no_unstable,
};

/// `adosc_auto_offset` of the C source: what an Auto level adds on top of the
/// slowest EMA's lookback (two EMAs seeded on one value can cancel early on).
fn adoscAuto(fast: usize, slow: usize) usize {
    const m = @min(fast, slow);
    const big = @max(fast, slow);
    var sum: usize = 0;
    var k: u6 = 1;
    while (k <= 16) : (k += 1) sum += @min(big >> k, m);
    return (15 * m + 3 * sum + 7) / 8;
}

pub const AdoscCore = struct {
    pub const In = K.Hlcv(f64);
    pub const Out = f64;
    pub const Params = AdoscParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Hlcv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    lb: usize,
    bf: f64,
    kf: f64,
    bs: f64,
    ks: f64,
    ad: f64 = 0.0,
    fe: f64 = 0.0,
    se: f64 = 0.0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try p.unstable.check();
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(p: Params) usize {
        const auto: usize = switch (p.unstable) {
            .bars => 0,
            else => adoscAuto(p.fast, p.slow),
        };
        return emaLb(@max(p.fast, p.slow), p.unstable) + auto;
    }
    pub fn init(p: Params) Error!AdoscCore {
        try validate(p);
        const f = EmaCore.betaK(p.fast);
        const s = EmaCore.betaK(p.slow);
        return .{ .lb = lookback(p), .bf = f[0], .kf = f[1], .bs = s[0], .ks = s[1] };
    }
    pub fn step(self: *AdoscCore, _: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const tmp = b.high - b.low;
        if (tmp > 0.0) self.ad += (b.close - b.low - (b.high - b.close)) / tmp * b.volume;
        if (n == 0) {
            self.fe = self.ad;
            self.se = self.ad;
        } else {
            self.fe = @mulAdd(f64, self.bf, self.fe, self.kf * self.ad);
            self.se = @mulAdd(f64, self.bs, self.se, self.ks * self.ad);
        }
        if (n < self.lb) return null;
        return self.fe - self.se;
    }
};

pub fn adoscLookback(p: AdoscParams) Error!usize {
    try AdoscCore.validate(p);
    return AdoscCore.lookback(p);
}
pub fn adosc(comptime T: type, high: []const T, low: []const T, close: []const T, volume: []const T, out: []T, p: AdoscParams) Error!usize {
    return K.batch(T, AdoscCore, p, .{ .high = high, .low = low, .close = close, .volume = volume }, .{out});
}
pub fn AdoscStream(comptime T: type) type {
    return K.Stream(T, AdoscCore);
}

// ── CMF ─────────────────────────────────────────────────────────────────────

pub const CmfParams = struct { period: usize = 20 };

pub const CmfCore = struct {
    pub const In = K.Hlcv(f64);
    pub const Out = f64;
    pub const Params = CmfParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Hlcv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    sum_mfv: f64 = 0.0,
    sum_vol: f64 = 0.0,
    null_run: usize = 0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 1;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params) Error!CmfCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *CmfCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n >= self.p) {
            const o = src.at(n - self.p);
            self.sum_mfv -= mfv(o.high, o.low, o.close, o.volume);
            self.sum_vol -= o.volume;
        }
        self.sum_mfv += mfv(b.high, b.low, b.close, b.volume);
        self.sum_vol += b.volume;
        // consecutive bars with |volume| <= 0 (a NaN volume is "live")
        self.null_run = if (@abs(b.volume) <= 0.0) self.null_run + 1 else 0;
        if (n + 1 < self.p) return null;
        if (n + 1 > self.p and self.null_run >= self.p) {
            self.sum_mfv = 0.0;
            self.sum_vol = 0.0;
            return 0.0;
        }
        if (self.sum_vol > 0.0) return self.sum_mfv / self.sum_vol;
        return 0.0;
    }
};

pub fn cmfLookback(p: CmfParams) Error!usize {
    try CmfCore.validate(p);
    return CmfCore.lookback(p);
}
pub fn cmf(comptime T: type, high: []const T, low: []const T, close: []const T, volume: []const T, out: []T, p: CmfParams) Error!usize {
    return K.batch(T, CmfCore, p, .{ .high = high, .low = low, .close = close, .volume = volume }, .{out});
}
pub fn CmfStream(comptime T: type) type {
    return K.Stream(T, CmfCore);
}

// ── EFI ─────────────────────────────────────────────────────────────────────

pub const EfiParams = struct {
    period: usize = 13,
    unstable: Unstable = core.no_unstable,
};

/// Elder's force index: EMA of `(close - previous close) * volume`, the EMA of
/// `ta_EMA.c` (SMA seed from the first `period` forces).
pub const EfiCore = struct {
    pub const In = K.Cv(f64);
    pub const Out = f64;
    pub const Params = EfiParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Cv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    prev_close: f64 = 0.0,
    ema: EmaCore,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(p: Params) usize {
        return 1 + emaLb(p.period, p.unstable);
    }
    pub fn init(p: Params) Error!EfiCore {
        try validate(p);
        return .{ .ema = try EmaCore.init(.{ .period = p.period, .unstable = p.unstable }) };
    }
    pub fn step(self: *EfiCore, _: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.prev_close = b.close;
            return null;
        }
        const force = (b.close - self.prev_close) * b.volume;
        self.prev_close = b.close;
        return self.ema.step({}, force);
    }
};

pub fn efiLookback(p: EfiParams) Error!usize {
    try EfiCore.validate(p);
    return EfiCore.lookback(p);
}
pub fn efi(comptime T: type, close: []const T, volume: []const T, out: []T, p: EfiParams) Error!usize {
    return K.batch(T, EfiCore, p, .{ .close = close, .volume = volume }, .{out});
}
pub fn EfiStream(comptime T: type) type {
    return K.Stream(T, EfiCore);
}

// ── EMV ─────────────────────────────────────────────────────────────────────

pub const EmvParams = struct {
    period: usize = 14,
    /// Volume divisor, 1 .. 3e37 (TA-Lib's range).
    divisor: f64 = 10000.0,
};

fn emvMid(h: f64, l: f64) f64 {
    return (h + l) / 2.0;
}
fn emvRaw(b: K.Hlv(f64), prev_mid: f64, div: f64) f64 {
    const range = b.high - b.low;
    var raw: f64 = 0.0;
    if (range != 0.0) {
        const box = b.volume / div / range;
        if (box != 0.0) raw = (emvMid(b.high, b.low) - prev_mid) / box;
    }
    return raw;
}

/// Ease of movement: the SMA (`ta_SMA.c`'s add / read / subtract order) of the
/// one-bar `(mid - previous mid) / (volume/divisor / range)`.
pub const EmvCore = struct {
    pub const In = K.Hlv(f64);
    pub const Out = f64;
    pub const Params = EmvParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.Hlv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    div: f64,
    prev_mid: f64 = 0.0,
    total: f64 = 0.0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
        if (!(p.divisor >= 1.0 and p.divisor <= 3e37)) return error.BadParam;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 1;
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!EmvCore {
        try validate(p);
        return .{ .p = p.period, .div = p.divisor };
    }
    pub fn step(self: *EmvCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.prev_mid = emvMid(b.high, b.low);
            return null;
        }
        const raw = emvRaw(b, self.prev_mid, self.div);
        self.prev_mid = emvMid(b.high, b.low);
        self.total += raw;
        if (n < self.p) return null;
        const t = self.total;
        const o = src.at(n - self.p + 1);
        const o1 = src.at(n - self.p);
        self.total -= emvRaw(o, emvMid(o1.high, o1.low), self.div);
        return t / pf(self.p);
    }
};

pub fn emvLookback(p: EmvParams) Error!usize {
    try EmvCore.validate(p);
    return EmvCore.lookback(p);
}
pub fn emv(comptime T: type, high: []const T, low: []const T, volume: []const T, out: []T, p: EmvParams) Error!usize {
    return K.batch(T, EmvCore, p, .{ .high = high, .low = low, .volume = volume }, .{out});
}
pub fn EmvStream(comptime T: type) type {
    return K.Stream(T, EmvCore);
}

// ── KVO ─────────────────────────────────────────────────────────────────────

pub const KvoParams = struct {
    fast: usize = 34,
    slow: usize = 55,
    signal: usize = 13,
    unstable: Unstable = core.no_unstable,
};

pub fn KvoOut(comptime T: type) type {
    return struct { kvo: T, signal: T };
}

/// Klinger volume oscillator (the 1997 factor `|2*(dm/cm) - 1|`); all three
/// EMAs seed raw on the first volume force.
pub const KvoCore = struct {
    pub const In = K.Hlcv(f64);
    pub const Out = KvoOut(f64);
    pub const Params = KvoParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Hlcv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return KvoOut(T);
    }
    n: usize = 0,
    lb: usize,
    bf: f64,
    kf: f64,
    bs: f64,
    ks: f64,
    bg: f64,
    kg: f64,
    prev_hlc: f64 = 0.0,
    prev_dm: f64 = 0.0,
    prev_trend: f64 = 1.0,
    cm: f64 = 0.0,
    ef: f64 = 0.0,
    es: f64 = 0.0,
    sig: f64 = 0.0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try core.checkPeriod(p.signal, 2);
        try p.unstable.check();
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(p: Params) usize {
        const longest = @max(p.fast, @max(p.slow, p.signal));
        const extra: usize = switch (p.unstable) {
            .bars => 0,
            .auto4 => (21 * longest + 1) / 2 - (10 * longest + 1) / 2,
            .auto8 => (33 * longest + 1) / 2 - (19 * longest + 1) / 2,
        };
        return 1 + emaLb(longest, p.unstable) + extra;
    }
    pub fn init(p: Params) Error!KvoCore {
        try validate(p);
        const f = EmaCore.betaK(p.fast);
        const s = EmaCore.betaK(p.slow);
        const g = EmaCore.betaK(p.signal);
        return .{ .lb = lookback(p), .bf = f[0], .kf = f[1], .bs = s[0], .ks = s[1], .bg = g[0], .kg = g[1] };
    }
    pub fn step(self: *KvoCore, _: anytype, b: In) ?Out {
        const n = self.n;
        self.n += 1;
        const hlc = b.high + b.low + b.close;
        const dm = b.high - b.low;
        if (n == 0) {
            self.prev_hlc = hlc;
            self.prev_dm = dm;
            self.prev_trend = 1.0;
            return null;
        }
        var trend: f64 = undefined;
        if (hlc > self.prev_hlc) {
            trend = 1.0;
        } else if (hlc < self.prev_hlc) {
            trend = -1.0;
        } else {
            trend = self.prev_trend;
        }
        if (n == 1 or trend != self.prev_trend) {
            self.cm = self.prev_dm + dm;
        } else {
            self.cm = self.cm + dm;
        }
        const vf: f64 = if (self.cm == 0.0) 0.0 else b.volume * @abs(2.0 * (dm / self.cm) - 1.0) * 100.0 * trend;
        var kv: f64 = undefined;
        if (n == 1) {
            self.ef = vf;
            self.es = vf;
            kv = self.ef - self.es;
            self.sig = kv;
        } else {
            self.ef = @mulAdd(f64, self.bf, self.ef, self.kf * vf);
            self.es = @mulAdd(f64, self.bs, self.es, self.ks * vf);
            kv = self.ef - self.es;
            self.sig = @mulAdd(f64, self.bg, self.sig, self.kg * kv);
        }
        self.prev_hlc = hlc;
        self.prev_dm = dm;
        self.prev_trend = trend;
        if (n < self.lb) return null;
        return .{ .kvo = kv, .signal = self.sig };
    }
};

pub fn kvoLookback(p: KvoParams) Error!usize {
    try KvoCore.validate(p);
    return KvoCore.lookback(p);
}
pub fn kvo(comptime T: type, high: []const T, low: []const T, close: []const T, volume: []const T, out_kvo: []T, out_signal: []T, p: KvoParams) Error!usize {
    return K.batch(T, KvoCore, p, .{ .high = high, .low = low, .close = close, .volume = volume }, .{ out_kvo, out_signal });
}
pub fn KvoStream(comptime T: type) type {
    return K.Stream(T, KvoCore);
}

// ── stateless and cumulative ────────────────────────────────────────────────

fn marketfiFn(b: K.Hlv(f64)) f64 {
    if (b.volume != 0.0) return (b.high - b.low) / b.volume;
    return 0.0;
}
/// Bill Williams' market facilitation index `(high - low) / volume`; a bar
/// without volume answers 0.
pub const MarketfiCore = K.PureCore(K.Hlv, marketfiFn);
pub fn marketfiLookback() usize {
    return 0;
}
pub fn marketfi(comptime T: type, high: []const T, low: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, MarketfiCore, .{}, .{ .high = high, .low = low, .volume = volume }, .{out});
}
pub fn MarketfiStream(comptime T: type) type {
    return K.Stream(T, MarketfiCore);
}

/// Negative (`positive = false`) or positive volume index: a running product
/// seeded at 1000, moved by the close-to-close change on bars whose volume
/// fell (rose) against the previous bar. A zero previous close, or an update
/// that would leave the finite range, carries the index forward.
pub fn VolIndexCore(comptime positive: bool) type {
    return struct {
        const Self = @This();
        pub const In = K.Cv(f64);
        pub const Out = f64;
        pub const Params = struct {};
        pub const windowed = false;
        pub fn Inputs(comptime T: type) type {
            return K.Cv(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        n: usize = 0,
        idx: f64 = 1000.0,
        prev_close: f64 = 0.0,
        prev_vol: f64 = 0.0,
        pub fn validate(_: Params) Error!void {}
        pub fn ringLen(_: Params) usize {
            return 0;
        }
        pub fn lookback(_: Params) usize {
            return 0;
        }
        pub fn init(_: Params) Error!Self {
            return .{};
        }
        pub fn step(self: *Self, _: anytype, b: In) ?f64 {
            if (self.n == 0) {
                self.prev_close = b.close;
                self.prev_vol = b.volume;
            }
            self.n += 1;
            const moved = if (positive) b.volume > self.prev_vol else b.volume < self.prev_vol;
            if (moved and self.prev_close != 0.0) {
                var t = self.idx;
                t += (b.close - self.prev_close) / self.prev_close * t;
                if (std.math.isFinite(t)) self.idx = t;
            }
            self.prev_close = b.close;
            self.prev_vol = b.volume;
            return self.idx;
        }
    };
}
pub const NviCore = VolIndexCore(false);
pub const PviCore = VolIndexCore(true);
pub fn nviLookback() usize {
    return 0;
}
pub fn nvi(comptime T: type, close: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, NviCore, .{}, .{ .close = close, .volume = volume }, .{out});
}
pub fn NviStream(comptime T: type) type {
    return K.Stream(T, NviCore);
}
pub fn pviLookback() usize {
    return 0;
}
pub fn pvi(comptime T: type, close: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, PviCore, .{}, .{ .close = close, .volume = volume }, .{out});
}
pub fn PviStream(comptime T: type) type {
    return K.Stream(T, PviCore);
}

/// On-balance volume: the running sum of volume signed by the close change,
/// seeded with the first bar's volume.
pub const ObvCore = struct {
    pub const In = K.Cv(f64);
    pub const Out = f64;
    pub const Params = struct {};
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Cv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    obv: f64 = 0.0,
    prev: f64 = 0.0,
    pub fn validate(_: Params) Error!void {}
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(_: Params) usize {
        return 0;
    }
    pub fn init(_: Params) Error!ObvCore {
        return .{};
    }
    pub fn step(self: *ObvCore, _: anytype, b: In) ?f64 {
        if (self.n == 0) {
            self.obv = b.volume;
            self.prev = b.close;
        }
        self.n += 1;
        if (b.close > self.prev) {
            self.obv += b.volume;
        } else if (b.close < self.prev) {
            self.obv -= b.volume;
        }
        self.prev = b.close;
        return self.obv;
    }
};
pub fn obvLookback() usize {
    return 0;
}
pub fn obv(comptime T: type, close: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, ObvCore, .{}, .{ .close = close, .volume = volume }, .{out});
}
pub fn ObvStream(comptime T: type) type {
    return K.Stream(T, ObvCore);
}

/// Price volume trend: the running sum of `(close - previous close) / previous
/// close * volume`; a zero previous close contributes nothing.
pub const PvtCore = struct {
    pub const In = K.Cv(f64);
    pub const Out = f64;
    pub const Params = struct {};
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Cv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    pvt: f64 = 0.0,
    prev: f64 = 0.0,
    pub fn validate(_: Params) Error!void {}
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(_: Params) usize {
        return 0;
    }
    pub fn init(_: Params) Error!PvtCore {
        return .{};
    }
    pub fn step(self: *PvtCore, _: anytype, b: In) ?f64 {
        if (self.n == 0) self.prev = b.close;
        self.n += 1;
        if (self.prev != 0.0) self.pvt += (b.close - self.prev) / self.prev * b.volume;
        self.prev = b.close;
        return self.pvt;
    }
};
pub fn pvtLookback() usize {
    return 0;
}
pub fn pvt(comptime T: type, close: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, PvtCore, .{}, .{ .close = close, .volume = volume }, .{out});
}
pub fn PvtStream(comptime T: type) type {
    return K.Stream(T, PvtCore);
}

/// Volume weighted average price, cumulative from the first bar (the anchor is
/// the caller's choice of slice). A bar with a non-finite price or volume is
/// skipped; before any volume has traded the answer is 0.
pub const VwapCore = struct {
    pub const In = K.Hlcv(f64);
    pub const Out = f64;
    pub const Params = struct {};
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.Hlcv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    sum_pv: f64 = 0.0,
    sum_v: f64 = 0.0,
    vwap: f64 = 0.0,
    pub fn validate(_: Params) Error!void {}
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(_: Params) usize {
        return 0;
    }
    pub fn init(_: Params) Error!VwapCore {
        return .{};
    }
    pub fn step(self: *VwapCore, _: anytype, b: In) ?f64 {
        self.n += 1;
        const typ = (b.high + b.low + b.close) / 3.0;
        const prod = typ * b.volume;
        if (std.math.isFinite(typ) and std.math.isFinite(b.volume)) {
            self.sum_pv += prod;
            self.sum_v += b.volume;
        }
        if (self.sum_v > 0.0) self.vwap = self.sum_pv / self.sum_v;
        return self.vwap;
    }
};
pub fn vwapLookback() usize {
    return 0;
}
pub fn vwap(comptime T: type, high: []const T, low: []const T, close: []const T, volume: []const T, out: []T) Error!usize {
    return K.batch(T, VwapCore, .{}, .{ .high = high, .low = low, .close = close, .volume = volume }, .{out});
}
pub fn VwapStream(comptime T: type) type {
    return K.Stream(T, VwapCore);
}

// ── RVOL ────────────────────────────────────────────────────────────────────

pub const RvolParams = struct { period: usize = 20 };

/// Relative volume: today's volume over the mean of the previous `period`
/// bars (today excluded). A window of `period` zero volumes resets the sum
/// to exactly 0.
pub const RvolCore = struct {
    pub const In = K.V(f64);
    pub const Out = f64;
    pub const Params = RvolParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.V(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    p: usize,
    total: f64 = 0.0,
    null_run: usize = 0,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 1;
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!RvolCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *RvolCore, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const today = b.volume;
        if (n < self.p) {
            self.total += today;
            self.null_run = if (@abs(today) <= 0.0) self.null_run + 1 else 0;
            return null;
        }
        const baseline = self.total / pf(self.p);
        const trailing = src.at(n - self.p).volume;
        const out = today / baseline;
        self.total -= trailing;
        self.total += today;
        self.null_run = if (@abs(today) <= 0.0) self.null_run + 1 else 0;
        if (self.null_run >= self.p) self.total = 0.0;
        return out;
    }
};
pub fn rvolLookback(p: RvolParams) Error!usize {
    try RvolCore.validate(p);
    return RvolCore.lookback(p);
}
pub fn rvol(comptime T: type, volume: []const T, out: []T, p: RvolParams) Error!usize {
    return K.batch(T, RvolCore, p, .{ .volume = volume }, .{out});
}
pub fn RvolStream(comptime T: type) type {
    return K.Stream(T, RvolCore);
}

// ── PVO ─────────────────────────────────────────────────────────────────────

pub const PvoParams = struct {
    fast: usize = 12,
    slow: usize = 26,
    ma: MaType = .ema,
    unstable: Unstable = core.no_unstable,
};

/// Percentage volume oscillator `(fast MA - slow MA) / slow MA * 100` of the
/// volume; fast and slow are swapped when slow < fast; a slow average within
/// 1e-14 of zero answers 0, and so does a window that is all zero volume for the
/// windowed MA types.
pub const PvoCore = struct {
    pub const In = K.V(f64);
    pub const Out = f64;
    pub const Params = PvoParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.V(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    cf: smooth.MaCore,
    cs: smooth.MaCore,
    slow_lb: usize,
    windowed_kind: bool,
    run: usize = 0,

    fn maParams(p: Params, period: usize) smooth.MaParams {
        return .{ .period = period, .kind = p.ma, .unstable = p.unstable };
    }
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try smooth.MaCore.validate(maParams(p, p.fast));
        try smooth.MaCore.validate(maParams(p, p.slow));
    }
    pub fn ringLen(p: Params) usize {
        return @max(smooth.MaCore.ringLen(maParams(p, p.fast)), smooth.MaCore.ringLen(maParams(p, p.slow)));
    }
    pub fn lookback(p: Params) usize {
        return smooth.MaCore.lookback(maParams(p, @max(p.fast, p.slow)));
    }
    pub fn init(p: Params) Error!PvoCore {
        try validate(p);
        const fp = @min(p.fast, p.slow);
        const sp = @max(p.fast, p.slow);
        return .{
            .cf = try smooth.MaCore.init(maParams(p, fp)),
            .cs = try smooth.MaCore.init(maParams(p, sp)),
            .slow_lb = smooth.MaCore.lookback(maParams(p, sp)),
            .windowed_kind = switch (p.ma) {
                .sma, .wma, .trima, .hma => true,
                else => false,
            },
        };
    }
    pub fn step(self: *PvoCore, src: anytype, b: In) ?f64 {
        self.n += 1;
        const vs = K.field(src, "volume");
        const fv = self.cf.step(vs, b.volume);
        const sv = self.cs.step(vs, b.volume);
        self.run = if (@abs(b.volume) <= 0.0) self.run + 1 else 0;
        if (fv == null or sv == null) return null;
        if (self.windowed_kind and self.run > self.slow_lb) return 0.0;
        const s = sv.?;
        const eps: f64 = 0.00000000000001;
        if (!(-eps < s and s < eps)) return (fv.? - s) / s * 100.0;
        return 0.0;
    }
};
pub fn pvoLookback(p: PvoParams) Error!usize {
    try PvoCore.validate(p);
    return PvoCore.lookback(p);
}
pub fn pvo(comptime T: type, volume: []const T, out: []T, p: PvoParams) Error!usize {
    return K.batch(T, PvoCore, p, .{ .volume = volume }, .{out});
}
pub fn PvoStream(comptime T: type) type {
    return K.Stream(T, PvoCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "ad, obv, vwap, pvt, marketfi, nvi, rvol: hand-checked vectors" {
    var out: [4]f64 = undefined;
    // AD: bar 0 (10,8,9, v100): (9-8-(10-9))/2*100 = 0; bar 1 (11,9,11, v50): (11-9-0)/2*50 = 50; bar 2 flat range: unchanged.
    _ = try ad(f64, &.{ 10, 11, 12 }, &.{ 8, 9, 12 }, &.{ 9, 11, 12 }, &.{ 100, 50, 10 }, out[0..3]);
    try testing.expectEqualSlices(f64, &.{ 0, 50, 50 }, out[0..3]);
    // OBV: 5; up +7; down -3; flat.
    _ = try obv(f64, &.{ 10, 11, 10.5, 10.5 }, &.{ 5, 7, 3, 4 }, &out);
    try testing.expectEqualSlices(f64, &.{ 5, 12, 9, 9 }, &out);
    // VWAP: typical price 10 (v1), then 20 (v3): (10 + 60) / 4 = 17.5; a NaN bar is skipped.
    _ = try vwap(f64, &.{ 10, 20, 99 }, &.{ 10, 20, 99 }, &.{ 10, 20, std.math.nan(f64) }, &.{ 1, 3, 5 }, out[0..3]);
    try testing.expectEqualSlices(f64, &.{ 10, 17.5, 17.5 }, out[0..3]);
    // PVT: bar 1 (110-100)/100*10 = 1, bar 2 (99-110)/110*10 = -1.
    _ = try pvt(f64, &.{ 100, 110, 99 }, &.{ 10, 10, 10 }, out[0..3]);
    try testing.expectApproxEqAbs(@as(f64, 1), out[1], 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0), out[2], 1e-12);
    // MARKETFI: (10-8)/4 = 0.5; zero volume answers 0.
    _ = try marketfi(f64, &.{ 10, 10 }, &.{ 8, 8 }, &.{ 4, 0 }, out[0..2]);
    try testing.expectEqualSlices(f64, &.{ 0.5, 0 }, out[0..2]);
    // NVI: 1000; volume fell: 1000 + (11-10)/10*1000 = 1100; rose: 1100; fell: 1100 + 1/12*1100.
    _ = try nvi(f64, &.{ 10, 11, 12, 13 }, &.{ 100, 90, 95, 80 }, &out);
    try testing.expectEqual(@as(f64, 1000), out[0]);
    try testing.expectEqual(@as(f64, 1100), out[1]);
    try testing.expectEqual(@as(f64, 1100), out[2]);
    try testing.expectApproxEqAbs(@as(f64, 1100 + 1100.0 / 12.0), out[3], 1e-9);
    // PVI moves on the rising bar only.
    _ = try pvi(f64, &.{ 10, 11, 12, 13 }, &.{ 100, 90, 95, 80 }, &out);
    try testing.expectEqual(@as(f64, 1000), out[1]);
    try testing.expectApproxEqAbs(@as(f64, 1000 + 1000.0 / 11.0), out[2], 1e-9);
    // RVOL period 2 over 2 4 6: baseline (2+4)/2 = 3, 6/3 = 2.
    try testing.expectEqual(@as(usize, 2), try rvol(f64, &.{ 2, 4, 6 }, out[0..3], .{ .period = 2 }));
    try testing.expectEqual(@as(f64, 2), out[2]);
}

test "volume: BadParam edges and lookbacks" {
    var out: [8]f64 = undefined;
    const z = [_]f64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try testing.expectError(error.BadParam, adosc(f64, &z, &z, &z, &z, &out, .{ .fast = 1 }));
    try testing.expectError(error.BadParam, adosc(f64, &z, &z, &z, &z, &out, .{ .slow = 100001 }));
    try testing.expectError(error.BadParam, cmf(f64, &z, &z, &z, &z, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, efi(f64, &z, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, emv(f64, &z, &z, &z, &out, .{ .divisor = 0.5 }));
    try testing.expectError(error.BadParam, emv(f64, &z, &z, &z, &out, .{ .divisor = 4e37 }));
    try testing.expectError(error.BadParam, kvo(f64, &z, &z, &z, &z, &out, &out, .{ .signal = 1 }));
    try testing.expectError(error.BadParam, rvol(f64, &z, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, pvo(f64, &z, &out, .{ .fast = 1 }));
    try testing.expectError(error.Unsupported, pvo(f64, &z, &out, .{ .ma = .mama }));
    try testing.expectError(error.BadParam, ad(f64, &z, &z, &z, z[0..7], &out));
    try testing.expectError(error.BadParam, obv(f64, &z, &z, out[0..7]));
    try testing.expectEqual(@as(usize, 9), try adoscLookback(.{}));
    try testing.expectEqual(@as(usize, 14), try emvLookback(.{}));
    try testing.expectEqual(@as(usize, 20), try rvolLookback(.{}));
    try testing.expectEqual(@as(usize, 1 + 54), try kvoLookback(.{}));
    try testing.expectEqual(@as(usize, 1 + 13 - 1 + 0), try efiLookback(.{}));
    try testing.expectEqual(@as(usize, 25), try pvoLookback(.{}));
    try testing.expectEqual(@as(usize, 6), try efiLookback(.{ .period = 1, .unstable = .{ .bars = 5 } }));
}

test "volume: unstable and AUTO lookbacks follow the C source" {
    // ADOSC(3,10) auto: m=3, M=10: terms min(10>>k, 3) for k=1..16 = 3,2,1,0... = 3+2+1+0*13 = 6 -> (45 + 18 + 7)/8 = 8
    try testing.expectEqual(@as(usize, 8), adoscAuto(3, 10));
    try testing.expectEqual(@as(usize, 9 + 50 + 8), try adoscLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 9 + 3), try adoscLookback(.{ .unstable = .{ .bars = 3 } }));
    // KVO(34,55,13), L=55: 1 + (54 + (10*55+1)/2) + ((21*55+1)/2 - (10*55+1)/2)
    try testing.expectEqual(@as(usize, 1 + 54 + 275 + (578 - 275)), try kvoLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 1 + 54 + 3), try kvoLookback(.{ .unstable = .{ .bars = 3 } }));
}

test "volume: batch == streaming, lookback == leading NaN" {
    var o: [300]f64 = undefined;
    var h: [300]f64 = undefined;
    var l: [300]f64 = undefined;
    var c: [300]f64 = undefined;
    var v: [300]f64 = undefined;
    K.fillBars(&o, &h, &l, &c, &v, 5);
    const hlcv = .{ .high = &h, .low = &l, .close = &c, .volume = &v };
    try K.checkCore(AdCore, .{}, hlcv);
    try K.checkCore(AdoscCore, .{}, hlcv);
    try K.checkCore(AdoscCore, .{ .fast = 10, .slow = 3, .unstable = .{ .bars = 4 } }, hlcv);
    try K.checkCore(AdoscCore, .{ .unstable = .auto4 }, hlcv);
    try K.checkCore(CmfCore, .{}, hlcv);
    try K.checkCore(CmfCore, .{ .period = 2 }, hlcv);
    try K.checkCore(KvoCore, .{ .fast = 5, .slow = 9, .signal = 3 }, hlcv);
    try K.checkCore(KvoCore, .{ .fast = 3, .slow = 4, .signal = 2, .unstable = .auto4 }, hlcv);
    try K.checkCore(VwapCore, .{}, hlcv);
    const cv = .{ .close = &c, .volume = &v };
    try K.checkCore(EfiCore, .{}, cv);
    try K.checkCore(EfiCore, .{ .period = 1, .unstable = .{ .bars = 2 } }, cv);
    try K.checkCore(NviCore, .{}, cv);
    try K.checkCore(PviCore, .{}, cv);
    try K.checkCore(ObvCore, .{}, cv);
    try K.checkCore(PvtCore, .{}, cv);
    const hlv = .{ .high = &h, .low = &l, .volume = &v };
    try K.checkCore(EmvCore, .{}, hlv);
    try K.checkCore(EmvCore, .{ .period = 1 }, hlv);
    try K.checkCore(MarketfiCore, .{}, hlv);
    const vv = .{ .volume = &v };
    try K.checkCore(RvolCore, .{}, vv);
    try K.checkCore(RvolCore, .{ .period = 1 }, vv);
    try K.checkCore(PvoCore, .{}, vv);
    try K.checkCore(PvoCore, .{ .fast = 9, .slow = 4, .ma = .sma }, vv);
    try K.checkCore(PvoCore, .{ .ma = .wma, .fast = 3, .slow = 7 }, vv);
    try K.checkCore(PvoCore, .{ .ma = .disabled }, vv);
}

test "volume: f32 inputs run the same math" {
    var o: [60]f64 = undefined;
    var h: [60]f64 = undefined;
    var l: [60]f64 = undefined;
    var c: [60]f64 = undefined;
    var v: [60]f64 = undefined;
    K.fillBars(&o, &h, &l, &c, &v, 9);
    var h3: [60]f32 = undefined;
    var l3: [60]f32 = undefined;
    var c3: [60]f32 = undefined;
    var v3: [60]f32 = undefined;
    for (0..60) |i| {
        h3[i] = @floatCast(h[i]);
        l3[i] = @floatCast(l[i]);
        c3[i] = @floatCast(c[i]);
        v3[i] = @floatCast(v[i]);
    }
    var o32: [60]f32 = undefined;
    try testing.expectEqual(@as(usize, 9), try adosc(f32, &h3, &l3, &c3, &v3, &o32, .{}));
    try testing.expectEqual(@as(usize, 19), try cmf(f32, &h3, &l3, &c3, &v3, &o32, .{}));
    try testing.expectEqual(@as(usize, 0), try vwap(f32, &h3, &l3, &c3, &v3, &o32));
    try testing.expectEqual(@as(usize, 25), try pvo(f32, &v3, &o32, .{}));
    var k32: [60]f32 = undefined;
    try testing.expectEqual(@as(usize, 55), try kvo(f32, &h3, &l3, &c3, &v3, &o32, &k32, .{}));
}

test "pvo: an all-zero window of a windowed MA answers exactly 0" {
    var v: [12]f64 = @splat(0.0);
    v[0] = 5;
    v[1] = 3;
    var out: [12]f64 = undefined;
    _ = try pvo(f64, &v, &out, .{ .fast = 2, .slow = 4, .ma = .sma });
    // bars 6.. have 4 zero volumes in the window
    try testing.expectEqual(@as(f64, 0), out[6]);
    try testing.expectEqual(@as(f64, 0), out[11]);
}
