// SPDX-License-Identifier: MIT
//! Window oscillators and price-difference indicators of the momentum group,
//! ported from TA-Lib 0.8.3 (`ta_MOM.c`, `ta_ROC*.c`, `ta_BOP.c`, `ta_IBS.c`,
//! `ta_QSTICK.c`, `ta_WAD.c`, `ta_ASI.c`, `ta_SI.c`, `ta_IMI.c`, `ta_AO.c`,
//! `ta_AC.c`, `ta_DPO.c`, `ta_ER.c`, `ta_FOSC.c`, `ta_CTI.c`, `ta_VHF.c`,
//! `ta_WILLR.c`, `ta_FRACTAL.c`, `ta_CCI.c`, `ta_CHOP.c`, `ta_CHOPTR.c`,
//! `ta_VORTEX.c`, `ta_MFI.c`, `ta_ULTOSC.c`, `ta_CMO.c`, `ta_CMOU.c`; BSD-3,
//! see NOTICE).
//!
//! Every function is a core (`vs_kit.zig` contract) whose `step` mirrors the C
//! loop bar by bar, so batch and streaming run the same arithmetic. Running
//! sums that the C starts at the first window bar (not at bar 0) start there
//! here too (`skip` of the AO / DPO / VORTEX / ULTOSC family): the doubles
//! differ in the last bits otherwise.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const vs = @import("vs_kit.zig");
const mu = @import("mom_util.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const pf = core.pf;

const eps: f64 = 0.00000000000001; // TA_EPSILON

/// `fabs(v) <= TA_EPSILON * scale`
fn zeroScaled(v: f64, scale: f64) bool {
    return @abs(v) <= eps * scale;
}

pub fn PeriodParams(comptime default: usize) type {
    return struct { period: usize = default };
}

/// Declarations every core of this file shares; `InF` is the input struct.
fn Common(comptime InF: fn (comptime type) type) type {
    return struct {
        pub const In = InF(f64);
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return InF(T);
        }
    };
}

fn checkP(p: usize, min: usize) Error!void {
    try core.checkPeriod(p, min);
}

// ── MOM / ROC family ────────────────────────────────────────────────────────

pub const RocKind = enum { mom, roc, rocp, rocr, rocr100 };
pub const MomParams = PeriodParams(10);

pub fn RocCore(comptime kind: RocKind) type {
    return struct {
        const Self = @This();
        const C = Common(vs.X);
        pub const In = C.In;
        pub const Inputs = C.Inputs;
        pub const windowed = true;
        pub const Out = f64;
        pub const Params = MomParams;
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        p: usize,
        n: usize = 0,
        pub fn validate(p: Params) Error!void {
            try checkP(p.period, 1);
        }
        pub fn lookback(p: Params) usize {
            return p.period;
        }
        pub fn ringLen(p: Params) usize {
            return p.period + 1;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .p = p.period };
        }
        pub fn step(self: *Self, src: anytype, b: In) ?f64 {
            const n = self.n;
            self.n += 1;
            if (n < self.p) return null;
            const x = b.x;
            const prior = src.at(n - self.p).x;
            switch (kind) {
                .mom => return x - prior,
                .roc => return if (prior != 0.0) (x / prior - 1.0) * 100.0 else 0.0,
                .rocp => return if (prior != 0.0) (x - prior) / prior else 0.0,
                .rocr => return if (prior != 0.0) x / prior else 0.0,
                .rocr100 => return if (prior != 0.0) x / prior * 100.0 else 0.0,
            }
        }
    };
}

pub const MOM = RocCore(.mom);
pub const ROC = RocCore(.roc);
pub const ROCP = RocCore(.rocp);
pub const ROCR = RocCore(.rocr);
pub const ROCR100 = RocCore(.rocr100);

pub fn momLookback(p: MomParams) Error!usize {
    try MOM.validate(p);
    return MOM.lookback(p);
}
pub fn mom(comptime T: type, in: []const T, out: []T, p: MomParams) Error!usize {
    return vs.batch(T, MOM, p, .{ .x = in }, .{out});
}
pub fn MomStream(comptime T: type) type {
    return vs.SingleStream(T, MOM);
}
pub fn rocLookback(p: MomParams) Error!usize {
    try ROC.validate(p);
    return ROC.lookback(p);
}
pub fn roc(comptime T: type, in: []const T, out: []T, p: MomParams) Error!usize {
    return vs.batch(T, ROC, p, .{ .x = in }, .{out});
}
pub fn RocStream(comptime T: type) type {
    return vs.SingleStream(T, ROC);
}
pub fn rocpLookback(p: MomParams) Error!usize {
    try ROCP.validate(p);
    return ROCP.lookback(p);
}
pub fn rocp(comptime T: type, in: []const T, out: []T, p: MomParams) Error!usize {
    return vs.batch(T, ROCP, p, .{ .x = in }, .{out});
}
pub fn RocpStream(comptime T: type) type {
    return vs.SingleStream(T, ROCP);
}
pub fn rocrLookback(p: MomParams) Error!usize {
    try ROCR.validate(p);
    return ROCR.lookback(p);
}
pub fn rocr(comptime T: type, in: []const T, out: []T, p: MomParams) Error!usize {
    return vs.batch(T, ROCR, p, .{ .x = in }, .{out});
}
pub fn RocrStream(comptime T: type) type {
    return vs.SingleStream(T, ROCR);
}
pub fn rocr100Lookback(p: MomParams) Error!usize {
    try ROCR100.validate(p);
    return ROCR100.lookback(p);
}
pub fn rocr100(comptime T: type, in: []const T, out: []T, p: MomParams) Error!usize {
    return vs.batch(T, ROCR100, p, .{ .x = in }, .{out});
}
pub fn Rocr100Stream(comptime T: type) type {
    return vs.SingleStream(T, ROCR100);
}

// ── parameterless per-bar functions: BOP, IBS, WAD ──────────────────────────

pub const BOP = vs.PureCore(vs.Ohlc, bopOf);
fn bopOf(b: vs.Ohlc(f64)) f64 {
    const r = b.high - b.low;
    return if (r <= 0.0) 0.0 else (b.close - b.open) / r;
}
pub fn bopLookback() usize {
    return 0;
}
pub fn bop(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return vs.batch(T, BOP, .{}, .{ .open = open, .high = high, .low = low, .close = close }, .{out});
}
pub fn BopStream(comptime T: type) type {
    return vs.Stream(T, BOP);
}

pub const IBS = vs.PureCore(vs.Hlc, ibsOf);
fn ibsOf(b: vs.Hlc(f64)) f64 {
    const r = b.high - b.low;
    const v = (b.close - b.low) / r;
    return if (r <= 0.0) 0.5 else v;
}
pub fn ibsLookback() usize {
    return 0;
}
pub fn ibs(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return vs.batch(T, IBS, .{}, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn IbsStream(comptime T: type) type {
    return vs.Stream(T, IBS);
}

/// Williams accumulation/distribution: a running sum of close minus the true
/// low (up bars) or true high (down bars).
pub const WAD = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = f64;
    pub const Params = struct {};
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    sum: f64 = 0.0,
    prev: f64 = 0.0,
    pub fn validate(_: Params) Error!void {}
    pub fn lookback(_: Params) usize {
        return 0;
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn init(_: Params) Error!Self {
        return .{};
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        if (self.n == 0) self.prev = b.close;
        self.n += 1;
        const close = b.close;
        if (close > self.prev) {
            var te = b.low;
            if (self.prev < te) te = self.prev;
            self.sum += close - te;
        } else if (close < self.prev) {
            var te = b.high;
            if (self.prev > te) te = self.prev;
            self.sum += close - te;
        }
        self.prev = close;
        return self.sum;
    }
};
pub fn wadLookback() usize {
    return 0;
}
pub fn wad(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return vs.batch(T, WAD, .{}, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn WadStream(comptime T: type) type {
    return vs.Stream(T, WAD);
}

// ── ASI / SI ────────────────────────────────────────────────────────────────

pub const SwingParams = struct { limit_move: f64 = 3.0 };

fn maxGt(a: f64, b: f64) f64 {
    return if (a > b) a else b;
}

/// Wilder's swing index of the bar given the previous close and body.
fn swingOf(b: vs.Ohlc(f64), prev_close: f64, prev_body: f64, limit: f64) struct { swing: f64, body: f64 } {
    const body = b.close - b.open;
    var nn = b.close - prev_close;
    nn += 0.5 * body;
    nn += 0.25 * prev_body;
    const up = @abs(b.high - prev_close);
    const dn = @abs(b.low - prev_close);
    const rg = @abs(b.high - b.low);
    const k = maxGt(up, dn);
    var r = maxGt(up - 0.5 * dn, dn - 0.5 * up);
    r = maxGt(r, rg);
    r += 0.25 * @abs(prev_body);
    const swing = if (r == 0.0) 0.0 else 50.0 * (nn / r) * (k / limit);
    return .{ .swing = swing, .body = body };
}

pub fn SwingCore(comptime accumulate: bool) type {
    return struct {
        const Self = @This();
        pub const In = vs.Ohlc(f64);
        pub const Out = f64;
        pub const Params = SwingParams;
        pub const windowed = false;
        pub fn Inputs(comptime T: type) type {
            return vs.Ohlc(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        limit: f64,
        n: usize = 0,
        pc: f64 = 0.0,
        pb: f64 = 0.0,
        sum: f64 = 0.0,
        pub fn validate(p: Params) Error!void {
            // TA-Lib: !(x >= 1e-8 && x <= TA_REAL_MAX) is out of range (NaN included)
            if (!(p.limit_move >= 1e-8 and p.limit_move <= 3.0e37)) return error.BadParam;
        }
        pub fn lookback(_: Params) usize {
            return if (accumulate) 0 else 1;
        }
        pub fn ringLen(_: Params) usize {
            return 0;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .limit = p.limit_move };
        }
        pub fn step(self: *Self, _: anytype, b: In) ?f64 {
            const k = self.n;
            self.n += 1;
            if (k == 0) {
                self.pc = b.close;
                self.pb = b.close - b.open;
                return if (accumulate) 0.0 else null;
            }
            const r = swingOf(b, self.pc, self.pb, self.limit);
            self.pc = b.close;
            self.pb = r.body;
            if (!accumulate) return r.swing;
            self.sum += r.swing;
            return self.sum;
        }
    };
}
pub const ASI = SwingCore(true);
pub const SI = SwingCore(false);

pub fn asiLookback(p: SwingParams) Error!usize {
    try ASI.validate(p);
    return ASI.lookback(p);
}
pub fn asi(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out: []T, p: SwingParams) Error!usize {
    return vs.batch(T, ASI, p, .{ .open = open, .high = high, .low = low, .close = close }, .{out});
}
pub fn AsiStream(comptime T: type) type {
    return vs.Stream(T, ASI);
}
pub fn siLookback(p: SwingParams) Error!usize {
    try SI.validate(p);
    return SI.lookback(p);
}
pub fn si(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out: []T, p: SwingParams) Error!usize {
    return vs.batch(T, SI, p, .{ .open = open, .high = high, .low = low, .close = close }, .{out});
}
pub fn SiStream(comptime T: type) type {
    return vs.Stream(T, SI);
}

// ── QSTICK / IMI ────────────────────────────────────────────────────────────

pub const QstickParams = PeriodParams(10);
pub const QSTICK = struct {
    const Self = @This();
    pub const In = mu.Oc(f64);
    pub const Out = f64;
    pub const Params = QstickParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return mu.Oc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    total: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 1);
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        self.total += b.close - b.open;
        if (n + 1 < self.p) return null;
        const t = self.total;
        const old = src.at(n + 1 - self.p);
        self.total -= old.close - old.open;
        return t / pf(self.p);
    }
};
pub fn qstickLookback(p: QstickParams) Error!usize {
    try QSTICK.validate(p);
    return QSTICK.lookback(p);
}
pub fn qstick(comptime T: type, open: []const T, close: []const T, out: []T, p: QstickParams) Error!usize {
    return vs.batch(T, QSTICK, p, .{ .open = open, .close = close }, .{out});
}
pub fn QstickStream(comptime T: type) type {
    return vs.Stream(T, QSTICK);
}

pub const ImiParams = PeriodParams(14);
pub const IMI = struct {
    const Self = @This();
    pub const In = mu.Oc(f64);
    pub const Out = f64;
    pub const Params = ImiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return mu.Oc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *Self, src: anytype, _: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n + 1 < self.p) return null;
        var upsum: f64 = 0.0;
        var downsum: f64 = 0.0;
        var i = n + 1 - self.p;
        while (i <= n) : (i += 1) {
            const t = src.at(i);
            const diff = t.close - t.open;
            const up = (diff + @abs(diff)) * 0.5;
            upsum += up;
            downsum += up - diff;
        }
        return if (upsum + downsum == 0.0) 50.0 else 100.0 * (upsum / (upsum + downsum));
    }
};
pub fn imiLookback(p: ImiParams) Error!usize {
    try IMI.validate(p);
    return IMI.lookback(p);
}
pub fn imi(comptime T: type, open: []const T, close: []const T, out: []T, p: ImiParams) Error!usize {
    return vs.batch(T, IMI, p, .{ .open = open, .close = close }, .{out});
}
pub fn ImiStream(comptime T: type) type {
    return vs.Stream(T, IMI);
}

// ── AO / AC ─────────────────────────────────────────────────────────────────

pub const AoParams = struct { fast: usize = 5, slow: usize = 34 };

fn median(b: vs.Hl(f64)) f64 {
    return (b.high + b.low) / 2.0;
}

/// The oscillator part shared by AO and AC: SMA(fast) - SMA(slow) of the median
/// price, each running sum starting at its own first window bar of the first
/// output.
const AoState = struct {
    f: usize,
    s: usize,
    l: usize, // lookback: max(f, s) - 1
    sum_f: f64 = 0.0,
    sum_s: f64 = 0.0,

    fn init(p: AoParams) AoState {
        return .{ .f = p.fast, .s = p.slow, .l = @max(p.fast, p.slow) - 1 };
    }
    /// `n` is the index of the bar being fed; null before the lookback.
    fn feed(self: *AoState, src: anytype, n: usize, b: vs.Hl(f64)) ?f64 {
        const m = median(b);
        if (n + self.f > self.l) self.sum_f += m; // n >= l - (f - 1)
        if (n + self.s > self.l) self.sum_s += m;
        if (n < self.l) return null;
        const t = self.sum_f / pf(self.f) - self.sum_s / pf(self.s);
        self.sum_f -= median(src.at(n + 1 - self.f));
        self.sum_s -= median(src.at(n + 1 - self.s));
        return t;
    }
};

fn checkAo(p: AoParams) Error!void {
    try checkP(p.fast, 2);
    try checkP(p.slow, 2);
}

pub const AO = struct {
    const Self = @This();
    pub const In = vs.Hl(f64);
    pub const Out = f64;
    pub const Params = AoParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    st: AoState,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkAo(p);
    }
    pub fn lookback(p: Params) usize {
        return @max(p.fast, p.slow) - 1;
    }
    pub fn ringLen(p: Params) usize {
        return @max(p.fast, p.slow);
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .st = AoState.init(p) };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        return self.st.feed(src, n, b);
    }
};
pub fn aoLookback(p: AoParams) Error!usize {
    try AO.validate(p);
    return AO.lookback(p);
}
pub fn ao(comptime T: type, high: []const T, low: []const T, out: []T, p: AoParams) Error!usize {
    return vs.batch(T, AO, p, .{ .high = high, .low = low }, .{out});
}
pub fn AoStream(comptime T: type) type {
    return vs.Stream(T, AO);
}

pub const AcParams = struct { fast: usize = 5, slow: usize = 34, signal: usize = 5 };

/// Accelerator oscillator: AO minus its SMA(signal); the AO values live in a
/// ring of `signal` slots in the scratch.
pub const AC = struct {
    const Self = @This();
    pub const In = vs.Hl(f64);
    pub const Out = f64;
    pub const Params = AcParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hl(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    st: AoState,
    sig: smooth.SmaCore,
    ring: mu.Ring,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkAo(.{ .fast = p.fast, .slow = p.slow });
        try checkP(p.signal, 2);
    }
    pub fn lookback(p: Params) usize {
        return @max(p.fast, p.slow) - 1 + p.signal - 1;
    }
    pub fn ringLen(p: Params) usize {
        return @max(p.fast, p.slow);
    }
    pub fn scratchLen(p: Params) usize {
        return p.signal;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < p.signal) return error.BadParam;
        return .{
            .st = AoState.init(.{ .fast = p.fast, .slow = p.slow }),
            .sig = try smooth.SmaCore.init(.{ .period = p.signal }),
            .ring = mu.Ring.init(scratch[0..p.signal]),
        };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const osc = self.st.feed(src, n, b) orelse return null;
        self.ring.push(osc);
        const avg = self.sig.step(self.ring.view(), osc) orelse return null;
        return osc - avg;
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?f64 {
        return mu.peekRings(Self, self, src, b);
    }
};
pub fn acLookback(p: AcParams) Error!usize {
    try AC.validate(p);
    return AC.lookback(p);
}
pub fn ac(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, out: []T, p: AcParams) core.AllocError!usize {
    return vs.batchScratch(T, AC, gpa, p, .{ .high = high, .low = low }, .{out});
}
pub fn AcStream(comptime T: type) type {
    return vs.Stream(T, AC);
}

// ── DPO ─────────────────────────────────────────────────────────────────────

pub const DpoParams = PeriodParams(20);
pub const DPO = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = DpoParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    l: usize,
    n: usize = 0,
    total: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return @max(p.period - 1, p.period / 2 + 1);
    }
    pub fn ringLen(p: Params) usize {
        return @max(p.period, p.period / 2 + 2);
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period, .l = lookback(p) };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n + self.p > self.l) self.total += b.x; // from bar l - (p - 1)
        if (n < self.l) return null;
        const t = self.total;
        self.total -= src.at(n + 1 - self.p).x;
        const disp = src.at(n - (self.p / 2 + 1)).x;
        return disp - t / pf(self.p);
    }
};
pub fn dpoLookback(p: DpoParams) Error!usize {
    try DPO.validate(p);
    return DPO.lookback(p);
}
pub fn dpo(comptime T: type, in: []const T, out: []T, p: DpoParams) Error!usize {
    return vs.batch(T, DPO, p, .{ .x = in }, .{out});
}
pub fn DpoStream(comptime T: type) type {
    return vs.SingleStream(T, DPO);
}

// ── ER (Kaufman efficiency ratio) ───────────────────────────────────────────

pub const ErParams = PeriodParams(10);
pub const ER = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = ErParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    sum: f64 = 0.0,
    null_run: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 2;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    fn ratio(self: *const Self, period_roc: f64) f64 {
        if (self.sum <= 0.0 or self.sum <= period_roc) return 1.0;
        var t = @abs(period_roc / self.sum);
        if (t > 1.0) t = 1.0;
        return t;
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) return null;
        const prev = src.at(n - 1).x;
        const d = @abs(prev - b.x);
        if (n > self.p) {
            // retire the oldest one-bar change, take the new one
            self.sum -= @abs(src.at(n - self.p - 1).x - src.at(n - self.p).x);
        }
        self.sum += d;
        self.null_run = if (d <= 0.0) self.null_run + 1 else 0;
        if (n < self.p) return null;
        const period_roc = b.x - src.at(n - self.p).x;
        if (n > self.p and self.null_run >= self.p) {
            self.null_run = self.p;
            self.sum = 0.0;
            return 1.0;
        }
        return self.ratio(period_roc);
    }
};
pub fn erLookback(p: ErParams) Error!usize {
    try ER.validate(p);
    return ER.lookback(p);
}
pub fn er(comptime T: type, in: []const T, out: []T, p: ErParams) Error!usize {
    return vs.batch(T, ER, p, .{ .x = in }, .{out});
}
pub fn ErStream(comptime T: type) type {
    return vs.SingleStream(T, ER);
}

// ── FOSC (forecast oscillator) ──────────────────────────────────────────────

pub const FoscParams = PeriodParams(5);
pub const FOSC = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = FoscParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    dp: f64,
    sum_x: f64,
    divisor: f64,
    n: usize = 0,
    sum_y: f64 = 0.0,
    sum_xy: f64 = 0.0,
    sum_abs: f64 = 0.0,
    since: usize,
    trailing: f64 = 0.0,
    m: f64 = 0.0,
    b: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 1;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        const dp = pf(p.period);
        const sum_x = dp * pf(p.period - 1) * 0.5;
        const sum_x_sqr = dp * pf(p.period - 1) * pf(2 * p.period - 1) / 6.0;
        return .{ .p = p.period, .dp = dp, .sum_x = sum_x, .divisor = sum_x * sum_x - dp * sum_x_sqr, .since = 32 * p.period };
    }
    fn fit(self: *Self) void {
        self.m = (self.dp * self.sum_xy - self.sum_x * self.sum_y) / self.divisor;
        self.b = (self.sum_y - self.m * self.sum_x) / self.dp;
    }
    fn out(self: *const Self, close: f64) f64 {
        if (close != 0.0) return 100.0 * (close - @mulAdd(f64, self.m, self.dp, self.b)) / close;
        return 0.0;
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const today = self.n;
        self.n += 1;
        const p = self.p;
        if (today < p) return null;
        if (today == p) {
            // the window is the p bars before the current one
            var i: usize = p;
            while (i > 0) {
                i -= 1;
                const v = src.at(p - 1 - i).x;
                self.sum_y += v;
                self.sum_xy += pf(i) * v;
                self.sum_abs += @abs(v);
            }
            self.fit();
            self.trailing = src.at(0).x;
            return self.out(b.x);
        }
        const weighted = self.dp * self.trailing;
        self.sum_xy = self.sum_xy + self.sum_y - weighted;
        self.sum_y = self.sum_y - self.trailing + src.at(today - 1).x;
        self.sum_abs = self.sum_abs - @abs(self.trailing) + @abs(src.at(today - 1).x);
        self.since -= 1;
        if (self.since == 0 or @abs(weighted) > 100.0 * self.sum_abs) {
            self.since = 32 * p;
            self.sum_y = 0.0;
            self.sum_xy = 0.0;
            self.sum_abs = 0.0;
            var w = pf(p - 1);
            var j = today - p;
            while (j < today) : (j += 1) {
                const v = src.at(j).x;
                self.sum_y += v;
                self.sum_xy += w * v;
                self.sum_abs += @abs(v);
                w -= 1.0;
            }
        }
        self.fit();
        self.trailing = src.at(today - p).x;
        return self.out(b.x);
    }
};
pub fn foscLookback(p: FoscParams) Error!usize {
    try FOSC.validate(p);
    return FOSC.lookback(p);
}
pub fn fosc(comptime T: type, in: []const T, out: []T, p: FoscParams) Error!usize {
    return vs.batch(T, FOSC, p, .{ .x = in }, .{out});
}
pub fn FoscStream(comptime T: type) type {
    return vs.SingleStream(T, FOSC);
}

// ── CTI (correlation trend indicator) ───────────────────────────────────────

pub const CtiParams = PeriodParams(20);
pub const CTI = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = CtiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    l: usize,
    dp: f64,
    inv: f64,
    sum_y: f64,
    ss_y: f64,
    n: usize = 0,
    shift: f64 = 0.0,
    sum_x: f64 = 0.0,
    sum_x2: f64 = 0.0,
    sum_xy: f64 = 0.0,
    peak_x2: f64 = 0.0,
    since: usize,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        const dp = pf(p.period);
        return .{
            .p = p.period,
            .l = p.period - 1,
            .dp = dp,
            .inv = 1.0 / dp,
            .sum_y = dp * (dp - 1.0) * 0.5,
            .ss_y = dp * (dp * dp - 1.0) / 12.0,
            .since = 32 * p.period,
        };
    }
    fn rebuild(self: *Self, src: anytype, today: usize) void {
        self.sum_xy = 0.0;
        self.sum_x2 = 0.0;
        self.sum_x = 0.0;
        var j = today - self.l;
        while (j <= today) : (j += 1) {
            const x = src.at(j).x - self.shift;
            self.sum_x += x;
            self.sum_x2 += x * x;
            self.sum_xy += x * pf(today - j);
        }
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const today = self.n;
        self.n += 1;
        if (today == 0) {
            self.shift = b.x;
        }
        if (today < self.l) {
            const x = b.x - self.shift;
            self.sum_x += x;
            self.sum_x2 += x * x;
            self.sum_xy += x * pf(self.l - today);
            return null;
        }
        if (today == self.l) self.peak_x2 = self.sum_x2;
        const x = b.x - self.shift;
        self.sum_x += x;
        self.sum_x2 += x * x;
        self.peak_x2 = if (self.sum_x2 > self.peak_x2) self.sum_x2 else self.peak_x2;
        var ss_x = self.sum_x2 - self.sum_x * self.sum_x * self.inv;
        var sp_xy = self.sum_xy - self.sum_x * self.sum_y * self.inv;
        self.since -= 1;
        if (ss_x < 0.000001 * self.peak_x2 or self.since == 0) {
            self.since = 32 * self.p;
            var t: f64 = 0.0;
            var j = today - self.l;
            while (j <= today) : (j += 1) t += src.at(j).x;
            self.shift = t * self.inv;
            self.rebuild(src, today);
            if (self.sum_x2 - self.sum_x * self.sum_x * self.inv < 0.000001 * self.sum_x2) {
                self.shift = b.x;
                self.rebuild(src, today);
            }
            self.peak_x2 = self.sum_x2;
            ss_x = self.sum_x2 - self.sum_x * self.sum_x * self.inv;
            sp_xy = self.sum_xy - self.sum_x * self.sum_y * self.inv;
        }
        const trailing_x = src.at(today - self.l).x - self.shift;
        var out: f64 = 0.0;
        if (ss_x > 0.00000000000001 * self.sum_x2 and ss_x * self.ss_y > 0.0) {
            var t = -sp_xy / @sqrt(ss_x * self.ss_y);
            if (t > 1.0) {
                t = 1.0;
            } else if (t < -1.0) {
                t = -1.0;
            }
            out = t;
        }
        self.sum_xy = self.sum_xy + self.sum_x - self.dp * trailing_x;
        self.sum_x -= trailing_x;
        self.sum_x2 -= trailing_x * trailing_x;
        return out;
    }
};
pub fn ctiLookback(p: CtiParams) Error!usize {
    try CTI.validate(p);
    return CTI.lookback(p);
}
pub fn cti(comptime T: type, in: []const T, out: []T, p: CtiParams) Error!usize {
    return vs.batch(T, CTI, p, .{ .x = in }, .{out});
}
pub fn CtiStream(comptime T: type) type {
    return vs.SingleStream(T, CTI);
}

// ── VHF / WILLR ─────────────────────────────────────────────────────────────

pub const VhfParams = PeriodParams(28);
pub const VHF = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = VhfParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 1;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const today = self.n;
        self.n += 1;
        if (today < self.p) return null;
        var highest = b.x;
        var lowest = highest;
        var prev = highest;
        var sum_change: f64 = 0.0;
        var i: usize = self.p + 1;
        while (i > 0) {
            i -= 1;
            const t = src.at(today - i).x;
            if (i < self.p) {
                sum_change += @abs(t - prev);
                if (t > highest) highest = t;
                if (t < lowest) lowest = t;
            }
            prev = t;
        }
        return if (sum_change > 0.0) (highest - lowest) / sum_change else 0.0;
    }
};
pub fn vhfLookback(p: VhfParams) Error!usize {
    try VHF.validate(p);
    return VHF.lookback(p);
}
pub fn vhf(comptime T: type, in: []const T, out: []T, p: VhfParams) Error!usize {
    return vs.batch(T, VHF, p, .{ .x = in }, .{out});
}
pub fn VhfStream(comptime T: type) type {
    return vs.SingleStream(T, VHF);
}

pub const WillrParams = PeriodParams(14);
pub const WILLR = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = f64;
    pub const Params = WillrParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const today = self.n;
        self.n += 1;
        if (today + 1 < self.p) return null;
        var highest = b.high;
        var lowest = b.low;
        var i = today + 1 - self.p;
        while (i < today) : (i += 1) {
            const t = src.at(i);
            if (t.high > highest) highest = t.high;
            if (t.low < lowest) lowest = t.low;
        }
        if (zeroScaled(highest - lowest, @abs(highest) + @abs(lowest))) return 0.0;
        var t = (highest - b.close) / (highest - lowest) * -100.0;
        if (t > 0.0) {
            t = 0.0;
        } else if (t < -100.0) {
            t = -100.0;
        }
        return t;
    }
};
pub fn willrLookback(p: WillrParams) Error!usize {
    try WILLR.validate(p);
    return WILLR.lookback(p);
}
pub fn willr(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: WillrParams) Error!usize {
    return vs.batch(T, WILLR, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn WillrStream(comptime T: type) type {
    return vs.Stream(T, WILLR);
}

// ── FRACTAL ─────────────────────────────────────────────────────────────────

pub const FractalParams = struct { left: usize = 2, right: usize = 2 };
pub const FRACTAL = struct {
    const Self = @This();
    pub const In = vs.Hl(f64);
    pub const Out = struct { swing_high: i8, swing_low: i8 };
    pub const Params = FractalParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hl(T);
    }
    pub fn Outputs(comptime _: type) type {
        return Out;
    }
    l: usize,
    r: usize,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.left, 1);
        try checkP(p.right, 1);
    }
    pub fn lookback(p: Params) usize {
        return p.left + p.right;
    }
    pub fn ringLen(p: Params) usize {
        return p.left + p.right + 1;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .l = p.left, .r = p.right };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?Out {
        const today = self.n;
        self.n += 1;
        const span = self.l + self.r;
        if (today < span) return null;
        var pivot = b;
        var other = b;
        var i = span + 1;
        while (i > 0) {
            i -= 1;
            const t = if (i == 0) b else src.at(today - i);
            if (i == self.r) {
                pivot = t;
            } else if (i == span) {
                other = t;
            } else {
                if (t.high > other.high) other.high = t.high;
                if (t.low < other.low) other.low = t.low;
            }
        }
        return .{
            .swing_high = if (pivot.high > other.high) 100 else 0,
            .swing_low = if (pivot.low < other.low) 100 else 0,
        };
    }
};
pub fn fractalLookback(p: FractalParams) Error!usize {
    try FRACTAL.validate(p);
    return FRACTAL.lookback(p);
}
/// Outputs are 100 where the middle bar is a swing high / low, 0 where not
/// (also in the lead).
pub fn fractal(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, swing_high: []i8, swing_low: []i8, p: FractalParams) core.AllocError!usize {
    return mu.batchLead0(T, FRACTAL, gpa, p, .{ .high = high, .low = low }, .{ swing_high, swing_low });
}
pub fn FractalStream(comptime T: type) type {
    return vs.Stream(T, FRACTAL);
}

// ── CCI ─────────────────────────────────────────────────────────────────────

pub const CciParams = PeriodParams(14);
pub const CCI = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = f64;
    pub const Params = CciParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    fn tp(t: In) f64 {
        return (t.high + t.low + t.close) / 3;
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        const p = self.p;
        if (n + 1 < p) return null;
        const last = tp(b);
        const cur = n % p;
        // TA-Lib sums over the slots of its circular buffer, in slot order
        var avg: f64 = 0;
        var j: usize = 0;
        while (j < p) : (j += 1) {
            const ago = (cur + p - j) % p;
            avg += if (ago == 0) last else tp(src.at(n - ago));
        }
        avg /= pf(p);
        var dev: f64 = 0;
        j = 0;
        while (j < p) : (j += 1) {
            const ago = (cur + p - j) % p;
            const v = if (ago == 0) last else tp(src.at(n - ago));
            dev += @abs(v - avg);
        }
        dev /= pf(p);
        const t = last - avg;
        const scale = @abs(avg);
        if (!zeroScaled(t, scale) and !zeroScaled(dev, scale) and 0.015 * dev != 0.0) return t / (0.015 * dev);
        return 0.0;
    }
};
pub fn cciLookback(p: CciParams) Error!usize {
    try CCI.validate(p);
    return CCI.lookback(p);
}
pub fn cci(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: CciParams) Error!usize {
    return vs.batch(T, CCI, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn CciStream(comptime T: type) type {
    return vs.Stream(T, CCI);
}

// ── CHOP / CHOPTR ───────────────────────────────────────────────────────────

pub const ChopParams = PeriodParams(14);
pub fn ChopCore(comptime true_range: bool) type {
    return struct {
        const Self = @This();
        pub const In = vs.Hlc(f64);
        pub const Out = f64;
        pub const Params = ChopParams;
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return vs.Hlc(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        p: usize,
        log_p: f64,
        n: usize = 0,
        pub fn validate(p: Params) Error!void {
            try checkP(p.period, 2);
        }
        pub fn lookback(p: Params) usize {
            return p.period;
        }
        pub fn ringLen(p: Params) usize {
            return p.period + 1;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .p = p.period, .log_p = std.math.log10(pf(p.period)) };
        }
        pub fn step(self: *Self, src: anytype, b: In) ?f64 {
            const today = self.n;
            self.n += 1;
            const p = self.p;
            if (today < p) return null;
            var highest = b.high;
            var lowest = b.low;
            var sum_tr: f64 = 0.0;
            var prev_close: f64 = 0.0;
            var i = p + 1;
            while (i > 0) {
                i -= 1;
                const t = if (i == 0) b else src.at(today - i);
                if (i < p) {
                    var th = t.high;
                    if (prev_close > th) th = prev_close;
                    var tl = t.low;
                    if (prev_close < tl) tl = prev_close;
                    sum_tr += th - tl;
                    if (true_range) {
                        if (th > highest) highest = th;
                        if (tl < lowest) lowest = tl;
                    } else {
                        if (t.high > highest) highest = t.high;
                        if (t.low < lowest) lowest = t.low;
                    }
                }
                prev_close = t.close;
            }
            if (true_range) {
                if (sum_tr <= 0.0) return 100.0;
            } else if (highest - lowest <= 0.0 or sum_tr <= 0.0) return 100.0;
            return 100.0 * (std.math.log10(sum_tr / (highest - lowest)) / self.log_p);
        }
    };
}
pub const CHOP = ChopCore(false);
pub const CHOPTR = ChopCore(true);
pub fn chopLookback(p: ChopParams) Error!usize {
    try CHOP.validate(p);
    return CHOP.lookback(p);
}
pub fn chop(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: ChopParams) Error!usize {
    return vs.batch(T, CHOP, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn ChopStream(comptime T: type) type {
    return vs.Stream(T, CHOP);
}
pub fn choptrLookback(p: ChopParams) Error!usize {
    try CHOPTR.validate(p);
    return CHOPTR.lookback(p);
}
pub fn choptr(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: ChopParams) Error!usize {
    return vs.batch(T, CHOPTR, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn ChoptrStream(comptime T: type) type {
    return vs.Stream(T, CHOPTR);
}

// ── VORTEX ──────────────────────────────────────────────────────────────────

pub const VortexParams = PeriodParams(14);
pub const VORTEX = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = struct { plus: f64, minus: f64 };
    pub const Params = VortexParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return struct { plus: T, minus: T };
    }
    p: usize,
    n: usize = 0,
    s_tr: f64 = 0.0,
    s_vmp: f64 = 0.0,
    s_vmm: f64 = 0.0,
    null_run: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 1);
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 2;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    const Terms = struct { tr: f64, vmp: f64, vmm: f64 };
    fn terms(cur: In, prev: In) Terms {
        var tr = cur.high - cur.low;
        var d = @abs(prev.close - cur.high);
        if (d > tr) tr = d;
        d = @abs(prev.close - cur.low);
        if (d > tr) tr = d;
        return .{ .tr = tr, .vmp = @abs(cur.high - prev.low), .vmm = @abs(cur.low - prev.high) };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?Out {
        const n = self.n;
        self.n += 1;
        if (n == 0) return null;
        const t = terms(b, src.at(n - 1));
        self.s_tr += t.tr;
        self.s_vmp += t.vmp;
        self.s_vmm += t.vmm;
        self.null_run = if (t.tr <= 0.0) self.null_run + 1 else 0;
        if (n < self.p) return null;
        if (self.null_run >= self.p) {
            self.null_run = self.p;
            self.s_tr = 0.0;
        }
        const cur_tr = self.s_tr;
        const cur_vmp = self.s_vmp;
        const cur_vmm = self.s_vmm;
        const k = n - self.p + 1; // the bar leaving the window
        const old = terms(src.at(k), src.at(k - 1));
        self.s_tr -= old.tr;
        self.s_vmp -= old.vmp;
        self.s_vmm -= old.vmm;
        if (cur_tr > 0.0) return .{ .plus = cur_vmp / cur_tr, .minus = cur_vmm / cur_tr };
        return .{ .plus = 0.0, .minus = 0.0 };
    }
};
pub fn vortexLookback(p: VortexParams) Error!usize {
    try VORTEX.validate(p);
    return VORTEX.lookback(p);
}
/// Outputs `plus` (+VI) and `minus` (-VI).
pub fn vortex(comptime T: type, high: []const T, low: []const T, close: []const T, plus: []T, minus: []T, p: VortexParams) Error!usize {
    return vs.batch(T, VORTEX, p, .{ .high = high, .low = low, .close = close }, .{ plus, minus });
}
pub fn VortexStream(comptime T: type) type {
    return vs.Stream(T, VORTEX);
}

// ── MFI ─────────────────────────────────────────────────────────────────────

pub const MfiParams = PeriodParams(14);
pub const MFI = struct {
    const Self = @This();
    pub const In = vs.Hlcv(f64);
    pub const Out = f64;
    pub const Params = MfiParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlcv(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    pos: f64 = 0.0,
    neg: f64 = 0.0,
    null_run: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 2;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    fn tp(t: In) f64 {
        return (t.high + t.low + t.close) / 3.0;
    }
    const Flow = struct { money: f64, pos: f64, neg: f64 };
    fn flow(cur: In, prev: In) Flow {
        const a = tp(cur);
        const pv = tp(prev);
        const diff = a - pv;
        const scale = @abs(a) + @abs(pv);
        const raw = a * cur.volume;
        const money = if (zeroScaled(diff, scale)) 0.0 else raw;
        return .{
            .money = money,
            .pos = if (diff < 0.0) 0.0 else money,
            .neg = if (diff < 0.0) money else 0.0,
        };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) return null;
        if (n > self.p) {
            const old = flow(src.at(n - self.p), src.at(n - self.p - 1));
            self.pos -= old.pos;
            self.neg -= old.neg;
        }
        const f = flow(b, src.at(n - 1));
        self.pos += f.pos;
        self.neg += f.neg;
        self.null_run = if (f.money == 0.0) self.null_run + 1 else 0;
        if (self.null_run >= self.p) {
            self.null_run = self.p;
            self.pos = 0.0;
            self.neg = 0.0;
        }
        if (n < self.p) return null;
        const t = self.pos + self.neg;
        const clamped = if (self.pos < 0.0) 0.0 else if (self.pos > t) t else self.pos;
        if (t <= 0.0) return 0.0;
        return 100.0 * (clamped / t);
    }
};
pub fn mfiLookback(p: MfiParams) Error!usize {
    try MFI.validate(p);
    return MFI.lookback(p);
}
pub fn mfi(comptime T: type, high: []const T, low: []const T, close: []const T, volume: []const T, out: []T, p: MfiParams) Error!usize {
    return vs.batch(T, MFI, p, .{ .high = high, .low = low, .close = close, .volume = volume }, .{out});
}
pub fn MfiStream(comptime T: type) type {
    return vs.Stream(T, MFI);
}

// ── ULTOSC ──────────────────────────────────────────────────────────────────

pub const UltoscParams = struct { period1: usize = 7, period2: usize = 14, period3: usize = 28 };
pub const ULTOSC = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = f64;
    pub const Params = UltoscParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p1: usize,
    p2: usize,
    p3: usize,
    n: usize = 0,
    a1: f64 = 0.0,
    b1: f64 = 0.0,
    a2: f64 = 0.0,
    b2: f64 = 0.0,
    a3: f64 = 0.0,
    b3: f64 = 0.0,
    null_run: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period1, 1);
        try checkP(p.period2, 1);
        try checkP(p.period3, 1);
    }
    /// The three periods, shortest first (TA-Lib sorts them).
    fn sorted(p: Params) [3]usize {
        var a = [3]usize{ p.period1, p.period2, p.period3 };
        std.mem.sort(usize, &a, {}, std.sort.asc(usize));
        return a;
    }
    pub fn lookback(p: Params) usize {
        return sorted(p)[2];
    }
    pub fn ringLen(p: Params) usize {
        return sorted(p)[2] + 1;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        const s = sorted(p);
        return .{ .p1 = s[0], .p2 = s[1], .p3 = s[2] };
    }
    const Term = struct { cmtl: f64, tr: f64 };
    fn term(cur: In, prev: In) Term {
        const true_low = if (cur.low < prev.close) cur.low else prev.close;
        var tr = cur.high - cur.low;
        var d = @abs(prev.close - cur.high);
        if (d > tr) tr = d;
        d = @abs(prev.close - cur.low);
        if (d > tr) tr = d;
        return .{ .cmtl = cur.close - true_low, .tr = tr };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) return null;
        const l = self.p3; // lookback
        const t = term(b, src.at(n - 1));
        const live = !(t.tr + @abs(t.cmtl) <= 0.0);
        self.null_run = if (live) 0 else self.null_run + 1;
        // sums start at the first bar of their own window of the first output
        if (n + self.p1 > l) {
            self.a1 += t.cmtl;
            self.b1 += t.tr;
        }
        if (n + self.p2 > l) {
            self.a2 += t.cmtl;
            self.b2 += t.tr;
        }
        self.a3 += t.cmtl;
        self.b3 += t.tr;
        if (n < l) return null;
        if (self.null_run >= self.p1) {
            self.a1 = 0.0;
            self.b1 = 0.0;
        }
        if (self.null_run >= self.p2) {
            self.a2 = 0.0;
            self.b2 = 0.0;
        }
        if (self.null_run >= self.p3) {
            self.null_run = self.p3;
            self.a3 = 0.0;
            self.b3 = 0.0;
        }
        var output: f64 = 0.0;
        if (self.b1 > 0.0) output += 4.0 * (self.a1 / self.b1);
        if (self.b2 > 0.0) output += 2.0 * (self.a2 / self.b2);
        if (self.b3 > 0.0) output += self.a3 / self.b3;
        const o1 = term(src.at(n + 1 - self.p1), src.at(n - self.p1));
        self.a1 -= o1.cmtl;
        self.b1 -= o1.tr;
        const o2 = term(src.at(n + 1 - self.p2), src.at(n - self.p2));
        self.a2 -= o2.cmtl;
        self.b2 -= o2.tr;
        const o3 = term(src.at(n + 1 - self.p3), src.at(n - self.p3));
        self.a3 -= o3.cmtl;
        self.b3 -= o3.tr;
        return 100.0 * (output / 7.0);
    }
};
pub fn ultoscLookback(p: UltoscParams) Error!usize {
    try ULTOSC.validate(p);
    return ULTOSC.lookback(p);
}
pub fn ultosc(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: UltoscParams) Error!usize {
    return vs.batch(T, ULTOSC, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn UltoscStream(comptime T: type) type {
    return vs.Stream(T, ULTOSC);
}

// ── CMO / CMOU ──────────────────────────────────────────────────────────────

pub const CmoParams = struct { period: usize = 14, unstable: Unstable = core.no_unstable };
pub const CMO = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = CmoParams;
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    l: usize,
    inv: f64,
    n: usize = 0,
    prev: f64 = 0.0,
    gain: f64 = 0.0,
    loss: f64 = 0.0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
        try p.unstable.check();
    }
    pub fn lookback(p: Params) usize {
        return p.period + p.unstable.get(10 * p.period, 19 * p.period);
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period, .l = lookback(p), .inv = 1.0 / pf(p.period) };
    }
    fn answer(self: *const Self) f64 {
        const t = self.gain + self.loss;
        return if (t > 0.0) 100.0 * ((self.gain - self.loss) / t) else 0.0;
    }
    pub fn step(self: *Self, _: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) {
            self.prev = b.x;
            return null;
        }
        const d = b.x - self.prev;
        self.prev = b.x;
        const gd = if (d > 0.0) d else 0.0;
        if (n <= self.p) {
            self.gain += gd;
            self.loss += gd - d;
            if (n < self.p) return null;
            self.loss /= pf(self.p);
            self.gain /= pf(self.p);
            return if (self.l == self.p) self.answer() else null;
        }
        self.gain += gd * self.inv - self.gain * self.inv;
        self.loss += (gd - d) * self.inv - self.loss * self.inv;
        return if (n >= self.l) self.answer() else null;
    }
};
pub fn cmoLookback(p: CmoParams) Error!usize {
    try CMO.validate(p);
    return CMO.lookback(p);
}
pub fn cmo(comptime T: type, in: []const T, out: []T, p: CmoParams) Error!usize {
    return vs.batch(T, CMO, p, .{ .x = in }, .{out});
}
pub fn CmoStream(comptime T: type) type {
    return vs.SingleStream(T, CMO);
}

pub const CmouParams = PeriodParams(14);
pub const CMOU = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = CmouParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    p: usize,
    n: usize = 0,
    up_sum: f64 = 0.0,
    down_sum: f64 = 0.0,
    null_run: usize = 0,
    pub fn validate(p: Params) Error!void {
        try checkP(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period;
    }
    pub fn ringLen(p: Params) usize {
        return p.period + 1;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        return .{ .p = p.period };
    }
    fn upOf(d: f64) f64 {
        return (d + @abs(d)) * 0.5;
    }
    fn answer(self: *const Self) f64 {
        const s = self.up_sum + self.down_sum;
        return if (s > 0.0) 100.0 * (self.up_sum - self.down_sum) / s else 0.0;
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        const n = self.n;
        self.n += 1;
        if (n == 0) return null;
        const d = b.x - src.at(n - 1).x;
        const up = upOf(d);
        self.up_sum += up;
        self.down_sum += up - d;
        self.null_run = if (@abs(d) <= 0.0) self.null_run + 1 else 0;
        if (n < self.p) return null;
        var out: f64 = undefined;
        if (n > self.p and self.null_run >= self.p) {
            self.null_run = self.p;
            self.up_sum = 0.0;
            self.down_sum = 0.0;
            out = 0.0;
        } else {
            out = self.answer();
        }
        const k = n - self.p + 1; // the bar leaving the window
        const od = src.at(k).x - src.at(k - 1).x;
        const ou = upOf(od);
        self.up_sum -= ou;
        self.down_sum -= ou - od;
        return out;
    }
};
pub fn cmouLookback(p: CmouParams) Error!usize {
    try CMOU.validate(p);
    return CMOU.lookback(p);
}
pub fn cmou(comptime T: type, in: []const T, out: []T, p: CmouParams) Error!usize {
    return vs.batch(T, CMOU, p, .{ .x = in }, .{out});
}
pub fn CmouStream(comptime T: type) type {
    return vs.SingleStream(T, CMOU);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "simple group: batch == streaming, lookback == NaN lead" {
    try mu.checkCore(MOM, .{}, 100, 1);
    try mu.checkCore(MOM, .{ .period = 1 }, 50, 2);
    try mu.checkCore(ROC, .{ .period = 3 }, 100, 3);
    try mu.checkCore(ROCP, .{ .period = 3 }, 100, 4);
    try mu.checkCore(ROCR, .{ .period = 3 }, 100, 5);
    try mu.checkCore(ROCR100, .{ .period = 3 }, 100, 6);
    try mu.checkCore(BOP, .{}, 100, 7);
    try mu.checkCore(IBS, .{}, 100, 8);
    try mu.checkCore(WAD, .{}, 100, 9);
    try mu.checkCore(ASI, .{}, 100, 10);
    try mu.checkCore(SI, .{ .limit_move = 0.5 }, 100, 11);
    try mu.checkCore(QSTICK, .{}, 100, 12);
    try mu.checkCore(QSTICK, .{ .period = 1 }, 50, 13);
    try mu.checkCore(IMI, .{}, 100, 14);
    try mu.checkCore(AO, .{}, 100, 15);
    try mu.checkCore(AO, .{ .fast = 9, .slow = 3 }, 100, 16);
    try mu.checkCore(AC, .{}, 100, 17);
    try mu.checkCore(AC, .{ .fast = 3, .slow = 4, .signal = 2 }, 100, 18);
    try mu.checkCore(DPO, .{}, 100, 19);
    try mu.checkCore(DPO, .{ .period = 2 }, 50, 20);
    try mu.checkCore(ER, .{}, 100, 21);
    try mu.checkCore(FOSC, .{}, 300, 22);
    try mu.checkCore(FOSC, .{ .period = 40 }, 300, 23);
    try mu.checkCore(CTI, .{}, 300, 24);
    try mu.checkCore(CTI, .{ .period = 2 }, 100, 25);
    try mu.checkCore(VHF, .{}, 100, 26);
    try mu.checkCore(WILLR, .{}, 100, 27);
    try mu.checkCore(CCI, .{}, 100, 28);
    try mu.checkCore(CCI, .{ .period = 2 }, 50, 29);
    try mu.checkCore(CHOP, .{}, 100, 30);
    try mu.checkCore(CHOPTR, .{}, 100, 31);
    try mu.checkCore(VORTEX, .{}, 100, 32);
    try mu.checkCore(VORTEX, .{ .period = 1 }, 50, 33);
    try mu.checkCore(MFI, .{}, 200, 34);
    try mu.checkCore(ULTOSC, .{}, 200, 35);
    try mu.checkCore(ULTOSC, .{ .period1 = 20, .period2 = 3, .period3 = 5 }, 100, 36);
    try mu.checkCore(CMO, .{}, 100, 37);
    try mu.checkCore(CMO, .{ .period = 4, .unstable = .{ .bars = 6 } }, 100, 38);
    try mu.checkCore(CMOU, .{}, 100, 39);
}

test "simple group: f32 path" {
    try mu.checkF32(MOM, .{}, 60, 41);
    try mu.checkF32(BOP, .{}, 60, 42);
    try mu.checkF32(AC, .{}, 80, 43);
    try mu.checkF32(CCI, .{}, 60, 44);
    try mu.checkF32(MFI, .{}, 60, 45);
    try mu.checkF32(VORTEX, .{}, 60, 46);
}

test "simple group: BadParam" {
    var o: [4]f64 = undefined;
    const x = [_]f64{ 1, 2, 3, 4 };
    try testing.expectError(error.BadParam, mom(f64, &x, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, roc(f64, &x, &o, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, mom(f64, &x, o[0..3], .{}));
    try testing.expectError(error.BadParam, asi(f64, &x, &x, &x, &x, &o, .{ .limit_move = 0 }));
    try testing.expectError(error.BadParam, si(f64, &x, &x, &x, &x, &o, .{ .limit_move = std.math.nan(f64) }));
    try testing.expectError(error.BadParam, ao(f64, &x, &x, &o, .{ .fast = 1 }));
    try testing.expectError(error.BadParam, cci(f64, &x, &x, &x, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, vortex(f64, &x, &x, &x, &o, &o, .{ .period = 0 }));
    var ia: [4]i8 = undefined;
    var ib: [4]i8 = undefined;
    try testing.expectError(error.BadParam, fractal(f64, testing.allocator, &x, &x, &ia, &ib, .{ .left = 0 }));
    try testing.expectError(error.BadParam, ultosc(f64, &x, &x, &x, &o, .{ .period2 = 0 }));
}

test "momentum hand vectors" {
    const x = [_]f64{ 2, 4, 5, 10 };
    var o: [4]f64 = undefined;
    _ = try mom(f64, &x, &o, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 3), o[2]);
    try testing.expectEqual(@as(f64, 6), o[3]);
    _ = try roc(f64, &x, &o, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 150), o[2]);
    try testing.expectEqual(@as(f64, 150), o[3]);
    _ = try rocp(f64, &x, &o, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 1.5), o[2]);
    _ = try rocr(f64, &x, &o, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 2.5), o[2]);
    _ = try rocr100(f64, &x, &o, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 250), o[2]);
    // a zero prior value answers 0
    const z = [_]f64{ 0, 1, 2 };
    _ = try roc(f64, &z, o[0..3], .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0), o[2]);
    // BOP: (close - open) / (high - low); IBS: (close - low) / (high - low)
    const op = [_]f64{ 10, 10 };
    const hi = [_]f64{ 12, 10 };
    const lo = [_]f64{ 8, 10 };
    const cl = [_]f64{ 11, 10 };
    _ = try bop(f64, &op, &hi, &lo, &cl, o[0..2]);
    try testing.expectEqual(@as(f64, 0.25), o[0]);
    try testing.expectEqual(@as(f64, 0), o[1]);
    _ = try ibs(f64, &hi, &lo, &cl, o[0..2]);
    try testing.expectEqual(@as(f64, 0.75), o[0]);
    try testing.expectEqual(@as(f64, 0.5), o[1]);
}

test "fractal hand vector" {
    // highs 1 2 5 2 1 -> bar 2 is a swing high; lows 5 4 1 4 5 -> a swing low
    const h = [_]f64{ 1, 2, 5, 2, 1 };
    const l = [_]f64{ 5, 4, 1, 4, 5 };
    var sh: [5]i8 = undefined;
    var sl: [5]i8 = undefined;
    try testing.expectEqual(@as(usize, 4), try fractal(f64, testing.allocator, &h, &l, &sh, &sl, .{}));
    try testing.expectEqual(@as(i8, 0), sh[0]);
    try testing.expectEqual(@as(i8, 100), sh[4]);
    try testing.expectEqual(@as(i8, 100), sl[4]);
}

test "fractal: batch == streaming" {
    const gpa = testing.allocator;
    const b = try mu.Bars.make(gpa, 120, 5);
    defer b.free(gpa);
    var sh: [120]i8 = undefined;
    var sl: [120]i8 = undefined;
    const p = FractalParams{ .left = 3, .right = 2 };
    const lb = try fractal(f64, gpa, b.h, b.l, &sh, &sl, p);
    try testing.expectEqual(@as(usize, 5), lb);
    var any = false;
    const S = FractalStream(f64);
    const buf = try gpa.alloc(f64, try S.bufLen(p));
    defer gpa.free(buf);
    var s = try S.init(p, buf);
    for (0..120) |i| {
        const bar = S.Input{ .high = b.h[i], .low = b.l[i] };
        const pk = s.peek(bar);
        const got = s.update(bar);
        if (i < lb) {
            try testing.expect(got == null and pk == null and sh[i] == 0 and sl[i] == 0);
        } else {
            try testing.expectEqual(sh[i], got.?.swing_high);
            try testing.expectEqual(sl[i], pk.?.swing_low);
            if (sh[i] == 100 or sl[i] == 100) any = true;
        }
    }
    try testing.expect(any);
}
