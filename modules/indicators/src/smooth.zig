// SPDX-License-Identifier: MIT
//! SMA, EMA, WMA and the `ma` dispatcher, ported from TA-Lib 0.8.3
//! (`ta_SMA.c`, `ta_EMA.c`, `ta_WMA.c`, `ta_MA.c`; BSD-3, see NOTICE).

const std = @import("std");
const core = @import("core.zig");
const Error = core.Error;
const Nan = core.Nan;
const Seed = core.Seed;
const Unstable = core.Unstable;
const MaType = core.MaType;
const pf = core.pf;
const SliceSrc = core.SliceSrc;
const RingSrc = core.RingSrc;
const PeekSrc = core.PeekSrc;

fn nanSkip(p: anytype) bool {
    if (@hasField(@TypeOf(p), "nan")) return p.nan == .skip;
    return false;
}

// ── generic drivers over a core ─────────────────────────────────────────────

/// Batch driver for a single-input, single-output core. `Core` provides
/// `init(p)`, `lookback(p)` (after a successful init) and `step(src, x)`.
pub fn batch1(comptime T: type, comptime Core: type, in: []const T, out: []T, p: anytype) Error!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{out.len});
    var c = try Core.init(p);
    const src = SliceSrc(T){ .xs = in };
    const skip = nanSkip(p);
    for (in, out) |x, *o| {
        const xv: f64 = x;
        if (skip and core.isNan(xv)) {
            o.* = std.math.nan(T);
            continue;
        }
        o.* = if (c.step(src, xv)) |r| core.to(T, r) else std.math.nan(T);
    }
    return Core.lookback(p);
}

fn countOf(comptime Core: type, c: *const Core) usize {
    return if (@hasDecl(Core, "count")) c.count() else c.n;
}

/// Streaming wrapper for a single-input core that keeps a ring of its last
/// `Core.ringLen(p)` inputs in a caller buffer. Copies of the value share the
/// buffer; `clone` copies it.
pub fn Stream1(comptime T: type, comptime Params: type, comptime Core: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        c: Core,
        buf: []f64,
        skip: bool,
        last: ?T = null,

        /// Number of f64 the caller must provide to `init`.
        pub fn bufLen(p: Params) Error!usize {
            try Core.validate(p);
            return Core.ringLen(p);
        }
        pub fn init(p: Params, buf: []f64) Error!Self {
            const need = try bufLen(p);
            if (buf.len < need) return error.BadParam;
            return .{ .c = try Core.init(p), .buf = buf[0..need], .skip = nanSkip(p) };
        }
        /// Feed one bar; null until the lookback is satisfied.
        pub fn update(self: *Self, x: T) ?T {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return null;
            if (self.buf.len != 0) self.buf[countOf(Core, &self.c) % self.buf.len] = xv;
            const r = self.c.step(RingSrc{ .buf = self.buf }, xv) orelse return null;
            self.last = core.to(T, r);
            return self.last;
        }
        /// What `update(x)` would answer, without changing the state.
        pub fn peek(self: *const Self, x: T) ?T {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return null;
            var cc = self.c;
            const r = cc.step(PeekSrc{ .buf = self.buf, .n = countOf(Core, &self.c), .x = xv }, xv) orelse return null;
            return core.to(T, r);
        }
        /// The last value `update` produced.
        pub fn value(self: *const Self) ?T {
            return self.last;
        }
        /// A copy whose ring lives in `dst` (`dst.len >= src buf len`).
        pub fn clone(self: *const Self, dst: []f64) Error!Self {
            if (dst.len < self.buf.len) return error.BadParam;
            var r = self.*;
            r.buf = dst[0..self.buf.len];
            @memcpy(r.buf, self.buf);
            return r;
        }
    };
}

/// Streaming wrapper for a single-input core without history (copyable by
/// value, no buffer).
pub fn Rec1(comptime T: type, comptime Params: type, comptime Core: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        c: Core,
        skip: bool,
        last: ?T = null,

        pub fn init(p: Params) Error!Self {
            return .{ .c = try Core.init(p), .skip = nanSkip(p) };
        }
        pub fn update(self: *Self, x: T) ?T {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return null;
            const r = self.c.step(NoSrc{}, xv) orelse return null;
            self.last = core.to(T, r);
            return self.last;
        }
        pub fn peek(self: *const Self, x: T) ?T {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return null;
            var cc = self.c;
            const r = cc.step(NoSrc{}, xv) orelse return null;
            return core.to(T, r);
        }
        pub fn value(self: *const Self) ?T {
            return self.last;
        }
    };
}

pub const NoSrc = struct {
    pub fn at(_: NoSrc, _: usize) f64 {
        unreachable; // cores wrapped with NoSrc never read history
    }
};

// ── SMA ─────────────────────────────────────────────────────────────────────

pub const SmaParams = struct { period: usize = 30 };

pub const SmaCore = struct {
    p: usize,
    n: usize = 0,
    sum: f64 = 0.0,

    pub fn validate(p: SmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: SmaParams) usize {
        return p.period;
    }
    pub fn lookback(p: SmaParams) usize {
        return p.period - 1;
    }
    pub fn init(p: SmaParams) Error!SmaCore {
        try validate(p);
        return .{ .p = p.period };
    }
    /// TA_SMA: add the bar, read the sum, drop the oldest bar of the window.
    pub fn step(self: *SmaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        self.sum += x;
        if (n + 1 < self.p) return null;
        const t = self.sum;
        self.sum -= src.at(n + 1 - self.p);
        return t / pf(self.p);
    }
};

pub fn smaLookback(p: SmaParams) Error!usize {
    try SmaCore.validate(p);
    return SmaCore.lookback(p);
}
pub fn sma(comptime T: type, in: []const T, out: []T, p: SmaParams) Error!usize {
    return batch1(T, SmaCore, in, out, p);
}
pub fn SmaStream(comptime T: type) type {
    return Stream1(T, SmaParams, SmaCore);
}

// ── EMA ─────────────────────────────────────────────────────────────────────

pub const EmaParams = struct {
    period: usize = 30,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
    seed: Seed = .sma,
};

pub const EmaCore = struct {
    p: usize,
    beta: f64,
    k: f64,
    u: usize,
    first: bool,
    n: usize = 0,
    sum: f64 = 0.0,
    prev: f64 = 0.0,

    pub fn validate(p: EmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
    }
    pub fn unstableOf(period: usize, un: Unstable) usize {
        const c4: usize = if (period > 1) (10 * period + 1) / 2 else 0;
        const c8: usize = if (period > 1) (19 * period + 1) / 2 else 0;
        return un.get(c4, c8);
    }
    pub fn lookbackOf(period: usize, un: Unstable, seed: Seed) usize {
        const u = unstableOf(period, un);
        if (period == 1 or seed == .first) return u;
        return period - 1 + u;
    }
    pub fn lookback(p: EmaParams) usize {
        return lookbackOf(p.period, p.unstable, p.seed);
    }
    /// TA_EMA's smoothing pair: beta = (p-1)/(p+1), k = 1-beta, and beta is
    /// re-derived as 1-k when beta < 0.5 so that beta + k is exactly 1.0.
    pub fn betaK(period: usize) [2]f64 {
        const beta0 = pf(period - 1) / pf(period + 1);
        const k = 1.0 - beta0;
        const beta = if (beta0 < 0.5) 1.0 - k else beta0;
        return .{ beta, k };
    }
    pub fn initRaw(period: usize, beta: f64, k: f64, u: usize, first: bool) EmaCore {
        return .{ .p = period, .beta = beta, .k = k, .u = u, .first = first };
    }
    pub fn init(p: EmaParams) Error!EmaCore {
        try validate(p);
        const bk = betaK(p.period);
        return initRaw(p.period, bk[0], bk[1], unstableOf(p.period, p.unstable), p.seed == .first);
    }
    pub fn step(self: *EmaCore, src: anytype, x: f64) ?f64 {
        _ = src;
        const n = self.n;
        self.n += 1;
        // No smoothing at period 1: an exact copy (keeps -0.0).
        if (self.p == 1) return if (n >= self.u) x else null;
        if (self.first) {
            self.prev = if (n == 0) x else @mulAdd(f64, self.beta, self.prev, self.k * x);
            return if (n >= self.u) self.prev else null;
        }
        if (n + 1 < self.p) {
            self.sum += x;
            return null;
        }
        if (n + 1 == self.p) {
            self.sum += x;
            self.prev = self.sum / pf(self.p);
        } else {
            self.prev = @mulAdd(f64, self.beta, self.prev, self.k * x);
        }
        return if (n + 1 >= self.p + self.u) self.prev else null;
    }
};

pub fn emaLookback(p: EmaParams) Error!usize {
    try EmaCore.validate(p);
    return EmaCore.lookback(p);
}
pub fn ema(comptime T: type, in: []const T, out: []T, p: EmaParams) Error!usize {
    return batch1(T, EmaCore, in, out, p);
}
pub fn EmaStream(comptime T: type) type {
    return Rec1(T, EmaParams, EmaCore);
}

// ── WMA ─────────────────────────────────────────────────────────────────────

pub const WmaParams = struct { period: usize = 30 };

pub const WmaCore = struct {
    p: usize,
    n: usize = 0,
    sum: f64 = 0.0,
    sub: f64 = 0.0,
    trailing: f64 = 0.0,
    since: usize,
    divider: f64,

    pub fn validate(p: WmaParams) Error!void {
        try core.checkPeriod(p.period, 1);
    }
    pub fn ringLen(p: WmaParams) usize {
        return p.period;
    }
    pub fn lookback(p: WmaParams) usize {
        return p.period - 1;
    }
    pub fn init(p: WmaParams) Error!WmaCore {
        try validate(p);
        // n(n+1)/2 in double: the int product overflows int32 at n >= 46341.
        return .{ .p = p.period, .since = 8 * p.period, .divider = pf(p.period) * pf(p.period + 1) / 2.0 };
    }
    /// TA_WMA: running weighted sum plus a running plain sum; both are rebuilt
    /// from the window every 8*period outputs (TA-Lib 0.8.x re-anchor).
    pub fn step(self: *WmaCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        if (self.p == 1) return x;
        if (n + 1 < self.p) {
            self.sub += x;
            self.sum += x * pf(n + 1);
            return null;
        }
        self.sub += x;
        self.sub -= self.trailing;
        self.sum += x * pf(self.p);
        self.since -= 1;
        if (self.since == 0) {
            self.since = 8 * self.p;
            self.sub = 0.0;
            self.sum = 0.0;
            var rw: f64 = 1.0;
            var j = n + 1 - self.p;
            while (j <= n) : (j += 1) {
                const t = src.at(j);
                self.sub += t;
                self.sum += t * rw;
                rw += 1.0;
            }
        }
        self.trailing = src.at(n + 1 - self.p);
        const out = self.sum / self.divider;
        self.sum -= self.sub;
        return out;
    }
};

pub fn wmaLookback(p: WmaParams) Error!usize {
    try WmaCore.validate(p);
    return WmaCore.lookback(p);
}
pub fn wma(comptime T: type, in: []const T, out: []T, p: WmaParams) Error!usize {
    return batch1(T, WmaCore, in, out, p);
}
pub fn WmaStream(comptime T: type) type {
    return Stream1(T, WmaParams, WmaCore);
}

// ── MA dispatcher ───────────────────────────────────────────────────────────

pub const MaParams = struct {
    period: usize = 30,
    kind: MaType = .sma,
    unstable: Unstable = core.no_unstable,
    seed: Seed = .sma,
};

pub const CopyCore = struct {
    n: usize = 0,
    pub fn step(self: *CopyCore, src: anytype, x: f64) ?f64 {
        _ = src;
        self.n += 1;
        return x;
    }
};

/// A moving average of any supported type. Period 1 and `.disabled` are an
/// identity copy with lookback 0, for every type (TA_MA).
pub const MaCore = union(enum) {
    copy: CopyCore,
    sma: SmaCore,
    ema: EmaCore,
    wma: WmaCore,

    pub fn validate(p: MaParams) Error!void {
        try core.checkPeriod(p.period, 1);
        try p.unstable.check();
        if (p.period == 1) return;
        switch (p.kind) {
            .sma, .ema, .wma, .disabled => {},
            else => return error.Unsupported,
        }
    }
    pub fn isCopy(p: MaParams) bool {
        return p.period == 1 or p.kind == .disabled;
    }
    pub fn ringLen(p: MaParams) usize {
        if (isCopy(p)) return 0;
        return switch (p.kind) {
            .sma, .wma => p.period,
            else => 0,
        };
    }
    pub fn lookback(p: MaParams) usize {
        if (isCopy(p)) return 0;
        return switch (p.kind) {
            .sma, .wma => p.period - 1,
            .ema => EmaCore.lookbackOf(p.period, p.unstable, p.seed),
            else => 0,
        };
    }
    pub fn init(p: MaParams) Error!MaCore {
        try validate(p);
        if (isCopy(p)) return .{ .copy = .{} };
        return switch (p.kind) {
            .sma => .{ .sma = try SmaCore.init(.{ .period = p.period }) },
            .ema => .{ .ema = try EmaCore.init(.{ .period = p.period, .unstable = p.unstable, .seed = p.seed }) },
            .wma => .{ .wma = try WmaCore.init(.{ .period = p.period }) },
            else => unreachable, // validate() refused the rest
        };
    }
    /// Index of the bar being fed (the ring slot to write before `step`).
    pub fn count(self: *const MaCore) usize {
        return switch (self.*) {
            inline else => |*c| c.n,
        };
    }
    pub fn step(self: *MaCore, src: anytype, x: f64) ?f64 {
        return switch (self.*) {
            inline else => |*c| c.step(src, x),
        };
    }
};

pub fn maLookback(p: MaParams) Error!usize {
    try MaCore.validate(p);
    return MaCore.lookback(p);
}
pub fn ma(comptime T: type, in: []const T, out: []T, p: MaParams) Error!usize {
    return batch1(T, MaCore, in, out, p);
}
pub fn MaStream(comptime T: type) type {
    return Stream1(T, MaParams, MaCore);
}

/// One moving-average stage of a composite streaming indicator: a `MaCore`
/// with its ring (carved from the composite's buffer). `peek` mode steps a copy
/// without storing the input.
pub const Stage = struct {
    c: MaCore,
    ring: []f64,

    pub fn init(p: MaParams, buf: *[]f64) Error!Stage {
        const need = MaCore.ringLen(p);
        if (buf.len < need) return error.BadParam;
        const c = try MaCore.init(p);
        return .{ .c = c, .ring = core.carve(buf, need) };
    }
    pub fn feed(self: *Stage, x: f64, comptime peek: bool) ?f64 {
        if (peek) {
            return self.c.step(PeekSrc{ .buf = self.ring, .n = self.c.count(), .x = x }, x);
        }
        if (self.ring.len != 0) self.ring[self.c.count() % self.ring.len] = x;
        return self.c.step(RingSrc{ .buf = self.ring }, x);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const th = @import("testhelp.zig");

test "sma hand-checked vector" {
    // period 3 over 1 2 3 4 5: windows (1+2+3)/3=2, (2+3+4)/3=3, (3+4+5)/3=4.
    // The running sum goes 1,3,6 -> out 6/3, sum 6-1=5; +4=9 -> 9/3, sum 9-2=7; +5=12 -> 12/3.
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var out: [5]f64 = undefined;
    const lb = try sma(f64, &in, &out, .{ .period = 3 });
    try testing.expectEqual(@as(usize, 2), lb);
    try testing.expect(std.math.isNan(out[0]) and std.math.isNan(out[1]));
    try testing.expectEqual(@as(f64, 2), out[2]);
    try testing.expectEqual(@as(f64, 3), out[3]);
    try testing.expectEqual(@as(f64, 4), out[4]);
}

test "sma period 1 copies" {
    const in = [_]f64{ 3, -0.0, 7 };
    var out: [3]f64 = undefined;
    try testing.expectEqual(@as(usize, 0), try sma(f64, &in, &out, .{ .period = 1 }));
    try testing.expectEqual(@as(f64, 3), out[0]);
    try testing.expectEqual(@as(f64, 7), out[2]);
}

test "ema hand-checked vector" {
    // period 3: beta = 2/4 = 0.5, k = 0.5 (beta is not < 0.5, kept as divided).
    // seed = (1+2+3)/3 = 2 at bar 2; bar 3: fma(0.5, 2, 0.5*4) = 1 + 2 = 3;
    // bar 4: fma(0.5, 3, 0.5*5) = 1.5 + 2.5 = 4.
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var out: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try ema(f64, &in, &out, .{ .period = 3 }));
    try testing.expectEqual(@as(f64, 2), out[2]);
    try testing.expectEqual(@as(f64, 3), out[3]);
    try testing.expectEqual(@as(f64, 4), out[4]);
}

test "ema period 2 re-derives beta so beta + k == 1" {
    // period 2: beta = 1/3 < 0.5 so k = 1 - 1/3 and beta = 1 - k.
    const bk = EmaCore.betaK(2);
    try testing.expectEqual(@as(f64, 1.0), bk[0] + bk[1]);
    const bk26 = EmaCore.betaK(26);
    try testing.expectEqual(@as(f64, 1.0), bk26[0] + bk26[1]);
}

test "ema period 1 is an exact copy and keeps -0.0" {
    const in = [_]f64{ -0.0, 2, 3 };
    var out: [3]f64 = undefined;
    try testing.expectEqual(@as(usize, 0), try ema(f64, &in, &out, .{ .period = 1 }));
    try testing.expect(std.math.signbit(out[0]));
    try testing.expectEqual(@as(f64, 3), out[2]);
}

test "ema unstable bars delay the output; auto levels use TA-Lib's constants" {
    try testing.expectEqual(@as(usize, 2 + 5), try emaLookback(.{ .period = 3, .unstable = .{ .bars = 5 } }));
    // auto4 = (10p+1)/2 = 15 for p=3; auto8 = (19p+1)/2 = 29.
    try testing.expectEqual(@as(usize, 2 + 15), try emaLookback(.{ .period = 3, .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 2 + 29), try emaLookback(.{ .period = 3, .unstable = .auto8 }));
    // period 1: the auto formulas give 0.
    try testing.expectEqual(@as(usize, 0), try emaLookback(.{ .period = 1, .unstable = .auto8 }));
    // seed = first: the first bar is the seed, output starts after the unstable bars.
    try testing.expectEqual(@as(usize, 0), try emaLookback(.{ .period = 10, .seed = .first }));
    const in = [_]f64{ 2, 4, 6 };
    var out: [3]f64 = undefined;
    _ = try ema(f64, &in, &out, .{ .period = 3, .seed = .first });
    // beta = k = 0.5: 2, then 0.5*2 + 0.5*4 = 3, then 0.5*3 + 0.5*6 = 4.5.
    try testing.expectEqual(@as(f64, 2), out[0]);
    try testing.expectEqual(@as(f64, 3), out[1]);
    try testing.expectEqual(@as(f64, 4.5), out[2]);
}

test "ema nan skip carries the state over" {
    const nan = std.math.nan(f64);
    const in = [_]f64{ 1, 2, 3, nan, 4, 5 };
    var out: [6]f64 = undefined;
    _ = try ema(f64, &in, &out, .{ .period = 3, .nan = .skip });
    // Same as the series without the NaN bar: seed 2, then 3, then 4.
    try testing.expectEqual(@as(f64, 2), out[2]);
    try testing.expect(std.math.isNan(out[3]));
    try testing.expectEqual(@as(f64, 3), out[4]);
    try testing.expectEqual(@as(f64, 4), out[5]);
    // propagate: the NaN poisons everything after it.
    _ = try ema(f64, &in, &out, .{ .period = 3 });
    try testing.expect(std.math.isNan(out[4]) and std.math.isNan(out[5]));
}

test "wma hand-checked vector" {
    // period 3, divider 6: (1*1+2*2+3*3)/6 = 14/6, (2+6+12)/6 = 20/6, (3+8+15)/6 = 26/6.
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var out: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try wma(f64, &in, &out, .{ .period = 3 }));
    try testing.expectApproxEqAbs(@as(f64, 14.0 / 6.0), out[2], 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 20.0 / 6.0), out[3], 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 26.0 / 6.0), out[4], 1e-15);
}

test "wma re-anchor path agrees with a direct weighted sum" {
    // period 2 re-anchors every 16 outputs; check 100 bars against the definition.
    var xs: [100]f64 = undefined;
    th.walk(&xs, 7);
    var out: [100]f64 = undefined;
    _ = try wma(f64, &xs, &out, .{ .period = 2 });
    for (1..100) |i| {
        const want = (xs[i - 1] * 1 + xs[i] * 2) / 3.0;
        try testing.expectApproxEqAbs(want, out[i], 1e-9);
    }
}

test "ma dispatches and refuses what is not built" {
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var a: [5]f64 = undefined;
    var b: [5]f64 = undefined;
    _ = try ma(f64, &in, &a, .{ .period = 3, .kind = .ema });
    _ = try ema(f64, &in, &b, .{ .period = 3 });
    try th.expectSameBits(&a, &b);
    _ = try ma(f64, &in, &a, .{ .period = 3, .kind = .wma });
    _ = try wma(f64, &in, &b, .{ .period = 3 });
    try th.expectSameBits(&a, &b);
    try testing.expectError(error.Unsupported, ma(f64, &in, &a, .{ .period = 3, .kind = .kama }));
    try testing.expectError(error.Unsupported, maLookback(.{ .period = 3, .kind = .t3 }));
    // period 1 and .disabled copy, for every type, even an unsupported one.
    _ = try ma(f64, &in, &a, .{ .period = 1, .kind = .kama });
    try th.expectSameBits(&a, &in);
    try testing.expectEqual(@as(usize, 0), try maLookback(.{ .period = 9, .kind = .disabled }));
}

test "smooth: BadParam on out-of-range parameters and lengths" {
    const in = [_]f64{ 1, 2, 3 };
    var out: [3]f64 = undefined;
    var short: [2]f64 = undefined;
    try testing.expectError(error.BadParam, sma(f64, &in, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, sma(f64, &in, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, ema(f64, &in, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, ema(f64, &in, &out, .{ .period = 2, .unstable = .{ .bars = (1 << 30) + 1 } }));
    try testing.expectError(error.BadParam, wma(f64, &in, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, ma(f64, &in, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, sma(f64, &in, &short, .{ .period = 2 }));
    _ = try sma(f64, &in, &out, .{ .period = 100000 }); // in range, all NaN
}

test "smooth: batch == streaming, lookback == leading NaN, f32 path" {
    var xs: [300]f64 = undefined;
    th.walk(&xs, 11);
    try th.checkOne(SmaParams, SmaStream, sma, smaLookback, &xs, .{ .period = 14 });
    try th.checkOne(WmaParams, WmaStream, wma, wmaLookback, &xs, .{ .period = 14 });
    try th.checkOne(WmaParams, WmaStream, wma, wmaLookback, &xs, .{ .period = 3 }); // crosses the re-anchor
    try th.checkOne(MaParams, MaStream, ma, maLookback, &xs, .{ .period = 9, .kind = .wma });
    try th.checkRec(EmaParams, EmaStream, ema, emaLookback, &xs, .{ .period = 12 });
    try th.checkRec(EmaParams, EmaStream, ema, emaLookback, &xs, .{ .period = 12, .unstable = .{ .bars = 7 } });
    try th.checkRec(EmaParams, EmaStream, ema, emaLookback, &xs, .{ .period = 12, .unstable = .auto4 });
    try th.checkRec(EmaParams, EmaStream, ema, emaLookback, &xs, .{ .period = 12, .seed = .first });
    try th.checkRec(EmaParams, EmaStream, ema, emaLookback, &xs, .{ .period = 1 });
    try th.checkRec(EmaParams, EmaStream, ema, emaLookback, &xs, .{ .period = 2 });
    // f32 path runs and rounds the f64 result once.
    var f32s: [300]f32 = undefined;
    for (&f32s, xs) |*d, s| d.* = @floatCast(s);
    var o32: [300]f32 = undefined;
    const lb = try ema(f32, &f32s, &o32, .{ .period = 12 });
    try testing.expectEqual(@as(usize, 11), lb);
    try testing.expect(std.math.isNan(o32[10]) and !std.math.isNan(o32[11]));
    var o64: [300]f64 = undefined;
    var back: [300]f64 = undefined;
    for (&back, f32s) |*d, s| d.* = s;
    _ = try ema(f64, &back, &o64, .{ .period = 12 });
    for (o32[11..], o64[11..]) |a, b| try testing.expectEqual(@as(f32, @floatCast(b)), a);
}

test "stream peek does not change the state, value reports the last output" {
    var xs: [40]f64 = undefined;
    th.walk(&xs, 3);
    var buf: [5]f64 = undefined;
    var s = try SmaStream(f64).init(.{ .period = 5 }, &buf);
    var e = try EmaStream(f64).init(.{ .period = 5 });
    for (xs) |x| {
        const ps = s.peek(x);
        const pe = e.peek(x);
        const us = s.update(x);
        const ue = e.update(x);
        try testing.expectEqual(ps, us);
        try testing.expectEqual(pe, ue);
    }
    try testing.expectEqual(s.update(1.0), s.value());
    // copy by value (EMA) continues independently
    var e2 = e;
    _ = e2.update(100.0);
    try testing.expect(e.value().? != e2.value().?);
    // clone of a ring stream owns its buffer
    var buf2: [5]f64 = undefined;
    var s2 = try s.clone(&buf2);
    _ = s2.update(100.0);
    try testing.expect(s.value().? != s2.value().?);
    try testing.expectError(error.BadParam, SmaStream(f64).init(.{ .period = 5 }, buf[0..4]));
}
