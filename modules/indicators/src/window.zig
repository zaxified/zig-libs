// SPDX-License-Identifier: MIT
//! Rolling SUM, MAX and MIN over a window, ported from TA-Lib 0.8.3
//! (`ta_SUM.c`, `ta_MAX.c`, `ta_MIN.c`; BSD-3, see NOTICE). The window extreme
//! core is also what STOCH reads its highest high and lowest low from.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const Error = core.Error;
const pf = core.pf;
const th = @import("testhelp.zig");

pub const WindowParams = struct { period: usize = 30 };
pub const SumParams = WindowParams;
pub const MaxParams = WindowParams;
pub const MinParams = WindowParams;

// ── SUM ─────────────────────────────────────────────────────────────────────

pub const SumCore = struct {
    p: usize,
    n: usize = 0,
    sum: f64 = 0.0,

    pub fn validate(p: WindowParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: WindowParams) usize {
        return p.period;
    }
    pub fn lookback(p: WindowParams) usize {
        return p.period - 1;
    }
    pub fn init(p: WindowParams) Error!SumCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *SumCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        self.sum += x;
        if (n + 1 < self.p) return null;
        const t = self.sum;
        self.sum -= src.at(n + 1 - self.p);
        return t;
    }
};

pub fn sumLookback(p: SumParams) Error!usize {
    try SumCore.validate(p);
    return SumCore.lookback(p);
}
pub fn sum(comptime T: type, in: []const T, out: []T, p: SumParams) Error!usize {
    return smooth.batch1(T, SumCore, in, out, p);
}
pub fn SumStream(comptime T: type) type {
    return smooth.Stream1(T, SumParams, SumCore);
}

// ── MAX / MIN ───────────────────────────────────────────────────────────────

/// The extreme of the last `period` bars. Tracks the index of the current
/// extreme and rescans the window only when it leaves it (TA_MAX / TA_MIN's
/// classic algorithm; ties keep the newest bar).
pub fn ExtCore(comptime is_max: bool) type {
    return struct {
        const Self = @This();
        p: usize,
        n: usize = 0,
        idx: ?usize = null,
        val: f64 = 0.0,

        pub fn validate(p: WindowParams) Error!void {
            try core.checkPeriod(p.period, 2);
        }
        pub fn ringLen(p: WindowParams) usize {
            return p.period;
        }
        pub fn lookback(p: WindowParams) usize {
            return p.period - 1;
        }
        pub fn init(p: WindowParams) Error!Self {
            try validate(p);
            return .{ .p = p.period };
        }
        /// The window-extreme update shared with STOCH; `period >= 1`.
        pub fn initAny(period: usize) Self {
            return .{ .p = period };
        }
        inline fn better(a: f64, b: f64) bool {
            return if (is_max) a > b else a < b;
        }
        inline fn betterEq(a: f64, b: f64) bool {
            return if (is_max) a >= b else a <= b;
        }
        pub fn step(self: *Self, src: anytype, x: f64) ?f64 {
            const n = self.n;
            self.n += 1;
            if (n + 1 < self.p) return null;
            const trailing = n + 1 - self.p;
            if (self.idx == null or self.idx.? < trailing) {
                var idx = trailing;
                var val = src.at(trailing);
                var i = trailing;
                while (i < n) {
                    i += 1;
                    const t = src.at(i);
                    if (better(t, val)) {
                        idx = i;
                        val = t;
                    }
                }
                self.idx = idx;
                self.val = val;
            } else if (betterEq(x, self.val)) {
                self.idx = n;
                self.val = x;
            }
            return self.val;
        }
        /// `step` over the bars `n..` of a slice once the output has started
        /// (`n + 1 >= p`), as one inlined update per bar: the same rescan and the
        /// same tie rule, the index kept as `idx + 1` (0 = none) in a register.
        pub const Run = struct {
            p: usize,
            idx1: usize,
            val: f64,
            pub fn of(c: *const Self) Run {
                return .{ .p = c.p, .idx1 = if (c.idx) |v| v + 1 else 0, .val = c.val };
            }
            pub fn store(r: Run, c: *Self, n: usize) void {
                c.n = n;
                c.idx = if (r.idx1 == 0) null else r.idx1 - 1;
                c.val = r.val;
            }
            pub inline fn bar(r: *Run, comptime T: type, xs: []const T, n: usize) f64 {
                const trailing = n + 1 - r.p;
                const x: f64 = xs[n];
                if (r.idx1 <= trailing) {
                    var idx = trailing;
                    var val: f64 = xs[trailing];
                    var i = trailing;
                    while (i < n) {
                        i += 1;
                        const t: f64 = xs[i];
                        if (better(t, val)) {
                            idx = i;
                            val = t;
                        }
                    }
                    r.idx1 = idx + 1;
                    r.val = val;
                } else if (betterEq(x, r.val)) {
                    r.idx1 = n + 1;
                    r.val = x;
                }
                return r.val;
            }
        };
    };
}

pub const MaxCore = ExtCore(true);
pub const MinCore = ExtCore(false);

/// TA-Lib 0.8.3's batch MAX / MIN: a Van Herk / Gil-Werman block scan (ta_MAX.c), reproduced
/// operation for operation, because it decides ties differently from the streaming automaton
/// of `ExtCore`: only the sign of an equal pair 0.0 / -0.0 (and where a NaN shows) can tell them apart.
/// Blocks are `period` bars; the output at a block's last bar is the block's suffix extremum
/// (scanned backward, a strict comparison, so the LATER of equal values stays); the other outputs
/// combine the suffix extremum of the older block's remainder with the running prefix extremum of the
/// newer block (scanned forward, strict, the EARLIEST stays), the suffix side winning a tie. TA-Lib keeps
/// two scratch arrays; here the suffix extrema of a block are parked in the output slots that block is
/// about to fill (`out[b + period - 1 + m]`), each read once before it is overwritten, so nothing is allocated.
/// `out` must not alias `in`. The streaming types still run `ExtCore` (TA-Lib's streaming tier does too).
pub fn extBatch(comptime T: type, comptime is_max: bool, in: []const T, out: []T, p: WindowParams) Error!usize {
    core.checkFloat(T);
    try core.checkPeriod(p.period, 2);
    try core.checkLen(in.len, &.{out.len});
    const per = p.period;
    const n = in.len;
    const lb = per - 1;
    const nan = std.math.nan(T);
    for (out[0..@min(lb, n)]) |*o| o.* = nan;
    var b: usize = 0; // block start; the block is [b, b + per - 1]
    while (b + per <= n) : (b += per) {
        const first = b + per - 1; // output slot of suf[0]
        var ext = in[first];
        if (first + per - 1 < n) out[first + per - 1] = ext;
        var m = per - 1;
        while (m > 0) {
            m -= 1;
            const t = in[b + m];
            if (if (is_max) t > ext else t < ext) ext = t;
            if (first + m < n) out[first + m] = ext;
        }
        // out[first] now holds suf[0]: the block's own output. The rest combine with the next block's prefix.
        const next = b + per;
        if (next >= n) break;
        const avail = @min(per - 1, n - next);
        var pre = in[next];
        var j: usize = 1;
        while (j <= avail) : (j += 1) {
            if (j > 1) {
                const t = in[next + j - 1];
                if (if (is_max) t > pre else t < pre) pre = t;
            }
            const slot = &out[first + j];
            if (if (is_max) pre > slot.* else pre < slot.*) slot.* = pre;
        }
    }
    return lb;
}

pub fn maxLookback(p: MaxParams) Error!usize {
    try MaxCore.validate(p);
    return MaxCore.lookback(p);
}
pub fn max(comptime T: type, in: []const T, out: []T, p: MaxParams) Error!usize {
    return extBatch(T, true, in, out, p);
}
pub fn MaxStream(comptime T: type) type {
    return smooth.Stream1(T, MaxParams, MaxCore);
}
pub fn minLookback(p: MinParams) Error!usize {
    try MinCore.validate(p);
    return MinCore.lookback(p);
}
pub fn min(comptime T: type, in: []const T, out: []T, p: MinParams) Error!usize {
    return extBatch(T, false, in, out, p);
}
pub fn MinStream(comptime T: type) type {
    return smooth.Stream1(T, MinParams, MinCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "sum hand-checked vector" {
    // period 3 over 1 2 3 4 5: 6, 9, 12 (running sum 1,3,6 -> 6; 6-1+4 = 9; 9-2+5 = 12).
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var out: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try sum(f64, &in, &out, .{ .period = 3 }));
    try testing.expect(std.math.isNan(out[1]));
    try testing.expectEqual(@as(f64, 6), out[2]);
    try testing.expectEqual(@as(f64, 9), out[3]);
    try testing.expectEqual(@as(f64, 12), out[4]);
}

test "max and min hand-checked vector" {
    // period 3 over 5 1 4 2 8 3: windows (5,1,4) (1,4,2) (4,2,8) (2,8,3).
    // The max of the first window is 5 at bar 0; at bar 3 it has left, so the
    // window is rescanned: (1,4,2) -> 4; bar 4: 8 >= 4 -> 8; bar 5: 8 is still inside -> 8.
    const in = [_]f64{ 5, 1, 4, 2, 8, 3 };
    var hi: [6]f64 = undefined;
    var lo: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try max(f64, &in, &hi, .{ .period = 3 }));
    try testing.expectEqual(@as(usize, 2), try min(f64, &in, &lo, .{ .period = 3 }));
    try testing.expectEqualSlices(f64, &.{ 5, 4, 8, 8 }, hi[2..]);
    try testing.expectEqualSlices(f64, &.{ 1, 1, 2, 2 }, lo[2..]);
}

test "window: BadParam, period 2 minimum" {
    const in = [_]f64{ 1, 2, 3 };
    var out: [3]f64 = undefined;
    try testing.expectError(error.BadParam, sum(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, max(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, min(f64, &in, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, sumLookback(.{ .period = 0 }));
    try testing.expectError(error.BadParam, max(f64, &in, out[0..2], .{ .period = 2 }));
    try testing.expectEqual(@as(usize, 1), try maxLookback(.{ .period = 2 }));
}

test "window: batch == streaming, lookback == leading NaN, matches naive scan, f32" {
    var xs: [400]f64 = undefined;
    th.walk(&xs, 21);
    try th.checkOne(SumParams, SumStream, sum, sumLookback, &xs, .{ .period = 10 });
    try th.checkOne(MaxParams, MaxStream, max, maxLookback, &xs, .{ .period = 10 });
    try th.checkOne(MinParams, MinStream, min, minLookback, &xs, .{ .period = 10 });
    try th.checkOne(MaxParams, MaxStream, max, maxLookback, &xs, .{ .period = 2 });
    var hi: [400]f64 = undefined;
    var lo: [400]f64 = undefined;
    _ = try max(f64, &xs, &hi, .{ .period = 7 });
    _ = try min(f64, &xs, &lo, .{ .period = 7 });
    for (6..400) |i| {
        var h = xs[i];
        var l = xs[i];
        for (xs[i - 6 .. i + 1]) |v| {
            h = @max(h, v);
            l = @min(l, v);
        }
        try testing.expectEqual(h, hi[i]);
        try testing.expectEqual(l, lo[i]);
    }
    var f32s: [50]f32 = undefined;
    for (&f32s, xs[0..50]) |*d, s| d.* = @floatCast(s);
    var o32: [50]f32 = undefined;
    try testing.expectEqual(@as(usize, 4), try sum(f32, &f32s, &o32, .{ .period = 5 }));
    try testing.expectEqual(@as(usize, 4), try max(f32, &f32s, &o32, .{ .period = 5 }));
    try testing.expectEqual(@as(usize, 4), try min(f32, &f32s, &o32, .{ .period = 5 }));
}

test "sum: a NaN poisons the running sum" {
    const nan = std.math.nan(f64);
    const in = [_]f64{ 1, 2, nan, 4, 5, 6 };
    var out: [6]f64 = undefined;
    _ = try sum(f64, &in, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 3), out[1]);
    for (out[2..]) |v| try testing.expect(std.math.isNan(v));
}

test "max/min with NaN: a NaN never wins a comparison; the batch block scan and the streaming automaton show it at different bars" {
    const nan = std.math.nan(f64);
    // max, period 3 over 1 2 NaN 0 0 0, BATCH (TA-Lib's block scan, by reading of ta_MAX.c; the oracle has no NaN inputs):
    //  block [1 2 NaN] scanned backward starts at NaN and nothing beats it: out[2] NaN, and the
    //  suffix NaN stays in the combined outputs 3 and 4; block [0 0 0] gives out[5] = 0.
    const a = [_]f64{ 1, 2, nan, 0, 0, 0 };
    var out: [6]f64 = undefined;
    _ = try max(f64, &a, &out, .{ .period = 3 });
    try testing.expect(std.math.isNan(out[2]));
    try testing.expect(std.math.isNan(out[3]));
    try testing.expect(std.math.isNan(out[4]));
    try testing.expectEqual(@as(f64, 0), out[5]);
    // min, period 3 over 5 4 NaN 9 9 9: NaN, NaN, NaN, 9
    const b = [_]f64{ 5, 4, nan, 9, 9, 9 };
    _ = try min(f64, &b, &out, .{ .period = 3 });
    try testing.expect(std.math.isNan(out[2]));
    try testing.expect(std.math.isNan(out[3]));
    try testing.expect(std.math.isNan(out[4]));
    try testing.expectEqual(@as(f64, 9), out[5]);
    // STREAMING (the automaton): max over 1 2 NaN 0 0 0:
    //  bar 2 rescan (1,2,NaN): 1 -> 2, NaN > 2 false -> 2; bar 3: 0 >= 2 false -> 2;
    //  bar 4: the max (bar 1) left, rescan (NaN,0,0): starts at NaN, 0 > NaN false -> NaN;
    //  bar 5: NaN's index left, rescan (0,0,0) -> 0.
    var sbuf: [3]f64 = undefined;
    var s = try MaxStream(f64).init(.{ .period = 3 }, &sbuf);
    var got: [6]?f64 = undefined;
    for (a, &got) |x, *g| g.* = s.update(x);
    try testing.expectEqual(@as(f64, 2), got[2].?);
    try testing.expectEqual(@as(f64, 2), got[3].?);
    try testing.expect(std.math.isNan(got[4].?));
    try testing.expectEqual(@as(f64, 0), got[5].?);
}

test "max/min batch is TA-Lib's block scan; the streaming automaton decides ties differently (0.0 vs -0.0)" {
    const nz = -0.0;
    // Batch, max, period 3 over -2 -0 -1 +0 -0 (block [0..2], then the next block's prefix):
    //  out[2] = suffix max of the block, the later of equals stays: -0 (from -2, -0, -1)
    //  out[3] = combine(suf[1] = -0, pre = +0): the prefix must be strictly greater to win: -0
    //  out[4] = combine(suf[2] = -1, pre = max(+0, -0) with the earlier staying = +0): +0
    const a = [_]f64{ -2, nz, -1, 0.0, nz };
    var out: [5]f64 = undefined;
    _ = try max(f64, &a, &out, .{ .period = 3 });
    try testing.expect(std.math.signbit(out[2]) and out[2] == 0);
    try testing.expect(std.math.signbit(out[3]) and out[3] == 0);
    try testing.expect(!std.math.signbit(out[4]) and out[4] == 0);
    // Batch, min, period 3 over 2 +0 1 -0 +0: out[2] = suf[0] = min(2, +0, 1) = +0;
    //  out[3] = combine(suf[1] = +0 (min of +0, 1), pre = -0): -0 < +0 is false: +0; out[4] = combine(suf[2] = 1, pre = -0 (the earlier of -0, +0)): -0.
    const b = [_]f64{ 2, 0.0, 1, nz, 0.0 };
    _ = try min(f64, &b, &out, .{ .period = 3 });
    try testing.expect(!std.math.signbit(out[2]) and out[2] == 0);
    try testing.expect(!std.math.signbit(out[3]) and out[3] == 0);
    try testing.expect(std.math.signbit(out[4]) and out[4] == 0);
    // Streaming: a rescan keeps the OLDEST of equal values, an incremental update the NEWEST.
    //  max, period 3 over -2 -0 -1 +0 -0: bar 2 rescan -> -0; bar 3: +0 >= -0 -> +0; bar 4: -0 >= +0 -> -0.
    var sbuf: [3]f64 = undefined;
    var s = try MaxStream(f64).init(.{ .period = 3 }, &sbuf);
    var got: [5]?f64 = undefined;
    for (a, &got) |x, *g| g.* = s.update(x);
    try testing.expect(std.math.signbit(got[2].?));
    try testing.expect(!std.math.signbit(got[3].?));
    try testing.expect(std.math.signbit(got[4].?));
}
