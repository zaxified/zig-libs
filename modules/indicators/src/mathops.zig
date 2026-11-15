// SPDX-License-Identifier: MIT
//! Math operators ported from TA-Lib 0.8.3 (`ta_ADD.c`, `ta_SUB.c`,
//! `ta_MULT.c`, `ta_DIV.c`, `ta_CUMSUM.c`, `ta_MINMAX.c`, `ta_MAXINDEX.c`,
//! `ta_MININDEX.c`, `ta_MINMAXINDEX.c`; BSD-3, see NOTICE). The vector
//! operators are plain IEEE arithmetic (division by zero is inf / NaN, as in
//! C). The window functions share the extremum automaton of `window.zig`
//! (MINMAX) or an index-tracking twin (MAXINDEX & co).
//!
//! The index outputs are absolute positions in the input slice (TA-Lib's
//! `outInteger`); the lead of an index output is `no_index` (`maxInt(usize)`).

const std = @import("std");
const core = @import("core.zig");
const window = @import("window.zig");
const K = @import("vs_kit.zig");
const th = @import("testhelp.zig");
const Error = core.Error;

pub const no_index = K.no_index;

// ── vector arithmetic ───────────────────────────────────────────────────────

fn addFn(b: K.Xy(f64)) f64 {
    return b.x + b.y;
}
fn subFn(b: K.Xy(f64)) f64 {
    return b.x - b.y;
}
fn multFn(b: K.Xy(f64)) f64 {
    return b.x * b.y;
}
fn divFn(b: K.Xy(f64)) f64 {
    return b.x / b.y;
}
pub const AddCore = K.PureCore(K.Xy, addFn);
pub const SubCore = K.PureCore(K.Xy, subFn);
pub const MultCore = K.PureCore(K.Xy, multFn);
pub const DivCore = K.PureCore(K.Xy, divFn);

pub fn addLookback() usize {
    return 0;
}
pub fn add(comptime T: type, in0: []const T, in1: []const T, out: []T) Error!usize {
    return K.batch(T, AddCore, .{}, .{ .x = in0, .y = in1 }, .{out});
}
pub fn AddStream(comptime T: type) type {
    return K.Stream(T, AddCore);
}
pub fn subLookback() usize {
    return 0;
}
pub fn sub(comptime T: type, in0: []const T, in1: []const T, out: []T) Error!usize {
    return K.batch(T, SubCore, .{}, .{ .x = in0, .y = in1 }, .{out});
}
pub fn SubStream(comptime T: type) type {
    return K.Stream(T, SubCore);
}
pub fn multLookback() usize {
    return 0;
}
pub fn mult(comptime T: type, in0: []const T, in1: []const T, out: []T) Error!usize {
    return K.batch(T, MultCore, .{}, .{ .x = in0, .y = in1 }, .{out});
}
pub fn MultStream(comptime T: type) type {
    return K.Stream(T, MultCore);
}
pub fn divLookback() usize {
    return 0;
}
pub fn div(comptime T: type, in0: []const T, in1: []const T, out: []T) Error!usize {
    return K.batch(T, DivCore, .{}, .{ .x = in0, .y = in1 }, .{out});
}
pub fn DivStream(comptime T: type) type {
    return K.Stream(T, DivCore);
}

/// Running total from the first bar.
pub const CumsumCore = struct {
    pub const In = K.X(f64);
    pub const Out = f64;
    pub const Params = struct {};
    pub const windowed = false;
    pub fn Inputs(comptime T: type) type {
        return K.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }
    n: usize = 0,
    total: f64 = 0.0,
    pub fn validate(_: Params) Error!void {}
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn lookback(_: Params) usize {
        return 0;
    }
    pub fn init(_: Params) Error!CumsumCore {
        return .{};
    }
    pub fn step(self: *CumsumCore, _: anytype, b: In) ?f64 {
        self.n += 1;
        self.total += b.x;
        return self.total;
    }
};
pub fn cumsumLookback() usize {
    return 0;
}
pub fn cumsum(comptime T: type, in: []const T, out: []T) Error!usize {
    return K.batch(T, CumsumCore, .{}, .{ .x = in }, .{out});
}
pub fn CumsumStream(comptime T: type) type {
    return K.SingleStream(T, CumsumCore);
}

// ── MINMAX ──────────────────────────────────────────────────────────────────

pub const MinmaxParams = window.WindowParams;
pub const MaxindexParams = window.WindowParams;
pub const MinindexParams = window.WindowParams;
pub const MinmaxindexParams = window.WindowParams;

pub fn MinmaxOut(comptime T: type) type {
    return struct { min: T, max: T };
}

/// Lowest and highest value of the last `period` bars (the extremum automaton
/// of MAX / MIN: rescan on expiry, incremental update otherwise; TA-Lib's streaming
/// tier runs the same). The batch function `minmax` runs TA-Lib's block scan instead,
/// and the two differ only in the sign of an equal pair 0.0 / -0.0.
pub const MinmaxCore = struct {
    pub const In = K.X(f64);
    pub const Out = MinmaxOut(f64);
    pub const Params = MinmaxParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return MinmaxOut(T);
    }
    n: usize = 0,
    lo: window.MinCore,
    hi: window.MaxCore,
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params) Error!MinmaxCore {
        try validate(p);
        return .{ .lo = window.MinCore.initAny(p.period), .hi = window.MaxCore.initAny(p.period) };
    }
    pub fn step(self: *MinmaxCore, src: anytype, b: In) ?Out {
        self.n += 1;
        const xs = K.field(src, "x");
        const mx = self.hi.step(xs, b.x);
        const mn = self.lo.step(xs, b.x);
        if (mx == null or mn == null) return null;
        return .{ .min = mn.?, .max = mx.? };
    }
};
pub fn minmaxLookback(p: MinmaxParams) Error!usize {
    try MinmaxCore.validate(p);
    return MinmaxCore.lookback(p);
}
pub fn minmax(comptime T: type, in: []const T, out_min: []T, out_max: []T, p: MinmaxParams) Error!usize {
    // TA-Lib's batch block scan (`window.extBatch`), not the automaton the stream runs: see the note on MinmaxCore.
    try MinmaxCore.validate(p);
    try core.checkLen(in.len, &.{ out_min.len, out_max.len });
    _ = try window.extBatch(T, false, in, out_min, p);
    return window.extBatch(T, true, in, out_max, p);
}
pub fn MinmaxStream(comptime T: type) type {
    return K.SingleStream(T, MinmaxCore);
}

/// Index (absolute bar number) of the extremum of the last `period` bars; a
/// tie names the newest bar.
fn ExtIdx(comptime is_max: bool) type {
    return struct {
        const Self = @This();
        p: usize,
        n: usize = 0,
        idx: ?usize = null,
        val: f64 = 0.0,
        fn better(a: f64, b: f64) bool {
            return if (is_max) a > b else a < b;
        }
        fn betterEq(a: f64, b: f64) bool {
            return if (is_max) a >= b else a <= b;
        }
        fn step(self: *Self, src: anytype, x: f64) ?usize {
            const n = self.n;
            self.n += 1;
            if (n + 1 < self.p) return null;
            const trailing = n + 1 - self.p;
            if (self.idx == null or self.idx.? < trailing) {
                // newest bar first, only a strictly better bar replaces it
                var idx = n;
                var val = x;
                var i = n;
                while (i > trailing) {
                    i -= 1;
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
            return self.idx;
        }
    };
}

pub fn IdxCore(comptime is_max: bool) type {
    return struct {
        const Self = @This();
        pub const In = K.X(f64);
        pub const Out = usize;
        pub const Params = window.WindowParams;
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return K.X(T);
        }
        pub fn Outputs(comptime _: type) type {
            return usize;
        }
        n: usize = 0,
        e: ExtIdx(is_max),
        pub fn validate(p: Params) Error!void {
            try core.checkPeriod(p.period, 2);
        }
        pub fn ringLen(p: Params) usize {
            return p.period;
        }
        pub fn lookback(p: Params) usize {
            return p.period - 1;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .e = .{ .p = p.period } };
        }
        pub fn step(self: *Self, src: anytype, b: In) ?usize {
            self.n += 1;
            return self.e.step(K.field(src, "x"), b.x);
        }
    };
}
pub const MaxindexCore = IdxCore(true);
pub const MinindexCore = IdxCore(false);

pub fn maxindexLookback(p: MaxindexParams) Error!usize {
    try MaxindexCore.validate(p);
    return MaxindexCore.lookback(p);
}
pub fn maxindex(comptime T: type, in: []const T, out: []usize, p: MaxindexParams) Error!usize {
    return K.batch(T, MaxindexCore, p, .{ .x = in }, .{out});
}
pub fn MaxindexStream(comptime T: type) type {
    return K.SingleStream(T, MaxindexCore);
}
pub fn minindexLookback(p: MinindexParams) Error!usize {
    try MinindexCore.validate(p);
    return MinindexCore.lookback(p);
}
pub fn minindex(comptime T: type, in: []const T, out: []usize, p: MinindexParams) Error!usize {
    return K.batch(T, MinindexCore, p, .{ .x = in }, .{out});
}
pub fn MinindexStream(comptime T: type) type {
    return K.SingleStream(T, MinindexCore);
}

pub const MinmaxindexOut = struct { min: usize, max: usize };

pub const MinmaxindexCore = struct {
    pub const In = K.X(f64);
    pub const Out = MinmaxindexOut;
    pub const Params = MinmaxindexParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return K.X(T);
    }
    pub fn Outputs(comptime _: type) type {
        return MinmaxindexOut;
    }
    n: usize = 0,
    lo: ExtIdx(false),
    hi: ExtIdx(true),
    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn init(p: Params) Error!MinmaxindexCore {
        try validate(p);
        return .{ .lo = .{ .p = p.period }, .hi = .{ .p = p.period } };
    }
    pub fn step(self: *MinmaxindexCore, src: anytype, b: In) ?Out {
        self.n += 1;
        const xs = K.field(src, "x");
        const mx = self.hi.step(xs, b.x);
        const mn = self.lo.step(xs, b.x);
        if (mx == null or mn == null) return null;
        return .{ .min = mn.?, .max = mx.? };
    }
};
pub fn minmaxindexLookback(p: MinmaxindexParams) Error!usize {
    try MinmaxindexCore.validate(p);
    return MinmaxindexCore.lookback(p);
}
pub fn minmaxindex(comptime T: type, in: []const T, out_min: []usize, out_max: []usize, p: MinmaxindexParams) Error!usize {
    return K.batch(T, MinmaxindexCore, p, .{ .x = in }, .{ out_min, out_max });
}
pub fn MinmaxindexStream(comptime T: type) type {
    return K.SingleStream(T, MinmaxindexCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "vector arithmetic and cumsum" {
    var out: [3]f64 = undefined;
    _ = try add(f64, &.{ 1, 2, 3 }, &.{ 3, 4, 5 }, &out);
    try testing.expectEqualSlices(f64, &.{ 4, 6, 8 }, &out);
    _ = try sub(f64, &.{ 1, 2, 3 }, &.{ 3, 4, 5 }, &out);
    try testing.expectEqualSlices(f64, &.{ -2, -2, -2 }, &out);
    _ = try mult(f64, &.{ 1, 2, 3 }, &.{ 3, 4, 5 }, &out);
    try testing.expectEqualSlices(f64, &.{ 3, 8, 15 }, &out);
    _ = try div(f64, &.{ 1, 6, 0 }, &.{ 4, 3, 0 }, &out);
    try testing.expectEqual(@as(f64, 0.25), out[0]);
    try testing.expectEqual(@as(f64, 2), out[1]);
    try testing.expect(std.math.isNan(out[2]));
    _ = try div(f64, &.{1}, &.{0}, out[0..1]);
    try testing.expect(std.math.isInf(out[0]));
    try testing.expectEqual(@as(usize, 0), try cumsum(f64, &.{ 1, 2, 3 }, &out));
    try testing.expectEqualSlices(f64, &.{ 1, 3, 6 }, &out);
    try testing.expectError(error.BadParam, add(f64, &.{ 1, 2 }, &.{1}, out[0..2]));
    try testing.expectError(error.BadParam, cumsum(f64, &.{ 1, 2 }, out[0..1]));
}

test "minmax, maxindex, minindex, minmaxindex: hand-checked" {
    const in = [_]f64{ 5, 1, 4, 2, 8, 3 };
    var lo: [6]f64 = undefined;
    var hi: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try minmax(f64, &in, &lo, &hi, .{ .period = 3 }));
    try testing.expectEqualSlices(f64, &.{ 1, 1, 2, 2 }, lo[2..]);
    try testing.expectEqualSlices(f64, &.{ 5, 4, 8, 8 }, hi[2..]);
    try testing.expect(std.math.isNan(lo[1]) and std.math.isNan(hi[0]));
    var imax: [6]usize = undefined;
    var imin: [6]usize = undefined;
    try testing.expectEqual(@as(usize, 2), try maxindex(f64, &in, &imax, .{ .period = 3 }));
    try testing.expectEqual(no_index, imax[1]);
    try testing.expectEqualSlices(usize, &.{ 0, 2, 4, 4 }, imax[2..]);
    _ = try minindex(f64, &in, &imin, .{ .period = 3 });
    try testing.expectEqualSlices(usize, &.{ 1, 1, 3, 3 }, imin[2..]);
    var a: [6]usize = undefined;
    var b: [6]usize = undefined;
    _ = try minmaxindex(f64, &in, &a, &b, .{ .period = 3 });
    try testing.expectEqualSlices(usize, &.{ 1, 1, 3, 3 }, a[2..]);
    try testing.expectEqualSlices(usize, &.{ 0, 2, 4, 4 }, b[2..]);
    // a tie names the newest bar
    _ = try maxindex(f64, &.{ 3, 3, 3 }, imax[0..3], .{ .period = 2 });
    try testing.expectEqualSlices(usize, &.{ 1, 2 }, imax[1..3]);
    _ = try minindex(f64, &.{ 3, 3, 3 }, imin[0..3], .{ .period = 2 });
    try testing.expectEqualSlices(usize, &.{ 1, 2 }, imin[1..3]);
}

test "mathops: BadParam edges" {
    var o: [4]f64 = undefined;
    var u: [4]usize = undefined;
    const z = [_]f64{ 1, 2, 3, 4 };
    try testing.expectError(error.BadParam, minmax(f64, &z, &o, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, maxindex(f64, &z, &u, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, minindex(f64, &z, u[0..3], .{ .period = 2 }));
    try testing.expectError(error.BadParam, minmaxindex(f64, &z, &u, &u, .{ .period = 0 }));
    try testing.expectEqual(@as(usize, 29), try minmaxLookback(.{}));
}

test "mathops: batch == streaming" {
    var xs: [300]f64 = undefined;
    var ys: [300]f64 = undefined;
    th.walk(&xs, 41);
    th.walk(&ys, 42);
    try K.checkCore(AddCore, .{}, .{ .x = &xs, .y = &ys });
    try K.checkCore(DivCore, .{}, .{ .x = &xs, .y = &ys });
    try K.checkCore(CumsumCore, .{}, .{ .x = &xs });
    inline for (.{ 2, 7, 30 }) |per| {
        try K.checkCore(MinmaxCore, .{ .period = per }, .{ .x = &xs });
        // index cores: stream against batch by hand
        var imax: [300]usize = undefined;
        var imin: [300]usize = undefined;
        var jmin: [300]usize = undefined;
        var jmax: [300]usize = undefined;
        const lb = try maxindex(f64, &xs, &imax, .{ .period = per });
        _ = try minindex(f64, &xs, &imin, .{ .period = per });
        _ = try minmaxindex(f64, &xs, &jmin, &jmax, .{ .period = per });
        const S = MaxindexStream(f64);
        const buf = try testing.allocator.alloc(f64, try S.bufLen(.{ .period = per }));
        defer testing.allocator.free(buf);
        var s = try S.init(.{ .period = per }, buf);
        for (xs, 0..) |x, i| {
            const pk = s.peek(x);
            const got = s.update(x);
            try testing.expectEqual(pk, got);
            if (i < lb) {
                try testing.expect(got == null);
                try testing.expectEqual(no_index, imax[i]);
            } else {
                try testing.expectEqual(imax[i], got.?);
                // the reported index holds the window maximum / minimum
                for (xs[i + 1 - per .. i + 1]) |v| {
                    try testing.expect(v <= xs[imax[i]]);
                    try testing.expect(v >= xs[imin[i]]);
                }
                try testing.expectEqual(imax[i], jmax[i]);
                try testing.expectEqual(imin[i], jmin[i]);
            }
        }
    }
}
