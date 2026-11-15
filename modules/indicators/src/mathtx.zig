// SPDX-License-Identifier: MIT
//! Math transforms ported from TA-Lib 0.8.3 (`ta_ACOS.c` ... `ta_TANH.c`; BSD-3,
//! see NOTICE): one C library function applied to every bar, lookback 0, no
//! parameters. The C calls `acos`, `asin`, `atan`, `ceil`, `cos`, `cosh`, `exp`,
//! `floor`, `log`, `log10`, `sin`, `sinh`, `sqrt`, `tan` and `tanh` of the C
//! library; ours call Zig's own implementations of the same functions (`ceil`,
//! `floor` and `sqrt` are exact and agree to the bit, the others are rounded
//! within a few ULP of the exact result by both libraries and can differ in the
//! last bits, see SPEC for the measured bound per function). A value outside a
//! function's domain is NaN (or an infinity), never an error, as in C.

const std = @import("std");
const core = @import("core.zig");
const xmath = @import("xmath.zig");
const K = @import("vs_kit.zig");
const th = @import("testhelp.zig");

/// The C library calls of the ported sources, in one place.
const libm = struct {
    fn acos(x: f64) f64 {
        return xmath.acos(x);
    }
    fn asin(x: f64) f64 {
        return xmath.asin(x);
    }
    fn atan(x: f64) f64 {
        return xmath.atan(x);
    }
    fn ceil(x: f64) f64 {
        return @ceil(x);
    }
    fn cos(x: f64) f64 {
        return @cos(x);
    }
    fn cosh(x: f64) f64 {
        return xmath.cosh(x);
    }
    fn exp(x: f64) f64 {
        return @exp(x);
    }
    fn floor(x: f64) f64 {
        return @floor(x);
    }
    fn ln(x: f64) f64 {
        return @log(x);
    }
    fn log10(x: f64) f64 {
        return @log10(x);
    }
    fn sin(x: f64) f64 {
        return @sin(x);
    }
    fn sinh(x: f64) f64 {
        return xmath.sinh(x);
    }
    fn sqrt(x: f64) f64 {
        return @sqrt(x);
    }
    fn tan(x: f64) f64 {
        return @tan(x);
    }
    fn tanh(x: f64) f64 {
        return xmath.tanh(x);
    }
};

fn Fn1(comptime name: []const u8) fn (K.X(f64)) f64 {
    return struct {
        fn f(b: K.X(f64)) f64 {
            return @field(libm, name)(b.x);
        }
    }.f;
}

pub const AcosCore = K.PureCore(K.X, Fn1("acos"));
pub const AsinCore = K.PureCore(K.X, Fn1("asin"));
pub const AtanCore = K.PureCore(K.X, Fn1("atan"));
pub const CeilCore = K.PureCore(K.X, Fn1("ceil"));
pub const CosCore = K.PureCore(K.X, Fn1("cos"));
pub const CoshCore = K.PureCore(K.X, Fn1("cosh"));
pub const ExpCore = K.PureCore(K.X, Fn1("exp"));
pub const FloorCore = K.PureCore(K.X, Fn1("floor"));
pub const LnCore = K.PureCore(K.X, Fn1("ln"));
pub const Log10Core = K.PureCore(K.X, Fn1("log10"));
pub const SinCore = K.PureCore(K.X, Fn1("sin"));
pub const SinhCore = K.PureCore(K.X, Fn1("sinh"));
pub const SqrtCore = K.PureCore(K.X, Fn1("sqrt"));
pub const TanCore = K.PureCore(K.X, Fn1("tan"));
pub const TanhCore = K.PureCore(K.X, Fn1("tanh"));

/// Declares `<name>Lookback`, `<name>` (batch) and `<Name>Stream` for one core.
fn Api(comptime Core: type) type {
    return struct {
        pub fn lookback() usize {
            return 0;
        }
        pub fn run(comptime T: type, in: []const T, out: []T) core.Error!usize {
            return K.batch(T, Core, .{}, .{ .x = in }, .{out});
        }
        pub fn Stream(comptime T: type) type {
            return K.SingleStream(T, Core);
        }
    };
}

pub const acosLookback = Api(AcosCore).lookback;
pub const acos = Api(AcosCore).run;
pub const AcosStream = Api(AcosCore).Stream;
pub const asinLookback = Api(AsinCore).lookback;
pub const asin = Api(AsinCore).run;
pub const AsinStream = Api(AsinCore).Stream;
pub const atanLookback = Api(AtanCore).lookback;
pub const atan = Api(AtanCore).run;
pub const AtanStream = Api(AtanCore).Stream;
pub const ceilLookback = Api(CeilCore).lookback;
pub const ceil = Api(CeilCore).run;
pub const CeilStream = Api(CeilCore).Stream;
pub const cosLookback = Api(CosCore).lookback;
pub const cos = Api(CosCore).run;
pub const CosStream = Api(CosCore).Stream;
pub const coshLookback = Api(CoshCore).lookback;
pub const cosh = Api(CoshCore).run;
pub const CoshStream = Api(CoshCore).Stream;
pub const expLookback = Api(ExpCore).lookback;
pub const exp = Api(ExpCore).run;
pub const ExpStream = Api(ExpCore).Stream;
pub const floorLookback = Api(FloorCore).lookback;
pub const floor = Api(FloorCore).run;
pub const FloorStream = Api(FloorCore).Stream;
pub const lnLookback = Api(LnCore).lookback;
pub const ln = Api(LnCore).run;
pub const LnStream = Api(LnCore).Stream;
pub const log10Lookback = Api(Log10Core).lookback;
pub const log10 = Api(Log10Core).run;
pub const Log10Stream = Api(Log10Core).Stream;
pub const sinLookback = Api(SinCore).lookback;
pub const sin = Api(SinCore).run;
pub const SinStream = Api(SinCore).Stream;
pub const sinhLookback = Api(SinhCore).lookback;
pub const sinh = Api(SinhCore).run;
pub const SinhStream = Api(SinhCore).Stream;
pub const sqrtLookback = Api(SqrtCore).lookback;
pub const sqrt = Api(SqrtCore).run;
pub const SqrtStream = Api(SqrtCore).Stream;
pub const tanLookback = Api(TanCore).lookback;
pub const tan = Api(TanCore).run;
pub const TanStream = Api(TanCore).Stream;
pub const tanhLookback = Api(TanhCore).lookback;
pub const tanh = Api(TanhCore).run;
pub const TanhStream = Api(TanhCore).Stream;

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "exact transforms: ceil, floor, sqrt on hand values, NaN and signed zero" {
    const in = [_]f64{ 1.2, -1.2, 2.0, -0.0, 0.5, -0.5, 4.0, std.math.nan(f64), std.math.inf(f64) };
    var out: [9]f64 = undefined;
    try testing.expectEqual(@as(usize, 0), try ceil(f64, &in, &out));
    try testing.expectEqual(@as(f64, 2.0), out[0]);
    try testing.expectEqual(@as(f64, -1.0), out[1]);
    try testing.expect(std.math.signbit(out[5])); // ceil(-0.5) = -0.0
    try testing.expect(std.math.isNan(out[7]));
    _ = try floor(f64, &in, &out);
    try testing.expectEqual(@as(f64, 1.0), out[0]);
    try testing.expectEqual(@as(f64, -2.0), out[1]);
    try testing.expectEqual(@as(f64, 0.0), out[4]);
    try testing.expect(std.math.isInf(out[8]));
    _ = try sqrt(f64, &in, &out);
    try testing.expectEqual(@as(f64, 2.0), out[6]);
    try testing.expect(std.math.isNan(out[1])); // sqrt of a negative: NaN, not an error
    try testing.expect(std.math.signbit(out[3])); // sqrt(-0.0) = -0.0
}

test "transforms: known values, domains" {
    const in = [_]f64{ 0.0, 1.0, -1.0, 2.0 };
    var out: [4]f64 = undefined;
    _ = try ln(f64, &in, &out);
    try testing.expect(std.math.isInf(out[0]) and out[0] < 0);
    try testing.expectEqual(@as(f64, 0.0), out[1]);
    try testing.expect(std.math.isNan(out[2]));
    _ = try exp(f64, &in, &out);
    try testing.expectEqual(@as(f64, 1.0), out[0]);
    try testing.expectApproxEqRel(@as(f64, std.math.e), out[1], 1e-15);
    _ = try acos(f64, &in, &out);
    try testing.expectApproxEqRel(@as(f64, std.math.pi / 2.0), out[0], 1e-15);
    try testing.expectEqual(@as(f64, 0.0), out[1]);
    try testing.expect(std.math.isNan(out[3])); // outside [-1, 1]
    _ = try asin(f64, &in, &out);
    try testing.expect(std.math.isNan(out[3]));
    _ = try log10(f64, &[_]f64{ 1.0, 10.0, 1000.0, 0.01 }, &out);
    try testing.expectEqual(@as(f64, 0.0), out[0]);
    try testing.expectEqual(@as(f64, 1.0), out[1]);
    try testing.expectEqual(@as(f64, 3.0), out[2]);
    try testing.expectEqual(@as(f64, -2.0), out[3]);
}

fn checkStream(comptime Api_: type, xs: []const f64) !void {
    var out: [64]f64 = undefined;
    const o = out[0..xs.len];
    try testing.expectEqual(@as(usize, 0), try Api_.run(f64, xs, o));
    var s = Api_.Stream(f64).init(.{}) catch unreachable;
    for (xs, o) |x, want| {
        const pk = s.peek(x);
        const got = s.update(x);
        try testing.expect(th.sameBits(got.?, want) and th.sameBits(pk.?, want));
        try testing.expect(th.sameBits(s.value().?, want));
    }
}

test "every transform: batch == stream, no lead, lengths, f32" {
    var xs: [40]f64 = undefined;
    th.walk(&xs, 21);
    for (&xs, 0..) |*x, i| x.* = (x.* - 100.0) / 3.0 + @as(f64, @floatFromInt(i % 5)) * 0.2; // around 0, some |x| < 1
    inline for ([_]type{ Api(AcosCore), Api(AsinCore), Api(AtanCore), Api(CeilCore), Api(CosCore), Api(CoshCore), Api(ExpCore), Api(FloorCore), Api(LnCore), Api(Log10Core), Api(SinCore), Api(SinhCore), Api(SqrtCore), Api(TanCore), Api(TanhCore) }) |A| {
        try checkStream(A, &xs);
        var short: [3]f64 = undefined;
        try testing.expectError(error.BadParam, A.run(f64, &xs, &short));
    }
    // f32: the f64 function of the rounded input, rounded once
    var x32: [40]f32 = undefined;
    for (&x32, xs) |*d, x| d.* = @floatCast(x);
    var o32: [40]f32 = undefined;
    _ = try atan(f32, &x32, &o32);
    for (x32, o32) |x, o| try testing.expectEqual(@as(f32, @floatCast(std.math.atan(@as(f64, x)))), o);
}
