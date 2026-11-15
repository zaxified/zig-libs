// SPDX-License-Identifier: MIT
//! Shared pieces of `indicators`: the error set, option types, the history
//! sources the window cores read through, and small helpers.
//!
//! The arithmetic of every indicator lives in a *core*: a small by-value struct
//! with `step(src, x) ?f64`. A core is fed bars one at a time, counts them in
//! `n` (index of the bar being fed, from 0 at the first bar fed to THIS core)
//! and answers null until its lookback is satisfied. A core that needs older
//! values reads them through `src.at(i)` (i is a bar index of this core, valid
//! for `n - period + 1 <= i <= n`). The batch functions hand a core a view of
//! the caller's slice, the streaming types hand it a ring buffer: the same
//! arithmetic runs in both, which is what makes batch and streaming agree to
//! the bit.

const std = @import("std");

pub const Error = error{
    /// A parameter is outside TA-Lib's documented range, or a slice length
    /// disagrees with the others.
    BadParam,
    /// The requested moving-average type is not implemented yet (see SPEC).
    Unsupported,
};

/// TA-Lib's range for every `optInTimePeriod`-like parameter.
pub const max_period: usize = 100000;
/// Largest accepted `Unstable.bars`.
pub const max_unstable: usize = 1 << 30;

/// What a recursive indicator does with a NaN input.
pub const Nan = enum {
    /// The NaN enters the recursion and poisons the state, as in TA-Lib.
    propagate,
    /// The bar is ignored: the state is carried over unchanged, the bar does not
    /// count towards the lookback and its output is NaN.
    skip,
};

/// How an EMA is seeded.
pub const Seed = enum {
    /// The simple average of the first `period` bars (TA-Lib 0.8.x).
    sma,
    /// The first bar itself (pandas `ewm(adjust=False)`); not a TA-Lib mode.
    first,
};

/// TA-Lib's unstable period, per call instead of process-global.
pub const Unstable = union(enum) {
    /// Extra bars dropped from the front of the output (`TA_SetUnstablePeriod`).
    bars: usize,
    /// Drop output until 4 significant digits no longer depend on the start.
    auto4,
    /// Same for 8 digits.
    auto8,

    pub fn get(self: Unstable, c4: usize, c8: usize) usize {
        return switch (self) {
            .bars => |b| b,
            .auto4 => c4,
            .auto8 => c8,
        };
    }

    pub fn check(self: Unstable) Error!void {
        switch (self) {
            .bars => |b| if (b > max_unstable) return error.BadParam,
            else => {},
        }
    }
};

pub const no_unstable: Unstable = .{ .bars = 0 };

/// TA-Lib's `TA_MAType` numbering. Types after `hma` and `disabled` follow
/// `ta_defs.h` (value 11 is `TA_MAType_DEFAULT`, resolved to `sma`).
pub const MaType = enum(u8) {
    sma = 0,
    ema = 1,
    wma = 2,
    dema = 3,
    tema = 4,
    trima = 5,
    kama = 6,
    mama = 7,
    t3 = 8,
    hma = 9,
    /// Identity copy at any period.
    disabled = 10,
    zlema = 12,
    rma = 13,
    vidya = 14,
    alma = 15,
};

/// One OHLC bar without the open (what TRANGE, ATR, NATR and STOCH read).
pub fn Bar(comptime T: type) type {
    return struct { high: T, low: T, close: T };
}

pub fn checkPeriod(p: usize, min: usize) Error!void {
    if (p < min or p > max_period) return error.BadParam;
}

pub fn checkLen(n: usize, lens: []const usize) Error!void {
    for (lens) |l| if (l != n) return error.BadParam;
}

/// f64 -> T (T is f32 or f64), and struct-of-f64 -> struct-of-T.
pub fn to(comptime D: type, v: anytype) D {
    if (D == @TypeOf(v)) return v;
    switch (@typeInfo(D)) {
        .float => return @floatCast(v),
        .@"struct" => |s| {
            var r: D = undefined;
            inline for (s.field_names, s.field_types) |name, ft| @field(r, name) = to(ft, @field(v, name));
            return r;
        },
        else => @compileError("to: unsupported type"),
    }
}

pub fn checkFloat(comptime T: type) void {
    if (T != f32 and T != f64) @compileError("indicators: T must be f32 or f64");
}

pub fn fillNan(comptime T: type, out: []T) void {
    @memset(out, std.math.nan(T));
}

pub fn isNan(x: f64) bool {
    return std.math.isNan(x);
}

pub fn pf(p: usize) f64 {
    return @floatFromInt(p);
}

/// History source over a caller slice (batch path). `off` is the slice index of
/// the core's bar 0.
pub fn SliceSrc(comptime T: type) type {
    return struct {
        xs: []const T,
        off: usize = 0,
        pub fn at(self: @This(), i: usize) f64 {
            return self.xs[self.off + i];
        }
    };
}

/// History source over a ring buffer (streaming path); `buf.len` is the period.
pub const RingSrc = struct {
    buf: []const f64,
    pub fn at(self: RingSrc, i: usize) f64 {
        return self.buf[i % self.buf.len];
    }
};

/// Ring source for `peek`: bar `n` is the not yet stored value `x`.
pub const PeekSrc = struct {
    buf: []const f64,
    n: usize,
    x: f64,
    pub fn at(self: PeekSrc, i: usize) f64 {
        if (i == self.n) return self.x;
        return self.buf[i % self.buf.len];
    }
};

/// A ring of f64 that a composite streaming type carves out of its buffer.
pub fn carve(buf: *[]f64, len: usize) []f64 {
    const r = buf.*[0..len];
    buf.* = buf.*[len..];
    return r;
}

test "to converts structs and floats" {
    const B = Bar(f32);
    const b = to(B, Bar(f64){ .high = 2, .low = 1, .close = 1.5 });
    try std.testing.expectEqual(@as(f32, 1.5), b.close);
    try std.testing.expectEqual(@as(f64, 3), to(f64, @as(f64, 3)));
}
