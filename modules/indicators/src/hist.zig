// SPDX-License-Identifier: MIT
//! Generic driver for the multi-input / multi-output indicators of the later
//! waves (bars with several fields in, one or several outputs out).
//!
//! A *core* here is a by-value struct that counts the bars fed to it in `n` and
//! answers `step(h, x) ?Out`. `x` is the bar being fed (`Core.In`, a struct of
//! f64 fields); `h.at(i)` returns the bar with index `i` (the core's own count,
//! valid for `n - ringLen + 1 <= i <= n`). `h` is a view of the caller slices
//! (batch) or a ring of the last `Core.ringLen(p)` bars (streaming); on a
//! `peek` the bar `n` is overlaid by `x` and `@TypeOf(h).dry` is true, which a
//! core with private scratch must honour (no writes). Private scratch (rings of
//! derived series) is declared with `Core.scratchLen(p)` and handed over by
//! `c.bind(slice)`.
//!
//! Required of a core: `In`, `Out`, `InOf(T)`, `OutOf(T)`, `validate(p)`,
//! `lookback(p)`, `ringLen(p)`, `init(p)`, `n`, `step`. `Out` is `f64` or a
//! struct whose fields are f64 (one output slice per field, in order) or
//! integer types (an output slice of exactly that integer type).

const std = @import("std");
const core = @import("core.zig");
const Error = core.Error;

pub fn nf(comptime S: type) usize {
    if (S == f64) return 1;
    return @typeInfo(S).@"struct".field_names.len;
}

/// High / low bars (what MIDPRICE, SAR, DONCHIAN, FRAMA, ZIGZAG, ICHIMOKU read).
pub fn Hl(comptime T: type) type {
    return struct { high: T, low: T };
}

/// Close and volume (VWMA).
pub fn Cv(comptime T: type) type {
    return struct { close: T, volume: T };
}

pub fn anyNan(comptime S: type, x: S) bool {
    if (S == f64) return std.math.isNan(x);
    const s = @typeInfo(S).@"struct";
    inline for (s.field_names) |name| {
        const v = @field(x, name);
        if (@typeInfo(@TypeOf(v)) == .float and std.math.isNan(v)) return true;
    }
    return false;
}

/// History over the caller's slices (batch path).
pub fn SliceHist(comptime T: type, comptime In: type) type {
    return struct {
        xs: [nf(In)][]const T,
        pub const dry = false;
        pub fn at(self: @This(), i: usize) In {
            if (In == f64) return self.xs[0][i];
            var r: In = undefined;
            const s = @typeInfo(In).@"struct";
            inline for (s.field_names, 0..) |name, q| @field(r, name) = self.xs[q][i];
            return r;
        }
    };
}

fn readSlot(comptime In: type, buf: []const f64, slot: usize) In {
    if (In == f64) return buf[slot];
    var r: In = undefined;
    const s = @typeInfo(In).@"struct";
    const k = s.field_names.len;
    inline for (s.field_names, 0..) |name, q| @field(r, name) = buf[slot * k + q];
    return r;
}

fn writeSlot(comptime In: type, buf: []f64, slot: usize, x: In) void {
    if (In == f64) {
        buf[slot] = x;
        return;
    }
    const s = @typeInfo(In).@"struct";
    const k = s.field_names.len;
    inline for (s.field_names, 0..) |name, q| buf[slot * k + q] = @field(x, name);
}

/// History over a ring of bars (streaming path); `buf.len / nf(In)` bars.
pub fn RingHist(comptime In: type) type {
    return struct {
        buf: []const f64,
        pub const dry = false;
        pub fn at(self: @This(), i: usize) In {
            return readSlot(In, self.buf, i % (self.buf.len / nf(In)));
        }
    };
}

/// Ring history for `peek`: bar `n` is the not yet stored `x`.
pub fn PeekHist(comptime In: type) type {
    return struct {
        buf: []const f64,
        n: usize,
        x: In,
        pub const dry = true;
        pub fn at(self: @This(), i: usize) In {
            if (i == self.n) return self.x;
            return readSlot(In, self.buf, i % (self.buf.len / nf(In)));
        }
    };
}

/// One field of the history as an f64 source (what `ExtCore` and friends read).
pub fn FieldSrc(comptime H: type, comptime name: anytype) type {
    return struct {
        h: H,
        pub fn at(self: @This(), i: usize) f64 {
            return @field(self.h.at(i), @tagName(name));
        }
    };
}

pub fn field(h: anytype, comptime name: anytype) FieldSrc(@TypeOf(h), name) {
    return .{ .h = h };
}

/// A private ring of derived values inside a core's scratch.
pub const PRing = struct {
    buf: []f64 = &.{},

    /// Store value `v` of bar `n` (not on a dry run).
    pub fn put(self: PRing, comptime dry: bool, n: usize, v: f64) void {
        if (!dry) self.buf[n % self.buf.len] = v;
    }
    /// Source over the ring where bar `n` is `v`, stored or not.
    pub fn src(self: PRing, n: usize, v: f64) core.PeekSrc {
        return .{ .buf = self.buf, .n = n, .x = v };
    }
};

fn nanSkip(p: anytype) bool {
    if (@hasField(@TypeOf(p), "nan")) return p.nan == .skip;
    return false;
}

fn scratchLenOf(comptime Core: type, p: anytype) usize {
    if (@hasDecl(Core, "scratchLen")) return Core.scratchLen(p);
    return 0;
}

fn lead(comptime O: type) O {
    return if (@typeInfo(O) == .float) std.math.nan(O) else 0;
}

fn conv(comptime O: type, v: anytype) O {
    const V = @TypeOf(v);
    if (@typeInfo(O) == .float) return if (@typeInfo(V) == .float) @floatCast(v) else @floatFromInt(v);
    return @intCast(v);
}

fn store(comptime Out: type, outs: anytype, i: usize, r: ?Out) void {
    if (Out == f64) {
        const O = @TypeOf(outs[0][0]);
        outs[0][i] = if (r) |v| conv(O, v) else lead(O);
        return;
    }
    const s = @typeInfo(Out).@"struct";
    inline for (s.field_names, 0..) |name, q| {
        const O = @TypeOf(outs[q][0]);
        outs[q][i] = if (r) |v| conv(O, @field(v, name)) else lead(O);
    }
}

/// Batch driver. `ins` holds one slice per field of `Core.In`, `outs` a tuple
/// with one slice per output (all of length `ins[0].len`). `scratch` must hold
/// `Core.scratchLen(p)` f64 when the core declares it. Returns the lookback.
pub fn batch(comptime T: type, comptime Core: type, ins: [nf(Core.In)][]const T, outs: anytype, p: anytype, scratch: []f64) Error!usize {
    core.checkFloat(T);
    const n = ins[0].len;
    for (ins) |s| if (s.len != n) return error.BadParam;
    inline for (outs) |o| if (o.len != n) return error.BadParam;
    var c = try Core.init(p);
    if (@hasDecl(Core, "scratchLen")) {
        const need = Core.scratchLen(p);
        if (scratch.len < need) return error.BadParam;
        c.bind(scratch[0..need]);
    }
    const h = SliceHist(T, Core.In){ .xs = ins };
    const skip = nanSkip(p);
    var last: ?Core.Out = null;
    for (0..n) |i| {
        const x = h.at(i);
        if (skip and anyNan(Core.In, x)) {
            store(Core.Out, outs, i, last);
            continue;
        }
        const r = c.step(h, x);
        store(Core.Out, outs, i, r);
        if (r != null) last = r;
    }
    return Core.lookback(p);
}

/// Allocating front of `batch` for cores with scratch.
pub fn batchAlloc(comptime T: type, comptime Core: type, gpa: std.mem.Allocator, ins: [nf(Core.In)][]const T, outs: anytype, p: anytype) core.AllocError!usize {
    try Core.validate(p);
    const need = scratchLenOf(Core, p);
    if (need == 0) return batch(T, Core, ins, outs, p, &.{});
    const buf = try gpa.alloc(f64, need);
    defer gpa.free(buf);
    return batch(T, Core, ins, outs, p, buf);
}

/// Streaming type over a core. `bufLen(p)` f64 are needed by `init` (the ring
/// of recent bars plus the core's private scratch).
pub fn Stream(comptime T: type, comptime Params: type, comptime Core: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        pub const InT = Core.InOf(T);
        pub const OutT = Core.OutOf(T);
        const k = nf(Core.In);

        c: Core,
        buf: []f64,
        ring_len: usize,
        scratch_len: usize,
        skip: bool,
        last: ?OutT = null,

        pub fn bufLen(p: Params) Error!usize {
            try Core.validate(p);
            return Core.ringLen(p) * k + scratchLenOf(Core, p);
        }
        pub fn init(p: Params, buf: []f64) Error!Self {
            const need = try bufLen(p);
            if (buf.len < need) return error.BadParam;
            const rl = Core.ringLen(p);
            const sl = scratchLenOf(Core, p);
            var c = try Core.init(p);
            if (@hasDecl(Core, "scratchLen")) c.bind(buf[rl * k .. need]);
            return .{ .c = c, .buf = buf[0 .. rl * k], .ring_len = rl, .scratch_len = sl, .skip = nanSkip(p) };
        }
        /// Feed one bar; null until the lookback is satisfied.
        pub fn update(self: *Self, x: InT) ?OutT {
            const xv = core.to(Core.In, x);
            if (self.skip and anyNan(Core.In, xv)) return self.last;
            if (self.ring_len != 0) writeSlot(Core.In, self.buf, self.c.n % self.ring_len, xv);
            const r = self.c.step(RingHist(Core.In){ .buf = self.buf }, xv) orelse return null;
            self.last = core.to(OutT, r);
            return self.last;
        }
        /// What `update(x)` would answer, without changing the state.
        pub fn peek(self: *const Self, x: InT) ?OutT {
            const xv = core.to(Core.In, x);
            if (self.skip and anyNan(Core.In, xv)) return self.last;
            var cc = self.c;
            const r = cc.step(PeekHist(Core.In){ .buf = self.buf, .n = self.c.n, .x = xv }, xv) orelse return null;
            return core.to(OutT, r);
        }
        /// The last value `update` produced.
        pub fn value(self: *const Self) ?OutT {
            return self.last;
        }
        /// A copy whose ring and scratch live in `dst` (`dst.len >= bufLen`).
        pub fn clone(self: *const Self, dst: []f64) Error!Self {
            const need = self.buf.len + self.scratch_len;
            if (dst.len < need) return error.BadParam;
            var r = self.*;
            r.buf = dst[0..self.buf.len];
            @memcpy(r.buf, self.buf);
            if (@hasDecl(Core, "scratchLen")) {
                const old = self.c.scratchSlice();
                const nw = dst[self.buf.len..need];
                @memcpy(nw, old);
                r.c.bind(nw);
            }
            return r;
        }
    };
}

// ── test support ────────────────────────────────────────────────────────────

const testing = std.testing;
const th = @import("testhelp.zig");

fn asF64(v: anytype) f64 {
    return switch (@typeInfo(@TypeOf(v))) {
        .float => v,
        .int => @floatFromInt(v),
        else => @compileError("asF64"),
    };
}

fn outField(comptime Out: type, v: Out, comptime q: usize) f64 {
    if (Out == f64) return v;
    return asF64(@field(v, @typeInfo(Out).@"struct".field_names[q]));
}

/// Batch against streaming for a generic core over f64 inputs `ins`: every
/// output bitwise equal, `peek` equals `update`, the lookback equals the
/// leading NaN count of the first output.
pub fn checkCore(comptime Core: type, comptime Params: type, ins: [nf(Core.In)][]const f64, p: Params) !void {
    const S = Stream(f64, Params, Core);
    const n = ins[0].len;
    const nout = comptime nf(Core.Out);
    var outs: [nout][]f64 = undefined;
    var made: usize = 0;
    defer for (outs[0..made]) |o| testing.allocator.free(o);
    for (&outs) |*o| {
        o.* = try testing.allocator.alloc(f64, n);
        made += 1;
    }
    const sc = try testing.allocator.alloc(f64, scratchLenOf(Core, p));
    defer testing.allocator.free(sc);
    const lb = try batch(f64, Core, ins, outs, p, sc);
    try testing.expectEqual(Core.lookback(p), lb);
    try testing.expectEqual(lb, th.leadingNan(outs[0]));
    const buf = try testing.allocator.alloc(f64, try S.bufLen(p));
    defer testing.allocator.free(buf);
    var s = try S.init(p, buf);
    for (0..n) |i| {
        var x: S.InT = undefined;
        if (Core.In == f64) {
            x = ins[0][i];
        } else {
            inline for (@typeInfo(Core.In).@"struct".field_names, 0..) |name, q| @field(x, name) = ins[q][i];
        }
        const pk = s.peek(x);
        const got = s.update(x);
        try testing.expect((pk == null) == (got == null));
        if (got) |g| {
            inline for (0..nout) |q| {
                try testing.expect(th.sameBits(outField(S.OutT, g, q), outs[q][i]));
                try testing.expect(th.sameBits(outField(S.OutT, pk.?, q), outs[q][i]));
            }
        } else {
            try testing.expect(std.math.isNan(outs[0][i]));
        }
    }
}
