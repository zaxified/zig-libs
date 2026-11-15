// SPDX-License-Identifier: MIT
//! Multi-input, multi-output plumbing shared by the volume, volatility,
//! price-transform, statistic and math-operator groups.
//!
//! A *tuple core* is a by-value struct with
//!
//!   - `In`      a struct of f64 fields (one per input series, e.g. high, low),
//!   - `Inputs(T)` the same struct with `T` fields (what streaming `update` takes),
//!   - `Out`     f64, usize or a struct of those (one field per output slice),
//!   - `Outputs(T)` the same with `T` where `Out` has f64,
//!   - `Params`, `validate(p)`, `lookback(p)`, `ringLen(p)`, `init(p)`,
//!   - `windowed: bool` (true when streaming needs a caller buffer),
//!   - `n: usize` (bars fed so far) and `step(src, in) ?Out`.
//!
//! `src.at(i)` answers the input tuple of bar `i` of the core (valid for the
//! last `ringLen(p)` bars including the current one). The batch driver hands
//! the core a view of the caller's slices, the stream a ring of tuples held in
//! a caller buffer; both run the same `step`, so they agree to the bit.
//! A core that keeps a sorted scratch array also declares `scratchLen(p)` and
//! `init(p, scratch)` and a non-mutating `peekStep`.

const std = @import("std");
const core = @import("core.zig");
const Error = core.Error;

pub fn Hlcv(comptime T: type) type {
    return struct { high: T, low: T, close: T, volume: T };
}
pub fn Hlv(comptime T: type) type {
    return struct { high: T, low: T, volume: T };
}
pub fn Cv(comptime T: type) type {
    return struct { close: T, volume: T };
}
pub fn V(comptime T: type) type {
    return struct { volume: T };
}
pub fn Hl(comptime T: type) type {
    return struct { high: T, low: T };
}
pub fn Hlc(comptime T: type) type {
    return struct { high: T, low: T, close: T };
}
pub fn Ohlc(comptime T: type) type {
    return struct { open: T, high: T, low: T, close: T };
}
pub fn X(comptime T: type) type {
    return struct { x: T };
}
pub fn Xy(comptime T: type) type {
    return struct { x: T, y: T };
}

/// "No index" marker of the index-valued outputs (the lead of MAXINDEX & co).
pub const no_index: usize = std.math.maxInt(usize);

fn fieldNames(comptime S: type) []const [:0]const u8 {
    return @typeInfo(S).@"struct".field_names;
}
fn nFields(comptime S: type) usize {
    return fieldNames(S).len;
}

/// A view of the caller's input slices (batch path). `off` is the slice index
/// of the core's bar 0.
pub fn SliceSrc(comptime In: type, comptime Ins: type) type {
    return struct {
        ins: Ins,
        off: usize = 0,
        pub fn at(self: @This(), i: usize) In {
            var r: In = undefined;
            inline for (comptime fieldNames(In)) |nm| @field(r, nm) = @field(self.ins, nm)[self.off + i];
            return r;
        }
    };
}

/// A ring of tuples in a caller buffer (`ring` slots of `nFields(In)` f64).
pub fn RingSrc(comptime In: type) type {
    return struct {
        buf: []const f64,
        ring: usize,
        pub fn at(self: @This(), i: usize) In {
            return load(In, self.buf, (i % self.ring) * nFields(In));
        }
    };
}

/// Ring view for `peek`: bar `n` is the not yet stored tuple `x`.
pub fn PeekSrc(comptime In: type) type {
    return struct {
        buf: []const f64,
        ring: usize,
        n: usize,
        x: In,
        pub fn at(self: @This(), i: usize) In {
            if (i == self.n) return self.x;
            return load(In, self.buf, (i % self.ring) * nFields(In));
        }
    };
}

fn load(comptime In: type, buf: []const f64, base: usize) In {
    var r: In = undefined;
    inline for (comptime fieldNames(In), 0..) |nm, j| @field(r, nm) = buf[base + j];
    return r;
}

/// One field of the tuples of `S`, as a plain f64 history source.
pub fn FieldSrc(comptime S: type, comptime name: anytype) type {
    return struct {
        s: S,
        pub fn at(self: @This(), i: usize) f64 {
            return @field(self.s.at(i), name);
        }
    };
}
pub fn field(src: anytype, comptime name: anytype) FieldSrc(@TypeOf(src), name) {
    return .{ .s = src };
}

/// `src` seen from a component that was started `off` bars after the core.
pub fn OffSrc(comptime S: type) type {
    return struct {
        s: S,
        off: usize,
        pub fn at(self: @This(), i: usize) f64 {
            return self.s.at(i + self.off);
        }
    };
}
pub fn offset(src: anytype, off: usize) OffSrc(@TypeOf(src)) {
    return .{ .s = src, .off = off };
}

/// A function of one bar's inputs (no parameters, lookback 0).
pub fn PureCore(comptime InFn: fn (comptime type) type, comptime f: fn (InFn(f64)) f64) type {
    return struct {
        const Self = @This();
        pub const In = InFn(f64);
        pub const Out = f64;
        pub const Params = struct {};
        pub const windowed = false;
        pub fn Inputs(comptime T: type) type {
            return InFn(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }
        n: usize = 0,
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
            self.n += 1;
            return f(b);
        }
    };
}

fn scratchOf(comptime Core: type, p: Core.Params) usize {
    if (@hasDecl(Core, "scratchLen")) return Core.scratchLen(p);
    return 0;
}

fn Child(comptime S: type) type {
    return @typeInfo(S).pointer.child;
}
fn nullOf(comptime E: type) E {
    return if (@typeInfo(E) == .float) std.math.nan(E) else std.math.maxInt(E);
}
fn OutAt(comptime R: type, comptime k: usize) type {
    if (@typeInfo(R) == .@"struct") return @typeInfo(R).@"struct".field_types[k];
    return R;
}
fn outAt(r: anytype, comptime k: usize) OutAt(@TypeOf(r), k) {
    if (@typeInfo(@TypeOf(r)) == .@"struct") return @field(r, fieldNames(@TypeOf(r))[k]);
    return r;
}

/// The batch loop over an initialised core `c` (also for cores built by hand,
/// e.g. with a moving-average variant fixed at comptime).
pub fn run(comptime Core: type, c: *Core, p: Core.Params, ins: anytype, outs: anytype) Error!usize {
    const InNames = comptime fieldNames(Core.In);
    const n = @field(ins, InNames[0]).len;
    inline for (InNames) |nm| if (@field(ins, nm).len != n) return error.BadParam;
    inline for (0..outs.len) |k| if (outs[k].len != n) return error.BadParam;
    const src = SliceSrc(Core.In, @TypeOf(ins)){ .ins = ins };
    // A core may declare `steady()` (every further `step` is its bare recurrence,
    // with an output) and `steadyStep(in) Out` (that step without the warm-up
    // branches, bitwise `step`); `has_steady = false` switches that off for an
    // instantiation. The loop then leaves the generic step once steady.
    const fast = comptime @hasDecl(Core, "steadyStep") and (!@hasDecl(Core, "has_steady") or Core.has_steady);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (fast and c.steady()) break;
        const b = src.at(i);
        if (c.step(src, b)) |r| {
            inline for (0..outs.len) |k| outs[k][i] = core.to(Child(@TypeOf(outs[k])), outAt(r, k));
        } else {
            inline for (0..outs.len) |k| outs[k][i] = nullOf(Child(@TypeOf(outs[k])));
        }
    }
    if (fast) {
        while (i < n) : (i += 1) {
            const r = c.steadyStep(src.at(i));
            inline for (0..outs.len) |k| outs[k][i] = core.to(Child(@TypeOf(outs[k])), outAt(r, k));
        }
    }
    return Core.lookback(p);
}

/// Batch driver for a core without scratch: `ins` is a struct of `[]const T`
/// named like `Core.In`, `outs` a tuple of output slices (one per output).
pub fn batch(comptime T: type, comptime Core: type, p: Core.Params, ins: anytype, outs: anytype) Error!usize {
    core.checkFloat(T);
    var c = try Core.init(p);
    return run(Core, &c, p, ins, outs);
}

/// Batch driver for a core with a scratch array (allocated from `gpa`, freed
/// before returning).
pub fn batchScratch(comptime T: type, comptime Core: type, gpa: std.mem.Allocator, p: Core.Params, ins: anytype, outs: anytype) core.AllocError!usize {
    core.checkFloat(T);
    try Core.validate(p);
    const scratch = try gpa.alloc(f64, scratchOf(Core, p));
    defer gpa.free(scratch);
    var c = try Core.init(p, scratch);
    return run(Core, &c, p, ins, outs);
}

/// Streaming wrapper. Cores that need history (`Core.windowed`) take a caller
/// buffer of `bufLen(p)` f64; the others are plain values (`init(p)`).
pub fn Stream(comptime T: type, comptime Core: type) type {
    core.checkFloat(T);
    const K = nFields(Core.In);
    return struct {
        const Self = @This();
        pub const Input = Core.Inputs(T);
        pub const Output = Core.Outputs(T);
        c: Core,
        buf: []f64 = &.{},
        ring: usize = 0,
        last: ?Output = null,

        /// Number of f64 the caller must provide to `init` (windowed cores).
        pub fn bufLen(p: Core.Params) Error!usize {
            try Core.validate(p);
            return Core.ringLen(p) * K + scratchOf(Core, p);
        }
        fn initBuf(p: Core.Params, buf: []f64) Error!Self {
            const need = try bufLen(p);
            if (buf.len < need) return error.BadParam;
            const rl = Core.ringLen(p);
            const c = if (@hasDecl(Core, "scratchLen")) try Core.init(p, buf[rl * K .. need]) else try Core.init(p);
            return .{ .c = c, .buf = buf[0 .. rl * K], .ring = rl };
        }
        fn initPlain(p: Core.Params) Error!Self {
            return .{ .c = try Core.init(p) };
        }
        pub const init = if (Core.windowed) initBuf else initPlain;

        /// Feed one bar; null until the lookback is satisfied.
        pub fn update(self: *Self, in: Input) ?Output {
            const inv = core.to(Core.In, in);
            if (self.ring != 0) {
                const base = (self.c.n % self.ring) * K;
                inline for (comptime fieldNames(Core.In), 0..) |nm, j| self.buf[base + j] = @field(inv, nm);
            }
            const src = RingSrc(Core.In){ .buf = self.buf, .ring = self.ring };
            const r = self.c.step(src, inv) orelse return null;
            self.last = core.to(Output, r);
            return self.last;
        }
        /// What `update(in)` would answer, without changing the state.
        pub fn peek(self: *const Self, in: Input) ?Output {
            const inv = core.to(Core.In, in);
            const src = PeekSrc(Core.In){ .buf = self.buf, .ring = self.ring, .n = self.c.n, .x = inv };
            var r: ?Core.Out = null;
            if (@hasDecl(Core, "peekStep")) {
                r = self.c.peekStep(src, inv);
            } else {
                var cc = self.c;
                r = cc.step(src, inv);
            }
            return core.to(Output, r orelse return null);
        }
        /// The last value `update` produced.
        pub fn value(self: *const Self) ?Output {
            return self.last;
        }
    };
}

/// A `Stream` of a core whose only input is `x`: `update(x)` instead of
/// `update(.{ .x = x })`, like the single-series streams of the seed set.
pub fn SingleStream(comptime T: type, comptime Core: type) type {
    const S = Stream(T, Core);
    return struct {
        const Self = @This();
        pub const Output = S.Output;
        s: S,
        pub fn bufLen(p: Core.Params) Error!usize {
            return S.bufLen(p);
        }
        fn initBuf(p: Core.Params, buf: []f64) Error!Self {
            return .{ .s = try S.init(p, buf) };
        }
        fn initPlain(p: Core.Params) Error!Self {
            return .{ .s = try S.init(p) };
        }
        pub const init = if (Core.windowed) initBuf else initPlain;
        pub fn update(self: *Self, x: T) ?Output {
            return self.s.update(.{ .x = x });
        }
        pub fn peek(self: *const Self, x: T) ?Output {
            return self.s.peek(.{ .x = x });
        }
        pub fn value(self: *const Self) ?Output {
            return self.s.value();
        }
    };
}

// ── generic tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const th = @import("testhelp.zig");

/// Batch against streaming for a float-valued tuple core: lookback equals the
/// leading NaN count of every output, stream and `peek` equal the batch bits.
/// `ins` is a struct of `[]const f64` named like `Core.In`.
pub fn checkCore(comptime Core: type, p: Core.Params, ins: anytype) !void {
    const names = comptime fieldNames(Core.In);
    const n = @field(ins, names[0]).len;
    const no = comptime if (@typeInfo(Core.Out) == .@"struct") nFields(Core.Out) else 1;
    const gpa = testing.allocator;
    var store: [no][]f64 = undefined;
    for (&store) |*s| s.* = try gpa.alloc(f64, n);
    defer for (store) |s| gpa.free(s);
    const lb = switch (no) {
        1 => if (@hasDecl(Core, "scratchLen")) try batchScratch(f64, Core, gpa, p, ins, .{store[0]}) else try batch(f64, Core, p, ins, .{store[0]}),
        2 => if (@hasDecl(Core, "scratchLen")) try batchScratch(f64, Core, gpa, p, ins, .{ store[0], store[1] }) else try batch(f64, Core, p, ins, .{ store[0], store[1] }),
        3 => try batch(f64, Core, p, ins, .{ store[0], store[1], store[2] }),
        4 => try batch(f64, Core, p, ins, .{ store[0], store[1], store[2], store[3] }),
        else => @compileError("checkCore: too many outputs"),
    };
    try testing.expectEqual(lb, Core.lookback(p));
    for (store) |s| try testing.expectEqual(lb, th.leadingNan(s));
    const S = Stream(f64, Core);
    const buf = try gpa.alloc(f64, if (Core.windowed) try S.bufLen(p) else 0);
    defer gpa.free(buf);
    var s = if (Core.windowed) try S.init(p, buf) else try S.init(p);
    for (0..n) |i| {
        var inp: S.Input = undefined;
        inline for (names) |nm| @field(inp, nm) = @field(ins, nm)[i];
        const pk = s.peek(inp);
        const got = s.update(inp);
        try testing.expect((pk == null) == (got == null));
        if (got) |g| {
            inline for (0..no) |k| {
                try testing.expect(th.sameBits(outAt(g, k), store[k][i]));
                try testing.expect(th.sameBits(outAt(pk.?, k), store[k][i]));
            }
        } else {
            inline for (0..no) |k| try testing.expect(std.math.isNan(store[k][i]));
        }
    }
}

/// Seeded OHLCV bars for tests: low <= open, close <= high, volume 0..2000 with
/// runs of zeros (zero-volume branches), all of one length.
pub fn fillBars(o: []f64, h: []f64, l: []f64, c: []f64, v: []f64, seed: u64) void {
    th.walkBars(h, l, c, seed);
    var prng = std.Random.DefaultPrng.init(seed +% 77);
    const r = prng.random();
    var zero_run: usize = 0;
    for (o, h, l, c, v, 0..) |*oo, hh, ll, cc, *vv, i| {
        const t = r.float(f64);
        oo.* = ll + (hh - ll) * t;
        _ = i;
        if (zero_run > 0) {
            zero_run -= 1;
            vv.* = 0.0;
        } else {
            vv.* = @floor(r.float(f64) * 2000.0);
            if (r.uintLessThan(usize, 25) == 0) zero_run = r.uintLessThan(usize, 12);
        }
        _ = cc;
    }
}

test "vs_kit: field names and no_index" {
    try testing.expectEqual(@as(usize, 4), fieldNames(Hlcv(f64)).len);
    try testing.expect(no_index == std.math.maxInt(usize));
}
