// SPDX-License-Identifier: MIT
//! Plumbing shared by the momentum group (`mom_*.zig`): a ring of derived
//! values that a core keeps in its scratch, the non-mutating `peek` for cores
//! that own such rings, a batch driver with a lead policy for integer outputs,
//! and generic test helpers.
//!
//! A core that needs the history of a *derived* series (a recursive series such
//! as an EMA, a running oscillator, ...) keeps it in a `Ring` carved out of the
//! scratch buffer the kit hands to `init(p, scratch)`. Derived series that are
//! pure functions of a bounded input window (a ROC, a true range, a typical
//! price) are not stored: the core recomputes them from the input ring, which
//! yields the very same doubles.

const std = @import("std");
const core = @import("core.zig");
const vs = @import("vs_kit.zig");
const th = @import("testhelp.zig");
const Error = core.Error;

/// Open and close of a bar (QSTICK, IMI).
pub fn Oc(comptime T: type) type {
    return struct { open: T, close: T };
}

/// A ring of f64 over caller memory. Indexed by push number: the value pushed
/// as the `i`-th (from 0) is `at(i)` until `buf.len` further pushes happened.
pub const Ring = struct {
    buf: []f64 = &.{},
    n: usize = 0,

    pub fn init(buf: []f64) Ring {
        @memset(buf, 0.0);
        return .{ .buf = buf };
    }
    pub fn push(self: *Ring, v: f64) void {
        if (self.buf.len != 0) self.buf[self.n % self.buf.len] = v;
        self.n += 1;
    }
    pub fn at(self: Ring, i: usize) f64 {
        return self.buf[i % self.buf.len];
    }
    /// A plain history source (`src.at(i)`) for the single-input cores.
    pub fn view(self: Ring) View {
        return .{ .r = self };
    }
};

pub const View = struct {
    r: Ring,
    pub fn at(self: View, i: usize) f64 {
        return self.r.at(i);
    }
};

/// Carve `len` f64 out of the front of `scratch` as a Ring.
pub fn carve(scratch: *[]f64, len: usize) Ring {
    const r = scratch.*[0..len];
    scratch.* = scratch.*[len..];
    return Ring.init(r);
}

fn ringCount(comptime S: type) usize {
    var c: usize = 0;
    inline for (@typeInfo(S).@"struct".field_types) |ft| {
        if (ft == Ring) {
            c += 1;
        } else if (@typeInfo(ft) == .@"struct") {
            c += ringCount(ft);
        }
    }
    return c;
}

fn collect(comptime S: type, p: *S, list: []*Ring, k: *usize) void {
    inline for (@typeInfo(S).@"struct".field_names, @typeInfo(S).@"struct".field_types) |nm, ft| {
        if (ft == Ring) {
            list[k.*] = &@field(p, nm);
            k.* += 1;
        } else if (@typeInfo(ft) == .@"struct") {
            collect(ft, &@field(p, nm), list, k);
        }
    }
}

/// `peekStep` for a core that owns `Ring` fields (directly or in nested
/// structs): steps a copy and puts back the one slot per ring that the step
/// overwrote. Each ring may be pushed at most once per step.
pub fn peekRings(comptime Core: type, self: *const Core, src: anytype, in: anytype) ?Core.Out {
    var cc = self.*;
    const K = comptime ringCount(Core);
    var rs: [K]*Ring = undefined;
    var k: usize = 0;
    collect(Core, &cc, &rs, &k);
    var ns: [K]usize = undefined;
    var saved: [K]f64 = undefined;
    for (rs, 0..) |r, i| {
        ns[i] = r.n;
        saved[i] = if (r.buf.len != 0) r.buf[r.n % r.buf.len] else 0.0;
    }
    const out = cc.step(src, in);
    for (rs, 0..) |r, i| {
        std.debug.assert(r.n <= ns[i] + 1);
        if (r.buf.len != 0 and r.n == ns[i] + 1) r.buf[ns[i] % r.buf.len] = saved[i];
    }
    return out;
}

// ── batch driver with integer-output support ────────────────────────────────

fn fieldNames(comptime S: type) []const [:0]const u8 {
    return @typeInfo(S).@"struct".field_names;
}
fn Child(comptime S: type) type {
    return @typeInfo(S).pointer.child;
}
fn leadOf(comptime E: type) E {
    if (@typeInfo(E) == .float) return std.math.nan(E);
    if (E == usize) return std.math.maxInt(usize);
    return 0;
}
fn OutAt(comptime R: type, comptime k: usize) type {
    if (@typeInfo(R) == .@"struct") return @typeInfo(R).@"struct".field_types[k];
    return R;
}
fn outAt(r: anytype, comptime k: usize) OutAt(@TypeOf(r), k) {
    if (@typeInfo(@TypeOf(r)) == .@"struct") return @field(r, fieldNames(@TypeOf(r))[k]);
    return r;
}

/// Batch driver for a scratch core (allocator variant, f64 scratch only) with
/// any mix of float / integer outputs. Floats lead with NaN, integers with 0.
pub fn batchLead0(comptime T: type, comptime Core: type, gpa: std.mem.Allocator, p: Core.Params, ins: anytype, outs: anytype) core.AllocError!usize {
    core.checkFloat(T);
    try Core.validate(p);
    const names = comptime fieldNames(Core.In);
    const n = @field(ins, names[0]).len;
    inline for (names) |nm| if (@field(ins, nm).len != n) return error.BadParam;
    inline for (0..outs.len) |k| if (outs[k].len != n) return error.BadParam;
    const scratch = try gpa.alloc(f64, if (@hasDecl(Core, "scratchLen")) Core.scratchLen(p) else 0);
    defer gpa.free(scratch);
    var c = if (@hasDecl(Core, "scratchLen")) try Core.init(p, scratch) else try Core.init(p);
    const src = vs.SliceSrc(Core.In, @TypeOf(ins)){ .ins = ins };
    for (0..n) |i| {
        if (c.step(src, src.at(i))) |r| {
            inline for (0..outs.len) |k| outs[k][i] = core.to(Child(@TypeOf(outs[k])), outAt(r, k));
        } else {
            inline for (0..outs.len) |k| outs[k][i] = leadOf(Child(@TypeOf(outs[k])));
        }
    }
    return Core.lookback(p);
}

// ── tests helpers ───────────────────────────────────────────────────────────

pub const Bars = struct {
    o: []f64,
    h: []f64,
    l: []f64,
    c: []f64,
    v: []f64,

    pub fn make(gpa: std.mem.Allocator, n: usize, seed: u64) !Bars {
        const b = Bars{
            .o = try gpa.alloc(f64, n),
            .h = try gpa.alloc(f64, n),
            .l = try gpa.alloc(f64, n),
            .c = try gpa.alloc(f64, n),
            .v = try gpa.alloc(f64, n),
        };
        vs.fillBars(b.o, b.h, b.l, b.c, b.v, seed);
        return b;
    }
    pub fn free(self: Bars, gpa: std.mem.Allocator) void {
        gpa.free(self.o);
        gpa.free(self.h);
        gpa.free(self.l);
        gpa.free(self.c);
        gpa.free(self.v);
    }
    /// The slices a core with input struct `In` reads (`x` is the close).
    pub fn ins(self: Bars, comptime In: type) InsOf(In, f64) {
        var r: InsOf(In, f64) = undefined;
        inline for (comptime fieldNames(In)) |nm| @field(r, nm) = self.field(nm);
        return r;
    }
    fn field(self: Bars, comptime nm: []const u8) []const f64 {
        if (comptime std.mem.eql(u8, nm, "open")) return self.o;
        if (comptime std.mem.eql(u8, nm, "high")) return self.h;
        if (comptime std.mem.eql(u8, nm, "low")) return self.l;
        if (comptime std.mem.eql(u8, nm, "volume")) return self.v;
        return self.c; // close and x
    }
};

/// A struct with the field names of `In` and `[]const T` slices.
pub fn InsOf(comptime In: type, comptime T: type) type {
    const names = fieldNames(In);
    var types: [names.len]type = undefined;
    for (&types) |*t| t.* = []const T;
    return @Struct(.auto, null, names, &types, &@splat(.{}));
}

/// batch == streaming (bitwise, `peek` too), lookback == NaN lead, over a seeded
/// OHLCV walk; for every float output. Cores without scratch only.
pub fn checkCore(comptime Core: type, p: Core.Params, n: usize, seed: u64) !void {
    const gpa = std.testing.allocator;
    const b = try Bars.make(gpa, n, seed);
    defer b.free(gpa);
    try vs.checkCore(Core, p, b.ins(Core.In));
}

/// The f32 path: outputs equal the f64 run over the widened inputs, rounded.
pub fn checkF32(comptime Core: type, p: Core.Params, n: usize, seed: u64) !void {
    const gpa = std.testing.allocator;
    const b = try Bars.make(gpa, n, seed);
    defer b.free(gpa);
    const names = comptime fieldNames(Core.In);
    const in64 = b.ins(Core.In);
    var in32: InsOf(Core.In, f32) = undefined;
    var wide: InsOf(Core.In, f64) = undefined;
    inline for (names) |nm| {
        const s = try gpa.alloc(f32, n);
        const w = try gpa.alloc(f64, n);
        for (s, w, @field(in64, nm)) |*d, *e, x| {
            d.* = @floatCast(x);
            e.* = d.*;
        }
        @field(in32, nm) = s;
        @field(wide, nm) = w;
    }
    defer inline for (names) |nm| {
        gpa.free(@constCast(@field(in32, nm)));
        gpa.free(@constCast(@field(wide, nm)));
    };
    const no = comptime if (@typeInfo(Core.Out) == .@"struct") fieldNames(Core.Out).len else 1;
    var o32: [no][]f32 = undefined;
    var o64: [no][]f64 = undefined;
    for (&o32, &o64) |*a, *c| {
        a.* = try gpa.alloc(f32, n);
        c.* = try gpa.alloc(f64, n);
    }
    defer for (o32, o64) |a, c| {
        gpa.free(a);
        gpa.free(c);
    };
    const lb32 = try runBatch(f32, Core, gpa, p, in32, &o32);
    const lb64 = try runBatch(f64, Core, gpa, p, wide, &o64);
    try std.testing.expectEqual(lb64, lb32);
    for (o32, o64) |a, c| for (a, c) |x, y| {
        const want: f32 = @floatCast(y);
        try std.testing.expect((std.math.isNan(x) and std.math.isNan(want)) or x == want);
    };
}

fn runBatch(comptime T: type, comptime Core: type, gpa: std.mem.Allocator, p: Core.Params, ins: anytype, o: anytype) !usize {
    return switch (o.len) {
        1 => try batchLead0(T, Core, gpa, p, ins, .{o[0]}),
        2 => try batchLead0(T, Core, gpa, p, ins, .{ o[0], o[1] }),
        3 => try batchLead0(T, Core, gpa, p, ins, .{ o[0], o[1], o[2] }),
        4 => try batchLead0(T, Core, gpa, p, ins, .{ o[0], o[1], o[2], o[3] }),
        else => @compileError("runBatch: too many outputs"),
    };
}

test "ring: push, at, peek restore" {
    var buf: [3]f64 = undefined;
    var r = Ring.init(&buf);
    r.push(1);
    r.push(2);
    try std.testing.expectEqual(@as(f64, 2), r.at(1));
    r.push(3);
    r.push(4); // evicts 1
    try std.testing.expectEqual(@as(f64, 4), r.at(3));
    try std.testing.expectEqual(@as(f64, 2), r.at(1));
}
