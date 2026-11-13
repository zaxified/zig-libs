// SPDX-License-Identifier: MIT
//! `arbitrary`: typed values from a choice source — the strategy library a
//! harness would otherwise hand-write (proptest's `Arbitrary`, Hypothesis'
//! `from_type`, rapid's `Make`).
//!
//!     const v = try testkit.arbitrary(Request, S, src, arena, .{});
//!
//! It is generic over the source exactly as the harnesses are: only
//! `valueRangeAtMost`, `value`, `bytes` and `index` are drawn, so
//! `fuzz.Rng`, `std.testing.Smith` and `fuzz.ScriptSource` all work, and the
//! driver's tape shrinker shrinks a typed value for free: every draw is
//! ordered so that a tape of zeros is the *smallest* value (`false`, 0, the
//! first enum tag, `null`, the empty slice, the first union tag), and each
//! draw's entry lowers toward that.
//!
//! | type | value |
//! |---|---|
//! | `bool` | a drawn bool |
//! | `iN` / `uN` | edge-biased: 0, 1, -1 (max for unsigned), min, max, min+1, max-1 about 1 draw in 9, else uniform |
//! | `fN` | edge-biased: 0, 1, -1, -0.0, ±inf, NaN (`float_nan`), smallest subnormal, ±max, smallest normal, a small integer, else uniform bit patterns (f80: from an f64) |
//! | `enum` | any declared tag; non-exhaustive: now and then an unnamed value |
//! | `?T` | `null` with probability 1/8 |
//! | `[N]T`, `@Vector(N, T)` | every element |
//! | `[]T`, `[]const T`, `[:s]T` | length in `0..max_len`, allocated in `arena` |
//! | `[]const u8` | also `opts.bytes`: `.any`, `.ascii_printable`, `.utf8` |
//! | `struct` / tuple | every field (comptime fields are skipped) |
//! | `union(enum)` | a drawn tag, then its payload |
//! | `void` | `{}` |
//!
//! A `pub fn arbitrary(comptime S: type, src: *S, arena: std.mem.Allocator)
//! std.mem.Allocator.Error!@This()` declared on a struct, union or enum
//! replaces the mapping for that type (a registered strategy: invariants a
//! plain field-by-field draw cannot know).
//!
//! Anything else — pointers other than slices, untagged/extern/packed unions,
//! sentinel-terminated arrays, opaque, error sets, `anyframe`, comptime types
//! — is a COMPILE error naming the path to the offending type.
//!
//! Recursion is bounded: an optional or a slice is one level, and below
//! `max_depth` optionals are `null` and slices empty, so a type that contains
//! itself through either terminates.

const std = @import("std");

pub const ArbOptions = struct {
    /// Longest slice (in `.utf8` mode: most code points). Under 2^20.
    max_len: usize = 16,
    /// Levels of optional/slice nesting before they stop growing.
    max_depth: u8 = 4,
    /// How a `[]const u8` / `[]u8` is filled.
    bytes: enum { any, ascii_printable, utf8 } = .any,
    /// Whether a float draw may be NaN.
    float_nan: bool = true,
};

/// What `arbitrary` can fail with: the arena running out (an override may
/// only fail the same way).
pub const Error = std.mem.Allocator.Error;

/// A value of type `T` drawn from `src`; slices are allocated in `arena`
/// (give it an arena: nothing is freed one by one).
pub fn arbitrary(comptime T: type, comptime S: type, src: *S, arena: std.mem.Allocator, comptime opts: ArbOptions) Error!T {
    comptime {
        if (opts.max_len >= 1 << 20) @compileError("testkit.arbitrary: ArbOptions.max_len must be under 2^20");
        check(T, @typeName(T), &.{});
    }
    return gen(T, S, src, arena, opts, 0);
}

// ── compile-time validation (the only place that knows paths) ────────────────

fn hasOverride(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, "arbitrary"),
        else => false,
    };
}

fn unsupported(comptime T: type, comptime path: []const u8, comptime why: []const u8) noreturn {
    @compileError("testkit.arbitrary: " ++ why ++ ": " ++ @typeName(T) ++ " at " ++ path);
}

fn check(comptime T: type, comptime path: []const u8, comptime seen: []const type) void {
    @setEvalBranchQuota(1_000_000);
    inline for (seen) |s| if (s == T) return;
    const now = seen ++ &[_]type{T};
    if (hasOverride(T)) return;
    switch (@typeInfo(T)) {
        .bool, .int, .float, .void => {},
        .@"enum" => |e| if (e.field_names.len == 0 and e.mode == .exhaustive) unsupported(T, path, "enum with no values"),
        .optional => |o| check(o.child, path ++ ".?", now),
        .array => |a| {
            if (a.sentinel() != null) unsupported(T, path, "sentinel-terminated array");
            check(a.child, path ++ "[i]", now);
        },
        .vector => |v| check(v.child, path ++ "[i]", now),
        .pointer => |p| {
            if (p.size != .slice) unsupported(T, path, "pointer that is not a slice");
            if (p.attrs.@"volatile" or p.attrs.@"allowzero")
                unsupported(T, path, "slice with volatile/allowzero");
            if (p.attrs.@"align") |a| if (a != @alignOf(p.child)) unsupported(T, path, "slice with a non-default alignment");
            check(p.child, path ++ "[]", now);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types, s.field_attrs) |name, ft, attr| {
            if (attr.@"comptime") continue;
            check(ft, path ++ "." ++ name, now);
        },
        .@"union" => |u| {
            if (u.tag_type == null) unsupported(T, path, "untagged union");
            if (u.field_names.len == 0) unsupported(T, path, "union with no fields");
            inline for (u.field_names, u.field_types) |name, ft| check(ft, path ++ "." ++ name, now);
        },
        else => unsupported(T, path, "unsupported type"),
    }
}

// ── generation ───────────────────────────────────────────────────────────────

fn gen(comptime T: type, comptime S: type, src: *S, arena: std.mem.Allocator, comptime opts: ArbOptions, depth: u8) Error!T {
    if (comptime hasOverride(T)) return T.arbitrary(S, src, arena);
    switch (@typeInfo(T)) {
        .bool => return src.value(bool),
        .void => return {},
        .int => return drawInt(T, S, src),
        .float => return drawFloat(T, S, src, opts.float_nan),
        .@"enum" => |e| {
            const all = comptime std.enums.values(T);
            if (e.mode == .nonexhaustive and (all.len == 0 or src.valueRangeAtMost(u8, 0, 7) == 7))
                return @fromBackingInt(@intCast(drawInt(e.tag_type, S, src)));
            return all[src.index(all.len)];
        },
        .optional => |o| {
            if (depth >= opts.max_depth) return null;
            if (src.valueRangeAtMost(u8, 0, 7) == 0) return null;
            return try gen(o.child, S, src, arena, opts, depth + 1);
        },
        .array => |a| {
            var r: T = undefined;
            for (&r) |*e| e.* = try gen(a.child, S, src, arena, opts, depth);
            return r;
        },
        .vector => |v| {
            var r: T = undefined;
            inline for (0..v.len) |i| r[i] = try gen(v.child, S, src, arena, opts, depth);
            return r;
        },
        .pointer => return genSlice(T, S, src, arena, opts, depth),
        .@"struct" => |s| {
            var r: T = undefined;
            inline for (s.field_names, s.field_types, s.field_attrs) |name, ft, attr| {
                if (!attr.@"comptime") @field(r, name) = try gen(ft, S, src, arena, opts, depth);
            }
            return r;
        },
        .@"union" => |u| {
            const k = src.index(u.field_names.len);
            inline for (u.field_names, u.field_types, 0..) |name, ft, i| {
                if (k == i) return @unionInit(T, name, try gen(ft, S, src, arena, opts, depth));
            }
            unreachable; // k < field_names.len
        },
        else => comptime unsupported(T, @typeName(T), "unsupported type"),
    }
}

fn genSlice(comptime T: type, comptime S: type, src: *S, arena: std.mem.Allocator, comptime opts: ArbOptions, depth: u8) Error!T {
    const p = @typeInfo(T).pointer;
    const E = p.child;
    const sentinel = comptime p.sentinel();
    const n: usize = if (depth >= opts.max_depth) 0 else src.index(opts.max_len + 1);

    if (comptime E == u8 and opts.bytes == .utf8) {
        // Up to four bytes a code point; `n` counts code points.
        const buf = try arena.alloc(u8, n * 4);
        var len: usize = 0;
        for (0..n) |_| len += drawCodePoint(S, src, buf[len..][0..4]);
        return finishBytes(T, sentinel, arena, buf, len);
    }
    if (comptime E == u8 and opts.bytes == .ascii_printable) {
        const buf = try arena.alloc(u8, n);
        for (buf) |*b| b.* = src.valueRangeAtMost(u8, 0x20, 0x7e);
        return finishBytes(T, sentinel, arena, buf, n);
    }
    if (comptime E == u8) {
        const buf = try arena.alloc(u8, n);
        if (n != 0) src.bytes(buf);
        return finishBytes(T, sentinel, arena, buf, n);
    }
    if (comptime sentinel) |s| {
        const out = try arena.allocSentinel(E, n, s);
        for (out) |*e| e.* = try gen(E, S, src, arena, opts, depth + 1);
        return out;
    }
    const out = try arena.alloc(E, n);
    for (out) |*e| e.* = try gen(E, S, src, arena, opts, depth + 1);
    return out;
}

/// `buf[0..len]` as the slice type `T`: with a sentinel, a copy that has one.
fn finishBytes(comptime T: type, comptime sentinel: ?u8, arena: std.mem.Allocator, buf: []u8, len: usize) Error!T {
    if (comptime sentinel) |s| {
        const out = try arena.allocSentinel(u8, len, s);
        @memcpy(out, buf[0..len]);
        return out;
    }
    return buf[0..len];
}

/// One code point, UTF-8 encoded into `out`; its length. A surrogate is never
/// drawn. A class of 0 (what a zeroed tape reads) is ASCII.
fn drawCodePoint(comptime S: type, src: *S, out: *[4]u8) usize {
    const edges = [_]u21{ 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfffd, 0xffff, 0x10000, 0x10ffff };
    const cp: u21 = switch (src.valueRangeAtMost(u8, 0, 7)) {
        0, 1, 2, 3 => src.valueRangeAtMost(u21, 0, 0x7f),
        4 => 0x80 + src.valueRangeAtMost(u21, 0, 0x7ff - 0x80),
        5 => blk: {
            const c = 0x800 + src.valueRangeAtMost(u21, 0, 0xffff - 0x800 - 0x800);
            break :blk if (c >= 0xd800) c + 0x800 else c;
        },
        6 => 0x10000 + src.valueRangeAtMost(u21, 0, 0x10ffff - 0x10000),
        else => edges[src.index(edges.len)],
    };
    // Valid by construction (no surrogate, nothing past 0x10ffff).
    return std.unicode.utf8Encode(cp, out) catch unreachable;
}

// ── scalars ──────────────────────────────────────────────────────────────────

fn drawInt(comptime T: type, comptime S: type, src: *S) T {
    const info = @typeInfo(T).int;
    if (info.bits == 0) return 0;
    const lo = std.math.minInt(T);
    const hi = std.math.maxInt(T);
    const one: T = if (info.signedness == .signed and info.bits == 1) -1 else 1;
    return switch (src.valueRangeAtMost(u8, 0, 63)) {
        0 => 0,
        1 => one,
        2 => if (info.signedness == .signed) -1 else hi,
        3 => lo,
        4 => hi,
        5 => lo +% 1,
        6 => hi -% 1,
        else => src.value(T),
    };
}

fn drawFloat(comptime T: type, comptime S: type, src: *S, comptime nan: bool) T {
    const inf = std.math.inf(T);
    const sel = src.valueRangeAtMost(u8, 0, 63);
    const v: T = switch (sel) {
        0 => 0.0,
        1 => 1.0,
        2 => -1.0,
        3 => std.math.copysign(@as(T, 0.0), @as(T, -1.0)),
        4 => inf,
        5 => -inf,
        6 => if (nan) std.math.nan(T) else 0.0,
        7 => std.math.floatTrueMin(T),
        8 => std.math.floatMax(T),
        9 => -std.math.floatMax(T),
        10 => std.math.floatMin(T),
        11 => @floatFromInt(src.valueRangeAtMost(u16, 0, 1024)),
        else => if (T == f80) @as(T, @floatCast(@as(f64, @bitCast(src.value(u64))))) else @bitCast(src.value(@Int(.unsigned, @bitSizeOf(T)))),
    };
    return if (!nan and std.math.isNan(v)) 0.0 else v;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const driver = @import("fuzz_driver.zig");
const shrinker = @import("shrink.zig");
const child_mod = @import("child.zig");
const ScriptSource = @import("fuzz.zig").ScriptSource;
const Rng = driver.Rng;

const Color = enum { red, green, blue };
const Open = enum(u8) { a = 1, b = 2, _ };
const Shape = union(enum) { dot, circle: u8, rect: struct { w: u16, h: u16 } };
const Mixed = struct {
    b: bool,
    i: i8,
    u: u16,
    f: f32,
    c: Color,
    o: ?u8,
    arr: [3]u8,
    v: @Vector(2, i16),
    s: []const u8,
    sh: Shape,
    t: struct { u8, bool },
    open: Open,
    zero: u0,
    nothing: void,
};

fn newArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "every mapping row is reached, and the pieces have the right shape" {
    var prng = std.Random.DefaultPrng.init(1);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    var seen_true = false;
    var seen_false = false;
    var null_n: usize = 0;
    var some_n: usize = 0;
    var colors: [3]bool = @splat(false);
    var shapes: [3]bool = @splat(false);
    var empty = false;
    var longest: usize = 0;
    var unnamed = false;
    var named = false;
    for (0..4000) |_| {
        const m = try arbitrary(Mixed, Rng, &rng, arena.allocator(), .{});
        if (m.b) seen_true = true else seen_false = true;
        if (m.o == null) null_n += 1 else some_n += 1;
        colors[@backingInt(m.c)] = true;
        shapes[@backingInt(std.meta.activeTag(m.sh))] = true;
        if (m.s.len == 0) empty = true;
        longest = @max(longest, m.s.len);
        const raw = @backingInt(m.open);
        if (raw == 1 or raw == 2) named = true else unnamed = true;
        try testing.expect(m.zero == 0);
    }
    try testing.expect(seen_true and seen_false);
    try testing.expect(null_n > 0 and some_n > null_n); // about 1 in 8 is null
    try testing.expect(colors[0] and colors[1] and colors[2]);
    try testing.expect(shapes[0] and shapes[1] and shapes[2]);
    try testing.expect(empty);
    try testing.expectEqual(@as(usize, 16), longest); // default max_len, reached
    try testing.expect(named and unnamed);
}

fn expectEdges(comptime T: type, edges: []const T) !void {
    var prng = std.Random.DefaultPrng.init(7);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    const hit = try testing.allocator.alloc(bool, edges.len);
    defer testing.allocator.free(hit);
    @memset(hit, false);
    for (0..10_000) |_| {
        const v = try arbitrary(T, Rng, &rng, arena.allocator(), .{});
        for (edges, 0..) |e, k| {
            if (std.meta.eql(v, e)) hit[k] = true;
        }
    }
    for (hit, 0..) |h, k| {
        if (!h) std.debug.print("edge {any} of {s} never drawn\n", .{ edges[k], @typeName(T) });
        try testing.expect(h);
    }
}

test "integer edges are reached within 10 000 draws" {
    try expectEdges(u8, &.{ 0, 1, 254, 255 });
    try expectEdges(i8, &.{ -128, -127, -1, 0, 1, 126, 127 });
    try expectEdges(u32, &.{ 0, 1, 0xffff_fffe, 0xffff_ffff });
    try expectEdges(i64, &.{ std.math.minInt(i64), std.math.minInt(i64) + 1, -1, 0, 1, std.math.maxInt(i64) - 1, std.math.maxInt(i64) });
    try expectEdges(u128, &.{ 0, 1, std.math.maxInt(u128) - 1, std.math.maxInt(u128) });
    try expectEdges(i1, &.{ -1, 0 });
    try expectEdges(u1, &.{ 0, 1 });
}

fn expectFloatEdges(comptime F: type) !void {
    const U = @Int(.unsigned, @bitSizeOf(F));
    var prng = std.Random.DefaultPrng.init(11);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    const edges = [_]F{
        0.0,                                          1.0,                  -1.0,
        std.math.copysign(@as(F, 0.0), @as(F, -1.0)), std.math.inf(F),      -std.math.inf(F),
        std.math.floatTrueMin(F),                     std.math.floatMax(F), -std.math.floatMax(F),
        std.math.floatMin(F),
    };
    var hit: [edges.len]bool = @splat(false);
    var nan = false;
    for (0..10_000) |_| {
        const v = try arbitrary(F, Rng, &rng, arena.allocator(), .{});
        if (std.math.isNan(v)) nan = true;
        for (edges, 0..) |e, k| {
            if (@as(U, @bitCast(v)) == @as(U, @bitCast(e))) hit[k] = true;
        }
    }
    try testing.expect(nan);
    for (hit, 0..) |h, k| {
        if (!h) std.debug.print("float edge #{d} of {s} never drawn\n", .{ k, @typeName(F) });
        try testing.expect(h);
    }
}

test "float edges are reached: 0, -0.0, +-inf, NaN, smallest subnormal, max" {
    try expectFloatEdges(f16);
    try expectFloatEdges(f32);
    try expectFloatEdges(f64);
    try expectFloatEdges(f128);
}

test "float_nan = false never yields NaN, and keeps the infinities" {
    var prng = std.Random.DefaultPrng.init(3);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    var inf = false;
    // f16: a NaN is 1 in 32 uniform bit patterns, so the filter is exercised.
    for (0..20_000) |_| {
        const v = try arbitrary(f16, Rng, &rng, arena.allocator(), .{ .float_nan = false });
        try testing.expect(!std.math.isNan(v));
        if (std.math.isInf(v)) inf = true;
    }
    try testing.expect(inf);
    // f80 goes through an f64 draw and is still a valid value.
    const w = try arbitrary(f80, Rng, &rng, arena.allocator(), .{ .float_nan = false });
    try testing.expect(!std.math.isNan(w));
}

test "determinism: the same seed gives the same value" {
    var a1 = newArena();
    defer a1.deinit();
    var a2 = newArena();
    defer a2.deinit();
    var p1 = std.Random.DefaultPrng.init(99);
    var p2 = std.Random.DefaultPrng.init(99);
    var r1: Rng = .{ .r = p1.random() };
    var r2: Rng = .{ .r = p2.random() };
    for (0..200) |_| {
        // No NaN: expectEqualDeep would call two NaNs different.
        const x = try arbitrary(Mixed, Rng, &r1, a1.allocator(), .{ .float_nan = false });
        const y = try arbitrary(Mixed, Rng, &r2, a2.allocator(), .{ .float_nan = false });
        try testing.expectEqualDeep(x, y);
    }
}

test "a script of zeros is the smallest value: false, 0, first tag, null, empty" {
    var src: ScriptSource = .init(&@as([256]u8, @splat(0)));
    var arena = newArena();
    defer arena.deinit();
    const m = try arbitrary(Mixed, ScriptSource, &src, arena.allocator(), .{});
    try testing.expect(!m.b);
    try testing.expectEqual(@as(i8, 0), m.i);
    try testing.expectEqual(@as(u16, 0), m.u);
    try testing.expectEqual(@as(f32, 0.0), m.f);
    try testing.expectEqual(Color.red, m.c);
    try testing.expectEqual(@as(?u8, null), m.o);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, &m.arr);
    try testing.expectEqual(@as(usize, 0), m.s.len);
    try testing.expectEqual(Shape.dot, m.sh);
    try testing.expectEqual(@as(u8, 0), m.t[0]);
    try testing.expect(!m.t[1]);
}

test "it runs under std.testing.Smith too" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var arena = newArena();
            defer arena.deinit();
            const m = try arbitrary(Mixed, testing.Smith, smith, arena.allocator(), .{});
            std.mem.doNotOptimizeAway(m.i);
        }
    }.f, .{});
}

test "bytes modes: any, ascii_printable, utf8 (always valid, 4-byte code points included)" {
    var prng = std.Random.DefaultPrng.init(5);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    var high = false;
    for (0..3000) |_| {
        const s = try arbitrary([]const u8, Rng, &rng, arena.allocator(), .{ .bytes = .any });
        try testing.expect(s.len <= 16);
        for (s) |c| if (c >= 0x80) {
            high = true;
        };
    }
    try testing.expect(high); // not forced to ASCII
    for (0..3000) |_| {
        const s = try arbitrary([]const u8, Rng, &rng, arena.allocator(), .{ .bytes = .ascii_printable, .max_len = 40 });
        try testing.expect(s.len <= 40);
        for (s) |c| try testing.expect(c >= 0x20 and c <= 0x7e);
    }
    var lead: [4]bool = @splat(false); // 1-, 2-, 3- and 4-byte code points
    var surrogate_edge = false;
    for (0..3000) |_| {
        const s = try arbitrary([]const u8, Rng, &rng, arena.allocator(), .{ .bytes = .utf8, .max_len = 12 });
        try testing.expect(std.unicode.utf8ValidateSlice(s));
        try testing.expect(try std.unicode.utf8CountCodepoints(s) <= 12);
        var it = (try std.unicode.Utf8View.init(s)).iterator();
        while (it.nextCodepoint()) |cp| {
            lead[(std.unicode.utf8CodepointSequenceLength(cp) catch unreachable) - 1] = true;
            if (cp == 0xd7ff or cp == 0xe000) surrogate_edge = true;
        }
    }
    try testing.expect(lead[0] and lead[1] and lead[2] and lead[3]);
    try testing.expect(surrogate_edge);
    // A sentinel slice carries its sentinel, in every mode.
    inline for (.{ .any, .ascii_printable, .utf8 }) |mode| {
        for (0..200) |_| {
            const z = try arbitrary([:0]const u8, Rng, &rng, arena.allocator(), .{ .bytes = mode });
            try testing.expectEqual(@as(u8, 0), z[z.len]);
        }
    }
}

test "slices respect max_len, hold other element types, and arrays/tuples fill every slot" {
    var prng = std.Random.DefaultPrng.init(8);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    var longest: usize = 0;
    for (0..2000) |_| {
        const xs = try arbitrary([]const u16, Rng, &rng, arena.allocator(), .{ .max_len = 5 });
        try testing.expect(xs.len <= 5);
        longest = @max(longest, xs.len);
        const ys = try arbitrary([]const []const u8, Rng, &rng, arena.allocator(), .{ .max_len = 3 });
        try testing.expect(ys.len <= 3);
        for (ys) |y| try testing.expect(y.len <= 3);
    }
    try testing.expectEqual(@as(usize, 5), longest);
    // A mutable slice and a packed struct, which a plain `@field` can assign.
    const P = packed struct { a: u3, b: bool, c: u4 };
    const ps = try arbitrary([]P, Rng, &rng, arena.allocator(), .{});
    try testing.expect(ps.len <= 16);
}

const Tree = struct { v: u8, kids: []const Tree, extra: ?[]const Tree };

fn depthOf(t: Tree) usize {
    var d: usize = 1;
    for (t.kids) |k| d = @max(d, 1 + depthOf(k));
    if (t.extra) |e| for (e) |k| {
        d = @max(d, 1 + depthOf(k));
    };
    return d;
}

const Expr = union(enum) { num: i8, add: []const Expr, neg: ?[]const Expr };

fn exprDepth(e: Expr) usize {
    switch (e) {
        .num => return 1,
        .add => |xs| {
            var d: usize = 1;
            for (xs) |x| d = @max(d, 1 + exprDepth(x));
            return d;
        },
        .neg => |m| {
            var d: usize = 1;
            if (m) |xs| for (xs) |x| {
                d = @max(d, 1 + exprDepth(x));
            };
            return d;
        },
    }
}

test "a recursive type terminates, within max_depth" {
    var prng = std.Random.DefaultPrng.init(21);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    var deepest: usize = 0;
    for (0..1500) |_| {
        const t = try arbitrary(Tree, Rng, &rng, arena.allocator(), .{ .max_len = 3 });
        const d = depthOf(t);
        deepest = @max(deepest, d);
        // The root is depth 0; slices of kids go one level a step, so the
        // deepest node is at depth `max_depth` (a 5-node chain at most).
        try testing.expect(d <= 4 + 1);
    }
    try testing.expect(deepest >= 3);
    var deepest_e: usize = 0;
    for (0..1500) |_| {
        const e = try arbitrary(Expr, Rng, &rng, arena.allocator(), .{ .max_len = 3, .max_depth = 2 });
        deepest_e = @max(deepest_e, exprDepth(e));
        try testing.expect(exprDepth(e) <= 2 + 1);
    }
    try testing.expect(deepest_e >= 2);
}

test "max_depth = 0: optionals are null and slices empty" {
    var prng = std.Random.DefaultPrng.init(22);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    for (0..500) |_| {
        const t = try arbitrary(Tree, Rng, &rng, arena.allocator(), .{ .max_depth = 0 });
        try testing.expectEqual(@as(usize, 0), t.kids.len);
        try testing.expectEqual(@as(?[]const Tree, null), t.extra);
        const o = try arbitrary(?u8, Rng, &rng, arena.allocator(), .{ .max_depth = 0 });
        try testing.expectEqual(@as(?u8, null), o);
    }
}

const Even = struct {
    n: u32,
    pub fn arbitrary(comptime S: type, src: *S, _: std.mem.Allocator) Error!Even {
        return .{ .n = src.valueRangeAtMost(u32, 0, 1000) * 2 };
    }
};
const Holder = struct { a: Even, l: []const Even, o: ?Even };

test "a type's own `arbitrary` decl overrides the mapping" {
    var prng = std.Random.DefaultPrng.init(31);
    var rng: Rng = .{ .r = prng.random() };
    var arena = newArena();
    defer arena.deinit();
    var n: usize = 0;
    for (0..500) |_| {
        const h = try arbitrary(Holder, Rng, &rng, arena.allocator(), .{});
        try testing.expect(h.a.n % 2 == 0 and h.a.n <= 2000);
        for (h.l) |e| {
            try testing.expect(e.n % 2 == 0 and e.n <= 2000);
            n += 1;
        }
        if (h.o) |e| try testing.expect(e.n % 2 == 0);
    }
    try testing.expect(n > 0);
    const top = try arbitrary(Even, Rng, &rng, arena.allocator(), .{});
    try testing.expect(top.n % 2 == 0);
}

test "an allocation failure is an error, not a panic" {
    var prng = std.Random.DefaultPrng.init(41);
    var rng: Rng = .{ .r = prng.random() };
    var fa: testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, arbitrary([8][]const u8, Rng, &rng, fa.allocator(), .{}));
}

// ── a failing property shrinks to a small typed value ────────────────────────

const Rec = struct { x: i32, name: []const u8, opt: ?u8, tag: Color, pair: [2]u8 };

fn recHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const r = try arbitrary(Rec, S, src, arena.allocator(), .{});
    // The deliberate bug: a large x with a name of at least two bytes.
    if (r.x > 1000 and r.name.len >= 2) return error.Bug;
}

test "a failing property over a struct shrinks to a small value" {
    if (!child_mod.supported) return error.SkipZigTest;
    var seed: u64 = 0;
    const found = while (seed < 100_000) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        recHarness(Rng, &rng, testing.allocator) catch break true;
    } else false;
    try testing.expect(found);
    const r = try shrinker.shrink(recHarness, testing.allocator, .{ .name = "rec", .seed = seed, .limit_ms = 5000, .budget_ms = 600_000, .report = false });
    defer testing.allocator.free(r.tape);
    try testing.expect(r.tape.len < r.from);
    // The shrunk tape is still the bug, and its value is the small one.
    try testing.expectError(error.Bug, shrinker.replayHere(recHarness, testing.allocator, r.tape, false));
    var t: driver.Tape = .{ .mode = .replay, .buf = r.tape, .len = r.tape.len };
    var prng = std.Random.DefaultPrng.init(0);
    var rng: Rng = .{ .r = prng.random(), .tape = &t };
    var arena = newArena();
    defer arena.deinit();
    const v = try arbitrary(Rec, Rng, &rng, arena.allocator(), .{});
    try testing.expect(v.x > 1000);
    try testing.expectEqual(@as(usize, 2), v.name.len); // not one byte more
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, v.name); // and the smallest ones
    try testing.expectEqual(@as(?u8, null), v.opt);
    try testing.expectEqual(Color.red, v.tag);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, &v.pair);
}
