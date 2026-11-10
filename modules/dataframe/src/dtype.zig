// SPDX-License-Identifier: MIT
//! Numeric width types (wave W11): which `ColumnType`s are integers or floats, their
//! ranges, the type two operands meet in (`supertype`), and a cell fitted to a width.
//! `.int` is Int64 and `.float` Float64; `int8`..`uint64` and `float32` hold their own
//! arrays (`frame.conform`). The rules are polars 2.1's unless a doc comment says
//! otherwise; the oracle `tools/oracle2j.py` freezes what the engines answer.

const std = @import("std");
const vm = @import("value.zig");
const ColumnType = vm.ColumnType;
const Value = vm.Value;

/// Int64 and every integer width.
pub fn isInteger(t: ColumnType) bool {
    return switch (t) {
        .int, .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 => true,
        else => false,
    };
}

/// A signed integer type (Int64 included).
pub fn isSigned(t: ColumnType) bool {
    return switch (t) {
        .int, .int8, .int16, .int32 => true,
        else => false,
    };
}

pub fn isUnsigned(t: ColumnType) bool {
    return switch (t) {
        .uint8, .uint16, .uint32, .uint64 => true,
        else => false,
    };
}

/// Float64 or Float32.
pub fn isFloat(t: ColumnType) bool {
    return t == .float or t == .float32;
}

/// An integer or float type (not decimal, not temporal).
pub fn isNumeric(t: ColumnType) bool {
    return isInteger(t) or isFloat(t);
}

/// A type with its own narrow array: every integer width but Int64, and Float32.
pub fn isWidth(t: ColumnType) bool {
    return switch (t) {
        .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => true,
        else => false,
    };
}

/// Bits of a numeric type; 0 for anything else.
pub fn bits(t: ColumnType) u8 {
    return switch (t) {
        .int8, .uint8 => 8,
        .int16, .uint16 => 16,
        .int32, .uint32, .float32 => 32,
        .int, .uint64, .float => 64,
        else => 0,
    };
}

/// The Zig integer an integer type stores.
pub fn IntOf(comptime t: ColumnType) type {
    return switch (t) {
        .int => i64,
        .int8 => i8,
        .int16 => i16,
        .int32 => i32,
        .uint8 => u8,
        .uint16 => u16,
        .uint32 => u32,
        .uint64 => u64,
        else => @compileError("not an integer type"),
    };
}

/// Smallest value of an integer type (0 for a non-integer).
pub fn intMin(t: ColumnType) i128 {
    return switch (t) {
        .int => std.math.minInt(i64),
        .int8 => std.math.minInt(i8),
        .int16 => std.math.minInt(i16),
        .int32 => std.math.minInt(i32),
        else => 0,
    };
}

/// Largest value of an integer type (0 for a non-integer).
pub fn intMax(t: ColumnType) i128 {
    return switch (t) {
        .int => std.math.maxInt(i64),
        .int8 => std.math.maxInt(i8),
        .int16 => std.math.maxInt(i16),
        .int32 => std.math.maxInt(i32),
        .uint8 => std.math.maxInt(u8),
        .uint16 => std.math.maxInt(u16),
        .uint32 => std.math.maxInt(u32),
        .uint64 => std.math.maxInt(u64),
        else => 0,
    };
}

/// polars' short name of a numeric type (`i8` … `u64`, `f32`, `f64`); the tag name otherwise.
pub fn name(t: ColumnType) []const u8 {
    return switch (t) {
        .int => "i64",
        .int8 => "i8",
        .int16 => "i16",
        .int32 => "i32",
        .uint8 => "u8",
        .uint16 => "u16",
        .uint32 => "u32",
        .uint64 => "u64",
        .float => "f64",
        .float32 => "f32",
        else => @tagName(t),
    };
}

/// The signed integer type of `n` bits (8..64), Int64 past that.
fn signedOf(n: u8) ColumnType {
    return switch (n) {
        0...8 => .int8,
        9...16 => .int16,
        17...32 => .int32,
        else => .int,
    };
}

fn unsignedOf(n: u8) ColumnType {
    return switch (n) {
        0...8 => .uint8,
        9...16 => .uint16,
        17...32 => .uint32,
        else => .uint64,
    };
}

/// The type two numeric operands meet in (arithmetic, concat, when/then, coalesce), or
/// null when one is not numeric. polars' supertype, but Int64 or a narrower signed type
/// with UInt64 is Float64 (polars says Int128, which this module does not have; pandas
/// says float64). A signed and an unsigned type meet in the signed type wide enough for
/// both (i8 with u8: i16); Float32 with an integer of 16 bits or less stays Float32,
/// with a wider one it is Float64.
pub fn supertype(a: ColumnType, b: ColumnType) ?ColumnType {
    if (!isNumeric(a) or !isNumeric(b)) return null;
    if (a == b) return a;
    if (isFloat(a) or isFloat(b)) {
        if (a == .float or b == .float) return .float;
        const other = if (a == .float32) b else a; // the side that is not Float32
        if (other == .float32) return .float32;
        return if (bits(other) <= 16) .float32 else .float;
    }
    const sa = isSigned(a);
    const sb = isSigned(b);
    if (sa == sb) {
        const n = @max(bits(a), bits(b));
        return if (sa) signedOf(n) else unsignedOf(n);
    }
    const s = if (sa) a else b;
    const u = if (sa) b else a;
    if (bits(s) > bits(u)) return s;
    if (bits(u) >= 64) return .float;
    return signedOf(bits(u) * 2);
}

/// Whether the integer `x` is a value of the integer type `t`.
pub fn fits(x: i128, t: ColumnType) bool {
    return isInteger(t) and x >= intMin(t) and x <= intMax(t);
}

/// The cell holding the integer `x` (`.int`, or `.uint` above `maxInt(i64)`), whatever type.
pub fn intValue(x: i128) ?Value {
    if (std.math.cast(i64, x)) |i| return .{ .int = i };
    if (std.math.cast(u64, x)) |u| return .{ .uint = u };
    return null;
}

/// `x` as a cell of the integer type `t`, or null when it is out of `t`'s range (the
/// module's overflow rule: null, where both engines wrap).
pub fn fitInt(x: i128, t: ColumnType) ?Value {
    if (!fits(x, t)) return null;
    return intValue(x);
}

/// `x` wrapped into the integer type `t` (two's complement, polars `wrap_numerical`,
/// numpy `astype`): its low `bits(t)` bits read as `t`.
pub fn wrapInt(x: i128, t: ColumnType) Value {
    const u: u128 = @bitCast(x);
    return switch (t) {
        .int8 => .{ .int = @as(i8, @bitCast(@as(u8, @truncate(u)))) },
        .int16 => .{ .int = @as(i16, @bitCast(@as(u16, @truncate(u)))) },
        .int32 => .{ .int = @as(i32, @bitCast(@as(u32, @truncate(u)))) },
        .uint8 => .{ .int = @as(u8, @truncate(u)) },
        .uint16 => .{ .int = @as(u16, @truncate(u)) },
        .uint32 => .{ .int = @as(u32, @truncate(u)) },
        .uint64 => intValue(@as(u64, @truncate(u))).?, // a u64 is always a cell
        else => .{ .int = @as(i64, @bitCast(@as(u64, @truncate(u)))) },
    };
}

/// The integer a numeric cell holds exactly as an `i128`: `.int`, `.uint`; a float or
/// decimal only when it is whole and within ±2^127 (callers that truncate use `truncInt`).
pub fn exactI128(v: Value) ?i128 {
    return switch (v) {
        .int => |i| i,
        .uint => |u| u,
        .float => |f| if (f == @trunc(f)) Value.floatToInt(i128, f) else null,
        .decimal => |r| if (@rem(r, vm.decimal_scale) == 0) @divExact(r, vm.decimal_scale) else null,
        else => null,
    };
}

/// A numeric cell truncated toward zero to an `i128` (pandas' and polars' float → int
/// cast), null for NaN, infinity, a value past ±2^127 or a non-numeric cell.
pub fn truncInt(v: Value) ?i128 {
    return switch (v) {
        .int => |i| i,
        .uint => |u| u,
        .float => |f| Value.floatToInt(i128, f),
        .decimal => |r| @divTrunc(r, vm.decimal_scale),
        else => null,
    };
}

/// `f` rounded to the nearest f32 (beyond its range: ±infinity, as polars' cast), back
/// as the f64 cell that holds it exactly.
pub fn roundF32(f: f64) f64 {
    const x: f32 = @floatCast(f);
    return x;
}

test "supertype follows polars, Int64 with UInt64 is Float64" {
    const t = std.testing;
    try t.expectEqual(ColumnType.int16, supertype(.int8, .uint8).?);
    try t.expectEqual(ColumnType.int16, supertype(.uint8, .int16).?);
    try t.expectEqual(ColumnType.int, supertype(.int32, .uint32).?);
    try t.expectEqual(ColumnType.float, supertype(.int, .uint64).?);
    try t.expectEqual(ColumnType.uint64, supertype(.uint8, .uint64).?);
    try t.expectEqual(ColumnType.float32, supertype(.uint8, .float32).?);
    try t.expectEqual(ColumnType.float, supertype(.int32, .float32).?);
    try t.expectEqual(ColumnType.float, supertype(.float32, .float).?);
    try t.expect(supertype(.int, .text) == null);
}

test "fitInt is null out of range, wrapInt wraps" {
    const t = std.testing;
    try t.expect(fitInt(128, .int8) == null);
    try t.expectEqual(@as(i64, -128), fitInt(-128, .int8).?.int);
    try t.expectEqual(@as(u64, std.math.maxInt(u64)), fitInt(std.math.maxInt(u64), .uint64).?.uint);
    try t.expect(fitInt(-1, .uint64) == null);
    try t.expectEqual(@as(i64, 44), wrapInt(300, .int8).int);
    try t.expectEqual(@as(i64, 255), wrapInt(-1, .uint8).int);
    try t.expectEqual(@as(u64, std.math.maxInt(u64)), wrapInt(-1, .uint64).uint);
}
