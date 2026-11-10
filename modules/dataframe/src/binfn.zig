// SPDX-License-Identifier: MIT
//! `.binary` cell functions (polars `Expr.bin`, `Binary`): a cell is `Value.text` holding bytes with
//! no UTF-8 promise; every function here reads bytes and never assumes text.
//!
//! polars 2.1 is the reference for each rule (probe run 2026-11-10): `contains`, `starts_with`,
//! `ends_with` (an empty pattern is true), `size` (UInt32 for bytes, Float64 for the larger
//! units), `get` (negative from the end), `head`/`tail`/`slice` (negative counts and offsets
//! count from the end), `encode` and `reinterpret` (the cell must be exactly the width's
//! size). Original work of the zig-libs authors (MIT); polars' documentation was read, no source.

const std = @import("std");
const vm = @import("value.zig");
const sf = @import("strfn.zig");
const Value = vm.Value;
const ColumnType = vm.ColumnType;

/// What a cell function can fail with.
pub const Error = sf.Error;

/// The unit of `size`: bytes, then kibi-, mebi-, gibi-, tebibytes (polars `bin.size(unit)`).
pub const SizeUnit = enum { b, kb, mb, gb, tb };

/// `Expr.bin`: one operation over a `.binary` operand (`Expr.bin`). A null cell is null.
pub const BinOp = union(enum) {
    /// Whether the bytes contain / start with / end with the literal `pat` (an empty one: true).
    contains: []const u8,
    starts_with: []const u8,
    ends_with: []const u8,
    /// The length: an int for `.b`, a float (length / 1024^k) for the other units.
    size: SizeUnit,
    /// Byte `i` as an int, negative from the end; out of range null (polars' default raises,
    /// which a per-cell function cannot; `null_on_oob=True` is this).
    get: i64,
    /// The first `n` bytes; a negative `n` all but the last `-n`. A `.binary` again.
    head: i64,
    /// The last `n` bytes; a negative `n` all but the first `-n`.
    tail: i64,
    /// `length` bytes from `offset` (negative: from the end; null `length`: to the end),
    /// clamped to the cell, as polars' `slice`.
    slice: struct { offset: i64, length: ?u64 = null },
    /// Lowercase hex or padded base64 text of the bytes (polars `bin.encode`).
    encode: sf.Encoding,
    /// The bytes as one number of the width `to` (`.int8` … `.uint64`, `.int` is Int64,
    /// `.float32`, `.float` Float64); a cell of another length is null (polars).
    reinterpret: struct { to: ColumnType, big_endian: bool = false },
};

/// Whether `t` is a type `reinterpret` can produce.
pub fn isReinterpretType(t: ColumnType) bool {
    return switch (t) {
        .int, .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float, .float32 => true,
        else => false,
    };
}

/// Bytes of one value of `t` (`isReinterpretType`).
fn widthOf(t: ColumnType) usize {
    return switch (t) {
        .int8, .uint8 => 1,
        .int16, .uint16 => 2,
        .int32, .uint32, .float32 => 4,
        else => 8,
    };
}

/// `t[start .. end]` as a `.binary` cell.
fn view(t: []const u8, start: usize, end: usize) Value {
    return .{ .text = t[start..end] };
}

/// The cell function: `op` over the bytes `t`. `a` allocates the text of `encode`.
pub fn cell(a: std.mem.Allocator, t: []const u8, op: BinOp) Error!Value {
    switch (op) {
        .contains => |p| return .{ .bool = std.mem.find(u8, t, p) != null },
        .starts_with => |p| return .{ .bool = std.mem.startsWith(u8, t, p) },
        .ends_with => |p| return .{ .bool = std.mem.endsWith(u8, t, p) },
        .size => |u| {
            if (u == .b) return .{ .int = @intCast(t.len) }; // a slice length fits i64
            const shift: u6 = switch (u) {
                .kb => 10,
                .mb => 20,
                .gb => 30,
                else => 40,
            };
            return .{ .float = @as(f64, @floatFromInt(t.len)) / @as(f64, @floatFromInt(@as(u64, 1) << shift)) };
        },
        .get => |i| {
            const n: i128 = t.len;
            const k: i128 = if (i < 0) n + i else i;
            if (k < 0 or k >= n) return .null;
            return .{ .int = t[@intCast(k)] };
        },
        .head => |n| {
            const k = count(t.len, n);
            return view(t, 0, k);
        },
        .tail => |n| {
            const k = count(t.len, n);
            return view(t, t.len - k, t.len);
        },
        .slice => |s| {
            const n: i128 = t.len;
            const start: i128 = if (s.offset < 0) n + s.offset else s.offset;
            const end: i128 = if (s.length) |l| start + l else n;
            const lo: usize = @intCast(std.math.clamp(start, 0, n));
            const hi: usize = @intCast(std.math.clamp(end, 0, n));
            return if (hi <= lo) view(t, 0, 0) else view(t, lo, hi);
        },
        .encode => |how| return .{ .text = try sf.encode(a, t, how) },
        .reinterpret => |r| return reinterpret(t, r.to, r.big_endian),
    }
}

/// How many bytes `head` or `tail` keeps of `len`: `n` bytes, a negative `n` all but `-n`,
/// never past the cell.
fn count(len: usize, n: i64) usize {
    if (n >= 0) return @intCast(@min(@as(u64, @intCast(n)), len));
    const drop: u64 = @abs(n);
    return if (drop >= len) 0 else len - @as(usize, @intCast(drop));
}

fn reinterpret(t: []const u8, to: ColumnType, big: bool) Value {
    if (!isReinterpretType(to) or t.len != widthOf(to)) return .null;
    const endian: std.builtin.Endian = if (big) .big else .little;
    switch (to) {
        inline .int8, .int16, .int32, .int, .uint8, .uint16, .uint32 => |ty| {
            const T = switch (ty) {
                .int8 => i8,
                .int16 => i16,
                .int32 => i32,
                .int => i64,
                .uint8 => u8,
                .uint16 => u16,
                else => u32,
            };
            return .{ .int = std.mem.readInt(T, t[0..@sizeOf(T)], endian) };
        },
        .uint64 => {
            const x = std.mem.readInt(u64, t[0..8], endian);
            return if (x <= std.math.maxInt(i64)) .{ .int = @intCast(x) } else .{ .uint = x };
        },
        .float32 => return .{ .float = @as(f32, @bitCast(std.mem.readInt(u32, t[0..4], endian))) },
        else => return .{ .float = @as(f64, @bitCast(std.mem.readInt(u64, t[0..8], endian))) },
    }
}

/// polars' table form of a binary cell: `b"` then each byte, printable ASCII (`!` … `~`) as it
/// is, every other byte (control characters, space, DEL, 0x80 and up) as `\xNN` in lowercase
/// hex, then `"`. polars escapes neither `"` nor `\` here, so the form is not reversible.
pub fn displayInto(a: std.mem.Allocator, t: []const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, "b\"");
    for (t) |c| {
        if (c >= 0x21 and c <= 0x7e) {
            try out.append(a, c);
        } else {
            const digits = "0123456789abcdef";
            try out.appendSlice(a, &.{ '\\', 'x', digits[c >> 4], digits[c & 15] });
        }
    }
    try out.append(a, '"');
    return out.toOwnedSlice(a);
}

/// Python's `repr(bytes)`, the form polars' `glimpse` prints: `b'...'` (double quotes when the
/// bytes hold a `'` and no `"`), `\t \n \r \\ \'` and `\xNN` for every other byte outside
/// ` ` … `~`.
pub fn reprInto(a: std.mem.Allocator, t: []const u8) std.mem.Allocator.Error![]const u8 {
    const has_single = std.mem.findScalar(u8, t, '\'') != null;
    const has_double = std.mem.findScalar(u8, t, '"') != null;
    const q: u8 = if (has_single and !has_double) '"' else '\'';
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, &.{ 'b', q });
    for (t) |c| switch (c) {
        '\t' => try out.appendSlice(a, "\\t"),
        '\n' => try out.appendSlice(a, "\\n"),
        '\r' => try out.appendSlice(a, "\\r"),
        '\\' => try out.appendSlice(a, "\\\\"),
        0x20...0x26, 0x28...0x5b, 0x5d...0x7e => try out.append(a, c),
        '\'' => if (q == '\'') try out.appendSlice(a, "\\'") else try out.append(a, c),
        else => {
            const digits = "0123456789abcdef";
            try out.appendSlice(a, &.{ '\\', 'x', digits[c >> 4], digits[c & 15] });
        },
    };
    try out.append(a, q);
    return out.toOwnedSlice(a);
}
