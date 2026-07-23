// SPDX-License-Identifier: MIT

//! dnp3.records — one table-driven codec for every static and event object
//! variation the outstation speaks (IEEE 1815-2012 Part 4/5 object library).
//!
//! `objects.zig` gives each of the handful of groups the base module needed a
//! hand-written struct. That does not scale to the ~40 group/variation pairs
//! an outstation has to produce: binary, double-bit binary, binary output
//! status, counter, frozen counter, analog input and analog output status,
//! each in with-flags / without-flags / with-absolute-time / with-relative-
//! time / 16-bit / 32-bit / float shapes.
//!
//! So this module describes a variation as a **layout** — does it carry a
//! flags octet, what width and type is the value, does a timestamp follow —
//! and encodes or decodes any of them with one function each. Adding a
//! variation is one table row, not a new struct.
//!
//! `objects.zig` is untouched and still the canonical home of the object
//! *header* framing; this module is purely about the per-object records that
//! follow a header.

const std = @import("std");
const objects = @import("objects.zig");

pub const Flags = objects.Flags;

// ── point kinds ─────────────────────────────────────────────────────────────

/// The seven point types an outstation exposes, in the order the class-0 scan
/// walks them (§ the conventional order a master expects: binary inputs
/// first, analog outputs last).
pub const PointKind = enum {
    binary_input,
    double_bit_input,
    binary_output_status,
    counter,
    frozen_counter,
    analog_input,
    analog_output_status,

    /// The static object group for this point type.
    pub fn staticGroup(self: PointKind) u8 {
        return switch (self) {
            .binary_input => 1,
            .double_bit_input => 3,
            .binary_output_status => 10,
            .counter => 20,
            .frozen_counter => 21,
            .analog_input => 30,
            .analog_output_status => 40,
        };
    }

    /// The event object group for this point type.
    pub fn eventGroup(self: PointKind) u8 {
        return switch (self) {
            .binary_input => 2,
            .double_bit_input => 4,
            .binary_output_status => 11,
            .counter => 22,
            .frozen_counter => 23,
            .analog_input => 32,
            .analog_output_status => 42,
        };
    }

    pub fn fromStaticGroup(group: u8) ?PointKind {
        return switch (group) {
            1 => .binary_input,
            3 => .double_bit_input,
            10 => .binary_output_status,
            20 => .counter,
            21 => .frozen_counter,
            30 => .analog_input,
            40 => .analog_output_status,
            else => null,
        };
    }

    pub fn fromEventGroup(group: u8) ?PointKind {
        return switch (group) {
            2 => .binary_input,
            4 => .double_bit_input,
            11 => .binary_output_status,
            22 => .counter,
            23 => .frozen_counter,
            32 => .analog_input,
            42 => .analog_output_status,
            else => null,
        };
    }
};

/// The double-bit binary state, carried in bits 6-7 of the flags octet
/// (§ Table "Double-bit state"): 00 intermediate, 01 determined off,
/// 10 determined on, 11 indeterminate.
pub const DoubleBit = enum(u2) {
    intermediate = 0,
    determined_off = 1,
    determined_on = 2,
    indeterminate = 3,
};

/// One point's value, whatever its type.
pub const Value = union(enum) {
    binary: bool,
    double_bit: DoubleBit,
    counter: u32,
    analog_int: i32,
    analog_float: f64,

    pub fn asInt(self: Value) i64 {
        return switch (self) {
            .binary => |b| @intFromBool(b),
            .double_bit => |d| @intFromEnum(d),
            .counter => |c| c,
            .analog_int => |v| v,
            .analog_float => |f| @intFromFloat(f),
        };
    }
};

// ── layout table ────────────────────────────────────────────────────────────

pub const ValueShape = enum {
    /// No value octets at all: the state lives in the flags octet
    /// (binary and double-bit "with flags" variations).
    in_flags,
    /// One bit per point, LSB-first, no per-point octet at all.
    packed_bit,
    /// Two bits per point, LSB-first.
    packed_dbit,
    u16,
    u32,
    i16,
    i32,
    f32,
    f64,
};

pub const TimeShape = enum {
    none,
    /// 48-bit absolute milliseconds since the UNIX epoch.
    abs48,
    /// 16-bit milliseconds relative to the fragment's common time-of-occurrence.
    rel16,
};

/// How one object record of a given group/variation is laid out on the wire.
pub const Layout = struct {
    /// A quality-flags octet precedes the value.
    flags: bool,
    value: ValueShape,
    time: TimeShape,

    /// Octets one record occupies, or null for the packed (sub-octet)
    /// shapes, whose size depends on how many points are in the range.
    pub fn wireLen(self: Layout) ?usize {
        const value_len: usize = switch (self.value) {
            .in_flags => 0,
            .packed_bit, .packed_dbit => return null,
            .u16, .i16 => 2,
            .u32, .i32, .f32 => 4,
            .f64 => 8,
        };
        const time_len: usize = switch (self.time) {
            .none => 0,
            .abs48 => 6,
            .rel16 => 2,
        };
        return @as(usize, @intFromBool(self.flags)) + value_len + time_len;
    }

    pub fn isPacked(self: Layout) bool {
        return self.value == .packed_bit or self.value == .packed_dbit;
    }
};

/// The layout of `group`/`variation`, or null if this module does not
/// implement it. Variation 0 ("any variation", request-only) is deliberately
/// absent: it is a request qualifier, not a record shape.
pub fn layoutOf(group: u8, variation: u8) ?Layout {
    return switch (group) {
        // g1 Binary Input (static)
        1 => switch (variation) {
            1 => .{ .flags = false, .value = .packed_bit, .time = .none },
            2 => .{ .flags = true, .value = .in_flags, .time = .none },
            else => null,
        },
        // g2 Binary Input Event
        2 => switch (variation) {
            1 => .{ .flags = true, .value = .in_flags, .time = .none },
            2 => .{ .flags = true, .value = .in_flags, .time = .abs48 },
            3 => .{ .flags = true, .value = .in_flags, .time = .rel16 },
            else => null,
        },
        // g3 Double-bit Binary Input (static)
        3 => switch (variation) {
            1 => .{ .flags = false, .value = .packed_dbit, .time = .none },
            2 => .{ .flags = true, .value = .in_flags, .time = .none },
            else => null,
        },
        // g4 Double-bit Binary Input Event
        4 => switch (variation) {
            1 => .{ .flags = true, .value = .in_flags, .time = .none },
            2 => .{ .flags = true, .value = .in_flags, .time = .abs48 },
            3 => .{ .flags = true, .value = .in_flags, .time = .rel16 },
            else => null,
        },
        // g10 Binary Output Status (static)
        10 => switch (variation) {
            1 => .{ .flags = false, .value = .packed_bit, .time = .none },
            2 => .{ .flags = true, .value = .in_flags, .time = .none },
            else => null,
        },
        // g11 Binary Output Status Event
        11 => switch (variation) {
            1 => .{ .flags = true, .value = .in_flags, .time = .none },
            2 => .{ .flags = true, .value = .in_flags, .time = .abs48 },
            else => null,
        },
        // g20 Counter (static)
        20 => switch (variation) {
            1 => .{ .flags = true, .value = .u32, .time = .none },
            2 => .{ .flags = true, .value = .u16, .time = .none },
            5 => .{ .flags = false, .value = .u32, .time = .none },
            6 => .{ .flags = false, .value = .u16, .time = .none },
            else => null,
        },
        // g21 Frozen Counter (static)
        21 => switch (variation) {
            1 => .{ .flags = true, .value = .u32, .time = .none },
            2 => .{ .flags = true, .value = .u16, .time = .none },
            5 => .{ .flags = true, .value = .u32, .time = .abs48 },
            6 => .{ .flags = true, .value = .u16, .time = .abs48 },
            9 => .{ .flags = false, .value = .u32, .time = .none },
            10 => .{ .flags = false, .value = .u16, .time = .none },
            else => null,
        },
        // g22 Counter Event
        22 => switch (variation) {
            1 => .{ .flags = true, .value = .u32, .time = .none },
            2 => .{ .flags = true, .value = .u16, .time = .none },
            5 => .{ .flags = true, .value = .u32, .time = .abs48 },
            6 => .{ .flags = true, .value = .u16, .time = .abs48 },
            else => null,
        },
        // g23 Frozen Counter Event
        23 => switch (variation) {
            1 => .{ .flags = true, .value = .u32, .time = .none },
            2 => .{ .flags = true, .value = .u16, .time = .none },
            5 => .{ .flags = true, .value = .u32, .time = .abs48 },
            6 => .{ .flags = true, .value = .u16, .time = .abs48 },
            else => null,
        },
        // g30 Analog Input (static)
        30 => switch (variation) {
            1 => .{ .flags = true, .value = .i32, .time = .none },
            2 => .{ .flags = true, .value = .i16, .time = .none },
            3 => .{ .flags = false, .value = .i32, .time = .none },
            4 => .{ .flags = false, .value = .i16, .time = .none },
            5 => .{ .flags = true, .value = .f32, .time = .none },
            6 => .{ .flags = true, .value = .f64, .time = .none },
            else => null,
        },
        // g32 Analog Input Event
        32 => switch (variation) {
            1 => .{ .flags = true, .value = .i32, .time = .none },
            2 => .{ .flags = true, .value = .i16, .time = .none },
            3 => .{ .flags = true, .value = .i32, .time = .abs48 },
            4 => .{ .flags = true, .value = .i16, .time = .abs48 },
            5 => .{ .flags = true, .value = .f32, .time = .none },
            6 => .{ .flags = true, .value = .f64, .time = .none },
            7 => .{ .flags = true, .value = .f32, .time = .abs48 },
            8 => .{ .flags = true, .value = .f64, .time = .abs48 },
            else => null,
        },
        // g40 Analog Output Status (static)
        40 => switch (variation) {
            1 => .{ .flags = true, .value = .i32, .time = .none },
            2 => .{ .flags = true, .value = .i16, .time = .none },
            3 => .{ .flags = true, .value = .f32, .time = .none },
            4 => .{ .flags = true, .value = .f64, .time = .none },
            else => null,
        },
        // g42 Analog Output Status Event
        42 => switch (variation) {
            1 => .{ .flags = true, .value = .i32, .time = .none },
            2 => .{ .flags = true, .value = .i16, .time = .none },
            3 => .{ .flags = true, .value = .i32, .time = .abs48 },
            4 => .{ .flags = true, .value = .i16, .time = .abs48 },
            5 => .{ .flags = true, .value = .f32, .time = .none },
            6 => .{ .flags = true, .value = .f64, .time = .none },
            7 => .{ .flags = true, .value = .f32, .time = .abs48 },
            8 => .{ .flags = true, .value = .f64, .time = .abs48 },
            else => null,
        },
        else => null,
    };
}

// ── record encode / decode ──────────────────────────────────────────────────

pub const EncodeError = error{
    BufferTooSmall,
    /// The layout is a packed (sub-octet) shape, which has no per-record
    /// encoder — use `packBits` / `packDoubleBits`.
    PackedLayout,
    /// The value does not fit the layout's width (e.g. 0x1_0000 into a u16).
    ValueOutOfRange,
};

pub const DecodeError = error{ ShortRecord, PackedLayout };

/// One decoded object record.
pub const Record = struct {
    flags: Flags,
    value: Value,
    /// Present only for `.abs48` layouts.
    time_ms: ?u48 = null,
    /// Present only for `.rel16` layouts.
    time_rel_ms: ?u16 = null,
};

/// Encodes one record of `layout` into `out`, returning the written prefix.
///
/// For binary and double-bit layouts the state travels *inside* the flags
/// octet: bit 7 for binary, bits 6-7 for double-bit. The caller passes the
/// state in `value` and the quality bits in `flags`; this function merges
/// them, so a caller can never forget to set the state bit.
pub fn encode(layout: Layout, flags: Flags, value: Value, time_ms: u48, time_rel: u16, out: []u8) EncodeError![]u8 {
    if (layout.isPacked()) return error.PackedLayout;
    const total = layout.wireLen().?;
    if (out.len < total) return error.BufferTooSmall;

    var pos: usize = 0;
    if (layout.flags) {
        var byte = flags.toByte();
        switch (value) {
            .binary => |b| {
                byte &= 0x7F;
                if (b) byte |= 0x80;
            },
            .double_bit => |d| {
                byte &= 0x3F;
                byte |= @as(u8, @intFromEnum(d)) << 6;
            },
            else => {},
        }
        out[0] = byte;
        pos = 1;
    }

    switch (layout.value) {
        .in_flags => {},
        .packed_bit, .packed_dbit => unreachable, // guarded above
        .u16 => {
            const v = value.counter;
            if (v > 0xFFFF) return error.ValueOutOfRange;
            std.mem.writeInt(u16, out[pos..][0..2], @intCast(v), .little);
            pos += 2;
        },
        .u32 => {
            std.mem.writeInt(u32, out[pos..][0..4], value.counter, .little);
            pos += 4;
        },
        .i16 => {
            const v = value.analog_int;
            if (v > 32767 or v < -32768) return error.ValueOutOfRange;
            std.mem.writeInt(i16, out[pos..][0..2], @intCast(v), .little);
            pos += 2;
        },
        .i32 => {
            std.mem.writeInt(i32, out[pos..][0..4], value.analog_int, .little);
            pos += 4;
        },
        .f32 => {
            const v: f32 = switch (value) {
                .analog_float => |f| @floatCast(f),
                .analog_int => |i| @floatFromInt(i),
                else => return error.ValueOutOfRange,
            };
            std.mem.writeInt(u32, out[pos..][0..4], @bitCast(v), .little);
            pos += 4;
        },
        .f64 => {
            const v: f64 = switch (value) {
                .analog_float => |f| f,
                .analog_int => |i| @floatFromInt(i),
                else => return error.ValueOutOfRange,
            };
            std.mem.writeInt(u64, out[pos..][0..8], @bitCast(v), .little);
            pos += 8;
        },
    }

    switch (layout.time) {
        .none => {},
        .abs48 => {
            std.mem.writeInt(u48, out[pos..][0..6], time_ms, .little);
            pos += 6;
        },
        .rel16 => {
            std.mem.writeInt(u16, out[pos..][0..2], time_rel, .little);
            pos += 2;
        },
    }

    std.debug.assert(pos == total);
    return out[0..total];
}

/// Decodes one record of `layout` from the front of `bytes`.
pub fn decode(layout: Layout, kind: PointKind, bytes: []const u8) DecodeError!Record {
    if (layout.isPacked()) return error.PackedLayout;
    const total = layout.wireLen().?;
    if (bytes.len < total) return error.ShortRecord;

    var pos: usize = 0;
    var flags: Flags = .{};
    if (layout.flags) {
        flags = Flags.fromByte(bytes[0]);
        pos = 1;
    }

    const value: Value = switch (layout.value) {
        .in_flags => switch (kind) {
            .double_bit_input => .{ .double_bit = @enumFromInt(@as(u2, @truncate(bytes[0] >> 6))) },
            else => .{ .binary = (bytes[0] & 0x80) != 0 },
        },
        .packed_bit, .packed_dbit => unreachable,
        .u16 => blk: {
            const v = std.mem.readInt(u16, bytes[pos..][0..2], .little);
            pos += 2;
            break :blk .{ .counter = v };
        },
        .u32 => blk: {
            const v = std.mem.readInt(u32, bytes[pos..][0..4], .little);
            pos += 4;
            break :blk .{ .counter = v };
        },
        .i16 => blk: {
            const v = std.mem.readInt(i16, bytes[pos..][0..2], .little);
            pos += 2;
            break :blk .{ .analog_int = v };
        },
        .i32 => blk: {
            const v = std.mem.readInt(i32, bytes[pos..][0..4], .little);
            pos += 4;
            break :blk .{ .analog_int = v };
        },
        .f32 => blk: {
            const bits = std.mem.readInt(u32, bytes[pos..][0..4], .little);
            pos += 4;
            break :blk .{ .analog_float = @as(f32, @bitCast(bits)) };
        },
        .f64 => blk: {
            const bits = std.mem.readInt(u64, bytes[pos..][0..8], .little);
            pos += 8;
            break :blk .{ .analog_float = @bitCast(bits) };
        },
    };

    var record = Record{ .flags = flags, .value = value };
    switch (layout.time) {
        .none => {},
        .abs48 => record.time_ms = std.mem.readInt(u48, bytes[pos..][0..6], .little),
        .rel16 => record.time_rel_ms = std.mem.readInt(u16, bytes[pos..][0..2], .little),
    }
    return record;
}

// ── packed shapes ───────────────────────────────────────────────────────────

/// Octets needed to carry `count` single-bit points.
pub fn packedBitBytes(count: usize) usize {
    return (count + 7) / 8;
}

/// Octets needed to carry `count` double-bit points.
pub fn packedDoubleBitBytes(count: usize) usize {
    return (count + 3) / 4;
}

/// Sets bit `i` (LSB-first) of a packed-bit region that `out` covers.
pub fn setPackedBit(out: []u8, i: usize, on: bool) void {
    const shift: u3 = @intCast(i % 8);
    if (on) out[i / 8] |= @as(u8, 1) << shift else out[i / 8] &= ~(@as(u8, 1) << shift);
}

pub fn getPackedBit(bytes: []const u8, i: usize) bool {
    const shift: u3 = @intCast(i % 8);
    return (bytes[i / 8] >> shift) & 1 != 0;
}

/// Sets the two-bit state of point `i` in a packed double-bit region.
pub fn setPackedDoubleBit(out: []u8, i: usize, state: DoubleBit) void {
    const shift: u3 = @intCast((i % 4) * 2);
    out[i / 4] &= ~(@as(u8, 0b11) << shift);
    out[i / 4] |= @as(u8, @intFromEnum(state)) << shift;
}

pub fn getPackedDoubleBit(bytes: []const u8, i: usize) DoubleBit {
    const shift: u3 = @intCast((i % 4) * 2);
    return @enumFromInt(@as(u2, @truncate(bytes[i / 4] >> shift)));
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "layout table: wire lengths match the object library" {
    // A representative row from each shape family.
    try testing.expectEqual(@as(?usize, 1), layoutOf(1, 2).?.wireLen()); // g1v2 flags only
    try testing.expectEqual(@as(?usize, null), layoutOf(1, 1).?.wireLen()); // g1v1 packed
    try testing.expectEqual(@as(?usize, 7), layoutOf(2, 2).?.wireLen()); // g2v2 flags + 48-bit time
    try testing.expectEqual(@as(?usize, 3), layoutOf(2, 3).?.wireLen()); // g2v3 flags + 16-bit time
    try testing.expectEqual(@as(?usize, 5), layoutOf(20, 1).?.wireLen()); // g20v1 flags + u32
    try testing.expectEqual(@as(?usize, 3), layoutOf(20, 2).?.wireLen()); // g20v2 flags + u16
    try testing.expectEqual(@as(?usize, 4), layoutOf(20, 5).?.wireLen()); // g20v5 u32, no flags
    try testing.expectEqual(@as(?usize, 11), layoutOf(21, 5).?.wireLen()); // g21v5 flags + u32 + time
    try testing.expectEqual(@as(?usize, 5), layoutOf(30, 1).?.wireLen()); // g30v1 flags + i32
    try testing.expectEqual(@as(?usize, 2), layoutOf(30, 4).?.wireLen()); // g30v4 i16, no flags
    try testing.expectEqual(@as(?usize, 9), layoutOf(30, 6).?.wireLen()); // g30v6 flags + f64
    try testing.expectEqual(@as(?usize, 11), layoutOf(32, 3).?.wireLen()); // g32v3 flags + i32 + time
    try testing.expectEqual(@as(?usize, 11), layoutOf(32, 7).?.wireLen()); // g32v7 flags + f32 + time
    try testing.expectEqual(@as(?usize, 5), layoutOf(40, 3).?.wireLen()); // g40v3 flags + f32

    // Variations the module does not implement, and variation 0.
    try testing.expectEqual(@as(?Layout, null), layoutOf(1, 0));
    try testing.expectEqual(@as(?Layout, null), layoutOf(1, 3));
    try testing.expectEqual(@as(?Layout, null), layoutOf(99, 1));
}

test "encode/decode: g1v2 binary carries state in the flags octet's bit 7" {
    const layout = layoutOf(1, 2).?;
    var out: [8]u8 = undefined;

    const on = try encode(layout, .{ .online = true }, .{ .binary = true }, 0, 0, &out);
    try testing.expectEqualSlices(u8, &.{0x81}, on);
    const off = try encode(layout, .{ .online = true }, .{ .binary = false }, 0, 0, &out);
    try testing.expectEqualSlices(u8, &.{0x01}, off);

    const back = try decode(layout, .binary_input, &.{0x81});
    try testing.expect(back.value.binary);
    try testing.expect(back.flags.online);
}

test "encode/decode: g3v2 double-bit carries state in flags bits 6-7" {
    const layout = layoutOf(3, 2).?;
    var out: [8]u8 = undefined;
    const cases = [_]struct { state: DoubleBit, byte: u8 }{
        .{ .state = .intermediate, .byte = 0x01 },
        .{ .state = .determined_off, .byte = 0x41 },
        .{ .state = .determined_on, .byte = 0x81 },
        .{ .state = .indeterminate, .byte = 0xC1 },
    };
    for (cases) |c| {
        const bytes = try encode(layout, .{ .online = true }, .{ .double_bit = c.state }, 0, 0, &out);
        try testing.expectEqualSlices(u8, &.{c.byte}, bytes);
        const back = try decode(layout, .double_bit_input, bytes);
        try testing.expectEqual(c.state, back.value.double_bit);
    }
}

test "encode/decode: g32v3 analog event round-trips value and 48-bit time" {
    const layout = layoutOf(32, 3).?;
    var out: [16]u8 = undefined;
    const bytes = try encode(
        layout,
        .{ .online = true },
        .{ .analog_int = -123456 },
        0x0001_9AB0_1234,
        0,
        &out,
    );
    try testing.expectEqual(@as(usize, 11), bytes.len);
    const back = try decode(layout, .analog_input, bytes);
    try testing.expectEqual(@as(i32, -123456), back.value.analog_int);
    try testing.expectEqual(@as(u48, 0x0001_9AB0_1234), back.time_ms.?);
}

test "encode/decode: float variations" {
    var out: [16]u8 = undefined;
    const f32_layout = layoutOf(30, 5).?;
    const b32 = try encode(f32_layout, .{ .online = true }, .{ .analog_float = 2.5 }, 0, 0, &out);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00, 0x20, 0x40 }, b32);
    try testing.expectEqual(@as(f64, 2.5), (try decode(f32_layout, .analog_input, b32)).value.analog_float);

    const f64_layout = layoutOf(30, 6).?;
    const b64 = try encode(f64_layout, .{ .online = true }, .{ .analog_float = -1.5 }, 0, 0, &out);
    try testing.expectEqual(@as(usize, 9), b64.len);
    try testing.expectEqual(@as(f64, -1.5), (try decode(f64_layout, .analog_input, b64)).value.analog_float);
}

test "encode: narrow variations reject values that do not fit" {
    var out: [16]u8 = undefined;
    const u16_layout = layoutOf(20, 2).?;
    _ = try encode(u16_layout, .{}, .{ .counter = 0xFFFF }, 0, 0, &out);
    try testing.expectError(error.ValueOutOfRange, encode(u16_layout, .{}, .{ .counter = 0x1_0000 }, 0, 0, &out));

    const i16_layout = layoutOf(30, 2).?;
    _ = try encode(i16_layout, .{}, .{ .analog_int = 32767 }, 0, 0, &out);
    _ = try encode(i16_layout, .{}, .{ .analog_int = -32768 }, 0, 0, &out);
    try testing.expectError(error.ValueOutOfRange, encode(i16_layout, .{}, .{ .analog_int = 32768 }, 0, 0, &out));
    try testing.expectError(error.ValueOutOfRange, encode(i16_layout, .{}, .{ .analog_int = -32769 }, 0, 0, &out));
}

test "encode/decode: packed shapes are refused by the record codec" {
    var out: [16]u8 = undefined;
    try testing.expectError(error.PackedLayout, encode(layoutOf(1, 1).?, .{}, .{ .binary = true }, 0, 0, &out));
    try testing.expectError(error.PackedLayout, decode(layoutOf(3, 1).?, .double_bit_input, &.{0}));
}

test "packed bits and double bits round-trip LSB-first" {
    var buf = [_]u8{0} ** 4;
    const values = [_]bool{ true, false, true, true, false, false, false, true, true };
    for (values, 0..) |v, i| setPackedBit(&buf, i, v);
    try testing.expectEqual(@as(usize, 2), packedBitBytes(values.len));
    try testing.expectEqual(@as(u8, 0b1000_1101), buf[0]);
    try testing.expectEqual(@as(u8, 0b0000_0001), buf[1]);
    for (values, 0..) |v, i| try testing.expectEqual(v, getPackedBit(&buf, i));

    var dbuf = [_]u8{0} ** 4;
    const states = [_]DoubleBit{ .determined_on, .determined_off, .indeterminate, .intermediate, .determined_on };
    for (states, 0..) |s, i| setPackedDoubleBit(&dbuf, i, s);
    try testing.expectEqual(@as(usize, 2), packedDoubleBitBytes(states.len));
    try testing.expectEqual(@as(u8, 0b00_11_01_10), dbuf[0]);
    for (states, 0..) |s, i| try testing.expectEqual(s, getPackedDoubleBit(&dbuf, i));
}

test "decode: short records are typed errors, never panics" {
    const layout = layoutOf(32, 3).?;
    var i: usize = 0;
    while (i < 11) : (i += 1) {
        const bytes = [_]u8{0xFF} ** 11;
        try testing.expectError(error.ShortRecord, decode(layout, .analog_input, bytes[0..i]));
    }
}

test "point kinds map to their static and event groups both ways" {
    for (std.enums.values(PointKind)) |kind| {
        try testing.expectEqual(kind, PointKind.fromStaticGroup(kind.staticGroup()).?);
        try testing.expectEqual(kind, PointKind.fromEventGroup(kind.eventGroup()).?);
    }
    try testing.expectEqual(@as(?PointKind, null), PointKind.fromStaticGroup(60));
    try testing.expectEqual(@as(?PointKind, null), PointKind.fromEventGroup(60));
}
