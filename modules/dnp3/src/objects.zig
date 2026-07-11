// SPDX-License-Identifier: MIT

//! dnp3.objects — the object-header framing (IEEE 1815-2012 §4.4/§4.5: group
//! + variation + qualifier + range specifier) and a core static-object
//! library (§ Part 4 / Part 5 object library): binary input (g1), binary
//! output status + CROB (g10/g12), binary counter (g20), analog input (g30),
//! analog output status + block (g40/g41), time-and-date (g50), and the
//! class-data markers (g60) used to request "give me everything of class N".
//!
//! Every encode/decode function here is a pure function over byte slices —
//! no allocation, no I/O — following the same "wire codec as pure functions"
//! shape as the sibling `link`/`transport` modules.
//!
//! Scope note: this is the *static* (non-event) core of the object library —
//! the groups explicitly called out for the base module. Event variations
//! (g2, g11, g22, g32, g42, g4/g13 relative-time, and the many
//! device/file/data-set groups elsewhere in Part 4/5) are not implemented;
//! see the module README "Scope" section.

const std = @import("std");

// ── object header: group/variation/qualifier/range ──────────────────────────

/// The qualifier byte's high nibble (§4.5.2.1): how each object *instance*
/// in the data portion is prefixed, if at all.
pub const PrefixCode = enum(u4) {
    none = 0,
    index_1b = 1,
    index_2b = 2,
    index_4b = 3,
    size_1b = 4,
    size_2b = 5,
    size_4b = 6,
    _,
};

/// The qualifier byte's low nibble (§4.5.2.1, Range Specifier): how the
/// range field after the qualifier byte is shaped.
pub const RangeCode = enum(u4) {
    start_stop_1b = 0,
    start_stop_2b = 1,
    start_stop_4b = 2,
    all_values = 6,
    count_1b = 7,
    count_2b = 8,
    count_4b = 9,
    _,
};

pub const Qualifier = struct {
    prefix_code: PrefixCode,
    range_code: RangeCode,

    pub fn toByte(self: Qualifier) u8 {
        return (@as(u8, @intFromEnum(self.prefix_code)) << 4) | @as(u8, @intFromEnum(self.range_code));
    }

    pub fn fromByte(b: u8) Qualifier {
        return .{
            .prefix_code = @enumFromInt(@as(u4, @truncate(b >> 4))),
            .range_code = @enumFromInt(@as(u4, @truncate(b & 0x0F))),
        };
    }
};

/// The range field's decoded meaning, per `RangeCode`.
pub const Range = union(enum) {
    start_stop: struct { start: u32, stop: u32 },
    all_values: void,
    count: u32,

    /// Number of object instances this range implies, for range shapes
    /// where that's determined by the range field alone (`start_stop`:
    /// `stop - start + 1`; `count`: the count value). `all_values` has no
    /// fixed instance count (the receiver already knows what "all" means
    /// for the group/variation) and returns `null`.
    pub fn objectCount(self: Range) ?u32 {
        return switch (self) {
            .start_stop => |r| if (r.stop >= r.start) r.stop - r.start + 1 else null,
            .all_values => null,
            .count => |c| c,
        };
    }
};

pub const ObjectHeader = struct {
    group: u8,
    variation: u8,
    qualifier: Qualifier,
    range: Range,
};

pub const EncodeError = error{
    /// `range` doesn't match the width class implied by `qualifier.range_code`
    /// (e.g. a `count` range with `range_code = .all_values`).
    RangeQualifierMismatch,
    /// A start/stop or count value doesn't fit the qualifier's field width.
    ValueOutOfRange,
    BufferTooSmall,
};

pub const DecodeError = error{
    ShortHeader,
    /// `range_code` isn't one of the range shapes this module implements
    /// (free-format/reserved codes are out of scope).
    UnsupportedRangeCode,
};

fn rangeFieldWidth(code: RangeCode) DecodeError!usize {
    return switch (code) {
        .start_stop_1b, .count_1b => 1,
        .start_stop_2b, .count_2b => 2,
        .start_stop_4b, .count_4b => 4,
        .all_values => 0,
        _ => error.UnsupportedRangeCode,
    };
}

/// Encodes `group, variation, qualifier, range` into `out`. The caller
/// chooses `qualifier` explicitly (this module does not auto-pick the
/// smallest encoding) so the wire shape is always exactly what was asked for.
pub fn encodeObjectHeader(header: ObjectHeader, out: []u8) EncodeError![]u8 {
    const width = switch (header.qualifier.range_code) {
        .start_stop_1b, .count_1b => @as(usize, 1),
        .start_stop_2b, .count_2b => @as(usize, 2),
        .start_stop_4b, .count_4b => @as(usize, 4),
        .all_values => @as(usize, 0),
        _ => return error.RangeQualifierMismatch,
    };
    const is_start_stop = switch (header.qualifier.range_code) {
        .start_stop_1b, .start_stop_2b, .start_stop_4b => true,
        else => false,
    };
    const is_count = switch (header.qualifier.range_code) {
        .count_1b, .count_2b, .count_4b => true,
        else => false,
    };

    const field_bytes: usize = if (is_start_stop) width * 2 else width;
    const total = 3 + field_bytes;
    if (out.len < total) return error.BufferTooSmall;

    out[0] = header.group;
    out[1] = header.variation;
    out[2] = header.qualifier.toByte();

    switch (header.range) {
        .start_stop => |r| {
            if (!is_start_stop) return error.RangeQualifierMismatch;
            if (!fitsWidth(r.start, width) or !fitsWidth(r.stop, width)) return error.ValueOutOfRange;
            writeUint(out[3..][0..width], r.start);
            writeUint(out[3 + width ..][0..width], r.stop);
        },
        .count => |c| {
            if (!is_count) return error.RangeQualifierMismatch;
            if (!fitsWidth(c, width)) return error.ValueOutOfRange;
            writeUint(out[3..][0..width], c);
        },
        .all_values => {
            if (header.qualifier.range_code != .all_values) return error.RangeQualifierMismatch;
        },
    }
    return out[0..total];
}

/// Decodes one object header from `bytes`. Returns the header plus how many
/// bytes of `bytes` it consumed.
pub fn decodeObjectHeader(bytes: []const u8) DecodeError!struct { header: ObjectHeader, consumed: usize } {
    if (bytes.len < 3) return error.ShortHeader;
    const qualifier = Qualifier.fromByte(bytes[2]);
    const width = try rangeFieldWidth(qualifier.range_code);
    const is_start_stop = switch (qualifier.range_code) {
        .start_stop_1b, .start_stop_2b, .start_stop_4b => true,
        else => false,
    };

    const field_bytes: usize = if (is_start_stop) width * 2 else width;
    if (bytes.len < 3 + field_bytes) return error.ShortHeader;

    const range: Range = switch (qualifier.range_code) {
        .all_values => .{ .all_values = {} },
        .start_stop_1b, .start_stop_2b, .start_stop_4b => .{ .start_stop = .{
            .start = readUint(bytes[3..][0..width]),
            .stop = readUint(bytes[3 + width ..][0..width]),
        } },
        .count_1b, .count_2b, .count_4b => .{ .count = readUint(bytes[3..][0..width]) },
        _ => return error.UnsupportedRangeCode,
    };

    return .{
        .header = .{ .group = bytes[0], .variation = bytes[1], .qualifier = qualifier, .range = range },
        .consumed = 3 + field_bytes,
    };
}

fn fitsWidth(v: u32, width: usize) bool {
    return switch (width) {
        1 => v <= 0xFF,
        2 => v <= 0xFFFF,
        4 => true,
        else => unreachable,
    };
}

fn writeUint(out: []u8, v: u32) void {
    switch (out.len) {
        1 => out[0] = @truncate(v),
        2 => std.mem.writeInt(u16, out[0..2], @truncate(v), .little),
        4 => std.mem.writeInt(u32, out[0..4], v, .little),
        else => unreachable,
    }
}

fn readUint(bytes: []const u8) u32 {
    return switch (bytes.len) {
        1 => bytes[0],
        2 => std.mem.readInt(u16, bytes[0..2], .little),
        4 => std.mem.readInt(u32, bytes[0..4], .little),
        else => unreachable,
    };
}

// ── shared flags byte (§Part 4/5, most static/event object groups) ─────────

/// The 1-byte quality-flags octet most object groups prefix a value with.
/// Bits 0-4 (ONLINE/RESTART/COMM_LOST/REMOTE_FORCED/LOCAL_FORCED) mean the
/// same thing in every group that carries flags. Bit 5 is group-specific
/// (CHATTER_FILTER for binary I/O, ROLLOVER for counters, OVER_RANGE for
/// analog I/O) -- this codec carries the bit but does not name or interpret
/// it further. Bit 6 is reserved (must be 0 on encode; not rejected on
/// decode). Bit 7 is the point's boolean STATE for binary-family groups; for
/// analog/counter groups it's typically unused and this codec neither sets
/// nor interprets it beyond carrying it.
pub const Flags = struct {
    online: bool = false,
    restart: bool = false,
    comm_lost: bool = false,
    remote_forced: bool = false,
    local_forced: bool = false,
    /// Group-specific bit 0x20 (see type doc comment).
    bit5: bool = false,
    /// Reserved bit 0x40.
    reserved: bool = false,
    /// Bit 0x80 -- binary STATE, or group-specific/unused elsewhere.
    bit7: bool = false,

    pub fn toByte(self: Flags) u8 {
        var b: u8 = 0;
        if (self.online) b |= 0x01;
        if (self.restart) b |= 0x02;
        if (self.comm_lost) b |= 0x04;
        if (self.remote_forced) b |= 0x08;
        if (self.local_forced) b |= 0x10;
        if (self.bit5) b |= 0x20;
        if (self.reserved) b |= 0x40;
        if (self.bit7) b |= 0x80;
        return b;
    }

    pub fn fromByte(b: u8) Flags {
        return .{
            .online = (b & 0x01) != 0,
            .restart = (b & 0x02) != 0,
            .comm_lost = (b & 0x04) != 0,
            .remote_forced = (b & 0x08) != 0,
            .local_forced = (b & 0x10) != 0,
            .bit5 = (b & 0x20) != 0,
            .reserved = (b & 0x40) != 0,
            .bit7 = (b & 0x80) != 0,
        };
    }
};

// ── g1: Binary Input ─────────────────────────────────────────────────────────

pub const g1 = struct {
    /// g1v1: packed bits, no flags -- one bit per point, LSB-first (point 0
    /// is bit 0 of the first byte).
    pub fn packBits(values: []const bool, out: []u8) error{BufferTooSmall}![]u8 {
        const nbytes = (values.len + 7) / 8;
        if (out.len < nbytes) return error.BufferTooSmall;
        @memset(out[0..nbytes], 0);
        for (values, 0..) |v, i| {
            if (v) out[i / 8] |= @as(u8, 1) << @intCast(i % 8);
        }
        return out[0..nbytes];
    }

    pub fn unpackBits(bytes: []const u8, count: usize, out: []bool) error{BufferTooSmall}!void {
        if (out.len < count or bytes.len < (count + 7) / 8) return error.BufferTooSmall;
        for (0..count) |i| out[i] = (bytes[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
    }

    /// g1v2: one flags byte per point (STATE is `Flags.bit7`).
    pub const V2 = struct {
        flags: Flags,

        pub fn encode(self: V2, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < 1) return error.BufferTooSmall;
            out[0] = self.flags.toByte();
            return out[0..1];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V2 {
            if (bytes.len < 1) return error.ShortRecord;
            return .{ .flags = Flags.fromByte(bytes[0]) };
        }
    };
};

// ── g10: Binary Output status ────────────────────────────────────────────────

pub const g10 = struct {
    /// g10v2: one flags byte per point (mirrors g1v2's shape).
    pub const V2 = g1.V2;
};

// ── g12: Binary Output / Control Relay Output Block (CROB) ─────────────────

pub const g12 = struct {
    pub const OpType = enum(u4) {
        nul = 0,
        pulse_on = 1,
        pulse_off = 2,
        latch_on = 3,
        latch_off = 4,
        _,
    };

    pub const TripCloseCode = enum(u2) {
        nul = 0,
        close = 1,
        trip = 2,
        _,
    };

    pub const ControlCode = struct {
        op_type: OpType,
        /// Clear-queue qualifier bit (0x10).
        clear: bool = false,
        tcc: TripCloseCode = .nul,

        pub fn toByte(self: ControlCode) u8 {
            var b: u8 = @as(u8, @intFromEnum(self.op_type));
            if (self.clear) b |= 0x10;
            b |= @as(u8, @intFromEnum(self.tcc)) << 6;
            return b;
        }

        pub fn fromByte(b: u8) ControlCode {
            return .{
                .op_type = @enumFromInt(@as(u4, @truncate(b & 0x0F))),
                .clear = (b & 0x10) != 0,
                .tcc = @enumFromInt(@as(u2, @truncate(b >> 6))),
            };
        }
    };

    /// Outstation command-echo status, common to CROB (g12v1) and the analog
    /// output block (g41).
    pub const CommandStatus = enum(u8) {
        success = 0,
        timeout = 1,
        no_select = 2,
        format_error = 3,
        not_supported = 4,
        already_active = 5,
        hardware_error = 6,
        local = 7,
        too_many_ops = 8,
        not_authorized = 9,
        automation_inhibit = 10,
        processing_limited = 11,
        out_of_range = 12,
        downstream_local = 13,
        already_complete = 14,
        blocked = 15,
        cancelled = 16,
        blocked_other_master = 17,
        downstream_fail = 18,
        non_participating = 126,
        undefined = 127,
        _,
    };

    /// g12v1: the Control Relay Output Block -- 11 bytes on the wire:
    /// control code(1) + count(1) + on-time ms(4, LE) + off-time ms(4, LE) +
    /// status(1). `status` is only meaningful in a select/operate echo.
    pub const V1 = struct {
        control_code: ControlCode,
        count: u8,
        on_time_ms: u32,
        off_time_ms: u32,
        status: CommandStatus = .success,

        pub const wire_len = 11;

        pub fn encode(self: V1, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            out[0] = self.control_code.toByte();
            out[1] = self.count;
            std.mem.writeInt(u32, out[2..6], self.on_time_ms, .little);
            std.mem.writeInt(u32, out[6..10], self.off_time_ms, .little);
            out[10] = @intFromEnum(self.status);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V1 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{
                .control_code = ControlCode.fromByte(bytes[0]),
                .count = bytes[1],
                .on_time_ms = std.mem.readInt(u32, bytes[2..6], .little),
                .off_time_ms = std.mem.readInt(u32, bytes[6..10], .little),
                .status = @enumFromInt(bytes[10]),
            };
        }
    };
};

// ── g20: Binary Counter ──────────────────────────────────────────────────────

pub const g20 = struct {
    /// g20v1: flags(1) + 32-bit counter value(4, LE) -- 5 bytes.
    pub const V1 = struct {
        flags: Flags,
        value: u32,

        pub const wire_len = 5;

        pub fn encode(self: V1, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            out[0] = self.flags.toByte();
            std.mem.writeInt(u32, out[1..5], self.value, .little);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V1 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .flags = Flags.fromByte(bytes[0]), .value = std.mem.readInt(u32, bytes[1..5], .little) };
        }
    };

    /// g20v2: flags(1) + 16-bit counter value(2, LE) -- 3 bytes.
    pub const V2 = struct {
        flags: Flags,
        value: u16,

        pub const wire_len = 3;

        pub fn encode(self: V2, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            out[0] = self.flags.toByte();
            std.mem.writeInt(u16, out[1..3], self.value, .little);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V2 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .flags = Flags.fromByte(bytes[0]), .value = std.mem.readInt(u16, bytes[1..3], .little) };
        }
    };
};

// ── g30: Analog Input ────────────────────────────────────────────────────────

pub const g30 = struct {
    /// g30v1: flags(1) + 32-bit signed value(4, LE) -- 5 bytes.
    pub const V1 = struct {
        flags: Flags,
        value: i32,

        pub const wire_len = 5;

        pub fn encode(self: V1, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            out[0] = self.flags.toByte();
            std.mem.writeInt(i32, out[1..5], self.value, .little);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V1 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .flags = Flags.fromByte(bytes[0]), .value = std.mem.readInt(i32, bytes[1..5], .little) };
        }
    };

    /// g30v2: flags(1) + 16-bit signed value(2, LE) -- 3 bytes.
    pub const V2 = struct {
        flags: Flags,
        value: i16,

        pub const wire_len = 3;

        pub fn encode(self: V2, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            out[0] = self.flags.toByte();
            std.mem.writeInt(i16, out[1..3], self.value, .little);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V2 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .flags = Flags.fromByte(bytes[0]), .value = std.mem.readInt(i16, bytes[1..3], .little) };
        }
    };

    /// g30v5: flags(1) + IEEE-754 single-precision float(4, LE) -- 5 bytes.
    pub const V5 = struct {
        flags: Flags,
        value: f32,

        pub const wire_len = 5;

        pub fn encode(self: V5, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            out[0] = self.flags.toByte();
            std.mem.writeInt(u32, out[1..5], @bitCast(self.value), .little);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V5 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .flags = Flags.fromByte(bytes[0]), .value = @bitCast(std.mem.readInt(u32, bytes[1..5], .little)) };
        }
    };
};

// ── g40: Analog Output Status ────────────────────────────────────────────────

pub const g40 = struct {
    /// g40v1: flags(1) + 32-bit signed value(4, LE) -- 5 bytes.
    pub const V1 = g30.V1;
    /// g40v2: flags(1) + 16-bit signed value(2, LE) -- 3 bytes.
    pub const V2 = g30.V2;
};

// ── g41: Analog Output Block (write/select/operate command) ────────────────

pub const g41 = struct {
    /// g41v1: 32-bit signed value(4, LE) + command status(1) -- 5 bytes.
    pub const V1 = struct {
        value: i32,
        status: g12.CommandStatus = .success,

        pub const wire_len = 5;

        pub fn encode(self: V1, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            std.mem.writeInt(i32, out[0..4], self.value, .little);
            out[4] = @intFromEnum(self.status);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V1 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .value = std.mem.readInt(i32, bytes[0..4], .little), .status = @enumFromInt(bytes[4]) };
        }
    };

    /// g41v2: 16-bit signed value(2, LE) + command status(1) -- 3 bytes.
    pub const V2 = struct {
        value: i16,
        status: g12.CommandStatus = .success,

        pub const wire_len = 3;

        pub fn encode(self: V2, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            std.mem.writeInt(i16, out[0..2], self.value, .little);
            out[2] = @intFromEnum(self.status);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V2 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .value = std.mem.readInt(i16, bytes[0..2], .little), .status = @enumFromInt(bytes[2]) };
        }
    };

    /// g41v3: IEEE-754 single-precision float(4, LE) + command status(1) -- 5 bytes.
    pub const V3 = struct {
        value: f32,
        status: g12.CommandStatus = .success,

        pub const wire_len = 5;

        pub fn encode(self: V3, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            std.mem.writeInt(u32, out[0..4], @bitCast(self.value), .little);
            out[4] = @intFromEnum(self.status);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V3 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .value = @bitCast(std.mem.readInt(u32, bytes[0..4], .little)), .status = @enumFromInt(bytes[4]) };
        }
    };
};

// ── g50: Time and Date ───────────────────────────────────────────────────────

pub const g50 = struct {
    /// g50v1: absolute time, 48-bit unsigned milliseconds since the UNIX
    /// epoch, little-endian on the wire (stored here in a `u64` -- only the
    /// low 48 bits round-trip).
    pub const V1 = struct {
        ms_since_epoch: u64,

        pub const wire_len = 6;

        pub fn encode(self: V1, out: []u8) error{BufferTooSmall}![]u8 {
            if (out.len < wire_len) return error.BufferTooSmall;
            std.mem.writeInt(u48, out[0..6], @truncate(self.ms_since_epoch), .little);
            return out[0..wire_len];
        }

        pub fn decode(bytes: []const u8) error{ShortRecord}!V1 {
            if (bytes.len < wire_len) return error.ShortRecord;
            return .{ .ms_since_epoch = std.mem.readInt(u48, bytes[0..6], .little) };
        }
    };
};

// ── g60: Class Data (request-only markers, no object payload) ──────────────

pub const g60 = struct {
    pub const Class = enum(u8) {
        class0 = 1,
        class1 = 2,
        class2 = 3,
        class3 = 4,
    };

    /// Builds the `ObjectHeader` for "read all of class N" -- group 60,
    /// variation = the class, qualifier all-values (no range data).
    pub fn readClassHeader(class: Class) ObjectHeader {
        return .{
            .group = 60,
            .variation = @intFromEnum(class),
            .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
            .range = .{ .all_values = {} },
        };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "qualifier byte round-trip" {
    const q = Qualifier{ .prefix_code = .index_1b, .range_code = .count_1b };
    try testing.expectEqual(@as(u8, 0x17), q.toByte());
    const back = Qualifier.fromByte(0x17);
    try testing.expectEqual(PrefixCode.index_1b, back.prefix_code);
    try testing.expectEqual(RangeCode.count_1b, back.range_code);
}

test "object header: 1-byte start-stop range" {
    const h = ObjectHeader{
        .group = 1,
        .variation = 2,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 9 } },
    };
    var out: [16]u8 = undefined;
    const bytes = try encodeObjectHeader(h, &out);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 0x00, 0, 9 }, bytes);

    const decoded = try decodeObjectHeader(bytes);
    try testing.expectEqual(@as(usize, 5), decoded.consumed);
    try testing.expectEqual(@as(u8, 1), decoded.header.group);
    try testing.expectEqual(@as(u32, 10), decoded.header.range.objectCount().?);
}

test "object header: 2-byte start-stop range" {
    const h = ObjectHeader{
        .group = 30,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_2b },
        .range = .{ .start_stop = .{ .start = 100, .stop = 355 } },
    };
    var out: [16]u8 = undefined;
    const bytes = try encodeObjectHeader(h, &out);
    try testing.expectEqual(@as(usize, 7), bytes.len);
    const decoded = try decodeObjectHeader(bytes);
    try testing.expectEqual(@as(u32, 100), decoded.header.range.start_stop.start);
    try testing.expectEqual(@as(u32, 355), decoded.header.range.start_stop.stop);
    try testing.expectEqual(@as(u32, 256), decoded.header.range.objectCount().?);
}

test "object header: all-values qualifier (class read)" {
    const h = g60.readClassHeader(.class0);
    var out: [8]u8 = undefined;
    const bytes = try encodeObjectHeader(h, &out);
    try testing.expectEqualSlices(u8, &.{ 60, 1, 0x06 }, bytes);
    const decoded = try decodeObjectHeader(bytes);
    try testing.expectEqual(@as(usize, 3), decoded.consumed);
    try testing.expect(decoded.header.range == .all_values);
    try testing.expectEqual(@as(?u32, null), decoded.header.range.objectCount());
}

test "object header: count + 1-byte index prefix (0x17, CROB write)" {
    const h = ObjectHeader{
        .group = 12,
        .variation = 1,
        .qualifier = .{ .prefix_code = .index_1b, .range_code = .count_1b },
        .range = .{ .count = 1 },
    };
    var out: [8]u8 = undefined;
    const bytes = try encodeObjectHeader(h, &out);
    try testing.expectEqualSlices(u8, &.{ 12, 1, 0x17, 1 }, bytes);
    const decoded = try decodeObjectHeader(bytes);
    try testing.expectEqual(@as(u32, 1), decoded.header.range.count);
}

test "object header: 4-byte count range" {
    const h = ObjectHeader{
        .group = 2,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .count_4b },
        .range = .{ .count = 70_000 },
    };
    var out: [16]u8 = undefined;
    const bytes = try encodeObjectHeader(h, &out);
    try testing.expectEqual(@as(usize, 7), bytes.len);
    const decoded = try decodeObjectHeader(bytes);
    try testing.expectEqual(@as(u32, 70_000), decoded.header.range.count);
}

test "object header: range/qualifier mismatch and value-out-of-range are typed errors" {
    var out: [16]u8 = undefined;
    const mismatched = ObjectHeader{
        .group = 1,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .all_values },
        .range = .{ .count = 5 },
    };
    try testing.expectError(error.RangeQualifierMismatch, encodeObjectHeader(mismatched, &out));

    const too_big = ObjectHeader{
        .group = 1,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .count_1b },
        .range = .{ .count = 300 },
    };
    try testing.expectError(error.ValueOutOfRange, encodeObjectHeader(too_big, &out));
}

test "object header: decode never panics on short/garbage input" {
    try testing.expectError(error.ShortHeader, decodeObjectHeader(&.{ 1, 2 }));
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const garbage: [8]u8 = .{0xFF} ** 8;
        _ = decodeObjectHeader(garbage[0..i]) catch {};
    }
}

test "flags byte round-trip" {
    const f = Flags{ .online = true, .comm_lost = true, .bit7 = true };
    const b = f.toByte();
    try testing.expectEqual(@as(u8, 0x01 | 0x04 | 0x80), b);
    const back = Flags.fromByte(b);
    try testing.expectEqual(f.online, back.online);
    try testing.expectEqual(f.comm_lost, back.comm_lost);
    try testing.expectEqual(f.bit7, back.bit7);
}

test "g1v1: packed bits round-trip" {
    const values = [_]bool{ true, false, true, true, false, false, false, true, true };
    var packed_out: [2]u8 = undefined;
    const bytes = try g1.packBits(&values, &packed_out);
    try testing.expectEqual(@as(usize, 2), bytes.len);
    try testing.expectEqual(@as(u8, 0b1000_1101), bytes[0]);

    var unpacked: [9]bool = undefined;
    try g1.unpackBits(bytes, 9, &unpacked);
    try testing.expectEqualSlices(bool, &values, &unpacked);
}

test "g1v2 binary input with flags round-trip" {
    const point = g1.V2{ .flags = .{ .online = true, .bit7 = true } };
    var out: [8]u8 = undefined;
    const bytes = try point.encode(&out);
    try testing.expectEqual(@as(usize, 1), bytes.len);
    const back = try g1.V2.decode(bytes);
    try testing.expect(back.flags.online);
    try testing.expect(back.flags.bit7);
}

test "g12v1 CROB round-trip (pulse-on close, 3 ops, 100ms/50ms)" {
    const crob = g12.V1{
        .control_code = .{ .op_type = .pulse_on, .tcc = .close },
        .count = 3,
        .on_time_ms = 100,
        .off_time_ms = 50,
        .status = .success,
    };
    var out: [16]u8 = undefined;
    const bytes = try crob.encode(&out);
    try testing.expectEqual(@as(usize, 11), bytes.len);
    const back = try g12.V1.decode(bytes);
    try testing.expectEqual(g12.OpType.pulse_on, back.control_code.op_type);
    try testing.expectEqual(g12.TripCloseCode.close, back.control_code.tcc);
    try testing.expectEqual(@as(u8, 3), back.count);
    try testing.expectEqual(@as(u32, 100), back.on_time_ms);
    try testing.expectEqual(@as(u32, 50), back.off_time_ms);
    try testing.expectEqual(g12.CommandStatus.success, back.status);
}

test "g20 counter v1/v2 round-trip" {
    var out: [8]u8 = undefined;
    const v1 = g20.V1{ .flags = .{ .online = true }, .value = 123456 };
    const b1 = try v1.encode(&out);
    const back1 = try g20.V1.decode(b1);
    try testing.expectEqual(@as(u32, 123456), back1.value);

    const v2 = g20.V2{ .flags = .{}, .value = 4321 };
    const b2 = try v2.encode(&out);
    const back2 = try g20.V2.decode(b2);
    try testing.expectEqual(@as(u16, 4321), back2.value);
}

test "g30 analog input v1/v2/v5 round-trip (incl. negative + float)" {
    var out: [8]u8 = undefined;
    const v1 = g30.V1{ .flags = .{}, .value = -12345 };
    const back1 = try g30.V1.decode(try v1.encode(&out));
    try testing.expectEqual(@as(i32, -12345), back1.value);

    const v2 = g30.V2{ .flags = .{}, .value = -100 };
    const back2 = try g30.V2.decode(try v2.encode(&out));
    try testing.expectEqual(@as(i16, -100), back2.value);

    const v5 = g30.V5{ .flags = .{}, .value = 3.14159 };
    const back5 = try g30.V5.decode(try v5.encode(&out));
    try testing.expectApproxEqAbs(@as(f32, 3.14159), back5.value, 0.0001);
}

test "g40 analog output status round-trip" {
    var out: [8]u8 = undefined;
    const v1 = g40.V1{ .flags = .{ .online = true }, .value = 42 };
    const back = try g40.V1.decode(try v1.encode(&out));
    try testing.expectEqual(@as(i32, 42), back.value);
}

test "g41 analog output block round-trip (v1/v2/v3)" {
    var out: [8]u8 = undefined;
    const v1 = g41.V1{ .value = -7, .status = .success };
    const back1 = try g41.V1.decode(try v1.encode(&out));
    try testing.expectEqual(@as(i32, -7), back1.value);

    const v2 = g41.V2{ .value = 9, .status = .out_of_range };
    const back2 = try g41.V2.decode(try v2.encode(&out));
    try testing.expectEqual(@as(i16, 9), back2.value);
    try testing.expectEqual(g12.CommandStatus.out_of_range, back2.status);

    const v3 = g41.V3{ .value = 2.5, .status = .success };
    const back3 = try g41.V3.decode(try v3.encode(&out));
    try testing.expectEqual(@as(f32, 2.5), back3.value);
}

test "g50 time and date round-trip" {
    var out: [8]u8 = undefined;
    const t = g50.V1{ .ms_since_epoch = 1_789_000_123_456 };
    const bytes = try t.encode(&out);
    try testing.expectEqual(@as(usize, 6), bytes.len);
    const back = try g50.V1.decode(bytes);
    try testing.expectEqual(@as(u64, 1_789_000_123_456), back.ms_since_epoch);
}

test "record decode: short buffers are typed errors, never panics" {
    try testing.expectError(error.ShortRecord, g1.V2.decode(&.{}));
    try testing.expectError(error.ShortRecord, g12.V1.decode(&.{ 0, 0 }));
    try testing.expectError(error.ShortRecord, g20.V1.decode(&.{0}));
    try testing.expectError(error.ShortRecord, g30.V5.decode(&.{ 0, 0, 0 }));
    try testing.expectError(error.ShortRecord, g50.V1.decode(&.{ 0, 0 }));
}
