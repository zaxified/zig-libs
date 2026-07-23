// SPDX-License-Identifier: MIT

//! Information elements — the leaf encodings shared by every IEC 60870-5-101/
//! -104 ASDU (IEC 60870-5-101 §7.2.6): the quality descriptor, the point
//! value types (SIQ/DIQ/VTI/BSI/NVA/SVA/R32/BCR), the command qualifiers
//! (SCO/DCO/RCO/QOS/QOI/QCC/QRP/COI) and the CP56Time2a / CP24Time2a /
//! CP16Time2a time tags.
//!
//! Every element is a plain struct with explicit `toByte`/`fromByte` (or
//! `encode`/`decode`) shifts rather than a `packed struct`, so the wire layout
//! never depends on Zig's bitfield-packing rules. Multi-octet integers are
//! little-endian, as the standard prescribes for the 101/104 profiles.
//!
//! No allocation, no I/O, no clock: a `CP56Time2a` is a value the caller
//! supplies or receives, never something this module reads from a system
//! clock.

const std = @import("std");

// ── quality descriptor ──────────────────────────────────────────────────────

/// The quality descriptor QDS (§7.2.6.3) and the quality bits shared by SIQ
/// (§7.2.6.1) and DIQ (§7.2.6.2).
///
/// * `ov` — OVERFLOW: the value is beyond the defined range (QDS only; the bit
///   is reserved in SIQ/DIQ).
/// * `bl` — BLOCKED: the value is blocked for transmission at the source.
/// * `sb` — SUBSTITUTED: the value was entered by an operator, not measured.
/// * `nt` — NOT TOPICAL: the value was not refreshed within a set interval.
/// * `iv` — INVALID: the value is unusable; a receiver must not act on it.
pub const Quality = struct {
    ov: bool = false,
    bl: bool = false,
    sb: bool = false,
    nt: bool = false,
    iv: bool = false,

    pub const ov_bit: u8 = 0x01;
    pub const bl_bit: u8 = 0x10;
    pub const sb_bit: u8 = 0x20;
    pub const nt_bit: u8 = 0x40;
    pub const iv_bit: u8 = 0x80;
    /// Every bit this type owns; the remainder (0x0E) is reserved and, per
    /// §7.2.6.3, must be transmitted as zero.
    pub const mask: u8 = ov_bit | bl_bit | sb_bit | nt_bit | iv_bit;

    pub fn toByte(self: Quality) u8 {
        var b: u8 = 0;
        if (self.ov) b |= ov_bit;
        if (self.bl) b |= bl_bit;
        if (self.sb) b |= sb_bit;
        if (self.nt) b |= nt_bit;
        if (self.iv) b |= iv_bit;
        return b;
    }

    pub fn fromByte(b: u8) Quality {
        return .{
            .ov = b & ov_bit != 0,
            .bl = b & bl_bit != 0,
            .sb = b & sb_bit != 0,
            .nt = b & nt_bit != 0,
            .iv = b & iv_bit != 0,
        };
    }

    /// True when none of IV/NT/SB/BL/OV is set, i.e. the value is a good,
    /// current, measured reading.
    pub fn isGood(self: Quality) bool {
        return !(self.ov or self.bl or self.sb or self.nt or self.iv);
    }
};

// ── time tags ───────────────────────────────────────────────────────────────

pub const TimeError = error{
    /// A field is outside the range the standard allows (§7.2.6.18): minute
    /// > 59, hour > 23, day 0 or > 31, month 0 or > 12, year > 99, or the
    /// combined milliseconds field >= 60000.
    ImpossibleTime,
    /// Fewer octets than the tag needs.
    ShortTime,
};

/// CP56Time2a — the seven-octet time tag (§7.2.6.18).
///
/// Octets 0..1 are a single little-endian 16-bit field holding
/// `seconds * 1000 + milliseconds`, i.e. **seconds and milliseconds share one
/// field** and range 0..59999 together. The remaining octets carry minute+IV,
/// hour+SU, day-of-month+day-of-week, month and year (two digits, relative to
/// 2000 by convention — this module does not add the century, it reports the
/// two digits as transmitted).
pub const CP56Time2a = struct {
    /// 0..999
    millisecond: u16 = 0,
    /// 0..59
    second: u8 = 0,
    /// 0..59
    minute: u8 = 0,
    /// 0..23
    hour: u8 = 0,
    /// 1..31
    day: u8 = 1,
    /// 0 = not used, 1 = Monday .. 7 = Sunday
    day_of_week: u3 = 0,
    /// 1..12
    month: u8 = 1,
    /// 0..99 (years since 2000 by convention)
    year: u8 = 0,
    /// IV — the time is invalid (the sender's clock is not synchronised).
    invalid: bool = false,
    /// SU — summer time (daylight saving) is in effect.
    summer_time: bool = false,
    /// GEN — the time tag was substituted by the transmitting station rather
    /// than acquired with the value. Bit 6 of the minute octet.
    substituted: bool = false,

    pub const wire_len: usize = 7;

    pub fn encode(self: CP56Time2a, out: []u8) TimeError![]u8 {
        if (out.len < wire_len) return error.ShortTime;
        try self.validate();
        const ms: u16 = @as(u16, self.second) * 1000 + self.millisecond;
        out[0] = @truncate(ms);
        out[1] = @truncate(ms >> 8);
        out[2] = self.minute | (if (self.substituted) @as(u8, 0x40) else 0) |
            (if (self.invalid) @as(u8, 0x80) else 0);
        out[3] = self.hour | (if (self.summer_time) @as(u8, 0x80) else 0);
        out[4] = self.day | (@as(u8, self.day_of_week) << 5);
        out[5] = self.month;
        out[6] = self.year;
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) TimeError!CP56Time2a {
        if (bytes.len < wire_len) return error.ShortTime;
        const ms = @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
        if (ms >= 60000) return error.ImpossibleTime;
        const t = CP56Time2a{
            .millisecond = ms % 1000,
            .second = @intCast(ms / 1000),
            .minute = bytes[2] & 0x3F,
            .hour = bytes[3] & 0x1F,
            .day = bytes[4] & 0x1F,
            .day_of_week = @intCast((bytes[4] >> 5) & 0x07),
            .month = bytes[5] & 0x0F,
            .year = bytes[6] & 0x7F,
            .invalid = bytes[2] & 0x80 != 0,
            .summer_time = bytes[3] & 0x80 != 0,
            .substituted = bytes[2] & 0x40 != 0,
        };
        try t.validate();
        return t;
    }

    /// Range-checks every field. Called by both `encode` and `decode`, so an
    /// impossible time on the wire is a typed error rather than a struct a
    /// caller might act on. The IV flag is orthogonal: an IV-flagged tag whose
    /// fields are in range is still structurally valid.
    pub fn validate(self: CP56Time2a) TimeError!void {
        if (self.millisecond > 999) return error.ImpossibleTime;
        if (self.second > 59) return error.ImpossibleTime;
        if (self.minute > 59) return error.ImpossibleTime;
        if (self.hour > 23) return error.ImpossibleTime;
        if (self.day == 0 or self.day > 31) return error.ImpossibleTime;
        if (self.month == 0 or self.month > 12) return error.ImpossibleTime;
        if (self.year > 99) return error.ImpossibleTime;
    }
};

/// CP24Time2a — the three-octet time tag (§7.2.6.17): milliseconds+seconds
/// and minute+IV only, used by the type IDs 2/4/6/8/10/12/14/16.
pub const CP24Time2a = struct {
    millisecond: u16 = 0,
    second: u8 = 0,
    minute: u8 = 0,
    invalid: bool = false,
    substituted: bool = false,

    pub const wire_len: usize = 3;

    pub fn encode(self: CP24Time2a, out: []u8) TimeError![]u8 {
        if (out.len < wire_len) return error.ShortTime;
        if (self.millisecond > 999 or self.second > 59 or self.minute > 59) return error.ImpossibleTime;
        const ms: u16 = @as(u16, self.second) * 1000 + self.millisecond;
        out[0] = @truncate(ms);
        out[1] = @truncate(ms >> 8);
        out[2] = self.minute | (if (self.substituted) @as(u8, 0x40) else 0) |
            (if (self.invalid) @as(u8, 0x80) else 0);
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) TimeError!CP24Time2a {
        if (bytes.len < wire_len) return error.ShortTime;
        const ms = @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
        if (ms >= 60000) return error.ImpossibleTime;
        const minute = bytes[2] & 0x3F;
        if (minute > 59) return error.ImpossibleTime;
        return .{
            .millisecond = ms % 1000,
            .second = @intCast(ms / 1000),
            .minute = minute,
            .invalid = bytes[2] & 0x80 != 0,
            .substituted = bytes[2] & 0x40 != 0,
        };
    }
};

/// CP16Time2a — the two-octet elapsed-time tag (§7.2.6.16), a plain
/// little-endian millisecond count.
pub const CP16Time2a = struct {
    milliseconds: u16 = 0,

    pub const wire_len: usize = 2;

    pub fn encode(self: CP16Time2a, out: []u8) TimeError![]u8 {
        if (out.len < wire_len) return error.ShortTime;
        out[0] = @truncate(self.milliseconds);
        out[1] = @truncate(self.milliseconds >> 8);
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) TimeError!CP16Time2a {
        if (bytes.len < wire_len) return error.ShortTime;
        return .{ .milliseconds = @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8) };
    }
};

// ── point value elements ────────────────────────────────────────────────────

/// SIQ — single-point information with quality (§7.2.6.1). Bit 0 is the point
/// state, bits 4..7 the BL/SB/NT/IV quality bits.
pub const Siq = struct {
    on: bool = false,
    quality: Quality = .{},

    pub fn toByte(self: Siq) u8 {
        // OV is reserved in SIQ; mask it out so a caller that reused a QDS
        // cannot smuggle it onto the wire.
        return (if (self.on) @as(u8, 0x01) else 0) | (self.quality.toByte() & ~Quality.ov_bit);
    }

    pub fn fromByte(b: u8) Siq {
        return .{ .on = b & 0x01 != 0, .quality = Quality.fromByte(b & ~@as(u8, 0x01)) };
    }
};

/// Double-point state (§7.2.6.2). `intermediate` and `indeterminate` are the
/// two fault states of a two-contact indication.
pub const DoublePoint = enum(u2) {
    intermediate = 0,
    off = 1,
    on = 2,
    indeterminate = 3,
};

/// DIQ — double-point information with quality (§7.2.6.2).
pub const Diq = struct {
    state: DoublePoint = .intermediate,
    quality: Quality = .{},

    pub fn toByte(self: Diq) u8 {
        return @as(u8, @intFromEnum(self.state)) | (self.quality.toByte() & ~Quality.ov_bit);
    }

    pub fn fromByte(b: u8) Diq {
        return .{
            .state = @enumFromInt(@as(u2, @truncate(b))),
            .quality = Quality.fromByte(b & ~@as(u8, 0x03)),
        };
    }
};

/// VTI — value with transient state indication (§7.2.6.5): a signed 7-bit
/// step position plus a "transient" bit saying the step is still moving.
pub const Vti = struct {
    value: i8 = 0, // -64..63
    transient: bool = false,

    pub const min: i8 = -64;
    pub const max: i8 = 63;

    pub fn toByte(self: Vti) u8 {
        const raw: u8 = @as(u8, @bitCast(self.value)) & 0x7F;
        return raw | (if (self.transient) @as(u8, 0x80) else 0);
    }

    pub fn fromByte(b: u8) Vti {
        const seven: u7 = @truncate(b);
        const signed: i7 = @bitCast(seven);
        return .{ .value = signed, .transient = b & 0x80 != 0 };
    }
};

/// Normalised value NVA (§7.2.6.6): a 16-bit fixed-point fraction in
/// [-1, 1-2^-15], transmitted little-endian as a signed integer.
pub const Nva = struct {
    raw: i16 = 0,

    pub fn fromFloat(f: f32) Nva {
        const scaled = @round(f * 32768.0);
        const clamped = @max(-32768.0, @min(32767.0, scaled));
        return .{ .raw = @intFromFloat(clamped) };
    }

    pub fn toFloat(self: Nva) f32 {
        return @as(f32, @floatFromInt(self.raw)) / 32768.0;
    }
};

/// A binary counter reading BCR (§7.2.6.9): a signed 32-bit counter plus a
/// sequence number and the CY/CA/IV flags.
pub const Bcr = struct {
    counter: i32 = 0,
    /// Free-running 5-bit sequence number of the counter reading.
    sequence: u5 = 0,
    /// CY — the counter overflowed during the integration period.
    carry: bool = false,
    /// CA — the counter was adjusted (reset) during the integration period.
    adjusted: bool = false,
    /// IV — the reading is invalid.
    invalid: bool = false,

    pub const wire_len: usize = 5;

    pub fn encode(self: Bcr, out: []u8) []u8 {
        std.mem.writeInt(i32, out[0..4], self.counter, .little);
        out[4] = @as(u8, self.sequence) |
            (if (self.carry) @as(u8, 0x20) else 0) |
            (if (self.adjusted) @as(u8, 0x40) else 0) |
            (if (self.invalid) @as(u8, 0x80) else 0);
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) Bcr {
        return .{
            .counter = std.mem.readInt(i32, bytes[0..4], .little),
            .sequence = @truncate(bytes[4]),
            .carry = bytes[4] & 0x20 != 0,
            .adjusted = bytes[4] & 0x40 != 0,
            .invalid = bytes[4] & 0x80 != 0,
        };
    }
};

// ── command qualifiers ──────────────────────────────────────────────────────

/// Qualifier of command QU (§7.2.6.26), the 5-bit field shared by SCO/DCO/RCO.
pub const CommandQualifier = enum(u5) {
    /// No additional definition — the outstation's default behaviour.
    none = 0,
    short_pulse = 1,
    long_pulse = 2,
    persistent = 3,
    _,
};

/// Select/execute — the S/E bit (§7.2.6.26) that carries select-before-operate.
/// A `select` command reserves the output; the matching `execute` (same type,
/// same IOA, same value, S/E cleared) fires it.
pub const SelectExecute = enum(u1) { execute = 0, select = 1 };

/// SCO — single command (§7.2.6.15).
pub const Sco = struct {
    on: bool = false,
    qualifier: CommandQualifier = .none,
    select: SelectExecute = .execute,

    pub fn toByte(self: Sco) u8 {
        return (if (self.on) @as(u8, 0x01) else 0) |
            (@as(u8, @intFromEnum(self.qualifier)) << 2) |
            (@as(u8, @intFromEnum(self.select)) << 7);
    }

    pub fn fromByte(b: u8) Sco {
        return .{
            .on = b & 0x01 != 0,
            .qualifier = @enumFromInt(@as(u5, @truncate(b >> 2))),
            .select = @enumFromInt(@as(u1, @truncate(b >> 7))),
        };
    }
};

/// DCO — double command (§7.2.6.16). State 0 and 3 are "not permitted".
pub const Dco = struct {
    state: DoublePoint = .off,
    qualifier: CommandQualifier = .none,
    select: SelectExecute = .execute,

    pub fn toByte(self: Dco) u8 {
        return @as(u8, @intFromEnum(self.state)) |
            (@as(u8, @intFromEnum(self.qualifier)) << 2) |
            (@as(u8, @intFromEnum(self.select)) << 7);
    }

    pub fn fromByte(b: u8) Dco {
        return .{
            .state = @enumFromInt(@as(u2, @truncate(b))),
            .qualifier = @enumFromInt(@as(u5, @truncate(b >> 2))),
            .select = @enumFromInt(@as(u1, @truncate(b >> 7))),
        };
    }
};

/// Regulating-step command state (§7.2.6.17).
pub const StepCommand = enum(u2) {
    not_permitted_0 = 0,
    lower = 1,
    higher = 2,
    not_permitted_3 = 3,
};

/// RCO — regulating step command (§7.2.6.17).
pub const Rco = struct {
    step: StepCommand = .lower,
    qualifier: CommandQualifier = .none,
    select: SelectExecute = .execute,

    pub fn toByte(self: Rco) u8 {
        return @as(u8, @intFromEnum(self.step)) |
            (@as(u8, @intFromEnum(self.qualifier)) << 2) |
            (@as(u8, @intFromEnum(self.select)) << 7);
    }

    pub fn fromByte(b: u8) Rco {
        return .{
            .step = @enumFromInt(@as(u2, @truncate(b))),
            .qualifier = @enumFromInt(@as(u5, @truncate(b >> 2))),
            .select = @enumFromInt(@as(u1, @truncate(b >> 7))),
        };
    }
};

/// QOS — qualifier of set-point command (§7.2.6.39), used by C_SE_NA/NB/NC.
/// Same S/E bit as SCO/DCO/RCO, with a 7-bit "QL" instead of QU.
pub const Qos = struct {
    ql: u7 = 0,
    select: SelectExecute = .execute,

    pub fn toByte(self: Qos) u8 {
        return @as(u8, self.ql) | (@as(u8, @intFromEnum(self.select)) << 7);
    }

    pub fn fromByte(b: u8) Qos {
        return .{ .ql = @truncate(b), .select = @enumFromInt(@as(u1, @truncate(b >> 7))) };
    }
};

/// QOI — qualifier of interrogation (§7.2.6.22). 20 is the station (general)
/// interrogation; 21..36 are the sixteen inventory groups.
pub const Qoi = enum(u8) {
    unused = 0,
    station = 20,
    group_1 = 21,
    group_16 = 36,
    _,

    pub fn group(n: u8) Qoi {
        std.debug.assert(n >= 1 and n <= 16);
        return @enumFromInt(20 + n);
    }
};

/// Request qualifier of a counter interrogation (§7.2.6.23, low six bits).
pub const CounterRequest = enum(u6) {
    unused = 0,
    group_1 = 1,
    group_2 = 2,
    group_3 = 3,
    group_4 = 4,
    general = 5,
    _,
};

/// Freeze qualifier of a counter interrogation (§7.2.6.23, top two bits).
pub const CounterFreeze = enum(u2) {
    /// Read without freezing.
    read = 0,
    /// Freeze without reset.
    freeze = 1,
    /// Freeze with reset.
    freeze_reset = 2,
    /// Reset the counter.
    reset = 3,
};

/// QCC — qualifier of counter interrogation (§7.2.6.23).
pub const Qcc = struct {
    request: CounterRequest = .general,
    freeze: CounterFreeze = .read,

    pub fn toByte(self: Qcc) u8 {
        return @as(u8, @intFromEnum(self.request)) | (@as(u8, @intFromEnum(self.freeze)) << 6);
    }

    pub fn fromByte(b: u8) Qcc {
        return .{
            .request = @enumFromInt(@as(u6, @truncate(b))),
            .freeze = @enumFromInt(@as(u2, @truncate(b >> 6))),
        };
    }
};

/// QRP — qualifier of reset process command (§7.2.6.27).
pub const Qrp = enum(u8) {
    unused = 0,
    general_reset = 1,
    reset_pending_events = 2,
    _,
};

/// COI — cause of initialisation (§7.2.6.21), carried by M_EI_NA_1.
pub const Coi = struct {
    /// 0 = local power switch on, 1 = local manual reset, 2 = remote reset.
    cause: u7 = 0,
    /// True when the outstation's parameters changed during initialisation.
    local_change: bool = false,

    pub fn toByte(self: Coi) u8 {
        return @as(u8, self.cause) | (if (self.local_change) @as(u8, 0x80) else 0);
    }

    pub fn fromByte(b: u8) Coi {
        return .{ .cause = @truncate(b), .local_change = b & 0x80 != 0 };
    }
};

// ── little-endian scalar helpers ────────────────────────────────────────────

/// Reads an IEEE-754 short float (§7.2.6.8) — four little-endian octets.
pub fn readF32(bytes: []const u8) f32 {
    return @bitCast(std.mem.readInt(u32, bytes[0..4], .little));
}

/// Writes an IEEE-754 short float (§7.2.6.8).
pub fn writeF32(out: []u8, v: f32) void {
    std.mem.writeInt(u32, out[0..4], @bitCast(v), .little);
}

/// Reads a scaled value SVA (§7.2.6.7) — a signed little-endian 16-bit int.
pub fn readI16(bytes: []const u8) i16 {
    return std.mem.readInt(i16, bytes[0..2], .little);
}

pub fn writeI16(out: []u8, v: i16) void {
    std.mem.writeInt(i16, out[0..2], v, .little);
}

/// Reads a bitstring BSI (§7.2.6.13) — 32 bits, little-endian.
pub fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

pub fn writeU32(out: []u8, v: u32) void {
    std.mem.writeInt(u32, out[0..4], v, .little);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "quality descriptor bit positions and round-trip" {
    try testing.expectEqual(@as(u8, 0x00), (Quality{}).toByte());
    try testing.expectEqual(@as(u8, 0x01), (Quality{ .ov = true }).toByte());
    try testing.expectEqual(@as(u8, 0x10), (Quality{ .bl = true }).toByte());
    try testing.expectEqual(@as(u8, 0x20), (Quality{ .sb = true }).toByte());
    try testing.expectEqual(@as(u8, 0x40), (Quality{ .nt = true }).toByte());
    try testing.expectEqual(@as(u8, 0x80), (Quality{ .iv = true }).toByte());
    try testing.expectEqual(@as(u8, 0xF1), (Quality{ .ov = true, .bl = true, .sb = true, .nt = true, .iv = true }).toByte());
    try testing.expect((Quality{}).isGood());
    try testing.expect(!(Quality{ .nt = true }).isGood());

    var b: u16 = 0;
    while (b < 256) : (b += 1) {
        const q = Quality.fromByte(@intCast(b));
        try testing.expectEqual(@as(u8, @intCast(b)) & Quality.mask, q.toByte());
    }
}

test "CP56Time2a: milliseconds and seconds share one 16-bit field" {
    // 38 s 135 ms -> 38135 = 0x94F7, little-endian F7 94.
    const t = CP56Time2a{
        .millisecond = 135,
        .second = 38,
        .minute = 18,
        .hour = 3,
        .day = 23,
        .day_of_week = 0,
        .month = 7,
        .year = 26,
    };
    var buf: [7]u8 = undefined;
    const enc = try t.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xF7, 0x94, 0x12, 0x03, 0x17, 0x07, 0x1A }, enc);
    const back = try CP56Time2a.decode(enc);
    try testing.expectEqual(t, back);
}

test "CP56Time2a: invalid and summer-time flags survive a round trip" {
    const t = CP56Time2a{
        .millisecond = 999,
        .second = 59,
        .minute = 59,
        .hour = 23,
        .day = 31,
        .day_of_week = 7,
        .month = 12,
        .year = 99,
        .invalid = true,
        .summer_time = true,
        .substituted = true,
    };
    var buf: [7]u8 = undefined;
    const enc = try t.encode(&buf);
    // ms 59999 = 0xEA5F; minute 59 | GEN 0x40 | IV 0x80 = 0xFB;
    // hour 23 | SU 0x80 = 0x97; day 31 | dow 7<<5 = 0xFF.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x5F, 0xEA, 0xFB, 0x97, 0xFF, 0x0C, 0x63 }, enc);
    try testing.expectEqual(t, try CP56Time2a.decode(enc));
}

test "CP56Time2a rejects impossible fields on both encode and decode" {
    var buf: [7]u8 = undefined;
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .minute = 60, .day = 1, .month = 1 }).encode(&buf));
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .hour = 24, .day = 1, .month = 1 }).encode(&buf));
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .day = 0, .month = 1 }).encode(&buf));
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .day = 32, .month = 1 }).encode(&buf));
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .day = 1, .month = 0 }).encode(&buf));
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .day = 1, .month = 13 }).encode(&buf));
    try testing.expectError(error.ImpossibleTime, (CP56Time2a{ .day = 1, .month = 1, .year = 100 }).encode(&buf));
    try testing.expectError(error.ShortTime, (CP56Time2a{ .day = 1, .month = 1 }).encode(buf[0..6]));

    // 60000 ms would decode as second 60.
    try testing.expectError(error.ImpossibleTime, CP56Time2a.decode(&[_]u8{ 0x60, 0xEA, 0, 0, 1, 1, 0 }));
    // minute 60 (0x3C), hour 24 (0x18), day 0, month 0.
    try testing.expectError(error.ImpossibleTime, CP56Time2a.decode(&[_]u8{ 0, 0, 0x3C, 0, 1, 1, 0 }));
    try testing.expectError(error.ImpossibleTime, CP56Time2a.decode(&[_]u8{ 0, 0, 0, 0x18, 1, 1, 0 }));
    try testing.expectError(error.ImpossibleTime, CP56Time2a.decode(&[_]u8{ 0, 0, 0, 0, 0, 1, 0 }));
    try testing.expectError(error.ImpossibleTime, CP56Time2a.decode(&[_]u8{ 0, 0, 0, 0, 1, 0, 0 }));
    try testing.expectError(error.ShortTime, CP56Time2a.decode(&[_]u8{ 0, 0, 0, 0, 1, 1 }));
}

test "CP24Time2a and CP16Time2a round-trip" {
    var buf: [3]u8 = undefined;
    const t = CP24Time2a{ .millisecond = 500, .second = 12, .minute = 45, .invalid = true };
    const enc = try t.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x30, 0xAD }, enc); // 12500 = 0x30D4
    try testing.expectEqual(t, try CP24Time2a.decode(enc));
    try testing.expectError(error.ImpossibleTime, CP24Time2a.decode(&[_]u8{ 0x60, 0xEA, 0 }));

    var b2: [2]u8 = undefined;
    const e2 = try (CP16Time2a{ .milliseconds = 0xBEEF }).encode(&b2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xEF, 0xBE }, e2);
    try testing.expectEqual(@as(u16, 0xBEEF), (try CP16Time2a.decode(e2)).milliseconds);
}

test "SIQ / DIQ / VTI encode the value in the low bits and quality above" {
    try testing.expectEqual(@as(u8, 0x01), (Siq{ .on = true }).toByte());
    try testing.expectEqual(@as(u8, 0x81), (Siq{ .on = true, .quality = .{ .iv = true } }).toByte());
    // OV is reserved in SIQ and must not reach the wire.
    try testing.expectEqual(@as(u8, 0x00), (Siq{ .quality = .{ .ov = true } }).toByte());
    try testing.expect(Siq.fromByte(0x81).on);
    try testing.expect(Siq.fromByte(0x81).quality.iv);

    try testing.expectEqual(@as(u8, 0x02), (Diq{ .state = .on }).toByte());
    try testing.expectEqual(DoublePoint.on, Diq.fromByte(0x02).state);
    try testing.expectEqual(DoublePoint.indeterminate, Diq.fromByte(0x43).state);
    try testing.expect(Diq.fromByte(0x43).quality.nt);

    try testing.expectEqual(@as(u8, 0x05), (Vti{ .value = 5 }).toByte());
    try testing.expectEqual(@as(i8, 5), Vti.fromByte(0x05).value);
    try testing.expectEqual(@as(u8, 0x85), (Vti{ .value = 5, .transient = true }).toByte());
    try testing.expect(Vti.fromByte(0x85).transient);
    // -1 is 0x7F in seven-bit two's complement.
    try testing.expectEqual(@as(u8, 0x7F), (Vti{ .value = -1 }).toByte());
    try testing.expectEqual(@as(i8, -1), Vti.fromByte(0x7F).value);
    try testing.expectEqual(@as(i8, -64), Vti.fromByte(0x40).value);
    try testing.expectEqual(@as(i8, 63), Vti.fromByte(0x3F).value);
}

test "NVA scales to and from a fraction of full scale" {
    try testing.expectEqual(@as(i16, 16384), Nva.fromFloat(0.5).raw);
    try testing.expectEqual(@as(i16, -8192), Nva.fromFloat(-0.25).raw);
    try testing.expectApproxEqAbs(@as(f32, 0.5), (Nva{ .raw = 16384 }).toFloat(), 1e-6);
    try testing.expectApproxEqAbs(@as(f32, -1.0), (Nva{ .raw = -32768 }).toFloat(), 1e-6);
    // Saturating rather than wrapping at the ends of the range.
    try testing.expectEqual(@as(i16, 32767), Nva.fromFloat(2.0).raw);
    try testing.expectEqual(@as(i16, -32768), Nva.fromFloat(-2.0).raw);
}

test "BCR round-trip with all flags" {
    var buf: [5]u8 = undefined;
    const b = Bcr{ .counter = -2, .sequence = 3, .carry = true, .adjusted = true, .invalid = true };
    const enc = b.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFE, 0xFF, 0xFF, 0xFF, 0xE3 }, enc);
    try testing.expectEqual(b, Bcr.decode(enc));
}

test "command qualifiers: the S/E bit is bit 7 in every one of them" {
    try testing.expectEqual(@as(u8, 0x81), (Sco{ .on = true, .select = .select }).toByte());
    try testing.expectEqual(@as(u8, 0x01), (Sco{ .on = true }).toByte());
    try testing.expectEqual(SelectExecute.select, Sco.fromByte(0x81).select);
    try testing.expectEqual(SelectExecute.execute, Sco.fromByte(0x01).select);

    try testing.expectEqual(@as(u8, 0x82), (Dco{ .state = .on, .select = .select }).toByte());
    try testing.expectEqual(@as(u8, 0x02), (Rco{ .step = .higher }).toByte());
    try testing.expectEqual(@as(u8, 0x80), (Qos{ .select = .select }).toByte());
    try testing.expectEqual(@as(u8, 0x00), (Qos{}).toByte());
    try testing.expectEqual(SelectExecute.select, Qos.fromByte(0x80).select);

    // The qualifier field sits between the value bits and the S/E bit.
    try testing.expectEqual(@as(u8, 0x85), (Sco{ .on = true, .qualifier = .short_pulse, .select = .select }).toByte());
    try testing.expectEqual(CommandQualifier.short_pulse, Sco.fromByte(0x85).qualifier);
}

test "QCC packs the request in the low six bits and the freeze above" {
    try testing.expectEqual(@as(u8, 0x05), (Qcc{ .request = .general, .freeze = .read }).toByte());
    try testing.expectEqual(@as(u8, 0x45), (Qcc{ .request = .general, .freeze = .freeze }).toByte());
    const q = Qcc.fromByte(0x85);
    try testing.expectEqual(CounterRequest.general, q.request);
    try testing.expectEqual(CounterFreeze.freeze_reset, q.freeze);
    try testing.expectEqual(Qoi.station, @as(Qoi, @enumFromInt(20)));
    try testing.expectEqual(Qoi.group_1, Qoi.group(1));
    try testing.expectEqual(Qoi.group_16, Qoi.group(16));
}

test "COI splits the cause from the local-change flag" {
    try testing.expectEqual(@as(u8, 0x00), (Coi{}).toByte());
    try testing.expectEqual(@as(u8, 0x82), (Coi{ .cause = 2, .local_change = true }).toByte());
    const c = Coi.fromByte(0x81);
    try testing.expectEqual(@as(u7, 1), c.cause);
    try testing.expect(c.local_change);
}

test "scalar helpers are little-endian" {
    var buf: [4]u8 = undefined;
    writeF32(&buf, 3.14159);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD0, 0x0F, 0x49, 0x40 }, &buf);
    try testing.expectEqual(@as(f32, 3.14159), readF32(&buf));
    writeI16(buf[0..2], -1234);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x2E, 0xFB }, buf[0..2]);
    try testing.expectEqual(@as(i16, -1234), readI16(&buf));
    writeU32(&buf, 0x12345678);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x78, 0x56, 0x34, 0x12 }, &buf);
    try testing.expectEqual(@as(u32, 0x12345678), readU32(&buf));
}

test "fuzz: CP56Time2a decode never panics and always round-trips" {
    try std.testing.fuzz({}, fuzzTime, .{});
}

fn fuzzTime(_: void, smith: *std.testing.Smith) !void {
    var buf: [7]u8 = undefined;
    smith.bytes(&buf);
    const t = CP56Time2a.decode(&buf) catch return;
    var again: [7]u8 = undefined;
    _ = try t.encode(&again);
    try testing.expectEqual(t, try CP56Time2a.decode(&again));
}
