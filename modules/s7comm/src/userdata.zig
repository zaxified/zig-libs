// SPDX-License-Identifier: MIT

//! Userdata (ROSCTR `0x07`) — the second, completely different request shape
//! S7 uses for everything that is not a variable access: reading the system
//! status list (SZL), CPU identification, block services, cyclic services,
//! security, time-of-day.
//!
//! A Userdata parameter block is *not* a `<function> <count>` pair. It has its
//! own sub-header:
//!
//! ```text
//! request  (8 octets):  0x00 0x01 0x12  0x04  0x11  <type|group>  <subfn>  <seq>
//! response (12 octets): 0x00 0x01 0x12  0x08  0x12  <type|group>  <subfn>  <seq>
//!                       <data unit ref> <last data unit> <error code:2>
//! ```
//!
//! * `0x000112` is a fixed head.
//! * The fourth octet is the length of what follows it (4 for a request, 8 for
//!   a response) — so the *parameter block* length and this octet must agree,
//!   and a decoder must use it rather than assuming.
//! * `type|group` packs the message type in the high nibble (4 = request,
//!   8 = response, 0 = push) and the function group in the low nibble.
//! * The response carries `last data unit`: `0x00` (`no_more`) is the last
//!   PDU of the response, `0x01` means more follow. A long SZL list arrives as
//!   several PDUs and a client that ignores this returns a truncated list.
//!
//! The payload then sits in the **data** block behind an ordinary
//! `<return code> <transport size> <length:2>` header, with the length counted
//! in octets because the transport size is `octet_string` (9).

const std = @import("std");
const items = @import("items.zig");

pub const Error = error{
    /// Fewer octets than the sub-header needs.
    ShortParameters,
    /// The fixed `0x000112` head is missing.
    BadHead,
    /// The length octet disagrees with the block.
    BadParameterLength,
    /// The data block is shorter than its own header claims.
    ShortData,
    /// The data block's return code reports a failure.
    DataError,
    /// The SZL header is missing or its record table does not fit.
    BadSzl,
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// A date-time is not the 10-octet form, has a BCD digit above 9, or a
    /// field outside its range (month, day of month, hour, ...).
    BadDateTime,
} || items.Error;

/// High nibble of the `type|group` octet.
pub const MessageType = enum(u4) {
    /// Unsolicited push (cyclic services).
    push = 0,
    request = 4,
    response = 8,
    _,
};

/// Low nibble of the `type|group` octet.
pub const FunctionGroup = enum(u4) {
    mode_transition = 0x0,
    programmer_commands = 0x1,
    cyclic_services = 0x2,
    block_functions = 0x3,
    /// CPU functions: read SZL, message services.
    cpu_functions = 0x4,
    security = 0x5,
    /// Programmable-block communication.
    pbc = 0x6,
    time_functions = 0x7,
    _,
};

/// Subfunctions of `cpu_functions`.
pub const CpuSubfunction = enum(u8) {
    read_szl = 0x01,
    message_service = 0x02,
    diagnostic_message = 0x03,
    alarm8_indication = 0x05,
    _,
};

/// Subfunctions of `time_functions` (group 7). `0x03` and `0x04` are the
/// variants some engineering tools use; the wire payload is the same.
pub const TimeSubfunction = enum(u8) {
    read_clock = 0x01,
    set_clock = 0x02,
    read_clock_following = 0x03,
    set_clock_alt = 0x04,
    _,
};

/// `last data unit` values.
///
/// Polarity is grounded in captured traffic: every **complete** single-PDU
/// response observed carried `0x00`, so `0x00` is "this is the last one".
/// A fragmented response was never observed here — see SPEC.md.
pub const LastDataUnit = enum(u8) {
    /// This is the last PDU of the response.
    no_more = 0x00,
    /// More PDUs follow.
    more_follows = 0x01,
    _,
};

/// The Userdata parameter sub-header.
pub const Param = struct {
    message_type: MessageType,
    function_group: FunctionGroup,
    subfunction: u8,
    /// Echoed by the PLC; the client increments it per request.
    sequence: u8 = 0,
    // Response-only fields.
    data_unit_ref: u8 = 0,
    last_data_unit: LastDataUnit = .no_more,
    error_code: u16 = 0,

    pub const request_len: usize = 8;
    pub const response_len: usize = 12;

    pub fn isResponse(self: Param) bool {
        return self.message_type == .response;
    }

    pub fn encodeRequest(self: Param, out: []u8) Error![]u8 {
        if (out.len < request_len) return error.BufferTooSmall;
        out[0] = 0x00;
        out[1] = 0x01;
        out[2] = 0x12;
        out[3] = 0x04; // length of what follows
        out[4] = 0x11; // request method
        out[5] = (@as(u8, @backingInt(self.message_type)) << 4) |
            @as(u8, @backingInt(self.function_group));
        out[6] = self.subfunction;
        out[7] = self.sequence;
        return out[0..request_len];
    }

    pub fn encodeResponse(self: Param, out: []u8) Error![]u8 {
        if (out.len < response_len) return error.BufferTooSmall;
        out[0] = 0x00;
        out[1] = 0x01;
        out[2] = 0x12;
        out[3] = 0x08;
        out[4] = 0x12; // response method
        out[5] = (@as(u8, @backingInt(self.message_type)) << 4) |
            @as(u8, @backingInt(self.function_group));
        out[6] = self.subfunction;
        out[7] = self.sequence;
        out[8] = self.data_unit_ref;
        out[9] = @backingInt(self.last_data_unit);
        out[10] = @intCast(self.error_code >> 8);
        out[11] = @intCast(self.error_code & 0xFF);
        return out[0..response_len];
    }

    pub fn decode(bytes: []const u8) Error!Param {
        if (bytes.len < request_len) return error.ShortParameters;
        if (bytes[0] != 0x00 or bytes[1] != 0x01 or bytes[2] != 0x12) return error.BadHead;
        const follows: usize = bytes[3];
        // The length octet counts from octet 4 onwards.
        if (4 + follows != bytes.len) return error.BadParameterLength;
        var p: Param = .{
            .message_type = @fromBackingInt(@intCast(@as(u4, @intCast(bytes[5] >> 4)))),
            .function_group = @fromBackingInt(@intCast(@as(u4, @intCast(bytes[5] & 0x0F)))),
            .subfunction = bytes[6],
            .sequence = bytes[7],
        };
        if (follows >= 8) {
            if (bytes.len < response_len) return error.ShortParameters;
            p.data_unit_ref = bytes[8];
            p.last_data_unit = @fromBackingInt(@intCast(bytes[9]));
            p.error_code = (@as(u16, bytes[10]) << 8) | bytes[11];
        }
        return p;
    }
};

/// The `<return code> <transport size> <length:2>` header the Userdata payload
/// sits behind, and the payload itself.
pub const DataBlock = struct {
    return_code: items.ReturnCode,
    transport_size: items.DataTransportSize,
    payload: []const u8,

    pub fn decode(bytes: []const u8) Error!DataBlock {
        if (bytes.len < 4) return error.ShortData;
        const rc: items.ReturnCode = @fromBackingInt(@intCast(bytes[0]));
        const ts: items.DataTransportSize = @fromBackingInt(@intCast(bytes[1]));
        const raw: u16 = (@as(u16, bytes[2]) << 8) | bytes[3];
        // F9: this used to compute `raw / 8` by hand for a bit-counted
        // length, silently floor-dividing a length that is not a whole
        // number of octets -- `items.decodeLength` (the same wire concept,
        // used by `items.DataItemIterator` for Read/Write Var) refuses that
        // shape instead. Two decoders for the same length encoding
        // disagreeing inside one module is exactly the parser differential
        // an OT monitor watching the wire with one rule would desync on.
        const n = try items.decodeLength(ts, raw);
        if (4 + n > bytes.len) return error.ShortData;
        return .{ .return_code = rc, .transport_size = ts, .payload = bytes[4..][0..n] };
    }

    pub fn encode(rc: items.ReturnCode, ts: items.DataTransportSize, payload: []const u8, out: []u8) Error![]u8 {
        if (out.len < 4 + payload.len) return error.BufferTooSmall;
        const raw: u16 = if (ts.lengthInBits())
            @intCast(payload.len * 8)
        else
            @intCast(payload.len);
        out[0] = @backingInt(rc);
        out[1] = @backingInt(ts);
        out[2] = @intCast(raw >> 8);
        out[3] = @intCast(raw & 0xFF);
        @memcpy(out[4..][0..payload.len], payload);
        return out[0 .. 4 + payload.len];
    }
};

// ── Read SZL ────────────────────────────────────────────────────────────────

/// A `Read SZL` request payload: the list id and the index within it.
pub const SzlRequest = struct {
    id: u16,
    index: u16 = 0,

    pub fn encode(self: SzlRequest, out: []u8) Error![]u8 {
        if (out.len < 4) return error.BufferTooSmall;
        out[0] = @intCast(self.id >> 8);
        out[1] = @intCast(self.id & 0xFF);
        out[2] = @intCast(self.index >> 8);
        out[3] = @intCast(self.index & 0xFF);
        return out[0..4];
    }

    pub fn decode(bytes: []const u8) Error!SzlRequest {
        if (bytes.len < 4) return error.BadSzl;
        return .{
            .id = (@as(u16, bytes[0]) << 8) | bytes[1],
            .index = (@as(u16, bytes[2]) << 8) | bytes[3],
        };
    }
};

/// The eight-octet header of an SZL response payload.
pub const SzlHeader = struct {
    id: u16,
    index: u16,
    /// Octets in one record.
    record_length: u16,
    /// Records in this PDU.
    record_count: u16,

    pub const wire_len: usize = 8;
};

/// A decoded SZL response: header plus a record table.
pub const SzlResponse = struct {
    header: SzlHeader,
    records: []const u8,

    /// Record `i`, or null when out of range.
    pub fn record(self: SzlResponse, i: usize) ?[]const u8 {
        const rl: usize = self.header.record_length;
        if (rl == 0) return null;
        if (i >= self.header.record_count) return null;
        const off = i * rl;
        if (off + rl > self.records.len) return null;
        return self.records[off..][0..rl];
    }

    pub fn decode(bytes: []const u8) Error!SzlResponse {
        if (bytes.len < SzlHeader.wire_len) return error.BadSzl;
        const h: SzlHeader = .{
            .id = (@as(u16, bytes[0]) << 8) | bytes[1],
            .index = (@as(u16, bytes[2]) << 8) | bytes[3],
            .record_length = (@as(u16, bytes[4]) << 8) | bytes[5],
            .record_count = (@as(u16, bytes[6]) << 8) | bytes[7],
        };
        const records = bytes[SzlHeader.wire_len..];
        // The table must fit: a header promising more than arrived is exactly
        // how a hostile peer would try to walk a reader off the end.
        const need = @as(usize, h.record_length) * @as(usize, h.record_count);
        if (need > records.len) return error.BadSzl;
        return .{ .header = h, .records = records[0..need] };
    }

    pub fn encode(h: SzlHeader, records: []const u8, out: []u8) Error![]u8 {
        if (out.len < SzlHeader.wire_len + records.len) return error.BufferTooSmall;
        out[0] = @intCast(h.id >> 8);
        out[1] = @intCast(h.id & 0xFF);
        out[2] = @intCast(h.index >> 8);
        out[3] = @intCast(h.index & 0xFF);
        out[4] = @intCast(h.record_length >> 8);
        out[5] = @intCast(h.record_length & 0xFF);
        out[6] = @intCast(h.record_count >> 8);
        out[7] = @intCast(h.record_count & 0xFF);
        @memcpy(out[8..][0..records.len], records);
        return out[0 .. 8 + records.len];
    }
};

/// SZL list ids worth naming. The full set is large and CPU-specific.
pub const SzlId = struct {
    /// Module identification: order number, hardware and firmware version.
    pub const module_identification: u16 = 0x0011;
    /// Component identification: names, serial number, copyright.
    pub const component_identification: u16 = 0x001C;
    /// Interrupt status.
    pub const interrupt_status: u16 = 0x0022;
    /// Communication status data.
    pub const communication_status: u16 = 0x0132;
    /// CPU protection level and operating mode.
    pub const protection_status: u16 = 0x0232;
    /// Status of the module LEDs.
    pub const led_status: u16 = 0x0074;
    /// Mode-transition / status of the CPU (what "get CPU state" reads).
    pub const cpu_status: u16 = 0x0424;
};

/// The operating mode, from the `bzu_id` octet of an SZL `0x0424` record.
pub const CpuStatus = enum(u8) {
    unknown = 0x00,
    stop = 0x04,
    run = 0x08,
    _,
};

/// Offset of the operating-mode octet inside a `0x0424` record.
/// Grounded in captured traffic: the same CPU returned `…5144 ff 08…` while
/// running and `…5144 ff 04…` after a stop, with everything else identical.
pub const cpu_status_offset: usize = 3;

/// Reads the CPU status out of an SZL `0x0424` response.
pub fn cpuStatusFrom(resp: SzlResponse) ?CpuStatus {
    const rec = resp.record(0) orelse return null;
    if (rec.len <= cpu_status_offset) return null;
    return @fromBackingInt(@intCast(rec[cpu_status_offset]));
}

// ── Time of day ─────────────────────────────────────────────────────────────

/// The S7 date-time of the time-of-day services, the 10-octet BCD form:
///
/// ```text
/// reserved  year1  year2  month  day  hour  minute  second  ms(hundreds,tens)  ms(units)|weekday
/// ```
///
/// Every octet is two BCD digits except the last, whose high nibble is the
/// units digit of the milliseconds and whose low nibble is the weekday
/// (1 = Sunday .. 7 = Saturday, 0 = undefined). `year1` is ignored on decode
/// (some CPUs send `0x19` for 20xx) and `year2` 00-89 means 2000-2089, 90-99
/// means 1990-1999. Layout after the Wireshark s7comm dissector (field layout
/// only) and the 8-octet S7 DATE_AND_TIME helper of gos7 (BSD-3), which this
/// form extends by the leading `reserved` and `year1` octets. Note: the
/// pure-Python python-snap7 uses an 8-octet form without those two octets and
/// Monday = 1; it is not a byte-layout oracle for this one.
pub const DateTime = struct {
    /// 1990..2089.
    year: u16,
    month: u8,
    day: u8,
    hour: u8 = 0,
    minute: u8 = 0,
    second: u8 = 0,
    millisecond: u16 = 0,
    /// 1 = Sunday .. 7 = Saturday, 0 = undefined.
    weekday: u8 = 0,

    pub const wire_len: usize = 10;

    /// Checks every field range, including the day of month for the month and
    /// leap year.
    pub fn validate(self: DateTime) Error!void {
        if (self.year < 1990 or self.year > 2089) return error.BadDateTime;
        if (self.month < 1 or self.month > 12) return error.BadDateTime;
        if (self.day < 1 or self.day > daysInMonth(self.year, self.month)) return error.BadDateTime;
        if (self.hour > 23 or self.minute > 59 or self.second > 59) return error.BadDateTime;
        if (self.millisecond > 999 or self.weekday > 7) return error.BadDateTime;
    }

    pub fn encode(self: DateTime, out: []u8) Error![]u8 {
        try self.validate();
        if (out.len < wire_len) return error.BufferTooSmall;
        const y: u8 = @intCast(self.year % 100);
        out[0] = 0x00;
        out[1] = if (self.year >= 2000) 0x20 else 0x19;
        out[2] = bcd(y);
        out[3] = bcd(self.month);
        out[4] = bcd(self.day);
        out[5] = bcd(self.hour);
        out[6] = bcd(self.minute);
        out[7] = bcd(self.second);
        out[8] = bcd(@intCast(self.millisecond / 10));
        out[9] = (@as(u8, @intCast(self.millisecond % 10)) << 4) | self.weekday;
        return out[0..wire_len];
    }

    /// Decodes exactly ten octets; any other length, a BCD digit above 9 or a
    /// field out of range is `BadDateTime`.
    pub fn decode(bytes: []const u8) Error!DateTime {
        if (bytes.len != wire_len) return error.BadDateTime;
        const year2 = try unbcd(bytes[2]);
        var ms: u16 = @as(u16, try unbcd(bytes[8])) * 10;
        const units = bytes[9] >> 4;
        if (units > 9) return error.BadDateTime;
        ms += units;
        const dt: DateTime = .{
            .year = (if (year2 < 90) @as(u16, 2000) else 1900) + year2,
            .month = try unbcd(bytes[3]),
            .day = try unbcd(bytes[4]),
            .hour = try unbcd(bytes[5]),
            .minute = try unbcd(bytes[6]),
            .second = try unbcd(bytes[7]),
            .millisecond = ms,
            .weekday = bytes[9] & 0x0F,
        };
        try dt.validate();
        return dt;
    }

    /// Weekday (1 = Sunday .. 7 = Saturday) of the calendar date, for callers
    /// that fill `weekday` from a clock.
    pub fn weekdayOf(year: u16, month: u8, day: u8) u8 {
        // Sakamoto's method: 0 = Sunday.
        const t = [12]u16{ 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
        const y: u32 = if (month < 3) year - 1 else year;
        const w = (y + y / 4 - y / 100 + y / 400 + t[month - 1] + day) % 7;
        return @intCast(w + 1);
    }
};

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        else => if ((year % 4 == 0 and year % 100 != 0) or year % 400 == 0) 29 else 28,
    };
}

fn bcd(v: u8) u8 {
    return ((v / 10) << 4) | (v % 10);
}

fn unbcd(b: u8) Error!u8 {
    const hi = b >> 4;
    const lo = b & 0x0F;
    if (hi > 9 or lo > 9) return error.BadDateTime;
    return hi * 10 + lo;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "request sub-header round trip" {
    var buf: [16]u8 = undefined;
    const p: Param = .{
        .message_type = .request,
        .function_group = .cpu_functions,
        .subfunction = @backingInt(CpuSubfunction.read_szl),
        .sequence = 0,
    };
    const enc = try p.encodeRequest(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00 }, enc);
    const dec = try Param.decode(enc);
    try testing.expectEqual(MessageType.request, dec.message_type);
    try testing.expectEqual(FunctionGroup.cpu_functions, dec.function_group);
    try testing.expectEqual(@as(u8, 1), dec.subfunction);
}

test "response sub-header round trip" {
    var buf: [16]u8 = undefined;
    const p: Param = .{
        .message_type = .response,
        .function_group = .cpu_functions,
        .subfunction = 1,
        .sequence = 0,
        .last_data_unit = .no_more,
    };
    const enc = try p.encodeResponse(&buf);
    // Byte for byte what the captured snap7-server's Read-SZL response
    // carried (F13: the capture's peer was snap7's software server-emulator,
    // not a physical Siemens CPU).
    try testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, enc);
    const dec = try Param.decode(enc);
    try testing.expect(dec.isResponse());
    try testing.expectEqual(LastDataUnit.no_more, dec.last_data_unit);
    try testing.expectEqual(@as(u16, 0), dec.error_code);
}

test "sub-header decode rejects hostile input" {
    try testing.expectError(error.ShortParameters, Param.decode(&[_]u8{ 0x00, 0x01, 0x12 }));
    try testing.expectError(error.BadHead, Param.decode(&[_]u8{ 0x00, 0x02, 0x12, 0x04, 0x11, 0x44, 1, 0 }));
    // Length octet says 8 but only 8 octets are present.
    try testing.expectError(error.BadParameterLength, Param.decode(&[_]u8{ 0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 1, 0 }));
    // Length octet says 4 but 12 octets are present.
    try testing.expectError(error.BadParameterLength, Param.decode(&[_]u8{
        0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 1, 0, 0, 0, 0, 0,
    }));
}

test "SZL response decode and record access" {
    // Header: id 0x0011, index 0, record length 0x1C, 2 records.
    var wire: [8 + 56]u8 = undefined;
    var h: [8]u8 = .{ 0x00, 0x11, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x02 };
    @memcpy(wire[0..8], &h);
    for (wire[8..], 0..) |*b, i| b.* = @intCast(i % 251);
    const r = try SzlResponse.decode(&wire);
    try testing.expectEqual(@as(u16, 0x0011), r.header.id);
    try testing.expectEqual(@as(u16, 2), r.header.record_count);
    try testing.expectEqual(@as(usize, 28), r.record(0).?.len);
    try testing.expectEqual(@as(u8, 28), r.record(1).?[0]);
    try testing.expect(r.record(2) == null);

    // A record table that does not fit is refused rather than truncated.
    h[7] = 0x10; // 16 records of 28 octets = 448, only 56 present
    @memcpy(wire[0..8], &h);
    try testing.expectError(error.BadSzl, SzlResponse.decode(&wire));
    try testing.expectError(error.BadSzl, SzlResponse.decode(&[_]u8{ 0, 1, 2 }));
}

test "SZL request round trip" {
    var buf: [8]u8 = undefined;
    const enc = try (SzlRequest{ .id = 0x0132, .index = 4 }).encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x32, 0x00, 0x04 }, enc);
    const dec = try SzlRequest.decode(enc);
    try testing.expectEqual(@as(u16, 0x0132), dec.id);
    try testing.expectEqual(@as(u16, 4), dec.index);
    try testing.expectError(error.BadSzl, SzlRequest.decode(&[_]u8{ 1, 2 }));
}

test "userdata data block is octet-counted" {
    var buf: [64]u8 = undefined;
    const payload = [_]u8{ 0x00, 0x11, 0x00, 0x00 };
    const enc = try DataBlock.encode(.success, .octet_string, &payload, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x09, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00 }, enc);
    const dec = try DataBlock.decode(enc);
    try testing.expectEqualSlices(u8, &payload, dec.payload);
    // Announcing more than is present is refused.
    try testing.expectError(error.ShortData, DataBlock.decode(&[_]u8{ 0xFF, 0x09, 0x00, 0x40, 0x00 }));
    try testing.expectError(error.ShortData, DataBlock.decode(&[_]u8{ 0xFF, 0x09 }));
}

test "F9: a bit-counted length that is not a whole octet is refused, not floor-divided" {
    // Same values the audit measured directly against `items.decodeLength`
    // (`ts = byte_word_dword`, which is bit-counted): before the fix this
    // decoder computed `raw / 8` by hand and accepted every one of these,
    // silently returning 0 or 1 octets instead of refusing a length that
    // does not describe a whole number of octets.
    for ([_]u16{ 1, 4, 12, 15, 17 }) |raw| {
        var buf: [8]u8 = undefined;
        buf[0] = @backingInt(items.ReturnCode.success);
        buf[1] = @backingInt(items.DataTransportSize.byte_word_dword);
        buf[2] = @intCast(raw >> 8);
        buf[3] = @intCast(raw & 0xFF);
        try testing.expectError(error.LengthTransportMismatch, DataBlock.decode(buf[0..8]));
    }
    // Positive control: a multiple of 8 still decodes, at the octet count
    // `items.decodeLength` (and the old `raw / 8`) both agree on.
    var ok: [8]u8 = undefined;
    ok[0] = @backingInt(items.ReturnCode.success);
    ok[1] = @backingInt(items.DataTransportSize.byte_word_dword);
    ok[2] = 0;
    ok[3] = 16; // 16 bits = 2 octets
    const dec = try DataBlock.decode(&ok);
    try testing.expectEqual(@as(usize, 2), dec.payload.len);
}

test "date-time encodes to the 10-octet BCD form and back" {
    var buf: [10]u8 = undefined;
    const dt: DateTime = .{ .year = 2026, .month = 11, .day = 19, .hour = 13, .minute = 45, .second = 59, .millisecond = 987, .weekday = 5 };
    const enc = try dt.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x20, 0x26, 0x11, 0x19, 0x13, 0x45, 0x59, 0x98, 0x75 }, enc);
    try testing.expectEqual(dt, try DateTime.decode(enc));
    // 1990s: year2 90..99, century octet 0x19.
    const old: DateTime = .{ .year = 1999, .month = 12, .day = 31 };
    const e2 = try old.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x19, 0x99, 0x12, 0x31, 0, 0, 0, 0, 0 }, e2);
    try testing.expectEqual(@as(u16, 1999), (try DateTime.decode(e2)).year);
    const y2000 = try (DateTime{ .year = 2000, .month = 1, .day = 1 }).encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x20, 0x00 }, y2000[0..3]);
    // Boundaries of the year split: 89 -> 2089, 90 -> 1990.
    try testing.expectEqual(@as(u16, 2089), (try DateTime.decode(&[_]u8{ 0, 0x20, 0x89, 1, 1, 0, 0, 0, 0, 0 })).year);
    try testing.expectEqual(@as(u16, 1990), (try DateTime.decode(&[_]u8{ 0, 0x19, 0x90, 1, 1, 0, 0, 0, 0, 0 })).year);
    // year1 and the reserved octet are ignored.
    try testing.expectEqual(@as(u16, 2014), (try DateTime.decode(&[_]u8{ 0x07, 0x19, 0x14, 1, 1, 0, 0, 0, 0, 0 })).year);
    try testing.expectError(error.BufferTooSmall, dt.encode(buf[0..9]));
}

test "date-time decode rejects bad BCD, ranges and lengths" {
    const good = [_]u8{ 0x00, 0x20, 0x26, 0x02, 0x28, 0x23, 0x59, 0x59, 0x99, 0x97 };
    _ = try DateTime.decode(&good);
    try testing.expectError(error.BadDateTime, DateTime.decode(good[0..9]));
    var long: [11]u8 = undefined;
    @memcpy(long[0..10], &good);
    long[10] = 0;
    try testing.expectError(error.BadDateTime, DateTime.decode(&long));
    // Every octet position: a high nibble above 9 and a low nibble above 9.
    for ([_]usize{ 2, 3, 4, 5, 6, 7, 8 }) |i| {
        var b = good;
        b[i] = 0xA0 | (good[i] & 0x0F);
        try testing.expectError(error.BadDateTime, DateTime.decode(&b));
        b = good;
        b[i] = (good[i] & 0xF0) | 0x0A;
        try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    }
    var b = good;
    b[9] = 0xA7; // ms units digit 10
    try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    b = good;
    b[9] = 0x98; // weekday 8
    try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    b[9] = 0x90; // weekday 0 (undefined) is allowed
    _ = try DateTime.decode(&b);
    // Ranges: month 0/13, day 0/32, hour 24, minute 60, second 60.
    const cases = [_]struct { i: usize, v: u8 }{
        .{ .i = 3, .v = 0x00 }, .{ .i = 3, .v = 0x13 }, .{ .i = 4, .v = 0x00 }, .{ .i = 4, .v = 0x32 },
        .{ .i = 5, .v = 0x24 }, .{ .i = 6, .v = 0x60 }, .{ .i = 7, .v = 0x60 },
    };
    for (cases) |c| {
        b = good;
        b[c.i] = c.v;
        try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    }
    // Day of month: 30 February, 29 February in a non-leap year, 31 April.
    b = good;
    b[3] = 0x02;
    b[4] = 0x30;
    try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    b[4] = 0x29; // 2026 is not a leap year
    try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    b[2] = 0x24; // 2024 is
    _ = try DateTime.decode(&b);
    b[2] = 0x00; // 2000 is (divisible by 400)
    _ = try DateTime.decode(&b);
    b[2] = 0x99; // 1999 is not
    try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    b[3] = 0x04;
    b[4] = 0x31;
    b[2] = 0x26;
    try testing.expectError(error.BadDateTime, DateTime.decode(&b));
    // Encode refuses what decode refuses.
    var out: [10]u8 = undefined;
    try testing.expectError(error.BadDateTime, (DateTime{ .year = 1989, .month = 1, .day = 1 }).encode(&out));
    try testing.expectError(error.BadDateTime, (DateTime{ .year = 2090, .month = 1, .day = 1 }).encode(&out));
    try testing.expectError(error.BadDateTime, (DateTime{ .year = 2026, .month = 1, .day = 1, .millisecond = 1000 }).encode(&out));
    try testing.expectError(error.BadDateTime, (DateTime{ .year = 2026, .month = 1, .day = 1, .weekday = 8 }).encode(&out));
}

test "weekdayOf: 1 = Sunday" {
    try testing.expectEqual(@as(u8, 5), DateTime.weekdayOf(2026, 11, 19)); // Thursday
    try testing.expectEqual(@as(u8, 7), DateTime.weekdayOf(2000, 1, 1)); // Saturday
    try testing.expectEqual(@as(u8, 1), DateTime.weekdayOf(2024, 3, 3)); // Sunday, after a leap day
    try testing.expectEqual(@as(u8, 5), DateTime.weekdayOf(2024, 2, 29)); // Thursday
}

test "cpu status is read from the 0x0424 record" {
    // The two records the same CPU returned while running and while stopped.
    const running = [_]u8{
        0x51, 0x44, 0xFF, 0x08, 0,    0,    0,    0,    0, 0, 0, 0,
        0x26, 0x07, 0x23, 0x06, 0x50, 0x40, 0x00, 0x04,
    };
    var stopped = running;
    stopped[3] = 0x04;

    var wire: [64]u8 = undefined;
    const h: SzlHeader = .{ .id = 0x0424, .index = 0, .record_length = 20, .record_count = 1 };
    const a = try SzlResponse.decode(try SzlResponse.encode(h, &running, &wire));
    try testing.expectEqual(CpuStatus.run, cpuStatusFrom(a).?);
    var wire2: [64]u8 = undefined;
    const b = try SzlResponse.decode(try SzlResponse.encode(h, &stopped, &wire2));
    try testing.expectEqual(CpuStatus.stop, cpuStatusFrom(b).?);

    // A record too short to hold the status octet.
    var wire3: [64]u8 = undefined;
    const short = try SzlResponse.encode(
        .{ .id = 0x0424, .index = 0, .record_length = 2, .record_count = 1 },
        &[_]u8{ 0, 0 },
        &wire3,
    );
    try testing.expect(cpuStatusFrom(try SzlResponse.decode(short)) == null);
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it -- 33 across 12
/// modules in three shapes -- each with its own note about the same trap (the
/// array has to be container-level or the returned slice dangles with the RIGHT
/// length and garbage behind it). It lives in `testkit.fuzz` now, with tests
/// that drive the real `std.testing.Smith` over what it produces.
const fuzzSeed = @import("testkit").fuzz.seedHex;
const fz = @import("fuzz_test.zig");

/// The three decoders this harness calls read three different framings out of
/// the same octets, so the corpus carries all three: userdata parameter heads,
/// data blocks, and an SZL response with its record table.
const userdata_seeds = [_][]const u8{
    fuzzSeed("0001120411440100"), // a Read SZL request parameter
    fuzzSeed("0001120812840100"), // a response parameter, 8 octets
    fuzzSeed("000112"), // shorter than a parameter
    fuzzSeed("0002120411440100"), // the head is not 00 01 12
    fuzzSeed("0001120812840100"), // a declared parameter length that does not fit
    fuzzSeed("01320004"), // a data block header
    fuzzSeed("ff09000400110000"), // a data block with a payload
    fuzzSeed("ff09004000"), // declares 64 octets, delivers 1
    fuzzSeed("ff09"), // truncated inside the data block header
    fuzzSeed("ff090008001100010004000000010002"), // an SZL response with one record
    fuzzSeed("ff09000c00110002000400000001000200030004"), // two records
    fuzzSeed("ff0900080011000400040000"), // a record count past the payload
};

test "fuzz: userdata decoders never panic" {
    try std.testing.fuzz({}, fuzzUserdataSmith, .{ .corpus = &userdata_seeds });
}

const fuzzUserdataMark = fz.Marker(enum { ran, nonempty });

fn fuzzUserdataSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzUserdata(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzUserdata(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    // `Smith.bytes` consumes the whole remaining seed, and the ranged draw then
    // finds fewer than eight octets left and returns the range MINIMUM — so the
    // length was 0 for every seed and this harness only ever saw the empty
    // input. Measured on 2026-09-06 over the corpus above: **0 of 12
    // non-empty and 0 accepted by any of the three decoders before, 12 of 12
    // non-empty and 5 accepted after.**
    const len: usize = fz.drawInput(S, src, &buf, &userdata_seeds);
    fuzzUserdataMark.mark(.ran);
    if (len != 0) fuzzUserdataMark.mark(.nonempty);
    _ = Param.decode(buf[0..len]) catch {};
    if (DataBlock.decode(buf[0..len])) |db| {
        try testing.expect(db.payload.len + 4 <= len);
    } else |_| {}
    if (SzlResponse.decode(buf[0..len])) |r| {
        var i: usize = 0;
        while (i < 300) : (i += 1) {
            const rec = r.record(i) orelse break;
            try testing.expect(rec.len == r.header.record_length);
        }
    } else |_| {}
}

test "fuzz driver: S7COMM_FUZZ (fuzzUserdata)" {
    try fz.fuzz_driver.run(fuzzUserdata, .{ .prefix = "S7COMM_FUZZ", .name = "s7comm-userdata-userdata" });
}

test "fuzz harness: fuzzUserdata, 400 seeds, reaches every outcome" {
    try fuzzUserdataMark.reach(fuzzUserdata, "s7comm-userdata-userdata", 400);
}
