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
};

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
        out[5] = (@as(u8, @intFromEnum(self.message_type)) << 4) |
            @as(u8, @intFromEnum(self.function_group));
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
        out[5] = (@as(u8, @intFromEnum(self.message_type)) << 4) |
            @as(u8, @intFromEnum(self.function_group));
        out[6] = self.subfunction;
        out[7] = self.sequence;
        out[8] = self.data_unit_ref;
        out[9] = @intFromEnum(self.last_data_unit);
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
            .message_type = @enumFromInt(@as(u4, @intCast(bytes[5] >> 4))),
            .function_group = @enumFromInt(@as(u4, @intCast(bytes[5] & 0x0F))),
            .subfunction = bytes[6],
            .sequence = bytes[7],
        };
        if (follows >= 8) {
            if (bytes.len < response_len) return error.ShortParameters;
            p.data_unit_ref = bytes[8];
            p.last_data_unit = @enumFromInt(bytes[9]);
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
        const rc: items.ReturnCode = @enumFromInt(bytes[0]);
        const ts: items.DataTransportSize = @enumFromInt(bytes[1]);
        const raw: u16 = (@as(u16, bytes[2]) << 8) | bytes[3];
        const n: usize = if (ts.lengthInBits()) raw / 8 else raw;
        if (4 + n > bytes.len) return error.ShortData;
        return .{ .return_code = rc, .transport_size = ts, .payload = bytes[4..][0..n] };
    }

    pub fn encode(rc: items.ReturnCode, ts: items.DataTransportSize, payload: []const u8, out: []u8) Error![]u8 {
        if (out.len < 4 + payload.len) return error.BufferTooSmall;
        const raw: u16 = if (ts.lengthInBits())
            @intCast(payload.len * 8)
        else
            @intCast(payload.len);
        out[0] = @intFromEnum(rc);
        out[1] = @intFromEnum(ts);
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
    return @enumFromInt(rec[cpu_status_offset]);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "request sub-header round trip" {
    var buf: [16]u8 = undefined;
    const p: Param = .{
        .message_type = .request,
        .function_group = .cpu_functions,
        .subfunction = @intFromEnum(CpuSubfunction.read_szl),
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
    // Byte for byte what a real CPU's Read-SZL response carried.
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

test "fuzz: userdata decoders never panic" {
    try std.testing.fuzz({}, fuzzUserdata, .{});
}

fn fuzzUserdata(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
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
