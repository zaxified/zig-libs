// SPDX-License-Identifier: MIT

//! dnp3.application — the Application Layer (IEEE 1815-2012 §4/§5): the
//! application-control octet (FIR/FIN/CON/UNS + a 4-bit sequence number),
//! the function-code byte, and the two-octet Internal Indications (IIN)
//! bitfield carried in every response fragment.
//!
//! A request fragment on the wire: `[control][function][object headers...]`.
//! A response fragment: `[control][function][iin1][iin2][object headers...]`.
//! Object-header framing (group/variation/qualifier/range) and the core
//! object library live in `objects.zig`; this module only frames the
//! application header and IIN around them.

const std = @import("std");
const objects = @import("objects.zig");

// ── application control octet ───────────────────────────────────────────────

pub const AppControl = struct {
    /// FIR (0x80): this is the first application-layer segment carried by
    /// the transport function for this fragment sequence.
    fir: bool,
    /// FIN (0x40): this is the last segment.
    fin: bool,
    /// CON (0x20): the sender requests an application-layer CONFIRM.
    con: bool = false,
    /// UNS (0x10): this fragment is an unsolicited response (or its confirm).
    uns: bool = false,
    /// Bits 0x0F: application-layer sequence number, incremented per new
    /// request/response pair (distinct from the transport function's 6-bit
    /// segment sequence in `transport.zig`).
    seq: u4,

    pub fn toByte(self: AppControl) u8 {
        var b: u8 = @as(u8, self.seq);
        if (self.fir) b |= 0x80;
        if (self.fin) b |= 0x40;
        if (self.con) b |= 0x20;
        if (self.uns) b |= 0x10;
        return b;
    }

    pub fn fromByte(b: u8) AppControl {
        return .{
            .fir = (b & 0x80) != 0,
            .fin = (b & 0x40) != 0,
            .con = (b & 0x20) != 0,
            .uns = (b & 0x10) != 0,
            .seq = @truncate(b & 0x0F),
        };
    }
};

/// Application-layer function codes (§4.2, Table 4-1). Non-exhaustive
/// (`_,`): the module decodes whatever byte is on the wire even if it isn't
/// one of the named codes below.
pub const FunctionCode = enum(u8) {
    confirm = 0x00,
    read = 0x01,
    write = 0x02,
    select = 0x03,
    operate = 0x04,
    direct_operate = 0x05,
    direct_operate_no_ack = 0x06,
    immediate_freeze = 0x07,
    immediate_freeze_no_ack = 0x08,
    freeze_clear = 0x09,
    freeze_clear_no_ack = 0x0A,
    freeze_at_time = 0x0B,
    freeze_at_time_no_ack = 0x0C,
    cold_restart = 0x0D,
    warm_restart = 0x0E,
    initialize_data = 0x0F,
    initialize_application = 0x10,
    start_application = 0x11,
    stop_application = 0x12,
    save_configuration = 0x13,
    enable_unsolicited = 0x14,
    disable_unsolicited = 0x15,
    assign_class = 0x16,
    delay_measure = 0x17,
    record_current_time = 0x18,
    open_file = 0x19,
    close_file = 0x1A,
    delete_file = 0x1B,
    get_file_info = 0x1C,
    authenticate_file = 0x1D,
    abort_file = 0x1E,
    activate_config = 0x1F,
    auth_request = 0x20,
    auth_request_no_ack = 0x21,
    response = 0x81,
    unsolicited_response = 0x82,
    auth_response = 0x83,
    _,
};

// ── Internal Indications (IIN) ───────────────────────────────────────────────

/// The 2-octet Internal Indications bitfield (§4.3.3, Table 4-2/4-3),
/// present only in responses. IIN1 is transmitted before IIN2.
pub const Iin = struct {
    // IIN1
    broadcast: bool = false,
    class_1_events: bool = false,
    class_2_events: bool = false,
    class_3_events: bool = false,
    need_time: bool = false,
    local_control: bool = false,
    device_trouble: bool = false,
    device_restart: bool = false,
    // IIN2
    func_not_supported: bool = false,
    object_unknown: bool = false,
    parameter_error: bool = false,
    event_buffer_overflow: bool = false,
    already_executing: bool = false,
    config_corrupt: bool = false,
    reserved_2: bool = false,
    reserved_1: bool = false,

    pub fn toBytes(self: Iin) [2]u8 {
        var iin1: u8 = 0;
        if (self.broadcast) iin1 |= 0x01;
        if (self.class_1_events) iin1 |= 0x02;
        if (self.class_2_events) iin1 |= 0x04;
        if (self.class_3_events) iin1 |= 0x08;
        if (self.need_time) iin1 |= 0x10;
        if (self.local_control) iin1 |= 0x20;
        if (self.device_trouble) iin1 |= 0x40;
        if (self.device_restart) iin1 |= 0x80;

        var iin2: u8 = 0;
        if (self.func_not_supported) iin2 |= 0x01;
        if (self.object_unknown) iin2 |= 0x02;
        if (self.parameter_error) iin2 |= 0x04;
        if (self.event_buffer_overflow) iin2 |= 0x08;
        if (self.already_executing) iin2 |= 0x10;
        if (self.config_corrupt) iin2 |= 0x20;
        if (self.reserved_2) iin2 |= 0x40;
        if (self.reserved_1) iin2 |= 0x80;

        return .{ iin1, iin2 };
    }

    pub fn fromBytes(bytes: [2]u8) Iin {
        const iin1 = bytes[0];
        const iin2 = bytes[1];
        return .{
            .broadcast = (iin1 & 0x01) != 0,
            .class_1_events = (iin1 & 0x02) != 0,
            .class_2_events = (iin1 & 0x04) != 0,
            .class_3_events = (iin1 & 0x08) != 0,
            .need_time = (iin1 & 0x10) != 0,
            .local_control = (iin1 & 0x20) != 0,
            .device_trouble = (iin1 & 0x40) != 0,
            .device_restart = (iin1 & 0x80) != 0,
            .func_not_supported = (iin2 & 0x01) != 0,
            .object_unknown = (iin2 & 0x02) != 0,
            .parameter_error = (iin2 & 0x04) != 0,
            .event_buffer_overflow = (iin2 & 0x08) != 0,
            .already_executing = (iin2 & 0x10) != 0,
            .config_corrupt = (iin2 & 0x20) != 0,
            .reserved_2 = (iin2 & 0x40) != 0,
            .reserved_1 = (iin2 & 0x80) != 0,
        };
    }
};

// ── header encode/decode ─────────────────────────────────────────────────────

pub const EncodeError = error{BufferTooSmall};
pub const DecodeError = error{ShortFragment};

pub const RequestHeader = struct {
    control: AppControl,
    function: FunctionCode,
};

pub const ResponseHeader = struct {
    control: AppControl,
    function: FunctionCode,
    iin: Iin,
};

pub const request_header_len = 2;
pub const response_header_len = 4;

pub fn encodeRequestHeader(header: RequestHeader, out: []u8) EncodeError![]u8 {
    if (out.len < request_header_len) return error.BufferTooSmall;
    out[0] = header.control.toByte();
    out[1] = @intFromEnum(header.function);
    return out[0..request_header_len];
}

pub fn decodeRequestHeader(bytes: []const u8) DecodeError!struct { header: RequestHeader, rest: []const u8 } {
    if (bytes.len < request_header_len) return error.ShortFragment;
    return .{
        .header = .{ .control = AppControl.fromByte(bytes[0]), .function = @enumFromInt(bytes[1]) },
        .rest = bytes[request_header_len..],
    };
}

pub fn encodeResponseHeader(header: ResponseHeader, out: []u8) EncodeError![]u8 {
    if (out.len < response_header_len) return error.BufferTooSmall;
    out[0] = header.control.toByte();
    out[1] = @intFromEnum(header.function);
    const iin_bytes = header.iin.toBytes();
    out[2] = iin_bytes[0];
    out[3] = iin_bytes[1];
    return out[0..response_header_len];
}

pub fn decodeResponseHeader(bytes: []const u8) DecodeError!struct { header: ResponseHeader, rest: []const u8 } {
    if (bytes.len < response_header_len) return error.ShortFragment;
    return .{
        .header = .{
            .control = AppControl.fromByte(bytes[0]),
            .function = @enumFromInt(bytes[1]),
            .iin = Iin.fromBytes(.{ bytes[2], bytes[3] }),
        },
        .rest = bytes[response_header_len..],
    };
}

// ── convenience: build a single-object-header request ───────────────────────

/// Builds a full request fragment consisting of just an application header
/// plus one object header (no object data) -- the shape of a READ request,
/// or a "read class N" request via `objects.g60.readClassHeader`.
pub fn buildRequest(
    seq: u4,
    function: FunctionCode,
    object_header: objects.ObjectHeader,
    out: []u8,
) (EncodeError || objects.EncodeError)![]u8 {
    const control = AppControl{ .fir = true, .fin = true, .seq = seq };
    const hdr_bytes = try encodeRequestHeader(.{ .control = control, .function = function }, out);
    const obj_bytes = try objects.encodeObjectHeader(object_header, out[request_header_len..]);
    return out[0 .. hdr_bytes.len + obj_bytes.len];
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "app control octet round-trip" {
    const c = AppControl{ .fir = true, .fin = true, .con = true, .seq = 5 };
    const b = c.toByte();
    try testing.expectEqual(@as(u8, 0xE5), b);
    const back = AppControl.fromByte(b);
    try testing.expect(back.fir and back.fin and back.con and !back.uns);
    try testing.expectEqual(@as(u4, 5), back.seq);
}

test "IIN round-trip: all bits" {
    const iin = Iin{
        .broadcast = true,
        .need_time = true,
        .device_restart = true,
        .object_unknown = true,
        .config_corrupt = true,
    };
    const bytes = iin.toBytes();
    const back = Iin.fromBytes(bytes);
    try testing.expect(back.broadcast);
    try testing.expect(back.need_time);
    try testing.expect(back.device_restart);
    try testing.expect(back.object_unknown);
    try testing.expect(back.config_corrupt);
    try testing.expect(!back.class_1_events);
}

test "request header round-trip" {
    var out: [4]u8 = undefined;
    const bytes = try encodeRequestHeader(.{ .control = .{ .fir = true, .fin = true, .seq = 1 }, .function = .read }, &out);
    try testing.expectEqualSlices(u8, &.{ 0xC1, 0x01 }, bytes);
    const decoded = try decodeRequestHeader(bytes);
    try testing.expectEqual(FunctionCode.read, decoded.header.function);
    try testing.expectEqual(@as(usize, 0), decoded.rest.len);
}

test "response header round-trip with IIN" {
    var out: [8]u8 = undefined;
    const header = ResponseHeader{
        .control = .{ .fir = true, .fin = true, .seq = 2 },
        .function = .response,
        .iin = .{ .device_restart = true },
    };
    const bytes = try encodeResponseHeader(header, &out);
    try testing.expectEqual(@as(usize, 4), bytes.len);
    const decoded = try decodeResponseHeader(bytes);
    try testing.expectEqual(FunctionCode.response, decoded.header.function);
    try testing.expect(decoded.header.iin.device_restart);
}

test "buildRequest: READ class 0" {
    var out: [16]u8 = undefined;
    const bytes = try buildRequest(0, .read, objects.g60.readClassHeader(.class0), &out);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0x01, 60, 1, 0x06 }, bytes);
}

test "decode: short fragment is a typed error" {
    try testing.expectError(error.ShortFragment, decodeRequestHeader(&.{0x01}));
    try testing.expectError(error.ShortFragment, decodeResponseHeader(&.{ 0x01, 0x81, 0x00 }));
}

test "non-exhaustive FunctionCode decodes unknown wire bytes without erroring" {
    const decoded = try decodeRequestHeader(&.{ 0xC0, 0x77 });
    // 0x77 is not a named function code; the non-exhaustive enum still holds it.
    try testing.expectEqual(@as(u8, 0x77), @intFromEnum(decoded.header.function));
}
