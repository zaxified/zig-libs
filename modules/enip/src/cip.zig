// SPDX-License-Identifier: MIT

//! The **CIP Message Router** message (CIP Volume 1, chapter 2): a service
//! code, an EPATH naming what the service acts on, and the service's data —
//! plus the reply shape, which is *not* symmetric with the request.
//!
//! Three things to get right:
//!
//! * **A reply sets bit 7 of the service code** (`0x4C` → `0xCC`). It is the
//!   only way to tell a request from a reply once both are sitting in the same
//!   CPF data item, and a decoder that ignores it reads a reply's general
//!   status as a path size.
//! * **`additional_status_size` is counted in 16-bit words**, and the array is
//!   attacker-controlled. A count of 255 claims 510 octets that may not exist,
//!   which is why it is bounds-checked against the buffer here and not trusted.
//! * **Service codes are only unique within an object class.** `0x4E` is
//!   `Forward_Close` on the Connection Manager (class 6) and `Read Modify
//!   Write Tag` on a Logix symbol object; `0x52` is `Unconnected_Send` on
//!   class 6 and `Read Tag Fragmented` everywhere else. Nothing here maps a
//!   bare service code to a name without knowing the path, and `Service` is
//!   deliberately a *set of constants per context* rather than one enum.

const std = @import("std");
const epath = @import("epath.zig");

pub const DecodeError = error{
    /// Not enough octets for the fixed part of a request or reply.
    Truncated,
    /// The request path size runs past the end of the message.
    PathOverruns,
    /// The additional-status array runs past the end of the message.
    AdditionalStatusOverruns,
    /// A request was expected but the reply bit was set (or the reverse).
    WrongDirection,
    /// A Multiple Service Packet whose offset table is inconsistent.
    BadOffsetTable,
    /// A reply whose reserved octet is not zero.
    BadReserved,
};

pub const EncodeError = error{
    BufferTooSmall,
    /// A path longer than 255 words, or an odd-length path.
    BadPath,
    /// More additional-status words than the count octet can hold.
    TooManyStatusWords,
    /// More embedded messages than a Multiple Service Packet can name.
    TooManyMessages,
};

/// The reply bit. `service | reply_bit` is what a target answers with.
pub const reply_bit: u8 = 0x80;

/// The CIP **common services** (Vol 1 Appendix A), which every object
/// implements the relevant subset of. These codes mean the same thing on
/// every class.
pub const Service = enum(u8) {
    get_attributes_all = 0x01,
    set_attributes_all = 0x02,
    get_attribute_list = 0x03,
    set_attribute_list = 0x04,
    reset = 0x05,
    start = 0x06,
    stop = 0x07,
    create = 0x08,
    delete = 0x09,
    multiple_service_packet = 0x0A,
    apply_attributes = 0x0D,
    get_attribute_single = 0x0E,
    set_attribute_single = 0x10,
    find_next_object_instance = 0x11,
    restore = 0x15,
    save = 0x16,
    no_operation = 0x17,
    get_member = 0x18,
    set_member = 0x19,
    insert_member = 0x1A,
    remove_member = 0x1B,
    group_sync = 0x1C,
    _,
};

/// Vendor-specific services on a **Logix symbol/tag object**. These codes
/// collide with the Connection Manager's; which meaning applies is decided by
/// the class in the request path, never by the code alone.
pub const LogixService = struct {
    pub const read_tag: u8 = 0x4C;
    pub const write_tag: u8 = 0x4D;
    pub const read_modify_write_tag: u8 = 0x4E;
    pub const read_tag_fragmented: u8 = 0x52;
    pub const write_tag_fragmented: u8 = 0x53;
    pub const get_instance_attribute_list: u8 = 0x55;
    pub const execute_pccc: u8 = 0x4B;
};

/// CIP object class codes worth naming (Vol 1 Table A-1).
pub const ClassCode = enum(u16) {
    identity = 0x01,
    message_router = 0x02,
    device_net = 0x03,
    assembly = 0x04,
    connection = 0x05,
    connection_manager = 0x06,
    register = 0x07,
    discrete_input_point = 0x08,
    discrete_output_point = 0x09,
    analog_input_point = 0x0A,
    analog_output_point = 0x0B,
    parameter = 0x0F,
    parameter_group = 0x10,
    group = 0x12,
    discrete_input_group = 0x1D,
    discrete_output_group = 0x1E,
    discrete_group = 0x1F,
    analog_input_group = 0x20,
    analog_output_group = 0x21,
    analog_group = 0x22,
    position_sensor = 0x23,
    position_controller_supervisor = 0x24,
    position_controller = 0x25,
    block_sequencer = 0x26,
    command_block = 0x27,
    motor_data = 0x28,
    control_supervisor = 0x29,
    ac_dc_drive = 0x2A,
    acknowledge_handler = 0x2B,
    overload = 0x2C,
    softstart = 0x2D,
    selection = 0x2E,
    s_device_supervisor = 0x30,
    s_analog_sensor = 0x31,
    s_analog_actuator = 0x32,
    s_single_stage_controller = 0x33,
    s_gas_calibration = 0x34,
    trip_point = 0x35,
    file_object = 0x37,
    /// The Logix "symbol object" a tag read names when it is not symbolic.
    symbol = 0x6B,
    /// The Logix template object describing a UDT's layout.
    template = 0x6C,
    port = 0xF4,
    tcp_ip_interface = 0xF5,
    ethernet_link = 0xF6,
    _,
};

/// CIP **general status** codes (Vol 1 Appendix B, Table B-1.1).
///
/// `partial_transfer` (0x06) is not an error: it is how a fragmented read says
/// "there is more". Treating it as a failure breaks every large tag read.
pub const GeneralStatus = enum(u8) {
    success = 0x00,
    connection_failure = 0x01,
    resource_unavailable = 0x02,
    invalid_parameter_value = 0x03,
    path_segment_error = 0x04,
    path_destination_unknown = 0x05,
    partial_transfer = 0x06,
    connection_lost = 0x07,
    service_not_supported = 0x08,
    invalid_attribute_value = 0x09,
    attribute_list_error = 0x0A,
    already_in_requested_mode = 0x0B,
    object_state_conflict = 0x0C,
    object_already_exists = 0x0D,
    attribute_not_settable = 0x0E,
    privilege_violation = 0x0F,
    device_state_conflict = 0x10,
    reply_data_too_large = 0x11,
    fragmentation_of_primitive_value = 0x12,
    not_enough_data = 0x13,
    attribute_not_supported = 0x14,
    too_much_data = 0x15,
    object_does_not_exist = 0x16,
    service_fragmentation_not_in_progress = 0x17,
    no_stored_attribute_data = 0x18,
    store_operation_failure = 0x19,
    routing_failure_request_too_large = 0x1A,
    routing_failure_response_too_large = 0x1B,
    missing_attribute_list_entry = 0x1C,
    invalid_attribute_value_list = 0x1D,
    embedded_service_error = 0x1E,
    vendor_specific_error = 0x1F,
    invalid_parameter = 0x20,
    write_once_already_written = 0x21,
    invalid_reply_received = 0x22,
    buffer_overflow = 0x23,
    message_format_error = 0x24,
    key_failure_in_path = 0x25,
    path_size_invalid = 0x26,
    unexpected_attribute_in_list = 0x27,
    invalid_member_id = 0x28,
    member_not_settable = 0x29,
    group_2_server_failure = 0x2A,
    unknown_modbus_error = 0x2B,
    attribute_not_gettable = 0x2C,
    _,

    pub fn isSuccess(s: GeneralStatus) bool {
        return s == .success;
    }

    /// True when the reply carried usable data even though the status is not
    /// `success` — the fragmented-read continuation case.
    pub fn hasData(s: GeneralStatus) bool {
        return s == .success or s == .partial_transfer;
    }
};

// ── requests ────────────────────────────────────────────────────────────────

/// A Message Router request: `service`, a word-counted EPATH, then data.
pub const Request = struct {
    service: u8,
    /// The EPATH, as octets — walk it with `epath.Iterator`.
    path: []const u8,
    data: []const u8,

    pub fn encodedLen(self: Request) usize {
        return 2 + self.path.len + self.data.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!Request {
        if (bytes.len < 2) return error.Truncated;
        const service = bytes[0];
        if (service & reply_bit != 0) return error.WrongDirection;
        const path_words: usize = bytes[1];
        const path_len = path_words * 2;
        if (2 + path_len > bytes.len) return error.PathOverruns;
        return .{
            .service = service,
            .path = bytes[2 .. 2 + path_len],
            .data = bytes[2 + path_len ..],
        };
    }

    pub fn encode(self: Request, out: []u8) EncodeError![]u8 {
        if (self.service & reply_bit != 0) return error.BadPath;
        if (self.path.len % 2 != 0 or self.path.len / 2 > 255) return error.BadPath;
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        out[0] = self.service;
        out[1] = @intCast(self.path.len / 2);
        @memcpy(out[2..][0..self.path.len], self.path);
        @memcpy(out[2 + self.path.len ..][0..self.data.len], self.data);
        return out[0..total];
    }

    /// The object class this request names, if the path has a class segment.
    /// This is what decides whether `0x52` means `Unconnected_Send` or
    /// `Read Tag Fragmented`.
    pub fn classCode(self: Request) epath.DecodeError!?u32 {
        return epath.findLogical(self.path, .class);
    }
};

// ── replies ─────────────────────────────────────────────────────────────────

/// A Message Router reply. The service code carries the reply bit; the
/// `service` field here holds it **stripped**, with `raw_service` keeping what
/// was on the wire so a re-encode is exact.
pub const Reply = struct {
    service: u8,
    reserved: u8 = 0,
    general_status: GeneralStatus,
    /// Additional status words, in wire order. Attacker-controlled length.
    additional_status: []const u8,
    data: []const u8,

    pub fn encodedLen(self: Reply) usize {
        return 4 + self.additional_status.len + self.data.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!Reply {
        if (bytes.len < 4) return error.Truncated;
        if (bytes[0] & reply_bit == 0) return error.WrongDirection;
        // Vol 1 §2-4.2: the octet after the service is reserved and zero.
        if (bytes[1] != 0) return error.BadReserved;
        const extra_words: usize = bytes[3];
        const extra_len = extra_words * 2;
        if (4 + extra_len > bytes.len) return error.AdditionalStatusOverruns;
        return .{
            .service = bytes[0] & ~reply_bit,
            .reserved = bytes[1],
            .general_status = @enumFromInt(bytes[2]),
            .additional_status = bytes[4 .. 4 + extra_len],
            .data = bytes[4 + extra_len ..],
        };
    }

    pub fn encode(self: Reply, out: []u8) EncodeError![]u8 {
        if (self.additional_status.len % 2 != 0) return error.TooManyStatusWords;
        if (self.additional_status.len / 2 > 255) return error.TooManyStatusWords;
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        out[0] = self.service | reply_bit;
        out[1] = self.reserved;
        out[2] = @intFromEnum(self.general_status);
        out[3] = @intCast(self.additional_status.len / 2);
        @memcpy(out[4..][0..self.additional_status.len], self.additional_status);
        @memcpy(out[4 + self.additional_status.len ..][0..self.data.len], self.data);
        return out[0..total];
    }

    /// The first additional-status word, which is where the Connection
    /// Manager's extended error code lives.
    pub fn extendedStatus(self: Reply) ?u16 {
        if (self.additional_status.len < 2) return null;
        return std.mem.readInt(u16, self.additional_status[0..2], .little);
    }
};

// ── Multiple Service Packet (0x0A) ─────────────────────────────────────────

/// The `Multiple_Service_Packet` payload: a count, an offset table, then the
/// embedded messages.
///
/// **The offsets are measured from the start of the count field**, not from
/// the start of the first embedded message and not from the start of the
/// Message Router message. Getting that wrong shifts every embedded request by
/// two octets plus the table's width, which decodes as garbage rather than
/// failing loudly — so both directions are asserted against captured traffic.
pub const MultipleService = struct {
    /// The whole payload, kept so offsets can be resolved against it.
    payload: []const u8,
    count: usize,

    pub fn decode(payload: []const u8) DecodeError!MultipleService {
        if (payload.len < 2) return error.Truncated;
        const count: usize = std.mem.readInt(u16, payload[0..2], .little);
        // Table itself must fit.
        if (2 + count * 2 > payload.len) return error.BadOffsetTable;
        return .{ .payload = payload, .count = count };
    }

    /// The `i`-th embedded message. Every offset is validated against the
    /// payload, and offsets must be non-decreasing — an out-of-order table
    /// would otherwise produce overlapping or negative-length slices.
    pub fn at(self: MultipleService, i: usize) DecodeError![]const u8 {
        if (i >= self.count) return error.BadOffsetTable;
        const start: usize = std.mem.readInt(u16, self.payload[2 + i * 2 ..][0..2], .little);
        if (start < 2 + self.count * 2 or start > self.payload.len) return error.BadOffsetTable;
        const end: usize = if (i + 1 == self.count)
            self.payload.len
        else blk: {
            const next: usize = std.mem.readInt(u16, self.payload[2 + (i + 1) * 2 ..][0..2], .little);
            if (next > self.payload.len or next < start) return error.BadOffsetTable;
            break :blk next;
        };
        return self.payload[start..end];
    }

    /// The number of octets the payload needs for `n` messages of the given
    /// sizes.
    pub fn encodedLen(sizes: []const usize) usize {
        var total: usize = 2 + sizes.len * 2;
        for (sizes) |s| total += s;
        return total;
    }

    /// Builds the payload from already-encoded embedded messages.
    pub fn encode(messages: []const []const u8, out: []u8) EncodeError![]u8 {
        if (messages.len > 0xFFFF) return error.TooManyMessages;
        var total: usize = 2 + messages.len * 2;
        for (messages) |m| total += m.len;
        if (total > 0xFFFF) return error.BufferTooSmall;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], @intCast(messages.len), .little);
        var off: usize = 2 + messages.len * 2;
        for (messages, 0..) |m, i| {
            std.mem.writeInt(u16, out[2 + i * 2 ..][0..2], @intCast(off), .little);
            @memcpy(out[off..][0..m.len], m);
            off += m.len;
        }
        return out[0..off];
    }
};

// ── convenience builders for the common services ───────────────────────────

/// `Get_Attribute_Single` on `class/instance/attribute`.
pub fn getAttributeSingle(class_id: u32, instance: u32, attribute: u32, out: []u8) EncodeError![]u8 {
    var path_buf: [16]u8 = undefined;
    const path = epath.logicalPath(class_id, instance, attribute, &path_buf) catch return error.BadPath;
    return (Request{
        .service = @intFromEnum(Service.get_attribute_single),
        .path = path,
        .data = &.{},
    }).encode(out);
}

/// `Get_Attributes_All` on `class/instance`.
pub fn getAttributesAll(class_id: u32, instance: u32, out: []u8) EncodeError![]u8 {
    var path_buf: [16]u8 = undefined;
    const path = epath.logicalPath(class_id, instance, null, &path_buf) catch return error.BadPath;
    return (Request{
        .service = @intFromEnum(Service.get_attributes_all),
        .path = path,
        .data = &.{},
    }).encode(out);
}

/// `Set_Attribute_Single` on `class/instance/attribute`, carrying `value`.
pub fn setAttributeSingle(
    class_id: u32,
    instance: u32,
    attribute: u32,
    value: []const u8,
    out: []u8,
) EncodeError![]u8 {
    var path_buf: [16]u8 = undefined;
    const path = epath.logicalPath(class_id, instance, attribute, &path_buf) catch return error.BadPath;
    return (Request{
        .service = @intFromEnum(Service.set_attribute_single),
        .path = path,
        .data = value,
    }).encode(out);
}

/// `Get_Attribute_List`: a count followed by the attribute ids to fetch.
/// The reply is a count followed by `{id, status, value}` triples whose value
/// widths are attribute-specific, so it is handed back raw.
pub fn getAttributeList(
    class_id: u32,
    instance: u32,
    attributes: []const u16,
    out: []u8,
) EncodeError![]u8 {
    var path_buf: [16]u8 = undefined;
    const path = epath.logicalPath(class_id, instance, null, &path_buf) catch return error.BadPath;
    var data_buf: [2 + 2 * 64]u8 = undefined;
    if (attributes.len > 64) return error.BufferTooSmall;
    std.mem.writeInt(u16, data_buf[0..2], @intCast(attributes.len), .little);
    for (attributes, 0..) |a, i| std.mem.writeInt(u16, data_buf[2 + i * 2 ..][0..2], a, .little);
    return (Request{
        .service = @intFromEnum(Service.get_attribute_list),
        .path = path,
        .data = data_buf[0 .. 2 + attributes.len * 2],
    }).encode(out);
}

/// One entry of a `Get_Attribute_List` reply.
pub const AttributeStatus = struct {
    id: u16,
    status: GeneralStatus,
};

/// Walks a `Get_Attribute_List` / `Set_Attribute_List` reply's `{id, status}`
/// header pairs. Value octets are attribute-specific and are not walked here.
pub const AttributeListIterator = struct {
    data: []const u8,
    off: usize = 2,
    remaining: usize,

    pub fn init(reply_data: []const u8) DecodeError!AttributeListIterator {
        if (reply_data.len < 2) return error.Truncated;
        return .{
            .data = reply_data,
            .remaining = std.mem.readInt(u16, reply_data[0..2], .little),
        };
    }

    /// The next `{id, status}` pair, or null. `valueLen` octets of value are
    /// consumed after it — the caller knows the width, this decoder does not.
    pub fn next(self: *AttributeListIterator, value_len: usize) DecodeError!?AttributeStatus {
        if (self.remaining == 0) return null;
        if (self.off + 4 + value_len > self.data.len) return error.Truncated;
        const id = std.mem.readInt(u16, self.data[self.off..][0..2], .little);
        const st: GeneralStatus = @enumFromInt(self.data[self.off + 2]);
        self.off += 4 + value_len;
        self.remaining -= 1;
        return .{ .id = id, .status = st };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "a request round trips and its path size is words" {
    var buf: [64]u8 = undefined;
    const wire = try getAttributeSingle(0x01, 1, 7, &buf);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07 },
        wire,
    );
    const req = try Request.decode(wire);
    try testing.expectEqual(@as(u8, 0x0E), req.service);
    try testing.expectEqual(@as(usize, 6), req.path.len);
    try testing.expectEqual(@as(usize, 0), req.data.len);
    try testing.expectEqual(@as(?u32, 1), try req.classCode());
}

test "a reply strips the reply bit but re-encodes it" {
    const wire = [_]u8{ 0x8E, 0x00, 0x00, 0x00, 0x01, 0x00 };
    const rep = try Reply.decode(&wire);
    try testing.expectEqual(@as(u8, 0x0E), rep.service);
    try testing.expect(rep.general_status.isSuccess());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, rep.data);
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try rep.encode(&out));
}

test "a request with the reply bit set is refused, and the reverse" {
    try testing.expectError(error.WrongDirection, Request.decode(&[_]u8{ 0xCC, 0x00 }));
    try testing.expectError(error.WrongDirection, Reply.decode(&[_]u8{ 0x4C, 0x00, 0x00, 0x00 }));
}

test "a path size that overruns the message is refused" {
    try testing.expectError(error.PathOverruns, Request.decode(&[_]u8{ 0x0E, 0x08, 0x20, 0x01 }));
}

test "an additional-status count that overruns is refused" {
    // Claims 255 words (510 octets) with none present.
    try testing.expectError(
        error.AdditionalStatusOverruns,
        Reply.decode(&[_]u8{ 0x8E, 0x00, 0x01, 0xFF }),
    );
    // Claims one word with one octet present.
    try testing.expectError(
        error.AdditionalStatusOverruns,
        Reply.decode(&[_]u8{ 0x8E, 0x00, 0x01, 0x01, 0x00 }),
    );
}

test "a reply carrying an extended status word exposes it" {
    const wire = [_]u8{ 0xD4, 0x00, 0x01, 0x01, 0x00, 0x03 };
    const rep = try Reply.decode(&wire);
    try testing.expectEqual(GeneralStatus.connection_failure, rep.general_status);
    try testing.expectEqual(@as(?u16, 0x0300), rep.extendedStatus());
    try testing.expectEqual(@as(usize, 0), rep.data.len);
}

test "a reply with a dirty reserved octet is refused" {
    try testing.expectError(error.BadReserved, Reply.decode(&[_]u8{ 0x8E, 0x01, 0x00, 0x00 }));
}

test "partial transfer is not an error, it is the fragmented-read continuation" {
    try testing.expect(!GeneralStatus.partial_transfer.isSuccess());
    try testing.expect(GeneralStatus.partial_transfer.hasData());
    try testing.expect(!GeneralStatus.path_destination_unknown.hasData());
}

test "multiple service packet offsets are measured from the count field" {
    const a = [_]u8{ 0x4C, 0x03, 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x00 };
    const b = [_]u8{ 0x4C, 0x02, 0x91, 0x03, 'A', 'B', 'C', 0x00 };
    var buf: [64]u8 = undefined;
    const payload = try MultipleService.encode(&[_][]const u8{ &a, &b }, &buf);
    // count = 2, then two offsets: 6 (2 + 2*2) and 6 + a.len.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x06, 0x00, 0x10, 0x00 }, payload[0..6]);
    const ms = try MultipleService.decode(payload);
    try testing.expectEqual(@as(usize, 2), ms.count);
    try testing.expectEqualSlices(u8, &a, try ms.at(0));
    try testing.expectEqualSlices(u8, &b, try ms.at(1));
    try testing.expectError(error.BadOffsetTable, ms.at(2));
}

test "a multiple-service offset table pointing outside the payload is refused" {
    // count 1, offset 200, payload 6 octets.
    const bad = [_]u8{ 0x01, 0x00, 0xC8, 0x00, 0xAA, 0xBB };
    const ms = try MultipleService.decode(&bad);
    try testing.expectError(error.BadOffsetTable, ms.at(0));
    // An offset that points into the table itself.
    const inside = [_]u8{ 0x01, 0x00, 0x01, 0x00, 0xAA, 0xBB };
    try testing.expectError(error.BadOffsetTable, (try MultipleService.decode(&inside)).at(0));
    // A table whose own width overruns the payload.
    try testing.expectError(error.BadOffsetTable, MultipleService.decode(&[_]u8{ 0xFF, 0x00, 0x01 }));
    // Descending offsets would make a negative-length slice.
    const descending = [_]u8{ 0x02, 0x00, 0x0A, 0x00, 0x06, 0x00, 1, 2, 3, 4, 5, 6 };
    try testing.expectError(error.BadOffsetTable, (try MultipleService.decode(&descending)).at(0));
}

test "service codes are only unique within a class" {
    // 0x52 with the Connection Manager in the path is Unconnected_Send…
    var buf: [32]u8 = undefined;
    var path_buf: [8]u8 = undefined;
    const cm = try epath.logicalPath(0x06, 1, null, &path_buf);
    const unconnected = try (Request{ .service = 0x52, .path = cm, .data = &.{} }).encode(&buf);
    try testing.expectEqual(@as(?u32, 0x06), try (try Request.decode(unconnected)).classCode());

    // …and 0x52 on a symbolic path is Read Tag Fragmented, with no class at all.
    var sym_buf: [16]u8 = undefined;
    var sb = epath.Builder.init(&sym_buf);
    try sb.symbol("SCADA");
    var buf2: [32]u8 = undefined;
    const frag = try (Request{ .service = 0x52, .path = sb.bytes(), .data = &.{} }).encode(&buf2);
    try testing.expectEqual(@as(?u32, null), try (try Request.decode(frag)).classCode());
}

test "get attribute list builds its count and ids" {
    var buf: [64]u8 = undefined;
    const wire = try getAttributeList(0x01, 1, &[_]u16{ 1, 7 }, &buf);
    const req = try Request.decode(wire);
    try testing.expectEqual(@as(u8, 0x03), req.service);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x01, 0x00, 0x07, 0x00 }, req.data);
}

test "attribute list reply iterates its id/status pairs" {
    // Two entries, each a u16 value.
    const data = [_]u8{ 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x12, 0x07, 0x00, 0x14, 0x00, 0x00, 0x00 };
    var it = try AttributeListIterator.init(&data);
    const first = (try it.next(2)).?;
    try testing.expectEqual(@as(u16, 1), first.id);
    try testing.expect(first.status.isSuccess());
    const second = (try it.next(2)).?;
    try testing.expectEqual(@as(u16, 7), second.id);
    try testing.expectEqual(GeneralStatus.attribute_not_supported, second.status);
    try testing.expectEqual(@as(?AttributeStatus, null), try it.next(2));
    // A count that outruns the data.
    var short = try AttributeListIterator.init(&[_]u8{ 0x05, 0x00, 0x01, 0x00, 0x00, 0x00 });
    _ = try short.next(0);
    try testing.expectError(error.Truncated, short.next(0));
}

test "encode refuses an odd path and an oversized additional status" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.BadPath, (Request{
        .service = 0x0E,
        .path = &[_]u8{ 0x20, 0x01, 0x24 },
        .data = &.{},
    }).encode(&out));
    try testing.expectError(error.TooManyStatusWords, (Reply{
        .service = 0x0E,
        .general_status = .success,
        .additional_status = &[_]u8{0x01},
        .data = &.{},
    }).encode(&out));
}

test "fuzz: request and reply decoders never panic and re-encode exactly" {
    try std.testing.fuzz({}, fuzzMessages, .{});
}

fn fuzzMessages(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var round: [512]u8 = undefined;
    if (Request.decode(buf[0..len])) |req| {
        try testing.expectEqualSlices(u8, buf[0..len], try req.encode(&round));
        _ = req.classCode() catch {};
    } else |_| {}
    if (Reply.decode(buf[0..len])) |rep| {
        try testing.expectEqualSlices(u8, buf[0..len], try rep.encode(&round));
        _ = rep.extendedStatus();
    } else |_| {}
}

test "fuzz: multiple service packet walking never panics" {
    try std.testing.fuzz({}, fuzzMultiple, .{});
}

fn fuzzMultiple(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const ms = MultipleService.decode(buf[0..len]) catch return;
    var i: usize = 0;
    while (i < ms.count) : (i += 1) {
        const msg = ms.at(i) catch continue;
        // Every slice handed out must lie inside the payload.
        try testing.expect(msg.len <= ms.payload.len);
        _ = Request.decode(msg) catch {};
        _ = Reply.decode(msg) catch {};
    }
}

test "fuzz: attribute list iteration never panics or hangs" {
    try std.testing.fuzz({}, fuzzAttrList, .{});
}

fn fuzzAttrList(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const width: usize = smith.valueRangeAtMost(u8, 0, 8);
    var it = AttributeListIterator.init(buf[0..len]) catch return;
    var guard: usize = 0;
    while (true) {
        guard += 1;
        try testing.expect(guard < 100_000);
        const e = it.next(width) catch break;
        if (e == null) break;
    }
}
