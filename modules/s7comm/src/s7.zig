// SPDX-License-Identifier: MIT

//! The S7comm PDU itself: the header that sits inside every COTP `DT`, plus
//! the `Setup communication` negotiation that bounds everything after it.
//!
//! ```text
//!  0     1       2..3            4..5      6..7      8..9     10..11
//! +----+-------+---------------+---------+---------+--------+-----------+
//! |0x32|ROSCTR |redundancy id  |PDU ref  |param len|data len|err cls/cod|
//! +----+-------+---------------+---------+---------+--------+-----------+
//!                                                            ^ only when
//!                                                              ROSCTR is
//!                                                              Ack/AckData
//! ```
//!
//! So the header is **10 octets for a Job or a Userdata PDU and 12 for an Ack
//! or an Ack-Data**. A decoder with a hard-coded 10 reads every reply's
//! parameters two octets early; a decoder with a hard-coded 12 does the same
//! to every request. That branch is the single most load-bearing line here.
//!
//! `parameter_length` and `data_length` are both counted from the end of the
//! header, and their sum must be exactly the remaining octets — anything else
//! is a malformed PDU, not something to paper over.

const std = @import("std");

/// Every S7comm PDU starts with this protocol identifier.
pub const protocol_id: u8 = 0x32;

pub const Error = error{
    /// Fewer octets than the header needs.
    ShortPdu,
    /// The first octet is not 0x32.
    BadProtocolId,
    /// The ROSCTR octet names a message type this implementation does not know.
    UnknownRosctr,
    /// `parameter_length + data_length` does not match the octets present.
    LengthMismatch,
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// The parameter or data block does not fit the 16-bit length fields.
    BlockTooLong,
    /// A Setup-communication parameter of the wrong shape.
    BadSetup,
    /// A negotiated PDU length outside the usable range.
    BadPduLength,
};

/// Remote Operating Service Control — what kind of message this is.
pub const Rosctr = enum(u8) {
    /// Request from the client to the PLC.
    job = 0x01,
    /// Acknowledgement without data. Rare in practice.
    ack = 0x02,
    /// Acknowledgement with data — the normal reply to a Job.
    ack_data = 0x03,
    /// Extended services: SZL reads, cyclic services, block functions,
    /// security. Carries its own parameter sub-header (see `userdata.zig`).
    userdata = 0x07,
    _,

    /// Ack and Ack-Data carry the two extra error octets; Job and Userdata do
    /// not. This is the branch that decides the header length.
    pub fn hasErrorField(self: Rosctr) bool {
        return switch (self) {
            .ack, .ack_data => true,
            else => false,
        };
    }

    pub fn headerLen(self: Rosctr) usize {
        return if (self.hasErrorField()) 12 else 10;
    }
};

/// The parameter function code, i.e. the first octet of a Job/Ack-Data
/// parameter block.
pub const Function = enum(u8) {
    cpu_services = 0x00,
    /// Read protection level / "set password" family.
    setup_communication = 0xF0,
    read_var = 0x04,
    write_var = 0x05,
    request_download = 0x1A,
    download_block = 0x1B,
    download_ended = 0x1C,
    start_upload = 0x1D,
    upload = 0x1E,
    end_upload = 0x1F,
    /// Program-invocation service: warm/cold restart, and the `P_PROGRAM`
    /// family generally.
    pi_service = 0x28,
    /// PLC stop.
    plc_stop = 0x29,
    _,
};

/// Error class in the Ack-Data header (octet 10).
pub const ErrorClass = enum(u8) {
    no_error = 0x00,
    application_relationship = 0x81,
    object_definition = 0x82,
    no_resources_available = 0x83,
    error_on_service_processing = 0x84,
    error_on_supplies = 0x85,
    access_error = 0x87,
    _,
};

/// A decoded S7 header.
pub const Header = struct {
    rosctr: Rosctr,
    /// Always 0 on every device seen in the wild; kept because it is on the
    /// wire and a peer is free to use it.
    redundancy_id: u16 = 0,
    /// Echoed by the PLC in the reply, which is how a reply is matched to its
    /// request. Big-endian on the wire and treated as an opaque token here.
    pdu_reference: u16,
    /// Derived from the slices on encode; only meaningful after a decode.
    parameter_length: u16 = 0,
    /// Derived from the slices on encode; only meaningful after a decode.
    data_length: u16 = 0,
    /// Present only when `rosctr.hasErrorField()`.
    error_class: ErrorClass = .no_error,
    error_code: u8 = 0,

    pub fn len(self: Header) usize {
        return self.rosctr.headerLen();
    }

    /// True when this is an Ack/Ack-Data reporting a PDU-level failure. Note
    /// that a *successful* Read Var can still contain per-item failures — see
    /// `items.ReturnCode`.
    pub fn isError(self: Header) bool {
        return self.rosctr.hasErrorField() and
            (self.error_class != .no_error or self.error_code != 0);
    }
};

/// A whole S7 PDU: header plus the two blocks it delimits.
pub const Pdu = struct {
    header: Header,
    parameters: []const u8,
    data: []const u8,
    /// Octets consumed, i.e. `header.len() + parameters.len + data.len`.
    total_len: usize,
};

fn be16(b: []const u8) u16 {
    return (@as(u16, b[0]) << 8) | b[1];
}

fn putBe16(out: []u8, v: u16) void {
    out[0] = @intCast(v >> 8);
    out[1] = @intCast(v & 0xFF);
}

/// Decodes a header only, without requiring the body to be present. Callers
/// that stream can use `header.len() + parameter_length + data_length` to know
/// how much more to read.
pub fn decodeHeader(bytes: []const u8) Error!Header {
    if (bytes.len < 10) return error.ShortPdu;
    if (bytes[0] != protocol_id) return error.BadProtocolId;
    const rosctr: Rosctr = @enumFromInt(bytes[1]);
    switch (rosctr) {
        .job, .ack, .ack_data, .userdata => {},
        _ => return error.UnknownRosctr,
    }
    var h: Header = .{
        .rosctr = rosctr,
        .redundancy_id = be16(bytes[2..4]),
        .pdu_reference = be16(bytes[4..6]),
        .parameter_length = be16(bytes[6..8]),
        .data_length = be16(bytes[8..10]),
    };
    if (rosctr.hasErrorField()) {
        if (bytes.len < 12) return error.ShortPdu;
        h.error_class = @enumFromInt(bytes[10]);
        h.error_code = bytes[11];
    }
    return h;
}

/// Decodes a whole PDU. The parameter and data lengths must account for
/// **exactly** the octets that follow the header — a PDU that claims more is
/// truncated, and one that claims less has trailing junk. Both are refused,
/// because in a protocol with no per-PDU checksum a length disagreement is the
/// only signal that framing has gone wrong.
pub fn decode(bytes: []const u8) Error!Pdu {
    const h = try decodeHeader(bytes);
    const hl = h.len();
    const body = @as(usize, h.parameter_length) + @as(usize, h.data_length);
    if (bytes.len != hl + body) return error.LengthMismatch;
    return .{
        .header = h,
        .parameters = bytes[hl..][0..h.parameter_length],
        .data = bytes[hl + h.parameter_length ..][0..h.data_length],
        .total_len = hl + body,
    };
}

/// Like `decode`, but tolerates trailing octets (used when the caller framed
/// the PDU itself and may be handing over a larger buffer).
pub fn decodePrefix(bytes: []const u8) Error!Pdu {
    const h = try decodeHeader(bytes);
    const hl = h.len();
    const body = @as(usize, h.parameter_length) + @as(usize, h.data_length);
    if (bytes.len < hl + body) return error.LengthMismatch;
    return .{
        .header = h,
        .parameters = bytes[hl..][0..h.parameter_length],
        .data = bytes[hl + h.parameter_length ..][0..h.data_length],
        .total_len = hl + body,
    };
}

/// Writes header + parameters + data into `out`. The header's length fields
/// are derived from the slices, never trusted from the caller's struct, so an
/// inconsistent header cannot be produced.
pub fn encode(h: Header, parameters: []const u8, data: []const u8, out: []u8) Error![]u8 {
    if (parameters.len > 0xFFFF or data.len > 0xFFFF) return error.BlockTooLong;
    const hl = h.rosctr.headerLen();
    const total = hl + parameters.len + data.len;
    if (out.len < total) return error.BufferTooSmall;
    out[0] = protocol_id;
    out[1] = @intFromEnum(h.rosctr);
    putBe16(out[2..4], h.redundancy_id);
    putBe16(out[4..6], h.pdu_reference);
    putBe16(out[6..8], @intCast(parameters.len));
    putBe16(out[8..10], @intCast(data.len));
    if (h.rosctr.hasErrorField()) {
        out[10] = @intFromEnum(h.error_class);
        out[11] = h.error_code;
    }
    @memcpy(out[hl..][0..parameters.len], parameters);
    @memcpy(out[hl + parameters.len ..][0..data.len], data);
    return out[0..total];
}

// ── Setup communication ─────────────────────────────────────────────────────

/// The `Setup communication` parameter block (function `0xF0`), which both
/// sides exchange immediately after the COTP connection comes up.
///
/// The negotiated `pdu_length` is **the** number in this protocol: it caps
/// every request and every reply for the rest of the connection, and the PLC
/// is free to return something smaller than what was asked for. A client that
/// keeps using its own requested value after the PLC lowered it will build
/// requests the PLC silently rejects.
pub const Setup = struct {
    /// Maximum outstanding requests this side will issue.
    max_amq_calling: u16 = 1,
    /// Maximum outstanding requests this side will accept.
    max_amq_called: u16 = 1,
    /// Bytes. 240 / 480 / 960 are the values real CPUs return.
    pdu_length: u16 = 480,

    pub const wire_len: usize = 8;
    /// Smallest PDU length that can still carry a one-item read reply
    /// (12 header + 2 parameters + 4 data-item header + 1 octet).
    pub const min_pdu_length: u16 = 19;

    pub fn encode(self: Setup, out: []u8) Error![]u8 {
        if (out.len < wire_len) return error.BufferTooSmall;
        if (self.pdu_length < min_pdu_length) return error.BadPduLength;
        out[0] = @intFromEnum(Function.setup_communication);
        out[1] = 0; // reserved
        putBe16(out[2..4], self.max_amq_calling);
        putBe16(out[4..6], self.max_amq_called);
        putBe16(out[6..8], self.pdu_length);
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) Error!Setup {
        if (bytes.len < wire_len) return error.BadSetup;
        if (bytes[0] != @intFromEnum(Function.setup_communication)) return error.BadSetup;
        const s: Setup = .{
            .max_amq_calling = be16(bytes[2..4]),
            .max_amq_called = be16(bytes[4..6]),
            .pdu_length = be16(bytes[6..8]),
        };
        if (s.pdu_length < min_pdu_length) return error.BadPduLength;
        return s;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "header length depends on ROSCTR" {
    try testing.expectEqual(@as(usize, 10), Rosctr.job.headerLen());
    try testing.expectEqual(@as(usize, 10), Rosctr.userdata.headerLen());
    try testing.expectEqual(@as(usize, 12), Rosctr.ack.headerLen());
    try testing.expectEqual(@as(usize, 12), Rosctr.ack_data.headerLen());
}

test "Job round trip" {
    const params = [_]u8{ 0x04, 0x01 };
    var buf: [64]u8 = undefined;
    const enc = try encode(.{ .rosctr = .job, .pdu_reference = 0x1234 }, &params, &.{}, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x32, 0x01, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x00, 0x04, 0x01,
    }, enc);
    const dec = try decode(enc);
    try testing.expectEqual(Rosctr.job, dec.header.rosctr);
    try testing.expectEqual(@as(u16, 0x1234), dec.header.pdu_reference);
    try testing.expectEqualSlices(u8, &params, dec.parameters);
    try testing.expectEqual(@as(usize, 0), dec.data.len);
}

test "Ack-Data carries the error class and code" {
    const params = [_]u8{ 0x04, 0x01 };
    const data = [_]u8{ 0xFF, 0x04, 0x00, 0x08, 0xA5 };
    var buf: [64]u8 = undefined;
    const enc = try encode(.{
        .rosctr = .ack_data,
        .pdu_reference = 3,
        .error_class = .access_error,
        .error_code = 0x04,
    }, &params, &data, &buf);
    try testing.expectEqual(@as(usize, 12 + 2 + 5), enc.len);
    try testing.expectEqual(@as(u8, 0x87), enc[10]);
    const dec = try decode(enc);
    try testing.expectEqual(ErrorClass.access_error, dec.header.error_class);
    try testing.expectEqual(@as(u8, 4), dec.header.error_code);
    try testing.expect(dec.header.isError());
    try testing.expectEqualSlices(u8, &data, dec.data);
}

test "a Job is not treated as having an error field" {
    // 0x32 01 ... with a body that would look like an error field if the
    // header length were wrong.
    const wire = [_]u8{ 0x32, 0x01, 0, 0, 0, 1, 0, 0x02, 0, 0, 0x87, 0x04 };
    const dec = try decode(&wire);
    try testing.expectEqual(@as(usize, 10), dec.header.len());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x87, 0x04 }, dec.parameters);
    try testing.expect(!dec.header.isError());
}

test "decode rejects a header whose lengths overflow the frame" {
    // parameter_length 0xFFFF with a 12-octet buffer.
    try testing.expectError(error.LengthMismatch, decode(&[_]u8{
        0x32, 0x01, 0, 0, 0, 1, 0xFF, 0xFF, 0, 0, 0, 0,
    }));
    // parameter + data both large: the sum must not wrap.
    try testing.expectError(error.LengthMismatch, decode(&[_]u8{
        0x32, 0x01, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF,
    }));
    // Trailing junk past the announced body.
    try testing.expectError(error.LengthMismatch, decode(&[_]u8{
        0x32, 0x01, 0, 0, 0, 1, 0, 0x01, 0, 0, 0x04, 0xAA,
    }));
    // ... which decodePrefix tolerates.
    const p = try decodePrefix(&[_]u8{ 0x32, 0x01, 0, 0, 0, 1, 0, 0x01, 0, 0, 0x04, 0xAA });
    try testing.expectEqual(@as(usize, 11), p.total_len);
}

test "decode rejects a bad protocol id, ROSCTR and short buffers" {
    try testing.expectError(error.ShortPdu, decode(&[_]u8{ 0x32, 0x01 }));
    try testing.expectError(error.BadProtocolId, decode(&[_]u8{ 0x33, 0x01, 0, 0, 0, 1, 0, 0, 0, 0 }));
    try testing.expectError(error.UnknownRosctr, decode(&[_]u8{ 0x32, 0x09, 0, 0, 0, 1, 0, 0, 0, 0 }));
    try testing.expectError(error.UnknownRosctr, decode(&[_]u8{ 0x32, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 }));
    // An Ack-Data that stops before its error octets.
    try testing.expectError(error.ShortPdu, decode(&[_]u8{ 0x32, 0x03, 0, 0, 0, 1, 0, 0, 0, 0 }));
}

test "Setup communication round trip" {
    var buf: [16]u8 = undefined;
    const s: Setup = .{ .max_amq_calling = 1, .max_amq_called = 1, .pdu_length = 480 };
    const enc = try s.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0 }, enc);
    const dec = try Setup.decode(enc);
    try testing.expectEqual(@as(u16, 480), dec.pdu_length);
    try testing.expectEqual(@as(u16, 1), dec.max_amq_calling);
}

test "Setup refuses an unusable PDU length" {
    var buf: [16]u8 = undefined;
    try testing.expectError(error.BadPduLength, (Setup{ .pdu_length = 8 }).encode(&buf));
    try testing.expectError(error.BadPduLength, Setup.decode(&[_]u8{ 0xF0, 0, 0, 1, 0, 1, 0, 0x08 }));
    try testing.expectError(error.BadSetup, Setup.decode(&[_]u8{ 0x04, 0, 0, 1, 0, 1, 0x01, 0xE0 }));
    try testing.expectError(error.BadSetup, Setup.decode(&[_]u8{ 0xF0, 0, 0, 1 }));
}

test "encode derives the length fields from the slices" {
    var buf: [64]u8 = undefined;
    // A header claiming nonsense lengths must not be able to emit them.
    const enc = try encode(
        .{ .rosctr = .job, .pdu_reference = 1, .parameter_length = 999, .data_length = 999 },
        &[_]u8{ 1, 2, 3 },
        &[_]u8{4},
        &buf,
    );
    try testing.expectEqual(@as(u16, 3), be16(enc[6..8]));
    try testing.expectEqual(@as(u16, 1), be16(enc[8..10]));
    _ = try decode(enc);
}

test "fuzz: s7 decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const pdu = decode(buf[0..len]) catch return;
    var round: [512]u8 = undefined;
    const again = try encode(pdu.header, pdu.parameters, pdu.data, &round);
    try testing.expectEqualSlices(u8, buf[0..len], again);
}
