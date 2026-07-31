// SPDX-License-Identifier: MIT

//! **Clause 20.1 — the application layer PDU.** Eight PDU types selected by
//! the top nibble of the first octet, each with its own fixed header before
//! the tagged service data.
//!
//! The part that repays care is **segmentation**. A `Confirmed-Request` or a
//! `ComplexACK` whose SEG bit is set carries two extra header octets (sequence
//! number and window size) *before* the service choice. A decoder that ignores
//! the SEG bit therefore reads the sequence number as the service choice and
//! the window size as the first tag — and produces a plausible-looking,
//! completely wrong decode. That is the single failure mode this file exists
//! to prevent: `decode` always looks at SEG first, and a segmented PDU is
//! returned as a **typed segment** the caller must deal with, never silently
//! flattened into an unsegmented one.
//!
//! This module does not *reassemble* segments (see SPEC.md's deferred list).
//! What it does instead is make refusing them correct and easy:
//! `Client`/`Device` advertise `max_segments = .unspecified` and answer an
//! offered segmented request with `Abort(segmentation_not_supported)`, which
//! is exactly what clause 5.4 prescribes for a device that cannot reassemble.
//!
//! Nothing here allocates; service data is a slice of the caller's buffer.

const std = @import("std");
const types = @import("types.zig");
const tag = @import("tag.zig");

pub const Error = error{
    /// Buffer ended inside a PDU header.
    Truncated,
    /// The top nibble is not one of the eight defined PDU types, or a
    /// reserved flag bit in the first octet is set.
    InvalidPduType,
    /// A field that must be a legal enumeration is not: a `max_apdu` code
    /// above 5, an unknown `Reject`/`Abort` reason where one is required.
    InvalidValue,
    /// Output buffer too small.
    NoSpace,
    /// The PDU is segmented and the caller asked for the unsegmented view.
    Segmented,
};

/// PDU types (clause 20.1.1, `BACnetPDUType`).
pub const PduType = enum(u4) {
    confirmed_request = 0,
    unconfirmed_request = 1,
    simple_ack = 2,
    complex_ack = 3,
    segment_ack = 4,
    err = 5,
    reject = 6,
    abort = 7,
    _,
};

/// `max-APDU-length-accepted` (clause 20.1.2.5) — a **code**, not a length.
/// 50 octets is the MS/TP floor; 1476 is what fits an Ethernet frame and is
/// what essentially every BACnet/IP device advertises.
pub const MaxApdu = enum(u4) {
    up_to_50 = 0,
    up_to_128 = 1,
    up_to_206 = 2,
    up_to_480 = 3,
    up_to_1024 = 4,
    up_to_1476 = 5,
    _,

    pub fn octets(self: MaxApdu) Error!u16 {
        return switch (self) {
            .up_to_50 => 50,
            .up_to_128 => 128,
            .up_to_206 => 206,
            .up_to_480 => 480,
            .up_to_1024 => 1024,
            .up_to_1476 => 1476,
            // 6..15 are reserved. Guessing a buffer size from a reserved code
            // is how a peer gets to choose your allocation.
            _ => error.InvalidValue,
        };
    }

    /// The largest code whose length fits in `n` octets.
    pub fn forOctets(n: u16) MaxApdu {
        if (n >= 1476) return .up_to_1476;
        if (n >= 1024) return .up_to_1024;
        if (n >= 480) return .up_to_480;
        if (n >= 206) return .up_to_206;
        if (n >= 128) return .up_to_128;
        return .up_to_50;
    }
};

/// `max-segments-accepted` (clause 20.1.2.4). `unspecified` is what a device
/// that will not reassemble says, and it is what this module always sends.
pub const MaxSegments = enum(u3) {
    unspecified = 0,
    two = 1,
    four = 2,
    eight = 3,
    sixteen = 4,
    thirty_two = 5,
    sixty_four = 6,
    more_than_64 = 7,
};

/// The two segmentation octets that sit between the invoke id and the service
/// choice when the SEG bit is set.
pub const SegmentInfo = struct {
    /// 0-based index of this segment.
    sequence_number: u8,
    /// How many segments the sender is willing to have outstanding, 1..127.
    window_size: u8,
    /// "More follows" — clear on the last segment.
    more_follows: bool,
};

/// A Confirmed-Request PDU (clause 20.1.2).
pub const ConfirmedRequest = struct {
    /// Set when the *sender* can accept a segmented response.
    segmented_response_accepted: bool = false,
    max_segments: MaxSegments = .unspecified,
    max_apdu: MaxApdu = .up_to_1476,
    invoke_id: u8,
    service: types.ConfirmedService,
    /// Present iff this request is itself segmented.
    segment: ?SegmentInfo = null,
    /// Tagged service parameters. Borrowed from the input buffer.
    data: []const u8 = &.{},
};

/// An Unconfirmed-Request PDU (clause 20.1.3) — Who-Is, I-Am, COV
/// notifications. Never segmented, never acknowledged.
pub const UnconfirmedRequest = struct {
    service: types.UnconfirmedService,
    data: []const u8 = &.{},
};

/// A SimpleACK (clause 20.1.4): "done", with no result data.
pub const SimpleAck = struct {
    invoke_id: u8,
    service: types.ConfirmedService,
};

/// A ComplexACK (clause 20.1.5): a result, possibly segmented.
pub const ComplexAck = struct {
    invoke_id: u8,
    service: types.ConfirmedService,
    segment: ?SegmentInfo = null,
    data: []const u8 = &.{},
};

/// A SegmentACK (clause 20.1.6): flow control for a segmented transfer.
pub const SegmentAck = struct {
    /// Negative acknowledgement — the sequence number was not what was
    /// expected and the sender must go back.
    negative: bool = false,
    /// Sent by the *server* side of the transaction.
    server: bool = false,
    invoke_id: u8,
    sequence_number: u8,
    actual_window_size: u8,
};

/// An Error PDU (clause 20.1.7): the service was understood and refused.
pub const ErrorPdu = struct {
    invoke_id: u8,
    service: types.ConfirmedService,
    class: types.ErrorClass,
    code: types.ErrorCode,
    /// Anything after the two mandatory enumerations (some services define a
    /// richer error structure). Borrowed.
    extra: []const u8 = &.{},
};

/// A Reject PDU (clause 20.1.8): the request could not be interpreted.
pub const Reject = struct {
    invoke_id: u8,
    reason: types.RejectReason,
};

/// An Abort PDU (clause 20.1.9): the transaction is over.
pub const Abort = struct {
    /// Sent by the server side of the transaction.
    server: bool = false,
    invoke_id: u8,
    reason: types.AbortReason,
};

/// A decoded APDU.
pub const Apdu = union(PduType) {
    confirmed_request: ConfirmedRequest,
    unconfirmed_request: UnconfirmedRequest,
    simple_ack: SimpleAck,
    complex_ack: ComplexAck,
    segment_ack: SegmentAck,
    err: ErrorPdu,
    reject: Reject,
    abort: Abort,

    pub fn pduType(self: Apdu) PduType {
        return std.meta.activeTag(self);
    }

    /// The invoke id, for the PDU types that carry one. An
    /// Unconfirmed-Request has no transaction, so it has none.
    pub fn invokeId(self: Apdu) ?u8 {
        return switch (self) {
            .confirmed_request => |r| r.invoke_id,
            .unconfirmed_request => null,
            .simple_ack => |a| a.invoke_id,
            .complex_ack => |a| a.invoke_id,
            .segment_ack => |a| a.invoke_id,
            .err => |e| e.invoke_id,
            .reject => |r| r.invoke_id,
            .abort => |a| a.invoke_id,
        };
    }

    /// True when this PDU is one segment of a larger message. A caller that
    /// does not reassemble **must** check this before looking at `data`.
    pub fn isSegmented(self: Apdu) bool {
        return switch (self) {
            .confirmed_request => |r| r.segment != null,
            .complex_ack => |a| a.segment != null,
            else => false,
        };
    }

    /// The tagged service data, or `error.Segmented` when this PDU is only
    /// part of a message. Use this in preference to reaching into `data`: it
    /// makes forgetting the segmentation check impossible.
    pub fn serviceData(self: Apdu) Error![]const u8 {
        if (self.isSegmented()) return error.Segmented;
        return switch (self) {
            .confirmed_request => |r| r.data,
            .unconfirmed_request => |r| r.data,
            .complex_ack => |a| a.data,
            .err => |e| e.extra,
            else => &.{},
        };
    }
};

// ── decode ──────────────────────────────────────────────────────────────────

/// Decodes one APDU from the payload of an NPDU.
pub fn decode(buf: []const u8) Error!Apdu {
    if (buf.len < 1) return error.Truncated;
    const b0 = buf[0];
    const kind: PduType = @enumFromInt(@as(u4, @truncate(b0 >> 4)));

    switch (kind) {
        .confirmed_request => {
            // 0 | SEG MOR SA | max-segments(3) max-apdu(4) | invoke | [seq win] | svc
            if (buf.len < 4) return error.Truncated;
            if (b0 & 0x01 != 0) return error.InvalidPduType; // reserved bit 0
            const seg = b0 & 0x08 != 0;
            const mor = b0 & 0x04 != 0;
            const sa = b0 & 0x02 != 0;
            const b1 = buf[1];
            if (b1 & 0x80 != 0) return error.InvalidPduType; // reserved bit 7
            var pos: usize = 3;
            var segment: ?SegmentInfo = null;
            if (seg) {
                if (buf.len < 6) return error.Truncated;
                segment = .{
                    .sequence_number = buf[3],
                    .window_size = buf[4],
                    .more_follows = mor,
                };
                pos = 5;
            } else if (mor) {
                // MOR without SEG is meaningless: there is no segment for more
                // to follow.
                return error.InvalidPduType;
            }
            if (buf.len < pos + 1) return error.Truncated;
            const svc: types.ConfirmedService = @enumFromInt(buf[pos]);
            return .{ .confirmed_request = .{
                .segmented_response_accepted = sa,
                .max_segments = @enumFromInt(@as(u3, @truncate((b1 >> 4) & 0x07))),
                .max_apdu = @enumFromInt(@as(u4, @truncate(b1 & 0x0F))),
                .invoke_id = buf[2],
                .service = svc,
                .segment = segment,
                .data = buf[pos + 1 ..],
            } };
        },
        .unconfirmed_request => {
            if (b0 & 0x0F != 0) return error.InvalidPduType;
            if (buf.len < 2) return error.Truncated;
            return .{ .unconfirmed_request = .{
                .service = @enumFromInt(buf[1]),
                .data = buf[2..],
            } };
        },
        .simple_ack => {
            if (b0 & 0x0F != 0) return error.InvalidPduType;
            if (buf.len < 3) return error.Truncated;
            // A SimpleACK is exactly three octets. Trailing data means the
            // peer sent something else and mislabelled it.
            if (buf.len != 3) return error.InvalidValue;
            return .{ .simple_ack = .{
                .invoke_id = buf[1],
                .service = @enumFromInt(buf[2]),
            } };
        },
        .complex_ack => {
            // 3 | SEG MOR 0 0 | invoke | [seq win] | svc | data
            if (b0 & 0x03 != 0) return error.InvalidPduType;
            if (buf.len < 3) return error.Truncated;
            const seg = b0 & 0x08 != 0;
            const mor = b0 & 0x04 != 0;
            var pos: usize = 2;
            var segment: ?SegmentInfo = null;
            if (seg) {
                if (buf.len < 5) return error.Truncated;
                segment = .{
                    .sequence_number = buf[2],
                    .window_size = buf[3],
                    .more_follows = mor,
                };
                pos = 4;
            } else if (mor) {
                return error.InvalidPduType;
            }
            if (buf.len < pos + 1) return error.Truncated;
            return .{ .complex_ack = .{
                .invoke_id = buf[1],
                .service = @enumFromInt(buf[pos]),
                .segment = segment,
                .data = buf[pos + 1 ..],
            } };
        },
        .segment_ack => {
            if (b0 & 0x0C != 0) return error.InvalidPduType;
            if (buf.len != 4) return error.Truncated;
            return .{ .segment_ack = .{
                .negative = b0 & 0x02 != 0,
                .server = b0 & 0x01 != 0,
                .invoke_id = buf[1],
                .sequence_number = buf[2],
                .actual_window_size = buf[3],
            } };
        },
        .err => {
            if (b0 & 0x0F != 0) return error.InvalidPduType;
            if (buf.len < 3) return error.Truncated;
            var r = tag.Reader.init(buf[3..]);
            const class_v = r.expectApp(.enumerated) catch return error.Truncated;
            const code_v = r.expectApp(.enumerated) catch return error.Truncated;
            if (class_v.enumerated > std.math.maxInt(u16)) return error.InvalidValue;
            if (code_v.enumerated > std.math.maxInt(u16)) return error.InvalidValue;
            return .{ .err = .{
                .invoke_id = buf[1],
                .service = @enumFromInt(buf[2]),
                .class = @enumFromInt(@as(u16, @intCast(class_v.enumerated))),
                .code = @enumFromInt(@as(u16, @intCast(code_v.enumerated))),
                .extra = r.rest(),
            } };
        },
        .reject => {
            if (b0 & 0x0F != 0) return error.InvalidPduType;
            if (buf.len != 3) return error.Truncated;
            return .{ .reject = .{
                .invoke_id = buf[1],
                .reason = @enumFromInt(buf[2]),
            } };
        },
        .abort => {
            if (b0 & 0x0E != 0) return error.InvalidPduType;
            if (buf.len != 3) return error.Truncated;
            return .{ .abort = .{
                .server = b0 & 0x01 != 0,
                .invoke_id = buf[1],
                .reason = @enumFromInt(buf[2]),
            } };
        },
        _ => return error.InvalidPduType,
    }
}

// ── encode ──────────────────────────────────────────────────────────────────

/// Encodes an APDU into `out`, returning the slice written.
pub fn encode(a: Apdu, out: []u8) Error![]u8 {
    var w = Buf{ .out = out };
    switch (a) {
        .confirmed_request => |r| {
            var b0: u8 = @as(u8, @intFromEnum(PduType.confirmed_request)) << 4;
            if (r.segment) |s| {
                b0 |= 0x08;
                if (s.more_follows) b0 |= 0x04;
            }
            if (r.segmented_response_accepted) b0 |= 0x02;
            try w.byte(b0);
            try w.byte((@as(u8, @intFromEnum(r.max_segments)) << 4) |
                @as(u8, @intFromEnum(r.max_apdu)));
            try w.byte(r.invoke_id);
            if (r.segment) |s| {
                try w.byte(s.sequence_number);
                try w.byte(s.window_size);
            }
            try w.byte(@intFromEnum(r.service));
            try w.raw(r.data);
        },
        .unconfirmed_request => |r| {
            try w.byte(@as(u8, @intFromEnum(PduType.unconfirmed_request)) << 4);
            try w.byte(@intFromEnum(r.service));
            try w.raw(r.data);
        },
        .simple_ack => |s| {
            try w.byte(@as(u8, @intFromEnum(PduType.simple_ack)) << 4);
            try w.byte(s.invoke_id);
            try w.byte(@intFromEnum(s.service));
        },
        .complex_ack => |c| {
            var b0: u8 = @as(u8, @intFromEnum(PduType.complex_ack)) << 4;
            if (c.segment) |s| {
                b0 |= 0x08;
                if (s.more_follows) b0 |= 0x04;
            }
            try w.byte(b0);
            try w.byte(c.invoke_id);
            if (c.segment) |s| {
                try w.byte(s.sequence_number);
                try w.byte(s.window_size);
            }
            try w.byte(@intFromEnum(c.service));
            try w.raw(c.data);
        },
        .segment_ack => |s| {
            var b0: u8 = @as(u8, @intFromEnum(PduType.segment_ack)) << 4;
            if (s.negative) b0 |= 0x02;
            if (s.server) b0 |= 0x01;
            try w.byte(b0);
            try w.byte(s.invoke_id);
            try w.byte(s.sequence_number);
            try w.byte(s.actual_window_size);
        },
        .err => |e| {
            try w.byte(@as(u8, @intFromEnum(PduType.err)) << 4);
            try w.byte(e.invoke_id);
            try w.byte(@intFromEnum(e.service));
            var tw = tag.Writer.init(out[w.pos..]);
            tw.appEnumerated(@intFromEnum(e.class)) catch return error.NoSpace;
            tw.appEnumerated(@intFromEnum(e.code)) catch return error.NoSpace;
            w.pos += tw.pos;
            try w.raw(e.extra);
        },
        .reject => |r| {
            try w.byte(@as(u8, @intFromEnum(PduType.reject)) << 4);
            try w.byte(r.invoke_id);
            try w.byte(@intFromEnum(r.reason));
        },
        .abort => |ab| {
            var b0: u8 = @as(u8, @intFromEnum(PduType.abort)) << 4;
            if (ab.server) b0 |= 0x01;
            try w.byte(b0);
            try w.byte(ab.invoke_id);
            try w.byte(@intFromEnum(ab.reason));
        },
    }
    return out[0..w.pos];
}

const Buf = struct {
    out: []u8,
    pos: usize = 0,

    fn byte(self: *Buf, b: u8) Error!void {
        if (self.pos + 1 > self.out.len) return error.NoSpace;
        self.out[self.pos] = b;
        self.pos += 1;
    }

    fn raw(self: *Buf, bytes: []const u8) Error!void {
        if (self.pos + bytes.len > self.out.len) return error.NoSpace;
        @memcpy(self.out[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }
};

/// Builds the `Abort` a device that cannot reassemble owes a peer that offered
/// it a segmented request (clause 5.4.5.3).
pub fn segmentationNotSupported(invoke_id: u8, server: bool) Apdu {
    return .{ .abort = .{
        .server = server,
        .invoke_id = invoke_id,
        .reason = .segmentation_not_supported,
    } };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "unconfirmed request: Who-Is with a device range" {
    // 10 08 || 09 01 19 64  — Who-Is, low 1, high 100.
    const wire = [_]u8{ 0x10, 0x08, 0x09, 0x01, 0x19, 0x64 };
    const a = try decode(&wire);
    try testing.expectEqual(types.UnconfirmedService.who_is, a.unconfirmed_request.service);
    try testing.expectEqualSlices(u8, wire[2..], try a.serviceData());
    try testing.expectEqual(@as(?u8, null), a.invokeId());
    try testing.expect(!a.isSegmented());

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(a, &out));

    // The low nibble of an Unconfirmed-Request is reserved.
    try testing.expectError(error.InvalidPduType, decode(&.{ 0x12, 0x08 }));
    try testing.expectError(error.Truncated, decode(&.{0x10}));
}

test "confirmed request: unsegmented ReadProperty" {
    // 00 05 01 0c || 0c 00 00 00 05 19 55
    //  ^  ^  ^  ^-- service 12 = ReadProperty
    //  |  |  +----- invoke id 1
    //  |  +-------- max-segments 0 (unspecified), max-apdu 5 (1476)
    //  +----------- type 0, no flags
    const wire = [_]u8{
        0x00, 0x05, 0x01, 0x0C,
        0x0C, 0x00, 0x00, 0x00,
        0x05, 0x19, 0x55,
    };
    const a = try decode(&wire);
    const r = a.confirmed_request;
    try testing.expectEqual(MaxSegments.unspecified, r.max_segments);
    try testing.expectEqual(MaxApdu.up_to_1476, r.max_apdu);
    try testing.expectEqual(@as(u16, 1476), try r.max_apdu.octets());
    try testing.expectEqual(@as(u8, 1), r.invoke_id);
    try testing.expectEqual(types.ConfirmedService.read_property, r.service);
    try testing.expectEqual(@as(?SegmentInfo, null), r.segment);
    try testing.expectEqualSlices(u8, wire[4..], r.data);

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(a, &out));
}

test "SEGMENTATION: the SEG bit moves the service choice by two octets" {
    // The whole point. Same bytes after the invoke id, but with SEG set the
    // service choice is at offset 5, not 3.
    const unseg = [_]u8{ 0x00, 0x05, 0x01, 0x0C, 0xAA, 0xBB };
    const seg = [_]u8{ 0x0C, 0x05, 0x01, 0x00, 0x10, 0x0C, 0xAA, 0xBB };
    //                  ^ SEG|MOR                ^seq ^win ^service

    const u = try decode(&unseg);
    try testing.expectEqual(types.ConfirmedService.read_property, u.confirmed_request.service);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, u.confirmed_request.data);

    const s = try decode(&seg);
    const si = s.confirmed_request.segment.?;
    try testing.expectEqual(@as(u8, 0), si.sequence_number);
    try testing.expectEqual(@as(u8, 16), si.window_size);
    try testing.expectEqual(true, si.more_follows);
    // Read from the RIGHT offset: still ReadProperty, not 0x00 (the sequence
    // number) which a SEG-blind decoder would have produced.
    try testing.expectEqual(types.ConfirmedService.read_property, s.confirmed_request.service);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, s.confirmed_request.data);

    // And the caller cannot get at the data without acknowledging it.
    try testing.expect(s.isSegmented());
    try testing.expectError(error.Segmented, s.serviceData());

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &seg, try encode(s, &out));

    // A segmented request that stops before its two segmentation octets.
    try testing.expectError(error.Truncated, decode(&.{ 0x0C, 0x05, 0x01, 0x00, 0x10 }));
    // MOR without SEG is not a thing.
    try testing.expectError(error.InvalidPduType, decode(&.{ 0x04, 0x05, 0x01, 0x0C }));
}

test "SEGMENTATION: a segmented ComplexACK is never mistaken for a whole one" {
    // Unsegmented: 30 01 0c || data
    const unseg = [_]u8{ 0x30, 0x01, 0x0C, 0x0C, 0x00, 0x00, 0x00, 0x05 };
    const u = try decode(&unseg);
    try testing.expectEqual(types.ConfirmedService.read_property, u.complex_ack.service);
    try testing.expectEqualSlices(u8, unseg[3..], try u.serviceData());

    // Segmented: 3c 01 00 10 0c || data — same trailing bytes, service choice
    // two octets later.
    const seg = [_]u8{ 0x3C, 0x01, 0x00, 0x10, 0x0C, 0x0C, 0x00, 0x00, 0x00, 0x05 };
    const s = try decode(&seg);
    const c = s.complex_ack;
    try testing.expectEqual(@as(u8, 0), c.segment.?.sequence_number);
    try testing.expectEqual(@as(u8, 16), c.segment.?.window_size);
    try testing.expectEqual(true, c.segment.?.more_follows);
    try testing.expectEqual(types.ConfirmedService.read_property, c.service);
    try testing.expect(s.isSegmented());
    try testing.expectError(error.Segmented, s.serviceData());

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &seg, try encode(s, &out));

    // The last segment: SEG set, MOR clear.
    const last = [_]u8{ 0x38, 0x01, 0x03, 0x10, 0x0C, 0xAA };
    const l = try decode(&last);
    try testing.expectEqual(false, l.complex_ack.segment.?.more_follows);
    try testing.expectEqual(@as(u8, 3), l.complex_ack.segment.?.sequence_number);

    try testing.expectError(error.Truncated, decode(&.{ 0x3C, 0x01, 0x00, 0x10 }));
    try testing.expectError(error.InvalidPduType, decode(&.{ 0x34, 0x01, 0x0C })); // MOR sans SEG
    try testing.expectError(error.InvalidPduType, decode(&.{ 0x31, 0x01, 0x0C })); // reserved bit
}

test "SimpleACK, Reject, Abort and SegmentACK are fixed-size" {
    var out: [16]u8 = undefined;

    const sack = [_]u8{ 0x20, 0x01, 0x0F };
    const s = try decode(&sack);
    try testing.expectEqual(@as(u8, 1), s.simple_ack.invoke_id);
    try testing.expectEqual(types.ConfirmedService.write_property, s.simple_ack.service);
    try testing.expectEqualSlices(u8, &sack, try encode(s, &out));
    try testing.expectError(error.InvalidValue, decode(&.{ 0x20, 0x01, 0x0F, 0x00 }));
    try testing.expectError(error.Truncated, decode(&.{ 0x20, 0x01 }));

    const rej = [_]u8{ 0x60, 0x01, 0x09 };
    const r = try decode(&rej);
    try testing.expectEqual(types.RejectReason.unrecognized_service, r.reject.reason);
    try testing.expectEqualSlices(u8, &rej, try encode(r, &out));
    try testing.expectError(error.Truncated, decode(&.{ 0x60, 0x01, 0x09, 0x00 }));

    const ab = [_]u8{ 0x71, 0x01, 0x04 };
    const a = try decode(&ab);
    try testing.expectEqual(true, a.abort.server);
    try testing.expectEqual(types.AbortReason.segmentation_not_supported, a.abort.reason);
    try testing.expectEqualSlices(u8, &ab, try encode(a, &out));
    // Bits 1..3 of an Abort's first octet are reserved.
    try testing.expectError(error.InvalidPduType, decode(&.{ 0x72, 0x01, 0x04 }));
    // An Abort carries no service data; trailing octets are a malformed PDU,
    // not an Abort with a payload it has no field for.
    try testing.expectError(error.Truncated, decode(&.{ 0x71, 0x01 }));
    try testing.expectError(error.Truncated, decode(&.{ 0x71, 0x01, 0x04, 0x00 }));

    const segack = [_]u8{ 0x42, 0x01, 0x03, 0x10 };
    const sa = try decode(&segack);
    try testing.expectEqual(true, sa.segment_ack.negative);
    try testing.expectEqual(false, sa.segment_ack.server);
    try testing.expectEqual(@as(u8, 3), sa.segment_ack.sequence_number);
    try testing.expectEqual(@as(u8, 16), sa.segment_ack.actual_window_size);
    try testing.expectEqualSlices(u8, &segack, try encode(sa, &out));
    try testing.expectError(error.Truncated, decode(&.{ 0x40, 0x01, 0x03 }));
    try testing.expectError(error.InvalidPduType, decode(&.{ 0x44, 0x01, 0x03, 0x10 }));
}

test "Error PDU carries two application-tagged enumerations" {
    // 50 01 0c || 91 01 (class=object) 91 20 (code=32 unknown-property)
    const wire = [_]u8{ 0x50, 0x01, 0x0C, 0x91, 0x01, 0x91, 0x20 };
    const a = try decode(&wire);
    const e = a.err;
    try testing.expectEqual(@as(u8, 1), e.invoke_id);
    try testing.expectEqual(types.ConfirmedService.read_property, e.service);
    try testing.expectEqual(types.ErrorClass.object, e.class);
    try testing.expectEqual(types.ErrorCode.unknown_property, e.code);
    try testing.expectEqual(@as(usize, 0), e.extra.len);

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(a, &out));

    // Missing the second enumeration.
    try testing.expectError(error.Truncated, decode(&.{ 0x50, 0x01, 0x0C, 0x91, 0x01 }));
    // Not enumerations at all.
    try testing.expectError(error.Truncated, decode(&.{ 0x50, 0x01, 0x0C, 0x21, 0x01, 0x21, 0x20 }));
}

test "max-APDU codes: reserved values are refused, not guessed" {
    try testing.expectEqual(@as(u16, 50), try MaxApdu.up_to_50.octets());
    try testing.expectEqual(@as(u16, 1476), try MaxApdu.up_to_1476.octets());
    for (6..16) |c| {
        const m: MaxApdu = @enumFromInt(@as(u4, @intCast(c)));
        try testing.expectError(error.InvalidValue, m.octets());
    }
    try testing.expectEqual(MaxApdu.up_to_1476, MaxApdu.forOctets(1500));
    try testing.expectEqual(MaxApdu.up_to_480, MaxApdu.forOctets(500));
    try testing.expectEqual(MaxApdu.up_to_50, MaxApdu.forOctets(10));
}

test "every PDU type round-trips through encode/decode" {
    var out: [64]u8 = undefined;
    const cases = [_]Apdu{
        .{ .confirmed_request = .{ .invoke_id = 7, .service = .read_property, .data = &.{ 0x09, 0x01 } } },
        .{ .confirmed_request = .{
            .invoke_id = 7,
            .service = .read_property,
            .max_segments = .sixteen,
            .max_apdu = .up_to_480,
            .segmented_response_accepted = true,
            .segment = .{ .sequence_number = 2, .window_size = 8, .more_follows = true },
            .data = &.{0xAA},
        } },
        .{ .unconfirmed_request = .{ .service = .i_am, .data = &.{0xC4} } },
        .{ .simple_ack = .{ .invoke_id = 3, .service = .write_property } },
        .{ .complex_ack = .{ .invoke_id = 3, .service = .read_property, .data = &.{0x0C} } },
        .{ .complex_ack = .{
            .invoke_id = 3,
            .service = .read_property_multiple,
            .segment = .{ .sequence_number = 1, .window_size = 4, .more_follows = false },
            .data = &.{0x0C},
        } },
        .{ .segment_ack = .{ .invoke_id = 3, .sequence_number = 1, .actual_window_size = 4, .negative = true, .server = true } },
        .{ .err = .{ .invoke_id = 3, .service = .write_property, .class = .property, .code = .write_access_denied } },
        .{ .reject = .{ .invoke_id = 3, .reason = .invalid_tag } },
        .{ .abort = .{ .invoke_id = 3, .reason = .segmentation_not_supported, .server = true } },
    };
    for (cases) |c| {
        const wire = try encode(c, &out);
        const back = try decode(wire);
        try testing.expectEqual(c.pduType(), back.pduType());
        try testing.expectEqual(c.invokeId(), back.invokeId());
        try testing.expectEqual(c.isSegmented(), back.isSegmented());
        var round: [64]u8 = undefined;
        try testing.expectEqualSlices(u8, wire, try encode(back, &round));
    }
}

test "the abort a non-reassembling device owes a segmenting peer" {
    var out: [8]u8 = undefined;
    const wire = try encode(segmentationNotSupported(9, true), &out);
    try testing.expectEqualSlices(u8, &.{ 0x71, 0x09, 0x04 }, wire);
}

test "encode reports NoSpace rather than truncating" {
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.NoSpace, encode(
        .{ .simple_ack = .{ .invoke_id = 1, .service = .read_property } },
        &tiny,
    ));
    var small: [5]u8 = undefined;
    try testing.expectError(error.NoSpace, encode(
        .{ .err = .{ .invoke_id = 1, .service = .read_property, .class = .object, .code = .unknown_object } },
        &small,
    ));
}

test "unknown PDU types and empty buffers" {
    try testing.expectError(error.Truncated, decode(&.{}));
    // Type 8..15 do not exist.
    for (8..16) |t| {
        const b0: u8 = @intCast(t << 4);
        try testing.expectError(error.InvalidPduType, decode(&.{ b0, 0x00, 0x00 }));
    }
}

test "fuzz: APDU decode never panics and round-trips what it accepts" {
    try std.testing.fuzz({}, fuzzApdu, .{});
}

fn fuzzApdu(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];
    const a = decode(input) catch return;
    var out: [256]u8 = undefined;
    const again = encode(a, &out) catch return;
    try testing.expectEqualSlices(u8, input, again);
}
