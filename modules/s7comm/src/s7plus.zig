// SPDX-License-Identifier: MIT

//! **S7CommPlus** — the S7-1200 / S7-1500 protocol (protocol id `0x72`).
//!
//! S7CommPlus rides on the *same* ISO-on-TCP stack as classic S7comm — TPKT
//! (`tpkt.zig`) then COTP class 0 (`cotp.zig`) — but everything above the COTP
//! `DT` is a different protocol: not the `0x32` header with area/offset reads,
//! but a `0x72` header wrapping a TLV object graph with a session, a per-PDU
//! sequence number and, on newer firmware, a running integrity value the peer
//! verifies. This module reuses the classic transport layers unchanged and adds
//! the `0x72` world on top.
//!
//! This file owns the **PDU frame**: the four-octet header, the PDU-type set
//! (Connect / Data / Data-with-integrity / Keep-alive), the data length, the
//! optional trailing integrity part, and the trailer — a *second* `0x72` header
//! form that closes a Data PDU. The typed-value codec is in `s7plus_value.zig`,
//! the object / session / function model in `s7plus_object.zig`, the symbolic
//! path parser in `s7plus_path.zig`, and the client / responder in
//! `s7plus_client.zig`.
//!
//! ## Wire layout
//!
//! ```text
//! +--------+--------+-----------------+
//! | 0x72   | pdutyp |   data length   |   header (4 octets)
//! +--------+--------+-----------------+
//! |            data part ...          |   `data length` octets
//! +-----------------------------------+
//! |      integrity part (V3 only)     |   present when pdutype == data_fw3
//! +--------+--------+-----------------+
//! | 0x72   | pdutyp |     0x0000      |   trailer (Data PDUs only)
//! +--------+--------+-----------------+
//! ```
//!
//! **Honesty note.** The header (`0x72`, PDU type, 16-bit data length) is the
//! part cross-checkable against the Wireshark `s7comm-plus` dissector's field
//! layout. The exact placement of the integrity part relative to the trailer,
//! and the trailer's own shape, are **self-derived** from the documented layout
//! — no live S7-1200/1500 and no S7CommPlus-capable Wireshark build was
//! available here (this environment's Wireshark 4.6.4 ships the classic
//! `s7comm` dissector but not `s7comm-plus`). The framing is internally
//! consistent and round-trips exactly; see SPEC.md for what that does and does
//! not prove.

const std = @import("std");

// ── the sibling files that make up the S7CommPlus surface ───────────────────

/// The typed value / datatype TLV codec — the heart of the protocol.
pub const value = @import("s7plus_value.zig");
/// The object model, session/sequence/integrity, and the function set.
pub const object = @import("s7plus_object.zig");
/// The symbolic-address path parser.
pub const path = @import("s7plus_path.zig");
/// The client and responder over the shared `Transport` seam.
pub const client = @import("s7plus_client.zig");
/// Self-derived goldens and the rawshark envelope check.
pub const goldens = @import("s7plus_goldens.zig");

// ── the frame ───────────────────────────────────────────────────────────────

/// The protocol id that distinguishes S7CommPlus from classic S7comm (`0x32`).
pub const protocol_id: u8 = 0x72;
/// Octets in the fixed header.
pub const header_len: usize = 4;
/// Octets in the trailer (a second header form with a zero length).
pub const trailer_len: usize = 4;

pub const Error = error{
    /// Fewer octets than the four-octet header.
    ShortFrame,
    /// The first octet is not `0x72`.
    BadProtocolId,
    /// The PDU-type octet is not one this module models.
    UnknownPduType,
    /// `data length` announces more octets than the frame carries.
    TruncatedData,
    /// A Data PDU did not end in a well-formed trailer.
    BadTrailer,
    /// The integrity region is shorter than the minimum an integrity part needs.
    BadIntegrity,
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// The caller's payload does not fit a 16-bit length.
    PayloadTooLong,
};

/// The PDU type (the dissector's "protocol version" octet). It selects both the
/// role of the frame and whether an integrity part and a trailer are present.
pub const PduType = enum(u8) {
    /// Connection establishment: carries a `CreateObject` for the session. No
    /// trailer, no integrity.
    connect = 0x01,
    /// A request/response/notification with no integrity part. Trailer present.
    data = 0x02,
    /// As `data`, but with a trailing integrity part (firmware that enforces
    /// the anti-replay value — S7-1500 V2+). Trailer present.
    data_fw3 = 0x03,
    /// A keep-alive. No trailer, no integrity.
    keepalive = 0xff,
    _,

    /// Whether a frame of this type is closed by a trailer.
    pub fn hasTrailer(self: PduType) bool {
        return self == .data or self == .data_fw3;
    }
    /// Whether a frame of this type carries a trailing integrity part.
    pub fn hasIntegrity(self: PduType) bool {
        return self == .data_fw3;
    }
};

/// A decoded S7CommPlus frame. `data` is the opcode/function/sequence body that
/// `s7plus_object.zig` parses; `integrity` is the raw trailing integrity part
/// (empty unless the PDU type carries one); `total_len` is what the framer
/// consumed.
pub const Frame = struct {
    pdu_type: PduType,
    data: []const u8,
    integrity: []const u8 = &.{},
    total_len: usize,
};

/// Decodes one S7CommPlus frame from a COTP `DT` payload. Enforces that the
/// announced data length, the (optional) integrity part and the (optional)
/// trailer account for exactly the octets present — a length that disagrees is
/// a typed error, because there is no per-PDU checksum to catch it later.
pub fn decode(bytes: []const u8) Error!Frame {
    if (bytes.len < header_len) return error.ShortFrame;
    if (bytes[0] != protocol_id) return error.BadProtocolId;
    const pt: PduType = @enumFromInt(bytes[1]);
    switch (pt) {
        .connect, .data, .data_fw3, .keepalive => {},
        _ => return error.UnknownPduType,
    }
    const data_len: usize = (@as(usize, bytes[2]) << 8) | bytes[3];
    if (header_len + data_len > bytes.len) return error.TruncatedData;
    const data = bytes[header_len..][0..data_len];

    var rest = bytes[header_len + data_len ..];
    var integrity: []const u8 = &.{};

    if (pt.hasTrailer()) {
        if (rest.len < trailer_len) return error.BadTrailer;
        // The trailer is the last four octets; anything between the data and it
        // is the integrity part.
        const trailer = rest[rest.len - trailer_len ..];
        if (trailer[0] != protocol_id or trailer[1] != @intFromEnum(pt) or
            trailer[2] != 0 or trailer[3] != 0) return error.BadTrailer;
        integrity = rest[0 .. rest.len - trailer_len];
        if (pt.hasIntegrity()) {
            // A V3 integrity part is at least a one-octet VLQ id.
            if (integrity.len < 1) return error.BadIntegrity;
        } else {
            // A plain Data PDU has no integrity region.
            if (integrity.len != 0) return error.BadTrailer;
        }
        rest = &.{};
    } else {
        // Connect / keep-alive: no trailer, and nothing may trail the data.
        if (rest.len != 0) return error.BadTrailer;
    }

    return .{
        .pdu_type = pt,
        .data = data,
        .integrity = integrity,
        .total_len = bytes.len - rest.len,
    };
}

/// Builds a frame into `out`. `data` is the object/function body; `integrity`
/// is the trailing integrity part (must be empty unless `pdu_type` carries
/// one). Returns the written slice.
pub fn encode(pdu_type: PduType, data: []const u8, integrity: []const u8, out: []u8) Error![]u8 {
    if (data.len > std.math.maxInt(u16)) return error.PayloadTooLong;
    if (!pdu_type.hasIntegrity() and integrity.len != 0) return error.BadIntegrity;
    if (pdu_type.hasIntegrity() and integrity.len == 0) return error.BadIntegrity;

    var need = header_len + data.len;
    if (pdu_type.hasTrailer()) need += integrity.len + trailer_len;
    if (out.len < need) return error.BufferTooSmall;

    out[0] = protocol_id;
    out[1] = @intFromEnum(pdu_type);
    out[2] = @intCast((data.len >> 8) & 0xff);
    out[3] = @intCast(data.len & 0xff);
    var w: usize = header_len;
    @memcpy(out[w..][0..data.len], data);
    w += data.len;
    if (pdu_type.hasTrailer()) {
        @memcpy(out[w..][0..integrity.len], integrity);
        w += integrity.len;
        out[w] = protocol_id;
        out[w + 1] = @intFromEnum(pdu_type);
        out[w + 2] = 0;
        out[w + 3] = 0;
        w += trailer_len;
    }
    return out[0..w];
}

// ── dark-tests aggregator: pull every sibling's tests into the binary ───────

test {
    _ = value;
    _ = object;
    _ = path;
    _ = client;
    _ = goldens;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "connect frame round trips with no trailer" {
    const data = [_]u8{ 0x31, 0x00, 0x00, 0x04, 0xca, 0x00, 0x00, 0x00, 0x01 };
    var buf: [64]u8 = undefined;
    const enc = try encode(.connect, &data, &.{}, &buf);
    // header(4) + data(9), no trailer.
    try testing.expectEqual(@as(usize, 13), enc.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x72, 0x01, 0x00, 0x09 }, enc[0..4]);
    const dec = try decode(enc);
    try testing.expectEqual(PduType.connect, dec.pdu_type);
    try testing.expectEqualSlices(u8, &data, dec.data);
    try testing.expectEqual(@as(usize, 0), dec.integrity.len);
    try testing.expectEqual(enc.len, dec.total_len);
}

test "data frame carries a trailer and round trips" {
    const data = [_]u8{ 0x32, 0x00, 0x00, 0x04, 0xf2, 0x00, 0x03 };
    var buf: [64]u8 = undefined;
    const enc = try encode(.data, &data, &.{}, &buf);
    // header(4) + data(7) + trailer(4).
    try testing.expectEqual(@as(usize, 15), enc.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x72, 0x02, 0x00, 0x00 }, enc[enc.len - 4 ..]);
    const dec = try decode(enc);
    try testing.expectEqual(PduType.data, dec.pdu_type);
    try testing.expectEqualSlices(u8, &data, dec.data);
    try testing.expectEqual(enc.len, dec.total_len);
}

test "a V3 data frame keeps the integrity part between data and trailer" {
    const data = [_]u8{ 0x32, 0x00, 0x00, 0x04, 0xe2, 0x00, 0x05 };
    const integ = [_]u8{ 0x2A, 0x11, 0x22, 0x33 }; // id VLQ + a short digest
    var buf: [64]u8 = undefined;
    const enc = try encode(.data_fw3, &data, &integ, &buf);
    const dec = try decode(enc);
    try testing.expectEqual(PduType.data_fw3, dec.pdu_type);
    try testing.expectEqualSlices(u8, &data, dec.data);
    try testing.expectEqualSlices(u8, &integ, dec.integrity);
    try testing.expectEqual(enc.len, dec.total_len);
}

test "keep-alive has neither integrity nor trailer" {
    const data = [_]u8{ 0x00, 0x00 };
    var buf: [16]u8 = undefined;
    const enc = try encode(.keepalive, &data, &.{}, &buf);
    try testing.expectEqual(@as(usize, 6), enc.len);
    const dec = try decode(enc);
    try testing.expectEqual(PduType.keepalive, dec.pdu_type);
}

test "decode rejects malformed frames" {
    // Too short.
    try testing.expectError(error.ShortFrame, decode(&[_]u8{ 0x72, 0x02, 0x00 }));
    // Wrong protocol id (a classic 0x32 frame must not decode here).
    try testing.expectError(error.BadProtocolId, decode(&[_]u8{ 0x32, 0x01, 0x00, 0x00 }));
    // Unknown PDU type.
    try testing.expectError(error.UnknownPduType, decode(&[_]u8{ 0x72, 0x55, 0x00, 0x00 }));
    // Data length runs past the buffer.
    try testing.expectError(error.TruncatedData, decode(&[_]u8{ 0x72, 0x01, 0x00, 0x40, 0x00 }));
    // A Data PDU without a valid trailer.
    var bad = [_]u8{ 0x72, 0x02, 0x00, 0x02, 0xAA, 0xBB, 0x72, 0x02, 0x00, 0x01 };
    try testing.expectError(error.BadTrailer, decode(&bad));
    // A trailer whose protocol id is wrong.
    bad = [_]u8{ 0x72, 0x02, 0x00, 0x02, 0xAA, 0xBB, 0x99, 0x02, 0x00, 0x00 };
    try testing.expectError(error.BadTrailer, decode(&bad));
    // A plain Data PDU with unexpected bytes where the integrity would be.
    const stray = [_]u8{ 0x72, 0x02, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0x72, 0x02, 0x00, 0x00 };
    try testing.expectError(error.BadTrailer, decode(&stray));
}

test "encode refuses an integrity part on a type that has none" {
    var buf: [16]u8 = undefined;
    try testing.expectError(error.BadIntegrity, encode(.data, &[_]u8{0x01}, &[_]u8{0x02}, &buf));
    try testing.expectError(error.BadIntegrity, encode(.data_fw3, &[_]u8{0x01}, &.{}, &buf));
}

test "fuzz: frame decode never panics" {
    try std.testing.fuzz({}, fuzzFrame, .{});
}

fn fuzzFrame(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const f = decode(buf[0..len]) catch return;
    try testing.expect(f.total_len <= len);
    try testing.expect(f.data.len <= len);
}
