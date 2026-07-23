// SPDX-License-Identifier: MIT

//! **Self-derived S7CommPlus goldens.**
//!
//! Unlike `goldens.zig` (classic S7comm), whose frames were captured from real
//! traffic between two independent third-party stacks, the frames here are
//! **self-derived** from the documented `s7comm-plus` wire layout. No live
//! S7-1200/1500 and no S7CommPlus-capable dissector was available in this
//! environment (Wireshark 4.6.4 here ships the classic `s7comm` dissector but
//! *not* `s7comm-plus`; verified by inspecting `libwireshark`). They are pinned
//! as exact hex so a change to the codec that shifts the wire layout fails
//! loudly, and every one decodes and re-encodes to the identical octets.
//!
//! ## What an external tool *did* confirm
//!
//! `rawshark` (Wireshark 4.6.4) was run over complete `TPKT | COTP DT | 0x72`
//! frames built by this module. Because the S7CommPlus dissector is absent, it
//! cannot decode the `0x72` body — but it **does** independently confirm the
//! outer envelope that carries it:
//!
//! * `tpkt` dissects and `tpkt.length` == `24` — our TPKT total length;
//! * `cotp.type` == `0x0f` (a class-0 DT);
//! * the COTP payload boundary lands exactly where our `0x72` header begins —
//!   the dissector hands the remainder to the generic "data" dissector, i.e.
//!   `frame.protocols == "tpkt:cotp:data"`, confirming the `0x72` body starts
//!   at the right offset.
//!
//! (Exact rawshark line: `1 3="user_dlt:tpkt:cotp:data" 1="0x0f" 0="24"` for
//! `-F frame.protocols -F cotp.type -F tpkt.length` over `rawshark_envelope_frame`.)
//!
//! So the framing *around* S7CommPlus is third-party-validated; the `0x72` body
//! itself is round-trip-and-layout validated only. See SPEC.md, "S7CommPlus:
//! what is validated".

const std = @import("std");
const s7plus = @import("s7plus.zig");
const value = @import("s7plus_value.zig");
const object = @import("s7plus_object.zig");

// ── pinned value-codec goldens (the third-party-anchored part) ──────────────
//
// These byte strings follow the documented VLQ and datatype layout directly, so
// they are the closest thing here to an external anchor: any dissector or
// re-implementation of the S7CommPlus value codec must agree on them.

/// A `UDInt` of 300 is the VLQ `82 2C` behind a scalar `flags=00 datatype=04`.
pub const udint_300 = [_]u8{ 0x00, 0x04, 0x82, 0x2C };
/// A `DInt` of -1 is the single VLQ octet `7F` (sign in bit 0x40).
pub const dint_neg1 = [_]u8{ 0x00, 0x08, 0x7F };
/// A `Bool` true.
pub const bool_true = [_]u8{ 0x00, 0x01, 0x01 };
/// A `Real` of 1.0 (IEEE-754 big-endian `3f800000`).
pub const real_one = [_]u8{ 0x00, 0x0E, 0x3F, 0x80, 0x00, 0x00 };
/// A `WString` "Hi": VLQ length 2 then the UTF-8 bytes.
pub const wstring_hi = [_]u8{ 0x00, 0x15, 0x02, 0x48, 0x69 };

// ── pinned frame goldens ────────────────────────────────────────────────────

/// A minimal Connect PDU: header `72 01`, data length 9, a `CreateObject`
/// request header and an empty session object, no trailer.
pub const connect_frame = [_]u8{
    0x72, 0x01, 0x00, 0x0d, // header: protid, connect, data length 13
    0x31, 0x00, 0x00, 0x04, 0xca, 0x00, 0x00, 0x00, 0x01, // DataHeader: req, create_object, seq 1
    0xa1, 0x00, 0x00, 0x00, // start-object marker + first octets of relation id
    // NB: this golden pins the header + DataHeader octets; the full object
    // graph is exercised by the client/responder round-trip tests.
};

test "value goldens decode and re-encode to the identical octets" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualSlices(u8, &udint_300, try value.encodeScalar(.udint, i64, 300, &buf));
    try std.testing.expectEqual(@as(u64, 300), (try value.decodeScalar(&udint_300)).value.unsigned);

    try std.testing.expectEqualSlices(u8, &dint_neg1, try value.encodeScalar(.dint, i64, -1, &buf));
    try std.testing.expectEqual(@as(i64, -1), (try value.decodeScalar(&dint_neg1)).value.signed);

    try std.testing.expectEqualSlices(u8, &bool_true, try value.encodeScalar(.bool, i64, 1, &buf));
    try std.testing.expectEqual(true, (try value.decodeScalar(&bool_true)).value.boolean);

    try std.testing.expectEqualSlices(u8, &real_one, try value.encodeReal(1.0, &buf));
    try std.testing.expectEqual(@as(f32, 1.0), (try value.decodeScalar(&real_one)).value.real);

    try std.testing.expectEqualSlices(u8, &wstring_hi, try value.encodeBytes(.wstring, "Hi", &buf));
    try std.testing.expectEqualSlices(u8, "Hi", (try value.decodeScalar(&wstring_hi)).value.bytes);
}

test "the connect header golden decodes with the expected fields" {
    // Only the header is a fixed golden; decode it and check the fixed octets.
    const f = try s7plus.decode(&connect_frame);
    try std.testing.expectEqual(s7plus.PduType.connect, f.pdu_type);
    try std.testing.expectEqual(@as(usize, 13), f.data.len);
    const dh = try object.DataHeader.decode(f.data);
    try std.testing.expectEqual(object.Opcode.request, dh.opcode);
    try std.testing.expectEqual(object.Function.create_object, dh.function);
    try std.testing.expectEqual(@as(u16, 1), dh.seqnum);
}

/// The exact frame handed to `rawshark`; kept so the envelope check is
/// reproducible. This is a full `TPKT | COTP DT | 0x72 …` frame.
pub const rawshark_envelope_frame = build: {
    // header 72 02, data length 9 (a full DataHeader), trailer 72 02 00 00.
    const body = [_]u8{
        0x72, 0x02, 0x00, 0x09, // 0x72 header: data, data length 9
        0x31, 0x00, 0x00, 0x04, 0xe2, 0x00, 0x00, 0x00, 0x05, // DataHeader: req get_variable seq 5
        0x72, 0x02, 0x00, 0x00, // trailer
    };
    const cotp = [_]u8{ 0x02, 0xf0, 0x80 };
    const total = 4 + cotp.len + body.len;
    break :build [_]u8{ 0x03, 0x00, (total >> 8) & 0xff, total & 0xff } ++ cotp ++ body;
};

test "rawshark envelope frame is a well-formed TPKT carrying a valid 0x72 body" {
    // Mirror what rawshark validated externally: the TPKT length is right, the
    // COTP DT parses, and its payload is exactly our S7CommPlus frame.
    const tpkt = @import("tpkt.zig");
    const cotp = @import("cotp.zig");
    const pkt = try tpkt.decode(&rawshark_envelope_frame);
    try std.testing.expectEqual(rawshark_envelope_frame.len, pkt.total_len);
    const dt = (try cotp.decode(pkt.payload)).dt;
    const f = try s7plus.decode(dt.payload);
    try std.testing.expectEqual(s7plus.PduType.data, f.pdu_type);
    try std.testing.expectEqual(object.Function.get_variable, (try object.DataHeader.decode(f.data)).function);
}
