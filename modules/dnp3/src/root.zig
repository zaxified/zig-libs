// SPDX-License-Identifier: MIT

//! dnp3 — pure-Zig DNP3 (IEEE 1815-2012): Data Link Layer, Transport
//! Function and Application Layer framing plus the object library as pure
//! codecs, and a complete **outstation** built on top of them.
//!
//! Implemented (this module):
//! - **Data Link Layer** (`link`, §9): the 0x0564 fixed frame, the control
//!   octet (DIR/PRM/FCB/FCV + 4-bit function code), 16-bit dest/src
//!   addresses, and the DNP3 CRC-16 (poly 0x3D65) over the header block and
//!   each <=16-byte data block.
//! - **Transport Function** (`transport`, §8): the transport octet
//!   (FIN/FIR + 6-bit sequence), fragment segmentation and reassembly.
//! - **Application Layer** (`application`, §4/§5): the application control
//!   octet (FIR/FIN/CON/UNS + 4-bit sequence), function codes, and the
//!   2-byte Internal Indications (IIN) bitfield in responses.
//! - **Object header + core object library** (`objects`, §4.4/§4.5 + Part
//!   4/5): qualifier/range framing (start-stop, count, count+index-prefix)
//!   and static objects for binary input (g1), binary output status/CROB
//!   (g10/g12), binary counter (g20), analog input (g30), analog output
//!   status/block (g40/g41), time-and-date (g50), and class-data read
//!   markers (g60).
//! - **Object records** (`records`): a table-driven codec for the ~40
//!   group/variation pairs an outstation emits — binary (g1/g2), double-bit
//!   binary (g3/g4), binary output status (g10/g11), counter (g20/g22),
//!   frozen counter (g21/g23), analog input (g30/g32) and analog output
//!   status (g40/g42), in the with-flags / without-flags / 16-bit / 32-bit /
//!   float / absolute-time / relative-time shapes plus the packed forms.
//! - **Outstation** (`outstation`): a stateful responder over a caller-owned
//!   point database — READ (class polls and specific reads), WRITE,
//!   SELECT/OPERATE/DIRECT_OPERATE with a select-before-operate timer,
//!   restart, delay measure, unsolicited enable/disable, freeze, assign
//!   class and CONFIRM; IIN bits; a bounded event buffer with a
//!   confirm/retire cycle; and multi-fragment responses with correct
//!   FIR/FIN/SEQ. `outstation.Session` wires it to the transport function
//!   and the data-link layer. No threads, no owned timers, no allocation:
//!   every deadline comes from an injected clock.
//!
//! - **Secure Authentication, SAv2 symmetric core** (`sa`, §7 / IEC 62351-5,
//!   object group 120): AES Key Wrap (RFC 3394), the SA MAC-algorithm
//!   registry (HMAC-SHA-1/SHA-256 truncated, AES-GMAC), the g120 v1/v2/v3/v4/
//!   v5/v6/v7/v9 message codecs, the challenge-response MAC-input construction,
//!   and session-key wrap/unwrap + CSQ/KSQ/expiry state helpers. The SAv5/SAv6
//!   asymmetric update-key change (g120 v8/v10–v15: RSA/DSA + certificates) is
//!   out of scope — see `sa.zig`'s module doc comment for exactly what is
//!   implemented and validated against what.
//!
//! Both master (build request / parse response) and outstation (parse
//! request / build response) roles are supported symmetrically: every
//! encode/decode function here is a pure function over byte slices, used by
//! whichever side is sending or receiving — the same "both directions are
//! pure functions, golden-byte tested offline" shape as the `wireguard` and
//! `modbus` sibling modules. There is no stateful `Master`/`Outstation`
//! session type in this base pass (no confirm/retry timers, no unsolicited
//! response state machine) — that belongs to a future pass built on top of
//! these codecs.
//!
//! Deliberately out of scope for this pass (see README "Scope"): event
//! object variations (g2/g11/g22/g32/g42 etc.), file transfer, data sets,
//! unsolicited-response confirmation/retry state machines, and any actual
//! transport (TCP/serial) I/O — this module is wire codec + pure
//! segmentation/reassembly only; the caller wires it to whatever transport
//! it likes.
//!
//! Provenance: clean-room from IEEE 1815-2012 (DNP3); structure and
//! behavior cross-referenced against opendnp3 (Apache-2.0) and public DNP3
//! primers — no source consulted or copied. The CRC-16 is independently
//! verified against the reveng CRC-catalogue "CRC-16/DNP" parameters,
//! cross-checked with a from-scratch bit-serial reference implementation
//! (see SPEC.md "CRC verification").

const std = @import("std");

pub const meta = .{
    .platform = .any,
    // master = the pure codecs (build request / parse response);
    // outstation = a real stateful responder in `outstation.zig`.
    .role = .both,
    // The codecs are reentrant (no shared state, every type caller-owned);
    // `Outstation`/`Session` hold session state and are single-owner.
    .concurrency = .reentrant,
    .model_after = "IEEE 1815-2012 (DNP3); structure ref opendnp3 (Apache-2.0) -- behavioral only, no source copied",
    .deps = .{},
};

/// The Data Link Layer (§9): frame codec + CRC-16.
pub const link = @import("link.zig");
/// The Transport Function (§8): segmentation + reassembly.
pub const transport = @import("transport.zig");
/// The Application Layer (§4/§5): header, function codes, IIN.
pub const application = @import("application.zig");
/// Object-header framing + the core static object library.
pub const objects = @import("objects.zig");
/// SCAFFOLD ONLY -- Secure Authentication (g120) hook. See its doc comment.
pub const sa = @import("sa.zig");
/// Table-driven codec for every static and event object variation the
/// outstation speaks (the object records that follow an object header).
pub const records = @import("records.zig");
/// The outstation (slave) role: a pure request-fragment-to-response-fragment
/// responder over a caller-owned point database, plus a `Session` that wires
/// it to the link and transport layers.
pub const outstation = @import("outstation.zig");
/// Byte-exact wire goldens for both roles, including frames captured from a
/// live opendnp3 master driving `outstation.Outstation`.
pub const goldens = @import("goldens.zig");

// Pull the submodules' tests into this module's test binary -- a bare
// re-export does NOT drag in the imported file's `test` blocks (the
// dark-tests rule; see CONVENTIONS.md §6.3).
test {
    _ = link;
    _ = transport;
    _ = application;
    _ = objects;
    _ = sa;
    _ = records;
    _ = outstation;
    _ = goldens;
}

// ── full-stack integration: link + transport together ───────────────────────

pub const SendError = link.EncodeError;

/// Segments `app_fragment` via the transport function and wraps each
/// segment in a data-link frame addressed `dest`/`src`, writing the
/// concatenated frame bytes into `out`. This is the whole "send" path: an
/// application fragment in, a byte stream of one-or-more link frames out,
/// ready to hand to any transport (serial, TCP, a test harness).
pub fn sendFragment(control: link.Control, dest: u16, src: u16, app_fragment: []const u8, out: []u8) SendError![]u8 {
    var seg = transport.Segmenter.init(app_fragment);
    var seg_buf: [1 + transport.max_segment_payload]u8 = undefined;
    var pos: usize = 0;
    while (seg.next(&seg_buf)) |segment| {
        const frame = try link.encodeFrame(control, dest, src, segment, out[pos..]);
        pos += frame.len;
    }
    return out[0..pos];
}

pub const RecvError = link.DecodeError || transport.ReassembleError;

/// The receive-side counterpart to `sendFragment`: feed it link frames one
/// at a time (in arrival order) and it reassembles the original application
/// fragment.
pub const FrameReceiver = struct {
    reassembler: transport.Reassembler,

    pub fn init(buf: []u8) FrameReceiver {
        return .{ .reassembler = transport.Reassembler.init(buf) };
    }

    /// Feeds one link frame's raw bytes (as decoded off the wire).
    /// `user_data_scratch` is a caller-owned scratch buffer the frame's
    /// user data is decoded into before being fed to the transport
    /// reassembler. Returns the complete application fragment once the
    /// FIN segment arrives, `null` while more segments are still expected.
    pub fn feedFrame(self: *FrameReceiver, frame_bytes: []const u8, user_data_scratch: []u8) RecvError!?[]const u8 {
        const decoded = try link.decodeFrame(frame_bytes, user_data_scratch);
        return self.reassembler.feed(user_data_scratch[0..decoded.user_data_len]);
    }
};

// ── tests: full stack round-trips ────────────────────────────────────────────

const testing = std.testing;

test "full stack round-trip: link -> transport -> app, single frame" {
    // Master builds a READ-class-0 request as the application fragment.
    var app_out: [16]u8 = undefined;
    const app_fragment = try application.buildRequest(3, .read, objects.g60.readClassHeader(.class0), &app_out);

    const control = link.Control{ .dir = true, .prm = true, .fcv_or_dfc = true, .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data) };
    var wire: [64]u8 = undefined;
    const wire_bytes = try sendFragment(control, 1024, 1, app_fragment, &wire);

    // "Receive" side: it's one frame (fragment fits in one segment).
    var reasm_buf: [64]u8 = undefined;
    var receiver = FrameReceiver.init(&reasm_buf);
    var scratch: [64]u8 = undefined;
    const result = try receiver.feedFrame(wire_bytes, &scratch);
    try testing.expect(result != null);
    try testing.expectEqualSlices(u8, app_fragment, result.?);

    // Outstation now parses the reassembled application fragment.
    const decoded = try application.decodeRequestHeader(result.?);
    try testing.expectEqual(application.FunctionCode.read, decoded.header.function);
    const obj = try objects.decodeObjectHeader(decoded.rest);
    try testing.expectEqual(@as(u8, 60), obj.header.group);
    try testing.expectEqual(@as(u8, 1), obj.header.variation); // class0
}

test "full stack round-trip: multi-frame application fragment (>250 bytes)" {
    // A big application fragment (bigger than one link frame's user data
    // limit) forces the transport function to segment across multiple
    // link frames, and the link layer to further split each segment across
    // multiple 16-byte CRC blocks.
    var app_fragment: [600]u8 = undefined;
    for (&app_fragment, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 256);

    const control = link.Control{ .dir = false, .prm = true, .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data) };
    var wire: [link.maxFrameLen(transport.max_segment_payload + 1) * 4]u8 = undefined;
    const wire_bytes = try sendFragment(control, 2, 3, &app_fragment, &wire);

    // Walk the concatenated frames one at a time, exactly as a receiver
    // reading a byte stream would: peek the length octet to know how much
    // of this frame to hand to decodeFrame.
    var reasm_buf: [600]u8 = undefined;
    var receiver = FrameReceiver.init(&reasm_buf);
    var scratch: [300]u8 = undefined;
    var offset: usize = 0;
    var result: ?[]const u8 = null;
    var frames_seen: usize = 0;
    while (offset < wire_bytes.len) {
        const length_octet = wire_bytes[offset + 2];
        const user_len: usize = @as(usize, length_octet) - 5;
        const blocks = if (user_len == 0) 0 else std.math.divCeil(usize, user_len, link.max_block_len) catch unreachable;
        const frame_len = link.header_frame_len + user_len + blocks * link.crc_len;
        const frame = wire_bytes[offset..][0..frame_len];

        result = try receiver.feedFrame(frame, &scratch);
        frames_seen += 1;
        offset += frame_len;
    }
    try testing.expectEqual(wire_bytes.len, offset);
    try testing.expect(frames_seen > 1); // actually forced multi-frame segmentation
    try testing.expect(result != null);
    try testing.expectEqualSlices(u8, &app_fragment, result.?);
}

test "master builds READ, outstation parses it; outstation builds RESPONSE, master parses it" {
    // Master side: build a READ request for Analog Input (g30v1), points 0-3.
    var req_out: [16]u8 = undefined;
    const req = try application.buildRequest(1, .read, .{
        .group = 30,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 3 } },
    }, &req_out);

    var frame_out: [64]u8 = undefined;
    const req_control = link.Control{ .dir = true, .prm = true, .fcv_or_dfc = true, .function = @intFromEnum(link.PrimaryFunction.unconfirmed_user_data) };
    const req_frame = try link.encodeFrame(req_control, 1024, 1, req, &frame_out);

    // Outstation side: decode the frame, then the application request.
    var user_buf: [32]u8 = undefined;
    const decoded_frame = try link.decodeFrame(req_frame, &user_buf);
    const req_decoded = try application.decodeRequestHeader(user_buf[0..decoded_frame.user_data_len]);
    try testing.expectEqual(application.FunctionCode.read, req_decoded.header.function);
    const obj_req = try objects.decodeObjectHeader(req_decoded.rest);
    try testing.expectEqual(@as(u8, 30), obj_req.header.group);
    try testing.expectEqual(@as(u32, 4), obj_req.header.range.objectCount().?);

    // Outstation builds a RESPONSE carrying 4 g30v1 analog inputs.
    var resp_buf: [64]u8 = undefined;
    const resp_hdr = try application.encodeResponseHeader(.{
        .control = .{ .fir = true, .fin = true, .seq = 1 },
        .function = .response,
        .iin = .{},
    }, &resp_buf);
    var pos = resp_hdr.len;
    const obj_hdr_bytes = try objects.encodeObjectHeader(.{
        .group = 30,
        .variation = 1,
        .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
        .range = .{ .start_stop = .{ .start = 0, .stop = 3 } },
    }, resp_buf[pos..]);
    pos += obj_hdr_bytes.len;
    const values = [_]i32{ 100, -50, 0, 12345 };
    for (values) |v| {
        const rec = try (objects.g30.V1{ .flags = .{ .online = true }, .value = v }).encode(resp_buf[pos..]);
        pos += rec.len;
    }
    const resp_fragment = resp_buf[0..pos];

    // Master side: decode the response.
    const resp_decoded = try application.decodeResponseHeader(resp_fragment);
    try testing.expectEqual(application.FunctionCode.response, resp_decoded.header.function);
    var rest = resp_decoded.rest;
    const obj_resp = try objects.decodeObjectHeader(rest);
    rest = rest[obj_resp.consumed..];
    try testing.expectEqual(@as(u32, 4), obj_resp.header.range.objectCount().?);
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const point = try objects.g30.V1.decode(rest[i * objects.g30.V1.wire_len ..]);
        try testing.expectEqual(values[i], point.value);
        try testing.expect(point.flags.online);
    }
}
