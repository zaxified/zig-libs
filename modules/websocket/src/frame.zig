// SPDX-License-Identifier: MIT

//! RFC 6455 §5 frame layer: parse and serialize the WebSocket frame wire
//! format. Pure codec — no I/O, no allocation. `parseFrame` is a streaming
//! parser: it never blocks or panics on a truncated buffer, it reports
//! `.need_more` so the caller can read more bytes and retry with a bigger
//! slice (the usual pattern for a caller-owned read buffer fed by any
//! transport). `writeFrame` serializes one frame to a `std.Io.Writer`.
//!
//! ## Wire format (§5.2)
//!
//! ```
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! |     Extended payload length continued, if payload len == 127  |
//! + - - - - - - - - - - - - - - - +-------------------------------+
//! |                               |Masking-key, if MASK set to 1  |
//! +-------------------------------+-------------------------------+
//! | Masking-key (continued)       |          Payload Data         |
//! +--------------------------------- - - - - - - - - - - - - - - -+
//! :                     Payload Data continued ...                :
//! +-----------------------------------------------------------... +
//! ```
//!
//! **Masking (§5.3) is the security-critical bit**: a client→server frame
//! MUST be masked; a server→client frame MUST NOT be masked. `parseFrame`
//! takes the parser's own `Role` and enforces the *inbound* direction of
//! that rule — a server-role parser rejects an unmasked frame
//! (`error.UnmaskedClientFrame`), a client-role parser rejects a masked one
//! (`error.MaskedServerFrame`). Both map to close code 1002 via
//! `closeCode`. `writeFrame` never infers masking — the caller passes
//! `mask_key: ?[4]u8` explicitly (null = send unmasked, non-null = mask
//! with that key), so a server can never accidentally mask and a client
//! can never accidentally send cleartext.

const std = @import("std");

/// Which side of the connection this parser instance is decoding *inbound*
/// frames for — i.e. "we are the server" or "we are the client". Drives the
/// masking-direction check in `parseFrame` (§5.1: a client MUST mask every
/// frame it sends; a server MUST NOT mask any frame it sends).
pub const Role = enum { server, client };

/// The six opcodes RFC 6455 defines (§5.2, §11.8). Values 0x3-0x7 (reserved
/// data) and 0xB-0xF (reserved control) are not representable here —
/// `decodeOpcode` returns `null` for them and the caller rejects the frame.
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,

    /// Control opcodes (§5.5): close/ping/pong. MUST NOT be fragmented and
    /// MUST carry a payload of at most 125 bytes — both enforced by
    /// `parseFrame`.
    pub fn isControl(op: Opcode) bool {
        return switch (op) {
            .close, .ping, .pong => true,
            .continuation, .text, .binary => false,
        };
    }
};

fn decodeOpcode(raw: u4) ?Opcode {
    return switch (raw) {
        0x0 => .continuation,
        0x1 => .text,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xA => .pong,
        else => null,
    };
}

/// Protocol violations `parseFrame` can report. Every variant maps to an
/// RFC 6455 close code via `closeCode` so the caller can fail the
/// connection correctly (§7.1.5/§7.4) without its own switch statement.
pub const FrameError = error{
    /// An RSV bit is set with no extension negotiated to define it (§5.2:
    /// "MUST be 0 unless an extension...defines meanings"). This module
    /// negotiates no extensions (see SPEC.md), so any RSV bit is a
    /// violation. Close 1002.
    ReservedRsvBits,
    /// Opcode 0x3-0x7 or 0xB-0xF (§11.8: reserved for future use). Close
    /// 1002.
    ReservedOpcode,
    /// A 126/127-length frame whose extended length field encodes a value
    /// that the shorter form could have carried (non-minimal encoding), or
    /// whose 64-bit length has the most significant bit set (§5.2 requires
    /// it to be 0). Close 1002.
    InvalidPayloadLength,
    /// A control frame (close/ping/pong) with `FIN` unset — control frames
    /// MUST NOT be fragmented (§5.5). Close 1002.
    FragmentedControlFrame,
    /// A control frame with a payload over 125 bytes (§5.5). Close 1002.
    ControlFrameTooLarge,
    /// This is a server-role parser and the frame's MASK bit is unset
    /// (§5.1: every client-to-server frame MUST be masked). Close 1002.
    UnmaskedClientFrame,
    /// This is a client-role parser and the frame's MASK bit is set (§5.1:
    /// a server MUST NOT mask any frame it sends). Close 1002.
    MaskedServerFrame,
    /// The frame's declared payload length exceeds the caller's
    /// `max_frame_size` bound. Reported as soon as the length is known —
    /// before buffering the (attacker-controlled) payload. Close 1009.
    FrameTooLarge,
};

/// Map a `FrameError` (or the higher-level errors `connection.zig` adds) to
/// the RFC 6455 §7.4.1 close-code it corresponds to, for building the
/// close frame that fails the connection.
pub fn closeCode(err: anyerror) u16 {
    return switch (err) {
        error.FrameTooLarge, error.MessageTooLarge => 1009, // Message Too Big
        error.InvalidUtf8 => 1007, // Invalid frame payload data
        else => 1002, // Protocol error (the default / everything else here)
    };
}

/// One decoded frame. `payload` borrows the input buffer passed to
/// `parseFrame` — if it was masked, the mask has already been removed
/// in-place, so `payload` is always the plaintext application data.
pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    /// Whether the frame was masked on the wire (informational — the
    /// masking-direction rule was already enforced by the time this is
    /// returned; `payload` is always unmasked).
    masked: bool,
    payload: []u8,
    /// Total bytes consumed from the input buffer (header + mask + payload).
    consumed: usize,
};

pub const ParseResult = union(enum) {
    frame: Frame,
    /// `buf` does not yet contain a complete frame; read more bytes and
    /// call again with a longer slice starting at the same offset.
    need_more,
};

/// XOR-mask (or unmask — the operation is its own inverse) `payload`
/// in-place with the 4-byte `key`, cycling the key over the payload
/// (§5.3).
///
/// Word-wise: the key is broadcast to a `u64` (two copies of the 4-byte key
/// back to back), so an 8-byte-aligned run is XORed 8 bytes at a time
/// instead of one byte at a time — this is every frame's one O(payload)
/// operation, on both the parse and write paths. Correct because 8 is a
/// multiple of the 4-byte key period: the key phase at the start of every
/// 8-byte chunk is always `key[0]` again, so chunking never desyncs the
/// cycle. The tail (`payload.len % 8` bytes) falls back to the byte-at-a-time
/// form.
pub fn applyMask(payload: []u8, key: [4]u8) void {
    const key32 = std.mem.readInt(u32, &key, .little);
    const key64: u64 = @as(u64, key32) | (@as(u64, key32) << 32);
    var i: usize = 0;
    while (i + 8 <= payload.len) : (i += 8) {
        const chunk = std.mem.readInt(u64, payload[i..][0..8], .little);
        std.mem.writeInt(u64, payload[i..][0..8], chunk ^ key64, .little);
    }
    while (i < payload.len) : (i += 1) payload[i] ^= key[i % 4];
}

/// Parse one frame from the front of `buf`. `buf` is mutable because a
/// masked payload is unmasked in-place — `Frame.payload` then aliases
/// `buf[header_len..consumed]`. `role` is *this parser's own* role (see
/// `Role`) and enforces the masking direction; `max_frame_size` bounds the
/// payload length, checked as soon as the length prefix is decoded (before
/// any payload bytes need to be present), so an oversized frame is
/// rejected without waiting to buffer it.
pub fn parseFrame(buf: []u8, role: Role, max_frame_size: u64) FrameError!ParseResult {
    if (buf.len < 2) return .need_more;

    const b0 = buf[0];
    const b1 = buf[1];

    const fin = (b0 & 0x80) != 0;
    const rsv_bits = b0 & 0x70;
    if (rsv_bits != 0) return error.ReservedRsvBits;
    const opcode = decodeOpcode(@truncate(b0 & 0x0f)) orelse return error.ReservedOpcode;

    const masked = (b1 & 0x80) != 0;
    switch (role) {
        .server => if (!masked) return error.UnmaskedClientFrame,
        .client => if (masked) return error.MaskedServerFrame,
    }

    const len7 = b1 & 0x7f;
    var header_len: usize = 2;
    var payload_len: u64 = undefined;
    if (len7 <= 125) {
        payload_len = len7;
    } else if (len7 == 126) {
        header_len += 2;
        if (buf.len < header_len) return .need_more;
        payload_len = std.mem.readInt(u16, buf[2..4], .big);
        if (payload_len <= 125) return error.InvalidPayloadLength; // non-minimal encoding
    } else { // len7 == 127
        header_len += 8;
        if (buf.len < header_len) return .need_more;
        payload_len = std.mem.readInt(u64, buf[2..10], .big);
        if (payload_len & (1 << 63) != 0) return error.InvalidPayloadLength; // MSB must be 0 (§5.2)
        if (payload_len <= 0xFFFF) return error.InvalidPayloadLength; // non-minimal encoding
    }

    if (opcode.isControl()) {
        if (!fin) return error.FragmentedControlFrame;
        if (payload_len > 125) return error.ControlFrameTooLarge;
    }
    if (payload_len > max_frame_size) return error.FrameTooLarge;

    var mask_key: [4]u8 = undefined;
    const mask_start = header_len;
    if (masked) {
        header_len += 4;
        if (buf.len < header_len) return .need_more;
        mask_key = buf[mask_start..][0..4].*;
    }

    const total: u64 = @as(u64, header_len) + payload_len;
    if (total > buf.len) return .need_more;
    const total_usize: usize = @intCast(total);

    const payload = buf[header_len..total_usize];
    if (masked) applyMask(payload, mask_key);

    return .{ .frame = .{
        .fin = fin,
        .opcode = opcode,
        .masked = masked,
        .payload = payload,
        .consumed = total_usize,
    } };
}

/// Options for `writeFrame`. `mask_key` is the entire masking decision:
/// null serializes an unmasked frame (server→client), a key serializes a
/// masked one (client→server) — `writeFrame` never decides this itself.
pub const WriteOptions = struct {
    fin: bool = true,
    opcode: Opcode,
    payload: []const u8,
    mask_key: ?[4]u8 = null,
};

/// Serialize one frame to `w`. Asserts the control-frame invariants
/// (`fin == true`, `payload.len <= 125`) with `std.debug.assert` — those
/// are caller (programmer) errors, not wire-input errors, since the
/// caller constructs `opts` itself (contrast `parseFrame`, which validates
/// untrusted bytes and never asserts).
pub fn writeFrame(w: *std.Io.Writer, opts: WriteOptions) std.Io.Writer.Error!void {
    if (opts.opcode.isControl()) {
        std.debug.assert(opts.fin);
        std.debug.assert(opts.payload.len <= 125);
    }

    var b0: u8 = @intFromEnum(opts.opcode);
    if (opts.fin) b0 |= 0x80;
    try w.writeByte(b0);

    const len = opts.payload.len;
    const mask_bit: u8 = if (opts.mask_key != null) 0x80 else 0;
    if (len <= 125) {
        try w.writeByte(mask_bit | @as(u8, @intCast(len)));
    } else if (len <= 0xFFFF) {
        try w.writeByte(mask_bit | 126);
        var lb: [2]u8 = undefined;
        std.mem.writeInt(u16, &lb, @intCast(len), .big);
        try w.writeAll(&lb);
    } else {
        try w.writeByte(mask_bit | 127);
        var lb: [8]u8 = undefined;
        std.mem.writeInt(u64, &lb, @intCast(len), .big);
        try w.writeAll(&lb);
    }

    if (opts.mask_key) |key| {
        try w.writeAll(&key);
        // Mask through a small stack buffer so `opts.payload` (const) is
        // never mutated and no allocation is needed. `tmp.len` (512) is a
        // multiple of 4 (the key period), so the key phase at the start of
        // every chunk is `key[0]` again — each chunk can go through the
        // shared `applyMask` (which always starts a fresh mask at `key[0]`)
        // and still reproduce exactly the single-call-over-the-whole-payload
        // result, instead of re-implementing the masking loop here.
        var tmp: [512]u8 = undefined;
        var i: usize = 0;
        while (i < len) {
            const n = @min(tmp.len, len - i);
            @memcpy(tmp[0..n], opts.payload[i..][0..n]);
            applyMask(tmp[0..n], key);
            try w.writeAll(tmp[0..n]);
            i += n;
        }
    } else {
        try w.writeAll(opts.payload);
    }
}

/// Build a convenience unmasked-or-masked pong reply for a received ping —
/// §5.5.3: "A Pong frame sent in response to a Ping frame must have
/// identical 'Application data' as found in the message body of the Ping
/// frame being replied to." Caller still supplies `mask_key` (server:
/// null, client: a fresh key).
pub fn pongFor(ping_payload: []const u8, mask_key: ?[4]u8) WriteOptions {
    return .{ .opcode = .pong, .payload = ping_payload, .mask_key = mask_key };
}

/// Encode a close-frame body (§5.5.1): an optional 2-byte big-endian status
/// code followed by a UTF-8 reason. `out` must be at least
/// `2 + reason.len`. Returns `error.ReasonTooLong` if `2 + reason.len` would
/// exceed the control-frame payload cap (125 bytes, §5.5).
pub fn encodeCloseBody(out: []u8, code: ?u16, reason: []const u8) error{ ReasonTooLong, BufferTooSmall }![]u8 {
    if (code == null) {
        if (reason.len != 0) return error.ReasonTooLong; // a reason needs a code to attach to
        return out[0..0];
    }
    if (2 + reason.len > 125) return error.ReasonTooLong;
    if (out.len < 2 + reason.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], code.?, .big);
    @memcpy(out[2..][0..reason.len], reason);
    return out[0 .. 2 + reason.len];
}

pub const CloseInfo = struct { code: ?u16, reason: []const u8 };

/// Decode a close-frame payload (§5.5.1). Empty payload → `.{ .code =
/// null, .reason = "" }`. A 1-byte payload is malformed (a code, if
/// present, is always 2 bytes) → `error.InvalidPayloadLength`. The reason
/// must be valid UTF-8 → `error.InvalidUtf8`.
pub fn decodeCloseBody(payload: []const u8) (FrameError || error{InvalidUtf8})!CloseInfo {
    if (payload.len == 0) return .{ .code = null, .reason = "" };
    if (payload.len == 1) return error.InvalidPayloadLength;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidUtf8;
    return .{ .code = code, .reason = reason };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// RFC 6455 §5.7 example: a single-frame unmasked text message "Hello".
test "parse: RFC 5.7 unmasked text 'Hello'" {
    var wire = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    const r = try parseFrame(&wire, .client, 1 << 20);
    const f = r.frame;
    try testing.expect(f.fin);
    try testing.expectEqual(Opcode.text, f.opcode);
    try testing.expect(!f.masked);
    try testing.expectEqualStrings("Hello", f.payload);
    try testing.expectEqual(@as(usize, 7), f.consumed);
}

// RFC 6455 §5.7 example: a single-frame masked text message "Hello".
test "parse: RFC 5.7 masked text 'Hello'" {
    var wire = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    const r = try parseFrame(&wire, .server, 1 << 20);
    const f = r.frame;
    try testing.expect(f.fin);
    try testing.expectEqual(Opcode.text, f.opcode);
    try testing.expect(f.masked);
    try testing.expectEqualStrings("Hello", f.payload);
    try testing.expectEqual(@as(usize, 11), f.consumed);
}

// RFC 6455 §5.7 example: fragmented unmasked text message "Hel" + "lo".
test "parse: RFC 5.7 fragmented unmasked 'Hel'+'lo'" {
    var wire1 = [_]u8{ 0x01, 0x03, 0x48, 0x65, 0x6c };
    const r1 = try parseFrame(&wire1, .client, 1 << 20);
    try testing.expect(!r1.frame.fin);
    try testing.expectEqual(Opcode.text, r1.frame.opcode);
    try testing.expectEqualStrings("Hel", r1.frame.payload);

    var wire2 = [_]u8{ 0x80, 0x02, 0x6c, 0x6f };
    const r2 = try parseFrame(&wire2, .client, 1 << 20);
    try testing.expect(r2.frame.fin);
    try testing.expectEqual(Opcode.continuation, r2.frame.opcode);
    try testing.expectEqualStrings("lo", r2.frame.payload);
}

// RFC 6455 §5.7 example: unmasked Ping request with body "Hello".
test "parse: RFC 5.7 unmasked ping 'Hello'" {
    var wire = [_]u8{ 0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    const r = try parseFrame(&wire, .client, 1 << 20);
    try testing.expectEqual(Opcode.ping, r.frame.opcode);
    try testing.expectEqualStrings("Hello", r.frame.payload);
}

// RFC 6455 §5.7 example: unmasked Pong response with body "Hello".
test "parse: RFC 5.7 unmasked pong 'Hello'" {
    var wire = [_]u8{ 0x8a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    const r = try parseFrame(&wire, .client, 1 << 20);
    try testing.expectEqual(Opcode.pong, r.frame.opcode);
    try testing.expectEqualStrings("Hello", r.frame.payload);
}

// RFC 6455 §5.7 example: 256 bytes binary message in a single unmasked frame.
test "parse+write: RFC 5.7 256-byte binary (16-bit length form)" {
    var payload: [256]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var wire: [4 + 256]u8 = undefined;
    wire[0] = 0x82;
    wire[1] = 126;
    std.mem.writeInt(u16, wire[2..4], 256, .big);
    @memcpy(wire[4..], &payload);

    const r = try parseFrame(&wire, .client, 1 << 20);
    try testing.expectEqual(Opcode.binary, r.frame.opcode);
    try testing.expectEqualSlices(u8, &payload, r.frame.payload);
    try testing.expectEqual(@as(usize, wire.len), r.frame.consumed);

    var out_buf: [4 + 256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try writeFrame(&out, .{ .opcode = .binary, .payload = &payload });
    try testing.expectEqualSlices(u8, &wire, out.buffered());
}

// RFC 6455 §5.7 example: 64KiB binary message in a single unmasked frame.
test "parse+write: RFC 5.7 64KiB binary (64-bit length form)" {
    const alloc = testing.allocator;
    const payload = try alloc.alloc(u8, 65536);
    defer alloc.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const wire = try alloc.alloc(u8, 10 + 65536);
    defer alloc.free(wire);
    wire[0] = 0x82;
    wire[1] = 127;
    std.mem.writeInt(u64, wire[2..10], 65536, .big);
    @memcpy(wire[10..], payload);

    const r = try parseFrame(wire, .client, 1 << 20);
    try testing.expectEqual(Opcode.binary, r.frame.opcode);
    try testing.expectEqualSlices(u8, payload, r.frame.payload);
    try testing.expectEqual(@as(usize, wire.len), r.frame.consumed);

    const out_buf = try alloc.alloc(u8, 10 + 65536);
    defer alloc.free(out_buf);
    var out: std.Io.Writer = .fixed(out_buf);
    try writeFrame(&out, .{ .opcode = .binary, .payload = payload });
    try testing.expectEqualSlices(u8, wire, out.buffered());
}

test "write: masked frame matches RFC 5.7 masked 'Hello' vector" {
    var out_buf: [11]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try writeFrame(&out, .{ .opcode = .text, .payload = "Hello", .mask_key = .{ 0x37, 0xfa, 0x21, 0x3d } });
    const expect = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    try testing.expectEqualSlices(u8, &expect, out.buffered());
}

test "parse: NeedMore on truncated header and truncated payload" {
    var one_byte = [_]u8{0x81};
    try testing.expectEqual(ParseResult.need_more, try parseFrame(&one_byte, .client, 1 << 20));

    var short_payload = [_]u8{ 0x81, 0x05, 0x48, 0x65 }; // says len=5, only 2 bytes present
    try testing.expectEqual(ParseResult.need_more, try parseFrame(&short_payload, .client, 1 << 20));

    var short_ext_len = [_]u8{ 0x81, 126, 0x01 }; // 16-bit length form, only 1 of 2 length bytes
    try testing.expectEqual(ParseResult.need_more, try parseFrame(&short_ext_len, .client, 1 << 20));

    var short_mask = [_]u8{ 0x81, 0x85, 0x01, 0x02 }; // masked, only 2 of 4 mask bytes
    try testing.expectEqual(ParseResult.need_more, try parseFrame(&short_mask, .server, 1 << 20));
}

// ── Autobahn-style teeth: constructed adversarial frames ───────────────────

test "parse: unmasked client frame is rejected (close 1002)" {
    var wire = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // no MASK bit
    try testing.expectError(error.UnmaskedClientFrame, parseFrame(&wire, .server, 1 << 20));
    try testing.expectEqual(@as(u16, 1002), closeCode(error.UnmaskedClientFrame));
}

test "parse: masked server frame is rejected (close 1002)" {
    var wire = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    try testing.expectError(error.MaskedServerFrame, parseFrame(&wire, .client, 1 << 20));
}

test "parse: RSV bits set are rejected (close 1002)" {
    var wire = [_]u8{ 0xC1, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // RSV1 set, unmasked (client role: no mask check trip)
    try testing.expectError(error.ReservedRsvBits, parseFrame(&wire, .client, 1 << 20));
}

test "parse: reserved opcode is rejected (close 1002)" {
    var wire = [_]u8{ 0x83, 0x00 }; // opcode 0x3, reserved
    try testing.expectError(error.ReservedOpcode, parseFrame(&wire, .client, 1 << 20));
}

test "parse: oversized frame is rejected (close 1009), before waiting for payload" {
    // The declared length must exceed 125, or the 126 form is a NON-MINIMAL
    // encoding (§5.2) and is rejected earlier as InvalidPayloadLength — which
    // is what this test used to hit, silently, while it was dark: it declared
    // 100 and so never reached the size check it exists to prove.
    var wire = [_]u8{ 0x82, 126, 0x00, 0xC8 }; // declares len=200, no payload bytes present
    try testing.expectError(error.FrameTooLarge, parseFrame(&wire, .client, 50));
    try testing.expectEqual(@as(u16, 1009), closeCode(error.FrameTooLarge));
}

test "parse: fragmented control frame is rejected (close 1002)" {
    var wire = [_]u8{ 0x09, 0x00 }; // ping, FIN unset
    try testing.expectError(error.FragmentedControlFrame, parseFrame(&wire, .client, 1 << 20));
}

test "parse: oversized control frame payload is rejected (close 1002)" {
    var wire = [_]u8{ 0x88, 126, 0x00, 126 }; // close, declares 126-byte payload (>125)
    try testing.expectError(error.ControlFrameTooLarge, parseFrame(&wire, .client, 1 << 20));
}

test "parse: non-minimal 16-bit length encoding is rejected (close 1002)" {
    var wire = [_]u8{ 0x82, 126, 0x00, 0x05, 1, 2, 3, 4, 5 }; // len=5 via the 16-bit form
    try testing.expectError(error.InvalidPayloadLength, parseFrame(&wire, .client, 1 << 20));
}

test "parse: non-minimal 64-bit length encoding is rejected (close 1002)" {
    var wire: [10]u8 = undefined;
    wire[0] = 0x82;
    wire[1] = 127;
    std.mem.writeInt(u64, wire[2..10], 5, .big); // len=5 via the 64-bit form
    try testing.expectError(error.InvalidPayloadLength, parseFrame(&wire, .client, 1 << 20));
}

test "parse: 64-bit length with MSB set is rejected (close 1002)" {
    var wire: [10]u8 = undefined;
    wire[0] = 0x82;
    wire[1] = 127;
    std.mem.writeInt(u64, wire[2..10], 1 << 63, .big);
    try testing.expectError(error.InvalidPayloadLength, parseFrame(&wire, .client, 1 << 62));
}

test "masking round-trip: applyMask is its own inverse" {
    var data = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };
    const orig = data;
    const key: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    applyMask(&data, key);
    try testing.expect(!std.mem.eql(u8, &orig, &data));
    applyMask(&data, key);
    try testing.expectEqualSlices(u8, &orig, &data);
}

// W2-B/websocket-F4: a round trip through `applyMask` alone (mask then
// unmask, or write-then-parse, which both call the same `applyMask`) cannot
// catch a broken word-wise key broadcast — a bug that zeroes the same half
// of the mask on both the masking and unmasking call is still its own
// inverse, so the previous round-trip test above passes either way. This one
// checks against an INDEPENDENT byte-at-a-time computation of §5.3's
// definition instead, on a payload long enough (19 bytes: two full 8-byte
// word chunks plus a 3-byte tail) to actually exercise the word path.
test "applyMask matches an independent byte-at-a-time oracle across the word/tail boundary" {
    var payload: [19]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i * 7 + 3);
    const key: [4]u8 = .{ 0xaa, 0x55, 0x11, 0xf0 };

    var want: [19]u8 = undefined;
    for (&want, 0..) |*b, i| b.* = payload[i] ^ key[i % 4];

    var got = payload;
    applyMask(&got, key);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "positive control: valid masked frame with max control payload (125) is accepted" {
    var payload: [125]u8 = undefined;
    @memset(&payload, 'x');
    var out_buf: [2 + 4 + 125]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try writeFrame(&out, .{ .opcode = .ping, .payload = &payload, .mask_key = .{ 1, 2, 3, 4 } });

    const wire = out.buffered();
    var mutable: [2 + 4 + 125]u8 = undefined;
    @memcpy(&mutable, wire);
    const r = try parseFrame(&mutable, .server, 1 << 20);
    try testing.expectEqual(Opcode.ping, r.frame.opcode);
    try testing.expectEqualSlices(u8, &payload, r.frame.payload);
}

test "encodeCloseBody / decodeCloseBody round-trip" {
    var buf: [125]u8 = undefined;
    const body = try encodeCloseBody(&buf, 1000, "bye");
    const info = try decodeCloseBody(body);
    try testing.expectEqual(@as(?u16, 1000), info.code);
    try testing.expectEqualStrings("bye", info.reason);
}

test "encodeCloseBody: no code, no reason -> empty body" {
    var buf: [4]u8 = undefined;
    const body = try encodeCloseBody(&buf, null, "");
    try testing.expectEqual(@as(usize, 0), body.len);
}

test "decodeCloseBody: 1-byte payload is InvalidPayloadLength" {
    try testing.expectError(error.InvalidPayloadLength, decodeCloseBody(&[_]u8{0x03}));
}

test "decodeCloseBody: invalid UTF-8 reason is rejected" {
    const payload = [_]u8{ 0x03, 0xe8, 0xff, 0xfe }; // code=1000, invalid UTF-8 reason
    try testing.expectError(error.InvalidUtf8, decodeCloseBody(&payload));
}

// ── fuzz: frame parsing off the wire, never panics ──────────────────────────
//
// `parseFrame` is the first thing done with bytes read straight off a
// WebSocket TCP socket — fully attacker-controlled, including the extended
// length fields and the mask key. Drive it as a real reader loop would:
// repeatedly parse-and-advance over a fuzzed buffer, so multi-frame streams
// (and `.need_more` retries) are exercised, not just a single header.

test "fuzz: parseFrame never panics on arbitrary bytes, server role" {
    try testing.fuzz({}, fuzzParseFrameServer, .{});
}

fn fuzzParseFrameServer(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var off: usize = 0;
    var iterations: usize = 0;
    while (off < len and iterations < 64) : (iterations += 1) {
        const result = parseFrame(buf[off..len], .server, 1 << 16) catch return;
        switch (result) {
            .need_more => return,
            .frame => |f| off += f.consumed,
        }
    }
}

test "fuzz: decodeCloseBody never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeCloseBody, .{});
}

fn fuzzDecodeCloseBody(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = decodeCloseBody(buf[0..len]) catch return;
}
