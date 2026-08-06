// SPDX-License-Identifier: MIT

//! A small per-connection state machine on top of `frame`: reassembles a
//! fragmented message (§5.4), tracks the close handshake (§7.1.1/§5.5.1),
//! and enforces an aggregate max-message-size cap (§5.4 doesn't bound
//! this — a fragmented message can otherwise grow unboundedly even with
//! every individual frame under `max_frame_size`).
//!
//! `Connection` owns no I/O: `receive` is fed the caller's read buffer
//! (same streaming `.need_more` contract as `frame.parseFrame`) and
//! returns an `Event` describing what happened; writing replies (pong,
//! close) is the caller's job via `frame.writeFrame` — `frame.pongFor`
//! and `frame.encodeCloseBody` are the matching helpers.

const std = @import("std");
const frame = @import("frame.zig");

pub const Connection = struct {
    role: frame.Role,
    /// Per-frame payload cap, forwarded to `frame.parseFrame` (close 1009).
    max_frame_size: u64,
    /// Reassembly scratch space, caller-owned. Its length *is* the
    /// aggregate max-message-size cap: a fragmented (or oversized single-
    /// frame) message that would not fit triggers `error.MessageTooLarge`
    /// (close 1009).
    message_buf: []u8,
    message_len: usize = 0,
    /// Non-null while a fragmented text/binary message is in progress —
    /// the opcode of the frame that started it (continuation frames don't
    /// carry it). Control frames may still interleave freely while this
    /// is set (§5.4): `receive` dispatches control opcodes before
    /// touching fragmentation state.
    fragment_opcode: ?frame.Opcode = null,
    /// This side has sent a close frame.
    close_sent: bool = false,
    /// This side has received a close frame.
    close_received: bool = false,

    pub fn init(role: frame.Role, message_buf: []u8, max_frame_size: u64) Connection {
        return .{ .role = role, .max_frame_size = max_frame_size, .message_buf = message_buf };
    }

    pub const Message = struct { opcode: frame.Opcode, payload: []const u8 };

    pub const Event = union(enum) {
        /// `buf` did not contain a complete frame; read more and retry.
        need_more,
        /// A non-final fragment was consumed; no message is ready yet.
        frame_consumed,
        /// A complete text or binary message (single-frame or reassembled
        /// from fragments). `payload` borrows either the input `buf`
        /// (single-frame case) or `message_buf` (reassembled case) —
        /// valid until the next `receive` call.
        message: Message,
        /// A ping was received; reply with `frame.pongFor(payload, ..)`.
        ping: []const u8,
        /// A pong was received (a reply to a ping, or unsolicited).
        pong: []const u8,
        /// A close frame was received (§5.5.1); `Connection.close_received`
        /// is now true. Reply with a close frame (echoing the code is
        /// conventional) to complete the closing handshake, then close
        /// the transport once `bothClosed()` is true.
        close: frame.CloseInfo,
    };

    pub const Result = struct { event: Event, consumed: usize };

    /// `frame.FrameError` plus the two errors only a multi-frame `Connection`
    /// can detect: an aggregate message over the `message_buf` cap, and an
    /// invalid frame sequence (a continuation with nothing to continue, or a
    /// new data frame starting before the previous one finished). Every
    /// variant maps to a close code via `frame.closeCode`.
    pub const Error = frame.FrameError || error{
        /// Reassembled (or single-frame) message exceeds `message_buf.len`.
        /// Close 1009.
        MessageTooLarge,
        /// A continuation frame with no message in progress, or a new
        /// text/binary frame while one is already in progress (§5.4).
        /// Close 1002.
        InvalidFragmentation,
        /// The complete text message (or the close reason) is not valid
        /// UTF-8 (§5.6/§5.5.1). Close 1007.
        InvalidUtf8,
    };

    /// Feed the next available bytes. Consumes at most one frame per call
    /// (mirrors `frame.parseFrame`); loop, advancing by `consumed`, until
    /// `.need_more`.
    pub fn receive(self: *Connection, buf: []u8) Error!Result {
        const parsed = switch (try frame.parseFrame(buf, self.role, self.max_frame_size)) {
            .need_more => return .{ .event = .need_more, .consumed = 0 },
            .frame => |f| f,
        };

        if (parsed.opcode.isControl()) {
            return switch (parsed.opcode) {
                .close => blk: {
                    self.close_received = true;
                    const info = try frame.decodeCloseBody(parsed.payload);
                    break :blk .{ .event = .{ .close = info }, .consumed = parsed.consumed };
                },
                .ping => .{ .event = .{ .ping = parsed.payload }, .consumed = parsed.consumed },
                .pong => .{ .event = .{ .pong = parsed.payload }, .consumed = parsed.consumed },
                else => unreachable,
            };
        }

        switch (parsed.opcode) {
            .continuation => {
                const start_opcode = self.fragment_opcode orelse return error.InvalidFragmentation;
                try self.appendFragment(parsed.payload);
                if (!parsed.fin) return .{ .event = .frame_consumed, .consumed = parsed.consumed };

                self.fragment_opcode = null;
                const payload = self.message_buf[0..self.message_len];
                if (start_opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
                return .{ .event = .{ .message = .{ .opcode = start_opcode, .payload = payload } }, .consumed = parsed.consumed };
            },
            .text, .binary => {
                if (self.fragment_opcode != null) return error.InvalidFragmentation;
                if (parsed.fin) {
                    // The cap is the caller's memory budget, so it has to apply
                    // to a one-frame message too — the doc comment on
                    // `message_buf` says so, and before this check the only
                    // bound on an unfragmented message was `max_frame_size`.
                    // The payload is still returned borrowed from `buf` (no
                    // copy into `message_buf`); the buffer's *length* is what
                    // is being honoured here, not its storage.
                    if (parsed.payload.len > self.message_buf.len) return error.MessageTooLarge;
                    if (parsed.opcode == .text and !std.unicode.utf8ValidateSlice(parsed.payload))
                        return error.InvalidUtf8;
                    return .{ .event = .{ .message = .{ .opcode = parsed.opcode, .payload = parsed.payload } }, .consumed = parsed.consumed };
                }
                self.fragment_opcode = parsed.opcode;
                self.message_len = 0;
                try self.appendFragment(parsed.payload);
                return .{ .event = .frame_consumed, .consumed = parsed.consumed };
            },
            else => unreachable, // control opcodes handled above
        }
    }

    fn appendFragment(self: *Connection, payload: []const u8) Error!void {
        if (self.message_len + payload.len > self.message_buf.len) return error.MessageTooLarge;
        @memcpy(self.message_buf[self.message_len..][0..payload.len], payload);
        self.message_len += payload.len;
    }

    /// The closing handshake (§7.1.1) is done on both sides — the
    /// transport may now be closed.
    pub fn bothClosed(self: *const Connection) bool {
        return self.close_sent and self.close_received;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn unmaskedFrame(comptime opcode_byte: u8, payload: []const u8, comptime buf_len: usize) [buf_len]u8 {
    var out: [buf_len]u8 = undefined;
    out[0] = opcode_byte;
    out[1] = @intCast(payload.len);
    @memcpy(out[2..], payload);
    return out;
}

test "reassembles a fragmented text message (RFC 5.7 'Hel'+'lo')" {
    var scratch: [64]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' }; // text, fin=0
    const r1 = try conn.receive(&wire1);
    try testing.expectEqual(Connection.Event.frame_consumed, r1.event);

    var wire2 = [_]u8{ 0x80, 0x02, 'l', 'o' }; // continuation, fin=1
    const r2 = try conn.receive(&wire2);
    switch (r2.event) {
        .message => |m| {
            try testing.expectEqual(frame.Opcode.text, m.opcode);
            try testing.expectEqualStrings("Hello", m.payload);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "a UTF-8 codepoint split across fragment boundaries validates correctly" {
    // "A€B" where '€' = 0xE2 0x82 0xAC, split mid-codepoint across two frames.
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire1 = [_]u8{ 0x01, 0x02, 'A', 0xE2 }; // text, fin=0, "A" + first byte of €
    try testing.expectEqual(Connection.Event.frame_consumed, (try conn.receive(&wire1)).event);

    // continuation, fin=1: remaining 2 bytes of '€' + "B"
    var wire2 = [_]u8{ 0x80, 0x03, 0x82, 0xAC, 'B' };
    const r2 = try conn.receive(&wire2);
    switch (r2.event) {
        .message => |m| try testing.expectEqualStrings("A€B", m.payload),
        else => return error.TestUnexpectedResult,
    }
}

test "control frame (ping) interleaves mid-fragmentation without disturbing it" {
    var scratch: [64]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' };
    _ = try conn.receive(&wire1);

    var ping_wire = [_]u8{ 0x89, 0x02, 'h', 'i' };
    const rp = try conn.receive(&ping_wire);
    switch (rp.event) {
        .ping => |p| try testing.expectEqualStrings("hi", p),
        else => return error.TestUnexpectedResult,
    }

    var wire2 = [_]u8{ 0x80, 0x02, 'l', 'o' };
    const r2 = try conn.receive(&wire2);
    switch (r2.event) {
        .message => |m| try testing.expectEqualStrings("Hello", m.payload),
        else => return error.TestUnexpectedResult,
    }
}

test "continuation frame with no start is rejected (close 1002)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire = [_]u8{ 0x80, 0x02, 'l', 'o' };
    try testing.expectError(error.InvalidFragmentation, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1002), frame.closeCode(error.InvalidFragmentation));
}

test "a new data frame before finishing the previous one is rejected (close 1002)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' };
    _ = try conn.receive(&wire1);

    var wire2 = [_]u8{ 0x02, 0x01, 0xAA }; // binary, fin=0 -- a second start before finishing
    try testing.expectError(error.InvalidFragmentation, conn.receive(&wire2));
}

test "aggregate message over message_buf cap is rejected (close 1009)" {
    var scratch: [4]u8 = undefined; // tiny cap
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' }; // 3 bytes, fits
    _ = try conn.receive(&wire1);

    var wire2 = [_]u8{ 0x80, 0x02, 'l', 'o' }; // +2 bytes = 5 > 4-byte cap
    try testing.expectError(error.MessageTooLarge, conn.receive(&wire2));
    try testing.expectEqual(@as(u16, 1009), frame.closeCode(error.MessageTooLarge));
}

test "an UNFRAGMENTED message over message_buf cap is rejected too (close 1009)" {
    // The cap the doc comment on `message_buf` promises used to apply only to
    // the reassembly path: a single FIN frame was returned borrowed from the
    // read buffer with no size check at all, so the only bound on a one-frame
    // message was `max_frame_size` and a caller who sized `message_buf` as its
    // memory budget did not have one. A 4-byte `message_buf` accepted a 10-byte
    // one-shot text frame.
    var scratch: [4]u8 = undefined; // the caller's stated memory budget
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire = [_]u8{ 0x81, 0x0a } ++ "abcdefghij".*; // text, FIN, 10 bytes
    try testing.expectError(error.MessageTooLarge, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1009), frame.closeCode(error.MessageTooLarge));

    // ...and the same for binary, which has no UTF-8 check to hide behind.
    var bin = [_]u8{ 0x82, 0x05, 1, 2, 3, 4, 5 };
    try testing.expectError(error.MessageTooLarge, conn.receive(&bin));

    // POSITIVE CONTROL: exactly the cap still goes through, and still borrows
    // the caller's read buffer rather than being copied into `message_buf`.
    var fits = [_]u8{ 0x81, 0x04 } ++ "abcd".*;
    const r = try conn.receive(&fits);
    switch (r.event) {
        .message => |m| {
            try testing.expectEqualStrings("abcd", m.payload);
            try testing.expect(m.payload.ptr == fits[2..].ptr);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "invalid UTF-8 single-frame text message is rejected (close 1007)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire = [_]u8{ 0x81, 0x02, 0xff, 0xfe }; // text, invalid UTF-8
    try testing.expectError(error.InvalidUtf8, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1007), frame.closeCode(error.InvalidUtf8));
}

test "invalid UTF-8 reassembled text message is rejected (close 1007)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire1 = [_]u8{ 0x01, 0x01, 0xff }; // text, fin=0, invalid lead byte
    _ = try conn.receive(&wire1);
    var wire2 = [_]u8{ 0x80, 0x01, 'x' };
    try testing.expectError(error.InvalidUtf8, conn.receive(&wire2));
}

test "close frame surfaces code + reason and updates close_received" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    // 2 status-code bytes + the 6-byte reason. The buffer was [7]u8, one short
    // of "normal", so this test never compiled — it was dark until root.zig
    // gained its aggregator.
    var body: [8]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], 1000, .big);
    @memcpy(body[2..], "normal");
    var wire: [2 + 8]u8 = undefined;
    wire[0] = 0x88;
    wire[1] = 8;
    @memcpy(wire[2..], &body);

    try testing.expect(!conn.close_received);
    const r = try conn.receive(&wire);
    switch (r.event) {
        .close => |info| {
            try testing.expectEqual(@as(?u16, 1000), info.code);
            try testing.expectEqualStrings("normal", info.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(conn.close_received);
    try testing.expect(!conn.bothClosed());
    conn.close_sent = true;
    try testing.expect(conn.bothClosed());
}

test "unmasked client frame is rejected through the Connection too (close 1002)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.server, &scratch, 1 << 20);
    var wire = unmaskedFrame(0x81, "hi", 4); // no MASK bit, server-role connection
    try testing.expectError(error.UnmaskedClientFrame, conn.receive(&wire));
}

test "need_more propagates from the underlying frame parser" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var partial = [_]u8{0x81};
    const r = try conn.receive(&partial);
    try testing.expectEqual(Connection.Event.need_more, r.event);
    try testing.expectEqual(@as(usize, 0), r.consumed);
}
