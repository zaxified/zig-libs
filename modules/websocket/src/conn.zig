// SPDX-License-Identifier: MIT

//! An optional read/write loop over a `std.Io.Reader` + `std.Io.Writer`
//! pair: what gorilla's and coder's `Conn` give a user — `readMessage`
//! answers pings and the peer's close by itself, `writeMessage` masks (client)
//! and compresses (permessage-deflate) by itself. The codec underneath
//! (`frame`, `Connection`, `deflate`) stays transport-agnostic; this is the
//! ~100 lines a caller would otherwise write around it, written once.
//!
//! Still no I/O of its own: the caller hands it the reader and writer of
//! whatever transport the handshake ran on (TCP, TLS, `http`'s upgraded
//! stream) and owns their buffers, the message buffer and — for deflate —
//! the compressor and window. One `Conn` is single-owner: one reader at a
//! time, one writer at a time (they may be different threads only if the
//! caller serializes `writeMessage`/`ping`/`close` against `readMessage`'s
//! automatic replies — it writes pongs and the closing frame itself).

const std = @import("std");
const frame = @import("frame.zig");
const deflate = @import("deflate.zig");
const Connection = @import("connection.zig").Connection;

pub const Options = struct {
    /// Client role: every frame this side sends is masked with a key drawn
    /// from here (RFC 6455 §5.3 wants it unpredictable — pass a CSPRNG).
    /// Must be non-null for `.client`, is ignored for `.server`.
    mask_random: ?std.Random = null,
    /// permessage-deflate was negotiated (`ServerAccept.deflate` /
    /// `ClientVerifyResult.deflate` non-null): set all four.
    deflate: ?Deflate = null,
    /// Per-frame payload cap (close 1009 past it).
    max_frame_size: u64 = 1 << 20,
};

pub const Deflate = struct {
    /// Receiving: see `Connection.compressed_buf`.
    compressed_buf: []u8,
    window: *deflate.Window,
    /// Sending: messages of at least `min_size` bytes go through it
    /// (coder/websocket's threshold without context takeover is 512).
    compressor: *deflate.Compressor,
    /// Room for one compressed message; a message that would not fit, or
    /// would not shrink, is sent uncompressed.
    out_buf: []u8,
    min_size: usize = 512,
    level: u4 = 1,
};

pub const Message = Connection.Message;

pub const ReadError = Connection.Error || std.Io.Reader.Error || frame.WriteError || error{
    /// The peer's close frame arrived (and was answered, unless this side
    /// had already sent one); `Conn.peer_close` holds its code and reason.
    /// The transport may be closed now.
    Closed,
    /// A frame does not fit the reader's buffer, so it can never be parsed
    /// whole. Give the reader a buffer of at least `max_frame_size` + 14.
    FrameExceedsBuffer,
};

pub const WriteError = frame.WriteError;

pub const Conn = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    conn: Connection,
    opts: Options,
    /// Bytes of the reader's buffer the last returned message still
    /// borrows; tossed at the start of the next `readMessage`.
    pending_toss: usize = 0,
    /// Set when `readMessage` returned `error.Closed`; its reason lives in
    /// `peer_reason_buf`.
    peer_close: ?frame.CloseInfo = null,
    peer_reason_buf: [123]u8 = undefined,

    pub fn init(role: frame.Role, reader: *std.Io.Reader, writer: *std.Io.Writer, message_buf: []u8, opts: Options) Conn {
        std.debug.assert(role == .server or opts.mask_random != null);
        var c: Conn = .{
            .reader = reader,
            .writer = writer,
            .conn = .init(role, message_buf, opts.max_frame_size),
            .opts = opts,
        };
        if (opts.deflate) |d| c.conn.enableDeflate(d.compressed_buf, d.window);
        return c;
    }

    /// The next text or binary message. Pings are answered and pongs
    /// skipped on the way; the peer's close is answered (echoing its code)
    /// and reported as `error.Closed`. A protocol error is answered with the
    /// close code `frame.closeCode` gives it, then returned. `payload` is
    /// valid until the next `readMessage`.
    pub fn readMessage(c: *Conn) ReadError!Message {
        c.reader.toss(c.pending_toss);
        c.pending_toss = 0;
        while (true) {
            const buf = c.reader.buffered();
            const r = c.conn.receive(buf) catch |err| {
                c.failWith(frame.closeCode(err));
                return err;
            };
            switch (r.event) {
                .need_more => {
                    if (buf.len == c.reader.buffer.len) {
                        c.failWith(1009);
                        return error.FrameExceedsBuffer;
                    }
                    try c.reader.fillMore();
                    continue;
                },
                .message => |m| {
                    c.pending_toss = r.consumed;
                    return m;
                },
                .frame_consumed, .pong => c.reader.toss(r.consumed),
                .ping => |p| {
                    // Copy before tossing: the ping's payload lives in the
                    // reader's buffer.
                    var body: [125]u8 = undefined;
                    @memcpy(body[0..p.len], p);
                    c.reader.toss(r.consumed);
                    if (!c.conn.close_sent) {
                        try c.writeControl(.pong, body[0..p.len]);
                        try c.writer.flush();
                    }
                },
                .close => |info| {
                    @memcpy(c.peer_reason_buf[0..info.reason.len], info.reason);
                    c.reader.toss(r.consumed);
                    c.peer_close = .{ .code = info.code, .reason = c.peer_reason_buf[0..info.reason.len] };
                    if (!c.conn.close_sent) {
                        // §5.5.1: echo the status code (none if it sent none).
                        var body: [2]u8 = undefined;
                        const echo = frame.encodeCloseBody(&body, info.code, "") catch unreachable;
                        c.writeControl(.close, echo) catch {};
                        c.writer.flush() catch {};
                        c.conn.close_sent = true;
                    }
                    return error.Closed;
                },
            }
        }
    }

    /// Send one text or binary message: compressed when deflate is on, the
    /// message is at least `min_size` and it shrinks; masked on the client.
    /// Flushes the writer.
    pub fn writeMessage(c: *Conn, opcode: frame.Opcode, payload: []const u8) WriteError!void {
        std.debug.assert(opcode == .text or opcode == .binary);
        if (c.opts.deflate) |d| if (payload.len >= d.min_size) {
            if (d.compressor.compressMessage(payload, d.out_buf, d.level)) |z| {
                try frame.writeFrame(c.writer, .{ .opcode = opcode, .payload = z, .mask_key = c.maskKey(), .compressed = true });
                return c.writer.flush();
            }
        };
        try frame.writeFrame(c.writer, .{ .opcode = opcode, .payload = payload, .mask_key = c.maskKey() });
        return c.writer.flush();
    }

    pub fn ping(c: *Conn, payload: []const u8) WriteError!void {
        try c.writeControl(.ping, payload);
        return c.writer.flush();
    }

    /// Start the closing handshake (§7.1.2): send a close frame. Then keep
    /// calling `readMessage` until it returns `error.Closed` (the peer's
    /// answer) before closing the transport. `reason` at most 123 bytes.
    pub fn close(c: *Conn, code: u16, reason: []const u8) (WriteError || error{ReasonTooLong})!void {
        if (c.conn.close_sent) return;
        var body: [125]u8 = undefined;
        const b = frame.encodeCloseBody(&body, code, reason) catch return error.ReasonTooLong;
        try c.writeControl(.close, b);
        try c.writer.flush();
        c.conn.close_sent = true;
    }

    fn writeControl(c: *Conn, opcode: frame.Opcode, payload: []const u8) WriteError!void {
        return frame.writeFrame(c.writer, .{ .opcode = opcode, .payload = payload, .mask_key = c.maskKey() });
    }

    fn maskKey(c: *Conn) ?[4]u8 {
        if (c.conn.role == .server) return null;
        var k: [4]u8 = undefined;
        c.opts.mask_random.?.bytes(&k);
        return k;
    }

    /// Fail the connection (§7.1.7): a close frame with `code`, best effort.
    fn failWith(c: *Conn, code: u16) void {
        if (c.conn.close_sent) return;
        var body: [2]u8 = undefined;
        const b = frame.encodeCloseBody(&body, code, "") catch unreachable;
        c.writeControl(.close, b) catch return;
        c.writer.flush() catch return;
        c.conn.close_sent = true;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Everything one side wrote, as the other side's reader input.
fn pipe(w: *std.Io.Writer.Allocating) std.Io.Reader {
    return .fixed(w.written());
}

test "Conn: client and server exchange messages, pings are answered, close is echoed" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(1);

    // Client writes: text, ping, binary, close.
    var c_out: std.Io.Writer.Allocating = .init(gpa);
    defer c_out.deinit();
    var dummy_in: std.Io.Reader = .fixed("");
    var cmsg: [256]u8 = undefined;
    var client: Conn = .init(.client, &dummy_in, &c_out.writer, &cmsg, .{ .mask_random = prng.random() });
    try client.writeMessage(.text, "hello");
    try client.ping("are you there");
    try client.writeMessage(.binary, &.{ 0, 1, 2, 3 });
    try client.close(1000, "bye");
    try client.close(1000, "again"); // no second close frame

    // Server reads it all, through a 64-byte reader buffer (frames arrive
    // in pieces), and its replies go to s_out.
    var s_in_all = pipe(&c_out);
    var s_buf: [64]u8 = undefined;
    var s_in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle }, .buffer = &s_buf, .seek = 0, .end = 0 };
    trickle_src = &s_in_all;
    var s_out: std.Io.Writer.Allocating = .init(gpa);
    defer s_out.deinit();
    var smsg: [256]u8 = undefined;
    var server: Conn = .init(.server, &s_in, &s_out.writer, &smsg, .{ .max_frame_size = 50 });
    const m1 = try server.readMessage();
    try testing.expectEqualStrings("hello", m1.payload);
    const m2 = try server.readMessage();
    try testing.expectEqual(frame.Opcode.binary, m2.opcode);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3 }, m2.payload);
    try testing.expectError(error.Closed, server.readMessage());
    try testing.expectEqual(@as(?u16, 1000), server.peer_close.?.code);
    try testing.expectEqualStrings("bye", server.peer_close.?.reason);

    // The server's replies, read back by the client: the pong, then the
    // close echo -- unmasked, as server frames must be.
    var c_in = pipe(&s_out);
    client.reader = &c_in;
    try testing.expectError(error.Closed, client.readMessage());
    try testing.expectEqual(@as(?u16, 1000), client.peer_close.?.code);
    const replies = s_out.written();
    try testing.expectEqualSlices(u8, "\x8a\x0dare you there", replies[0..15]);
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xe8", replies[15..]);
}

var trickle_src: *std.Io.Reader = undefined;

/// A transport that delivers at most 7 bytes per read.
fn trickle(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = r;
    return trickle_src.stream(w, limit.min(.limited(7)));
}

test "Conn: a protocol error is answered with its close code" {
    const gpa = testing.allocator;
    var in: std.Io.Reader = .fixed("\x81\x02hi"); // unmasked frame to a server
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [64]u8 = undefined;
    var server: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectError(error.UnmaskedClientFrame, server.readMessage());
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xea", out.written()); // 1002
}

test "Conn: a frame bigger than the reader's buffer is refused with 1009, not a hang" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    try frame.writeFrame(&wire.writer, .{ .opcode = .binary, .payload = &(@as([100]u8, @splat(7))), .mask_key = .{ 1, 2, 3, 4 } });
    var src = pipe(&wire);
    var small: [32]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [256]u8 = undefined;
    var server: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectError(error.FrameExceedsBuffer, server.readMessage());
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xf1", out.written());
}

test "Conn: permessage-deflate both ways, small messages stay uncompressed" {
    const gpa = testing.allocator;
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    const window = try gpa.create(deflate.Window);
    defer gpa.destroy(window);
    var cbuf: [4096]u8 = undefined;
    var obuf: [4096]u8 = undefined;
    const d: Deflate = .{ .compressed_buf = &cbuf, .window = window, .compressor = comp, .out_buf = &obuf };
    var prng: std.Random.DefaultPrng = .init(2);

    var c_out: std.Io.Writer.Allocating = .init(gpa);
    defer c_out.deinit();
    var none: std.Io.Reader = .fixed("");
    var cmsg: [4096]u8 = undefined;
    var client: Conn = .init(.client, &none, &c_out.writer, &cmsg, .{ .mask_random = prng.random(), .deflate = d });
    const big = strRepeat("{\"k\":\"value\",\"n\":12345}", 64);
    try client.writeMessage(.text, big);
    try client.writeMessage(.text, "short");
    const wire = c_out.written();
    try testing.expect(wire[0] & 0x40 != 0); // RSV1 on the big one
    try testing.expect(wire.len < big.len / 4);

    var in = pipe(&c_out);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var smsg: [4096]u8 = undefined;
    var server: Conn = .init(.server, &in, &out.writer, &smsg, .{ .deflate = d });
    try testing.expectEqualStrings(big, (try server.readMessage()).payload);
    try testing.expectEqualStrings("short", (try server.readMessage()).payload);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
