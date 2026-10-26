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
    /// whole. Since 2026-10-26 only a compressed frame (permessage-deflate)
    /// or a frame whose message would not fit `message_buf` anyway can get
    /// here: an uncompressed text/binary/continuation payload that does not
    /// fit is read straight into `message_buf`. With deflate, give the reader
    /// a buffer of at least the largest compressed frame + 14.
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
    /// The error that ended reading (review F1/F2, 2026-10-26): every later
    /// `readMessage` returns it again. A protocol error has been answered
    /// with a close frame, so nothing after it is read, whichever way its
    /// frame came in. A transport error (`ReadFailed`, `EndOfStream`) is
    /// kept only when it cut a frame being read straight into `message_buf`
    /// (`readDirect`): part of that frame is gone from the reader, so the
    /// stream cannot be parsed further -- close the transport. One while
    /// the frame was still in the reader's buffer leaves the buffer intact,
    /// and a retry reads on.
    sticky: ?ReadError = null,

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
        if (c.sticky) |e| return e;
        c.reader.toss(c.pending_toss);
        c.pending_toss = 0;
        while (true) {
            const buf = c.reader.buffered();
            var r = c.conn.receive(buf) catch |err| {
                c.failWith(frame.closeCode(err));
                c.sticky = err;
                return err;
            };
            if (r.event == .need_more) {
                const direct = c.readDirect(buf) catch |err| {
                    // The message in progress is gone with the frame, and
                    // so is the stream position.
                    c.conn.discardMessage();
                    c.sticky = err;
                    switch (err) {
                        error.ReadFailed, error.EndOfStream => {},
                        else => c.failWith(frame.closeCode(err)),
                    }
                    return err;
                };
                if (direct) |d| r = d;
            }
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

    /// Bytes of a direct payload read per step: each step is unmasked (and,
    /// for text, validated) before the next is read. A multiple of 4, so the
    /// mask key's phase is the same at every step.
    const direct_step = 64 * 1024;

    /// A data frame the reader's buffer cannot hold from where it starts
    /// (it would be shuffled to the buffer's front, or never fit at all):
    /// its payload goes straight into `message_buf` (2026-10-26). Before, a
    /// 64 KiB frame in a 128 KiB buffer cost a 64 KiB `memmove` on top of the
    /// read about every other frame, and a frame over the buffer was refused.
    /// Null when the frame is not one for this path (`directPayload`) or is
    /// small enough to finish in the buffer; the caller then goes on as
    /// before. The reader is left after the frame.
    fn readDirect(c: *Conn, buf: []u8) (Connection.Error || std.Io.Reader.Error)!?Connection.Result {
        const opts: frame.ParseOptions = .{ .allow_rsv1 = c.conn.compressed_buf != null };
        // `receive` has just parsed this header without an error.
        const h = switch (frame.parseHeaderWith(buf, c.conn.role, c.conn.max_frame_size, opts) catch return null) {
            .need_more => return null,
            .header => |h| h,
        };
        if (h.len + h.payload_len <= c.reader.buffer.len - c.reader.seek) return null;
        const slot = try c.conn.directPayload(h) orelse return null;
        const dest = slot.dest;
        var utf8 = slot.utf8;
        // The part that has arrived, then the rest, a step at a time.
        const have = buf.len - h.len;
        @memcpy(dest[0..have], buf[h.len..]);
        c.reader.toss(buf.len);
        var done: usize = 0;
        var filled = have;
        while (true) {
            const piece = dest[done..filled];
            if (h.mask_key) |key| {
                var k: [4]u8 = undefined;
                for (&k, 0..) |*b, i| b.* = key[(done + i) % 4];
                frame.applyMask(piece, k);
            }
            if (utf8) |*u| try u.feed(piece);
            done = filled;
            if (done == dest.len) break;
            filled = @min(dest.len, done + direct_step);
            try c.reader.readSliceAll(dest[done..filled]);
        }
        return try c.conn.receiveFrame(.{
            .fin = h.fin,
            .opcode = h.opcode,
            .masked = h.mask_key != null,
            .rsv1 = false,
            .payload = dest,
            .consumed = 0,
        });
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

test "Conn: a data frame bigger than the reader's buffer is read straight into message_buf" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    var big: [100]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    try frame.writeFrame(&wire.writer, .{ .opcode = .binary, .payload = &big, .mask_key = .{ 1, 2, 3, 4 } });
    // A fragmented text message whose fragments are bigger than the buffer
    // too (two-byte code points split across fragments), then a small frame.
    const text = strRepeat("ž", 60);
    try frame.writeFrame(&wire.writer, .{ .fin = false, .opcode = .text, .payload = text[0..71], .mask_key = .{ 9, 8, 7, 6 } });
    try frame.writeFrame(&wire.writer, .{ .opcode = .continuation, .payload = text[71..], .mask_key = .{ 5, 4, 3, 2 } });
    try frame.writeFrame(&wire.writer, .{ .opcode = .text, .payload = "after", .mask_key = .{ 1, 1, 1, 1 } });
    var src = pipe(&wire);
    var small: [32]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [256]u8 = undefined;
    var server: Conn = .init(.server, &in, &out.writer, &msg, .{});
    const m1 = try server.readMessage();
    try testing.expectEqual(frame.Opcode.binary, m1.opcode);
    try testing.expectEqualSlices(u8, &big, m1.payload);
    const m2 = try server.readMessage();
    try testing.expectEqual(frame.Opcode.text, m2.opcode);
    try testing.expectEqualStrings(text, m2.payload);
    try testing.expectEqualStrings("after", (try server.readMessage()).payload);
    try testing.expectEqual(@as(usize, 0), out.written().len);
}

test "Conn: invalid UTF-8 in a frame read straight into message_buf fails at its step, not at the frame's end" {
    const gpa = testing.allocator;
    const len = 3 * Conn.direct_step;
    const payload = try gpa.alloc(u8, len);
    defer gpa.free(payload);
    @memset(payload, 'a');
    payload[Conn.direct_step + 5] = 0xff;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    try frame.writeFrame(&wire.writer, .{ .opcode = .text, .payload = payload, .mask_key = .{ 1, 2, 3, 4 } });
    var src = pipe(&wire);
    var small: [64]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle_fast }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const msg = try gpa.alloc(u8, len);
    defer gpa.free(msg);
    var server: Conn = .init(.server, &in, &out.writer, msg, .{ .max_frame_size = len });
    try testing.expectError(error.InvalidUtf8, server.readMessage());
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xef", out.written()); // 1007
    // The third step was never read.
    try testing.expect(src.bufferedLen() >= Conn.direct_step);
}

/// A transport that delivers whatever is asked for.
fn trickle_fast(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = r;
    return trickle_src.stream(w, limit);
}

test "Conn: a frame over the reader's buffer with no room in message_buf is MessageTooLarge (1009); a compressed one is FrameExceedsBuffer (1009), not a hang" {
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
    var msg: [64]u8 = undefined;
    var server: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectError(error.MessageTooLarge, server.readMessage());
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xf1", out.written());

    // Compressed bytes collect in compressed_buf through the reader's
    // buffer: one over it can never be parsed whole.
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    const window = try gpa.create(deflate.Window);
    defer gpa.destroy(window);
    var cbuf: [512]u8 = undefined;
    var obuf: [512]u8 = undefined;
    var zwire: std.Io.Writer.Allocating = .init(gpa);
    defer zwire.deinit();
    try frame.writeFrame(&zwire.writer, .{ .opcode = .binary, .payload = &(@as([100]u8, @splat(7))), .mask_key = .{ 1, 2, 3, 4 }, .compressed = true });
    var zsrc = pipe(&zwire);
    var in2: std.Io.Reader = .{ .vtable = &.{ .stream = trickle }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &zsrc;
    var out2: std.Io.Writer.Allocating = .init(gpa);
    defer out2.deinit();
    var msg2: [256]u8 = undefined;
    var server2: Conn = .init(.server, &in2, &out2.writer, &msg2, .{ .deflate = .{ .compressed_buf = &cbuf, .window = window, .compressor = comp, .out_buf = &obuf } });
    try testing.expectError(error.FrameExceedsBuffer, server2.readMessage());
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xf1", out2.written());
}

/// The frames of `ops` as a client sends them (masked, key varying per
/// frame).
fn clientWire(gpa: std.mem.Allocator, ops: []const frame.WriteOptions) !std.Io.Writer.Allocating {
    var wire: std.Io.Writer.Allocating = .init(gpa);
    errdefer wire.deinit();
    for (ops, 0..) |op, i| {
        var o = op;
        o.mask_key = .{ @truncate(i), 0x5a, @truncate(i *% 7), 0xc3 };
        try frame.writeFrame(&wire.writer, o);
    }
    return wire;
}

const Outcome = struct {
    /// Messages: opcode, then the payload's hash and length.
    msgs: [16]struct { op: frame.Opcode, hash: u64, len: usize } = undefined,
    n: usize = 0,
    err: ?anyerror = null,
    /// What this side wrote: its pongs and its close.
    wrote: [64]u8 = undefined,
    wrote_len: usize = 0,
};

/// Read `wire` through a server `Conn` whose reader buffer is `rbuf_len`
/// long, until an error (`Closed` included) or 16 messages.
fn readAll(gpa: std.mem.Allocator, wire: []const u8, rbuf_len: usize, msg_len: usize) !Outcome {
    var src: std.Io.Reader = .fixed(wire);
    const rbuf = try gpa.alloc(u8, rbuf_len);
    defer gpa.free(rbuf);
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle }, .buffer = rbuf, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const msg = try gpa.alloc(u8, msg_len);
    defer gpa.free(msg);
    var server: Conn = .init(.server, &in, &out.writer, msg, .{ .max_frame_size = 4096 });
    server.conn.max_fragments = 6;
    var o: Outcome = .{};
    while (o.n < o.msgs.len) {
        const m = server.readMessage() catch |err| {
            o.err = err;
            // A failed frame stays failed (review F1/F2): the next call
            // says the same, whichever path the frame took.
            if (err != error.Closed) try testing.expectError(err, server.readMessage());
            break;
        };
        o.msgs[o.n] = .{ .op = m.opcode, .hash = std.hash.Wyhash.hash(0, m.payload), .len = m.payload.len };
        o.n += 1;
    }
    o.wrote_len = @min(out.written().len, o.wrote.len);
    @memcpy(o.wrote[0..o.wrote_len], out.written()[0..o.wrote_len]);
    return o;
}

fn expectSameOutcome(a: Outcome, b: Outcome) !void {
    try testing.expectEqual(a.err, b.err);
    try testing.expectEqual(a.n, b.n);
    for (a.msgs[0..a.n], b.msgs[0..b.n]) |x, y| {
        try testing.expectEqual(x.op, y.op);
        try testing.expectEqual(x.len, y.len);
        try testing.expectEqual(x.hash, y.hash);
    }
    try testing.expectEqualSlices(u8, a.wrote[0..a.wrote_len], b.wrote[0..b.wrote_len]);
}

test "Conn: a frame read straight in fails exactly as a buffered one -- same error, same close code, message discarded (review F1/F3)" {
    const gpa = testing.allocator;
    const big = @as([100]u8, @splat('x'));
    var bad = big;
    bad[10] = 0xff;
    const cases = [_][]const frame.WriteOptions{
        // Invalid UTF-8 in a big continuation of "abc".
        &.{ .{ .fin = false, .opcode = .text, .payload = "abc" }, .{ .opcode = .continuation, .payload = &bad } },
        // Orphan continuation; text inside a fragmented message. (Data
        // after a close never reaches `Conn`: the close ends `readMessage`;
        // `directPayload`'s test has it.)
        &.{.{ .opcode = .continuation, .payload = &big }},
        &.{ .{ .fin = false, .opcode = .binary, .payload = "ab" }, .{ .opcode = .text, .payload = &big } },
        // One fragment over max_fragments (6), its payload invalid UTF-8:
        // TooManyFragments (1009), checked before UTF-8 on both paths.
        &.{ .{ .fin = false, .opcode = .text, .payload = "a" }, .{ .fin = false, .opcode = .continuation, .payload = "b" }, .{ .fin = false, .opcode = .continuation, .payload = "c" }, .{ .fin = false, .opcode = .continuation, .payload = "d" }, .{ .fin = false, .opcode = .continuation, .payload = "e" }, .{ .fin = false, .opcode = .continuation, .payload = "f" }, .{ .opcode = .continuation, .payload = &bad } },
        // A big frame that does not fit message_buf (512).
        &.{.{ .opcode = .binary, .payload = &(@as([600]u8, @splat(1))) }},
    };
    for (cases) |ops| {
        var wire = try clientWire(gpa, ops);
        defer wire.deinit();
        const direct = try readAll(gpa, wire.written(), 32, 512);
        const buffered = try readAll(gpa, wire.written(), 4096, 512);
        try testing.expect(direct.err != null and direct.err.? != error.Closed);
        try expectSameOutcome(direct, buffered);
    }
}

test "Conn: a direct read cut by the transport stays failed -- no garbage parsed from mid-payload (review F2)" {
    const gpa = testing.allocator;
    var wire = try clientWire(gpa, &.{.{ .opcode = .binary, .payload = &(@as([100]u8, @splat(0x81))) }});
    defer wire.deinit();
    // The transport fails after 40 bytes; the payload bytes would read as a
    // FIN text frame header if parsed.
    var src: std.Io.Reader = .fixed(wire.written()[0..40]);
    var small: [32]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = failAtEnd }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [256]u8 = undefined;
    var server: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectError(error.ReadFailed, server.readMessage());
    try testing.expectError(error.ReadFailed, server.readMessage());
    try testing.expectEqual(@as(usize, 0), out.written().len);
}

/// `trickle`, then `ReadFailed` (a timeout, a reset) where the bytes end.
fn failAtEnd(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    return trickle(r, w, limit) catch |err| switch (err) {
        error.EndOfStream => error.ReadFailed,
        else => |e| e,
    };
}

test "Conn: the mask key's phase holds across a direct read's steps, for binary and multi-byte text (review F5)" {
    const gpa = testing.allocator;
    const len = 3 * Conn.direct_step + 37;
    const bin = try gpa.alloc(u8, len);
    defer gpa.free(bin);
    for (bin, 0..) |*b, i| b.* = @truncate(i *% 131 +% 17);
    // Text: "ž" (2 bytes) and "😀" (4 bytes) so code points straddle the
    // steps and the read chunks.
    const text = try gpa.alloc(u8, len);
    defer gpa.free(text);
    var i: usize = 0;
    while (i < len) {
        if (len - i >= 6) {
            @memcpy(text[i..][0..6], "ž😀");
            i += 6;
        } else {
            text[i] = 'a';
            i += 1;
        }
    }
    for ([_]struct { op: frame.Opcode, data: []const u8 }{ .{ .op = .binary, .data = bin }, .{ .op = .text, .data = text } }) |m| {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try frame.writeFrame(&wire.writer, .{ .opcode = m.op, .payload = m.data, .mask_key = .{ 1, 2, 3, 4 } });
        var src: std.Io.Reader = .fixed(wire.written());
        var small: [64]u8 = undefined;
        var in: std.Io.Reader = .{ .vtable = &.{ .stream = oddChunks }, .buffer = &small, .seek = 0, .end = 0 };
        trickle_src = &src;
        odd_turn = 0;
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        const msg = try gpa.alloc(u8, len);
        defer gpa.free(msg);
        var server: Conn = .init(.server, &in, &out.writer, msg, .{ .max_frame_size = len });
        const got = try server.readMessage();
        try testing.expectEqual(m.op, got.opcode);
        try testing.expectEqualSlices(u8, m.data, got.payload);
    }
}

var odd_turn: usize = 0;

/// Reads of 5 and 4093 bytes in turn.
fn oddChunks(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = r;
    odd_turn += 1;
    return trickle_src.stream(w, limit.min(.limited(if (odd_turn % 2 == 1) 5 else 4093)));
}

test "Conn: random frame streams read the same through a 140-byte and a 4 KiB reader buffer" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x7069);
    const r = prng.random();
    var payload_store: [16][300]u8 = undefined;
    for (0..400) |_| {
        var ops: [16]frame.WriteOptions = undefined;
        const n = 1 + r.uintLessThan(usize, ops.len);
        for (ops[0..n], 0..) |*op, k| {
            const p = &payload_store[k];
            const plen = r.uintLessThan(usize, if (r.boolean()) 300 else 20);
            r.bytes(p[0..plen]);
            // Mostly ASCII, so text frames are usually valid UTF-8.
            if (r.uintLessThan(u8, 4) != 0) for (p[0..plen]) |*b| {
                b.* &= 0x7f;
            };
            const opcode: frame.Opcode = switch (r.uintLessThan(u8, 10)) {
                0, 1, 2 => .text,
                3, 4 => .binary,
                5, 6, 7 => .continuation,
                8 => .ping,
                else => .close,
            };
            op.* = .{
                .fin = opcode.isControl() or r.uintLessThan(u8, 3) != 0,
                .opcode = opcode,
                .payload = switch (opcode) {
                    .ping => p[0..@min(plen, 125)],
                    .close => "\x03\xe8",
                    else => p[0..plen],
                },
            };
        }
        var wire = try clientWire(gpa, ops[0..n]);
        defer wire.deinit();
        const msg_len: usize = if (r.boolean()) 512 else 128;
        // 140: room for any control frame (125 + 6), not for the big data
        // frames, which go the direct way.
        try expectSameOutcome(try readAll(gpa, wire.written(), 140, msg_len), try readAll(gpa, wire.written(), 4096, msg_len));
    }
}

const fz = @import("fuzz_test.zig");
const fuzz_driver = @import("testkit").fuzz.driver;

/// `conn-direct` (2026-10-26, review F5): a stream of frames chosen by the
/// fuzz source -- text/binary/continuation/ping/close, FIN or not, payloads
/// up to 300 bytes (mostly ASCII, so text is often valid) -- read through a
/// server `Conn` with a 140-byte reader buffer (data frames over it go
/// straight into `message_buf`) and with a 4 KiB one. Oracle: the same
/// messages, the same error, the same bytes written back.
fn connDirectHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var payload_store: [12][300]u8 = undefined;
    var ops: [12]frame.WriteOptions = undefined;
    const n = @as(usize, src.valueRangeAtMost(u16, 1, ops.len));
    var direct = false;
    for (ops[0..n], 0..) |*op, k| {
        const p = &payload_store[k];
        const plen = if (src.value(bool)) @as(usize, src.valueRangeAtMost(u16, 0, 300)) else @as(usize, src.valueRangeAtMost(u16, 0, 20));
        src.bytes(p[0..plen]);
        if (src.valueRangeAtMost(u8, 0, 3) != 0) for (p[0..plen]) |*b| {
            b.* &= 0x7f;
        };
        const opcode: frame.Opcode = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0, 1, 2 => .text,
            3, 4 => .binary,
            5, 6, 7 => .continuation,
            8 => .ping,
            else => .close,
        };
        if (!opcode.isControl() and plen + 8 > 140) direct = true;
        op.* = .{
            .fin = opcode.isControl() or src.valueRangeAtMost(u8, 0, 2) != 0,
            .opcode = opcode,
            .payload = switch (opcode) {
                .ping => p[0..@min(plen, 125)],
                .close => "\x03\xe8",
                else => p[0..plen],
            },
        };
    }
    if (direct) fz.mark(.conn_direct_frame);
    var wire = try clientWire(gpa, ops[0..n]);
    defer wire.deinit();
    const msg_len: usize = if (src.value(bool)) 512 else 128;
    const a = try readAll(gpa, wire.written(), 140, msg_len);
    try expectSameOutcome(a, try readAll(gpa, wire.written(), 4096, msg_len));
    fz.mark(if (a.err == null or a.err.? == error.Closed or a.err.? == error.EndOfStream) .conn_stream_ended else .conn_stream_failed);
}

test "fuzz driver: WEBSOCKET_FUZZ (conn-direct)" {
    try fuzz_driver.run(connDirectHarness, .{ .prefix = "WEBSOCKET_FUZZ", .name = "conn-direct" });
}

test "fuzz harness: conn-direct, 300 seeds in every test run, reaching the direct path, clean ends and failures" {
    fz.resetReach();
    for (0..300) |sd| {
        var prng = std.Random.DefaultPrng.init(sd);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        connDirectHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("websocket conn-direct seed {d}: {t}\n", .{ sd, err });
            return err;
        };
    }
    try fz.expectReached(&.{ .conn_direct_frame, .conn_stream_ended, .conn_stream_failed });
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
