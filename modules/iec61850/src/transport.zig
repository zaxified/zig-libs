// SPDX-License-Identifier: MIT

//! The two seams this module rides on, and the optional adapters onto them.
//!
//! * **`Transport`** — a byte stream, for MMS. One `read`, one `write`. A
//!   caller that wants a read timeout implements it inside its own `read`;
//!   there is no timer thread here.
//! * **`Link`** — whole layer-2 frames, for GOOSE and SV. `send` takes a
//!   complete Ethernet frame including both MAC addresses and the EtherType,
//!   and `recv` returns one.
//!
//! **This module deliberately does not open a raw socket.** GOOSE needs
//! `AF_PACKET`/`SOCK_RAW`, which is a capability decision (`CAP_NET_RAW`) and a
//! platform decision, and neither belongs inside a codec. The sibling
//! `rawsock` module does exactly that job; this module takes **no dependency**
//! on it, so wiring the two together is three lines in the caller:
//!
//! ```zig
//! // In the consumer, not here:
//! var sock = try rawsock.PacketSocket.open(.{ .ifname = "eth0", .protocol = 0x88B8 });
//! const link = iec61850.Link{
//!     .ctx = &sock,
//!     .vtable = &.{ .send = mySend, .recv = myRecv },
//! };
//! ```
//!
//! where `mySend`/`myRecv` are two-line shims over the socket's own calls. The
//! same shape works over a pcap replay, a netns bridge, a simulation harness or
//! a test double — which is what `LoopLink` below is.

const std = @import("std");
const tpkt = @import("tpkt.zig");

pub const TransportError = error{
    ReadFailed,
    WriteFailed,
    /// The peer closed the stream.
    EndOfStream,
};

/// A byte stream. `read` returning 0 means "nothing available this round" and
/// is **not** end of stream — that is `error.EndOfStream`.
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, buf: []u8) TransportError!usize,
        write: *const fn (ctx: *anyopaque, bytes: []const u8) TransportError!void,
    };

    pub fn read(self: Transport, buf: []u8) TransportError!usize {
        return self.vtable.read(self.ctx, buf);
    }

    pub fn write(self: Transport, bytes: []const u8) TransportError!void {
        return self.vtable.write(self.ctx, bytes);
    }
};

pub const LinkError = error{
    SendFailed,
    RecvFailed,
};

/// Whole layer-2 frames, for GOOSE and SV.
pub const Link = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ctx: *anyopaque, frame: []const u8) LinkError!void,
        /// Returns 0 when nothing is available this round.
        recv: *const fn (ctx: *anyopaque, buf: []u8) LinkError!usize,
    };

    pub fn send(self: Link, frame: []const u8) LinkError!void {
        return self.vtable.send(self.ctx, frame);
    }

    pub fn recv(self: Link, buf: []u8) LinkError!usize {
        return self.vtable.recv(self.ctx, buf);
    }
};

/// The registered ISO-on-TCP port (IANA `iso-tsap`). Every IEC 61850 server
/// listens here, and it is privileged — a test server needs either root, a
/// network namespace, or a different port.
pub const default_port: u16 = 102;

// ── optional real transport: ISO-on-TCP over std.Io.net ────────────────────
// Demo/interop convenience only — nothing in the codecs, the client's PDU
// logic or the offline tests needs it.

/// Blocking TCP transport over `std.Io.net`.
///
/// It reads **one whole TPKT per `read`**: four octets of header, then exactly
/// the octets the length field announces. That keeps the adapter from
/// over-reading into a buffer the caller cannot see.
///
/// Pin the value in place before wrapping it: the persistent reader/writer
/// point into this struct's own buffers, so it must not be copied after the
/// first `read`/`write`.
pub const TcpTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    rbuf: [16384]u8 = undefined,
    wbuf: [16384]u8 = undefined,
    reader: ?std.Io.net.Stream.Reader = null,
    writer: ?std.Io.net.Stream.Writer = null,
    read_timeout_ms: ?u32 = null,

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpTransport {
        return .{ .io = io, .stream = try address.connect(io, .{ .mode = .stream }) };
    }

    pub fn fromStream(io: std.Io, stream: std.Io.net.Stream) TcpTransport {
        return .{ .io = io, .stream = stream };
    }

    pub fn close(self: *TcpTransport) void {
        self.stream.close(self.io);
    }

    /// Bounds how long a read blocks. Implemented with `poll(2)` rather than
    /// `SO_RCVTIMEO`, because an `EAGAIN` surfacing out of `std.Io` is treated
    /// there as a programmer error.
    pub fn setReadTimeout(self: *TcpTransport, milliseconds: u32) void {
        self.read_timeout_ms = milliseconds;
    }

    fn waitReadable(self: *TcpTransport) bool {
        const ms = self.read_timeout_ms orelse return true;
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const n = std.posix.poll(&fds, @intCast(ms)) catch return true;
        return n != 0;
    }

    pub fn transport(self: *TcpTransport) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn ensure(self: *TcpTransport) void {
        if (self.reader == null) self.reader = self.stream.reader(self.io, &self.rbuf);
        if (self.writer == null) self.writer = self.stream.writer(self.io, &self.wbuf);
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        self.ensure();
        if (buf.len < tpkt.header_len) return error.ReadFailed;
        const r = &self.reader.?.interface;
        if (r.bufferedLen() == 0 and !self.waitReadable()) return 0;
        r.readSliceAll(buf[0..tpkt.header_len]) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            else => return error.ReadFailed,
        };
        const total = tpkt.peekLength(buf[0..tpkt.header_len]) catch return error.ReadFailed;
        if (total > buf.len) return error.ReadFailed;
        // Past the header there is no graceful idle: a stall here means the
        // peer stopped mid-packet and the connection is unusable.
        r.readSliceAll(buf[tpkt.header_len..total]) catch return error.ReadFailed;
        return total;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        self.ensure();
        const w = &self.writer.?.interface;
        w.writeAll(bytes) catch return error.WriteFailed;
        w.flush() catch return error.WriteFailed;
    }
};

// ── in-memory doubles ──────────────────────────────────────────────────────

/// An in-memory full-duplex pipe standing in for a socket.
pub const LoopTransport = struct {
    to_peer: [65536]u8 = undefined,
    to_peer_len: usize = 0,
    from_peer: [65536]u8 = undefined,
    from_peer_len: usize = 0,
    from_peer_pos: usize = 0,

    pub fn transport(self: *LoopTransport) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    pub fn deliver(self: *LoopTransport, bytes: []const u8) void {
        @memcpy(self.from_peer[self.from_peer_len..][0..bytes.len], bytes);
        self.from_peer_len += bytes.len;
    }

    pub fn sent(self: *const LoopTransport) []const u8 {
        return self.to_peer[0..self.to_peer_len];
    }

    pub fn clearSent(self: *LoopTransport) void {
        self.to_peer_len = 0;
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *LoopTransport = @ptrCast(@alignCast(ctx));
        const avail = self.from_peer_len - self.from_peer_pos;
        if (avail == 0) return 0;
        // Hand back exactly one TPKT, like the real adapter does.
        const head = self.from_peer[self.from_peer_pos..self.from_peer_len];
        const total = tpkt.peekLength(head) catch @min(avail, buf.len);
        const n = @min(@min(total, avail), buf.len);
        @memcpy(buf[0..n], head[0..n]);
        self.from_peer_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *LoopTransport = @ptrCast(@alignCast(ctx));
        if (self.to_peer_len + bytes.len > self.to_peer.len) return error.WriteFailed;
        @memcpy(self.to_peer[self.to_peer_len..][0..bytes.len], bytes);
        self.to_peer_len += bytes.len;
    }
};

/// A layer-2 double: frames written go into a queue a test can inspect, and a
/// test can deliver frames to be received. This is what makes a full
/// publisher-to-subscriber round trip runnable with no network.
pub const LoopLink = struct {
    out: [16][2048]u8 = undefined,
    out_len: [16]usize = @splat(0),
    out_count: usize = 0,
    in: [16][2048]u8 = undefined,
    in_len: [16]usize = @splat(0),
    in_count: usize = 0,
    in_pos: usize = 0,
    /// Frames dropped because the queue was full — a test asserts on it rather
    /// than losing them silently.
    dropped: usize = 0,

    pub fn link(self: *LoopLink) Link {
        return .{ .ctx = self, .vtable = &.{ .send = sendFn, .recv = recvFn } };
    }

    pub fn sentFrame(self: *const LoopLink, i: usize) []const u8 {
        return self.out[i][0..self.out_len[i]];
    }

    pub fn deliver(self: *LoopLink, frame: []const u8) void {
        if (self.in_count == self.in.len or frame.len > self.in[0].len) {
            self.dropped += 1;
            return;
        }
        @memcpy(self.in[self.in_count][0..frame.len], frame);
        self.in_len[self.in_count] = frame.len;
        self.in_count += 1;
    }

    /// Moves everything one side sent into the other side's receive queue.
    pub fn pump(a: *LoopLink, b: *LoopLink) void {
        var i: usize = 0;
        while (i < a.out_count) : (i += 1) b.deliver(a.sentFrame(i));
        a.out_count = 0;
    }

    fn sendFn(ctx: *anyopaque, frame: []const u8) LinkError!void {
        const self: *LoopLink = @ptrCast(@alignCast(ctx));
        if (self.out_count == self.out.len or frame.len > self.out[0].len) {
            self.dropped += 1;
            return error.SendFailed;
        }
        @memcpy(self.out[self.out_count][0..frame.len], frame);
        self.out_len[self.out_count] = frame.len;
        self.out_count += 1;
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) LinkError!usize {
        const self: *LoopLink = @ptrCast(@alignCast(ctx));
        if (self.in_pos >= self.in_count) return 0;
        const n = self.in_len[self.in_pos];
        if (n > buf.len) return error.RecvFailed;
        @memcpy(buf[0..n], self.in[self.in_pos][0..n]);
        self.in_pos += 1;
        return n;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the loop transport hands back one TPKT per read" {
    var lt: LoopTransport = .{};
    const t = lt.transport();
    try t.write(&[_]u8{ 1, 2, 3 });
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, lt.sent());

    // Two packets delivered at once come back one at a time.
    lt.deliver(&[_]u8{ 0x03, 0x00, 0x00, 0x06, 0xAA, 0xBB });
    lt.deliver(&[_]u8{ 0x03, 0x00, 0x00, 0x05, 0xCC });
    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 6), try t.read(&buf));
    try testing.expectEqual(@as(usize, 5), try t.read(&buf));
    try testing.expectEqual(@as(usize, 0), try t.read(&buf));
}

test "the loop transport refuses to overflow" {
    var lt: LoopTransport = .{};
    const big = [_]u8{0} ** 65536;
    try lt.transport().write(&big);
    try testing.expectError(error.WriteFailed, lt.transport().write(&[_]u8{1}));
}

test "the loop link carries frames between two sides" {
    var a: LoopLink = .{};
    var b: LoopLink = .{};
    try a.link().send(&[_]u8{ 0x01, 0x0C, 0xCD });
    try a.link().send(&[_]u8{0xAA});
    a.pump(&b);
    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), try b.link().recv(&buf));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x0C, 0xCD }, buf[0..3]);
    try testing.expectEqual(@as(usize, 1), try b.link().recv(&buf));
    try testing.expectEqual(@as(usize, 0), try b.link().recv(&buf));
    try testing.expectEqual(@as(usize, 0), b.dropped);
}

test "a full send queue is reported, not silently dropped" {
    var a: LoopLink = .{};
    var i: usize = 0;
    while (i < 16) : (i += 1) try a.link().send(&[_]u8{0xAA});
    try testing.expectError(error.SendFailed, a.link().send(&[_]u8{0xAA}));
    try testing.expectEqual(@as(usize, 1), a.dropped);
}

test "a frame larger than the receive buffer is an error, not a truncation" {
    var a: LoopLink = .{};
    a.deliver(&[_]u8{0xAA} ** 100);
    var small: [10]u8 = undefined;
    try testing.expectError(error.RecvFailed, a.link().recv(&small));
}
