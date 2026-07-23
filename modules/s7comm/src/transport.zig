// SPDX-License-Identifier: MIT

//! The byte-stream seam the client and the responder ride on, plus the two
//! adapters onto it: `TcpTransport` (a real socket, for demos and live
//! interop) and `LoopTransport` (an in-memory pipe, which is what makes a
//! full client-to-responder round trip testable with no network at all).
//!
//! Keeping the seam in its own file is what lets `client` and `server` share
//! it without either importing the other, and what lets a consumer put a TLS
//! tunnel, a serial gateway or a recording proxy underneath without this
//! module knowing.

const std = @import("std");
const tpkt = @import("tpkt.zig");

pub const TransportError = error{
    /// The underlying byte stream failed while reading.
    ReadFailed,
    /// The underlying byte stream failed while writing.
    WriteFailed,
    /// The peer closed the stream.
    EndOfStream,
};

/// One `read`, one `write`. `read` returning 0 means "nothing available this
/// round" and is **not** end of stream — that is `error.EndOfStream`. A caller
/// that wants a read timeout implements it inside its own `read`; there is no
/// timer thread here.
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

/// The registered ISO-on-TCP port (IANA `iso-tsap`). S7 PLCs listen here.
pub const default_port: u16 = 102;

// ── optional real transport: ISO-on-TCP over std.Io.net ────────────────────
// Demo/interop convenience only — nothing in the codecs, the client's PDU
// logic or the offline tests needs it.

/// Blocking TCP transport over `std.Io.net`.
///
/// It reads **one whole TPKT per `read`**: four octets of header, then exactly
/// the octets the length field announces. That keeps the adapter from
/// over-reading into a buffer the caller cannot see, which a generic "read
/// whatever is available" adapter cannot avoid.
///
/// Pin the value in place before wrapping it: the persistent reader/writer
/// point into this struct's own buffers, so it must not be copied after the
/// first `read`/`write`.
pub const TcpTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    rbuf: [4096]u8 = undefined,
    wbuf: [4096]u8 = undefined,
    reader: ?std.Io.net.Stream.Reader = null,
    writer: ?std.Io.net.Stream.Writer = null,
    /// Milliseconds a read may wait before reporting "nothing this round".
    /// Null blocks indefinitely.
    read_timeout_ms: ?u32 = null,

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpTransport {
        return .{ .io = io, .stream = try address.connect(io, .{ .mode = .stream }) };
    }

    /// Wraps an already-accepted stream (the responder side).
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
        // Anything already buffered by a previous read counts as readable.
        if (r.bufferedLen() == 0 and !self.waitReadable()) return 0;
        r.readSliceAll(buf[0..tpkt.header_len]) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            else => return error.ReadFailed,
        };
        const total = tpkt.peekLength(buf[0..tpkt.header_len]) catch return error.ReadFailed;
        if (total > buf.len) return error.ReadFailed;
        // Past the header there is no graceful idle: a timeout here means the
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

// ── in-memory pipe ─────────────────────────────────────────────────────────

/// An in-memory full-duplex pipe standing in for a socket: what one side
/// writes lands in `to_peer`, what the peer wants delivered sits in
/// `from_peer`. Every offline client test runs against it.
pub const LoopTransport = struct {
    to_peer: [8192]u8 = undefined,
    to_peer_len: usize = 0,
    from_peer: [8192]u8 = undefined,
    from_peer_len: usize = 0,
    from_peer_pos: usize = 0,

    pub fn transport(self: *LoopTransport) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    /// Queues bytes for the other side to read.
    pub fn deliver(self: *LoopTransport, bytes: []const u8) void {
        @memcpy(self.from_peer[self.from_peer_len..][0..bytes.len], bytes);
        self.from_peer_len += bytes.len;
    }

    /// Everything written so far.
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
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.from_peer[self.from_peer_pos..][0..n]);
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

/// Cross-connects two `LoopTransport`s so a client and a responder can talk in
/// one process: whatever `a` wrote is handed to `b` and vice versa.
pub fn pump(a: *LoopTransport, b: *LoopTransport) void {
    if (a.to_peer_len > 0) {
        b.deliver(a.sent());
        a.clearSent();
    }
    if (b.to_peer_len > 0) {
        a.deliver(b.sent());
        b.clearSent();
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "loop transport round trips" {
    var lt: LoopTransport = .{};
    const t = lt.transport();
    try t.write(&[_]u8{ 1, 2, 3 });
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, lt.sent());
    lt.deliver(&[_]u8{ 9, 8 });
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), try t.read(&buf));
    try testing.expectEqualSlices(u8, &[_]u8{ 9, 8 }, buf[0..2]);
    // An empty pipe reports "nothing this round", not end of stream.
    try testing.expectEqual(@as(usize, 0), try t.read(&buf));
}

test "pump cross-connects two pipes" {
    var a: LoopTransport = .{};
    var b: LoopTransport = .{};
    try a.transport().write(&[_]u8{0xAA});
    pump(&a, &b);
    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try b.transport().read(&buf));
    try testing.expectEqual(@as(u8, 0xAA), buf[0]);
}

test "loop transport refuses to overflow" {
    var lt: LoopTransport = .{};
    const big = [_]u8{0} ** 8192;
    try lt.transport().write(&big);
    try testing.expectError(error.WriteFailed, lt.transport().write(&[_]u8{1}));
}
