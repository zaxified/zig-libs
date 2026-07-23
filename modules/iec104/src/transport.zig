// SPDX-License-Identifier: MIT

//! The byte-stream seam both roles ride on, plus the two adapters onto it:
//! `TcpTransport` (a real socket, for demos and live interop) and
//! `LoopTransport` (an in-memory pipe, which is what makes a full
//! master-to-outstation round trip testable with no network at all).
//!
//! Keeping the seam in its own file is what lets `client` and `outstation`
//! share it without either importing the other.

const std = @import("std");
const apci = @import("apci.zig");

pub const TransportError = error{
    /// The underlying byte stream failed while reading.
    ReadFailed,
    /// The underlying byte stream failed while writing.
    WriteFailed,
    /// The peer closed the stream.
    EndOfStream,
};

/// The byte-stream seam: one `read`, one `write`. `read` returning 0 means
/// "nothing available this round" and is **not** end of stream — that is
/// `error.EndOfStream`. A caller that wants a read timeout implements it
/// inside its own `read`; there is no timer thread here.
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

// ── optional real transport: IEC 104 over std.Io.net ───────────────────────
// Demo/interop convenience only — nothing in the codec, the state machine or
// the offline tests needs it.

/// The registered IEC 60870-5-104 TCP port (IANA `iec-104`).
pub const default_port: u16 = 2404;

/// Blocking TCP transport over `std.Io.net`, for demos and live interop.
///
/// It reads **one whole APDU per `read`**: two octets (start + length), then
/// exactly the octets the length field announces. That keeps the adapter from
/// over-reading into a buffer the caller cannot see, which a generic
/// "read whatever is available" adapter cannot avoid.
///
/// Pin the value in place before wrapping it: the persistent reader/writer
/// point into this struct's own buffers, so it must not be copied after the
/// first `read`/`write`. Set `SO_RCVTIMEO` via `setReadTimeout` if the caller
/// needs `poll` to return on an idle link instead of blocking.
pub const TcpTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    rbuf: [4096]u8 = undefined,
    wbuf: [apci.max_apdu_len]u8 = undefined,
    reader: ?std.Io.net.Stream.Reader = null,
    writer: ?std.Io.net.Stream.Writer = null,
    /// Milliseconds a read may wait before reporting "nothing this round".
    /// Null blocks indefinitely.
    read_timeout_ms: ?u32 = null,

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpTransport {
        return .{ .io = io, .stream = try address.connect(io, .{ .mode = .stream }) };
    }

    pub fn close(self: *TcpTransport) void {
        self.stream.close(self.io);
    }

    /// Bounds how long a read blocks, so the caller's `poll` returns on an
    /// idle link and the t1/t2/t3 timers can still fire. Implemented with
    /// `poll(2)` on the socket rather than `SO_RCVTIMEO`, because an `EAGAIN`
    /// surfacing out of `std.Io` is treated there as a programmer error.
    pub fn setReadTimeout(self: *TcpTransport, milliseconds: u32) !void {
        self.read_timeout_ms = milliseconds;
    }

    /// True when the socket has something to read (or the wait timed out and
    /// the caller should be told "nothing this round").
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
        if (buf.len < apci.max_apdu_len) return error.ReadFailed;
        const r = &self.reader.?.interface;
        // Anything already buffered by a previous read counts as readable.
        if (r.bufferedLen() == 0 and !self.waitReadable()) return 0;
        r.readSliceAll(buf[0..2]) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            else => return error.ReadFailed,
        };
        if (buf[0] != apci.start_byte) return error.ReadFailed;
        const n: usize = buf[1];
        if (n < apci.min_length or n > apci.max_length) return error.ReadFailed;
        // Past the header there is no graceful idle: a timeout here means the
        // peer stopped mid-frame and the connection is unusable.
        r.readSliceAll(buf[2..][0..n]) catch return error.ReadFailed;
        return 2 + n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        self.ensure();
        const w = &self.writer.?.interface;
        w.writeAll(bytes) catch return error.WriteFailed;
        w.flush() catch return error.WriteFailed;
    }
};

// ââ in-memory pipe ââââââââââââââââââââââââââââââ

/// An in-memory full-duplex pipe standing in for a socket: what the client
/// writes lands in `to_peer`, what the peer wants delivered sits in
/// `from_peer`. Every client test runs against it, offline.
pub const LoopTransport = struct {
    to_peer: [4096]u8 = undefined,
    to_peer_len: usize = 0,
    from_peer: [4096]u8 = undefined,
    from_peer_len: usize = 0,
    from_peer_pos: usize = 0,

    pub fn transport(self: *LoopTransport) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    /// Queues bytes for the client to read.
    pub fn deliver(self: *LoopTransport, bytes: []const u8) void {
        @memcpy(self.from_peer[self.from_peer_len..][0..bytes.len], bytes);
        self.from_peer_len += bytes.len;
    }

    /// Everything the client has written so far.
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
