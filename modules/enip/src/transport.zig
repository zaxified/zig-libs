// SPDX-License-Identifier: MIT

//! The byte-stream seam the client and the adapter ride on, plus the adapters
//! onto it: `TcpTransport` (a real socket, for demos and live interop),
//! `UdpDiscovery` (the datagram side, because `ListIdentity` discovery is a
//! **broadcast** and not a stream) and `LoopTransport` (an in-memory pipe,
//! which is what makes a full client-to-adapter round trip testable with no
//! network at all).
//!
//! Keeping the seam in its own file is what lets `client` and `adapter` share
//! it without either importing the other, and what lets a consumer put a
//! TLS tunnel, a serial gateway or a recording proxy underneath without this
//! module knowing.

const std = @import("std");
const netaddr = @import("netaddr");
const encap = @import("encap.zig");

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

/// The registered EtherNet/IP explicit-messaging port.
pub const default_port: u16 = encap.default_tcp_port;

// ── optional real transport: EtherNet/IP over std.Io.net ───────────────────
// Demo/interop convenience only — nothing in the codecs, the client's logic
// or the offline tests needs it.

/// Blocking TCP transport over `std.Io.net`.
///
/// It reads **one whole encapsulation message per `read`**: 24 octets of
/// header, then exactly the octets the length field announces. That keeps the
/// adapter from over-reading into a buffer the caller cannot see, which a
/// generic "read whatever is available" adapter cannot avoid.
///
/// Pin the value in place before wrapping it: the persistent reader/writer
/// point into this struct's own buffers, so it must not be copied after the
/// first `read`/`write`.
pub const TcpTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    rbuf: [8192]u8 = undefined,
    wbuf: [8192]u8 = undefined,
    reader: ?std.Io.net.Stream.Reader = null,
    writer: ?std.Io.net.Stream.Writer = null,
    /// Milliseconds a read may wait before reporting "nothing this round".
    /// Null blocks indefinitely.
    read_timeout_ms: ?u32 = null,

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpTransport {
        return .{ .io = io, .stream = try address.connect(io, .{ .mode = .stream }) };
    }

    /// Wraps an already-accepted stream (the adapter side).
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
        if (buf.len < encap.header_len) return error.ReadFailed;
        const r = &self.reader.?.interface;
        // Anything already buffered by a previous read counts as readable.
        if (r.bufferedLen() == 0 and !self.waitReadable()) return 0;
        r.readSliceAll(buf[0..encap.header_len]) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            else => return error.ReadFailed,
        };
        const total = encap.peekTotalLen(buf[0..encap.header_len]) catch return error.ReadFailed;
        if (total > buf.len) return error.ReadFailed;
        // Past the header there is no graceful idle: a timeout here means the
        // peer stopped mid-message and the connection is unusable.
        r.readSliceAll(buf[encap.header_len..total]) catch return error.ReadFailed;
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

// ── UDP discovery ──────────────────────────────────────────────────────────

/// One received discovery datagram: the octets and who sent them.
pub const Datagram = struct {
    from_ip: netaddr.Ip,
    from_port: u16,
    bytes: []u8,
};

/// The datagram side. `ListIdentity` is a **broadcast** on UDP 44818 — every
/// device on the segment answers with its own datagram — so it does not fit
/// the stream seam at all and gets its own adapter.
///
/// This is deliberately **not** a `Transport`: a broadcast has many replies
/// and no connection, and pretending otherwise is what makes discovery code
/// wrong (it stops at the first answer and reports one device on a segment
/// with forty).
pub const UdpDiscovery = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    recv_timeout_ns: ?u64 = null,

    pub const Options = struct {
        /// Local port to bind. 0 lets the OS pick, which is what a pure
        /// discovery client wants; a device that must *answer* broadcasts
        /// binds 44818.
        port: u16 = 0,
    };

    pub fn open(io: std.Io, options: Options) !UdpDiscovery {
        const local: std.Io.net.IpAddress = .{
            .ip4 = std.Io.net.Ip4Address.unspecified(options.port),
        };
        // SO_BROADCAST must be on before a datagram addressed to a broadcast
        // address is allowed out at all.
        const sock = try local.bind(io, .{ .mode = .dgram, .allow_broadcast = true });
        return .{ .io = io, .socket = sock };
    }

    pub fn close(self: *UdpDiscovery) void {
        self.socket.close(self.io);
    }

    pub fn setRecvTimeout(self: *UdpDiscovery, milliseconds: u32) void {
        self.recv_timeout_ns = @as(u64, milliseconds) * std.time.ns_per_ms;
    }

    pub fn send(self: *UdpDiscovery, ip: netaddr.Ip, port: u16, bytes: []const u8) !void {
        const dest: std.Io.net.IpAddress = switch (ip) {
            .v4 => |q| .{ .ip4 = .{ .bytes = q, .port = port } },
            .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = port, .flowinfo = 0, .scope_id = 0 } },
        };
        try self.socket.send(self.io, &dest, bytes);
    }

    /// The IPv4 limited broadcast, which is where a `ListIdentity` sweep goes.
    pub const limited_broadcast: netaddr.Ip = .{ .v4 = .{ 255, 255, 255, 255 } };

    /// One datagram, or null when the wait elapsed. Call it in a loop until
    /// it returns null — that is the whole of discovery.
    pub fn receive(self: *UdpDiscovery, buf: []u8) !?Datagram {
        const msg = blk: {
            if (self.recv_timeout_ns) |ns| {
                break :blk self.socket.receiveTimeout(self.io, buf, .{ .duration = .{
                    .raw = .fromNanoseconds(@intCast(ns)),
                    .clock = .awake,
                } }) catch |e| switch (e) {
                    error.Timeout => return null,
                    else => return e,
                };
            }
            break :blk try self.socket.receive(self.io, buf);
        };
        return switch (msg.from) {
            .ip4 => |a| .{ .from_ip = .{ .v4 = a.bytes }, .from_port = a.port, .bytes = msg.data },
            .ip6 => |a| .{ .from_ip = .{ .v6 = a.bytes }, .from_port = a.port, .bytes = msg.data },
        };
    }
};

// ── in-memory pipe ─────────────────────────────────────────────────────────

/// An in-memory full-duplex pipe standing in for a socket: what one side
/// writes lands in `to_peer`, what the peer wants delivered sits in
/// `from_peer`. Every offline client test runs against it.
pub const LoopTransport = struct {
    to_peer: [16384]u8 = undefined,
    to_peer_len: usize = 0,
    from_peer: [16384]u8 = undefined,
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

/// Cross-connects two `LoopTransport`s so a client and an adapter can talk in
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
    const big = [_]u8{0} ** 16384;
    try lt.transport().write(&big);
    try testing.expectError(error.WriteFailed, lt.transport().write(&[_]u8{1}));
}
