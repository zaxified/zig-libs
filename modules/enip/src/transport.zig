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
    /// The blocking operation was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`). Surfaced instead of `ReadFailed`/
    /// `WriteFailed` so a caller can tell a canceled wait from a real
    /// transport failure.
    Canceled,
};

/// One `read`, one `write`. `read` returning 0 means "nothing available this
/// round" and is **not** end of stream — that is `error.EndOfStream` — and not
/// a cancellation either, which is `error.Canceled`. Conflating the three is
/// what turns a canceled shutdown into a caller that polls forever. A caller
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

    /// True when the socket has something to read, false when the wait
    /// elapsed with nothing there.
    ///
    /// `std.posix.poll` is **not** a `std.Io` cancellation point: it restarts
    /// itself on `EINTR`, so the signal `Future.cancel` sends is swallowed and
    /// the wait still runs to its full timeout. Without the explicit
    /// `checkCancel` below, a canceled read would come back as `false` and
    /// then as `0` from `readFn` — "nothing available this round" — and the
    /// caller would keep polling a connection it had already abandoned.
    fn waitReadable(self: *TcpTransport) TransportError!bool {
        const ms = self.read_timeout_ms orelse return true;
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        // A poll that fails outright defers to the real read, which reports
        // the failure properly — but a cancel must not be lost on that path.
        const n = std.posix.poll(&fds, @intCast(ms)) catch {
            try self.checkCanceled();
            return true;
        };
        if (n != 0) return true;
        try self.checkCanceled();
        return false;
    }

    /// `Io.checkCancel` acknowledges the request, so it reports a pending
    /// cancel exactly once — the answer has to be turned into the error here
    /// and not asked for again.
    fn checkCanceled(self: *TcpTransport) TransportError!void {
        self.io.checkCancel() catch return error.Canceled;
    }

    /// Distinguish a canceled wait from a genuine read failure. `Io.Reader`'s
    /// error set cannot carry `Canceled`; the concrete reader records it here.
    fn readFailure(self: *TcpTransport) TransportError {
        if (self.reader.?.err) |e| if (e == error.Canceled) return error.Canceled;
        return error.ReadFailed;
    }

    /// The writer side of `readFailure`.
    fn writeFailure(self: *TcpTransport) TransportError {
        if (self.writer.?.err) |e| if (e == error.Canceled) return error.Canceled;
        return error.WriteFailed;
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
        if (r.bufferedLen() == 0 and !try self.waitReadable()) return 0;
        r.readSliceAll(buf[0..encap.header_len]) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return self.readFailure(),
        };
        const total = encap.peekTotalLen(buf[0..encap.header_len]) catch return error.ReadFailed;
        if (total > buf.len) return error.ReadFailed;
        // Past the header there is no graceful idle: a timeout here means the
        // peer stopped mid-message and the connection is unusable, so even a
        // clean close counts as a failure. A cancel is still a cancel.
        r.readSliceAll(buf[encap.header_len..total]) catch |e| switch (e) {
            error.EndOfStream => return error.ReadFailed,
            error.ReadFailed => return self.readFailure(),
        };
        return total;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        self.ensure();
        const w = &self.writer.?.interface;
        w.writeAll(bytes) catch return self.writeFailure();
        w.flush() catch return self.writeFailure();
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
            .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = port } },
        };
        try self.socket.send(self.io, &dest, bytes);
    }

    /// The IPv4 limited broadcast, which is where a `ListIdentity` sweep goes.
    pub const limited_broadcast: netaddr.Ip = .{ .v4 = .{ 255, 255, 255, 255 } };

    /// One datagram, or null when the wait elapsed. Call it in a loop until
    /// it returns null — that is the whole of discovery.
    ///
    /// This needs no `Canceled` recovery of its own: it is not a `Transport`,
    /// so nothing narrows its errors to `TransportError`, and
    /// `Socket.receive`/`receiveTimeout` already carry `Io.Cancelable` in
    /// their own error sets. A cancel reaches the caller as `error.Canceled`
    /// unchanged — only `error.Timeout` is folded away, into `null`.
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

// ── cancellation ───────────────────────────────────────────────────────────
//
// `Future.cancel` does unblock a thread parked in a socket read, but the
// reason is erased twice on the way out: `Io.Reader.Error` has no `Canceled`
// variant (only the concrete reader's out-of-band `err` field keeps it), and
// this file used to fold every reader failure into `error.ReadFailed`. Both
// tests below run against a listener that accepts and then never writes, so
// the read really is parked when the cancel arrives.

fn acceptOne(
    server: *std.Io.net.Server,
    io: std.Io,
) std.Io.net.Server.AcceptError!std.Io.net.Stream {
    return server.accept(io);
}

/// The blocking call under test, on its own thread so it can be canceled.
fn readOnce(t: *TcpTransport, buf: []u8) TransportError!usize {
    return t.transport().read(buf);
}

/// A connected `TcpTransport` plus the accepted peer that will stay silent.
const SilentPeer = struct {
    tt: TcpTransport,
    peer: std.Io.net.Stream,

    /// `error.SkipZigTest` when loopback is not usable, which is how the rest
    /// of the collection's socket tests behave on a sandboxed runner.
    fn open(io: std.Io, server: *std.Io.net.Server) !SilentPeer {
        var accept_fut = try io.concurrent(acceptOne, .{ server, io });
        const tt = TcpTransport.connect(io, server.socket.address) catch |err| {
            if (accept_fut.cancel(io)) |s| s.close(io) else |_| {}
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        return .{ .tt = tt, .peer = try accept_fut.await(io) };
    }

    fn close(self: *SilentPeer, io: std.Io) void {
        self.peer.close(io);
        self.tt.close();
    }
};

fn silentListener(io: std.Io) !std.Io.net.Server {
    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    return addr.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("loopback listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
}

test "a canceled blocking read surfaces Canceled, not ReadFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try silentListener(io);
    defer server.deinit(io);
    var fixture = try SilentPeer.open(io, &server);
    defer fixture.close(io);

    var buf: [64]u8 = undefined;
    var fut = try io.concurrent(readOnce, .{ &fixture.tt, &buf });
    // Long enough that the read is certainly parked in the kernel.
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

test "a cancel during the read timeout's poll is not reported as an idle round" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try silentListener(io);
    defer server.deinit(io);
    var fixture = try SilentPeer.open(io, &server);
    defer fixture.close(io);

    // With a timeout set, the read never reaches `std.Io` at all: it waits in
    // `poll(2)`, which restarts on the cancel's signal. The cancel therefore
    // only becomes visible after the full 600 ms elapse — and a `waitReadable`
    // that did not ask `std.Io` would return `false`, making `read` answer `0`
    // for "nothing available this round" and the caller poll on forever.
    fixture.tt.setReadTimeout(600);
    var buf: [64]u8 = undefined;
    var fut = try io.concurrent(readOnce, .{ &fixture.tt, &buf });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}
