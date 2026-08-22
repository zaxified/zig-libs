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
    /// The blocking operation was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`). Surfaced instead of `ReadFailed`/
    /// `WriteFailed` so a caller can tell a canceled wait from a real
    /// transport failure.
    Canceled,
};

/// One `read`, one `write`. `read` returning 0 means "nothing available this
/// round" and is **not** end of stream — that is `error.EndOfStream` — and not
/// a cancellation either, which is `error.Canceled`. A caller that wants a
/// read timeout implements it inside its own `read`; there is no timer thread
/// here.
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

    /// `std.posix.poll` is **not** a `std.Io` cancellation point: it restarts
    /// itself on `EINTR`, so the signal `Future.cancel` sends is swallowed and
    /// the wait still runs to its full timeout. Without the explicit
    /// `checkCanceled` below, a canceled read would come back as `false` and
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
        if (buf.len < tpkt.header_len) return error.ReadFailed;
        const r = &self.reader.?.interface;
        // Anything already buffered by a previous read counts as readable.
        if (r.bufferedLen() == 0 and !try self.waitReadable()) return 0;
        r.readSliceAll(buf[0..tpkt.header_len]) catch |e| switch (e) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return self.readFailure(),
        };
        const total = tpkt.peekLength(buf[0..tpkt.header_len]) catch return error.ReadFailed;
        if (total > buf.len) return error.ReadFailed;
        // Past the header there is no graceful idle: a timeout here means the
        // peer stopped mid-packet and the connection is unusable, so even a
        // clean close counts as a failure. A cancel is still a cancel.
        r.readSliceAll(buf[tpkt.header_len..total]) catch |e| switch (e) {
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
            std.debug.print("loopback connect failed ({t}), skipping\n", .{err});
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
        std.debug.print("loopback listen failed ({t}), skipping\n", .{err});
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

    var buf: [4096]u8 = undefined;
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
    var buf: [4096]u8 = undefined;
    var fut = try io.concurrent(readOnce, .{ &fixture.tt, &buf });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}
