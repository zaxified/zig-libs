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

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

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

    // Pairing a Reader and a Writer on the same stream is safe: each keeps its
    // own copy of the two-word `Stream` and its own buffer. The `Stream.Reader`
    // "stops writes reaching the wire" hazard noted in
    // `modules/bacnet/src/sc_interop.zig` does not reproduce — see the
    // regression test at the end of this file, which pins it.
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

// ── regression: the paired Stream.Reader / Stream.Writer over a real socket ──
//
// `TcpTransport` pairs a `std.Io.net.Stream.Reader` and a
// `std.Io.net.Stream.Writer` on the **same** stream (see `ensure`). A prior
// report — see `modules/bacnet/src/sc_interop.zig` — claimed that creating a
// `Stream.Reader` on a socket stops subsequent writes through the paired
// `Stream.Writer` from reaching the wire under `std.Io.Threaded`. That claim
// does **not** reproduce: reader and writer each hold their own copy of the
// two-word `Stream` and their own buffer, neither touches the fd's flags, and
// both `netRead`/`netWrite` are plain `readv`/`sendmsg`. The paired pattern is
// sound.
//
// The genuine hazard in code like this is a **readiness/buffer mismatch**: a
// buffered `Reader` can already hold a whole TPKT that a later `poll(2)` on the
// raw fd will never report as readable, so a naive `read` that always polls
// first would stall on coalesced frames. `readFn` guards against it with the
// `r.bufferedLen() == 0` check before `waitReadable()`.
//
// This test pins both properties with **no env gate and no external peer**: an
// in-process loopback socket, a write → read → write sequence, and a peer that
// answers with two TPKTs coalesced into one segment so the guard is exercised.
// Removing the `bufferedLen()` check in `readFn` makes the second `read` stall
// and this test fail.

const test_port_regression: u16 = 15684;

const RegressionPeer = struct {
    got_first: bool = false,
    got_second: bool = false,
    first_len: usize = 0,
    second_len: usize = 0,
};

fn regressionSleepMs(ms: u64) void {
    var req: std.posix.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    var rem: std.posix.timespec = undefined;
    while (std.posix.errno(std.posix.system.nanosleep(&req, &rem)) == .INTR) req = rem;
}

fn regressionReadOnce(fd: std.posix.fd_t, buf: []u8, ms: i32) usize {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, ms) catch return 0;
    if (ready == 0) return 0;
    return std.posix.read(fd, buf) catch 0;
}

/// The peer side: an *observer* of what reached the wire, using the raw
/// descriptor rather than the code under test.
fn regressionPeer(res: *RegressionPeer, ready: *std.atomic.Value(bool)) void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse("127.0.0.1", test_port_regression) catch return;
    var server = addr.listen(io, .{ .reuse_address = true }) catch return;
    defer server.socket.close(io);
    ready.store(true, .release);

    const conn = server.accept(io) catch return;
    defer conn.close(io);
    const fd = conn.socket.handle;

    var buf: [64]u8 = undefined;
    res.first_len = regressionReadOnce(fd, &buf, 2000);
    res.got_first = res.first_len == tpkt.header_len + 1;

    // Two one-octet-payload TPKTs written in one syscall, so the transport's
    // Reader over-reads the second into its own buffer — the coalesced case.
    var a: [tpkt.header_len + 1]u8 = undefined;
    var b: [tpkt.header_len + 1]u8 = undefined;
    _ = tpkt.encode(&[_]u8{0xA1}, &a) catch return;
    _ = tpkt.encode(&[_]u8{0xB2}, &b) catch return;
    var reply: [2 * (tpkt.header_len + 1)]u8 = undefined;
    @memcpy(reply[0..a.len], &a);
    @memcpy(reply[a.len..], &b);
    _ = std.posix.system.write(fd, &reply, reply.len);

    res.second_len = regressionReadOnce(fd, &buf, 2000);
    res.got_second = res.second_len == tpkt.header_len + 1;
}

test "TcpTransport delivers write->read->write over a real socket (no env gate)" {
    var res = RegressionPeer{};
    var ready = std.atomic.Value(bool).init(false);
    const th = std.Thread.spawn(.{}, regressionPeer, .{ &res, &ready }) catch |e| {
        if (verboseSkip()) std.debug.print("SKIPPED: cannot spawn thread ({t})\n", .{e});
        return error.SkipZigTest;
    };

    var spin: usize = 0;
    while (!ready.load(.acquire)) : (spin += 1) {
        if (spin > 500) {
            th.join();
            return error.PeerNeverListened;
        }
        regressionSleepMs(2);
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", test_port_regression);

    var tt: TcpTransport = undefined;
    var tries: usize = 0;
    while (true) : (tries += 1) {
        tt = TcpTransport.connect(io, addr) catch |e| {
            if (tries > 500) {
                th.join();
                return e;
            }
            regressionSleepMs(2);
            continue;
        };
        break;
    }
    defer tt.close();
    tt.setReadTimeout(200);
    const t = tt.transport();

    // Write #1 — before any read.
    var f1: [tpkt.header_len + 1]u8 = undefined;
    _ = try tpkt.encode(&[_]u8{0x11}, &f1);
    try t.write(&f1);

    // Read both coalesced replies; the second is served from the Reader's
    // internal buffer, which the `bufferedLen()` guard makes possible.
    var rbuf: [4096]u8 = undefined;
    try testing.expectEqual(@as(usize, tpkt.header_len + 1), try regressionReadFrame(t, &rbuf));
    try testing.expectEqual(@as(usize, tpkt.header_len + 1), try regressionReadFrame(t, &rbuf));

    // Write #2 — after the reads.
    var f2: [tpkt.header_len + 1]u8 = undefined;
    _ = try tpkt.encode(&[_]u8{0x22}, &f2);
    try t.write(&f2);

    th.join();
    try testing.expect(res.got_first);
    try testing.expect(res.got_second);
}

fn regressionReadFrame(t: Transport, buf: []u8) !usize {
    var tries: usize = 0;
    while (tries < 30) : (tries += 1) {
        const n = try t.read(buf);
        if (n != 0) return n;
    }
    return error.ReadTimeout;
}
