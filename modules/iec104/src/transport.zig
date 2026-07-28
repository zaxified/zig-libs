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

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

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

// ── regression: the paired Stream.Reader / Stream.Writer over a real socket ──
//
// `TcpTransport` pairs a `std.Io.net.Stream.Reader` and a
// `std.Io.net.Stream.Writer` on the **same** stream (see `ensure`). A prior
// report — see `modules/bacnet/src/sc_interop.zig` — claimed that merely
// creating a `Stream.Reader` on a socket stops subsequent writes through the
// paired `Stream.Writer` from reaching the wire under `std.Io.Threaded`. That
// claim does **not** reproduce: reader and writer each hold their own copy of
// the two-word `Stream` and their own buffer; neither touches the fd's flags,
// and both `netRead`/`netWrite` are plain `readv`/`sendmsg`. The paired pattern
// is sound.
//
// The real hazard in code shaped like this is a **readiness/buffer mismatch**:
// a buffered `Reader` can already hold a whole APDU that a later `poll(2)` on
// the raw fd will never report as readable — so a naive `read` that always
// polls before reading would stall on coalesced frames. `readFn` guards against
// exactly this with the `r.bufferedLen() == 0` check before `waitReadable()`.
//
// This test pins both properties with **no env gate and no external peer**: an
// in-process loopback socket, a write → read → write sequence, and a peer that
// answers with two APDUs coalesced into one segment so the guard is exercised.
// Removing the `bufferedLen()` check in `readFn` makes the second `read` stall
// and this test fail — which is what gives it teeth.

const testing = std.testing;

const test_port_regression: u16 = 15683;

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

/// Reads once, waiting up to `ms`, and returns the byte count (0 on timeout).
fn regressionReadOnce(fd: std.posix.fd_t, buf: []u8, ms: i32) usize {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, ms) catch return 0;
    if (ready == 0) return 0;
    return std.posix.read(fd, buf) catch 0;
}

/// The peer side: listen, accept, observe the transport's first write, answer
/// with two coalesced APDUs, then observe the transport's second write. It uses
/// the raw descriptor deliberately — it is an *observer* of what reached the
/// wire, not the code under test.
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
    res.got_first = res.first_len == apci.apci_len;

    // Two U-format APDUs written in one syscall, so the transport's Reader
    // over-reads the second into its own buffer — the coalesced case.
    const a = apci.encodeU(.testfr_con);
    const b = apci.encodeU(.startdt_con);
    var reply: [2 * apci.apci_len]u8 = undefined;
    @memcpy(reply[0..apci.apci_len], &a);
    @memcpy(reply[apci.apci_len..], &b);
    _ = std.posix.system.write(fd, &reply, reply.len);

    res.second_len = regressionReadOnce(fd, &buf, 2000);
    res.got_second = res.second_len == apci.apci_len;
}

test "TcpTransport delivers write->read->write over a real socket (no env gate)" {
    var res = RegressionPeer{};
    var ready = std.atomic.Value(bool).init(false);
    const th = std.Thread.spawn(.{}, regressionPeer, .{ &res, &ready }) catch |e| {
        if (verboseSkip()) std.debug.print("SKIPPED: cannot spawn thread ({t})\n", .{e});
        return error.SkipZigTest;
    };

    // Wait for the peer to be listening before dialling in.
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
    try tt.setReadTimeout(200);
    const t = tt.transport();

    // Write #1 — issued *before* any read, the write the bug report agreed
    // does reach the wire.
    const f1 = apci.encodeU(.startdt_act);
    try t.write(&f1);

    // Read both coalesced replies back through the real adapter. The second
    // one is served from the Reader's internal buffer, not the socket — the
    // `bufferedLen()` guard is what keeps it from stalling.
    var rbuf: [apci.max_apdu_len]u8 = undefined;
    try testing.expectEqual(apci.apci_len, try regressionReadFrame(t, &rbuf));
    try testing.expectEqual(apci.apci_len, try regressionReadFrame(t, &rbuf));

    // Write #2 — issued *after* the reads, the write the report claimed never
    // reaches the wire.
    const f2 = apci.encodeU(.stopdt_act);
    try t.write(&f2);

    th.join();
    try testing.expect(res.got_first); // write #1 reached the peer
    try testing.expect(res.got_second); // write #2 reached the peer, post-read
}

/// Polls the adapter until it yields one frame, so a slow peer does not turn a
/// single-shot 0 into a false failure.
fn regressionReadFrame(t: Transport, buf: []u8) !usize {
    var tries: usize = 0;
    while (tries < 30) : (tries += 1) {
        const n = try t.read(buf);
        if (n != 0) return n;
    }
    return error.ReadTimeout;
}
