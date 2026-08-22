// SPDX-License-Identifier: MIT

//! The **datagram** seam both roles ride on, plus the two adapters onto it:
//! `UdpTransport` (a real socket, for demos and live interop) and
//! `LoopTransport` (an in-memory network, which is what makes a full
//! client-to-device round trip testable with no sockets at all).
//!
//! BACnet/IP is UDP, so unlike a TCP protocol there is **no framing problem
//! and no stream to split** — one datagram is exactly one BVLC message, and
//! the length field can therefore be checked against what the socket
//! delivered. What the seam must carry instead is the **peer address on both
//! sides**: a device answers a request to whoever sent it, and a client must
//! know which device answered a broadcast. That is why `recv` returns a
//! source address and `send` takes a destination, rather than the
//! read/write pair a connected protocol would use.
//!
//! Keeping the seam in its own file is what lets `client` and `device` share
//! it without either importing the other.

const std = @import("std");
const bvll = @import("bvll.zig");

pub const TransportError = error{
    /// The underlying socket failed while sending.
    SendFailed,
    /// The underlying socket failed while receiving.
    RecvFailed,
    /// The caller's buffer is smaller than the datagram that arrived.
    DatagramTooLarge,
    /// The blocking send or receive was canceled through the `std.Io`
    /// cancellation protocol (`Future.cancel`). Surfaced instead of
    /// `SendFailed`/`RecvFailed` because a canceled wait is not a transport
    /// failure — the socket is fine, the caller just stopped waiting on it —
    /// and a caller (e.g. a poll loop torn down mid-`recv`) needs to tell the
    /// two apart.
    Canceled,
};

/// A received datagram: the octets, and who sent them.
pub const Received = struct {
    from: bvll.BipAddress,
    /// A prefix of the buffer the caller passed to `recv`.
    bytes: []u8,
};

/// The datagram seam: one `send`, one `recv`, one `broadcast`.
///
/// `recv` returning `null` means "nothing available this round" and is **not**
/// an error — a UDP peer that has said nothing is indistinguishable from one
/// that is thinking. A caller that wants a receive timeout implements it
/// inside its own `recv`; there is no timer thread here.
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ctx: *anyopaque, to: bvll.BipAddress, bytes: []const u8) TransportError!void,
        /// Sends to the local subnet's broadcast address. Separate from `send`
        /// because the broadcast address is a property of the *interface*, not
        /// something a protocol layer can compute.
        broadcast: *const fn (ctx: *anyopaque, bytes: []const u8) TransportError!void,
        recv: *const fn (ctx: *anyopaque, buf: []u8) TransportError!?Received,
    };

    pub fn send(self: Transport, to: bvll.BipAddress, bytes: []const u8) TransportError!void {
        return self.vtable.send(self.ctx, to, bytes);
    }

    pub fn broadcast(self: Transport, bytes: []const u8) TransportError!void {
        return self.vtable.broadcast(self.ctx, bytes);
    }

    pub fn recv(self: Transport, buf: []u8) TransportError!?Received {
        return self.vtable.recv(self.ctx, buf);
    }
};

/// The largest BACnet/IP datagram worth buffering: the 1476-octet maximum APDU
/// plus room for the NPDU header and the BVLC header. Sized so an unsegmented
/// transfer at the largest advertised APDU size always fits.
pub const max_datagram = 1500;

// ── optional real transport: BACnet/IP over std.Io.net ─────────────────────
// Demo/interop convenience only — nothing in the codecs, the client or the
// offline tests needs it.

/// Blocking UDP transport over `std.Io.net`.
///
/// Pin the value in place before wrapping it: the vtable closes over this
/// struct's address, so it must not be copied after the first `send`/`recv`.
pub const UdpTransport = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    /// Where `broadcast` sends. Defaults to the IPv4 limited broadcast
    /// `255.255.255.255`, which reaches the local link; a real deployment
    /// normally wants the *directed* subnet broadcast instead, because a
    /// BBMD's Forwarded-NPDU handling keys off it.
    broadcast_address: bvll.BipAddress,
    /// Nanoseconds a receive may wait before reporting "nothing this round".
    /// Null blocks indefinitely.
    recv_timeout_ns: ?u64 = null,

    pub const Options = struct {
        /// Local port to bind. A device must bind 47808 to be discoverable by
        /// a broadcast Who-Is; a pure client may bind any free port, but then
        /// it will only ever see unicast replies.
        port: u16 = bvll.default_port,
        broadcast_address: bvll.BipAddress = .{ .ip = .{ 255, 255, 255, 255 } },
    };

    pub fn open(io: std.Io, options: Options) !UdpTransport {
        const local: std.Io.net.IpAddress = .{
            .ip4 = std.Io.net.Ip4Address.unspecified(options.port),
        };
        // `allow_broadcast` is the SO_BROADCAST opt-in every BSD-derived
        // stack requires before a datagram to a broadcast address is allowed
        // out at all.
        const sock = try local.bind(io, .{ .mode = .dgram, .allow_broadcast = true });
        return .{
            .io = io,
            .socket = sock,
            .broadcast_address = options.broadcast_address,
        };
    }

    pub fn close(self: *UdpTransport) void {
        self.socket.close(self.io);
    }

    /// Bounds how long a receive blocks, so a caller's poll loop returns on an
    /// idle link and its own timers can still fire.
    pub fn setRecvTimeout(self: *UdpTransport, milliseconds: u32) void {
        self.recv_timeout_ns = @as(u64, milliseconds) * std.time.ns_per_ms;
    }

    pub fn transport(self: *UdpTransport) Transport {
        return .{ .ctx = self, .vtable = &.{
            .send = sendFn,
            .broadcast = broadcastFn,
            .recv = recvFn,
        } };
    }

    fn sendTo(self: *UdpTransport, to: bvll.BipAddress, bytes: []const u8) TransportError!void {
        const dest: std.Io.net.IpAddress = .{
            .ip4 = .{ .bytes = to.ip, .port = to.port },
        };
        // `Socket.SendError` already carries `Io.Cancelable` (unlike
        // `std.Io.Reader.Error`, which cannot express it) — no out-of-band
        // field to consult, just don't flatten what std handed us.
        self.socket.send(self.io, &dest, bytes) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return error.SendFailed,
        };
    }

    fn sendFn(ctx: *anyopaque, to: bvll.BipAddress, bytes: []const u8) TransportError!void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return self.sendTo(to, bytes);
    }

    fn broadcastFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return self.sendTo(self.broadcast_address, bytes);
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) TransportError!?Received {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        const msg = blk: {
            if (self.recv_timeout_ns) |ns| {
                break :blk self.socket.receiveTimeout(self.io, buf, .{ .duration = .{
                    .raw = .fromNanoseconds(@intCast(ns)),
                    .clock = .awake,
                } }) catch |e| switch (e) {
                    // An idle link is not an error — it is the normal state of
                    // a BACnet client between transactions.
                    error.Timeout => return null,
                    // `Socket.ReceiveError`/`ReceiveTimeoutError` already carry
                    // `Io.Cancelable` directly, so there is no out-of-band
                    // field to consult here (unlike `std.Io.Reader.Error`) —
                    // just pass it through instead of relabeling it a failure.
                    error.Canceled => return error.Canceled,
                    else => return error.RecvFailed,
                };
            }
            break :blk self.socket.receive(self.io, buf) catch |e| switch (e) {
                error.Canceled => return error.Canceled,
                else => return error.RecvFailed,
            };
        };
        // Annex J is IPv4-only. An IPv6 datagram on this socket is either an
        // IPv4-mapped address (which converts) or something that has no
        // business being here.
        const ip4 = switch (msg.from) {
            .ip4 => |a| a,
            .ip6 => |a| std.Io.net.Ip4Address.fromIp6(a) orelse return error.RecvFailed,
        };
        return .{
            .from = .{ .ip = ip4.bytes, .port = ip4.port },
            .bytes = msg.data,
        };
    }
};

// ── in-memory network ──────────────────────────────────────────────────────

/// A tiny in-memory network: every endpoint has an address, `send` drops a
/// datagram in the addressee's inbox, and `broadcast` drops a copy in
/// everyone else's. Every offline round-trip test runs on one of these.
pub const LoopNetwork = struct {
    endpoints: [8]?*LoopTransport = @splat(null),
    count: usize = 0,

    pub fn attach(self: *LoopNetwork, ep: *LoopTransport) void {
        std.debug.assert(self.count < self.endpoints.len);
        self.endpoints[self.count] = ep;
        self.count += 1;
        ep.net = self;
    }

    fn deliver(self: *LoopNetwork, to: bvll.BipAddress, from: bvll.BipAddress, bytes: []const u8) void {
        for (self.endpoints[0..self.count]) |maybe| {
            const ep = maybe orelse continue;
            if (ep.address.eql(to)) ep.push(from, bytes);
        }
    }

    fn deliverAll(self: *LoopNetwork, from: bvll.BipAddress, bytes: []const u8) void {
        for (self.endpoints[0..self.count]) |maybe| {
            const ep = maybe orelse continue;
            if (ep.address.eql(from)) continue;
            ep.push(from, bytes);
        }
    }
};

/// One endpoint on a `LoopNetwork`.
pub const LoopTransport = struct {
    address: bvll.BipAddress,
    net: ?*LoopNetwork = null,
    /// A small inbox; enough for a discovery burst plus its answers.
    inbox: [16]Slot = @splat(.{}),
    head: usize = 0,
    tail: usize = 0,
    /// Every datagram this endpoint has sent, for assertions.
    sent_count: usize = 0,
    /// Set when the inbox overflowed, so a test cannot silently lose traffic.
    dropped: bool = false,

    const Slot = struct {
        from: bvll.BipAddress = .{ .ip = @splat(0) },
        buf: [max_datagram]u8 = undefined,
        len: usize = 0,
    };

    pub fn init(address: bvll.BipAddress) LoopTransport {
        return .{ .address = address };
    }

    pub fn transport(self: *LoopTransport) Transport {
        return .{ .ctx = self, .vtable = &.{
            .send = sendFn,
            .broadcast = broadcastFn,
            .recv = recvFn,
        } };
    }

    fn push(self: *LoopTransport, from: bvll.BipAddress, bytes: []const u8) void {
        const next = (self.tail + 1) % self.inbox.len;
        if (next == self.head or bytes.len > max_datagram) {
            self.dropped = true;
            return;
        }
        self.inbox[self.tail].from = from;
        @memcpy(self.inbox[self.tail].buf[0..bytes.len], bytes);
        self.inbox[self.tail].len = bytes.len;
        self.tail = next;
    }

    /// Queues a datagram as if it had arrived from `from`, for tests that need
    /// to inject something no peer on the network would send.
    pub fn inject(self: *LoopTransport, from: bvll.BipAddress, bytes: []const u8) void {
        self.push(from, bytes);
    }

    pub fn pending(self: *const LoopTransport) usize {
        return (self.tail + self.inbox.len - self.head) % self.inbox.len;
    }

    fn sendFn(ctx: *anyopaque, to: bvll.BipAddress, bytes: []const u8) TransportError!void {
        const self: *LoopTransport = @ptrCast(@alignCast(ctx));
        self.sent_count += 1;
        if (self.net) |n| n.deliver(to, self.address, bytes);
        return;
    }

    fn broadcastFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *LoopTransport = @ptrCast(@alignCast(ctx));
        self.sent_count += 1;
        if (self.net) |n| n.deliverAll(self.address, bytes);
        return;
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) TransportError!?Received {
        const self: *LoopTransport = @ptrCast(@alignCast(ctx));
        if (self.head == self.tail) return null;
        const slot = &self.inbox[self.head];
        if (slot.len > buf.len) return error.DatagramTooLarge;
        @memcpy(buf[0..slot.len], slot.buf[0..slot.len]);
        const from = slot.from;
        const n = slot.len;
        self.head = (self.head + 1) % self.inbox.len;
        return .{ .from = from, .bytes = buf[0..n] };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "loop network: unicast reaches one endpoint, broadcast reaches the rest" {
    var net: LoopNetwork = .{};
    var a = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } });
    var b = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 2 } });
    var c = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 3 } });
    net.attach(&a);
    net.attach(&b);
    net.attach(&c);

    const ta = a.transport();
    try ta.send(b.address, "hello");
    try testing.expectEqual(@as(usize, 1), b.pending());
    try testing.expectEqual(@as(usize, 0), c.pending());

    var buf: [64]u8 = undefined;
    const got = (try b.transport().recv(&buf)).?;
    try testing.expectEqualStrings("hello", got.bytes);
    try testing.expect(got.from.eql(a.address));
    try testing.expectEqual(@as(?Received, null), try b.transport().recv(&buf));

    try ta.broadcast("everyone");
    try testing.expectEqual(@as(usize, 1), b.pending());
    try testing.expectEqual(@as(usize, 1), c.pending());
    // The sender does not receive its own broadcast.
    try testing.expectEqual(@as(usize, 0), a.pending());
}

test "loop network: a datagram for nobody is simply dropped" {
    var net: LoopNetwork = .{};
    var a = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } });
    net.attach(&a);
    try a.transport().send(.{ .ip = .{ 10, 0, 0, 9 } }, "nobody home");
    try testing.expectEqual(@as(usize, 1), a.sent_count);
    try testing.expectEqual(@as(usize, 0), a.pending());
}

test "loop transport: an overflowing inbox is recorded, never silently lost" {
    var ep = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } });
    for (0..20) |_| ep.inject(.{ .ip = .{ 10, 0, 0, 1 } }, "x");
    try testing.expect(ep.dropped);
    try testing.expectEqual(ep.inbox.len - 1, ep.pending());
}

test "loop transport: a datagram larger than the caller's buffer is an error" {
    var ep = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } });
    ep.inject(.{ .ip = .{ 10, 0, 0, 1 } }, "0123456789");
    var small: [4]u8 = undefined;
    try testing.expectError(error.DatagramTooLarge, ep.transport().recv(&small));
    // ... and the datagram is still there for a caller with a real buffer.
    var ok: [16]u8 = undefined;
    const got = (try ep.transport().recv(&ok)).?;
    try testing.expectEqualStrings("0123456789", got.bytes);
}

// Real-socket test: proves `Socket.ReceiveError`'s `Io.Cancelable` survives
// `recvFn` instead of being relabeled `RecvFailed`. Uses `UdpTransport` on an
// ephemeral local port that nothing ever sends to, so `receive` is genuinely
// blocked in the kernel when the cancel lands.
const RecvTask = struct {
    fn run(t: Transport, buf: []u8) TransportError!?Received {
        return t.recv(buf);
    }
};

test "udp transport: a cancel during a blocked receive surfaces Canceled, not RecvFailed" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tp = try UdpTransport.open(io, .{ .port = 0 });
    defer tp.close();

    var buf: [max_datagram]u8 = undefined;
    var fut = try io.concurrent(RecvTask.run, .{ tp.transport(), &buf });
    try io.sleep(.fromMilliseconds(200), .awake);

    try testing.expectError(error.Canceled, fut.cancel(io));
}
