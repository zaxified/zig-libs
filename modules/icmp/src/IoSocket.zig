// SPDX-License-Identifier: MIT

//! An ICMP echo socket over `std.Io.net` instead of raw syscalls: the
//! unprivileged ping socket (`.dgram` + `protocol = .icmp`/`.icmpv6`), with
//! every send, receive and wait going through the `Io`. What a deterministic
//! `Io` (a simulator) or an evented one needs; `Pinger` uses it when
//! `Config.io` is set.
//!
//! Narrower than `Socket`: no RAW fallback, no kernel receive timestamps (the
//! receive time is read from the `Io` clock), no TTL/TOS capture or setting,
//! no `sendmmsg` batching, no error queue (ICMP errors about probes are not
//! seen), no interface binding or fwmark. A source address is supported.

const std = @import("std");
const linux = std.os.linux;
const Socket = @import("Socket.zig");
const net = std.Io.net;

const IoSocket = @This();

io: std.Io,
socket: net.Socket,
family: Socket.Family,
/// ICMP echo identifier: a ping socket's local port, which the kernel (or
/// the simulator) writes into every request and filters replies by.
ident: u16,

pub fn open(io: std.Io, family: Socket.Family, source: ?net.IpAddress) Socket.OpenError!IoSocket {
    const any: net.IpAddress = source orelse switch (family) {
        .v4 => .{ .ip4 = .unspecified(0) },
        .v6 => .{ .ip6 = .unspecified(0) },
    };
    const sock = any.bind(io, .{
        .mode = .dgram,
        .protocol = switch (family) {
            .v4 => .icmp,
            .v6 => .icmpv6,
        },
    }) catch |err| return switch (err) {
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.AddressUnavailable, error.AddressInUse => error.SourceAddressBind,
        // `std.Io.Threaded` has no tag for the EACCES a ping socket gets when
        // the process group is outside net.ipv4.ping_group_range.
        error.Unexpected, error.ProtocolUnsupportedBySystem => error.PermissionDenied,
        else => error.Unexpected,
    };
    return .{ .io = io, .socket = sock, .family = family, .ident = sock.address.getPort() };
}

pub fn close(self: *IoSocket) void {
    self.socket.close(self.io);
}

pub fn sendTo(self: *const IoSocket, dest: net.IpAddress, packet: []const u8) Socket.SendError!void {
    self.socket.send(self.io, &dest, packet) catch |err| return switch (err) {
        error.NetworkUnreachable, error.NetworkDown => error.NetworkUnreachable,
        error.HostUnreachable => error.HostUnreachable,
        error.AccessDenied => error.PermissionDenied,
        error.MessageOversize => error.MessageTooLong,
        error.SystemResources => error.WouldBlock,
        else => error.Unexpected,
    };
}

/// Every reply already received, without waiting, into `b`'s slots: the
/// shape of `Socket.recvBatch`.
pub fn recvBatch(self: *const IoSocket, b: *Socket.RecvBatch) error{SlabTooSmall}![]const Socket.RecvInfo {
    const need = std.math.mul(usize, Socket.batch_max, b.slot_size) catch return error.SlabTooSmall; // sweep IC-10
    if (b.slab.len < need) return error.SlabTooSmall;
    const now: std.Io.Timeout = .{ .duration = .{ .raw = .zero, .clock = .awake } };
    var n: usize = 0;
    while (n < Socket.batch_max) : (n += 1) {
        const slot = b.slab[n * b.slot_size ..][0..b.slot_size];
        const msg = self.socket.receiveTimeout(self.io, slot, now) catch break;
        b.infos[n] = infoOf(msg);
    }
    return b.infos[0..n];
}

pub fn infoOf(msg: net.IncomingMessage) Socket.RecvInfo {
    return .{ .packet = msg.data, .src = srcOf(msg.from) };
}

fn srcOf(from: net.IpAddress) Socket.RecvInfo.SrcAddr {
    return switch (from) {
        .ip4 => |a| .{ .v4 = .{ .port = 0, .addr = std.mem.bytesToValue(u32, &a.bytes) } },
        .ip6 => |a| .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = a.bytes, .scope_id = 0 } },
    };
}

/// The `std.Io.net` address of a `linux.sockaddr` target.
pub fn ipOf(sa: anytype) net.IpAddress {
    return switch (@TypeOf(sa)) {
        linux.sockaddr.in => .{ .ip4 = .{ .bytes = std.mem.toBytes(sa.addr), .port = 0 } },
        linux.sockaddr.in6 => .{ .ip6 = .{ .bytes = sa.addr, .port = 0 } },
        else => @compileError("not an IP sockaddr"),
    };
}

// ── whole-module mutation audit (2026-11-17) ────────────────────────────────

test "audit: ipOf carries the address bytes of either family" {
    const a4 = ipOf(linux.sockaddr.in{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 10, 1, 2, 3 }) });
    try std.testing.expectEqual([4]u8{ 10, 1, 2, 3 }, a4.ip4.bytes);
    var b6: [16]u8 = @splat(0);
    b6[0] = 0x20;
    b6[15] = 9;
    const a6 = ipOf(linux.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = b6, .scope_id = 0 });
    try std.testing.expectEqual(b6, a6.ip6.bytes);
}

test "audit: recvBatch sizes the slab exactly, one slot per reply, each described" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var s = open(threaded.io(), .v4, null) catch return error.SkipZigTest;
    defer s.close();
    var slab: [Socket.batch_max * 32]u8 = undefined;
    var b: Socket.RecvBatch = .{ .slab = &slab, .slot_size = 32 };
    var short: Socket.RecvBatch = .{ .slab = slab[0 .. slab.len - 1], .slot_size = 32 };
    try std.testing.expectError(error.SlabTooSmall, s.recvBatch(&short));
    try std.testing.expectEqual(@as(usize, 0), (try s.recvBatch(&b)).len); // exact slab, nothing queued
    const lo = ipOf(linux.sockaddr.in{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 127, 0, 0, 1 }) });
    for ([_]u16{ 1, 2, 3 }) |seq| {
        var pk: [8]u8 = @splat(0);
        pk[0] = 8;
        std.mem.writeInt(u16, pk[6..8], seq, .big);
        s.sendTo(lo, &pk) catch return error.SkipZigTest;
    }
    const nap: linux.timespec = .{ .sec = 0, .nsec = 150 * std.time.ns_per_ms };
    _ = linux.nanosleep(&nap, null);
    const got = try s.recvBatch(&b);
    if (got.len == 0) return error.SkipZigTest; // no ICMP echo in this environment
    try std.testing.expectEqual(@as(usize, 3), got.len);
    for (got, [_]u16{ 1, 2, 3 }, 0..) |g, seq, i| {
        try std.testing.expectEqual(@intFromPtr(&slab) + i * 32, @intFromPtr(g.packet.ptr));
        try std.testing.expectEqual(@as(usize, 8), g.packet.len);
        try std.testing.expectEqual(seq, std.mem.readInt(u16, g.packet[6..8], .big));
        try std.testing.expect(g.src == .v4);
    }
}
