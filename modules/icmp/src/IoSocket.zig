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
    if (b.slab.len < Socket.batch_max * b.slot_size) return error.SlabTooSmall;
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
        .ip4 => |a| .{ .v4 = .{ .port = 0, .addr = @bitCast(a.bytes) } },
        .ip6 => |a| .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = a.bytes, .scope_id = 0 } },
    };
}

/// The `std.Io.net` address of a `linux.sockaddr` target.
pub fn ipOf(sa: anytype) net.IpAddress {
    return switch (@TypeOf(sa)) {
        linux.sockaddr.in => .{ .ip4 = .{ .bytes = @bitCast(sa.addr), .port = 0 } },
        linux.sockaddr.in6 => .{ .ip6 = .{ .bytes = sa.addr, .port = 0 } },
        else => @compileError("not an IP sockaddr"),
    };
}
