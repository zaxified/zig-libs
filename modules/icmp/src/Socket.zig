// SPDX-License-Identifier: MIT

//! Non-blocking ICMP sockets for IPv4/IPv6 on Linux.
//!
//! Tries an unprivileged SOCK_DGRAM ICMP socket first (requires
//! net.ipv4.ping_group_range to cover the process group), then falls back to
//! SOCK_RAW (requires CAP_NET_RAW or root) — configurable via `Mode`.
//!
//! Replies are read with recvmsg so ancillary data can be captured:
//! SO_TIMESTAMPNS kernel receive timestamps (accurate RTT under load),
//! TTL/hop limit and TOS/traffic class, and the source address.
//!
//! Raw syscalls via errno-encoded `std.os.linux` — no libc.

const std = @import("std");
const linux = std.os.linux;

pub const Mode = enum {
    /// Prefer unprivileged DGRAM, fall back to RAW.
    auto,
    dgram,
    raw,
};

pub const Kind = enum { dgram, raw };
pub const Family = enum { v4, v6 };

pub const OpenError = error{
    /// Neither DGRAM (ping_group_range) nor RAW (CAP_NET_RAW) is available.
    PermissionDenied,
    AddressFamilyUnsupported,
    /// Source address bind failed.
    SourceAddressBind,
    /// SO_BINDTODEVICE failed; requires CAP_NET_RAW.
    InterfaceBind,
    Unexpected,
};

pub const SendError = error{
    WouldBlock,
    NetworkUnreachable,
    HostUnreachable,
    PermissionDenied,
    MessageTooLong,
    Unexpected,
};

/// Socket-level options applied at open time. All optional; mirrors the
/// fping probing options that map to setsockopt calls.
pub const Options = struct {
    recv_buf_size: u32 = 1 << 20,
    /// IP TTL / IPv6 unicast hops (fping -H).
    ttl: ?u8 = null,
    /// IP TOS / IPv6 traffic class (fping -O).
    tos: ?u8 = null,
    /// Set the Don't Fragment flag (fping -M).
    dont_fragment: bool = false,
    /// Routing mark (fping -k/--fwmark); requires CAP_NET_ADMIN.
    fwmark: ?u32 = null,
    /// Bind to a specific interface (fping -I); requires CAP_NET_RAW.
    iface: ?[]const u8 = null,
    /// Send probes via a specific outgoing interface while receiving from
    /// any (fping --oiface): every send carries an IP_PKTINFO/IPV6_PKTINFO
    /// control message with this interface index.
    oiface_index: ?u32 = null,
    /// Source address to bind (fping -S). Must match the socket family.
    source: ?union(Family) {
        v4: linux.sockaddr.in,
        v6: linux.sockaddr.in6,
    } = null,
};

/// Ancillary information captured for one received packet.
pub const RecvInfo = struct {
    packet: []u8,
    /// Kernel receive timestamp, CLOCK_REALTIME ns (SO_TIMESTAMPNS).
    timestamp_real_ns: ?i64 = null,
    /// Received TTL (v4) or hop limit (v6).
    ttl: ?u8 = null,
    /// Received TOS (v4) or traffic class (v6).
    tos: ?u8 = null,
    /// Source address of the packet (sockaddr bytes, family-specific).
    src: SrcAddr = .none,

    pub const SrcAddr = union(enum) {
        none,
        v4: linux.sockaddr.in,
        v6: linux.sockaddr.in6,
    };
};

const Socket = @This();

fd: i32,
family: Family,
kind: Kind,
/// ICMP echo identifier this socket sends with and accepts replies for
/// (host byte order). For DGRAM sockets the kernel enforces/rewrites it.
ident: u16,
/// Outgoing interface index for --oiface (0 = routing table decides).
oiface_index: u32 = 0,
/// IPv4 source for the pktinfo spec_dst field when both a source bind and
/// an outgoing interface are used (network byte order; 0 = unset).
pktinfo_src4: u32 = 0,

pub fn open(family: Family, mode: Mode, opts: Options) OpenError!Socket {
    const domain: u32 = switch (family) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };
    const proto: u32 = switch (family) {
        .v4 => linux.IPPROTO.ICMP,
        .v6 => linux.IPPROTO.ICMPV6,
    };
    const flags: u32 = linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;

    var kind: Kind = undefined;
    var fd: i32 = -1;

    if (mode == .auto or mode == .dgram) {
        const rc = linux.socket(domain, linux.SOCK.DGRAM | flags, proto);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                fd = @intCast(rc);
                kind = .dgram;
            },
            .ACCES, .PERM, .AFNOSUPPORT, .PROTONOSUPPORT, .INVAL => {},
            else => return error.Unexpected,
        }
    }
    if (fd < 0 and (mode == .auto or mode == .raw)) {
        const rc = linux.socket(domain, linux.SOCK.RAW | flags, proto);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                fd = @intCast(rc);
                kind = .raw;
            },
            .ACCES, .PERM => return error.PermissionDenied,
            .AFNOSUPPORT, .PROTONOSUPPORT => return error.AddressFamilyUnsupported,
            else => return error.Unexpected,
        }
    }
    if (fd < 0) return error.PermissionDenied;
    errdefer _ = linux.close(fd);

    var self: Socket = .{ .fd = fd, .family = family, .kind = kind, .ident = 0 };

    // A large receive buffer absorbs reply bursts when thousands of probes
    // are in flight; losing replies inflates false loss.
    if (opts.recv_buf_size > 0)
        setOptInt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, opts.recv_buf_size);

    // Kernel receive timestamps; optional (older kernels), errors ignored —
    // the engine falls back to userspace timing.
    setOptInt(fd, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD, 1);

    switch (family) {
        .v4 => {
            setOptInt(fd, linux.SOL.IP, linux.IP.RECVTTL, 1);
            setOptInt(fd, linux.SOL.IP, linux.IP.RECVTOS, 1);
            // A1 F5: on a SOCK_DGRAM ping socket the kernel does not put ICMP
            // errors (Time Exceeded, Destination Unreachable) about our own
            // probes on the normal receive queue -- it can only be read back
            // via the socket error queue, and only once IP_RECVERR is set.
            // Without this, `Stats.icmp_errors` is structurally always 0 on
            // the (default, preferred) DGRAM path, no matter what arrives.
            // Errors ignored: the fallback is simply "no error queue data",
            // which is the status quo this line replaces.
            setOptInt(fd, linux.SOL.IP, linux.IP.RECVERR, 1);
            if (opts.ttl) |v| setOptInt(fd, linux.SOL.IP, linux.IP.TTL, @as(u32, v));
            if (opts.tos) |v| setOptInt(fd, linux.SOL.IP, linux.IP.TOS, @as(u32, v));
            if (opts.dont_fragment)
                setOptInt(fd, linux.SOL.IP, linux.IP.MTU_DISCOVER, linux.IP.PMTUDISC_DO);
        },
        .v6 => {
            setOptInt(fd, linux.SOL.IPV6, linux.IPV6.RECVHOPLIMIT, 1);
            setOptInt(fd, linux.SOL.IPV6, linux.IPV6.RECVTCLASS, 1);
            // A1 F5, IPv6 half of the same fix.
            setOptInt(fd, linux.SOL.IPV6, linux.IPV6.RECVERR, 1);
            if (opts.ttl) |v| setOptInt(fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS, @as(u32, v));
            if (opts.tos) |v| setOptInt(fd, linux.SOL.IPV6, linux.IPV6.TCLASS, @as(u32, v));
            if (opts.dont_fragment)
                setOptInt(fd, linux.SOL.IPV6, linux.IPV6.MTU_DISCOVER, linux.IPV6.PMTUDISC_DO);
        },
    }

    if (opts.fwmark) |mark| setOptInt(fd, linux.SOL.SOCKET, linux.SO.MARK, mark);

    if (opts.iface) |name| {
        const rc = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, name.ptr, @intCast(name.len));
        if (linux.errno(rc) != .SUCCESS) return error.InterfaceBind;
    }

    if (opts.oiface_index) |idx| self.oiface_index = idx;

    if (opts.source) |src| {
        const ok = switch (src) {
            .v4 => |sa| family == .v4 and bindAddr(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)),
            .v6 => |sa| family == .v6 and bindAddr(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6)),
        };
        if (!ok) return error.SourceAddressBind;
        if (src == .v4) self.pktinfo_src4 = src.v4.addr;
        if (kind == .dgram) self.ident = try self.boundIdent();
    } else if (kind == .dgram) {
        // Bind to the wildcard to learn the kernel-assigned echo identifier
        // ("port").
        try self.bindWildcard();
        self.ident = try self.boundIdent();
    }

    // A1 F6: was `@intCast(linux.getpid() & 0xffff)`. On the DGRAM path the
    // kernel picks the identifier (it is the socket's ephemeral "port"), so
    // this module has no say there -- but on the RAW path this value is
    // purely this module's own correlation token (the kernel never uses it
    // to demux a raw socket's traffic), and a PID is the opposite of
    // unguessable: an off-path attacker sharing the host sees 299/299
    // consecutive PIDs differ by exactly 1 (measured 2026-09-05). Getting it
    // from the kernel CSPRNG closes that; `randomIdent` falls back to the
    // old PID-derived value only if the syscall itself is refused, so this
    // can only get *more* random than before, never less.
    if (kind == .raw) self.ident = randomIdent();

    return self;
}

/// A 16-bit identifier from the kernel CSPRNG (`getrandom(2)`), with a
/// PID-derived fallback for the vanishingly unlikely case the syscall is
/// refused (e.g. a seccomp filter without GRND_NONBLOCK allowed). `std.crypto
/// .random` does not exist in 0.16; `getrandom` is the direct, dependency-free
/// route to the same kernel entropy pool.
fn randomIdent() u16 {
    var buf: [2]u8 = undefined;
    const rc = linux.getrandom(&buf, buf.len, 0);
    if (linux.errno(rc) == .SUCCESS and rc == buf.len)
        return std.mem.readInt(u16, &buf, .little);
    return @intCast(linux.getpid() & 0xffff);
}

pub fn close(self: *Socket) void {
    _ = linux.close(self.fd);
    self.* = undefined;
}

fn setOptInt(fd: i32, level: i32, opt: u32, value: u32) void {
    const v: u32 = value;
    _ = linux.setsockopt(fd, level, opt, @ptrCast(&v), @sizeOf(u32));
}

fn bindAddr(fd: i32, addr: *const linux.sockaddr, len: linux.socklen_t) bool {
    return linux.errno(linux.bind(fd, addr, len)) == .SUCCESS;
}

fn bindWildcard(self: *Socket) OpenError!void {
    switch (self.family) {
        .v4 => {
            const sa: linux.sockaddr.in = .{ .port = 0, .addr = 0 };
            if (!bindAddr(self.fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) return error.Unexpected;
        },
        .v6 => {
            const sa: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 };
            if (!bindAddr(self.fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) return error.Unexpected;
        },
    }
}

fn boundIdent(self: *Socket) OpenError!u16 {
    var storage: [@sizeOf(linux.sockaddr.in6)]u8 align(8) = @splat(0);
    var len: linux.socklen_t = storage.len;
    const rc = linux.getsockname(self.fd, @ptrCast(&storage), &len);
    if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
    // sockaddr.in and sockaddr.in6 both store the port (= echo ident for
    // ping sockets) big-endian at offset 2.
    return std.mem.readInt(u16, storage[2..4], .big);
}

pub fn sendTo(self: *const Socket, addr: *const linux.sockaddr, addr_len: linux.socklen_t, packet: []const u8) SendError!void {
    const rc = if (self.oiface_index != 0)
        self.sendmsgPktinfo(addr, addr_len, packet)
    else
        linux.sendto(self.fd, packet.ptr, packet.len, linux.MSG.NOSIGNAL, addr, addr_len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .NOBUFS => return error.WouldBlock,
        .NETUNREACH, .NETDOWN => return error.NetworkUnreachable,
        .HOSTUNREACH, .HOSTDOWN => return error.HostUnreachable,
        .ACCES, .PERM => return error.PermissionDenied,
        .MSGSIZE => return error.MessageTooLong,
        else => return error.Unexpected,
    }
}

/// Build the IP_PKTINFO / IPV6_PKTINFO control message forcing the
/// outgoing interface (fping --oiface, see socket_sendto_ping_ipv4 in
/// fping's socket4.c). Returns the control length to pass in msghdr.
fn buildPktinfo(self: *const Socket, control: *align(@alignOf(linux.cmsghdr)) [64]u8) usize {
    const hdr_len = @sizeOf(linux.cmsghdr);
    const cmsg: *linux.cmsghdr = @ptrCast(control);
    switch (self.family) {
        .v4 => {
            const info: linux.in_pktinfo = .{
                .ifindex = @bitCast(self.oiface_index), // sweep IC-8: >= 2^31 is ENODEV, not a cast panic
                .spec_dst = self.pktinfo_src4,
                .addr = 0,
            };
            cmsg.* = .{ .len = hdr_len + @sizeOf(linux.in_pktinfo), .level = linux.SOL.IP, .type = linux.IP.PKTINFO };
            @memcpy(control[hdr_len..][0..@sizeOf(linux.in_pktinfo)], std.mem.asBytes(&info));
        },
        .v6 => {
            const info: linux.in6_pktinfo = .{
                .addr = @splat(0),
                .ifindex = @bitCast(self.oiface_index), // sweep IC-8: >= 2^31 is ENODEV, not a cast panic
            };
            cmsg.* = .{ .len = hdr_len + @sizeOf(linux.in6_pktinfo), .level = linux.SOL.IPV6, .type = linux.IPV6.PKTINFO };
            @memcpy(control[hdr_len..][0..@sizeOf(linux.in6_pktinfo)], std.mem.asBytes(&info));
        },
    }
    return std.mem.alignForward(usize, cmsg.len, @alignOf(linux.cmsghdr));
}

fn sendmsgPktinfo(self: *const Socket, addr: *const linux.sockaddr, addr_len: linux.socklen_t, packet: []const u8) usize {
    var control: [64]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const control_len = self.buildPktinfo(&control);

    var iov = [_]std.posix.iovec_const{.{ .base = packet.ptr, .len = packet.len }};
    const msg: linux.msghdr_const = .{
        .name = addr,
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control_len,
        .flags = 0,
    };
    return linux.sendmsg(self.fd, &msg, linux.MSG.NOSIGNAL);
}

/// Messages exchanged per sendmmsg/recvmmsg syscall.
pub const batch_max = 16;

/// Send up to batch_max same-family packets with one sendmmsg call.
/// Returns how many packets the kernel accepted; the caller retries the
/// remainder via sendTo, which reports an accurate per-packet errno
/// (sendmmsg stops at the first failure without saying why).
///
/// `error.TooManyPackets` when `addrs.len != packets.len` or either exceeds
/// `batch_max`. This was `std.debug.assert`, which `ReleaseFast`/
/// `ReleaseSmall` compile out (`if (!ok) unreachable`) -- and the two fixed
/// `[batch_max]` stack arrays below are then indexed with a caller-chosen
/// length the type system cannot relate to their size. A1 F1/m30: measured
/// 2026-09-05 with 64 packets against `batch_max = 16` -- Debug/ReleaseSafe
/// panicked (SIGABRT), ReleaseFast wrote past both stack arrays (SIGSEGV,
/// no diagnostic at all). Same class this module already closed twice
/// (`recvBatch` -> `error.SlabTooSmall`, `writeEchoRequest` ->
/// `error.BufferTooSmall`) -- this was the one instance of it left.
pub fn sendMany(
    self: *const Socket,
    addrs: []const *const linux.sockaddr,
    addr_len: linux.socklen_t,
    packets: []const []const u8,
) error{TooManyPackets}!usize {
    if (addrs.len != packets.len or packets.len > batch_max) return error.TooManyPackets;
    var control: [64]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const control_len: usize = if (self.oiface_index != 0) self.buildPktinfo(&control) else 0;

    var iovs: [batch_max]std.posix.iovec = undefined;
    var msgs: [batch_max]linux.mmsghdr = undefined;
    for (packets, addrs, 0..) |pkt, addr, i| {
        // mmsghdr embeds the mutable msghdr; the kernel never writes
        // through iov/name on the send path, so the casts are safe.
        iovs[i] = .{ .base = @constCast(pkt.ptr), .len = pkt.len };
        msgs[i] = .{
            .hdr = .{
                .name = @constCast(addr),
                .namelen = addr_len,
                .iov = @ptrCast(&iovs[i]),
                .iovlen = 1,
                .control = if (control_len != 0) &control else null,
                .controllen = control_len,
                .flags = 0,
            },
            .len = 0,
        };
    }
    const rc = linux.sendmmsg(self.fd, &msgs, @intCast(packets.len), linux.MSG.NOSIGNAL);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return rc;
}

/// Read one packet with ancillary data; returns null when the socket is
/// drained (EAGAIN) or on transient errors.
pub fn recvMsg(self: *const Socket, buf: []u8) ?RecvInfo {
    var src_storage: [@sizeOf(linux.sockaddr.in6)]u8 align(8) = @splat(0);
    var control: [256]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    var iov: std.posix.iovec = .{ .base = buf.ptr, .len = buf.len };
    var msg: linux.msghdr = .{
        .name = @ptrCast(&src_storage),
        .namelen = src_storage.len,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };

    const rc = linux.recvmsg(self.fd, &msg, 0);
    if (linux.errno(rc) != .SUCCESS) return null;

    var info: RecvInfo = .{ .packet = buf[0..rc] };
    info.src = parseSrc(&src_storage, msg.namelen);
    parseControl(control[0..msg.controllen], &info);
    return info;
}

/// `parseSrc` over a sockaddr of unknown length (the offender after a
/// `sock_extended_err`); a short or AF_UNSPEC one is `.none`.
fn parseSrcSlice(bytes: []const u8) RecvInfo.SrcAddr {
    var storage: [@sizeOf(linux.sockaddr.in6)]u8 align(8) = @splat(0);
    const n = @min(bytes.len, storage.len);
    @memcpy(storage[0..n], bytes[0..n]);
    return parseSrc(&storage, @intCast(n));
}

fn parseSrc(storage: *const [@sizeOf(linux.sockaddr.in6)]u8, namelen: linux.socklen_t) RecvInfo.SrcAddr {
    if (namelen < 2) return .none;
    const af = std.mem.readInt(u16, storage[0..2], .little);
    if (af == linux.AF.INET and namelen >= @sizeOf(linux.sockaddr.in)) {
        return .{ .v4 = std.mem.bytesToValue(linux.sockaddr.in, storage[0..@sizeOf(linux.sockaddr.in)]) };
    } else if (af == linux.AF.INET6 and namelen >= @sizeOf(linux.sockaddr.in6)) {
        return .{ .v6 = std.mem.bytesToValue(linux.sockaddr.in6, storage[0..@sizeOf(linux.sockaddr.in6)]) };
    }
    return .none;
}

/// `struct sock_extended_err` (linux/errqueue.h). Not in std's linux
/// bindings; the layout is stable kernel UAPI, reproduced here directly.
/// Followed in the same cmsg by the offender `sockaddr_in`/`sockaddr_in6`
/// (`SO_EE_OFFENDER`): the host that sent the ICMP error. `recvmsg`'s
/// `msg_name` is a different address -- the quoted original destination.
const sock_extended_err = extern struct {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
};

/// One entry read back from the socket error queue (A1 F5).
pub const ErrInfo = struct {
    /// The kernel's quoted copy of the ICMP message this error is about --
    /// for a ping socket this is our own echo request header (ident at
    /// [4..6], seq at [6..8], same layout `echo.writeEchoRequest` wrote),
    /// recovered from the ICMP error's quoted headers even though this
    /// socket never itself retains a copy of what it sent.
    packet: []u8,
    /// ICMP type/code of the error (e.g. `echo.v4.time_exceeded`).
    err_type: u8,
    err_code: u8,
    /// `ee_origin`: `origin_icmp`/`origin_icmp6` for an ICMP error from the
    /// network; anything else (`SO_EE_ORIGIN_LOCAL`, e.g. a local EMSGSIZE)
    /// carries no ICMP message and `err_type`/`err_code` mean nothing.
    origin: u8 = 0,
    /// The address the error is about: the kernel puts the probe's original
    /// destination (from the quoted header) into `msg_name`. Mirrors
    /// `RecvInfo.src`'s SrcAddr shape so `sourceMatches` (pinger.zig) works
    /// unchanged on it.
    src: RecvInfo.SrcAddr = .none,
    /// The host that sent the ICMP error (`SO_EE_OFFENDER`) -- the router
    /// for a Time Exceeded, which is what a traceroute wants. `.none` when
    /// the kernel gave none (a local error).
    offender: RecvInfo.SrcAddr = .none,
};

/// `ee_origin` values (linux/errqueue.h).
pub const origin_icmp: u8 = 2;
pub const origin_icmp6: u8 = 3;

/// Read one entry from the socket error queue (`MSG_ERRQUEUE`), non-blocking.
/// Requires `IP_RECVERR`/`IPV6_RECVERR`, which `open` always sets. Returns
/// null when the queue is empty (EAGAIN) or on transient errors -- same
/// convention as `recvMsg`.
///
/// A1 F5: on the DGRAM ("ping") path the kernel does not deliver ICMP
/// errors about our own probes through the normal receive queue at all --
/// verified live (`errq.py`/`errq2.py` under `unshare`): a forged Time
/// Exceeded quoting a DGRAM socket's ident/seq produced nothing on a normal
/// `recvmsg`, but appeared immediately on `MSG_ERRQUEUE` once `IP_RECVERR`
/// was set, complete with the quoted echo header as `msg_iov` payload and
/// the quoted destination address as `msg_name` -- both usable exactly like
/// the RAW path's `.icmp_error` variant.
pub fn recvErr(self: *const Socket, buf: []u8) ?ErrInfo {
    var src_storage: [@sizeOf(linux.sockaddr.in6)]u8 align(8) = @splat(0);
    var control: [256]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    var iov: std.posix.iovec = .{ .base = buf.ptr, .len = buf.len };
    var msg: linux.msghdr = .{
        .name = @ptrCast(&src_storage),
        .namelen = src_storage.len,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };

    const rc = linux.recvmsg(self.fd, &msg, linux.MSG.ERRQUEUE);
    if (linux.errno(rc) != .SUCCESS) return null;

    var info: ErrInfo = .{ .packet = buf[0..rc], .err_type = 0, .err_code = 0 };
    info.src = parseSrc(&src_storage, msg.namelen);
    parseErrControl(control[0..@min(msg.controllen, control.len)], &info);
    return info;
}

/// The `IP_RECVERR`/`IPV6_RECVERR` control message of an error-queue read:
/// type, code, origin and offender into `info`. Malformed control data is
/// skipped, never trusted for a length.
fn parseErrControl(ctl: []const u8, info: *ErrInfo) void {
    const hdr_len = @sizeOf(linux.cmsghdr);
    const cmsg_align = @alignOf(linux.cmsghdr);
    var off: usize = 0;
    while (off + hdr_len <= ctl.len) {
        const cmsg = std.mem.bytesToValue(linux.cmsghdr, ctl[off..][0..hdr_len]);
        if (cmsg.len < hdr_len or cmsg.len > ctl.len - off) break;
        const data = ctl[off + hdr_len .. off + cmsg.len];

        const is_recverr = (cmsg.level == linux.SOL.IP and cmsg.type == linux.IP.RECVERR) or
            (cmsg.level == linux.SOL.IPV6 and cmsg.type == linux.IPV6.RECVERR);
        if (is_recverr and data.len >= @sizeOf(sock_extended_err)) {
            const ee = std.mem.bytesToValue(sock_extended_err, data[0..@sizeOf(sock_extended_err)]);
            info.err_type = ee.ee_type;
            info.err_code = ee.ee_code;
            info.origin = ee.ee_origin;
            info.offender = parseSrcSlice(data[@sizeOf(sock_extended_err)..]);
        }

        const step = std.mem.alignForward(usize, cmsg.len, cmsg_align);
        if (step > ctl.len - off) break;
        off += step;
    }
}

/// Reusable storage for batched receives: one packet slab of batch_max
/// slots (allocated by the owner) plus per-message scratch headers.
pub const RecvBatch = struct {
    /// batch_max * slot_size bytes.
    slab: []u8,
    slot_size: usize,
    addrs: [batch_max][@sizeOf(linux.sockaddr.in6)]u8 align(8) = undefined,
    controls: [batch_max][256]u8 align(@alignOf(linux.cmsghdr)) = undefined,
    iovs: [batch_max]std.posix.iovec = undefined,
    msgs: [batch_max]linux.mmsghdr = undefined,
    infos: [batch_max]RecvInfo = undefined,
};

/// Read up to batch_max packets with one recvmmsg call. Returns the empty
/// slice when the socket is drained (EAGAIN) or on transient errors; a
/// full slice means more packets may be waiting — call again.
///
/// `error.SlabTooSmall` when `b` does not carry the `batch_max * slot_size`
/// bytes its own documentation requires. This was an `std.debug.assert`,
/// which `ReleaseFast`/`ReleaseSmall` compile out — and the kernel then
/// writes past the end of the slab, because both operands are runtime
/// values the type system cannot relate.
pub fn recvBatch(self: *const Socket, b: *RecvBatch) error{SlabTooSmall}![]const RecvInfo {
    // sweep IC-10: `batch_max * slot_size` wrapped for a huge slot_size and
    // let the kernel write past the slab.
    const need = std.math.mul(usize, batch_max, b.slot_size) catch return error.SlabTooSmall;
    if (b.slab.len < need) return error.SlabTooSmall;
    for (0..batch_max) |i| {
        b.iovs[i] = .{ .base = b.slab.ptr + i * b.slot_size, .len = b.slot_size };
        b.msgs[i] = .{
            .hdr = .{
                .name = @ptrCast(&b.addrs[i]),
                .namelen = b.addrs[i].len,
                .iov = @ptrCast(&b.iovs[i]),
                .iovlen = 1,
                .control = &b.controls[i],
                .controllen = b.controls[i].len,
                .flags = 0,
            },
            .len = 0,
        };
    }
    const rc = linux.recvmmsg(self.fd, &b.msgs, batch_max, 0, null);
    if (linux.errno(rc) != .SUCCESS) return b.infos[0..0];
    const n: usize = rc;
    for (b.msgs[0..n], 0..) |*m, i| {
        var info: RecvInfo = .{ .packet = b.slab[i * b.slot_size ..][0..m.len] };
        info.src = parseSrc(&b.addrs[i], m.hdr.namelen);
        parseControl(b.controls[i][0..m.hdr.controllen], &info);
        b.infos[i] = info;
    }
    return b.infos[0..n];
}

/// Walk the cmsg list (manual CMSG_NXTHDR; std has no cmsg iteration
/// helpers as of 0.16).
fn parseControl(control: []const u8, info: *RecvInfo) void {
    const hdr_len = @sizeOf(linux.cmsghdr);
    const cmsg_align = @alignOf(linux.cmsghdr);
    var off: usize = 0;
    while (off + hdr_len <= control.len) {
        const cmsg: *const linux.cmsghdr = @ptrCast(@alignCast(control.ptr + off));
        if (cmsg.len < hdr_len or off + cmsg.len > control.len) break;
        const data = control[off + hdr_len .. off + cmsg.len];

        if (cmsg.level == linux.SOL.SOCKET and cmsg.type == linux.SO.TIMESTAMPNS_OLD) {
            if (data.len >= @sizeOf(linux.timespec)) {
                const ts: *const linux.timespec = @ptrCast(@alignCast(data.ptr));
                info.timestamp_real_ns = @as(i64, ts.sec) * std.time.ns_per_s + ts.nsec;
            }
        } else if (cmsg.level == linux.SOL.IP and cmsg.type == linux.IP.TTL) {
            if (data.len >= 4) info.ttl = @truncate(std.mem.readInt(u32, data[0..4], .little));
        } else if (cmsg.level == linux.SOL.IP and cmsg.type == linux.IP.TOS) {
            if (data.len >= 1) info.tos = data[0];
        } else if (cmsg.level == linux.SOL.IPV6 and cmsg.type == linux.IPV6.HOPLIMIT) {
            if (data.len >= 4) info.ttl = @truncate(std.mem.readInt(u32, data[0..4], .little));
        } else if (cmsg.level == linux.SOL.IPV6 and cmsg.type == linux.IPV6.TCLASS) {
            if (data.len >= 4) info.tos = @truncate(std.mem.readInt(u32, data[0..4], .little));
        }

        // CMSG_NXTHDR: advance by len rounded up to cmsghdr alignment.
        off += std.mem.alignForward(usize, cmsg.len, cmsg_align);
    }
}

test "A1 F12 m25: parseControl stops at a cmsg claiming more bytes than the control buffer holds" {
    // `if (cmsg.len < hdr_len or off + cmsg.len > control.len) break;` --
    // the `cmsg.len < hdr_len` half alone does not protect the `data =
    // control[off + hdr_len .. off + cmsg.len]` slice a few lines below:
    // a cmsg can declare a `len` field far past the actual control buffer
    // (this is exactly the kind of value a peer/kernel bug or a crafted
    // ancillary-data blob could produce), and without the second half of
    // the OR, that slice's end index exceeds `control.len`.
    const hdr_len = @sizeOf(linux.cmsghdr);
    var control: [hdr_len + 4]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const cmsg: *linux.cmsghdr = @ptrCast(&control);
    cmsg.* = .{ .len = 1000, .level = linux.SOL.SOCKET, .type = linux.SO.TIMESTAMPNS_OLD };
    var info: RecvInfo = .{ .packet = &.{} };
    parseControl(&control, &info); // must not panic
    try std.testing.expectEqual(@as(?i64, null), info.timestamp_real_ns);
}

/// One `IP_RECVERR`-shaped control message: cmsghdr + sock_extended_err +
/// `offender` bytes, padded to the cmsg alignment. Test helper.
fn testErrCmsg(buf: []align(@alignOf(linux.cmsghdr)) u8, level: i32, typ: i32, ee: sock_extended_err, offender: []const u8) []const u8 {
    const hdr_len = @sizeOf(linux.cmsghdr);
    const data_len = @sizeOf(sock_extended_err) + offender.len;
    const hdr: linux.cmsghdr = .{ .len = hdr_len + data_len, .level = level, .type = typ };
    @memset(buf, 0);
    @memcpy(buf[0..hdr_len], std.mem.asBytes(&hdr));
    @memcpy(buf[hdr_len..][0..@sizeOf(sock_extended_err)], std.mem.asBytes(&ee));
    @memcpy(buf[hdr_len + @sizeOf(sock_extended_err) ..][0..offender.len], offender);
    return buf[0..std.mem.alignForward(usize, hdr_len + data_len, @alignOf(linux.cmsghdr))];
}

test "recvErr control: the offender is the router, apart from msg_name" {
    var buf: [128]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    const ee: sock_extended_err = .{
        .ee_errno = @backingInt(linux.E.HOSTUNREACH),
        .ee_origin = origin_icmp,
        .ee_type = 11, // ICMPv4 Time Exceeded
        .ee_code = 0,
        .ee_pad = 0,
        .ee_info = 0,
        .ee_data = 0,
    };
    const router: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 10, 0, 0, 1 }) };
    var info: ErrInfo = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(testErrCmsg(&buf, linux.SOL.IP, linux.IP.RECVERR, ee, std.mem.asBytes(&router)), &info);
    try std.testing.expectEqual(@as(u8, 11), info.err_type);
    try std.testing.expectEqual(origin_icmp, info.origin);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, std.mem.asBytes(&info.offender.v4.addr));
    // msg_name is parsed elsewhere; the control message leaves `src` alone.
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, info.src);

    // IPv6.
    var ee6 = ee;
    ee6.ee_origin = origin_icmp6;
    ee6.ee_type = 3; // ICMPv6 Time Exceeded
    var addr6: [16]u8 = @splat(0);
    addr6[0..4].* = .{ 0x20, 0x01, 0x0d, 0xb8 };
    addr6[15] = 1;
    const router6: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = addr6, .scope_id = 0 };
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(testErrCmsg(&buf, linux.SOL.IPV6, linux.IPV6.RECVERR, ee6, std.mem.asBytes(&router6)), &info);
    try std.testing.expectEqual(origin_icmp6, info.origin);
    try std.testing.expectEqualSlices(u8, &router6.addr, &info.offender.v6.addr);
}

test "recvErr control: no offender, short and lying cmsgs" {
    var buf: [128]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    const ee: sock_extended_err = .{ .ee_errno = 90, .ee_origin = 1, .ee_type = 0, .ee_code = 0, .ee_pad = 0, .ee_info = 1400, .ee_data = 0 };
    // A local error (origin 1) with an AF_UNSPEC offender: `.none`.
    const unspec: [16]u8 = @splat(0);
    var info: ErrInfo = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(testErrCmsg(&buf, linux.SOL.IP, linux.IP.RECVERR, ee, &unspec), &info);
    try std.testing.expectEqual(@as(u8, 1), info.origin);
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, info.offender);

    // A truncated offender (4 bytes of a sockaddr_in): `.none`, no read past it.
    const ctl = testErrCmsg(&buf, linux.SOL.IP, linux.IP.RECVERR, ee, &.{ 2, 0, 0, 0 });
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(ctl, &info);
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, info.offender);

    // A cmsg claiming more than the buffer: ignored entirely.
    const lying: linux.cmsghdr = .{ .len = 4096, .level = linux.SOL.IP, .type = linux.IP.RECVERR };
    @memcpy(buf[0..@sizeOf(linux.cmsghdr)], std.mem.asBytes(&lying));
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(buf[0..64], &info);
    try std.testing.expectEqual(@as(u8, 0), info.origin);
    // Every prefix of a valid message: never a panic.
    const good = testErrCmsg(&buf, linux.SOL.IP, linux.IP.RECVERR, ee, &unspec);
    for (0..good.len + 1) |n| parseErrControl(good[0..n], &info);
}

test "recvBatch rejects an undersized slab instead of letting the kernel write past it" {
    // fd -1 is never reached: the size check runs before recvmmsg, which is
    // the whole point — the old `std.debug.assert` compiled out of
    // ReleaseFast/ReleaseSmall and the kernel wrote `batch_max * slot_size`
    // bytes into a slab that was shorter than that.
    const sock: Socket = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 1 };

    const slot_size = 64;
    var short: [batch_max * slot_size - 1]u8 = undefined;
    var b: RecvBatch = .{ .slab = &short, .slot_size = slot_size };
    try std.testing.expectError(error.SlabTooSmall, sock.recvBatch(&b));
}

test "A1 F1/m30: sendMany reports too many packets as an error, not an assert" {
    // fd -1 is never reached: the length check runs before any iovs/msgs
    // are built or any syscall is made -- the whole point, mirroring
    // `recvBatch`'s slab check above. The OLD code
    // (`std.debug.assert(addrs.len == packets.len and packets.len <=
    // batch_max)`) panicked in Debug/ReleaseSafe and, measured 2026-09-05,
    // SIGSEGV'd in ReleaseFast by indexing the two fixed `[batch_max]`
    // stack arrays with `packets.len` (64) past their real size (16).
    const sock: Socket = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 1 };

    var addr: linux.sockaddr.in = .{ .port = 0, .addr = 0 };
    const addr_ptr: *const linux.sockaddr = @ptrCast(&addr);
    var addrs: [batch_max + 1]*const linux.sockaddr = undefined;
    var pkts: [batch_max + 1][]const u8 = undefined;
    const one_packet = "x";
    for (0..addrs.len) |i| {
        addrs[i] = addr_ptr;
        pkts[i] = one_packet;
    }
    try std.testing.expectError(
        error.TooManyPackets,
        sock.sendMany(&addrs, @sizeOf(linux.sockaddr.in), &pkts),
    );

    // Mismatched lengths, still within batch_max -- the second half of the
    // old assert's condition.
    try std.testing.expectError(
        error.TooManyPackets,
        sock.sendMany(addrs[0..2], @sizeOf(linux.sockaddr.in), pkts[0..1]),
    );

    // Positive control: exactly batch_max, matching lengths -- must reach
    // the syscall, which then fails on the bogus fd (not TooManyPackets).
    // The point here is which error comes back, not a successful send.
    const result = sock.sendMany(addrs[0..batch_max], @sizeOf(linux.sockaddr.in), pkts[0..batch_max]);
    try std.testing.expectEqual(@as(usize, 0), try result);
}

test "A1 F6: a RAW socket's ident is drawn from the kernel CSPRNG, not the process id" {
    // Old code: `self.ident = @intCast(linux.getpid() & 0xffff)`. Two RAW
    // sockets opened back-to-back by this SAME test process share a PID, so
    // under the old code they would get the IDENTICAL ident -- the whole
    // problem (measured live 2026-09-05: 299/299 consecutive idents on a
    // busy host differ from a neighboring process's by exactly 1, because
    // it is really just the PID). A real 16-bit CSPRNG draw makes two
    // sockets collide with probability 1/65536; this test accepts that
    // vanishingly small flake rather than mocking the syscall.
    var s1 = Socket.open(.v4, .raw, .{}) catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer s1.close();
    var s2 = Socket.open(.v4, .raw, .{}) catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer s2.close();

    try std.testing.expect(s1.ident != s2.ident);
}
