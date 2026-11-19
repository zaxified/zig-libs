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
    var e = self.sendOnce(addr, addr_len, packet);
    // `open` sets IP_RECVERR (A1 F5), and with it the kernel also stores
    // every ICMP error about ANY earlier probe in the socket's pending error
    // (sk_err), raw and ping sockets alike: the next send fails with it once
    // -- EHOSTUNREACH for a Time Exceeded or Host Unreachable, EACCES for
    // Administratively Prohibited, ... -- though it is not that send's
    // error, and that probe is lost. Measured 2026-10-31 (ping socket, a
    // netns, nft rejecting echoes to 127.0.0.2 with host-unreachable): the
    // next send to 127.0.0.1 failed EHOSTUNREACH, the one after went out;
    // without IP_RECVERR neither failed. The failed send cleared sk_err (the
    // error stays on the error queue for `recvErr`), so one retry sends the
    // probe; a send that fails again has an error of its own.
    if (icmpReportedErrno(e)) e = self.sendOnce(addr, addr_len, packet);
    return sendResult(e);
}

/// The `SendError` a send's errno stands for (a pure table, so it is tested
/// without provoking each errno from the kernel).
fn sendResult(e: linux.E) SendError!void {
    switch (e) {
        .SUCCESS => {},
        .AGAIN, .NOBUFS => return error.WouldBlock,
        .NETUNREACH, .NETDOWN => return error.NetworkUnreachable,
        .HOSTUNREACH, .HOSTDOWN => return error.HostUnreachable,
        .ACCES, .PERM => return error.PermissionDenied,
        .MSGSIZE => return error.MessageTooLong,
        else => return error.Unexpected,
    }
}

fn sendOnce(self: *const Socket, addr: *const linux.sockaddr, addr_len: linux.socklen_t, packet: []const u8) linux.E {
    const rc = if (self.oiface_index != 0)
        self.sendmsgPktinfo(addr, addr_len, packet)
    else
        linux.sendto(self.fd, packet.ptr, packet.len, linux.MSG.NOSIGNAL, addr, addr_len);
    return linux.errno(rc);
}

/// The errnos the kernel turns ICMP errors into (`icmp_err_convert`,
/// `icmpv6_err_convert`): what a pending sk_err from an earlier probe's
/// ICMP error surfaces as on the next send.
fn icmpReportedErrno(e: linux.E) bool {
    return switch (e) {
        .NETUNREACH, .HOSTUNREACH, .HOSTDOWN, .CONNREFUSED, .ACCES, .MSGSIZE, .NOPROTOOPT, .OPNOTSUPP, .NONET, .PROTO => true,
        else => false,
    };
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
    // `sa_family` is native-endian, unlike the port and address after it.
    const af = std.mem.bytesToValue(u16, storage[0..2]);
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
    /// `ee_info`: for a Fragmentation Needed (ICMPv4 type 3 code 4) and a
    /// Packet Too Big (ICMPv6 type 2) the next-hop MTU; also the path MTU
    /// of a local `EMSGSIZE`. Other errors leave it at whatever the kernel
    /// put there (usually 0), so read it only for those types.
    ee_info: u32 = 0,
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
            info.ee_info = ee.ee_info;
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
        const cmsg = std.mem.bytesToValue(linux.cmsghdr, control[off..][0..hdr_len]);
        // `cmsg.len` is untrusted: compare against the room left, never add
        // it to `off` (wraps for a lying length).
        if (cmsg.len < hdr_len or cmsg.len > control.len - off) break;
        const data = control[off + hdr_len .. off + cmsg.len];

        if (cmsg.level == linux.SOL.SOCKET and cmsg.type == linux.SO.TIMESTAMPNS_OLD) {
            if (data.len >= @sizeOf(linux.timespec)) {
                const ts = std.mem.bytesToValue(linux.timespec, data[0..@sizeOf(linux.timespec)]);
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

        // CMSG_NXTHDR: advance by len rounded up to cmsghdr alignment; a
        // step past the end ends the walk.
        const step = std.mem.alignForward(usize, cmsg.len, cmsg_align);
        if (step > control.len - off) break;
        off += step;
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

test "parseSrc: a native sockaddr is recognised on either byte order (big-endian MIPS got .none)" {
    const v4: linux.sockaddr.in = .{ .port = 0, .addr = 0x01020304 };
    switch (parseSrcSlice(std.mem.asBytes(&v4))) {
        .v4 => |a| try std.testing.expectEqual(v4.addr, a.addr),
        else => return error.TestUnexpectedResult,
    }
    const v6: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(7), .scope_id = 0 };
    switch (parseSrcSlice(std.mem.asBytes(&v6))) {
        .v6 => |a| try std.testing.expectEqual(v6.addr, a.addr),
        else => return error.TestUnexpectedResult,
    }
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

test "sendTo: an earlier probe's ICMP error does not fail the next send (sk_err retry)" {
    // Needs a ping socket and, to forge the router's error, a raw one
    // (CAP_NET_RAW, e.g. root in `unshare -rn`); skipped otherwise.
    var sock = Socket.open(.v4, .dgram, .{}) catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer sock.close();
    var injector = Socket.open(.v4, .raw, .{}) catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer injector.close();
    const lo: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 127, 0, 0, 1 }) };
    // Loopback must be up (a fresh netns has it down).
    var probe: [16]u8 = @splat(0);
    probe[0] = 8; // echo request; the kernel fills ident and checksum
    sock.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), &probe) catch return error.SkipZigTest;

    // A forged Host Unreachable about one of our probes to 10.9.9.77.
    var pkt: [8 + 20 + 8]u8 = @splat(0);
    pkt[0] = 3; // destination unreachable
    pkt[1] = 1; // host unreachable
    pkt[8] = 0x45;
    pkt[8 + 8] = 64;
    pkt[8 + 9] = 1; // quoted protocol ICMP: routes it to the ping socket
    pkt[8 + 12 ..][0..4].* = .{ 127, 0, 0, 1 };
    pkt[8 + 16 ..][0..4].* = .{ 10, 9, 9, 77 };
    pkt[8 + 20] = 8; // the quoted echo request
    std.mem.writeInt(u16, pkt[8 + 20 + 4 ..][0..2], sock.ident, .big);
    std.mem.writeInt(u16, pkt[8 + 20 + 6 ..][0..2], 7, .big);
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < pkt.len) : (i += 2) sum += std.mem.readInt(u16, pkt[i..][0..2], .big);
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    std.mem.writeInt(u16, pkt[2..4], @truncate(~sum), .big);
    try injector.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), &pkt);
    const ts: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
    _ = linux.nanosleep(&ts, null);

    // The error is pending: this send used to fail with EHOSTUNREACH.
    try sock.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), &probe);
    // And it is still on the error queue, about 10.9.9.77.
    var buf: [64]u8 = undefined;
    var info: ?ErrInfo = null;
    for (0..8) |_| {
        info = sock.recvErr(&buf);
        if (info) |e| if (e.err_type == 3) break;
    }
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u8, 3), info.?.err_type);
    try std.testing.expectEqualSlices(u8, &.{ 10, 9, 9, 77 }, std.mem.asBytes(&info.?.src.v4.addr));
}

test "icmpReportedErrno: the errnos ICMP errors become, nothing else" {
    for ([_]linux.E{ .NETUNREACH, .HOSTUNREACH, .HOSTDOWN, .CONNREFUSED, .ACCES, .MSGSIZE, .NOPROTOOPT, .OPNOTSUPP, .NONET, .PROTO }) |e|
        try std.testing.expect(icmpReportedErrno(e));
    for ([_]linux.E{ .SUCCESS, .AGAIN, .NOBUFS, .PERM, .INVAL, .BADF, .NETDOWN }) |e|
        try std.testing.expect(!icmpReportedErrno(e));
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

// ── whole-module mutation audit (2026-11-17): option, ancillary-data and
// loopback tests. A ping socket needs `net.ipv4.ping_group_range`; every test
// that needs one skips when `open` says it cannot have one.

/// Can this process make a ping socket at all? Asked of the kernel directly,
/// so a refusal from `open` itself (a mutated mode switch, a wrong domain) is
/// a failure and not a skip.
fn pingAvailable(family: Family) bool {
    const rc = linux.socket(switch (family) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    }, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, switch (family) {
        .v4 => linux.IPPROTO.ICMP,
        .v6 => linux.IPPROTO.ICMPV6,
    });
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Can this process make a RAW ICMP socket (CAP_NET_RAW)?
fn rawAvailable() bool {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.IPPROTO.ICMP);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Can this process set SO_MARK (CAP_NET_ADMIN)?
fn markSettable() bool {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const mark: u32 = 0x1234;
    return linux.errno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.MARK, @ptrCast(&mark), @sizeOf(u32))) == .SUCCESS;
}

fn openOrSkip(family: Family, mode: Mode, opts: Options) !Socket {
    if (!pingAvailable(family)) return error.SkipZigTest;
    return Socket.open(family, mode, opts);
}

fn getOptU32(fd: i32, level: i32, opt: u32) !u32 {
    var v: u32 = 0;
    var len: linux.socklen_t = @sizeOf(u32);
    if (linux.errno(linux.getsockopt(fd, level, opt, @ptrCast(&v), &len)) != .SUCCESS) return error.TestUnexpectedResult;
    return v;
}

fn loopback4() linux.sockaddr.in {
    return .{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 127, 0, 0, 1 }) };
}

test "open v4: every option and ancillary request reaches the kernel" {
    var s = try openOrSkip(.v4, .dgram, .{ .recv_buf_size = 8192, .ttl = 77, .tos = 0x28, .dont_fragment = true });
    defer s.close();
    try std.testing.expectEqual(Kind.dgram, s.kind);
    try std.testing.expect(s.ident != 0);
    try std.testing.expectEqual(@as(u32, 77), try getOptU32(s.fd, linux.SOL.IP, linux.IP.TTL));
    try std.testing.expectEqual(@as(u32, 0x28), try getOptU32(s.fd, linux.SOL.IP, linux.IP.TOS));
    try std.testing.expectEqual(@as(u32, linux.IP.PMTUDISC_DO), try getOptU32(s.fd, linux.SOL.IP, linux.IP.MTU_DISCOVER));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.IP, linux.IP.RECVTTL));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.IP, linux.IP.RECVTOS));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.IP, linux.IP.RECVERR));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD));
    // The kernel doubles a requested receive buffer: 8 KiB asked, 16 KiB held.
    try std.testing.expectEqual(@as(u32, 16384), try getOptU32(s.fd, linux.SOL.SOCKET, linux.SO.RCVBUF));

    // No option given: kernel defaults (TTL 64, no DF, default receive buffer),
    // and `recv_buf_size = 0` means "leave it".
    var d = try openOrSkip(.v4, .dgram, .{ .recv_buf_size = 0 });
    defer d.close();
    try std.testing.expect((try getOptU32(d.fd, linux.SOL.IP, linux.IP.TTL)) != 77);
    try std.testing.expect((try getOptU32(d.fd, linux.SOL.IP, linux.IP.MTU_DISCOVER)) != linux.IP.PMTUDISC_DO);
    try std.testing.expect((try getOptU32(d.fd, linux.SOL.SOCKET, linux.SO.RCVBUF)) > 100_000);
}

test "open v6: every option and ancillary request reaches the kernel" {
    var s = try openOrSkip(.v6, .dgram, .{ .ttl = 77, .tos = 0x28, .dont_fragment = true });
    defer s.close();
    try std.testing.expectEqual(@as(u32, 77), try getOptU32(s.fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS));
    try std.testing.expectEqual(@as(u32, 0x28), try getOptU32(s.fd, linux.SOL.IPV6, linux.IPV6.TCLASS));
    try std.testing.expectEqual(@as(u32, linux.IPV6.PMTUDISC_DO), try getOptU32(s.fd, linux.SOL.IPV6, linux.IPV6.MTU_DISCOVER));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.IPV6, linux.IPV6.RECVHOPLIMIT));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.IPV6, linux.IPV6.RECVTCLASS));
    try std.testing.expectEqual(@as(u32, 1), try getOptU32(s.fd, linux.SOL.IPV6, linux.IPV6.RECVERR));
    var d = try openOrSkip(.v6, .dgram, .{});
    defer d.close();
    try std.testing.expect((try getOptU32(d.fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS)) != 77);
    try std.testing.expect((try getOptU32(d.fd, linux.SOL.IPV6, linux.IPV6.MTU_DISCOVER)) != linux.IPV6.PMTUDISC_DO);
}

test "open: mode, source, interface and outgoing-interface options" {
    // Mode: dgram and auto yield a ping socket; raw yields a raw one or a refusal.
    var a = try openOrSkip(.v4, .auto, .{});
    defer a.close();
    try std.testing.expectEqual(Kind.dgram, a.kind);
    var dg = try openOrSkip(.v4, .dgram, .{});
    defer dg.close();
    try std.testing.expectEqual(Kind.dgram, dg.kind);
    if (Socket.open(.v4, .raw, .{})) |r| {
        var rr = r;
        defer rr.close();
        try std.testing.expectEqual(Kind.raw, rr.kind);
    } else |err| {
        try std.testing.expect(!rawAvailable()); // a refusal only where the kernel refuses
        try std.testing.expectEqual(error.PermissionDenied, err);
    }

    // A source address is bound; the ident is the bound port; pktinfo keeps it.
    var s = try openOrSkip(.v4, .dgram, .{ .source = .{ .v4 = loopback4() }, .oiface_index = 1 });
    defer s.close();
    try std.testing.expectEqual(loopback4().addr, s.pktinfo_src4);
    try std.testing.expectEqual(@as(u32, 1), s.oiface_index);
    var sa: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockname(s.fd, @ptrCast(&sa), &len)));
    try std.testing.expectEqual(loopback4().addr, sa.addr);
    try std.testing.expect(s.ident != 0);
    try std.testing.expectEqual(std.mem.bigToNative(u16, sa.port), s.ident);

    // A plain open binds a wildcard just to learn the ident; nothing is stored.
    try std.testing.expectEqual(@as(u32, 0), a.oiface_index);
    try std.testing.expectEqual(@as(u32, 0), a.pktinfo_src4);
    try std.testing.expect(a.ident != 0);

    // A source of the other family, or one that is not local, is refused.
    try std.testing.expectError(error.SourceAddressBind, Socket.open(.v4, .dgram, .{ .source = .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 } } }));
    const v6_other = Socket.open(.v6, .dgram, .{ .source = .{ .v4 = loopback4() } });
    if (v6_other) |o| {
        var oo = o;
        oo.close();
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.SourceAddressBind => {},
        error.AddressFamilyUnsupported => {},
        else => return err,
    }
    const away: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 192, 0, 2, 55 }) };
    try std.testing.expectError(error.SourceAddressBind, Socket.open(.v4, .dgram, .{ .source = .{ .v4 = away } }));

    // SO_BINDTODEVICE: an unknown name is refused, `lo` is bound.
    try std.testing.expectError(error.InterfaceBind, Socket.open(.v4, .dgram, .{ .iface = "nonexist0" }));
    if (Socket.open(.v4, .dgram, .{ .iface = "lo" })) |b| {
        var bb = b;
        defer bb.close();
        var name: [16]u8 = @splat(0);
        var nl: linux.socklen_t = name.len;
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockopt(bb.fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, &name, &nl)));
        try std.testing.expectEqualStrings("lo", name[0..2]);
    } else |err| try std.testing.expectEqual(error.InterfaceBind, err); // an environment that forbids it

    // SO_MARK needs CAP_NET_ADMIN; where the kernel allows it the mark must be set.
    var m = try openOrSkip(.v4, .dgram, .{ .fwmark = 0x1234 });
    defer m.close();
    const got = try getOptU32(m.fd, linux.SOL.SOCKET, linux.SO.MARK);
    if (markSettable()) try std.testing.expectEqual(@as(u32, 0x1234), got) else try std.testing.expectEqual(@as(u32, 0), got);
}

test "sendResult maps every send errno, and only those" {
    try sendResult(.SUCCESS);
    const table = [_]struct { e: linux.E, want: SendError }{
        .{ .e = .AGAIN, .want = error.WouldBlock },
        .{ .e = .NOBUFS, .want = error.WouldBlock },
        .{ .e = .NETUNREACH, .want = error.NetworkUnreachable },
        .{ .e = .NETDOWN, .want = error.NetworkUnreachable },
        .{ .e = .HOSTUNREACH, .want = error.HostUnreachable },
        .{ .e = .HOSTDOWN, .want = error.HostUnreachable },
        .{ .e = .ACCES, .want = error.PermissionDenied },
        .{ .e = .PERM, .want = error.PermissionDenied },
        .{ .e = .MSGSIZE, .want = error.MessageTooLong },
        .{ .e = .INVAL, .want = error.Unexpected },
        .{ .e = .BADF, .want = error.Unexpected },
    };
    for (table) |t| try std.testing.expectError(t.want, sendResult(t.e));
}

test "buildPktinfo lays out the IP_PKTINFO / IPV6_PKTINFO control message exactly" {
    const hdr_len = @sizeOf(linux.cmsghdr);
    var control: [64]u8 align(@alignOf(linux.cmsghdr)) = @splat(0xAA);
    var s4: Socket = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0, .oiface_index = 7, .pktinfo_src4 = 0x0a0b0c0d };
    const n4 = s4.buildPktinfo(&control);
    try std.testing.expectEqual(std.mem.alignForward(usize, hdr_len + @sizeOf(linux.in_pktinfo), @alignOf(linux.cmsghdr)), n4);
    const h4: *const linux.cmsghdr = @ptrCast(&control);
    try std.testing.expectEqual(hdr_len + @sizeOf(linux.in_pktinfo), h4.len);
    try std.testing.expectEqual(@as(i32, linux.SOL.IP), h4.level);
    try std.testing.expectEqual(@as(i32, linux.IP.PKTINFO), h4.type);
    const p4 = std.mem.bytesToValue(linux.in_pktinfo, control[hdr_len..][0..@sizeOf(linux.in_pktinfo)]);
    try std.testing.expectEqual(@as(i32, 7), p4.ifindex);
    try std.testing.expectEqual(@as(u32, 0x0a0b0c0d), p4.spec_dst);
    try std.testing.expectEqual(@as(u32, 0), p4.addr);

    control = @splat(0xAA);
    var s6: Socket = .{ .fd = -1, .family = .v6, .kind = .dgram, .ident = 0, .oiface_index = 9 };
    const n6 = s6.buildPktinfo(&control);
    try std.testing.expectEqual(std.mem.alignForward(usize, hdr_len + @sizeOf(linux.in6_pktinfo), @alignOf(linux.cmsghdr)), n6);
    const h6: *const linux.cmsghdr = @ptrCast(&control);
    try std.testing.expectEqual(hdr_len + @sizeOf(linux.in6_pktinfo), h6.len);
    try std.testing.expectEqual(@as(i32, linux.SOL.IPV6), h6.level);
    try std.testing.expectEqual(@as(i32, linux.IPV6.PKTINFO), h6.type);
    const p6 = std.mem.bytesToValue(linux.in6_pktinfo, control[hdr_len..][0..@sizeOf(linux.in6_pktinfo)]);
    try std.testing.expectEqual(@as(i32, 9), p6.ifindex);
    try std.testing.expectEqual(@as([16]u8, @splat(0)), p6.addr);
}

/// Append one cmsg (header + `data`) to `buf` at `off`; returns the aligned end.
fn putCmsg(buf: []u8, off: usize, level: i32, typ: i32, data: []const u8) usize {
    const hdr_len = @sizeOf(linux.cmsghdr);
    const hdr: linux.cmsghdr = .{ .len = hdr_len + data.len, .level = level, .type = typ };
    @memcpy(buf[off..][0..hdr_len], std.mem.asBytes(&hdr));
    @memcpy(buf[off + hdr_len ..][0..data.len], data);
    return off + std.mem.alignForward(usize, hdr_len + data.len, @alignOf(linux.cmsghdr));
}

fn u32le(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    return b;
}

test "parseControl: TTL, TOS, hop limit, traffic class and the kernel timestamp, back to back" {
    var buf: [256]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const ts: linux.timespec = .{ .sec = 5, .nsec = 7 };
    // TOS is 1 data byte (cmsg len 17, step 24): the timestamp after it is
    // found only if the walk steps by the aligned length.
    var end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TTL, &u32le(64));
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IP.TOS, &[_]u8{0x2e});
    end = putCmsg(&buf, end, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD, std.mem.asBytes(&ts));
    var info: RecvInfo = .{ .packet = &.{} };
    parseControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(?u8, 64), info.ttl);
    try std.testing.expectEqual(@as(?u8, 0x2e), info.tos);
    try std.testing.expectEqual(@as(?i64, 5 * std.time.ns_per_s + 7), info.timestamp_real_ns);

    buf = @splat(0);
    end = putCmsg(&buf, 0, linux.SOL.IPV6, linux.IPV6.HOPLIMIT, &u32le(55));
    end = putCmsg(&buf, end, linux.SOL.IPV6, linux.IPV6.TCLASS, &u32le(0xb8));
    info = .{ .packet = &.{} };
    parseControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(?u8, 55), info.ttl);
    try std.testing.expectEqual(@as(?u8, 0xb8), info.tos);
    try std.testing.expectEqual(@as(?i64, null), info.timestamp_real_ns);
}

test "parseControl: the level, the data length and the cmsg bounds are each checked" {
    var buf: [256]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    var info: RecvInfo = .{ .packet = &.{} };
    // The right type at the wrong level is not it.
    var end = putCmsg(&buf, 0, linux.SOL.IPV6, linux.IP.TTL, &u32le(9));
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IPV6.HOPLIMIT, &u32le(9));
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IPV6.TCLASS, &u32le(9));
    end = putCmsg(&buf, end, linux.SOL.SOCKET, linux.IP.TOS, &[_]u8{9});
    parseControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(?u8, null), info.ttl);
    try std.testing.expectEqual(@as(?u8, null), info.tos);

    // One byte short of its payload: not read.
    buf = @splat(0);
    info = .{ .packet = &.{} };
    end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TTL, &[_]u8{ 64, 0, 0 });
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IP.TOS, &.{});
    end = putCmsg(&buf, end, linux.SOL.IPV6, linux.IPV6.HOPLIMIT, &[_]u8{ 1, 0, 0 });
    end = putCmsg(&buf, end, linux.SOL.IPV6, linux.IPV6.TCLASS, &[_]u8{ 1, 0, 0 });
    end = putCmsg(&buf, end, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD, &@as([15]u8, @splat(0)));
    parseControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(?u8, null), info.ttl);
    try std.testing.expectEqual(@as(?u8, null), info.tos);
    try std.testing.expectEqual(@as(?i64, null), info.timestamp_real_ns);

    // Exactly sized payloads (no padding, no slack) are read, at the very end of the buffer.
    buf = @splat(0);
    info = .{ .packet = &.{} };
    _ = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TTL, &u32le(33));
    parseControl(buf[0 .. @sizeOf(linux.cmsghdr) + 4], &info);
    try std.testing.expectEqual(@as(?u8, 33), info.ttl);
    buf = @splat(0);
    info = .{ .packet = &.{} };
    const ts: linux.timespec = .{ .sec = 1, .nsec = 2 };
    _ = putCmsg(&buf, 0, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD, std.mem.asBytes(&ts));
    parseControl(buf[0 .. @sizeOf(linux.cmsghdr) + @sizeOf(linux.timespec)], &info);
    try std.testing.expectEqual(@as(?i64, std.time.ns_per_s + 2), info.timestamp_real_ns);
    // A one-byte TOS at the end of the buffer.
    buf = @splat(0);
    info = .{ .packet = &.{} };
    _ = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TOS, &[_]u8{0x10});
    parseControl(buf[0 .. @sizeOf(linux.cmsghdr) + 1], &info);
    try std.testing.expectEqual(@as(?u8, 0x10), info.tos);

    // A cmsg shorter than its own header ends the walk without a slice panic;
    // a header-only cmsg (len == header) is skipped and the walk goes on.
    buf = @splat(0);
    info = .{ .packet = &.{} };
    const stub: linux.cmsghdr = .{ .len = 4, .level = linux.SOL.IP, .type = linux.IP.TTL };
    @memcpy(buf[0..@sizeOf(linux.cmsghdr)], std.mem.asBytes(&stub));
    parseControl(buf[0..64], &info);
    try std.testing.expectEqual(@as(?u8, null), info.ttl);
    buf = @splat(0);
    end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TOS, &.{});
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IP.TTL, &u32le(12));
    parseControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(?u8, 12), info.ttl);
}

test "parseErrControl: both families, exact sizes, wrong levels and the aligned walk" {
    var buf: [256]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const ee: sock_extended_err = .{ .ee_errno = 113, .ee_origin = origin_icmp, .ee_type = 3, .ee_code = 1, .ee_pad = 0, .ee_info = 0, .ee_data = 0 };
    const ee_bytes = std.mem.asBytes(&ee);
    var info: ErrInfo = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };

    // v6 level, exactly sock_extended_err (no offender): read; type != code.
    var end = putCmsg(&buf, 0, linux.SOL.IPV6, linux.IPV6.RECVERR, ee_bytes);
    parseErrControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(u8, 3), info.err_type);
    try std.testing.expectEqual(@as(u8, 1), info.err_code);
    try std.testing.expectEqual(origin_icmp, info.origin);
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, info.offender);

    // Wrong level/type combinations carrying the same payload are not it.
    buf = @splat(0);
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TTL, ee_bytes);
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IPV6.RECVERR, ee_bytes);
    end = putCmsg(&buf, end, linux.SOL.IPV6, linux.IP.RECVERR, ee_bytes);
    end = putCmsg(&buf, end, linux.SOL.SOCKET, linux.IP.RECVERR, ee_bytes);
    parseErrControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(u8, 0), info.err_type);
    try std.testing.expectEqual(@as(u8, 0), info.origin);

    // One byte short of sock_extended_err: ignored, no read past the data.
    buf = @splat(0);
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.RECVERR, ee_bytes[0 .. ee_bytes.len - 1]);
    parseErrControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(u8, 0), info.err_type);

    // A cmsg shorter than its header ends the walk; a header-only cmsg is
    // skipped and the one behind it is read.
    buf = @splat(0);
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    const stub: linux.cmsghdr = .{ .len = 4, .level = linux.SOL.IP, .type = linux.IP.RECVERR };
    @memcpy(buf[0..@sizeOf(linux.cmsghdr)], std.mem.asBytes(&stub));
    parseErrControl(buf[0..64], &info);
    try std.testing.expectEqual(@as(u8, 0), info.err_type);
    buf = @splat(0);
    end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TTL, &.{});
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IP.RECVERR, ee_bytes);
    parseErrControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(u8, 3), info.err_type);

    // Two messages, the first with an unaligned length (16-byte header + 16
    // + 4 offender bytes = 36, step 40): the second is found at the aligned offset.
    buf = @splat(0);
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    var ee2 = ee;
    ee2.ee_type = 11;
    var data1: [20]u8 = @splat(0);
    @memcpy(data1[0..16], ee_bytes);
    end = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.RECVERR, &data1);
    end = putCmsg(&buf, end, linux.SOL.IP, linux.IP.RECVERR, std.mem.asBytes(&ee2));
    parseErrControl(buf[0..end], &info);
    try std.testing.expectEqual(@as(u8, 11), info.err_type);
}

test "parseControl: a lying cmsg_len after a good cmsg ends the walk without overflow" {
    // `off + cmsg.len` wrapped for a huge length once `off > 0`; the length is
    // now compared against the room left, as the kernel's CMSG_NXTHDR does.
    var buf: [128]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const hdr_len = @sizeOf(linux.cmsghdr);
    const lies = [_]usize{
        std.math.maxInt(usize), // off + len wraps to off - 1
        std.math.maxInt(usize) - hdr_len, // off + len wraps past zero
        std.math.maxInt(usize) - 2, // alignForward would wrap
        std.math.maxInt(usize) / 2,
        hdr_len - 1, // shorter than its own header
    };
    for (lies) |lie| {
        buf = @splat(0);
        var info: RecvInfo = .{ .packet = &.{} };
        const off = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TTL, &u32le(7));
        const bad: linux.cmsghdr = .{ .len = lie, .level = linux.SOL.IP, .type = linux.IP.TOS };
        @memcpy(buf[off..][0..hdr_len], std.mem.asBytes(&bad));
        // A valid TOS cmsg behind the lie must not be reached.
        _ = putCmsg(&buf, off + hdr_len, linux.SOL.IP, linux.IP.TOS, &[_]u8{0x20});
        parseControl(buf[0 .. off + 2 * hdr_len + 8], &info);
        try std.testing.expectEqual(@as(?u8, 7), info.ttl);
        try std.testing.expectEqual(@as(?u8, null), info.tos);
    }
}

test "parseControl: a cmsg whose aligned step leaves the buffer ends the walk" {
    // Declared length fits (data ends at the buffer end) but its aligned step
    // does not; the walk ends, the cmsg itself is still read.
    var buf: [64]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    var info: RecvInfo = .{ .packet = &.{} };
    _ = putCmsg(&buf, 0, linux.SOL.IP, linux.IP.TOS, &[_]u8{0x10});
    parseControl(buf[0 .. @sizeOf(linux.cmsghdr) + 1], &info);
    try std.testing.expectEqual(@as(?u8, 0x10), info.tos);
}

test "parseErrControl: ee_info carries the next-hop MTU (v4 Frag Needed, v6 Packet Too Big)" {
    var buf: [128]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    var ee: sock_extended_err = .{
        .ee_errno = @backingInt(linux.E.MSGSIZE),
        .ee_origin = origin_icmp,
        .ee_type = 3, // Destination Unreachable
        .ee_code = 4, // Fragmentation Needed
        .ee_pad = 0,
        .ee_info = 1400,
        .ee_data = 0,
    };
    const router: linux.sockaddr.in = .{ .port = 0, .addr = 0x0100000a };
    var info: ErrInfo = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    try std.testing.expectEqual(@as(u32, 0), info.ee_info);
    parseErrControl(testErrCmsg(&buf, linux.SOL.IP, linux.IP.RECVERR, ee, std.mem.asBytes(&router)), &info);
    try std.testing.expectEqual(@as(u32, 1400), info.ee_info);
    try std.testing.expectEqual(@as(u8, 4), info.err_code);

    ee.ee_origin = origin_icmp6;
    ee.ee_type = 2; // Packet Too Big
    ee.ee_code = 0;
    ee.ee_info = 0xfedc_ba98; // all four bytes are kept
    const router6: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(1), .scope_id = 0 };
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(testErrCmsg(&buf, linux.SOL.IPV6, linux.IPV6.RECVERR, ee, std.mem.asBytes(&router6)), &info);
    try std.testing.expectEqual(@as(u32, 0xfedc_ba98), info.ee_info);

    // A cmsg of another level never touches it.
    info = .{ .packet = &.{}, .err_type = 0, .err_code = 0 };
    parseErrControl(testErrCmsg(&buf, linux.SOL.SOCKET, linux.IP.RECVERR, ee, &.{}), &info);
    try std.testing.expectEqual(@as(u32, 0), info.ee_info);
}

test "parseSrc and parseSrcSlice: lengths decide, a long slice is clamped" {
    var st: [@sizeOf(linux.sockaddr.in6)]u8 align(8) = @splat(0);
    const v4a: linux.sockaddr.in = .{ .port = 0, .addr = 0x0100007f };
    @memcpy(st[0..@sizeOf(linux.sockaddr.in)], std.mem.asBytes(&v4a));
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, parseSrc(&st, @sizeOf(linux.sockaddr.in) - 1));
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, parseSrc(&st, 1));
    switch (parseSrc(&st, @sizeOf(linux.sockaddr.in))) {
        .v4 => |a| try std.testing.expectEqual(@as(u32, 0x0100007f), a.addr),
        else => return error.TestUnexpectedResult,
    }
    var v6a: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 };
    v6a.addr[15] = 1;
    @memcpy(st[0..@sizeOf(linux.sockaddr.in6)], std.mem.asBytes(&v6a));
    try std.testing.expectEqual(RecvInfo.SrcAddr.none, parseSrc(&st, @sizeOf(linux.sockaddr.in6) - 1));
    switch (parseSrc(&st, @sizeOf(linux.sockaddr.in6))) {
        .v6 => |a| try std.testing.expectEqual(@as(u8, 1), a.addr[15]),
        else => return error.TestUnexpectedResult,
    }
    // A slice longer than a sockaddr_in6 (an error cmsg's offender is followed by padding).
    var long: [40]u8 = @splat(0xEE);
    @memcpy(long[0..@sizeOf(linux.sockaddr.in6)], std.mem.asBytes(&v6a));
    switch (parseSrcSlice(&long)) {
        .v6 => |a| try std.testing.expectEqual(@as(u8, 1), a.addr[15]),
        else => return error.TestUnexpectedResult,
    }
}

/// Wait (bounded) until `recvMsg` yields a packet.
fn waitRecv(s: *const Socket, buf: []u8) !RecvInfo {
    for (0..300) |_| {
        if (s.recvMsg(buf)) |i| return i;
        const nap: linux.timespec = .{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
        _ = linux.nanosleep(&nap, null);
    }
    return error.SkipZigTest; // no reply: an environment without ICMP echo
}

fn echoProbe(seq: u16, len: usize, buf: []u8) []u8 {
    @memset(buf[0..len], 0);
    buf[0] = 8; // echo request; the kernel fills ident and checksum on a ping socket
    std.mem.writeInt(u16, buf[6..8], seq, .big);
    return buf[0..len];
}

test "a ping socket round-trips echoes over loopback: recvMsg, recvBatch, sendMany, pktinfo" {
    var s = try openOrSkip(.v4, .dgram, .{});
    defer s.close();
    const lo = loopback4();
    var pk: [16]u8 = undefined;
    var rb: [512]u8 = undefined;

    // Nothing queued: null, not a bogus slice.
    try std.testing.expect(s.recvMsg(&rb) == null);
    try std.testing.expect(s.recvErr(&rb) == null);

    s.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), echoProbe(1, 8, &pk)) catch return error.SkipZigTest;
    const info = try waitRecv(&s, &rb);
    try std.testing.expectEqual(@as(usize, 8), info.packet.len); // the packet, not the whole buffer
    try std.testing.expectEqual(@as(u8, 0), info.packet[0]); // echo reply
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, info.packet[6..8], .big));
    switch (info.src) {
        .v4 => |a| try std.testing.expectEqual(lo.addr, a.addr),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(?u8, 64), info.ttl);
    try std.testing.expect(info.tos != null);
    try std.testing.expect(info.timestamp_real_ns != null and info.timestamp_real_ns.? > 0);

    // A batch: three replies land in their own slots, each fully described.
    // slot_size 16 = the reply length, so a slot one byte short truncates.
    var slab: [batch_max * 16]u8 = undefined;
    var b: RecvBatch = .{ .slab = &slab, .slot_size = 16 };
    for ([_]u16{ 10, 11, 12 }) |seq| s.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), echoProbe(seq, 16, &pk)) catch return error.SkipZigTest;
    const nap: linux.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
    _ = linux.nanosleep(&nap, null);
    const got = try s.recvBatch(&b);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    for (got, [_]u16{ 10, 11, 12 }, 0..) |g, seq, i| {
        try std.testing.expectEqual(@intFromPtr(&slab) + i * 16, @intFromPtr(g.packet.ptr));
        try std.testing.expectEqual(@as(usize, 16), g.packet.len);
        try std.testing.expectEqual(seq, std.mem.readInt(u16, g.packet[6..8], .big));
        try std.testing.expect(g.src == .v4 and g.src.v4.addr == lo.addr);
        try std.testing.expectEqual(@as(?u8, 64), g.ttl);
        try std.testing.expect(g.timestamp_real_ns != null);
    }
    try std.testing.expectEqual(@as(usize, 0), (try s.recvBatch(&b)).len); // drained
    // An exactly sized slab is accepted, one byte less is not.
    var short: RecvBatch = .{ .slab = slab[0 .. slab.len - 1], .slot_size = 16 };
    try std.testing.expectError(error.SlabTooSmall, s.recvBatch(&short));

    // sendMany: all three go out; with an outgoing interface the pktinfo goes too.
    var p1: [16]u8 = undefined;
    var p2: [16]u8 = undefined;
    var p3: [16]u8 = undefined;
    const pkts = [_][]const u8{ echoProbe(20, 16, &p1), echoProbe(21, 16, &p2), echoProbe(22, 16, &p3) };
    const addrs = [_]*const linux.sockaddr{ @ptrCast(&lo), @ptrCast(&lo), @ptrCast(&lo) };
    try std.testing.expectEqual(@as(usize, 3), try s.sendMany(&addrs, @sizeOf(linux.sockaddr.in), &pkts));
    _ = linux.nanosleep(&nap, null);
    try std.testing.expectEqual(@as(usize, 3), (try s.recvBatch(&b)).len);
    s.oiface_index = 1; // lo
    s.pktinfo_src4 = lo.addr;
    try std.testing.expectEqual(@as(usize, 3), try s.sendMany(&addrs, @sizeOf(linux.sockaddr.in), &pkts));
    _ = linux.nanosleep(&nap, null);
    try std.testing.expectEqual(@as(usize, 3), (try s.recvBatch(&b)).len);
    s.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), echoProbe(30, 8, &pk)) catch return error.TestUnexpectedResult;
    _ = try waitRecv(&s, &rb);
    // A real outgoing interface is honoured; a nonexistent one is an error
    // from the kernel, on the single and the batched path alike.
    s.oiface_index = 99999;
    try std.testing.expect(std.meta.isError(s.sendTo(@ptrCast(&lo), @sizeOf(linux.sockaddr.in), echoProbe(31, 8, &pk))));
    try std.testing.expectEqual(@as(usize, 0), try s.sendMany(&addrs, @sizeOf(linux.sockaddr.in), &pkts));
}

test "recvErr returns the quoted destination, the ICMP error and its offender" {
    // A UDP socket with IP_RECVERR stands in for the ping socket: a datagram to
    // a closed port comes back as an ICMP port unreachable on the error queue.
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const on: u32 = 1;
    if (linux.errno(linux.setsockopt(fd, linux.SOL.IP, linux.IP.RECVERR, @ptrCast(&on), @sizeOf(u32))) != .SUCCESS) return error.SkipZigTest;
    const closed = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(closed) != .SUCCESS) return error.SkipZigTest;
    const cfd: i32 = @intCast(closed);
    var dst = loopback4();
    if (linux.errno(linux.bind(cfd, @ptrCast(&dst), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(cfd);
        return error.SkipZigTest;
    }
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(cfd, @ptrCast(&dst), &len);
    _ = linux.close(cfd); // nobody listens on that port now
    const payload = "quoted-payload";
    if (linux.errno(linux.sendto(fd, payload, payload.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;

    const s: Socket = .{ .fd = fd, .family = .v4, .kind = .dgram, .ident = 0 };
    var buf: [128]u8 = undefined;
    var info: ?ErrInfo = null;
    for (0..100) |_| {
        info = s.recvErr(&buf);
        if (info != null) break;
        const nap: linux.timespec = .{ .sec = 0, .nsec = 2 * std.time.ns_per_ms };
        _ = linux.nanosleep(&nap, null);
    }
    const e = info orelse return error.SkipZigTest;
    try std.testing.expectEqualStrings(payload, e.packet); // the quoted datagram, not the whole buffer
    try std.testing.expectEqual(@as(u8, 3), e.err_type); // destination unreachable
    try std.testing.expectEqual(@as(u8, 3), e.err_code); // port unreachable
    try std.testing.expectEqual(origin_icmp, e.origin);
    switch (e.src) {
        .v4 => |a| {
            try std.testing.expectEqual(dst.addr, a.addr);
            try std.testing.expectEqual(dst.port, a.port);
        },
        else => return error.TestUnexpectedResult,
    }
    switch (e.offender) {
        .v4 => |a| try std.testing.expectEqual(dst.addr, a.addr),
        else => return error.TestUnexpectedResult,
    }
}
