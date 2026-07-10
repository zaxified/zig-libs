// SPDX-License-Identifier: MIT
//! rawsock — Linux AF_PACKET raw-frame capture + inject.
//!
//! A minimal libpcap-shaped path to layer-2: open a `SOCK_RAW` capture socket
//! for one EtherType (or all frames), decode the kernel's `sockaddr_ll` into a
//! typed `Frame`, attach an in-kernel classic-BPF filter, toggle promiscuous
//! mode, and cook-inject frames on a named interface via a `SOCK_DGRAM`
//! socket. Interface enumeration (`SIOCGIFINDEX` / `SIOCGIFNAME` /
//! `SIOCGIFHWADDR`) rounds it out.
//!
//! Two layers, so the wire code is testable without privileges:
//!
//!  * Pure helpers — Ethernet header parse/build (`EthHeader`), hwaddr
//!    parse/format (`parseHwaddr` / `formatHwaddr`), classic-BPF instruction
//!    encoding (`bpf`, `etherTypeFilter`), `sockaddr_ll` decode
//!    (`LinkAddr.fromSockaddr`) and a seeded ARP request/reply codec — none of
//!    which touch a socket.
//!  * `Socket` — the AF_PACKET path: `open` (capture), `openInject` (cooked
//!    send), `recv` → `Frame`, `send` / `sendRaw`, `setFilter`, `setPromisc`,
//!    `close`.
//!
//! Linux-only by design (errno-encoded `std.os.linux` raw syscalls, no libc —
//! the same conscious ceiling as `icmp` / `netlink`). Needs `CAP_NET_RAW` to
//! open a socket; without it `open` returns a distinct `error.AccessDenied`.
//! IP addresses that surface (ARP) come back as sibling `netaddr.Ip` values.
//!
//! Basic usage:
//!
//! ```zig
//! const rawsock = @import("rawsock");
//!
//! var sock = try rawsock.Socket.open(rawsock.eth_p.arp, .{ .iface = "eth0" });
//! defer sock.close();
//! try sock.setFilter(&rawsock.etherTypeFilter(rawsock.eth_p.arp));
//!
//! var buf: [2048]u8 = undefined;
//! const frame = try sock.recv(&buf); // Frame{ bytes, ifindex, src_hwaddr, ... }
//! if (rawsock.EthHeader.parse(frame.bytes)) |eth| _ = eth.ethertype;
//! ```

const std = @import("std");
const builtin = @import("builtin");
const netaddr = @import("netaddr");

const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux)
        @compileError("rawsock is Linux-only (AF_PACKET raw syscalls, no portable fallback)");
}

pub const meta = .{
    .platform = .linux,
    .role = .both,
    .concurrency = .reentrant, // no shared state; one Socket per thread/loop
    .model_after = "libpcap (minimal AF_PACKET path); packet(7) + BPF UAPI",
    .deps = .{"netaddr"},
};

// ── EtherType constants ───────────────────────────────────────────────────────

/// Common EtherType values (host byte order), for `open` / `send` / filters.
/// `all` is the kernel's `ETH_P_ALL` — capture every frame regardless of type.
pub const eth_p = struct {
    pub const all: u16 = 0x0003; // ETH_P_ALL — every frame (already host order)
    pub const ip: u16 = 0x0800;
    pub const arp: u16 = 0x0806;
    pub const rarp: u16 = 0x8035;
    pub const vlan: u16 = 0x8100; // 802.1Q tag
    pub const ipv6: u16 = 0x86dd;
    pub const lldp: u16 = 0x88cc;
    pub const macsec: u16 = 0x88e5;
};

/// Length of an Ethernet II header: dst(6) + src(6) + ethertype(2).
pub const eth_hdr_len = 14;

/// Length of a hardware address in bytes (Ethernet).
pub const hwaddr_len = 6;

// ── pure: Ethernet header ─────────────────────────────────────────────────────

/// A decoded Ethernet II header. Pure — no socket required.
pub const EthHeader = struct {
    dst: [hwaddr_len]u8,
    src: [hwaddr_len]u8,
    /// EtherType in host byte order (e.g. `0x0806` for ARP). For an 802.1Q
    /// frame this is `0x8100`; the real type sits inside the VLAN tag.
    ethertype: u16,

    /// Decode the first 14 bytes of `frame`; null if the frame is too short.
    pub fn parse(frame: []const u8) ?EthHeader {
        if (frame.len < eth_hdr_len) return null;
        return .{
            .dst = frame[0..6].*,
            .src = frame[6..12].*,
            .ethertype = std.mem.readInt(u16, frame[12..14], .big),
        };
    }

    /// Serialize the header into `out` (big-endian ethertype).
    pub fn write(h: EthHeader, out: *[eth_hdr_len]u8) void {
        @memcpy(out[0..6], &h.dst);
        @memcpy(out[6..12], &h.src);
        std.mem.writeInt(u16, out[12..14], h.ethertype, .big);
    }
};

// ── pure: hardware-address text ───────────────────────────────────────────────

/// Length of a formatted hwaddr: "aa:bb:cc:dd:ee:ff".
pub const hwaddr_text_len = 17;

/// Format a 6-byte MAC as lowercase colon-separated hex into `buf`.
pub fn formatHwaddr(mac: [hwaddr_len]u8, buf: *[hwaddr_text_len]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch unreachable;
}

/// Parse "aa:bb:cc:dd:ee:ff" (or dash-separated) into a 6-byte MAC. Strict:
/// exactly six 2-hex-digit octets with a single separator between. Null on
/// anything malformed; never panics.
pub fn parseHwaddr(text: []const u8) ?[hwaddr_len]u8 {
    if (text.len != hwaddr_text_len) return null;
    const sep = text[2];
    if (sep != ':' and sep != '-') return null;
    var out: [hwaddr_len]u8 = undefined;
    var i: usize = 0;
    while (i < hwaddr_len) : (i += 1) {
        const off = i * 3;
        if (i > 0 and text[off - 1] != sep) return null;
        const hi = std.fmt.charToDigit(text[off], 16) catch return null;
        const lo = std.fmt.charToDigit(text[off + 1], 16) catch return null;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

// ── pure: sockaddr_ll decode ──────────────────────────────────────────────────

/// The link-layer address a frame arrived on, decoded from `sockaddr_ll`. The
/// seed read these fields ad hoc at the recv site; here they are a typed
/// result so the decode is unit-tested without a socket.
pub const LinkAddr = struct {
    /// Interface index the frame was seen on.
    ifindex: i32,
    /// EtherType in host byte order (`sll_protocol`).
    protocol: u16,
    /// `PACKET_HOST` / `PACKET_BROADCAST` / `PACKET_OUTGOING` / … (see `pkt`).
    pkttype: u8,
    /// Valid bytes of `hwaddr` (`sll_halen`; 6 for Ethernet, 0 for cooked).
    halen: u8,
    /// Source hardware address, zero-padded to 6 bytes.
    hwaddr: [hwaddr_len]u8,

    pub fn fromSockaddr(sll: linux.sockaddr.ll) LinkAddr {
        var mac: [hwaddr_len]u8 = @splat(0);
        const n = @min(@as(usize, sll.halen), hwaddr_len);
        @memcpy(mac[0..n], sll.addr[0..n]);
        return .{
            .ifindex = sll.ifindex,
            .protocol = std.mem.bigToNative(u16, sll.protocol),
            .pkttype = sll.pkttype,
            .halen = sll.halen,
            .hwaddr = mac,
        };
    }
};

/// `sockaddr_ll.sll_pkttype` values (which direction / addressee a frame is).
pub const pkt = struct {
    pub const host = linux.PACKET.HOST;
    pub const broadcast = linux.PACKET.BROADCAST;
    pub const multicast = linux.PACKET.MULTICAST;
    pub const otherhost = linux.PACKET.OTHERHOST;
    pub const outgoing = linux.PACKET.OUTGOING;
};

// ── pure: classic BPF ─────────────────────────────────────────────────────────

/// One classic-BPF instruction (`struct sock_filter`). 8 bytes, fixed layout.
pub const BpfInsn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// `struct sock_fprog` — the program vector handed to `SO_ATTACH_FILTER`.
const SockFprog = extern struct {
    len: u16,
    filter: [*]const BpfInsn,
};

/// Classic-BPF opcode building blocks (`<linux/bpf_common.h>` values) plus two
/// tiny constructors, so filter programs are assembled — and asserted — in
/// pure code. `code` is an OR of a class + size/op + mode/source.
pub const bpf = struct {
    // instruction class
    pub const ld: u16 = 0x00; // load into accumulator
    pub const jmp: u16 = 0x05; // conditional jump
    pub const ret: u16 = 0x06; // return (accept N bytes / drop on 0)
    // load size
    pub const w: u16 = 0x00; // word (32-bit)
    pub const h: u16 = 0x08; // halfword (16-bit)
    pub const b: u16 = 0x10; // byte
    // addressing mode
    pub const abs: u16 = 0x20; // fixed offset from frame start
    // jump operation
    pub const jeq: u16 = 0x10; // A == k
    // source
    pub const k: u16 = 0x00; // constant operand

    /// A non-jump statement (`jt`/`jf` unused).
    pub fn stmt(code: u16, imm: u32) BpfInsn {
        return .{ .code = code, .jt = 0, .jf = 0, .k = imm };
    }

    /// A jump: on match advance `jt`, else `jf` instructions.
    pub fn jump(code: u16, imm: u32, jt: u8, jf: u8) BpfInsn {
        return .{ .code = code, .jt = jt, .jf = jf, .k = imm };
    }
};

/// Build a classic-BPF program that accepts only frames whose outer EtherType
/// equals `ethertype` and drops the rest — the `ether proto X` filter, applied
/// in-kernel via `Socket.setFilter`. Pure and usable without a socket. Note it
/// matches the *outer* type, so 802.1Q-tagged frames read as `0x8100`.
pub fn etherTypeFilter(ethertype: u16) [4]BpfInsn {
    return .{
        bpf.stmt(bpf.ld | bpf.h | bpf.abs, 12), // A = ethertype halfword at offset 12
        bpf.jump(bpf.jmp | bpf.jeq | bpf.k, ethertype, 0, 1), // if A == type: accept else drop
        bpf.stmt(bpf.ret | bpf.k, 0x40000), // accept up to 256 KiB
        bpf.stmt(bpf.ret | bpf.k, 0), // drop
    };
}

// ── pure: ARP codec (surfaces netaddr.Ip) ─────────────────────────────────────

/// Minimal ARP-over-Ethernet codec (IPv4): `buildArpRequest` /
/// `parseArpReply`. IP addresses surface as sibling `netaddr.Ip` values.
/// Pure — no socket required.
pub const arp = struct {
    /// Total length of an ARP-request Ethernet frame (header + ARP body).
    pub const request_len = 42;

    /// Build a broadcast ARP request "who-has `target_ip`, tell `src_ip`".
    pub fn buildRequest(src_mac: [hwaddr_len]u8, src_ip: [4]u8, target_ip: [4]u8) [request_len]u8 {
        var f: [request_len]u8 = @splat(0);
        @memset(f[0..6], 0xff); // Ethernet dst = broadcast
        @memcpy(f[6..12], &src_mac); // Ethernet src
        std.mem.writeInt(u16, f[12..14], eth_p.arp, .big); // EtherType = ARP
        std.mem.writeInt(u16, f[14..16], 0x0001, .big); // htype = Ethernet
        std.mem.writeInt(u16, f[16..18], eth_p.ip, .big); // ptype = IPv4
        f[18] = hwaddr_len; // hlen
        f[19] = 4; // plen
        std.mem.writeInt(u16, f[20..22], 0x0001, .big); // oper = request
        @memcpy(f[22..28], &src_mac); // sender MAC
        @memcpy(f[28..32], &src_ip); // sender IP
        // target MAC left zero
        @memcpy(f[38..42], &target_ip); // target IP
        return f;
    }

    /// A parsed ARP reply: the sender's IP (as `netaddr.Ip`) and MAC.
    pub const Reply = struct { ip: netaddr.Ip, mac: [hwaddr_len]u8 };

    /// Parse an ARP *reply* frame → sender IP + MAC, or null (wrong
    /// EtherType/oper or short frame). Skips outgoing requests (oper = 1).
    pub fn parseReply(frame: []const u8) ?Reply {
        if (frame.len < request_len) return null;
        if (std.mem.readInt(u16, frame[12..14], .big) != eth_p.arp) return null;
        if (std.mem.readInt(u16, frame[20..22], .big) != 0x0002) return null; // not a reply
        return .{
            .ip = .{ .v4 = frame[28..32].* },
            .mac = frame[22..28].*,
        };
    }
};

// ── errors ────────────────────────────────────────────────────────────────────

pub const OpenError = error{
    /// No `CAP_NET_RAW` (EPERM/EACCES) — a distinct error.
    AccessDenied,
    /// A named interface (`Options.iface`) does not exist.
    NoSuchInterface,
    /// `bind(2)` to the interface failed.
    BindFailed,
    /// `socket(2)` failed for another reason.
    SocketFailed,
};

pub const RecvError = error{
    /// No frame within `recv_timeout_ms` (SO_RCVTIMEO), or non-blocking.
    WouldBlock,
    /// Interrupted by a signal before any data arrived.
    Interrupted,
    RecvFailed,
};

pub const SendError = error{
    AccessDenied,
    MessageTooLong,
    WouldBlock,
    SendFailed,
};

pub const FilterError = error{
    /// Empty program, or more than 65535 instructions.
    InvalidFilter,
    FilterFailed,
};

pub const PromiscError = error{ AccessDenied, PromiscFailed };

pub const IfaceError = error{ NoSuchInterface, SocketFailed };

// ── Socket ────────────────────────────────────────────────────────────────────

/// An AF_PACKET socket. `open` yields a `SOCK_RAW` capture socket (frames
/// arrive with their full link-layer header); `openInject` yields a
/// `SOCK_DGRAM` cooked-send socket bound to one interface. Both wrap a single
/// fd; copy freely, `close` once. No internal state — reentrant.
pub const Socket = struct {
    fd: i32,

    pub const Options = struct {
        /// Bind capture to this interface by name; null = all interfaces.
        iface: ?[]const u8 = null,
        /// `SO_RCVTIMEO` in milliseconds; 0 = block forever.
        recv_timeout_ms: u32 = 0,
        /// Open the socket non-blocking (`recv` returns `WouldBlock`).
        nonblocking: bool = false,
    };

    /// Open a `SOCK_RAW` capture socket for `ethertype` (use `eth_p.all` for
    /// every frame). CLOEXEC is always set. Returns `error.AccessDenied`
    /// without `CAP_NET_RAW`.
    pub fn open(ethertype: u16, opts: Options) OpenError!Socket {
        const proto: u32 = std.mem.nativeToBig(u16, ethertype);
        var typ: u32 = linux.SOCK.RAW | linux.SOCK.CLOEXEC;
        if (opts.nonblocking) typ |= linux.SOCK.NONBLOCK;

        const rc = linux.socket(linux.AF.PACKET, typ, proto);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.SocketFailed,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);

        if (opts.recv_timeout_ms != 0) setRcvTimeout(fd, opts.recv_timeout_ms);
        if (opts.iface) |name| {
            const idx = ifaceIndexOn(fd, name) catch return error.NoSuchInterface;
            try bindPacket(fd, idx, ethertype);
        }
        return .{ .fd = fd };
    }

    /// Open a `SOCK_DGRAM` (cooked) send-only socket bound to `ifindex`. The
    /// kernel builds the Ethernet header from `send`'s arguments; the caller
    /// supplies only the payload. Returns `error.AccessDenied` without
    /// `CAP_NET_RAW`.
    pub fn openInject(ifindex: i32) OpenError!Socket {
        const rc = linux.socket(linux.AF.PACKET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.SocketFailed,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);
        try bindPacket(fd, ifindex, 0);
        return .{ .fd = fd };
    }

    /// Receive one frame into `buf`. `Frame.bytes` aliases `buf`; the source
    /// link-layer address is decoded from `sockaddr_ll`.
    pub fn recv(self: Socket, buf: []u8) RecvError!Frame {
        var sll: linux.sockaddr.ll = undefined;
        var slen: linux.socklen_t = @sizeOf(linux.sockaddr.ll);
        const n = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&sll), &slen);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .AGAIN => return error.WouldBlock,
            .INTR => return error.Interrupted,
            else => return error.RecvFailed,
        }
        const la = LinkAddr.fromSockaddr(sll);
        return .{
            .bytes = buf[0..n],
            .ifindex = la.ifindex,
            .src_hwaddr = la.hwaddr,
            .ethertype = la.protocol,
            .pkttype = la.pkttype,
        };
    }

    /// Cooked send: the kernel prepends an Ethernet header (dst = `dst_hwaddr`,
    /// src = the interface's own address, type = `ethertype`) to `payload` and
    /// transmits on `ifindex`. Intended for an `openInject` socket.
    pub fn send(
        self: Socket,
        ifindex: i32,
        dst_hwaddr: [hwaddr_len]u8,
        ethertype: u16,
        payload: []const u8,
    ) SendError!void {
        var sll = linux.sockaddr.ll{
            .protocol = std.mem.nativeToBig(u16, ethertype),
            .ifindex = ifindex,
            .hatype = 0,
            .pkttype = 0,
            .halen = hwaddr_len,
            .addr = .{ dst_hwaddr[0], dst_hwaddr[1], dst_hwaddr[2], dst_hwaddr[3], dst_hwaddr[4], dst_hwaddr[5], 0, 0 },
        };
        try sendTo(self.fd, &sll, payload);
    }

    /// Raw send: transmit a complete link-layer `frame` (already containing its
    /// Ethernet header) on `ifindex`. For a `SOCK_RAW` socket from `open`.
    pub fn sendRaw(self: Socket, ifindex: i32, frame: []const u8) SendError!void {
        var sll = linux.sockaddr.ll{
            .protocol = 0,
            .ifindex = ifindex,
            .hatype = 0,
            .pkttype = 0,
            .halen = 0,
            .addr = @splat(0),
        };
        try sendTo(self.fd, &sll, frame);
    }

    /// Attach a classic-BPF program for in-kernel filtering (`SO_ATTACH_FILTER`).
    /// Build one with `etherTypeFilter` or the `bpf` constructors.
    pub fn setFilter(self: Socket, prog: []const BpfInsn) FilterError!void {
        if (prog.len == 0 or prog.len > std.math.maxInt(u16)) return error.InvalidFilter;
        const fprog = SockFprog{ .len = @intCast(prog.len), .filter = prog.ptr };
        const rc = linux.setsockopt(
            self.fd,
            linux.SOL.SOCKET,
            linux.SO.ATTACH_FILTER,
            @ptrCast(&fprog),
            @sizeOf(SockFprog),
        );
        if (linux.errno(rc) != .SUCCESS) return error.FilterFailed;
    }

    /// Enable or disable promiscuous reception on `ifindex`
    /// (`PACKET_ADD_MEMBERSHIP` / `PACKET_DROP_MEMBERSHIP` with
    /// `PACKET_MR_PROMISC`). The membership is dropped automatically when the
    /// socket closes, but call with `on = false` to drop it early.
    pub fn setPromisc(self: Socket, ifindex: i32, on: bool) PromiscError!void {
        const mreq = PacketMreq{
            .ifindex = ifindex,
            .type = PACKET_MR_PROMISC,
            .alen = 0,
            .address = @splat(0),
        };
        const opt: u32 = if (on) linux.PACKET.ADD_MEMBERSHIP else linux.PACKET.DROP_MEMBERSHIP;
        const rc = linux.setsockopt(self.fd, linux.SOL.PACKET, opt, @ptrCast(&mreq), @sizeOf(PacketMreq));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.PromiscFailed,
        }
    }

    /// Close the socket fd.
    pub fn close(self: Socket) void {
        _ = linux.close(self.fd);
    }
};

/// A frame received off a `Socket`, with its `sockaddr_ll` decoded. `bytes`
/// aliases the caller's recv buffer and includes the Ethernet header (for
/// `SOCK_RAW` sockets).
pub const Frame = struct {
    bytes: []u8,
    ifindex: i32,
    src_hwaddr: [hwaddr_len]u8,
    /// EtherType from `sockaddr_ll` (host byte order).
    ethertype: u16,
    /// Direction/addressee (`pkt.host`, `pkt.outgoing`, …).
    pkttype: u8,
};

// ── interface helpers ─────────────────────────────────────────────────────────

/// Look up an interface index by name (`SIOCGIFINDEX`). Unprivileged — uses a
/// throwaway datagram socket for the ioctl, so no `CAP_NET_RAW` is needed.
pub fn ifaceByName(name: []const u8) IfaceError!i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    return ifaceIndexOn(fd, name);
}

/// Resolve `ifindex` → interface name via `SIOCGIFNAME` (ioctl on `fd`, which
/// may be any socket). The name is written into `out` and a slice of it (up to
/// the NUL) is returned — so the result does not dangle.
pub fn ifaceName(fd: i32, ifindex: i32, out: *[16]u8) IfaceError![]const u8 {
    var req: ifreq = .{};
    req.un[0..4].* = @bitCast(ifindex); // ifr_ifindex (native-endian i32)
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFNAME, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    @memcpy(out, &req.name);
    const end = std.mem.indexOfScalar(u8, out, 0) orelse out.len;
    return out[0..end];
}

/// Read an interface's hardware (MAC) address by index (`SIOCGIFNAME` then
/// `SIOCGIFHWADDR`; ioctls on `fd`).
pub fn hwaddr(fd: i32, ifindex: i32) IfaceError![hwaddr_len]u8 {
    var namebuf: [16]u8 = undefined;
    const name = try ifaceName(fd, ifindex, &namebuf);
    var req: ifreq = .{};
    @memcpy(req.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFHWADDR, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    // ifr_hwaddr is a sockaddr: family(2) then sa_data — MAC at bytes [2..8].
    var mac: [hwaddr_len]u8 = undefined;
    @memcpy(&mac, req.un[2..8]);
    return mac;
}

// ── internals ─────────────────────────────────────────────────────────────────

/// `struct ifreq`: a 16-byte name followed by a 24-byte union (40 bytes total).
const ifreq = extern struct {
    name: [16]u8 = @splat(0),
    un: [24]u8 = @splat(0),
};

/// `struct packet_mreq` (not exposed by std).
const PacketMreq = extern struct {
    ifindex: i32,
    type: u16,
    alen: u16,
    address: [8]u8,
};

/// `PACKET_MR_PROMISC` (not exposed by std; std has the `PACKET_*` sockopts
/// but not the membership-request types).
const PACKET_MR_PROMISC: u16 = 1;

fn ifaceIndexOn(fd: i32, name: []const u8) error{NoSuchInterface}!i32 {
    if (name.len == 0 or name.len > 15) return error.NoSuchInterface;
    var req: ifreq = .{};
    @memcpy(req.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    return @bitCast(req.un[0..4].*); // ifr_ifindex, native endian
}

fn bindPacket(fd: i32, ifindex: i32, ethertype: u16) OpenError!void {
    var sll = linux.sockaddr.ll{
        .protocol = std.mem.nativeToBig(u16, ethertype),
        .ifindex = ifindex,
        .hatype = 0,
        .pkttype = 0,
        .halen = 0,
        .addr = @splat(0),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll))) != .SUCCESS)
        return error.BindFailed;
}

fn setRcvTimeout(fd: i32, ms: u32) void {
    const tv = linux.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
}

fn sendTo(fd: i32, sll: *const linux.sockaddr.ll, data: []const u8) SendError!void {
    const rc = linux.sendto(fd, data.ptr, data.len, 0, @ptrCast(sll), @sizeOf(linux.sockaddr.ll));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.AccessDenied,
        .MSGSIZE => return error.MessageTooLong,
        .AGAIN => return error.WouldBlock,
        else => return error.SendFailed,
    }
}

// ── tests: pure helpers (always run; no socket) ───────────────────────────────

const testing = std.testing;

test "EthHeader parse/write round-trip" {
    const dst = [_]u8{ 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };
    const src = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    const h: EthHeader = .{ .dst = dst, .src = src, .ethertype = eth_p.lldp };

    var out: [eth_hdr_len]u8 = undefined;
    h.write(&out);
    try testing.expectEqual(@as(u16, 0x88cc), std.mem.readInt(u16, out[12..14], .big));

    const parsed = EthHeader.parse(&out).?;
    try testing.expectEqual(dst, parsed.dst);
    try testing.expectEqual(src, parsed.src);
    try testing.expectEqual(eth_p.lldp, parsed.ethertype);

    // Too-short frames decode to null.
    try testing.expectEqual(@as(?EthHeader, null), EthHeader.parse(out[0..13]));
}

test "hwaddr format/parse round-trip" {
    const mac = [_]u8{ 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f };
    var buf: [hwaddr_text_len]u8 = undefined;
    try testing.expectEqualStrings("0a:1b:2c:3d:4e:5f", formatHwaddr(mac, &buf));
    try testing.expectEqual(mac, parseHwaddr("0a:1b:2c:3d:4e:5f").?);
    try testing.expectEqual(mac, parseHwaddr("0a-1b-2c-3d-4e-5f").?); // dash separator
    try testing.expectEqual(mac, parseHwaddr("0A:1B:2C:3D:4E:5F").?); // case-insensitive

    const bad = [_][]const u8{
        "",                  "0a:1b:2c:3d:4e",    "0a:1b:2c:3d:4e:5f:60",
        "0a:1b:2c:3d:4e:5g", "0a1b2c3d4e5f",      "0a:1b:2c:3d:4e:5",
        "0a:1b:2c-3d:4e:5f", "za:1b:2c:3d:4e:5f",
    };
    for (bad) |t| try testing.expectEqual(@as(?[hwaddr_len]u8, null), parseHwaddr(t));
}

test "LinkAddr.fromSockaddr decode" {
    const sll = linux.sockaddr.ll{
        .protocol = std.mem.nativeToBig(u16, eth_p.arp),
        .ifindex = 3,
        .hatype = 1,
        .pkttype = pkt.broadcast,
        .halen = 6,
        .addr = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xff, 0xff },
    };
    const la = LinkAddr.fromSockaddr(sll);
    try testing.expectEqual(@as(i32, 3), la.ifindex);
    try testing.expectEqual(eth_p.arp, la.protocol); // decoded back to host order
    try testing.expectEqual(pkt.broadcast, la.pkttype);
    try testing.expectEqual(@as(u8, 6), la.halen);
    try testing.expectEqual([_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, la.hwaddr);

    // A cooked (halen 0) address zero-fills the hwaddr.
    var cooked = sll;
    cooked.halen = 0;
    try testing.expectEqual([_]u8{0} ** hwaddr_len, LinkAddr.fromSockaddr(cooked).hwaddr);
}

test "etherTypeFilter encodes the classic ether-proto program" {
    const prog = etherTypeFilter(eth_p.arp);
    try testing.expectEqual(@as(usize, 8), @sizeOf(BpfInsn)); // wire layout is fixed
    // ldh [12]
    try testing.expectEqual(@as(u16, bpf.ld | bpf.h | bpf.abs), prog[0].code);
    try testing.expectEqual(@as(u32, 12), prog[0].k);
    // jeq #0x0806, jt 0, jf 1
    try testing.expectEqual(@as(u16, bpf.jmp | bpf.jeq | bpf.k), prog[1].code);
    try testing.expectEqual(@as(u32, 0x0806), prog[1].k);
    try testing.expectEqual(@as(u8, 0), prog[1].jt);
    try testing.expectEqual(@as(u8, 1), prog[1].jf);
    // ret #accept / ret #0
    try testing.expectEqual(@as(u32, 0x40000), prog[2].k);
    try testing.expectEqual(@as(u32, 0), prog[3].k);
}

test "struct sizes match the kernel ABI" {
    try testing.expectEqual(@as(usize, 8), @sizeOf(BpfInsn)); // sock_filter
    try testing.expectEqual(@as(usize, 16), @sizeOf(PacketMreq)); // packet_mreq
    try testing.expectEqual(@as(usize, 40), @sizeOf(ifreq)); // ifreq
}

test "arp build/parse round-trip (surfaces netaddr.Ip)" {
    const src_mac = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const src_ip = [_]u8{ 192, 0, 2, 1 };
    const target_ip = [_]u8{ 192, 0, 2, 2 };

    const req = arp.buildRequest(src_mac, src_ip, target_ip);
    try testing.expectEqual(@as(usize, 42), req.len);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, req[0..6]); // broadcast
    try testing.expectEqual(eth_p.arp, std.mem.readInt(u16, req[12..14], .big));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, req[20..22], .big)); // oper = request
    try testing.expectEqualSlices(u8, &target_ip, req[38..42]);
    // A request is not a reply.
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&req));

    // Forge the corresponding reply and parse it back.
    var reply = req;
    std.mem.writeInt(u16, reply[20..22], 0x0002, .big); // oper = reply
    const rep_mac = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    @memcpy(reply[22..28], &rep_mac);
    @memcpy(reply[28..32], &target_ip); // sender = the host that answered
    const got = arp.parseReply(&reply).?;
    try testing.expectEqual(rep_mac, got.mac);
    try testing.expect(got.ip.eql(.{ .v4 = target_ip }));
}

// ── tests: socket path (gated on CAP_NET_RAW / a netns) ───────────────────────
//
// These need CAP_NET_RAW. Run them under an unprivileged network namespace:
//
//     unshare -rn zig build test-rawsock
//
// Without the capability, `Socket.open` returns error.AccessDenied and the
// test returns error.SkipZigTest — the repo's env-gated pattern. Even with the
// capability, if the environment cannot loop a frame back (e.g. `lo` cannot be
// brought up) the round-trip test skips rather than fails.

// A locally-administered experimental EtherType, unlikely to collide with real
// traffic on the loopback path.
const test_ethertype: u16 = 0x88b5; // ETH_P_802_EX1

/// Best-effort `ip link set lo up` via SIOCSIFFLAGS (needs CAP_NET_ADMIN, which
/// a `unshare -rn` root namespace has). Errors are ignored — the caller treats
/// a non-looping environment as "skip".
fn bringLoopbackUp() void {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var req: ifreq = .{};
    @memcpy(req.name[0..2], "lo");
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&req))) != .SUCCESS) return;
    var flags = std.mem.readInt(u16, req.un[0..2], .little);
    flags |= 0x1; // IFF_UP
    std.mem.writeInt(u16, req.un[0..2], flags, .little);
    _ = linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&req));
}

test "capture socket: open + setFilter + setPromisc (needs CAP_NET_RAW)" {
    var sock = Socket.open(test_ethertype, .{ .iface = "lo", .recv_timeout_ms = 200 }) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest, // no CAP_NET_RAW
        error.NoSuchInterface => return error.SkipZigTest, // no `lo` (unusual)
        else => return e,
    };
    defer sock.close();

    const lo = try ifaceByName("lo");
    try sock.setFilter(&etherTypeFilter(test_ethertype));
    try sock.setPromisc(lo, true);
    try sock.setPromisc(lo, false);
}

test "loopback round-trip: inject a frame, capture it back (needs CAP_NET_RAW + netns)" {
    const lo = ifaceByName("lo") catch return error.SkipZigTest;
    // Bring `lo` up *before* binding the capture: a socket bound to a down
    // interface reports the pending ENETDOWN on its first recv.
    bringLoopbackUp(); // best-effort; a still-down `lo` just means we skip below

    var cap = Socket.open(test_ethertype, .{ .iface = "lo", .recv_timeout_ms = 300 }) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        error.NoSuchInterface => return error.SkipZigTest,
        else => return e,
    };
    defer cap.close();

    var inj = Socket.openInject(lo) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };
    defer inj.close();

    const payload = "rawsock-loopback-selftest";
    const dst = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    inj.send(lo, dst, test_ethertype, payload) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };

    // The capture sees both the outgoing copy and (once looped) the inbound
    // one; scan a handful of frames for our payload.
    var buf: [2048]u8 = undefined;
    var tries: usize = 0;
    while (tries < 8) : (tries += 1) {
        const frame = cap.recv(&buf) catch |e| switch (e) {
            // No loopback traffic in this environment — env-limited, not a bug.
            error.WouldBlock, error.Interrupted => return error.SkipZigTest,
            else => return e,
        };
        const eth = EthHeader.parse(frame.bytes) orelse continue;
        if (eth.ethertype != test_ethertype) continue;
        if (std.mem.indexOf(u8, frame.bytes[eth_hdr_len..], payload) != null) {
            try testing.expectEqual(lo, frame.ifindex);
            return; // observed our own frame — success
        }
    }
    return error.SkipZigTest; // couldn't observe it within the window
}

test {
    testing.refAllDecls(@This());
}
