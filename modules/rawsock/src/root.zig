// SPDX-License-Identifier: MIT
//! rawsock — Linux AF_PACKET raw-frame capture + inject.
//!
//! A minimal libpcap-shaped path to layer-2: open a `SOCK_RAW` capture socket
//! for one EtherType (or all frames), decode the kernel's `sockaddr_ll` into a
//! typed `Frame`, attach an in-kernel classic-BPF filter, toggle promiscuous
//! mode, and cook-inject frames on a named interface via a `SOCK_DGRAM`
//! socket. Interface enumeration (`SIOCGIFINDEX` / `SIOCGIFNAME` /
//! `SIOCGIFHWADDR` / `SIOCGIFADDR` / `SIOCGIFNETMASK`) rounds it out.
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
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing
/// and the `Cursor` the two shape harnesses read their scripts from.
const testkit = @import("testkit");
const builtin = @import("builtin");
const netaddr = @import("netaddr");

const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux)
        @compileError("rawsock is Linux-only (AF_PACKET raw syscalls, no portable fallback)");
}

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Linux AF_PACKET raw-frame capture + inject — BPF filter, promiscuous mode, typed frame decode",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{ .linux64, .linux32 },
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
    /// EtherType in host byte order (e.g. `0x0806` for ARP). ⚠ On Linux this
    /// is the type the KERNEL delivered, not necessarily what a wire-level
    /// tool like `tcpdump` reports: `skb_vlan_untag` strips an 802.1Q tag
    /// before any AF_PACKET tap sees the frame, so a VLAN-tagged frame's
    /// `ethertype` here is the INNER type, never `0x8100` — measured against
    /// a real veth pair, `tcpdump` on the same wire shows the tag and this
    /// module does not. The tag itself (`tp_vlan_tci`) isn't exposed by this
    /// module at all. See `A1/rawsock.md` F3 (open — this is a documentation
    /// fix only; making the tag visible needs `PACKET_AUXDATA` + `recvmsg`).
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
    /// Valid bytes actually copied into `hwaddr` — always `<= hwaddr_len`
    /// (6 for Ethernet, 0 for cooked), even if the kernel's `sll_halen`
    /// itself reports more. Before this clamp the field echoed the raw
    /// `sll_halen` verbatim (up to 255, `u8`'s full range) while `hwaddr` is
    /// a fixed `[6]u8` — `la.hwaddr[0..la.halen]`, which the doc's own
    /// example invites, panicked in Debug/ReleaseSafe and was UB in
    /// ReleaseFast. See `A1/rawsock.md` F7.
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
            .halen = @intCast(n), // clamped to hwaddr_len — see the field's doc (F7)
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

/// Build a classic-BPF program that accepts only frames whose EtherType
/// equals `ethertype` and drops the rest — the `ether proto X` filter, applied
/// in-kernel via `Socket.setFilter`. Pure and usable without a socket. ⚠ On
/// Linux the kernel has already stripped any 802.1Q tag before this filter
/// runs (see `EthHeader.ethertype`'s doc), so for a tagged frame this matches
/// the INNER type, not the outer `0x8100` — a filter built for "ARP only"
/// passes ARP from every VLAN indiscriminately. See `A1/rawsock.md` F3.
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
    pub const Reply = struct {
        ip: netaddr.Ip,
        mac: [hwaddr_len]u8,
        /// Whether the Ethernet source address equals the ARP sender MAC.
        /// True for an ordinary reply; false is not itself invalid — a
        /// legitimate proxy-ARP responder answers on someone else's behalf —
        /// but it is also the classic `arpwatch` signature of a spoofed
        /// reply. RFC 826 doesn't require the two to match, so `parseReply`
        /// doesn't reject on a mismatch; it surfaces the comparison and lets
        /// the caller decide. See `A1/rawsock.md` F2.
        sender_is_eth_src: bool,
    };

    /// Parse an ARP *reply* frame → sender IP + MAC, or null (wrong
    /// EtherType/oper, short frame, or a hardware/protocol type this decoder
    /// doesn't understand). Skips outgoing requests (oper = 1).
    ///
    /// Validates the four RFC 826 fields the frame itself declares —
    /// `ar$hrd` (hardware type), `ar$pro` (protocol type), `ar$hln`
    /// (hardware address length), `ar$pln` (protocol address length) — before
    /// trusting the fixed byte offsets below them. Without this a frame that
    /// declares `ar$pro = 0x86dd` (IPv6) with `ar$pln = 16` decodes the first
    /// four bytes of a 16-byte IPv6 address as a bogus `netaddr.Ip.v4`; a
    /// live 802.1Q-segment test found 16 of 23 forged replies accepted this
    /// way before this check existed. See `A1/rawsock.md` F2.
    pub fn parseReply(frame: []const u8) ?Reply {
        if (frame.len < request_len) return null;
        if (std.mem.readInt(u16, frame[12..14], .big) != eth_p.arp) return null;
        if (std.mem.readInt(u16, frame[14..16], .big) != 0x0001) return null; // ar$hrd: Ethernet
        if (std.mem.readInt(u16, frame[16..18], .big) != eth_p.ip) return null; // ar$pro: IPv4
        if (frame[18] != hwaddr_len) return null; // ar$hln
        if (frame[19] != 4) return null; // ar$pln
        if (std.mem.readInt(u16, frame[20..22], .big) != 0x0002) return null; // not a reply
        return .{
            .ip = .{ .v4 = frame[28..32].* },
            .mac = frame[22..28].*,
            .sender_is_eth_src = std.mem.eql(u8, frame[6..12], frame[22..28]),
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
    /// `Options.recv_timeout_ms` was requested but `SO_RCVTIMEO` could not be
    /// set — previously discarded silently, leaving a socket that blocks
    /// forever while the caller believes it has a timeout. See F13.
    TimeoutFailed,
    /// `Options.recv_buf_bytes` was requested but `SO_RCVBUF` could not be set.
    RcvBufFailed,
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

pub const IfaceError = error{
    NoSuchInterface,
    SocketFailed,
    /// `hwaddr()` only: the interface's hardware-address family isn't
    /// `ARPHRD_ETHER` — a tunnel, `lo`, or anything else without a real
    /// Ethernet MAC. See F6.
    NotEthernet,
};

pub const StatsError = error{StatsFailed};

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
        /// `SO_RCVTIMEO` in milliseconds; 0 = block forever. ⚠ Bounds ONE
        /// `recvfrom` call, not "wait up to N ms for a frame I care about" —
        /// a caller that loops `recv` while discarding frames of the wrong
        /// type restarts the timer every call, so the loop as a whole can
        /// run far longer than this budget (measured: a 200 ms budget, a
        /// loop discarding unwanted frames, and a flooding peer produced a
        /// 19.2 SECOND wait). Attach a `setFilter` in-kernel filter instead
        /// of filtering in the loop if the wait must actually be bounded —
        /// the same setup measured 204–207 ms instead. See `A1/rawsock.md` F8.
        recv_timeout_ms: u32 = 0,
        /// Open the socket non-blocking (`recv` returns `WouldBlock`).
        nonblocking: bool = false,
        /// `SO_RCVBUF` in bytes; null = kernel default (commonly ~212 KiB).
        /// The socket's receive queue is exactly what stands between a burst
        /// of frames and `PACKET_STATISTICS`' `drops` counter (`Socket.stats`)
        /// — the default was measured losing 98.9% of a 20,000-frame burst
        /// silently (`recv` returns `WouldBlock`, indistinguishable from a
        /// quiet wire, unless the caller reads `stats()`). See F5/F14.
        recv_buf_bytes: ?u32 = null,
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

        if (opts.recv_buf_bytes) |bytes| {
            var sz: u32 = bytes;
            const rcvbuf_rc = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, @ptrCast(&sz), @sizeOf(u32));
            if (linux.errno(rcvbuf_rc) != .SUCCESS) return error.RcvBufFailed;
        }
        if (opts.recv_timeout_ms != 0) {
            setRcvTimeout(fd, opts.recv_timeout_ms) catch return error.TimeoutFailed;
        }
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

    /// Receive one frame into `buf`. `Frame.bytes` aliases `buf` (truncated
    /// to `buf.len` if the frame was longer — compare against `Frame.wire_len`
    /// to detect that); the source link-layer address is decoded from
    /// `sockaddr_ll`.
    pub fn recv(self: Socket, buf: []u8) RecvError!Frame {
        var sll: linux.sockaddr.ll = undefined;
        var slen: linux.socklen_t = @sizeOf(linux.sockaddr.ll);
        // MSG_TRUNC: on a truncated datagram/packet the kernel returns the
        // full ON-THE-WIRE length, not the number of bytes actually copied
        // into `buf` — without it those two numbers are conflated and a
        // caller with a buffer smaller than the frame (a smaller MTU
        // assumption, a jumbo frame, "I only need the header") gets a
        // truncated frame that is indistinguishable from a complete one.
        // See `A1/rawsock.md` F1.
        const n = linux.recvfrom(self.fd, buf.ptr, buf.len, linux.MSG.TRUNC, @ptrCast(&sll), &slen);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .AGAIN => return error.WouldBlock,
            .INTR => return error.Interrupted,
            else => return error.RecvFailed,
        }
        const wire_len: usize = n;
        const copied = @min(wire_len, buf.len);
        const la = LinkAddr.fromSockaddr(sll);
        return .{
            .bytes = buf[0..copied],
            .wire_len = wire_len,
            .ifindex = la.ifindex,
            .src_hwaddr = la.hwaddr,
            .ethertype = la.protocol,
            .pkttype = la.pkttype,
        };
    }

    /// `struct tpacket_stats` (not exposed by std): frames the kernel queued
    /// for this socket and how many of those it had to drop because the
    /// receive queue (`Options.recv_buf_bytes` / `SO_RCVBUF`) was full before
    /// the caller ever called `recv`. ⚠ Reading this resets the kernel's
    /// counters — `getsockopt(PACKET_STATISTICS)` semantics — so call it once
    /// per measurement window, not speculatively between every `recv`.
    ///
    /// Without this there is no way to tell a socket that lost 98.9% of a
    /// burst from one that saw a quiet wire: both return `error.WouldBlock`
    /// from `recv`. See `A1/rawsock.md` F5.
    pub fn stats(self: Socket) StatsError!struct { packets: u32, drops: u32 } {
        var st: TpacketStats = undefined;
        var len: linux.socklen_t = @sizeOf(TpacketStats);
        const rc = linux.getsockopt(self.fd, linux.SOL.PACKET, linux.PACKET.STATISTICS, @ptrCast(&st), &len);
        if (linux.errno(rc) != .SUCCESS) return error.StatsFailed;
        return .{ .packets = st.packets, .drops = st.drops };
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
    /// The frame's real length on the wire — from `MSG_TRUNC`. Equal to
    /// `bytes.len` when the whole frame fit in the caller's buffer;
    /// `bytes.len < wire_len` means the frame was truncated to fit and
    /// `bytes` holds only its first `bytes.len` octets. See F1.
    wire_len: usize,
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
/// `SIOCGIFHWADDR`; ioctls on `fd`). `error.NotEthernet` for an interface
/// whose hardware-address family isn't `ARPHRD_ETHER` — a tunnel, `lo`, or
/// anything else that doesn't have a real 6-byte MAC (see `hwaddrFromIfreq`
/// and `A1/rawsock.md` F6).
pub fn hwaddr(fd: i32, ifindex: i32) IfaceError![hwaddr_len]u8 {
    var namebuf: [16]u8 = undefined;
    const name = try ifaceName(fd, ifindex, &namebuf);
    var req: ifreq = .{};
    @memcpy(req.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFHWADDR, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    return hwaddrFromIfreq(req) orelse error.NotEthernet;
}

/// Read an interface's IPv4 address by index (`SIOCGIFNAME` then
/// `SIOCGIFADDR`; ioctls on `fd`). Unprivileged, like `hwaddr` — any open
/// socket works as `fd`. Returns `error.NoSuchInterface` both when the
/// interface doesn't exist and when it has no IPv4 address configured (the
/// kernel reports both as an ioctl failure; this module doesn't need to tell
/// them apart, matching the other wrappers' error shape).
pub fn ipv4Addr(fd: i32, ifindex: i32) IfaceError![4]u8 {
    var namebuf: [16]u8 = undefined;
    const name = try ifaceName(fd, ifindex, &namebuf);
    var req: ifreq = .{};
    @memcpy(req.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFADDR, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    return sockaddrInAddr(req);
}

/// Read an interface's IPv4 netmask by index (`SIOCGIFNAME` then
/// `SIOCGIFNETMASK`; ioctls on `fd`). Deliberately shipped alongside
/// `ipv4Addr` rather than left for the caller to hand-roll: the kernel
/// exposes address and netmask as two separate ioctls, but a consumer that
/// wants the *subnet* (an ARP sweep needs the host range, not just this
/// host's own address) needs both — `netaddr.Prefix`/`AddrIterator` can take
/// it from here once the caller turns the mask into a prefix length.
pub fn ipv4Netmask(fd: i32, ifindex: i32) IfaceError![4]u8 {
    var namebuf: [16]u8 = undefined;
    const name = try ifaceName(fd, ifindex, &namebuf);
    var req: ifreq = .{};
    @memcpy(req.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFNETMASK, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    return sockaddrInAddr(req);
}

// ── internals ─────────────────────────────────────────────────────────────────

/// Extract the IPv4 address from an `ifreq` union filled by `SIOCGIFADDR` /
/// `SIOCGIFNETMASK`: the kernel writes a `struct sockaddr_in` there — family
/// (2 bytes), port (2 bytes, always zero for these two ioctls), address (4
/// bytes) — so the address sits at byte offset 4, one word deeper than
/// `hwaddr`'s bare `struct sockaddr` MAC at offset 2 (no port field in
/// `sockaddr_ll`/the generic hwaddr sockaddr).
fn sockaddrInAddr(req: ifreq) [4]u8 {
    return req.un[4..8].*;
}

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

/// `struct tpacket_stats` (not exposed by std) — the payload of
/// `getsockopt(SOL_PACKET, PACKET_STATISTICS)`, read by `Socket.stats`.
const TpacketStats = extern struct {
    packets: u32,
    drops: u32,
};

/// `ARPHRD_ETHER` (`net/if_arp.h`, not exposed by std) — the hardware-address
/// type `hwaddr()` knows how to interpret as a 6-byte Ethernet MAC.
const ARPHRD_ETHER: u16 = 1;

/// Decode `ifr_hwaddr` from a `SIOCGIFHWADDR` reply: family (2 bytes,
/// native-endian, matching the `@bitCast` style `ifaceIndexOn` and the
/// `sockaddrInAddr` test already use for this union) then sa_data — MAC at
/// bytes [2..8], the same offset `sockaddrInAddr` documents for the sibling
/// `sockaddr_in` shape (no port field here, unlike that one). Null when the
/// family isn't `ARPHRD_ETHER`: a `sit` tunnel reports its own 4-byte remote
/// address there (measured: `198.51.100.7` read back as MAC
/// `c6:33:64:07:00:00`), and `lo`/`gre0` report an all-zero address
/// indistinguishable from a real zero MAC. Neither is a MAC address this
/// module has any business returning. See `A1/rawsock.md` F6.
fn hwaddrFromIfreq(req: ifreq) ?[hwaddr_len]u8 {
    const family: u16 = @bitCast(req.un[0..2].*);
    if (family != ARPHRD_ETHER) return null;
    var mac: [hwaddr_len]u8 = undefined;
    @memcpy(&mac, req.un[2..8]);
    return mac;
}

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

/// Set `SO_RCVTIMEO`. Was `fn (...) void` with `_ = linux.setsockopt(...)` —
/// a failed `setsockopt` was silently discarded, so `open` could return a
/// socket that blocks forever while the caller believes `recv_timeout_ms`
/// is in effect. Now the failure reaches `open`'s caller as
/// `error.TimeoutFailed`. See `A1/rawsock.md` F13.
fn setRcvTimeout(fd: i32, ms: u32) error{TimeoutFailed}!void {
    const tv = linux.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
    const rc = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
    if (linux.errno(rc) != .SUCCESS) return error.TimeoutFailed;
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
        // F15: a right-length (17), right-hex-digit string whose separator is
        // uniformly wrong throughout — the two prior bad vectors either fail
        // on length ("0a1b2c3d4e5f") or on a MIXED separator
        // ("0a:1b:2c-3d:4e:5f"), so neither exercises `sep != ':' and sep !=
        // '-'` on its own; a mutant that deletes that check alone survived.
        "0a.1b.2c.3d.4e.5f",
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

    // A malformed/oversized halen (sll_addr is only 8 bytes; a hostile or
    // buggy peer could report more than the Ethernet hwaddr_len) must clamp
    // to 6, not read/write past the fixed-size hwaddr buffer.
    var oversized = sll;
    oversized.halen = 8;
    const decoded_oversized = LinkAddr.fromSockaddr(oversized);
    try testing.expectEqual([_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, decoded_oversized.hwaddr);
    // F7: the REPORTED halen must clamp too, not just the copy. Before this
    // fix `la.halen` echoed `sll.halen` verbatim (8, even 255), so
    // `la.hwaddr[0..la.halen]` — which the field's own doc example invited —
    // panicked in Debug/ReleaseSafe and was UB in ReleaseFast.
    try testing.expectEqual(@as(u8, hwaddr_len), decoded_oversized.halen);
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

test "sockaddrInAddr decodes a real SIOCGIFADDR/SIOCGIFNETMASK ifreq layout" {
    // A real SIOCGIFADDR reply for 192.0.2.1: ifr_addr is a sockaddr_in —
    // family AF_INET (2, native-endian u16) at [0..2), port 0 at [2..4),
    // address at [4..8), the sin_zero padding after (untouched, left 0).
    var req: ifreq = .{};
    req.un[0..2].* = @bitCast(@as(u16, linux.AF.INET));
    req.un[4..8].* = .{ 192, 0, 2, 1 };
    try testing.expectEqual([_]u8{ 192, 0, 2, 1 }, sockaddrInAddr(req));

    // A real SIOCGIFNETMASK reply for a /24 (255.255.255.0): same layout,
    // different address bytes — the two ioctls share one wire shape.
    var mreq: ifreq = .{};
    mreq.un[0..2].* = @bitCast(@as(u16, linux.AF.INET));
    mreq.un[4..8].* = .{ 255, 255, 255, 0 };
    try testing.expectEqual([_]u8{ 255, 255, 255, 0 }, sockaddrInAddr(mreq));
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
    // F2: `reply`'s Ethernet source is still `src_mac` (only frame[22..32]
    // was overwritten above), but the ARP sender MAC is `rep_mac` — a
    // deliberate mismatch, e.g. a proxy-ARP responder answering on someone
    // else's behalf. RFC 826 doesn't forbid this, so `parseReply` still
    // ACCEPTS it; it only surfaces the disagreement for the caller to act on.
    try testing.expect(!got.sender_is_eth_src);
}

test "F2 fix: RFC 826 hrd/pro/hln/pln validation, offline against the real-capture golden" {
    // Vector #10 from A1/rawsock.md F2: a well-formed-looking reply whose
    // ar$pro/ar$pln claim IPv6 (0x86dd / 16) instead of IPv4 (0x0800 / 4).
    // Before this check, `parseReply` didn't read these fields at all and
    // decoded the first four bytes of the (would-be) 16-byte IPv6 address as
    // a bogus `netaddr.Ip.v4` — live on a real segment, 16 of 23 forged
    // replies like this were accepted.
    var ipv6_shaped = arp_reply_frame;
    std.mem.writeInt(u16, ipv6_shaped[16..18], eth_p.ipv6, .big); // ar$pro
    ipv6_shaped[19] = 16; // ar$pln
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&ipv6_shaped));

    var bad_htype = arp_reply_frame;
    std.mem.writeInt(u16, bad_htype[14..16], 6, .big); // ar$hrd = IEEE 802, not Ethernet
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&bad_htype));

    var bad_hlen = arp_reply_frame;
    bad_hlen[18] = 0; // ar$hln
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&bad_hlen));

    var bad_pro = arp_reply_frame;
    std.mem.writeInt(u16, bad_pro[16..18], eth_p.ip, .big); // ar$pro left IPv4 (correct)...
    bad_pro[19] = 16; // ...but ar$pln alone claims 16 (RFC-inconsistent on its own)
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&bad_pro));

    // Positive control: the real-capture golden, untouched, must still pass —
    // these checks must not be stricter than a real ARP reply.
    try testing.expect(arp.parseReply(&arp_reply_frame) != null);
}

test "F12: parseReply length boundary — 41B rejected, the real 42B golden accepted" {
    // `m5`/`m6` from the audit's mutation matrix: deleting `frame.len <
    // request_len` (m5) or weakening it to `< 22` (m6) both survived the
    // existing tests because nothing in the suite exercised a frame between
    // those two lengths and 42. 41 bytes: one short of a complete reply, and
    // long enough (`> 22`) that a weakened check would let it through.
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(arp_reply_frame[0..41]));
    try testing.expect(arp.parseReply(&arp_reply_frame) != null); // positive control
}

test "F12: parseReply rejects a 30-byte frame inside the m6-weakened `< 22` gap" {
    var buf: [30]u8 = undefined;
    @memcpy(&buf, arp_reply_frame[0..30]);
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&buf));
}

test "F12: parseReply rejects every oper value except 2 (reply), enumerated 0..15" {
    // `m10`: `oper` compared by a single bit out of sixteen instead of exact
    // equality survived because the suite's only rejection vector was
    // `oper == 1`, which a 1-bit comparison also rejects — `arpmat` measured
    // the 1-bit version accepting `oper == 8`. Enumerating every value in
    // 0..15 individually forces exact equality, not just "differs from 1".
    var f = arp_reply_frame;
    var op: u16 = 0;
    while (op <= 15) : (op += 1) {
        std.mem.writeInt(u16, f[20..22], op, .big);
        if (op == 0x0002) {
            try testing.expect(arp.parseReply(&f) != null);
        } else {
            try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&f));
        }
    }
}

test "F16: ifaceIndexOn rejects an over-length interface name before any syscall" {
    // `m21`: deleting `name.len == 0 or name.len > 15` survived the test
    // gate in BOTH lanes and, in ReleaseFast, the module's own example
    // exits 0 while `@memcpy` writes past the intent of the fixed 16-byte
    // `ifreq.name` (a 30-byte name in that reproduction; here 20 is enough
    // to prove the point without relying on Debug's bounds-check panic vs.
    // ReleaseFast's silent UB — either way, with the guard PRESENT this call
    // must return cleanly, syscall never reached (fd -1 would surface as a
    // syscall failure, not this specific error, if the guard were skipped
    // and the copy somehow survived).
    const too_long = "a" ** 20;
    try testing.expectEqual(error.NoSuchInterface, ifaceIndexOn(-1, too_long));
}

test "F12/F16: ifaceName on `lo` round-trips and is NUL-terminated (unprivileged)" {
    // `m22`: `ifaceName` returning all 16 raw bytes of `ifr_ifrn.ifrn_name`
    // instead of truncating at the NUL survived because nothing compared its
    // result to the interface's actual (short) name. `ifaceByName`/
    // `ifaceName` only need a throwaway AF_INET socket for the ioctl (see
    // `ipv4Addr`'s test above), so this runs unconditionally.
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    try testing.expectEqual(.SUCCESS, linux.errno(rc));
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    const lo = try ifaceByName("lo");
    var buf: [16]u8 = undefined;
    const name = try ifaceName(fd, lo, &buf);
    try testing.expectEqualStrings("lo", name);
}

test "F6: hwaddrFromIfreq rejects a non-Ethernet hardware-address family, offline" {
    // Real values from the audit's `probe hwtypes` (A1/rawsock.md F6):
    // ARPHRD_ETHER=1 (veth, a real MAC), ARPHRD_SIT=776 (a `sit` tunnel,
    // whose 4-byte remote address `198.51.100.7` was read back as MAC
    // `c6:33:64:07:00:00`), ARPHRD_LOOPBACK=772 (`lo`, all-zero).
    var eth_req: ifreq = .{};
    eth_req.un[0..2].* = @bitCast(@as(u16, 1)); // ARPHRD_ETHER
    eth_req.un[2..8].* = .{ 0xbe, 0x68, 0x94, 0xcf, 0xca, 0xfc };
    try testing.expectEqual([_]u8{ 0xbe, 0x68, 0x94, 0xcf, 0xca, 0xfc }, hwaddrFromIfreq(eth_req).?);

    var sit_req: ifreq = .{};
    sit_req.un[0..2].* = @bitCast(@as(u16, 776)); // ARPHRD_SIT
    sit_req.un[2..8].* = .{ 0xc6, 0x33, 0x64, 0x07, 0x00, 0x00 }; // 198.51.100.7 as hex
    try testing.expectEqual(@as(?[hwaddr_len]u8, null), hwaddrFromIfreq(sit_req));

    var lo_req: ifreq = .{};
    lo_req.un[0..2].* = @bitCast(@as(u16, 772)); // ARPHRD_LOOPBACK
    try testing.expectEqual(@as(?[hwaddr_len]u8, null), hwaddrFromIfreq(lo_req));

    // The offset itself, pinned: bytes [2..8) are the MAC, [8..10) are NOT —
    // a mutant that shifts the read window (audit's `m23_hwaddr_offset`,
    // `un[4..10]` instead of `un[2..8]`) must fail this.
    var offset_req: ifreq = .{};
    offset_req.un[0..2].* = @bitCast(@as(u16, 1));
    offset_req.un[2..10].* = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0xff };
    try testing.expectEqual([_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, hwaddrFromIfreq(offset_req).?);
}

// ── real-capture goldens (veth pair, tcpdump, 2026-08-01) ───────────────────
//
// The round-trip test above only ever parses this module's *own* encoder
// output — a hand-computed fixture never checked against a real kernel or a
// real L2 segment. Loopback can't fill that gap: `lo` never does ARP (local
// delivery skips neighbor resolution entirely, and it has no real hwaddr).
// So this is captured off a genuine layer-2 segment instead: a veth pair,
// each end moved into its own network namespace (`ip link set <dev> netns
// <pid>` across two nested `unshare --net` children sharing one throwaway
// `unshare --user --net` owner) — this is the only way to get real ARP
// resolution without touching the host (no setcap, no persistent interface,
// the whole namespace tree is torn down when the owning process exits).
// `tcpdump -i veth1` captured a real `ping` between the two ends: kernel-
// assigned random MACs, a genuine ARP who-has/is-at exchange, and (as a
// bonus) the resulting Ethernet+IPv4+ICMP frames.
//
// This anchors real Ethernet framing (real MACs, not `aa:bb:cc:dd:ee:ff`)
// and the real ARP wire layout independently of `buildRequest`/`parseReply`
// agreeing with themselves.

const arp_request_frame = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x98, 0xd4, 0x25, 0xce, 0x67, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x98, 0xd4, 0x25, 0xce, 0x67, 0x0a, 0x37, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x37, 0x00, 0x02,
};
const arp_reply_frame = [_]u8{
    0x02, 0x98, 0xd4, 0x25, 0xce, 0x67, 0xba, 0x89, 0xdd, 0xc5, 0x71, 0x9a, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0xba, 0x89, 0xdd, 0xc5, 0x71, 0x9a, 0x0a, 0x37, 0x00, 0x02,
    0x02, 0x98, 0xd4, 0x25, 0xce, 0x67, 0x0a, 0x37, 0x00, 0x01,
};
// A real Ethernet+IPv4+ICMP frame from the same exchange, for EthHeader.
const ip_echo_request_frame = [_]u8{
    0xba, 0x89, 0xdd, 0xc5, 0x71, 0x9a, 0x02, 0x98, 0xd4, 0x25, 0xce, 0x67, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x54, 0x1c, 0x75, 0x40, 0x00, 0x40, 0x01, 0x09, 0xc4, 0x0a, 0x37, 0x00, 0x01, 0x0a, 0x37,
    0x00, 0x02, 0x08, 0x00, 0x99, 0xc5, 0xa0, 0x5b, 0x00, 0x01, 0x42, 0xe0, 0x6d, 0x6a, 0x00, 0x00,
    0x00, 0x00, 0x42, 0xc0, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37,
};

test "golden: real capture — EthHeader.parse on a real ARP request frame" {
    const eth = EthHeader.parse(&arp_request_frame).?;
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, &eth.dst);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x98, 0xd4, 0x25, 0xce, 0x67 }, &eth.src);
    try testing.expectEqual(eth_p.arp, eth.ethertype);
}

test "golden: real capture — EthHeader.parse on a real IPv4 frame" {
    const eth = EthHeader.parse(&ip_echo_request_frame).?;
    try testing.expectEqualSlices(u8, &.{ 0xba, 0x89, 0xdd, 0xc5, 0x71, 0x9a }, &eth.dst);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x98, 0xd4, 0x25, 0xce, 0x67 }, &eth.src);
    try testing.expectEqual(eth_p.ip, eth.ethertype);
}

test "golden: real capture — arp.parseReply on a real who-has/is-at exchange" {
    // The request is not a reply — a real one, not a synthesized one.
    try testing.expectEqual(@as(?arp.Reply, null), arp.parseReply(&arp_request_frame));

    const got = arp.parseReply(&arp_reply_frame).?;
    try testing.expect(got.ip.eql(.{ .v4 = .{ 10, 55, 0, 2 } }));
    try testing.expectEqualSlices(u8, &.{ 0xba, 0x89, 0xdd, 0xc5, 0x71, 0x9a }, &got.mac);
}

test "golden: real-capture fixture count + size canary — 3 real veth-pair captures" {
    try testing.expectEqual(@as(usize, 42), arp_request_frame.len);
    try testing.expectEqual(@as(usize, 42), arp_reply_frame.len);
    try testing.expectEqual(@as(usize, 98), ip_echo_request_frame.len);
}

// ── fuzz: frame-off-the-wire parsers, never panic ──────────────────────────
//
// `EthHeader.parse`, `parseHwaddr` and `arp.parseReply` are the three pure
// parsers in this module that touch bytes an attacker on the local segment
// controls directly — a captured frame's link-layer header, operator/config
// input for a MAC address, and an ARP reply body (classic ARP-spoofing
// territory). None require a socket, so the harness drives them offline.

/// The two real captured frames this module already anchors its golden tests
/// to, plus the shapes around `eth_hdr_len`.
const eth_seeds = [_][]const u8{
    testkit.fuzz.seed(&ip_echo_request_frame), // 98 octets, a real capture
    testkit.fuzz.seed(&arp_reply_frame), // 42 octets, the same exchange
    testkit.fuzz.seed(ip_echo_request_frame[0..eth_hdr_len]), // exactly the header
    testkit.fuzz.seed(ip_echo_request_frame[0 .. eth_hdr_len - 1]), // one octet short
    testkit.fuzz.seed(""), // the input this target used to run for ever
};

test "fuzz: EthHeader.parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzEthHeaderParse, .{ .corpus = &eth_seeds });
}

fn fuzzEthHeaderParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input this target ever ran outside
    // `--fuzz` (a ranged draw needs eight octets and `bytes` had eaten them),
    // so `parse` returned null off its `frame.len < 14` check every round.
    const len: usize = smith.slice(&buf);
    if (EthHeader.parse(buf[0..len])) |h| {
        var out: [eth_hdr_len]u8 = undefined;
        h.write(&out);
    }
}

test "corpus: the Ethernet seeds reach the parser, and the counts are pinned" {
    var nonempty: usize = 0;
    var parsed: usize = 0;
    // The round trip is the number an empty replay cannot produce: a parsed
    // header must rewrite to the same fourteen octets it came from.
    var rewrote: usize = 0;
    for (eth_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const h = EthHeader.parse(buf[0..len]) orelse continue;
        parsed += 1;
        var out: [eth_hdr_len]u8 = undefined;
        h.write(&out);
        if (std.mem.eql(u8, &out, buf[0..eth_hdr_len])) rewrote += 1;
    }
    try testing.expectEqual(eth_seeds.len - 1, nonempty); // all but the empty seed
    try testing.expectEqual(@as(usize, 3), parsed);
    try testing.expectEqual(@as(usize, 3), rewrote);
}

/// ⛔ The measurement: this target's FIRST draw was `smith.value(bool)`, and it
/// had no corpus — so the input was already exhausted and the draw returned
/// FALSE on every round the ordinary lane ever ran. Only the `else` arm ran,
/// the "structurally-correct skeleton" the comment below is about; and inside
/// it every `smith.index` was 0 too, so the text built was always the same
/// `"00:00:00:00:00:00"`. The raw-bytes arm — the length/separator gate — had
/// never executed at all, and the skeleton arm produced exactly one string.
///
/// The byte draw now comes first and the shape choices are read out of it
/// through `testkit.fuzz.Cursor`, so a seed is a script anyone can read.
const hwaddr_seeds = [_][]const u8{
    // Mode `raw`: the drawn octets go straight to `parseHwaddr`.
    hwSeed("aa:bb:cc:dd:ee:ff", 1),
    hwSeed("AA-BB-CC-DD-EE-FF", 1),
    hwSeed("aa:bb:cc:dd:ee:f", 1), // one octet short of `hwaddr_text_len`
    hwSeed("aa:bb:cc:dd:ee:fff", 1), // one too long
    hwSeed("aa:bb:cc:dd:ee.ff", 1), // a separator that is neither ':' nor '-'
    hwSeed("aa:bb:cc:dd:ee:fg", 1), // 'g' is not a hex digit
    hwSeed("", 1),
    // Mode `skeleton`: the octets are indices into `hex_digits`, twelve of
    // them, and the first picks the separator. `x`/`y`/`z`/space sit at
    // indices 22..25 and are the deliberately-invalid digits.
    hwSeed(&[_]u8{0} ++ [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, 0),
    hwSeed(&[_]u8{1} ++ [_]u8{ 16, 17, 18, 19, 20, 21, 16, 17, 18, 19, 20, 21 }, 0), // '-', uppercase
    hwSeed(&[_]u8{0} ++ [_]u8{ 22, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, 0), // a leading 'x'
    hwSeed(&[_]u8{0} ++ [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 25 }, 0), // a trailing space
    hwSeed("", 0), // the empty script: separator ':' and all-zero digits
};

/// The script, then the `u64` word the mode knob after the byte draw reads
/// (`1` = raw, `0` = skeleton). ⛔ Without that word the knob is dead on a
/// corpus replay and every seed would take the same arm.
fn hwSeed(comptime script: []const u8, comptime mode: u64) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, script.len)) ++ script[0..script.len].* ++
            std.mem.toBytes(mode);
    }.bytes;
}

const hw_hex_digits = "0123456789abcdefABCDEFxyz "; // last four: deliberately invalid

test "fuzz: parseHwaddr never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParseHwaddr, .{ .corpus = &hwaddr_seeds });
}

fn fuzzParseHwaddr(_: void, smith: *std.testing.Smith) !void {
    // ⚠ The byte draw is FIRST. See `hwaddr_seeds`.
    var buf: [64]u8 = undefined;
    const len: usize = smith.slice(&buf);
    // Two shapes: the drawn octets verbatim (exercises the length/separator
    // gate), and a structurally-correct "xx:xx:xx:xx:xx:xx" skeleton whose hex
    // digits, separator and case come from the same octets — the only way to
    // reach the per-octet `charToDigit` calls instead of bailing out at the
    // length or separator check on the first try.
    if (smith.value(bool)) {
        _ = parseHwaddr(buf[0..len]);
    } else {
        var cur: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
        const sep: u8 = if (cur.byte() & 1 == 0) ':' else '-';
        var text: [hwaddr_text_len]u8 = undefined;
        for (0..hwaddr_len) |i| {
            text[i * 3] = hw_hex_digits[cur.byte() % hw_hex_digits.len];
            text[i * 3 + 1] = hw_hex_digits[cur.byte() % hw_hex_digits.len];
            if (i != hwaddr_len - 1) text[i * 3 + 2] = sep;
        }
        _ = parseHwaddr(&text);
    }
}

test "corpus: the hwaddr seeds drive both shapes, and the counts are pinned" {
    var raw_arm: usize = 0;
    var skeleton_arm: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number the collapsed draw could not produce: DISTINCT addresses
    // parsed. Both arms used to build the same `"00:00:00:00:00:00"`, so this
    // was 1 at best; and the raw arm never ran at all.
    var seen: [8][hwaddr_len]u8 = undefined;
    var distinct: usize = 0;
    for (hwaddr_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        var got: ?[hwaddr_len]u8 = null;
        if (smith.value(bool)) {
            raw_arm += 1;
            got = parseHwaddr(buf[0..len]);
        } else {
            skeleton_arm += 1;
            var cur: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
            const sep: u8 = if (cur.byte() & 1 == 0) ':' else '-';
            var text: [hwaddr_text_len]u8 = undefined;
            for (0..hwaddr_len) |i| {
                text[i * 3] = hw_hex_digits[cur.byte() % hw_hex_digits.len];
                text[i * 3 + 1] = hw_hex_digits[cur.byte() % hw_hex_digits.len];
                if (i != hwaddr_len - 1) text[i * 3 + 2] = sep;
            }
            got = parseHwaddr(&text);
        }
        const mac = got orelse continue;
        accepted += 1;
        var already = false;
        for (seen[0..distinct]) |prev| {
            if (std.mem.eql(u8, &prev, &mac)) already = true;
        }
        if (!already) {
            seen[distinct] = mac;
            distinct += 1;
        }
    }
    try testing.expectEqual(@as(usize, 7), raw_arm);
    try testing.expectEqual(@as(usize, 5), skeleton_arm);
    try testing.expectEqual(@as(usize, 5), accepted);
    try testing.expectEqual(@as(usize, 4), distinct);
}

/// ⛔ Same measurement as `fuzzParseHwaddr`, and worse: the FIRST draw was
/// `smith.value(bool)`, false on every input, so only the raw-bytes arm ran
/// and its own length draw was 0 — `arp.parseReply("")` every round. The
/// `else` arm, which starts from a REAL ARP reply and mutates it so the sender
/// IP/MAC extraction actually runs, had never executed once.
///
/// Script layout for the mutate arm: `[0]` mutation count (`b % 7`), then per
/// mutation a position octet and a replacement octet.
const arp_seeds = [_][]const u8{
    arpSeed(&arp_reply_frame, 1), // mode raw: the real captured reply
    arpSeed(arp_reply_frame[0..21], 1), // truncated before `oper`
    arpSeed(&[_]u8{ 0xff, 0xff }, 1), // far too short for the ethertype gate
    arpSeed("", 1),
    arpSeed(&[_]u8{0}, 0), // mode mutate: no mutations, the pristine reply
    arpSeed(&[_]u8{ 1, 12, 0x08 }, 0), // one octet inside the ethertype
    arpSeed(&[_]u8{ 1, 21, 0x01 }, 0), // `oper` back to request
    arpSeed(&[_]u8{ 6, 22, 0x11, 28, 0x22, 30, 0x33, 32, 0x44, 38, 0x55, 41, 0x66 }, 0), // sender IP/MAC
    arpSeed("", 0), // the empty script: zero mutations
};

fn arpSeed(comptime script: []const u8, comptime mode: u64) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, script.len)) ++ script[0..script.len].* ++
            std.mem.toBytes(mode);
    }.bytes;
}

test "fuzz: arp.parseReply never panics on arbitrary or structurally ARP-shaped frames" {
    try testing.fuzz({}, fuzzArpParseReply, .{ .corpus = &arp_seeds });
}

fn fuzzArpParseReply(_: void, smith: *std.testing.Smith) !void {
    // ⚠ The byte draw is FIRST. See `arp_seeds`.
    var buf: [128]u8 = undefined;
    const len: usize = smith.slice(&buf);

    // Two shapes: the drawn octets verbatim (the length/ethertype gate), and a
    // real ARP reply frame with octets from the same draw written over it —
    // gets past the ethertype/oper checks so the sender IP/MAC extraction
    // actually runs on hostile data.
    if (smith.value(bool)) {
        _ = arp.parseReply(buf[0..len]);
    } else {
        var reply = arp.buildRequest(
            .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
            .{ 192, 0, 2, 1 },
            .{ 192, 0, 2, 2 },
        );
        std.mem.writeInt(u16, reply[20..22], 0x0002, .big); // oper = reply
        var cur: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
        const n_mutations = cur.ranged(0, 6);
        var i: u32 = 0;
        while (i < n_mutations) : (i += 1) {
            const pos = cur.ranged(0, @intCast(reply.len - 1));
            reply[pos] = cur.byte();
        }
        _ = arp.parseReply(&reply);
    }
}

test "corpus: the ARP seeds drive both shapes, and the counts are pinned" {
    var raw_arm: usize = 0;
    var mutate_arm: usize = 0;
    var mutations: usize = 0;
    var parsed: usize = 0;
    for (arp_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [128]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (smith.value(bool)) {
            raw_arm += 1;
            if (arp.parseReply(buf[0..len]) != null) parsed += 1;
        } else {
            mutate_arm += 1;
            var reply = arp.buildRequest(
                .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
                .{ 192, 0, 2, 1 },
                .{ 192, 0, 2, 2 },
            );
            std.mem.writeInt(u16, reply[20..22], 0x0002, .big);
            var cur: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
            const n = cur.ranged(0, 6);
            mutations += n;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const pos = cur.ranged(0, @intCast(reply.len - 1));
                reply[pos] = cur.byte();
            }
            if (arp.parseReply(&reply) != null) parsed += 1;
        }
    }
    // ⛔ `mutate_arm` and `mutations` were both **0** for every input this
    // target had ever run, and `parsed` was 0 too — `parseReply("")` was the
    // only call it ever made.
    try testing.expectEqual(@as(usize, 4), raw_arm);
    try testing.expectEqual(@as(usize, 5), mutate_arm);
    try testing.expectEqual(@as(usize, 8), mutations);
    try testing.expectEqual(@as(usize, 5), parsed);
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

test "ipv4Addr / ipv4Netmask: real ioctl on `lo` (unprivileged — no CAP_NET_RAW needed)" {
    // Unlike the Socket.open tests below, ipv4Addr/ipv4Netmask (like hwaddr
    // and ifaceName) only need a throwaway AF_INET/SOCK_DGRAM socket for the
    // ioctl, so this runs unconditionally rather than SkipZigTest-ing on a
    // missing capability. `lo` is 127.0.0.1/8 once up — the host's default
    // netns already has it up, but a fresh netns (`unshare -rn`) starts `lo`
    // DOWN and *without* that address (measured: SIOCGIFADDR fails until
    // `ip link set lo up`, which is also why the loopback round-trip test
    // below calls the same helper) — Linux autoconfigures 127.0.0.1/8 only
    // once the link comes up.
    bringLoopbackUp(); // best-effort; needs CAP_NET_ADMIN, which `unshare -rn` grants

    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    try testing.expectEqual(.SUCCESS, linux.errno(rc));
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    const lo = try ifaceByName("lo");
    const addr = ipv4Addr(fd, lo) catch |e| switch (e) {
        // Only reachable in an unprivileged fresh netns, where `lo` can
        // never be brought up (no CAP_NET_ADMIN) and so never gets an
        // address — an environment limitation, not a missing feature.
        error.NoSuchInterface => return error.SkipZigTest,
        else => return e,
    };
    try testing.expectEqual([_]u8{ 127, 0, 0, 1 }, addr);
    try testing.expectEqual([_]u8{ 255, 0, 0, 0 }, try ipv4Netmask(fd, lo));
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

test "F13 fix: setRcvTimeout surfaces a failed setsockopt instead of discarding it" {
    // fd -1 makes setsockopt fail with EBADF, unconditionally, no privilege
    // needed. Before F13 this call was `fn (...) void` with `_ =` in front
    // of the setsockopt — there was no way to observe this at all; the
    // socket would silently NOT have a timeout and nothing would say so.
    try testing.expectError(error.TimeoutFailed, setRcvTimeout(-1, 200));
}

test "F1 fix: recv() reports wire_len distinct from a truncated bytes.len (needs CAP_NET_RAW + netns)" {
    const lo = ifaceByName("lo") catch return error.SkipZigTest;
    bringLoopbackUp();

    var cap = Socket.open(test_ethertype, .{ .iface = "lo", .recv_timeout_ms = 300 }) catch |e| switch (e) {
        error.AccessDenied, error.NoSuchInterface => return error.SkipZigTest,
        else => return e,
    };
    defer cap.close();

    var inj = Socket.openInject(lo) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };
    defer inj.close();

    // A payload well over a deliberately small capture buffer: 100 bytes ->
    // a 114-byte frame (14-byte Ethernet header + 100), read into 20 bytes.
    var payload: [100]u8 = undefined;
    @memset(&payload, 0xab);
    const dst = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    inj.send(lo, dst, test_ethertype, &payload) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };

    var small_buf: [20]u8 = undefined;
    var tries: usize = 0;
    while (tries < 8) : (tries += 1) {
        const frame = cap.recv(&small_buf) catch |e| switch (e) {
            error.WouldBlock, error.Interrupted => return error.SkipZigTest,
            else => return e,
        };
        if (frame.ethertype != test_ethertype) continue;
        // BEFORE F1 this frame was indistinguishable from a complete 20-byte
        // one: `bytes.len == buf.len` either way, and `Frame` had no second
        // number to compare it against. `wire_len` is the fix.
        try testing.expectEqual(@as(usize, 20), frame.bytes.len);
        try testing.expectEqual(@as(usize, eth_hdr_len + payload.len), frame.wire_len);
        try testing.expect(frame.bytes.len < frame.wire_len);
        return;
    }
    return error.SkipZigTest;
}

test "F5 fix: Socket.stats() reports a real packet count (needs CAP_NET_RAW + netns)" {
    const lo = ifaceByName("lo") catch return error.SkipZigTest;
    bringLoopbackUp();

    var cap = Socket.open(test_ethertype, .{ .iface = "lo", .recv_timeout_ms = 300 }) catch |e| switch (e) {
        error.AccessDenied, error.NoSuchInterface => return error.SkipZigTest,
        else => return e,
    };
    defer cap.close();

    var inj = Socket.openInject(lo) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };
    defer inj.close();
    const dst = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    inj.send(lo, dst, test_ethertype, "stats-probe") catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    };

    // Drain until we see our own frame, so the kernel has definitely counted
    // at least one packet for this socket.
    var buf: [256]u8 = undefined;
    var tries: usize = 0;
    var seen = false;
    while (tries < 8 and !seen) : (tries += 1) {
        const frame = cap.recv(&buf) catch |e| switch (e) {
            error.WouldBlock, error.Interrupted => break,
            else => return e,
        };
        if (frame.ethertype == test_ethertype) seen = true;
    }
    if (!seen) return error.SkipZigTest;

    // BEFORE F5 there was no way to ask the kernel this at all — a socket
    // that lost every frame to a full receive queue and one that saw a
    // quiet wire both returned `error.WouldBlock` from `recv`. `stats()` is
    // the fix; a real, positive, kernel-reported count is the measurement.
    const after = try cap.stats();
    try testing.expect(after.packets >= 1);
}

test "F14 fix: Options.recv_buf_bytes actually moves SO_RCVBUF (needs CAP_NET_RAW)" {
    var sock = Socket.open(test_ethertype, .{ .iface = "lo", .recv_buf_bytes = 8192 }) catch |e| switch (e) {
        error.AccessDenied, error.NoSuchInterface => return error.SkipZigTest,
        else => return e,
    };
    defer sock.close();

    var got: u32 = 0;
    var len: linux.socklen_t = @sizeOf(u32);
    const rc = linux.getsockopt(sock.fd, linux.SOL.SOCKET, linux.SO.RCVBUF, @ptrCast(&got), &len);
    try testing.expectEqual(.SUCCESS, linux.errno(rc));
    // The kernel doubles whatever is requested and enforces its own floor
    // (man socket(7)), so this isn't byte-exact — but BEFORE F14 there was no
    // knob at all: every socket got this kernel's default, measured 212992
    // in `A1/rawsock.md` F5/F14 (and directly responsible for that finding's
    // 98.9% burst loss). Requesting 8192 must move it well below that.
    try testing.expect(got < 212992);
}

test {
    testing.refAllDecls(@This());
}
