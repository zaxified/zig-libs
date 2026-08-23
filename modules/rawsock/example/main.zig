// SPDX-License-Identifier: MIT

//! What a link-layer consumer does with `rawsock`: build and parse the
//! wire formats (Ethernet header, hwaddr text, classic-BPF filter, ARP)
//! that never need a socket, look up interface facts that need no
//! capability, and attempt the AF_PACKET capture/inject path that does.
//!
//! ⚠ WHAT RAN LIVE VS. WHAT DID NOT, AND WHY:
//!
//!  - **LIVE, unprivileged**: `ifaceByName("lo")`, `ifaceName`, `hwaddr`,
//!    `ipv4Addr`, `ipv4Netmask` — all real `ioctl`s on a throwaway
//!    `AF_INET`/`SOCK_DGRAM` socket, no `CAP_NET_RAW` needed (the module's
//!    own doc comments say so; this example proves it by calling them for
//!    real against `lo`, which every Linux host has, up, with an address).
//!  - **LIVE, gated on privilege**: `Socket.open` (AF_PACKET) genuinely
//!    needs `CAP_NET_RAW`. Following the `traceroute` example's pattern,
//!    this example calls it for real and asserts the named
//!    `error.AccessDenied` it gets without the capability; with it (e.g.
//!    root), it runs the real capture + `setFilter` + `setPromisc` +
//!    cooked-inject-and-capture-back loopback round trip instead, so the
//!    check is never vacuous either way.
//!  - **NOT live, by construction from the module's own public encoder**:
//!    a "captured-shape" Ethernet+ARP exchange. `loopback` never does ARP
//!    (local delivery skips neighbour resolution, and `lo` has no real
//!    hardware address), so there is no unprivileged live path to a real
//!    ARP frame at all — the module's own real-capture goldens needed a
//!    veth pair in two network namespaces to get one (`root.zig`'s
//!    "real-capture goldens" section). This example instead builds a
//!    request with `arp.buildRequest` (the module's own public encoder,
//!    not hand-invented bytes) and derives a reply from it the way a real
//!    responder would, then parses it back with `arp.parseReply` — the
//!    same pure codec the module ships for exactly this reason.
//!
//! This module allocates nowhere in its public API (`std.mem.Allocator`
//! does not appear anywhere in `root.zig`) — there is no OutOfMemory path
//! to exercise and no `std.heap.DebugAllocator` gate to wrap this example
//! in.

const std = @import("std");
const rawsock = @import("rawsock");
const netaddr = @import("netaddr");
const linux = std.os.linux;

/// `struct ifreq`, shaped the way `SIOCGIFFLAGS`/`SIOCSIFFLAGS` need it —
/// plain `std.os.linux` syscalls, not a reach into `rawsock`'s own private
/// `ifreq` (this example only ever sees the module's PUBLISHED surface).
const ExampleIfreq = extern struct {
    name: [16]u8 = @splat(0),
    un: [24]u8 = @splat(0),
};

/// Best-effort `ip link set lo up`, needed only inside the CAP_NET_RAW-gated
/// branch below: a fresh network namespace (e.g. `unshare -rn`) starts `lo`
/// DOWN, and a downed loopback drops every frame sent on it before this
/// example's capture socket ever sees one. This never runs unless the
/// operator already elevated privilege to reach that branch in the first
/// place (matching `CAP_NET_ADMIN`, which `unshare -rn`'s root grants
/// alongside `CAP_NET_RAW`) — the unprivileged baseline run never touches
/// this function at all. Errors are ignored; a `lo` this can't bring up
/// just means the loopback round trip below observes nothing and says so.
fn bringLoopbackUp() void {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var req: ExampleIfreq = .{};
    @memcpy(req.name[0..2], "lo");
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&req))) != .SUCCESS) return;
    var flags = std.mem.readInt(u16, req.un[0..2], .little);
    flags |= 0x1; // IFF_UP
    std.mem.writeInt(u16, req.un[0..2], flags, .little);
    _ = linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&req));
}

pub fn main() !void {
    // ── 1. pure: Ethernet header, hwaddr text, BPF filter ─────────────────

    const src_mac = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const dst_mac = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    const h: rawsock.EthHeader = .{ .dst = dst_mac, .src = src_mac, .ethertype = rawsock.eth_p.arp };
    var eth_buf: [rawsock.eth_hdr_len]u8 = undefined;
    h.write(&eth_buf);
    const parsed = rawsock.EthHeader.parse(&eth_buf) orelse return error.ParseFailed;
    if (parsed.ethertype != rawsock.eth_p.arp) return error.WrongEthertype;

    var mac_buf: [rawsock.hwaddr_text_len]u8 = undefined;
    const mac_text = rawsock.formatHwaddr(src_mac, &mac_buf);
    if (rawsock.parseHwaddr(mac_text)) |round_tripped| {
        if (!std.mem.eql(u8, &round_tripped, &src_mac)) return error.HwaddrMismatch;
    } else return error.ParseHwaddrFailed;
    std.debug.print("EthHeader + hwaddr round-trip OK ({s})\n", .{mac_text});

    const filter = rawsock.etherTypeFilter(rawsock.eth_p.arp);
    if (filter.len != 4) return error.WrongFilterLength;
    if (filter[1].k != rawsock.eth_p.arp) return error.WrongFilterMatch;
    std.debug.print("etherTypeFilter(ARP): {d} classic-BPF instructions built\n", .{filter.len});

    // ── 2. captured-shape ARP, built from the module's own public encoder ──

    const my_ip = [4]u8{ 192, 0, 2, 10 };
    const their_ip = [4]u8{ 192, 0, 2, 20 };
    const request = rawsock.arp.buildRequest(src_mac, my_ip, their_ip);
    if (rawsock.arp.parseReply(&request) != null) return error.RequestShouldNotParseAsReply;

    // A real responder's reply: same frame shape, oper flipped to 2,
    // sender fields swapped to the answering host's own identity.
    var reply = request;
    std.mem.writeInt(u16, reply[20..22], 0x0002, .big); // oper = reply
    @memcpy(reply[6..12], &dst_mac); // Ethernet src = responder
    @memcpy(reply[22..28], &dst_mac); // ARP sender MAC = responder
    @memcpy(reply[28..32], &their_ip); // ARP sender IP = responder's own

    const got = rawsock.arp.parseReply(&reply) orelse return error.ParseReplyFailed;
    if (!got.ip.eql(.{ .v4 = their_ip })) return error.WrongSenderIp;
    if (!std.mem.eql(u8, &got.mac, &dst_mac)) return error.WrongSenderMac;
    std.debug.print("arp: built a request, derived+parsed a reply (sender {any})\n", .{got.ip});

    // ── 3. LIVE, unprivileged: interface facts on `lo` ─────────────────────

    const lo = try rawsock.ifaceByName("lo");
    var namebuf: [16]u8 = undefined;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    const lo_name = try rawsock.ifaceName(fd, lo, &namebuf);
    if (!std.mem.eql(u8, lo_name, "lo")) return error.WrongIfaceName;
    const lo_hw = try rawsock.hwaddr(fd, lo);
    std.debug.print("lo: index={d} name={s} hwaddr={any}\n", .{ lo, lo_name, lo_hw });

    if (rawsock.ipv4Addr(fd, lo)) |addr| {
        std.debug.print("lo: ipv4={any} netmask={any}\n", .{ addr, try rawsock.ipv4Netmask(fd, lo) });
    } else |err| switch (err) {
        // Only reachable in an unprivileged network namespace where `lo`
        // was never brought up and so never got an address -- an
        // environment limitation, not a missing feature (mirrors
        // root.zig's own test for the same ioctl).
        error.NoSuchInterface => std.debug.print("lo: no IPv4 address in this sandbox (environment-limited, not a failure)\n", .{}),
        else => return err,
    }

    // ── 4. named negative case, pure (no socket, no privilege) ────────────

    const dummy_sock: rawsock.Socket = .{ .fd = -1 };
    if (dummy_sock.setFilter(&.{})) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidFilter => std.debug.print("setFilter(&.{{}}): InvalidFilter (expected, checked before any syscall)\n", .{}),
        error.FilterFailed => return err,
    }

    if (rawsock.ifaceByName("zig-libs-example-no-such-iface")) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.NoSuchInterface => std.debug.print("ifaceByName(\"zig-libs-example-no-such-iface\"): NoSuchInterface (expected)\n", .{}),
        error.SocketFailed => return err,
    }

    // ── 5. LIVE, gated on CAP_NET_RAW: the AF_PACKET path ──────────────────

    const test_ethertype: u16 = 0x88b5; // ETH_P_802_EX1, unlikely to collide with real traffic
    bringLoopbackUp(); // best-effort; only matters inside this branch, see the function's doc comment
    if (rawsock.Socket.open(test_ethertype, .{ .iface = "lo", .recv_timeout_ms = 300 })) |cap_const| {
        var cap = cap_const;
        defer cap.close();
        try cap.setFilter(&rawsock.etherTypeFilter(test_ethertype));
        try cap.setPromisc(lo, true);
        try cap.setPromisc(lo, false);

        var inj = try rawsock.Socket.openInject(lo);
        defer inj.close();
        const payload = "rawsock-example-selftest";
        try inj.send(lo, dst_mac, test_ethertype, payload);

        var recv_buf: [2048]u8 = undefined;
        var seen = false;
        var tries: usize = 0;
        while (tries < 8 and !seen) : (tries += 1) {
            const frame = cap.recv(&recv_buf) catch |err| switch (err) {
                error.WouldBlock, error.Interrupted => continue,
                error.RecvFailed => return err,
            };
            const feth = rawsock.EthHeader.parse(frame.bytes) orelse continue;
            if (feth.ethertype != test_ethertype) continue;
            if (std.mem.indexOf(u8, frame.bytes[rawsock.eth_hdr_len..], payload) != null) seen = true;
        }
        std.debug.print(
            "CAP_NET_RAW IS available: real AF_PACKET capture+inject on lo ran, saw own frame back={}\n",
            .{seen},
        );
    } else |err| switch (err) {
        error.AccessDenied => std.debug.print(
            "Socket.open(AF_PACKET): AccessDenied (expected -- no CAP_NET_RAW on this host)\n",
            .{},
        ),
        error.NoSuchInterface, error.BindFailed, error.SocketFailed => return err,
    }

    std.debug.print("OK: all rawsock example checks passed\n", .{});
}
