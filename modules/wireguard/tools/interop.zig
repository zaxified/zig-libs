// SPDX-License-Identifier: MIT

//! LIVE interop of `wireguard`'s handshake and data plane against the Linux
//! kernel's own WireGuard (`wireguard.ko`), and the recorder that freezes both
//! exchanges into `src/testdata/kernel_handshake.zig`, which
//! `src/kernel_handshake_replay.zig` replays with no kernel, no root and no
//! socket.
//!
//! ## Why this is a PROGRAM and not a test
//!
//! The kernel test in `handshake.zig` needs euid 0 to create a WireGuard
//! link, so it SKIPS in every lane that is not root -- it was never the
//! offline anchor. This program takes the anchor once, in a user + network
//! namespace, and the module's own lane replays its bytes everywhere.
//!
//! ## Usage
//!
//!     unshare -rn zig build interop-wireguard                # check both directions
//!     unshare -rn zig build interop-wireguard -- --capture   # ...and rewrite the transcript
//!
//! (`unshare -rn` maps the caller to root in a fresh user + network namespace:
//! the links and sockets vanish with it, nothing touches the host.) Needs `ip`
//! and the `wireguard` kernel module.
//!
//!     zig build interop-wireguard -- --wireguard-go            # needs go, no root
//!     zig build interop-wireguard -- --wireguard-go --capture  # ...and rewrite uapi_get.txt
//!
//! The first form also drives `Tunnel` against the kernel in both roles (C) and
//! checks `conf` and `listDevices` against the real `wg` (D). The second builds
//! `tools/go_oracle` (a real wireguard-go, b3bc704ef0ee, MIT) and runs `uapi.Client`
//! and `Tunnel` against it in both roles (E).
//!
//! ## What is recorded
//!
//! Every key, ephemeral, index and timestamp on OUR side is a fixed constant
//! -- the ones `handshake.zig`'s KAT uses -- so our bytes are reproducible,
//! and the replay can require that this module still produces exactly the
//! bytes the kernel accepted. The kernel's side is random and is what is
//! frozen.
//!
//! - **A: the kernel initiates.** A kernel device with the KAT initiator's
//!   static key and our KAT responder key as its peer (persistent keepalive
//!   1 s, so it initiates at once). We consume its initiation, answer with
//!   our response, and open the keepalive it then sends.
//! - **B: we initiate.** A kernel device with the KAT responder's static
//!   key, address 10.77.0.1/24, our KAT initiator key as peer (allowed
//!   10.77.0.2/32). Our initiation is byte-for-byte the KAT's `msg1`; the
//!   kernel answers; we seal an ICMP echo request 10.77.0.2 -> 10.77.0.1
//!   through the session, and open the kernel's echo reply.

const std = @import("std");
const wg = @import("wireguard");
const hs = wg.handshake;
const transport = wg.transport;
const linux = std.os.linux;

const transcript_path = "modules/wireguard/src/testdata/kernel_handshake.zig";

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// The KAT's constants (`handshake.zig`, `const kat`).
const si_priv = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const sr_priv = hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
const ei_priv = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const er_priv = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
const psk: hs.PresharedKey = @splat(0x55);
const timestamp = hex("400000005e6b0d3d0e2f6b4a");
const idx_i: u32 = 0x11111111;
const idx_r: u32 = 0x22222222;
/// The session clock both replays use; nothing here is near its limits.
const now_s: u64 = 1_000;

const port_b: u16 = 51899;
const ping_payload = "zig-libs wg ping";

fn fail(comptime fmt: []const u8, args: anytype) error{Mismatch} {
    std.debug.print("FAIL: " ++ fmt ++ "\n", args);
    return error.Mismatch;
}

fn run(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    const r = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    switch (r.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    std.debug.print("`{s}` failed: {s}\n", .{ argv[0], r.stderr });
    return error.CommandFailed;
}

const Udp = struct {
    fd: i32,
    port: u16,

    fn open() !Udp {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.Socket;
        const fd: i32 = @intCast(rc);
        var a: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        if (linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.Bind;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        _ = linux.getsockname(fd, @ptrCast(&a), &len);
        return .{ .fd = fd, .port = std.mem.bigToNative(u16, a.port) };
    }

    fn close(u: Udp) void {
        _ = linux.close(u.fd);
    }

    /// The next datagram of `want_type`, within `ms`; others are skipped.
    fn recvType(u: Udp, buf: []u8, want_type: u32, ms: i32, from: *linux.sockaddr.in) ![]u8 {
        var left: i32 = ms;
        while (left > 0) : (left -= 100) {
            var pfd = [1]linux.pollfd{.{ .fd = u.fd, .events = linux.POLL.IN, .revents = 0 }};
            if (linux.poll(&pfd, 1, 100) == 0) continue;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(u.fd, buf.ptr, buf.len, 0, @ptrCast(from), &len);
            if (linux.errno(n) != .SUCCESS or n < 4) continue;
            if (std.mem.readInt(u32, buf[0..4], .little) == want_type) return buf[0..n];
        }
        return error.Timeout;
    }

    fn sendTo(u: Udp, bytes: []const u8, to: *const linux.sockaddr.in) !void {
        const rc = linux.sendto(u.fd, bytes.ptr, bytes.len, 0, @ptrCast(to), @sizeOf(linux.sockaddr.in));
        if (linux.errno(rc) != .SUCCESS) return error.Send;
    }
};

fn keypair(priv: [32]u8) hs.Keypair {
    var kp: hs.Keypair = undefined;
    hs.Keypair.fromPrivateKey(&priv, &kp) catch unreachable;
    return kp;
}

fn appendHex(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, bytes: []const u8) !void {
    try out.print(gpa, "pub const {s} = \"{x}\";\n", .{ name, bytes });
}

/// A: the kernel initiates, we respond.
fn kernelInitiates(gpa: std.mem.Allocator, io: std.Io, out: *std.ArrayList(u8)) !void {
    const udp = try Udp.open();
    defer udp.close();
    try run(gpa, io, &.{ "ip", "link", "add", "wga", "type", "wireguard" });
    defer run(gpa, io, &.{ "ip", "link", "del", "wga" }) catch {};
    var ctl = try wg.Wireguard.open(gpa);
    defer ctl.close();
    try ctl.setDevice(.{
        .ifname = "wga",
        .private_key = si_priv,
        .peers = &.{.{
            .public_key = keypair(sr_priv).public,
            .preshared_key = psk,
            .endpoint = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = udp.port } },
            .persistent_keepalive_interval = 1,
        }},
    });
    try run(gpa, io, &.{ "ip", "link", "set", "wga", "up" });

    var buf: [2048]u8 = undefined;
    var from: linux.sockaddr.in = undefined;
    const init_bytes = try udp.recvType(&buf, @backingInt(hs.MessageType.handshake_initiation), 10_000, &from);
    if (init_bytes.len != @sizeOf(hs.MessageInitiation)) return fail("A: initiation of {d} bytes", .{init_bytes.len});
    try appendHex(gpa, out, "a_initiation", init_bytes);

    var h: hs.Handshake = .{
        .static_keypair = keypair(sr_priv),
        .remote_static_public = keypair(si_priv).public,
        .preshared_key = psk,
        .local_ephemeral = keypair(er_priv),
        .local_index = idx_r,
    };
    var msg1: hs.MessageInitiation = undefined;
    @memcpy(std.mem.asBytes(&msg1), init_bytes);
    try h.consumeInitiation(msg1);
    const msg2 = try h.createResponse(io);
    try appendHex(gpa, out, "a_response", std.mem.asBytes(&msg2));
    var session: transport.Session = undefined;
    h.transportSession(false, now_s, &session);
    try udp.sendTo(std.mem.asBytes(&msg2), &from);

    const ka = try udp.recvType(&buf, @backingInt(hs.MessageType.transport_data), 10_000, &from);
    var empty: [0]u8 = .{};
    const r = try session.recv.open(&empty, ka, now_s);
    if (r.len != 0) return fail("A: keepalive opened to {d} bytes", .{r.len});
    try appendHex(gpa, out, "a_keepalive", ka);
    std.debug.print("A: the kernel's initiation answered, its keepalive opens\n", .{});
}

fn ipChecksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) sum += std.mem.readInt(u16, bytes[i..][0..2], .big);
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @truncate(sum));
}

/// The ICMP echo request we tunnel in B: 10.77.0.2 -> 10.77.0.1.
pub fn echoRequest() [20 + 8 + ping_payload.len]u8 {
    var p: [20 + 8 + ping_payload.len]u8 = @splat(0);
    p[0] = 0x45;
    std.mem.writeInt(u16, p[2..4], p.len, .big);
    std.mem.writeInt(u16, p[4..6], 0x1234, .big);
    p[8] = 64;
    p[9] = 1;
    p[12..16].* = .{ 10, 77, 0, 2 };
    p[16..20].* = .{ 10, 77, 0, 1 };
    std.mem.writeInt(u16, p[10..12], ipChecksum(p[0..20]), .big);
    p[20] = 8;
    std.mem.writeInt(u16, p[24..26], 0x4242, .big);
    std.mem.writeInt(u16, p[26..28], 1, .big);
    @memcpy(p[28..], ping_payload);
    std.mem.writeInt(u16, p[22..24], ipChecksum(p[20..]), .big);
    return p;
}

/// B: we initiate, the kernel responds, a ping goes through.
fn weInitiate(gpa: std.mem.Allocator, io: std.Io, out: *std.ArrayList(u8)) !void {
    const udp = try Udp.open();
    defer udp.close();
    try run(gpa, io, &.{ "ip", "link", "add", "wgb", "type", "wireguard" });
    defer run(gpa, io, &.{ "ip", "link", "del", "wgb" }) catch {};
    var ctl = try wg.Wireguard.open(gpa);
    defer ctl.close();
    try ctl.setDevice(.{
        .ifname = "wgb",
        .private_key = sr_priv,
        .listen_port = port_b,
        .peers = &.{.{
            .public_key = keypair(si_priv).public,
            .preshared_key = psk,
            .allowed_ips = &.{wg.AllowedIp.v4(.{ 10, 77, 0, 2 }, 32)},
        }},
    });
    try run(gpa, io, &.{ "ip", "addr", "add", "10.77.0.1/24", "dev", "wgb" });
    try run(gpa, io, &.{ "ip", "link", "set", "wgb", "up" });

    var h: hs.Handshake = .{
        .static_keypair = keypair(si_priv),
        .remote_static_public = keypair(sr_priv).public,
        .preshared_key = psk,
        .local_ephemeral = keypair(ei_priv),
        .local_index = idx_i,
    };
    const msg1 = try h.createInitiation(io, timestamp);
    try appendHex(gpa, out, "b_initiation", std.mem.asBytes(&msg1));
    const kernel: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port_b), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try udp.sendTo(std.mem.asBytes(&msg1), &kernel);

    var buf: [2048]u8 = undefined;
    var from: linux.sockaddr.in = undefined;
    const resp = try udp.recvType(&buf, @backingInt(hs.MessageType.handshake_response), 10_000, &from);
    if (resp.len != @sizeOf(hs.MessageResponse)) return fail("B: response of {d} bytes", .{resp.len});
    try appendHex(gpa, out, "b_response", resp);
    var msg2: hs.MessageResponse = undefined;
    @memcpy(std.mem.asBytes(&msg2), resp);
    try h.consumeResponse(msg2);
    var session: transport.Session = undefined;
    h.transportSession(true, now_s, &session);

    const ping = echoRequest();
    var sealed: [transport.sealedLen(ping.len)]u8 = undefined;
    _ = try session.send.seal(&sealed, &ping, now_s);
    try appendHex(gpa, out, "b_ping", &sealed);
    try udp.sendTo(&sealed, &kernel);

    const reply = try udp.recvType(&buf, @backingInt(hs.MessageType.transport_data), 10_000, &from);
    var plain: [256]u8 = undefined;
    const r = try session.recv.open(&plain, reply, now_s);
    const ip = plain[0..r.len];
    if (ip.len < 28 or ip[9] != 1 or ip[20] != 0) return fail("B: the kernel's reply is not an ICMP echo reply", .{});
    if (!std.mem.eql(u8, ip[28..][0..ping_payload.len], ping_payload)) return fail("B: echo payload differs", .{});
    try appendHex(gpa, out, "b_pong", reply);
    std.debug.print("B: the kernel accepted our initiation and ping, its echo reply opens\n", .{});
}

// ── C: Tunnel against the kernel ────────────────────────────────────────────

fn clockNow(io: std.Io) wg.tunnel.Clock {
    const mono = std.Io.Clock.awake.now(io).toMilliseconds();
    const wall = std.Io.Clock.real.now(io).toNanoseconds();
    return .{
        .mono_ms = @intCast(mono),
        .tai64n = wg.tunnel.tai64n(@intCast(@divTrunc(wall, 1_000_000_000)), @intCast(@mod(wall, 1_000_000_000))),
    };
}

/// Run a tunnel's output through the socket until `want` comes up the tunnel.
fn pumpUntil(io: std.Io, t: *wg.Tunnel, udp: Udp, peer: *linux.sockaddr.in, want: []const u8, ms: i32) !void {
    var buf: [2048]u8 = undefined;
    var dgram: [2048]u8 = undefined;
    var left = ms;
    while (left > 0) : (left -= 50) {
        while (true) {
            switch (try t.poll(io, clockNow(io), &buf)) {
                .network => |b| try udp.sendTo(b, peer),
                else => break,
            }
        }
        var pfd = [1]linux.pollfd{.{ .fd = udp.fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&pfd, 1, 50) == 0) continue;
        var from: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        const n = linux.recvfrom(udp.fd, &dgram, dgram.len, 0, @ptrCast(&from), &len);
        if (linux.errno(n) != .SUCCESS) continue;
        const r = t.decapsulate(io, clockNow(io), dgram[0..n], &buf) catch |e| {
            std.debug.print("  dropped: {s}\n", .{@errorName(e)});
            continue;
        };
        if (r.authenticated) peer.* = from;
        switch (r.output) {
            .network => |b| try udp.sendTo(b, peer),
            .tunnel => |plain| {
                if (want.len != 0 and std.mem.eql(u8, plain[28..], want[28..])) return;
            },
            .none => {},
        }
        if (want.len == 0 and t.hasSession(clockNow(io))) return;
    }
    return error.Timeout;
}

fn tunnelAgainstKernel(gpa: std.mem.Allocator, io: std.Io) !void {
    const udp = try Udp.open();
    defer udp.close();
    try run(gpa, io, &.{ "ip", "link", "add", "wgc", "type", "wireguard" });
    defer run(gpa, io, &.{ "ip", "link", "del", "wgc" }) catch {};
    var ctl = try wg.Wireguard.open(gpa);
    defer ctl.close();
    const peer_pub = keypair(si_priv).public;
    try ctl.setDeviceFrom(&.{
        .ifname = "wgc",
        .private_key = sr_priv,
        .listen_port = port_b,
        .peers = &.{.{
            .public_key = peer_pub,
            .preshared_key = psk,
            .allowed_ips = &.{wg.AllowedIp.v4(.{ 10, 77, 0, 2 }, 32)},
            .endpoint = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = udp.port } },
        }},
    });
    try run(gpa, io, &.{ "ip", "addr", "add", "10.77.0.1/24", "dev", "wgc" });
    try run(gpa, io, &.{ "ip", "link", "set", "wgc", "up" });

    var stage: [4096]u8 = undefined;
    var t: wg.Tunnel = undefined;
    try wg.Tunnel.init(&t, &.{ .static_private = &si_priv, .remote_static = keypair(sr_priv).public, .preshared_key = &psk, .stage = &stage }, io, clockNow(io));
    defer t.wipe();
    var kernel: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port_b), .addr = std.mem.nativeToBig(u32, 0x7f000001) };

    // C1: we initiate, on a packet that waits on the stage; the kernel answers it.
    var buf: [2048]u8 = undefined;
    const ping = echoRequest();
    switch (try t.encapsulate(io, clockNow(io), &ping, &buf)) {
        .network => |b| try udp.sendTo(b, &kernel),
        else => return fail("C1: no initiation", .{}),
    }
    try pumpUntil(io, &t, udp, &kernel, &ping, 10_000);
    std.debug.print("C1: Tunnel initiated, the staged ping crossed the kernel and came back\n", .{});

    // C2: the kernel initiates at us: its responder path is Tunnel's. The device's
    // own session has to go first, or it would just use it.
    var r: wg.Tunnel = undefined;
    try wg.Tunnel.init(&r, &.{ .static_private = &si_priv, .remote_static = keypair(sr_priv).public, .preshared_key = &psk }, io, clockNow(io));
    defer r.wipe();
    try ctl.setDeviceFrom(&.{
        .ifname = "wgc",
        .peers = &.{.{ .public_key = peer_pub, .remove = true }},
    });
    try ctl.setDeviceFrom(&.{
        .ifname = "wgc",
        .peers = &.{.{
            .public_key = peer_pub,
            .preshared_key = psk,
            .allowed_ips = &.{wg.AllowedIp.v4(.{ 10, 77, 0, 2 }, 32)},
            .endpoint = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = udp.port } },
            .persistent_keepalive_interval = 1,
        }},
    });
    try pumpUntil(io, &r, udp, &kernel, "", 10_000);
    const p2 = (try r.encapsulate(io, clockNow(io), &ping, &buf)).network;
    try udp.sendTo(p2, &kernel);
    try pumpUntil(io, &r, udp, &kernel, &ping, 10_000);
    std.debug.print("C2: Tunnel responded, its first data crossed the kernel and came back\n", .{});
}

// ── D: conf and listDevices against wg(8) ───────────────────────────────────

const conf_dir = ".zig-cache/interop-wireguard";

fn capture(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) !struct { ok: bool, out: []u8 } {
    const r = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(r.stderr);
    return .{ .ok = r.term == .exited and r.term.exited == 0, .out = r.stdout };
}

/// `wg <verb> <device> /dev/stdin`, the text down a pipe. No file: a distribution's
/// AppArmor profile for `wg` may refuse to open a config outside /etc/wireguard
/// (Ubuntu's does). True if it exited 0; `must` turns a refusal into an error.
fn wgFeed(io: std.Io, verb: []const u8, device: []const u8, text: []const u8, must: bool) !void {
    const ok = try wgStdin(io, verb, device, text);
    if (must and !ok) return fail("wg {s} {s} refused its input", .{ verb, device });
}

fn wgAccepts(io: std.Io, text: []const u8) !bool {
    return wgStdin(io, "setconf", "wgd", text);
}

fn wgStdin(io: std.Io, verb: []const u8, device: []const u8, text: []const u8) !bool {
    var child = try std.process.spawn(io, .{ .argv = &.{ "wg", verb, device, "/dev/stdin" }, .stdin = .pipe, .stdout = .ignore, .stderr = .ignore });
    var wbuf: [4096]u8 = undefined;
    var w = child.stdin.?.writerStreaming(io, &wbuf);
    w.interface.writeAll(text) catch {};
    w.interface.flush() catch {};
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    return term == .exited and term.exited == 0;
}

const conf_full =
    \\[Interface]
    \\PrivateKey = wFvUHvCFh9Vyq7hzvWhH3l2pW9Wg4ZzGZ1m4ZQ1rV3M=
    \\ListenPort = 51777
    \\FwMark = 0x2a
    \\
    \\[Peer]
    \\PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
    \\PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
    \\AllowedIPs = 10.0.0.0/24, 2001:db8::/32
    \\Endpoint = 203.0.113.5:51820
    \\PersistentKeepalive = 25
    \\
    \\[Peer]
    \\PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
    \\AllowedIPs = 10.1.0.1/32
    \\Endpoint = [2001:db8::1]:7
    \\
;

/// Text, and whether `wg setconf` is expected to take it, asked of `wg` itself.
const conf_cases = [_][]const u8{
    "",                                                                                             "# only a comment\n",                                                                                                                   "\n\n",
    "[interface]\n",                                                                                "[INTERFACE]\n",                                                                                                                        "[Interface] # c\n",
    "[ Interface ]\n",                                                                              "[Interface]x\n",                                                                                                                       "[Interface\n",
    "Interface]\n",                                                                                 "[Other]\n",                                                                                                                            "[Interface]\n[Interface]\n",
    "ListenPort = 1\n",                                                                             "[Interface]\nlistenport = 1\n",                                                                                                        "[Interface]\nLISTENPORT=1\n",
    "[Interface]\nListen Port = 1\n",                                                               "[Interface]\nListenPort = 1 2\n",                                                                                                      "[Interface]\nListenPort = 65535\n",
    "[Interface]\nListenPort = 65536\n",                                                            "[Interface]\nListenPort = -1\n",                                                                                                       "[Interface]\nListenPort =\n",
    "[Interface]\nListenPort = 0x10\n",                                                             "[Interface]\nListenPort = off\n",                                                                                                      "[Interface]\nFwMark = off\n",
    "[Interface]\nFwMark = OFF\n",                                                                  "[Interface]\nFwMark = 0\n",                                                                                                            "[Interface]\nFwMark = 0x10\n",
    "[Interface]\nFwMark = 0X10\n",                                                                 "[Interface]\nFwMark = 16\n",                                                                                                           "[Interface]\nFwMark = 4294967295\n",
    "[Interface]\nFwMark = 4294967296\n",                                                           "[Interface]\nFwMark = 0x100000000\n",                                                                                                  "[Interface]\nFwMark =\n",
    "[Interface]\nPrivateKey = short\n",                                                            "[Interface]\nPrivateKey =\n",                                                                                                          "[Interface]\nAddress = 10.0.0.1/24\n",
    "[Interface]\nFoo = 1\n",                                                                       "[Interface]\nNoEquals\n",                                                                                                              "[Interface]\n=1\n",
    "[Peer]\n",                                                                                     "[Peer]\nAllowedIPs = 10.0.0.1/32\n",                                                                                                   "[Peer]\nPublicKey = short\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n",                           "[peer]\npublickey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n",                                                                   "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nListenPort = 1\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPresharedKey =\n",           "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs =\n",                                                     "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.1\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/33\n", "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/8,,10.0.0.1/32\n",                             "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/8,\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = ,10.0.0.0/8\n", "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.1 / 8\n",                                        "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4:5\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4\n",       "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4:65536\n",                                         "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = [::1]:5\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = [1.2.3.4]:5\n",   "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint =\n",                                                       "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPersistentKeepalive = off\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPersistentKeepalive = 0\n",  "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPersistentKeepalive = 65535\n",                                      "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPersistentKeepalive = 65536\n",
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPersistentKeepalive =\n",    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n",
};

fn confAgainstWg(gpa: std.mem.Allocator, io: std.Io) !void {
    try run(gpa, io, &.{ "ip", "link", "add", "wgd", "type", "wireguard" });
    defer run(gpa, io, &.{ "ip", "link", "del", "wgd" }) catch {};
    try run(gpa, io, &.{ "ip", "link", "add", "wge", "type", "wireguard" });
    defer run(gpa, io, &.{ "ip", "link", "del", "wge" }) catch {};
    var ctl = try wg.Wireguard.open(gpa);
    defer ctl.close();

    // D1: wg and we read the same file to the same device; our print is theirs.
    try wgFeed(io, "setconf", "wgd", conf_full, true);
    var parsed: wg.conf.ParsedConfig = undefined;
    try wg.conf.parse(gpa, conf_full, .{}, null, &parsed);
    defer parsed.deinit();
    parsed.config.ifname = "wge";
    try ctl.setDeviceFrom(&parsed.config);
    const theirs = try capture(gpa, io, &.{ "wg", "showconf", "wgd" });
    defer gpa.free(theirs.out);
    const via_ours = try capture(gpa, io, &.{ "wg", "showconf", "wge" });
    defer gpa.free(via_ours.out);
    if (!std.mem.eql(u8, theirs.out, via_ours.out)) return fail("D1: devices differ:\n{s}\n---\n{s}", .{ theirs.out, via_ours.out });
    var dev = try ctl.getDevice("wgd");
    defer dev.deinit(gpa);
    var printed: std.Io.Writer.Allocating = .init(gpa);
    defer printed.deinit();
    try wg.conf.formatDevice(&printed.writer, &dev);
    // `wg showconf` ends each section with a blank line where ours separates them.
    const want = std.mem.trimEnd(u8, theirs.out, "\n");
    const have = std.mem.trimEnd(u8, printed.written(), "\n");
    if (!std.mem.eql(u8, want, have)) return fail("D1: formatDevice differs from wg showconf:\n{s}\n---\n{s}", .{ want, have });
    std.debug.print("D1: wg setconf and conf.parse + setDevice make the same device; formatDevice prints wg showconf\n", .{});

    // D2: setconf clears; ours too. (addconf keeps; ours too.)
    const small = "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.2.0.1/32\n";
    try wgFeed(io, "addconf", "wgd", small, true);
    var add: wg.conf.ParsedConfig = undefined;
    try wg.conf.parse(gpa, "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.2.0.1/32\n", .{ .mode = .add }, null, &add);
    defer add.deinit();
    add.config.ifname = "wge";
    try ctl.setDeviceFrom(&add.config);
    const a1 = try capture(gpa, io, &.{ "wg", "showconf", "wgd" });
    defer gpa.free(a1.out);
    const a2 = try capture(gpa, io, &.{ "wg", "showconf", "wge" });
    defer gpa.free(a2.out);
    if (!std.mem.eql(u8, a1.out, a2.out)) return fail("D2: addconf differs:\n{s}\n---\n{s}", .{ a1.out, a2.out });

    try wgFeed(io, "setconf", "wgd", small, true);
    var clr: wg.conf.ParsedConfig = undefined;
    try wg.conf.parse(gpa, "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.2.0.1/32\n", .{}, null, &clr);
    defer clr.deinit();
    clr.config.ifname = "wge";
    try ctl.setDeviceFrom(&clr.config);
    const c1 = try capture(gpa, io, &.{ "wg", "showconf", "wgd" });
    defer gpa.free(c1.out);
    const c2 = try capture(gpa, io, &.{ "wg", "showconf", "wge" });
    defer gpa.free(c2.out);
    if (!std.mem.eql(u8, c1.out, c2.out)) return fail("D2: setconf differs:\n{s}\n---\n{s}", .{ c1.out, c2.out });
    std.debug.print("D2: addconf keeps and setconf clears the same things\n", .{});

    // D3: syncconf. Both start from the full file, both move to another.
    try wgFeed(io, "setconf", "wgd", conf_full, true);
    try wgFeed(io, "setconf", "wge", conf_full, true);
    const next_text = "[Interface]\nPrivateKey = wFvUHvCFh9Vyq7hzvWhH3l2pW9Wg4ZzGZ1m4ZQ1rV3M=\nListenPort = 51778\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.3.0.0/16\nEndpoint = 203.0.113.5:51820\n";
    try wgFeed(io, "syncconf", "wgd", next_text, true);
    var nx: wg.conf.ParsedConfig = undefined;
    try wg.conf.parse(gpa, next_text, .{ .mode = .add }, null, &nx);
    defer nx.deinit();
    nx.config.ifname = "wge";
    var cur = try ctl.getDevice("wge");
    defer cur.deinit(gpa);
    var delta: wg.conf.ParsedConfig = undefined;
    try wg.conf.sync(gpa, &cur, &nx.config, &delta);
    defer delta.deinit();
    try ctl.setDeviceFrom(&delta.config);
    const s1 = try capture(gpa, io, &.{ "wg", "showconf", "wgd" });
    defer gpa.free(s1.out);
    const s2 = try capture(gpa, io, &.{ "wg", "showconf", "wge" });
    defer gpa.free(s2.out);
    if (!std.mem.eql(u8, s1.out, s2.out)) return fail("D3: syncconf differs:\n{s}\n---\n{s}", .{ s1.out, s2.out });
    std.debug.print("D3: conf.sync lands where wg syncconf does\n", .{});

    // D4: accept or refuse, line for line with wg itself.
    // wg passes these to getaddrinfo or truncates; conf.parse refuses on purpose.
    const stricter = [_][]const u8{
        "[Interface]\nListenPort = 65536\n",
        "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4:65536\n",
        "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = [1.2.3.4]:5\n",
    };
    var mismatches: usize = 0;
    var strict_seen: usize = 0;
    for (conf_cases) |text| {
        const r_ok = wgAccepts(io, text) catch |e| return e;
        var q: wg.conf.ParsedConfig = undefined;
        const ours = if (wg.conf.parse(gpa, text, .{}, null, &q)) |_| blk: {
            q.deinit();
            break :blk true;
        } else |_| false;
        var is_strict = false;
        for (stricter) |t| is_strict = is_strict or std.mem.eql(u8, t, text);
        if (is_strict and r_ok and !ours) {
            strict_seen += 1;
        } else if (ours != r_ok) {
            mismatches += 1;
            std.debug.print("D4: wg {s}, conf.parse {s}: {f}\n", .{ if (r_ok) "takes" else "refuses", if (ours) "takes" else "refuses", std.zig.fmtString(text) });
        }
    }
    if (mismatches != 0) return fail("D4: {d} of {d} files judged differently", .{ mismatches, conf_cases.len });
    std.debug.print("D4: {d} files judged alike by wg and conf.parse, {d} refused on purpose\n", .{ conf_cases.len - strict_seen, strict_seen });

    // D5: wg show interfaces.
    const names = try wg.listDevices(gpa);
    defer gpa.free(names);
    const shown = try capture(gpa, io, &.{ "wg", "show", "interfaces" });
    defer gpa.free(shown.out);
    var it = std.mem.tokenizeAny(u8, shown.out, " \n");
    var n: usize = 0;
    while (it.next()) |want_name| : (n += 1) {
        var found = false;
        for (names) |*x| found = found or std.mem.eql(u8, x.slice(), want_name);
        if (!found) return fail("D5: listDevices misses {s}", .{want_name});
    }
    if (n != names.len or n < 2) return fail("D5: {d} names from wg, {d} from listDevices", .{ n, names.len });
    std.debug.print("D5: listDevices names what wg show interfaces names ({d})\n", .{n});
}

// ── E: uapi.Client and Tunnel against a real wireguard-go ───────────────────

const go_dir = "modules/wireguard/tools/go_oracle";
const go_exe = conf_dir ++ "/go_oracle";
const uapi_capture_path = "modules/wireguard/src/testdata/uapi_get.txt";
const go_port: u16 = 51821;

fn againstWireguardGo(gpa: std.mem.Allocator, io: std.Io, want_capture: bool) !void {
    try std.Io.Dir.cwd().createDirPath(io, conf_dir);
    const abs_dir = try std.Io.Dir.cwd().realPathFileAlloc(io, conf_dir, gpa);
    defer gpa.free(abs_dir);
    const abs_exe = try std.fmt.allocPrint(gpa, "{s}/go_oracle", .{abs_dir});
    defer gpa.free(abs_exe);
    const build = try std.process.run(gpa, io, .{ .argv = &.{ "go", "build", "-o", abs_exe, "." }, .cwd = .{ .path = go_dir } });
    defer gpa.free(build.stdout);
    defer gpa.free(build.stderr);
    if (build.term != .exited or build.term.exited != 0) return fail("go build: {s}", .{build.stderr});

    // Not under the repository: a sockaddr_un path has 108 bytes.
    const sock_dir = try std.fmt.allocPrint(gpa, "/tmp/zig-libs-wg-{d}", .{linux.getpid()});
    defer gpa.free(sock_dir);
    try std.Io.Dir.cwd().createDirPath(io, sock_dir);
    defer std.Io.Dir.cwd().deleteDir(io, sock_dir) catch {};
    const sock_path = try std.fmt.allocPrint(gpa, "{s}/wgo0.sock", .{sock_dir});
    defer gpa.free(sock_path);
    defer std.Io.Dir.cwd().deleteFile(io, sock_path) catch {};

    var child = try std.process.spawn(io, .{ .argv = &.{ abs_exe, sock_path }, .stdin = .pipe, .stdout = .pipe, .stderr = .inherit });
    defer {
        child.stdin.?.close(io);
        child.stdin = null;
        _ = child.wait(io) catch {};
    }
    var rbuf: [64]u8 = undefined;
    var reader = child.stdout.?.readerStreaming(io, &rbuf);
    _ = reader.interface.takeDelimiterExclusive('\n') catch return fail("E: the oracle did not start", .{});

    var client: wg.uapi.Client = .{ .gpa = gpa, .dir = sock_dir };

    // E1: the frames a real daemon takes and gives.
    var keys: [3]wg.Key = undefined;
    for (&keys, 0..) |*k, i| k.* = keypair(@splat(@intCast(0x31 + i))).public;
    const ep: wg.Endpoint = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 12912 } };
    // Clamped already: wireguard-go stores and reports a clamped private key.
    const pk: [32]u8 = blk: {
        var k: [32]u8 = @splat(0x41);
        k[0] &= 248;
        k[31] = (k[31] & 127) | 64;
        break :blk k;
    };
    const ips = [_]wg.AllowedIp{ wg.AllowedIp.v4(.{ 10, 9, 0, 0 }, 16), wg.AllowedIp.parse("2001:db8::/48") catch unreachable };
    const one = [_]wg.AllowedIp{wg.AllowedIp.v4(.{ 10, 8, 0, 1 }, 32)};
    try client.setDevice(&.{
        .ifname = "wgo0",
        .private_key = pk,
        .listen_port = go_port,
        .replace_peers = true,
        .peers = &.{
            .{ .public_key = keys[0], .preshared_key = @splat(0x51), .endpoint = ep, .persistent_keepalive_interval = 25, .replace_allowed_ips = true, .allowed_ips = &ips },
            .{ .public_key = keys[1], .allowed_ips = &one },
            .{ .public_key = keys[2] },
            .{ .public_key = keys[2], .remove = true },
        },
    });
    var dev: wg.Device = undefined;
    try client.getDevice("wgo0", &dev);
    defer dev.deinit(gpa);
    if (dev.listen_port != go_port or dev.peers.len != 2) return fail("E1: got port {d}, {d} peers", .{ dev.listen_port, dev.peers.len });
    if (!std.mem.eql(u8, &dev.private_key.?, &pk)) return fail("E1: private key differs", .{});
    if (!std.mem.eql(u8, &dev.public_key.?, &keypair(pk).public)) return fail("E1: derived public key differs", .{});
    for (dev.peers) |*p| {
        if (std.mem.eql(u8, &p.public_key, &keys[0])) {
            if (p.persistent_keepalive_interval != 25 or p.allowed_ips.len != 2 or p.endpoint.?.port() != 12912 or p.protocol_version != 1)
                return fail("E1: first peer differs", .{});
            if (!std.mem.eql(u8, &p.preshared_key.?, &@as([32]u8, @splat(0x51)))) return fail("E1: its PSK differs", .{});
        } else if (std.mem.eql(u8, &p.public_key, &keys[1])) {
            if (p.preshared_key != null or p.endpoint != null or p.allowed_ips.len != 1) return fail("E1: second peer differs", .{});
        } else return fail("E1: a peer that was removed", .{});
    }
    if (want_capture) {
        // The raw reply, as it came.
        const raw = try rawGet(gpa, sock_path);
        defer gpa.free(raw);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = uapi_capture_path, .data = raw });
        std.debug.print("E1: reply written to {s}\n", .{uapi_capture_path});
    }
    // A refusal comes back as a number.
    if (client.setDevice(&.{ .ifname = "wgo0", .listen_port = 1, .peers = &.{.{ .public_key = keys[0], .allowed_ips = &.{.{ .family = wg.AF.INET, .addr_len = 4, .cidr = 33 }} }} })) |_| {
        return fail("E1: an invalid allowed-ip went out", .{});
    } else |e| if (e != error.InvalidConfig) return e;
    if (client.getDevice("nosuch", &dev)) |_| {
        return fail("E1: a device that does not exist", .{});
    } else |e| if (e != error.NoSuchDevice) return e;
    const listed = try wg.uapi.listDevices(io, gpa, sock_dir);
    defer gpa.free(listed);
    if (listed.len != 1 or !std.mem.eql(u8, listed[0].slice(), "wgo0")) return fail("E1: listDevices: {d}", .{listed.len});
    std.debug.print("E1: uapi.Client set and read back a real wireguard-go's configuration\n", .{});

    // E2: Tunnel initiates; wireguard-go answers and echoes a staged packet.
    const udp = try Udp.open();
    defer udp.close();
    const ours_priv: [32]u8 = @splat(0x61);
    const ours = keypair(ours_priv);
    const go_pub = keypair(pk).public;
    const go_psk: [32]u8 = @splat(0x71);
    try client.setDevice(&.{
        .ifname = "wgo0",
        .replace_peers = true,
        .peers = &.{.{ .public_key = ours.public, .preshared_key = go_psk, .allowed_ips = &.{wg.AllowedIp.v4(.{ 10, 77, 0, 2 }, 32)} }},
    });
    var stage: [4096]u8 = undefined;
    var t: wg.Tunnel = undefined;
    try wg.Tunnel.init(&t, &.{ .static_private = &ours_priv, .remote_static = go_pub, .preshared_key = &go_psk, .stage = &stage }, io, clockNow(io));
    defer t.wipe();
    var peer: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, go_port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    var buf: [2048]u8 = undefined;
    const ping = echoRequest();
    switch (try t.encapsulate(io, clockNow(io), &ping, &buf)) {
        .network => |b| try udp.sendTo(b, &peer),
        else => return fail("E2: no initiation", .{}),
    }
    try pumpUntil(io, &t, udp, &peer, &ping, 10_000);
    var after: wg.Device = undefined;
    try client.getDevice("wgo0", &after);
    defer after.deinit(gpa);
    if (after.peers.len != 1 or after.peers[0].last_handshake_time.sec == 0 or after.peers[0].rx_bytes == 0)
        return fail("E2: wireguard-go reports no handshake or no traffic", .{});
    std.debug.print("E2: Tunnel initiated, wireguard-go echoed the staged packet, and its counters saw it\n", .{});

    // E3: wireguard-go initiates; Tunnel is the responder.
    const udp2 = try Udp.open();
    defer udp2.close();
    var r: wg.Tunnel = undefined;
    try wg.Tunnel.init(&r, &.{ .static_private = &ours_priv, .remote_static = go_pub, .preshared_key = &go_psk }, io, clockNow(io));
    defer r.wipe();
    try client.setDevice(&.{
        .ifname = "wgo0",
        .replace_peers = true,
        .peers = &.{.{
            .public_key = ours.public,
            .preshared_key = go_psk,
            .allowed_ips = &.{wg.AllowedIp.v4(.{ 10, 77, 0, 2 }, 32)},
            .endpoint = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = udp2.port } },
            .persistent_keepalive_interval = 1,
        }},
    });
    try pumpUntil(io, &r, udp2, &peer, "", 10_000);
    const data = (try r.encapsulate(io, clockNow(io), &ping, &buf)).network;
    try udp2.sendTo(data, &peer);
    try pumpUntil(io, &r, udp2, &peer, &ping, 10_000);
    std.debug.print("E3: wireguard-go initiated, Tunnel responded, data crossed both ways\n", .{});
}

/// `get=1` straight off the socket, the reply byte for byte.
fn rawGet(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var sa: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(sa.path[0..path.len], path);
    if (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.Connect;
    _ = linux.sendto(fd, "get=1\n\n", 7, 0, null, 0);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (!std.mem.endsWith(u8, out.items, "\n\n")) {
        var b: [4096]u8 = undefined;
        const n = linux.recvfrom(fd, &b, b.len, 0, null, null);
        if (linux.errno(n) != .SUCCESS or n == 0) return error.Recv;
        try out.appendSlice(gpa, b[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var do_capture = false;
    var go = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) {
            do_capture = true;
        } else if (std.mem.eql(u8, a, "--wireguard-go")) {
            go = true;
        } else {
            std.debug.print("usage: unshare -rn zig build interop-wireguard [-- --capture]\n       zig build interop-wireguard -- --wireguard-go [--capture]\n", .{});
            return 2;
        }
    }
    if (go) {
        againstWireguardGo(gpa, io, do_capture) catch |e| {
            std.debug.print("E (wireguard-go): {s}\n", .{@errorName(e)});
            return 1;
        };
        return 0;
    }
    if (linux.geteuid() != 0) {
        std.debug.print("interop-wireguard: needs euid 0 -- run it under `unshare -rn`\n", .{});
        return 2;
    }
    try run(gpa, io, &.{ "ip", "link", "set", "lo", "up" });

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, "// SPDX-License-Identifier: MIT\n" ++
        "// Generated by `unshare -rn zig build interop-wireguard -- --capture`\n" ++
        "// (modules/wireguard/tools/interop.zig): real exchanges with the Linux kernel's\n" ++
        "// WireGuard, replayed by src/kernel_handshake_replay.zig. Do not edit by hand.\n\n");

    kernelInitiates(gpa, io, &out) catch |e| {
        std.debug.print("A (kernel initiates): {s}\n", .{@errorName(e)});
        return 1;
    };
    weInitiate(gpa, io, &out) catch |e| {
        std.debug.print("B (we initiate): {s}\n", .{@errorName(e)});
        return 1;
    };
    if (do_capture) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = transcript_path, .data = out.items });
        std.debug.print("interop-wireguard: transcript written to {s}\n", .{transcript_path});
    }
    tunnelAgainstKernel(gpa, io) catch |e| {
        std.debug.print("C (Tunnel against the kernel): {s}\n", .{@errorName(e)});
        return 1;
    };
    confAgainstWg(gpa, io) catch |e| {
        std.debug.print("D (conf against wg): {s}\n", .{@errorName(e)});
        return 1;
    };
    return 0;
}
