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
    const init_bytes = try udp.recvType(&buf, @intFromEnum(hs.MessageType.handshake_initiation), 10_000, &from);
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

    const ka = try udp.recvType(&buf, @intFromEnum(hs.MessageType.transport_data), 10_000, &from);
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
    const resp = try udp.recvType(&buf, @intFromEnum(hs.MessageType.handshake_response), 10_000, &from);
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

    const reply = try udp.recvType(&buf, @intFromEnum(hs.MessageType.transport_data), 10_000, &from);
    var plain: [256]u8 = undefined;
    const r = try session.recv.open(&plain, reply, now_s);
    const ip = plain[0..r.len];
    if (ip.len < 28 or ip[9] != 1 or ip[20] != 0) return fail("B: the kernel's reply is not an ICMP echo reply", .{});
    if (!std.mem.eql(u8, ip[28..][0..ping_payload.len], ping_payload)) return fail("B: echo payload differs", .{});
    try appendHex(gpa, out, "b_pong", reply);
    std.debug.print("B: the kernel accepted our initiation and ping, its echo reply opens\n", .{});
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else {
            std.debug.print("usage: unshare -rn zig build interop-wireguard [-- --capture]\n", .{});
            return 2;
        }
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
    if (capture) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = transcript_path, .data = out.items });
        std.debug.print("interop-wireguard: transcript written to {s}\n", .{transcript_path});
    }
    return 0;
}
