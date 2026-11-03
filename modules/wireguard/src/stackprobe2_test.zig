// SPDX-License-Identifier: MIT

//! Dead-stack probe for `noise.keyedMac` on `testkit.stackprobe` (the older
//! `stackprobe_test.zig` covers the rest): residue below the burn, and the MAC
//! key as a needle in any frame. ReleaseFast only (`skipUnlessOptimized`, a
//! runtime skip, so the body is type-checked in every mode).

const std = @import("std");
const wg = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [32]u8 = undefined;
var data: [116]u8 = undefined;

test "STACKPROBE: no MAC-key residue after noise.keyedMac" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("wireguard probe mac key", &key, .{});
    @memset(&data, 0x5a);
    const secrets = [_][]const u8{&key};
    _ = try P.run("noise.keyedMac", wg.noise.keyedMac, .{ @as([]const u8, &key), @as([]const u8, &data) }, &secrets, .{});
}

const tun = wg.tunnel;

var pa: [32]u8 = undefined;
var pb: [32]u8 = undefined;
var psk: [32]u8 = undefined;
var ta: wg.Tunnel = undefined;
var tb: wg.Tunnel = undefined;
var wire: [2048]u8 = undefined;
var wire2: [2048]u8 = undefined;
var packet: [64]u8 = undefined;
const clk: tun.Clock = .{ .mono_ms = 1000, .tai64n = tun.tai64n(100, 0) };

fn initBoth(io: std.Io) tun.InitError!void {
    var ka: wg.handshake.Keypair = undefined;
    var kb: wg.handshake.Keypair = undefined;
    wg.handshake.Keypair.fromPrivateKey(&pa, &ka) catch return error.InvalidKey;
    wg.handshake.Keypair.fromPrivateKey(&pb, &kb) catch return error.InvalidKey;
    const pub_a = ka.public;
    const pub_b = kb.public;
    std.crypto.secureZero(u8, &ka.private);
    std.crypto.secureZero(u8, &kb.private);
    try wg.Tunnel.init(&ta, &.{ .allowed_ips = null, .static_private = &pa, .remote_static = pub_b, .preshared_key = &psk }, io, clk);
    try wg.Tunnel.init(&tb, &.{ .allowed_ips = null, .static_private = &pb, .remote_static = pub_a, .preshared_key = &psk }, io, clk);
}

fn exchange(io: std.Io) anyerror!void {
    const m1 = (try ta.initiateHandshake(io, clk, &wire)).network;
    const m2 = (try tb.decapsulate(io, clk, m1, &wire2)).output.network;
    const k = (try ta.decapsulate(io, clk, m2, &wire)).output.network;
    _ = try tb.decapsulate(io, clk, k, &wire2);
}

fn dataBothWays(io: std.Io) anyerror!void {
    const w = (try ta.encapsulate(io, clk, &packet, &wire)).network;
    _ = (try tb.decapsulate(io, clk, w, &wire2)).output.tunnel;
    _ = try ta.poll(io, clk, &wire);
}

test "STACKPROBE: no key residue after Tunnel.init, a handshake and data" {
    try sp.skipUnlessOptimized();
    const io = std.testing.io;
    std.crypto.hash.sha2.Sha256.hash("wireguard probe tunnel a", &pa, .{});
    std.crypto.hash.sha2.Sha256.hash("wireguard probe tunnel b", &pb, .{});
    std.crypto.hash.sha2.Sha256.hash("wireguard probe tunnel psk", &psk, .{});
    @memset(&packet, 0x33);
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 64;
    const statics = [_][]const u8{ &pa, &pb, &psk };
    try initBoth(io);
    _ = try P.run("Tunnel.init", initBoth, .{io}, &statics, .{});
    const dh = [_][]const u8{ &pa, &pb, &psk, &ta.static_static, &tb.static_static };
    _ = try P.run("Tunnel handshake", exchange, .{io}, &dh, .{});
    const session = [_][]const u8{ &pa, &pb, &psk, &ta.current.?.session.send.key, &ta.current.?.session.recv.key };
    _ = try P.run("Tunnel data", dataBothWays, .{io}, &session, .{});
}
