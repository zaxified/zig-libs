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

// ── control plane: conf.zig and uapi.zig ────────────────────────────────────
//
// Private and pre-shared keys pass through `conf` (base64 text) and `uapi` (hex
// text). The needles are the raw keys AND both text forms. The residue rule
// looks only below the longest zero run, and `root.keyFromBase64Into` /
// `keyToBase64Into` carry a 4 KiB burn of their own, which is such a run: with
// the entry point's own burn removed the probe would stay green while the
// entry point's frames above that run go unwiped. So `pinTop` pins where the
// run starts, with a bound per entry point taken from its removed-burn mutant.
// `uapi` has no burn of its own (only `defer secureZero`), so its probes run
// with `.burn = false`: needles only.

const conf = wg.conf;
const uapi = wg.uapi;

var cp_priv: wg.Key = undefined;
var cp_psk: wg.Key = undefined;
var cp_psk_old: wg.Key = undefined;
var cp_pub: wg.Key = undefined;
var cp_priv_b64: [wg.key_b64_len]u8 = undefined;
var cp_psk_b64: [wg.key_b64_len]u8 = undefined;
var cp_psk_old_b64: [wg.key_b64_len]u8 = undefined;
var cp_priv_hex: [64]u8 = undefined;
var cp_psk_hex: [64]u8 = undefined;
var cp_text_buf: [512]u8 = undefined;
var cp_text: []const u8 = &.{};
var cp_out: [1024]u8 = undefined;
var cp_parsed: conf.ParsedConfig = undefined;
var cp_synced: conf.ParsedConfig = undefined;
var cp_key_out: wg.Key = undefined;
var cp_hex_out: [64]u8 = undefined;
var cp_peer_cfg: [1]wg.PeerConfig = undefined;
var cp_cfg: wg.Config = undefined;
var cp_peer_dev: [1]wg.Peer = undefined;
var cp_dev: wg.Device = undefined;
var cp_peer_cur: [1]wg.Peer = undefined;
var cp_cur: wg.Device = undefined;

/// The longest zero run must start this close to the region top. Measured with
/// the entry point's burn in place; with the burn removed the run starts a body
/// deeper (the removed-burn mutants).
fn pinTop(label: []const u8, r: sp.Report, max: usize) !void {
    if (r.burn_top >= max) {
        std.debug.print("STACKPROBE {s}: the zero run starts {d} B deep (want < {d} B): the entry point's own burn is missing or too small\n", .{ label, r.burn_top, max });
        return error.BurnNotAtTheTop;
    }
}

fn cpSetup() !void {
    std.crypto.hash.sha2.Sha256.hash("wireguard conf probe private", &cp_priv, .{});
    std.crypto.hash.sha2.Sha256.hash("wireguard conf probe preshared", &cp_psk, .{});
    std.crypto.hash.sha2.Sha256.hash("wireguard conf probe preshared, the device's old one", &cp_psk_old, .{});
    std.crypto.hash.sha2.Sha256.hash("wireguard conf probe peer public", &cp_pub, .{});
    wg.keyToBase64Into(&cp_priv, &cp_priv_b64);
    wg.keyToBase64Into(&cp_psk, &cp_psk_b64);
    wg.keyToBase64Into(&cp_psk_old, &cp_psk_old_b64);
    var pub_b64: [wg.key_b64_len]u8 = undefined;
    wg.keyToBase64Into(&cp_pub, &pub_b64);
    uapi.keyToHex(&cp_priv, &cp_priv_hex);
    uapi.keyToHex(&cp_psk, &cp_psk_hex);
    cp_text = try std.fmt.bufPrint(&cp_text_buf, "[Interface]\nPrivateKey = {s}\nListenPort = 51820\n\n[Peer]\nPublicKey = {s}\nPresharedKey = {s}\nAllowedIPs = 10.0.0.2/32\nPersistentKeepalive = 25\n", .{ &cp_priv_b64, &pub_b64, &cp_psk_b64 });
    cp_peer_cfg = .{.{ .public_key = cp_pub, .preshared_key = cp_psk }};
    cp_cfg = .{ .private_key = cp_priv, .listen_port = 51820, .peers = &cp_peer_cfg };
    cp_peer_dev = .{.{ .public_key = cp_pub, .preshared_key = cp_psk }};
    cp_dev = .{ .private_key = cp_priv, .listen_port = 51820, .peers = &cp_peer_dev };
    cp_peer_cur = .{.{ .public_key = cp_pub, .preshared_key = cp_psk_old }};
    cp_cur = .{ .private_key = cp_priv, .listen_port = 51820, .peers = &cp_peer_cur };
}

fn parseDrop(text: []const u8) anyerror!void {
    try conf.parse(std.heap.page_allocator, text, .{}, null, &cp_parsed); // global-alloc-ok: the probed call must not allocate from testing.allocator, and this helper lives outside any test block
    cp_parsed.deinit();
}

fn formatConfigFixed(cfg: *const wg.Config) anyerror!void {
    var w: std.Io.Writer = .fixed(&cp_out);
    try conf.formatConfig(&w, cfg);
}

fn formatDeviceFixed(dev: *const wg.Device) anyerror!void {
    var w: std.Io.Writer = .fixed(&cp_out);
    try conf.formatDevice(&w, dev);
}

fn syncDrop(current: *const wg.Device, desired: *const wg.Config) anyerror!void {
    try conf.sync(std.heap.page_allocator, current, desired, &cp_synced); // global-alloc-ok: the probed call must not allocate from testing.allocator, and this helper lives outside any test block
    cp_synced.deinit();
}

var cp_line_priv: [80]u8 = undefined;
var cp_line_pub: [80]u8 = undefined;
var cp_line_psk: [80]u8 = undefined;
var cp_line_priv_s: []const u8 = &.{};
var cp_line_pub_s: []const u8 = &.{};
var cp_line_psk_s: []const u8 = &.{};
var cp_getp: uapi.GetParser = undefined;

fn feedLines() anyerror!void {
    cp_getp = uapi.GetParser.init(std.heap.page_allocator, .{}); // global-alloc-ok: the probed call must not allocate from testing.allocator, and this helper lives outside any test block
    try cp_getp.feedLine(cp_line_priv_s);
    try cp_getp.feedLine("listen_port=51820");
    try cp_getp.feedLine(cp_line_pub_s);
    try cp_getp.feedLine(cp_line_psk_s);
    cp_getp.deinit();
}

fn finishLines() anyerror!void {
    cp_getp = uapi.GetParser.init(std.heap.page_allocator, .{}); // global-alloc-ok: the probed call must not allocate from testing.allocator, and this helper lives outside any test block
    try cp_getp.feedLine(cp_line_priv_s);
    try cp_getp.feedLine(cp_line_pub_s);
    try cp_getp.feedLine(cp_line_psk_s);
    var dev: wg.Device = undefined;
    try cp_getp.finishInto(&dev);
    dev.deinit(std.heap.page_allocator); // global-alloc-ok: the probed call must not allocate from testing.allocator, and this helper lives outside any test block
    cp_getp.deinit();
}

fn writeSetFixed(cfg: *const wg.Config) anyerror!void {
    var w: std.Io.Writer = .fixed(&cp_out);
    try uapi.writeSet(&w, cfg);
}

test "STACKPROBE: no key residue after conf.parse, formatConfig, formatDevice and sync" {
    try sp.skipUnlessOptimized();
    try cpSetup();
    const keys = [_][]const u8{ &cp_priv, &cp_psk, &cp_psk_old, &cp_priv_b64, &cp_psk_b64, &cp_psk_old_b64 };
    // Bounds from the removed-burn mutants (ReleaseFast, 2026-11-03): with the burn
    // in place the run starts at parse 143 B, formatConfig 159 B, formatDevice
    // 423 B, sync 143 B; without it parse 1319 B, formatConfig 455 B, formatDevice
    // 575 B (writeKeyLine's burn), sync none (the probe itself goes red).
    const parse_r = try P.run("conf.parse", parseDrop, .{cp_text}, &keys, .{});
    try pinTop("conf.parse", parse_r, 512);
    const fc_r = try P.run("conf.formatConfig", formatConfigFixed, .{&cp_cfg}, &keys, .{});
    try pinTop("conf.formatConfig", fc_r, 300);
    const fd_r = try P.run("conf.formatDevice", formatDeviceFixed, .{&cp_dev}, &keys, .{});
    try pinTop("conf.formatDevice", fd_r, 500);
    const sy_r = try P.run("conf.sync", syncDrop, .{ &cp_cur, &cp_cfg }, &keys, .{});
    try pinTop("conf.sync", sy_r, 512);
}

test "STACKPROBE: no key residue after uapi.keyToHex, keyFromHex, writeSet and GetParser.feedLine" {
    try sp.skipUnlessOptimized();
    try cpSetup();
    var pub_hex: [64]u8 = undefined;
    uapi.keyToHex(&cp_pub, &pub_hex);
    cp_line_priv_s = try std.fmt.bufPrint(&cp_line_priv, "private_key={s}", .{&cp_priv_hex});
    cp_line_pub_s = try std.fmt.bufPrint(&cp_line_pub, "public_key={s}", .{&pub_hex});
    cp_line_psk_s = try std.fmt.bufPrint(&cp_line_psk, "preshared_key={s}", .{&cp_psk_hex});
    const keys = [_][]const u8{ &cp_priv, &cp_psk, &cp_priv_hex, &cp_psk_hex };
    // No burn in uapi: needles only.
    const no_burn: sp.Expect = .{ .burn = false, .residue = false };
    _ = try P.run("uapi.keyToHex", uapi.keyToHex, .{ &cp_priv, &cp_hex_out }, &keys, no_burn);
    try std.testing.expectEqualSlices(u8, &cp_priv_hex, &cp_hex_out);
    _ = try P.run("uapi.keyFromHex", uapi.keyFromHex, .{ @as([]const u8, &cp_psk_hex), &cp_key_out }, &keys, no_burn);
    try std.testing.expectEqualSlices(u8, &cp_psk, &cp_key_out);
    _ = try P.run("uapi.writeSet", writeSetFixed, .{&cp_cfg}, &keys, no_burn);
    // Red before `secretKeyLine`'s burn: one raw key copy per key line, 703..767 B deep.
    _ = try P.run("uapi.GetParser.feedLine", feedLines, .{}, &keys, no_burn);
    // Needles only: `finishInto` derives the public key from the private one.
    _ = try P.run("uapi.GetParser.finishInto", finishLines, .{}, &keys, no_burn);
}
