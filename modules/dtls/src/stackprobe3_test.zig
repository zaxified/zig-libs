// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the DTLS 1.2 engine (`Connection12`): the entry points of a PSK handshake
//! and of the record path. ReleaseFast only (`sp.skipUnlessOptimized`). The secrets are the PSK, the master
//! secret and the AES-128 write keys of both directions; they are learned from an identical (seeded) first
//! handshake, so the probed run can look for them from its very first call.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const c12 = @import("Connection12.zig");
const conn13 = @import("Connection.zig");

const P = sp.Probe(.{ .window = 256 * 1024, .repeats = 1 });

const psk = "a 1.2 pre-shared key";
var cl: c12.Connection12 = undefined;
var sv: c12.Connection12 = undefined;
var a: [8192]u8 = undefined;
var b: [8192]u8 = undefined;
var last: usize = 0;
var prng: std.Random.DefaultCsprng = undefined;
var master_n: [48]u8 = undefined;
var ckey: [16]u8 = undefined;
var skey: [16]u8 = undefined;

fn cfg(role: conn13.Role) conn13.Config {
    return .{
        .role = role,
        .versions = &.{.dtls12},
        .psk_identity = "device-12",
        .psk = psk,
        .cipher_suites12 = &.{.psk_with_aes_128_gcm_sha256},
    };
}

fn rnd() conn13.Entropy {
    return .{ .seeded_for_test = prng.random() };
}

fn initPair() !void {
    prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x61)));
    cl = try c12.Connection12.clientInit(cfg(.client));
    sv = try c12.Connection12.serverInit(cfg(.server));
}

fn wStart(c: *c12.Connection12, o: []u8) !void {
    last = (try c.startHandshake(rnd(), 0, o)).len;
}
fn wFlight(c: *c12.Connection12, dg: []const u8, o: []u8) !void {
    const r = try c.handleFlight(dg, rnd(), 0, o);
    last = r.out.len;
}
fn wSend(c: *c12.Connection12, p: []const u8, o: []u8) !void {
    last = (try c.send(p, o)).len;
}
fn wRecv(c: *c12.Connection12, dg: []const u8, o: []u8) !void {
    last = (try c.recv(dg, o)).len;
}

fn learn() !void {
    try initPair();
    try wStart(&cl, &a);
    try wFlight(&sv, a[0..last], &b);
    try wFlight(&cl, b[0..last], &a);
    try wFlight(&sv, a[0..last], &b);
    try wFlight(&cl, b[0..last], &a);
    master_n = cl.master;
    ckey = cl.write_keys.key[0..16].*;
    skey = sv.write_keys.key[0..16].*;
    cl.deinit();
    sv.deinit();
}

test "mutation 2026-11-26: STACKPROBE: DTLS 1.2 PSK handshake and record path leave no PSK, master secret or record key on the dead stack" {
    try sp.skipUnlessOptimized();
    try learn();
    try initPair();
    const needles: []const []const u8 = &.{ psk, &master_n, &ckey, &skey };
    _ = try P.run("12 client startHandshake", wStart, .{ &cl, &a }, needles, .{});
    const n1 = last;
    _ = try P.run("12 server handleFlight (ClientHello)", wFlight, .{ &sv, a[0..n1], &b }, needles, .{});
    const n2 = last;
    _ = try P.run("12 client handleFlight (server flight)", wFlight, .{ &cl, b[0..n2], &a }, needles, .{});
    const n3 = last;
    _ = try P.run("12 server handleFlight (client flight)", wFlight, .{ &sv, a[0..n3], &b }, needles, .{});
    const n4 = last;
    _ = try P.run("12 client handleFlight (server Finished)", wFlight, .{ &cl, b[0..n4], &a }, needles, .{});
    _ = try P.run("12 client send", wSend, .{ &cl, "ping over dtls 1.2", &a }, needles, .{});
    const n5 = last;
    _ = try P.run("12 server recv", wRecv, .{ &sv, a[0..n5], &b }, needles, .{});
    _ = try P.run("12 server send", wSend, .{ &sv, "pong", &b }, needles, .{});
    const n6 = last;
    _ = try P.run("12 client recv", wRecv, .{ &cl, b[0..n6], &a }, needles, .{});
    cl.deinit();
    sv.deinit();
}
