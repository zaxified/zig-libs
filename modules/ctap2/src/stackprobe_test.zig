// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `clientpin.SharedSecret`, the
//! platform side's session key: `authenticate`, `encrypt` and `decryptToken`
//! for PIN/UV protocols one and two (coverage sweep 2026-11-26; the module had
//! no probe). The MAC and AES-CBC primitives below are `ctap2pin`'s, which
//! burn; these wrappers add no burn of their own, so the needles are the
//! check: the shared secret and the PIN token. `decryptToken` returns the
//! token by value (into the probe's call frame by shape): the shared secret
//! is its needle. ReleaseFast/ReleaseSmall only.

const std = @import("std");
const ctap2 = @import("root.zig");
const sp = @import("testkit").stackprobe;

const SharedSecret = ctap2.clientpin.SharedSecret;
const P = sp.Probe(.{ .window = 64 * 1024 });

var ss1: SharedSecret = undefined;
var ss2: SharedSecret = undefined;
var token: [32]u8 = undefined;
var enc1: [32]u8 = undefined;
var enc2: [48]u8 = undefined;
var prng: std.Random.DefaultPrng = .init(3);

fn authW(s: *const SharedSecret) ctap2.clientpin.Signature {
    return s.authenticate("ctap2 probe message");
}
fn encW(s: *const SharedSecret, dst: []u8) !void {
    return s.encrypt(prng.random(), dst, &token);
}
fn decTokW(s: *const SharedSecret, ct: []const u8) !ctap2.Token {
    return s.decryptToken(ct);
}

test "STACKPROBE: SharedSecret authenticate / encrypt / decryptToken leave no shared secret or PIN token on the dead stack" {
    try sp.skipUnlessOptimized();
    var h: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("ctap2 probe shared secret", &h, .{});
    ss1 = .{ .protocol = .one, .bytes = undefined, .platform_key = undefined };
    ss1.bytes = h;
    ss2 = .{ .protocol = .two, .bytes = undefined, .platform_key = undefined };
    ss2.bytes = h;
    std.crypto.hash.sha2.Sha256.hash("ctap2 probe pin token", &token, .{});
    const no_burn: sp.Expect = .{ .burn = false };

    _ = try P.run("SharedSecret.authenticate (one)", authW, .{&ss1}, &.{h[0..32]}, no_burn);
    _ = try P.run("SharedSecret.authenticate (two)", authW, .{&ss2}, &.{h[0..32]}, no_burn);
    _ = try P.run("SharedSecret.encrypt (one)", encW, .{ &ss1, @as([]u8, &enc1) }, &.{ h[0..32], &token }, no_burn);
    _ = try P.run("SharedSecret.encrypt (two)", encW, .{ &ss2, @as([]u8, &enc2) }, &.{ &h, &token }, no_burn);
    try ss1.encrypt(prng.random(), &enc1, &token);
    try ss2.encrypt(prng.random(), &enc2, &token);
    _ = try P.run("SharedSecret.decryptToken (one)", decTokW, .{ &ss1, @as([]const u8, &enc1) }, &.{h[0..32]}, no_burn);
    _ = try P.run("SharedSecret.decryptToken (two)", decTokW, .{ &ss2, @as([]const u8, &enc2) }, &.{&h}, no_burn);
}
