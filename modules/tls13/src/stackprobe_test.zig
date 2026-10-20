// SPDX-License-Identifier: MIT

//! Dead-stack probe for `kex`'s entry points (`testkit.stackprobe`): residue
//! below each per-group burn, and the ephemeral secret / shared secret as
//! needles in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime
//! skip, so the body is type-checked in every mode). `keyschedule` and
//! `certverify.sign` are probed by `dtls`'s `stackprobe_test.zig` through its
//! shim and re-export.

const std = @import("std");
const kex = @import("kex.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 }); // must exceed kex_hybrid_burn (160 KiB) plus the burn top

var csprng: std.Random.DefaultCsprng = undefined;
var client: kex.KeyPair = undefined;
var ex: kex.ServerExchange = undefined;
var shared: kex.SharedSecret = undefined;

fn probeGroup(comptime label: []const u8, group: u16) !void {
    csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5c)));
    const rnd = csprng.random();
    // Only the group's own prefix of `secret` is written (the curves use 32
    // or 48 of its 96 bytes); the rest must not become a needle.
    const n = kex.scalarLen(group);

    _ = try P.run(label ++ " generate", kex.generate, .{ group, rnd, &client }, &[_][]const u8{client.secret[0..n]}, .{});
    _ = try P.run(label ++ " serverExchange", kex.serverExchange, .{ group, client.public[0..client.public_len], rnd, &ex }, &[_][]const u8{ex.shared.slice()}, .{});
    _ = try P.run(label ++ " sharedSecret", kex.sharedSecret, .{ group, client.secret[0..n], ex.public[0..ex.public_len], &shared }, &[_][]const u8{ client.secret[0..n], shared.slice() }, .{});
    if (!std.mem.eql(u8, shared.slice(), ex.shared.slice())) return error.ProbeExchangeDisagrees;
}

test "STACKPROBE: no ephemeral or shared secret residue after any kex entry point" {
    try sp.skipUnlessOptimized();
    try probeGroup("x25519", kex.x25519_group);
    try probeGroup("secp256r1", kex.secp256r1_group);
    try probeGroup("secp384r1", kex.secp384r1_group);
    try probeGroup("x25519mlkem768", kex.x25519_mlkem768_group);
}
