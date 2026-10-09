// SPDX-License-Identifier: MIT

//! Dead-stack probe for the credential entry points (`testkit.stackprobe`):
//! residue below each burn, and the key / password as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).

const std = @import("std");
const stun = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [16]u8 = undefined;
var out_key: [16]u8 = undefined;
var buf: [128]u8 = undefined;
var builder: stun.Builder = undefined;
const password = "probe-password-Zk4n8Qw2";
const txid: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

test "STACKPROBE: no credential residue after the MESSAGE-INTEGRITY and long-term-key paths" {
    try sp.skipUnlessOptimized();
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("stun probe key", &full, .{});
    key = full[0..16].*;
    const secrets = [_][]const u8{ &key, &out_key, password };

    _ = try P.run("longTermKey", stun.longTermKey, .{ &out_key, @as([]const u8, "user"), @as([]const u8, "example.org"), @as([]const u8, password) }, &secrets, .{});

    builder = try stun.Builder.init(&buf, .request, .binding, txid);
    _ = try P.run("Builder.addMessageIntegrity", stun.Builder.addMessageIntegrity, .{ &builder, @as([]const u8, &key) }, &secrets, .{});

    // A message signed with `key`, so verify runs to the constant-time compare.
    var b2 = try stun.Builder.init(&buf, .request, .binding, txid);
    try b2.addMessageIntegrity(&key);
    const m = try stun.decode(b2.finish());
    _ = try P.run("Message.verifyMessageIntegrity", stun.Message.verifyMessageIntegrity, .{ m, @as([]const u8, &key) }, &secrets, .{});
}
