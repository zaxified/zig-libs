// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the OpenSSH key-derivation
//! entry points burned 2026-10-09: `openssh.bcryptPbkdf` and
//! `openssh.Blowfish.init` (the private-key paths are in `stackprobe_test.zig`).
//! One-shot slow KDF: generous burn (`kdf_burn`). ReleaseFast only
//! (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 96 * 1024 });

var pass: [24]u8 = undefined;
var salt: [16]u8 = undefined;
var out: [48]u8 = undefined;
var key: [56]u8 = undefined;

test "STACKPROBE: bcrypt_pbkdf and Blowfish.init leave no passphrase or key on the dead stack" {
    try sp.skipUnlessOptimized();
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rsa probe2 pass", &h, .{});
    @memcpy(&pass, h[0..24]);
    std.crypto.hash.sha2.Sha256.hash("rsa probe2 salt", &h, .{});
    @memcpy(&salt, h[0..16]);
    std.crypto.hash.sha2.Sha256.hash("rsa probe2 key", h[0..], .{});
    @memcpy(key[0..32], &h);
    @memcpy(key[32..], h[0..24]);
    _ = try P.run("openssh.bcryptPbkdf", root.openssh.bcryptPbkdf, .{ &pass, &salt, @as(u32, 2), &out }, &.{ &pass, &out }, .{});
    _ = try P.run("openssh.Blowfish.init", root.openssh.Blowfish.init, .{@as([]const u8, &key)}, &.{&key}, .{});
}
