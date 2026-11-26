// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `CipherState.initializeKey` on
//! an AES-GCM suite, where it expands the key into the cached `Cipher.Context`
//! (`stackprobe_test.zig` calls it on `DefaultSuite`, ChaChaPoly, which caches
//! nothing). No burn (it writes only into `self`): the key and the expanded
//! context are needles. ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const noise = @import("root.zig");
const aesgcm = @import("aesgcm");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });
const AesSuite = noise.Suite(std.crypto.dh.X25519, aesgcm.Aes256Gcm, std.crypto.hash.sha2.Sha256);
const CS = AesSuite.CipherState;

var key: [32]u8 = undefined;
var cs: CS = undefined;

fn initKeyW(k: *const [32]u8) void {
    cs = .{};
    cs.initializeKey(k);
}

test "STACKPROBE: CipherState.initializeKey (AES-256-GCM) leaves no key or key schedule on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("noise probe2 key", &key, .{});
    initKeyW(&key);
    const ctx_image = std.mem.toBytes(cs.ctx);
    defer cs.wipe();
    _ = try P.run("CipherState.initializeKey (AES-256-GCM)", initKeyW, .{&key}, &.{ &key, &ctx_image }, .{ .burn = false });
}
