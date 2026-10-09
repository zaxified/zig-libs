// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for the key
//! construction entry points burned in the 2026-10-09 sweep:
//! `SecretKey.fromBytesInto`, `SecretKey.fromBytes` (residue only: it returns
//! the key by value, which is the caller's frame by contract) and
//! `PublicKey.fromSecretKey`. Signing and `KeyPair.fromSecretKey` stay covered
//! by the older `stackprobe_test.zig`. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

// Window above the deepest burn (16 KiB).
const P = sp.Probe(.{ .window = 64 * 1024 });

var sk_bytes: [32]u8 = undefined;
var sk_out: root.SecretKey = undefined;
var sk: root.SecretKey = undefined;

test "STACKPROBE: bip340 key construction leaves no secret in any frame" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("bip340 probe sk", &sk_bytes, .{});
    sk_bytes[0] = 0; // < n

    _ = try P.run("SecretKey.fromBytesInto", root.SecretKey.fromBytesInto, .{ &sk_out, &sk_bytes }, &[_][]const u8{ &sk_bytes, &sk_out.bytes }, .{});
    // By-value form: the array argument and the result are the caller's copies
    // by construction, so only the library's own frames are checked.
    _ = try P.run("SecretKey.fromBytes", root.SecretKey.fromBytes, .{sk_bytes}, &.{}, .{});
    sk = .{ .bytes = sk_bytes };
    _ = try P.run("PublicKey.fromSecretKey", root.PublicKey.fromSecretKey, .{&sk}, &[_][]const u8{&sk_bytes}, .{});
}
