// SPDX-License-Identifier: MIT

//! Dead-stack probe for `nonceGen` on `testkit.stackprobe` (the older
//! `stackprobe_test.zig` keeps the hand-made `sign` probe): residue below the
//! burn, and the secret key and the `rand'` draw as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).

const std = @import("std");
const musig2 = @import("root.zig");
const k256 = @import("k256");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var sk: [32]u8 = undefined;
var rand_prime: [32]u8 = undefined;
var result: musig2.NonceGenResult = undefined;

test "STACKPROBE: no key or nonce residue after nonceGen" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("musig2 probe sk", &sk, .{});
    std.crypto.hash.sha2.Sha256.hash("musig2 probe rand", &rand_prime, .{});
    const pk = (try k256.Secp256k1.combMulBase(sk, .big)).toCompressedSec1();
    // The output needle is `k1 ‖ k2` only: `secnonce` ends with the PUBLIC key
    // `pk` (BIP327), which legitimately sits in the caller's frame as the by-value
    // `pk` argument — as a needle it reported 12 windows above the burn.
    const k12: []const u8 = std.mem.asBytes(&result.secnonce)[0..64];
    const secrets = [_][]const u8{ &sk, &rand_prime, k12 };

    _ = try P.run("nonceGen", musig2.nonceGen, .{ &result, @as(?*const [32]u8, &sk), pk, @as(?[32]u8, null), @as(?[]const u8, "msg"), @as(?[]const u8, null), @as(*const [32]u8, &rand_prime), std.testing.io }, &secrets, .{});
    _ = try P.run("nonceGen no sk", musig2.nonceGen, .{ &result, @as(?*const [32]u8, null), pk, @as(?[32]u8, null), @as(?[]const u8, null), @as(?[]const u8, null), @as(*const [32]u8, &rand_prime), std.testing.io }, &secrets, .{});
}
