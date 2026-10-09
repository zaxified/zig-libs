// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the entry points burned
//! 2026-10-09: `KeyPair.generateInto` and `KeyPair.signerInto` (the rest of the
//! module is in `stackprobe_test.zig`). One-shot calls: `sign_burn`.
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const p256 = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Ecdsa = p256.EcdsaP256Sha256;

const P = sp.Probe(.{ .window = 32 * 1024 });

var seed: [32]u8 = undefined;
var kp: Ecdsa.KeyPair = undefined;
var kp2: Ecdsa.KeyPair = undefined;
var signer_out: Ecdsa.Signer = undefined;

test "STACKPROBE: P-256 key generation and signer construction leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("p256 probe2 seed", &seed, .{});
    try Ecdsa.KeyPair.generateDeterministicInto(&kp, &seed);
    _ = try P.run("KeyPair.generateInto", Ecdsa.KeyPair.generateInto, .{ &kp2, std.testing.io }, &.{std.mem.asBytes(&kp2.secret_key)}, .{});
    // `signer` returns the Signer — secret key inside — by value, so its own
    // result slot holds the key (18 windows, 2026-10-09); `signerInto` does not.
    _ = try P.run("KeyPair.signerInto", Ecdsa.KeyPair.signerInto, .{ &signer_out, &kp, null }, &.{std.mem.asBytes(&kp.secret_key)}, .{});
}
