// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `KeyPair.signPrehashed`, the
//! std-shaped prehashed signer `stackprobe_test.zig` does not call (it probes
//! `sign`/`signPrehashedInto`): residue below its burn, the secret key as a needle (the noise is
//! a by-value parameter of this API, so its copy is the caller's by shape). ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const E = root.EcdsaP256Sha256;
const P = sp.Probe(.{ .window = 64 * 1024 });

var kp: E.KeyPair = undefined;
var digest: [32]u8 = undefined;
var noise: [E.noise_length]u8 = undefined;

fn signPreW(k: *const E.KeyPair, d: *const [32]u8, n: *const [E.noise_length]u8) !E.Signature {
    return k.signPrehashed(d.*, n.*);
}
fn signPreNoNoiseW(k: *const E.KeyPair, d: *const [32]u8) !E.Signature {
    return k.signPrehashed(d.*, null);
}

test "STACKPROBE: signPrehashed leaves no key or noise on the dead stack" {
    try sp.skipUnlessOptimized();
    var seed: [E.KeyPair.seed_length]u8 = undefined;
    std.crypto.hash.sha3.Shake256.hash("p256 probe3 seed", &seed, .{});
    kp = try E.KeyPair.generateDeterministic(seed);
    std.crypto.hash.sha2.Sha256.hash("p256 probe3 message", &digest, .{});
    std.crypto.hash.sha3.Shake256.hash("p256 probe3 noise", &noise, .{});
    _ = try P.run("KeyPair.signPrehashed (noise)", signPreW, .{ &kp, &digest, &noise }, &.{&kp.secret_key.bytes}, .{}); // noise is by value in this API: its copy is the caller's
    _ = try P.run("KeyPair.signPrehashed (deterministic)", signPreNoNoiseW, .{ &kp, &digest }, &.{&kp.secret_key.bytes}, .{});
}
