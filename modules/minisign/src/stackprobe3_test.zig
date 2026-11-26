// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `signDigest`, the prehashed
//! signer the older probes do not call: residue below its burn, the Ed25519
//! seed and secret key as needles. ReleaseFast/ReleaseSmall only. Coverage
//! sweep 2026-11-26.

const std = @import("std");
const ms = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var kp: ms.KeyPair = undefined;
var seed: [32]u8 = undefined;
var digest: [ms.prehash_length]u8 = undefined;

fn signDigestW(k: *const ms.KeyPair, d: *const [ms.prehash_length]u8) !ms.RawSignature {
    return ms.signDigest(k, d.*);
}

test "STACKPROBE: signDigest leaves no Ed25519 seed or secret key on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("minisign probe3 seed", &seed, .{});
    kp = .{ .key_number = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .ed25519 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) };
    std.crypto.hash.blake2.Blake2b512.hash("minisign probe3 message", &digest, .{});
    _ = try P.run("signDigest", signDigestW, .{ &kp, &digest }, &.{ &seed, &kp.ed25519.secret_key.bytes }, .{});
}
