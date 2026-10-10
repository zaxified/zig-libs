// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for every secret entry point:
//! key derivation, signing, ECDH and the constant-time multiply. Residue
//! below each burn and the secret inputs/outputs as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const E = root.EcdsaP521Sha512;
const P = sp.Probe(.{ .window = 64 * 1024 });

var seed: [E.KeyPair.seed_length]u8 = undefined;
var kp: E.KeyPair = undefined;
var kp2: E.KeyPair = undefined;
var sk: E.SecretKey = undefined;
var digest: [64]u8 = undefined;
var sig: E.Signature = undefined;
var shared: [66]u8 = undefined;
var peer: [133]u8 = undefined;
var point: root.P521 = undefined;

test "STACKPROBE: no key, seed or shared-secret residue after the secret entry points" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha3.Shake256.hash("p521 probe seed", &seed, .{});
    std.crypto.hash.sha2.Sha512.hash("p521 probe message", &digest, .{});

    const kp_secrets = [_][]const u8{ &seed, &kp.secret_key.bytes };
    _ = try P.run("generateDeterministicInto", E.KeyPair.generateDeterministicInto, .{ &kp, &seed }, &kp_secrets, .{});
    sk = kp.secret_key;

    const sk_secrets = [_][]const u8{ &sk.bytes, &kp2.secret_key.bytes };
    _ = try P.run("fromSecretKeyInto", E.KeyPair.fromSecretKeyInto, .{ &kp2, &sk }, &sk_secrets, .{});
    try std.testing.expect(kp2.public_key.p.equivalent(kp.public_key.p));

    const sign_secrets = [_][]const u8{&kp.secret_key.bytes};
    _ = try P.run("signPrehashedInto", E.KeyPair.signPrehashedInto, .{ &sig, &kp, &digest, null }, &sign_secrets, .{});
    try sig.verifyPrehashed(digest, kp.public_key);

    peer = root.P521.basePoint.dbl().toUncompressedSec1();
    const ecdh_secrets = [_][]const u8{ &sk.bytes, &shared };
    _ = try P.run("ecdhInto", root.ecdhInto, .{ &shared, &sk.bytes, &peer }, &ecdh_secrets, .{});

    const mul_secrets = [_][]const u8{&sk.bytes}; // the product is the public key
    _ = try P.run("mulInto", root.P521.mulInto, .{ &point, root.P521.basePoint, &sk.bytes, .big }, &mul_secrets, .{});
    try std.testing.expect(point.equivalent(kp.public_key.p));
}
