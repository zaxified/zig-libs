// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `sign.signRrset`, the one
//! entry point that holds a zone signing key: per algorithm, the secret
//! scalar / seed as needles and a burn required below the call (residue
//! rule). ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const dns = @import("dns");
const rsa = @import("rsa");
const sp = @import("testkit").stackprobe;
const sign = @import("sign.zig");
const ed448 = @import("ed448").ed448;

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

const P = sp.Probe(.{ .window = 256 * 1024 });

var kp256: EcdsaP256.KeyPair = undefined;
var kp384: EcdsaP384.KeyPair = undefined;
var kped: Ed25519.KeyPair = undefined;
var kp448: ed448.KeyPair = undefined;
var kprsa: rsa.KeyPair = undefined;
var seed448: [57]u8 = undefined;

const params: sign.SignParams = .{
    .signer_name = "example.org",
    .key_tag = 0x1234,
    .inception = 1_000_000,
    .expiration = 2_000_000,
};

fn rr(last: u8) dns.Record {
    return .{ .name = "www.example.org", .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, last } } };
}

/// Signs and frees: the probed call must not leak the RRSIG allocation.
fn signFree(key: sign.SigningKey) void {
    const rrset = [_]dns.Record{ rr(2), rr(1) };
    const out = sign.signRrset(std.testing.allocator, &rrset, "www.example.org", key, params) catch unreachable;
    std.testing.allocator.free(out);
}

test "STACKPROBE: signRrset leaves no zone signing key on the dead stack" {
    try sp.skipUnlessOptimized();
    var h: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("dnssec probe keys", &h, .{});
    kp256 = try EcdsaP256.KeyPair.generateDeterministic(h[0..32].*);
    kp384 = try EcdsaP384.KeyPair.generateDeterministic(h[0..48].*);
    kped = try Ed25519.KeyPair.generateDeterministic(h[32..64].*);
    @memcpy(seed448[0..57], h[0..57]);
    kp448 = ed448.KeyPair.create(&seed448);
    var prng = std.Random.DefaultCsprng.init(h[0..32].*);
    try rsa.generate(&kprsa, prng.random(), 1024, 65537);

    _ = try P.run("signRrset ecdsa_p256", signFree, .{sign.SigningKey{ .ecdsa_p256 = &kp256 }}, &.{&kp256.secret_key.bytes}, .{});
    _ = try P.run("signRrset ecdsa_p384", signFree, .{sign.SigningKey{ .ecdsa_p384 = &kp384 }}, &.{&kp384.secret_key.bytes}, .{});
    _ = try P.run("signRrset ed25519", signFree, .{sign.SigningKey{ .ed25519 = &kped }}, &.{kped.secret_key.bytes[0..32]}, .{});
    _ = try P.run("signRrset ed448", signFree, .{sign.SigningKey{ .ed448 = &kp448 }}, &.{&seed448}, .{});
    _ = try P.run("signRrset rsa_sha256", signFree, .{sign.SigningKey{ .rsa_sha256 = &kprsa.secret_key }}, &.{}, .{});
}
