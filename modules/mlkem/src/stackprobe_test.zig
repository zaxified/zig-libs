// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for every secret entry point:
//! `KeyPair.generateDeterministicInto`, `PublicKey.encapsDeterministicInto`,
//! `SecretKey.decapsInto` and `SecretKey.fromBytesInto`, all three parameter
//! sets (the by-value forms keep their result in their own frame by shape).
//! ReleaseFast/ReleaseSmall only (`skipUnlessOptimized`).
//!
//! Needles: the seed d ‖ z, m, the decapsulation key's encoded form (its
//! secret part: the NTT of s), and every output secret (the shared secret,
//! K). The engine's residue rule covers the intermediates (s, e, r, e1, e2,
//! the Keccak states) below each burn without naming them. The burn sizes in
//! `burn.zig` come from this probe's dirty depths (`verbose`).

const std = @import("std");
const mlkem = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 });

fn Suite(comptime K: type, comptime name: []const u8) type {
    return struct {
        var seed: [K.seed_length]u8 = undefined;
        var kp: K.KeyPair = undefined;
        var m: [32]u8 = undefined;
        var es: K.EncapsulatedSecret = undefined;
        var ss: [K.shared_length]u8 = undefined;
        var sk_bytes: [K.SecretKey.encoded_length]u8 = undefined;
        var sk2: K.SecretKey = undefined;

        fn probe() !void {
            std.crypto.hash.sha2.Sha512.hash("mlkem stackprobe seed " ++ name, &seed, .{});
            std.crypto.hash.sha2.Sha256.hash("mlkem stackprobe m " ++ name, &m, .{});
            // The secret part of the encoded key: the byte-encoded NTT of s.
            const s_part = sk_bytes[0 .. K.SecretKey.encoded_length - (K.PublicKey.encoded_length + 64)];

            _ = try P.run(name ++ " generateDeterministicInto", K.KeyPair.generateDeterministicInto, .{ &kp, &seed }, &.{&seed}, .{});
            sk_bytes = kp.secret_key.toBytes();
            _ = try P.run(name ++ " encapsDeterministicInto", K.PublicKey.encapsDeterministicInto, .{ &kp.public_key, &m, &es }, &.{ &m, &es.shared_secret }, .{});
            _ = try P.run(name ++ " decapsInto", K.SecretKey.decapsInto, .{ &kp.secret_key, &es.ciphertext, &ss }, &.{ s_part, &ss }, .{});
            try std.testing.expectEqualSlices(u8, &es.shared_secret, &ss);
            _ = try P.run(name ++ " SecretKey.fromBytesInto", K.SecretKey.fromBytesInto, .{ &sk2, &sk_bytes }, &.{s_part}, .{});
        }
    };
}

test "STACKPROBE: ML-KEM keygen, encaps, decaps and secret-key import leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    try Suite(mlkem.MLKem512, "512").probe();
    try Suite(mlkem.MLKem768, "768").probe();
    try Suite(mlkem.MLKem1024, "1024").probe();
}
