// SPDX-License-Identifier: MIT

//! mlkem — ML-KEM-512/768/1024 (FIPS 203), the module-lattice KEM, with
//! vectorised ring arithmetic (16-lane i16 NTT and base multiplication)
//! and 4-way batched Keccak for the matrix and noise samplers.
//!
//! The public shape is `std.crypto.kem.ml_kem.nist.MLKem*`'s: `KeyPair`
//! (`generate`, `generateDeterministic` from d ‖ z), `PublicKey`
//! (`encaps`, `encapsDeterministic`, `toBytes`, `fromBytes`) and
//! `SecretKey` (`decaps`, `toBytes`, `fromBytes`). Differences from std:
//! keys and ciphertexts go by pointer; `decaps` returns the key directly
//! (implicit rejection cannot fail); `SecretKey.fromBytes` performs the
//! FIPS 203 §7.3 hash check; random draws are fail-closed (`entropy`).
//!
//! ```zig
//! const mlkem = @import("mlkem");
//! const K = mlkem.MLKem768;
//! const kp = K.KeyPair.generate(io);
//! const enc = kp.public_key.encaps(io);
//! const ss = kp.secret_key.decaps(&enc.ciphertext); // == enc.shared_secret
//! ```

const std = @import("std");
const kem = @import("kem.zig");

pub const meta = .{
    .doc = "ML-KEM-512/768/1024 (FIPS 203) with a vectorised NTT and 4-way Keccak; std's `ml_kem.nist` API shape, fail-closed randomness, FIPS 203 §7 key checks.",
    .platform_note = "any (16-lane vectors; AVX2 on amd64)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation; RNG only in `generate`/`encaps` (fail-closed via `entropy`)
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "FIPS 203 (2024-08-13); pq-crystals Kyber AVX2 and mlkem-native as design references for the vector NTT layout and the batched Keccak",
    .deps = .{"entropy"},
};

pub const Params = kem.Params;
pub const KeyError = kem.KeyError;
pub const Kem = kem.Kem;

pub const MLKem512 = kem.Kem(kem.ml_kem_512);
pub const MLKem768 = kem.Kem(kem.ml_kem_768);
pub const MLKem1024 = kem.Kem(kem.ml_kem_1024);

test {
    _ = @import("poly.zig");
    _ = @import("sample.zig");
    _ = @import("keccak4.zig");
    _ = @import("kem.zig");
    _ = @import("vectors_test.zig");
    _ = @import("fuzz_test.zig");
}

const testing = std.testing;

fn diffStd(comptime Ours: type, comptime Std: type, iterations: usize) !void {
    var prng = std.Random.DefaultPrng.init(0x6d6c6b656d);
    const rnd = prng.random();
    for (0..iterations) |_| {
        var seed: [64]u8 = undefined;
        rnd.bytes(&seed);
        var m: [32]u8 = undefined;
        rnd.bytes(&m);

        const ours = Ours.KeyPair.generateDeterministic(seed);
        const theirs = try Std.KeyPair.generateDeterministic(seed);
        try testing.expectEqualSlices(u8, &theirs.public_key.toBytes(), &ours.public_key.toBytes());
        try testing.expectEqualSlices(u8, &theirs.secret_key.toBytes(), &ours.secret_key.toBytes());

        const e_ours = ours.public_key.encapsDeterministic(&m);
        const e_theirs = theirs.public_key.encapsDeterministic(&m);
        try testing.expectEqualSlices(u8, &e_theirs.ciphertext, &e_ours.ciphertext);
        try testing.expectEqualSlices(u8, &e_theirs.shared_secret, &e_ours.shared_secret);
        try testing.expectEqualSlices(u8, &e_ours.shared_secret, &ours.secret_key.decaps(&e_ours.ciphertext));

        // Implicit rejection: a flipped ciphertext bit decapsulates to std's J(z ‖ c).
        var bad = e_ours.ciphertext;
        bad[rnd.uintLessThan(usize, bad.len)] ^= @as(u8, 1) << rnd.int(u3);
        try testing.expectEqualSlices(u8, &(try theirs.secret_key.decaps(&bad)), &ours.secret_key.decaps(&bad));

        // Import paths agree with the generated keys.
        const pk2 = try Ours.PublicKey.fromBytes(&ours.public_key.toBytes());
        try testing.expectEqualSlices(u8, &e_ours.ciphertext, &pk2.encapsDeterministic(&m).ciphertext);
        const sk2 = try Ours.SecretKey.fromBytes(&ours.secret_key.toBytes());
        try testing.expectEqualSlices(u8, &e_ours.shared_secret, &sk2.decaps(&e_ours.ciphertext));
    }
}

test "byte-identical to std ml_kem.nist on random seeds (all three sets)" {
    const nist = std.crypto.kem.ml_kem;
    try diffStd(MLKem512, nist.MLKem512, 50);
    try diffStd(MLKem768, nist.MLKem768, 50);
    try diffStd(MLKem1024, nist.MLKem1024, 50);
}

test "SecretKey.fromBytes rejects a dk whose H(ek) does not match" {
    const seed: [64]u8 = @splat(7);
    const kp = MLKem768.KeyPair.generateDeterministic(seed);
    var dk = kp.secret_key.toBytes();
    dk[MLKem768.SecretKey.encoded_length - 40] ^= 1; // inside H(ek)
    try testing.expectError(error.InconsistentKey, MLKem768.SecretKey.fromBytes(&dk));
}

test "PublicKey.fromBytes rejects a coefficient ≥ q" {
    const seed: [64]u8 = @splat(9);
    const kp = MLKem512.KeyPair.generateDeterministic(seed);
    var ek = kp.public_key.toBytes();
    ek[0] = 0xff;
    ek[1] |= 0x0f; // first coefficient = 4095
    try testing.expectError(error.NonCanonical, MLKem512.PublicKey.fromBytes(&ek));
}

test "seed form: a generated key keeps d ‖ z, re-derivation is identical, an imported one has none" {
    const io = testing.io;
    inline for (.{ MLKem512, MLKem768, MLKem1024 }) |K| {
        const kp = try K.KeyPair.tryGenerate(io, .{ .pairwise_check = true });
        const seed = kp.secret_key.seedBytes().?;
        const again = K.KeyPair.generateDeterministic(seed);
        try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &again.secret_key.toBytes());
        try testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &again.public_key.toBytes());
        const imported = try K.SecretKey.fromBytes(&kp.secret_key.toBytes());
        try testing.expectEqual(@as(?[64]u8, null), imported.seedBytes());

        const e = try kp.public_key.tryEncaps(io);
        try testing.expectEqualSlices(u8, &e.shared_secret, &kp.secret_key.decaps(&e.ciphertext));
        const e2 = kp.public_key.encaps(io);
        try testing.expect(!std.mem.eql(u8, &e.ciphertext, &e2.ciphertext));
    }
}

test "pairwiseConsistencyCheck rejects a mismatched pair" {
    const a = MLKem768.KeyPair.generateDeterministic(@splat(1));
    const b = MLKem768.KeyPair.generateDeterministic(@splat(2));
    try a.pairwiseConsistencyCheck();
    const mixed: MLKem768.KeyPair = .{ .secret_key = a.secret_key, .public_key = b.public_key };
    try testing.expectError(error.PairwiseConsistency, mixed.pairwiseConsistencyCheck());
}
