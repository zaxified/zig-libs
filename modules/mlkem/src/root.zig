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

// Tests added by the 2026-11-11 whole-module mutation run.

fn rejectionKey(comptime K: type, sk: *const K.SecretKey, c: *const [K.ciphertext_length]u8) [32]u8 {
    // J(z ‖ c) with z read back from the dk encoding (its last 32 bytes).
    const dk = sk.toBytes();
    var out: [32]u8 = undefined;
    var j = std.crypto.hash.sha3.Shake256.init(.{});
    j.update(dk[dk.len - 32 ..]);
    j.update(c);
    j.squeeze(&out);
    return out;
}

test "decaps of a ciphertext damaged in any single byte is exactly J(z ‖ c); an intact one gives K" {
    inline for (.{ MLKem512, MLKem768, MLKem1024 }, 0..) |K, which| {
        const kp = K.KeyPair.generateDeterministic(@splat(@as(u8, 0x30 + which)));
        const m: [32]u8 = @splat(0x11);
        const enc = kp.public_key.encapsDeterministic(&m);
        try testing.expectEqualSlices(u8, &enc.shared_secret, &kp.secret_key.decaps(&enc.ciphertext));
        for (0..K.ciphertext_length) |at| {
            var bad = enc.ciphertext;
            bad[at] ^= @as(u8, 1) << @intCast(at % 8);
            try testing.expectEqualSlices(u8, &rejectionKey(K, &kp.secret_key, &bad), &kp.secret_key.decaps(&bad));
        }
        // An all-different ciphertext too (every byte of the comparison differs).
        var other: [K.ciphertext_length]u8 = undefined;
        for (&other, enc.ciphertext) |*o, c| o.* = ~c;
        try testing.expectEqualSlices(u8, &rejectionKey(K, &kp.secret_key, &other), &kp.secret_key.decaps(&other));
    }
}

test "SecretKey.fromBytes reduces dk_pke coefficients >= q exactly like std" {
    const nist = std.crypto.kem.ml_kem;
    inline for (.{
        .{ MLKem512, nist.MLKem512 },
        .{ MLKem768, nist.MLKem768 },
        .{ MLKem1024, nist.MLKem1024 },
    }) |pair| {
        const K = pair[0];
        const S = pair[1];
        const kp = K.KeyPair.generateDeterministic(@splat(5));
        var dk = kp.secret_key.toBytes();
        const k = (K.PublicKey.encoded_length - 32) / 384;
        // coefficient 0 of every polynomial of ŝ := 4095, and the last two := 4095
        for (0..k) |i| {
            dk[384 * i] = 0xff;
            dk[384 * i + 1] |= 0x0f;
        }
        dk[384 * k - 3] = 0xff;
        dk[384 * k - 2] = 0xff;
        dk[384 * k - 1] = 0xff;
        const ours = try K.SecretKey.fromBytes(&dk);
        const theirs = try S.SecretKey.fromBytes(&dk);
        try testing.expectEqualSlices(u8, &theirs.toBytes(), &ours.toBytes());
        const first: u16 = @as(u16, ours.toBytes()[0]) | (@as(u16, ours.toBytes()[1] & 0x0f) << 8);
        try testing.expect(first < 3329);
        const enc = kp.public_key.encapsDeterministic(&@as([32]u8, @splat(0x22)));
        try testing.expectEqualSlices(u8, &(try theirs.decaps(&enc.ciphertext)), &ours.decaps(&enc.ciphertext));
    }
}

test "fresh randomness: generate, generateInto, tryGenerate, encaps and tryEncaps never repeat" {
    const io = testing.io;
    inline for (.{ MLKem512, MLKem768, MLKem1024 }) |K| {
        const a = K.KeyPair.generate(io);
        const b = K.KeyPair.generate(io);
        var c: K.KeyPair = undefined;
        K.KeyPair.generateInto(&c, io);
        var d: K.KeyPair = undefined;
        try K.KeyPair.tryGenerateInto(&d, io, .{});
        const e = try K.KeyPair.tryGenerate(io, .{});
        const pairs = [_]K.KeyPair{ a, b, c, d, e };
        for (pairs, 0..) |x, i| {
            for (pairs[i + 1 ..]) |y| {
                try testing.expect(!std.mem.eql(u8, &x.secret_key.seedBytes().?, &y.secret_key.seedBytes().?));
                try testing.expect(!std.mem.eql(u8, &x.public_key.toBytes(), &y.public_key.toBytes()));
            }
            const enc = x.public_key.encaps(io);
            try testing.expectEqualSlices(u8, &enc.shared_secret, &x.secret_key.decaps(&enc.ciphertext));
        }
        const e1 = a.public_key.encaps(io);
        const e2 = a.public_key.encaps(io);
        const t1 = try a.public_key.tryEncaps(io);
        const t2 = try a.public_key.tryEncaps(io);
        const encs = [_]K.EncapsulatedSecret{ e1, e2, t1, t2 };
        for (encs, 0..) |x, i| {
            for (encs[i + 1 ..]) |y| {
                try testing.expect(!std.mem.eql(u8, &x.ciphertext, &y.ciphertext));
                try testing.expect(!std.mem.eql(u8, &x.shared_secret, &y.shared_secret));
            }
            try testing.expectEqualSlices(u8, &x.shared_secret, &a.secret_key.decaps(&x.ciphertext));
        }
    }
}

test "parameter sets and encoded sizes are the FIPS 203 Table 2 and 3 values" {
    const p = @import("kem.zig");
    inline for (.{
        .{ p.ml_kem_512, MLKem512, "ML-KEM-512", 2, 3, 10, 4, 800, 1632, 768 },
        .{ p.ml_kem_768, MLKem768, "ML-KEM-768", 3, 2, 10, 4, 1184, 2400, 1088 },
        .{ p.ml_kem_1024, MLKem1024, "ML-KEM-1024", 4, 2, 11, 5, 1568, 3168, 1568 },
    }) |row| {
        const K = row[1];
        try testing.expectEqualStrings(row[2], row[0].name);
        try testing.expectEqualStrings(row[2], K.name);
        try testing.expectEqual(@as(u8, row[3]), row[0].k);
        try testing.expectEqual(@as(u2, row[4]), row[0].eta1);
        try testing.expectEqual(@as(u4, row[5]), row[0].du);
        try testing.expectEqual(@as(u4, row[6]), row[0].dv);
        try testing.expectEqual(@as(usize, row[7]), K.PublicKey.encoded_length);
        try testing.expectEqual(@as(usize, row[8]), K.SecretKey.encoded_length);
        try testing.expectEqual(@as(usize, row[9]), K.ciphertext_length);
        try testing.expectEqual(@as(usize, 32), K.shared_length);
        try testing.expectEqual(@as(usize, 32), K.encaps_seed_length);
        try testing.expectEqual(@as(usize, 64), K.seed_length);
    }
}
