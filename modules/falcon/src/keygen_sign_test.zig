// SPDX-License-Identifier: MIT
//! keygen_sign_test — byte-exact KEYGEN-side KAT harness (plus the full
//! keygen->sign pipeline and a keygen->sign->verify round trip), against
//! `root.zig`'s public API and the official NIST Round-3 vectors
//! (`kat_vectors.zig`).
//!
//! Randomness replay (matches PQCgenKAT_sign.c + nist.c exactly):
//!   randombytes_init(vector `seed`); then per vector the reference
//!   makes three randombytes() draws, each of which reseeds the DRBG:
//!     1. 48 bytes — crypto_sign_keypair's keygen seed. The reference
//!        injects those 48 bytes into a fresh SHAKE256 context and runs
//!        Zf(keygen) off it; `sign.ShakePrng` IS that construction, so
//!        feeding it the draw reproduces (f, g) — and hence pk/sk —
//!        bit-for-bit (NTRUSolve consumes no randomness).
//!     2. 40 bytes — the signature nonce.
//!     3. 48 bytes — the signer's SHAKE->ChaCha20 PRNG seed.
//!   Draws 2+3 are replayed through `kat_sign_test.FixedRng` so
//!   `signWithRng` consumes them in the reference's exact order.
//!
//! `kat_sign_test.zig` covers the signer in isolation (sk decoded from
//! the vector); this file covers keygen in isolation AND the two glued
//! together — the complete seed -> pk/sk/sm pipeline.

const std = @import("std");
const falcon = @import("root.zig");
const poly = @import("poly.zig");
const v = @import("kat_vectors.zig");
const kst = @import("kat_sign_test.zig");

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = std.fmt.hexToBytes(out, hex_str) catch unreachable;
    return out;
}

test "Falcon-512 KAT: deterministic keygen reproduces pk/sk byte-exact" {
    const gpa = std.testing.allocator;
    for (v.falcon512) |vec| {
        const seed = try hexAlloc(gpa, vec.seed);
        defer gpa.free(seed);
        const want_pk = try hexAlloc(gpa, vec.pk);
        defer gpa.free(want_pk);
        const want_sk = try hexAlloc(gpa, vec.sk);
        defer gpa.free(want_sk);
        try std.testing.expectEqual(@as(usize, 48), seed.len);
        try std.testing.expectEqual(@as(usize, 897), want_pk.len);
        try std.testing.expectEqual(@as(usize, 1281), want_sk.len);

        var drbg = kst.Drbg.init(seed[0..48]);
        var kgseed: [48]u8 = undefined;
        drbg.bytes(&kgseed); // draw 1: the keygen seed
        var prng = falcon.sign.ShakePrng.init(&kgseed);
        const kp = try falcon.generateKeyPair(prng.random());

        try std.testing.expectEqualSlices(u8, want_pk, &kp.public_key.toBytes());
        try std.testing.expectEqualSlices(u8, want_sk, &kp.signing_key.toSecretKeyBytes());
    }
}

test "Falcon-1024 KAT: deterministic keygen reproduces pk/sk byte-exact" {
    const gpa = std.testing.allocator;
    for (v.falcon1024) |vec| {
        const seed = try hexAlloc(gpa, vec.seed);
        defer gpa.free(seed);
        const want_pk = try hexAlloc(gpa, vec.pk);
        defer gpa.free(want_pk);
        const want_sk = try hexAlloc(gpa, vec.sk);
        defer gpa.free(want_sk);
        try std.testing.expectEqual(@as(usize, 48), seed.len);
        try std.testing.expectEqual(@as(usize, 1793), want_pk.len);
        try std.testing.expectEqual(@as(usize, 2305), want_sk.len);

        var drbg = kst.Drbg.init(seed[0..48]);
        var kgseed: [48]u8 = undefined;
        drbg.bytes(&kgseed);
        var prng = falcon.sign.ShakePrng.init(&kgseed);
        const kp = try falcon.generateKeyPair1024(prng.random());

        try std.testing.expectEqualSlices(u8, want_pk, &kp.public_key.toBytes());
        try std.testing.expectEqualSlices(u8, want_sk, &kp.signing_key.toSecretKeyBytes());
    }
}

test "Falcon-512 KAT: full pipeline — keygen + sign from seed reproduces the sm envelope" {
    const gpa = std.testing.allocator;
    const Signer = falcon.sign.Signer(poly.Ring512);
    for (v.falcon512) |vec| {
        const seed = try hexAlloc(gpa, vec.seed);
        defer gpa.free(seed);
        const msg = try hexAlloc(gpa, vec.msg);
        defer gpa.free(msg);
        const sm = try hexAlloc(gpa, vec.sm);
        defer gpa.free(sm);

        // Expected nonce + signature field out of the sm envelope (the
        // same parse `openNistSignedMessage` — already KAT-verified —
        // performs internally).
        const sig_len = (@as(usize, sm[0]) << 8) | sm[1];
        try std.testing.expect(sig_len >= 1 and sig_len <= sm.len - 2 - falcon.nonce_length);
        const want_nonce = sm[2 .. 2 + falcon.nonce_length];
        const want_sig = sm[sm.len - sig_len ..];
        try std.testing.expectEqual(falcon.sig_header, want_sig[0]);

        // Replay all three DRBG draws.
        var drbg = kst.Drbg.init(seed[0..48]);
        var kgseed: [48]u8 = undefined;
        drbg.bytes(&kgseed); // draw 1: keygen
        var rng_stream: [falcon.nonce_length + 48]u8 = undefined;
        drbg.bytes(rng_stream[0..falcon.nonce_length]); // draw 2: nonce
        drbg.bytes(rng_stream[falcon.nonce_length..]); // draw 3: sign seed

        var prng = falcon.sign.ShakePrng.init(&kgseed);
        const kp = try falcon.generateKeyPair(prng.random());

        var fixed = kst.FixedRng{ .buf = &rng_stream };
        var nonce_out: [falcon.nonce_length]u8 = undefined;
        var sig_out: [2000]u8 = undefined;
        const len = try Signer.signWithRng(&kp.signing_key.tree, msg, fixed.random(), &nonce_out, &sig_out, falcon.sig_bound);

        try std.testing.expectEqualSlices(u8, want_nonce, &nonce_out);
        try std.testing.expectEqualSlices(u8, want_sig, sig_out[0..len]);
    }
}

test "randomized keygen -> sign -> verify round trip, fresh key" {
    // Not KAT-pinned: a fresh key from an arbitrary (deterministic-seed)
    // PRNG, signed with `signRandomized`, verified by this module's own
    // (already KAT-verified) `PublicKey.verify` — end-to-end
    // self-consistency independent of byte-exact reproduction.
    // (std.Random.DefaultPrng stands in for a CSPRNG; production callers
    // should seed from the OS.)
    var prng = std.Random.DefaultPrng.init(0xfa1c05eed);
    const rng = prng.random();
    const kp = try falcon.generateKeyPair(rng);
    const message = "falcon keygen round-trip";
    var nonce: [falcon.nonce_length]u8 = undefined;
    var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
    const len = try falcon.signRandomized(&kp.signing_key, message, rng, &nonce, &sig_buf);
    try kp.public_key.verify(message, &nonce, sig_buf[0..len]);
}

test "randomized keygen -> sign -> verify: a tampered message is rejected by PublicKey.verify directly" {
    // Every reject-path test elsewhere in this module's suite goes through
    // `openNistSignedMessage` against the ONE fixed NIST KAT public key —
    // never through `PublicKey.verify` directly on a freshly generated
    // keypair. A `verify` defect that happened to still reject that one
    // pinned vector's specific numeric range (by coincidence, or because
    // `openNistSignedMessage`'s own framing catches it first) would not
    // be caught by any of them.
    var prng = std.Random.DefaultPrng.init(0xfa1c05eed);
    const rng = prng.random();
    const kp = try falcon.generateKeyPair(rng);
    const message = "falcon keygen round-trip";
    var nonce: [falcon.nonce_length]u8 = undefined;
    var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
    const len = try falcon.signRandomized(&kp.signing_key, message, rng, &nonce, &sig_buf);

    try std.testing.expectError(
        error.SignatureVerificationFailed,
        kp.public_key.verify("a different message entirely", &nonce, sig_buf[0..len]),
    );
}
