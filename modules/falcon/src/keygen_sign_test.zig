// SPDX-License-Identifier: MIT
//! keygen_sign_test — the keygen + sign KAT harness. Written against
//! `root.zig`'s FINAL public API (`generateKeyPair`, `signDeterministic`,
//! `signRandomized`), which delegates the hard math to `ntru`/
//! `ffsampling`/`gaussian` — all `@panic("TODO(fable/core): ...")` stubs
//! today (see `root.zig`'s module doc comment for the full list).
//!
//! Every test below does REAL work — hex-decoding the vector, checking
//! lengths, setting up the deterministic PRNG — and then stops with
//! `return error.SkipZigTest` immediately before the first call that
//! would reach a stub, so `zig build test-falcon` stays GREEN today (a
//! skipped test is not a failed test). Once the stubs are filled in,
//! delete that `SkipZigTest` line (grep this file for it) and uncomment
//! the "once real" block right below it — each test becomes a genuine
//! byte-exact KAT check against the official NIST Round-3 vectors'
//! `seed`/`pk`/`sk`/`sm` fields (`kat_vectors.zig` — see that file's
//! module doc comment for provenance of `seed`).
//!
//! What each (currently-skipped) assertion will check once real:
//!   - `generateKeyPair`, seeded deterministically from a vector's
//!     `seed` (via `sign.ShakePrng`), reproduces that vector's own `pk`
//!     bytes exactly (`PublicKey.toBytes()`) and its `sk` bytes exactly
//!     (`SigningKey.toSecretKeyBytes()`).
//!   - `signDeterministic`, given the regenerated signing key and the
//!     same `seed`, reproduces the vector's own compressed signature
//!     field bytes exactly (the `sm` envelope's tail, after the 40-byte
//!     nonce and the message).
//!   - `signRandomized`, given ANY valid signing key (not necessarily
//!     KAT-derived) and a real CSPRNG, produces a signature that the
//!     module's own (already NIST-KAT-verified) `verify` path accepts —
//!     an end-to-end round trip that does not depend on byte-exact
//!     reproduction of anything, only on keygen+sign+verify being
//!     mutually consistent.
//!
//! Full byte-exact KAT reproduction (the first two bullets) additionally
//! requires `ntru.zig`, `ffsampling.zig`, and `gaussian.zig` to consume
//! randomness from `rng` in the same order/quantity the Falcon reference
//! implementation does — intertwined with their (currently stubbed)
//! internals, so it cannot be pinned down further until they exist; see
//! `sign.ShakePrng`'s doc comment for the precise caveat.

const std = @import("std");
const falcon = @import("root.zig");
const v = @import("kat_vectors.zig");

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = std.fmt.hexToBytes(out, hex_str) catch unreachable;
    return out;
}

test "Falcon-512 KAT: deterministic keygen reproduces pk/sk byte-exact (STUB — SkipZigTest until ntru/ffsampling/gaussian land)" {
    const gpa = std.testing.allocator;
    for (v.falcon512) |vec| {
        const seed = try hexAlloc(gpa, vec.seed);
        defer gpa.free(seed);
        const want_pk = try hexAlloc(gpa, vec.pk);
        defer gpa.free(want_pk);
        const want_sk = try hexAlloc(gpa, vec.sk);
        defer gpa.free(want_sk);

        // The harness itself is real: seed decodes to exactly 48 bytes
        // (the NIST-KAT DRBG seed width) for every embedded vector.
        try std.testing.expectEqual(@as(usize, 48), seed.len);
        try std.testing.expectEqual(@as(usize, 897), want_pk.len);
        try std.testing.expectEqual(@as(usize, 1281), want_sk.len);
    }

    // `falcon.generateKeyPair` reaches `ntru.Ntru(Ring).generate` (via
    // `keygen.Keygen(Ring).generate`) and `ffsampling.buildTree` — both
    // stubs. Skip past the actual keygen call until they're implemented.
    return error.SkipZigTest;

    // Once real, for each vector:
    //   var prng = falcon.sign.ShakePrng.init(seed);
    //   const kp = try falcon.generateKeyPair(prng.random());
    //   try std.testing.expectEqualSlices(u8, want_pk, &kp.public_key.toBytes());
    //   try std.testing.expectEqualSlices(u8, want_sk, &kp.signing_key.toSecretKeyBytes());
}

test "Falcon-512 KAT: deterministic sign reproduces the compressed signature byte-exact (STUB — SkipZigTest until ffsampling/gaussian land)" {
    const gpa = std.testing.allocator;
    const vec = v.falcon512[0];
    const seed = try hexAlloc(gpa, vec.seed);
    defer gpa.free(seed);
    const sm = try hexAlloc(gpa, vec.sm);
    defer gpa.free(sm);

    // The harness itself is real: the vector's own sm envelope parses
    // (this is the SAME parse `openNistSignedMessage` — already
    // KAT-verified on the verify side — performs internally).
    const sig_len = (@as(usize, sm[0]) << 8) | sm[1];
    try std.testing.expect(sig_len >= 1 and sig_len <= sm.len - 2 - falcon.nonce_length);
    const want_sig_field = sm[sm.len - sig_len ..];
    try std.testing.expectEqual(falcon.sig_header, want_sig_field[0]);

    // `signDeterministic` reaches `ffsampling.sampleSignature` (via
    // `sign.Signer(Ring).signWithRng`) — a stub. Skip past the actual
    // sign call until it (and its own dependencies, fft/gaussian) are
    // implemented.
    return error.SkipZigTest;

    // Once real (needs a signing key — either decoded from vec.sk once
    // SecretKey carries G too, or regenerated via the keygen test above
    // from the same seed):
    //   var nonce: [falcon.nonce_length]u8 = undefined;
    //   var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
    //   const len = try falcon.signDeterministic(&signing_key, vec_msg, seed, &nonce, &sig_buf);
    //   try std.testing.expectEqualSlices(u8, want_sig_field, sig_buf[0..len]);
}

test "Falcon-1024 KAT: deterministic keygen harness decodes correctly (STUB — SkipZigTest until ntru/ffsampling/gaussian land)" {
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
    }
    return error.SkipZigTest;

    // Once real, mirrors the Falcon-512 keygen test above against
    // falcon.generateKeyPair1024 / falcon.SigningKey1024.
}

test "randomized sign -> verify round trip, any fresh key (STUB — SkipZigTest until the full signer stack lands)" {
    // Not KAT-pinned: `signRandomized` with `std.crypto.random`, verified
    // by this module's own (already KAT-verified) `PublicKey.verify` —
    // the cheapest possible end-to-end self-consistency check once
    // keygen+sign exist, independent of byte-exact KAT reproduction.
    return error.SkipZigTest;

    // Once real:
    //   const kp = try falcon.generateKeyPair(std.crypto.random);
    //   var nonce: [falcon.nonce_length]u8 = undefined;
    //   var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
    //   const len = try falcon.signRandomized(&kp.signing_key, "hello", std.crypto.random, &nonce, &sig_buf);
    //   try kp.public_key.verify("hello", &nonce, sig_buf[0..len]);
}
