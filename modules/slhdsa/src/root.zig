// SPDX-License-Identifier: MIT
//! slhdsa — SLH-DSA (FIPS 205, the standardized SPHINCS+): stateless
//! hash-based digital signatures, pure Zig over std.crypto's SHA-2/SHAKE256.
//!
//! **All twelve FIPS 205 parameter sets implemented end-to-end**:
//! SLH-DSA-SHA2-{128,192,256}{s,f} and SLH-DSA-SHAKE-{128,192,256}{s,f} —
//! keygen, sign, verify, each NIST-KAT-verified byte-exactly against the
//! official ACVP FIPS 205 vectors (keyGen + deterministic-internal sigGen
//! per set; 128f additionally hedged and pure-with-context sigGen) — see
//! src/kat_vectors.zig for exact test-case provenance. Both §11 hash
//! instantiations are real: SHAKE256 (§11.1, full 32-byte ADRS) and SHA-2
//! (§11.2, compressed ADRS, with the category-3/5 SHA-512 split for
//! H/T_l/H_msg/PRF_msg), plus WOTS+ (§5), XMSS (§6), the hypertree (§7),
//! FORS (§8), the internal functions (§9) and the pure external interface
//! with context strings (§10.2).
//!
//! Out of scope: the HashSLH-DSA pre-hash variants (§10.2.2). Signing is
//! NOT constant-time hardened (fine for this public-key scheme's verify;
//! keep sk handling in mind). Key generation takes caller-supplied seed
//! bytes — bring your own CSPRNG (std 0.16 removed std.crypto.random).
//! Fills a real std gap: Zig 0.16 std.crypto ships ML-DSA and ML-KEM but
//! no SLH-DSA.
//!
//! Zig std GAP: yes — std.crypto has no stateless hash-based signature
//! scheme. Clean-room from FIPS 205 (public standard); no third-party
//! implementation ported or studied, so no NOTICE entry (spec citation in
//! SPEC.md); the NIST ACVP JSON vectors are used purely as a test oracle.

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys are plain value types
    .model_after = "FIPS 205 (SLH-DSA / SPHINCS+); NIST ACVP vectors as KAT oracle",
    .deps = .{}, // std only (SHA-256/SHA-512 + HMAC + SHAKE256)
};

/// All twelve FIPS 205 parameter sets + the `Params` struct.
pub const params = @import("params.zig");

/// §4.2 hash addresses (ADRS) incl. the SHA2 compressed form.
pub const address = @import("address.zig");

/// The generic construction; instantiate via `SlhDsa(params.sha2_128f)`.
pub const engine = @import("engine.zig");

/// Generic SLH-DSA over any FIPS 205 `params.Params` set.
pub const SlhDsa = engine.SlhDsa;

// Ready-to-use instantiations, all NIST-KAT-verified. "s" = small signature
// / slow signing, "f" = fast signing / large signature.

/// SLH-DSA-SHA2-128s (category 1: pk 32 B, sk 64 B, sig 7 856 B).
pub const SlhDsaSha2_128s = engine.SlhDsa(params.sha2_128s);
/// SLH-DSA-SHA2-128f (category 1: pk 32 B, sk 64 B, sig 17 088 B).
pub const SlhDsaSha2_128f = engine.SlhDsa(params.sha2_128f);
/// SLH-DSA-SHA2-192s (category 3: pk 48 B, sk 96 B, sig 16 224 B).
pub const SlhDsaSha2_192s = engine.SlhDsa(params.sha2_192s);
/// SLH-DSA-SHA2-192f (category 3: pk 48 B, sk 96 B, sig 35 664 B).
pub const SlhDsaSha2_192f = engine.SlhDsa(params.sha2_192f);
/// SLH-DSA-SHA2-256s (category 5: pk 64 B, sk 128 B, sig 29 792 B).
pub const SlhDsaSha2_256s = engine.SlhDsa(params.sha2_256s);
/// SLH-DSA-SHA2-256f (category 5: pk 64 B, sk 128 B, sig 49 856 B).
pub const SlhDsaSha2_256f = engine.SlhDsa(params.sha2_256f);

/// SLH-DSA-SHAKE-128s (category 1: pk 32 B, sk 64 B, sig 7 856 B).
pub const SlhDsaShake_128s = engine.SlhDsa(params.shake_128s);
/// SLH-DSA-SHAKE-128f (category 1: pk 32 B, sk 64 B, sig 17 088 B).
pub const SlhDsaShake_128f = engine.SlhDsa(params.shake_128f);
/// SLH-DSA-SHAKE-192s (category 3: pk 48 B, sk 96 B, sig 16 224 B).
pub const SlhDsaShake_192s = engine.SlhDsa(params.shake_192s);
/// SLH-DSA-SHAKE-192f (category 3: pk 48 B, sk 96 B, sig 35 664 B).
pub const SlhDsaShake_192f = engine.SlhDsa(params.shake_192f);
/// SLH-DSA-SHAKE-256s (category 5: pk 64 B, sk 128 B, sig 29 792 B).
pub const SlhDsaShake_256s = engine.SlhDsa(params.shake_256s);
/// SLH-DSA-SHAKE-256f (category 5: pk 64 B, sk 128 B, sig 49 856 B).
pub const SlhDsaShake_256f = engine.SlhDsa(params.shake_256f);

test "public API surface: sizes and a sign/verify smoke" {
    // Table 2 sizes for every exported instantiation.
    inline for (.{
        .{ SlhDsaSha2_128s, 32, 7856 },  .{ SlhDsaShake_128s, 32, 7856 },
        .{ SlhDsaSha2_128f, 32, 17088 }, .{ SlhDsaShake_128f, 32, 17088 },
        .{ SlhDsaSha2_192s, 48, 16224 }, .{ SlhDsaShake_192s, 48, 16224 },
        .{ SlhDsaSha2_192f, 48, 35664 }, .{ SlhDsaShake_192f, 48, 35664 },
        .{ SlhDsaSha2_256s, 64, 29792 }, .{ SlhDsaShake_256s, 64, 29792 },
        .{ SlhDsaSha2_256f, 64, 49856 }, .{ SlhDsaShake_256f, 64, 49856 },
    }) |case| {
        try std.testing.expectEqual(@as(usize, case[1]), case[0].public_key_length);
        try std.testing.expectEqual(@as(usize, 2 * case[1]), case[0].secret_key_length);
        try std.testing.expectEqual(@as(usize, case[2]), case[0].signature_length);
    }

    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i);
    const kp = SlhDsaSha2_128f.keyGen(seed);
    var sig: [SlhDsaSha2_128f.signature_length]u8 = undefined;
    try SlhDsaSha2_128f.sign(&sig, "hello", kp.sk, "", null);
    try std.testing.expect(SlhDsaSha2_128f.verify(&sig, "hello", kp.pk, ""));
    try std.testing.expect(!SlhDsaSha2_128f.verify(&sig, "hellp", kp.pk, ""));
}

test {
    _ = params;
    _ = address;
    _ = engine;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}
