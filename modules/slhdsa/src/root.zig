// SPDX-License-Identifier: MIT
//! slhdsa — SLH-DSA (FIPS 205, the standardized SPHINCS+): stateless
//! hash-based digital signatures, pure Zig over std.crypto's SHA-256.
//!
//! **Implemented parameter set: SLH-DSA-SHA2-128f only** (security
//! category 1, "fast"; pk 32 B, sk 64 B, signature 17 088 B), end-to-end:
//! keygen, sign, verify — the §11.2 SHA2 tweakable hashes/PRFs (incl. the
//! compressed ADRS), WOTS+ (§5), XMSS (§6), the hypertree (§7), FORS (§8),
//! the internal functions (§9) and the pure external interface with context
//! strings (§10.2). KAT-validated byte-exactly against the official NIST
//! ACVP FIPS 205 vectors (keyGen + deterministic/hedged/pure-with-context
//! sigGen) — see src/kat_vectors.zig for the exact test-case provenance.
//!
//! Out of scope (this pass): the other eleven parameter sets (128s,
//! 192s/f, 256s/f, all SHAKE variants — `params.Params` carries every knob,
//! so they are addable without restructuring) and the HashSLH-DSA pre-hash
//! variants (§10.2.2). Signing is NOT constant-time hardened (fine for this
//! public-key scheme's verify; keep sk handling in mind). Fills a real
//! std gap: Zig 0.16 std.crypto ships ML-DSA and ML-KEM but no SLH-DSA.
//!
//! Zig std GAP: yes — std.crypto has no stateless hash-based signature
//! scheme. Clean-room from FIPS 205 (public standard); no third-party
//! implementation ported or studied, so no NOTICE entry (spec citation in
//! SPEC.md); the NIST ACVP JSON vectors are used purely as a test oracle.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys are plain value types
    .model_after = "FIPS 205 (SLH-DSA / SPHINCS+); NIST ACVP vectors as KAT oracle",
    .deps = .{}, // std only (std.crypto SHA-256 + HMAC-SHA-256)
};

/// FIPS 205 parameter sets (`params.sha2_128f`) + the `Params` struct.
pub const params = @import("params.zig");

/// §4.2 hash addresses (ADRS) incl. the SHA2 compressed form.
pub const address = @import("address.zig");

/// The generic construction; instantiate via `SlhDsa(params.sha2_128f)`.
pub const engine = @import("engine.zig");

/// Generic SLH-DSA over a `params.Params` set (only the SHA2
/// security-category-1 instantiation compiles today).
pub const SlhDsa = engine.SlhDsa;

/// SLH-DSA-SHA2-128f — the one KAT-validated, ready-to-use instantiation.
pub const SlhDsaSha2_128f = engine.SlhDsa(params.sha2_128f);

test "public API surface: sizes and a sign/verify smoke" {
    try std.testing.expectEqual(@as(usize, 32), SlhDsaSha2_128f.public_key_length);
    try std.testing.expectEqual(@as(usize, 64), SlhDsaSha2_128f.secret_key_length);
    try std.testing.expectEqual(@as(usize, 17088), SlhDsaSha2_128f.signature_length);

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
