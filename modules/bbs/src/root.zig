// SPDX-License-Identifier: MIT
//! bbs — BBS signatures (draft-irtf-cfrg-bbs-signatures): pairing-based
//! multi-message signatures supporting zero-knowledge SELECTIVE
//! DISCLOSURE proofs — sign a vector of messages under one header with a
//! single, constant-size signature, then later prove knowledge of that
//! signature while revealing only a chosen SUBSET of the signed messages,
//! without revealing the signature itself or the undisclosed messages.
//! This is the cryptographic basis of anonymous credentials / verifiable
//! credentials (W3C VC selective disclosure, mobile driving licenses,
//! privacy-preserving identity wallets). Builds directly on the finished
//! `bls12_381` module (Parts 1-3: field tower, `G1`/`G2` group
//! arithmetic, the pairing, RFC 9380 hash-to-curve) — this module adds
//! nothing to the field/group/pairing math itself, only the
//! BBS-signature-specific ciphersuite machinery, key generation, wire
//! codecs, and the four signature/proof cores.
//!
//! **Status: COMPLETE.** The ciphersuite machinery (`ciphersuite.zig`:
//! `expand_message`/`hash_to_scalar`/`create_generators`/
//! `messages_to_scalars`/`calculate_domain`/`calculate_random_scalars`/
//! `mocked_random_scalars`), key generation (`keys.zig`: `keyGen`/
//! `skToPk`), the `Signature`/`Proof` wire structs + byte codecs, AND the
//! FOUR cryptographic cores `sign`/`verify`/`proofGen`/`proofVerify`
//! (`bbs.zig`) are all implemented and byte-exact KAT-pinned against
//! `mattrglobal/pairing_crypto`'s official `bls12_381_sha_256` fixture
//! directory (see `SPEC.md` for the exact draft version/commit pinned).
//! `gate.core_implemented = true`, so every gated KAT — the sign/proof
//! byte-exact vectors and the signature/proof tamper-rejection cases —
//! runs and passes (Debug + ReleaseFast). See `bbs.zig`'s module
//! doc comment for why `proofGen`/`proofVerify` (the selective-disclosure
//! Fiat-Shamir NIZK), not `sign`/`verify`, are the genuinely hard core.
//!
//! ## Layout
//!
//! - `ciphersuite.zig` — REAL. The `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`
//!   ciphersuite constants (`P1`/`BP2`/DSTs/`expand_len`/`api_id`) and
//!   the mechanical hash/generator/domain/random-scalar machinery.
//! - `keys.zig` — REAL. `KeyGen`/`SkToPk`, `SecretKey`/`PublicKey` + wire
//!   codecs.
//! - `bbs.zig` — `Signature`/`Proof` structs + byte codecs (REAL); the
//!   four **FABLE CORE** functions `sign`/`verify`/`proofGen`/
//!   `proofVerify` (implemented).
//! - `gate.zig` — the single switch (`core_implemented`) gating the four
//!   cores' KAT tests.
//! - `kat_vectors.zig` — `mattrglobal/pairing_crypto`'s official
//!   `bls12_381_sha_256` fixtures, transcribed verbatim.
//! - `kat_test.zig` — the byte-exact KAT harness (ungated
//!   generators/KeyGen/messages-to-scalars/mocked-RNG tests plus the
//!   now-enabled gated sign/verify/proofGen/proofVerify byte-exact +
//!   tamper-rejection tests — all run and pass).
//!
//! ## Randomness
//!
//! `proofGen` (`bbs.zig`) needs fresh entropy for its blinding scalars
//! (draft §3.7.1's `random_scalars`, `3 + U` values for `U` undisclosed
//! messages) — but the draft's own OFFICIAL test vectors are only
//! reproducible byte-exact under a DETERMINISTIC mock RNG (§7.1's
//! `seeded_random_scalars`). Rather than having `proofGen` read
//! `std.Io`/internal entropy directly (which would make the deterministic
//! KAT vectors unreachable without a test-only code path), this module's
//! `proofGen` takes `random_scalars: []const Fr` as a PLAIN PARAMETER —
//! the caller supplies it, sourced from either:
//!
//! - `ciphersuite.calculateRandomScalars(comptime count, io: std.Io)` —
//!   real entropy (draft §4.2.1), for production callers.
//! - `ciphersuite.mockedRandomScalars(comptime count, seed: []const u8)`
//!   — the deterministic mock RNG (draft §7.1), for KAT reproducibility.
//!
//! This mirrors `frost`'s "nonces are an explicit input, never an
//! internal `std.Io` read" convention (see `frost/src/root.zig`'s own
//! doc comment) — the same shape, generalized from FROST's signing
//! nonces to BBS's proof-blinding scalars. `bbs.zig`'s module doc
//! comment has the full rationale and `kat_test.zig`'s gated `proofGen`
//! tests show both sources in use.

const std = @import("std");

pub const ciphersuite = @import("ciphersuite.zig");
pub const keys = @import("keys.zig");
pub const gate = @import("gate.zig");

const bbs_mod = @import("bbs.zig");
pub const BbsError = bbs_mod.BbsError;
pub const Signature = bbs_mod.Signature;
pub const Proof = bbs_mod.Proof;
/// FABLE CORE — see `bbs.zig`.
pub const sign = bbs_mod.sign;
/// FABLE CORE — see `bbs.zig`.
pub const verify = bbs_mod.verify;
/// FABLE CORE — see `bbs.zig`.
pub const proofGen = bbs_mod.proofGen;
/// FABLE CORE — see `bbs.zig`.
pub const proofVerify = bbs_mod.proofVerify;

pub const SecretKey = keys.SecretKey;
pub const PublicKey = keys.PublicKey;
pub const keyGen = keys.keyGen;
pub const skToPk = keys.skToPk;

/// Re-exported: the sibling module this module builds on.
pub const bls12_381 = @import("bls12_381");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure computation; the one entropy source (calculateRandomScalars) takes a portable std.Io, no raw getrandom(2)
    .role = .util, // no I/O, no wire framing beyond point/scalar (de)serialization
    .concurrency = .reentrant, // every type is a plain value; no globals
    .model_after = "draft-irtf-cfrg-bbs-signatures-04 (the BLS12-381-SHA-256 ciphersuite); test vectors from mattrglobal/pairing_crypto's bls12_381_sha_256 fixture directory (see SPEC.md for exact version/commit pinning); bls12_381 (this repo) supplies the field/group/pairing/hash-to-curve primitives",
    .deps = .{ "bls12_381", "entropy" }, // entropy: the blinding-scalar draw
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too.

const kat_test = @import("kat_test.zig");

test {
    _ = ciphersuite;
    _ = keys;
    _ = gate;
    _ = bbs_mod;
    _ = kat_test;
}

test "meta.model_after names the bbs-signatures draft" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "bbs-signatures-04") != null);
}

test "meta.deps is exactly {bls12_381, entropy}" {
    try std.testing.expectEqual(@as(usize, 2), meta.deps.len);
    try std.testing.expectEqualStrings("bls12_381", meta.deps[0]);
    try std.testing.expectEqualStrings("entropy", meta.deps[1]);
}

test "gate IS flipped (the four Fable cores are implemented)" {
    // The scaffold-stage counterpart of this test asserted
    // `!gate.core_implemented`; the Fable pass that implemented the four
    // cores flipped `gate.zig`, so this now pins the POST-Fable state
    // (and `kat_test.zig`'s gated byte-exact KATs actually run).
    try std.testing.expect(gate.core_implemented);
}

test "Signature.encoded_bytes / Proof.encodedLen(0) match the draft's fixed widths" {
    try std.testing.expectEqual(@as(usize, 80), Signature.encoded_bytes);
    try std.testing.expectEqual(@as(usize, 192), Proof.encodedLen(0));
}
