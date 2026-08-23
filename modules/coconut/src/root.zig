// SPDX-License-Identifier: MIT
//! coconut — Coconut threshold-issuance selective-disclosure anonymous
//! credentials over `bls12_381` (Sonnino, Bano, Al-Bassam, Danezis,
//! "Coconut: Threshold Issuance Selective Disclosure Credentials with
//! Applications to Distributed Ledgers", NDSS 2019 — the credential layer
//! of Nym). A set of `n` authorities each hold a Shamir share of a
//! Pointcheval-Sanders (PS) secret key; any `t` of them independently
//! issue partial credentials on an attribute vector, which the user
//! aggregates (Lagrange-in-EXPONENT) into one short, re-randomizable PS
//! credential, then later SHOWS to a verifier while revealing only a
//! chosen subset of attributes in zero knowledge.
//!
//! ## Status: Phase 1 — COMPLETE (Fable core implemented).
//!
//! The mechanical layer is REAL and tested: the pairing/curve plumbing
//! over `bls12_381` (`params.zig`), the trusted-dealer Shamir threshold
//! keygen + Lagrange-in-exponent verification-key aggregation
//! (`keys.zig`), the `lagrange.coefficientAtZero` helper (`lagrange.zig`),
//! the wire codecs, and the two verification oracles
//! `psSignWithSecret`/`psVerifyPlain` (`credential.zig`). The FOUR
//! irreducible cores — `signPartial`, `aggregateCredential`,
//! `proveCredential`, `verifyCredential` — are now implemented and their
//! end-to-end anchor + NIZK-soundness controls execute
//! (`gate.fable_core_implemented = true`). See `SPEC.md` for the
//! construction, the full Fiat-Shamir transcript element list, the
//! Fable-vs-mechanical split, the tier finding (no external byte-exact
//! vector exists → genuine Fable, weight concentrated in the
//! selective-disclosure NIZK), and the deferred increments (blind
//! issuance ElGamal + NIZK π_s; distributed-authority DKG wiring; SHAKE
//! ciphersuite).
//!
//! ## Randomness
//!
//! Both entry points that sample secrets — `keygen` (the authority master
//! secret `(x, y₁…y_q)` and its Shamir blinding) and `proveCredential` (the
//! re-randomisation scalars and the Sigma-protocol witness nonces) — take
//! `io: std.Io` and draw every scalar through `Entropy.scalar` (`keys.zig`),
//! which calls `bls12_381`'s `Fr.random(io)`. That function is fail-closed:
//! it draws through `entropy.fill`, which is `std.Io.randomSecure` or an
//! abort, never the silently-degrading `std.Io.random` (`std/Io.zig`'s
//! `random` doc documents the fallback; `entropy`'s doc comment has the
//! measurements). This module reaches that posture transitively, through
//! `bls12_381`, rather than by importing `entropy` itself — this is the
//! `bbs`/`ibe`/`tlock` shape (`io: std.Io` for the real draw, an explicitly
//! named seeded path for tests), and unlike when this note was last written,
//! failing closed is no longer an open question: it is `CONVENTIONS.md` §2.2,
//! formerly tracked as B7, now closed.
//!
//! It matters because the consequences are total, not marginal. A
//! seed-derived master secret lets anyone who recovers the seed issue
//! arbitrary valid credentials — the `t`-of-`n` threshold split becomes
//! decoration, since the dealer's secret never had to be reassembled from
//! shares. A witness nonce that repeats across two shows lets a verifier who
//! sees both extract the hidden attributes and the blinding by the standard
//! two-transcript Sigma-protocol argument, which is precisely what selective
//! disclosure exists to prevent.
//!
//! Coconut has no published byte-exact test vector (SPEC §3), so nothing
//! outside this repo needs a deterministic issuance. This module's own suites
//! get one from `keygenSeededForTest` / `proveCredentialSeededForTest` —
//! named so that a production call site cannot reach determinism by accident.
//!
//! ## Layout
//!
//! - `params.zig` — REAL. `Setup(q)`: attribute generators + the common
//!   base `h = hashToCurveG1(cm)`.
//! - `keys.zig` — REAL. Threshold keygen, `vk` derivation, Lagrange-in-
//!   exponent `vk` aggregation.
//! - `lagrange.zig` — REAL. Lagrange coefficient at `x = 0` over `Fr`.
//! - `credential.zig` — `Credential`/`PartialCredential`/`ShowProof` +
//!   codecs + the `psSignWithSecret`/`psVerifyPlain` oracles (REAL); the
//!   four **FABLE CORE** functions (implemented; the show-proof NIZK's
//!   full Fiat-Shamir transcript is documented on `showChallenge`).
//! - `gate.zig` — the single `fable_core_implemented` switch (now `true`).
//! - `harness_test.zig` — the `BrokenCoconut` positive control (REAL) and
//!   the gated end-to-end anchor + NIZK-soundness controls.

const std = @import("std");

pub const gate = @import("gate.zig");
pub const params = @import("params.zig");
pub const lagrange = @import("lagrange.zig");
pub const keys = @import("keys.zig");
pub const credential = @import("credential.zig");

// Convenience re-exports.
pub const Parameters = params.Parameters;
pub const SecretKey = keys.SecretKey;
pub const VerificationKey = keys.VerificationKey;
pub const SecretKeyShare = keys.SecretKeyShare;
pub const VerificationKeyShare = keys.VerificationKeyShare;
pub const ThresholdKeys = keys.ThresholdKeys;
pub const Entropy = keys.Entropy;
pub const keygen = keys.keygen;
/// TEST ONLY — see `keys.keygenSeededForTest`.
pub const keygenSeededForTest = keys.keygenSeededForTest;
pub const aggregateVerificationKeys = keys.aggregateVerificationKeys;
pub const Credential = credential.Credential;
pub const PartialCredential = credential.PartialCredential;
pub const ShowProof = credential.ShowProof;
pub const CoconutError = credential.CoconutError;
pub const signPartial = credential.signPartial;
pub const aggregateCredential = credential.aggregateCredential;
pub const proveCredential = credential.proveCredential;
/// TEST ONLY — see `credential.proveCredentialSeededForTest`.
pub const proveCredentialSeededForTest = credential.proveCredentialSeededForTest;
pub const verifyCredential = credential.verifyCredential;
pub const psSignWithSecret = credential.psSignWithSecret;
pub const psVerifyPlain = credential.psVerifyPlain;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Coconut threshold-issuance anonymous credentials over `bls12_381` — t-of-n issued Pointcheval-Sanders credentials with selective-disclosure showing.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure Fr/G1/G2/pairing math over bls12_381
    .role = .util,
    .concurrency = .reentrant, // no shared state; the one entropy source (keygen/proveCredential) takes a portable std.Io, no raw getrandom(2)
    .model_after = "asonnino/coconut (Python) + nymtech/coconut (Rust/Go), Coconut NDSS 2019",
    .deps = .{"bls12_381"},
};

// Dark-tests aggregator: a bare `pub const x = @import(...)` re-export
// does NOT pull x's tests into the test binary — every submodule with
// tests must be named here (CONVENTIONS.md §6).
test {
    _ = params;
    _ = lagrange;
    _ = keys;
    _ = credential;
    _ = @import("harness_test.zig");
}

test "meta.model_after names Coconut" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Coconut") != null);
}
