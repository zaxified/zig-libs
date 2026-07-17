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
//! ## Status: Phase 1 — SCAFFOLD (Fable core gated).
//!
//! The mechanical layer is REAL and tested: the pairing/curve plumbing
//! over `bls12_381` (`params.zig`), the trusted-dealer Shamir threshold
//! keygen + Lagrange-in-exponent verification-key aggregation
//! (`keys.zig`), the `lagrange.coefficientAtZero` helper (`lagrange.zig`),
//! the wire codecs, and the two verification oracles
//! `psSignWithSecret`/`psVerifyPlain` (`credential.zig`). The FOUR
//! irreducible cores — `signPartial`, `aggregateCredential`,
//! `proveCredential`, `verifyCredential` — are `@panic("TODO(fable/core):
//! …")` stubs behind `gate.fable_core_implemented` (`false`). See
//! `SPEC.md` for the construction, the Fable-vs-mechanical split, the
//! tier finding (no external byte-exact vector exists → genuine Fable,
//! weight concentrated in the selective-disclosure NIZK), and the
//! deferred increments (blind issuance ElGamal + NIZK π_s;
//! distributed-authority DKG wiring; SHAKE ciphersuite).
//!
//! ## Randomness
//!
//! Following the `bbs`/`frost`/`ibe` convention, the blinding + witness
//! nonces are supplied by a caller `std.Random` (keygen: `keys.keygen`;
//! show: `proveCredential`) rather than read from `std.Io` internally, so
//! a seeded PRNG makes issuance/show deterministic in tests.
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
//!   four **FABLE CORE** functions (gated `@panic` stubs).
//! - `gate.zig` — the single `fable_core_implemented` switch.
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
pub const keygen = keys.keygen;
pub const aggregateVerificationKeys = keys.aggregateVerificationKeys;
pub const Credential = credential.Credential;
pub const PartialCredential = credential.PartialCredential;
pub const ShowProof = credential.ShowProof;
pub const CoconutError = credential.CoconutError;
pub const signPartial = credential.signPartial;
pub const aggregateCredential = credential.aggregateCredential;
pub const proveCredential = credential.proveCredential;
pub const verifyCredential = credential.verifyCredential;
pub const psSignWithSecret = credential.psSignWithSecret;
pub const psVerifyPlain = credential.psVerifyPlain;

pub const meta = .{
    .platform = .any, // pure Fr/G1/G2/pairing math over bls12_381
    .role = .util,
    .concurrency = .reentrant, // no shared state; randomness is a caller param
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
