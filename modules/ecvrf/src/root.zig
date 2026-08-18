// SPDX-License-Identifier: MIT
//! ecvrf — ECVRF-EDWARDS25519-SHA512-TAI, the elliptic-curve Verifiable
//! Random Function ciphersuite from RFC 9381 ("Verifiable Random
//! Functions (VRFs)", IRTF CFRG, August 2023) built on
//! `std.crypto.ecc.Edwards25519` + `std.crypto.hash.sha2.Sha512`. A VRF
//! is the public-key analogue of a keyed hash: only the secret-key
//! holder can compute `(pi, beta) = prove(sk, alpha)`, but anyone with
//! the public key can `verify(pk, alpha, pi)` that `beta =
//! proofToHash(pi)` really is the unique, deterministic output for that
//! `(pk, alpha)` pair — without learning the secret key, and without
//! being able to bias or predict `beta` before proving.
//!
//! Consumers: blockchain leader election / committee selection
//! (unpredictable-in-advance, publicly-verifiable randomness — the
//! headline VRF use case, e.g. Algorand's sortition), and DNSSEC NSEC5
//! (RFC 9276-adjacent; VRF-based authenticated denial of existence that
//! resists offline zone enumeration, unlike plain NSEC/NSEC3 hashing) —
//! both cited directly in RFC 9381's own introduction as motivating
//! applications. More generally, anywhere a party needs to prove "I
//! deterministically derived this pseudorandom value from my secret key
//! and this public input" without revealing the key.
//!
//! **Status: implemented.** `ecvrf.zig`'s `prove`/`proofToHash`/`verify`
//! and their RFC 9381 §5.4 auxiliary functions (`encodeToCurve` — the
//! try-and-increment hash-to-curve, `nonceGeneration` — RFC 8032-style
//! deterministic nonce, `decodeProof`, `validateKey`) are real, no
//! stubs; `kat_test.zig` validates the whole stack byte-exact against
//! RFC 9381 Appendix B.3's three official ECVRF-EDWARDS25519-SHA512-TAI
//! test vectors, including every published intermediate value (`x`, `H`,
//! `k_string`, `k`) and negative/tamper-reject cases beyond what the RFC
//! itself publishes. See `ecvrf.zig`'s own module doc comment for the
//! algorithm-to-RFC-section map and two easy-to-miss details it corrects
//! against a naive reading (the `suite_string = 0x03` vs the sibling
//! ELL2 ciphersuite's `0x04`, and `ECVRF_challenge_generation` hashing
//! FIVE points — `Y` included — not four).
//!
//! Zig std GAP: partial. `std.crypto` has no VRF construction of its own
//! (expected — a VRF is a composed protocol, not a primitive), but ships
//! every primitive this ciphersuite needs (`Edwards25519`, its `scalar`
//! submodule, `Sha512`) — this module is pure orchestration over std, no
//! new field/curve arithmetic (contrast `ed448`/`decaf448`/`bls12_381`,
//! which had to build a curve family std lacks).
//!
//! Deferred (out of scope for this module): **ECVRF-P256-SHA256-TAI**
//! and **ECVRF-EDWARDS25519-SHA512-ELL2** (RFC 9381 §5.5's other two
//! ciphersuites — P-256 would need `std.crypto.ecc`'s P256 support plus
//! SEC1 point encoding; ELL2 would need RFC 9380's Elligator2
//! hash-to-curve, `Edwards25519.fromUniform`/`elligator2`, both already
//! in std and a plausible low-effort follow-up); the **RSA-FDH-VRF**
//! family (RFC 9381 Appendix A, an entirely different non-elliptic-curve
//! construction).
//!
//! Provenance: clean-room from RFC 9381 (a public IETF/IRTF spec — no
//! third-party source ported). See `NOTICE`.

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation over caller-supplied keys/bytes — no owned socket/transport
    .concurrency = .reentrant, // no globals; every function here is a plain caller-owned value
    .model_after = "RFC 9381 §5 (Elliptic Curve VRF) + §5.5's ECVRF-EDWARDS25519-SHA512-TAI ciphersuite fixing, referencing RFC 8032 §5.1.2/§5.1.5 for point/scalar encoding and secret-key derivation; std.crypto.ecc.Edwards25519 (+ its scalar submodule) and std.crypto.hash.sha2.Sha512 supply every primitive",
    .deps = .{"ct25519"}, // constant-time secret-scalar multiply (see ecvrf.zig's module doc comment)
};

pub const ecvrf = @import("ecvrf.zig");

// Flat re-exports — the surface most callers need.
pub const suite_string = ecvrf.suite_string;
pub const c_len = ecvrf.c_len;
pub const q_len = ecvrf.q_len;
pub const pt_len = ecvrf.pt_len;
pub const h_len = ecvrf.h_len;
pub const proof_len = ecvrf.proof_len;

pub const SecretKey = ecvrf.SecretKey;
pub const PublicKey = ecvrf.PublicKey;
pub const Proof = ecvrf.Proof;
pub const Output = ecvrf.Output;
pub const Error = ecvrf.Error;
pub const DecodedProof = ecvrf.DecodedProof;

pub const secretScalar = ecvrf.secretScalar;
pub const publicKey = ecvrf.publicKey;
pub const encodeToCurve = ecvrf.encodeToCurve;
pub const nonceGenerationString = ecvrf.nonceGenerationString;
pub const nonceGeneration = ecvrf.nonceGeneration;
pub const decodeProof = ecvrf.decodeProof;
pub const validateKey = ecvrf.validateKey;
pub const prove = ecvrf.prove;
pub const proofToHash = ecvrf.proofToHash;
pub const verify = ecvrf.verify;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = ecvrf;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.deps is exactly {ct25519} (the constant-time secret-scalar ladder)" {
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("ct25519", meta.deps[0]);
}

test "suite_string is 0x03 (ECVRF-EDWARDS25519-SHA512-TAI), not the sibling ELL2 ciphersuite's 0x04" {
    try std.testing.expectEqual(@as(u8, 0x03), suite_string);
}

test "proof_len is ptLen+cLen+qLen = 32+16+32 = 80" {
    try std.testing.expectEqual(@as(usize, 80), proof_len);
}
