// SPDX-License-Identifier: MIT
//! hqc — HQC (Hamming Quasi-Cyclic), the code-based KEM NIST selected in
//! March 2025 as a structurally-independent backup to ML-KEM (std already
//! ships ML-KEM/ML-DSA, both lattice-based; HQC is code-based — a
//! genuine, previously-unfilled gap in this repo's PQ coverage).
//!
//! **This is Part 1 of a multi-part arc — the ring/PRNG foundation, not a
//! usable KEM yet.** No `keygen`/`encapsulate`/`decapsulate` exist here.
//! What Part 1 delivers:
//!
//! - `params` — the three NIST parameter sets (hqc-128/192/256) as
//!   comptime structs, transcribed from and cross-checked against the
//!   official spec's Table 5/6 and the reference implementation's
//!   `parameters.h` (see params.zig's module doc for exact provenance).
//! - `gf2x` — the ambient ring R = F2[X]/(X^n-1): a bit-packed vector
//!   type, XOR-add, cyclic-convolution multiply, Hamming weight,
//!   byte codec (LSB-first, per spec), and truncate.
//! - `prng` — the two SHAKE256 instantiations HQC uses (its internal
//!   `Prng`, domain 0 — which, notably, is ALSO exactly the NIST KAT
//!   harness's `randombytes()` in this reference, no AES-DRBG needed;
//!   and its `Xof`, domain 1, with a load-bearing 8-byte-rounding quirk
//!   in `getBytes`), the I/G/H/J hash oracles, and both fixed-weight
//!   vector samplers (the unbiased rejection-sampling `$` variant for
//!   keygen's x/y, and the biased Algorithm-5 variant for encryption's
//!   r1/r2/e).
//!
//! **Byte-exactness status**: `Xof`, `Prng`(construction), `hashI`,
//! `hashG`, `sampleVect`, and `sampleFixedWeightRejection` are
//! independently verified byte-for-byte against the reference
//! implementation's own intermediate-value dump (kat_vectors.zig /
//! kat_test.zig) — not just transcribed from source. `hashH`, `hashJ`,
//! and `sampleFixedWeightBiased` are transcribed from the reference
//! source with the same care but are not yet numeric-KAT-pinned (the
//! reference's published fixture doesn't expose those intermediate
//! values directly) — see SPEC.md's Verification section for the exact
//! tier of every primitive.
//!
//! **The Fable-hard core is NOT here.** Part 1 is mechanical constant-
//! structure bit arithmetic and exact PRNG-construction matching — real
//! work, but not algorithmically hard. The genuinely hard part of HQC is
//! Part 2's concatenated Reed-Muller/Reed-Solomon decoder (Berlekamp +
//! additive-FFT root-finding for RS, Hadamard-transform maximum-
//! likelihood decoding for duplicated RM) — see SPEC.md's "Arc plan".
//!
//! Provenance: `NOTICE` for the reference-implementation design
//! reference; SPEC.md for the exact spec version + KAT source + what's
//! pinned vs. self-tested.

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; every type here is a plain value
    .model_after = "HQC spec v5.0.0 (22/08/2025, pqc-hqc.org); reference impl gitlab.com/pqc-hqc/hqc tag v5.0.0 as design + KAT-fixture reference",
    .deps = .{}, // std only (SHAKE256/SHA3-256/SHA3-512 from std.crypto.hash.sha3)
};

/// HQC-128/192/256 parameter sets.
pub const params = @import("params.zig");
/// The ambient ring R = F2[X]/(X^n-1).
pub const gf2x = @import("gf2x.zig");
/// SHAKE256 PRNG/XOF/hash layer + fixed-weight vector samplers.
pub const prng = @import("prng.zig");

test {
    // Dark-tests rule (CONVENTIONS.md §6.3): every submodule's tests must
    // be pulled in here, not just re-exported.
    _ = params;
    _ = gf2x;
    _ = prng;
    _ = @import("kat_test.zig");
}
