// SPDX-License-Identifier: MIT
//! hqc — HQC (Hamming Quasi-Cyclic), the code-based KEM NIST selected in
//! March 2025 as a structurally-independent backup to ML-KEM (std already
//! ships ML-KEM/ML-DSA, both lattice-based; HQC is code-based — a
//! genuine, previously-unfilled gap in this repo's PQ coverage).
//!
//! **Part 3 (this update) completes the arc: a usable KEM.** `Hqc128`/
//! `Hqc192`/`Hqc256` (thin `kem.Kem(params, generator)` instantiations)
//! expose `keypair`/`encaps`/`decaps` — see "Part 3" below. What follows
//! documents Part 1 (ring/PRNG foundation) for context.
//!
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
//! **Part 2 (this update) adds the concatenated Reed-Muller/Reed-Solomon
//! codec** (spec §3.4) — `gf256` (the GF(2^8) field), `reedsolomon` (the
//! outer [n1,k,delta] code), `reedmuller` (the inner duplicated RM(1,7)
//! code), and `code` (their concatenation: `encode`/`decode`). Every
//! ENCODE path is real and byte-exact-KAT'd against the reference; both
//! DECODE cores are now real implementations too (Fable pass):
//! `reedsolomon.RS(p,g).decode` (syndromes -> constant-time
//! Berlekamp-Massey -> Gao-Mateer additive-FFT root-finding -> Forney)
//! and `reedmuller.RM(p).decodeSymbol` (expand-and-sum -> fast Hadamard
//! transform -> find_peaks), exact ports of the v5.0.0 reference — see
//! `gate.zig` (`decoder_core_implemented = true`) and those functions'
//! doc comments. **This decoder pair is the genuinely Fable-hard core of
//! the whole HQC arc** (see SPEC.md's "Arc plan"), pinned by the
//! decode-correctness tests in `code_kat_test.zig` (zero-error round-trip,
//! at-capacity correction, exhaustive RM decode — across all three
//! parameter sets, including hqc-192/256's PARAM_FFT=5 radixBig path).
//!
//! **Part 3 adds `pke` (the HQC public-key encryption scheme) and `kem`
//! (the Fujisaki-Okamoto implicit-rejection KEM transform over `pke`)** —
//! spec §3.5/§4.2, reference `src/ref/hqc.c` + `src/common/kem.c`. This is
//! **pure Sonnet composition, confirmed no Fable-hard core**: every step
//! is direct wiring over Parts 1-2's already-real primitives (`gf2x.Ring`
//! for the ring arithmetic, `prng`'s samplers/I/G/H/J hashes, `code.Code`
//! for the error-correcting encode/decode) — no new algorithm is
//! introduced, same posture this repo's bn254 precompiles/Groth16
//! composition carried. Byte-exact against the official NIST KAT
//! (`kem_kat_test.zig` / `kat_vectors_kem.zig`: first 3 `count`s per
//! parameter set, pk/sk/ct/ss all verified, plus `decaps` on the genuine
//! ciphertext recovering the same `ss` — reproducing the reference's own
//! `main_kat.c` self-check). See `pke.zig`/`kem.zig`'s module docs for the
//! exact byte-layout and FO-transform details matched against the
//! reference (sampling order, hash domain wiring, the `vect_compare`
//! constant-time mask trick for implicit rejection).
//!
//! Provenance: `NOTICE` for the reference-implementation design
//! reference; SPEC.md for the exact spec version + KAT source + what's
//! pinned vs. self-tested.

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "HQC — code-based post-quantum KEM, NIST's structurally-independent backup to lattice-based ML-KEM. Complete keygen, encrypt, decrypt.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
/// GF(2^8), the field Part 2's Reed-Solomon layer operates over.
pub const gf256 = @import("gf256.zig");
/// The outer [n1,k,delta] Reed-Solomon code (encode + decode both real).
pub const reedsolomon = @import("reedsolomon.zig");
/// The inner duplicated RM(1,7) code (encode + decode both real).
pub const reedmuller = @import("reedmuller.zig");
/// The concatenated code C = RM ∘ RS (encode + decode both real; decode
/// composes the two real decoders above).
pub const code = @import("code.zig");
/// The Part-2 decoder-core gate (now `true`) — see gate.zig.
pub const gate = @import("gate.zig");
/// Part 3: the HQC public-key encryption scheme (pure composition over
/// gf2x/prng/code — no new algorithm, see pke.zig's module doc).
pub const pke = @import("pke.zig");
/// Part 3: the HQC-KEM Fujisaki-Okamoto (implicit-rejection) transform
/// over `pke` — the arc's top-level deliverable.
pub const kem = @import("kem.zig");

/// HQC-128 (NIST category 1) KEM — `keypair`/`encaps`/`decaps` plus every
/// byte size (`ek_bytes`/`dk_bytes`/`ct_bytes`/`ss_bytes`/`coins_bytes`).
/// Byte-exact against the official NIST KAT (`kem_kat_test.zig`).
pub const Hqc128 = kem.Kem(params.hqc128, reedsolomon.generator_hqc128);
/// HQC-192 (NIST category 3) KEM — see `Hqc128`.
pub const Hqc192 = kem.Kem(params.hqc192, reedsolomon.generator_hqc192);
/// HQC-256 (NIST category 5) KEM — see `Hqc128`.
pub const Hqc256 = kem.Kem(params.hqc256, reedsolomon.generator_hqc256);

test {
    // Dark-tests rule (CONVENTIONS.md §6.3): every submodule's tests must
    // be pulled in here, not just re-exported.
    _ = params;
    _ = gf2x;
    _ = prng;
    _ = @import("kat_test.zig");
    _ = gf256;
    _ = reedsolomon;
    _ = reedmuller;
    _ = code;
    _ = gate;
    _ = @import("code_kat_test.zig");
    _ = pke;
    _ = kem;
    _ = @import("kem_kat_test.zig");
}
