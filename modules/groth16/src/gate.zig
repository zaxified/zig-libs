// SPDX-License-Identifier: MIT
//! gate — the marker for the **Groth16 prover core** (`prover.zig`'s `setup`
//! toy-CRS generation + `prove` proof assembly). It is the constant `true`:
//! `setup`/`prove` are implemented and the end-to-end anchor
//! (`prove(setup(…)) → bn254.groth16Verify == true`, plus tamper/wrong-input/
//! non-satisfying-witness → `false`) runs unconditionally. The flag is kept so
//! tests and docs can name the prover core.
//!
//! ## What the harness is built from
//!
//! Everything feeding the prover is implemented and heavily anchored:
//!   - `field.zig` — `Fr` helpers over the sibling `bn254` scalar field.
//!   - `poly.zig` — dense `Fr[x]` arithmetic + division by the vanishing
//!     polynomial `Z(x) = x^n − 1`.
//!   - `domain.zig` — the radix-2 evaluation domain (`n`-th roots of unity
//!     over `Fr`, `n | r−1`, 2-adicity 28).
//!   - `fft.zig` — the radix-2 NTT / inverse-NTT over `Fr` and FFT-based
//!     polynomial multiplication (round-trip + `== schoolbook` anchored).
//!   - `msm.zig` — naive multi-scalar multiplication in `G1`/`G2`.
//!   - `r1cs.zig` — the rank-1 constraint system + witness satisfaction.
//!   - `qap.zig` — R1CS→QAP interpolation + the divisibility oracle
//!     (`A·B−C` is divisible by `Z` iff the witness satisfies the R1CS).
//!   - `prover.zig`'s DELIBERATELY-BROKEN positive control (`brokenProof`,
//!     built WITHOUT the real core) — the sibling `bn254.groth16Verify`
//!     REJECTS it, proving the end-to-end anchor has teeth.
//!
//! ## Why the core is anchored
//!
//! The Groth16 prover core is **fully anchored** by a complete deterministic
//! oracle — the sibling `bn254` module's Groth16 VERIFIER. A correct prover's
//! output verifies; ANY wrong coefficient, index, sign, or randomizer makes
//! `bn254.groth16Verify` return `false`. There is no self-consistent-but-wrong
//! failure mode the verifier misses. The construction is the published one
//! (Groth 2016).
pub const prover_core_implemented = true;
