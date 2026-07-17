// SPDX-License-Identifier: MIT
//! gate — the switch that used to guard the one part a Phase-1 SCAFFOLD did
//! NOT ship: the **Groth16 prover core** (`prover.zig`'s `setup` toy-CRS
//! generation + `prove` proof assembly). **It is now `true` (Part 2 shipped):**
//! `setup`/`prove` are implemented and the end-to-end anchor
//! (`prove(setup(…)) → bn254.groth16Verify == true`, plus tamper/wrong-input/
//! non-satisfying-witness → `false`) runs green. The flag is retained as a
//! self-documenting marker of the scaffold→core boundary and the tier call.
//!
//! ## What IS real and ungated today (the harness has teeth without the core)
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
//!     REJECTS it, proving the end-to-end anchor has teeth before `prove`
//!     exists.
//!
//! ## Why this gate is an Opus flag, not a Fable flag
//!
//! The Groth16 prover core is **fully anchored** by a complete deterministic
//! oracle — the sibling `bn254` module's Groth16 VERIFIER. A correct prover's
//! output verifies; ANY wrong coefficient, index, sign, or randomizer makes
//! `bn254.groth16Verify` return `false`. There is no self-consistent-but-wrong
//! failure mode the verifier misses (unlike an FHE noise budget or a NIZK
//! soundness argument with no checking oracle). Published construction (Groth
//! 2016) + a complete anchor ⇒ this is **Opus**, not Fable. See `SPEC.md`'s
//! "Fable-vs-Opus tier call".
pub const prover_core_implemented = true;
