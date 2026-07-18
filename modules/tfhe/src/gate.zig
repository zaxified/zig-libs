// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising this module's
//! gated **Fable core**: the programmable gate-bootstrapping arithmetic.
//!
//! TFHE ships its ENTIRE mechanical layer REAL and tested — the negacyclic ring
//! (`poly`), the signed gadget decomposition (`gadget`), torus (de)coding and
//! modulus switching (`torus`), and, in `tfhe.zig`, LWE/GLWE/GGSW keygen /
//! encrypt / decrypt, bootstrap-key and key-switch-key generation, sample
//! extraction, LWE key switching, and the cleartext LUT + rotation reference
//! (`clearBootstrap`). The four irreducible, soundness-bearing functions are
//! scaffolded behind this flag:
//!
//!   • `externalProduct` (GGSW ⊠ GLWE) — decompose the input GLWE and dot with
//!     the GGSW rows; the noise-growth heart of TFHE.
//!   • `cmux` — the encrypted selector `d0 + C ⊠ (d1 − d0)`.
//!   • `blindRotate` — the accumulator loop of `n` CMux over the bootstrap key
//!     (the X^{ã_i} exponents and the initial X^{−b̃} rotation live here — the
//!     classic off-by-one/​sign hazard).
//!   • `bootstrap` — mod-switch → blind-rotate → sample-extract → key-switch,
//!     producing a FRESH low-noise LWE encrypting the programmed LUT of the
//!     input. This is what makes depth unbounded.
//!
//! There is NO external byte-exact KAT for these (TFHE-rs / OpenFHE-binfhe /
//! concrete all differ in encoding and params), so a self-consistent-but-wrong
//! core can pass a naive round-trip. The harness defends with: a mechanical
//! cleartext blind-rotation oracle (`clearBootstrap`) that pins the LUT +
//! rotation indexing WITHOUT the core; deliberately-broken positive controls
//! (wrong sample-extract sign, dropped-level gadget, wrong rotation sign) that
//! PASS today; and — once this flag flips — an unlimited-depth bootstrap chain,
//! a corrupted-bootstrap-key control, and an output-noise-budget assertion.
//!
//! While `false`, the four cores `@panic` and the dependent tests report SKIP
//! (a skip is NOT a green light) — the same convention as `bfv`/`fss`/`coconut`.

/// The genuine Fable core: externalProduct / cmux / blindRotate / bootstrap.
pub const fable_core_implemented = false;
