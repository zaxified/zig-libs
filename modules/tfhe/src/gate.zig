// SPDX-License-Identifier: MIT

//! gate — the switch for the tests that exercise the gate-bootstrapping
//! arithmetic of this module.
//!
//! TFHE ships its ENTIRE mechanical layer REAL and tested — the negacyclic ring
//! (`poly`), the signed gadget decomposition (`gadget`), torus (de)coding and
//! modulus switching (`torus`), and, in `tfhe.zig`, LWE/GLWE/GGSW keygen /
//! encrypt / decrypt, bootstrap-key and key-switch-key generation, sample
//! extraction, LWE key switching, and the cleartext LUT + rotation reference
//! (`clearBootstrap`). The four soundness-bearing functions behind this flag are:
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
//! `interop_test.zig` holds the bootstrap byte-identical to tfhe-rs's on
//! tfhe-rs's own keys and ciphertexts, the external anchor a self-consistent-
//! but-wrong core cannot pass. The harness (`harness_test.zig`) adds a
//! mechanical cleartext blind-rotation oracle (`clearBootstrap`) that pins the
//! LUT + rotation indexing WITHOUT the core; deliberately-broken positive
//! controls (wrong sample-extract sign, dropped-level gadget, wrong rotation
//! sign); an unlimited-depth bootstrap chain, a corrupted-bootstrap-key
//! control, and an output-noise-budget assertion.
//!
//! The flag is `true`: the four cores are implemented, and every gated test —
//! the programmable gate, the 2-input AND, the unlimited-depth bootstrap
//! chain, the corrupted-bootstrap-key control, and the noise-budget
//! assertion — runs and passes. Were it `false`, the dependent tests would
//! report SKIP (a skip is NOT a green light), the same convention as
//! `bfv`/`fss`/`coconut`.

/// The bootstrapping core: externalProduct / cmux / blindRotate / bootstrap.
/// Implemented — see this file's module doc comment.
pub const fable_core_implemented = true;
