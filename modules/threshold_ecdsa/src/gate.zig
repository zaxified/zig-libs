// SPDX-License-Identifier: MIT

//! gate — the switch for the tests that exercise the Πprm/Πmod
//! zero-knowledge proof-of-correct-generation CORES
//! (`aux_proofs.Piprm.prove`/`.verify`, `aux_proofs.Pimod.prove`/`.verify`;
//! CGGMP21 ePrint 2021/060 Fig.16 "Πmod" / Fig.17 "Πprm").
//!
//! The flag is `true`: the four cores are implemented, so every
//! proof-core-dependent test in `aux_proofs.zig` (completeness, the two
//! F1-soundness "Πprm/Πmod REJECTS" halves, the tamper tests) executes real
//! assertions. Were it set to `false` those tests would report SKIP
//! (`error.SkipZigTest`), which is not a green light; everything else in
//! `aux_proofs.zig` (the `PrmProof`/`ModProof` byte codecs, the
//! `AuxTrapdoor` plumbing, the Fiat-Shamir transcript wiring, the
//! "validate() ACCEPTS a crafted param" half of both F1-soundness
//! scenarios) is ungated.
pub const aux_proofs_core_implemented = true;
