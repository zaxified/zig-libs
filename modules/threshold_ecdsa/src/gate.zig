// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the Πprm/Πmod
//! zero-knowledge proof-of-correct-generation CORES
//! (`aux_proofs.Piprm.prove`/`.verify`, `aux_proofs.Pimod.prove`/`.verify`).
//! Those four functions are the two irreducible ZK-proof number-theory
//! cores this scaffold pass deliberately leaves `@panic`-stubbed (CGGMP21
//! ePrint 2021/060 Fig.16 "Πmod" / Fig.17 "Πprm" — see each stub's own doc
//! comment for the exact construction a follow-up crypto pass must
//! transcribe). Mirrors `bn254`'s `gate.zig` / `df-elect`'s `gate.zig`
//! scaffold-then-implement pattern (CONVENTIONS.md's "gate-flag/dark-tests"
//! convention).
//!
//! While this is `false`: `aux_proofs.zig`'s proof-core-dependent tests
//! (completeness, the two F1-soundness "Πprm/Πmod REJECTS" halves, and the
//! tamper tests) report **SKIP** (via `error.SkipZigTest`), not PASS — a
//! skip is not a green light. Everything else in `aux_proofs.zig` —
//! `PrmProof`/`ModProof`'s struct shapes and byte codecs, the
//! `AuxTrapdoor` plumbing (`root.zig`), the Fiat-Shamir transcript wiring
//! (`deriveModChallenge`/`derivePrmChallengeBits`), and the "validate()
//! ACCEPTS a crafted param" half of both F1-soundness scenarios — is REAL
//! and ungated, proving the harness has teeth independent of the two
//! stubbed cores.
//!
//! The follow-up crypto pass implemented ONLY `Piprm.prove`/`.verify` and
//! `Pimod.prove`/`.verify`, then flipped this to `true` (converting every
//! gated SKIP into a real, executed assertion) — same flip `bn254`'s
//! `pairing_core_implemented` and `df-elect`'s election-decide gate
//! document.
pub const aux_proofs_core_implemented = true;
