// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the one
//! Fable-irreducible core of this module: the **correction-word
//! construction**, i.e. `dpf.zig`'s `genWithSeeds` (the per-level seed-CW +
//! two control-bit-CWs derivation that keeps the two parties' seeds EQUAL
//! off the α-path and pseudorandomly DIFFERENT on it, plus the final output
//! correction word) and the matching traversal `eval`. One wrong CW bit and
//! the shares either fail to reconstruct or leak α — this is the classic FSS
//! hard part (Boyle–Gilboa–Ishai, CCS 2016, Fig. 1), and it is the only
//! thing behind this flag.
//!
//! **IMPLEMENTED (Fable pass):** `genWithSeeds`/`eval` are real; this flag is
//! `true`, so every formerly-SKIPped test in `kat_test.zig` — full-domain
//! exhaustive reconstruction, the byte-exact KAT vs the INDEPENDENT Python
//! re-derivation in `kat_vectors.zig` (the anti-self-consistency anchor, see
//! SPEC.md), the security smell test, and the CW-perturbation positive
//! control — now runs as an executed assertion. While it was `false`, the
//! cores `@panic`'d and those tests reported SKIP (a skip is NOT a green
//! light). Same convention as `bulletproofs`/`bn254`/`decaf448`/
//! `threshold_ecdsa`.
//!
//! Everything ELSE in this module is REAL and UNGATED today, proving the
//! harness has teeth independent of the gated core:
//!   - `prg.zig` — both length-doubling PRGs `G` (`Aes128Mmo`, the default,
//!     and `Sha256Prg`) and `convert`.
//!   - `group.zig` — the Z_{2^{8L}} output-group arithmetic.
//!   - `dpf.zig`'s `Key` struct + `serializeCw`/byte codec.
//!   - `kat_test.zig`'s DELIBERATELY-BROKEN positive controls
//!     (`brokenAllBeta`/`brokenAllZero`, built WITHOUT the real core) and the
//!     pure `firstMismatch` full-domain checker they exercise — these run and
//!     PASS today, proving the checker rejects non-DPF share pairs before the
//!     real core even exists.
pub const core_implemented = true;
