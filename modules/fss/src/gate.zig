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
//! While this is `false`, `genWithSeeds`/`eval` (and therefore `evalAll`,
//! which is a mechanical loop over `eval`) `@panic("TODO(fable/core): ...")`,
//! and every `kat_test.zig` test that calls them reports **SKIP**
//! (`error.SkipZigTest`) — a skip is NOT a green light. A Fable pass then
//! implements the two cores to reproduce the byte-exact vectors in
//! `kat_vectors.zig` (derived from an INDEPENDENT Python re-derivation of the
//! same construction, see SPEC.md) and flips this to `true`, converting every
//! gated SKIP into a real, executed assertion. Same convention as
//! `bulletproofs`/`bn254`/`decaf448`/`threshold_ecdsa`.
//!
//! Everything ELSE in this module is REAL and UNGATED today, proving the
//! harness has teeth independent of the gated core:
//!   - `prg.zig` — the SHA-256 length-doubling PRG `G` and `convert`.
//!   - `group.zig` — the Z_{2^{8L}} output-group arithmetic.
//!   - `dpf.zig`'s `Key` struct + `serializeCw`/byte codec.
//!   - `kat_test.zig`'s DELIBERATELY-BROKEN positive controls
//!     (`brokenAllBeta`/`brokenAllZero`, built WITHOUT the real core) and the
//!     pure `firstMismatch` full-domain checker they exercise — these run and
//!     PASS today, proving the checker rejects non-DPF share pairs before the
//!     real core even exists.
pub const core_implemented = false;
