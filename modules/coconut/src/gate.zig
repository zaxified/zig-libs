// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising Coconut's
//! four gated cores (`credential.zig`'s `signPartial`,
//! `aggregateCredential`, `proveCredential`, `verifyCredential`). One
//! flag covers all four: they are mutually dependent — the
//! selective-disclosure NIZK (`proveCredential`/`verifyCredential`, the
//! genuinely Fable-hard part) can only be exercised over a valid
//! threshold-aggregated credential (`aggregateCredential`), which in turn
//! only exists once the authorities' `signPartial` produces partials, so
//! there is no intermediate state where an "easier" subset is done and
//! testable but the NIZK isn't (the same single-flag rationale `bbs`'s
//! `core_implemented` and `bulletproofs`' `core_implemented` document for
//! their own multi-core splits).
//!
//! Everything ELSE in this module is fully real today and needs no gate:
//! the pairing/curve plumbing over `bls12_381` (`params.zig`), the
//! Shamir threshold keygen + Lagrange-in-exponent verification-key
//! aggregation (`keys.zig`), the `lagrange.coefficientAtZero` helper
//! (`lagrange.zig`), the wire codecs, AND the two mechanical oracles
//! `psSignWithSecret` / `psVerifyPlain` (`credential.zig`) — a single
//! trusted-signer PS signature built from KNOWN scalars, and the PS
//! pairing-verify equation. That real half is what proves the harness has
//! teeth INDEPENDENT of whether the four cores are filled in yet: the
//! `BrokenCoconut` positive control (`harness_test.zig`) mechanically
//! mis-aggregates partial signatures (all-ones weights instead of the
//! Lagrange coefficients) and shows `psVerifyPlain` REJECTS the result
//! while the Lagrange-weighted aggregation is ACCEPTED — the pairing
//! check + Lagrange-in-exponent teeth are demonstrated with NO gated code
//! on the path.
//!
//! While this was `false` the four cores were `@panic("TODO(fable/core):
//! ...")` stubs and the gated tests in `harness_test.zig` reported **SKIP**
//! via `error.SkipZigTest` — a skip is not a green light. The function
//! signatures type-checked at every call site, so the cores' contracts
//! were frozen before the bodies existed (CONVENTIONS.md's "gate-flag /
//! dark-tests" convention, matching `bbs`/`dkg`/`bulletproofs`'
//! scaffold-then-implement discipline). The Fable pass has since
//! implemented the four cores per their per-function doc-comment contracts
//! in `credential.zig` and flipped this to `true`: the gated end-to-end
//! anchor (threshold-issue → aggregate → re-randomize →
//! selective-disclosure show → verify) and the NIZK-soundness rejection
//! tests are now executed assertions rather than skips.
pub const fable_core_implemented = true;
