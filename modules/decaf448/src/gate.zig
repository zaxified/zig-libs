// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the four
//! irreducible decaf448 field-math cores (`element.zig`'s `sqrtRatioM1`,
//! `Element.encode`, `Element.decode`, and `mapToElement` — RFC 9496
//! §5.2/§5.3.1/§5.3.2/§5.3.4's irreducible decaf-specific formulas; see
//! each core's own doc comment for the exact construction). The scaffold
//! pass left these `@panic`-stubbed behind this flag; a Fable pass then
//! implemented all four and flipped the flag to `true`. Mirrors `ed448`'s
//! sibling scaffold-then-implement modules (`bn254`'s `gate.zig`,
//! `df-elect`'s `gate.zig`, `pping`'s `gate.zig`) — CONVENTIONS.md's
//! "gate-flag/dark-tests" convention.
//!
//! Now that this is `true`: `kat_test.zig`'s core-dependent tests (RFC 9496
//! Appendix B.1 byte-exact encode of `[0]G..[15]G`, the decode round-trip
//! half of that same suite, B.2's 21 invalid-encoding rejections, and B.3's
//! 7 element-derivation/`oneWayMap` vectors) all RUN and PASS (byte-exact),
//! rather than reporting **SKIP** (via `error.SkipZigTest`) as they did
//! while the flag was `false`.
//!
//! Everything ELSE in this module is REAL and UNGATED today, proving the
//! harness has teeth independent of the four stubbed cores:
//!   - `Element`'s group-op layer (`add`/`sub`/`negate`/`scalarMul`,
//!     `identity`/`generator`, `equals`) — these are mechanical wrappers
//!     around `ed448`'s already-real, already-KAT-validated `Point`
//!     arithmetic, and RFC 9496 §5.3.1's B.1 vector's own recipe ("each
//!     successive entry is obtained by adding the generator to the
//!     previous entry") is itself exercised group-law-only, via repeated
//!     `Element.add`, without needing `encode` at all.
//!   - `Scalar`'s 56-byte <-> `ed448.scalar`'s 57-byte wire-width
//!     conversion (RFC 9496 §5.4 vs RFC 8032 §5.2's differing scalar
//!     container widths for the SAME underlying order `l` = `L`).
//!   - `D`/`ONE_MINUS_D`/`ONE_MINUS_TWO_D`/`SQRT_MINUS_D`/
//!     `INVSQRT_MINUS_D` (RFC 9496 §5.1's implementation constants) —
//!     hardcoded from the RFC's decimal values and cross-checked at
//!     comptime/test time against their defining relations
//!     (`SQRT_MINUS_D^2 == -D`, `SQRT_MINUS_D * INVSQRT_MINUS_D == 1`) —
//!     these are PLAIN NUMBERS, not derived by any square-root computation
//!     of this module's own, so declaring and self-checking them needs no
//!     Fable core.
//!
//! The crypto pass implemented ONLY `sqrtRatioM1`, `Element.encode`,
//! `Element.decode`, and `mapToElement`, then flipped this to `true`
//! (converting every gated SKIP into a real, executed assertion) — same
//! flip `bn254`'s `pairing_core_implemented` and `df-elect`'s election
//! gate document.
pub const core_implemented = true;
