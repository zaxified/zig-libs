// SPDX-License-Identifier: MIT

//! gate — the two switches that select the **irreducible Fable cores** this
//! SCAFFOLD phase deliberately did NOT ship. Both default to `false`, so every
//! operation runs on the portable oracle path (which is byte-exact against
//! `std.crypto.ecc.Secp256k1` + the official BIP340 vectors) until a Fable agent
//! fills the core and flips the flag, at which point the corresponding
//! core-vs-portable differential harness lights up.
//!
//! ## What is REAL and ungated today (the oracle + the harness with teeth)
//!
//! Everything except the two cores below is implemented and tested:
//!   - `field.zig` — the secp256k1 base field `Fe` over `p = 2^256 − 2^32 − 977`,
//!     with the special-prime (Solinas) reduction written straightforwardly on
//!     wide integers, plus add/sub/neg/inv/sqrt/codecs. Byte-exact vs
//!     `std.crypto.ecc.Secp256k1.Fe` on thousands of random inputs.
//!   - `group.zig` — the curve group (homogeneous-projective complete formulas,
//!     the same Renes–Costello–Batina algorithms std uses), the constant-time
//!     `mul`, and the variable-time `mulPublic` / `mulDoubleBasePublic` that the
//!     verifier uses. Byte-exact vs std at the point level.
//!   - `scalar.zig` — the scalar field (re-exported from std; NOT on the accel
//!     critical path, see SPEC "Dedup / scope") plus the REAL, tested GLV
//!     balanced decomposition `splitScalar` (its lattice constants diffed
//!     against std's `Endormorphism.splitScalar`) — the reference the gated GLV
//!     scalarmul builds on.
//!   - `kat_test.zig` / `oracle_test.zig` — the differential-vs-std harness, the
//!     official BIP340 vectors, and a deliberately-broken positive control (a
//!     wrong reduction constant) the harness flags RED.
//!
//! ## The two cut-lines (what the Fable agent fills)
//!
//! ### 1. `field_asm_implemented` → the amd64 MULX/ADX field mul + square
//! (`fast_core.fieldMul` / `fast_core.fieldSq`). A `z = a·b mod p` over four
//! full 2^64 limbs using two independent carry chains (`ADCX`/`ADOX`) fed by
//! `MULX`, followed by the special-prime fold (high limbs × `2^32+977`) — the
//! single biggest and most curve-specific win. Its result type is the same
//! `[4]u64` the portable Solinas mul returns, so a wrong core cannot
//! typecheck-and-silently-pass: the differential compares limb-for-limb.
//!
//! ### 2. `glv_scalarmul_implemented` → the GLV variable-base scalarmul
//! (`group.mulPublicGlv`). Split `k = k1 + k2·λ` via `scalar.splitScalar`
//! (already REAL + tested here), map `P ↦ (β·x, y)` for the `λ`-multiple, and
//! combine the two half-length multiplies with interleaved wNAF — ~40% fewer
//! doublings for verification. Portable fallback: the plain double-and-add
//! `mulPublic`, which the differential pins it to.
//!
//! ## Status: SCAFFOLD — both cores GATED OFF.
//!
//! A skip in the differential harness is NOT a green light; it means the core is
//! not yet implemented and dispatch is on the proven portable oracle.

/// Selects the amd64 `MULX/ADX` field multiply/square core
/// (`fast_core.fieldMul` / `fast_core.fieldSq`). While `false`, the field runs
/// the portable Solinas reduction on every target.
pub const field_asm_implemented = false;

/// Selects the GLV-decomposition variable-base scalarmul
/// (`group.mulPublicGlv`). While `false`, `mulPublic` runs the plain
/// double-and-add fallback.
pub const glv_scalarmul_implemented = false;
