// SPDX-License-Identifier: MIT

//! gate — the two switches that select the **irreducible Fable cores**. This
//! SCAFFOLD ships both as `false` (portable oracle everywhere); a later Fable
//! core phase fills each core and flips its flag, at which point the
//! core-vs-portable differential harness in `oracle_test.zig` goes LIVE. The
//! portable path — byte-exact against `std.crypto.ecc.P256` + the ECDSA-P256
//! anchors — is the correctness ORACLE and the permanent fallback for non-amd64
//! targets (and for any build with a flag left `false`).
//!
//! ## What is REAL and ungated today (the oracle + the harness with teeth)
//!
//! Everything except the two cores below is implemented and tested:
//!   - `field.zig` — the P-256 base field `Fe` over
//!     `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`, with the special-prime (Solinas)
//!     reduction (`2^256 ≡ 2^224 − 2^192 − 2^96 + 1`) written straightforwardly
//!     on wide integers, plus add/sub/neg/inv/sqrt/codecs. Byte-exact vs
//!     `std.crypto.ecc.P256.Fe` on thousands of random inputs.
//!   - `group.zig` — the curve group (`a = −3`; the RCB complete formulas std
//!     uses — Algorithm 6 doubling, Algorithm 4 addition), the constant-time
//!     `mul`, the fixed-base `combMulBase`, and the variable-time `mulPublic` /
//!     `mulDoubleBasePublic` the verifier uses. Byte-exact vs std at the point
//!     level.
//!   - `scalar.zig` — the scalar field (re-exported from std; NOT on the accel
//!     critical path, see SPEC "Scope"). P-256 has NO efficiently-computable
//!     endomorphism, so — unlike k256 — there is no GLV decomposition here.
//!   - `kat_test.zig` / `oracle_test.zig` — the differential-vs-std harness, the
//!     official RFC 6979 ECDSA-P256 vectors, the std-signer ECDSA differential,
//!     and a deliberately-broken positive control (a wrong reduction constant)
//!     the harness flags RED.
//!
//! ## The two cut-lines (both a `@panic("TODO(fable/core)")` stub today)
//!
//! ### 1. `field_asm_implemented` → the amd64 MULX/ADX field mul + square
//! (`fast_core.fieldMul` / `fast_core.fieldSq`). A `z = a·b mod p` over four
//! full 2^64 limbs using two independent carry chains (`ADCX`/`ADOX`) fed by
//! `MULX`, followed by the P-256 Solinas fold (high limbs × `M = 2^224 − 2^192 −
//! 2^96 + 1`). This is the single biggest and most curve-specific win, and its
//! carry pattern is DISTINCT from k256's tiny-constant fold — see SPEC. Its
//! result type is the same `[4]u64` the portable Solinas mul returns, so a wrong
//! core cannot typecheck-and-silently-pass: the differential compares
//! limb-for-limb.
//!
//! ### 2. `fast_scalarmul_implemented` → the fast constant-time scalar multiplies
//! (`group.combMulBaseFast` — the fixed-base comb for `k·G`, the signing path —
//! and `group.mulCtWindowed` — the CT windowed variable-base for secret
//! scalars). P-256 has no endomorphism, so these are plain windowed forms with a
//! `blackBox`-guarded constant-time masked table scan (the k256 comb lesson),
//! NOT a GLV combine. Portable fallback: the proven constant-time double-and-add
//! (`group.mul` / `basePoint.mul`), which the differentials pin the cores to.
//!
//! ## Status: SCAFFOLD — both cores are panic stubs, both flags `false`.
//!
//! Dispatch therefore takes the proven portable oracle everywhere; a skip in the
//! gated differential harness is NOT a green light for a core — it means the
//! core is not present on this build.

/// Selects the amd64 `MULX/ADX` field multiply/square core
/// (`fast_core.fieldMul` / `fast_core.fieldSq`). While `false` (this scaffold),
/// the field runs the portable Solinas reduction on every target.
pub const field_asm_implemented = false;

/// Selects the fast constant-time scalar multiplies (`group.combMulBaseFast`
/// fixed-base comb + `group.mulCtWindowed` variable-base). While `false` (this
/// scaffold), the secret-scalar multiplies run the plain constant-time
/// double-and-add fallbacks.
pub const fast_scalarmul_implemented = false;
