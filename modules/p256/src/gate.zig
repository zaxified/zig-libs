// SPDX-License-Identifier: MIT

//! gate — the switches that select the **irreducible Fable cores** (two) and
//! the constant-time inversion (`fast_invert_implemented`, 2026-09-28). All
//! cores are IMPLEMENTED and every flag is `true`: the core-vs-portable
//! differential harness in `oracle_test.zig` is LIVE. The portable path —
//! byte-exact against `std.crypto.ecc.P256` + the ECDSA-P256 anchors — is the
//! correctness ORACLE and the permanent fallback for non-amd64 targets (and
//! for any build with a flag flipped back to `false`).
//!
//! ## The ungated substrate (the oracle + the harness with teeth)
//!
//! Everything outside the two cores below is portable and tested:
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
//!   - `scalar.zig` — the scalar field: std's fiat arithmetic wrapped, with
//!     this module's inverse (`modinv.zig`) — the inverse WAS on the critical
//!     path, 45 % of a signature, see SPEC "Scope". P-256 has NO
//!     efficiently-computable endomorphism, so — unlike k256 — there is no GLV
//!     decomposition here.
//!   - `kat_test.zig` / `oracle_test.zig` — the differential-vs-std harness, the
//!     official RFC 6979 ECDSA-P256 vectors, the std-signer ECDSA differential,
//!     and a deliberately-broken positive control (a wrong reduction constant)
//!     the harness flags RED.
//!
//! ## The two cut-lines (both IMPLEMENTED)
//!
//! ### 1. `field_asm_implemented` → the amd64 MULX/ADX field mul + square
//! (`fast_core.fieldMul` / `fast_core.fieldSq`). A `z = a·b mod p` over four
//! full 2^64 limbs using two independent carry chains (`ADCX`/`ADOX`) fed by
//! `MULX`, followed by the **NIST word-shuffle reduction** (the signed
//! s1+2s2+2s3+s4+s5−s6−s7−s8−s9 form over the 32-bit product words — see
//! `fast_core.zig`; its carry/borrow pattern is DISTINCT from k256's
//! tiny-constant fold). Its result type is the same `[4]u64` the portable
//! Solinas mul returns, so a wrong core cannot typecheck-and-silently-pass:
//! the differential compares limb-for-limb.
//!
//! ### 2. `fast_scalarmul_implemented` → the fast constant-time scalar multiplies
//! (`group.combMulBaseFast` — the fixed-base comb for `k·G`, the signing path —
//! and `group.mulCtWindowed` — the CT windowed variable-base for secret
//! scalars). P-256 has no endomorphism, so these are plain windowed forms with a
//! `blackBox`-guarded constant-time masked table scan (the k256 comb lesson),
//! NOT a GLV combine. Portable fallback: the proven constant-time double-and-add
//! (`group.mul` / `basePoint.mul`), which the differentials pin the cores to.
//!
//! ## Status: both cores live; the gated differentials run (they no longer skip
//! on amd64 builds). On a non-amd64 target the field differential still skips —
//! a skip there means "core not present on this build", never a green light.

/// Selects the amd64 `MULX/ADX` field multiply/square core
/// (`fast_core.fieldMul` / `fast_core.fieldSq`). IMPLEMENTED — the core is the
/// MULX/ADCX/ADOX schoolbook product + the NIST word-shuffle reduction, pinned
/// bit-for-bit to the portable Solinas oracle by the gated differential. On
/// non-amd64 targets the field still runs the portable reduction.
pub const field_asm_implemented = true;

/// Selects the fast constant-time scalar multiplies (`group.combMulBaseFast`
/// fixed-base comb + `group.mulCtWindowed` variable-base). IMPLEMENTED — both
/// use the `blackBox`-guarded masked linear table scan and are pinned to the
/// portable double-and-add ladder + std by the gated differentials. Flipping
/// back to `false` restores the plain constant-time double-and-add fallbacks.
pub const fast_scalarmul_implemented = true;

/// Selects the constant-time safegcd inversion (`modinv.zig`, Bernstein–Yang
/// divsteps in 62-bit batches) for BOTH `Fe.invert` (base field) and
/// `Scalar.invert` (scalar field). Portable (no asm), so it is on for every
/// target. Flipping back to `false` restores the two oracles the differentials
/// pin it to: the Fermat inverse `a^(p−2)` (`Fe.invertFermat`) and std's fiat
/// scalar inverse. Measured 2026-09-28 on the i7-7920HQ: Fe.invert 12.1 µs →
/// ~3 µs, Scalar.invert 40.7 µs → ~3 µs (see SPEC "Performance status").
pub const fast_invert_implemented = true;
