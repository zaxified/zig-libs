// SPDX-License-Identifier: MIT

//! gate — the single switch that selects the **irreducible asm core** this
//! SCAFFOLD phase deliberately did NOT ship: the amd64
//! `MULX/ADCX/ADOX` dual-carry-chain CIOS Montgomery multiply
//! (`asm_core.montMul`), the one piece that reaches OpenSSL-competitive speed.
//!
//! ## What is REAL and ungated today (the oracle + the harness with teeth)
//!
//! Everything except the asm inner loop is implemented and tested:
//!   - `limbs.zig` — full radix-2^64 add/sub/compare + schoolbook & Karatsuba
//!     full-products (mutually cross-checked).
//!   - `montint.zig` — the PORTABLE constant-time CIOS Montgomery multiply,
//!     `toMontgomery`/`fromMontgomery`, modular `add`/`sub`/`mul`, and the
//!     constant-time 5-bit-window `powMont` modexp. This portable path is the
//!     **correctness ORACLE**: it is byte-exact against an independent
//!     CPython-bignum reference (`kat_vectors.zig`) at 256/512/2048/4096 bits.
//!   - `kat_test.zig` — the KAT-vs-oracle checks, a deliberately-broken
//!     positive control (`brokenMontMul`, drops the final conditional subtract)
//!     that the harness flags RED, and the **asm-vs-portable differential**
//!     (thousands of random `(a,b,odd-N)`), which is the anti-self-consistency
//!     anchor: the asm core MUST reproduce the proven-vs-CPython portable path
//!     bit-for-bit.
//!
//! ## The cut-line (what the Fable agent fills)
//!
//! `asm_core.montMul(z, a, b, m, n0inv)` — a `z = a·b·R⁻¹ mod m` Montgomery
//! multiply over `n = m.len` full 2^64 limbs, using two independent carry
//! chains (`ADCX` for the add chain, `ADOX` for the mul-carry chain) fed by
//! `MULX`, exactly the `x86_64-mont5.pl` technique. Its result type is the same
//! `[]u64` the portable CIOS returns, so a wrong core cannot typecheck-and-pass:
//! the differential harness compares limb-for-limb against the oracle.
//!
//! ## Status: IMPLEMENTED (Fable core phase)
//!
//! The amd64 core is filled in (`asm_core.zig`): Zig CIOS outer loop mirroring
//! the portable oracle word-for-word + inline-asm dual-carry-chain row
//! primitives (4-limb-unrolled main loop, remainder loop, CF preserved across
//! `dec`-driven loop control, OF folded into the pending-hi limb). With this
//! flag `true` the dispatcher routes to the asm core on
//! x86-64+ADX+BMI2 targets and the asm-vs-portable differential test is LIVE.
pub const asm_core_implemented = true;
