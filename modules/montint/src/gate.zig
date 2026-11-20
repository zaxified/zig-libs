// SPDX-License-Identifier: MIT

//! gate — the switch for the amd64 asm core: the `MULX/ADCX/ADOX`
//! dual-carry-chain CIOS Montgomery multiply (`asm_core.zig`), the piece that
//! reaches OpenSSL-competitive speed.
//!
//! The flag is `true`: on x86-64+ADX+BMI2 targets the dispatcher routes
//! `montMul`/`montSqr` to the asm kernels (see `fixed_min_limbs` in
//! `montint.zig`) and the asm-vs-portable differential test runs for real.
//! The asm kernels are a Zig CIOS outer loop mirroring the portable oracle
//! word-for-word plus inline-asm dual-carry-chain row primitives (CF
//! preserved across the `dec`-driven loop control, OF folded into the
//! pending-hi limb).
//!
//! Everything else is ungated and is the correctness anchor of the asm path:
//!   - `limbs.zig` — radix-2^64 add/sub/compare + schoolbook & Karatsuba
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
pub const asm_core_implemented = true;
