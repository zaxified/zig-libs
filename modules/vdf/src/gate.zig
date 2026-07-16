// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising `vdf.zig`'s
//! two Fable-hard cores: `prove` (the efficient/streaming Wesolowski
//! prover) and `verify` (the `π^l * x^r == y (mod N)` soundness check).
//! Both are now REAL — see each function's implementation + doc comment
//! in `vdf.zig`.
//!
//! Everything ELSE in this module — `group.zig`'s Z_N* wrapper + element
//! validation + the RSA-2048 Factoring Challenge modulus, `vdf.zig`'s
//! `eval` (the sequential delay itself), `hashToPrime` (the Fiat-Shamir
//! challenge-prime derivation, including its Miller-Rabin primality test),
//! `pow2Mod` (the mechanical half of `verify`'s check), and `Proof`'s byte
//! codec — is fully real today and needs no gate; it is what proves the
//! harness in `kat_test.zig` has teeth independent of whether `prove`/
//! `verify` are filled in yet.
//!
//! One flag covers both `prove` and `verify`: `verify`'s completeness
//! tests cannot run without `prove` already producing a real proof to feed
//! them (there is no intermediate state where one is done and the other
//! isn't testable), so splitting this into two flags would only add
//! bookkeeping — same reasoning as `bulletproofs`'s `gate.zig`.
//!
//! This is `true`: the completeness/soundness tests in `kat_test.zig` that
//! call `prove`/`verify` RUN (and pass). The flag remains as the single
//! switch it always was — were it `false`, those tests would report
//! **SKIP** (via `error.SkipZigTest`), never PASS, since a skip is not a
//! green light; it is `true` now that `vdf.zig`'s `prove`/`verify` are
//! real, not `@panic` stubs.
pub const core_implemented = true;
