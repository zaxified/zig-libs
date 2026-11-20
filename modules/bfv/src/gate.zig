// SPDX-License-Identifier: MIT

//! gate — the switches for the tests exercising this module's scheme layer.
//! The arithmetic backbone (`modarith`/`ntt`/`rns`/`ring`/`encode`/`params`) is
//! ungated; the scheme layer (`bfv.zig`) has TWO flags, because its two halves
//! are anchored differently (see SPEC.md):
//!
//!   • `scheme_core_implemented` — `keyGen` / `encrypt` / `decrypt` / `add`.
//!     Textbook leveled-BFV over the RNS ring. What is checked is
//!     `Dec(Enc(x)) == x` and the additive homomorphic property against this
//!     module's own plaintext-space reference (`encode.addRef`) plus a
//!     deterministic noiseless-ciphertext KAT; no external (SEAL) vectors are
//!     checked in (`modules/bfv/data/` is empty).
//!
//!   • `fable_core_implemented` — `mul` (ciphertext tensoring + the
//!     `⌊t/q·…⌉` RNS rescale) + `relinearize` (relin-key key-switch back to a
//!     2-element ciphertext) + `noiseBudget`. This is where self-consistent
//!     tests can pass while noise is silently mismanaged — a multiply that
//!     "works" for tiny inputs but whose noise growth is wrong and fails at
//!     depth, or a key-switch that decrypts subtly wrong. It is anchored by
//!     the mul+relin and multiply-depth end-to-end tests under a worst-case
//!     noise ledger (see SPEC.md). (The flag keeps its historical name.)
//!
//! Multiply/relin tests depend on encrypt/decrypt, so they gate on BOTH flags.
//! A test whose flag is `false` reports SKIP (a skip is NOT a green light) —
//! the same convention as `fss`/`dkg`/`coconut`.
//!
//! Everything the arithmetic backbone tests, plus the DELIBERATELY-BROKEN
//! positive controls in `kat_test.zig` (a cyclic-instead-of-negacyclic NTT and
//! a wrong-scale "encryptor"), is ungated and PASSES — proving the harness has
//! teeth independent of the scheme cores.

/// keyGen / encrypt / decrypt / add.
pub const scheme_core_implemented = true;

/// mul / relinearize / noiseBudget.
pub const fable_core_implemented = true;
