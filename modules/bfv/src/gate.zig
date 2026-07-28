// SPDX-License-Identifier: MIT

//! gate — the switches that turn on the tests exercising this module's gated
//! scheme layer. BFV Part 1 ships the ENTIRE arithmetic backbone real
//! (`modarith`/`ntt`/`rns`/`ring`/`encode`/`params`) and scaffolds the scheme
//! layer (`bfv.zig`) behind TWO honestly-separated flags, because the two
//! halves of the scheme are DIFFERENT tiers (see SPEC.md "Fable boundary"):
//!
//!   • `scheme_core_implemented` — Part 2, **Opus tier**: `keyGen` / `encrypt`
//!     / `decrypt` / `add`. Textbook leveled-BFV over the (already real) RNS
//!     ring; the construction is KAT-**able** byte-exact against Microsoft
//!     SEAL in principle (small fix-space, deterministic feedback), which is
//!     why a careful non-Fable pass could land it — but no SEAL vectors have
//!     actually been produced or checked in (`modules/bfv/data/` is empty).
//!     What IS checked today is `Dec(Enc(x)) == x` and the additive
//!     homomorphic property against this module's own plaintext-space
//!     reference (`encode.addRef`), not an external oracle. The decrypt
//!     `⌊t/q·(c0+c1·s)⌉` rounding is the only noise-adjacent piece here, and
//!     even it has no external anchor actually in place yet.
//!
//!   • `fable_core_implemented` — Part 3, **genuine Fable tier**: `mul`
//!     (ciphertext tensoring + the `⌊t/q·…⌉` RNS rescale) + `relinearize`
//!     (relin-key key-switch back to a 2-element ciphertext) + `noiseBudget`.
//!     This is where self-consistent tests can pass while noise is silently
//!     mismanaged — a multiply that "works" for tiny inputs but whose noise
//!     growth is wrong and fails at depth, or a key-switch that decrypts
//!     subtly wrong. No simple anchor bounds the hard part. (See SPEC.md.)
//!
//! Multiply/relin tests depend on encrypt/decrypt existing, so they gate on
//! BOTH flags. While a flag is `false`, its cores `@panic` and the dependent
//! tests report SKIP (a skip is NOT a green light) — the same convention as
//! `fss`/`dkg`/`coconut`.
//!
//! Everything the arithmetic backbone tests, plus the DELIBERATELY-BROKEN
//! positive controls in `kat_test.zig` (a cyclic-instead-of-negacyclic NTT and
//! a wrong-scale "encryptor"), is REAL and UNGATED today and PASSES — proving
//! the harness has teeth before either scheme core exists.

/// Part 2 (Opus): keyGen / encrypt / decrypt / add.
pub const scheme_core_implemented = true;

/// Part 3 (Fable): mul / relinearize / noiseBudget.
pub const fable_core_implemented = true;
