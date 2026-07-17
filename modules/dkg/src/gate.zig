// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real,
//! stub-backed GJKR distributed-key-generation CORE (`core.zig`'s five
//! irreducible protocol-soundness functions: `verifyPedersenShare`,
//! `verifyFeldmanShare`, `computeQual`, `deriveGroupPublicKey`, and
//! `combineKeyShare`). Those five are the bias-prevention / Byzantine-
//! detection kernel this scaffolding pass deliberately leaves
//! `@panic`-stubbed — see each stub's doc comment in `core.zig` for the
//! exact GJKR construction a follow-up crypto pass must transcribe.
//!
//! Everything ELSE in this module is fully real today and needs no gate:
//! the mechanical Pedersen/Feldman commitment helpers (`commit.zig`), the
//! wire codecs (`types.zig`), the synchronous round driver's plumbing and
//! the self-contained `BrokenDkg` positive control (`protocol.zig`), and
//! the invariant checkers (`checks.zig`). That real half is the proof the
//! harness has teeth INDEPENDENT of whether the DKG core is filled in yet:
//! the positive control drives a deliberately-broken DKG (one that skips
//! the share-vs-commitment verification and accepts a Byzantine bad share)
//! all the way to key material, then the checker reconstructs the group
//! secret and shows `x·G != Q` — the harness catches the resulting
//! unusable key with NO gated code on the path.
//!
//! Flip this to `true` once `core.zig`'s five functions are no longer
//! `@panic` stubs. The gated tests in `protocol.zig`/`root.zig` will then
//! actually drive the honest `Dkg` through the round protocol under
//! adversarial share injection and enforce the correctness invariants
//! (all honest parties agree on `Q`; any `t` honest shares Lagrange-
//! reconstruct `x` with `x·G == Q`; a Byzantine dealer is detected,
//! complained-about, and disqualified from QUAL) — culminating in the
//! decisive end-to-end anchor: the DKG-produced shares feed the REAL
//! `threshold_ecdsa.signWithShares`, whose output verifies under `Q` via
//! `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`.
//!
//! Leaving it `false` makes those gated tests report **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light. A skipped
//! test still compiles (so every core function's signature is exercised by
//! the type checker), it just never calls into the panicking body.
pub const fable_core_implemented = false;
