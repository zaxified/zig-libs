// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the GJKR
//! distributed-key-generation CORE (`core.zig`'s five irreducible
//! protocol-soundness functions: `verifyPedersenShare`,
//! `verifyFeldmanShare`, `computeQual`, `deriveGroupPublicKey`, and
//! `combineKeyShare`). Those five are the bias-prevention / Byzantine-
//! detection kernel; the scaffolding pass left them `@panic`-stubbed, and
//! the follow-up core pass has now implemented them — see each function's
//! doc comment in `core.zig` for the exact GJKR construction.
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
//! This is now `true`: `core.zig`'s five functions are implemented, so
//! the formerly-gated tests in `protocol.zig`/`root.zig` actually drive
//! the honest `Dkg` through the round protocol under adversarial share
//! injection and enforce the correctness invariants (all honest parties
//! agree on `Q`; any `t` honest shares Lagrange-reconstruct `x` with
//! `x·G == Q`; a Byzantine dealer is detected, complained-about, and
//! disqualified from QUAL) — culminating in the decisive end-to-end
//! anchor: the DKG-produced shares feed the REAL
//! `threshold_ecdsa.signWithShares`, whose output verifies under `Q` via
//! `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`.
//!
//! (While it was `false`, those tests reported **SKIP** via
//! `error.SkipZigTest`, not PASS — a skip is not a green light.)
pub const fable_core_implemented = true;
