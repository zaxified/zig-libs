// SPDX-License-Identifier: MIT

//! gate — the single switch that will turn on the tests exercising
//! `tlock.zig`'s two Fable-hard cores: `encrypt` (BF-IBE FullIdent
//! encryption — picking `sigma`/deriving `r`/computing `U`/`V`/`W`) and
//! `decrypt` (recovering `sigma`/`M` from a round signature and running
//! the Fiat-Shamir-Okamoto `U == r*gen` consistency check that makes
//! this CCA-secure, not merely CPA-secure). Both are now REAL
//! (implemented — this flag is `true`; they began life as
//! `@panic("TODO(fable/core): ...")` stubs) — see `tlock.zig`'s own
//! module doc comment and each function's doc comment for the exact
//! construction the Fable pass transcribed.
//!
//! Everything ELSE in this module — `ciphersuite.zig`'s `beaconId`/
//! `h1`/`h2`/`h3`/`h4`/`randomSigma`, and `tlock.zig`'s `Ciphertext`
//! struct + byte codec — is fully REAL today and needs no gate; that is
//! what proves `kat_test.zig`'s ungated tests have teeth independent of
//! whether `encrypt`/`decrypt` are filled in yet (byte-exact identity
//! digests, real production quicknet `h1`/pairing sanity checks against
//! a genuine drand round signature, deterministic `h2`/`h3`/`h4`
//! constructions — see that file's "1. REAL, UNGATED" section).
//!
//! One flag covers both `encrypt` and `decrypt`: every gated
//! completeness test in `kat_test.zig` is a `decrypt(round_sig,
//! encrypt(...))` round trip (or a byte-exact `decrypt` against a
//! genuine drand ciphertext once one is embedded), so there is no
//! intermediate state where one core is done and independently
//! testable while the other isn't — the same reasoning `bbs`/`vdf`/
//! `bulletproofs`'s own single-flag `gate.zig`s document for their own
//! two/four-core splits.
//!
//! This is now `true`: `tlock.zig`'s `encrypt`/`decrypt` are REAL —
//! implemented (BF-IBE FullIdent assembly + the FO consistency check +
//! a module-local constant-time `fp12Pow`) and byte-exact-verified
//! against a GENUINE drand-Go-produced interop ciphertext
//! (`kat_test.zig`'s "drand interop vector" section: a `tle`-encrypted
//! fixture from `drand/tlock`'s own `testdata/`, decrypted with the
//! genuine published round signature, plaintext independently confirmed
//! through the age header MAC — see `SPEC.md`'s "KAT plan" for the full
//! verification chain). All previously-SKIPped gated tests in
//! `kat_test.zig` now run and PASS — mirroring `bbs`/`vdf`/
//! `bulletproofs`/`bn254`/`threshold_ecdsa`'s identical
//! scaffold-then-implement discipline (`CONVENTIONS.md`'s
//! "gate-flag/dark-tests" convention).
pub const core_implemented = true;
