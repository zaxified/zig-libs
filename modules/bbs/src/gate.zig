// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising BBS's
//! four Fable-hard cores: `bbs.zig`'s `sign`/`verify`/`proofGen`/
//! `proofVerify`. One flag covers all four: `proofGen`/`proofVerify`
//! (the genuinely hard selective-disclosure NIZK) cannot be exercised
//! without `sign`/`verify` already working (every `ProofGen` fixture
//! first signs, then proves over that signature — see
//! `bbs.zig`'s module doc comment and the mattrglobal fixture generator
//! this module's KAT vectors are drawn from), so there is no
//! intermediate state where the "easier" pair is done and testable but
//! the NIZK pair isn't yet — the same reasoning `bulletproofs`' single
//! `core_implemented` flag documents for its own two-core split.
//!
//! Everything ELSE in this module — `ciphersuite.zig`'s
//! `expandMessage`/`hashToScalar`/`createGenerators`/
//! `messagesToScalars`/`calculateDomain`/`calculateRandomScalars`/
//! `mockedRandomScalars`, `keys.zig`'s `keyGen`/`skToPk`, and
//! `bbs.Signature`/`bbs.Proof`'s struct + byte codecs — is fully real
//! today and needs no gate; it is what proves the harness has teeth
//! independent of whether the four cores are filled in yet (see
//! `kat_test.zig`'s ungated tests, byte-exact against
//! `mattrglobal/pairing_crypto`'s `bls12_381_sha_256` fixtures for
//! generators/`h2s`/`messages_to_scalars`/`KeyGen`).
//!
//! This is now `true`: a Fable pass implemented all four cores per
//! `bbs.zig`'s per-step doc-comment contracts, so `kat_test.zig`'s
//! gated tests are executed byte-exact assertions rather than
//! `error.SkipZigTest` skips. (While it was `false` during the scaffold
//! stage the gated tests reported SKIP — never PASS — a skip being no
//! green light; they still compiled, so the four cores' signatures were
//! type-checked at every call site even before the bodies existed.)
//! Mirrors `bulletproofs`/`bn254`/`threshold_ecdsa`'s identical
//! scaffold-then-implement discipline (CONVENTIONS.md's
//! "gate-flag/dark-tests" convention).
pub const core_implemented = true;
