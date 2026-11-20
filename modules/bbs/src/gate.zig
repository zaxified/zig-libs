// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising BBS's
//! four core functions: `bbs.zig`'s `sign`/`verify`/`proofGen`/
//! `proofVerify`. One flag covers all four: `proofGen`/`proofVerify`
//! (the genuinely hard selective-disclosure NIZK) cannot be exercised
//! without `sign`/`verify` already working (every `ProofGen` fixture
//! first signs, then proves over that signature — see
//! `bbs.zig`'s module doc comment and the draft's proof fixtures, which
//! carry the signature they prove over), so there is no
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
//! independent of the four cores (see
//! `kat_test.zig`'s primitive tests, byte-exact against draft-12's
//! vectors for generators/`h2s`/`messages_to_scalars`/`KeyGen`).
//!
//! This is `true`: all four cores are implemented per `bbs.zig`'s per-step
//! doc-comment contracts, so `kat_test.zig`'s gated tests are executed
//! byte-exact assertions rather than `error.SkipZigTest` skips (a skip is no
//! green light; with the flag `false` they would still compile, so the four
//! cores' signatures stay type-checked at every call site). Same gate-flag
//! convention as `bulletproofs`/`bn254`/`threshold_ecdsa`.
pub const core_implemented = true;
