// SPDX-License-Identifier: MIT
//! Recoverable ECDSA/secp256k1 for BOLT#11's `signature` field — a
//! recoverable compact ECDSA signature (`r || s || recid`), letting a
//! reader recover the payee's node ID straight from the signature when no
//! `n` field is present.
//!
//! This used to be a standalone implementation (RFC 6979 deterministic
//! sign + public-key recovery, built directly on `k256`'s field/group/
//! scalar primitives) — it turned out to be general secp256k1 machinery,
//! not anything BOLT#11-specific, so it now lives in `k256` itself
//! (`k256/src/ecdsa_recover.zig`). This file is a thin re-export so
//! existing callers (`bolt11.zig`'s `ecdsa.*`, and `lninvoice`'s root-level
//! `sign`/`recoverPubkey`/`Signature`) keep working unchanged.

const k256 = @import("k256");

pub const SignError = k256.ecdsa_recover.SignError;
pub const Signature = k256.ecdsa_recover.Signature;
pub const sign = k256.ecdsa_recover.sign;

pub const RecoverError = k256.ecdsa_recover.RecoverError;
pub const recoverPubkey = k256.ecdsa_recover.recoverPubkey;

pub const isLowS = k256.ecdsa_recover.isLowS;
