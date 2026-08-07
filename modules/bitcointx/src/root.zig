// SPDX-License-Identifier: MIT
//! bitcointx — Bitcoin transaction (de)serialization and signature hashing:
//! CompactSize varints, legacy + BIP144 segwit transaction wire codecs, and
//! all three deployed sighash algorithms (legacy, BIP143 segwit-v0, BIP341
//! taproot key-path). Published consensus rules with official byte-exact
//! test vectors throughout — see SPEC.md for the full verification story
//! and scope cuts, README.md for usage.
//!
//! ## Layout
//!
//! - `tx.zig` — CompactSize + `Transaction`/`TxIn`/`TxOut`/`Witness` +
//!   `deserialize`/`serialize` + `txid`/`wtxid`. Parses untrusted wire
//!   bytes fail-closed (module doc comment there has the full threat
//!   model).
//! - `sighash_legacy.zig` — pre-segwit `SignatureHash()`.
//! - `sighash_bip143.zig` — segwit-v0 sighash (BIP143).
//! - `sighash_bip341.zig` — taproot key-path sighash (BIP341); tapscript
//!   (BIP342) and annex support are explicitly out of scope (its own doc
//!   comment explains why).
//! - `hashtype.zig` — the shared `ALL`/`NONE`/`SINGLE`/`ANYONECANPAY` bit
//!   layout `sighash_legacy`/`sighash_bip143` both use (BIP341 has its own
//!   stricter single-byte encoding, defined in `sighash_bip341.zig`).
//! - `precomputed.zig` — `PrecomputedTransactionData`: the per-transaction
//!   BIP143/BIP341 commitment hashes, computed once per transaction so a
//!   validator's cost is linear in transaction size rather than quadratic
//!   (that seam is what BIP143 exists for — see the file's doc comment).
//! - `instrument.zig` — test-only counter backing the regression test for
//!   the above; compiles to nothing outside a test build. Re-exported as
//!   `instrument` so a *consumer*'s tests can assert the same property at
//!   their own call sites (audit BD-18).
//! - `hash256.zig` — `sha256d` (Bitcoin's double-SHA256) and plain
//!   `sha256` (what BIP341's commitment hashes use instead).
//! - `*_kat_vectors.zig` / `*_kat_test.zig` — official test vectors
//!   (machine-transcribed, never hand-typed — see each file's doc comment
//!   for provenance) and the tests that check byte-exactness against them.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant, // no shared/global state; every call is over caller-owned values
    .model_after = "BIP141/143/144/340/341 (bitcoin/bips); Bitcoin Core reference behavior (src/script/interpreter.cpp SignatureHash) for the legacy algorithm, which predates the BIP process",
    .deps = .{"bip340"},
};

pub const tx = @import("tx.zig");
pub const hash256 = @import("hash256.zig");
pub const hashtype = @import("hashtype.zig");
pub const legacy = @import("sighash_legacy.zig");
pub const bip143 = @import("sighash_bip143.zig");
pub const bip341 = @import("sighash_bip341.zig");
pub const precomputed = @import("precomputed.zig");
/// Test-only commitment-hash counter. Public because the property it measures
/// — "compute once per transaction" — is a property of the CALL PATTERN, so it
/// has to be assertable from the consumers that make the calls
/// (`bitcoinscript` is one) and not only from this module's own tests. Outside
/// a test build every symbol in here is `void`/zero and reaches no object file;
/// see `instrument.zig`. Non-test code must never read it.
pub const instrument = @import("instrument.zig");

/// Bitcoin Core's `PrecomputedTransactionData` equivalent: the BIP143 and
/// BIP341 per-transaction commitment hashes, computed once per transaction
/// and reused for every input and every `CHECKSIG`. See `precomputed.zig`
/// for why an implementation without this seam is BIP143-shaped but still
/// `O(n²)` on attacker-chosen input.
pub const PrecomputedTransactionData = precomputed.PrecomputedTransactionData;

// Re-export the tx/CompactSize surface at the package root for convenience
// (`@import("bitcointx").deserialize(...)` alongside `@import("bitcointx").tx.deserialize(...)`).
pub const Transaction = tx.Transaction;
pub const OutPoint = tx.OutPoint;
pub const TxIn = tx.TxIn;
pub const TxOut = tx.TxOut;
pub const Witness = tx.Witness;
pub const deserialize = tx.deserialize;
pub const deserializePartial = tx.deserializePartial;
pub const serialize = tx.serialize;
pub const serializeLegacy = tx.serializeLegacy;
pub const serializeSegwit = tx.serializeSegwit;
pub const encodeCompactSize = tx.encodeCompactSize;
pub const decodeCompactSize = tx.decodeCompactSize;
pub const compactSizeLen = tx.compactSizeLen;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule (and every
// vector/test file not otherwise imported above) must be named here too.
test {
    _ = tx;
    _ = hash256;
    _ = hashtype;
    _ = legacy;
    _ = bip143;
    _ = bip341;
    _ = precomputed;
    _ = instrument;
    _ = @import("testutil.zig");
    _ = @import("tx_kat_vectors.zig");
    _ = @import("tx_kat_test.zig");
    _ = @import("legacy_kat_vectors.zig");
    _ = @import("legacy_kat_test.zig");
    _ = @import("single_bug_kat_vectors.zig");
    _ = @import("single_bug_kat_test.zig");
    _ = @import("bip143_kat_vectors.zig");
    _ = @import("bip143_kat_test.zig");
    _ = @import("bip341_kat_vectors.zig");
    _ = @import("bip341_kat_test.zig");
}

test "meta.deps names bip340" {
    try std.testing.expect(std.mem.eql(u8, meta.deps[0], "bip340"));
}

test "root re-exports resolve to the same types/values as tx.zig" {
    comptime std.debug.assert(tx.Transaction == Transaction);
    try std.testing.expectEqual(tx.compactSizeLen(300), compactSizeLen(300));
}
