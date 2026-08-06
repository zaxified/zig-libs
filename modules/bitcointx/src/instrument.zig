// SPDX-License-Identifier: MIT
//! Test-only instrumentation for the per-transaction commitment hashes.
//!
//! BIP143 exists to make segwit sighashing LINEAR in transaction size — the
//! legacy algorithm's `O(n²)` blowup was a consensus-level DoS vector, and
//! the three reusable midstates are the whole point of the new algorithm.
//! BIP341 does the same with five commitment hashes. "Reusable" is a
//! property of the *call pattern*, not of the digest bytes, so no
//! byte-exactness KAT can observe it and no assertion about the digests can
//! guard it.
//!
//! A stopwatch would be the obvious oracle and the wrong one: a complexity
//! assertion made with a clock is a flaky test on a loaded CI box. So count
//! instead. `commitment_hashes` counts how many *per-transaction*
//! commitment hashes have been computed; a caller that hoists them via
//! `Precomputed` pays a constant number for a whole transaction, and a
//! caller that does not pays one set per input. The regression test asserts
//! the count is independent of `vin.len`, which is exactly the property
//! BIP143 was designed to deliver.
//!
//! Per-INPUT hashes (BIP143's SIGHASH_SINGLE `hashOutputs` over the single
//! matching output, BIP341's `sha_single_output`) are deliberately NOT
//! counted: they are per-input by construction in Core too, so counting
//! them would make the oracle unable to distinguish the defect.
//!
//! `builtin.is_test` is a comptime constant, so outside a test build
//! `Counter` is `void`, every `noteCommitmentHash` is a store to a
//! zero-sized value, and none of it reaches the object file. The module's
//! `.concurrency = .reentrant` / no-shared-state claim therefore still
//! holds for everything that ships; the mutable state exists only in a test
//! binary, where these tests are single-threaded. Non-test code must never
//! read it.

const builtin = @import("builtin");

const Counter = if (builtin.is_test) usize else void;
const counter_init: Counter = if (builtin.is_test) 0 else {};

/// Number of per-transaction commitment hashes computed since `reset()`.
/// Test builds only — see the module doc comment.
pub var commitment_hashes: Counter = counter_init;

pub inline fn noteCommitmentHash() void {
    if (builtin.is_test) commitment_hashes += 1;
}

/// Zero the counter. Returns nothing; read with `count()`.
pub fn reset() void {
    if (builtin.is_test) commitment_hashes = 0;
}

/// The counter's current value (always 0 outside a test build).
pub fn count() usize {
    return if (builtin.is_test) commitment_hashes else 0;
}
