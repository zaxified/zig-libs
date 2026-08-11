// SPDX-License-Identifier: MIT
//! `PrecomputedTransactionData` — the per-transaction sighash cache.
//!
//! ## Why this exists
//!
//! BIP143's stated motivation is that the legacy sighash algorithm made
//! transaction validation **quadratic** in transaction size: every input
//! reserialized the whole transaction, so an attacker who chose the
//! transaction chose the validation cost. That was a consensus-level DoS
//! vector, and the new algorithm was designed around three *per-transaction*
//! midstates precisely so a validator computes them once and reuses them for
//! every input. BIP341 does the same with five commitment hashes.
//!
//! "Compute once" is a property of the CALL PATTERN, not of the digest bytes.
//! An implementation that recomputes the midstates inside every `sighash`
//! call is byte-exact against every published vector and still `O(n²)` — it
//! has the letter of BIP143 and none of its point. So the cache has to be a
//! seam a caller can actually hold, not an internal detail.
//!
//! Bitcoin Core's equivalent is `PrecomputedTransactionData`
//! (`src/script/interpreter.h`), built once per transaction and threaded
//! into every `SignatureHash`/`SignatureHashSchnorr` call. This is that
//! shape: `segwit_v0` mirrors Core's `hashPrevouts`/`hashSequence`/
//! `hashOutputs`, `taproot` mirrors its `m_*_single_hash` set, and — as in
//! Core, whose `m_spent_outputs_ready` gates exactly this — the taproot half
//! is present only when the caller supplied the spent outputs, since BIP341
//! commits to every input's spent amount and scriptPubKey and BIP143 does
//! not.
//!
//! ## Using it
//!
//! ```zig
//! const pre = try bitcointx.PrecomputedTransactionData.init(a, transaction, spent_outputs);
//! for (transaction.vin, 0..) |_, i| {
//!     const h = try bitcointx.bip143.sighashWith(a, pre.segwit_v0, transaction, i, script_code, spent_outputs[i].value, hash_type);
//!     // ... verify
//! }
//! ```
//!
//! ## ⚠ Precondition: `pre` is a SNAPSHOT, and mutation invalidates it
//!
//! **`pre` is invalidated by any mutation of the transaction or its spent
//! outputs; the fingerprint detects substitution only.** Rebuild it after
//! every change, and treat the transaction as frozen for as long as a `pre`
//! built from it is alive.
//!
//! `pre` holds hashes of the transaction's contents AS THEY WERE at
//! `init` time. The `*With` entry points carry a cheap O(1) identity
//! fingerprint (the `vin`/`vout`/`spent_outputs` slice pointers and lengths,
//! see F11) that refuses a `pre` paired with a DIFFERENT transaction value
//! with `error.PrecomputedMismatch`. That fingerprint cannot see a change
//! made THROUGH those same slices:
//!
//! ```zig
//! const pre = try bitcointx.PrecomputedTransactionData.init(a, t, spent);
//! t.vout[0].value += 1;                    // same slices, same pointers, same lengths
//! const h = try bip143.sighashWith(a, pre.segwit_v0, t, 0, sc, amount, ht);
//! // ^ NO error. `h` is the digest of the transaction BEFORE the mutation.
//! ```
//!
//! This is the realistic route to a wrong consensus digest — filling in a
//! `script_sig`, adjusting an output and signing again is an ordinary
//! PSBT-shaped flow, whereas passing a wholly different transaction is a
//! coding slip. It is not a fork risk: Bitcoin Core's
//! `PrecomputedTransactionData` has exactly the same property (it carries no
//! correspondence check at all and leaves the whole question to the caller),
//! so this is **parity, documented**. Catching mutation would mean hashing
//! the transaction's contents on every call — which is precisely the `O(n)`
//! per-input cost the cache exists to eliminate, so the check would cost
//! more than the thing it guards. `precomputed.zig`'s F12 test asserts this
//! limit rather than hiding it, so the behaviour cannot change without this
//! paragraph changing with it.
//!
//! Every `*With` entry point is byte-identical to its uncached counterpart —
//! the `hash_type`-dependent selection over the cached hashes lives in one
//! place per algorithm, shared by both routes, so a cached validator and an
//! uncached signer cannot diverge on the consensus bytes.
//!
//! The legacy (pre-segwit) algorithm has no equivalent cache and never will:
//! its digest depends on the input index and the scriptCode in a way that
//! admits no per-transaction factor. That is the defect BIP143 was written
//! to retire, not an omission here.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bip143 = @import("sighash_bip143.zig");
const bip341 = @import("sighash_bip341.zig");
const tx = @import("tx.zig");

pub const PrecomputedError = bip341.Bip341Error;

/// A snapshot of one transaction's per-transaction commitment hashes.
///
/// ⚠ **Precondition — `pre` is invalidated by any mutation of the
/// transaction or its spent outputs; the fingerprint detects substitution
/// only.** The `*With` entry points refuse a `pre` paired with a different
/// `Transaction` VALUE (`error.PrecomputedMismatch`, F11), but a mutation
/// made in place — through the very `vin`/`vout`/`spent_outputs` slices this
/// was built from — leaves pointers and lengths identical and is therefore
/// invisible: the call succeeds and returns the digest of the transaction as
/// it was at `init` time. Rebuild after every change. This matches Bitcoin
/// Core's `PrecomputedTransactionData`, which carries no check at all; see
/// the module doc comment above for why detecting it would cost exactly what
/// the cache exists to save.
pub const PrecomputedTransactionData = struct {
    /// BIP143 segwit-v0: `hashPrevouts`/`hashSequence`/`hashOutputs`.
    segwit_v0: bip143.Precomputed,
    /// BIP341 taproot: the five commitment hashes. `null` when `init` was
    /// called without spent outputs — taproot sighashing is impossible
    /// without them, so there is nothing to cache.
    taproot: ?bip341.Precomputed,

    /// Compute the whole cache in one `O(n)` pass over the transaction.
    /// Pass `null` for `spent_outputs` if only the segwit-v0 half is wanted;
    /// otherwise it must hold one entry per `vin`, in `vin` order, or this
    /// returns `error.PrevoutsCountMismatch`.
    pub fn init(
        allocator: Allocator,
        transaction: tx.Transaction,
        spent_outputs: ?[]const tx.TxOut,
    ) PrecomputedError!PrecomputedTransactionData {
        return .{
            .segwit_v0 = try bip143.precompute(allocator, transaction),
            .taproot = if (spent_outputs) |so| try bip341.precompute(allocator, transaction, so) else null,
        };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const instrument = @import("instrument.zig");

fn buildTx(allocator: Allocator, n: usize) !tx.Transaction {
    const vin = try allocator.alloc(tx.TxIn, n);
    for (vin, 0..) |*v, i| v.* = .{
        .prevout = .{ .txid = [_]u8{@truncate(i)} ** 32, .vout = @intCast(i) },
        .script_sig = &.{},
        .sequence = 0xfffffffe -% @as(u32, @intCast(i)),
    };
    const vout = try allocator.alloc(tx.TxOut, n);
    for (vout, 0..) |*o, i| o.* = .{ .value = @intCast(1000 + i), .script_pubkey = &.{} };
    return .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 17, .has_witness = false };
}

fn freeTx(allocator: Allocator, t: tx.Transaction) void {
    allocator.free(t.vin);
    allocator.free(t.vout);
}

/// Every hash type both algorithms accept, so the count assertion below is
/// not just about the ALL path the published vectors all happen to use.
const bip143_hash_types = [_]u32{
    bip143.ALL,
    bip143.NONE,
    bip143.SINGLE,
    bip143.ALL | bip143.ANYONECANPAY,
    bip143.NONE | bip143.ANYONECANPAY,
    bip143.SINGLE | bip143.ANYONECANPAY,
};
const bip341_hash_types = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };

// The oracle here is a COUNTER, not a stopwatch: a complexity assertion made
// with a clock is a flaky test on a loaded box. `instrument.count()` counts
// per-transaction commitment hashes, so "hoisted" is the literal, exact,
// deterministic statement `count() == k` for a k that does not depend on
// `vin.len`. See `instrument.zig`.

test "precomputed: commitment-hash count is O(1) in vin.len, not O(n)" {
    const a = testing.allocator;
    // Two sizes an order of magnitude apart. If the midstates were recomputed
    // per input the counts would differ by ~64x; hoisted, they are equal.
    for ([_]usize{ 2, 128 }) |n| {
        const t = try buildTx(a, n);
        defer freeTx(a, t);
        const spent = try a.alloc(tx.TxOut, n);
        defer a.free(spent);
        for (spent, 0..) |*o, i| o.* = .{ .value = @intCast(5000 + i), .script_pubkey = &.{} };

        instrument.reset();
        const pre = try PrecomputedTransactionData.init(a, t, spent);
        // 3 (BIP143) + 5 (BIP341), once for the whole transaction.
        try testing.expectEqual(@as(usize, 8), instrument.count());

        for (0..n) |i| {
            for (bip143_hash_types) |ht| {
                const h = try bip143.sighashWith(a, pre.segwit_v0, t, i, &[_]u8{0xAA}, 12345, ht);
                std.mem.doNotOptimizeAway(&h);
            }
            for (bip341_hash_types) |ht| {
                const h = try bip341.sighashWith(a, pre.taproot.?, t, i, ht, spent);
                std.mem.doNotOptimizeAway(&h);
            }
        }
        // Still 8: validating every input under every hash type computed no
        // further per-transaction commitment hash. This is the whole finding.
        try testing.expectEqual(@as(usize, 8), instrument.count());
    }
}

test "precomputed: the uncached path is the quadratic one (the counter can tell them apart)" {
    // Guards the counter itself: if `instrument` were inert, the test above
    // would pass for the wrong reason (0 == 0). Here the SAME counter must
    // grow with n on the uncached entry points.
    const a = testing.allocator;
    var counts: [2]usize = undefined;
    for ([_]usize{ 2, 16 }, 0..) |n, k| {
        const t = try buildTx(a, n);
        defer freeTx(a, t);
        instrument.reset();
        for (0..n) |i| {
            const h = try bip143.sighash(a, t, i, &[_]u8{0xAA}, 12345, bip143.ALL);
            std.mem.doNotOptimizeAway(&h);
        }
        counts[k] = instrument.count();
    }
    try testing.expectEqual(@as(usize, 2 * 3), counts[0]);
    try testing.expectEqual(@as(usize, 16 * 3), counts[1]);
}

test "precomputed: cached and uncached sighashes are byte-identical (all hash types, all inputs)" {
    const a = testing.allocator;
    const n = 5;
    const t = try buildTx(a, n);
    defer freeTx(a, t);
    const spent = try a.alloc(tx.TxOut, n);
    defer a.free(spent);
    for (spent, 0..) |*o, i| o.* = .{ .value = @intCast(5000 + i), .script_pubkey = &[_]u8{ 0x51, @truncate(i) } };

    const pre = try PrecomputedTransactionData.init(a, t, spent);

    var checked: usize = 0;
    for (0..n) |i| {
        for (bip143_hash_types) |ht| {
            // Full preimage, not just the digest: a digest comparison would
            // hide a length or field-order difference behind SHA-256.
            const want = try bip143.preimage(a, t, i, &[_]u8{ 0xAA, 0xBB }, 987654321, ht);
            defer a.free(want);
            const got = try bip143.preimageWith(a, pre.segwit_v0, t, i, &[_]u8{ 0xAA, 0xBB }, 987654321, ht);
            defer a.free(got);
            try testing.expectEqualSlices(u8, want, got);
            checked += 1;
        }
        for (bip341_hash_types) |ht| {
            const want = try bip341.sigMsg(a, t, i, ht, spent);
            defer a.free(want);
            const got = try bip341.sigMsgWith(a, pre.taproot.?, t, i, ht, spent);
            defer a.free(got);
            try testing.expectEqualSlices(u8, want, got);
            checked += 1;
        }
    }
    try testing.expectEqual(@as(usize, n * (bip143_hash_types.len + bip341_hash_types.len)), checked);
}

test "precomputed: taproot half is optional, and a bad spent-outputs count is rejected" {
    const a = testing.allocator;
    const t = try buildTx(a, 3);
    defer freeTx(a, t);
    const only_v0 = try PrecomputedTransactionData.init(a, t, null);
    try testing.expect(only_v0.taproot == null);

    const too_few = [_]tx.TxOut{.{ .value = 1, .script_pubkey = &.{} }};
    try testing.expectError(error.PrevoutsCountMismatch, PrecomputedTransactionData.init(a, t, &too_few));
}

test "F11: a precomputed cache built from one transaction is refused against a different one" {
    // F11 (2026-08-11 re-audit): `pre` and `transaction` used to be two
    // independent arguments with no correspondence check — a caller that
    // hoisted `pre` for one transaction and then called `sighashWith` with a
    // DIFFERENT transaction got a silently wrong consensus digest, no error,
    // no assert. `fuzzSighash` (root.zig) structurally could not find this
    // class, since it always builds `pre` from the same `t` it passes on
    // (see the test right after this one, which closes that gap too).
    const a = testing.allocator;
    const t1 = try buildTx(a, 3);
    defer freeTx(a, t1);
    const t2 = try buildTx(a, 3); // same shape, DIFFERENT backing allocation
    defer freeTx(a, t2);
    const spent1 = try a.alloc(tx.TxOut, 3);
    defer a.free(spent1);
    for (spent1, 0..) |*o, i| o.* = .{ .value = @intCast(5000 + i), .script_pubkey = &.{} };
    const spent2 = try a.alloc(tx.TxOut, 3);
    defer a.free(spent2);
    for (spent2, 0..) |*o, i| o.* = .{ .value = @intCast(5000 + i), .script_pubkey = &.{} };

    const pre1 = try PrecomputedTransactionData.init(a, t1, spent1);

    // bip143: pre from t1, transaction argument is t2.
    try testing.expectError(
        error.PrecomputedMismatch,
        bip143.sighashWith(a, pre1.segwit_v0, t2, 0, &[_]u8{0xAA}, 12345, bip143.ALL),
    );
    // bip341: pre from t1 (built with spent1), transaction argument is t2.
    try testing.expectError(
        error.PrecomputedMismatch,
        bip341.sighashWith(a, pre1.taproot.?, t2, 0, 0x00, spent1),
    );
    // bip341: pre from t1, right transaction but a DIFFERENT spent_outputs —
    // BIP341 commits to the spent outputs too, so a mismatch there is the
    // same class of bug.
    try testing.expectError(
        error.PrecomputedMismatch,
        bip341.sighashWith(a, pre1.taproot.?, t1, 0, 0x00, spent2),
    );

    // Sanity: the SAME transaction and spent_outputs the cache was built
    // from still works — this isn't refusing everything.
    _ = try bip143.sighashWith(a, pre1.segwit_v0, t1, 0, &[_]u8{0xAA}, 12345, bip143.ALL);
    _ = try bip341.sighashWith(a, pre1.taproot.?, t1, 0, 0x00, spent1);
}

test "F12: an IN-PLACE mutation is NOT detected — the documented limit, asserted rather than hidden" {
    // F12 (2026-08-11 re-audit). This test asserts what the code DOES, which
    // here is deliberately less than a reader might assume from F11: the
    // identity fingerprint catches SUBSTITUTION (a `pre` paired with a
    // different `Transaction` value) and cannot catch MUTATION (the same
    // slices, edited in place) — pointers and lengths are unchanged, so
    // `matches` says yes and the caller gets the pre-mutation digest with no
    // error.
    //
    // Recorded as parity, not as a defect: Bitcoin Core's
    // `PrecomputedTransactionData` has exactly the same property, and the
    // only check that would see through an in-place edit is a hash of the
    // transaction's contents — an `O(n)` cost per call, which is precisely
    // what the cache exists to remove. The disposition is therefore
    // documentation plus a precondition (see this file's module doc comment,
    // both `Precomputed` doc comments, README.md and SPEC.md), and this test
    // is the thing that keeps the documentation honest.
    //
    // ⚠ IF THIS TEST FAILS because the binding was strengthened: that is a
    // behaviour change, and the four places above now say something untrue.
    // Update them together with this test — do not simply relax it.
    const a = testing.allocator;
    const t = try buildTx(a, 3);
    defer freeTx(a, t);
    const spent = try a.alloc(tx.TxOut, 3);
    defer a.free(spent);
    for (spent, 0..) |*o, i| o.* = .{ .value = @intCast(5000 + i), .script_pubkey = &.{} };

    const pre = try PrecomputedTransactionData.init(a, t, spent);

    const before_v0 = try bip143.sighashWith(a, pre.segwit_v0, t, 0, &[_]u8{0xAA}, 12345, bip143.ALL);
    const before_tr = try bip341.sighashWith(a, pre.taproot.?, t, 0, 0x00, spent);

    // ── mutation 1: an output value, committed to by both algorithms ──────
    t.vout[0].value +%= 1;

    const stale_v0 = bip143.sighashWith(a, pre.segwit_v0, t, 0, &[_]u8{0xAA}, 12345, bip143.ALL) catch
        return error.InPlaceMutationIsNowDetected_UpdateTheDocumentedPrecondition;
    const stale_tr = bip341.sighashWith(a, pre.taproot.?, t, 0, 0x00, spent) catch
        return error.InPlaceMutationIsNowDetected_UpdateTheDocumentedPrecondition;

    // Not merely "no error": the digest handed back is the one from BEFORE
    // the mutation. That is the sharp end of the limit — a caller who signs
    // this has signed a transaction that no longer exists.
    try testing.expectEqualSlices(u8, &before_v0, &stale_v0);
    try testing.expectEqualSlices(u8, &before_tr, &stale_tr);

    // ...and it really is stale, not accidentally equal: the uncached entry
    // points, which read the transaction as it is now, disagree with it.
    const fresh_v0 = try bip143.sighash(a, t, 0, &[_]u8{0xAA}, 12345, bip143.ALL);
    const fresh_tr = try bip341.sighash(a, t, 0, 0x00, spent);
    try testing.expect(!std.mem.eql(u8, &stale_v0, &fresh_v0));
    try testing.expect(!std.mem.eql(u8, &stale_tr, &fresh_tr));

    // Rebuilding is the documented remedy, and it works.
    const rebuilt = try PrecomputedTransactionData.init(a, t, spent);
    const rebuilt_v0 = try bip143.sighashWith(a, rebuilt.segwit_v0, t, 0, &[_]u8{0xAA}, 12345, bip143.ALL);
    const rebuilt_tr = try bip341.sighashWith(a, rebuilt.taproot.?, t, 0, 0x00, spent);
    try testing.expectEqualSlices(u8, &fresh_v0, &rebuilt_v0);
    try testing.expectEqualSlices(u8, &fresh_tr, &rebuilt_tr);

    // ── mutation 2: a SPENT OUTPUT, which only BIP341 commits to ──────────
    // The precondition names the spent outputs as well as the transaction,
    // so it is pinned separately: `spent` is a distinct allocation from the
    // transaction, with its own pointer in the fingerprint.
    const tr_before_spent_edit = try bip341.sighashWith(a, rebuilt.taproot.?, t, 0, 0x00, spent);
    spent[0].value +%= 1;
    const tr_stale = bip341.sighashWith(a, rebuilt.taproot.?, t, 0, 0x00, spent) catch
        return error.InPlaceMutationIsNowDetected_UpdateTheDocumentedPrecondition;
    try testing.expectEqualSlices(u8, &tr_before_spent_edit, &tr_stale);
    const tr_fresh = try bip341.sighash(a, t, 0, 0x00, spent);
    try testing.expect(!std.mem.eql(u8, &tr_stale, &tr_fresh));
}
