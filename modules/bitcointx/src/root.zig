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
    _ = @import("tx_wire_test.zig");
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

// ── fuzz: a decoded transaction through all three sighash algorithms ────────
//
// W2 A3 (F5) recorded that `deserializePartial` was the only fuzzed entry
// point in this module, and that the three sighash functions — the only ones
// that consume attacker-derived data on a validating node, since every field
// they read comes off the wire — had never been fuzzed at all. The obstacle
// is that the harness for `deserializePartial` lives in `tx.zig`, and `tx.zig`
// is what the sighash files import: it cannot reach them without a cycle. So
// the decode→sighash harness lives here, where all four are already in scope.
//
// The oracle is not just "no panic". `sighashWith` (the precomputed-midstate
// seam) must be byte-identical to the one-off `sighash` for the same inputs;
// that is the invariant a validator's whole O(n) vs O(n²) choice rests on, and
// it is checked on every input that decodes.
test "fuzz: every decoded transaction through legacy/BIP143/BIP341 sighash" {
    try std.testing.fuzz({}, fuzzSighash, .{ .corpus = sighash_seeds });
}

/// F11 (2026-08-11 re-audit): a same-shape clone of `t` with an
/// INDEPENDENT `vin`/`vout` backing allocation, so `PrecomputedTransactionData`
/// built from `t` never structurally matches it — pairing `t.clone()` with
/// `t`'s cache is exactly the class of caller mistake F11 named. `witness`
/// is shared with `t` deliberately (not duplicated): the clone is never
/// `deinit`'d, only `.free`'d, so there is no double-free.
const ClonedVinVout = struct {
    tx: Transaction,
    fn free(self: *ClonedVinVout, allocator: std.mem.Allocator) void {
        allocator.free(self.tx.vin);
        allocator.free(self.tx.vout);
    }
};

fn cloneVinVout(allocator: std.mem.Allocator, t: Transaction) !ClonedVinVout {
    const vin = try allocator.dupe(TxIn, t.vin);
    errdefer allocator.free(vin);
    const vout = try allocator.dupe(TxOut, t.vout);
    return .{ .tx = .{
        .version = t.version,
        .vin = vin,
        .vout = vout,
        .witness = t.witness,
        .locktime = t.locktime,
        .has_witness = t.has_witness,
    } };
}

fn fuzzSighash(_: void, smith: *std.testing.Smith) !void {
    const a = std.testing.allocator;
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    // The same three-way bias `tx.zig`'s harness uses on the octet after the
    // version field, so transactions actually decode instead of the fuzzer
    // spending its budget on the CompactSize bail-out.
    buf[4] = switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => smith.valueRangeAtMost(u8, 0, 4),
        1 => 0x00,
        else => smith.value(u8),
    };
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var r = deserializePartial(a, buf[0..len]) catch return;
    defer r.tx.deinit(a);
    const t = r.tx;

    var script_buf: [96]u8 = undefined;
    smith.bytes(&script_buf);
    const script = script_buf[0..smith.valueRangeAtMost(u8, 0, script_buf.len)];
    // Deliberately drawn past `vin.len`: `InputIndexOutOfRange` is a gate all
    // three implement separately, and an out-of-range index is exactly what a
    // hostile witness stack supplies.
    const idx: usize = smith.valueRangeAtMost(u8, 0, 5);
    const amount = smith.value(i64);

    // Half the draws are a well-formed hash type (base 0..3, optional
    // ANYONECANPAY), half are arbitrary — the SIGHASH_SINGLE bug and the
    // unknown-base fallthrough are both only reachable from the first half.
    const ht32: u32 = if (smith.value(bool))
        @as(u32, smith.valueRangeAtMost(u8, 0, 3)) | (if (smith.value(bool)) @as(u32, 0x80) else 0)
    else
        smith.value(u32);

    _ = legacy.sighash(a, t, idx, script, ht32) catch {};

    if (bip143.sighash(a, t, idx, script, amount, ht32)) |h| {
        const pre = try bip143.precompute(a, t);
        const h2 = bip143.sighashWith(a, pre, t, idx, script, amount, ht32) catch
            return error.PrecomputedSeamRefusedAnAcceptedInput;
        if (!std.mem.eql(u8, &h, &h2)) return error.Bip143PrecomputedDiverged;

        // F11 (2026-08-11 re-audit): this harness used to ALWAYS pair `pre`
        // with the exact `t` it was built from, so it could not reach the
        // mismatched-pair defect class no matter how long it ran. Half the
        // draws now build a same-shape clone with an independent backing
        // allocation and pair it with `pre` on purpose, asserting the
        // refusal fires rather than a wrong digest or a crash.
        if (smith.value(bool)) {
            var clone = try cloneVinVout(a, t);
            defer clone.free(a);
            try std.testing.expectError(
                error.PrecomputedMismatch,
                bip143.sighashWith(a, pre, clone.tx, idx, script, amount, ht32),
            );
        }
    } else |_| {}

    // BIP341 commits to every spent output, so it needs one per input.
    var spent: [8]TxOut = undefined;
    if (t.vin.len <= spent.len) {
        for (spent[0..t.vin.len]) |*o| o.* = .{
            .value = smith.value(i64),
            .script_pubkey = script,
        };
        const outs = spent[0..t.vin.len];
        const valid_ht = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };
        const ht8: u8 = if (smith.value(bool))
            valid_ht[smith.valueRangeAtMost(u8, 0, valid_ht.len - 1)]
        else
            smith.value(u8);
        if (bip341.sighash(a, t, idx, ht8, outs)) |h| {
            const pre = bip341.precompute(a, t, outs) catch
                return error.PrecomputeRefusedAnAcceptedTransaction;
            const h2 = bip341.sighashWith(a, pre, t, idx, ht8, outs) catch
                return error.PrecomputedSeamRefusedAnAcceptedInput;
            if (!std.mem.eql(u8, &h, &h2)) return error.Bip341PrecomputedDiverged;

            // F11: same coverage as the bip143 branch above, and additionally
            // covers the `spent_outputs` half of the identity — the same
            // transaction, but a differently-allocated `spent_outputs`.
            if (smith.value(bool)) {
                var clone = try cloneVinVout(a, t);
                defer clone.free(a);
                try std.testing.expectError(
                    error.PrecomputedMismatch,
                    bip341.sighashWith(a, pre, clone.tx, idx, ht8, outs),
                );
            }
            if (smith.value(bool)) {
                var outs2: [8]TxOut = undefined;
                @memcpy(outs2[0..outs.len], outs);
                try std.testing.expectError(
                    error.PrecomputedMismatch,
                    bip341.sighashWith(a, pre, t, idx, ht8, outs2[0..outs.len]),
                );
            }
        } else |_| {}
    }
}

/// See `iec61850/src/goose.zig`: without `--fuzz` the runner feeds only
/// `options.corpus` plus one empty input, and an empty input makes every draw
/// return its range minimum — a zero-length buffer that decodes to nothing.
/// The first `smith.bytes` draw takes raw octets, so the seed's head is a
/// transaction prefix; the words after it are kept small because `Smith`
/// discards any word outside a draw's declared range.
fn sighashSeed(comptime head: []const u8, comptime bits: u64, comptime n: usize) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    for (out[0..256], 0..) |*b, i| b.* = head[i % head.len];
    var i: usize = 256;
    var w: u6 = 0;
    while (i + 8 <= n) : (i += 8) {
        std.mem.writeInt(u64, out[i..][0..8], (bits >> w) & 0x03, .little);
        w +%= 1;
    }
    return out;
}

const sighash_seeds: []const []const u8 = &.{
    // version 2, one input, one output, small scripts — a shape that decodes.
    &sighashSeed(&[_]u8{
        0x02, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x51, 0x52, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x10,
        0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x51, 0x51, 0x00, 0x00,
        0x00, 0x00,
    }, 0x9E37_79B9_7F4A_7C15, 512),
    &sighashSeed(&[_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }, 0x0123_4567_89AB_CDEF, 512),
    &sighashSeed(&[_]u8{ 0x01, 0x00, 0x00, 0x00, 0x02 }, 0xF0E1_D2C3_B4A5_9687, 512),
    &sighashSeed(&[_]u8{0xFF}, 0xFFFF_FFFF_FFFF_FFFF, 512),
};
