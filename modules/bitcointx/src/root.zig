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
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bitcoin transaction (de)serialization + signature hashing — legacy, BIP143 segwit-v0, and BIP341 taproot key-path sighash.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    var corpus: SighashCorpus = .{};
    try std.testing.fuzz({}, fuzzSighash, .{ .corpus = corpus.build() });
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
    // ⚠ Two `smith.slice` calls, never `bytes` followed by a ranged length.
    // Measured on the four 512-octet seeds this target used to carry: `len`
    // came out of `valueRangeAtMost(u16, 0, 256)` reading the tail words
    // `sighashSeed` writes, which are `& 0x03` — so the LONGEST transaction
    // this harness ever decoded was **3 octets**, shorter than the `version`
    // field, and `deserializePartial` bailed out before the first CompactSize
    // on every input for as long as the target existed. `script` was the same
    // shape and always empty.
    //
    // ⚠ And 256 was too small anyway: see `tx.fuzz_tx_buf_len` — the module's
    // own smallest reference transaction is 275 octets, so not one of them
    // could have passed through here even with a working length draw.
    var buf: [tx.fuzz_tx_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    // The same bias `tx.zig`'s harness uses on the octet after the version
    // field, so ARBITRARY bytes decode instead of the fuzzer spending its
    // budget on the CompactSize bail-out. `else` leaves a seeded frame alone.
    if (len > 4) {
        buf[4] = switch (smith.valueRangeAtMost(u8, 0, 3)) {
            0 => smith.valueRangeAtMost(u8, 0, 4),
            1 => 0x00,
            2 => smith.value(u8),
            else => buf[4],
        };
    }

    var r = deserializePartial(a, buf[0..len]) catch return;
    defer r.tx.deinit(a);
    const t = r.tx;

    var script_buf: [96]u8 = undefined;
    const script_len: usize = smith.slice(&script_buf);
    const script = script_buf[0..script_len];
    // Deliberately drawn past `vin.len`: `InputIndexOutOfRange` is a gate all
    // three implement separately, and an out-of-range index is exactly what a
    // hostile witness stack supplies.
    const idx: usize = smith.valueRangeAtMost(u8, 0, 5);
    const amount = smith.value(i64);

    // A well-formed hash type (base 0..3, optional ANYONECANPAY) or an
    // arbitrary one: the SIGHASH_SINGLE bug needs the first, the unknown-base
    // fallthrough the second.
    // ⚠ The comment here used to say "half the draws ... half are arbitrary".
    // Under `--fuzz` that is the fuzzer's business, not a fact about the code;
    // over the corpus it was simply false — measured 2026-09-08, this knob was
    // `true` on 4 of 4 decoded seeds, because every tail in the corpus was
    // built out of `1`s, so `smith.value(u32)` had never been reached. The
    // corpus now carries two seeds whose tail selects the arbitrary arm, and
    // the guard below pins the split instead of a comment asserting a rate.
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

/// Without `--fuzz` the runner feeds only `options.corpus` plus one empty
/// input, and an empty input makes every draw return its range minimum.
///
/// ⛔ The four 512-octet seeds this target used to carry did NOT fix that.
/// They were built by a helper that wrote `(bits >> w) & 0x03` into every
/// trailing `u64` word — including the word the length draw read — so
/// `len = valueRangeAtMost(u16, 0, 256)` was **at most 3 octets**, shorter
/// than the four-octet `version` field. The transaction prefix in each seed's
/// head was never decoded, the `script` draw was the same shape and always
/// empty, and the three sighash functions this harness exists to exercise had
/// never run on a transaction. That is the measurement this rewrite replaces.
///
/// A seed here is: the transaction as a `testkit.fuzz` slice seed, then the
/// `which` word for the version-byte bias, then the script as a second slice
/// seed, then the `u64` words the knobs after it read. ⚠ Every word must fall
/// inside its draw's declared range or `Smith` discards the REST of the input,
/// so `1` is used throughout: it is in range for `bool`, for
/// `valueRangeAtMost(u8, 0, 5)`, for `value(i64)` and for the `valid_ht`
/// index, and `true` is the branch that reaches the precomputed-mismatch
/// assertions.
const SighashCorpus = struct {
    store: [12 * (4 + tx.fuzz_tx_buf_len + 16 + 4 + 96 + 32 * 8)]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    n: usize = 0,

    /// `which_arg` is the word arms 0 and 2 of the version-byte switch draw
    /// AFTER `which` and BEFORE the script slice.
    /// ⛔ Measured 2026-09-08: without it, arm 0's `valueRangeAtMost(u8, 0, 4)`
    /// read the script seed's own `u32` length header as its eight octets, and
    /// the script slice that followed then read a length out of the middle of
    /// the script. Passing `null` for an arm that draws nothing (1 and 3) is
    /// what keeps the two cases apart.
    fn push(
        self: *SighashCorpus,
        frame: []const u8,
        which: u64,
        which_arg: ?u64,
        script: []const u8,
        tail: []const u64,
    ) void {
        const start = self.used;
        var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
        if (frame.len > 4) {
            std.mem.writeInt(u64, self.store[at..][0..8], which, .little);
            at += 8;
            if (which_arg) |w| {
                std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
                at += 8;
            }
        }
        at += testkit.fuzz.seedInto(self.store[at..], script).len;
        for (tail) |w| {
            std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
            at += 8;
        }
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *SighashCorpus) []const []const u8 {
        // `1` repeated: idx = 1, amount = 1, structured hash types, and every
        // `value(bool)` true, so the precomputed-mismatch branches all run.
        const ones = [_]u64{1} ** 24;
        // idx = 0 with a SIGHASH_SINGLE base (2) and no ANYONECANPAY —
        // the legacy SIGHASH_SINGLE bug path.
        const single = [_]u64{ 0, 1, 1, 2, 0 } ++ [_]u64{1} ** 19;
        // ⛔ The two `value(bool)` knobs that choose between a WELL-FORMED and
        // an ARBITRARY hash type were `true` on 4 of 4 decoded seeds when this
        // was measured on 2026-09-08 — every tail in the corpus was built out
        // of `1`s — so `smith.value(u32)` and the arbitrary `smith.value(u8)`
        // arms had never run, and the harness comment beside them claimed
        // "half the draws". `0` selects the arbitrary arm; the trailing zeroes
        // keep every later knob in range whatever the transaction's `vin.len`
        // turns out to be, so this tail is valid for both KATs.
        const arbitrary = [_]u64{ 0, 1, 0, 0xdeadbeef } ++ [_]u64{0} ** 20;
        // ⛔ 3 = "leave the frame's own version byte alone". The other values
        // are the arbitrary-bytes bias, which would corrupt a real fixture.
        self.push(&tx.fuzz_kat_legacy, 3, null, &p2pkh_script, &ones);
        self.push(&tx.fuzz_kat_legacy, 3, null, &p2pkh_script, &single);
        self.push(&tx.fuzz_kat_segwit, 3, null, &p2pkh_script, &ones);
        self.push(&tx.fuzz_kat_segwit, 3, null, &[_]u8{}, &ones); // empty script
        const rewritten = [_]u64{2} ++ [_]u64{1} ** 23;
        self.push(&tx.fuzz_kat_legacy, 0, 2, &p2pkh_script, &rewritten); // vin count rewritten
        // ⛔ Arms 1 and 2 of the same switch had never been selected either:
        // the `which` histogram was 1 / 0 / 0 / 5. Arm 1 writes `0x00`, which
        // is the SEGWIT MARKER — the path `tx.zig`'s own comment says the bias
        // exists to reach — and arm 2 writes an arbitrary octet.
        self.push(&tx.fuzz_kat_legacy, 1, null, &p2pkh_script, &ones);
        self.push(&tx.fuzz_kat_legacy, 2, 0xfd, &p2pkh_script, &ones);
        self.push(&tx.fuzz_kat_legacy, 3, null, &p2pkh_script, &arbitrary);
        self.push(&tx.fuzz_kat_segwit, 3, null, &p2pkh_script, &arbitrary);
        self.push(tx.fuzz_kat_legacy[0..40], 3, null, &p2pkh_script, &ones); // truncated
        self.push("", 3, null, &[_]u8{}, &ones); // the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

/// A standard 25-octet P2PKH `scriptPubKey`, the `scriptCode` a real signer
/// hands these functions. The old harness's script was always empty.
const p2pkh_script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x42} ** 20 ++ [_]u8{ 0x88, 0xac };

test "corpus: sighash seeds reach the decoder, and the counts are pinned" {
    const a = std.testing.allocator;
    var corpus: SighashCorpus = .{};
    var nonempty: usize = 0;
    var decoded: usize = 0;
    // ⛔ The numbers the empty input cannot produce, and that a bare
    // "decoded > 0" would not have held up: inputs walked out of the decoded
    // transactions, and — the point of this target — sighash digests actually
    // computed. Both were 0 for every input this harness ever ran.
    var vin_total: usize = 0;
    var legacy_digests: usize = 0;
    var bip143_digests: usize = 0;
    var bip341_digests: usize = 0;
    var script_octets: usize = 0;
    // ⛔ The knobs drawn AFTER the two byte draws. Every one of them reads a
    // tail word, so they are alive — but "alive" is not "varying", and two of
    // them were CONSTANT: `structured_ht32` and `structured_ht8` were 4 of 4
    // when this was first measured, so the two `smith.value(u32)` /
    // `smith.value(u8)` arbitrary arms had never run. `which_hist` was
    // 1 / 0 / 0 / 5 for the same reason. Pinned as histograms rather than
    // totals: a total cannot tell "both arms ran" from "one arm ran twice".
    var which_hist = [_]usize{0} ** 4;
    var structured_ht32: usize = 0;
    var anyonecanpay: usize = 0;
    var structured_ht8: usize = 0;
    var clone_assertions: usize = 0;
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [tx.fuzz_tx_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (len > 4) {
            const which = smith.valueRangeAtMost(u8, 0, 3);
            which_hist[which] += 1;
            buf[4] = switch (which) {
                0 => smith.valueRangeAtMost(u8, 0, 4),
                1 => 0x00,
                2 => smith.value(u8),
                else => buf[4],
            };
        }
        var r = deserializePartial(a, buf[0..len]) catch continue;
        defer r.tx.deinit(a);
        decoded += 1;
        vin_total += r.tx.vin.len;
        var script_buf: [96]u8 = undefined;
        const script = script_buf[0..smith.slice(&script_buf)];
        script_octets += script.len;
        const idx: usize = smith.valueRangeAtMost(u8, 0, 5);
        const amount = smith.value(i64);
        const ht32: u32 = if (smith.value(bool)) blk: {
            structured_ht32 += 1;
            const base = @as(u32, smith.valueRangeAtMost(u8, 0, 3));
            const acp: u32 = if (smith.value(bool)) 0x80 else 0;
            if (acp != 0) anyonecanpay += 1;
            break :blk base | acp;
        } else smith.value(u32);
        if (legacy.sighash(a, r.tx, idx, script, ht32)) |_| legacy_digests += 1 else |_| {}
        // ⚠ From here the draw order must match `fuzzSighash` exactly, or the
        // knobs after it are measured against words they never read.
        if (bip143.sighash(a, r.tx, idx, script, amount, ht32)) |_| {
            bip143_digests += 1;
            if (smith.value(bool)) clone_assertions += 1;
        } else |_| {}
        var spent: [8]TxOut = undefined;
        if (r.tx.vin.len <= spent.len) {
            for (spent[0..r.tx.vin.len]) |*o| o.* = .{ .value = smith.value(i64), .script_pubkey = script };
            const valid_ht = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };
            const ht8: u8 = if (smith.value(bool)) blk: {
                structured_ht8 += 1;
                break :blk valid_ht[smith.valueRangeAtMost(u8, 0, valid_ht.len - 1)];
            } else smith.value(u8);
            if (bip341.sighash(a, r.tx, idx, ht8, spent[0..r.tx.vin.len])) |_| {
                bip341_digests += 1;
                if (smith.value(bool)) clone_assertions += 1;
                if (smith.value(bool)) clone_assertions += 1;
            } else |_| {}
        }
    }
    try std.testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try std.testing.expectEqual(@as(usize, 6), decoded);
    try std.testing.expectEqual(@as(usize, 9), vin_total);
    try std.testing.expectEqual(@as(usize, 125), script_octets);
    // ⛔ These three were **0** for every input this target ever ran, because
    // the length draw capped the transaction at 3 octets. They were 3 / 3 / 3
    // over the seven-seed corpus of 2026-09-07; the two `arbitrary` seeds
    // added on 2026-09-08 decode too, hence 5.
    try std.testing.expectEqual(@as(usize, 5), legacy_digests);
    try std.testing.expectEqual(@as(usize, 5), bip143_digests);
    try std.testing.expectEqual(@as(usize, 5), bip341_digests);
    // Measured 2026-09-08. Before the two `arbitrary` seeds and the arm-1/arm-2
    // seeds: which = {1, 0, 0, 5}, structured_ht32 = 4 of 4, structured_ht8 =
    // 4 of 4, anyonecanpay = 3, clone assertions = 9. After:
    try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 1, 1, 7 }, &which_hist);
    try std.testing.expectEqual(@as(usize, 4), structured_ht32);
    try std.testing.expectEqual(@as(usize, 3), anyonecanpay);
    try std.testing.expectEqual(@as(usize, 4), structured_ht8);
    try std.testing.expectEqual(@as(usize, 9), clone_assertions);
}
