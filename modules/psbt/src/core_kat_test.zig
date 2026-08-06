// SPDX-License-Identifier: MIT
//! Byte-exact checks against `core_kat_vectors.zig` -- Bitcoin Core's
//! `test/functional/data/rpc_psbt.json`, a SEPARATE external oracle from
//! BIP174 itself (`kat_vectors.zig`/`kat_test.zig`). See that file's doc
//! comment for provenance and `modules/psbt/NOTICE` for attribution.
//!
//! ## What this closes, and what it doesn't
//!
//! This was commissioned to close the gap `ANCHOR-TASKS.tsv`'s `psbt` row
//! named: P2WPKH and native P2WSH multisig finalization had no published
//! vector, only self-authored `finalize_test.zig` coverage. Core's own
//! `finalizer`/`extractor` entries were checked FIRST, byte-for-byte,
//! against `kat_vectors.zig`'s `finalize_combined_hex`/`finalize_finalized_hex`/
//! `finalize_extracted_tx_hex` -- **they are identical**. Core's functional
//! test simply reuses BIP174's own worked example (bare P2SH 2-of-2 +
//! P2SH-P2WSH 2-of-2) rather than adding new spend shapes. So: the
//! P2WPKH/native-P2WSH finalizer gap is **NOT closed by this JSON** --
//! see `ANCHOR-TASKS.tsv` for the honest re-pricing. What Core's JSON DOES
//! give this module, for the first time, is external (non-BIP174) coverage
//! of the raw `parse`/`invalid`/`valid` wire-format surface -- see below.
//!
//! ## Three real findings from working through `invalid`/`invalid_with_msg`
//!
//! 1. **A genuine BIP174 gap, now fixed.** `invalid[19]` and `invalid[42]`
//!    are ordinary-looking v0 PSBTs whose only defect is `PSBT_GLOBAL_VERSION`
//!    set to a nonzero value (1 and 2). BIP174 §"Version 0" is unambiguous:
//!    "Version 0 PSBTs must either omit PSBT_GLOBAL_VERSION or include it and
//!    set it to 0." `root.zig`'s `validateGlobalMap` checked the VERSION
//!    field's *shape* (exactly 4 bytes) but never its *value* -- any declared
//!    version silently parsed as if it were 0. Fixed: `parse` now rejects a
//!    nonzero `PSBT_GLOBAL_VERSION` with `error.UnsupportedPsbtVersion`. These
//!    two Core vectors are this fix's external oracle (test group A below).
//!
//! 2. **Everything else Core's `invalid`/`invalid_with_msg` sets exercise
//!    that this module still accepts is out of its declared scope, not a
//!    bug.** Every remaining case was individually decoded (its keytypes
//!    inspected directly, not guessed from Core's message) and falls into
//!    exactly one bucket: BIP371 Taproot single-sig fields (`0x13`-`0x18`,
//!    `0x5`-`0x7` at output scope), MuSig2 fields (`0x1a`-`0x1c`, a BIP-374-ish
//!    proposal Core validates), BIP370 (PSBTv2) fields coexisting with or
//!    instead of this module's v0 fields, or BIP174 §"Signer"'s TXID-of-
//!    NON_WITNESS_UTXO-matches-prevout cross-check (a Signer-role
//!    responsibility per the BIP's own text, and Signer is explicitly
//!    deferred here -- SPEC.md). None of this is validated by BIP174 v0's
//!    own wire-format rules, which is all `parse` implements; accepting it
//!    as opaque passthrough is the documented, correct behavior (SPEC.md
//!    "Known vs. unknown key types"), not a security hole -- `finalize`
//!    never consumes any of these fields. Test groups B/C below assert this
//!    explicitly (ACCEPT, not reject) so the claim is checked, not assumed.
//!
//! 3. **`valid[5]` hits the ALREADY-DOCUMENTED `bitcointx` 0-vin/BIP144-marker
//!    ambiguity, via a new error code.** `kat_vectors.zig`'s BIP174 "PSBT with
//!    0 inputs" case is the same root cause (`error.InvalidWitnessFlag`);
//!    `valid[5]`'s would-be BIP144 flag byte happens to be `0x01`, a
//!    syntactically legal flag, so `bitcointx.deserialize` commits further
//!    into the segwit-parse path before running out of bytes, and fails with
//!    `error.TooManyItems` instead. Still fail-closed, same underlying
//!    limitation, not a new independent bug -- test group E below.
//!
//! `invalid_with_msg`: of the 23, only 4 are rejected by `parse` at all
//! (`{0, 20, 21, 22}`); of those, `{20, 21, 22}` are rejected for a genuinely
//! defensible reason (`error.UnsupportedPsbtVersion` on a PSBTv2-marked
//! PSBT -- correct, even though Core's own stated reason is more specific).
//! `invalid_with_msg[0]` is rejected too, but *coincidentally*: it is
//! fuzzer-generated garbage (its `PSBT_GLOBAL_UNSIGNED_TX` value is not a
//! parseable transaction at all), so `error.Truncated` fires from the
//! unrelated "not enough bytes for the input/output maps the (garbage)
//! unsigned tx implies" path -- NOT because this module validates Taproot
//! BIP32 keypath length (it doesn't; `0x16` is opaque here). Test group D
//! below documents this explicitly rather than claiming credit for it.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const psbt = @import("root.zig");
const vectors = @import("core_kat_vectors.zig");

fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

// ── A: the real bug -- PSBT_GLOBAL_VERSION must be 0 (BIP174 §"Version 0") ──

test "Core invalid[]: BIP174-v0-scope violations are rejected (includes the PSBT_GLOBAL_VERSION!=0 fix's own external oracle)" {
    const allocator = testing.allocator;
    for (vectors.invalid_v0_scope) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        if (psbt.parse(allocator, raw)) |result| {
            var r = result;
            r.deinit(allocator);
            std.debug.print("FAIL (accepted a Core invalid[] vector): core_index={d}\n", .{case.core_index});
            return error.TestUnexpectedSuccess;
        } else |_| {}
    }
}

test "Core invalid[19] and invalid[42]: PSBT_GLOBAL_VERSION=1/2 specifically rejected with error.UnsupportedPsbtVersion" {
    const allocator = testing.allocator;
    for (vectors.invalid_v0_scope) |case| {
        if (case.core_index != 19 and case.core_index != 42) continue;
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        try testing.expectError(error.UnsupportedPsbtVersion, psbt.parse(allocator, raw));
    }
}

// ── B/C: out-of-scope BIP370/BIP371/MuSig2/Signer-role content -- ACCEPTED, not a bug ──

test "Core invalid[]: BIP370/BIP371/MuSig2/Signer-role content is accepted as opaque passthrough (documented scope cut, not a bug)" {
    const allocator = testing.allocator;
    for (vectors.invalid_out_of_scope) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        var result = psbt.parse(allocator, raw) catch |err| {
            std.debug.print(
                "FAIL (expected ACCEPT as out-of-scope [{s}], but parse rejected): core_index={d} err={}\n",
                .{ case.reason, case.core_index, err },
            );
            return err;
        };
        // Round-trips too -- opaque passthrough must still be byte-exact.
        const reser = try psbt.serialize(allocator, result);
        defer allocator.free(reser);
        try testing.expectEqualSlices(u8, raw, reser);
        result.deinit(allocator);
    }
}

test "Core invalid_with_msg: 4 of 23 rejected (3 defensibly, 1 coincidentally); the other 19 are out-of-scope Taproot/MuSig2 content, accepted" {
    const allocator = testing.allocator;
    for (vectors.invalid_with_msg) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        const result = psbt.parse(allocator, raw);
        switch (case.core_index) {
            20, 21, 22 => {
                // Defensible: parse detects the PSBTv2 marker itself, even
                // though Core's own stated reason is more specific.
                testing.expectError(error.UnsupportedPsbtVersion, result) catch |err| {
                    std.debug.print("FAIL: core_index={d} (core msg: \"{s}\")\n", .{ case.core_index, case.core_message });
                    return err;
                };
            },
            0 => {
                // Coincidental (see file doc comment): fuzzer garbage, so
                // Truncated fires from the unrelated "not enough bytes for
                // the maps the garbage unsigned tx implies" path -- not
                // because this module validates Taproot BIP32 keypath length.
                testing.expectError(error.Truncated, result) catch |err| {
                    std.debug.print("FAIL: core_index=0 (core msg: \"{s}\")\n", .{case.core_message});
                    return err;
                };
            },
            else => {
                // Out-of-scope Taproot/MuSig2 content: must be ACCEPTED.
                if (result) |r| {
                    var res = r;
                    res.deinit(allocator);
                } else |err| {
                    std.debug.print(
                        "FAIL (expected ACCEPT as out-of-scope Taproot/MuSig2 content): core_index={d} (core msg: \"{s}\") err={}\n",
                        .{ case.core_index, case.core_message, err },
                    );
                    return err;
                }
            },
        }
    }
}

// ── B2: UTXO binding -- parse accepts (pure wire codec), finalize REJECTS ──

test "Core invalid[39]/invalid[40]: a UTXO that does not bind to its input is rejected by finalize (reclassified from invalid_out_of_scope)" {
    for (vectors.invalid_utxo_binding) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        const raw = try hexToBytesAlloc(allocator, case.hex);
        // `parse` is a pure BIP174-v0 wire codec and still accepts these --
        // asserted here so the reclassification is about WHERE the refusal
        // lives, not a silent change of the parse contract.
        const p = try psbt.parse(allocator, raw);
        try testing.expect(p.inputs.len >= 1);

        const results = try psbt.finalize(allocator, p);
        const got = results[0];
        const want: anyerror = switch (case.expect) {
            .outpoint_mismatch => error.UtxoOutpointMismatch,
            .missing_utxo => error.MissingUtxo,
        };
        if (got == null) {
            std.debug.print(
                "FAIL: core_index={d} finalize ACCEPTED a UTXO that does not bind to its input\n",
                .{case.core_index},
            );
            return error.TestUnexpectedResult;
        }
        testing.expectEqual(want, @as(anyerror, got.?)) catch |err| {
            std.debug.print("FAIL: core_index={d} got={any}\n", .{ case.core_index, got.? });
            return err;
        };
    }
}

// ── D: valid[] within scope -- parse -> serialize byte-exact ────────────

test "Core valid[]: parse -> serialize is byte-exact" {
    const allocator = testing.allocator;
    for (vectors.valid_accept) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        var p = psbt.parse(allocator, raw) catch |err| {
            std.debug.print("FAIL (rejected a Core valid[] vector): core_index={d}\n", .{case.core_index});
            return err;
        };
        defer p.deinit(allocator);
        const reser = try psbt.serialize(allocator, p);
        defer allocator.free(reser);
        testing.expectEqualSlices(u8, raw, reser) catch |err| {
            std.debug.print("FAIL (round-trip mismatch): core_index={d}\n", .{case.core_index});
            return err;
        };
    }
}

// ── E: valid[5] -- the same documented bitcointx ambiguity, new facet ────

test "Core valid[5]: same documented bitcointx 0-vin/BIP144-marker ambiguity as kat_vectors.zig's BIP174 case, via error.TooManyItems instead of error.InvalidWitnessFlag" {
    const allocator = testing.allocator;
    for (vectors.valid_known_ambiguity) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        try testing.expectError(error.TooManyItems, psbt.parse(allocator, raw));
    }
}

// ── F: valid[] that are pure PSBTv2 -- out of scope, correctly rejected ──

test "Core valid[] PSBTv2-only vectors: correctly rejected with error.UnsupportedPsbtVersion (BIP370 is out of scope, not a bug)" {
    const allocator = testing.allocator;
    for (vectors.valid_out_of_scope_psbtv2) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        testing.expectError(error.UnsupportedPsbtVersion, psbt.parse(allocator, raw)) catch |err| {
            std.debug.print("FAIL: core_index={d}\n", .{case.core_index});
            return err;
        };
    }
}
