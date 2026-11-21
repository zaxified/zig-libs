// SPDX-License-Identifier: MIT
//! Byte-exact checks against `core_kat_vectors.zig` -- Bitcoin Core's
//! `test/functional/data/rpc_psbt.json`, a SEPARATE external oracle from
//! BIP174 itself (`kat_vectors.zig`/`kat_test.zig`). See that file's doc
//! comment for provenance and `modules/psbt/NOTICE` for attribution.
//!
//! ## What this closes, and what it doesn't
//!
//! This was commissioned to close the gap this module's anchor record (`SPEC.md` § Anchoring)
//! named: P2WPKH and native P2WSH multisig finalization had no published
//! vector, only self-authored `finalize_test.zig` coverage. Core's own
//! `finalizer`/`extractor` entries were checked FIRST, byte-for-byte,
//! against `kat_vectors.zig`'s `finalize_combined_hex`/`finalize_finalized_hex`/
//! `finalize_extracted_tx_hex` -- **they are identical**. Core's functional
//! test simply reuses BIP174's own worked example (bare P2SH 2-of-2 +
//! P2SH-P2WSH 2-of-2) rather than adding new spend shapes. So: the
//! P2WPKH/native-P2WSH finalizer gap is **NOT closed by this JSON** --
//! see the anchor record in `SPEC.md` for the honest re-pricing. What Core's JSON DOES
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
//! 2. **BIP371 defects are rejected.** Core's 11 `invalid[]` taproot-field
//!    cases (28-35, 37, 38, 41) and `invalid_with_msg[0]`/`[1]` (taproot
//!    keypath length, empty tap tree) are refused by `parse`'s BIP371 field
//!    shapes (`bip371.zig`), each with a specific error. `invalid[39]`/`[40]`
//!    (a UTXO that does not bind to its input) are accepted by `parse`, a pure
//!    wire codec, and refused by `finalize` (group B2). **Everything else
//!    Core's `invalid`/`invalid_with_msg` sets exercise that this module
//!    accepts is out of its declared scope, not a bug.** Every remaining case
//!    was individually decoded (its keytypes inspected directly, not guessed
//!    from Core's message) and falls into exactly one bucket: MuSig2 fields
//!    (`0x1a`-`0x1c`, BIP373, which Core validates) or BIP370 (PSBTv2) fields
//!    coexisting with or instead of this module's v0 fields. None of this is
//!    validated by BIP174 v0's own wire-format rules; accepting it as opaque
//!    passthrough is the documented behaviour (SPEC.md "Known vs. unknown key
//!    types"), not a security hole -- `finalize` never consumes any of these
//!    fields. Test groups B/C below assert this explicitly (ACCEPT, not
//!    reject) so the claim is checked, not assumed.
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
//! `invalid_with_msg`: `{20, 21, 22}` are rejected with
//! `error.UnsupportedPsbtVersion` (the PSBTv2 marker; Core's own stated
//! reason is more specific), `[0]` with `error.InvalidFixedFieldLength` (the
//! BIP371 taproot BIP32 derivation shape), `[1]` with
//! `error.InvalidTapTree`; the rest are BIP373 MuSig2 field defects, rejected
//! with `InvalidKeyDataLength` / `InvalidFixedFieldLength` / `InvalidPublicKey`.

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

// ── B: BIP371 field defects -- REJECTED; C: out-of-scope BIP370 (PSBTv2) content -- ACCEPTED, not a bug ──

/// BIP371 field defects Core's `invalid` set lists; `parse` has validated these
/// since the BIP371 typed fields landed (`bip371.zig`), each with the error for
/// its defect. Indices are Core's `invalid[]`.
fn expectedTaprootRejection(core_index: usize) ?anyerror {
    return switch (core_index) {
        28, 29, 30, 32, 35 => error.InvalidFixedFieldLength, // key / script-sig / internal-key values of the wrong size
        31, 33, 34, 37, 38, 41 => error.InvalidKeyDataLength, // x-only key, key+leaf hash or control block of the wrong size
        else => null,
    };
}

test "Core invalid[]: BIP371 field defects are rejected with the specific error (formerly accepted as out of scope)" {
    const allocator = testing.allocator;
    var n: usize = 0;
    for (vectors.invalid_out_of_scope) |case| {
        if (!std.mem.eql(u8, case.reason, "taproot")) continue;
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        const want = expectedTaprootRejection(case.core_index) orelse return error.TestUnexpectedResult;
        testing.expectError(want, psbt.parse(allocator, raw)) catch |err| {
            std.debug.print("FAIL: core_index={d}\n", .{case.core_index});
            return err;
        };
        n += 1;
    }
    try testing.expectEqual(@as(usize, 11), n);
}

test "Core invalid[]: BIP370 (PSBTv2) field mixes are accepted as opaque passthrough (documented scope cut, not a bug)" {
    const allocator = testing.allocator;
    for (vectors.invalid_out_of_scope) |case| {
        if (std.mem.eql(u8, case.reason, "taproot")) continue;
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

test "Core invalid_with_msg: all 23 rejected (3 as PSBTv2, 2 BIP371 defects, 18 BIP373 MuSig2 defects)" {
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
                // "Input Taproot BIP32 keypath has an invalid length": the
                // BIP371 derivation value shape check (it used to be rejected
                // only coincidentally, as fuzzer garbage).
                testing.expectError(error.InvalidFixedFieldLength, result) catch |err| {
                    std.debug.print("FAIL: core_index=0 (core msg: \"{s}\")\n", .{case.core_message});
                    return err;
                };
            },
            1 => {
                // "Output Taproot tree must not be empty".
                testing.expectError(error.InvalidTapTree, result) catch |err| {
                    std.debug.print("FAIL: core_index=1 (core msg: \"{s}\")\n", .{case.core_message});
                    return err;
                };
            },
            else => {
                // BIP373 (MuSig2) field defects: rejected with the error each names.
                const want: ?anyerror = switch (case.core_index) {
                    2, 8, 10, 11, 13, 14 => error.InvalidKeyDataLength,
                    3, 4, 5, 6, 9, 16, 17, 18, 19 => error.InvalidPublicKey,
                    7, 12 => error.InvalidFixedFieldLength,
                    15 => null, // "Size of value was not the stated size": a framing error, whichever the parser names
                    else => return error.TestUnexpectedResult,
                };
                if (result) |r| {
                    var res = r;
                    res.deinit(allocator);
                    std.debug.print("FAIL (accepted a BIP373 defect): core_index={d} (core msg: \"{s}\")\n", .{ case.core_index, case.core_message });
                    return error.TestUnexpectedSuccess;
                } else |err| {
                    if (want) |w| testing.expectEqual(w, err) catch |e| {
                        std.debug.print("FAIL: core_index={d} (core msg: \"{s}\") got {}\n", .{ case.core_index, case.core_message, err });
                        return e;
                    };
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

        const results = try psbt.finalize(allocator, p, .{});
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
