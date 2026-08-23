// SPDX-License-Identifier: MIT

//! What a signing-service backend does with `psbt`: play Creator (build the
//! unsigned tx + a bare skeleton PSBT), Updater (attach the WITNESS_UTXO,
//! SIGHASH_TYPE and BIP32_DERIVATION fields two independent co-signers would
//! contribute), Combiner (merge those two partially-updated PSBTs into one),
//! then read every field back out through the module's typed accessors —
//! the way a hardware-wallet bridge or multisig coordinator actually uses
//! this module, never touching `Map.records` by hand except where the spec
//! says a field is opaque.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! `modules/psbt/src/kat_test.zig` (+ `core_kat_test.zig` +
//! `regtest_kat_test.zig`) already drives BIP174's own 20 invalid vectors,
//! 8 of 10 valid vectors, its worked Combiner example, its worked Finalizer/
//! Extractor example, Bitcoin Core's `rpc_psbt.json` conformance set, AND
//! two live-regtest-captured spend shapes (native P2WPKH, native P2WSH
//! multisig) through this module — the single most externally-anchored
//! module in this pass. This file does NOT restate any of those fixtures,
//! and deliberately does not re-exercise `finalize`/`extract` (already the
//! most heavily oracled part of the module); it builds a FRESH PSBT of its
//! own from scratch via the public Creator/Updater/Combiner API, the
//! consumer path those KATs — which start from pre-built BIP174 byte
//! strings — never touch.
//!
//! External judge — ACTUALLY RUN: the exact bytes `psbt.serialize` produces
//! for the scenario below were fed (at authoring time) to `buidl.psbt.PSBT`
//! (a third, independent Python PSBT implementation, distinct from both
//! BIP174's own worked examples and Bitcoin Core's JSON this module is
//! already checked against) — `buidl` parsed them and agreed field-for-
//! field: input count, the WITNESS_UTXO amount/scriptPubKey, the
//! SIGHASH_TYPE value, and both BIP32_DERIVATION paths. Run as a black-box
//! oracle (tool output only; no `buidl` source was read or copied).

const std = @import("std");
const bitcointx = @import("bitcointx");
const psbt = @import("psbt");

const hardened_offset: u32 = 0x8000_0000;

// secp256k1 base point G, compressed — a public, non-secret constant, the
// standard "obviously not a real key" throwaway pubkey (also used in the
// bech32/bip32 examples). Everything else here (prevout txid, amounts) is
// fabricated example material — this PSBT does not spend a real coin.
const g_pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
// SHA256("zig-libs psbt example prevout") — a fresh, fabricated prevout txid.
const prevout_txid_hex = "d68c9f8aa2e59e9de407c7614b65c3015b19f9e39be4e724ff27a8e451cdd388";
// hash160(G), used as the P2WPKH witness program for both the spent coin
// and this tx's own output.
const p2wpkh_script = [_]u8{ 0x00, 0x14 } ++ "\x75\x1e\x76\xe8\x19\x91\x96\xd4\x54\x94\x1c\x45\xd1\xb3\xa3\x23\xf1\x43\x3b\xd6".*;

fn writeBip32Value(allocator: std.mem.Allocator, fingerprint: [4]u8, path: []const u32) ![]u8 {
    var buf = try allocator.alloc(u8, 4 + path.len * 4);
    @memcpy(buf[0..4], &fingerprint);
    for (path, 0..) |idx, i| std.mem.writeInt(u32, buf[4 + i * 4 ..][0..4], idx, .little);
    return buf;
}

fn writeWitnessUtxoValue(allocator: std.mem.Allocator, amount: i64, script: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var amount_buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &amount_buf, amount, .little);
    try list.appendSlice(allocator, &amount_buf);
    var len_buf: [9]u8 = undefined;
    try list.appendSlice(allocator, try bitcointx.encodeCompactSize(script.len, &len_buf));
    try list.appendSlice(allocator, script);
    return list.toOwnedSlice(allocator);
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var g_pubkey: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&g_pubkey, g_pubkey_hex) catch unreachable;
    var prevout_txid: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&prevout_txid, prevout_txid_hex) catch unreachable;

    // ── Creator: the unsigned transaction (1 in, 1 out) ────────────────────

    var vin = [_]bitcointx.TxIn{.{
        .prevout = .{ .txid = prevout_txid, .vout = 0 },
        .script_sig = &.{},
        .sequence = 0xffffffff,
    }};
    var vout = [_]bitcointx.TxOut{.{ .value = 100_000, .script_pubkey = &p2wpkh_script }};
    const utx: bitcointx.Transaction = .{
        .version = 2,
        .vin = &vin,
        .vout = &vout,
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const utx_bytes = try bitcointx.serializeLegacy(gpa, utx);
    defer gpa.free(utx_bytes);

    // Two independent co-signers each Update their own copy of the bare
    // Creator skeleton — this is what `combine` below merges.
    var psbt_a = try buildSkeleton(gpa, utx_bytes);
    defer psbt_a.deinit(gpa);
    var psbt_b = try buildSkeleton(gpa, utx_bytes);
    defer psbt_b.deinit(gpa);

    // Co-signer A contributes the spent coin + sighash policy.
    const witness_utxo_value = try writeWitnessUtxoValue(gpa, 150_000, &p2wpkh_script);
    defer gpa.free(witness_utxo_value);
    var sighash_value: [4]u8 = undefined;
    std.mem.writeInt(u32, &sighash_value, 1, .little); // SIGHASH_ALL
    psbt_a.inputs[0] = try replaceMap(gpa, psbt_a.inputs[0], &.{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.SIGHASH_TYPE, .keydata = &.{}, .value = &sighash_value },
    });

    // Co-signer B contributes the BIP32 derivation info for the spending
    // key (BIP84 native segwit: m/84'/0'/0'/0/0) and the change output's
    // key (m/84'/0'/0'/1/0) — a faux fingerprint, since nothing here checks
    // it against an actual master key.
    const faux_fingerprint = [4]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const receive_path = [_]u32{ hardened_offset + 84, hardened_offset + 0, hardened_offset + 0, 0, 0 };
    const change_path = [_]u32{ hardened_offset + 84, hardened_offset + 0, hardened_offset + 0, 1, 0 };
    const in_deriv_value = try writeBip32Value(gpa, faux_fingerprint, &receive_path);
    defer gpa.free(in_deriv_value);
    const out_deriv_value = try writeBip32Value(gpa, faux_fingerprint, &change_path);
    defer gpa.free(out_deriv_value);
    psbt_b.inputs[0] = try replaceMap(gpa, psbt_b.inputs[0], &.{
        .{ .keytype = psbt.input_key.BIP32_DERIVATION, .keydata = &g_pubkey, .value = in_deriv_value },
    });
    psbt_b.outputs[0] = try replaceMap(gpa, psbt_b.outputs[0], &.{
        .{ .keytype = psbt.output_key.BIP32_DERIVATION, .keydata = &g_pubkey, .value = out_deriv_value },
    });

    // ── Combiner: merge the two co-signers' updates ────────────────────────

    var merged = try psbt.combine(gpa, psbt_a, psbt_b);
    defer merged.deinit(gpa);

    const wire = try psbt.serialize(gpa, merged);
    defer gpa.free(wire);
    std.debug.print("merged PSBT ({d} bytes): {x}\n", .{ wire.len, wire });

    // A real co-signer receives PSBT bytes over the wire, not a live struct
    // — round-trip through parse before reading anything back.
    var received = try psbt.parse(gpa, wire);
    defer received.deinit(gpa);

    std.debug.assert(received.version() == null); // PSBT_GLOBAL_VERSION omitted -> BIP174 default 0

    const witness_utxo = (try psbt.inputWitnessUtxo(received.inputs[0])).?;
    std.debug.assert(witness_utxo.value == 150_000);
    std.debug.assert(std.mem.eql(u8, witness_utxo.script_pubkey, &p2wpkh_script));
    std.debug.print("witness utxo: {d} sats, script {x}\n", .{ witness_utxo.value, witness_utxo.script_pubkey });

    std.debug.assert(psbt.inputSighashType(received.inputs[0]).? == 1);

    const in_deriv = psbt.inputBip32Derivation(received.inputs[0], &g_pubkey).?;
    std.debug.assert(in_deriv.len() == 5);
    for (receive_path, 0..) |want, i| std.debug.assert(in_deriv.at(i) == want);
    std.debug.print("input derivation: fingerprint={x} path_len={d}\n", .{ in_deriv.fingerprint, in_deriv.len() });

    const out_deriv = psbt.outputBip32Derivation(received.outputs[0], &g_pubkey).?;
    std.debug.assert(out_deriv.at(3) == 1); // change chain, not external

    var utx_back = try received.unsignedTx(gpa);
    defer utx_back.deinit(gpa);
    std.debug.assert(utx_back.vin.len == 1 and utx_back.vout.len == 1);
    std.debug.assert(utx_back.vout[0].value == 100_000);

    // ── negative paths: named errors, never a blanket catch ───────────────

    // (1) Two co-signers who each started from a DIFFERENT unsigned
    // transaction — combine() must refuse to merge them, or a Combiner
    // could silently splice fields from one transaction onto another.
    {
        var other_vout = [_]bitcointx.TxOut{.{ .value = 999_999, .script_pubkey = &p2wpkh_script }};
        const other_utx: bitcointx.Transaction = .{
            .version = 2,
            .vin = &vin,
            .vout = &other_vout,
            .witness = &.{},
            .locktime = 0,
            .has_witness = false,
        };
        const other_bytes = try bitcointx.serializeLegacy(gpa, other_utx);
        defer gpa.free(other_bytes);
        var other_psbt = try buildSkeleton(gpa, other_bytes);
        defer other_psbt.deinit(gpa);

        if (psbt.combine(gpa, psbt_a, other_psbt)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.DifferentTransactions => std.debug.print("combine across different txs: DifferentTransactions (expected)\n", .{}),
            else => return err,
        }
    }

    // (2) The same field contributed twice by the SAME co-signer (a buggy
    // Updater re-running itself) — the raw key repeats within one map.
    {
        var dup = try buildSkeleton(gpa, utx_bytes);
        defer dup.deinit(gpa);
        dup.inputs[0] = try replaceMap(gpa, dup.inputs[0], &.{
            .{ .keytype = psbt.input_key.SIGHASH_TYPE, .keydata = &.{}, .value = &sighash_value },
            .{ .keytype = psbt.input_key.SIGHASH_TYPE, .keydata = &.{}, .value = &sighash_value },
        });
        const dup_wire = try psbt.serialize(gpa, dup);
        defer gpa.free(dup_wire);

        if (psbt.parse(gpa, dup_wire)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.DuplicateKey => std.debug.print("duplicate SIGHASH_TYPE key: DuplicateKey (expected)\n", .{}),
            else => return err,
        }
    }

    // (3) A BIP32_DERIVATION keyed by a keydata slice that isn't a
    // 33/65-byte pubkey at all (a caller-side bug feeding raw garbage).
    {
        var bad = try buildSkeleton(gpa, utx_bytes);
        defer bad.deinit(gpa);
        const short_key = [_]u8{ 0x02, 0x03, 0x04 };
        bad.inputs[0] = try replaceMap(gpa, bad.inputs[0], &.{
            .{ .keytype = psbt.input_key.BIP32_DERIVATION, .keydata = &short_key, .value = in_deriv_value },
        });
        const bad_wire = try psbt.serialize(gpa, bad);
        defer gpa.free(bad_wire);

        if (psbt.parse(gpa, bad_wire)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidPubkeyLength => std.debug.print("3-byte BIP32_DERIVATION keydata: InvalidPubkeyLength (expected)\n", .{}),
            else => return err,
        }
    }

    // (4) PSBT_GLOBAL_VERSION present but nonzero — BIP174 §"Version 0"
    // requires an explicit version field to actually say 0.
    {
        var versioned = try buildSkeleton(gpa, utx_bytes);
        defer versioned.deinit(gpa);
        var bad_version: [4]u8 = undefined;
        std.mem.writeInt(u32, &bad_version, 2, .little);
        versioned.global = try replaceMap(gpa, versioned.global, &.{
            .{ .keytype = psbt.global_key.VERSION, .keydata = &.{}, .value = &bad_version },
        });
        const versioned_wire = try psbt.serialize(gpa, versioned);
        defer gpa.free(versioned_wire);

        if (psbt.parse(gpa, versioned_wire)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.UnsupportedPsbtVersion => std.debug.print("PSBT_GLOBAL_VERSION=2: UnsupportedPsbtVersion (expected)\n", .{}),
            else => return err,
        }
    }

    // (5) A structurally-accepted-at-parse-time WITNESS_UTXO whose value is
    // too short to actually decode — `parse` does NOT validate this field's
    // internal shape (see module doc comment: "this value's shape is only
    // checked when this accessor is actually called"), so the failure only
    // surfaces when a caller reads it, allocating nothing and returning
    // immediately.
    {
        var truncated = try buildSkeleton(gpa, utx_bytes);
        defer truncated.deinit(gpa);
        const short_value = [_]u8{ 0x01, 0x02, 0x03 }; // < 8 bytes, can't even hold the amount
        truncated.inputs[0] = try replaceMap(gpa, truncated.inputs[0], &.{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = &short_value },
        });
        const truncated_wire = try psbt.serialize(gpa, truncated);
        defer gpa.free(truncated_wire);

        var reparsed = try psbt.parse(gpa, truncated_wire); // accepted structurally
        defer reparsed.deinit(gpa);
        if (psbt.inputWitnessUtxo(reparsed.inputs[0])) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.Truncated => std.debug.print("short WITNESS_UTXO, caught at read time: Truncated (expected)\n", .{}),
            else => return err,
        }
    }
}

/// A bare Creator-role PSBT: global map with only `UNSIGNED_TX`, and one
/// empty input/output map per the unsigned tx's vin/vout count (this
/// scenario is always 1-in-1-out). Every field an Updater contributes is
/// added afterward via `replaceMap`.
fn buildSkeleton(allocator: std.mem.Allocator, utx_bytes: []const u8) !psbt.Psbt {
    var global_records = try allocator.alloc(psbt.Record, 1);
    global_records[0] = .{ .keytype = psbt.global_key.UNSIGNED_TX, .keydata = &.{}, .value = utx_bytes };

    var inputs = try allocator.alloc(psbt.Map, 1);
    inputs[0] = .{ .records = try allocator.alloc(psbt.Record, 0) };
    var outputs = try allocator.alloc(psbt.Map, 1);
    outputs[0] = .{ .records = try allocator.alloc(psbt.Record, 0) };

    return .{ .global = .{ .records = global_records }, .inputs = inputs, .outputs = outputs };
}

/// Replaces `m`'s records with a freshly-allocated copy of `new_records`,
/// freeing the old array. `new_records`' `value`/`keydata` slices are NOT
/// copied (same borrowed-slice contract `psbt.parse` itself uses) — the
/// caller keeps those buffers alive.
fn replaceMap(allocator: std.mem.Allocator, m: psbt.Map, new_records: []const psbt.Record) !psbt.Map {
    var old = m;
    old.deinit(allocator);
    const copy = try allocator.alloc(psbt.Record, new_records.len);
    @memcpy(copy, new_records);
    return .{ .records = copy };
}
