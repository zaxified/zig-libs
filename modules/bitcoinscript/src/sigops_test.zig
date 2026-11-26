// SPDX-License-Identifier: MIT
//! Tests for `sigops.zig`. The first block is Bitcoin Core's
//! `script_tests.cpp` `GetSigOpCount` unit test (accurate vs. inaccurate
//! multisig counts, the P2SH redeem-script path); the rest pin each branch of
//! `CountWitnessSigOps` / `GetTransactionSigOpCost` with hand-built values.

const std = @import("std");
const bitcointx = @import("bitcointx");
const sigops = @import("sigops.zig");
const flags_mod = @import("flags.zig");

const t = std.testing;

fn rep(comptime b: u8, comptime n: usize) [n]u8 {
    return @splat(b);
}

const dummy20 = rep(0x11, 20);
const dummy32 = rep(0x22, 32);
const push20 = [_]u8{20} ++ dummy20;
const push33 = [_]u8{33} ++ [_]u8{2} ++ dummy32;

// s1 = OP_1 <20B> <20B> OP_2 OP_CHECKMULTISIG
const s1_base = [_]u8{0x51} ++ push20 ++ push20 ++ [_]u8{ 0x52, 0xae };
// ... OP_IF OP_CHECKSIG OP_ENDIF
const s1 = s1_base ++ [_]u8{ 0x63, 0xac, 0x68 };

fn p2shOf(script: []const u8) [23]u8 {
    var out: [23]u8 = undefined;
    out[0] = 0xa9;
    out[1] = 0x14;
    @import("ripemd160").hash160(script, out[2..22]);
    out[22] = 0x87;
    return out;
}

test "Core GetSigOpCount: empty, accurate vs inaccurate multisig" {
    try t.expectEqual(@as(u64, 0), sigops.countScript(&.{}, false));
    try t.expectEqual(@as(u64, 0), sigops.countScript(&.{}, true));
    try t.expectEqual(@as(u64, 2), sigops.countScript(&s1_base, true));
    try t.expectEqual(@as(u64, 3), sigops.countScript(&s1, true));
    try t.expectEqual(@as(u64, 21), sigops.countScript(&s1, false));
}

test "Core GetSigOpCount: P2SH redeem-script path" {
    const p2sh = p2shOf(&s1);
    // scriptSig = OP_0 <push of s1>  (s1 is 70 bytes: a direct push)
    const sig = [_]u8{0x00} ++ [_]u8{s1.len} ++ s1;
    try t.expectEqual(@as(u64, 3), sigops.countP2sh(&p2sh, &sig));

    // 1-of-3 bare multisig as redeem script
    const s2 = [_]u8{0x51} ++ push33 ++ push33 ++ push33 ++ [_]u8{ 0x53, 0xae };
    try t.expectEqual(@as(u64, 3), sigops.countScript(&s2, true));
    try t.expectEqual(@as(u64, 20), sigops.countScript(&s2, false));
    const p2sh2 = p2shOf(&s2);
    // a P2SH output scanned as an ordinary script has no sigops
    try t.expectEqual(@as(u64, 0), sigops.countScript(&p2sh2, true));
    try t.expectEqual(@as(u64, 0), sigops.countScript(&p2sh2, false));
    const sig2 = [_]u8{0x51} ++ push20 ++ push20 ++ [_]u8{ 0x4c, s2.len } ++ s2;
    try t.expectEqual(@as(u64, 3), sigops.countP2sh(&p2sh2, &sig2));
}

test "countP2sh: a non-push opcode or a truncated push in scriptSig counts 0" {
    const p2sh = p2shOf(&s1);
    try t.expectEqual(@as(u64, 0), sigops.countP2sh(&p2sh, &[_]u8{ 0x76, s1.len } ++ s1)); // OP_DUP first
    try t.expectEqual(@as(u64, 0), sigops.countP2sh(&p2sh, &[_]u8{ 0x00, 0x05, 0xac })); // truncated push
    // a non-P2SH scriptPubKey is counted accurately by itself
    try t.expectEqual(@as(u64, 3), sigops.countScript(&s1, true));
    try t.expectEqual(@as(u64, 3), sigops.countP2sh(&s1, &.{}));
}

test "countScript: a truncated push ends the walk, earlier sigops stay counted" {
    try t.expectEqual(@as(u64, 1), sigops.countScript(&[_]u8{ 0xac, 0x4c }, false));
    try t.expectEqual(@as(u64, 1), sigops.countScript(&[_]u8{ 0xac, 0x05, 0xac, 0xac }, false));
}

test "countScript: only an immediately preceding OP_1..OP_16 sets the accurate count" {
    // OP_16 OP_NOP OP_CHECKMULTISIG -> 20 (accurate falls back to the maximum)
    try t.expectEqual(@as(u64, 20), sigops.countScript(&[_]u8{ 0x60, 0x61, 0xaf }, true));
    try t.expectEqual(@as(u64, 16), sigops.countScript(&[_]u8{ 0x60, 0xaf }, true));
    // OP_0 before it is not OP_1..OP_16
    try t.expectEqual(@as(u64, 20), sigops.countScript(&[_]u8{ 0x00, 0xae }, true));
    // OP_CHECKSIGVERIFY counts too
    try t.expectEqual(@as(u64, 2), sigops.countScript(&[_]u8{ 0xad, 0xac }, true));
}

const wp_keyhash = [_]u8{ 0x00, 0x14 } ++ dummy20;
const wscript = [_]u8{ 0x52, 0xae, 0xac }; // OP_2 OP_CHECKMULTISIG OP_CHECKSIG -> 2 + 1
const wp_scripthash = [_]u8{ 0x00, 0x20 } ++ dummy32;
const wp_taproot = [_]u8{ 0x51, 0x20 } ++ dummy32;

const f_witness: flags_mod.ScriptFlags = .{ .witness = true };

test "witnessCount: native v0 key-hash, v0 script-hash, taproot, unknown" {
    const empty: []const []const u8 = &.{};
    try t.expectEqual(@as(u64, 1), sigops.witnessCount(&.{}, &wp_keyhash, empty, f_witness));
    const items = [_][]const u8{ &dummy20, &wscript };
    try t.expectEqual(@as(u64, 3), sigops.witnessCount(&.{}, &wp_scripthash, &items, f_witness));
    // empty witness stack: no script to count
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&.{}, &wp_scripthash, empty, f_witness));
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&.{}, &wp_taproot, &items, f_witness));
    const v2 = [_]u8{ 0x52, 0x02, 0xaa, 0xbb };
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&.{}, &v2, &items, f_witness));
    // flag off
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&.{}, &wp_keyhash, empty, .{}));
}

test "witnessCount: P2SH-wrapped witness programs" {
    const items = [_][]const u8{ &dummy20, &wscript };
    const sig_wsh = [_]u8{wp_scripthash.len} ++ wp_scripthash;
    const sig_wpkh = [_]u8{wp_keyhash.len} ++ wp_keyhash;
    const p2sh_wsh = p2shOf(&wp_scripthash);
    const p2sh_wpkh = p2shOf(&wp_keyhash);
    try t.expectEqual(@as(u64, 3), sigops.witnessCount(&sig_wsh, &p2sh_wsh, &items, f_witness));
    try t.expectEqual(@as(u64, 1), sigops.witnessCount(&sig_wpkh, &p2sh_wpkh, &items, f_witness));
    // scriptSig not push-only -> 0
    const bad = [_]u8{0x76} ++ sig_wpkh;
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&bad, &p2sh_wpkh, &items, f_witness));
    // last push is not a witness program -> 0
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&[_]u8{ 0x01, 0xac }, &p2sh_wpkh, &items, f_witness));
    // undecodable scriptSig: not push-only
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&[_]u8{ 0x05, 0x01 }, &p2sh_wpkh, &items, f_witness));
}

fn mkTx(vin: []bitcointx.TxIn, vout: []bitcointx.TxOut, witness: []bitcointx.Witness) bitcointx.Transaction {
    return .{ .version = 2, .vin = vin, .vout = vout, .witness = witness, .locktime = 0, .has_witness = witness.len != 0 };
}

test "transactionCost: legacy x4, P2SH x4, witness x1; coinbase legacy only" {
    const p2sh_spk = p2shOf(&s1);
    const sig_p2sh = [_]u8{ 0x00, s1.len } ++ s1; // redeem script counts 3
    const sig_legacy = [_]u8{ 0xac, 0xad }; // 2 legacy sigops in a scriptSig
    var vin = [_]bitcointx.TxIn{
        .{ .prevout = .{ .txid = @splat(1), .vout = 0 }, .script_sig = &sig_p2sh, .sequence = 0 },
        .{ .prevout = .{ .txid = @splat(2), .vout = 0 }, .script_sig = &sig_legacy, .sequence = 0 },
        .{ .prevout = .{ .txid = @splat(3), .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
        .{ .prevout = .{ .txid = @splat(4), .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
    };
    const out_spk = [_]u8{ 0x76, 0xa9, 0x14 } ++ dummy20 ++ [_]u8{ 0x88, 0xac }; // 1 legacy sigop
    var vout = [_]bitcointx.TxOut{.{ .value = 1, .script_pubkey = &out_spk }};
    const w_items = [_][]const u8{ &dummy20, &wscript };
    var wit = [_]bitcointx.Witness{
        .{ .items = &.{} },
        .{ .items = &.{} },
        .{ .items = @constCast(&[_][]const u8{ &dummy20, &dummy20 }) },
        .{ .items = @constCast(&w_items) },
    };
    const spent = [_]bitcointx.TxOut{
        .{ .value = 1, .script_pubkey = &p2sh_spk },
        .{ .value = 1, .script_pubkey = &[_]u8{0x51} },
        .{ .value = 1, .script_pubkey = &wp_keyhash },
        .{ .value = 1, .script_pubkey = &wp_scripthash },
    };
    const tx = mkTx(&vin, &vout, &wit);
    // legacy: scriptSig#2 has 2, output has 1; the P2SH scriptSig push data
    // is not scanned by the legacy walk (it is one data push: `0x00 <70 bytes>`,
    // whose payload is skipped) -> 3 legacy sigops, 12 cost units.
    try t.expectEqual(@as(u64, 3), sigops.legacyCount(tx));
    try t.expectEqual(@as(u64, 3), try sigops.p2shCount(tx, &spent));
    const full = try sigops.transactionCost(tx, &spent, .{ .p2sh = true, .witness = true });
    try t.expectEqual(@as(u64, 3 * 4 + 3 * 4 + 1 + 3), full);
    // without p2sh / witness flags only the legacy part remains
    try t.expectEqual(@as(u64, 12), try sigops.transactionCost(tx, &spent, .{}));
    try t.expectEqual(@as(u64, 12 + 12), try sigops.transactionCost(tx, &spent, .{ .p2sh = true }));
    try t.expectError(error.SpentOutputsMismatch, sigops.transactionCost(tx, spent[0..2], .{ .p2sh = true }));

    // coinbase: only the legacy count, and no spent outputs are needed
    var cb_in = [_]bitcointx.TxIn{.{ .prevout = .{ .txid = @splat(0), .vout = 0xffffffff }, .script_sig = &sig_legacy, .sequence = 0 }};
    const cb = mkTx(&cb_in, &vout, &.{});
    try t.expectEqual(@as(u64, 3 * 4), try sigops.transactionCost(cb, &.{}, .{ .p2sh = true, .witness = true }));
    try t.expectEqual(@as(u64, 0), try sigops.p2shCount(cb, &.{.{ .value = 0, .script_pubkey = &p2sh_spk }}));
}

test "mutation 2026-11-25: sigops count boundaries, the P2SH shape and the scriptSig walk" {
    // OP_1 OP_CHECKMULTISIG: the accurate count is 1 (OP_1 itself is a key count).
    try t.expectEqual(@as(u64, 1), sigops.countScript(&[_]u8{ 0x51, 0xae }, true));
    try t.expectEqual(@as(u64, 20), sigops.countScript(&[_]u8{ 0x51, 0xae }, false));

    // A scriptPubKey one byte off the P2SH shape is counted as itself (0 sigops),
    // never through scriptSig's last push (which would count 3).
    const p2sh = p2shOf(&s1);
    const sig = [_]u8{ 0x00, s1.len } ++ s1;
    try t.expectEqual(@as(u64, 3), sigops.countP2sh(&p2sh, &sig));
    const longer = p2sh ++ [_]u8{0x00};
    var b0 = p2sh;
    b0[0] = 0xaa;
    var b1 = p2sh;
    b1[1] = 0x15;
    var b22 = p2sh;
    b22[22] = 0x88;
    for ([_][]const u8{ &longer, &b0, &b1, &b22 }) |spk| {
        try t.expectEqual(@as(u64, 0), sigops.countP2sh(spk, &sig));
    }
    // OP_16 in scriptSig is a push; the redeem script behind it is still counted.
    try t.expectEqual(@as(u64, 3), sigops.countP2sh(&p2sh, &([_]u8{0x60} ++ sig)));
    // A push followed by OP_N: the last instruction has no data, the redeem script is empty.
    try t.expectEqual(@as(u64, 0), sigops.countP2sh(&p2sh, &(sig ++ [_]u8{0x51})));
    // A truncated push after the redeem script: undecodable, 0 (not the redeem script's 3).
    try t.expectEqual(@as(u64, 0), sigops.countP2sh(&p2sh, &(sig ++ [_]u8{0x4c})));

    // witnessCount: OP_16 is push-only; a witness program followed by OP_1 is not "the last push";
    // a scriptSig program under a scriptPubKey that is not P2SH counts nothing.
    const items = [_][]const u8{ &dummy20, &wscript };
    const sig_wpkh = [_]u8{wp_keyhash.len} ++ wp_keyhash;
    const p2sh_wpkh = p2shOf(&wp_keyhash);
    try t.expectEqual(@as(u64, 1), sigops.witnessCount(&([_]u8{0x60} ++ sig_wpkh), &p2sh_wpkh, &items, f_witness));
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&(sig_wpkh ++ [_]u8{0x51}), &p2sh_wpkh, &items, f_witness));
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ dummy20 ++ [_]u8{ 0x88, 0xac };
    try t.expectEqual(@as(u64, 0), sigops.witnessCount(&sig_wpkh, &p2pkh, &items, f_witness));
}

test "mutation 2026-11-25: legacyCount counts inaccurately, p2shCount/transactionCost shape rules" {
    const multisig = [_]u8{ 0x51, 0xae }; // 1 accurate, 20 inaccurate
    var vin_a = [_]bitcointx.TxIn{.{ .prevout = .{ .txid = @splat(1), .vout = 0 }, .script_sig = &multisig, .sequence = 0 }};
    var vout_a = [_]bitcointx.TxOut{.{ .value = 1, .script_pubkey = &.{} }};
    try t.expectEqual(@as(u64, 20), sigops.legacyCount(mkTx(&vin_a, &vout_a, &.{})));
    var vin_b = [_]bitcointx.TxIn{.{ .prevout = .{ .txid = @splat(1), .vout = 0 }, .script_sig = &.{}, .sequence = 0 }};
    var vout_b = [_]bitcointx.TxOut{.{ .value = 1, .script_pubkey = &multisig }};
    try t.expectEqual(@as(u64, 20), sigops.legacyCount(mkTx(&vin_b, &vout_b, &.{})));

    const p2sh_spk = p2shOf(&s1);
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ dummy20 ++ [_]u8{ 0x88, 0xac }; // 1 sigop as a script
    const redeem_sig = [_]u8{ 0x00, s1.len } ++ s1;
    // A mismatched spent-outputs slice is an error of p2shCount itself.
    try t.expectError(error.SpentOutputsMismatch, sigops.p2shCount(mkTx(&vin_b, &vout_b, &.{}), &.{}));
    // A spent output that is not P2SH adds nothing, whatever it contains.
    const spent_p2pkh = [_]bitcointx.TxOut{.{ .value = 1, .script_pubkey = &p2pkh }};
    try t.expectEqual(@as(u64, 0), try sigops.p2shCount(mkTx(&vin_b, &vout_b, &.{}), &spent_p2pkh));
    // A coinbase has no spent output to speak of: 0 even when its scriptSig looks like a redeem push.
    var cb_in = [_]bitcointx.TxIn{.{ .prevout = .{ .txid = @splat(0), .vout = 0xffffffff }, .script_sig = &redeem_sig, .sequence = 0 }};
    const cb = mkTx(&cb_in, &vout_b, &.{});
    const spent_p2sh = [_]bitcointx.TxOut{.{ .value = 0, .script_pubkey = &p2sh_spk }};
    try t.expectEqual(@as(u64, 0), try sigops.p2shCount(cb, &spent_p2sh));
    // transactionCost: the length check holds without the p2sh flag too.
    var vin_c = [_]bitcointx.TxIn{
        .{ .prevout = .{ .txid = @splat(1), .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
        .{ .prevout = .{ .txid = @splat(2), .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
    };
    try t.expectError(error.SpentOutputsMismatch, sigops.transactionCost(mkTx(&vin_c, &vout_b, &.{}), &spent_p2pkh, .{}));
    // A transaction whose witness slice is shorter than its inputs (here empty) is counted, not indexed.
    const spent_wpkh = [_]bitcointx.TxOut{.{ .value = 1, .script_pubkey = &wp_keyhash }};
    try t.expectEqual(@as(u64, 20 * 4 + 1), try sigops.transactionCost(mkTx(&vin_a, &vout_a, &.{}), &spent_wpkh, f_witness));
}
