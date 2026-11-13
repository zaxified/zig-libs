// SPDX-License-Identifier: MIT
//! `finalize` for P2TR script-path spends (BIP371 `TAP_LEAF_SCRIPT` +
//! `TAP_SCRIPT_SIG`). Constructed round trips, like `bitcoinscript`'s own
//! `tapscript_test.zig`: a real taproot output is built with `taproot`, the
//! tapscript sighash is signed with `bip340`, and `finalize` must assemble a
//! witness that its mandatory `verifyScript` pass accepts. The commitment math
//! and the Schnorr rules are anchored in those siblings' own vectors; what is
//! under test here is the PSBT side: which leaf is picked, the witness order,
//! the refusals and the field clearing.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const bitcoinscript = @import("bitcoinscript");
const bip340 = @import("bip340");
const taproot = @import("taproot");
const psbt = @import("root.zig");
const bip371 = psbt.bip371;

const tapscript = bitcoinscript.tapscript;

const Key = struct { sk: bip340.SecretKey, x: [32]u8 };

fn key(seed: u8) !Key {
    const sk = try bip340.SecretKey.fromBytes(@as([32]u8, @splat(seed)));
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &sk);
    return .{ .sk = sk, .x = kp.public.x };
}

fn checksigScript(a: Allocator, k: [32]u8) ![]u8 {
    return a.dupe(u8, &([_]u8{0x20} ++ k ++ [_]u8{0xac}));
}

fn multiA2of2(a: Allocator, k1: [32]u8, k2: [32]u8) ![]u8 {
    return a.dupe(u8, &([_]u8{0x20} ++ k1 ++ [_]u8{ 0xac, 0x20 } ++ k2 ++ [_]u8{ 0xba, 0x52, 0x9c }));
}

const Fixture = struct {
    ps: psbt.Psbt,
    tx: bitcointx.Transaction,
    spent: []bitcointx.TxOut,
    info: taproot.SpendInfo,
    internal: Key,
};

/// One P2TR input spending a taproot output committing to `scripts` (depth-first
/// list `depths`), with every leaf and the internal key recorded as an Updater would.
fn fixture(a: Allocator, scripts: []const []const u8, depths: []const u8) !Fixture {
    const internal = try key(1);
    var list: std.ArrayList(taproot.DepthLeaf) = .empty;
    for (scripts, depths) |s, d| try list.append(a, .{ .depth = d, .script = s });
    const info = try taproot.buildFromLeaves(a, .{ .x = internal.x }, list.items);

    var spk: [34]u8 = undefined;
    spk[0] = 0x51;
    spk[1] = 0x20;
    @memcpy(spk[2..], &info.output.x);
    const spent = try a.alloc(bitcointx.TxOut, 1);
    spent[0] = .{ .value = 20000, .script_pubkey = try a.dupe(u8, &spk) };

    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = @as([32]u8, @splat(0x77)), .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 19000, .script_pubkey = &.{} };
    const tx: bitcointx.Transaction = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };

    var ps = try psbt.fromUnsignedTx(a, tx);
    try psbt.setInputWitnessUtxo(a, &ps, 0, spent[0]);
    try bip371.setInputTapInternalKey(a, &ps, 0, internal.x);
    if (info.merkle_root) |r| try bip371.setInputTapMerkleRoot(a, &ps, 0, r);
    for (info.leaves, 0..) |leaf, i| {
        const cb = try info.controlBlockAlloc(a, i);
        try bip371.addInputTapLeafScript(a, &ps, 0, cb, leaf.script, leaf.version);
    }
    return .{ .ps = ps, .tx = tx, .spent = spent, .info = info, .internal = internal };
}

fn signLeaf(a: Allocator, f: *const Fixture, k: Key, leaf_index: usize) ![64]u8 {
    var exec: tapscript.ExecData = .{ .tapleaf_hash = f.info.leaves[leaf_index].leaf_hash, .codesep_pos = 0xffffffff };
    const sighash = try tapscript.sighash(a, f.tx, 0, tapscript.SIGHASH_DEFAULT, f.spent, &exec);
    const io: std.Io = undefined;
    return bip340.sign(&k.sk, &sighash, @as([32]u8, @splat(0xaa)), io, .{});
}

fn addSig(a: Allocator, f: *Fixture, k: Key, leaf_index: usize) !void {
    const sig = try signLeaf(a, f, k, leaf_index);
    try bip371.setInputTapScriptSig(a, &f.ps, 0, k.x, f.info.leaves[leaf_index].leaf_hash, &sig);
}

fn leafIndex(f: *const Fixture, script: []const u8) usize {
    for (f.info.leaves, 0..) |l, i| if (std.mem.eql(u8, l.script, script)) return i;
    unreachable;
}

fn witnessOf(a: Allocator, f: *const Fixture) ![][]const u8 {
    const r = f.ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) orelse return error.NotFinalized;
    return psbt.decodeWitnessStack(a, r.value);
}

test "P2TR script path: <key> OP_CHECKSIG leaf is finalized; witness is [sig, script, control block]; fields cleared" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const k2 = try key(2);
    const k3 = try key(3);
    const k4 = try key(4);
    const sa = try checksigScript(a, k2.x);
    const sb = try multiA2of2(a, k3.x, k4.x);
    const sc = try checksigScript(a, (try key(5)).x);
    var f = try fixture(a, &.{ sa, sb, sc }, &.{ 1, 2, 2 });
    const ia = leafIndex(&f, sa);
    try addSig(a, &f, k2, ia);
    try bip371.setInputTapBip32Derivation(a, &f.ps, 0, k2.x, &.{f.info.leaves[ia].leaf_hash}, .{ 1, 2, 3, 4 }, &.{0});

    const res = try psbt.finalize(a, f.ps, .{});
    try testing.expectEqual(@as(?psbt.InputFinalizeError, null), res[0]);

    const w = try witnessOf(a, &f);
    try testing.expectEqual(@as(usize, 3), w.len);
    try testing.expectEqual(@as(usize, 64), w[0].len);
    try testing.expectEqualSlices(u8, sa, w[1]);
    const cb = try f.info.controlBlockAlloc(a, ia);
    try testing.expectEqualSlices(u8, cb, w[2]);

    const m = f.ps.inputs[0];
    try testing.expect(m.find(psbt.input_key.TAP_LEAF_SCRIPT) == null);
    try testing.expect(m.find(psbt.input_key.TAP_MERKLE_ROOT) == null);
    var leaves = bip371.inputTapLeafScripts(m);
    try testing.expect(leaves.next() == null);
    try testing.expect(bip371.inputTapScriptSig(m, k2.x, f.info.leaves[ia].leaf_hash) == null);
    // BIP371 asks the Finalizer to drop only those four; the internal key and derivations stay.
    try testing.expect(bip371.inputTapInternalKey(m) != null);
    try testing.expect(bip371.inputTapBip32Derivation(m, k2.x) != null);
    try testing.expect(m.find(psbt.input_key.WITNESS_UTXO) != null);

    // extract splices the same witness into a transaction.
    const out = try psbt.extract(a, f.ps);
    try testing.expectEqual(@as(usize, 3), out.witness[0].items.len);
    // and finalize is idempotent: a re-run re-verifies and succeeds.
    const again = try psbt.finalize(a, f.ps, .{});
    try testing.expectEqual(@as(?psbt.InputFinalizeError, null), again[0]);
}

test "P2TR script path: multi_a 2-of-2 puts key 1's signature on top of the stack" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const k3 = try key(3);
    const k4 = try key(4);
    const sb = try multiA2of2(a, k3.x, k4.x);
    const sa = try checksigScript(a, (try key(2)).x);
    var f = try fixture(a, &.{ sa, sb }, &.{ 1, 1 });
    const ib = leafIndex(&f, sb);
    const sig3 = try signLeaf(a, &f, k3, ib);
    const sig4 = try signLeaf(a, &f, k4, ib);
    try addSig(a, &f, k4, ib);
    try addSig(a, &f, k3, ib);

    const res = try psbt.finalize(a, f.ps, .{});
    try testing.expectEqual(@as(?psbt.InputFinalizeError, null), res[0]);
    const w = try witnessOf(a, &f);
    try testing.expectEqual(@as(usize, 4), w.len);
    try testing.expectEqualSlices(u8, &sig4, w[0]); // bottom: the last key
    try testing.expectEqualSlices(u8, &sig3, w[1]); // top: key 1
    try testing.expectEqualSlices(u8, sb, w[2]);
}

test "P2TR script path: refusals name their reason and leave the input unfinalized" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const k2 = try key(2);
    const k3 = try key(3);
    const k4 = try key(4);
    const sa = try checksigScript(a, k2.x);
    const sb = try multiA2of2(a, k3.x, k4.x);

    // leaves present, nobody signed: MissingTaprootSignature
    {
        var f = try fixture(a, &.{ sa, sb }, &.{ 1, 1 });
        const res = try psbt.finalize(a, f.ps, .{});
        try testing.expectEqual(@as(?psbt.InputFinalizeError, error.MissingTaprootSignature), res[0]);
        _ = &f;
    }
    // multi_a with one of two signatures: InsufficientSignatures
    {
        var f = try fixture(a, &.{ sa, sb }, &.{ 1, 1 });
        try addSig(a, &f, k3, leafIndex(&f, sb));
        const res = try psbt.finalize(a, f.ps, .{});
        try testing.expectEqual(@as(?psbt.InputFinalizeError, error.InsufficientSignatures), res[0]);
        try testing.expect(f.ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);
    }
    // a signature for the wrong leaf does not satisfy another leaf
    {
        var f = try fixture(a, &.{ sa, sb }, &.{ 1, 1 });
        const sig = try signLeaf(a, &f, k2, leafIndex(&f, sa));
        try bip371.setInputTapScriptSig(a, &f.ps, 0, k2.x, f.info.leaves[leafIndex(&f, sb)].leaf_hash, &sig);
        const res = try psbt.finalize(a, f.ps, .{});
        try testing.expect(res[0] != null);
    }
    // a tampered signature fails the verifyScript gate
    {
        var f = try fixture(a, &.{ sa, sb }, &.{ 1, 1 });
        var sig = try signLeaf(a, &f, k2, leafIndex(&f, sa));
        sig[10] ^= 1;
        try bip371.setInputTapScriptSig(a, &f.ps, 0, k2.x, f.info.leaves[leafIndex(&f, sa)].leaf_hash, &sig);
        const res = try psbt.finalize(a, f.ps, .{});
        try testing.expect(res[0] != null);
        try testing.expect(f.ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);
    }
    // a committed leaf with a script this finalizer does not recognise: NonStandardScript
    {
        const op_true = try a.dupe(u8, &.{0x51});
        var f = try fixture(a, &.{op_true}, &.{0});
        _ = &f;
        const res = try psbt.finalize(a, f.ps, .{});
        try testing.expectEqual(@as(?psbt.InputFinalizeError, error.NonStandardScript), res[0]);
    }
    // a leaf whose control block does not commit to the output key is not used
    {
        var f = try fixture(a, &.{sa}, &.{0});
        try addSig(a, &f, k2, 0);
        var cb = try f.info.controlBlockAlloc(a, 0);
        cb[5] ^= 1; // the internal key no longer matches
        try bip371.addInputTapLeafScript(a, &f.ps, 0, cb, sa, 0xc0);
        // the genuine leaf is still there and still satisfiable
        const res = try psbt.finalize(a, f.ps, .{});
        try testing.expectEqual(@as(?psbt.InputFinalizeError, null), res[0]);
    }
    {
        // only the corrupted leaf: nothing commits
        var f = try fixture(a, &.{sa}, &.{0});
        var cb = try f.info.controlBlockAlloc(a, 0);
        var ps2 = try psbt.fromUnsignedTx(a, f.tx);
        try psbt.setInputWitnessUtxo(a, &ps2, 0, f.spent[0]);
        cb[5] ^= 1;
        try bip371.addInputTapLeafScript(a, &ps2, 0, cb, sa, 0xc0);
        const res = try psbt.finalize(a, ps2, .{});
        try testing.expectEqual(@as(?psbt.InputFinalizeError, error.NonStandardScript), res[0]);
        _ = &f;
    }
}

test "P2TR: TAP_KEY_SIG still wins over script-path data" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sa = try checksigScript(a, (try key(2)).x);
    var f = try fixture(a, &.{sa}, &.{0});
    // A (bogus) key-path signature is taken as is, as before: the verifyScript gate rejects it.
    try bip371.setInputTapKeySig(a, &f.ps, 0, &(@as([64]u8, @splat(3))));
    const res = try psbt.finalize(a, f.ps, .{});
    try testing.expect(res[0] != null);
    try testing.expect(res[0].? != error.NonStandardScript and res[0].? != error.MissingTaprootSignature);
}
