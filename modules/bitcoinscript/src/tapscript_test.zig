// SPDX-License-Identifier: MIT
//! End-to-end BIP342 tapscript (taproot script-path) spends, verified
//! through the SAME `verifyScript` path a node would use: BIP341 taproot
//! commitment (control block → tapleaf → tweak → output key), the BIP341/342
//! Schnorr sighash extension, `bip340.verify`, the `OP_CHECKSIG`/
//! `OP_CHECKSIGADD` opcodes, the `OP_SUCCESSx` short-circuit, and the
//! validation-weight budget.
//!
//! ## Vector provenance
//!
//! - The taproot commitment math (`tapscript.verifyCommitment` /
//!   `tapleafHash`) is validated against **external** BIP341
//!   wallet-test-vectors in `tapscript.zig`'s own tests.
//! - The BIP341/342 SigMsg common prefix is cross-checked **byte-for-byte**
//!   against `bitcointx`'s KAT-backed key-path `sigMsg` in `tapscript.zig`.
//! - The spends BELOW are **constructed round-trips** (we build a taproot
//!   output, sign the tapscript sighash with `bip340`, and verify): they
//!   prove the CHECKSIG/CHECKSIGADD/OP_SUCCESS/budget wiring end-to-end, and
//!   each has a positive control. They are NOT byte-exact against an
//!   external transaction vector — for that, see `consensus_kat_test.zig`
//!   (real Bitcoin Core `script_assets_test.json` consensus transactions,
//!   added 2026-07-28; a representative slice, not the full corpus).

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const bip340 = @import("bip340");
const k256 = @import("k256");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const tapscript = @import("tapscript.zig");
const flags_mod = @import("flags.zig");

const ScriptFlags = flags_mod.ScriptFlags;

/// Flag set enforcing full consensus taproot rules but with the three
/// tapscript *policy* discourage-flags OFF (so consensus-valid upgrade hooks
/// / OP_SUCCESS / unknown pubkeys behave as consensus dictates, not as
/// standardness would reject them).
const consensus_taproot: ScriptFlags = .{
    .p2sh = true,
    .witness = true,
    .taproot = true,
    .minimaldata = true,
    .low_s = true,
    .dersig = true,
    .strictenc = true,
    .nulldummy = true,
    .cleanstack = true,
};

fn keypair(seed: u8) !struct { sk: bip340.SecretKey, x: [32]u8 } {
    const sk = try bip340.SecretKey.fromBytes([_]u8{seed} ** 32);
    const kp = try bip340.KeyPair.fromSecretKey(sk);
    return .{ .sk = sk, .x = kp.public.x };
}

/// Recompute the taproot output key `Q = lift_x(internal) + t*G` for a given
/// internal key + Merkle root, returning its x-only serialization and
/// y-parity. Mirrors `tapscript.verifyCommitment`'s derivation (that
/// derivation is itself validated against external BIP341 vectors).
fn taprootOutput(internal_x: [32]u8, merkle_root: [32]u8) struct { q: [32]u8, parity: u8 } {
    var th = bip340.hash.taggedHasher("TapTweak");
    th.update(&internal_x);
    th.update(&merkle_root);
    const t = th.finalResult();
    const P = (bip340.XOnlyPublicKey.fromBytes(internal_x) catch unreachable).lift() catch unreachable;
    const tG = k256.Secp256k1.basePoint.mulPublic(t, .big) catch unreachable;
    const Q = P.add(tG);
    const aff = Q.affineCoordinates();
    return .{ .q = aff.x.toBytes(.big), .parity = if (aff.y.isOdd()) 1 else 0 };
}

const Setup = struct {
    script_pubkey: [34]u8,
    control_block: [33]u8,
    tapleaf_hash: [32]u8,
    tx: bitcointx.Transaction,
    spent: []const bitcointx.TxOut,
    ctx: txctx.TxContext,
};

/// Build a single-leaf taproot output committing to `script` (leaf version
/// 0xc0), and a spending transaction for it. Returns everything needed to
/// assemble a witness and compute the tapscript sighash.
fn buildSingleLeaf(a: std.mem.Allocator, internal_x: [32]u8, script: []const u8) !Setup {
    const leaf_hash = tapscript.tapleafHash(0xc0, script);
    const out = taprootOutput(internal_x, leaf_hash); // single leaf: merkle root == leaf hash

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x51; // OP_1
    script_pubkey[1] = 0x20; // push 32
    @memcpy(script_pubkey[2..34], &out.q);

    var control_block: [33]u8 = undefined;
    control_block[0] = 0xc0 | out.parity;
    @memcpy(control_block[1..33], &internal_x);

    // crediting output the spend consumes
    const spk = try a.dupe(u8, &script_pubkey);
    const credit_value: i64 = 20000;

    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = [_]u8{0x77} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 19000, .script_pubkey = &.{} };
    const tx: bitcointx.Transaction = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = true };

    const spent = try a.alloc(bitcointx.TxOut, 1);
    spent[0] = .{ .value = credit_value, .script_pubkey = spk };

    return .{
        .script_pubkey = script_pubkey,
        .control_block = control_block,
        .tapleaf_hash = leaf_hash,
        .tx = tx,
        .spent = spent,
        .ctx = .{ .tx = tx, .input_index = 0, .spent_outputs = spent },
    };
}

fn signLeaf(a: std.mem.Allocator, sk: bip340.SecretKey, s: *const Setup, aux: u8) ![64]u8 {
    var exec: tapscript.ExecData = .{ .tapleaf_hash = s.tapleaf_hash, .codesep_pos = 0xffffffff };
    const sighash = try tapscript.sighash(a, s.tx, 0, tapscript.SIGHASH_DEFAULT, s.spent, &exec);
    const io: std.Io = undefined;
    return bip340.sign(sk, &sighash, [_]u8{aux} ** 32, io);
}

// ── 1. script-path CHECKSIG spend ────────────────────────────────────────

test "e2e tapscript: script-path OP_CHECKSIG spend verifies; tampered sig fails closed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const internal = try keypair(0x01);
    const leaf = try keypair(0x02);

    // leaf script: <32-byte xonly leaf key> OP_CHECKSIG
    var script: [34]u8 = undefined;
    script[0] = 0x20;
    @memcpy(script[1..33], &leaf.x);
    script[33] = 0xac; // OP_CHECKSIG

    const s = try buildSingleLeaf(a, internal.x, &script);
    const sig = try signLeaf(a, leaf.sk, &s, 0x33);

    const witness = [_][]const u8{ &sig, &script, &s.control_block };
    try verify.verifyScript(a, &.{}, &s.script_pubkey, &witness, consensus_taproot, s.ctx);

    // Positive control: tamper one signature byte.
    var bad_sig = sig;
    bad_sig[10] ^= 0x01;
    const bad_witness = [_][]const u8{ &bad_sig, &script, &s.control_block };
    try testing.expectError(error.SchnorrSig, verify.verifyScript(a, &.{}, &s.script_pubkey, &bad_witness, consensus_taproot, s.ctx));
}

// ── 2. OP_CHECKSIGADD 2-of-2 threshold ───────────────────────────────────

test "e2e tapscript: OP_CHECKSIGADD 2-of-2 threshold verifies; one bad sig fails closed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const internal = try keypair(0x05);
    const ka = try keypair(0x06);
    const kb = try keypair(0x07);

    // <pkA> OP_CHECKSIG <pkB> OP_CHECKSIGADD OP_2 OP_NUMEQUAL
    var script: std.ArrayList(u8) = .empty;
    try script.append(a, 0x20);
    try script.appendSlice(a, &ka.x);
    try script.append(a, 0xac); // OP_CHECKSIG
    try script.append(a, 0x20);
    try script.appendSlice(a, &kb.x);
    try script.append(a, 0xba); // OP_CHECKSIGADD
    try script.append(a, 0x52); // OP_2
    try script.append(a, 0x9c); // OP_NUMEQUAL

    const s = try buildSingleLeaf(a, internal.x, script.items);
    const sig_a = try signLeaf(a, ka.sk, &s, 0x40);
    const sig_b = try signLeaf(a, kb.sk, &s, 0x41);

    // initial stack (bottom->top): sigB, sigA
    const witness = [_][]const u8{ &sig_b, &sig_a, script.items, &s.control_block };
    try verify.verifyScript(a, &.{}, &s.script_pubkey, &witness, consensus_taproot, s.ctx);

    // Positive control: replace sigB with sigA -> B's check fails -> immediate SchnorrSig.
    const bad_witness = [_][]const u8{ &sig_a, &sig_a, script.items, &s.control_block };
    try testing.expectError(error.SchnorrSig, verify.verifyScript(a, &.{}, &s.script_pubkey, &bad_witness, consensus_taproot, s.ctx));

    // Threshold NOT met: an empty sig for B -> CHECKSIGADD keeps n=1 -> 1 != 2 -> EvalFalse.
    const short_witness = [_][]const u8{ "", &sig_a, script.items, &s.control_block };
    try testing.expectError(error.EvalFalse, verify.verifyScript(a, &.{}, &s.script_pubkey, &short_witness, consensus_taproot, s.ctx));
}

// ── 3. OP_SUCCESSx unconditional success ─────────────────────────────────

test "e2e tapscript: OP_SUCCESS80 makes the leaf succeed unconditionally (and DISCOURAGE_OP_SUCCESS rejects it)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const internal = try keypair(0x0a);
    // A leaf whose only opcode is OP_SUCCESS80 (0x50). It would otherwise
    // leave an empty stack (fail), but OP_SUCCESSx short-circuits to success.
    const script = [_]u8{0x50};
    const s = try buildSingleLeaf(a, internal.x, &script);

    // No initial stack items; witness = [script, control_block].
    const witness = [_][]const u8{ &script, &s.control_block };
    try verify.verifyScript(a, &.{}, &s.script_pubkey, &witness, consensus_taproot, s.ctx);

    // With the policy flag set, the same spend is rejected.
    var policy = consensus_taproot;
    policy.discourage_op_success = true;
    try testing.expectError(error.DiscourageOpSuccess, verify.verifyScript(a, &.{}, &s.script_pubkey, &witness, policy, s.ctx));

    // A tampered control block (wrong commitment) is rejected even though the
    // leaf contains OP_SUCCESS — the commitment is checked first.
    var bad_cb = s.control_block;
    bad_cb[5] ^= 0x01;
    const bad_witness = [_][]const u8{ &script, &bad_cb };
    try testing.expectError(error.TaprootCommitmentMismatch, verify.verifyScript(a, &.{}, &s.script_pubkey, &bad_witness, consensus_taproot, s.ctx));
}

// ── 4. empty signature -> CHECKSIG false ─────────────────────────────────

test "e2e tapscript: empty signature makes OP_CHECKSIG push false (EvalFalse), CHECKSIGVERIFY fails" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const internal = try keypair(0x0b);
    const leaf = try keypair(0x0c);

    // <pk> OP_CHECKSIG
    var script: [34]u8 = undefined;
    script[0] = 0x20;
    @memcpy(script[1..33], &leaf.x);
    script[33] = 0xac;
    const s = try buildSingleLeaf(a, internal.x, &script);

    // initial stack = [empty] -> CHECKSIG pops empty sig -> false -> EvalFalse.
    const witness = [_][]const u8{ "", &script, &s.control_block };
    try testing.expectError(error.EvalFalse, verify.verifyScript(a, &.{}, &s.script_pubkey, &witness, consensus_taproot, s.ctx));

    // <pk> OP_CHECKSIGVERIFY with an empty sig -> immediate Checksigverify.
    var script_v: [34]u8 = undefined;
    @memcpy(script_v[0..33], script[0..33]);
    script_v[33] = 0xad; // OP_CHECKSIGVERIFY
    const sv = try buildSingleLeaf(a, internal.x, &script_v);
    const witness_v = [_][]const u8{ "", &script_v, &sv.control_block };
    try testing.expectError(error.Checksigverify, verify.verifyScript(a, &.{}, &sv.script_pubkey, &witness_v, consensus_taproot, sv.ctx));
}

// ── 5. validation-weight budget exhaustion ───────────────────────────────

test "e2e tapscript: exceeding the sigops/validation-weight budget fails closed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const internal = try keypair(0x0d);

    // Reuse a tiny 1-byte "signature" + 1-byte (unknown-type) pubkey via
    // OP_2DUP, running OP_CHECKSIGVERIFY four times. Each non-empty-sig check
    // costs 50 weight regardless of pubkey type; the small witness keeps the
    // budget low enough that the 3rd check drives it below zero.
    //   <0x'53'> <0x'53'> OP_2DUP OP_CHECKSIGVERIFY x4  OP_2DROP OP_1
    var script: std.ArrayList(u8) = .empty;
    try script.appendSlice(a, &[_]u8{ 0x01, 0x53 }); // push 1-byte sig
    try script.appendSlice(a, &[_]u8{ 0x01, 0x53 }); // push 1-byte pubkey (unknown type)
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        try script.append(a, 0x6e); // OP_2DUP
        try script.append(a, 0xad); // OP_CHECKSIGVERIFY
    }
    try script.append(a, 0x6d); // OP_2DROP
    try script.append(a, 0x51); // OP_1 (would leave true if it got this far)

    const s = try buildSingleLeaf(a, internal.x, script.items);
    const witness = [_][]const u8{ script.items, &s.control_block };

    // discourage_upgradable_pubkeytype must be OFF so unknown-type checks
    // are "successful" (and thus reach/charge the budget) rather than being
    // rejected outright.
    try testing.expectError(error.TapscriptValidationWeight, verify.verifyScript(a, &.{}, &s.script_pubkey, &witness, consensus_taproot, s.ctx));
}
