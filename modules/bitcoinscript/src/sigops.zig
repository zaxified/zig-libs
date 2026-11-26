// SPDX-License-Identifier: MIT
//! Signature-operation counting — Bitcoin Core `CScript::GetSigOpCount`,
//! `GetLegacySigOpCount`, `GetP2SHSigOpCount`, `CountWitnessSigOps` and
//! `GetTransactionSigOpCost` (`script/script.cpp`, `consensus/tx_verify.cpp`,
//! `script/interpreter.cpp`). The block-validity limit
//! (`MAX_BLOCK_SIGOPS_COST` = 80 000) is a sum of these counts, so a block
//! validator cannot do without them.
//!
//! Every function walks untrusted script bytes with the same decode rules as
//! the interpreter (`interpreter.readInstruction`): like Core's
//! `while (GetOp(pc, opcode))`, a failing decode simply ENDS the walk, it is
//! not an error. Tapscript (witness v1) outputs contribute 0 here: BIP342
//! replaced sigop counting by the validation-weight budget.

const std = @import("std");
const bitcointx = @import("bitcointx");
const interpreter = @import("interpreter.zig");
const limits = @import("limits.zig");
const flags_mod = @import("flags.zig");

/// BIP141 `WITNESS_SCALE_FACTOR`: legacy and P2SH sigops cost four sigop-cost
/// units, a witness sigop one.
pub const witness_scale_factor: u64 = 4;
/// Consensus `MAX_BLOCK_SIGOPS_COST`: a block's summed sigop cost may not
/// exceed this.
pub const max_block_sigops_cost: u64 = 80_000;

const op_1: u8 = 0x51;
const op_16: u8 = 0x60;
const op_checksig: u8 = 0xac;
const op_checksigverify: u8 = 0xad;
const op_checkmultisig: u8 = 0xae;
const op_checkmultisigverify: u8 = 0xaf;

/// `CScript::GetSigOpCount(fAccurate)`: one per `OP_CHECKSIG(VERIFY)`; per
/// `OP_CHECKMULTISIG(VERIFY)` the key count `n` of an immediately preceding
/// `OP_1..OP_16` when `accurate`, else the consensus maximum of 20. Legacy
/// output/input scripts are counted with `accurate = false`, P2SH redeem and
/// P2WSH witness scripts with `accurate = true`.
pub fn countScript(script: []const u8, accurate: bool) u64 {
    var n: u64 = 0;
    var last: u8 = 0xff; // Core: `lastOpcode = OP_INVALIDOPCODE`
    var i: usize = 0;
    while (i < script.len) {
        const instr = interpreter.readInstruction(script, i) catch break;
        const op = instr.opcode;
        if (op == op_checksig or op == op_checksigverify) {
            n += 1;
        } else if (op == op_checkmultisig or op == op_checkmultisigverify) {
            if (accurate and last >= op_1 and last <= op_16) {
                n += last - 0x50;
            } else {
                n += @intCast(limits.max_pubkeys_per_multisig);
            }
        }
        last = op;
        i = instr.next;
    }
    return n;
}

/// `CScript::IsPayToScriptHash`.
fn isP2sh(spk: []const u8) bool {
    return spk.len == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and spk[22] == 0x87;
}

/// `CScript::IsPushOnly`: every instruction decodes and is `<= OP_16`.
fn isPushOnly(script: []const u8) bool {
    var i: usize = 0;
    while (i < script.len) {
        const instr = interpreter.readInstruction(script, i) catch return false;
        if (instr.opcode > op_16) return false;
        i = instr.next;
    }
    return true;
}

/// The data of the last instruction of `script_sig` (Core's loop over
/// `GetOp` that keeps the final `vData`; empty for an `OP_N`); a decode
/// failure is `error.Undecodable`.
fn lastPushData(script_sig: []const u8) error{Undecodable}![]const u8 {
    var i: usize = 0;
    var data: []const u8 = &.{};
    while (i < script_sig.len) {
        const instr = interpreter.readInstruction(script_sig, i) catch return error.Undecodable;
        data = instr.data orelse &.{};
        i = instr.next;
    }
    return data;
}

/// `CScript::GetSigOpCount(const CScript& scriptSig)` on a scriptPubKey:
/// for a P2SH output the accurate count of the redeem script (the last push
/// of `script_sig`; 0 when `script_sig` has a non-push opcode or does not
/// decode), otherwise the inaccurate count of `script_pubkey` itself.
pub fn countP2sh(script_pubkey: []const u8, script_sig: []const u8) u64 {
    if (!isP2sh(script_pubkey)) return countScript(script_pubkey, true);
    var i: usize = 0;
    var data: []const u8 = &.{};
    while (i < script_sig.len) {
        const instr = interpreter.readInstruction(script_sig, i) catch return 0;
        if (instr.opcode > op_16) return 0;
        data = instr.data orelse &.{};
        i = instr.next;
    }
    return countScript(data, true);
}

/// `GetLegacySigOpCount(tx)`: inaccurate count over every `script_sig` and
/// `script_pubkey` of the transaction (coinbase included).
pub fn legacyCount(tx: bitcointx.Transaction) u64 {
    var n: u64 = 0;
    for (tx.vin) |in| n += countScript(in.script_sig, false);
    for (tx.vout) |out| n += countScript(out.script_pubkey, false);
    return n;
}

/// `GetP2SHSigOpCount(tx, inputs)`: the accurate redeem-script counts of
/// every P2SH input. `spent_outputs[i]` is the output `tx.vin[i]` spends.
/// Returns `error.SpentOutputsMismatch` when the slice length differs from
/// the input count (Core would fail on a missing coin instead).
pub fn p2shCount(tx: bitcointx.Transaction, spent_outputs: []const bitcointx.TxOut) error{SpentOutputsMismatch}!u64 {
    if (spent_outputs.len != tx.vin.len) return error.SpentOutputsMismatch;
    if (tx.isCoinbase()) return 0;
    var n: u64 = 0;
    for (tx.vin, spent_outputs) |in, prev| {
        if (isP2sh(prev.script_pubkey)) n += countP2sh(prev.script_pubkey, in.script_sig);
    }
    return n;
}

const WitnessProgram = struct { version: u8, program: []const u8 };

fn witnessProgram(spk: []const u8) ?WitnessProgram {
    if (spk.len < 4 or spk.len > 42) return null;
    const first = spk[0];
    const version: u8 = if (first == 0x00) 0 else if (first >= op_1 and first <= op_16) first - 0x50 else return null;
    if (spk[1] < 2 or spk[1] > 40 or spk.len != @as(usize, spk[1]) + 2) return null;
    return .{ .version = version, .program = spk[2..] };
}

/// `WitnessSigOps`: a v0 key-hash program costs 1, a v0 script-hash program
/// the accurate count of its witness script (the last witness item); every
/// other version (taproot included) 0.
fn witnessSigOps(version: u8, program: []const u8, witness: []const []const u8) u64 {
    if (version != 0) return 0;
    if (program.len == 20) return 1;
    if (program.len == 32 and witness.len > 0) return countScript(witness[witness.len - 1], true);
    return 0;
}

/// `CountWitnessSigOps(scriptSig, scriptPubKey, witness, flags)`: 0 unless
/// `flags.witness`; a native witness program is counted directly, a
/// P2SH-wrapped one (`script_sig` push-only and its last push a witness
/// program; like Core, `flags.p2sh` is not consulted, since segwit implies
/// P2SH) through the redeem script.
pub fn witnessCount(
    script_sig: []const u8,
    script_pubkey: []const u8,
    witness: []const []const u8,
    flags: flags_mod.ScriptFlags,
) u64 {
    if (!flags.witness) return 0;
    if (witnessProgram(script_pubkey)) |wp| return witnessSigOps(wp.version, wp.program, witness);
    if (isP2sh(script_pubkey) and isPushOnly(script_sig)) {
        const data = lastPushData(script_sig) catch &.{};
        if (witnessProgram(data)) |wp| return witnessSigOps(wp.version, wp.program, witness);
    }
    return 0;
}

pub const SigOpError = error{
    /// `spent_outputs.len != tx.vin.len`.
    SpentOutputsMismatch,
};

/// `GetTransactionSigOpCost(tx, inputs, flags)`: legacy count x 4, plus (with
/// `flags.p2sh`) the P2SH count x 4, plus the witness count. A coinbase
/// costs only its legacy count. `spent_outputs[i]` is the output `tx.vin[i]`
/// spends (ignored for a coinbase, which has none). The caller sums these
/// over a block and compares with `max_block_sigops_cost`.
pub fn transactionCost(
    tx: bitcointx.Transaction,
    spent_outputs: []const bitcointx.TxOut,
    flags: flags_mod.ScriptFlags,
) SigOpError!u64 {
    var cost: u64 = legacyCount(tx) * witness_scale_factor;
    if (tx.isCoinbase()) return cost;
    if (spent_outputs.len != tx.vin.len) return error.SpentOutputsMismatch;
    if (flags.p2sh) cost += try p2shCount(tx, spent_outputs) * witness_scale_factor;
    for (tx.vin, spent_outputs, 0..) |in, prev, i| {
        const wit: []const []const u8 = if (i < tx.witness.len) tx.witness[i].items else &.{};
        cost += witnessCount(in.script_sig, prev.script_pubkey, wit, flags);
    }
    return cost;
}
