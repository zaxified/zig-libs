// SPDX-License-Identifier: MIT
//! The transaction-side context `OP_CHECKSIG`/`OP_CHECKMULTISIG`/BIP65/
//! BIP112 need: which spending transaction, which input, and — because
//! BIP143/BIP341 sighashes commit to it — the spent output's value (and,
//! for taproot, every input's spent output).

const bitcointx = @import("bitcointx");

/// Which sighash algorithm `OP_CHECKSIG`-family opcodes use, selected by
/// which execution context the interpreter is currently running under
/// (legacy scriptSig/scriptPubKey/P2SH-redeem vs. a segwit v0 witness
/// script). Never chosen by the opcode itself.
pub const SigVersion = enum { base, witness_v0 };

/// The spending transaction plus the specific input being verified.
/// `spent_outputs` holds the previous output every `tx.vin[i]` spends, in
/// `vin` order — required in full (not just the input being signed) by
/// BIP341 taproot sighashing; `witness_v0`/`base` sighashing only ever
/// reads `spent_outputs[input_index]`.
pub const TxContext = struct {
    tx: bitcointx.Transaction,
    input_index: usize,
    spent_outputs: []const bitcointx.TxOut,

    pub fn amountSats(self: TxContext) i64 {
        return self.spent_outputs[self.input_index].value;
    }
};
