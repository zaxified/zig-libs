// SPDX-License-Identifier: MIT
//! The transaction-side context `OP_CHECKSIG`/`OP_CHECKMULTISIG`/BIP65/
//! BIP112 need: which spending transaction, which input, and — because
//! BIP143/BIP341 sighashes commit to it — the spent output's value (and,
//! for taproot, every input's spent output).

const std = @import("std");
const bitcointx = @import("bitcointx");

/// Which sighash algorithm `OP_CHECKSIG`-family opcodes use, selected by
/// which execution context the interpreter is currently running under
/// (legacy scriptSig/scriptPubKey/P2SH-redeem vs. a segwit v0 witness
/// script vs. a BIP342 tapscript leaf). Never chosen by the opcode itself.
///
/// - `.base` / `.witness_v0` — ECDSA over the legacy / BIP143 sighash
///   (`sigcheck.zig`).
/// - `.tapscript` — BIP340 Schnorr over the BIP341/342 sighash extension
///   (`tapscript.zig`); `OP_CHECKSIG`/`OP_CHECKSIGADD` semantics, the
///   `OP_SUCCESSx` set, the validation-weight budget, and mandatory
///   MINIMALIF all differ from the other two versions (see BIP342).
pub const SigVersion = enum { base, witness_v0, tapscript };

/// The spending transaction plus the specific input being verified.
/// `spent_outputs` holds the previous output every `tx.vin[i]` spends, in
/// `vin` order — required in full (not just the input being signed) by
/// BIP341 taproot sighashing; `witness_v0`/`base` sighashing only ever
/// reads `spent_outputs[input_index]`.
pub const TxContext = struct {
    tx: bitcointx.Transaction,
    input_index: usize,
    spent_outputs: []const bitcointx.TxOut,
    /// The per-transaction sighash cache (`bitcointx.PrecomputedTransactionData`
    /// — Bitcoin Core's `PrecomputedTransactionData`), or null to recompute the
    /// commitment hashes inside every sighash call.
    ///
    /// BIP143 and BIP341 exist BECAUSE the legacy algorithm made validation
    /// quadratic in transaction size, and their per-transaction midstates are
    /// the fix. "Compute once" is a property of the CALL PATTERN, not of the
    /// digest bytes, so leaving this null is byte-exact against every published
    /// vector and still `O(n²)` over a transaction's inputs — the letter of the
    /// BIPs with none of their point. A validator that verifies more than one
    /// input of the same transaction should build the cache once (see
    /// `withPrecomputed`) and reuse this context for every input; a signer
    /// touching a single input need not.
    ///
    /// The cache is a pure function of `tx` and `spent_outputs`, so it must be
    /// the one built for THOSE — see `withPrecomputed`, which is the only
    /// constructor that cannot get that pairing wrong.
    precomputed: ?bitcointx.PrecomputedTransactionData = null,

    pub fn amountSats(self: TxContext) i64 {
        return self.spent_outputs[self.input_index].value;
    }

    /// This context with the sighash cache built from its own `tx` /
    /// `spent_outputs`. Costs one `O(n)` pass; every subsequent sighash over
    /// any input of this transaction is then `O(1)` in the commitment hashes.
    /// Change `input_index` on the result to walk the other inputs — the cache
    /// is per-transaction and stays valid.
    ///
    /// `spent_outputs` must hold one entry per `vin`, in `vin` order, or this
    /// returns `error.PrevoutsCountMismatch` (BIP341 commits to every input's
    /// spent output, so a short list cannot produce a taproot sighash).
    pub fn withPrecomputed(self: TxContext, allocator: std.mem.Allocator) bitcointx.precomputed.PrecomputedError!TxContext {
        var out = self;
        out.precomputed = try bitcointx.PrecomputedTransactionData.init(allocator, self.tx, self.spent_outputs);
        return out;
    }

    /// The BIP143 segwit-v0 half of the cache, if any.
    pub fn segwitV0Precomputed(self: TxContext) ?bitcointx.bip143.Precomputed {
        const p = self.precomputed orelse return null;
        return p.segwit_v0;
    }

    /// The BIP341 taproot half of the cache, if any. Null when no cache was
    /// supplied, and also when it was built without spent outputs.
    pub fn taprootPrecomputed(self: TxContext) ?bitcointx.bip341.Precomputed {
        const p = self.precomputed orelse return null;
        return p.taproot;
    }
};
