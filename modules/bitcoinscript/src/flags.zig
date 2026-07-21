// SPDX-License-Identifier: MIT
//! `ScriptFlags` — the `SCRIPT_VERIFY_*` policy/consensus flag set (Bitcoin
//! Core `script/interpreter.h`). Each flag gates one specific extra check;
//! `verifyScript` is called with whichever combination applies to the spend
//! being validated (mempool/relay policy passes nearly all of them,
//! historical block validation passes fewer — see SPEC.md "Flags").

const std = @import("std");

pub const ScriptFlags = struct {
    /// BIP16: evaluate P2SH redeem scripts.
    p2sh: bool = false,
    /// BIP62 rule 1: reject legacy ECDSA signatures not in strict DER form.
    dersig: bool = false,
    /// BIP62 rule 5 + BIP146: reject ECDSA signatures with high-S.
    low_s: bool = false,
    /// BIP62 rule 2/3 + hashtype-byte validation: reject undefined sighash
    /// types and non-canonical pubkey encodings for CHECKSIG-family ops.
    strictenc: bool = false,
    /// BIP147: the CHECKMULTISIG dummy element must be exactly empty.
    nulldummy: bool = false,
    /// Reject `OP_NOP1`/`OP_NOP4..OP_NOP10` (upgradable-NOP reservations)
    /// when executed, so future soft-forks that repurpose them can't be
    /// silently no-op'd by old nodes running with this flag on.
    discourage_upgradable_nops: bool = false,
    /// BIP62 rule 6: after successful execution exactly one truthy element
    /// must remain on the stack (no cruft left by a permissive script).
    cleanstack: bool = false,
    /// BIP65: enable `OP_CHECKLOCKTIMEVERIFY` (else it's a plain NOP).
    checklocktimeverify: bool = false,
    /// BIP112: enable `OP_CHECKSEQUENCEVERIFY` (else it's a plain NOP).
    checksequenceverify: bool = false,
    /// BIP141/143/144: enable segwit v0 program recognition + execution.
    witness: bool = false,
    /// Reject witness programs whose version is unassigned (only 0 is
    /// defined pre-taproot; 1 is taproot when `taproot` is also set).
    discourage_upgradable_witness_program: bool = false,
    /// BIP141 script-flag companion: inside a P2WSH/P2WPKH `OP_IF`/
    /// `OP_NOTIF`, the top stack element must be exactly empty or `0x01`
    /// (no other "truthy" encoding of true is accepted).
    minimalif: bool = false,
    /// Segwit v0 pubkeys for CHECKSIG-family ops must be compressed.
    witness_pubkeytype: bool = false,
    /// BIP146: when a CHECKSIG/CHECKMULTISIG verification fails, every
    /// signature involved must have been the empty string (defends against
    /// signature-malleability in multisig).
    nullfail: bool = false,
    /// Push operands (data pushes only, not `CScriptNum` arithmetic
    /// operands — see `number.zig`) must use the shortest possible push
    /// opcode for their length.
    minimaldata: bool = false,
    /// BIP341/342: enable taproot (P2TR) key-path (and, if implemented,
    /// script-path) spending. This module implements key-path only —
    /// script-path (tapscript) support is deferred (SPEC.md).
    taproot: bool = false,
    /// Mempool-relay policy only (not consensus): `scriptSig` must be
    /// push-only, checked unconditionally at the very start of
    /// `verifyScript` — independent of, and in addition to, the P2SH
    /// redeem-script-resume path's own (always-on, flag-independent)
    /// push-only requirement.
    sigpushonly: bool = false,
    /// BIP342 policy: reject a tapscript leaf that contains an `OP_SUCCESSx`
    /// opcode (which would otherwise make the script succeed
    /// unconditionally). A standardness rule that keeps the `OP_SUCCESSx`
    /// upgrade hooks unused on the network until a future soft-fork assigns
    /// them meaning; consensus (this flag off) still accepts them.
    discourage_op_success: bool = false,
    /// BIP342 policy: reject a tapscript CHECKSIG-family opcode whose public
    /// key is of an unknown (not 32-byte, not empty) type — which consensus
    /// (this flag off) treats as an always-successful upgrade hook.
    discourage_upgradable_pubkeytype: bool = false,
    /// BIP341 policy: reject a taproot script-path spend whose leaf version
    /// is not `0xc0` (the only assigned tapscript version) — which consensus
    /// (this flag off) treats as anyone-can-spend for future upgradeability.
    discourage_upgradable_taproot_version: bool = false,

    pub const none: ScriptFlags = .{};

    /// The flag set commonly called "standard" (mempool-relay policy) —
    /// everything this module implements, turned on. Convenience for
    /// callers/tests; production callers should still name flags
    /// explicitly where behavior matters.
    pub const standard: ScriptFlags = .{
        .p2sh = true,
        .dersig = true,
        .low_s = true,
        .strictenc = true,
        .nulldummy = true,
        .discourage_upgradable_nops = true,
        .cleanstack = true,
        .checklocktimeverify = true,
        .checksequenceverify = true,
        .witness = true,
        .discourage_upgradable_witness_program = true,
        .minimalif = true,
        .witness_pubkeytype = true,
        .nullfail = true,
        .minimaldata = true,
        .taproot = true,
        .sigpushonly = true,
        .discourage_op_success = true,
        .discourage_upgradable_pubkeytype = true,
        .discourage_upgradable_taproot_version = true,
    };
};

const testing = std.testing;

test "none has every flag off, standard has every implemented flag on" {
    const n = ScriptFlags.none;
    inline for (std.meta.fields(ScriptFlags)) |f| {
        if (f.type == bool) try testing.expectEqual(false, @field(n, f.name));
    }
    const s = ScriptFlags.standard;
    inline for (std.meta.fields(ScriptFlags)) |f| {
        if (f.type == bool) try testing.expectEqual(true, @field(s, f.name));
    }
}
