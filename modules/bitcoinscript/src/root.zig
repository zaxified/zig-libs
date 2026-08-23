// SPDX-License-Identifier: MIT
//! bitcoinscript — a Bitcoin Script interpreter / consensus VM: the stack
//! machine (`interpreter.zig`), ECDSA/pubkey encoding checks and CHECKSIG
//! sighash dispatch (`sigcheck.zig`, built on the sibling `bitcointx`/
//! `k256` modules), and the top-level `verifyScript` orchestration
//! (`verify.zig`) covering legacy, BIP16 P2SH, BIP141 segwit v0
//! (P2WPKH/P2WSH), BIP341 taproot key-path, and BIP341/342 taproot
//! script-path (tapscript) spends. Published consensus rules, verified
//! against Bitcoin Core's own `script_tests.json` corpus plus BIP341
//! taproot-commitment KATs and end-to-end tapscript round-trips — see
//! SPEC.md for the full verification story and scope cuts.
//!
//! `script`/`witness` bytes handed to this module are UNTRUSTED —
//! `verifyScript` and everything it calls is fail-closed and DoS-bounded
//! (`limits.zig`); see `interpreter.zig`'s module doc comment for the
//! detailed threat model.
//!
//! ## Layout
//!
//! - `opcodes.zig` — the opcode byte/mnemonic table + disabled-opcode set.
//! - `number.zig` — `CScriptNum` (Script's sign-magnitude integer encoding).
//! - `limits.zig` — consensus DoS bounds (script/stack/push size, op count, …).
//! - `flags.zig` — `ScriptFlags` (the `SCRIPT_VERIFY_*` policy/consensus set).
//! - `txctx.zig` — `SigVersion` + `TxContext` (the spending-tx-side inputs
//!   `CHECKSIG`/BIP65/BIP112 need).
//! - `sigcheck.zig` — DER/pubkey encoding checks (BIP62/66/146) + the
//!   actual ECDSA verification (sighash via `bitcointx`, curve check via
//!   `k256`).
//! - `tapscript.zig` — BIP341/342 script-path primitives: taproot
//!   control-block commitment, tapleaf hashing, the `ext_flag=1` sighash
//!   extension, and BIP340 Schnorr signature checking.
//! - `interpreter.zig` — the stack machine (`eval` / `evalTapscript`):
//!   opcode dispatch, `IF`/`ELSE`/`ENDIF` structuring, `OP_CODESEPARATOR`-
//!   aware scriptCode, and the BIP342 tapscript opcode semantics.
//! - `verify.zig` — `verifyScript`: legacy/P2SH/segwit-v0/taproot
//!   (key-path + script-path) orchestration built on `interpreter.eval`.
//! - `script_tests_vectors.zig` / `script_tests_test.zig` — a pinned
//!   subset of Bitcoin Core's official `script_tests.json` corpus.
//! - `script_tests_witness_vectors.zig` / `script_tests_witness_test.zig` —
//!   the witness-bearing rows of that same corpus, which the file above
//!   excludes; the external oracle for segwit v0.
//! - `tx_findanddelete_vectors.zig` / `tx_findanddelete_test.zig` — the
//!   `FindAndDelete`/`OP_CODESEPARATOR`/`CONST_SCRIPTCODE` rows of Core's
//!   `tx_valid.json` + `tx_invalid.json` (real transactions).
//! - `tx_locktime_vectors.zig` / `tx_locktime_test.zig` — the BIP65/BIP112
//!   boundary rows of those same two files; the only external oracle for the
//!   locktime comparisons, since `script_tests.json`'s synthetic spend fixes
//!   `nLockTime = 0` and `nSequence = SEQUENCE_FINAL`.
//! - `findanddelete_test.zig` — Core's own `script_FindAndDelete` unit test,
//!   byte-for-byte.
//! - `e2e_test.zig` — real P2PKH/P2WPKH/P2TR spends verified end-to-end
//!   through `bitcointx` sighash + `k256`/`bip340` signatures.
//! - `dos_test.zig` — additional consensus-limit DoS teeth at the
//!   `verifyScript` level (complementing `interpreter.zig`'s own).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bitcoin Script consensus interpreter — full opcode set, CHECKSIG/CHECKMULTISIG; verifies bare/P2SH/segwit/P2TR key-path scripts.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant, // no shared/global state; every call is over caller-owned values
    .model_after = "Bitcoin Core script/interpreter.cpp (script_tests.json is Core's own conformance corpus); BIP16/62/65/66/112/141/142/143/144/146/340/341/342",
    .deps = .{ "bitcointx", "k256", "bip340", "ripemd160" },
};

pub const opcodes = @import("opcodes.zig");
pub const number = @import("number.zig");
pub const limits = @import("limits.zig");
pub const flags = @import("flags.zig");
pub const txctx = @import("txctx.zig");
pub const sigcheck = @import("sigcheck.zig");
pub const tapscript = @import("tapscript.zig");
pub const interpreter = @import("interpreter.zig");
pub const verify = @import("verify.zig");

// Flat re-exports of the primary public surface.
pub const ScriptFlags = flags.ScriptFlags;
pub const SigVersion = txctx.SigVersion;
pub const TxContext = txctx.TxContext;
pub const EvalError = interpreter.EvalError;
pub const VerifyError = verify.VerifyError;
pub const verifyScript = verify.verifyScript;
pub const Opcode = opcodes.Opcode;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule (and every
// vector/test file not otherwise imported above) must be named here too.
test {
    _ = opcodes;
    _ = number;
    _ = limits;
    _ = flags;
    _ = txctx;
    _ = sigcheck;
    _ = tapscript;
    _ = interpreter;
    _ = verify;
    _ = @import("asmparser.zig");
    _ = @import("script_tests_vectors.zig");
    _ = @import("script_tests_test.zig");
    _ = @import("script_tests_witness_test.zig");
    _ = @import("e2e_test.zig");
    _ = @import("dos_test.zig");
    _ = @import("tapscript_test.zig");
    _ = @import("precomputed_test.zig");
    _ = @import("findanddelete_test.zig");
    _ = @import("scriptcode_test.zig");
    _ = @import("tx_findanddelete_vectors.zig");
    _ = @import("tx_findanddelete_test.zig");
    _ = @import("tx_locktime_test.zig");
    _ = @import("consensus_kat_vectors.zig");
    _ = @import("consensus_kat_test.zig");
}

test "meta.deps names bitcointx, k256, bip340, ripemd160" {
    const std_testing = std.testing;
    try std_testing.expectEqual(@as(usize, 4), meta.deps.len);
    try std_testing.expect(std.mem.eql(u8, meta.deps[0], "bitcointx"));
    try std_testing.expect(std.mem.eql(u8, meta.deps[1], "k256"));
    try std_testing.expect(std.mem.eql(u8, meta.deps[2], "bip340"));
    try std_testing.expect(std.mem.eql(u8, meta.deps[3], "ripemd160"));
}
