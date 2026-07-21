// SPDX-License-Identifier: MIT
//! bitcoinscript — a Bitcoin Script interpreter / consensus VM: the stack
//! machine (`interpreter.zig`), ECDSA/pubkey encoding checks and CHECKSIG
//! sighash dispatch (`sigcheck.zig`, built on the sibling `bitcointx`/
//! `k256` modules), and the top-level `verifyScript` orchestration
//! (`verify.zig`) covering legacy, BIP16 P2SH, BIP141 segwit v0
//! (P2WPKH/P2WSH), and BIP341 taproot key-path spends. Published
//! consensus rules, verified against Bitcoin Core's own
//! `script_tests.json` corpus — see SPEC.md for the full verification
//! story and scope cuts (notably: BIP342 tapscript script-path spending is
//! NOT implemented — every witness stack shaped like a script-path spend
//! fails closed with a typed error, never silently accepted).
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
//! - `interpreter.zig` — the stack machine (`eval`): opcode dispatch,
//!   `IF`/`ELSE`/`ENDIF` structuring, `OP_CODESEPARATOR`-aware scriptCode.
//! - `verify.zig` — `verifyScript`: legacy/P2SH/segwit-v0/taproot
//!   orchestration built on `interpreter.eval`.
//! - `script_tests_vectors.zig` / `script_tests_test.zig` — a pinned
//!   subset of Bitcoin Core's official `script_tests.json` corpus.
//! - `e2e_test.zig` — real P2PKH/P2WPKH/P2TR spends verified end-to-end
//!   through `bitcointx` sighash + `k256`/`bip340` signatures.
//! - `dos_test.zig` — additional consensus-limit DoS teeth at the
//!   `verifyScript` level (complementing `interpreter.zig`'s own).

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant, // no shared/global state; every call is over caller-owned values
    .model_after = "Bitcoin Core script/interpreter.cpp (script_tests.json is Core's own conformance corpus); BIP16/62/65/66/112/141/142/143/144/146/340/341",
    .deps = .{ "bitcointx", "k256", "bip340", "ripemd160" },
};

pub const opcodes = @import("opcodes.zig");
pub const number = @import("number.zig");
pub const limits = @import("limits.zig");
pub const flags = @import("flags.zig");
pub const txctx = @import("txctx.zig");
pub const sigcheck = @import("sigcheck.zig");
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
    _ = interpreter;
    _ = verify;
    _ = @import("asmparser.zig");
    _ = @import("script_tests_vectors.zig");
    _ = @import("script_tests_test.zig");
    _ = @import("e2e_test.zig");
    _ = @import("dos_test.zig");
}

test "meta.deps names bitcointx, k256, bip340, ripemd160" {
    const std_testing = std.testing;
    try std_testing.expectEqual(@as(usize, 4), meta.deps.len);
    try std_testing.expect(std.mem.eql(u8, meta.deps[0], "bitcointx"));
    try std_testing.expect(std.mem.eql(u8, meta.deps[1], "k256"));
    try std_testing.expect(std.mem.eql(u8, meta.deps[2], "bip340"));
    try std_testing.expect(std.mem.eql(u8, meta.deps[3], "ripemd160"));
}
