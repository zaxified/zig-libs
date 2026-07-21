// SPDX-License-Identifier: MIT
//! Consensus DoS bounds (Bitcoin Core `script/script.h` / `policy/policy.h`
//! constants + `interpreter.cpp`'s `EvalScript`). Executing a script is
//! executing UNTRUSTED, attacker-supplied bytes — every one of these is a
//! hard, typed-error-on-exceed ceiling, never a soft/advisory limit.

/// A single element pushed onto the stack may be at most this many bytes.
pub const max_script_element_size: usize = 520;
/// A single scriptSig/scriptPubKey/P2SH-redeem-script/witness-script may be
/// at most this many bytes.
pub const max_script_size: usize = 10_000;
/// Combined main+alt stack element count ceiling.
pub const max_stack_size: usize = 1_000;
/// Non-push opcode count ceiling per script (pushes are metered separately
/// by `max_script_size`/`max_script_element_size`, not this counter).
pub const max_ops_per_script: usize = 201;
/// `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY` public-key count ceiling.
pub const max_pubkeys_per_multisig: i64 = 20;
/// A witness stack (`vin[i]`'s items) may hold at most this many items.
pub const max_stack_items_in_witness: usize = 1_000;
