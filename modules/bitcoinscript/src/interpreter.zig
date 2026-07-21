// SPDX-License-Identifier: MIT
//! The Bitcoin Script stack machine (`EvalScript` in Bitcoin Core
//! `script/interpreter.cpp`): parses and executes one script against a
//! caller-supplied main stack (+ a fresh altstack per call, matching
//! Bitcoin Core — the altstack does NOT persist across the scriptSig →
//! scriptPubKey → (P2SH-redeem/witness-script) chain the way the main
//! stack does; `verify.zig` owns that chaining).
//!
//! ## Threat model
//!
//! `script` is UNTRUSTED, attacker-controlled bytes. Every consensus DoS
//! bound (`limits.zig`) is enforced before the resource it bounds is
//! consumed (push-size checked before allocating, op-count/stack-size
//! checked before executing the opcode that would exceed them) — this
//! module never panics, infinite-loops (scripts have no jumps/loops, only
//! forward-only `IF`/`ELSE`/`ENDIF` structuring, so termination is
//! immediate from `script.len` being finite and bounded), or allocates
//! unboundedly on hostile input.
//!
//! ## Allocator contract
//!
//! `allocator` is assumed arena-like: every pushed/computed byte buffer
//! this module allocates (`allocator.dupe`/`ArrayList.append`) is owned by
//! the caller's arena and bulk-freed after the whole `verifyScript` call
//! completes — `eval` never frees an individual allocation. This keeps
//! duplication (`OP_DUP`/`OP_2DUP`/`OP_PICK`/…, which alias an existing
//! stack slice rather than copying it) and multisig's must-extract-before-
//! shrink pattern (below) sound without per-element refcounting.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const opcodes = @import("opcodes.zig");
const number = @import("number.zig");
const limits = @import("limits.zig");
const flags_mod = @import("flags.zig");
const sigcheck = @import("sigcheck.zig");
const txctx = @import("txctx.zig");
const ripemd160 = @import("ripemd160");

pub const ScriptFlags = flags_mod.ScriptFlags;
pub const SigVersion = txctx.SigVersion;
pub const TxContext = txctx.TxContext;
const Opcode = opcodes.Opcode;

pub const EvalError = error{
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    MinimalData,
    MinimalIf,
    EvalFalse,
    OpReturn,
    Verify,
    Equalverify,
    Checksigverify,
    Checkmultisigverify,
    Numequalverify,
    DiscourageUpgradableNops,
    SigNullfail,
    /// BIP147: `OP_CHECKMULTISIG`'s dummy stack element was non-empty.
    SigNulldummy,
    /// Catch-all for conditions Bitcoin Core itself folds into
    /// `SCRIPT_ERR_UNKNOWN_ERROR` (a `CScriptNum` construction that
    /// overflows or is non-minimal — distinct from the dedicated
    /// `MinimalData` class, which is push-*opcode* minimality only).
    UnknownError,
} || sigcheck.SigCheckError || bitcointx.legacy.LegacyError || bitcointx.bip143.Bip143Error;

const Stack = std.ArrayList([]const u8);

pub const Instruction = struct { opcode: u8, data: ?[]const u8, next: usize };

/// Reads one instruction at `script[i..]`: a bare opcode, or (for the
/// `0x00..0x4e` range) a data push whose length prefix shape depends on the
/// opcode byte itself. Shared by the main eval loop AND `scriptCodeFor`'s
/// `OP_CODESEPARATOR` removal pass, so both walk the exact same push-length
/// rules (a correctness requirement — see that function's doc comment).
pub fn readInstruction(script: []const u8, i: usize) EvalError!Instruction {
    const op = script[i];
    var pos = i + 1;
    if (op <= 0x4e) {
        var len: usize = undefined;
        if (op < 0x4c) {
            len = op;
        } else if (op == 0x4c) {
            if (pos >= script.len) return error.BadOpcode;
            len = script[pos];
            pos += 1;
        } else if (op == 0x4d) {
            if (pos + 2 > script.len) return error.BadOpcode;
            len = std.mem.readInt(u16, script[pos..][0..2], .little);
            pos += 2;
        } else {
            if (pos + 4 > script.len) return error.BadOpcode;
            len = std.mem.readInt(u32, script[pos..][0..4], .little);
            pos += 4;
        }
        if (pos + len > script.len) return error.BadOpcode;
        const data = script[pos .. pos + len];
        pos += len;
        return .{ .opcode = op, .data = data, .next = pos };
    }
    return .{ .opcode = op, .data = null, .next = pos };
}

/// Bitcoin Core `CheckMinimalPush`: the opcode chosen to push `data` must
/// be the shortest one capable of encoding it.
fn checkMinimalPush(opcode: u8, data: []const u8) bool {
    if (data.len == 0) return opcode == 0x00;
    if (data.len == 1 and data[0] >= 1 and data[0] <= 16) return opcode == 0x50 + data[0];
    if (data.len == 1 and data[0] == 0x81) return opcode == 0x4f;
    if (data.len <= 75) return opcode == data.len;
    if (data.len <= 255) return opcode == 0x4c;
    if (data.len <= 65535) return opcode == 0x4d;
    return opcode == 0x4e;
}

/// The scriptCode a `CHECKSIG`-family opcode signs over: `script[from..]`
/// (everything from the last executed `OP_CODESEPARATOR` onward — `from`
/// is 0 if none executed yet). For `sig_version == .base` (legacy), Bitcoin
/// Core additionally runs `FindAndDelete(OP_CODESEPARATOR)` over that
/// sub-script — literal `0xab` opcode bytes are dropped (parsed
/// opcode-by-opcode via `readInstruction`, so a `0xab` *byte inside a
/// push's data payload* is correctly left alone). BIP143 §"No
/// FindAndDelete" makes `witness_v0` skip this step entirely: the
/// sub-script from `from` onward is used exactly as-is.
fn scriptCodeFor(allocator: Allocator, script: []const u8, from: usize, sig_version: SigVersion) EvalError![]const u8 {
    const sub = script[from..];
    if (sig_version == .witness_v0) return sub;

    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < sub.len) {
        const instr = try readInstruction(sub, i);
        if (instr.opcode != @intFromEnum(Opcode.OP_CODESEPARATOR)) {
            try out.appendSlice(allocator, sub[i..instr.next]);
        }
        i = instr.next;
    }
    return out.toOwnedSlice(allocator);
}

fn allExecuting(cond_stack: []const bool) bool {
    for (cond_stack) |v| {
        if (!v) return false;
    }
    return true;
}

const State = struct {
    allocator: Allocator,
    stack: *Stack,
    altstack: *Stack,
    script: []const u8,
    last_codesep: usize = 0,
    op_count: usize = 0,
    ctx: TxContext,
    sig_version: SigVersion,
    flags: ScriptFlags,

    fn pushOwned(self: *State, data: []const u8) EvalError!void {
        const owned = try self.allocator.dupe(u8, data);
        try self.stack.append(self.allocator, owned);
    }

    fn pushExisting(self: *State, data: []const u8) EvalError!void {
        try self.stack.append(self.allocator, data);
    }

    fn pushBool(self: *State, v: bool) EvalError!void {
        try self.pushOwned(if (v) &[_]u8{1} else &[_]u8{});
    }

    fn pushNum(self: *State, v: i64) EvalError!void {
        var buf: [9]u8 = undefined;
        try self.pushOwned(number.encode(v, &buf));
    }

    /// Pops the top element and decodes it as a `CScriptNum` (4-byte
    /// bound). Non-minimal encoding or overflow both fold into
    /// `UnknownError` (module doc comment on `EvalError.UnknownError`).
    fn popNum(self: *State) EvalError!i64 {
        if (self.stack.items.len < 1) return error.InvalidStackOperation;
        const top = self.stack.pop().?;
        return number.decode(top, self.flags.minimaldata, number.default_max_num_size) catch error.UnknownError;
    }
};

fn checkSigForState(state: *State, sig: []const u8, pubkey: []const u8) EvalError!bool {
    const script_code = try scriptCodeFor(state.allocator, state.script, state.last_codesep, state.sig_version);
    return sigcheck.checkEcdsaSig(state.allocator, sig, pubkey, script_code, state.ctx, state.sig_version, state.flags);
}

fn execOpcode(state: *State, opcode: u8, instr_next: usize) EvalError!void {
    const stack = state.stack;
    const altstack = state.altstack;
    const allocator = state.allocator;

    switch (opcode) {
        0x4f => try state.pushOwned(&[_]u8{0x81}), // OP_1NEGATE
        0x51...0x60 => try state.pushOwned(&[_]u8{opcode - 0x50}), // OP_1..OP_16

        @intFromEnum(Opcode.OP_NOP) => {},

        @intFromEnum(Opcode.OP_VERIFY) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const top = stack.pop().?;
            if (!number.castToBool(top)) return error.Verify;
        },
        @intFromEnum(Opcode.OP_RETURN) => return error.OpReturn,

        @intFromEnum(Opcode.OP_TOALTSTACK) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            try altstack.append(allocator, stack.pop().?);
        },
        @intFromEnum(Opcode.OP_FROMALTSTACK) => {
            if (altstack.items.len < 1) return error.InvalidAltstackOperation;
            try stack.append(allocator, altstack.pop().?);
        },
        @intFromEnum(Opcode.OP_2DROP) => {
            if (stack.items.len < 2) return error.InvalidStackOperation;
            stack.shrinkRetainingCapacity(stack.items.len - 2);
        },
        @intFromEnum(Opcode.OP_2DUP) => {
            const n = stack.items.len;
            if (n < 2) return error.InvalidStackOperation;
            try state.pushExisting(stack.items[n - 2]);
            try state.pushExisting(stack.items[n - 1]);
        },
        @intFromEnum(Opcode.OP_3DUP) => {
            const n = stack.items.len;
            if (n < 3) return error.InvalidStackOperation;
            try state.pushExisting(stack.items[n - 3]);
            try state.pushExisting(stack.items[n - 2]);
            try state.pushExisting(stack.items[n - 1]);
        },
        @intFromEnum(Opcode.OP_2OVER) => {
            const n = stack.items.len;
            if (n < 4) return error.InvalidStackOperation;
            try state.pushExisting(stack.items[n - 4]);
            try state.pushExisting(stack.items[n - 3]);
        },
        @intFromEnum(Opcode.OP_2ROT) => {
            const n = stack.items.len;
            if (n < 6) return error.InvalidStackOperation;
            const a = stack.orderedRemove(n - 6);
            const b = stack.orderedRemove(n - 6);
            try state.pushExisting(a);
            try state.pushExisting(b);
        },
        @intFromEnum(Opcode.OP_2SWAP) => {
            const n = stack.items.len;
            if (n < 4) return error.InvalidStackOperation;
            const a = stack.items[n - 4];
            const b = stack.items[n - 3];
            const c = stack.items[n - 2];
            const d = stack.items[n - 1];
            stack.items[n - 4] = c;
            stack.items[n - 3] = d;
            stack.items[n - 2] = a;
            stack.items[n - 1] = b;
        },
        @intFromEnum(Opcode.OP_IFDUP) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const top = stack.items[stack.items.len - 1];
            if (number.castToBool(top)) try state.pushExisting(top);
        },
        @intFromEnum(Opcode.OP_DEPTH) => try state.pushNum(@intCast(stack.items.len)),
        @intFromEnum(Opcode.OP_DROP) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            _ = stack.pop();
        },
        @intFromEnum(Opcode.OP_DUP) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            try state.pushExisting(stack.items[stack.items.len - 1]);
        },
        @intFromEnum(Opcode.OP_NIP) => {
            if (stack.items.len < 2) return error.InvalidStackOperation;
            _ = stack.orderedRemove(stack.items.len - 2);
        },
        @intFromEnum(Opcode.OP_OVER) => {
            if (stack.items.len < 2) return error.InvalidStackOperation;
            try state.pushExisting(stack.items[stack.items.len - 2]);
        },
        @intFromEnum(Opcode.OP_PICK), @intFromEnum(Opcode.OP_ROLL) => {
            const n = try state.popNum();
            if (n < 0 or @as(u64, @intCast(n)) >= stack.items.len) return error.InvalidStackOperation;
            const idx = stack.items.len - 1 - @as(usize, @intCast(n));
            const v = stack.items[idx];
            if (opcode == @intFromEnum(Opcode.OP_ROLL)) {
                _ = stack.orderedRemove(idx);
            }
            try state.pushExisting(v);
        },
        @intFromEnum(Opcode.OP_ROT) => {
            if (stack.items.len < 3) return error.InvalidStackOperation;
            const v = stack.orderedRemove(stack.items.len - 3);
            try state.pushExisting(v);
        },
        @intFromEnum(Opcode.OP_SWAP) => {
            const n = stack.items.len;
            if (n < 2) return error.InvalidStackOperation;
            const tmp = stack.items[n - 2];
            stack.items[n - 2] = stack.items[n - 1];
            stack.items[n - 1] = tmp;
        },
        @intFromEnum(Opcode.OP_TUCK) => {
            const n = stack.items.len;
            if (n < 2) return error.InvalidStackOperation;
            try stack.insert(allocator, n - 2, stack.items[n - 1]);
        },

        @intFromEnum(Opcode.OP_SIZE) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            try state.pushNum(@intCast(stack.items[stack.items.len - 1].len));
        },

        @intFromEnum(Opcode.OP_EQUAL), @intFromEnum(Opcode.OP_EQUALVERIFY) => {
            if (stack.items.len < 2) return error.InvalidStackOperation;
            const b = stack.pop().?;
            const a = stack.pop().?;
            const eq = std.mem.eql(u8, a, b);
            if (opcode == @intFromEnum(Opcode.OP_EQUALVERIFY)) {
                if (!eq) return error.Equalverify;
            } else {
                try state.pushBool(eq);
            }
        },

        @intFromEnum(Opcode.OP_1ADD) => try state.pushNum((try state.popNum()) + 1),
        @intFromEnum(Opcode.OP_1SUB) => try state.pushNum((try state.popNum()) - 1),
        @intFromEnum(Opcode.OP_NEGATE) => try state.pushNum(-(try state.popNum())),
        @intFromEnum(Opcode.OP_ABS) => {
            const a = try state.popNum();
            try state.pushNum(if (a < 0) -a else a);
        },
        @intFromEnum(Opcode.OP_NOT) => try state.pushBool((try state.popNum()) == 0),
        @intFromEnum(Opcode.OP_0NOTEQUAL) => try state.pushBool((try state.popNum()) != 0),
        @intFromEnum(Opcode.OP_ADD) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushNum(a + b);
        },
        @intFromEnum(Opcode.OP_SUB) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushNum(a - b);
        },
        @intFromEnum(Opcode.OP_BOOLAND) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a != 0 and b != 0);
        },
        @intFromEnum(Opcode.OP_BOOLOR) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a != 0 or b != 0);
        },
        @intFromEnum(Opcode.OP_NUMEQUAL), @intFromEnum(Opcode.OP_NUMEQUALVERIFY) => {
            const b = try state.popNum();
            const a = try state.popNum();
            if (opcode == @intFromEnum(Opcode.OP_NUMEQUALVERIFY)) {
                if (a != b) return error.Numequalverify;
            } else {
                try state.pushBool(a == b);
            }
        },
        @intFromEnum(Opcode.OP_NUMNOTEQUAL) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a != b);
        },
        @intFromEnum(Opcode.OP_LESSTHAN) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a < b);
        },
        @intFromEnum(Opcode.OP_GREATERTHAN) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a > b);
        },
        @intFromEnum(Opcode.OP_LESSTHANOREQUAL) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a <= b);
        },
        @intFromEnum(Opcode.OP_GREATERTHANOREQUAL) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushBool(a >= b);
        },
        @intFromEnum(Opcode.OP_MIN) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushNum(@min(a, b));
        },
        @intFromEnum(Opcode.OP_MAX) => {
            const b = try state.popNum();
            const a = try state.popNum();
            try state.pushNum(@max(a, b));
        },
        @intFromEnum(Opcode.OP_WITHIN) => {
            const max_v = try state.popNum();
            const min_v = try state.popNum();
            const x = try state.popNum();
            try state.pushBool(min_v <= x and x < max_v);
        },

        @intFromEnum(Opcode.OP_RIPEMD160) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const data = stack.pop().?;
            var out: [20]u8 = undefined;
            ripemd160.Ripemd160.hash(data, &out, .{});
            try state.pushOwned(&out);
        },
        @intFromEnum(Opcode.OP_SHA1) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const data = stack.pop().?;
            var out: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
            std.crypto.hash.Sha1.hash(data, &out, .{});
            try state.pushOwned(&out);
        },
        @intFromEnum(Opcode.OP_SHA256) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const data = stack.pop().?;
            var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
            try state.pushOwned(&out);
        },
        @intFromEnum(Opcode.OP_HASH160) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const data = stack.pop().?;
            var out: [20]u8 = undefined;
            ripemd160.hash160(data, &out);
            try state.pushOwned(&out);
        },
        @intFromEnum(Opcode.OP_HASH256) => {
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const data = stack.pop().?;
            const out = bitcointx.hash256.sha256d(data);
            try state.pushOwned(&out);
        },
        @intFromEnum(Opcode.OP_CODESEPARATOR) => {
            state.last_codesep = instr_next;
        },

        @intFromEnum(Opcode.OP_CHECKSIG), @intFromEnum(Opcode.OP_CHECKSIGVERIFY) => {
            if (stack.items.len < 2) return error.InvalidStackOperation;
            const pubkey = stack.pop().?;
            const sig = stack.pop().?;
            const ok = try checkSigForState(state, sig, pubkey);
            if (!ok and state.flags.nullfail and sig.len != 0) return error.SigNullfail;
            if (opcode == @intFromEnum(Opcode.OP_CHECKSIGVERIFY)) {
                if (!ok) return error.Checksigverify;
            } else {
                try state.pushBool(ok);
            }
        },

        @intFromEnum(Opcode.OP_CHECKMULTISIG), @intFromEnum(Opcode.OP_CHECKMULTISIGVERIFY) => {
            const n_keys_i = try state.popNum();
            if (n_keys_i < 0 or n_keys_i > limits.max_pubkeys_per_multisig) return error.PubkeyCount;
            const n_keys: usize = @intCast(n_keys_i);
            state.op_count += n_keys;
            if (state.op_count > limits.max_ops_per_script) return error.OpCount;
            if (stack.items.len < n_keys) return error.InvalidStackOperation;
            // Bitcoin Core walks keys (and, below, signatures) starting
            // from the TOP of their stack block -- i.e. the LAST-pushed
            // pubkey is tried first, not the first-pushed one
            // (`stacktop(-ikey)` with `ikey` initialized just past the
            // popped count, then incrementing toward the bottom). Reversed
            // from naive "push order" reading of the script.
            var pubkey_buf: [20][]const u8 = undefined;
            {
                var j: usize = 0;
                while (j < n_keys) : (j += 1) pubkey_buf[j] = stack.items[stack.items.len - 1 - j];
            }
            stack.shrinkRetainingCapacity(stack.items.len - n_keys);
            const pubkeys = pubkey_buf[0..n_keys];

            const n_sigs_i = try state.popNum();
            if (n_sigs_i < 0 or n_sigs_i > @as(i64, @intCast(n_keys))) return error.SigCount;
            const n_sigs: usize = @intCast(n_sigs_i);
            if (stack.items.len < n_sigs) return error.InvalidStackOperation;
            var sig_buf: [20][]const u8 = undefined;
            {
                var j: usize = 0;
                while (j < n_sigs) : (j += 1) sig_buf[j] = stack.items[stack.items.len - 1 - j];
            }
            stack.shrinkRetainingCapacity(stack.items.len - n_sigs);
            const sigs = sig_buf[0..n_sigs];

            if (stack.items.len < 1) return error.InvalidStackOperation;
            const dummy = stack.pop().?;
            if (state.flags.nulldummy and dummy.len != 0) return error.SigNulldummy;

            const script_code = try scriptCodeFor(allocator, state.script, state.last_codesep, state.sig_version);
            // Direct translation of Bitcoin Core's matching loop
            // (`interpreter.cpp` `OP_CHECKMULTISIG`): `key_i`/`sig_i` index
            // into `pubkeys`/`sigs` (both top-to-bottom, see above);
            // `keys_remaining`/`sigs_remaining` are Core's `nKeysCount`/
            // `nSigsCount`, which both count DOWN each iteration (keys
            // always; sigs only on a match) -- encoding is checked for
            // EVERY attempted pair regardless of match outcome
            // (`checkEcdsaSig` raises a hard error for an encoding
            // violation, matching Core's unconditional
            // `CheckSignatureEncoding && CheckPubKeyEncoding` gate ahead of
            // the actual curve check). The bail check
            // (`sigs_remaining > keys_remaining => fail`) is evaluated
            // EVERY iteration, NOT only after a match -- otherwise a run of
            // all-non-matching attempts (e.g. every supplied "signature" is
            // empty) would walk `key_i` past `pubkeys.len` with no
            // terminating condition, since `sigs_remaining` would never
            // decrement on its own.
            var key_i: usize = 0;
            var sig_i: usize = 0;
            var keys_remaining = n_keys;
            var sigs_remaining = n_sigs;
            var success = true;
            while (success and sigs_remaining > 0) {
                if (key_i >= n_keys) return error.InvalidStackOperation; // unreachable given the bound below; defense in depth
                const ok = try sigcheck.checkEcdsaSig(allocator, sigs[sig_i], pubkeys[key_i], script_code, state.ctx, state.sig_version, state.flags);
                if (ok) {
                    sig_i += 1;
                    sigs_remaining -= 1;
                }
                key_i += 1;
                keys_remaining -= 1;
                if (sigs_remaining > keys_remaining) success = false;
            }

            if (!success and state.flags.nullfail) {
                for (sigs) |s| {
                    if (s.len != 0) return error.SigNullfail;
                }
            }

            if (opcode == @intFromEnum(Opcode.OP_CHECKMULTISIGVERIFY)) {
                if (!success) return error.Checkmultisigverify;
            } else {
                try state.pushBool(success);
            }
        },

        @intFromEnum(Opcode.OP_CHECKLOCKTIMEVERIFY) => {
            if (!state.flags.checklocktimeverify) {
                if (state.flags.discourage_upgradable_nops) return error.DiscourageUpgradableNops;
                return; // acts as OP_NOP2
            }
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const top = stack.items[stack.items.len - 1];
            const locktime = number.decode(top, state.flags.minimaldata, number.locktime_max_num_size) catch return error.UnknownError;
            if (locktime < 0) return error.NegativeLocktime;
            const threshold: i64 = 500_000_000;
            const tx_locktime: i64 = @intCast(state.ctx.tx.locktime);
            const same_kind = (locktime < threshold) == (tx_locktime < threshold);
            if (!same_kind) return error.UnsatisfiedLocktime;
            if (locktime > tx_locktime) return error.UnsatisfiedLocktime;
            if (state.ctx.tx.vin[state.ctx.input_index].sequence == 0xffffffff) return error.UnsatisfiedLocktime;
        },

        @intFromEnum(Opcode.OP_CHECKSEQUENCEVERIFY) => {
            if (!state.flags.checksequenceverify) {
                if (state.flags.discourage_upgradable_nops) return error.DiscourageUpgradableNops;
                return; // acts as OP_NOP3
            }
            if (stack.items.len < 1) return error.InvalidStackOperation;
            const top = stack.items[stack.items.len - 1];
            const seq_num = number.decode(top, state.flags.minimaldata, number.locktime_max_num_size) catch return error.UnknownError;
            if (seq_num < 0) return error.NegativeLocktime;

            const disable_flag: i64 = 1 << 31;
            if ((seq_num & disable_flag) != 0) return; // relative-locktime disabled by the argument: success, no further checks

            if (state.ctx.tx.version < 2) return error.UnsatisfiedLocktime;
            const tx_seq: u32 = state.ctx.tx.vin[state.ctx.input_index].sequence;
            if ((tx_seq & (1 << 31)) != 0) return error.UnsatisfiedLocktime;

            const type_flag: i64 = 1 << 22;
            const mask: i64 = 0x0000ffff;
            const tx_seq_i64: i64 = @intCast(tx_seq);
            if ((seq_num & type_flag) != (tx_seq_i64 & type_flag)) return error.UnsatisfiedLocktime;
            if ((seq_num & mask) > (tx_seq_i64 & mask)) return error.UnsatisfiedLocktime;
        },

        @intFromEnum(Opcode.OP_NOP1),
        @intFromEnum(Opcode.OP_NOP4),
        @intFromEnum(Opcode.OP_NOP5),
        @intFromEnum(Opcode.OP_NOP6),
        @intFromEnum(Opcode.OP_NOP7),
        @intFromEnum(Opcode.OP_NOP8),
        @intFromEnum(Opcode.OP_NOP9),
        @intFromEnum(Opcode.OP_NOP10),
        => {
            if (state.flags.discourage_upgradable_nops) return error.DiscourageUpgradableNops;
        },

        else => return error.BadOpcode,
    }
}

/// Executes `script` against `stack` (persists across calls, per Bitcoin
/// Core's scriptSig→scriptPubKey→redeem/witness-script chaining — caller's
/// job) with a fresh altstack (never persists — module doc comment).
pub fn eval(
    allocator: Allocator,
    stack: *Stack,
    script: []const u8,
    ctx: TxContext,
    sig_version: SigVersion,
    flags: ScriptFlags,
) EvalError!void {
    if (script.len > limits.max_script_size) return error.ScriptSize;

    var altstack: Stack = .empty;
    var cond_stack: std.ArrayList(bool) = .empty;

    var state: State = .{
        .allocator = allocator,
        .stack = stack,
        .altstack = &altstack,
        .script = script,
        .ctx = ctx,
        .sig_version = sig_version,
        .flags = flags,
    };

    var pc: usize = 0;
    while (pc < script.len) {
        const instr = try readInstruction(script, pc);
        pc = instr.next;

        if (opcodes.isDisabled(instr.opcode)) return error.DisabledOpcode;
        if (opcodes.isReservedConditional(instr.opcode)) return error.BadOpcode;

        // Op-count is metered for every non-push opcode > OP_16 (this
        // includes IF/NOTIF/ELSE/ENDIF themselves), regardless of whether
        // the current branch is executing -- Bitcoin Core counts this
        // before ever consulting fExec, so a script can't hide unbounded
        // opcodes inside a never-taken branch.
        if (instr.data == null and instr.opcode > @intFromEnum(Opcode.OP_16)) {
            state.op_count += 1;
            if (state.op_count > limits.max_ops_per_script) return error.OpCount;
        }

        const exec = allExecuting(cond_stack.items);

        if (instr.data) |data| {
            if (data.len > limits.max_script_element_size) return error.PushSize;
            if (exec) {
                if (flags.minimaldata and !checkMinimalPush(instr.opcode, data)) return error.MinimalData;
                try state.pushOwned(data);
            }
        } else if (instr.opcode == @intFromEnum(Opcode.OP_IF) or instr.opcode == @intFromEnum(Opcode.OP_NOTIF)) {
            var value = false;
            if (exec) {
                if (stack.items.len < 1) return error.InvalidStackOperation;
                const top = stack.items[stack.items.len - 1];
                // Bitcoin Core gates MINIMALIF on `sigversion ==
                // WITNESS_V0` in addition to the flag -- it is not checked
                // for legacy/base-context IF/NOTIF at all, even with the
                // flag on (script_tests.json has vectors that rely on
                // exactly this: MINIMALIF set, a non-minimal boolean, base
                // context -- expected result is EVAL_FALSE, not MINIMALIF).
                if (flags.minimalif and sig_version == .witness_v0) {
                    if (top.len > 1 or (top.len == 1 and top[0] != 1)) return error.MinimalIf;
                }
                value = number.castToBool(top);
                stack.shrinkRetainingCapacity(stack.items.len - 1);
            }
            const is_notif = instr.opcode == @intFromEnum(Opcode.OP_NOTIF);
            try cond_stack.append(allocator, value != is_notif);
        } else if (instr.opcode == @intFromEnum(Opcode.OP_ELSE)) {
            if (cond_stack.items.len == 0) return error.UnbalancedConditional;
            const last = cond_stack.items.len - 1;
            cond_stack.items[last] = !cond_stack.items[last];
        } else if (instr.opcode == @intFromEnum(Opcode.OP_ENDIF)) {
            if (cond_stack.items.len == 0) return error.UnbalancedConditional;
            _ = cond_stack.pop();
        } else if (exec) {
            try execOpcode(&state, instr.opcode, instr.next);
        }

        if (stack.items.len + altstack.items.len > limits.max_stack_size) return error.StackSize;
    }

    if (cond_stack.items.len != 0) return error.UnbalancedConditional;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn dummyCtx() TxContext {
    return .{
        .tx = .{ .version = 1, .vin = &.{}, .vout = &.{}, .witness = &.{}, .locktime = 0, .has_witness = false },
        .input_index = 0,
        .spent_outputs = &.{},
    };
}

fn run(script: []const u8) EvalError!Stack {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var stack: Stack = .empty;
    try eval(arena.allocator(), &stack, script, dummyCtx(), .base, ScriptFlags.none);
    return stack;
}

test "OP_1 OP_2 OP_ADD OP_3 OP_EQUAL leaves true" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var stack: Stack = .empty;
    // 0x51 0x52 0x93 0x53 0x87
    try eval(arena.allocator(), &stack, &.{ 0x51, 0x52, 0x93, 0x53, 0x87 }, dummyCtx(), .base, ScriptFlags.none);
    try testing.expectEqual(@as(usize, 1), stack.items.len);
    try testing.expect(number.castToBool(stack.items[0]));
}

test "unbalanced OP_IF (no ENDIF) is rejected" {
    try testing.expectError(error.UnbalancedConditional, run(&.{ 0x51, 0x63 })); // OP_1 OP_IF
}

test "OP_ELSE/OP_ENDIF with empty condition stack are rejected" {
    try testing.expectError(error.UnbalancedConditional, run(&.{0x67})); // bare OP_ELSE
    try testing.expectError(error.UnbalancedConditional, run(&.{0x68})); // bare OP_ENDIF
}

test "disabled opcode fails even inside a never-taken IF branch" {
    // OP_0 OP_IF OP_CAT OP_ENDIF -- branch never executes, but OP_CAT still fails.
    try testing.expectError(error.DisabledOpcode, run(&.{ 0x00, 0x63, 0x7e, 0x68 }));
}

test "DoS: script exceeding MAX_SCRIPT_SIZE is rejected before any execution" {
    var big: [limits.max_script_size + 1]u8 = undefined;
    @memset(&big, 0x61); // OP_NOP repeated
    try testing.expectError(error.ScriptSize, run(&big));
}

test "DoS: op-count over the limit is rejected" {
    var script: [limits.max_ops_per_script + 2]u8 = undefined;
    @memset(&script, 0x61); // OP_NOP
    try testing.expectError(error.OpCount, run(&script));
}

test "DoS: oversized single push (> MAX_SCRIPT_ELEMENT_SIZE) is rejected" {
    var script: [3 + limits.max_script_element_size + 1]u8 = undefined;
    script[0] = 0x4d; // OP_PUSHDATA2
    std.mem.writeInt(u16, script[1..3], @intCast(limits.max_script_element_size + 1), .little);
    @memset(script[3..], 0xab);
    try testing.expectError(error.PushSize, run(&script));
}

test "DoS: stack-size limit is enforced (many small pushes)" {
    const allocator = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(allocator);
    var i: usize = 0;
    while (i < limits.max_stack_size + 5) : (i += 1) try script.append(allocator, 0x51); // OP_1
    try testing.expectError(error.StackSize, run(script.items));
}

test "MINIMALDATA: violation errors when flag set, succeeds when not" {
    const script = [_]u8{ 0x4c, 0x01, 0x01 }; // PUSHDATA1 <0x01>
    var arena1 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena1.deinit();
    var stack1: Stack = .empty;
    try testing.expectError(error.MinimalData, eval(arena1.allocator(), &stack1, &script, dummyCtx(), .base, .{ .minimaldata = true }));

    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    var stack2: Stack = .empty;
    try eval(arena2.allocator(), &stack2, &script, dummyCtx(), .base, ScriptFlags.none);
    try testing.expectEqual(@as(usize, 1), stack2.items.len);
}

test "OP_CHECKLOCKTIMEVERIFY without the flag is a plain NOP" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var stack: Stack = .empty;
    // push a CLTV arg then execute OP_CHECKLOCKTIMEVERIFY without the flag enabled.
    try eval(arena.allocator(), &stack, &.{ 0x01, 0x05, 0xb1 }, dummyCtx(), .base, ScriptFlags.none);
    try testing.expectEqual(@as(usize, 1), stack.items.len); // arg still on stack, untouched
}
