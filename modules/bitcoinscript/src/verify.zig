// SPDX-License-Identifier: MIT
//! `verifyScript` — the top-level entry point (Bitcoin Core `VerifyScript`
//! in `script/interpreter.cpp`): orchestrates scriptSig → scriptPubKey →
//! (BIP16 P2SH-redeem | BIP141 segwit-v0 witness-script/P2WPKH-template |
//! BIP341 taproot key-path) execution over `interpreter.eval`, matching
//! Bitcoin Core's exact control flow, including its quirks (the stack
//! carried from *after scriptSig, before scriptPubKey* is what P2SH
//! resumes from; a witness program's scriptSig must be empty; a
//! P2SH-wrapped witness program's scriptSig must be exactly one push of
//! the redeem script, byte for byte).
//!
//! ## Taproot: key-path AND script-path (BIP341/342)
//!
//! `wp.version == 1` (taproot) with a witness stack of exactly one element
//! (after optional annex-stripping) is verified directly as a BIP340
//! Schnorr signature over the BIP341 key-path sighash — no script is
//! executed at all, per BIP341. A witness stack with more elements is a
//! **script-path (tapscript, BIP342) spend**: the last item is the control
//! block, the second-to-last is the leaf script, and the rest seed the
//! stack. `verifyTaprootScriptPath` checks the BIP341 taproot commitment
//! (control block → tapleaf hash → Merkle root → tweak → output-key match),
//! then executes the leaf under `interpreter.evalTapscript` with BIP342
//! semantics (`OP_SUCCESSx` pre-scan, Schnorr `OP_CHECKSIG`/`OP_CHECKSIGADD`,
//! the validation-weight budget, mandatory MINIMALIF). See `tapscript.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const bip340 = @import("bip340");
const interpreter = @import("interpreter.zig");
const number = @import("number.zig");
const flags_mod = @import("flags.zig");
const txctx = @import("txctx.zig");
const limits = @import("limits.zig");
const tapscript = @import("tapscript.zig");

pub const ScriptFlags = flags_mod.ScriptFlags;
pub const TxContext = txctx.TxContext;
pub const SigVersion = txctx.SigVersion;

pub const VerifyError = interpreter.EvalError || bitcointx.bip341.Bip341Error || error{
    SigPushonly,
    CleanStack,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2SH,
    WitnessUnexpected,
    DiscourageUpgradableWitnessProgram,
    InvalidTaprootSignature,
    /// BIP341 script-path: the control block's length is not `33 + 32m`
    /// (`0 <= m <= 128`).
    TaprootWrongControlSize,
    /// BIP341 script-path: the control block does not commit to the witness
    /// program (the recomputed taproot output key's x-coordinate/parity does
    /// not match).
    TaprootCommitmentMismatch,
    /// BIP341 policy (`discourage_upgradable_taproot_version`): the leaf
    /// version is not the assigned tapscript version `0xc0`.
    DiscourageUpgradableTaprootVersion,
};

// ── script templates (BIP16 / BIP141) ───────────────────────────────────

fn isPushOnly(script: []const u8) bool {
    var i: usize = 0;
    while (i < script.len) {
        const instr = interpreter.readInstruction(script, i) catch return false;
        if (instr.opcode > 0x60) return false; // Bitcoin Core CScript::IsPushOnly: opcode <= OP_16
        i = instr.next;
    }
    return true;
}

/// `script_sig` must be exactly one push instruction whose data equals
/// `expected`, and nothing else (BIP16's anti-malleability rule for
/// P2SH-wrapped witness programs).
fn isExactPush(script_sig: []const u8, expected: []const u8) bool {
    if (script_sig.len == 0) return false;
    const instr = interpreter.readInstruction(script_sig, 0) catch return false;
    if (instr.next != script_sig.len) return false;
    const data = instr.data orelse return false;
    return std.mem.eql(u8, data, expected);
}

fn isP2sh(script_pubkey: []const u8) bool {
    return script_pubkey.len == 23 and script_pubkey[0] == 0xa9 and script_pubkey[1] == 0x14 and script_pubkey[22] == 0x87;
}

const WitnessProgram = struct { version: u8, program: []const u8 };

/// Bitcoin Core `CScript::IsWitnessProgram`: `OP_0`/`OP_1..OP_16` followed
/// by a single minimal 2..40-byte push, nothing else, total length 4..42.
fn parseWitnessProgram(script_pubkey: []const u8) ?WitnessProgram {
    if (script_pubkey.len < 4 or script_pubkey.len > 42) return null;
    const first = script_pubkey[0];
    const version: u8 = if (first == 0x00) 0 else if (first >= 0x51 and first <= 0x60) first - 0x50 else return null;
    const push_len = script_pubkey[1];
    if (push_len < 2 or push_len > 40) return null;
    if (script_pubkey.len != @as(usize, 2) + push_len) return null;
    return .{ .version = version, .program = script_pubkey[2..] };
}

// ── BIP341 taproot key-path ─────────────────────────────────────────────

/// Total serialized byte size of an input's witness stack (BIP342's
/// validation-weight budget base): `compact_size(n) + Σ (compact_size(len_i)
/// + len_i)`.
fn witnessSerializedSize(witness: []const []const u8) usize {
    var total: usize = bitcointx.compactSizeLen(witness.len);
    for (witness) |item| {
        total += bitcointx.compactSizeLen(item.len);
        total += item.len;
    }
    return total;
}

/// BIP341 taproot spend dispatch: key-path (1 item after annex-stripping) or
/// script-path (2+ items). `program_x` is the 32-byte witness program (the
/// output key's x-coordinate). `witness` is the FULL, un-stripped stack (its
/// serialized size seeds the BIP342 weight budget).
fn verifyTaproot(allocator: Allocator, program_x: []const u8, witness: []const []const u8, flags: ScriptFlags, ctx: TxContext) VerifyError!void {
    if (program_x.len != 32) return error.InvalidTaprootSignature;

    var items = witness;
    var annex: ?[]const u8 = null;
    // BIP341 annex: present iff >=2 items remain and the last starts 0x50.
    if (items.len >= 2 and items[items.len - 1].len >= 1 and items[items.len - 1][0] == 0x50) {
        annex = items[items.len - 1];
        items = items[0 .. items.len - 1];
    }
    if (items.len == 0) return error.WitnessProgramWitnessEmpty;
    if (items.len == 1) return verifyTaprootKeyPath(allocator, program_x, items[0], ctx);
    return verifyTaprootScriptPath(allocator, program_x, items, annex, witness, flags, ctx);
}

fn verifyTaprootKeyPath(allocator: Allocator, program_x: []const u8, sig_bytes: []const u8, ctx: TxContext) VerifyError!void {
    if (sig_bytes.len != 64 and sig_bytes.len != 65) return error.InvalidTaprootSignature;
    const hash_type: u8 = if (sig_bytes.len == 65) sig_bytes[64] else bitcointx.bip341.SIGHASH_DEFAULT;
    if (sig_bytes.len == 65 and hash_type == bitcointx.bip341.SIGHASH_DEFAULT) return error.InvalidTaprootSignature;
    var sig64: [64]u8 = undefined;
    @memcpy(&sig64, sig_bytes[0..64]);

    const msg = try bitcointx.bip341.sighash(allocator, ctx.tx, ctx.input_index, hash_type, ctx.spent_outputs);

    var xonly: [32]u8 = undefined;
    @memcpy(&xonly, program_x);
    const pk = bip340.XOnlyPublicKey.fromBytes(xonly) catch return error.InvalidTaprootSignature;
    const sig = bip340.Signature.fromBytes(sig64) catch return error.InvalidTaprootSignature;
    if (!bip340.verify(pk, &msg, sig)) return error.InvalidTaprootSignature;
}

/// BIP341/342 taproot **script-path** spend. `items` is the witness stack
/// with the annex already stripped (>=2 items): `items[last]` is the control
/// block, `items[last-1]` the leaf script, `items[0..last-1]` the initial
/// stack. `full_witness` (annex included) is used only to size the weight
/// budget.
fn verifyTaprootScriptPath(
    allocator: Allocator,
    program_x: []const u8,
    items: []const []const u8,
    annex: ?[]const u8,
    full_witness: []const []const u8,
    flags: ScriptFlags,
    ctx: TxContext,
) VerifyError!void {
    const control_block = items[items.len - 1];
    const script = items[items.len - 2];
    const initial_stack = items[0 .. items.len - 2];

    if (!tapscript.controlBlockValid(control_block)) return error.TaprootWrongControlSize;
    if (!tapscript.verifyCommitment(program_x, control_block, script)) return error.TaprootCommitmentMismatch;

    const leaf_version = control_block[0] & 0xfe;
    if (leaf_version != tapscript.TAPSCRIPT_LEAF_VERSION) {
        // Unknown leaf version: anyone-can-spend for future upgradeability,
        // unless policy discourages it (BIP341).
        if (flags.discourage_upgradable_taproot_version) return error.DiscourageUpgradableTaprootVersion;
        return;
    }

    // BIP342 OP_SUCCESSx pre-scan (before any execution or stack checks).
    if (try interpreter.scanOpSuccess(script)) {
        if (flags.discourage_op_success) return error.DiscourageOpSuccess;
        return;
    }

    // BIP342: the 520-byte-per-element limit and the 1000-element stack
    // limit are extended to the INITIAL stack.
    if (initial_stack.len > limits.max_stack_size) return error.CleanStack;
    for (initial_stack) |elem| {
        if (elem.len > limits.max_script_element_size) return error.PushSize;
    }

    var exec_data: tapscript.ExecData = .{
        .tapleaf_hash = tapscript.tapleafHash(leaf_version, script),
        .validation_weight = tapscript.validation_weight_offset + @as(i64, @intCast(witnessSerializedSize(full_witness))),
        .annex = annex,
    };

    var stack: std.ArrayList([]const u8) = .empty;
    for (initial_stack) |elem| try stack.append(allocator, elem);

    try interpreter.evalTapscript(allocator, &stack, script, ctx, flags, &exec_data);

    if (stack.items.len != 1) return error.CleanStack;
    if (!number.castToBool(stack.items[0])) return error.EvalFalse;
}

// ── BIP141 segwit v0 / taproot dispatch ─────────────────────────────────

/// `witness.len`/each item's size are bounded here defensively
/// (`error.PushSize`) beyond what a bit-exact consensus port would enforce
/// at this exact layer — true Bitcoin Core consensus bounds witness data
/// only indirectly, via the block *weight* limit (an orchestration-layer
/// concern outside a standalone script verifier). Without this, a caller
/// that hands `verifyScript` attacker-supplied witness data directly
/// (fuzzing, a mempool admission path with no separate weight check yet)
/// would have no bound on the memory this function walks.
fn verifyWitnessProgram(
    allocator: Allocator,
    wp: WitnessProgram,
    witness: []const []const u8,
    flags: ScriptFlags,
    ctx: TxContext,
    is_p2sh: bool,
) VerifyError!void {
    if (witness.len > limits.max_stack_items_in_witness) return error.PushSize;

    if (wp.version == 0) {
        var exec_stack: std.ArrayList([]const u8) = .empty;
        var script_pubkey: []const u8 = undefined;
        if (wp.program.len == 32) {
            // P2WSH: last witness item is the witness script; sha256 of it
            // must match the program; remaining items seed the stack.
            if (witness.len == 0) return error.WitnessProgramWitnessEmpty;
            const witness_script = witness[witness.len - 1];
            var got: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(witness_script, &got, .{});
            if (!std.mem.eql(u8, &got, wp.program)) return error.WitnessProgramMismatch;
            script_pubkey = witness_script; // size bound: interpreter.eval's own MAX_SCRIPT_SIZE check
            for (witness[0 .. witness.len - 1]) |item| {
                // Defensive DoS bound beyond what a bit-exact consensus port
                // would enforce here (module doc comment above).
                if (item.len > limits.max_script_element_size) return error.PushSize;
                try exec_stack.append(allocator, item);
            }
        } else if (wp.program.len == 20) {
            // P2WPKH: implicit `OP_DUP OP_HASH160 <program> OP_EQUALVERIFY
            // OP_CHECKSIG`; witness must be exactly [sig, pubkey].
            if (witness.len != 2) return error.WitnessProgramMismatch;
            if (witness[0].len > limits.max_script_element_size or witness[1].len > limits.max_script_element_size) return error.PushSize;
            var p2wpkh_script: [25]u8 = undefined;
            p2wpkh_script[0] = 0x76;
            p2wpkh_script[1] = 0xa9;
            p2wpkh_script[2] = 0x14;
            @memcpy(p2wpkh_script[3..23], wp.program);
            p2wpkh_script[23] = 0x88;
            p2wpkh_script[24] = 0xac;
            script_pubkey = try allocator.dupe(u8, &p2wpkh_script);
            try exec_stack.append(allocator, witness[0]);
            try exec_stack.append(allocator, witness[1]);
        } else {
            return error.WitnessProgramWrongLength;
        }
        try interpreter.eval(allocator, &exec_stack, script_pubkey, ctx, .witness_v0, flags);
        // Bitcoin Core enforces "exactly one element left" for segwit v0
        // unconditionally (not gated on the CLEANSTACK flag).
        if (exec_stack.items.len != 1) return error.CleanStack;
        if (!number.castToBool(exec_stack.items[0])) return error.EvalFalse;
        return;
    }

    if (wp.version == 1 and wp.program.len == 32 and !is_p2sh) {
        if (!flags.taproot) return; // taproot rules not enforced by caller: anyone-can-spend
        return verifyTaproot(allocator, wp.program, witness, flags, ctx);
    }

    // Any other version/length combination is future-reserved:
    // anyone-can-spend unless the caller opts to discourage it.
    if (flags.discourage_upgradable_witness_program) return error.DiscourageUpgradableWitnessProgram;
}

// ── top-level entry point ───────────────────────────────────────────────

/// Verifies that `script_sig` (+ `witness`, if any) satisfies
/// `script_pubkey` for the input described by `ctx`, under `flags`.
/// `witness` is the input's witness stack (`&.{}` if none). Returns
/// normally on success; a typed `VerifyError` on any failure — this
/// function is fail-closed: every path either returns success explicitly
/// or an error, never an ambiguous/partial state.
pub fn verifyScript(
    allocator: Allocator,
    script_sig: []const u8,
    script_pubkey: []const u8,
    witness: []const []const u8,
    flags: ScriptFlags,
    ctx: TxContext,
) VerifyError!void {
    if (script_sig.len > limits.max_script_size) return error.ScriptSize;
    if (script_pubkey.len > limits.max_script_size) return error.ScriptSize;

    // Mempool-policy-only check, unconditional and independent of P2SH
    // (Bitcoin Core: the very first thing `VerifyScript` does).
    if (flags.sigpushonly and !isPushOnly(script_sig)) return error.SigPushonly;

    var stack: std.ArrayList([]const u8) = .empty;
    try interpreter.eval(allocator, &stack, script_sig, ctx, .base, flags);

    // Snapshot the post-scriptSig stack for a possible P2SH redeem-script
    // resume (Bitcoin Core: `if (flags & SCRIPT_VERIFY_P2SH) stackCopy = stack;`
    // -- taken BEFORE scriptPubKey runs).
    var stack_copy: std.ArrayList([]const u8) = .empty;
    if (flags.p2sh) {
        try stack_copy.appendSlice(allocator, stack.items);
    }

    try interpreter.eval(allocator, &stack, script_pubkey, ctx, .base, flags);
    if (stack.items.len == 0) return error.EvalFalse;
    if (!number.castToBool(stack.items[stack.items.len - 1])) return error.EvalFalse;

    var had_witness = false;

    if (flags.witness) {
        if (parseWitnessProgram(script_pubkey)) |wp| {
            had_witness = true;
            if (script_sig.len != 0) return error.WitnessMalleated;
            try verifyWitnessProgram(allocator, wp, witness, flags, ctx, false);
            stack.shrinkRetainingCapacity(1);
        }
    }

    if (flags.p2sh and isP2sh(script_pubkey)) {
        if (!isPushOnly(script_sig)) return error.SigPushonly;
        stack = stack_copy;
        if (stack.items.len == 0) return error.EvalFalse;
        const redeem_script = stack.items[stack.items.len - 1];
        stack.shrinkRetainingCapacity(stack.items.len - 1);

        try interpreter.eval(allocator, &stack, redeem_script, ctx, .base, flags);
        if (stack.items.len == 0) return error.EvalFalse;
        if (!number.castToBool(stack.items[stack.items.len - 1])) return error.EvalFalse;

        if (flags.witness) {
            if (parseWitnessProgram(redeem_script)) |wp| {
                had_witness = true;
                if (!isExactPush(script_sig, redeem_script)) return error.WitnessMalleatedP2SH;
                try verifyWitnessProgram(allocator, wp, witness, flags, ctx, true);
                stack.shrinkRetainingCapacity(1);
            }
        }
    }

    if (flags.cleanstack) {
        if (stack.items.len != 1) return error.CleanStack;
    }

    if (flags.witness) {
        if (!had_witness and witness.len != 0) return error.WitnessUnexpected;
    }
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn dummyCtx() TxContext {
    return .{
        .tx = .{ .version = 1, .vin = @constCast(&[_]bitcointx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff }}), .vout = &.{}, .witness = &.{}, .locktime = 0, .has_witness = false },
        .input_index = 0,
        .spent_outputs = &[_]bitcointx.TxOut{.{ .value = 1000, .script_pubkey = &.{} }},
    };
}

test "bare EVAL_FALSE: OP_0 scriptPubKey leaves a falsy stack" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.EvalFalse, verifyScript(arena.allocator(), &.{}, &.{0x00}, &.{}, ScriptFlags.none, dummyCtx()));
}

test "trivial success: OP_1 scriptPubKey" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try verifyScript(arena.allocator(), &.{}, &.{0x51}, &.{}, ScriptFlags.none, dummyCtx());
}

test "P2SH: scriptSig must be push-only when SCRIPT_VERIFY_P2SH is set" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // redeemScript = OP_1 (0x51); its hash160 forms the P2SH scriptPubKey.
    const redeem = [_]u8{0x51};
    var h: [20]u8 = undefined;
    @import("ripemd160").hash160(&redeem, &h);
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &h);
    script_pubkey[22] = 0x87;

    // scriptSig = <push redeem-as-data> OP_NOP(non-push) -- not push-only.
    // (OP_NOP rather than e.g. OP_CHECKSIG: must not itself fail for an
    // unrelated reason -- InvalidStackOperation would mask the very
    // SigPushonly check this test targets.)
    const bad_script_sig = [_]u8{ 0x01, 0x51, 0x61 };
    try testing.expectError(error.SigPushonly, verifyScript(arena.allocator(), &bad_script_sig, &script_pubkey, &.{}, .{ .p2sh = true }, dummyCtx()));

    // scriptSig = <push redeem> only -- push-only, redeem evaluates to true.
    const good_script_sig = [_]u8{ 0x01, 0x51 };
    try verifyScript(arena.allocator(), &good_script_sig, &script_pubkey, &.{}, .{ .p2sh = true }, dummyCtx());
}

test "witness program: scriptSig must be empty" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xaa} ** 20; // P2WPKH program
    const nonempty_sig = [_]u8{0x51};
    try testing.expectError(error.WitnessMalleated, verifyScript(arena.allocator(), &nonempty_sig, &script_pubkey, &.{ "sig", "pubkey" }, .{ .witness = true }, dummyCtx()));
}

test "taproot script-path: a malformed control block fails closed (wrong control size)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const script_pubkey = [_]u8{ 0x51, 0x20 } ++ [_]u8{0xbb} ** 32; // P2TR program
    // 13-byte control block is not 33 + 32m -> TaprootWrongControlSize.
    const w = [_][]const u8{ "leaf-script", "control-block" };
    try testing.expectError(error.TaprootWrongControlSize, verifyScript(arena.allocator(), &.{}, &script_pubkey, &w, .{ .witness = true, .taproot = true }, dummyCtx()));
}

test "DoS: oversized scriptPubKey rejected before any execution" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var big: [limits.max_script_size + 1]u8 = undefined;
    @memset(&big, 0x61);
    try testing.expectError(error.ScriptSize, verifyScript(arena.allocator(), &.{}, &big, &.{}, ScriptFlags.none, dummyCtx()));
}

// ── fuzz: verifyScript never panics on arbitrary attacker-controlled ─────
// script/witness bytes ────────────────────────────────────────────────────
//
// `verifyScript` is THE consensus-critical boundary this whole module
// exists for: `script_sig` comes from a peer's transaction, `script_pubkey`
// from whatever previous output is being spent, `witness` from the same
// transaction's witness stack -- all attacker-controlled the moment this
// runs inside a node validating an incoming tx/block. It drives the
// interpreter's full opcode dispatch (arithmetic, stack manipulation,
// hashing, CHECKSIG/CHECKMULTISIG, the P2SH/segwit/taproot sub-paths) --
// exactly where a real script interpreter's classic bug classes live
// (stack-depth/height confusion, `CScriptNum` decode edge cases, push-size
// bookkeeping). Bytes are biased toward *some* structure: most opcode
// bytes are drawn from the actual defined range (`0x00..0xba`, covering
// every real opcode including the push-data forms) rather than fully
// uniform, so the interpreter's dispatch table and its push-length
// bookkeeping actually get exercised instead of dying on the first
// undefined-opcode byte; flags and the witness stack are randomized too,
// so the P2SH/segwit-v0/taproot sub-paths of `verifyScript` above get a
// turn as well.
test "fuzz: verifyScript never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzVerifyScript, .{});
}

fn fuzzScriptBytes(smith: *std.testing.Smith, buf: []u8) []u8 {
    for (buf) |*b| {
        // Real opcodes (incl. push-data forms) 5-in-6 of the time; fully
        // random (incl. bytes past 0xba) the rest.
        b.* = if (smith.valueRangeAtMost(u8, 0, 5) != 0) smith.valueRangeAtMost(u8, 0, 0xba) else smith.value(u8);
    }
    const len: usize = smith.valueRangeAtMost(u8, 0, @intCast(buf.len));
    return buf[0..len];
}

fn fuzzVerifyScript(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sig_buf: [64]u8 = undefined;
    const script_sig = fuzzScriptBytes(smith, &sig_buf);
    var pubkey_buf: [96]u8 = undefined;
    const script_pubkey = fuzzScriptBytes(smith, &pubkey_buf);

    const n_witness = smith.valueRangeAtMost(u8, 0, 4);
    var witness_bufs: [4][80]u8 = undefined;
    var witness_items: [4][]const u8 = undefined;
    var i: u8 = 0;
    while (i < n_witness) : (i += 1) {
        smith.bytes(&witness_bufs[i]);
        const wlen: usize = smith.valueRangeAtMost(u8, 0, witness_bufs[i].len);
        witness_items[i] = witness_bufs[i][0..wlen];
    }

    const sf: ScriptFlags = .{
        .p2sh = smith.value(bool),
        .dersig = smith.value(bool),
        .low_s = smith.value(bool),
        .strictenc = smith.value(bool),
        .cleanstack = smith.value(bool),
        .witness = smith.value(bool),
        .minimaldata = smith.value(bool),
        .taproot = smith.value(bool),
    };

    verifyScript(a, script_sig, script_pubkey, witness_items[0..n_witness], sf, dummyCtx()) catch return;
}
