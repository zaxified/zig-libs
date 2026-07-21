// SPDX-License-Identifier: MIT
//! DoS-bound teeth at the `verifyScript` level (complementing
//! `interpreter.zig`'s own script-size/op-count/stack-size/push-size
//! tests): every check here proves `verifyScript` fails closed with a
//! typed error — never an unbounded allocation or a panic — on hostile
//! witness-shaped input, which is attacker-controlled the same way
//! scriptSig/scriptPubKey bytes are (module doc comments on
//! `interpreter.zig` and `verify.zig`'s `verifyWitnessProgram`).

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");
const limits = @import("limits.zig");

fn dummyCtx() txctx.TxContext {
    return .{
        .tx = .{ .version = 1, .vin = @constCast(&[_]bitcointx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff }}), .vout = &.{}, .witness = &.{}, .locktime = 0, .has_witness = false },
        .input_index = 0,
        .spent_outputs = &[_]bitcointx.TxOut{.{ .value = 1000, .script_pubkey = &.{} }},
    };
}

test "DoS: witness item count over the consensus-adjacent bound is rejected, no OOM" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const script_pubkey = [_]u8{ 0x00, 0x20 } ++ [_]u8{0xcc} ** 32; // P2WSH program
    var items: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < limits.max_stack_items_in_witness + 5) : (i += 1) try items.append(a, "x");

    try testing.expectError(error.PushSize, verify.verifyScript(a, &.{}, &script_pubkey, items.items, .{ .witness = true }, dummyCtx()));
}

test "DoS: an oversized non-final witness item (P2WSH stack seed) is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const witness_script = [_]u8{0x51}; // OP_1: trivially true, so a size failure -- not EVAL_FALSE -- must be what's observed
    var got: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&witness_script, &got, .{});
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x20;
    @memcpy(script_pubkey[2..34], &got);

    var big_item: [limits.max_script_element_size + 1]u8 = undefined;
    @memset(&big_item, 0xab);
    const witness = [_][]const u8{ &big_item, &witness_script };

    try testing.expectError(error.PushSize, verify.verifyScript(a, &.{}, &script_pubkey, &witness, .{ .witness = true }, dummyCtx()));
}

test "DoS: P2WPKH witness item oversized is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xaa} ** 20;
    var big_sig: [limits.max_script_element_size + 1]u8 = undefined;
    @memset(&big_sig, 0x01);
    const pubkey = [_]u8{0x02} ** 33;
    const witness = [_][]const u8{ &big_sig, &pubkey };
    try testing.expectError(error.PushSize, verify.verifyScript(a, &.{}, &script_pubkey, &witness, .{ .witness = true }, dummyCtx()));
}

test "DoS: a P2SH redeem script is bounded (pushed as data, so <=520 bytes) even when it then runs as a <=10000-byte script" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A redeem script right at the max element size, consisting of
    // MAX_SCRIPT_ELEMENT_SIZE NOPs followed by nothing -- exercises the
    // P2SH resume path without hitting any other limit, proving the
    // "redeem script is itself a bounded push" invariant holds structurally.
    // OP_1 repeated (not OP_NOP): push opcodes (<= OP_16) don't count
    // against MAX_OPS_PER_SCRIPT the way non-push opcodes do, so this
    // stays under that separate limit while still being exactly
    // MAX_SCRIPT_ELEMENT_SIZE bytes and evaluating to a truthy final stack.
    var redeem: [limits.max_script_element_size]u8 = undefined;
    @memset(&redeem, 0x51); // OP_1

    var h: [20]u8 = undefined;
    @import("ripemd160").hash160(&redeem, &h);
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &h);
    script_pubkey[22] = 0x87;

    // scriptSig = PUSHDATA2 <520 bytes of redeem>
    var script_sig: std.ArrayList(u8) = .empty;
    try script_sig.append(a, 0x4d);
    var lb: [2]u8 = undefined;
    std.mem.writeInt(u16, &lb, @intCast(redeem.len), .little);
    try script_sig.appendSlice(a, &lb);
    try script_sig.appendSlice(a, &redeem);

    try verify.verifyScript(a, script_sig.items, &script_pubkey, &.{}, .{ .p2sh = true }, dummyCtx());
}

test "DoS: oversized scriptSig is rejected before any execution" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var big: [limits.max_script_size + 1]u8 = undefined;
    @memset(&big, 0x61);
    try testing.expectError(error.ScriptSize, verify.verifyScript(a, &big, &.{0x51}, &.{}, flags_mod.ScriptFlags.none, dummyCtx()));
}
