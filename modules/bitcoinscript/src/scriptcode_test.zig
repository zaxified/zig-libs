// SPDX-License-Identifier: MIT
//! What a CHECKSIG does when the scriptCode it must hash does not decode.
//!
//! Bitcoin Core builds the scriptCode inside `EvalChecksigPreTapscript` and
//! serializes it with `CTransactionSignatureSerializer::SerializeScriptCode`
//! (`script/interpreter.cpp`, v29.0):
//!
//! ```cpp
//! while (scriptCode.GetOp(it, opcode)) { ... }
//! ```
//!
//! `GetOp` returning false ENDS that walk — it is not an error and it does
//! not abort the CHECKSIG. Core therefore goes on to
//! `CheckSignatureEncoding` / `CheckPubKeyEncoding` / `CheckECDSASignature`
//! and reports whatever *those* say. An implementation that instead treats an
//! undecodable scriptCode as a hard script failure answers a different error
//! class than Core for the same bytes, at the one call site where the two
//! engines are supposed to be indistinguishable.
//!
//! Reachability, stated exactly, because it bounds how bad this is:
//! `FindAndDelete` only ever deletes whole instructions here (its pattern is
//! `CScript() << vchSig`, a canonical push, and the byte it matches at a walk
//! position is that push's own length prefix — so the match length always
//! equals the instruction length and downstream boundaries never move). The
//! undecodable scriptCode is therefore always an undecodable *script*, which
//! `evalCore` will itself reject on reaching those bytes. So the valid/invalid
//! verdict cannot diverge — but the error class can, and does, as the vector
//! below shows.
//!
//! No upstream vector covers this. Counted, not assumed, against
//! `script_tests.json` v29.0: 1207 data rows, exactly 3 scripts whose `GetOp`
//! walk fails (the "PUSHDATA1/2/4 with not enough bytes" rows), and 0 of them
//! reaches a CHECKSIG-family opcode before failing, so none of them ever
//! constructs a scriptCode. `tx_valid.json`/`tx_invalid.json`: 0 prevout
//! scriptPubKeys with a failing walk. The tail bytes used below are those
//! upstream rows' bytes verbatim; the surrounding script is ours, because
//! upstream has none.

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");

fn dummyCtx() txctx.TxContext {
    return .{
        .tx = .{
            .version = 1,
            .vin = @constCast(&[_]bitcointx.TxIn{.{
                .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 },
                .script_sig = &.{},
                .sequence = 0xffffffff,
            }}),
            .vout = &.{},
            .witness = &.{},
            .locktime = 0,
            .has_witness = false,
        },
        .input_index = 0,
        .spent_outputs = &[_]bitcointx.TxOut{.{ .value = 1000, .script_pubkey = &.{} }},
    };
}

test "CHECKSIG over an undecodable scriptCode reports Core's error class, not BAD_OPCODE" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // scriptSig: a 9-byte non-DER "signature", then a 33-byte "pubkey".
    const script_sig = [_]u8{0x09} ++ [_]u8{0xaa} ** 9 ++ [_]u8{0x21} ++ [_]u8{0x02} ++ [_]u8{0xbb} ** 32;
    // scriptPubKey: OP_CHECKSIG followed by script_tests.json's "PUSHDATA2
    // with not enough bytes" bytes. The CHECKSIG executes first, so it must
    // build a scriptCode out of an undecodable byte string.
    const script_pubkey = [_]u8{ 0xac, 0x4d, 0x02, 0x00, 0xff };

    // Core: FindAndDelete finds nothing, the SerializeScriptCode walk simply
    // stops at the 0x4d, and CheckSignatureEncoding then rejects the
    // signature under DERSIG => SCRIPT_ERR_SIG_DER.
    try testing.expectError(
        error.SigDer,
        verify.verifyScript(a, &script_sig, &script_pubkey, &.{}, .{ .dersig = true }, dummyCtx()),
    );
}

test "the same script without a CHECKSIG still dies on the undecodable tail" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // The other half of the contract: not erroring inside the scriptCode
    // builder must not make the undecodable bytes themselves acceptable.
    // `evalCore` walks the whole script and still rejects them, which is what
    // keeps the valid/invalid verdict identical to Core's.
    const script_pubkey = [_]u8{ 0x51, 0x4d, 0x02, 0x00, 0xff }; // OP_1, then the bad push
    try testing.expectError(
        error.BadOpcode,
        verify.verifyScript(a, &.{}, &script_pubkey, &.{}, .{}, dummyCtx()),
    );
}
