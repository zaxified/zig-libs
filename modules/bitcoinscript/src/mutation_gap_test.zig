// SPDX-License-Identifier: MIT
//! Tests added by the 2026-11-17 whole-module mutation audit. Each one closes a
//! gap the mutant run exposed: an opcode semantic or stack-depth boundary the
//! pinned `script_tests.json` subset never reaches, a policy flag with no
//! test that turns it on, a `verifyScript` dispatch boundary, the tapscript
//! signature-size rules, and Core's LAX DER acceptance (a script run without
//! `dersig` must accept what `ecdsa_signature_parse_der_lax` accepts).

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const bitcointx = @import("bitcointx");
const bip340 = @import("bip340");
const ripemd160 = @import("ripemd160");
const asmparser = @import("asmparser.zig");
const interpreter = @import("interpreter.zig");
const verify = @import("verify.zig");
const sigcheck = @import("sigcheck.zig");
const tapscript = @import("tapscript.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");
const tt = @import("tapscript_test.zig");

const ScriptFlags = flags_mod.ScriptFlags;
const Stack = std.ArrayList([]const u8);
const EcdsaSecp256k1Sha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn dummyCtx(a: Allocator) !txctx.TxContext {
    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = @as([32]u8, @splat(0x77)), .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 900, .script_pubkey = &.{} };
    const spent = try a.alloc(bitcointx.TxOut, 1);
    spent[0] = .{ .value = 1000, .script_pubkey = &.{} };
    return .{
        .tx = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = true },
        .input_index = 0,
        .spent_outputs = spent,
    };
}

// ── opcode semantics through `interpreter.eval` ──────────────────────────

fn evalAsm(a: Allocator, text: []const u8, stack: *Stack) !void {
    const script = try asmparser.assemble(a, text);
    try interpreter.eval(a, stack, script, try dummyCtx(a), .base, ScriptFlags.none);
}

fn expectStack(text: []const u8, want: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var stack: Stack = .empty;
    evalAsm(arena.allocator(), text, &stack) catch |e| {
        std.debug.print("\nscript `{s}` failed with {s}\n", .{ text, @errorName(e) });
        return e;
    };
    try testing.expectEqual(want.len, stack.items.len);
    for (want, stack.items) |w, g| try testing.expectEqualSlices(u8, w, g);
}

fn expectEvalError(text: []const u8, want: anyerror) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var stack: Stack = .empty;
    if (evalAsm(arena.allocator(), text, &stack)) |_| {
        std.debug.print("\nscript `{s}` unexpectedly succeeded\n", .{text});
        return error.TestUnexpectedResult;
    } else |e| try testing.expectEqual(want, e);
}

const Row = struct { []const u8, []const []const u8 };

test "opcode semantics: stack manipulation (exact result stacks)" {
    const rows = [_]Row{
        .{ "1 2 3 2DROP", &.{"\x01"} },
        .{ "1 2 2DUP", &.{ "\x01", "\x02", "\x01", "\x02" } },
        .{ "1 2 3 3DUP", &.{ "\x01", "\x02", "\x03", "\x01", "\x02", "\x03" } },
        .{ "1 2 3 4 2OVER", &.{ "\x01", "\x02", "\x03", "\x04", "\x01", "\x02" } },
        .{ "1 2 3 4 5 6 2ROT", &.{ "\x03", "\x04", "\x05", "\x06", "\x01", "\x02" } },
        .{ "1 2 3 4 2SWAP", &.{ "\x03", "\x04", "\x01", "\x02" } },
        .{ "1 IFDUP", &.{ "\x01", "\x01" } },
        .{ "0 IFDUP", &.{""} },
        .{ "1 2 3 DEPTH", &.{ "\x01", "\x02", "\x03", "\x03" } },
        .{ "1 2 NIP", &.{"\x02"} },
        .{ "1 2 3 NIP", &.{ "\x01", "\x03" } },
        .{ "1 2 OVER", &.{ "\x01", "\x02", "\x01" } },
        .{ "1 2 3 DUP", &.{ "\x01", "\x02", "\x03", "\x03" } },
        .{ "1 2 3 2 PICK", &.{ "\x01", "\x02", "\x03", "\x01" } },
        .{ "1 2 3 0 PICK", &.{ "\x01", "\x02", "\x03", "\x03" } },
        .{ "1 2 3 2 ROLL", &.{ "\x02", "\x03", "\x01" } },
        .{ "1 2 3 0 ROLL", &.{ "\x01", "\x02", "\x03" } },
        .{ "1 2 3 ROT", &.{ "\x02", "\x03", "\x01" } },
        .{ "1 2 SWAP", &.{ "\x02", "\x01" } },
        .{ "1 2 TUCK", &.{ "\x02", "\x01", "\x02" } },
        .{ "1 2 3 TUCK", &.{ "\x01", "\x03", "\x02", "\x03" } },
        .{ "'abc' SIZE", &.{ "abc", "\x03" } },
        .{ "0 SIZE", &.{ "", "" } },
        .{ "1 TOALTSTACK FROMALTSTACK", &.{"\x01"} },
        .{ "1 2 TOALTSTACK 3 FROMALTSTACK", &.{ "\x01", "\x03", "\x02" } },
        .{ "1 VERIFY", &.{} },
        .{ "1 1 EQUALVERIFY", &.{} },
        .{ "1 1 NUMEQUALVERIFY", &.{} },
        .{ "1 1 EQUAL", &.{"\x01"} },
        .{ "1 2 EQUAL", &.{""} },
        .{ "'ab' 'a' EQUAL", &.{""} },
    };
    for (rows) |r| try expectStack(r[0], r[1]);
}

test "opcode semantics: arithmetic and comparison (exact results)" {
    const rows = [_]Row{
        .{ "5 NEGATE", &.{"\x85"} },
        .{ "-5 NEGATE", &.{"\x05"} },
        .{ "-5 ABS", &.{"\x05"} },
        .{ "5 ABS", &.{"\x05"} },
        .{ "0 ABS", &.{""} },
        .{ "0 0NOTEQUAL", &.{""} },
        .{ "3 0NOTEQUAL", &.{"\x01"} },
        .{ "0 NOT", &.{"\x01"} },
        .{ "2 NOT", &.{""} },
        .{ "5 1ADD", &.{"\x06"} },
        .{ "5 1SUB", &.{"\x04"} },
        .{ "7 3 SUB", &.{"\x04"} },
        .{ "3 7 SUB", &.{"\x84"} },
        .{ "3 4 ADD", &.{"\x07"} },
        .{ "1 0 BOOLOR", &.{"\x01"} },
        .{ "0 1 BOOLOR", &.{"\x01"} },
        .{ "0 0 BOOLOR", &.{""} },
        .{ "1 0 BOOLAND", &.{""} },
        .{ "1 2 BOOLAND", &.{"\x01"} },
        .{ "3 3 NUMEQUAL", &.{"\x01"} },
        .{ "3 4 NUMEQUAL", &.{""} },
        .{ "3 4 NUMNOTEQUAL", &.{"\x01"} },
        .{ "3 3 NUMNOTEQUAL", &.{""} },
        .{ "3 3 LESSTHAN", &.{""} },
        .{ "2 3 LESSTHAN", &.{"\x01"} },
        .{ "3 3 GREATERTHAN", &.{""} },
        .{ "4 3 GREATERTHAN", &.{"\x01"} },
        .{ "3 3 LESSTHANOREQUAL", &.{"\x01"} },
        .{ "4 3 LESSTHANOREQUAL", &.{""} },
        .{ "3 3 GREATERTHANOREQUAL", &.{"\x01"} },
        .{ "2 3 GREATERTHANOREQUAL", &.{""} },
        .{ "1 2 MIN", &.{"\x01"} },
        .{ "2 1 MIN", &.{"\x01"} },
        .{ "1 2 MAX", &.{"\x02"} },
        .{ "2 1 MAX", &.{"\x02"} },
        .{ "3 3 5 WITHIN", &.{"\x01"} },
        .{ "5 3 5 WITHIN", &.{""} },
        .{ "2 3 5 WITHIN", &.{""} },
        .{ "4 3 5 WITHIN", &.{"\x01"} },
    };
    for (rows) |r| try expectStack(r[0], r[1]);
}

test "opcode errors: every stack-depth guard fires with exactly one element too few and not with exactly enough" {
    const Op = struct { name: []const u8, k: usize };
    const ops = [_]Op{
        .{ .name = "VERIFY", .k = 1 },         .{ .name = "TOALTSTACK", .k = 1 },      .{ .name = "IFDUP", .k = 1 },
        .{ .name = "DROP", .k = 1 },           .{ .name = "DUP", .k = 1 },             .{ .name = "SIZE", .k = 1 },
        .{ .name = "RIPEMD160", .k = 1 },      .{ .name = "SHA1", .k = 1 },            .{ .name = "SHA256", .k = 1 },
        .{ .name = "HASH160", .k = 1 },        .{ .name = "HASH256", .k = 1 },         .{ .name = "1ADD", .k = 1 },
        .{ .name = "1SUB", .k = 1 },           .{ .name = "NEGATE", .k = 1 },          .{ .name = "ABS", .k = 1 },
        .{ .name = "NOT", .k = 1 },            .{ .name = "0NOTEQUAL", .k = 1 },       .{ .name = "2DROP", .k = 2 },
        .{ .name = "2DUP", .k = 2 },           .{ .name = "NIP", .k = 2 },             .{ .name = "OVER", .k = 2 },
        .{ .name = "SWAP", .k = 2 },           .{ .name = "TUCK", .k = 2 },            .{ .name = "EQUAL", .k = 2 },
        .{ .name = "EQUALVERIFY", .k = 2 },    .{ .name = "ADD", .k = 2 },             .{ .name = "SUB", .k = 2 },
        .{ .name = "BOOLAND", .k = 2 },        .{ .name = "BOOLOR", .k = 2 },          .{ .name = "NUMEQUAL", .k = 2 },
        .{ .name = "NUMEQUALVERIFY", .k = 2 }, .{ .name = "NUMNOTEQUAL", .k = 2 },     .{ .name = "LESSTHAN", .k = 2 },
        .{ .name = "GREATERTHAN", .k = 2 },    .{ .name = "LESSTHANOREQUAL", .k = 2 }, .{ .name = "GREATERTHANOREQUAL", .k = 2 },
        .{ .name = "MIN", .k = 2 },            .{ .name = "MAX", .k = 2 },             .{ .name = "CHECKSIG", .k = 2 },
        .{ .name = "3DUP", .k = 3 },           .{ .name = "ROT", .k = 3 },             .{ .name = "WITHIN", .k = 3 },
        .{ .name = "2OVER", .k = 4 },          .{ .name = "2SWAP", .k = 4 },           .{ .name = "2ROT", .k = 6 },
    };
    var buf: [128]u8 = undefined;
    for (ops) |op| {
        // k-1 operands: refused
        var w = std.Io.Writer.fixed(&buf);
        for (0..op.k - 1) |_| try w.writeAll("1 ");
        try w.writeAll(op.name);
        try expectEvalError(w.buffered(), error.InvalidStackOperation);
        // k operands: accepted
        w = std.Io.Writer.fixed(&buf);
        for (0..op.k) |_| try w.writeAll("1 ");
        try w.writeAll(op.name);
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var stack: Stack = .empty;
        evalAsm(arena.allocator(), w.buffered(), &stack) catch |e| {
            std.debug.print("\n`{s}` with {d} operands failed with {s}\n", .{ op.name, op.k, @errorName(e) });
            return e;
        };
    }
    try expectEvalError("FROMALTSTACK", error.InvalidAltstackOperation);
    try expectEvalError("1 TOALTSTACK FROMALTSTACK FROMALTSTACK", error.InvalidAltstackOperation);
    try expectEvalError("DROP", error.InvalidStackOperation);
    try expectEvalError("1 2 -1 PICK", error.InvalidStackOperation);
    try expectEvalError("1 2 -1 ROLL", error.InvalidStackOperation);
    try expectEvalError("1 2 2 PICK", error.InvalidStackOperation);
    try expectEvalError("0 PICK", error.InvalidStackOperation);
    try expectEvalError("0 VERIFY", error.Verify);
    try expectEvalError("1 2 EQUALVERIFY", error.Equalverify);
    try expectEvalError("1 2 NUMEQUALVERIFY", error.Numequalverify);
    try expectEvalError("1 2 3 CHECKSIGADD", error.BadOpcode);
}

test "hash opcodes push the full digest of the whole operand" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const data = "helloopcode";
    var sha1: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(data, &sha1, .{});
    var sha256: [32]u8 = undefined;
    Sha256.hash(data, &sha256, .{});
    var rmd: [20]u8 = undefined;
    ripemd160.Ripemd160.hash(data, &rmd, .{});
    var h160: [20]u8 = undefined;
    ripemd160.Ripemd160.hash(&sha256, &h160, .{});
    var h256: [32]u8 = undefined;
    Sha256.hash(&sha256, &h256, .{});
    const cases = [_]struct { op: []const u8, want: []const u8 }{
        .{ .op = "SHA1", .want = &sha1 },
        .{ .op = "SHA256", .want = &sha256 },
        .{ .op = "RIPEMD160", .want = &rmd },
        .{ .op = "HASH160", .want = &h160 },
        .{ .op = "HASH256", .want = &h256 },
    };
    for (cases) |c| {
        var stack: Stack = .empty;
        const text = try std.fmt.allocPrint(a, "'{s}' {s}", .{ data, c.op });
        try evalAsm(a, text, &stack);
        try testing.expectEqual(@as(usize, 1), stack.items.len);
        try testing.expectEqualSlices(u8, c.want, stack.items[0]);
    }
}

test "CHECKMULTISIG: a one-byte signature counts for NULLFAIL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // dummy, <1-byte sig>, m=1, <33-byte key>, n=1, CHECKMULTISIG
    const script = [_]u8{ 0x00, 0x01, 0x01, 0x51, 0x21 } ++ @as([33]u8, @splat(0x02)) ++ [_]u8{ 0x51, 0xae };
    var stack: Stack = .empty;
    try testing.expectError(error.SigNullfail, interpreter.eval(a, &stack, &script, try dummyCtx(a), .base, .{ .nullfail = true }));
    stack = .empty;
    try interpreter.eval(a, &stack, &script, try dummyCtx(a), .base, ScriptFlags.none);
}

// ── verifyScript dispatch boundaries ─────────────────────────────────────

fn sha256Of(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

fn p2shSpk(redeem: []const u8) [23]u8 {
    var h: [20]u8 = undefined;
    ripemd160.hash160(redeem, &h);
    return [_]u8{ 0xa9, 0x14 } ++ h ++ [_]u8{0x87};
}

fn vs(a: Allocator, script_sig: []const u8, spk: []const u8, witness: []const []const u8, flags: ScriptFlags) verify.VerifyError!void {
    const ctx = dummyCtx(a) catch return error.PushSize;
    return verify.verifyScript(a, script_sig, spk, witness, flags, ctx);
}

test "P2SH recognition needs all of HASH160, the 20-byte push and EQUAL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d: [20]u8 = @splat(0x6a); // OP_RETURN bytes: executing them as a redeem script would fail
    // each of these is 23 bytes with two of the three P2SH markers, and evaluates true as an ordinary script
    const no_hash160 = [_]u8{ 0x61, 0x14 } ++ d ++ [_]u8{0x87};
    try vs(a, &([_]u8{0x14} ++ d), &no_hash160, &.{}, .{ .p2sh = true });
    const no_push20 = [_]u8{ 0xa9, 0x75, 0x51, 0x51 } ++ @as([18]u8, @splat(0x61)) ++ [_]u8{0x87};
    try testing.expectEqual(@as(usize, 23), no_push20.len);
    try vs(a, &.{ 0x01, 0x6a }, &no_push20, &.{}, .{ .p2sh = true });
    const no_equal = [_]u8{ 0xa9, 0x14 } ++ d ++ [_]u8{0x61};
    try vs(a, &.{ 0x01, 0x6a }, &no_equal, &.{}, .{ .p2sh = true });
    // and the real thing does execute the redeem script
    const spk = p2shSpk(&.{0x6a});
    try testing.expectError(error.OpReturn, vs(a, &.{ 0x01, 0x6a }, &spk, &.{}, .{ .p2sh = true }));
    // a redeem script that evaluates false
    const spk0 = p2shSpk(&.{0x00});
    try testing.expectError(error.EvalFalse, vs(a, &.{ 0x01, 0x00 }, &spk0, &.{}, .{ .p2sh = true }));
}

test "P2SH-wrapped P2WSH: the scriptSig must be exactly one push; CLEANSTACK holds after the witness program" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const witness_script = [_]u8{0x51};
    const wsh = sha256Of(&witness_script);
    const redeem = [_]u8{ 0x00, 0x20 } ++ wsh;
    const spk = p2shSpk(&redeem);
    const one_push = [_]u8{0x22} ++ redeem;
    const two_pushes = one_push ++ one_push;
    const witness = [_][]const u8{&witness_script};
    try vs(a, &one_push, &spk, &witness, .{ .p2sh = true, .witness = true });
    try vs(a, &one_push, &spk, &witness, .{ .p2sh = true, .witness = true, .cleanstack = true });
    try testing.expectError(error.WitnessMalleatedP2SH, vs(a, &two_pushes, &spk, &witness, .{ .p2sh = true, .witness = true }));
    // a witness that does not belong to a program is refused
    try testing.expectError(error.WitnessUnexpected, vs(a, &.{}, &.{0x51}, &witness, .{ .witness = true }));
}

test "witness program shapes: lengths 2..40 are programs, anything else is an ordinary script" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const discourage: ScriptFlags = .{ .witness = true, .discourage_upgradable_witness_program = true };
    const p40 = [_]u8{ 0x51, 0x28 } ++ @as([40]u8, @splat(0xaa));
    try testing.expectError(error.DiscourageUpgradableWitnessProgram, vs(a, &.{}, &p40, &.{}, discourage));
    try testing.expectError(error.DiscourageUpgradableWitnessProgram, vs(a, &.{}, &.{ 0x51, 0x02, 0xaa, 0xbb }, &.{}, discourage));
    // one trailing byte: not a program, so nothing is discouraged
    try vs(a, &.{}, &.{ 0x51, 0x02, 0xaa, 0xbb, 0x61 }, &.{}, discourage);
    // OP_RESERVED is not a witness version
    try testing.expectError(error.BadOpcode, vs(a, &.{}, &.{ 0x50, 0x02, 0xaa, 0xbb }, &.{}, discourage));
    // version 0 with a program that is neither 20 nor 32 bytes
    const p33 = [_]u8{ 0x00, 0x21 } ++ @as([33]u8, @splat(0xaa));
    try testing.expectError(error.WitnessProgramWrongLength, vs(a, &.{}, &p33, &.{"x"}, .{ .witness = true }));
    const p19 = [_]u8{ 0x00, 0x13 } ++ @as([19]u8, @splat(0xaa));
    try testing.expectError(error.WitnessProgramWrongLength, vs(a, &.{}, &p19, &.{"x"}, .{ .witness = true }));
}

test "taproot dispatch: only a bare v1 32-byte program is taproot, and only when the flag is on" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p2 = [_]u8{ 0x52, 0x20 } ++ @as([32]u8, @splat(0xaa));
    try vs(a, &.{}, &p2, &.{"junk"}, .{ .witness = true, .taproot = true });
    const p1 = [_]u8{ 0x51, 0x20 } ++ @as([32]u8, @splat(0xaa));
    try vs(a, &.{}, &p1, &.{"junk"}, .{ .witness = true }); // flag off: anyone-can-spend
    try testing.expectError(error.InvalidTaprootSignature, vs(a, &.{}, &p1, &.{"junk"}, .{ .witness = true, .taproot = true }));
    // wrapped in P2SH it is a reserved program, never taproot
    const redeem = p1;
    const spk = p2shSpk(&redeem);
    const sig = [_]u8{0x22} ++ redeem;
    try vs(a, &sig, &spk, &.{"junk"}, .{ .p2sh = true, .witness = true, .taproot = true });
}

test "witness v0 limits: item counts and sizes sit exactly on their bounds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const flags: ScriptFlags = .{ .witness = true };
    // P2WSH: 999 seed items + the script = 1000 witness items passes the count check
    const s1 = [_]u8{0x51};
    const spk1 = [_]u8{ 0x00, 0x20 } ++ sha256Of(&s1);
    var many: [1000][]const u8 = undefined;
    for (many[0..999]) |*m| m.* = "\x01";
    many[999] = &s1;
    try testing.expectError(error.CleanStack, vs(a, &.{}, &spk1, &many, flags));
    // an element of exactly 520 bytes is fine, 521 is not
    const s2 = [_]u8{ 0x75, 0x51 };
    const spk2 = [_]u8{ 0x00, 0x20 } ++ sha256Of(&s2);
    const e520 = try a.alloc(u8, 520);
    @memset(e520, 0xee);
    try vs(a, &.{}, &spk2, &.{ e520, &s2 }, flags);
    const e521 = try a.alloc(u8, 521);
    @memset(e521, 0xee);
    try testing.expectError(error.PushSize, vs(a, &.{}, &spk2, &.{ e521, &s2 }, flags));
    // P2WSH needs exactly one element left
    const s3 = [_]u8{ 0x51, 0x51 };
    const spk3 = [_]u8{ 0x00, 0x20 } ++ sha256Of(&s3);
    try testing.expectError(error.CleanStack, vs(a, &.{}, &spk3, &.{&s3}, flags));
    // P2WPKH: a 520-byte signature passes the size check (and then fails on the key hash), a 521-byte key does not
    const spkk = [_]u8{ 0x00, 0x14 } ++ @as([20]u8, @splat(0xaa));
    try testing.expectError(error.Equalverify, vs(a, &.{}, &spkk, &.{ e520, &(@as([33]u8, @splat(0x02))) }, flags));
    try testing.expectError(error.PushSize, vs(a, &.{}, &spkk, &.{ "x", e521 }, flags));
}

test "script size bounds at verifyScript: exactly 10000 passes, and the size check runs before anything executes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var big: std.ArrayList(u8) = .empty;
    for (0..19) |_| {
        try big.appendSlice(a, &.{ 0x4d, 0x08, 0x02 });
        try big.appendNTimes(a, 0xaa, 520);
    }
    try big.append(a, 62);
    try big.appendNTimes(a, 0xaa, 62);
    try testing.expectEqual(@as(usize, 10000), big.items.len);
    try vs(a, big.items, &.{0x51}, &.{}, .{});
    try vs(a, &.{}, big.items, &.{}, .{});
    var over = try big.clone(a);
    try over.append(a, 0x61);
    // the failing scriptSig / non-push-only scriptSig must not get a say first
    try testing.expectError(error.ScriptSize, vs(a, &.{0x6a}, over.items, &.{}, .{}));
    try testing.expectError(error.ScriptSize, vs(a, over.items, &.{0x51}, &.{}, .{ .sigpushonly = true }));
}

test "SIGPUSHONLY: OP_16 is a push, an undecodable scriptSig is not" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try vs(a, &.{0x60}, &.{0x51}, &.{}, .{ .sigpushonly = true });
    try testing.expectError(error.SigPushonly, vs(a, &.{0x61}, &.{0x51}, &.{}, .{ .sigpushonly = true }));
    try testing.expectError(error.SigPushonly, vs(a, &.{0x4c}, &.{0x51}, &.{}, .{ .sigpushonly = true }));
}

// ── taproot script path / key path ───────────────────────────────────────

const taproot_flags: ScriptFlags = .{ .witness = true, .taproot = true };

fn leafSetup(a: Allocator, script: []const u8) !tt.Setup {
    const internal = try tt.keypair(0x01);
    return tt.buildSingleLeaf(a, internal.x, script);
}

test "taproot witness shape: annex detection and empty witness" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try leafSetup(a, &.{0x51});
    const junk32: [32]u8 = @splat(0x12);
    var annexed_single: [64]u8 = @splat(0x34);
    annexed_single[0] = 0x50;
    // a lone item starting with 0x50 is a key-path signature, not an annex
    try testing.expectError(error.InvalidTaprootSignature, vs(a, &.{}, &s.script_pubkey, &.{&annexed_single}, taproot_flags));
    // two items whose last is annex-shaped: the annex is stripped and the rest is a key-path spend
    try testing.expectError(error.InvalidTaprootSignature, vs(a, &.{}, &s.script_pubkey, &.{ &junk32, "\x50\xaa" }, taproot_flags));
    // an empty last item is no annex: it is the (empty) control block
    try testing.expectError(error.TaprootWrongControlSize, vs(a, &.{}, &s.script_pubkey, &.{ &junk32, "" }, taproot_flags));
    try testing.expectError(error.WitnessProgramWitnessEmpty, vs(a, &.{}, &s.script_pubkey, &.{}, taproot_flags));
}

test "taproot key path: an explicit SIGHASH_DEFAULT byte is refused even on a valid signature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try leafSetup(a, &.{0x51});
    const k = try tt.keypair(0x09);
    const spk = [_]u8{ 0x51, 0x20 } ++ k.x;
    const h = try bitcointx.bip341.sighash(a, s.tx, 0, bitcointx.bip341.SIGHASH_DEFAULT, s.spent);
    const io: std.Io = undefined;
    const sig = try bip340.sign(&k.sk, &h, @as([32]u8, @splat(0x21)), io, .{});
    try vs2(a, &spk, &.{&sig}, s.ctx);
    const sig65 = sig ++ [_]u8{0x00};
    try testing.expectError(error.InvalidTaprootSignature, verify.verifyScript(a, &.{}, &spk, &.{&sig65}, taproot_flags, s.ctx));
}

fn vs2(a: Allocator, spk: []const u8, witness: []const []const u8, ctx: txctx.TxContext) !void {
    try verify.verifyScript(a, &.{}, spk, witness, taproot_flags, ctx);
}

test "taproot script path: unknown leaf version, initial stack elements, clean stack" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // unknown leaf version 0xc2: anyone-can-spend, unless policy says otherwise
    const internal = try tt.keypair(0x01);
    const script = [_]u8{0x51};
    const out = tt.taprootOutput(internal.x, tapscript.tapleafHash(0xc2, &script));
    const spk = [_]u8{ 0x51, 0x20 } ++ out.q;
    const cb = [_]u8{0xc2 | out.parity} ++ internal.x;
    const s = try leafSetup(a, &.{0x51});
    try vs2(a, &spk, &.{ &script, &cb }, s.ctx);
    var pol = taproot_flags;
    pol.discourage_upgradable_taproot_version = true;
    try testing.expectError(error.DiscourageUpgradableTaprootVersion, verify.verifyScript(a, &.{}, &spk, &.{ &script, &cb }, pol, s.ctx));
    // initial stack elements: 520 bytes fine, 521 refused
    const drop1 = [_]u8{ 0x75, 0x51 };
    const sd = try leafSetup(a, &drop1);
    const e520 = try a.alloc(u8, 520);
    @memset(e520, 1);
    const e521 = try a.alloc(u8, 521);
    @memset(e521, 1);
    try vs2(a, &sd.script_pubkey, &.{ e520, &drop1, &sd.control_block }, sd.ctx);
    try testing.expectError(error.PushSize, verify.verifyScript(a, &.{}, &sd.script_pubkey, &.{ e521, &drop1, &sd.control_block }, taproot_flags, sd.ctx));
    // two truthy elements left: not clean
    const two = [_]u8{ 0x51, 0x51 };
    const s2 = try leafSetup(a, &two);
    try testing.expectError(error.CleanStack, verify.verifyScript(a, &.{}, &s2.script_pubkey, &.{ &two, &s2.control_block }, taproot_flags, s2.ctx));
    // a false result
    const zero = [_]u8{0x00};
    const s3 = try leafSetup(a, &zero);
    try testing.expectError(error.EvalFalse, verify.verifyScript(a, &.{}, &s3.script_pubkey, &.{ &zero, &s3.control_block }, taproot_flags, s3.ctx));
}

test "tapscript validation-weight budget: 50 + the witness's serialized size, to the byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // seven CHECKSIGVERIFYs over 33-byte (unknown-type) keys with 1-byte signatures cost 7 * 50;
    // the budget is 50 + S where S is the witness size: 1 + 7*2 + (1+L) + 34 = 50 + L, so L = 250 is
    // exactly enough and L = 249 is one weight unit short.
    const unit = [_]u8{0x21} ++ @as([33]u8, @splat(0x02)) ++ [_]u8{0xad};
    var body: std.ArrayList(u8) = .empty;
    for (0..7) |_| try body.appendSlice(a, &unit);
    try body.append(a, 0x51);
    try testing.expectEqual(@as(usize, 246), body.items.len);
    const sig: []const u8 = "\x01";

    var exact = try body.clone(a);
    try exact.appendNTimes(a, 0x61, 4);
    const se = try leafSetup(a, exact.items);
    const w_exact = [_][]const u8{ sig, sig, sig, sig, sig, sig, sig, exact.items, &se.control_block };
    try verify.verifyScript(a, &.{}, &se.script_pubkey, &w_exact, taproot_flags, se.ctx);

    var short = try body.clone(a);
    try short.appendNTimes(a, 0x61, 3);
    const ss = try leafSetup(a, short.items);
    const w_short = [_][]const u8{ sig, sig, sig, sig, sig, sig, sig, short.items, &ss.control_block };
    try testing.expectError(error.TapscriptValidationWeight, verify.verifyScript(a, &.{}, &ss.script_pubkey, &w_short, taproot_flags, ss.ctx));

    // the annex is part of the witness: 4 more bytes of size, 4 fewer pad bytes
    const sa = try leafSetup(a, body.items);
    const w_annex = [_][]const u8{ sig, sig, sig, sig, sig, sig, sig, body.items, &sa.control_block, "\x50\xaa\xbb" };
    try verify.verifyScript(a, &.{}, &sa.script_pubkey, &w_annex, taproot_flags, sa.ctx);
}

// ── tapscript signature checks ───────────────────────────────────────────

fn xOnlyNotOnCurve() [32]u8 {
    var x: [32]u8 = @splat(0);
    var i: u8 = 1;
    while (i < 255) : (i += 1) {
        x[31] = i;
        if (bip340.XOnlyPublicKey.fromBytes(x)) |_| {} else |_| return x;
    }
    unreachable;
}

test "checkSchnorrSig: 64 or 65 bytes, hashtype byte validated, error classes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const internal = try tt.keypair(0x01);
    const leaf = try tt.keypair(0x02);
    const script = [_]u8{0x20} ++ leaf.x ++ [_]u8{0xac};
    const s = try tt.buildSingleLeaf(a, internal.x, &script);
    const exec: tapscript.ExecData = .{ .tapleaf_hash = s.tapleaf_hash };
    const io: std.Io = undefined;

    const h0 = try tapscript.sighash(a, s.tx, 0, 0x00, s.spent, &exec);
    const sig0 = try bip340.sign(&leaf.sk, &h0, @as([32]u8, @splat(0x31)), io, .{});
    try tapscript.checkSchnorrSig(a, &sig0, &leaf.x, s.ctx, &exec);

    const h1 = try tapscript.sighash(a, s.tx, 0, 0x01, s.spent, &exec);
    const sig1 = try bip340.sign(&leaf.sk, &h1, @as([32]u8, @splat(0x32)), io, .{});
    const sig1_65 = sig1 ++ [_]u8{0x01};
    try tapscript.checkSchnorrSig(a, &sig1_65, &leaf.x, s.ctx, &exec);
    // the hashtype byte really decides which message was signed
    const sig1_as_0 = sig1 ++ [_]u8{0x02};
    try testing.expectError(error.SchnorrSig, tapscript.checkSchnorrSig(a, &sig1_as_0, &leaf.x, s.ctx, &exec));

    try testing.expectError(error.SchnorrSigSize, tapscript.checkSchnorrSig(a, sig0[0..63], &leaf.x, s.ctx, &exec));
    try testing.expectError(error.SchnorrSigSize, tapscript.checkSchnorrSig(a, &(sig0 ++ [_]u8{ 1, 2 }), &leaf.x, s.ctx, &exec));
    try testing.expectError(error.SchnorrSigHashtype, tapscript.checkSchnorrSig(a, &(sig0 ++ [_]u8{0x00}), &leaf.x, s.ctx, &exec));
    try testing.expectError(error.SchnorrSigHashtype, tapscript.checkSchnorrSig(a, &(sig0 ++ [_]u8{0x04}), &leaf.x, s.ctx, &exec));
    // a key that is not a curve point is a signature failure, not a size failure
    const bad = xOnlyNotOnCurve();
    try testing.expectError(error.SchnorrSig, tapscript.checkSchnorrSig(a, &sig0, &bad, s.ctx, &exec));
    // the signature really is bound to the key
    try testing.expectError(error.SchnorrSig, tapscript.checkSchnorrSig(a, &sig0, &internal.x, s.ctx, &exec));
}

test "tapscript sigMsg commits to the last executed codeseparator position and to the leaf" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try leafSetup(a, &.{0x51});
    var exec: tapscript.ExecData = .{ .tapleaf_hash = @as([32]u8, @splat(0x5a)), .codesep_pos = 7 };
    const msg = try tapscript.sigMsg(a, s.tx, 0, 0x00, s.spent, &exec);
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, msg[msg.len - 4 ..][0..4], .little));
    try testing.expectEqual(@as(u8, 0x00), msg[msg.len - 5]);
    try testing.expectEqualSlices(u8, &exec.tapleaf_hash, msg[msg.len - 37 .. msg.len - 5]);
    exec.annex = "\x50\xaa";
    const with_annex = try tapscript.sigMsg(a, s.tx, 0, 0x00, s.spent, &exec);
    try testing.expectEqual(msg.len + 32, with_annex.len);
}

test "controlBlockValid accepts the maximum 128 nodes" {
    try testing.expect(tapscript.controlBlockValid(&(@as([33 + 32 * 128]u8, @splat(0)))));
}

// ── ECDSA: Core's lax DER acceptance, codeseparator scriptCode, S-ending-in-hashtype ──

const LegacySpend = struct {
    kp: EcdsaSecp256k1Sha256.KeyPair,
    pk: [33]u8,
    tx: bitcointx.Transaction,
    spent: []const bitcointx.TxOut,

    fn init(a: Allocator, spk: []const u8, pk_seed: u8) !LegacySpend {
        const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(pk_seed)));
        const vin = try a.alloc(bitcointx.TxIn, 1);
        vin[0] = .{ .prevout = .{ .txid = @as([32]u8, @splat(0x42)), .vout = 1 }, .script_sig = &.{}, .sequence = 0xffffffff };
        const vout = try a.alloc(bitcointx.TxOut, 1);
        vout[0] = .{ .value = 900, .script_pubkey = &.{} };
        const spent = try a.alloc(bitcointx.TxOut, 1);
        spent[0] = .{ .value = 1000, .script_pubkey = try a.dupe(u8, spk) };
        return .{
            .kp = kp,
            .pk = kp.public_key.toCompressedSec1(),
            .tx = .{ .version = 1, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false },
            .spent = spent,
        };
    }

    fn ctx(self: LegacySpend) txctx.TxContext {
        return .{ .tx = self.tx, .input_index = 0, .spent_outputs = self.spent };
    }
};

fn pushOf(a: Allocator, data: []const u8) ![]u8 {
    std.debug.assert(data.len < 0x4c);
    return std.mem.concat(a, u8, &.{ &[_]u8{@intCast(data.len)}, data });
}

test "lax DER: a script run without DERSIG accepts what Core's lax parser accepts (every rule), refuses what it refuses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // P2PK; its own scriptCode is the whole scriptPubKey
    var spk_buf: [35]u8 = undefined;
    const sp0 = try LegacySpend.init(a, &.{}, 0x61);
    spk_buf[0] = 0x21;
    @memcpy(spk_buf[1..34], &sp0.pk);
    spk_buf[34] = 0xac;
    const spk: []const u8 = &spk_buf;
    const sp = try LegacySpend.init(a, spk, 0x61);
    const h = try bitcointx.legacy.sighash(a, sp.tx, 0, spk, 1);
    const sig = try sp.kp.signPrehashed(h, null);

    const r_int = [_]u8{ 0x02, 0x20 } ++ sig.r;
    const s_int = [_]u8{ 0x02, 0x20 } ++ sig.s;
    const body = r_int ++ s_int;
    const ht = [_]u8{0x01};
    const Case = struct { name: []const u8, der: []const u8, ok: bool };
    const r_long = [_]u8{ 0x02, 0x81, 0x20 } ++ sig.r;
    const r_long_zeros = [_]u8{ 0x02, 0x84, 0x00, 0x00, 0x00, 0x20 } ++ sig.r;
    const s_long = [_]u8{ 0x02, 0x82, 0x00, 0x20 } ++ sig.s;
    const r_padded = [_]u8{ 0x02, 0x22, 0x00, 0x00 } ++ sig.r;
    const s_padded = [_]u8{ 0x02, 0x22, 0x00, 0x00 } ++ sig.s;
    const r_33 = [_]u8{ 0x02, 0x21, 0xaa } ++ sig.r;
    const r_len4 = [_]u8{ 0x02, 0x84, 0x01, 0x00, 0x00, 0x00 } ++ sig.r;
    const cases = [_]Case{
        .{ .name = "canonical length byte", .der = &([_]u8{ 0x30, 0x44 } ++ body), .ok = true },
        .{ .name = "sequence length too large", .der = &([_]u8{ 0x30, 0x7f } ++ body), .ok = true },
        .{ .name = "sequence length zero", .der = &([_]u8{ 0x30, 0x00 } ++ body), .ok = true },
        .{ .name = "long-form sequence length", .der = &([_]u8{ 0x30, 0x81, 0x44 } ++ body), .ok = true },
        .{ .name = "long-form sequence length, junk bytes", .der = &([_]u8{ 0x30, 0x82, 0xde, 0xad } ++ body), .ok = true },
        .{ .name = "long-form R length", .der = &([_]u8{ 0x30, 0x00 } ++ r_long ++ s_int), .ok = true },
        .{ .name = "long-form R length with zero length bytes", .der = &([_]u8{ 0x30, 0x00 } ++ r_long_zeros ++ s_int), .ok = true },
        .{ .name = "long-form S length", .der = &([_]u8{ 0x30, 0x00 } ++ r_int ++ s_long), .ok = true },
        .{ .name = "excess leading zeros on R and S", .der = &([_]u8{ 0x30, 0x00 } ++ r_padded ++ s_padded), .ok = true },
        .{ .name = "trailing bytes after S", .der = &([_]u8{ 0x30, 0x44 } ++ body ++ [_]u8{ 0xde, 0xad }), .ok = true },
        .{ .name = "wrong sequence tag", .der = &([_]u8{ 0x31, 0x44 } ++ body), .ok = false },
        .{ .name = "wrong R tag", .der = &([_]u8{ 0x30, 0x44, 0x03 } ++ body[1..].*), .ok = false },
        .{ .name = "wrong S tag", .der = &([_]u8{ 0x30, 0x44 } ++ r_int ++ [_]u8{0x03} ++ s_int[1..].*), .ok = false },
        .{ .name = "R longer than the input", .der = &([_]u8{ 0x30, 0x44, 0x02, 0x7f } ++ body[2..].*), .ok = false },
        .{ .name = "S one byte longer than the input", .der = &([_]u8{ 0x30, 0x44 } ++ r_int ++ [_]u8{ 0x02, 0x21 } ++ sig.s), .ok = false },
        .{ .name = "R with 33 significant bytes", .der = &([_]u8{ 0x30, 0x00 } ++ r_33 ++ s_int), .ok = false },
        .{ .name = "long-form length with four significant bytes", .der = &([_]u8{ 0x30, 0x00 } ++ r_len4 ++ s_int), .ok = false },
    };
    for (cases) |c| {
        const sig_el = try std.mem.concat(a, u8, &.{ c.der, &ht });
        var ss: std.ArrayList(u8) = .empty;
        if (sig_el.len < 0x4c) {
            try ss.append(a, @intCast(sig_el.len));
        } else {
            try ss.appendSlice(a, &.{ 0x4c, @intCast(sig_el.len) });
        }
        try ss.appendSlice(a, sig_el);
        const got = verify.verifyScript(a, ss.items, spk, &.{}, .{}, sp.ctx());
        if (c.ok) {
            got catch |e| {
                std.debug.print("\nlax case `{s}` should verify, got {s}\n", .{ c.name, @errorName(e) });
                return e;
            };
        } else {
            testing.expectError(error.EvalFalse, got) catch |e| {
                std.debug.print("\nlax case `{s}` should not verify\n", .{c.name});
                return e;
            };
        }
        // under DERSIG every non-canonical shape is a hard error (the strict path is unchanged)
        if (c.ok and !std.mem.eql(u8, c.name, "canonical length byte")) {
            const strict = verify.verifyScript(a, ss.items, spk, &.{}, .{ .dersig = true }, sp.ctx());
            testing.expectError(error.SigDer, strict) catch |e| {
                std.debug.print("\nlax case `{s}` must be SigDer under dersig\n", .{c.name});
                return e;
            };
        }
    }
}

test "CHECKMULTISIG signs the scriptCode that starts after the last OP_CODESEPARATOR" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sp0 = try LegacySpend.init(a, &.{}, 0x62);
    // NOP CODESEPARATOR 1 <pk> 1 CHECKMULTISIG
    const spk = [_]u8{ 0x61, 0xab, 0x51, 0x21 } ++ sp0.pk ++ [_]u8{ 0x51, 0xae };
    const sp = try LegacySpend.init(a, &spk, 0x62);
    const good_code = spk[2..];
    for ([_][]const u8{ good_code, &spk }, 0..) |code, i| {
        const h = try bitcointx.legacy.sighash(a, sp.tx, 0, code, 1);
        const sig = try sp.kp.signPrehashed(h, null);
        var der_buf: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&der_buf);
        const el = try std.mem.concat(a, u8, &.{ der, &[_]u8{0x01} });
        const script_sig = try std.mem.concat(a, u8, &.{ &[_]u8{0x00}, try pushOf(a, el) });
        const got = verify.verifyScript(a, script_sig, &spk, &.{}, .{}, sp.ctx());
        if (i == 0) try got else try testing.expectError(error.EvalFalse, got);
    }
}

test "the hashtype byte is the LAST byte of the element: an S that ends in it does not borrow it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var spk_buf: [35]u8 = undefined;
    const sp0 = try LegacySpend.init(a, &.{}, 0x63);
    spk_buf[0] = 0x21;
    @memcpy(spk_buf[1..34], &sp0.pk);
    spk_buf[34] = 0xac;
    const spk: []const u8 = &spk_buf;
    const sp = try LegacySpend.init(a, spk, 0x63);
    const h = try bitcointx.legacy.sighash(a, sp.tx, 0, spk, 1);
    // grind a signature whose S ends in 0x01 (= SIGHASH_ALL) and send it WITHOUT a separate hashtype byte
    var n: u32 = 0;
    while (n < 20000) : (n += 1) {
        var noise: [32]u8 = @splat(0);
        std.mem.writeInt(u32, noise[0..4], n, .little);
        const sig = try sp.kp.signPrehashed(h, noise);
        if (sig.s[31] != 0x01) continue;
        const el = [_]u8{ 0x30, 0x44, 0x02, 0x20 } ++ sig.r ++ [_]u8{ 0x02, 0x20 } ++ sig.s;
        var ss: std.ArrayList(u8) = .empty;
        try ss.append(a, 0x46); // 70-byte push
        try ss.appendSlice(a, &el);
        // Core: the last byte is the hashtype, so S is one byte short and the lax parse fails
        try testing.expectError(error.EvalFalse, verify.verifyScript(a, ss.items, spk, &.{}, .{}, sp.ctx()));
        return;
    }
    return error.TestUnexpectedResult;
}

test "CHECKMULTISIG: key and signature counts one larger than the stack are refused" {
    try expectEvalError("1 CHECKMULTISIG", error.InvalidStackOperation);
    try expectEvalError("1 'pk' 1 CHECKMULTISIG", error.InvalidStackOperation);
    try expectEvalError("0 CHECKMULTISIG", error.InvalidStackOperation);
    try expectEvalError("2 'pk' 1 CHECKMULTISIG", error.SigCount);
    try expectEvalError("21 CHECKMULTISIG", error.PubkeyCount);
    try expectEvalError("-1 CHECKMULTISIG", error.PubkeyCount);
}
