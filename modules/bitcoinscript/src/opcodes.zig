// SPDX-License-Identifier: MIT
//! Bitcoin Script opcode table — byte values and mnemonics exactly matching
//! Bitcoin Core's `opcodetype` enum (`script/script.h`). This is metadata
//! only (values + names + the disabled-opcode set); execution semantics
//! live in `interpreter.zig`.

const std = @import("std");

pub const Opcode = enum(u8) {
    // Push value
    OP_0 = 0x00,
    // 0x01..0x4b: direct data push (opcode byte == length, 1..75) — not
    // named individually; `interpreter.zig` handles this range numerically.
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // Splice (disabled)
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // Bitwise (mostly disabled)
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // Arithmetic
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d, // disabled
    OP_2DIV = 0x8e, // disabled
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95, // disabled
    OP_DIV = 0x96, // disabled
    OP_MOD = 0x97, // disabled
    OP_LSHIFT = 0x98, // disabled
    OP_RSHIFT = 0x99, // disabled
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,

    // Crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // Expansion / locktime
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // Tapscript (BIP342): replaces the (disabled-in-tapscript)
    // `OP_CHECKMULTISIG` family. `interpreter.zig` executes it only under
    // `SigVersion.tapscript`; under `.base`/`.witness_v0` it falls through
    // to `BadOpcode`, matching Bitcoin Core's `EvalScript` (which rejects it
    // outside tapscript execution).
    OP_CHECKSIGADD = 0xba,

    OP_INVALIDOPCODE = 0xff,

    _,
};

pub const OP_FALSE: u8 = 0x00;
pub const OP_TRUE: u8 = 0x51;

/// Opcodes Bitcoin Core disables unconditionally — `interpreter.zig` must
/// reject these the instant they're read, regardless of whether the
/// enclosing `OP_IF` branch is even taken (Bitcoin Core checks this before
/// consulting the execution-branch flag, so a disabled opcode inside a
/// never-taken branch still fails the whole script).
pub fn isDisabled(op: u8) bool {
    return switch (op) {
        0x7e,
        0x7f,
        0x80,
        0x81, // CAT, SUBSTR, LEFT, RIGHT
        0x83,
        0x84,
        0x85,
        0x86, // INVERT, AND, OR, XOR
        0x8d,
        0x8e, // 2MUL, 2DIV
        0x95,
        0x96,
        0x97,
        0x98,
        0x99, // MUL, DIV, MOD, LSHIFT, RSHIFT
        => true,
        else => false,
    };
}

/// `OP_VERIF`/`OP_VERNOTIF` — reserved conditional-control opcodes that
/// Bitcoin Core rejects unconditionally (like disabled opcodes, NOT gated
/// on the current execution-branch flag), because a script-level "invalid
/// conditional shape" must be caught even scanning through a skipped branch.
pub fn isReservedConditional(op: u8) bool {
    return op == 0x65 or op == 0x66;
}

/// BIP342 `OP_SUCCESSx`: the opcode bytes that, when present ANYWHERE in a
/// tapscript leaf (executed or not, even in an otherwise-undecodable tail),
/// make the whole script succeed unconditionally (unless the
/// `DISCOURAGE_OP_SUCCESS` policy flag is set). This is the EXACT set from
/// BIP342 — "80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254"
/// — which is also precisely the union of Bitcoin Script's previously
/// disabled/reserved opcodes plus the whole undefined 0xbb..0xfe tail, so a
/// tapscript leaf never reaches the legacy `isDisabled`/`BadOpcode` paths
/// for any of these. Only meaningful under `SigVersion.tapscript`.
pub fn isOpSuccess(op: u8) bool {
    return switch (op) {
        80, 98, 126...129, 131...134, 137...138, 141...142, 149...153, 187...254 => true,
        else => false,
    };
}

const testing = std.testing;

test "opcode values match Bitcoin Core's opcodetype enum at a few checked points" {
    try testing.expectEqual(@as(u8, 0xac), @intFromEnum(Opcode.OP_CHECKSIG));
    try testing.expectEqual(@as(u8, 0xae), @intFromEnum(Opcode.OP_CHECKMULTISIG));
    try testing.expectEqual(@as(u8, 0xa9), @intFromEnum(Opcode.OP_HASH160));
    try testing.expectEqual(@as(u8, 0xb1), @intFromEnum(Opcode.OP_CHECKLOCKTIMEVERIFY));
    try testing.expectEqual(@as(u8, 0xb2), @intFromEnum(Opcode.OP_CHECKSEQUENCEVERIFY));
    try testing.expectEqual(@as(u8, 0x51), @intFromEnum(Opcode.OP_1));
    try testing.expectEqual(@as(u8, 0x60), @intFromEnum(Opcode.OP_16));
    try testing.expectEqual(@as(u8, 0xff), @intFromEnum(Opcode.OP_INVALIDOPCODE));
}

test "isDisabled covers exactly the splice/bitwise/wide-arithmetic set" {
    const disabled = [_]u8{ 0x7e, 0x7f, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98, 0x99 };
    for (disabled) |op| try testing.expect(isDisabled(op));
    try testing.expect(!isDisabled(0x93)); // OP_ADD stays enabled
    try testing.expect(!isDisabled(0x82)); // OP_SIZE stays enabled
    try testing.expect(!isDisabled(0x87)); // OP_EQUAL stays enabled
}
