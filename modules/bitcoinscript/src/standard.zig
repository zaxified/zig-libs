// SPDX-License-Identifier: MIT
//! Output-script template classification — Bitcoin Core `Solver`,
//! `IsStandard` and `ExtractDestination` (`script/solver.cpp`,
//! `script/standard.cpp`, `policy/policy.cpp`), and the btcd `txscript`
//! `standard.go` equivalents. Tells a wallet or relay filter what a
//! scriptPubKey pays to, without running it.
//!
//! Every result borrows from the input script (no allocation). The matchers
//! decode with the interpreter's `readInstruction`, so push-length rules are
//! the consensus ones; like Core, a bare-pubkey / multisig key is accepted
//! when its header byte and length agree (`CPubKey::ValidSize`), without a
//! curve check.

const std = @import("std");
const ripemd160 = @import("ripemd160");
const interpreter = @import("interpreter.zig");

/// Core `TxoutType` (`script/solver.h`).
pub const TxoutType = enum {
    nonstandard,
    anchor,
    pubkey,
    pubkeyhash,
    scripthash,
    multisig,
    nulldata,
    witness_v0_scripthash,
    witness_v0_keyhash,
    witness_v1_taproot,
    witness_unknown,
};

/// Most keys a standard-template bare multisig can carry (`OP_16`).
pub const max_multisig_keys = 16;

pub const Multisig = struct {
    /// `m` of the `m`-of-`n`, 1..16.
    required: u8,
    /// Number of keys `n`, `required <= n <= 16`.
    n: u8,
    key_storage: [max_multisig_keys][]const u8,

    /// The `n` public keys (33 or 65 bytes each), in script order.
    pub fn keys(self: *const Multisig) []const []const u8 {
        return self.key_storage[0..self.n];
    }
};

/// The template an output script matches and the data it commits to
/// (Core's `vSolutionsRet`).
pub const Template = union(TxoutType) {
    nonstandard,
    /// `OP_1 <0x4e73>` (BIP-0433-style pay-to-anchor).
    anchor,
    /// `<pubkey> OP_CHECKSIG`; the 33- or 65-byte key.
    pubkey: []const u8,
    pubkeyhash: *const [20]u8,
    scripthash: *const [20]u8,
    multisig: Multisig,
    /// `OP_RETURN` followed only by pushes.
    nulldata,
    witness_v0_scripthash: *const [32]u8,
    witness_v0_keyhash: *const [20]u8,
    /// The 32-byte x-only output key.
    witness_v1_taproot: *const [32]u8,
    /// Any other witness program of version 1..16 (version 1 with a
    /// 32-byte program is taproot, version 0 with a length other than 20/32
    /// is `nonstandard`).
    witness_unknown: struct { version: u8, program: []const u8 },
};

/// `CPubKey::ValidSize`: 33 bytes with header 02/03, or 65 with 04/06/07.
fn validPubkeySize(k: []const u8) bool {
    if (k.len == 0) return false;
    return switch (k[0]) {
        2, 3 => k.len == 33,
        4, 6, 7 => k.len == 65,
        else => false,
    };
}

fn isSmallInteger(op: u8) bool {
    return op >= 0x51 and op <= 0x60;
}

fn matchMultisig(script: []const u8) ?Multisig {
    if (script.len < 1 or script[script.len - 1] != 0xae) return null;
    var i: usize = 0;
    const first = interpreter.readInstruction(script, 0) catch return null;
    if (!isSmallInteger(first.opcode)) return null;
    const required = first.opcode - 0x50;
    i = first.next;
    var ms: Multisig = .{ .required = required, .n = 0, .key_storage = undefined };
    // Core: `while (GetOp(it, opcode, data) && ValidSize(data)) push`, then
    // the instruction that ended the loop must be the small-integer `n`.
    var last_op: u8 = 0xff;
    var last_next: usize = i;
    var decoded = false;
    while (i < script.len) {
        const instr = interpreter.readInstruction(script, i) catch {
            decoded = false;
            break;
        };
        decoded = true;
        last_op = instr.opcode;
        last_next = instr.next;
        i = instr.next;
        const data = instr.data orelse &.{};
        if (!validPubkeySize(data)) break;
        if (ms.n == max_multisig_keys) return null; // 17th key: `n` cannot name it
        ms.key_storage[ms.n] = data;
        ms.n += 1;
        decoded = false;
    }
    if (!decoded) return null;
    if (!isSmallInteger(last_op)) return null;
    const n = last_op - 0x50;
    if (ms.n != n or n < required) return null;
    // `it + 1 == script.end()`: only OP_CHECKMULTISIG remains.
    if (last_next + 1 != script.len) return null;
    return ms;
}

/// Core `Solver`: classify `script_pubkey` and return what it commits to.
pub fn solve(script_pubkey: []const u8) Template {
    const s = script_pubkey;
    if (s.len == 23 and s[0] == 0xa9 and s[1] == 0x14 and s[22] == 0x87) return .{ .scripthash = s[2..22] };
    // Witness program: OP_0 / OP_1..OP_16 + one direct push of 2..40 bytes.
    if (s.len >= 4 and s.len <= 42 and s[1] >= 2 and s[1] <= 40 and s.len == @as(usize, s[1]) + 2 and
        (s[0] == 0x00 or isSmallInteger(s[0])))
    {
        const version: u8 = if (s[0] == 0) 0 else s[0] - 0x50;
        const prog = s[2..];
        if (version == 0 and prog.len == 20) return .{ .witness_v0_keyhash = prog[0..20] };
        if (version == 0 and prog.len == 32) return .{ .witness_v0_scripthash = prog[0..32] };
        if (version == 1 and prog.len == 32) return .{ .witness_v1_taproot = prog[0..32] };
        if (version == 1 and prog.len == 2 and prog[0] == 0x4e and prog[1] == 0x73) return .anchor;
        if (version != 0) return .{ .witness_unknown = .{ .version = version, .program = prog } };
        return .nonstandard;
    }
    if (s.len >= 1 and s[0] == 0x6a and pushOnly(s[1..])) return .nulldata;
    if (s.len == 67 and s[0] == 65 and s[66] == 0xac and validPubkeySize(s[1..66])) return .{ .pubkey = s[1..66] };
    if (s.len == 35 and s[0] == 33 and s[34] == 0xac and validPubkeySize(s[1..34])) return .{ .pubkey = s[1..34] };
    if (s.len == 25 and s[0] == 0x76 and s[1] == 0xa9 and s[2] == 0x14 and s[23] == 0x88 and s[24] == 0xac)
        return .{ .pubkeyhash = s[3..23] };
    if (matchMultisig(s)) |ms| return .{ .multisig = ms };
    return .nonstandard;
}

fn pushOnly(script: []const u8) bool {
    var i: usize = 0;
    while (i < script.len) {
        const instr = interpreter.readInstruction(script, i) catch return false;
        if (instr.opcode > 0x60) return false;
        i = instr.next;
    }
    return true;
}

/// Relay-policy knobs of `IsStandard`.
pub const StandardOptions = struct {
    /// Largest standard `OP_RETURN` script in bytes, or null to refuse all
    /// data carriers. Core v31 default (`-datacarriersize`,
    /// `MAX_OP_RETURN_RELAY`): 100000.
    max_datacarrier_bytes: ?usize = 100_000,
};

/// Core `IsStandard(scriptPubKey, max_datacarrier_bytes, whichType)`: the
/// template is not `nonstandard`; bare multisig is at most 3 keys with
/// `1 <= m <= n`; a data carrier fits `max_datacarrier_bytes`. Returns the
/// template type when standard.
pub fn isStandard(script_pubkey: []const u8, opts: StandardOptions) ?TxoutType {
    const t = solve(script_pubkey);
    switch (t) {
        .nonstandard => return null,
        .multisig => |m| {
            if (m.n < 1 or m.n > 3) return null;
            if (m.required < 1 or m.required > m.n) return null;
        },
        .nulldata => {
            const max = opts.max_datacarrier_bytes orelse return null;
            if (script_pubkey.len > max) return null;
        },
        else => {},
    }
    return std.meta.activeTag(t);
}

/// What a script pays to (Core's `CTxDestination`).
pub const Destination = union(enum) {
    /// P2PKH, and a bare P2PK key reduced to its hash160 (as Core does).
    pubkeyhash: [20]u8,
    scripthash: [20]u8,
    witness_v0_keyhash: [20]u8,
    witness_v0_scripthash: [32]u8,
    witness_v1_taproot: [32]u8,
    pay_to_anchor,
    witness_unknown: struct { version: u8, program: []const u8 },
};

/// Core `ExtractDestination`: the single destination of `script_pubkey`, or
/// null for bare multisig, data carriers and non-standard scripts.
pub fn extractDestination(script_pubkey: []const u8) ?Destination {
    return switch (solve(script_pubkey)) {
        .pubkey => |k| blk: {
            var h: [20]u8 = undefined;
            ripemd160.hash160(k, &h);
            break :blk .{ .pubkeyhash = h };
        },
        .pubkeyhash => |h| .{ .pubkeyhash = h.* },
        .scripthash => |h| .{ .scripthash = h.* },
        .witness_v0_keyhash => |h| .{ .witness_v0_keyhash = h.* },
        .witness_v0_scripthash => |h| .{ .witness_v0_scripthash = h.* },
        .witness_v1_taproot => |h| .{ .witness_v1_taproot = h.* },
        .anchor => .pay_to_anchor,
        .witness_unknown => |w| .{ .witness_unknown = .{ .version = w.version, .program = w.program } },
        .multisig, .nulldata, .nonstandard => null,
    };
}
