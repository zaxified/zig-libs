// SPDX-License-Identifier: MIT
//! Test-support only: an assembler for Bitcoin Core's `script_tests.json`
//! human-readable script format (`src/test/util/json.cpp` /
//! `script_tests.cpp`'s `ParseScript`), so the pinned vectors in
//! `script_tests_vectors.zig` can be transcribed as the exact asm text the
//! JSON file itself contains, rather than pre-assembled byte arrays —
//! keeping the diff against the official corpus auditable. NOT part of the
//! module's public API (not re-exported from `root.zig`).
//!
//! Token grammar (matching Bitcoin Core exactly):
//! - a decimal integer (optionally `-`-prefixed): pushed via the same
//!   `CScript::operator<<(int64_t)` encoding used everywhere else in this
//!   module (`OP_0`/`OP_1NEGATE`/`OP_1..OP_16` for the values they cover,
//!   else a minimal-length data push of the `CScriptNum` encoding).
//! - `0x<hex>`: raw bytes, inserted into the output **verbatim, not
//!   pushed** — this is how the corpus hand-constructs malformed/edge-case
//!   encodings (a bare `PUSHDATA1` length prefix, a `CODESEPARATOR` byte
//!   mid-push, …) byte-for-byte.
//! - `'quoted string'`: pushed as literal data via the ordinary
//!   minimal-push-opcode-for-length rule (never through the number
//!   optimization above, even for e.g. `'\x01'`).
//! - anything else: an opcode mnemonic, matched against this module's
//!   `Opcode` enum with an optional `OP_` prefix (`DUP` and `OP_DUP` both
//!   resolve to `Opcode.OP_DUP`), plus the `TRUE`/`FALSE` aliases Bitcoin
//!   Core's `GetOpCode` also recognizes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const number = @import("number.zig");
const opcodes = @import("opcodes.zig");
const Opcode = opcodes.Opcode;

pub const AsmError = error{UnknownMnemonic} || Allocator.Error || std.fmt.ParseIntError || @typeInfo(@typeInfo(@TypeOf(std.fmt.hexToBytes)).@"fn".return_type.?).error_union.error_set;

fn isAllDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn appendDataPush(out: *std.ArrayList(u8), allocator: Allocator, data: []const u8) Allocator.Error!void {
    if (data.len < 0x4c) {
        try out.append(allocator, @intCast(data.len));
    } else if (data.len <= 0xff) {
        try out.append(allocator, 0x4c);
        try out.append(allocator, @intCast(data.len));
    } else if (data.len <= 0xffff) {
        try out.append(allocator, 0x4d);
        var lb: [2]u8 = undefined;
        std.mem.writeInt(u16, &lb, @intCast(data.len), .little);
        try out.appendSlice(allocator, &lb);
    } else {
        try out.append(allocator, 0x4e);
        var lb: [4]u8 = undefined;
        std.mem.writeInt(u32, &lb, @intCast(data.len), .little);
        try out.appendSlice(allocator, &lb);
    }
    try out.appendSlice(allocator, data);
}

fn appendNumberPush(out: *std.ArrayList(u8), allocator: Allocator, n: i64) Allocator.Error!void {
    if (n == 0) {
        try out.append(allocator, 0x00);
        return;
    }
    if (n == -1) {
        try out.append(allocator, 0x4f);
        return;
    }
    if (n >= 1 and n <= 16) {
        try out.append(allocator, @intCast(0x50 + n));
        return;
    }
    var buf: [9]u8 = undefined;
    try appendDataPush(out, allocator, number.encode(n, &buf));
}

fn lookupOpcode(name: []const u8) ?u8 {
    if (std.mem.eql(u8, name, "TRUE")) return 0x51;
    if (std.mem.eql(u8, name, "FALSE")) return 0x00;
    var buf: [40]u8 = undefined;
    var canonical: []const u8 = name;
    if (!std.mem.startsWith(u8, name, "OP_")) {
        if (name.len + 3 > buf.len) return null;
        @memcpy(buf[0..3], "OP_");
        @memcpy(buf[3 .. 3 + name.len], name);
        canonical = buf[0 .. 3 + name.len];
    }
    if (std.meta.stringToEnum(Opcode, canonical)) |e| return @intFromEnum(e);
    return null;
}

/// Assembles Bitcoin Core asm text into script bytes. Caller owns the
/// returned slice.
pub fn assemble(allocator: Allocator, text: []const u8) AsmError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
    while (it.next()) |tok| {
        if (isAllDigits(tok) or (tok.len > 1 and tok[0] == '-' and isAllDigits(tok[1..]))) {
            const n = try std.fmt.parseInt(i64, tok, 10);
            try appendNumberPush(&out, allocator, n);
        } else if (tok.len > 2 and tok[0] == '0' and tok[1] == 'x') {
            const hex = tok[2..];
            const raw = try allocator.alloc(u8, hex.len / 2);
            defer allocator.free(raw);
            _ = try std.fmt.hexToBytes(raw, hex);
            try out.appendSlice(allocator, raw);
        } else if (tok.len >= 2 and tok[0] == '\'' and tok[tok.len - 1] == '\'') {
            try appendDataPush(&out, allocator, tok[1 .. tok.len - 1]);
        } else {
            const op = lookupOpcode(tok) orelse return error.UnknownMnemonic;
            try out.append(allocator, op);
        }
    }
    return out.toOwnedSlice(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "numbers: 0/-1/1..16 use the dedicated opcodes, others a minimal push" {
    const allocator = testing.allocator;
    {
        const b = try assemble(allocator, "0");
        defer allocator.free(b);
        try testing.expectEqualSlices(u8, &.{0x00}, b);
    }
    {
        const b = try assemble(allocator, "-1");
        defer allocator.free(b);
        try testing.expectEqualSlices(u8, &.{0x4f}, b);
    }
    {
        const b = try assemble(allocator, "16");
        defer allocator.free(b);
        try testing.expectEqualSlices(u8, &.{0x60}, b);
    }
    {
        const b = try assemble(allocator, "17");
        defer allocator.free(b);
        try testing.expectEqualSlices(u8, &.{ 0x01, 0x11 }, b);
    }
    {
        const b = try assemble(allocator, "-17");
        defer allocator.free(b);
        try testing.expectEqualSlices(u8, &.{ 0x01, 0x91 }, b);
    }
}

test "0x hex tokens are inserted raw, not wrapped in a push" {
    const allocator = testing.allocator;
    const b = try assemble(allocator, "0x4c 0x01 0x01");
    defer allocator.free(b);
    try testing.expectEqualSlices(u8, &.{ 0x4c, 0x01, 0x01 }, b);
}

test "quoted strings push literal bytes via the minimal-length rule" {
    const allocator = testing.allocator;
    const b = try assemble(allocator, "'abc'");
    defer allocator.free(b);
    try testing.expectEqualSlices(u8, &.{ 0x03, 'a', 'b', 'c' }, b);
}

test "opcode mnemonics resolve with or without the OP_ prefix" {
    const allocator = testing.allocator;
    const a = try assemble(allocator, "DUP HASH160 EQUALVERIFY CHECKSIG");
    defer allocator.free(a);
    const b = try assemble(allocator, "OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG");
    defer allocator.free(b);
    try testing.expectEqualSlices(u8, a, b);
    try testing.expectEqualSlices(u8, &.{ 0x76, 0xa9, 0x88, 0xac }, a);
}

test "TRUE/FALSE aliases" {
    const allocator = testing.allocator;
    const t = try assemble(allocator, "TRUE");
    defer allocator.free(t);
    try testing.expectEqualSlices(u8, &.{0x51}, t);
    const f = try assemble(allocator, "FALSE");
    defer allocator.free(f);
    try testing.expectEqualSlices(u8, &.{0x00}, f);
}

test "unknown mnemonic is a typed error" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnknownMnemonic, assemble(allocator, "NOTANOPCODE"));
}

test "P2PKH-shaped script assembles to the expected 25-byte template" {
    const allocator = testing.allocator;
    const b = try assemble(allocator, "DUP HASH160 0x14 0x89abcdefabbaabbaabbaabbaabbaabbaabbaabba EQUALVERIFY CHECKSIG");
    defer allocator.free(b);
    try testing.expectEqual(@as(usize, 25), b.len);
    try testing.expectEqual(@as(u8, 0x76), b[0]);
    try testing.expectEqual(@as(u8, 0xa9), b[1]);
    try testing.expectEqual(@as(u8, 0x14), b[2]);
    try testing.expectEqual(@as(u8, 0x88), b[23]);
    try testing.expectEqual(@as(u8, 0xac), b[24]);
}
