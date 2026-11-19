// SPDX-License-Identifier: MIT
//! Script construction and disassembly: `ScriptBuilder` (push opcodes, data
//! and integers with the shortest encoding) and `toAsm` (the inverse, a
//! human-readable rendering).
//!
//! ## Builder
//!
//! `pushData` emits the shortest push that Bitcoin Core's `MINIMALDATA`
//! rule (`CheckMinimalPush`) accepts: the empty string is `OP_0`, one byte
//! `1..16` is `OP_1..OP_16`, the single byte `0x81` is `OP_1NEGATE`, up to 75
//! bytes a direct push, then `OP_PUSHDATA1/2/4`. A single `0x00` byte is NOT
//! `OP_0` (that would push the empty string, a different stack element): it is
//! the two bytes `01 00`. `pushInt` writes `OP_0`, `OP_1NEGATE`, `OP_1..OP_16`
//! for the values they cover and otherwise the minimal `CScriptNum` data push.
//!
//! The builder is bounded. By default it refuses to grow past
//! `limits.max_script_size` (10 000 bytes) and to push an element longer than
//! `limits.max_script_element_size` (520 bytes), the consensus bounds an
//! executable legacy / segwit v0 script and its stack elements obey
//! (`Limits` raises them, e.g. for a tapscript leaf, which has no script-size
//! limit). A refused push leaves the script unchanged.
//!
//! ## Disassembler
//!
//! `toAsm` follows Bitcoin Core's `ScriptToAsmStr`: opcodes by their Core
//! name (`OP_DUP`; `OP_0`, `OP_1NEGATE` and `OP_1..OP_16` are shown as the
//! numbers `0`, `-1`, `1..16`), a data push of at most 4 bytes as the decimal
//! `CScriptNum` it encodes (non-minimal forms accepted), a longer push as
//! bare lowercase hex, and a script that ends inside a push as `[error]`.
//! Like Core's output, the text is not injective (`01 05` and `OP_5` both
//! read `5`; a 5-byte push whose hex is all digits looks like a number).
//! `AsmOptions.sighash_decode` is Core's `fAttemptSighashDecode`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const limits_mod = @import("limits.zig");
const number = @import("number.zig");
const opcodes = @import("opcodes.zig");
const interpreter = @import("interpreter.zig");
const sigcheck = @import("sigcheck.zig");
const Opcode = opcodes.Opcode;

/// Bounds a `ScriptBuilder` enforces; the defaults are the consensus limits.
pub const Limits = struct {
    /// The script may not grow beyond this many bytes.
    max_script_size: usize = limits_mod.max_script_size,
    /// A single pushed element may not be longer than this.
    max_element_size: usize = limits_mod.max_script_element_size,
};

pub const BuildError = error{
    /// The push would make the script longer than `Limits.max_script_size`.
    ScriptTooLarge,
    /// The element is longer than `Limits.max_element_size` (or than a
    /// `OP_PUSHDATA4` length can express).
    PushTooLarge,
} || Allocator.Error;

/// Number of bytes the shortest push of `n` data bytes (beyond the special
/// one-byte forms) takes: opcode + length prefix + data.
fn pushLen(n: usize) usize {
    if (n < 0x4c) return 1 + n;
    if (n <= 0xff) return 2 + n;
    if (n <= 0xffff) return 3 + n;
    return 5 + n;
}

pub const ScriptBuilder = struct {
    allocator: Allocator,
    buf: std.ArrayList(u8) = .empty,
    limits: Limits = .{},

    pub fn init(allocator: Allocator) ScriptBuilder {
        return .{ .allocator = allocator };
    }

    pub fn initWithLimits(allocator: Allocator, limits: Limits) ScriptBuilder {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *ScriptBuilder) void {
        self.buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// The script built so far; valid until the next push.
    pub fn bytes(self: *const ScriptBuilder) []const u8 {
        return self.buf.items;
    }

    /// Returns the script and leaves the builder empty (limits kept).
    pub fn toOwnedSlice(self: *ScriptBuilder) Allocator.Error![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    /// Drops the script, keeping the allocation.
    pub fn reset(self: *ScriptBuilder) void {
        self.buf.clearRetainingCapacity();
    }

    fn room(self: *const ScriptBuilder, extra: usize) BuildError!void {
        // `buf.items.len <= max_script_size` is an invariant of every push.
        if (self.limits.max_script_size - self.buf.items.len < extra) return error.ScriptTooLarge;
    }

    /// Appends one opcode byte (any byte, as Core's `operator<<(opcodetype)`
    /// does; pushes of data go through `pushData`).
    pub fn pushOpcode(self: *ScriptBuilder, op: Opcode) BuildError!void {
        try self.room(1);
        try self.buf.append(self.allocator, @backingInt(op));
    }

    /// Appends the shortest push of `data` (see the module doc).
    pub fn pushData(self: *ScriptBuilder, data: []const u8) BuildError!void {
        const special: ?u8 = if (data.len == 0)
            0x00
        else if (data.len == 1 and data[0] >= 1 and data[0] <= 16)
            0x50 + data[0]
        else if (data.len == 1 and data[0] == 0x81)
            0x4f
        else
            null;
        if (special) |op| {
            try self.room(1);
            try self.buf.append(self.allocator, op);
            return;
        }
        // btcd's order: the script bound first, then the element bound.
        if (data.len > std.math.maxInt(u32)) return error.PushTooLarge;
        try self.room(pushLen(data.len));
        if (data.len > self.limits.max_element_size) return error.PushTooLarge;
        try self.buf.ensureUnusedCapacity(self.allocator, pushLen(data.len));
        const n = data.len;
        if (n < 0x4c) {
            self.buf.appendAssumeCapacity(@intCast(n));
        } else if (n <= 0xff) {
            self.buf.appendSliceAssumeCapacity(&.{ 0x4c, @intCast(n) });
        } else if (n <= 0xffff) {
            self.buf.appendAssumeCapacity(0x4d);
            self.buf.appendSliceAssumeCapacity(&std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(n))));
        } else {
            self.buf.appendAssumeCapacity(0x4e);
            self.buf.appendSliceAssumeCapacity(&std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(n))));
        }
        self.buf.appendSliceAssumeCapacity(data);
    }

    /// Appends `n` the way Core's `CScript::operator<<(int64_t)` does:
    /// `OP_0`, `OP_1NEGATE`, `OP_1..OP_16`, else the minimal `CScriptNum`
    /// bytes as a data push.
    pub fn pushInt(self: *ScriptBuilder, n: i64) BuildError!void {
        if (n == 0 or n == -1 or (n >= 1 and n <= 16)) {
            try self.room(1);
            const op: u8 = if (n == 0) 0x00 else if (n == -1) 0x4f else @intCast(0x50 + n);
            try self.buf.append(self.allocator, op);
            return;
        }
        var tmp: [9]u8 = undefined;
        try self.pushData(number.encode(n, &tmp));
    }
};

// ── disassembler ────────────────────────────────────────────────────────

/// Bitcoin Core's `GetOpName`: `0`, `-1`, `1..16` for the small-number
/// opcodes, `OP_<NAME>` otherwise (`OP_CHECKLOCKTIMEVERIFY` /
/// `OP_CHECKSEQUENCEVERIFY` for NOP2/NOP3), `OP_UNKNOWN` for an undefined byte
/// (`0x01..0x4b`, `0xbb..0xfe`).
pub fn opcodeName(op: u8) []const u8 {
    if (op == 0x00) return "0";
    if (op == 0x4f) return "-1";
    if (op >= 0x51 and op <= 0x60) {
        const names = comptime blk: {
            var t: [16][]const u8 = undefined;
            for (&t, 1..) |*e, i| e.* = std.fmt.comptimePrint("{d}", .{i});
            break :blk t;
        };
        return names[op - 0x51];
    }
    return std.enums.tagName(Opcode, @fromBackingInt(@intCast(op))) orelse "OP_UNKNOWN";
}

pub const AsmOptions = struct {
    /// Core's `fAttemptSighashDecode`: a data push of more than 4 bytes that is
    /// a strictly DER-encoded signature with a defined sighash type is shown as
    /// `<hex of the DER part>[ALL]` (`NONE`, `SINGLE`, each also with
    /// `|ANYONECANPAY`). Not applied to a script that starts with `OP_RETURN`
    /// or is longer than `limits.max_script_size` (data, not signatures).
    sighash_decode: bool = false,
};

fn sighashName(t: u8) ?[]const u8 {
    return switch (t) {
        0x01 => "ALL",
        0x02 => "NONE",
        0x03 => "SINGLE",
        0x81 => "ALL|ANYONECANPAY",
        0x82 => "NONE|ANYONECANPAY",
        0x83 => "SINGLE|ANYONECANPAY",
        else => null,
    };
}

/// Writes the Core-style asm text of `script` to `w`. A script that ends
/// inside a push (or has a truncated length prefix) is rendered up to that
/// point followed by `[error]`; the function itself never fails on content.
pub fn toAsm(script: []const u8, w: *Writer, opts: AsmOptions) Writer.Error!void {
    const decode_sig = opts.sighash_decode and !(script.len > 0 and script[0] == 0x6a) and script.len <= limits_mod.max_script_size;
    var pos: usize = 0;
    var first = true;
    while (pos < script.len) {
        if (!first) try w.writeAll(" ");
        first = false;
        const ins = interpreter.readInstruction(script, pos) catch {
            try w.writeAll("[error]");
            return;
        };
        pos = ins.next;
        const data = ins.data orelse {
            try w.writeAll(opcodeName(ins.opcode));
            continue;
        };
        if (data.len <= 4) {
            // A 4-byte CScriptNum always fits an i64 and cannot overflow.
            const v = number.decode(data, false, 4) catch unreachable;
            try w.print("{d}", .{v});
        } else if (decode_sig and sigcheck.isValidSignatureEncoding(data) and sigcheck.isDefinedHashtype(data[data.len - 1])) {
            try w.print("{x}[{s}]", .{ data[0 .. data.len - 1], sighashName(data[data.len - 1]).? });
        } else {
            try w.print("{x}", .{data});
        }
    }
}

/// `toAsm` into a freshly allocated string; the caller frees it.
pub fn toAsmAlloc(allocator: Allocator, script: []const u8, opts: AsmOptions) Allocator.Error![]u8 {
    var aw: Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    toAsm(script, &aw.writer, opts) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectBuilt(expected: []const u8, comptime f: anytype, arg: anytype) !void {
    var b = ScriptBuilder.init(testing.allocator);
    defer b.deinit();
    try f(&b, arg);
    try testing.expectEqualSlices(u8, expected, b.bytes());
}

test "pushInt: dedicated opcodes for 0, -1, 1..16, minimal CScriptNum data otherwise" {
    try expectBuilt(&.{0x00}, ScriptBuilder.pushInt, 0);
    try expectBuilt(&.{0x4f}, ScriptBuilder.pushInt, -1);
    try expectBuilt(&.{0x51}, ScriptBuilder.pushInt, 1);
    try expectBuilt(&.{0x60}, ScriptBuilder.pushInt, 16);
    try expectBuilt(&.{ 0x01, 0x11 }, ScriptBuilder.pushInt, 17);
    try expectBuilt(&.{ 0x01, 0x82 }, ScriptBuilder.pushInt, -2);
    try expectBuilt(&.{ 0x01, 0x7f }, ScriptBuilder.pushInt, 127);
    try expectBuilt(&.{ 0x02, 0x80, 0x00 }, ScriptBuilder.pushInt, 128);
    try expectBuilt(&.{ 0x02, 0x80, 0x80 }, ScriptBuilder.pushInt, -128);
    try expectBuilt(&.{ 0x02, 0x00, 0x01 }, ScriptBuilder.pushInt, 256);
    try expectBuilt(&.{ 0x04, 0xff, 0xff, 0xff, 0x7f }, ScriptBuilder.pushInt, 2147483647);
    try expectBuilt(&.{ 0x05, 0x00, 0x00, 0x00, 0x80, 0x00 }, ScriptBuilder.pushInt, 2147483648);
    try expectBuilt(&.{ 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, ScriptBuilder.pushInt, std.math.maxInt(i64));
    try expectBuilt(&.{ 0x09, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x80 }, ScriptBuilder.pushInt, std.math.minInt(i64));
}

test "pushData: the MINIMALDATA-minimal opcode at every length boundary" {
    try expectBuilt(&.{0x00}, ScriptBuilder.pushData, &[_]u8{});
    try expectBuilt(&.{ 0x01, 0x00 }, ScriptBuilder.pushData, &[_]u8{0x00}); // not OP_0: that pushes the empty string
    try expectBuilt(&.{0x51}, ScriptBuilder.pushData, &[_]u8{0x01});
    try expectBuilt(&.{0x60}, ScriptBuilder.pushData, &[_]u8{0x10});
    try expectBuilt(&.{ 0x01, 0x11 }, ScriptBuilder.pushData, &[_]u8{0x11});
    try expectBuilt(&.{0x4f}, ScriptBuilder.pushData, &[_]u8{0x81});
    try expectBuilt(&.{ 0x01, 0x80 }, ScriptBuilder.pushData, &[_]u8{0x80});
    try expectBuilt(&.{ 0x02, 0x01, 0x01 }, ScriptBuilder.pushData, &[_]u8{ 0x01, 0x01 });

    const lens = [_]usize{ 75, 76, 255, 256, 520 };
    const heads = [_][]const u8{ &.{0x4b}, &.{ 0x4c, 76 }, &.{ 0x4c, 0xff }, &.{ 0x4d, 0x00, 0x01 }, &.{ 0x4d, 0x08, 0x02 } };
    for (lens, heads) |n, head| {
        const data = try testing.allocator.alloc(u8, n);
        defer testing.allocator.free(data);
        @memset(data, 0xab);
        var b = ScriptBuilder.init(testing.allocator);
        defer b.deinit();
        try b.pushData(data);
        try testing.expectEqualSlices(u8, head, b.bytes()[0..head.len]);
        try testing.expectEqual(head.len + n, b.bytes().len);
        try testing.expectEqualSlices(u8, data, b.bytes()[head.len..]);
    }
}

test "pushData: OP_PUSHDATA4 above 65535 bytes needs raised limits" {
    const n = 70_000;
    const data = try testing.allocator.alloc(u8, n);
    defer testing.allocator.free(data);
    @memset(data, 0x07);
    var b = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = 100_000, .max_element_size = 100_000 });
    defer b.deinit();
    try b.pushData(data);
    try testing.expectEqualSlices(u8, &.{ 0x4e, 0x70, 0x11, 0x01, 0x00 }, b.bytes()[0..5]);
    try testing.expectEqual(@as(usize, 5 + n), b.bytes().len);
}

test "pushData: the 2-byte / 4-byte length boundary and the 32-bit length ceiling" {
    const big_limits: Limits = .{ .max_script_size = 200_000, .max_element_size = 200_000 };
    const data = try testing.allocator.alloc(u8, 65_536);
    defer testing.allocator.free(data);
    @memset(data, 0x33);
    var b = ScriptBuilder.initWithLimits(testing.allocator, big_limits);
    defer b.deinit();
    try b.pushData(data[0..65_535]);
    try testing.expectEqualSlices(u8, &.{ 0x4d, 0xff, 0xff }, b.bytes()[0..3]);
    try testing.expectEqual(@as(usize, 3 + 65_535), b.bytes().len);
    b.reset();
    try b.pushData(data);
    try testing.expectEqualSlices(u8, &.{ 0x4e, 0x00, 0x00, 0x01, 0x00 }, b.bytes()[0..5]);
    try testing.expectEqual(@as(usize, 5 + 65_536), b.bytes().len);

    // A length that does not fit OP_PUSHDATA4's u32 is refused before any
    // allocation; the slice is never read (its pointer is not backed).
    var f = ScriptBuilder.initWithLimits(testing.failing_allocator, .{ .max_script_size = std.math.maxInt(usize), .max_element_size = std.math.maxInt(usize) });
    defer f.deinit();
    const unbacked: [*]const u8 = @ptrFromInt(0x1000);
    try testing.expectError(error.PushTooLarge, f.pushData(unbacked[0 .. @as(usize, std.math.maxInt(u32)) + 1]));
    try testing.expectError(error.OutOfMemory, f.pushData(unbacked[0..std.math.maxInt(u32)]));
}

test "pushData: a push that exactly fills max_script_size fits at every length class, one byte less refuses" {
    const data = try testing.allocator.alloc(u8, 65_536);
    defer testing.allocator.free(data);
    @memset(data, 0x44);
    const lens = [_]usize{ 2, 75, 76, 255, 256, 65_535, 65_536 };
    for (lens) |n| {
        const total = pushLen(n);
        var fit = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = total, .max_element_size = 70_000 });
        defer fit.deinit();
        try fit.pushData(data[0..n]);
        try testing.expectEqual(total, fit.bytes().len);
        // the expected sizes, independent of pushLen
        const want: usize = switch (n) {
            2, 75 => 1 + n,
            76, 255 => 2 + n,
            65_535, 256 => 3 + n,
            else => 5 + n,
        };
        try testing.expectEqual(want, total);
        var tight = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = total - 1, .max_element_size = 70_000 });
        defer tight.deinit();
        try testing.expectError(error.ScriptTooLarge, tight.pushData(data[0..n]));
        try testing.expectEqual(@as(usize, 0), tight.bytes().len);
    }
}

test "builder limits: 520-byte element and 10 000-byte script, refusal leaves the script unchanged" {
    const big: [521]u8 = @splat(0x42);
    var b = ScriptBuilder.init(testing.allocator);
    defer b.deinit();
    try b.pushOpcode(.OP_DUP);
    try testing.expectError(error.PushTooLarge, b.pushData(&big));
    try testing.expectEqualSlices(u8, &.{0x76}, b.bytes());
    try b.pushData(big[0..520]);
    try testing.expectEqual(@as(usize, 1 + 3 + 520), b.bytes().len);

    b.reset();
    try testing.expectEqual(@as(usize, 0), b.bytes().len);
    var i: usize = 0;
    while (i < 10_000) : (i += 1) try b.pushOpcode(.OP_NOP);
    try testing.expectError(error.ScriptTooLarge, b.pushOpcode(.OP_NOP));
    try testing.expectError(error.ScriptTooLarge, b.pushInt(5));
    try testing.expectError(error.ScriptTooLarge, b.pushData(&.{}));
    try testing.expectEqual(@as(usize, 10_000), b.bytes().len);

    // a multi-byte push that would cross the bound is refused as a whole
    b.reset();
    i = 0;
    while (i < 9_999) : (i += 1) try b.pushOpcode(.OP_NOP);
    try testing.expectError(error.ScriptTooLarge, b.pushData(&.{ 0x01, 0x01 }));
    try testing.expectError(error.ScriptTooLarge, b.pushInt(1000));
    try testing.expectEqual(@as(usize, 9_999), b.bytes().len);
    try b.pushInt(7); // exactly one byte left
    try testing.expectEqual(@as(usize, 10_000), b.bytes().len);

    // raised limits
    var c = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = 5, .max_element_size = 2 });
    defer c.deinit();
    try c.pushData(&.{ 0xaa, 0xbb });
    try testing.expectError(error.ScriptTooLarge, c.pushData(&.{ 0xaa, 0xbb })); // 3 + 3 > 5
    try c.pushOpcode(.OP_NOP);
    try c.pushOpcode(.OP_NOP);
    try testing.expectError(error.ScriptTooLarge, c.pushOpcode(.OP_NOP));

    var d = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = 100, .max_element_size = 2 });
    defer d.deinit();
    try d.pushData(&.{ 0xaa, 0xbb });
    try testing.expectError(error.PushTooLarge, d.pushData(&.{ 1, 2, 3 }));
    try testing.expectEqual(@as(usize, 3), d.bytes().len);
}

test "toOwnedSlice hands the script over and empties the builder" {
    var b = ScriptBuilder.init(testing.allocator);
    defer b.deinit();
    try b.pushOpcode(.OP_DUP);
    try b.pushOpcode(.OP_HASH160);
    const owned = try b.toOwnedSlice();
    defer testing.allocator.free(owned);
    try testing.expectEqualSlices(u8, &.{ 0x76, 0xa9 }, owned);
    try testing.expectEqual(@as(usize, 0), b.bytes().len);
    try b.pushOpcode(.OP_CHECKSIG);
    try testing.expectEqualSlices(u8, &.{0xac}, b.bytes());
}

fn expectAsm(expected: []const u8, script: []const u8) !void {
    const got = try toAsmAlloc(testing.allocator, script, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "toAsm: a P2PKH script and the standard multisig shape" {
    var b = ScriptBuilder.init(testing.allocator);
    defer b.deinit();
    try b.pushOpcode(.OP_DUP);
    try b.pushOpcode(.OP_HASH160);
    try b.pushData(&[_]u8{ 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba });
    try b.pushOpcode(.OP_EQUALVERIFY);
    try b.pushOpcode(.OP_CHECKSIG);
    try expectAsm("OP_DUP OP_HASH160 89abcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUALVERIFY OP_CHECKSIG", b.bytes());

    try expectAsm("", &.{});
    try expectAsm("OP_DUP", &.{0x76});
    try expectAsm("1 2 OP_CHECKMULTISIG", &.{ 0x51, 0x52, 0xae });
}

test "toAsm: small-number opcodes and pushes of up to 4 bytes read as decimal numbers" {
    try expectAsm("0 -1 1 16", &.{ 0x00, 0x4f, 0x51, 0x60 });
    try expectAsm("5", &.{ 0x01, 0x05 }); // non-minimal form: same text as OP_5
    try expectAsm("-1", &.{ 0x01, 0x81 });
    try expectAsm("0", &.{ 0x01, 0x00 });
    try expectAsm("0", &.{ 0x01, 0x80 }); // negative zero
    try expectAsm("0", &.{ 0x4c, 0x00 }); // empty PUSHDATA1
    try expectAsm("128", &.{ 0x02, 0x80, 0x00 });
    try expectAsm("-128", &.{ 0x02, 0x80, 0x80 });
    try expectAsm("2147483647", &.{ 0x04, 0xff, 0xff, 0xff, 0x7f });
    try expectAsm("-2147483647", &.{ 0x04, 0xff, 0xff, 0xff, 0xff });
    try expectAsm("0", &.{ 0x04, 0x00, 0x00, 0x00, 0x00 }); // non-minimal zero
    try expectAsm("0102030405", &.{ 0x05, 1, 2, 3, 4, 5 }); // 5 bytes: hex, not a number
    try expectAsm("0102030405", &.{ 0x4c, 0x05, 1, 2, 3, 4, 5 });
    try expectAsm("00000000ff", &.{ 0x4d, 0x05, 0x00, 0, 0, 0, 0, 0xff });
}

test "toAsm: opcode names follow Core's GetOpName" {
    try expectAsm("OP_RESERVED", &.{0x50});
    try expectAsm("OP_VER OP_IF OP_NOTIF OP_VERIF OP_VERNOTIF OP_ELSE OP_ENDIF", &.{ 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 });
    try expectAsm("OP_NOP1 OP_CHECKLOCKTIMEVERIFY OP_CHECKSEQUENCEVERIFY OP_NOP4 OP_NOP10", &.{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb9 });
    try expectAsm("OP_CHECKSIGADD OP_UNKNOWN OP_UNKNOWN OP_INVALIDOPCODE", &.{ 0xba, 0xbb, 0xfe, 0xff });
    try expectAsm("OP_CAT OP_2MUL OP_RSHIFT", &.{ 0x7e, 0x8d, 0x99 });
}

test "toAsm: a script that ends inside a push renders [error] like Core" {
    try expectAsm("[error]", &.{0x4c});
    try expectAsm("[error]", &.{ 0x4d, 0x01 });
    try expectAsm("[error]", &.{ 0x4e, 0x01, 0x00, 0x00 });
    try expectAsm("[error]", &.{0x01});
    try expectAsm("[error]", &.{ 0x4b, 1, 2, 3 });
    try expectAsm("[error]", &.{ 0x4c, 0x02, 0x01 });
    try expectAsm("[error]", &.{ 0x4e, 0xff, 0xff, 0xff, 0xff, 0x01 }); // 4 GiB length, 1 byte present
    try expectAsm("OP_DUP 1 [error]", &.{ 0x76, 0x51, 0x4c });
    try expectAsm("OP_DUP 7 [error]", &.{ 0x76, 0x01, 0x07, 0x02, 0x01 });
}

fn derSig(hashtype: u8) [9]u8 {
    return .{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, hashtype };
}

test "toAsm: sighash_decode names the defined sighash types of strict DER signatures only" {
    const names = [_]struct { t: u8, n: []const u8 }{
        .{ .t = 0x01, .n = "ALL" },
        .{ .t = 0x02, .n = "NONE" },
        .{ .t = 0x03, .n = "SINGLE" },
        .{ .t = 0x81, .n = "ALL|ANYONECANPAY" },
        .{ .t = 0x82, .n = "NONE|ANYONECANPAY" },
        .{ .t = 0x83, .n = "SINGLE|ANYONECANPAY" },
    };
    for (names) |c| {
        var script: [10]u8 = undefined;
        script[0] = 9;
        script[1..].* = derSig(c.t);
        const got = try toAsmAlloc(testing.allocator, &script, .{ .sighash_decode = true });
        defer testing.allocator.free(got);
        // the DER part is 8 bytes (16 hex digits), then "[" name "]"
        try testing.expect(std.mem.startsWith(u8, got, "3006020101020101["));
        try testing.expectEqualStrings(c.n, got[17 .. got.len - 1]);
        try testing.expectEqual(@as(usize, 16 + 1 + c.n.len + 1), got.len);
        // off by default: the full hex including the hashtype byte
        const plain = try toAsmAlloc(testing.allocator, &script, .{});
        defer testing.allocator.free(plain);
        try testing.expectEqual(@as(usize, 18), plain.len);
        try testing.expect(std.mem.startsWith(u8, plain, "3006020101020101"));
    }
    // undefined hashtypes, a non-DER blob, and data after OP_RETURN stay hex
    for ([_]u8{ 0x00, 0x04, 0x80, 0x84, 0x05 }) |t| {
        var script: [10]u8 = undefined;
        script[0] = 9;
        script[1..].* = derSig(t);
        const got = try toAsmAlloc(testing.allocator, &script, .{ .sighash_decode = true });
        defer testing.allocator.free(got);
        try testing.expectEqual(@as(usize, 18), got.len);
    }
    var blob = [_]u8{ 9, 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try testing.expectEqual(@as(usize, 18), (try decodedLen(&blob)));
    var ret: [11]u8 = undefined;
    ret[0] = 0x6a;
    ret[1] = 9;
    ret[2..].* = derSig(0x01);
    const got = try toAsmAlloc(testing.allocator, &ret, .{ .sighash_decode = true });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("OP_RETURN 300602010102010101", got);
}

test "toAsm: sighash_decode on an empty script, and the 10 000-byte script bound" {
    try testing.expectEqual(@as(usize, 0), try decodedLen(&.{}));
    var b = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = 10_001 });
    defer b.deinit();
    while (b.bytes().len < 10_000 - 10) try b.pushOpcode(.OP_NOP);
    try b.pushData(&derSig(0x01));
    try testing.expectEqual(@as(usize, 10_000), b.bytes().len);
    const at_bound = try toAsmAlloc(testing.allocator, b.bytes(), .{ .sighash_decode = true });
    defer testing.allocator.free(at_bound);
    try testing.expect(std.mem.endsWith(u8, at_bound, "3006020101020101[ALL]"));
    // one byte longer: Core's IsUnspendable (size > MAX_SCRIPT_SIZE) switches the decode off
    var c = ScriptBuilder.initWithLimits(testing.allocator, .{ .max_script_size = 10_001 });
    defer c.deinit();
    try c.pushOpcode(.OP_NOP);
    while (c.bytes().len < 10_001 - 10) try c.pushOpcode(.OP_NOP);
    try c.pushData(&derSig(0x01));
    try testing.expectEqual(@as(usize, 10_001), c.bytes().len);
    const over = try toAsmAlloc(testing.allocator, c.bytes(), .{ .sighash_decode = true });
    defer testing.allocator.free(over);
    try testing.expect(std.mem.endsWith(u8, over, "300602010102010101"));
}

fn decodedLen(script: []const u8) !usize {
    const got = try toAsmAlloc(testing.allocator, script, .{ .sighash_decode = true });
    defer testing.allocator.free(got);
    return got.len;
}

test "opcodeName covers every byte without allocating" {
    try testing.expectEqualStrings("0", opcodeName(0x00));
    try testing.expectEqualStrings("OP_UNKNOWN", opcodeName(0x01));
    try testing.expectEqualStrings("OP_UNKNOWN", opcodeName(0x4b));
    try testing.expectEqualStrings("OP_PUSHDATA1", opcodeName(0x4c));
    try testing.expectEqualStrings("OP_PUSHDATA4", opcodeName(0x4e));
    try testing.expectEqualStrings("-1", opcodeName(0x4f));
    try testing.expectEqualStrings("1", opcodeName(0x51));
    try testing.expectEqualStrings("9", opcodeName(0x59));
    try testing.expectEqualStrings("10", opcodeName(0x5a));
    try testing.expectEqualStrings("16", opcodeName(0x60));
    try testing.expectEqualStrings("OP_NOP", opcodeName(0x61));
    var n: usize = 0;
    for (0..256) |op| {
        if (opcodeName(@intCast(op)).len > 0) n += 1;
    }
    try testing.expectEqual(@as(usize, 256), n);
}
