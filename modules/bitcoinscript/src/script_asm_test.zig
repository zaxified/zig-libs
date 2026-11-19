// SPDX-License-Identifier: MIT
//! Round trip `ScriptBuilder` -> `toAsm` -> `asmparser.assemble`, and `toAsm`
//! over every script of the pinned `script_tests.json` subset.
//!
//! Core's asm text is not injective (see `script.zig`), so the exact byte
//! round trip is asserted only for scripts whose pushes are the canonical
//! ones; for every other well-formed script the weaker fixed point
//! `toAsm(assemble(toAsm(s))) == toAsm(s)` is asserted. The parser's grammar
//! has no bare-hex data token (Core's output prints data without a prefix), so
//! the test turns a data token of 5 or more bytes into the parser's raw `0x`
//! form with its own push prefix (it knows which tokens those are from the
//! bytes, since a 5-byte push of decimal-looking hex reads like a number).

const std = @import("std");
const testing = std.testing;
const asmparser = @import("asmparser.zig");
const interpreter = @import("interpreter.zig");
const number = @import("number.zig");
const script = @import("script.zig");
const vectors_mod = @import("script_tests_vectors.zig");

/// Turns Core-style asm into the parser's grammar. Tokens and instructions
/// correspond one to one, so the data pushes of 5 or more bytes (which the asm
/// text shows as bare hex, indistinguishable from a 10-digit number) are known
/// from the bytes.
fn toParserText(allocator: std.mem.Allocator, bytes: []const u8, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    var pos: usize = 0;
    while (it.next()) |tok| {
        const ins = try interpreter.readInstruction(bytes, pos);
        pos = ins.next;
        if (out.items.len > 0) try out.append(allocator, ' ');
        if (ins.data) |d| if (d.len >= 5) {
            const n = d.len;
            if (n <= 0x4b) {
                try out.print(allocator, "0x{x:0>2}", .{n});
            } else if (n <= 0xff) {
                try out.print(allocator, "0x4c{x:0>2}", .{n});
            } else {
                try out.print(allocator, "0x4d{x:0>2}{x:0>2}", .{ n & 0xff, n >> 8 });
            }
            try out.appendSlice(allocator, " 0x");
        };
        try out.appendSlice(allocator, tok);
    }
    try testing.expectEqual(bytes.len, pos);
    return try out.toOwnedSlice(allocator);
}

/// True when every instruction of `bytes` is the one the asm text would be
/// re-assembled to (see the module doc).
fn isCanonical(bytes: []const u8) bool {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const ins = interpreter.readInstruction(bytes, pos) catch return false;
        pos = ins.next;
        if (ins.data) |d| {
            if (d.len == 0) {
                if (ins.opcode != 0x00) return false;
            } else if (d.len <= 4) {
                if (ins.opcode != d.len) return false;
                const v = number.decode(d, true, 4) catch return false;
                if (v >= -1 and v <= 16) return false;
            } else {
                const minimal: u8 = if (d.len <= 0x4b) @intCast(d.len) else if (d.len <= 0xff) 0x4c else if (d.len <= 0xffff) 0x4d else 0x4e;
                if (ins.opcode != minimal) return false;
            }
        } else if (ins.opcode >= 0xbb and ins.opcode <= 0xfe) {
            return false; // OP_UNKNOWN has no mnemonic in the parser
        }
    }
    return true;
}

const Counts = struct { exact: usize = 0, fixed_point: usize = 0, errors: usize = 0, skipped: usize = 0 };

fn checkOne(allocator: std.mem.Allocator, bytes: []const u8, counts: *Counts) !void {
    const text = try script.toAsmAlloc(allocator, bytes, .{});
    defer allocator.free(text);
    if (std.mem.endsWith(u8, text, "[error]")) {
        // the same malformation `readInstruction` reports on the way
        var pos: usize = 0;
        while (pos < bytes.len) {
            const ins = interpreter.readInstruction(bytes, pos) catch break;
            pos = ins.next;
        } else return error.ErrorMarkerWithoutMalformation;
        counts.errors += 1;
        return;
    }
    const parser_text = try toParserText(allocator, bytes, text);
    defer allocator.free(parser_text);
    const back = asmparser.assemble(allocator, parser_text) catch |e| switch (e) {
        error.UnknownMnemonic => {
            // only OP_UNKNOWN (an undefined byte) has no mnemonic
            try testing.expect(std.mem.find(u8, text, "OP_UNKNOWN") != null);
            counts.skipped += 1;
            return;
        },
        else => return e,
    };
    defer allocator.free(back);
    if (isCanonical(bytes)) {
        try testing.expectEqualSlices(u8, bytes, back);
        counts.exact += 1;
    }
    const text2 = try script.toAsmAlloc(allocator, back, .{});
    defer allocator.free(text2);
    try testing.expectEqualStrings(text, text2);
    counts.fixed_point += 1;
}

test "toAsm over the pinned script_tests.json rows: canonical scripts round trip, all others reach a fixed point" {
    const allocator = testing.allocator;
    var counts: Counts = .{};
    for (vectors_mod.vectors) |v| {
        for ([_][]const u8{ v.script_sig, v.script_pubkey }) |src| {
            const bytes = try asmparser.assemble(allocator, src);
            defer allocator.free(bytes);
            try checkOne(allocator, bytes, &counts);
            // cut the script short: either still well formed or an [error]
            var cut: usize = 1;
            while (cut <= 3 and cut < bytes.len) : (cut += 1) try checkOne(allocator, bytes[0 .. bytes.len - cut], &counts);
        }
    }
    // the corpus has hundreds of scripts of each kind; a collapse to a few means the check stopped running
    if (counts.exact <= 300 or counts.fixed_point <= 500 or counts.errors <= 5 or counts.skipped >= 200) {
        std.debug.print("counts: {any}\n", .{counts});
        return error.TestUnexpectedResult;
    }
}

test "ScriptBuilder -> toAsm -> assemble reproduces the builder's bytes" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xb17c0ffe);
    const rnd = prng.random();
    var round: usize = 0;
    var counts: Counts = .{};
    while (round < 400) : (round += 1) {
        var b = script.ScriptBuilder.init(allocator);
        defer b.deinit();
        const n_items = rnd.intRangeAtMost(usize, 1, 12);
        for (0..n_items) |_| {
            switch (rnd.uintLessThan(u8, 3)) {
                0 => try b.pushOpcode(@fromBackingInt(@intCast(rnd.intRangeAtMost(u8, 0x61, 0xba)))),
                1 => {
                    const kind = rnd.uintLessThan(u8, 3);
                    const v: i64 = switch (kind) {
                        0 => rnd.intRangeAtMost(i64, -20, 20),
                        1 => rnd.intRangeAtMost(i64, -70_000, 70_000),
                        else => rnd.intRangeAtMost(i64, -99_999_999, 99_999_999), // <= 9 digits: a 10-digit number reads like 5 bytes of hex
                    };
                    try b.pushInt(v);
                },
                else => {
                    // 5..520 random bytes (at the length boundaries too)
                    const len = switch (rnd.uintLessThan(u8, 4)) {
                        0 => rnd.intRangeAtMost(usize, 5, 80),
                        1 => rnd.intRangeAtMost(usize, 250, 260),
                        else => rnd.intRangeAtMost(usize, 5, 520),
                    };
                    var data: [520]u8 = undefined;
                    rnd.bytes(data[0..len]);
                    try b.pushData(data[0..len]);
                },
            }
        }
        try checkOne(allocator, b.bytes(), &counts);
    }
    // every generated script is canonical, so none may be skipped or reduced to the weak check
    try testing.expectEqual(@as(usize, 400), counts.exact + counts.skipped);
    try testing.expect(counts.skipped < 5);
}

test "builder data pushes equal the parser's quoted-string pushes at every length" {
    const allocator = testing.allocator;
    var len: usize = 5;
    while (len <= 520) : (len += if (len < 80) 1 else 37) {
        const data = try allocator.alloc(u8, len);
        defer allocator.free(data);
        for (data, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
        var b = script.ScriptBuilder.init(allocator);
        defer b.deinit();
        try b.pushData(data);
        const text = try std.fmt.allocPrint(allocator, "'{s}'", .{data});
        defer allocator.free(text);
        const want = try asmparser.assemble(allocator, text);
        defer allocator.free(want);
        try testing.expectEqualSlices(u8, want, b.bytes());
    }
}

test "builder pushInt equals the parser's decimal tokens" {
    const allocator = testing.allocator;
    const values = [_]i64{ 0, -1, 1, 2, 15, 16, 17, -2, 127, 128, -127, -128, 255, 256, 32767, 32768, 65535, 8388607, 8388608, 2147483647, -2147483647, 2147483648, 4294967296 };
    for (values) |v| {
        var b = script.ScriptBuilder.init(allocator);
        defer b.deinit();
        try b.pushInt(v);
        const text = try std.fmt.allocPrint(allocator, "{d}", .{v});
        defer allocator.free(text);
        const want = try asmparser.assemble(allocator, text);
        defer allocator.free(want);
        try testing.expectEqualSlices(u8, want, b.bytes());
    }
}
