// SPDX-License-Identifier: MIT

//! The conventional STEP 7 address notation — `DB1.DBW20`, `M10.2`, `I0.0`,
//! `QB4`, `T5`, `C3`, `PIW256` — parsed into an `items.Item`.
//!
//! Every S7 tool in existence takes addresses in this notation, so a library
//! that only takes `(area, db, byte, bit)` tuples pushes a string parser into
//! every consumer. It is also where the bit/byte confusion of `items.zig`
//! becomes visible to a human: `DB1.DBX0.3` is byte 0 bit 3 is wire address 3,
//! while `DB1.DBB3` is byte 3 is wire address 24.
//!
//! Grammar (case-insensitive; both English and German mnemonics):
//!
//! ```text
//!   DB<n>.DBX<byte>.<bit>     bit in a data block
//!   DB<n>.DBB<byte>           byte   DB<n>.DBW<byte>   word
//!   DB<n>.DBD<byte>           dword
//!   M<byte>.<bit> | MB | MW | MD          bit memory (flags / merker)
//!   I<byte>.<bit> | IB | IW | ID          inputs   (E / EB / EW / ED)
//!   Q<byte>.<bit> | QB | QW | QD          outputs  (A / AB / AW / AD)
//!   PIB | PIW | PID | PEB | PEW | PED     peripheral inputs
//!   PQB | PQW | PQD | PAB | PAW | PAD     peripheral outputs
//!   T<n>                                  timer
//!   C<n> | Z<n>                           counter
//! ```
//!
//! A `.<bit>` suffix is only legal where a bit can be addressed, and only for
//! bits 0..7 — `M10.8` is not "byte 11 bit 0", it is a typo, and this parser
//! says so rather than silently normalising it.

const std = @import("std");
const items = @import("items.zig");

pub const Error = error{
    /// The string is empty or ends where a number was expected.
    Empty,
    /// The area mnemonic is not one of the known ones.
    UnknownArea,
    /// A number is missing, malformed or does not fit.
    BadNumber,
    /// A bit index above 7, or a bit suffix where none is allowed.
    BadBitIndex,
    /// A data block number of 0, or above 65535.
    BadDbNumber,
    /// Trailing characters after a complete address.
    TrailingCharacters,
    /// A count of zero, or one that overflows the wire field.
    BadCount,
} || items.Error;

/// A parsed address: everything needed to build an `items.Item`, kept apart
/// from it so the human-facing byte/bit form survives.
pub const Address = struct {
    area: items.Area,
    db_number: u16 = 0,
    byte_offset: u32 = 0,
    bit: u3 = 0,
    transport_size: items.TransportSize,

    /// Builds a request item for `count` consecutive elements.
    pub fn item(self: Address, count: u16) Error!items.Item {
        if (count == 0) return error.BadCount;
        return items.Item.at(self.area, self.db_number, self.byte_offset, self.bit, self.transport_size, count);
    }

    /// Octets one element occupies.
    pub fn elementBytes(self: Address) u16 {
        return self.transport_size.elementBytes() orelse 1;
    }
};

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Reads a decimal number, returning it and the rest of the string.
fn number(s: []const u8) Error!struct { value: u32, rest: []const u8 } {
    var i: usize = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {}
    if (i == 0) return error.BadNumber;
    // A leading run of digits longer than 8 cannot fit any field here.
    if (i > 8) return error.BadNumber;
    const v = std.fmt.parseInt(u32, s[0..i], 10) catch return error.BadNumber;
    return .{ .value = v, .rest = s[i..] };
}

/// Parses an optional `.<bit>` suffix. Returns 0 when absent.
fn bitSuffix(s: []const u8) Error!struct { bit: u3, rest: []const u8 } {
    if (s.len == 0 or s[0] != '.') return .{ .bit = 0, .rest = s };
    const n = try number(s[1..]);
    if (n.value > 7) return error.BadBitIndex;
    return .{ .bit = @intCast(n.value), .rest = n.rest };
}

/// Parses one STEP 7 address.
pub fn parse(text: []const u8) Error!Address {
    const s = std.mem.trim(u8, text, " \t");
    if (s.len == 0) return error.Empty;

    // ── data blocks: DB<n>.DB{X,B,W,D}<byte>[.<bit>] ────────────────────────
    if (s.len >= 2 and eqIgnoreCase(s[0..2], "DB")) {
        const n = try number(s[2..]);
        if (n.value == 0 or n.value > 0xFFFF) return error.BadDbNumber;
        const db_number: u16 = @intCast(n.value);
        var rest = n.rest;
        if (rest.len < 4 or rest[0] != '.') return error.UnknownArea;
        rest = rest[1..];
        if (!eqIgnoreCase(rest[0..2], "DB")) return error.UnknownArea;
        const kind = rest[2];
        const off = try number(rest[3..]);
        const ts: items.TransportSize = switch (std.ascii.toUpper(kind)) {
            'X' => .bit,
            'B' => .byte,
            'W' => .word,
            'D' => .dword,
            else => return error.UnknownArea,
        };
        const b = try bitSuffix(off.rest);
        if (b.rest.len != 0) return error.TrailingCharacters;
        if (ts != .bit and b.bit != 0) return error.BadBitIndex;
        // `DB1.DBX0` without a bit is ambiguous; require the bit.
        if (ts == .bit and !std.mem.startsWith(u8, off.rest, ".")) return error.BadBitIndex;
        return .{
            .area = .db,
            .db_number = db_number,
            .byte_offset = off.value,
            .bit = b.bit,
            .transport_size = ts,
        };
    }

    // ── peripheral: P{I,E,Q,A}{B,W,D}<n> ────────────────────────────────────
    if (s.len >= 3 and (s[0] == 'P' or s[0] == 'p')) {
        const dir = std.ascii.toUpper(s[1]);
        const width = std.ascii.toUpper(s[2]);
        const area: ?items.Area = switch (dir) {
            'I', 'E' => .inputs,
            'Q', 'A' => .outputs,
            else => null,
        };
        if (area) |a| {
            const ts: ?items.TransportSize = switch (width) {
                'B' => .byte,
                'W' => .word,
                'D' => .dword,
                else => null,
            };
            if (ts) |t| {
                const off = try number(s[3..]);
                if (off.rest.len != 0) return error.TrailingCharacters;
                return .{ .area = a, .byte_offset = off.value, .transport_size = t };
            }
        }
    }

    // ── timers and counters ─────────────────────────────────────────────────
    switch (std.ascii.toUpper(s[0])) {
        'T' => {
            const n = try number(s[1..]);
            if (n.rest.len != 0) return error.TrailingCharacters;
            return .{ .area = .timer, .byte_offset = n.value, .transport_size = .timer };
        },
        'C', 'Z' => {
            const n = try number(s[1..]);
            if (n.rest.len != 0) return error.TrailingCharacters;
            return .{ .area = .counter, .byte_offset = n.value, .transport_size = .counter };
        },
        else => {},
    }

    // ── bit memory and the process image: {M,I,E,Q,A}[B|W|D]<n>[.<bit>] ─────
    const area: items.Area = switch (std.ascii.toUpper(s[0])) {
        'M' => .flags,
        'I', 'E' => .inputs,
        'Q', 'A' => .outputs,
        else => return error.UnknownArea,
    };
    var rest = s[1..];
    var ts: items.TransportSize = .bit;
    if (rest.len > 0) {
        switch (std.ascii.toUpper(rest[0])) {
            'B' => {
                ts = .byte;
                rest = rest[1..];
            },
            'W' => {
                ts = .word;
                rest = rest[1..];
            },
            'D' => {
                ts = .dword;
                rest = rest[1..];
            },
            else => {},
        }
    }
    const off = try number(rest);
    const b = try bitSuffix(off.rest);
    if (b.rest.len != 0) return error.TrailingCharacters;
    if (ts != .bit and b.bit != 0) return error.BadBitIndex;
    if (ts == .bit and !std.mem.startsWith(u8, off.rest, ".")) return error.BadBitIndex;
    return .{ .area = area, .byte_offset = off.value, .bit = b.bit, .transport_size = ts };
}

/// Parses an address and immediately turns it into a request item.
pub fn parseItem(text: []const u8, count: u16) Error!items.Item {
    return (try parse(text)).item(count);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "data block addresses" {
    const w = try parse("DB1.DBW20");
    try testing.expectEqual(items.Area.db, w.area);
    try testing.expectEqual(@as(u16, 1), w.db_number);
    try testing.expectEqual(@as(u32, 20), w.byte_offset);
    try testing.expectEqual(items.TransportSize.word, w.transport_size);
    // ... and the wire address is the bit address.
    try testing.expectEqual(@as(u24, 160), (try w.item(1)).address);

    const b = try parse("DB12.DBB100");
    try testing.expectEqual(@as(u16, 12), b.db_number);
    try testing.expectEqual(items.TransportSize.byte, b.transport_size);
    try testing.expectEqual(@as(u24, 800), (try b.item(1)).address);

    const d = try parse("DB2.DBD8");
    try testing.expectEqual(items.TransportSize.dword, d.transport_size);

    const x = try parse("DB1.DBX0.3");
    try testing.expectEqual(items.TransportSize.bit, x.transport_size);
    try testing.expectEqual(@as(u3, 3), x.bit);
    try testing.expectEqual(@as(u24, 3), (try x.item(1)).address);

    // Case does not matter.
    try testing.expectEqual(@as(u16, 5), (try parse("db5.dbw2")).db_number);
    // Surrounding whitespace is trimmed.
    try testing.expectEqual(@as(u16, 5), (try parse("  DB5.DBW2 ")).db_number);
}

test "bit memory, inputs and outputs" {
    const m = try parse("M10.2");
    try testing.expectEqual(items.Area.flags, m.area);
    try testing.expectEqual(@as(u32, 10), m.byte_offset);
    try testing.expectEqual(@as(u3, 2), m.bit);
    try testing.expectEqual(@as(u24, 82), (try m.item(1)).address);

    try testing.expectEqual(items.TransportSize.byte, (try parse("MB10")).transport_size);
    try testing.expectEqual(items.TransportSize.word, (try parse("MW10")).transport_size);
    try testing.expectEqual(items.TransportSize.dword, (try parse("MD10")).transport_size);

    const i = try parse("I0.0");
    try testing.expectEqual(items.Area.inputs, i.area);
    try testing.expectEqual(@as(u24, 0), (try i.item(1)).address);
    // The German mnemonic for the same area.
    try testing.expectEqual(items.Area.inputs, (try parse("E0.7")).area);
    try testing.expectEqual(@as(u3, 7), (try parse("E0.7")).bit);

    const q = try parse("Q1.5");
    try testing.expectEqual(items.Area.outputs, q.area);
    try testing.expectEqual(@as(u24, 13), (try q.item(1)).address);
    try testing.expectEqual(items.Area.outputs, (try parse("A1.5")).area);
    try testing.expectEqual(items.TransportSize.word, (try parse("QW4")).transport_size);
    try testing.expectEqual(items.TransportSize.byte, (try parse("AB4")).transport_size);
}

test "timers, counters and peripherals" {
    const t = try parse("T5");
    try testing.expectEqual(items.Area.timer, t.area);
    // Timer addresses are element indices, not bit addresses.
    try testing.expectEqual(@as(u24, 5), (try t.item(1)).address);

    const c = try parse("C3");
    try testing.expectEqual(items.Area.counter, c.area);
    try testing.expectEqual(@as(u24, 3), (try c.item(2)).address);
    try testing.expectEqual(items.Area.counter, (try parse("Z3")).area);

    const p = try parse("PIW256");
    try testing.expectEqual(items.Area.inputs, p.area);
    try testing.expectEqual(@as(u32, 256), p.byte_offset);
    try testing.expectEqual(items.TransportSize.word, p.transport_size);
    try testing.expectEqual(items.Area.inputs, (try parse("PEB0")).area);
    try testing.expectEqual(items.Area.outputs, (try parse("PQW8")).area);
    try testing.expectEqual(items.Area.outputs, (try parse("PAD8")).area);
}

test "malformed addresses are typed errors, never a wrong address" {
    const bad = [_][]const u8{
        "", "   ",
        "DB", // no number
        "DB1", // no member
        "DB1.", // nothing after the dot
        "DB1.DB", // no width letter
        "DB1.DBQ0", // unknown width
        "DB0.DBW0", // DB numbering starts at 1
        "DB65536.DBW0", // above the 16-bit field
        "DB1.DBX0", // a bit address without a bit
        "DB1.DBX0.8", // bit index out of range
        "DB1.DBW0.1", // a bit suffix on a word
        "DB1.DBW", // no offset
        "DB1.DBWxyz", // offset is not a number
        "DB1.DBW20junk", // trailing junk
        "M", // no offset
        "M10", // a bit address without a bit
        "M10.8", // bit index out of range
        "M10.2.3", // two bit suffixes
        "MB10.1", // a bit suffix on a byte
        "MB", // no offset
        "X1.0", // unknown area
        "K5", // unknown area
        "T", // no number
        "Txyz",
        "C", "C3.1", // counters have no bit
        "PIW", // no offset
        "PIW1x", // trailing junk
        "DB999999999999.DBW0", // number too long to be a DB
        "MW999999999", // offset overflows
    };
    for (bad) |s| {
        if (parse(s)) |a| {
            std.debug.print("expected an error for \"{s}\", got {any}\n", .{ s, a });
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "an offset that overflows the 24-bit wire address is refused at item time" {
    // 2097152 * 8 = 16777216, one past the 24-bit field.
    const a = try parse("MB2097152");
    try testing.expectError(error.AddressOutOfRange, a.item(1));
    // One less fits.
    _ = try (try parse("MB2097151")).item(1);
}

test "a count of zero is refused" {
    try testing.expectError(error.BadCount, (try parse("DB1.DBW0")).item(0));
}

test "parseItem is the one-call form" {
    const it = try parseItem("DB1.DBW20", 2);
    try testing.expectEqual(items.Area.db, it.area);
    try testing.expectEqual(@as(u16, 2), it.count);
    try testing.expectEqual(@as(u24, 160), it.address);
}

test "fuzz: address parser never panics" {
    try std.testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [40]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const a = parse(buf[0..len]) catch return;
    // Anything that parses must build an item or fail cleanly.
    const it = a.item(1) catch return;
    var out: [items.item_len]u8 = undefined;
    _ = try it.encode(&out);
}
