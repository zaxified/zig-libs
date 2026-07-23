// SPDX-License-Identifier: MIT

//! The **symbolic tag path** notation every Logix tool takes —
//! `Program:MainProgram.MyUDT.Member`, `MyArray[3]`, `Matrix[1,2]` — parsed
//! into the EPATH segments a `Read Tag` request needs.
//!
//! The mapping is:
//!
//! * every dotted component becomes an **ANSI Extended Symbol** segment
//!   (`0x91`, length, characters, pad to even);
//! * a program scope is **one segment containing the colon** —
//!   `Program:MainProgram` is a single 19-character symbol, not two;
//! * every `[i]` index becomes a **Member ID** segment (`0x28`/`0x29`/`0x2A`),
//!   and a multi-dimensional `[i,j,k]` becomes that many consecutive member
//!   segments.
//!
//! Name rules are Logix's, and they are checked rather than assumed: a tag
//! name starts with a letter or an underscore, contains only letters, digits
//! and underscores, is at most 40 characters, never contains two consecutive
//! underscores and never ends in one. A silently-accepted bad name produces a
//! request the controller answers with `path_segment_error`, which is a much
//! worse debugging experience than a parse error here.

const std = @import("std");
const epath = @import("epath.zig");

pub const ParseError = error{
    /// The whole path is empty.
    Empty,
    /// A component between dots is empty (`A..B`, a leading or trailing dot).
    EmptyComponent,
    /// A name that does not start with a letter or underscore.
    BadNameStart,
    /// A character that is not a letter, digit or underscore.
    BadNameCharacter,
    /// A name longer than 40 characters.
    NameTooLong,
    /// Two consecutive underscores, or a trailing one.
    BadUnderscore,
    /// A `[` with no matching `]`, or a `]` with no `[`.
    UnbalancedBracket,
    /// `[]`, or an index that is not a decimal number.
    BadIndex,
    /// An index that does not fit in 32 bits.
    IndexTooLarge,
    /// More than three dimensions, which is Logix's own limit.
    TooManyDimensions,
    /// Characters after the closing bracket of a component.
    TrailingCharacters,
    /// More segments than the caller's buffer can hold.
    BufferTooSmall,
};

/// Logix's own limits, checked here so a malformed name never reaches a
/// controller.
pub const max_name_len: usize = 40;
pub const max_dimensions: usize = 3;

/// The prefix that makes a component a program scope. The colon is part of
/// the symbol, not a separator.
pub const program_prefix = "Program:";

fn isNameStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}

fn isNameChar(c: u8) bool {
    return isNameStart(c) or (c >= '0' and c <= '9');
}

fn validateName(name: []const u8) ParseError!void {
    if (name.len == 0) return error.EmptyComponent;
    if (name.len > max_name_len) return error.NameTooLong;
    if (!isNameStart(name[0])) return error.BadNameStart;
    for (name) |c| if (!isNameChar(c)) return error.BadNameCharacter;
    if (name[name.len - 1] == '_') return error.BadUnderscore;
    var i: usize = 1;
    while (i < name.len) : (i += 1) {
        if (name[i] == '_' and name[i - 1] == '_') return error.BadUnderscore;
    }
}

/// One dotted component: a name plus its (possibly empty) index list.
pub const Component = struct {
    name: []const u8,
    indices: [max_dimensions]u32 = @splat(0),
    dimensions: usize = 0,

    pub fn index(self: Component, i: usize) ?u32 {
        return if (i < self.dimensions) self.indices[i] else null;
    }
};

/// A parsed tag path.
pub const TagPath = struct {
    components: []const Component,
    /// True when the first component is a `Program:` scope.
    program_scoped: bool,

    /// Encodes the path as EPATH octets into `out`.
    pub fn encode(self: TagPath, out: []u8) (ParseError || epath.EncodeError)![]const u8 {
        var b = epath.Builder.init(out);
        for (self.components) |c| {
            try b.symbol(c.name);
            var d: usize = 0;
            while (d < c.dimensions) : (d += 1) try b.member(c.indices[d]);
        }
        return b.bytes();
    }

    /// The path size in 16-bit words, which is what a request header carries.
    pub fn words(self: TagPath, out: []u8) (ParseError || epath.EncodeError)!u8 {
        var b = epath.Builder.init(out);
        for (self.components) |c| {
            try b.symbol(c.name);
            var d: usize = 0;
            while (d < c.dimensions) : (d += 1) try b.member(c.indices[d]);
        }
        return b.words();
    }
};

/// Parses `text` into `storage`. Nothing is copied — every `name` slices
/// `text`.
pub fn parse(text: []const u8, storage: []Component) ParseError!TagPath {
    if (text.len == 0) return error.Empty;
    var n: usize = 0;
    var rest = text;
    var program_scoped = false;
    var first = true;

    while (true) {
        // A `Program:Name` component keeps its colon, so the split on '.'
        // must not treat the colon as anything special — but the *name*
        // validation must run on the part after it.
        const dot = std.mem.indexOfScalar(u8, rest, '.');
        const piece = if (dot) |d| rest[0..d] else rest;
        if (piece.len == 0) return error.EmptyComponent;
        if (n >= storage.len) return error.BufferTooSmall;
        storage[n] = try parseComponent(piece, first, &program_scoped);
        n += 1;
        first = false;
        if (dot) |d| {
            rest = rest[d + 1 ..];
            // A trailing dot leaves an empty remainder.
            if (rest.len == 0) return error.EmptyComponent;
        } else break;
    }
    return .{ .components = storage[0..n], .program_scoped = program_scoped };
}

fn parseComponent(piece: []const u8, first: bool, program_scoped: *bool) ParseError!Component {
    var name_end = piece.len;
    if (std.mem.indexOfScalar(u8, piece, '[')) |br| name_end = br;
    if (std.mem.indexOfScalar(u8, piece, ']')) |cb| {
        if (name_end == piece.len or cb < name_end) return error.UnbalancedBracket;
    }
    const name = piece[0..name_end];

    // `Program:Foo` is one symbol; validate only the part after the colon.
    var validate_from = name;
    if (first and std.mem.startsWith(u8, name, program_prefix)) {
        program_scoped.* = true;
        validate_from = name[program_prefix.len..];
        if (validate_from.len == 0) return error.EmptyComponent;
        // The whole segment (prefix included) still has to fit the wire.
        if (name.len > 255) return error.NameTooLong;
        try validateName(validate_from);
    } else {
        try validateName(name);
    }

    var c = Component{ .name = name };
    if (name_end == piece.len) return c;

    // Indices.
    const close = std.mem.lastIndexOfScalar(u8, piece, ']') orelse return error.UnbalancedBracket;
    if (close != piece.len - 1) return error.TrailingCharacters;
    const inner = piece[name_end + 1 .. close];
    if (inner.len == 0) return error.BadIndex;
    var it = std.mem.splitScalar(u8, inner, ',');
    while (it.next()) |num| {
        if (c.dimensions >= max_dimensions) return error.TooManyDimensions;
        if (num.len == 0) return error.BadIndex;
        for (num) |ch| if (ch < '0' or ch > '9') return error.BadIndex;
        const v = std.fmt.parseInt(u32, num, 10) catch return error.IndexTooLarge;
        c.indices[c.dimensions] = v;
        c.dimensions += 1;
    }
    return c;
}

/// Parses `text` and encodes it in one call — the everyday entry point.
pub fn encodePath(text: []const u8, out: []u8) (ParseError || epath.EncodeError)![]const u8 {
    var storage: [8]Component = undefined;
    const p = try parse(text, &storage);
    return p.encode(out);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "a bare tag name" {
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x00 },
        try encodePath("SCADA", &out),
    );
}

test "an array element is a member segment" {
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x91, 0x07, 'M', 'y', 'A', 'r', 'r', 'a', 'y', 0x00, 0x28, 0x03 },
        try encodePath("MyArray[3]", &out),
    );
}

test "a multi-dimensional index becomes several member segments" {
    var storage: [4]Component = undefined;
    const p = try parse("Matrix[1,2,3]", &storage);
    try testing.expectEqual(@as(usize, 1), p.components.len);
    try testing.expectEqual(@as(usize, 3), p.components[0].dimensions);
    try testing.expectEqual(@as(?u32, 2), p.components[0].index(1));
    try testing.expectEqual(@as(?u32, null), p.components[0].index(3));
    var out: [64]u8 = undefined;
    const wire = try p.encode(&out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x28, 0x01, 0x28, 0x02, 0x28, 0x03 }, wire[wire.len - 6 ..]);
}

test "a UDT member chain becomes several symbol segments" {
    var out: [64]u8 = undefined;
    const wire = try encodePath("MyUDT.Member", &out);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x91, 0x05, 'M', 'y', 'U', 'D', 'T', 0x00, 0x91, 0x06, 'M', 'e', 'm', 'b', 'e', 'r' },
        wire,
    );
    try testing.expectEqual(@as(usize, 2), try epath.countSegments(wire));
}

test "a program scope is one segment including the colon" {
    var storage: [4]Component = undefined;
    const p = try parse("Program:MainProgram.MyTag", &storage);
    try testing.expect(p.program_scoped);
    try testing.expectEqual(@as(usize, 2), p.components.len);
    try testing.expectEqualStrings("Program:MainProgram", p.components[0].name);
    var out: [64]u8 = undefined;
    const wire = try p.encode(&out);
    try testing.expectEqual(@as(u8, 0x91), wire[0]);
    try testing.expectEqual(@as(u8, 19), wire[1]);
    try testing.expectEqualStrings("Program:MainProgram", (try epath.findSymbol(wire)).?);
    try testing.expectEqual(@as(usize, 2), try epath.countSegments(wire));
}

test "an index larger than an octet widens the member segment" {
    var out: [64]u8 = undefined;
    const wire = try encodePath("Big[300]", &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x29, 0x00, 0x2C, 0x01 }, wire[wire.len - 4 ..]);
    const wire32 = try encodePath("Big[70000]", &out);
    try testing.expectEqual(@as(u8, 0x2A), wire32[wire32.len - 6]);
}

test "a full chain of scope, member and index round trips through EPATH" {
    var out: [128]u8 = undefined;
    const wire = try encodePath("Program:Main.MyUDT.Members[2]", &out);
    var round: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, wire, try epath.reencode(wire, &round));
    try testing.expectEqual(@as(usize, 4), try epath.countSegments(wire));
}

test "malformed paths are typed errors" {
    var storage: [8]Component = undefined;
    const cases = [_]struct { text: []const u8, want: ParseError }{
        .{ .text = "", .want = error.Empty },
        .{ .text = ".", .want = error.EmptyComponent },
        .{ .text = "A..B", .want = error.EmptyComponent },
        .{ .text = ".Tag", .want = error.EmptyComponent },
        .{ .text = "Tag.", .want = error.EmptyComponent },
        .{ .text = "1Tag", .want = error.BadNameStart },
        .{ .text = "Ta-g", .want = error.BadNameCharacter },
        .{ .text = "Tag ", .want = error.BadNameCharacter },
        .{ .text = "Ta__g", .want = error.BadUnderscore },
        .{ .text = "Tag_", .want = error.BadUnderscore },
        .{ .text = "Tag[", .want = error.UnbalancedBracket },
        .{ .text = "Tag]", .want = error.UnbalancedBracket },
        .{ .text = "Tag]1[", .want = error.UnbalancedBracket },
        .{ .text = "Tag[]", .want = error.BadIndex },
        .{ .text = "Tag[a]", .want = error.BadIndex },
        .{ .text = "Tag[1,]", .want = error.BadIndex },
        .{ .text = "Tag[,1]", .want = error.BadIndex },
        .{ .text = "Tag[-1]", .want = error.BadIndex },
        .{ .text = "Tag[1 ]", .want = error.BadIndex },
        .{ .text = "Tag[99999999999]", .want = error.IndexTooLarge },
        .{ .text = "Tag[1,2,3,4]", .want = error.TooManyDimensions },
        .{ .text = "Tag[1]x", .want = error.TrailingCharacters },
        .{ .text = "Program:", .want = error.EmptyComponent },
        .{ .text = "Program:1Bad", .want = error.BadNameStart },
        .{ .text = "ThisNameIsFarTooLongToBeAValidLogixTagName", .want = error.NameTooLong },
    };
    for (cases) |c| {
        try testing.expectError(c.want, parse(c.text, &storage));
    }
    // A name of exactly 41 characters, all legal, is a length error.
    try testing.expectError(error.NameTooLong, parse("A" ** 41, &storage));
    // 40 is fine.
    _ = try parse("A" ** 40, &storage);
    // More components than the caller's storage.
    var tiny: [1]Component = undefined;
    try testing.expectError(error.BufferTooSmall, parse("A.B", &tiny));
}

test "a colon is only a scope prefix on the first component" {
    var storage: [4]Component = undefined;
    // `Program:` in the middle is not a scope, so the colon is an illegal
    // character in a name.
    try testing.expectError(error.BadNameCharacter, parse("Tag.Program:X", &storage));
}

test "path size in words matches what the builder produced" {
    var storage: [4]Component = undefined;
    const p = try parse("SCADA[0]", &storage);
    var out: [64]u8 = undefined;
    const wire = try p.encode(&out);
    var scratch: [64]u8 = undefined;
    try testing.expectEqual(@as(u8, @intCast(wire.len / 2)), try p.words(&scratch));
}

test "fuzz: tag path parsing never panics and always encodes" {
    try std.testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    var storage: [8]Component = undefined;
    const p = parse(buf[0..len], &storage) catch return;
    // Anything that parses must encode to a legal, even-length EPATH.
    var out: [512]u8 = undefined;
    const wire = p.encode(&out) catch return;
    try testing.expect(wire.len % 2 == 0);
    var round: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, wire, try epath.reencode(wire, &round));
}
