// SPDX-License-Identifier: MIT
//! Tests of the LSP 3.17 conversion: `lspCharacter` / `byteColumn`,
//! `writeLsp` / `writeLspArray`, `fromLsp`, and the `hint` severity.
//!
//! Provenance of the vectors. The LSP 3.17 specification (the `types/` and
//! `language/publishDiagnostics.md` pages, `metaModel.json`) defines the shapes
//! only as TypeScript interfaces; it contains no JSON example of a
//! `Diagnostic`, so the expected objects below are written by hand from the
//! metaModel (property names, `DiagnosticSeverity` 1..4, `DiagnosticTag` 1..2,
//! `Position`/`Range`/`Location`, `PositionEncodingKind`) and compared
//! value-equal (`std.json` parse of both, objects order-insensitive). The
//! character counts of the UTF-8/UTF-16/UTF-32 table come from Python's
//! `len(s[:i].encode(...))` / `utf-16-le` counts, not from this module.

const std = @import("std");
const dg = @import("root.zig");
const testing = std.testing;

// ── helpers ──────────────────────────────────────────────────────────────────

fn jsonEq(a: std.json.Value, b: std.json.Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    switch (a) {
        .null => return true,
        .bool => |x| return x == b.bool,
        .integer => |x| return x == b.integer,
        .float => |x| return x == b.float,
        .number_string => |x| return std.mem.eql(u8, x, b.number_string),
        .string => |x| return std.mem.eql(u8, x, b.string),
        .array => |x| {
            if (x.items.len != b.array.items.len) return false;
            for (x.items, b.array.items) |p, q| if (!jsonEq(p, q)) return false;
            return true;
        },
        .object => |x| {
            if (x.count() != b.object.count()) return false;
            var it = x.iterator();
            while (it.next()) |e| {
                const o = b.object.get(e.key_ptr.*) orelse return false;
                if (!jsonEq(e.value_ptr.*, o)) return false;
            }
            return true;
        },
    }
}

fn lspText(d: dg.Diagnostic, sources: []const dg.Source, enc: dg.PositionEncoding, opts: dg.LspOptions) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    try dg.writeLsp(&out.writer, d, sources, enc, opts);
    return out.toOwnedSlice();
}

fn expectLsp(expected: []const u8, d: dg.Diagnostic, sources: []const dg.Source, enc: dg.PositionEncoding, opts: dg.LspOptions) !void {
    const got = try lspText(d, sources, enc, opts);
    defer testing.allocator.free(got);
    const e = try std.json.parseFromSlice(std.json.Value, testing.allocator, expected, .{});
    defer e.deinit();
    const g = try std.json.parseFromSlice(std.json.Value, testing.allocator, got, .{});
    defer g.deinit();
    if (!jsonEq(e.value, g.value)) {
        std.debug.print("\nexpected: {s}\n     got: {s}\n", .{ expected, got });
        return error.TestExpectedEqual;
    }
}

/// start line, start character, end line, end character of `writeLsp`'s range.
fn rangeOf(d: dg.Diagnostic, sources: []const dg.Source, enc: dg.PositionEncoding) ![4]i64 {
    const got = try lspText(d, sources, enc, .{});
    defer testing.allocator.free(got);
    const g = try std.json.parseFromSlice(std.json.Value, testing.allocator, got, .{});
    defer g.deinit();
    const r = g.value.object.get("range").?.object;
    const s = r.get("start").?.object;
    const e = r.get("end").?.object;
    return .{ s.get("line").?.integer, s.get("character").?.integer, e.get("line").?.integer, e.get("character").?.integer };
}

fn mk(line: ?u32, col: ?u32, end_line: ?u32, end_col: ?u32) dg.Diagnostic {
    return .{ .path = "", .line = line, .col = col, .end_line = end_line, .end_col = end_col, .severity = .@"error", .code = "", .message = "m" };
}

// ── character conversion ─────────────────────────────────────────────────────

/// `bytes`, `utf16`, `utf32` offsets of every character boundary (Python).
const Bound = struct { b: u32, u16: u32, u32: u32 };

fn checkTable(text: []const u8, bounds: []const Bound) !void {
    for (bounds) |p| {
        try testing.expectEqual(p.b, dg.lspCharacter(text, p.b + 1, .utf8));
        try testing.expectEqual(p.u16, dg.lspCharacter(text, p.b + 1, .utf16));
        try testing.expectEqual(p.u32, dg.lspCharacter(text, p.b + 1, .utf32));
        try testing.expectEqual(@as(?u32, p.b + 1), dg.byteColumn(text, p.b, .utf8));
        try testing.expectEqual(@as(?u32, p.b + 1), dg.byteColumn(text, p.u16, .utf16));
        try testing.expectEqual(@as(?u32, p.b + 1), dg.byteColumn(text, p.u32, .utf32));
    }
}

test "character: astral (U+1F600, U+10400) is 2 UTF-16 units, 1 UTF-32 unit, 4 bytes" {
    try checkTable("a\u{1F600}b", &.{
        .{ .b = 0, .u16 = 0, .u32 = 0 }, .{ .b = 1, .u16 = 1, .u32 = 1 },
        .{ .b = 5, .u16 = 3, .u32 = 2 }, .{ .b = 6, .u16 = 4, .u32 = 3 },
    });
    try checkTable("a\u{10400}b", &.{
        .{ .b = 0, .u16 = 0, .u32 = 0 }, .{ .b = 1, .u16 = 1, .u32 = 1 },
        .{ .b = 5, .u16 = 3, .u32 = 2 }, .{ .b = 6, .u16 = 4, .u32 = 3 },
    });
    try checkTable("\u{1F600}\u{1F600}", &.{
        .{ .b = 0, .u16 = 0, .u32 = 0 }, .{ .b = 4, .u16 = 2, .u32 = 1 }, .{ .b = 8, .u16 = 4, .u32 = 2 },
    });
}

test "character: BMP CJK is 3 bytes, 1 UTF-16 unit" {
    try checkTable("\u{65E5}\u{672C}\u{8A9E}x", &.{
        .{ .b = 0, .u16 = 0, .u32 = 0 }, .{ .b = 3, .u16 = 1, .u32 = 1 },  .{ .b = 6, .u16 = 2, .u32 = 2 },
        .{ .b = 9, .u16 = 3, .u32 = 3 }, .{ .b = 10, .u16 = 4, .u32 = 4 },
    });
}

test "character: a combining mark is a character of its own; a tab is one unit" {
    // 'e' + U+0301 (2 bytes) + 'x'
    try checkTable("e\u{301}x", &.{
        .{ .b = 0, .u16 = 0, .u32 = 0 }, .{ .b = 1, .u16 = 1, .u32 = 1 },
        .{ .b = 3, .u16 = 2, .u32 = 2 }, .{ .b = 4, .u16 = 3, .u32 = 3 },
    });
    try checkTable("\tx", &.{ .{ .b = 0, .u16 = 0, .u32 = 0 }, .{ .b = 1, .u16 = 1, .u32 = 1 }, .{ .b = 2, .u16 = 2, .u32 = 2 } });
}

test "character: inside a character, past the end, column 0, inside a surrogate pair" {
    const t = "a\u{1F600}b";
    // Byte column 3 is the 3rd byte of the emoji: counts as the emoji's start.
    try testing.expectEqual(@as(u32, 1), dg.lspCharacter(t, 3, .utf16));
    try testing.expectEqual(@as(u32, 1), dg.lspCharacter(t, 3, .utf32));
    try testing.expectEqual(@as(u32, 2), dg.lspCharacter(t, 3, .utf8));
    // Past the end: the line length.
    try testing.expectEqual(@as(u32, 4), dg.lspCharacter(t, 99, .utf16));
    try testing.expectEqual(@as(u32, 3), dg.lspCharacter(t, 99, .utf32));
    try testing.expectEqual(@as(u32, 6), dg.lspCharacter(t, 99, .utf8));
    try testing.expectEqual(@as(u32, 0), dg.lspCharacter(t, 0, .utf16));
    try testing.expectEqual(@as(?u32, 7), dg.byteColumn(t, 99, .utf16));
    try testing.expectEqual(@as(?u32, 7), dg.byteColumn(t, 99, .utf8));
    // UTF-16 character 2 is between the two halves of the emoji.
    try testing.expectEqual(@as(?u32, null), dg.byteColumn(t, 2, .utf16));
    try testing.expectEqual(@as(?u32, 6), dg.byteColumn(t, 2, .utf32));
    try testing.expectEqual(@as(u32, 0), dg.lspCharacter("", 1, .utf16));
    try testing.expectEqual(@as(?u32, 1), dg.byteColumn("", 5, .utf16));
}

test "character: invalid UTF-8 counts byte by byte in every encoding" {
    const cases = [_][]const u8{
        "a\xffb", // stray byte
        "x\xF0\x9Fy", // truncated 4-byte sequence
        "\xC0\x80z", // overlong NUL
        "\xED\xA0\x80z", // an encoded surrogate
        "a\x80\x80b", // stray continuation bytes
    };
    for (cases) |t| {
        for ([_]dg.PositionEncoding{ .utf8, .utf16, .utf32 }) |enc| {
            for (0..t.len + 1) |o| {
                try testing.expectEqual(@as(u32, @intCast(o)), dg.lspCharacter(t, @intCast(o + 1), enc));
                try testing.expectEqual(@as(?u32, @intCast(o + 1)), dg.byteColumn(t, @intCast(o), enc));
            }
        }
    }
    // A valid character after the bad bytes is counted normally.
    try testing.expectEqual(@as(u32, 4), dg.lspCharacter("a\xff\u{1F600}", 7, .utf16));
}

test "character: every byte offset maps back to a boundary at or before it" {
    const t = "a\u{1F600}\u{65E5}e\u{301}\xffz\u{1F600}\t";
    for ([_]dg.PositionEncoding{ .utf8, .utf16, .utf32 }) |enc| {
        for (0..t.len + 1) |o| {
            const c = dg.lspCharacter(t, @intCast(o + 1), enc);
            const bc = dg.byteColumn(t, c, enc).?;
            try testing.expect(bc <= o + 1);
            try testing.expectEqual(c, dg.lspCharacter(t, bc, enc));
        }
    }
}

// ── writeLsp ─────────────────────────────────────────────────────────────────

// `bad` is at byte columns 18..21, UTF-16 characters 15..18, UTF-32 14..17
// (the emoji before it is 4 bytes, 2 UTF-16 units, 1 code point).
const line1 = "let s = \"\u{1F600}\" + bad;\n";

const full: dg.Diagnostic = .{
    .path = "ignored",
    .file = "/src/a b.txt",
    .line = 1,
    .col = 18,
    .end_line = 1,
    .end_col = 21,
    .severity = .warning,
    .code = "E0425",
    .message = "cannot find `bad`",
    .suggest = "not in LSP",
    .code_url = "https://e.invalid/E0425",
    .tags = &.{.deprecated},
    .labels = &.{
        .{ .line = 1, .col = 5, .end_col = 6, .message = "declared here" },
        .{ .file = "/src/other.txt", .line = 2, .col = 1, .message = "elsewhere" },
    },
};

fn expectedFull(comptime sc: []const u8, comptime ec: []const u8) []const u8 {
    return
    \\{"range":{"start":{"line":0,"character":
    ++ sc ++
        \\},"end":{"line":0,"character":
    ++ ec ++
        \\}},"severity":2,"code":"E0425","codeDescription":{"href":"https://e.invalid/E0425"},
        \\"source":"zdiag","message":"cannot find `bad`","tags":[2],"relatedInformation":[
        \\{"location":{"uri":"file:///src/a%20b.txt","range":{"start":{"line":0,"character":4},"end":{"line":0,"character":5}}},"message":"declared here"},
        \\{"location":{"uri":"file:///src/other.txt","range":{"start":{"line":1,"character":0},"end":{"line":1,"character":0}}},"message":"elsewhere"}]}
    ;
}

test "writeLsp: every field, in each position encoding" {
    const srcs = [_]dg.Source{.{ .file = "/src/a b.txt", .text = line1 }};
    const o: dg.LspOptions = .{ .source = "zdiag" };
    try expectLsp(expectedFull("15", "18"), full, &srcs, .utf16, o);
    try expectLsp(expectedFull("17", "20"), full, &srcs, .utf8, o);
    try expectLsp(expectedFull("14", "17"), full, &srcs, .utf32, o);
}

test "writeLsp: without the source text character is col - 1 (UTF-8 semantics)" {
    try expectLsp(expectedFull("17", "20"), full, &.{}, .utf16, .{ .source = "zdiag" });
}

test "writeLsp: optional members are left out, severity is 1..4, uri_prefix is applied" {
    var d = mk(3, 2, null, null);
    d.labels = &.{.{ .file = "x/y.txt", .line = 1, .col = 1, .message = "r" }};
    try expectLsp(
        \\{"range":{"start":{"line":2,"character":1},"end":{"line":2,"character":1}},"severity":1,"message":"m",
        \\"relatedInformation":[{"location":{"uri":"x/y.txt","range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}}},"message":"r"}]}
    , d, &.{}, .utf16, .{ .uri_prefix = "" });
    inline for (.{ .{ dg.Severity.@"error", 1 }, .{ dg.Severity.warning, 2 }, .{ dg.Severity.info, 3 }, .{ dg.Severity.hint, 4 } }) |p| {
        var e = mk(null, null, null, null);
        e.severity = p[0];
        const got = try lspText(e, &.{}, .utf16, .{});
        defer testing.allocator.free(got);
        const g = try std.json.parseFromSlice(std.json.Value, testing.allocator, got, .{});
        defer g.deinit();
        try testing.expectEqual(@as(i64, p[1]), g.value.object.get("severity").?.integer);
        try testing.expect(g.value.object.get("code") == null);
        try testing.expect(g.value.object.get("tags") == null);
        try testing.expect(g.value.object.get("relatedInformation") == null);
        try testing.expect(g.value.object.get("data") == null);
    }
}

test "writeLsp: range rules" {
    const text = "h\u{E9}llo\nx\nabc";
    const src = [_]dg.Source{.{ .file = "f", .text = text }};
    // No line: 0:0-0:0.
    try testing.expectEqual([4]i64{ 0, 0, 0, 0 }, try rangeOf(mk(null, 5, null, null), &src, .utf16));
    // A line without a column: the whole line (6 bytes, 5 UTF-16 units).
    try testing.expectEqual([4]i64{ 0, 0, 0, 5 }, try rangeOf(mk(1, null, null, null), &src, .utf16));
    try testing.expectEqual([4]i64{ 0, 0, 0, 6 }, try rangeOf(mk(1, null, null, null), &src, .utf8));
    // ... and zero-width at its start when the text is not there.
    try testing.expectEqual([4]i64{ 4, 0, 4, 0 }, try rangeOf(mk(5, null, null, null), &src, .utf16));
    // A column and no end: a point (byte col 4 is after 'é': character 2).
    try testing.expectEqual([4]i64{ 0, 2, 0, 2 }, try rangeOf(mk(1, 4, null, null), &src, .utf16));
    try testing.expectEqual([4]i64{ 0, 3, 0, 3 }, try rangeOf(mk(1, 4, null, null), &src, .utf8));
    // end_col without end_line: the same line.
    try testing.expectEqual([4]i64{ 0, 2, 0, 4 }, try rangeOf(mk(1, 4, null, 6), &src, .utf16));
    // end_line without end_col: the end of that line.
    try testing.expectEqual([4]i64{ 0, 2, 1, 1 }, try rangeOf(mk(1, 4, 2, null), &src, .utf16));
    // Several lines.
    try testing.expectEqual([4]i64{ 0, 2, 2, 2 }, try rangeOf(mk(1, 4, 3, 3), &src, .utf16));
    // An end before the start is the start.
    try testing.expectEqual([4]i64{ 0, 2, 0, 2 }, try rangeOf(mk(1, 4, 1, 1), &src, .utf16));
    // A column past the line clamps to its length.
    try testing.expectEqual([4]i64{ 1, 1, 1, 1 }, try rangeOf(mk(2, 99, null, null), &src, .utf16));
}

test "writeLsp: the message is data, JSON-escaped, not terminal-escaped; file names are percent-encoded" {
    var d = mk(1, 1, null, null);
    d.message = "a\"b\\c\n\x1b[2J \u{E9}";
    d.labels = &.{.{ .file = "/t/\u{E9} #?%.txt", .line = 1, .message = "" }};
    const got = try lspText(d, &.{}, .utf16, .{});
    defer testing.allocator.free(got);
    const g = try std.json.parseFromSlice(std.json.Value, testing.allocator, got, .{});
    defer g.deinit();
    try testing.expectEqualStrings(d.message, g.value.object.get("message").?.string);
    const uri = g.value.object.get("relatedInformation").?.array.items[0].object.get("location").?.object.get("uri").?.string;
    try testing.expectEqualStrings("file:///t/%C3%A9%20%23%3F%25.txt", uri);
}

test "writeLspArray: a JSON array of the same objects" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try dg.writeLspArray(&out.writer, &.{ mk(1, 1, null, null), full }, &.{}, .utf16, .{});
    const g = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.written(), .{});
    defer g.deinit();
    try testing.expectEqual(@as(usize, 2), g.value.array.items.len);
    try testing.expectEqualStrings("cannot find `bad`", g.value.array.items[1].object.get("message").?.string);
    var empty: std.Io.Writer.Allocating = .init(testing.allocator);
    defer empty.deinit();
    try dg.writeLspArray(&empty.writer, &.{}, &.{}, .utf16, .{});
    try testing.expectEqualStrings("[]", empty.written());
}

// ── fromLsp ──────────────────────────────────────────────────────────────────

fn parse(arena: std.mem.Allocator, text: []const u8) !std.json.Value {
    return try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
}

test "fromLsp: an LSP-shaped diagnostic with an integer code, hint, tags, related information" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try parse(a,
        \\{"range":{"start":{"line":1,"character":3},"end":{"line":1,"character":7}},"severity":4,"code":42,
        \\"codeDescription":{"href":"https://e.invalid/42"},"source":"eslint","message":"unused","tags":[1,2,9],
        \\"relatedInformation":[{"location":{"uri":"file:///w/b%20c.txt","range":{"start":{"line":0,"character":0},"end":{"line":0,"character":2}}},"message":"r"},
        \\{"location":{"uri":"file:///w/a.txt","range":{"start":{"line":4,"character":1},"end":{"line":4,"character":1}}},"message":"same file"}],
        \\"data":{"x":1}}
    );
    const d = try dg.fromLsp(a, v, "/w/a.txt", &.{}, .utf16, .{});
    try testing.expectEqualStrings("/w/a.txt", d.file.?);
    try testing.expectEqual(@as(?u32, 2), d.line);
    try testing.expectEqual(@as(?u32, 4), d.col);
    try testing.expectEqual(@as(?u32, 2), d.end_line);
    try testing.expectEqual(@as(?u32, 8), d.end_col);
    try testing.expectEqual(dg.Severity.hint, d.severity);
    try testing.expectEqualStrings("42", d.code);
    try testing.expectEqualStrings("https://e.invalid/42", d.code_url.?);
    try testing.expectEqualStrings("unused", d.message);
    try testing.expectEqualSlices(dg.Tag, &.{ .unnecessary, .deprecated }, d.tags.?);
    try testing.expectEqual(@as(usize, 2), d.labels.?.len);
    try testing.expectEqualStrings("/w/b c.txt", d.labels.?[0].file.?);
    try testing.expectEqual(@as(u32, 1), d.labels.?[0].line);
    try testing.expectEqual(@as(?u32, 3), d.labels.?[0].end_col);
    try testing.expect(d.labels.?[1].file == null);
    try testing.expectEqual(@as(?u32, null), d.labels.?[1].end_col);
    try testing.expectEqualStrings("same file", d.labels.?[1].message);
}

test "fromLsp: defaults and errors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ok = try dg.fromLsp(a, try parse(a,
        \\{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}},"message":"m"}
    ), null, &.{}, .utf16, .{});
    try testing.expectEqual(dg.Severity.@"error", ok.severity);
    try testing.expectEqualStrings("", ok.code);
    try testing.expectEqual(@as(?u32, null), ok.end_line);
    const bad = [_][]const u8{
        \\{"message":"m"}
        ,
        \\{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}}}
        ,
        \\{"range":"x","message":"m"}
        ,
        \\{"range":{"start":{"line":-1,"character":0},"end":{"line":0,"character":0}},"message":"m"}
        ,
        \\{"range":{"start":{"line":0,"character":0}},"message":"m"}
        ,
        \\{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}},"message":7}
        ,
        \\{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}},"message":"m","code":true}
        ,
        \\[1]
    };
    for (bad) |t| try testing.expectError(error.InvalidDiagnostic, dg.fromLsp(a, try parse(a, t), null, &.{}, .utf16, .{}));
}

test "round trip: writeLsp then fromLsp, in each encoding, with astral and CJK lines" {
    const text = line1 ++ "\u{65E5}\u{672C}\u{1F600} tail\n";
    const srcs = [_]dg.Source{.{ .file = "/src/a b.txt", .text = text }};
    const d: dg.Diagnostic = .{
        .path = "",
        .file = "/src/a b.txt",
        .line = 1,
        .col = 18,
        .end_line = 2,
        .end_col = 11, // after the emoji (3 + 3 + 4 bytes)
        .severity = .hint,
        .code = "E1",
        .message = "msg",
        .code_url = "https://e.invalid/E1",
        .tags = &.{ .unnecessary, .deprecated },
        .labels = &.{
            .{ .line = 2, .col = 7, .end_col = 11, .message = "emoji" },
            .{ .file = "/other/z.txt", .line = 7, .col = 3, .end_col = 9, .message = "no text" },
        },
    };
    for ([_]dg.PositionEncoding{ .utf8, .utf16, .utf32 }) |enc| {
        const json = try lspText(d, &srcs, enc, .{ .source = "t" });
        defer testing.allocator.free(json);
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const back = try dg.fromLsp(a, try parse(a, json), d.file, &srcs, enc, .{});
        try testing.expectEqualStrings(d.file.?, back.file.?);
        try testing.expectEqual(d.line, back.line);
        try testing.expectEqual(d.col, back.col);
        try testing.expectEqual(d.end_line, back.end_line);
        try testing.expectEqual(d.end_col, back.end_col);
        try testing.expectEqual(d.severity, back.severity);
        try testing.expectEqualStrings(d.code, back.code);
        try testing.expectEqualStrings(d.message, back.message);
        try testing.expectEqualStrings(d.code_url.?, back.code_url.?);
        try testing.expectEqualSlices(dg.Tag, d.tags.?, back.tags.?);
        try testing.expectEqual(@as(usize, 2), back.labels.?.len);
        for (d.labels.?, back.labels.?) |x, y| {
            try testing.expectEqual(x.file == null, y.file == null);
            if (x.file) |f| try testing.expectEqualStrings(f, y.file.?);
            try testing.expectEqual(x.line, y.line);
            try testing.expectEqual(x.col, y.col);
            try testing.expectEqual(x.end_col, y.end_col);
            try testing.expectEqualStrings(x.message, y.message);
        }
    }
}

test "fromLsp: a position inside a surrogate pair is taken at the pair's start" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const srcs = [_]dg.Source{.{ .file = "f", .text = "a\u{1F600}b" }};
    const d = try dg.fromLsp(a, try parse(a,
        \\{"range":{"start":{"line":0,"character":2},"end":{"line":0,"character":3}},"message":"m"}
    ), "f", &srcs, .utf16, .{});
    try testing.expectEqual(@as(?u32, 2), d.col);
    try testing.expectEqual(@as(?u32, 6), d.end_col);
}

// ── hint ─────────────────────────────────────────────────────────────────────

test "hint: short, snippet, colour, JSON and counting" {
    const d: dg.Diagnostic = .{ .path = "", .line = 1, .col = 1, .severity = .hint, .code = "c", .message = "m" };
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try dg.renderOne(&w, d, .{});
    try testing.expectEqualStrings("1:1: hint[c]: m\n", w.buffered());
    var w2: std.Io.Writer = .fixed(&buf);
    try dg.renderOne(&w2, d, .{ .style = .snippet, .sources = &.{.{ .file = "whatever", .text = "abc" }} });
    try testing.expectEqualStrings("hint[c]: m\n  --> 1:1\n  |\n1 | abc\n  | ^\n\n", w2.buffered());
    var w3: std.Io.Writer = .fixed(&buf);
    try dg.renderOne(&w3, d, .{ .color = true });
    try testing.expect(std.mem.startsWith(u8, w3.buffered(), "1:1: \x1b[1;36mhint[c]\x1b[0m"));
    var w4: std.Io.Writer = .fixed(&buf);
    try dg.writeJsonSlice(&w4, &.{d});
    try testing.expect(std.mem.find(u8, w4.buffered(), "\"severity\":\"hint\"") != null);
    var diag: dg.Diagnostics = .init(testing.allocator);
    defer diag.deinit();
    try diag.append(d);
    try diag.append(d);
    try testing.expectEqual(@as(usize, 2), diag.countBySeverity(.hint));
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.info));
}
