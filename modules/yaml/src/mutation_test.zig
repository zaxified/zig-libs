// SPDX-License-Identifier: MIT
//! Tests that kill the survivors of the 2026-11-27 whole-module mutation run.
//! Every expected value comes from YAML 1.2.2 (or from the module's own doc
//! comments), never from running the code. Each case is a near miss: an input
//! one step away from a rule, so that dropping or shifting one condition of the
//! rule changes the outcome.

const std = @import("std");
const testing = std.testing;
const compose_mod = @import("compose.zig");
const Value = compose_mod.Value;
const Pair = compose_mod.Pair;
const scanner = @import("scanner.zig");
const parser_mod = @import("parser.zig");
const encoding = @import("encoding.zig");
const emit = @import("emit.zig");
const typed = @import("typed.zig");
const Diagnostic = @import("diagnostic.zig").Diagnostic;

// ── helpers ─────────────────────────────────────────────────────────────────

fn show(w: *std.Io.Writer, v: Value) std.Io.Writer.Error!void {
    switch (v) {
        .null => try w.writeAll("~"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| try w.print("{d}", .{i}),
        .float => |f| try w.print("f{d}", .{f}),
        .string => |s| try w.print("\"{s}\"", .{s}),
        .sequence => |s| {
            try w.writeByte('[');
            for (s, 0..) |x, i| {
                if (i != 0) try w.writeAll(", ");
                try show(w, x);
            }
            try w.writeByte(']');
        },
        .mapping => |m| {
            try w.writeByte('{');
            for (m, 0..) |p, i| {
                if (i != 0) try w.writeAll(", ");
                try show(w, p.key);
                try w.writeAll(": ");
                try show(w, p.value);
            }
            try w.writeByte('}');
        },
    }
}

fn expectDoc(src: []const u8, opts: compose_mod.Options, want: []const u8) !void {
    const r = try compose_mod.compose(testing.allocator, src, opts);
    defer r.deinit();
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try show(&w, r.root);
    try testing.expectEqualStrings(want, w.buffered());
}

fn expectInvalid(src: []const u8) !void {
    try testing.expectError(error.InvalidYaml, compose_mod.compose(testing.allocator, src, .{}));
}

fn expectProblem(src: []const u8, want: []const u8) !void {
    var d: Diagnostic = .{};
    try testing.expectError(error.InvalidYaml, compose_mod.compose(testing.allocator, src, .{ .diagnostic = &d }));
    try testing.expectEqualStrings(want, d.problem);
}

/// The scanner's problem text after scanning `src` to its first error ("" if none).
fn scanProblem(arena: std.mem.Allocator, src: []const u8, out: *scanner.Scanner) []const u8 {
    out.* = scanner.Scanner.init(arena, src);
    while (true) {
        const t = out.next() catch return out.problem;
        if (t.kind == .stream_end) return "";
    }
}

// ── scanner: character widths and marks ─────────────────────────────────────

test "mutation 2026-11-27: columns count characters whatever the width of the UTF-8 sequence" {
    // 2-, 3-, 4-byte and U+0800 (lead byte 0xE0) characters inside an
    // unterminated quoted scalar: the error is at the end, 4 + 4 characters in.
    var d: Diagnostic = .{};
    try testing.expectError(error.InvalidYaml, compose_mod.compose(
        testing.allocator,
        "a: '\u{e9}\u{20ac}\u{1f600}\u{800}",
        .{ .diagnostic = &d },
    ));
    try testing.expectEqual(@as(usize, 0), d.mark.line);
    try testing.expectEqual(@as(usize, 8), d.mark.column);
}

test "mutation 2026-11-27: the mark of a non-printable byte counts CR, LF and CRLF as one break each" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Case = struct { src: []const u8, line: usize, column: usize };
    const cases = [_]Case{
        .{ .src = "a\rb\x01", .line = 1, .column = 1 },
        .{ .src = "a\nb\x01", .line = 1, .column = 1 },
        .{ .src = "a\n\nb\x01", .line = 2, .column = 1 },
        .{ .src = "a\r\nb\x01", .line = 1, .column = 1 },
        .{ .src = "a\rbc\x01", .line = 1, .column = 2 },
    };
    for (cases) |c| {
        var s: scanner.Scanner = undefined;
        _ = scanProblem(arena, c.src, &s);
        try testing.expectEqual(c.line, s.problem_mark.line);
        try testing.expectEqual(c.column, s.problem_mark.column);
    }
}

test "mutation 2026-11-27: an unfinished last line puts the end-of-stream mark on the next line, column 0" {
    var d: Diagnostic = .{};
    try testing.expectError(error.InvalidYaml, compose_mod.compose(testing.allocator, "a: 1\nb", .{ .diagnostic = &d }));
    try testing.expectEqualStrings("could not find expected ':'", d.problem);
    try testing.expectEqual(@as(usize, 2), d.mark.line);
    try testing.expectEqual(@as(usize, 0), d.mark.column);
}

test "mutation 2026-11-27: a lone CR is a line break" {
    try expectDoc("a: 1\rb: 2\r", .{}, "{\"a\": 1, \"b\": 2}");
}

test "mutation 2026-11-27: a flow indicator ends a plain scalar inside a flow collection" {
    try expectInvalid("[a[b ]\n");
    try expectInvalid("{a{b }\n");
}

test "mutation 2026-11-27: the document markers are exactly three characters at column 0 followed by a blank" {
    try expectDoc("x--\n", .{}, "\"x--\"");
    try expectDoc("--x\n", .{}, "\"--x\"");
    try expectDoc("x..\n", .{}, "\"x..\"");
    try expectDoc(".x.\n", .{}, "\".x.\"");
    try expectDoc("..x\n", .{}, "\"..x\"");
    try expectDoc("...x\n", .{}, "\"...x\"");
    try expectDoc("a: ...\n", .{}, "{\"a\": \"...\"}");
}

test "mutation 2026-11-27: % | > cannot start a token where they are not an indicator of the context" {
    const msg = "found character that cannot start any token";
    try expectProblem("a: %b\n", msg);
    try expectProblem("[|]\n", msg);
    try expectProblem("[>]\n", msg);
}

test "mutation 2026-11-27: only the byte order mark EF BB BF is skipped; three-byte near misses are content" {
    try expectDoc("a: 1\n\u{2EFF}b: 2\n", .{}, "{\"a\": 1, \"\u{2EFF}b\": 2}");
    try expectDoc("a: 1\n\u{FF3F}b: 2\n", .{}, "{\"a\": 1, \"\u{FF3F}b\": 2}");
    try expectDoc("a: 1\n\u{FEFA}b: 2\n", .{}, "{\"a\": 1, \"\u{FEFA}b\": 2}");
    try expectDoc("\u{0EFF}x\n", .{}, "\"\u{0EFF}x\"");
    try expectDoc("\u{FF3F}x\n", .{}, "\"\u{FF3F}x\"");
    try expectDoc("\u{FEFA}x\n", .{}, "\"\u{FEFA}x\"");
}

test "mutation 2026-11-27: a BOM at the start of the stream takes no column" {
    try expectDoc("\u{FEFF}a: 1\nb: 2\n", .{}, "{\"a\": 1, \"b\": 2}");
}

test "mutation 2026-11-27: a UTF-16/UTF-32 BOM is refused by name; bytes that only resemble one are judged by their own value" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bom = "UTF-16/UTF-32 BOM: only UTF-8 input is supported";
    const real = [_][]const u8{ "\x00\x00\xFE\xFF", "\xFF\xFE\x00\x00", "\xFE\xFF", "\xFF\xFE" };
    for (real) |src| {
        var s: scanner.Scanner = undefined;
        try testing.expectEqualStrings(bom, scanProblem(arena, src, &s));
    }
    const near = [_][]const u8{
        "x\x00\xFE\xFF", "\x00x\xFE\xFF", "\x00\x00x\xFF", "\x00\x00\xFEx",
        "x\xFE\x00\x00", "\xFFx\x00\x00", "x\xFF",         "\xFEx",
        "x\xFE",         "\xFFx",
    };
    for (near) |src| {
        var s: scanner.Scanner = undefined;
        const p = scanProblem(arena, src, &s);
        try testing.expect(p.len != 0);
        try testing.expect(!std.mem.eql(u8, p, bom));
    }
}

// ── scanner: directives, anchors, tags, block and quoted scalars ────────────

test "mutation 2026-11-27: directive names may hold - and _, tag handles may hold -" {
    try expectDoc("%FOO-BAR x\n--- a\n", .{}, "\"a\"");
    try expectDoc("%FOO_BAR x\n--- a\n", .{}, "\"a\"");
    try expectDoc("%TAG !a-b! tag:example.com,2000:\n--- !a-b!c v\n", .{}, "\"v\"");
}

test "mutation 2026-11-27: a version number may have nine digits, not ten" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var s = scanner.Scanner.init(arena, "%YAML 123456789.1\n--- a\n");
    _ = try s.next(); // stream start
    const t = try s.next();
    try testing.expectEqual(scanner.TokenKind.version_directive, t.kind);
    try testing.expectEqual(@as(u32, 123456789), t.major);
    var s2: scanner.Scanner = undefined;
    try testing.expectEqualStrings("found extremely long version number", scanProblem(arena, "%YAML 1234567890.1\n--- a\n", &s2));
}

test "mutation 2026-11-27: the context of an anchor and of an alias fault is named apart" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var s: scanner.Scanner = undefined;
    _ = scanProblem(arena, "* a\n", &s);
    try testing.expectEqualStrings("while scanning an alias", s.context);
    _ = scanProblem(arena, "& a\n", &s);
    try testing.expectEqualStrings("while scanning an anchor", s.context);
}

test "mutation 2026-11-27: block scalar header: one indentation digit 1..9 and one chomping sign, at most two indicators" {
    try expectInvalid("--- |a\n");
    try expectProblem("--- |0\n x\n", "found an indentation indicator equal to 0");
    try expectDoc("--- |9\n         x\n", .{}, "\"x\n\"");
    try expectProblem("--- |1+-\n x\n", "did not find expected comment or line break");
}

test "mutation 2026-11-27: a double-quoted scalar keeps a doubled apostrophe, a single-quoted one has no escapes" {
    try expectDoc("\"a''b\"\n", .{}, "\"a''b\"");
    try expectDoc("'a\\\n b'\n", .{}, "\"a\\ b\"");
}

test "mutation 2026-11-27: surrogate pairs of \\u escapes are combined exactly when high is D800..DBFF and low DC00..DFFF" {
    try expectDoc("\"\\uD800\\uDC00\"\n", .{}, "\"\u{10000}\"");
    try expectDoc("\"\\uDBFF\\uDFFF\"\n", .{}, "\"\u{10FFFF}\"");
    try expectDoc("\"\\U0010FFFF\"\n", .{}, "\"\u{10FFFF}\"");
    try expectInvalid("\"\\U0000D800\\uDC00\"\n");
    try expectInvalid("\"\\u0041\\uDC00\"\n");
    try expectInvalid("\"\\uD83DxuDC00\"\n");
    try expectInvalid("\"\\uD83D\\xDC00\"\n");
    try expectInvalid("\"\\uD83D\\uE000\"\n");
}

// ── parser ──────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: a flow-sequence pair with no value before , or ] has an empty value" {
    try expectDoc("[a: , b]\n", .{}, "[{\"a\": ~}, \"b\"]");
    try expectDoc("[a: ]\n", .{}, "[{\"a\": ~}]");
}

test "mutation 2026-11-27: the parser's state stack never grows past max_depth" {
    // 2048 block sequences on one line, then 2100 flow sequences: the scanner
    // allows both (4096 each), the parser's one stack of states holds them all.
    var doc: std.ArrayList(u8) = .empty;
    defer doc.deinit(testing.allocator);
    for (0..2048) |_| try doc.appendSlice(testing.allocator, "- ");
    for (0..2100) |_| try doc.append(testing.allocator, '[');
    try doc.append(testing.allocator, '1');
    for (0..2100) |_| try doc.append(testing.allocator, ']');
    try doc.append(testing.allocator, '\n');
    var p = parser_mod.Parser.init(testing.allocator, doc.items);
    defer p.deinit();
    var most: usize = 0;
    var refused = false;
    while (true) {
        const ev = p.next() catch {
            refused = true;
            break;
        };
        if (ev == null) break;
        most = @max(most, p.states.items.len);
    }
    try testing.expect(refused);
    try testing.expect(most <= scanner.max_depth);
}

test "mutation 2026-11-27: the tag expansion budget (1 MiB) allows exactly its size and no more" {
    const gpa = testing.allocator;
    var doc: std.ArrayList(u8) = .empty;
    defer doc.deinit(gpa);
    try doc.appendSlice(gpa, "%TAG !e! ");
    try doc.appendNTimes(gpa, 'x', 32767); // prefix + the 1-byte suffix = 32768 bytes a use
    try doc.appendSlice(gpa, "\n---\n");
    for (0..32) |_| try doc.appendSlice(gpa, "- !e!a v\n");
    {
        const r = try compose_mod.compose(gpa, doc.items, .{});
        defer r.deinit();
        try testing.expectEqual(@as(usize, 32), r.root.sequence.len);
    }
    try doc.appendSlice(gpa, "- !e!a v\n");
    var d: Diagnostic = .{};
    try testing.expectError(error.InvalidYaml, compose_mod.compose(gpa, doc.items, .{ .diagnostic = &d }));
    try testing.expectEqualStrings("tag expansion over budget", d.problem);
}

// ── composer ────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: Value.at is null past the end and the element inside" {
    const items = [_]Value{ .{ .int = 1 }, .{ .int = 2 } };
    const v: Value = .{ .sequence = &items };
    try testing.expectEqual(@as(i64, 2), v.at(1).?.int);
    try testing.expect(v.at(2) == null);
    try testing.expect(v.at(0) != null);
}

test "mutation 2026-11-27: valueEql compares kind, length, keys and values" {
    const a1 = [_]Value{ .{ .int = 1 }, .{ .int = 2 } };
    const a2 = [_]Value{ .{ .int = 1 }, .{ .int = 2 } };
    const a3 = [_]Value{.{ .int = 1 }};
    const a4 = [_]Value{ .{ .int = 1 }, .{ .int = 3 } };
    try testing.expect(compose_mod.valueEql(.{ .sequence = &a1 }, .{ .sequence = &a2 }));
    try testing.expect(!compose_mod.valueEql(.{ .sequence = &a1 }, .null));
    try testing.expect(!compose_mod.valueEql(.{ .sequence = &a1 }, .{ .sequence = &a3 }));
    try testing.expect(!compose_mod.valueEql(.{ .sequence = &a1 }, .{ .sequence = &a4 }));
    const m1 = [_]Pair{.{ .key = .{ .string = "a" }, .value = .{ .int = 1 } }};
    const m2 = [_]Pair{.{ .key = .{ .string = "a" }, .value = .{ .int = 1 } }};
    const m3 = [_]Pair{.{ .key = .{ .string = "a" }, .value = .{ .int = 2 } }};
    const m4 = [_]Pair{.{ .key = .{ .string = "b" }, .value = .{ .int = 1 } }};
    const m5 = [_]Pair{ m1[0], m1[0] };
    try testing.expect(compose_mod.valueEql(.{ .mapping = &m1 }, .{ .mapping = &m2 }));
    try testing.expect(!compose_mod.valueEql(.{ .mapping = &m1 }, .null));
    try testing.expect(!compose_mod.valueEql(.{ .mapping = &m1 }, .{ .mapping = &m3 }));
    try testing.expect(!compose_mod.valueEql(.{ .mapping = &m1 }, .{ .mapping = &m4 }));
    try testing.expect(!compose_mod.valueEql(.{ .mapping = &m1 }, .{ .mapping = &m5 }));
}

test "mutation 2026-11-27: max_nodes counts every node and allows exactly that many" {
    try expectDoc("[1, 2]\n", .{ .max_nodes = 3 }, "[1, 2]");
    try testing.expectError(error.TooManyNodes, compose_mod.compose(testing.allocator, "[1, 2]\n", .{ .max_nodes = 2 }));
}

/// `count` block-sequence entries `- &<p>0 [x]`, `- &<p>1 [*<p>0]`, ... : the
/// anchor `<p><count-1>` names a value `count` collections deep.
fn aliasChain(gpa: std.mem.Allocator, doc: *std.ArrayList(u8), p: []const u8, count: usize) !void {
    for (0..count) |i| {
        if (i == 0) {
            try doc.print(gpa, "- &{s}0 [x]\n", .{p});
        } else {
            try doc.print(gpa, "- &{s}{d} [*{s}{d}]\n", .{ p, i, p, i - 1 });
        }
    }
}

test "mutation 2026-11-27: a mapping key may nest exactly max_depth (1024) collections through aliases; 1025 is TooDeep" {
    const gpa = testing.allocator;
    {
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);
        try aliasChain(gpa, &doc, "c", 1024);
        try doc.appendSlice(gpa, "- {*c1023 : v}\n");
        const r = try compose_mod.compose(gpa, doc.items, .{});
        r.deinit();
    }
    {
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);
        try aliasChain(gpa, &doc, "c", 1025);
        try doc.appendSlice(gpa, "- {*c1024 : v}\n");
        try testing.expectError(error.TooDeep, compose_mod.compose(gpa, doc.items, .{}));
    }
    {
        // Two separate (not shared) 1024-deep equal keys: a duplicate, not a depth error.
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);
        try aliasChain(gpa, &doc, "a", 1024);
        try aliasChain(gpa, &doc, "b", 1024);
        try doc.appendSlice(gpa, "- {*a1023 : 1, *b1023 : 2}\n");
        try testing.expectError(error.DuplicateKey, compose_mod.compose(gpa, doc.items, .{}));
    }
}

// ── composer: the YAML 1.1 timestamp grammar ────────────────────────────────

test "mutation 2026-11-27: parseTimestamp refuses every near miss of its grammar" {
    const bad = [_][]const u8{
        "20011-12-14", // five-digit year
        "2001x12-14",
        "2001-12x14",
        "2001-12-00", // day 0
        "2001-12-14t1", // hour then the end
        "2001-12-14t21-59:43", // no first colon
        "2001-12-14t21:59", // minutes then the end
        "2001-12-14t21:59-43", // no second colon
        "2001-12-14t21:59:43 ", // blank, then the end
        "2001-12-14t21:59:43 x5", // not a zone
        "2001-12-14t21:59:43 +5x30", // zone hours, no colon, trailing text
    };
    for (bad) |s| try testing.expect(compose_mod.parseTimestamp(s) == null);
}

test "mutation 2026-11-27: parseTimestamp takes the upper edge of every range" {
    try testing.expect(compose_mod.parseTimestamp("2001-12-14t23:59:59") != null);
    try testing.expect(compose_mod.parseTimestamp("2001-12-14t21:59:43") != null); // no fraction, no zone
    try testing.expect(compose_mod.parseTimestamp("2001-12-14t21:59:43 +23:59") != null);
    const z = compose_mod.parseTimestamp("2001-12-14t21:59:43 -5").?;
    try testing.expectEqual(@as(?i32, -300), z.utc_offset_minutes);
}

// ── composer: scalar resolution ─────────────────────────────────────────────

test "mutation 2026-11-27: the JSON schema keeps the empty scalar a string and reads a fraction without an exponent" {
    try expectDoc("a:\n", .{ .schema = .json }, "{\"a\": \"\"}");
    try expectDoc("1.5\n", .{ .schema = .json }, "f1.5");
    const r = try compose_mod.compose(testing.allocator, "1.\n", .{ .schema = .json });
    r.deinit(); // a fraction with no digit ends the text: only that nothing reads past it
}

test "mutation 2026-11-27: core integers: octal digits 0-7 only, a bare sign is no integer, tagged errors" {
    try expectDoc("0o-1\n", .{}, "\"0o-1\"");
    try expectDoc("0o0\n", .{}, "0");
    try expectDoc("0o17\n", .{}, "15");
    try testing.expectError(error.BadTaggedScalar, compose_mod.compose(testing.allocator, "!!int 0o8\n", .{}));
    try testing.expectError(error.BadTaggedScalar, compose_mod.compose(testing.allocator, "!!int \"-\"\n", .{}));
    try testing.expectError(error.BadTaggedScalar, compose_mod.compose(testing.allocator, "!!float \"\"\n", .{}));
}

test "mutation 2026-11-27: a float's digits may not be broken by anything the core schema does not allow" {
    // The core schema's float regular expression has no underscore.
    try expectDoc(".5_5\n", .{}, "\".5_5\"");
    try expectDoc("1.5_5\n", .{}, "\"1.5_5\"");
    try expectDoc("1e5_0\n", .{}, "\"1e5_0\"");
}

// ── encoding ────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: detect: every NUL pattern and mark needs all of its bytes and its length" {
    const E = encoding.Encoding;
    const Case = struct { src: []const u8, want: E };
    const cases = [_]Case{
        // real marks, exactly their length
        .{ .src = "\x00\x00\xFE\xFF", .want = .utf32be },
        .{ .src = "\xFF\xFE\x00\x00", .want = .utf32le },
        .{ .src = "\xFE\xFF", .want = .utf16be },
        .{ .src = "\xFF\xFE", .want = .utf16le },
        .{ .src = "\xEF\xBB\xBF", .want = .utf8 },
        .{ .src = "\x00\x00\x00x", .want = .utf32be },
        .{ .src = "x\x00\x00\x00", .want = .utf32le },
        .{ .src = "\x00x", .want = .utf16be },
        .{ .src = "x\x00", .want = .utf16le },
        // one byte off
        .{ .src = "x\x00\xFE\xFF", .want = .utf16le },
        .{ .src = "\x00x\xFE\xFF", .want = .utf16be },
        .{ .src = "\x00\x00x\xFF", .want = .utf8 },
        .{ .src = "\x00\x00\xFEx", .want = .utf8 },
        .{ .src = "x\xFE\x00\x00", .want = .utf8 },
        .{ .src = "\xFFx\x00\x00", .want = .utf8 },
        .{ .src = "\xFF\xFE\x00x", .want = .utf16le },
        .{ .src = "\xFEx", .want = .utf8 },
        .{ .src = "x\xFE", .want = .utf8 },
        .{ .src = "\xFFx", .want = .utf8 },
        .{ .src = "x\xFF", .want = .utf8 },
        .{ .src = "\x00\xBB\xBF", .want = .utf16be },
        .{ .src = "\xEF\x00\xBF", .want = .utf16le },
        .{ .src = "x\x00\x00y", .want = .utf16le },
        .{ .src = "xy\x00\x00", .want = .utf8 },
        .{ .src = "\x00\x00xy", .want = .utf8 },
        .{ .src = "\x00\x00\x00\x00", .want = .utf8 },
        .{ .src = "\x00\x00", .want = .utf8 },
    };
    for (cases) |c| try testing.expectEqual(c.want, encoding.detect(c.src));
}

fn convert(arena: std.mem.Allocator, src: []const u8, problem: *[]const u8) ![]const u8 {
    return encoding.toUtf8(arena, src, problem);
}

test "mutation 2026-11-27: toUtf8: the surrogate ranges of UTF-16 and the ceiling of UTF-32 are exact" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var problem: []const u8 = "";
    // UTF-16LE after its byte order mark (kept as U+FEFF): D800 DC00 is U+10000, DBFF DFFF is U+10FFFF
    try testing.expectEqualStrings("\u{FEFF}\u{10000}", try convert(arena, "\xFF\xFE\x00\xD8\x00\xDC", &problem));
    try testing.expectEqualStrings("\u{FEFF}\u{10FFFF}", try convert(arena, "\xFF\xFE\xFF\xDB\xFF\xDF", &problem));
    // a high surrogate followed by something above the low range
    try testing.expectError(error.InvalidYaml, convert(arena, "\xFF\xFE\x00\xD8\x00\xE0", &problem));
    // a low surrogate on its own: named as such
    problem = "";
    try testing.expectError(error.InvalidYaml, convert(arena, "\xFF\xFE\x00\xDC\x41\x00", &problem));
    try testing.expect(std.mem.find(u8, problem, "low surrogate") != null);
    problem = "";
    try testing.expectError(error.InvalidYaml, convert(arena, "\xFF\xFE\xFF\xDF\x41\x00", &problem));
    try testing.expect(std.mem.find(u8, problem, "low surrogate") != null);
    // UTF-32LE (after its mark): U+10FFFF is valid, U+110000 is not
    try testing.expectEqualStrings("\u{FEFF}\u{10FFFF}", try convert(arena, "\xFF\xFE\x00\x00\xFF\xFF\x10\x00", &problem));
    try testing.expectError(error.InvalidYaml, convert(arena, "\xFF\xFE\x00\x00\x00\x00\x11\x00", &problem));
}

// ── diagnostic ──────────────────────────────────────────────────────────────

fn render(d: Diagnostic, src: []const u8, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try d.write(&w, src);
    return w.buffered();
}

test "mutation 2026-11-27: Diagnostic.write: a lone CR ends a line, no context line without a context, a mark at the end of the text" {
    var buf: [512]u8 = undefined;
    // CR-only source, mark on the second line
    const d1: Diagnostic = .{ .problem = "p", .mark = .{ .index = 2, .line = 1, .column = 0 }, .positioned = true };
    try testing.expectEqualStrings("p at line 2, column 1\n    b\n    ^\n", try render(d1, "a\rb", &buf));
    // no context text: no "starting at" line
    const d2: Diagnostic = .{ .problem = "p", .mark = .{ .index = 1, .line = 0, .column = 1 }, .positioned = true };
    try testing.expectEqualStrings("p at line 1, column 2\n    a\n     ^\n", try render(d2, "a", &buf));
    // a mark on the empty line after the last break (index == len)
    const d3: Diagnostic = .{ .problem = "p", .mark = .{ .index = 2, .line = 1, .column = 0 }, .positioned = true };
    try testing.expectEqualStrings("p at line 2, column 1\n    \n    ^\n", try render(d3, "a\n", &buf));
}

// ── emitter ─────────────────────────────────────────────────────────────────

fn emitted(v: Value) ![]u8 {
    return emit.stringify(testing.allocator, v);
}

test "mutation 2026-11-27: a string of 32 bytes (not 31) reached twice is written once with an anchor" {
    const s32 = "0123456789012345678901234567890a";
    const s31 = "0123456789012345678901234567890";
    try testing.expectEqual(@as(usize, 32), s32.len);
    const items32 = [_]Value{ .{ .string = s32 }, .{ .string = s32 } };
    const out32 = try emitted(.{ .sequence = &items32 });
    defer testing.allocator.free(out32);
    try testing.expect(std.mem.find(u8, out32, "&a1") != null);
    try testing.expect(std.mem.find(u8, out32, "*a1") != null);
    const items31 = [_]Value{ .{ .string = s31 }, .{ .string = s31 } };
    const out31 = try emitted(.{ .sequence = &items31 });
    defer testing.allocator.free(out31);
    try testing.expect(std.mem.find(u8, out31, "&a1") == null);
}

test "mutation 2026-11-27: isSafePlain: 512 bytes are plain, 513 are quoted" {
    const a512: [512]u8 = @splat('a');
    const a513: [513]u8 = @splat('a');
    try testing.expect(emit.isSafePlain(&a512));
    try testing.expect(!emit.isSafePlain(&a513));
}

test "mutation 2026-11-27: escapes pick the shortest form: U+FFFF is \\uFFFF" {
    const out = try emitted(.{ .string = "\u{FFFF}" });
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("\"\\uFFFF\"\n", out);
}

test "mutation 2026-11-27: floats: 1e20 is plain digits, 1e-7 and 1e30 use the signed exponent with a dot" {
    const Case = struct { x: f64, want: []const u8 };
    const cases = [_]Case{
        .{ .x = 1e20, .want = "100000000000000000000.0\n" },
        .{ .x = 1e-6, .want = "0.000001\n" },
        .{ .x = 1e-7, .want = "1.0e-7\n" },
        .{ .x = 1e30, .want = "1.0e+30\n" },
        .{ .x = 1.5e30, .want = "1.5e+30\n" },
    };
    for (cases) |c| {
        const out = try emitted(.{ .float = c.x });
        defer testing.allocator.free(out);
        try testing.expectEqualStrings(c.want, out);
    }
}

// ── typed ───────────────────────────────────────────────────────────────────

const Link = struct { next: ?*const Link = null };
const Wrap = struct { link: Link };

test "mutation 2026-11-27: typed.toValue follows a value nested exactly 4096 levels (a struct, its optional and its pointer are one level each)" {
    // The wrapper is depth 0, so node j of the chain is at depth 1 + 3 j: the
    // last of 1366 nodes (j = 1365) is at depth 4096, the documented ceiling.
    const n = 1366;
    const nodes = try testing.allocator.alloc(Link, n);
    defer testing.allocator.free(nodes);
    for (nodes, 0..) |*l, i| l.* = .{ .next = if (i + 1 < n) &nodes[i + 1] else null };
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const v = try typed.toValue(arena_state.allocator(), Wrap{ .link = nodes[0] });
    try testing.expect(v == .mapping);
}

test "mutation 2026-11-27: typed: unknown and non-string keys follow ignore_unknown_fields" {
    const T = struct { a: u8 };
    const strict: typed.Options = .{ .ignore_unknown_fields = false };
    {
        const p = try typed.parse(T, testing.allocator, "a: 1\n", strict);
        defer p.deinit();
        try testing.expectEqual(@as(u8, 1), p.value.a);
    }
    try testing.expectError(error.UnknownField, typed.parse(T, testing.allocator, "a: 1\nb: 2\n", strict));
    try testing.expectError(error.UnknownField, typed.parse(T, testing.allocator, "? [1]\n: 2\na: 3\n", strict));
    const p = try typed.parse(T, testing.allocator, "? [1]\n: 2\na: 3\n", .{});
    defer p.deinit();
    try testing.expectEqual(@as(u8, 3), p.value.a);
}

test "mutation 2026-11-27: typed: a union takes a mapping of exactly one string key" {
    const U = union(enum) { a: u8, b: u8 };
    {
        const p = try typed.parse(U, testing.allocator, "a: 1\n", .{});
        defer p.deinit();
        try testing.expectEqual(@as(u8, 1), p.value.a);
    }
    try testing.expectError(error.WrongType, typed.parse(U, testing.allocator, "a: 1\nb: 2\n", .{}));
    try testing.expectError(error.WrongType, typed.parse(U, testing.allocator, "? [1]\n: 2\n", .{}));
}

test "mutation 2026-11-27: typed: NaN maps onto f32, and max_alloc_bytes allows exactly what is allocated" {
    const p = try typed.parse(f32, testing.allocator, ".nan\n", .{});
    defer p.deinit();
    try testing.expect(std.math.isNan(p.value));
    const ok = try typed.parse([]const u32, testing.allocator, "[1, 2, 3]\n", .{ .max_alloc_bytes = 12 });
    ok.deinit();
    try testing.expectError(error.TooLarge, typed.parse([]const u32, testing.allocator, "[1, 2, 3]\n", .{ .max_alloc_bytes = 11 }));
}

// ── composer: the heap budget ───────────────────────────────────────────────

/// A child allocator that never resizes or remaps in place (so the pattern of
/// requests is the same whatever the budget in front of it does) and records
/// the peak of the bytes live at once.
const NoResize = struct {
    gpa: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,
    remaps: usize = 0,

    fn allocator(self: *NoResize) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *NoResize = @ptrCast(@alignCast(ctx));
        const p = self.gpa.rawAlloc(len, a, ra) orelse return null;
        self.live += len;
        self.peak = @max(self.peak, self.live);
        return p;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(ctx: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        const self: *NoResize = @ptrCast(@alignCast(ctx));
        self.remaps += 1;
        return null;
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *NoResize = @ptrCast(@alignCast(ctx));
        self.live -= buf.len;
        self.gpa.rawFree(buf, a, ra);
    }
};

test "mutation 2026-11-27: max_heap_bytes is the most bytes live at once: the peak passes, one byte less is HeapBudgetExceeded" {
    const src = "a: [1, 2, 3, 4, 5, 6, 7, 8]\nb: {c: d, e: f, g: [h, i, j]}\nk: some longer text to take space\n";
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var probe: NoResize = .{ .gpa = arena_state.allocator() };
    _ = try compose_mod.composeAllLeaky(probe.allocator(), src, .{ .max_heap_bytes = null });
    const peak = probe.peak;
    try testing.expect(peak > 0);
    try testing.expect(probe.remaps > 0); // the growth path of the budget is exercised

    var at: NoResize = .{ .gpa = arena_state.allocator() };
    _ = try compose_mod.composeAllLeaky(at.allocator(), src, .{ .max_heap_bytes = peak });
    var under: NoResize = .{ .gpa = arena_state.allocator() };
    try testing.expectError(error.HeapBudgetExceeded, compose_mod.composeAllLeaky(under.allocator(), src, .{ .max_heap_bytes = peak - 1 }));
}

test "mutation 2026-11-27: a plain scalar's continuation line in flow must be indented past the parent block node (YAML 1.2 7.4, as 9C9N)" {
    // The same rule the scanner applies to `[a,\nb]` (suite 9C9N); libyaml
    // accepts both, the spec and the suite do not.
    try expectInvalid("k:\n  [a\nb]\n");
    try expectInvalid("- [a\nb]\n");
    try expectInvalid("k:\n  [a\n\tb]\n");
    try expectDoc("k:\n  [a\n b]\n", .{}, "{\"k\": [\"a b\"]}");
    try expectDoc("[a\nb]\n", .{}, "[\"a b\"]");
}

test "mutation 2026-11-27: `_` in a tag handle and a mid-line U+FEFF are accepted, as libyaml does" {
    // Neither is in YAML 1.2's grammar (`ns-word-char` has no `_`; `nb-char`
    // excludes U+FEFF), and neither is a MUST to refuse: libyaml / PyYAML 6.0.3
    // accept both and this module behaves like them (CONVENTIONS: reference
    // behaviour where the spec does not mandate one).
    try expectDoc("%TAG !my_x! tag:example.com,2000:\n--- !my_x!foo bar\n", .{}, "\"bar\"");
    try expectDoc("a:  \u{feff}b\n", .{}, "{\"a\": \"\u{feff}b\"}");
    try expectDoc("[a,\u{feff}b]\n", .{}, "[\"a\", \"\u{feff}b\"]");
}
