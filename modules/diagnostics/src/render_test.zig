// SPDX-License-Identifier: MIT
//! Display width, line endings, term_width, charsets and context lines of the
//! snippet renderer.

const std = @import("std");
const dg = @import("root.zig");
const testing = std.testing;

fn render(d: dg.Diagnostic, text: []const u8, o: dg.RenderOptions) ![]u8 {
    const src = [_]dg.Source{.{ .file = "f", .text = text }};
    var opts = o;
    opts.style = .snippet;
    opts.sources = &src;
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    try dg.renderOne(&out.writer, d, opts);
    return out.toOwnedSlice();
}

fn diag(line: u32, col: u32, end_col: u32) dg.Diagnostic {
    return .{ .path = "", .file = "f", .line = line, .col = col, .end_line = line, .end_col = end_col, .severity = .@"error", .code = "", .message = "m", .span_message = "here" };
}

fn expectRender(want: []const u8, d: dg.Diagnostic, text: []const u8, o: dg.RenderOptions) !void {
    const got = try render(d, text, o);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "charWidth: wide, combining, zero-width, emoji, controls (unicode-width 0.2.2)" {
    try testing.expectEqual(@as(u2, 1), dg.charWidth('a'));
    try testing.expectEqual(@as(u2, 1), dg.charWidth(0x00e9)); // e acute
    try testing.expectEqual(@as(u2, 1), dg.charWidth(0x03a9)); // Omega (ambiguous: narrow)
    try testing.expectEqual(@as(u2, 2), dg.charWidth(0x8def)); // CJK ideograph
    try testing.expectEqual(@as(u2, 2), dg.charWidth(0xff21)); // fullwidth A
    try testing.expectEqual(@as(u2, 2), dg.charWidth(0xac00)); // Hangul syllable
    try testing.expectEqual(@as(u2, 2), dg.charWidth(0x1f600)); // emoji presentation
    try testing.expectEqual(@as(u2, 2), dg.charWidth(0x1f404)); // cow
    try testing.expectEqual(@as(u2, 1), dg.charWidth(0x2603)); // snowman: text presentation
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0x0301)); // combining acute
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0x200d)); // ZWJ
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0x200b)); // ZWSP
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0xfe0f)); // variation selector 16
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0xfeff)); // BOM / ZWNBSP
    try testing.expectEqual(@as(u2, 2), dg.charWidth(0x1f3fb)); // emoji modifier
    try testing.expectEqual(@as(u2, 1), dg.charWidth(0x10fffd)); // past the last range
    try testing.expectEqual(@as(u2, 3), dg.charWidth(0x17d8)); // the crate gives Khmer beyyal 3
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0x00ad)); // soft hyphen
    try testing.expectEqual(@as(u2, 0), dg.charWidth(0x0007)); // control: no width
}

test "carets line up under wide, combining and emoji characters" {
    // Two ideographs (4 columns), then the spanned `x` (byte column 7).
    try expectRender("error: m\n  --> f:1:7\n  |\n1 | 路濫x\n  |     ^ here\n\n", diag(1, 7, 8), "路濫x", .{});
    try expectRender("error: m\n  --> f:1:3\n  |\n1 | 路濫x\n  |     ^ here\n\n", diag(1, 7, 8), "路濫x", .{ .column = .char });
    // `e` + combining acute (zero columns) + `x`.
    try expectRender("error: m\n  --> f:1:4\n  |\n1 | e\u{301}x\n  |  ^ here\n\n", diag(1, 4, 5), "e\u{301}x", .{});
    // An emoji is two columns.
    try expectRender("error: m\n  --> f:1:5\n  |\n1 | \u{1F600}x\n  |   ^ here\n\n", diag(1, 5, 6), "\u{1F600}x", .{});
    // A span over a wide character underlines both of its columns.
    try expectRender("error: m\n  --> f:1:2\n  |\n1 | a路b\n  |  ^^ here\n\n", diag(1, 2, 5), "a路b", .{});
    // A tab still aligns to the next multiple of tab_width, after a wide character.
    try expectRender("error: m\n  --> f:1:5\n  |\n1 | 路 x\n  |    ^ here\n\n", diag(1, 5, 6), "路\tx", .{ .tab_width = 3 });
}

test "a span that starts or ends inside a character: the column, the carets" {
    const cow = "\u{1F404}\u{1F311}"; // two 4-byte characters
    // Bytes 1..3 of the first one: its two columns, and the character column 1.
    try expectRender("error: m\n  --> f:1:1\n  |\n1 | \u{1F404}\u{1F311}\n  | ^^ here\n\n", diag(1, 2, 4), cow, .{ .column = .char });
    try expectRender("error: m\n  --> f:1:2\n  |\n1 | \u{1F404}\u{1F311}\n  | ^^ here\n\n", diag(1, 2, 4), cow, .{});
    // Starting on the second character: one character wholly before it.
    try expectRender("error: m\n  --> f:1:2\n  |\n1 | \u{1F404}\u{1F311}\n  |   ^^ here\n\n", diag(1, 5, 7), cow, .{ .column = .char });
}

test "line endings and control characters in the quoted line" {
    // A lone CR is not a line break (as in codespan and rustc): it is a control
    // character, shown as `?`; line 2 is after the `\n`.
    try expectRender("error: m\n  --> f:1:3\n  |\n1 | a?b\n  |   ^ here\n\n", diag(1, 3, 4), "a\rb\nc", .{});
    try expectRender("error: m\n  --> f:2:1\n  |\n2 | c\n  | ^ here\n\n", diag(2, 1, 2), "a\rb\nc", .{});
    // CRLF: the CR is part of the break.
    try expectRender("error: m\n  --> f:2:1\n  |\n2 | c\n  | ^ here\n\n", diag(2, 1, 2), "a\r\nc", .{});
    // U+2028 / U+2029 are not breaks either, and are shown as `?`.
    try expectRender("error: m\n  --> f:1:5\n  |\n1 | a?b\n  |   ^ here\n\n", diag(1, 5, 6), "a\u{2028}b", .{});
    try expectRender("error: m\n  --> f:1:5\n  |\n1 | a?b\n  |   ^ here\n\n", diag(1, 5, 6), "a\u{2029}b", .{});
    // A C1 control (U+009B is CSI to some terminals) is never written raw.
    try expectRender("error: m\n  --> f:1:4\n  |\n1 | a?b\n  |   ^ here\n\n", diag(1, 4, 5), "a\u{9b}b", .{});
    // An invalid byte is one `?` column.
    try expectRender("error: m\n  --> f:1:3\n  |\n1 | a?b\n  |   ^ here\n\n", diag(1, 3, 4), "a\xffb", .{});
    // A UTF-8 BOM opening the text: not written, no column; the byte column
    // counts its three bytes, the character column does not.
    try expectRender("error: m\n  --> f:1:4\n  |\n1 | ab\n  | ^ here\n\n", diag(1, 4, 5), "\u{FEFF}ab", .{});
    try expectRender("error: m\n  --> f:1:1\n  |\n1 | ab\n  | ^ here\n\n", diag(1, 4, 5), "\u{FEFF}ab", .{ .column = .char });
}

test "before_label_lines and after_label_lines: shown, clamped, the gutter is not widened" {
    const text = "l1\nl2\nl3\nl4\nl5\nl6\nl7\n";
    try expectRender("error: m\n  --> f:4:1\n  |\n3 | l3\n4 | l4\n  | ^ here\n5 | l5\n6 | l6\n\n", diag(4, 1, 2), text, .{ .before_label_lines = 1, .after_label_lines = 2 });
    // Clamped at both ends of the source.
    try expectRender("error: m\n  --> f:1:1\n  |\n1 | a\n  | ^ here\n2 | b\n\n", diag(1, 1, 2), "a\nb", .{ .before_label_lines = 5, .after_label_lines = 5 });
    // Like codespan, a context line with a wider number than the labelled
    // ones sticks out of the gutter.
    try expectRender("error: m\n  --> f:9:1\n  |\n9 | x\n  | ^ here\n10 | x\n\n", diag(9, 1, 2), "x\nx\nx\nx\nx\nx\nx\nx\nx\nx", .{ .after_label_lines = 1 });
    // Two lines apart: the gap is one line, shown; farther: a break.
    try expectRender("error: m\n  --> f:1:1\n  |\n1 | l1\n  | ^^ here\n2 | l2\n3 | l3\n  .\n6 | l6\n  | -- other\n7 | l7\n\n", .{
        .path = "",
        .file = "f",
        .line = 1,
        .col = 1,
        .end_line = 1,
        .end_col = 3,
        .severity = .@"error",
        .code = "",
        .message = "m",
        .span_message = "here",
        .labels = &.{.{ .line = 6, .col = 1, .end_line = 6, .end_col = 3, .message = "other" }},
    }, "l1\nl2\nl3\nl4\nl5\nl6\nl7", .{ .after_label_lines = 2 });
}

test "chars = .unicode draws box characters, in every part of the layout" {
    try expectRender("error: m\n  \u{250c}\u{2500} f:1:1\n  \u{2502}\n1 \u{2502} a\n  \u{2502} ^ here\n\n", diag(1, 1, 2), "a", .{ .chars = .unicode });
    // A multi-line span: the corner, the bars and the closing corner.
    var d = diag(1, 2, 3);
    d.end_line = 5;
    d.end_col = 2;
    try expectRender(
        "error: m\n  \u{250c}\u{2500} f:1:2\n  \u{2502}  \n1 \u{2502}   a b\n  \u{2502} \u{256d}\u{2500}\u{2500}^\n" ++
            "2 \u{2502} \u{2502} c\n3 \u{2502} \u{2502} d\n4 \u{2502} \u{2502} e\n5 \u{2502} \u{2502} e2\n  \u{2502} \u{2570}\u{2500}^ here\n\n",
        d,
        "a b\nc\nd\ne\ne2\nf",
        .{ .chars = .unicode },
    );
}

test "term_width cuts a long line around the span, the carets stay aligned" {
    var long: [120]u8 = undefined;
    for (&long, 0..) |*c, i| c.* = '0' + @as(u8, @intCast(i % 10));
    // Right-cut only: the line fits once trimmed from the right.
    try expectRender("error: m\n  --> f:1:61\n  |\n1 | 0123456789012345678901234567890123456789012345678901234567890123456789012...\n" ++
        "  |                                                             ^^^^^ here\n\n", diag(1, 61, 66), &long, .{ .term_width = 80 });
    // Cut on both sides, centred on the span (annotate-snippets `Margin`).
    try expectRender("error: m\n  --> f:1:61\n  |\n1 | ...012345678901234567890123456789...\n  |              ^^^^^ here\n\n", diag(1, 61, 66), &long, .{ .term_width = 40 });
    // A width the line fits in, or no width: nothing is cut.
    const full = try render(diag(1, 61, 66), &long, .{});
    defer testing.allocator.free(full);
    const wide = try render(diag(1, 61, 66), &long, .{ .term_width = 200 });
    defer testing.allocator.free(wide);
    try testing.expectEqualStrings(full, wide);
}

test "term_width: the caret is under the spanned character whatever the cut" {
    var prng: std.Random.DefaultPrng = .init(0x7E12);
    const rnd = prng.random();
    var text: [200]u8 = undefined;
    for (0..2000) |_| {
        const n = 1 + rnd.uintLessThan(usize, text.len);
        for (text[0..n], 0..) |*c, i| c.* = if (rnd.uintLessThan(u8, 6) == 0) ' ' else 'a' + @as(u8, @intCast(i % 26));
        const start = rnd.uintLessThan(usize, n);
        const end = @min(n, start + 1 + rnd.uintLessThan(usize, 12));
        const tw: u16 = 12 + rnd.uintLessThan(u16, 100);
        var d = diag(1, @intCast(start + 1), @intCast(end + 1));
        d.span_message = if (rnd.boolean()) "message" else null;
        const got = try render(d, text[0..n], .{ .term_width = tw });
        defer testing.allocator.free(got);
        var lines = std.mem.splitScalar(u8, got, '\n');
        var src_row: ?[]const u8 = null;
        var caret_row: ?[]const u8 = null;
        while (lines.next()) |l| {
            if (std.mem.startsWith(u8, l, "1 | ")) src_row = l;
            if (src_row != null and std.mem.startsWith(u8, l, "  | ") and std.mem.findScalar(u8, l, '^') != null) {
                caret_row = l;
                break;
            }
        }
        const sr = src_row.?;
        const cr = caret_row.?;
        const col = std.mem.findScalar(u8, cr, '^').?;
        // Under the first caret is the spanned character, unless a `...` covers it.
        if (col < sr.len and sr[col] != '.') try testing.expectEqual(text[start], sr[col]);
        // A cut line is never wider than the terminal (the label may be).
        if (tw >= end - start + 16) try testing.expect(sr.len <= tw);
    }
}

test "term_width: tiny widths, wide characters and multi-line spans stay bounded" {
    const text = "\u{8def}\u{6fab}x \u{1F404}y\nsecond line here\n\tthird\u{301} line\nfourth";
    for ([_]u16{ 0, 1, 3, 5, 8, 12, 30 }) |tw| {
        var d = diag(1, 1, 3);
        d.end_line = 4;
        d.end_col = 3;
        d.labels = &.{.{ .line = 2, .col = 3, .end_line = 2, .end_col = 9, .message = "label" }};
        const got = try render(d, text, .{ .term_width = tw, .chars = .unicode });
        defer testing.allocator.free(got);
        try testing.expect(std.mem.endsWith(u8, got, "\n\n"));
    }
}
