// SPDX-License-Identifier: MIT
//! Where a malformed document went wrong, in a form a caret diagnostic can be
//! drawn from. `Parser.problem` / `problem_mark` / `context` / `context_mark`
//! are libyaml's four fields (the fault, the place the scanner stood when it
//! found it, and, when the fault is inside a quoted scalar, an anchor, a tag, a
//! block scalar, a directive or a plain scalar, where that construct began);
//! `ComposeOptions.diagnostic` hands the same to a caller of `compose`.

const std = @import("std");
const parser = @import("parser.zig");
const Mark = parser.Mark;

pub const Diagnostic = struct {
    /// What is wrong (a static string; the error name when the composer, not
    /// the parser, refused the stream: a duplicate key, a budget, an alias).
    problem: []const u8 = "",
    /// Where the scanner or parser stood. Zero when `problem` came from the
    /// composer, which carries no position.
    mark: Mark = .{},
    /// "while scanning a quoted scalar", ... or empty.
    context: []const u8 = "",
    /// Start of the construct `context` names.
    context_mark: Mark = .{},
    /// True when `mark` / `context_mark` say something (a parser or scanner
    /// problem), false for a composer-level refusal.
    positioned: bool = false,

    pub fn fromParser(p: *const parser.Parser, err: anyerror) Diagnostic {
        if (p.problem.len == 0) return .{ .problem = @errorName(err) };
        return .{
            .problem = p.problem,
            .mark = p.problem_mark,
            .context = p.context,
            .context_mark = p.context_mark,
            .positioned = true,
        };
    }

    /// Render for a person, with the source line and a caret:
    ///
    ///     did not find expected alphabetic or numeric character at line 2, column 7
    ///         key: &
    ///               ^
    ///     while scanning an anchor starting at line 2, column 6
    ///
    /// Lines and columns count from 1, columns in characters. `source` is the
    /// text that was parsed.
    pub fn write(self: Diagnostic, w: *std.Io.Writer, source: []const u8) std.Io.Writer.Error!void {
        if (!self.positioned) return w.print("{s}\n", .{self.problem});
        try w.print("{s} at line {d}, column {d}\n", .{ self.problem, self.mark.line + 1, self.mark.column + 1 });
        try snippet(w, source, self.mark.index);
        if (self.context.len > 0) {
            try w.print("{s} starting at line {d}, column {d}\n", .{ self.context, self.context_mark.line + 1, self.context_mark.column + 1 });
        }
    }
};

/// How much of a line is shown on each side of the mark.
const window = 60;

fn isBreak(b: u8) bool {
    return b == '\n' or b == '\r';
}

fn snippet(w: *std.Io.Writer, source: []const u8, index: usize) std.Io.Writer.Error!void {
    const at = @min(index, source.len);
    var start = at;
    while (start > 0 and !isBreak(source[start - 1])) start -= 1;
    var end = at;
    while (end < source.len and !isBreak(source[end])) end += 1;
    // A very long line is shown around the mark only.
    var from = start;
    if (at - from > window) from = at - window;
    while (from < at and source[from] & 0xc0 == 0x80) from += 1; // not inside a character
    var to = end;
    if (to - at > window) to = at + window;
    while (to < end and source[to] & 0xc0 == 0x80) to += 1;
    try w.writeAll("    ");
    try w.writeAll(source[from..to]);
    try w.writeAll("\n    ");
    for (source[from..at]) |b| {
        if (b & 0xc0 == 0x80) continue; // continuation byte: same character
        try w.writeByte(if (b == '\t') '\t' else ' ');
    }
    try w.writeAll("^\n");
}

test "Diagnostic.write: the line, a caret under the mark, the construct's start" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = parser.Parser.init(arena.allocator(), "k: 1\nkey: &\n");
    defer p.deinit();
    while (true) {
        const ev = p.next() catch break;
        if (ev == null) return error.TestUnexpectedResult;
    }
    const d = Diagnostic.fromParser(&p, error.InvalidYaml);
    try std.testing.expectEqualStrings("while scanning an anchor", d.context);
    try std.testing.expectEqual(@as(usize, 1), d.context_mark.line);
    try std.testing.expectEqual(@as(usize, 5), d.context_mark.column);
    try std.testing.expectEqual(@as(usize, 6), d.mark.column);
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try d.write(&w, "k: 1\nkey: &\n");
    try std.testing.expectEqualStrings(
        "did not find expected alphabetic or numeric character at line 2, column 7\n" ++
            "    key: &\n" ++
            "          ^\n" ++
            "while scanning an anchor starting at line 2, column 6\n",
        w.buffered(),
    );
}

test "Diagnostic.write: tabs are kept, multi-byte characters take one column, a long line is windowed" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const src = "\tx\xc3\xa9y: z";
    try snippet(&w, src, 4); // at the `y`
    try std.testing.expectEqualStrings("    \tx\xc3\xa9y: z\n    \t  ^\n", w.buffered());

    var long: [300]u8 = @splat('a');
    var w2: std.Io.Writer = .fixed(&buf);
    try snippet(&w2, &long, 200);
    // 60 characters either side of the mark, caret under the 61st.
    try std.testing.expectEqual(@as(usize, 4 + 120 + 1 + 4 + 60 + 2), w2.buffered().len);
}

test "Diagnostic: a composer-level refusal has a problem and no position" {
    var d: Diagnostic = .{};
    const compose = @import("compose.zig");
    try std.testing.expectError(error.DuplicateKey, compose.compose(std.testing.allocator, "a: 1\na: 2\n", .{ .diagnostic = &d }));
    try std.testing.expectEqualStrings("DuplicateKey", d.problem);
    try std.testing.expect(!d.positioned);
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try d.write(&w, "a: 1\na: 2\n");
    try std.testing.expectEqualStrings("DuplicateKey\n", w.buffered());

    // A malformed stream carries the scanner's words and marks.
    var e: Diagnostic = .{};
    try std.testing.expectError(error.InvalidYaml, compose.compose(std.testing.allocator, "a: \"abc\n", .{ .diagnostic = &e }));
    try std.testing.expect(e.positioned);
    try std.testing.expectEqualStrings("while scanning a quoted scalar", e.context);
    try std.testing.expectEqual(@as(usize, 3), e.context_mark.index);
    // Nothing is written on success.
    var ok: Diagnostic = .{ .problem = "kept" };
    const good = try compose.compose(std.testing.allocator, "a: 1\n", .{ .diagnostic = &ok });
    good.deinit();
    try std.testing.expectEqualStrings("kept", ok.problem);
}
