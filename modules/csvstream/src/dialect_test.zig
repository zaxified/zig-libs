// SPDX-License-Identifier: MIT
//! Dialect options (S2, 2026-10-20): escape byte, `double_quote`, trim,
//! `strict`, comment lines, record positions, field-count policy,
//! `readHeader`, writer quote styles. Hand cases here pin the rules; the
//! Python/Go differential over the same options is `oracle_test.zig`.

const std = @import("std");
const t = std.testing;
const line = @import("line.zig");
const stream = @import("stream.zig");
const writer = @import("writer.zig");

fn expectSplit(rec: []const u8, opts: line.SplitOptions, want: []const []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var buf: [16][]const u8 = undefined;
    const got = try line.splitFieldsOpts(rec, &buf, ',', '"', arena.allocator(), opts);
    try t.expectEqual(want.len, got.len);
    for (want, got) |w, g| try t.expectEqualStrings(w, g);
    // The count agrees with the split under the same options.
    try t.expectEqual(want.len, line.countFieldsOpts(rec, ',', '"', opts));
}

test "escape byte inside quotes (rust-csv escape + double_quote=false)" {
    const o: line.SplitOptions = .{ .escape = '\\', .double_quote = false };
    try expectSplit("\"a\\\"b\",c", o, &.{ "a\"b", "c" });
    try expectSplit("\"a\\,b\",c", o, &.{ "a,b", "c" });
    try expectSplit("\"a\\\\\",c", o, &.{ "a\\", "c" }); // escaped escape, then the closing quote
    // Outside quotes the escape byte is an ordinary byte.
    try expectSplit("a\\b,c", o, &.{ "a\\b", "c" });
    // An escape as the record's last byte inside an open quote stays literal.
    try expectSplit("\"a\\", o, &.{"a\\"});
    // Both escapes at once: `""` still works when double_quote stays on.
    try expectSplit("\"a\"\"b\\\"c\"", .{ .escape = '\\' }, &.{"a\"b\"c"});
}

test "double_quote=false: a doubled quote is two lazy literal quotes" {
    try expectSplit("\"a\"\"b\",c", .{ .double_quote = false }, &.{ "a\"\"b", "c" });
}

test "escape equal to the quote is ignored" {
    try expectSplit("\"a\"\"b\",c", .{ .escape = '"' }, &.{ "a\"b", "c" });
}

test "trim leading: blanks before a field, a quote after them still opens it" {
    const o: line.SplitOptions = .{ .trim = .leading };
    try expectSplit("  a, b ,\t\"c,d\"", o, &.{ "a", "b ", "c,d" });
    try expectSplit(" , ", o, &.{ "", "" });
}

test "trim all: blanks after unquoted fields and after a closing quote; inside quotes kept" {
    const o: line.SplitOptions = .{ .trim = .all };
    try expectSplit("  a  , \" b \"  ,c", o, &.{ "a", " b ", "c" });
    try expectSplit("\"x\"  ", o, &.{"x"});
    try expectSplit("a ,", o, &.{ "a", "" });
}

test "trim never eats a tab delimiter" {
    var buf: [8][]const u8 = undefined;
    const got = try line.splitFieldsOpts("a\t\tb", &buf, '\t', '"', t.allocator, .{ .trim = .all });
    try t.expectEqual(@as(usize, 3), got.len);
    try t.expectEqualStrings("", got[1]);
}

test "strict: bare quote, extraneous quote, unterminated quote with column" {
    var buf: [8][]const u8 = undefined;
    var d: line.SplitDiag = .{};
    const o: line.SplitOptions = .{ .strict = true, .diag = &d };
    try t.expectError(error.BareQuote, line.splitFieldsOpts("ab,c\"d", &buf, ',', '"', t.allocator, o));
    try t.expectEqual(@as(usize, 4), d.column);
    try t.expectError(error.ExtraneousQuote, line.splitFieldsOpts("x,\"a\"b", &buf, ',', '"', t.allocator, o));
    try t.expectEqual(@as(usize, 4), d.column);
    try t.expectError(error.UnterminatedQuote, line.splitFieldsOpts("x,\"ab", &buf, ',', '"', t.allocator, o));
    try t.expectEqual(@as(usize, 2), d.column);
    // Well-formed input is read as without `strict`.
    const ok = try line.splitFieldsOpts("\"a\"\"b\",c", &buf, ',', '"', t.allocator, .{ .strict = true });
    defer line.freeFields("\"a\"\"b\",c", ok, t.allocator);
    try t.expectEqualStrings("a\"b", ok[0]);
}

test "strict error frees the copies made before it" {
    var buf: [8][]const u8 = undefined;
    // testing.allocator reports a leak if the first field's copy survives.
    try t.expectError(error.BareQuote, line.splitFieldsOpts("\"a\"\"b\",c\"d", &buf, ',', '"', t.allocator, .{ .strict = true }));
}

fn collect(it: *line.LineIterator, out: []line.LineSlice) usize {
    var n: usize = 0;
    while (it.next()) |r| : (n += 1) out[n] = r;
    return n;
}

test "comment lines are skipped in both modes; their quotes open nothing" {
    const input = "# a \"comment\nx,1\n#\"\ny,\"2\n3\"\n";
    var recs: [8]line.LineSlice = undefined;

    var lazy = line.LineIterator.initOpts(input, 0, .{ .comment = '#' });
    const n1 = collect(&lazy, &recs);
    try t.expectEqual(@as(usize, 3), n1); // `y,"2` and `3"` are separate lines in lazy mode
    try t.expectEqualStrings("x,1", recs[0].bytes);
    try t.expectEqual(@as(u64, 2), recs[0].line_number);

    var span = line.LineIterator.initSpan(input, '"', 0, .{ .comment = '#' });
    const n2 = collect(&span, &recs);
    try t.expectEqual(@as(usize, 2), n2);
    try t.expectEqualStrings("x,1", recs[0].bytes);
    try t.expectEqualStrings("y,\"2\n3\"", recs[1].bytes);
    try t.expectEqual(@as(u64, 4), recs[1].line_number);
    try t.expect(recs[1].spanned);

    // A comment char not at the record start is data.
    var mid = line.LineIterator.initOpts("a,#b\n", 0, .{ .comment = '#' });
    try t.expectEqualStrings("a,#b", mid.next().?.bytes);
}

test "line_number and record_index count physical lines and returned records" {
    const input = "a\n\nb\r\n\"c\nd\"\ne";
    var recs: [8]line.LineSlice = undefined;
    var span = line.LineIterator.initSpan(input, '"', 0, .{});
    const n = collect(&span, &recs);
    try t.expectEqual(@as(usize, 4), n);
    const lines = [_]u64{ 1, 3, 4, 6 };
    for (recs[0..n], 0..) |r, i| {
        try t.expectEqual(lines[i], r.line_number);
        try t.expectEqual(@as(u64, i), r.record_index);
    }
    var lazy = line.LineIterator.init(input, '"', 0);
    const n2 = collect(&lazy, &recs);
    try t.expectEqual(@as(usize, 5), n2);
    try t.expectEqual(@as(u64, 5), recs[3].line_number); // `d"`
    try t.expectEqual(@as(u64, 6), recs[4].line_number); // `e`
}

test "span scanner closes a quote where the split does: escape and trim=all" {
    // `\"` must not close the field, so the newline after it is quoted.
    const input = "\"a\\\"\nb\",c\nd,e\n";
    var it = line.LineIterator.initSpan(input, '"', 0, .{ .escape = '\\', .double_quote = false });
    const r = it.next().?;
    try t.expectEqualStrings("\"a\\\"\nb\",c", r.bytes);
    try expectSplit(r.bytes, .{ .escape = '\\', .double_quote = false }, &.{ "a\"\nb", "c" });
    // trim=all: `"x"  ,` closes, so the next line is a new record.
    var it2 = line.LineIterator.initSpan("\"x\"  ,1\ny,2\n", '"', 0, .{ .trim = .all });
    try t.expectEqualStrings("\"x\"  ,1", it2.next().?.bytes);
    try t.expectEqualStrings("y,2", it2.next().?.bytes);
}

fn withFile(body: []const u8, opts: stream.StreamReader.Options, f: *const fn (*stream.StreamReader) anyerror!void) !void {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var file = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer file.close(t.io);
    var r = try stream.StreamReader.init(t.io, t.allocator, file, opts);
    defer r.deinit();
    try f(&r);
}

test "StreamReader: positions continue across chunks" {
    // Chunks of 8 bytes force many re-inits of the per-chunk iterator.
    try withFile("aa,1\n\nbb,2\n# c\ncc,3\ndd,4\n", .{ .chunk_size = 8, .max_record_len = 16, .comment = '#' }, struct {
        fn run(r: *stream.StreamReader) !void {
            const want_lines = [_]u64{ 1, 3, 5, 6 };
            var i: usize = 0;
            while (try r.next()) |rec| : (i += 1) {
                try t.expectEqual(want_lines[i], rec.line_number);
                try t.expectEqual(@as(u64, i), rec.record_index);
            }
            try t.expectEqual(@as(usize, 4), i);
        }
    }.run);
}

test "StreamReader: fields_per_record first_record refuses a ragged row and names it" {
    try withFile("a,b\n1,2\n3\n4,5\n", .{ .fields_per_record = .first_record }, struct {
        fn run(r: *stream.StreamReader) !void {
            var buf: [4][]const u8 = undefined;
            _ = (try r.nextFields(&buf, t.allocator)).?;
            _ = (try r.nextFields(&buf, t.allocator)).?;
            try t.expectError(error.FieldCountMismatch, r.nextFields(&buf, t.allocator));
            try t.expectEqual(@as(u64, 3), r.last.line_number);
            try t.expectEqual(@as(u64, 2), r.last.record_index);
            // The reader goes on after the refusal.
            try t.expectEqual(@as(usize, 2), (try r.nextFields(&buf, t.allocator)).?.len);
        }
    }.run);
}

test "StreamReader: fields_per_record count frees copies of a refused row" {
    try withFile("\"a\"\"b\",c,d\n", .{ .fields_per_record = .{ .count = 2 } }, struct {
        fn run(r: *stream.StreamReader) !void {
            var buf: [4][]const u8 = undefined;
            try t.expectError(error.FieldCountMismatch, r.nextFields(&buf, t.allocator));
        }
    }.run);
}

test "StreamReader: readHeader, then rows looked up by name, with trim and escape" {
    try withFile(" id, \"na\\\"me\"\n 7, \"Bo\\\"b\"\n", .{ .trim = .all, .escape = '\\', .double_quote = false }, struct {
        fn run(r: *stream.StreamReader) !void {
            var buf: [4][]const u8 = undefined;
            var h = (try r.readHeader(&buf, t.allocator)).?;
            defer h.deinit();
            try t.expectEqual(@as(usize, 2), h.len());
            var arena: std.heap.ArenaAllocator = .init(t.allocator);
            defer arena.deinit();
            const row = (try r.nextFields(&buf, arena.allocator())).?;
            try t.expectEqualStrings("7", h.get(row, "id").?);
            try t.expectEqualStrings("Bo\"b", h.get(row, "na\"me").?);
            try t.expect((try r.readHeader(&buf, t.allocator)) == null);
        }
    }.run);
}

test "StreamReader: strict refuses through nextFields; last names the record" {
    try withFile("a,b\nc,d\"e\n", .{ .strict = true }, struct {
        fn run(r: *stream.StreamReader) !void {
            var buf: [4][]const u8 = undefined;
            _ = (try r.nextFields(&buf, t.allocator)).?;
            var d: line.SplitDiag = .{};
            try t.expectError(error.BareQuote, r.nextFieldsOpts(&buf, t.allocator, .{ .diag = &d }));
            try t.expectEqual(@as(usize, 3), d.column);
            try t.expectEqual(@as(u64, 2), r.last.line_number);
        }
    }.run);
}

fn expectWrite(fields: []const []const u8, opts: writer.WriteOptions, want: []const u8) !void {
    var out: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writer.writeRecord(&w, fields, opts);
    try t.expectEqualStrings(want, w.buffered());
}

test "lazy unbalanced flag: an escaped quote inside quotes does not toggle" {
    var it = line.LineIterator.initOpts("\"a\\\"\n", 0, .{ .escape = '\\' });
    try t.expect(it.next().?.unbalanced_quote); // `"a\"`: the second quote is escaped, the field stays open
    var plain = line.LineIterator.initOpts("\"a\\\"\n", 0, .{});
    try t.expect(!plain.next().?.unbalanced_quote); // without the escape: open, close
}

test "writer quotes a first field that starts with the comment byte" {
    try expectWrite(&.{ "#x", "#y" }, .{ .comment = '#', .line_terminator = .lf }, "\"#x\",#y\n");
    try expectWrite(&.{ "#x", "y" }, .{ .line_terminator = .lf }, "#x,y\n");
}

test "nextFieldsOpts: caller strict turns strictness on for the call" {
    try withFile("a\"b\n", .{}, struct {
        fn run(r: *stream.StreamReader) !void {
            var buf: [4][]const u8 = undefined;
            try t.expectError(error.BareQuote, r.nextFieldsOpts(&buf, t.allocator, .{ .strict = true }));
        }
    }.run);
}

test "writer quote styles" {
    try expectWrite(&.{ "a", "", "b c" }, .{ .quote_style = .always, .line_terminator = .lf }, "\"a\",\"\",\"b c\"\n");
    try expectWrite(&.{ "a", "x,y" }, .{ .quote_style = .never, .line_terminator = .lf }, "a,x,y\n");
    try expectWrite(&.{""}, .{ .quote_style = .never, .line_terminator = .lf }, "\n");
    try expectWrite(&.{ "a", "x,y" }, .{ .line_terminator = .lf }, "a,\"x,y\"\n");
}

test "writer escape dialect round-trips through the escape reader" {
    const fields = [_][]const u8{ "say \"hi\"", "back\\slash", "plain" };
    var out: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writer.writeRecord(&w, &fields, .{ .escape = '\\', .quote_style = .always, .line_terminator = .lf });
    try t.expectEqualStrings("\"say \\\"hi\\\"\",\"back\\\\slash\",\"plain\"\n", w.buffered());
    const rec = w.buffered()[0 .. w.buffered().len - 1];
    try expectSplit(rec, .{ .escape = '\\', .double_quote = false }, &fields);
}
