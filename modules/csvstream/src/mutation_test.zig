// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-25 delta mutation run (sniff, record, StreamReader.seekTo, dialect checks).
const std = @import("std");
const t = std.testing;
const sniffmod = @import("sniff.zig");
const recmod = @import("record.zig");
const header = @import("header.zig");
const stream = @import("stream.zig");
const line = @import("line.zig");

/// `pre ++ s * n ++ post` on the testing allocator (array `**` is gone in 0.17).
fn rep(pre: []const u8, s: []const u8, n: usize, post: []const u8) ![]u8 {
    const out = try t.allocator.alloc(u8, pre.len + s.len * n + post.len);
    @memcpy(out[0..pre.len], pre);
    for (0..n) |i| @memcpy(out[pre.len + i * s.len ..][0..s.len], s);
    @memcpy(out[pre.len + s.len * n ..], post);
    return out;
}

fn sn(sample: []const u8, opts: sniffmod.SniffOptions) !sniffmod.Dialect {
    return sniffmod.sniff(sample, opts) orelse error.TestUnexpectedResult;
}

fn expectD(sample: []const u8, delim: u8, quote: u8) !void {
    const d = try sn(sample, .{});
    try t.expectEqual(delim, d.delimiter);
    try t.expectEqual(quote, d.quote);
}

test "mutation 2026-11-25: sniff ranks a non-preferred candidate after the preferred ones, a cut final line is dropped only after one line" {
    const d = try sn("a b;c\n1 2;3\n", .{ .delimiters = " ;" });
    try t.expectEqual(@as(u8, ';'), d.delimiter);
    try t.expectEqual(@as(u8, ','), (try sn("a,b\n1", .{})).delimiter);
}

test "mutation 2026-11-25: sniff strips the CR before judging a closing quote, skips blank lines" {
    try expectD("x;'a'\r\ny;'b'\r\n", ';', '\'');
    try expectD("a,b\n\n1,2\n", ',', '"');
}

test "mutation 2026-11-25: sniff quote votes need a delimiter beside the quote, a closing quote that is not doubled" {
    // an apostrophe inside a field, after a letter, is no opening quote
    try expectD("a,it's,fine'\nb,it's,fine'\n", ',', '"');
    // a doubled quote stays inside the quoted field
    try expectD("'a''b';c\n", ';', '\'');
    // the closing quote must be followed by a delimiter (or end the line)
    try expectD("'a'x,b\n'c'y,d\n", ',', '"');
    // a whole-line quoted field says nothing
    const lone = try rep("'x'\n", "u,v\n", 19, "");
    defer t.allocator.free(lone);
    try expectD(lone, ',', '"');
    // but a quote at one end beside a delimiter does
    try expectD("'a';b\n'c';d\n", ';', '\'');
}

test "mutation 2026-11-25: sniff delimiter votes come from both sides of a quoted field" {
    try expectD("p,q,r|'a'\ns,t,u|'b'\n", '|', '\'');
    try expectD("'a'|x,y,z\n'b'|x,y,z\n", '|', '\'');
}

test "mutation 2026-11-25: sniff continues after the closing quote (no re-opening on it)" {
    // line 1: 'a,','  (one vote for ' as quote), line 2: x;"y";z (one vote for ")
    const d = try sn("'a,','\nx;\"y\";z\n", .{});
    try t.expectEqual(@as(u8, '"'), d.quote);
    try t.expectEqual(@as(u8, ';'), d.delimiter);
}

test "mutation 2026-11-25: sniff ties: equal quote votes pick \", equal delimiter votes the preferred byte, equal space votes no trim" {
    try expectD("'a';b\n\"c\";d\n", ';', '"');
    try expectD("\"a\",1;\"b\"\n", ',', '"');
    const d = try sn("\"a\",1;\"b\"\n", .{ .delimiters = ";," });
    try t.expectEqual(@as(u8, ','), d.delimiter);
    const e = try sn("1,\"a\"\n2, \"b\"\n", .{});
    try t.expectEqual(line.Trim.none, e.trim);
}

test "mutation 2026-11-25: sniff counts past 63 per line share a bucket; an absent candidate is never the delimiter" {
    const row = try rep("", "x,", 70, "x\n");
    defer t.allocator.free(row);
    const two = try rep("", row, 2, "");
    defer t.allocator.free(two);
    try expectD(two, ',', '"');
    try t.expect(sniffmod.sniff("abc\ndef\n", .{ .min_consistency = 0 }) == null);
}

test "mutation 2026-11-25: sniff trim is leading only when EVERY delimiter of the first line is followed by a space" {
    const many = try rep("title\n", "a,b\n", 19, "");
    defer t.allocator.free(many);
    const d = try sn(many, .{});
    try t.expectEqual(line.Trim.none, d.trim);
    const e = try sn("a, b,c\n1,2,3\n4,5,6\n", .{});
    try t.expectEqual(line.Trim.none, e.trim);
}

test "mutation 2026-11-25: hasHeader reads 20 body rows, skips ragged rows, and keeps a column's kind strictly" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d: sniffmod.Dialect = .{};
    const long = try rep("id,v\n", "1,2\n", 20, "x,y\n");
    defer t.allocator.free(long);
    try t.expect(try sniffmod.hasHeader(a, long, d));
    try t.expect(try sniffmod.hasHeader(a, "name,w\n1,a\n2,bb\nabc\n", d));
    try t.expect(!(try sniffmod.hasHeader(a, "name\n1\nabc\n3\n", d)));
    try t.expect(!(try sniffmod.hasHeader(a, "name\nab\ncde\n", d)));
    try t.expect(!(try sniffmod.hasHeader(a, "name\nab\n12\n", d)));
}

test "mutation 2026-11-25: record optional text with trim keeps blanks, a missing column reports the header's column" {
    const O = struct { a: ?[]const u8 };
    const o = try recmod.deserialize(O, null, &.{"  "}, .{ .trim = true });
    try t.expectEqualStrings("  ", o.a.?);
    const R = struct {
        pub const csv_rename = .{ .x = "b" };
        x: u8,
    };
    var h = try header.Header.init(t.allocator, &.{ "a", "b" });
    defer h.deinit();
    var diag: recmod.Diag = .{};
    try t.expectError(error.MissingColumn, recmod.deserialize(R, &h, &.{"1"}, .{ .diag = &diag }));
    try t.expectEqual(@as(usize, 1), diag.column);
}

test "mutation 2026-11-25: StreamReader.seekTo keeps quote, escape and comment of the dialect in lazy mode" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "q.csv", .data = "\"open\nx\n" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "e.csv", .data = "\"a\\\"\nx\n" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "c.csv", .data = "#c\ny\n#d\nz\n" });
    {
        var f = try tmp.dir.openFile(t.io, "q.csv", .{});
        defer f.close(t.io);
        var sr = try stream.StreamReader.init(t.io, t.allocator, f, .{});
        defer sr.deinit();
        _ = try sr.next();
        sr.seekTo(0);
        try t.expect((try sr.next()).?.unbalanced_quote);
    }
    {
        var f = try tmp.dir.openFile(t.io, "e.csv", .{});
        defer f.close(t.io);
        var sr = try stream.StreamReader.init(t.io, t.allocator, f, .{ .escape = '\\' });
        defer sr.deinit();
        _ = try sr.next();
        sr.seekTo(0);
        try t.expect((try sr.next()).?.unbalanced_quote);
    }
    {
        var f = try tmp.dir.openFile(t.io, "c.csv", .{});
        defer f.close(t.io);
        var sr = try stream.StreamReader.init(t.io, t.allocator, f, .{ .comment = '#' });
        defer sr.deinit();
        _ = try sr.next();
        sr.seekTo(0);
        try t.expectEqualStrings("y", (try sr.next()).?.bytes);
        try t.expectEqualStrings("z", (try sr.next()).?.bytes);
    }
}

test "mutation 2026-11-25: a delimiter of 0 with quote 0 is not a dialect clash" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = "a\n" });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var sr = try stream.StreamReader.init(t.io, t.allocator, f, .{ .delimiter = 0, .quote = 0 });
    sr.deinit();
}
