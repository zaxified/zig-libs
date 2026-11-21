// SPDX-License-Identifier: MIT
//! Dialect sniffing from a sample (Python `csv.Sniffer`): which delimiter and quote character a CSV
//! text uses, and whether its first row is a header. A heuristic, never a guarantee: it reads the
//! sample the caller hands over (typically the first few KiB of a file), allocates nothing in
//! `sniff`, and answers null when the sample gives no consistent delimiter.
//!
//! Two methods, as Python's: (1) quoted fields next to a delimiter (`a,"b,c",d` shows both the quote
//! and the delimiter); when there are none, (2) the byte whose count per line is the same on (nearly)
//! every line. Python's own source was not read: the behaviour is its documentation's.
//!
//! Differences from Python, on purpose: the default candidate set is `,;\t|:` (Python considers
//! every ASCII byte, which finds `^` or a space in free text; pass `delimiters` to widen it), the
//! result does not guess an escape character, and `double_quote` is always true (RFC 4180, the default of Go
//! and rust-csv; a sample without a doubled quote proves nothing about the rest of the file, which Python's
//! `doublequote = False` for such a sample ignores).
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");
const line = @import("line.zig");
const coerce = @import("coerce.zig");

pub const Dialect = struct {
    delimiter: u8 = ',',
    quote: u8 = '"',
    double_quote: bool = true,
    /// `.leading` when every delimiter is followed by a space (Python `skipinitialspace`), else `.none`.
    trim: line.Trim = .none,
};

pub const default_delimiters = ",;\t|:";

pub const SniffOptions = struct {
    /// The bytes that may be the delimiter, in order of preference when two are equally consistent
    /// (`,` `\t` `;` `|` `:` first, whatever the order here, as Python prefers them; others after).
    delimiters: []const u8 = default_delimiters,
    /// How many non-empty lines to look at.
    max_lines: usize = 200,
    /// The least share of lines that must agree on a byte's count for it to be the delimiter.
    min_consistency: f64 = 0.9,
};

const preferred = ",\t;|:";

fn rank(c: u8, set: []const u8) usize {
    if (std.mem.indexOfScalar(u8, preferred, c)) |i| return i;
    return preferred.len + (std.mem.indexOfScalar(u8, set, c) orelse set.len);
}

/// The next non-empty line of `s` from `pos.*` (no terminator), or null; a final line the sample
/// cut short (no terminator) is dropped when it is not the only one, since its fields are not all there.
fn nextLine(s: []const u8, pos: *usize, seen: usize) ?[]const u8 {
    while (pos.* < s.len) {
        const start = pos.*;
        const nl = std.mem.indexOfScalarPos(u8, s, start, '\n');
        const end = nl orelse s.len;
        pos.* = if (nl) |n| n + 1 else s.len;
        if (nl == null and seen > 0) return null;
        var l = s[start..end];
        if (l.len != 0 and l[l.len - 1] == '\r') l = l[0 .. l.len - 1];
        if (l.len != 0) return l;
    }
    return null;
}

const QuoteVotes = struct {
    quotes: [2]usize = .{ 0, 0 }, // `"` and `'`
    delims: [256]usize = @splat(0),
    after_space: usize = 0,
    plain: usize = 0,
};

/// Quoted fields beside a delimiter: every quote char that opens a field (at the start of a line, or
/// after a delimiter candidate and at most one space) and closes with the same char before the line
/// ends or a delimiter candidate follows. Votes for the quote and for the delimiter on either side.
fn quoteVotes(s: []const u8, opts: SniffOptions) QuoteVotes {
    var v: QuoteVotes = .{};
    var pos: usize = 0;
    var seen: usize = 0;
    while (seen < opts.max_lines) {
        const l = nextLine(s, &pos, seen) orelse break;
        seen += 1;
        var i: usize = 0;
        while (i < l.len) : (i += 1) {
            const q = l[i];
            if (q != '"' and q != '\'') continue;
            var before: ?u8 = null;
            var sp = false;
            if (i > 0) {
                var j = i - 1;
                if (l[j] == ' ' and j > 0 and std.mem.indexOfScalar(u8, opts.delimiters, l[j - 1]) != null) {
                    sp = true;
                    j -= 1;
                }
                if (std.mem.indexOfScalar(u8, opts.delimiters, l[j]) == null) continue;
                before = l[j];
            }
            // the closing quote: a doubled quote stays inside
            var k = i + 1;
            const close: usize = while (k < l.len) : (k += 1) {
                if (l[k] != q) continue;
                if (k + 1 < l.len and l[k + 1] == q) {
                    k += 1;
                    continue;
                }
                break k;
            } else continue;
            var after: ?u8 = null;
            if (close + 1 < l.len) {
                if (std.mem.indexOfScalar(u8, opts.delimiters, l[close + 1]) == null) continue;
                after = l[close + 1];
            }
            if (before == null and after == null) continue; // a lone quoted line says nothing about the delimiter
            v.quotes[@intFromBool(q == '\'')] += 1;
            if (before) |b| v.delims[b] += 1;
            if (after) |a| v.delims[a] += 1;
            if (before != null) {
                if (sp) v.after_space += 1 else v.plain += 1;
            }
            i = close;
        }
    }
    return v;
}

/// How many `d` the line holds outside `quote`d stretches.
fn countOutside(l: []const u8, d: u8, quote: u8) usize {
    var n: usize = 0;
    var inq = false;
    for (l) |b| {
        if (b == quote) inq = !inq else if (b == d and !inq) n += 1;
    }
    return n;
}

/// The dialect `sample` looks like it is written in, or null when no candidate delimiter appears the
/// same number of times on (nearly) every line. See the file header for the method.
pub fn sniff(sample: []const u8, opts: SniffOptions) ?Dialect {
    if (opts.delimiters.len == 0) return null;
    var d: Dialect = .{};
    const qv = quoteVotes(sample, opts);
    if (qv.quotes[0] + qv.quotes[1] != 0) {
        d.quote = if (qv.quotes[1] > qv.quotes[0]) '\'' else '"';
        var best: ?u8 = null;
        for (opts.delimiters) |c| {
            if (qv.delims[c] == 0) continue;
            if (best == null or qv.delims[c] > qv.delims[best.?] or (qv.delims[c] == qv.delims[best.?] and rank(c, opts.delimiters) < rank(best.?, opts.delimiters))) best = c;
        }
        if (best) |b| {
            d.delimiter = b;
            if (qv.after_space > qv.plain) d.trim = .leading;
            return d;
        }
    }

    // The byte whose count per line is the same on nearly every line.
    var best: ?u8 = null;
    var best_cons: f64 = 0;
    for (opts.delimiters) |c| {
        // histogram of the count per line, in a small fixed table (counts past 63 share a bucket)
        var hist: [64]usize = @splat(0);
        var lines: usize = 0;
        var pos: usize = 0;
        while (lines < opts.max_lines) {
            const l = nextLine(sample, &pos, lines) orelse break;
            lines += 1;
            hist[@min(countOutside(l, c, d.quote), 63)] += 1;
        }
        if (lines == 0) continue;
        var mode: usize = 1;
        for (hist[2..], 2..) |h, i| if (h > hist[mode]) {
            mode = i;
        };
        if (hist[mode] == 0) continue;
        const cons = @as(f64, @floatFromInt(hist[mode])) / @as(f64, @floatFromInt(lines));
        if (cons < opts.min_consistency) continue;
        const better = best == null or cons > best_cons or (cons == best_cons and rank(c, opts.delimiters) < rank(best.?, opts.delimiters));
        if (better) {
            best = c;
            best_cons = cons;
        }
    }
    const b = best orelse return null;
    d.delimiter = b;
    // every delimiter of the first line followed by a space
    var pos: usize = 0;
    if (nextLine(sample, &pos, 0)) |first| {
        const all = countOutside(first, b, d.quote);
        var sp: usize = 0;
        var inq = false;
        for (first, 0..) |ch, i| {
            if (ch == d.quote) inq = !inq else if (ch == b and !inq and i + 1 < first.len and first[i + 1] == ' ') sp += 1;
        }
        if (all != 0 and all == sp) d.trim = .leading;
    }
    return d;
}

const max_columns = 256;

const Kind = union(enum) { unset, number, fixed: usize, none };

/// Whether the first row of `sample` looks like a header (Python `Sniffer.has_header`): over the next
/// 20 rows each column is all numbers, or all of one length, or neither; the first row votes for a header
/// where it is text in a numeric column or of another length than a fixed-length column, and against it
/// where it fits. More votes for than against: a header. The first 256 columns are looked at.
/// `alloc` takes the copies of fields holding doubled quotes (an arena is the usual choice).
pub fn hasHeader(alloc: std.mem.Allocator, sample: []const u8, dialect: Dialect) !bool {
    var kinds: [max_columns]Kind = @splat(.unset);
    var first: [max_columns]?[]const u8 = @splat(null);
    var buf: [max_columns][]const u8 = undefined;
    var pos: usize = 0;
    var rows: usize = 0;
    var ncols: usize = 0;
    const so: line.SplitOptions = .{ .on_overflow = .truncate, .trim = dialect.trim, .double_quote = dialect.double_quote };
    while (rows < 21) {
        const l = nextLine(sample, &pos, rows) orelse break;
        const fields = line.splitFieldsOpts(l, &buf, dialect.delimiter, dialect.quote, alloc, so) catch continue;
        defer line.freeFields(l, fields, alloc);
        if (rows == 0) {
            ncols = fields.len;
            for (fields, 0..) |f, i| first[i] = try alloc.dupe(u8, f);
            rows = 1;
            continue;
        }
        if (fields.len != ncols) continue; // a ragged row says nothing about the columns
        rows += 1;
        for (fields, 0..) |f, i| {
            const is_num = if (coerce.parseFloat(f64, f)) |_| true else |_| false;
            kinds[i] = switch (kinds[i]) {
                .unset => if (is_num) .number else .{ .fixed = f.len },
                .number => if (is_num) .number else .none,
                .fixed => |n| if (!is_num and f.len == n) .{ .fixed = n } else .none,
                .none => .none,
            };
        }
    }
    defer for (first[0..ncols]) |f| if (f) |x| alloc.free(x);
    var votes: i64 = 0;
    for (kinds[0..ncols], first[0..ncols]) |k, f| {
        const cell = f orelse continue;
        switch (k) {
            .number => votes += if (coerce.parseFloat(f64, cell)) |_| -1 else |_| 1,
            .fixed => |n| votes += if (cell.len != n) 1 else -1,
            .unset, .none => {},
        }
    }
    return votes > 0;
}

// ============================================================
// Tests
// ============================================================

const t = std.testing;

fn expectDialect(want_delim: u8, want_quote: u8, sample: []const u8) !void {
    const d = sniff(sample, .{}) orelse return error.TestUnexpectedResult;
    try t.expectEqual(want_delim, d.delimiter);
    try t.expectEqual(want_quote, d.quote);
}

test "sniff: comma, semicolon, tab and pipe by the consistent count per line" {
    try expectDialect(',', '"', "a,b,c\n1,2,3\n4,5,6\n7,8,9\n");
    try expectDialect(';', '"', "a;b;c\n1;2;3\n4;5;6\n7;8;9\n1;1;1\n2;2;2\n3;3;3\n4;4;4\n5,5;5\n6;6;6\n");
    try expectDialect('\t', '"', "a\tb\tc\n1\t2\t3\n4\t5\t6\n");
    try expectDialect('|', '"', "a|b|c\n1|2|3\n4|5|6\n");
}

test "sniff: a comma inside quotes does not count (the quoted-field method, then the counts)" {
    try expectDialect(',', '"', "name,note\n\"Smith, J.\",\"a, b, c\"\nDoe,\"x\"\n");
    try expectDialect(';', '"', "name;note\n\"a;b\";\"c,d,e\"\n\"x\";y\n");
    // counts alone (no quoted field next to a delimiter): quotes in the middle of a line still hide the comma
    try expectDialect(',', '"', "id,text\n1,say \"a,b\" now\n2,plain\n");
}

test "sniff: a single-quote dialect, a trailing ragged line cut by the sample, CRLF" {
    try expectDialect(',', '\'', "'a','b,c','d'\n'e','f','g'\n");
    try expectDialect(',', '"', "a,b,c\r\n1,2,3\r\n4,5,6\r\n7,8");
}

test "sniff: skipinitialspace when every delimiter is followed by a space, quoted or not" {
    var d = sniff("a, b, c\n1, 2, 3\n4, 5, 6\n", .{}).?;
    try t.expectEqual(line.Trim.leading, d.trim);
    d = sniff("a,b,c\n1,2,3\n", .{}).?;
    try t.expectEqual(line.Trim.none, d.trim);
    d = sniff("\"a\", \"b\"\n\"c\", \"d\"\n", .{}).?;
    try t.expectEqual(line.Trim.leading, d.trim);
    try t.expectEqual(@as(u8, ','), d.delimiter);
}

test "sniff: no delimiter, an inconsistent sample and an empty one are null; delimiters widens the set" {
    try t.expect(sniff("", .{}) == null);
    try t.expect(sniff("hello world\nfoo bar baz\n", .{}) == null);
    try t.expect(sniff("a,b\n1,2,3\n4\n5,6,7,8\n9,9\n10\n11,11,11\n", .{}) == null);
    const d = sniff("a b c\n1 2 3\n4 5 6\n", .{ .delimiters = " " }).?;
    try t.expectEqual(@as(u8, ' '), d.delimiter);
    try t.expect(sniff("a,b\n1,2\n", .{ .delimiters = "" }) == null);
}

test "sniff: ties go to the preferred bytes (comma before semicolon before pipe)" {
    try expectDialect(',', '"', "a,b;c\n1,2;3\n");
    try expectDialect(';', '"', "a;b|c\n1;2|3\n");
}

test "sniff: double_quote is true whatever the sample shows" {
    var d = sniff("a,\"x\"\"y\",c\n1,\"z\",3\n", .{}).?;
    try t.expect(d.double_quote);
    d = sniff("a,b\n1,2\n", .{}).?;
    try t.expect(d.double_quote);
}

test "sniff then read: the sniffed dialect splits a sample the way its writer meant" {
    const sample = "id;name;note\n1;\"Smith; J.\";ok\n2;Doe;\"say \"\"hi\"\"\"\n";
    const d = sniff(sample, .{}).?;
    try t.expectEqual(@as(u8, ';'), d.delimiter);
    var it = line.LineIterator.init(sample, d.quote, 0);
    _ = it.next();
    var buf: [8][]const u8 = undefined;
    const r1 = it.next().?;
    const f1 = try line.splitFields(r1.bytes, &buf, d.delimiter, d.quote, t.allocator);
    defer line.freeFields(r1.bytes, f1, t.allocator);
    try t.expectEqual(@as(usize, 3), f1.len);
    try t.expectEqualStrings("Smith; J.", f1[1]);
}

test "hasHeader: text over numbers, text over fixed-length cells, and the cases that say no" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d: Dialect = .{};
    try t.expect(try hasHeader(a, "name,age\nAda,41\nBob,29\nCy,33\n", d));
    try t.expect(!(try hasHeader(a, "Ada,41\nBob,29\nCy,33\n", d)));
    try t.expect(try hasHeader(a, "id,code\n1,ABC\n2,DEF\n3,GHI\n", d));
    try t.expect(!(try hasHeader(a, "1,ABC\n2,DEF\n3,GHI\n", d)));
    // nothing to compare against: no header
    try t.expect(!(try hasHeader(a, "a,b,c\n", d)));
    try t.expect(!(try hasHeader(a, "", d)));
    // quoted fields, a ragged row ignored
    try t.expect(try hasHeader(a, "\"name\",\"v\"\n\"x\",1.5\n\"y\"\n\"z\",2.5\n", d));
}
