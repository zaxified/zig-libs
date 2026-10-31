// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over csvstream's two existing `testing.fuzz`
//! harnesses (`LineIterator`, `splitFields`; added 2026-10-09). The bodies
//! live here, generic over their source of choices (`fn(comptime S, *S,
//! gpa)`); `line.zig`'s `testing.fuzz` tests feed them through the cursor
//! adapter below, the driver feeds them a PRNG.
//!
//! Driver: `CSVSTREAM_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_MS`, `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const line = @import("line.zig");

pub const Label = enum { records, unbalanced, fields, strict_refused, escaped, trimmed, comment_skipped, spanned, fallback };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

const quotes = [_]u8{ '"', 0 };
const delims = [_]u8{ ',', ';', '\t' };

/// `LineIterator` never panics or loops: the record count is bounded by the
/// input length, with and without quoting.
pub fn lineHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    for (quotes) |quote| {
        var it = line.LineIterator.init(buf[0..len], quote, 0);
        var steps: usize = 0;
        while (it.next()) |rec| {
            steps += 1;
            if (steps >= 2) mark(.records);
            if (rec.unbalanced_quote) mark(.unbalanced);
            try testing.expect(steps <= len + 1);
        }
    }
}

/// `splitFields` never panics on one arbitrary record, for every delimiter
/// and quote setting. (Its one error, more fields than the 64-slot buffer,
/// is not reachable from random bytes, so it is not a reach label.)
pub fn splitHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var line_buf: [256]u8 = undefined;
    const len: usize = src.slice(&line_buf);
    var fields_buf: [64][]const u8 = undefined;
    for (delims) |delimiter| {
        for (quotes) |quote| {
            const out = line.splitFields(line_buf[0..len], &fields_buf, delimiter, quote, arena.allocator()) catch continue;
            if (out.len >= 2) mark(.fields);
        }
    }
}

/// The dialect options (2026-10-20) over a small CSV alphabet, both record
/// modes. Invariants: a split's field count is `countFieldsOpts`'s; `strict`
/// only refuses — what it accepts reads exactly as the lazy split does; a
/// lazy split never raises a quote error; records are numbered in order and
/// line numbers never go back.
pub fn dialectHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var raw: [320]u8 = undefined;
    const n: usize = src.slice(&raw);
    if (n < 2) return;
    const alphabet = "a,\" \\#\n\r\tb";
    const sel = raw[0];
    var text: [318]u8 = undefined;
    const len = n - 2;
    for (raw[2..n], 0..) |b, i| text[i] = alphabet[b % alphabet.len];
    const bytes = text[0..len];
    const escape: u8 = if (sel & 1 != 0) '\\' else 0;
    const double_quote = sel & 2 == 0;
    const trim: line.Trim = switch ((sel >> 2) % 3) {
        0 => .none,
        1 => .leading,
        else => .all,
    };
    const comment: u8 = if (sel & 0x20 != 0) '#' else 0;
    const span = sel & 0x40 != 0;
    const delimiter: u8 = if (raw[1] & 1 != 0) '\t' else ',';
    const lazy: line.SplitOptions = .{ .escape = escape, .double_quote = double_quote, .trim = trim };
    var strict = lazy;
    strict.strict = true;

    var it = if (span)
        line.LineIterator.initSpan(bytes, '"', 0, .{ .delimiter = delimiter, .escape = escape, .double_quote = double_quote, .trim = trim, .comment = comment })
    else
        line.LineIterator.initOpts(bytes, 0, .{ .escape = escape, .comment = comment });
    var want_index: u64 = 0;
    var last_line: u64 = 0;
    var records: usize = 0;
    var buf_lazy: [400][]const u8 = undefined;
    var buf_strict: [400][]const u8 = undefined;
    var buf_plain: [400][]const u8 = undefined;
    while (it.next()) |rec| {
        records += 1;
        try testing.expect(records <= len + 1);
        try testing.expectEqual(want_index, rec.record_index);
        want_index += 1;
        try testing.expect(rec.line_number > last_line);
        last_line = rec.line_number;
        if (rec.spanned) {
            mark(.spanned);
            // The scanner and the split agree: every line feed inside a
            // spanned record lies inside a quoted field as the split reads it.
            var pos: usize = 0;
            var nl_at: usize = 0;
            while (pos < rec.bytes.len) {
                const f = try line.scanField(rec.bytes, pos, delimiter, '"', lazy);
                const quoted = f.start > 0 and f.start - 1 >= pos and rec.bytes[f.start - 1] == '"' and f.start - 1 < f.next;
                const lo = if (quoted) f.start else f.next;
                const hi = if (quoted) f.end else f.next;
                while (std.mem.findScalarPos(u8, rec.bytes, nl_at, '\n')) |nl| {
                    if (nl >= f.next) break;
                    if (!(nl >= lo and nl < hi)) {
                        std.debug.print("line feed at {d} outside a quoted field in {f}\n", .{ nl, std.zig.fmtString(rec.bytes) });
                        return error.ScannerAndSplitDisagree;
                    }
                    nl_at = nl + 1;
                }
                pos = f.next;
            }
        }
        if (comment != 0 and rec.bytes.len != 0) try testing.expect(rec.bytes[0] != comment);
        const fl = line.splitFieldsOpts(rec.bytes, &buf_lazy, delimiter, '"', a, lazy) catch |err| switch (err) {
            error.BareQuote, error.ExtraneousQuote, error.UnterminatedQuote => return error.LazySplitRaisedQuoteError,
            else => return err,
        };
        try testing.expectEqual(fl.len, line.countFieldsOpts(rec.bytes, delimiter, '"', lazy));
        if (line.splitFieldsOpts(rec.bytes, &buf_strict, delimiter, '"', a, strict)) |fs| {
            try testing.expectEqual(fl.len, fs.len);
            for (fl, fs) |x, y| try testing.expectEqualStrings(x, y);
        } else |err| switch (err) {
            error.BareQuote, error.ExtraneousQuote, error.UnterminatedQuote => mark(.strict_refused),
            else => return err,
        }
        // Reach: the options changed something.
        const plain = try line.splitFieldsOpts(rec.bytes, &buf_plain, delimiter, '"', a, .{ .double_quote = double_quote, .trim = trim });
        if (escape != 0 and !sameFields(plain, fl)) mark(.escaped);
        if (trim != .none) {
            const untrimmed = try line.splitFieldsOpts(rec.bytes, &buf_plain, delimiter, '"', a, .{ .escape = escape, .double_quote = double_quote });
            if (!sameFields(untrimmed, fl)) mark(.trimmed);
        }
    }
    if (comment != 0 and len > 0 and bytes[0] == comment) mark(.comment_skipped);

    // The event-jumping scanner against its bytewise reference, from every
    // start, with and without the input's end in view, under caps small
    // enough to fall back.
    const scanner = line.SpanScanner.init('"', .{
        .delimiter = delimiter,
        .escape = escape,
        .double_quote = double_quote,
        .trim = trim,
        .comment = comment,
        .max_quoted_lines = raw[1] >> 5,
        .max_record_len = if (raw[1] & 2 != 0) (raw[1] >> 2) % 32 + 1 else std.math.maxInt(usize),
    });
    for (0..len) |s| {
        for ([_]bool{ true, false }) |at_eof| {
            const fast = scanner.scanRaw(bytes, s, at_eof);
            const slow = scanner.scanRawBytewise(bytes, s, at_eof);
            if (!std.meta.eql(fast, slow)) {
                std.debug.print("scanRaw != bytewise at {d} (eof {}): {any} vs {any}\n", .{ s, at_eof, fast, slow });
                return error.ScannerDisagreesWithReference;
            }
            if (fast == .record and fast.record.unbalanced) mark(.fallback);
        }
    }
    // The lazy iterator's parity shortcut against the toggling loop.
    var lz = line.LineIterator.initOpts(bytes, 0, .{ .escape = escape });
    while (lz.next()) |rec| {
        // `double_quote` must not matter to the flag: both readings agree.
        try testing.expectEqual(toggleOpen(rec.bytes, escape, double_quote), rec.unbalanced_quote);
    }
}

/// The original `.end_record` quote toggle, kept as the reference for the
/// parity shortcut. (`rec` may have lost a trailing CR, which holds no quote.)
fn toggleOpen(rec: []const u8, escape: u8, double_quote: bool) bool {
    var in_q = false;
    var i: usize = 0;
    while (i < rec.len) {
        const c = rec[i];
        if (c == '"') {
            if (double_quote and in_q and i + 1 < rec.len and rec[i + 1] == '"') {
                i += 2;
                continue;
            }
            in_q = !in_q;
            i += 1;
        } else if (in_q and escape != 0 and c == escape and i + 1 < rec.len) {
            i += 2;
        } else i += 1;
    }
    return in_q;
}

fn sameFields(x: []const []const u8, y: []const []const u8) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!std.mem.eql(u8, p, q)) return false;
    return true;
}

test "fuzz driver: CSVSTREAM_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ lineHarness, .{ .prefix = "CSVSTREAM_FUZZ", .name = "csvstream-line" } },
        .{ splitHarness, .{ .prefix = "CSVSTREAM_FUZZ", .name = "csvstream-split" } },
        .{ dialectHarness, .{ .prefix = "CSVSTREAM_FUZZ", .name = "csvstream-dialect" } },
    });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        lineHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("csvstream line seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        splitHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("csvstream split seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        dialectHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("csvstream dialect seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
