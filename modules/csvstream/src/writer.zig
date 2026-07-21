// SPDX-License-Identifier: MIT
//! RFC 4180 CSV writer: per-field quoting when (and only when) a field
//! contains the delimiter, the quote char, CR, or LF, doubling any embedded
//! quote char. Row-at-a-time, streaming to any `*std.Io.Writer` — no
//! allocation, mirroring the `csvsafe` streaming style (`writeSafe`).
//!
//! This is the writing-side counterpart csvsafe's own SPEC explicitly defers:
//! csvsafe is the OWASP formula-injection guard ONLY and states RFC 4180
//! quoting is "the CSV writer's or csvstream's job, not this guard's" (see
//! modules/csvsafe/README.md "DEFER"). There is no quoting primitive to reuse
//! from csvsafe — the quoting logic below is this module's own, std-only.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");

/// Record terminator. RFC 4180 §2 rule 1 specifies CRLF; `.lf` is offered for
/// Unix-style output (this module's own reader already accepts either).
pub const LineTerminator = enum {
    crlf,
    lf,

    fn bytes(self: LineTerminator) []const u8 {
        return switch (self) {
            .crlf => "\r\n",
            .lf => "\n",
        };
    }
};

pub const WriteOptions = struct {
    /// Field separator (typically ',').
    delimiter: u8 = ',',
    /// Quoting char. `0` disables quoting entirely (fields are written
    /// verbatim, matching the reader's `quote == 0` convention) — the caller
    /// is then responsible for ensuring no field contains the delimiter/CR/LF.
    quote: u8 = '"',
    /// Record terminator; RFC 4180 default is CRLF.
    line_terminator: LineTerminator = .crlf,
};

/// Returns true if `field` needs RFC 4180 quoting under `opts`: it contains
/// the delimiter, the quote char, a CR, or a LF.
fn needsQuoting(field: []const u8, opts: WriteOptions) bool {
    if (opts.quote == 0) return false;
    for (field) |b| {
        if (b == opts.delimiter or b == opts.quote or b == '\r' or b == '\n') return true;
    }
    return false;
}

/// Writes one field, quoting it (and doubling any embedded quote char) only
/// if `needsQuoting` says it must be — the common case of a plain field costs
/// nothing beyond the scan.
pub fn writeField(w: *std.Io.Writer, field: []const u8, opts: WriteOptions) std.Io.Writer.Error!void {
    if (!needsQuoting(field, opts)) {
        try w.writeAll(field);
        return;
    }
    try w.writeByte(opts.quote);
    var start: usize = 0;
    for (field, 0..) |b, i| {
        if (b == opts.quote) {
            try w.writeAll(field[start..i]);
            // RFC 4180 §2 rule 7: a literal quote inside a quoted field is
            // escaped by doubling it.
            try w.writeByte(opts.quote);
            try w.writeByte(opts.quote);
            start = i + 1;
        }
    }
    try w.writeAll(field[start..]);
    try w.writeByte(opts.quote);
}

/// Writes one full record: `fields` joined by `opts.delimiter`, each quoted
/// per `writeField`, terminated by `opts.line_terminator`.
pub fn writeRecord(w: *std.Io.Writer, fields: []const []const u8, opts: WriteOptions) std.Io.Writer.Error!void {
    for (fields, 0..) |field, i| {
        if (i != 0) try w.writeByte(opts.delimiter);
        try writeField(w, field, opts);
    }
    try w.writeAll(opts.line_terminator.bytes());
}

// ============================================================
// Tests
// ============================================================

const t = std.testing;
const line = @import("line.zig");

fn expectRecord(fields: []const []const u8, opts: WriteOptions, expected: []const u8) !void {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeRecord(&w, fields, opts);
    try t.expectEqualStrings(expected, w.buffered());
}

test "writeRecord: plain fields need no quoting" {
    try expectRecord(&.{ "a", "b", "c" }, .{}, "a,b,c\r\n");
}

test "writeRecord: default line terminator is CRLF per RFC 4180" {
    try expectRecord(&.{"x"}, .{}, "x\r\n");
}

test "writeRecord: .lf line terminator opt-out" {
    try expectRecord(&.{ "a", "b" }, .{ .line_terminator = .lf }, "a,b\n");
}

test "writeRecord: field containing the delimiter is quoted" {
    try expectRecord(&.{ "a,b", "c" }, .{}, "\"a,b\",c\r\n");
}

test "writeRecord: field containing the quote char is quoted with the quote doubled" {
    try expectRecord(&.{"a\"b"}, .{}, "\"a\"\"b\"\r\n");
}

test "writeRecord: field containing an embedded newline is quoted (LF and CR)" {
    try expectRecord(&.{"a\nb"}, .{}, "\"a\nb\"\r\n");
    try expectRecord(&.{"a\rb"}, .{}, "\"a\rb\"\r\n");
}

test "writeRecord: field starting and ending with quote chars, all doubled" {
    try expectRecord(&.{"\"\""}, .{}, "\"\"\"\"\"\"\r\n"); // `""` -> `""""""`
}

test "writeRecord: empty field and empty record" {
    try expectRecord(&.{""}, .{}, "\r\n");
    try expectRecord(&.{}, .{}, "\r\n");
}

test "writeRecord: custom delimiter and quote char" {
    try expectRecord(&.{ "a;b", "c" }, .{ .delimiter = ';', .quote = '\'' }, "'a;b';c\r\n");
}

test "writeRecord: quote == 0 disables quoting, fields written verbatim" {
    // Caller's responsibility not to feed a delimiter/CR/LF in this mode —
    // mirrors the reader's quote==0 convention.
    try expectRecord(&.{ "a,b", "c" }, .{ .quote = 0 }, "a,b,c\r\n");
}

// ── Positive control: a field that would silently corrupt a downstream parse
// if quoting were skipped or the escape were wrong. ─────────────────────────

test "positive control: comma-bearing field without quoting would misparse into an extra field" {
    // If writeField failed to quote "a,b", a naive re-split on ',' would see
    // 3 fields ("a", "b", "c") instead of the intended 2 ("a,b", "c"). Prove
    // writeRecord's actual output round-trips to exactly 2 fields via this
    // module's own splitFields.
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeRecord(&w, &.{ "a,b", "c" }, .{});
    var fbuf: [8][]const u8 = undefined;
    const fields = try line.splitFields(w.buffered()[0 .. w.buffered().len - 2], &fbuf, ',', '"', t.allocator); // strip trailing CRLF
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("a,b", fields[0]);
    try t.expectEqualStrings("c", fields[1]);
}

test "positive control: unescaped embedded quote would break the closing-quote scan on re-read" {
    // If the embedded quote in `a"b` were written as a single (undoubled)
    // quote char, splitFields would read the field as closed after `a`,
    // leaving `b"` dangling as bogus trailing bytes instead of one field
    // "a\"b". Prove the actual (correctly doubled) output round-trips.
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeRecord(&w, &.{"a\"b"}, .{});
    var fbuf: [8][]const u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const fields = try line.splitFields(w.buffered()[0 .. w.buffered().len - 2], &fbuf, ',', '"', arena.allocator());
    try t.expectEqual(@as(usize, 1), fields.len);
    try t.expectEqualStrings("a\"b", fields[0]);
}

// ── Round-trip: write → StreamReader read back ──────────────────────────────

test "round-trip: write a multi-row CSV to a file, read it back with StreamReader + splitFields" {
    // Deliberately no embedded-newline field here: this module's OWN reader
    // is documented to end every record at '\n' regardless of quote state
    // (the "lazy quotes" deviation — see stream.zig / line.zig doc comments),
    // so a writer-emitted multi-line quoted field (which IS valid RFC 4180,
    // see the standalone "embedded newline" writer test above) would NOT
    // round-trip through this reader. Comma- and quote-bearing fields do.
    const stream = @import("stream.zig");

    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();

    const rows = [_][]const []const u8{
        &.{ "name", "note", "age" },
        &.{ "alice", "hello, world", "30" },
        &.{ "bob", "says \"hi\"", "25" },
        &.{ "carol", "mix, and \"quote\"", "28" },
    };

    {
        var f = try tmp.dir.createFile(t.io, "roundtrip.csv", .{});
        defer f.close(t.io);
        var file_buf: [256]u8 = undefined;
        var fw = f.writer(t.io, &file_buf);
        for (rows) |row| try writeRecord(&fw.interface, row, .{});
        try fw.interface.flush();
    }

    var f = try tmp.dir.openFile(t.io, "roundtrip.csv", .{});
    defer f.close(t.io);
    var sr = try stream.StreamReader.init(t.io, t.allocator, f, .{});
    defer sr.deinit();

    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var fbuf: [8][]const u8 = undefined;
    for (rows) |expected_row| {
        const rec = (try sr.next()).?;
        const fields = try line.splitFields(rec.bytes, &fbuf, ',', '"', arena.allocator());
        try t.expectEqual(expected_row.len, fields.len);
        for (expected_row, fields) |exp, got| try t.expectEqualStrings(exp, got);
    }
    try t.expect((try sr.next()) == null);
}
