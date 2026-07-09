// SPDX-License-Identifier: MIT
//! In-memory RFC 4180 line/field splitting. Operates purely on a caller-owned
//! byte slice — no I/O, no allocation on the common path. `LineIterator` walks
//! a buffer record-by-record while preserving each record's byte offset within
//! the buffer (composed with an absolute `base_offset`); `splitFields` splits a
//! single record into its fields.
//!
//! Provenance: lifted faithfully from the authors' bxp-core/src/csv.zig (MIT).

const std = @import("std");

/// Splits one CSV line into its constituent fields.
///
/// `delimiter` is the field separator (typically ',').
/// `quote` controls the quoting character (0 = no quoting, '"' = RFC 4180).
/// When quote != 0, fields wrapped in that character may contain the delimiter;
/// doubled quote chars (e.g. "" for quote='"') inside a quoted field are
/// unescaped to a single quote char.
/// Fills `buf` with slices that point directly into `line` when no unescaping
/// is needed, or into alloc-owned copies for fields containing an escaped quote.
/// Returns a sub-slice of `buf` containing only the fields found on the line.
/// `buf` must be large enough to hold all fields; extra capacity is ignored.
pub fn splitFields(line: []const u8, buf: [][]const u8, delimiter: u8, quote: u8, alloc: std.mem.Allocator) ![][]const u8 {
    var count: usize = 0;
    var pos: usize = 0;
    // Loop condition: pos <= line.len (one past end) lets the outer while
    // reach the `if (pos == line.len) break` sentinel for the trailing-field
    // case, avoiding a separate post-loop append.
    while (count < buf.len and pos <= line.len) {
        if (pos == line.len) break;
        if (quote != 0 and line[pos] == quote) {
            // Quoted field: scan until the closing quote.
            // Track whether any doubled-quote escape sequences were found so we
            // only allocate when actually needed.
            pos += 1;
            const start = pos;
            var has_escaped_quote = false;
            while (pos < line.len) {
                const b = line[pos];
                if (b == quote) {
                    if (pos + 1 < line.len and line[pos + 1] == quote) {
                        has_escaped_quote = true;
                        pos += 2; // Skip escaped quote (e.g. "")
                    } else {
                        break; // Closing quote
                    }
                } else {
                    pos += 1;
                }
            }
            const raw = line[start..pos];
            if (pos < line.len) pos += 1; // Skip closing quote.
            if (pos < line.len and line[pos] == delimiter) pos += 1; // Skip delimiter.

            // Unescape doubled quote → single quote only when needed (avoids
            // allocation in the common case).
            if (has_escaped_quote) {
                buf[count] = try unescapeQuotes(raw, quote, alloc);
            } else {
                buf[count] = raw;
            }
        } else {
            // Unquoted field: scan until the next delimiter.
            const start = pos;
            while (pos < line.len and line[pos] != delimiter) : (pos += 1) {}
            buf[count] = line[start..pos];
            if (pos < line.len) pos += 1; // Skip delimiter.
        }
        count += 1;
    }
    return buf[0..count];
}

/// One record produced by `LineIterator.next()`: the record bytes (a slice into
/// the underlying buffer — an RFC-4180 quote-aware logical line with `\r`
/// stripped from the terminator) plus its absolute byte offset (the iterator's
/// `base_offset` + the record's start within the buffer). When streaming a file
/// the offset points at the exact source bytes, so a consumer can seek back to
/// the source record for drill-down.
pub const LineSlice = struct {
    bytes: []const u8,
    byte_offset: u64,
    /// True when this record ended (at '\n' or EOF) while still inside an
    /// open quote — i.e. the line carries an unbalanced/stray quote char.
    /// The record is still emitted (the stray quote is treated as a literal
    /// byte, "lazy quotes" semantics); the flag lets the caller warn so the
    /// situation isn't silent. See `LineIterator.next`.
    unbalanced_quote: bool = false,
};

/// Quote-aware streaming iterator over CSV records held in a single in-memory
/// buffer. The caller pulls one record at a time; emitted `LineSlice.bytes`
/// borrow the buffer for the iterator's lifetime.
///
/// quote semantics: `quote == 0` disables quoting; `quote != 0` treats a
/// doubled `quote quote` as an escape that stays inside the quoted field and a
/// bare `quote` as the toggle.
///
/// A '\n' ALWAYS terminates the record — quoted fields may NOT span physical
/// lines (deliberately NOT RFC 4180 §2 rule 6). This makes a single
/// stray/unbalanced quote a one-line problem instead of letting it swallow
/// every following row up to the next quote ("lazy quotes" semantics, à la Go
/// `encoding/csv` LazyQuotes). When a record ends with an open quote,
/// `LineSlice.unbalanced_quote` is set so the caller can warn. Quoting still
/// protects the *delimiter* within a line (e.g. `"a,b"` is one field) — only
/// the newline is no longer protected. This also means every '\n' is a safe
/// chunk boundary, which is what lets `StreamReader` split a file into
/// record-aligned chunks with bounded memory.
///
/// `base_offset` is the absolute byte offset of `bytes[0]` — when a chunk is
/// streamed from a file this is `ChunkReader.chunk_start_in_file` at the time
/// the chunk was returned, so emitted offsets are absolute file offsets.
///
/// Empty records (consecutive `\n` or trailing `\n` at EOF) are skipped.
/// Returns `null` once the buffer is exhausted.
pub const LineIterator = struct {
    bytes: []const u8,
    quote: u8,
    base_offset: u64,
    pos: usize,

    pub fn init(bytes: []const u8, quote: u8, base_offset: u64) LineIterator {
        return .{ .bytes = bytes, .quote = quote, .base_offset = base_offset, .pos = 0 };
    }

    pub fn next(self: *LineIterator) ?LineSlice {
        // Skip leading empty records so the first call returns the first
        // non-empty record.
        while (self.pos < self.bytes.len) {
            const rec_start = self.pos;
            var in_quotes: bool = false;
            var terminated = false;
            while (self.pos < self.bytes.len) {
                const c = self.bytes[self.pos];
                if (self.quote != 0 and c == self.quote) {
                    if (in_quotes and self.pos + 1 < self.bytes.len and self.bytes[self.pos + 1] == self.quote) {
                        self.pos += 2; // escaped quote inside quoted field
                        continue;
                    }
                    in_quotes = !in_quotes;
                    self.pos += 1;
                } else if (c == '\n') {
                    // Newline ALWAYS ends the record (see type doc): even an
                    // open quote does not let it span lines. `in_quotes` here
                    // therefore means "stray/unbalanced quote on this line".
                    terminated = true;
                    break;
                } else {
                    self.pos += 1;
                }
            }
            var rec = self.bytes[rec_start..self.pos];
            const unbalanced = in_quotes; // open quote at '\n' or EOF
            if (terminated) self.pos += 1; // consume the newline
            if (rec.len > 0 and rec[rec.len - 1] == '\r') rec = rec[0 .. rec.len - 1];
            if (rec.len == 0) continue; // skip empty record, try next
            return .{ .bytes = rec, .byte_offset = self.base_offset + rec_start, .unbalanced_quote = unbalanced };
        }
        return null;
    }
};

/// Returns a copy of `s` with every doubled quote char replaced by a single one.
/// The returned slice is allocated with `alloc`.
fn unescapeQuotes(s: []const u8, quote: u8, alloc: std.mem.Allocator) ![]u8 {
    var out = std.array_list.Managed(u8).init(alloc);
    try out.ensureTotalCapacity(s.len);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == quote and i + 1 < s.len and s[i + 1] == quote) {
            try out.append(quote);
            i += 2;
        } else {
            try out.append(s[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice();
}

// ============================================================
// Tests — ported verbatim from bxp-core/src/csv.zig (the oracle).
// ============================================================

const t = std.testing;

test "splitFields: empty line yields zero fields" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 0), fields.len);
}

test "splitFields: single unquoted field" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("hello", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 1), fields.len);
    try t.expectEqualStrings("hello", fields[0]);
}

test "splitFields: three unquoted fields" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("a,b,c", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 3), fields.len);
    try t.expectEqualStrings("a", fields[0]);
    try t.expectEqualStrings("b", fields[1]);
    try t.expectEqualStrings("c", fields[2]);
}

test "splitFields: leading empty field" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields(",b", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("", fields[0]);
    try t.expectEqualStrings("b", fields[1]);
}

test "splitFields: empty field between delimiters" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("a,,b", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 3), fields.len);
    try t.expectEqualStrings("a", fields[0]);
    try t.expectEqualStrings("", fields[1]);
    try t.expectEqualStrings("b", fields[2]);
}

test "splitFields: trailing delimiter produces no extra empty field" {
    // After the last field the delimiter is consumed, then pos==len → break.
    // This deviates from strict RFC 4180 (which would yield a trailing "").
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("a,b,", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("a", fields[0]);
    try t.expectEqualStrings("b", fields[1]);
}

test "splitFields: quoted field containing delimiter" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("\"a,b\",c", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("a,b", fields[0]);
    try t.expectEqualStrings("c", fields[1]);
}

test "splitFields: quoted field with escaped double-quote" {
    // Doubled quote inside a quoted field (RFC 4180 §2 rule 7): "" → "
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("\"a\"\"b\"", &buf, ',', '"', arena.allocator());
    try t.expectEqual(@as(usize, 1), fields.len);
    try t.expectEqualStrings("a\"b", fields[0]);
}

test "splitFields: empty quoted field" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("\"\"", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 1), fields.len);
    try t.expectEqualStrings("", fields[0]);
}

test "splitFields: quote=0 disables quoting" {
    // With quote=0 the double-quote is plain data; comma still splits.
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("\"a,b\"", &buf, ',', 0, t.allocator);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("\"a", fields[0]);
    try t.expectEqualStrings("b\"", fields[1]);
}

test "splitFields: spaces are preserved (trimming is done by Context.field)" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("  a  ,  b  ", &buf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("  a  ", fields[0]);
    try t.expectEqualStrings("  b  ", fields[1]);
}

test "splitFields: tab delimiter" {
    var buf: [8][]const u8 = undefined;
    const fields = try splitFields("x\ty\tz", &buf, '\t', 0, t.allocator);
    try t.expectEqual(@as(usize, 3), fields.len);
    try t.expectEqualStrings("x", fields[0]);
    try t.expectEqualStrings("y", fields[1]);
    try t.expectEqualStrings("z", fields[2]);
}

// ============================================================
// LineIterator tests
// ============================================================

test "LineIterator: empty input yields null immediately" {
    var it = LineIterator.init("", '"', 0);
    try t.expectEqual(@as(?LineSlice, null), it.next());
}

test "LineIterator: three simple lines with absolute offsets" {
    var it = LineIterator.init("a,b\nc,d\ne,f\n", '"', 1000);
    const r1 = it.next().?;
    try t.expectEqualStrings("a,b", r1.bytes);
    try t.expectEqual(@as(u64, 1000), r1.byte_offset);
    const r2 = it.next().?;
    try t.expectEqualStrings("c,d", r2.bytes);
    try t.expectEqual(@as(u64, 1004), r2.byte_offset);
    const r3 = it.next().?;
    try t.expectEqualStrings("e,f", r3.bytes);
    try t.expectEqual(@as(u64, 1008), r3.byte_offset);
    try t.expectEqual(@as(?LineSlice, null), it.next());
}

test "LineIterator: newline ends record even inside an open quote (lazy quotes)" {
    // A stray '"' no longer swallows the next line. Each physical line is its
    // own record; the lines carrying the unbalanced quote are flagged.
    var it = LineIterator.init("\"a\nb\",c\nd,e\n", '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("\"a", r1.bytes);
    try t.expectEqual(@as(u64, 0), r1.byte_offset);
    try t.expect(r1.unbalanced_quote);
    const r2 = it.next().?;
    try t.expectEqualStrings("b\",c", r2.bytes);
    try t.expectEqual(@as(u64, 3), r2.byte_offset);
    try t.expect(r2.unbalanced_quote);
    const r3 = it.next().?;
    try t.expectEqualStrings("d,e", r3.bytes);
    try t.expectEqual(@as(u64, 8), r3.byte_offset);
    try t.expect(!r3.unbalanced_quote);
    try t.expectEqual(@as(?LineSlice, null), it.next());
}

test "LineIterator: doubled-quote escape is still honored within a line" {
    // The "" escape does not toggle quote state, so the leading '"' is left
    // unmatched when the line ends → the record is flagged unbalanced. The
    // newline still splits the record (no multi-line spanning).
    var it = LineIterator.init("\"a\"\"b\nc\"\nnext\n", '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("\"a\"\"b", r1.bytes);
    try t.expect(r1.unbalanced_quote);
    const r2 = it.next().?;
    try t.expectEqualStrings("c\"", r2.bytes);
    try t.expect(r2.unbalanced_quote);
    const r3 = it.next().?;
    try t.expectEqualStrings("next", r3.bytes);
    try t.expect(!r3.unbalanced_quote);
}

test "LineIterator: balanced quoted field with embedded delimiter stays one field" {
    // Quoting still protects the DELIMITER within a line — only the newline
    // is no longer protected. "a,b" is a single record with the comma inside.
    var it = LineIterator.init("\"a,b\",c\nd\n", '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("\"a,b\",c", r1.bytes);
    try t.expect(!r1.unbalanced_quote);
    const r2 = it.next().?;
    try t.expectEqualStrings("d", r2.bytes);
}

test "LineIterator: CRLF line endings strip the CR" {
    var it = LineIterator.init("a,b\r\nc,d\r\n", '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("a,b", r1.bytes);
    const r2 = it.next().?;
    try t.expectEqualStrings("c,d", r2.bytes);
}

test "LineIterator: last record without trailing newline" {
    var it = LineIterator.init("a\nb", '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("a", r1.bytes);
    try t.expectEqual(@as(u64, 0), r1.byte_offset);
    const r2 = it.next().?;
    try t.expectEqualStrings("b", r2.bytes);
    try t.expectEqual(@as(u64, 2), r2.byte_offset);
    try t.expectEqual(@as(?LineSlice, null), it.next());
}

test "LineIterator: consecutive newlines skip empty records" {
    var it = LineIterator.init("a\n\n\nb\n", '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("a", r1.bytes);
    try t.expectEqual(@as(u64, 0), r1.byte_offset);
    const r2 = it.next().?;
    try t.expectEqualStrings("b", r2.bytes);
    try t.expectEqual(@as(u64, 4), r2.byte_offset);
}

test "LineIterator: quote=0 disables quoting (embedded quote is plain data)" {
    // quote=0: no quote-aware tracking. The bare '"' is plain data; the
    // '\n' inside what looks like a quoted field still ends the record.
    var it = LineIterator.init("\"a\nb\",c\n", 0, 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("\"a", r1.bytes);
    const r2 = it.next().?;
    try t.expectEqualStrings("b\",c", r2.bytes);
}

test "LineIterator: base_offset propagates correctly across records" {
    var it = LineIterator.init("xx\nyy\n", '"', 50);
    try t.expectEqual(@as(u64, 50), it.next().?.byte_offset);
    try t.expectEqual(@as(u64, 53), it.next().?.byte_offset);
}
