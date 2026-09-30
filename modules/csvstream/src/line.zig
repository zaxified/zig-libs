// SPDX-License-Identifier: MIT
//! In-memory RFC 4180 line/field splitting. Operates purely on a caller-owned
//! byte slice — no I/O, no allocation on the common path. `LineIterator` walks
//! a buffer record-by-record while preserving each record's byte offset within
//! the buffer (composed with an absolute `base_offset`); `splitFields` splits a
//! single record into its fields.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");

/// What `splitFieldsOpts` does when the record has more fields than `buf` holds.
pub const OverflowPolicy = enum {
    /// Refuse with `error.FieldBufferTooSmall`. The default, and what
    /// `splitFields` always does — see F2 in this module's CHANGELOG for why
    /// silently dropping the surplus is a defect rather than leniency.
    @"error",
    /// Fill `buf`, return it, and drop the surplus fields. For a caller whose
    /// own contract is to keep processing malformed input rather than refuse
    /// it (a converter fed third-party files, say).
    ///
    /// ⚠ **The caller takes on F2's composed failure, F3.** When a header and
    /// its rows are split with the SAME buffer, both truncate to the same
    /// width, so `validateArity` reports a match and `Header.len()` returns
    /// the truncated count as if it were the true one — the file's real shape
    /// is gone and nothing downstream can tell. A `.truncate` caller must
    /// handle that itself: `countFields` gives the true count for a record
    /// independent of any buffer, and sizing the header's buffer one slot
    /// wider than the rows' makes an over-wide header detectable.
    truncate,
};

/// Caller policy for `splitFieldsOpts`. Passed as a literal the branch is
/// comptime-known and folds away, so a call site pays nothing for the choice.
pub const SplitOptions = struct {
    on_overflow: OverflowPolicy = .@"error",
};

/// Splits one CSV line into its constituent fields.
///
/// `delimiter` is the field separator (typically ',').
/// `quote` controls the quoting character (0 = no quoting, '"' = RFC 4180).
/// When quote != 0, fields wrapped in that character may contain the delimiter;
/// doubled quote chars (e.g. "" for quote='"') inside a quoted field are
/// unescaped to a single quote char.
/// Fills `buf` with slices that point directly into `line` when no unescaping
/// is needed, or into alloc-owned copies for fields containing an escaped quote.
/// Those copies are the caller's to free: `freeFields(line, fields, alloc)`
/// frees exactly them, or split with an arena and reset it per record.
/// Returns a sub-slice of `buf` containing only the fields found on the line.
/// `buf` must be large enough to hold all fields — a record with more fields
/// than `buf` holds is `error.FieldBufferTooSmall`, never a short row. Use
/// `splitFieldsOpts` to choose truncation instead; extra capacity is ignored.
pub fn splitFields(line: []const u8, buf: [][]const u8, delimiter: u8, quote: u8, alloc: std.mem.Allocator) ![][]const u8 {
    return splitFieldsOpts(line, buf, delimiter, quote, alloc, .{});
}

/// Frees the fields `splitFields`/`splitFieldsOpts` allocated for `line` —
/// the unescaped copies of fields that held a doubled quote — and nothing
/// else: every other field borrows `line` and is left alone. `line` and
/// `alloc` must be the ones the split was given, and `line` must still be
/// alive (the test is on addresses: a borrowed field lies inside `line`, a
/// copy cannot). Not needed when `alloc` is an arena the caller resets.
///
/// Until 2026-09-18 a caller with a general-purpose allocator had no way to
/// do this: which fields were copies was visible only to the split's own
/// error path, and a record with escaped quotes leaked on the success path.
pub fn freeFields(line: []const u8, fields: []const []const u8, alloc: std.mem.Allocator) void {
    for (fields) |f| {
        // Zero-length fields are never copies (a copy holds at least the one
        // quote it unescaped) and an empty borrowed field at end of record
        // has the one-past-the-end address, which no range test attributes.
        if (f.len != 0 and !borrowsFrom(f, line)) alloc.free(f);
    }
}

/// `splitFields` with the caller's overflow policy — see `SplitOptions`.
/// Identical in every other respect; `splitFields` is this with the default.
pub fn splitFieldsOpts(
    line: []const u8,
    buf: [][]const u8,
    delimiter: u8,
    quote: u8,
    alloc: std.mem.Allocator,
    opts: SplitOptions,
) ![][]const u8 {
    var count: usize = 0;
    var pos: usize = 0;
    // Fields that needed unescaping are alloc-owned; every other field borrows
    // `line`. On an error partway through, the caller never receives the
    // slice, so without this the copies made so far were simply unreachable
    // (W2 re-audit 2026-09-02, `csvstream` F7).
    //
    // WHICH slots are copies is asked of the ADDRESS, not of a side list. That
    // list used to be a fixed `[64]usize`, and the 65th copy onwards was made
    // but never recorded, so this errdefer freed 64 of them and left the rest
    // unreachable — measured 2026-09-17 on a record of 15,000 escaped fields
    // split into a 4,096-slot buffer: 4,096 copies, 64 freed, 40,324,032 bytes
    // stranded per call, on the module's own default (refusing) policy.
    // Asking the address has no ceiling to exceed and allocates nothing, which
    // is what this path needs — it runs when an allocation has just failed.
    // A zero-length field is skipped rather than classified: an empty
    // borrowed field at end-of-record has the one-past-the-end address, which
    // no range test can attribute. `Allocator.free` is a no-op at length 0
    // either way, so nothing is stranded by skipping it. The same test is the
    // caller's `freeFields` on the success path.
    errdefer freeFields(line, buf[0..count], alloc);
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
                    } else if (pos + 1 == line.len or line[pos + 1] == delimiter) {
                        break; // Closing quote: end of record, or a delimiter next.
                    } else {
                        // ⚠ A lone quote with something OTHER than a delimiter
                        // after it is a literal quote — Go `encoding/csv`'s
                        // `LazyQuotes` rule, which this module's docs name as
                        // its model. It used to close the field here, so a
                        // field boundary was emitted at a position where the
                        // input contains no delimiter: `"a"b` became two
                        // fields, `"a,b"c,d` became three. File content then
                        // chose a row's column count, `Header.get` read the
                        // wrong column, and `unbalanced_quote` stayed false
                        // because the quotes really were balanced
                        // (W2 re-audit 2026-09-02, `csvstream` F1).
                        pos += 1;
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
    // The surplus used to be dropped in silence — and because a header and its
    // rows are usually split with the same buffer, both were truncated to the
    // same width, so `validateArity` reported a match and `Header.len()`
    // returned the truncated column count as if it were the true one. The
    // signature always had an error channel; nothing used it
    // (W2 re-audit 2026-09-02, `csvstream` F2). Refusing stays the DEFAULT;
    // `.truncate` is that old behaviour back, but only where a caller asked
    // for it in as many words and took F3 on (see `OverflowPolicy.truncate`).
    if (count == buf.len and pos < line.len and opts.on_overflow == .@"error") {
        return error.FieldBufferTooSmall;
    }
    // Falling through on `.truncate` is what makes the surplus safe to drop:
    // the `errdefer` above frees the alloc-owned (escaped-quote) fields, and
    // it runs only on an error return. A caller that today ignores
    // `FieldBufferTooSmall` and reads `buf` anyway gets those slots freed
    // under it, with no way to tell which slots they were.
    return buf[0..count];
}

/// How many fields `splitFields` would produce for `line` — the true count,
/// independent of any buffer. Exists because `splitFields`'s "buf must be
/// large enough" was a precondition a caller had no way to evaluate: learning
/// the count meant re-implementing the quote-aware scan.
pub fn countFields(line: []const u8, delimiter: u8, quote: u8) usize {
    var n: usize = 0;
    var pos: usize = 0;
    while (pos <= line.len) {
        if (pos == line.len) break;
        if (quote != 0 and line[pos] == quote) {
            pos += 1;
            while (pos < line.len) {
                const b = line[pos];
                if (b == quote) {
                    if (pos + 1 < line.len and line[pos + 1] == quote) {
                        pos += 2;
                    } else if (pos + 1 == line.len or line[pos + 1] == delimiter) {
                        break;
                    } else {
                        pos += 1;
                    }
                } else pos += 1;
            }
            if (pos < line.len) pos += 1;
            if (pos < line.len and line[pos] == delimiter) pos += 1;
        } else {
            while (pos < line.len and line[pos] != delimiter) : (pos += 1) {}
            if (pos < line.len) pos += 1;
        }
        n += 1;
    }
    return n;
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
    /// situation isn't silent. See `LineIterator.next`. In `.span` mode it is
    /// set exactly when an opening quote was declared stray and the record
    /// fell back to one physical line (see `SpanConfig`).
    unbalanced_quote: bool = false,
    /// `.span` mode only: the record contains a newline inside a quoted
    /// field, i.e. it covers more than one physical line.
    spanned: bool = false,
};

/// How a newline inside a quoted field is read.
pub const QuotedNewlines = enum {
    /// Every `\n` ends a record, open quote or not ("lazy quotes"). The
    /// default: a stray quote costs one line, never the rest of the file,
    /// and every `\n` is a chunk boundary.
    end_record,
    /// RFC 4180 §2 rule 6: a quoted field may contain newlines — bounded.
    /// See `SpanConfig`.
    span,
};

/// Default cap on the newlines one quoted field may contain in `.span` mode.
pub const default_max_quoted_lines: usize = 64;

/// Which field count a spanned record must have to keep its span.
pub const FieldCheck = union(enum) {
    /// No field-count check.
    none,
    /// The first non-empty record (the header) sets the count.
    first_record,
    /// A count the caller knows.
    count: usize,
};

/// `.span` mode: quoted fields may cross newlines, within a bound.
///
/// **Why a bound.** An opening quote is ambiguous: the start of a multi-line
/// field, or a stray byte. No local rule tells them apart, and reading a stray
/// quote as an opener swallows everything up to the next stray quote — bxp
/// once lost ~256 k rows of IMDb `title.basics.tsv` to two of them. So a
/// quoted field may contain at most `max_quoted_lines` newlines and the record
/// at most `max_record_len` bytes; past either, the opening quote is declared
/// stray and the record is re-read as one physical line, flagged
/// `unbalanced_quote`. A stray quote then costs one record's look-ahead, never
/// the file, and memory stays bounded. `field_check` adds a second test: a
/// spanned record whose field count differs from the expected one falls back
/// the same way — the line cap alone lets through two stray quotes that happen
/// to lie close together.
///
/// **What opens a quoted field.** Only a quote at the start of a field. A
/// quote inside an unquoted field (`5" floppy`) is a literal byte, as in RFC
/// 4180 and Go `encoding/csv`, and as `splitFields` already reads it. Inside
/// a quoted field, `""` is an escaped quote, a quote followed by the
/// delimiter, `\n`, `\r\n` or the end of input closes the field, and any other
/// quote is literal (Go's `LazyQuotes` rule, again matching `splitFields`).
pub const SpanConfig = struct {
    delimiter: u8 = ',',
    max_quoted_lines: usize = default_max_quoted_lines,
    /// Byte cap on one spanned record. `StreamReader` sets it to its own
    /// `max_record_len`; in memory it defaults to no cap.
    max_record_len: usize = std.math.maxInt(usize),
    field_check: FieldCheck = .none,
};

/// The `.span` record scanner: `SpanConfig` plus what it has learned so far
/// (the header's field count under `.first_record`). One function decides
/// where every spanned record ends — `ChunkReader` (to cut chunks) and
/// `LineIterator` (to split them) both call it, so the two cannot disagree.
pub const SpanScanner = struct {
    quote: u8,
    cfg: SpanConfig,
    /// The field count a spanned record must have, once known.
    expected_fields: ?usize = null,
    /// Still waiting for the first non-empty record (`.first_record`).
    awaiting_header: bool = false,

    pub fn init(quote: u8, cfg: SpanConfig) SpanScanner {
        return .{
            .quote = quote,
            .cfg = cfg,
            .expected_fields = switch (cfg.field_check) {
                .count => |n| n,
                else => null,
            },
            .awaiting_header = cfg.field_check == .first_record,
        };
    }

    pub const Scan = union(enum) {
        /// A record: `bytes[start..end]` (the terminator and any `\r` before
        /// it not yet stripped); the next record starts at `next`.
        record: struct { end: usize, next: usize, spanned: bool, unbalanced: bool },
        /// More bytes are needed to decide; only when `at_eof` is false.
        incomplete,
    };

    /// Scan one record starting at `start`. `at_eof`: `bytes` ends where the
    /// input ends (true in memory and for a chunk already cut on a record
    /// boundary); false while a `ChunkReader` still has bytes to read.
    ///
    /// Why the chunk cut and the split agree: every decision here depends
    /// only on bytes up to what decided it. A record that closes normally
    /// lies wholly inside the chunk; a record that fell back was decided by
    /// look-ahead that lay in the buffer, and when the chunk is cut before that
    /// look-ahead, the re-scan meets the chunk's end still inside the quote and
    /// falls back at EOF — to the same physical line.
    pub fn scan(self: *SpanScanner, bytes: []const u8, start: usize, at_eof: bool) Scan {
        const r = self.scanRaw(bytes, start, at_eof);
        if (r == .record and self.awaiting_header) {
            const rec = trimCr(bytes[start..r.record.end]);
            if (rec.len != 0) {
                self.awaiting_header = false;
                self.expected_fields = countFields(rec, self.cfg.delimiter, self.quote);
            }
        }
        return r;
    }

    fn scanRaw(self: *const SpanScanner, bytes: []const u8, start: usize, at_eof: bool) Scan {
        const quote = self.quote;
        const delim = self.cfg.delimiter;
        var pos = start;
        var field_start = true;
        var in_q = false;
        var spanned = false;
        var q_lines: usize = 0;
        while (pos < bytes.len) {
            const c = bytes[pos];
            if (in_q) {
                if (c == quote) {
                    // The byte after a quote decides escape vs close vs
                    // literal; at the buffer's end it is not known yet.
                    if (pos + 1 >= bytes.len) {
                        if (!at_eof) return .incomplete;
                        in_q = false;
                        pos += 1;
                        continue;
                    }
                    const n = bytes[pos + 1];
                    if (n == quote) {
                        pos += 2;
                        continue;
                    }
                    if (n == delim or n == '\n') {
                        in_q = false;
                        pos += 1;
                        continue;
                    }
                    if (n == '\r') {
                        if (pos + 2 >= bytes.len) {
                            if (!at_eof) return .incomplete;
                            in_q = false;
                            pos += 1;
                            continue;
                        }
                        if (bytes[pos + 2] == '\n') {
                            in_q = false;
                            pos += 1;
                            continue;
                        }
                    }
                    pos += 1; // a literal quote inside the field
                } else {
                    if (c == '\n') {
                        spanned = true;
                        q_lines += 1;
                        if (q_lines > self.cfg.max_quoted_lines) return lazyFallback(bytes, start, at_eof);
                    }
                    pos += 1;
                }
                if (spanned and pos - start >= self.cfg.max_record_len) return lazyFallback(bytes, start, at_eof);
            } else {
                if (c == '\n') return self.finish(bytes, start, pos, pos + 1, spanned, at_eof);
                if (field_start and quote != 0 and c == quote) {
                    in_q = true;
                    field_start = false;
                } else field_start = c == delim;
                pos += 1;
            }
        }
        if (!at_eof) return .incomplete;
        // The input ended inside a quote: the opener had no closer at all.
        if (in_q) return lazyFallback(bytes, start, true);
        return self.finish(bytes, start, bytes.len, bytes.len, spanned, true);
    }

    fn finish(self: *const SpanScanner, bytes: []const u8, start: usize, end: usize, next: usize, spanned: bool, at_eof: bool) Scan {
        if (spanned) {
            if (self.expected_fields) |want| {
                if (countFields(trimCr(bytes[start..end]), self.cfg.delimiter, self.quote) != want)
                    return lazyFallback(bytes, start, at_eof);
            }
        }
        return .{ .record = .{ .end = end, .next = next, .spanned = spanned, .unbalanced = false } };
    }

    /// The opening quote was stray: the record is the physical line it
    /// starts on, as `.end_record` mode reads it.
    fn lazyFallback(bytes: []const u8, start: usize, at_eof: bool) Scan {
        if (std.mem.indexOfScalarPos(u8, bytes, start, '\n')) |nl|
            return .{ .record = .{ .end = nl, .next = nl + 1, .spanned = false, .unbalanced = true } };
        if (!at_eof) return .incomplete;
        return .{ .record = .{ .end = bytes.len, .next = bytes.len, .spanned = false, .unbalanced = true } };
    }
};

fn trimCr(rec: []const u8) []const u8 {
    if (rec.len > 0 and rec[rec.len - 1] == '\r') return rec[0 .. rec.len - 1];
    return rec;
}

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
/// every following row up to the next quote. (Go's `encoding/csv` LazyQuotes
/// tolerates the stray quote too, but still lets a quoted field span lines;
/// the one-line rule is this module's own.) When a record ends with an open quote,
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
///
/// `initSpan` selects `.span` mode instead: quoted fields may contain
/// newlines, within `SpanConfig`'s bound. The buffer's end is the input's end.
pub const LineIterator = struct {
    bytes: []const u8,
    quote: u8,
    base_offset: u64,
    pos: usize,
    /// Non-null in `.span` mode. Carries what it learned (the header's field
    /// count) from record to record.
    span: ?SpanScanner = null,

    pub fn init(bytes: []const u8, quote: u8, base_offset: u64) LineIterator {
        return .{ .bytes = bytes, .quote = quote, .base_offset = base_offset, .pos = 0 };
    }

    pub fn initSpan(bytes: []const u8, quote: u8, base_offset: u64, cfg: SpanConfig) LineIterator {
        return initSpanScanner(bytes, base_offset, SpanScanner.init(quote, cfg));
    }

    /// `.span` mode continuing an existing scanner's state — how
    /// `StreamReader` carries the header's field count from chunk to chunk.
    pub fn initSpanScanner(bytes: []const u8, base_offset: u64, scanner: SpanScanner) LineIterator {
        return .{ .bytes = bytes, .quote = scanner.quote, .base_offset = base_offset, .pos = 0, .span = scanner };
    }

    pub fn next(self: *LineIterator) ?LineSlice {
        if (self.span != null) return self.nextSpan();
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

    fn nextSpan(self: *LineIterator) ?LineSlice {
        const scanner = &self.span.?;
        while (self.pos < self.bytes.len) {
            const rec_start = self.pos;
            // `at_eof` is true, so the scan always yields a record.
            const r = scanner.scan(self.bytes, rec_start, true).record;
            self.pos = r.next;
            const rec = trimCr(self.bytes[rec_start..r.end]);
            if (rec.len == 0) continue;
            return .{
                .bytes = rec,
                .byte_offset = self.base_offset + rec_start,
                .unbalanced_quote = r.unbalanced,
                .spanned = r.spanned,
            };
        }
        return null;
    }
};

/// The 3-byte UTF-8 byte-order-mark some tools (notably Excel on Windows)
/// prepend to a CSV file so it opens as UTF-8 instead of the system codepage.
pub const utf8_bom = "\xEF\xBB\xBF";

/// Returns `bytes` with a leading UTF-8 BOM stripped, or `bytes` unchanged if
/// none is present. A BOM is only meaningful at the very start of a buffer/
/// file — callers apply this once, to the first chunk, not per-record.
pub fn stripBom(bytes: []const u8) []const u8 {
    if (std.mem.startsWith(u8, bytes, utf8_bom)) return bytes[utf8_bom.len..];
    return bytes;
}

/// Returns a copy of `s` with every doubled quote char replaced by a single one.
/// The returned slice is allocated with `alloc`.
/// Does `f` point into `line`? A field `splitFieldsOpts` did not unescape is a
/// sub-slice of `line` by construction; an unescaped copy is a separate
/// allocation and therefore cannot be. This is what lets the error path tell
/// the two apart with nothing remembered and nothing allocated.
fn borrowsFrom(f: []const u8, line: []const u8) bool {
    const p = @intFromPtr(f.ptr);
    const start = @intFromPtr(line.ptr);
    return p >= start and p < start + line.len;
}

fn unescapeQuotes(s: []const u8, quote: u8, alloc: std.mem.Allocator) ![]u8 {
    var out = std.array_list.Managed(u8).init(alloc);
    // `toOwnedSlice` can allocate too, so a failure anywhere after the
    // reserve leaked the whole list — the same missing-errdefer shape as its
    // caller (W2 re-audit 2026-09-02, `csvstream` F7).
    errdefer out.deinit();
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
// Tests
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

// ============================================================
// stripBom tests
// ============================================================

test "stripBom: strips a leading UTF-8 BOM" {
    const with_bom = "\xEF\xBB\xBFa,b\n";
    const stripped = stripBom(with_bom);
    try t.expectEqualStrings("a,b\n", stripped);
}

test "stripBom: leaves input unchanged when no BOM present" {
    const plain = "a,b\n";
    try t.expectEqualStrings(plain, stripBom(plain));
}

test "stripBom: does not strip a BOM-like sequence mid-buffer" {
    // Only a LEADING BOM is stripped; the same 3 bytes elsewhere are data.
    const mid = "a\xEF\xBB\xBFb";
    try t.expectEqualStrings(mid, stripBom(mid));
}

test "stripBom: empty and too-short inputs are unaffected" {
    try t.expectEqualStrings("", stripBom(""));
    try t.expectEqualStrings("\xEF\xBB", stripBom("\xEF\xBB")); // partial BOM, not a match
}

test "stripBom composes with LineIterator: BOM-prefixed buffer yields a clean first record" {
    const raw = "\xEF\xBB\xBFname,age\nalice,30\n";
    var it = LineIterator.init(stripBom(raw), '"', 0);
    const r1 = it.next().?;
    try t.expectEqualStrings("name,age", r1.bytes);
    const r2 = it.next().?;
    try t.expectEqualStrings("alice,30", r2.bytes);
}

// ── fuzz: LineIterator and splitFields are the untrusted-input decode
// surface (arbitrary CSV bytes) — must never panic, loop forever, or read
// out of bounds, only yield records/fields or drop silently.

/// `testkit.fuzz.seed`, aliased so the corpora below read as the CSV they are.
/// A corpus entry is not the record: `Smith.slice` reads a little-endian `u32`
/// length first, so a raw buffer would arrive minus its own first four octets.
const seed = @import("testkit").fuzz.seed;

/// The quoting characters both harnesses sweep. `quote` used to come from
/// `smith.value(u8)` drawn AFTER the byte draw, which on a corpus replay is
/// always 0 — the "no quoting at all" setting — so the entire quoted-field
/// branch (and with it the `LazyQuotes` rule the F1 fix above is about) was
/// unreachable from any seed. Swept rather than drawn: the fuzzer still drives
/// the bytes, and every seed now visits both settings.
const fuzz_quotes = [_]u8{ '"', 0 };

/// The field separators `fuzzSplitFields` sweeps, for the same reason:
/// `delimiter` was also drawn after the bytes and was therefore always 0, so
/// no seed could ever produce more than one field.
const fuzz_delims = [_]u8{ ',', ';', '\t' };

/// Multi-record buffers, in the format the length draw reads. The shapes the
/// value tests pin: both terminators, a bare CR, a quoted field spanning a
/// newline, an unterminated quote (the scan runs to the end of the buffer —
/// the loop this harness bounds), and a leading BOM.
const line_seeds = [_][]const u8{
    seed("name,age\nalice,30\nbob,31\n"), // the ordinary LF-terminated document
    seed("name,age\r\nalice,30\r\n"), // CRLF
    seed("a,b\rc,d\n"), // a bare CR inside the buffer
    seed("\"multi\nline\",x\nnext,y\n"), // a newline inside a quoted field
    seed("\"unterminated,x\ny\n"), // an unterminated quote: the scan runs to the end
    seed("\xEF\xBB\xBFname,age\nalice,30\n"), // a leading BOM, unstripped
    seed("a\n\nb\n"), // an empty record between two records
    seed("no trailing terminator"), // the final record with no terminator at all
    seed("\n\r\n\r"), // terminators only
    seed("\"\"\"\",\"a\"\"b\"\n"), // doubled quotes, both as a whole field and inside one
};

test "fuzz: LineIterator never panics or loops on arbitrary bytes" {
    // `std.testing.fuzz`, spelled out rather than through this file's `t`
    // alias: `zig build check-fuzz` greps the SOURCE TEXT for the literal
    // substring "testing.fuzz(" to find harnesses, so `t.fuzz(` — this
    // harness's original form — was structurally invisible to the gate
    // despite genuinely running, which is why this module was flagged as
    // uncovered even though it already had two working harnesses.
    try std.testing.fuzz({}, fuzzLineIterator, .{ .corpus = &line_seeds });
}

fn fuzzLineIterator(_: void, smith: *std.testing.Smith) !void {
    // ⚠ This used to be `smith.bytes(&buf)` followed by
    // `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` consumes
    // `min(buf.len, in.len)` octets and the ranged draw then reads eight MORE
    // as a little-endian u64, returning the range minimum when fewer remain —
    // so `len` was 0 on every input a seed can carry, `it.next()` returned null
    // at once, and the `steps <= len + 1` assertion below had never executed.
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);

    for (fuzz_quotes) |quote| {
        var it = LineIterator.init(buf[0..len], quote, 0);
        // Every record consumes at least one byte plus its terminator, so the
        // number of records is bounded by the input length.
        var steps: usize = 0;
        while (it.next()) |_| {
            steps += 1;
            try t.expect(steps <= len + 1);
        }
    }
}

test "corpus: every line seed reaches the iterator, and the records yielded are pinned" {
    // Records yielded is the second number: `LineIterator.init("")` is legal
    // and simply yields nothing, so "it did not error" was already true while
    // the harness was seeing an empty buffer.
    //
    // ⚠ The record count is the SAME under both quote settings, and that is not
    // an accident of these seeds — `next` treats '\n' as ending the record even
    // inside an open quote (see the comment in `next`), so quoting cannot change
    // how a buffer splits, only whether the split is reported as unbalanced.
    // Writing this guard is what established that; the first draft asserted the
    // two counts would differ, and it was wrong. `unbalanced` is therefore the
    // number that separates the two settings, and it is the one the drawn knob
    // could never reach: with `quote == 0` it is 0 for every input there is.
    var nonempty: usize = 0;
    var records: usize = 0;
    var unbalanced_quoted: usize = 0;
    var unbalanced_raw: usize = 0;
    for (line_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        for (fuzz_quotes, [_]*usize{ &unbalanced_quoted, &unbalanced_raw }) |quote, counter| {
            var it = LineIterator.init(buf[0..len], quote, 0);
            while (it.next()) |rec| {
                if (quote == fuzz_quotes[0]) records += 1;
                if (rec.unbalanced_quote) counter.* += 1;
            }
        }
    }
    try t.expectEqual(line_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 of 10 seeds arrived
    // non-empty, 0 records were yielded and `unbalanced_quote` was never once
    // set. After: 10 seeds / 17 records / 3 unbalanced with quoting on, 0 with
    // quoting off — which is exactly the branch the drawn knob had disabled.
    try t.expectEqual(@as(usize, 17), records);
    try t.expectEqual(@as(usize, 3), unbalanced_quoted);
    try t.expectEqual(@as(usize, 0), unbalanced_raw);
}

/// Single records, in the format the length draw reads: the `LazyQuotes`
/// shapes the "a field ends only at a delimiter" test pins, plus the escape
/// and allocation edges (a doubled quote forces the alloc path) and a record
/// with more fields than the 64-slot buffer can hold.
const field_seeds = [_][]const u8{
    seed("a,b,c"), // three plain fields
    seed("\"a\",b"), // an ordinary quoted field
    seed("\"a\"b"), // LazyQuotes: a lone quote followed by a non-delimiter
    seed("\"a,b\"c,d"), // …the same, with a delimiter inside the quoted run
    seed("\"a\"\"b\",c"), // a doubled quote: this is the seed that allocates
    seed("\"\"a"), // an empty quoted field immediately followed by data
    seed("a;b;c"), // the ';' delimiter of the sweep
    seed("a\tb\tc"), // the '\t' delimiter of the sweep
    seed(",,,"), // empty fields only
    seed("\"unterminated"), // the closing quote never arrives
    seed("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,+,/,=,!"), // 66 fields against a 64-slot buffer
};

test "fuzz: splitFields never panics on arbitrary bytes" {
    // See the sibling harness above for why this is spelled out rather than
    // through the `t` alias.
    try std.testing.fuzz({}, fuzzSplitFields, .{ .corpus = &field_seeds });
}

fn fuzzSplitFields(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();

    // ⚠ Same collapse as the sibling: the length was 0 and both `delimiter`
    // and `quote` were drawn after the bytes, so every seed reached
    // `splitFields` as an empty record with delimiter 0 and quoting disabled.
    var line_buf: [256]u8 = undefined;
    const len: usize = smith.slice(&line_buf);

    var fields_buf: [64][]const u8 = undefined;
    for (fuzz_delims) |delimiter| {
        for (fuzz_quotes) |quote| {
            _ = splitFields(line_buf[0..len], &fields_buf, delimiter, quote, arena.allocator()) catch continue;
        }
    }
}

test "corpus: every field seed reaches splitFields, and the fields split are pinned" {
    // Fields split is the second number: `splitFields("")` returns an empty
    // slice without erroring, so an "it did not error" guard reads 100% on a
    // harness seeing nothing. The count below cannot be produced by an empty
    // record, and it also cannot be produced with `quote == 0`, which is what
    // the drawn knob always was.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var nonempty: usize = 0;
    var fields: usize = 0;
    var errors: usize = 0;
    var fields_buf: [64][]const u8 = undefined;
    for (field_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var line_buf: [256]u8 = undefined;
        const len: usize = smith.slice(&line_buf);
        if (len != 0) nonempty += 1;
        for (fuzz_delims) |delimiter| {
            for (fuzz_quotes) |quote| {
                const out = splitFields(line_buf[0..len], &fields_buf, delimiter, quote, arena.allocator()) catch {
                    errors += 1;
                    continue;
                };
                fields += out.len;
            }
        }
    }
    try t.expectEqual(field_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 11 seeds non-empty and 0 fields split before.
    try t.expectEqual(@as(usize, 86), fields);
    try t.expectEqual(@as(usize, 2), errors); // the 66-field seed against the 64-slot buffer, both quote settings
}

test "a field ends only at a delimiter or at end of record" {
    const gpa = std.testing.allocator;
    // Junk after a closing quote used to end the field there, emitting a
    // boundary at a position where the input contains no delimiter. Expected
    // values below are Go `encoding/csv` with `LazyQuotes=true`, which is the
    // model this module's own docs name (W2 re-audit 2026-09-02, F1).
    const cases = [_]struct { in: []const u8, want: []const []const u8 }{
        .{ .in = "\"a\"b", .want = &.{"a\"b"} },
        .{ .in = "\"\"a", .want = &.{"\"a"} },
        .{ .in = "\"a\"b\"c", .want = &.{"a\"b\"c"} },
        .{ .in = "\"a\" ,b", .want = &.{"a\" ,b"} },
        .{ .in = "\"a,b\"c,d", .want = &.{"a,b\"c,d"} },
        // …and the ordinary shapes still behave.
        .{ .in = "\"a\",b", .want = &.{ "a", "b" } },
        .{ .in = "\"a,b\",c", .want = &.{ "a,b", "c" } },
        .{ .in = "a,b", .want = &.{ "a", "b" } },
        .{ .in = "\"a\"\"b\"", .want = &.{"a\"b"} },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var buf: [8][]const u8 = undefined;
        const got = try splitFields(c.in, &buf, ',', '"', arena.allocator());
        // The count first: an inflated field count is the shape that shifts
        // every later column.
        try std.testing.expectEqual(c.want.len, got.len);
        try std.testing.expectEqual(c.want.len, countFields(c.in, ',', '"'));
        try std.testing.expectEqualStrings(c.want[0], got[0]);
    }
}

test "a record with more fields than the buffer holds is an error, not a short row" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const wide = "c1,c2,c3,c4,c5,c6,c7,c8,c9,c10";
    try std.testing.expectEqual(@as(usize, 10), countFields(wide, ',', '"'));

    var small: [4][]const u8 = undefined;
    try std.testing.expectError(error.FieldBufferTooSmall, splitFields(wide, &small, ',', '"', a));

    // Exactly the right size is fine — the bound is pinned at the value, not
    // near it.
    var exact: [10][]const u8 = undefined;
    const got = try splitFields(wide, &exact, ',', '"', a);
    try std.testing.expectEqual(@as(usize, 10), got.len);

    // The composed case this made possible: header and row split with the
    // same too-small buffer were truncated to the same width, so the module's
    // own ragged-row guard reported a match and `Header.get` returned another
    // column's bytes (F3).
    var hbuf: [3][]const u8 = undefined;
    try std.testing.expectError(
        error.FieldBufferTooSmall,
        splitFields("user,note,role,extra", &hbuf, ',', '"', a),
    );
}

test "splitFieldsOpts: .truncate fills the buffer, drops the surplus, and does NOT free what it returns" {
    // ⭐ The seam. Escaped-quote fields are alloc-owned and the `errdefer`
    // frees them -- which is exactly why "ignore FieldBufferTooSmall and read
    // buf anyway" was never a workaround: those slots come back freed, with
    // no way to tell which ones they were. `.truncate` returns through the
    // SUCCESS path, so the errdefer must not run at all.
    const gpa = std.testing.allocator;
    const wide = "\"a\"\"b\",c,d,e";
    // The true width is still knowable after truncation -- this is how a
    // `.truncate` caller detects that it happened (see `OverflowPolicy`).
    try std.testing.expectEqual(@as(usize, 4), countFields(wide, ',', '"'));

    var buf: [2][]const u8 = undefined;
    const got = try splitFieldsOpts(wide, &buf, ',', '"', gpa, .{ .on_overflow = .truncate });
    try std.testing.expectEqual(@as(usize, 2), got.len);
    // Not just the count: the CONTENT of the owned slot survived, unescaped.
    try std.testing.expectEqualStrings("a\"b", got[0]);
    try std.testing.expectEqualStrings("c", got[1]);

    // Exact accounting, enforced by `testing.allocator`: freeing the owned
    // slot here is a double free if the split already freed it, and a leak if
    // nobody does. Borrowed slots point into `wide` and must not be freed.
    for (got) |fld| {
        const borrowed = @intFromPtr(fld.ptr) >= @intFromPtr(wide.ptr) and
            @intFromPtr(fld.ptr) < @intFromPtr(wide.ptr) + wide.len;
        if (!borrowed) gpa.free(fld);
    }
}

test "freeFields frees exactly the copies a split made, on the success path, past 64 of them" {
    // `testing.allocator` is the judge both ways: a copy left behind is a
    // leak, and a borrowed field handed to `free` is an invalid free. 200
    // escaped fields also cross the old 64-slot ceiling the error path had
    // (`9a42db83`), and the unescaped fields between them must stay borrowed.
    const gpa = std.testing.allocator;
    var rec: std.ArrayList(u8) = .empty;
    defer rec.deinit(gpa);
    for (0..200) |i| {
        if (i != 0) try rec.append(gpa, ',');
        if (i % 2 == 0) try rec.appendSlice(gpa, "\"x\"\"y\"") else try rec.appendSlice(gpa, "plain");
    }
    var buf: [256][]const u8 = undefined;
    const got = try splitFields(rec.items, &buf, ',', '"', gpa);
    try std.testing.expectEqual(@as(usize, 200), got.len);
    try std.testing.expectEqualStrings("x\"y", got[0]);
    try std.testing.expectEqualStrings("plain", got[1]);
    freeFields(rec.items, got, gpa);

    // A record with no escaped quote allocates nothing, and freeing it is a no-op.
    const plain = "a,\"b,c\",,d";
    const fields = try splitFields(plain, &buf, ',', '"', gpa);
    try std.testing.expectEqual(@as(usize, 4), fields.len);
    freeFields(plain, fields, gpa);
}

test "splitFieldsOpts: the DEFAULT policy is refusal, so `.{}` is byte-for-byte splitFields" {
    // The F2 audit result is what an uninformed caller keeps getting. A
    // mutation of the field's default flips this test, which a test that only
    // ever passed `.truncate` explicitly would not notice.
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    try std.testing.expectEqual(OverflowPolicy.@"error", (SplitOptions{}).on_overflow);

    const wide = "c1,c2,c3,c4,c5";
    var small: [2][]const u8 = undefined;
    try std.testing.expectError(
        error.FieldBufferTooSmall,
        splitFieldsOpts(wide, &small, ',', '"', a, .{}),
    );
    try std.testing.expectError(
        error.FieldBufferTooSmall,
        splitFieldsOpts(wide, &small, ',', '"', a, .{ .on_overflow = .@"error" }),
    );

    // ⭐ And `.truncate` is not a no-op guard that happens to agree: on a
    // record that FITS, both policies return the same fields, so the option
    // only ever speaks to the overflow case.
    var exact: [5][]const u8 = undefined;
    const strict = try splitFieldsOpts(wide, &exact, ',', '"', a, .{});
    try std.testing.expectEqual(@as(usize, 5), strict.len);
    var exact2: [5][]const u8 = undefined;
    const lenient = try splitFieldsOpts(wide, &exact2, ',', '"', a, .{ .on_overflow = .truncate });
    try std.testing.expectEqual(@as(usize, 5), lenient.len);
    for (strict, lenient) |x, y| try std.testing.expectEqualStrings(x, y);
}

test "a failed split frees the fields it had already allocated" {
    // Only escaped-quote fields allocate, so this needs two of them and a
    // failure on the second. Without the errdefer the first one's bytes are
    // unreachable: the caller never receives the slice
    // (W2 re-audit 2026-09-02, `csvstream` F7).
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    const a = failing.allocator();
    var buf: [4][]const u8 = undefined;
    try std.testing.expectError(
        error.OutOfMemory,
        splitFields("\"a\"\"a\",\"b\"\"b\"", &buf, ',', '"', a),
    );
    try std.testing.expectEqual(failing.allocations, failing.deallocations);
}

/// Builds a record of `n` fields that every one need unescaping (`"a""a"`), so
/// the split allocates exactly once per field. Shared by the two tests below,
/// which differ only in HOW the split is made to fail.
fn escapedRecord(alloc: std.mem.Allocator, n: usize) ![]u8 {
    var out = std.array_list.Managed(u8).init(alloc);
    errdefer out.deinit();
    for (0..n) |i| {
        if (i > 0) try out.append(',');
        try out.appendSlice("\"a\"\"a\"");
    }
    return out.toOwnedSlice();
}

test "a failed split frees ALL the fields it allocated, past any fixed bookkeeping size" {
    // ⭐ The test above pins the same invariant at TWO fields, and that is why
    // it kept passing while the invariant did not hold: the errdefer used to
    // consult a fixed `[64]usize` of copied-slot indices, so it freed the
    // first 64 copies and left every later one unreachable. Two is under 64.
    // 200 is not.
    const gpa = std.testing.allocator;
    const rec = try escapedRecord(gpa, 200);
    defer gpa.free(rec);
    try std.testing.expectEqual(@as(usize, 200), countFields(rec, ',', '"'));

    // Fail an allocation well past the old ceiling, so the copies already made
    // span both sides of it.
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 150 });
    const a = failing.allocator();
    const buf = try gpa.alloc([]const u8, 256);
    defer gpa.free(buf);
    try std.testing.expectError(error.OutOfMemory, splitFields(rec, buf, ',', '"', a));

    // Bytes, not just counts: a partial cleanup shows up here as a positive
    // remainder even when the allocation/free COUNTS happen to line up.
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    try std.testing.expectEqual(failing.allocations, failing.deallocations);
}

test "the overflow refusal frees the fields it allocated, however many there were" {
    // The reachable half of the same defect, and the one that needs no
    // allocation failure at all: a record WIDER than the field buffer is
    // refused after the buffer has been filled with copies. Measured before
    // the fix on 15,000 fields into a 4,096-slot buffer: 4,096 copies made,
    // 64 freed, 40,324,032 bytes stranded on one call — attacker-shaped, since
    // the field count is chosen by the input file.
    const gpa = std.testing.allocator;
    const rec = try escapedRecord(gpa, 200);
    defer gpa.free(rec);

    var failing = std.testing.FailingAllocator.init(gpa, .{});
    const a = failing.allocator();
    const buf = try gpa.alloc([]const u8, 100); // < 200, and > 64
    defer gpa.free(buf);
    try std.testing.expectError(error.FieldBufferTooSmall, splitFields(rec, buf, ',', '"', a));

    // Bytes first: a partial cleanup leaves a positive remainder here even
    // when the counts happen to line up.
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    try std.testing.expectEqual(failing.allocations, failing.deallocations);
    // And the test is not vacuous: every one of the 100 filled slots was a
    // copy, so the cleanup had at least that many to find. (`unescapeQuotes`
    // allocates more than once per field; the count is not pinned exactly,
    // because that is its business and not this invariant's.)
    try std.testing.expect(failing.allocations >= 100);
}

test "the cleanup frees only the copies, never a field borrowed from the record" {
    // The other way this can go wrong: freeing a slice that points into the
    // caller's record. Mixing borrowed and copied fields means the cleanup has
    // to tell them apart correctly in BOTH directions -- a test made only of
    // escaped fields would pass an errdefer that freed everything in `buf`.
    const gpa = std.testing.allocator;
    var out = std.array_list.Managed(u8).init(gpa);
    defer out.deinit();
    // 400 alternating fields into a 200-slot buffer, so 100 of the filled
    // slots are copies -- past the old 64-entry ceiling in this direction too.
    for (0..400) |i| {
        if (i > 0) try out.append(',');
        // Alternating: even fields borrow, odd fields are copied.
        try out.appendSlice(if (i % 2 == 0) "plain" else "\"a\"\"a\"");
    }

    var failing = std.testing.FailingAllocator.init(gpa, .{});
    const a = failing.allocator();
    const buf = try gpa.alloc([]const u8, 200);
    defer gpa.free(buf);
    try std.testing.expectError(error.FieldBufferTooSmall, splitFields(out.items, buf, ',', '"', a));

    // Half of the 200 filled slots were copies; the other half point into
    // `out.items` and must be left alone. An errdefer that freed the whole
    // buffer indiscriminately would hand `testing.allocator` a pointer it
    // never issued, which it reports as an invalid free — so THAT direction is
    // enforced by the allocator, and this is the other one: nothing stranded.
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    try std.testing.expectEqual(failing.allocations, failing.deallocations);
    try std.testing.expect(failing.allocations >= 100);
}

// ── `.span` mode ─────────────────────────────────────────────────────────────

/// Collect every record `.span` mode yields for `bytes` (arena-owned copies).
fn spanRecords(arena: std.mem.Allocator, bytes: []const u8, cfg: SpanConfig) ![]LineSlice {
    var out: std.ArrayList(LineSlice) = .empty;
    var it = LineIterator.initSpan(bytes, '"', 0, cfg);
    while (it.next()) |r| try out.append(arena, r);
    return out.items;
}

test "span: a quoted field crosses a newline (csv-spectrum newlines shape)" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const recs = try spanRecords(arena_state.allocator(), "a,b,c\n1,2,3\n\"Once upon \na time\",5,6\n7,8,9\n", .{});
    try t.expectEqual(@as(usize, 4), recs.len);
    try t.expectEqualStrings("\"Once upon \na time\",5,6", recs[2].bytes);
    try t.expect(recs[2].spanned and !recs[2].unbalanced_quote);
    try t.expectEqual(@as(u64, 12), recs[2].byte_offset);
    try t.expect(!recs[1].spanned and !recs[3].spanned);
    // The in-line splitter reads the spanned record into the right fields.
    var fbuf: [4][]const u8 = undefined;
    const fields = try splitFields(recs[2].bytes, &fbuf, ',', '"', arena_state.allocator());
    try t.expectEqual(@as(usize, 3), fields.len);
    try t.expectEqualStrings("Once upon \na time", fields[0]);
}

test "span: CRLF inside a quoted field is kept, the record's own CRLF is stripped" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const recs = try spanRecords(arena_state.allocator(), "a,b\r\n\"x\r\ny\",z\r\n", .{});
    try t.expectEqual(@as(usize, 2), recs.len);
    try t.expectEqualStrings("\"x\r\ny\",z", recs[1].bytes);
}

test "span: doubled quotes and newlines together (csv-spectrum quotes_and_newlines shape)" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const recs = try spanRecords(arena, "a,b\n1,\"ha \n\"\"ha\"\" \nha\"\n3,4\n", .{});
    try t.expectEqual(@as(usize, 3), recs.len);
    var fbuf: [4][]const u8 = undefined;
    const fields = try splitFields(recs[1].bytes, &fbuf, ',', '"', arena);
    try t.expectEqualStrings("ha \n\"ha\" \nha", fields[1]);
}

test "span: a quote inside an unquoted field is literal and opens nothing" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const recs = try spanRecords(arena_state.allocator(), "a,5\" floppy,c\nd,e,f\n", .{});
    try t.expectEqual(@as(usize, 2), recs.len);
    try t.expect(!recs[0].spanned and !recs[0].unbalanced_quote);
    try t.expectEqualStrings("d,e,f", recs[1].bytes);
}

test "span: the IMDb shape — two stray field-start quotes far apart give 1:1 rows and two flags" {
    // bxp's `title.basics.tsv` failure: stray quotes 255 866 lines apart. Here
    // 200 apart, well past the 64-line cap.
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(arena, "id\ttitle\n");
    for (0..202) |i| {
        if (i == 1 or i == 201)
            try body.print(arena, "{d}\t\"Rock\n", .{i})
        else
            try body.print(arena, "{d}\tplain\n", .{i});
    }
    const recs = try spanRecords(arena, body.items, .{ .delimiter = '\t' });
    try t.expectEqual(@as(usize, 203), recs.len); // header + 202 rows, none merged
    var flagged: usize = 0;
    for (recs) |r| {
        try t.expect(!r.spanned);
        if (r.unbalanced_quote) flagged += 1;
    }
    try t.expectEqual(@as(usize, 2), flagged);
    try t.expectEqualStrings("1\t\"Rock", recs[2].bytes);
}

test "span: max_quoted_lines is the exact bound" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // A quoted field with exactly `n` newlines, then one more record.
    const build = struct {
        fn f(a: std.mem.Allocator, n: usize) ![]const u8 {
            var b: std.ArrayList(u8) = .empty;
            try b.appendSlice(a, "\"x");
            for (0..n) |_| try b.appendSlice(a, "\ny");
            try b.appendSlice(a, "\",1\nz,2\n");
            return b.items;
        }
    }.f;
    const at_cap = try spanRecords(arena, try build(arena, 3), .{ .max_quoted_lines = 3 });
    try t.expectEqual(@as(usize, 2), at_cap.len);
    try t.expect(at_cap[0].spanned);
    const past_cap = try spanRecords(arena, try build(arena, 4), .{ .max_quoted_lines = 3 });
    // Fallback: the opener's line, then every following physical line.
    try t.expectEqual(@as(usize, 6), past_cap.len);
    try t.expect(past_cap[0].unbalanced_quote and !past_cap[0].spanned);
    try t.expectEqualStrings("\"x", past_cap[0].bytes);
}

test "span: field_check catches two stray quotes that lie close together" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Row 1 opens a stray field-start quote; a stray quote in row 3 closes it.
    // Read as a span they re-balance into one 3-line record of 4 fields under
    // a 3-field header.
    const body = "a,b,c\n1,\"x,y\n2,m,n\n3\",q,z\n4,r,s\n";
    const lax = try spanRecords(arena, body, .{});
    try t.expectEqual(@as(usize, 3), lax.len); // merged: what the line cap alone lets through
    try t.expect(lax[1].spanned);
    const checked = try spanRecords(arena, body, .{ .field_check = .first_record });
    try t.expectEqual(@as(usize, 5), checked.len);
    try t.expect(checked[1].unbalanced_quote and !checked[1].spanned);
    try t.expectEqualStrings("2,m,n", checked[2].bytes);
    // A genuine multi-line field with the right width survives the check.
    const good = try spanRecords(arena, "a,b\n\"x\ny\",1\n", .{ .field_check = .first_record });
    try t.expectEqual(@as(usize, 2), good.len);
    try t.expect(good[1].spanned);
    // `.count` is the same check with a caller-known width.
    const counted = try spanRecords(arena, "\"x\ny\",1\n", .{ .field_check = .{ .count = 3 } });
    try t.expectEqual(@as(usize, 2), counted.len);
}

test "span: max_record_len caps a spanned record; EOF inside a quote falls back" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const capped = try spanRecords(arena, "\"aaaa\nbbbbbbbbbbbbbbbb\nc\",1\n", .{ .max_record_len = 12 });
    try t.expect(capped[0].unbalanced_quote);
    try t.expectEqualStrings("\"aaaa", capped[0].bytes);
    const open = try spanRecords(arena, "a,b\n1,\"never closed\n2,3", .{});
    try t.expectEqual(@as(usize, 3), open.len);
    try t.expect(open[1].unbalanced_quote);
    try t.expectEqualStrings("2,3", open[2].bytes);
}

test "span: quote == 0 disables quoting entirely" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    var out: std.ArrayList(LineSlice) = .empty;
    var it = LineIterator.initSpan("\"a\nb\"\n", 0, 0, .{});
    while (it.next()) |r| try out.append(arena_state.allocator(), r);
    try t.expectEqual(@as(usize, 2), out.items.len);
}

test "span: the record scanner and splitFields agree on where fields end" {
    // Lazy-quote shapes inside a quoted field: `"a"b"` is one field `a"b`.
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const recs = try spanRecords(arena, "\"a\"b\nc\",d\ne,f\n", .{});
    try t.expectEqual(@as(usize, 2), recs.len);
    var fbuf: [4][]const u8 = undefined;
    const fields = try splitFields(recs[0].bytes, &fbuf, ',', '"', arena);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("a\"b\nc", fields[0]);
    try t.expectEqual(@as(usize, 2), countFields(recs[0].bytes, ',', '"'));
}
