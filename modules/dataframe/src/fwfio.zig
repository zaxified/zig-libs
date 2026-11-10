// SPDX-License-Identifier: MIT
//! `readFwf`: pandas `read_fwf`, a fixed-width text table. Each line is cut into cells at
//! character offsets (`colspecs`, `widths`, or inferred from the first lines), the cells are
//! stripped of the delimiter characters, and the result is typed by `readCsv`: the cells are
//! re-emitted as one canonical CSV record per line (quoted only where a cell holds a `,`, a
//! quote, or a line break) and handed to `csvio.readCsv`, so type inference, `types`, `names`,
//! null markers, `thousands`, `parse_dates`, row limits... are exactly the CSV reader's and
//! there is no second inferrer.
//!
//! Offsets count characters (Python `str` slicing in pandas): one UTF-8 sequence is one
//! character, a byte that does not start a valid sequence is one character of its own.
//! Half-open `[start, end)`; a spec past the end of a line is an empty cell, a reversed one
//! (`end < start`) is empty too, overlapping specs are allowed (each is a plain slice).

const std = @import("std");
const csvio = @import("csvio.zig");
const value = @import("value.zig");

const Frame = @import("frame.zig").Frame;
pub const CsvReadError = csvio.CsvReadError;

/// One column: characters `start..end` of a line.
pub const Colspec = struct { start: usize, end: usize };

/// How the line is cut.
pub const FwfSpec = union(enum) {
    /// pandas `colspecs="infer"`: the runs of non-delimiter characters of the first
    /// `infer_nrows` lines (the header line included, skipped lines not).
    infer,
    /// pandas `colspecs=[(start, end), ...]`.
    colspecs: []const Colspec,
    /// pandas `widths=[...]`: adjacent columns of these widths from character 0.
    widths: []const usize,
};

pub const FwfReadOptions = struct {
    spec: FwfSpec = .infer,
    /// Lines `.infer` looks at (pandas `infer_nrows`); at least one is read.
    infer_nrows: usize = 100,
    /// The characters stripped from both ends of every cell, and that separate the columns
    /// `.infer` finds (pandas `delimiter`, default `" \t"`; `\r` and `\n` always count). ASCII only.
    delimiter: []const u8 = " \t",
    /// The reader's options for everything after the cutting: `names`, `has_header`, `types`,
    /// `null_values`, `infer_types`, `parse_dates`, `thousands`, `decimal`, `n_rows`,
    /// `skipfooter`, `skip_rows_after_header`, `row_index_name`, `columns`, `max_*` (`max_bytes`
    /// also bounds the cut cells' text, which overlapping specs can multiply). `skip_rows` drops
    /// LINES before the header and `comment` cuts a line at that byte, both applied here;
    /// `delimiter`, `quote`, `escape_char`, `double_quote`, `strict_quotes`, `skipinitialspace`
    /// and `max_quoted_lines` do not apply (the cells are not delimited text).
    csv: csvio.CsvReadOptions = .{},
};

/// Length in bytes of the character that starts at `s[i]` (`i < s.len`).
fn charLen(s: []const u8, i: usize) usize {
    const n = std.unicode.utf8ByteSequenceLength(s[i]) catch return 1;
    if (i + n > s.len) return 1;
    _ = std.unicode.utf8Decode(s[i..][0..n]) catch return 1;
    return n;
}

fn isDelim(opts: *const FwfReadOptions, c: u8) bool {
    return c == '\r' or c == '\n' or std.mem.indexOfScalar(u8, opts.delimiter, c) != null;
}

fn needsQuote(cell: []const u8) bool {
    for (cell) |c| if (c == ',' or c == '"' or c == '\r' or c == '\n') return true;
    return false;
}

fn appendCell(a: std.mem.Allocator, out: *std.ArrayList(u8), cell: []const u8) std.mem.Allocator.Error!void {
    if (!needsQuote(cell)) return out.appendSlice(a, cell);
    try out.append(a, '"');
    for (cell) |c| {
        if (c == '"') try out.append(a, '"');
        try out.append(a, c);
    }
    try out.append(a, '"');
}

/// The lines of `bytes` after the BOM, `\n`-split (a final line without `\n` counts, an empty
/// tail does not), the `\r` of a `\r\n` dropped.
const Lines = struct {
    rest: []const u8,

    fn init(bytes: []const u8) Lines {
        return .{ .rest = if (std.mem.startsWith(u8, bytes, "\xEF\xBB\xBF")) bytes[3..] else bytes };
    }

    fn next(l: *Lines) ?[]const u8 {
        if (l.rest.len == 0) return null;
        const nl = std.mem.indexOfScalar(u8, l.rest, '\n');
        var line = l.rest[0 .. nl orelse l.rest.len];
        l.rest = if (nl) |n| l.rest[n + 1 ..] else l.rest[l.rest.len..];
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        return line;
    }
};

fn cutComment(line: []const u8, comment: u8) []const u8 {
    if (comment == 0) return line;
    return line[0 .. std.mem.indexOfScalar(u8, line, comment) orelse line.len];
}

/// pandas `detect_colspecs`: positions where "some line has a non-delimiter character" starts
/// and stops. Allocates the result in `a`.
fn inferSpecs(a: std.mem.Allocator, bytes: []const u8, opts: *const FwfReadOptions) CsvReadError![]Colspec {
    const csv = &opts.csv;
    var lines = Lines.init(bytes);
    var skipped: usize = 0;
    while (skipped < csv.skip_rows) : (skipped += 1) _ = lines.next() orelse break;
    const want = @max(opts.infer_nrows, 1);
    // First pass: the longest line in characters.
    var probe = lines;
    var max_len: usize = 0;
    var n: usize = 0;
    while (n < want) : (n += 1) {
        const line = probe.next() orelse break;
        if (line.len > csv.max_record_bytes) return error.RecordTooLarge;
        var i: usize = 0;
        var chars: usize = 0;
        const cut = cutComment(line, csv.comment);
        while (i < cut.len) : (chars += 1) i += charLen(cut, i);
        max_len = @max(max_len, chars);
    }
    if (n == 0) return error.EmptyInput;
    const mask = try a.alloc(u8, max_len + 1);
    defer a.free(mask);
    @memset(mask, 0);
    n = 0;
    while (n < want) : (n += 1) {
        const line = lines.next() orelse break;
        const cut = cutComment(line, csv.comment);
        var i: usize = 0;
        var pos: usize = 0;
        while (i < cut.len) : (pos += 1) {
            const l = charLen(cut, i);
            if (!(l == 1 and isDelim(opts, cut[i]))) mask[pos] = 1;
            i += l;
        }
    }
    // Edges: where the mask differs from itself shifted by one (mask[-1] = 0); pairs of them.
    var specs: std.ArrayList(Colspec) = .empty;
    errdefer specs.deinit(a);
    var prev: u8 = 0;
    var open: usize = 0;
    for (mask, 0..) |m, p| {
        if (m != prev) {
            if (m == 1) {
                open = p;
            } else {
                if (specs.items.len >= csv.max_columns) return error.TooManyColumns;
                try specs.append(a, .{ .start = open, .end = p });
            }
        }
        prev = m;
    }
    if (specs.items.len == 0) return error.EmptyInput;
    return specs.toOwnedSlice(a);
}

/// Reads fixed-width text. Every failure is an error: a spec count past `max_columns`, input
/// past `max_bytes` (or cut cells past it), lines past `max_record_bytes`, rows past `max_rows`,
/// `rows x columns` past `max_cells`, no line at all, a non-ASCII `delimiter` (`BadOptions`), plus
/// everything `readCsv` can report for the cells. A line shorter than the specs gives empty
/// (null) cells, a line longer than the last spec is cut there, a line whose cells are all
/// empty is dropped (pandas `skip_blank_lines`).
pub fn readFwf(a: std.mem.Allocator, bytes: []const u8, opts: FwfReadOptions) CsvReadError!Frame {
    const csv = &opts.csv;
    if (bytes.len > csv.max_bytes) return error.InputTooLarge;
    for (opts.delimiter) |c| if (c >= 0x80) return error.BadOptions;

    var specs_buf: []Colspec = &.{};
    defer if (opts.spec != .colspecs) a.free(specs_buf);
    const specs: []const Colspec = switch (opts.spec) {
        .colspecs => |s| s,
        .widths => |ws| blk: {
            if (ws.len > csv.max_columns) return error.TooManyColumns;
            specs_buf = try a.alloc(Colspec, ws.len);
            var at: usize = 0;
            for (ws, specs_buf) |w, *sp| {
                sp.* = .{ .start = at, .end = at +| w };
                at = at +| w;
            }
            break :blk specs_buf;
        },
        .infer => blk: {
            specs_buf = try inferSpecs(a, bytes, &opts);
            break :blk specs_buf;
        },
    };
    if (specs.len > csv.max_columns) return error.TooManyColumns;
    if (specs.len == 0) return error.EmptyInput;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    var starts: std.ArrayList(usize) = .empty;
    defer starts.deinit(a);

    var max_end: usize = 0;
    for (specs) |sp| max_end = @max(max_end, @max(sp.start, sp.end));

    var lines = Lines.init(bytes);
    var skipped: usize = 0;
    while (skipped < csv.skip_rows) : (skipped += 1) _ = lines.next() orelse break;
    var rows: usize = 0;
    while (lines.next()) |raw| {
        if (raw.len > csv.max_record_bytes) return error.RecordTooLarge;
        const line = cutComment(raw, csv.comment);
        // Byte offset of every character boundary up to `max_end`; `starts[n]` is the line's end.
        starts.clearRetainingCapacity();
        var i: usize = 0;
        while (i < line.len and starts.items.len <= max_end) {
            try starts.append(a, i);
            i += charLen(line, i);
        }
        if (i >= line.len) try starts.append(a, line.len) else try starts.append(a, i);
        const nchars = starts.items.len - 1; // characters before `max_end` (or all of them)
        const row_start = out.items.len;
        var any = false;
        for (specs, 0..) |sp, k| {
            if (k > 0) try out.append(a, ',');
            const s = @min(sp.start, nchars);
            const e = @min(sp.end, nchars);
            var cell: []const u8 = if (e > s) line[starts.items[s]..starts.items[e]] else "";
            while (cell.len > 0 and isDelim(&opts, cell[0])) cell = cell[1..];
            while (cell.len > 0 and isDelim(&opts, cell[cell.len - 1])) cell = cell[0 .. cell.len - 1];
            if (cell.len > csv.max_cell_bytes) return error.CellTooLarge;
            if (cell.len > 0) any = true;
            try appendCell(a, &out, cell);
            if (out.items.len > csv.max_bytes) return error.InputTooLarge;
        }
        if (!any) {
            out.shrinkRetainingCapacity(row_start);
            continue;
        }
        try out.append(a, '\n');
        rows += 1;
        // `readCsv` counts the header as a record; its own limits give the final word.
        if (rows > csv.max_rows +| 1) return error.TooManyRows;
    }
    if (rows == 0) return error.EmptyInput;

    var o = csv.*;
    o.delimiter = ',';
    o.quote = '"';
    o.comment = 0;
    o.skip_rows = 0;
    o.escape_char = 0;
    o.double_quote = true;
    o.strict_quotes = true;
    o.skipinitialspace = false;
    o.max_quoted_lines = null;
    o.max_bytes = std.math.maxInt(usize);
    o.max_record_bytes = std.math.maxInt(usize);
    return csvio.readCsv(a, out.items, o);
}
