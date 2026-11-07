// SPDX-License-Identifier: MIT
//! CSV in and out of a `Frame`, through `csvstream` (records, fields, quoting): this file
//! has no CSV parser of its own, only what pandas' and polars' `read_csv`/`to_csv` add on
//! top: header and name handling, null markers, type inference, limits.
//!
//! **Reading** takes the whole input (a byte slice, or a `std.Io.Reader` read up to
//! `max_bytes`) and walks it twice through the same record scanner: the first pass
//! decides each column's type from all of its cells (pandas does the same; polars looks
//! at 100 rows), the second builds the columns. No cell is kept between the passes.
//! Everything a hostile input can grow is capped by an option and answered with a
//! dedicated error, never a panic and never an unbounded allocation: `max_bytes`,
//! `max_columns`, `max_cell_bytes`, `max_record_bytes`, `max_rows`, `max_cells`.
//!
//! Use an arena: the frame's arrays may sit behind slice capacity (see `FrameBuilder`).

const std = @import("std");
const csvstream = @import("csvstream");
const value = @import("value.zig");
const frame_mod = @import("frame.zig");
const textio = @import("textio.zig");

const Frame = frame_mod.Frame;
const FrameBuilder = frame_mod.FrameBuilder;
const Column = value.Column;
const ColumnType = value.ColumnType;
const Value = value.Value;

/// The strings pandas reads as missing by default (`na_values`, `keep_default_na`).
pub const pandas_na_values = [_][]const u8{
    "",     "#N/A", "#N/A N/A", "#NA",  "-1.#IND", "-1.#QNAN", "-NaN", "-nan", "1.#IND", "1.#QNAN",
    "<NA>", "N/A",  "NA",       "NULL", "NaN",     "None",     "n/a",  "nan",  "null",
};

/// polars' default: only the empty field is missing (`NA`, `null`, `NaN` stay text, and
/// `NaN` in a float column is the number).
pub const polars_na_values = [_][]const u8{""};

/// Cap on the stream `readCsvReader` takes, 256 MiB.
pub const default_max_bytes: usize = 256 << 20;

pub const CsvReadError = error{
    OutOfMemory,
    ReadFailed,
    /// The input is longer than `max_bytes`.
    InputTooLarge,
    /// No record at all (after `skip_rows`).
    EmptyInput,
    /// A record of more than `max_columns` fields.
    TooManyColumns,
    /// More than `max_rows` data rows.
    TooManyRows,
    /// Rows times columns past `max_cells`.
    TooManyCells,
    /// A field longer than `max_cell_bytes`.
    CellTooLarge,
    /// A record longer than `max_record_bytes` (a quoted field that never closes).
    RecordTooLarge,
    /// A record ended inside an open quote (`strict_quotes`).
    UnterminatedQuote,
    /// A row with more fields than the header (`truncate_ragged` off).
    RaggedRow,
    /// `columns` or `types` names a column the file does not have.
    NoSuchColumn,
    /// `names` is not as long as the record, or holds a name twice.
    BadNames,
    /// A cell that does not parse as the type `types` demands.
    BadValue,
};

/// A column type given by name instead of inferred (pandas `dtype=`, polars `schema_overrides`).
/// `.decimal` reads `[+-]digits[.digits]` with up to 12 fractional digits.
pub const TypeOverride = struct { name: []const u8, type: ColumnType };

pub const CsvReadOptions = struct {
    delimiter: u8 = ',',
    /// `0` turns quoting off.
    quote: u8 = '"',
    /// The first record (after `skip_rows`) names the columns. Off: the columns are
    /// `column_0`, `column_1`... (polars 2.1; pandas gives the numbers 0, 1...).
    has_header: bool = true,
    /// Replaces the header's names (pandas `names=`), or names a header-less file.
    names: ?[]const []const u8 = null,
    /// Read only these columns (pandas `usecols`, polars `columns`); the result keeps the
    /// file's order, as pandas does.
    columns: ?[]const []const u8 = null,
    types: []const TypeOverride = &.{},
    /// Cells equal to one of these (before any trimming) are null. The default is pandas'.
    null_values: []const []const u8 = &pandas_na_values,
    /// Off: every column is text (pandas `dtype=str`, polars `infer_schema=False`).
    infer_types: bool = true,
    /// A column of ISO dates becomes `.date`, of ISO instants `.timestamp` (pandas
    /// `parse_dates`, polars `try_parse_dates`; both are off by default, as here).
    parse_dates: bool = false,
    /// Records dropped before the header.
    skip_rows: usize = 0,
    /// Stop after this many data rows.
    n_rows: ?usize = null,
    /// A record that starts with this byte is skipped; `0` = none. Only at the start of a
    /// record (pandas also cuts a comment off the end of a line).
    comment: u8 = 0,
    /// A row with more fields than the header is cut (polars `truncate_ragged_lines`)
    /// instead of `error.RaggedRow`. A shorter row is padded with nulls either way.
    truncate_ragged: bool = false,
    /// A record that ends inside an open quote is `error.UnterminatedQuote`. Off: the
    /// quote is read as a literal byte (csvstream's "lazy quotes").
    strict_quotes: bool = true,
    max_bytes: usize = default_max_bytes,
    max_columns: usize = 1 << 16,
    max_cell_bytes: usize = 1 << 20,
    max_record_bytes: usize = 1 << 24,
    max_rows: usize = 1 << 26,
    max_cells: usize = 1 << 26,
};

// ── the record scanner both passes share ────────────────────────────────────

const Scanner = struct {
    it: csvstream.LineIterator,
    opts: *const CsvReadOptions,
    scratch: std.heap.ArenaAllocator,
    /// File column names (mangled), set by `init`.
    width: usize = 0,
    buf: [][]const u8 = &.{},
    /// Fields of the record `next` returned: `buf[0..present]`.
    present: usize = 0,
    rows: usize = 0,
    /// The first record when the file has no header: the first data row.
    pending: ?csvstream.LineSlice = null,

    fn deinit(s: *Scanner) void {
        s.scratch.deinit();
    }

    fn open(a: std.mem.Allocator, bytes_in: []const u8, opts: *const CsvReadOptions) CsvReadError!Scanner {
        const bytes = csvstream.stripBom(bytes_in);
        var it = if (opts.quote == 0)
            csvstream.LineIterator.initOpts(bytes, 0, .{ .quote = 0, .comment = opts.comment })
        else
            csvstream.LineIterator.initSpan(bytes, opts.quote, 0, .{
                .delimiter = opts.delimiter,
                .max_record_len = opts.max_record_bytes,
                .comment = opts.comment,
            });
        for (0..opts.skip_rows) |_| _ = it.next() orelse return error.EmptyInput;
        return .{ .it = it, .opts = opts, .scratch = std.heap.ArenaAllocator.init(a) };
    }

    /// Next record's fields in `buf[0..n]`, valid until the next call. `max` is the
    /// buffer width the caller allows (the true width + 1, so a long row shows).
    fn record(s: *Scanner, rec: csvstream.LineSlice, buf: [][]const u8) CsvReadError!usize {
        if (rec.unbalanced_quote and s.opts.strict_quotes) return error.UnterminatedQuote;
        if (rec.bytes.len > s.opts.max_record_bytes) return error.RecordTooLarge;
        _ = s.scratch.reset(.retain_capacity);
        const sp: csvstream.SplitOptions = .{ .on_overflow = .truncate };
        const fields = csvstream.splitFieldsOpts(rec.bytes, buf, s.opts.delimiter, s.opts.quote, s.scratch.allocator(), sp) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RaggedRow,
        };
        for (fields) |f| if (f.len > s.opts.max_cell_bytes) return error.CellTooLarge;
        return fields.len;
    }

    /// Reads the header (or, without one, the first row) and fixes the width.
    fn header(s: *Scanner, a: std.mem.Allocator) CsvReadError![]const []const u8 {
        const rec = s.it.next() orelse return error.EmptyInput;
        const width = csvstream.countFieldsOpts(rec.bytes, s.opts.delimiter, s.opts.quote, .{});
        if (width > s.opts.max_columns) return error.TooManyColumns;
        s.width = width;
        s.buf = try a.alloc([]const u8, width + 1);
        // The split and the count agree; if they ever did not, the split is what rows get.
        s.width = try s.record(rec, s.buf);
        if (!s.opts.has_header) {
            s.pending = rec;
            return &.{};
        }
        const out = try a.alloc([]const u8, width);
        for (out, s.buf[0..width]) |*o, f| o.* = try a.dupe(u8, f);
        return out;
    }

    /// The next data row: `buf[0..present]`, `present <= width`. Null at the end.
    fn next(s: *Scanner) CsvReadError!?[]const []const u8 {
        const rec = if (s.pending) |p| blk: {
            s.pending = null;
            break :blk p;
        } else s.it.next() orelse return null;
        if (s.opts.n_rows) |lim| if (s.rows >= lim) return null;
        if (s.rows >= s.opts.max_rows) return error.TooManyRows;
        var n = try s.record(rec, s.buf);
        if (n > s.width) {
            if (!s.opts.truncate_ragged) return error.RaggedRow;
            n = s.width;
        }
        s.rows += 1;
        s.present = n;
        return s.buf[0..n];
    }
};

/// Names pandas gives: an empty name is `Unnamed: <position>`, a repeated one gets `.1`,
/// `.2`... skipping any name the header holds anywhere (`a,a,a.1` is `a`, `a.2`, `a.1`);
/// polars writes `a_duplicated_0`.
fn mangleNames(a: std.mem.Allocator, raw: []const []const u8) CsvReadError![]const []const u8 {
    const out = try a.alloc([]const u8, raw.len);
    var in_header: std.StringHashMapUnmanaged(void) = .empty;
    for (raw) |r| try in_header.put(a, r, {});
    var used: std.StringHashMapUnmanaged(void) = .empty;
    var next_n: std.StringHashMapUnmanaged(usize) = .empty;
    for (raw, out, 0..) |r, *o, i| {
        var name: []const u8 = if (r.len == 0) try std.fmt.allocPrint(a, "Unnamed: {d}", .{i}) else r;
        if (used.contains(name)) {
            const gop = try next_n.getOrPut(a, name);
            if (!gop.found_existing) gop.value_ptr.* = 1;
            while (true) {
                const cand = try std.fmt.allocPrint(a, "{s}.{d}", .{ name, gop.value_ptr.* });
                gop.value_ptr.* += 1;
                if (!used.contains(cand) and !in_header.contains(cand)) {
                    name = cand;
                    break;
                }
            }
        }
        try used.put(a, name, {});
        o.* = name;
    }
    return out;
}

// ── cell parsing ────────────────────────────────────────────────────────────

const k_int: u8 = 1;
const k_float: u8 = 2;
const k_bool: u8 = 4;
const k_date: u8 = 8;
const k_stamp: u8 = 16;

fn isNullCell(opts: *const CsvReadOptions, s: []const u8) bool {
    for (opts.null_values) |n| if (std.mem.eql(u8, n, s)) return true;
    return false;
}

fn parseBoolToken(s: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(s, "true")) return true;
    if (std.ascii.eqlIgnoreCase(s, "false")) return false;
    return null;
}

fn isIsoDate(s: []const u8) bool {
    return s.len == 10 and value.parseIsoDate(s) != null;
}

/// The set of types a non-null token can be read as.
fn kindsOf(s: []const u8, parse_dates: bool) u8 {
    const t = textio.trimBlank(s);
    var m: u8 = 0;
    if (textio.isIntGrammar(t)) {
        // An integer that does not fit i64 is text: a float would lose its digits.
        if (std.fmt.parseInt(i64, t, 10)) |_| m |= k_int | k_float else |_| {}
    } else if (textio.isFloatGrammar(t)) {
        m |= k_float;
    }
    if (parseBoolToken(s) != null) m |= k_bool;
    if (parse_dates) {
        if (isIsoDate(s)) m |= k_date else if (value.parseIsoTimestamp(s) != null) m |= k_stamp;
    }
    return m;
}

fn typeOfMask(seen: bool, mask: u8) ColumnType {
    if (!seen) return .text;
    if (mask & k_int != 0) return .int;
    if (mask & k_float != 0) return .float;
    if (mask & k_bool != 0) return .bool;
    if (mask & k_date != 0) return .date;
    if (mask & k_stamp != 0) return .timestamp;
    return .text;
}

/// The cell as `ty`, or null when it cannot be one (the caller decides if that is an error).
fn parseAs(ty: ColumnType, s: []const u8) ?Value {
    switch (ty) {
        .text => return .{ .text = s },
        .int => {
            const t = textio.trimBlank(s);
            if (!textio.isIntGrammar(t)) return null;
            return .{ .int = std.fmt.parseInt(i64, t, 10) catch return null };
        },
        .float => {
            const t = textio.trimBlank(s);
            if (!textio.isFloatGrammar(t)) return null;
            return .{ .float = textio.parseFloatToken(t) orelse return null };
        },
        .bool => return .{ .bool = parseBoolToken(s) orelse return null },
        .date => return if (isIsoDate(s)) .{ .text = s } else null,
        .timestamp => return .{ .int = value.parseIsoTimestamp(s) orelse return null },
        .decimal => return .{ .decimal = textio.parseDecimalToken(textio.trimBlank(s)) orelse return null },
    }
}

// ── readCsv ─────────────────────────────────────────────────────────────────

/// A `Frame` from CSV text. Types: an entry of `types` wins, else the column's cells
/// decide (all cells, as pandas; polars reads 100 rows) in this order:
///
/// 1. `int`: `[+-]digits` that fits i64, blanks around it allowed (pandas; polars takes
///    neither the `+` nor the blanks, and gives i128 for what does not fit i64: here it is text);
/// 2. `float`: decimal or exponent form, `inf`, `infinity`, `nan` (any case), blanks
///    allowed (pandas; polars: `inf` and `NaN` only, no blanks);
/// 3. `bool`: `true`/`false` in any case (both engines); `1`/`0` are ints;
/// 4. with `parse_dates`: `date` for `YYYY-MM-DD`, `timestamp` for the other ISO 8601
///    forms (a zone is applied, the result is UTC); a column that mixes the two is text
///    (both engines);
/// 5. otherwise `text`.
///
/// A column with no non-null cell is `text` (polars; pandas gives float64). Missing cells
/// are null in their own type: an int column with a hole stays int (polars; pandas turns
/// it into float64 with NaN). A short row is padded with nulls.
///
/// The result copies what it needs from `bytes`.
pub fn readCsv(a: std.mem.Allocator, bytes: []const u8, opts: CsvReadOptions) CsvReadError!Frame {
    if (bytes.len > opts.max_bytes) return error.InputTooLarge;
    var o = opts;
    var sc = try Scanner.open(a, bytes, &o);
    defer sc.deinit();
    const raw_names = try sc.header(a);
    const width = sc.width;
    const file_names: []const []const u8 = blk: {
        if (opts.names) |nm| {
            if (nm.len != width) return error.BadNames;
            break :blk nm;
        }
        if (!opts.has_header) {
            const gen = try a.alloc([]const u8, width);
            for (gen, 0..) |*g, i| g.* = try std.fmt.allocPrint(a, "column_{d}", .{i});
            break :blk gen;
        }
        break :blk raw_names;
    };
    // pandas mangles a header's blanks and repeats; given names must be good already.
    const names = if (opts.names != null) names_checked: {
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        for (file_names) |n| {
            if ((try seen.getOrPut(a, n)).found_existing) return error.BadNames;
        }
        break :names_checked file_names;
    } else try mangleNames(a, file_names);

    // Which file columns are read, in file order.
    const sel = try a.alloc(usize, width);
    var nsel: usize = 0;
    if (opts.columns) |want| {
        var index: std.StringHashMapUnmanaged(usize) = .empty;
        for (names, 0..) |n, i| try index.put(a, n, i);
        const take = try a.alloc(bool, width);
        @memset(take, false);
        for (want) |w| take[index.get(w) orelse return error.NoSuchColumn] = true;
        for (take, 0..) |t, i| if (t) {
            sel[nsel] = i;
            nsel += 1;
        };
    } else {
        for (sel, 0..) |*s, i| s.* = i;
        nsel = width;
    }
    const sel_idx = sel[0..nsel];

    // Types: overrides first; the rest are inferred.
    const types = try a.alloc(ColumnType, nsel);
    const fixed = try a.alloc(bool, nsel);
    for (types, fixed, sel_idx) |*t, *f, c| {
        t.* = .text;
        f.* = !opts.infer_types;
        for (opts.types) |ov| if (std.mem.eql(u8, ov.name, names[c])) {
            t.* = ov.type;
            f.* = true;
        };
    }
    for (opts.types) |ov| {
        var found = false;
        for (names) |n| if (std.mem.eql(u8, ov.name, n)) {
            found = true;
        };
        if (!found) return error.NoSuchColumn;
    }

    var row_count: usize = 0;
    var any_infer = false;
    for (fixed) |f| any_infer = any_infer or !f;
    {
        // Pass 1: the type of every column that is not fixed; the row count.
        const masks = try a.alloc(u8, nsel);
        const seen = try a.alloc(bool, nsel);
        @memset(masks, 0xff);
        @memset(seen, false);
        var pass1 = try Scanner.open(a, bytes, &o);
        defer pass1.deinit();
        _ = try pass1.header(a);
        while (try pass1.next()) |fields| {
            if (nsel != 0 and pass1.rows > opts.max_cells / nsel) return error.TooManyCells;
            if (!any_infer) continue;
            for (sel_idx, 0..) |c, j| {
                if (fixed[j] or c >= fields.len) continue;
                const s = fields[c];
                if (isNullCell(&o, s)) continue;
                seen[j] = true;
                masks[j] &= kindsOf(s, opts.parse_dates);
            }
        }
        row_count = pass1.rows;
        for (types, fixed, masks, seen) |*t, f, m, sn| {
            if (!f) t.* = typeOfMask(sn, m);
        }
    }

    // Pass 2: the cells.
    const cols = try a.alloc(Column, nsel);
    for (cols, sel_idx, types) |*c, i, t| c.* = .{ .name = try a.dupe(u8, names[i]), .type = t };
    var fb = try FrameBuilder.init(a, cols, row_count);
    var p2 = try Scanner.open(a, bytes, &o);
    defer p2.deinit();
    _ = try p2.header(a);
    const cells = try a.alloc(Value, nsel);
    while (try p2.next()) |fields| {
        for (cells, sel_idx, types) |*cell, c, t| {
            if (c >= fields.len) {
                cell.* = .null;
                continue;
            }
            const s = fields[c];
            if (isNullCell(&o, s)) {
                cell.* = .null;
                continue;
            }
            cell.* = parseAs(t, s) orelse return error.BadValue;
        }
        fb.appendRow(cells) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.RowLength => unreachable, // cells.len == columns.len
        };
    }
    return fb.toOwned();
}

/// `readCsv` over a stream: reads at most `opts.max_bytes` of it, `error.InputTooLarge`
/// past that. The stream is held in memory whole, as both passes need it.
pub fn readCsvReader(a: std.mem.Allocator, r: *std.Io.Reader, opts: CsvReadOptions) CsvReadError!Frame {
    const bytes = r.allocRemaining(a, .limited(opts.max_bytes)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.InputTooLarge,
        error.ReadFailed => return error.ReadFailed,
    };
    return readCsv(a, bytes, opts);
}

// ── writeCsv ────────────────────────────────────────────────────────────────

pub const CsvQuote = enum {
    /// Only a field holding the delimiter, the quote, CR or LF (pandas `QUOTE_MINIMAL`,
    /// polars `necessary`); an empty *text* is quoted, a null is not (polars).
    necessary,
    always,
    never,
    /// Text, dates, timestamps and the header are quoted, numbers and bools are not
    /// (pandas `QUOTE_NONNUMERIC`).
    non_numeric,
};

pub const CsvWriteOptions = struct {
    delimiter: u8 = ',',
    quote: u8 = '"',
    header: bool = true,
    /// What a null cell, and a NaN, is written as (pandas `na_rep`, polars `null_value`).
    null_text: []const u8 = "",
    quote_style: CsvQuote = .necessary,
    /// pandas ends a line with LF on Linux, and so does polars; RFC 4180 says CRLF.
    line_terminator: csvstream.LineTerminator = .lf,
    true_text: []const u8 = "True",
    false_text: []const u8 = "False",
    /// Fixed fractional digits for floats (pandas `float_format="%.Nf"`, polars
    /// `float_precision`; at most 22, more is 22); `null`: the shortest digits that read back exactly.
    float_precision: ?u8 = null,
};

pub const CsvWriteError = error{ WriteFailed, OutOfMemory };

/// `f` as CSV: the header (`header`), then one line per row. Floats are written as
/// Python's `repr` (pandas): `1.0`, `0.1`, `1e-05`, `inf`; NaN is the null text. A
/// timestamp is `YYYY-MM-DD HH:MM:SS` with a fraction of 3 or 6 digits in every cell of a
/// column when one cell has a fraction (pandas); a date is its ISO text; a decimal is
/// exact. A frame with no columns writes nothing. `a` holds one flag per column.
pub fn writeCsv(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: CsvWriteOptions) CsvWriteError!void {
    if (f.columns.len == 0) return;
    const base: csvstream.WriteOptions = .{
        .delimiter = opts.delimiter,
        .quote = opts.quote,
        .line_terminator = opts.line_terminator,
        .quote_style = switch (opts.quote_style) {
            .necessary, .non_numeric => .necessary,
            .always => .always,
            .never => .never,
        },
    };
    var always = base;
    always.quote_style = .always;
    const term: []const u8 = switch (opts.line_terminator) {
        .crlf => "\r\n",
        .lf => "\n",
    };
    const single = f.columns.len == 1;
    if (opts.header) {
        for (f.columns, 0..) |c, i| {
            if (i != 0) try w.writeByte(opts.delimiter);
            if (single and c.name.len == 0) try writeEmptyQuoted(w, opts) else try csvstream.writeField(w, c.name, if (opts.quote_style == .non_numeric) always else base);
        }
        try w.writeAll(term);
    }
    // The fraction digits of each timestamp column.
    const stamp_cols = try a.alloc(u8, f.columns.len);
    defer a.free(stamp_cols);
    for (f.columns, 0..) |c, ci| {
        stamp_cols[ci] = 0;
        if (c.type != .timestamp) continue;
        const col = f.columnAt(ci);
        for (0..f.len) |ri| {
            const v = col.get(ri);
            if (v == .int) stamp_cols[ci] = textio.fractionDigits(v.int, stamp_cols[ci]);
            if (stamp_cols[ci] == 6) break;
        }
    }
    for (0..f.len) |ri| {
        for (f.columns, 0..) |c, ci| {
            if (ci != 0) try w.writeByte(opts.delimiter);
            const v = f.columnAt(ci).get(ri);
            var nb: [textio.max_float_len + 8]u8 = undefined;
            var big: [400]u8 = undefined; // a fixed-point float: up to 309 digits and the fraction
            var sb: [textio.max_stamp_len]u8 = undefined;
            var db: [textio.max_decimal_len]u8 = undefined;
            var text_like = false;
            var is_text_value = false;
            const s: []const u8 = switch (v) {
                .null => opts.null_text,
                .bool => |b| if (b) opts.true_text else opts.false_text,
                .int => |i| if (c.type == .timestamp) blk: {
                    text_like = true;
                    break :blk textio.formatStampSpace(&sb, i, stamp_cols[ci]);
                } else std.fmt.bufPrint(&nb, "{d}", .{i}) catch unreachable,
                .float => |x| if (std.math.isNan(x))
                    opts.null_text
                else if (std.math.isInf(x))
                    (if (x > 0) "inf" else "-inf")
                else if (opts.float_precision) |p|
                    textio.formatFloatFixed(&big, x, @min(p, 22))
                else
                    textio.formatFloat(nb[0..textio.max_float_len], x),
                .decimal => |r| textio.formatDecimal(&db, r),
                .text => |t| blk: {
                    text_like = true;
                    is_text_value = true;
                    break :blk t;
                },
            };
            const missing = v == .null or (v == .float and std.math.isNan(v.float));
            if (missing) {
                if (single and s.len == 0) try writeEmptyQuoted(w, opts) else try csvstream.writeField(w, s, base);
            } else if (is_text_value and s.len == 0) {
                try writeEmptyQuoted(w, opts);
            } else {
                try csvstream.writeField(w, s, if (opts.quote_style == .non_numeric and text_like) always else base);
            }
        }
        try w.writeAll(term);
    }
}

/// zig-libs request: csvstream -- `writeField` cannot quote one field that `necessary` would
/// leave bare (an empty text that must stay distinct from a null, polars' `write_csv`), so the two
/// quote bytes are written here; a per-field `force_quote` in `WriteOptions` would replace this.
///
/// An empty field as `""`: a text that is empty, and a lone empty field (which would
/// read back as a blank line, so csvstream's `writeRecord` quotes it too).
fn writeEmptyQuoted(w: *std.Io.Writer, opts: CsvWriteOptions) std.Io.Writer.Error!void {
    if (opts.quote == 0 or opts.quote_style == .never) return;
    try w.writeByte(opts.quote);
    try w.writeByte(opts.quote);
}
