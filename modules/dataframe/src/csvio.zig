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
const dtype = @import("dtype.zig");
const csvstream = @import("csvstream");
const value = @import("value.zig");
const frame_mod = @import("frame.zig");
const textio = @import("textio.zig");
const jsonio = @import("jsonio.zig");
const dtfn = @import("dtfn.zig");
const tz = @import("tz");
const catfn = @import("catfn.zig");

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
    /// A line longer than `max_record_bytes`. A quoted field still open when the cap is
    /// reached is `UnterminatedQuote` (csvstream cuts the record there).
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
    /// Options that contradict each other or cannot work: `thousands` equal to `decimal`,
    /// `decimal` = 0 (a `thousands` byte equal to the delimiter is fine for quoted cells), a
    /// `date_format` that is not a `%` layout, a `row_index_name` some column already has.
    BadOptions,
};

/// Extra null markers of one column (pandas `na_values={"col": [...]}`, polars
/// `null_values={"col": ...}`), added to the global ones.
pub const ColumnNulls = struct { name: []const u8, values: []const []const u8 };

/// What `read_csv` does with a record that has more fields than the header.
pub const BadLines = enum {
    /// `error.RaggedRow` (pandas `on_bad_lines="error"`; `truncate_ragged` cuts instead).
    @"error",
    /// The record is dropped (pandas `"skip"`, polars `ignore_errors` for this case);
    /// `bad_lines_skipped` receives the count (pandas `"warn"` is this plus that count).
    skip,
};

/// A column type given by name instead of inferred (pandas `dtype=`, polars `schema_overrides`).
/// `.decimal` reads `[+-]digits[.digits]` with up to 12 fractional digits.
pub const TypeOverride = struct {
    name: []const u8,
    type: ColumnType,
    /// With `type = .timestamp`: the IANA zone the column carries, polars
    /// `schema_overrides={"ts": pl.Datetime("us", "Europe/Prague")}`, pandas
    /// `read_csv(parse_dates=...)` then `tz_localize`/`tz_convert`. A cell with an offset or `Z`
    /// is that instant; **a cell with none is read as UTC, as polars does** (pandas would read
    /// the wall clock in the zone: apply `Expr.replace_time_zone` after reading without a zone
    /// for that). Another `type` with a zone, or an unknown zone, is `error.BadOptions`
    /// (`error.BadValue` in `readJson`).
    time_zone: ?[]const u8 = null,
    /// With `type = .array` (`readJson` only; `readCsv` has no nesting): the length every row
    /// must have, else `error.BadValue`. polars cannot read an array from JSON at all.
    array_width: u32 = 0,
};

/// `f` with the zone of every `types` entry that names one set on its (timestamp) column; the
/// cells already are UTC instants, so this only tags. A zone on a type other than `.timestamp`,
/// or one `tz` does not know, is `error.BadOptions`.
pub fn applyZones(a: std.mem.Allocator, f: Frame, types: []const TypeOverride) error{ OutOfMemory, BadOptions }!Frame {
    var cols: ?[]Column = null;
    for (types) |t| {
        const zn = t.time_zone orelse continue;
        if (t.type != .timestamp or tz.find(zn) == null) return error.BadOptions;
        const ci = f.columnIndex(t.name) orelse continue;
        if (f.columns[ci].type != .timestamp) continue;
        if (cols == null) cols = try a.dupe(Column, f.columns);
        cols.?[ci].time_zone = try a.dupe(u8, zn);
    }
    return if (cols) |c| .{ .columns = c, .data = f.data, .len = f.len } else f;
}

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
    /// Columns held as a fixed category list (polars `schema_overrides` with `pl.Enum`, pandas
    /// `dtype=CategoricalDtype(categories, ordered)`): the dictionary is the list, in its order,
    /// and a value outside it is `error.BadValue`. Applied after `types`.
    enums: []const catfn.EnumDecl = &.{},
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
    /// Newlines one quoted field may hold. `null`: under `strict_quotes` no line cap
    /// (only `max_record_bytes`), so whatever `writeCsv` writes reads back, and the first
    /// quote with no closer ends the read with `error.UnterminatedQuote`; without
    /// `strict_quotes` csvstream's 64, because there every stray quote looks ahead up to
    /// this many lines and a larger cap multiplies the scan.
    max_quoted_lines: ?usize = null,
    max_bytes: usize = default_max_bytes,
    max_columns: usize = 1 << 16,
    max_cell_bytes: usize = 1 << 20,
    max_record_bytes: usize = 1 << 24,
    max_rows: usize = 1 << 26,
    max_cells: usize = 1 << 26,

    // ── added 2026-11-09 (dataframe S2, input options) ──
    /// A byte that groups digits in numbers, dropped before an int/float/decimal cell is
    /// read (pandas `thousands`; polars has none). `0` = none. `1,234` with `thousands = ','`
    /// (the cell quoted, or another delimiter) is the int 1234; a column that is not all
    /// numbers keeps its text untouched.
    thousands: u8 = 0,
    /// The byte that is the decimal point of float and decimal cells (pandas `decimal`,
    /// polars `decimal_comma` = `','`). A cell with a `.` is then not a number.
    decimal: u8 = '.',
    /// Extra spellings of `true` (pandas `true_values`); a column whose cells are all
    /// among `true_values`, `false_values` and the usual `true`/`false` is bool. An
    /// entry here wins over a number reading (`"1"` in `true_values` makes `1`/`0` bool
    /// when `0` is in `false_values`). Exact, case-sensitive match.
    true_values: []const []const u8 = &.{},
    /// As `true_values`, for `false`.
    false_values: []const []const u8 = &.{},
    /// Markers added to `null_values` for every column (pandas `na_values` with
    /// `keep_default_na=True` is `null_values = pandas_na_values` plus these;
    /// `keep_default_na=False` is `null_values = &.{}`, which is why there is no flag).
    extra_null_values: []const []const u8 = &.{},
    /// Markers for single columns, added to the global ones (pandas dict `na_values`, polars
    /// per-column `null_values`).
    column_null_values: []const ColumnNulls = &.{},
    /// Off: nothing is null (pandas `na_filter=False`): the markers are ignored and an
    /// empty cell stays an empty text (so a number column with a hole is text).
    na_filter: bool = true,
    /// Off: the empty cell is not a null marker even when `null_values` holds `""`
    /// (polars `missing_utf8_is_empty_string`); it is then an empty text, or makes a
    /// numeric column text.
    empty_string_is_null: bool = true,
    /// Blanks after a delimiter are skipped, also before an opening quote (pandas
    /// `skipinitialspace`, csvstream's `Trim.leading`).
    skipinitialspace: bool = false,
    /// Rows dropped at the end of the data (pandas `skipfooter`; counted in records,
    /// comments and blank lines not among them).
    skipfooter: usize = 0,
    /// Data rows dropped right after the header (polars `skip_rows_after_header`).
    skip_rows_after_header: usize = 0,
    /// A leading int column of this name with `row_index_offset`, `row_index_offset + 1`...
    /// (polars `row_index_name`/`row_index_offset`; pandas' `index_col` goes the other
    /// way, a frame here has no index). A column of that name already in the file is `error.BadOptions`.
    row_index_name: ?[]const u8 = null,
    row_index_offset: i64 = 0,
    /// A record with too many fields: error, or skipped (pandas `on_bad_lines`).
    on_bad_lines: BadLines = .@"error",
    /// Receives the number of records `on_bad_lines = .skip` dropped.
    bad_lines_skipped: ?*usize = null,
    /// A `%` layout (pandas `read_csv(date_format=)`, `to_datetime(format=)`) for `parse_dates`
    /// instead of ISO 8601. A layout with a time part (`%H %I %M %S %f %p %z %T %R`) reads
    /// `timestamp`, else `date`; a cell that does not match is not a date (the column is
    /// text). pandas' `dayfirst=True` is `date_format = "%d/%m/%Y"` here: the layout is the
    /// whole answer, there is no guessing. Also applies to a `.date`/`.timestamp` entry of `types`.
    date_format: ?[]const u8 = null,
    /// Escape byte inside quoted fields (pandas/Python `escapechar`, csvstream `escape`), `0` = none.
    escape_char: u8 = 0,
    /// A doubled quote inside a quoted field is one quote (pandas `doublequote`; off needs `escape_char`).
    double_quote: bool = true,
};

// ── the record scanner both passes share ────────────────────────────────────

/// The record scanner configuration `readCsv` cuts records with (null: quoting is off,
/// so every newline ends a record). Shared with `csvchunk.zig`, whose stream reader must
/// cut records exactly where the whole-input reader does.
pub fn recordSpanConfig(opts: *const CsvReadOptions) ?csvstream.SpanConfig {
    if (opts.quote == 0) return null;
    return .{
        .delimiter = opts.delimiter,
        .max_record_len = opts.max_record_bytes,
        .max_quoted_lines = opts.max_quoted_lines orelse
            if (opts.strict_quotes) std.math.maxInt(usize) else csvstream.default_max_quoted_lines,
        .comment = opts.comment,
        .escape = opts.escape_char,
        .double_quote = opts.double_quote,
        .trim = if (opts.skipinitialspace) .leading else .none,
    };
}

/// The record iterator over `bytes` (BOM already stripped) that both passes of `readCsv` use.
pub fn recordIterator(bytes: []const u8, opts: *const CsvReadOptions) csvstream.LineIterator {
    if (recordSpanConfig(opts)) |cfg| return csvstream.LineIterator.initSpan(bytes, opts.quote, 0, cfg);
    return csvstream.LineIterator.initOpts(bytes, 0, .{ .quote = 0, .comment = opts.comment });
}

/// The field split options `readCsv` reads records with.
pub fn recordSplitOptions(opts: *const CsvReadOptions) csvstream.SplitOptions {
    return Scanner.splitOpts(opts);
}

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
    /// `skip_rows_after_header` still to drop.
    skip_left: usize = 0,
    /// Data records taken so far (those `skipfooter` and `on_bad_lines` look at).
    recs: usize = 0,
    /// Data records to take at most (`skipfooter`).
    rec_limit: usize = std.math.maxInt(usize),
    /// Records `on_bad_lines = .skip` dropped.
    bad: usize = 0,

    fn splitOpts(o: *const CsvReadOptions) csvstream.SplitOptions {
        return .{
            .escape = if (o.quote == 0) 0 else o.escape_char,
            .double_quote = o.double_quote,
            .trim = if (o.skipinitialspace) .leading else .none,
        };
    }

    fn deinit(s: *Scanner) void {
        s.scratch.deinit();
    }

    fn open(a: std.mem.Allocator, bytes_in: []const u8, opts: *const CsvReadOptions) CsvReadError!Scanner {
        const bytes = csvstream.stripBom(bytes_in);
        var it = recordIterator(bytes, opts);
        for (0..opts.skip_rows) |_| _ = it.next() orelse return error.EmptyInput;
        var s: Scanner = .{ .it = it, .opts = opts, .scratch = std.heap.ArenaAllocator.init(a), .skip_left = opts.skip_rows_after_header };
        if (opts.skipfooter > 0) {
            // The data records there are (a copy of the iterator walks them without
            // splitting), less the ones dropped at both ends.
            var c = it;
            if (opts.has_header) _ = c.next();
            var n: usize = 0;
            while (c.next()) |_| n += 1;
            s.rec_limit = n -| opts.skip_rows_after_header -| opts.skipfooter;
        }
        return s;
    }

    /// Next record's fields in `buf[0..n]`, valid until the next call. `max` is the
    /// buffer width the caller allows (the true width + 1, so a long row shows).
    fn record(s: *Scanner, rec: csvstream.LineSlice, buf: [][]const u8) CsvReadError!usize {
        if (rec.unbalanced_quote and s.opts.strict_quotes) return error.UnterminatedQuote;
        if (rec.bytes.len > s.opts.max_record_bytes) return error.RecordTooLarge;
        _ = s.scratch.reset(.retain_capacity);
        var sp = splitOpts(s.opts);
        sp.on_overflow = .truncate;
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
        const width = csvstream.countFieldsOpts(rec.bytes, s.opts.delimiter, s.opts.quote, splitOpts(s.opts));
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
        while (true) {
            const rec = if (s.pending) |p| blk: {
                s.pending = null;
                break :blk p;
            } else s.it.next() orelse return null;
            if (s.skip_left > 0) {
                s.skip_left -= 1;
                continue;
            }
            if (s.recs >= s.rec_limit) return null;
            if (s.opts.n_rows) |lim| if (s.rows >= lim) return null;
            if (s.rows >= s.opts.max_rows) return error.TooManyRows;
            s.recs += 1;
            var n = try s.record(rec, s.buf);
            if (n > s.width) {
                if (s.opts.on_bad_lines == .skip and !s.opts.truncate_ragged) {
                    s.bad += 1;
                    continue;
                }
                if (!s.opts.truncate_ragged) return error.RaggedRow;
                n = s.width;
            }
            s.rows += 1;
            s.present = n;
            return s.buf[0..n];
        }
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
/// A time of day under `parse_dates`: polars' `try_parse_dates` infers `Time` from whatever
/// `parseTimeOfDay` reads (`H:M`, `1:02:03`, a leading blank, oracle2k `time-csv-probe-try-*`);
/// a trailing blank keeps the column text there, so the raw cell is tried, not the trimmed one.
const k_time: u8 = 32;

fn isNullCell(opts: *const CsvReadOptions, s: []const u8) bool {
    for (opts.null_values) |n| if (n.len == s.len and std.mem.eql(u8, n, s)) return true;
    return false;
}

/// `isNullCell` with a cheap reject up front: which lengths and first bytes any null
/// marker has. The default list has 19 markers, and a number matches none of them, so
/// the linear scan cost a compare per marker per cell (14 % of `read_csv`).
const NullSet = struct {
    /// Bit `l` set: some marker is `l` bytes long (`l < 64`).
    lens: u64 = 0,
    /// Some marker is 64 bytes or longer.
    has_long: bool = false,
    /// Some marker starts with this byte.
    first: [256]bool = @splat(false),

    fn init(opts: *const CsvReadOptions) NullSet {
        var ns: NullSet = .{};
        for (opts.null_values) |n| {
            if (n.len < 64) ns.lens |= @as(u64, 1) << @intCast(n.len) else ns.has_long = true;
            if (n.len > 0) ns.first[n[0]] = true;
        }
        return ns;
    }

    inline fn isNull(ns: *const NullSet, opts: *const CsvReadOptions, s: []const u8) bool {
        if (s.len < 64) {
            if ((ns.lens >> @intCast(s.len)) & 1 == 0) return false;
        } else if (!ns.has_long) return false;
        if (s.len > 0 and !ns.first[s[0]]) return false;
        return isNullCell(opts, s);
    }
};

/// `[+-]?[0-9]+` that fits an i64, in one pass over the bytes: what `isIntGrammar` and
/// `std.fmt.parseInt(i64, t, 10)` give together (null for either failing).
/// An integer's text as an `i128`: what `fastInt` reads, and past `maxInt(i64)` a u64
/// (a UInt64 column's upper half). Null for anything else.
fn parseWideInt(t: []const u8) ?i128 {
    if (fastInt(t)) |x| return x;
    if (!textio.isIntGrammar(t)) return null;
    return std.fmt.parseInt(u64, t, 10) catch null;
}

fn fastInt(t: []const u8) ?i64 {
    var i: usize = 0;
    var neg = false;
    if (t.len > 0 and (t[0] == '+' or t[0] == '-')) {
        neg = t[0] == '-';
        i = 1;
    }
    if (i == t.len) return null;
    var acc: u64 = 0;
    for (t[i..]) |c| {
        const d = c -% '0';
        if (d > 9) return null;
        const m = @mulWithOverflow(acc, 10);
        if (m[1] != 0) return null;
        const r = @addWithOverflow(m[0], d);
        if (r[1] != 0) return null;
        acc = r[0];
    }
    if (neg) {
        if (acc > @as(u64, 1) << 63) return null;
        return @bitCast(0 -% acc);
    }
    if (acc > std.math.maxInt(i64)) return null;
    return @intCast(acc);
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
    // An int token is neither a bool nor (with dates on, a 10-digit one cannot be an
    // ISO date either) anything else; only without `parse_dates` is that skipped.
    if (!parse_dates and fastInt(t) != null) return k_int | k_float;
    var m: u8 = 0;
    if (textio.isIntGrammar(t)) {
        // An integer that does not fit i64 is text: a float would lose its digits.
        if (std.fmt.parseInt(i64, t, 10)) |_| m |= k_int | k_float else |_| {}
    } else if (textio.isFloatGrammar(t) and textio.parseFloatToken(t) != null) {
        // The same parse pass 2 makes, so an inferred float column never ends in BadValue.
        m |= k_float;
    }
    if (parseBoolToken(s) != null) m |= k_bool;
    if (parse_dates) {
        if (isIsoDate(s)) m |= k_date else if (value.parseIsoTimestamp(s) != null) m |= k_stamp else if (value.parseTimeOfDay(s) != null) m |= k_time;
    }
    return m;
}

const pow10 = blk: {
    var t: [16]f64 = undefined;
    var x: f64 = 1;
    for (&t) |*e| {
        e.* = x;
        x *= 10;
    }
    break :blk t;
};

/// `[+-]?(digits[.digits*]|.digits)` of up to 15 digits and no exponent, in one pass:
/// the mantissa is below 2^53 and the power of ten is exact, so the one division rounds
/// once, as `std.fmt.parseFloat` does (Clinger's fast path). Null for anything else,
/// which is for the general parser to say.
fn fastFloat(t: []const u8) ?f64 {
    var i: usize = 0;
    var neg = false;
    if (t.len > 0 and (t[0] == '+' or t[0] == '-')) {
        neg = t[0] == '-';
        i = 1;
    }
    var mant: u64 = 0;
    var digits: usize = 0;
    var frac: usize = 0;
    var seen_dot = false;
    while (i < t.len) : (i += 1) {
        const c = t[i];
        if (c == '.') {
            if (seen_dot) return null;
            seen_dot = true;
            continue;
        }
        const d = c -% '0';
        if (d > 9) return null;
        mant = mant *% 10 +% d;
        digits += 1;
        if (seen_dot) frac += 1;
    }
    if (digits == 0 or digits > 15) return null;
    const v = @as(f64, @floatFromInt(mant)) / pow10[frac];
    return if (neg) -v else v;
}

/// The float a token reads as when `kindsOf` calls it a float and not an int: the token
/// is not an int that fits (the caller has tried), so an int-looking one is too long.
fn floatOnly(t: []const u8) ?f64 {
    // Tokens with a point or only digits: a plain int never gets here (the caller has
    // tried), but 16+ digits do, and `fastFloat` hands those on.
    if (fastFloat(t)) |v| {
        // Digits only is an int token (in range, since a fitting int was taken before;
        // here it is at most 15 digits, so it fits): the caller has already ruled it out.
        if (std.mem.findScalar(u8, t, '.') != null) return v;
    }
    if (textio.isIntGrammar(t) or !textio.isFloatGrammar(t)) return null;
    return textio.parseFloatToken(t);
}

fn typeOfMask(seen: bool, mask: u8) ColumnType {
    if (!seen) return .text;
    if (mask & k_int != 0) return .int;
    if (mask & k_float != 0) return .float;
    if (mask & k_bool != 0) return .bool;
    if (mask & k_date != 0) return .date;
    if (mask & k_stamp != 0) return .timestamp;
    if (mask & k_time != 0) return .time;
    return .text;
}

/// The cell as `ty`, or null when it cannot be one (the caller decides if that is an error).
/// Shared with `jsonread`, so a JSON cell reads as a CSV cell of the same text does.
pub fn parseAs(ty: ColumnType, s: []const u8) ?Value {
    switch (ty) {
        .text, .categorical => return .{ .text = s },
        .int => return .{ .int = fastInt(textio.trimBlank(s)) orelse return null },
        // A width: the integer's text, then its range (out of it: null, `error.BadValue`
        // for the readers, as polars' `could not parse`).
        .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 => return dtype.fitInt(parseWideInt(textio.trimBlank(s)) orelse return null, ty),
        .float, .float32 => {
            const t = textio.trimBlank(s);
            if (!textio.isFloatGrammar(t)) return null;
            const x = textio.parseFloatToken(t) orelse return null;
            return .{ .float = if (ty == .float32) dtype.roundF32(x) else x };
        },
        .bool => return .{ .bool = parseBoolToken(s) orelse return null },
        .date => return if (isIsoDate(s)) .{ .text = s } else null,
        .timestamp => return .{ .int = value.parseIsoTimestamp(s) orelse return null },
        .duration => return .{ .int = value.parseDurationCell(textio.trimBlank(s)) orelse return null },
        .time => return .{ .int = value.parseTimeOfDay(textio.trimBlank(s)) orelse return null },
        .decimal => return .{ .decimal = textio.parseDecimalToken(textio.trimBlank(s)) orelse return null },
        // CSV has no nesting, and a JSON text is not parsed here (polars refuses a nested
        // type in `read_csv` too): only a null cell reads as one.
        .list, .array, .@"struct" => return null,
    }
}

// ── the options that rewrite cells (cell-by-cell reading) ──────────────────

/// Folds `na_filter`, `extra_null_values` and `empty_string_is_null` into `o.null_values`,
/// and refuses contradictory options. Allocates only when the list changes.
fn prepareOptions(a: std.mem.Allocator, o: *CsvReadOptions) CsvReadError!void {
    if (o.decimal == 0 or (o.thousands != 0 and o.thousands == o.decimal)) return error.BadOptions;
    if (!o.na_filter) {
        o.null_values = &.{};
        o.extra_null_values = &.{};
        return;
    }
    if (o.extra_null_values.len == 0 and o.empty_string_is_null) return;
    var list: std.ArrayList([]const u8) = .empty;
    for ([_][]const []const u8{ o.null_values, o.extra_null_values }) |src| {
        for (src) |m| {
            if (m.len == 0 and !o.empty_string_is_null) continue;
            try list.append(a, m);
        }
    }
    o.null_values = list.items;
}

fn needsCx(o: *const CsvReadOptions) bool {
    return o.thousands != 0 or o.decimal != '.' or o.true_values.len != 0 or o.false_values.len != 0 or
        (o.na_filter and o.column_null_values.len != 0) or o.date_format != null;
}

/// Whether a `%` layout carries a time of day (so it reads `timestamp`, not `date`).
fn layoutHasTime(fmt: []const u8) bool {
    var i: usize = 0;
    while (i + 1 < fmt.len) : (i += 1) {
        if (fmt[i] != '%') continue;
        i += 1;
        if (std.mem.findScalar(u8, "HIMSfpzTRc:", fmt[i]) != null) return true;
    }
    return false;
}

/// The reading rules that need the cell rewritten or looked up in a list: digit
/// grouping, the decimal byte, bool spellings, per-column null markers, `%` date
/// layouts. Kept apart from the speculative one-pass reader so that stays as it was:
/// a read with any of these takes the cell-by-cell pass-1/pass-2 way.
const Cx = struct {
    o: *const CsvReadOptions,
    layout: ?[]const u8,
    stamp: bool,
    col_nulls: []const []const []const u8,
    buf: std.ArrayList(u8) = .empty,
    a: std.mem.Allocator,
    scratch: std.heap.ArenaAllocator,

    fn init(a: std.mem.Allocator, o: *const CsvReadOptions, names: []const []const u8, sel: []const usize) CsvReadError!Cx {
        var layout: ?[]const u8 = null;
        if (o.date_format) |f| layout = dtfn.translateFormat(a, f) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadFormat => return error.BadOptions,
        };
        const cn = try a.alloc([]const []const u8, sel.len);
        @memset(cn, &.{});
        if (o.na_filter) {
            for (o.column_null_values) |e| {
                var found = false;
                for (names) |n| found = found or std.mem.eql(u8, n, e.name);
                if (!found) return error.NoSuchColumn;
                for (sel, 0..) |c, j| if (std.mem.eql(u8, names[c], e.name)) {
                    cn[j] = e.values;
                };
            }
        }
        return .{
            .o = o,
            .layout = layout,
            .stamp = if (o.date_format) |f| layoutHasTime(f) else false,
            .col_nulls = cn,
            .a = a,
            .scratch = std.heap.ArenaAllocator.init(a),
        };
    }

    fn isColNull(x: *const Cx, j: usize, s: []const u8) bool {
        for (x.col_nulls[j]) |m| if (std.mem.eql(u8, m, s)) return true;
        return false;
    }

    fn boolOf(x: *const Cx, s: []const u8) ?bool {
        for (x.o.true_values) |m| if (std.mem.eql(u8, m, s)) return true;
        for (x.o.false_values) |m| if (std.mem.eql(u8, m, s)) return false;
        return null;
    }

    /// `s` with the grouping byte dropped and the decimal byte made a `.`, or null when
    /// it holds a `.` that is not the decimal point (so it cannot be a number).
    fn numView(x: *Cx, s: []const u8) CsvReadError!?[]const u8 {
        const o = x.o;
        if (o.thousands == 0 and o.decimal == '.') return s;
        x.buf.clearRetainingCapacity();
        for (s) |c| {
            if (o.thousands != 0 and c == o.thousands) continue;
            try x.buf.append(x.a, c);
        }
        const v = x.buf.items;
        if (o.decimal != '.') {
            if (std.mem.findScalar(u8, v, '.') != null) return null;
            for (v) |*c| if (c.* == o.decimal) {
                c.* = '.';
            };
        }
        return v;
    }

    /// Frees what the row's `date` calls allocated. A `Value` from `date`/`parse` is valid
    /// until the next `rowReset`, so the caller resets once per row, before the first cell
    /// (two layout-parsed columns of one row must not share the arena's memory).
    fn rowReset(x: *Cx) void {
        _ = x.scratch.reset(.retain_capacity);
    }

    /// The `Value` is a `.text` allocated in `x.scratch`: valid until `rowReset`.
    fn date(x: *Cx, to: dtfn.ParseTo, s: []const u8) CsvReadError!?Value {
        const v = dtfn.strptime(x.scratch.allocator(), .{ .text = s }, x.layout.?, to) catch return error.OutOfMemory;
        return if (v == .null) null else v;
    }

    /// `kindsOf` under these rules.
    fn kinds(x: *Cx, s: []const u8) CsvReadError!u8 {
        if (x.boolOf(s) != null) return k_bool;
        const o = x.o;
        const iso_dates = o.parse_dates and x.layout == null;
        var m = kindsOf(s, iso_dates);
        if (o.thousands != 0 or o.decimal != '.') {
            m &= ~(k_int | k_float);
            if (try x.numView(s)) |n| m |= kindsOf(n, false) & (k_int | k_float);
        }
        if (o.parse_dates and x.layout != null) {
            if (try x.date(if (x.stamp) .timestamp else .date, s) != null) m |= if (x.stamp) k_stamp else k_date;
        }
        return m;
    }

    /// `parseAs` under these rules.
    fn parse(x: *Cx, ty: ColumnType, s: []const u8) CsvReadError!?Value {
        switch (ty) {
            .int, .float, .decimal, .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => {
                if (x.o.thousands == 0 and x.o.decimal == '.') return parseAs(ty, s);
                const n = (try x.numView(s)) orelse return null;
                return parseAs(ty, n);
            },
            .bool => if (x.boolOf(s)) |b| return .{ .bool = b },
            .date, .timestamp => if (x.layout != null) return x.date(if (ty == .date) .date else .timestamp, s),
            else => {},
        }
        return parseAs(ty, s);
    }
};

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
    var o = opts;
    if (opts.enums.len != 0) o.types = try enumTypes(a, opts.enums, opts.types);
    const f0 = try encodeRead(a, try readCsvImpl(a, bytes, o, true));
    const f = catfn.applyEnums(a, f0, opts.enums) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooLarge => error.TooManyRows,
        error.BadValue => error.BadValue,
    };
    return withRowIndex(a, try applyZones(a, f, opts.types), opts);
}

/// `types` with the `enums` columns declared text first (their cells are matched against the
/// category list as text, whatever they look like), the caller's own entries after.
pub fn enumTypes(a: std.mem.Allocator, enums: []const catfn.EnumDecl, types: []const TypeOverride) std.mem.Allocator.Error![]const TypeOverride {
    const ts = try a.alloc(TypeOverride, enums.len + types.len);
    for (enums, ts[0..enums.len]) |e, *t| t.* = .{ .name = e.name, .type = .text };
    @memcpy(ts[enums.len..], types);
    return ts;
}

/// `row_index_name`: a leading int column `offset`, `offset + 1`... (wrapping past i64).
fn withRowIndex(a: std.mem.Allocator, f: Frame, opts: CsvReadOptions) CsvReadError!Frame {
    const name = opts.row_index_name orelse return f;
    if (f.columnIndex(name) != null) return error.BadOptions;
    const vals = try a.alloc(i64, f.len);
    for (vals, 0..) |*v, i| v.* = opts.row_index_offset +% @as(i64, @bitCast(@as(u64, i)));
    const cols = try a.alloc(Column, f.columns.len + 1);
    const data = try a.alloc(ColumnData, f.columns.len + 1);
    cols[0] = .{ .name = try a.dupe(u8, name), .type = .int };
    data[0] = if (f.len == 0) .nulls else .{ .int = .{ .values = vals, .valid = null } };
    @memcpy(cols[1..], f.columns);
    for (data[1..], 0..) |*d, i| d.* = if (i < f.data.len) f.data[i] else .nulls;
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// A read frame with its `.categorical` columns encoded (`types` names them).
fn encodeRead(a: std.mem.Allocator, f: Frame) CsvReadError!Frame {
    return frame_mod.encodeDeclared(a, f) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooLarge => error.TooManyRows, // past u32 rows: `max_rows` was raised that far
    };
}

/// For the differential tests only: the cell-by-cell second pass the typed one replaced.
pub const test_hooks = struct {
    pub fn readCsvCells(a: std.mem.Allocator, bytes: []const u8, opts: CsvReadOptions) CsvReadError!Frame {
        return encodeRead(a, try readCsvImpl(a, bytes, opts, false));
    }
    /// How many reads the one-pass reader finished, and how many it gave up on.
    pub var spec_done: usize = 0;
    pub var spec_gave_up: usize = 0;
    pub const fastInt = fastIntImpl;
    pub const fastFloat = fastFloatImpl;
    pub const countNewlines = countNewlinesImpl;
    pub const isNullFast = nullFast;
    pub const isNullSlow = isNullCell;
    pub const kindsOfFn = kindsOf;
};

fn fastIntImpl(t: []const u8) ?i64 {
    return fastInt(t);
}

fn fastFloatImpl(t: []const u8) ?f64 {
    return fastFloat(t);
}

fn countNewlinesImpl(b: []const u8) usize {
    return countNewlines(b);
}

fn nullFast(opts: *const CsvReadOptions, s: []const u8) bool {
    const ns = NullSet.init(opts);
    return ns.isNull(opts, s);
}

fn readCsvImpl(a: std.mem.Allocator, bytes: []const u8, opts: CsvReadOptions, typed: bool) CsvReadError!Frame {
    if (bytes.len > opts.max_bytes) return error.InputTooLarge;
    var o = opts;
    try prepareOptions(a, &o);
    if (opts.bad_lines_skipped) |p| p.* = 0;
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

    const nulls = NullSet.init(&o);
    var cx_store: Cx = undefined;
    const cx: ?*Cx = if (needsCx(&o)) blk: {
        cx_store = try Cx.init(a, &o, names, sel_idx);
        break :blk &cx_store;
    } else null;
    if (typed and cx == null and !o.parse_dates) {
        if (try readSpeculative(a, bytes, &o, &nulls, names, sel_idx, types, fixed)) |f| return f;
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
            if (cx) |x| x.rowReset();
            for (sel_idx, 0..) |c, j| {
                // Mask 0 (text) cannot change any more.
                if (fixed[j] or masks[j] == 0 or c >= fields.len) continue;
                const s = fields[c];
                if (nulls.isNull(&o, s)) continue;
                if (cx) |x| {
                    if (x.isColNull(j, s)) continue;
                    seen[j] = true;
                    masks[j] &= try x.kinds(s);
                    continue;
                }
                seen[j] = true;
                masks[j] &= kindsOf(s, opts.parse_dates);
            }
        }
        if (opts.bad_lines_skipped) |p| p.* = pass1.bad;
        row_count = pass1.rows;
        for (types, fixed, masks, seen) |*t, f, m, sn| {
            if (!f) t.* = typeOfMask(sn, m);
        }
    }

    // Pass 2: the cells.
    const cols = try a.alloc(Column, nsel);
    for (cols, sel_idx, types) |*c, i, t| c.* = .{ .name = try a.dupe(u8, names[i]), .type = t };
    // A text column reserves from its first cell times the row count; cap each one at
    // its share of the input, so all reservations together stay within `bytes.len`
    // (a wide first row of long cells over short rows reserved 1 MiB per column).
    const text_share = bytes.len / @max(nsel, 1);
    if (typed and cx == null) typed_pass: {
        var tp = try Scanner.open(a, bytes, &o);
        defer tp.deinit();
        _ = try tp.header(a);
        const accs = try a.alloc(Acc, nsel);
        for (accs, types) |*ac, t| ac.* = .{ .ty = t, .infer = false, .cap = row_count, .text_cap = text_share };
        const rows = scanInto(a, &tp, &o, &nulls, accs, sel_idx, row_count) catch |e| switch (e) {
            // Only `putInfer` (nothing is inferred here) and a row past `row_count` (pass 1
            // counted them all) say it; if it ever did, read the cells the slow way below
            // rather than trust an invariant with `unreachable`.
            error.SpeculationFailed => break :typed_pass,
            else => |x| return x,
        };
        const data = try a.alloc(ColumnData, nsel);
        for (data, accs) |*d, *ac| d.* = ac.finish(rows);
        return .{ .columns = cols, .data = data, .len = rows };
    }

    var p2 = try Scanner.open(a, bytes, &o);
    defer p2.deinit();
    _ = try p2.header(a);
    var fb = try FrameBuilder.init(a, cols, row_count);
    for (fb.cols) |*c| c.text_cap = @min(c.text_cap, text_share);
    const cells = try a.alloc(Value, nsel);
    while (try p2.next()) |fields| {
        // The cells of this row may point into the scratch arena (layout-parsed dates): one
        // reset per row, never per cell, so the cells stay valid until `appendRow` copies them.
        if (cx) |x| x.rowReset();
        for (cells, sel_idx, types, 0..) |*cell, c, t, j| {
            if (c >= fields.len) {
                cell.* = .null;
                continue;
            }
            const s = fields[c];
            if (isNullCell(&o, s) or (cx != null and cx.?.isColNull(j, s))) {
                cell.* = .null;
                continue;
            }
            cell.* = (if (cx) |x| try x.parse(t, s) else parseAs(t, s)) orelse return error.BadValue;
        }
        fb.appendRow(cells) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.RowLength => unreachable, // cells.len == columns.len
        };
    }
    return fb.toOwned();
}

/// Cells `readSpeculative` reserves beyond the input's length: room for a small file.
const speculation_slack_cells: usize = 4096;

fn countNewlines(bytes: []const u8) usize {
    const V = @Vector(32, u8);
    const nl: V = @splat('\n');
    var n: usize = 0;
    var i: usize = 0;
    while (i + 32 <= bytes.len) : (i += 32) {
        const v: V = bytes[i..][0..32].*;
        n += @popCount(@as(u32, @bitCast(v == nl)));
    }
    for (bytes[i..]) |c| n += @intFromBool(c == '\n');
    return n;
}

/// Both passes in one: the types are decided while the cells are stored. Null when a
/// column's type turned out to need the cells read again (see `Acc`); the caller then
/// takes the two-pass way. Not for `parse_dates`, whose date and timestamp kinds rank
/// among the others.
fn readSpeculative(
    a: std.mem.Allocator,
    bytes: []const u8,
    o: *const CsvReadOptions,
    nulls: *const NullSet,
    names: []const []const u8,
    sel_idx: []const usize,
    types: []ColumnType,
    fixed: []const bool,
) CsvReadError!?Frame {
    const nsel = sel_idx.len;
    var sc = try Scanner.open(a, bytes, o);
    defer sc.deinit();
    _ = try sc.header(a);
    // At most one row per newline, one more for a last line without one, and no more
    // than the cell limit lets through (it errors on the row past it).
    const lines = countNewlines(bytes) + 1;
    const est = @min(lines, o.max_cells / @max(nsel, 1) + 1);
    // Memory is proportional to the input (sweep S2-1): a row of `nsel` fields takes at
    // least `nsel - 1` bytes of the input, so `est x nsel` cells past the input's length
    // (blank lines, comments, quoted newlines, short rows over a wide header) are not
    // reserved on a guess; the two-pass reader counts the rows it really has.
    if (est *| nsel > bytes.len +| speculation_slack_cells) return null;
    const text_share = bytes.len / @max(nsel, 1);
    const accs = try a.alloc(Acc, nsel);
    for (accs, types, fixed) |*ac, t, f| ac.* = .{ .ty = t, .infer = !f, .cap = est, .text_cap = text_share };
    const rows = scanInto(a, &sc, o, nulls, accs, sel_idx, est) catch |e| switch (e) {
        error.SpeculationFailed => {
            if (@import("builtin").is_test) test_hooks.spec_gave_up += 1;
            return null;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => |x| return @as(CsvReadError, @errorCast(x)),
    };
    if (@import("builtin").is_test) test_hooks.spec_done += 1;
    if (o.bad_lines_skipped) |p| p.* = sc.bad;
    const cols = try a.alloc(Column, nsel);
    for (cols, sel_idx, accs, types, fixed) |*c, i, *ac, t, f| c.* = .{ .name = try a.dupe(u8, names[i]), .type = if (f) t else if (ac.nonnull == 0) .text else ac.ty };
    const data = try a.alloc(ColumnData, nsel);
    for (data, accs) |*d, *ac| d.* = ac.finish(rows);
    return .{ .columns = cols, .data = data, .len = rows };
}

/// One output column of the typed readers. Storage is picked by the column's type
/// (every cell `parseAs` makes has the tag that type implies, so this is the array
/// `FrameBuilder` would have picked), allocated at the first non-null cell with the
/// rows before it as zeros and clear bits; no non-null cell: `.nulls`.
///
/// An `infer` column has no type yet: the first non-null cell picks int, float or text
/// and a later cell may widen int to float (in place, the array is 8-byte cells either
/// way); anything that would make the column a different type than the cells so far
/// (text, bool, an int that does not fit) is `error.SpeculationFailed`, and the caller
/// reads the file again the slow way, with the types known.
const Acc = struct {
    ty: ColumnType,
    infer: bool,
    /// Rows the arrays hold.
    cap: usize,
    text_cap: usize,
    ready: bool = false,
    nonnull: usize = 0,
    ints: []i64 = &.{},
    floats: []f64 = &.{},
    bools: []bool = &.{},
    decs: []i128 = &.{},
    offsets: []usize = &.{},
    bytes: std.ArrayList(u8) = .empty,
    valid: []u64 = &.{},

    fn isText(s: *const Acc) bool {
        return s.ty == .text or s.ty == .date or s.ty == .categorical;
    }

    fn setReady(s: *Acc, a: std.mem.Allocator, first_len: usize) std.mem.Allocator.Error!void {
        const n = s.cap;
        switch (s.ty) {
            // A width is stored as Int64 or (UInt64) its bit pattern, Float32 as f64; the
            // reader's `encodeDeclared` narrows them (`frame.conform`).
            .int, .timestamp, .duration, .time, .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 => {
                s.ints = try a.alloc(i64, n);
                @memset(s.ints, 0);
            },
            .float, .float32 => {
                s.floats = try a.alloc(f64, n);
                @memset(s.floats, 0);
            },
            .bool => {
                s.bools = try a.alloc(bool, n);
                @memset(s.bools, false);
            },
            .decimal => {
                s.decs = try a.alloc(i128, n);
                @memset(s.decs, 0);
            },
            .text, .date, .categorical => {
                s.offsets = try a.alloc(usize, n + 1);
                @memset(s.offsets, 0);
                try s.bytes.ensureTotalCapacity(a, @min(s.text_cap, first_len *| n));
            },
            .list, .array, .@"struct" => unreachable, // `putFixed` refuses every cell of these first
        }
        s.valid = try a.alloc(u64, n / 64 + 1);
        @memset(s.valid, 0);
        s.ready = true;
    }

    inline fn mark(s: *Acc, ri: usize) void {
        s.valid[ri / 64] |= @as(u64, 1) << @intCast(ri % 64);
        s.nonnull += 1;
    }

    /// The array of ints becomes the array of floats, in place.
    fn widen(s: *Acc, rows: usize) void {
        const fl: [*]f64 = @ptrCast(s.ints.ptr);
        for (0..rows) |i| fl[i] = @floatFromInt(s.ints[i]);
        s.floats = fl[0..s.cap];
        s.ints = &.{};
        s.ty = .float;
    }

    /// A cell of a column with a known type.
    fn putFixed(s: *Acc, a: std.mem.Allocator, ri: usize, c: []const u8) error{ OutOfMemory, BadValue }!void {
        switch (s.ty) {
            .int => {
                const x = fastInt(textio.trimBlank(c)) orelse return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                s.ints[ri] = x;
            },
            .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 => {
                const x = parseWideInt(textio.trimBlank(c)) orelse return error.BadValue;
                if (!dtype.fits(x, s.ty)) return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                // UInt64's upper half as its bit pattern; `finish` reads the array as u64.
                s.ints[ri] = if (s.ty == .uint64) @bitCast(@as(u64, @intCast(x))) else @intCast(x);
            },
            .float, .float32 => {
                const t = textio.trimBlank(c);
                const x = fastFloat(t) orelse blk: {
                    if (!textio.isFloatGrammar(t)) return error.BadValue;
                    break :blk textio.parseFloatToken(t) orelse return error.BadValue;
                };
                if (!s.ready) try s.setReady(a, 0);
                s.floats[ri] = if (s.ty == .float32) dtype.roundF32(x) else x;
            },
            .bool => {
                const x = parseBoolToken(c) orelse return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                s.bools[ri] = x;
            },
            .timestamp => {
                const x = value.parseIsoTimestamp(c) orelse return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                s.ints[ri] = x;
            },
            .duration => {
                const x = value.parseDurationCell(textio.trimBlank(c)) orelse return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                s.ints[ri] = x;
            },
            .time => {
                const x = value.parseTimeOfDay(textio.trimBlank(c)) orelse return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                s.ints[ri] = x;
            },
            .decimal => {
                const x = textio.parseDecimalToken(textio.trimBlank(c)) orelse return error.BadValue;
                if (!s.ready) try s.setReady(a, 0);
                s.decs[ri] = x;
            },
            .text, .date, .categorical => {
                if (s.ty == .date and !isIsoDate(c)) return error.BadValue;
                if (!s.ready) try s.setReady(a, c.len);
                try s.bytes.appendSlice(a, c);
            },
            .list, .array, .@"struct" => return error.BadValue, // `parseAs`'s rule
        }
        s.mark(ri);
    }

    /// A cell of a column whose type is still open. Without `parse_dates` the types
    /// are int, float, bool and text, and `kindsOf` ranks them: this follows its
    /// answer for the cells so far, and gives up where the answer could change a cell
    /// already stored.
    fn putInfer(s: *Acc, a: std.mem.Allocator, ri: usize, c: []const u8) error{ OutOfMemory, SpeculationFailed }!void {
        if (!s.ready) {
            // First non-null cell: every cell before it is null, nothing is lost.
            const t = textio.trimBlank(c);
            if (fastInt(t)) |x| {
                if (x == 0 and t[0] == '-') return error.SpeculationFailed;
                s.ty = .int;
                try s.setReady(a, 0);
                s.ints[ri] = x;
            } else if (textio.isIntGrammar(t) or floatOnly(t) == null) {
                // An int that does not fit is text; so is what is no number (bool: maybe).
                if (!textio.isIntGrammar(t) and kindsOf(c, false) != 0) return error.SpeculationFailed;
                s.ty = .text;
                try s.setReady(a, c.len);
                try s.bytes.appendSlice(a, c);
            } else {
                s.ty = .float;
                try s.setReady(a, 0);
                s.floats[ri] = floatOnly(t).?;
            }
            s.mark(ri);
            return;
        }
        switch (s.ty) {
            .int => {
                var x = fastInt(c);
                if (x == null) x = fastInt(textio.trimBlank(c));
                if (x) |v| {
                    if (v == 0 and textio.trimBlank(c)[0] == '-') return error.SpeculationFailed;
                    s.ints[ri] = v;
                } else {
                    // Not an int: a float widens the column, anything else makes it
                    // text or bool, and the ints before are not text yet.
                    const f = floatOnly(textio.trimBlank(c)) orelse return error.SpeculationFailed;
                    s.widen(ri);
                    s.floats[ri] = f;
                }
            },
            .float => {
                const t = textio.trimBlank(c);
                if (fastInt(t)) |v| {
                    // `-0` is -0.0 as a float token, 0 as an int.
                    s.floats[ri] = if (v == 0) (textio.parseFloatToken(t) orelse return error.SpeculationFailed) else @floatFromInt(v);
                } else {
                    s.floats[ri] = floatOnly(t) orelse return error.SpeculationFailed;
                }
            },
            .text => try s.bytes.appendSlice(a, c),
            else => unreachable, // putInfer only ever picks these three
        }
        s.mark(ri);
    }

    fn finish(s: *const Acc, rows: usize) ColumnData {
        if (s.nonnull == 0) return .nulls;
        const valid: ?[]const u64 = if (s.nonnull == rows) null else s.valid[0 .. rows / 64 + 1];
        return switch (s.ty) {
            .int, .timestamp, .duration, .time, .int8, .int16, .int32, .uint8, .uint16, .uint32 => .{ .int = .{ .values = s.ints[0..rows], .valid = valid } },
            .uint64 => .{ .uint64 = .{ .values = @ptrCast(s.ints[0..rows]), .valid = valid } },
            .float, .float32 => .{ .float = .{ .values = s.floats[0..rows], .valid = valid } },
            .bool => .{ .bool = .{ .values = s.bools[0..rows], .valid = valid } },
            .decimal => .{ .decimal = .{ .values = s.decs[0..rows], .valid = valid } },
            .text, .date, .categorical => .{ .text = .{ .offsets = s.offsets[0 .. rows + 1], .bytes = s.bytes.items, .valid = valid } },
            .list, .array, .@"struct" => .nulls, // no cell was stored (`putFixed`)
        };
    }
};

const ColumnData = frame_mod.ColumnData;

const ScanError = CsvReadError || error{SpeculationFailed};

/// The rows of `sc` (past its header) into `accs`; `est` is the most rows there can be.
/// Returns the row count. A cell that does not parse as its column's type is
/// `error.BadValue`, but only once the whole input has been scanned, so that a
/// malformed record later on is reported first, as the two-pass reader does.
fn scanInto(
    a: std.mem.Allocator,
    sc: *Scanner,
    o: *const CsvReadOptions,
    nulls: *const NullSet,
    accs: []Acc,
    sel_idx: []const usize,
    est: usize,
) ScanError!usize {
    var ri: usize = 0;
    var bad = false;
    while (try sc.next()) |fields| : (ri += 1) {
        if (accs.len != 0 and sc.rows > o.max_cells / accs.len) return error.TooManyCells;
        if (ri >= est) return error.SpeculationFailed;
        for (accs, sel_idx) |*ac, c| {
            if (c < fields.len and !bad) {
                const cell = fields[c];
                if (!nulls.isNull(o, cell)) {
                    if (ac.infer) {
                        try ac.putInfer(a, ri, cell);
                    } else ac.putFixed(a, ri, cell) catch |e| switch (e) {
                        error.BadValue => bad = true,
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                }
            }
            if (ac.ready and ac.isText()) ac.offsets[ri + 1] = ac.bytes.items.len;
        }
    }
    if (bad) return error.BadValue;
    return ri;
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

    // ── added 2026-11-09 (dataframe S2, output options) ──
    /// A `%` layout (pandas `date_format`, polars `date_format`) for `.date` columns instead of
    /// ISO `YYYY-MM-DD`. A `.timestamp` column that is not `datetime_format`ed ignores it.
    date_format: ?[]const u8 = null,
    /// A `%` layout (pandas `date_format`, polars `datetime_format`) for `.timestamp` columns
    /// instead of `YYYY-MM-DD HH:MM:SS[.fff]` (the cell is UTC). There is no time-of-day column
    /// type here, so pandas' and polars' `time_format` has nothing to apply to.
    datetime_format: ?[]const u8 = null,
    /// Floats in scientific notation (polars `float_scientific=True`, Rust's `1.2345e2`, with
    /// `float_precision` digits when set), or never (`false`: `0.00001`, `2` for 2.0, no exponent). `null`: Python's `repr` (pandas, polars' automatic choice).
    /// pandas' `float_format="%.3e"` (exponent `e+02`) is not offered.
    float_scientific: ?bool = null,
    /// Write only these columns, in this order (pandas `columns`, polars `select` before). A
    /// name the frame lacks is `error.NoSuchColumn`.
    columns: ?[]const []const u8 = null,
    /// The byte written as the decimal point of floats and decimals (pandas `decimal`,
    /// polars `decimal_comma` = `','`; with `delimiter = ','` the cell is then quoted).
    decimal: u8 = '.',
    /// A quote inside a quoted field is doubled (pandas `doublequote`). Off: it is written
    /// as `escape_char` + quote, and `escape_char` must be set (else `error.BadOptions`).
    double_quote: bool = true,
    /// Escape byte for `double_quote = false` (pandas `escapechar`).
    escape_char: u8 = 0,
    /// Start with a UTF-8 byte order mark (polars `include_bom`; pandas `encoding="utf-8-sig"`).
    include_bom: bool = false,
};

pub const CsvWriteError = error{
    WriteFailed,
    OutOfMemory,
    /// `columns` names a column the frame does not have.
    NoSuchColumn,
    /// A `date_format`/`datetime_format` that is not a `%` layout, `decimal` of `0`, or
    /// `double_quote = false` without `escape_char`.
    BadOptions,
};

/// `f` as CSV: the header (`header`), then one line per row. Floats are written as
/// Python's `repr` (pandas): `1.0`, `0.1`, `1e-05`, `inf`; NaN is the null text. A
/// timestamp is `YYYY-MM-DD HH:MM:SS` with a fraction of 3 or 6 digits in every cell of a
/// column when one cell has a fraction (pandas); a date is its ISO text; a decimal is
/// exact. A frame with no columns writes nothing. `a` holds one flag per column.
pub fn writeCsv(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: CsvWriteOptions) CsvWriteError!void {
    if (opts.decimal == 0 or (!opts.double_quote and opts.escape_char == 0)) return error.BadOptions;
    // The columns written, as indexes into `f`.
    const sel = try a.alloc(usize, if (opts.columns) |c| c.len else f.columns.len);
    defer a.free(sel);
    if (opts.columns) |want| {
        for (sel, want) |*s, n| s.* = f.columnIndex(n) orelse return error.NoSuchColumn;
    } else for (sel, 0..) |*s, i| {
        s.* = i;
    }
    var date_layout: ?[]const u8 = null;
    var stamp_layout: ?[]const u8 = null;
    var layouts = std.heap.ArenaAllocator.init(a);
    defer layouts.deinit();
    if (opts.date_format) |l| date_layout = dtfn.translateFormat(layouts.allocator(), l) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadFormat => return error.BadOptions,
    };
    if (opts.datetime_format) |l| stamp_layout = dtfn.translateFormat(layouts.allocator(), l) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadFormat => return error.BadOptions,
    };
    var fmt_scratch = std.heap.ArenaAllocator.init(a);
    defer fmt_scratch.deinit();
    if (sel.len == 0) return;
    if (opts.include_bom) try w.writeAll("\xEF\xBB\xBF");
    const base: csvstream.WriteOptions = .{
        .delimiter = opts.delimiter,
        .quote = opts.quote,
        .escape = if (opts.double_quote) 0 else opts.escape_char,
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
    const single = sel.len == 1;
    if (opts.header) {
        for (sel, 0..) |fi, i| {
            const c = f.columns[fi];
            if (i != 0) try w.writeByte(opts.delimiter);
            if (single and c.name.len == 0) try writeEmptyQuoted(w, opts) else try csvstream.writeField(w, c.name, if (opts.quote_style == .non_numeric) always else base);
        }
        try w.writeAll(term);
    }
    // The fraction digits of each timestamp column.
    const stamp_cols = try a.alloc(u8, sel.len);
    defer a.free(stamp_cols);
    for (sel, 0..) |fi, ci| {
        stamp_cols[ci] = 0;
        if (f.columns[fi].type != .timestamp) continue;
        const col = f.columnAt(fi);
        for (0..f.len) |ri| {
            const v = col.get(ri);
            if (v == .int) stamp_cols[ci] = textio.fractionDigits(v.int, stamp_cols[ci]);
            if (stamp_cols[ci] == 6) break;
        }
    }
    // The zone of each timestamp column: its cells are written as that zone's wall clock + offset.
    const stamp_zones = try a.alloc(?*const tz.Zone, sel.len);
    defer a.free(stamp_zones);
    for (sel, stamp_zones) |fi, *z| z.* = if (f.columns[fi].type == .timestamp) textio.zoneOf(f.columns[fi].time_zone) else null;
    // A nested cell's JSON, one at a time.
    var nested: std.Io.Writer.Allocating = .init(a);
    defer nested.deinit();
    for (0..f.len) |ri| {
        for (sel, 0..) |fi, ci| {
            const c = f.columns[fi];
            if (ci != 0) try w.writeByte(opts.delimiter);
            const v = f.columnAt(fi).get(ri);
            var nb: [textio.max_float_len + 8]u8 = undefined;
            var big: [400]u8 = undefined; // a fixed-point float: up to 309 digits and the fraction
            var sb: [textio.max_stamp_len]u8 = undefined;
            var db: [textio.max_decimal_len]u8 = undefined;
            var ub: [value.max_duration_len]u8 = undefined;
            var sb2: [400]u8 = undefined;
            var text_like = false;
            var is_text_value = false;
            var layout_text: ?[]const u8 = null;
            if (v != .null) {
                const lay = if (c.type == .date) date_layout else if (c.type == .timestamp) stamp_layout else null;
                if (lay) |l| {
                    _ = fmt_scratch.reset(.retain_capacity);
                    const t = (if (stamp_zones[ci]) |z| dtfn.strftimeZoned(fmt_scratch.allocator(), v, "", l, z) else dtfn.strftime(fmt_scratch.allocator(), v, l)) catch return error.OutOfMemory;
                    if (t == .text) layout_text = t.text;
                }
            }
            var s: []const u8 = if (layout_text) |t| blk: {
                text_like = true;
                break :blk t;
            } else switch (v) {
                .null => opts.null_text,
                .bool => |b| if (b) opts.true_text else opts.false_text,
                .int => |i| if (c.type == .timestamp) blk: {
                    text_like = true;
                    break :blk textio.formatStampZoned(&sb, i, stamp_cols[ci], stamp_zones[ci]);
                } else if (c.type == .duration) blk: {
                    // polars refuses a duration in CSV, pandas writes `1 days 02:03:04`;
                    // ISO 8601 is the form `readCsv` reads back (and both engines' JSON).
                    text_like = true;
                    break :blk value.formatIsoDuration(&ub, i);
                } else if (c.type == .time) blk: {
                    // polars writes nine digits (its nanoseconds), pandas `str(time)`;
                    // this is polars' display and JSON form, which `readCsv` reads back.
                    text_like = true;
                    var tb: [value.max_time_len]u8 = undefined;
                    const t = value.formatTimeOfDay(&tb, i) orelse break :blk opts.null_text;
                    @memcpy(ub[0..t.len], t);
                    break :blk ub[0..t.len];
                } else std.fmt.bufPrint(&nb, "{d}", .{i}) catch unreachable,
                .float => |x| if (std.math.isNan(x))
                    opts.null_text
                else if (std.math.isInf(x))
                    (if (x > 0) "inf" else "-inf")
                else if (opts.float_scientific) |sci|
                    (if (sci) formatSci(&big, x, opts.float_precision) else formatPlain(&big, x, opts.float_precision))
                else if (opts.float_precision) |p|
                    textio.formatFloatFixed(&big, x, @min(p, 22))
                else if (c.type == .float32)
                    textio.formatFloat32(nb[0..textio.max_float_len], @floatCast(x))
                else
                    textio.formatFloat(nb[0..textio.max_float_len], x),
                .uint => |u| std.fmt.bufPrint(&nb, "{d}", .{u}) catch unreachable, // 20 digits fit
                .decimal => |r| textio.formatDecimal(&db, r),
                .text => |t| blk: {
                    text_like = true;
                    is_text_value = true;
                    break :blk t;
                },
                // As its JSON text (pandas writes a Python repr, polars refuses), which
                // `readJson` reads back nested and `readCsv` as text.
                .list, .record => blk: {
                    text_like = true;
                    nested.clearRetainingCapacity();
                    jsonio.writeValue(&nested.writer, v, c, 0) catch return error.OutOfMemory; // an Allocating writer fails only so
                    break :blk nested.written();
                },
            };
            if (opts.decimal != '.' and ((v == .float and !std.math.isNan(v.float)) or v == .decimal) and std.mem.findScalar(u8, s, '.') != null) {
                // The point is the only '.' in a number's spelling (an exponent has none).
                const copy = sb2[0..@min(s.len, sb2.len)];
                @memcpy(copy, s[0..copy.len]);
                for (copy) |*ch| if (ch.* == '.') {
                    ch.* = opts.decimal;
                };
                s = copy;
            }
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

/// Rust's `{:e}` (polars `float_scientific=True`): `1.2345e2`, `.N` digits when `prec` is set.
fn formatSci(buf: []u8, x: f64, prec: ?u8) []const u8 {
    return (if (prec) |p|
        std.fmt.bufPrint(buf, "{e:.[1]}", .{ x, @as(usize, @min(p, 22)) })
    else
        std.fmt.bufPrint(buf, "{e}", .{x})) catch "";
}

/// A float without an exponent (polars `float_scientific=False`): the shortest digits (`2`,
/// `0.00001`, `100000000000000000000`: polars prints no `.0` here), or `prec` fixed digits.
fn formatPlain(buf: []u8, x: f64, prec: ?u8) []const u8 {
    if (prec) |p| return textio.formatFloatFixed(buf, x, @min(p, 22));
    return std.fmt.bufPrint(buf, "{d}", .{x}) catch "";
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
