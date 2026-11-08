// SPDX-License-Identifier: MIT
//! A `Frame` from JSON text, the reverse of `jsonio`: `records` (`[{"a":1,"b":"x"},...]`,
//! pandas `read_json(orient="records")`, polars `read_json`), `columns`
//! (`{"a":[1,2],"b":["x","y"]}`, pandas `orient="list"` as `DataFrame(dict)` reads it) and
//! ndjson (one object per line, pandas `lines=True`, polars `read_ndjson`).
//!
//! Two passes over the bytes through `std.json.Scanner` (iterative, so nesting depth costs
//! a bit per level, never stack): the first finds the columns, in the order their keys first
//! appear, and the kinds of value each holds; the second stores the cells straight into
//! typed arrays. A column's type follows the CSV reader's rules on the same text, so a
//! number in JSON reads as the same number in CSV (`csvio.parseAs` does both):
//!
//! - only integers that fit i64: `int`; integers and other numbers: `float`; an integer past
//!   i64 makes the column `text` (a float would lose its digits, as in `readCsv`);
//! - only `true`/`false`: `bool`;
//! - only strings: `text`, or with `parse_dates` `date` (every one `YYYY-MM-DD`) or
//!   `timestamp` (every one another ISO 8601 instant, zone applied, UTC);
//! - no value but `null` (or the key never there): `text`, as `readCsv`;
//! - anything else, a mix of kinds or an object/array value: `text`, each cell written as
//!   its source — a number's digits as they stand, `true`/`false`, a nested value's JSON
//!   text (pandas keeps a Python object, polars a struct/list column; this module has no
//!   nested columns yet, and the JSON text loses nothing).
//!
//! A key missing from a record is null in that row (both engines); a key repeated in one
//! object keeps its last value (Python's `json`, so pandas; RFC 8259 leaves it open). In
//! `columns` every array must be as long as the others (`error.RaggedColumns`, both
//! engines refuse); a repeated key keeps its last array.

const std = @import("std");
const value = @import("value.zig");
const frame_mod = @import("frame.zig");
const csvio = @import("csvio.zig");

const Frame = frame_mod.Frame;
const ColBuilder = frame_mod.ColBuilder;
const Column = value.Column;
const ColumnType = value.ColumnType;
const Value = value.Value;
const Scanner = std.json.Scanner;

pub const JsonReadOrient = enum { records, columns };

pub const JsonReadError = error{
    OutOfMemory,
    /// The input is longer than `max_bytes`.
    InputTooLarge,
    /// Not JSON (RFC 8259, strings valid UTF-8), or cut short.
    BadJson,
    /// JSON, but not the shape the orient reads: `records` wants an array of objects,
    /// `columns` an object of arrays, ndjson an object on every non-blank line.
    BadShape,
    /// `columns` arrays of different lengths.
    RaggedColumns,
    /// More than `max_columns` distinct keys.
    TooManyColumns,
    /// More than `max_rows` rows.
    TooManyRows,
    /// Rows times read columns past `max_cells`.
    TooManyCells,
    /// A string, number or nested value longer than `max_cell_bytes` (a key too).
    CellTooLarge,
    /// `columns` or `types` names a key the input does not have.
    NoSuchColumn,
    /// A value that does not read as the type `types` demands.
    BadValue,
};

pub const JsonReadOptions = struct {
    /// Ignored by `readNdjson`.
    orient: JsonReadOrient = .records,
    /// Read only these columns; the result keeps the input's order.
    columns: ?[]const []const u8 = null,
    /// A column's type given instead of inferred (pandas `dtype=`, polars `schema_overrides`).
    /// A string or number reads as `readCsv` reads the same text; `true`/`false` as text
    /// or bool; a nested value only as text.
    types: []const csvio.TypeOverride = &.{},
    /// Off: every column of scalars is still typed, strings stay text. On: see the module doc.
    parse_dates: bool = false,
    /// Stop after this many rows (pandas `nrows`, polars `n_rows`). The rest must still be JSON.
    n_rows: ?usize = null,
    max_bytes: usize = csvio.default_max_bytes,
    max_columns: usize = 1 << 16,
    max_cell_bytes: usize = 1 << 20,
    max_rows: usize = 1 << 26,
    max_cells: usize = 1 << 26,
};

/// One JSON document as a frame, in `opts.orient`. `[]` and `{}` are a frame of no columns.
/// The result copies what it needs from `bytes`; `a` is meant to be an arena (the frame
/// rule), and the scratch of the read stays in it.
pub fn readJson(a: std.mem.Allocator, bytes: []const u8, opts: JsonReadOptions) JsonReadError!Frame {
    return read(a, bytes, opts, if (opts.orient == .records) .records else .columns);
}

/// One object per line (`\n`, a `\r` before it allowed); blank lines are skipped (both
/// engines). An empty input is a frame of no columns.
pub fn readNdjson(a: std.mem.Allocator, bytes: []const u8, opts: JsonReadOptions) JsonReadError!Frame {
    return read(a, bytes, opts, .lines);
}

const Shape = enum { records, columns, lines };

const Tok = union(enum) {
    null,
    bool: bool,
    number: []const u8,
    string: []const u8,
    /// An object or array value, as its JSON source text.
    nested: []const u8,
};

const m_int: u8 = 1;
const m_float: u8 = 2;
const m_big: u8 = 4; // a number `parseAs` reads as neither int nor float
const m_bool: u8 = 8;
const m_str: u8 = 16;
const m_nested: u8 = 32;
const m_not_date: u8 = 64; // a string that is not an ISO date
const m_not_stamp: u8 = 128; // a string that is not an ISO instant

fn kindOf(t: Tok, parse_dates: bool) u8 {
    return switch (t) {
        .null => 0,
        .bool => m_bool,
        .number => |s| if (csvio.parseAs(.int, s) != null) m_int else if (csvio.parseAs(.float, s) != null) m_float else m_big,
        .string => |s| if (!parse_dates) m_str else m_str |
            (if (csvio.parseAs(.date, s) != null) 0 else m_not_date) |
            (if (value.parseIsoTimestamp(s) != null) 0 else m_not_stamp),
        .nested => m_nested,
    };
}

fn typeOf(mask: u8, parse_dates: bool) ColumnType {
    const kinds = mask & (m_int | m_float | m_big | m_bool | m_str | m_nested);
    if (kinds == 0) return .text;
    if (kinds & ~(m_int | m_float) == 0) return if (kinds == m_int) .int else .float;
    if (kinds == m_bool) return .bool;
    if (kinds == m_str and parse_dates) {
        if (mask & m_not_date == 0) return .date;
        if (mask & m_not_stamp == 0) return .timestamp;
    }
    return .text;
}

/// The cell as `ty`; null when it cannot be one.
fn convert(t: Tok, ty: ColumnType) ?Value {
    const src: []const u8 = switch (t) {
        .null => return .null,
        .bool => |b| if (b) "true" else "false",
        .number, .string => |s| s,
        .nested => |s| if (ty == .text) s else return null,
    };
    return csvio.parseAs(ty, src);
}

/// The walk both passes share: it finds the rows and keys and hands each kept cell to
/// the pass, once per (row, column), the last value of a repeated key.
const Walk = struct {
    a: std.mem.Allocator,
    opts: *const JsonReadOptions,
    discover: bool = true,
    names: std.ArrayList([]const u8) = .empty,
    map: std.StringHashMapUnmanaged(usize) = .empty,
    /// Per column: row + 1 while it is set in the record being read.
    stamp: std.ArrayList(usize) = .empty,
    /// Per column: its entry in `rec`.
    slot: std.ArrayList(usize) = .empty,
    rec: std.ArrayList(struct { ci: usize, tok: Tok }) = .empty,
    /// `columns`: per column the ordinal of its last key and that array's length.
    last_ord: std.ArrayList(usize) = .empty,
    col_len: std.ArrayList(usize) = .empty,
    rows: usize = 0,

    fn limitRows(w: *const Walk) usize {
        return w.opts.n_rows orelse std.math.maxInt(usize);
    }

    /// The column of `key`; in discovery a new key is a new column.
    fn column(w: *Walk, key: []const u8) JsonReadError!struct { ci: usize, new: bool } {
        if (!w.discover) return .{ .ci = w.map.get(key).?, .new = false }; // discovery saw every key
        const gop = try w.map.getOrPut(w.a, key);
        if (gop.found_existing) return .{ .ci = gop.value_ptr.*, .new = false };
        if (w.names.items.len >= w.opts.max_columns) return error.TooManyColumns;
        gop.value_ptr.* = w.names.items.len;
        try w.names.append(w.a, key);
        try w.stamp.append(w.a, 0);
        try w.slot.append(w.a, 0);
        try w.last_ord.append(w.a, 0);
        try w.col_len.append(w.a, 0);
        return .{ .ci = gop.value_ptr.*, .new = true };
    }

    fn startPass(w: *Walk, discover: bool) void {
        w.discover = discover;
        @memset(w.stamp.items, 0);
        w.rows = 0;
    }

    fn walk(w: *Walk, bytes: []const u8, shape: Shape, pass: anytype) JsonReadError!void {
        switch (shape) {
            .records => {
                var sc = Scanner.initCompleteInput(w.a, bytes);
                defer sc.deinit();
                if (try peek(&sc) != .array_begin) return error.BadShape;
                _ = try next(&sc);
                while (try peek(&sc) != .array_end) {
                    if (w.rows >= w.limitRows()) {
                        sc.skipValue() catch |e| return jsonErr(e);
                        continue;
                    }
                    try w.record(&sc, pass);
                }
                _ = try next(&sc);
                if (try peek(&sc) != .end_of_document) return error.BadJson;
            },
            .lines => {
                var it = std.mem.splitScalar(u8, bytes, '\n');
                while (it.next()) |raw| {
                    const line = std.mem.trim(u8, raw, " \t\r");
                    if (line.len == 0) continue;
                    var sc = Scanner.initCompleteInput(w.a, line);
                    defer sc.deinit();
                    if (w.rows >= w.limitRows()) {
                        // Still JSON, as the brief for `n_rows` says; not read into the frame.
                        sc.skipValue() catch |e| return jsonErr(e);
                    } else {
                        if (try peek(&sc) != .object_begin) return error.BadShape;
                        try w.record(&sc, pass);
                    }
                    if (try peek(&sc) != .end_of_document) return error.BadJson;
                }
            },
            .columns => try w.columnsDoc(bytes, pass),
        }
    }

    /// One object as one row.
    fn record(w: *Walk, sc: *Scanner, pass: anytype) JsonReadError!void {
        if (try peek(sc) != .object_begin) return error.BadShape;
        _ = try next(sc);
        if (w.rows >= w.opts.max_rows) return error.TooManyRows;
        const row = w.rows;
        w.rec.clearRetainingCapacity();
        while (true) {
            const key = try w.nextKey(sc) orelse break;
            const col = try w.column(key);
            const tok = try w.scalarOrNested(sc);
            if (w.stamp.items[col.ci] == row + 1) {
                w.rec.items[w.slot.items[col.ci]].tok = tok;
            } else {
                w.stamp.items[col.ci] = row + 1;
                w.slot.items[col.ci] = w.rec.items.len;
                try w.rec.append(w.a, .{ .ci = col.ci, .tok = tok });
            }
        }
        for (w.rec.items) |c| try pass.cell(row, c.ci, c.tok);
        w.rows += 1;
    }

    fn columnsDoc(w: *Walk, bytes: []const u8, pass: anytype) JsonReadError!void {
        var sc = Scanner.initCompleteInput(w.a, bytes);
        defer sc.deinit();
        if (try peek(&sc) != .object_begin) return error.BadShape;
        _ = try next(&sc);
        var ord: usize = 0;
        while (try w.nextKey(&sc)) |key| : (ord += 1) {
            const col = try w.column(key);
            if (w.discover) {
                if (!col.new) pass.reset(col.ci); // a repeated key: its last array wins
                w.last_ord.items[col.ci] = ord;
            } else if (w.last_ord.items[col.ci] != ord) {
                sc.skipValue() catch |e| return jsonErr(e);
                continue;
            }
            if (try peek(&sc) != .array_begin) return error.BadShape;
            _ = try next(&sc);
            var i: usize = 0;
            while (try peek(&sc) != .array_end) : (i += 1) {
                if (i >= w.opts.max_rows) return error.TooManyRows;
                if (i >= w.limitRows()) {
                    sc.skipValue() catch |e| return jsonErr(e);
                    continue;
                }
                try pass.cell(i, col.ci, try w.scalarOrNested(&sc));
            }
            _ = try next(&sc);
            w.col_len.items[col.ci] = i;
        }
        if (try peek(&sc) != .end_of_document) return error.BadJson;
        const lens = w.col_len.items;
        for (lens) |l| if (l != lens[0]) return error.RaggedColumns;
        w.rows = if (lens.len == 0) 0 else @min(lens[0], w.limitRows());
    }

    /// The next key of an object, or null at its end.
    fn nextKey(w: *Walk, sc: *Scanner) JsonReadError!?[]const u8 {
        const t = sc.nextAllocMax(w.a, .alloc_if_needed, w.opts.max_cell_bytes) catch |e| return jsonErr(e);
        return switch (t) {
            .object_end => null,
            .string => |s| s,
            .allocated_string => |s| s,
            else => error.BadJson, // the scanner gives only keys or the end here
        };
    }

    fn scalarOrNested(w: *Walk, sc: *Scanner) JsonReadError!Tok {
        switch (try peek(sc)) {
            .object_begin, .array_begin => {
                // `peek` skipped the blanks: the cursor is at the opening bracket.
                const start = sc.cursor;
                sc.skipValue() catch |e| return jsonErr(e);
                const text = sc.input[start..sc.cursor];
                if (text.len > w.opts.max_cell_bytes) return error.CellTooLarge;
                return .{ .nested = text };
            },
            else => {},
        }
        const t = sc.nextAllocMax(w.a, .alloc_if_needed, w.opts.max_cell_bytes) catch |e| return jsonErr(e);
        return switch (t) {
            .null => .null,
            .true => .{ .bool = true },
            .false => .{ .bool = false },
            .number => |s| .{ .number = s },
            .allocated_number => |s| .{ .number = s },
            .string => |s| .{ .string = s },
            .allocated_string => |s| .{ .string = s },
            else => error.BadJson, // a value was peeked; the end tokens are not values
        };
    }
};

fn peek(sc: *Scanner) JsonReadError!std.json.TokenType {
    return sc.peekNextTokenType() catch |e| jsonErr(e);
}

fn next(sc: *Scanner) JsonReadError!std.json.Token {
    return sc.next() catch |e| jsonErr(e);
}

fn jsonErr(e: anyerror) JsonReadError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.ValueTooLong => error.CellTooLarge,
        else => error.BadJson, // SyntaxError, UnexpectedEndOfInput (BufferUnderrun cannot happen on complete input)
    };
}

/// Pass 1: what each column holds.
const Infer = struct {
    a: std.mem.Allocator,
    parse_dates: bool,
    masks: std.ArrayList(u8) = .empty,

    fn grow(p: *Infer, ci: usize) JsonReadError!void {
        while (p.masks.items.len <= ci) try p.masks.append(p.a, 0);
    }

    fn cell(p: *Infer, row: usize, ci: usize, t: Tok) JsonReadError!void {
        _ = row;
        try p.grow(ci);
        p.masks.items[ci] |= kindOf(t, p.parse_dates);
    }

    fn reset(p: *Infer, ci: usize) void {
        if (ci < p.masks.items.len) p.masks.items[ci] = 0;
    }
};

/// Pass 2: the cells into their columns.
const Fill = struct {
    /// Per input column: its output column, or null when not read.
    out: []const ?usize,
    types: []const ColumnType,
    builders: []ColBuilder,

    fn cell(p: *Fill, row: usize, ci: usize, t: Tok) JsonReadError!void {
        const oi = p.out[ci] orelse return;
        const b = &p.builders[oi];
        while (b.len < row) try b.appendNull();
        try b.append(convert(t, p.types[oi]) orelse return error.BadValue);
    }

    fn reset(p: *Fill, ci: usize) void {
        _ = p;
        _ = ci;
    }
};

fn read(a: std.mem.Allocator, bytes: []const u8, opts: JsonReadOptions, shape: Shape) JsonReadError!Frame {
    if (bytes.len > opts.max_bytes) return error.InputTooLarge;
    var w: Walk = .{ .a = a, .opts = &opts };
    var infer: Infer = .{ .a = a, .parse_dates = opts.parse_dates };
    w.startPass(true);
    try w.walk(bytes, shape, &infer);
    const rows = w.rows;
    const width = w.names.items.len;
    try infer.grow(width -| 1);

    // The columns read, in input order, and their types.
    const out = try a.alloc(?usize, width);
    @memset(out, null);
    if (opts.columns) |want| {
        for (want) |n| out[w.map.get(n) orelse return error.NoSuchColumn] = 0;
    } else @memset(out, 0);
    var nsel: usize = 0;
    for (out) |*o| if (o.* != null) {
        o.* = nsel;
        nsel += 1;
    };
    const cells = std.math.mul(usize, rows, nsel) catch return error.TooManyCells;
    if (cells > opts.max_cells) return error.TooManyCells;

    const cols = try a.alloc(Column, nsel);
    const types = try a.alloc(ColumnType, nsel);
    for (out, 0..) |o, ci| if (o) |oi| {
        cols[oi] = .{ .name = w.names.items[ci], .type = typeOf(infer.masks.items[ci], opts.parse_dates) };
    };
    for (opts.types) |t| {
        const ci = w.map.get(t.name) orelse return error.NoSuchColumn;
        if (out[ci]) |oi| cols[oi].type = t.type;
    }
    for (cols, types) |c, *t| t.* = c.type;

    const builders = try a.alloc(ColBuilder, nsel);
    const text_cap = if (nsel == 0) 0 else bytes.len / nsel + 1;
    for (builders) |*b| b.* = .{ .a = a, .hint = rows, .text_cap = text_cap };
    var fill: Fill = .{ .out = out, .types = types, .builders = builders };
    w.startPass(false);
    try w.walk(bytes, shape, &fill);

    const data = try a.alloc(frame_mod.ColumnData, nsel);
    for (builders, data) |*b, *d| {
        while (b.len < rows) try b.appendNull();
        d.* = b.finish();
    }
    return .{ .columns = cols, .data = data, .len = rows };
}
