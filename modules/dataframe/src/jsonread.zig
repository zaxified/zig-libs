// SPDX-License-Identifier: MIT
//! A `Frame` from JSON text, the reverse of `jsonio`: `records` (`[{"a":1,"b":"x"},...]`,
//! pandas `read_json(orient="records")`, polars `read_json`), `columns`
//! (`{"a":[1,2],"b":["x","y"]}`, pandas `orient="list"` as `DataFrame(dict)` reads it) and
//! ndjson (one object per line, pandas `lines=True`, polars `read_ndjson`).
//!
//! Two passes over the bytes through `std.json.Scanner`: the first finds the columns, in
//! the order their keys first appear, and the shape of the values each holds (a tree: the
//! column, its arrays' elements, its objects' fields, down to `max_nesting_depth`); the
//! second stores the cells straight into typed arrays. A scalar's type follows the CSV
//! reader's rules on the same text, so a number in JSON reads as the same number in CSV
//! (`csvio.parseAs` does both):
//!
//! - only integers that fit i64: `int`; integers and other numbers: `float`; an integer past
//!   i64 makes the column `text` (a float would lose its digits, as in `readCsv`);
//! - only `true`/`false`: `bool`;
//! - only strings: `text`, or with `parse_dates` `date` (every one `YYYY-MM-DD`) or
//!   `timestamp` (every one another ISO 8601 instant, zone applied, UTC);
//! - no value but `null` (or the key never there): `text`, as `readCsv`;
//! - only arrays: `list`, its elements typed by these same rules over all of them; only
//!   objects: `struct`, one field per key any of them has (null where an object lacks it),
//!   each typed by these rules (polars builds the same columns; pandas keeps Python objects);
//! - anything else, a mix of kinds (arrays and objects included): `text`, each cell written
//!   as its source — a number's digits as they stand, `true`/`false`, a nested value's
//!   JSON text, so nothing is lost. The same at every level: a list of `1` and `"x"` is a
//!   list of text. An array or object `max_nesting_depth` levels down is its JSON text.
//!
//! A key missing from a record is null in that row (both engines). A key repeated in one
//! object, at any depth, is `error.BadJson` by default (`duplicate_keys = .reject`, as
//! `jsonshape`: two parsers of one feed can disagree on it); `.last` keeps its last value
//! (Python's `json`, so pandas). In `columns` every array must be as long as the others
//! (`error.RaggedColumns`, both engines refuse).
//!
//! JSONPath, projection of deep documents and `json_normalize`-style flattening are not
//! here: they are `jsonshape`'s (RFC 9535 queries, column key paths, depth and work limits).

const std = @import("std");
const value = @import("value.zig");
const frame_mod = @import("frame.zig");
const csvio = @import("csvio.zig");
const catfn = @import("catfn.zig");
const textio = @import("textio.zig");
const jsonio = @import("jsonio.zig");

const Frame = frame_mod.Frame;
const ColBuilder = frame_mod.ColBuilder;
const Column = value.Column;
const ColumnType = value.ColumnType;
const Value = value.Value;
const Scanner = std.json.Scanner;

/// The document shapes `readJson` reads (pandas `read_json(orient=)`). The index the
/// index-carrying shapes hold is dropped: a frame has none (pandas would make it the
/// frame's index, which `orient="records"` never has either).
pub const JsonReadOrient = enum {
    /// `[{"a":1},...]`.
    records,
    /// `{"a":[1,2],...}` (pandas `list`).
    columns,
    /// `{"columns":["a","b"],"index":[...],"data":[[1,"x"],...]}`; `index` is ignored. A row
    /// longer than `columns` is `error.BadShape`.
    split,
    /// `{"0":{"a":1},"1":{...}}`: the keys are dropped, the values are records.
    index,
    /// `[[1,"x"],...]`: no names, so the columns are `column_0`, `column_1`... (polars' names
    /// for a file without a header; pandas numbers them).
    values,
    /// pandas' Table Schema (`{"schema":{...},"data":[{"index":0,"a":1},...]}`): the
    /// `primaryKey` columns are dropped (they are the index), the rest read as `records`. The
    /// field types of the schema are not applied (a `datetime` field reads as text, or as a
    /// timestamp with `parse_dates`).
    table,
};

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
    /// More than `max_columns` distinct key paths: columns, the fields of their objects and
    /// the elements of their arrays, at every level, counted together.
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
    /// or bool; a nested value as text (its source) or as the `list`/`struct` it is.
    types: []const csvio.TypeOverride = &.{},
    /// Columns held as a fixed category list (`CsvReadOptions.enums`): the dictionary is the
    /// list, in its order; a value outside it is `error.BadValue`.
    enums: []const catfn.EnumDecl = &.{},
    /// Off: every column of scalars is still typed, strings stay text. On: see the module doc.
    parse_dates: bool = false,
    /// Stop after this many rows (pandas `nrows`, polars `n_rows`). The rest must still be JSON.
    n_rows: ?usize = null,
    max_bytes: usize = csvio.default_max_bytes,
    max_columns: usize = 1 << 16,
    max_cell_bytes: usize = 1 << 20,
    max_rows: usize = 1 << 26,
    max_cells: usize = 1 << 26,
    /// An object repeating a key, at any depth. `.reject` (`error.BadJson`) is the safe
    /// reading, as `jsonshape`'s default: two parsers of one feed can disagree on it.
    /// `.last` keeps the last value (Python's `json`, so pandas; RFC 8259 leaves it open).
    duplicate_keys: DuplicateKeys = .reject,
    /// Columns holding epoch integers, read as `timestamp` (pandas `convert_dates=[...]`; its
    /// automatic guess by column name is not done). Every cell must be an integer or null,
    /// else `error.BadValue`; the unit is `date_unit`.
    epoch_dates: []const []const u8 = &.{},
    /// The unit of `epoch_dates` numbers (pandas `date_unit`, whose default is `ms`).
    date_unit: jsonio.JsonDateUnit = .ms,
    /// Columns holding a length of time as an integer count of `date_unit`, read as `duration`
    /// (pandas writes a `timedelta64` as epoch milliseconds, `date_unit` default `ms`, and
    /// reads it back with `dtype="timedelta64[ms]"`; polars `write_json` has no duration
    /// number form). Every cell must be an integer or null, else `error.BadValue`. A column
    /// named both here and in `epoch_dates` is a duration.
    epoch_durations: []const []const u8 = &.{},
};

pub const DuplicateKeys = enum { reject, last };

/// One JSON document as a frame, in `opts.orient`. `[]` and `{}` are a frame of no columns.
/// The result copies what it needs from `bytes`; `a` is meant to be an arena (the frame
/// rule), and the scratch of the read stays in it.
pub fn readJson(a: std.mem.Allocator, bytes: []const u8, opts: JsonReadOptions) JsonReadError!Frame {
    const shape: Shape = switch (opts.orient) {
        .records => .records,
        .columns => .columns,
        .split => .split,
        .index => .index,
        .values => .values,
        .table => .table,
    };
    for (opts.epoch_dates) |d| for (opts.epoch_durations) |u| if (std.mem.eql(u8, d, u)) return error.BadValue;
    var o = opts;
    // Epoch columns are read as int and converted below.
    var types: std.ArrayList(csvio.TypeOverride) = .empty;
    if (opts.enums.len != 0) o.types = try csvio.enumTypes(a, opts.enums, opts.types);
    if (opts.epoch_dates.len != 0 or opts.epoch_durations.len != 0) {
        try types.appendSlice(a, o.types);
        for (opts.epoch_dates) |n| try types.append(a, .{ .name = n, .type = .int });
        for (opts.epoch_durations) |n| try types.append(a, .{ .name = n, .type = .int });
        o.types = types.items;
    }
    var f = try applyEnums(a, try encodeRead(a, try read(a, bytes, o, shape)), opts.enums);
    if (opts.orient == .table) f = try dropPrimaryKey(a, bytes, f, opts);
    if (opts.epoch_dates.len != 0) f = try epochToTimestamps(a, f, opts.epoch_dates, .timestamp, opts.date_unit);
    if (opts.epoch_durations.len != 0) f = try epochToTimestamps(a, f, opts.epoch_durations, .duration, opts.date_unit);
    return f;
}

/// The columns the Table Schema's `primaryKey` names, removed.
fn dropPrimaryKey(a: std.mem.Allocator, bytes: []const u8, f: Frame, opts: JsonReadOptions) JsonReadError!Frame {
    var sc = Scanner.initCompleteInput(a, bytes);
    defer sc.deinit();
    var pk: std.ArrayList([]const u8) = .empty;
    if (try peek(&sc) != .object_begin) return error.BadShape;
    _ = try next(&sc);
    while (try nextKey(a, &sc, opts.max_cell_bytes)) |key| {
        if (!std.mem.eql(u8, key, "schema") or try peek(&sc) != .object_begin) {
            sc.skipValue() catch |e| return jsonErr(e);
            continue;
        }
        _ = try next(&sc);
        while (try nextKey(a, &sc, opts.max_cell_bytes)) |k2| {
            if (!std.mem.eql(u8, k2, "primaryKey") or try peek(&sc) != .array_begin) {
                sc.skipValue() catch |e| return jsonErr(e);
                continue;
            }
            _ = try next(&sc);
            while (try peek(&sc) != .array_end) {
                switch (try readScalar(a, &sc, opts.max_cell_bytes)) {
                    .string => |n| try pk.append(a, n),
                    else => return error.BadShape,
                }
            }
            _ = try next(&sc);
        }
    }
    if (pk.items.len == 0) return f;
    const cols = try a.alloc(Column, f.columns.len);
    const data = try a.alloc(frame_mod.ColumnData, f.columns.len);
    var n: usize = 0;
    for (f.columns, 0..) |c, i| {
        var drop = false;
        for (pk.items) |k| drop = drop or std.mem.eql(u8, k, c.name);
        if (drop) continue;
        cols[n] = c;
        data[n] = if (i < f.data.len) f.data[i] else .nulls;
        n += 1;
    }
    return .{ .columns = cols[0..n], .data = data[0..n], .len = f.len };
}

/// The int columns `names` as `ty` (timestamps or durations, microseconds), counted in `unit`.
fn epochToTimestamps(a: std.mem.Allocator, f: Frame, names: []const []const u8, ty: ColumnType, unit: jsonio.JsonDateUnit) JsonReadError!Frame {
    const cols = try a.dupe(Column, f.columns);
    const data = try a.dupe(frame_mod.ColumnData, f.data);
    for (names) |n| {
        const ci = f.columnIndex(n) orelse continue;
        switch (data[ci]) {
            .int => |t| {
                const vals = try a.alloc(i64, t.values.len);
                for (vals, t.values) |*o, v| o.* = switch (unit) {
                    .s => std.math.mul(i64, v, 1_000_000) catch return error.BadValue,
                    .ms => std.math.mul(i64, v, 1000) catch return error.BadValue,
                    .us => v,
                    .ns => @divFloor(v, 1000),
                };
                data[ci] = .{ .int = .{ .values = vals, .valid = t.valid } };
                cols[ci].type = ty;
            },
            // All null (no storage): still a timestamp column.
            .nulls => cols[ci].type = ty,
            else => return error.BadValue,
        }
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// A read frame with its `.categorical` columns (`types` names them) encoded.
fn encodeRead(a: std.mem.Allocator, f: Frame) JsonReadError!Frame {
    return frame_mod.encodeDeclared(a, f) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooLarge => error.TooManyRows,
    };
}

fn applyEnums(a: std.mem.Allocator, f: Frame, decls: []const catfn.EnumDecl) JsonReadError!Frame {
    return catfn.applyEnums(a, f, decls) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooLarge => error.TooManyRows,
        error.BadValue => error.BadValue,
    };
}

/// One object per line (`\n`, a `\r` before it allowed); blank lines are skipped (both
/// engines). An empty input is a frame of no columns.
pub fn readNdjson(a: std.mem.Allocator, bytes: []const u8, opts: JsonReadOptions) JsonReadError!Frame {
    var o = opts;
    if (opts.enums.len != 0) o.types = try csvio.enumTypes(a, opts.enums, opts.types);
    return applyEnums(a, try encodeRead(a, try read(a, bytes, o, .lines)), opts.enums);
}

const Shape = enum { records, columns, lines, split, index, values, table };

const Tok = union(enum) {
    null,
    bool: bool,
    number: []const u8,
    string: []const u8,
    /// An object or array value, as its JSON source text.
    nested: []const u8,
};

const m_int: u16 = 1;
const m_float: u16 = 2;
const m_big: u16 = 4; // a number `parseAs` reads as neither int nor float
const m_bool: u16 = 8;
const m_str: u16 = 16;
const m_not_date: u16 = 64; // a string that is not an ISO date
const m_not_stamp: u16 = 128; // a string that is not an ISO instant
const m_list: u16 = 256;
const m_obj: u16 = 512;

/// The kind bits of a scalar token (`.nested` is the caller's: it walks the value).
fn kindOf(t: Tok, parse_dates: bool) u16 {
    return switch (t) {
        .null, .nested => 0,
        .bool => m_bool,
        // An integer that does not fit i64 is text, as in `readCsv` (a float loses digits).
        .number => |s| if (textio.isIntGrammar(s))
            (if (csvio.parseAs(.int, s) != null) m_int else m_big)
        else if (csvio.parseAs(.float, s) != null) m_float else m_big,
        .string => |s| if (!parse_dates) m_str else m_str |
            (if (csvio.parseAs(.date, s) != null) 0 else m_not_date) |
            (if (value.parseIsoTimestamp(s) != null) 0 else m_not_stamp),
    };
}

fn typeOf(mask: u16, parse_dates: bool) ColumnType {
    const kinds = mask & (m_int | m_float | m_big | m_bool | m_str | m_list | m_obj);
    if (kinds == 0) return .text;
    if (kinds == m_list) return .list;
    if (kinds == m_obj) return .@"struct";
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
    /// `values`: the generated names `column_0`...; `split`: the `columns` array.
    gen: std.ArrayList([]const u8) = .empty,
    split_names: ?[]const []const u8 = null,

    fn limitRows(w: *const Walk) usize {
        return w.opts.n_rows orelse std.math.maxInt(usize);
    }

    /// The column of `key`; in discovery a new key is a new column.
    fn column(w: *Walk, key: []const u8) JsonReadError!struct { ci: usize, new: bool } {
        if (!w.discover) return .{ .ci = w.map.get(key) orelse return error.BadJson, .new = false }; // discovery saw every key
        const gop = try w.map.getOrPut(w.a, key);
        if (gop.found_existing) return .{ .ci = gop.value_ptr.*, .new = false };
        if (w.names.items.len >= w.opts.max_columns) return error.TooManyColumns;
        // The key may be a slice of the caller's bytes: the frame keeps its own copy.
        const name = try w.a.dupe(u8, key);
        gop.key_ptr.* = name;
        gop.value_ptr.* = w.names.items.len;
        try w.names.append(w.a, name);
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
            .index => {
                var sc = Scanner.initCompleteInput(w.a, bytes);
                defer sc.deinit();
                if (try peek(&sc) != .object_begin) return error.BadShape;
                _ = try next(&sc);
                while (try nextKey(w.a, &sc, w.opts.max_cell_bytes)) |_| {
                    if (w.rows >= w.limitRows()) {
                        sc.skipValue() catch |e| return jsonErr(e);
                        continue;
                    }
                    try w.record(&sc, pass);
                }
                if (try peek(&sc) != .end_of_document) return error.BadJson;
            },
            .values => {
                var sc = Scanner.initCompleteInput(w.a, bytes);
                defer sc.deinit();
                if (try peek(&sc) != .array_begin) return error.BadShape;
                _ = try next(&sc);
                while (try peek(&sc) != .array_end) {
                    if (w.rows >= w.limitRows()) {
                        sc.skipValue() catch |e| return jsonErr(e);
                        continue;
                    }
                    try w.rowArray(&sc, pass, null);
                }
                _ = try next(&sc);
                if (try peek(&sc) != .end_of_document) return error.BadJson;
            },
            .split => try w.splitDoc(bytes, pass),
            .table => {
                var sc = Scanner.initCompleteInput(w.a, bytes);
                defer sc.deinit();
                if (try peek(&sc) != .object_begin) return error.BadShape;
                _ = try next(&sc);
                var seen = false;
                while (try nextKey(w.a, &sc, w.opts.max_cell_bytes)) |key| {
                    if (seen or !std.mem.eql(u8, key, "data")) {
                        sc.skipValue() catch |e| return jsonErr(e);
                        continue;
                    }
                    seen = true;
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
                }
                if (!seen or try peek(&sc) != .end_of_document) return error.BadShape;
            },
        }
    }

    /// The generated name of column `i` (`values`).
    fn genName(w: *Walk, i: usize) JsonReadError![]const u8 {
        if (i >= w.opts.max_columns) return error.TooManyColumns;
        while (w.gen.items.len <= i) try w.gen.append(w.a, try std.fmt.allocPrint(w.a, "column_{d}", .{w.gen.items.len}));
        return w.gen.items[i];
    }

    /// One array as one row: element `i` is the column `names[i]` (`split`), or `column_i`.
    fn rowArray(w: *Walk, sc: *Scanner, pass: anytype, names: ?[]const []const u8) JsonReadError!void {
        if (try peek(sc) != .array_begin) return error.BadShape;
        _ = try next(sc);
        if (w.rows >= w.opts.max_rows) return error.TooManyRows;
        const row = w.rows;
        w.rec.clearRetainingCapacity();
        var i: usize = 0;
        while (try peek(sc) != .array_end) : (i += 1) {
            const key = if (names) |n| (if (i < n.len) n[i] else return error.BadShape) else try w.genName(i);
            const col = try w.column(key);
            const tok = try readTok(w.a, sc, w.opts.max_cell_bytes);
            w.stamp.items[col.ci] = row + 1;
            w.slot.items[col.ci] = w.rec.items.len;
            try w.rec.append(w.a, .{ .ci = col.ci, .tok = tok });
        }
        _ = try next(sc);
        for (w.rec.items) |c| try pass.cell(row, c.ci, c.tok);
        w.rows += 1;
    }

    /// `split`: the `columns` array first (found by its own scan, whatever the key order),
    /// then the rows of `data`.
    fn splitDoc(w: *Walk, bytes: []const u8, pass: anytype) JsonReadError!void {
        if (w.split_names == null) {
            var sc = Scanner.initCompleteInput(w.a, bytes);
            defer sc.deinit();
            if (try peek(&sc) != .object_begin) return error.BadShape;
            _ = try next(&sc);
            var names: std.ArrayList([]const u8) = .empty;
            var found = false;
            while (try nextKey(w.a, &sc, w.opts.max_cell_bytes)) |key| {
                if (found or !std.mem.eql(u8, key, "columns")) {
                    sc.skipValue() catch |e| return jsonErr(e);
                    continue;
                }
                found = true;
                if (try peek(&sc) != .array_begin) return error.BadShape;
                _ = try next(&sc);
                while (try peek(&sc) != .array_end) {
                    if (names.items.len >= w.opts.max_columns) return error.TooManyColumns;
                    switch (try readScalar(w.a, &sc, w.opts.max_cell_bytes)) {
                        .string => |n| try names.append(w.a, try w.a.dupe(u8, n)),
                        else => return error.BadShape,
                    }
                }
                _ = try next(&sc);
            }
            if (!found) return error.BadShape;
            for (names.items, 0..) |n, i| for (names.items[0..i]) |m| if (std.mem.eql(u8, n, m)) return error.BadShape;
            w.split_names = names.items;
        }
        const names = w.split_names.?;
        // The columns exist even when `data` has no rows.
        if (w.discover) {
            for (names) |n| _ = try w.column(n);
        }
        var sc = Scanner.initCompleteInput(w.a, bytes);
        defer sc.deinit();
        if (try peek(&sc) != .object_begin) return error.BadShape;
        _ = try next(&sc);
        var seen = false;
        while (try nextKey(w.a, &sc, w.opts.max_cell_bytes)) |key| {
            if (seen or !std.mem.eql(u8, key, "data")) {
                sc.skipValue() catch |e| return jsonErr(e);
                continue;
            }
            seen = true;
            if (try peek(&sc) != .array_begin) return error.BadShape;
            _ = try next(&sc);
            while (try peek(&sc) != .array_end) {
                if (w.rows >= w.limitRows()) {
                    sc.skipValue() catch |e| return jsonErr(e);
                    continue;
                }
                try w.rowArray(&sc, pass, names);
            }
            _ = try next(&sc);
        }
        if (try peek(&sc) != .end_of_document) return error.BadJson;
    }

    /// One object as one row.
    fn record(w: *Walk, sc: *Scanner, pass: anytype) JsonReadError!void {
        if (try peek(sc) != .object_begin) return error.BadShape;
        _ = try next(sc);
        if (w.rows >= w.opts.max_rows) return error.TooManyRows;
        const row = w.rows;
        w.rec.clearRetainingCapacity();
        while (true) {
            const key = try nextKey(w.a, sc, w.opts.max_cell_bytes) orelse break;
            const col = try w.column(key);
            const tok = try readTok(w.a, sc, w.opts.max_cell_bytes);
            if (w.stamp.items[col.ci] == row + 1) {
                if (w.opts.duplicate_keys == .reject) return error.BadJson;
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
        while (try nextKey(w.a, &sc, w.opts.max_cell_bytes)) |key| : (ord += 1) {
            const col = try w.column(key);
            if (w.discover) {
                if (!col.new) {
                    if (w.opts.duplicate_keys == .reject) return error.BadJson;
                    try pass.reset(col.ci); // a repeated key: its last array wins
                }
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
                try pass.cell(i, col.ci, try readTok(w.a, &sc, w.opts.max_cell_bytes));
            }
            _ = try next(&sc);
            w.col_len.items[col.ci] = i;
        }
        if (try peek(&sc) != .end_of_document) return error.BadJson;
        const lens = w.col_len.items;
        for (lens) |l| if (l != lens[0]) return error.RaggedColumns;
        w.rows = if (lens.len == 0) 0 else @min(lens[0], w.limitRows());
    }
};

fn capped(s: []const u8, max: usize) JsonReadError![]const u8 {
    return if (s.len > max) error.CellTooLarge else s;
}

/// The next key of an object, or null at its end.
fn nextKey(a: std.mem.Allocator, sc: *Scanner, max: usize) JsonReadError!?[]const u8 {
    const t = sc.nextAllocMax(a, .alloc_if_needed, max) catch |e| return jsonErr(e);
    return switch (t) {
        .object_end => null,
        // `nextAllocMax` caps only what it has to copy; a plain string is a slice.
        .string => |s| try capped(s, max),
        .allocated_string => |s| s,
        else => error.BadJson, // the scanner gives only keys or the end here
    };
}

/// The next value: a scalar, or an object/array as its source text.
fn readTok(a: std.mem.Allocator, sc: *Scanner, max: usize) JsonReadError!Tok {
    switch (try peek(sc)) {
        .object_begin, .array_begin => {
            // `peek` skipped the blanks: the cursor is at the opening bracket.
            const start = sc.cursor;
            sc.skipValue() catch |e| return jsonErr(e);
            const text = sc.input[start..sc.cursor];
            if (text.len > max) return error.CellTooLarge;
            return .{ .nested = text };
        },
        else => return readScalar(a, sc, max),
    }
}

fn readScalar(a: std.mem.Allocator, sc: *Scanner, max: usize) JsonReadError!Tok {
    const t = sc.nextAllocMax(a, .alloc_if_needed, max) catch |e| return jsonErr(e);
    return switch (t) {
        .null => .null,
        .true => .{ .bool = true },
        .false => .{ .bool = false },
        .number => |s| .{ .number = try capped(s, max) },
        .allocated_number => |s| .{ .number = s },
        .string => |s| .{ .string = try capped(s, max) },
        .allocated_string => |s| .{ .string = s },
        else => error.BadJson, // a value was peeked; the end tokens are not values
    };
}

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

const no_node = std.math.maxInt(u32);

/// What pass 1 learns about one position in the columns' values: a column, the elements
/// of its lists, a field of its objects, and so on down. A tree (one node per path).
const Node = struct {
    mask: u16 = 0,
    /// An array or object seen `max_nesting_depth` levels down: the node is text.
    deep: bool = false,
    /// A key repeated in one object here (with `duplicate_keys = .last`).
    dup: bool = false,
    /// The node of the elements of its arrays.
    elem: u32 = no_node,
    /// Elements of all its arrays.
    elems: usize = 0,
    /// Its objects' keys, in first-seen order, and their nodes.
    names: std.ArrayList([]const u8) = .empty,
    fields: std.ArrayList(u32) = .empty,
    map: std.StringHashMapUnmanaged(u32) = .empty,
    /// Per field: the object it was last set in (repeats and gaps).
    stamp: std.ArrayList(u64) = .empty,

    fn ty(n: Node, parse_dates: bool) ColumnType {
        return if (n.deep) .text else typeOf(n.mask, parse_dates);
    }
};

/// Pass 1: what each column holds.
const Infer = struct {
    a: std.mem.Allocator,
    opts: *const JsonReadOptions,
    nodes: std.ArrayList(Node) = .empty,
    /// Per input column: its node.
    roots: std.ArrayList(u32) = .empty,
    seq: u64 = 0,

    /// Columns and the fields under them count against `max_columns` together: each is a
    /// node of pass 1 and a builder of pass 2, so a document of many distinct key paths is
    /// refused before it costs memory (review M1).
    fn newNode(p: *Infer) JsonReadError!u32 {
        if (p.nodes.items.len >= p.opts.max_columns) return error.TooManyColumns;
        try p.nodes.append(p.a, .{});
        return @intCast(p.nodes.items.len - 1);
    }

    fn grow(p: *Infer, ci: usize) JsonReadError!void {
        while (p.roots.items.len <= ci) try p.roots.append(p.a, try p.newNode());
    }

    fn cell(p: *Infer, row: usize, ci: usize, t: Tok) JsonReadError!void {
        _ = row;
        try p.grow(ci);
        const ni = p.roots.items[ci];
        switch (t) {
            .nested => |text| {
                var sc = Scanner.initCompleteInput(p.a, text);
                defer sc.deinit();
                try p.scan(ni, &sc, 0);
            },
            else => p.nodes.items[ni].mask |= kindOf(t, p.opts.parse_dates),
        }
    }

    fn reset(p: *Infer, ci: usize) JsonReadError!void {
        if (ci < p.roots.items.len) p.roots.items[ci] = try p.newNode();
    }

    /// The field `key` of node `ni`, a new one the first time.
    fn field(p: *Infer, ni: u32, key: []const u8) JsonReadError!u32 {
        if (p.nodes.items[ni].map.get(key)) |k| return k;
        if (p.nodes.items[ni].names.items.len >= p.opts.max_columns) return error.TooManyColumns;
        const child = try p.newNode();
        const name = try p.a.dupe(u8, key); // not the caller's bytes (review M3)
        const n = &p.nodes.items[ni];
        const k: u32 = @intCast(n.names.items.len);
        try n.map.put(p.a, name, k);
        try n.names.append(p.a, name);
        try n.fields.append(p.a, child);
        try n.stamp.append(p.a, 0);
        return k;
    }

    /// The next value in `sc`, `depth` levels below its column, into node `ni`.
    fn scan(p: *Infer, ni: u32, sc: *Scanner, depth: u8) JsonReadError!void {
        const tt = try peek(sc);
        if (tt != .array_begin and tt != .object_begin) {
            const t = try readScalar(p.a, sc, p.opts.max_cell_bytes);
            p.nodes.items[ni].mask |= kindOf(t, p.opts.parse_dates);
            return;
        }
        if (depth >= value.max_nesting_depth) {
            p.nodes.items[ni].deep = true;
            sc.skipValue() catch |e| return jsonErr(e);
            return;
        }
        _ = try next(sc);
        if (tt == .array_begin) {
            p.nodes.items[ni].mask |= m_list;
            if (p.nodes.items[ni].elem == no_node) {
                const e = try p.newNode();
                p.nodes.items[ni].elem = e;
            }
            const e = p.nodes.items[ni].elem;
            while (try peek(sc) != .array_end) {
                p.nodes.items[ni].elems += 1;
                try p.scan(e, sc, depth + 1);
            }
            _ = try next(sc);
            return;
        }
        p.nodes.items[ni].mask |= m_obj;
        p.seq += 1;
        const seq = p.seq;
        while (try nextKey(p.a, sc, p.opts.max_cell_bytes)) |key| {
            const k = try p.field(ni, key);
            const n = &p.nodes.items[ni];
            if (n.stamp.items[k] == seq) {
                if (p.opts.duplicate_keys == .reject) return error.BadJson;
                n.dup = true;
            }
            n.stamp.items[k] = seq;
            try p.scan(n.fields.items[k], sc, depth + 1);
        }
    }

    /// The cells under node `ni` read as `ty`, `slots` times: itself, its lists' elements,
    /// its objects' fields (a field has a cell in every row of its struct, null included).
    fn cells(p: *const Infer, ni: u32, ty: ColumnType, slots: usize) usize {
        const n = p.nodes.items[ni];
        var t = slots;
        switch (ty) {
            .list => if (n.elem != no_node) {
                t +|= p.cells(n.elem, p.nodes.items[n.elem].ty(p.opts.parse_dates), n.elems);
            },
            .@"struct" => for (n.fields.items) |f| {
                t +|= p.cells(f, p.nodes.items[f].ty(p.opts.parse_dates), slots);
            },
            else => {},
        }
        return t;
    }

    /// The column node `ni` declares, read as `ty`.
    fn schema(p: *const Infer, ni: u32, name: []const u8, ty: ColumnType) JsonReadError!Column {
        const n = p.nodes.items[ni];
        var inner: []Column = &.{};
        switch (ty) {
            .list => if (n.elem != no_node) {
                inner = try p.a.alloc(Column, 1);
                inner[0] = try p.schema(n.elem, "item", p.nodes.items[n.elem].ty(p.opts.parse_dates));
            },
            .@"struct" => {
                inner = try p.a.alloc(Column, n.fields.items.len);
                for (inner, n.fields.items, n.names.items) |*c, f, nm| c.* = try p.schema(f, nm, p.nodes.items[f].ty(p.opts.parse_dates));
            },
            else => {},
        }
        return .{ .name = name, .type = ty, .inner = inner };
    }
};

/// Pass 2's builder of one node: a leaf column, or a list or struct over its children.
const Builder = struct {
    kind: enum { leaf, list, record } = .leaf,
    ty: ColumnType = .text,
    leaf: ColBuilder = undefined,
    len: usize = 0,
    nulls: usize = 0,
    valid: std.ArrayList(u64) = .empty,
    /// `.list`: the end offset of every row so far (starting with 0), elements so far.
    offsets: std.ArrayList(u32) = .empty,
    count: usize = 0,

    fn rows(b: *const Builder) usize {
        return if (b.kind == .leaf) b.leaf.len else b.len;
    }
};

/// Pass 2: the cells into their columns.
const Fill = struct {
    a: std.mem.Allocator,
    opts: *const JsonReadOptions,
    nodes: []Node,
    /// Per input column: its output column, or null when not read.
    out: []const ?usize,
    /// Per output column: its node.
    roots: []const u32,
    /// Per node (those under a read column).
    b: []Builder,
    seq: u64 = 0,
    /// Per node, `.last` only: the ordinal of each field's last key in the object read.
    last: std.ArrayList(u32) = .empty,

    /// Builders for node `ni` read as `ty`, and below it.
    fn init(p: *Fill, ni: u32, ty: ColumnType, hint: usize, text_cap: usize) JsonReadError!void {
        const n = p.nodes[ni];
        const pd = p.opts.parse_dates;
        switch (ty) {
            .list => {
                p.b[ni] = .{ .kind = .list, .ty = ty };
                try p.b[ni].offsets.append(p.a, 0);
                if (n.elem != no_node) try p.init(n.elem, p.nodes[n.elem].ty(pd), 0, 1 << 20);
            },
            .@"struct" => {
                p.b[ni] = .{ .kind = .record, .ty = ty };
                // The column's share of the input is its fields' to share (review M2).
                const share = text_cap / @max(1, n.fields.items.len);
                for (n.fields.items) |f| try p.init(f, p.nodes[f].ty(pd), hint, share);
            },
            else => p.b[ni] = .{ .ty = ty, .leaf = .{ .a = p.a, .hint = hint, .text_cap = text_cap } },
        }
    }

    fn cell(p: *Fill, row: usize, ci: usize, t: Tok) JsonReadError!void {
        const oi = p.out[ci] orelse return;
        const ni = p.roots[oi];
        while (p.b[ni].rows() < row) try p.appendNull(ni);
        switch (p.b[ni].kind) {
            .leaf => try p.b[ni].leaf.append(convert(t, p.b[ni].ty) orelse return error.BadValue),
            .list, .record => switch (t) {
                .null => try p.appendNull(ni),
                .nested => |text| {
                    var sc = Scanner.initCompleteInput(p.a, text);
                    defer sc.deinit();
                    try p.put(ni, &sc, 0);
                },
                else => return error.BadValue, // a nested type (`types`), a scalar cell
            },
        }
    }

    fn reset(p: *Fill, ci: usize) JsonReadError!void {
        _ = p;
        _ = ci;
    }

    fn mark(p: *Fill, ni: u32, present: bool) JsonReadError!void {
        const b = &p.b[ni];
        const w = b.len / 64;
        while (b.valid.items.len <= w) try b.valid.append(p.a, 0);
        if (present) b.valid.items[w] |= @as(u64, 1) << @intCast(b.len % 64) else b.nulls += 1;
        b.len += 1;
    }

    fn appendNull(p: *Fill, ni: u32) JsonReadError!void {
        switch (p.b[ni].kind) {
            .leaf => return p.b[ni].leaf.appendNull(),
            .list => try p.b[ni].offsets.append(p.a, @intCast(p.b[ni].count)),
            .record => for (p.nodes[ni].fields.items) |f| try p.appendNull(f),
        }
        try p.mark(ni, false);
    }

    /// The next value in `sc`, `depth` levels below its column, into node `ni`'s builder.
    fn put(p: *Fill, ni: u32, sc: *Scanner, depth: u8) JsonReadError!void {
        const max = p.opts.max_cell_bytes;
        switch (p.b[ni].kind) {
            .leaf => {
                const t = try readTok(p.a, sc, max);
                return p.b[ni].leaf.append(convert(t, p.b[ni].ty) orelse return error.BadValue);
            },
            .list => switch (try peek(sc)) {
                .null => {
                    _ = try next(sc);
                    return p.appendNull(ni);
                },
                .array_begin => {
                    _ = try next(sc);
                    const e = p.nodes[ni].elem;
                    while (try peek(sc) != .array_end) {
                        if (e == no_node) return error.BadJson; // pass 1 saw this array's elements
                        try p.put(e, sc, depth + 1);
                        p.b[ni].count += 1;
                    }
                    _ = try next(sc);
                    // Arrow's u32 offsets; `max_cells` (2^26) refuses long before.
                    if (p.b[ni].count > std.math.maxInt(u32)) return error.TooManyCells;
                    try p.b[ni].offsets.append(p.a, @intCast(p.b[ni].count));
                    return p.mark(ni, true);
                },
                else => return error.BadValue,
            },
            .record => switch (try peek(sc)) {
                .null => {
                    _ = try next(sc);
                    return p.appendNull(ni);
                },
                .object_begin => return if (p.nodes[ni].dup) p.recordLast(ni, sc, depth) else p.recordOnce(ni, sc, depth),
                else => return error.BadValue,
            },
        }
    }

    fn fieldOf(p: *Fill, ni: u32, key: []const u8) JsonReadError!u32 {
        return p.nodes[ni].map.get(key) orelse error.BadJson; // pass 1 saw every key
    }

    /// Fields not set in the object just read are null in its row.
    fn closeRecord(p: *Fill, ni: u32, seq: u64) JsonReadError!void {
        const n = p.nodes[ni];
        for (n.fields.items, n.stamp.items) |f, st| if (st != seq) try p.appendNull(f);
        try p.mark(ni, true);
    }

    fn recordOnce(p: *Fill, ni: u32, sc: *Scanner, depth: u8) JsonReadError!void {
        _ = try next(sc);
        p.seq += 1;
        const seq = p.seq;
        while (try nextKey(p.a, sc, p.opts.max_cell_bytes)) |key| {
            const k = try p.fieldOf(ni, key);
            if (p.nodes[ni].stamp.items[k] == seq) return error.BadJson; // pass 1 refused or flagged it
            p.nodes[ni].stamp.items[k] = seq;
            try p.put(p.nodes[ni].fields.items[k], sc, depth + 1);
        }
        return p.closeRecord(ni, seq);
    }

    /// An object of a node where some object repeats a key: its keys are read once to find
    /// the last of each, then again for the values (`duplicate_keys = .last`).
    fn recordLast(p: *Fill, ni: u32, sc: *Scanner, depth: u8) JsonReadError!void {
        const start = sc.cursor; // `peek` left it at the brace
        sc.skipValue() catch |e| return jsonErr(e);
        const text = sc.input[start..sc.cursor];
        const nf = p.nodes[ni].fields.items.len;
        const base = p.last.items.len;
        try p.last.appendNTimes(p.a, 0, nf);
        defer p.last.shrinkRetainingCapacity(base);
        {
            var s1 = Scanner.initCompleteInput(p.a, text);
            defer s1.deinit();
            _ = try next(&s1);
            var ord: u32 = 0;
            while (try nextKey(p.a, &s1, p.opts.max_cell_bytes)) |key| : (ord += 1) {
                p.last.items[base + try p.fieldOf(ni, key)] = ord;
                s1.skipValue() catch |e| return jsonErr(e);
            }
        }
        var s2 = Scanner.initCompleteInput(p.a, text);
        defer s2.deinit();
        _ = try next(&s2);
        p.seq += 1;
        const seq = p.seq;
        var ord: u32 = 0;
        while (try nextKey(p.a, &s2, p.opts.max_cell_bytes)) |key| : (ord += 1) {
            const k = try p.fieldOf(ni, key);
            if (p.last.items[base + k] != ord) {
                s2.skipValue() catch |e| return jsonErr(e);
                continue;
            }
            p.nodes[ni].stamp.items[k] = seq;
            try p.put(p.nodes[ni].fields.items[k], &s2, depth + 1);
        }
        return p.closeRecord(ni, seq);
    }

    /// Node `ni`'s storage.
    fn finish(p: *Fill, ni: u32) JsonReadError!frame_mod.ColumnData {
        const b = &p.b[ni];
        const valid: ?[]const u64 = if (b.nulls == 0) null else b.valid.items;
        switch (b.kind) {
            .leaf => return b.leaf.finish(),
            // Every row null: no storage, as `ColBuilder` gives.
            .list, .record => if (b.len == b.nulls) return .nulls,
        }
        const n = p.nodes[ni];
        if (b.kind == .list) {
            const items = try p.a.create(frame_mod.ColumnData);
            items.* = if (n.elem == no_node) .nulls else try p.finish(n.elem);
            return .{ .list = .{ .offsets = b.offsets.items, .items = items, .valid = valid } };
        }
        const children = try p.a.alloc(frame_mod.ColumnData, n.fields.items.len);
        for (children, n.fields.items) |*c, f| c.* = try p.finish(f);
        const st = try p.a.create(frame_mod.StructColumn);
        st.* = .{ .names = n.names.items, .children = children, .len = b.len, .valid = valid };
        return .{ .@"struct" = st };
    }
};

fn read(a: std.mem.Allocator, bytes: []const u8, opts: JsonReadOptions, shape: Shape) JsonReadError!Frame {
    if (bytes.len > opts.max_bytes) return error.InputTooLarge;
    var w: Walk = .{ .a = a, .opts = &opts };
    var infer: Infer = .{ .a = a, .opts = &opts };
    w.startPass(true);
    try w.walk(bytes, shape, &infer);
    const rows = w.rows;
    const width = w.names.items.len;
    if (width > 0) try infer.grow(width - 1);

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

    const types = try a.alloc(ColumnType, nsel);
    const roots = try a.alloc(u32, nsel);
    for (out, 0..) |o, ci| if (o) |oi| {
        roots[oi] = infer.roots.items[ci];
        types[oi] = infer.nodes.items[roots[oi]].ty(opts.parse_dates);
    };
    for (opts.types) |t| {
        const ci = w.map.get(t.name) orelse return error.NoSuchColumn;
        if (out[ci]) |oi| types[oi] = t.type;
    }
    // Every cell the frame will hold, nested levels included, against `max_cells`.
    var cells: usize = 0;
    for (roots, types) |r, t| cells +|= infer.cells(r, t, rows);
    if (cells > opts.max_cells) return error.TooManyCells;

    const cols = try a.alloc(Column, nsel);
    for (out, 0..) |o, ci| if (o) |oi| {
        cols[oi] = try infer.schema(roots[oi], w.names.items[ci], types[oi]);
    };

    const text_cap = if (nsel == 0) 0 else bytes.len / nsel + 1;
    var fill: Fill = .{
        .a = a,
        .opts = &opts,
        .nodes = infer.nodes.items,
        .out = out,
        .roots = roots,
        .b = try a.alloc(Builder, infer.nodes.items.len),
    };
    for (roots, types) |r, t| try fill.init(r, t, rows, text_cap);
    for (infer.nodes.items) |*n| @memset(n.stamp.items, 0);
    w.startPass(false);
    try w.walk(bytes, shape, &fill);

    const data = try a.alloc(frame_mod.ColumnData, nsel);
    for (roots, data) |r, *d| {
        while (fill.b[r].rows() < rows) try fill.appendNull(r);
        d.* = try fill.finish(r);
    }
    return .{ .columns = cols, .data = data, .len = rows };
}
