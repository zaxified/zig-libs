// SPDX-License-Identifier: MIT
//! A `Frame` as JSON text: `records` (`[{"a":1,"b":"x"},...]`, pandas `to_json(orient=
//! "records")`, polars `write_json`), `columns` (`{"a":[1,2],"b":["x","y"]}`, pandas'
//! `orient="list"`, polars' `to_dict(as_series=False)`) and ndjson (one record per line,
//! pandas `lines=True`, polars `write_ndjson`). Compact, no spaces, written to any
//! `std.Io.Writer`; a frame's size is the caller's, nothing is buffered here.
//!
//! The number and string rules are those of `dataset.frameToJson`, which this replaces:
//! integers as digits, NaN and infinities as `null` (both engines), decimals as exact
//! numbers, strings escaped with `\"` `\\` `\n` `\r` `\t` and `\u00XX` for other controls,
//! non-ASCII left as UTF-8 and bytes that are not valid UTF-8 replaced by U+FFFD one
//! at a time, so the document is always valid. Floats go further than `frameToJson`
//! (which printed `1` for 1.0): they keep a fractional digit (`1.0`), as both engines do,
//! so a float column reads back as floats.

const std = @import("std");
const value = @import("value.zig");
const frame_mod = @import("frame.zig");
const textio = @import("textio.zig");

const Frame = frame_mod.Frame;
const Value = value.Value;
const ColumnType = value.ColumnType;

/// The document shapes `writeJson` writes. A frame has no index, so the index-carrying
/// shapes write pandas' default `RangeIndex` (0..n-1) as pandas does for a frame with one.
pub const JsonOrient = enum {
    /// `[{"a":1,"b":"x"},...]` (pandas `records`, polars `write_json`).
    records,
    /// `{"a":[1,2],"b":["x","y"]}` (pandas `list`, polars `to_dict(as_series=False)`).
    columns,
    /// `{"columns":["a","b"],"index":[0,1],"data":[[1,"x"],[2,"y"]]}` (pandas `split`).
    split,
    /// `{"0":{"a":1,"b":"x"},"1":{...}}`, keyed by the row number (pandas `index`).
    index,
    /// `[[1,"x"],[2,"y"]]` (pandas `values`).
    values,
    /// pandas' Table Schema: `{"schema":{"fields":[{"name":"index","type":"integer"},...],
    /// "primaryKey":["index"],"pandas_version":"1.4.0"},"data":[{"index":0,"a":1,...},...]}`.
    /// Field types: `integer`, `number` (floats, decimals), `boolean`, `string` (text,
    /// categorical), `date`, `datetime`, `duration`, `array`, `object`. pandas writes a date
    /// column as `datetime` and a categorical as `any` with an `enum`; here they keep their kind.
    table,
};

pub const JsonError = std.Io.Writer.Error;
/// What `writeJson` returns: the writer's errors, and `BadOptions` for a frame the orient cannot
/// write readably (`.table` of a frame with a column named `index`, which the table's own
/// index field would duplicate; pandas refuses it too).
pub const JsonDocError = JsonError || error{BadOptions};

pub const JsonDateFormat = enum { iso, epoch };
pub const JsonDateUnit = enum { s, ms, us, ns };

pub const JsonWriteOptions = struct {
    /// Escape every non-ASCII character as `\uXXXX` (surrogate pairs past the BMP): pandas'
    /// `force_ascii`, which is *on* by default there; polars never does. Off here, the
    /// existing form (valid UTF-8). Written in this file instead of through `jsontext`'s
    /// `ascii_only`, which would add a module dependency for fifteen lines.
    force_ascii: bool = false,
    /// Round floats to this many decimals and drop trailing zeros but one (pandas
    /// `double_precision`, default 10 there, at most 15; `null` here: the shortest digits
    /// that read back exactly, as both engines' own default).
    double_precision: ?u8 = null,
    /// Spaces per nesting level; pandas' `indent` (`"a":1` without a space after the colon, as
    /// ujson prints it). Compact when null or `0`. Needs the document in memory first:
    /// `max_indent_bytes` caps it (`error.OutputTooLarge`), and `writeJsonOpts`'s allocator holds it.
    indent: ?u8 = null,
    /// Timestamps, dates and durations as RFC 3339 text (the existing form; pandas'
    /// `iso`, which has no zone) or as integers in `date_unit` since the epoch (pandas'
    /// default `epoch`). A duration is then a count of `date_unit`s; a date its midnight UTC.
    date_format: JsonDateFormat = .iso,
    /// pandas `date_unit`, for `date_format = .epoch` (pandas' default `ms`).
    date_unit: JsonDateUnit = .ms,
    max_indent_bytes: usize = 1 << 28,
};

pub const JsonWriteError = JsonDocError || error{ OutOfMemory, OutputTooLarge };

const default_opts: JsonWriteOptions = .{};

/// The whole frame as one JSON document, compact and with the default options.
/// `records` of no rows is `[]`, `columns` of no columns is `{}`.
pub fn writeJson(w: *std.Io.Writer, f: Frame, orient: JsonOrient) JsonDocError!void {
    try writeDoc(w, f, orient, &default_opts);
}

/// `writeJson` with options (pandas `to_json(orient=, force_ascii=, double_precision=,
/// date_format=, date_unit=, indent=)`). `a` is used only for `indent`.
pub fn writeJsonOpts(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, orient: JsonOrient, opts: JsonWriteOptions) JsonWriteError!void {
    const ind = opts.indent orelse 0;
    if (ind == 0) return writeDoc(w, f, orient, &opts);
    var buf: std.Io.Writer.Allocating = .init(a);
    defer buf.deinit();
    // The Allocating writer fails only when it cannot allocate.
    writeDoc(&buf.writer, f, orient, &opts) catch |e| return if (e == error.WriteFailed) error.OutOfMemory else e;
    if (buf.written().len > opts.max_indent_bytes) return error.OutputTooLarge;
    try reindent(w, buf.written(), ind, opts.max_indent_bytes);
}

/// The compact document `src` with one item per line, `step` spaces per level. Strings are
/// copied as they are; an empty `[]` or `{}` stays on one line. The indentation can dwarf the
/// compact text (depth times `step` per line), so the output is counted and past `max`
/// it is `error.OutputTooLarge`, before the next line is written.
fn reindent(w: *std.Io.Writer, src: []const u8, step: u8, max: usize) (JsonError || error{OutputTooLarge})!void {
    var depth: usize = 0;
    var extra: usize = 0; // bytes the layout adds to `src`
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const c = src[i];
        switch (c) {
            '"' => {
                var j = i + 1;
                while (j < src.len and src[j] != '"') j += if (src[j] == '\\') 2 else 1;
                const end = @min(j + 1, src.len);
                try w.writeAll(src[i..end]);
                i = end - 1;
            },
            '{', '[' => {
                const close: u8 = if (c == '{') '}' else ']';
                if (i + 1 < src.len and src[i + 1] == close) {
                    try w.writeByte(c);
                    try w.writeByte(close);
                    i += 1;
                } else {
                    try w.writeByte(c);
                    depth += 1;
                    try newline(w, depth, step, i + extra, &extra, max);
                }
            },
            '}', ']' => {
                depth -|= 1;
                try newline(w, depth, step, i + extra, &extra, max);
                try w.writeByte(c);
            },
            ',' => {
                try w.writeByte(',');
                try newline(w, depth, step, i + extra, &extra, max);
            },
            else => try w.writeByte(c),
        }
    }
    if (src.len + extra > max) return error.OutputTooLarge; // the bytes after the last line break
}

/// A line break and the indent of `depth`; `at` is the output size so far, `extra` the layout's share.
fn newline(w: *std.Io.Writer, depth: usize, step: u8, at: usize, extra: *usize, max: usize) (JsonError || error{OutputTooLarge})!void {
    const add = 1 + depth * step;
    if (at +| add > max) return error.OutputTooLarge;
    extra.* += add;
    try w.writeByte('\n');
    try w.splatByteAll(' ', depth * step);
}

fn writeDoc(w: *std.Io.Writer, f: Frame, orient: JsonOrient, o: *const JsonWriteOptions) JsonDocError!void {
    switch (orient) {
        .records => {
            try w.writeByte('[');
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try writeRecord(w, f, ri, o);
            }
            try w.writeByte(']');
        },
        .columns => {
            try w.writeByte('{');
            for (f.columns, 0..) |c, ci| {
                if (ci != 0) try w.writeByte(',');
                try writeStringA(w, c.name, o.force_ascii);
                try w.writeAll(":[");
                const col = f.columnAt(ci);
                for (0..f.len) |ri| {
                    if (ri != 0) try w.writeByte(',');
                    try writeValueO(w, col.get(ri), c, 0, o);
                }
                try w.writeByte(']');
            }
            try w.writeByte('}');
        },
        .split => {
            try w.writeAll("{\"columns\":[");
            for (f.columns, 0..) |c, ci| {
                if (ci != 0) try w.writeByte(',');
                try writeStringA(w, c.name, o.force_ascii);
            }
            try w.writeAll("],\"index\":[");
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try w.print("{d}", .{ri});
            }
            try w.writeAll("],\"data\":[");
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try writeRow(w, f, ri, o);
            }
            try w.writeAll("]}");
        },
        .index => {
            try w.writeByte('{');
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try w.print("\"{d}\":", .{ri});
                try writeRecord(w, f, ri, o);
            }
            try w.writeByte('}');
        },
        .values => {
            try w.writeByte('[');
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try writeRow(w, f, ri, o);
            }
            try w.writeByte(']');
        },
        .table => {
            for (f.columns) |c| if (std.mem.eql(u8, c.name, "index")) return error.BadOptions;
            try w.writeAll("{\"schema\":{\"fields\":[{\"name\":\"index\",\"type\":\"integer\"}");
            for (f.columns) |c| {
                try w.writeAll(",{\"name\":");
                try writeStringA(w, c.name, o.force_ascii);
                try w.print(",\"type\":\"{s}\"", .{tableType(c.type)});
                // pandas' Table Schema names the zone of a tz-aware column in `tz`.
                if (c.type == .timestamp) if (c.time_zone) |zn| {
                    try w.writeAll(",\"tz\":");
                    try writeStringA(w, zn, o.force_ascii);
                };
                try w.writeByte('}');
            }
            try w.writeAll("],\"primaryKey\":[\"index\"],\"pandas_version\":\"1.4.0\"},\"data\":[");
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try w.print("{{\"index\":{d}", .{ri});
                for (f.columns, 0..) |c, ci| {
                    try w.writeByte(',');
                    try writeStringA(w, c.name, o.force_ascii);
                    try w.writeByte(':');
                    try writeValueO(w, f.columnAt(ci).get(ri), c, 0, o);
                }
                try w.writeByte('}');
            }
            try w.writeAll("]}");
        },
    }
}

fn tableType(t: ColumnType) []const u8 {
    return switch (t) {
        .int => "integer",
        .float, .decimal => "number",
        .bool => "boolean",
        .text, .categorical => "string",
        .date => "date",
        .timestamp => "datetime",
        .duration => "duration",
        .list => "array",
        .@"struct" => "object",
    };
}

fn writeRow(w: *std.Io.Writer, f: Frame, ri: usize, o: *const JsonWriteOptions) JsonError!void {
    try w.writeByte('[');
    for (f.columns, 0..) |c, ci| {
        if (ci != 0) try w.writeByte(',');
        try writeValueO(w, f.columnAt(ci).get(ri), c, 0, o);
    }
    try w.writeByte(']');
}

/// One record per line, each ended by `\n` (the last too).
pub fn writeNdjson(w: *std.Io.Writer, f: Frame) JsonError!void {
    for (0..f.len) |ri| {
        try writeRecord(w, f, ri, &default_opts);
        try w.writeByte('\n');
    }
}

fn writeRecord(w: *std.Io.Writer, f: Frame, ri: usize, o: *const JsonWriteOptions) JsonError!void {
    try w.writeByte('{');
    for (f.columns, 0..) |c, ci| {
        if (ci != 0) try w.writeByte(',');
        try writeStringA(w, c.name, o.force_ascii);
        try w.writeByte(':');
        try writeValueO(w, f.columnAt(ci).get(ri), c, 0, o);
    }
    try w.writeByte('}');
}

/// One cell as JSON. `col` is its declared column (null: none, the cell alone decides):
/// its type writes an int as a timestamp or a duration, and its `inner` columns do the
/// same for a nested value's elements and fields. A list is an array, a record an object
/// with its field names; past `max_nesting_depth` a nested value is `null`.
pub fn writeValue(w: *std.Io.Writer, v0: Value, col: ?value.Column, depth: u8) JsonError!void {
    return writeValueO(w, v0, col, depth, &default_opts);
}

const us_per_day: i64 = 86_400_000_000;

/// A timestamp/date/duration cell (microseconds) in `unit`, floored; null when it overflows.
fn epochIn(us: i64, unit: JsonDateUnit) ?i64 {
    return switch (unit) {
        .s => @divFloor(us, 1_000_000),
        .ms => @divFloor(us, 1000),
        .us => us,
        .ns => std.math.mul(i64, us, 1000) catch null,
    };
}

fn writeValueO(w: *std.Io.Writer, v0: Value, col: ?value.Column, depth: u8, o: *const JsonWriteOptions) JsonError!void {
    const v = Value.capped(v0, depth);
    const ty: ?ColumnType = if (col) |c| c.type else null;
    if (o.date_format == .epoch) {
        // pandas' epoch form: an integer, the unit chosen by `date_unit`.
        const us: ?i64 = switch (v) {
            .int => |i| if (ty == .timestamp or ty == .duration) i else null,
            .text => |t| if (ty == .date) (if (value.parseIsoDate(t)) |d| d.ordinal() * us_per_day else null) else null,
            else => null,
        };
        if (us) |u| {
            if (epochIn(u, o.date_unit)) |e| try w.print("{d}", .{e}) else try w.writeAll("null");
            return;
        }
    }
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| if (ty == .timestamp) {
            var tb: [textio.max_stamp_len]u8 = undefined;
            try writeStringA(w, textio.formatIsoZoned(&tb, i, textio.zoneOf(if (col) |c| c.time_zone else null)), o.force_ascii);
        } else if (ty == .duration) {
            var ub: [value.max_duration_len]u8 = undefined;
            try writeStringA(w, value.formatIsoDuration(&ub, i), o.force_ascii);
        } else try w.print("{d}", .{i}),
        .float => |x| if (std.math.isFinite(x)) {
            var fb: [textio.max_float_len]u8 = undefined;
            if (o.double_precision) |p| {
                var big: [400]u8 = undefined;
                const t = textio.formatFloatFixed(&big, x, @min(p, 15));
                var end = t.len;
                if (std.mem.findScalar(u8, t, '.')) |dot| {
                    while (end > dot + 2 and t[end - 1] == '0') end -= 1;
                    try w.writeAll(t[0..end]);
                    if (end == dot + 1) try w.writeByte('0');
                } else {
                    try w.writeAll(t);
                    try w.writeAll(".0");
                }
            } else try w.writeAll(textio.formatFloat(&fb, x));
        } else try w.writeAll("null"),
        .decimal => |r| {
            var db: [textio.max_decimal_len]u8 = undefined;
            try w.writeAll(textio.formatDecimal(&db, r));
        },
        .text => |t| try writeStringA(w, t, o.force_ascii),
        .list => |l| {
            const elem: ?value.Column = if (col) |c| c.innerAt(0, "") else null;
            try w.writeByte('[');
            for (0..l.len()) |i| {
                if (i != 0) try w.writeByte(',');
                try writeValueO(w, l.get(i), elem, depth + 1, o);
            }
            try w.writeByte(']');
        },
        .record => |r| {
            try w.writeByte('{');
            for (0..r.len()) |i| {
                if (i != 0) try w.writeByte(',');
                try writeStringA(w, r.name(i), o.force_ascii);
                try w.writeByte(':');
                try writeValueO(w, r.get(i), if (col) |c| c.innerAt(i, r.name(i)) else null, depth + 1, o);
            }
            try w.writeByte('}');
        },
    }
}

/// `s` as a JSON string. Invalid UTF-8 is replaced byte by byte with U+FFFD.
pub fn writeString(w: *std.Io.Writer, s: []const u8) JsonError!void {
    return writeStringA(w, s, false);
}

/// `writeString`; with `ascii`, every non-ASCII character is `\uXXXX` (a surrogate pair
/// past the BMP), a byte that is not valid UTF-8 `\ufffd`.
pub fn writeStringA(w: *std.Io.Writer, s: []const u8, ascii: bool) JsonError!void {
    try w.writeByte('"');
    var i: usize = 0;
    var run: usize = 0; // start of the bytes not written yet
    while (i < s.len) {
        const ch = s[i];
        if (ch < 0x80) {
            const esc: ?[]const u8 = switch (ch) {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                else => null,
            };
            if (esc != null or ch < 0x20) {
                try w.writeAll(s[run..i]);
                if (esc) |e| try w.writeAll(e) else try w.print("\\u{x:0>4}", .{ch});
                run = i + 1;
            }
            i += 1;
            continue;
        }
        const n = std.unicode.utf8ByteSequenceLength(ch) catch 0;
        if (n != 0 and i + n <= s.len and std.unicode.utf8ValidateSlice(s[i .. i + n])) {
            if (ascii) {
                try w.writeAll(s[run..i]);
                const cp = std.unicode.utf8Decode(s[i .. i + n]) catch 0xFFFD;
                if (cp >= 0x10000) {
                    const x = cp - 0x10000;
                    try w.print("\\u{x:0>4}\\u{x:0>4}", .{ 0xD800 + (x >> 10), 0xDC00 + (x & 0x3FF) });
                } else try w.print("\\u{x:0>4}", .{cp});
                run = i + n;
            }
            i += n;
            continue;
        }
        try w.writeAll(s[run..i]);
        if (ascii) try w.writeAll("\\ufffd") else try w.writeAll(&std.unicode.replacement_character_utf8);
        i += 1;
        run = i;
    }
    try w.writeAll(s[run..]);
    try w.writeByte('"');
}
