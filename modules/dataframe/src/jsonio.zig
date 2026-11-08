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

pub const JsonOrient = enum { records, columns };

pub const JsonError = std.Io.Writer.Error;

/// The whole frame as one JSON document. `records` of no rows is `[]`, `columns` of no
/// columns is `{}`.
pub fn writeJson(w: *std.Io.Writer, f: Frame, orient: JsonOrient) JsonError!void {
    switch (orient) {
        .records => {
            try w.writeByte('[');
            for (0..f.len) |ri| {
                if (ri != 0) try w.writeByte(',');
                try writeRecord(w, f, ri);
            }
            try w.writeByte(']');
        },
        .columns => {
            try w.writeByte('{');
            for (f.columns, 0..) |c, ci| {
                if (ci != 0) try w.writeByte(',');
                try writeString(w, c.name);
                try w.writeAll(":[");
                const col = f.columnAt(ci);
                for (0..f.len) |ri| {
                    if (ri != 0) try w.writeByte(',');
                    try writeValue(w, col.get(ri), c, 0);
                }
                try w.writeByte(']');
            }
            try w.writeByte('}');
        },
    }
}

/// One record per line, each ended by `\n` (the last too).
pub fn writeNdjson(w: *std.Io.Writer, f: Frame) JsonError!void {
    for (0..f.len) |ri| {
        try writeRecord(w, f, ri);
        try w.writeByte('\n');
    }
}

fn writeRecord(w: *std.Io.Writer, f: Frame, ri: usize) JsonError!void {
    try w.writeByte('{');
    for (f.columns, 0..) |c, ci| {
        if (ci != 0) try w.writeByte(',');
        try writeString(w, c.name);
        try w.writeByte(':');
        try writeValue(w, f.columnAt(ci).get(ri), c, 0);
    }
    try w.writeByte('}');
}

/// One cell as JSON. `col` is its declared column (null: none, the cell alone decides):
/// its type writes an int as a timestamp or a duration, and its `inner` columns do the
/// same for a nested value's elements and fields. A list is an array, a record an object
/// with its field names; past `max_nesting_depth` a nested value is `null`.
pub fn writeValue(w: *std.Io.Writer, v0: Value, col: ?value.Column, depth: u8) JsonError!void {
    const v = Value.capped(v0, depth);
    const ty: ?ColumnType = if (col) |c| c.type else null;
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| if (ty == .timestamp) {
            var tb: [value.max_iso_timestamp_len]u8 = undefined;
            try writeString(w, value.formatIsoTimestamp(&tb, i));
        } else if (ty == .duration) {
            var ub: [value.max_duration_len]u8 = undefined;
            try writeString(w, value.formatIsoDuration(&ub, i));
        } else try w.print("{d}", .{i}),
        .float => |x| if (std.math.isFinite(x)) {
            var fb: [textio.max_float_len]u8 = undefined;
            try w.writeAll(textio.formatFloat(&fb, x));
        } else try w.writeAll("null"),
        .decimal => |r| {
            var db: [textio.max_decimal_len]u8 = undefined;
            try w.writeAll(textio.formatDecimal(&db, r));
        },
        .text => |t| try writeString(w, t),
        .list => |l| {
            const elem: ?value.Column = if (col) |c| c.innerAt(0, "") else null;
            try w.writeByte('[');
            for (0..l.len()) |i| {
                if (i != 0) try w.writeByte(',');
                try writeValue(w, l.get(i), elem, depth + 1);
            }
            try w.writeByte(']');
        },
        .record => |r| {
            try w.writeByte('{');
            for (0..r.len()) |i| {
                if (i != 0) try w.writeByte(',');
                try writeString(w, r.name(i));
                try w.writeByte(':');
                try writeValue(w, r.get(i), if (col) |c| c.innerAt(i, r.name(i)) else null, depth + 1);
            }
            try w.writeByte('}');
        },
    }
}

/// `s` as a JSON string. Invalid UTF-8 is replaced byte by byte with U+FFFD.
pub fn writeString(w: *std.Io.Writer, s: []const u8) JsonError!void {
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
            i += n;
            continue;
        }
        try w.writeAll(s[run..i]);
        try w.writeAll(&std.unicode.replacement_character_utf8);
        i += 1;
        run = i;
    }
    try w.writeAll(s[run..]);
    try w.writeByte('"');
}
