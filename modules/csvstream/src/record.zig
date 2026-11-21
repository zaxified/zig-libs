// SPDX-License-Identifier: MIT
//! Struct mapping for CSV records (rust-csv's serde `deserialize`/`serialize`, Go `gocsv`/`csvutil`):
//! a record's already-split fields into a struct by column name (with a `Header`) or by position
//! (without one), and a struct back into one written record. Comptime reflection over the struct's
//! fields; nothing here reads or writes bytes beyond what `splitFields`/`writeRecord` do.
//!
//! Field types: integers (`parseInt`), floats (`parseFloat`), `bool` (`parseBool`), enums (by
//! tag name), `[]const u8` (the field's bytes, verbatim, BORROWED from the record: the borrow
//! contract of `StreamReader.next()` applies) and `?T` of those (an empty field is null). Anything
//! else is a compile error naming the field. A struct opts in to other column names with
//! `pub const csv_rename = .{ .field_name = "Column Name" };`.
//!
//! Provenance: original work of the zig-libs authors (MIT). Behaviour after rust-csv's serde
//! (`Option` empty = `None`, columns matched by header name, unknown columns ignored, a short
//! positional record is an error) and Go `csvutil` (a struct field named by a tag).

const std = @import("std");
const coerce = @import("coerce.zig");
const header = @import("header.zig");
const writer = @import("writer.zig");
const stream = @import("stream.zig");

const Header = header.Header;

pub const Options = struct {
    /// An empty field of an optional field type is null (rust-csv `Option`, `csvutil` `omitempty` on read).
    /// `false`: an empty field is parsed like any other (and an empty number is `error.InvalidField`).
    empty_is_null: bool = true,
    /// Trim spaces and tabs around a number, bool or enum field before parsing (text stays verbatim).
    /// `coerce` never trims; serde does not either, so this is off by default.
    trim: bool = false,
    /// Filled when `error.InvalidField` or `error.MissingColumn` is returned: the struct field and the
    /// column index (the struct field's position without a header) that failed.
    diag: ?*Diag = null,
};

pub const Diag = struct {
    field: []const u8 = "",
    column: usize = 0,
};

pub const Error = error{
    /// A struct field with no default and no optional type has no column: absent from the header, or past
    /// the end of a short positional record.
    MissingColumn,
    /// A field's text does not parse as its struct field's type.
    InvalidField,
};

/// The column name of struct field `name` of `T`: `T.csv_rename.<name>` when there is one, else `name`.
pub fn columnName(comptime T: type, comptime name: []const u8) []const u8 {
    if (@hasDecl(T, "csv_rename")) {
        const R = @TypeOf(T.csv_rename);
        if (@hasField(R, name)) return @field(T.csv_rename, name);
    }
    return name;
}

fn requireStruct(comptime T: type) void {
    if (@typeInfo(T) != .@"struct" or @typeInfo(T).@"struct".is_tuple) @compileError("csvstream.record: " ++ @typeName(T) ++ " is not a struct");
}

fn checkSupported(comptime F: type, comptime name: []const u8) void {
    switch (@typeInfo(F)) {
        .int, .float, .bool, .@"enum" => {},
        .optional => |o| checkSupported(o.child, name),
        .pointer => |p| {
            if (!(p.size == .slice and p.child == u8 and p.attrs.@"const")) @compileError("csvstream.record: field '" ++ name ++ "' of type " ++ @typeName(F) ++ " is not supported");
        },
        else => @compileError("csvstream.record: field '" ++ name ++ "' of type " ++ @typeName(F) ++ " is not supported"),
    }
}

fn trimmed(s: []const u8, opts: Options) []const u8 {
    return if (opts.trim) std.mem.trim(u8, s, " \t") else s;
}

fn parseValue(comptime F: type, s: []const u8, opts: Options) Error!F {
    switch (@typeInfo(F)) {
        .optional => |o| {
            // An empty field is null; a field of blanks too when the child is parsed trimmed (not text).
            const blank = if (o.child == []const u8) s.len == 0 else trimmed(s, opts).len == 0;
            if (opts.empty_is_null and blank) return null;
            return try parseValue(o.child, s, opts);
        },
        .pointer => return s,
        .bool => return coerce.parseBool(trimmed(s, opts)) catch error.InvalidField,
        .int => return coerce.parseInt(F, trimmed(s, opts)) catch error.InvalidField,
        .float => return coerce.parseFloat(F, trimmed(s, opts)) catch error.InvalidField,
        .@"enum" => return std.meta.stringToEnum(F, trimmed(s, opts)) orelse error.InvalidField,
        else => unreachable,
    }
}

/// One record into a `T`: by column name through `hdr`, or, with a null `hdr`, field `i` of the struct
/// from column `i`. Struct fields the record has no column for take their default, else null when
/// optional, else `error.MissingColumn`; columns no struct field names are ignored (a longer positional
/// record too). Text fields borrow from `row`.
pub fn deserialize(comptime T: type, hdr: ?*const Header, row: []const []const u8, opts: Options) Error!T {
    requireStruct(T);
    var out: T = undefined;
    const info = @typeInfo(T).@"struct";
    inline for (info.field_names, info.field_types, info.field_attrs, 0..) |fname, FT, attrs, i| {
        comptime checkSupported(FT, fname);
        const col: ?usize = if (hdr) |h| h.indexOf(comptime columnName(T, fname)) else i;
        const text: ?[]const u8 = if (col) |c| (if (c < row.len) row[c] else null) else null;
        if (text) |s| {
            @field(out, fname) = parseValue(FT, s, opts) catch |e| {
                if (opts.diag) |d| d.* = .{ .field = fname, .column = col.? };
                return e;
            };
        } else if (comptime attrs.defaultValue(FT)) |d| {
            @field(out, fname) = d;
        } else if (@typeInfo(FT) == .optional) {
            @field(out, fname) = null;
        } else {
            if (opts.diag) |d| d.* = .{ .field = fname, .column = col orelse i };
            return error.MissingColumn;
        }
    }
    return out;
}

/// `deserialize` over the reader's next record: the fields are split into `buf` (see
/// `StreamReader.nextFieldsOpts`), `alloc` takes the copies of escaped-quote fields (an arena reset
/// per record is the usual choice), and the text fields of the result borrow from the record or `alloc`.
/// Null at end of input.
pub fn nextRecord(comptime T: type, sr: *stream.StreamReader, hdr: ?*const Header, buf: [][]const u8, alloc: std.mem.Allocator, opts: Options) !?T {
    const row = (try sr.nextFields(buf, alloc)) orelse return null;
    return try deserialize(T, hdr, row, opts);
}

/// The header row of `T`: its field names (or `csv_rename` names) in order, as one record.
pub fn writeHeader(comptime T: type, w: *std.Io.Writer, opts: writer.WriteOptions) std.Io.Writer.Error!void {
    requireStruct(T);
    const info = @typeInfo(T).@"struct";
    var names: [info.field_names.len][]const u8 = undefined;
    inline for (info.field_names, info.field_types, 0..) |fname, FT, i| {
        comptime checkSupported(FT, fname);
        names[i] = comptime columnName(T, fname);
    }
    try writer.writeRecord(w, &names, opts);
}

/// One `value` as one written record, fields in declaration order: integers in decimal, floats in their
/// shortest decimal form that reads back (`{d}`, `{e}` past 64 bytes), bools `true`/`false`, enums by tag
/// name, text as is, a null optional as an empty field. Quoting per `opts`.
pub fn serialize(w: *std.Io.Writer, value: anytype, opts: writer.WriteOptions) std.Io.Writer.Error!void {
    const T = @TypeOf(value);
    requireStruct(T);
    const info = @typeInfo(T).@"struct";
    var cells: [info.field_names.len][]const u8 = undefined;
    var scratch: [info.field_names.len][64]u8 = undefined;
    inline for (info.field_names, info.field_types, 0..) |fname, FT, i| {
        comptime checkSupported(FT, fname);
        cells[i] = cellOf(FT, @field(value, fname), &scratch[i]);
    }
    try writer.writeRecord(w, &cells, opts);
}

fn cellOf(comptime F: type, v: F, buf: *[64]u8) []const u8 {
    switch (@typeInfo(F)) {
        .optional => |o| return if (v) |x| cellOf(o.child, x, buf) else "",
        .pointer => return v,
        .bool => return if (v) "true" else "false",
        .int => return std.fmt.bufPrint(buf, "{d}", .{v}) catch unreachable, // 64 bytes hold every integer up to 128 bits
        .float => return std.fmt.bufPrint(buf, "{d}", .{v}) catch (std.fmt.bufPrint(buf, "{e}", .{v}) catch unreachable),
        .@"enum" => return @tagName(v),
        else => unreachable,
    }
}

// ============================================================
// Tests
// ============================================================

const t = std.testing;

const Person = struct {
    name: []const u8,
    age: u8,
    score: ?f64 = null,
    active: bool = true,
};

test "deserialize: by header name, in any column order; unknown columns and a missing optional or defaulted column" {
    var h = try Header.init(t.allocator, &.{ "city", "age", "name" });
    defer h.deinit();
    const p = try deserialize(Person, &h, &.{ "Prague", "41", "Ada" }, .{});
    try t.expectEqualStrings("Ada", p.name);
    try t.expectEqual(@as(u8, 41), p.age);
    try t.expectEqual(@as(?f64, null), p.score);
    try t.expect(p.active);
    var h2 = try Header.init(t.allocator, &.{ "name", "age", "score", "active" });
    defer h2.deinit();
    const q = try deserialize(Person, &h2, &.{ "Bob", "7", "2.5", "FALSE" }, .{});
    try t.expectEqual(@as(?f64, 2.5), q.score);
    try t.expect(!q.active);
}

test "deserialize: by position without a header; a longer record is fine, a shorter one is MissingColumn" {
    const p = try deserialize(Person, null, &.{ "Ada", "41", "", "0", "extra" }, .{});
    try t.expectEqual(@as(?f64, null), p.score); // empty = null
    try t.expect(!p.active);
    var d: Diag = .{};
    try t.expectError(error.MissingColumn, deserialize(Person, null, &.{"Ada"}, .{ .diag = &d }));
    try t.expectEqualStrings("age", d.field);
    // optional and defaulted fields at the end may be absent
    const q = try deserialize(Person, null, &.{ "Ada", "41" }, .{});
    try t.expect(q.active);
}

test "deserialize: a missing required column, a bad number, diag names the field and the column" {
    var h = try Header.init(t.allocator, &.{ "name", "score" });
    defer h.deinit();
    var d: Diag = .{};
    try t.expectError(error.MissingColumn, deserialize(Person, &h, &.{ "Ada", "1" }, .{ .diag = &d }));
    try t.expectEqualStrings("age", d.field);
    var h2 = try Header.init(t.allocator, &.{ "name", "age" });
    defer h2.deinit();
    try t.expectError(error.InvalidField, deserialize(Person, &h2, &.{ "Ada", "forty" }, .{ .diag = &d }));
    try t.expectEqualStrings("age", d.field);
    try t.expectEqual(@as(usize, 1), d.column);
    try t.expectError(error.InvalidField, deserialize(Person, &h2, &.{ "Ada", "256" }, .{})); // u8 overflow
    try t.expectError(error.InvalidField, deserialize(Person, &h2, &.{ "Ada", "" }, .{})); // empty number
    try t.expectError(error.InvalidField, deserialize(Person, &h2, &.{ "Ada", " 4" }, .{})); // no trimming by default
    const ok = try deserialize(Person, &h2, &.{ "Ada", " 4\t" }, .{ .trim = true });
    try t.expectEqual(@as(u8, 4), ok.age);
}

test "deserialize: empty_is_null off parses an empty optional like any other field; optional text is empty, not null" {
    const S = struct { a: ?[]const u8, b: ?i32 };
    const s = try deserialize(S, null, &.{ "", "" }, .{});
    try t.expectEqual(@as(?i32, null), s.b);
    try t.expect(s.a == null); // an empty field of an optional text is null too (rust-csv `Option<String>`)
    try t.expectError(error.InvalidField, deserialize(S, null, &.{ "x", "" }, .{ .empty_is_null = false }));
    const u = try deserialize(S, null, &.{ "", "3" }, .{ .empty_is_null = false });
    try t.expectEqualStrings("", u.a.?);
}

test "deserialize: enums by tag name, csv_rename, floats incl. nan and inf" {
    const Kind = enum { cat, dog };
    const Pet = struct {
        kind: Kind,
        weight: f32,
        pub const csv_rename = .{ .kind = "Kind", .weight = "Weight (kg)" };
    };
    var h = try Header.init(t.allocator, &.{ "Weight (kg)", "Kind" });
    defer h.deinit();
    const p = try deserialize(Pet, &h, &.{ "4.5", "dog" }, .{});
    try t.expectEqual(Kind.dog, p.kind);
    try t.expectEqual(@as(f32, 4.5), p.weight);
    try t.expectError(error.InvalidField, deserialize(Pet, &h, &.{ "4.5", "bird" }, .{}));
    try t.expectError(error.InvalidField, deserialize(Pet, &h, &.{ "4.5", "Dog" }, .{})); // case-sensitive
    const n = try deserialize(Pet, &h, &.{ "nan", "cat" }, .{});
    try t.expect(std.math.isNan(n.weight));
    const i = try deserialize(Pet, &h, &.{ "inf", "cat" }, .{});
    try t.expect(std.math.isInf(i.weight));
    // csv_rename: the plain struct field name is not a column any more
    var h2 = try Header.init(t.allocator, &.{ "weight", "kind" });
    defer h2.deinit();
    try t.expectError(error.MissingColumn, deserialize(Pet, &h2, &.{ "4.5", "dog" }, .{}));
}

test "serialize and writeHeader: order, quoting, optionals, enums, bools, floats, integers of every width" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeHeader(Person, &w, .{ .line_terminator = .lf });
    try serialize(&w, Person{ .name = "A, \"B\"", .age = 41, .score = 0.1, .active = false }, .{ .line_terminator = .lf });
    try serialize(&w, Person{ .name = "C", .age = 0 }, .{ .line_terminator = .lf });
    try t.expectEqualStrings("name,age,score,active\n\"A, \"\"B\"\"\",41,0.1,false\nC,0,,true\n", w.buffered());

    const W = struct { a: i128, b: u128, c: i8, d: f64, e: f64, f: enum { x, y } };
    var buf2: [512]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    try serialize(&w2, W{ .a = std.math.minInt(i128), .b = std.math.maxInt(u128), .c = -128, .d = 1e300, .e = 5e-324, .f = .y }, .{ .line_terminator = .lf });
    const line = w2.buffered();
    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\n"), ',');
    try t.expectEqualStrings("-170141183460469231731687303715884105728", it.next().?);
    try t.expectEqualStrings("340282366920938463463374607431768211455", it.next().?);
    try t.expectEqualStrings("-128", it.next().?);
    // 1e300 does not fit 64 bytes in `{d}` form: the scientific form reads back
    try t.expectEqual(@as(f64, 1e300), try coerce.parseFloat(f64, it.next().?));
    try t.expectEqual(@as(f64, 5e-324), try coerce.parseFloat(f64, it.next().?));
    try t.expectEqualStrings("y", it.next().?);
}

test "round trip: serialize then split then deserialize gives the struct back, text with delimiter, quote and newline" {
    const Row = struct { id: u32, text: []const u8, ratio: ?f64, ok: bool };
    const rows = [_]Row{
        .{ .id = 1, .text = "plain", .ratio = 0.5, .ok = true },
        .{ .id = 2, .text = "a,b", .ratio = null, .ok = false },
        .{ .id = 3, .text = "say \"hi\"", .ratio = -1e-9, .ok = true },
        .{ .id = 4, .text = "", .ratio = 12345.678, .ok = false },
    };
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();
    try writeHeader(Row, &aw.writer, .{ .line_terminator = .lf });
    for (rows) |r| try serialize(&aw.writer, r, .{ .line_terminator = .lf });
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "rows.csv", .data = aw.written() });
    var f = try tmp.dir.openFile(t.io, "rows.csv", .{});
    defer f.close(t.io);
    var sr = try stream.StreamReader.init(t.io, t.allocator, f, .{});
    defer sr.deinit();
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var fbuf: [8][]const u8 = undefined;
    var h = (try sr.readHeader(&fbuf, t.allocator)).?;
    defer h.deinit();
    for (rows) |want| {
        _ = arena.reset(.retain_capacity);
        const got = (try nextRecord(Row, &sr, &h, &fbuf, arena.allocator(), .{})).?;
        try t.expectEqual(want.id, got.id);
        try t.expectEqual(want.ok, got.ok);
        try t.expectEqual(want.ratio, got.ratio);
        // an empty text is a null optional only for `?[]const u8`; a plain `[]const u8` keeps it
        try t.expectEqualStrings(want.text, got.text);
    }
    try t.expect((try nextRecord(Row, &sr, &h, &fbuf, arena.allocator(), .{})) == null);
}
