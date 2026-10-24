// SPDX-License-Identifier: MIT
//! json5 stringify — the other direction of `root.zig`: a JSON5 writer
//! (`writeValue` for a `std.json.Value` tree, `write` for any Zig value
//! `std.json.Stringify` accepts), shaped after `JSON5.stringify(value, {space,
//! quote})` of the reference json5 2.2.3 (JS).
//!
//! What it matches, byte for byte (tests are goldens captured from the
//! reference, see the bottom of the file): the quote choice per string, the
//! escape set, number formatting (JS `String(number)`: `1e+21`, `-0` -> `0`,
//! `NaN`, `Infinity`), unquoted identifier keys, `key: value` / trailing-comma
//! layout when indented.
//!
//! Not supported (a compile error, or documented below): untagged unions,
//! `jsonStringify` hooks (ignored), many-item pointers without a sentinel.
//! Nesting deeper than `Options.max_depth` -- cyclic data among it -- is
//! `error.NestingTooDeep` (the reference throws too). String bytes are written
//! as they are, UTF-8 is not validated.

const std = @import("std");
const Writer = std.Io.Writer;

pub const Error = Writer.Error || error{NestingTooDeep};

/// The longest indent the reference allows (`Math.min(10, space)`).
pub const max_indent = 10;

pub const Quote = enum {
    /// The reference's default: per string, the quote that occurs less in it
    /// (a tie takes `'`), so that fewer escapes are needed.
    auto,
    /// Always `"` (the reference's `quote: '"'`; no switching per string).
    double,
    /// Always `'`.
    single,
};

pub const Options = struct {
    /// Indent per level, clamped to `max_indent`; 0 = compact single line (the
    /// reference's `space`).
    indent: u8 = 0,
    /// The reference's `quote`. `.auto` is what the reference does without it.
    quote: Quote = .auto,
    /// Object keys that are identifiers are written unquoted (reference
    /// behaviour). The identifier test is ASCII only: `[A-Za-z$_][A-Za-z0-9$_]*`.
    /// The reference also leaves Unicode `ID_Start`/`ID_Continue` keys bare
    /// (`é`, `日本`); this writer quotes them, which is valid JSON5 and
    /// round-trips. Reserved words (`class`, `null`) stay bare, as in the
    /// reference (ES5 allows them as property names).
    unquoted_keys: bool = true,
    /// Trailing comma after the last member/element when indented (reference:
    /// yes). Never written in the compact form.
    trailing_commas: bool = true,
    /// Containers nested deeper than this are `error.NestingTooDeep`. The
    /// writer recurses once per level; `parseFromSlice` builds a
    /// `std.json.Value` of any depth without recursing, so a hostile
    /// `[[[[…` that parses would otherwise overflow the stack here
    /// (review 2026-10-24).
    max_depth: usize = 1000,
};

/// Write a `std.json.Value` tree as JSON5. `.number_string` is written
/// verbatim (it is a JSON number, hence a JSON5 one); `.float` NaN/Infinity as
/// the JSON5 literals.
pub fn writeValue(w: *Writer, value: std.json.Value, opts: Options) Error!void {
    var s: Ser = .{ .w = w, .o = opts };
    try s.jsonValue(value);
}

/// Write any Zig value as JSON5, with the mapping `std.json.Stringify` uses:
/// structs -> objects (tuples -> arrays, `void` fields skipped), slices and
/// arrays -> arrays (`u8` ones -> strings), optionals -> value or `null`,
/// enums and errors -> their name as a string (a non-exhaustive enum with an
/// unnamed value -> its integer), tagged unions -> `{name: payload}` (`void`
/// payload -> `{}`), bool, ints, floats (NaN/Infinity as literals),
/// `std.json.Value` (via `writeValue`).
pub fn write(w: *Writer, value: anytype, opts: Options) Error!void {
    var s: Ser = .{ .w = w, .o = opts };
    try s.value(value);
}

/// ECMAScript `Number::toString` for a finite non-zero magnitude's digits
/// (`-0` is `0`), plus `NaN` / `Infinity` / `-Infinity`.
// The layout rules are ported from the ECMAScript spec (Number::toString),
// which json5/json5 v2.2.3 lib/stringify.js reaches via `String(value)`.
pub fn writeFloat(w: *Writer, f: anytype) Error!void {
    if (std.math.isNan(f)) return w.writeAll("NaN");
    if (std.math.isInf(f)) return w.writeAll(if (f < 0) "-Infinity" else "Infinity");
    if (f == 0) return w.writeAll("0");
    var buf: [160]u8 = undefined;
    // `{e}` without precision is the shortest round-trip form: `d[.ddd]e<exp>`.
    const s = std.fmt.bufPrint(&buf, "{e}", .{@abs(f)}) catch unreachable;
    const epos = std.mem.findScalar(u8, s, 'e').?;
    var digits_buf: [160]u8 = undefined;
    var k: usize = 0;
    for (s[0..epos]) |c| {
        if (c == '.') continue;
        digits_buf[k] = c;
        k += 1;
    }
    const digits = digits_buf[0..k];
    const exp = std.fmt.parseInt(i32, s[epos + 1 ..], 10) catch unreachable;
    const n: i32 = exp + 1; // position of the decimal point relative to digits
    const kk: i32 = @intCast(k);
    if (f < 0) try w.writeByte('-');
    if (kk <= n and n <= 21) {
        try w.writeAll(digits);
        try w.splatByteAll('0', @intCast(n - kk));
    } else if (0 < n and n <= 21) {
        try w.writeAll(digits[0..@intCast(n)]);
        try w.writeByte('.');
        try w.writeAll(digits[@intCast(n)..]);
    } else if (-6 < n and n <= 0) {
        try w.writeAll("0.");
        try w.splatByteAll('0', @intCast(-n));
        try w.writeAll(digits);
    } else {
        try w.writeByte(digits[0]);
        if (k > 1) {
            try w.writeByte('.');
            try w.writeAll(digits[1..]);
        }
        const e = n - 1;
        try w.writeAll(if (e < 0) "e-" else "e+");
        try w.print("{d}", .{@abs(e)});
    }
}

/// Write `s` as a quoted JSON5 string.
// ported from json5/json5 v2.2.3 lib/stringify.js (quoteString)
pub fn writeString(w: *Writer, s: []const u8, quote: Quote) Error!void {
    const q: u8 = switch (quote) {
        .double => '"',
        .single => '\'',
        .auto => blk: {
            var sq: usize = 0;
            var dq: usize = 0;
            for (s) |c| switch (c) {
                '\'' => sq += 1,
                '"' => dq += 1,
                else => {},
            };
            // The reference seeds the counters 0.1 (') and 0.2 ("): a tie is '.
            break :blk if (sq <= dq) '\'' else '"';
        },
    };
    try w.writeByte(q);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        switch (c) {
            '\\' => try w.writeAll("\\\\"),
            0x08 => try w.writeAll("\\b"),
            0x0c => try w.writeAll("\\f"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x0b => try w.writeAll("\\v"),
            0 => if (i + 1 < s.len and s[i + 1] >= '0' and s[i + 1] <= '9')
                try w.writeAll("\\x00")
            else
                try w.writeAll("\\0"),
            0xe2 => if (i + 2 < s.len and s[i + 1] == 0x80 and (s[i + 2] == 0xa8 or s[i + 2] == 0xa9)) {
                try w.writeAll(if (s[i + 2] == 0xa8) "\\u2028" else "\\u2029");
                i += 2;
            } else try w.writeByte(c),
            else => {
                if (c == q) {
                    try w.writeByte('\\');
                    try w.writeByte(c);
                } else if (c < 0x20) {
                    try w.print("\\x{x:0>2}", .{c});
                } else try w.writeByte(c);
            },
        }
    }
    try w.writeByte(q);
}

fn isBareKey(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key, 0..) |c, i| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '$' or c == '_' or
            (i > 0 and c >= '0' and c <= '9');
        if (!ok) return false;
    }
    return true;
}

const Ser = struct {
    w: *Writer,
    o: Options,
    level: usize = 0,

    fn gap(self: *const Ser) usize {
        return @min(self.o.indent, max_indent);
    }

    fn pad(self: *Ser, level: usize) Error!void {
        try self.w.splatByteAll(' ', level * self.gap());
    }

    /// Before a member/element: separator, newline and indent.
    fn item(self: *Ser, first: *bool) Error!void {
        if (!first.*) try self.w.writeByte(',');
        first.* = false;
        if (self.gap() > 0) {
            try self.w.writeByte('\n');
            try self.pad(self.level);
        }
    }

    fn open(self: *Ser, ch: u8) Error!void {
        if (self.level >= self.o.max_depth) return error.NestingTooDeep;
        try self.w.writeByte(ch);
        self.level += 1;
    }

    fn close(self: *Ser, first: bool, ch: u8) Error!void {
        self.level -= 1;
        if (!first and self.gap() > 0) {
            if (self.o.trailing_commas) try self.w.writeByte(',');
            try self.w.writeByte('\n');
            try self.pad(self.level);
        }
        try self.w.writeByte(ch);
    }

    fn key(self: *Ser, name: []const u8) Error!void {
        if (self.o.unquoted_keys and isBareKey(name)) {
            try self.w.writeAll(name);
        } else try writeString(self.w, name, self.o.quote);
        try self.w.writeByte(':');
        if (self.gap() > 0) try self.w.writeByte(' ');
    }

    fn jsonValue(self: *Ser, v: std.json.Value) Error!void {
        switch (v) {
            .null => try self.w.writeAll("null"),
            .bool => |b| try self.w.writeAll(if (b) "true" else "false"),
            .integer => |n| try self.w.print("{d}", .{n}),
            .float => |f| try writeFloat(self.w, f),
            .number_string => |s| try self.w.writeAll(s),
            .string => |s| try writeString(self.w, s, self.o.quote),
            .array => |a| {
                try self.open('[');
                var first = true;
                for (a.items) |e| {
                    try self.item(&first);
                    try self.jsonValue(e);
                }
                try self.close(first, ']');
            },
            .object => |o| {
                try self.open('{');
                var first = true;
                for (o.keys(), o.values()) |k, e| {
                    try self.item(&first);
                    try self.key(k);
                    try self.jsonValue(e);
                }
                try self.close(first, '}');
            },
        }
    }

    fn seq(self: *Ser, items: anytype) Error!void {
        try self.open('[');
        var first = true;
        for (items) |e| {
            try self.item(&first);
            try self.value(e);
        }
        try self.close(first, ']');
    }

    fn value(self: *Ser, v: anytype) Error!void {
        const T = @TypeOf(v);
        if (T == std.json.Value) return self.jsonValue(v);
        switch (@typeInfo(T)) {
            .null => try self.w.writeAll("null"),
            .bool => try self.w.writeAll(if (v) "true" else "false"),
            .int, .comptime_int => try self.w.print("{d}", .{v}),
            .float => try writeFloat(self.w, v),
            .comptime_float => try writeFloat(self.w, @as(f64, v)),
            .optional => if (v) |p| try self.value(p) else try self.w.writeAll("null"),
            .@"enum" => |info| {
                if (info.mode == .nonexhaustive) {
                    inline for (info.field_names) |name| {
                        if (v == @field(T, name)) break;
                    } else return self.value(@backingInt(v));
                }
                try writeString(self.w, @tagName(v), self.o.quote);
            },
            .enum_literal => try writeString(self.w, @tagName(v), self.o.quote),
            .error_set => try writeString(self.w, @errorName(v), self.o.quote),
            .@"union" => |info| {
                if (info.tag_type == null) @compileError("unable to stringify untagged union '" ++ @typeName(T) ++ "'");
                try self.open('{');
                var first = true;
                try self.item(&first);
                inline for (info.field_names, info.field_types) |name, ft| {
                    if (v == @field(info.tag_type.?, name)) {
                        try self.key(name);
                        if (ft == void) {
                            try self.open('{');
                            try self.close(true, '}');
                        } else try self.value(@field(v, name));
                    }
                }
                try self.close(first, '}');
            },
            .@"struct" => |info| {
                const open_ch: u8 = if (info.is_tuple) '[' else '{';
                try self.open(open_ch);
                var first = true;
                inline for (info.field_names, info.field_types) |name, ft| {
                    if (ft != void) {
                        try self.item(&first);
                        if (!info.is_tuple) try self.key(name);
                        try self.value(@field(v, name));
                    }
                }
                try self.close(first, if (info.is_tuple) ']' else '}');
            },
            .pointer => |p| switch (p.size) {
                .one => switch (@typeInfo(p.child)) {
                    .array => |a| {
                        const Slice = []const a.child;
                        try self.value(@as(Slice, v));
                    },
                    else => try self.value(v.*),
                },
                .many, .slice => {
                    if (p.size == .many and p.sentinel() == null)
                        @compileError("unable to stringify type '" ++ @typeName(T) ++ "' without sentinel");
                    const slice = if (p.size == .many) std.mem.span(v) else v;
                    if (p.child == u8) {
                        try writeString(self.w, slice, self.o.quote);
                    } else try self.seq(slice);
                },
                else => @compileError("unable to stringify type '" ++ @typeName(T) ++ "'"),
            },
            .array => try self.value(&v),
            .vector => |info| {
                const arr: [info.len]info.child = v;
                try self.value(&arr);
            },
            else => @compileError("unable to stringify type '" ++ @typeName(T) ++ "'"),
        }
    }
};

// ---------------------------------------------------------------- tests ----

const testing = std.testing;

const Case = struct {
    /// Standard JSON input, parsed into a `std.json.Value`.
    json: []const u8,
    indent: u8,
    quote: Quote,
    /// `JSON5.stringify(JSON.parse(json), {space: indent, quote})` of json5
    /// 2.2.3, CAPTURED by running the reference under bun (generator:
    /// a 25-line script over this table; `quote` maps to `undefined`/`"`/`'`).
    want: []const u8,
};

const cases = [_]Case{
    .{ .json = "null", .indent = 0, .quote = .auto, .want = "null" },
    .{ .json = "true", .indent = 0, .quote = .auto, .want = "true" },
    .{ .json = "false", .indent = 0, .quote = .auto, .want = "false" },
    .{ .json = "0", .indent = 0, .quote = .auto, .want = "0" },
    .{ .json = "-0", .indent = 0, .quote = .auto, .want = "0" },
    .{ .json = "1e21", .indent = 0, .quote = .auto, .want = "1e+21" },
    .{ .json = "1.5", .indent = 0, .quote = .auto, .want = "1.5" },
    .{ .json = "-12.25e-3", .indent = 0, .quote = .auto, .want = "-0.01225" },
    .{ .json = "1e-7", .indent = 0, .quote = .auto, .want = "1e-7" },
    .{ .json = "123456789012345680000", .indent = 0, .quote = .auto, .want = "123456789012345680000" },
    .{ .json = "0.000001", .indent = 0, .quote = .auto, .want = "0.000001" },
    .{ .json = "2.0", .indent = 0, .quote = .auto, .want = "2" },
    .{ .json = "100", .indent = 0, .quote = .auto, .want = "100" },
    .{ .json = "5e-324", .indent = 0, .quote = .auto, .want = "5e-324" },
    .{ .json = "1.7976931348623157e308", .indent = 0, .quote = .auto, .want = "1.7976931348623157e+308" },
    .{ .json = "\"abc\"", .indent = 0, .quote = .auto, .want = "'abc'" },
    .{ .json = "\"it's\"", .indent = 0, .quote = .auto, .want = "\"it's\"" },
    .{ .json = "\"say \\\"hi\\\"\"", .indent = 0, .quote = .auto, .want = "'say \"hi\"'" },
    .{ .json = "\"a'b\\\"c'd\"", .indent = 0, .quote = .auto, .want = "\"a'b\\\"c'd\"" },
    .{ .json = "\"'\\\"\"", .indent = 0, .quote = .auto, .want = "'\\'\"'" },
    .{ .json = "\"\"", .indent = 0, .quote = .auto, .want = "''" },
    .{ .json = "\"\\b\\f\\n\\r\\t\\u000b\\u0000\"", .indent = 0, .quote = .auto, .want = "'\\b\\f\\n\\r\\t\\v\\0'" },
    .{ .json = "\"\\u00001\"", .indent = 0, .quote = .auto, .want = "'\\x001'" },
    .{ .json = "\"\\u0000a\"", .indent = 0, .quote = .auto, .want = "'\\0a'" },
    .{ .json = "\"\\u0001\\u001f\\u007f\"", .indent = 0, .quote = .auto, .want = "'\\x01\\x1f\u{7f}'" },
    .{ .json = "\"back\\\\slash\"", .indent = 0, .quote = .auto, .want = "'back\\\\slash'" },
    .{ .json = "\"héllo ☃ 😀\"", .indent = 0, .quote = .auto, .want = "'héllo ☃ 😀'" },
    .{ .json = "\"a\\u2028b\\u2029c\"", .indent = 0, .quote = .auto, .want = "'a\\u2028b\\u2029c'" },
    .{ .json = "[]", .indent = 0, .quote = .auto, .want = "[]" },
    .{ .json = "{}", .indent = 0, .quote = .auto, .want = "{}" },
    .{ .json = "[]", .indent = 2, .quote = .auto, .want = "[]" },
    .{ .json = "{}", .indent = 4, .quote = .auto, .want = "{}" },
    .{ .json = "{\"a\":{\"b\":[1,2,{\"c\":null}]},\"d\":[]}", .indent = 0, .quote = .auto, .want = "{a:{b:[1,2,{c:null}]},d:[]}" },
    .{ .json = "{\"a\":{\"b\":[1,2,{\"c\":null}]},\"d\":[]}", .indent = 2, .quote = .auto, .want = "{\n  a: {\n    b: [\n      1,\n      2,\n      {\n        c: null,\n      },\n    ],\n  },\n  d: [],\n}" },
    .{ .json = "{\"a\":{\"b\":[1,2,{\"c\":null}]},\"d\":[]}", .indent = 4, .quote = .auto, .want = "{\n    a: {\n        b: [\n            1,\n            2,\n            {\n                c: null,\n            },\n        ],\n    },\n    d: [],\n}" },
    .{ .json = "{\"a b\":1,\"1a\":2,\"class\":3,\"$x\":4,\"_y\":5,\"\":6,\"a-b\":7,\"x9\":8}", .indent = 0, .quote = .auto, .want = "{'a b':1,'1a':2,class:3,$x:4,_y:5,'':6,'a-b':7,x9:8}" },
    .{ .json = "{\"a b\":1,\"1a\":2,\"class\":3,\"$x\":4,\"_y\":5,\"\":6,\"a-b\":7,\"x9\":8}", .indent = 2, .quote = .auto, .want = "{\n  'a b': 1,\n  '1a': 2,\n  class: 3,\n  $x: 4,\n  _y: 5,\n  '': 6,\n  'a-b': 7,\n  x9: 8,\n}" },
    .{ .json = "{\"it's\":1,\"say \\\"x\\\"\":2}", .indent = 0, .quote = .auto, .want = "{\"it's\":1,'say \"x\"':2}" },
    .{ .json = "\"say \\\"hi\\\"\"", .indent = 0, .quote = .double, .want = "\"say \\\"hi\\\"\"" },
    .{ .json = "\"it's\"", .indent = 0, .quote = .single, .want = "'it\\'s'" },
    .{ .json = "\"plain\"", .indent = 0, .quote = .double, .want = "\"plain\"" },
    .{ .json = "\"it's\"", .indent = 0, .quote = .double, .want = "\"it's\"" },
    .{ .json = "{\"k\":\"it's\",\"it's\":\"v\"}", .indent = 2, .quote = .single, .want = "{\n  k: 'it\\'s',\n  'it\\'s': 'v',\n}" },
    .{ .json = "[[1,2],[3,[4,[]]],{}]", .indent = 2, .quote = .auto, .want = "[\n  [\n    1,\n    2,\n  ],\n  [\n    3,\n    [\n      4,\n      [],\n    ],\n  ],\n  {},\n]" },
    .{ .json = "{\"a\":[],\"b\":{}}", .indent = 2, .quote = .auto, .want = "{\n  a: [],\n  b: {},\n}" },
    .{ .json = "[1,\"two\",[3],{\"four\":4}]", .indent = 3, .quote = .auto, .want = "[\n   1,\n   'two',\n   [\n      3,\n   ],\n   {\n      four: 4,\n   },\n]" },
    .{ .json = "[1,[2]]", .indent = 12, .quote = .auto, .want = "[\n          1,\n          [\n                    2,\n          ],\n]" },
    .{ .json = "[1,[2]]", .indent = 1, .quote = .auto, .want = "[\n 1,\n [\n  2,\n ],\n]" },
    .{ .json = "[true,false,null]", .indent = 0, .quote = .auto, .want = "[true,false,null]" },
};

fn render(value: std.json.Value, opts: Options) ![]u8 {
    var aw: Writer.Allocating = .init(testing.allocator);
    errdefer aw.deinit();
    try writeValue(&aw.writer, value, opts);
    return aw.toOwnedSlice();
}

fn renderAny(value: anytype, opts: Options) ![]u8 {
    var aw: Writer.Allocating = .init(testing.allocator);
    errdefer aw.deinit();
    try write(&aw.writer, value, opts);
    return aw.toOwnedSlice();
}

fn num(v: std.json.Value) ?f64 {
    return switch (v) {
        .integer => |n| @floatFromInt(n),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn same(a: std.json.Value, b: std.json.Value) bool {
    if (num(a)) |x| return if (num(b)) |y| x == y else false;
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    switch (a) {
        .null => return true,
        .bool => |x| return x == b.bool,
        .string => |x| return std.mem.eql(u8, x, b.string),
        .array => |x| {
            if (x.items.len != b.array.items.len) return false;
            for (x.items, b.array.items) |p, q| if (!same(p, q)) return false;
            return true;
        },
        .object => |x| {
            if (x.count() != b.object.count()) return false;
            for (x.keys(), x.values(), b.object.keys(), b.object.values()) |k1, v1, k2, v2| {
                if (!std.mem.eql(u8, k1, k2) or !same(v1, v2)) return false;
            }
            return true;
        },
        else => unreachable,
    }
}

test "nesting deeper than max_depth is an error, not a stack overflow" {
    // Review 2026-10-24: `parseFromSlice` builds a `std.json.Value` of any
    // depth without recursing; this writer recurses once per level.
    const root = @import("root.zig");
    const gpa = std.testing.allocator;
    const open_: [100_000]u8 = @splat('[');
    const close_: [100_000]u8 = @splat(']');
    const deep = try std.mem.concat(gpa, u8, &.{ &open_, &close_ });
    defer gpa.free(deep);
    const v = try root.parseFromSlice(std.json.Value, gpa, deep, .{});
    defer v.deinit();
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try std.testing.expectError(error.NestingTooDeep, writeValue(&aw.writer, v.value, .{}));
    // The limit is the deepest container allowed, exactly.
    const three = try root.parseFromSlice(std.json.Value, gpa, "[[[]]]", .{});
    defer three.deinit();
    aw.clearRetainingCapacity();
    try writeValue(&aw.writer, three.value, .{ .max_depth = 3 });
    try std.testing.expectEqualStrings("[[[]]]", aw.written());
    try std.testing.expectError(error.NestingTooDeep, writeValue(&aw.writer, three.value, .{ .max_depth = 2 }));
    // Within the limit it writes as before.
    const v2 = try root.parseFromSlice(std.json.Value, gpa, deep[100_000 - 500 .. 100_000 + 500], .{});
    defer v2.deinit();
    aw.clearRetainingCapacity();
    try writeValue(&aw.writer, v2.value, .{});
    try std.testing.expectEqual(@as(usize, 1000), aw.written().len);
}

test "goldens from the reference json5 2.2.3" {
    for (cases) |c| {
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, c.json, .{});
        defer parsed.deinit();
        const got = try render(parsed.value, .{ .indent = c.indent, .quote = c.quote });
        defer testing.allocator.free(got);
        testing.expectEqualStrings(c.want, got) catch |err| {
            std.debug.print("case json={s} indent={d}\n", .{ c.json, c.indent });
            return err;
        };
    }
}

test "round trip through preprocess + std.json" {
    const root = @import("root.zig");
    for (cases) |c| {
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, c.json, .{});
        defer parsed.deinit();
        const out = try render(parsed.value, .{ .indent = c.indent, .quote = c.quote });
        defer testing.allocator.free(out);
        const plain = try root.preprocess(testing.allocator, out);
        defer testing.allocator.free(plain);
        const back = try std.json.parseFromSlice(std.json.Value, testing.allocator, plain, .{});
        defer back.deinit();
        testing.expect(same(parsed.value, back.value)) catch |err| {
            std.debug.print("round trip json={s} json5={s}\n", .{ c.json, out });
            return err;
        };
    }
}

test "non-finite and -0 floats (reference String(number))" {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const want = [_]struct { f: f64, s: []const u8 }{
        .{ .f = nan, .s = "NaN" },
        .{ .f = inf, .s = "Infinity" },
        .{ .f = -inf, .s = "-Infinity" },
        .{ .f = -0.0, .s = "0" },
        .{ .f = @as(f64, 0.1) + @as(f64, 0.2), .s = "0.30000000000000004" },
        .{ .f = 1e21, .s = "1e+21" },
        .{ .f = 1e20, .s = "100000000000000000000" },
        .{ .f = 1.5e-7, .s = "1.5e-7" },
        .{ .f = -123.456, .s = "-123.456" },
    };
    for (want) |c| {
        const a = try renderAny(c.f, .{});
        defer testing.allocator.free(a);
        try testing.expectEqualStrings(c.s, a);
        const b = try render(.{ .float = c.f }, .{});
        defer testing.allocator.free(b);
        try testing.expectEqualStrings(c.s, b);
    }
    const f32s = try renderAny(@as(f32, 0.1), .{});
    defer testing.allocator.free(f32s);
    try testing.expectEqualStrings("0.1", f32s);
}

test "non-finite literals round trip under non_finite = .quoted" {
    const root = @import("root.zig");
    const out = try renderAny([_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64) }, .{});
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("[NaN,Infinity,-Infinity]", out);
    const plain = try root.preprocessWithOptions(testing.allocator, out, .{ .non_finite = .quoted });
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("[\"NaN\",\"Infinity\",\"-Infinity\"]", plain);
}

// Hand-derived from the reference's rules (not captured): the options the
// reference has no switch for.
test "options: trailing_commas, unquoted_keys" {
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, "{\"a\":[1,{\"b b\":2}],\"c\":{}}", .{});
    defer parsed.deinit();
    const a = try render(parsed.value, .{ .indent = 2, .trailing_commas = false });
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("{\n  a: [\n    1,\n    {\n      'b b': 2\n    }\n  ],\n  c: {}\n}", a);
    const b = try render(parsed.value, .{ .unquoted_keys = false });
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("{'a':[1,{'b b':2}],'c':{}}", b);
    // Compact output never carries a trailing comma.
    const c = try render(parsed.value, .{ .trailing_commas = true });
    defer testing.allocator.free(c);
    try testing.expectEqualStrings("{a:[1,{'b b':2}],c:{}}", c);
}

// Hand-derived: this writer quotes non-ASCII keys, the reference leaves them bare.
test "deviation: non-ASCII key is quoted" {
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, "{\"é\":1}", .{});
    defer parsed.deinit();
    const a = try render(parsed.value, .{});
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("{'é':1}", a);
}

test "write: structs, optionals, enums, slices, tuples, unions" {
    const Color = enum { red, green };
    const U = union(enum) { n: u8, none, s: []const u8 };
    const S = struct {
        name: []const u8,
        count: u32,
        ratio: f64,
        tags: []const []const u8,
        maybe: ?u8,
        color: Color,
        pair: struct { i8, bool },
        u: U,
        raw: [3]u8,
    };
    const v: S = .{
        .name = "it's",
        .count = 7,
        .ratio = 0.5,
        .tags = &.{ "a", "b c" },
        .maybe = null,
        .color = .green,
        .pair = .{ -1, true },
        .u = .{ .s = "x" },
        .raw = "abc".*,
    };
    const compact = try renderAny(v, .{});
    defer testing.allocator.free(compact);
    try testing.expectEqualStrings(
        "{name:\"it's\",count:7,ratio:0.5,tags:['a','b c'],maybe:null,color:'green',pair:[-1,true],u:{s:'x'},raw:'abc'}",
        compact,
    );
    const pretty = try renderAny(.{ .u = U{ .none = {} }, .m = @as(?u8, 3), .l = &[_]u8{} }, .{ .indent = 2 });
    defer testing.allocator.free(pretty);
    try testing.expectEqualStrings("{\n  u: {\n    none: {},\n  },\n  m: 3,\n  l: '',\n}", pretty);
    const val = try renderAny(std.json.Value{ .string = "q" }, .{ .quote = .double });
    defer testing.allocator.free(val);
    try testing.expectEqualStrings("\"q\"", val);
}
