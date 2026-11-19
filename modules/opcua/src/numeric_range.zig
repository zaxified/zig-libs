// SPDX-License-Identifier: MIT

//! NumericRange (OPC 10000-4 §7.27): the `IndexRange` string of a Read /
//! Write operand, which selects part of an array value (or of a String /
//! ByteString) instead of the whole value.
//!
//! Grammar (§7.27):
//!
//!     numeric-range ::= dimension [',' dimension]*
//!     dimension     ::= index [':' index]
//!     index         ::= digit+                  (an unsigned 32-bit number)
//!
//! `a` selects one element; `a:b` selects the inclusive range, and the spec
//! requires `a < b` (so `3:3` and `5:2` are syntax errors; a single element is
//! just `3`). The first dimension is the outermost (row-major flat storage,
//! the way `VariantArray.items` lays a multi-dimensional array out).
//!
//! Behaviour follows the spec and, where the spec is silent, open62541's
//! (`UA_NumericRange_parse`, `checkAdjustRange`, `UA_Variant_copyRange`,
//! `Variant_setRange`; behavioural reference only, nothing copied):
//!   - syntax error, `a >= b`, a number above 2^32-1 -> `IndexRangeInvalid`;
//!   - the range's dimension count differs from the value's -> `NoData`;
//!   - Read: a range reaching past the end is clipped to the array, a range
//!     that starts past the end (or any range on an empty/null value, or on a
//!     scalar other than String/ByteString/XmlElement) -> `NoData`;
//!   - Write: the range must lie inside the stored array (a write never grows
//!     it) -> else `NoData`; the new value must have exactly as many
//!     elements as the range selects -> else `IndexRangeInvalid`; element type
//!     must equal the stored one -> else `TypeMismatch`;
//!   - an array of Strings/ByteStrings takes one extra trailing dimension that
//!     selects bytes inside each selected element (Read only; the matching
//!     Write is `WriteNotSupported`).
//!
//! The range text is untrusted: it is capped at `max_text_len` bytes and
//! `max_dims` dimensions, every index is a `u32`, all arithmetic is `u64`, and
//! nothing is allocated in proportion to an index -- only in proportion to
//! the number of elements actually selected, which the stored array bounds.

const std = @import("std");
const encoding = @import("encoding.zig");

pub const max_text_len = 256;
pub const max_dims = 16;
/// Longest text `Range.format` can produce: 16 x (`4294967295:4294967295` + `,`).
pub const max_format_len = max_dims * 22;

pub const ParseError = error{IndexRangeInvalid};

/// One dimension: inclusive `min..max`. `min == max` is the single index `n`.
pub const Dim = struct { min: u32, max: u32 };

pub const Range = struct {
    n: u8 = 0,
    dims: [max_dims]Dim = undefined,

    pub fn slice(r: *const Range) []const Dim {
        return r.dims[0..r.n];
    }

    /// Build a range from dimensions (the client side). `min > max` or an
    /// empty/over-long list is `IndexRangeInvalid`; `min == max` is a single
    /// index.
    pub fn init(dims: []const Dim) ParseError!Range {
        if (dims.len == 0 or dims.len > max_dims) return error.IndexRangeInvalid;
        var r: Range = .{ .n = @intCast(dims.len) };
        for (dims, 0..) |d, i| {
            if (d.min > d.max) return error.IndexRangeInvalid;
            r.dims[i] = d;
        }
        return r;
    }

    /// The wire text (`"0:1,2"`), into `buf` (`max_format_len` always suffices).
    pub fn format(r: *const Range, buf: []u8) error{NoSpaceLeft}![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        for (r.slice(), 0..) |d, i| {
            if (i != 0) w.writeByte(',') catch return error.NoSpaceLeft;
            if (d.min == d.max) {
                w.print("{d}", .{d.min}) catch return error.NoSpaceLeft;
            } else {
                w.print("{d}:{d}", .{ d.min, d.max }) catch return error.NoSpaceLeft;
            }
        }
        return w.buffered();
    }
};

fn readIndex(text: []const u8, pos: *usize) ParseError!u32 {
    var i = pos.*;
    var v: u64 = 0;
    const first = i;
    while (i < text.len and text[i] >= '0' and text[i] <= '9') : (i += 1) {
        v = v * 10 + (text[i] - '0');
        if (v > std.math.maxInt(u32)) return error.IndexRangeInvalid;
    }
    if (i == first) return error.IndexRangeInvalid;
    pos.* = i;
    return @intCast(v);
}

/// Parse a non-empty `IndexRange` string. (An empty string means "no range"
/// and is the caller's business.)
pub fn parse(text: []const u8) ParseError!Range {
    if (text.len == 0 or text.len > max_text_len) return error.IndexRangeInvalid;
    var r: Range = .{};
    var pos: usize = 0;
    while (true) {
        if (r.n == max_dims) return error.IndexRangeInvalid;
        const lo = try readIndex(text, &pos);
        var hi = lo;
        if (pos < text.len and text[pos] == ':') {
            pos += 1;
            hi = try readIndex(text, &pos);
            if (lo >= hi) return error.IndexRangeInvalid;
        }
        r.dims[r.n] = .{ .min = lo, .max = hi };
        r.n += 1;
        if (pos == text.len) return r;
        if (text[pos] != ',') return error.IndexRangeInvalid;
        pos += 1;
    }
}

pub const ApplyError = error{ OutOfMemory, IndexRangeInvalid, IndexRangeNoData };
pub const WriteError = ApplyError || error{ TypeMismatch, WriteNotSupported };

/// The elements a range selects out of a (possibly multi-dimensional) array
/// stored flat in row-major order, produced one flat index at a time.
pub const Selection = struct {
    n: usize,
    start: [max_dims]u64 = undefined,
    count: [max_dims]u64 = undefined,
    stride: [max_dims]u64 = undefined,
    pos: [max_dims]u64 = @splat(0),
    total: u64,
    emitted: u64 = 0,

    pub fn next(s: *Selection) ?usize {
        if (s.emitted == s.total) return null;
        var flat: u64 = 0;
        for (0..s.n) |d| flat += (s.start[d] + s.pos[d]) * s.stride[d];
        s.emitted += 1;
        var d = s.n;
        while (d > 0) {
            d -= 1;
            s.pos[d] += 1;
            if (s.pos[d] < s.count[d]) break;
            s.pos[d] = 0;
        }
        return @intCast(flat);
    }
};

const Mode = enum { read, write };

/// Resolve `range` against an array whose dimension lengths are `lens`
/// (`range.n == lens.len` is the caller's check). Read clips, write is exact.
fn select(range: *const Range, lens: []const u64, mode: Mode) error{IndexRangeNoData}!Selection {
    std.debug.assert(range.n == lens.len);
    var s: Selection = .{ .n = lens.len, .total = 1 };
    for (range.slice(), lens, 0..) |d, len, i| {
        if (d.min >= len) return error.IndexRangeNoData;
        var max: u64 = d.max;
        if (max >= len) {
            if (mode == .write) return error.IndexRangeNoData;
            max = len - 1;
        }
        s.start[i] = d.min;
        s.count[i] = max - d.min + 1;
        s.total *= s.count[i];
    }
    var stride: u64 = 1;
    var i = lens.len;
    while (i > 0) {
        i -= 1;
        s.stride[i] = stride;
        stride *= lens[i];
    }
    return s;
}

/// The array's dimension lengths: the `dimensions` field when it is usable
/// (1..max_dims positive entries whose product is the element count), else
/// one flat dimension.
fn arrayLens(arr: encoding.VariantArray, len: usize, buf: *[max_dims]u64) []const u64 {
    if (arr.dimensions) |dims| flat: {
        if (dims.len == 0 or dims.len > max_dims) break :flat;
        var prod: u64 = 1;
        for (dims, 0..) |d, i| {
            if (d <= 0) break :flat;
            buf[i] = @intCast(d);
            prod *= buf[i];
            if (prod > len) break :flat;
        }
        if (prod != len) break :flat;
        return buf[0..dims.len];
    }
    buf[0] = len;
    return buf[0..1];
}

fn isStringLike(comptime tag: anytype) bool {
    return comptime std.mem.eql(u8, @tagName(tag), "string") or
        std.mem.eql(u8, @tagName(tag), "byte_string") or
        std.mem.eql(u8, @tagName(tag), "xml_element");
}

fn subBytes(s: ?[]const u8, d: Dim, mode: Mode) error{IndexRangeNoData}![]const u8 {
    const bytes = s orelse return error.IndexRangeNoData;
    if (d.min >= bytes.len) return error.IndexRangeNoData;
    var max: u64 = d.max;
    if (max >= bytes.len) {
        if (mode == .write) return error.IndexRangeNoData;
        max = bytes.len - 1;
    }
    return bytes[d.min .. max + 1];
}

/// Apply `range` to a value for Read. The result borrows the elements of `v`
/// (strings, ExtensionObjects, ...) and allocates only the new element slice
/// (and dimension list) from `arena`.
pub fn readRange(arena: std.mem.Allocator, v: encoding.Variant, range: *const Range) ApplyError!encoding.Variant {
    switch (v) {
        .empty => return error.IndexRangeNoData,
        .scalar => |sc| switch (sc) {
            inline .string, .byte_string, .xml_element => |s, tag| {
                if (range.n != 1) return error.IndexRangeNoData;
                const sub = try subBytes(s, range.dims[0], .read);
                return .{ .scalar = @unionInit(encoding.VariantScalar, @tagName(tag), sub) };
            },
            else => return error.IndexRangeNoData,
        },
        .array => |arr| switch (arr.items) {
            inline else => |maybe, tag| {
                const src = maybe orelse return error.IndexRangeNoData;
                var lbuf: [max_dims]u64 = undefined;
                const lens = arrayLens(arr, src.len, &lbuf);
                const Elem = @typeInfo(@TypeOf(src)).pointer.child;
                var out_dims: ?[]const i32 = null;
                var out: []Elem = undefined;
                if (range.n == lens.len) {
                    var sel = try select(range, lens, .read);
                    out = try arena.alloc(Elem, @intCast(sel.total));
                    var k: usize = 0;
                    while (sel.next()) |ix| : (k += 1) out[k] = src[ix];
                    if (lens.len > 1) out_dims = try countsAsDims(arena, &sel);
                } else if (comptime isStringLike(tag)) {
                    if (range.n != lens.len + 1) return error.IndexRangeNoData;
                    const outer: Range = .{ .n = @intCast(lens.len), .dims = range.dims };
                    var sel = try select(&outer, lens, .read);
                    out = try arena.alloc(Elem, @intCast(sel.total));
                    var k: usize = 0;
                    const last = range.dims[lens.len];
                    while (sel.next()) |ix| : (k += 1) out[k] = try subBytes(src[ix], last, .read);
                    if (lens.len > 1) out_dims = try countsAsDims(arena, &sel);
                } else return error.IndexRangeNoData;
                return .{ .array = .{
                    .items = @unionInit(encoding.VariantArrayItems, @tagName(tag), out),
                    .dimensions = out_dims,
                } };
            },
        },
    }
}

fn countsAsDims(arena: std.mem.Allocator, sel: *const Selection) std.mem.Allocator.Error![]const i32 {
    const dims = try arena.alloc(i32, sel.n);
    for (dims, 0..) |*d, i| d.* = @intCast(sel.count[i]);
    return dims;
}

/// Apply a ranged Write: the value `stored` with the range replaced by the
/// elements of `incoming`. The result (and its element slice) is built in
/// `tmp` and borrows everything else from `stored`/`incoming`: deep-copy it
/// before keeping it.
pub fn writeRange(tmp: std.mem.Allocator, stored: encoding.Variant, incoming: encoding.Variant, range: *const Range) WriteError!encoding.Variant {
    switch (stored) {
        .empty => return error.IndexRangeInvalid,
        .scalar => |sc| switch (sc) {
            inline .string, .byte_string, .xml_element => |s, tag| {
                const inc = switch (incoming) {
                    .scalar => |isc| switch (isc) {
                        tag => |x| x,
                        else => return error.TypeMismatch,
                    },
                    else => return error.TypeMismatch,
                };
                if (range.n != 1) return error.IndexRangeNoData;
                const old = s orelse return error.IndexRangeNoData;
                const d = range.dims[0];
                if (d.max >= old.len) return error.IndexRangeNoData;
                const new_bytes = inc orelse return error.IndexRangeInvalid;
                if (new_bytes.len != @as(u64, d.max) - d.min + 1) return error.IndexRangeInvalid;
                const buf = try tmp.dupe(u8, old);
                @memcpy(buf[d.min..][0..new_bytes.len], new_bytes);
                return .{ .scalar = @unionInit(encoding.VariantScalar, @tagName(tag), buf) };
            },
            else => return error.IndexRangeNoData,
        },
        .array => |arr| switch (arr.items) {
            inline else => |maybe, tag| {
                const Elem = @typeInfo(@TypeOf(maybe.?)).pointer.child;
                var one: [1]Elem = undefined;
                const inc: []const Elem = switch (incoming) {
                    .empty => return error.TypeMismatch,
                    .array => |ia| if (std.meta.activeTag(ia.items) == tag)
                        (@field(ia.items, @tagName(tag)) orelse return error.IndexRangeInvalid)
                    else
                        return error.TypeMismatch,
                    .scalar => |isc| blk: {
                        if (std.meta.activeTag(isc) != @field(std.meta.Tag(encoding.VariantScalar), @tagName(tag))) return error.TypeMismatch;
                        one[0] = @field(isc, @tagName(tag));
                        break :blk one[0..];
                    },
                };
                const src = maybe orelse return error.IndexRangeInvalid;
                var lbuf: [max_dims]u64 = undefined;
                const lens = arrayLens(arr, src.len, &lbuf);
                if (range.n != lens.len) {
                    if (comptime isStringLike(tag)) {
                        if (range.n == lens.len + 1) return error.WriteNotSupported;
                    }
                    return error.IndexRangeNoData;
                }
                var sel = try select(range, lens, .write);
                if (inc.len != sel.total) return error.IndexRangeInvalid;
                const out = try tmp.dupe(Elem, src);
                var k: usize = 0;
                while (sel.next()) |ix| : (k += 1) out[ix] = inc[k];
                return .{ .array = .{
                    .items = @unionInit(encoding.VariantArrayItems, @tagName(tag), out),
                    .dimensions = arr.dimensions,
                } };
            },
        },
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectParse(text: []const u8, want: []const Dim) !void {
    const r = try parse(text);
    try testing.expectEqual(want.len, r.slice().len);
    for (want, r.slice()) |w, g| {
        try testing.expectEqual(w.min, g.min);
        try testing.expectEqual(w.max, g.max);
    }
}

test "parse: valid ranges" {
    try expectParse("0", &.{.{ .min = 0, .max = 0 }});
    try expectParse("7", &.{.{ .min = 7, .max = 7 }});
    try expectParse("1:3", &.{.{ .min = 1, .max = 3 }});
    try expectParse("0:1,2:3", &.{ .{ .min = 0, .max = 1 }, .{ .min = 2, .max = 3 } });
    try expectParse("4,0:9,2", &.{ .{ .min = 4, .max = 4 }, .{ .min = 0, .max = 9 }, .{ .min = 2, .max = 2 } });
    try expectParse("007:010", &.{.{ .min = 7, .max = 10 }}); // the grammar allows leading zeros
    try expectParse("4294967295", &.{.{ .min = 4294967295, .max = 4294967295 }});
    try expectParse("0:4294967295", &.{.{ .min = 0, .max = 4294967295 }});
}

test "parse: invalid ranges" {
    const bad = [_][]const u8{
        "",           ":",            "1:",                   ":1",    "1:2:3", ",",   "1,", ",1",  "1,,2", "1:3,",
        "-1",         "+1",           "1 ",                   " 1",    "1.5",   "0x1", "a",  "1:b", "3:3",  "5:2",
        "1;2",        "1 : 2",        "1:2 ,3",               "1\x00",
        "٣",
        "4294967296", "0:4294967296", "99999999999999999999",
    };
    for (bad) |t| try testing.expectError(error.IndexRangeInvalid, parse(t));
}

test "parse: bounded length and dimension count" {
    var buf: [max_text_len + 8]u8 = undefined;
    // exactly max_dims dimensions parse, one more does not
    var w: std.Io.Writer = .fixed(&buf);
    for (0..max_dims) |i| {
        if (i != 0) try w.writeByte(',');
        try w.writeByte('1');
    }
    try testing.expectEqual(@as(u8, max_dims), (try parse(w.buffered())).n);
    try w.writeAll(",1");
    try testing.expectError(error.IndexRangeInvalid, parse(w.buffered()));
    // over-long text, even if every character is a valid digit
    @memset(buf[0 .. max_text_len + 1], '1');
    try testing.expectError(error.IndexRangeInvalid, parse(buf[0 .. max_text_len + 1]));
    // within the length cap a long digit run is still bounded by u32
    try testing.expectError(error.IndexRangeInvalid, parse(buf[0..max_text_len]));
}

test "format round-trips parse" {
    var buf: [max_format_len]u8 = undefined;
    for ([_][]const u8{ "0", "5", "1:3", "0:1,2:3", "4,0:9,2", "0:4294967295,4294967295" }) |t| {
        const r = try parse(t);
        try testing.expectEqualStrings(t, try r.format(&buf));
    }
    const r = try Range.init(&.{ .{ .min = 2, .max = 2 }, .{ .min = 0, .max = 3 } });
    try testing.expectEqualStrings("2,0:3", try r.format(&buf));
    try testing.expectError(error.IndexRangeInvalid, Range.init(&.{.{ .min = 3, .max = 2 }}));
    try testing.expectError(error.IndexRangeInvalid, Range.init(&.{}));
    var small: [2]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, r.format(&small));
    // the worst case really fits max_format_len
    var dims: [max_dims]Dim = @splat(.{ .min = 4294967294, .max = 4294967295 });
    const worst = try Range.init(&dims);
    try testing.expectEqual(@as(usize, max_dims * 22 - 1), (try worst.format(&buf)).len);
}

fn arrOf(comptime tag: []const u8, items: anytype) encoding.Variant {
    return .{ .array = .{ .items = @unionInit(encoding.VariantArrayItems, tag, items) } };
}

test "readRange: 1-D array, single, range, clipping, no data" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const v = arrOf("int32", @as(?[]const i32, &.{ 10, 11, 12, 13, 14 }));
    const one = try readRange(a.allocator(), v, &try parse("2"));
    try testing.expectEqualSlices(i32, &.{12}, one.array.items.int32.?);
    const mid = try readRange(a.allocator(), v, &try parse("1:3"));
    try testing.expectEqualSlices(i32, &.{ 11, 12, 13 }, mid.array.items.int32.?);
    try testing.expectEqual(@as(?[]const i32, null), mid.array.dimensions);
    const all = try readRange(a.allocator(), v, &try parse("0:4"));
    try testing.expectEqualSlices(i32, &.{ 10, 11, 12, 13, 14 }, all.array.items.int32.?);
    // clipped: 3:100 -> 3..4
    const clip = try readRange(a.allocator(), v, &try parse("3:100"));
    try testing.expectEqualSlices(i32, &.{ 13, 14 }, clip.array.items.int32.?);
    const last = try readRange(a.allocator(), v, &try parse("4:5"));
    try testing.expectEqualSlices(i32, &.{14}, last.array.items.int32.?);
    // starts past the end
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("5")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("5:9")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("4294967295")));
    // wrong number of dimensions
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("0,0")));
    // empty / null array, zero-length array
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), .empty, &try parse("0")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), arrOf("int32", @as(?[]const i32, null)), &try parse("0")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), arrOf("int32", @as(?[]const i32, &.{})), &try parse("0")));
}

test "readRange: 2-D array keeps row-major order and reports dimensions" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    // 3 x 4:  row r, column c -> 10*r + c
    const data = [_]i32{ 0, 1, 2, 3, 10, 11, 12, 13, 20, 21, 22, 23 };
    const dims = [_]i32{ 3, 4 };
    const v: encoding.Variant = .{ .array = .{ .items = .{ .int32 = &data }, .dimensions = &dims } };
    const blk = try readRange(a.allocator(), v, &try parse("1:2,1:3"));
    try testing.expectEqualSlices(i32, &.{ 11, 12, 13, 21, 22, 23 }, blk.array.items.int32.?);
    try testing.expectEqualSlices(i32, &.{ 2, 3 }, blk.array.dimensions.?);
    const cell = try readRange(a.allocator(), v, &try parse("2,0"));
    try testing.expectEqualSlices(i32, &.{20}, cell.array.items.int32.?);
    try testing.expectEqualSlices(i32, &.{ 1, 1 }, cell.array.dimensions.?);
    // each dimension is clipped on its own
    const clip = try readRange(a.allocator(), v, &try parse("2:9,3:9"));
    try testing.expectEqualSlices(i32, &.{23}, clip.array.items.int32.?);
    // one dimension out of bounds is enough for NoData
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("0,4")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("3,0")));
    // a 1-D range on a 2-D array: dimension count differs
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v, &try parse("0:1")));
    // dimensions that do not multiply to the length are ignored (flat array)
    const bad_dims = [_]i32{ 5, 5 };
    const flat: encoding.Variant = .{ .array = .{ .items = .{ .int32 = &data }, .dimensions = &bad_dims } };
    const f = try readRange(a.allocator(), flat, &try parse("10:11"));
    try testing.expectEqualSlices(i32, &.{ 22, 23 }, f.array.items.int32.?);
}

test "readRange: strings, byte strings and scalars" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const s: encoding.Variant = .{ .scalar = .{ .string = "abcdef" } };
    try testing.expectEqualStrings("bcd", (try readRange(a.allocator(), s, &try parse("1:3"))).scalar.string.?);
    try testing.expectEqualStrings("f", (try readRange(a.allocator(), s, &try parse("5"))).scalar.string.?);
    try testing.expectEqualStrings("ef", (try readRange(a.allocator(), s, &try parse("4:50"))).scalar.string.?);
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), s, &try parse("6")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), s, &try parse("0,0")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), .{ .scalar = .{ .string = null } }, &try parse("0")));
    const bs: encoding.Variant = .{ .scalar = .{ .byte_string = "\x00\x01\x02" } };
    try testing.expectEqualStrings("\x01\x02", (try readRange(a.allocator(), bs, &try parse("1:2"))).scalar.byte_string.?);
    // other scalars carry no range
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), .{ .scalar = .{ .int32 = 1 } }, &try parse("0")));
    // array of strings: one dimension selects elements, a second one the bytes
    const strs = arrOf("string", @as(?[]const ?[]const u8, &.{ "alpha", "beta", "gamma" }));
    const els = try readRange(a.allocator(), strs, &try parse("1:2"));
    try testing.expectEqualStrings("beta", els.array.items.string.?[0].?);
    try testing.expectEqualStrings("gamma", els.array.items.string.?[1].?);
    const subs = try readRange(a.allocator(), strs, &try parse("0:1,1:2"));
    try testing.expectEqualStrings("lp", subs.array.items.string.?[0].?);
    try testing.expectEqualStrings("et", subs.array.items.string.?[1].?);
    // a selected element too short for the byte range: no data for the whole request
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), strs, &try parse("0:2,4")));
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), strs, &try parse("0,1,1")));
    // a 2-D array of non-string elements takes no third dimension
    const dims = [_]i32{ 1, 2 };
    const ints: encoding.Variant = .{ .array = .{ .items = .{ .int32 = &.{ 1, 2 } }, .dimensions = &dims } };
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), ints, &try parse("0,0,0")));
}

test "readRange: every element type" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const q: []const encoding.QualifiedName = &.{ .{ .namespace_index = 0, .name = "a" }, .{ .namespace_index = 1, .name = "b" } };
    const r = try readRange(a.allocator(), arrOf("qualified_name", @as(?[]const encoding.QualifiedName, q)), &try parse("1"));
    try testing.expectEqualStrings("b", r.array.items.qualified_name.?[0].name.?);
    const d: []const f64 = &.{ 1.5, 2.5 };
    const rd = try readRange(a.allocator(), arrOf("double", @as(?[]const f64, d)), &try parse("0:1"));
    try testing.expectEqualSlices(f64, d, rd.array.items.double.?);
}

test "readRange: no allocation proportional to an index" {
    // a 4 GiB-ish index against a 3-element array must be a NoData without
    // allocating anything (a failing allocator would turn any attempt into OOM)
    const v = arrOf("byte", @as(?[]const u8, &.{ 1, 2, 3 }));
    try testing.expectError(error.IndexRangeNoData, readRange(testing.failing_allocator, v, &try parse("0:4294967295,0")));
    try testing.expectError(error.IndexRangeNoData, readRange(testing.failing_allocator, v, &try parse("4294967290:4294967295")));
    // the clipped selection is bounded by the array: 3 elements
    var buf: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const got = try readRange(fba.allocator(), v, &try parse("0:4294967295"));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, got.array.items.byte.?);
}

test "writeRange: 1-D array" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const stored = arrOf("int32", @as(?[]const i32, &.{ 1, 2, 3, 4, 5 }));
    const w = try writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, &.{ 20, 30 })), &try parse("1:2"));
    try testing.expectEqualSlices(i32, &.{ 1, 20, 30, 4, 5 }, w.array.items.int32.?);
    // the stored array is untouched
    try testing.expectEqualSlices(i32, &.{ 1, 2, 3, 4, 5 }, stored.array.items.int32.?);
    // a scalar of the same type writes a single element
    const one = try writeRange(a.allocator(), stored, .{ .scalar = .{ .int32 = 99 } }, &try parse("4"));
    try testing.expectEqualSlices(i32, &.{ 1, 2, 3, 4, 99 }, one.array.items.int32.?);
    // the full array
    const full = try writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, &.{ 9, 9, 9, 9, 9 })), &try parse("0:4"));
    try testing.expectEqualSlices(i32, &.{ 9, 9, 9, 9, 9 }, full.array.items.int32.?);
    // out of bounds: a write never grows the array
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), stored, .{ .scalar = .{ .int32 = 1 } }, &try parse("5")));
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, &.{ 1, 2 })), &try parse("4:5")));
    // element count differs from the range
    try testing.expectError(error.IndexRangeInvalid, writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, &.{ 1, 2, 3 })), &try parse("1:2")));
    try testing.expectError(error.IndexRangeInvalid, writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, &.{1})), &try parse("1:2")));
    try testing.expectError(error.IndexRangeInvalid, writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, null)), &try parse("1")));
    // element type differs
    try testing.expectError(error.TypeMismatch, writeRange(a.allocator(), stored, .{ .scalar = .{ .uint32 = 1 } }, &try parse("1")));
    try testing.expectError(error.TypeMismatch, writeRange(a.allocator(), stored, arrOf("int16", @as(?[]const i16, &.{1})), &try parse("1")));
    try testing.expectError(error.TypeMismatch, writeRange(a.allocator(), stored, .empty, &try parse("1")));
    // dimension count differs
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), stored, .{ .scalar = .{ .int32 = 1 } }, &try parse("0,0")));
    // nothing stored
    try testing.expectError(error.IndexRangeInvalid, writeRange(a.allocator(), .empty, .{ .scalar = .{ .int32 = 1 } }, &try parse("0")));
    try testing.expectError(error.IndexRangeInvalid, writeRange(a.allocator(), arrOf("int32", @as(?[]const i32, null)), .{ .scalar = .{ .int32 = 1 } }, &try parse("0")));
}

test "writeRange: 2-D array and dimensions are kept" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const data = [_]i32{ 0, 1, 2, 3, 10, 11, 12, 13, 20, 21, 22, 23 };
    const dims = [_]i32{ 3, 4 };
    const stored: encoding.Variant = .{ .array = .{ .items = .{ .int32 = &data }, .dimensions = &dims } };
    const w = try writeRange(a.allocator(), stored, arrOf("int32", @as(?[]const i32, &.{ -1, -2, -3, -4 })), &try parse("1:2,1:2"));
    try testing.expectEqualSlices(i32, &.{ 0, 1, 2, 3, 10, -1, -2, 13, 20, -3, -4, 23 }, w.array.items.int32.?);
    try testing.expectEqualSlices(i32, &dims, w.array.dimensions.?);
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), stored, .{ .scalar = .{ .int32 = 1 } }, &try parse("0,4")));
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), stored, .{ .scalar = .{ .int32 = 1 } }, &try parse("0")));
}

test "writeRange: strings" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const s: encoding.Variant = .{ .scalar = .{ .string = "abcdef" } };
    const w = try writeRange(a.allocator(), s, .{ .scalar = .{ .string = "XY" } }, &try parse("1:2"));
    try testing.expectEqualStrings("aXYdef", w.scalar.string.?);
    try testing.expectError(error.IndexRangeInvalid, writeRange(a.allocator(), s, .{ .scalar = .{ .string = "X" } }, &try parse("1:2")));
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), s, .{ .scalar = .{ .string = "XY" } }, &try parse("5:6")));
    try testing.expectError(error.TypeMismatch, writeRange(a.allocator(), s, .{ .scalar = .{ .byte_string = "XY" } }, &try parse("0:1")));
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), .{ .scalar = .{ .int32 = 1 } }, .{ .scalar = .{ .int32 = 1 } }, &try parse("0")));
    // an element of a string array is written as a whole element; a byte range
    // inside an element is a partial write this module does not support
    const strs = arrOf("string", @as(?[]const ?[]const u8, &.{ "alpha", "beta" }));
    const e = try writeRange(a.allocator(), strs, .{ .scalar = .{ .string = "ZZ" } }, &try parse("1"));
    try testing.expectEqualStrings("alpha", e.array.items.string.?[0].?);
    try testing.expectEqualStrings("ZZ", e.array.items.string.?[1].?);
    try testing.expectError(error.WriteNotSupported, writeRange(a.allocator(), strs, .{ .scalar = .{ .string = "Z" } }, &try parse("1,0")));
    try testing.expectError(error.IndexRangeNoData, writeRange(a.allocator(), strs, .{ .scalar = .{ .string = "Z" } }, &try parse("1,0,0")));
}

test "Selection visits row-major, once each" {
    const lens = [_]u64{ 2, 3, 4 };
    var sel = try select(&try parse("0:1,1:2,0:3"), &lens, .read);
    var seen: [24]bool = @splat(false);
    var prev: ?usize = null;
    while (sel.next()) |ix| {
        try testing.expect(!seen[ix]);
        seen[ix] = true;
        if (prev) |p| try testing.expect(ix > p);
        prev = ix;
    }
    var n: usize = 0;
    for (seen, 0..) |s, i| {
        const inside = (i / 4) % 3 >= 1;
        try testing.expectEqual(inside, s);
        if (s) n += 1;
    }
    try testing.expectEqual(@as(usize, 16), n);
}

test "readRange: unusable dimensions fall back to a flat array without overflowing" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const data = [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    // product smaller than the length
    const short = [_]i32{ 2, 3 };
    const v1: encoding.Variant = .{ .array = .{ .items = .{ .int32 = &data }, .dimensions = &short } };
    try testing.expectError(error.IndexRangeNoData, readRange(a.allocator(), v1, &try parse("0:1,0:2")));
    try testing.expectEqualSlices(i32, &.{ 10, 11 }, (try readRange(a.allocator(), v1, &try parse("10:11"))).array.items.int32.?);
    // a product that would overflow u64 if it were not cut short
    const huge = [_]i32{ 1 << 30, 1 << 30, 1 << 30, 1 << 30 };
    const v2: encoding.Variant = .{ .array = .{ .items = .{ .int32 = data[0..4] }, .dimensions = &huge } };
    try testing.expectEqualSlices(i32, &.{ 1, 2 }, (try readRange(a.allocator(), v2, &try parse("1:2"))).array.items.int32.?);
    // more dimensions than a range can have
    const many: [max_dims + 1]i32 = @splat(1);
    const v3: encoding.Variant = .{ .array = .{ .items = .{ .int32 = data[0..1] }, .dimensions = &many } };
    try testing.expectEqualSlices(i32, &.{0}, (try readRange(a.allocator(), v3, &try parse("0"))).array.items.int32.?);
    // negative and zero entries
    const neg = [_]i32{ -3, -4 };
    const v4: encoding.Variant = .{ .array = .{ .items = .{ .int32 = data[0..12] }, .dimensions = &neg } };
    try testing.expectEqualSlices(i32, &.{ 3, 4 }, (try readRange(a.allocator(), v4, &try parse("3:4"))).array.items.int32.?);
}

test "parse: the length cap counts bytes, not digits' value" {
    var buf: [max_text_len + 1]u8 = undefined;
    @memset(&buf, '0');
    try expectParse(buf[0..max_text_len], &.{.{ .min = 0, .max = 0 }});
    try testing.expectError(error.IndexRangeInvalid, parse(buf[0 .. max_text_len + 1]));
}
