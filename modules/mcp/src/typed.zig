// SPDX-License-Identifier: MIT
//! Typed tools: a JSON Schema derived from a Zig type at compile time
//! (`schemaOf`), and the matching decoder from a `tools/call` arguments value
//! into that type (`parse`, surfaced as `ToolCall.argsAs`). This is the Zig
//! counterpart of the Go SDK's `mcp.AddTool[In, Out]` (schema inference through
//! google/jsonschema-go), the TypeScript SDK's zod schemas and the Python SDK's
//! type hints.
//!
//! Mapping (the subset `schema_check` validates):
//!
//!   - struct -> `{"type":"object","properties":{..},"required":[..],
//!     "additionalProperties":false}`; required = fields that are neither `?T`
//!     nor have a default value; no `required` key when there is none;
//!   - bool -> boolean; floats -> number;
//!   - integers -> integer with `minimum`/`maximum` from the bit width, clamped
//!     to +-(2^53 - 1): JSON numbers are doubles in most peers, so a wider
//!     bound would promise values a peer cannot send exactly. `parse` enforces
//!     the same bounds;
//!   - `[]const u8` -> string; enum -> string with `enum` of the tag names;
//!   - `?T` -> the schema of `T`, not required (`parse` also takes JSON `null`
//!     for it, as `ToolCall.arg` does);
//!   - `[]const T` / `[]T` -> array with `items`; `[N]T` -> array with
//!     `minItems` = `maxItems` = N (`[N]u8` is an array of integers, not a
//!     string);
//!   - a struct may declare `pub const mcp_descriptions = .{ .field = "text" }`
//!     which becomes each property's `description`; a name that is not a field
//!     is a compile error.
//!
//! Compile errors (cannot be runtime tests): a pointer that is not a slice, a
//! `[]u8` that is not `[]const u8`, a union, `anytype`/`comptime_int`/other
//! unsupported type, a comptime field, an enum with no tag, a typo in
//! `mcp_descriptions`, a type nested deeper than `max_depth` (a recursive
//! type). Each names the offending field path.

const std = @import("std");

/// Nesting limit for `schemaOf`; a recursive type hits it and is a compile
/// error instead of an endless evaluation.
pub const max_depth: usize = 16;

/// JSON numbers are doubles on the wire for most peers: integers beyond this
/// magnitude are not exactly representable, so schemas and `parse` clamp to it.
pub const max_safe_int: comptime_int = 9007199254740991;

/// The JSON Schema text for `T`, comptime-known; plugs into
/// `Tool.input_schema` / `Tool.output_schema`. `inline` so the result is a
/// comptime-known operand of `++` at the call site.
pub inline fn schemaOf(comptime T: type) []const u8 {
    const s = comptime blk: {
        @setEvalBranchQuota(2_000_000);
        break :blk emit(T, @typeName(T), 0);
    };
    return s;
}

fn quote(comptime s: []const u8) []const u8 {
    comptime {
        var out: []const u8 = "\"";
        for (s) |c| {
            const piece: []const u8 = switch (c) {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                0...8, 11, 12, 14...31 => std.fmt.comptimePrint("\\u{x:0>4}", .{c}),
                else => &[_]u8{c},
            };
            out = out ++ piece;
        }
        return out ++ "\"";
    }
}

fn intLo(comptime T: type) comptime_int {
    return @max(std.math.minInt(T), -max_safe_int);
}

fn intHi(comptime T: type) comptime_int {
    return @min(std.math.maxInt(T), max_safe_int);
}

fn unsupported(comptime path: []const u8, comptime T: type, comptime why: []const u8) noreturn {
    @compileError("mcp typed: '" ++ path ++ "' of type " ++ @typeName(T) ++ ": " ++ why);
}

fn withDescription(comptime schema: []const u8, comptime desc: []const u8) []const u8 {
    // Every schema emitted here is an object literal ending in `}`.
    return schema[0 .. schema.len - 1] ++ ",\"description\":" ++ quote(desc) ++ "}";
}

fn emit(comptime T: type, comptime path: []const u8, comptime depth: usize) []const u8 {
    if (depth > max_depth) unsupported(path, T, "nested too deeply (a recursive type?)");
    switch (@typeInfo(T)) {
        .bool => return "{\"type\":\"boolean\"}",
        .int => return std.fmt.comptimePrint("{{\"type\":\"integer\",\"minimum\":{d},\"maximum\":{d}}}", .{ intLo(T), intHi(T) }),
        .float => return "{\"type\":\"number\"}",
        .optional => |o| return emit(o.child, path, depth + 1),
        .@"enum" => |e| {
            if (e.field_names.len == 0) unsupported(path, T, "an enum with no tag");
            var list: []const u8 = "";
            for (e.field_names, 0..) |n, i| list = list ++ (if (i == 0) "" else ",") ++ quote(n);
            return "{\"type\":\"string\",\"enum\":[" ++ list ++ "]}";
        },
        .pointer => |p| {
            if (p.size != .slice) unsupported(path, T, "only slices are supported pointers");
            if (p.child == u8) {
                if (!p.attrs.@"const") unsupported(path, T, "use []const u8");
                return "{\"type\":\"string\"}";
            }
            return "{\"type\":\"array\",\"items\":" ++ emit(p.child, path ++ "[]", depth + 1) ++ "}";
        },
        .array => |a| return "{\"type\":\"array\",\"items\":" ++ emit(a.child, path ++ "[]", depth + 1) ++
            std.fmt.comptimePrint(",\"minItems\":{d},\"maxItems\":{d}}}", .{ a.len, a.len }),
        .@"struct" => |info| {
            const has_desc = @hasDecl(T, "mcp_descriptions");
            if (has_desc) {
                const D = @TypeOf(T.mcp_descriptions);
                if (@typeInfo(D) != .@"struct") unsupported(path, T, "mcp_descriptions must be a struct literal");
                for (@typeInfo(D).@"struct".field_names) |dn| {
                    if (!@hasField(T, dn)) unsupported(path, T, "mcp_descriptions names '" ++ dn ++ "', which is not a field");
                }
            }
            var props: []const u8 = "";
            var req: []const u8 = "";
            for (info.field_names, info.field_types, 0..) |n, FT, i| {
                const a = info.field_attrs[i];
                if (a.@"comptime") unsupported(path ++ "." ++ n, FT, "comptime fields are not supported");
                var s = emit(FT, path ++ "." ++ n, depth + 1);
                if (has_desc and @hasField(@TypeOf(T.mcp_descriptions), n)) {
                    s = withDescription(s, @field(T.mcp_descriptions, n));
                }
                props = props ++ (if (props.len == 0) "" else ",") ++ quote(n) ++ ":" ++ s;
                if (!isOptional(FT) and a.default_value_ptr == null) {
                    req = req ++ (if (req.len == 0) "" else ",") ++ quote(n);
                }
            }
            return "{\"type\":\"object\",\"properties\":{" ++ props ++ "}" ++
                (if (req.len == 0) "" else ",\"required\":[" ++ req ++ "]") ++
                ",\"additionalProperties\":false}";
        },
        else => unsupported(path, T, "unsupported type"),
    }
}

fn isOptional(comptime T: type) bool {
    return @typeInfo(T) == .optional;
}

// ── decoding ────────────────────────────────────────────────────────────────

pub const ParseError = error{ InvalidArguments, OutOfMemory };

/// Why `parse` refused: a JSON Pointer to the offending value ("" = the
/// arguments object itself) and a message. Both live in the arena given to
/// `parse` (or are static).
pub const Failure = struct {
    pointer: []const u8 = "",
    message: []const u8 = "",
};

/// Decode `v` (a `tools/call` `arguments` value; `.null` counts as `{}`) into
/// `T`. Strings and slices point into `v` or the arena. Unknown properties,
/// missing required ones, wrong JSON types and out-of-range integers are
/// `error.InvalidArguments` with `fail` filled in. Nesting is bounded by the
/// type, so this cannot recurse deeper than `max_depth`.
pub fn parse(comptime T: type, arena: std.mem.Allocator, v: std.json.Value, fail: *Failure) ParseError!T {
    if (@typeInfo(T) != .@"struct") @compileError("mcp typed: the arguments type must be a struct, not " ++ @typeName(T));
    _ = comptime schemaOf(T); // reject unsupported types with the path-naming message
    fail.* = .{};
    const obj: std.json.Value = if (v == .null) .{ .object = .empty } else v;
    return decode(T, arena, obj, fail);
}

fn bad(fail: *Failure, msg: []const u8) error{InvalidArguments} {
    fail.message = msg;
    fail.pointer = "";
    return error.InvalidArguments;
}

fn under(arena: std.mem.Allocator, fail: *Failure, seg: []const u8) error{OutOfMemory}!void {
    fail.pointer = try arena.print("/{s}{s}", .{ seg, fail.pointer });
}

fn underIndex(arena: std.mem.Allocator, fail: *Failure, i: usize) error{OutOfMemory}!void {
    fail.pointer = try arena.print("/{d}{s}", .{ i, fail.pointer });
}

fn enumList(comptime T: type) []const u8 {
    comptime {
        var s: []const u8 = "must be one of ";
        for (@typeInfo(T).@"enum".field_names, 0..) |n, i| s = s ++ (if (i == 0) "" else ", ") ++ n;
        return s;
    }
}

fn defaultOf(comptime T: type, comptime i: usize) ?@typeInfo(T).@"struct".field_types[i] {
    const info = @typeInfo(T).@"struct";
    const FT = info.field_types[i];
    const dp = info.field_attrs[i].default_value_ptr orelse return null;
    const p: *const FT = @ptrCast(@alignCast(dp));
    return p.*;
}

fn decode(comptime T: type, arena: std.mem.Allocator, v: std.json.Value, fail: *Failure) ParseError!T {
    switch (@typeInfo(T)) {
        .bool => {
            if (v != .bool) return bad(fail, "must be a boolean");
            return v.bool;
        },
        .int => {
            const x: i128 = switch (v) {
                .integer => |i| i,
                .float => |f| blk: {
                    // `5.0` is an integer to JSON Schema, as in `ToolCall.arg`.
                    if (@floor(f) != f or f < -9.223372036854775808e18 or f >= 9.223372036854775808e18)
                        return bad(fail, "must be an integer in range");
                    break :blk @intFromFloat(f);
                },
                .number_string => return bad(fail, "must be an integer in range"),
                else => return bad(fail, "must be an integer"),
            };
            if (x < intLo(T) or x > intHi(T)) {
                return bad(fail, comptime std.fmt.comptimePrint("must be an integer between {d} and {d}", .{ intLo(T), intHi(T) }));
            }
            return std.math.cast(T, x) orelse bad(fail, "must be an integer in range");
        },
        .float => switch (v) {
            .integer => |i| return @floatFromInt(i),
            .float => |f| return @floatCast(f),
            .number_string => |s| return @floatCast(std.fmt.parseFloat(f64, s) catch return bad(fail, "must be a number")),
            else => return bad(fail, "must be a number"),
        },
        .optional => |o| {
            if (v == .null) return null;
            return try decode(o.child, arena, v, fail);
        },
        .@"enum" => {
            if (v != .string) return bad(fail, "must be a string");
            return std.meta.stringToEnum(T, v.string) orelse bad(fail, comptime enumList(T));
        },
        .pointer => |p| {
            if (p.child == u8) {
                if (v != .string) return bad(fail, "must be a string");
                return v.string;
            }
            if (v != .array) return bad(fail, "must be an array");
            const items = v.array.items;
            const out = try arena.alloc(p.child, items.len);
            for (out, items, 0..) |*o, item, i| {
                o.* = decode(p.child, arena, item, fail) catch |e| {
                    if (e == error.InvalidArguments) try underIndex(arena, fail, i);
                    return e;
                };
            }
            return out;
        },
        .array => |a| {
            if (v != .array) return bad(fail, "must be an array");
            if (v.array.items.len != a.len) {
                return bad(fail, comptime std.fmt.comptimePrint("must have exactly {d} items", .{a.len}));
            }
            var out: T = undefined;
            for (&out, v.array.items, 0..) |*o, item, i| {
                o.* = decode(a.child, arena, item, fail) catch |e| {
                    if (e == error.InvalidArguments) try underIndex(arena, fail, i);
                    return e;
                };
            }
            return out;
        },
        .@"struct" => |info| {
            if (v != .object) return bad(fail, "must be an object");
            var it = v.object.iterator();
            while (it.next()) |e| {
                var known = false;
                inline for (info.field_names) |n| {
                    if (std.mem.eql(u8, e.key_ptr.*, n)) known = true;
                }
                if (!known) {
                    const k = e.key_ptr.*;
                    return bad(fail, try arena.print("unexpected property \"{s}\"", .{k[0..@min(k.len, 64)]}));
                }
            }
            var out: T = undefined;
            inline for (info.field_names, info.field_types, 0..) |n, FT, i| {
                const got: ?std.json.Value = if (v.object.get(n)) |g|
                    (if (g == .null and isOptional(FT)) null else g)
                else
                    null;
                if (got) |g| {
                    @field(out, n) = decode(FT, arena, g, fail) catch |e| {
                        if (e == error.InvalidArguments) try under(arena, fail, n);
                        return e;
                    };
                } else if (comptime defaultOf(T, i)) |d| {
                    @field(out, n) = d;
                } else if (comptime isOptional(FT)) {
                    @field(out, n) = null;
                } else {
                    return bad(fail, "missing required property \"" ++ n ++ "\"");
                }
            }
            return out;
        },
        else => comptime unsupported(@typeName(T), T, "unsupported type"),
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const schema_check = @import("schema_check.zig");

const Color = enum { red, green };
const Inner = struct { x: i32, y: ?f64 = null };
const Described = struct {
    a: bool,
    pub const mcp_descriptions = .{ .a = "A \"flag\"\n" };
};
const Rich = struct {
    name: []const u8,
    count: u8,
    big: i64,
    ratio: f64,
    ok: bool,
    color: Color,
    tags: []const []const u8,
    pair: [2]i16,
    inner: Inner,
    note: ?[]const u8,
    items: []const Inner = &.{},
    limit: u32 = 10,
    pub const mcp_descriptions = .{ .name = "The name", .limit = "max rows" };
};

fn expectSchema(comptime T: type, expected: []const u8) !void {
    try testing.expectEqualStrings(expected, schemaOf(T));
}

test "schemaOf: object shapes" {
    try expectSchema(struct { a: bool }, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"boolean\"}},\"required\":[\"a\"],\"additionalProperties\":false}");
    try expectSchema(struct {}, "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}");
    try expectSchema(struct { a: ?bool = null }, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"boolean\"}},\"additionalProperties\":false}");
}

test "schemaOf: scalar fields" {
    const S = struct { b: bool, u: u8, i: i16, w: i64, x: u64, f: f32, s: []const u8, c: Color };
    try expectSchema(S, "{\"type\":\"object\",\"properties\":{" ++
        "\"b\":{\"type\":\"boolean\"}," ++
        "\"u\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":255}," ++
        "\"i\":{\"type\":\"integer\",\"minimum\":-32768,\"maximum\":32767}," ++
        "\"w\":{\"type\":\"integer\",\"minimum\":-9007199254740991,\"maximum\":9007199254740991}," ++
        "\"x\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991}," ++
        "\"f\":{\"type\":\"number\"}," ++
        "\"s\":{\"type\":\"string\"}," ++
        "\"c\":{\"type\":\"string\",\"enum\":[\"red\",\"green\"]}" ++
        "},\"required\":[\"b\",\"u\",\"i\",\"w\",\"x\",\"f\",\"s\",\"c\"],\"additionalProperties\":false}");
}

test "schemaOf: optional, default, array, slice, nested, descriptions" {
    try expectSchema(Inner, "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"integer\",\"minimum\":-2147483648,\"maximum\":2147483647},\"y\":{\"type\":\"number\"}},\"required\":[\"x\"],\"additionalProperties\":false}");
    try expectSchema(Described, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"boolean\",\"description\":\"A \\\"flag\\\"\\n\"}},\"required\":[\"a\"],\"additionalProperties\":false}");
    const S = struct { p: [2]bool, l: []const i8, o: ?[]const u8, d: u8 = 3, n: Described };
    try expectSchema(S, "{\"type\":\"object\",\"properties\":{" ++
        "\"p\":{\"type\":\"array\",\"items\":{\"type\":\"boolean\"},\"minItems\":2,\"maxItems\":2}," ++
        "\"l\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":-128,\"maximum\":127}}," ++
        "\"o\":{\"type\":\"string\"}," ++
        "\"d\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":255}," ++
        "\"n\":" ++ schemaOf(Described) ++
        "},\"required\":[\"p\",\"l\",\"n\"],\"additionalProperties\":false}");
}

/// Compile `schema_text`, validate `instance_text`; true = accepted.
fn accepts(schema_text: []const u8, instance_text: []const u8) !bool {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sv = try std.json.parseFromSliceLeaky(std.json.Value, arena, schema_text, .{});
    const sc = try schema_check.Schema.compile(arena, sv);
    const iv = try std.json.parseFromSliceLeaky(std.json.Value, arena, instance_text, .{});
    return (try sc.validate(arena, iv)) == null;
}

test "schemaOf: generated schemas compile in schema_check and accept/reject" {
    const rich = comptime schemaOf(Rich);
    const good =
        \\{"name":"n","count":255,"big":-5,"ratio":1.5,"ok":true,"color":"red","tags":["a"],"pair":[1,2],"inner":{"x":1},"note":"z","limit":3}
    ;
    try testing.expect(try accepts(rich, good));
    // `note` and `limit` and `items` are not required.
    try testing.expect(try accepts(rich,
        \\{"name":"n","count":0,"big":0,"ratio":0,"ok":false,"color":"green","tags":[],"pair":[0,0],"inner":{"x":0,"y":2}}
    ));
    // missing required `name`
    try testing.expect(!try accepts(rich,
        \\{"count":1,"big":0,"ratio":0,"ok":false,"color":"green","tags":[],"pair":[0,0],"inner":{"x":0}}
    ));
    // u8 out of range, bad enum tag, pair length, unknown property
    try testing.expect(!try accepts(rich, "{\"name\":\"n\",\"count\":256,\"big\":0,\"ratio\":0,\"ok\":false,\"color\":\"red\",\"tags\":[],\"pair\":[0,0],\"inner\":{\"x\":0}}"));
    try testing.expect(!try accepts(rich, "{\"name\":\"n\",\"count\":1,\"big\":0,\"ratio\":0,\"ok\":false,\"color\":\"blue\",\"tags\":[],\"pair\":[0,0],\"inner\":{\"x\":0}}"));
    try testing.expect(!try accepts(rich, "{\"name\":\"n\",\"count\":1,\"big\":0,\"ratio\":0,\"ok\":false,\"color\":\"red\",\"tags\":[],\"pair\":[0],\"inner\":{\"x\":0}}"));
    try testing.expect(!try accepts(rich, "{\"name\":\"n\",\"count\":1,\"big\":0,\"ratio\":0,\"ok\":false,\"color\":\"red\",\"tags\":[],\"pair\":[0,0],\"inner\":{\"x\":0},\"zzz\":1}"));
    try testing.expect(!try accepts(rich, "{\"name\":\"n\",\"count\":1,\"big\":9007199254740992,\"ratio\":0,\"ok\":false,\"color\":\"red\",\"tags\":[],\"pair\":[0,0],\"inner\":{\"x\":0}}"));
}

fn parseText(comptime T: type, arena: std.mem.Allocator, text: []const u8, fail: *Failure) !T {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    return parse(T, arena, v, fail);
}

test "parse: round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Failure = .{};
    const r = try parseText(Rich, arena,
        \\{"name":"n","count":255,"big":-5,"ratio":1,"ok":true,"color":"green","tags":["a","b"],"pair":[1,-2],"inner":{"x":7,"y":0.5},"note":null,"items":[{"x":1},{"x":2}]}
    , &f);
    try testing.expectEqualStrings("n", r.name);
    try testing.expectEqual(@as(u8, 255), r.count);
    try testing.expectEqual(@as(i64, -5), r.big);
    try testing.expectEqual(@as(f64, 1.0), r.ratio);
    try testing.expect(r.ok);
    try testing.expectEqual(Color.green, r.color);
    try testing.expectEqual(@as(usize, 2), r.tags.len);
    try testing.expectEqualStrings("b", r.tags[1]);
    try testing.expectEqual([2]i16{ 1, -2 }, r.pair);
    try testing.expectEqual(@as(i32, 7), r.inner.x);
    try testing.expectEqual(@as(?f64, 0.5), r.inner.y);
    try testing.expect(r.note == null); // JSON null = absent
    try testing.expectEqual(@as(usize, 2), r.items.len);
    try testing.expectEqual(@as(i32, 2), r.items[1].x);
    try testing.expectEqual(@as(u32, 10), r.limit); // default
    // 5.0 is an integer; an absent arguments value is `{}`.
    const e = try parseText(struct { n: u8 = 1, m: ?u8 }, arena, "{\"n\":5.0}", &f);
    try testing.expectEqual(@as(u8, 5), e.n);
    try testing.expect(e.m == null);
    const z = try parse(struct { n: u8 = 4 }, arena, .null, &f);
    try testing.expectEqual(@as(u8, 4), z.n);
}

fn expectFail(comptime T: type, text: []const u8, pointer: []const u8, message: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var f: Failure = .{};
    try testing.expectError(error.InvalidArguments, parseText(T, arena_state.allocator(), text, &f));
    try testing.expectEqualStrings(pointer, f.pointer);
    try testing.expectEqualStrings(message, f.message);
}

test "parse: error paths" {
    const S = struct { name: []const u8, n: u8, inner: Inner = .{ .x = 0 }, l: []const bool = &.{}, p: [2]u8 = .{ 0, 0 }, c: Color = .red, s: i64 = 0, fl: f32 = 0 };
    try expectFail(S, "{\"n\":1}", "", "missing required property \"name\"");
    try expectFail(S, "{\"name\":1,\"n\":1}", "/name", "must be a string");
    try expectFail(S, "{\"name\":\"a\",\"n\":\"1\"}", "/n", "must be an integer");
    try expectFail(S, "{\"name\":\"a\",\"n\":1.5}", "/n", "must be an integer in range");
    try expectFail(S, "{\"name\":\"a\",\"n\":256}", "/n", "must be an integer between 0 and 255");
    try expectFail(S, "{\"name\":\"a\",\"n\":-1}", "/n", "must be an integer between 0 and 255");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"s\":9007199254740992}", "/s", "must be an integer between -9007199254740991 and 9007199254740991");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"s\":99999999999999999999}", "/s", "must be an integer in range");
    try expectFail(S, "{\"name\":\"a\",\"n\":null}", "/n", "must be an integer");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"extra\":true}", "", "unexpected property \"extra\"");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"inner\":{\"x\":\"q\"}}", "/inner/x", "must be an integer");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"inner\":{}}", "/inner", "missing required property \"x\"");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"inner\":5}", "/inner", "must be an object");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"l\":[true,3]}", "/l/1", "must be a boolean");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"l\":true}", "/l", "must be an array");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"p\":[1]}", "/p", "must have exactly 2 items");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"p\":[1,300]}", "/p/1", "must be an integer between 0 and 255");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"c\":\"blue\"}", "/c", "must be one of red, green");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"c\":3}", "/c", "must be a string");
    try expectFail(S, "{\"name\":\"a\",\"n\":1,\"fl\":\"x\"}", "/fl", "must be a number");
    try expectFail(S, "[1]", "", "must be an object");
}

test "parse: OOM is an error, never a crash" {
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var f: Failure = .{};
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), "{\"l\":[true]}", .{});
    try testing.expectError(error.OutOfMemory, parse(struct { l: []const bool }, fa.allocator(), parsed, &f));
}

// Verdicts frozen from tools/typed_oracle (github.com/google/jsonschema-go v0.4.3
// inferring the schema of equivalent Go structs, run 2026-11-13): `schemaOf` +
// `schema_check` and `parse` must agree with them on every instance.
const OracleRow = struct { valid: bool, instance: []const u8 };
const oracle_search = [_]OracleRow{
    .{ .valid = true, .instance = "{\"query\":\"a\"}" },
    .{ .valid = true, .instance = "{\"query\":\"a\",\"limit\":255,\"tags\":[\"x\",\"y\"],\"exact\":true}" },
    .{ .valid = false, .instance = "{\"query\":\"a\",\"limit\":256}" },
    .{ .valid = false, .instance = "{\"query\":\"a\",\"limit\":-1}" },
    .{ .valid = false, .instance = "{\"query\":\"a\",\"limit\":1.5}" },
    .{ .valid = false, .instance = "{\"limit\":3}" },
    .{ .valid = false, .instance = "{\"query\":1}" },
    .{ .valid = false, .instance = "{\"query\":\"a\",\"tags\":[1]}" },
    .{ .valid = false, .instance = "{\"query\":\"a\",\"extra\":1}" },
    .{ .valid = false, .instance = "{\"query\":\"a\",\"exact\":\"yes\"}" },
    .{ .valid = false, .instance = "[]" },
};
const oracle_shape = [_]OracleRow{
    .{ .valid = true, .instance = "{\"name\":\"s\",\"center\":{\"x\":1,\"y\":2.5}}" },
    .{ .valid = true, .instance = "{\"name\":\"s\",\"center\":{\"x\":1,\"y\":2,\"label\":\"c\"},\"sides\":[1,2,3]}" },
    .{ .valid = false, .instance = "{\"name\":\"s\"}" },
    .{ .valid = false, .instance = "{\"name\":\"s\",\"center\":{\"x\":1}}" },
    .{ .valid = false, .instance = "{\"name\":\"s\",\"center\":{\"x\":\"1\",\"y\":2}}" },
    .{ .valid = false, .instance = "{\"name\":\"s\",\"center\":{\"x\":1,\"y\":2},\"sides\":[2147483648]}" },
    .{ .valid = false, .instance = "{\"name\":\"s\",\"center\":{\"x\":1,\"y\":2,\"z\":3}}" },
};
const oracle_triple = [_]OracleRow{
    .{ .valid = true, .instance = "{\"values\":[1,2,3]}" },
    .{ .valid = false, .instance = "{\"values\":[1,2]}" },
    .{ .valid = false, .instance = "{\"values\":[1,2,3,4]}" },
    .{ .valid = false, .instance = "{\"values\":[1,2,32768]}" },
    .{ .valid = true, .instance = "{\"values\":[1,2,-32768]}" },
    .{ .valid = false, .instance = "{}" },
};

const OSearch = struct { query: []const u8, limit: u8 = 0, tags: []const []const u8 = &.{}, exact: bool = false };
const OPoint = struct { x: f64, y: f64, label: ?[]const u8 = null };
const OShape = struct { name: []const u8, center: OPoint, sides: []const i32 = &.{} };
const OTriple = struct { values: [3]i16 };

fn expectOracle(comptime T: type, rows: []const OracleRow) !void {
    const schema = comptime schemaOf(T);
    for (rows) |row| {
        try testing.expectEqual(row.valid, try accepts(schema, row.instance));
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        var f: Failure = .{};
        const ok = if (parseText(T, arena_state.allocator(), row.instance, &f)) |_| true else |_| false;
        try testing.expectEqual(row.valid, ok);
    }
}

test "schemaOf: verdicts agree with jsonschema-go" {
    try expectOracle(OSearch, &oracle_search);
    try expectOracle(OShape, &oracle_shape);
    try expectOracle(OTriple, &oracle_triple);
}
