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

// ── mutation-run tests (2026-11-13): the hostile-client shapes of `decode` ──

fn objWith(arena: std.mem.Allocator, key: []const u8, val: std.json.Value) !std.json.Value {
    var m: std.json.ObjectMap = .empty;
    try m.put(arena, key, val);
    return .{ .object = m };
}

/// Decode `{"n": val}` into `struct { n: T }`: the value, or the refusal message.
fn decodeOne(comptime T: type, val: std.json.Value) !union(enum) { ok: T, refused: []const u8 } {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Failure = .{};
    const r = parse(struct { n: T }, arena, try objWith(arena, "n", val), &f) catch |e| {
        if (e != error.InvalidArguments) return e;
        try testing.expectEqualStrings("/n", f.pointer);
        return .{ .refused = f.message };
    };
    return .{ .ok = r.n };
}

fn expectRefused(comptime T: type, val: std.json.Value, message: []const u8) !void {
    const r = try decodeOne(T, val);
    try testing.expect(r == .refused);
    try testing.expectEqualStrings(message, r.refused);
}

test "parse: integers from hostile floats and edge values" {
    const range = "must be an integer in range";
    const inf = std.math.inf(f64);
    // huge, infinite and NaN doubles never reach the integer conversion
    try expectRefused(i64, .{ .float = 1e300 }, range);
    try expectRefused(i64, .{ .float = -1e300 }, range);
    try expectRefused(i64, .{ .float = inf }, range);
    try expectRefused(i64, .{ .float = -inf }, range);
    try expectRefused(i64, .{ .float = std.math.nan(f64) }, range);
    try expectRefused(i64, .{ .float = 0.5 }, range);
    try expectRefused(i64, .{ .float = -0.5 }, range);
    // 2^63 is refused as out of range; -2^63 passes the range check and meets the bound
    try expectRefused(i64, .{ .float = 9.223372036854775808e18 }, range);
    const between = "must be an integer between -9007199254740991 and 9007199254740991";
    try expectRefused(i64, .{ .float = -9.223372036854775808e18 }, between);
    try expectRefused(i64, .{ .float = 9007199254740992.0 }, between);
    try expectRefused(i64, .{ .integer = -9007199254740992 }, between);
    try expectRefused(i64, .{ .integer = std.math.minInt(i64) }, between);
    try expectRefused(i64, .{ .integer = std.math.maxInt(i64) }, between);
    try expectRefused(i64, .{ .number_string = "123456789012345678901234567890" }, range);
    try expectRefused(i64, .{ .number_string = "5" }, range);
    // the exact edges are accepted
    try testing.expectEqual(@as(i64, 9007199254740991), (try decodeOne(i64, .{ .integer = 9007199254740991 })).ok);
    try testing.expectEqual(@as(i64, -9007199254740991), (try decodeOne(i64, .{ .integer = -9007199254740991 })).ok);
    try testing.expectEqual(@as(i64, 9007199254740991), (try decodeOne(i64, .{ .float = 9007199254740991.0 })).ok);
    try testing.expectEqual(@as(i64, -9007199254740991), (try decodeOne(i64, .{ .float = -9007199254740991.0 })).ok);
    try testing.expectEqual(@as(i64, 0), (try decodeOne(i64, .{ .float = -0.0 })).ok);
    try testing.expectEqual(@as(i8, -128), (try decodeOne(i8, .{ .integer = -128 })).ok);
    try testing.expectEqual(@as(i8, 127), (try decodeOne(i8, .{ .integer = 127 })).ok);
    try testing.expectEqual(@as(u8, 0), (try decodeOne(u8, .{ .integer = 0 })).ok);
    try testing.expectEqual(@as(u8, 255), (try decodeOne(u8, .{ .float = 255.0 })).ok);
    try expectRefused(i8, .{ .integer = 128 }, "must be an integer between -128 and 127");
    try expectRefused(i8, .{ .integer = -129 }, "must be an integer between -128 and 127");
    try expectRefused(u8, .{ .float = -1.0 }, "must be an integer between 0 and 255");
    try expectRefused(u64, .{ .integer = -1 }, "must be an integer between 0 and 9007199254740991");
    try expectRefused(i64, .{ .string = "1" }, "must be an integer");
    try expectRefused(i64, .{ .bool = true }, "must be an integer");
    try expectRefused(i64, .{ .null = {} }, "must be an integer");
    try expectRefused(i64, .{ .array = std.json.Array.init(testing.allocator) }, "must be an integer");
}

test "parse: floats, strings, booleans and enums refuse the wrong JSON type" {
    // a bare huge integer (a `number_string` after std.json) is a valid double
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Failure = .{};
    const big = try parseText(struct { x: f64 }, arena, "{\"x\":100000000000000000000}", &f);
    try testing.expectEqual(@as(f64, 1e20), big.x);
    const neg = try parseText(struct { x: f64 }, arena, "{\"x\":-3}", &f);
    try testing.expectEqual(@as(f64, -3.0), neg.x);
    // f32 saturates to infinity instead of trapping
    const wide = try parseText(struct { x: f32 }, arena, "{\"x\":1e300}", &f);
    try testing.expect(std.math.isInf(wide.x));
    try expectRefused(f64, .{ .number_string = "12x" }, "must be a number");
    try expectRefused(f64, .{ .bool = false }, "must be a number");
    try expectRefused(f64, .{ .null = {} }, "must be a number");
    try expectRefused(bool, .{ .integer = 1 }, "must be a boolean");
    try expectRefused(bool, .{ .string = "true" }, "must be a boolean");
    try expectRefused(bool, .{ .null = {} }, "must be a boolean");
    try expectRefused([]const u8, .{ .integer = 1 }, "must be a string");
    try expectRefused([]const u8, .{ .null = {} }, "must be a string");
    try expectRefused(Color, .{ .null = {} }, "must be a string");
    try expectRefused(Color, .{ .string = "" }, "must be one of red, green");
    try expectRefused(Color, .{ .string = "gree" }, "must be one of red, green");
    try expectRefused([]const bool, .{ .object = .empty }, "must be an array");
    try expectRefused([2]bool, .{ .string = "ab" }, "must be an array");
    try expectRefused(Inner, .{ .array = std.json.Array.init(testing.allocator) }, "must be an object");
    try expectRefused(Inner, .{ .null = {} }, "must be an object");
    try testing.expectEqual(Color.red, (try decodeOne(Color, .{ .string = "red" })).ok);
    try testing.expectEqual(Color.green, (try decodeOne(Color, .{ .string = "green" })).ok);
    try testing.expectEqual(false, (try decodeOne(bool, .{ .bool = false })).ok);
}

test "parse: the pointer names the full path through arrays and structs" {
    const S = struct { items: []const Inner = &.{}, m: []const []const bool = &.{}, g: [2][2]bool = .{ .{ false, false }, .{ false, false } }, o: struct { a: struct { c: u8 } = .{ .c = 0 } } = .{} };
    try expectFail(S, "{\"items\":[{\"x\":1},{\"x\":\"q\"}]}", "/items/1/x", "must be an integer");
    try expectFail(S, "{\"items\":[{\"x\":1},{}]}", "/items/1", "missing required property \"x\"");
    try expectFail(S, "{\"m\":[[true],[true,1]]}", "/m/1/1", "must be a boolean");
    try expectFail(S, "{\"m\":[[true],5]}", "/m/1", "must be an array");
    try expectFail(S, "{\"g\":[[true,true],[true,1]]}", "/g/1/1", "must be a boolean");
    try expectFail(S, "{\"g\":[[true,true],[true]]}", "/g/1", "must have exactly 2 items");
    try expectFail(S, "{\"g\":[[true,true]]}", "/g", "must have exactly 2 items");
    try expectFail(S, "{\"g\":[[true,true],[true,true],[true,true]]}", "/g", "must have exactly 2 items");
    try expectFail(S, "{\"o\":{\"a\":{\"c\":300}}}", "/o/a/c", "must be an integer between 0 and 255");
    try expectFail(S, "{\"o\":{\"a\":{\"c\":1,\"d\":2}}}", "/o/a", "unexpected property \"d\"");
    // nesting far beyond the type is a plain type error, not a descent
    var deep: [400]u8 = undefined;
    @memset(deep[0..200], '[');
    @memset(deep[200..], ']');
    var text: [420]u8 = undefined;
    const t = try std.fmt.bufPrint(&text, "{{\"m\":[{s}]}}", .{deep[0..400]});
    try expectFail(S, t, "/m/0/0", "must be a boolean");
}

test "parse: optional elements, null as absent, defaults" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Failure = .{};
    const S = struct { xs: []const ?u8 = &.{}, d: ?u32 = 5, e: ?u32 = null, k: u8 = 3, u: ?Color = .green, w: ?Color = null };
    const a = try parseText(S, arena, "{\"xs\":[1,null,3],\"u\":\"red\",\"w\":\"green\"}", &f);
    try testing.expectEqual(@as(usize, 3), a.xs.len);
    try testing.expectEqual(@as(?u8, 1), a.xs[0]);
    try testing.expectEqual(@as(?u8, null), a.xs[1]);
    try testing.expectEqual(@as(?u8, 3), a.xs[2]);
    try testing.expectEqual(@as(?u32, 5), a.d); // absent: the default, not null
    try testing.expectEqual(@as(?u32, null), a.e);
    try testing.expectEqual(@as(u8, 3), a.k);
    try testing.expectEqual(@as(?Color, .red), a.u);
    try testing.expectEqual(@as(?Color, .green), a.w);
    // an explicit null is "absent": the default applies (`?T = 5` stays 5)
    const b = try parseText(S, arena, "{\"d\":null,\"e\":null,\"u\":null,\"w\":null}", &f);
    try testing.expectEqual(@as(?u32, 5), b.d);
    try testing.expectEqual(@as(?u32, null), b.e);
    try testing.expectEqual(@as(?Color, .green), b.u);
    try testing.expectEqual(@as(?Color, null), b.w);
    const c = try parseText(S, arena, "{}", &f);
    try testing.expectEqual(@as(?u32, 5), c.d);
    try testing.expectEqual(@as(?Color, .green), c.u);
    // a non-optional field is not rescued by null, default or not
    try expectFail(S, "{\"k\":null}", "/k", "must be an integer");
    try expectFail(S, "{\"d\":\"x\"}", "/d", "must be an integer");
    try expectFail(S, "{\"xs\":[1,\"x\"]}", "/xs/1", "must be an integer");
    try expectFail(S, "{\"xs\":[300]}", "/xs/0", "must be an integer between 0 and 255");
}

test "parse: unknown property is matched exactly and echoed truncated" {
    const S = struct { name: u8 = 0, n: u8 = 0 };
    try expectFail(S, "{\"names\":1}", "", "unexpected property \"names\"");
    try expectFail(S, "{\"nam\":1}", "", "unexpected property \"nam\"");
    try expectFail(S, "{\"\":1}", "", "unexpected property \"\"");
    try expectFail(S, "{\"Name\":1}", "", "unexpected property \"Name\"");
    const long: [100]u8 = @splat('k');
    const k64: [64]u8 = @splat('k');
    try expectFail(S, "{\"" ++ long ++ "\":1}", "", "unexpected property \"" ++ k64 ++ "\"");
    try expectFail(S, "{\"" ++ k64 ++ "\":1}", "", "unexpected property \"" ++ k64 ++ "\"");
    const k65: [65]u8 = @splat('k');
    try expectFail(S, "{\"" ++ k65 ++ "\":1}", "", "unexpected property \"" ++ k64 ++ "\"");
    // known keys together with an unknown one: the unknown one still refuses
    try expectFail(S, "{\"name\":1,\"n\":2,\"zz\":3}", "", "unexpected property \"zz\"");
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var f: Failure = .{};
    const ok = try parseText(S, arena_state.allocator(), "{\"name\":1,\"n\":2}", &f);
    try testing.expectEqual(@as(u8, 1), ok.name);
    try testing.expectEqual(@as(u8, 2), ok.n);
}

test "parse: the failure record is reset by every call" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Failure = .{ .pointer = "/stale", .message = "stale" };
    _ = try parseText(struct { n: u8 }, arena, "{\"n\":1}", &f);
    try testing.expectEqualStrings("", f.pointer);
    try testing.expectEqualStrings("", f.message);
    try testing.expectError(error.InvalidArguments, parseText(struct { n: u8 }, arena, "{\"n\":\"x\"}", &f));
    try testing.expectEqualStrings("/n", f.pointer);
    // a second refusal on the same record does not accumulate the first one's path
    try testing.expectError(error.InvalidArguments, parseText(struct { n: u8 }, arena, "{}", &f));
    try testing.expectEqualStrings("", f.pointer);
    try testing.expectEqualStrings("missing required property \"n\"", f.message);
}

test "parse: OOM while building the pointer or message is OutOfMemory" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var f: Failure = .{};
    const A = struct { l: []const bool };
    const bad_elem = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), "{\"l\":[1]}", .{});
    var one: [1]u8 = undefined; // room for the one-element slice, not for the "/0" pointer
    var fba = std.heap.FixedBufferAllocator.init(&one);
    try testing.expectError(error.OutOfMemory, parse(A, fba.allocator(), bad_elem, &f));
    const B = struct { n: u8 };
    const bad_field = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), "{\"n\":\"x\"}", .{});
    var fa0 = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, parse(B, fa0.allocator(), bad_field, &f));
    const unknown = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), "{\"zz\":1}", .{});
    var fa2 = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, parse(B, fa2.allocator(), unknown, &f));
    // a sweep over every allocation point of a full document: ok or OOM, never a crash
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(),
        \\{"name":"n","count":1,"big":2,"ratio":1,"ok":true,"color":"red","tags":["a"],"pair":[1,2],"inner":{"x":1},"items":[{"x":1}]}
    , .{});
    var i: usize = 0;
    while (i < 12) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var inner_arena = std.heap.ArenaAllocator.init(fa.allocator());
        defer inner_arena.deinit();
        _ = parse(Rich, inner_arena.allocator(), doc, &f) catch |e| if (e != error.OutOfMemory) return e;
    }
}

/// Fails exactly the allocation number `fail_at` and serves every other one
/// (`std.testing.FailingAllocator` keeps failing from its index on, so it
/// cannot show what a handler does after the failure).
const OneShotFail = struct {
    inner: std.mem.Allocator,
    fail_at: usize,
    n: usize = 0,

    fn allocator(self: *OneShotFail) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        defer self.n += 1;
        if (self.n == self.fail_at) return null;
        return self.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(m, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(m, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(m, a, ra);
    }
};

test "parse: an OOM after the first allocation leaves the failure record untouched" {
    var backing = std.heap.ArenaAllocator.init(testing.allocator);
    defer backing.deinit();
    const doc_arena = backing.allocator();
    const Nested = struct { l: []const []const bool };
    const Arr = struct { g: [1][]const bool };
    const Obj = struct { l: []const bool };
    const nested = try std.json.parseFromSliceLeaky(std.json.Value, doc_arena, "{\"l\":[[true]]}", .{});
    const arr = try std.json.parseFromSliceLeaky(std.json.Value, doc_arena, "{\"g\":[[true]]}", .{});
    const obj = try std.json.parseFromSliceLeaky(std.json.Value, doc_arena, "{\"l\":[true]}", .{});
    var f: Failure = .{};
    // the inner slice (allocation 1) fails: element, field and root frames must not add a pointer
    var s1: OneShotFail = .{ .inner = doc_arena, .fail_at = 1 };
    try testing.expectError(error.OutOfMemory, parse(Nested, s1.allocator(), nested, &f));
    try testing.expectEqualStrings("", f.pointer);
    try testing.expectEqualStrings("", f.message);
    var s2: OneShotFail = .{ .inner = doc_arena, .fail_at = 0 };
    try testing.expectError(error.OutOfMemory, parse(Arr, s2.allocator(), arr, &f));
    try testing.expectEqualStrings("", f.pointer);
    var s3: OneShotFail = .{ .inner = doc_arena, .fail_at = 0 };
    try testing.expectError(error.OutOfMemory, parse(Obj, s3.allocator(), obj, &f));
    try testing.expectEqualStrings("", f.pointer);
    // and the same documents decode when nothing fails
    var s4: OneShotFail = .{ .inner = doc_arena, .fail_at = 99 };
    const r = try parse(Nested, s4.allocator(), nested, &f);
    try testing.expect(r.l[0][0]);
}
