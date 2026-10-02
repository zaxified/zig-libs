// SPDX-License-Identifier: MIT
//! `x-mcp-header` annotations in a tool's `inputSchema` (spec 2026-07-28,
//! server/tools.mdx "x-mcp-header"; basic/transports/streamable-http.mdx
//! "Schema Extension"). An annotation tells a Streamable HTTP client to mirror
//! that argument into an `Mcp-Param-{name}` header.
//!
//! The spec makes a tool whose annotation breaks the rules INVALID: an HTTP
//! client must drop it from `tools/list`, so it silently disappears for
//! exactly the clients the annotation was written for. `Server.addTool` runs
//! `validate` so the author learns at registration instead. The rules:
//!
//!   - the value is a non-empty HTTP token (`1*tchar`, RFC 9110 §5.6.2 — no
//!     control characters, no CR/LF);
//!   - case-insensitively unique within the schema;
//!   - on a parameter whose `type` is `"string"`, `"integer"` or `"boolean"`
//!     (`"number"` is not permitted);
//!   - statically reachable: the chain from the root is `properties` keys and
//!     nothing else — never `items`, `oneOf`/`anyOf`/`allOf`/`not`,
//!     `if`/`then`/`else` or `$ref`. `mcp-http` reads annotations along
//!     exactly such chains (`modern.paramHeaders`), at most `max_chain` deep.
//!
//! A type given as an array (`["string", "null"]`) is refused: the spec names
//! the three primitive types, and a client that reads it strictly would drop
//! the tool. The integer range (±(2⁵³−1)) is a property of call values, not of
//! the schema; `mcp-http` compares integers numerically.

const std = @import("std");

pub const Error = error{
    /// An annotation that is not on a `properties`-only chain from the root
    /// (or on the root itself, or deeper than `max_chain`).
    HeaderAnnotationNotReachable,
    /// Empty, not a string, or not an HTTP token.
    HeaderAnnotationInvalidName,
    /// Two annotations whose names differ only in case, or not at all.
    HeaderAnnotationDuplicate,
    /// The annotated parameter's `type` is not `string`, `integer` or `boolean`.
    HeaderAnnotationInvalidType,
} || std.mem.Allocator.Error;

/// The deepest `properties` chain an annotation may sit at — the depth
/// `mcp-http` walks to find them.
pub const max_chain = 32;

/// Checks every `x-mcp-header` annotation in `input_schema`. A schema with no
/// annotation is not parsed at all; a schema that is not JSON is not judged
/// here (`tools/list` already reports it).
pub fn validate(gpa: std.mem.Allocator, input_schema: []const u8) Error!void {
    if (std.mem.indexOf(u8, input_schema, "x-mcp-header") == null) return;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, input_schema, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    var names: std.ArrayList([]const u8) = .empty;
    try walk(arena, root, null, 0, &names);
}

/// Keywords whose value is DATA, not a schema: a key spelled `x-mcp-header`
/// inside an example is not an annotation.
const data_keywords = [_][]const u8{ "default", "const", "enum", "examples" };

/// `chain`: the length of the `properties`-only chain that reached `v`, or
/// null if `v` was reached any other way (the root included — it is not a
/// parameter).
fn walk(arena: std.mem.Allocator, v: std.json.Value, chain: ?usize, depth: usize, names: *std.ArrayList([]const u8)) Error!void {
    // Nesting beyond this is no schema anyone writes; it only bounds the
    // recursion. Anything below it can hold no reachable annotation.
    if (depth > 2 * max_chain + 8) return;
    switch (v) {
        .array => |a| for (a.items) |item| try walk(arena, item, null, depth + 1, names),
        .object => |o| {
            if (o.get("x-mcp-header")) |h| {
                const c = chain orelse return error.HeaderAnnotationNotReachable;
                if (c > max_chain) return error.HeaderAnnotationNotReachable;
                if (h != .string or !isToken(h.string)) return error.HeaderAnnotationInvalidName;
                const ty = o.get("type") orelse return error.HeaderAnnotationInvalidType;
                if (ty != .string or !isPrimitive(ty.string)) return error.HeaderAnnotationInvalidType;
                for (names.items) |seen| {
                    if (std.ascii.eqlIgnoreCase(seen, h.string)) return error.HeaderAnnotationDuplicate;
                }
                try names.append(arena, h.string);
            }
            var it = o.iterator();
            next: while (it.next()) |e| {
                const key = e.key_ptr.*;
                for (data_keywords) |k| if (std.mem.eql(u8, key, k)) continue :next;
                if (std.mem.eql(u8, key, "properties") and e.value_ptr.* == .object) {
                    // A property map: each value is a parameter schema, on the
                    // chain if this schema is (or is the root).
                    const child_chain: ?usize = if (chain) |c| c + 1 else if (depth == 0) 1 else null;
                    var pit = e.value_ptr.object.iterator();
                    while (pit.next()) |p| try walk(arena, p.value_ptr.*, child_chain, depth + 1, names);
                } else {
                    try walk(arena, e.value_ptr.*, null, depth + 1, names);
                }
            }
        },
        else => {},
    }
}

fn isPrimitive(t: []const u8) bool {
    return std.mem.eql(u8, t, "string") or std.mem.eql(u8, t, "integer") or std.mem.eql(u8, t, "boolean");
}

/// RFC 9110 §5.6.2 `token = 1*tchar`.
fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null;
        if (!ok) return false;
    }
    return true;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn check(schema: []const u8) Error!void {
    return validate(testing.allocator, schema);
}

test "valid: the spec's execute_sql example, nested properties chains" {
    try check(
        \\{"type":"object","properties":{
        \\  "region":{"type":"string","description":"The region","x-mcp-header":"Region"},
        \\  "query":{"type":"string"},
        \\  "opts":{"type":"object","properties":{
        \\    "shard":{"type":"integer","x-mcp-header":"Shard"},
        \\    "dry":{"type":"boolean","x-mcp-header":"Dry-Run_1.x"}}}},
        \\ "required":["region","query"]}
    );
    try check("{\"type\":\"object\"}"); // no annotation at all
    try check("not json, x-mcp-header"); // not judged here
}

test "not reachable: items, composition, conditionals, $ref targets, the root" {
    const cases = [_][]const u8{
        \\{"type":"object","properties":{"l":{"type":"array","items":{"type":"string","x-mcp-header":"A"}}}}
        ,
        \\{"type":"object","properties":{"u":{"oneOf":[{"type":"string","x-mcp-header":"A"}]}}}
        ,
        \\{"type":"object","properties":{"u":{"type":"string","allOf":[{"x-mcp-header":"A","type":"string"}]}}}
        ,
        \\{"type":"object","if":{"properties":{"a":{"type":"string","x-mcp-header":"A"}}}}
        ,
        \\{"type":"object","$defs":{"r":{"type":"string","x-mcp-header":"A"}},"properties":{"a":{"$ref":"#/$defs/r"}}}
        ,
        \\{"type":"string","x-mcp-header":"Root"}
        ,
        // `properties` under `items` restarts nothing: the chain is already broken.
        \\{"type":"object","properties":{"l":{"type":"array","items":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A"}}}}}}
    };
    for (cases) |c| try testing.expectError(error.HeaderAnnotationNotReachable, check(c));
}

test "names: empty, non-string, non-token, control characters, duplicate in any case" {
    try testing.expectError(error.HeaderAnnotationInvalidName, check(
        \\{"properties":{"a":{"type":"string","x-mcp-header":""}}}
    ));
    try testing.expectError(error.HeaderAnnotationInvalidName, check(
        \\{"properties":{"a":{"type":"string","x-mcp-header":7}}}
    ));
    try testing.expectError(error.HeaderAnnotationInvalidName, check(
        \\{"properties":{"a":{"type":"string","x-mcp-header":"Two Words"}}}
    ));
    try testing.expectError(error.HeaderAnnotationInvalidName, check(
        \\{"properties":{"a":{"type":"string","x-mcp-header":"A\r\nX-Evil: 1"}}}
    ));
    try testing.expectError(error.HeaderAnnotationInvalidName, check(
        \\{"properties":{"a":{"type":"string","x-mcp-header":"Région"}}}
    ));
    try testing.expectError(error.HeaderAnnotationDuplicate, check(
        \\{"properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"object","properties":{"c":{"type":"string","x-mcp-header":"rEGION"}}}}}
    ));
}

test "types: number, object, array, missing, a type list" {
    for ([_][]const u8{
        \\{"properties":{"a":{"type":"number","x-mcp-header":"A"}}}
        ,
        \\{"properties":{"a":{"type":"object","x-mcp-header":"A"}}}
        ,
        \\{"properties":{"a":{"type":"array","x-mcp-header":"A"}}}
        ,
        \\{"properties":{"a":{"x-mcp-header":"A"}}}
        ,
        \\{"properties":{"a":{"type":["string","null"],"x-mcp-header":"A"}}}
    }) |c| try testing.expectError(error.HeaderAnnotationInvalidType, check(c));
}

test "data keywords are not schemas" {
    try check(
        \\{"properties":{"a":{"type":"object","default":{"x-mcp-header":"no"},"examples":[{"x-mcp-header":"no"}]}}}
    );
}

test "the chain depth mcp-http reads is the depth allowed" {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const deep = struct {
        fn build(wr: *std.Io.Writer, levels: usize) !void {
            try wr.writeAll("{\"type\":\"object\"");
            for (0..levels - 1) |_| try wr.writeAll(",\"properties\":{\"p\":{\"type\":\"object\"");
            try wr.writeAll(",\"properties\":{\"p\":{\"type\":\"string\",\"x-mcp-header\":\"Deep\"}}");
            for (0..levels - 1) |_| try wr.writeAll("}}");
            try wr.writeAll("}");
        }
    };
    try deep.build(&w, max_chain);
    try check(w.buffered());
    w = .fixed(&buf);
    try deep.build(&w, max_chain + 1);
    try testing.expectError(error.HeaderAnnotationNotReachable, check(w.buffered()));
}
